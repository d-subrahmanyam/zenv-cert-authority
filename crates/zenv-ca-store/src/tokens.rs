//! Bearer-token authentication.
//!
//! Tokens are 256-bit random values (`zca_<base64url>`). Because they are high-entropy,
//! a fast hash (SHA-256) is sufficient: there is nothing to brute-force, unlike human
//! passwords, which would need Argon2. Only the hash is stored.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::audit::append;
use crate::error::{StoreError, StoreResult};
use crate::{Store, now_unix};

const TOKEN_PREFIX: &str = "zca_";

/// Authorisation level of a token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// May request certificates and manage (download/revoke) their own.
    Requester,
    /// May additionally see and revoke every certificate and read the audit log.
    Admin,
}

impl Role {
    /// Stable string form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requester => "requester",
            Self::Admin => "admin",
        }
    }

    fn parse(s: &str) -> StoreResult<Self> {
        match s {
            "requester" => Ok(Self::Requester),
            "admin" => Ok(Self::Admin),
            other => Err(StoreError::Corrupt(format!("unknown role '{other}'"))),
        }
    }
}

impl std::str::FromStr for Role {
    type Err = StoreError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// The authenticated caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    /// Token id.
    pub token_id: i64,
    /// Token name; recorded as `requested_by` / audit actor.
    pub name: String,
    /// Role.
    pub role: Role,
}

impl Principal {
    /// `true` for administrators.
    pub fn is_admin(&self) -> bool {
        self.role == Role::Admin
    }
}

/// Token metadata (never includes the secret).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenInfo {
    /// Id.
    pub id: i64,
    /// Unique name, e.g. `team-payments` or `alice`.
    pub name: String,
    /// Role.
    pub role: Role,
    /// Leading characters of the token, to recognise it in logs.
    pub prefix: String,
    /// Creation time (unix).
    pub created_at: i64,
    /// Last successful use (unix).
    pub last_used_at: Option<i64>,
    /// When the token was disabled (unix).
    pub disabled_at: Option<i64>,
}

fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

impl Store {
    /// Creates a token and returns its metadata plus the **plaintext**, which is not
    /// recoverable afterwards.
    pub fn create_token(&self, name: &str, role: Role, actor: &str) -> StoreResult<(TokenInfo, String)> {
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let token = format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(secret));
        let prefix: String = token.chars().take(10).collect();
        let now = now_unix();

        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO api_tokens (name, role, token_hash, token_prefix, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![name, role.as_str(), hash_token(&token), prefix, now],
        )?;
        let id = tx.last_insert_rowid();
        append(
            &tx,
            actor,
            "token.created",
            name,
            &serde_json::json!({ "role": role.as_str(), "prefix": prefix }),
        )?;
        tx.commit()?;
        Ok((
            TokenInfo {
                id,
                name: name.to_owned(),
                role,
                prefix,
                created_at: now,
                last_used_at: None,
                disabled_at: None,
            },
            token,
        ))
    }

    /// Resolves a bearer token to a principal. Disabled or unknown tokens yield `None`.
    pub fn authenticate(&self, token: &str) -> StoreResult<Option<Principal>> {
        if !token.starts_with(TOKEN_PREFIX) || token.len() > 128 {
            return Ok(None);
        }
        let conn = self.conn();
        let found: Option<(i64, String, String)> = conn
            .query_row(
                "SELECT id, name, role FROM api_tokens WHERE token_hash = ?1 AND disabled_at IS NULL",
                [hash_token(token)],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((id, name, role)) = found else {
            return Ok(None);
        };
        conn.execute(
            "UPDATE api_tokens SET last_used_at = ?1 WHERE id = ?2",
            params![now_unix(), id],
        )?;
        Ok(Some(Principal {
            token_id: id,
            name,
            role: Role::parse(&role)?,
        }))
    }

    /// Lists all tokens.
    pub fn list_tokens(&self) -> StoreResult<Vec<TokenInfo>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id, name, role, token_prefix, created_at, last_used_at, disabled_at
             FROM api_tokens ORDER BY id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, Option<i64>>(5)?,
                r.get::<_, Option<i64>>(6)?,
            ))
        })?;
        rows.map(|row| {
            let (id, name, role, prefix, created_at, last_used_at, disabled_at) = row?;
            Ok(TokenInfo {
                id,
                name,
                role: Role::parse(&role)?,
                prefix,
                created_at,
                last_used_at,
                disabled_at,
            })
        })
        .collect()
    }

    /// Disables a token by name. Returns `false` when no active token had that name.
    pub fn disable_token(&self, name: &str, actor: &str) -> StoreResult<bool> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let changed = tx.execute(
            "UPDATE api_tokens SET disabled_at = ?1 WHERE name = ?2 AND disabled_at IS NULL",
            params![now_unix(), name],
        )?;
        if changed > 0 {
            append(&tx, actor, "token.disabled", name, &serde_json::json!({}))?;
        }
        tx.commit()?;
        Ok(changed > 0)
    }

    /// `true` when at least one admin token is active (used by `init` checks).
    pub fn has_admin(&self) -> StoreResult<bool> {
        let conn = self.conn();
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM api_tokens WHERE role = 'admin' AND disabled_at IS NULL",
            [],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }
}
