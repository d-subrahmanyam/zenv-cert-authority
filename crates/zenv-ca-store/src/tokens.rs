//! Bearer tokens: types and the backend-independent secret handling.
//!
//! Tokens are 256-bit random values (`zca_<base64url>`). Because they are high-entropy,
//! a fast hash (SHA-256) is sufficient: there is nothing to brute-force, unlike human
//! passwords, which would need Argon2. Backends store only [`NewToken::hash`].

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{StoreError, StoreResult};

/// Every token starts with this marker (makes leaked tokens easy to grep for).
pub const TOKEN_PREFIX: &str = "zca_";
/// Longest string accepted as a token (anything longer is rejected before hashing).
pub const MAX_TOKEN_LEN: usize = 128;

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
    /// Stable string form, as stored.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requester => "requester",
            Self::Admin => "admin",
        }
    }
}

impl std::str::FromStr for Role {
    type Err = StoreError;
    fn from_str(s: &str) -> StoreResult<Self> {
        match s {
            "requester" => Ok(Self::Requester),
            "admin" => Ok(Self::Admin),
            other => Err(StoreError::Corrupt(format!("unknown role '{other}'"))),
        }
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

/// A freshly generated token. `secret` goes to the user once; `hash` and `prefix` are
/// what the backend stores.
pub struct NewToken {
    /// Plaintext bearer token.
    pub secret: String,
    /// SHA-256 hex of `secret`.
    pub hash: String,
    /// First 10 characters, for identification.
    pub prefix: String,
}

impl std::fmt::Debug for NewToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewToken")
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

impl NewToken {
    /// Generates 32 random bytes from the OS RNG.
    pub fn generate() -> Self {
        let mut raw = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        let secret = format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(raw));
        Self {
            hash: hash_token(&secret),
            prefix: secret.chars().take(10).collect(),
            secret,
        }
    }
}

/// SHA-256 hex of a token, the value backends look tokens up by.
pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Cheap syntactic check done before touching the database.
pub fn is_well_formed(token: &str) -> bool {
    token.starts_with(TOKEN_PREFIX) && token.len() <= MAX_TOKEN_LEN
}
