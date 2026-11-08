//! # zenv-ca-store-sqlite
//!
//! [`CaStore`] backed by an embedded SQLite file: zero operational overhead, one file to
//! back up. The right choice for a single CA host. For several daemon instances sharing
//! one database use `zenv-ca-store-postgres`.
//!
//! * WAL journal, `synchronous=FULL`, foreign keys on, 5 s busy timeout.
//! * Writes use `BEGIN IMMEDIATE`, so the daemon and the CLI writing at the same time
//!   queue on the busy timeout instead of failing with "database is locked".
//! * One connection behind a mutex per process; SQLite allows one writer anyway.
//! * Audit `UPDATE`/`DELETE` are blocked by triggers; the hash chain catches the rest.

mod schema;

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::{Connection, ErrorCode, OptionalExtension, Row, Transaction, TransactionBehavior, params};
use zenv_ca_core::{IssuedCertificate, RevocationReason, RevocationStatus, RevokedEntry};
use zenv_ca_store::audit::{AuditRow, ChainVerifier, events};
use zenv_ca_store::certs::{CERT_COLUMNS, CertificateRow, decode_revocation_status, decode_revoked_entry};
use zenv_ca_store::tokens::{NewToken, hash_token, is_well_formed};
use zenv_ca_store::{
    AuditRecord, AuditVerification, CaStore, CertFilter, CertificateRecord, IssuanceMethod, Principal,
    RevokeOutcome, Role, StoreError, StoreResult, TokenInfo, now_unix,
};

/// Internal error: lets `?` work on both driver and store errors.
#[derive(Debug)]
pub(crate) enum Error {
    Sql(rusqlite::Error),
    Store(StoreError),
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sql(e)
    }
}

impl From<StoreError> for Error {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<Error> for StoreError {
    fn from(e: Error) -> Self {
        match e {
            Error::Store(e) => e,
            Error::Sql(rusqlite::Error::SqliteFailure(f, msg))
                if f.code == ErrorCode::ConstraintViolation =>
            {
                // UNIQUE / PRIMARY KEY violations; CHECK and trigger failures stay backend errors.
                let text = msg.unwrap_or_default();
                if text.contains("UNIQUE") {
                    StoreError::Conflict(text)
                } else {
                    StoreError::backend(rusqlite::Error::SqliteFailure(f, Some(text)))
                }
            }
            Error::Sql(e) => StoreError::backend(e),
        }
    }
}

type Res<T> = Result<T, Error>;

/// SQLite implementation of [`CaStore`]. Cheap to share behind an `Arc`.
#[derive(Debug)]
pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl SqliteStore {
    /// Opens (creating if needed) the database at `path` and applies migrations.
    /// On Unix the file is restricted to the owner (`0600`).
    pub fn open(path: &Path) -> StoreResult<Self> {
        let conn = Connection::open(path).map_err(Error::from)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| StoreError::Io(e.to_string()))?;
        }
        Ok(Self::init(conn, true)?)
    }

    /// Opens a private in-memory database (tests, dry runs).
    pub fn open_in_memory() -> StoreResult<Self> {
        let conn = Connection::open_in_memory().map_err(Error::from)?;
        Ok(Self::init(conn, false)?)
    }

    fn init(conn: Connection, wal: bool) -> Res<Self> {
        if wal {
            conn.pragma_update(None, "journal_mode", "WAL")?;
        }
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        schema::migrate(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn conn(&self) -> MutexGuard<'_, Connection> {
        // A poisoned mutex only means another thread panicked mid-operation; SQLite's own
        // transactions keep the data consistent, so continuing is safe.
        self.conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Runs `f` in a write transaction (`BEGIN IMMEDIATE`), committing on success.
    fn write<T>(&self, f: impl FnOnce(&Transaction<'_>) -> Res<T>) -> StoreResult<T> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(Error::from)?;
        let out = f(&tx)?;
        tx.commit().map_err(Error::from)?;
        Ok(out)
    }

    /// Runs a read-only closure on the connection.
    fn read<T>(&self, f: impl FnOnce(&Connection) -> Res<T>) -> StoreResult<T> {
        Ok(f(&self.conn())?)
    }
}

/// Appends an audit entry inside the caller's (write-locked) transaction.
fn append(
    tx: &Transaction<'_>,
    actor: &str,
    action: &str,
    target: &str,
    details: &serde_json::Value,
) -> Res<()> {
    let last: Option<(i64, String)> = tx
        .query_row(
            "SELECT id, hash FROM audit_log ORDER BY id DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let e = AuditRow::next(last, actor, action, target, details);
    tx.execute(
        "INSERT INTO audit_log (id, ts, actor, action, target, details, prev_hash, hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            e.id,
            e.ts,
            e.actor,
            e.action,
            e.target,
            e.details,
            e.prev_hash,
            e.hash
        ],
    )?;
    Ok(())
}

fn cert_row(r: &Row<'_>) -> rusqlite::Result<CertificateRow> {
    Ok(CertificateRow {
        serial: r.get(0)?,
        common_name: r.get(1)?,
        dns_names: r.get(2)?,
        ip_addresses: r.get(3)?,
        profile: r.get(4)?,
        key_algorithm: r.get(5)?,
        issuance_method: r.get(6)?,
        requested_by: r.get(7)?,
        not_before: r.get(8)?,
        not_after: r.get(9)?,
        fingerprint_sha256: r.get(10)?,
        cert_pem: r.get(11)?,
        created_at: r.get(12)?,
        revoked_at: r.get(13)?,
        revocation_reason: r.get(14)?,
        revoked_by: r.get(15)?,
    })
}

fn audit_row(r: &Row<'_>) -> rusqlite::Result<AuditRow> {
    Ok(AuditRow {
        id: r.get(0)?,
        ts: r.get(1)?,
        actor: r.get(2)?,
        action: r.get(3)?,
        target: r.get(4)?,
        details: r.get(5)?,
        prev_hash: r.get(6)?,
        hash: r.get(7)?,
    })
}

fn get_cert(conn: &Connection, serial: &str) -> Res<Option<CertificateRecord>> {
    let row = conn
        .query_row(
            &format!("SELECT {CERT_COLUMNS} FROM certificates WHERE serial = ?1"),
            [serial],
            cert_row,
        )
        .optional()?;
    Ok(row.map(CertificateRow::decode).transpose()?)
}

fn decode_all(rows: impl Iterator<Item = rusqlite::Result<CertificateRow>>) -> Res<Vec<CertificateRecord>> {
    rows.map(|r| Ok(r?.decode()?)).collect()
}

impl CaStore for SqliteStore {
    fn backend(&self) -> &'static str {
        "sqlite"
    }

    fn ping(&self) -> StoreResult<()> {
        self.read(|c| Ok(c.query_row("SELECT 1", [], |_| Ok(()))?))
    }

    fn insert_certificate(
        &self,
        cert: &IssuedCertificate,
        method: IssuanceMethod,
        requested_by: &str,
    ) -> StoreResult<()> {
        let row = CertificateRow::encode(cert, method, requested_by)?;
        self.write(|tx| {
            tx.execute(
                &format!(
                    "INSERT INTO certificates ({CERT_COLUMNS})
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, NULL, NULL, NULL)"
                ),
                params![
                    row.serial,
                    row.common_name,
                    row.dns_names,
                    row.ip_addresses,
                    row.profile,
                    row.key_algorithm,
                    row.issuance_method,
                    row.requested_by,
                    row.not_before,
                    row.not_after,
                    row.fingerprint_sha256,
                    row.cert_pem,
                    row.created_at,
                ],
            )?;
            append(
                tx,
                requested_by,
                events::CERT_ISSUED,
                &cert.serial,
                &events::certificate_issued(cert, method),
            )
        })
    }

    fn get_certificate(&self, serial: &str) -> StoreResult<Option<CertificateRecord>> {
        self.read(|c| get_cert(c, serial))
    }

    fn list_certificates(&self, filter: &CertFilter) -> StoreResult<Vec<CertificateRecord>> {
        let now = now_unix();
        let search = filter.search_pattern();
        let status = filter.status.map(|s| s.as_str());
        self.read(|c| {
            let mut stmt = c.prepare(&format!(
                "SELECT {CERT_COLUMNS} FROM certificates
                 WHERE (?1 IS NULL OR requested_by = ?1)
                   AND (?2 IS NULL OR lower(common_name) LIKE ?2 ESCAPE '\\'
                                   OR lower(dns_names) LIKE ?2 ESCAPE '\\')
                   AND (?3 IS NULL
                        OR (?3 = 'revoked' AND revoked_at IS NOT NULL)
                        OR (?3 = 'expired' AND revoked_at IS NULL AND not_after < ?4)
                        OR (?3 = 'active'  AND revoked_at IS NULL AND not_after >= ?4))
                 ORDER BY created_at DESC, serial
                 LIMIT ?5 OFFSET ?6"
            ))?;
            let rows = stmt.query_map(
                params![
                    filter.requested_by,
                    search,
                    status,
                    now,
                    filter.effective_limit(),
                    filter.offset
                ],
                cert_row,
            )?;
            decode_all(rows)
        })
    }

    fn expiring_within(&self, days: u32) -> StoreResult<Vec<CertificateRecord>> {
        let now = now_unix();
        let horizon = now + i64::from(days) * 86_400;
        self.read(|c| {
            let mut stmt = c.prepare(&format!(
                "SELECT {CERT_COLUMNS} FROM certificates
                 WHERE revoked_at IS NULL AND not_after >= ?1 AND not_after < ?2
                 ORDER BY not_after, serial"
            ))?;
            let rows = stmt.query_map(params![now, horizon], cert_row)?;
            decode_all(rows)
        })
    }

    fn revoke(&self, serial: &str, reason: RevocationReason, actor: &str) -> StoreResult<RevokeOutcome> {
        self.write(|tx| {
            let Some(record) = get_cert(tx, serial)? else {
                return Ok(RevokeOutcome::NotFound);
            };
            if record.revoked_at.is_some() {
                return Ok(RevokeOutcome::AlreadyRevoked(Box::new(record)));
            }
            tx.execute(
                "UPDATE certificates SET revoked_at = ?1, revocation_reason = ?2, revoked_by = ?3
                 WHERE serial = ?4",
                params![now_unix(), reason.as_str(), actor, serial],
            )?;
            append(
                tx,
                actor,
                events::CERT_REVOKED,
                serial,
                &events::certificate_revoked(reason),
            )?;
            let updated = get_cert(tx, serial)?
                .ok_or_else(|| StoreError::Corrupt(format!("{serial} vanished during revocation")))?;
            Ok(RevokeOutcome::Revoked(Box::new(updated)))
        })
    }

    fn crl_entries(&self) -> StoreResult<Vec<RevokedEntry>> {
        self.read(|c| {
            let mut stmt = c.prepare(
                "SELECT serial, revoked_at, revocation_reason FROM certificates
                 WHERE revoked_at IS NOT NULL AND not_after >= ?1 ORDER BY revoked_at, serial",
            )?;
            let rows = stmt.query_map([now_unix()], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?;
            rows.map(|row| {
                let (serial, ts, reason) = row?;
                Ok(decode_revoked_entry(serial, ts, &reason)?)
            })
            .collect()
        })
    }

    fn revocation_revision(&self) -> StoreResult<(i64, i64)> {
        self.read(|c| {
            Ok(c.query_row(
                "SELECT COUNT(*), COALESCE(MAX(revoked_at), 0) FROM certificates WHERE revoked_at IS NOT NULL",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?)
        })
    }

    fn next_crl_number(&self, actor: &str, revoked: usize) -> StoreResult<u64> {
        let n: i64 = self.write(|tx| {
            let n: i64 = tx.query_row(
                "UPDATE crl_state SET crl_number = crl_number + 1 WHERE id = 1 RETURNING crl_number",
                [],
                |r| r.get(0),
            )?;
            append(
                tx,
                actor,
                events::CRL_GENERATED,
                &n.to_string(),
                &events::crl_generated(revoked),
            )?;
            Ok(n)
        })?;
        u64::try_from(n).map_err(|e| StoreError::Corrupt(e.to_string()))
    }

    fn revocation_status(&self, serial: &str) -> StoreResult<RevocationStatus> {
        self.read(|c| {
            let row = c
                .query_row(
                    "SELECT revoked_at, revocation_reason FROM certificates WHERE serial = ?1",
                    [serial],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            Ok(decode_revocation_status(row))
        })
    }

    fn create_token(&self, name: &str, role: Role, actor: &str) -> StoreResult<(TokenInfo, String)> {
        let token = NewToken::generate();
        let now = now_unix();
        let id = self.write(|tx| {
            tx.execute(
                "INSERT INTO api_tokens (name, role, token_hash, token_prefix, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![name, role.as_str(), token.hash, token.prefix, now],
            )?;
            let id = tx.last_insert_rowid();
            append(
                tx,
                actor,
                events::TOKEN_CREATED,
                name,
                &events::token_created(role, &token.prefix),
            )?;
            Ok(id)
        })?;
        let info = TokenInfo {
            id,
            name: name.to_owned(),
            role,
            prefix: token.prefix.clone(),
            created_at: now,
            last_used_at: None,
            disabled_at: None,
        };
        Ok((info, token.secret))
    }

    fn authenticate(&self, token: &str) -> StoreResult<Option<Principal>> {
        if !is_well_formed(token) {
            return Ok(None);
        }
        self.read(|c| {
            let found: Option<(i64, String, String)> = c
                .query_row(
                    "SELECT id, name, role FROM api_tokens WHERE token_hash = ?1 AND disabled_at IS NULL",
                    [hash_token(token)],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            let Some((id, name, role)) = found else {
                return Ok(None);
            };
            c.execute(
                "UPDATE api_tokens SET last_used_at = ?1 WHERE id = ?2",
                params![now_unix(), id],
            )?;
            Ok(Some(Principal {
                token_id: id,
                name,
                role: role.parse()?,
            }))
        })
    }

    fn list_tokens(&self) -> StoreResult<Vec<TokenInfo>> {
        self.read(|c| {
            let mut stmt = c.prepare(
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
                    role: role.parse()?,
                    prefix,
                    created_at,
                    last_used_at,
                    disabled_at,
                })
            })
            .collect()
        })
    }

    fn disable_token(&self, name: &str, actor: &str) -> StoreResult<bool> {
        self.write(|tx| {
            let changed = tx.execute(
                "UPDATE api_tokens SET disabled_at = ?1 WHERE name = ?2 AND disabled_at IS NULL",
                params![now_unix(), name],
            )?;
            if changed > 0 {
                append(tx, actor, events::TOKEN_DISABLED, name, &events::token_disabled())?;
            }
            Ok(changed > 0)
        })
    }

    fn has_admin(&self) -> StoreResult<bool> {
        self.read(|c| {
            let n: i64 = c.query_row(
                "SELECT COUNT(*) FROM api_tokens WHERE role = 'admin' AND disabled_at IS NULL",
                [],
                |r| r.get(0),
            )?;
            Ok(n > 0)
        })
    }

    fn audit(&self, actor: &str, action: &str, target: &str, details: &serde_json::Value) -> StoreResult<()> {
        self.write(|tx| append(tx, actor, action, target, details))
    }

    fn audit_log(&self, limit: u32) -> StoreResult<Vec<AuditRecord>> {
        self.read(|c| {
            let mut stmt = c.prepare(
                "SELECT id, ts, actor, action, target, details, prev_hash, hash
                 FROM audit_log ORDER BY id DESC LIMIT ?1",
            )?;
            let rows = stmt.query_map([limit], audit_row)?;
            Ok(rows.map(|r| r.map(AuditRecord::from)).collect::<Result<_, _>>()?)
        })
    }

    fn verify_audit_chain(&self) -> StoreResult<AuditVerification> {
        self.read(|c| {
            let mut stmt = c.prepare(
                "SELECT id, ts, actor, action, target, details, prev_hash, hash
                 FROM audit_log ORDER BY id ASC",
            )?;
            let mut verifier = ChainVerifier::default();
            for row in stmt.query_map([], audit_row)? {
                verifier.push(&row?);
            }
            Ok(verifier.finish())
        })
    }
}
