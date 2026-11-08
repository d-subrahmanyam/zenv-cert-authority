//! Forward-only schema migrations tracked with `PRAGMA user_version`.

use rusqlite::Connection;
use zenv_ca_store::StoreError;

use crate::Error;

/// Ordered list of migrations; index + 1 is the resulting schema version.
const MIGRATIONS: &[&str] = &[r"
CREATE TABLE certificates (
    serial             TEXT PRIMARY KEY,
    common_name        TEXT    NOT NULL,
    dns_names          TEXT    NOT NULL,           -- JSON array
    ip_addresses       TEXT    NOT NULL,           -- JSON array
    profile            TEXT    NOT NULL,
    key_algorithm      TEXT    NOT NULL,
    issuance_method    TEXT    NOT NULL,           -- 'csr' | 'keygen'
    requested_by       TEXT    NOT NULL,
    not_before         INTEGER NOT NULL,
    not_after          INTEGER NOT NULL,
    fingerprint_sha256 TEXT    NOT NULL UNIQUE,
    cert_pem           TEXT    NOT NULL,
    created_at         INTEGER NOT NULL,
    revoked_at         INTEGER,
    revocation_reason  TEXT,
    revoked_by         TEXT,
    CHECK ((revoked_at IS NULL) = (revocation_reason IS NULL))
);
CREATE INDEX idx_certificates_requested_by ON certificates(requested_by);
CREATE INDEX idx_certificates_not_after    ON certificates(not_after);
CREATE INDEX idx_certificates_revoked_at   ON certificates(revoked_at);

CREATE TABLE api_tokens (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT    NOT NULL UNIQUE,
    role         TEXT    NOT NULL CHECK (role IN ('requester', 'admin')),
    token_hash   TEXT    NOT NULL UNIQUE,         -- SHA-256 hex of the bearer token
    token_prefix TEXT    NOT NULL,                -- first chars, for identification only
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER,
    disabled_at  INTEGER
);

CREATE TABLE audit_log (
    id        INTEGER PRIMARY KEY,
    ts        INTEGER NOT NULL,
    actor     TEXT    NOT NULL,
    action    TEXT    NOT NULL,
    target    TEXT    NOT NULL,
    details   TEXT    NOT NULL,                  -- JSON object
    prev_hash TEXT    NOT NULL,
    hash      TEXT    NOT NULL UNIQUE
);

-- The audit log is append-only: refuse updates and deletes at the database level.
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

CREATE TABLE crl_state (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    crl_number  INTEGER NOT NULL
);
INSERT INTO crl_state (id, crl_number) VALUES (1, 0);
"];

pub(crate) fn migrate(conn: &Connection) -> Result<(), Error> {
    let current: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    let target = i64::try_from(MIGRATIONS.len()).unwrap_or(i64::MAX);
    if current > target {
        return Err(StoreError::SchemaTooNew(current).into());
    }
    for (index, sql) in MIGRATIONS
        .iter()
        .enumerate()
        .skip(usize::try_from(current).unwrap_or(0))
    {
        let version = index + 1;
        tracing::info!(version, "applying database migration");
        conn.execute_batch(&format!("BEGIN; {sql}; PRAGMA user_version = {version}; COMMIT;"))?;
    }
    Ok(())
}
