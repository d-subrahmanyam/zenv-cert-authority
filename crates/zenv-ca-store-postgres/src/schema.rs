//! Forward-only migrations, tracked in `zenv_ca_schema_version` and serialised with an
//! advisory lock so several daemon instances starting at once cannot race.
//!
//! The table layout mirrors the SQLite backend column for column (Unix seconds as
//! `BIGINT`, JSON as `TEXT`), so data can move between backends with a plain export.

use postgres::Client;
use zenv_ca_store::StoreError;

use crate::{AUDIT_LOCK_CLASS, Error};

/// Ordered list of migrations; index + 1 is the resulting schema version.
const MIGRATIONS: &[&str] = &[r"
CREATE TABLE certificates (
    serial             TEXT    PRIMARY KEY,
    common_name        TEXT    NOT NULL,
    dns_names          TEXT    NOT NULL,           -- JSON array (text, as in SQLite)
    ip_addresses       TEXT    NOT NULL,           -- JSON array
    profile            TEXT    NOT NULL,
    key_algorithm      TEXT    NOT NULL,
    issuance_method    TEXT    NOT NULL CHECK (issuance_method IN ('csr', 'keygen')),
    requested_by       TEXT    NOT NULL,
    not_before         BIGINT  NOT NULL,
    not_after          BIGINT  NOT NULL,
    fingerprint_sha256 TEXT    NOT NULL UNIQUE,
    cert_pem           TEXT    NOT NULL,
    created_at         BIGINT  NOT NULL,
    revoked_at         BIGINT,
    revocation_reason  TEXT,
    revoked_by         TEXT,
    CHECK ((revoked_at IS NULL) = (revocation_reason IS NULL))
);
CREATE INDEX idx_certificates_requested_by ON certificates (requested_by);
CREATE INDEX idx_certificates_not_after    ON certificates (not_after);
CREATE INDEX idx_certificates_revoked_at   ON certificates (revoked_at) WHERE revoked_at IS NOT NULL;

CREATE TABLE api_tokens (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name         TEXT   NOT NULL UNIQUE,
    role         TEXT   NOT NULL CHECK (role IN ('requester', 'admin')),
    token_hash   TEXT   NOT NULL UNIQUE,          -- SHA-256 hex of the bearer token
    token_prefix TEXT   NOT NULL,
    created_at   BIGINT NOT NULL,
    last_used_at BIGINT,
    disabled_at  BIGINT
);

CREATE TABLE audit_log (
    id        BIGINT PRIMARY KEY,
    ts        BIGINT NOT NULL,
    actor     TEXT   NOT NULL,
    action    TEXT   NOT NULL,
    target    TEXT   NOT NULL,
    details   TEXT   NOT NULL,                    -- exact hashed text: NOT jsonb
    prev_hash TEXT   NOT NULL,
    hash      TEXT   NOT NULL UNIQUE
);

CREATE FUNCTION zenv_ca_audit_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END
$$;
CREATE TRIGGER audit_log_no_update_delete BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION zenv_ca_audit_append_only();
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION zenv_ca_audit_append_only();

CREATE TABLE crl_state (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    crl_number BIGINT  NOT NULL
);
INSERT INTO crl_state (id, crl_number) VALUES (1, 0);
"];

/// Accepts only plain lower-case identifiers, because the schema name is interpolated
/// into `search_path`.
pub(crate) fn validate_identifier(name: &str) -> Result<(), StoreError> {
    let mut chars = name.chars();
    let ok = name.len() <= 63
        && chars.next().is_some_and(|c| c.is_ascii_lowercase() || c == '_')
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    if ok {
        Ok(())
    } else {
        Err(StoreError::Configuration(format!(
            "invalid schema name '{name}': use lower-case letters, digits and '_'"
        )))
    }
}

pub(crate) fn migrate(client: &mut Client) -> Result<(), Error> {
    let mut tx = client.transaction()?;
    // Same lock as audit appends: no writes interleave with a migration.
    tx.execute(
        "SELECT pg_advisory_xact_lock($1, hashtext(current_schema()))",
        &[&AUDIT_LOCK_CLASS],
    )?;
    // Check before creating: `CREATE TABLE IF NOT EXISTS` needs CREATE on the schema even
    // when the table exists, and the runtime role deliberately lacks it (DML-only).
    let tracked: bool = tx
        .query_one("SELECT to_regclass('zenv_ca_schema_version') IS NOT NULL", &[])?
        .try_get(0)?;
    if !tracked {
        tx.batch_execute(
            "CREATE TABLE zenv_ca_schema_version (version INTEGER NOT NULL);
             INSERT INTO zenv_ca_schema_version (version) VALUES (0);",
        )?;
    }
    let current = i64::from(
        tx.query_one("SELECT version FROM zenv_ca_schema_version", &[])?
            .try_get::<_, i32>(0)?,
    );
    let target = i64::try_from(MIGRATIONS.len()).unwrap_or(i64::MAX);
    if current > target {
        return Err(StoreError::SchemaTooNew(current).into());
    }
    for (index, sql) in MIGRATIONS
        .iter()
        .enumerate()
        .skip(usize::try_from(current).unwrap_or(0))
    {
        let version = i32::try_from(index + 1).unwrap_or(i32::MAX);
        tracing::info!(version, "applying PostgreSQL migration");
        tx.batch_execute(sql)?;
        tx.execute("UPDATE zenv_ca_schema_version SET version = $1", &[&version])?;
    }
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_names_are_restricted() {
        for ok in ["zenv_ca", "_x", "ca2"] {
            assert!(validate_identifier(ok).is_ok(), "{ok}");
        }
        for bad in ["", "Zenv", "a-b", "a;drop", "1abc", "public,evil"] {
            assert!(validate_identifier(bad).is_err(), "{bad}");
        }
    }
}
