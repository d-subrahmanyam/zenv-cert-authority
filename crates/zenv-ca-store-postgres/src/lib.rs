//! # zenv-ca-store-postgres
//!
//! [`CaStore`] backed by PostgreSQL. Use it when several `zenv-cad` instances share one
//! database (high availability behind a load balancer), or when your organisation
//! requires a managed database for backups and replication.
//!
//! * **Pool**: `r2d2` over the synchronous `postgres` client. Calls block, which fits the
//!   daemon's `spawn_blocking` model. Never call it from an async worker thread.
//! * **TLS**: rustls on aws-lc-rs, the same crypto as the rest of the CA. Certificates and
//!   host names are always verified, so `sslmode=require` behaves like libpq's
//!   `verify-full`. Roots come from `tls_ca_file`, or from the OS trust store.
//! * **Multiple instances**: every write takes a transaction-scoped advisory lock
//!   (namespaced by schema) before appending to the audit log, so instances never fork
//!   the hash chain. CRL numbers come from a single-row `UPDATE ... RETURNING`.
//! * **Append-only audit**: a trigger rejects `UPDATE`, `DELETE` and `TRUNCATE` on
//!   `audit_log`. Also `REVOKE UPDATE, DELETE, TRUNCATE` from the application role, as
//!   described in the operations guide.
//! * **Schemas**: `schema` sets `search_path`, so one database can host several CAs.

mod schema;

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use postgres::error::SqlState;
use postgres::{GenericClient, Row, Transaction};
use r2d2_postgres::PostgresConnectionManager;
use tokio_postgres_rustls::MakeRustlsConnect;
use zenv_ca_core::{IssuedCertificate, RevocationReason, RevocationStatus, RevokedEntry};
use zenv_ca_store::audit::{AuditRow, ChainVerifier, events};
use zenv_ca_store::certs::{CERT_COLUMNS, CertificateRow, decode_revocation_status, decode_revoked_entry};
use zenv_ca_store::tokens::{NewToken, hash_token, is_well_formed};
use zenv_ca_store::{
    AuditRecord, AuditVerification, CaStore, CertFilter, CertificateRecord, IssuanceMethod, Principal,
    RevokeOutcome, Role, StoreError, StoreResult, TokenInfo, now_unix,
};

type Pool = r2d2::Pool<PostgresConnectionManager<MakeRustlsConnect>>;

/// First half of the advisory lock key ("zCA\0"); the second half is the schema hash.
const AUDIT_LOCK_CLASS: i32 = 0x7A43_4100;

/// Connection settings.
#[derive(Clone)]
pub struct PostgresOptions {
    /// libpq-style URL or key/value string, e.g.
    /// `postgresql://zenv_ca@db.dmz.zenv.internal:5432/zenv_ca?sslmode=require`.
    /// Keep the password out of it and use [`password`](Self::password).
    pub url: String,
    /// Password, read by the caller from a file or credential, never from config text.
    pub password: Option<String>,
    /// Schema for the CA's tables (`search_path`). `None` uses the role's default.
    pub schema: Option<String>,
    /// Maximum pooled connections per process.
    pub pool_size: u32,
    /// Timeout for establishing a connection and for checking one out of the pool.
    pub connect_timeout: Duration,
    /// PEM file with the CA certificate(s) that signed the server's TLS certificate.
    /// `None` uses the operating system trust store.
    pub tls_ca_file: Option<PathBuf>,
}

impl std::fmt::Debug for PostgresOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresOptions")
            .field("url", &self.url)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("schema", &self.schema)
            .field("pool_size", &self.pool_size)
            .field("connect_timeout", &self.connect_timeout)
            .field("tls_ca_file", &self.tls_ca_file)
            .finish()
    }
}

impl PostgresOptions {
    /// Options with defaults (pool of 8, 10 s timeout, OS trust store) for `url`.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            password: None,
            schema: None,
            pool_size: 8,
            connect_timeout: Duration::from_secs(10),
            tls_ca_file: None,
        }
    }
}

/// Internal error: lets `?` work on driver, pool and store errors alike.
#[derive(Debug)]
pub(crate) enum Error {
    Pg(postgres::Error),
    Pool(r2d2::Error),
    Store(StoreError),
}

impl From<postgres::Error> for Error {
    fn from(e: postgres::Error) -> Self {
        Self::Pg(e)
    }
}

impl From<r2d2::Error> for Error {
    fn from(e: r2d2::Error) -> Self {
        Self::Pool(e)
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
            Error::Pg(e) if e.code() == Some(&SqlState::UNIQUE_VIOLATION) => {
                let detail = e
                    .as_db_error()
                    .map(|d| d.constraint().unwrap_or(d.message()).to_owned())
                    .unwrap_or_else(|| e.to_string());
                StoreError::Conflict(detail)
            }
            Error::Pg(e) => StoreError::Backend(pg_error_text(&e).into()),
            Error::Pool(e) => StoreError::backend(e),
        }
    }
}

type Res<T> = Result<T, Error>;

/// `postgres::Error`'s `Display` is just "db error" for server-side errors; include the
/// SQLSTATE and the server's message (never the query parameters).
fn pg_error_text(e: &postgres::Error) -> String {
    match e.as_db_error() {
        Some(db) => format!("{} ({}): {}", db.severity(), db.code().code(), db.message()),
        None => {
            let mut text = e.to_string();
            let mut source = std::error::Error::source(e);
            while let Some(s) = source {
                text.push_str(": ");
                text.push_str(&s.to_string());
                source = s.source();
            }
            text
        }
    }
}

/// PostgreSQL implementation of [`CaStore`]. Cheap to clone (shares the pool).
#[derive(Clone)]
pub struct PostgresStore {
    pool: Pool,
}

impl std::fmt::Debug for PostgresStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.pool.state();
        f.debug_struct("PostgresStore")
            .field("connections", &state.connections)
            .field("idle", &state.idle_connections)
            .finish_non_exhaustive()
    }
}

impl PostgresStore {
    /// Connects, verifies TLS settings and applies migrations.
    ///
    /// **Blocking**: on a tokio runtime, call it from `spawn_blocking`.
    pub fn open(options: &PostgresOptions) -> StoreResult<Self> {
        let mut config = postgres::Config::from_str(&options.url)
            .map_err(|e| StoreError::Configuration(format!("invalid database url: {e}")))?;
        if config.get_password().is_some() {
            tracing::warn!("database password embedded in the URL; prefer database.password_file");
        }
        if let Some(pw) = &options.password {
            config.password(pw.as_bytes());
        }
        if let Some(schema) = &options.schema {
            schema::validate_identifier(schema)?;
            config.options(&format!("-c search_path={schema}"));
        }
        config.application_name("zenv-cad");
        config.connect_timeout(options.connect_timeout);
        warn_on_weak_tls(&config);

        let manager = PostgresConnectionManager::new(config, tls_connector(options)?);
        // One direct connection first: r2d2 would retry until the timeout and then hide
        // the cause (wrong password, TLS failure, unknown database).
        {
            use r2d2::ManageConnection;
            drop(manager.connect().map_err(|e| {
                StoreError::Configuration(format!("cannot connect to PostgreSQL: {}", pg_error_text(&e)))
            })?);
        }
        let pool = r2d2::Pool::builder()
            .max_size(options.pool_size.max(1))
            .min_idle(Some(1))
            .connection_timeout(options.connect_timeout)
            .build(manager)
            .map_err(|e| StoreError::Configuration(format!("cannot connect to PostgreSQL: {e}")))?;

        let store = Self { pool };
        {
            let mut client = store.pool.get().map_err(Error::from)?;
            schema::migrate(&mut client)?;
        }
        Ok(store)
    }

    /// Runs `f` in a transaction holding the audit advisory lock, committing on success.
    /// Every mutation appends to the audit log, so every write goes through here.
    fn write<T>(&self, f: impl FnOnce(&mut Transaction<'_>) -> Res<T>) -> StoreResult<T> {
        let run = || -> Res<T> {
            let mut client = self.pool.get()?;
            let mut tx = client.transaction()?;
            tx.execute(
                "SELECT pg_advisory_xact_lock($1, hashtext(current_schema()))",
                &[&AUDIT_LOCK_CLASS],
            )?;
            let out = f(&mut tx)?;
            tx.commit()?;
            Ok(out)
        };
        Ok(run()?)
    }

    /// Runs a read on a pooled connection.
    fn read<T>(&self, f: impl FnOnce(&mut postgres::Client) -> Res<T>) -> StoreResult<T> {
        let run = || -> Res<T> {
            let mut client = self.pool.get()?;
            f(&mut client)
        };
        Ok(run()?)
    }
}

fn tls_connector(options: &PostgresOptions) -> StoreResult<MakeRustlsConnect> {
    let mut roots = rustls::RootCertStore::empty();
    if let Some(path) = &options.tls_ca_file {
        use rustls::pki_types::CertificateDer;
        use rustls::pki_types::pem::PemObject;
        let certs = CertificateDer::pem_file_iter(path)
            .and_then(|it| it.collect::<Result<Vec<_>, _>>())
            .map_err(|e| StoreError::Configuration(format!("cannot read {}: {e}", path.display())))?;
        let (added, _) = roots.add_parsable_certificates(certs);
        if added == 0 {
            return Err(StoreError::Configuration(format!(
                "{} contains no usable CA certificates",
                path.display()
            )));
        }
    } else {
        let native = rustls_native_certs::load_native_certs();
        for e in &native.errors {
            tracing::debug!(error = %e, "skipping unreadable system certificate");
        }
        roots.add_parsable_certificates(native.certs);
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| StoreError::Configuration(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(MakeRustlsConnect::new(config))
}

/// Warns when a TCP connection could fall back to (or is configured for) plaintext.
fn warn_on_weak_tls(config: &postgres::Config) {
    use postgres::config::{Host, SslMode};
    let remote_tcp = config.get_hosts().iter().any(|h| match h {
        Host::Tcp(name) => !matches!(name.as_str(), "localhost" | "127.0.0.1" | "::1"),
        #[cfg(unix)]
        Host::Unix(_) => false,
    });
    if remote_tcp && config.get_ssl_mode() != SslMode::Require {
        tracing::warn!("database connection is not required to use TLS; add sslmode=require to database.url");
    }
}

/// Appends an audit entry inside the caller's (advisory-locked) transaction.
fn append(
    tx: &mut Transaction<'_>,
    actor: &str,
    action: &str,
    target: &str,
    details: &serde_json::Value,
) -> Res<()> {
    let last = tx
        .query_opt("SELECT id, hash FROM audit_log ORDER BY id DESC LIMIT 1", &[])?
        .map(|r| -> Res<_> { Ok((r.try_get::<_, i64>(0)?, r.try_get::<_, String>(1)?)) })
        .transpose()?;
    let e = AuditRow::next(last, actor, action, target, details);
    tx.execute(
        "INSERT INTO audit_log (id, ts, actor, action, target, details, prev_hash, hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        &[
            &e.id,
            &e.ts,
            &e.actor,
            &e.action,
            &e.target,
            &e.details,
            &e.prev_hash,
            &e.hash,
        ],
    )?;
    Ok(())
}

fn cert_row(r: &Row) -> Res<CertificateRow> {
    Ok(CertificateRow {
        serial: r.try_get(0)?,
        common_name: r.try_get(1)?,
        dns_names: r.try_get(2)?,
        ip_addresses: r.try_get(3)?,
        profile: r.try_get(4)?,
        key_algorithm: r.try_get(5)?,
        issuance_method: r.try_get(6)?,
        requested_by: r.try_get(7)?,
        not_before: r.try_get(8)?,
        not_after: r.try_get(9)?,
        fingerprint_sha256: r.try_get(10)?,
        cert_pem: r.try_get(11)?,
        created_at: r.try_get(12)?,
        revoked_at: r.try_get(13)?,
        revocation_reason: r.try_get(14)?,
        revoked_by: r.try_get(15)?,
    })
}

fn audit_row(r: &Row) -> Res<AuditRow> {
    Ok(AuditRow {
        id: r.try_get(0)?,
        ts: r.try_get(1)?,
        actor: r.try_get(2)?,
        action: r.try_get(3)?,
        target: r.try_get(4)?,
        details: r.try_get(5)?,
        prev_hash: r.try_get(6)?,
        hash: r.try_get(7)?,
    })
}

fn decode_all(rows: &[Row]) -> Res<Vec<CertificateRecord>> {
    rows.iter().map(|r| Ok(cert_row(r)?.decode()?)).collect()
}

fn get_cert(c: &mut impl GenericClient, serial: &str, for_update: bool) -> Res<Option<CertificateRecord>> {
    let lock = if for_update { " FOR UPDATE" } else { "" };
    let row = c.query_opt(
        &format!("SELECT {CERT_COLUMNS} FROM certificates WHERE serial = $1{lock}"),
        &[&serial],
    )?;
    match row {
        Some(r) => Ok(Some(cert_row(&r)?.decode()?)),
        None => Ok(None),
    }
}

impl CaStore for PostgresStore {
    fn backend(&self) -> &'static str {
        "postgres"
    }

    fn ping(&self) -> StoreResult<()> {
        self.read(|c| {
            c.simple_query("SELECT 1")?;
            Ok(())
        })
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
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NULL, NULL, NULL)"
                ),
                &[
                    &row.serial,
                    &row.common_name,
                    &row.dns_names,
                    &row.ip_addresses,
                    &row.profile,
                    &row.key_algorithm,
                    &row.issuance_method,
                    &row.requested_by,
                    &row.not_before,
                    &row.not_after,
                    &row.fingerprint_sha256,
                    &row.cert_pem,
                    &row.created_at,
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
        self.read(|c| get_cert(c, serial, false))
    }

    fn list_certificates(&self, filter: &CertFilter) -> StoreResult<Vec<CertificateRecord>> {
        let now = now_unix();
        let search = filter.search_pattern();
        let status = filter.status.map(|s| s.as_str());
        let limit = i64::from(filter.effective_limit());
        let offset = i64::from(filter.offset);
        self.read(|c| {
            let rows = c.query(
                &format!(
                    "SELECT {CERT_COLUMNS} FROM certificates
                     WHERE ($1::TEXT IS NULL OR requested_by = $1)
                       AND ($2::TEXT IS NULL OR lower(common_name) LIKE $2 ESCAPE '\\'
                                         OR lower(dns_names) LIKE $2 ESCAPE '\\')
                       AND ($3::TEXT IS NULL
                            OR ($3 = 'revoked' AND revoked_at IS NOT NULL)
                            OR ($3 = 'expired' AND revoked_at IS NULL AND not_after < $4)
                            OR ($3 = 'active'  AND revoked_at IS NULL AND not_after >= $4))
                     ORDER BY created_at DESC, serial
                     LIMIT $5 OFFSET $6"
                ),
                &[&filter.requested_by, &search, &status, &now, &limit, &offset],
            )?;
            decode_all(&rows)
        })
    }

    fn expiring_within(&self, days: u32) -> StoreResult<Vec<CertificateRecord>> {
        let now = now_unix();
        let horizon = now + i64::from(days) * 86_400;
        self.read(|c| {
            let rows = c.query(
                &format!(
                    "SELECT {CERT_COLUMNS} FROM certificates
                     WHERE revoked_at IS NULL AND not_after >= $1 AND not_after < $2
                     ORDER BY not_after, serial"
                ),
                &[&now, &horizon],
            )?;
            decode_all(&rows)
        })
    }

    fn revoke(&self, serial: &str, reason: RevocationReason, actor: &str) -> StoreResult<RevokeOutcome> {
        self.write(|tx| {
            let Some(record) = get_cert(tx, serial, true)? else {
                return Ok(RevokeOutcome::NotFound);
            };
            if record.revoked_at.is_some() {
                return Ok(RevokeOutcome::AlreadyRevoked(Box::new(record)));
            }
            tx.execute(
                "UPDATE certificates SET revoked_at = $1, revocation_reason = $2, revoked_by = $3
                 WHERE serial = $4",
                &[&now_unix(), &reason.as_str(), &actor, &serial],
            )?;
            append(
                tx,
                actor,
                events::CERT_REVOKED,
                serial,
                &events::certificate_revoked(reason),
            )?;
            let updated = get_cert(tx, serial, false)?
                .ok_or_else(|| StoreError::Corrupt(format!("{serial} vanished during revocation")))?;
            Ok(RevokeOutcome::Revoked(Box::new(updated)))
        })
    }

    fn crl_entries(&self) -> StoreResult<Vec<RevokedEntry>> {
        self.read(|c| {
            let rows = c.query(
                "SELECT serial, revoked_at, revocation_reason FROM certificates
                 WHERE revoked_at IS NOT NULL AND not_after >= $1 ORDER BY revoked_at, serial",
                &[&now_unix()],
            )?;
            rows.iter()
                .map(|r| {
                    let reason: String = r.try_get(2)?;
                    Ok(decode_revoked_entry(r.try_get(0)?, r.try_get(1)?, &reason)?)
                })
                .collect()
        })
    }

    fn revocation_revision(&self) -> StoreResult<(i64, i64)> {
        self.read(|c| {
            let r = c.query_one(
                "SELECT COUNT(*), COALESCE(MAX(revoked_at), 0)::BIGINT
                 FROM certificates WHERE revoked_at IS NOT NULL",
                &[],
            )?;
            Ok((r.try_get(0)?, r.try_get(1)?))
        })
    }

    fn next_crl_number(&self, actor: &str, revoked: usize) -> StoreResult<u64> {
        let n: i64 = self.write(|tx| {
            let n: i64 = tx
                .query_one(
                    "UPDATE crl_state SET crl_number = crl_number + 1 WHERE id = 1 RETURNING crl_number",
                    &[],
                )?
                .try_get(0)?;
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
                .query_opt(
                    "SELECT revoked_at, revocation_reason FROM certificates WHERE serial = $1",
                    &[&serial],
                )?
                .map(|r| -> Res<_> { Ok((r.try_get(0)?, r.try_get(1)?)) })
                .transpose()?;
            Ok(decode_revocation_status(row))
        })
    }

    fn create_token(&self, name: &str, role: Role, actor: &str) -> StoreResult<(TokenInfo, String)> {
        let token = NewToken::generate();
        let now = now_unix();
        let id: i64 = self.write(|tx| {
            let id: i64 = tx
                .query_one(
                    "INSERT INTO api_tokens (name, role, token_hash, token_prefix, created_at)
                     VALUES ($1, $2, $3, $4, $5) RETURNING id",
                    &[&name, &role.as_str(), &token.hash, &token.prefix, &now],
                )?
                .try_get(0)?;
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
            // One round trip: look up and record the use atomically.
            let row = c.query_opt(
                "UPDATE api_tokens SET last_used_at = $1
                 WHERE token_hash = $2 AND disabled_at IS NULL
                 RETURNING id, name, role",
                &[&now_unix(), &hash_token(token)],
            )?;
            let Some(r) = row else { return Ok(None) };
            let role: String = r.try_get(2)?;
            Ok(Some(Principal {
                token_id: r.try_get(0)?,
                name: r.try_get(1)?,
                role: role.parse()?,
            }))
        })
    }

    fn list_tokens(&self) -> StoreResult<Vec<TokenInfo>> {
        self.read(|c| {
            let rows = c.query(
                "SELECT id, name, role, token_prefix, created_at, last_used_at, disabled_at
                 FROM api_tokens ORDER BY id",
                &[],
            )?;
            rows.iter()
                .map(|r| {
                    let role: String = r.try_get(2)?;
                    Ok(TokenInfo {
                        id: r.try_get(0)?,
                        name: r.try_get(1)?,
                        role: role.parse()?,
                        prefix: r.try_get(3)?,
                        created_at: r.try_get(4)?,
                        last_used_at: r.try_get(5)?,
                        disabled_at: r.try_get(6)?,
                    })
                })
                .collect()
        })
    }

    fn disable_token(&self, name: &str, actor: &str) -> StoreResult<bool> {
        self.write(|tx| {
            let changed = tx.execute(
                "UPDATE api_tokens SET disabled_at = $1 WHERE name = $2 AND disabled_at IS NULL",
                &[&now_unix(), &name],
            )?;
            if changed > 0 {
                append(tx, actor, events::TOKEN_DISABLED, name, &events::token_disabled())?;
            }
            Ok(changed > 0)
        })
    }

    fn has_admin(&self) -> StoreResult<bool> {
        self.read(|c| {
            Ok(c.query_one(
                "SELECT EXISTS (SELECT 1 FROM api_tokens WHERE role = 'admin' AND disabled_at IS NULL)",
                &[],
            )?
            .try_get(0)?)
        })
    }

    fn audit(&self, actor: &str, action: &str, target: &str, details: &serde_json::Value) -> StoreResult<()> {
        self.write(|tx| append(tx, actor, action, target, details))
    }

    fn audit_log(&self, limit: u32) -> StoreResult<Vec<AuditRecord>> {
        self.read(|c| {
            let rows = c.query(
                "SELECT id, ts, actor, action, target, details, prev_hash, hash
                 FROM audit_log ORDER BY id DESC LIMIT $1",
                &[&i64::from(limit)],
            )?;
            rows.iter().map(|r| Ok(audit_row(r)?.into())).collect()
        })
    }

    fn verify_audit_chain(&self) -> StoreResult<AuditVerification> {
        self.read(|c| {
            // Stream through a portal so a long log is never loaded into memory at once.
            let mut tx = c.build_transaction().read_only(true).start()?;
            let portal = tx.bind(
                "SELECT id, ts, actor, action, target, details, prev_hash, hash
                 FROM audit_log ORDER BY id ASC",
                &[],
            )?;
            let mut verifier = ChainVerifier::default();
            loop {
                let rows = tx.query_portal(&portal, 1000)?;
                if rows.is_empty() {
                    break;
                }
                for r in &rows {
                    verifier.push(&audit_row(r)?);
                }
            }
            tx.commit()?;
            Ok(verifier.finish())
        })
    }
}
