//! # zenv-ca-store
//!
//! The **storage contract** of the Zenv DMZ CA: the [`CaStore`] trait plus the types and
//! logic that every backend must share. It has no database dependency itself; concrete
//! backends live in their own crates and are selected at start-up:
//!
//! | Crate | Backend |
//! |---|---|
//! | `zenv-ca-store-sqlite` | embedded SQLite file (default, single host) |
//! | `zenv-ca-store-postgres` | PostgreSQL (shared database, several daemon instances) |
//!
//! What lives here, so that backends cannot drift apart:
//!
//! * the audit hash chain ([`audit::AuditRow::next`], [`audit::ChainVerifier`]) and the
//!   canonical audit events ([`audit::events`]);
//! * token generation and hashing ([`tokens::NewToken`]);
//! * the stored row format ([`certs::CertificateRow`]) and status derivation;
//! * fail-closed revocation lookups ([`Revocations`]);
//! * a backend-agnostic conformance suite (feature `testkit`) that every backend runs.
//!
//! ## Contract for implementers
//!
//! 1. Every mutating method writes its audit entry **in the same transaction** as the
//!    change, and appends are serialised so the chain has no forks or gaps.
//! 2. `details` is stored as the exact text from [`audit::AuditRow`].
//! 3. Unique-constraint violations map to [`StoreError::Conflict`].
//! 4. Methods are blocking. Async callers run them on a blocking thread pool.
//! 5. The backend passes [`testkit`]'s conformance suite.

pub mod audit;
pub mod certs;
mod error;
pub mod tokens;

#[cfg(feature = "testkit")]
pub mod testkit;

use std::fmt::Debug;

use zenv_ca_core::{IssuedCertificate, RevocationLookup, RevocationReason, RevocationStatus, RevokedEntry};

pub use audit::{AuditRecord, AuditVerification};
pub use certs::{CertFilter, CertStatus, CertificateRecord, IssuanceMethod, RevokeOutcome};
pub use error::{StoreError, StoreResult};
pub use tokens::{Principal, Role, TokenInfo};

/// Current Unix time in seconds.
pub fn now_unix() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// Persistence used by the daemon and the CLI. Object-safe: callers hold an
/// `Arc<dyn CaStore>` and never name a concrete backend.
///
/// All methods block; call them from `spawn_blocking` in async code.
pub trait CaStore: Send + Sync + Debug {
    /// Short backend name for logs and `/api/v1/ca` (`"sqlite"`, `"postgres"`).
    fn backend(&self) -> &'static str;

    /// Cheap liveness query for the readiness probe.
    fn ping(&self) -> StoreResult<()>;

    // ---- certificate inventory -------------------------------------------------------

    /// Records a newly issued certificate and its `certificate.issued` audit entry
    /// atomically. A duplicate serial or fingerprint is a [`StoreError::Conflict`] and
    /// leaves no audit entry behind.
    fn insert_certificate(
        &self,
        cert: &IssuedCertificate,
        method: IssuanceMethod,
        requested_by: &str,
    ) -> StoreResult<()>;

    /// Fetches one certificate by canonical serial.
    fn get_certificate(&self, serial: &str) -> StoreResult<Option<CertificateRecord>>;

    /// Lists certificates, newest first.
    fn list_certificates(&self, filter: &CertFilter) -> StoreResult<Vec<CertificateRecord>>;

    /// Active certificates expiring within `days`, soonest first.
    fn expiring_within(&self, days: u32) -> StoreResult<Vec<CertificateRecord>>;

    /// Revokes a certificate (idempotent) and records the audit entry atomically.
    fn revoke(&self, serial: &str, reason: RevocationReason, actor: &str) -> StoreResult<RevokeOutcome>;

    /// Revoked, not-yet-expired certificates: exactly what belongs on the CRL.
    fn crl_entries(&self) -> StoreResult<Vec<RevokedEntry>>;

    /// `(revoked count, latest revocation time)`. Changes whenever anything is revoked,
    /// by any process, so a cached CRL can be detected as stale.
    fn revocation_revision(&self) -> StoreResult<(i64, i64)>;

    /// Atomically increments and returns the CRL number (monotonic across restarts and
    /// across daemon instances), auditing `crl.generated`.
    fn next_crl_number(&self, actor: &str, revoked: usize) -> StoreResult<u64>;

    /// Revocation status of a serial; [`RevocationStatus::Unknown`] if it is not ours.
    fn revocation_status(&self, serial: &str) -> StoreResult<RevocationStatus>;

    // ---- API tokens ------------------------------------------------------------------

    /// Creates a token; returns its metadata and the plaintext, which is not recoverable
    /// afterwards. A duplicate name is a [`StoreError::Conflict`].
    fn create_token(&self, name: &str, role: Role, actor: &str) -> StoreResult<(TokenInfo, String)>;

    /// Resolves a bearer token. Unknown, malformed or disabled tokens yield `None`.
    fn authenticate(&self, token: &str) -> StoreResult<Option<Principal>>;

    /// Lists all tokens.
    fn list_tokens(&self) -> StoreResult<Vec<TokenInfo>>;

    /// Disables a token by name; `false` when no active token had that name.
    fn disable_token(&self, name: &str, actor: &str) -> StoreResult<bool>;

    /// `true` when at least one admin token is active.
    fn has_admin(&self) -> StoreResult<bool>;

    // ---- audit log -------------------------------------------------------------------

    /// Records an event that is not tied to another state change.
    fn audit(&self, actor: &str, action: &str, target: &str, details: &serde_json::Value) -> StoreResult<()>;

    /// Most recent audit entries, newest first.
    fn audit_log(&self, limit: u32) -> StoreResult<Vec<AuditRecord>>;

    /// Recomputes every hash (with [`audit::ChainVerifier`]) and checks the links.
    fn verify_audit_chain(&self) -> StoreResult<AuditVerification>;
}

/// Adapts any [`CaStore`] to [`RevocationLookup`] for `CertificateAuthority::verify`,
/// **failing closed**: a database error reports [`RevocationStatus::Unknown`], which the
/// verifier treats as a failed check, never as "good".
#[derive(Debug, Clone, Copy)]
pub struct Revocations<'a>(pub &'a dyn CaStore);

impl RevocationLookup for Revocations<'_> {
    fn status(&self, serial: &str) -> RevocationStatus {
        self.0.revocation_status(serial).unwrap_or_else(|e| {
            tracing::error!(error = %e, backend = self.0.backend(), "revocation lookup failed");
            RevocationStatus::Unknown
        })
    }
}
