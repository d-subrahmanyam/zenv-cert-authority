//! Certificate inventory and revocation state.

use rusqlite::{OptionalExtension, Row, params};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use zenv_ca_core::{
    CertProfile, IssuedCertificate, RevocationLookup, RevocationReason, RevocationStatus, RevokedEntry,
};

use crate::audit::append;
use crate::error::{StoreError, StoreResult};
use crate::{Store, now_unix};

/// How the key pair was produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IssuanceMethod {
    /// Requester submitted a CSR; the CA never saw the private key.
    Csr,
    /// The CA generated the key and handed it over once.
    Keygen,
}

impl IssuanceMethod {
    fn as_str(self) -> &'static str {
        match self {
            Self::Csr => "csr",
            Self::Keygen => "keygen",
        }
    }
}

/// Derived lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CertStatus {
    /// Valid and not revoked.
    Active,
    /// Revoked before expiry.
    Revoked,
    /// Past `notAfter`.
    Expired,
}

/// A certificate as stored in the inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateRecord {
    /// Canonical hex serial.
    pub serial: String,
    /// Subject CN.
    pub common_name: String,
    /// DNS SANs.
    pub dns_names: Vec<String>,
    /// IP SANs.
    pub ip_addresses: Vec<String>,
    /// Profile.
    pub profile: CertProfile,
    /// Key algorithm.
    pub key_algorithm: String,
    /// CSR or server-side keygen.
    pub issuance_method: IssuanceMethod,
    /// Principal that requested it.
    pub requested_by: String,
    /// Unix `notBefore`.
    pub not_before: i64,
    /// Unix `notAfter`.
    pub not_after: i64,
    /// SHA-256 fingerprint.
    pub fingerprint_sha256: String,
    /// PEM certificate.
    pub cert_pem: String,
    /// Unix creation time.
    pub created_at: i64,
    /// Unix revocation time.
    pub revoked_at: Option<i64>,
    /// Revocation reason.
    pub revocation_reason: Option<RevocationReason>,
    /// Who revoked it.
    pub revoked_by: Option<String>,
    /// Derived status at read time.
    pub status: CertStatus,
}

/// Listing filter.
#[derive(Debug, Clone, Default)]
pub struct CertFilter {
    /// Only certificates requested by this principal.
    pub requested_by: Option<String>,
    /// Only certificates in this state.
    pub status: Option<CertStatus>,
    /// Case-insensitive substring match on CN / SANs.
    pub search: Option<String>,
    /// Page size (capped at 500).
    pub limit: u32,
    /// Page offset.
    pub offset: u32,
}

/// Result of a revocation attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevokeOutcome {
    /// Revoked now.
    Revoked(Box<CertificateRecord>),
    /// Was already revoked (idempotent).
    AlreadyRevoked(Box<CertificateRecord>),
    /// No such serial.
    NotFound,
}

const COLUMNS: &str = "serial, common_name, dns_names, ip_addresses, profile, key_algorithm,
    issuance_method, requested_by, not_before, not_after, fingerprint_sha256, cert_pem,
    created_at, revoked_at, revocation_reason, revoked_by";

fn from_row(r: &Row<'_>) -> rusqlite::Result<CertificateRecord> {
    let corrupt = |col: usize, e: String| {
        rusqlite::Error::FromSqlConversionFailure(col, rusqlite::types::Type::Text, e.into())
    };
    let dns: String = r.get(2)?;
    let ips: String = r.get(3)?;
    let profile: String = r.get(4)?;
    let method: String = r.get(6)?;
    let reason: Option<String> = r.get(14)?;
    let not_after: i64 = r.get(9)?;
    let revoked_at: Option<i64> = r.get(13)?;
    let status = if revoked_at.is_some() {
        CertStatus::Revoked
    } else if not_after < now_unix() {
        CertStatus::Expired
    } else {
        CertStatus::Active
    };
    Ok(CertificateRecord {
        serial: r.get(0)?,
        common_name: r.get(1)?,
        dns_names: serde_json::from_str(&dns).map_err(|e| corrupt(2, e.to_string()))?,
        ip_addresses: serde_json::from_str(&ips).map_err(|e| corrupt(3, e.to_string()))?,
        profile: profile
            .parse()
            .map_err(|e: zenv_ca_core::CaError| corrupt(4, e.to_string()))?,
        key_algorithm: r.get(5)?,
        issuance_method: match method.as_str() {
            "csr" => IssuanceMethod::Csr,
            "keygen" => IssuanceMethod::Keygen,
            other => return Err(corrupt(6, format!("unknown issuance method {other}"))),
        },
        requested_by: r.get(7)?,
        not_before: r.get(8)?,
        not_after,
        fingerprint_sha256: r.get(10)?,
        cert_pem: r.get(11)?,
        created_at: r.get(12)?,
        revoked_at,
        revocation_reason: reason
            .map(|s| {
                s.parse()
                    .map_err(|e: zenv_ca_core::CaError| corrupt(14, e.to_string()))
            })
            .transpose()?,
        revoked_by: r.get(15)?,
        status,
    })
}

impl Store {
    /// Records a newly issued certificate (and its audit entry) atomically.
    pub fn insert_certificate(
        &self,
        cert: &IssuedCertificate,
        method: IssuanceMethod,
        requested_by: &str,
    ) -> StoreResult<()> {
        let to_json =
            |v: &Vec<String>| serde_json::to_string(v).map_err(|e| StoreError::Corrupt(e.to_string()));
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute(
            &format!("INSERT INTO certificates ({COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, NULL, NULL, NULL)"),
            params![
                cert.serial,
                cert.common_name,
                to_json(&cert.dns_names)?,
                to_json(&cert.ip_addresses)?,
                cert.profile.as_str(),
                cert.key_algorithm,
                method.as_str(),
                requested_by,
                cert.not_before.unix_timestamp(),
                cert.not_after.unix_timestamp(),
                cert.fingerprint_sha256,
                cert.cert_pem,
                now_unix(),
            ],
        )?;
        append(
            &tx,
            requested_by,
            "certificate.issued",
            &cert.serial,
            &serde_json::json!({
                "common_name": cert.common_name,
                "dns_names": cert.dns_names,
                "ip_addresses": cert.ip_addresses,
                "profile": cert.profile.as_str(),
                "method": method.as_str(),
                "not_after": cert.not_after.unix_timestamp(),
                "fingerprint_sha256": cert.fingerprint_sha256,
            }),
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Fetches one certificate by canonical serial.
    pub fn get_certificate(&self, serial: &str) -> StoreResult<Option<CertificateRecord>> {
        let conn = self.conn();
        Ok(conn
            .query_row(
                &format!("SELECT {COLUMNS} FROM certificates WHERE serial = ?1"),
                [serial],
                from_row,
            )
            .optional()?)
    }

    /// Lists certificates, newest first.
    pub fn list_certificates(&self, filter: &CertFilter) -> StoreResult<Vec<CertificateRecord>> {
        let now = now_unix();
        let limit = if filter.limit == 0 {
            100
        } else {
            filter.limit.min(500)
        };
        let search = filter
            .search
            .as_ref()
            .map(|s| format!("%{}%", s.to_ascii_lowercase()));
        let status = filter.status.map(|s| match s {
            CertStatus::Active => "active",
            CertStatus::Revoked => "revoked",
            CertStatus::Expired => "expired",
        });
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {COLUMNS} FROM certificates
             WHERE (?1 IS NULL OR requested_by = ?1)
               AND (?2 IS NULL OR lower(common_name) LIKE ?2 OR lower(dns_names) LIKE ?2)
               AND (?3 IS NULL
                    OR (?3 = 'revoked' AND revoked_at IS NOT NULL)
                    OR (?3 = 'expired' AND revoked_at IS NULL AND not_after < ?4)
                    OR (?3 = 'active'  AND revoked_at IS NULL AND not_after >= ?4))
             ORDER BY created_at DESC, serial
             LIMIT ?5 OFFSET ?6"
        ))?;
        let rows = stmt.query_map(
            params![filter.requested_by, search, status, now, limit, filter.offset],
            from_row,
        )?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Active certificates expiring within `days` (for notifications).
    pub fn expiring_within(&self, days: u32) -> StoreResult<Vec<CertificateRecord>> {
        let now = now_unix();
        let horizon = now + i64::from(days) * 86_400;
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {COLUMNS} FROM certificates
             WHERE revoked_at IS NULL AND not_after >= ?1 AND not_after < ?2
             ORDER BY not_after"
        ))?;
        let rows = stmt.query_map(params![now, horizon], from_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Revokes a certificate (idempotent), recording the audit entry atomically.
    pub fn revoke(&self, serial: &str, reason: RevocationReason, actor: &str) -> StoreResult<RevokeOutcome> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let existing = tx
            .query_row(
                &format!("SELECT {COLUMNS} FROM certificates WHERE serial = ?1"),
                [serial],
                from_row,
            )
            .optional()?;
        let Some(record) = existing else {
            return Ok(RevokeOutcome::NotFound);
        };
        if record.revoked_at.is_some() {
            return Ok(RevokeOutcome::AlreadyRevoked(Box::new(record)));
        }
        let now = now_unix();
        tx.execute(
            "UPDATE certificates SET revoked_at = ?1, revocation_reason = ?2, revoked_by = ?3 WHERE serial = ?4",
            params![now, reason.as_str(), actor, serial],
        )?;
        append(
            &tx,
            actor,
            "certificate.revoked",
            serial,
            &serde_json::json!({ "reason": reason.as_str() }),
        )?;
        let updated = tx.query_row(
            &format!("SELECT {COLUMNS} FROM certificates WHERE serial = ?1"),
            [serial],
            from_row,
        )?;
        tx.commit()?;
        Ok(RevokeOutcome::Revoked(Box::new(updated)))
    }

    /// Revoked certificates that have not yet expired: exactly what belongs on the CRL
    /// (RFC 5280 allows dropping entries once the certificate has expired).
    pub fn crl_entries(&self) -> StoreResult<Vec<RevokedEntry>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT serial, revoked_at, revocation_reason FROM certificates
             WHERE revoked_at IS NOT NULL AND not_after >= ?1 ORDER BY revoked_at",
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
            Ok(RevokedEntry {
                serial,
                revoked_at: OffsetDateTime::from_unix_timestamp(ts)
                    .map_err(|e| StoreError::Corrupt(e.to_string()))?,
                reason: reason
                    .parse()
                    .map_err(|e: zenv_ca_core::CaError| StoreError::Corrupt(e.to_string()))?,
            })
        })
        .collect()
    }

    /// Cheap fingerprint of the revocation state: `(revoked count, latest revocation time)`.
    /// Changes whenever anything is revoked, including from the CLI, so the daemon can
    /// tell that a cached CRL is stale.
    pub fn revocation_revision(&self) -> StoreResult<(i64, i64)> {
        let conn = self.conn();
        Ok(conn.query_row(
            "SELECT COUNT(*), COALESCE(MAX(revoked_at), 0) FROM certificates WHERE revoked_at IS NOT NULL",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?)
    }

    /// Atomically increments and returns the CRL number (RFC 5280 requires it to be
    /// monotonically increasing).
    pub fn next_crl_number(&self, actor: &str, revoked: usize) -> StoreResult<u64> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE crl_state SET crl_number = crl_number + 1 WHERE id = 1",
            [],
        )?;
        let n: i64 = tx.query_row("SELECT crl_number FROM crl_state WHERE id = 1", [], |r| r.get(0))?;
        append(
            &tx,
            actor,
            "crl.generated",
            &n.to_string(),
            &serde_json::json!({ "entries": revoked }),
        )?;
        tx.commit()?;
        u64::try_from(n).map_err(|e| StoreError::Corrupt(e.to_string()))
    }

    /// Revocation status, also exposed through [`RevocationLookup`].
    pub fn revocation_status(&self, serial: &str) -> StoreResult<RevocationStatus> {
        let conn = self.conn();
        let row: Option<(Option<i64>, Option<String>)> = conn
            .query_row(
                "SELECT revoked_at, revocation_reason FROM certificates WHERE serial = ?1",
                [serial],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        Ok(match row {
            None => RevocationStatus::Unknown,
            Some((None, _)) => RevocationStatus::Good,
            Some((Some(ts), reason)) => RevocationStatus::Revoked {
                revoked_at: ts,
                reason: reason.and_then(|r| r.parse().ok()).unwrap_or_default(),
            },
        })
    }
}

impl RevocationLookup for Store {
    fn status(&self, serial: &str) -> RevocationStatus {
        self.revocation_status(serial).unwrap_or_else(|e| {
            tracing::error!(error = %e, "revocation lookup failed");
            // Fail closed: an unreadable inventory must not make a certificate look good.
            RevocationStatus::Unknown
        })
    }
}
