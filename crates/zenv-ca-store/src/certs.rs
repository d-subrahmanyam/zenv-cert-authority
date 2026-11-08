//! Certificate inventory types and the row encoding shared by all backends.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use zenv_ca_core::{CertProfile, IssuedCertificate, RevocationReason, RevocationStatus, RevokedEntry};

use crate::error::{StoreError, StoreResult};
use crate::now_unix;

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
    /// Stable string form, as stored.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Csr => "csr",
            Self::Keygen => "keygen",
        }
    }
}

impl std::str::FromStr for IssuanceMethod {
    type Err = StoreError;
    fn from_str(s: &str) -> StoreResult<Self> {
        match s {
            "csr" => Ok(Self::Csr),
            "keygen" => Ok(Self::Keygen),
            other => Err(StoreError::Corrupt(format!("unknown issuance method '{other}'"))),
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

impl CertStatus {
    /// Stable string form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    /// Status of a certificate at `now`.
    pub fn derive(revoked_at: Option<i64>, not_after: i64, now: i64) -> Self {
        if revoked_at.is_some() {
            Self::Revoked
        } else if not_after < now {
            Self::Expired
        } else {
            Self::Active
        }
    }
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
    /// Page size: 0 means the default (100); capped at 500.
    pub limit: u32,
    /// Page offset.
    pub offset: u32,
}

impl CertFilter {
    /// Page size after applying the default and the cap.
    pub fn effective_limit(&self) -> u32 {
        if self.limit == 0 { 100 } else { self.limit.min(500) }
    }

    /// `LIKE` pattern for [`search`](Self::search), lower-cased, with `%`, `_` and `\`
    /// escaped (use `ESCAPE '\'`).
    pub fn search_pattern(&self) -> Option<String> {
        self.search.as_ref().map(|s| {
            let mut out = String::with_capacity(s.len() + 2);
            out.push('%');
            for c in s.to_lowercase().chars() {
                if matches!(c, '%' | '_' | '\\') {
                    out.push('\\');
                }
                out.push(c);
            }
            out.push('%');
            out
        })
    }
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

/// Column list, in [`CertificateRow`] order. Backends use the same table layout.
pub const CERT_COLUMNS: &str = "serial, common_name, dns_names, ip_addresses, profile, key_algorithm, \
    issuance_method, requested_by, not_before, not_after, fingerprint_sha256, cert_pem, \
    created_at, revoked_at, revocation_reason, revoked_by";

/// A `certificates` row in its stored (text / integer) form. Backends read rows into this
/// and call [`CertificateRow::decode`], or build one with [`CertificateRow::encode`] to
/// insert, so the on-disk format is identical everywhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRow {
    /// `serial`
    pub serial: String,
    /// `common_name`
    pub common_name: String,
    /// `dns_names` (JSON array text)
    pub dns_names: String,
    /// `ip_addresses` (JSON array text)
    pub ip_addresses: String,
    /// `profile`
    pub profile: String,
    /// `key_algorithm`
    pub key_algorithm: String,
    /// `issuance_method`
    pub issuance_method: String,
    /// `requested_by`
    pub requested_by: String,
    /// `not_before`
    pub not_before: i64,
    /// `not_after`
    pub not_after: i64,
    /// `fingerprint_sha256`
    pub fingerprint_sha256: String,
    /// `cert_pem`
    pub cert_pem: String,
    /// `created_at`
    pub created_at: i64,
    /// `revoked_at`
    pub revoked_at: Option<i64>,
    /// `revocation_reason`
    pub revocation_reason: Option<String>,
    /// `revoked_by`
    pub revoked_by: Option<String>,
}

impl CertificateRow {
    /// Encodes a newly issued certificate (not revoked, created now).
    pub fn encode(cert: &IssuedCertificate, method: IssuanceMethod, requested_by: &str) -> StoreResult<Self> {
        let json = |v: &Vec<String>| serde_json::to_string(v).map_err(|e| StoreError::Corrupt(e.to_string()));
        Ok(Self {
            serial: cert.serial.clone(),
            common_name: cert.common_name.clone(),
            dns_names: json(&cert.dns_names)?,
            ip_addresses: json(&cert.ip_addresses)?,
            profile: cert.profile.as_str().to_owned(),
            key_algorithm: cert.key_algorithm.clone(),
            issuance_method: method.as_str().to_owned(),
            requested_by: requested_by.to_owned(),
            not_before: cert.not_before.unix_timestamp(),
            not_after: cert.not_after.unix_timestamp(),
            fingerprint_sha256: cert.fingerprint_sha256.clone(),
            cert_pem: cert.cert_pem.clone(),
            created_at: now_unix(),
            revoked_at: None,
            revocation_reason: None,
            revoked_by: None,
        })
    }

    /// Decodes a stored row; the status is derived at the current time.
    pub fn decode(self) -> StoreResult<CertificateRecord> {
        let corrupt = |field: &str, e: String| StoreError::Corrupt(format!("{}.{field}: {e}", self.serial));
        let dns_names =
            serde_json::from_str(&self.dns_names).map_err(|e| corrupt("dns_names", e.to_string()))?;
        let ip_addresses =
            serde_json::from_str(&self.ip_addresses).map_err(|e| corrupt("ip_addresses", e.to_string()))?;
        let profile = self
            .profile
            .parse::<CertProfile>()
            .map_err(|e| corrupt("profile", e.to_string()))?;
        let issuance_method = self.issuance_method.parse::<IssuanceMethod>()?;
        let revocation_reason = self
            .revocation_reason
            .as_deref()
            .map(|s| s.parse::<RevocationReason>())
            .transpose()
            .map_err(|e| corrupt("revocation_reason", e.to_string()))?;
        Ok(CertificateRecord {
            status: CertStatus::derive(self.revoked_at, self.not_after, now_unix()),
            serial: self.serial,
            common_name: self.common_name,
            dns_names,
            ip_addresses,
            profile,
            key_algorithm: self.key_algorithm,
            issuance_method,
            requested_by: self.requested_by,
            not_before: self.not_before,
            not_after: self.not_after,
            fingerprint_sha256: self.fingerprint_sha256,
            cert_pem: self.cert_pem,
            created_at: self.created_at,
            revoked_at: self.revoked_at,
            revocation_reason,
            revoked_by: self.revoked_by,
        })
    }
}

/// Decodes a `(serial, revoked_at, revocation_reason)` row into a CRL entry.
pub fn decode_revoked_entry(serial: String, revoked_at: i64, reason: &str) -> StoreResult<RevokedEntry> {
    Ok(RevokedEntry {
        revoked_at: OffsetDateTime::from_unix_timestamp(revoked_at)
            .map_err(|e| StoreError::Corrupt(format!("{serial}.revoked_at: {e}")))?,
        reason: reason
            .parse()
            .map_err(|e: zenv_ca_core::CaError| StoreError::Corrupt(format!("{serial}.reason: {e}")))?,
        serial,
    })
}

/// Maps the `(revoked_at, revocation_reason)` of a looked-up serial (`None` when the
/// serial is not in the inventory) to a [`RevocationStatus`].
pub fn decode_revocation_status(row: Option<(Option<i64>, Option<String>)>) -> RevocationStatus {
    match row {
        None => RevocationStatus::Unknown,
        Some((None, _)) => RevocationStatus::Good,
        Some((Some(revoked_at), reason)) => RevocationStatus::Revoked {
            revoked_at,
            reason: reason.and_then(|r| r.parse().ok()).unwrap_or_default(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_pattern_escapes_wildcards() {
        let f = CertFilter {
            search: Some("A_b%c\\".into()),
            ..CertFilter::default()
        };
        assert_eq!(f.search_pattern().as_deref(), Some("%a\\_b\\%c\\\\%"));
        assert_eq!(CertFilter::default().effective_limit(), 100);
        assert_eq!(
            CertFilter {
                limit: 9999,
                ..CertFilter::default()
            }
            .effective_limit(),
            500
        );
    }
}
