//! Hash-chained, append-only audit log: the parts every backend must agree on.
//!
//! `hash = SHA-256(prev_hash | id | ts | actor | action | target | details)`, each field
//! followed by the 0x1f unit separator, with the first entry chained to 64 zeros.
//!
//! Backends only *store* entries. Hash computation ([`AuditRow::next`]) and chain
//! verification ([`ChainVerifier`]) live here, so a log written by one backend verifies
//! identically after migrating to another.
//!
//! **Backends must store `details` as the exact text produced here** (e.g. `TEXT`, not
//! PostgreSQL `JSONB`, which re-serialises it and would break the hashes).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::now_unix;

/// `prev_hash` of the first entry.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// One audit entry as returned to callers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Sequence number (1, 2, 3, ... without gaps).
    pub id: i64,
    /// Unix timestamp.
    pub ts: i64,
    /// Who did it (token name, `cli:<user>`, `system`).
    pub actor: String,
    /// What happened (`certificate.issued`, `certificate.revoked`, ...).
    pub action: String,
    /// What it happened to (serial, token name, ...).
    pub target: String,
    /// Extra JSON details.
    pub details: serde_json::Value,
    /// Hash of the previous entry.
    pub prev_hash: String,
    /// Hash of this entry.
    pub hash: String,
}

/// Result of [`CaStore::verify_audit_chain`](crate::CaStore::verify_audit_chain).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditVerification {
    /// Number of entries checked.
    pub entries: u64,
    /// `true` when the chain is intact.
    pub intact: bool,
    /// First entry whose hash or link does not match, if any.
    pub first_broken_id: Option<i64>,
    /// Hash of the newest entry (publish this externally as a checkpoint).
    pub head_hash: String,
}

/// An audit row exactly as stored (details as text). Also the shape of a new entry
/// produced by [`AuditRow::next`] for a backend to `INSERT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRow {
    /// Sequence number.
    pub id: i64,
    /// Unix timestamp.
    pub ts: i64,
    /// Actor.
    pub actor: String,
    /// Action.
    pub action: String,
    /// Target.
    pub target: String,
    /// JSON details, as the exact stored text.
    pub details: String,
    /// Previous hash.
    pub prev_hash: String,
    /// This entry's hash.
    pub hash: String,
}

impl From<AuditRow> for AuditRecord {
    fn from(r: AuditRow) -> Self {
        Self {
            id: r.id,
            ts: r.ts,
            actor: r.actor,
            action: r.action,
            target: r.target,
            details: serde_json::from_str(&r.details).unwrap_or(serde_json::Value::String(r.details)),
            prev_hash: r.prev_hash,
            hash: r.hash,
        }
    }
}

impl AuditRow {
    /// Builds the entry that follows `last`, the `(id, hash)` of the newest stored entry
    /// (`None` for an empty log).
    ///
    /// The backend must read `last` and insert the result **inside the same transaction
    /// as the change being audited**, while holding a lock that serialises appenders
    /// (SQLite's write lock; an advisory lock on PostgreSQL).
    pub fn next(
        last: Option<(i64, String)>,
        actor: &str,
        action: &str,
        target: &str,
        details: &serde_json::Value,
    ) -> Self {
        let (id, prev_hash) = match last {
            Some((id, hash)) => (id + 1, hash),
            None => (1, GENESIS_HASH.to_owned()),
        };
        let ts = now_unix();
        let details = details.to_string();
        let hash = entry_hash(&prev_hash, id, ts, actor, action, target, &details);
        Self {
            id,
            ts,
            actor: actor.to_owned(),
            action: action.to_owned(),
            target: target.to_owned(),
            details,
            prev_hash,
            hash,
        }
    }
}

/// Computes an entry's hash.
pub fn entry_hash(
    prev: &str,
    id: i64,
    ts: i64,
    actor: &str,
    action: &str,
    target: &str,
    details: &str,
) -> String {
    let mut h = Sha256::new();
    for part in [
        prev,
        &id.to_string(),
        &ts.to_string(),
        actor,
        action,
        target,
        details,
    ] {
        h.update(part.as_bytes());
        h.update(b"\x1f"); // unit separator: unambiguous field boundaries
    }
    hex::encode(h.finalize())
}

/// Streaming verifier: feed rows in ascending `id` order, then call [`finish`](Self::finish).
#[derive(Debug)]
pub struct ChainVerifier {
    expected_prev: String,
    expected_id: i64,
    entries: u64,
    first_broken_id: Option<i64>,
}

impl Default for ChainVerifier {
    fn default() -> Self {
        Self {
            expected_prev: GENESIS_HASH.to_owned(),
            expected_id: 1,
            entries: 0,
            first_broken_id: None,
        }
    }
}

impl ChainVerifier {
    /// Checks one row against the chain so far.
    pub fn push(&mut self, row: &AuditRow) {
        self.entries += 1;
        let recomputed = entry_hash(
            &row.prev_hash,
            row.id,
            row.ts,
            &row.actor,
            &row.action,
            &row.target,
            &row.details,
        );
        let ok = row.id == self.expected_id && row.prev_hash == self.expected_prev && recomputed == row.hash;
        if !ok && self.first_broken_id.is_none() {
            self.first_broken_id = Some(row.id);
        }
        self.expected_prev.clone_from(&row.hash);
        self.expected_id = row.id + 1;
    }

    /// The verdict.
    pub fn finish(self) -> AuditVerification {
        AuditVerification {
            entries: self.entries,
            intact: self.first_broken_id.is_none(),
            first_broken_id: self.first_broken_id,
            head_hash: self.expected_prev,
        }
    }
}

/// Canonical audit actions and their `details` payloads, shared by all backends so the
/// log reads the same whichever database produced it.
pub mod events {
    use serde_json::{Value, json};
    use zenv_ca_core::{IssuedCertificate, RevocationReason};

    use crate::{IssuanceMethod, Role};

    /// A certificate was issued.
    pub const CERT_ISSUED: &str = "certificate.issued";
    /// A certificate was revoked.
    pub const CERT_REVOKED: &str = "certificate.revoked";
    /// An API token was created.
    pub const TOKEN_CREATED: &str = "token.created";
    /// An API token was disabled.
    pub const TOKEN_DISABLED: &str = "token.disabled";
    /// A CRL number was allocated (a CRL was signed).
    pub const CRL_GENERATED: &str = "crl.generated";

    /// Details for [`CERT_ISSUED`].
    pub fn certificate_issued(cert: &IssuedCertificate, method: IssuanceMethod) -> Value {
        json!({
            "common_name": cert.common_name,
            "dns_names": cert.dns_names,
            "ip_addresses": cert.ip_addresses,
            "profile": cert.profile.as_str(),
            "method": method.as_str(),
            "not_after": cert.not_after.unix_timestamp(),
            "fingerprint_sha256": cert.fingerprint_sha256,
        })
    }

    /// Details for [`CERT_REVOKED`].
    pub fn certificate_revoked(reason: RevocationReason) -> Value {
        json!({ "reason": reason.as_str() })
    }

    /// Details for [`TOKEN_CREATED`].
    pub fn token_created(role: Role, prefix: &str) -> Value {
        json!({ "role": role.as_str(), "prefix": prefix })
    }

    /// Details for [`TOKEN_DISABLED`].
    pub fn token_disabled() -> Value {
        json!({})
    }

    /// Details for [`CRL_GENERATED`].
    pub fn crl_generated(entries: usize) -> Value {
        json!({ "entries": entries })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_detects_edits_and_gaps() {
        let a = AuditRow::next(None, "x", "a", "t", &serde_json::json!({}));
        let b = AuditRow::next(
            Some((a.id, a.hash.clone())),
            "x",
            "b",
            "t",
            &serde_json::json!({"k": 1}),
        );
        let mut v = ChainVerifier::default();
        v.push(&a);
        v.push(&b);
        let ok = v.finish();
        assert!(ok.intact);
        assert_eq!(ok.entries, 2);
        assert_eq!(ok.head_hash, b.hash);

        let mut edited = b.clone();
        edited.actor = "mallory".into();
        let mut v = ChainVerifier::default();
        v.push(&a);
        v.push(&edited);
        assert_eq!(v.finish().first_broken_id, Some(2));

        // Deleting the first entry breaks the chain at the new first row.
        let mut v = ChainVerifier::default();
        v.push(&b);
        assert_eq!(v.finish().first_broken_id, Some(2));
    }
}
