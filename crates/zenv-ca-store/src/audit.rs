//! Hash-chained, append-only audit log.
//!
//! `hash = SHA-256(prev_hash | id | ts | actor | action | target | details)`, with the
//! first entry chained to 64 zeros. Combined with the SQL triggers that block `UPDATE` and
//! `DELETE`, tampering requires rewriting the file *and* recomputing every later hash;
//! exporting the latest hash periodically (e.g. to the SIEM) makes even that detectable.

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::StoreResult;
use crate::{Store, now_unix};

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// One audit entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Sequence number.
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

/// Result of [`Store::verify_audit_chain`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditVerification {
    /// Number of entries checked.
    pub entries: u64,
    /// `true` when the chain is intact.
    pub intact: bool,
    /// First entry whose hash does not match, if any.
    pub first_broken_id: Option<i64>,
    /// Hash of the newest entry (publish this externally as a checkpoint).
    pub head_hash: String,
}

fn entry_hash(
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

/// Appends an entry using an existing connection/transaction.
pub(crate) fn append(
    conn: &Connection,
    actor: &str,
    action: &str,
    target: &str,
    details: &serde_json::Value,
) -> StoreResult<()> {
    let last: Option<(i64, String)> = conn
        .query_row(
            "SELECT id, hash FROM audit_log ORDER BY id DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (id, prev) = match last {
        Some((id, hash)) => (id + 1, hash),
        None => (1, GENESIS.to_string()),
    };
    let ts = now_unix();
    let details = details.to_string();
    let hash = entry_hash(&prev, id, ts, actor, action, target, &details);
    conn.execute(
        "INSERT INTO audit_log (id, ts, actor, action, target, details, prev_hash, hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![id, ts, actor, action, target, details, prev, hash],
    )?;
    Ok(())
}

impl Store {
    /// Records an event that is not tied to another state change (e.g. a failed login).
    pub fn audit(
        &self,
        actor: &str,
        action: &str,
        target: &str,
        details: &serde_json::Value,
    ) -> StoreResult<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        append(&tx, actor, action, target, details)?;
        tx.commit()?;
        Ok(())
    }

    /// Most recent audit entries, newest first.
    pub fn audit_log(&self, limit: u32) -> StoreResult<Vec<AuditRecord>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id, ts, actor, action, target, details, prev_hash, hash
             FROM audit_log ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], |r| {
            let details: String = r.get(5)?;
            Ok(AuditRecord {
                id: r.get(0)?,
                ts: r.get(1)?,
                actor: r.get(2)?,
                action: r.get(3)?,
                target: r.get(4)?,
                details: serde_json::from_str(&details).unwrap_or(serde_json::Value::String(details)),
                prev_hash: r.get(6)?,
                hash: r.get(7)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Recomputes every hash and checks the links between entries.
    pub fn verify_audit_chain(&self) -> StoreResult<AuditVerification> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id, ts, actor, action, target, details, prev_hash, hash
             FROM audit_log ORDER BY id ASC",
        )?;
        let mut rows = stmt.query([])?;
        let mut expected_prev = GENESIS.to_string();
        let mut expected_id = 1_i64;
        let mut entries = 0_u64;
        let mut first_broken_id = None;
        while let Some(r) = rows.next()? {
            let id: i64 = r.get(0)?;
            let (ts, actor, action, target, details, prev, hash): (
                i64,
                String,
                String,
                String,
                String,
                String,
                String,
            ) = (
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get(7)?,
            );
            entries += 1;
            let recomputed = entry_hash(&prev, id, ts, &actor, &action, &target, &details);
            if first_broken_id.is_none() && (id != expected_id || prev != expected_prev || recomputed != hash)
            {
                first_broken_id = Some(id);
            }
            expected_prev = hash;
            expected_id = id + 1;
        }
        Ok(AuditVerification {
            entries,
            intact: first_broken_id.is_none(),
            first_broken_id,
            head_hash: expected_prev,
        })
    }
}
