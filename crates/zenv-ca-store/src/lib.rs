//! # zenv-ca-store
//!
//! SQLite-backed persistence for the CA daemon.
//!
//! * **Certificate inventory**: every issued certificate (never private keys).
//! * **API tokens**: stored as SHA-256 hashes only; plaintext is shown once at creation.
//! * **Audit log**: append-only and *hash-chained*: each entry commits to the previous
//!   one, so editing or deleting a row is detectable with [`Store::verify_audit_chain`].
//!
//! Every state change and its audit entry are written in **one transaction**, so the log
//! can never disagree with the inventory.
//!
//! SQLite (WAL mode) is plenty for a departmental CA; the schema is plain SQL so moving
//! to PostgreSQL later is mechanical.

mod audit;
mod certs;
mod error;
mod schema;
mod tokens;

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::Connection;

pub use audit::{AuditRecord, AuditVerification};
pub use certs::{CertFilter, CertStatus, CertificateRecord, IssuanceMethod, RevokeOutcome};
pub use error::{StoreError, StoreResult};
pub use tokens::{Principal, Role, TokenInfo};

/// Handle to the CA database. Cheap to share behind an `Arc`.
///
/// Access is serialised through a mutex: SQLite allows one writer at a time anyway and
/// every operation here takes microseconds. Async callers should invoke these methods
/// from `spawn_blocking`.
#[derive(Debug)]
pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    /// Opens (creating if needed) the database at `path` and applies migrations.
    /// On Unix the file is restricted to the owner (`0600`).
    pub fn open(path: &Path) -> StoreResult<Self> {
        let conn = Connection::open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| StoreError::Io(e.to_string()))?;
        }
        Self::init(conn, true)
    }

    /// Opens a private in-memory database (tests, dry runs).
    pub fn open_in_memory() -> StoreResult<Self> {
        Self::init(Connection::open_in_memory()?, false)
    }

    fn init(conn: Connection, wal: bool) -> StoreResult<Self> {
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
}

fn now_unix() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

impl Store {
    /// Cheap liveness query used by the readiness probe.
    pub fn ping(&self) -> StoreResult<()> {
        self.conn().query_row("SELECT 1", [], |_| Ok(()))?;
        Ok(())
    }
}
