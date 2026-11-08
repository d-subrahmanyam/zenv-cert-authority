use thiserror::Error;

/// Errors raised by any storage backend.
///
/// Backends map their driver errors onto these variants so that callers (the daemon, the
/// CLI) never depend on a particular database crate.
#[derive(Debug, Error)]
pub enum StoreError {
    /// The underlying database failed (connection lost, I/O, SQL error, ...).
    #[error("database error: {0}")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
    /// A uniqueness constraint was violated (duplicate serial, fingerprint or token name).
    #[error("already exists: {0}")]
    Conflict(String),
    /// Filesystem error while preparing the database.
    #[error("I/O error: {0}")]
    Io(String),
    /// A row could not be decoded (corrupted or hand-edited database).
    #[error("corrupt record: {0}")]
    Corrupt(String),
    /// The database was created by a newer version of the software.
    #[error("unsupported schema version {0}")]
    SchemaTooNew(i64),
    /// The backend was configured incorrectly or is not compiled in.
    #[error("storage configuration error: {0}")]
    Configuration(String),
}

impl StoreError {
    /// Wraps any driver error as [`StoreError::Backend`].
    pub fn backend(e: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Backend(Box::new(e))
    }
}

/// Convenience alias.
pub type StoreResult<T> = Result<T, StoreError>;
