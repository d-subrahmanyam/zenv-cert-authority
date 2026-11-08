use thiserror::Error;

/// Errors raised by the store.
#[derive(Debug, Error)]
pub enum StoreError {
    /// Underlying SQLite failure.
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    /// Filesystem error while preparing the database file.
    #[error("I/O error: {0}")]
    Io(String),
    /// A row could not be decoded (corrupted or hand-edited database).
    #[error("corrupt record: {0}")]
    Corrupt(String),
    /// The database was created by a newer version of the software.
    #[error("unsupported schema version {0}")]
    SchemaTooNew(i64),
}

/// Convenience alias.
pub type StoreResult<T> = Result<T, StoreError>;
