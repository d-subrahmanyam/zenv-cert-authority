//! Error type shared by every operation in the core crate.

use thiserror::Error;

/// Everything that can go wrong while operating the certificate authority.
///
/// Variants are deliberately coarse: callers (the HTTP layer, the CLI) map them to
/// user-facing responses, so each variant corresponds to a distinct *kind* of failure
/// rather than to an internal code path.
#[derive(Debug, Error)]
pub enum CaError {
    /// The request is well-formed but the issuance policy forbids it
    /// (name outside the allowed suffixes, validity too long, ...).
    #[error("policy violation: {0}")]
    Policy(String),

    /// The submitted CSR could not be parsed, or its self-signature is invalid.
    #[error("invalid certificate signing request: {0}")]
    InvalidCsr(String),

    /// Any other malformed caller input (bad PEM, bad serial, weak password, ...).
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// Key generation, encryption or decryption failed.
    #[error("key error: {0}")]
    Key(String),

    /// The CA material on disk is inconsistent (key does not match cert, broken chain, ...).
    #[error("CA configuration error: {0}")]
    Configuration(String),

    /// Building or signing an X.509 structure failed.
    #[error("certificate generation failed: {0}")]
    Generation(#[from] rcgen::Error),

    /// Encoding a certificate into a download format failed.
    #[error("export failed: {0}")]
    Export(String),
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, CaError>;
