//! # zenv-ca-core
//!
//! Pure domain logic for the Zenv DMZ certificate authority. No I/O, no HTTP, no database:
//! everything here is a deterministic function of its inputs (plus the OS CSPRNG), which
//! keeps it easy to test and audit.
//!
//! * [`hierarchy`]: bootstrap the offline root and the name-constrained intermediate.
//! * [`CertificateAuthority`]: the online signer (CSR issuance, server-side keygen, CRLs).
//! * [`IssuancePolicy`]: which names and lifetimes are allowed.
//! * [`CertProfile`]: fixed key-usage templates (server / client / both).
//! * [`verify`]: chain + signature + validity + name-constraint + revocation checks.
//! * [`export`]: PEM, DER, chain, full chain and PKCS#12 encodings.
//! * [`keys`]: key generation and encrypted PKCS#8 storage of CA keys.

pub mod authority;
pub mod error;
pub mod export;
pub mod hierarchy;
pub mod keys;
pub mod policy;
pub mod profile;
pub mod revocation;
pub mod serial;
pub mod verify;

pub use authority::{
    CertificateAuthority, CrlDocument, CsrRequest, IssuedCertificate, KeygenRequest, RevokedEntry,
};
pub use error::{CaError, Result};
pub use export::CertFormat;
pub use hierarchy::{CaSpec, CaSubject, GeneratedCa};
pub use keys::KeyAlgorithm;
pub use policy::IssuancePolicy;
pub use profile::CertProfile;
pub use rcgen::KeyPair;
pub use revocation::{NoRevocationInfo, RevocationLookup, RevocationReason, RevocationStatus};
pub use verify::{Check, VerificationReport, VerifyOptions};
