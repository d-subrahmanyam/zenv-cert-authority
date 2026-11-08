//! Download formats for issued certificates.
//!
//! | Format      | Contents                              | Typical consumer                      |
//! |-------------|---------------------------------------|---------------------------------------|
//! | `pem`       | leaf certificate                      | nginx, HAProxy, Envoy, Go, Node       |
//! | `der`       | leaf certificate, binary              | Windows `.cer`, embedded devices      |
//! | `chain`     | leaf + intermediate (PEM)             | what a TLS server should present      |
//! | `fullchain` | leaf + intermediate + root (PEM)      | tools that want the whole path        |
//! | PKCS#12     | key + leaf + chain, password-protected| Java/Spring, .NET, IIS, Windows       |
//!
//! PKCS#12 is only available when the CA generated the key (it never holds CSR keys).

use std::fmt;
use std::str::FromStr;

use p12_keystore::{Certificate, KeyStore, KeyStoreEntry, PrivateKey, PrivateKeyChain};
use rcgen::KeyPair;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::authority::CertificateAuthority;
use crate::error::{CaError, Result};
use crate::hierarchy::pem_to_der;

/// Minimum PKCS#12 password length.
pub const MIN_PKCS12_PASSWORD_LEN: usize = 8;

/// Certificate-only download formats.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertFormat {
    /// Leaf certificate, PEM.
    #[default]
    Pem,
    /// Leaf certificate, DER.
    Der,
    /// Leaf + intermediate, PEM.
    Chain,
    /// Leaf + intermediate + root, PEM.
    Fullchain,
}

impl CertFormat {
    /// HTTP `Content-Type` for the format.
    pub fn content_type(self) -> &'static str {
        match self {
            Self::Der => "application/pkix-cert",
            _ => "application/x-pem-file",
        }
    }

    /// Suggested file name suffix.
    pub fn file_suffix(self) -> &'static str {
        match self {
            Self::Pem => ".crt.pem",
            Self::Der => ".cer",
            Self::Chain => ".chain.pem",
            Self::Fullchain => ".fullchain.pem",
        }
    }
}

impl fmt::Display for CertFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pem => "pem",
            Self::Der => "der",
            Self::Chain => "chain",
            Self::Fullchain => "fullchain",
        })
    }
}

impl FromStr for CertFormat {
    type Err = CaError;

    fn from_str(s: &str) -> Result<Self> {
        Ok(match s {
            "pem" => Self::Pem,
            "der" => Self::Der,
            "chain" => Self::Chain,
            "fullchain" => Self::Fullchain,
            other => return Err(CaError::InvalidInput(format!("unknown format '{other}'"))),
        })
    }
}

/// Renders a stored certificate in the requested format.
pub fn render_certificate(cert_pem: &str, ca: &CertificateAuthority, format: CertFormat) -> Result<Vec<u8>> {
    Ok(match format {
        CertFormat::Pem => cert_pem.as_bytes().to_vec(),
        CertFormat::Der => pem_to_der(cert_pem, "CERTIFICATE")?,
        CertFormat::Chain => format!("{cert_pem}{}", ca.intermediate_pem()).into_bytes(),
        CertFormat::Fullchain => format!("{cert_pem}{}{}", ca.intermediate_pem(), ca.root_pem()).into_bytes(),
    })
}

/// Builds a password-protected PKCS#12 bundle (PBES2/AES-256-CBC, HMAC-SHA256), the same
/// defaults as modern JDKs, readable by OpenSSL 1.1+, Java 8u301+, .NET and Windows.
pub fn pkcs12_bundle(
    cert_pem: &str,
    key: &KeyPair,
    ca: &CertificateAuthority,
    alias: &str,
    password: &str,
) -> Result<Vec<u8>> {
    if password.chars().count() < MIN_PKCS12_PASSWORD_LEN {
        return Err(CaError::InvalidInput(format!(
            "PKCS#12 password must be at least {MIN_PKCS12_PASSWORD_LEN} characters"
        )));
    }
    let export = |e: p12_keystore::error::Error| CaError::Export(e.to_string());
    let leaf_der = pem_to_der(cert_pem, "CERTIFICATE")?;
    let certs = vec![
        Certificate::from_der(&leaf_der).map_err(export)?,
        Certificate::from_der(ca.intermediate_der()).map_err(export)?,
        Certificate::from_der(ca.root_der()).map_err(export)?,
    ];
    let key_der = Zeroizing::new(key.serialize_der());
    let private_key = PrivateKey::from_der(&key_der).map_err(export)?;
    let local_key_id = Sha256::digest(&leaf_der).to_vec();
    let chain = PrivateKeyChain::new(local_key_id, private_key, certs);

    let mut store = KeyStore::new();
    store.add_entry(alias, KeyStoreEntry::PrivateKeyChain(chain));
    store.writer(password).write().map_err(export)
}
