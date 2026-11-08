//! Key generation and at-rest protection of CA private keys.
//!
//! CA keys are stored as **encrypted PKCS#8** (`-----BEGIN ENCRYPTED PRIVATE KEY-----`,
//! PBES2 with PBKDF2-HMAC-SHA256 at 600 000 iterations + AES-256-CBC). The parameters are
//! chosen for interoperability: OpenSSL, Java and HSM import tools all read them
//! (`openssl pkey -in intermediate.key.enc`). The `pkcs8` crate's default (scrypt with
//! a large work factor) exceeds OpenSSL's default scrypt memory limit, so it is avoided.

use pkcs8::pkcs5::pbes2;
use pkcs8::{EncryptedPrivateKeyInfo, LineEnding, PrivateKeyInfo, SecretDocument};
use rand_core::RngCore;
use rcgen::{KeyPair, RsaKeySize, SignatureAlgorithm};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{CaError, Result};

/// PEM label used for encrypted PKCS#8 documents (RFC 5958).
const ENCRYPTED_LABEL: &str = "ENCRYPTED PRIVATE KEY";

/// PBKDF2-HMAC-SHA256 iteration count (OWASP 2023 recommendation).
pub const PBKDF2_ITERATIONS: u32 = 600_000;

/// Minimum passphrase length accepted for encrypting CA keys.
pub const MIN_PASSPHRASE_LEN: usize = 12;

/// Supported key algorithms.
///
/// ECDSA P-256 is the default: universally supported by TLS stacks, small and fast.
/// RSA is offered for legacy clients; Ed25519 is offered for modern internal services but
/// is not accepted by most browsers for TLS server certificates.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyAlgorithm {
    /// ECDSA over NIST P-256 with SHA-256 (recommended default).
    #[default]
    EcdsaP256,
    /// ECDSA over NIST P-384 with SHA-384 (used for the root and intermediate by default).
    EcdsaP384,
    /// RSA 2048-bit with SHA-256 (legacy compatibility).
    Rsa2048,
    /// RSA 3072-bit with SHA-256.
    Rsa3072,
    /// Ed25519 (modern internal services only).
    Ed25519,
}

impl KeyAlgorithm {
    /// Generates a fresh key pair for this algorithm using the OS CSPRNG.
    pub fn generate(self) -> Result<KeyPair> {
        let generated = match self {
            Self::EcdsaP256 => KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256),
            Self::EcdsaP384 => KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384),
            Self::Rsa2048 => KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, RsaKeySize::_2048),
            Self::Rsa3072 => KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, RsaKeySize::_3072),
            Self::Ed25519 => KeyPair::generate_for(&rcgen::PKCS_ED25519),
        };
        generated.map_err(|e| CaError::Key(format!("key generation failed: {e}")))
    }

    /// Human readable name, used in API responses and the audit log.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EcdsaP256 => "ecdsa-p256",
            Self::EcdsaP384 => "ecdsa-p384",
            Self::Rsa2048 => "rsa2048",
            Self::Rsa3072 => "rsa3072",
            Self::Ed25519 => "ed25519",
        }
    }
}

/// Returns `true` when the signature algorithm belongs to the RSA family.
///
/// Used to decide whether the `keyEncipherment` key usage is appropriate.
pub fn is_rsa(alg: &SignatureAlgorithm) -> bool {
    [
        &rcgen::PKCS_RSA_SHA256,
        &rcgen::PKCS_RSA_SHA384,
        &rcgen::PKCS_RSA_SHA512,
    ]
    .contains(&alg)
}

/// Serialises a private key as **unencrypted** PKCS#8 PEM.
///
/// Only used for keys generated on behalf of an end user, which are handed over once and
/// never persisted. The returned string is zeroised on drop.
pub fn private_key_pem(key: &KeyPair) -> Zeroizing<String> {
    Zeroizing::new(key.serialize_pem())
}

/// Encrypts a key pair as PKCS#8 (PBES2 / PBKDF2-SHA256 / AES-256-CBC) and returns PEM text.
pub fn encrypt_private_key(key: &KeyPair, passphrase: &[u8]) -> Result<String> {
    if passphrase.len() < MIN_PASSPHRASE_LEN {
        return Err(CaError::Key(format!(
            "passphrase must be at least {MIN_PASSPHRASE_LEN} bytes"
        )));
    }
    let der = Zeroizing::new(key.serialize_der());
    let info = PrivateKeyInfo::try_from(der.as_slice())
        .map_err(|e| CaError::Key(format!("cannot read PKCS#8 key: {e}")))?;
    let mut salt = [0u8; 16];
    let mut iv = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut salt);
    rand_core::OsRng.fill_bytes(&mut iv);
    let params = pbes2::Parameters::pbkdf2_sha256_aes256cbc(PBKDF2_ITERATIONS, &salt, &iv)
        .map_err(|e| CaError::Key(format!("bad PBES2 parameters: {e}")))?;
    let encrypted = info
        .encrypt_with_params(params, passphrase)
        .map_err(|e| CaError::Key(format!("encryption failed: {e}")))?;
    let pem = encrypted
        .to_pem(ENCRYPTED_LABEL, LineEnding::LF)
        .map_err(|e| CaError::Key(format!("PEM encoding failed: {e}")))?;
    Ok(pem.to_string())
}

/// Decrypts an encrypted PKCS#8 PEM document produced by [`encrypt_private_key`]
/// (or by `openssl pkcs8 -topk8 -v2 aes-256-cbc`).
pub fn decrypt_private_key(pem: &str, passphrase: &[u8]) -> Result<KeyPair> {
    let (label, document) = SecretDocument::from_pem(pem)
        .map_err(|e| CaError::Key(format!("cannot parse encrypted key PEM: {e}")))?;
    if label != ENCRYPTED_LABEL {
        return Err(CaError::Key(format!(
            "expected an '{ENCRYPTED_LABEL}' PEM block, found '{label}'"
        )));
    }
    let encrypted = EncryptedPrivateKeyInfo::try_from(document.as_bytes())
        .map_err(|e| CaError::Key(format!("malformed encrypted key: {e}")))?;
    let decrypted = encrypted
        .decrypt(passphrase)
        .map_err(|_| CaError::Key("decryption failed (wrong passphrase?)".into()))?;
    KeyPair::try_from(decrypted.as_bytes())
        .map_err(|e| CaError::Key(format!("decrypted key is not usable: {e}")))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use rcgen::PublicKeyData;

    #[test]
    fn encrypted_key_round_trips() {
        let key = KeyAlgorithm::EcdsaP256.generate().unwrap();
        let pem = encrypt_private_key(&key, b"correct horse battery").unwrap();
        assert!(pem.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
        let back = decrypt_private_key(&pem, b"correct horse battery").unwrap();
        assert_eq!(key.subject_public_key_info(), back.subject_public_key_info());
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let key = KeyAlgorithm::EcdsaP256.generate().unwrap();
        let pem = encrypt_private_key(&key, b"correct horse battery").unwrap();
        assert!(decrypt_private_key(&pem, b"incorrect horse battery").is_err());
    }

    #[test]
    fn short_passphrase_is_rejected() {
        let key = KeyAlgorithm::EcdsaP256.generate().unwrap();
        assert!(encrypt_private_key(&key, b"short").is_err());
    }

    #[test]
    fn rsa_detection() {
        assert!(is_rsa(&rcgen::PKCS_RSA_SHA256));
        assert!(!is_rsa(&rcgen::PKCS_ECDSA_P256_SHA256));
    }
}
