//! # zenv-ca-server
//!
//! HTTP surface of the Zenv DMZ CA: REST API under `/api/v1`, PKI distribution under
//! `/pki`, health probes, and the self-service web UI at `/`.
//!
//! The library half is shared with the admin CLI (configuration, passphrase discovery,
//! CA loading) and with the integration tests (the router).

pub mod auth;
pub mod config;
pub mod error;
pub mod routes;
pub mod state;
pub mod storage;

use anyhow::Context;
use zenv_ca_core::CertificateAuthority;
use zenv_ca_core::keys::decrypt_private_key;

use crate::config::Config;

/// Loads the online CA (certificates + decrypted intermediate key) described by `config`.
pub fn load_authority(config: &Config, passphrase: &[u8]) -> anyhow::Result<CertificateAuthority> {
    let paths = &config.paths;
    let read = |p: std::path::PathBuf| {
        std::fs::read_to_string(&p).with_context(|| format!("cannot read {}", p.display()))
    };
    let root_pem = read(paths.root_cert())?;
    let intermediate_pem = read(paths.intermediate_cert())?;
    let key_pem = zeroize::Zeroizing::new(read(paths.intermediate_key())?);
    let key = decrypt_private_key(&key_pem, passphrase).context("cannot unlock the intermediate key")?;
    CertificateAuthority::load(
        &root_pem,
        &intermediate_pem,
        key,
        config.policy.clone(),
        Some(config.crl_url()),
    )
    .context("CA material is inconsistent")
}
