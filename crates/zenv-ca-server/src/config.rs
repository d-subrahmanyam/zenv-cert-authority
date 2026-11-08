//! Configuration file (`zenv-ca.toml`) shared by the daemon and the admin CLI.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use zenv_ca_core::{CaSpec, IssuancePolicy};
use zeroize::Zeroizing;

/// Top-level configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// HTTP listener settings.
    pub server: ServerConfig,
    /// Filesystem layout.
    #[serde(default)]
    pub paths: PathsConfig,
    /// CA hierarchy settings (used by `zenv-ca init`).
    pub ca: CaConfig,
    /// Issuance policy enforced on every request.
    pub policy: IssuancePolicy,
    /// CRL publication.
    #[serde(default)]
    pub crl: CrlConfig,
    /// Logging.
    #[serde(default)]
    pub logging: LoggingConfig,
}

/// HTTP listener settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Socket to bind, e.g. `0.0.0.0:8443`.
    pub listen: SocketAddr,
    /// Externally reachable base URL, embedded in certificates as the CRL location.
    pub public_url: String,
    /// TLS for the daemon itself.
    #[serde(default)]
    pub tls: TlsConfig,
    /// Maximum request body size.
    #[serde(default = "default_body_limit")]
    pub max_body_bytes: usize,
    /// Per-request timeout.
    #[serde(default = "default_timeout")]
    pub request_timeout_secs: u64,
}

fn default_body_limit() -> usize {
    64 * 1024
}
fn default_timeout() -> u64 {
    30
}

/// TLS settings for the daemon's own listener.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Serve HTTPS. Only disable this behind a TLS-terminating proxy.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Certificate chain (PEM). Defaults to `<data_dir>/tls/server.chain.pem`.
    #[serde(default)]
    pub cert: Option<PathBuf>,
    /// Private key (PEM). Defaults to `<data_dir>/tls/server.key`.
    #[serde(default)]
    pub key: Option<PathBuf>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cert: None,
            key: None,
        }
    }
}

fn default_true() -> bool {
    true
}

/// Filesystem layout under a single data directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathsConfig {
    /// Root of all state. Must be owned by the service user with mode `0700`.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("/var/lib/zenv-ca")
}

impl Default for PathsConfig {
    fn default() -> Self {
        Self {
            data_dir: default_data_dir(),
        }
    }
}

impl PathsConfig {
    /// Directory holding CA certificates and encrypted keys.
    pub fn ca_dir(&self) -> PathBuf {
        self.data_dir.join("ca")
    }
    /// Root certificate.
    pub fn root_cert(&self) -> PathBuf {
        self.ca_dir().join("root.crt")
    }
    /// Encrypted root key. **Move this offline after `init`.**
    pub fn root_key(&self) -> PathBuf {
        self.ca_dir().join("root.key.enc")
    }
    /// Intermediate certificate.
    pub fn intermediate_cert(&self) -> PathBuf {
        self.ca_dir().join("intermediate.crt")
    }
    /// Encrypted intermediate key.
    pub fn intermediate_key(&self) -> PathBuf {
        self.ca_dir().join("intermediate.key.enc")
    }
    /// SQLite database.
    pub fn database(&self) -> PathBuf {
        self.data_dir.join("zenv-ca.db")
    }
    /// Directory for the daemon's own TLS material.
    pub fn tls_dir(&self) -> PathBuf {
        self.data_dir.join("tls")
    }
}

/// CA hierarchy settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaConfig {
    /// Root CA parameters.
    pub root: CaSpec,
    /// Intermediate CA parameters.
    pub intermediate: CaSpec,
    /// File containing the intermediate key passphrase. Prefer systemd credentials
    /// (`LoadCredential=intermediate-passphrase:...`), which are picked up automatically.
    #[serde(default)]
    pub intermediate_passphrase_file: Option<PathBuf>,
    /// DNS names for the daemon's own TLS certificate (defaults to the public URL host).
    #[serde(default)]
    pub tls_hostnames: Vec<String>,
}

/// CRL publication settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrlConfig {
    /// `nextUpdate - thisUpdate`. The CRL is re-signed once half of this has elapsed and
    /// immediately after any revocation.
    #[serde(default = "default_crl_hours")]
    pub validity_hours: u32,
}

fn default_crl_hours() -> u32 {
    168
}

impl Default for CrlConfig {
    fn default() -> Self {
        Self {
            validity_hours: default_crl_hours(),
        }
    }
}

/// Log output format.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Human-friendly.
    #[default]
    Pretty,
    /// One JSON object per line (for log shippers / SIEM).
    Json,
}

/// Logging settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    /// Output format.
    #[serde(default)]
    pub format: LogFormat,
    /// `tracing` filter directive; `RUST_LOG` overrides it.
    #[serde(default = "default_filter")]
    pub filter: String,
}

fn default_filter() -> String {
    "info,tower_http=info".into()
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            format: LogFormat::default(),
            filter: default_filter(),
        }
    }
}

impl Config {
    /// Reads and validates a configuration file.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read config file {}", path.display()))?;
        let config: Self =
            toml::from_str(&text).with_context(|| format!("invalid config file {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    /// Semantic validation beyond what serde checks.
    pub fn validate(&self) -> anyhow::Result<()> {
        self.policy.validate().context("invalid [policy]")?;
        let url = &self.server.public_url;
        if !(url.starts_with("https://") || url.starts_with("http://")) || url.ends_with('/') {
            bail!("server.public_url must be an http(s) URL without a trailing slash");
        }
        if self.crl.validity_hours < 2 {
            bail!("crl.validity_hours must be at least 2");
        }
        Ok(())
    }

    /// URL embedded in issued certificates as the CRL distribution point.
    pub fn crl_url(&self) -> String {
        format!("{}/pki/crl.der", self.server.public_url)
    }

    /// Host part of the public URL.
    pub fn public_host(&self) -> Option<String> {
        let rest = self.server.public_url.split_once("://")?.1;
        let authority = rest.split('/').next()?;
        let host = if authority.starts_with('[') {
            authority.split(']').next()?.trim_start_matches('[')
        } else {
            authority.split(':').next()?
        };
        Some(host.to_owned())
    }

    /// TLS certificate path (explicit or default).
    pub fn tls_cert_path(&self) -> PathBuf {
        self.server
            .tls
            .cert
            .clone()
            .unwrap_or_else(|| self.paths.tls_dir().join("server.chain.pem"))
    }

    /// TLS key path (explicit or default).
    pub fn tls_key_path(&self) -> PathBuf {
        self.server
            .tls
            .key
            .clone()
            .unwrap_or_else(|| self.paths.tls_dir().join("server.key"))
    }
}

/// Looks for the intermediate key passphrase in non-interactive sources, in order:
///
/// 1. `$ZENV_CA_INTERMEDIATE_PASSPHRASE_FILE`
/// 2. `ca.intermediate_passphrase_file` from the config
/// 3. `$CREDENTIALS_DIRECTORY/intermediate-passphrase` (systemd `LoadCredential=`)
/// 4. `$ZENV_CA_INTERMEDIATE_PASSPHRASE` (development only, since environment variables leak easily)
pub fn passphrase_from_environment(config: &Config) -> anyhow::Result<Option<Zeroizing<String>>> {
    let from_file = |p: &Path| -> anyhow::Result<Zeroizing<String>> {
        let raw = Zeroizing::new(
            std::fs::read_to_string(p)
                .with_context(|| format!("cannot read passphrase file {}", p.display()))?,
        );
        Ok(Zeroizing::new(raw.trim_end_matches(['\r', '\n']).to_owned()))
    };
    if let Some(p) = std::env::var_os("ZENV_CA_INTERMEDIATE_PASSPHRASE_FILE") {
        return from_file(Path::new(&p)).map(Some);
    }
    if let Some(p) = &config.ca.intermediate_passphrase_file {
        return from_file(p).map(Some);
    }
    if let Some(dir) = std::env::var_os("CREDENTIALS_DIRECTORY") {
        let p = Path::new(&dir).join("intermediate-passphrase");
        if p.exists() {
            return from_file(&p).map(Some);
        }
    }
    if let Ok(value) = std::env::var("ZENV_CA_INTERMEDIATE_PASSPHRASE") {
        tracing::warn!("using passphrase from environment variable; prefer a credentials file");
        return Ok(Some(Zeroizing::new(value)));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn example_config_parses() {
        let text = include_str!("../../../config/zenv-ca.example.toml");
        let config: Config = toml::from_str(text).unwrap();
        config.validate().unwrap();
        assert_eq!(config.public_host().as_deref(), Some("ca.dmz.zenv.internal"));
        assert_eq!(config.crl_url(), "https://ca.dmz.zenv.internal:8443/pki/crl.der");
    }
}
