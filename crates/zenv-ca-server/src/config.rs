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
    /// Storage backend (SQLite by default).
    #[serde(default)]
    pub database: DatabaseConfig,
}

/// Storage backend selection, keyed by `backend`:
///
/// ```toml
/// [database]
/// backend = "sqlite"                # default; file at <data_dir>/zenv-ca.db
///
/// [database]
/// backend = "postgres"
/// url = "postgresql://zenv_ca@db.dmz.zenv.internal/zenv_ca?sslmode=require"
/// password_file = "/etc/zenv-ca/db-password"
/// ```
///
/// A backend must also be compiled in (Cargo features `sqlite`, `postgres`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "backend", rename_all = "lowercase")]
pub enum DatabaseConfig {
    /// Embedded SQLite file.
    Sqlite(SqliteConfig),
    /// PostgreSQL server.
    Postgres(PostgresConfig),
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self::Sqlite(SqliteConfig::default())
    }
}

impl DatabaseConfig {
    /// Backend name as written in the config.
    pub fn backend(&self) -> &'static str {
        match self {
            Self::Sqlite(_) => "sqlite",
            Self::Postgres(_) => "postgres",
        }
    }
}

/// `[database]` with `backend = "sqlite"`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SqliteConfig {
    /// Database file. Defaults to `<data_dir>/zenv-ca.db`.
    #[serde(default)]
    pub path: Option<PathBuf>,
}

/// `[database]` with `backend = "postgres"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresConfig {
    /// libpq-style URL **without** the password; add `sslmode=require` for remote hosts.
    pub url: String,
    /// File containing the password. Prefer the systemd credential `database-password`.
    #[serde(default)]
    pub password_file: Option<PathBuf>,
    /// Schema for the CA's tables (must already exist). Defaults to the role's
    /// `search_path`.
    #[serde(default)]
    pub schema: Option<String>,
    /// Maximum pooled connections per daemon instance.
    #[serde(default = "default_pool_size")]
    pub pool_size: u32,
    /// Connect / pool checkout timeout.
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,
    /// PEM CA bundle that signed the database server's certificate (defaults to the OS
    /// trust store).
    #[serde(default)]
    pub tls_ca_file: Option<PathBuf>,
}

fn default_pool_size() -> u32 {
    8
}

fn default_connect_timeout() -> u64 {
    10
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
        if let DatabaseConfig::Postgres(pg) = &self.database {
            if pg.url.trim().is_empty() {
                bail!("database.url is required when database.backend = \"postgres\"");
            }
            if !(1..=256).contains(&pg.pool_size) {
                bail!("database.pool_size must be between 1 and 256");
            }
        }
        Ok(())
    }

    /// SQLite database file (explicit or `<data_dir>/zenv-ca.db`).
    pub fn sqlite_path(&self) -> PathBuf {
        match &self.database {
            DatabaseConfig::Sqlite(SqliteConfig { path: Some(p) }) => p.clone(),
            _ => self.paths.database(),
        }
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
    secret_from_environment(&SecretSources {
        file_env: "ZENV_CA_INTERMEDIATE_PASSPHRASE_FILE",
        config_file: config.ca.intermediate_passphrase_file.as_deref(),
        credential: "intermediate-passphrase",
        value_env: "ZENV_CA_INTERMEDIATE_PASSPHRASE",
    })
}

/// Looks for the PostgreSQL password, in order:
///
/// 1. `$ZENV_CA_DATABASE_PASSWORD_FILE`
/// 2. `database.password_file` from the config
/// 3. `$CREDENTIALS_DIRECTORY/database-password` (systemd `LoadCredential=`)
/// 4. `$ZENV_CA_DATABASE_PASSWORD` (development only)
///
/// `None` is fine when the server authenticates otherwise (peer auth over a socket,
/// `.pgpass`, client certificates).
pub fn database_password_from_environment(pg: &PostgresConfig) -> anyhow::Result<Option<Zeroizing<String>>> {
    secret_from_environment(&SecretSources {
        file_env: "ZENV_CA_DATABASE_PASSWORD_FILE",
        config_file: pg.password_file.as_deref(),
        credential: "database-password",
        value_env: "ZENV_CA_DATABASE_PASSWORD",
    })
}

/// Where to look for one secret, in priority order.
struct SecretSources<'a> {
    file_env: &'static str,
    config_file: Option<&'a Path>,
    credential: &'static str,
    value_env: &'static str,
}

fn secret_from_environment(src: &SecretSources<'_>) -> anyhow::Result<Option<Zeroizing<String>>> {
    let from_file = |p: &Path| -> anyhow::Result<Zeroizing<String>> {
        let raw = Zeroizing::new(
            std::fs::read_to_string(p).with_context(|| format!("cannot read secret file {}", p.display()))?,
        );
        Ok(Zeroizing::new(raw.trim_end_matches(['\r', '\n']).to_owned()))
    };
    if let Some(p) = std::env::var_os(src.file_env) {
        return from_file(Path::new(&p)).map(Some);
    }
    if let Some(p) = src.config_file {
        return from_file(p).map(Some);
    }
    if let Some(dir) = std::env::var_os("CREDENTIALS_DIRECTORY") {
        let p = Path::new(&dir).join(src.credential);
        if p.exists() {
            return from_file(&p).map(Some);
        }
    }
    if let Ok(value) = std::env::var(src.value_env) {
        tracing::warn!(
            variable = src.value_env,
            "using a secret from an environment variable; prefer a credentials file"
        );
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
        assert_eq!(config.database, DatabaseConfig::default());
    }

    fn with_database(section: &str) -> anyhow::Result<Config> {
        let text = format!("{}\n{section}", include_str!("../../../config/zenv-ca.dev.toml"));
        let config: Config = toml::from_str(&text)?;
        config.validate()?;
        Ok(config)
    }

    #[test]
    fn database_section_selects_backend() {
        let dev = with_database("").unwrap();
        assert_eq!(dev.database.backend(), "sqlite");
        assert_eq!(dev.sqlite_path(), PathBuf::from("dev-data/zenv-ca.db"));

        let custom = with_database("[database]\nbackend = \"sqlite\"\npath = \"/srv/ca.db\"").unwrap();
        assert_eq!(custom.sqlite_path(), PathBuf::from("/srv/ca.db"));

        let pg = with_database(
            "[database]\nbackend = \"postgres\"\nurl = \"postgresql://zenv@db/zenv_ca?sslmode=require\"\nschema = \"zenv_ca\"",
        )
        .unwrap();
        match pg.database {
            DatabaseConfig::Postgres(p) => {
                assert_eq!(p.pool_size, 8);
                assert_eq!(p.connect_timeout_secs, 10);
                assert_eq!(p.schema.as_deref(), Some("zenv_ca"));
            }
            other => panic!("{other:?}"),
        }

        // Typos and wrong-backend keys are rejected, not silently ignored.
        assert!(with_database("[database]\nbackend = \"mysql\"").is_err());
        assert!(
            with_database("[database]\nbackend = \"postgres\"").is_err(),
            "url required"
        );
        assert!(with_database("[database]\nbackend = \"sqlite\"\nurl = \"x\"").is_err());
        assert!(with_database("[database]\nbackend = \"postgres\"\nurl = \"x\"\npool = 3").is_err());
        assert!(with_database("[database]\nbackend = \"postgres\"\nurl = \" \"").is_err());
    }
}
