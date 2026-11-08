//! Storage backend selection: the **only** place that knows which backend crates exist.
//!
//! Everything else (handlers, the CRL cache, the CLI) works against
//! `Arc<dyn zenv_ca_store::CaStore>`. Backends are compiled in with Cargo features:
//!
//! | Feature | Crate | `[database] backend` |
//! |---|---|---|
//! | `sqlite` (default) | `zenv-ca-store-sqlite` | `"sqlite"` |
//! | `postgres` | `zenv-ca-store-postgres` | `"postgres"` |
//!
//! Adding a backend means a new crate that implements `CaStore` and passes the
//! `zenv_ca_store::testkit` suite, plus one feature and one match arm here.
//!
//! These functions **block** (connecting, migrating); call them before starting the
//! async runtime or from `spawn_blocking`.

use std::sync::Arc;

use anyhow::Context;
use zenv_ca_store::CaStore;

use crate::config::{Config, DatabaseConfig};

/// Opens (creating and migrating if needed) the configured store.
pub fn open_store(config: &Config) -> anyhow::Result<Arc<dyn CaStore>> {
    match &config.database {
        DatabaseConfig::Sqlite(_) => open_sqlite(config),
        DatabaseConfig::Postgres(_) => open_postgres(config),
    }
}

/// Whether the configured database already holds a CA (used by `zenv-ca init` to refuse
/// overwriting, and by the other commands to say "run init first").
///
/// For SQLite this only checks that the file exists, without creating it.
pub fn is_provisioned(config: &Config) -> anyhow::Result<bool> {
    match &config.database {
        DatabaseConfig::Sqlite(_) => Ok(config.sqlite_path().exists()),
        DatabaseConfig::Postgres(_) => Ok(!open_store(config)?.audit_log(1)?.is_empty()),
    }
}

/// Human-readable location for logs, without secrets.
pub fn describe(config: &Config) -> String {
    match &config.database {
        DatabaseConfig::Sqlite(_) => format!("sqlite:{}", config.sqlite_path().display()),
        DatabaseConfig::Postgres(pg) => {
            // Strip any userinfo from URL-style connection strings before logging.
            let url = match pg.url.split_once("://") {
                Some((scheme, rest)) => match rest.rsplit_once('@') {
                    Some((_, host)) => format!("{scheme}://{host}"),
                    None => pg.url.clone(),
                },
                None => "<key/value connection string>".to_owned(),
            };
            match &pg.schema {
                Some(schema) => format!("postgres:{url} (schema {schema})"),
                None => format!("postgres:{url}"),
            }
        }
    }
}

#[cfg(feature = "sqlite")]
fn open_sqlite(config: &Config) -> anyhow::Result<Arc<dyn CaStore>> {
    let path = config.sqlite_path();
    let store = zenv_ca_store_sqlite::SqliteStore::open(&path)
        .with_context(|| format!("cannot open SQLite database {}", path.display()))?;
    Ok(Arc::new(store))
}

#[cfg(not(feature = "sqlite"))]
fn open_sqlite(_: &Config) -> anyhow::Result<Arc<dyn CaStore>> {
    anyhow::bail!("this build has no SQLite support; rebuild with `--features sqlite`")
}

#[cfg(feature = "postgres")]
fn open_postgres(config: &Config) -> anyhow::Result<Arc<dyn CaStore>> {
    use zenv_ca_store_postgres::{PostgresOptions, PostgresStore};

    let DatabaseConfig::Postgres(pg) = &config.database else {
        anyhow::bail!("not a PostgreSQL configuration");
    };
    let password = crate::config::database_password_from_environment(pg)?;
    let options = PostgresOptions {
        url: pg.url.clone(),
        password: password.as_ref().map(|p| p.to_string()),
        schema: pg.schema.clone(),
        pool_size: pg.pool_size,
        connect_timeout: std::time::Duration::from_secs(pg.connect_timeout_secs),
        tls_ca_file: pg.tls_ca_file.clone(),
    };
    let store = PostgresStore::open(&options).with_context(|| format!("cannot open {}", describe(config)))?;
    Ok(Arc::new(store))
}

#[cfg(not(feature = "postgres"))]
fn open_postgres(_: &Config) -> anyhow::Result<Arc<dyn CaStore>> {
    anyhow::bail!("this build has no PostgreSQL support; rebuild with `--features postgres`")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::config::PostgresConfig;

    #[test]
    fn describe_never_prints_credentials() {
        let mut config: Config = toml::from_str(include_str!("../../../config/zenv-ca.dev.toml")).unwrap();
        assert_eq!(describe(&config), "sqlite:dev-data/zenv-ca.db");
        config.database = DatabaseConfig::Postgres(PostgresConfig {
            url: "postgresql://zenv:hunter2@db.internal:5432/ca?sslmode=require".into(),
            password_file: None,
            schema: Some("zenv_ca".into()),
            pool_size: 8,
            connect_timeout_secs: 10,
            tls_ca_file: None,
        });
        let text = describe(&config);
        assert!(!text.contains("hunter2"), "{text}");
        assert_eq!(
            text,
            "postgres:postgresql://db.internal:5432/ca?sslmode=require (schema zenv_ca)"
        );
    }
}
