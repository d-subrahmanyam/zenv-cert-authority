//! `zenv-cad`: the Zenv DMZ certificate authority daemon.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, bail};
use clap::Parser;
use tracing_subscriber::EnvFilter;
use zenv_ca_server::config::{Config, LogFormat, passphrase_from_environment};
use zenv_ca_server::routes::{Limits, router};
use zenv_ca_server::state::AppState;
use zenv_ca_server::storage;

/// Zenv DMZ certificate authority daemon.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    /// Path to the configuration file.
    #[arg(
        short,
        long,
        env = "ZENV_CA_CONFIG",
        default_value = "/etc/zenv-ca/zenv-ca.toml"
    )]
    config: PathBuf,
}

fn init_tracing(config: &Config) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.logging.filter));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false);
    match config.logging.format {
        LogFormat::Json => builder.json().flatten_event(true).init(),
        LogFormat::Pretty => builder.init(),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let config = Config::load(&args.config)?;
    init_tracing(&config);

    let passphrase = passphrase_from_environment(&config)?.context(
        "no intermediate key passphrase found: set ca.intermediate_passphrase_file, \
         ZENV_CA_INTERMEDIATE_PASSPHRASE_FILE, or a systemd credential named 'intermediate-passphrase'",
    )?;
    let ca = zenv_ca_server::load_authority(&config, passphrase.as_bytes())?;
    drop(passphrase);

    // Opening the store connects/migrates and the first CRL hits the database: blocking
    // work that must not run on an async worker thread.
    let state = {
        let config = config.clone();
        tokio::task::spawn_blocking(move || -> anyhow::Result<AppState> {
            tracing::info!(database = %storage::describe(&config), "opening store");
            let store = storage::open_store(&config)?;
            let crl_validity = time::Duration::hours(i64::from(config.crl.validity_hours));
            let state = AppState::new(ca, store, crl_validity, config.server.tls.enabled);
            // Sign an initial CRL so the distribution point works from the first request.
            state
                .refresh_crl()
                .map_err(|e| anyhow::anyhow!("cannot sign initial CRL: {e:?}"))?;
            Ok(state)
        })
        .await
        .context("start-up task panicked")??
    };
    spawn_expiry_monitor(state.clone());

    let app = router(
        state,
        Limits {
            max_body_bytes: config.server.max_body_bytes,
            timeout: Duration::from_secs(config.server.request_timeout_secs),
        },
    );

    let handle = axum_server::Handle::new();
    tokio::spawn(shutdown_on_signal(handle.clone()));
    let addr = config.server.listen;

    if config.server.tls.enabled {
        let (cert, key) = (config.tls_cert_path(), config.tls_key_path());
        if !cert.exists() || !key.exists() {
            bail!(
                "TLS is enabled but {} / {} are missing (run `zenv-ca tls issue`)",
                cert.display(),
                key.display()
            );
        }
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert, &key)
            .await
            .context("cannot load TLS certificate/key")?;
        tracing::info!(%addr, public_url = %config.server.public_url, "zenv-cad listening (HTTPS)");
        axum_server::bind_rustls(addr, tls)
            .handle(handle)
            .serve(app.into_make_service())
            .await?;
    } else {
        tracing::warn!(%addr, "TLS disabled: only run like this behind a TLS-terminating proxy");
        axum_server::bind(addr)
            .handle(handle)
            .serve(app.into_make_service())
            .await?;
    }
    tracing::info!("zenv-cad stopped");
    Ok(())
}

/// Graceful shutdown on SIGINT / SIGTERM: stop accepting, drain for up to 10 s.
async fn shutdown_on_signal(handle: axum_server::Handle) {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! { () = ctrl_c => {}, () = term => {} }
    tracing::info!("shutdown signal received, draining connections");
    handle.graceful_shutdown(Some(Duration::from_secs(10)));
}

/// Logs a warning every 12 h for certificates expiring within 14 days. Hook alerting
/// (Prometheus/Alertmanager, email, chat) onto these log lines or extend this task.
fn spawn_expiry_monitor(state: AppState) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(12 * 3600));
        loop {
            tick.tick().await;
            let result = state.blocking(|s| Ok(s.store().expiring_within(14)?)).await;
            match result {
                Ok(certs) => {
                    for c in certs {
                        tracing::warn!(serial = %c.serial, cn = %c.common_name, owner = %c.requested_by,
                            not_after = c.not_after, "certificate expires within 14 days");
                    }
                }
                Err(e) => tracing::error!(error = ?e, "expiry check failed"),
            }
        }
    });
}
