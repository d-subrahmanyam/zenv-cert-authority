//! `zenv-ca`: administration CLI for the Zenv DMZ certificate authority.
//!
//! Operates directly on the data directory and database (run it on the CA host as the
//! service user). The daemon picks up changes, including revocations, without a restart.

use std::fs::{self, OpenOptions};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail, ensure};
use clap::{Parser, Subcommand, ValueEnum};
use time::OffsetDateTime;
use zenv_ca_core::export::render_certificate;
use zenv_ca_core::hierarchy::{create_intermediate, create_root};
use zenv_ca_core::keys::{MIN_PASSPHRASE_LEN, encrypt_private_key, private_key_pem};
use zenv_ca_core::serial::normalise_serial;
use zenv_ca_core::verify::openssl_fingerprint;
use zenv_ca_core::{CertFormat, CertProfile, KeyAlgorithm, KeygenRequest, RevocationReason};
use zenv_ca_server::config::{Config, passphrase_from_environment};
use zenv_ca_store::{CertFilter, CertStatus, IssuanceMethod, RevokeOutcome, Role, Store};
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(
    name = "zenv-ca",
    version,
    about = "Administer the Zenv DMZ certificate authority"
)]
struct Cli {
    /// Path to the configuration file.
    #[arg(
        short,
        long,
        global = true,
        env = "ZENV_CA_CONFIG",
        default_value = "/etc/zenv-ca/zenv-ca.toml"
    )]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Bootstrap a new CA: root + intermediate + daemon TLS cert + database + first admin token.
    Init {
        /// File with the ROOT key passphrase (prompted if omitted).
        #[arg(long)]
        root_passphrase_file: Option<PathBuf>,
        /// File with the INTERMEDIATE key passphrase (falls back to the configured sources,
        /// then a prompt).
        #[arg(long)]
        intermediate_passphrase_file: Option<PathBuf>,
        /// Name of the initial admin token.
        #[arg(long, default_value = "admin")]
        admin_name: String,
    },
    /// Manage API tokens.
    #[command(subcommand)]
    Token(TokenCmd),
    /// Inspect and revoke certificates.
    #[command(subcommand)]
    Cert(CertCmd),
    /// (Re-)issue the daemon's own TLS certificate.
    #[command(subcommand)]
    Tls(TlsCmd),
    /// Inspect the tamper-evident audit log.
    #[command(subcommand)]
    Audit(AuditCmd),
}

#[derive(Debug, Subcommand)]
enum TokenCmd {
    /// Create a token. The secret is printed once.
    Create {
        /// Unique name: a person (`alice`) or a team/pipeline (`team-payments-ci`).
        #[arg(long)]
        name: String,
        #[arg(long, value_enum, default_value_t = RoleArg::Requester)]
        role: RoleArg,
    },
    /// List tokens.
    List,
    /// Disable a token immediately.
    Disable {
        #[arg(long)]
        name: String,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RoleArg {
    Requester,
    Admin,
}

#[derive(Debug, Subcommand)]
enum CertCmd {
    /// List certificates.
    List {
        #[arg(long, value_enum)]
        status: Option<StatusArg>,
        #[arg(long)]
        owner: Option<String>,
        #[arg(long)]
        search: Option<String>,
        /// Output JSON instead of a table.
        #[arg(long)]
        json: bool,
    },
    /// Show one certificate (PEM to stdout with --pem).
    Show {
        serial: String,
        #[arg(long)]
        pem: bool,
    },
    /// Revoke a certificate. The daemon re-signs the CRL on its next request.
    Revoke {
        serial: String,
        #[arg(long, value_enum, default_value_t = ReasonArg::Unspecified)]
        reason: ReasonArg,
    },
    /// List active certificates expiring soon.
    Expiring {
        #[arg(long, default_value_t = 14)]
        days: u32,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum StatusArg {
    Active,
    Revoked,
    Expired,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ReasonArg {
    Unspecified,
    KeyCompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
}

impl From<ReasonArg> for RevocationReason {
    fn from(r: ReasonArg) -> Self {
        match r {
            ReasonArg::Unspecified => Self::Unspecified,
            ReasonArg::KeyCompromise => Self::KeyCompromise,
            ReasonArg::AffiliationChanged => Self::AffiliationChanged,
            ReasonArg::Superseded => Self::Superseded,
            ReasonArg::CessationOfOperation => Self::CessationOfOperation,
        }
    }
}

#[derive(Debug, Subcommand)]
enum TlsCmd {
    /// Issue a fresh TLS certificate for the daemon (restart zenv-cad afterwards).
    Issue {
        #[arg(long)]
        intermediate_passphrase_file: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum AuditCmd {
    /// Recompute the hash chain and report the head hash.
    Verify,
    /// Show the most recent entries.
    Tail {
        #[arg(long, default_value_t = 20)]
        limit: u32,
    },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    let config = Config::load(&cli.config)?;
    let actor = format!(
        "cli:{}",
        std::env::var("USER").unwrap_or_else(|_| "unknown".into())
    );

    match cli.command {
        Command::Init {
            root_passphrase_file,
            intermediate_passphrase_file,
            admin_name,
        } => init(
            &config,
            root_passphrase_file.as_deref(),
            intermediate_passphrase_file.as_deref(),
            &admin_name,
            &actor,
        ),
        Command::Token(cmd) => token(&config, cmd, &actor),
        Command::Cert(cmd) => cert(&config, cmd, &actor),
        Command::Tls(TlsCmd::Issue {
            intermediate_passphrase_file,
        }) => {
            let pass = intermediate_passphrase(&config, intermediate_passphrase_file.as_deref(), false)?;
            let ca = zenv_ca_server::load_authority(&config, pass.as_bytes())?;
            let store = open_store(&config)?;
            issue_daemon_tls(&config, &ca, &store, true)?;
            println!("Restart zenv-cad to load the new certificate.");
            Ok(())
        }
        Command::Audit(cmd) => audit(&config, cmd),
    }
}

// ---------------------------------------------------------------- helpers

fn open_store(config: &Config) -> anyhow::Result<Store> {
    let path = config.paths.database();
    ensure!(
        path.exists(),
        "database {} not found; run `zenv-ca init` first",
        path.display()
    );
    Store::open(&path).context("cannot open database")
}

fn read_secret_file(path: &Path) -> anyhow::Result<Zeroizing<String>> {
    let raw =
        Zeroizing::new(fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?);
    Ok(Zeroizing::new(raw.trim_end_matches(['\r', '\n']).to_owned()))
}

fn prompt_secret(label: &str, confirm: bool) -> anyhow::Result<Zeroizing<String>> {
    ensure!(
        std::io::stdin().is_terminal(),
        "{label} required but stdin is not a terminal; use a passphrase file"
    );
    let first = Zeroizing::new(rpassword::prompt_password(format!("{label}: "))?);
    if confirm {
        let second = Zeroizing::new(rpassword::prompt_password(format!("Confirm {label}: "))?);
        ensure!(*first == *second, "passphrases do not match");
    }
    Ok(first)
}

fn intermediate_passphrase(
    config: &Config,
    file: Option<&Path>,
    confirm: bool,
) -> anyhow::Result<Zeroizing<String>> {
    if let Some(f) = file {
        return read_secret_file(f);
    }
    if let Some(p) = passphrase_from_environment(config)? {
        return Ok(p);
    }
    prompt_secret("Intermediate key passphrase", confirm)
}

/// Writes a file that must not already exist, with explicit Unix permissions.
fn write_new(path: &Path, contents: &[u8], mode: u32) -> anyhow::Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut f = opts
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    f.write_all(contents)?;
    f.sync_all()?;
    Ok(())
}

/// Atomically replaces a file (write temp + rename) with explicit permissions.
fn write_replace(path: &Path, contents: &[u8], mode: u32) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    let _ = fs::remove_file(&tmp);
    write_new(&tmp, contents, mode)?;
    fs::rename(&tmp, path).with_context(|| format!("cannot replace {}", path.display()))?;
    Ok(())
}

fn create_private_dir(path: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(path).with_context(|| format!("cannot create {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn fmt_ts(unix: i64) -> String {
    OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|t| t.format(&time::format_description::well_known::Rfc3339).ok())
        .unwrap_or_else(|| unix.to_string())
}

// ---------------------------------------------------------------- init

fn init(
    config: &Config,
    root_pass_file: Option<&Path>,
    inter_pass_file: Option<&Path>,
    admin_name: &str,
    actor: &str,
) -> anyhow::Result<()> {
    let paths = &config.paths;
    if paths.root_cert().exists() || paths.database().exists() {
        bail!(
            "{} already contains a CA; refusing to overwrite it",
            paths.data_dir.display()
        );
    }

    let root_pass = match root_pass_file {
        Some(f) => read_secret_file(f)?,
        None => prompt_secret("Root key passphrase (store it offline)", true)?,
    };
    let inter_pass = intermediate_passphrase(config, inter_pass_file, true)?;
    ensure!(
        root_pass.len() >= MIN_PASSPHRASE_LEN,
        "root passphrase must be at least {MIN_PASSPHRASE_LEN} characters"
    );
    ensure!(
        inter_pass.len() >= MIN_PASSPHRASE_LEN,
        "intermediate passphrase must be at least {MIN_PASSPHRASE_LEN} characters"
    );
    ensure!(
        *root_pass != *inter_pass,
        "root and intermediate passphrases must differ"
    );

    create_private_dir(&paths.data_dir)?;
    create_private_dir(&paths.ca_dir())?;
    create_private_dir(&paths.tls_dir())?;

    eprintln!("Generating root CA ({}) …", config.ca.root.key_algorithm.as_str());
    let root = create_root(&config.ca.root)?;
    write_new(&paths.root_cert(), root.cert_pem.as_bytes(), 0o644)?;
    write_new(
        &paths.root_key(),
        encrypt_private_key(&root.key, root_pass.as_bytes())?.as_bytes(),
        0o600,
    )?;

    eprintln!(
        "Generating intermediate CA ({}) with name constraints …",
        config.ca.intermediate.key_algorithm.as_str()
    );
    let inter = create_intermediate(&root.cert_pem, &root.key, &config.ca.intermediate, &config.policy)?;
    write_new(&paths.intermediate_cert(), inter.cert_pem.as_bytes(), 0o644)?;
    write_new(
        &paths.intermediate_key(),
        encrypt_private_key(&inter.key, inter_pass.as_bytes())?.as_bytes(),
        0o600,
    )?;
    drop(root);

    // Round-trip through disk exactly like the daemon will, proving the files are usable.
    let ca = zenv_ca_server::load_authority(config, inter_pass.as_bytes())?;
    let store = Store::open(&paths.database())?;
    store.audit(
        actor,
        "ca.initialised",
        &config.ca.intermediate.subject.common_name,
        &serde_json::json!({
            "root_sha256": openssl_fingerprint(ca.root_der()),
            "intermediate_sha256": openssl_fingerprint(ca.intermediate_der()),
            "allowed_dns_suffixes": config.policy.allowed_dns_suffixes,
        }),
    )?;
    if config.server.tls.enabled {
        issue_daemon_tls(config, &ca, &store, false)?;
    } else {
        eprintln!("server.tls.enabled = false: skipping the daemon TLS certificate");
    }
    let (_, admin_token) = store.create_token(admin_name, Role::Admin, actor)?;

    println!("\nCA initialised in {}\n", paths.data_dir.display());
    println!("  Root CA          {}", paths.root_cert().display());
    println!("  Root SHA-256     {}", openssl_fingerprint(ca.root_der()));
    println!("  Intermediate     {}", paths.intermediate_cert().display());
    println!(
        "  Name constraints {}",
        config.policy.allowed_dns_suffixes.join(", ")
    );
    println!(
        "\nAdmin API token ('{admin_name}'). Shown once, store it in your secrets manager:\n\n  {admin_token}\n"
    );
    println!("Next steps:");
    println!(
        "  1. Move {} and the root passphrase OFFLINE.",
        paths.root_key().display()
    );
    println!("  2. Provide the intermediate passphrase to zenv-cad (systemd LoadCredential).");
    println!("  3. Start the daemon:  systemctl enable --now zenv-cad");
    println!("  4. Distribute the root certificate and its SHA-256 fingerprint to DMZ clients.");
    Ok(())
}

fn issue_daemon_tls(
    config: &Config,
    ca: &zenv_ca_core::CertificateAuthority,
    store: &Store,
    replace: bool,
) -> anyhow::Result<()> {
    let mut names = config.ca.tls_hostnames.clone();
    if names.is_empty() {
        names.extend(config.public_host());
    }
    ensure!(!names.is_empty(), "no TLS host names: set ca.tls_hostnames");
    let max = ca.policy().max_validity_days;
    let (issued, key) = ca
        .issue_with_generated_key(&KeygenRequest {
            common_name: None,
            dns_names: names,
            ip_addresses: vec![],
            profile: CertProfile::Server,
            validity_days: Some(max),
            key_algorithm: KeyAlgorithm::EcdsaP256,
        })
        .context("cannot issue the daemon TLS certificate (are the TLS host names inside the policy?)")?;
    store.insert_certificate(&issued, IssuanceMethod::Keygen, "system:zenv-cad-tls")?;
    let chain = render_certificate(&issued.cert_pem, ca, CertFormat::Chain)?;
    let key_pem = private_key_pem(&key);
    let (cert_path, key_path) = (config.tls_cert_path(), config.tls_key_path());
    if replace {
        write_replace(&key_path, key_pem.as_bytes(), 0o600)?;
        write_replace(&cert_path, &chain, 0o644)?;
    } else {
        write_new(&key_path, key_pem.as_bytes(), 0o600)?;
        write_new(&cert_path, &chain, 0o644)?;
    }
    println!(
        "Daemon TLS certificate for {} (serial {}, expires {}) written to {}",
        issued.dns_names.join(", "),
        issued.serial,
        issued.not_after.date(),
        cert_path.display()
    );
    Ok(())
}

// ---------------------------------------------------------------- tokens

fn token(config: &Config, cmd: TokenCmd, actor: &str) -> anyhow::Result<()> {
    let store = open_store(config)?;
    match cmd {
        TokenCmd::Create { name, role } => {
            let role = match role {
                RoleArg::Requester => Role::Requester,
                RoleArg::Admin => Role::Admin,
            };
            let (info, secret) = store
                .create_token(&name, role, actor)
                .context("cannot create token (duplicate name?)")?;
            eprintln!(
                "Token '{}' ({}) created. It is shown only once:",
                info.name,
                info.role.as_str()
            );
            println!("{secret}");
        }
        TokenCmd::List => {
            println!(
                "{:<4} {:<24} {:<10} {:<12} {:<22} {:<22} STATUS",
                "ID", "NAME", "ROLE", "PREFIX", "CREATED", "LAST USED"
            );
            for t in store.list_tokens()? {
                println!(
                    "{:<4} {:<24} {:<10} {:<12} {:<22} {:<22} {}",
                    t.id,
                    t.name,
                    t.role.as_str(),
                    t.prefix,
                    fmt_ts(t.created_at),
                    t.last_used_at.map(fmt_ts).unwrap_or_else(|| "never".into()),
                    if t.disabled_at.is_some() {
                        "disabled"
                    } else {
                        "active"
                    }
                );
            }
        }
        TokenCmd::Disable { name } => {
            ensure!(
                store.disable_token(&name, actor)?,
                "no active token named '{name}'"
            );
            println!("Token '{name}' disabled.");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- certificates

fn cert(config: &Config, cmd: CertCmd, actor: &str) -> anyhow::Result<()> {
    let store = open_store(config)?;
    match cmd {
        CertCmd::List {
            status,
            owner,
            search,
            json,
        } => {
            let rows = store.list_certificates(&CertFilter {
                requested_by: owner,
                status: status.map(|s| match s {
                    StatusArg::Active => CertStatus::Active,
                    StatusArg::Revoked => CertStatus::Revoked,
                    StatusArg::Expired => CertStatus::Expired,
                }),
                search,
                limit: 500,
                offset: 0,
            })?;
            if json {
                println!("{}", serde_json::to_string_pretty(&rows)?);
                return Ok(());
            }
            println!(
                "{:<34} {:<36} {:<14} {:<8} {:<11} OWNER",
                "SERIAL", "COMMON NAME", "PROFILE", "STATUS", "EXPIRES"
            );
            for c in rows {
                println!(
                    "{:<34} {:<36} {:<14} {:<8} {:<11} {}",
                    c.serial,
                    c.common_name,
                    c.profile.as_str(),
                    format!("{:?}", c.status).to_lowercase(),
                    &fmt_ts(c.not_after)[..10],
                    c.requested_by
                );
            }
        }
        CertCmd::Show { serial, pem } => {
            let serial = normalise_serial(&serial)?;
            let c = store
                .get_certificate(&serial)?
                .with_context(|| format!("no certificate {serial}"))?;
            if pem {
                print!("{}", c.cert_pem);
            } else {
                let mut v = serde_json::to_value(&c)?;
                if let Some(obj) = v.as_object_mut() {
                    obj.remove("cert_pem");
                }
                println!("{}", serde_json::to_string_pretty(&v)?);
            }
        }
        CertCmd::Revoke { serial, reason } => {
            let serial = normalise_serial(&serial)?;
            match store.revoke(&serial, reason.into(), actor)? {
                RevokeOutcome::Revoked(c) => println!(
                    "Revoked {} ({}). The CRL is re-signed on the next fetch.",
                    c.serial, c.common_name
                ),
                RevokeOutcome::AlreadyRevoked(c) => println!("{} was already revoked.", c.serial),
                RevokeOutcome::NotFound => bail!("no certificate {serial}"),
            }
        }
        CertCmd::Expiring { days } => {
            for c in store.expiring_within(days)? {
                println!(
                    "{}  {:<36} {}  {}",
                    &fmt_ts(c.not_after)[..10],
                    c.common_name,
                    c.serial,
                    c.requested_by
                );
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- audit

fn audit(config: &Config, cmd: AuditCmd) -> anyhow::Result<()> {
    let store = open_store(config)?;
    match cmd {
        AuditCmd::Verify => {
            let v = store.verify_audit_chain()?;
            if v.intact {
                println!("Audit chain intact: {} entries, head {}", v.entries, v.head_hash);
            } else {
                bail!(
                    "AUDIT CHAIN BROKEN at entry #{} ({} entries checked)",
                    v.first_broken_id.unwrap_or_default(),
                    v.entries
                );
            }
        }
        AuditCmd::Tail { limit } => {
            for e in store.audit_log(limit)?.into_iter().rev() {
                println!(
                    "#{:<5} {} {:<22} {:<22} {} {}",
                    e.id,
                    fmt_ts(e.ts),
                    e.actor,
                    e.action,
                    e.target,
                    e.details
                );
            }
        }
    }
    Ok(())
}
