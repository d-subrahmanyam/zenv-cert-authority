# Operations guide

## Install

```bash
cargo build --release --locked
sudo install -m 0755 target/release/zenv-cad target/release/zenv-ca /usr/local/bin/
sudo useradd --system --home /var/lib/zenv-ca --shell /usr/sbin/nologin zenv-ca
sudo install -d -m 0750 -o root -g zenv-ca /etc/zenv-ca
sudo install -m 0640 -o root -g zenv-ca config/zenv-ca.example.toml /etc/zenv-ca/zenv-ca.toml
sudoedit /etc/zenv-ca/zenv-ca.toml        # public_url, policy, subjects
```

## Bootstrap

```bash
# passphrases: ≥12 chars, different from each other
sudo install -m 0400 -o root -g root /dev/stdin /etc/zenv-ca/intermediate.pass <<< "$(openssl rand -base64 32)"
sudo -u zenv-ca ZENV_CA_INTERMEDIATE_PASSPHRASE_FILE=/etc/zenv-ca/intermediate.pass \
     zenv-ca init                         # prompts for the ROOT passphrase
```

`init` prints the root SHA-256 fingerprint and the first admin token (**once**). Then:

1. Copy `/var/lib/zenv-ca/ca/root.key.enc` to offline media, verify the copy, `shred -u` the online one. Store the root passphrase separately (e.g. split between two officers).
2. Install the unit and start the daemon:

```bash
sudo install -m 0644 deploy/zenv-cad.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now zenv-cad
curl --cacert /var/lib/zenv-ca/ca/root.crt https://ca.dmz.zenv.internal:8443/readyz
```

3. Create tokens per team / pipeline:

```bash
sudo -u zenv-ca zenv-ca token create --name team-shop
sudo -u zenv-ca zenv-ca token create --name gitlab-dmz-deployer
```

## Configuration reference

See the commented [`config/zenv-ca.example.toml`](../config/zenv-ca.example.toml).

| Key | Default | Notes |
|---|---|---|
| `server.listen` | (required) | `0.0.0.0:8443` |
| `server.public_url` | (required) | baked into every cert as CRL DP: pick a stable name |
| `server.tls.enabled` | `true` | disable only behind a TLS proxy |
| `server.max_body_bytes` | `65536` | |
| `server.request_timeout_secs` | `30` | |
| `paths.data_dir` | `/var/lib/zenv-ca` | |
| `ca.root/intermediate.*` | | subject, `validity_days`, `key_algorithm` (used by `init`) |
| `ca.intermediate_passphrase_file` | | prefer systemd credentials |
| `ca.tls_hostnames` | public URL host | must be inside the policy |
| `policy.allowed_dns_suffixes` | (required) | also become Name Constraints at `init` |
| `policy.allowed_ip_networks` | `[]` | CIDR |
| `policy.default_validity_days` / `max_validity_days` | `30` / `90` | |
| `policy.allow_wildcards` | `false` | |
| `policy.allow_server_side_keygen` | `true` | |
| `policy.max_sans` | `20` | |
| `crl.validity_hours` | `168` | re-signed at half-life or on revocation |
| `logging.format` | `pretty` | `json` for SIEM; `RUST_LOG` overrides `filter` |

Passphrase lookup order: `$ZENV_CA_INTERMEDIATE_PASSPHRASE_FILE` → `ca.intermediate_passphrase_file` → `$CREDENTIALS_DIRECTORY/intermediate-passphrase` → `$ZENV_CA_INTERMEDIATE_PASSPHRASE` (dev only).

> Changing `policy.allowed_dns_suffixes` after `init` does **not** change the intermediate's Name Constraints. Widening the namespace requires a new intermediate.

## Monitoring

| Signal | Source |
|---|---|
| Liveness / readiness | `GET /healthz`, `GET /readyz` |
| Expiring certs | log `certificate expires within 14 days` (every 12 h); `zenv-ca cert expiring --days 14` |
| Auth failures | log `rejected invalid bearer token` |
| Revocations | log `certificate revoked` (warn) |
| Audit integrity | `zenv-ca audit verify` (exit ≠ 0 on break): run from a timer, alert on failure |
| CA expiry | intermediate `notAfter`; plan rotation ≥ 90 days ahead |

## Backup & restore

Back up `/var/lib/zenv-ca` (DB + certs + encrypted intermediate key) daily, encrypted. Use SQLite's online backup for consistency:

```bash
sqlite3 /var/lib/zenv-ca/zenv-ca.db ".backup '/backup/zenv-ca-$(date +%F).db'"
```

Restore: stop daemon → restore files with ownership `zenv-ca` and modes (`0700` dirs, `0600` keys/DB) → `zenv-ca audit verify` → start.

## Runbooks

### Token leaked
`zenv-ca token disable --name <name>` → review `zenv-ca cert list --owner <name>` and `zenv-ca audit tail` → revoke anything suspicious → issue a new token.

### Leaf key compromised
`zenv-ca cert revoke <serial> --reason key-compromise` (or via UI) → owner issues a new cert with a **new key**.

### Renew daemon TLS certificate
`sudo -u zenv-ca zenv-ca tls issue && sudo systemctl restart zenv-cad`. Schedule it monthly with a systemd timer (cert max = policy max validity).

### Intermediate compromise
1. Stop the daemon. 2. Retrieve the root key from offline storage. 3. Re-run bootstrap into a new data dir (or rotate, see roadmap) and redistribute. 4. Because DMZ clients trust the root, publish a CRL from the root revoking the old intermediate (roadmap: `zenv-ca intermediate revoke`). Meanwhile, remove the old intermediate from any explicit bundles.

### Disaster: database lost, keys intact
Restore from backup. Without a backup, the verify/status APIs return `unknown` for existing certs (fail closed) while TLS clients keep working; re-issue certificates.
