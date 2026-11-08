# Operations guide

## Install

```bash
cargo build --release --locked                     # SQLite only (default)
# cargo build --release --locked --features zenv-ca-server/postgres,zenv-ca-cli/postgres
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
| `database.backend` | `sqlite` | `sqlite` or `postgres` (the backend must be compiled in) |
| `database.path` | `<data_dir>/zenv-ca.db` | SQLite only |
| `database.url` | (required for postgres) | libpq URL **without** password; add `sslmode=require` for remote hosts |
| `database.password_file` | | prefer the systemd credential `database-password` |
| `database.schema` | role's `search_path` | must exist; lower-case identifier |
| `database.pool_size` | `8` | connections per daemon instance |
| `database.connect_timeout_secs` | `10` | connect and pool checkout |
| `database.tls_ca_file` | OS trust store | CA bundle for the database server's certificate (can be our own DMZ root) |

Passphrase lookup order: `$ZENV_CA_INTERMEDIATE_PASSPHRASE_FILE` → `ca.intermediate_passphrase_file` → `$CREDENTIALS_DIRECTORY/intermediate-passphrase` → `$ZENV_CA_INTERMEDIATE_PASSPHRASE` (dev only).

Database password lookup order: `$ZENV_CA_DATABASE_PASSWORD_FILE` → `database.password_file` → `$CREDENTIALS_DIRECTORY/database-password` → `$ZENV_CA_DATABASE_PASSWORD` (dev only).

> Changing `policy.allowed_dns_suffixes` after `init` does **not** change the intermediate's Name Constraints. Widening the namespace requires a new intermediate.

## PostgreSQL backend (optional)

Use it for several daemon instances (HA) or when a managed database is required. Otherwise keep the default SQLite.

**1. Roles and schema (least privilege).** The *owner* role runs migrations, only during `init` and upgrades. The *app* role runs the daemon and day-to-day CLI with DML only, so it can never rewrite the audit log or disable its trigger:

```sql
CREATE ROLE zenv_ca_owner LOGIN PASSWORD '…';
CREATE ROLE zenv_ca_app   LOGIN PASSWORD '…';
CREATE DATABASE zenv_ca OWNER zenv_ca_owner;
\c zenv_ca
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA zenv_ca AUTHORIZATION zenv_ca_owner;
GRANT USAGE ON SCHEMA zenv_ca TO zenv_ca_app;
```

**2. Bootstrap as the owner.** Use a config whose `[database]` names the owner role:

```toml
[database]
backend = "postgres"
url = "postgresql://zenv_ca_owner@db.dmz.zenv.internal:5432/zenv_ca?sslmode=require"
password_file = "/etc/zenv-ca/db-owner.pass"
schema = "zenv_ca"
tls_ca_file = "/etc/zenv-ca/db-ca.pem"   # e.g. our own DMZ root, if it issued the DB cert
```

```bash
sudo -u zenv-ca zenv-ca --config /etc/zenv-ca/zenv-ca.owner.toml init
```

**3. Grant the app role**, then point `/etc/zenv-ca/zenv-ca.toml` at `zenv_ca_app`:

```sql
SET ROLE zenv_ca_owner;
GRANT SELECT, INSERT, UPDATE ON zenv_ca.certificates, zenv_ca.api_tokens TO zenv_ca_app;
GRANT SELECT, UPDATE         ON zenv_ca.crl_state                       TO zenv_ca_app;
GRANT SELECT, INSERT         ON zenv_ca.audit_log                       TO zenv_ca_app;
GRANT SELECT                 ON zenv_ca.zenv_ca_schema_version          TO zenv_ca_app;
```

Re-check the grants after an upgrade that adds tables. Run upgrades with the owner config once; it applies migrations, and the app role refuses to.

**4. Deliver the password** as a credential: uncomment `LoadCredential=database-password:…` in `zenv-cad.service`.

**5. More instances.** Run each one with the same config and the **same** `data_dir/ca` material (certificates plus the encrypted intermediate key, distributed like any secret), behind one `public_url`. Instances coordinate through the database:
- audit appends take an advisory lock;
- CRL numbers come from one counter;
- any instance re-signs the CRL when the revocation revision changes.

Notes:
- `sslmode=require` makes the connection fail rather than fall back to plaintext. The server certificate and host name are always verified (rustls), so `require` is as strict as libpq's `verify-full`. `prefer` falls back to plaintext when the server doesn't offer TLS, so don't use it for remote hosts. The daemon warns if you do.
- Connection errors such as a wrong password, a TLS failure or an unknown database are reported at start-up with PostgreSQL's own message, not after a pool timeout.
- `/readyz` returns `{"status":"ready","database":"postgres"}`.

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

Back up `/var/lib/zenv-ca` (certs + encrypted intermediate key, plus the DB for SQLite) daily, encrypted. Take a consistent database snapshot:

```bash
# SQLite: online backup
sqlite3 /var/lib/zenv-ca/zenv-ca.db ".backup '/backup/zenv-ca-$(date +%F).db'"
# PostgreSQL: logical dump of the CA schema (or rely on the managed service's PITR)
pg_dump --schema=zenv_ca --format=custom -f /backup/zenv-ca-$(date +%F).dump "$OWNER_URL"
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
