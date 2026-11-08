# Containers

There are two images, one per storage backend. Each holds `zenv-cad` and `zenv-ca` on `gcr.io/distroless/cc-debian12:nonroot` (uid 65532, no shell). A compose stack for each runs the CA locally. They work with Docker or Podman (`podman compose` works too).

> **Experimental.** The stacks serve **plain HTTP** on `127.0.0.1:8080`. The root key lives (encrypted) in the `ca-data` volume next to the intermediate. That's fine for trying things out. For anything real, follow [operations](../../docs/operations.md): take the root key offline and enable TLS or put a proxy in front.

| File | Purpose |
|---|---|
| [`Dockerfile.sqlite`](Dockerfile.sqlite) | image with only the SQLite store compiled in |
| [`Dockerfile.postgres`](Dockerfile.postgres) | image with only the PostgreSQL store compiled in |
| [`compose.sqlite.yml`](compose.sqlite.yml) | `init` (one-shot) → `zenv-cad` |
| [`compose.postgres.yml`](compose.postgres.yml) | `postgres` (official image) → `init` → `grants` → `zenv-cad` |
| [`config/`](config/) | the `zenv-ca.toml` each service mounts at `/etc/zenv-ca/zenv-ca.toml` |
| [`postgres-init/`](postgres-init/) | first-boot role/database/schema script and the app-role grants |
| [`make-secrets.sh`](make-secrets.sh) | random passphrases/passwords into `secrets/` (gitignored) |

## Quick start

```bash
cd deploy/docker
./make-secrets.sh

docker compose -f compose.sqlite.yml up --build -d      # or compose.postgres.yml
docker compose -f compose.sqlite.yml logs init          # admin token, printed once on first run
curl -s http://localhost:8080/readyz                    # {"status":"ready","database":"sqlite"}
```

Issue a certificate with the token (see [API](../../docs/api.md)):

```bash
TOKEN=zca_...
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"dns_names":["app.dmz.zenv.internal"],"pkcs12_password":"change-me-please"}' \
  http://localhost:8080/api/v1/certificates/keygen
```

Admin CLI commands run as a one-off container on the same volume and config:

```bash
docker compose -f compose.sqlite.yml run --rm --entrypoint zenv-ca zenv-cad cert list
docker compose -f compose.sqlite.yml run --rm --entrypoint zenv-ca zenv-cad audit verify
```

The web UI is at <http://localhost:8080/>.

## How the stacks start

`init` runs `zenv-ca init --if-needed` on every `up`. The first time, it creates the CA, the tables and the admin token. After that it sees a complete CA and exits 0 without changes. `zenv-cad` starts only once `init` has completed successfully.

The PostgreSQL stack adds two steps around that:

1. On an empty `pg-data` volume, `postgres` runs [`postgres-init/10-zenv-ca.sh`](postgres-init/10-zenv-ca.sh). It creates the roles `zenv_ca_owner` and `zenv_ca_app`, then the database `zenv_ca` (owned by `zenv_ca_owner`) and the schema `zenv_ca`.
2. `init` connects as **`zenv_ca_owner`** ([`config/zenv-ca.postgres-owner.toml`](config/zenv-ca.postgres-owner.toml)) and creates the tables.
3. `grants` applies [`postgres-init/grants.sql`](postgres-init/grants.sql) as the owner. This gives **`zenv_ca_app`** DML only.
4. `zenv-cad` connects as `zenv_ca_app` ([`config/zenv-ca.postgres.toml`](config/zenv-ca.postgres.toml)). It cannot alter the schema, and it cannot update, delete or truncate `audit_log`.

PostgreSQL is not published to the host. Uncomment `ports` on the `postgres` service to use `psql`. The connection is plain TCP on the compose network. For a remote database, use `?sslmode=require` and `tls_ca_file`; see [operations](../../docs/operations.md#postgresql-backend-optional).

## Secrets

Compose mounts the files in `secrets/` at `/run/secrets/<name>`. The configs point there (`ca.intermediate_passphrase_file`, `database.password_file`).

| Secret | Used by |
|---|---|
| `root_passphrase` | `init` only (encrypts the root key) |
| `intermediate_passphrase` | `init`, `zenv-cad` |
| `db_superuser_password` | `postgres` (the `postgres` superuser) |
| `db_owner_password` | `postgres` first boot, `init`, `grants` |
| `db_app_password` | `postgres` first boot, `zenv-cad` |

The files are mode 0644 so the non-root users inside the containers can read them. The `secrets/` directory is 0700, which protects them on the host. The values are baked into the volumes on first start. To rotate one, change it inside the CA or database too, or start over:

```bash
docker compose -f compose.postgres.yml down -v   # deletes the CA and database volumes
```

## Building the images alone

The build context is the repository root:

```bash
docker build -f deploy/docker/Dockerfile.sqlite   -t zenv-ca:sqlite   .
docker build -f deploy/docker/Dockerfile.postgres -t zenv-ca:postgres .
```

Builds use BuildKit cache mounts for the cargo registry and `target/`, so rebuilds are incremental. Both runtime images run read-only with all capabilities dropped in the compose files. Only `/var/lib/zenv-ca` is writable.
