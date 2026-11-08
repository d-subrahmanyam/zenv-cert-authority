# Zenv DMZ Certificate Authority

A small, self-hosted **certificate authority daemon written in Rust** for Zenv's DMZ / pre-production zone. Teams get TLS certificates for their apps through a **self-service web UI** or a **REST API**. The CA publishes a **CRL** and **verification endpoints** so DMZ clients and humans can check whether a certificate is valid, revoked or foreign.

> ⚠️ **Non-production.** This hierarchy is deliberately separate from production PKI. Never install its root in production trust stores.

```mermaid
flowchart LR
    Dev[Developer / CI] -- "CSR or keygen<br/>(Bearer token)" --> CAD[zenv-cad]
    CAD -- "cert · chain · PKCS#12" --> Dev
    Dev -- deploy --> App[DMZ app]
    Client[DMZ client<br/>trusts root.crt] -- TLS --> App
    Client -- "CRL / verify / status" --> CAD
```

## Features

- **Two-tier PKI**: offline-intended root plus an online intermediate with **X.509 Name Constraints** (it cannot vouch for names outside your DMZ namespace).
- **CSR-first issuance**: the requester keeps the private key. Only the CSR's key and names are used; everything else comes from fixed **profiles** (`server`, `client`, `server-client`).
- **Server-side keygen** (optional): ECDSA P-256/P-384, RSA 2048/3072 or Ed25519. The key is returned **once** as PEM and as a password-protected **PKCS#12**; the CA keeps no copy.
- **Policy engine**: allowed DNS suffixes (label-boundary aware), IP networks, wildcard opt-in, max SANs, default and max lifetime.
- **Download formats**: PEM, DER, chain (leaf + intermediate), full chain, PKCS#12.
- **Validation**:
  - CRL at a URL embedded in every certificate
  - JSON status API
  - verify API that reports each check: signature, chain, validity, basic constraints, name constraints, live revocation, host name
- **Security**:
  - Bearer tokens stored only as hashes; requester and admin roles; ownership checks
  - CA keys encrypted at rest (PBES2 / PBKDF2-SHA256 / AES-256)
  - Hardened systemd unit
  - Strict CSP and security headers
- **Tamper-evident audit**: an append-only, hash-chained log, written in the same transaction as every change.
- **Pluggable storage**: embedded SQLite by default, and PostgreSQL for several daemon instances. Both pass the same conformance suite.
- **Ops**: health and readiness probes, JSON logs, expiry warnings, graceful shutdown, admin CLI.

## Repository layout

```
crates/
  zenv-ca-core/    domain logic (no I/O): hierarchy, policy, issuance, CRL, verify, export, keys
  zenv-ca-store/            storage contract: CaStore trait, audit chain, tokens, conformance testkit
  zenv-ca-store-sqlite/     SQLite backend (default)
  zenv-ca-store-postgres/   PostgreSQL backend (feature `postgres`, for HA)
  zenv-ca-server/  zenv-cad daemon: axum API, embedded web UI (ui/), TLS
  zenv-ca-cli/     zenv-ca admin CLI: init, token, cert, tls, audit
config/            example (prod-like) and dev configs
deploy/            hardened systemd unit; docker/: SQLite and PostgreSQL images + compose stacks
docs/              architecture, use cases, flows, security, API, operations, ADRs, UML
scripts/           diagram tooling
```

Each crate has its own README with modules, usage examples and design notes:

| Crate | Kind | README |
|---|---|---|
| `zenv-ca-core` | library | [crates/zenv-ca-core](crates/zenv-ca-core/README.md): PKI domain logic, API examples |
| `zenv-ca-store` | library | [crates/zenv-ca-store](crates/zenv-ca-store/README.md): `CaStore` trait, shared audit/token logic, writing a backend |
| `zenv-ca-store-sqlite` | library | [crates/zenv-ca-store-sqlite](crates/zenv-ca-store-sqlite/README.md): embedded default backend |
| `zenv-ca-store-postgres` | library | [crates/zenv-ca-store-postgres](crates/zenv-ca-store-postgres/README.md): HA backend, TLS, least-privilege roles |
| `zenv-ca-server` | library + `zenv-cad` | [crates/zenv-ca-server](crates/zenv-ca-server/README.md): config, passphrase sources, HTTP surface |
| `zenv-ca-cli` | `zenv-ca` | [crates/zenv-ca-cli](crates/zenv-ca-cli/README.md): command reference |

Dependencies point one way: `cli → server → store-{sqlite,postgres} → store → core`. Only `core` does crypto, and it does no I/O. Storage is pluggable: handlers see only `Arc<dyn CaStore>`, and backends are picked by Cargo feature and `[database] backend` ([ADR 0006](docs/adr/0006-pluggable-storage-backends.md)).

## Quick start (local, plain HTTP)

```bash
export ZENV_CA_CONFIG=config/zenv-ca.dev.toml
export ZENV_CA_INTERMEDIATE_PASSPHRASE_FILE=dev-data.intermediate.pass
printf 'dev-intermediate-pass' > dev-data.intermediate.pass
printf 'dev-root-passphrase!!' > dev-data.root.pass

cargo run --bin zenv-ca -- init --root-passphrase-file dev-data.root.pass   # prints an admin token
cargo run --bin zenv-cad                                                    # http://127.0.0.1:8080
```

Open <http://127.0.0.1:8080>, paste the token, and request a certificate. Or use the API:

```bash
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout app.key -out app.csr \
  -subj "/CN=app.dmz.zenv.internal" -addext "subjectAltName=DNS:app.dmz.zenv.internal"
jq -n --rawfile csr app.csr '{csr_pem:$csr}' |
  curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d @- \
       http://127.0.0.1:8080/api/v1/certificates
```

For a real deployment (HTTPS, systemd, offline root) follow [docs/operations.md](docs/operations.md).

## Documentation

| Doc | Contents |
|---|---|
| [Architecture](docs/architecture.md) | context, components, PKI hierarchy, data model, runtime, deployment |
| [Use cases](docs/use-cases.md) | actors, use-case diagram, UC1–UC13 specifications |
| [Flows](docs/flows.md) | sequence diagrams (bootstrap, issuance, keygen, TLS validation, verify, revocation), lifecycle state machine |
| [Security](docs/security.md) | assets, trust boundaries, STRIDE, crypto choices, checklist |
| [API](docs/api.md) | endpoint reference with curl examples |
| [Operations](docs/operations.md) | install, bootstrap, config reference, monitoring, backups, runbooks |
| [Roadmap](docs/roadmap.md) | ACME, OIDC, OCSP, HSM, metrics, … |
| [ADRs](docs/adr/) | key design decisions (incl. [0006 pluggable storage](docs/adr/0006-pluggable-storage-backends.md)) |
| [UML](docs/uml/) | PlantUML: use cases, components, deployment, class, sequences, state |

Diagrams: the Mermaid diagrams render inline on GitHub. `python3 scripts/build-diagram-viewer.py` regenerates [`docs/diagrams.html`](docs/diagrams.html), a single page with all of them. `scripts/render-uml.sh` renders the PlantUML sources to SVG using `plantuml`, or a container if `plantuml` isn't installed.

## Run it in containers

Two images and compose stacks live in [`deploy/docker/`](deploy/docker/README.md): SQLite in a single container, or PostgreSQL using the official `postgres` image with least-privilege roles. They work with Docker or Podman:

```bash
cd deploy/docker && ./make-secrets.sh
docker compose -f compose.sqlite.yml up --build     # or compose.postgres.yml
docker compose -f compose.sqlite.yml logs init      # first admin token
curl http://localhost:8080/readyz
```

## Development

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace          # unit + integration tests (core lifecycle, store conformance on SQLite, HTTP API)
cargo clippy --workspace --all-targets --all-features -- -D warnings

# PostgreSQL backend against a disposable database (each test uses its own schema)
ZENV_CA_TEST_POSTGRES_URL=postgresql://zenv:secret@127.0.0.1:5432/zenv_test \
  cargo test --workspace --all-features
```

Engineering conventions:
- `unsafe` is forbidden; `unwrap`/`expect` are linted outside tests.
- Pure core, I/O at the edges.
- Every state change is audited in the same transaction.
- Blocking work runs in `spawn_blocking`.
- Errors are RFC 9457 problem+json, and internal details are logged, never returned.
- There is no hosted CI (experimental repo). Run the commands above before pushing, plus `cargo deny check` when dependencies change.
