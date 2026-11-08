# zenv-ca-store-postgres

The **PostgreSQL backend** for the Zenv DMZ CA. It implements [`zenv_ca_store::CaStore`](../zenv-ca-store/README.md) on a shared PostgreSQL database. Use it when you run **several `zenv-cad` instances** (HA behind a load balancer), or when policy requires a managed database with replication and PITR.

It's an optional feature:

```bash
cargo build --release --features zenv-ca-server/postgres,zenv-ca-cli/postgres
```

```toml
[database]
backend = "postgres"
url = "postgresql://zenv_ca_app@db.dmz.zenv.internal:5432/zenv_ca?sslmode=require"
schema = "zenv_ca"
password_file = "/etc/zenv-ca/db-app.pass"   # or systemd LoadCredential=database-password:...
tls_ca_file = "/etc/zenv-ca/db-ca.pem"        # default: OS trust store
pool_size = 8
connect_timeout_secs = 10
```

As a library:

```rust
use zenv_ca_store_postgres::{PostgresOptions, PostgresStore};

let store = PostgresStore::open(&PostgresOptions {
    password: Some(read_secret()?),
    schema: Some("zenv_ca".into()),
    ..PostgresOptions::new("postgresql://zenv_ca_app@db.internal/zenv_ca?sslmode=require")
})?; // blocking: from async code, call it inside spawn_blocking
```

## Design

| Concern | How |
|---|---|
| Driver | sync `postgres` 0.19 with an `r2d2` pool (`min_idle = 1`, `max_size = pool_size`). Blocking, like the rest of the store API. **Never** call it on a tokio worker thread. |
| TLS | rustls on **aws-lc-rs**, the same crypto as the rest of the CA. The server certificate and host name are **always** verified, so `sslmode=require` is as strict as libpq's `verify-full`. Roots come from `tls_ca_file` or the OS store. A remote host without `sslmode=require` logs a warning. |
| Fail fast | `open` makes one direct connection before building the pool, so a wrong password, TLS failure or unknown database comes back immediately with PostgreSQL's message (e.g. `FATAL (28P01): password authentication failed`). |
| Several instances | Every write transaction first takes `pg_advisory_xact_lock(0x7A434100, hashtext(current_schema()))`. Audit appends are serialised across all instances, so the hash chain never forks. CRL numbers come from `UPDATE crl_state … RETURNING`. Revocation uses `SELECT … FOR UPDATE`. |
| Migrations | Forward-only, tracked in `zenv_ca_schema_version`, run under the same advisory lock, so instances starting together don't race. When the schema is current, no DDL runs, which means a DML-only role can start the daemon. |
| Append-only audit | A PL/pgSQL trigger rejects `UPDATE`, `DELETE` and `TRUNCATE` on `audit_log`. Combined with a non-owner runtime role, the daemon **cannot** alter history or disable the trigger. |
| Schema layout | Mirrors SQLite: Unix seconds as `BIGINT`, JSON as `TEXT`. `details` is deliberately not `JSONB`, because PostgreSQL would re-serialise it and break the hashes. |
| Schemas | `schema` sets `search_path`, so one database can host several CAs. The name is validated (lower-case identifier). |
| Errors | `23505 unique_violation` becomes `StoreError::Conflict`. Other errors become `StoreError::Backend`, with SQLSTATE and server message but never query parameters. |

## Least-privilege roles

The owner role migrates; the app role, used by the daemon and day-to-day CLI, gets DML only. The full recipe is in [operations.md](../../docs/operations.md#postgresql-backend-optional). In short:

```sql
GRANT SELECT, INSERT, UPDATE ON zenv_ca.certificates, zenv_ca.api_tokens TO zenv_ca_app;
GRANT SELECT, UPDATE         ON zenv_ca.crl_state                       TO zenv_ca_app;
GRANT SELECT, INSERT         ON zenv_ca.audit_log                       TO zenv_ca_app;
GRANT SELECT                 ON zenv_ca.zenv_ca_schema_version          TO zenv_ca_app;
```

With these grants, `UPDATE`/`DELETE`/`TRUNCATE`/`DROP` on `audit_log` and `ALTER TABLE … DISABLE TRIGGER` all fail for the app role.

## Tests

The database tests need a **disposable** PostgreSQL. Each test creates its own schema:

```bash
ZENV_CA_TEST_POSTGRES_URL='postgresql://zenv:secret@127.0.0.1:5432/zenv_test' \
  cargo test -p zenv-ca-store-postgres
```

Without the variable they're skipped, and only the configuration tests run. [`tests/postgres.rs`](tests/postgres.rs) covers:
- the shared conformance suite
- two independent pools (two "instances") writing concurrently, with one unbroken chain
- trigger enforcement and tamper detection
- idempotent reopening, and refusal of newer schemas
- fast failure on bad settings

CI runs all of this against a `postgres:17` service container.
