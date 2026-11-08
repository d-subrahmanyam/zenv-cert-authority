# zenv-ca-store-sqlite

The **SQLite backend** for the Zenv DMZ CA, and the default. It implements [`zenv_ca_store::CaStore`](../zenv-ca-store/README.md) on one embedded database file, so there is nothing to operate and one file to back up. It's the right choice for a single CA host.

```rust
use std::sync::Arc;
use zenv_ca_store::CaStore;
use zenv_ca_store_sqlite::SqliteStore;

let store: Arc<dyn CaStore> = Arc::new(SqliteStore::open("/var/lib/zenv-ca/zenv-ca.db".as_ref())?);
let test_store = SqliteStore::open_in_memory()?;           // tests, dry runs
```

In the daemon you don't construct it yourself. `[database] backend = "sqlite"` is the default, with the file at `<data_dir>/zenv-ca.db` unless `database.path` says otherwise.

## Behaviour

- **File:** created with mode `0600`. Migrations are forward-only, tracked with `PRAGMA user_version`, and a database from a newer version is refused (`SchemaTooNew`).
- **Durability:** WAL journal, `synchronous=FULL`, foreign keys on.
- **Concurrency:** one connection per process behind a mutex. Writes use `BEGIN IMMEDIATE` with a 5 s busy timeout, so the daemon and the CLI writing at the same moment queue up instead of failing with "database is locked". The test suite covers this with two handles on one file.
- **Audit:** triggers abort `UPDATE` and `DELETE` on `audit_log`, and the shared hash chain catches anyone who drops the triggers.
- **Errors:** `UNIQUE` violations become `StoreError::Conflict`; other failures become `StoreError::Backend`.

## Tests

```bash
cargo test -p zenv-ca-store-sqlite
```

[`tests/sqlite.rs`](tests/sqlite.rs) runs the shared conformance suite, then the SQLite-specific checks:
- two handles writing concurrently
- tamper detection after dropping the triggers
- file permissions
- idempotent reopening
- refusal of newer schemas

## Backups

```bash
sqlite3 /var/lib/zenv-ca/zenv-ca.db ".backup '/backup/zenv-ca-$(date +%F).db'"
```

To move to PostgreSQL, see [`zenv-ca-store-postgres`](../zenv-ca-store-postgres/README.md). The tables match column for column.
