# ADR 0006: Pluggable storage backends (SQLite and PostgreSQL)

- **Status:** accepted
- **Refines:** [ADR 0004](0004-sqlite-and-hash-chained-audit.md)

## Context
SQLite (ADR 0004) is ideal for one CA host. Some teams need:
- **several `zenv-cad` instances** behind a load balancer, which means one shared database;
- a **managed database** for backups, replication and PITR, because their policy requires it.

We want either backend without forking the code, and without the two drifting apart. The most dangerous kind of drift is a different audit hash. That would make a log migrated from one backend fail verification on the other.

## Decision
1. **`zenv-ca-store` is the contract.** It holds an object-safe, synchronous `CaStore` trait and the record types. It also owns every piece of logic where backends must agree:
   - audit hash computation and chain verification (`AuditRow::next`, `ChainVerifier`)
   - canonical audit events
   - token generation and hashing
   - the stored row format (`CertificateRow`)
   - status derivation
   - fail-closed revocation lookup (`Revocations`)

   This crate has **no database dependency**.
2. **One crate per backend:** `zenv-ca-store-sqlite` and `zenv-ca-store-postgres`. A backend only moves rows. It must:
   - write each change and its audit row in one transaction;
   - serialise audit appends, using SQLite's write lock or a PostgreSQL advisory lock;
   - store `details` as exact text (not `JSONB`);
   - map unique violations to `StoreError::Conflict`.
3. **Selection.**
   - *Build time:* Cargo features on `zenv-ca-server` and `zenv-ca-cli`: `sqlite` (default) and `postgres`.
   - *Run time:* the `[database] backend` key.
   - Only `zenv-ca-server/src/storage.rs` names the backend crates. Everything else holds an `Arc<dyn CaStore>`.
4. **A conformance suite** (`zenv-ca-store` feature `testkit`) runs unchanged against every backend, including a multi-writer test that requires a single unbroken audit chain.
5. **Synchronous API.** The daemon already runs all store work on `spawn_blocking`. An async trait would add `async-trait` or boxed futures for no gain at this load, and would complicate the CLI.

## Consequences
+ HA deployments are possible: N daemons, one PostgreSQL. CRL numbers stay monotonic and the audit chain stays linear across instances.
+ A new backend (say MySQL, or a cloud KV) is: one crate, the testkit macro, one feature, one match arm.
+ Least privilege on PostgreSQL. An owner role runs migrations, and the runtime role has only DML. It can't `UPDATE`, `DELETE` or `TRUNCATE` the audit log, or disable its trigger.
− Every PostgreSQL write takes a per-schema advisory lock, which serialises writes. That's fine for a CA, where writes happen a few times a minute, but don't reuse the pattern for high-volume tables.
− No built-in SQLite → PostgreSQL copy yet. The tables match column for column, so a plain export/import works, and `zenv-ca audit verify` confirms the result. A `zenv-ca db migrate` command is on the roadmap.
