# ADR 0004: SQLite inventory with a hash-chained audit log

- **Status:** accepted

## Context
Issuance volume is small (thousands/year). Operations want zero extra infrastructure. Auditors want evidence that history wasn't rewritten.

## Decision
- SQLite (WAL, `synchronous=FULL`) behind a mutex; forward-only migrations via `PRAGMA user_version`.
- Every state change and its audit row are committed in **one transaction**.
- `audit_log` is append-only (triggers abort UPDATE/DELETE) and each row hashes the previous row's hash.
- Tokens are stored as SHA-256 hashes (they are 256-bit random, so no slow KDF is needed).

## Consequences
+ No external DB; trivial backups (`.backup`).
+ Tampering is detectable (`zenv-ca audit verify`); anchoring the head hash externally makes it provable.
− Single-node. Superseded in part by [ADR 0006](0006-pluggable-storage-backends.md): SQLite stays the default, and PostgreSQL is available for HA. The hash-chained audit design applies to both.
