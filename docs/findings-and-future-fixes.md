# Findings and future fixes

This page lists the gaps found while building, containerising and testing zenv-ca by hand, end to end. None of them are on the [roadmap](roadmap.md). The roadmap covers new **features** (ACME, OIDC, OCSP, …). This page covers **fixes and hardening** of what already exists.

Status as of 2026-11-08 (commit `fcde718`).

## Scales

| Priority | Meaning |
|---|---|
| **P1** | Do next. A real security gap, or a missing safety net while the repo has no CI. |
| **P2** | Worth doing soon. It reduces risk or friction noticeably. |
| **P3** | Nice to have, or only matters at larger scale. |

| Effort | Rough size (one developer who knows the codebase) |
|---|---|
| **XS** | under 2 hours |
| **S** | half a day to 1 day |
| **M** | 2 to 4 days |
| **L** | 1 to 2 weeks |

| Complexity | Meaning |
|---|---|
| **Low** | Local change, obvious design, little risk of regressions. |
| **Medium** | Touches several crates or the storage contract, or needs a migration. Some design choices. |
| **High** | Changes trust model or crypto, needs careful design and review, hard to undo once deployed. |

## Summary

| ID | Item | Category | Priority | Effort | Complexity |
|---|---|---|---|---|---|
| [F-01](#f-01-local-check-script-replacing-ci) | Local check script replacing CI | Engineering | **P1** | S | Low |
| [F-02](#f-02-offline-root-ceremony) | Offline root ceremony (`init` split) | Security | **P1** | M | High |
| [F-03](#f-03-admin-token-printed-to-container-logs) | Admin token printed to container logs | Security | **P1** | XS | Low |
| [F-04](#f-04-no-healthcheck-for-the-daemon-container) | No healthcheck for the daemon container | Operations | P2 | XS | Low |
| [F-05](#f-05-api-tokens-never-expire) | API tokens never expire | Security | P2 | M | Medium |
| [F-06](#f-06-audit-checkpoints-are-manual) | Audit checkpoints are manual | Security | P2 | M | Medium |
| [F-07](#f-07-no-fuzzing-or-property-tests-on-untrusted-input) | No fuzzing or property tests on untrusted input | Security | P2 | M | Medium |
| [F-08](#f-08-grantssql-must-track-every-migration) | `grants.sql` must track every migration | Maintenance | P2 | S | Low |
| [F-09](#f-09-no-backup--restore-command) | No backup / restore command | Operations | P2 | M | Medium |
| [F-10](#f-10-near-duplicate-container-configs) | Near-duplicate container configs | Operations | P3 | S | Medium |
| [F-11](#f-11-concurrent-crl-fetches-can-both-re-sign) | Concurrent CRL fetches can both re-sign | Correctness | P3 | XS | Low |
| [F-12](#f-12-keygen-always-requires-a-pkcs12-password) | Keygen always requires a PKCS#12 password | Usability | P3 | XS | Low |
| [F-13](#f-13-post-quantum-signature-experiment) | Post-quantum signature experiment | Research | P3 | L | High |

**Suggested order:** F-03 and F-04 first (both tiny), then F-01 and F-08 (safety net), then F-02, F-05 and F-06 (trust model). Everything else can follow.

---

## F-01 Local check script replacing CI

**Priority** P1 · **Effort** S · **Complexity** Low

**Finding.** The repo has no hosted CI by choice (it is experimental). The checks the README lists run only when someone remembers to run them. The PostgreSQL tests are skipped unless `ZENV_CA_TEST_POSTGRES_URL` is set, and the container stacks were verified only by hand. Without CI, a change can break the PostgreSQL backend or a compose stack and nobody notices.

**Proposed fix.** Add `scripts/check.sh` with three stages, each runnable on its own:

1. `fast`: `cargo fmt --check`, `clippy -D warnings` for default features and `--all-features`, `cargo test --workspace`, `cargo doc` with `-D warnings`.
2. `postgres`: start a throwaway `postgres:18` container on a random local port, run `cargo test --all-features` against it, remove it.
3. `containers`: build both images, bring each compose stack up, issue a certificate with the admin token, revoke it with the CLI, check the CRL with `openssl crl`, run `audit verify`, then `down -v`.

Optionally add a git `pre-push` hook (opt-in, via `scripts/install-hooks.sh`) that runs `fast`.

**Notes.** The script should detect Docker or Podman. It should also allow a `CONTAINER_RUNTIME` override, because some hosts have a broken default OCI runtime: during testing, Homebrew podman 6.1.4 was calling an old system `crun` 1.14.1.

**Done when.** `scripts/check.sh all` passes on a clean checkout, fails with a clear message when something breaks, and the README's Development section points to it.

## F-02 Offline root ceremony

**Priority** P1 · **Effort** M · **Complexity** High

**Finding.** `zenv-ca init` generates the root and the intermediate **on the CA host**. The encrypted root key (`ca/root.key.enc`) is left next to the intermediate in `data_dir`, and in the container stacks it sits in the `ca-data` volume. The docs tell the operator to move it offline afterwards. A step that relies on someone remembering it is a weak control. Anyone who can read the volume and get the root passphrase can mint a new intermediate with no name constraints.

**Proposed fix.** Split bootstrapping into a ceremony:

| Step | Where | Command |
|---|---|---|
| 1 | offline machine | `zenv-ca root init`: creates the root key and certificate; the key never leaves the machine |
| 2 | CA host | `zenv-ca intermediate request`: generates the intermediate key and writes a CSR |
| 3 | offline machine | `zenv-ca root sign-intermediate --csr …`: applies the name constraints from policy and outputs the certificate |
| 4 | CA host | `zenv-ca intermediate install --cert …`: checks it chains to the pinned root, then provisions the database and admin token |

Keep the current one-shot `init` for development, renamed or behind `--insecure-colocated-root` so the trade-off is explicit. The compose stacks keep using it.

**Notes.** Step 3 must check the CSR's public key and subject against the policy, not trust the CSR blindly. Also plan root re-signing for intermediate rotation (roadmap #8), which builds on this. Update the bootstrap sequence diagram in [flows.md](flows.md) and [security.md](security.md).

**Done when.** A CA can be brought up with the root key never present on the CA host. The flows doc shows the ceremony, and a test drives all four steps.

## F-03 Admin token printed to container logs

**Priority** P1 · **Effort** XS · **Complexity** Low

**Finding.** `init` prints the first admin token to stdout. On a terminal that is fine. In containers, stdout goes into the container log, which persists, is readable by anyone with access to the container engine, and is often shipped to log aggregation.

**Proposed fix.** Add `init --admin-token-file PATH`. It writes the token with mode 0600, refuses to overwrite an existing file, and prints only the path and the token prefix. The compose stacks pass `--admin-token-file /var/lib/zenv-ca/admin.token`, and the README says how to read it once and delete it.

**Done when.** `docker compose logs init` shows no secret, and the token can still be retrieved once.

## F-04 No healthcheck for the daemon container

**Priority** P2 · **Effort** XS · **Complexity** Low

**Finding.** The distroless runtime image has no shell or `curl`, so the `zenv-cad` compose services have no healthcheck. `docker compose ps` shows "Up" even if the daemon can't reach its database, and other services can't wait for `service_healthy`.

**Proposed fix.** Add `zenv-cad healthcheck [--url http://127.0.0.1:8080/readyz]`. It exits 0 only on HTTP 200 with `status: ready`, has a short timeout, and when TLS is enabled it trusts the CA's own chain. Add a `healthcheck:` block to both compose files.

**Done when.** Stopping the `postgres` service turns `zenv-cad` unhealthy within one interval.

## F-05 API tokens never expire

**Priority** P2 · **Effort** M · **Complexity** Medium

**Finding.** A token is valid until an admin disables it. `last_used_at` is already recorded and shown by `token list`. However, there is no expiry and no way to find stale tokens other than reading the list. A leaked pipeline token stays valid forever.

**Proposed fix.**

- Add a nullable `expires_at` column to `api_tokens` (migration v2 in both backends) and a `--ttl 90d` option on `token create`. Add a configurable `max_token_ttl` in policy, applied to new tokens.
- Reject expired tokens in the auth layer as `401` with a distinct problem type, and audit it.
- Add `token list --stale 30d`, which lists tokens unused for that long, and `token rotate --name …`, which creates the replacement and disables the old token in one audited transaction.
- Add conformance tests in the `testkit` so both backends behave the same.

**Notes.** Existing tokens keep `NULL` (no expiry), so the change is backward compatible. Remember [F-08](#f-08-grantssql-must-track-every-migration) when adding the migration.

**Done when.** An expired token gets a 401, rotation is a single command, and the conformance suite covers expiry.

## F-06 Audit checkpoints are manual

**Priority** P2 · **Effort** M · **Complexity** Medium

**Finding.** The audit log is hash-chained, but the chain only shows tampering if someone recorded an earlier head hash **outside** the CA. The docs ask operators to do that by hand on a schedule. Without external anchors, an attacker with database-owner access can rewrite the whole chain consistently.

**Proposed fix.**

- A periodic task in `zenv-cad` (configurable interval) produces a **checkpoint**: `{entries, head_hash, ts}` signed with the intermediate key (or a dedicated audit key).
- Sinks, configurable: append to a file outside `data_dir`, POST to a webhook (chat or ticketing), or both.
- `zenv-ca audit verify --checkpoints FILE` checks that the current chain extends every recorded checkpoint.

**Notes.** Signing with the intermediate key widens what that key does. A separate Ed25519 audit key is cleaner but needs its own passphrase handling. Decide this in an ADR.

**Done when.** A rewritten chain is detected against stored checkpoints without any manual step.

## F-07 No fuzzing or property tests on untrusted input

**Priority** P2 · **Effort** M · **Complexity** Medium

**Finding.** Several code paths parse attacker-controlled input. CSRs go through `POST /api/v1/certificates`, and PEM/DER certificates through `POST /api/v1/verify`. Name and IP matching runs in the policy engine (suffixes, wildcards, IP ranges). Today there are only example-based tests. A panic in a parser is a denial of service; a matching bug is a policy bypass.

**Proposed fix.**

- Add `cargo-fuzz` targets in a `fuzz/` directory (outside the workspace) for CSR parsing and validation, certificate verification input, and serial normalisation.
- Add `proptest` properties for policy. Every name that passes is under an allowed suffix. A wildcard never matches more than one label. Case and trailing-dot variants agree. IPs outside every allowed network are always rejected.
- Add a `scripts/check.sh fuzz` stage that runs each target briefly (for example 60 seconds).

**Done when.** The fuzz targets run clean for a set time, and the property tests are part of `cargo test`.

## F-08 `grants.sql` must track every migration

**Priority** P2 · **Effort** S · **Complexity** Low

**Finding.** In the PostgreSQL compose stack, the app role's rights come from [`deploy/docker/postgres-init/grants.sql`](../deploy/docker/postgres-init/grants.sql), and the same recipe appears in [operations.md](operations.md). A future migration that adds a table without updating both leaves the daemon with `permission denied` at runtime. Only the stack would show it, not the unit tests.

**Proposed fix.** Pick one:

- **(a) Simple.** Add a test in `zenv-ca-store-postgres` that runs the migrations, applies `grants.sql` to a fresh DML-only role, opens a `PostgresStore` as that role, and runs the conformance suite. A missing grant then fails `cargo test`.
- **(b) Thorough.** Move the grants into the crate as `PostgresStore::grant_app_role(role)` (or `zenv-ca db grant --role …`), generated from the same migration list. `grants.sql` and the docs then call it instead of duplicating it.

Option (a) can come first; (b) removes the duplication.

**Done when.** Adding a table without granting it fails a test.

## F-09 No backup / restore command

**Priority** P2 · **Effort** M · **Complexity** Medium

**Finding.** A CA's state is the keys and certificates in `data_dir` **plus** the database, and they must be backed up together. [operations.md](operations.md) describes doing this by hand (`sqlite3 .backup` or `pg_dump`, plus copying files). Restores are never verified, so the first real test of a backup is the disaster.

**Proposed fix.**

- `zenv-ca backup --out FILE`: takes a consistent snapshot. For SQLite that means the online backup API; for PostgreSQL, a dump within one transaction snapshot. It also includes `ca/` and `tls/` and a manifest with checksums, the audit head hash and the schema version. The output is a tarball encrypted with a passphrase.
- `zenv-ca restore --verify FILE --into DIR`: restores into a scratch location, checks the chain hash against the manifest, checks that the intermediate chains to the root, and reports the result.
- Restore can target a different backend, which overlaps with the roadmap's SQLite → PostgreSQL `db migrate`. Build both on the same export format.

**Done when.** Backup, wipe, restore and `audit verify` round-trip on both backends.

## F-10 Near-duplicate container configs

**Priority** P3 · **Effort** S · **Complexity** Medium

**Finding.** `deploy/docker/config/` has three TOML files that differ only in the `[database]` section. Every policy or subject change has to be made three times. A Helm chart (roadmap #13) would face the same problem.

**Proposed fix.** Support environment overrides on top of the file, for example `ZENV_CA__SERVER__PUBLIC_URL` or `ZENV_CA__DATABASE__URL`. The double underscore separates nesting levels; the `figment` or `config` crates do this. Then keep one base file and set the backend-specific values in compose `environment:`.

**Notes.** Overrides make it harder to see the effective configuration. Add `zenv-ca config show`, which prints the merged config with secrets redacted. `deny_unknown_fields` must still catch typos in variable names.

**Done when.** One config file serves all compose services, and `config show` explains the result.

## F-11 Concurrent CRL fetches can both re-sign

**Priority** P3 · **Effort** XS · **Complexity** Low

**Finding.** `AppState::current_crl` reads the cache, finds it stale, and calls `refresh_crl`, which takes the write lock and signs. Two requests that arrive together after a revocation both see a stale cache and both sign. The result is still correct, but it uses two CRL numbers and writes two `crl.generated` audit entries. With several instances behind a load balancer this happens more often. See [`state.rs`](../crates/zenv-ca-server/src/state.rs).

**Proposed fix.** Use double-checked locking: after acquiring the write lock in `refresh_crl`, re-read the revision and the cache and return the cached CRL if another request already refreshed it. The explicit refresh after an API revocation should still force a re-sign.

**Done when.** A test with N concurrent fetches after one revocation produces exactly one new CRL number.

## F-12 Keygen always requires a PKCS#12 password

**Priority** P3 · **Effort** XS · **Complexity** Low

**Finding.** `POST /api/v1/certificates/keygen` returns 422 unless `pkcs12_password` is present, even for clients that only want the PEM key and certificate. This came up while writing the container quick start.

**Proposed fix.** Make `pkcs12_password` optional. When it is absent, omit `pkcs12_base64` from the response. Keep the minimum length check when it is present, and update [api.md](api.md) and the UI.

**Done when.** A PEM-only keygen request succeeds and the response has no PKCS#12 field.

## F-13 Post-quantum signature experiment

**Priority** P3 · **Effort** L · **Complexity** High

**Finding.** The hierarchy uses ECDSA, RSA and Ed25519, none of which are quantum-resistant. Production CAs will need ML-DSA (FIPS 204) eventually. An experimental repo is a good place to learn what breaks first: client support, certificate sizes, and CRL and PKCS#12 tooling.

**Proposed fix.** Behind a `pqc` cargo feature, add `ml-dsa-65` as a key algorithm for a separate test hierarchy, using a maintained RustCrypto or aws-lc-rs implementation once `rcgen` can sign with it. Record what interoperates (OpenSSL 3.5+, Go, Java) in an ADR. Do not mix it into the default hierarchy.

**Done when.** An ML-DSA root, intermediate and leaf can be issued and verified with OpenSSL, and the ADR captures the interoperability results.

---

## Environment notes (not repo issues)

- **Podman on this host.** Homebrew podman 6.1.4 called the system `/usr/bin/crun` 1.14.1, which fails with "unknown version specified". Fix it with `runtime = "/home/linuxbrew/.linuxbrew/bin/crun"` under `[engine]` in `~/.config/containers/containers.conf`, then restart `podman.socket`.
- **podman-compose** ran the one-shot `init` service more than once per `up`. `init --if-needed` makes this harmless; Docker Compose runs it once.
