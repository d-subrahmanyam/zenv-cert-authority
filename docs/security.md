# Security model

## Assets

| Asset | Impact if compromised |
|---|---|
| Root private key | Attacker can mint any intermediate → full hierarchy rebuild, re-trust everywhere |
| Intermediate private key | Attacker can mint DMZ certs (limited by Name Constraints) until the intermediate is revoked/rotated |
| API tokens | Attacker can request certs within policy as that principal |
| Inventory DB | Loss → verification reports `Unknown` (fail closed); tampering → detectable via audit chain |
| End-user private keys | **Not held by the CA** (CSR path), handed over once and dropped (keygen path) |

## Trust boundaries

1. **Network → daemon**: TLS (rustls), bearer-token auth, body size limit (64 KiB), request timeout, strict JSON (`deny_unknown_fields`).
2. **Daemon → disk**: data dir `0700`, keys `0600`, DB `0600`, intermediate key encrypted (PBES2: PBKDF2-HMAC-SHA256 600k + AES-256-CBC).
3. **Online ↔ offline**: root key is only needed for `init` and intermediate rotation and should live offline.
4. **Browser → UI**: same-origin only (strict CSP, no inline script, `frame-ancestors 'none'`), DOM built with `textContent` only.

## STRIDE threat model

| Threat | Example | Controls |
|---|---|---|
| **S**poofing | Use a stolen/forged token | 256-bit random tokens; only SHA-256 hash stored; disable instantly (`zenv-ca token disable`); `last_used_at` tracking; failed auth logged |
| **S**poofing | Get a cert for `login.bank.com` or another team's host | Policy: allowed DNS suffixes on label boundaries, IP networks, no wildcards by default; **Name Constraints** in the intermediate make out-of-scope certs invalid for RFC 5280 clients even if mis-issued |
| **T**ampering | CSR asks for `CA:TRUE`, long lifetime, extra EKUs | Only the CSR's public key and names are used; everything else comes from the profile + policy; CSR self-signature is verified |
| **T**ampering | Edit the inventory or erase audit evidence | Mutations and audit rows in one transaction; append-only triggers; hash chain detects edits even if triggers are dropped; export head hash to SIEM for external anchoring |
| **R**epudiation | "I never requested that cert" | Every issuance/revocation records the principal, time, names and fingerprint in the audit chain |
| **I**nformation disclosure | Enumerate other teams' certificates | Requesters see only their own; foreign serials return `404` (not `403`) |
| **I**nformation disclosure | Private key leakage | CSR-first; keygen responses `Cache-Control: no-store`; keys zeroized in memory; never logged; never persisted |
| **D**enial of service | Large bodies, slowloris, CPU-heavy RSA keygen | Body limit, timeout, blocking work off the async executor; put rate limiting at the reverse proxy (roadmap: built-in) |
| **E**levation of privilege | Requester revokes others' certs, reads audit | Ownership checks on every cert route; `AdminAuth` extractor for admin routes; extractor-based auth means a handler cannot forget it |

## Cryptographic choices

| Purpose | Choice | Why |
|---|---|---|
| CA keys | ECDSA P-384 | Strong, universally supported for CA signatures |
| Default leaf keys | ECDSA P-256 | Universal TLS support, small, fast |
| Legacy leaf keys | RSA 2048/3072 | Old Java/appliances |
| Serials | 128-bit CSPRNG | CA/B Forum ≥64 bits; unpredictability defeats chosen-prefix attacks |
| Key at rest | PBES2 PBKDF2-SHA256 (600k) + AES-256-CBC | OpenSSL/Java/HSM-tool compatible (scrypt defaults exceed OpenSSL's memory cap) |
| PKCS#12 | PBES2 AES-256-CBC + HMAC-SHA256 MAC | Modern JDK defaults; readable by OpenSSL 3 and Java 8u301+ |
| Crypto backend | aws-lc-rs | FIPS-capable, one backend for signing, verification and TLS |

## Operational security checklist

- [ ] Run `zenv-ca init` on a trusted host; move `root.key.enc` + root passphrase to offline storage immediately.
- [ ] Supply the intermediate passphrase via `systemd LoadCredential`, never an environment variable.
- [ ] Use the hardened unit in [`deploy/zenv-cad.service`](../deploy/zenv-cad.service).
- [ ] Distribute `root.crt` with its SHA-256 fingerprint over a trusted channel.
- [ ] **Never** add this root to production trust stores.
- [ ] Give each team/pipeline its own `requester` token; keep `admin` tokens few.
- [ ] Ship JSON logs to the SIEM; alert on `rejected invalid bearer token`, `certificate revoked`, `audit chain BROKEN`.
- [ ] Periodically export `zenv-ca audit verify` head hash to an external system.
- [ ] Back up `/var/lib/zenv-ca` (encrypted) and test restores.

## Known limitations (see [roadmap](roadmap.md))

- No OIDC/SSO yet: tokens only.
- Single intermediate: rotating it means existing certs verify via CRL/chain only until they expire (verify API knows only the current intermediate).
- No HSM/PKCS#11 yet; key is software-protected.
- No built-in rate limiting.
