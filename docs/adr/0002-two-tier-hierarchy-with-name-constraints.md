# ADR 0002: Two-tier hierarchy with a name-constrained intermediate

- **Status:** accepted

## Context
A single online root means any daemon compromise forces every DMZ host to re-trust a new root. A DMZ CA also must not be able to vouch for production or public names.

## Decision
- Root (P-384, 10 y, `pathLen=1`) is used only for `init` and intermediate rotation; its key is moved offline.
- Online intermediate (P-384, 3 y, `pathLen=0`) issues all leaves.
- The intermediate carries a **critical Name Constraints** extension equal to `policy.allowed_dns_suffixes` / `allowed_ip_networks`.
- Subjects carry `OU=DMZ Non-Production`.

## Consequences
+ Intermediate compromise is recoverable without touching trust stores.
+ Even a mis-issued certificate for `login.bank.com` fails RFC 5280 validation in clients.
− Widening the namespace requires issuing a new intermediate.
