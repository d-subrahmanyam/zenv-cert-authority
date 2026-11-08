# Roadmap

Ordered by value for a DMZ CA. ✅ = done in v0.1.

## v0.1 (this release)
- ✅ Two-tier hierarchy, name-constrained intermediate, encrypted keys at rest
- ✅ CSR issuance, server-side keygen, profiles, policy engine
- ✅ PEM / DER / chain / full chain / PKCS#12 downloads
- ✅ CRL distribution, status API, verification API
- ✅ Token auth (requester/admin), ownership enforcement
- ✅ Hash-chained, append-only audit log
- ✅ Self-service web UI, admin CLI, hardened systemd unit

## Next

| # | Item | Why | Notes |
|---|---|---|---|
| 1 | **ACME (RFC 8555)** | cert-manager, Caddy, Traefik and certbot automate issuance + renewal with no UI | `instant-acme`-compatible server; HTTP-01 / DNS-01 inside the DMZ; External Account Binding mapped to tokens |
| 2 | **OIDC / SSO login** for the UI | named humans instead of shared tokens; group → allowed suffix mapping | `openidconnect` crate, PKCE; per-group policy overrides |
| 3 | **Per-principal policy** | team A only gets `*.shop.dmz…` | `allowed_dns_suffixes` per token / OIDC group |
| 4 | **Prometheus metrics** | `/metrics`: issued, revoked, expiring, auth failures | `metrics` + exporter |
| 5 | **Expiry notifications** | email / chat webhooks before expiry | builds on the existing expiry monitor |
| 6 | **OCSP responder** | clients that require OCSP (some Java/.NET configs) | `x509-ocsp` crate, delegated responder cert |
| 7 | **HSM / PKCS#11** for the intermediate key | key never in process memory | `cryptoki`; SoftHSM in CI; rcgen `SigningKey` impl |
| 8 | **Intermediate rotation** with overlap | verify/CRL for both old and new intermediates | multi-issuer `CertificateAuthority` |
| 9 | Built-in **rate limiting** | defence in depth | `tower_governor` per token / IP |
| 10 | **PKCS#7 (.p7b)** chain download | Windows / some appliances | `cms` crate |
| 11 | **PostgreSQL** backend | HA / multi-instance | trait the store; schema is plain SQL |
| 12 | Approval workflow | names outside a team's scope need an admin's approval | pending → approved state |
| 13 | Container image + Helm chart | k8s DMZ clusters | distroless, read-only rootfs |
