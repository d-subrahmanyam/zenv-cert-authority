# ADR 0005: CRL + JSON status API first; OCSP and ACME later

- **Status:** accepted

## Context
Relying parties need revocation information. Options: CRL, OCSP, short-lived certs, custom API.

## Decision
- Publish a CRL at a stable URL embedded in every certificate; re-sign on revocation and at half-life (default validity 7 days).
- Offer `GET /api/v1/certificates/{serial}/status` and `POST /api/v1/verify` for explicit, human-friendly checks.
- Keep leaf lifetimes short (30 d default, 90 d max) so revocation matters less.
- OCSP and ACME are deferred (roadmap).

## Consequences
+ Works with OpenSSL, Java, Go, nginx (`ssl_crl`) today; simple to operate.
− Clients that insist on OCSP need the roadmap item; CRL freshness depends on client caching.
