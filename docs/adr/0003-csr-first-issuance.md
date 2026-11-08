# ADR 0003: CSR-first issuance; server-side keygen keeps no keys

- **Status:** accepted

## Context
Teams want "click and download", but a CA that stores everyone's private keys becomes the juiciest target in the DMZ.

## Decision
- The primary path is CSR submission: the requester keeps the private key.
- Only the CSR's **public key and names** are used. Key usage, EKU, basic constraints, validity and extensions come from a fixed **profile** + **policy**.
- Server-side keygen is offered for convenience (Java/.NET teams wanting a `.p12`) but: the key is returned once (PEM + PKCS#12), the response is `no-store`, the key is zeroized and never persisted, and admins can disable it (`allow_server_side_keygen = false`).

## Consequences
+ The CA never accumulates private keys.
+ A malicious CSR cannot request a CA certificate or a long lifetime.
− Lost keygen keys cannot be recovered: issue a new certificate.
