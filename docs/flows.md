# Flows (sequence & state diagrams)

PlantUML sources with more detail live in [`uml/`](uml/). The Mermaid diagrams below render on GitHub.

- [Bootstrap](#uc10-bootstrap)
- [Issue from CSR](#uc1-issue-from-csr)
- [Server-side keygen](#uc2-server-side-keygen)
- [Runtime TLS validation by a relying party](#runtime-tls-validation)
- [Explicit verification](#uc6-explicit-verification)
- [Revocation & CRL](#uc5-revocation--crl-publication)
- [Certificate lifecycle](#certificate-lifecycle)

## UC10: Bootstrap

```mermaid
sequenceDiagram
    autonumber
    actor Admin
    participant CLI as zenv-ca CLI
    participant Core as zenv-ca-core
    participant FS as data_dir
    participant DB as Store (SQLite / PostgreSQL)
    Admin->>CLI: zenv-ca init --root-passphrase-file …
    CLI->>CLI: refuse if CA exists · passphrases ≥12 chars and different
    CLI->>FS: create data/, ca/, tls/ (0700)
    CLI->>Core: create_root (P-384, pathLen=1, 10y)
    CLI->>FS: root.crt + root.key.enc (PBES2, 0600)
    CLI->>Core: create_intermediate (pathLen=0, Name Constraints, ≤ root expiry)
    CLI->>FS: intermediate.crt + intermediate.key.enc
    CLI->>Core: CertificateAuthority::load (key↔cert + chain check)
    CLI->>DB: migrate · audit "ca.initialised"
    CLI->>Core: issue daemon TLS cert
    CLI->>FS: tls/server.chain.pem + server.key (0600)
    CLI->>DB: create admin token (hash only)
    CLI-->>Admin: root SHA-256 · admin token (once) · "move root key offline"
```

## UC1: Issue from CSR

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer / CI
    participant Tool as openssl
    participant API as zenv-cad (router + auth)
    participant CA as CertificateAuthority
    participant Pol as IssuancePolicy
    participant DB as Store
    Dev->>Tool: generate key + CSR locally
    Note right of Tool: private key never leaves the requester
    Dev->>API: POST /api/v1/certificates (Bearer token, csr_pem, profile)
    API->>DB: authenticate(sha256(token))
    alt invalid token
        API-->>Dev: 401 problem+json
    end
    API->>CA: issue_from_csr (spawn_blocking)
    CA->>CA: parse CSR + verify self-signature
    CA->>Pol: resolve_validity · check_names
    alt policy violation
        CA-->>API: Policy error
        API-->>Dev: 403 policy-violation
    end
    CA->>CA: params from PROFILE (KU, EKU, CA:FALSE, CRL DP, random serial)
    CA->>CA: sign with intermediate
    CA->>DB: tx { insert certificate · audit "certificate.issued" }
    API-->>Dev: 201 Created + Location
    Dev->>API: GET …/{serial}/download?format=chain
    API-->>Dev: leaf + intermediate PEM
```

## UC2: Server-side keygen

```mermaid
sequenceDiagram
    autonumber
    actor U as User
    participant UI as Web UI
    participant API as zenv-cad
    participant CA as CertificateAuthority
    participant DB as Store
    U->>UI: names, profile, algorithm, PKCS#12 password
    UI->>API: POST /api/v1/certificates/keygen
    API->>CA: issue_with_generated_key
    CA->>CA: keygen allowed? → generate key → policy → sign
    API->>API: build PKCS#12 (AES-256-CBC, HMAC-SHA256)
    alt weak password
        API-->>UI: 422, nothing recorded
    end
    API->>DB: tx { insert (method=keygen) · audit }
    API-->>UI: 201 {certificate, private_key_pem, pkcs12_base64} · no-store
    Note over API: key dropped & zeroized: CA keeps no copy
    UI-->>U: .p12 / .key downloads (Blob, client-side)
```

## Runtime TLS validation

How certificates are actually validated in the DMZ. **The CA is not on the hot path**: clients validate locally and only fetch the CRL.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client (root.crt in trust store)
    participant S as DMZ server (leaf + intermediate)
    participant CA as zenv-cad /pki/crl.der
    C->>S: ClientHello (SNI)
    S-->>C: Certificate chain
    rect rgba(127,127,127,0.12)
    Note over C: local path validation
    C->>C: chain → root · signatures · validity
    C->>C: pathLen · KU/EKU · Name Constraints
    C->>C: host name ∈ SANs
    end
    opt revocation checking
        C->>CA: GET CRL (cached until nextUpdate)
        CA-->>C: CRL signed by intermediate
        C->>C: serial not listed?
    end
    C->>S: continue or abort handshake
```

## UC6: Explicit verification

```mermaid
sequenceDiagram
    autonumber
    actor X as Human / app
    participant API as zenv-cad
    participant V as verify()
    participant DB as Store
    X->>API: POST /api/v1/verify {certificate_pem, hostname?}
    API->>V: verify(input, options, store)
    V->>V: parse · signature by our intermediate · chain to root
    V->>V: validity · not a CA · Name Constraints
    V->>DB: status(serial)
    DB-->>V: Good / Revoked / Unknown
    V->>V: hostname match (optional)
    API-->>X: {valid, checks[]}
```

## UC5: Revocation & CRL publication

```mermaid
sequenceDiagram
    autonumber
    actor O as Owner / Admin
    participant API as zenv-cad
    participant St as CRL cache
    participant CA as CertificateAuthority
    participant DB as Store
    participant RP as Relying party
    O->>API: POST …/{serial}/revoke {reason}
    API->>DB: owner or admin? (else 404)
    API->>DB: tx { mark revoked · audit }
    API->>St: refresh_crl
    St->>DB: crl_entries · next_crl_number
    St->>CA: build_crl → signed CRL
    API-->>O: 200 revoked
    Note over DB: CLI revocations: cache keyed on revocation revision
    RP->>API: GET /pki/crl.der
    API->>St: current_crl (fresh & unchanged? else re-sign)
    API-->>RP: application/pkix-crl
```

## Certificate lifecycle

```mermaid
stateDiagram-v2
    [*] --> Requested: CSR / keygen
    Requested --> Rejected: auth / policy / bad CSR
    Rejected --> [*]
    Requested --> Active: signed, recorded, audited
    Active --> Revoked: revoke(reason) → CRL re-signed
    Active --> Expired: now > notAfter
    Revoked --> Expired: now > notAfter (dropped from CRL)
    Expired --> [*]
```
