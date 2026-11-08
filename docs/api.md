# HTTP API reference (v1)

Base URL: `https://<host>:8443`. Errors are RFC 9457 `application/problem+json`:

```json
{ "type": "about:blank", "title": "policy-violation", "status": 403,
  "detail": "'login.bank.com' is outside the allowed DNS suffixes (dmz.zenv.internal)" }
```

| Status | `title` | Meaning |
|---|---|---|
| 400 | `bad-request` | malformed request |
| 401 | `unauthorized` | missing/invalid bearer token (`WWW-Authenticate: Bearer`) |
| 403 | `forbidden` / `policy-violation` | role insufficient / policy refused the request |
| 404 | `not-found` | unknown, or not yours |
| 413 | | body > `max_body_bytes` |
| 422 | `invalid-csr` / `invalid-input` | CSR or input could not be processed |
| 500 | `internal-error` | logged with a reference id |

Authentication: `Authorization: Bearer zca_…`.

## Public endpoints

| Method & path | Description |
|---|---|
| `GET /healthz` | liveness → `{"status":"ok"}` |
| `GET /readyz` | readiness (DB reachable) |
| `GET /pki/root.crt` · `/pki/root.der` | root certificate |
| `GET /pki/intermediate.crt` | intermediate certificate |
| `GET /pki/chain.pem` | intermediate + root |
| `GET /pki/crl.der` · `/pki/crl.pem` | current CRL |
| `GET /api/v1/ca` | fingerprints, policy summary, profiles, algorithms, formats |
| `POST /api/v1/verify` | verification report |
| `GET /api/v1/certificates/{serial}/status` | `good` / `revoked` / `unknown` |

### `POST /api/v1/verify`

```bash
jq -n --rawfile c server.crt '{certificate_pem:$c, hostname:"shop.dmz.zenv.internal"}' |
  curl -sS --cacert root.crt -H 'Content-Type: application/json' -d @- https://ca.dmz.zenv.internal:8443/api/v1/verify
```

Body: exactly one of `certificate_pem` / `certificate_der_base64`; optional `hostname`, `at` (RFC 3339).

```json
{ "valid": false, "serial": "12cd…", "subject": "CN=shop.dmz.zenv.internal", "dns_names": ["shop.dmz.zenv.internal"],
  "revocation": { "status": "revoked", "revoked_at": 1794146098, "reason": "key-compromise" },
  "checks": [
    { "name": "parse", "passed": true, "detail": "certificate parsed" },
    { "name": "signature", "passed": true, "detail": "signed by this CA's intermediate" },
    { "name": "chain", "passed": true, "detail": "intermediate chains to the root" },
    { "name": "validity", "passed": true, "detail": "within validity period" },
    { "name": "basic-constraints", "passed": true, "detail": "end-entity certificate" },
    { "name": "name-constraints", "passed": true, "detail": "all names within dmz.zenv.internal" },
    { "name": "revocation", "passed": false, "detail": "revoked (key-compromise)" },
    { "name": "hostname", "passed": true, "detail": "valid for 'shop.dmz.zenv.internal'" } ] }
```

## Authenticated endpoints

| Method & path | Role | Description |
|---|---|---|
| `GET /api/v1/me` | any | `{token_id, name, role}` |
| `POST /api/v1/certificates` | any | issue from CSR → `201` + `Location` |
| `POST /api/v1/certificates/keygen` | any | CA generates key → `201` |
| `GET /api/v1/certificates` | any | list (own; admin: all). Query: `status`, `search`, `requested_by` (admin), `limit` ≤500, `offset` |
| `GET /api/v1/certificates/{serial}` | owner/admin | record |
| `GET /api/v1/certificates/{serial}/download?format=` | owner/admin | `pem` · `der` · `chain` · `fullchain` |
| `POST /api/v1/certificates/{serial}/revoke` | owner/admin | body `{"reason": "…"}` (optional); idempotent |
| `GET /api/v1/audit?limit=` | admin | newest-first audit entries |
| `GET /api/v1/audit/verify` | admin | `{entries, intact, first_broken_id, head_hash}` |

### Issue from CSR

```bash
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout shop.key -out shop.csr -subj "/CN=shop.dmz.zenv.internal" \
  -addext "subjectAltName=DNS:shop.dmz.zenv.internal"

jq -n --rawfile csr shop.csr '{csr_pem:$csr, profile:"server", validity_days:30}' |
  curl -sS --cacert root.crt -H "Authorization: Bearer $ZCA_TOKEN" \
       -H 'Content-Type: application/json' -d @- \
       https://ca.dmz.zenv.internal:8443/api/v1/certificates
```

Request fields: `csr_pem` (required), `profile` (`server` | `client` | `server-client`, default `server`), `validity_days` (default policy default).

Response (`CertificateRecord`):

```json
{ "serial": "12cd2f7b7e4ffbd41c242d3e72c669bb", "common_name": "shop.dmz.zenv.internal",
  "dns_names": ["shop.dmz.zenv.internal"], "ip_addresses": [], "profile": "server",
  "key_algorithm": "ecdsa-p256", "issuance_method": "csr", "requested_by": "team-shop",
  "not_before": 1794145798, "not_after": 1796738098, "fingerprint_sha256": "…",
  "cert_pem": "-----BEGIN CERTIFICATE-----…", "created_at": 1794146098,
  "revoked_at": null, "revocation_reason": null, "revoked_by": null, "status": "active" }
```

### Keygen

```json
POST /api/v1/certificates/keygen
{ "dns_names": ["java-app.dmz.zenv.internal"], "ip_addresses": [], "profile": "server",
  "key_algorithm": "rsa2048", "validity_days": 30, "pkcs12_password": "≥8 chars" }
```

Response: `{ "certificate": CertificateRecord, "private_key_pem": "…", "pkcs12_base64": "…" }` with `Cache-Control: no-store`. **The key is not retrievable later.**

`key_algorithm`: `ecdsa-p256` (default), `ecdsa-p384`, `rsa2048`, `rsa3072`, `ed25519`.

### Download & use

```bash
curl -sS --cacert root.crt -H "Authorization: Bearer $ZCA_TOKEN" -OJ \
  "https://ca.dmz.zenv.internal:8443/api/v1/certificates/$SERIAL/download?format=chain"
```

| Consumer | Use |
|---|---|
| nginx | `ssl_certificate chain.pem; ssl_certificate_key shop.key;` |
| HAProxy | `cat chain.pem shop.key > haproxy.pem` |
| Spring Boot | `server.ssl.key-store=app.p12`, `server.ssl.key-store-type=PKCS12` |
| Go | `tls.LoadX509KeyPair("chain.pem", "shop.key")` |
| Node | `https.createServer({ cert: chain, key })` |
| Windows/IIS | import the `.p12` |
