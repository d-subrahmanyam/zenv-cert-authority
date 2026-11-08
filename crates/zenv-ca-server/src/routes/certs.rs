//! Certificate issuance, listing, download and revocation.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use zenv_ca_core::export::{pkcs12_bundle, render_certificate};
use zenv_ca_core::keys::private_key_pem;
use zenv_ca_core::serial::normalise_serial;
use zenv_ca_core::{CertFormat, CertProfile, CsrRequest, KeyAlgorithm, KeygenRequest, RevocationReason};
use zenv_ca_store::{CertFilter, CertStatus, CertificateRecord, IssuanceMethod, Principal, RevokeOutcome};
use zeroize::Zeroizing;

use crate::auth::Auth;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Loads a certificate the principal is allowed to see (owner or admin). Unauthorised
/// access answers 404 rather than 403, so serial numbers cannot be probed.
fn owned_certificate(state: &AppState, principal: &Principal, serial: &str) -> ApiResult<CertificateRecord> {
    let serial = normalise_serial(serial)?;
    match state.store().get_certificate(&serial)? {
        Some(rec) if principal.is_admin() || rec.requested_by == principal.name => Ok(rec),
        _ => Err(ApiError::not_found("certificate")),
    }
}

fn created(record: impl Serialize, serial: &str) -> Response {
    let mut res = (StatusCode::CREATED, Json(record)).into_response();
    if let Ok(v) = HeaderValue::from_str(&format!("/api/v1/certificates/{serial}")) {
        res.headers_mut().insert(header::LOCATION, v);
    }
    res
}

/// `POST /api/v1/certificates`: sign a CSR (recommended: the key never leaves the client).
pub async fn issue_from_csr(
    State(state): State<AppState>,
    Auth(principal): Auth,
    Json(request): Json<CsrRequest>,
) -> ApiResult<Response> {
    let record = state
        .blocking(move |s| {
            let issued = s.ca().issue_from_csr(&request)?;
            s.store().insert_certificate(&issued, IssuanceMethod::Csr, &principal.name)?;
            tracing::info!(serial = %issued.serial, cn = %issued.common_name, by = %principal.name, "certificate issued from CSR");
            s.store().get_certificate(&issued.serial)?.ok_or_else(|| ApiError::internal("record vanished"))
        })
        .await?;
    let serial = record.serial.clone();
    Ok(created(record, &serial))
}

/// Body of `POST /api/v1/certificates/keygen`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeygenBody {
    #[serde(default)]
    common_name: Option<String>,
    #[serde(default)]
    dns_names: Vec<String>,
    #[serde(default)]
    ip_addresses: Vec<std::net::IpAddr>,
    #[serde(default)]
    profile: CertProfile,
    #[serde(default)]
    validity_days: Option<u32>,
    #[serde(default)]
    key_algorithm: KeyAlgorithm,
    /// Password protecting the returned PKCS#12 bundle.
    pkcs12_password: Zeroizing<String>,
}

#[derive(Serialize)]
struct KeygenResponse {
    certificate: CertificateRecord,
    /// Unencrypted PKCS#8 PEM. Returned exactly once; the CA keeps no copy.
    private_key_pem: Zeroizing<String>,
    /// Password-protected PKCS#12 (key + leaf + chain), base64.
    pkcs12_base64: String,
}

/// `POST /api/v1/certificates/keygen`: the CA generates the key pair (convenience path).
pub async fn issue_with_keygen(
    State(state): State<AppState>,
    Auth(principal): Auth,
    Json(body): Json<KeygenBody>,
) -> ApiResult<Response> {
    let response = state
        .blocking(move |s| {
            let request = KeygenRequest {
                common_name: body.common_name,
                dns_names: body.dns_names,
                ip_addresses: body.ip_addresses,
                profile: body.profile,
                validity_days: body.validity_days,
                key_algorithm: body.key_algorithm,
            };
            let (issued, key) = s.ca().issue_with_generated_key(&request)?;
            let alias = issued.common_name.clone();
            // Build the bundle before recording, so a weak password fails the request
            // without leaving an orphaned certificate behind.
            let p12 = pkcs12_bundle(&issued.cert_pem, &key, s.ca(), &alias, &body.pkcs12_password)?;
            s.store().insert_certificate(&issued, IssuanceMethod::Keygen, &principal.name)?;
            tracing::info!(serial = %issued.serial, cn = %issued.common_name, by = %principal.name, "certificate issued with server-side key");
            let certificate = s
                .store()
                .get_certificate(&issued.serial)?
                .ok_or_else(|| ApiError::internal("record vanished"))?;
            Ok(KeygenResponse {
                certificate,
                private_key_pem: private_key_pem(&key),
                pkcs12_base64: STANDARD.encode(p12),
            })
        })
        .await?;
    let serial = response.certificate.serial.clone();
    Ok(created(response, &serial))
}

/// Query string of `GET /api/v1/certificates`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListQuery {
    #[serde(default)]
    status: Option<CertStatus>,
    #[serde(default)]
    search: Option<String>,
    /// Admins only: filter by requester. Requesters always see only their own.
    #[serde(default)]
    requested_by: Option<String>,
    #[serde(default)]
    limit: Option<u32>,
    #[serde(default)]
    offset: Option<u32>,
}

/// `GET /api/v1/certificates`
pub async fn list(
    State(state): State<AppState>,
    Auth(principal): Auth,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Vec<CertificateRecord>>> {
    let filter = CertFilter {
        requested_by: if principal.is_admin() {
            q.requested_by
        } else {
            Some(principal.name.clone())
        },
        status: q.status,
        search: q.search.filter(|s| !s.trim().is_empty()),
        limit: q.limit.unwrap_or(100),
        offset: q.offset.unwrap_or(0),
    };
    let rows = state
        .blocking(move |s| Ok(s.store().list_certificates(&filter)?))
        .await?;
    Ok(Json(rows))
}

/// `GET /api/v1/certificates/{serial}`
pub async fn get_one(
    State(state): State<AppState>,
    Auth(principal): Auth,
    Path(serial): Path<String>,
) -> ApiResult<Json<CertificateRecord>> {
    let rec = state
        .blocking(move |s| owned_certificate(s, &principal, &serial))
        .await?;
    Ok(Json(rec))
}

/// Query string of the download endpoint.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DownloadQuery {
    #[serde(default)]
    format: CertFormat,
}

/// `GET /api/v1/certificates/{serial}/download?format=pem|der|chain|fullchain`
pub async fn download(
    State(state): State<AppState>,
    Auth(principal): Auth,
    Path(serial): Path<String>,
    Query(q): Query<DownloadQuery>,
) -> ApiResult<Response> {
    let (rec, body) = state
        .blocking(move |s| {
            let rec = owned_certificate(s, &principal, &serial)?;
            let body = render_certificate(&rec.cert_pem, s.ca(), q.format)?;
            Ok((rec, body))
        })
        .await?;
    let safe_cn: String = rec
        .common_name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let filename = format!(
        "{safe_cn}-{}{}",
        &rec.serial[..8.min(rec.serial.len())],
        q.format.file_suffix()
    );
    let mut res = body.into_response();
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(q.format.content_type()),
    );
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    Ok(res)
}

/// Body of the revoke endpoint.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeBody {
    #[serde(default)]
    reason: RevocationReason,
}

/// `POST /api/v1/certificates/{serial}/revoke`: idempotent; re-signs the CRL immediately.
pub async fn revoke(
    State(state): State<AppState>,
    Auth(principal): Auth,
    Path(serial): Path<String>,
    body: Option<Json<RevokeBody>>,
) -> ApiResult<Json<CertificateRecord>> {
    let reason = body.map(|Json(b)| b.reason).unwrap_or_default();
    let rec = state
        .blocking(move |s| {
            let rec = owned_certificate(s, &principal, &serial)?;
            match s.store().revoke(&rec.serial, reason, &principal.name)? {
                RevokeOutcome::Revoked(r) => {
                    tracing::warn!(serial = %r.serial, %reason, by = %principal.name, "certificate revoked");
                    s.refresh_crl()?;
                    Ok(*r)
                }
                RevokeOutcome::AlreadyRevoked(r) => Ok(*r),
                RevokeOutcome::NotFound => Err(ApiError::not_found("certificate")),
            }
        })
        .await?;
    Ok(Json(rec))
}
