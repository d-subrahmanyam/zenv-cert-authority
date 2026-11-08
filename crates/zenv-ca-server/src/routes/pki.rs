//! Public PKI endpoints: trust anchors, CRL, CA info, health.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use zenv_ca_core::{CertFormat, CertProfile, KeyAlgorithm};

use crate::error::ApiResult;
use crate::state::AppState;

fn file(body: impl Into<Vec<u8>>, content_type: &'static str, filename: &str, cache_secs: u32) -> Response {
    let mut res = body.into().into_response();
    let h = res.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    if let Ok(v) = HeaderValue::from_str(&format!("public, max-age={cache_secs}")) {
        h.insert(header::CACHE_CONTROL, v);
    }
    res
}

/// `GET /healthz`: liveness (process is up).
pub async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

/// `GET /readyz`: readiness (database reachable).
pub async fn readyz(State(state): State<AppState>) -> ApiResult<Json<serde_json::Value>> {
    let backend = state
        .blocking(|s| {
            s.store().ping()?;
            Ok(s.store().backend())
        })
        .await?;
    Ok(Json(
        serde_json::json!({ "status": "ready", "database": backend }),
    ))
}

/// `GET /pki/root.crt`
pub async fn root_pem(State(state): State<AppState>) -> Response {
    file(
        state.ca().root_pem().as_bytes(),
        "application/x-pem-file",
        "zenv-dmz-root.crt",
        3600,
    )
}

/// `GET /pki/root.der`
pub async fn root_der(State(state): State<AppState>) -> Response {
    file(
        state.ca().root_der(),
        "application/pkix-cert",
        "zenv-dmz-root.cer",
        3600,
    )
}

/// `GET /pki/intermediate.crt`
pub async fn intermediate_pem(State(state): State<AppState>) -> Response {
    file(
        state.ca().intermediate_pem().as_bytes(),
        "application/x-pem-file",
        "zenv-dmz-intermediate.crt",
        3600,
    )
}

/// `GET /pki/chain.pem`: intermediate + root.
pub async fn chain_pem(State(state): State<AppState>) -> Response {
    file(
        state.ca().chain_pem(),
        "application/x-pem-file",
        "zenv-dmz-ca-chain.pem",
        3600,
    )
}

/// `GET /pki/crl.der`: the URL embedded in every certificate.
pub async fn crl_der(State(state): State<AppState>) -> ApiResult<Response> {
    let crl = state.blocking(|s| s.current_crl()).await?;
    Ok(file(crl.der, "application/pkix-crl", "zenv-dmz.crl", 300))
}

/// `GET /pki/crl.pem`
pub async fn crl_pem(State(state): State<AppState>) -> ApiResult<Response> {
    let crl = state.blocking(|s| s.current_crl()).await?;
    Ok(file(crl.pem, "application/x-pem-file", "zenv-dmz.crl.pem", 300))
}

#[derive(Serialize)]
pub struct CaInfo {
    root_pem: String,
    intermediate_pem: String,
    root_sha256: String,
    intermediate_sha256: String,
    allowed_dns_suffixes: Vec<String>,
    allowed_ip_networks: Vec<String>,
    default_validity_days: u32,
    max_validity_days: u32,
    allow_wildcards: bool,
    allow_server_side_keygen: bool,
    profiles: Vec<CertProfile>,
    key_algorithms: Vec<KeyAlgorithm>,
    download_formats: Vec<String>,
}

/// `GET /api/v1/ca`: everything a client (or the UI) needs to know about this CA.
pub async fn ca_info(State(state): State<AppState>) -> Json<CaInfo> {
    use zenv_ca_core::verify::openssl_fingerprint as fp;
    let ca = state.ca();
    let p = ca.policy();
    Json(CaInfo {
        root_pem: ca.root_pem().to_owned(),
        intermediate_pem: ca.intermediate_pem().to_owned(),
        root_sha256: fp(ca.root_der()),
        intermediate_sha256: fp(ca.intermediate_der()),
        allowed_dns_suffixes: p.allowed_dns_suffixes.clone(),
        allowed_ip_networks: p.allowed_ip_networks.clone(),
        default_validity_days: p.default_validity_days,
        max_validity_days: p.max_validity_days,
        allow_wildcards: p.allow_wildcards,
        allow_server_side_keygen: p.allow_server_side_keygen,
        profiles: vec![
            CertProfile::Server,
            CertProfile::Client,
            CertProfile::ServerClient,
        ],
        key_algorithms: vec![
            KeyAlgorithm::EcdsaP256,
            KeyAlgorithm::EcdsaP384,
            KeyAlgorithm::Rsa2048,
            KeyAlgorithm::Rsa3072,
            KeyAlgorithm::Ed25519,
        ],
        download_formats: [
            CertFormat::Pem,
            CertFormat::Der,
            CertFormat::Chain,
            CertFormat::Fullchain,
        ]
        .iter()
        .map(ToString::to_string)
        .chain(std::iter::once("pkcs12".to_string()))
        .collect(),
    })
}
