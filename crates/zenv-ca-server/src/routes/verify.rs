//! Public validation endpoints: the CA's "verifier" role.
//!
//! TLS clients validate certificates locally and consult the CRL. These endpoints add an
//! *explicit* check for humans and for applications that want a live answer.

use axum::Json;
use axum::extract::{Path, State};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use zenv_ca_core::serial::normalise_serial;
use zenv_ca_core::{RevocationStatus, VerificationReport, VerifyOptions};

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Body of `POST /api/v1/verify`. Supply exactly one of the certificate fields.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyBody {
    #[serde(default)]
    certificate_pem: Option<String>,
    #[serde(default)]
    certificate_der_base64: Option<String>,
    /// Also require the certificate to be valid for this host name / IP.
    #[serde(default)]
    hostname: Option<String>,
    /// Evaluate validity at this instant (RFC 3339) instead of now.
    #[serde(default, with = "time::serde::rfc3339::option")]
    at: Option<time::OffsetDateTime>,
}

/// `POST /api/v1/verify`
pub async fn verify(
    State(state): State<AppState>,
    Json(body): Json<VerifyBody>,
) -> ApiResult<Json<VerificationReport>> {
    let input = match (body.certificate_pem, body.certificate_der_base64) {
        (Some(pem), None) => pem.into_bytes(),
        (None, Some(b64)) => STANDARD
            .decode(b64.trim())
            .map_err(|_| ApiError::bad_request("certificate_der_base64 is not valid base64"))?,
        _ => {
            return Err(ApiError::bad_request(
                "provide exactly one of certificate_pem or certificate_der_base64",
            ));
        }
    };
    let options = VerifyOptions {
        hostname: body.hostname,
        at: body.at,
    };
    let report = state
        .blocking(move |s| Ok(s.ca().verify(&input, &options, s.store())))
        .await?;
    Ok(Json(report))
}

#[derive(Serialize)]
pub struct StatusResponse {
    serial: String,
    #[serde(flatten)]
    status: RevocationStatus,
    /// Unix `notAfter`, when known.
    not_after: Option<i64>,
}

/// `GET /api/v1/certificates/{serial}/status`: a lightweight, OCSP-like JSON answer.
pub async fn status(
    State(state): State<AppState>,
    Path(serial): Path<String>,
) -> ApiResult<Json<StatusResponse>> {
    let serial = normalise_serial(&serial)?;
    let res = state
        .blocking(move |s| {
            let status = s.store().revocation_status(&serial)?;
            let not_after = s.store().get_certificate(&serial)?.map(|c| c.not_after);
            Ok(StatusResponse {
                serial,
                status,
                not_after,
            })
        })
        .await?;
    Ok(Json(res))
}
