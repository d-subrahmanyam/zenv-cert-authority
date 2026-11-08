//! Identity and audit endpoints.

use axum::Json;
use axum::extract::{Query, State};
use serde::Deserialize;
use zenv_ca_store::{AuditRecord, AuditVerification, Principal};

use crate::auth::{AdminAuth, Auth};
use crate::error::ApiResult;
use crate::state::AppState;

/// `GET /api/v1/me`: who am I?
pub async fn me(Auth(principal): Auth) -> Json<Principal> {
    Json(principal)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditQuery {
    #[serde(default)]
    limit: Option<u32>,
}

/// `GET /api/v1/audit` (admin)
pub async fn audit_log(
    State(state): State<AppState>,
    AdminAuth(_): AdminAuth,
    Query(q): Query<AuditQuery>,
) -> ApiResult<Json<Vec<AuditRecord>>> {
    let limit = q.limit.unwrap_or(100).min(1000);
    Ok(Json(
        state.blocking(move |s| Ok(s.store().audit_log(limit)?)).await?,
    ))
}

/// `GET /api/v1/audit/verify` (admin): recompute the hash chain.
pub async fn audit_verify(
    State(state): State<AppState>,
    AdminAuth(_): AdminAuth,
) -> ApiResult<Json<AuditVerification>> {
    Ok(Json(
        state.blocking(|s| Ok(s.store().verify_audit_chain()?)).await?,
    ))
}
