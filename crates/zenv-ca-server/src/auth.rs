//! Bearer-token authentication extractors.
//!
//! The extractor is the single place authentication happens; handlers that take an
//! [`Auth`] or [`AdminAuth`] argument cannot be reached without a valid token.

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use zenv_ca_store::Principal;

use crate::error::ApiError;
use crate::state::AppState;

/// Any authenticated principal.
#[derive(Debug, Clone)]
pub struct Auth(pub Principal);

/// An authenticated administrator.
#[derive(Debug, Clone)]
pub struct AdminAuth(pub Principal);

fn bearer(parts: &Parts) -> Option<String> {
    let value = parts.headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| token.trim().to_owned())
}

impl FromRequestParts<AppState> for Auth {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let Some(token) = bearer(parts) else {
            return Err(ApiError::unauthorized());
        };
        let principal = state
            .blocking(move |s| Ok(s.store().authenticate(&token)?))
            .await?;
        match principal {
            Some(p) => Ok(Self(p)),
            None => {
                tracing::warn!(path = %parts.uri.path(), "rejected invalid bearer token");
                Err(ApiError::unauthorized())
            }
        }
    }
}

impl FromRequestParts<AppState> for AdminAuth {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let Auth(p) = Auth::from_request_parts(parts, state).await?;
        if p.is_admin() {
            Ok(Self(p))
        } else {
            Err(ApiError::forbidden("administrator role required"))
        }
    }
}
