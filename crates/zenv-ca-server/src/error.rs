//! HTTP error type rendered as RFC 9457 `application/problem+json`.

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use zenv_ca_core::CaError;
use zenv_ca_store::StoreError;

/// An error returned by a handler.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    title: &'static str,
    detail: String,
}

#[derive(Serialize)]
struct Problem<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    title: &'a str,
    status: u16,
    detail: &'a str,
}

impl ApiError {
    /// Builds an error with an explicit status.
    pub fn new(status: StatusCode, title: &'static str, detail: impl Into<String>) -> Self {
        Self {
            status,
            title,
            detail: detail.into(),
        }
    }

    /// 400.
    pub fn bad_request(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad-request", detail)
    }

    /// 401.
    pub fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "a valid bearer token is required",
        )
    }

    /// 403.
    pub fn forbidden(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", detail)
    }

    /// 404.
    pub fn not_found(what: &str) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not-found", format!("{what} not found"))
    }

    /// 500. The detail is logged, never sent to the client.
    pub fn internal(detail: impl std::fmt::Display) -> Self {
        let id = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
        tracing::error!(error_id = %id, error = %detail, "internal error");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal-error",
            format!("internal error (reference {id})"),
        )
    }
}

impl From<CaError> for ApiError {
    fn from(e: CaError) -> Self {
        match e {
            CaError::Policy(d) => Self::new(StatusCode::FORBIDDEN, "policy-violation", d),
            CaError::InvalidCsr(d) => Self::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid-csr", d),
            CaError::InvalidInput(d) => Self::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid-input", d),
            other => Self::internal(other),
        }
    }
}

impl From<StoreError> for ApiError {
    fn from(e: StoreError) -> Self {
        Self::internal(e)
    }
}

impl From<tokio::task::JoinError> for ApiError {
    fn from(e: tokio::task::JoinError) -> Self {
        Self::internal(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = serde_json::to_vec(&Problem {
            kind: "about:blank",
            title: self.title,
            status: self.status.as_u16(),
            detail: &self.detail,
        })
        .unwrap_or_default();
        let mut response = (self.status, body).into_response();
        let headers = response.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        if self.status == StatusCode::UNAUTHORIZED {
            headers.insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"zenv-ca\""),
            );
        }
        response
    }
}

/// Handler result alias.
pub type ApiResult<T> = Result<T, ApiError>;
