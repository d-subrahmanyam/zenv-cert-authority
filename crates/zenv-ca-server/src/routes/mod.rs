//! Router assembly and cross-cutting middleware.

mod admin;
mod certs;
mod pki;
mod ui;
mod verify;

use std::time::Duration;

use axum::Router;
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::routing::{get, post};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::state::AppState;

/// Content-Security-Policy for the UI: same-origin only, no inline script, no framing.
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
                   connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

/// Limits applied to every request.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Maximum body size in bytes.
    pub max_body_bytes: usize,
    /// Per-request timeout.
    pub timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_body_bytes: 64 * 1024,
            timeout: Duration::from_secs(30),
        }
    }
}

/// Builds the complete application router.
pub fn router(state: AppState, limits: Limits) -> Router {
    let api = Router::new()
        // Public: relying parties and humans debugging TLS need these without a token.
        .route("/ca", get(pki::ca_info))
        .route("/verify", post(verify::verify))
        .route("/certificates/{serial}/status", get(verify::status))
        // Authenticated.
        .route("/me", get(admin::me))
        .route("/certificates", post(certs::issue_from_csr).get(certs::list))
        .route("/certificates/keygen", post(certs::issue_with_keygen))
        .route("/certificates/{serial}", get(certs::get_one))
        .route("/certificates/{serial}/download", get(certs::download))
        .route("/certificates/{serial}/revoke", post(certs::revoke))
        // Admin.
        .route("/audit", get(admin::audit_log))
        .route("/audit/verify", get(admin::audit_verify))
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ));

    let hsts = state.tls_enabled().then(|| {
        SetResponseHeaderLayer::if_not_present(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000"),
        )
    });

    Router::new()
        .route("/", get(ui::index))
        .route("/ui/app.js", get(ui::app_js))
        .route("/ui/style.css", get(ui::style_css))
        .route("/healthz", get(pki::healthz))
        .route("/readyz", get(pki::readyz))
        .route("/pki/root.crt", get(pki::root_pem))
        .route("/pki/root.der", get(pki::root_der))
        .route("/pki/intermediate.crt", get(pki::intermediate_pem))
        .route("/pki/chain.pem", get(pki::chain_pem))
        .route("/pki/crl.der", get(pki::crl_der))
        .route("/pki/crl.pem", get(pki::crl_pem))
        .nest("/api/v1", api)
        .fallback(|| async { crate::error::ApiError::not_found("route") })
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(CSP),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("cross-origin-opener-policy"),
            HeaderValue::from_static("same-origin"),
        ))
        .layer(tower::util::option_layer(hsts))
        .layer(RequestBodyLimitLayer::new(limits.max_body_bytes))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            limits.timeout,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
