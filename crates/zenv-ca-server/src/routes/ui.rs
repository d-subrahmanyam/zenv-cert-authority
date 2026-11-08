//! The self-service web UI: static assets compiled into the binary.
//!
//! The UI is a thin client over the JSON API: no server-side templating, so there is
//! exactly one code path for every operation and nothing UI-specific to secure.

use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};

const INDEX_HTML: &str = include_str!("../../ui/index.html");
const APP_JS: &str = include_str!("../../ui/app.js");
const STYLE_CSS: &str = include_str!("../../ui/style.css");

fn asset(body: &'static str, content_type: &'static str) -> Response {
    let mut res = body.into_response();
    let h = res.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    res
}

/// `GET /`
pub async fn index() -> Response {
    asset(INDEX_HTML, "text/html; charset=utf-8")
}

/// `GET /ui/app.js`
pub async fn app_js() -> Response {
    asset(APP_JS, "text/javascript; charset=utf-8")
}

/// `GET /ui/style.css`
pub async fn style_css() -> Response {
    asset(STYLE_CSS, "text/css; charset=utf-8")
}
