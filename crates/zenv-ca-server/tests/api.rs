//! In-process API tests: the real router, an in-memory database, a throwaway CA.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use zenv_ca_core::hierarchy::{create_intermediate, create_root};
use zenv_ca_core::*;
use zenv_ca_server::routes::{Limits, router};
use zenv_ca_server::state::AppState;
use zenv_ca_store::{CaStore, Role};
use zenv_ca_store_sqlite::SqliteStore;

struct Harness {
    app: Router,
    alice: String,
    bob: String,
    admin: String,
}

fn harness() -> Harness {
    let policy = IssuancePolicy::default();
    let subject = |cn: &str| CaSubject {
        common_name: cn.into(),
        organization: "Test".into(),
        organizational_unit: "DMZ Non-Production".into(),
    };
    let root = create_root(&CaSpec {
        subject: subject("Root"),
        validity_days: 3650,
        key_algorithm: KeyAlgorithm::EcdsaP256,
    })
    .unwrap();
    let inter = create_intermediate(
        &root.cert_pem,
        &root.key,
        &CaSpec {
            subject: subject("Issuing"),
            validity_days: 365,
            key_algorithm: KeyAlgorithm::EcdsaP256,
        },
        &policy,
    )
    .unwrap();
    let ca = CertificateAuthority::load(
        &root.cert_pem,
        &inter.cert_pem,
        inter.key,
        policy,
        Some("https://ca.test/pki/crl.der".into()),
    )
    .unwrap();
    let store = SqliteStore::open_in_memory().unwrap();
    let (_, alice) = store.create_token("alice", Role::Requester, "test").unwrap();
    let (_, bob) = store.create_token("bob", Role::Requester, "test").unwrap();
    let (_, admin) = store.create_token("ops", Role::Admin, "test").unwrap();
    let state = AppState::new(ca, std::sync::Arc::new(store), time::Duration::days(7), true);
    Harness {
        app: router(state, Limits::default()),
        alice,
        bob,
        admin,
    }
}

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let mut req = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let req = match body {
        Some(b) => req
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(b.to_string())),
        None => req.body(Body::empty()),
    }
    .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = res.into_body().collect().await.unwrap().to_bytes().to_vec();
    (status, headers, bytes)
}

fn json_of(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap_or_else(|_| panic!("not JSON: {}", String::from_utf8_lossy(bytes)))
}

fn make_csr(names: &[&str]) -> String {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params =
        rcgen::CertificateParams::new(names.iter().map(|s| (*s).to_string()).collect::<Vec<_>>()).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.serialize_request(&key).unwrap().pem().unwrap()
}

#[tokio::test]
async fn public_endpoints_and_security_headers() {
    let h = harness();
    let (status, headers, body) = call(&h.app, "GET", "/healthz", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json_of(&body)["status"], "ok");
    assert!(
        headers[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'")
    );
    assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert!(headers.contains_key(header::STRICT_TRANSPORT_SECURITY));

    let (status, _, body) = call(&h.app, "GET", "/readyz", None, None).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));

    let (status, headers, body) = call(&h.app, "GET", "/pki/root.crt", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        String::from_utf8(body)
            .unwrap()
            .starts_with("-----BEGIN CERTIFICATE-----")
    );
    assert!(
        headers[header::CONTENT_DISPOSITION]
            .to_str()
            .unwrap()
            .contains("attachment")
    );

    let (status, headers, body) = call(&h.app, "GET", "/pki/crl.der", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], "application/pkix-crl");
    assert_eq!(body[0], 0x30);

    let (status, _, body) = call(&h.app, "GET", "/api/v1/ca", None, None).await;
    assert_eq!(status, StatusCode::OK);
    let info = json_of(&body);
    assert_eq!(info["allowed_dns_suffixes"][0], "dmz.zenv.internal");
    assert!(info["root_sha256"].as_str().unwrap().contains(':'));

    let (status, headers, body) = call(&h.app, "GET", "/", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        headers[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/html")
    );
    assert!(String::from_utf8(body).unwrap().contains("Zenv DMZ"));

    let (status, headers, _) = call(&h.app, "GET", "/nope", None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(headers[header::CONTENT_TYPE], "application/problem+json");
}

#[tokio::test]
async fn authentication_is_required() {
    let h = harness();
    let (status, headers, _) = call(&h.app, "GET", "/api/v1/certificates", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(headers.contains_key(header::WWW_AUTHENTICATE));
    let (status, _, _) = call(&h.app, "GET", "/api/v1/me", Some("zca_forged"), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _, body) = call(&h.app, "GET", "/api/v1/me", Some(&h.alice), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json_of(&body)["name"], "alice");
    let (status, _, _) = call(&h.app, "GET", "/api/v1/audit", Some(&h.alice), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn csr_issue_download_verify_revoke() {
    let h = harness();
    let csr = make_csr(&["shop.dmz.zenv.internal"]);
    let (status, headers, body) = call(
        &h.app,
        "POST",
        "/api/v1/certificates",
        Some(&h.alice),
        Some(json!({ "csr_pem": csr, "profile": "server", "validity_days": 10 })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&body));
    let cert = json_of(&body);
    let serial = cert["serial"].as_str().unwrap().to_string();
    assert_eq!(
        headers[header::LOCATION],
        format!("/api/v1/certificates/{serial}").as_str()
    );
    assert_eq!(cert["requested_by"], "alice");
    assert_eq!(cert["status"], "active");
    assert_eq!(cert["issuance_method"], "csr");

    // Ownership: bob cannot see alice's certificate (404, not 403), admin can.
    let (status, _, _) = call(
        &h.app,
        "GET",
        &format!("/api/v1/certificates/{serial}"),
        Some(&h.bob),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) = call(
        &h.app,
        "GET",
        &format!("/api/v1/certificates/{serial}"),
        Some(&h.admin),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, _, body) = call(&h.app, "GET", "/api/v1/certificates", Some(&h.bob), None).await;
    assert_eq!(json_of(&body).as_array().unwrap().len(), 0);

    // Downloads.
    let (status, headers, body) = call(
        &h.app,
        "GET",
        &format!("/api/v1/certificates/{serial}/download?format=chain"),
        Some(&h.alice),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        headers[header::CONTENT_DISPOSITION]
            .to_str()
            .unwrap()
            .contains(".chain.pem")
    );
    let chain = String::from_utf8(body).unwrap();
    assert_eq!(chain.matches("BEGIN CERTIFICATE").count(), 2);
    let (_, headers, _) = call(
        &h.app,
        "GET",
        &format!("/api/v1/certificates/{serial}/download?format=der"),
        Some(&h.alice),
        None,
    )
    .await;
    assert_eq!(headers[header::CONTENT_TYPE], "application/pkix-cert");

    // Public verification.
    let (status, _, body) = call(
        &h.app,
        "POST",
        "/api/v1/verify",
        None,
        Some(json!({ "certificate_pem": chain, "hostname": "shop.dmz.zenv.internal" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let report = json_of(&body);
    assert_eq!(report["valid"], true, "{report:#}");

    // Bob cannot revoke it; alice can; revocation is idempotent.
    let revoke = format!("/api/v1/certificates/{serial}/revoke");
    let (status, _, _) = call(
        &h.app,
        "POST",
        &revoke,
        Some(&h.bob),
        Some(json!({ "reason": "key-compromise" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, body) = call(
        &h.app,
        "POST",
        &revoke,
        Some(&h.alice),
        Some(json!({ "reason": "key-compromise" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json_of(&body)["status"], "revoked");
    let (status, _, _) = call(&h.app, "POST", &revoke, Some(&h.alice), None).await;
    assert_eq!(status, StatusCode::OK);

    // The status endpoint, the CRL and verification all reflect the revocation.
    let (_, _, body) = call(
        &h.app,
        "GET",
        &format!("/api/v1/certificates/{serial}/status"),
        None,
        None,
    )
    .await;
    let st = json_of(&body);
    assert_eq!(st["status"], "revoked");
    assert_eq!(st["reason"], "key-compromise");
    let (_, _, crl) = call(&h.app, "GET", "/pki/crl.der", None, None).await;
    let (_, parsed) = <x509_parser::revocation_list::CertificateRevocationList as x509_parser::prelude::FromDer<_>>::from_der(&crl).unwrap();
    assert!(
        parsed
            .iter_revoked_certificates()
            .any(|r| hex::encode(r.raw_serial()) == serial)
    );
    let (_, _, body) = call(
        &h.app,
        "POST",
        "/api/v1/verify",
        None,
        Some(json!({ "certificate_pem": chain })),
    )
    .await;
    assert_eq!(json_of(&body)["valid"], false);

    // The audit trail recorded everything and is intact.
    let (_, _, body) = call(&h.app, "GET", "/api/v1/audit/verify", Some(&h.admin), None).await;
    assert_eq!(json_of(&body)["intact"], true);
    let (_, _, body) = call(&h.app, "GET", "/api/v1/audit", Some(&h.admin), None).await;
    let actions: Vec<String> = json_of(&body)
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap().to_owned())
        .collect();
    assert!(actions.contains(&"certificate.issued".to_string()));
    assert!(actions.contains(&"certificate.revoked".to_string()));
}

#[tokio::test]
async fn keygen_and_policy_errors() {
    let h = harness();
    let (status, headers, body) = call(
        &h.app,
        "POST",
        "/api/v1/certificates/keygen",
        Some(&h.alice),
        Some(json!({ "dns_names": ["api.dmz.zenv.internal"], "key_algorithm": "ecdsa-p256", "pkcs12_password": "s3cret-pass" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&body));
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    let res = json_of(&body);
    assert!(res["private_key_pem"].as_str().unwrap().contains("PRIVATE KEY"));
    use base64::Engine;
    let p12 = base64::engine::general_purpose::STANDARD
        .decode(res["pkcs12_base64"].as_str().unwrap())
        .unwrap();
    assert!(!p12.is_empty());
    assert_eq!(res["certificate"]["issuance_method"], "keygen");

    // Policy violation → 403 problem+json, and nothing recorded.
    let (status, headers, body) = call(
        &h.app,
        "POST",
        "/api/v1/certificates/keygen",
        Some(&h.alice),
        Some(json!({ "dns_names": ["www.example.com"], "pkcs12_password": "s3cret-pass" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(headers[header::CONTENT_TYPE], "application/problem+json");
    assert_eq!(json_of(&body)["title"], "policy-violation");

    // Weak PKCS#12 password → 422 and no orphaned certificate.
    let (status, _, _) = call(
        &h.app,
        "POST",
        "/api/v1/certificates/keygen",
        Some(&h.alice),
        Some(json!({ "dns_names": ["x.dmz.zenv.internal"], "pkcs12_password": "short" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let (_, _, body) = call(&h.app, "GET", "/api/v1/certificates", Some(&h.alice), None).await;
    assert_eq!(json_of(&body).as_array().unwrap().len(), 1);

    // Garbage CSR → 422; unknown JSON fields → 4xx.
    let (status, _, _) = call(
        &h.app,
        "POST",
        "/api/v1/certificates",
        Some(&h.alice),
        Some(json!({ "csr_pem": "junk" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let (status, _, _) = call(
        &h.app,
        "POST",
        "/api/v1/certificates",
        Some(&h.alice),
        Some(json!({ "csr_pem": "x", "is_ca": true })),
    )
    .await;
    assert!(status.is_client_error());
}

#[tokio::test]
async fn oversized_bodies_are_rejected() {
    let h = harness();
    let big = "A".repeat(200 * 1024);
    let (status, _, _) = call(
        &h.app,
        "POST",
        "/api/v1/verify",
        None,
        Some(json!({ "certificate_pem": big })),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}
