#![allow(clippy::unwrap_used, clippy::expect_used)]

use time::{Duration, OffsetDateTime};
use zenv_ca_core::{CertProfile, IssuedCertificate, RevocationLookup, RevocationReason, RevocationStatus};
use zenv_ca_store::*;

fn cert(serial: &str, cn: &str, days: i64) -> IssuedCertificate {
    let now = OffsetDateTime::now_utc().replace_nanosecond(0).unwrap();
    IssuedCertificate {
        serial: serial.into(),
        common_name: cn.into(),
        dns_names: vec![cn.into()],
        ip_addresses: vec![],
        profile: CertProfile::Server,
        not_before: now - Duration::days(1),
        not_after: now + Duration::days(days),
        key_algorithm: "ecdsa-p256".into(),
        fingerprint_sha256: format!("fp-{serial}"),
        cert_pem: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n".into(),
    }
}

#[test]
fn tokens_authenticate_and_disable() {
    let store = Store::open_in_memory().unwrap();
    let (info, secret) = store.create_token("alice", Role::Requester, "cli:test").unwrap();
    assert!(secret.starts_with("zca_"));
    assert!(secret.starts_with(&info.prefix));

    let p = store.authenticate(&secret).unwrap().expect("valid token");
    assert_eq!(p.name, "alice");
    assert!(!p.is_admin());
    assert!(store.authenticate("zca_wrong").unwrap().is_none());
    assert!(store.authenticate("Bearer junk").unwrap().is_none());

    assert!(store.disable_token("alice", "cli:test").unwrap());
    assert!(store.authenticate(&secret).unwrap().is_none());
    assert!(
        !store.disable_token("alice", "cli:test").unwrap(),
        "already disabled"
    );
    assert!(
        store.create_token("alice", Role::Admin, "cli:test").is_err(),
        "names are unique"
    );
}

#[test]
fn inventory_revocation_and_crl_entries() {
    let store = Store::open_in_memory().unwrap();
    store
        .insert_certificate(
            &cert("aa01", "a.dmz.zenv.internal", 30),
            IssuanceMethod::Csr,
            "alice",
        )
        .unwrap();
    store
        .insert_certificate(
            &cert("aa02", "b.dmz.zenv.internal", 30),
            IssuanceMethod::Keygen,
            "bob",
        )
        .unwrap();
    store
        .insert_certificate(
            &cert("aa03", "old.dmz.zenv.internal", -2),
            IssuanceMethod::Csr,
            "alice",
        )
        .unwrap();

    let all = store.list_certificates(&CertFilter::default()).unwrap();
    assert_eq!(all.len(), 3);
    let alices = store
        .list_certificates(&CertFilter {
            requested_by: Some("alice".into()),
            ..CertFilter::default()
        })
        .unwrap();
    assert_eq!(alices.len(), 2);
    let expired = store
        .list_certificates(&CertFilter {
            status: Some(CertStatus::Expired),
            ..CertFilter::default()
        })
        .unwrap();
    assert_eq!(
        expired.iter().map(|c| c.serial.as_str()).collect::<Vec<_>>(),
        vec!["aa03"]
    );
    let searched = store
        .list_certificates(&CertFilter {
            search: Some("B.DMZ".into()),
            ..CertFilter::default()
        })
        .unwrap();
    assert_eq!(searched.len(), 1);

    assert_eq!(store.status("aa01"), RevocationStatus::Good);
    assert_eq!(store.status("ffff"), RevocationStatus::Unknown);

    match store
        .revoke("aa01", RevocationReason::KeyCompromise, "admin")
        .unwrap()
    {
        RevokeOutcome::Revoked(r) => assert_eq!(r.status, CertStatus::Revoked),
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        store
            .revoke("aa01", RevocationReason::Superseded, "admin")
            .unwrap(),
        RevokeOutcome::AlreadyRevoked(_)
    ));
    assert!(matches!(
        store
            .revoke("nope", RevocationReason::Unspecified, "admin")
            .unwrap(),
        RevokeOutcome::NotFound
    ));
    assert!(matches!(
        store.status("aa01"),
        RevocationStatus::Revoked {
            reason: RevocationReason::KeyCompromise,
            ..
        }
    ));

    // Revoking an already-expired cert must not put it on the CRL.
    store
        .revoke("aa03", RevocationReason::Superseded, "admin")
        .unwrap();
    let entries = store.crl_entries().unwrap();
    assert_eq!(
        entries.iter().map(|e| e.serial.as_str()).collect::<Vec<_>>(),
        vec!["aa01"]
    );

    assert_eq!(store.next_crl_number("system", 1).unwrap(), 1);
    assert_eq!(store.next_crl_number("system", 1).unwrap(), 2);

    let soon = store.expiring_within(31).unwrap();
    assert_eq!(
        soon.iter().map(|c| c.serial.as_str()).collect::<Vec<_>>(),
        vec!["aa02"]
    );
}

#[test]
fn duplicate_serials_are_rejected() {
    let store = Store::open_in_memory().unwrap();
    store
        .insert_certificate(
            &cert("aa01", "a.dmz.zenv.internal", 30),
            IssuanceMethod::Csr,
            "alice",
        )
        .unwrap();
    let mut dup = cert("aa01", "b.dmz.zenv.internal", 30);
    dup.fingerprint_sha256 = "different".into();
    assert!(
        store
            .insert_certificate(&dup, IssuanceMethod::Csr, "alice")
            .is_err()
    );
    // The failed insert must not leave an orphan audit entry behind.
    let log = store.audit_log(10).unwrap();
    assert_eq!(log.iter().filter(|e| e.action == "certificate.issued").count(), 1);
}

#[test]
fn audit_chain_is_tamper_evident() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ca.db");
    {
        let store = Store::open(&path).unwrap();
        store.create_token("ops", Role::Admin, "cli:root").unwrap();
        store
            .insert_certificate(
                &cert("aa01", "a.dmz.zenv.internal", 30),
                IssuanceMethod::Csr,
                "ops",
            )
            .unwrap();
        store.revoke("aa01", RevocationReason::Superseded, "ops").unwrap();
        let v = store.verify_audit_chain().unwrap();
        assert!(v.intact);
        assert_eq!(v.entries, 3);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    // The append-only triggers block naive tampering...
    let raw = rusqlite::Connection::open(&path).unwrap();
    assert!(
        raw.execute("UPDATE audit_log SET actor = 'mallory' WHERE id = 2", [])
            .is_err()
    );
    assert!(raw.execute("DELETE FROM audit_log WHERE id = 2", []).is_err());
    // ...and if an attacker drops the triggers, the hash chain still exposes the edit.
    raw.execute_batch(
        "DROP TRIGGER audit_log_no_update; UPDATE audit_log SET actor = 'mallory' WHERE id = 2;",
    )
    .unwrap();
    drop(raw);

    let store = Store::open(&path).unwrap();
    let v = store.verify_audit_chain().unwrap();
    assert!(!v.intact);
    assert_eq!(v.first_broken_id, Some(2));
}

#[test]
fn reopening_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ca.db");
    Store::open(&path)
        .unwrap()
        .create_token("x", Role::Admin, "t")
        .unwrap();
    let store = Store::open(&path).unwrap();
    assert!(store.has_admin().unwrap());
}
