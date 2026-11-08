//! Backend conformance suite (feature `testkit`).
//!
//! Every backend runs the same behavioural tests, so swapping SQLite for PostgreSQL (or
//! adding a new backend) cannot silently change semantics. In a backend crate:
//!
//! ```ignore
//! // tests/conformance.rs
//! fn make() -> Option<Box<dyn zenv_ca_store::CaStore>> {
//!     Some(Box::new(MyStore::open_fresh().unwrap()))   // or None to skip
//! }
//! zenv_ca_store::conformance_tests!(make);
//! ```
//!
//! Each case gets a **fresh, empty** store. [`concurrent_writers_keep_chain_intact`]
//! needs two handles on the *same* database and is called separately.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

use std::sync::Arc;

use time::{Duration, OffsetDateTime};
use zenv_ca_core::{CertProfile, IssuedCertificate, RevocationLookup, RevocationReason, RevocationStatus};

use crate::{CaStore, CertFilter, CertStatus, IssuanceMethod, Revocations, RevokeOutcome, Role, StoreError};

/// Generates one `#[test]` per conformance case. `$make` evaluates to something callable
/// as `fn() -> Option<Box<dyn CaStore>>`; returning `None` skips the case (e.g. no
/// PostgreSQL URL configured).
#[macro_export]
macro_rules! conformance_tests {
    ($make:expr) => {
        $crate::conformance_tests!(@cases $make;
            tokens_authenticate_and_disable,
            duplicate_token_names_conflict,
            inventory_filters_and_pagination,
            revocation_and_crl_entries,
            duplicate_serials_conflict_without_audit,
            audit_chain_covers_every_change,
            crl_numbers_are_monotonic,
            revocation_lookup_fails_closed,
            search_treats_wildcards_literally
        );
    };
    (@cases $make:expr; $($case:ident),* $(,)?) => {
        $(
            #[test]
            fn $case() {
                let make = $make;
                let Some(store) = make() else {
                    eprintln!("skipped {}: backend not available", stringify!($case));
                    return;
                };
                $crate::testkit::$case(&*store);
            }
        )*
    };
}

/// A syntactically plausible issued certificate (the store does not parse PEM).
pub fn sample_cert(serial: &str, cn: &str, days: i64) -> IssuedCertificate {
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

fn serials(records: &[crate::CertificateRecord]) -> Vec<&str> {
    records.iter().map(|c| c.serial.as_str()).collect()
}

pub fn tokens_authenticate_and_disable(store: &dyn CaStore) {
    assert!(!store.has_admin().unwrap());
    let (info, secret) = store.create_token("alice", Role::Requester, "cli:test").unwrap();
    assert!(secret.starts_with("zca_"));
    assert!(secret.starts_with(&info.prefix));
    assert!(!store.has_admin().unwrap());

    let p = store.authenticate(&secret).unwrap().expect("valid token");
    assert_eq!(
        (p.name.as_str(), p.role, p.token_id),
        ("alice", Role::Requester, info.id)
    );
    assert!(store.authenticate("zca_wrong").unwrap().is_none());
    assert!(store.authenticate("Bearer junk").unwrap().is_none());
    assert!(store.authenticate(&"zca_x".repeat(100)).unwrap().is_none());

    let listed = store.list_tokens().unwrap();
    assert_eq!(listed.len(), 1);
    assert!(listed[0].last_used_at.is_some(), "authenticate records last use");

    assert!(store.disable_token("alice", "cli:test").unwrap());
    assert!(store.authenticate(&secret).unwrap().is_none());
    assert!(
        !store.disable_token("alice", "cli:test").unwrap(),
        "already disabled"
    );
    assert!(store.list_tokens().unwrap()[0].disabled_at.is_some());

    store.create_token("ops", Role::Admin, "cli:test").unwrap();
    assert!(store.has_admin().unwrap());
}

pub fn duplicate_token_names_conflict(store: &dyn CaStore) {
    store.create_token("alice", Role::Requester, "t").unwrap();
    let err = store.create_token("alice", Role::Admin, "t").unwrap_err();
    assert!(matches!(err, StoreError::Conflict(_)), "{err:?}");
    let tokens = store.audit_log(10).unwrap();
    assert_eq!(tokens.iter().filter(|e| e.action == "token.created").count(), 1);
}

pub fn inventory_filters_and_pagination(store: &dyn CaStore) {
    store
        .insert_certificate(
            &sample_cert("aa01", "a.dmz.zenv.internal", 30),
            IssuanceMethod::Csr,
            "alice",
        )
        .unwrap();
    store
        .insert_certificate(
            &sample_cert("aa02", "b.dmz.zenv.internal", 30),
            IssuanceMethod::Keygen,
            "bob",
        )
        .unwrap();
    store
        .insert_certificate(
            &sample_cert("aa03", "old.dmz.zenv.internal", -2),
            IssuanceMethod::Csr,
            "alice",
        )
        .unwrap();

    let one = store.get_certificate("aa02").unwrap().unwrap();
    assert_eq!(one.issuance_method, IssuanceMethod::Keygen);
    assert_eq!(one.requested_by, "bob");
    assert_eq!(one.dns_names, vec!["b.dmz.zenv.internal".to_string()]);
    assert_eq!(one.status, CertStatus::Active);
    assert!(store.get_certificate("ffff").unwrap().is_none());

    assert_eq!(store.list_certificates(&CertFilter::default()).unwrap().len(), 3);
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
    assert_eq!(serials(&expired), vec!["aa03"]);
    let active = store
        .list_certificates(&CertFilter {
            status: Some(CertStatus::Active),
            ..CertFilter::default()
        })
        .unwrap();
    assert_eq!(active.len(), 2);
    let searched = store
        .list_certificates(&CertFilter {
            search: Some("B.DMZ".into()),
            ..CertFilter::default()
        })
        .unwrap();
    assert_eq!(serials(&searched), vec!["aa02"]);

    let page1 = store
        .list_certificates(&CertFilter {
            limit: 2,
            ..CertFilter::default()
        })
        .unwrap();
    let page2 = store
        .list_certificates(&CertFilter {
            limit: 2,
            offset: 2,
            ..CertFilter::default()
        })
        .unwrap();
    assert_eq!(page1.len(), 2);
    assert_eq!(page2.len(), 1);
    assert!(!serials(&page1).contains(&page2[0].serial.as_str()));

    let soon = store.expiring_within(31).unwrap();
    assert_eq!(serials(&soon), vec!["aa01", "aa02"]);
    assert!(store.expiring_within(1).unwrap().is_empty());
}

pub fn revocation_and_crl_entries(store: &dyn CaStore) {
    store
        .insert_certificate(
            &sample_cert("aa01", "a.dmz.zenv.internal", 30),
            IssuanceMethod::Csr,
            "alice",
        )
        .unwrap();
    store
        .insert_certificate(
            &sample_cert("aa03", "old.dmz.zenv.internal", -2),
            IssuanceMethod::Csr,
            "alice",
        )
        .unwrap();
    assert_eq!(store.revocation_revision().unwrap(), (0, 0));

    match store
        .revoke("aa01", RevocationReason::KeyCompromise, "admin")
        .unwrap()
    {
        RevokeOutcome::Revoked(r) => {
            assert_eq!(r.status, CertStatus::Revoked);
            assert_eq!(r.revocation_reason, Some(RevocationReason::KeyCompromise));
            assert_eq!(r.revoked_by.as_deref(), Some("admin"));
        }
        other => panic!("{other:?}"),
    }
    let rev1 = store.revocation_revision().unwrap();
    assert_eq!(rev1.0, 1);
    assert!(matches!(
        store.revoke("aa01", RevocationReason::Superseded, "admin").unwrap(),
        RevokeOutcome::AlreadyRevoked(r) if r.revocation_reason == Some(RevocationReason::KeyCompromise)
    ));
    assert!(matches!(
        store
            .revoke("nope", RevocationReason::Unspecified, "admin")
            .unwrap(),
        RevokeOutcome::NotFound
    ));
    assert_eq!(
        store.revocation_revision().unwrap(),
        rev1,
        "idempotent revoke changes nothing"
    );
    assert!(matches!(
        store.revocation_status("aa01").unwrap(),
        RevocationStatus::Revoked {
            reason: RevocationReason::KeyCompromise,
            ..
        }
    ));

    // Revoking an already-expired certificate must not put it on the CRL.
    store
        .revoke("aa03", RevocationReason::Superseded, "admin")
        .unwrap();
    assert_eq!(store.revocation_revision().unwrap().0, 2);
    let entries = store.crl_entries().unwrap();
    assert_eq!(
        entries.iter().map(|e| e.serial.as_str()).collect::<Vec<_>>(),
        vec!["aa01"]
    );
    assert_eq!(entries[0].reason, RevocationReason::KeyCompromise);
}

pub fn duplicate_serials_conflict_without_audit(store: &dyn CaStore) {
    store
        .insert_certificate(
            &sample_cert("aa01", "a.dmz.zenv.internal", 30),
            IssuanceMethod::Csr,
            "alice",
        )
        .unwrap();
    let mut dup = sample_cert("aa01", "b.dmz.zenv.internal", 30);
    dup.fingerprint_sha256 = "different".into();
    let err = store
        .insert_certificate(&dup, IssuanceMethod::Csr, "alice")
        .unwrap_err();
    assert!(matches!(err, StoreError::Conflict(_)), "{err:?}");
    // Same fingerprint, different serial: also a conflict.
    let mut same_fp = sample_cert("aa02", "c.dmz.zenv.internal", 30);
    same_fp.fingerprint_sha256 = "fp-aa01".into();
    assert!(matches!(
        store.insert_certificate(&same_fp, IssuanceMethod::Csr, "alice"),
        Err(StoreError::Conflict(_))
    ));
    // The failed inserts must not leave orphan audit entries, and the chain stays intact.
    let log = store.audit_log(10).unwrap();
    assert_eq!(log.iter().filter(|e| e.action == "certificate.issued").count(), 1);
    assert!(store.verify_audit_chain().unwrap().intact);
}

pub fn audit_chain_covers_every_change(store: &dyn CaStore) {
    let empty = store.verify_audit_chain().unwrap();
    assert!(empty.intact);
    assert_eq!(empty.entries, 0);
    assert_eq!(empty.head_hash, crate::audit::GENESIS_HASH);

    store.create_token("ops", Role::Admin, "cli:root").unwrap();
    store
        .insert_certificate(
            &sample_cert("aa01", "a.dmz.zenv.internal", 30),
            IssuanceMethod::Csr,
            "ops",
        )
        .unwrap();
    store.revoke("aa01", RevocationReason::Superseded, "ops").unwrap();
    store.next_crl_number("system", 1).unwrap();
    store.disable_token("ops", "cli:root").unwrap();
    store
        .audit(
            "ops",
            "login.failed",
            "10.0.0.1",
            &serde_json::json!({"why": "bad token"}),
        )
        .unwrap();

    let log = store.audit_log(100).unwrap();
    assert_eq!(
        log.iter().map(|e| e.action.as_str()).collect::<Vec<_>>(),
        vec![
            "login.failed",
            "token.disabled",
            "crl.generated",
            "certificate.revoked",
            "certificate.issued",
            "token.created",
        ],
        "newest first"
    );
    assert_eq!(log[0].details["why"], "bad token");
    assert_eq!(log[4].details["fingerprint_sha256"], "fp-aa01");
    assert_eq!(store.audit_log(2).unwrap().len(), 2);

    let v = store.verify_audit_chain().unwrap();
    assert!(v.intact, "{v:?}");
    assert_eq!(v.entries, 6);
    assert_eq!(v.head_hash, log[0].hash);
    for pair in log.windows(2) {
        assert_eq!(pair[0].prev_hash, pair[1].hash);
        assert_eq!(pair[0].id, pair[1].id + 1);
    }
}

pub fn crl_numbers_are_monotonic(store: &dyn CaStore) {
    assert_eq!(store.next_crl_number("system", 0).unwrap(), 1);
    assert_eq!(store.next_crl_number("system", 3).unwrap(), 2);
    assert_eq!(store.next_crl_number("system", 0).unwrap(), 3);
}

pub fn revocation_lookup_fails_closed(store: &dyn CaStore) {
    let lookup = Revocations(store);
    assert_eq!(lookup.status("aa01"), RevocationStatus::Unknown);
    store
        .insert_certificate(
            &sample_cert("aa01", "a.dmz.zenv.internal", 30),
            IssuanceMethod::Csr,
            "alice",
        )
        .unwrap();
    assert_eq!(lookup.status("aa01"), RevocationStatus::Good);
}

pub fn search_treats_wildcards_literally(store: &dyn CaStore) {
    store
        .insert_certificate(
            &sample_cert("aa01", "a.dmz.zenv.internal", 30),
            IssuanceMethod::Csr,
            "alice",
        )
        .unwrap();
    for pattern in ["%", "_", "a_dmz"] {
        let found = store
            .list_certificates(&CertFilter {
                search: Some(pattern.into()),
                ..CertFilter::default()
            })
            .unwrap();
        assert!(found.is_empty(), "'{pattern}' must not act as a wildcard");
    }
}

/// Two handles on the **same** database (two daemon instances, or daemon + CLI) write
/// concurrently; every write must land and the audit chain must stay one unbroken line.
pub fn concurrent_writers_keep_chain_intact(a: Arc<dyn CaStore>, b: Arc<dyn CaStore>) {
    const PER_THREAD: usize = 15;
    let handles: Vec<_> = [a.clone(), b.clone(), a, b]
        .into_iter()
        .enumerate()
        .map(|(t, store)| {
            std::thread::spawn(move || {
                for i in 0..PER_THREAD {
                    let serial = format!("{t:02x}{i:04x}");
                    store
                        .insert_certificate(
                            &sample_cert(&serial, &format!("h{t}-{i}.dmz.zenv.internal"), 30),
                            IssuanceMethod::Csr,
                            "load",
                        )
                        .unwrap();
                    if i % 3 == 0 {
                        store
                            .revoke(&serial, RevocationReason::Superseded, "load")
                            .unwrap();
                        store.next_crl_number("system", 1).unwrap();
                    }
                }
                store
            })
        })
        .collect();
    let stores: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let store = &stores[0];
    let total = 4 * PER_THREAD;
    let revoked = 4 * PER_THREAD.div_ceil(3);
    assert_eq!(
        store
            .list_certificates(&CertFilter {
                limit: 500,
                ..CertFilter::default()
            })
            .unwrap()
            .len(),
        total
    );
    let v = store.verify_audit_chain().unwrap();
    assert!(v.intact, "{v:?}");
    assert_eq!(v.entries, u64::try_from(total + 2 * revoked).unwrap());
    assert_eq!(
        store.next_crl_number("system", 0).unwrap(),
        u64::try_from(revoked + 1).unwrap()
    );
}
