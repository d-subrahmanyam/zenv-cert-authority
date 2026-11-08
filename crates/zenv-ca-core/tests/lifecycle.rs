//! End-to-end lifecycle tests for the core crate: bootstrap → issue → verify → revoke → CRL.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;

use rcgen::{CertificateParams, DnType, KeyPair};
use x509_parser::prelude::FromDer;
use x509_parser::revocation_list::CertificateRevocationList;
use zenv_ca_core::export::{pkcs12_bundle, render_certificate};
use zenv_ca_core::hierarchy::{create_intermediate, create_root, pem_to_der};
use zenv_ca_core::keys::{decrypt_private_key, encrypt_private_key};
use zenv_ca_core::*;

struct MapLookup(HashMap<String, RevocationStatus>);

impl RevocationLookup for MapLookup {
    fn status(&self, serial: &str) -> RevocationStatus {
        self.0.get(serial).cloned().unwrap_or(RevocationStatus::Unknown)
    }
}

fn subject(cn: &str) -> CaSubject {
    CaSubject {
        common_name: cn.into(),
        organization: "Zenv Test".into(),
        organizational_unit: "DMZ Non-Production".into(),
    }
}

fn bootstrap(policy: IssuancePolicy) -> CertificateAuthority {
    let root = create_root(&CaSpec {
        subject: subject("Test Root"),
        validity_days: 3650,
        key_algorithm: KeyAlgorithm::EcdsaP384,
    })
    .unwrap();
    let inter = create_intermediate(
        &root.cert_pem,
        &root.key,
        &CaSpec {
            subject: subject("Test Intermediate"),
            validity_days: 1095,
            key_algorithm: KeyAlgorithm::EcdsaP256,
        },
        &policy,
    )
    .unwrap();
    // Exercise the encrypted-at-rest round trip the daemon performs on start-up.
    let enc = encrypt_private_key(&inter.key, b"a very long passphrase").unwrap();
    let key = decrypt_private_key(&enc, b"a very long passphrase").unwrap();
    CertificateAuthority::load(
        &root.cert_pem,
        &inter.cert_pem,
        key,
        policy,
        Some("https://ca.dmz.zenv.internal/pki/crl.der".into()),
    )
    .unwrap()
}

fn csr(names: &[&str], cn: Option<&str>) -> (String, KeyPair) {
    let key = KeyPair::generate().unwrap();
    let mut params =
        CertificateParams::new(names.iter().map(|s| (*s).to_string()).collect::<Vec<_>>()).unwrap();
    if let Some(cn) = cn {
        params.distinguished_name.push(DnType::CommonName, cn);
    }
    (params.serialize_request(&key).unwrap().pem().unwrap(), key)
}

fn good(serial: &str) -> MapLookup {
    MapLookup(HashMap::from([(serial.to_string(), RevocationStatus::Good)]))
}

#[test]
fn csr_issuance_and_verification() {
    let ca = bootstrap(IssuancePolicy::default());
    let (csr_pem, _) = csr(&["app.dmz.zenv.internal"], Some("app.dmz.zenv.internal"));
    let issued = ca
        .issue_from_csr(&CsrRequest {
            csr_pem,
            profile: CertProfile::Server,
            validity_days: Some(14),
        })
        .unwrap();

    assert_eq!(issued.serial.len(), 32);
    assert_eq!(issued.dns_names, vec!["app.dmz.zenv.internal"]);
    assert_eq!((issued.not_after - issued.not_before).whole_days(), 14);

    let report = ca.verify(
        issued.cert_pem.as_bytes(),
        &VerifyOptions {
            hostname: Some("app.dmz.zenv.internal".into()),
            at: None,
        },
        &good(&issued.serial),
    );
    assert!(report.valid, "{report:#?}");
    assert_eq!(report.serial.as_deref(), Some(issued.serial.as_str()));

    let wrong_host = ca.verify(
        issued.cert_pem.as_bytes(),
        &VerifyOptions {
            hostname: Some("other.dmz.zenv.internal".into()),
            at: None,
        },
        &good(&issued.serial),
    );
    assert!(!wrong_host.valid);
}

#[test]
fn csr_cannot_escape_policy() {
    let ca = bootstrap(IssuancePolicy::default());
    for names in [
        vec!["www.google.com"],
        vec!["ok.dmz.zenv.internal", "evil.example"],
    ] {
        let (csr_pem, _) = csr(&names, None);
        let err = ca
            .issue_from_csr(&CsrRequest {
                csr_pem,
                profile: CertProfile::Server,
                validity_days: None,
            })
            .unwrap_err();
        assert!(matches!(err, CaError::Policy(_)), "{err}");
    }
    let (csr_pem, _) = csr(&["ok.dmz.zenv.internal"], None);
    let too_long = ca.issue_from_csr(&CsrRequest {
        csr_pem,
        profile: CertProfile::Server,
        validity_days: Some(365),
    });
    assert!(matches!(too_long, Err(CaError::Policy(_))));
}

#[test]
fn cn_only_legacy_csr_gets_san() {
    let ca = bootstrap(IssuancePolicy::default());
    let (csr_pem, _) = csr(&[], Some("legacy.dmz.zenv.internal"));
    let issued = ca
        .issue_from_csr(&CsrRequest {
            csr_pem,
            profile: CertProfile::Client,
            validity_days: None,
        })
        .unwrap();
    assert_eq!(issued.dns_names, vec!["legacy.dmz.zenv.internal"]);
}

#[test]
fn tampered_csr_is_rejected() {
    let ca = bootstrap(IssuancePolicy::default());
    let (csr_pem, _) = csr(&["app.dmz.zenv.internal"], None);
    let mut der = pem_to_der(&csr_pem, "CERTIFICATE REQUEST").unwrap();
    let last = der.len() - 1;
    der[last] ^= 0xff; // corrupt the signature
    let tampered = pem::encode(&pem::Pem::new("CERTIFICATE REQUEST", der));
    let err = ca
        .issue_from_csr(&CsrRequest {
            csr_pem: tampered,
            profile: CertProfile::Server,
            validity_days: None,
        })
        .unwrap_err();
    assert!(matches!(err, CaError::InvalidCsr(_)), "{err}");
}

#[test]
fn foreign_and_revoked_certificates_fail_verification() {
    let ca = bootstrap(IssuancePolicy::default());
    let other_ca = bootstrap(IssuancePolicy::default());
    let (csr_pem, _) = csr(&["app.dmz.zenv.internal"], None);
    let foreign = other_ca
        .issue_from_csr(&CsrRequest {
            csr_pem: csr_pem.clone(),
            profile: CertProfile::Server,
            validity_days: None,
        })
        .unwrap();
    let report = ca.verify(
        foreign.cert_pem.as_bytes(),
        &VerifyOptions::default(),
        &good(&foreign.serial),
    );
    assert!(!report.valid);
    assert!(report.checks.iter().any(|c| c.name == "signature" && !c.passed));

    let ours = ca
        .issue_from_csr(&CsrRequest {
            csr_pem,
            profile: CertProfile::Server,
            validity_days: None,
        })
        .unwrap();
    let revoked = MapLookup(HashMap::from([(
        ours.serial.clone(),
        RevocationStatus::Revoked {
            revoked_at: 0,
            reason: RevocationReason::KeyCompromise,
        },
    )]));
    let report = ca.verify(ours.cert_pem.as_bytes(), &VerifyOptions::default(), &revoked);
    assert!(!report.valid);
    let unknown = ca.verify(
        ours.cert_pem.as_bytes(),
        &VerifyOptions::default(),
        &NoRevocationInfo,
    );
    assert!(
        !unknown.valid,
        "serials missing from the inventory must not verify"
    );

    let garbage = ca.verify(b"not a cert", &VerifyOptions::default(), &NoRevocationInfo);
    assert!(!garbage.valid);
}

#[test]
fn expiry_is_enforced() {
    let ca = bootstrap(IssuancePolicy::default());
    let (csr_pem, _) = csr(&["app.dmz.zenv.internal"], None);
    let issued = ca
        .issue_from_csr(&CsrRequest {
            csr_pem,
            profile: CertProfile::Server,
            validity_days: Some(1),
        })
        .unwrap();
    let later = VerifyOptions {
        hostname: None,
        at: Some(issued.not_after + time::Duration::hours(1)),
    };
    let report = ca.verify(issued.cert_pem.as_bytes(), &later, &good(&issued.serial));
    assert!(!report.valid);
    assert!(report.checks.iter().any(|c| c.name == "validity" && !c.passed));
}

#[test]
fn keygen_issuance_and_pkcs12_round_trip() {
    let ca = bootstrap(IssuancePolicy::default());
    for alg in [
        KeyAlgorithm::EcdsaP256,
        KeyAlgorithm::Rsa2048,
        KeyAlgorithm::Ed25519,
    ] {
        let (issued, key) = ca
            .issue_with_generated_key(&KeygenRequest {
                common_name: None,
                dns_names: vec!["svc.dmz.zenv.internal".into()],
                ip_addresses: vec![],
                profile: CertProfile::ServerClient,
                validity_days: None,
                key_algorithm: alg,
            })
            .unwrap();
        assert_eq!(issued.common_name, "svc.dmz.zenv.internal");

        let p12 = pkcs12_bundle(&issued.cert_pem, &key, &ca, "svc", "changeit-please").unwrap();
        let store = p12_keystore::KeyStore::from_pkcs12(
            &p12,
            "changeit-please",
            p12_keystore::Pkcs12ImportPolicy::default(),
        )
        .unwrap();
        let (_, chain) = store.private_key_chain().expect("key entry");
        assert_eq!(chain.certs().len(), 3, "{alg:?}");
        assert!(pkcs12_bundle(&issued.cert_pem, &key, &ca, "svc", "short").is_err());
    }

    let no_keygen = IssuancePolicy {
        allow_server_side_keygen: false,
        ..IssuancePolicy::default()
    };
    let ca = bootstrap(no_keygen);
    let denied = ca.issue_with_generated_key(&KeygenRequest {
        common_name: None,
        dns_names: vec!["svc.dmz.zenv.internal".into()],
        ip_addresses: vec![],
        profile: CertProfile::Server,
        validity_days: None,
        key_algorithm: KeyAlgorithm::EcdsaP256,
    });
    assert!(matches!(denied, Err(CaError::Policy(_))));
}

#[test]
fn export_formats() {
    let ca = bootstrap(IssuancePolicy::default());
    let (csr_pem, _) = csr(&["app.dmz.zenv.internal"], None);
    let issued = ca
        .issue_from_csr(&CsrRequest {
            csr_pem,
            profile: CertProfile::Server,
            validity_days: None,
        })
        .unwrap();
    let count = |b: Vec<u8>| String::from_utf8(b).unwrap().matches("BEGIN CERTIFICATE").count();
    assert_eq!(
        count(render_certificate(&issued.cert_pem, &ca, CertFormat::Pem).unwrap()),
        1
    );
    assert_eq!(
        count(render_certificate(&issued.cert_pem, &ca, CertFormat::Chain).unwrap()),
        2
    );
    assert_eq!(
        count(render_certificate(&issued.cert_pem, &ca, CertFormat::Fullchain).unwrap()),
        3
    );
    let der = render_certificate(&issued.cert_pem, &ca, CertFormat::Der).unwrap();
    assert_eq!(der[0], 0x30, "DER starts with a SEQUENCE");
}

#[test]
fn crl_lists_revoked_serials_and_verifies() {
    let ca = bootstrap(IssuancePolicy::default());
    let (csr_pem, _) = csr(&["app.dmz.zenv.internal"], None);
    let issued = ca
        .issue_from_csr(&CsrRequest {
            csr_pem,
            profile: CertProfile::Server,
            validity_days: None,
        })
        .unwrap();
    let crl = ca
        .build_crl(
            &[RevokedEntry {
                serial: issued.serial.clone(),
                revoked_at: time::OffsetDateTime::now_utc(),
                reason: RevocationReason::Superseded,
            }],
            7,
            time::Duration::days(7),
        )
        .unwrap();
    let (_, parsed) = CertificateRevocationList::from_der(&crl.der).unwrap();
    let serials: Vec<String> = parsed
        .iter_revoked_certificates()
        .map(|r| hex::encode(r.raw_serial()))
        .collect();
    assert_eq!(serials, vec![issued.serial]);
    let inter_der = pem_to_der(ca.intermediate_pem(), "CERTIFICATE").unwrap();
    let (_, inter) = x509_parser::certificate::X509Certificate::from_der(&inter_der).unwrap();
    parsed.verify_signature(inter.public_key()).unwrap();
}
