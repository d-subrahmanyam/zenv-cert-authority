//! Bootstrapping the two-tier CA hierarchy.
//!
//! ```text
//!   Root CA (offline, 10y, pathLen=1)
//!     └── Intermediate CA (online in the daemon, 3y, pathLen=0, Name Constraints)
//!           └── Leaf certificates (30-90 days)
//! ```
//!
//! The root key is only needed here and when rotating the intermediate. After
//! `zenv-ca init` it should be moved to offline storage.

use std::fmt;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose,
};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

use crate::error::{CaError, Result};
use crate::keys::KeyAlgorithm;
use crate::policy::IssuancePolicy;
use crate::serial::random_serial;

/// Distinguished name fields used for CA certificates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaSubject {
    /// Common name, e.g. `Zenv DMZ Root CA`.
    pub common_name: String,
    /// Organisation, e.g. `Zenv`.
    pub organization: String,
    /// Organisational unit. Defaults to a marker that this hierarchy is **not** for prod.
    #[serde(default = "default_ou")]
    pub organizational_unit: String,
}

fn default_ou() -> String {
    "DMZ Non-Production".into()
}

impl CaSubject {
    fn to_dn(&self) -> DistinguishedName {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, self.common_name.as_str());
        dn.push(DnType::OrganizationName, self.organization.as_str());
        dn.push(DnType::OrganizationalUnitName, self.organizational_unit.as_str());
        dn
    }
}

/// Parameters for a CA certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaSpec {
    /// Subject of the CA certificate.
    pub subject: CaSubject,
    /// Lifetime in days.
    pub validity_days: u32,
    /// Key algorithm for the CA key.
    pub key_algorithm: KeyAlgorithm,
}

/// A freshly generated CA certificate together with its private key.
pub struct GeneratedCa {
    /// PEM-encoded certificate.
    pub cert_pem: String,
    /// The CA private key. Encrypt it before writing it anywhere.
    pub key: KeyPair,
}

impl fmt::Debug for GeneratedCa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeneratedCa")
            .field("cert_pem", &self.cert_pem)
            .field("key", &"<redacted>")
            .finish()
    }
}

fn ca_params(
    spec: &CaSpec,
    path_len: u8,
    not_after_cap: Option<OffsetDateTime>,
) -> Result<CertificateParams> {
    if spec.validity_days == 0 {
        return Err(CaError::InvalidInput(
            "CA validity must be at least one day".into(),
        ));
    }
    let now = OffsetDateTime::now_utc();
    let mut not_after = now + Duration::days(i64::from(spec.validity_days));
    if let Some(cap) = not_after_cap {
        if not_after > cap {
            not_after = cap;
        }
    }
    let mut params = CertificateParams::default();
    params.distinguished_name = spec.subject.to_dn();
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(path_len));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.not_before = now - Duration::minutes(5);
    params.not_after = not_after;
    params.serial_number = Some(random_serial());
    Ok(params)
}

/// Creates a self-signed root CA (pathLen = 1, so it can sign exactly one tier of
/// intermediates).
pub fn create_root(spec: &CaSpec) -> Result<GeneratedCa> {
    let key = spec.key_algorithm.generate()?;
    let params = ca_params(spec, 1, None)?;
    let cert = params.self_signed(&key)?;
    Ok(GeneratedCa {
        cert_pem: cert.pem(),
        key,
    })
}

/// Creates the online intermediate CA, signed by the root.
///
/// * `pathLen = 0`: it can only issue leaf certificates.
/// * Name Constraints mirror the issuance policy, so the intermediate is *technically*
///   unable to vouch for names outside the DMZ namespace.
/// * Its lifetime never exceeds the root's.
pub fn create_intermediate(
    root_cert_pem: &str,
    root_key: &KeyPair,
    spec: &CaSpec,
    policy: &IssuancePolicy,
) -> Result<GeneratedCa> {
    policy.validate()?;
    let root_der = pem_to_der(root_cert_pem, "CERTIFICATE")?;
    let (_, root) = X509Certificate::from_der(&root_der)
        .map_err(|e| CaError::Configuration(format!("cannot parse root certificate: {e}")))?;
    let root_not_after = OffsetDateTime::from_unix_timestamp(root.validity().not_after.timestamp())
        .map_err(|e| CaError::Configuration(format!("bad root expiry: {e}")))?;

    let issuer = Issuer::from_ca_cert_pem(root_cert_pem, root_key)?;
    let key = spec.key_algorithm.generate()?;
    let mut params = ca_params(spec, 0, Some(root_not_after))?;
    params.name_constraints = Some(policy.name_constraints()?);
    params.use_authority_key_identifier_extension = true;
    let cert = params.signed_by(&key, &issuer)?;
    Ok(GeneratedCa {
        cert_pem: cert.pem(),
        key,
    })
}

/// Extracts the DER payload of the first PEM block with the given tag.
pub fn pem_to_der(pem_text: &str, tag: &str) -> Result<Vec<u8>> {
    pem::parse_many(pem_text)
        .map_err(|e| CaError::InvalidInput(format!("invalid PEM: {e}")))?
        .into_iter()
        .find(|p| p.tag() == tag)
        .map(|p| p.into_contents())
        .ok_or_else(|| CaError::InvalidInput(format!("no '{tag}' PEM block found")))
}
