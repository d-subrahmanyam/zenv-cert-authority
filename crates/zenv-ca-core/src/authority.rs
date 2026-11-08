//! The online signing authority: issues leaf certificates and CRLs with the intermediate key.

use std::fmt;
use std::net::IpAddr;

use rcgen::{
    CertificateParams, CertificateRevocationListParams, CertificateSigningRequestParams,
    CrlDistributionPoint, DistinguishedName, DnType, Issuer, KeyIdMethod, KeyPair, PublicKeyData,
    RevokedCertParams, SanType, SerialNumber,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use x509_parser::certificate::X509Certificate;
use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::prelude::FromDer;

use crate::error::{CaError, Result};
use crate::hierarchy::pem_to_der;
use crate::keys::{KeyAlgorithm, is_rsa};
use crate::policy::{IssuancePolicy, normalise_dns_name};
use crate::profile::CertProfile;
use crate::revocation::RevocationReason;
use crate::serial::{random_serial, serial_from_hex, serial_to_hex};

/// Clock-skew allowance: `notBefore` is back-dated by this much.
const BACKDATE: Duration = Duration::minutes(5);

/// Request to sign a CSR the requester generated themselves (recommended path).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsrRequest {
    /// PEM-encoded PKCS#10 certificate signing request.
    pub csr_pem: String,
    /// Usage profile.
    #[serde(default)]
    pub profile: CertProfile,
    /// Requested validity; the policy default applies when absent.
    #[serde(default)]
    pub validity_days: Option<u32>,
}

/// Request for the CA to generate the key pair as well (convenience path).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeygenRequest {
    /// Subject common name; defaults to the first DNS name.
    #[serde(default)]
    pub common_name: Option<String>,
    /// DNS subject alternative names.
    #[serde(default)]
    pub dns_names: Vec<String>,
    /// IP subject alternative names.
    #[serde(default)]
    pub ip_addresses: Vec<IpAddr>,
    /// Usage profile.
    #[serde(default)]
    pub profile: CertProfile,
    /// Requested validity; the policy default applies when absent.
    #[serde(default)]
    pub validity_days: Option<u32>,
    /// Algorithm for the generated key.
    #[serde(default)]
    pub key_algorithm: KeyAlgorithm,
}

/// Metadata and encoding of an issued certificate (never contains a private key).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuedCertificate {
    /// Canonical lower-case hex serial number.
    pub serial: String,
    /// Subject common name.
    pub common_name: String,
    /// DNS SANs.
    pub dns_names: Vec<String>,
    /// IP SANs (textual form).
    pub ip_addresses: Vec<String>,
    /// Usage profile.
    pub profile: CertProfile,
    /// Start of validity.
    #[serde(with = "time::serde::rfc3339")]
    pub not_before: OffsetDateTime,
    /// End of validity.
    #[serde(with = "time::serde::rfc3339")]
    pub not_after: OffsetDateTime,
    /// Public key algorithm description.
    pub key_algorithm: String,
    /// SHA-256 fingerprint of the DER certificate (lower-case hex).
    pub fingerprint_sha256: String,
    /// PEM-encoded certificate.
    pub cert_pem: String,
}

/// An entry on the certificate revocation list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokedEntry {
    /// Canonical hex serial.
    pub serial: String,
    /// When the revocation took effect.
    pub revoked_at: OffsetDateTime,
    /// RFC 5280 reason code.
    pub reason: RevocationReason,
}

/// A signed CRL in both encodings.
#[derive(Debug, Clone)]
pub struct CrlDocument {
    /// DER encoding (served as `application/pkix-crl`).
    pub der: Vec<u8>,
    /// PEM encoding.
    pub pem: String,
    /// CRL number (monotonic).
    pub number: u64,
    /// `thisUpdate`.
    pub this_update: OffsetDateTime,
    /// `nextUpdate`; relying parties must refetch before this.
    pub next_update: OffsetDateTime,
}

/// The online CA: intermediate key + certificate chain + policy.
pub struct CertificateAuthority {
    issuer: Issuer<'static, KeyPair>,
    root_pem: String,
    root_der: Vec<u8>,
    intermediate_pem: String,
    intermediate_der: Vec<u8>,
    policy: IssuancePolicy,
    crl_url: Option<String>,
}

impl fmt::Debug for CertificateAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertificateAuthority")
            .field("policy", &self.policy)
            .field("crl_url", &self.crl_url)
            .finish_non_exhaustive()
    }
}

impl CertificateAuthority {
    /// Loads the CA from its certificates and the (already decrypted) intermediate key.
    ///
    /// Fails fast when the material is inconsistent: key/cert mismatch, intermediate not
    /// signed by the root, intermediate not a CA, or an invalid policy.
    pub fn load(
        root_pem: &str,
        intermediate_pem: &str,
        intermediate_key: KeyPair,
        policy: IssuancePolicy,
        crl_url: Option<String>,
    ) -> Result<Self> {
        policy.validate()?;
        let root_der = pem_to_der(root_pem, "CERTIFICATE")?;
        let intermediate_der = pem_to_der(intermediate_pem, "CERTIFICATE")?;
        {
            let root = parse_cert(&root_der, "root")?;
            let intermediate = parse_cert(&intermediate_der, "intermediate")?;
            if !root.is_ca() || !intermediate.is_ca() {
                return Err(CaError::Configuration(
                    "root and intermediate must both be CA certificates".into(),
                ));
            }
            intermediate
                .verify_signature(Some(root.public_key()))
                .map_err(|_| CaError::Configuration("intermediate is not signed by the root".into()))?;
            if intermediate_key.subject_public_key_info() != intermediate.public_key().raw {
                return Err(CaError::Configuration(
                    "intermediate key does not match the intermediate certificate".into(),
                ));
            }
        }
        let issuer = Issuer::from_ca_cert_pem(intermediate_pem, intermediate_key)?;
        Ok(Self {
            issuer,
            root_pem: root_pem.to_owned(),
            root_der,
            intermediate_pem: intermediate_pem.to_owned(),
            intermediate_der,
            policy,
            crl_url,
        })
    }

    /// The active issuance policy.
    pub fn policy(&self) -> &IssuancePolicy {
        &self.policy
    }

    /// Root certificate (PEM), the trust anchor relying parties install.
    pub fn root_pem(&self) -> &str {
        &self.root_pem
    }

    /// Root certificate (DER).
    pub fn root_der(&self) -> &[u8] {
        &self.root_der
    }

    /// Intermediate certificate (PEM).
    pub fn intermediate_pem(&self) -> &str {
        &self.intermediate_pem
    }

    /// Intermediate certificate (DER).
    pub fn intermediate_der(&self) -> &[u8] {
        &self.intermediate_der
    }

    /// Intermediate followed by root, PEM. Handy as a CA bundle.
    pub fn chain_pem(&self) -> String {
        format!("{}{}", self.intermediate_pem, self.root_pem)
    }

    /// Signs a requester-supplied CSR.
    ///
    /// Only the CSR's **public key** and **names** are used. Every other attribute
    /// (key usage, basic constraints, validity, extensions) comes from the profile and the
    /// policy, so a CSR cannot ask for a CA certificate or a long lifetime.
    pub fn issue_from_csr(&self, request: &CsrRequest) -> Result<IssuedCertificate> {
        let csr = CertificateSigningRequestParams::from_pem(&request.csr_pem)
            .map_err(|e| CaError::InvalidCsr(e.to_string()))?;
        let common_name = csr_common_name(&request.csr_pem)?;

        let mut dns_names = Vec::new();
        let mut ips = Vec::new();
        for san in &csr.params.subject_alt_names {
            match san {
                SanType::DnsName(name) => dns_names.push(name.as_str().to_owned()),
                SanType::IpAddress(ip) => ips.push(*ip),
                other => {
                    return Err(CaError::Policy(format!(
                        "unsupported subject alternative name type: {other:?}"
                    )));
                }
            }
        }
        // Legacy CSRs often carry the host name only in the CN.
        if dns_names.is_empty() && ips.is_empty() {
            if let Some(cn) = &common_name {
                dns_names.push(cn.clone());
            }
        }
        // The CA owns the subject: a CSR CN that is not one of the requested names
        // (e.g. "my-service" or a tool default) is dropped rather than copied verbatim.
        let common_name = common_name.filter(|cn| {
            let cn_norm = normalise_dns_name(cn);
            dns_names.iter().any(|d| normalise_dns_name(d) == cn_norm)
                || ips.iter().any(|ip| ip.to_string() == *cn)
        });

        let rsa = is_rsa(csr.public_key.algorithm());
        let leaf = self.leaf_params(
            common_name.as_deref(),
            &dns_names,
            &ips,
            request.profile,
            request.validity_days,
            rsa,
        )?;
        let cert = leaf.params.signed_by(&csr.public_key, &self.issuer)?;
        Ok(leaf.into_issued(cert.pem(), cert.der(), describe_alg(csr.public_key.algorithm())))
    }

    /// Generates a key pair and a certificate for it. The caller is responsible for
    /// handing the key to the requester exactly once and then dropping it.
    pub fn issue_with_generated_key(&self, request: &KeygenRequest) -> Result<(IssuedCertificate, KeyPair)> {
        if !self.policy.allow_server_side_keygen {
            return Err(CaError::Policy(
                "server-side key generation is disabled; submit a CSR instead".into(),
            ));
        }
        let key = request.key_algorithm.generate()?;
        let leaf = self.leaf_params(
            request.common_name.as_deref(),
            &request.dns_names,
            &request.ip_addresses,
            request.profile,
            request.validity_days,
            is_rsa(key.algorithm()),
        )?;
        let cert = leaf.params.signed_by(&key, &self.issuer)?;
        let issued = leaf.into_issued(cert.pem(), cert.der(), request.key_algorithm.as_str().into());
        Ok((issued, key))
    }

    /// Builds and signs a CRL listing `revoked`.
    pub fn build_crl(
        &self,
        revoked: &[RevokedEntry],
        crl_number: u64,
        validity: Duration,
    ) -> Result<CrlDocument> {
        let now = OffsetDateTime::now_utc();
        let revoked_certs = revoked
            .iter()
            .map(|r| {
                Ok(RevokedCertParams {
                    serial_number: serial_from_hex(&r.serial)?,
                    revocation_time: r.revoked_at,
                    reason_code: Some(r.reason.into()),
                    invalidity_date: None,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let params = CertificateRevocationListParams {
            this_update: now,
            next_update: now + validity,
            crl_number: SerialNumber::from(crl_number),
            issuing_distribution_point: None,
            revoked_certs,
            key_identifier_method: KeyIdMethod::Sha256,
        };
        let crl = params.signed_by(&self.issuer)?;
        Ok(CrlDocument {
            der: crl.der().to_vec(),
            pem: crl.pem()?,
            number: crl_number,
            this_update: params.this_update,
            next_update: params.next_update,
        })
    }

    fn leaf_params(
        &self,
        common_name: Option<&str>,
        dns_names: &[String],
        ips: &[IpAddr],
        profile: CertProfile,
        validity_days: Option<u32>,
        rsa_key: bool,
    ) -> Result<LeafParams> {
        let days = self.policy.resolve_validity(validity_days)?;
        let dns_names = self.policy.check_names(dns_names, ips)?;
        let ip_strings: Vec<String> = ips.iter().map(ToString::to_string).collect();

        // The CN must be one of the validated SANs, otherwise it would be an unchecked
        // name that legacy clients might still honour.
        let common_name = match common_name.map(str::trim).filter(|c| !c.is_empty()) {
            Some(cn) => {
                let normalised = normalise_dns_name(cn);
                if dns_names.contains(&normalised) {
                    normalised
                } else if ip_strings.iter().any(|ip| ip == cn) {
                    cn.to_owned()
                } else {
                    return Err(CaError::Policy(format!(
                        "common name '{cn}' must also appear as a subject alternative name"
                    )));
                }
            }
            None => dns_names
                .first()
                .or(ip_strings.first())
                .cloned()
                .ok_or_else(|| CaError::Policy("no names requested".into()))?,
        };
        if common_name.len() > 64 {
            return Err(CaError::Policy("common name exceeds 64 characters".into()));
        }

        let now = OffsetDateTime::now_utc();
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name.as_str());
        params.distinguished_name = dn;
        params.subject_alt_names = dns_names
            .iter()
            .map(|n| {
                n.clone()
                    .try_into()
                    .map(SanType::DnsName)
                    .map_err(|_| CaError::Policy(format!("'{n}' is not a valid IA5 name")))
            })
            .chain(ips.iter().map(|ip| Ok(SanType::IpAddress(*ip))))
            .collect::<Result<Vec<_>>>()?;
        params.not_before = now - BACKDATE;
        params.not_after = now + Duration::days(i64::from(days));
        let serial = random_serial();
        let serial_hex = serial_to_hex(&serial.to_bytes());
        params.serial_number = Some(serial);
        params.use_authority_key_identifier_extension = true;
        if let Some(url) = &self.crl_url {
            params.crl_distribution_points = vec![CrlDistributionPoint {
                uris: vec![url.clone()],
            }];
        }
        profile.apply(&mut params, rsa_key);

        Ok(LeafParams {
            serial: serial_hex,
            common_name,
            dns_names,
            ip_addresses: ip_strings,
            profile,
            not_before: params.not_before,
            not_after: params.not_after,
            params,
        })
    }
}

/// Leaf parameters plus the metadata we report back after signing.
struct LeafParams {
    params: CertificateParams,
    serial: String,
    common_name: String,
    dns_names: Vec<String>,
    ip_addresses: Vec<String>,
    profile: CertProfile,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
}

impl LeafParams {
    fn into_issued(self, cert_pem: String, cert_der: &[u8], key_algorithm: String) -> IssuedCertificate {
        IssuedCertificate {
            serial: self.serial,
            common_name: self.common_name,
            dns_names: self.dns_names,
            ip_addresses: self.ip_addresses,
            profile: self.profile,
            // X.509 stores whole seconds; report what is actually in the certificate.
            not_before: self.not_before.replace_nanosecond(0).unwrap_or(self.not_before),
            not_after: self.not_after.replace_nanosecond(0).unwrap_or(self.not_after),
            key_algorithm,
            fingerprint_sha256: hex::encode(Sha256::digest(cert_der)),
            cert_pem,
        }
    }
}

fn parse_cert<'a>(der: &'a [u8], what: &str) -> Result<X509Certificate<'a>> {
    X509Certificate::from_der(der)
        .map(|(_, c)| c)
        .map_err(|e| CaError::Configuration(format!("cannot parse {what} certificate: {e}")))
}

/// Reads the subject CN from a CSR (rcgen does not expose it in a convenient form).
fn csr_common_name(csr_pem: &str) -> Result<Option<String>> {
    let der = pem_to_der(csr_pem, "CERTIFICATE REQUEST")?;
    let (_, csr) =
        X509CertificationRequest::from_der(&der).map_err(|e| CaError::InvalidCsr(e.to_string()))?;
    Ok(csr
        .certification_request_info
        .subject
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(str::to_owned))
}

fn describe_alg(alg: &rcgen::SignatureAlgorithm) -> String {
    if alg == &rcgen::PKCS_ECDSA_P256_SHA256 {
        "ecdsa-p256".into()
    } else if alg == &rcgen::PKCS_ECDSA_P384_SHA384 {
        "ecdsa-p384".into()
    } else if alg == &rcgen::PKCS_ED25519 {
        "ed25519".into()
    } else if is_rsa(alg) {
        "rsa".into()
    } else {
        format!("{alg:?}")
    }
}
