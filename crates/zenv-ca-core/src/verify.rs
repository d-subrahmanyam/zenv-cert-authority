//! Certificate verification ("is this certificate one of ours, and is it still good?").
//!
//! This mirrors what a relying party does locally (chain, signature, validity, names), plus
//! a live revocation check against the CA inventory. Trust comes **only** from the CA's own
//! root and intermediate: any intermediates the caller includes are ignored.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;
use x509_parser::time::ASN1Time;

use crate::authority::CertificateAuthority;
use crate::policy::is_within;
use crate::revocation::{RevocationLookup, RevocationStatus};
use crate::serial::serial_to_hex;

/// Options for [`CertificateAuthority::verify`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyOptions {
    /// If set, the certificate must be valid for this host name or IP address.
    #[serde(default)]
    pub hostname: Option<String>,
    /// Evaluate validity at this instant instead of now (useful for incident analysis).
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub at: Option<OffsetDateTime>,
}

/// Outcome of a single check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Check {
    /// Stable machine-readable check id.
    pub name: String,
    /// Whether it passed.
    pub passed: bool,
    /// Human-readable explanation.
    pub detail: String,
}

/// Full verification report.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationReport {
    /// `true` only if every check passed.
    pub valid: bool,
    /// Subject DN.
    pub subject: Option<String>,
    /// Issuer DN.
    pub issuer: Option<String>,
    /// Canonical hex serial.
    pub serial: Option<String>,
    /// SHA-256 fingerprint of the DER certificate.
    pub fingerprint_sha256: Option<String>,
    /// Start of validity (RFC 3339).
    pub not_before: Option<String>,
    /// End of validity (RFC 3339).
    pub not_after: Option<String>,
    /// DNS SANs.
    pub dns_names: Vec<String>,
    /// Revocation status from the inventory.
    pub revocation: Option<RevocationStatus>,
    /// Individual checks, in evaluation order.
    pub checks: Vec<Check>,
}

impl VerificationReport {
    fn push(&mut self, name: &str, passed: bool, detail: impl Into<String>) {
        self.checks.push(Check {
            name: name.into(),
            passed,
            detail: detail.into(),
        });
    }

    fn finish(mut self) -> Self {
        self.valid = !self.checks.is_empty() && self.checks.iter().all(|c| c.passed);
        self
    }
}

/// Extracts the first certificate from PEM text or raw DER.
fn leaf_der(input: &[u8]) -> Result<Vec<u8>, String> {
    if input.windows(10).any(|w| w == b"-----BEGIN") {
        let text = std::str::from_utf8(input).map_err(|_| "PEM input is not UTF-8".to_string())?;
        pem::parse_many(text)
            .map_err(|e| format!("invalid PEM: {e}"))?
            .into_iter()
            .find(|p| p.tag() == "CERTIFICATE")
            .map(|p| p.into_contents())
            .ok_or_else(|| "no CERTIFICATE block found".to_string())
    } else {
        Ok(input.to_vec())
    }
}

/// SHA-256 fingerprint in the colon-separated upper-case form printed by
/// `openssl x509 -noout -fingerprint -sha256`, for comparing against out-of-band values.
pub fn openssl_fingerprint(der: &[u8]) -> String {
    Sha256::digest(der)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn rfc3339(t: ASN1Time) -> Option<String> {
    OffsetDateTime::from_unix_timestamp(t.timestamp())
        .ok()
        .and_then(|t| t.format(&time::format_description::well_known::Rfc3339).ok())
}

impl CertificateAuthority {
    /// Verifies a certificate (PEM or DER) against this CA.
    pub fn verify(
        &self,
        input: &[u8],
        options: &VerifyOptions,
        revocation: &dyn RevocationLookup,
    ) -> VerificationReport {
        let mut report = VerificationReport::default();

        let der = match leaf_der(input) {
            Ok(der) => der,
            Err(e) => {
                report.push("parse", false, e);
                return report.finish();
            }
        };
        let leaf = match X509Certificate::from_der(&der) {
            Ok((_, cert)) => cert,
            Err(e) => {
                report.push("parse", false, format!("not an X.509 certificate: {e}"));
                return report.finish();
            }
        };
        // The CA's own material was validated at load time, so parsing cannot fail here;
        // stay defensive anyway rather than panicking inside a request handler.
        let (Ok((_, intermediate)), Ok((_, root))) = (
            X509Certificate::from_der(self.intermediate_der()),
            X509Certificate::from_der(self.root_der()),
        ) else {
            report.push("ca", false, "CA certificates could not be parsed");
            return report.finish();
        };
        report.push("parse", true, "certificate parsed");

        let serial = serial_to_hex(leaf.raw_serial());
        report.subject = Some(leaf.subject().to_string());
        report.issuer = Some(leaf.issuer().to_string());
        report.serial = Some(serial.clone());
        report.fingerprint_sha256 = Some(hex::encode(Sha256::digest(&der)));
        report.not_before = rfc3339(leaf.validity().not_before);
        report.not_after = rfc3339(leaf.validity().not_after);

        let (dns_names, ips) = sans(&leaf);
        report.dns_names = dns_names.clone();

        // 1. Issued by our intermediate (name match + cryptographic signature).
        let issuer_matches = leaf.issuer().as_raw() == intermediate.subject().as_raw();
        let signature_ok = leaf.verify_signature(Some(intermediate.public_key())).is_ok();
        report.push(
            "signature",
            issuer_matches && signature_ok,
            if !issuer_matches {
                "certificate was not issued by this CA's intermediate".to_string()
            } else if !signature_ok {
                "signature does not verify against the intermediate key".to_string()
            } else {
                "signed by this CA's intermediate".to_string()
            },
        );

        // 2. Intermediate chains to the root.
        let chain_ok = intermediate.verify_signature(Some(root.public_key())).is_ok()
            && root.verify_signature(None).is_ok();
        report.push(
            "chain",
            chain_ok,
            if chain_ok {
                "intermediate chains to the root"
            } else {
                "broken CA chain"
            },
        );

        // 3. Validity window, for the leaf and every CA above it.
        let at = options.at.unwrap_or_else(OffsetDateTime::now_utc);
        let at_asn1 = ASN1Time::from_timestamp(at.unix_timestamp()).unwrap_or_else(|_| ASN1Time::now());
        let leaf_time_ok = leaf.validity().is_valid_at(at_asn1);
        let ca_time_ok = intermediate.validity().is_valid_at(at_asn1) && root.validity().is_valid_at(at_asn1);
        report.push(
            "validity",
            leaf_time_ok && ca_time_ok,
            if !leaf_time_ok {
                "certificate is expired or not yet valid"
            } else if !ca_time_ok {
                "a CA certificate in the chain is expired"
            } else {
                "within validity period"
            },
        );

        // 4. Leaf must not be a CA.
        let not_ca = !leaf.is_ca();
        report.push(
            "basic-constraints",
            not_ca,
            if not_ca {
                "end-entity certificate"
            } else {
                "leaf is marked as a CA"
            },
        );

        // 5. Names fall inside the intermediate's Name Constraints.
        let (nc_ok, nc_detail) = check_name_constraints(&intermediate, &dns_names);
        report.push("name-constraints", nc_ok, nc_detail);

        // 6. Revocation status from the inventory.
        let status = revocation.status(&serial);
        let (rev_ok, rev_detail) = match &status {
            RevocationStatus::Good => (true, "not revoked".to_string()),
            RevocationStatus::Revoked { reason, .. } => (false, format!("revoked ({reason})")),
            RevocationStatus::Unknown => (false, "serial is not in the CA inventory".to_string()),
        };
        report.revocation = Some(status);
        report.push("revocation", rev_ok, rev_detail);

        // 7. Optional host name check.
        if let Some(host) = options
            .hostname
            .as_deref()
            .map(str::trim)
            .filter(|h| !h.is_empty())
        {
            let ok = matches_host(host, &dns_names, &ips);
            report.push(
                "hostname",
                ok,
                if ok {
                    format!("valid for '{host}'")
                } else {
                    format!("not valid for '{host}'")
                },
            );
        }

        report.finish()
    }
}

fn sans(cert: &X509Certificate<'_>) -> (Vec<String>, Vec<IpAddr>) {
    let mut dns = Vec::new();
    let mut ips = Vec::new();
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for name in &ext.value.general_names {
            match name {
                GeneralName::DNSName(d) => dns.push(d.to_ascii_lowercase()),
                GeneralName::IPAddress(bytes) => {
                    if let Ok(v4) = <[u8; 4]>::try_from(*bytes) {
                        ips.push(IpAddr::from(v4));
                    } else if let Ok(v6) = <[u8; 16]>::try_from(*bytes) {
                        ips.push(IpAddr::from(v6));
                    }
                }
                _ => {}
            }
        }
    }
    (dns, ips)
}

fn check_name_constraints(intermediate: &X509Certificate<'_>, dns_names: &[String]) -> (bool, String) {
    let constraints = intermediate
        .extensions()
        .iter()
        .find_map(|e| match e.parsed_extension() {
            ParsedExtension::NameConstraints(nc) => Some(nc),
            _ => None,
        });
    let Some(nc) = constraints else {
        return (true, "intermediate has no name constraints".into());
    };
    let permitted: Vec<&str> = nc
        .permitted_subtrees
        .iter()
        .flatten()
        .filter_map(|s| match s.base {
            GeneralName::DNSName(d) => Some(d),
            _ => None,
        })
        .collect();
    if permitted.is_empty() {
        return (true, "no DNS name constraints".into());
    }
    let outside: Vec<&String> = dns_names
        .iter()
        .filter(|n| {
            let base = n.strip_prefix("*.").unwrap_or(n);
            !permitted
                .iter()
                .any(|p| is_within(base, p.trim_start_matches('.')))
        })
        .collect();
    if outside.is_empty() {
        (true, format!("all names within {}", permitted.join(", ")))
    } else {
        (
            false,
            format!(
                "names outside permitted subtrees: {}",
                outside.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            ),
        )
    }
}

/// RFC 6125 host matching: exact match, or a left-most wildcard matching one label.
fn matches_host(host: &str, dns_names: &[String], ips: &[IpAddr]) -> bool {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return ips.contains(&ip);
    }
    let host = crate::policy::normalise_dns_name(host);
    dns_names.iter().any(|name| {
        if let Some(rest) = name.strip_prefix("*.") {
            host.split_once('.')
                .is_some_and(|(label, tail)| !label.is_empty() && tail == rest)
        } else {
            *name == host
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_matching_rules() {
        let names = vec!["api.dmz.x".to_string(), "*.web.dmz.x".to_string()];
        assert!(matches_host("api.dmz.x", &names, &[]));
        assert!(matches_host("API.dmz.x.", &names, &[]));
        assert!(matches_host("a.web.dmz.x", &names, &[]));
        assert!(!matches_host("a.b.web.dmz.x", &names, &[]));
        assert!(!matches_host("web.dmz.x", &names, &[]));
        assert!(!matches_host("other.dmz.x", &names, &[]));
    }
}
