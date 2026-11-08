//! Issuance policy: which names may appear in a certificate and for how long it may live.
//!
//! The policy is the main defence against a requester obtaining a certificate for a name
//! they do not own. It is enforced in software at issuance time **and** mirrored into the
//! intermediate certificate as an X.509 *Name Constraints* extension, so that even a
//! mis-issued certificate outside the allowed namespace is rejected by RFC 5280 clients.

use std::net::IpAddr;
use std::str::FromStr;

use rcgen::{CidrSubnet, GeneralSubtree, NameConstraints};
use serde::{Deserialize, Serialize};

use crate::error::{CaError, Result};

fn default_validity_days() -> u32 {
    30
}
fn default_max_validity_days() -> u32 {
    90
}
fn default_max_sans() -> usize {
    20
}
fn default_true() -> bool {
    true
}

/// Rules applied to every end-entity certificate request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuancePolicy {
    /// DNS suffixes certificates may be issued under, e.g. `dmz.zenv.internal`.
    /// A name matches when it equals a suffix or ends with `.<suffix>`.
    pub allowed_dns_suffixes: Vec<String>,

    /// IP networks (CIDR notation) that IP SANs may come from. Empty means no IP SANs.
    #[serde(default)]
    pub allowed_ip_networks: Vec<String>,

    /// Validity applied when the requester does not ask for a specific one.
    #[serde(default = "default_validity_days")]
    pub default_validity_days: u32,

    /// Hard upper bound on validity. Short-lived certificates limit the damage of a leaked
    /// key and make revocation less critical.
    #[serde(default = "default_max_validity_days")]
    pub max_validity_days: u32,

    /// Whether `*.example` wildcard names may be requested.
    #[serde(default)]
    pub allow_wildcards: bool,

    /// Whether the CA may generate key pairs on behalf of requesters.
    /// CSR-based issuance (key never leaves the requester) is always available.
    #[serde(default = "default_true")]
    pub allow_server_side_keygen: bool,

    /// Maximum number of subject alternative names per certificate.
    #[serde(default = "default_max_sans")]
    pub max_sans: usize,
}

impl Default for IssuancePolicy {
    fn default() -> Self {
        Self {
            allowed_dns_suffixes: vec!["dmz.zenv.internal".into()],
            allowed_ip_networks: Vec::new(),
            default_validity_days: default_validity_days(),
            max_validity_days: default_max_validity_days(),
            allow_wildcards: false,
            allow_server_side_keygen: true,
            max_sans: default_max_sans(),
        }
    }
}

impl IssuancePolicy {
    /// Validates the policy itself (called once at start-up).
    pub fn validate(&self) -> Result<()> {
        if self.allowed_dns_suffixes.is_empty() && self.allowed_ip_networks.is_empty() {
            return Err(CaError::Configuration(
                "policy must allow at least one DNS suffix or IP network".into(),
            ));
        }
        for suffix in &self.allowed_dns_suffixes {
            validate_dns_name(suffix, false)
                .map_err(|e| CaError::Configuration(format!("bad DNS suffix '{suffix}': {e}")))?;
        }
        for net in &self.allowed_ip_networks {
            IpNetwork::from_str(net)?;
        }
        if self.default_validity_days == 0 || self.default_validity_days > self.max_validity_days {
            return Err(CaError::Configuration(
                "default_validity_days must be between 1 and max_validity_days".into(),
            ));
        }
        Ok(())
    }

    /// Resolves the effective validity in days, rejecting out-of-range requests rather than
    /// silently clamping them (explicit failures are easier to reason about).
    pub fn resolve_validity(&self, requested: Option<u32>) -> Result<u32> {
        let days = requested.unwrap_or(self.default_validity_days);
        if days == 0 {
            return Err(CaError::Policy("validity must be at least one day".into()));
        }
        if days > self.max_validity_days {
            return Err(CaError::Policy(format!(
                "requested validity of {days} days exceeds the maximum of {} days",
                self.max_validity_days
            )));
        }
        Ok(days)
    }

    /// Normalises and checks a set of requested names.
    ///
    /// Returns the normalised DNS names (lower-case, no trailing dot, de-duplicated).
    pub fn check_names(&self, dns_names: &[String], ips: &[IpAddr]) -> Result<Vec<String>> {
        if dns_names.is_empty() && ips.is_empty() {
            return Err(CaError::Policy(
                "at least one DNS name or IP address is required".into(),
            ));
        }
        if dns_names.len() + ips.len() > self.max_sans {
            return Err(CaError::Policy(format!(
                "too many subject alternative names (max {})",
                self.max_sans
            )));
        }

        let mut normalised: Vec<String> = Vec::with_capacity(dns_names.len());
        for raw in dns_names {
            let name = normalise_dns_name(raw);
            let is_wildcard = name.starts_with("*.");
            if is_wildcard && !self.allow_wildcards {
                return Err(CaError::Policy(format!("wildcard names are not allowed: {name}")));
            }
            validate_dns_name(&name, is_wildcard).map_err(CaError::Policy)?;
            let base = name.strip_prefix("*.").unwrap_or(&name);
            if !self.allowed_dns_suffixes.iter().any(|s| is_within(base, s)) {
                return Err(CaError::Policy(format!(
                    "'{name}' is outside the allowed DNS suffixes ({})",
                    self.allowed_dns_suffixes.join(", ")
                )));
            }
            if !normalised.contains(&name) {
                normalised.push(name);
            }
        }

        let networks = self
            .allowed_ip_networks
            .iter()
            .map(|n| IpNetwork::from_str(n))
            .collect::<Result<Vec<_>>>()?;
        for ip in ips {
            if !networks.iter().any(|n| n.contains(*ip)) {
                return Err(CaError::Policy(format!(
                    "IP address {ip} is outside the allowed networks"
                )));
            }
        }
        Ok(normalised)
    }

    /// Builds the X.509 Name Constraints extension that mirrors this policy.
    /// Embedded in the intermediate CA certificate at bootstrap.
    pub fn name_constraints(&self) -> Result<NameConstraints> {
        let mut permitted: Vec<GeneralSubtree> = self
            .allowed_dns_suffixes
            .iter()
            .map(|s| GeneralSubtree::DnsName(normalise_dns_name(s)))
            .collect();
        for net in &self.allowed_ip_networks {
            let subnet = CidrSubnet::from_str(net)
                .map_err(|()| CaError::Configuration(format!("bad IP network '{net}'")))?;
            permitted.push(GeneralSubtree::IpAddress(subnet));
        }
        Ok(NameConstraints {
            permitted_subtrees: permitted,
            excluded_subtrees: Vec::new(),
        })
    }
}

/// Lower-cases a DNS name and strips a trailing dot.
pub fn normalise_dns_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// `true` when `name` equals `suffix` or is a sub-domain of it (label boundary aware:
/// `evil-dmz.zenv.internal` is **not** within `dmz.zenv.internal`).
pub fn is_within(name: &str, suffix: &str) -> bool {
    let suffix = normalise_dns_name(suffix);
    name == suffix
        || name
            .strip_suffix(&suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

/// RFC 1035 / RFC 5280 host name syntax check (LDH labels, length limits).
fn validate_dns_name(name: &str, wildcard: bool) -> std::result::Result<(), String> {
    let host = if wildcard {
        name.strip_prefix("*.")
            .ok_or_else(|| format!("wildcards are only allowed as the left-most label: {name}"))?
    } else {
        name
    };
    if host.is_empty() || host.len() > 253 {
        return Err(format!("invalid DNS name length: '{name}'"));
    }
    for label in host.split('.') {
        let ok_len = !label.is_empty() && label.len() <= 63;
        let ok_chars = label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        let ok_hyphens = !label.starts_with('-') && !label.ends_with('-');
        if !(ok_len && ok_chars && ok_hyphens) {
            return Err(format!("invalid DNS label '{label}' in '{name}'"));
        }
    }
    Ok(())
}

/// Minimal CIDR network used for IP SAN policy checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IpNetwork {
    addr: IpAddr,
    prefix: u8,
}

impl FromStr for IpNetwork {
    type Err = CaError;

    fn from_str(s: &str) -> Result<Self> {
        let bad = || CaError::Configuration(format!("bad IP network '{s}' (expected CIDR)"));
        let (addr, prefix) = s.split_once('/').ok_or_else(bad)?;
        let addr: IpAddr = addr.parse().map_err(|_| bad())?;
        let prefix: u8 = prefix.parse().map_err(|_| bad())?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(bad());
        }
        Ok(Self { addr, prefix })
    }
}

impl IpNetwork {
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(self.prefix)).unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX.checked_shl(128 - u32::from(self.prefix)).unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn policy() -> IssuancePolicy {
        IssuancePolicy {
            allowed_ip_networks: vec!["10.20.0.0/16".into()],
            ..IssuancePolicy::default()
        }
    }

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn accepts_names_under_suffix() {
        let out = policy()
            .check_names(&names(&["API.dmz.zenv.internal.", "dmz.zenv.internal"]), &[])
            .unwrap();
        assert_eq!(out, names(&["api.dmz.zenv.internal", "dmz.zenv.internal"]));
    }

    #[test]
    fn rejects_label_boundary_tricks() {
        let err = policy().check_names(&names(&["evil-dmz.zenv.internal"]), &[]);
        assert!(err.is_err());
        let err = policy().check_names(&names(&["dmz.zenv.internal.attacker.com"]), &[]);
        assert!(err.is_err());
    }

    #[test]
    fn rejects_bad_syntax() {
        for bad in [
            "-a.dmz.zenv.internal",
            "a..dmz.zenv.internal",
            "a_b.dmz.zenv.internal",
        ] {
            assert!(policy().check_names(&names(&[bad]), &[]).is_err(), "{bad}");
        }
    }

    #[test]
    fn wildcards_need_opt_in() {
        let wc = names(&["*.dmz.zenv.internal"]);
        assert!(policy().check_names(&wc, &[]).is_err());
        let mut p = policy();
        p.allow_wildcards = true;
        assert!(p.check_names(&wc, &[]).is_ok());
        assert!(p.check_names(&names(&["a.*.dmz.zenv.internal"]), &[]).is_err());
    }

    #[test]
    fn ip_sans_must_be_in_allowed_network() {
        let p = policy();
        assert!(p.check_names(&[], &["10.20.3.4".parse().unwrap()]).is_ok());
        assert!(p.check_names(&[], &["10.21.3.4".parse().unwrap()]).is_err());
        assert!(p.check_names(&[], &["::1".parse().unwrap()]).is_err());
    }

    #[test]
    fn validity_bounds() {
        let p = policy();
        assert_eq!(p.resolve_validity(None).unwrap(), 30);
        assert_eq!(p.resolve_validity(Some(90)).unwrap(), 90);
        assert!(p.resolve_validity(Some(91)).is_err());
        assert!(p.resolve_validity(Some(0)).is_err());
    }

    #[test]
    fn policy_self_validation() {
        assert!(policy().validate().is_ok());
        let mut p = policy();
        p.allowed_dns_suffixes.clear();
        p.allowed_ip_networks.clear();
        assert!(p.validate().is_err());
    }
}
