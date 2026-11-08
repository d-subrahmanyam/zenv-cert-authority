//! Revocation reasons and the lookup abstraction used during verification.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::CaError;

/// The subset of RFC 5280 §5.3.1 reason codes that make sense for a leaf-issuing CA.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RevocationReason {
    /// No specific reason.
    #[default]
    Unspecified,
    /// The private key was (or may have been) exposed.
    KeyCompromise,
    /// The subject's relationship with the organisation changed.
    AffiliationChanged,
    /// Replaced by a newer certificate.
    Superseded,
    /// The service was decommissioned.
    CessationOfOperation,
}

impl RevocationReason {
    /// Stable string form, used in storage and the API.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::KeyCompromise => "key-compromise",
            Self::AffiliationChanged => "affiliation-changed",
            Self::Superseded => "superseded",
            Self::CessationOfOperation => "cessation-of-operation",
        }
    }
}

impl fmt::Display for RevocationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RevocationReason {
    type Err = CaError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "unspecified" => Self::Unspecified,
            "key-compromise" => Self::KeyCompromise,
            "affiliation-changed" => Self::AffiliationChanged,
            "superseded" => Self::Superseded,
            "cessation-of-operation" => Self::CessationOfOperation,
            other => {
                return Err(CaError::InvalidInput(format!(
                    "unknown revocation reason '{other}'"
                )));
            }
        })
    }
}

impl From<RevocationReason> for rcgen::RevocationReason {
    fn from(r: RevocationReason) -> Self {
        match r {
            RevocationReason::Unspecified => Self::Unspecified,
            RevocationReason::KeyCompromise => Self::KeyCompromise,
            RevocationReason::AffiliationChanged => Self::AffiliationChanged,
            RevocationReason::Superseded => Self::Superseded,
            RevocationReason::CessationOfOperation => Self::CessationOfOperation,
        }
    }
}

/// Revocation state of a serial as known to the CA's inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum RevocationStatus {
    /// Issued by this CA and not revoked.
    Good,
    /// Issued by this CA and revoked.
    Revoked {
        /// Unix timestamp of the revocation.
        revoked_at: i64,
        /// Reason code.
        reason: RevocationReason,
    },
    /// Not in the inventory. For a certificate that *does* chain to this CA this is an
    /// anomaly (lost database or key misuse) and verification fails.
    Unknown,
}

/// Source of revocation information (implemented by the store).
pub trait RevocationLookup {
    /// Looks up a canonical hex serial.
    fn status(&self, serial: &str) -> RevocationStatus;
}

/// Lookup used when no inventory is available: every serial is [`RevocationStatus::Unknown`].
#[derive(Debug, Clone, Copy, Default)]
pub struct NoRevocationInfo;

impl RevocationLookup for NoRevocationInfo {
    fn status(&self, _serial: &str) -> RevocationStatus {
        RevocationStatus::Unknown
    }
}
