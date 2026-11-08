//! Certificate profiles: the fixed set of key usages / extended key usages a leaf gets.
//!
//! Requesters choose a profile; they never choose raw extensions. Anything the CSR asks
//! for beyond its names and public key is ignored.

use std::fmt;
use std::str::FromStr;

use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose};
use serde::{Deserialize, Serialize};

use crate::error::CaError;

/// What the certificate will be used for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertProfile {
    /// TLS server (`serverAuth`). The common case for services in the DMZ.
    #[default]
    Server,
    /// TLS client for mutual TLS (`clientAuth`).
    Client,
    /// Both server and client authentication (service-to-service mTLS).
    ServerClient,
}

impl CertProfile {
    /// Stable string form, used in storage and the API.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Client => "client",
            Self::ServerClient => "server-client",
        }
    }

    /// Applies the profile's extensions to the certificate parameters.
    ///
    /// `rsa_key` controls whether `keyEncipherment` is added (only meaningful for RSA keys,
    /// where TLS 1.2 RSA key exchange may need it).
    pub(crate) fn apply(self, params: &mut CertificateParams, rsa_key: bool) {
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        if rsa_key {
            params.key_usages.push(KeyUsagePurpose::KeyEncipherment);
        }
        params.extended_key_usages = match self {
            Self::Server => vec![ExtendedKeyUsagePurpose::ServerAuth],
            Self::Client => vec![ExtendedKeyUsagePurpose::ClientAuth],
            Self::ServerClient => vec![
                ExtendedKeyUsagePurpose::ServerAuth,
                ExtendedKeyUsagePurpose::ClientAuth,
            ],
        };
    }
}

impl fmt::Display for CertProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CertProfile {
    type Err = CaError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "server" => Ok(Self::Server),
            "client" => Ok(Self::Client),
            "server-client" => Ok(Self::ServerClient),
            other => Err(CaError::InvalidInput(format!("unknown profile '{other}'"))),
        }
    }
}
