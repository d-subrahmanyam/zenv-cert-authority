//! Certificate serial numbers.
//!
//! Serials are 128 bits from the OS CSPRNG (the CA/Browser Forum requires at least 64 bits
//! of entropy). They are unpredictable, which defeats chosen-prefix collision attacks, and
//! unique with overwhelming probability. The store enforces uniqueness anyway.

use rand::RngCore;
use rcgen::SerialNumber;

use crate::error::{CaError, Result};

/// Generates a positive, 16-byte serial number with no leading zero byte, so its DER
/// encoding is always exactly 16 bytes and its hex form is stable (32 hex chars).
pub fn random_serial() -> SerialNumber {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes[0] &= 0x7f; // keep it positive in two's complement
    if bytes[0] == 0 {
        bytes[0] = 0x01; // avoid a leading zero that DER would strip
    }
    SerialNumber::from_slice(&bytes)
}

/// Canonical lower-case hex representation used as the primary key everywhere.
pub fn serial_to_hex(serial: &[u8]) -> String {
    hex::encode(serial)
}

/// Parses a serial from hex, accepting optional `:` separators (as printed by OpenSSL).
pub fn serial_from_hex(text: &str) -> Result<SerialNumber> {
    let cleaned: String = text.chars().filter(|c| *c != ':').collect();
    let bytes = hex::decode(cleaned.to_ascii_lowercase())
        .map_err(|_| CaError::InvalidInput(format!("'{text}' is not a hex serial number")))?;
    if bytes.is_empty() || bytes.len() > 20 {
        return Err(CaError::InvalidInput("serial must be 1..=20 bytes".into()));
    }
    Ok(SerialNumber::from_slice(&bytes))
}

/// Normalises user-supplied serial text into the canonical form.
pub fn normalise_serial(text: &str) -> Result<String> {
    Ok(serial_to_hex(&serial_from_hex(text)?.to_bytes()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn serials_are_16_bytes_and_positive() {
        for _ in 0..256 {
            let s = random_serial().to_bytes();
            assert_eq!(s.len(), 16);
            assert!(s[0] != 0 && s[0] < 0x80);
        }
    }

    #[test]
    fn openssl_style_serials_normalise() {
        assert_eq!(normalise_serial("0A:FF:10").unwrap(), "0aff10");
        assert!(normalise_serial("zz").is_err());
    }
}
