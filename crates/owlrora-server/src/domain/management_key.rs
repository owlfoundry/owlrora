use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore as _;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

const PREFIX: &str = "owlrora_mgmt_v1";
const LOOKUP_BYTES: usize = 16;
const SECRET_BYTES: usize = 32;
const MAX_LOOKUP_BYTES: usize = 32;
const MAX_SECRET_BYTES: usize = 64;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ManagementKeyMaterial {
    lookup: Vec<u8>,
    secret: Vec<u8>,
}

impl fmt::Debug for ManagementKeyMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ManagementKeyMaterial([REDACTED])")
    }
}

impl ManagementKeyMaterial {
    pub fn parse(value: &str) -> Result<Self, ManagementKeyParseError> {
        let mut segments = value.split('.');
        let prefix = segments.next();
        let lookup = segments.next();
        let secret = segments.next();
        if segments.next().is_some() || prefix != Some(PREFIX) {
            return Err(ManagementKeyParseError::InvalidFormat);
        }
        let lookup_text = lookup.ok_or(ManagementKeyParseError::InvalidFormat)?;
        let secret_text = secret.ok_or(ManagementKeyParseError::InvalidFormat)?;
        if lookup_text.contains('=') || secret_text.contains('=') {
            return Err(ManagementKeyParseError::NonCanonicalEncoding);
        }
        let lookup = URL_SAFE_NO_PAD
            .decode(lookup_text)
            .map_err(|_| ManagementKeyParseError::InvalidEncoding)?;
        let secret = URL_SAFE_NO_PAD
            .decode(secret_text)
            .map_err(|_| ManagementKeyParseError::InvalidEncoding)?;
        if !(LOOKUP_BYTES..=MAX_LOOKUP_BYTES).contains(&lookup.len())
            || !(SECRET_BYTES..=MAX_SECRET_BYTES).contains(&secret.len())
        {
            return Err(ManagementKeyParseError::InsufficientEntropy);
        }
        if URL_SAFE_NO_PAD.encode(&lookup) != lookup_text
            || URL_SAFE_NO_PAD.encode(&secret) != secret_text
        {
            return Err(ManagementKeyParseError::NonCanonicalEncoding);
        }
        Ok(Self { lookup, secret })
    }

    #[must_use]
    pub fn expose_once(&self) -> String {
        format!(
            "{PREFIX}.{}.{}",
            URL_SAFE_NO_PAD.encode(&self.lookup),
            URL_SAFE_NO_PAD.encode(&self.secret)
        )
    }

    #[must_use]
    pub fn lookup_text(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.lookup)
    }

    fn canonical_decoded_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 + self.lookup.len() + self.secret.len());
        bytes.extend_from_slice(
            &u16::try_from(self.lookup.len())
                .expect("management key lookup length is bounded")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&self.lookup);
        bytes.extend_from_slice(
            &u16::try_from(self.secret.len())
                .expect("management key secret length is bounded")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&self.secret);
        bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ManagementKeyParseError {
    #[error("management key has an invalid format")]
    InvalidFormat,
    #[error("management key has invalid base64url encoding")]
    InvalidEncoding,
    #[error("management key encoding is not canonical")]
    NonCanonicalEncoding,
    #[error("management key does not contain the required entropy")]
    InsufficientEntropy,
}

#[must_use]
pub fn generate_management_key() -> ManagementKeyMaterial {
    let mut lookup = vec![0_u8; LOOKUP_BYTES];
    let mut secret = vec![0_u8; SECRET_BYTES];
    rand::rng().fill_bytes(&mut lookup);
    rand::rng().fill_bytes(&mut secret);
    ManagementKeyMaterial { lookup, secret }
}

#[must_use]
pub fn seed_admin_key_version_id(material: &ManagementKeyMaterial) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"owlrora/management-api-key/seed-admin/v1\0");
    digest.update(material.canonical_decoded_bytes());
    digest.finalize().into()
}

#[must_use]
pub fn management_key_digest(material: &ManagementKeyMaterial) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"owlrora/management-api-key/durable/v1\0");
    digest.update(material.canonical_decoded_bytes());
    digest.finalize().into()
}

#[must_use]
pub fn constant_time_digest_matches(left: &[u8; 32], right: &[u8; 32]) -> bool {
    bool::from(left.ct_eq(right))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_round_trip_canonically() {
        let key = generate_management_key();
        let encoded = key.expose_once();
        let parsed = ManagementKeyMaterial::parse(&encoded).unwrap();
        assert_eq!(parsed.expose_once(), encoded);
        assert_eq!(management_key_digest(&parsed), management_key_digest(&key));
    }

    #[test]
    fn parser_rejects_wrong_class_padding_and_short_values() {
        assert_eq!(
            ManagementKeyMaterial::parse("owlrora_llm_v1.AA.AA").unwrap_err(),
            ManagementKeyParseError::InvalidFormat
        );
        assert_eq!(
            ManagementKeyMaterial::parse("owlrora_mgmt_v1.AA=.AA=").unwrap_err(),
            ManagementKeyParseError::NonCanonicalEncoding
        );
        assert_eq!(
            ManagementKeyMaterial::parse("owlrora_mgmt_v1.AA.AA").unwrap_err(),
            ManagementKeyParseError::InsufficientEntropy
        );
    }

    #[test]
    fn seed_and_durable_domains_are_distinct() {
        let key = generate_management_key();
        assert_ne!(seed_admin_key_version_id(&key), management_key_digest(&key));
    }

    #[test]
    fn debug_output_is_redacted() {
        let key = generate_management_key();
        let raw = key.expose_once();
        let debug = format!("{key:?}");
        assert!(!debug.contains(&raw));
        assert!(debug.contains("REDACTED"));
    }
}
