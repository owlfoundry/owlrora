use std::sync::Arc;

use chacha20poly1305::{
    KeyInit as _, XChaCha20Poly1305, XNonce,
    aead::{Aead as _, Payload},
};
use hkdf::Hkdf;
use rand::RngCore as _;
use sha2::Sha256;
use thiserror::Error;

use owlrora_key_provider::{OpaqueEnvelope, ProtectionContext, SecretPlaintext};

use crate::config::SecretRoot;

const MAGIC: &[u8; 4] = b"ORSE";
const FORMAT_VERSION: u8 = 1;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = MAGIC.len() + 1 + NONCE_LEN;
const HKDF_SALT: &[u8] = b"owlrora/configuration-secret/hkdf-salt/v1";
const HKDF_INFO: &[u8] = b"owlrora/configuration-secret/software-xchacha20-poly1305-v1/key";

pub struct SoftwareSecretService {
    cipher: XChaCha20Poly1305,
    _root: Arc<SecretRoot>,
}

impl std::fmt::Debug for SoftwareSecretService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SoftwareSecretService([REDACTED])")
    }
}

#[derive(Debug, Error)]
pub enum SoftwareSecretError {
    #[error("configuration secret envelope has an unsupported format")]
    UnsupportedFormat,
    #[error("configuration secret envelope failed authentication")]
    AuthenticationFailed,
    #[error("configuration secret value is invalid")]
    InvalidValue,
    #[error("configuration secret key derivation failed")]
    KeyDerivationFailed,
}

impl SoftwareSecretService {
    pub fn new(root: Arc<SecretRoot>) -> Result<Self, SoftwareSecretError> {
        let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), root.expose());
        let mut key = [0_u8; 32];
        hkdf.expand(HKDF_INFO, &mut key)
            .map_err(|_| SoftwareSecretError::KeyDerivationFailed)?;
        let cipher = XChaCha20Poly1305::new((&key).into());
        key.fill(0);
        Ok(Self {
            cipher,
            _root: root,
        })
    }

    pub fn seal(
        &self,
        context: &ProtectionContext,
        plaintext: &SecretPlaintext,
    ) -> Result<OpaqueEnvelope, SoftwareSecretError> {
        let mut nonce = [0_u8; NONCE_LEN];
        rand::rng().fill_bytes(&mut nonce);
        let ciphertext = plaintext
            .expose(|bytes| {
                self.cipher.encrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: bytes,
                        aad: context.canonical_bytes(),
                    },
                )
            })
            .map_err(|_| SoftwareSecretError::AuthenticationFailed)?;
        let mut envelope = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        envelope.extend_from_slice(MAGIC);
        envelope.push(FORMAT_VERSION);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);
        OpaqueEnvelope::new(envelope).map_err(|_| SoftwareSecretError::InvalidValue)
    }

    pub fn open(
        &self,
        context: &ProtectionContext,
        envelope: &OpaqueEnvelope,
    ) -> Result<SecretPlaintext, SoftwareSecretError> {
        let plaintext = envelope.expose(|bytes| {
            if bytes.len() <= HEADER_LEN
                || bytes.get(..MAGIC.len()) != Some(MAGIC)
                || bytes.get(MAGIC.len()) != Some(&FORMAT_VERSION)
            {
                return Err(SoftwareSecretError::UnsupportedFormat);
            }
            let nonce = bytes
                .get(MAGIC.len() + 1..HEADER_LEN)
                .ok_or(SoftwareSecretError::UnsupportedFormat)?;
            let ciphertext = bytes
                .get(HEADER_LEN..)
                .ok_or(SoftwareSecretError::UnsupportedFormat)?;
            self.cipher
                .decrypt(
                    XNonce::from_slice(nonce),
                    Payload {
                        msg: ciphertext,
                        aad: context.canonical_bytes(),
                    },
                )
                .map_err(|_| SoftwareSecretError::AuthenticationFailed)
        })?;
        SecretPlaintext::new(plaintext).map_err(|_| SoftwareSecretError::InvalidValue)
    }
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use owlrora_key_provider::{
        ContextVersion, FieldPurpose, InstallationId, MaterialId, OrganizationId, OwnerId,
        OwnerKind, ProtectionContextParts, ProviderFormatVersion, ProviderId, SecretScope,
    };

    use super::*;

    fn context(organization: &str) -> ProtectionContext {
        ProtectionContext::new(ProtectionContextParts {
            version: ContextVersion::V1,
            installation_id: InstallationId::new("installation_01").unwrap(),
            scope: SecretScope::Organization(OrganizationId::new(organization).unwrap()),
            material_id: MaterialId::new("material_01").unwrap(),
            owner_kind: OwnerKind::new("identity_issuer").unwrap(),
            owner_id: OwnerId::new("issuer_01").unwrap(),
            owner_generation: 1,
            secret_version: 1,
            field_purpose: FieldPurpose::new("oidc_client_secret").unwrap(),
            provider_id: ProviderId::new("software-xchacha20-poly1305").unwrap(),
            provider_format_version: ProviderFormatVersion::new(1).unwrap(),
        })
        .unwrap()
    }

    fn service(byte: u8) -> SoftwareSecretService {
        let encoded = URL_SAFE_NO_PAD.encode([byte; 32]);
        let root_bytes: [u8; 32] = URL_SAFE_NO_PAD.decode(encoded).unwrap().try_into().unwrap();
        SoftwareSecretService::new(Arc::new(SecretRoot::from_bytes(root_bytes))).unwrap()
    }

    #[test]
    fn round_trip_uses_fresh_nonces_and_redacted_types() {
        let service = service(1);
        let context = context("organization_01");
        let plaintext = SecretPlaintext::new(b"client-secret".to_vec()).unwrap();
        let first = service.seal(&context, &plaintext).unwrap();
        let second = service.seal(&context, &plaintext).unwrap();
        assert_ne!(first.expose(<[u8]>::to_vec), second.expose(<[u8]>::to_vec));
        let opened = service.open(&context, &first).unwrap();
        assert!(opened.expose(|value| value == b"client-secret"));
        assert!(!format!("{first:?}").contains("client-secret"));
    }

    #[test]
    fn wrong_root_context_and_tamper_fail_authentication() {
        let first = service(1);
        let second = service(2);
        let original_context = context("organization_01");
        let other_context = context("organization_02");
        let plaintext = SecretPlaintext::new(b"client-secret".to_vec()).unwrap();
        let envelope = first.seal(&original_context, &plaintext).unwrap();
        assert!(second.open(&original_context, &envelope).is_err());
        assert!(first.open(&other_context, &envelope).is_err());

        let mut bytes = envelope.expose(<[u8]>::to_vec);
        let last = bytes.last_mut().unwrap();
        *last ^= 1;
        let tampered = OpaqueEnvelope::new(bytes).unwrap();
        assert!(first.open(&original_context, &tampered).is_err());
    }
}
