#![forbid(unsafe_code)]

//! Provider-neutral configuration-secret custody capabilities for `OwlRora`.
//!
//! These contracts are intended for trusted implementations that are statically composed into a
//! custom server binary through `owlrora_server::ServerBuilder`. This crate owns only bounded
//! values and exact-context seal/open contracts; it owns no `OwlRora` policy, persistence, HTTP,
//! configuration parsing, or vendor integration.

mod context;
mod error;
mod secrets;
mod values;

pub use context::{
    ContextVersion, FieldPurpose, InstallationId, MaterialId, OrganizationId, OwnerId, OwnerKind,
    ProtectionContext, ProtectionContextParts, SecretScope,
};
pub use error::{
    ProviderError, ProviderErrorClass, ProviderErrorCode, RetryClassification, ValueError,
};
pub use secrets::{
    ConfigurationSecretOpener, ConfigurationSecretSealer, OpenSecretRequest, SealSecretRequest,
    SealedSecret, SecretPlaintext,
};
pub use values::{OpaqueEnvelope, ProviderFormatVersion, ProviderFormatVersions, ProviderId};

/// Re-exported object-safe async trait convention for provider implementations.
pub use async_trait::async_trait;
