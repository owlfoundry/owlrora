use std::{collections::BTreeSet, fmt, str::FromStr};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

const PREFIX: &str = "owlrora_llm_v1";
const LOOKUP_BYTES: usize = 16;
const SECRET_BYTES: usize = 32;
const MAX_LOOKUP_BYTES: usize = 32;
const MAX_SECRET_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LlmScope {
    Invoke,
    Stream,
    Tools,
    MultimodalInput,
    StructuredOutput,
}

impl LlmScope {
    pub const ALL: [Self; 5] = [
        Self::Invoke,
        Self::Stream,
        Self::Tools,
        Self::MultimodalInput,
        Self::StructuredOutput,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Invoke => "llm:invoke",
            Self::Stream => "llm:stream",
            Self::Tools => "llm:tools",
            Self::MultimodalInput => "llm:multimodal-input",
            Self::StructuredOutput => "llm:structured-output",
        }
    }
}

impl fmt::Display for LlmScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for LlmScope {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|scope| scope.as_str() == value)
            .ok_or_else(|| format!("unknown LLM scope: {value}"))
    }
}

impl Serialize for LlmScope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for LlmScope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct LlmScopeSet(BTreeSet<LlmScope>);

impl<'de> Deserialize<'de> for LlmScopeSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = Vec::<LlmScope>::deserialize(deserializer)?;
        let scopes = values.iter().copied().collect::<BTreeSet<_>>();
        if scopes.len() != values.len() {
            return Err(de::Error::custom("duplicate LLM scope"));
        }
        Self::new(scopes).map_err(de::Error::custom)
    }
}

impl LlmScopeSet {
    pub fn new(scopes: impl IntoIterator<Item = LlmScope>) -> Result<Self, String> {
        let scopes = scopes.into_iter().collect::<BTreeSet<_>>();
        if !scopes.contains(&LlmScope::Invoke) {
            return Err("llm:invoke is required".to_owned());
        }
        Ok(Self(scopes))
    }

    #[must_use]
    pub fn contains(&self, scope: LlmScope) -> bool {
        self.0.contains(&scope)
    }

    #[must_use]
    pub fn is_superset(&self, other: &Self) -> bool {
        self.0.is_superset(&other.0)
    }

    #[must_use]
    pub fn intersection(&self, other: &Self) -> Option<Self> {
        let scopes = self
            .0
            .intersection(&other.0)
            .copied()
            .collect::<BTreeSet<_>>();
        scopes.contains(&LlmScope::Invoke).then_some(Self(scopes))
    }

    pub fn iter(&self) -> impl Iterator<Item = LlmScope> + '_ {
        self.0.iter().copied()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LlmScopeCeiling(Option<LlmScopeSet>);

impl Serialize for LlmScopeCeiling {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match &self.0 {
            Some(scopes) => scopes.serialize(serializer),
            None => BTreeSet::<LlmScope>::new().serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for LlmScopeCeiling {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = Vec::<LlmScope>::deserialize(deserializer)?;
        let scopes = values.iter().copied().collect::<BTreeSet<_>>();
        if scopes.len() != values.len() {
            return Err(de::Error::custom("duplicate LLM scope"));
        }
        if scopes.is_empty() {
            Ok(Self::denied())
        } else {
            LlmScopeSet::new(scopes)
                .map(|scopes| Self(Some(scopes)))
                .map_err(de::Error::custom)
        }
    }
}

impl LlmScopeCeiling {
    #[must_use]
    pub const fn denied() -> Self {
        Self(None)
    }

    #[must_use]
    pub fn from_scopes(scopes: LlmScopeSet) -> Self {
        Self(Some(scopes))
    }

    #[must_use]
    pub fn as_scopes(&self) -> Option<&LlmScopeSet> {
        self.0.as_ref()
    }

    #[must_use]
    pub fn allows(&self, required: &LlmScopeSet) -> bool {
        self.0
            .as_ref()
            .is_some_and(|ceiling| ceiling.is_superset(required))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LlmFeatureCapability {
    Streaming,
    Tools,
    ParallelTools,
    ImageInput,
    AudioInput,
    DocumentInput,
    StructuredOutput,
    JsonSchema,
    PromptCaching,
    SystemInstructions,
    DeveloperInstructions,
    ReasoningControls,
    OpaqueReasoningState,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct GatewayKeyMaterial {
    lookup: Vec<u8>,
    secret: Vec<u8>,
}

impl fmt::Debug for GatewayKeyMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GatewayKeyMaterial([REDACTED])")
    }
}

impl GatewayKeyMaterial {
    pub fn parse(value: &str) -> Result<Self, GatewayKeyParseError> {
        let mut segments = value.split('.');
        let prefix = segments.next();
        let lookup = segments.next();
        let secret = segments.next();
        if segments.next().is_some() || prefix != Some(PREFIX) {
            return Err(GatewayKeyParseError::InvalidFormat);
        }
        let lookup_text = lookup.ok_or(GatewayKeyParseError::InvalidFormat)?;
        let secret_text = secret.ok_or(GatewayKeyParseError::InvalidFormat)?;
        if lookup_text.contains('=') || secret_text.contains('=') {
            return Err(GatewayKeyParseError::NonCanonicalEncoding);
        }
        let lookup = URL_SAFE_NO_PAD
            .decode(lookup_text)
            .map_err(|_| GatewayKeyParseError::InvalidEncoding)?;
        let secret = URL_SAFE_NO_PAD
            .decode(secret_text)
            .map_err(|_| GatewayKeyParseError::InvalidEncoding)?;
        if !(LOOKUP_BYTES..=MAX_LOOKUP_BYTES).contains(&lookup.len())
            || !(SECRET_BYTES..=MAX_SECRET_BYTES).contains(&secret.len())
        {
            return Err(GatewayKeyParseError::InsufficientEntropy);
        }
        if URL_SAFE_NO_PAD.encode(&lookup) != lookup_text
            || URL_SAFE_NO_PAD.encode(&secret) != secret_text
        {
            return Err(GatewayKeyParseError::NonCanonicalEncoding);
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
                .expect("Gateway key lookup length is bounded")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&self.lookup);
        bytes.extend_from_slice(
            &u16::try_from(self.secret.len())
                .expect("Gateway key secret length is bounded")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&self.secret);
        bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GatewayKeyParseError {
    #[error("gateway key has an invalid format")]
    InvalidFormat,
    #[error("gateway key has invalid base64url encoding")]
    InvalidEncoding,
    #[error("gateway key encoding is not canonical")]
    NonCanonicalEncoding,
    #[error("gateway key does not contain the required entropy")]
    InsufficientEntropy,
}

#[must_use]
pub fn generate_gateway_key() -> GatewayKeyMaterial {
    let mut lookup = vec![0_u8; LOOKUP_BYTES];
    let mut secret = vec![0_u8; SECRET_BYTES];
    rand::rng().fill_bytes(&mut lookup);
    rand::rng().fill_bytes(&mut secret);
    GatewayKeyMaterial { lookup, secret }
}

#[must_use]
pub fn gateway_key_digest(material: &GatewayKeyMaterial) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"owlrora/gateway-api-key/durable/v1\0");
    digest.update(material.canonical_decoded_bytes());
    digest.finalize().into()
}

#[must_use]
pub fn constant_time_gateway_digest_matches(left: &[u8; 32], right: &[u8; 32]) -> bool {
    bool::from(left.ct_eq(right))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::ManagementKeyMaterial;

    #[test]
    fn scope_set_is_closed_and_requires_invoke() {
        assert!(LlmScopeSet::new([LlmScope::Invoke, LlmScope::Stream]).is_ok());
        assert!(LlmScopeSet::new([LlmScope::Stream]).is_err());
        assert!("llm:*".parse::<LlmScope>().is_err());
        assert!(serde_json::from_str::<LlmScopeSet>(r#"["llm:stream"]"#).is_err());
        assert!(serde_json::from_str::<LlmScopeSet>("[]").is_err());
        assert!(serde_json::from_str::<LlmScopeSet>(r#"["llm:invoke","llm:stream"]"#).is_ok());
    }

    #[test]
    fn generated_keys_round_trip_canonically() {
        let key = generate_gateway_key();
        let encoded = key.expose_once();
        let parsed = GatewayKeyMaterial::parse(&encoded).unwrap();
        assert_eq!(parsed.expose_once(), encoded);
        assert_eq!(gateway_key_digest(&parsed), gateway_key_digest(&key));
    }

    #[test]
    fn key_classes_are_rejected_by_the_opposite_parser() {
        let gateway = generate_gateway_key();
        assert!(ManagementKeyMaterial::parse(&gateway.expose_once()).is_err());
        let management = crate::domain::generate_management_key();
        assert!(GatewayKeyMaterial::parse(&management.expose_once()).is_err());
    }

    #[test]
    fn parser_rejects_padding_and_short_values() {
        assert_eq!(
            GatewayKeyMaterial::parse("owlrora_llm_v1.AA=.AA=").unwrap_err(),
            GatewayKeyParseError::NonCanonicalEncoding
        );
        assert_eq!(
            GatewayKeyMaterial::parse("owlrora_llm_v1.AA.AA").unwrap_err(),
            GatewayKeyParseError::InsufficientEntropy
        );
    }

    #[test]
    fn debug_output_is_redacted() {
        let key = generate_gateway_key();
        let raw = key.expose_once();
        let debug = format!("{key:?}");
        assert!(!debug.contains(&raw));
        assert!(debug.contains("REDACTED"));
    }
}
