use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use super::LlmFeatureCapability;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogScopeKind {
    Deployment,
    Organization,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    StaticApiKey,
    OauthOpenaiCodex,
    AwsDefaultChain,
    AwsAssumeRole,
    GoogleApplicationDefault,
    GoogleServiceAccount,
    AzureApiKey,
    AzureWorkloadIdentity,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialSourceKind {
    EncryptedDatabase,
    EnvironmentReference,
    MountedFileReference,
    WorkloadIdentity,
}

impl CredentialKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StaticApiKey => "static_api_key",
            Self::OauthOpenaiCodex => "oauth_openai_codex",
            Self::AwsDefaultChain => "aws_default_chain",
            Self::AwsAssumeRole => "aws_assume_role",
            Self::GoogleApplicationDefault => "google_application_default",
            Self::GoogleServiceAccount => "google_service_account",
            Self::AzureApiKey => "azure_api_key",
            Self::AzureWorkloadIdentity => "azure_workload_identity",
        }
    }
}

impl CredentialSourceKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EncryptedDatabase => "encrypted_database",
            Self::EnvironmentReference => "environment_reference",
            Self::MountedFileReference => "mounted_file_reference",
            Self::WorkloadIdentity => "workload_identity",
        }
    }

    #[must_use]
    pub const fn organization_self_service_allowed(self) -> bool {
        matches!(self, Self::EncryptedDatabase)
    }
}

impl CredentialKind {
    #[must_use]
    pub const fn organization_self_service_allowed(self) -> bool {
        matches!(self, Self::StaticApiKey | Self::AzureApiKey)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointAdapterKind {
    AnthropicApi,
    AwsBedrockRuntime,
    GoogleVertex,
    GoogleGeminiApi,
    OpenaiApi,
    OpenaiCodex,
    AzureOpenai,
}

impl EndpointAdapterKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AnthropicApi => "anthropic_api",
            Self::AwsBedrockRuntime => "aws_bedrock_runtime",
            Self::GoogleVertex => "google_vertex",
            Self::GoogleGeminiApi => "google_gemini_api",
            Self::OpenaiApi => "openai_api",
            Self::OpenaiCodex => "openai_codex",
            Self::AzureOpenai => "azure_openai",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    AnthropicMessagesNative,
    AnthropicMessagesBedrock,
    AnthropicMessagesVertex,
    OpenaiChatCompletions,
    OpenaiResponsesHttp,
    OpenaiResponsesWebsocket,
    OpenaiCodexResponses,
    AzureOpenaiChatCompletions,
    AzureOpenaiResponses,
    GoogleGeminiGenerateContent,
    GoogleVertexGenerateContent,
}

impl TransportKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AnthropicMessagesNative => "anthropic_messages_native",
            Self::AnthropicMessagesBedrock => "anthropic_messages_bedrock",
            Self::AnthropicMessagesVertex => "anthropic_messages_vertex",
            Self::OpenaiChatCompletions => "openai_chat_completions",
            Self::OpenaiResponsesHttp => "openai_responses_http",
            Self::OpenaiResponsesWebsocket => "openai_responses_websocket",
            Self::OpenaiCodexResponses => "openai_codex_responses",
            Self::AzureOpenaiChatCompletions => "azure_openai_chat_completions",
            Self::AzureOpenaiResponses => "azure_openai_responses",
            Self::GoogleGeminiGenerateContent => "google_gemini_generate_content",
            Self::GoogleVertexGenerateContent => "google_vertex_generate_content",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IngressProtocolFamily {
    AnthropicMessages,
    OpenaiChatCompletions,
    OpenaiResponses,
    GoogleGemini,
}

impl IngressProtocolFamily {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AnthropicMessages => "anthropic_messages",
            Self::OpenaiChatCompletions => "openai_chat_completions",
            Self::OpenaiResponses => "openai_responses",
            Self::GoogleGemini => "google_gemini",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompatibilityTuple {
    pub ingress: IngressProtocolFamily,
    pub endpoint: EndpointAdapterKind,
    pub credential: CredentialKind,
    pub transport: TransportKind,
    pub supports_http: bool,
    pub supports_streaming: bool,
    pub supports_websocket: bool,
}

pub const COMPATIBILITY_REGISTRY_V1: &[CompatibilityTuple] = &[
    tuple(
        IngressProtocolFamily::AnthropicMessages,
        EndpointAdapterKind::AnthropicApi,
        CredentialKind::StaticApiKey,
        TransportKind::AnthropicMessagesNative,
        true,
        true,
        false,
    ),
    tuple(
        IngressProtocolFamily::AnthropicMessages,
        EndpointAdapterKind::AwsBedrockRuntime,
        CredentialKind::AwsDefaultChain,
        TransportKind::AnthropicMessagesBedrock,
        true,
        true,
        false,
    ),
    tuple(
        IngressProtocolFamily::AnthropicMessages,
        EndpointAdapterKind::AwsBedrockRuntime,
        CredentialKind::AwsAssumeRole,
        TransportKind::AnthropicMessagesBedrock,
        true,
        true,
        false,
    ),
    tuple(
        IngressProtocolFamily::AnthropicMessages,
        EndpointAdapterKind::GoogleVertex,
        CredentialKind::GoogleApplicationDefault,
        TransportKind::AnthropicMessagesVertex,
        true,
        true,
        false,
    ),
    tuple(
        IngressProtocolFamily::AnthropicMessages,
        EndpointAdapterKind::GoogleVertex,
        CredentialKind::GoogleServiceAccount,
        TransportKind::AnthropicMessagesVertex,
        true,
        true,
        false,
    ),
    tuple(
        IngressProtocolFamily::OpenaiChatCompletions,
        EndpointAdapterKind::OpenaiApi,
        CredentialKind::StaticApiKey,
        TransportKind::OpenaiChatCompletions,
        true,
        true,
        false,
    ),
    tuple(
        IngressProtocolFamily::OpenaiChatCompletions,
        EndpointAdapterKind::AzureOpenai,
        CredentialKind::AzureApiKey,
        TransportKind::AzureOpenaiChatCompletions,
        true,
        true,
        false,
    ),
    tuple(
        IngressProtocolFamily::OpenaiChatCompletions,
        EndpointAdapterKind::AzureOpenai,
        CredentialKind::AzureWorkloadIdentity,
        TransportKind::AzureOpenaiChatCompletions,
        true,
        true,
        false,
    ),
    tuple(
        IngressProtocolFamily::OpenaiResponses,
        EndpointAdapterKind::OpenaiApi,
        CredentialKind::StaticApiKey,
        TransportKind::OpenaiResponsesHttp,
        true,
        true,
        false,
    ),
    tuple(
        IngressProtocolFamily::OpenaiResponses,
        EndpointAdapterKind::OpenaiApi,
        CredentialKind::StaticApiKey,
        TransportKind::OpenaiResponsesWebsocket,
        false,
        false,
        true,
    ),
    tuple(
        IngressProtocolFamily::OpenaiResponses,
        EndpointAdapterKind::OpenaiCodex,
        CredentialKind::OauthOpenaiCodex,
        TransportKind::OpenaiCodexResponses,
        true,
        true,
        false,
    ),
    tuple(
        IngressProtocolFamily::OpenaiResponses,
        EndpointAdapterKind::AzureOpenai,
        CredentialKind::AzureApiKey,
        TransportKind::AzureOpenaiResponses,
        true,
        true,
        false,
    ),
    tuple(
        IngressProtocolFamily::OpenaiResponses,
        EndpointAdapterKind::AzureOpenai,
        CredentialKind::AzureWorkloadIdentity,
        TransportKind::AzureOpenaiResponses,
        true,
        true,
        false,
    ),
    tuple(
        IngressProtocolFamily::GoogleGemini,
        EndpointAdapterKind::GoogleGeminiApi,
        CredentialKind::StaticApiKey,
        TransportKind::GoogleGeminiGenerateContent,
        true,
        true,
        false,
    ),
    tuple(
        IngressProtocolFamily::GoogleGemini,
        EndpointAdapterKind::GoogleGeminiApi,
        CredentialKind::GoogleApplicationDefault,
        TransportKind::GoogleGeminiGenerateContent,
        true,
        true,
        false,
    ),
    tuple(
        IngressProtocolFamily::GoogleGemini,
        EndpointAdapterKind::GoogleGeminiApi,
        CredentialKind::GoogleServiceAccount,
        TransportKind::GoogleGeminiGenerateContent,
        true,
        true,
        false,
    ),
    tuple(
        IngressProtocolFamily::GoogleGemini,
        EndpointAdapterKind::GoogleVertex,
        CredentialKind::GoogleApplicationDefault,
        TransportKind::GoogleVertexGenerateContent,
        true,
        true,
        false,
    ),
    tuple(
        IngressProtocolFamily::GoogleGemini,
        EndpointAdapterKind::GoogleVertex,
        CredentialKind::GoogleServiceAccount,
        TransportKind::GoogleVertexGenerateContent,
        true,
        true,
        false,
    ),
];

const fn tuple(
    ingress: IngressProtocolFamily,
    endpoint: EndpointAdapterKind,
    credential: CredentialKind,
    transport: TransportKind,
    supports_http: bool,
    supports_streaming: bool,
    supports_websocket: bool,
) -> CompatibilityTuple {
    CompatibilityTuple {
        ingress,
        endpoint,
        credential,
        transport,
        supports_http,
        supports_streaming,
        supports_websocket,
    }
}

#[must_use]
pub fn compatibility(
    ingress: IngressProtocolFamily,
    endpoint: EndpointAdapterKind,
    credential: CredentialKind,
    transport: TransportKind,
) -> Option<&'static CompatibilityTuple> {
    COMPATIBILITY_REGISTRY_V1.iter().find(|entry| {
        entry.ingress == ingress
            && entry.endpoint == endpoint
            && entry.credential == credential
            && entry.transport == transport
    })
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountingOrigin {
    SystemProvided,
    OrganizationByok,
}

impl AccountingOrigin {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SystemProvided => "system_provided",
            Self::OrganizationByok => "organization_byok",
        }
    }
}

impl CatalogScopeKind {
    #[must_use]
    pub const fn accounting_origin(self) -> AccountingOrigin {
        match self {
            Self::Deployment => AccountingOrigin::SystemProvided,
            Self::Organization => AccountingOrigin::OrganizationByok,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetMode {
    Enforce,
    RecordOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyKind {
    GatewayKeyBudget,
    OrganizationOriginBudget,
    GatewayKeyRequestLimits,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteAffinityMode {
    #[default]
    None,
    Preferred,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteSelectionPolicy {
    #[serde(default = "default_routing_algorithm")]
    pub algorithm: String,
    #[serde(default)]
    pub affinity_mode: RouteAffinityMode,
}

impl Default for RouteSelectionPolicy {
    fn default() -> Self {
        Self {
            algorithm: default_routing_algorithm(),
            affinity_mode: RouteAffinityMode::None,
        }
    }
}

impl RouteSelectionPolicy {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.algorithm == "replicated-wrh-v1"
    }
}

fn default_routing_algorithm() -> String {
    "replicated-wrh-v1".to_owned()
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRequestPolicy {
    #[serde(default = "default_max_header_bytes")]
    pub max_header_bytes: u64,
    #[serde(default = "default_max_request_body_bytes")]
    pub max_request_body_bytes: u64,
    #[serde(default = "default_max_response_body_bytes")]
    pub max_response_body_bytes: u64,
    #[serde(default = "default_max_output_units")]
    pub max_output_units: u64,
    #[serde(default = "default_max_stream_seconds")]
    pub max_stream_seconds: u32,
    #[serde(default = "default_state_origin_ttl_seconds")]
    pub state_origin_ttl_seconds: u32,
}

impl Default for RouteRequestPolicy {
    fn default() -> Self {
        Self {
            max_header_bytes: default_max_header_bytes(),
            max_request_body_bytes: default_max_request_body_bytes(),
            max_response_body_bytes: default_max_response_body_bytes(),
            max_output_units: default_max_output_units(),
            max_stream_seconds: default_max_stream_seconds(),
            state_origin_ttl_seconds: default_state_origin_ttl_seconds(),
        }
    }
}

impl RouteRequestPolicy {
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.max_header_bytes > 0
            && self.max_request_body_bytes > 0
            && self.max_response_body_bytes > 0
            && self.max_output_units > 0
            && self.max_stream_seconds > 0
            && self.state_origin_ttl_seconds > 0
    }
}

fn deserialize_present_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

fn deserialize_unique_capabilities_option<'de, D>(
    deserializer: D,
) -> Result<Option<BTreeSet<LlmFeatureCapability>>, D::Error>
where
    D: Deserializer<'de>,
{
    let capabilities = Vec::<LlmFeatureCapability>::deserialize(deserializer)?;
    let unique = capabilities.iter().copied().collect::<BTreeSet<_>>();
    if unique.len() != capabilities.len() {
        return Err(D::Error::custom(
            "allowed_capabilities must not contain duplicates",
        ));
    }
    Ok(Some(unique))
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteGrantRequestPolicyCeilings {
    #[serde(
        default,
        deserialize_with = "deserialize_present_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_header_bytes: Option<u64>,
    #[serde(
        default,
        deserialize_with = "deserialize_present_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_request_body_bytes: Option<u64>,
    #[serde(
        default,
        deserialize_with = "deserialize_present_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_response_body_bytes: Option<u64>,
    #[serde(
        default,
        deserialize_with = "deserialize_present_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_stream_seconds: Option<u32>,
    #[serde(
        default,
        deserialize_with = "deserialize_present_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub state_origin_ttl_seconds: Option<u32>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SystemRouteGrantCeilings {
    #[serde(
        default,
        deserialize_with = "deserialize_unique_capabilities_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub allowed_capabilities: Option<BTreeSet<LlmFeatureCapability>>,
    #[serde(
        default,
        deserialize_with = "deserialize_present_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_context_bytes: Option<u64>,
    #[serde(
        default,
        deserialize_with = "deserialize_present_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_output_units: Option<u64>,
    #[serde(default)]
    pub request_policy: RouteGrantRequestPolicyCeilings,
}

impl SystemRouteGrantCeilings {
    #[must_use]
    pub fn allows_capabilities(&self, required: &BTreeSet<LlmFeatureCapability>) -> bool {
        self.allowed_capabilities
            .as_ref()
            .is_none_or(|allowed| allowed.is_superset(required))
    }

    #[must_use]
    pub fn narrow_request_policy(&self, policy: &RouteRequestPolicy) -> RouteRequestPolicy {
        RouteRequestPolicy {
            max_header_bytes: self
                .request_policy
                .max_header_bytes
                .map_or(policy.max_header_bytes, |value| {
                    value.min(policy.max_header_bytes)
                }),
            max_request_body_bytes: self
                .request_policy
                .max_request_body_bytes
                .into_iter()
                .chain(self.max_context_bytes)
                .min()
                .map_or(policy.max_request_body_bytes, |value| {
                    value.min(policy.max_request_body_bytes)
                }),
            max_response_body_bytes: self
                .request_policy
                .max_response_body_bytes
                .map_or(policy.max_response_body_bytes, |value| {
                    value.min(policy.max_response_body_bytes)
                }),
            max_output_units: self
                .max_output_units
                .map_or(policy.max_output_units, |value| {
                    value.min(policy.max_output_units)
                }),
            max_stream_seconds: self
                .request_policy
                .max_stream_seconds
                .map_or(policy.max_stream_seconds, |value| {
                    value.min(policy.max_stream_seconds)
                }),
            state_origin_ttl_seconds: self
                .request_policy
                .state_origin_ttl_seconds
                .map_or(policy.state_origin_ttl_seconds, |value| {
                    value.min(policy.state_origin_ttl_seconds)
                }),
        }
    }

    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.max_context_bytes.is_none_or(|value| value > 0)
            && self.max_output_units.is_none_or(|value| value > 0)
            && [
                self.request_policy.max_header_bytes,
                self.request_policy.max_request_body_bytes,
                self.request_policy.max_response_body_bytes,
                self.request_policy.max_stream_seconds.map(u64::from),
                self.request_policy.state_origin_ttl_seconds.map(u64::from),
            ]
            .into_iter()
            .all(|value| value.is_none_or(|value| value > 0))
    }
}

const fn default_max_header_bytes() -> u64 {
    64 * 1024
}

const fn default_max_output_units() -> u64 {
    16_384
}

const fn default_max_stream_seconds() -> u32 {
    3_600
}

const fn default_state_origin_ttl_seconds() -> u32 {
    86_400
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetNarrowingConstraints {
    #[serde(default)]
    pub max_output_units: Option<u64>,
    #[serde(default)]
    pub max_context_units: Option<u64>,
}

impl TargetNarrowingConstraints {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.max_output_units.is_none_or(|value| value > 0) && self.max_context_units.is_none()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetTimeoutOverrides {
    #[serde(default)]
    pub connect_timeout_ms: Option<u64>,
    #[serde(default)]
    pub response_header_timeout_ms: Option<u64>,
    #[serde(default)]
    pub body_timeout_ms: Option<u64>,
    #[serde(default)]
    pub stream_idle_timeout_ms: Option<u64>,
}

impl TargetTimeoutOverrides {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.connect_timeout_ms
            .is_none_or(|value| (10..=120_000).contains(&value))
            && self
                .response_header_timeout_ms
                .is_none_or(|value| (10..=3_600_000).contains(&value))
            && self
                .body_timeout_ms
                .is_none_or(|value| (10..=3_600_000).contains(&value))
            && self
                .stream_idle_timeout_ms
                .is_none_or(|value| (100..=3_600_000).contains(&value))
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownEstimateMode {
    #[default]
    RequireEstimate,
    FixedUnknownReservation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetEstimatePolicy {
    #[serde(default)]
    pub unknown_mode: UnknownEstimateMode,
    #[serde(default)]
    pub fixed_unknown_reservation_nanos: Option<u128>,
    #[serde(default = "default_input_units_per_byte")]
    pub input_units_per_byte: u32,
}

impl Default for BudgetEstimatePolicy {
    fn default() -> Self {
        Self {
            unknown_mode: UnknownEstimateMode::RequireEstimate,
            fixed_unknown_reservation_nanos: None,
            input_units_per_byte: default_input_units_per_byte(),
        }
    }
}

const fn default_input_units_per_byte() -> u32 {
    1
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetAllowancePolicy {
    #[serde(default = "default_allowance_slice_nanos")]
    pub max_slice_nanos: u128,
    #[serde(default = "default_allowance_low_watermark_nanos")]
    pub low_watermark_nanos: u128,
    #[serde(default = "default_allowance_grant_seconds")]
    pub grant_seconds: u32,
    #[serde(default)]
    pub emergency_reserve_nanos: u128,
}

impl Default for BudgetAllowancePolicy {
    fn default() -> Self {
        Self {
            max_slice_nanos: default_allowance_slice_nanos(),
            low_watermark_nanos: default_allowance_low_watermark_nanos(),
            grant_seconds: default_allowance_grant_seconds(),
            emergency_reserve_nanos: 0,
        }
    }
}

const fn default_allowance_slice_nanos() -> u128 {
    100_000_000
}

const fn default_allowance_low_watermark_nanos() -> u128 {
    10_000_000
}

const fn default_allowance_grant_seconds() -> u32 {
    30
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoordinationFailureMode {
    #[default]
    Deny,
    BoundedLocal,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetFailurePolicy {
    #[serde(default)]
    pub coordination_failure_mode: CoordinationFailureMode,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetRecoveryPolicy {
    #[serde(default)]
    pub require_verified_state_loss: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RateGrantPolicy {
    #[serde(default = "default_rate_grant_tokens")]
    pub max_request_tokens: u32,
    #[serde(default = "default_rate_grant_seconds")]
    pub grant_seconds: u32,
}

impl Default for RateGrantPolicy {
    fn default() -> Self {
        Self {
            max_request_tokens: default_rate_grant_tokens(),
            grant_seconds: default_rate_grant_seconds(),
        }
    }
}

const fn default_rate_grant_tokens() -> u32 {
    32
}

const fn default_rate_grant_seconds() -> u32 {
    10
}

impl PolicyKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GatewayKeyBudget => "gateway_key_budget",
            Self::OrganizationOriginBudget => "organization_origin_budget",
            Self::GatewayKeyRequestLimits => "gateway_key_request_limits",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EgressDnsPolicy {
    #[serde(default = "default_dns_revalidate_on_connect")]
    pub revalidate_on_connect: bool,
    #[serde(default = "default_max_resolved_addresses")]
    pub max_resolved_addresses: u8,
}

const fn default_dns_revalidate_on_connect() -> bool {
    true
}

const fn default_max_resolved_addresses() -> u8 {
    16
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EgressAddressPolicy {
    #[serde(default)]
    pub allow_private: bool,
    #[serde(default)]
    pub allow_loopback: bool,
    #[serde(default)]
    pub allow_link_local: bool,
    #[serde(default)]
    pub allow_metadata: bool,
    #[serde(default)]
    pub allowed_cidrs: Vec<String>,
    #[serde(default)]
    pub denied_cidrs: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EgressTlsPolicy {
    #[serde(default = "default_tls_verify")]
    pub verify_hostname: bool,
    #[serde(default = "default_tls_verify")]
    pub verify_certificate: bool,
    #[serde(default = "default_minimum_tls_version")]
    pub minimum_version: String,
}

const fn default_tls_verify() -> bool {
    true
}

fn default_minimum_tls_version() -> String {
    "1.2".to_owned()
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EgressRedirectPolicy {
    #[serde(default)]
    pub max_redirects: u8,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EgressConnectionPolicy {
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u32,
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u32,
    #[serde(default = "default_idle_timeout_ms")]
    pub pool_idle_timeout_ms: u32,
    #[serde(default = "default_idle_connections_per_host")]
    pub max_idle_connections_per_host: usize,
}

const fn default_connect_timeout_ms() -> u32 {
    10_000
}

const fn default_request_timeout_ms() -> u32 {
    120_000
}

const fn default_idle_timeout_ms() -> u32 {
    90_000
}

const fn default_idle_connections_per_host() -> usize {
    16
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EgressBodyPolicy {
    #[serde(default = "default_max_request_body_bytes")]
    pub max_request_body_bytes: u64,
    #[serde(default = "default_max_response_body_bytes")]
    pub max_response_body_bytes: u64,
}

const fn default_max_request_body_bytes() -> u64 {
    16 * 1024 * 1024
}

const fn default_max_response_body_bytes() -> u64 {
    64 * 1024 * 1024
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EgressNetworkConfiguration {
    #[serde(default)]
    pub dns: EgressDnsPolicy,
    #[serde(default)]
    pub address: EgressAddressPolicy,
    pub proxy_url: Option<String>,
    #[serde(default)]
    pub tls: EgressTlsPolicy,
    #[serde(default)]
    pub redirect: EgressRedirectPolicy,
    #[serde(default)]
    pub connection: EgressConnectionPolicy,
    #[serde(default)]
    pub body: EgressBodyPolicy,
    pub custom_ca_secret_id: Option<uuid::Uuid>,
    pub custom_ca_generation: u64,
    pub config_version: u64,
}

impl Default for EgressDnsPolicy {
    fn default() -> Self {
        Self {
            revalidate_on_connect: default_dns_revalidate_on_connect(),
            max_resolved_addresses: default_max_resolved_addresses(),
        }
    }
}

impl Default for EgressTlsPolicy {
    fn default() -> Self {
        Self {
            verify_hostname: true,
            verify_certificate: true,
            minimum_version: default_minimum_tls_version(),
        }
    }
}

impl Default for EgressConnectionPolicy {
    fn default() -> Self {
        Self {
            connect_timeout_ms: default_connect_timeout_ms(),
            request_timeout_ms: default_request_timeout_ms(),
            pool_idle_timeout_ms: default_idle_timeout_ms(),
            max_idle_connections_per_host: default_idle_connections_per_host(),
        }
    }
}

impl Default for EgressBodyPolicy {
    fn default() -> Self {
        Self {
            max_request_body_bytes: default_max_request_body_bytes(),
            max_response_body_bytes: default_max_response_body_bytes(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PricingRates {
    pub currency: String,
    pub cost_nanos_per_unit: BTreeMap<String, u64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PricingRoundingMode {
    Up,
    Nearest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PricingRoundingPolicy {
    pub mode: PricingRoundingMode,
    pub quantum_units: u64,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn registry_has_no_duplicate_exact_tuple() {
        let tuples = COMPATIBILITY_REGISTRY_V1
            .iter()
            .map(|entry| {
                (
                    entry.ingress,
                    entry.endpoint,
                    entry.credential,
                    entry.transport,
                )
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(tuples.len(), COMPATIBILITY_REGISTRY_V1.len());
    }

    #[test]
    fn codex_is_responses_http_only() {
        let codex = compatibility(
            IngressProtocolFamily::OpenaiResponses,
            EndpointAdapterKind::OpenaiCodex,
            CredentialKind::OauthOpenaiCodex,
            TransportKind::OpenaiCodexResponses,
        )
        .unwrap();
        assert!(codex.supports_http && codex.supports_streaming);
        assert!(!codex.supports_websocket);
        assert!(
            compatibility(
                IngressProtocolFamily::OpenaiResponses,
                EndpointAdapterKind::OpenaiCodex,
                CredentialKind::OauthOpenaiCodex,
                TransportKind::OpenaiResponsesWebsocket,
            )
            .is_none()
        );
    }

    #[test]
    fn scope_derives_origin_without_caller_input() {
        assert_eq!(
            CatalogScopeKind::Deployment.accounting_origin(),
            AccountingOrigin::SystemProvided
        );
        assert_eq!(
            CatalogScopeKind::Organization.accounting_origin(),
            AccountingOrigin::OrganizationByok
        );
    }

    #[test]
    fn system_route_grant_ceilings_only_narrow_route_authority() {
        let route_policy = RouteRequestPolicy {
            max_header_bytes: 1024,
            max_request_body_bytes: 2048,
            max_response_body_bytes: 4096,
            max_output_units: 512,
            max_stream_seconds: 120,
            state_origin_ttl_seconds: 300,
        };
        let ceilings = SystemRouteGrantCeilings {
            allowed_capabilities: Some(BTreeSet::from([
                LlmFeatureCapability::Streaming,
                LlmFeatureCapability::Tools,
            ])),
            max_context_bytes: Some(1024),
            max_output_units: Some(128),
            request_policy: RouteGrantRequestPolicyCeilings {
                max_header_bytes: Some(2048),
                max_request_body_bytes: Some(1536),
                max_response_body_bytes: Some(1024),
                max_stream_seconds: Some(60),
                state_origin_ttl_seconds: Some(600),
            },
        };

        assert!(ceilings.is_valid());
        assert!(ceilings.allows_capabilities(&BTreeSet::from([
            LlmFeatureCapability::Streaming,
            LlmFeatureCapability::Tools,
        ])));
        assert!(!ceilings.allows_capabilities(&BTreeSet::from([
            LlmFeatureCapability::Streaming,
            LlmFeatureCapability::ImageInput,
        ])));
        assert_eq!(
            ceilings.narrow_request_policy(&route_policy),
            RouteRequestPolicy {
                max_header_bytes: 1024,
                max_request_body_bytes: 1024,
                max_response_body_bytes: 1024,
                max_output_units: 128,
                max_stream_seconds: 60,
                state_origin_ttl_seconds: 300,
            }
        );

        let invalid = SystemRouteGrantCeilings {
            max_output_units: Some(0),
            ..SystemRouteGrantCeilings::default()
        };
        assert!(!invalid.is_valid());
    }

    #[test]
    fn system_route_grant_ceilings_reject_explicit_nulls_and_duplicates() {
        for value in [
            serde_json::json!({"allowed_capabilities":null}),
            serde_json::json!({"max_context_bytes":null}),
            serde_json::json!({"max_output_units":null}),
            serde_json::json!({"request_policy":{"max_header_bytes":null}}),
            serde_json::json!({"request_policy":{"max_request_body_bytes":null}}),
            serde_json::json!({"request_policy":{"max_response_body_bytes":null}}),
            serde_json::json!({"request_policy":{"max_stream_seconds":null}}),
            serde_json::json!({"request_policy":{"state_origin_ttl_seconds":null}}),
            serde_json::json!({"allowed_capabilities":["streaming","streaming"]}),
        ] {
            assert!(
                serde_json::from_value::<SystemRouteGrantCeilings>(value.clone()).is_err(),
                "unexpectedly accepted {value}"
            );
        }
        assert_eq!(
            serde_json::from_value::<SystemRouteGrantCeilings>(serde_json::json!({})).unwrap(),
            SystemRouteGrantCeilings::default()
        );
    }
}
