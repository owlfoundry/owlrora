use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::{
    adapters::provider::wire::{WireError, adapt_provider_body},
    domain::{IngressProtocolFamily, StateIsolationMode, StateIsolationProfile},
    protocols::NativeRequest,
};

use super::{AdmissionContext, Candidate, GatewayPrincipal};

pub(super) fn prepare_body(
    admission: &AdmissionContext,
    candidate: &Candidate,
    native: &NativeRequest,
    maximum_output: u64,
) -> Result<Vec<u8>, WireError> {
    let profile: StateIsolationProfile =
        serde_json::from_value(candidate.deployment.state_isolation_profile.clone())
            .map_err(|_| WireError::Framing)?;
    let dedicated = profile.mode == StateIsolationMode::OrganizationDedicated
        && profile.valid_for(candidate.deployment.scope)
        && candidate.deployment.organization_id == Some(admission.organization.id);
    if has_semantic_reference(native.family, &native.envelope) && !dedicated {
        return Err(WireError::Framing);
    }
    let mut isolated = native.clone();
    if matches!(
        native.family,
        IngressProtocolFamily::OpenaiChatCompletions | IngressProtocolFamily::OpenaiResponses
    ) && let Some(value) = isolated.envelope.get_mut("prompt_cache_key")
    {
        let caller = value
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or(WireError::Framing)?;
        *value = Value::String(namespaced_key(&[
            "owlrora:provider-opaque-key:v1",
            &admission.organization.id.to_string(),
            match admission.principal {
                GatewayPrincipal::GatewayKey { .. } => "gateway_key",
                GatewayPrincipal::LocalUser { .. } => "local_user",
            },
            &admission.principal.affinity_uuid().to_string(),
            &admission.route.id.to_string(),
            "prompt_cache_key",
            caller,
        ]));
    }
    adapt_provider_body(
        &isolated,
        candidate.deployment.transport_kind,
        &candidate.deployment.upstream_model_id,
        maximum_output,
    )
}

fn namespaced_key(parts: &[&str]) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part.as_bytes());
    }
    format!("{:x}", digest.finalize())
}

/// Only inspect native resource slots, never arbitrary prompt/tool/schema objects.
pub(super) fn has_semantic_reference(family: IngressProtocolFamily, body: &Value) -> bool {
    let present = |field: &str| body.get(field).is_some_and(|value| !value.is_null());
    match family {
        IngressProtocolFamily::GoogleGemini => present("cachedContent"),
        IngressProtocolFamily::AnthropicMessages => {
            present("container")
                || items(body.get("messages"))
                    .any(|message| content_has_file(message.get("content")))
        }
        IngressProtocolFamily::OpenaiChatCompletions => {
            items(body.get("messages")).any(|message| content_has_file(message.get("content")))
        }
        IngressProtocolFamily::OpenaiResponses => {
            present("conversation")
                || present("container")
                || items(body.get("input")).any(|item| {
                    item.get("type").and_then(Value::as_str) == Some("item_reference")
                        || content_has_file(item.get("content"))
                        || item.get("file_id").is_some()
                })
                || items(body.get("tools")).any(|tool| {
                    match tool.get("type").and_then(Value::as_str) {
                        Some("file_search") => tool.get("vector_store_ids").is_some(),
                        Some("code_interpreter") => {
                            tool.get("container").is_some_and(|container| {
                                container.is_string() || container.get("file_ids").is_some()
                            })
                        }
                        _ => false,
                    }
                })
        }
    }
}

fn items(value: Option<&Value>) -> impl Iterator<Item = &Value> {
    value.and_then(Value::as_array).into_iter().flatten()
}

fn content_has_file(content: Option<&Value>) -> bool {
    items(content).any(|block| {
        block.get("file_id").is_some()
            || block
                .get("file")
                .is_some_and(|file| file.get("file_id").is_some())
            || block
                .get("source")
                .is_some_and(|source| source.get("file_id").is_some())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn opaque_namespaces_bind_every_component_without_delimiter_collisions() {
        let scope = [
            "domain",
            "organization",
            "gateway_key",
            "principal",
            "route",
            "field",
            "caller",
        ];
        let expected = namespaced_key(&scope);
        assert_eq!(expected.len(), 64);
        assert_eq!(expected, namespaced_key(&scope));
        for index in 0..scope.len() {
            let mut other = scope;
            other[index] = "other";
            assert_ne!(expected, namespaced_key(&other));
        }
        assert_ne!(namespaced_key(&["a", "bc"]), namespaced_key(&["ab", "c"]));
    }

    #[test]
    fn semantic_resources_are_distinct_from_inline_content_and_continuations() {
        for body in [
            json!({"conversation":"conv_1"}),
            json!({"tools":[{"type":"code_interpreter","container":{"type":"auto","file_ids":["file_1"]}}]}),
            json!({"input":[{"type":"item_reference","id":"item_1"}]}),
            json!({"tools":[{"type":"file_search","vector_store_ids":["vs_1"]}]}),
            json!({"input":[{"content":[{"type":"input_file","file_id":"file_1"}]}]}),
        ] {
            assert!(has_semantic_reference(
                IngressProtocolFamily::OpenaiResponses,
                &body
            ));
        }
        assert!(has_semantic_reference(
            IngressProtocolFamily::GoogleGemini,
            &json!({"cachedContent":"cachedContents/1"})
        ));
        assert!(!has_semantic_reference(
            IngressProtocolFamily::OpenaiResponses,
            &json!({
                "previous_response_id":"resp_1", "input":"conversation file_id", "prompt_cache_key":"x",
                "tools":[{"type":"function","parameters":{"properties":{"file_id":{"type":"string"}}}}]
            })
        ));
        assert!(!has_semantic_reference(
            IngressProtocolFamily::AnthropicMessages,
            &json!({
                "messages":[{"content":[{"type":"text","text":"x","cache_control":{"type":"ephemeral"}}]}]
            })
        ));
    }

    #[test]
    fn dedicated_profile_is_closed_and_never_authorizes_shared_deployments() {
        let profile: StateIsolationProfile =
            serde_json::from_value(json!({"mode":"organization_dedicated"})).unwrap();
        assert!(profile.valid_for(crate::domain::CatalogScopeKind::Organization));
        assert!(!profile.valid_for(crate::domain::CatalogScopeKind::Deployment));
        assert!(
            serde_json::from_value::<StateIsolationProfile>(json!({"dedicated":true})).is_err()
        );
    }
}
