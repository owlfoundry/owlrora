#![allow(
    clippy::case_sensitive_file_extension_comparisons,
    clippy::struct_excessive_bools
)]

use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum OperationAuthentication {
    Public,
    Management,
    BrowserSession,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct OperationDescriptor {
    pub id: &'static str,
    pub method: &'static str,
    pub path: &'static str,
    pub authentication: OperationAuthentication,
    pub etag_precondition: bool,
    pub one_time_secret_response: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationMode {
    Query,
    Command,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationQualification {
    Public,
    Personal,
    System,
    Organization,
    Operations,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationIdempotency {
    NotApplicable,
    Supported,
    Rejected,
    StateMachine,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationSecretInputMode {
    ReplaceBody,
    MergeIntoCandidate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct OperationSecretInput {
    pub field: &'static str,
    pub mode: OperationSecretInputMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct OperationAuthorizationVariant {
    pub required_capability: &'static str,
    pub condition: Option<&'static str>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OperationQueryParameter {
    pub name: &'static str,
    pub schema: serde_json::Value,
    pub required: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CheckedOperationContract {
    pub id: &'static str,
    pub resource_family: String,
    pub method: &'static str,
    pub path: &'static str,
    pub authentication: OperationAuthentication,
    pub mode: OperationMode,
    pub qualification: OperationQualification,
    pub required_scopes: Vec<&'static str>,
    pub authorization_variants: Vec<OperationAuthorizationVariant>,
    pub request_schema: Option<serde_json::Value>,
    pub response_schema: String,
    pub paginated: bool,
    pub query_parameters: Vec<OperationQueryParameter>,
    pub etag_precondition: bool,
    pub idempotency: OperationIdempotency,
    pub client_generated_idempotency_key: bool,
    pub secret_input: Option<OperationSecretInput>,
    pub one_time_secret_response: bool,
    pub sensitive_result: bool,
    pub high_impact: bool,
    pub destructive: bool,
    pub approval_recommended: bool,
    pub cli_path: Option<String>,
    pub mcp_tool: Option<String>,
    pub mcp_toolset: Option<&'static str>,
    pub console_capability_key: Option<&'static str>,
}

impl OperationDescriptor {
    #[must_use]
    pub fn checked_contract(self) -> CheckedOperationContract {
        let mode = operation_mode(self.id, self.method);
        let qualification = operation_qualification(self.path);
        let required_scopes = operation_scopes(self.id, mode, qualification, self.authentication);
        let authorization_variants = operation_authorization_variants(self.id, mode);
        let paginated = matches!(
            self.id,
            "me.organizations.list"
                | "me.sessions.list"
                | "system.users.list"
                | "system.organizations.list"
                | "organization.memberships.list"
                | "system.management_keys.list"
                | "organization.management_keys.list"
                | "organization.invitations.list"
                | "system.identity_issuers.list"
                | "system.identity_bindings.list"
                | "system.provisioning_policies.list"
                | "system.upstream_credentials.list"
                | "organization.upstream_credentials.list"
                | "system.egress_network_policies.list"
                | "system.reliability_policies.list"
                | "system.upstream_endpoints.list"
                | "system.pricing_policies.list"
                | "system.model_deployments.list"
                | "organization.model_deployments.list"
                | "system.model_routes.list"
                | "organization.model_routes.list"
                | "organization.available_routes.list"
                | "organization.available_endpoints.list"
                | "organization.available_deployments.list"
                | "organization.available_reliability_policies.list"
                | "organization.gateway_api_keys.list"
                | "system.administrators.list"
                | "organization.audit.list"
                | "system.audit.list"
        );
        let idempotency = operation_idempotency(self.id, mode, self.one_time_secret_response);
        let client_generated_idempotency_key = matches!(
            self.id,
            "system.upstream_credentials.replace_secret"
                | "organization.upstream_credentials.replace_secret"
        );
        let secret_input = operation_secret_input(self.id);
        let destructive = self.id.ends_with(".remove")
            || self.id.ends_with(".revoke")
            || self.id.ends_with(".cleanup")
            || self.id == "system.operations.coordination.recoveries.create"
            || self.id == "session.logout";
        let high_impact = destructive
            || self.id.contains("administrators")
            || self.id.contains("key_policy")
            || self.id.contains("identity_issuers")
            || self.id.contains("provisioning_policies")
            || self.id.starts_with("system.operations.") && mode == OperationMode::Command;
        let sensitive_result = self.one_time_secret_response
            || self.id.ends_with("audit.list")
            || qualification == OperationQualification::Operations;
        let management_client_visible = self.authentication == OperationAuthentication::Management
            && !matches!(self.id, "openapi.get");
        let console_visible = self.authentication != OperationAuthentication::Public
            && !matches!(self.id, "openapi.get");
        let toolset = if !management_client_visible {
            None
        } else if qualification == OperationQualification::Operations {
            Some("operations")
        } else if required_scopes.contains(&"management:authority") {
            Some("authority")
        } else if secret_input.is_some() || self.one_time_secret_response {
            Some("secrets")
        } else if mode == OperationMode::Command {
            Some("write")
        } else {
            Some("read")
        };
        CheckedOperationContract {
            id: self.id,
            resource_family: self
                .id
                .rsplit_once('.')
                .map_or_else(|| self.id.to_owned(), |(family, _)| family.to_owned()),
            method: self.method,
            path: self.path,
            authentication: self.authentication,
            mode,
            qualification,
            required_scopes,
            authorization_variants,
            request_schema: operation_request_schema(self.id),
            response_schema: format!("{}.response", self.id),
            paginated,
            query_parameters: operation_query_parameters(self.id, paginated),
            etag_precondition: self.etag_precondition,
            idempotency,
            client_generated_idempotency_key,
            secret_input,
            one_time_secret_response: self.one_time_secret_response,
            sensitive_result,
            high_impact,
            destructive,
            approval_recommended: high_impact || self.one_time_secret_response,
            cli_path: management_client_visible.then(|| {
                self.id
                    .split('.')
                    .map(|segment| match segment {
                        "management_keys" => "management-api-keys".to_owned(),
                        "management_key_policy" => "management-api-key-policy".to_owned(),
                        _ => segment.replace('_', "-"),
                    })
                    .collect::<Vec<_>>()
                    .join(" ")
            }),
            mcp_tool: management_client_visible.then(|| self.id.replace('.', "_")),
            mcp_toolset: toolset,
            console_capability_key: console_visible.then_some(self.id),
        }
    }
}

fn operation_mode(id: &str, method: &str) -> OperationMode {
    if method == "POST" || matches!(id, "auth.issuer.login" | "auth.issuer.callback") {
        OperationMode::Command
    } else {
        OperationMode::Query
    }
}

fn operation_qualification(path: &str) -> OperationQualification {
    if path.starts_with("/api/v1/system/operations") {
        OperationQualification::Operations
    } else if path.starts_with("/api/v1/system") {
        OperationQualification::System
    } else if path.starts_with("/api/v1/organizations/") {
        OperationQualification::Organization
    } else if path.starts_with("/api/v1") {
        OperationQualification::Personal
    } else {
        OperationQualification::Public
    }
}

fn operation_scopes(
    id: &str,
    mode: OperationMode,
    qualification: OperationQualification,
    authentication: OperationAuthentication,
) -> Vec<&'static str> {
    if authentication == OperationAuthentication::Public || id == "session.logout" {
        return Vec::new();
    }
    let mut scopes = vec![if mode == OperationMode::Query {
        "management:read"
    } else {
        "management:write"
    }];
    if qualification == OperationQualification::Operations {
        scopes.push("management:operations");
    }
    if matches!(
        id,
        "system.management_keys.create"
            | "organization.management_keys.create"
            | "system.management_keys.rotate"
            | "organization.management_keys.rotate"
            | "organization.invitations.create"
            | "organization.invitations.resend"
            | "organization.gateway_api_keys.create"
            | "organization.gateway_api_keys.rotate"
            | "system.egress_network_policies.replace_custom_ca"
            | "system.upstream_credentials.create"
            | "system.upstream_credentials.replace_secret"
            | "system.upstream_credentials.codex_login.start"
            | "system.upstream_credentials.codex_login.complete"
            | "organization.upstream_credentials.create"
            | "organization.upstream_credentials.replace_secret"
            | "system.identity_issuers.replace_client_secret"
            | "system.identity_issuers.validate_browser_login"
    ) {
        scopes.push("management:secrets");
    }
    if matches!(
        id,
        "system.management_keys.create"
            | "system.management_keys.update"
            | "system.management_key_policy.update"
            | "organization.management_keys.create"
            | "organization.management_keys.update"
            | "organization.api_key_policy.update"
            | "system.administrators.grant"
            | "system.administrators.revoke"
            | "system.identity_issuers.create"
            | "system.identity_issuers.update"
            | "system.identity_issuers.refresh"
            | "system.identity_issuers.replace_client_secret"
            | "system.identity_issuers.validate_browser_login"
            | "system.identity_bindings.create"
            | "system.identity_bindings.relink"
            | "system.identity_bindings.remove"
            | "system.provisioning_policies.create"
            | "system.provisioning_policies.update"
    ) {
        scopes.push("management:authority");
    }
    scopes.sort_unstable();
    scopes.dedup();
    scopes
}

fn operation_authorization_variants(
    id: &str,
    mode: OperationMode,
) -> Vec<OperationAuthorizationVariant> {
    let capability = if id == "invitations.accept" {
        None
    } else if id.starts_with("system.users") {
        Some("manage_system_users")
    } else if id.starts_with("system.organizations") {
        Some("manage_system_organizations")
    } else if id.starts_with("system.management_keys") {
        Some(if id.ends_with(".list") || id.ends_with(".get") {
            "read_management_keys"
        } else {
            "manage_system_keys"
        })
    } else if id.starts_with("system.management_key_policy") {
        Some("manage_system_keys")
    } else if id.starts_with("system.administrators") {
        Some("manage_administrators")
    } else if id.starts_with("system.identity_") || id.starts_with("system.provisioning_") {
        Some("manage_identity")
    } else if id.starts_with("system.egress_network_policies")
        || id.starts_with("system.gateway_policy_ceilings")
        || id.starts_with("system.reliability_policies")
        || id.starts_with("system.upstream_endpoints")
        || id.starts_with("system.upstream_credentials")
        || id.starts_with("system.pricing_policies")
        || id.starts_with("system.model_deployments")
        || id.starts_with("system.model_routes")
    {
        Some("manage_gateway_catalog")
    } else if id.starts_with("organization.upstream_credentials")
        || id.starts_with("organization.model_deployments")
    {
        Some("manage_byok")
    } else if id.starts_with("organization.model_routes") {
        Some("configure_routes")
    } else if id.starts_with("organization.available_") {
        Some("read_organization")
    } else if id.starts_with("organization.system_route_grants")
        || id.starts_with("organization.endpoint_grants")
        || id.starts_with("organization.deployment_grants")
        || id.starts_with("organization.reliability_policy_grants")
    {
        Some("manage_gateway_catalog")
    } else if id.starts_with("organization.gateway_api_keys.budget")
        || id.starts_with("organization.gateway_api_keys.limits")
        || id.starts_with("organization.provider_budgets.byok")
        || id == "organization.provider_budgets.system.get"
    {
        Some("configure_budgets")
    } else if id.starts_with("organization.provider_budgets.system") {
        Some("manage_gateway_catalog")
    } else if id.starts_with("organization.gateway_api_keys") {
        Some(if id.ends_with(".list") || id.ends_with(".get") {
            "read_gateway_keys"
        } else if id.ends_with(".create") {
            "create_gateway_keys"
        } else {
            "manage_gateway_keys"
        })
    } else if id.starts_with("system.usage") || id.starts_with("organization.usage") {
        Some("read_usage")
    } else if id.starts_with("system.audit") || id.starts_with("organization.audit") {
        Some("read_audit")
    } else if id.starts_with("system.operations") {
        Some(if mode == OperationMode::Command {
            "recover_operations"
        } else {
            "read_operations"
        })
    } else if id.contains("memberships") || id.contains("invitations") {
        Some(if id.ends_with(".list") || id.ends_with(".get") {
            "read_members"
        } else {
            "manage_members"
        })
    } else if id.starts_with("organization.management_keys") {
        if id.ends_with(".create") {
            // Organization owners/admins use create_management_keys. A local member may instead
            // use read_organization when the persisted member-self-service policy enables it.
            return vec![
                OperationAuthorizationVariant {
                    required_capability: "create_management_keys",
                    condition: None,
                },
                OperationAuthorizationVariant {
                    required_capability: "read_organization",
                    condition: Some("local_member_self_service_policy"),
                },
            ];
        }
        Some(if id.ends_with(".list") || id.ends_with(".get") {
            "read_management_keys"
        } else {
            "manage_management_keys"
        })
    } else if id.starts_with("organization.api_key_policy") {
        Some(if id.ends_with(".get") {
            "read_management_keys"
        } else {
            "update_api_key_policy"
        })
    } else if id.starts_with("organization.") {
        Some(if id.ends_with(".get") {
            "read_organization"
        } else {
            "update_organization"
        })
    } else {
        None
    };
    capability
        .into_iter()
        .map(|required_capability| OperationAuthorizationVariant {
            required_capability,
            condition: None,
        })
        .collect()
}

fn operation_secret_input(id: &str) -> Option<OperationSecretInput> {
    let (field, mode) = match id {
        "auth.management_key_session.create" => ("key", OperationSecretInputMode::ReplaceBody),
        "invitations.accept" => ("token", OperationSecretInputMode::ReplaceBody),
        "system.identity_issuers.replace_client_secret" => {
            ("client_secret", OperationSecretInputMode::ReplaceBody)
        }
        "system.egress_network_policies.create" => (
            "custom_ca_pem",
            OperationSecretInputMode::MergeIntoCandidate,
        ),
        "system.egress_network_policies.replace_custom_ca" => {
            ("custom_ca_pem", OperationSecretInputMode::ReplaceBody)
        }
        "system.upstream_credentials.create" | "organization.upstream_credentials.create" => {
            ("secret", OperationSecretInputMode::MergeIntoCandidate)
        }
        "system.upstream_credentials.replace_secret"
        | "organization.upstream_credentials.replace_secret" => {
            ("secret", OperationSecretInputMode::ReplaceBody)
        }
        _ => return None,
    };
    Some(OperationSecretInput { field, mode })
}

fn operation_idempotency(
    id: &str,
    mode: OperationMode,
    one_time_secret_response: bool,
) -> OperationIdempotency {
    if mode == OperationMode::Query {
        OperationIdempotency::NotApplicable
    } else if id == "system.upstream_credentials.codex_login.start" {
        OperationIdempotency::StateMachine
    } else if one_time_secret_response || id == "auth.management_key_session.create" {
        OperationIdempotency::Rejected
    } else if matches!(
        id,
        "system.users.create"
            | "system.organizations.create"
            | "organization.memberships.create"
            | "system.identity_issuers.create"
            | "system.identity_bindings.create"
            | "system.provisioning_policies.create"
            | "system.upstream_credentials.create"
            | "organization.upstream_credentials.create"
            | "system.egress_network_policies.create"
            | "system.reliability_policies.create"
            | "system.upstream_endpoints.create"
            | "system.pricing_policies.create"
            | "system.model_deployments.create"
            | "organization.model_deployments.create"
            | "system.model_routes.create"
            | "organization.model_routes.create"
            | "system.pricing_policies.publish_version"
            | "system.upstream_credentials.replace_secret"
            | "organization.upstream_credentials.replace_secret"
            | "organization.gateway_api_keys.budget.begin_epoch"
            | "organization.provider_budgets.system.begin_epoch"
            | "organization.provider_budgets.byok.begin_epoch"
            | "system.upstream_credentials.reload_source"
            | "system.upstream_credentials.validate"
            | "organization.upstream_credentials.validate"
            | "system.upstream_endpoints.validate"
            | "system.model_deployments.validate"
            | "organization.model_deployments.validate"
    ) {
        OperationIdempotency::Supported
    } else if matches!(
        id,
        "auth.issuer.login"
            | "auth.issuer.callback"
            | "invitations.accept"
            | "system.upstream_credentials.codex_login.complete"
            | "system.upstream_credentials.codex_login.cancel"
            | "system.upstream_credentials.refresh"
            | "system.upstream_credentials.revoke"
    ) {
        OperationIdempotency::StateMachine
    } else {
        OperationIdempotency::NotApplicable
    }
}

fn object_schema(properties: serde_json::Value, required: &[&str]) -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false,
    })
}

fn nonempty_object_schema(properties: serde_json::Value) -> serde_json::Value {
    let mut schema = object_schema(properties, &[]);
    schema
        .as_object_mut()
        .expect("object schema is an object")
        .insert("minProperties".to_owned(), serde_json::json!(1));
    schema
}

fn catalog_grant_resource_ids_schema() -> serde_json::Value {
    serde_json::json!({
        "type":"array",
        "maxItems":4096,
        "uniqueItems":true,
        "items":{"type":"string","format":"uuid"}
    })
}

fn system_route_ceilings_schema() -> serde_json::Value {
    let positive_integer = serde_json::json!({"type":"integer","minimum":1});
    serde_json::json!({
        "type":"object",
        "maxProperties":4096,
        "propertyNames":{"type":"string","format":"uuid"},
        "additionalProperties":object_schema(
            serde_json::json!({
                "allowed_capabilities":{
                    "type":"array",
                    "uniqueItems":true,
                    "items":{
                        "type":"string",
                        "enum":[
                            "streaming","tools","parallel_tools","image_input","audio_input",
                            "document_input","structured_output","json_schema","prompt_caching",
                            "system_instructions","developer_instructions","reasoning_controls",
                            "opaque_reasoning_state"
                        ]
                    }
                },
                "max_context_bytes":positive_integer,
                "max_output_units":{"type":"integer","minimum":1},
                "request_policy":object_schema(
                    serde_json::json!({
                        "max_header_bytes":{"type":"integer","minimum":1},
                        "max_request_body_bytes":{"type":"integer","minimum":1},
                        "max_response_body_bytes":{"type":"integer","minimum":1},
                        "max_stream_seconds":{"type":"integer","minimum":1},
                        "state_origin_ttl_seconds":{"type":"integer","minimum":1}
                    }),
                    &[],
                )
            }),
            &[],
        )
    })
}

fn route_selection_policy_schema() -> serde_json::Value {
    object_schema(
        serde_json::json!({
            "algorithm":{"type":"string","enum":["replicated-wrh-v1"]},
            "affinity_mode":{"type":"string","enum":["none","preferred"]}
        }),
        &[],
    )
}

fn route_request_policy_schema() -> serde_json::Value {
    object_schema(
        serde_json::json!({
            "max_header_bytes":{"type":"integer","minimum":1},
            "max_request_body_bytes":{"type":"integer","minimum":1},
            "max_response_body_bytes":{"type":"integer","minimum":1},
            "max_output_units":{"type":"integer","minimum":1},
            "max_stream_seconds":{"type":"integer","minimum":1},
            "state_origin_ttl_seconds":{"type":"integer","minimum":1}
        }),
        &[],
    )
}

fn route_target_schema() -> serde_json::Value {
    object_schema(
        serde_json::json!({
            "id":{"type":["string","null"],"format":"uuid"},
            "deployment_id":{"type":"string","format":"uuid"},
            "priority":{"type":"integer","minimum":0,"maximum":255},
            "weight":{"type":"integer","minimum":1,"maximum":256},
            "enabled":{"type":"boolean"},
            "narrowing_constraints":object_schema(
                serde_json::json!({
                    "max_output_units":{"type":"integer","minimum":1}
                }),
                &[],
            ),
            "timeout_overrides":object_schema(
                serde_json::json!({
                    "connect_timeout_ms":{"type":"integer","minimum":10,"maximum":120_000},
                    "response_header_timeout_ms":{"type":"integer","minimum":10,"maximum":3_600_000},
                    "body_timeout_ms":{"type":"integer","minimum":10,"maximum":3_600_000},
                    "stream_idle_timeout_ms":{"type":"integer","minimum":100,"maximum":3_600_000}
                }),
                &[],
            )
        }),
        &["deployment_id", "priority", "weight"],
    )
}

fn route_targets_schema() -> serde_json::Value {
    serde_json::json!({
        "type":"array",
        "maxItems":256,
        "items":route_target_schema()
    })
}

fn reliability_policy_properties(include_name: bool) -> serde_json::Value {
    use serde_json::json;
    let mut properties = json!({
        "attempt_policy": object_schema(json!({
            "max_total_attempts":{"type":"integer","minimum":1,"maximum":16},
            "max_same_target_retries":{"type":"integer","minimum":0,"maximum":8},
            "max_distinct_failover_targets":{"type":"integer","minimum":0,"maximum":15}
        }), &["max_total_attempts","max_same_target_retries","max_distinct_failover_targets"]),
        "deadline_policy": object_schema(json!({
            "overall_timeout_ms":{"type":"integer","minimum":100,"maximum":3_600_000},
            "connect_timeout_ms":{"type":"integer","minimum":10,"maximum":120_000},
            "response_header_timeout_ms":{"type":"integer","minimum":10,"maximum":3_600_000},
            "body_timeout_ms":{"type":"integer","minimum":10,"maximum":3_600_000},
            "stream_idle_timeout_ms":{"type":"integer","minimum":100,"maximum":3_600_000},
            "pre_commit_classification_timeout_ms":{"type":"integer","minimum":10,"maximum":120_000}
        }), &["overall_timeout_ms","connect_timeout_ms","response_header_timeout_ms","body_timeout_ms","stream_idle_timeout_ms","pre_commit_classification_timeout_ms"]),
        "retry_policy": object_schema(json!({
            "conditions":{"type":"array","maxItems":6,"uniqueItems":true,"items":{"type":"string","enum":["connect_failure","connect_timeout","response_header_timeout","provider_overloaded","provider_rate_limited","provider_5xx"]}},
            "initial_backoff_ms":{"type":"integer","minimum":0,"maximum":60_000},
            "max_backoff_ms":{"type":"integer","minimum":0,"maximum":300_000},
            "jitter_ratio_millis":{"type":"integer","minimum":0,"maximum":1000},
            "honor_retry_after":{"type":"boolean"}
        }), &["conditions","initial_backoff_ms","max_backoff_ms","jitter_ratio_millis","honor_retry_after"]),
        "failover_policy": object_schema(json!({
            "enabled":{"type":"boolean"},
            "require_replay_safe_request":{"type":"boolean"}
        }), &["enabled","require_replay_safe_request"]),
        "commitment_policy": object_schema(json!({
            "stream_precommit_buffer_bytes":{"type":"integer","minimum":1,"maximum":16_777_216},
            "stream_precommit_buffer_events":{"type":"integer","minimum":1,"maximum":4096}
        }), &["stream_precommit_buffer_bytes","stream_precommit_buffer_events"]),
        "health_policy": object_schema(json!({
            "shared_summary_ttl_ms":{"type":"integer","minimum":100,"maximum":300_000},
            "stale_after_ms":{"type":"integer","minimum":100,"maximum":300_000}
        }), &["shared_summary_ttl_ms","stale_after_ms"]),
        "circuit_policy": object_schema(json!({
            "failure_threshold":{"type":"integer","minimum":1,"maximum":1000},
            "success_threshold":{"type":"integer","minimum":1,"maximum":1000},
            "open_duration_ms":{"type":"integer","minimum":100,"maximum":3_600_000},
            "max_open_duration_ms":{"type":"integer","minimum":100,"maximum":3_600_000},
            "half_open_max_requests":{"type":"integer","minimum":1,"maximum":128},
            "recovery_duration_ms":{"type":"integer","minimum":100,"maximum":3_600_000}
        }), &[
            "failure_threshold","success_threshold","open_duration_ms",
            "max_open_duration_ms","half_open_max_requests","recovery_duration_ms"
        ]),
        "probe_policy": object_schema(json!({
            "enabled":{"type":"boolean"},
            "interval_ms":{"type":"integer","minimum":1000,"maximum":3_600_000},
            "timeout_ms":{"type":"integer","minimum":10,"maximum":120_000},
            "path":{"type":"string","pattern":"^/[^/]","maxLength":1024}
        }), &["enabled","interval_ms","timeout_ms","path"]),
        "status":{"type":"string","enum":["active","disabled"]}
    });
    if include_name {
        properties
            .as_object_mut()
            .expect("properties are an object")
            .insert(
                "name".to_owned(),
                json!({"type":"string","minLength":1,"maxLength":160}),
            );
    }
    properties
}

fn budget_policy_properties() -> serde_json::Value {
    serde_json::json!({
        "epoch":{"type":"string","minLength":1,"maxLength":160},
        "limit_cost_nanos":{"type":"string","pattern":"^[0-9]+$","maxLength":39},
        "mode":{"type":"string","enum":["enforce","record_only"]},
        "estimate_policy":{"type":"object"},
        "allowance_policy":{"type":"object"},
        "failure_policy":{"type":"object"},
        "recovery_policy":{"type":"object"},
        "status":{"type":"string","enum":["active","disabled"]}
    })
}

fn gateway_budget_input_schema() -> serde_json::Value {
    let mut properties = budget_policy_properties();
    properties
        .as_object_mut()
        .expect("budget properties are an object")
        .remove("status");
    object_schema(properties, &["limit_cost_nanos", "mode", "epoch"])
}

fn llm_scope_set_schema() -> serde_json::Value {
    serde_json::json!({
        "type":"array",
        "minItems":1,
        "maxItems":crate::domain::LlmScope::ALL.len(),
        "uniqueItems":true,
        "contains":{"const":crate::domain::LlmScope::Invoke.as_str()},
        "minContains":1,
        "items":{
            "type":"string",
            "enum":crate::domain::LlmScope::ALL.map(crate::domain::LlmScope::as_str)
        }
    })
}

fn request_limits_schema() -> serde_json::Value {
    object_schema(
        serde_json::json!({
            "epoch":{"type":"string","minLength":1,"maxLength":160},
            "requests_per_minute":{"type":"integer","minimum":1,"maximum":4_294_967_295_u64},
            "input_units_per_minute":{"type":["integer","null"],"minimum":1},
            "grant_mode":{"type":"string","enum":["local_grants","strict"]},
            "grant_policy":{"type":"object"},
            "concurrency_mode":{"type":["string","null"],"enum":["approximate","strict",null]},
            "concurrency_limit":{"type":["integer","null"],"minimum":1,"maximum":4_294_967_295_u64},
            "lease_seconds":{"type":["integer","null"],"minimum":1,"maximum":90000},
            "max_stream_seconds":{"type":"integer","minimum":1,"maximum":86400}
        }),
        &[
            "epoch",
            "requests_per_minute",
            "input_units_per_minute",
            "grant_mode",
            "concurrency_mode",
            "concurrency_limit",
            "lease_seconds",
            "max_stream_seconds",
        ],
    )
}

fn upstream_credential_create_schema(organization: bool) -> serde_json::Value {
    use serde_json::json;

    let non_workload_sources = json!({
        "type":"string",
        "enum":["encrypted_database","environment_reference","mounted_file_reference"]
    });
    let empty_configuration = object_schema(json!({}), &[]);
    let variant = |kind: &str,
                   source: serde_json::Value,
                   configuration: serde_json::Value,
                   injection: serde_json::Value,
                   secret: serde_json::Value,
                   secret_required: bool| {
        let mut required = vec![
            "credential_kind",
            "secret_source_kind",
            "source_configuration",
            "injection_kind",
        ];
        if secret_required {
            required.push("secret");
        }
        json!({
            "type":"object",
            "properties":{
                "credential_kind":{"const":kind},
                "secret_source_kind":source,
                "source_configuration":configuration,
                "injection_kind":injection,
                "secret":secret
            },
            "required":required
        })
    };
    let api_key_variant = |kind: &str, injection: serde_json::Value| {
        variant(
            kind,
            if organization {
                json!({"const":"encrypted_database"})
            } else {
                non_workload_sources.clone()
            },
            if organization {
                empty_configuration.clone()
            } else {
                json!({"type":"object"})
            },
            injection,
            if organization {
                json!({"type":"string","minLength":1,"maxLength":65536})
            } else {
                json!({"type":["string","null"],"minLength":1,"maxLength":65536})
            },
            organization,
        )
    };
    let mut variants = vec![
        api_key_variant(
            "static_api_key",
            json!({"type":"string","enum":["bearer","x_api_key","api_key_header"]}),
        ),
        api_key_variant("azure_api_key", json!({"const":"api_key_header"})),
    ];
    if !organization {
        variants.extend([
            variant(
                "oauth_openai_codex",
                non_workload_sources.clone(),
                json!({"type":"object"}),
                json!({"const":"bearer"}),
                json!({"type":["string","null"],"minLength":1,"maxLength":65536}),
                false,
            ),
            variant(
                "aws_default_chain",
                json!({"const":"workload_identity"}),
                empty_configuration.clone(),
                json!({"const":"aws_sigv4"}),
                json!({"type":"null"}),
                false,
            ),
            variant(
                "aws_assume_role",
                json!({"const":"workload_identity"}),
                object_schema(
                    json!({
                        "role_arn":{"type":"string","pattern":"^arn:","maxLength":2048},
                        "role_session_name":{"type":"string","minLength":1,"maxLength":64},
                        "external_id":{"type":"string","minLength":1,"maxLength":1024}
                    }),
                    &["role_arn"],
                ),
                json!({"const":"aws_sigv4"}),
                json!({"type":"null"}),
                false,
            ),
            variant(
                "google_application_default",
                json!({"const":"workload_identity"}),
                empty_configuration,
                json!({"const":"google_oauth"}),
                json!({"type":"null"}),
                false,
            ),
            variant(
                "google_service_account",
                non_workload_sources,
                json!({"type":"object"}),
                json!({"const":"google_oauth"}),
                json!({"type":["string","null"],"minLength":1,"maxLength":65536}),
                false,
            ),
            variant(
                "azure_workload_identity",
                json!({"const":"workload_identity"}),
                object_schema(
                    json!({
                        "tenant_id":{"type":"string","format":"uuid"},
                        "client_id":{"type":"string","format":"uuid"},
                        "token_file":{"type":"string","minLength":1,"maxLength":4096}
                    }),
                    &["tenant_id", "client_id", "token_file"],
                ),
                json!({"const":"azure_bearer"}),
                json!({"type":"null"}),
                false,
            ),
        ]);
    }

    let mut schema = object_schema(
        json!({
            "name":{"type":"string","minLength":1,"maxLength":160},
            "credential_kind":if organization {
                json!({"type":"string","enum":["static_api_key","azure_api_key"]})
            } else {
                json!({
                    "type":"string",
                    "enum":[
                        "static_api_key","oauth_openai_codex","aws_default_chain",
                        "aws_assume_role","google_application_default","google_service_account",
                        "azure_api_key","azure_workload_identity"
                    ]
                })
            },
            "secret_source_kind":{"type":"string"},
            "source_configuration":{"type":"object"},
            "injection_kind":{"type":"string"},
            "sharing_policy":if organization {
                json!({"const":"same_scope_reusable"})
            } else {
                json!({"type":"string"})
            },
            "secret":{"type":["string","null"],"minLength":1,"maxLength":65536},
            "safe_metadata":{"type":"object"}
        }),
        &[
            "name",
            "credential_kind",
            "secret_source_kind",
            "source_configuration",
            "injection_kind",
            "sharing_policy",
            "safe_metadata",
        ],
    );
    schema
        .as_object_mut()
        .expect("credential schema is an object")
        .insert("oneOf".to_owned(), serde_json::Value::Array(variants));
    schema
}

fn operation_request_schema(id: &str) -> Option<serde_json::Value> {
    use serde_json::json;

    let string = || json!({"type":"string","minLength":1,"maxLength":4096});
    let nullable_string = || json!({"type":["string","null"],"maxLength":4096});
    let string_array = || {
        json!({
            "type":"array",
            "items":{"type":"string","minLength":1,"maxLength":512},
            "maxItems":256,
            "uniqueItems":true
        })
    };
    let schema = match id {
        "auth.management_key_session.create" => object_schema(json!({"key": string()}), &["key"]),
        "system.users.create" => object_schema(
            json!({
                "kind":{"type":"string","enum":["human","synthetic"]},
                "display_name":{"type":"string","minLength":1,"maxLength":160},
                "primary_email":nullable_string()
            }),
            &["kind", "display_name"],
        ),
        "system.users.update" => nonempty_object_schema(json!({
            "display_name":{"type":"string","minLength":1,"maxLength":160},
            "primary_email":nullable_string(),
            "status":{"type":"string","enum":["active","disabled"]}
        })),
        "system.organizations.create" => object_schema(
            json!({
                "kind":{"type":"string","enum":["ordinary","synthetic"]},
                "name":{"type":"string","minLength":1,"maxLength":160},
                "slug":nullable_string(),
                "initial_owner_user_id":string()
            }),
            &["kind", "name", "initial_owner_user_id"],
        ),
        "system.organizations.update" | "organization.update" => nonempty_object_schema(json!({
            "name":{"type":"string","minLength":1,"maxLength":160},
            "slug":nullable_string(),
            "status":{"type":"string","enum":["active","suspended"]}
        })),
        "organization.memberships.create" => object_schema(
            json!({
                "user_id":string(),
                "role":{"type":"string","enum":["owner","admin","member"]},
                "llm_scope_ceiling":string_array(),
                "llm_capability_ceiling":string_array(),
                "llm_route_ceiling":{"type":"object"}
            }),
            &["user_id", "role", "llm_route_ceiling"],
        ),
        "organization.memberships.update" => nonempty_object_schema(json!({
            "role":{"type":"string","enum":["owner","admin","member"]},
            "llm_scope_ceiling":string_array(),
            "llm_capability_ceiling":string_array(),
            "llm_route_ceiling":{"type":"object"}
        })),
        "system.management_keys.create" | "organization.management_keys.create" => object_schema(
            json!({
                "name":{"type":"string","minLength":1,"maxLength":160},
                "scopes":string_array(),
                "capability_ceiling":string_array(),
                "expires_at":{"type":["string","null"],"format":"date-time"}
            }),
            &["name", "scopes", "capability_ceiling"],
        ),
        "system.management_keys.update" | "organization.management_keys.update" => {
            nonempty_object_schema(json!({
                "name":{"type":"string","minLength":1,"maxLength":160},
                "scopes":string_array(),
                "capability_ceiling":string_array(),
                "status":{"type":"string","enum":["active","disabled","revoked"]},
                "expires_at":{"type":["string","null"],"format":"date-time"}
            }))
        }
        "system.management_keys.rotate" | "organization.management_keys.rotate" => object_schema(
            json!({"overlap_seconds":{"type":"integer","minimum":0,"maximum":4_294_967_295_u64}}),
            &[],
        ),
        "system.management_key_policy.update" | "organization.api_key_policy.update" => {
            object_schema(json!({"policy":{"type":"object"}}), &["policy"])
        }
        "organization.invitations.create" => object_schema(
            json!({
                "intended_email":nullable_string(),
                "intended_role":{"type":"string","enum":["owner","admin","member"]},
                "llm_scope_ceiling":string_array(),
                "llm_capability_ceiling":string_array(),
                "llm_route_ceiling":{"type":"object"},
                "expires_at":{"type":"string","format":"date-time"}
            }),
            &["intended_role", "llm_route_ceiling", "expires_at"],
        ),
        "invitations.accept" => object_schema(json!({"token":string()}), &["token"]),
        "system.administrators.grant" => object_schema(
            json!({
                "subject_kind":{"type":"string","enum":["local_user","deployment_management_api_key"]},
                "subject_id":string()
            }),
            &["subject_kind", "subject_id"],
        ),
        "system.identity_issuers.create" => object_schema(
            json!({
                "name":string(),
                "display_name":string(),
                "issuer":{"type":"string","format":"uri","maxLength":4096},
                "status":{"type":"string","enum":["active","disabled"]},
                "jwks_source":{"type":"object"},
                "allowed_algorithms":string_array(),
                "accepted_audiences":string_array(),
                "subject_claim":string(),
                "claim_mapping":{"type":"object"},
                "jwt_capability_ceiling":string_array(),
                "management_scope_ceiling":string_array(),
                "management_capability_ceiling":string_array(),
                "management_organization_ceiling":{"type":"object"},
                "llm_scope_ceiling":string_array(),
                "llm_capability_ceiling":string_array(),
                "capability_claim_policy":{},
                "jwt_route_ceiling":{"type":"object"},
                "organization_selector":{"type":"object"},
                "provisioning_policy_id":nullable_string(),
                "browser_login":{"type":["object","null"]},
                "clock_skew_seconds":{"type":"integer","minimum":0,"maximum":4_294_967_295_u64},
                "key_cache_policy":{"type":"object"}
            }),
            &[
                "name",
                "display_name",
                "issuer",
                "status",
                "jwks_source",
                "allowed_algorithms",
                "accepted_audiences",
                "management_organization_ceiling",
                "capability_claim_policy",
                "jwt_route_ceiling",
                "organization_selector",
                "provisioning_policy_id",
                "browser_login",
            ],
        ),
        "system.identity_issuers.update" => nonempty_object_schema(json!({
            "display_name":{"type":["string","null"]},
            "status":{},
            "jwks_source":{},
            "allowed_algorithms":{},
            "accepted_audiences":{},
            "subject_claim":{},
            "claim_mapping":{},
            "jwt_capability_ceiling":{},
            "management_scope_ceiling":{},
            "management_capability_ceiling":{},
            "management_organization_ceiling":{},
            "llm_scope_ceiling":{},
            "llm_capability_ceiling":{},
            "capability_claim_policy":{},
            "jwt_route_ceiling":{},
            "organization_selector":{},
            "provisioning_policy_id":{},
            "browser_login":{},
            "clock_skew_seconds":{},
            "key_cache_policy":{}
        })),
        "system.identity_issuers.replace_client_secret" => object_schema(
            json!({"client_secret":{"type":"string","minLength":1,"maxLength":65536}}),
            &["client_secret"],
        ),
        "system.identity_bindings.create" => object_schema(
            json!({"issuer_id":string(),"external_subject":string(),"user_id":string()}),
            &["issuer_id", "external_subject", "user_id"],
        ),
        "system.identity_bindings.relink" => {
            object_schema(json!({"user_id":string()}), &["user_id"])
        }
        "system.provisioning_policies.create" => object_schema(
            json!({
                "name":string(),
                "status":{"type":"string","enum":["active","disabled"]},
                "user_kind":{"type":"string","enum":["human","synthetic"]},
                "configuration":{"type":"object"}
            }),
            &["name", "status", "user_kind", "configuration"],
        ),
        "system.provisioning_policies.update" => nonempty_object_schema(json!({
            "name":{"type":"string","minLength":1,"maxLength":160},
            "status":{"type":"string","enum":["active","disabled"]},
            "user_kind":{"type":"string","enum":["human","synthetic"]},
            "configuration":{"type":"object"}
        })),
        "system.gateway_policy_ceilings.update" => nonempty_object_schema(json!({
            "key_budget_max_limit_cost_nanos":{"type":"string","pattern":"^[0-9]+$","maxLength":39},
            "byok_origin_budget_max_limit_cost_nanos":{"type":"string","pattern":"^[0-9]+$","maxLength":39},
            "max_recovery_incident_cap_nanos":{"type":"string","pattern":"^[0-9]+$","maxLength":39},
            "max_recovery_epoch_cap_nanos":{"type":"string","pattern":"^[0-9]+$","maxLength":39},
            "max_requests_per_minute":{"type":"integer","minimum":1,"maximum":4_294_967_295_u64},
            "max_input_units_per_minute":{"type":"integer","minimum":1},
            "max_concurrency":{"type":"integer","minimum":1,"maximum":4_294_967_295_u64},
            "max_stream_seconds":{"type":"integer","minimum":1,"maximum":86400},
            "allowed_budget_modes":{"type":"array","minItems":1,"maxItems":2,"uniqueItems":true,"items":{"type":"string","enum":["enforce","record_only"]}},
            "allowed_rate_grant_modes":{"type":"array","minItems":1,"maxItems":2,"uniqueItems":true,"items":{"type":"string","enum":["local_grants","strict"]}},
            "allowed_concurrency_modes":{"type":"array","minItems":1,"maxItems":2,"uniqueItems":true,"items":{"type":"string","enum":["approximate","strict"]}}
        })),
        "organization.gateway_api_keys.create" => object_schema(
            json!({
                "name":{"type":"string","minLength":1,"maxLength":160},
                "scopes":llm_scope_set_schema(),
                "route_ids":{"type":"array","minItems":1,"maxItems":1024,"uniqueItems":true,"items":{"type":"string","minLength":1,"maxLength":512}},
                "budget":gateway_budget_input_schema(),
                "expires_at":{"type":["string","null"],"format":"date-time"}
            }),
            &["name", "scopes", "route_ids", "budget", "expires_at"],
        ),
        "organization.gateway_api_keys.update" => nonempty_object_schema(json!({
            "name":{"type":"string","minLength":1,"maxLength":160},
            "scopes":llm_scope_set_schema(),
            "route_ids":{"type":"array","minItems":1,"maxItems":1024,"uniqueItems":true,"items":{"type":"string","minLength":1,"maxLength":512}},
            "status":{"type":"string","enum":["active","disabled","revoked"]},
            "expires_at":{"type":["string","null"],"format":"date-time"}
        })),
        "organization.gateway_api_keys.rotate" => object_schema(
            json!({"overlap_seconds":{"type":"integer","minimum":0,"maximum":4_294_967_295_u64}}),
            &[],
        ),
        "organization.gateway_api_keys.budget.update"
        | "organization.provider_budgets.system.update"
        | "organization.provider_budgets.byok.update" => {
            nonempty_object_schema(budget_policy_properties())
        }
        "organization.gateway_api_keys.budget.begin_epoch"
        | "organization.provider_budgets.system.begin_epoch"
        | "organization.provider_budgets.byok.begin_epoch" => object_schema(
            json!({
                "epoch":{"type":"string","minLength":1,"maxLength":160},
                "limit_cost_nanos":{"type":"string","pattern":"^[0-9]+$","maxLength":39},
                "mode":{"type":"string","enum":["enforce","record_only"]}
            }),
            &["epoch"],
        ),
        "organization.gateway_api_keys.limits.update" => nonempty_object_schema(json!({
            "limits":{"oneOf":[request_limits_schema(),{"type":"null"}]},
            "status":{"type":"string","enum":["active","disabled"]}
        })),
        "system.egress_network_policies.create" => object_schema(
            json!({
                "name":{"type":"string","minLength":1,"maxLength":160},
                "dns_policy":{"type":"object"},
                "address_policy":{"type":"object"},
                "proxy_url":{"type":"null","description":"Reserved until proxy target-address enforcement is modeled"},
                "tls_policy":{"type":"object"},
                "redirect_policy":{"type":"object"},
                "connection_policy":{"type":"object"},
                "body_policy":{"type":"object"},
                "custom_ca_pem":{"type":["string","null"],"minLength":1,"maxLength":1_048_576},
                "status":{"type":"string","enum":["active","disabled"]}
            }),
            &["name"],
        ),
        "system.egress_network_policies.update" => nonempty_object_schema(json!({
            "name":{"type":"string","minLength":1,"maxLength":160},
            "dns_policy":{"type":"object"},
            "address_policy":{"type":"object"},
            "proxy_url":{"type":"null","description":"Reserved until proxy target-address enforcement is modeled"},
            "tls_policy":{"type":"object"},
            "redirect_policy":{"type":"object"},
            "connection_policy":{"type":"object"},
            "body_policy":{"type":"object"},
            "status":{"type":"string","enum":["active","disabled"]}
        })),
        "system.egress_network_policies.replace_custom_ca" => object_schema(
            json!({"custom_ca_pem":{"type":"string","minLength":1,"maxLength":1_048_576}}),
            &["custom_ca_pem"],
        ),
        "system.upstream_credentials.create" => upstream_credential_create_schema(false),
        "organization.upstream_credentials.create" => upstream_credential_create_schema(true),
        "system.upstream_credentials.update" | "organization.upstream_credentials.update" => {
            nonempty_object_schema(json!({
                "name":{"type":"string","minLength":1,"maxLength":160},
                "sharing_policy":{"type":"string"},
                "administrative_status":{"type":"string","enum":["active","disabled","revoked"]},
                "safe_metadata":{"type":"object"}
            }))
        }
        "system.upstream_credentials.replace_secret"
        | "organization.upstream_credentials.replace_secret" => object_schema(
            json!({"secret":{"type":"string","minLength":1,"maxLength":65536}}),
            &["secret"],
        ),
        "system.upstream_credentials.codex_login.start"
        | "system.upstream_credentials.codex_login.complete" => object_schema(json!({}), &[]),
        "system.upstream_endpoints.create" => object_schema(
            json!({
                "name":{"type":"string","minLength":1,"maxLength":160},
                "adapter_kind":{"type":"string","enum":["anthropic_api","aws_bedrock_runtime","google_vertex","google_gemini_api","openai_api","openai_codex","azure_openai"]},
                "base_url":{"type":"string","format":"uri","minLength":1,"maxLength":4096},
                "region":nullable_string(),
                "api_version":nullable_string(),
                "network_policy_id":string(),
                "safe_headers":{"type":"object"},
                "status":{"type":"string","enum":["active","disabled","validation_failed"]}
            }),
            &["name", "adapter_kind", "base_url", "network_policy_id"],
        ),
        "system.upstream_endpoints.update" => nonempty_object_schema(json!({
            "name":{"type":"string","minLength":1,"maxLength":160},
            "base_url":{"type":"string","format":"uri","minLength":1,"maxLength":4096},
            "region":nullable_string(),
            "api_version":nullable_string(),
            "network_policy_id":string(),
            "safe_headers":{"type":"object"},
            "status":{"type":"string","enum":["active","disabled","validation_failed"]}
        })),
        "system.reliability_policies.create" => object_schema(
            reliability_policy_properties(true),
            &[
                "name",
                "attempt_policy",
                "deadline_policy",
                "retry_policy",
                "failover_policy",
                "commitment_policy",
                "health_policy",
                "circuit_policy",
                "probe_policy",
            ],
        ),
        "system.reliability_policies.update" => {
            nonempty_object_schema(reliability_policy_properties(false))
        }
        "system.pricing_policies.create" => object_schema(
            json!({
                "name":{"type":"string","minLength":1,"maxLength":160},
                "status":{"type":"string","enum":["active","disabled"]}
            }),
            &["name"],
        ),
        "system.pricing_policies.update" => nonempty_object_schema(json!({
            "name":{"type":"string","minLength":1,"maxLength":160},
            "status":{"type":"string","enum":["active","disabled"]}
        })),
        "system.pricing_policies.publish_version" => object_schema(
            json!({
                "rates":{"type":"object"},
                "rounding_policy":{"type":"object"},
                "organization_usable":{"type":"boolean"},
                "publication_evidence":{"type":"object"}
            }),
            &["rates", "rounding_policy", "publication_evidence"],
        ),
        "system.model_deployments.create" | "organization.model_deployments.create" => {
            object_schema(
                json!({
                    "name":{"type":"string","minLength":1,"maxLength":160},
                    "endpoint_id":string(),
                    "credential_id":string(),
                    "transport_kind":{"type":"string"},
                    "upstream_model_id":{"type":"string","minLength":1,"maxLength":512},
                    "model_family":nullable_string(),
                    "capability_set":string_array(),
                    "context_limits":{"type":"object"},
                    "state_isolation_profile":{"type":"object"},
                    "pricing_policy_version_id":{"type":["string","null"]},
                    "unpriced":{"type":"boolean"},
                    "status":{"type":"string","enum":["active","disabled","validation_failed"]}
                }),
                &[
                    "name",
                    "endpoint_id",
                    "credential_id",
                    "transport_kind",
                    "upstream_model_id",
                    "capability_set",
                    "context_limits",
                    "state_isolation_profile",
                ],
            )
        }
        "system.model_deployments.update" | "organization.model_deployments.update" => {
            nonempty_object_schema(json!({
                "name":{"type":"string","minLength":1,"maxLength":160},
                "model_family":nullable_string(),
                "capability_set":string_array(),
                "context_limits":{"type":"object"},
                "state_isolation_profile":{"type":"object"},
                "pricing_policy_version_id":{"type":["string","null"]},
                "unpriced":{"type":"boolean"},
                "status":{"type":"string","enum":["active","disabled","validation_failed"]}
            }))
        }
        "system.model_routes.create" | "organization.model_routes.create" => object_schema(
            json!({
                "owner_user_id":{"type":["string","null"]},
                "model_key":{"type":"string","minLength":1,"maxLength":512},
                "ingress_protocol_family":{"type":"string","enum":["anthropic_messages","openai_chat_completions","openai_responses","google_gemini"]},
                "required_base_capabilities":string_array(),
                "selection_policy":route_selection_policy_schema(),
                "reliability_policy_id":string(),
                "request_policy":route_request_policy_schema(),
                "status":{"type":"string","enum":["draft","active","disabled"]},
                "targets":route_targets_schema()
            }),
            &[
                "model_key",
                "ingress_protocol_family",
                "required_base_capabilities",
                "selection_policy",
                "reliability_policy_id",
                "request_policy",
                "targets",
            ],
        ),
        "system.model_routes.update" | "organization.model_routes.update" => {
            nonempty_object_schema(json!({
                "required_base_capabilities":string_array(),
                "selection_policy":route_selection_policy_schema(),
                "reliability_policy_id":string(),
                "request_policy":route_request_policy_schema(),
                "status":{"type":"string","enum":["draft","active","disabled"]},
                "targets":route_targets_schema()
            }))
        }
        "organization.model_routes.transfer_ownership" => object_schema(
            json!({"owner_user_id":{"type":"string","format":"uuid"}}),
            &["owner_user_id"],
        ),
        "organization.system_route_grants.update" => object_schema(
            json!({
                "resource_ids":catalog_grant_resource_ids_schema(),
                "system_route_ceilings":system_route_ceilings_schema(),
            }),
            &["resource_ids"],
        ),
        "organization.endpoint_grants.update"
        | "organization.deployment_grants.update"
        | "organization.reliability_policy_grants.update" => object_schema(
            json!({"resource_ids":catalog_grant_resource_ids_schema()}),
            &["resource_ids"],
        ),
        "system.operations.coordination.recoveries.create" => object_schema(
            json!({
                "incident_reference":{"type":"string","minLength":1,"maxLength":512},
                "reason":{"type":"string","minLength":1,"maxLength":2048},
                "safe_evidence":{"type":"object"},
                "allocations":{
                    "type":"array","minItems":1,"maxItems":64,
                    "items":object_schema(
                        json!({
                            "organization_id":{"type":"string","format":"uuid"},
                            "policy_kind":{"type":"string","enum":["gateway_key_budget","organization_origin_budget"]},
                            "policy_id":{"type":"string","format":"uuid"},
                            "authorized_allowance_nanos":{"type":"string","pattern":"^[0-9]{1,38}$"}
                        }),
                        &["organization_id","policy_kind","policy_id","authorized_allowance_nanos"]
                    )
                }
            }),
            &[
                "incident_reference",
                "reason",
                "safe_evidence",
                "allocations",
            ],
        ),
        "system.operations.state_origins.cleanup" => object_schema(
            json!({
                "organization_id":{"type":"string","format":"uuid"},
                "cursor":{"type":["string","null"],"pattern":"^[0-9]{1,20}$"},
                "limit":{"type":["integer","null"],"minimum":1,"maximum":500}
            }),
            &["organization_id"],
        ),
        "system.operations.target_health.probe" => object_schema(
            json!({
                "target_ids":{"type":"array","minItems":1,"maxItems":64,"uniqueItems":true,"items":{"type":"string","format":"uuid"}}
            }),
            &["target_ids"],
        ),
        _ => return None,
    };
    Some(schema)
}

macro_rules! operation {
    ($id:literal, $method:literal, $path:literal, $auth:ident) => {
        OperationDescriptor {
            id: $id,
            method: $method,
            path: $path,
            authentication: OperationAuthentication::$auth,
            etag_precondition: false,
            one_time_secret_response: false,
        }
    };
    ($id:literal, $method:literal, $path:literal, $auth:ident, etag) => {
        OperationDescriptor {
            id: $id,
            method: $method,
            path: $path,
            authentication: OperationAuthentication::$auth,
            etag_precondition: true,
            one_time_secret_response: false,
        }
    };
    ($id:literal, $method:literal, $path:literal, $auth:ident, secret) => {
        OperationDescriptor {
            id: $id,
            method: $method,
            path: $path,
            authentication: OperationAuthentication::$auth,
            etag_precondition: false,
            one_time_secret_response: true,
        }
    };
    ($id:literal, $method:literal, $path:literal, $auth:ident, etag_secret) => {
        OperationDescriptor {
            id: $id,
            method: $method,
            path: $path,
            authentication: OperationAuthentication::$auth,
            etag_precondition: true,
            one_time_secret_response: true,
        }
    };
}

pub const MODULE_I_OPERATIONS: &[OperationDescriptor] = &[
    operation!("health.get", "GET", "/health", Public),
    operation!("ready.get", "GET", "/ready", Public),
    operation!("auth.issuers.list", "GET", "/auth/v1/issuers", Public),
    operation!(
        "auth.issuer.login",
        "GET",
        "/auth/v1/issuers/{issuer_name}/login",
        Public
    ),
    operation!(
        "auth.issuer.callback",
        "GET",
        "/auth/v1/issuers/{issuer_name}/callback",
        Public
    ),
    operation!(
        "auth.management_key_session.create",
        "POST",
        "/auth/v1/management-api-key/session/actions/create",
        Public
    ),
    operation!("session.get", "GET", "/api/v1/session", Management),
    operation!(
        "session.logout",
        "POST",
        "/api/v1/session/actions/logout",
        BrowserSession
    ),
    operation!("me.get", "GET", "/api/v1/me", Management),
    operation!(
        "me.organizations.list",
        "GET",
        "/api/v1/me/organizations",
        Management
    ),
    operation!(
        "me.sessions.list",
        "GET",
        "/api/v1/me/sessions",
        BrowserSession
    ),
    operation!(
        "me.sessions.revoke",
        "POST",
        "/api/v1/me/sessions/{session_id}/actions/revoke",
        BrowserSession
    ),
    operation!(
        "system.users.list",
        "GET",
        "/api/v1/system/users",
        Management
    ),
    operation!(
        "system.users.create",
        "POST",
        "/api/v1/system/users/actions/create",
        Management
    ),
    operation!(
        "system.users.get",
        "GET",
        "/api/v1/system/users/{user_id}",
        Management
    ),
    operation!(
        "system.users.update",
        "POST",
        "/api/v1/system/users/{user_id}/actions/update",
        Management,
        etag
    ),
    operation!(
        "system.organizations.list",
        "GET",
        "/api/v1/system/organizations",
        Management
    ),
    operation!(
        "system.organizations.create",
        "POST",
        "/api/v1/system/organizations/actions/create",
        Management
    ),
    operation!(
        "system.organizations.get",
        "GET",
        "/api/v1/system/organizations/{organization_id}",
        Management
    ),
    operation!(
        "system.organizations.update",
        "POST",
        "/api/v1/system/organizations/{organization_id}/actions/update",
        Management,
        etag
    ),
    operation!(
        "organization.get",
        "GET",
        "/api/v1/organizations/{organization_id}",
        Management
    ),
    operation!(
        "organization.update",
        "POST",
        "/api/v1/organizations/{organization_id}/actions/update",
        Management,
        etag
    ),
    operation!(
        "organization.memberships.list",
        "GET",
        "/api/v1/organizations/{organization_id}/memberships",
        Management
    ),
    operation!(
        "organization.memberships.create",
        "POST",
        "/api/v1/organizations/{organization_id}/memberships/actions/create",
        Management
    ),
    operation!(
        "organization.memberships.get",
        "GET",
        "/api/v1/organizations/{organization_id}/memberships/{user_id}",
        Management
    ),
    operation!(
        "organization.memberships.update",
        "POST",
        "/api/v1/organizations/{organization_id}/memberships/{user_id}/actions/update",
        Management,
        etag
    ),
    operation!(
        "organization.memberships.remove",
        "POST",
        "/api/v1/organizations/{organization_id}/memberships/{user_id}/actions/remove",
        Management
    ),
    operation!(
        "system.management_keys.list",
        "GET",
        "/api/v1/system/management-api-keys",
        Management
    ),
    operation!(
        "system.management_keys.create",
        "POST",
        "/api/v1/system/management-api-keys/actions/create",
        Management,
        secret
    ),
    operation!(
        "system.management_keys.get",
        "GET",
        "/api/v1/system/management-api-keys/{management_api_key_id}",
        Management
    ),
    operation!(
        "system.management_keys.update",
        "POST",
        "/api/v1/system/management-api-keys/{management_api_key_id}/actions/update",
        Management,
        etag
    ),
    operation!(
        "system.management_keys.rotate",
        "POST",
        "/api/v1/system/management-api-keys/{management_api_key_id}/actions/rotate",
        Management,
        secret
    ),
    operation!(
        "system.management_key_policy.get",
        "GET",
        "/api/v1/system/management-api-key-policy",
        Management
    ),
    operation!(
        "system.management_key_policy.update",
        "POST",
        "/api/v1/system/management-api-key-policy/actions/update",
        Management,
        etag
    ),
    operation!(
        "organization.management_keys.list",
        "GET",
        "/api/v1/organizations/{organization_id}/management-api-keys",
        Management
    ),
    operation!(
        "organization.management_keys.create",
        "POST",
        "/api/v1/organizations/{organization_id}/management-api-keys/actions/create",
        Management,
        secret
    ),
    operation!(
        "organization.management_keys.get",
        "GET",
        "/api/v1/organizations/{organization_id}/management-api-keys/{management_api_key_id}",
        Management
    ),
    operation!(
        "organization.management_keys.update",
        "POST",
        "/api/v1/organizations/{organization_id}/management-api-keys/{management_api_key_id}/actions/update",
        Management,
        etag
    ),
    operation!(
        "organization.management_keys.rotate",
        "POST",
        "/api/v1/organizations/{organization_id}/management-api-keys/{management_api_key_id}/actions/rotate",
        Management,
        secret
    ),
    operation!(
        "organization.api_key_policy.get",
        "GET",
        "/api/v1/organizations/{organization_id}/api-key-policy",
        Management
    ),
    operation!(
        "organization.api_key_policy.update",
        "POST",
        "/api/v1/organizations/{organization_id}/api-key-policy/actions/update",
        Management,
        etag
    ),
    operation!(
        "organization.invitations.list",
        "GET",
        "/api/v1/organizations/{organization_id}/invitations",
        Management
    ),
    operation!(
        "organization.invitations.get",
        "GET",
        "/api/v1/organizations/{organization_id}/invitations/{invitation_id}",
        Management
    ),
    operation!(
        "organization.invitations.create",
        "POST",
        "/api/v1/organizations/{organization_id}/invitations/actions/create",
        Management,
        secret
    ),
    operation!(
        "organization.invitations.resend",
        "POST",
        "/api/v1/organizations/{organization_id}/invitations/{invitation_id}/actions/resend",
        Management,
        secret
    ),
    operation!(
        "organization.invitations.revoke",
        "POST",
        "/api/v1/organizations/{organization_id}/invitations/{invitation_id}/actions/revoke",
        Management
    ),
    operation!(
        "invitations.accept",
        "POST",
        "/api/v1/invitations/actions/accept",
        BrowserSession
    ),
    operation!(
        "system.administrators.list",
        "GET",
        "/api/v1/system/administrators",
        Management
    ),
    operation!(
        "system.administrators.grant",
        "POST",
        "/api/v1/system/administrators/actions/grant",
        Management
    ),
    operation!(
        "system.administrators.revoke",
        "POST",
        "/api/v1/system/administrators/{subject_kind}/{subject_id}/actions/revoke",
        Management
    ),
    operation!(
        "system.identity_issuers.list",
        "GET",
        "/api/v1/system/identity-issuers",
        Management
    ),
    operation!(
        "system.identity_issuers.create",
        "POST",
        "/api/v1/system/identity-issuers/actions/create",
        Management
    ),
    operation!(
        "system.identity_issuers.get",
        "GET",
        "/api/v1/system/identity-issuers/{issuer_id}",
        Management
    ),
    operation!(
        "system.identity_issuers.update",
        "POST",
        "/api/v1/system/identity-issuers/{issuer_id}/actions/update",
        Management,
        etag
    ),
    operation!(
        "system.identity_issuers.refresh",
        "POST",
        "/api/v1/system/identity-issuers/{issuer_id}/actions/refresh-verifier-material",
        Management
    ),
    operation!(
        "system.identity_issuers.replace_client_secret",
        "POST",
        "/api/v1/system/identity-issuers/{issuer_id}/browser-login/actions/replace-client-secret",
        Management
    ),
    operation!(
        "system.identity_issuers.validate_browser_login",
        "POST",
        "/api/v1/system/identity-issuers/{issuer_id}/browser-login/actions/validate",
        Management
    ),
    operation!(
        "system.identity_bindings.list",
        "GET",
        "/api/v1/system/identity-bindings",
        Management
    ),
    operation!(
        "system.identity_bindings.create",
        "POST",
        "/api/v1/system/identity-bindings/actions/create",
        Management
    ),
    operation!(
        "system.identity_bindings.get",
        "GET",
        "/api/v1/system/identity-bindings/{binding_id}",
        Management
    ),
    operation!(
        "system.identity_bindings.relink",
        "POST",
        "/api/v1/system/identity-bindings/{binding_id}/actions/relink",
        Management,
        etag
    ),
    operation!(
        "system.identity_bindings.remove",
        "POST",
        "/api/v1/system/identity-bindings/{binding_id}/actions/remove",
        Management,
        etag
    ),
    operation!(
        "system.provisioning_policies.list",
        "GET",
        "/api/v1/system/provisioning-policies",
        Management
    ),
    operation!(
        "system.provisioning_policies.create",
        "POST",
        "/api/v1/system/provisioning-policies/actions/create",
        Management
    ),
    operation!(
        "system.provisioning_policies.get",
        "GET",
        "/api/v1/system/provisioning-policies/{policy_id}",
        Management
    ),
    operation!(
        "system.provisioning_policies.update",
        "POST",
        "/api/v1/system/provisioning-policies/{policy_id}/actions/update",
        Management,
        etag
    ),
    operation!(
        "system.upstream_credentials.list",
        "GET",
        "/api/v1/system/upstream-credentials",
        Management
    ),
    operation!(
        "system.upstream_credentials.create",
        "POST",
        "/api/v1/system/upstream-credentials/actions/create",
        Management
    ),
    operation!(
        "system.upstream_credentials.get",
        "GET",
        "/api/v1/system/upstream-credentials/{credential_id}",
        Management
    ),
    operation!(
        "system.upstream_credentials.update",
        "POST",
        "/api/v1/system/upstream-credentials/{credential_id}/actions/update",
        Management,
        etag
    ),
    operation!(
        "system.upstream_credentials.replace_secret",
        "POST",
        "/api/v1/system/upstream-credentials/{credential_id}/actions/replace-secret",
        Management
    ),
    operation!(
        "system.upstream_credentials.reload_source",
        "POST",
        "/api/v1/system/upstream-credentials/{credential_id}/actions/reload-source",
        Management
    ),
    operation!(
        "system.upstream_credentials.validate",
        "POST",
        "/api/v1/system/upstream-credentials/{credential_id}/actions/validate",
        Management
    ),
    operation!(
        "system.upstream_credentials.codex_login.start",
        "POST",
        "/api/v1/system/upstream-credentials/{credential_id}/codex-login/actions/start",
        Management,
        secret
    ),
    operation!(
        "system.upstream_credentials.codex_login.get",
        "GET",
        "/api/v1/system/upstream-credentials/{credential_id}/codex-login/{session_id}",
        Management
    ),
    operation!(
        "system.upstream_credentials.codex_login.complete",
        "POST",
        "/api/v1/system/upstream-credentials/{credential_id}/codex-login/{session_id}/actions/complete",
        Management
    ),
    operation!(
        "system.upstream_credentials.codex_login.cancel",
        "POST",
        "/api/v1/system/upstream-credentials/{credential_id}/codex-login/{session_id}/actions/cancel",
        Management
    ),
    operation!(
        "system.upstream_credentials.refresh",
        "POST",
        "/api/v1/system/upstream-credentials/{credential_id}/actions/refresh",
        Management
    ),
    operation!(
        "system.upstream_credentials.revoke",
        "POST",
        "/api/v1/system/upstream-credentials/{credential_id}/actions/revoke",
        Management
    ),
    operation!(
        "organization.upstream_credentials.list",
        "GET",
        "/api/v1/organizations/{organization_id}/upstream-credentials",
        Management
    ),
    operation!(
        "organization.upstream_credentials.create",
        "POST",
        "/api/v1/organizations/{organization_id}/upstream-credentials/actions/create",
        Management
    ),
    operation!(
        "organization.upstream_credentials.get",
        "GET",
        "/api/v1/organizations/{organization_id}/upstream-credentials/{credential_id}",
        Management
    ),
    operation!(
        "organization.upstream_credentials.update",
        "POST",
        "/api/v1/organizations/{organization_id}/upstream-credentials/{credential_id}/actions/update",
        Management,
        etag
    ),
    operation!(
        "organization.upstream_credentials.replace_secret",
        "POST",
        "/api/v1/organizations/{organization_id}/upstream-credentials/{credential_id}/actions/replace-secret",
        Management
    ),
    operation!(
        "organization.upstream_credentials.validate",
        "POST",
        "/api/v1/organizations/{organization_id}/upstream-credentials/{credential_id}/actions/validate",
        Management
    ),
    operation!(
        "system.egress_network_policies.list",
        "GET",
        "/api/v1/system/egress-network-policies",
        Management
    ),
    operation!(
        "system.egress_network_policies.create",
        "POST",
        "/api/v1/system/egress-network-policies/actions/create",
        Management
    ),
    operation!(
        "system.egress_network_policies.get",
        "GET",
        "/api/v1/system/egress-network-policies/{id}",
        Management
    ),
    operation!(
        "system.egress_network_policies.update",
        "POST",
        "/api/v1/system/egress-network-policies/{id}/actions/update",
        Management,
        etag
    ),
    operation!(
        "system.egress_network_policies.replace_custom_ca",
        "POST",
        "/api/v1/system/egress-network-policies/{id}/actions/replace-custom-ca",
        Management,
        etag
    ),
    operation!(
        "system.reliability_policies.list",
        "GET",
        "/api/v1/system/reliability-policies",
        Management
    ),
    operation!(
        "system.reliability_policies.create",
        "POST",
        "/api/v1/system/reliability-policies/actions/create",
        Management
    ),
    operation!(
        "system.reliability_policies.get",
        "GET",
        "/api/v1/system/reliability-policies/{id}",
        Management
    ),
    operation!(
        "system.reliability_policies.update",
        "POST",
        "/api/v1/system/reliability-policies/{id}/actions/update",
        Management,
        etag
    ),
    operation!(
        "system.upstream_endpoints.list",
        "GET",
        "/api/v1/system/upstream-endpoints",
        Management
    ),
    operation!(
        "system.upstream_endpoints.create",
        "POST",
        "/api/v1/system/upstream-endpoints/actions/create",
        Management
    ),
    operation!(
        "system.upstream_endpoints.get",
        "GET",
        "/api/v1/system/upstream-endpoints/{id}",
        Management
    ),
    operation!(
        "system.upstream_endpoints.update",
        "POST",
        "/api/v1/system/upstream-endpoints/{id}/actions/update",
        Management,
        etag
    ),
    operation!(
        "system.upstream_endpoints.validate",
        "POST",
        "/api/v1/system/upstream-endpoints/{id}/actions/validate",
        Management
    ),
    operation!(
        "system.gateway_policy_ceilings.get",
        "GET",
        "/api/v1/system/gateway-policy-ceilings",
        Management
    ),
    operation!(
        "system.gateway_policy_ceilings.update",
        "POST",
        "/api/v1/system/gateway-policy-ceilings/actions/update",
        Management,
        etag
    ),
    operation!(
        "system.pricing_policies.list",
        "GET",
        "/api/v1/system/pricing-policies",
        Management
    ),
    operation!(
        "system.pricing_policies.create",
        "POST",
        "/api/v1/system/pricing-policies/actions/create",
        Management
    ),
    operation!(
        "system.pricing_policies.get",
        "GET",
        "/api/v1/system/pricing-policies/{id}",
        Management
    ),
    operation!(
        "system.pricing_policies.update",
        "POST",
        "/api/v1/system/pricing-policies/{id}/actions/update",
        Management,
        etag
    ),
    operation!(
        "system.pricing_policies.publish_version",
        "POST",
        "/api/v1/system/pricing-policies/{id}/actions/publish-version",
        Management,
        etag
    ),
    operation!(
        "system.model_deployments.list",
        "GET",
        "/api/v1/system/model-deployments",
        Management
    ),
    operation!(
        "system.model_deployments.create",
        "POST",
        "/api/v1/system/model-deployments/actions/create",
        Management
    ),
    operation!(
        "system.model_deployments.get",
        "GET",
        "/api/v1/system/model-deployments/{id}",
        Management
    ),
    operation!(
        "system.model_deployments.update",
        "POST",
        "/api/v1/system/model-deployments/{id}/actions/update",
        Management,
        etag
    ),
    operation!(
        "system.model_deployments.validate",
        "POST",
        "/api/v1/system/model-deployments/{id}/actions/validate",
        Management
    ),
    operation!(
        "organization.model_deployments.list",
        "GET",
        "/api/v1/organizations/{organization_id}/model-deployments",
        Management
    ),
    operation!(
        "organization.model_deployments.create",
        "POST",
        "/api/v1/organizations/{organization_id}/model-deployments/actions/create",
        Management
    ),
    operation!(
        "organization.model_deployments.get",
        "GET",
        "/api/v1/organizations/{organization_id}/model-deployments/{id}",
        Management
    ),
    operation!(
        "organization.model_deployments.update",
        "POST",
        "/api/v1/organizations/{organization_id}/model-deployments/{id}/actions/update",
        Management,
        etag
    ),
    operation!(
        "organization.model_deployments.validate",
        "POST",
        "/api/v1/organizations/{organization_id}/model-deployments/{id}/actions/validate",
        Management
    ),
    operation!(
        "system.model_routes.list",
        "GET",
        "/api/v1/system/model-routes",
        Management
    ),
    operation!(
        "system.model_routes.create",
        "POST",
        "/api/v1/system/model-routes/actions/create",
        Management
    ),
    operation!(
        "system.model_routes.get",
        "GET",
        "/api/v1/system/model-routes/{id}",
        Management
    ),
    operation!(
        "system.model_routes.update",
        "POST",
        "/api/v1/system/model-routes/{id}/actions/update",
        Management,
        etag
    ),
    operation!(
        "organization.model_routes.list",
        "GET",
        "/api/v1/organizations/{organization_id}/model-routes",
        Management
    ),
    operation!(
        "organization.model_routes.create",
        "POST",
        "/api/v1/organizations/{organization_id}/model-routes/actions/create",
        Management
    ),
    operation!(
        "organization.model_routes.get",
        "GET",
        "/api/v1/organizations/{organization_id}/model-routes/{id}",
        Management
    ),
    operation!(
        "organization.model_routes.update",
        "POST",
        "/api/v1/organizations/{organization_id}/model-routes/{id}/actions/update",
        Management,
        etag
    ),
    operation!(
        "organization.model_routes.transfer_ownership",
        "POST",
        "/api/v1/organizations/{organization_id}/model-routes/{id}/actions/transfer-ownership",
        Management,
        etag
    ),
    operation!(
        "organization.available_routes.list",
        "GET",
        "/api/v1/organizations/{organization_id}/available-routes",
        Management
    ),
    operation!(
        "organization.available_endpoints.list",
        "GET",
        "/api/v1/organizations/{organization_id}/available-endpoints",
        Management
    ),
    operation!(
        "organization.available_deployments.list",
        "GET",
        "/api/v1/organizations/{organization_id}/available-deployments",
        Management
    ),
    operation!(
        "organization.available_reliability_policies.list",
        "GET",
        "/api/v1/organizations/{organization_id}/available-reliability-policies",
        Management
    ),
    operation!(
        "organization.system_route_grants.get",
        "GET",
        "/api/v1/organizations/{organization_id}/system-route-grants",
        Management
    ),
    operation!(
        "organization.system_route_grants.update",
        "POST",
        "/api/v1/organizations/{organization_id}/system-route-grants/actions/update",
        Management,
        etag
    ),
    operation!(
        "organization.endpoint_grants.get",
        "GET",
        "/api/v1/organizations/{organization_id}/endpoint-grants",
        Management
    ),
    operation!(
        "organization.endpoint_grants.update",
        "POST",
        "/api/v1/organizations/{organization_id}/endpoint-grants/actions/update",
        Management,
        etag
    ),
    operation!(
        "organization.deployment_grants.get",
        "GET",
        "/api/v1/organizations/{organization_id}/deployment-grants",
        Management
    ),
    operation!(
        "organization.deployment_grants.update",
        "POST",
        "/api/v1/organizations/{organization_id}/deployment-grants/actions/update",
        Management,
        etag
    ),
    operation!(
        "organization.reliability_policy_grants.get",
        "GET",
        "/api/v1/organizations/{organization_id}/reliability-policy-grants",
        Management
    ),
    operation!(
        "organization.reliability_policy_grants.update",
        "POST",
        "/api/v1/organizations/{organization_id}/reliability-policy-grants/actions/update",
        Management,
        etag
    ),
    operation!(
        "organization.gateway_api_keys.list",
        "GET",
        "/api/v1/organizations/{organization_id}/gateway-api-keys",
        Management
    ),
    operation!(
        "organization.gateway_api_keys.create",
        "POST",
        "/api/v1/organizations/{organization_id}/gateway-api-keys/actions/create",
        Management,
        secret
    ),
    operation!(
        "organization.gateway_api_keys.get",
        "GET",
        "/api/v1/organizations/{organization_id}/gateway-api-keys/{key_id}",
        Management
    ),
    operation!(
        "organization.gateway_api_keys.update",
        "POST",
        "/api/v1/organizations/{organization_id}/gateway-api-keys/{key_id}/actions/update",
        Management,
        etag
    ),
    operation!(
        "organization.gateway_api_keys.rotate",
        "POST",
        "/api/v1/organizations/{organization_id}/gateway-api-keys/{key_id}/actions/rotate",
        Management,
        etag_secret
    ),
    operation!(
        "organization.gateway_api_keys.budget.get",
        "GET",
        "/api/v1/organizations/{organization_id}/gateway-api-keys/{key_id}/budget",
        Management
    ),
    operation!(
        "organization.gateway_api_keys.budget.update",
        "POST",
        "/api/v1/organizations/{organization_id}/gateway-api-keys/{key_id}/budget/actions/update",
        Management,
        etag
    ),
    operation!(
        "organization.gateway_api_keys.budget.begin_epoch",
        "POST",
        "/api/v1/organizations/{organization_id}/gateway-api-keys/{key_id}/budget/actions/begin-epoch",
        Management
    ),
    operation!(
        "organization.gateway_api_keys.limits.get",
        "GET",
        "/api/v1/organizations/{organization_id}/gateway-api-keys/{key_id}/limits",
        Management
    ),
    operation!(
        "organization.gateway_api_keys.limits.update",
        "POST",
        "/api/v1/organizations/{organization_id}/gateway-api-keys/{key_id}/limits/actions/update",
        Management,
        etag
    ),
    operation!(
        "organization.provider_budgets.system.get",
        "GET",
        "/api/v1/organizations/{organization_id}/provider-budgets/system",
        Management
    ),
    operation!(
        "organization.provider_budgets.system.update",
        "POST",
        "/api/v1/organizations/{organization_id}/provider-budgets/system/actions/update",
        Management,
        etag
    ),
    operation!(
        "organization.provider_budgets.system.begin_epoch",
        "POST",
        "/api/v1/organizations/{organization_id}/provider-budgets/system/actions/begin-epoch",
        Management
    ),
    operation!(
        "organization.provider_budgets.byok.get",
        "GET",
        "/api/v1/organizations/{organization_id}/provider-budgets/byok",
        Management
    ),
    operation!(
        "organization.provider_budgets.byok.update",
        "POST",
        "/api/v1/organizations/{organization_id}/provider-budgets/byok/actions/update",
        Management,
        etag
    ),
    operation!(
        "organization.provider_budgets.byok.begin_epoch",
        "POST",
        "/api/v1/organizations/{organization_id}/provider-budgets/byok/actions/begin-epoch",
        Management
    ),
    operation!(
        "organization.usage.get",
        "GET",
        "/api/v1/organizations/{organization_id}/usage",
        Management
    ),
    operation!(
        "organization.usage.breakdown",
        "GET",
        "/api/v1/organizations/{organization_id}/usage/breakdown",
        Management
    ),
    operation!(
        "organization.audit.list",
        "GET",
        "/api/v1/organizations/{organization_id}/audit",
        Management
    ),
    operation!(
        "system.usage.get",
        "GET",
        "/api/v1/system/usage",
        Management
    ),
    operation!(
        "system.usage.breakdown",
        "GET",
        "/api/v1/system/usage/breakdown",
        Management
    ),
    operation!(
        "system.audit.list",
        "GET",
        "/api/v1/system/audit",
        Management
    ),
    operation!(
        "system.operations.overview",
        "GET",
        "/api/v1/system/operations",
        Management
    ),
    operation!(
        "system.operations.readiness",
        "GET",
        "/api/v1/system/operations/readiness",
        Management
    ),
    operation!(
        "system.operations.runtime",
        "GET",
        "/api/v1/system/operations/runtime",
        Management
    ),
    operation!(
        "system.operations.runtime.reconcile",
        "POST",
        "/api/v1/system/operations/runtime/actions/reconcile",
        Management
    ),
    operation!(
        "system.operations.coordination",
        "GET",
        "/api/v1/system/operations/coordination",
        Management
    ),
    operation!(
        "system.operations.recoveries",
        "GET",
        "/api/v1/system/operations/coordination/recoveries",
        Management
    ),
    operation!(
        "system.operations.coordination.recoveries.create",
        "POST",
        "/api/v1/system/operations/coordination/recoveries/actions/create",
        Management
    ),
    operation!(
        "system.operations.activations",
        "GET",
        "/api/v1/system/operations/coordination/activations",
        Management
    ),
    operation!(
        "system.operations.coordination.activations.reconcile",
        "POST",
        "/api/v1/system/operations/coordination/activations/actions/reconcile",
        Management
    ),
    operation!(
        "system.operations.state_origins",
        "GET",
        "/api/v1/system/operations/state-origins",
        Management
    ),
    operation!(
        "system.operations.state_origins.cleanup",
        "POST",
        "/api/v1/system/operations/state-origins/actions/cleanup",
        Management
    ),
    operation!(
        "system.operations.upstream_credentials",
        "GET",
        "/api/v1/system/operations/upstream-credentials",
        Management
    ),
    operation!(
        "system.operations.upstream_credentials.reconcile",
        "POST",
        "/api/v1/system/operations/upstream-credentials/actions/reconcile",
        Management
    ),
    operation!(
        "system.operations.codex_refresh_leases.reconcile",
        "POST",
        "/api/v1/system/operations/coordination/codex-refresh-leases/actions/reconcile",
        Management
    ),
    operation!(
        "system.operations.identity_state.cleanup",
        "POST",
        "/api/v1/system/operations/identity-state/actions/cleanup",
        Management
    ),
    operation!(
        "system.operations.target_health",
        "GET",
        "/api/v1/system/operations/target-health",
        Management
    ),
    operation!(
        "system.operations.target_health.probe",
        "POST",
        "/api/v1/system/operations/target-health/actions/probe",
        Management
    ),
    operation!(
        "system.operations.secret_custody",
        "GET",
        "/api/v1/system/operations/secret-custody",
        Management
    ),
    operation!(
        "system.operations.usage_pipeline",
        "GET",
        "/api/v1/system/operations/usage-pipeline",
        Management
    ),
    operation!(
        "system.operations.usage_pipeline.flush",
        "POST",
        "/api/v1/system/operations/usage-pipeline/actions/flush",
        Management
    ),
    operation!(
        "system.operations.telemetry",
        "GET",
        "/api/v1/system/operations/telemetry",
        Management
    ),
    operation!("openapi.get", "GET", "/api/v1/openapi.json", Management),
];

#[must_use]
pub fn operation_catalog() -> Vec<CheckedOperationContract> {
    MODULE_I_OPERATIONS
        .iter()
        .copied()
        .map(OperationDescriptor::checked_contract)
        .collect()
}

fn path_parameter_names(path: &str) -> Vec<&str> {
    path.split('/')
        .filter_map(|segment| segment.strip_prefix('{')?.strip_suffix('}'))
        .collect()
}

fn operation_query_parameters(id: &str, paginated: bool) -> Vec<OperationQueryParameter> {
    use serde_json::json;

    let parameter = |name, schema, required| OperationQueryParameter {
        name,
        schema,
        required,
    };
    if id.ends_with("usage.breakdown") || id.ends_with("usage.get") {
        let mut parameters = vec![
            parameter("start", json!({"type":"string","format":"date-time"}), true),
            parameter("end", json!({"type":"string","format":"date-time"}), true),
            parameter(
                "granularity",
                json!({"type":"string","enum":["hour","day"]}),
                false,
            ),
            parameter(
                "organization_id",
                json!({"type":"string","format":"uuid"}),
                false,
            ),
            parameter(
                "principal_kind",
                json!({"type":"string","minLength":1,"maxLength":160}),
                false,
            ),
            parameter("user_id", json!({"type":"string","format":"uuid"}), false),
            parameter(
                "gateway_api_key_id",
                json!({"type":"string","format":"uuid"}),
                false,
            ),
            parameter("route_id", json!({"type":"string","format":"uuid"}), false),
            parameter("target_id", json!({"type":"string","format":"uuid"}), false),
            parameter(
                "origin",
                json!({"type":"string","enum":["system_provided","organization_byok"]}),
                false,
            ),
            parameter(
                "deployment_id",
                json!({"type":"string","format":"uuid"}),
                false,
            ),
            parameter(
                "endpoint_id",
                json!({"type":"string","format":"uuid"}),
                false,
            ),
            parameter(
                "credential_id",
                json!({"type":"string","format":"uuid"}),
                false,
            ),
            parameter(
                "outcome",
                json!({"type":"string","minLength":1,"maxLength":160}),
                false,
            ),
        ];
        if id.starts_with("organization.") {
            parameters.retain(|parameter| parameter.name != "credential_id");
        }
        if id.ends_with("usage.breakdown") {
            let dimensions = if id.starts_with("organization.") {
                json!([
                    "organization",
                    "principal_kind",
                    "user",
                    "gateway_api_key",
                    "route",
                    "protocol",
                    "target",
                    "origin",
                    "deployment",
                    "endpoint",
                    "outcome"
                ])
            } else {
                json!([
                    "organization",
                    "principal_kind",
                    "user",
                    "gateway_api_key",
                    "route",
                    "protocol",
                    "target",
                    "origin",
                    "deployment",
                    "endpoint",
                    "credential",
                    "outcome"
                ])
            };
            parameters.extend([
                parameter(
                    "fact_family",
                    json!({"type":"string","enum":["logical_requests","attempts"]}),
                    true,
                ),
                parameter(
                    "dimension",
                    json!({"type":"string","enum":dimensions}),
                    true,
                ),
                parameter(
                    "order",
                    json!({"type":"string","enum":["count_desc","cost_desc","dimension_asc"]}),
                    false,
                ),
                parameter(
                    "limit",
                    json!({"type":"integer","minimum":1,"maximum":100}),
                    false,
                ),
            ]);
        }
        parameters
    } else if id.ends_with("audit.list") {
        vec![
            parameter("cursor", json!({"type":"string","maxLength":2048}), false),
            parameter(
                "limit",
                json!({"type":"integer","minimum":1,"maximum":200}),
                false,
            ),
            parameter(
                "since",
                json!({"type":"string","format":"date-time"}),
                false,
            ),
            parameter(
                "before",
                json!({"type":"string","format":"date-time"}),
                false,
            ),
            parameter(
                "operation_id",
                json!({"type":"string","minLength":1,"maxLength":512}),
                false,
            ),
            parameter(
                "outcome",
                json!({"type":"string","minLength":1,"maxLength":160}),
                false,
            ),
            parameter(
                "target_resource_kind",
                json!({"type":"string","minLength":1,"maxLength":160}),
                false,
            ),
        ]
    } else if paginated {
        vec![
            parameter("cursor", json!({"type":"string","maxLength":2048}), false),
            parameter(
                "limit",
                json!({"type":"integer","minimum":1,"maximum":200}),
                false,
            ),
        ]
    } else {
        Vec::new()
    }
}

fn openapi_operation(operation: OperationDescriptor) -> serde_json::Value {
    use serde_json::json;

    let contract = operation.checked_contract();
    let mut parameters = path_parameter_names(operation.path)
        .into_iter()
        .map(|name| {
            json!({
                "name":name,
                "in":"path",
                "required":true,
                "schema":{"type":"string","minLength":1,"maxLength":512}
            })
        })
        .collect::<Vec<_>>();
    parameters.extend(contract.query_parameters.iter().map(|parameter| {
        json!({
            "name":parameter.name,
            "in":"query",
            "required":parameter.required,
            "schema":parameter.schema
        })
    }));
    if contract.etag_precondition {
        parameters.push(json!({
            "name":"If-Match",
            "in":"header",
            "required":true,
            "schema":{"type":"string","minLength":1,"maxLength":512}
        }));
    }
    if contract.idempotency == OperationIdempotency::Supported {
        parameters.push(json!({
            "name":"Idempotency-Key",
            "in":"header",
            "required":false,
            "schema":{"type":"string","minLength":1,"maxLength":200}
        }));
    }
    let mut value = json!({
        "operationId": operation.id,
        "parameters": parameters,
        "x-owlrora-contract": &contract,
        "responses": {
            "200": {
                "description":"Typed OwlRora response",
                "content": {
                    "application/json": {
                        "schema": {
                            "x-owlrora-schema-id": contract.response_schema
                        }
                    }
                }
            },
            "default":{"description":"Typed OwlRora error response"}
        },
    });
    if let Some(schema) = contract.request_schema {
        value
            .as_object_mut()
            .expect("OpenAPI operation is an object")
            .insert(
                "requestBody".to_owned(),
                json!({
                    "required":true,
                    "content":{"application/json":{"schema":schema}}
                }),
            );
    }
    value
}

#[must_use]
pub fn openapi_document() -> serde_json::Value {
    let mut paths = serde_json::Map::new();
    for operation in MODULE_I_OPERATIONS {
        if operation.path.starts_with("/api/") || operation.path.starts_with("/auth/") {
            let method = operation.method.to_ascii_lowercase();
            paths
                .entry(operation.path.to_owned())
                .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()))
                .as_object_mut()
                .expect("generated path entries are objects")
                .insert(method, openapi_operation(*operation));
        }
    }
    serde_json::json!({
        "openapi":"3.1.0",
        "info":{"title":"OwlRora Management API","version":"v1"},
        "paths":paths,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn operation_inventory_is_unique_and_uses_the_management_method_model() {
        let mut ids = BTreeSet::new();
        let mut routes = BTreeSet::new();
        for operation in MODULE_I_OPERATIONS {
            assert!(ids.insert(operation.id));
            assert!(routes.insert((operation.method, operation.path)));
            assert!(matches!(operation.method, "GET" | "POST"));
            if operation.etag_precondition {
                assert_eq!(operation.method, "POST");
                assert!(
                    operation.path.ends_with("/actions/update")
                        || operation.path.ends_with("/actions/relink")
                        || operation.path.ends_with("/actions/remove")
                        || operation.path.ends_with("/actions/replace-secret")
                        || operation.path.ends_with("/actions/replace-custom-ca")
                        || operation.path.ends_with("/actions/publish-version")
                        || operation.path.ends_with("/actions/transfer-ownership")
                        || operation.path.ends_with("/actions/rotate")
                );
            }
        }
    }

    #[test]
    fn checked_contract_classifies_every_management_client_operation() {
        let contracts = operation_catalog();
        assert_eq!(contracts.len(), MODULE_I_OPERATIONS.len());
        for contract in contracts {
            if contract.authentication == OperationAuthentication::Management {
                assert!(!contract.required_scopes.is_empty());
                if contract.id != "openapi.get" {
                    assert!(contract.cli_path.is_some());
                    assert!(contract.mcp_tool.is_some());
                    assert!(contract.mcp_toolset.is_some());
                    assert!(contract.console_capability_key.is_some());
                }
            }
            if contract.one_time_secret_response {
                let expected = if contract.id == "system.upstream_credentials.codex_login.start" {
                    OperationIdempotency::StateMachine
                } else {
                    OperationIdempotency::Rejected
                };
                assert_eq!(contract.idempotency, expected);
                assert!(contract.sensitive_result);
            }
            if contract.client_generated_idempotency_key {
                assert_eq!(contract.idempotency, OperationIdempotency::Supported);
            }
            if let Some(secret_input) = contract.secret_input {
                assert!(contract.request_schema.as_ref().is_some_and(|schema| {
                    schema["properties"].get(secret_input.field).is_some()
                }));
            }
            if contract.etag_precondition {
                assert_eq!(contract.mode, OperationMode::Command);
            }
        }
    }

    #[test]
    fn console_authority_includes_browser_session_and_usage_operations() {
        let contracts = operation_catalog();
        let revoke = contracts
            .iter()
            .find(|operation| operation.id == "me.sessions.revoke")
            .unwrap();
        assert_eq!(revoke.required_scopes, vec!["management:write"]);
        assert_eq!(revoke.console_capability_key, Some("me.sessions.revoke"));

        let usage = contracts
            .iter()
            .find(|operation| operation.id == "organization.usage.get")
            .unwrap();
        assert_eq!(usage.required_scopes, vec!["management:read"]);
        assert_eq!(
            usage.authorization_variants,
            vec![OperationAuthorizationVariant {
                required_capability: "read_usage",
                condition: None,
            }]
        );

        let pipeline = contracts
            .iter()
            .find(|operation| operation.id == "system.operations.usage_pipeline")
            .unwrap();
        assert_eq!(
            pipeline.required_scopes,
            vec!["management:operations", "management:read"]
        );
        assert_eq!(pipeline.mcp_toolset, Some("operations"));
    }

    #[test]
    fn key_authority_variants_match_backend_paths() {
        let contracts = operation_catalog();
        let system_list = contracts
            .iter()
            .find(|operation| operation.id == "system.management_keys.list")
            .unwrap();
        assert_eq!(
            system_list.authorization_variants,
            vec![OperationAuthorizationVariant {
                required_capability: "read_management_keys",
                condition: None,
            }]
        );
        let organization_create = contracts
            .iter()
            .find(|operation| operation.id == "organization.management_keys.create")
            .unwrap();
        assert_eq!(
            organization_create.authorization_variants,
            vec![
                OperationAuthorizationVariant {
                    required_capability: "create_management_keys",
                    condition: None,
                },
                OperationAuthorizationVariant {
                    required_capability: "read_organization",
                    condition: Some("local_member_self_service_policy"),
                },
            ]
        );
    }

    #[test]
    fn request_schemas_cover_every_json_command_body() {
        let expected = BTreeSet::from([
            "auth.management_key_session.create",
            "system.users.create",
            "system.users.update",
            "system.organizations.create",
            "system.organizations.update",
            "organization.update",
            "organization.memberships.create",
            "organization.memberships.update",
            "system.management_keys.create",
            "system.management_keys.update",
            "system.management_keys.rotate",
            "organization.management_keys.create",
            "organization.management_keys.update",
            "organization.management_keys.rotate",
            "system.management_key_policy.update",
            "organization.api_key_policy.update",
            "organization.invitations.create",
            "invitations.accept",
            "system.administrators.grant",
            "system.identity_issuers.create",
            "system.identity_issuers.update",
            "system.identity_issuers.replace_client_secret",
            "system.identity_bindings.create",
            "system.identity_bindings.relink",
            "system.provisioning_policies.create",
            "system.provisioning_policies.update",
            "system.egress_network_policies.create",
            "system.egress_network_policies.update",
            "system.egress_network_policies.replace_custom_ca",
            "system.upstream_credentials.create",
            "system.upstream_credentials.update",
            "system.upstream_credentials.replace_secret",
            "system.upstream_credentials.codex_login.start",
            "system.upstream_credentials.codex_login.complete",
            "system.upstream_endpoints.create",
            "system.upstream_endpoints.update",
            "organization.upstream_credentials.create",
            "organization.upstream_credentials.update",
            "organization.upstream_credentials.replace_secret",
            "system.pricing_policies.create",
            "system.pricing_policies.update",
            "system.pricing_policies.publish_version",
            "system.reliability_policies.create",
            "system.reliability_policies.update",
            "system.model_deployments.create",
            "system.model_deployments.update",
            "organization.model_deployments.create",
            "organization.model_deployments.update",
            "system.model_routes.create",
            "system.model_routes.update",
            "organization.model_routes.create",
            "organization.model_routes.update",
            "organization.model_routes.transfer_ownership",
            "organization.system_route_grants.update",
            "organization.endpoint_grants.update",
            "organization.deployment_grants.update",
            "organization.reliability_policy_grants.update",
            "system.operations.coordination.recoveries.create",
            "system.operations.state_origins.cleanup",
            "system.operations.target_health.probe",
            "system.gateway_policy_ceilings.update",
            "organization.gateway_api_keys.create",
            "organization.gateway_api_keys.update",
            "organization.gateway_api_keys.rotate",
            "organization.gateway_api_keys.budget.update",
            "organization.gateway_api_keys.budget.begin_epoch",
            "organization.gateway_api_keys.limits.update",
            "organization.provider_budgets.system.update",
            "organization.provider_budgets.system.begin_epoch",
            "organization.provider_budgets.byok.update",
            "organization.provider_budgets.byok.begin_epoch",
        ]);
        let actual = operation_catalog()
            .into_iter()
            .filter_map(|operation| operation.request_schema.map(|_| operation.id))
            .collect::<BTreeSet<_>>();
        assert_eq!(actual, expected);
        for operation in operation_catalog() {
            if let Some(schema) = operation.request_schema {
                assert_eq!(schema["type"], "object", "{}", operation.id);
                assert_eq!(schema["additionalProperties"], false, "{}", operation.id);
            }
        }
    }

    #[test]
    fn model_route_schema_matches_the_exact_runtime_policy_contract() {
        let schema = operation_catalog()
            .into_iter()
            .find(|operation| operation.id == "organization.model_routes.create")
            .and_then(|operation| operation.request_schema)
            .unwrap();
        let selection = &schema["properties"]["selection_policy"];
        assert_eq!(selection["additionalProperties"], false);
        assert_eq!(
            selection["properties"]["algorithm"]["enum"],
            serde_json::json!(["replicated-wrh-v1"])
        );
        let request = &schema["properties"]["request_policy"];
        assert_eq!(request["additionalProperties"], false);
        assert_eq!(request["properties"]["max_stream_seconds"]["minimum"], 1);

        let target = &schema["properties"]["targets"]["items"];
        assert_eq!(target["additionalProperties"], false);
        assert_eq!(
            target["required"],
            serde_json::json!(["deployment_id", "priority", "weight"])
        );
        assert_eq!(target["properties"]["priority"]["maximum"], 255);
        assert_eq!(target["properties"]["weight"]["maximum"], 256);
        assert_eq!(
            target["properties"]["narrowing_constraints"]["additionalProperties"],
            false
        );
        assert!(
            target["properties"]["narrowing_constraints"]["properties"]
                .get("max_context_units")
                .is_none()
        );
        assert_eq!(
            target["properties"]["timeout_overrides"]["properties"]["stream_idle_timeout_ms"]["minimum"],
            100
        );
    }

    #[test]
    fn module_ii_contract_captures_secret_etag_and_idempotency_semantics() {
        let contracts = operation_catalog();
        let find = |id| {
            contracts
                .iter()
                .find(|operation| operation.id == id)
                .unwrap()
        };

        let rotate = find("organization.gateway_api_keys.rotate");
        assert!(rotate.etag_precondition);
        assert!(rotate.one_time_secret_response);
        assert_eq!(rotate.idempotency, OperationIdempotency::Rejected);
        assert_eq!(rotate.resource_family, "organization.gateway_api_keys");

        let replace = find("system.upstream_credentials.replace_secret");
        assert_eq!(replace.idempotency, OperationIdempotency::Supported);
        assert!(replace.client_generated_idempotency_key);
        assert_eq!(
            replace.secret_input,
            Some(OperationSecretInput {
                field: "secret",
                mode: OperationSecretInputMode::ReplaceBody,
            })
        );

        let create = find("organization.upstream_credentials.create");
        assert_eq!(
            create.secret_input,
            Some(OperationSecretInput {
                field: "secret",
                mode: OperationSecretInputMode::MergeIntoCandidate,
            })
        );
        for id in [
            "system.upstream_credentials.create",
            "organization.upstream_credentials.create",
            "system.egress_network_policies.create",
            "system.reliability_policies.create",
            "system.upstream_endpoints.create",
            "system.pricing_policies.create",
            "system.model_deployments.create",
            "organization.model_deployments.create",
            "system.model_routes.create",
            "organization.model_routes.create",
        ] {
            assert_eq!(
                find(id).idempotency,
                OperationIdempotency::Supported,
                "{id}"
            );
            assert!(!find(id).client_generated_idempotency_key, "{id}");
        }
        assert_eq!(
            find("system.egress_network_policies.create").secret_input,
            Some(OperationSecretInput {
                field: "custom_ca_pem",
                mode: OperationSecretInputMode::MergeIntoCandidate,
            })
        );
        let codex_start = find("system.upstream_credentials.codex_login.start");
        assert!(codex_start.one_time_secret_response);
        assert!(codex_start.sensitive_result);
        assert_eq!(codex_start.idempotency, OperationIdempotency::StateMachine);
        for id in [
            "organization.gateway_api_keys.budget.begin_epoch",
            "organization.provider_budgets.system.begin_epoch",
            "organization.provider_budgets.byok.begin_epoch",
        ] {
            assert_eq!(
                find(id).idempotency,
                OperationIdempotency::Supported,
                "{id}"
            );
        }
        for id in [
            "system.upstream_credentials.codex_login.start",
            "system.upstream_credentials.codex_login.complete",
        ] {
            assert!(find(id).secret_input.is_none(), "{id}");
        }
    }

    #[test]
    fn gateway_key_schema_uses_domain_scope_values_and_application_bounds() {
        let create = operation_catalog()
            .into_iter()
            .find(|operation| operation.id == "organization.gateway_api_keys.create")
            .unwrap();
        let schema = create.request_schema.unwrap();
        let values = schema["properties"]["scopes"]["items"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            values,
            crate::domain::LlmScope::ALL
                .map(crate::domain::LlmScope::as_str)
                .to_vec()
        );
        assert_eq!(
            schema["properties"]["scopes"]["contains"]["const"],
            crate::domain::LlmScope::Invoke.as_str()
        );
        assert_eq!(schema["properties"]["scopes"]["minContains"], 1);
        assert!(
            serde_json::from_value::<crate::domain::LlmScopeSet>(serde_json::json!([
                crate::domain::LlmScope::Stream.as_str()
            ]))
            .is_err()
        );
        for scope in crate::domain::LlmScope::ALL {
            let candidate = if scope == crate::domain::LlmScope::Invoke {
                serde_json::json!([scope.as_str()])
            } else {
                serde_json::json!([crate::domain::LlmScope::Invoke.as_str(), scope.as_str()])
            };
            serde_json::from_value::<crate::domain::LlmScopeSet>(candidate).unwrap();
        }
        assert_eq!(schema["properties"]["route_ids"]["maxItems"], 1024);

        let limits = operation_catalog()
            .into_iter()
            .find(|operation| operation.id == "organization.gateway_api_keys.limits.update")
            .unwrap()
            .request_schema
            .unwrap();
        assert_eq!(
            limits["properties"]["limits"]["oneOf"][0]["properties"]["lease_seconds"]["maximum"],
            90_000
        );
    }

    #[test]
    fn upstream_credential_schema_exposes_exact_default_chain_contracts() {
        let operations = operation_catalog();
        let system = operations
            .iter()
            .find(|operation| operation.id == "system.upstream_credentials.create")
            .unwrap()
            .request_schema
            .as_ref()
            .unwrap();
        for (kind, injection) in [
            ("aws_default_chain", "aws_sigv4"),
            ("google_application_default", "google_oauth"),
        ] {
            let branch = system["oneOf"]
                .as_array()
                .unwrap()
                .iter()
                .find(|branch| branch["properties"]["credential_kind"]["const"] == kind)
                .unwrap();
            assert_eq!(
                branch["properties"]["secret_source_kind"]["const"],
                "workload_identity"
            );
            assert_eq!(
                branch["properties"]["source_configuration"]["additionalProperties"],
                false
            );
            assert!(
                branch["properties"]["source_configuration"]["properties"]
                    .as_object()
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(branch["properties"]["injection_kind"]["const"], injection);
            assert_eq!(branch["properties"]["secret"]["type"], "null");
            assert!(
                !branch["required"]
                    .as_array()
                    .unwrap()
                    .contains(&serde_json::json!("secret"))
            );
        }

        let organization = operations
            .iter()
            .find(|operation| operation.id == "organization.upstream_credentials.create")
            .unwrap()
            .request_schema
            .as_ref()
            .unwrap();
        let organization_kinds = organization["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .map(|branch| {
                branch["properties"]["credential_kind"]["const"]
                    .as_str()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(organization_kinds, vec!["static_api_key", "azure_api_key"]);
        for branch in organization["oneOf"].as_array().unwrap() {
            assert_eq!(branch["properties"]["secret"]["type"], "string");
            assert!(
                branch["required"]
                    .as_array()
                    .unwrap()
                    .contains(&serde_json::json!("secret"))
            );
        }
    }

    #[test]
    fn usage_query_contract_is_typed_and_required_across_generated_clients() {
        let operations = operation_catalog();
        let usage = operations
            .iter()
            .find(|operation| operation.id == "system.usage.get")
            .unwrap();
        let start = usage
            .query_parameters
            .iter()
            .find(|parameter| parameter.name == "start")
            .unwrap();
        assert!(start.required);
        assert_eq!(start.schema["format"], "date-time");
        let breakdown = operations
            .iter()
            .find(|operation| operation.id == "organization.usage.breakdown")
            .unwrap();
        assert!(
            breakdown
                .query_parameters
                .iter()
                .any(|parameter| parameter.name == "fact_family" && parameter.required)
        );
        assert!(
            !breakdown
                .query_parameters
                .iter()
                .any(|parameter| parameter.name == "credential_id")
        );
        assert!(
            !breakdown
                .query_parameters
                .iter()
                .find(|parameter| parameter.name == "dimension")
                .unwrap()
                .schema["enum"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("credential"))
        );
    }

    #[test]
    fn generated_openapi_has_every_versioned_operation_and_typed_inputs() {
        let document = openapi_document();
        let paths = document["paths"].as_object().unwrap();
        let expected = MODULE_I_OPERATIONS
            .iter()
            .filter(|operation| {
                operation.path.starts_with("/api/") || operation.path.starts_with("/auth/")
            })
            .count();
        let actual = paths
            .values()
            .map(|path| path.as_object().unwrap().len())
            .sum::<usize>();
        assert_eq!(actual, expected);
        let create = &document["paths"]["/api/v1/system/users/actions/create"]["post"];
        assert_eq!(
            create["requestBody"]["content"]["application/json"]["schema"]["properties"]["display_name"]
                ["type"],
            "string"
        );
        let update = &document["paths"]["/api/v1/system/users/{user_id}/actions/update"]["post"];
        assert!(
            update["parameters"]
                .as_array()
                .unwrap()
                .iter()
                .any(|parameter| parameter["name"] == "user_id" && parameter["in"] == "path")
        );
        assert!(
            update["parameters"]
                .as_array()
                .unwrap()
                .iter()
                .any(|parameter| parameter["name"] == "If-Match" && parameter["in"] == "header")
        );
        let usage = &document["paths"]["/api/v1/system/usage"]["get"];
        assert!(
            usage["parameters"]
                .as_array()
                .unwrap()
                .iter()
                .any(|parameter| {
                    parameter["name"] == "start"
                        && parameter["required"] == true
                        && parameter["schema"]["format"] == "date-time"
                })
        );
    }
}
