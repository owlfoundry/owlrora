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
pub struct OperationAuthorizationVariant {
    pub required_capability: &'static str,
    pub condition: Option<&'static str>,
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
    pub etag_precondition: bool,
    pub idempotency: OperationIdempotency,
    pub secret_input: bool,
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
        let authorization_variants = operation_authorization_variants(self.id);
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
                | "system.administrators.list"
                | "organization.audit.list"
                | "system.audit.list"
        );
        let idempotency = operation_idempotency(self.id, mode, self.one_time_secret_response);
        let secret_input = matches!(
            self.id,
            "auth.management_key_session.create"
                | "invitations.accept"
                | "system.identity_issuers.replace_client_secret"
        );
        let destructive = self.id.ends_with(".remove")
            || self.id.ends_with(".revoke")
            || self.id.ends_with(".cleanup")
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
        } else if secret_input || self.one_time_secret_response {
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
                .split_once('.')
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
            etag_precondition: self.etag_precondition,
            idempotency,
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

fn operation_authorization_variants(id: &str) -> Vec<OperationAuthorizationVariant> {
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
    } else if id.starts_with("system.audit") || id.starts_with("organization.audit") {
        Some("read_audit")
    } else if id.starts_with("system.operations") {
        Some(if id.ends_with(".reconcile") || id.ends_with(".cleanup") {
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

fn operation_idempotency(
    id: &str,
    mode: OperationMode,
    one_time_secret_response: bool,
) -> OperationIdempotency {
    if mode == OperationMode::Query {
        OperationIdempotency::NotApplicable
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
    ) {
        OperationIdempotency::Supported
    } else if matches!(
        id,
        "auth.issuer.login" | "auth.issuer.callback" | "invitations.accept"
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
                "llm_scope_ceiling":string_array()
            }),
            &["user_id", "role"],
        ),
        "organization.memberships.update" => nonempty_object_schema(json!({
            "role":{"type":"string","enum":["owner","admin","member"]},
            "llm_scope_ceiling":string_array()
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
                "expires_at":{"type":"string","format":"date-time"}
            }),
            &["intended_role", "expires_at"],
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
                "management_organization_ceiling":{"type":"object"},
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
            "management_organization_ceiling":{},
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
        "organization.audit.list",
        "GET",
        "/api/v1/organizations/{organization_id}/audit",
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
        "system.operations.identity_state.cleanup",
        "POST",
        "/api/v1/system/operations/identity-state/actions/cleanup",
        Management
    ),
    operation!(
        "system.operations.secret_custody",
        "GET",
        "/api/v1/system/operations/secret-custody",
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

fn query_parameter_names(id: &str, paginated: bool) -> &'static [&'static str] {
    if id.ends_with("audit.list") {
        &[
            "cursor",
            "limit",
            "since",
            "before",
            "operation_id",
            "outcome",
            "target_resource_kind",
        ]
    } else if paginated {
        &["cursor", "limit"]
    } else {
        &[]
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
    parameters.extend(
        query_parameter_names(contract.id, contract.paginated)
            .iter()
            .map(|name| {
                let schema = if *name == "limit" {
                    json!({"type":"integer","minimum":1,"maximum":200})
                } else {
                    json!({"type":"string","maxLength":2048})
                };
                json!({"name":name,"in":"query","required":false,"schema":schema})
            }),
    );
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
                );
            }
            assert!(!(operation.etag_precondition && operation.one_time_secret_response));
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
                assert_eq!(contract.idempotency, OperationIdempotency::Rejected);
                assert!(contract.sensitive_result);
            }
            if contract.etag_precondition {
                assert_eq!(contract.mode, OperationMode::Command);
            }
        }
    }

    #[test]
    fn console_authority_includes_browser_session_scopes_and_excludes_unimplemented_usage() {
        let contracts = operation_catalog();
        let revoke = contracts
            .iter()
            .find(|operation| operation.id == "me.sessions.revoke")
            .unwrap();
        assert_eq!(revoke.required_scopes, vec!["management:write"]);
        assert_eq!(revoke.console_capability_key, Some("me.sessions.revoke"));
        assert!(contracts.iter().all(|operation| {
            !operation.id.contains("usage_pipeline") && !operation.path.contains("usage-pipeline")
        }));
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
    }
}
