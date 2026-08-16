use std::sync::OnceLock;

use serde::Deserialize;
use serde_json::Value;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum OperationMode {
    Query,
    Command,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SecretInputMode {
    ReplaceBody,
    MergeIntoCandidate,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SecretInput {
    pub field: String,
    pub mode: SecretInputMode,
}

#[derive(Clone, Debug, Deserialize)]
pub struct QueryParameter {
    pub name: String,
    pub schema: Value,
    pub required: bool,
}

impl QueryParameter {
    pub fn is_integer(&self) -> bool {
        self.schema.get("type").and_then(Value::as_str) == Some("integer")
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct AuthorizationVariant {
    pub required_capability: String,
    pub condition: Option<String>,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize)]
pub struct Operation {
    pub id: String,
    pub method: String,
    pub path: String,
    pub mode: OperationMode,
    pub required_scopes: Vec<String>,
    pub authorization_variants: Vec<AuthorizationVariant>,
    pub request_schema: Option<Value>,
    #[serde(default)]
    pub query_parameters: Vec<QueryParameter>,
    pub etag_precondition: bool,
    pub idempotency: String,
    pub client_generated_idempotency_key: bool,
    pub secret_input: Option<SecretInput>,
    pub one_time_secret_response: bool,
    pub sensitive_result: bool,
    pub high_impact: bool,
    pub destructive: bool,
    pub approval_recommended: bool,
    pub cli_path: Option<String>,
    pub mcp_tool: Option<String>,
    pub mcp_toolset: Option<String>,
}

impl Operation {
    pub fn path_parameters(&self) -> Vec<String> {
        let mut parameters = Vec::new();
        let mut remainder = self.path.as_str();
        while let Some(start) = remainder.find('{') {
            let after_start = &remainder[start + 1..];
            let Some(end) = after_start.find('}') else {
                break;
            };
            parameters.push(after_start[..end].to_owned());
            remainder = &after_start[end + 1..];
        }
        parameters
    }

    pub fn query_parameters(&self) -> &[QueryParameter] {
        &self.query_parameters
    }

    pub const fn accepts_body(&self) -> bool {
        self.request_schema.is_some()
    }
}

pub fn operations() -> &'static [Operation] {
    static OPERATIONS: OnceLock<Vec<Operation>> = OnceLock::new();
    OPERATIONS.get_or_init(|| {
        serde_json::from_str(include_str!("management_operations.json"))
            .expect("generated management operation contract must be valid")
    })
}

pub fn operation_by_cli_path(path: &str) -> Option<&'static Operation> {
    operations()
        .iter()
        .find(|operation| operation.cli_path.as_deref() == Some(path))
}

pub fn operation_by_tool(name: &str) -> Option<&'static Operation> {
    operations()
        .iter()
        .find(|operation| operation.mcp_tool.as_deref() == Some(name))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn generated_contract_has_unique_cli_and_mcp_names() {
        let mut cli_paths = BTreeSet::new();
        let mut tools = BTreeSet::new();
        assert!(!operations().is_empty());
        for operation in operations() {
            assert!(cli_paths.insert(operation.cli_path.as_deref().unwrap()));
            assert!(tools.insert(operation.mcp_tool.as_deref().unwrap()));
            assert!(operation.path.starts_with("/api/v1"));
        }
    }

    #[test]
    fn extracts_opaque_path_parameters_in_order() {
        let operation = operations()
            .iter()
            .find(|operation| operation.id == "system.administrators.revoke")
            .unwrap();
        assert_eq!(operation.path_parameters(), ["subject_kind", "subject_id"]);
    }
}
