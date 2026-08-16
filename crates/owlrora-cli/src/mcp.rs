use std::{
    collections::BTreeSet,
    io::{self, BufRead, Read as _, Write},
};

use serde_json::{Map, Value, json};
use thiserror::Error;

use crate::{
    client::{Invocation, ManagementClient},
    contract::{Operation, OperationMode, operation_by_tool, operations},
};

const MAX_PROTOCOL_LINE_BYTES: usize = 1024 * 1024;
const LATEST_PROTOCOL_VERSION: &str = "2025-06-18";

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug)]
pub struct McpOptions {
    pub toolsets: BTreeSet<String>,
    pub allow_write: bool,
    pub allow_secret_inputs: bool,
    pub allow_sensitive_results: bool,
    pub full_access: bool,
}

impl Default for McpOptions {
    fn default() -> Self {
        Self {
            toolsets: BTreeSet::from(["read".to_owned()]),
            allow_write: false,
            allow_secret_inputs: false,
            allow_sensitive_results: false,
            full_access: false,
        }
    }
}

#[derive(Debug, Error)]
pub enum McpError {
    #[error("failed to read MCP standard input: {0}")]
    Read(io::Error),
    #[error("failed to write MCP standard output: {0}")]
    Write(io::Error),
    #[error("MCP protocol frame exceeds the {MAX_PROTOCOL_LINE_BYTES}-byte limit")]
    FrameTooLarge,
}

pub fn run(client: &ManagementClient, options: &McpOptions) -> Result<(), McpError> {
    if options.full_access {
        eprintln!(
            "Warning: MCP full access exposes every typed management tool, including writes, secret inputs, and one-time sensitive results. Server authorization still applies."
        );
    }
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    let mut line = String::new();
    loop {
        line.clear();
        let read = read_frame(&mut reader, &mut line)?;
        if read == 0 {
            break;
        }
        let Ok(request) = serde_json::from_str::<Value>(&line) else {
            write_message(&mut writer, &rpc_error(&Value::Null, -32700, "Parse error"))?;
            continue;
        };
        if let Some(response) = handle_message(client, options, &request) {
            write_message(&mut writer, &response)?;
        }
    }
    Ok(())
}

fn read_frame(reader: &mut impl BufRead, line: &mut String) -> Result<usize, McpError> {
    let read = reader
        .by_ref()
        .take((MAX_PROTOCOL_LINE_BYTES + 1) as u64)
        .read_line(line)
        .map_err(McpError::Read)?;
    if read > MAX_PROTOCOL_LINE_BYTES {
        return Err(McpError::FrameTooLarge);
    }
    Ok(read)
}

fn handle_message(
    client: &ManagementClient,
    options: &McpOptions,
    request: &Value,
) -> Option<Value> {
    let id = request.get("id")?;
    let method = request.get("method").and_then(Value::as_str);
    match method {
        Some("initialize") => Some(rpc_result(
            id,
            &json!({
                "protocolVersion":negotiated_protocol(request),
                "capabilities":{"tools":{"listChanged":false}},
                "serverInfo":{
                    "name":"owlrora-management",
                    "version":env!("CARGO_PKG_VERSION")
                },
                "instructions":"Typed OwlRora Management API tools. Visible tools never expand server-side authority."
            }),
        )),
        Some("ping") => Some(rpc_result(id, &json!({}))),
        Some("tools/list") => Some(rpc_result(id, &json!({"tools":list_tools(options)}))),
        Some("tools/call") => Some(rpc_result(id, &call_tool(client, options, request))),
        Some(_) | None => Some(rpc_error(id, -32601, "Method not found")),
    }
}

fn negotiated_protocol(request: &Value) -> String {
    let requested = request
        .pointer("/params/protocolVersion")
        .and_then(Value::as_str);
    match requested {
        Some("2024-11-05" | "2025-03-26" | "2025-06-18") => requested.unwrap().to_owned(),
        _ => LATEST_PROTOCOL_VERSION.to_owned(),
    }
}

fn list_tools(options: &McpOptions) -> Vec<Value> {
    operations()
        .iter()
        .filter(|operation| visible(operation, options))
        .map(tool_definition)
        .collect()
}

fn visible(operation: &Operation, options: &McpOptions) -> bool {
    if options.full_access {
        return true;
    }
    let Some(toolset) = operation.mcp_toolset.as_deref() else {
        return false;
    };
    options.toolsets.contains(toolset)
        && (operation.mode == OperationMode::Query || options.allow_write)
        && (operation.secret_input.is_none() || options.allow_secret_inputs)
        && (!operation.sensitive_result || options.allow_sensitive_results)
}

fn tool_definition(operation: &Operation) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();
    for parameter in operation.path_parameters() {
        properties.insert(
            parameter.clone(),
            json!({
                "type":"string",
                "minLength":1,
                "maxLength":512,
                "description":"Opaque path authority identifier"
            }),
        );
        required.push(parameter);
    }
    for parameter in operation.query_parameters() {
        properties.insert(parameter.name.clone(), parameter.schema.clone());
        if parameter.required {
            required.push(parameter.name.clone());
        }
    }
    if let Some(request_schema) = &operation.request_schema {
        let mut request_schema = request_schema.clone();
        if let Some(schema) = request_schema.as_object_mut() {
            schema.insert(
                "description".to_owned(),
                json!(format!("Typed request candidate for {}", operation.id)),
            );
        }
        properties.insert("body".to_owned(), request_schema);
        required.push("body".to_owned());
    }
    if operation.etag_precondition {
        properties.insert(
            "etag".to_owned(),
            json!({
                "type":"string",
                "minLength":1,
                "maxLength":512,
                "description":"Opaque ETag returned with the candidate's source GET"
            }),
        );
        required.push("etag".to_owned());
    }
    if operation.idempotency == "supported" {
        properties.insert(
            "idempotency_key".to_owned(),
            json!({"type":"string","minLength":1,"maxLength":200}),
        );
    }
    let scope_description = if operation.required_scopes.is_empty() {
        "no management scope metadata".to_owned()
    } else {
        operation.required_scopes.join(", ")
    };
    let authorization_description = authorization_description(operation);
    json!({
        "name":operation.mcp_tool,
        "description":format!(
            "{} {}. Required scopes: {}{}",
            operation.method,
            operation.path,
            scope_description,
            authorization_description
        ),
        "inputSchema":{
            "type":"object",
            "properties":properties,
            "required":required,
            "additionalProperties":false
        },
        "annotations":{
            "title":operation.id,
            "readOnlyHint":operation.mode == OperationMode::Query,
            "destructiveHint":operation.destructive,
            "idempotentHint":operation.mode == OperationMode::Query,
            "openWorldHint":false
        },
        "_meta":{
            "owlrora/toolset":operation.mcp_toolset,
            "owlrora/highImpact":operation.high_impact,
            "owlrora/approvalRecommended":operation.approval_recommended,
            "owlrora/secretInput":operation.secret_input.as_ref().map(|input| json!({
                "field":input.field,
                "mode":match input.mode {
                    crate::contract::SecretInputMode::ReplaceBody => "replace_body",
                    crate::contract::SecretInputMode::MergeIntoCandidate => "merge_into_candidate",
                }
            })),
            "owlrora/sensitiveResult":operation.sensitive_result,
            "owlrora/nonRepeatable":operation.one_time_secret_response
        }
    })
}

fn authorization_description(operation: &Operation) -> String {
    if operation.authorization_variants.is_empty() {
        return String::new();
    }
    let variants = operation
        .authorization_variants
        .iter()
        .map(|variant| {
            variant.condition.as_ref().map_or_else(
                || variant.required_capability.clone(),
                |condition| format!("{} ({condition})", variant.required_capability),
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(". Authorization capability (any variant): {variants}")
}

fn call_tool(client: &ManagementClient, options: &McpOptions, request: &Value) -> Value {
    let Some(name) = request.pointer("/params/name").and_then(Value::as_str) else {
        return tool_error("invalid_request", "tools/call requires params.name", None);
    };
    let Some(operation) = operation_by_tool(name) else {
        return tool_error("unknown_tool", "the requested tool does not exist", None);
    };
    if !visible(operation, options) {
        return tool_error(
            "tool_not_enabled",
            "the requested tool is not enabled by this MCP launch mode",
            None,
        );
    }
    let arguments = request
        .pointer("/params/arguments")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let invocation = match invocation_from_arguments(operation, &arguments) {
        Ok(invocation) => invocation,
        Err(message) => return tool_error("invalid_arguments", &message, None),
    };
    match client.invoke(operation, &invocation, "mcp") {
        Ok(response) => {
            let value = json!({
                "data":response.body,
                "client":{
                    "http_status":response.status.as_u16(),
                    "etag":response.etag,
                    "request_id":response.request_id,
                }
            });
            json!({
                "content":[{
                    "type":"text",
                    "text":serde_json::to_string(&value).expect("tool result is serializable")
                }],
                "isError":false
            })
        }
        Err(error) => tool_error(
            "management_api_error",
            &error.to_string(),
            error.request_id(),
        ),
    }
}

fn invocation_from_arguments(
    operation: &Operation,
    arguments: &Map<String, Value>,
) -> Result<Invocation, String> {
    let path_parameters = operation.path_parameters();
    let query_parameters = operation.query_parameters();
    let mut allowed = path_parameters.iter().cloned().collect::<BTreeSet<_>>();
    allowed.extend(
        query_parameters
            .iter()
            .map(|parameter| parameter.name.clone()),
    );
    if operation.accepts_body() {
        allowed.insert("body".to_owned());
    }
    if operation.etag_precondition {
        allowed.insert("etag".to_owned());
    }
    if operation.idempotency == "supported" {
        allowed.insert("idempotency_key".to_owned());
    }
    if let Some(unknown) = arguments.keys().find(|key| !allowed.contains(*key)) {
        return Err(format!("unknown argument {unknown:?}"));
    }
    let mut invocation = Invocation::default();
    for parameter in path_parameters {
        let value = arguments
            .get(&parameter)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("missing string argument {parameter:?}"))?;
        invocation
            .path_arguments
            .insert(parameter, value.to_owned());
    }
    for parameter in query_parameters {
        let Some(value) = arguments.get(&parameter.name) else {
            if parameter.required {
                return Err(format!("missing argument {:?}", parameter.name));
            }
            continue;
        };
        let value = if parameter.is_integer() {
            value
                .as_u64()
                .ok_or_else(|| format!("{} must be a non-negative integer", parameter.name))?
                .to_string()
        } else {
            value
                .as_str()
                .ok_or_else(|| format!("{} must be a string", parameter.name))?
                .to_owned()
        };
        invocation.query.insert(parameter.name.clone(), value);
    }
    if operation.accepts_body() {
        let body = arguments
            .get("body")
            .and_then(Value::as_object)
            .ok_or_else(|| "body must be an object".to_owned())?;
        invocation.body = Some(Value::Object(body.clone()));
    }
    invocation.etag = arguments
        .get("etag")
        .and_then(Value::as_str)
        .map(str::to_owned);
    invocation.idempotency_key = arguments
        .get("idempotency_key")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            operation
                .client_generated_idempotency_key
                .then(|| uuid::Uuid::now_v7().to_string())
        });
    Ok(invocation)
}

fn tool_error(code: &str, message: &str, request_id: Option<&str>) -> Value {
    let value = json!({"error":{"code":code,"message":message,"request_id":request_id}});
    json!({
        "content":[{
            "type":"text",
            "text":serde_json::to_string(&value).expect("tool error is serializable")
        }],
        "isError":true
    })
}

fn rpc_result(id: &Value, result: &Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":result})
}

fn rpc_error(id: &Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc":"2.0",
        "id":id,
        "error":{"code":code,"message":message}
    })
}

fn write_message(writer: &mut impl Write, message: &Value) -> Result<(), McpError> {
    serde_json::to_writer(&mut *writer, message)
        .map_err(|error| McpError::Write(io::Error::new(io::ErrorKind::InvalidData, error)))?;
    writer.write_all(b"\n").map_err(McpError::Write)?;
    writer.flush().map_err(McpError::Write)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_catalog_is_read_only_and_excludes_sensitive_queries() {
        let options = McpOptions::default();
        let tools = list_tools(&options);
        assert!(!tools.is_empty());
        assert!(
            tools
                .iter()
                .all(|tool| tool["annotations"]["readOnlyHint"] == true)
        );
        assert!(
            tools
                .iter()
                .all(|tool| tool["_meta"]["owlrora/sensitiveResult"] == false)
        );
    }

    #[test]
    fn full_access_exposes_every_generated_management_tool() {
        let options = McpOptions {
            full_access: true,
            ..McpOptions::default()
        };
        assert_eq!(list_tools(&options).len(), operations().len());
    }

    #[test]
    fn update_tools_require_candidate_bound_etags() {
        let operation = operations()
            .iter()
            .find(|operation| operation.id == "system.users.update")
            .unwrap();
        let definition = tool_definition(operation);
        assert!(
            definition["inputSchema"]["required"]
                .as_array()
                .unwrap()
                .contains(&json!("etag"))
        );
    }

    #[test]
    fn command_tools_expose_generated_request_fields_instead_of_arbitrary_json() {
        let operation = operations()
            .iter()
            .find(|operation| operation.id == "system.users.create")
            .unwrap();
        let definition = tool_definition(operation);
        let body = &definition["inputSchema"]["properties"]["body"];
        assert_eq!(body["type"], "object");
        assert_eq!(body["additionalProperties"], false);
        assert_eq!(body["properties"]["display_name"]["type"], "string");
        assert!(
            body["required"]
                .as_array()
                .unwrap()
                .contains(&json!("display_name"))
        );

        let bodyless = operations()
            .iter()
            .find(|operation| operation.id == "system.administrators.revoke")
            .unwrap();
        assert!(
            tool_definition(bodyless)["inputSchema"]["properties"]
                .get("body")
                .is_none()
        );
    }

    #[test]
    fn tool_annotations_only_mark_queries_as_idempotent() {
        let query = operations()
            .iter()
            .find(|operation| operation.id == "system.users.get")
            .unwrap();
        let supported = operations()
            .iter()
            .find(|operation| operation.id == "system.users.create")
            .unwrap();
        let state_machine = operations()
            .iter()
            .find(|operation| operation.id == "system.upstream_credentials.codex_login.start")
            .unwrap();
        assert_eq!(
            tool_definition(query)["annotations"]["idempotentHint"],
            true
        );
        assert_eq!(
            tool_definition(supported)["annotations"]["idempotentHint"],
            false
        );
        assert_eq!(
            tool_definition(state_machine)["annotations"]["idempotentHint"],
            false
        );
    }

    #[test]
    fn management_key_capability_ceilings_are_exact_string_arrays() {
        for operation_id in [
            "system.management_keys.create",
            "system.management_keys.update",
            "organization.management_keys.create",
            "organization.management_keys.update",
        ] {
            let operation = operations()
                .iter()
                .find(|operation| operation.id == operation_id)
                .unwrap();
            let definition = tool_definition(operation);
            let capability_ceiling = &definition["inputSchema"]["properties"]["body"]["properties"]
                ["capability_ceiling"];
            assert_eq!(capability_ceiling["type"], "array", "{operation_id}");
            assert_eq!(
                capability_ceiling["items"]["type"], "string",
                "{operation_id}"
            );
            assert_eq!(capability_ceiling["uniqueItems"], true, "{operation_id}");
        }
    }

    #[test]
    fn usage_tools_expose_and_forward_typed_required_query_parameters() {
        let operation = operations()
            .iter()
            .find(|operation| operation.id == "system.usage.breakdown")
            .unwrap();
        let definition = tool_definition(operation);
        let schema = &definition["inputSchema"];
        assert_eq!(schema["properties"]["start"]["format"], "date-time");
        assert_eq!(schema["properties"]["limit"]["maximum"], 100);
        for required in ["start", "end", "fact_family", "dimension"] {
            assert!(
                schema["required"]
                    .as_array()
                    .unwrap()
                    .contains(&json!(required))
            );
        }
        let arguments = serde_json::from_value::<Map<String, Value>>(json!({
            "start":"2026-01-01T00:00:00Z",
            "end":"2026-01-02T00:00:00Z",
            "fact_family":"attempts",
            "dimension":"origin",
            "limit":20
        }))
        .unwrap();
        let invocation = invocation_from_arguments(operation, &arguments).unwrap();
        assert_eq!(
            invocation.query.get("fact_family"),
            Some(&"attempts".to_owned())
        );
        assert_eq!(invocation.query.get("limit"), Some(&"20".to_owned()));
    }

    #[test]
    fn secret_replacement_invocations_generate_one_stable_retry_key() {
        let operation = operations()
            .iter()
            .find(|operation| operation.id == "system.upstream_credentials.replace_secret")
            .unwrap();
        let arguments = serde_json::from_value::<Map<String, Value>>(json!({
            "credential_id":"credential-1",
            "body":{"secret":"protected"}
        }))
        .unwrap();
        let invocation = invocation_from_arguments(operation, &arguments).unwrap();
        assert!(invocation.idempotency_key.is_some());
        assert_eq!(invocation.body, Some(json!({"secret":"protected"})));
    }

    #[test]
    fn oversized_frame_is_rejected_before_unbounded_allocation() {
        let bytes = vec![b'x'; MAX_PROTOCOL_LINE_BYTES + 2];
        let mut reader = io::Cursor::new(bytes);
        let mut line = String::new();
        assert!(matches!(
            read_frame(&mut reader, &mut line),
            Err(McpError::FrameTooLarge)
        ));
        assert_eq!(line.len(), MAX_PROTOCOL_LINE_BYTES + 1);
    }
}
