use serde::Serialize;

use owlrora_server::http::{
    OperationAuthorizationVariant, OperationIdempotency, OperationMode, OperationQualification,
    OperationQueryParameter, OperationSecretInput, operation_catalog,
};

#[allow(clippy::struct_excessive_bools)]
#[derive(Serialize)]
struct ConsoleOperationContract {
    id: &'static str,
    resource_family: String,
    method: &'static str,
    path: &'static str,
    mode: OperationMode,
    qualification: OperationQualification,
    required_scopes: Vec<&'static str>,
    authorization_variants: Vec<OperationAuthorizationVariant>,
    request_schema: Option<serde_json::Value>,
    response_schema: String,
    paginated: bool,
    query_parameters: Vec<OperationQueryParameter>,
    etag_precondition: bool,
    idempotency: OperationIdempotency,
    client_generated_idempotency_key: bool,
    secret_input: Option<OperationSecretInput>,
    one_time_secret_response: bool,
    one_time_result_field: Option<&'static str>,
    sensitive_result: bool,
    high_impact: bool,
    destructive: bool,
    approval_recommended: bool,
}

fn main() {
    if std::env::args().any(|argument| argument == "--catalog") {
        let tuples = owlrora_server::domain::COMPATIBILITY_REGISTRY_V1
            .iter()
            .map(|entry| {
                serde_json::json!({
                    "ingress": entry.ingress,
                    "endpoint": entry.endpoint,
                    "credential": entry.credential,
                    "transport": entry.transport,
                })
            })
            .collect::<Vec<_>>();
        println!(
            "{}",
            serde_json::to_string_pretty(&tuples).expect("catalog serializes")
        );
        return;
    }
    let operations = operation_catalog()
        .into_iter()
        .filter(|operation| operation.console_capability_key.is_some())
        .map(|operation| ConsoleOperationContract {
            id: operation.id,
            resource_family: operation.resource_family,
            method: operation.method,
            path: operation.path,
            mode: operation.mode,
            qualification: operation.qualification,
            required_scopes: operation.required_scopes,
            authorization_variants: operation.authorization_variants,
            request_schema: operation.request_schema,
            response_schema: operation.response_schema,
            paginated: operation.paginated,
            query_parameters: operation.query_parameters,
            etag_precondition: operation.etag_precondition,
            idempotency: operation.idempotency,
            client_generated_idempotency_key: operation.client_generated_idempotency_key,
            secret_input: operation.secret_input,
            one_time_secret_response: operation.one_time_secret_response,
            one_time_result_field: operation.one_time_result_field,
            sensitive_result: operation.sensitive_result,
            high_impact: operation.high_impact,
            destructive: operation.destructive,
            approval_recommended: operation.approval_recommended,
        })
        .collect::<Vec<_>>();
    println!(
        "{}",
        serde_json::to_string_pretty(&operations)
            .expect("console operation contract is serializable")
    );
}
