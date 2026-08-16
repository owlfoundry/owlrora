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
    sensitive_result: bool,
    high_impact: bool,
    destructive: bool,
    approval_recommended: bool,
}

fn main() {
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
