use serde::Serialize;

use owlrora_server::http::{OperationAuthorizationVariant, operation_catalog};

#[derive(Serialize)]
struct ConsoleAuthority {
    id: &'static str,
    required_scopes: Vec<&'static str>,
    authorization_variants: Vec<OperationAuthorizationVariant>,
}

fn main() {
    let operations = operation_catalog()
        .into_iter()
        .filter(|operation| operation.console_capability_key.is_some())
        .map(|operation| ConsoleAuthority {
            id: operation.id,
            required_scopes: operation.required_scopes,
            authorization_variants: operation.authorization_variants,
        })
        .collect::<Vec<_>>();
    println!(
        "{}",
        serde_json::to_string_pretty(&operations)
            .expect("console authority projection is serializable")
    );
}
