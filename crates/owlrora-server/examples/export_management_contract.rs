use owlrora_server::http::operation_catalog;

fn main() {
    let operations = operation_catalog()
        .into_iter()
        .filter(|operation| operation.cli_path.is_some())
        .collect::<Vec<_>>();
    println!(
        "{}",
        serde_json::to_string_pretty(&operations)
            .expect("management operation catalog is serializable")
    );
}
