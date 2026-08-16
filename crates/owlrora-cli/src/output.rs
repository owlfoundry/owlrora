use std::io::{self, IsTerminal as _, Write};

use serde_json::{Value, json};

use crate::{client::OperationResponse, profile::OutputFormat};

const MAX_TABLE_ROWS: usize = 100;
const MAX_TABLE_COLUMNS: usize = 8;
const MAX_CELL_CHARACTERS: usize = 80;

pub fn print_response(
    response: &OperationResponse,
    format: OutputFormat,
    one_time_sensitive: bool,
) -> io::Result<()> {
    if one_time_sensitive && io::stdout().is_terminal() {
        eprintln!(
            "Warning: this response contains a one-time secret. It cannot be recovered after this output."
        );
    }
    let mut output = io::stdout().lock();
    write_response(&mut output, response, format, one_time_sensitive)
}

fn write_response(
    output: &mut impl Write,
    response: &OperationResponse,
    format: OutputFormat,
    one_time_sensitive: bool,
) -> io::Result<()> {
    if format == OutputFormat::Json || one_time_sensitive {
        let envelope = json!({
            "data":response.body,
            "client":{
                "http_status":response.status.as_u16(),
                "etag":response.etag,
                "request_id":response.request_id,
            }
        });
        serde_json::to_writer_pretty(&mut *output, &envelope)?;
        writeln!(output)?;
    } else {
        print_table(output, &response.body, response.status.as_u16())?;
    }
    Ok(())
}

fn print_table(output: &mut impl Write, value: &Value, status: u16) -> io::Result<()> {
    if value.is_null() {
        writeln!(output, "HTTP {status}")?;
        return Ok(());
    }
    let rows = value
        .get("items")
        .and_then(Value::as_array)
        .or_else(|| value.as_array());
    if let Some(rows) = rows {
        return print_rows(output, rows);
    }
    if let Some(object) = value.as_object() {
        for (key, value) in object.iter().take(MAX_TABLE_ROWS) {
            writeln!(output, "{key}\t{}", cell(value))?;
        }
        return Ok(());
    }
    writeln!(output, "{}", cell(value))
}

fn print_rows(output: &mut impl Write, rows: &[Value]) -> io::Result<()> {
    if rows.is_empty() {
        writeln!(output, "No results.")?;
        return Ok(());
    }
    let columns = table_columns(rows);
    if columns.is_empty() {
        for row in rows.iter().take(MAX_TABLE_ROWS) {
            writeln!(output, "{}", cell(row))?;
        }
        return Ok(());
    }
    writeln!(output, "{}", columns.join("\t"))?;
    for row in rows.iter().take(MAX_TABLE_ROWS) {
        let object = row.as_object();
        let values = columns
            .iter()
            .map(|column| {
                object
                    .and_then(|object| object.get(column))
                    .map_or_else(String::new, cell)
            })
            .collect::<Vec<_>>();
        writeln!(output, "{}", values.join("\t"))?;
    }
    if rows.len() > MAX_TABLE_ROWS {
        writeln!(output, "… {} more rows", rows.len() - MAX_TABLE_ROWS)?;
    }
    Ok(())
}

fn table_columns(rows: &[Value]) -> Vec<String> {
    let Some(first) = rows.first().and_then(Value::as_object) else {
        return Vec::new();
    };
    first
        .iter()
        .filter(|(_, value)| is_table_scalar(value))
        .take(MAX_TABLE_COLUMNS)
        .map(|(key, _)| key.clone())
        .collect()
}

fn is_table_scalar(value: &Value) -> bool {
    matches!(
        value,
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
    )
}

fn cell(value: &Value) -> String {
    let raw = match value {
        Value::Null => String::new(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => value.clone(),
        Value::Array(_) | Value::Object(_) => compact_json(value),
    };
    truncate(&raw)
}

fn compact_json(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "<invalid>".to_owned())
}

fn truncate(value: &str) -> String {
    let mut characters = value.chars();
    let prefix = characters
        .by_ref()
        .take(MAX_CELL_CHARACTERS)
        .collect::<String>();
    if characters.next().is_some() {
        format!("{prefix}…")
    } else {
        prefix
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cells_are_bounded_by_unicode_characters() {
        let input = "界".repeat(MAX_CELL_CHARACTERS + 1);
        let rendered = truncate(&input);
        assert_eq!(rendered.chars().count(), MAX_CELL_CHARACTERS + 1);
        assert!(rendered.ends_with('…'));
    }

    #[test]
    fn one_time_secret_bypasses_table_cell_truncation() {
        let key = format!("owlrora_llm_v1.{}.{}", "l".repeat(22), "s".repeat(43));
        assert_eq!(key.len(), 81);
        let response = OperationResponse {
            status: reqwest::StatusCode::OK,
            body: json!({"key":key}),
            etag: Some("\"etag\"".to_owned()),
            request_id: Some("req_test".to_owned()),
        };
        let mut output = Vec::new();
        write_response(&mut output, &response, OutputFormat::Table, true).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains(&key));
        assert!(!output.contains('…'));
        let rendered: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(rendered["data"]["key"], key);
    }
}
