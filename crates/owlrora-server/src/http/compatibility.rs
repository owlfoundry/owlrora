use axum::{
    Router,
    body::Bytes,
    extract::{Path, RawQuery, State, ws::WebSocketUpgrade},
    http::{HeaderMap, HeaderValue},
    response::Response,
    routing::post,
};
use uuid::Uuid;

use crate::{
    gateway::{authenticate_and_admit, dispatch, upgrade_responses_websocket},
    protocols::{
        ProtocolError, ProtocolErrorKind, parse_anthropic, parse_gemini, parse_openai_chat,
        parse_openai_responses,
    },
};

use super::{HttpState, request_header_bytes};

#[must_use]
pub fn router(state: HttpState) -> Router {
    Router::new()
        .route("/v1/messages", post(anthropic_messages))
        .route("/v1/chat/completions", post(openai_chat))
        .route(
            "/v1/responses",
            post(openai_responses).get(openai_responses_websocket),
        )
        .route("/v1beta/models/{model_action}", post(gemini))
        .with_state(state)
}

async fn anthropic_messages(
    State(state): State<HttpState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ProtocolError> {
    let request_id = request_id(&headers);
    let native = parse_anthropic(&headers, body, &request_id)?;
    Box::pin(invoke(state, headers, native, request_id)).await
}

async fn openai_chat(
    State(state): State<HttpState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ProtocolError> {
    let request_id = request_id(&headers);
    let native = parse_openai_chat(body, &request_id)?;
    Box::pin(invoke(state, headers, native, request_id)).await
}

async fn openai_responses(
    State(state): State<HttpState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ProtocolError> {
    let request_id = request_id(&headers);
    let native = parse_openai_responses(body, &request_id)?;
    Box::pin(invoke(state, headers, native, request_id)).await
}

async fn openai_responses_websocket(
    State(state): State<HttpState>,
    headers: HeaderMap,
    websocket: WebSocketUpgrade,
) -> Result<Response, ProtocolError> {
    let request_id = request_id(&headers);
    upgrade_responses_websocket(state.application, headers, websocket, request_id).await
}

async fn gemini(
    State(state): State<HttpState>,
    Path(model_action): Path<String>,
    RawQuery(query): RawQuery,
    mut headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ProtocolError> {
    let request_id = request_id(&headers);
    let Some((model, stream)) = parse_gemini_action(&model_action) else {
        return Err(ProtocolError::new(
            crate::domain::IngressProtocolFamily::GoogleGemini,
            ProtocolErrorKind::InvalidRequest,
            request_id,
            "Gemini path must select generateContent or streamGenerateContent",
        ));
    };
    let query_key = parse_gemini_query(
        query.as_deref(),
        stream,
        state.application.config.gemini_query_key_compatibility,
    )
    .map_err(|message| {
        ProtocolError::new(
            crate::domain::IngressProtocolFamily::GoogleGemini,
            ProtocolErrorKind::InvalidRequest,
            request_id.clone(),
            message,
        )
    })?;
    if let Some(query_key) = query_key {
        let mut value = HeaderValue::from_str(&query_key).map_err(|_| {
            ProtocolError::new(
                crate::domain::IngressProtocolFamily::GoogleGemini,
                ProtocolErrorKind::InvalidRequest,
                request_id.clone(),
                "Gemini query key is not a valid credential value",
            )
        })?;
        value.set_sensitive(true);
        headers.append("x-goog-api-key", value);
    }
    let native = parse_gemini(model, stream, body, &request_id)?;
    Box::pin(invoke(state, headers, native, request_id)).await
}

fn parse_gemini_action(value: &str) -> Option<(&str, bool)> {
    if let Some(model) = value.strip_suffix(":streamGenerateContent")
        && !model.is_empty()
    {
        return Some((model, true));
    }
    value
        .strip_suffix(":generateContent")
        .filter(|model| !model.is_empty())
        .map(|model| (model, false))
}

async fn invoke(
    state: HttpState,
    headers: HeaderMap,
    native: crate::protocols::NativeRequest,
    request_id: String,
) -> Result<Response, ProtocolError> {
    let header_bytes = request_header_bytes(&headers);
    let admission = authenticate_and_admit(
        &state.application,
        native.family,
        &headers,
        &native.intent,
        request_id,
    )?;
    if header_bytes > admission.effective_request_policy.max_header_bytes {
        return Err(ProtocolError::new(
            native.family,
            ProtocolErrorKind::RequestTooLarge,
            admission.request_id,
            "request headers exceed the route limit",
        ));
    }
    Box::pin(dispatch(admission, native)).await
}

fn request_id(headers: &HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .map(str::to_owned)
        .unwrap_or_else(|| Uuid::now_v7().to_string())
}

fn parse_gemini_query(
    query: Option<&str>,
    streaming: bool,
    allow_query_key: bool,
) -> Result<Option<String>, &'static str> {
    let mut key = None;
    let mut alt_sse = false;
    for (name, value) in query
        .filter(|query| !query.is_empty())
        .map(|query| url::form_urlencoded::parse(query.as_bytes()))
        .into_iter()
        .flatten()
    {
        match name.as_ref() {
            "alt" if streaming && value == "sse" && !alt_sse => alt_sse = true,
            "key"
                if allow_query_key && key.is_none() && !value.is_empty() && value.len() <= 4096 =>
            {
                key = Some(value.into_owned());
            }
            _ => return Err("Gemini query parameters are invalid or duplicated"),
        }
    }
    if streaming && !alt_sse {
        return Err("streamGenerateContent requires exactly one alt=sse query parameter");
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gemini_stream_query_is_closed() {
        assert_eq!(
            parse_gemini_action("route:generateContent"),
            Some(("route", false))
        );
        assert_eq!(
            parse_gemini_action("route:streamGenerateContent"),
            Some(("route", true))
        );
        assert_eq!(parse_gemini_action(":generateContent"), None);
        assert_eq!(parse_gemini_action("route:unknown"), None);
        assert_eq!(parse_gemini_query(Some("alt=sse"), true, false), Ok(None));
        assert!(parse_gemini_query(None, true, false).is_err());
        assert!(parse_gemini_query(Some("alt=json"), true, false).is_err());
        assert!(parse_gemini_query(Some("alt=sse&alt=sse"), true, false).is_err());
        assert!(parse_gemini_query(Some("x=1&alt=sse"), true, false).is_err());
        assert!(parse_gemini_query(Some("key=secret"), false, false).is_err());
        assert_eq!(
            parse_gemini_query(Some("key=secret"), false, true),
            Ok(Some("secret".to_owned()))
        );
        assert_eq!(
            parse_gemini_query(Some("alt=sse&key=secret"), true, true),
            Ok(Some("secret".to_owned()))
        );
        assert!(parse_gemini_query(Some("key=a&key=b"), false, true).is_err());
    }
}
