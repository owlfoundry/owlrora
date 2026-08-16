#!/usr/bin/env python3
"""Build sanitized OwlRora provider fixtures from reviewed ai-gateway cassettes.

The source cassettes are evidence only. This importer intentionally emits a small,
provider-neutral test vocabulary and never copies credentials, provider resource
names, opaque reasoning, user prompts, provider-generated identifiers, or response
text. Streaming frames not present in the recordings are derived from the sanitized
recorded response shapes and are marked as synthetic fixture coverage.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import pathlib
import struct
from typing import Any

import yaml

SOURCE_COMMIT = "24b6a0bc9541ddb98d928a54303f85cfa1106d2f"
PROMPT = "Return the string fixture-ok."
OUTPUT = "fixture-ok"
MODEL = "fixture-model"

CASSETTES = {
    "anthropic_messages_native": "anthropic-official-simple_chat.yaml",
    "anthropic_messages_bedrock": "anthropic-bedrock-simple_chat.yaml",
    "anthropic_messages_vertex": "anthropic-vertex-simple_chat.yaml",
    "openai_chat_completions": "openai-official-simple_chat.yaml",
    "openai_responses_http": "openai-official-responses_simple.yaml",
    "openai_codex_responses": "openai-official-responses_simple.yaml",
    "azure_openai_chat_completions": "azure-openai-simple_chat.yaml",
    "azure_openai_responses": "azure-openai-responses_simple.yaml",
    "google_vertex_generate_content": "gemini-simple_chat.yaml",
}


def provider_interaction(document: dict[str, Any]) -> dict[str, Any]:
    interactions = document.get("interactions")
    if not isinstance(interactions, list) or not interactions:
        raise ValueError("cassette has no interactions")
    candidates = [
        interaction
        for interaction in interactions
        if isinstance(interaction.get("request", {}).get("parsed_body"), dict)
        and "access_token" not in interaction.get("response", {}).get("parsed_body", {})
    ]
    if len(candidates) != 1:
        raise ValueError("cassette must contain exactly one provider interaction")
    return candidates[0]


def anthropic_body(*, stream: bool) -> dict[str, Any]:
    return {
        "model": MODEL,
        "max_tokens": 32,
        "messages": [{"role": "user", "content": [{"type": "text", "text": PROMPT}]}],
        "stream": stream,
    }


def anthropic_response() -> dict[str, Any]:
    return {
        "id": "msg_fixture",
        "type": "message",
        "role": "assistant",
        "model": MODEL,
        "content": [{"type": "text", "text": OUTPUT}],
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {
            "input_tokens": 12,
            "output_tokens": 4,
            "cache_creation_input_tokens": 0,
            "cache_read_input_tokens": 0,
        },
    }


def anthropic_sse() -> list[str]:
    events = [
        ("message_start", {"type": "message_start", "message": {**anthropic_response(), "content": [], "stop_reason": None, "usage": {"input_tokens": 12, "output_tokens": 0}}}),
        ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
        ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": OUTPUT}}),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None}, "usage": {"output_tokens": 4}}),
        ("message_stop", {"type": "message_stop"}),
    ]
    return [f"event: {event}\ndata: {json.dumps(body, separators=(',', ':'))}\n\n" for event, body in events]


def chat_body(*, stream: bool) -> dict[str, Any]:
    body: dict[str, Any] = {
        "model": MODEL,
        "messages": [{"role": "user", "content": PROMPT}],
        "stream": stream,
        "max_tokens": 32,
    }
    if stream:
        body["stream_options"] = {"include_usage": True}
    return body


def chat_response() -> dict[str, Any]:
    return {
        "id": "chatcmpl_fixture",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": MODEL,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": OUTPUT}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 12, "completion_tokens": 4, "total_tokens": 16, "prompt_tokens_details": {"cached_tokens": 2}, "completion_tokens_details": {"reasoning_tokens": 1}},
    }


def chat_sse() -> list[str]:
    chunks = [
        {"id": "chatcmpl_fixture", "object": "chat.completion.chunk", "created": 1_700_000_000, "model": MODEL, "choices": [{"index": 0, "delta": {"role": "assistant", "content": ""}, "finish_reason": None}]},
        {"id": "chatcmpl_fixture", "object": "chat.completion.chunk", "created": 1_700_000_000, "model": MODEL, "choices": [{"index": 0, "delta": {"content": OUTPUT}, "finish_reason": None}]},
        {"id": "chatcmpl_fixture", "object": "chat.completion.chunk", "created": 1_700_000_000, "model": MODEL, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
        {"id": "chatcmpl_fixture", "object": "chat.completion.chunk", "created": 1_700_000_000, "model": MODEL, "choices": [], "usage": {"prompt_tokens": 12, "completion_tokens": 4, "total_tokens": 16, "prompt_tokens_details": {"cached_tokens": 2}, "completion_tokens_details": {"reasoning_tokens": 1}}},
    ]
    return [f"data: {json.dumps(chunk, separators=(',', ':'))}\n\n" for chunk in chunks] + ["data: [DONE]\n\n"]


def responses_body(*, stream: bool) -> dict[str, Any]:
    return {"model": MODEL, "input": PROMPT, "max_output_tokens": 32, "stream": stream}


def responses_response() -> dict[str, Any]:
    return {
        "id": "resp_fixture",
        "object": "response",
        "created_at": 1_700_000_000,
        "status": "completed",
        "model": MODEL,
        "output": [{"id": "msg_fixture", "type": "message", "status": "completed", "role": "assistant", "content": [{"type": "output_text", "text": OUTPUT, "annotations": []}]}],
        "usage": {"input_tokens": 12, "output_tokens": 5, "total_tokens": 17, "input_tokens_details": {"cached_tokens": 2}, "output_tokens_details": {"reasoning_tokens": 1}},
    }


def responses_sse() -> list[str]:
    response = responses_response()
    events = [
        {"type": "response.created", "sequence_number": 0, "response": {**response, "status": "in_progress", "output": [], "usage": None}},
        {"type": "response.output_item.added", "sequence_number": 1, "output_index": 0, "item": {"id": "msg_fixture", "type": "message", "status": "in_progress", "role": "assistant", "content": []}},
        {"type": "response.output_text.delta", "sequence_number": 2, "item_id": "msg_fixture", "output_index": 0, "content_index": 0, "delta": OUTPUT},
        {"type": "response.completed", "sequence_number": 3, "response": response},
    ]
    return [f"event: {event['type']}\ndata: {json.dumps(event, separators=(',', ':'))}\n\n" for event in events] + ["data: [DONE]\n\n"]


def gemini_body() -> dict[str, Any]:
    return {"contents": [{"role": "user", "parts": [{"text": PROMPT}]}], "generationConfig": {"maxOutputTokens": 32}}


def gemini_response() -> dict[str, Any]:
    return {
        "candidates": [{"content": {"role": "model", "parts": [{"text": OUTPUT}]}, "finishReason": "STOP"}],
        "usageMetadata": {"promptTokenCount": 12, "candidatesTokenCount": 4, "thoughtsTokenCount": 1, "cachedContentTokenCount": 2, "totalTokenCount": 17},
        "modelVersion": MODEL,
        "responseId": "gemini_fixture",
    }


def sse_json(value: dict[str, Any]) -> list[str]:
    return [f"data: {json.dumps(value, separators=(',', ':'))}\n\n"]


def eventstream_header(name: str, value: str) -> bytes:
    name_bytes = name.encode()
    value_bytes = value.encode()
    return bytes([len(name_bytes)]) + name_bytes + b"\x07" + struct.pack(">H", len(value_bytes)) + value_bytes


def eventstream_message(payload: bytes) -> bytes:
    headers = b"".join([
        eventstream_header(":message-type", "event"),
        eventstream_header(":event-type", "chunk"),
        eventstream_header(":content-type", "application/json"),
    ])
    total_length = 16 + len(headers) + len(payload)
    prelude = struct.pack(">II", total_length, len(headers))
    prelude_crc = struct.pack(">I", binascii.crc32(prelude) & 0xFFFFFFFF)
    message_without_crc = prelude + prelude_crc + headers + payload
    return message_without_crc + struct.pack(">I", binascii.crc32(message_without_crc) & 0xFFFFFFFF)


def bedrock_stream() -> list[str]:
    frames = []
    for event in anthropic_sse():
        data = next(line[6:] for line in event.splitlines() if line.startswith("data: "))
        wrapper = json.dumps({"bytes": base64.b64encode(data.encode()).decode()}, separators=(",", ":")).encode()
        frames.append(base64.b64encode(eventstream_message(wrapper)).decode())
    return frames


def request_headers(kind: str) -> dict[str, str]:
    common = {"content-type": "application/json", "x-request-id": "request-fixture"}
    if kind.startswith("anthropic_messages_native"):
        return {**common, "anthropic-version": "2023-06-01", "x-api-key": "fixture-secret"}
    if kind == "anthropic_messages_bedrock":
        return {**common, "authorization": "AWS4-HMAC-SHA256 fixture", "x-amz-date": "20240101T000000Z", "x-amz-content-sha256": "fixture-sha256"}
    if kind in {"anthropic_messages_vertex", "google_vertex_generate_content"}:
        return {**common, "authorization": "Bearer fixture-token"}
    if kind.startswith("azure_openai"):
        return {**common, "api-key": "fixture-secret"}
    if kind == "google_gemini_generate_content":
        return {**common, "x-goog-api-key": "fixture-secret"}
    if kind == "openai_codex_responses":
        return {**common, "authorization": "Bearer fixture-token", "chatgpt-account-id": "fixture-account"}
    return {**common, "authorization": "Bearer fixture-secret"}


def make_case(name: str, path: str, body: dict[str, Any], response: dict[str, Any], stream: list[str], *, framing: str = "sse", source: str | None = None) -> dict[str, Any]:
    return {
        "name": name,
        "transport": name,
        "source_cassette": source,
        "request": {"method": "POST", "path_and_query": path, "headers": request_headers(name), "json": body},
        "response": {"status": 200, "headers": {"content-type": "application/json"}, "json": response},
        "stream": {"framing": framing, "chunks": stream},
    }


def build(source_directory: pathlib.Path) -> dict[str, Any]:
    for transport, cassette in CASSETTES.items():
        path = source_directory / cassette
        if not path.is_file():
            raise ValueError(f"missing cassette: {cassette}")
        provider_interaction(yaml.safe_load(path.read_text(encoding="utf-8")))

    cases = [
        make_case("anthropic_messages_native", "/v1/messages", anthropic_body(stream=False), anthropic_response(), anthropic_sse(), source=CASSETTES["anthropic_messages_native"]),
        make_case("anthropic_messages_bedrock", f"/model/{MODEL}/invoke", {key: value for key, value in (anthropic_body(stream=False) | {"anthropic_version": "bedrock-2023-05-31"}).items() if key not in {"model", "stream"}}, anthropic_response(), bedrock_stream(), framing="aws_event_stream_base64", source=CASSETTES["anthropic_messages_bedrock"]),
        make_case("anthropic_messages_vertex", f"/v1/projects/fixture-project/locations/fixture-region/publishers/anthropic/models/{MODEL}:rawPredict", {key: value for key, value in (anthropic_body(stream=False) | {"anthropic_version": "vertex-2023-10-16"}).items() if key != "model"}, anthropic_response(), anthropic_sse(), source=CASSETTES["anthropic_messages_vertex"]),
        make_case("openai_chat_completions", "/v1/chat/completions", chat_body(stream=False), chat_response(), chat_sse(), source=CASSETTES["openai_chat_completions"]),
        make_case("openai_responses_http", "/v1/responses", responses_body(stream=False), responses_response(), responses_sse(), source=CASSETTES["openai_responses_http"]),
        make_case("openai_codex_responses", "/backend-api/codex/responses", {k: v for k, v in (responses_body(stream=False) | {"instructions": ""}).items() if k != "max_output_tokens"}, responses_response(), responses_sse(), source=CASSETTES["openai_codex_responses"]),
        make_case("azure_openai_chat_completions", "/openai/deployments/fixture-model/chat/completions?api-version=fixture-version", chat_body(stream=False), chat_response(), chat_sse(), source=CASSETTES["azure_openai_chat_completions"]),
        make_case("azure_openai_responses", "/openai/responses?api-version=fixture-version", responses_body(stream=False), responses_response(), responses_sse(), source=CASSETTES["azure_openai_responses"]),
        make_case("google_gemini_generate_content", f"/v1beta/models/{MODEL}:generateContent", gemini_body(), gemini_response(), sse_json(gemini_response()), source=None),
        make_case("google_vertex_generate_content", f"/v1/projects/fixture-project/locations/fixture-region/publishers/google/models/{MODEL}:generateContent", gemini_body(), gemini_response(), sse_json(gemini_response()), source=CASSETTES["google_vertex_generate_content"]),
    ]
    websocket_frames = [
        {"type": "response.create", **{key: value for key, value in responses_body(stream=False).items() if key != "stream"}},
        {"type": "response.created", "sequence_number": 0, "response": {**responses_response(), "status": "in_progress", "output": [], "usage": None}},
        {"type": "response.output_text.delta", "sequence_number": 1, "item_id": "msg_fixture", "output_index": 0, "content_index": 0, "delta": OUTPUT},
        {"type": "response.completed", "sequence_number": 2, "response": responses_response()},
    ]
    cases.append({
        "name": "openai_responses_websocket",
        "transport": "openai_responses_websocket",
        "source_cassette": None,
        "request": {"method": "GET", "path_and_query": "/v1/responses", "headers": {"authorization": "Bearer fixture-secret", "upgrade": "websocket", "connection": "upgrade"}, "json": None},
        "response": {"status": 101, "headers": {"upgrade": "websocket"}, "json": None},
        "stream": {"framing": "websocket_text", "chunks": [json.dumps(frame, separators=(",", ":")) for frame in websocket_frames]},
    })
    return {
        "version": 1,
        "source": {"repository": "https://github.com/Wh1isper/llm-homelabs", "commit": SOURCE_COMMIT, "note": "Recorded structures were sanitized; synthetic streaming and WebSocket frames are explicitly fixture-derived."},
        "placeholders": {"prompt": PROMPT, "output": OUTPUT, "model": MODEL},
        "cases": cases,
    }


def secret_scan(serialized: str) -> None:
    forbidden = [
        "claude-test-project", "youware-office", "fzw-ai", "gAAAAA", "eyJ0eXAi",
        "api.anthropic.com", "api.openai.com", "cognitiveservices.azure.com",
        "@", "sk-", "AKIA", "chatgpt.com",
    ]
    matches = [value for value in forbidden if value.lower() in serialized.lower()]
    if matches:
        raise ValueError(f"sanitized fixture contains forbidden source material: {matches}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=pathlib.Path, help="proxy_vcr/cassettes directory at the reviewed commit")
    parser.add_argument("output", type=pathlib.Path)
    arguments = parser.parse_args()
    document = build(arguments.source)
    serialized = json.dumps(document, indent=2, sort_keys=True) + "\n"
    secret_scan(serialized)
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(serialized, encoding="utf-8")


if __name__ == "__main__":
    main()
