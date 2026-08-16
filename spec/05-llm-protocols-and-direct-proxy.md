# LLM protocols and direct proxy

## 1. Protocol-native architecture

OwlRora preserves the caller’s protocol family from ingress to a compatible upstream transport and back.

It does not normalize Anthropic Messages, OpenAI Chat Completions, OpenAI Responses, and Google Gemini into one universal chat schema. Each protocol module owns:

- bounded request validation and extraction;
- native body and extension-field handling;
- capability and routing-intent extraction;
- compatible upstream construction;
- stream framing and commitment recognition;
- native error rendering;
- usage extraction.

Provider-hosted variants may adapt URL, authentication, signing, envelope, and framing inside the same semantic family. Cross-family bridges are separate explicitly configured capabilities and never implicit failover.

## 2. Ingress compatibility matrix

| Family | Endpoint | Non-streaming | Streaming |
| --- | --- | :---: | :---: |
| Anthropic Messages | `POST /v1/messages` | yes | SSE |
| OpenAI Chat Completions | `POST /v1/chat/completions` | yes | SSE |
| OpenAI Responses | `POST /v1/responses` | yes | SSE |
| Google Gemini | `POST /v1beta/models/{model}:generateContent` | yes | no |
| Google Gemini | `POST /v1beta/models/{model}:streamGenerateContent?alt=sse` | no | SSE |
| OpenAI Responses | `GET /v1/responses` with WebSocket Upgrade | no | WebSocket when the deployment advertises it |

Gemini streaming requires exactly one `alt=sse` query value. A missing, duplicate, or different `alt` value is rejected rather than silently changing response framing. The OpenAI Responses WebSocket endpoint uses the same `/v1/responses` resource with an HTTP WebSocket upgrade, no OwlRora-required subprotocol, and the version-1 Responses frame contract covered by the running build's fixtures.

The version-1 ingress contract is Anthropic Messages with `anthropic-version: 2023-06-01`, OpenAI Chat Completions and Responses v1 JSON/SSE shapes, Gemini `v1beta` GenerateContent JSON/SSE shapes, and the fixture-backed OpenAI Responses WebSocket frame set. A compatibility claim names the endpoint, this protocol contract, streaming mode, and its tested feature set. Additive native fields are accepted only under the unknown-field rules below; a changed semantic or framing contract requires an explicit registry/version update. Path similarity never implies complete vendor API compatibility. Model listing, files, batches, embeddings, fine-tuning, and token-counting APIs are separate capabilities and are not implied.

## 3. Client authentication and header boundary

Compatibility endpoints accept:

- an OwlRora gateway API key in the protocol's exact credential location; or
- a trusted JWT that resolves a local user and is authorized for `llm:invoke` in the selected organization.

Credential locations are closed:

- OpenAI Chat Completions, OpenAI Responses HTTP/SSE, and Responses WebSocket use `Authorization: Bearer` for either the versioned Gateway key or JWT;
- Anthropic Messages uses `x-api-key` for a Gateway key and `Authorization: Bearer` for a JWT;
- Gemini uses `x-goog-api-key` for a Gateway key and `Authorization: Bearer` for a JWT; the `key` query parameter is accepted only when the deployment explicitly enables the Google query-key compatibility option and is removed before request telemetry.

More than one supported credential location, duplicate credential headers, a Gateway key in the JWT location for Anthropic/Gemini, or a JWT in a provider-key location is a conflicting credential error. Gateway-key prefixes and JWT structure make the shared OpenAI Bearer location unambiguous. Direct JWT requests supply organization context through the configured signed claim or bounded OwlRora header.

Client credentials are never upstream credentials. The gateway discards caller-supplied provider authorization, cloud signatures, cookies, account/project headers, host, and hop-by-hop headers. The selected adapter constructs a fresh upstream header map from:

1. protocol-required headers;
2. the selected `UpstreamCredential` injection policy;
3. explicitly allowlisted safe client headers;
4. endpoint-controlled non-secret headers.

## 4. Native request representation

Each ingress module returns:

```text
NativeRequest {
    family,
    bounded_original_body,
    parsed_envelope,
    validated_headers,
}

LlmIntent {
    requested_model_key,
    streaming,
    required_capabilities,
    requested_output_bound?,
    continuation_reference?,
}
```

The parsed envelope contains only fields required for validation, authorization, routing, size limits, and adapter construction. Prompt and tool content remain in the native payload and are not exposed to the authorization module.

Unknown fields:

- are preserved for a matching transport when safe;
- are rejected when an adapter cannot prove faithful handling;
- are never silently removed, renamed, or reinterpreted.

## 5. Permitted request mutation

Adapters may:

- replace the client route key with the deployment’s upstream model ID;
- construct typed provider paths, versions, project/region identifiers, signatures, and authentication;
- apply a documented route-enforced maximum or default using the native field;
- namespace opaque cache/affinity keys for tenant isolation;
- adapt tested Bedrock, Vertex, or Azure envelopes inside the same semantic family;
- add supported idempotency, tracing, and request identifiers;
- remove prohibited client headers and explicitly unsupported fields for a named transport contract.

They do not silently alter prompts, roles, tools, sampling, safety configuration, structured-output schema, stop sequences, or reasoning controls.

### 5.1 Cache and state isolation

Caller-controlled provider cache or routing identifiers are not forwarded unchanged through an upstream account shared across principals or organizations. When a field is documented as opaque, OwlRora derives a fixed-length domain-separated SHA-256 value over organization ID, authenticated principal kind, `principal_affinity_id`, route ID, field domain, and caller value. `principal_affinity_id` is the local-user ID for JWT traffic or Gateway API key ID for key traffic; creator identity is never substituted.

If namespacing would change documented semantics, the request requires an endpoint/credential isolation policy dedicated to the tenant. Otherwise the capability is rejected.

Provider-generated continuation IDs remain client-visible and use strict authenticated-principal-kind/`principal_affinity_id`-, organization-, route-, protocol-, and origin-qualified storage.

## 6. Anthropic Messages family

`anthropic_messages_native` preserves Anthropic request and SSE semantics while replacing model/auth headers.

`anthropic_messages_bedrock` may:

- apply AWS SigV4;
- construct Bedrock model paths;
- add the required Anthropic version envelope;
- convert AWS event-stream framing to Anthropic-compatible SSE;
- map transport errors and extract usage.

`anthropic_messages_vertex` performs equivalent project/location/auth and tested envelope adaptation for Vertex.

These are Anthropic-family adapters, not generic translation to arbitrary model APIs.

## 7. OpenAI Chat Completions family

Chat Completions transports preserve request JSON and SSE semantics. Azure adaptation may replace deployment paths, API versions, and authentication while retaining the Chat Completions contract.

A Chat Completions request is not routed to a Responses-only deployment unless a separately specified bridge is configured.

## 8. OpenAI Responses family

Responses transports preserve item types, tools, reasoning items, event ordering, usage, and continuation semantics.

For `previous_response_id` or equivalent provider state:

- route namespace and caller authorization are resolved first;
- after request-level overload/rate/concurrency admission, the versioned origin target, deployment, endpoint, transport kind, and credential account identity are resolved before ordinary target ordering or target-specific admission;
- organization, authenticated principal kind, `principal_affinity_id`, route, and protocol must match the creator;
- a continuation never moves to another target or a changed upstream security domain;
- a newly exposed state ID is not sent downstream until the origin binding is durable;
- a missing, changed, or unavailable origin returns `state_origin_unavailable` rather than guessing.

Responses WebSocket is a separate capability on `GET /v1/responses` with WebSocket Upgrade. The initial HTTP request performs authentication, organization qualification, route authorization, and connection admission; every client turn then derives a fresh bounded native intent and revalidates the captured route/principal policy against a current generation before dispatch. One downstream connection pins one compatible upstream connection when provider state can be connection-local. Failover is possible only before any upstream event is exposed and only for replay-safe frames without prior state. The connection uses no OwlRora-required WebSocket subprotocol; unknown requested subprotocols are rejected rather than echoed.

## 9. OpenAI Codex subscription

Codex subscription is a dedicated Responses transport, not a general subscription adapter.

### 9.1 Community-maintained upstream contract

Codex subscription support is a best-effort community feature rather than a provider compatibility guarantee. Its endpoint, auth, headers, and request patches live in one built-in adapter and may evolve with OwlRora updates without creating managed profile resources or deployment migrations. Additive upstream fields are handled defensively; a contract OwlRora no longer understands makes only Codex unavailable with a sanitized diagnostic.

The adapter uses fixed OpenAI-controlled locations:

```text
issuer:           https://auth.openai.com
user-code:        /api/accounts/deviceauth/usercode
device-token:     /api/accounts/deviceauth/token
oauth-token:      /oauth/token
verification:     https://auth.openai.com/codex/device
Responses base:   https://chatgpt.com/backend-api/codex
Responses HTTP:   /responses
```

Administrators cannot override these URLs through ordinary endpoint configuration. Version 1 advertises Codex subscription only for Responses HTTP/SSE; it does not route Codex credentials through the generic Responses WebSocket transport. Any future Codex WebSocket support requires a distinct accepted transport contract and fixtures. Community maintainers update this centralized adapter and its fixtures as the upstream contract changes; OwlRora does not promise long-term compatibility with an undocumented consumer backend.

### 9.2 Device authorization and credential state

The management flow:

1. creates a bounded one-time login session and requests a device/user code;
2. stores provider `device_code`, polling bearer, and any other recoverable login secret as a short-lived envelope-encrypted secret;
3. shows the verification URL and user-facing code once;
4. polls only through an explicit complete/poll command with provider-directed interval and `slow_down` handling;
5. exchanges the authorization code for OAuth tokens;
6. stores token material through the encrypted secret service;
7. records safe account metadata, advances the account `state_identity_version` when it changed, and activates the credential;
8. publishes its new credential version and physically deletes no-longer-needed login-secret ciphertext from the active database.

The credential has independent `administrative_status = active | disabled` and Codex `auth_lifecycle_state = unauthenticated | login_pending | active | refreshing | refresh_error | refresh_outcome_unknown | expired | revoked`. It is routable only when administrative status and auth lifecycle are both `active`. Login-session states are `pending`, `completed`, `expired`, `cancelled`, and `failed`; terminal cleanup physically deletes every no-longer-needed polling-secret ciphertext from the active database while retaining only safe lifecycle/audit metadata. Backup copies age out under the documented backup-retention policy; OwlRora does not claim per-secret cryptographic erasure under the shared environment root.

### 9.3 Refresh concurrency

Refresh uses a PostgreSQL compare-and-swap attempt over credential version, token fingerprint, and a unique monotonically fenced lease token:

- one worker persists `refreshing` with a unique attempt ID and lease token before using the refresh token;
- the lease duration exceeds the provider hard network deadline plus a bounded database-commit margin;
- provider network I/O occurs outside the transaction and is cancelled before the lease margin;
- success or explicit failure commits only while the exact lease token, credential version, and old fingerprint still match;
- a newer login or manual replacement fences out stale refresh results;
- an attempt that may have reached the provider but did not commit a known local result becomes `refresh_outcome_unknown` when its lease is lost; another worker does not replay that refresh token;
- automatic recovery is allowed only when the currently supported adapter contract has evidence that refresh-token reuse or a fixed upstream idempotency identity is safe;
- terminal refresh errors mark the credential expired; known transient failures enter `refresh_error` with bounded backoff; unknown outcomes require reauthentication.

Workers query only credentials due for refresh using indexed `next_refresh_at` state and bounded claims. Every gateway node does not scan the full credential table.

A request may force one refresh after an explicit pre-commit upstream authentication rejection only when the Responses request is safely replayable. Ambiguous sends, continuation requests, and committed streams are not replayed merely because a token may have expired.

### 9.4 Codex request adaptation

The adapter builds:

```http
Authorization: Bearer <runtime_access_token>
ChatGPT-Account-ID: <account_id>  # when required
```

It may also derive one organization/authenticated-principal/route-namespaced session identity for `session_id`, `x-client-request-id`, and `prompt_cache_key` when the upstream contract uses them. The principal component is the typed `principal_affinity_id`, never a Gateway key creator.

For the currently supported Codex Responses behavior, the adapter:

- replaces `model` with the selected upstream model;
- preserves native input, tools, reasoning, continuation, and unknown safe fields;
- ensures `instructions` is a string, using the documented empty default when absent;
- removes `max_output_tokens` only while the current Codex backend rejects that field;
- does not inject Chat Completions `stream_options`;
- keeps every such patch centralized and covered by community-maintained transport fixtures.

A Codex subscription credential is ineligible for Chat Completions, ordinary OpenAI API endpoints, or any non-Codex provider. OwlRora has no Anthropic, Google, or other provider-subscription credential type.

## 10. Google Gemini family

Gemini ingress extracts the route key from the model path and substitutes the selected upstream model identifier. Direct Gemini and Vertex transports differ in authentication and resource paths but share only capabilities demonstrated by adapter tests.

Gemini requests and JSON/SSE responses remain Gemini-native. OwlRora does not implicitly convert OpenAI or Anthropic tools/messages into Gemini semantics.

## 11. Capability extraction

Protocol modules detect at least:

- streaming;
- tools, tool choice, and parallel tool use;
- LLM multimodal input including image, audio, and documents;
- structured output and JSON schema;
- system/developer instruction behavior;
- prompt caching;
- reasoning controls and opaque state;
- continuation references;
- output bounds;
- beta or extension fields affecting semantics.

Eligibility requires matching transport/deployment capabilities for all detected requirements.

## 12. Streaming and response commitment

The gateway incrementally parses upstream frames with bounded bytes, frames, time, and queues. It does not buffer a complete stream.

A response is uncommitted until downstream status/headers and first body bytes are sent. A small bounded prefix may be held to classify immediate upstream errors. After commitment:

- all bytes come from one attempt;
- retry and failover are forbidden;
- truncation terminates the stream without manufacturing a success event;
- cancellation and usage settlement are best effort and conservative.

Downstream backpressure propagates to upstream reads. Client disconnect cancels upstream work where supported but does not prove the provider incurred no cost.

## 13. Usage and errors

Each attempt extracts typed usage with optional token/cache/reasoning/provider-unit fields and a `complete`, `partial`, or `absent` marker. Missing usage is unknown rather than zero. Repeated cumulative streaming counters are not blindly summed.

Internal errors distinguish caller validation, authorization/admission, route availability, upstream transport, upstream protocol, and post-commit interruption. The ingress module renders the expected protocol envelope and sanitizes endpoint, credential, account, network, and provider-internal details.

## 14. Time, size, and replay bounds

Every route bounds headers, body, parsed complexity, output, connection, response-header, non-streaming total, stream idle, stream duration, buffers, and response size.

Caller idempotency keys are forwarded only to transports with compatible semantics. OwlRora does not claim exactly-once LLM execution. A retry after an ambiguous upstream send may duplicate work and cost, and the attempt record preserves that uncertainty.
