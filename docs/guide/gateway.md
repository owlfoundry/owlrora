# Gateway plane

The Gateway plane accepts protocol-native LLM requests, resolves the client-facing model to a first-class route, applies distributed admission and reliability policy, and dispatches to a compatible upstream transport.

::: warning Release boundary
Confirm that the selected server release contains these Gateway surfaces, then pin its image by immutable digest. This page follows repository `main` and can be newer than a selected binary.
:::

## Ingress endpoints

| Client protocol            | Endpoint                                                    | Streaming            |
| -------------------------- | ----------------------------------------------------------- | -------------------- |
| Anthropic Messages         | `POST /v1/messages`                                         | SSE when requested   |
| OpenAI Chat Completions    | `POST /v1/chat/completions`                                 | SSE when requested   |
| OpenAI Responses           | `POST /v1/responses`                                        | HTTP or SSE          |
| OpenAI Responses WebSocket | `GET /v1/responses` with WebSocket upgrade                  | bidirectional stream |
| Google Gemini              | `POST /v1beta/models/{model}:generateContent`               | no                   |
| Google Gemini              | `POST /v1beta/models/{model}:streamGenerateContent?alt=sse` | SSE                  |

The OpenAI and Anthropic model is read from the native request body. Gemini uses the native model path. The selected client-facing name resolves directly to a route; there is no model-alias layer.

## Authentication

### Gateway API keys

Send a Gateway API key as a bearer token:

```http
Authorization: Bearer owlrora_llm_v1.<lookup>.<secret>
```

Gateway keys are organization resources. Each key has:

- a non-empty allowlist of stable route IDs;
- one finite overall key budget;
- optional rate and concurrency policy;
- revocation and expiration state.

The creator user is never copied into request attribution.

### Gemini query-key compatibility

Gemini clients sometimes place credentials in a query parameter. This is disabled by default because URLs are more likely to be logged. Set `OWLRORA_GEMINI_QUERY_KEY_COMPATIBILITY=true` only when a client cannot use an authorization header. OwlRora removes the query credential before internal processing and treats it as sensitive, but upstream proxies may already have observed the original URL.

### Qualified direct JWT traffic

An explicitly configured direct-JWT issuer may authorize Gateway traffic without fabricating a Gateway key. This traffic is observed, but it is not charged to a fake key budget. Issuer policy, organization ceilings, route grants, and protocol constraints still apply.

## Native request examples

### OpenAI Chat Completions

```bash
curl --fail-with-body https://owlrora.example.com/v1/chat/completions \
  -H "Authorization: Bearer $OWLRORA_GATEWAY_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{
    "model": "support-chat",
    "messages": [{"role": "user", "content": "Hello"}]
  }'
```

### Anthropic Messages

```bash
curl --fail-with-body https://owlrora.example.com/v1/messages \
  -H "Authorization: Bearer $OWLRORA_GATEWAY_API_KEY" \
  -H 'Content-Type: application/json' \
  -H 'anthropic-version: 2023-06-01' \
  -d '{
    "model": "support-claude",
    "max_tokens": 256,
    "messages": [{"role": "user", "content": "Hello"}]
  }'
```

### Gemini

```bash
curl --fail-with-body \
  "https://owlrora.example.com/v1beta/models/support-gemini:generateContent" \
  -H "Authorization: Bearer $OWLRORA_GATEWAY_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"contents":[{"parts":[{"text":"Hello"}]}]}'
```

Gemini streaming requires exactly one `alt=sse` query parameter:

```bash
curl --no-buffer --fail-with-body \
  "https://owlrora.example.com/v1beta/models/support-gemini:streamGenerateContent?alt=sse" \
  -H "Authorization: Bearer $OWLRORA_GATEWAY_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"contents":[{"parts":[{"text":"Hello"}]}]}'
```

## Routing and reliability

For each logical request OwlRora:

1. Captures one immutable runtime generation.
2. Validates protocol, key/JWT authority, route allowlist, and request bounds.
3. Applies key-level rate and concurrency policy.
4. Selects an operational target by priority tier and weight.
5. Reserves both key budget and the organization budget for that target's actual origin.
6. Applies target timeout overrides, endpoint network policy, credential injection, and protocol-matching transport.
7. Retries or fails over only when the reliability policy permits it.
8. Settles the physical attempt and emits logical/attempt usage independently.

Stickiness is a routing hint, not an authorization or budget bypass. Health/circuit state can exclude a sticky target.

## Origin accounting

Every physical Gateway-key attempt consumes exactly one organization origin pool:

- `system_provided` for a deployment-owned target granted to the organization;
- `organization_byok` for an organization-owned target.

Mixed routes may fail over between these classes. Settlement always follows the target actually attempted, not the route's first target or provider name.

## Provider and credential boundaries

OwlRora preserves matching semantic families rather than translating every request through one universal model. Upstream deployments may use static secret injection, workload/default-chain credentials, AWS SigV4, Azure Entra access tokens, Google OAuth token exchange, or the explicitly modeled OpenAI Codex subscription credential.

The Codex adapter is community-maintained, best-effort, and valid only for the OpenAI Responses semantic family. It is not a generic provider-subscription framework.

## Failure and usage semantics

OwlRora separates:

- logical request outcome;
- each physical attempt;
- definitely-not-dispatched failures;
- ambiguous pre-header failures;
- actual upstream responses;
- stream completion or interruption.

This prevents retries, failovers, connector errors, and partial streams from being collapsed into misleading single-request usage. Built-in aggregates remain compact; OwlRora does not synchronously persist raw request or response bodies on the data path.
