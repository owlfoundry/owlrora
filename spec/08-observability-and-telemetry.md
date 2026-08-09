# Observability and telemetry

## 1. Observability boundary

OwlRora provides two complementary views:

1. **Built-in management observability** — configuration health, compact tenant usage, budget state, recent aggregate outcomes, and actionable gateway status.
2. **External operational observability** — standard OpenTelemetry metrics, traces, and events exported to a collector and viewed in systems such as Prometheus/Grafana, Tempo, Jaeger, or vendor backends.

The built-in console is not a telemetry backend. OpenTelemetry is not the source of budget enforcement truth. Neither path stores prompts or responses by default.

## 2. Privacy-by-default data classes

### 2.1 Forbidden by default

The following MUST NOT appear in logs, metrics, spans, events, audit records, panic reports, or error bodies by default:

- prompt, message, tool argument, response, output, file, or image contents;
- full request or response bodies;
- management API key, gateway API key, upstream secret, OAuth token, JWT, cookie, cloud signature, or authorization header;
- raw provider-side state/conversation identifiers;
- arbitrary caller headers or query strings;
- secret configuration or raw provider credentials.

### 2.2 Safe structured metadata

Allowed metadata includes bounded values such as:

- generated request and attempt IDs;
- protocol family and endpoint operation;
- route/deployment/endpoint IDs under the applicable cardinality policy;
- organization/user/gateway-key opaque IDs in restricted traces/events, never default metrics labels;
- status/classification, attempt number, retry/failover reason;
- token/unit counts, known cost, latency phases, streaming flags;
- snapshot/pricing/policy versions;
- body byte counts, not contents.

### 2.3 Optional content capture

OwlRora does not capture prompts or responses. Any content-capture product would require a separate specification covering per-organization opt-in, purpose, encryption, redaction, retention, access audit, export controls, deletion, and provider terms. A generic debug log switch MUST NOT enable content capture.

## 3. Signal model

### 3.1 Metrics

Metrics answer fleet health and performance questions with low-cardinality labels.

Required metric families include:

- accepted/rejected logical requests;
- upstream attempts by outcome category;
- retry and failover counts;
- request, time-to-first-byte, upstream phase, and stream-duration histograms;
- active requests and streams;
- request/response bytes;
- token and known-cost counters;
- unknown-usage/cost counters;
- rate, concurrency, and budget denials;
- circuit state transitions and open-target gauge;
- runtime generation version/age/refresh failures;
- coordinator operation latency/errors and policy-activation state/deadline;
- aggregate and telemetry queue depth/drops/flush failures;
- upstream endpoint/client pool and timeout signals.

Default labels MAY include protocol family, operation, streaming, broad outcome, endpoint adapter kind, transport kind, and gateway node/region. They MUST NOT include organization ID, user ID, gateway-key ID, request ID, session ID, raw model key, arbitrary upstream model ID, URL, or error message.

A deployment MAY explicitly enable bounded route/deployment labels after evaluating catalog cardinality. Dynamic tenant route names remain disallowed as default metrics labels.

### 3.2 Traces

A logical request trace SHOULD contain:

- one server span for ingress and policy/routing summary;
- one child span per upstream attempt;
- coordination spans only when sampled and useful;
- events for retry, failover, response commitment, cancellation, and settlement anomaly.

Trace attributes follow OpenTelemetry semantic conventions where applicable and use an `owlrora.*` namespace for domain fields.

Trace context from untrusted clients is accepted only under configured policy and size limits. OwlRora creates a new trace when context is invalid. Baggage is dropped by default and never forwarded blindly to providers.

Opaque tenant identifiers MAY appear on sampled restricted traces if enabled by the operator. Otherwise tenant identifiers are omitted rather than transformed through another managed secret.

### 3.3 Structured events/logs

Application logs are operational events, not request records. Required events include:

- startup/readiness/shutdown transitions;
- snapshot publication/application failure;
- endpoint/deployment validation and circuit transitions;
- Redis allowance degradation, emergency-grant use/stranding, recovery-generation installation, and durable bounded recovery-allowance authorization;
- background queue overflow/persistence failure;
- security-sensitive configuration changes via the audit subsystem;
- invariant violations and sanitized unexpected errors.

Each event has a stable event name and typed fields. Error strings are supplemental and MUST NOT be the only machine-readable classification.

Per-request completion logging is disabled by default. A sampled metadata-only completion event MAY be enabled with cardinality and privacy limits.

## 4. Request and attempt evidence

Telemetry distinguishes one logical request from one or more provider attempts. Built-in aggregation uses separate logical-request and provider-attempt facts; attempt rows MUST NOT be summed as logical request counts.

### 4.1 Logical request outcome

A logical request records:

- admission result;
- protocol/operation/streaming mode;
- total duration and time to downstream commitment;
- route ID and snapshot version under trace/event policy;
- attempt count and final serving attempt;
- final client-visible outcome classification;
- aggregate usage/cost across attempts;
- usage and local/distributed allowance settlement completeness.

### 4.2 Attempt outcome

An attempt records:

- target, deployment, endpoint, and transport;
- candidate/attempt number and retry/failover cause;
- connection, response-header, first-byte, body/stream duration;
- status and internal category;
- whether provider acceptance was ambiguous;
- whether downstream response committed from this attempt;
- provider usage completeness and calculated cost;
- cancellation result where known.

A failed attempt is not erased because a later attempt succeeded.

## 5. OpenTelemetry export

OTLP export supports standard gRPC and/or HTTP transports through configuration. Export is asynchronous with:

- bounded queues;
- bounded batches and export timeouts;
- retry/backoff inside a fixed memory/time budget;
- no blocking network export on the data-plane response path;
- explicit drop counters by signal and reason;
- graceful shutdown flush with a bounded deadline.

When the collector is unavailable, OwlRora continues serving requests until another required dependency fails. It drops oldest or newest telemetry according to a documented per-signal policy rather than growing memory without bound.

Metrics aggregation occurs in the SDK/process and exports periodically. There is no per-request collector round trip.

## 6. Sampling

- Metrics are aggregated, not sampled as individual request records.
- Parent-based probabilistic trace sampling is the baseline.
- Errors and high-latency requests MAY use tail-aware sampling only in the external collector, because in-process unbounded tail buffering is not acceptable.
- OwlRora MAY add a bounded decision hint for important errors, but cannot guarantee external retention.
- Sampling decisions MUST NOT depend on prompt content.
- Organization-specific sampling overrides, if enabled, are system policy with strict maximums and do not alter budget/usage accounting.

## 7. Built-in observability data

Built-in views use:

- versioned control-plane configuration and validation results;
- desired/staged/armed/active/finalized policy generations, prior-generation cutoff, and current local/distributed allowance, rate, and concurrency state;
- sparse hourly/daily usage aggregates;
- bounded process health snapshots;
- immutable administrative audit records.

They do not query an internal raw request table because none exists by default.

### 7.1 System dashboard

The system dashboard SHOULD show:

- gateway node/readiness and snapshot freshness;
- request/attempt outcome and latency summaries over bounded recent buckets;
- endpoint/deployment health, open circuits, and validation state;
- allowance coordinator generation, pending activation deadline, calculated drift bound, emergency cohort use, recovery authorization, and persistence pipeline health;
- aggregate top routes/deployments/endpoints by volume/cost under bounded queries;
- telemetry collector/export status and dropped-signal counts;
- configuration changes requiring attention.

Whole-fleet real-time deep analysis belongs in the external observability stack. The console links or documents the configured collector/dashboard integration rather than replicating Grafana.

### 7.2 Organization dashboard

An organization view SHOULD show only that tenant’s:

- each Gateway key's desired/pending/active overall policy and each organization system-provider/BYOK origin pool, with enforcing versus record-only mode, approximate allowance state, and separate drift/recovery status;
- request, token, cost, failure, retry, and latency aggregate trends;
- breakdown by user, Gateway key, route, target origin, and safe deployment/endpoint labels;
- unknown usage/cost warnings;
- active key and policy health.

No tenant can query another tenant’s dimensions or infer system-wide provider credential details.

## 8. Latency semantics

Latency measurements use monotonic clocks in process and define:

- `admission_duration` — authentication through rate/concurrency/allowance admission;
- `queue_duration` — bounded local/provider wait, if any;
- `connect_duration`;
- `response_header_duration`;
- `time_to_first_upstream_content`;
- `time_to_downstream_commit`;
- `upstream_duration`;
- `stream_duration`;
- `total_duration`.

Retries produce per-attempt timings and a logical total. Histograms use explicit units and stable bucket strategies suitable for both non-streaming and long streaming requests.

## 9. Usage and cost semantics

Telemetry and built-in aggregates use the same typed usage/cost event produced by protocol extraction and settlement. They MUST NOT independently recalculate cost from mutable current prices.

Required distinctions:

- known zero vs unknown cost;
- logical request count vs attempt count;
- served attempt vs failed/superseded attempt;
- provider-reported complete, partial, or absent usage;
- reserved, settled actual, or conservatively settled cost;
- cache input and other provider dimensions where available.

Monetary metric export SHOULD use a documented base unit such as cost nanos or USD decimal histogram strategy. Floating-point metric display is not the enforcement source of truth.

## 10. Audit versus telemetry

Audit and telemetry have different guarantees:

| Property | Audit | Telemetry |
| --- | --- | --- |
| purpose | security/accountability for management changes | operations/performance/diagnosis |
| durability | durable PostgreSQL record | best-effort external export/bounded buffers |
| sampling | never for required actions | allowed |
| request volume | no normal per-request records | aggregated/sampled |
| tenant IDs | explicit where required | cardinality/privacy controlled |
| content/secrets | forbidden | forbidden by default |

Telemetry failure does not roll back a management command whose required audit record committed transactionally. Every accepted management command has durable audit evidence; ordinary management queries, audit queries, and protected diagnostic `GET`s do not create per-request audit rows and use bounded request metadata/telemetry instead. Every accepted seed-administrator command uses the stable `seed_admin` user, fixed management-key identity, and direct-key or key-session method in unsampled audit evidence; it never records `seed_admin_key_version_id`. Other management-key commands record the durable safe key resource ID, deployment/organization resource scope, non-secret secret-version row ID, and key principal; `created_by_principal` remains separate creation metadata and is never reported as the current actor. A rejected key attempt records only the attempted credential class without claiming an authenticated actor. Raw keys, reusable digests, CLI/MCP secret inputs, and one-time results never appear.

## 11. Internal diagnostics

Typed protected diagnostics under `/api/v1/system/operations/**` MAY expose:

- process build/version and uptime;
- readiness dependency state;
- applied snapshot versions/ages;
- queue sizes and drop counters;
- connection-pool and circuit summaries;
- recent sanitized invariant errors.

It MUST require `management:operations` plus `management:read`, current system-administrator authority, and the configured operator-network policy. It uses the normal versioned management envelope and descriptor and MUST NOT expose heap contents, environment variables, secrets, raw headers, request bodies, or per-tenant request lists. Diagnostic queries create no durable per-request audit record; any recovery or mutation under the same route family additionally requires `management:write` and commits the normal command audit record.

## 12. Failure and overload behavior

- Telemetry channel sends are non-blocking or strictly bounded.
- Cardinality guards reject or collapse unknown dynamic labels.
- Aggregate queue overflow increments a loss counter and emits a rate-limited error; it does not allocate indefinitely.
- Logging sinks use backpressure/drop policy independent of request tasks.
- Repeated identical errors are rate-limited while preserving counters.
- Panic/error hooks sanitize values before emission.
- Collector endpoints are operator configuration and use network/TLS policy; callers cannot redirect telemetry.

## 13. Observability boundaries

OwlRora does not provide prompt/response capture or replay, a raw request explorer, a distributed trace store, a Prometheus/Tempo/Grafana replacement, tenant-defined arbitrary metric dimensions, lossless telemetry delivery, or whole-fleet latency-driven route selection.

Built-in console views use tenant-qualified compact aggregates. Whole-fleet real-time analysis, long-retention traces, and custom dashboards belong to standard external telemetry systems.
