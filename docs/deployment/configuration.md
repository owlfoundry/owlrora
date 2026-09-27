# Server configuration

::: warning Release boundary
This page follows repository `main`. Confirm that the selected server release contains these settings, and keep every process in one deployment on a compatible server release.
:::

`owlrora-server` reads environment variables once at startup. Empty values count as unset. Configuration is strict: **any unknown variable whose name begins with `OWLRORA_` causes startup to fail**.

Do not inject CLI-only variables such as `OWLRORA_SERVER_URL` or `OWLRORA_MANAGEMENT_API_KEY` into the server container.

## Required settings by profile

| Variable                                     |   `full` | `management` | `gateway` | `worker` | `health-only` |
| -------------------------------------------- | -------: | -----------: | --------: | -------: | ------------: |
| `OWLRORA_DATABASE_URL`                       | required |     required |  required | required |       ignored |
| `OWLRORA_REDIS_URL`                          | required |     required |  required | required |       ignored |
| `OWLRORA_PUBLIC_ORIGIN`                      | required |     required |        no |       no |       ignored |
| `OWLRORA_SEED_ADMIN_API_KEY`                 | required |     required |        no |       no |       ignored |
| `OWLRORA_SECRET_ROOT` in the official binary | required |     required |  required | required |            no |

`OWLRORA_SECRET_ROOT` is syntactically optional in the library configuration because a custom statically linked server may provide another custody write pair. The official `owlrora-server` binary always selects bundled software custody and fails startup without the root for every non-health-only profile.

## Identity, network, and storage

| Variable                    | Default                                         | Contract                                                                                                                 |
| --------------------------- | ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `OWLRORA_ADDR`              | binary: `127.0.0.1:8080`; image: `0.0.0.0:8080` | Valid socket address. Prefer a private or loopback bind behind TLS termination.                                          |
| `OWLRORA_PROFILE`           | `full`                                          | `full`, `management`, `gateway`, `worker`, or `health-only`.                                                             |
| `OWLRORA_DATABASE_URL`      | none                                            | SQLx PostgreSQL connection string. Usually contains a secret. Required outside `health-only`.                            |
| `OWLRORA_REDIS_URL`         | none                                            | One `redis://` or `rediss://` URL with a host and no query/fragment. Required outside `health-only`.                     |
| `OWLRORA_PUBLIC_ORIGIN`     | none                                            | Exact browser-visible origin. Credentials, path, query, and fragment are forbidden. Non-loopback origins must use HTTPS. |
| `OWLRORA_OPERATOR_NETWORKS` | `127.0.0.0/8,::1/128`                           | Comma-separated IPv4/IPv6 CIDRs; at least one. Evaluated against the direct TCP peer for protected diagnostics.          |

Replicas have no durable OwlRora application identity. Runtime publication and process counters are local evidence, Redis allowance grants use globally unique grant IDs, and active probes use short lease tokens. Identical replicas may use the same configuration and do not require stable names or StatefulSet ordinals.

## Deployment secrets

| Variable                     | Format                              | Contract                                                                                                                       |
| ---------------------------- | ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `OWLRORA_SEED_ADMIN_API_KEY` | `owlrora_mgmt_v1.<lookup>.<secret>` | High-entropy, canonical base64url fields without padding. Full-scope built-in management key; never stored in PostgreSQL.      |
| `OWLRORA_SECRET_ROOT`        | canonical base64url without padding | Must decode to exactly 32 bytes. Root for versioned authenticated software secret envelopes and immutable installation-ID AAD. |

Server debug output redacts database/Redis URLs and secret identity. Environment visibility remains an operating-system/container responsibility.

## Connection pools and coordination timeouts

| Variable                                    | Default | Allowed range | Unit                    |
| ------------------------------------------- | ------: | ------------: | ----------------------- |
| `OWLRORA_DATABASE_MAX_CONNECTIONS`          |    `16` |         2–128 | connections per process |
| `OWLRORA_REDIS_POOL_SIZE`                   |     `8` |         1–128 | connections per process |
| `OWLRORA_REDIS_CONNECT_TIMEOUT_MILLIS`      |   `500` |     50–30,000 | milliseconds            |
| `OWLRORA_REDIS_COMMAND_TIMEOUT_MILLIS`      |   `250` |     10–10,000 | milliseconds            |
| `OWLRORA_POLICY_ACTIVATION_TIMEOUT_SECONDS` |    `30` |         5–600 | seconds                 |
| `OWLRORA_POLICY_RETIREMENT_GRACE_SECONDS`   |    `60` |       5–3,600 | seconds                 |

Pool limits multiply by the maximum concurrent process count. Do not size one replica in isolation.

## Sessions and runtime security

| Variable                                    |  Default | Allowed range | Unit    |
| ------------------------------------------- | -------: | ------------: | ------- |
| `OWLRORA_SESSION_LIFETIME_SECONDS`          | `28,800` |   300–604,800 | seconds |
| `OWLRORA_MAX_SECURITY_SNAPSHOT_AGE_SECONDS` |     `30` |         5–300 | seconds |

The security snapshot age is an admission fail-closed bound, not a runtime publication poll interval. Increasing it expands the period in which a process may serve a stale authorization snapshot.

## Readiness and shutdown

| Variable | Default | Contract |
| --- | --- | --- |
| `OWLRORA_REQUIRED_ROUTE_IDS` | unset | Comma-separated exact route UUIDs. Every named route must be structurally callable with a current client; unknown IDs fail readiness. No live provider call is made. |
| `OWLRORA_SHUTDOWN_REQUEST_TIMEOUT_SECONDS` | `15` | 1–300 seconds from drain start for ordinary HTTP and pre-header work. |
| `OWLRORA_SHUTDOWN_STREAM_TIMEOUT_SECONDS` | `30` | 1–3,600 seconds from drain start for committed SSE and upgraded WebSocket work. |
| `OWLRORA_SHUTDOWN_WORKER_TIMEOUT_SECONDS` | `10` | 1–300 seconds for bounded worker settlement/usage flush. |

All non-health-only profiles expose coarse `/ready`. It becomes unavailable during drain; `/health` remains liveness. See [Production operations](/deployment/operations) for ownership, final telemetry flush, and orchestrator grace.

## Usage aggregation

| Variable                               | Default | Allowed range | Unit           |
| -------------------------------------- | ------: | ------------: | -------------- |
| `OWLRORA_USAGE_FLUSH_INTERVAL_SECONDS` |     `5` |         1–300 | seconds        |
| `OWLRORA_USAGE_MAX_AGGREGATE_KEYS`     | `4,096` | 128–1,000,000 | in-memory keys |
| `OWLRORA_USAGE_MAX_PENDING_BATCHES`    |    `16` |       1–1,024 | batches        |

These are bounded reliability controls. Reaching a bound produces protected loss/pending evidence; it must not be tuned away without memory and failure-mode analysis.

## Gateway process capacities

| Variable                                    | Default | Allowed range | Scope                             |
| ------------------------------------------- | ------: | ------------: | --------------------------------- |
| `OWLRORA_GATEWAY_MAX_IN_FLIGHT`             | `4,096` |   1–1,000,000 | all attempts in one process       |
| `OWLRORA_GATEWAY_ENDPOINT_MAX_IN_FLIGHT`    |   `512` |   1–1,000,000 | endpoint in one process           |
| `OWLRORA_GATEWAY_CREDENTIAL_MAX_IN_FLIGHT`  |   `512` |   1–1,000,000 | credential binding in one process |
| `OWLRORA_GATEWAY_DEPLOYMENT_MAX_IN_FLIGHT`  |   `256` |   1–1,000,000 | deployment in one process         |
| `OWLRORA_GATEWAY_WEBSOCKET_MAX_CONNECTIONS` | `1,024` |   1–1,000,000 | WebSockets in one process         |

These process-local protections complement distributed Redis policies. They are not global fleet quotas.

## Compatibility options

| Variable                                 | Default | Contract                                                                                                                                                              |
| ---------------------------------------- | ------: | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `OWLRORA_GEMINI_QUERY_KEY_COMPATIBILITY` | `false` | Boolean. Allows a Gemini query credential for clients that cannot send an authorization header. URLs may be logged by intermediaries; leave disabled unless required. |

## Logging

`RUST_LOG` uses `tracing_subscriber::EnvFilter` syntax and defaults to `info`.

```bash
RUST_LOG=owlrora_server=info,tower_http=warn
```

Logs are structured JSON on standard output. They are separate from OTLP and must not be configured to capture request bodies or secrets.

## OpenTelemetry

| Variable | Default | Contract |
| --- | --- | --- |
| `OWLRORA_OTLP_ENDPOINT` | unset (disabled) | Operator-controlled HTTP(S) collector base URL, without URL credentials, query, or fragment. Appends `/v1/traces` and `/v1/metrics`. Ignored by `health-only`. |
| `OWLRORA_TRACE_SAMPLE_RATIO` | `0.1` | Finite 0–1 root sampling probability; child spans follow their parent. Metrics and compact usage are not sampled. |

The source exports standard OTLP/HTTP protobuf using SDK-owned batch and periodic workers. There is no collector round trip on a request task. Untrusted inbound trace context and baggage are ignored; a gateway logical request starts a new trace and upstream attempt spans share its parent. No trace headers are injected into provider requests. No body, header, query, tenant/key/user ID, model name, or arbitrary URL is exported by this instrumentation.

Exported instruments currently include:

- `owlrora.gateway.facts`, `.duration` (seconds), `.units`, `.cost` (USD nanos), `.unknown_cost`, and `.active`, separated by logical/attempt family, protocol, and bounded outcome;
- `owlrora.gateway.http_responses`, `.http_response_headers` (seconds until response headers, not total stream duration), and `.http_bytes` (HTTP body bytes polled), including pre-admission HTTP rejections;
- `owlrora.runtime.revision` and `.confirmation_age` (milliseconds);
- `owlrora.usage.pending_batches` and `.lost_facts`;
- `owlrora.telemetry.outstanding_spans`, `.dropped_spans` by queue/export reason, and `.metric_export_failures`.

Do not sum logical and attempt facts or costs together. Attempt cost captures each physical attempt; logical evidence describes the client-visible result. Floating-point metric cost is display evidence, not budget authority. Native WebSocket turns contribute logical/attempt metrics; HTTP byte counters do not measure upgraded frames. Fine-grained connect/first-content/coordination latency, per-circuit transitions, and the remaining target signal inventory are not yet exported.

Traces allow at most 512 queued plus in-flight spans and 128 spans per batch, with a one-second scheduled flush. Overflow drops the newest span. HTTP transport timeout is 500 milliseconds; a failed export can retry once with bounded backoff within a 500-millisecond retry budget (an already-started HTTP attempt can extend that budget by at most one transport timeout). Failed batches are counted and discarded, not persisted. Metrics use bounded SDK cardinality and cumulative aggregation, exporting every ten seconds; a failed export loses that observation but a later cumulative snapshot can recover counter totals. Histograms do not guarantee recovery of every missed observation interval.

Providers shut down after request owners and usage workers, with a five-second wait per signal. Protected `system operations telemetry` exposes queue, dropped/export-failed, completed-export, and shutdown-failure evidence without revealing the collector URL or headers. Collector failure never makes readiness fail.

Use TLS for remote collectors; loopback/plain HTTP is suitable for a local collector sidecar. Redirects and implicit HTTP proxies are disabled. The SDK also accepts its standard `OTEL_EXPORTER_OTLP[_TRACES|_METRICS]_HEADERS` operator environment settings for collector authentication. Keep those secrets outside command lines/logs. Explicit OwlRora endpoint/protocol/timeout settings take precedence over the corresponding SDK defaults; do not assume arbitrary `OTEL_*` variables are OwlRora configuration.

## Dynamic upstream credential environment

An upstream credential may reference an environment variable by name. Those names are stored as credential source configuration and resolved in each process that builds the credential client.

Dynamic names must:

- be at most 128 characters;
- contain only uppercase ASCII letters, digits, and `_`;
- not start with a digit.

Do not prefix a dynamic credential variable with `OWLRORA_`, because the fixed server allowlist will reject it before runtime compilation. Workload/default-chain AWS and Google credentials may also consume their provider SDK's standard environment or files; consult the corresponding provider credential contract rather than assuming a closed list here.

## Development Compose variables

The following variables configure `dev/compose.yml` only and must not be injected into the server process:

- `OWLRORA_DEV_POSTGRES_HOST`
- `OWLRORA_DEV_POSTGRES_PORT`
- `OWLRORA_DEV_POSTGRES_DB`
- `OWLRORA_DEV_POSTGRES_USER`
- `OWLRORA_DEV_POSTGRES_PASSWORD`
- `OWLRORA_DEV_REDIS_HOST`
- `OWLRORA_DEV_REDIS_PORT`
