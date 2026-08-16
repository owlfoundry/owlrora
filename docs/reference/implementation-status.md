# Implementation status

This page separates OwlRora's normative target design from released binaries and current source implementation.

**Audit baseline:** repository `main`, reviewed against all chapters under `spec/` and `spec/ui/` on 2026-08-16. The Phase 2 implementation baseline entered `main` at `da261139144b6bcb5af0624bb4693e445eeedf40`; this audit also includes the later stateless-replica cleanup documented in current source.

## Verdict

The answer to “is the complete target specification implemented?” is **no**.

Phase 2 delivers a substantial end-to-end Gateway and management plane on `main`, including real PostgreSQL/Redis coordination, native protocol ingress, routing, policy enforcement, usage persistence, Console, CLI, and MCP. That does not mean every target requirement, production lifecycle, scale objective, telemetry signal, or UI workflow in `spec/` is complete.

## Delivery states

| State                 | Meaning                                                                                  |
| --------------------- | ---------------------------------------------------------------------------------------- |
| Released              | Present in a published immutable server/CLI release tag.                                 |
| Implemented on `main` | Present in source and covered by repository tests/CI, but newer than the latest release. |
| Partial               | A real implementation exists, but one or more material target requirements remain.       |
| Target only           | Described normatively under `spec/`, with no complete implementation evidence.           |

## Release boundary

| Artifact                      | Latest published release at audit time |            Gateway Phase 2 included? |
| ----------------------------- | -------------------------------------- | -----------------------------------: |
| `owlrora-server` / GHCR image | `server-v0.0.3`                        |                                   no |
| `owlrora` CLI                 | `cli-v0.0.3`                           |                                   no |
| Repository `main`             | `da26113` and later                    | implemented source, not yet released |

The documentation site follows `main`, so a page may describe implemented source behavior before a binary release contains it. Every such page carries an explicit source/release warning.

## Spec-by-spec assessment

| Target chapter                                    | Current source status                    | Implemented evidence                                                                                                                                                                                                                                  | Material remaining work                                                                                                                                                                                                                                              |
| ------------------------------------------------- | ---------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 01 Product scope and system context               | Partial                                  | One server contains Management, Gateway, workers, and Console; PostgreSQL/Redis composition, runtime generations, CLI/MCP, and compact usage exist.                                                                                                   | Standard OpenTelemetry export is absent; Redis is currently mandatory rather than optional outside `health-only`; the 10M logical requests/day objective is not benchmarked.                                                                                         |
| 02 Principals, tenancy, and system administration | Core implemented                         | Typed principals, users, organizations, memberships, owner invariant, invitations, system grants, external JWT/JWKS, bounded OIDC, provisioning, sessions, and seed administrator are end to end.                                                     | OwlAuth-specific interoperability is not shipped or tested; optional JWT signature memoization is absent.                                                                                                                                                            |
| 03 Credentials, permissions, and policy           | Partial, core behavior implemented       | Separate Management/Gateway key classes, one-time secrets, scoped dominance, policy clamps, JWT intersections, route allowlists, budgets, and runtime verification exist.                                                                             | Management and Gateway decisions share typed models but still use separate authorizer implementations rather than one literal decision engine.                                                                                                                       |
| 04 Provider, model, and route catalog             | Partial                                  | Separate endpoints, credentials, deployments, first-class routes/targets, grants, versions, registry tuples, egress clients, and atomic publication exist.                                                                                            | Capability constraints and `state_isolation_profile` are not a complete typed/enforced contract; deployment validation proves binding/runtime construction but does not make a real model request.                                                                   |
| 05 LLM protocols and direct proxy                 | Partial, primary paths implemented       | Anthropic Messages, OpenAI Chat/Responses HTTP/SSE, Responses WebSocket, Gemini, eleven recorded transports, cloud authentication, streaming, and Codex lifecycle exist.                                                                              | Explicit safe client-header forwarding, complete unknown-field proof/rejection, cache/state namespacing, and some provider-error normalization remain incomplete.                                                                                                    |
| 06 Routing, reliability, and stickiness           | Partial, primary paths implemented       | Tier/weight selection, retry/failover, commitment boundaries, passive/active health, circuits, timeout layers, capacity bounds, and sticky routing exist.                                                                                             | Some advanced affinity precedence, strict origin identity, full retry/error taxonomy, and route-decision evidence remain incomplete.                                                                                                                                 |
| 07 Budgets, usage, and rate limits                | Partial, primary enforcement implemented | Paired key/origin allowances, generation fencing, enforce/record-only modes, rate/strict-or-approx concurrency, recovery authority, logical/attempt hourly usage, bounded flushes, and queries exist.                                                 | Bounded-local emergency allowance behavior is modeled but not executed; daily rollup and retention workers are explicitly not implemented; full uncertainty/exposure presentation remains incomplete.                                                                |
| 08 Observability and telemetry                    | Partial                                  | Structured JSON process logs, protected operations evidence, target health, logical/attempt usage, pipeline receipts/loss counters, and Console evidence pages exist.                                                                                 | No OpenTelemetry SDK, OTLP exporter, trace propagation, metric instruments, sampling, or exporter queue/drop telemetry exists. Split-profile process-local evidence cannot be collected through a management process.                                                |
| 09 Data model, hot path, and scale                | Partial                                  | Durable schema, revision serialization, repeatable-read generation capture, `ArcSwap` publication, stateless replicas without durable process registration, in-memory Gateway lookup, client reuse, and bounded asynchronous usage persistence exist. | Publication still polls and performs full snapshot rebuilds rather than journal-delta notification; daily retention is absent; required-route readiness and target load/latency validation are absent.                                                               |
| 10 HTTP surfaces and Console                      | Partial, broad surface implemented       | Query/command Management API, opaque `ETag`, idempotency, OpenAPI/operation descriptor, native Gateway ingress, embedded SPA, stable routes/guards, catalog/policy/usage/evidence workflows exist.                                                    | Admin and organization overview composition is incomplete; several complex forms/evidence views remain schema/raw-JSON oriented; full browser E2E and conflict UX coverage remain target work.                                                                       |
| 11 Operations, security, and deployment           | Partial                                  | Stateless deployment profiles, automatic migrations, non-root image, public liveness, protected operations, software custody, custom custody SPI, egress controls, and signal-based graceful HTTP shutdown exist.                                     | Native TLS, gateway/worker readiness and direct process-local diagnostics in split profiles, required-route readiness, automated backup/restore, complete Redis-loss runbook, standard telemetry, and the full unready/drain/stream/flush shutdown model are absent. |
| 12 Implementation architecture                    | Partial, structural form implemented     | Rust modular monolith, independent CLI and key-provider SPI, module boundaries, runtime generation, background workers, public HTTP adapters, and package-isolation checks exist.                                                                     | Some target port abstractions are not perfectly enforced; application modules still contain SQL in places; incremental publication and target-scale evidence are incomplete.                                                                                         |
| 13 CLI and MCP                                    | Partial, close to target                 | Generated typed command inventory, profiles, secret sources, `ETag`, idempotency, sensitive annotations, approval metadata, stdio MCP, native updater, and cross-platform release artifacts exist.                                                    | Interactive structured edit/delta workflows and broader real-server CLI/MCP HTTP E2E remain incomplete.                                                                                                                                                              |
| UI information architecture and workflows         | Partial, broad surface implemented       | GitLab-like shell, `/admin`, organization workspaces, personal area, stable authority IDs, server-derived guards, responsive design, accessibility basics, and major workflows exist.                                                                 | Overview dashboards, purpose-built presentation for several complex resources, and broader browser automation remain incomplete.                                                                                                                                     |

## Safe claims today

For repository `main`, it is accurate to say:

- the primary Management and Gateway planes are implemented end to end;
- protocol-native HTTP/SSE and Responses WebSocket paths run through real routing, policy, Redis coordination, PostgreSQL usage persistence, and provider transports;
- the server embeds a functional management Console and publishes typed CLI/MCP contracts;
- the official image is non-root and the source passes package, image, and real network integration tests;
- the normal Gateway request path uses one captured in-memory runtime generation and does not synchronously query PostgreSQL.

It is not accurate to say:

- the complete target spec is finished;
- Phase 2 is present in `server-v0.0.3` or `cli-v0.0.3`;
- OpenTelemetry/OTLP export is available;
- Redis is optional for a current non-health-only server process;
- daily usage rollups/retention are active;
- the target 10M/day scale has been benchmarked;
- required-route readiness, native TLS, automatic backup/restore, or the full drain/flush model is available;
- every provider capability, state-isolation rule, unknown field, or advanced affinity semantic is fully enforced.

## Validation evidence on `main`

The current reviewed source passed:

- repository formatting, lint, source, and generated-contract checks;
- 184 server library tests plus Redis integration and provider fixture suites;
- 27 Web tests;
- packaged offline CLI/server builds;
- release preparation tests;
- docs build;
- production container build and smoke test;
- real PostgreSQL + Redis recorded Gateway E2E covering 26 logical requests and 32 physical attempts across HTTP, SSE, WebSocket, cloud authentication, failover, usage settlement, TLS connection timeout, slow headers/body, and connection-pool reuse;
- browser QA of the embedded Console at the Phase 2 baseline, with all five discovered issues resolved.

These are strong functional signals, not production-scale benchmark evidence.

## Normative source

The authoritative target remains [`spec/`](https://github.com/owlfoundry/owlrora/tree/main/spec). Public docs describe implemented and released boundaries; unresolved design discussion and review notes do not belong in the target specification.
