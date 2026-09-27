# Implementation status

This page separates OwlRora's normative target design from released binaries and current source implementation.

**Source baseline:** repository `main`, including the architecture reset following the Phase 2 baseline (`da261139144b6bcb5af0624bb4693e445eeedf40`). This is a source-capability assessment, not a claim that an existing release tag contains later changes.

## Verdict

The answer to “is the complete target specification implemented?” is **no**.

Phase 2 delivers a substantial end-to-end Gateway and management plane in reviewed repository source, including real PostgreSQL/Redis coordination, native protocol ingress, routing, policy enforcement, usage persistence, Console, CLI, and MCP. That does not mean every target requirement, production lifecycle, scale objective, telemetry signal, or UI workflow in `spec/` is complete.

## Delivery states

| State                 | Meaning                                                                                  |
| --------------------- | ---------------------------------------------------------------------------------------- |
| Released              | Present in a published immutable server/CLI release tag.                                 |
| Implemented on `main` | Present in source and covered by repository tests/CI, but newer than the latest release. |
| Partial               | A real implementation exists, but one or more material target requirements remain.       |
| Target only           | Described normatively under `spec/`, with no complete implementation evidence.           |

## Release boundary

Server and CLI artifacts are released independently. Consult [GitHub Releases](https://github.com/owlfoundry/owlrora/releases) for immutable tags and release notes, then verify that each selected tag resolves to source containing the required capabilities. This page deliberately does not embed a moving latest-version table.

The documentation site follows `main`, so pages may describe implemented source behavior newer than a selected binary release. Such pages carry an explicit source/release warning.

## Spec-by-spec assessment

| Target chapter                                    | Current source status                    | Implemented evidence                                                                                                                                                                                                                                  | Material remaining work                                                                                                                                                                                                                                              |
| ------------------------------------------------- | ---------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 01 Product scope and system context               | Partial                                  | One server contains Management, Gateway, workers, and Console; PostgreSQL/Redis composition, runtime generations, CLI/MCP, and compact usage exist.                                                                                                   | Redis remains mandatory outside `health-only`; the 10M logical requests/day objective is not benchmarked.                                                                                         |
| 02 Principals, tenancy, and system administration | Core implemented                         | Typed principals, users, organizations, memberships, owner invariant, invitations, system grants, external JWT/JWKS, bounded OIDC, provisioning, sessions, and seed administrator are end to end.                                                     | OwlAuth-specific interoperability is not shipped or tested; optional JWT signature memoization is absent.                                                                                                                                                            |
| 03 Credentials, permissions, and policy           | Partial, core behavior implemented       | Separate Management/Gateway key classes, one-time secrets, scoped dominance, policy clamps, JWT intersections, route allowlists, budgets, and runtime verification exist.                                                                             | Management and Gateway decisions share typed models but still use separate authorizer implementations rather than one literal decision engine.                                                                                                                       |
| 04 Provider, model, and route catalog             | Partial                                  | Separate endpoints, credentials, deployments, first-class routes/targets, grants, versions, registry tuples, egress clients, and atomic publication exist.                                                                                            | Typed capability/transport compatibility, organization-owned routes, and state-isolation policy are enforced. Deployment validation proves binding/runtime construction but does not make a real model request.                                                                   |
| 05 LLM protocols and direct proxy                 | Partial, primary paths implemented       | Anthropic Messages, OpenAI Chat/Responses HTTP/SSE, Responses WebSocket, Gemini, eleven recorded transports, cloud authentication, streaming, and Codex lifecycle exist.                                                                              | Bounded request policy, cache/state isolation, cancellation ownership, and usage-aware settlement are implemented. Exhaustive coverage of every evolving provider field and error remains outside the proven compatibility set.                                                                                                    |
| 06 Routing, reliability, and stickiness           | Partial, primary paths implemented       | Tier/weight selection, retry/failover, commitment boundaries, passive/active health, circuits, timeout layers, capacity bounds, and sticky routing exist.                                                                                             | Some advanced affinity precedence, strict origin identity, full retry/error taxonomy, and route-decision evidence remain incomplete.                                                                                                                                 |
| 07 Budgets, usage, and rate limits                | Partial, primary enforcement implemented | Paired key/origin allowances, generation fencing, enforce/record-only modes, rate/strict-or-approx concurrency, recovery authority, logical/attempt hourly usage, bounded flushes, and queries exist.                                                 | Atomic daily/hourly rollup, receipt replay horizons, and bounded retention are implemented. Bounded-local emergency allowance behavior and full uncertainty/exposure presentation remain incomplete.                                                                |
| 08 Observability and telemetry                    | Partial                                  | Structured JSON process logs, protected operations evidence, target health, logical/attempt usage, pipeline receipts/loss counters, and Console evidence pages exist.                                                                                 | SDK OTLP/HTTP traces and metrics, parent-based sampling, bounded queues/export/shutdown, and protected drop diagnostics exist. Inbound/outbound trace propagation and the full target signal inventory remain absent. A management process cannot retrieve another replica's local diagnostics.                                                |
| 09 Data model, hot path, and scale                | Partial                                  | Durable schema, revision serialization, repeatable-read generation capture, `ArcSwap` publication, stateless replicas without durable process registration, in-memory Gateway lookup, client reuse, and bounded asynchronous usage persistence exist. | Publication still polls and rebuilds coherent snapshots rather than journal-delta notification. Daily retention and required-route readiness are implemented; target-scale load/latency validation remains absent.                                                               |
| 10 HTTP surfaces and Console                      | Partial, broad surface implemented       | Query/command Management API, opaque `ETag`, idempotency, OpenAPI/operation descriptor, native Gateway ingress, embedded SPA, stable routes/guards, catalog/policy/usage/evidence workflows exist.                                                    | Catalog workflows use named paginated dependencies, typed compatibility and target controls; form sessions preserve resource/ETag identity and secret-safe retries. Overview composition, some advanced JSON settings, and exhaustive real-server browser coverage remain incomplete.                                                                       |
| 11 Operations, security, and deployment           | Partial                                  | Stateless deployment profiles, automatic migrations, non-root image, public liveness, protected operations, software custody, custom custody SPI, egress controls, and signal-based graceful HTTP shutdown exist.                                     | All non-health-only profiles expose readiness, optional required-route checks, owned request/stream draining, bounded usage flush and OTLP shutdown. Native TLS, direct remote process diagnostics, automated backup/restore, and a complete Redis-loss runbook remain absent. |
| 12 Implementation architecture                    | Partial, structural form implemented     | Rust modular monolith, independent CLI and key-provider SPI, module boundaries, runtime generation, background workers, public HTTP adapters, and package-isolation checks exist.                                                                     | The accepted architecture is a SQL-owning modular monolith, not a completed ports-and-adapters rewrite. Incremental publication and target-scale evidence remain incomplete.                                                                                         |
| 13 CLI and MCP                                    | Partial, close to target                 | Generated typed command inventory, profiles, secret sources, `ETag`, idempotency, sensitive annotations, approval metadata, stdio MCP, native updater, and cross-platform release artifacts exist.                                                    | Interactive structured edit/delta workflows and broader real-server CLI/MCP HTTP E2E remain incomplete.                                                                                                                                                              |
| UI information architecture and workflows         | Partial, broad surface implemented       | GitLab-like shell, `/admin`, organization workspaces, personal area, stable authority IDs, server-derived guards, responsive design, accessibility basics, and major workflows exist.                                                                 | Overview dashboards, purpose-built presentation for several complex resources, and broader browser automation remain incomplete.                                                                                                                                     |

## Safe claims today

For the reviewed repository source, it is accurate to say:

- the primary Management and Gateway planes are implemented end to end;
- protocol-native HTTP/SSE and Responses WebSocket paths run through real routing, policy, Redis coordination, PostgreSQL usage persistence, and provider transports;
- the server embeds a functional management Console and publishes typed CLI/MCP contracts;
- the official image is non-root and the source passes package, image, and real network integration tests;
- the normal Gateway request path uses one captured in-memory runtime generation and does not synchronously query PostgreSQL;
- standard asynchronous OTLP, bounded shutdown, required-route readiness, and atomic hourly/daily usage retention exist in source.

It is not accurate to say:

- the complete target spec is finished;
- Redis is optional for a current non-health-only server process;
- the target 10M/day scale has been benchmarked;
- native TLS, automatic backup/restore, or lossless shutdown is available;
- every evolving provider capability, unknown field, or advanced affinity semantic is fully covered.

## Validation evidence

The historical Phase 2 baseline passed the following checks (these counts are not the architecture-reset suite size):

- repository formatting, lint, source, and generated-contract checks;
- 184 server library tests plus Redis integration and provider fixture suites;
- 27 Web tests;
- packaged offline CLI/server builds;
- release preparation tests;
- docs build;
- production container build and smoke test;
- real PostgreSQL + Redis recorded Gateway E2E covering 26 logical requests and 32 physical attempts across HTTP, SSE, WebSocket, cloud authentication, failover, usage settlement, TLS connection timeout, slow headers/body, and connection-pool reuse;
- browser QA of the embedded Console at the Phase 2 baseline, with all five discovered issues resolved.

Architecture-reset regression coverage additionally exercises runtime MVCC/freshness, authority independent of creator lifecycle, cancellation settlement, state isolation, form/ETag changes, one-time-secret retry safety, all-profile readiness, blocked downstream drain, WebSocket turn admission during shutdown, atomic rollups/retention/replay, and real local OTLP collector success/failure/stalls. See repository tests and CI for the exact suite at the selected commit. Neither functional regression coverage nor package/container checks are production-scale benchmarks.

## Normative source

The authoritative target remains [`spec/`](https://github.com/owlfoundry/owlrora/tree/main/spec). Public docs describe implemented and released boundaries; unresolved design discussion and review notes do not belong in the target specification.
