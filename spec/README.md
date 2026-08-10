# OwlRora architecture specifications

OwlRora is **Routing and Observability for Reliable AI**.

**Route Once. Reach All.**

This directory defines OwlRora’s target LLM gateway architecture. The specifications proceed from product and system boundaries to domain models, request execution, infrastructure, and implementation structure.

The architecture is independent of rollout order. Capabilities may ship incrementally, but a partial implementation does not redefine the target model. Public guidance under [`docs/`](../docs/) must distinguish implemented behavior from product direction.

Design alternatives, objections, and unresolved trade-offs belong under the local, non-normative `local-reference/` workspace rather than in these specifications.

## Normative language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**, and **MAY** express architectural invariants and interoperability requirements. They do not imply that every capability ships in one release.

## Reading order

| Specification | Architectural layer |
| --- | --- |
| [`01-product-scope-and-system-context.md`](01-product-scope-and-system-context.md) | product boundary, actors, authority, system components, and end-to-end request flow |
| [`02-principals-tenancy-and-system-administration.md`](02-principals-tenancy-and-system-administration.md) | local principals, external identity, organizations, memberships, and administration |
| [`03-credentials-permissions-and-policy.md`](03-credentials-permissions-and-policy.md) | unified authorization, management/gateway API keys, JWTs, scopes, grants, and revocation |
| [`04-provider-model-and-route-catalog.md`](04-provider-model-and-route-catalog.md) | upstream credentials, endpoints, model deployments, routes, targets, and pricing |
| [`05-llm-protocols-and-direct-proxy.md`](05-llm-protocols-and-direct-proxy.md) | Anthropic, OpenAI, Google, Codex subscription, protocol-native proxying, and streaming |
| [`06-routing-reliability-and-stickiness.md`](06-routing-reliability-and-stickiness.md) | deterministic selection, affinity, health, retry, failover, and circuit behavior |
| [`07-budgets-usage-and-rate-limits.md`](07-budgets-usage-and-rate-limits.md) | approximate budgets, usage accounting, distributed allowance, rate, and concurrency policy |
| [`08-observability-and-telemetry.md`](08-observability-and-telemetry.md) | privacy defaults, OpenTelemetry, request/attempt evidence, and operational views |
| [`09-data-model-hot-path-and-scale.md`](09-data-model-hot-path-and-scale.md) | durable state, local cache synchronization, hot-path I/O, aggregation, and horizontal scale |
| [`10-http-surfaces-and-web-console.md`](10-http-surfaces-and-web-console.md) | management and compatibility APIs, update semantics, browser security, and console structure |
| [`11-operations-security-and-deployment.md`](11-operations-security-and-deployment.md) | deployment profiles, bundled secret encryption, custom custody SPI, network security, and recovery |
| [`12-implementation-architecture.md`](12-implementation-architecture.md) | modular-monolith boundaries, packages, request orchestration, workers, and testing structure |
| [`13-cli-and-mcp.md`](13-cli-and-mcp.md) | official CLI/MCP packaging, public-HTTP boundary, profiles, toolsets, safety, and generated contracts |
| [`ui/`](ui/README.md) | GitLab-style console information architecture, browser routes, guards, workflows, and visual direction |

## Shared vocabulary

| Term | Meaning |
| --- | --- |
| **Control plane** | configuration, tenancy, policy, and management operations |
| **Data plane** | latency-sensitive LLM proxy request path |
| **Principal** | built-in `seed_admin`, active local user, or deployment/organization API-key resource identity established by supported authentication evidence |
| **Management API key** | deployment-owned or organization-owned scoped control-plane automation principal for management APIs, CLI, MCP, or key-derived browser sessions; never an LLM credential |
| **Management scope** | one of the five concrete control-plane operation classes applied to keys, direct JWTs, and browser sessions; coarse `management:access` is not a scope grant |
| **Organization** | tenant authorization, policy, lifecycle, and resource boundary |
| **Gateway API key** | OwlRora-issued organization-owned LLM-only service principal; never a user or management credential |
| **Upstream credential** | system-scoped or organization-only BYOK authentication material with typed request-injection behavior |
| **Upstream endpoint** | a validated network origin and adapter profile, without embedded credentials |
| **Model deployment** | one upstream model bound to an endpoint, credential, and transport |
| **Model route** | client-addressable routing policy over compatible model deployments |
| **Route target** | one deployment’s weighted, prioritized role in a route |
| **Logical request** | one caller request, possibly containing multiple upstream attempts |
| **Attempt** | one dispatch to one route target |
| **Usage** | provider consumption and calculated cost attributed to an attempt |
| **Runtime generation** | one immutable, versioned policy/catalog snapshot plus its matching credential-client registry |

A model route is not an alias. Its client-facing model key resolves a policy object with targets, compatibility, reliability, and organization visibility.

## System-wide invariants

1. OwlRora owns local users, organizations, memberships, grants, routes, policies, and attribution. OwlAuth is an optional identity adapter, not a domain dependency.
2. Management keys/key-derived sessions, external sessions, trusted JWTs, and gateway keys converge on one typed authorization pipeline. Management and gateway keys have disjoint prefixes, scope vocabularies, indexes, and accepted surfaces. Durable keys are deployment/organization resource principals; `created_by_principal` is attribution, never ownership or runtime authority. External issuer management access has explicit management-scope and organization ceilings; `management:access` alone grants no operation.
3. The deployment seed key is a full-scope Management key for the built-in API-key-only `seed_admin` user. It is management-only. Durable Management/Gateway keys authenticate as their own resource principals, not creator users.
4. Every LLM request resolves one active organization and first-class model route. JWT requests additionally resolve an active local user/membership; Gateway-key requests resolve an active organization key principal, a required route allowlist, and never fabricate user attribution.
5. External claims and management scopes never create system-administrator authority or organization membership. Deployment Management keys require an explicit administrator grant; organization key authority comes only from immutable resource scope, stored ceilings, and current key policy.
6. Protocol handling is direct by default. Anthropic Messages, OpenAI Chat Completions, OpenAI Responses, and Google Gemini do not pass through one lossy universal request model.
7. Upstream credentials and endpoints are independent resources. System endpoints remain deployment-owned. Organization BYOK credentials are same-organization-only and may form organization deployments only with explicitly granted system endpoints; no organization endpoint editing or cross-tenant secret reuse exists.
8. Routing selects only compatible targets. Streaming failover stops permanently once downstream response bytes are committed.
9. Automatic failover preserves deterministic affinity where possible and uses bounded passive health, active probes, cooldown, and recovery dampening.
10. Budgets are operational admission controls, not a billing ledger. Every Gateway key has one overall budget, while each actual attempt also uses either the organization's admin-assigned system-provider pool or organization-managed BYOK pool according to deployment origin; both may enforce or only record. Direct JWT traffic has no fabricated quota. Drift is calculated from configured emergency, recovery, concurrency, and estimate-overrun ceilings.
11. Usage remains attributable by organization, optional user or Gateway key, logical request, attempt, route, target, derived system/BYOK origin, deployment, endpoint, applicable policy epochs, and pricing version. Key creator is never copied into request user attribution.
12. The normal data path performs no PostgreSQL operation and emits no synchronous raw request log.
13. A request captures one runtime generation before authentication and uses it through dispatch. Runtime-affecting commits produce a contiguous commit-ordered journal, and generations are derived under one PostgreSQL MVCC/revision fence; PostgreSQL remains durable authority and Redis remains bounded coordination state.
14. Prompts, responses, authorization headers, and provider credentials are excluded from logs and telemetry by default.
15. OwlRora-persisted non-recoverable bearer values are stored only as SHA-256 digests. The management-only seed-administrator key remains solely in deployment configuration. The official server binary directly encrypts recoverable secrets from an environment root; independent statically linked custody implementations use the small published SPI.
16. The deployable system is the `owlrora-server` Rust modular monolith with an embedded React console. The independently released `owlrora-cli` package installs the remote `owlrora` management CLI and local stdio MCP mode without linking server internals; the third-party custody boundary remains the small `owlrora-key-provider` SPI.
17. CLI and MCP call only public management HTTP APIs; full tool coverage never bypasses Management-key resource scope, current key policy/administrator grant, tenant qualification, `ETag`, audit, or one-time-secret semantics. Native CLI self-update accepts only bounded checksum-verified `cli-v*` assets and never updates the server.

## Product boundary

OwlRora is an LLM gateway. It covers:

- Anthropic Messages;
- OpenAI Chat Completions;
- OpenAI Responses;
- Google Gemini generate-content APIs;
- OpenAI Codex subscription access through the Responses semantic family;
- multi-provider routing, health, retry, failover, affinity, budgets, usage, rate limits, and observability;
- complete system and organization administration through APIs, the embedded console, the official CLI, and the local stdio MCP server.

It does not define billing, payment, commercial top-up, agent workflows, prompt management, or a generic reverse-proxy/plugin platform.

No provider subscription integration exists other than the explicitly modeled OpenAI Codex subscription credential.
