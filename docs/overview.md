# Product overview

OwlRora stands for **Routing and Observability for Reliable AI**.

**Route Once. Reach All.**

::: warning Delivery boundary
OwlRora now provides its identity and management plane, but it is not yet an operational LLM gateway. Data-plane sections describe the target architecture; the shipped management capabilities are listed below.
:::

## What OwlRora is

OwlRora is a self-hosted, multi-tenant LLM gateway for applications and platforms that use multiple models, upstream accounts, and protocol families through one controlled boundary.

For each accepted request, the gateway determines:

1. which authenticated principal is acting: a local JWT user or an organization Gateway-key resource principal;
2. which explicit organization and first-class route group apply;
3. which compatible target should serve each attempt and whether Gateway-key overall plus target-derived system/BYOK origin quota applies;
4. what happened across every attempt, how long it took, and what usage/cost was observed.

## LLM protocols

The target ingress families are:

- Anthropic Messages;
- OpenAI Chat Completions;
- OpenAI Responses;
- Google Gemini generate-content APIs.

Requests remain protocol-native. OwlRora does not turn these APIs into one lowest-common-denominator chat schema. Provider-hosted variants such as Bedrock, Vertex, and Azure use explicit compatible transports.

OpenAI Codex subscription is modeled as one community-maintained, best-effort upstream credential and Responses transport. Adapter behavior evolves with OwlRora builds; there is no managed compatibility-profile catalog or SLA. It does not create a general provider-subscription framework, and no other provider subscription integration is planned by the architecture.

## Routing catalog

OwlRora separates reusable upstream concerns:

- **Credential** — authentication material and typed injection/refresh behavior;
- **Endpoint** — validated network origin, region, TLS, proxy, and adapter profile;
- **Model deployment** — one credential + endpoint + transport + upstream model binding;
- **Model route** — client-facing model key and policy over compatible deployments;
- **Route target** — one deployment’s priority, weight, affinity, and health role.

This lets one credential serve multiple compatible endpoints or deployments and lets one endpoint host several credentials or models. A model route is a policy object rather than an alias.

## Identity and tenancy

OwlRora owns local system administrators, users, organizations, memberships, roles, route grants, and attribution.

Identity is pluggable:

| Mode | Responsibility |
| --- | --- |
| Management API key | a deployment-owned or organization-owned control-plane key authenticates as its own automation principal for API, CLI, MCP, or a key-derived console session |
| Seed administrator key | an environment management key authenticates the built-in API-key-only `seed_admin` user with full fixed management scope |
| OwlAuth integration | OwlAuth authenticates a subject; OwlRora maps it to a local user |
| Trusted external JWT | a configured issuer signs a token that maps to a local user |
| Direct administration | a system administrator provisions human or synthetic users and organizations |
| Gateway API key | OwlRora authenticates an organization-owned LLM-only service principal; creator identity is audit metadata only |

Management keys/key-derived sessions, external sessions, JWTs, and gateway keys converge on one typed authorization pipeline. Management keys and gateway keys have distinct prefixes, scopes, verifier indexes, accepted surfaces, and resource principals. `seed_admin` may manage the deployment directly or grant an active local user/deployment Management key system administration, and every action is audited as the actual user or key principal. A trusted JWT issuer is API-only unless an optional bounded OpenID Connect code-flow profile enables browser login. External claims never directly create membership, system administration, route access, or budget authority.

This supports standalone use, optional OwlAuth, SaaS embedding, and enterprise integration without maintaining separate control-plane and workload-JWT authorization models.

## Reliability

A route can balance quota, price, and availability across compatible deployments using:

- deterministic priority and integer-weighted rendezvous ordering;
- preferred affinity without load-balancer stickiness;
- strict origin affinity for provider-side response state;
- bounded retries and pre-commit failover;
- passive target health, active probes, cooldown, and gradual recovery;
- local circuits and optional compact shared health summaries;
- bounded endpoint and process concurrency.

Once response bytes are committed, OwlRora never mixes in another upstream attempt.

## Budgets and usage

Budgets are operational admission controls rather than a financial ledger.

- Every Gateway API key has a required route allowlist and overall budget. Each of its actual attempts also uses one organization origin pool: an administrator-assigned system-provider allocation or the organization's BYOK budget, derived from the selected deployment rather than chosen by the caller.
- Optional Redis-compatible coordination issues bounded allowance grants; requests normally consume grants locally rather than contacting Redis every time.
- Standalone Redis is supported; Redis Cluster or managed high availability is recommended for production but not required.
- Emergency continuation uses Redis-issued, precharged grants with a configured fleet bound; a node started during an outage cannot obtain or renew one.
- Uncertain Redis state loss installs a new generation with only a durably capped availability-first recovery allowance; repeated recovery is capped per epoch.
- Key and origin budgets independently support enforcing and record-only modes. Direct-JWT traffic is observed but has no fabricated Gateway-key/origin quota; deployments needing quota enforcement issue keys.
- Usage is attributed by organization, optional JWT user or Gateway key, route, target origin, deployment, endpoint, pricing version, and attempt; a key creator is never treated as the request user.
- PostgreSQL stores sparse hourly/daily aggregates rather than one row per request.

Billing, payment, credit, commercial reset, and top-up meaning remains in the embedding platform.

## Secrets

OwlRora distinguishes persisted bearer and recoverable-secret handling:

- durable management keys, gateway keys, and other persisted non-recoverable bearer values are stored only as SHA-256 digests;
- recoverable provider keys and OAuth tokens use versioned authenticated encryption;
- the full-scope `seed_admin` management key remains solely in deployment environment configuration and never enters PostgreSQL or secret custody.

The official server binary reads one explicit 32-byte `OWLRORA_SECRET_ROOT` environment value and directly encrypts database secrets with HKDF-SHA-256 plus XChaCha20-Poly1305. There is no local key-provider object, key file, built-in KMS adapter, or fallback key. Users needing remote custody can implement the small provider-neutral SPI in an independent crate and statically link a custom server binary. Secrets are opened while building reusable upstream clients, never on each LLM request.

## Data and horizontal scale

PostgreSQL is durable control-plane authority. Each request captures one coherent immutable runtime generation before authentication and uses it through upstream dispatch.

Configuration changes serialize their final transaction phase through a PostgreSQL revision-counter lock, producing a contiguous commit-ordered journal. Nodes wake through best-effort notification and read affected components under one PostgreSQL MVCC/revision fence. Nodes build clients outside the transaction and atomically swap one snapshot/client-registry root. Periodic jittered reconciliation recovers lost notifications. Nodes do not perform full configuration reloads for every small mutation.

The normal request path performs no PostgreSQL operation and no synchronous raw request-log write. Redis operations are amortized by allowance grants unless an explicitly strict policy is selected.

The architecture is designed for data growth beyond ten million logical requests per day through horizontal gateway replication, bounded local state, sparse aggregation, and targeted snapshot synchronization rather than immediate database sharding.

## Management and console

The shipped management plane consists of the `owlrora-server` Management API and embedded React console plus the independently released `owlrora-cli` package containing the `owlrora` management client and local stdio MCP mode. The CLI and MCP call only the public HTTP API; their full command/tool inventory does not bypass Management-key resource scope, key policy/administrator grants, or server authorization.

Management queries use `GET`. Commands use `POST`, with coarse tri-state updates:

- omitted field means unchanged;
- `null` clears a nullable field;
- non-null value replaces it after aggregate validation.

Every coarse resource update uses the same opaque HTTP `ETag`/`If-Match` precondition, so the concurrency rule remains simple and a stale editor cannot silently restore another administrator’s removed state. Distinct lifecycle operations such as management-key or gateway-key rotation, Codex login, validation, and budget epoch creation remain explicit actions.

The console uses a GitLab-like split between global administration and organization workspaces. `seed_admin` or a durable deployment/organization Management key can be exchanged for a scope-preserving secure key-principal session; the browser does not retain the raw key. Personal pages contain no API-key ownership. Organization workspaces manage organization Management/Gateway keys, API-key policy, organization-only BYOK credentials/deployments, mixed-origin routes, key/BYOK budgets, usage, and audit; system endpoints, system-provider allocations, and the shared catalog remain under Admin authority.

## Current implementation

The repository currently provides:

- a Rust/Axum server with PostgreSQL migrations for users, organizations, memberships, administrator grants, invitations, scoped Management API keys, key-derived sessions, external identity bindings, issuer verifier material, idempotency, audit, and runtime publication evidence;
- one typed authorization pipeline for seed administration, durable deployment/organization key principals, browser sessions, external sessions, and direct JWT callers;
- bundled secret-root encryption and non-recoverable management-key digests;
- an embedded React console with deployment and organization workspaces, route/action guards, ETag-aware commands, and one-time-secret handling;
- generated typed `owlrora` management commands and 67 bounded stdio MCP tools over the public HTTP API, plus hardened profiles, structured output, and native self-update;
- deterministic contract/frontend generation, real-PostgreSQL tests, isolated package builds, container smoke tests, documentation, and immutable CLI/server release automation.

It does not yet provide LLM gateway keys and traffic ingress, provider credentials/catalog execution, protocol adapters, routing/failover, Redis allowance coordination, or usage aggregation. Those data-plane capabilities remain target design under `spec/`.
