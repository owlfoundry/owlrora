# OwlRora

**Routing and Observability for Reliable AI**

**Route Once. Reach All.**

OwlRora is a self-hosted, multi-tenant LLM gateway for routing protocol-native requests across explicit model deployments, enforcing tenant and reliability policy, and observing logical requests and physical attempts.

> [!IMPORTANT]
> The capability list below describes reviewed repository source, not a promise that every published artifact or target-spec requirement contains it. Verify the source and release notes for the exact server and CLI artifacts you select, and see [Implementation status](docs/reference/implementation-status.md).

## Implemented on `main`

- PostgreSQL-backed users, organizations, memberships, roles, system grants, invitations, audit, idempotency, and runtime revisions.
- Separate deployment/organization Management API keys, key-derived sessions, Gateway API keys, external JWT/JWKS, and bounded OIDC browser login.
- Independent upstream endpoints, credentials, model deployments, first-class model routes and targets, catalog grants, and versioned policies.
- Native-compatible Anthropic Messages, OpenAI Chat Completions, OpenAI Responses HTTP/SSE/WebSocket, and Gemini ingress.
- Matching upstream transports, static/workload/cloud credentials, AWS SigV4, Azure/Google token exchange, and the explicitly modeled community-maintained Codex subscription adapter.
- Tier/weight routing, retry/failover, stickiness, passive and active health, circuits, timeouts, and process-local capacity bounds.
- Redis-coordinated key/origin budgets, rate limits, strict/approximate concurrency, bounded recovery, and logical/attempt usage aggregation.
- Embedded GitLab-like React Console, generated typed `owlrora` CLI, and bounded local stdio MCP mode over public Management APIs.
- Non-root server image, automatic PostgreSQL migrations, deployment profiles, public `/health`, and protected operations evidence.

## Product boundaries

OwlRora is not a billing ledger, identity provider, prompt manager, agent framework, semantic cache, vector database, training platform, or generic reverse-proxy/plugin host.

OwlRora preserves native Anthropic, OpenAI, and Gemini semantics rather than forcing every protocol through one lossy universal request model. Client-facing models are first-class routes. Endpoints, credentials, and deployments remain separate reusable resources.

Only Gateway API keys are quota-bearing request principals. Every key has a non-empty stable route-ID allowlist and one finite overall budget. Every physical key attempt also settles against the organization pool for the target's actual `system_provided` or `organization_byok` origin. Direct-JWT traffic is observed without fabricating a key budget.

The OpenAI Codex subscription adapter is community-maintained, best-effort, and limited to the Responses semantic family. It is not a generic provider-subscription framework or SLA.

## Repository layout

- `crates/owlrora-server/` — Rust modular monolith, Management and Gateway HTTP surfaces, workers, and embedded production Console;
- `crates/owlrora-cli/` — independently released typed management CLI, stdio MCP adapter, profiles, output handling, and native updater;
- `crates/owlrora-key-provider/` — provider-neutral custom secret-custody SPI;
- `apps/web/` — React/Vite Console source;
- `spec/` — normative target architecture;
- `docs/` — public VitePress documentation with release and implementation boundaries;
- `scripts/` — package, container, fixture, contract, and release checks.

## Requirements

- Rust stable
- Node.js 24 or later
- pnpm 11.20.0
- Docker with Compose v2
- PostgreSQL 17 and Redis 7.4/8 for the tested non-health-only server configuration

## Local development

Install locked dependencies and create the ignored local environment:

```bash
make install
cp .env.example .env
make dev
```

The application listens on <http://127.0.0.1:8080>. The checked-in example secrets are public and disposable; never reuse them outside local development.

`make dev` builds embedded Console assets, starts healthy PostgreSQL and Redis containers, runs embedded migrations, publishes the initial runtime generation, and serves the `full` profile. Optional Compose overrides live in `dev/.env`; see [dev/README.md](dev/README.md).

Inspect the source CLI and MCP adapter:

```bash
cargo run --locked --package owlrora-cli -- --help
cargo run --locked --package owlrora-cli -- mcp --help
```

Run the documentation site:

```bash
make docs
```

## Validation

```bash
make check
make test
make build
make package-check
make docs-build
make docker-build
```

## Deployment

The official image runs as a non-root UID, embeds the Console, exposes port 8080, and provides public process liveness at `GET /health`. Every current non-`health-only` profile requires PostgreSQL, Redis, and the software-custody root; stateless replicas require no durable application identity. Management-capable profiles additionally require the public origin and seed administrator key.

Do not expose port 8080 directly to the public Internet. Terminate TLS at a trusted reverse proxy, pin an immutable image digest, and preserve PostgreSQL plus the external secret root as one recovery set.

Start with the [deployment guide](docs/deployment/index.md), [configuration reference](docs/deployment/configuration.md), and [operations runbook](docs/deployment/operations.md).

## Design and delivery status

The authoritative target design lives under [`spec/`](spec/README.md). Public docs distinguish:

- capability in the latest published immutable release;
- implemented but unreleased behavior on `main`;
- partially implemented or target-only work.

The current evidence-based matrix is [docs/reference/implementation-status.md](docs/reference/implementation-status.md).

## License

OwlRora is released under the [BSD 3-Clause License](LICENSE).
