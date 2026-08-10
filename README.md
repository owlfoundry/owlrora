# OwlRora

**Routing and Observability for Reliable AI**

**Route Once. Reach All.**

OwlRora is a self-hosted AI gateway for routing requests across models and providers, observing usage and latency, and applying reliability and tenant policy in one place.

> [!IMPORTANT]
> OwlRora is currently at the runnable-foundation and product-design stage. The gateway protocols and management capabilities described below are product direction, not shipped behavior. The current `owlrora-server` embeds the React shell and exposes `GET /health`; the independent `owlrora` CLI currently provides help, version, and bounded checksum-verified self-update.

## RORA

- **Routing** — route across models and providers without coupling applications to one upstream.
- **Observability** — measure requests, tokens, cost, latency, outcomes, and routing decisions.
- **Reliable** — apply retries, fallbacks, circuit breaking, and rate limits at the gateway boundary.
- **AI** — keep the product focused on operational AI workloads.

## Product direction

OwlRora is an LLM gateway targeting native compatibility with:

- Anthropic Messages API;
- OpenAI Chat Completions API;
- OpenAI Responses API;
- Google Gemini API.

It also models OpenAI Codex subscription authentication as a community-maintained, best-effort upstream credential for the Responses semantic family. OwlRora ships its current adapter behavior with each build rather than promising a compatibility-profile service or SLA. Other provider subscription integrations are not part of the design.

Compatibility endpoints and upstream transports are separate boundaries. Requests remain protocol-native while OwlRora selects an eligible model deployment from explicit credentials, endpoints, transports, and route targets.

## Gateway policy

OwlRora owns organization/user authorization, scoped gateway credentials, model access, approximate budgets, rate and concurrency limits, usage attribution, routing health, and operational observability.

It does not implement billing, payments, commercial top-up flows, or product-specific reset workflows. A commercial platform owns those workflows and updates OwlRora policy through the management boundary.

## Multi-tenant and embeddable

OwlRora owns its internal users, organizations, memberships, roles, and resource attribution. It does not require one identity product.

Target identity and provisioning modes include:

- scoped management API keys for direct API, CLI, MCP, and key-derived console sessions;
- a high-entropy environment management API key for the built-in API-key-only `seed_admin` user;
- optional OwlAuth integration;
- trusted external JWT issuers that map an authenticated subject to an OwlRora user;
- direct system-administrator creation and management of users and organizations;
- synthetic users and organizations for automation, testing, or embedding into another platform.

Authentication proves a principal. OwlRora remains authoritative for organization membership, roles, budgets, model access, credentials, and AI resources.

The `seed_admin` user may administer the deployment directly or promote an existing active local user to system administrator. Both use the same authorizer and audit path. Management API keys and LLM gateway API keys are separate credential classes with different scopes and accepted surfaces. A system administrator manages deployment-wide configuration, including reusable upstream credentials, endpoints, model deployments, shared routes, secret-custody status, and direct tenant provisioning. Organization administrators manage members and organization policy within that system boundary.

## Design principles

- **Protocol compatibility without domain coupling** — preserve client-facing API semantics at the edge and isolate provider-specific translation.
- **Organization-qualified authority** — tenant resources are organization-owned and every creation/command is attributed to the actual typed user, key, or system principal without making creator attribution runtime authority.
- **Unified identity path** — management keys/key-derived sessions, external sessions, trusted JWTs, and gateway keys converge on one typed authorization pipeline without making OwlAuth a dependency or conflating control-plane and LLM credentials.
- **Protocol-native proxying** — preserve Anthropic, OpenAI, and Gemini semantics rather than forcing one lossy universal request model.
- **Composable upstream catalog** — model credentials, endpoints, deployments, and route targets as separate reusable resources.
- **Approximate operational enforcement** — use bounded local allowance and optional Redis-compatible coordination with availability-first bounded recovery, without pretending to be a billing ledger.
- **Encrypted recoverable secrets** — hash durable management keys and gateway keys; directly encrypt upstream secrets from an explicit environment root in the official server binary, with a small static-composition SPI for user-provided custody.
- **Observable routing** — retain structured evidence explaining selection, attempts, latency, usage, and cost without default prompt/response logs.
- **First-party automation** — ship an independent official CLI package containing the `owlrora` management client and local stdio MCP mode; both use only scoped public management HTTP APIs and retain server authorization, ETag, audit, and one-time-secret rules.

## Repository status and specifications

The repository currently contains a Rust/Axum server foundation, an independently packaged `owlrora` CLI with native self-update, the provider-neutral key-custody SPI, an embedded React frontend, isolated crate packaging tests, container packaging, documentation, and separate CLI/server release automation for crates, GitHub Releases, and immutable versioned server images. Product implementation has not started.

Target design lives under [`spec/`](spec/README.md). The thirteen specifications proceed from product and system boundaries through identity, authorization, upstream catalog, protocols, routing, budgets, observability, local-cache scale, management, operations, and implementation architecture. Public documentation lives under [`docs/`](docs/index.md) and distinguishes current behavior from product direction.

## Repository layout

- `crates/owlrora-cli/` — independently versioned `owlrora` CLI, native updater, and planned stdio MCP/client commands;
- `crates/owlrora-key-provider/` — provider-neutral custom secret-custody SPI;
- `crates/owlrora-server/` — Rust server/library, `owlrora-server` executable, and packaged frontend assets;
- `apps/web/` — React and Vite frontend source;
- `spec/` — normative target product and domain specifications;
- `docs/` — public VitePress documentation;
- `scripts/` — package, container, and release checks.

## Requirements

- Rust stable
- Node.js 24 or later
- pnpm 11.20.0
- Docker for container builds

## Development

Install locked dependencies:

```bash
make install
```

Build the frontend and run the current server foundation:

```bash
make dev
```

The application listens on `http://localhost:8080` by default. Override the listener with `OWLRORA_ADDR`.

Inspect the independent CLI and its implemented update command:

```bash
cargo run --locked --package owlrora-cli -- --help
cargo run --locked --package owlrora-cli -- update --version 0.0.0-dev --dry-run --force
```

For frontend development with Vite:

```bash
pnpm dev
```

Run the documentation site locally:

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
```

## Container

Build and smoke-test the production image:

```bash
make docker-build
```

Run the locally built image:

```bash
docker run --rm --publish 8080:8080 owlrora:dev
```

The image serves the current API and embedded frontend from one non-root process. Its health endpoint is `GET /health`.

## License

OwlRora is released under the [BSD 3-Clause License](LICENSE).
