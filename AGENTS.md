# OwlRora repository guide

OwlRora is the server foundation for a planned self-hosted AI gateway — Routing and Observability for Reliable AI — delivered as a single Rust web server with an embedded React frontend.

## Design and documentation

- `spec/` is the normative authority for accepted target product and domain behavior. Product implementation must conform to it.
- `docs/` is public guidance. It may describe clearly labeled product direction, but only implemented and released capabilities may be presented as available.

## Source map

- `spec/` — normative target product and domain specifications; keep unresolved discussion and review metadata out
- `spec/ui/` — normative console information architecture, browser routes, guards, and workflows
- `local-reference/` — non-normative architecture challenges, alternatives, review notes, and discussion drafts
- `crates/owlrora-cli/src/` — independent `owlrora` management CLI and native self-update; the local stdio MCP adapter is planned here
- `crates/owlrora-key-provider/src/` — bounded provider-neutral custom secret-custody SPI
- `crates/owlrora-server/src/` — Axum server, `owlrora-server` executable, and embedded frontend delivery
- `crates/owlrora-server/web/dist/` — tracked production frontend assets packaged with the server crate
- `apps/web/` — React and Vite frontend source
- `docs/` — VitePress documentation deployed with Cloudflare Workers
- `scripts/docker/` — container smoke tests
- `scripts/release/` — release version preparation and crates.io publication

## Repository boundaries

- Keep `spec/` focused on the chosen target design. Put objections, alternatives, unresolved trade-offs, and review notes in `local-reference/`; do not implement them as accepted behavior until the target specs change.
- Keep management APIs query/command oriented: use `GET` for queries, coarse tri-state `POST .../actions/update` commands for ordinary resource changes, and explicit action commands only for distinct lifecycle or one-time-secret semantics. Every coarse `POST .../actions/update` requires the resource's opaque HTTP `ETag` in `If-Match`; keep this one uniform check and do not expose database revisions or classify fields separately. Do not add application `PUT`, `PATCH`, or `DELETE` operations.
- Keep identity pluggable. OwlAuth is an optional adapter; direct administration and trusted external JWT issuers must not depend on OwlAuth domain or storage. Management keys/key-derived sessions, external sessions, JWTs, and gateway keys must converge on one typed authorization pipeline. Durable keys authenticate as deployment/organization resource principals, never their creator user. Keep Management API keys and Gateway API keys as disjoint credential classes with distinct prefixes, scopes, verifier indexes, accepted surfaces, and audit fields; neither class is user-owned. External JWT/OIDC management access requires explicit issuer management-scope and organization ceilings; coarse `management:access` never implies scopes or deployment-wide reach, and OIDC sessions capture ceilings so later expansion requires re-login. A direct-JWT issuer is API-only unless it has an explicit bounded OIDC browser-login profile; JWKS refresh persists and journals immutable verifier-material versions rather than mutating runtime keys in place.
- Model client-facing models as first-class routes with explicit targets and policy; do not add a model-alias abstraction.
- Keep upstream credentials, endpoints, and model deployments as separate reusable resources. Support organization-only BYOK credentials and same-organization deployments while keeping endpoints/system egress profiles deployment-owned and explicitly granted; BYOK never grants endpoint editing or cross-organization secret reuse. Do not reintroduce a provider-connection aggregate that bundles vendor kind, endpoint, credential, and model.
- Preserve protocol-native LLM requests and use direct matching transports by default; do not force Anthropic, OpenAI, and Gemini through a lossy universal request model.
- Only Gateway API keys are quota-bearing request principals. Require every key to have a non-empty stable route-ID allowlist and one finite overall budget. For each actual key attempt, also consume exactly one organization origin budget derived from deployment scope: system administrators assign the organization's `system_provided` pool, while organization owners/admins manage its `organization_byok` pool within ceilings. Both key and origin policies support `enforce` and `record_only`; mixed routes may fail over across origins and settle every attempt against its actual target origin. Direct-JWT traffic is observed without fabricated quota. Never copy a key's creator into request user attribution. Use paired amortized Redis allowances and bounded recovery rather than a financial ledger or default per-request coordination.
- Store OwlRora-persisted non-recoverable bearer values only as domain-separated SHA-256 digests. Support scoped, revocable deployment-owned and organization-owned Management API keys whose effective permission is the intersection of key scopes/capabilities, immutable resource scope, current key policy, and any required deployment administrator grant. Organization Management/Gateway keys are managed by owners/admins, exact-capability same-organization Management-key principals, or qualifying system administrators through explicit organization context; organization policy may allow bounded member creation. Persist immutable `standard | member_self_service` issuance policy class so member-policy tightening never consults creator identity or lifecycle. `created_by_principal` is audit attribution only and never ownership or runtime authority. Keep the high-entropy `OWLRORA_SEED_ADMIN_API_KEY` solely in deployment configuration: it is a full-scope management key for the built-in API-key-only `seed_admin` user, never enters PostgreSQL or LLM authentication, and every action is audited as that user and key identity. Derive one deterministic `seed_admin_key_version_id` for direct constant-time verification and key-session rotation checks; do not add separate verifier/fingerprint derivations. It may directly administer the system or grant an active local user/deployment-owned Management-key principal `SystemAdministratorGrant`; do not reintroduce one-time bootstrap authority.
- The official server binary protects recoverable secrets directly with versioned authenticated encryption rooted in the explicit `OWLRORA_SECRET_ROOT` environment value and an immutable PostgreSQL installation ID in AAD; never add a fixed/generated fallback or a built-in KMS adapter. With no per-secret DEK/root ring, delete no-longer-needed active ciphertext and never claim per-secret cryptographic erasure. Keep `owlrora-key-provider` as a small provider-neutral SPI for user crates statically linked into custom server binaries, following OwlAuth's composition model.
- Support only the explicitly modeled OpenAI Codex subscription credential, and only through the OpenAI Responses semantic family. Treat it as a community-maintained best-effort adapter shipped with OwlRora; do not add a compatibility-profile catalog, SLA, or generic provider-subscription framework.
- Keep PostgreSQL and synchronous raw request logging off the normal data-plane path; capture one coherent runtime generation before authentication and use it through dispatch. Serialize runtime-affecting commit revisions, then build generations from one PostgreSQL MVCC/revision fence; use compact aggregates, amortized coordination, and asynchronous standard OpenTelemetry.
- Keep the console GitLab-like: one `/admin` deployment-wide area, organization workspaces under `/organizations/{organization_id}`, and a small personal area with no personal API-key management. Keep browser-route authority IDs stable and opaque, make system access explicit, and render `seed_admin` as a built-in API-key-only user without fabricating a durable local-user row, membership, tenant owner, or gateway key.
- Keep frontend source in `apps/web`; do not move application source into the Rust crate.
- Keep public user documentation in `docs`, normative target design in `spec`, and non-normative discussion in `local-reference`; docs are not an application under `apps`.
- Keep server-side product domain, gateway, protocols, infrastructure, HTTP, workers, and bundled software encryption as modules compiled together in `owlrora-server`; its executable is `owlrora-server`. Keep the independently released management CLI and local stdio MCP adapter together in `owlrora-cli`; its executable is `owlrora`. The CLI package must not depend on or launch the server and must use only public management HTTP APIs, preserving authorization/tenant/ETag/audit/one-time-secret semantics without a generic raw HTTP tool. Do not extract additional shared crates until a real independently publishable API or material dependency/security boundary makes that split simpler. Keep `owlrora-key-provider` as the externally implementable SPI published before `owlrora-server`. Every published crate must build without Node.js or unpublished sibling paths.
- Keep the runtime image non-root and preserve the `/health` endpoint for container health checks.

## Embedded frontend assets

- Vite builds `apps/web` into `crates/owlrora-server/web/dist`.
- The generated production assets are committed because `owlrora-server` embeds them and publishes them to crates.io.
- Run `pnpm build` after every frontend change and commit the resulting asset updates.
- Never edit generated assets directly. CI rebuilds them and rejects drift.
- Build the frontend before compiling the server when generated assets are not already present.

## Documentation

- Use VitePress under `docs` and deploy its static output with Cloudflare Workers.
- Clearly label product direction and roadmap material. Do not present planned capabilities as implemented or available.
- Run `make docs-build` before submitting documentation changes.
- The `Docs` workflow always builds and dry-runs deployment. It deploys `main` only when the `docs` environment provides `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`.

## Validation

- Run `make check`, `make test`, `make build`, `make package-check`, and `make docs-build` before submitting changes.
- Keep Cargo and pnpm lockfiles current and use locked installs and builds in CI.
- Preserve the server image smoke test whenever container startup, routing, assets, or health behavior changes.

## Releases

- Keep committed `owlrora-cli`, `owlrora-key-provider`, and `owlrora-server` versions, plus the server's exact key-provider dependency requirement, at the reserved `0.0.0-dev` development sentinel.
- CLI tags use `cli-v<semver>` and publish `owlrora-cli` plus five platform archives for its single `owlrora` binary and `SHA256SUMS`; they publish no server crate or container. Four Unix archives are `.tar.gz`; the Windows x86_64 archive is `.zip`. Release SemVer may include prerelease identifiers but not build metadata. The native updater selects only `cli-v*`, keeps its repository and HTTPS redirect origins fixed, verifies one exact checksum and one-file archive inventory, and performs transaction-locked cross-platform replacement of the exact running path. The checksum shares the GitHub Release trust boundary and is not an independent signature.
- Server tags create a GitHub Release, publish `owlrora-key-provider` then `owlrora-server` at one exact version, and publish one immutable GHCR version tag. Do not publish or promote a mutable `latest` tag; reruns preserve any existing version-tag digest and release. The manual release workflow input may backfill an existing `server-v<semver>` tag from that tag's source without moving the tag.
- Do not commit a release-only version bump. `scripts/release/prepare_release.py` materializes only the selected tag component in its manifests, exact internal requirements, and `Cargo.lock` inside the workflow; the unrelated component remains at the development sentinel.
- Do not run `cargo publish` manually. CI owns tests, package verification, cross-platform checks, and server-image smoke tests. Release workflows only construct and publish their required artifacts; do not add test/smoke jobs, main-branch comparisons, commit-history checks, or ordinary CI execution to them.
- Configure `CARGO_REGISTRY_TOKEN` before an initial CLI or server tag. A rerun may publish a crate only when its crates.io checksum exactly matches the package generated from tagged source.
