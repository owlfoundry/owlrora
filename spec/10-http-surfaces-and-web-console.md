# HTTP surfaces and web console

## 1. HTTP surfaces

One server exposes three logical surfaces:

1. **Process health** — unauthenticated, minimal `/health` and optional `/ready` only;
2. **LLM compatibility** — Anthropic, OpenAI, and Google protocol paths;
3. **Management application** — versioned OwlRora APIs, protected operational diagnostics/recovery, authentication adapters, and the embedded React console.

Each surface has distinct middleware, body/time limits, authentication, CORS, error, and telemetry policy. Protected operational APIs are not an unversioned fourth surface: they are typed management routes under `/api/v1/system/operations/**`, use the management envelope and descriptor, and remain excluded from SPA fallback through the `/api/` prefix.

## 2. Management method model

Management APIs use:

- `GET` for side-effect-free queries;
- `POST .../actions/create` for resource creation;
- `POST .../{id}/actions/update` for a coarse validated identified-resource update;
- `POST .../actions/update` for a coarse validated singleton or complete-set aggregate update;
- explicit `POST .../actions/<verb>` only when the command has semantics that are not a field update.

Explicit commands include one-time secret creation/rotation, invitation acceptance, Codex device authorization, provider validation, budget epoch creation, and destructive recovery operations.

OwlRora does not expose application `PUT`, `PATCH`, or `DELETE`. It also avoids one endpoint per ordinary editable field.

### 2.1 Tri-state update fields

Every update DTO uses generated tri-state fields:

```text
UpdateField<T> =
    omitted       -> leave unchanged
    null          -> clear, only when the field is nullable
    value(T)      -> replace with validated value
```

An empty update is rejected. `null` on a non-nullable field is a typed validation error. Nested objects are replaced as documented rather than recursively merge-patched by accident.

One update command validates the resulting aggregate and dependent graph transactionally. For example, updating a route may replace display metadata, status, selection policy, reliability policy, request policy, and the complete target set in one candidate revision. The server publishes either the full valid result or no change.

The concurrency rule is uniform: every ordinary `actions/update`, whether identified-resource, singleton, or complete-set aggregate, requires the strong opaque `ETag` returned by its latest authoritative `GET` representation in `If-Match`. A missing precondition returns `428`; a stale precondition returns `412` with safe current representation metadata. Create commands and distinct lifecycle/one-time actions use their own idempotency/state-machine semantics and do not inherit this rule.

The tag covers the authoritative editable resource representation and excludes volatile health, usage, and diagnostics. It is one server-generated HTTP representation version, not a database transaction ID, a body field, or a field-by-field conflict classifier. This single check prevents stale whole-resource editors from restoring removed targets or grants without requiring merge semantics.

A complete target replacement carries stable IDs for existing targets; new entries omit ID and receive a new never-reused ID. The server preserves each existing target’s `affinity_identity`, rejects foreign/retired IDs, and never turns remove-plus-recreate into identity reuse.

A lifecycle transition carried by the ordinary update DTO uses the same `If-Match` rule and receives the same confirmation, authorization, audit, and fail-closed publication behavior as a dedicated verb.

### 2.2 Singleton and complete-set aggregates

A singleton or authoritative complete-set aggregate has one canonical representation and update path:

```text
GET  /api/v1/.../{aggregate}
POST /api/v1/.../{aggregate}/actions/update
```

The `GET` returns the aggregate's strong `ETag`; the update applies the same tri-state DTO, `If-Match`, `412`, and `428` rules as an identified resource. The aggregate path is not a collection create endpoint. This convention covers Gateway-key budget/limits, organization origin budgets, API-key issuance policy, and organization catalog-grant sets.

## 3. Versioning and media types

- Management paths begin with `/api/v1`.
- Additive response fields are backward compatible.
- Removed/renamed fields or changed command meaning require a new API version or migration window.
- JSON is UTF-8 unless a route explicitly streams or downloads.
- Unsupported content type returns `415`.
- Management schemas come from one checked typed source and generate OpenAPI.

Protocol compatibility versioning follows the relevant vendor path/header contract and the capabilities advertised by the running OwlRora build.

## 4. Authentication

| Surface | Accepted authentication |
| --- | --- |
| `/health`, optionally minimal `/ready` | none; responses expose process state only |
| `/api/v1/system/operations/**` | operator-network policy plus an authorized management API key/key-derived session, external session, or trusted JWT resolving to an authorized user with `management:operations` and read/write scope as required |
| other `/api/v1/**` | management API key/key-derived session, external local-user web session, or trusted JWT resolving to an authorized user |
| LLM compatibility paths | gateway API key or trusted JWT resolving to an authorized local user/organization |
| embedded static assets | none |

Management API keys use `Authorization: Bearer <management-api-key>` and a distinct versioned management prefix. They resolve the configured `seed_admin` user or a durable deployment/organization key resource principal, preserve the key's scopes/capabilities and immutable resource scope, enter the same typed authorizer, and are rejected on every LLM compatibility path. A key-derived browser session preserves the exact key principal, key identity/version, ceilings, resource scope, and authentication origin; it never substitutes the creator user.

Gateway API keys use their own versioned LLM prefix and protocol-compatible header locations. A syntactically valid key of the wrong class is rejected without trying to reinterpret it. JWT verification and local authorization are shared across management and LLM surfaces. Audience proves the token was intended for OwlRora. A management JWT/session requires issuer/token `management:access`, the operation's concrete scopes from the explicit issuer management-scope ceiling, the effective issuer management-organization ceiling, and current local capabilities; `management:access` alone grants nothing. LLM requests require the applicable LLM scopes and current local authority.

Provider credentials, Codex access tokens, external identity tokens, management API keys, and the seed-administrator deployment key are never accepted as gateway API keys.

## 5. Management errors

```json
{
  "error": {
    "code": "membership_not_active",
    "message": "The requested operation is not permitted for this organization.",
    "request_id": "req_...",
    "details": {}
  }
}
```

- `code` is stable and machine-readable.
- `message` is safe and contains no SQL, secret, KMS, network, or provider internal.
- `details` is optional, typed, and bounded.
- `request_id` is always present.
- Lookup/authorization responses do not reveal cross-tenant existence.

Status conventions are `400` syntax, `401` authentication, `403` authorization, `404` absent/concealed, `409` domain state conflict, `412` stale `If-Match`, `422` typed validation, `428` required precondition missing, `429` management rate limit, and `503` required control dependency unavailable.

Public commands do not accept an `expected_revision` body field or expose persistence revisions. Application transactions always validate current state; every ordinary update uses the same opaque HTTP precondition defined above.

## 6. Pagination, filtering, and time

Unbounded lists use opaque cursor pagination with bounded `limit`, allowlisted filters, stable ordering, and a unique tie-breaker. A cursor binds its ordering/filter context and is reauthorized when decoded.

Timestamps are RFC 3339 UTC. Usage intervals are half-open `[start, end)` with bounded range and granularity. Monetary values use decimal strings and explicit currency/scale.

## 7. Command idempotency

Commands likely to receive duplicate delivery accept `Idempotency-Key`, including ordinary resource creation, invitation resend, provisioning callbacks, policy updates from platforms, and begin-epoch.

The key is scoped to actor, organization/system scope, action, and canonical request fingerprint. Reuse with a different fingerprint returns conflict.

Management-key and gateway-key create/rotate plus any command returning new non-recoverable bearer material reject idempotency. An ambiguous response is recovered by invalidating undisclosed material and issuing new material.

Codex device-login start/complete use explicit login-session identity and state-machine idempotency rather than replaying OAuth secret responses through generic command storage.

## 8. Route-family convention

For a collection `R` and resource ID:

```text
GET  /api/v1/.../R
POST /api/v1/.../R/actions/create
GET  /api/v1/.../R/{id}
POST /api/v1/.../R/{id}/actions/update
```

For singleton or complete-set aggregate `S`:

```text
GET  /api/v1/.../S
POST /api/v1/.../S/actions/update
```

The update endpoint carries the tri-state aggregate DTO and requires the `GET` representation's `ETag`. The following sections list resource families rather than repeating these paths for each resource.

## 9. Management API key authentication and current principal

```text
POST /auth/v1/management-api-key/session/actions/create

GET  /api/v1/session
POST /api/v1/session/actions/logout
GET  /api/v1/me
GET  /api/v1/me/organizations
GET  /api/v1/me/usage
```

The browser exchange accepts one `ManagementApiKey` over TLS, returns only an opaque secure session cookie, and never persists or echoes the key. The session binds the exact seed, deployment-key, or organization-key principal, key ID/version, resource scope, and scope/capability ceiling captured at exchange. Each later request intersects that ceiling with current key and deployment/organization key policy: narrowing and disablement apply under the normal security-propagation objective, while a later key/policy expansion requires a new exchange and cannot widen the existing session. Key rotation invalidates the session when its accepted version leaves overlap. For `seed_admin`, the protected session record alone stores the deterministic `seed_admin_key_version_id` from specification 11; no API, audit, telemetry, or diagnostic field exposes it. The console keeps no raw key in browser storage. CLI, MCP, and embedding clients use the same key directly with the Bearer scheme.

No first-run bootstrap user is required: `seed_admin` can configure an issuer, provision or observe a registered local user, and grant that user ordinary system-administrator authority. Only issuers with an active optional browser-login profile expose the bounded OpenID Connect routes below; direct-JWT-only issuers do not appear as console login choices.

```text
GET /auth/v1/issuers/{issuer_name}/login
GET /auth/v1/issuers/{issuer_name}/callback
```

The login route creates state/nonce/PKCE evidence and redirects to the configured authorization endpoint. The callback consumes the one-time code, performs server-side token exchange/validation, creates the local-user session with the captured concrete management scope set and issuer/login organization/capability ceilings defined in specifications 02 and 03, removes code-bearing callback state from browser history, and redirects to an allowlisted console path. `GET /api/v1/me` returns `principal_kind=seed_admin|local_user|deployment_management_api_key|organization_management_api_key`, authentication origin, safe key resource identity where applicable, effective typed capabilities/scopes, and safe allowed-organization metadata needed for context selection. These are the result of the current typed principal, credential/session, and policy intersection, not creator attribution. Calls by non-local-user principals to local-user-only `/me` subresources return a typed not-applicable denial rather than an empty list or fabricated membership/ownership.

## 10. Management keys, system identity, and tenancy resources

Durable scoped Management API keys are resource-qualified:

```text
/api/v1/system/management-api-keys
/api/v1/organizations/{organization_id}/management-api-keys
```

Deployment and organization collections never merge. Create fixes resource scope from the path, records `created_by_principal`, and accepts concrete scopes/capability ceiling, expiry, and name without an owner user. Ordinary metadata/scope/status/expiry changes use detail `actions/update` with `If-Match`; rotation is explicit and returns new material once. Every create, scope/capability widening, rotation, re-enable/reactivation, expiry extension, or overlap restoration/extension applies specification 03's target credential dominance rule and current destination key policy. A narrow caller may still perform an authorized one-way disablement, narrowing, expiry shortening, or overlap termination:

```text
POST /api/v1/system/management-api-keys/actions/create
POST /api/v1/system/management-api-keys/{management_api_key_id}/actions/update
POST /api/v1/system/management-api-keys/{management_api_key_id}/actions/rotate
POST /api/v1/organizations/{organization_id}/management-api-keys/actions/create
POST /api/v1/organizations/{organization_id}/management-api-keys/{management_api_key_id}/actions/update
POST /api/v1/organizations/{organization_id}/management-api-keys/{management_api_key_id}/actions/rotate
```

The configured `seed_admin` key appears only as safe built-in authority metadata in current-principal/administrator views and is never a resource in either family.

System resource families:

```text
/api/v1/system/users
/api/v1/system/organizations
/api/v1/system/identity-issuers
/api/v1/system/identity-bindings
/api/v1/system/administrators
/api/v1/system/provisioning-policies
```

Each supports collection/detail query and authorized create/update as meaningful. Binding relink remains an explicit command because it carries identity-collision semantics. System-administrator authority uses explicit commands rather than generic resource creation/deletion:

```text
POST /api/v1/system/administrators/actions/grant
POST /api/v1/system/administrators/{subject_kind}/{subject_id}/actions/revoke
```

The target must be an existing active local user or active deployment-owned Management API key. Both `seed_admin` and a currently authorized system-administrator principal may invoke these commands when the calling credential/session includes `management:write` and `management:authority`. Granting a deployment key checks target credential dominance against the key's complete post-grant authority; creating the key and granting it are separate audited commands. `seed_admin` itself is returned separately as built-in authority and is never a grant row or command target.

Optional issuer browser-login configuration is part of the issuer representation and ordinary ETag update. Confidential client material uses explicit write-only actions:

```text
POST /api/v1/system/identity-issuers/{issuer_id}/browser-login/actions/replace-client-secret
POST /api/v1/system/identity-issuers/{issuer_id}/browser-login/actions/validate
```

System audit evidence is query-only:

```text
GET /api/v1/system/audit
```

System audit uses bounded cursor/time/filter semantics and returns immutable sanitized records. There is no parallel `/api/v1/system/status` diagnostic endpoint: deployment readiness, runtime publication, coordination, custody, queue, and telemetry state are available only through the protected operations family below. Ordinary system resource queries may return bounded per-resource lifecycle/status fields but MUST NOT aggregate or proxy protected operational posture.

Protected operational diagnostics and recovery use versioned management routes only:

```text
GET /api/v1/system/operations
GET /api/v1/system/operations/readiness
GET /api/v1/system/operations/runtime
GET /api/v1/system/operations/coordination
GET /api/v1/system/operations/coordination/recoveries
GET /api/v1/system/operations/secret-custody
GET /api/v1/system/operations/usage-pipeline
GET /api/v1/system/operations/telemetry
POST /api/v1/system/operations/.../actions/<typed-recovery-command>
```

Every route is represented in the same checked operation descriptor, OpenAPI document, management error envelope, CLI inventory, and MCP inventory as other management APIs. It requires `management:operations` plus `management:read` for diagnostics or `management:write` for a recovery/mutation command, current system-administrator capability, and the configured operator-network policy. Diagnostic `GET`s are side-effect-free and create no durable per-request audit row; bounded request metadata and telemetry are sufficient. Every accepted recovery/mutation command commits its durable audit evidence under the normal command contract. Public `/health` and `/ready` never proxy or summarize these protected details.

## 11. Upstream catalog resources

System resource families:

```text
/api/v1/system/upstream-credentials
/api/v1/system/upstream-endpoints
/api/v1/system/model-deployments
/api/v1/system/pricing-policies
/api/v1/system/reliability-policies
/api/v1/system/model-routes
/api/v1/system/gateway-policy-ceilings
```

Important explicit commands are:

```text
POST /api/v1/system/upstream-credentials/{id}/actions/replace-secret
POST /api/v1/system/upstream-credentials/{id}/actions/reload-source
POST /api/v1/system/upstream-credentials/{id}/actions/validate
POST /api/v1/system/upstream-endpoints/{id}/actions/validate
POST /api/v1/system/model-deployments/{id}/actions/validate
POST /api/v1/system/pricing-policies/{id}/actions/publish-version
```

Create/replace secret accepts write-only material or a typed external source reference. Queries expose source kind, custody-provider/format metadata, credential state, expiry, version, and validation status without ciphertext, opaque envelopes, fingerprints usable as secrets, or plaintext.

A route update may replace its full target set atomically rather than requiring add/update/remove target endpoints. Like every ordinary update, it requires `If-Match` and stable existing target IDs. Deployment, route, and reliability grants use the organization-qualified complete-set paths defined below, or explicit grant/revoke commands when external platforms need idempotent deltas.

## 12. Codex subscription management

Only an `oauth_openai_codex` credential exposes subscription login routes:

```text
POST /api/v1/system/upstream-credentials/{id}/codex-login/actions/start
GET  /api/v1/system/upstream-credentials/{id}/codex-login/{session_id}
POST /api/v1/system/upstream-credentials/{id}/codex-login/{session_id}/actions/complete
POST /api/v1/system/upstream-credentials/{id}/codex-login/{session_id}/actions/cancel
POST /api/v1/system/upstream-credentials/{id}/actions/refresh
POST /api/v1/system/upstream-credentials/{id}/actions/revoke
```

Start returns the safe verification URL, user code, expiry, and polling interval once. It never returns OAuth access/refresh/ID tokens. Complete follows provider polling semantics and returns credential status only. Refresh and revoke are audited high-impact commands.

No generic provider-subscription route family exists.

## 13. Organization resources

Organization-qualified families:

```text
/api/v1/organizations/{organization_id}
/api/v1/organizations/{organization_id}/members
/api/v1/organizations/{organization_id}/invitations
/api/v1/organizations/{organization_id}/management-api-keys
/api/v1/organizations/{organization_id}/gateway-api-keys
/api/v1/organizations/{organization_id}/api-key-policy
/api/v1/organizations/{organization_id}/upstream-credentials
/api/v1/organizations/{organization_id}/model-deployments
/api/v1/organizations/{organization_id}/model-routes
/api/v1/organizations/{organization_id}/provider-budgets/system
/api/v1/organizations/{organization_id}/provider-budgets/byok
/api/v1/organizations/{organization_id}/system-route-grants
/api/v1/organizations/{organization_id}/endpoint-grants
/api/v1/organizations/{organization_id}/deployment-grants
/api/v1/organizations/{organization_id}/reliability-policy-grants
```

Read-only discovery and evidence:

```text
GET /api/v1/organizations/{organization_id}/available-routes
GET /api/v1/organizations/{organization_id}/available-endpoints
GET /api/v1/organizations/{organization_id}/available-deployments
GET /api/v1/organizations/{organization_id}/available-reliability-policies
GET /api/v1/organizations/{organization_id}/usage
GET /api/v1/organizations/{organization_id}/usage/breakdown
GET /api/v1/organizations/{organization_id}/audit
```

Membership updates can set role and scope ceiling together. Removal and invitation acceptance remain explicit commands because they have lifecycle/token semantics. Organization route updates may replace complete target configuration atomically. Route create always names one eligible active-member `owner_user_id`; a Management-key or system-administrator actor never becomes or fabricates that owner. Ownership transfer is a distinct audited command requiring the current route ETag and one eligible active-member destination:

```text
POST /api/v1/organizations/{organization_id}/model-routes/{route_id}/actions/transfer-ownership
```

Gateway-key routes add explicit one-time operations:

```text
POST /api/v1/organizations/{organization_id}/gateway-api-keys/actions/create
POST /api/v1/organizations/{organization_id}/gateway-api-keys/{gateway_api_key_id}/actions/rotate
```

Both key classes are organization resources with immutable `created_by_principal`, not user-owned credentials. Authorized paths are an owner/admin local user, a policy-enabled member for creation only, a same-organization Management-key principal with exact scope/capability and target dominance, or a qualifying system administrator through explicit organization context. Every key stores immutable `issuance_policy_class=standard|member_self_service`, which selects policy ceilings without consulting creator identity or lifecycle. Every Gateway key requires a non-empty stable route-ID allowlist and a finite overall key budget; neither a provider allowlist nor an all-current/future-routes shortcut exists.

Organization BYOK and deployment commands are:

```text
POST /api/v1/organizations/{organization_id}/upstream-credentials/actions/create
POST /api/v1/organizations/{organization_id}/upstream-credentials/{credential_id}/actions/update
POST /api/v1/organizations/{organization_id}/upstream-credentials/{credential_id}/actions/replace-secret
POST /api/v1/organizations/{organization_id}/upstream-credentials/{credential_id}/actions/validate
POST /api/v1/organizations/{organization_id}/model-deployments/actions/create
POST /api/v1/organizations/{organization_id}/model-deployments/{deployment_id}/actions/update
POST /api/v1/organizations/{organization_id}/model-deployments/{deployment_id}/actions/validate
```

Credential create/replace requires `management:write`, `management:secrets`, organization BYOK capability, and a write-only encrypted-database secret supported by an organization-self-service-safe adapter. Organization deployment create/update requires a same-organization credential and granted system endpoint; no organization endpoint create/update route exists.

`api-key-policy`, each origin-budget path, each Gateway-key budget/limits path, and each grant-set path are canonical singleton/complete-set representations. Their ordinary update is `POST {path}/actions/update` with the `GET` ETag. Each grant-set update carries the complete desired stable-ID set and atomically removes omitted prior grants. Catalog-grant mutation requires system-administrator capability; organization roles may consume/configure only resources already inside those grants. Revoking an endpoint grant makes dependent organization deployments ineligible and publishes as security tightening.

The two budget layers have explicit paths:

```text
GET  /api/v1/organizations/{organization_id}/gateway-api-keys/{gateway_api_key_id}/budget
POST /api/v1/organizations/{organization_id}/gateway-api-keys/{gateway_api_key_id}/budget/actions/update
GET  /api/v1/organizations/{organization_id}/gateway-api-keys/{gateway_api_key_id}/limits
POST /api/v1/organizations/{organization_id}/gateway-api-keys/{gateway_api_key_id}/limits/actions/update

GET  /api/v1/organizations/{organization_id}/provider-budgets/system
POST /api/v1/organizations/{organization_id}/provider-budgets/system/actions/update
GET  /api/v1/organizations/{organization_id}/provider-budgets/byok
POST /api/v1/organizations/{organization_id}/provider-budgets/byok/actions/update
```

`system` is the organization's collective budget for attempts using granted system deployments and only a system administrator may update/begin its epoch. `byok` is the collective budget for attempts using same-organization deployments and organization budget authority may update/begin it within system ceilings. Both expose `enforce | record_only`. The key budget spans every attempt made by that key across both origins. Beginning an epoch remains explicit:

```text
POST /api/v1/organizations/{organization_id}/gateway-api-keys/{gateway_api_key_id}/budget/actions/begin-epoch
POST /api/v1/organizations/{organization_id}/provider-budgets/system/actions/begin-epoch
POST /api/v1/organizations/{organization_id}/provider-budgets/byok/actions/begin-epoch
```

## 14. LLM compatibility routes

```text
POST /v1/messages
POST /v1/chat/completions
POST /v1/responses
POST /v1beta/models/{model}:generateContent
POST /v1beta/models/{model}:streamGenerateContent
```

Responses WebSocket uses only its documented protocol-compatible route. These endpoints use protocol-native auth locations, limits, streams, and error envelopes rather than the management envelope.

Direct JWT LLM requests select organization through configured claim/header policy and pass the same local membership/route authorizer as Gateway-key requests. They record usage but do not receive a fabricated Gateway key, route allowlist, key budget, provider-origin budget, rate policy, or concurrency policy.

## 15. Browser security

Cookie-authenticated management commands require secure HTTP-only session cookies, strict allowed origin, CSRF defense, no application state change through `GET`, restrictive CSP, clickjacking/MIME/referrer protections, and `Cache-Control: no-store` for sensitive responses. The one-time OpenID Connect callback may consume its bound state/code and create a session as an authentication-protocol endpoint; it cannot execute a management command.

The management-key session exchange is TLS-only, same-origin, non-cacheable, body-bounded, and separately rate-limited. Authentication middleware consumes and redacts the submitted key before request diagnostics or telemetry can inspect values. The form uses a password control with autocomplete disabled and clears its in-memory value after every attempt.

Direct management-key and bearer-JWT calls use strict CORS and normal local authorization. CORS is same-origin by default; wildcard with credentials or authorization is forbidden.

The SPA fallback excludes `/api/`, `/auth/`, `/v1/`, `/v1beta/`, `/health`, and `/ready`; protected operational routes are already covered by `/api/`.

## 16. Console information architecture

The embedded React console is a complete management client for the target architecture. The normative information architecture, browser routes, guards, workflows, visual direction, and reference mockups are defined under [`ui/`](ui/README.md); this section records the shared safety boundary.

### 16.1 Global shell

- exact user kind (`seed_admin` or local user), management-key identity where applicable, effective key ceiling, and authentication origin;
- in-memory-only management-key entry followed by secure session exchange;
- organization selector for local users and explicit organization context for system administrators;
- separate system-administration navigation;
- current snapshot, Redis allowance, aggregate, secret-custody, and telemetry warnings;
- no redisplay of one-time secrets.

### 16.2 Organization views

- Overview — requests, failures, retries, cost, separated key/system-provider/BYOK budget state, and warnings;
- Management and Gateway API keys — organization automation/LLM resources, reveal-once lifecycle, required route allowlists, overall key budgets, and key-only limits;
- Members, invitations, and API-key issuance policy;
- BYOK credentials and same-organization deployments;
- Routes — first-class groups that may mix granted system and BYOK deployments;
- Usage — bounded user/key/route/origin/deployment breakdowns;
- Provider budgets — read-only system allocation for organization actors and organization-managed BYOK pool, with explicit mode/approximation/drift state;
- Audit and settings.

### 16.3 System views

- system readiness and runtime revision;
- users, scoped management API keys, organizations, synthetic entities, issuers, bindings, administrators;
- upstream credentials, encrypted-secret/key-provider state, and Codex login/refresh;
- endpoints, deployments, capabilities, pricing, reliability policies;
- shared routes and organization grants;
- Redis allowance/health, snapshot lag, aggregates, telemetry, audit.

### 16.4 Safety

Every editor retains the detail response `ETag`; on `412` it reloads and shows the user the conflict instead of automatically replaying a stale update. High-impact updates also show the complete resulting state and consequence before confirmation. Secret values are one-time, non-cacheable, and absent after navigation. Route editors call the resource a route, show target priority/weight/health, and never label the model key as an alias. Budget views distinguish the Gateway key overall budget from the organization's `system_provided` and `organization_byok` pools. Each shows `enforce | record_only`, desired/staged/armed/active/finalized policy and prior-generation cutoff, settled aggregate evidence, active local/distributed allowance, calculated drift bounds, estimated remaining capacity, and uncertainty; a mixed route never collapses the two origins into one balance.
