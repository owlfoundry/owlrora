# Console routes and workflows

## 1. Routing contract

Browser routes are client-side paths served by the embedded SPA. They are not management API paths and do not change the API conventions in specification 10.

A route definition contains:

- a stable path pattern;
- one coarse navigation guard;
- a data loader that calls the authorized management query;
- capability checks for individual controls;
- a breadcrumb and context-sidebar registration;
- explicit loading, empty, forbidden, absent, degraded, and error states.

The server remains authoritative. A frontend guard may hide navigation or redirect after a known principal response, but it MUST NOT substitute for API authorization. Resource loaders use organization-qualified APIs and treat concealed `404` differently only when the server safely distinguishes it.

## 2. Route parameters and query state

- `{organization_id}`, `{user_id}`, `{resource_id}`, and other authority parameters are opaque stable IDs.
- Mutable names/slugs may appear in labels and search, never as the sole authorization key.
- Cursor, allowlisted filter, sort, time range, breakdown, and selected tab may use query parameters.
- Secrets, bearer values, OAuth codes after callback completion, provider errors, prompts, responses, and raw filter expressions never appear in browser URLs.
- A `return_to` value is accepted only when it decodes to a same-origin allowlisted console path without credentials or nested external URLs.
- Tabs that represent durable/deep-linkable information use path or bounded query state; a modal is not the only route to a core resource.

## 3. Guard vocabulary

| Guard | Meaning |
| --- | --- |
| `PublicOnly` | no active console session; an authenticated principal redirects through root selection |
| `Authenticated` | active `seed_admin`, local-user, deployment Management-key, or organization Management-key session |
| `LocalUser` | active durable local-user principal; all key principals receive not-applicable/redirect behavior |
| `SystemAdministrator` | built-in `seed_admin`, active granted local user, or active granted deployment Management key after scope/capability and current deployment-policy intersection; organization keys and creator grants never qualify |
| `OrganizationVisible` | active membership with read capability, matching organization Management-key principal, or explicit system-administrator access to the named organization |
| `OrganizationManage` | server-authorized tenant management capability or explicit system authority |
| `OrganizationOwner` | owner-only tenant action or explicit system authority, subject to domain invariants |

A route uses the weakest guard needed to load its safe shell. Page controls use typed capabilities returned by the API. For example, an organization member may load the gateway-key list route but sees only keys and actions permitted by current policy.

## 4. Public and session routes

| Browser route | Guard | Purpose | Primary API relationship |
| --- | --- | --- | --- |
| `/` | any | deterministic context redirect | `GET /api/v1/session`, `GET /api/v1/me` |
| `/sign-in` | `PublicOnly` | active browser-login issuer choices and management API key exchange | `GET /auth/v1/issuers/{issuer_name}/login`; management-key session create |
| `/signed-out` | public | safe logout completion | none |
| `/forbidden` | any | safe authorization failure | none |
| `/not-found` | any | absent or concealed resource | none |
| `/profile` | `Authenticated` | actor identity, origin, and applicable profile | `GET /api/v1/me` |
| `/profile/organizations` | `LocalUser` | membership index and context selection | `GET /api/v1/me/organizations` |
| `/profile/sessions` | `Authenticated` | current/other session state where supported | `GET /api/v1/session` and session commands |
| `/organizations` | `LocalUser` | organization membership selector | `GET /api/v1/me/organizations` |

`seed_admin` and durable key principals may view `/profile` only as a safe actor/session summary. Deployment keys link to Admin key management; organization keys link to their fixed organization. They are redirected from local-user membership routes and no personal API-key route exists.

## 5. Organization browser routes

All routes under `/organizations/{organization_id}` require `OrganizationVisible` before loading organization data. System-administrator access is clearly labeled and never fabricated as membership.

| Browser route | Page | Additional capability/action notes |
| --- | --- | --- |
| `/organizations/{organization_id}` | Overview | safe organization, usage, separate key/system/BYOK budget, route, and warning summaries |
| `/organizations/{organization_id}/members` | Members | list visible members and roles |
| `/organizations/{organization_id}/members/{user_id}` | Member detail | role/scope update uses ETag; remove is explicit |
| `/organizations/{organization_id}/invitations` | Invitations | invite/resend/revoke according to typed capability |
| `/organizations/{organization_id}/management-api-keys` | Management API keys | organization automation principals; all metadata server-filtered |
| `/organizations/{organization_id}/management-api-keys/new` | Create Management API key | policy/caller dominance plus one-time result |
| `/organizations/{organization_id}/management-api-keys/{management_api_key_id}` | Management-key detail | resource scope, scopes/capabilities, creator attribution; no raw key |
| `/organizations/{organization_id}/management-api-keys/{management_api_key_id}/edit` | Edit Management-key policy | uniform `If-Match` update |
| `/organizations/{organization_id}/management-api-keys/{management_api_key_id}/rotate` | Rotate Management API key | dominance check and explicit one-time reveal |
| `/organizations/{organization_id}/gateway-api-keys` | Gateway API keys | organization-owned LLM service keys; server-filtered |
| `/organizations/{organization_id}/gateway-api-keys/new` | Create gateway API key | one-time non-idempotent secret result |
| `/organizations/{organization_id}/gateway-api-keys/{gateway_api_key_id}` | Gateway-key detail | required route allowlist, overall budget, origin breakdown; no digest/raw key |
| `/organizations/{organization_id}/gateway-api-keys/{gateway_api_key_id}/edit` | Edit gateway-key policy | scopes/route allowlist/lifecycle with uniform `If-Match` update |
| `/organizations/{organization_id}/gateway-api-keys/{gateway_api_key_id}/budget` | Gateway-key overall budget | finite threshold, mode, epoch, policy state, grants, drift |
| `/organizations/{organization_id}/gateway-api-keys/{gateway_api_key_id}/limits` | Gateway-key request limits | optional key-only rate/concurrency policy |
| `/organizations/{organization_id}/gateway-api-keys/{gateway_api_key_id}/rotate` | Rotate Gateway API key | explicit one-time command and reveal state |
| `/organizations/{organization_id}/api-key-policy` | API key policy | member creation and per-class ceilings |
| `/organizations/{organization_id}/api-key-policy/edit` | API key policy editor | singleton ETag update |
| `/organizations/{organization_id}/upstream-credentials` | BYOK credentials | organization-only safe metadata and dependent deployments |
| `/organizations/{organization_id}/upstream-credentials/new` | Create BYOK credential | write-only encrypted secret and safe adapter kind |
| `/organizations/{organization_id}/upstream-credentials/{credential_id}` | BYOK credential detail | status/version/validation; no secret |
| `/organizations/{organization_id}/upstream-credentials/{credential_id}/edit` | Edit BYOK credential metadata/lifecycle | uniform ETag update; no secret/source widening |
| `/organizations/{organization_id}/upstream-credentials/{credential_id}/replace-secret` | Replace BYOK secret | write-only one-way action |
| `/organizations/{organization_id}/model-deployments` | Model deployments | same-org BYOK deployments plus safe eligibility state |
| `/organizations/{organization_id}/model-deployments/new` | Create model deployment | same-org credential and granted system endpoint only |
| `/organizations/{organization_id}/model-deployments/{deployment_id}` | Deployment detail | adapter/model/capabilities/validation/dependents |
| `/organizations/{organization_id}/model-deployments/{deployment_id}/edit` | Deployment editor | ETag update; no endpoint URL editing |
| `/organizations/{organization_id}/model-routes` | Model routes | granted system and organization-owned BYOK deployments |
| `/organizations/{organization_id}/model-routes/new` | Create organization route | only when organization route composition is enabled |
| `/organizations/{organization_id}/model-routes/{route_id}` | Route detail | targets, health, capabilities, grants, audit |
| `/organizations/{organization_id}/model-routes/{route_id}/edit` | Route editor | complete target set with stable IDs and ETag |
| `/organizations/{organization_id}/usage` | Usage | bounded time range with user/key/route/origin/deployment dimensions |
| `/organizations/{organization_id}/provider-budgets` | Provider budgets | read-only system allocation plus organization-managed BYOK pool; never one merged balance |
| `/organizations/{organization_id}/provider-budgets/byok/edit` | BYOK budget editor | `enforce | record_only`, finite threshold, epoch policy with ETag |
| `/organizations/{organization_id}/audit` | Audit | organization-qualified immutable evidence |
| `/organizations/{organization_id}/settings` | Settings | profile and lifecycle within authority |

### 5.1 Organization API mapping

The routes above use these API families rather than frontend-specific endpoints:

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
/api/v1/organizations/{organization_id}/usage
/api/v1/organizations/{organization_id}/audit
```

The console may combine several bounded queries on an overview page. It does not add an unbounded backend-for-frontend response that bypasses existing organization qualification. `api-key-policy`, both provider-origin budgets, each Gateway-key budget/limits aggregate, and the four catalog-grant sets use singleton `GET` plus `POST .../actions/update` and retain that `GET` response's ETag. Organization actors cannot edit `provider-budgets/system`.

## 6. Admin browser routes

Every `/admin` route requires the effective `SystemAdministrator` guard returned for the current session by `GET /api/v1/me`; a durable grant with an exact-organization key/session boundary does not satisfy it. The sidebar preserves five stable groups: Overview, Identity and access, Upstream catalog, Operations, and Audit.

### 6.1 Admin overview

| Browser route | Purpose | Primary API relationship |
| --- | --- | --- |
| `/admin` | deployment overview and actionable warnings | bounded system resource summaries plus authorized `/api/v1/system/operations/**` queries |

There is no `/admin/status` or `/api/v1/system/status` diagnostic bypass. Runtime, readiness, coordination, custody, aggregate-pipeline, and telemetry posture on the overview are loaded only from the matching protected operations queries and therefore require `management:operations`, `management:read`, effective system-administrator authority, and operator-network policy. If that authorization fails, the overview keeps safe non-operational resource summaries and renders an explicit unavailable/forbidden operations panel; it does not reconstruct diagnostics from ordinary APIs.

### 6.2 Users, organizations, and administrators

| Browser route | Purpose | Primary API family/action |
| --- | --- | --- |
| `/admin/users` | users index | `/api/v1/system/users` |
| `/admin/users/new` | direct human/synthetic user creation | users create action |
| `/admin/users/{user_id}` | identity, bindings, memberships, status, admin authority | user detail and related queries |
| `/admin/users/{user_id}/edit` | user metadata/lifecycle editor | user update with ETag |
| `/admin/organizations` | all organizations index | `/api/v1/system/organizations` |
| `/admin/organizations/new` | direct ordinary/synthetic organization creation | organizations create action |
| `/admin/organizations/{organization_id}` | global lifecycle, owners, summary, workspace link | organization detail |
| `/admin/organizations/{organization_id}/edit` | global organization editor | organization update with ETag |
| `/admin/organizations/{organization_id}/catalog-grants` | complete route/endpoint/deployment/reliability grant sets | organization grant singleton APIs |
| `/admin/organizations/{organization_id}/system-provider-budget` | system-provider allocation for this organization | `/api/v1/organizations/{organization_id}/provider-budgets/system` |
| `/admin/management-api-keys` | deployment-owned Management API keys | `/api/v1/system/management-api-keys` |
| `/admin/management-api-keys/new` | create deployment automation key | one-time create action; no user owner |
| `/admin/management-api-keys/{management_api_key_id}` | deployment key detail/grant state | key detail plus administrator grant evidence |
| `/admin/administrators` | built-in seed authority and local-user/deployment-key grants | `/api/v1/system/administrators` |

The administrator page renders `seed_admin` as immutable built-in authority and local-user/deployment-key administrators as typed grant rows. User promotion starts from user detail; deployment automation grant starts from key detail. Key creation and grant are two confirmation/audit steps.

Explicit management actions are:

```text
POST /api/v1/system/administrators/actions/grant
POST /api/v1/system/administrators/{subject_kind}/{subject_id}/actions/revoke
```

Neither command targets `seed_admin`. They are confirmation-required authority transitions, not ordinary resource updates and not HTTP `DELETE`.

### 6.3 Identity and provisioning

Resource-family browser routes use the same list/new/detail/edit shape:

```text
/admin/identity/issuers
/admin/identity/issuers/new
/admin/identity/issuers/{issuer_id}
/admin/identity/issuers/{issuer_id}/edit

/admin/identity/bindings
/admin/identity/bindings/new
/admin/identity/bindings/{binding_id}

/admin/identity/provisioning-policies
/admin/identity/provisioning-policies/new
/admin/identity/provisioning-policies/{policy_id}
/admin/identity/provisioning-policies/{policy_id}/edit
```

They map respectively to:

```text
/api/v1/system/identity-issuers
/api/v1/system/identity-bindings
/api/v1/system/provisioning-policies
```

An issuer editor exposes direct-JWT verification independently from its optional OpenID Connect browser-login profile. Only an active valid profile appears on `/sign-in`; confidential client-secret replacement uses the write-only browser-login action and never the ordinary ETag body.

Binding relink/removal uses explicit confirmation and collision-aware commands. Issuer or binding changes that remove a granted user's login path no longer need a final-local-administrator exception because the seed path remains configured, but their impact is still shown and audited.

### 6.4 System upstream catalog

These routes manage deployment-owned system catalog resources. Organization BYOK remains in the organization workspace and never grants endpoint/network editing.

The common browser route shape is:

```text
/admin/catalog/{family}
/admin/catalog/{family}/new
/admin/catalog/{family}/{resource_id}
/admin/catalog/{family}/{resource_id}/edit
```

Allowed `{family}` values and API families are:

| Browser family | API family | Detail emphasis |
| --- | --- | --- |
| `egress-network-policies` | `/api/v1/system/egress-network-policies` | DNS/address/TLS/redirect/connection/body bounds, reserved null-only proxy field, protected CA state |
| `credentials` | `/api/v1/system/upstream-credentials` | kind, source/custody state, version, validation, dependent deployments |
| `endpoints` | `/api/v1/system/upstream-endpoints` | origin/network policy, adapter, validation, health |
| `deployments` | `/api/v1/system/model-deployments` | endpoint + credential + transport + model, capabilities |
| `model-routes` | `/api/v1/system/model-routes` | model key, targets, policy, grants, stateful behavior |
| `pricing-policies` | `/api/v1/system/pricing-policies` | immutable versions and publication |
| `reliability-policies` | `/api/v1/system/reliability-policies` | retry/failover/circuit behavior |

Gateway policy ceilings are one deployment-wide singleton rather than an ID-qualified catalog collection:

```text
/admin/catalog/gateway-policy-ceilings
/admin/catalog/gateway-policy-ceilings/edit
```

They map to singleton `GET /api/v1/system/gateway-policy-ceilings` and `POST /api/v1/system/gateway-policy-ceilings/actions/update`; no create or resource-ID route exists.

The router registers only the allowlisted family values; arbitrary family strings do not become API paths. Egress policies use the same list/new/detail/edit route shape as the other ordinary catalog collections, and every ordinary update or singleton ceiling update uses the ETag conflict workflow. The UI never displays protected custom-CA bytes.

Additional credential workflow routes are:

```text
/admin/catalog/credentials/{credential_id}/replace-secret
/admin/catalog/credentials/{credential_id}/codex-login/{login_session_id}
```

`replace-secret` is a write-only action page. The Codex page shows safe device-flow state and invokes only the explicit Codex actions from specification 10. The login-session ID is opaque state identity, not a bearer; no OAuth token enters the URL or browser response.

### 6.5 Usage and operations

`/admin/usage` is the bounded global aggregate explorer backed by `GET /api/v1/system/usage` and `/api/v1/system/usage/breakdown`. It separates logical requests from attempts and supports safe organization, route, target origin, deployment, outcome, and time dimensions; it is not an operational status or raw-request log.

Validation, source reload, pricing publication, and other explicit catalog actions remain controls on the applicable detail page rather than creating extra browser routes. Their checked operation descriptors still govern idempotency, approval, and audit.

| Browser route | Purpose | Primary evidence |
| --- | --- | --- |
| `/admin/operations` | capability-scoped operations overview and detailed system status | `GET /api/v1/system/operations` |
| `/admin/operations/readiness` | process and dependency readiness | `GET /api/v1/system/operations/readiness` |
| `/admin/operations/runtime` | runtime revision, age, publication, journal lag | `GET /api/v1/system/operations/runtime` |
| `/admin/operations/coordination` | Redis topology/health, active generations, grants, recovery exposure | `GET /api/v1/system/operations/coordination` |
| `/admin/operations/coordination/recoveries` | durable recovery incidents and epoch caps | `GET /api/v1/system/operations/coordination/recoveries` and typed recovery actions |
| `/admin/operations/coordination/activations` | staged/armed/active/finalized generations and deadlines | `GET /api/v1/system/operations/coordination/activations` |
| `/admin/operations/state-origins` | bounded origin-binding status and cleanup | `GET /api/v1/system/operations/state-origins` |
| `/admin/operations/upstream-credentials` | refresh/login/controller due work and fenced errors | `GET /api/v1/system/operations/upstream-credentials` |
| `/admin/operations/target-health` | local/shared target health and probes | `GET /api/v1/system/operations/target-health` |
| `/admin/operations/secret-custody` | bundled/custom provider and protected-format readiness | `GET /api/v1/system/operations/secret-custody` |
| `/admin/operations/usage-pipeline` | aggregate queue, flush, rollup, loss | `GET /api/v1/system/operations/usage-pipeline` |
| `/admin/operations/telemetry` | OTLP exporter, queue, drops, collector state | `GET /api/v1/system/operations/telemetry` |
| `/admin/audit` | deployment-wide audit search | `GET /api/v1/system/audit` |

All protected diagnostics require `management:operations` plus `management:read`; recovery/mutation controls additionally require `management:write`. The same requests require effective system-administrator authorization and operator-network policy. Diagnostic `GET`s create no durable per-request audit row, while accepted recovery/mutation commands do. The console must render a clear scope or network-policy denial rather than encouraging the user to weaken protection.

## 7. Navigation behavior

### 7.1 Context switching

- Organization selector entries come from `GET /api/v1/me/organizations` for ordinary local-user memberships. An organization Management-key session is fixed to its bound organization and has no cross-tenant selector.
- Seed, granted local-user, and granted deployment-key system administrators receive a separate `Search all organizations` entry that opens `/admin/organizations`; arbitrary ID entry is not the primary UX.
- Opening an organization from Admin goes to `/organizations/{organization_id}` and preserves a visible `System administrator access` banner.
- Returning to Admin preserves only safe list filters and the prior admin route.
- A removed membership invalidates a local-user workspace on the next query and redirects to `/organizations` after a safe access-change message. It does not revoke resource-owned organization keys created by that user.

### 7.2 Deep links

After authentication, a valid internal `return_to` deep link is reloaded from the server and reauthorized. The console never assumes access from pre-login route visibility. A stale or unauthorized deep link lands on a safe forbidden/not-found page without revealing another tenant's resource.

### 7.3 Unsaved changes

Navigating away from an editor with local changes requires confirmation. The warning does not claim that state is reserved or locked. A session expiry or `401` preserves only non-secret form values in memory long enough to sign in and deliberately restart; secret inputs and one-time result values are discarded.

## 8. Primary workflows

### 8.1 Sign in with a management API key

1. Operator opens `/sign-in` and chooses `Use a management API key`.
2. The form explains that the credential is scoped to management operations and is not an LLM gateway key. A seed-administrator key is additionally labeled as full deployment authority.
3. The browser submits the value once to `POST /auth/v1/management-api-key/session/actions/create` over TLS.
4. The server validates its management-only prefix and verifier, then creates an opaque session bound to the exact seed/deployment/organization key principal, key ID/version, resource scope, and scope/capability ceiling.
5. For `seed_admin`, the session binds the current deterministic `seed_admin_key_version_id`; for a durable key, every request reevaluates current key state, destination key policy, and any deployment administrator grant without consulting creator state.
6. The frontend clears the input and redirects using the principal's fixed context rule.
7. `GET /api/v1/me` confirms principal kind, safe key resource identity, authentication origin, and effective scope/grant metadata.
8. Every later command passes normal key-ceiling/resource-policy authorization and is audited as the key principal with `management_api_key_session` authentication.

Failure returns the ordinary non-enumerating authentication error. The UI clears the value and does not preserve it for retry. Direct API, CLI, and MCP clients use `Authorization: Bearer <management-api-key>` without this browser workflow.

### 8.2 Create a scoped Management API key for CLI or MCP

1. For organization automation, an owner/admin opens `/organizations/{organization_id}/management-api-keys`; a member sees create only when organization API-key policy permits. A same-organization Management-key session with exact creation capability/dominance or a system administrator in explicit organization context may open the same organization path without fabricated membership. For deployment automation, a system administrator opens `/admin/management-api-keys`.
2. Resource scope comes from the route and cannot be changed in the body. The form selects concrete management scopes/capabilities, expiry, and name, and shows current destination policy ceilings. It never selects a user owner.
3. Creating standing automation authority requires an explicit high-impact confirmation. Organization keys can never request system/operations capability; a deployment key receives no system-administrator authority until a separate grant command succeeds.
4. The console invokes the non-idempotent create command once, records the actual creator only as audit metadata, persists `issuance_policy_class=member_self_service` only for the member path and `standard` for all other paths, and enters an in-memory one-time reveal state.
5. Setup guidance shows how to place the key in `OWLRORA_MANAGEMENT_API_KEY` or a protected client profile without a shell argument.
6. The operator configures `owlrora` CLI or `owlrora mcp`; those clients authenticate as the key resource principal and receive no console/session bypass.
7. Leaving clears the raw value permanently. An ambiguous result follows metadata/disable/reissue and is never retried automatically. Creator disablement or membership removal does not revoke the organization/deployment resource.

The configured `seed_admin` key is not created, listed, rotated, or recovered here. A Management API key can never be converted into a Gateway API key, change resource scope, impersonate its creator, or broaden itself.

### 8.3 Grant system-administrator authority

1. For a person, a user signs in through a configured issuer/onboarding flow or an administrator directly creates/binds it. For automation, the deployment Management key is created first without implicit authority.
2. `seed_admin` or a granted administrator opens the user detail or deployment-key detail.
3. The page confirms active subject state and displays authentication/key scope evidence without exposing tokens.
4. `Grant system administrator` shows the fixed deployment-wide capability set, typed target identity, and—for a key—the scopes that will continue to narrow the grant.
5. On confirmation the console calls `POST /api/v1/system/administrators/actions/grant`.
6. The server validates current state, commits the grant and audit, and publishes the authority change.
7. The user/key detail and `/admin/administrators` show pending/applied propagation state where relevant.
8. The granted user or deployment-key principal receives effective Admin access only after the new runtime generation is active and its own authentication/scopes remain valid.

Granting an already active grant is an explicit idempotent/domain response, not a duplicate hidden row. JWT claims, creator identity, issuer groups, email, and organization owner role never trigger this workflow automatically.

### 8.4 Revoke a system administrator

1. Administrator starts revoke from a local-user/deployment-key detail or `/admin/administrators`.
2. Confirmation shows the typed subject losing deployment-wide authority; a user retains memberships and a key remains active but ungranted.
3. The console calls `POST /api/v1/system/administrators/{subject_kind}/{subject_id}/actions/revoke`.
4. Current state and audit commit transactionally; security-tightening publication applies.
5. Existing requests/sessions lose administrator capability under the bounded propagation rule.

Revoking the last durable user/key grant is permitted because the `seed_admin` management key remains the configured management path. The built-in seed row has no revoke control.

### 8.5 Create an organization and open its workspace

1. System administrator opens `/admin/organizations/new`.
2. Form creates an ordinary/synthetic organization and requires an eligible active local user as initial owner for an active organization.
3. `seed_admin` itself is never offered as owner.
4. After create, the console opens `/admin/organizations/{organization_id}`.
5. `Open organization workspace` navigates to `/organizations/{organization_id}` with explicit system-access labeling.
6. Tenant resources are then managed through organization-qualified APIs.

### 8.6 Compose and publish an upstream route

For the system catalog, a system administrator independently creates a system credential, endpoint, deployment, and route, then grants safe resources to organizations.

For organization BYOK:

1. An authorized organization actor creates an organization credential with a write-only encrypted secret; the adapter must be organization-self-service-safe.
2. The actor selects a read-only system endpoint granted to the organization; there is no organization endpoint URL/network editor.
3. The actor creates a same-organization deployment binding that credential, endpoint, adapter-approved transport, upstream model, and compatible pricing/unpriced state.
4. Validation checks credential/endpoint/transport/model without exposing provider errors or secret material.
5. Route create explicitly selects one eligible active member as `owner_user_id`, including when the actor is a Management-key/system-administrator principal; no creator is fabricated as owner. The actor then creates/edits the route using same-organization deployments and/or granted system deployments with a complete target set and `If-Match`.
6. Ownership transfer uses the dedicated `.../actions/transfer-ownership` command, current route ETag, and one eligible active-member destination; it is not an ordinary editable field.
7. Publish/activation preserves stable targets, audit, tenant qualification, and fail-closed grant behavior.

The UI keeps credential, endpoint, deployment, and route distinct; it never introduces a provider connection or calls a route key an alias. Creator departure does not disable organization BYOK resources.

### 8.7 Create or rotate a gateway API key

1. An organization owner/admin opens the Gateway API key page; a member may see create only when API-key policy permits. A same-organization Management-key session with exact creation capability/dominance or a qualifying system administrator may use the same explicit organization page without fabricated membership.
2. Create form requires scopes, a non-empty stable route-ID allowlist, a finite overall key budget with `enforce | record_only`, expiry, and optional key-only rate/concurrency limits within current organization/deployment ceilings. Organization binding comes from the path and no user owner or provider allowlist is selected.
3. The console invokes the non-idempotent create command exactly once and records immutable `issuance_policy_class=member_self_service` only for the member path; owner/admin/key/system paths use `standard`.
4. Success enters an in-memory one-time reveal state; raw key is never added to URL/history or persisted storage.
5. User copies the value and acknowledges that it cannot be recovered.
6. Leaving clears the value permanently.

Rotation follows the same reveal behavior and explains overlap. After an ambiguous response, the UI queries metadata, offers disable of potentially undisclosed material, and requires a deliberate new rotation; it never automatically retries.

The key belongs to the organization and authenticates as its own Gateway-key principal. `created_by_principal` records the actual human/key/system actor but never supplies runtime user identity or authority. A system administrator may create it through explicit organization context without membership or a proxy owner.

### 8.8 Complete Codex device login

1. System administrator opens a credential whose kind is `oauth_openai_codex`.
2. Start action returns safe verification URL, user code, expiry, and polling interval.
3. The console opens the bounded login-session route and polls only at the server-directed cadence.
4. It displays pending, slow-down, complete, expired, cancelled, denied, refresh-unknown, or reauthentication-required state.
5. Completion returns credential status only; access/refresh/ID/device bearers remain server-side protected material.
6. The resulting credential is usable only by the Responses community adapter.

The console labels this integration community-maintained/best-effort and does not expose a compatibility-profile selector or support matrix.

### 8.9 Resolve an ETag conflict

1. Editor loads a detail representation and retains its opaque `ETag`.
2. Save sends the tri-state aggregate to `POST .../{id}/actions/update` with `If-Match`.
3. `412` stops the save and opens a conflict view.
4. The console obtains the latest representation and ETag.
5. It shows safe current values beside the unsaved candidate and names changed fields where the server can do so safely.
6. User reloads, deliberately reapplies desired changes, and saves against the new ETag.

There is no automatic replay, field-classified concurrency mode, client-supplied revision, or merge patch.

### 8.10 Inspect Redis state-loss recovery

1. Admin Operations reports an actual/uncertain coordinator state loss and new fenced generation.
2. `/admin/operations/coordination/recoveries` shows incident ID, epoch, authorized allowance, cumulative epoch recovery allowance, cap, uncertainty, and calculated `R_epoch + I × U` exposure.
3. Gateway-key and provider-budget pages show key overall, system-provider, and BYOK policy impact separately and never present aggregate evidence as exact or merged balance.
4. Automatic recovery exposes no more than the durably recorded policy allowance.
5. If the policy cap is zero or exhausted, admission denies; an administrator may deliberately change policy or begin a new epoch through existing audited commands.

The UI does not offer an ad hoc `restore apparent balance` action.

## 9. Uniform update workflow

For every browser `.../edit` page backed by an ordinary resource update:

1. load detail and strong `ETag`;
2. initialize a typed form from the representation;
3. preserve omitted versus explicit `null` versus replacement intent;
4. validate locally for usability, then rely on server aggregate validation;
5. submit `POST .../{id}/actions/update` with `If-Match`;
6. on success, replace local state/ETag from the response and show audit/publication status;
7. on `422`, map bounded field/domain errors;
8. on `412`, enter the conflict workflow;
9. on `428`, report a console defect/expired state and reload;
10. on `401`/`403`/concealed `404`, discard secret fields and follow safe access handling.

Create and distinct action pages do not inherit `If-Match` unless their own contract explicitly requires it.

## 10. Route-registration tests

Automated tests must prove:

- every documented browser route is registered once and builds under the embedded base path;
- reserved route words such as `new` and `edit` do not parse as resource IDs;
- every Admin route has the `SystemAdministrator` guard;
- every organization route loads through explicit `{organization_id}` qualification;
- seed sessions redirect to `/admin`, cannot reach LLM/key-owner workflows, and render no fake user;
- ordinary users cannot discover Admin routes through navigation and direct access still fails server authorization;
- route-to-API mappings do not use application `PUT`, `PATCH`, or `DELETE`;
- all ordinary editors send `If-Match` and handle `412`/`428`;
- one-time secret, seed key, and Codex token values never enter URL/history/storage/telemetry;
- responsive navigation retains context and actor/access-reason labels;
- frontend route inventory and implemented capability registration cannot drift silently.
