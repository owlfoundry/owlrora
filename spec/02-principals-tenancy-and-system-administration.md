# Principals, tenancy, and system administration

## 1. Identity principles

1. OwlRora has one typed principal model covering users and resource-owned API-key automation principals.
2. The built-in `seed_admin` user authenticates only through its deployment-supplied management API key; local users authenticate through browser sessions or trusted JWTs, while durable Management and Gateway API keys authenticate as their own deployment/organization resource principals.
3. Management API keys and gateway API keys are distinct credential classes for distinct HTTP surfaces; neither is accepted in place of the other and neither is user-owned.
4. Every authentication method converges on the same authorizer; authentication proves the exact user or key principal acting and policy decides what that principal may do.
5. Organization authority for a local-user/JWT principal comes from active membership; organization API-key authority comes from immutable resource scope, stored scopes/capabilities, and current organization API-key policy.
6. Deployment-wide authority comes from the built-in seed administrator, an explicit `SystemAdministratorGrant` on an active local user, or a deployment-owned Management API key within current deployment key policy.
7. OwlAuth is one optional external identity adapter and has no privileged domain status.
8. Synthetic users and organizations use normal lifecycle and authorization rules.
9. Tenant access is organization-qualified in API paths, application services, repositories, and runtime snapshots.

## 2. Local users

A `User` is OwlRora’s stable identity for human or externally authenticated service attribution. API keys are separate resource principals rather than user credentials.

| Field | Meaning |
| --- | --- |
| `id` | opaque immutable identifier |
| `kind` | `human` or `synthetic` |
| `status` | `active` or `disabled` |
| `display_name` | local presentation value |
| `primary_email` | optional metadata, never an authorization key |
| `created_by` | seed administrator, local administrator, or provisioning-policy attribution |
| timestamps | creation and update |

Equal email addresses never merge users. A synthetic user may own a route or represent an externally authenticated service identity and may later receive an external identity binding through an explicit command; it is not required merely to hold an API key.

Disabling a user prevents new browser/JWT admission through that user after bounded configuration propagation. It does not disable organization/deployment API keys the user previously created because `created_by_principal` is historical audit attribution, not ownership or delegated authority.

## 3. Trusted JWT issuers

An `ExternalIdentityIssuer` defines one JWT verification and principal-mapping boundary.

| Field | Meaning |
| --- | --- |
| `id`, `name` | stable local identity and administrative label |
| `issuer` | exact accepted `iss` value |
| `jwks_source` | HTTPS JWKS URI or administratively supplied verification keys |
| `verifier_material_version_id` | current immutable validated public-key-set version |
| `allowed_algorithms` | explicit asymmetric algorithm allowlist |
| `accepted_audiences` | non-empty exact audience set for OwlRora |
| `subject_claim` | stable subject claim, normally `sub` |
| `claim_mapping` | optional typed management-scope/capability, LLM-scope/capability, route/organization narrowing, and presentation metadata mapping |
| `jwt_capability_ceiling` | closed coarse access classes `management:access` and `llm:access`; it never expands either typed ceiling |
| `management_scope_ceiling` | explicit subset of the five recognized management scopes; non-empty and required when `management:access` is enabled, otherwise empty |
| `management_capability_ceiling` | explicit closed typed management capability set; non-empty and required with management access |
| `management_organization_ceiling` | `all_authorized` or non-empty exact organization IDs; required with management access and optionally narrowed by a mapped signed claim |
| `llm_scope_ceiling` | explicit closed request-scope set containing `llm:invoke` when `llm:access` is enabled; empty means deny |
| `llm_capability_ceiling` | explicit closed protocol/model feature ceiling, independent of request scopes |
| `capability_claim_policy` | ignore, optional narrowing, or required narrowing through explicitly mapped typed claims |
| `jwt_route_ceiling` | `all_organization_granted` or an explicit route-ID set |
| `organization_selector` | signed claim, bounded OwlRora header, or either |
| `provisioning_policy_id` | optional local provisioning command policy |
| `browser_login` | optional bounded OpenID Connect authorization-code profile |
| `clock_skew`, `key_cache_policy` | bounded verification configuration |
| `status` | `active` or `disabled` |

There is no separate control-plane issuer and workload issuer model. One verified JWT establishes one local principal. The requested operation then passes through the same authorizer used by sessions and API keys.

Audience validation still prevents accepting tokens minted for unrelated services: at least one exact configured audience must be present. A deployment may configure multiple accepted OwlRora audiences, but audience alone does not grant an operation. The issuer capability ceiling contains only the coarse access classes `management:access` and `llm:access`. Management access separately requires explicit management scope, typed capability, and organization ceilings; LLM access separately requires a non-empty closed LLM scope ceiling plus explicit feature/route/organization-selector policy. Neither coarse class expands a typed set. Optional mapped token capabilities/scopes/routes/organizations can only narrow the corresponding issuer ceiling, never widen it. Claim absence follows the issuer’s explicit capability-claim policy. An active issuer configuration with an incomplete access-class contract is rejected rather than defaulted.

JWT algorithm selection is checked against the issuer configuration rather than trusted from the token header. Symmetric bearer-token algorithms are not supported.

### 3.1 External identity bindings

An `ExternalIdentityBinding` maps one unique `(issuer_id, external_subject)` pair to one local `user_id`.

- One user may have bindings from multiple issuers.
- Email equality never creates or changes a binding.
- Create, relink, and removal are explicit audited commands or outputs of an enabled provisioning policy.
- Relinking rejects collisions, validates the target user and issuer, and is audited transactionally. No final-local-administrator-path exception exists because the deployment seed-administrator management key remains independent of bindings.

### 3.2 Verification flow

Direct JWT authentication validates:

1. bounded token syntax and configured algorithm;
2. signature against a currently valid issuer key;
3. exact issuer and at least one accepted audience;
4. expiry and not-before with bounded clock skew;
5. non-empty stable subject;
6. issuer status;
7. an existing local binding;
8. local user status.

An unknown subject never provisions durable state on an LLM or ordinary direct-API request. Policy-driven provisioning runs only at the bounded onboarding boundary described below; the original request retries only after the binding is committed and published.

Unknown signing-key IDs trigger one rate-limited asynchronous JWKS refresh and fail the current data-plane request. No data-plane request waits on identity-provider network I/O. A still-valid cached key may be used according to issuer policy.

A refresh validates the complete bounded key set outside a database transaction, then transactionally stores a new immutable `IssuerVerifierMaterialVersion`, advances the issuer's current verifier-material pointer, and writes the normal configuration journal/outbox record. Key removal therefore publishes a new version rather than mutating an in-memory cache. Every node converges through the ordinary runtime-generation path; an external JWKS change does not wait for an unrelated administrator command.

A successful-signature memoization entry binds token digest, issuer ID, allowed algorithm, issuer-policy version, and verifier-material version. It expires at the earliest of token expiry, key/material acceptance expiry, policy cache bound, or revocation boundary. It cannot survive issuer disablement, policy change, key removal, or verifier-material replacement.

### 3.3 Optional browser login

Direct JWT verification does not by itself make an issuer a browser-login provider. An issuer appears on `/sign-in` only when its optional `browser_login` profile is active and valid.

```text
BrowserLoginProfile {
    authorization_endpoint,
    token_endpoint,
    client_id,
    client_auth: public | protected_client_secret_source,
    scopes,
    pkce_method: S256,
    status,
}
```

Endpoints are explicit validated HTTPS values or resolved from validated OpenID Connect discovery. The redirect URI is derived from one configured public OwlRora origin plus the fixed issuer callback path; callers cannot supply it. Scopes include `openid`; PKCE S256, state, and nonce are mandatory. A confidential-client secret uses the normal recoverable-secret source/custody boundary and one-time replacement semantics.

The server performs authorization-code exchange under bounded identity egress policy, validates the returned ID token through the same issuer/verifier-material contract, resolves or provisions the local binding only at the explicit onboarding boundary, and creates an opaque local session. That session captures the issuer ID, concrete effective management scope set, and safe typed effective login capability/organization ceiling produced by intersecting the issuer's explicit scope/organization ceilings with configured claim narrowing at exchange. Every request intersects those captured ceilings with current issuer status/policy and current local-user authority: later scope/capability narrowing or issuer disablement applies, while later expansion requires a new login and cannot widen the existing session. Authorization codes, arbitrary claim documents, and identity-provider access/refresh/ID tokens are never exposed to frontend JavaScript or retained after the bounded exchange unless a separately specified identity adapter requires protected refresh state. OwlAuth is one adapter that may supply this profile; an arbitrary direct-JWT issuer without it remains API-only.

## 4. Principal convergence

Successful authentication produces:

```text
AuthenticatedPrincipal {
    principal:
        seed_admin | local_user(local_user_id) |
        deployment_management_api_key(management_api_key_id) |
        organization_management_api_key(organization_id, management_api_key_id) |
        organization_gateway_api_key(organization_id, gateway_api_key_id),
    authentication_method:
        management_api_key | management_api_key_session |
        external_session | external_jwt | gateway_api_key,
    external_issuer_id?,
    external_subject?,
    session_id?,
    credential_resource_scope?,
    credential_capability_ceiling?,
    effective_management_scopes?,
    management_organization_ceiling?,
    organization_allowlist?,
    external_session_login_ceiling?,
    jwt_claimed_capabilities?,
}
```

`seed_admin` is a built-in API-key-only user in the principal model. It is not a nullable local-user reference, a synthetic tenant user, or a mutable PostgreSQL `users` row. Every `local_user(...)` principal resolves one active durable local user. Durable management/gateway keys resolve their own resource principal and never impersonate or inherit current authority from `created_by_principal`. A management-key-derived browser session preserves the exact key principal, key ID/version, scopes, capabilities, and resource scope; exchanging a narrowed key for a session never expands it. A direct JWT derives concrete effective management scopes from the issuer ceiling and typed claim narrowing on every request. An external session preserves its issuer ID, captured concrete management scopes, and captured typed login ceiling and never substitutes the user's unconstrained current authority.

Organization context is resolved separately:

- system and cross-organization management paths authorize `seed_admin`, a granted local system administrator, or a qualifying deployment Management API key explicitly;
- organization management paths name the organization in the URL and organization Management keys must match it;
- Gateway API key authentication obtains it from the key resource binding;
- direct JWT LLM requests use the configured signed claim or bounded `x-owlrora-organization-id` header;
- a claim or header selects an existing membership and never creates one.

When both an allowed claim and header are present, they must match. `seed_admin` has no LLM or organization-member identity and is rejected on LLM compatibility paths.

## 5. Provisioning modes

### 5.1 Map existing

Map-existing is the default. An unknown `(issuer, subject)` fails without revealing whether a similar user exists. A system administrator or embedding platform provisions the user and binding first.

### 5.2 Policy-driven onboarding provisioning

An issuer may reference a `ProvisioningPolicy` that defines:

- whether a user may be created;
- accepted claim predicates;
- local user kind and metadata mapping;
- whether a personal organization may be created;
- which preconfigured organization mappings and maximum roles are allowed;
- an idempotency identity derived from issuer and subject.

The policy runs only during an explicit browser-login exchange or a dedicated, rate-limited onboarding command. It executes ordinary OwlRora commands transactionally and cannot grant system-administrator authority. Token-provided organization IDs, slugs, groups, and roles are untrusted inputs to the configured mapping.

The onboarding operation succeeds only after the new binding and authority are visible in an eligible runtime generation. An unknown subject on an LLM compatibility path or ordinary direct management path is denied and does not trigger provisioning work, preventing data-plane database writes and subject-flood amplification.

### 5.3 Direct provisioning

System administrators can directly create human or synthetic users, ordinary or synthetic organizations, memberships, and external bindings. Directly provisioned users do not require an external identity until they need user-authenticated access; API keys are managed deployment/organization resources rather than user login methods.

OwlRora does not implement password authentication. A human using the console authenticates through a configured external issuer; an embedding platform may manage local entities entirely through APIs.

## 6. System administrators

### 6.1 Built-in seed administrator

Every management-enabled deployment has one built-in API-key-only user with the stable identity `seed_admin`. Its `ManagementApiKey` is supplied through deployment configuration, uses the normal management-key wire format and authentication adapter, and carries the complete fixed management scope set. The user and key are represented in the principal model but are not mutable PostgreSQL `users` or `management_api_keys` rows and do not use `SystemAdministratorGrant`.

`seed_admin` has the fixed deployment-wide system-administrator capability set. It may administer system resources and any explicitly named organization, create users and organizations, and grant or revoke ordinary system-administrator authority. It cannot:

- authenticate on LLM compatibility paths;
- authenticate through JWT, external browser login, password, or gateway API key;
- hold a membership or organization role;
- be treated as the owner of durable Management/Gateway API keys or other organization resources;
- be renamed, disabled, deleted, or have its authority/scopes changed through PostgreSQL state.

The browser may exchange the seed management key once for an opaque key-derived session; this is a transport convenience and not another identity credential. Changing or removing seed access is an operator deployment-secret action, not an application command. Every action is attributed to `seed_admin`, the management-key ID, and the concrete direct-key or key-session authentication method in audit.

### 6.2 Administrator grants

A `SystemAdministratorGrant` assigns the same deployment-wide capability set to one active local user or one active deployment-owned Management API key. `seed_admin` or an already authorized system administrator may grant authority only to an existing eligible subject. A grant never derives from management-key scopes, JWT claims, issuer groups, email equality, organization roles, or `created_by_principal`. For a deployment key, effective authority remains the intersection of the grant, stored management scopes/capability ceiling, and current deployment key policy; key creation and administrator grant are separate audited commands.

An active granted user still needs a usable external identity binding and issuer to authenticate. Disabling that user immediately removes its effective system authority after bounded propagation. A granted deployment key authenticates as its own principal; disabling/expiring/narrowing the key or revoking its grant removes effective authority without consulting its creator.

OwlRora permits zero durable administrator grants because the configured `seed_admin` management key remains the administrative path. Revoking the last local-user/key grant, disabling its subject, or removing a user login binding therefore does not require a special final-administrator exception. Database state cannot remove seed access. Host/database break-glass recovery remains operationally explicit and high-severity audited.

System-administrator authority is independent of organization roles. All user/key system-administrator principals act through the same typed capabilities and must name a target organization for cross-tenant operations.

## 7. Organizations and memberships

An `Organization` is the tenant boundary.

| Field | Meaning |
| --- | --- |
| `id` | opaque immutable identifier |
| `name` | mutable presentation value |
| `slug` | optional lookup/display value, never authority |
| `kind` | `ordinary` or `synthetic` |
| `status` | `active` or `suspended` |
| `created_by_principal` | stable authenticated seed/user/deployment-key/organization-key actor attribution; never ownership |
| timestamps | creation and update |

There is no implicit system organization. Suspension rejects new LLM admission and ordinary tenant commands while preserving members, resources, usage, and audit history.

A `Membership` joins one user to one organization:

| Role | Tenant authority |
| --- | --- |
| `owner` | all organization actions within system ceilings, including owner management |
| `admin` | delegated member, key, route, budget, and policy administration |
| `member` | permitted invocation and configured self-service operations |

A membership has active/removed lifecycle and an LLM scope ceiling. At most one active membership exists per `(organization_id, user_id)`. Every active organization retains at least one active owner; concurrent final-owner removal or demotion is rejected.

A removed membership invalidates that user's tenant access and disables admission through an organization route when that user is its current explicit route owner. It does not revoke organization-owned Management/Gateway keys or BYOK credentials/deployments created by that user. Re-adding membership does not silently reactivate a disabled route.

## 8. Invitations and sessions

An invitation is onboarding state rather than authority. It contains organization, intended role, expiry, state, and a hashed one-time token. Acceptance requires an authenticated local user and atomically creates membership under owner invariants. Email metadata alone never proves identity.

The web console uses an opaque server-managed session after external login or an explicit management API key exchange:

- `HttpOnly`, `Secure`, `SameSite=Lax` cookie;
- exact `seed_admin`, local-user, deployment-key, or organization-key principal binding plus authentication origin;
- bounded lifetime and revocation;
- a key-derived session binds the Management API key resource scope, ID, and current secret version, retains its scope/capability ceiling, and becomes invalid when the key is disabled, expires, rotates beyond overlap, or current deployment/organization key policy rejects it;
- the seed-administrator session stores only its deterministic `seed_admin_key_version_id` and becomes invalid when the configured key changes;
- an OIDC-derived session stores issuer ID, captured concrete management scopes, and its safe typed login capability/organization ceiling; current issuer/user narrowing applies and expansion requires re-login;
- OIDC/OAuth state and nonce where applicable;
- no external identity token, arbitrary external claim document, or management API key is persisted in frontend storage or exposed after exchange;
- organization selection is UI state and is reauthorized on each request.

A trusted JWT or management API key may call the same management APIs directly without first creating a browser session. Management keys are never accepted by invitation, onboarding, gateway-key, or LLM authentication.

## 9. Tenant qualification

Every organization query and command names `organization_id` explicitly. Repository operations include that identifier in predicates and composite constraints where practical. Looking up a resource globally and checking its tenant afterward is not the sole isolation boundary.

Cross-organization actions require system authority and explicit source/destination context. Resource transfer, organization merge, and user merge are not part of the domain model.

## 10. Lifecycle effects

- **User disablement** rejects all new browser/JWT authentication through that user, revokes user sessions, and preserves history; resource-owned API keys created by that user are unaffected.
- **Membership removal** rejects that user's tenant access but does not transfer or disable organization-owned keys, BYOK credentials, deployments, or other organization resources.
- **Organization suspension** rejects organization Management/Gateway key admission and all new organization LLM admission; resumption does not re-enable individually disabled resources.
- **Issuer disablement** rejects new JWT authentication and may revoke derived user sessions under configured urgency; organization Gateway keys remain governed by key and tenant state.

Each lifecycle command writes domain state, audit, configuration journal, and outbox records in one transaction.

## 11. Audit and concurrency

Commands use current-state transactions and explicit row-lock ordering for cross-row invariants. Public clients never submit database transaction IDs or row-version columns. Every ordinary resource update requires the same opaque HTTP representation precondition defined in spec 10; it detects a stale editor without exposing persistence internals or classifying fields separately.

Every system-administrator command and security-sensitive tenant command records:

- actor principal kind and stable ID (`seed_admin`, local user, deployment Management key, or organization Management key);
- authentication method, session, key resource scope, and issuer where applicable;
- organization and target resource;
- operation and outcome;
- request ID and safe changed-field names;
- timestamp.

Audit records never contain raw JWTs, API keys, provider secrets, prompts, or responses.
