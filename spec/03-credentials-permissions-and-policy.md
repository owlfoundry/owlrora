# Credentials, permissions, and policy

## 1. One authorization pipeline

OwlRora separates authentication evidence from authorization policy.

```text
Management API key/session | external session | trusted JWT | gateway API key
                                      ↓
       seed_admin | local user | deployment key | organization key principal
                                      ↓
                         credential capability ceiling
                                      ↓
                      one typed OwlRora authorizer
                             ↙                 ↘
      system authority and key policy      organization, membership or key policy
                                                   ↓
                                      management or LLM decision
```

The same authorizer evaluates browser, direct API, CLI, MCP, embedded-platform, and LLM calls. Management API key and JWT authentication do not branch into parallel authorization systems.

Credential type still matters:

- durable management API keys are deployment-owned or organization-owned automation resources, never user-owned credentials; sessions derived from them retain the key principal, scope, and resource ceiling;
- the deployment-supplied seed-administrator key is one fixed full-scope management API key for the built-in `seed_admin` user;
- external-login sessions are browser-oriented and carry no provider or LLM privilege by themselves;
- trusted JWTs may call operations allowed by issuer ceilings, token claims, and current local authority;
- gateway API keys are organization-owned LLM credentials, not user credentials, and are limited to LLM capabilities inside their organization;
- management and gateway keys use disjoint wire prefixes, lookup indexes, scope vocabularies, endpoints, and audit fields;
- only gateway-key requests create quota-bearing LLM admission: every such key has a route allowlist and overall budget, and each actual attempt also consumes its target-derived organization origin pool.

## 2. Management roles and capabilities

Organization roles map to typed internal capabilities:

| Capability | Owner | Admin | Member |
| --- | :---: | :---: | :---: |
| read organization profile | yes | yes | yes |
| read organization-wide usage/key metadata | yes | yes | configurable |
| create Gateway API keys within organization policy | yes | yes | configurable |
| create Management API keys within organization policy | yes | yes | configurable |
| manage all organization API keys | yes | yes | no |
| manage organization BYOK credentials/deployments | yes | yes | configurable |
| administer non-owner memberships | yes | yes | no |
| add, demote, or remove owners | yes, preserving final owner | no | no |
| configure organization routes within grants | yes | yes | configurable |
| configure budgets and limits within ceilings | yes | configurable | no |

The role table applies to local-user membership principals. A same-organization Management-key principal may perform organization actions only when its stored scopes/capability ceiling, immutable organization scope, current key policy, and target-dominance rules grant the exact typed capability; it receives no fabricated role or membership. A qualifying system administrator may act through an explicit organization path under system authority. System-administrator capabilities are evaluated separately and are always audited. The built-in `seed_admin` user plus an active local user or deployment Management-key principal with `SystemAdministratorGrant` receive the same typed deployment-wide capability set; their authentication and actor attribution differ. A deployment key's stored scopes/capability ceiling and current deployment key policy narrow that grant, and it never borrows creator authority. HTTP handlers ask the application authorizer for a typed capability rather than branching directly on role names.

The seed-administrator path is deliberately narrow:

- its configured management key has the complete fixed management scope set but grants no LLM scope and is rejected before LLM admission;
- it requires no issuer, external binding, membership, or organization role;
- it can perform tenant operations only through explicit system-administrator capabilities against an organization-qualified path;
- it never creates tenant-user, gateway-key, or LLM usage attribution for its own actions;
- its user authority and key scopes cannot be widened or narrowed by a database role, JWT claim, or request header.

## 3. Management scope vocabulary

The version-1 recognized management scope set is exactly:

- `management:read` — side-effect-free management and audit queries;
- `management:write` — resource creation, ordinary updates, and lifecycle commands that do not require a stronger scope;
- `management:secrets` — additional permission for commands accepting protected secret material or returning a new one-time bearer;
- `management:operations` — additional permission for protected diagnostics and operational recovery commands under `/api/v1/system/operations/**`;
- `management:authority` — additional permission for administrator grants and other explicitly classified authority transitions.

Every authenticated management request resolves a concrete effective subset of this same vocabulary. A durable management API key stores its explicit non-empty set. A key-derived session captures that set and intersects it with current key state. A direct JWT derives it from the issuer's explicit `management_scope_ceiling` intersected with any configured typed claim narrowing on every request; its resource ceiling likewise comes from the explicit `management_organization_ceiling` and any narrower mapped organization claim. An OIDC-derived session captures that derived set at login and later intersects it with the current issuer ceiling. The seed-administrator key has the complete fixed set. Coarse `management:access`, user role, or system-administrator authority never implies any management scope. If authentication evidence has no resulting scope set, management access is denied.

Operations may require more than one scope. For example, replacing an upstream secret requires `management:write` and `management:secrets`; granting system administration requires `management:write` and `management:authority`. Unknown scopes and wildcard strings are rejected. A UI may call the complete current set "full management access", but durable credentials and sessions retain concrete versioned scopes rather than an unbounded wildcard.

Every durable management key has exactly one resource scope:

```text
deployment | organization(exactly one organization ID)
```

A deployment key may address system resources and explicitly named organizations within its stored scope/capability ceiling. An organization key denies system resources, cross-organization operations, `management:operations`, and deployment-wide administrator transitions before resource lookup. Resource scope is required and immutable; no `all_authorized` future-expansion marker or multi-organization key exists. Separate organization keys are used when automation spans independently administered tenants.

Effective management permission is principal-specific:

```text
required operation scopes
  ∩ credential/session effective management scopes and resource scope
  ∩ (current local-user authority OR current deployment/organization key policy)
  ∩ current resource state and policy
  = management decision
```

Management scopes never grant a user role or membership. A resource-owned key is itself a typed automation principal, so `created_by_principal` is audit metadata only and never supplies ongoing authority. `seed_admin` remains the sole non-durable configured key: its full concrete scope set and built-in user supply fixed deployment-wide authority.

## 4. Management API keys

A `ManagementApiKey` is a local control-plane credential and is never an LLM credential.

| Field | Meaning |
| --- | --- |
| `id` | opaque credential identity |
| `resource_scope` | immutable `deployment` or one `organization_id` |
| `created_by_principal` | immutable audit attribution; never owner or ongoing authority |
| `issuance_policy_class` | immutable `standard` or `member_self_service`; policy classification, never creator identity |
| `name`, `key_prefix` | non-secret operator metadata |
| `secret_digest_versions` | current and optional bounded-overlap SHA-256 verifier |
| `scopes` | explicit management scope set |
| `capability_ceiling` | typed deployment or organization capability ceiling in addition to scopes |
| `status`, `expires_at` | lifecycle and hard expiry |
| timestamps | creation, rotation, approximate last use, update |

The canonical management-key wire form is:

```text
owlrora_mgmt_v1.<base64url-no-pad-lookup>.<base64url-no-pad-secret>
```

The dot separator is outside the base64url alphabet; parsing requires exactly three canonical no-padding segments. The decoded lookup contains at least 128 bits of CSPRNG entropy and the decoded secret at least 256 bits. Durable management keys use the same high-entropy, one-time reveal, digest-only storage, local verification, rotation-overlap, and no-replay principles defined for gateway keys below, but have a distinct prefix and separate lookup index. The key is supplied as `Authorization: Bearer <management-api-key>` on `/api/v1/**`, including protected `/api/v1/system/operations/**` routes. A syntactically valid management key on an LLM route, or gateway key on a management route, returns a non-enumerating invalid-credential response and never falls through to the other verifier.

Deployment-owned management keys are created and managed only through deployment authority. Organization-owned management keys are organization resources managed through one of four explicit paths: an owner/admin local user, a policy-enabled member for creation only, a same-organization Management-key principal with the required scopes/capability and target dominance, or a qualifying system administrator acting through explicit organization context. An `OrganizationApiKeyPolicy` may allow members to create them under explicit management-scope, capability, active-count, and expiry ceilings. Issuance requires `management:write`, `management:secrets`, and `management:authority` because it creates standing automation authority. Every requested scope/capability MUST be present in the caller credential's effective ceiling and allowed by the destination key policy. An organization key can mint only a same-organization key and can never request `management:operations` or deployment capabilities. Issuance never grants a user role or membership. Creator disablement or membership removal does not disable a resource-owned key; key/policy narrowing, organization suspension, expiry, disablement, or rotation narrows or rejects requests after bounded propagation.

A uniform **target credential dominance** rule applies to every management-key command that increases authority or makes credential authority newly usable. This includes create, scope or capability widening, rotation, re-enable/reactivation, expiry extension, and restoration or extension of a previous-secret overlap. The target key's complete post-command scope/capability set and resource scope MUST be no broader than the calling credential's current effective ceiling, and the caller MUST hold the typed user or key-principal capability required for those target scopes and resources. Rotation is covered even when scopes do not change because it returns a new bearer for the target's existing authority. Re-enable and expiry/overlap extension are covered because they reactivate or prolong that authority. The post-command key must also fit the destination deployment/organization key policy. Therefore, a narrow key cannot rotate, re-enable, extend, or otherwise recover a wider sibling key and cannot widen itself; a different currently dominant credential is required.

Safe one-way restriction remains possible under ordinary deployment/organization key-management rules: a caller may disable a key, narrow its scopes or capability ceiling, shorten its expiry, or end overlap without first dominating the target's wider pre-state. These operations cannot return new bearer material or preserve a capability removed by the submitted restriction. Metadata-only changes remain subject to ordinary ownership/capability rules and cannot alter credential usability.

Management-key create and rotate return raw material once and reject generic idempotent replay. A browser exchange may create an opaque session bound to the exact key ID, accepted secret version, and scope/resource ceiling captured at exchange. Every session request intersects that captured ceiling with current key state and current deployment/organization key policy. Narrowing or disablement applies under security propagation; a later key expansion does not widen an existing session and requires a new exchange. The exchange cannot turn a narrow automation key into a full browser session.

The seed-administrator management key is deployment supplied rather than a durable key row. Its fixed key ID/version and rotation behavior are defined in specification 11. It cannot be listed, created, rotated, disabled, or recovered through management APIs.

## 5. LLM scope vocabulary

The version-1 recognized LLM scope set is exactly:

- `llm:invoke`;
- `llm:stream`;
- `llm:tools`;
- `llm:multimodal-input`;
- `llm:structured-output`.

`llm:invoke` is required for every LLM request. Protocol modules derive any additional required credential scopes only from this closed set. Protocol capability support, route eligibility, provider features, or unknown strings do not invent implicit credential scopes. Unknown scopes are rejected rather than treated as granted; adding a future scope requires an explicit versioned schema/registry change.

A membership carries an `llm_scope_ceiling`, a closed `llm_capability_ceiling`, and a typed `llm_route_ceiling`; invitations capture the same three immutable onboarding inputs. Empty scope/capability sets and `route kind=none` mean explicit deny. Organization and system policy may further narrow them. Role ownership does not bypass these ceilings.

## 6. Gateway API keys

A `GatewayApiKey` is a local LLM credential.

| Field | Meaning |
| --- | --- |
| `id` | opaque credential identity |
| `organization_id` | immutable tenant binding |
| `created_by_principal` | immutable audit attribution; never owner or request actor |
| `issuance_policy_class` | immutable `standard` or `member_self_service`; policy classification, never creator identity |
| `name`, `key_prefix` | non-secret operator metadata |
| `secret_digest_versions` | current and optional bounded-overlap SHA-256 verifier |
| `scopes` | explicit LLM scope set |
| `route_allowlist` | required non-empty set of stable organization-visible route IDs |
| `budget_policy_id` | required overall gateway-key budget policy |
| `rate_policy_id` | optional gateway-key-only rate/concurrency policy |
| `status`, `expires_at` | lifecycle and hard expiry |
| timestamps | creation, rotation, approximate last use, update |

### 6.1 Wire format and verification

The canonical gateway-key wire form is:

```text
owlrora_llm_v1.<base64url-no-pad-lookup>.<base64url-no-pad-secret>
```

The same exact three-segment, dot-separated, canonical no-padding grammar applies. A generated key contains:

- the exact versioned LLM-only OwlRora prefix;
- a non-secret lookup component with at least 128 bits of entropy;
- a cryptographically random secret with at least 256 bits of entropy.

Storage contains only a domain-separated SHA-256 digest over version, lookup component, and secret. Verification performs local lookup followed by constant-time digest comparison. Gateway keys are never encrypted for recovery and never enter the recoverable secret store.

The raw key is returned once in a non-cacheable create or rotate response. It is absent from list/detail APIs, storage, logs, audit, telemetry, and error details.

### 6.2 One-time command semantics

Gateway-key create and rotate do not accept `Idempotency-Key`. If response delivery is ambiguous, clients inspect key metadata, disable any undisclosed key, and create or rotate again. The design never retains plaintext or encrypted replay escrow for gateway API keys.

Concurrent rotations serialize. One previous digest may remain valid until a bounded `overlap_until`; a later rotation invalidates an older overlap. Current and overlap values share one key, policy, and accounting identity.

### 6.3 Runtime verification

Active key metadata, organization policy ceilings, and digest verifiers are part of the immutable runtime snapshot. Normal valid and invalid verification performs no PostgreSQL or Redis request. A bounded negative cache may reduce repeated invalid-key work without delaying newly published keys beyond the propagation objective.

A Gateway API key authenticates as `organization_gateway_api_key(key_id, organization_id)`, not as its creator or any fabricated member. Admission requires an active organization/key, effective scopes within current organization policy, an exact match in the key's required route allowlist, an eligible organization-visible route, and a ready overall key budget. Every actual attempt additionally requires the origin budget derived from its selected deployment: the system-administrator allocation for `system_provided`, or the organization-managed pool for `organization_byok`. Optional rate/concurrency policy is key-scoped. Usage is attributed to organization and Gateway key; `user_id` is absent and never copied from `created_by_principal`.

### 6.4 Organization API-key policy

Each organization has one `OrganizationApiKeyPolicy` governing both key classes:

- global runtime ceilings for every organization key: management/LLM scopes and capabilities, active count, overlap, expiry horizon, permitted routes, key-budget limits/modes, and optional rate/concurrency;
- whether members may create Gateway API keys;
- whether members may create organization Management API keys;
- stricter management/LLM scope, capability, route, budget/rate, active-count, overlap, and expiry ceilings for the immutable `member_self_service` issuance class.

A key created by an owner/admin, same-organization Management-key principal, or qualifying system administrator has `issuance_policy_class=standard`; a member self-service creation has `member_self_service`. The class is authorization metadata fixed by the successful issuance path, not derived later from `created_by_principal`, creator membership, or creator lifecycle. Global policy tightening intersects every existing key. Member-class tightening additionally intersects existing `member_self_service` keys and applies after bounded security propagation; standard keys are unaffected by member-only ceilings. Later expansion never adds scopes, routes, budget, or lifetime to an existing key. Owners/admins, same-organization key principals with exact management capability/dominance, and qualifying system administrators may manage lifecycle under global policy; members never gain sibling-key management merely by creating a key. The singleton policy uses ordinary ETag update semantics and every accepted change is audited.

## 7. Trusted JWT authorization

After issuer verification and local user binding, JWT authorization uses typed ceilings from three sources:

1. **issuer policy** — maximum access classes, explicit management scope ceiling, LLM capabilities, route ceiling, organization-selector mode, accepted audiences, and claim mode;
2. **token claims** — optional or required typed narrowing of management scopes/capabilities/routes under an explicitly configured mapping; claims never add authority beyond the issuer ceiling;
3. **local policy** — active user, membership role/scope ceiling, organization status, visible route grants, and system ceilings.

There is no organization-level JWT-access policy or enable switch. Direct-JWT LLM admission is already the intersection of deployment-trusted issuer configuration, token narrowing, explicit organization selection, active local binding and membership, and organization-visible routes. Adding a second tenant JWT policy would duplicate those controls and create contradictory authorization state.

Management access does not need a second issuer mode. A direct JWT or its derived browser session requires effective `management:access`, every concrete management scope required by the operation, and the relevant current local system or organization capability. The issuer's `management_scope_ceiling` and `management_organization_ceiling` are explicit whenever `management:access` is enabled; neither defaults from that coarse access class. Optional or required mapped scope claims may only narrow it. LLM access requires an issuer explicitly configured with an LLM capability ceiling containing `llm:invoke`, any additional request scopes, explicit organization context, an active local binding and membership, and an eligible organization-visible route. When claim narrowing is ignored or optional and absent, the applicable explicit issuer ceiling applies; when configured as required, an absent or invalid mapped claim denies authentication for the affected access class.

An OIDC-derived local session captures the issuer ID, concrete effective management scope set, and safe typed effective login capability/organization ceiling after issuer policy and login claims are intersected at exchange; it stores no external token or arbitrary claim document. Every later request intersects those captured ceilings with the issuer's current status/policy and the user's current authority. Issuer disablement or later scope/capability narrowing therefore applies after bounded propagation, while a later issuer-policy or user-authority expansion cannot widen the existing session and requires a new login.

A JWT request has no `gateway_api_key_id`. OwlRora records its organization/user/route/attempt usage but applies no Gateway-key allowlist, key budget, organization origin budget, rate policy, or concurrency policy. Node overload and target protection still apply. Deployments requiring quota controls disable direct-JWT LLM access at the trusted issuer and issue Gateway API keys instead.

A JWT claim cannot grant membership, system administration, or a route absent from current local grants. Missing policy, empty capability intersections, and explicit empty route sets deny access.

## 8. Effective LLM permission

A route is usable only when all applicable layers permit it:

```text
system ceilings
  ∩ active organization and route grants
  ∩ principal authority
      - gateway-key scopes and required route allowlist; or
      - active user/membership plus issuer/token JWT ceilings
  ∩ route capability and request policy
  ∩ for Gateway keys only: overall key policy and selected-target origin policy
  = effective LLM permission
```

Absence has typed semantics:

- no required scope means denied;
- no route grant means denied;
- an active Gateway key requires its finite overall budget plus the selected target's active system/BYOK origin budget;
- `record_only` records threshold state but never denies, while absence of a required Gateway-key/origin policy is not unlimited;
- no key rate/concurrency policy means unlimited only at that key layer;
- disabled state always denies;
- no Gateway-key identity means no key/origin quota or key attribution is fabricated.

## 9. Admission context

Protocol modules derive a bounded intent without normalizing request content:

```text
LlmIntent {
    protocol_family,
    requested_model_key,
    streaming,
    required_capabilities,
    requested_output_bound?,
    continuation_reference?,
}
```

Authorization returns an immutable context:

```text
AdmissionContext {
    principal_kind: local_user | organization_gateway_api_key,
    principal_affinity_id,
    user_id?,
    organization_id,
    authentication_method,
    gateway_api_key_id?,
    external_issuer_id?,
    effective_scopes,
    route_id,
    gateway_key_budget_policy_ref?,
    selected_origin_budget_policy_ref?,
    gateway_key_rate_policy_ref?,
    snapshot_version,
}
```

The same context follows every attempt, usage delta, and telemetry signal for the logical request.

## 10. Revocation and configuration propagation

Every mutation affecting authentication, authorization, admission, grants, credentials, or runtime eligibility is classified from typed old/new state. Callers cannot label a change as non-security-sensitive.

Security-tightening changes include:

- seed-administrator key rotation for its key-derived sessions;
- user disablement, organization suspension, membership removal, or role/scope reduction for user/JWT admission;
- management-key or gateway-key disablement, expiry reduction, rotation invalidation, scope/resource narrowing, or organization API-key-policy tightening;
- issuer, external binding, audience, capability, route, or organization-selector narrowing;
- route/deployment/endpoint/credential/target disablement;
- route, deployment, reliability-policy, or pricing grant revocation;
- capability, output, retry, Gateway-key route/budget/rate/concurrency tightening, or organization system/BYOK origin-budget tightening.

Unrecognized changes in these domains default to security tightening. Presentation-only changes and authority expansion use ordinary propagation.

A committed command writes the new state, audit entry, and ordered configuration journal record transactionally. Healthy nodes target five-second propagation for security tightening and thirty seconds for ordinary changes. A node beyond `max_security_snapshot_age` rejects new admission rather than serve indefinitely stale authority.

## 11. Error semantics

| Condition | HTTP status | Stable class |
| --- | ---: | --- |
| no usable credential | 401 | `authentication_required` |
| invalid management API key, key-derived session, gateway API key, or JWT | 401 | `invalid_credential` |
| disabled/expired credential or user | 401 | `credential_inactive` |
| inactive organization or membership | 403 | `tenant_access_denied` |
| missing capability | 403 | `scope_denied` |
| route not granted | 403 or protocol-compatible concealed not-found | `route_access_denied` |
| unsupported request capability | 400 | `unsupported_capability` |
| budget policy denial | 429 | `budget_exceeded` |
| rate/concurrency denial | 429 | `rate_limit_exceeded` or `concurrency_limit_exceeded` |

Management endpoints use OwlRora’s management envelope. LLM endpoints render the ingress protocol’s error shape while retaining a safe OwlRora classification. Errors never reveal whether another organization owns a resource.

## 12. Management rules

- Every key-creation command names a credential class explicitly; a client cannot toggle one key between management and LLM use.
- Gateway-key creation targets one explicit organization resource. It may be created by an owner/admin local user, a policy-enabled member, a same-organization Management-key principal with exact capability/dominance, or a qualifying system administrator through explicit organization context. Requested scopes, required non-empty route allowlist, finite overall budget, optional rate/concurrency policy, and lifetime must fit the applicable global plus issuance-class ceilings. The key has no user owner.
- Management-key creation targets either deployment scope or exactly one organization. Deployment keys require system authority. Organization keys may be created by an owner/admin, a policy-enabled member, a same-organization Management-key principal satisfying target dominance, or a qualifying system administrator through explicit organization context; requested management scopes/capabilities/lifetime must fit every caller, global policy, and applicable issuance-class ceiling. For a JWT or OIDC-session caller, issuer-derived ceilings participate in target credential dominance; `management:access` alone cannot mint a key. The built-in seed key is never a command target.
- Organization owners/admins manage all organization keys. Same-organization Management-key principals may manage only when their own exact scopes/capability ceiling and target dominance authorize it; qualifying system administrators may do so through explicit organization context. Members cannot manage sibling keys. `created_by_principal` is immutable audit evidence only; creator disablement, membership removal, or later role change neither transfers nor disables a key.
- Listing either key class returns metadata and status, never digests or raw material.
- Direct-JWT LLM access is disabled unless the deployment-trusted issuer explicitly permits the required LLM scopes; no organization JWT-policy resource exists and no Gateway-key or origin-pool quota is fabricated for JWT traffic.
- Bulk disable is an audited, credential-class-specific and scope-qualified command.
- Resource-owned API keys are the automation principals. Synthetic users remain available for externally authenticated service identities but are not required merely to own a key.
- Granting or revoking `SystemAdministratorGrant` is an explicit audited authority transition and never follows management-key scope, organization role, or external claims.
- Management-key authentication is accepted only on versioned management routes. Organization keys are rejected from system and protected `/api/v1/system/operations/**` routes; only authorized deployment keys, seed access, or qualifying user/JWT sessions may reach them. The `seed_admin` user cannot own or invoke a gateway key.
