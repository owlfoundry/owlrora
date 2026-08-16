# Data model, local cache, hot path, and scale

## 1. Scale shape

OwlRora’s data architecture assumes at least 10 million logical requests per day, uneven bursts, streaming connections, retries, multiple stateless processes, and substantially larger retained configuration over time.

The architecture avoids:

- PostgreSQL work proportional to request count;
- durable raw request/attempt rows;
- full configuration reload on every mutation;
- Redis metric reads for each routing decision;
- one Redis operation per request for default budget/rate policy;
- unbounded queues, caches, or dimensional cubes;
- sharding and partitioning as substitutes for a poor initial schema.

Horizontal scaling comes from replicated stateless data-plane processes, immutable local runtime state, amortized coordination allowances, and batched sparse persistence.

## 2. State ownership

| State                                                                                                     | Durable authority                          | Runtime representation                                  | Normal request access                    |
| --------------------------------------------------------------------------------------------------------- | ------------------------------------------ | ------------------------------------------------------- | ---------------------------------------- |
| built-in `seed_admin` user and management-key verifier                                                    | deployment environment                     | bounded redacted management-auth configuration          | management only                          |
| users, organizations, memberships, grants                                                                 | PostgreSQL                                 | immutable local snapshot/index                          | memory                                   |
| management API-key digests and scope policy                                                               | PostgreSQL                                 | separate immutable management-key lookup index          | management only                          |
| gateway API-key digests and LLM policy                                                                    | PostgreSQL                                 | separate immutable gateway-key lookup index             | LLM only                                 |
| JWT issuer policy and versioned verifier material                                                         | PostgreSQL; refreshed from external JWKS   | immutable versioned verifier snapshot                   | memory                                   |
| upstream credentials                                                                                      | encrypted PostgreSQL or external reference | dedicated redacted secret/client cache                  | memory client                            |
| endpoints, deployments, routes, pricing, reliability                                                      | PostgreSQL                                 | immutable catalog snapshot                              | memory                                   |
| Gateway-key plus organization origin-budget allowance, key-rate allowance, and optional key strict leases | Redis-compatible coordinator               | bounded key/origin paired grants plus coordinator state | local; amortized or strict as configured |
| provider-state origin                                                                                     | Redis-compatible coordinator               | bounded TTL binding                                     | create/continuation only                 |
| circuit and immediate health                                                                              | gateway process                            | bounded local structures                                | memory                                   |
| shared target health summary                                                                              | Redis-compatible coordinator               | coalesced local health view                             | memory; periodic sync                    |
| usage analytics                                                                                           | local accumulators then PostgreSQL         | bounded sparse deltas                                   | local append                             |
| telemetry                                                                                                 | process SDK then external collector        | bounded SDK queues                                      | non-blocking append                      |
| audit                                                                                                     | PostgreSQL                                 | management queries                                      | never data path                          |

Redis is not authority for users, keys, grants, endpoints, credentials, routes, or pricing.

## 3. Durable domain groups

### 3.1 Identity and tenancy

- `users`
- `external_identity_issuers`
- `external_identity_bindings`
- `issuer_verifier_material_versions`
- `system_administrator_grants`
- `organizations`
- `memberships`
- `invitations`
- `web_sessions`
- `provisioning_policies`

The built-in `seed_admin` user, its environment management key, and its verifier are not durable domain rows. A key-derived web session persists its opaque session digest, typed seed/deployment-key/organization-key principal, authentication origin, management-key identity/version, and the exact scope/resource ceiling needed to prevent privilege expansion. It stores a `user_id` only for the special built-in `seed_admin` principal and never stores or resolves the durable key creator as a session user. A seed-administrator session stores the deterministic `seed_admin_key_version_id` defined in specification 11. An OIDC-derived session instead persists its issuer ID, concrete management scope set, and safe typed effective login capability/organization ceiling captured after explicit issuer scope/organization ceilings and claim narrowing are intersected; it stores no external token or arbitrary claim document. Request authorization intersects those captured ceilings with current issuer status/policy and local-user authority, so expansion requires re-login.

### 3.2 Credentials and authorization

- `management_api_keys`
- `management_api_key_secret_versions`
- `gateway_api_keys`
- `gateway_api_key_secret_versions`
- `organization_api_key_policies`
- `organization_route_grants`
- `organization_endpoint_grants`
- `organization_deployment_grants`
- `organization_reliability_policy_grants`
- typed system, issuer, organization, and membership ceilings

Management-key and gateway-key digest records are separated from listable metadata and from each other where practical. Their lookup IDs, prefixes, scope vocabularies, runtime indexes, and accepted HTTP surfaces are disjoint. Durable key metadata stores immutable deployment/organization resource scope, `issuance_policy_class=standard|member_self_service`, and `created_by_principal`, never `owner_user_id`; creation attribution is not consulted on admission or policy classification.

### 3.3 Upstream catalog and secrets

- `upstream_credentials`
- `upstream_credential_secret_versions`
- `upstream_credential_auth_state`
- `upstream_credential_login_sessions`
- `upstream_credential_refresh_leases`
- `upstream_endpoints`
- `model_deployments`
- `pricing_policies` and immutable versions
- `model_routes`
- `route_targets`
- `reliability_policies`
- typed capabilities and adapter contracts

Protected secret records carry immutable system/organization resource scope, safe creation attribution, custody provider ID, provider/context format versions, and one bounded opaque envelope. The bundled software envelope contains its suite, nonce, and ciphertext; it has no wrapped DEK. Protected material does not share a JSON blob with safe endpoint or route configuration.

There is no provider-connection or model-alias table.

### 3.4 Enforcement and usage

- `gateway_key_budget_policies`, one mandatory stable policy per Gateway key;
- `organization_origin_budget_policies`, unique by `(organization_id, system_provided | organization_byok)`;
- immutable desired/active budget-policy versions carrying `enforce | record_only`, limit, epoch, estimate, allowance, failure, and recovery configuration;
- one optional Gateway-key request-limits policy per key, with immutable desired/active versions carrying both rate and optional approximate/strict concurrency configuration; there is no independent concurrency-policy reference;
- durable coordinator activation states with explicit `policy_kind + policy_id`, generations, and externally controlled epochs;
- durable approximate allowance checkpoints aggregated across processes and keyed by exact `(policy_kind, policy_id, epoch, generation)`, plus separately identified recovery records;
- `logical_usage_hourly` and `attempt_usage_hourly` plus daily rollups, with target-derived origin and applicable key/origin policy epochs;
- `aggregate_flush_receipts` keyed by process source epoch and batch sequence.

### 3.5 Control-plane integrity

- singleton immutable `system_installation` identity used by protected-secret context;
- immutable audit entries with a typed actor principal (`seed_admin`, local user, deployment Management key, organization Management key, or other explicitly supported actor) plus safe authentication/credential identity; `user_id` is present only for a user principal;
- transactional outbox events;
- ordered configuration journal records;
- bounded idempotency records for retryable commands;
- process-local applied configuration state and protected diagnostics, without durable replica registration.

## 4. Organization-qualified schema

1. Every tenant table has non-null `organization_id`, even when another relation could imply it.
2. Tenant unique constraints include `organization_id` unless intentionally global.
3. Repository methods accept organization ID explicitly and include it in predicates.
4. Composite foreign keys enforce same-organization relationships where practical.
5. System scope uses a discriminator rather than a fake organization.
6. Historical aggregate/audit identifiers remain valid after rename or disablement.
7. Lifecycle status is modeled explicitly; generic soft delete is not a substitute.

## 5. Runtime snapshot

Each server process exposes one atomically replaceable generation:

```text
RuntimeGeneration {
    snapshot: Arc<RuntimeSnapshotRoot>,
    credential_clients: Arc<CredentialClientRegistry>,
}

RuntimeSnapshotRoot {
    revision,
    built_at,
    security_sequence,
    identity: Arc<IdentitySnapshot>,
    management_key_index: PersistentMap<ManagementKeyLookupId, ManagementKeyVerifierAndResourcePrincipal>,
    gateway_key_index: PersistentMap<GatewayKeyLookupId, GatewayKeyVerifierAndOrganizationPrincipal>,
    catalog: Arc<CatalogSnapshot>,
    organizations: PersistentMap<OrganizationId, Arc<TenantPolicySnapshot>>,
}
```

One request captures one `RuntimeGeneration` and therefore observes one coherent policy/catalog revision and matching credential-client versions for authentication, authorization, target selection, and dispatch.

`IdentitySnapshot` contains active issuer policy including explicit management scope/organization ceilings, the exact current `IssuerVerifierMaterialVersion` and public keys, subject-binding index, user status, deployment Management-key resource/scope state, and system-administrator grants whose subject is a local user or deployment Management key. A JWKS refresh writes a new material version and configuration-journal revision before processes can publish it; verifier maps are never mutated in place. The config-derived seed-administrator management-key verifier remains in the management-authentication runtime and never enters the LLM gateway-key index or tenant snapshot.

A short successful JWT signature cache keys by `(token_digest, issuer_id, algorithm, issuer_policy_version, verifier_material_version)` and expires at the earliest of token expiry, key/material acceptance expiry, policy bound, or revocation boundary. Current issuer, user, membership, and authorization state are still reevaluated from the captured snapshot on every call.

`TenantPolicySnapshot` contains organization status, memberships, scope ceilings, organization API-key policy, organization Management/Gateway key metadata including required route allowlists and overall key-budget references, organization BYOK credentials/deployments, endpoint/route/deployment/reliability grants, the system-provided and BYOK origin-budget references, Gateway-key-only rate/concurrency references, and any newer tightening activation deadline that must fail closed. Direct JWT eligibility comes from the identity snapshot's trusted-issuer/token ceilings intersected with tenant membership and route state; there is no separate organization JWT-policy row and no key/origin quota is fabricated for JWT traffic.

Persistent immutable maps and `Arc` sharing avoid cloning the whole deployment for one tenant change.

Recoverable upstream plaintext is deliberately excluded from the serializable-safe snapshot. The catalog references `(credential_id, secret_version)`, while the same atomic runtime generation carries a non-serializable credential-client registry keyed by exactly `(credential_id, secret_version, endpoint_id, endpoint_config_version, transport_kind)`. Database-backed upstream secret-version rows reference exactly one generic protected-secret envelope; environment, file, and workload versions persist only typed bounded source configuration.

## 6. Configuration synchronization

### 6.1 Transactional publication

A control-plane command commits in one PostgreSQL transaction:

1. domain changes;
2. required audit entry;
3. acquisition of the singleton runtime-revision counter row with `SELECT ... FOR UPDATE`;
4. allocation of the next revision while holding that row lock until transaction commit;
5. one configuration journal record at that revision with affected resource/scope IDs and security classification;
6. an outbox wake-up record.

The revision-counter lock is the commit-order serialization point for every runtime-affecting transaction. No such transaction may allocate a revision and release the lock before commit, and no network/custody/provider work runs while it is held. A rollback also rolls back the counter increment and journal row. Consequently committed journal revisions are contiguous and their numeric order equals commit order; a later revision cannot become visible while an earlier allocated revision remains uncommitted.

The journal record names the new revision and enough affected identities to rebuild bounded components. It never contains plaintext secrets. Coordinator-backed policy changes use the durable pending/activation transitions in spec 07: desired tightening can publish a fail-closed deadline marker, while only the coordinator-confirmed active transition publishes spendable runtime policy.

### 6.2 Process catch-up

Each server process:

1. receives a best-effort Redis/pub-sub or PostgreSQL notification that a newer revision exists;
2. coalesces concurrent notifications through one singleflight refresh;
3. starts one PostgreSQL `REPEATABLE READ`, read-only transaction and captures its schema compatibility plus transaction-visible journal high-watermark;
4. reads ordered journal entries through that high-watermark and bulk-loads every affected user/tenant/catalog component in bounded queries inside the same MVCC snapshot;
5. copies the exact versioned protected-secret/source records needed by that candidate, then closes the database transaction;
6. performs secret opening, file/environment, provider-client build, and validation I/O outside the transaction;
7. rebuilds a complete candidate `RuntimeGeneration` whose revision equals the captured journal high-watermark;
8. publishes through one compare-and-swap only if its revision is newer than the current root and no known newer security candidate makes it unsafe, then reports the applied revision;
9. immediately schedules another catch-up when the journal advanced during the build and periodically reconciles with jitter so lost notifications cannot stall convergence.

A burst of changes coalesces to the highest contiguous commit-ordered revision visible in the transaction. Every candidate therefore corresponds to one committed PostgreSQL snapshot; no lower revision can commit after that watermark, and bounded component queries can never synthesize identity, grant, catalog, or credential state from different revisions. Processes do not reload the complete catalog for every small mutation, issue per-route N+1 queries, or update independent maps under unrelated locks.

A journal gap or incremental-compatibility failure triggers one bounded full snapshot rebuild under the same `REPEATABLE READ` high-watermark fence. Unsupported schema/journal kinds reject the candidate. Before publication, the process rechecks schema compatibility, its current applied revision, and highest known security revision; it never regresses or labels a mixed/latest read as an earlier revision. The prior valid snapshot remains available only within staleness policy. Security disablement that leaves a route with zero targets still compiles as an operationally unavailable graph.

### 6.3 Secret changes

A credential secret update publishes only identity/version metadata. Each server process opens the selected protected secret outside the snapshot lock, builds a new client, validates the candidate binding as configured, and publishes the safe snapshot plus matching client registry through one `RuntimeGeneration` pointer swap.

No plaintext enters pub/sub, outbox, journal, runtime diagnostics, or a broadly serializable snapshot. Unchanged credential clients are structurally shared rather than rebuilt. If bundled decryption or custom custody fails for a newly selected version, the published runtime generation marks only that credential and its dependent deployments operationally unavailable; it does not retain an older permissive catalog or block unrelated security changes. An older secret version remains selectable only under an explicit bounded overlap policy.

### 6.4 Staleness

Security tightening targets propagation within five seconds; ordinary changes target thirty seconds. A process whose confirmed snapshot is older than `max_security_snapshot_age` rejects new admission. Existing committed streams continue under their captured context unless a separately configured emergency termination policy applies.

## 7. Gateway-key and JWT hot path

Gateway-key verification resolves an organization key principal directly; it does not load or fabricate a creator user/membership. Gateway-key wire format includes a random non-secret lookup component. The local index resolves it in constant expected time and performs constant-time SHA-256 digest comparison. Its snapshot value directly references the required stable route-ID allowlist, overall key budget, and optional key rate/concurrency policy. Unknown keys do not fall back to PostgreSQL or Redis.

JWT verification reads only the local issuer/material snapshot. An unknown `kid` fails the current request and triggers one bounded asynchronous refresh. The worker validates the fetched complete key set outside a transaction, then commits a new verifier-material version, issuer pointer, audit/diagnostic evidence, configuration journal, and outbox wake-up together. Identity-provider network calls are never in the LLM request path, and all processes converge through the same immutable generation publication.

Active-key capacity and memory per key are measurable operational dimensions. If one process can no longer hold the required index, the architecture may introduce key-hash data-plane pools; it does not begin by sharding PostgreSQL.

## 8. Normal request path

```mermaid
flowchart LR
    Ingress[Bounded protocol parsing] --> Root[Capture runtime generation]
    Root --> Auth[Local authentication and organization qualification]
    Auth --> Route[Resolve authorized route and capabilities]
    Route --> RequestLimits[Overload plus key-only rate/concurrency]
    RequestLimits --> Origin[Optional strict state-origin lookup]
    Origin --> Select[Origin-qualified or deterministic candidates]
    Select --> TargetLimits[Target capacity plus paired key/origin budget]
    TargetLimits --> Upstream[Matching generation client]
    Upstream --> Settle[Local settlement and optional strict release]
    Settle --> Buffers[Aggregate and OTLP buffers]
```

The normal path does not synchronously:

- query PostgreSQL;
- load or decrypt a secret;
- insert request/attempt rows;
- publish to a durable broker;
- fetch routing metrics from Redis;
- refresh JWKS;
- write ordinary preferred affinity;
- wait for aggregate flush or OTLP export.

Redis calls occur only when a local enforcing allowance needs replenishment, strict Gateway-key concurrency is configured, shared state-origin is created/consumed, or another explicit coordinated capability requires it. Continuation origin lookup occurs after route authorization and overload plus any key rate/concurrency admission but before target ordering, target-specific pricing, paired key/origin allowance reservation, and capacity acquisition. Unknown continuation IDs therefore cannot generate unmetered coordinator reads. Direct-JWT traffic has no fabricated quota coordinator state.

## 9. Usage write path

Each process accumulates `LogicalUsageDelta` and `AttemptUsageDelta` in separate bounded maps keyed by canonical sparse hourly dimensions.

A process generates `aggregate_source_epoch`; flush batches use monotonic `batch_sequence`:

1. atomically swap the active delta map;
2. create immutable bounded batches;
3. transactionally insert unique `(source_epoch, batch_sequence)` receipt and additive checked upserts;
4. treat receipt conflict as already applied, including commit-then-timeout ambiguity;
5. retry the same batch within memory/time bounds;
6. drop only after configured capacity is exhausted and emit explicit loss signals.

Logical facts count one request. Attempt facts count every upstream attempt and retain target, derived `system_provided | organization_byok` origin, deployment, endpoint, pricing version, applicable key/origin policy epochs, outcome, usage, and cost. Provider breakdowns never masquerade as unique request counts.

Hourly-to-daily rollup is idempotent. Retention operates in bounded batches. Broad fleet analytics belongs to the external observability backend.

## 10. Database access and indexes

PostgreSQL pools serve management commands, snapshot refresh, secret-controller work, audit, and aggregate workers. Data-plane volume does not linearly consume DB connections.

Indexes prioritize:

- organization-qualified resource lookup;
- active gateway-key lookup by non-secret component during snapshot build;
- journal sequence and affected-scope catch-up;
- credentials due for refresh by `next_refresh_at`;
- organization/time usage queries;
- user/Gateway-key/route/target-origin/deployment breakdown within bounded time ranges;
- rollup and retention by bucket.

The schema does not materialize every dashboard cube or index permutation. Native partitioning is introduced only when measured retention/maintenance pressure justifies it.

## 11. Background task bounds

Every worker has explicit ownership, bounded concurrency, retry/backoff, cancellation, shutdown deadline, lag signals, and replay semantics. No worker holds a database transaction while calling an upstream provider, KMS, JWKS endpoint, or telemetry collector.

Credential refresh workers claim only due rows through indexed bounded batches and version/fingerprint fencing. They do not run one full-table scan per gateway process.

## 12. Failure behavior

| Failure                                 | Behavior                                                                                                                |
| --------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| PostgreSQL unavailable after valid load | data plane continues inside staleness bounds; management/flush/refresh degrade                                          |
| notification lost                       | ordered journal reconciliation catches up                                                                               |
| notification burst                      | singleflight/coalescing applies highest revision                                                                        |
| invalid candidate graph                 | prior valid root remains until staleness bound; high-severity fault                                                     |
| operational disable leaves no target    | unavailable graph publishes immediately                                                                                 |
| Redis unavailable                       | local grants continue; later admission follows `deny` or bounded-local policy                                           |
| Redis state loss                        | a new generation fences old grants and automatically activates only the durably capped recovery allowance for the epoch |
| aggregate database unavailable          | bounded buffering/drop; proxy continues                                                                                 |
| OTel collector unavailable              | bounded SDK drop; proxy continues                                                                                       |
| KMS/key provider unavailable            | affected secret rebuild/rotation fails; unrelated loaded routes continue                                                |
| process crash                           | local analytics and settlement detail may lose a bounded window; leases/grants expire                                   |

## 13. Performance evidence

Any published scale claim includes hardware, process/replica count, protocol/payload mix, streaming duration, enabled policies, Redis call rate, upstream stub behavior, database write rate, memory, queue depth, and latency results.

Performance work profiles the hot path and cache synchronization before proposing microservices, PostgreSQL sharding, or broad table partitioning. The central architectural evidence is:

- zero normal PostgreSQL operations per LLM request;
- Redis operations amortized by allowance grants unless strict policy is selected;
- bounded memory per key, route, target, aggregate key, active request, and stream;
- configuration-change cost proportional to affected components rather than total request volume;
- aggregate persistence proportional to sparse dimensions and flush cadence rather than request count.
