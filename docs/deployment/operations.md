# Production operations

::: warning Release boundary
This runbook follows repository `main`. Read the selected release notes and keep binaries, schema, configuration, and recovery state matched to a compatible release.
:::

It does not turn unimplemented target-spec features into guarantees.

## Health model

### Public liveness

`GET /health` returns HTTP 200 and `ok` when the process serves HTTP. It deliberately does not query PostgreSQL, Redis, runtime publication, workers, routes, or providers.

Use it for container liveness and restart decisions, not traffic admission.

### Coarse and detailed readiness

Every profile except `health-only` exposes public `GET /ready`. It returns only `{"status":"ready"}` or `{"status":"not_ready"}` and is suitable for a coarse load-balancer decision.

The authenticated `system.operations.readiness` Management resource exposes the detailed evidence behind that result:

- current-process applied runtime revision;
- current durable database revision;
- age of the process's last successful revision confirmation;
- the current-process publication error, if any.

Readiness reads the coherent published generation and its confirmation evidence without making a database query per probe: the generation must include the highest observed security revision and its database confirmation must remain fresh. Ordinary configuration lag and an overdue tenant policy are diagnostics, not deployment-wide unready conditions. A failed rebuild cannot keep revoked management authority alive merely because revision polling still succeeds. Inspect policy activation deadlines through `system operations activations`; only admission consuming the affected policy is blocked.

The protected `system operations runtime` response also reports a runtime `build_id`. Configuration revision orders durable changes; build identity identifies a particular reconstruction. Unavailable credential clients are retried with bounded backoff, and explicit runtime reconciliation can repair the same configuration revision. Healthy unchanged clients remain shared. This does not automatically rotate an already healthy mounted-file credential: use its managed credential replacement/version workflow.

```bash
owlrora --profile production --output json system operations readiness
```

It does **not** include Redis, target probe, usage worker, or other worker health. Inspect those separately with `system operations coordination`, `target-health`, and `usage-pipeline`.

`OWLRORA_REQUIRED_ROUTE_IDS` optionally lists stable route UUIDs. Each must resolve to an enabled, structurally callable route with an eligible current client and valid scope bindings. An unknown ID, stale security evidence, or process drain makes readiness fail. This does not send a provider request or promise that a remote provider is healthy. Do not make every tenant route mandatory: an isolated tenant failure should not evict a whole gateway. Probe each split-profile process directly; a management process cannot report the local runtime of a separate gateway/worker.

## Startup and migrations

Every non-health-only process:

1. opens a PostgreSQL pool;
2. runs embedded SQLx migrations;
3. creates or reads the immutable installation identity and default management policy;
4. connects to Redis and requires a successful `PING`;
5. captures a repeatable-read database snapshot and builds a runtime generation;
6. starts profile-specific workers and HTTP surfaces.

There is no separate migration executable or migration-only URL. The runtime database role requires DDL privileges. Before a rollout:

- take a PostgreSQL backup;
- test migration and startup against a restored copy;
- deploy one process first and inspect logs/readiness;
- only then continue the rollout.

Do not run a newer binary against production and assume an older binary can always roll back after schema migration. The project does not publish a general backward-schema compatibility guarantee.

Migration `0012_remove_node_instance_identity.sql` is a concrete compatibility boundary: it drops `node_watermarks`, which pre-0012 processes read and write. Before starting any build that contains 0012, drain and stop every pre-0012 process. After 0012 commits, do not restart a pre-0012 binary against that database; rollback requires restoring the pre-upgrade PostgreSQL backup and matching deployment state.

## Backup contract

A recoverable backup set contains:

1. one transactionally consistent PostgreSQL backup, including `system_installation`;
2. the exact `OWLRORA_SECRET_ROOT`, stored separately from the database;
3. the deployment's seed key if continued break-glass access is required;
4. external credential/workload configuration and provider-side identities;
5. image digest and complete non-secret server configuration.

PostgreSQL contains encrypted recoverable secret envelopes and domain-separated digests, not the software root. Backing up only the database is insufficient.

Redis is coordination state, but the current implementation does not provide a one-command Redis-loss recovery runbook. Use Redis HA/persistence appropriate to your risk tolerance. Bounded recovery requires explicit Management API authority and durable evidence; do not restore or flush Redis casually.

## Restore drill

Perform restore tests in isolation:

1. Provision an empty PostgreSQL instance and restore the entire database.
2. Restore the exact secret root through the deployment secret manager.
3. Start one OwlRora process with the pinned image digest; no durable replica identity is required.
4. Verify public coarse readiness plus protected runtime revision, custody evidence, policy activations, target health, and usage pipeline.
5. Verify a non-production upstream credential can be opened and a test route can complete.
6. Validate Redis coordination/recovery evidence before admitting production Gateway traffic.

Never create a new `system_installation` row for a restored database. It is immutable authenticated context for encrypted secrets.

## Upgrade procedure

1. Read the release notes and pin the new image digest.
2. Back up PostgreSQL and deployment secrets.
3. Restore the backup into a staging environment and start the new image.
4. Run management, Gateway, streaming, WebSocket, usage, and provider-specific smoke tests relevant to your deployment.
5. Use a rolling canary only when the release notes explicitly guarantee mixed-version and schema compatibility for the source and destination versions.
6. Otherwise, drain and stop every older process before the first new process starts and runs embedded migrations; plan a maintenance window.
7. Inspect protected runtime, coordination, target-health, usage-pipeline, custody, and telemetry status, respecting the evidence scopes below.
8. Admit the new processes gradually and retain the pre-upgrade database backup until validation completes.

The project does not infer rolling compatibility merely because replicas are stateless. PostgreSQL migrations and Redis key schemas can establish a version boundary.

On SIGTERM/Ctrl+C, the process marks itself unready and stops accepting connections. New business requests and new turns on existing WebSockets are rejected. Ordinary HTTP work, including a blocked downstream body, has the request drain grace (default 15 seconds). Already committed SSE and WebSocket work has the stream grace (default 30 seconds). Pre-header work uses request grace, even when the caller requested streaming. Both deadlines start at drain initiation, not at the next body poll. Remaining connection/request owners are dropped and joined before aggregate flush.

Controllers and probes stop, distributed permit-release/grant return is bounded, and usage flush has a worker deadline (default 10 seconds, with individual database flushes bounded to five seconds). Unconfirmed and lost aggregate counts are reported rather than silently called durable. Standard telemetry drains last, with at most five seconds per signal. Configure the orchestrator termination grace to exceed the stream/request maximum plus worker and telemetry allowances. Remove the replica from external ingress before termination when uninterrupted traffic is required; graceful shutdown is bounded, not lossless.

## Scaling

### Stateless replicas

OwlRora does not register or persist replica identities. Identical replicas may share one configuration and do not require stable Pod names, StatefulSet ordinals, or load-balancer affinity. Redis allowance grants carry unique grant IDs; target probes use short lease tokens; runtime and loss counters remain local to the responding process. Use your deployment platform and telemetry backend for fleet inventory.

### Database and Redis

Multiply connection pools by maximum replica count. Runtime publication currently polls and rebuilds coherent snapshots rather than consuming incremental LISTEN/NOTIFY deltas, so additional processes also increase configuration-read load.

### Split profiles

Split `management`, `gateway`, and `worker` only when you need independent exposure or scaling. All profiles still share PostgreSQL, Redis, installation identity, and secret custody configuration. A gateway-only process does not expose Console or Management API; a worker-only process has no business HTTP surface. Both expose `/health` and coarse `/ready`.

### No affinity requirement

HTTP session and routing authority are durable/shared or captured in the runtime generation. Normal traffic does not require sticky load-balancer sessions. Provider-side state may still require route-level stickiness configured in OwlRora.

### Operations evidence scope

- `readiness` and `runtime.publication` describe the current Management process plus the durable journal.
- `target-health.local` and target-health loss/circuit details are current-process evidence; cached active-probe summaries are TTL-bounded Redis-shared evidence.
- `usage-pipeline.process` is current-process evidence; recent flush receipts and aggregate bucket timestamps are durable fleet evidence.
- `coordination` combines a live Redis check with durable recovery/activation records.

In a split-profile deployment, the Management API cannot directly retrieve process-local evidence from gateway-only or worker-only replicas.

## Reverse proxy requirements

- Terminate TLS before OwlRora.
- Preserve WebSocket upgrades for `GET /v1/responses`.
- Disable response buffering for SSE.
- Use timeouts longer than allowed long-running stream policy.
- Forward the original `Host`/scheme as normal proxy metadata, but do not expect OwlRora to trust forwarded IP headers for operator-network authorization.
- Keep Management API and operator diagnostics off untrusted public paths when possible.
- Never log authorization, cookie, `x-api-key`, `x-goog-api-key`, or query credentials.

## Incident response

Protected operations resources are the first evidence source. Run these through the private operator ingress, not the public hostname:

```bash
owlrora --profile production --output json system operations overview
owlrora --profile production --output json system operations runtime
owlrora --profile production --output json system operations coordination
owlrora --profile production --output json system operations target-health
owlrora --profile production --output json system operations usage-pipeline
owlrora --profile production --output json system operations secret-custody
owlrora --profile production --output json system operations telemetry
```

Emergency coordination recovery is explicit, bounded, audited, and generation-fenced. Do not bypass it by manually editing Redis keys or PostgreSQL policy rows.

## Compact usage retention and replay

Each flush writes hourly and daily logical/attempt aggregates plus its deduplication receipt in one PostgreSQL transaction. Migration 0014 backfills daily totals from existing hourly facts. Hourly buckets are retained for 30 days, daily buckets for 366 days, and receipts for at least eight days. A maintenance pass runs every 60 seconds, deletes at most 10,000 rows per table, and has a five-second total timeout. Expired rows can therefore remain longer during load or outage.

Batch replay is accepted only within seven days of its aggregate bucket, checked against the database clock before receipt lookup. Old replay cannot resurrect facts after receipt cleanup. Recent receipts cannot be deleted through the retention path. Day queries use daily aggregates for fully covered UTC days and hourly aggregates for partial-day edges, without double counting. Partial-day edges older than hourly retention cannot be reconstructed; the response reports completeness/retention limits.

These aggregates are best-effort operational evidence, not a financial ledger. Collector failure does not change usage persistence; database outage can exhaust bounded aggregate queues. Inspect loss and unconfirmed counts before treating totals as complete.

## Known operational gaps

The current source does not yet provide:

- native TLS listener configuration;
- automated PostgreSQL/secret backup or restore tooling;
- a fully documented and automated Redis-loss recovery command;
- target incremental runtime publication via journal deltas/notifications;
- benchmark evidence for the target fleet/request-scale objectives;
- the entire target telemetry signal inventory (the exported subset is listed under server configuration).

Treat these as deployment design inputs, not hidden assurances. Track them on [Implementation status](/reference/implementation-status).
