# Security model

::: warning Release boundary
This page follows repository `main`. Confirm the security behavior of the exact server release you select, and do not mix incompatible releases in one deployment.
:::

OwlRora uses explicit resource authority, separate credential classes, fail-closed runtime snapshots, bounded network egress, and authenticated secret custody. This page summarizes implemented source behavior; it is not a substitute for a deployment threat model.

## Credential classes

### Management API keys

Management keys use the `owlrora_mgmt_v1` wire prefix. They authenticate only management surfaces and may be deployment-owned or organization-owned. Effective authority intersects scopes, capability ceilings, immutable resource scope, current policy, and any required administrator grant.

### Gateway API keys

Gateway keys use a distinct `owlrora_llm_v1` prefix, verifier index, scope model, and accepted surface. They are the only quota-bearing request principals. Each key has a non-empty stable route-ID allowlist and one finite overall budget.

Neither key class is owned by its creator user. `created_by_principal` is audit attribution only.

### Seed administrator key

`OWLRORA_SEED_ADMIN_API_KEY` remains only in deployment configuration. It authenticates the built-in API-key-only `seed_admin` principal, is never inserted into PostgreSQL, and is never accepted at Gateway ingress. Generate one high-entropy value, keep it consistent across management nodes, and store it as break-glass material.

### Sessions and external identity

Key-derived sessions, local-user sessions, external JWTs, and bounded OIDC sessions converge on one typed authorization pipeline. OIDC sessions capture issuer and organization ceilings at login; expanding those ceilings requires a new login.

An external issuer's coarse management-access marker does not imply operation scopes or system reach. A direct-JWT issuer is API-only unless configured with an explicit browser-login profile.

## Stored secret classes

### Non-recoverable bearer values

OwlRora stores only domain-separated SHA-256 digests for bearer values it never needs to recover, including durable API-key verification material and session tokens.

### Recoverable secrets

The official binary encrypts provider credentials and other recoverable values with versioned authenticated encryption rooted in `OWLRORA_SECRET_ROOT`. The immutable PostgreSQL installation ID participates in authenticated context.

Operational consequences:

- preserve the exact root with every database backup;
- do not store it inside PostgreSQL;
- do not change it as an attempted rotation;
- deleting ciphertext removes the active recoverable copy, but is not per-secret cryptographic erasure because there is no per-secret DEK/root ring.

`owlrora-key-provider` is a provider-neutral SPI for custom statically linked server binaries. The official binary does not ship a built-in KMS adapter.

## Egress boundary

An endpoint references a deployment-owned egress network policy. Runtime clients:

- disable ambient HTTP proxy discovery;
- disable redirects;
- require HTTPS according to endpoint policy;
- validate certificates and hostnames;
- enforce TLS version policy and optional custom CA identity;
- re-resolve and revalidate destination addresses;
- enforce CIDR allow/deny and special-address classification;
- bound DNS answers, connect/request/body limits, pool size, and in-flight attempts.

Organization BYOK grants credential use, not endpoint or egress-policy editing.

## Browser and HTTP protections

The embedded Console applies a restrictive content security policy, frame denial, MIME sniffing protection, and referrer policy. Management CORS accepts only the configured public origin and explicit methods/headers.

For non-loopback deployment:

- terminate TLS at a trusted proxy;
- set `OWLRORA_PUBLIC_ORIGIN` to the exact HTTPS origin;
- keep bearer values out of URLs;
- redact sensitive headers and cookies in every proxy/logging layer;
- separate operator diagnostics from public ingress.

OwlRora evaluates operator networks from the direct TCP peer. It does not trust `X-Forwarded-For` as an operator identity mechanism.

## Data-path privacy

The normal Gateway path does not synchronously persist raw request or response bodies. Built-in usage stores compact IDs, counts, durations, outcome classes, token/cost aggregates, and bounded error classifications.

Standard OpenTelemetry export and an opt-in content-capture subsystem are not implemented in the current source. Do not describe the existing `tracing` JSON logs as a complete OTel implementation.

## Hardening checklist

- Pin image digests; never deploy a mutable tag.
- Use separate least-privilege PostgreSQL and Redis credentials.
- Keep server port 8080 private.
- Use TLS for browser, Management API, and Gateway traffic.
- Store seed key and secret root in a deployment secret manager.
- Restrict `OWLRORA_OPERATOR_NETWORKS` and operator routes.
- Leave Gemini query-key compatibility disabled unless required.
- Use bounded endpoint CIDRs and verify custom CA provenance.
- Treat replicas as stateless; inspect each rollout process through deployment health checks and use external telemetry for fleet inventory.
- Back up and restore-test PostgreSQL plus the external secret root together.
- Keep Management and Gateway keys separate in clients and automation.
