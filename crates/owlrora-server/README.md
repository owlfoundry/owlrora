# OwlRora Server

`owlrora-server` is the Rust modular-monolith library and executable for OwlRora — Routing and Observability for Reliable AI. It packages the production React Console and owns the Management API, native-compatible Gateway ingress, runtime publication, provider transports, Redis coordination, usage aggregation, and background workers.

Implemented source capabilities include:

- PostgreSQL-backed identity, tenancy, grants, audit, idempotency, catalog, policy, recovery, and usage state;
- separate Management and Gateway key classes, sessions, external JWT/JWKS, and bounded OIDC login;
- upstream endpoints, credentials, deployments, first-class routes/targets, egress policies, and catalog grants;
- Anthropic Messages, OpenAI Chat/Responses HTTP/SSE, Responses WebSocket, and Gemini ingress;
- routing, retry/failover, stickiness, health/circuits, budgets, rates, concurrency, and logical/attempt evidence;
- bundled software custody rooted in `OWLRORA_SECRET_ROOT` plus a custom statically linked custody composition API;
- full, management, gateway, worker, and health-only deployment profiles.

The official binary requires PostgreSQL, Redis, and `OWLRORA_SECRET_ROOT` for every non-health-only profile. Replicas are stateless and require no durable application identity. Management-capable profiles also require `OWLRORA_PUBLIC_ORIGIN` and `OWLRORA_SEED_ADMIN_API_KEY`. `GET /health` is public process liveness; management-capable profiles also expose a coarse public `GET /ready`, while detailed readiness and operations evidence remain protected Management API resources.

Release availability and remaining target gaps are tracked in the repository [implementation status](../../docs/reference/implementation-status.md). Before deployment, read the selected release notes, pin the server image by immutable digest, and follow the [deployment guide](../../docs/deployment/index.md).
