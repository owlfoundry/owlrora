# OwlRora Server

`owlrora-server` is the server library and executable for OwlRora — Routing and Observability for Reliable AI. It packages the production React console and currently ships OwlRora's identity and management plane.

Implemented capabilities include PostgreSQL-backed users, organizations, memberships, administrator grants, invitations, scoped Management API keys and key-derived sessions, external identity/JWT/OIDC administration, audit and idempotency evidence, secret-root encryption, and coherent runtime publication. The embedded console exposes deployment and organization workspaces over the same public Management API used by the independent `owlrora-cli` package.

The LLM gateway data plane is not implemented yet: protocol ingress, provider credentials and catalog execution, gateway keys, routing/failover, Redis allowance coordination, and usage aggregation remain planned. Custom key-provider registration and the higher-level custom server composition builder also remain future work; the official binary directly provides its bundled environment-root encryption path.

The executable requires PostgreSQL plus explicit `OWLRORA_DATABASE_URL`, `OWLRORA_PUBLIC_ORIGIN`, `OWLRORA_SEED_ADMIN_API_KEY`, and `OWLRORA_SECRET_ROOT` configuration. It provides `GET /health` for public liveness and exposes protected operational readiness/publication evidence through the Management API.
