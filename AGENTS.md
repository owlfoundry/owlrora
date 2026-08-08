# OwlRora repository guide

OwlRora is a single Rust web server with an embedded React frontend.

## Source map

- `crates/owlrora-server/src/` — Axum server and embedded frontend delivery
- `apps/web/` — React and Vite frontend
- `scripts/docker/` — container smoke tests

## Development rules

- Keep the repository free of product and domain definitions until they are explicitly designed.
- Build the frontend before compiling the server because the server embeds `apps/web/dist`.
- Run `make check` and `make test` before submitting changes.
- Keep the runtime image non-root and preserve the `/health` endpoint for container health checks.
