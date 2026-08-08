# OwlRora

OwlRora is initialized as a Rust web server with a React frontend in `apps/web`. The production frontend is embedded into the server binary. This repository intentionally contains only the runnable project foundation and no product or domain definitions.

## Requirements

- Rust stable
- Node.js 24 or later
- pnpm 10.30.3
- Docker for container builds

## Development

Install locked dependencies:

```bash
make install
```

Build the frontend and run the server:

```bash
make dev
```

The application listens on `http://localhost:8080` by default. Override the listener with `OWLRORA_ADDR`.

For frontend development with Vite:

```bash
pnpm dev
```

## Validation

```bash
make check
make test
make build
```

## Container

Build and smoke-test the production image:

```bash
make docker-build
```

Run it directly:

```bash
docker run --rm --publish 8080:8080 ghcr.io/owlfoundry/owlrora:latest
```

The image serves both the API and frontend from one non-root process. Its health endpoint is `GET /health`.
