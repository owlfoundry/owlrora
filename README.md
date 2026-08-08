# OwlRora

OwlRora is initialized as a Rust web server with a React frontend in `apps/web`. The production frontend is embedded into the server binary. This repository intentionally contains only the runnable project foundation and no product or domain definitions.

## Requirements

- Rust stable
- Node.js 24 or later
- pnpm 11.20.0
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

## Documentation

Run the VitePress documentation site locally:

```bash
make docs
```

## Validation

```bash
make check
make test
make build
make package-check
make docs-build
```

## Container

Build and smoke-test the production image:

```bash
make docker-build
```

Run the locally built image:

```bash
docker run --rm --publish 8080:8080 owlrora:dev
```

The image serves both the API and frontend from one non-root process. Its health endpoint is `GET /health`.
