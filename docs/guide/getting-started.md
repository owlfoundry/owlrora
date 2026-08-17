# Getting started

This guide evaluates the current source tree as one `full` process. It is not a production topology; use the [deployment guide](/deployment/) before exposing OwlRora to real traffic.

::: warning Source versus release
This guide follows repository `main`. For a reproducible deployment, select server and CLI releases whose source contains the documented capabilities; when evaluating newer source, build both components from the same revision. Never assume that a documentation deployment changes an existing binary.
:::

## Prerequisites

- Git
- Docker with Compose v2
- Rust and Node.js only if you want to run outside the container build
- `curl`, `python3`, and a browser

The repository development stack uses PostgreSQL 17 and Redis 7.4 on loopback-only ports.

## 1. Clone and start dependencies

```bash
git clone https://github.com/owlfoundry/owlrora.git
cd owlrora
git checkout main

docker compose -f dev/compose.yml up -d --wait
```

Development endpoints:

- PostgreSQL: `127.0.0.1:55432`
- Redis: `127.0.0.1:56379`

Both contain disposable local state.

## 2. Create local server configuration

The checked-in `.env.example` contains public development-only values. Copy it only for local evaluation:

```bash
cp .env.example .env
```

The example configures:

- the `full` deployment profile;
- local PostgreSQL and Redis;
- stateless replica configuration with no persistent process identity;
- the public browser origin `http://127.0.0.1:8080`;
- a public test-only seed Management API key and secret root.

Do not reuse either example secret outside a disposable local environment. Production generation and storage requirements are documented under [Deployment](/deployment/).

## 3. Run the server

```bash
make dev
```

The process runs embedded SQL migrations during startup, builds the initial runtime generation, starts workers, and then serves the Management and Gateway surfaces.

In another terminal:

```bash
curl -fsS http://127.0.0.1:8080/health
```

Expected response:

```text
ok
```

Open <http://127.0.0.1:8080/> for the embedded Console.

## 4. Authenticate as the built-in seed administrator

For the local example only, export the test key from `.env`:

```bash
set -a
. ./.env
set +a
```

The seed key is a deployment configuration secret. It authenticates the built-in API-key-only `seed_admin` principal and is never inserted into PostgreSQL.

Use the CLI from source:

```bash
cargo run --locked -p owlrora-cli -- \
  --server-url http://127.0.0.1:8080 \
  --key-env OWLRORA_SEED_ADMIN_API_KEY \
  --output json \
  me get
```

You can also paste the key into the Console login flow. Browser key exchange must use TLS for non-loopback origins.

## 5. Inspect server readiness and operations

`/health` is public process liveness. For `full` and `management`, `/ready` is a public coarse signal with no detailed evidence:

```bash
curl -fsS http://127.0.0.1:8080/ready
```

Inspect the detailed authenticated readiness resource through the CLI:

```bash
cargo run --locked -p owlrora-cli -- \
  --server-url http://127.0.0.1:8080 \
  --key-env OWLRORA_SEED_ADMIN_API_KEY \
  system operations readiness
```

Use CLI discovery if an operation name changes:

```bash
cargo run --locked -p owlrora-cli -- system --help
cargo run --locked -p owlrora-cli -- system operations --help
```

## 6. Configure a first route

Use the Console or typed CLI in this order:

1. Create an egress network policy and an upstream endpoint bound to it.
2. Create an upstream credential. Secret-returning operations show plaintext once.
3. Create a pricing policy and publish an immutable pricing version, or deliberately mark the deployment unpriced.
4. Create a model deployment that references the endpoint, credential, transport, and pricing choice; run deployment validation before activating it.
5. Create a reliability policy. It is a directly versioned resource updated with `ETag`/`If-Match`, not a separately published reliability-version object.
6. Create a first-class model route that references the reliability policy and one or more explicit deployment targets.
7. Configure and activate the organization's existing `system_provided` and `organization_byok` origin budget policies as applicable. These two resources are created with the organization.
8. Create an organization Gateway API key. The create input contains its non-empty stable route-ID allowlist **and** finite overall key-budget policy.
9. Optionally create/update the key's request-limit policy for rate and concurrency behavior.

See [Management plane](/guide/management) for resource and concurrency semantics, then [Gateway plane](/guide/gateway) for protocol-native requests.

## 7. Stop the local stack

Stop the server with `Ctrl+C`, then:

```bash
docker compose -f dev/compose.yml down
```

To stop the services and remove disposable PostgreSQL and Redis volumes:

```bash
docker compose -f dev/compose.yml down --volumes
```

`make dev-reset` is different: it deletes the volumes and immediately starts clean services again.
