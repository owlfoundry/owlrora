# Local development infrastructure

`dev/compose.yml` runs the disposable infrastructure used by local OwlRora development:

- PostgreSQL 17 on `127.0.0.1:55432`
- Redis 7.4 on `127.0.0.1:56379`

Both services bind to loopback by default. PostgreSQL uses a named volume. Redis holds coordination state; both are disposable in this development stack, but Redis is a required runtime dependency for every current non-`health-only` server profile.

From the repository root:

```bash
make install
cp .env.example .env
make dev
```

`make dev` validates the local environment, rebuilds embedded web assets, starts and waits for healthy PostgreSQL and Redis containers, then runs OwlRora in the foreground. The example config uses the `full` profile and includes the required database URL, Redis URL, public origin, test seed key, and test secret root. Replicas require no durable application identity.

Manage infrastructure independently:

```bash
make dev-up
make dev-status
make dev-logs
make dev-postgres
make dev-redis
make dev-down
```

`make dev-reset` removes containers and the PostgreSQL named volume before starting healthy empty services. It intentionally deletes local development state.

Optional Compose overrides:

```bash
cp dev/.env.example dev/.env
```

Keep root `.env` values synchronized with Compose overrides:

- `OWLRORA_DATABASE_URL`
- `OWLRORA_REDIS_URL`

Changing database initialization credentials does not update an existing PostgreSQL volume. Use `make dev-reset` only when deleting that local data is acceptable.

The fixed values in `.env.example` and `dev/.env.example` are public development credentials. Generate independent values and follow the [deployment guide](../docs/deployment/index.md) outside disposable local development.
