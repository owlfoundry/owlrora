# Local development infrastructure

`dev/compose.yml` runs the disposable infrastructure used by local OwlRora development:

- PostgreSQL 17 on `127.0.0.1:55432`
- Redis 7.4 on `127.0.0.1:56379`

Both services bind to loopback by default. PostgreSQL uses a named volume; Redis is disposable coordination state.

From the repository root:

```bash
make install
cp .env.example .env
make dev
```

`make dev` validates the local environment, rebuilds embedded web assets, starts and waits for healthy PostgreSQL and Redis containers, then runs OwlRora in the foreground. The infrastructure can also be managed independently:

```bash
make dev-up
make dev-status
make dev-logs
make dev-postgres
make dev-redis
make dev-down
```

`make dev-reset` removes the containers and PostgreSQL volume before starting healthy empty services. It intentionally deletes local development data.

Optional Compose overrides can be placed in `dev/.env`:

```bash
cp dev/.env.example dev/.env
```

Keep the root `OWLRORA_DATABASE_URL` synchronized with any PostgreSQL host, port, database, user, or password override. Changing the initialization database or credentials does not update an existing PostgreSQL volume; use `make dev-reset` when that local data may be deleted and recreated. Redis starts with the development stack but is not consumed by the current server until the Redis coordination adapter is implemented.
