#!/usr/bin/env bash
set -euo pipefail

image="${1:?usage: smoke-server-image.sh <image>}"
version_output="$(docker run --rm "$image" --version)"
grep --quiet --extended-regexp '^owlrora-server [0-9A-Za-z.+-]+$' <<<"$version_output"

suffix="$$-$RANDOM"
network="owlrora-smoke-$suffix"
postgres="owlrora-smoke-postgres-$suffix"
server="owlrora-smoke-server-$suffix"

cleanup() {
  docker rm --force "$server" "$postgres" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker network create "$network" >/dev/null
docker run --detach \
  --name "$postgres" \
  --network "$network" \
  --network-alias postgres \
  --env POSTGRES_DB=owlrora \
  --env POSTGRES_USER=owlrora \
  --env POSTGRES_PASSWORD=owlrora_smoke \
  postgres:17-bookworm >/dev/null

for _ in $(seq 1 30); do
  if docker exec \
    --env PGPASSWORD=owlrora_smoke \
    "$postgres" \
    psql --host=127.0.0.1 --username=owlrora --dbname=owlrora \
      --no-psqlrc --set=ON_ERROR_STOP=1 --command='SELECT 1' \
      >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
if ! docker exec \
  --env PGPASSWORD=owlrora_smoke \
  "$postgres" \
  psql --host=127.0.0.1 --username=owlrora --dbname=owlrora \
    --no-psqlrc --set=ON_ERROR_STOP=1 --command='SELECT 1' \
    >/dev/null 2>&1; then
  docker logs "$postgres" >&2
  exit 1
fi

docker run --detach \
  --name "$server" \
  --network "$network" \
  --publish 127.0.0.1::8080 \
  --env OWLRORA_DATABASE_URL=postgresql://owlrora:owlrora_smoke@postgres:5432/owlrora \
  --env OWLRORA_PUBLIC_ORIGIN=http://127.0.0.1:8080 \
  --env OWLRORA_SEED_ADMIN_API_KEY=owlrora_mgmt_v1.CQkJCQkJCQkJCQkJCQkJCQ.CgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgo \
  --env OWLRORA_SECRET_ROOT=CwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCws \
  "$image" >/dev/null

address="$(docker port "$server" 8080/tcp)"
port="${address##*:}"

for _ in $(seq 1 30); do
  if health="$(curl --fail --silent --show-error "http://127.0.0.1:${port}/health" 2>/dev/null)"; then
    test "$health" = "ok"
    ready="$(curl --fail --silent --show-error "http://127.0.0.1:${port}/ready")"
    grep --quiet '"status":"ready"' <<<"$ready"
    page="$(curl --fail --silent --show-error "http://127.0.0.1:${port}/")"
    grep --quiet '<title>OwlRora</title>' <<<"$page"
    exit 0
  fi
  sleep 1
done

docker logs "$server" >&2
docker logs "$postgres" >&2
exit 1
