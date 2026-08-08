#!/usr/bin/env bash
set -euo pipefail

image="${1:?usage: smoke-server-image.sh <image>}"
container="$(docker run --detach --publish 127.0.0.1::8080 "$image")"

cleanup() {
  docker rm --force "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT

address="$(docker port "$container" 8080/tcp)"
port="${address##*:}"

for _ in $(seq 1 30); do
  if health="$(curl --fail --silent --show-error "http://127.0.0.1:${port}/health" 2>/dev/null)"; then
    test "$health" = "ok"
    page="$(curl --fail --silent --show-error "http://127.0.0.1:${port}/")"
    grep --quiet '<title>OwlRora</title>' <<<"$page"
    exit 0
  fi
  sleep 1
done

docker logs "$container" >&2
exit 1
