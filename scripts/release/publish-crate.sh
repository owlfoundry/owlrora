#!/usr/bin/env bash
set -euo pipefail

manifest="${1:-}"
expected_version="${2:-}"
if [[ -z "$manifest" || ! -f "$manifest" || -z "$expected_version" ]]; then
  printf 'usage: %s <Cargo.toml> <expected-release-version>\n' "$0" >&2
  exit 2
fi

read -r package version < <(
  awk '
    /^\[package\]$/ { in_package = 1; next }
    /^\[/ { in_package = 0 }
    in_package && /^name = / {
      name = $0
      sub(/^[^"]*"/, "", name)
      sub(/".*$/, "", name)
    }
    in_package && /^version = / {
      version = $0
      sub(/^[^"]*"/, "", version)
      sub(/".*$/, "", version)
    }
    END { print name, version }
  ' "$manifest"
)
if [[ -z "$package" || "$version" != "$expected_version" || "$version" == "0.0.0-dev" ]]; then
  printf 'refusing to publish %s at unexpected version %s\n' "${package:-<unknown>}" "${version:-<unknown>}" >&2
  exit 1
fi

cargo package --locked --allow-dirty --manifest-path "$manifest"
archive="target/package/${package}-${version}.crate"
metadata="$(mktemp)"
trap 'rm -f "$metadata"' EXIT
status="$(curl --silent --show-error \
  --user-agent 'owlrora-release (https://github.com/owlfoundry/owlrora)' \
  --output "$metadata" --write-out '%{http_code}' \
  "https://crates.io/api/v1/crates/$package/$version")"

case "$status" in
  200)
    local_checksum="$(sha256sum "$archive" | awk '{print $1}')"
    published_checksum="$(python3 -c 'import json, sys; print(json.load(sys.stdin)["version"]["checksum"])' < "$metadata")"
    if [[ "$local_checksum" != "$published_checksum" ]]; then
      printf 'published crate checksum does not match the current source package\n' >&2
      exit 1
    fi
    printf '%s %s is already published with the expected checksum\n' "$package" "$version"
    ;;
  404)
    : "${CARGO_REGISTRY_TOKEN:?CARGO_REGISTRY_TOKEN is required}"
    cargo publish --locked --allow-dirty --manifest-path "$manifest"
    ;;
  *)
    printf 'crates.io returned HTTP %s while checking %s %s\n' "$status" "$package" "$version" >&2
    exit 1
    ;;
esac
