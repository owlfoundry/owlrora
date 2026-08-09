#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repository_root"

package_version() {
  local manifest="$1"
  sed -n 's/^version = "\([^"]*\)"$/\1/p' "$manifest" | head -n 1
}

key_provider_version="$(package_version crates/owlrora-key-provider/Cargo.toml)"
server_version="$(package_version crates/owlrora-server/Cargo.toml)"
test "$key_provider_version" = "$server_version"

key_provider_archive="target/package/owlrora-key-provider-${key_provider_version}.crate"
server_archive="target/package/owlrora-server-${server_version}.crate"
work_directory="$(mktemp -d "${TMPDIR:-/tmp}/owlrora-package.XXXXXX")"
cleanup() {
  rm -rf "$work_directory"
}
trap cleanup EXIT

rm -f "$key_provider_archive" "$server_archive"
cargo package \
  --manifest-path crates/owlrora-key-provider/Cargo.toml \
  --locked --allow-dirty --no-verify
cargo package \
  --manifest-path crates/owlrora-server/Cargo.toml \
  --locked --allow-dirty --no-verify \
  --config 'patch.crates-io.owlrora-key-provider.path="crates/owlrora-key-provider"'

key_provider_files="$(tar -tzf "$key_provider_archive" | sed 's#^[^/]*/##')"
grep -qx LICENSE <<< "$key_provider_files"
grep -qx README.md <<< "$key_provider_files"
grep -qx src/lib.rs <<< "$key_provider_files"

server_files="$(tar -tzf "$server_archive" | sed 's#^[^/]*/##')"
grep -qx LICENSE <<< "$server_files"
grep -qx README.md <<< "$server_files"
grep -qx src/main.rs <<< "$server_files"
grep -qx web/dist/index.html <<< "$server_files"
grep -q '^web/dist/assets/.*\.css$' <<< "$server_files"
grep -q '^web/dist/assets/.*\.js$' <<< "$server_files"

tar -xzf "$key_provider_archive" -C "$work_directory"
tar -xzf "$server_archive" -C "$work_directory"
cat > "$work_directory/Cargo.toml" <<EOF
[workspace]
members = ["owlrora-server-${server_version}"]
resolver = "3"

[patch.crates-io]
owlrora-key-provider = { path = "owlrora-key-provider-${key_provider_version}" }
EOF

host_target="$(rustc -vV | sed -n 's/^host: //p')"
test -n "$host_target"
cargo fetch --locked --target "$host_target"
CARGO_NET_OFFLINE=true cargo generate-lockfile \
  --manifest-path "$work_directory/Cargo.toml"
CARGO_NET_OFFLINE=true cargo build \
  --manifest-path "$work_directory/Cargo.toml" \
  --package owlrora-server \
  --locked

packaged_binary="$work_directory/target/debug/owlrora"
test "$("$packaged_binary" --version)" = "owlrora ${server_version}"

printf 'verified offline build and execution of packaged owlrora-server %s\n' "$server_version"
