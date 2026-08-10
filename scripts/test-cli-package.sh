#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repository_root"

package_version() {
  local manifest="$1"
  sed -n 's/^version = "\([^"]*\)"$/\1/p' "$manifest" | head -n 1
}

cli_version="$(package_version crates/owlrora-cli/Cargo.toml)"
cli_archive="target/package/owlrora-cli-${cli_version}.crate"
work_directory="$(mktemp -d "${TMPDIR:-/tmp}/owlrora-cli-package.XXXXXX")"
cleanup() {
  rm -rf "$work_directory"
}
trap cleanup EXIT

rm -f "$cli_archive"
cargo package \
  --manifest-path crates/owlrora-cli/Cargo.toml \
  --locked --allow-dirty --no-verify

cli_files="$(tar -tzf "$cli_archive" | sed 's#^[^/]*/##')"
grep -qx LICENSE <<< "$cli_files"
grep -qx README.md <<< "$cli_files"
grep -qx src/main.rs <<< "$cli_files"
grep -qx src/update.rs <<< "$cli_files"

tar -xzf "$cli_archive" -C "$work_directory"
cat > "$work_directory/Cargo.toml" <<EOF
[workspace]
members = ["owlrora-cli-${cli_version}"]
resolver = "3"
EOF

host_target="$(rustc -vV | sed -n 's/^host: //p')"
test -n "$host_target"
cargo fetch --locked --target "$host_target"
CARGO_NET_OFFLINE=true cargo generate-lockfile \
  --manifest-path "$work_directory/Cargo.toml"
CARGO_NET_OFFLINE=true cargo build \
  --manifest-path "$work_directory/Cargo.toml" \
  --package owlrora-cli \
  --locked

packaged_binary="$work_directory/target/debug/owlrora"
test "$("$packaged_binary" --version)" = "owlrora ${cli_version}"
"$packaged_binary" update \
  --version "$cli_version" \
  --dry-run \
  --force \
  | grep -qx 'status: dry-run'

printf 'verified offline build and execution of packaged owlrora-cli %s\n' "$cli_version"
