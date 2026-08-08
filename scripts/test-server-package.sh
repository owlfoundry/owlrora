#!/usr/bin/env bash
set -euo pipefail

version="$(sed -n 's/^version = "\([^"]*\)"$/\1/p' crates/owlrora-server/Cargo.toml | head -n 1)"
archive="target/package/owlrora-server-${version}.crate"
rm -f "$archive"

cargo package \
  --manifest-path crates/owlrora-server/Cargo.toml \
  --locked --allow-dirty

files="$(tar -tzf "$archive" | sed 's#^[^/]*/##')"
grep -qx README.md <<<"$files"
grep -qx web/dist/index.html <<<"$files"
grep -q '^web/dist/assets/.*\.css$' <<<"$files"
grep -q '^web/dist/assets/.*\.js$' <<<"$files"

printf 'verified packaged owlrora-server %s\n' "$version"
