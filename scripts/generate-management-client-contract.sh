#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
cli_target="crates/owlrora-cli/src/management_operations.json"
console_target="apps/web/src/operation_authority.json"
cli_temporary="$(mktemp)"
console_raw="$(mktemp)"
console_temporary="$(mktemp)"
trap 'rm -f "$cli_temporary" "$console_raw" "$console_temporary"' EXIT

cargo run --quiet --locked --package owlrora-server --example export_management_contract > "$cli_temporary"
cargo run --quiet --locked --package owlrora-server --example export_console_authority > "$console_raw"
pnpm --filter @owlrora/web exec prettier --stdin-filepath src/operation_authority.json < "$console_raw" > "$console_temporary"

if [[ "${1:-}" == "--check" ]]; then
  stale=false
  if ! cmp --silent "$cli_temporary" "$cli_target"; then
    echo "management client contract is stale; run scripts/generate-management-client-contract.sh" >&2
    stale=true
  fi
  if ! cmp --silent "$console_temporary" "$console_target"; then
    echo "console authority projection is stale; run scripts/generate-management-client-contract.sh" >&2
    stale=true
  fi
  if [[ "$stale" == true ]]; then
    exit 1
  fi
else
  mv "$cli_temporary" "$cli_target"
  mv "$console_temporary" "$console_target"
  trap - EXIT
fi
