# CLI and MCP

The independently released `owlrora` executable is a stateless Management API client. It never embeds, launches, or imports the server. Typed CLI commands and local stdio MCP tools are generated from the same server operation descriptor.

::: warning Release boundary
Verify that the selected CLI command inventory matches the server release you operate. Build the CLI from the same source revision when evaluating unreleased server source.
:::

## Direct CLI use

By default the client reads:

- `OWLRORA_SERVER_URL`
- `OWLRORA_MANAGEMENT_API_KEY`

```bash
export OWLRORA_SERVER_URL=https://owlrora.example.com
read -rsp 'Management API key: ' OWLRORA_MANAGEMENT_API_KEY
echo
export OWLRORA_MANAGEMENT_API_KEY

owlrora --output json me get
```

Credential source options are explicit. Prefer environment, protected file, or stdin input; do not put bearer secrets directly in shell history.

```bash
owlrora --help
owlrora system --help
owlrora organization --help
```

## Profiles

Profiles store the server URL, output preference, and a reference to a credential source. They must not store plaintext key material inline.

```bash
owlrora profile set production \
  --profile-server-url https://owlrora.example.com \
  --profile-key-env OWLRORA_MANAGEMENT_API_KEY

owlrora profile use production
owlrora profile show production
```

Profile state is local to the CLI. Server authorization remains authoritative.

## Structured input and output

Generated commands support operation-specific flags and structured JSON input. For automation:

- use `--output json`;
- preserve `ETag` values exactly;
- supply `If-Match` for update commands;
- provide required idempotency keys;
- treat one-time secret output as sensitive and non-replayable.

The CLI does not expose a generic raw HTTP command and never guesses uncompiled operation names or fields. Its command inventory is embedded at build time; use a CLI built from a compatible server revision. An incompatible server may reject the request with a missing operation, validation error, or response-contract error.

## TLS safeguards

Plaintext or verification-disabled non-loopback targets are rejected by default. `--allow-insecure-non-loopback` is an explicit development escape hatch and should not be used in production.

The native updater keeps its GitHub repository and HTTPS redirect origins fixed, verifies the exact checksum and one-file archive inventory, and replaces the exact running executable under a transaction lock. The release checksum shares the GitHub Release trust boundary; it is not an independent signature.

## Local stdio MCP

Start MCP mode against the same profile:

```bash
owlrora --profile production mcp
```

MCP exposes typed tools grouped by the operation descriptor. It preserves:

- principal and organization context;
- operation scopes and authorization failures;
- `ETag` and `If-Match` requirements;
- idempotency requirements;
- one-time-secret annotations;
- sensitive and high-impact operation metadata;
- approval hints from the server contract.

The adapter communicates over local stdio and uses only public Management HTTP APIs. It is not a server plugin and does not bypass audit or tenant boundaries.

## Version compatibility

Use a CLI built from or released with a compatible operation descriptor. Before production automation:

```bash
owlrora --version
owlrora --profile production --output json me get
```

For source builds:

```bash
cargo run --locked -p owlrora-cli -- --help
```
