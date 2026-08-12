# OwlRora CLI

`owlrora-cli` installs the `owlrora` command-line client for [OwlRora](https://github.com/owlfoundry/owlrora).

The CLI provides generated typed commands for OwlRora's public Management HTTP API, local management profiles, a bounded stdio MCP adapter, structured JSON or table output, and checksum-verified native self-update. It does not link or launch the server.

```bash
owlrora --version
owlrora --server-url https://owlrora.example \
  --key-env OWLRORA_MANAGEMENT_API_KEY me get
owlrora mcp --toolset read
owlrora update --dry-run
```

Management commands preserve ETag preconditions, idempotency keys, tenant qualification, one-time-secret handling, and outcome-unknown recovery semantics. The MCP adapter exposes the same generated operation catalog and is read-only by default; write, secret, sensitive-result, and full-access surfaces require explicit startup gates.

On Unix, profile and key files must be regular files owned by the current effective user with no group or world permissions. Reads reject symlinks and are bounded; profile saves use restricted temporary files, durable flushes, and atomic replacement. Platforms without equivalent owner, ACL, and reparse-point validation fail closed for profile and key files. On those platforms, use explicit server options with an environment-variable or redirected-stdin key source.

A specific version may be selected with `--version`; prereleases are explicit and build metadata is rejected. `--force` permits an intentional reinstall or downgrade. The updater selects only stable `cli-v*` releases by default, restricts requests and redirects to GitHub HTTPS origins, downloads the native archive and `SHA256SUMS`, enforces bounded response sizes, verifies the exact archive checksum and single-file inventory, and then performs a transaction-locked cross-platform replacement of the exact running path. The checksum shares the GitHub Release trust boundary with the archive; it detects corruption and asset mismatch but is not an independent release signature.

## License

[BSD 3-Clause](LICENSE).
