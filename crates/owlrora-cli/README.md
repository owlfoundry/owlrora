# OwlRora CLI

`owlrora-cli` installs the `owlrora` command-line client for [OwlRora](https://github.com/owlfoundry/owlrora).

The current foundation implements checksum-verified self-update from versioned `cli-v<semver>` GitHub Releases. Management API commands and the local stdio MCP adapter remain planned and will use only OwlRora's public Management HTTP API; the CLI does not link or launch the server.

```bash
owlrora --version
owlrora update --dry-run
owlrora update
```

A specific version may be selected with `--version`; prereleases are explicit and build metadata is rejected. `--force` permits an intentional reinstall or downgrade. The updater selects only stable `cli-v*` releases by default, restricts requests and redirects to GitHub HTTPS origins, downloads the native archive and `SHA256SUMS`, enforces bounded response sizes, verifies the exact archive checksum and single-file inventory, and then performs a transaction-locked cross-platform replacement of the exact running path. The checksum shares the GitHub Release trust boundary with the archive; it detects corruption and asset mismatch but is not an independent release signature.

## License

[BSD 3-Clause](LICENSE).
