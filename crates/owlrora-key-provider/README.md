# OwlRora key-provider SPI

`owlrora-key-provider` is the small provider-neutral configuration-secret custody boundary for OwlRora.

It defines bounded canonical protection context values, redacted zeroizing plaintext/envelope wrappers, classified errors, and object-safe asynchronous seal/open capabilities. Third-party implementations are statically composed into a custom OwlRora server binary.

This crate intentionally contains no server policy, persistence, HTTP contracts, configuration parser, vendor SDK, or runtime plugin loader. The official server's bundled environment-root encryption is implemented directly by `owlrora-server`, not as a registered provider.
