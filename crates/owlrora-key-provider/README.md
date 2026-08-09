# OwlRora key-provider SPI

`owlrora-key-provider` is the small provider-neutral configuration-secret custody boundary for OwlRora.

It defines bounded canonical protection context values, redacted zeroizing plaintext/envelope wrappers, classified errors, and object-safe asynchronous seal/open capabilities. This is an initial prospective SPI foundation: the current runnable server does not yet expose provider registration or the planned high-level custom-composition builder, so implementations cannot yet be attached to the official foundation binary.

This crate intentionally contains no server policy, persistence, HTTP contracts, configuration parser, vendor SDK, or runtime plugin loader. The official server's bundled environment-root encryption is implemented directly by `owlrora-server`, not as a registered provider.
