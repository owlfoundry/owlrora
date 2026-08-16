# OwlRora key-provider SPI

`owlrora-key-provider` is the small provider-neutral configuration-secret custody boundary for OwlRora.

It defines bounded canonical protection context values, redacted zeroizing plaintext/envelope wrappers, classified errors, and object-safe asynchronous seal/open capabilities. Trusted implementations are statically registered through `owlrora_server::ServerBuilder`; OwlRora dispatches every persisted provider ID and format version to one exact registered sealer/opener without fallback.

OwlRora performs provider I/O outside PostgreSQL transactions. Concurrent or retried commands may seal the same exact context and plaintext more than once before one database write wins. Custom sealers must be safe to repeat and their envelopes must be independently discardable until persisted; they must not allocate an external durable resource that requires compensation when an unused envelope is discarded. Duplicate provider audit or billing events remain possible.

This crate intentionally contains no server policy, persistence, HTTP contracts, configuration parser, vendor SDK, or runtime plugin loader. The official server's bundled environment-root encryption is implemented directly by `owlrora-server`, not as a registered provider.
