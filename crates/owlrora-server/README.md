# OwlRora Server

`owlrora-server` is the server library and source package for OwlRora — Routing and Observability for Reliable AI. It installs the `owlrora-server` executable and includes the production frontend assets required by the runnable server foundation.

OwlRora is planned as a self-hosted, multi-tenant LLM gateway for protocol-native model routing, usage observability, reliability policy, and complete system/organization administration.

This crate currently provides only the runnable server and embedded-frontend foundation. The gateway protocols, management surface, and custom custody provider registration/composition builder are not implemented yet. The independent `owlrora-cli` package installs the remote `owlrora` client; it does not depend on this crate or receive an in-process server path.
