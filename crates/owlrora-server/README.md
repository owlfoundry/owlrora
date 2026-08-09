# OwlRora Server

`owlrora-server` is the server library and source package for the single `owlrora` executable — Routing and Observability for Reliable AI. The published crate includes production frontend assets; `owlrora serve` runs the current server foundation, while management CLI and stdio MCP modes remain planned.

OwlRora is planned as a self-hosted, multi-tenant LLM gateway for protocol-native model routing, usage observability, reliability policy, and complete system/organization administration.

This crate currently provides only the runnable server and embedded-frontend foundation. The gateway protocols, management clients, and custom custody provider registration/composition builder are not implemented yet.
