---
layout: home

title: OwlRora
titleTemplate: Routing and Observability for Reliable AI

hero:
  name: OwlRora
  text: Routing and Observability for Reliable AI
  tagline: Route Once. Reach All.
  actions:
    - theme: brand
      text: Get started
      link: /guide/getting-started
    - theme: alt
      text: Deployment guide
      link: /deployment/
    - theme: alt
      text: Implementation status
      link: /reference/implementation-status

features:
  - title: Protocol-native gateway
    details: Preserve OpenAI, Anthropic, and Gemini request semantics while routing to compatible upstream deployments.
  - title: Policy-driven reliability
    details: Apply target selection, failover, retry, circuit, health, stickiness, timeout, budget, rate, and concurrency policy.
  - title: Multi-tenant management
    details: Keep deployment and organization authority explicit across users, JWT issuers, Management API keys, Gateway API keys, BYOK resources, and grants.
  - title: Self-hosted modular monolith
    details: Run one Rust server with an embedded React console, PostgreSQL durable state, Redis coordination, and no hidden control-plane service.
---

## Current delivery boundary

::: warning Release status
The latest published server release is **server-v0.0.3**. It contains the identity and management foundation, but not the Gateway plane described throughout the source-status sections of this site.

The repository `main` branch at and after commit `da26113` contains the implemented Phase 2 Gateway, management, CLI/MCP, and Console work. That source state has passed repository CI and real PostgreSQL, Redis, HTTP, TLS, streaming, and WebSocket tests, but it has not yet been published under a new server or CLI release tag.
:::

OwlRora's normative target architecture lives under [`spec/`](https://github.com/owlfoundry/owlrora/tree/main/spec). The target specification is **not yet complete as a delivered product**. See [Implementation status](/reference/implementation-status) for the evidence-based boundary between released capability, implemented-but-unreleased source, and remaining target work.

## Start with the right path

- Evaluate the current source tree: [Getting started](/guide/getting-started)
- Plan a production topology: [Deployment](/deployment/)
- Configure every server setting: [Configuration](/deployment/configuration)
- Operate upgrades, backups, and recovery: [Production operations](/deployment/operations)
- Understand trust and secret boundaries: [Security model](/reference/security)
