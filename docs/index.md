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

::: warning Source and release boundary
This site follows repository `main` and can describe capabilities newer than a selected binary. Before deployment, pin exact server and CLI releases, verify their source and release notes, and pin the server image by immutable digest. Do not interpret a release as completion of the target specification.
:::

OwlRora's normative target architecture lives under [`spec/`](https://github.com/owlfoundry/owlrora/tree/main/spec). The target specification is **not yet complete as a delivered product**. See [Implementation status](/reference/implementation-status) for the evidence-based boundary between released capability, newer source revisions, and remaining target work.

## Start with the right path

- Evaluate the current source tree: [Getting started](/guide/getting-started)
- Plan a production topology: [Deployment](/deployment/)
- Configure every server setting: [Configuration](/deployment/configuration)
- Operate upgrades, backups, and recovery: [Production operations](/deployment/operations)
- Understand trust and secret boundaries: [Security model](/reference/security)
