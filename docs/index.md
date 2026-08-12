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
      text: Product Overview
      link: /overview
    - theme: alt
      text: View on GitHub
      link: https://github.com/owlfoundry/owlrora

features:
  - title: Available — Management plane
    details: PostgreSQL-backed identity, tenancy, scoped management keys and sessions, external issuers, and an embedded console.
  - title: Available — Automation
    details: Generated typed CLI commands and a bounded stdio MCP adapter over the public management API.
  - title: Planned — Gateway data plane
    details: Product direction for protocol-native routing, reliability, budgets, usage, and observability.
  - title: Available — Secure foundations
    details: Explicit secret-root encryption, non-recoverable key digests, typed authorization, ETags, audit evidence, and immutable runtime publication.
---

::: warning Current status
OwlRora currently ships its identity and management plane, embedded console, generated CLI/MCP clients, and secure PostgreSQL-backed runtime publication. The LLM ingress, upstream routing, Redis allowance coordination, and usage/observability data plane described here remain product direction.
:::

## Target product

OwlRora is designed as a complete multi-tenant LLM gateway for Anthropic Messages, OpenAI Chat Completions, OpenAI Responses, Google Gemini, and a dedicated Codex subscription Responses transport.

OwlRora will own routing, usage accounting, observability, reliability policy, organization authorization, encrypted upstream credentials, scoped management API keys, and separate LLM-only gateway keys. Identity remains pluggable: OwlAuth can be integrated, a trusted external JWT can represent a local user, or a system administrator can provision users and organizations directly. A high-entropy environment management key authenticates the built-in API-key-only `seed_admin` user, which may operate directly or promote an existing local user. The independently released CLI package will contain the official `owlrora` management client and local stdio MCP mode, both using only the public management APIs.

[Read the product overview →](/overview)
