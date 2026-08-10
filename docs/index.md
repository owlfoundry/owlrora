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
  - title: Planned — Routing
    details: Product direction for a provider-neutral gateway boundary across models, providers, and compatible AI APIs.
  - title: Planned — Observability
    details: Product direction for structured usage, token, cost, latency, outcome, and routing evidence.
  - title: Planned — Reliable
    details: Product direction for retries, fallbacks, circuit breaking, and rate limits at the gateway boundary.
  - title: Planned — AI
    details: Product direction for protocol-native Anthropic, OpenAI, Gemini, and Codex Responses traffic.
---

::: warning Current status
OwlRora is currently at the runnable-foundation and product-design stage. The LLM gateway and management capabilities described here are product direction, not shipped behavior. The current `owlrora-server` embeds the frontend shell and exposes `GET /health`; the separate `owlrora` CLI currently provides help, version, and bounded checksum-verified self-update.
:::

## Target product

OwlRora is designed as a complete multi-tenant LLM gateway for Anthropic Messages, OpenAI Chat Completions, OpenAI Responses, Google Gemini, and a dedicated Codex subscription Responses transport.

OwlRora will own routing, usage accounting, observability, reliability policy, organization authorization, encrypted upstream credentials, scoped management API keys, and separate LLM-only gateway keys. Identity remains pluggable: OwlAuth can be integrated, a trusted external JWT can represent a local user, or a system administrator can provision users and organizations directly. A high-entropy environment management key authenticates the built-in API-key-only `seed_admin` user, which may operate directly or promote an existing local user. The independently released CLI package will contain the official `owlrora` management client and local stdio MCP mode, both using only the public management APIs.

[Read the product overview →](/overview)
