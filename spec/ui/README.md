# Console specifications

This directory defines the normative target information architecture and browser-routing contract for the embedded OwlRora console.

The console follows a GitLab-like mental model:

- a **global administration area** at `/admin` for deployment-wide users, organizations, upstream catalog, policy, operations, and audit;
- an **organization workspace** at `/organizations/{organization_id}` for members, organization Management/Gateway API keys, key policy, BYOK credentials/deployments, mixed-origin routes, Gateway-key/BYOK budgets, the visible system-provider allocation, usage, audit, and settings;
- a small **personal area** for user identity, memberships, and sessions, never personal API-key ownership;
- one sign-in entry that supports configured external identity providers and scoped management API keys, including the deployment seed-administrator key.

These documents refine the console boundary in [`../10-http-surfaces-and-web-console.md`](../10-http-surfaces-and-web-console.md). They do not redefine domain authority or API behavior in specifications 02, 03, and 10.

## Documents

| Document | Scope |
| --- | --- |
| [`01-console-information-architecture.md`](01-console-information-architecture.md) | navigation model, page hierarchy, principals, states, responsive behavior, and safety conventions |
| [`02-console-routes-and-workflows.md`](02-console-routes-and-workflows.md) | browser paths, route guards, API relationships, and primary end-to-end workflows |
| [`03-console-visual-direction.md`](03-console-visual-direction.md) | visual system, layout rules, responsive behavior, and reference mockups |

## Interpretation rules

- Paths in this directory are **browser routes** unless explicitly labeled as management API paths.
- Browser guards improve navigation and prevent accidental disclosure, but the server authorizer remains the security boundary.
- Route parameters use opaque stable IDs for authority. Mutable names and slugs are display and search values only.
- A resource editor uses the latest detail response `ETag` and follows the uniform `If-Match` conflict workflow.
- The console never stores a Management API key, Gateway API key, BYOK/provider secret, OAuth token, or one-time secret in a browser URL, local storage, session storage, analytics event, or error report.
- Planned pages become visible only when their backing capability is implemented; target information architecture does not imply current availability.
