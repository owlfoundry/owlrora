# CLI and MCP management clients

## 1. Product boundary

OwlRora ships an official command-line client and a local Model Context Protocol server for the complete management surface.

They are clients of the same versioned HTTP APIs used by the embedded console. They do not open PostgreSQL directly, call domain services in process, read server deployment secrets, bypass organization qualification, weaken `ETag` preconditions, or introduce a second authorization system.

The three management clients have one authority model:

```text
Console session | CLI management API key | MCP management API key
                              ↓
                    versioned management API
                              ↓
             authenticated user or resource-key principal
                              ↓
                  key/session ceiling + current policy
                              ↓
                     one typed authorizer and audit
```

"Full access" means that the CLI command inventory and MCP tool inventory can cover every management query and command. It does not mean that either client receives authority absent from its Management API key resource scope, current key policy, and any required deployment administrator grant.

The native LLM compatibility endpoints remain data-plane APIs. The management MCP does not duplicate arbitrary LLM invocation as tools and does not expose a generic HTTP-request tool.

## 2. Packaging and process model

The server and its remote management clients have independent package and executable boundaries:

```text
owlrora-server

owlrora profile ...
owlrora system ...
owlrora organization ...
owlrora me ...
owlrora update ...
owlrora mcp ...
```

The `owlrora-server` package installs `owlrora-server`, which starts the server roles directly without a `serve` subcommand. The independently published `owlrora-cli` package installs `owlrora`; its ordinary command families are bounded management API clients, `update` updates only this CLI executable, and `mcp` runs a local MCP server over standard input/output for an MCP host to launch as a child process.

`owlrora-cli` does not depend on or launch `owlrora-server`, contain server private state, or create another daemon, database schema, privileged sidecar, or network service. The typed HTTP client and stdio MCP adapter remain in the CLI package. Checked management-operation descriptors generate or validate both server contracts and committed client bindings without introducing an in-process privileged path; a shared crate is extracted only when real stable types make it simpler than generated package-local code. `cli-v<semver>` releases publish the `owlrora-cli` crate plus five platform archives and checksums. `server-v<semver>` releases create a GitHub Release and publish the server crate family plus one immutable versioned GHCR image. CI validates release inputs and the server image before tagging; release workflows only construct and publish artifacts. The official MCP mode does not listen on an unauthenticated TCP or HTTP socket.

## 3. Authentication profiles

A client profile contains only connection and credential-source configuration:

```text
ManagementProfile {
    name,
    server_url,
    management_api_key_source,
    tls_policy,
    default_output?,
}
```

The credential source may be a named environment variable, a permission-restricted file, or standard input for a one-shot invocation. The default environment variable is `OWLRORA_MANAGEMENT_API_KEY`. A raw key is not accepted as a normal command-line argument because process listings and shell history commonly expose arguments.

Profiles never contain gateway API keys, upstream provider credentials, external identity tokens, or the server's software-encryption root. TLS certificate verification is enabled by default; any development-only insecure override is explicit, conspicuous, and rejected for non-loopback targets unless the operator deliberately enables the documented unsafe mode.

A profile selects credentials, not authority. The server authenticates the Management API key on every request and reevaluates its deployment/organization key principal, status, scopes/capabilities, immutable resource scope, current key policy, and any required deployment administrator grant. The CLI and MCP never infer authorization from locally cached profile metadata.

## 4. CLI contract

### 4.1 Command inventory

The CLI mirrors the management API by stable resource families and explicit actions. Local profile, output, completion, `update`, and stdio-MCP lifecycle commands are client concerns rather than management operations and never receive server authority. Representative management commands are:

```text
owlrora system users list
owlrora system model-routes get <route_id>
owlrora system model-routes update <route_id> --from <file>
owlrora system management-api-keys create --from <file>
owlrora organization members list --organization <organization_id>
owlrora organization management-api-keys create --organization <organization_id> --from <file>
owlrora organization gateway-api-keys create --organization <organization_id> --from <file>
owlrora organization gateway-api-keys budget update --organization <organization_id> <gateway_api_key_id> --from <file>
owlrora organization gateway-api-keys limits update --organization <organization_id> <gateway_api_key_id> --from <file>
owlrora organization api-key-policy update --organization <organization_id> --from <file>
owlrora organization upstream-credentials replace-secret --organization <organization_id> <credential_id> --secret-stdin
owlrora organization model-deployments create --organization <organization_id> --from <file>
owlrora organization provider-budgets system update --organization <organization_id> --from <file>
owlrora organization provider-budgets byok update --organization <organization_id> --from <file>
owlrora system upstream-credentials replace-secret <credential_id> --secret-stdin
```

Commands use opaque IDs for authority and may resolve display names only through an explicit query followed by unambiguous user selection. They never treat a mutable name or slug as a hidden authorization key.

The client supports bounded table output for humans and stable JSON output for automation. JSON mode writes only the HTTP response contract plus documented client metadata; progress and diagnostics use standard error. Secret-bearing responses are never mixed into progress logs.

### 4.2 Concurrency and retries

For every ordinary update, the CLI binds the candidate representation to the `ETag` returned by the same authoritative `GET` on which that candidate was based and sends that exact value as `If-Match`. An interactive fetch/edit/save flow performs one `GET`, retains its representation and tag while editing, and submits the edited candidate with that retained tag. A `--from <file>` flow requires provenance metadata captured with the source representation, either embedded in the exported document, in a protected sidecar, or supplied explicitly as `--etag`; it MUST NOT fetch a fresh tag at submission time for a pre-existing candidate file. A `412` stops and reports the conflict without loading a new tag or replaying the stale candidate.

Only explicit delta-style flags may use a fetch-before-update flow: the CLI fetches the latest representation and tag, applies the requested bounded delta to that exact representation, and submits the resulting candidate with that same tag. It does not reinterpret a complete input file as a delta. This prevents an old complete candidate from restoring targets, grants, or other entries deleted after the candidate was read.

Safe idempotent queries may retry bounded transient failures. A command retries only when the API contract declares the operation retry-safe and, where required, uses an `Idempotency-Key`. One-time secret creation/rotation, Codex transitions, destructive recovery, and ambiguous commands are never replayed automatically.

### 4.3 Secret input and output

Write-only secret inputs use standard input or an explicit protected file source, not ordinary flags. One-time secret results are written exactly once to the selected destination. Human output warns before printing to a terminal; machine output never adds the value to logs, profile state, shell completion, diagnostics, or retry storage.

The CLI does not offer a command to recover an already disclosed management key, gateway key, provider secret, OAuth token, or seed-administrator key.

### 4.4 Native self-update

`owlrora update` updates only the independently installed `owlrora` CLI; it never updates, restarts, or replaces `owlrora-server` or its container. Its public controls are:

```text
owlrora update [--version <SEMVER>] [--dry-run] [--force] [--install-dir <DIRECTORY>]
```

Without `--version`, the client queries a bounded number of GitHub Release pages and selects the highest canonical stable SemVer whose tag is exactly `cli-v<semver>`, whose release is neither draft nor prerelease, and whose SemVer has no prerelease identifiers or build metadata. It ignores `server-v*` and every unrelated tag. An explicit version accepts plain SemVer, `v<semver>`, or `cli-v<semver>` and resolves to that exact versioned CLI release, including an explicitly selected prerelease; build metadata is rejected because it does not define SemVer precedence. A same-version update is a successful no-op; a reinstall or downgrade requires `--force`. A dry run resolves the exact release, target archive, and destination but downloads no release asset and changes no filesystem state.

The supported native asset set is closed: GNU Linux x86_64/aarch64 and macOS x86_64/aarch64 use `.tar.gz`; Windows MSVC x86_64 uses `.zip`. Archive names are exactly `owlrora-cli-<version>-<target>.<extension>`. The release repository is compiled in rather than selected by environment or configuration. Initial requests and every redirect are restricted to bounded GitHub/GitHubusercontent HTTPS origins with Rustls certificate verification, connection/request timeouts, bounded response sizes, and a non-secret client user agent. `SHA256SUMS` must contain exactly one syntactically valid entry for the selected archive. The downloaded bytes must match that digest before parsing. The checksum and archive share the GitHub Release trust boundary, so this is corruption and asset-mismatch detection, not an independent signature or protection from compromised release authority.

A valid archive contains exactly one top-level regular file named `owlrora` or `owlrora.exe`. Absolute, nested, traversal, link, device, duplicate, directory, and extra entries fail before installation; expanded binary size is bounded, and ZIP entry cardinality is checked independently of filename-index deduplication. A non-dry-run updater acquires a non-blocking installation-directory lock before release discovery and holds it through download, verification, and replacement. It stages and syncs the verified binary in that same directory, restores executable permissions as applicable, and uses a cross-platform self-replacement primitive against the exact running executable path even when the executable was renamed. An explicit alternate install directory replaces only its `owlrora` destination with same-directory staging and rollback on platforms that cannot overwrite in place; rollback failures retain and report the backup path, while post-success cleanup failures do not misreport the replacement as failed. No background check or automatic update mutates the installation.

## 5. MCP contract

### 5.1 Transport and lifecycle

`owlrora mcp` implements the supported MCP protocol over stdio. Standard output carries only protocol frames; diagnostics use standard error with redaction. The process uses one selected management profile and exits when its parent closes the transport or its bounded shutdown completes.

A remote MCP deployment, HTTP/SSE transport, multi-user credential broker, or hosted agent service is outside the official server boundary. Operators may build such systems as ordinary management API clients and must own their authentication, tenant isolation, and network exposure.

### 5.2 Typed toolsets

MCP tools are typed projections of checked management API operations. Tools use stable names, bounded schemas, opaque resource IDs, and the same response/error semantics as the API. The official server exposes no generic `request`, arbitrary URL, SQL, shell, or raw HTTP tool.

The catalog is grouped into toolsets so an MCP host need not load one massive flat inventory:

| Toolset | Management API key scope ceiling | Examples |
| --- | --- | --- |
| `read` | `management:read` | list/get/status/usage/audit queries |
| `write` | `management:write` | create and ordinary update commands |
| `secrets` | `management:secrets` plus the required write scope | key creation/rotation and protected-secret replacement |
| `operations` | `management:operations` plus read/write as required | typed `/api/v1/system/operations/**` diagnostics and recovery commands |
| `authority` | `management:authority` plus write | administrator grants and other explicit authority transitions |

The default MCP launch exposes the `read` toolset. Explicit toolset selection plus `--allow-write`, `--allow-secret-inputs`, and `--allow-sensitive-results` add the corresponding bounded capabilities; enabling the `secrets` toolset alone does not silently permit secret input or one-time bearer output. `--full-access` is a deliberate shorthand that exposes every typed management tool and permits writes, secret inputs, and one-time sensitive results. It prints a startup warning to standard error and does not change server-side authority.

Tool visibility is usability and context control, not a security boundary. Even a tool visible under `--full-access` fails unless the current Management API key resource principal, key policy/grant, and resource state authorize that exact request. An organization key cannot invoke system tools, and tool filtering never substitutes for that server check.

### 5.3 Approval and annotations

Every tool declares accurate MCP behavior annotations where supported:

- queries are read-only;
- updates and lifecycle commands are mutating;
- authority changes, recovery actions, and disable/revoke operations are destructive or high impact as applicable;
- tools that accept protected secret material or may return a one-time bearer are marked sensitive; one-time results are also non-repeatable.

The MCP host should require human approval for mutating, authority-changing, destructive, or sensitive-result tools. OwlRora does not treat host annotations or approval UI as authorization evidence; the server remains authoritative.

Protected secret material may enter an MCP request only when the tool is enabled by `--allow-secret-inputs` or `--full-access`. A one-time secret result may enter the MCP response only when the tool is enabled by `--allow-sensitive-results` or `--full-access`. It is returned once, is not cached or replayed by OwlRora, and is absent from subsequent queries. Operators must assume that the MCP host or model transcript can retain any secret deliberately supplied as tool input or returned as tool output.

### 5.4 ETag and ambiguous outcomes

An MCP update tool requires the opaque `etag` obtained from the corresponding get tool and sends it as `If-Match`. A `412` returns a structured conflict to the host; the MCP adapter never silently loads a new tag and resubmits the model's stale candidate.

Non-idempotent and one-time-secret tools are issued at most once per invocation. An interrupted or ambiguous result is reported as unknown and is not retried. Follow-up uses safe metadata queries and a deliberate new command, matching the HTTP contract.

## 6. API descriptor and compatibility

Management HTTP schemas, OpenAPI, CLI commands, and MCP tools derive from one checked operation descriptor. Each operation records at least:

- stable operation ID and resource family;
- query or command classification;
- required management scopes;
- system or organization qualification;
- request/response schema and bounded pagination;
- `ETag`/`If-Match` behavior;
- idempotency and retry classification;
- secret input, one-time sensitive result, and redaction classification;
- high-impact/destructive and approval metadata.

Generation may produce adapter registration code and tests, but handwritten domain-specific presentation is allowed. CI rejects an API operation that lacks the metadata needed to classify its CLI and MCP behavior. A new API version may coexist during a documented compatibility window; clients do not guess renamed fields or command meaning.

## 7. Audit and observability

Every accepted management command records the authenticated actor, exact typed capability, target scope/resource, outcome, and request ID under the ordinary durable audit contract. Ordinary management queries, audit queries, and protected diagnostic `GET`s are side-effect-free and do not create a durable per-request audit row; they produce only bounded request metadata and ordinary telemetry, avoiding audit-query recursion. Accepted protected recovery/mutation commands are audited like every other command.

For durable Management keys, command audit records use the safe key resource ID, deployment/organization resource scope, non-secret secret-version row ID, and `management_api_key` principal; key-derived sessions retain those underlying safe fields, session identity, and `management_api_key_session`. `created_by_principal` remains creation metadata and is never substituted as the current actor. The seed key is the exception because it has no durable key/version row: direct or session-derived seed commands record only the fixed seed-key identity, `seed_admin`, and direct/session origin. They MUST NEVER record or emit `seed_admin_key_version_id`. External sessions and JWTs retain their corresponding safe authentication-origin evidence.

Official clients send bounded client metadata identifying `cli` or `mcp` plus their version. This metadata is useful for audit filtering but is untrusted attribution and never changes authorization. Raw keys, request authorization headers, secret inputs, one-time results, and MCP protocol bodies are excluded from logs and telemetry.

Local CLI/MCP diagnostics include request IDs and safe error classes. They do not duplicate response bodies known to contain sensitive material.

## 8. Required tests

Contract and end-to-end tests cover:

- every management operation has a classified CLI command and MCP tool or an explicit documented exclusion;
- management keys and gateway keys are rejected on the opposite surface;
- scope/capability, immutable deployment/organization resource scope, current key policy/grant, disablement, expiry, and rotation intersections;
- create/update attempts cannot mint a caller-missing scope, widen an exact boundary, or self-expand the authenticating key;
- a narrow key cannot rotate, re-enable/reactivate, extend expiry, or restore/extend overlap on a wider sibling key, while authorized one-way restriction remains possible;
- key-derived sessions apply later narrowing but do not inherit later key expansion;
- direct JWT/OIDC management access derives an explicit concrete management scope/organization ceiling, rejects missing ceilings, and never interprets coarse `management:access` as full scope;
- OIDC-derived sessions apply issuer/user scope/capability narrowing and disablement but do not inherit later ceiling expansion without re-login;
- seed administrator, granted local-user administrators, and explicitly granted deployment Management-key principals; organization keys remain unable to reach system operations;
- CLI complete-file updates require candidate-bound ETags, never submission-time fresh tags; interactive and explicit delta flows retain the exact source-GET tag;
- CLI and MCP `ETag`, `412`, `428`, idempotency, timeout, and ambiguous-result behavior;
- stdio protocol purity and stderr redaction;
- default read-only, bounded toolset, write/secret-input/sensitive-result opt-ins, and full-access launch modes;
- one-time secret non-replay and absence from logs, audit, telemetry, profiles, and diagnostics;
- protected diagnostics and recovery use only typed `/api/v1/system/operations/**` routes with operation-scope, user-authority, and operator-network enforcement; no general status query or overview aggregation bypasses that family;
- management queries create no durable audit rows, while every accepted command does and retains safe credential attribution;
- organization BYOK secret commands require write+secrets+typed organization capability, accept no organization endpoint URL mutation, and retain exact tenant qualification;
- Gateway-key admission/audit/usage never fabricates its creator as a user, while creator removal does not revoke the organization resource;
- every Gateway-key create requires a non-empty stable route-ID allowlist and finite overall budget; route authorization never accepts provider prefixes, upstream model strings, provider allowlists, or an implicit all-future-routes marker;
- system-provider origin-budget updates require system authority, BYOK origin-budget updates require organization budget authority, both preserve `enforce | record_only`, and every actual mixed-route attempt is attributed to the target-derived origin while also charging the key overall budget;
- direct JWT LLM usage creates no fabricated Gateway-key, origin-budget, rate, or concurrency enforcement identity;
- packaged execution using only public HTTP APIs, including against a different OwlRora node from the one that launched the client;
- CLI update release selection rejects drafts, mislabeled prereleases, build metadata, noncanonical and non-CLI tags, and unbounded pagination;
- update requests start at the compiled-in repository, redirect only among the allowed GitHub HTTPS hosts, enforce timeout/body limits, and require one exact archive checksum entry while rejecting malformed, missing, duplicate, or mismatched values;
- tar/zip fixtures reject absolute and traversal paths, nested entries, links, non-files, duplicate central-directory entries, oversized expansion, and extra entries while accepting the exact one-file platform inventory;
- dry-run filesystem purity, same-version, force, downgrade, full-transaction install locking, non-running destination replacement, packaged `--version`, exact renamed running paths, rollback failures, and Unix/Windows child-process self-replacement behavior.
