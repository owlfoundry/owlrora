import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import { OutcomeUnknownError, apiRequest, readCookie, type CurrentPrincipal } from "./api";
import { operationAllows, operationAuthority, type JsonSchema } from "./operation-authority";
import {
  candidateFromStates,
  commandIsNonRepeatable,
  deviceAuthorization,
  hasFieldStateChanges,
  optionalFieldPresenceLabel,
  resolveSchemaVariant,
  secretResult,
  type FieldStates,
} from "./schema-form";
import {
  CONSOLE_ROUTES,
  buildPath,
  defaultPath,
  guardAllows,
  isSafeReturnTo,
  matchRoute,
  routeHasCapability,
  routeOperationId,
} from "./routes";
import { OneTimeReveal, OutcomeUnknownState, SubmitBar } from "./ui";
import { hourInput } from "./usage-pages";

const seed: CurrentPrincipal = {
  principal: { kind: "seed_admin" },
  authentication_method: "management_api_key_session",
  effective_management_scopes: [
    "management:read",
    "management:write",
    "management:secrets",
    "management:operations",
    "management:authority",
  ],
  resource_scope: { kind: "deployment" },
  system_administrator: true,
  allowed_organizations: [],
  capabilities: [
    "system_administration",
    "read_organization",
    "update_organization",
    "read_members",
    "manage_members",
    "manage_owners",
    "read_management_keys",
    "create_management_keys",
    "manage_management_keys",
    "update_api_key_policy",
    "read_audit",
    "manage_identity",
    "manage_system_keys",
    "manage_system_organizations",
    "manage_system_users",
    "manage_administrators",
    "read_operations",
    "recover_operations",
  ],
};

const localUser: CurrentPrincipal = {
  principal: { kind: "local_user", user_id: "user-1" },
  authentication_method: "external_session",
  effective_management_scopes: ["management:read", "management:write"],
  resource_scope: { kind: "deployment" },
  system_administrator: false,
  allowed_organizations: [
    {
      organization_id: "org-1",
      name: "Example",
      access_reason: "membership",
      role: "owner",
      capabilities: [
        "read_organization",
        "update_organization",
        "read_members",
        "manage_members",
        "manage_owners",
        "read_management_keys",
        "create_management_keys",
        "manage_management_keys",
        "update_api_key_policy",
        "read_audit",
      ],
      management_key_self_service: null,
    },
  ],
  capabilities: [],
};

describe("console route contract", () => {
  it("registers every route exactly once", () => {
    expect(new Set(CONSOLE_ROUTES.map((route) => route.id)).size).toBe(CONSOLE_ROUTES.length);
    expect(new Set(CONSOLE_ROUTES.map((route) => route.path)).size).toBe(CONSOLE_ROUTES.length);
  });

  it("protects every Admin route with the system-administrator guard", () => {
    for (const route of CONSOLE_ROUTES.filter((candidate) => candidate.context === "admin")) {
      expect(route.guard, route.path).toBe("system_administrator");
    }
  });

  it("qualifies every organization route by an opaque organization ID", () => {
    for (const route of CONSOLE_ROUTES.filter(
      (candidate) => candidate.context === "organization",
    )) {
      expect(route.path, route.id).toContain("{organization_id}");
    }
  });

  it("matches reserved route words before detail parameters", () => {
    expect(matchRoute("/admin/users/new")?.route.id).toBe("admin-user-new");
    expect(matchRoute("/organizations/org-1/management-api-keys/new")?.route.id).toBe(
      "organization-management-key-new",
    );
    expect(matchRoute("/admin/identity/provisioning-policies/policy-1/edit")?.params).toEqual({
      policy_id: "policy-1",
    });
  });

  it("builds paths with encoded stable IDs", () => {
    expect(
      buildPath("/organizations/{organization_id}/members/{user_id}", {
        organization_id: "org/unsafe",
        user_id: "user 1",
      }),
    ).toBe("/organizations/org%2Funsafe/members/user%201");
  });

  it("enforces deterministic context selection and guards", () => {
    expect(defaultPath(seed)).toBe("/admin");
    expect(defaultPath(localUser)).toBe("/organizations/org-1");
    expect(
      guardAllows("organization_visible", localUser, {
        organization_id: "org-1",
      }),
    ).toBe(true);
    expect(
      guardAllows("organization_visible", localUser, {
        organization_id: "org-2",
      }),
    ).toBe(false);
    expect(
      guardAllows("organization_visible", seed, {
        organization_id: "org-2",
      }),
    ).toBe(true);
    expect(guardAllows("system_administrator", localUser, {})).toBe(false);
  });

  it("maps every resource-qualified route to a generated operation contract", () => {
    for (const route of CONSOLE_ROUTES.filter(
      (candidate) =>
        (candidate.context === "organization" || candidate.context === "admin") &&
        candidate.id !== "admin-overview",
    )) {
      expect(routeOperationId(route), route.id).not.toBeNull();
    }
  });

  it("uses generated scopes and context-qualified capabilities for route visibility", () => {
    const members = matchRoute("/organizations/org-1/members");
    const adminUsers = matchRoute("/admin/users");
    expect(members).not.toBeNull();
    expect(adminUsers).not.toBeNull();
    expect(routeHasCapability(members!.route, localUser, members!.params.organization_id)).toBe(
      true,
    );
    expect(routeHasCapability(members!.route, localUser, "org-2")).toBe(false);
    expect(routeHasCapability(adminUsers!.route, seed)).toBe(true);
    const readOnlySeed = {
      ...seed,
      effective_management_scopes: [
        "management:read",
      ] as CurrentPrincipal["effective_management_scopes"],
    };
    expect(routeHasCapability(adminUsers!.route, readOnlySeed)).toBe(true);
    expect(routeHasCapability(matchRoute("/admin/users/new")!.route, readOnlySeed)).toBe(false);
  });

  it("accepts only same-origin registered return paths", () => {
    expect(isSafeReturnTo("/admin/users?status=active")).toBe(true);
    expect(isSafeReturnTo("/organizations/org-1/members")).toBe(true);
    expect(isSafeReturnTo("https://attacker.example/admin")).toBe(false);
    expect(isSafeReturnTo("//attacker.example/admin")).toBe(false);
    expect(isSafeReturnTo("/sign-in")).toBe(false);
    expect(isSafeReturnTo("/unregistered/path")).toBe(false);
  });
});

describe("generated operation authority", () => {
  it("intersects every required scope with the action capability", () => {
    const withoutSecrets = {
      ...localUser,
      effective_management_scopes: [
        "management:read",
        "management:write",
        "management:authority",
      ] as CurrentPrincipal["effective_management_scopes"],
    };
    expect(operationAllows(withoutSecrets, "organization.management_keys.create", "org-1")).toBe(
      false,
    );
    expect(operationAllows(withoutSecrets, "organization.management_keys.list", "org-1")).toBe(
      true,
    );
    expect(operationAuthority("me.sessions.revoke")?.required_scopes).toEqual(["management:write"]);
    expect(operationAuthority("system.operations.usage_pipeline")?.required_scopes).toEqual([
      "management:operations",
      "management:read",
    ]);
  });

  it("projects every operations command and one-time Codex state-machine result", () => {
    for (const operationId of [
      "system.operations.runtime.reconcile",
      "system.operations.coordination.recoveries.create",
      "system.operations.coordination.activations.reconcile",
      "system.operations.state_origins.cleanup",
      "system.operations.upstream_credentials.reconcile",
      "system.operations.target_health.probe",
      "system.operations.usage_pipeline.flush",
    ]) {
      expect(operationAuthority(operationId), operationId).not.toBeNull();
    }
    const codexStart = operationAuthority("system.upstream_credentials.codex_login.start");
    expect(codexStart?.idempotency).toBe("state_machine");
    expect(codexStart?.one_time_secret_response).toBe(true);
    expect(codexStart?.sensitive_result).toBe(true);
  });

  it("matches narrowed system-key reads and member self-service alternatives", () => {
    const systemKeyReader: CurrentPrincipal = {
      ...seed,
      effective_management_scopes: ["management:read"],
      capabilities: ["read_management_keys"],
    };
    expect(operationAllows(systemKeyReader, "system.management_keys.list")).toBe(true);
    expect(operationAllows(systemKeyReader, "system.management_keys.get")).toBe(true);
    expect(operationAllows(systemKeyReader, "system.management_keys.create")).toBe(false);

    const member: CurrentPrincipal = {
      ...localUser,
      effective_management_scopes: [
        "management:read",
        "management:write",
        "management:secrets",
        "management:authority",
      ],
      allowed_organizations: [
        {
          ...localUser.allowed_organizations[0],
          role: "member",
          capabilities: ["read_organization"],
          management_key_self_service: {
            eligible: true,
            allowed_scopes: ["management:read"],
            allowed_capabilities: ["read_organization"],
            max_expiry_days: 30,
            max_active_keys: 2,
            active_keys: 0,
          },
        },
      ],
    };
    expect(operationAllows(member, "organization.management_keys.create", "org-1")).toBe(true);
    expect(operationAllows(member, "organization.management_keys.list", "org-1")).toBe(false);
    const policyDisabled = {
      ...member,
      allowed_organizations: member.allowed_organizations.map((organization) => ({
        ...organization,
        management_key_self_service: {
          ...organization.management_key_self_service!,
          eligible: false,
        },
      })),
    };
    expect(operationAllows(policyDisabled, "organization.management_keys.create", "org-1")).toBe(
      false,
    );
    const emptyIntersection = {
      ...member,
      allowed_organizations: member.allowed_organizations.map((organization) => ({
        ...organization,
        management_key_self_service: {
          ...organization.management_key_self_service!,
          allowed_capabilities: ["read_members"],
        },
      })),
    };
    expect(operationAllows(emptyIntersection, "organization.management_keys.create", "org-1")).toBe(
      false,
    );
    expect(
      operationAuthority("organization.management_keys.create")?.authorization_variants,
    ).toContainEqual({
      required_capability: "read_organization",
      condition: "local_member_self_service_policy",
    });
  });
});

describe("schema command form states", () => {
  it("describes optional-field opt-in actions without implying inverted preservation", () => {
    expect(optionalFieldPresenceLabel(false)).toBe("Include this field");
    expect(optionalFieldPresenceLabel(true)).toBe("Change this value");
  });

  it("distinguishes schema defaults from user edits", () => {
    const baseline = {
      budget: { enabled: true, clear: false, text: "{}", checked: false },
      name: { enabled: true, clear: false, text: "", checked: false },
    };
    expect(hasFieldStateChanges(baseline, baseline)).toBe(false);
    expect(
      hasFieldStateChanges(baseline, {
        ...baseline,
        name: { ...baseline.name, text: "Production key" },
      }),
    ).toBe(true);
    expect(
      hasFieldStateChanges(baseline, {
        ...baseline,
        name: { ...baseline.name, text: "" },
      }),
    ).toBe(false);
  });

  it("resolves discriminated oneOf branches and never forwards a stale workload secret", () => {
    const schema: JsonSchema = {
      type: "object",
      properties: {
        credential_kind: {
          type: "string",
          enum: ["static_api_key", "aws_default_chain"],
        },
        secret_source_kind: { type: "string" },
        injection_kind: { type: "string" },
        secret: { type: ["string", "null"] },
      },
      required: ["credential_kind", "secret_source_kind", "injection_kind"],
      oneOf: [
        {
          properties: {
            credential_kind: { const: "static_api_key" },
            secret_source_kind: { const: "encrypted_database" },
            injection_kind: { const: "bearer" },
            secret: { type: "string", minLength: 1 },
          },
          required: ["credential_kind", "secret_source_kind", "injection_kind", "secret"],
        },
        {
          properties: {
            credential_kind: { const: "aws_default_chain" },
            secret_source_kind: { const: "workload_identity" },
            injection_kind: { const: "aws_sigv4" },
            secret: { type: "null" },
          },
          required: ["credential_kind", "secret_source_kind", "injection_kind"],
        },
      ],
    };
    const field = (text: string, enabled = true) => ({
      enabled,
      clear: false,
      text,
      checked: false,
    });
    const states: FieldStates = {
      credential_kind: field("aws_default_chain"),
      secret_source_kind: field("not-authoritative"),
      injection_kind: field("not-authoritative"),
      secret: field("must-not-be-forwarded"),
    };
    const effective = resolveSchemaVariant(schema, states);
    expect(effective.properties?.secret?.type).toBe("null");
    expect(candidateFromStates(effective, states)).toEqual({
      credential_kind: "aws_default_chain",
      secret_source_kind: "workload_identity",
      injection_kind: "aws_sigv4",
      secret: null,
    });
  });

  it("extracts one-time Codex device codes without retaining them in metadata", () => {
    const revealed = secretResult({
      id: "session-1",
      user_code: "ABCD-EFGH",
      verification_url: "https://example.test/device",
    });
    expect(revealed).toEqual({
      secret: "ABCD-EFGH",
      metadata: {
        id: "session-1",
        verification_url: "https://example.test/device",
      },
    });
    expect(
      deviceAuthorization("system.upstream_credentials.codex_login.start", revealed!.metadata),
    ).toEqual({ verificationUrl: "https://example.test/device" });
    expect(
      deviceAuthorization("system.upstream_credentials.codex_login.start", {
        verification_url: "javascript:alert(1)",
      }),
    ).toBeUndefined();
  });

  it("renders device authorization instructions instead of secret-storage instructions", () => {
    const html = renderToStaticMarkup(
      <OneTimeReveal
        credentialClass="OpenAI Codex device code"
        secret="ABCD-EFGH"
        metadata={null}
        doneHref="/session"
        deviceAuthorization={{ verificationUrl: "https://example.test/device" }}
      />,
    );
    expect(html).toContain("Open verification page");
    expect(html).toContain("entered this one-time code");
    expect(html).not.toContain("approved secret store");
  });

  it("uses state-aware outcome-unknown recovery guidance", () => {
    const commandHtml = renderToStaticMarkup(
      <OutcomeUnknownState
        command="credential refresh"
        requestId="request-1"
        recoveryHref="/credential"
      />,
    );
    expect(commandHtml).toContain("inspect current authoritative state");
    expect(commandHtml).toContain("determine whether the command took effect");
    expect(commandHtml).not.toContain("usable material that was never disclosed");

    const secretHtml = renderToStaticMarkup(
      <OutcomeUnknownState
        command="key rotation"
        requestId="request-2"
        recoveryHref="/key"
        oneTimeMaterial
      />,
    );
    expect(secretHtml).toContain("usable material that was never disclosed");
    expect(secretHtml).toContain("disable or revoke potentially undisclosed material");
  });

  it("treats destructive and state-machine commands as non-repeatable", () => {
    expect(commandIsNonRepeatable({ destructive: true, idempotency: "not_applicable" })).toBe(true);
    expect(commandIsNonRepeatable({ destructive: false, idempotency: "state_machine" })).toBe(true);
    expect(commandIsNonRepeatable({ destructive: false, idempotency: "supported" })).toBe(false);
    expect(commandIsNonRepeatable(operationAuthority("system.upstream_credentials.refresh")!)).toBe(
      true,
    );
    expect(
      commandIsNonRepeatable(operationAuthority("system.upstream_credentials.codex_login.cancel")!),
    ).toBe(true);
  });

  it("keeps disabled confirmation actions distinct from active submissions", () => {
    const html = renderToStaticMarkup(
      <SubmitBar
        submitting={false}
        disabled
        submitLabel="Create Gateway API key"
        cancelHref="/organizations/org-1/gateway-api-keys"
      />,
    );
    expect(html).toContain("Create Gateway API key");
    expect(html).not.toContain("Working…");
    expect(html).toContain("disabled");
    expect(html).toContain('href="/organizations/org-1/gateway-api-keys"');
  });
});

describe("usage range time-zone handling", () => {
  it("preserves fractional local offsets for UTC hour boundaries", () => {
    const utcHour = new Date("2026-01-01T00:00:00.000Z");
    expect(hourInput(utcHour, -330)).toBe("2026-01-01T05:30");
    expect(hourInput(utcHour, -345)).toBe("2026-01-01T05:45");
  });
});

describe("browser secret handling helpers", () => {
  it("reads the non-HttpOnly CSRF cookie without accepting an empty value", () => {
    expect(readCookie("owlrora_csrf", "other=x; owlrora_csrf=csrf-value")).toBe("csrf-value");
    expect(readCookie("owlrora_csrf", "owlrora_csrf=")).toBeNull();
  });

  it("classifies a one-time command transport failure as outcome unknown without retrying", async () => {
    const fetch = vi.fn().mockRejectedValue(new TypeError("connection closed"));
    vi.stubGlobal("fetch", fetch);
    vi.stubGlobal("document", { cookie: "" });
    await expect(
      apiRequest("/api/v1/test/actions/create", { method: "POST", nonRepeatable: true }),
    ).rejects.toBeInstanceOf(OutcomeUnknownError);
    expect(fetch).toHaveBeenCalledTimes(1);
    vi.unstubAllGlobals();
  });

  it("classifies a committed one-time response body failure without retrying", async () => {
    const response = {
      ok: true,
      status: 200,
      headers: new Headers({
        "x-owlrora-command-status": "committed",
        "x-owlrora-process-publication": "pending",
      }),
      json: vi.fn().mockRejectedValue(new TypeError("body stream ended")),
    } as unknown as Response;
    const fetch = vi.fn().mockResolvedValue(response);
    vi.stubGlobal("fetch", fetch);
    vi.stubGlobal("document", { cookie: "" });
    const error = await apiRequest("/api/v1/test/actions/create", {
      method: "POST",
      nonRepeatable: true,
    }).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(OutcomeUnknownError);
    expect((error as OutcomeUnknownError).committed).toBe(true);
    expect(fetch).toHaveBeenCalledTimes(1);
    vi.unstubAllGlobals();
  });

  it("classifies truncated one-time JSON as outcome unknown", async () => {
    const fetch = vi.fn().mockResolvedValue(new Response("{", { status: 200 }));
    vi.stubGlobal("fetch", fetch);
    vi.stubGlobal("document", { cookie: "" });
    await expect(
      apiRequest("/api/v1/test/actions/create", { method: "POST", nonRepeatable: true }),
    ).rejects.toBeInstanceOf(OutcomeUnknownError);
    expect(fetch).toHaveBeenCalledTimes(1);
    vi.unstubAllGlobals();
  });

  it("reads committed runtime-publication metadata from successful commands", async () => {
    const fetch = vi.fn().mockResolvedValue(
      new Response(null, {
        status: 204,
        headers: {
          "x-owlrora-command-status": "committed",
          "x-owlrora-process-publication": "pending",
          "x-owlrora-applied-revision": "4",
          "x-owlrora-database-revision": "5",
        },
      }),
    );
    vi.stubGlobal("fetch", fetch);
    vi.stubGlobal("document", { cookie: "" });
    const response = await apiRequest<void>("/api/v1/test/actions/update", { method: "POST" });
    expect(response.commandStatus).toEqual({
      persistence: "committed",
      processPublication: "pending",
      appliedRevision: 4,
      databaseRevision: 5,
    });
    vi.unstubAllGlobals();
  });

  it("registers Module II in qualified contexts without personal API-key management", () => {
    const paths = CONSOLE_ROUTES.map((route) => route.path).join("\n");
    expect(paths).not.toContain("/profile/api-keys");
    expect(paths).toContain("/organizations/{organization_id}/gateway-api-keys");
    expect(paths).toContain("/organizations/{organization_id}/upstream-credentials");
    expect(paths).toContain("/organizations/{organization_id}/model-routes");
    expect(paths).toContain("/admin/catalog/credentials");
    expect(paths).toContain("/admin/usage");
    expect(paths).toContain("/admin/operations/coordination/recoveries");
    expect(paths).toContain("/admin/operations/target-health");
    expect(paths).toContain("/admin/operations/usage-pipeline");
  });
});
