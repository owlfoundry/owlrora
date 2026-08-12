import { describe, expect, it, vi } from "vitest";

import { OutcomeUnknownError, apiRequest, readCookie, type CurrentPrincipal } from "./api";
import { operationAllows, operationAuthority } from "./operation-authority";
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
    expect(operationAuthority("system.operations.usage_pipeline")).toBeNull();
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
        "x-owlrora-node-publication": "pending",
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
          "x-owlrora-node-publication": "pending",
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
      nodePublication: "pending",
      appliedRevision: 4,
      databaseRevision: 5,
    });
    vi.unstubAllGlobals();
  });

  it("does not register personal API-key or unimplemented Module II routes", () => {
    const paths = CONSOLE_ROUTES.map((route) => route.path).join("\n");
    expect(paths).not.toContain("/profile/api-keys");
    expect(paths).not.toContain("gateway-api-keys");
    expect(paths).not.toContain("upstream-credentials");
    expect(paths).not.toContain("model-routes");
    expect(paths).not.toContain("usage-pipeline");
  });
});
