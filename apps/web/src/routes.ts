import type { CurrentPrincipal } from "./api";
import { operationAllows } from "./operation-authority";

export type RouteGuard =
  | "any"
  | "public_only"
  | "authenticated"
  | "local_user"
  | "system_administrator"
  | "organization_visible";

export type RouteContext = "public" | "personal" | "organization" | "admin";

export interface ConsoleRoute {
  id: string;
  path: string;
  guard: RouteGuard;
  context: RouteContext;
  title: string;
}

export interface RouteMatch {
  route: ConsoleRoute;
  params: Record<string, string>;
}

function route(
  id: string,
  path: string,
  guard: RouteGuard,
  context: RouteContext,
  title: string,
): ConsoleRoute {
  return { id, path, guard, context, title };
}

// Static words are deliberately registered before parameterized detail routes.
export const CONSOLE_ROUTES: readonly ConsoleRoute[] = [
  route("root", "/", "any", "public", "OwlRora"),
  route("sign-in", "/sign-in", "public_only", "public", "Sign in"),
  route("signed-out", "/signed-out", "any", "public", "Signed out"),
  route("forbidden", "/forbidden", "any", "public", "Access denied"),
  route("not-found", "/not-found", "any", "public", "Not found"),
  route("profile", "/profile", "authenticated", "personal", "Profile"),
  route(
    "profile-organizations",
    "/profile/organizations",
    "local_user",
    "personal",
    "Organizations",
  ),
  route("profile-sessions", "/profile/sessions", "authenticated", "personal", "Sessions"),
  route("organization-selector", "/organizations", "local_user", "personal", "Organizations"),
  route(
    "organization-management-key-new",
    "/organizations/{organization_id}/management-api-keys/new",
    "organization_visible",
    "organization",
    "Create Management API key",
  ),
  route(
    "organization-management-key-edit",
    "/organizations/{organization_id}/management-api-keys/{management_api_key_id}/edit",
    "organization_visible",
    "organization",
    "Edit Management API key",
  ),
  route(
    "organization-management-key-rotate",
    "/organizations/{organization_id}/management-api-keys/{management_api_key_id}/rotate",
    "organization_visible",
    "organization",
    "Rotate Management API key",
  ),
  route(
    "organization-management-key-detail",
    "/organizations/{organization_id}/management-api-keys/{management_api_key_id}",
    "organization_visible",
    "organization",
    "Management API key",
  ),
  route(
    "organization-management-keys",
    "/organizations/{organization_id}/management-api-keys",
    "organization_visible",
    "organization",
    "Management API keys",
  ),
  route(
    "organization-policy-edit",
    "/organizations/{organization_id}/api-key-policy/edit",
    "organization_visible",
    "organization",
    "Edit API key policy",
  ),
  route(
    "organization-policy",
    "/organizations/{organization_id}/api-key-policy",
    "organization_visible",
    "organization",
    "API key policy",
  ),
  route(
    "organization-member-detail",
    "/organizations/{organization_id}/members/{user_id}",
    "organization_visible",
    "organization",
    "Member",
  ),
  route(
    "organization-members",
    "/organizations/{organization_id}/members",
    "organization_visible",
    "organization",
    "Members",
  ),
  route(
    "organization-invitations",
    "/organizations/{organization_id}/invitations",
    "organization_visible",
    "organization",
    "Invitations",
  ),
  route(
    "organization-audit",
    "/organizations/{organization_id}/audit",
    "organization_visible",
    "organization",
    "Audit",
  ),
  route(
    "organization-settings",
    "/organizations/{organization_id}/settings",
    "organization_visible",
    "organization",
    "Settings",
  ),
  route(
    "organization-overview",
    "/organizations/{organization_id}",
    "organization_visible",
    "organization",
    "Overview",
  ),
  route("admin-user-new", "/admin/users/new", "system_administrator", "admin", "Create user"),
  route(
    "admin-user-edit",
    "/admin/users/{user_id}/edit",
    "system_administrator",
    "admin",
    "Edit user",
  ),
  route("admin-user-detail", "/admin/users/{user_id}", "system_administrator", "admin", "User"),
  route("admin-users", "/admin/users", "system_administrator", "admin", "Users"),
  route(
    "admin-organization-new",
    "/admin/organizations/new",
    "system_administrator",
    "admin",
    "Create organization",
  ),
  route(
    "admin-organization-edit",
    "/admin/organizations/{organization_id}/edit",
    "system_administrator",
    "admin",
    "Edit organization",
  ),
  route(
    "admin-organization-detail",
    "/admin/organizations/{organization_id}",
    "system_administrator",
    "admin",
    "Organization",
  ),
  route(
    "admin-organizations",
    "/admin/organizations",
    "system_administrator",
    "admin",
    "Organizations",
  ),
  route(
    "admin-management-key-new",
    "/admin/management-api-keys/new",
    "system_administrator",
    "admin",
    "Create Management API key",
  ),
  route(
    "admin-management-key-edit",
    "/admin/management-api-keys/{management_api_key_id}/edit",
    "system_administrator",
    "admin",
    "Edit Management API key",
  ),
  route(
    "admin-management-key-rotate",
    "/admin/management-api-keys/{management_api_key_id}/rotate",
    "system_administrator",
    "admin",
    "Rotate Management API key",
  ),
  route(
    "admin-management-key-detail",
    "/admin/management-api-keys/{management_api_key_id}",
    "system_administrator",
    "admin",
    "Management API key",
  ),
  route(
    "admin-management-keys",
    "/admin/management-api-keys",
    "system_administrator",
    "admin",
    "Management API keys",
  ),
  route(
    "admin-management-key-policy-edit",
    "/admin/management-api-key-policy/edit",
    "system_administrator",
    "admin",
    "Edit Management API key policy",
  ),
  route(
    "admin-management-key-policy",
    "/admin/management-api-key-policy",
    "system_administrator",
    "admin",
    "Management API key policy",
  ),
  route(
    "admin-administrators",
    "/admin/administrators",
    "system_administrator",
    "admin",
    "System administrators",
  ),
  route(
    "admin-issuer-new",
    "/admin/identity/issuers/new",
    "system_administrator",
    "admin",
    "Create identity issuer",
  ),
  route(
    "admin-issuer-edit",
    "/admin/identity/issuers/{issuer_id}/edit",
    "system_administrator",
    "admin",
    "Edit identity issuer",
  ),
  route(
    "admin-issuer-detail",
    "/admin/identity/issuers/{issuer_id}",
    "system_administrator",
    "admin",
    "Identity issuer",
  ),
  route(
    "admin-issuers",
    "/admin/identity/issuers",
    "system_administrator",
    "admin",
    "Identity issuers",
  ),
  route(
    "admin-binding-new",
    "/admin/identity/bindings/new",
    "system_administrator",
    "admin",
    "Create identity binding",
  ),
  route(
    "admin-binding-detail",
    "/admin/identity/bindings/{binding_id}",
    "system_administrator",
    "admin",
    "Identity binding",
  ),
  route(
    "admin-bindings",
    "/admin/identity/bindings",
    "system_administrator",
    "admin",
    "Identity bindings",
  ),
  route(
    "admin-provisioning-policy-new",
    "/admin/identity/provisioning-policies/new",
    "system_administrator",
    "admin",
    "Create provisioning policy",
  ),
  route(
    "admin-provisioning-policy-edit",
    "/admin/identity/provisioning-policies/{policy_id}/edit",
    "system_administrator",
    "admin",
    "Edit provisioning policy",
  ),
  route(
    "admin-provisioning-policy-detail",
    "/admin/identity/provisioning-policies/{policy_id}",
    "system_administrator",
    "admin",
    "Provisioning policy",
  ),
  route(
    "admin-provisioning-policies",
    "/admin/identity/provisioning-policies",
    "system_administrator",
    "admin",
    "Provisioning policies",
  ),
  route(
    "admin-operations-readiness",
    "/admin/operations/readiness",
    "system_administrator",
    "admin",
    "Readiness",
  ),
  route(
    "admin-operations-runtime",
    "/admin/operations/runtime",
    "system_administrator",
    "admin",
    "Runtime",
  ),
  route(
    "admin-operations-recoveries",
    "/admin/operations/coordination/recoveries",
    "system_administrator",
    "admin",
    "Recoveries",
  ),
  route(
    "admin-operations-coordination",
    "/admin/operations/coordination",
    "system_administrator",
    "admin",
    "Coordination",
  ),
  route(
    "admin-operations-secret-custody",
    "/admin/operations/secret-custody",
    "system_administrator",
    "admin",
    "Secret custody",
  ),
  route(
    "admin-operations-telemetry",
    "/admin/operations/telemetry",
    "system_administrator",
    "admin",
    "Telemetry",
  ),
  route("admin-operations", "/admin/operations", "system_administrator", "admin", "Operations"),
  route("admin-audit", "/admin/audit", "system_administrator", "admin", "Audit"),
  route("admin-overview", "/admin", "system_administrator", "admin", "Admin"),
];

const ROUTE_OPERATIONS: Readonly<Record<string, string>> = {
  profile: "me.get",
  "profile-organizations": "me.organizations.list",
  "profile-sessions": "me.sessions.list",
  "organization-selector": "me.organizations.list",
  "organization-management-key-new": "organization.management_keys.create",
  "organization-management-key-edit": "organization.management_keys.update",
  "organization-management-key-rotate": "organization.management_keys.rotate",
  "organization-management-key-detail": "organization.management_keys.get",
  "organization-management-keys": "organization.management_keys.list",
  "organization-policy-edit": "organization.api_key_policy.update",
  "organization-policy": "organization.api_key_policy.get",
  "organization-member-detail": "organization.memberships.get",
  "organization-members": "organization.memberships.list",
  "organization-invitations": "organization.invitations.list",
  "organization-audit": "organization.audit.list",
  "organization-settings": "organization.get",
  "organization-overview": "organization.get",
  "admin-user-new": "system.users.create",
  "admin-user-edit": "system.users.update",
  "admin-user-detail": "system.users.get",
  "admin-users": "system.users.list",
  "admin-organization-new": "system.organizations.create",
  "admin-organization-edit": "system.organizations.update",
  "admin-organization-detail": "system.organizations.get",
  "admin-organizations": "system.organizations.list",
  "admin-management-key-new": "system.management_keys.create",
  "admin-management-key-edit": "system.management_keys.update",
  "admin-management-key-rotate": "system.management_keys.rotate",
  "admin-management-key-detail": "system.management_keys.get",
  "admin-management-keys": "system.management_keys.list",
  "admin-management-key-policy-edit": "system.management_key_policy.update",
  "admin-management-key-policy": "system.management_key_policy.get",
  "admin-administrators": "system.administrators.list",
  "admin-issuer-new": "system.identity_issuers.create",
  "admin-issuer-edit": "system.identity_issuers.update",
  "admin-issuer-detail": "system.identity_issuers.get",
  "admin-issuers": "system.identity_issuers.list",
  "admin-binding-new": "system.identity_bindings.create",
  "admin-binding-detail": "system.identity_bindings.get",
  "admin-bindings": "system.identity_bindings.list",
  "admin-provisioning-policy-new": "system.provisioning_policies.create",
  "admin-provisioning-policy-edit": "system.provisioning_policies.update",
  "admin-provisioning-policy-detail": "system.provisioning_policies.get",
  "admin-provisioning-policies": "system.provisioning_policies.list",
  "admin-operations-readiness": "system.operations.readiness",
  "admin-operations-runtime": "system.operations.runtime",
  "admin-operations-recoveries": "system.operations.recoveries",
  "admin-operations-coordination": "system.operations.coordination",
  "admin-operations-secret-custody": "system.operations.secret_custody",
  "admin-operations-telemetry": "system.operations.telemetry",
  "admin-operations": "system.operations.overview",
  "admin-audit": "system.audit.list",
};

export function routeOperationId(route: ConsoleRoute): string | null {
  return ROUTE_OPERATIONS[route.id] ?? null;
}

function decodeSegment(segment: string): string | null {
  try {
    const decoded = decodeURIComponent(segment);
    return decoded.length > 0 && !decoded.includes("/") ? decoded : null;
  } catch {
    return null;
  }
}

function matchPattern(pattern: string, pathname: string): Record<string, string> | null {
  const expected = pattern === "/" ? [] : pattern.slice(1).split("/");
  const actual = pathname === "/" ? [] : pathname.replace(/\/+$/, "").slice(1).split("/");
  if (expected.length !== actual.length) {
    return null;
  }
  const params: Record<string, string> = {};
  for (let index = 0; index < expected.length; index += 1) {
    const expectedSegment = expected[index];
    const actualSegment = decodeSegment(actual[index] ?? "");
    if (actualSegment === null) {
      return null;
    }
    if (expectedSegment.startsWith("{") && expectedSegment.endsWith("}")) {
      params[expectedSegment.slice(1, -1)] = actualSegment;
    } else if (expectedSegment !== actualSegment) {
      return null;
    }
  }
  return params;
}

export function matchRoute(pathname: string): RouteMatch | null {
  for (const candidate of CONSOLE_ROUTES) {
    const params = matchPattern(candidate.path, pathname);
    if (params !== null) {
      return { route: candidate, params };
    }
  }
  return null;
}

export function buildPath(pattern: string, params: Record<string, string>): string {
  return pattern.replace(/\{([^}]+)\}/g, (_, name: string) => {
    const value = params[name];
    if (value === undefined || value.length === 0) {
      throw new Error(`Missing route parameter: ${name}`);
    }
    return encodeURIComponent(value);
  });
}

export function guardAllows(
  guard: RouteGuard,
  me: CurrentPrincipal | null,
  params: Record<string, string>,
): boolean {
  if (guard === "any") {
    return true;
  }
  if (guard === "public_only") {
    return me === null;
  }
  if (me === null) {
    return false;
  }
  if (guard === "authenticated") {
    return true;
  }
  if (guard === "local_user") {
    return me.principal.kind === "local_user";
  }
  if (guard === "system_administrator") {
    return me.system_administrator;
  }
  const organizationId = params.organization_id;
  return (
    organizationId !== undefined &&
    (me.system_administrator ||
      me.allowed_organizations.some(
        (organization) => organization.organization_id === organizationId,
      ))
  );
}

export function defaultPath(me: CurrentPrincipal): string {
  if (me.principal.kind === "organization_management_api_key") {
    return `/organizations/${encodeURIComponent(me.principal.organization_id)}`;
  }
  if (me.principal.kind === "seed_admin" || me.system_administrator) {
    return "/admin";
  }
  if (me.principal.kind !== "local_user") {
    return "/profile";
  }
  if (me.allowed_organizations.length === 1) {
    return `/organizations/${encodeURIComponent(me.allowed_organizations[0].organization_id)}`;
  }
  return me.allowed_organizations.length > 1 ? "/organizations" : "/profile";
}

export function isSafeReturnTo(value: string | null): value is string {
  if (value === null || !value.startsWith("/") || value.startsWith("//")) {
    return false;
  }
  try {
    const url = new URL(value, "https://console.invalid");
    if (url.origin !== "https://console.invalid" || url.username !== "" || url.password !== "") {
      return false;
    }
    return matchRoute(url.pathname) !== null && url.pathname !== "/sign-in";
  } catch {
    return false;
  }
}

export function hasCapability(
  me: CurrentPrincipal,
  capability: string,
  organizationId?: string,
): boolean {
  if (organizationId === undefined) return me.capabilities.includes(capability);
  if (me.system_administrator && me.capabilities.includes(capability)) return true;
  return (
    me.allowed_organizations
      .find((organization) => organization.organization_id === organizationId)
      ?.capabilities.includes(capability) === true
  );
}

export function routeHasCapability(
  route: ConsoleRoute,
  me: CurrentPrincipal,
  organizationId?: string,
): boolean {
  const operationId = routeOperationId(route);
  if (operationId === null) return true;
  return operationAllows(
    me,
    operationId,
    route.context === "organization" ? organizationId : undefined,
  );
}
