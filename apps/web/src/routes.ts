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

const SYSTEM_CATALOG_FAMILIES = [
  [
    "egress-network-policies",
    "egress-network-policy",
    "Egress network policy",
    "system.egress_network_policies",
  ],
  ["credentials", "credential", "Upstream credential", "system.upstream_credentials"],
  ["endpoints", "endpoint", "Upstream endpoint", "system.upstream_endpoints"],
  ["deployments", "deployment", "Model deployment", "system.model_deployments"],
  ["model-routes", "model-route", "Model route", "system.model_routes"],
  ["pricing-policies", "pricing-policy", "Pricing policy", "system.pricing_policies"],
  [
    "reliability-policies",
    "reliability-policy",
    "Reliability policy",
    "system.reliability_policies",
  ],
] as const;

const ORGANIZATION_CATALOG_FAMILIES = [
  [
    "upstream-credentials",
    "upstream-credential",
    "BYOK credential",
    "organization.upstream_credentials",
    "credential_id",
  ],
  [
    "model-deployments",
    "model-deployment",
    "Model deployment",
    "organization.model_deployments",
    "deployment_id",
  ],
  ["model-routes", "model-route", "Model route", "organization.model_routes", "route_id"],
] as const;

function systemCatalogRoutes(): ConsoleRoute[] {
  return SYSTEM_CATALOG_FAMILIES.flatMap(([family, singular, title]) => [
    route(
      `admin-catalog-${singular}-new`,
      `/admin/catalog/${family}/new`,
      "system_administrator",
      "admin",
      `Create ${title.toLowerCase()}`,
    ),
    route(
      `admin-catalog-${singular}-edit`,
      `/admin/catalog/${family}/{resource_id}/edit`,
      "system_administrator",
      "admin",
      `Edit ${title.toLowerCase()}`,
    ),
    route(
      `admin-catalog-${singular}-detail`,
      `/admin/catalog/${family}/{resource_id}`,
      "system_administrator",
      "admin",
      title,
    ),
    route(
      `admin-catalog-${family}`,
      `/admin/catalog/${family}`,
      "system_administrator",
      "admin",
      title
        .replace(/ policy$/, " policies")
        .replace(/ credential$/, " credentials")
        .replace(/ endpoint$/, " endpoints")
        .replace(/ deployment$/, " deployments")
        .replace(/ route$/, " routes"),
    ),
  ]);
}

function organizationCatalogRoutes(): ConsoleRoute[] {
  return ORGANIZATION_CATALOG_FAMILIES.flatMap(([family, singular, title, , idParameter]) => [
    route(
      `organization-${singular}-new`,
      `/organizations/{organization_id}/${family}/new`,
      "organization_visible",
      "organization",
      `Create ${title.toLowerCase()}`,
    ),
    route(
      `organization-${singular}-edit`,
      `/organizations/{organization_id}/${family}/{${idParameter}}/edit`,
      "organization_visible",
      "organization",
      `Edit ${title.toLowerCase()}`,
    ),
    route(
      `organization-${singular}-detail`,
      `/organizations/{organization_id}/${family}/{${idParameter}}`,
      "organization_visible",
      "organization",
      title,
    ),
    route(
      `organization-${family}`,
      `/organizations/{organization_id}/${family}`,
      "organization_visible",
      "organization",
      title,
    ),
  ]);
}

function catalogRouteOperations(): Record<string, string> {
  const mappings: Record<string, string> = {};
  for (const [family, singular, , operationFamily] of SYSTEM_CATALOG_FAMILIES) {
    mappings[`admin-catalog-${singular}-new`] = `${operationFamily}.create`;
    mappings[`admin-catalog-${singular}-edit`] = `${operationFamily}.update`;
    mappings[`admin-catalog-${singular}-detail`] = `${operationFamily}.get`;
    mappings[`admin-catalog-${family}`] = `${operationFamily}.list`;
  }
  for (const [family, singular, , operationFamily] of ORGANIZATION_CATALOG_FAMILIES) {
    mappings[`organization-${singular}-new`] = `${operationFamily}.create`;
    mappings[`organization-${singular}-edit`] = `${operationFamily}.update`;
    mappings[`organization-${singular}-detail`] = `${operationFamily}.get`;
    mappings[`organization-${family}`] = `${operationFamily}.list`;
  }
  return mappings;
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
    "organization-gateway-key-new",
    "/organizations/{organization_id}/gateway-api-keys/new",
    "organization_visible",
    "organization",
    "Create Gateway API key",
  ),
  route(
    "organization-gateway-key-edit",
    "/organizations/{organization_id}/gateway-api-keys/{gateway_api_key_id}/edit",
    "organization_visible",
    "organization",
    "Edit Gateway API key",
  ),
  route(
    "organization-gateway-key-budget",
    "/organizations/{organization_id}/gateway-api-keys/{gateway_api_key_id}/budget",
    "organization_visible",
    "organization",
    "Gateway-key budget",
  ),
  route(
    "organization-gateway-key-limits",
    "/organizations/{organization_id}/gateway-api-keys/{gateway_api_key_id}/limits",
    "organization_visible",
    "organization",
    "Gateway-key request limits",
  ),
  route(
    "organization-gateway-key-rotate",
    "/organizations/{organization_id}/gateway-api-keys/{gateway_api_key_id}/rotate",
    "organization_visible",
    "organization",
    "Rotate Gateway API key",
  ),
  route(
    "organization-gateway-key-detail",
    "/organizations/{organization_id}/gateway-api-keys/{gateway_api_key_id}",
    "organization_visible",
    "organization",
    "Gateway API key",
  ),
  route(
    "organization-gateway-keys",
    "/organizations/{organization_id}/gateway-api-keys",
    "organization_visible",
    "organization",
    "Gateway API keys",
  ),
  route(
    "organization-upstream-credential-replace-secret",
    "/organizations/{organization_id}/upstream-credentials/{credential_id}/replace-secret",
    "organization_visible",
    "organization",
    "Replace BYOK secret",
  ),
  ...organizationCatalogRoutes(),
  route(
    "organization-provider-budget-byok-edit",
    "/organizations/{organization_id}/provider-budgets/byok/edit",
    "organization_visible",
    "organization",
    "Edit BYOK budget",
  ),
  route(
    "organization-provider-budgets",
    "/organizations/{organization_id}/provider-budgets",
    "organization_visible",
    "organization",
    "Provider budgets",
  ),
  route(
    "organization-usage",
    "/organizations/{organization_id}/usage",
    "organization_visible",
    "organization",
    "Usage",
  ),
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
    "admin-organization-catalog-grants",
    "/admin/organizations/{organization_id}/catalog-grants",
    "system_administrator",
    "admin",
    "Catalog grants",
  ),
  route(
    "admin-organization-system-provider-budget",
    "/admin/organizations/{organization_id}/system-provider-budget",
    "system_administrator",
    "admin",
    "System-provider allocation",
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
    "admin-catalog-credential-replace-secret",
    "/admin/catalog/credentials/{credential_id}/replace-secret",
    "system_administrator",
    "admin",
    "Replace upstream secret",
  ),
  route(
    "admin-catalog-credential-codex-login",
    "/admin/catalog/credentials/{credential_id}/codex-login/{login_session_id}",
    "system_administrator",
    "admin",
    "Codex login",
  ),
  route(
    "admin-catalog-gateway-policy-ceilings-edit",
    "/admin/catalog/gateway-policy-ceilings/edit",
    "system_administrator",
    "admin",
    "Edit Gateway policy ceilings",
  ),
  route(
    "admin-catalog-gateway-policy-ceilings",
    "/admin/catalog/gateway-policy-ceilings",
    "system_administrator",
    "admin",
    "Gateway policy ceilings",
  ),
  ...systemCatalogRoutes(),
  route("admin-usage", "/admin/usage", "system_administrator", "admin", "Usage"),
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
    "admin-operations-activations",
    "/admin/operations/coordination/activations",
    "system_administrator",
    "admin",
    "Policy activations",
  ),
  route(
    "admin-operations-state-origins",
    "/admin/operations/state-origins",
    "system_administrator",
    "admin",
    "State origins",
  ),
  route(
    "admin-operations-upstream-credentials",
    "/admin/operations/upstream-credentials",
    "system_administrator",
    "admin",
    "Upstream credential controllers",
  ),
  route(
    "admin-operations-target-health",
    "/admin/operations/target-health",
    "system_administrator",
    "admin",
    "Target health",
  ),
  route(
    "admin-operations-usage-pipeline",
    "/admin/operations/usage-pipeline",
    "system_administrator",
    "admin",
    "Usage pipeline",
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
  "organization-gateway-key-new": "organization.gateway_api_keys.create",
  "organization-gateway-key-edit": "organization.gateway_api_keys.update",
  "organization-gateway-key-budget": "organization.gateway_api_keys.budget.get",
  "organization-gateway-key-limits": "organization.gateway_api_keys.limits.get",
  "organization-gateway-key-rotate": "organization.gateway_api_keys.rotate",
  "organization-gateway-key-detail": "organization.gateway_api_keys.get",
  "organization-gateway-keys": "organization.gateway_api_keys.list",
  "organization-upstream-credential-replace-secret":
    "organization.upstream_credentials.replace_secret",
  "organization-provider-budget-byok-edit": "organization.provider_budgets.byok.update",
  "organization-provider-budgets": "organization.provider_budgets.byok.get",
  "organization-usage": "organization.usage.get",
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
  ...catalogRouteOperations(),
  "admin-user-new": "system.users.create",
  "admin-user-edit": "system.users.update",
  "admin-user-detail": "system.users.get",
  "admin-users": "system.users.list",
  "admin-organization-new": "system.organizations.create",
  "admin-organization-edit": "system.organizations.update",
  "admin-organization-catalog-grants": "organization.system_route_grants.get",
  "admin-organization-system-provider-budget": "organization.provider_budgets.system.get",
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
  "admin-catalog-credential-replace-secret": "system.upstream_credentials.replace_secret",
  "admin-catalog-credential-codex-login": "system.upstream_credentials.codex_login.get",
  "admin-catalog-gateway-policy-ceilings-edit": "system.gateway_policy_ceilings.update",
  "admin-catalog-gateway-policy-ceilings": "system.gateway_policy_ceilings.get",
  "admin-usage": "system.usage.get",
  "admin-operations-readiness": "system.operations.readiness",
  "admin-operations-runtime": "system.operations.runtime",
  "admin-operations-recoveries": "system.operations.recoveries",
  "admin-operations-coordination": "system.operations.coordination",
  "admin-operations-activations": "system.operations.activations",
  "admin-operations-state-origins": "system.operations.state_origins",
  "admin-operations-upstream-credentials": "system.operations.upstream_credentials",
  "admin-operations-target-health": "system.operations.target_health",
  "admin-operations-usage-pipeline": "system.operations.usage_pipeline",
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
