import { useEffect, useMemo, useState } from "react";

import {
  ApiError,
  apiRequest,
  COMMAND_STATUS_EVENT,
  logout,
  type CommandStatus,
  type CurrentPrincipal,
  type Page,
  type AllowedOrganization,
} from "./api";
import {
  AdminOrganizationCreatePage,
  AdminOrganizationDetailPage,
  AdminOrganizationEditPage,
  AdminOrganizationsPage,
  AdministratorsPage,
  AdminOverviewPage,
  UserCreatePage,
  UserDetailPage,
  UserEditPage,
  UsersPage,
} from "./admin-resource-pages";
import {
  CatalogResourceCreatePage,
  CatalogResourceDetailPage,
  CatalogResourceEditPage,
  CatalogResourceListPage,
  CodexLoginPage,
  CredentialReplaceSecretPage,
  SingletonPolicyEditPage,
  SingletonPolicyPage,
} from "./catalog-pages";
import { AuditPage, OperationsPage } from "./evidence-pages";
import {
  IdentityBindingCreatePage,
  IdentityBindingDetailPage,
  IdentityBindingsPage,
  IdentityIssuerCreatePage,
  IdentityIssuerDetailPage,
  IdentityIssuerEditPage,
  IdentityIssuersPage,
  ProvisioningPoliciesPage,
  ProvisioningPolicyCreatePage,
  ProvisioningPolicyDetailPage,
  ProvisioningPolicyEditPage,
} from "./identity-pages";
import {
  CatalogGrantsPage,
  GatewayKeyBudgetPage,
  GatewayKeyCreatePage,
  GatewayKeyDetailPage,
  GatewayKeyEditPage,
  GatewayKeyLimitsPage,
  GatewayKeyListPage,
  GatewayKeyRotatePage,
  ProviderBudgetEditPage,
  ProviderBudgetsPage,
} from "./gateway-pages";
import {
  KeyPolicyEditPage,
  KeyPolicyPage,
  ManagementKeyCreatePage,
  ManagementKeyDetailPage,
  ManagementKeyEditPage,
  ManagementKeyListPage,
  ManagementKeyRotatePage,
  type KeyScope,
} from "./key-pages";
import {
  InvitationsPage,
  MemberDetailPage,
  MembersPage,
  OrganizationOverviewPage,
  OrganizationSettingsPage,
} from "./organization-pages";
import {
  CONSOLE_ROUTES,
  defaultPath,
  guardAllows,
  matchRoute,
  routeHasCapability,
  type RouteMatch,
} from "./routes";
import {
  ForbiddenPage,
  NotFoundPage,
  OrganizationSelectorPage,
  ProfilePage,
  SessionsPage,
  SignedOutPage,
  SignInPage,
} from "./session-pages";
import { UsagePage } from "./usage-pages";
import {
  ApiErrorState,
  Link,
  LoadingState,
  NAVIGATION_EVENT,
  navigate,
  requestNavigation,
} from "./ui";

interface SessionState {
  loading: boolean;
  me: CurrentPrincipal | null;
  error: ApiError | null;
}

function usePathname(): string {
  const [pathname, setPathname] = useState(() => window.location.pathname);
  useEffect(() => {
    const update = () => setPathname(window.location.pathname);
    const updateFromHistory = () => {
      const target = window.location.pathname;
      if (!requestNavigation(target)) {
        window.history.pushState(null, "", pathname);
        return;
      }
      setPathname(target);
    };
    window.addEventListener("popstate", updateFromHistory);
    window.addEventListener(NAVIGATION_EVENT, update);
    return () => {
      window.removeEventListener("popstate", updateFromHistory);
      window.removeEventListener(NAVIGATION_EVENT, update);
    };
  }, [pathname]);
  return pathname;
}

async function loadCurrentPrincipal(signal: AbortSignal): Promise<CurrentPrincipal> {
  const response = await apiRequest<CurrentPrincipal>("/api/v1/me", { signal });
  const me = response.value;
  if (me.principal.kind !== "local_user") return me;
  const organizations: AllowedOrganization[] = [];
  let cursor: string | null = null;
  do {
    const query = new URLSearchParams({ limit: "100" });
    if (cursor !== null) query.set("cursor", cursor);
    const page = await apiRequest<Page<AllowedOrganization>>(
      `/api/v1/me/organizations?${query.toString()}`,
      { signal },
    );
    organizations.push(...page.value.items);
    if (page.value.next_cursor === cursor) {
      throw new ApiError(0, "invalid_pagination", "The organization cursor did not advance.");
    }
    cursor = page.value.next_cursor;
  } while (cursor !== null);
  return { ...me, allowed_organizations: organizations };
}

function useSession(pathname: string): [SessionState, (me: CurrentPrincipal | null) => void] {
  const [state, setState] = useState<SessionState>({ loading: true, me: null, error: null });
  useEffect(() => {
    const controller = new AbortController();
    void loadCurrentPrincipal(controller.signal)
      .then((me) => setState({ loading: false, me, error: null }))
      .catch((caught: unknown) => {
        if (controller.signal.aborted) return;
        if (caught instanceof ApiError && caught.status === 401) {
          setState({ loading: false, me: null, error: null });
        } else {
          setState({
            loading: false,
            me: null,
            error:
              caught instanceof ApiError
                ? caught
                : new ApiError(0, "network_error", "The server could not be reached."),
          });
        }
      });
    return () => controller.abort();
  }, [pathname]);
  return [state, (me) => setState({ loading: false, me, error: null })];
}

function Redirect({ to }: { to: string }) {
  useEffect(() => navigate(to, true), [to]);
  return <LoadingState label="Opening an authorized context" />;
}

function principalLabel(me: CurrentPrincipal): string {
  switch (me.principal.kind) {
    case "seed_admin":
      return "Seed administrator";
    case "local_user":
      return `Local user · ${me.principal.user_id.slice(0, 8)}`;
    case "deployment_management_api_key":
      return `Deployment automation · ${me.principal.management_api_key_id.slice(0, 8)}`;
    case "organization_management_api_key":
      return `Organization automation · ${me.principal.management_api_key_id.slice(0, 8)}`;
  }
}

interface NavItem {
  label: string;
  href: string;
}
interface NavGroup {
  label: string;
  items: NavItem[];
}

function navigation(match: RouteMatch, me: CurrentPrincipal): NavGroup[] {
  if (match.route.context === "admin") {
    return [
      { label: "Overview", items: [{ label: "Admin overview", href: "/admin" }] },
      {
        label: "Identity and access",
        items: [
          { label: "Users", href: "/admin/users" },
          { label: "Organizations", href: "/admin/organizations" },
          { label: "Management API keys", href: "/admin/management-api-keys" },
          { label: "Key policy", href: "/admin/management-api-key-policy" },
          { label: "System administrators", href: "/admin/administrators" },
          { label: "Identity issuers", href: "/admin/identity/issuers" },
          { label: "Identity bindings", href: "/admin/identity/bindings" },
          { label: "Provisioning policies", href: "/admin/identity/provisioning-policies" },
        ],
      },
      {
        label: "Upstream catalog",
        items: [
          { label: "Egress policies", href: "/admin/catalog/egress-network-policies" },
          { label: "Credentials", href: "/admin/catalog/credentials" },
          { label: "Endpoints", href: "/admin/catalog/endpoints" },
          { label: "Deployments", href: "/admin/catalog/deployments" },
          { label: "Model routes", href: "/admin/catalog/model-routes" },
          { label: "Pricing policies", href: "/admin/catalog/pricing-policies" },
          { label: "Reliability policies", href: "/admin/catalog/reliability-policies" },
          { label: "Gateway policy ceilings", href: "/admin/catalog/gateway-policy-ceilings" },
        ],
      },
      {
        label: "Operations",
        items: [
          { label: "Usage", href: "/admin/usage" },
          { label: "Overview", href: "/admin/operations" },
          { label: "Readiness", href: "/admin/operations/readiness" },
          { label: "Runtime", href: "/admin/operations/runtime" },
          { label: "Coordination", href: "/admin/operations/coordination" },
          { label: "Recoveries", href: "/admin/operations/coordination/recoveries" },
          { label: "Activations", href: "/admin/operations/coordination/activations" },
          { label: "State origins", href: "/admin/operations/state-origins" },
          { label: "Credential controllers", href: "/admin/operations/upstream-credentials" },
          { label: "Target health", href: "/admin/operations/target-health" },
          { label: "Usage pipeline", href: "/admin/operations/usage-pipeline" },
          { label: "Secret custody", href: "/admin/operations/secret-custody" },
          { label: "Telemetry", href: "/admin/operations/telemetry" },
        ],
      },
      { label: "Audit", items: [{ label: "System audit", href: "/admin/audit" }] },
    ];
  }
  if (match.route.context === "organization") {
    const id = match.params.organization_id;
    const base = `/organizations/${encodeURIComponent(id)}`;
    return [
      {
        label: "Organization",
        items: [
          { label: "Overview", href: base },
          { label: "Members", href: `${base}/members` },
          { label: "Invitations", href: `${base}/invitations` },
          { label: "Audit", href: `${base}/audit` },
          { label: "Settings", href: `${base}/settings` },
        ],
      },
      {
        label: "Gateway access",
        items: [
          { label: "Gateway API keys", href: `${base}/gateway-api-keys` },
          { label: "Management API keys", href: `${base}/management-api-keys` },
          { label: "API key policy", href: `${base}/api-key-policy` },
          { label: "Provider budgets", href: `${base}/provider-budgets` },
        ],
      },
      {
        label: "Upstream catalog",
        items: [
          { label: "BYOK credentials", href: `${base}/upstream-credentials` },
          { label: "Model deployments", href: `${base}/model-deployments` },
          { label: "Model routes", href: `${base}/model-routes` },
          { label: "Usage", href: `${base}/usage` },
        ],
      },
    ];
  }
  const localUserItems =
    me.principal.kind === "local_user" ? [{ label: "Organizations", href: "/organizations" }] : [];
  return [
    {
      label: "Personal",
      items: [
        { label: "Profile", href: "/profile" },
        ...localUserItems,
        { label: "Sessions", href: "/profile/sessions" },
      ],
    },
  ];
}

function authorizedNavigation(groups: NavGroup[], me: CurrentPrincipal): NavGroup[] {
  return groups
    .map((group) => ({
      ...group,
      items: group.items.filter((item) => {
        const match = matchRoute(item.href);
        return match !== null && routeHasCapability(match.route, me, match.params.organization_id);
      }),
    }))
    .filter((group) => group.items.length > 0);
}

function contextLabel(
  match: RouteMatch,
  me: CurrentPrincipal,
): { kind: string; name: string; systemAccess: boolean } {
  if (match.route.context === "admin")
    return { kind: "Admin", name: "Deployment", systemAccess: true };
  if (match.route.context === "organization") {
    const organization = me.allowed_organizations.find(
      (item) => item.organization_id === match.params.organization_id,
    );
    return {
      kind: "Organization",
      name: organization?.name ?? match.params.organization_id,
      systemAccess: organization === undefined && me.system_administrator,
    };
  }
  return { kind: "Personal", name: principalLabel(me), systemAccess: false };
}

function AppShell({
  match,
  me,
  onSignedOut,
}: {
  match: RouteMatch;
  me: CurrentPrincipal;
  onSignedOut: () => void;
}) {
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [signOutError, setSignOutError] = useState<ApiError | null>(null);
  const [commandStatus, setCommandStatus] = useState<CommandStatus | null>(null);
  useEffect(() => {
    const update = (event: Event) => {
      setCommandStatus((event as CustomEvent<CommandStatus>).detail);
    };
    window.addEventListener(COMMAND_STATUS_EVENT, update);
    return () => window.removeEventListener(COMMAND_STATUS_EVENT, update);
  }, []);
  const groups = authorizedNavigation(navigation(match, me), me);
  const context = contextLabel(match, me);
  async function signOut(): Promise<void> {
    if (!requestNavigation("/signed-out")) return;
    setSignOutError(null);
    try {
      await logout();
      onSignedOut();
      navigate("/signed-out", true, true);
    } catch (caught: unknown) {
      setSignOutError(
        caught instanceof ApiError
          ? caught
          : new ApiError(0, "network_error", "The server could not be reached."),
      );
    }
  }
  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>
      <header className="topbar">
        <button
          className="nav-toggle"
          type="button"
          aria-label="Toggle navigation"
          aria-expanded={drawerOpen}
          onClick={() => setDrawerOpen((value) => !value)}
        >
          Menu
        </button>
        <Link className="brand" href="/">
          <span className="brand-mark" aria-hidden="true">
            O
          </span>
          <strong>OwlRora</strong>
        </Link>
        <div className="context-chip">
          <span>{context.kind}</span>
          <strong>{context.name}</strong>
          {context.systemAccess && match.route.context === "organization" ? (
            <em>System access</em>
          ) : null}
        </div>
        <nav className="top-actions" aria-label="Global navigation">
          {me.system_administrator && match.route.context !== "admin" ? (
            <Link href="/admin">Admin</Link>
          ) : null}
          <a
            href="/docs/"
            onClick={(event) => {
              if (!requestNavigation("/docs/")) event.preventDefault();
            }}
          >
            Help
          </a>
          <Link href="/profile">{principalLabel(me)}</Link>
          <button type="button" onClick={() => void signOut()}>
            Sign out
          </button>
        </nav>
      </header>
      <aside
        className={`sidebar${drawerOpen ? " sidebar-open" : ""}`}
        aria-label={`${context.kind} navigation`}
      >
        <div className="sidebar-context">
          <span>{context.kind} context</span>
          <strong>{context.name}</strong>
          {context.systemAccess && match.route.context === "organization" ? (
            <em>System administrator access</em>
          ) : null}
        </div>
        <nav>
          {groups.map((group) => (
            <div className="nav-group" key={group.label}>
              <h2>{group.label}</h2>
              {group.items.map((item) => {
                const selected =
                  window.location.pathname === item.href ||
                  (item.href !== "/admin" && window.location.pathname.startsWith(`${item.href}/`));
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={selected ? "nav-link selected" : "nav-link"}
                    ariaCurrent={selected ? "page" : undefined}
                  >
                    {item.label}
                  </Link>
                );
              })}
            </div>
          ))}
        </nav>
      </aside>
      {drawerOpen ? (
        <button
          className="drawer-backdrop"
          type="button"
          aria-label="Close navigation"
          onClick={() => setDrawerOpen(false)}
        />
      ) : null}
      <main className="content" id="main-content">
        {signOutError === null ? null : <ApiErrorState error={signOutError} compact />}
        {commandStatus === null ? null : (
          <div
            className={`alert ${commandStatus.nodePublication === "applied" ? "alert-success" : "alert-warning"}`}
            role="status"
          >
            <strong>Command committed</strong>
            <span>
              {commandStatus.nodePublication === "applied"
                ? "This node has applied the current runtime generation."
                : "Runtime publication is pending; the committed state remains authoritative."}
            </span>
            {commandStatus.appliedRevision === null ||
            commandStatus.databaseRevision === null ? null : (
              <span className="technical">
                Applied revision {commandStatus.appliedRevision}; database revision{" "}
                {commandStatus.databaseRevision}
              </span>
            )}
            <button
              className="button button-secondary"
              type="button"
              onClick={() => setCommandStatus(null)}
            >
              Dismiss
            </button>
          </div>
        )}
        <div className="breadcrumb">
          <Link
            href={
              match.route.context === "admin"
                ? "/admin"
                : match.route.context === "organization"
                  ? `/organizations/${encodeURIComponent(match.params.organization_id)}`
                  : "/profile"
            }
          >
            {context.kind}
          </Link>
          <span aria-hidden="true">/</span>
          <span>{match.route.title}</span>
        </div>
        <RouteContent match={match} me={me} />
      </main>
    </div>
  );
}

function organizationKeyScope(match: RouteMatch): KeyScope {
  return { kind: "organization", organizationId: match.params.organization_id };
}

function RouteContent({ match, me }: { match: RouteMatch; me: CurrentPrincipal }) {
  const p = match.params;
  const pathSegments = match.route.path.split("/");
  const catalogFamily = pathSegments[3];
  const genericAdminCatalog =
    match.route.id.startsWith("admin-catalog-") &&
    !match.route.id.startsWith("admin-catalog-credential-replace") &&
    !match.route.id.startsWith("admin-catalog-credential-codex") &&
    !match.route.id.startsWith("admin-catalog-gateway-policy-ceilings");
  if (genericAdminCatalog) {
    if (match.route.id.endsWith("-new"))
      return <CatalogResourceCreatePage scope="system" family={catalogFamily} />;
    if (match.route.id.endsWith("-edit"))
      return (
        <CatalogResourceEditPage scope="system" family={catalogFamily} resourceId={p.resource_id} />
      );
    if (match.route.id.endsWith("-detail"))
      return (
        <CatalogResourceDetailPage
          scope="system"
          family={catalogFamily}
          resourceId={p.resource_id}
          me={me}
        />
      );
    return <CatalogResourceListPage scope="system" family={catalogFamily} me={me} />;
  }
  const genericOrganizationCatalog =
    match.route.context === "organization" &&
    ["upstream-credentials", "model-deployments", "model-routes"].includes(catalogFamily) &&
    match.route.id !== "organization-upstream-credential-replace-secret";
  if (genericOrganizationCatalog) {
    const organizationCatalogResourceId = p.credential_id ?? p.deployment_id ?? p.route_id;
    if (match.route.id.endsWith("-new"))
      return (
        <CatalogResourceCreatePage
          scope="organization"
          family={catalogFamily}
          organizationId={p.organization_id}
        />
      );
    if (match.route.id.endsWith("-edit"))
      return (
        <CatalogResourceEditPage
          scope="organization"
          family={catalogFamily}
          organizationId={p.organization_id}
          resourceId={organizationCatalogResourceId}
        />
      );
    if (match.route.id.endsWith("-detail"))
      return (
        <CatalogResourceDetailPage
          scope="organization"
          family={catalogFamily}
          organizationId={p.organization_id}
          resourceId={organizationCatalogResourceId}
          me={me}
        />
      );
    return (
      <CatalogResourceListPage
        scope="organization"
        family={catalogFamily}
        organizationId={p.organization_id}
        me={me}
      />
    );
  }
  switch (match.route.id) {
    case "profile":
      return <ProfilePage me={me} />;
    case "profile-organizations":
    case "organization-selector":
      return <OrganizationSelectorPage me={me} />;
    case "profile-sessions":
      return <SessionsPage me={me} />;
    case "organization-overview":
      return <OrganizationOverviewPage organizationId={p.organization_id} me={me} />;
    case "organization-members":
      return <MembersPage organizationId={p.organization_id} me={me} />;
    case "organization-member-detail":
      return <MemberDetailPage organizationId={p.organization_id} userId={p.user_id} me={me} />;
    case "organization-invitations":
      return <InvitationsPage organizationId={p.organization_id} me={me} />;
    case "organization-gateway-keys":
      return <GatewayKeyListPage organizationId={p.organization_id} me={me} />;
    case "organization-gateway-key-new":
      return <GatewayKeyCreatePage organizationId={p.organization_id} />;
    case "organization-gateway-key-detail":
      return (
        <GatewayKeyDetailPage
          organizationId={p.organization_id}
          keyId={p.gateway_api_key_id}
          me={me}
        />
      );
    case "organization-gateway-key-edit":
      return <GatewayKeyEditPage organizationId={p.organization_id} keyId={p.gateway_api_key_id} />;
    case "organization-gateway-key-budget":
      return (
        <GatewayKeyBudgetPage organizationId={p.organization_id} keyId={p.gateway_api_key_id} />
      );
    case "organization-gateway-key-limits":
      return (
        <GatewayKeyLimitsPage organizationId={p.organization_id} keyId={p.gateway_api_key_id} />
      );
    case "organization-gateway-key-rotate":
      return (
        <GatewayKeyRotatePage organizationId={p.organization_id} keyId={p.gateway_api_key_id} />
      );
    case "organization-upstream-credential-replace-secret":
      return (
        <CredentialReplaceSecretPage
          scope="organization"
          organizationId={p.organization_id}
          credentialId={p.credential_id}
        />
      );
    case "organization-provider-budgets":
      return <ProviderBudgetsPage organizationId={p.organization_id} me={me} />;
    case "organization-provider-budget-byok-edit":
      return (
        <ProviderBudgetEditPage
          organizationId={p.organization_id}
          origin="byok"
          returnHref={`/organizations/${encodeURIComponent(p.organization_id)}/provider-budgets`}
        />
      );
    case "organization-usage":
      return <UsagePage organizationId={p.organization_id} />;
    case "organization-management-keys":
      return <ManagementKeyListPage scope={organizationKeyScope(match)} me={me} />;
    case "organization-management-key-new":
      return <ManagementKeyCreatePage scope={organizationKeyScope(match)} me={me} />;
    case "organization-management-key-detail":
      return (
        <ManagementKeyDetailPage
          scope={organizationKeyScope(match)}
          keyId={p.management_api_key_id}
          me={me}
        />
      );
    case "organization-management-key-edit":
      return (
        <ManagementKeyEditPage
          scope={organizationKeyScope(match)}
          keyId={p.management_api_key_id}
        />
      );
    case "organization-management-key-rotate":
      return (
        <ManagementKeyRotatePage
          scope={organizationKeyScope(match)}
          keyId={p.management_api_key_id}
        />
      );
    case "organization-policy":
      return <KeyPolicyPage scope={organizationKeyScope(match)} me={me} />;
    case "organization-policy-edit":
      return <KeyPolicyEditPage scope={organizationKeyScope(match)} />;
    case "organization-audit":
      return <AuditPage organizationId={p.organization_id} />;
    case "organization-settings":
      return <OrganizationSettingsPage organizationId={p.organization_id} me={me} />;
    case "admin-overview":
      return <AdminOverviewPage me={me} />;
    case "admin-users":
      return <UsersPage me={me} />;
    case "admin-user-new":
      return <UserCreatePage />;
    case "admin-user-detail":
      return <UserDetailPage userId={p.user_id} me={me} />;
    case "admin-user-edit":
      return <UserEditPage userId={p.user_id} />;
    case "admin-organizations":
      return <AdminOrganizationsPage me={me} />;
    case "admin-organization-new":
      return <AdminOrganizationCreatePage />;
    case "admin-organization-detail":
      return <AdminOrganizationDetailPage organizationId={p.organization_id} me={me} />;
    case "admin-organization-edit":
      return <AdminOrganizationEditPage organizationId={p.organization_id} />;
    case "admin-organization-catalog-grants":
      return <CatalogGrantsPage organizationId={p.organization_id} />;
    case "admin-organization-system-provider-budget":
      return (
        <ProviderBudgetEditPage
          organizationId={p.organization_id}
          origin="system"
          returnHref={`/admin/organizations/${encodeURIComponent(p.organization_id)}`}
        />
      );
    case "admin-management-keys":
      return <ManagementKeyListPage scope={{ kind: "system" }} me={me} />;
    case "admin-management-key-new":
      return <ManagementKeyCreatePage scope={{ kind: "system" }} me={me} />;
    case "admin-management-key-detail":
      return (
        <ManagementKeyDetailPage
          scope={{ kind: "system" }}
          keyId={p.management_api_key_id}
          me={me}
        />
      );
    case "admin-management-key-edit":
      return <ManagementKeyEditPage scope={{ kind: "system" }} keyId={p.management_api_key_id} />;
    case "admin-management-key-rotate":
      return <ManagementKeyRotatePage scope={{ kind: "system" }} keyId={p.management_api_key_id} />;
    case "admin-management-key-policy":
      return <KeyPolicyPage scope={{ kind: "system" }} me={me} />;
    case "admin-management-key-policy-edit":
      return <KeyPolicyEditPage scope={{ kind: "system" }} />;
    case "admin-administrators":
      return <AdministratorsPage me={me} />;
    case "admin-issuers":
      return <IdentityIssuersPage me={me} />;
    case "admin-issuer-new":
      return <IdentityIssuerCreatePage />;
    case "admin-issuer-detail":
      return <IdentityIssuerDetailPage issuerId={p.issuer_id} me={me} />;
    case "admin-issuer-edit":
      return <IdentityIssuerEditPage issuerId={p.issuer_id} />;
    case "admin-bindings":
      return <IdentityBindingsPage me={me} />;
    case "admin-binding-new":
      return <IdentityBindingCreatePage />;
    case "admin-binding-detail":
      return <IdentityBindingDetailPage bindingId={p.binding_id} me={me} />;
    case "admin-provisioning-policies":
      return <ProvisioningPoliciesPage me={me} />;
    case "admin-provisioning-policy-new":
      return <ProvisioningPolicyCreatePage />;
    case "admin-provisioning-policy-detail":
      return <ProvisioningPolicyDetailPage policyId={p.policy_id} me={me} />;
    case "admin-provisioning-policy-edit":
      return <ProvisioningPolicyEditPage policyId={p.policy_id} />;
    case "admin-catalog-credential-replace-secret":
      return <CredentialReplaceSecretPage scope="system" credentialId={p.credential_id} />;
    case "admin-catalog-credential-codex-login":
      return <CodexLoginPage credentialId={p.credential_id} sessionId={p.login_session_id} />;
    case "admin-catalog-gateway-policy-ceilings":
      return (
        <SingletonPolicyPage
          operationFamily="system.gateway_policy_ceilings"
          title="Gateway policy ceilings"
          description="Deployment-wide singleton bounds for Gateway-key budgets and request-limit grants."
          editHref="/admin/catalog/gateway-policy-ceilings/edit"
          me={me}
        />
      );
    case "admin-catalog-gateway-policy-ceilings-edit":
      return (
        <SingletonPolicyEditPage
          operationFamily="system.gateway_policy_ceilings"
          title="Gateway policy ceilings"
          returnHref="/admin/catalog/gateway-policy-ceilings"
        />
      );
    case "admin-usage":
      return <UsagePage />;
    case "admin-audit":
      return <AuditPage />;
    default:
      if (match.route.id.startsWith("admin-operations"))
        return <OperationsPage routeId={match.route.id} me={me} />;
      return <NotFoundPage />;
  }
}

export function App() {
  const pathname = usePathname();
  const match = useMemo(() => matchRoute(pathname), [pathname]);
  const [session, setMe] = useSession(pathname);
  if (session.loading)
    return (
      <main className="public-page">
        <LoadingState label="Authorizing console session" />
      </main>
    );
  if (session.error !== null)
    return (
      <main className="public-page">
        <ApiErrorState
          error={session.error}
          retry={() => navigate(window.location.pathname, true)}
        />
      </main>
    );
  if (match === null) return <NotFoundPage />;
  if (match.route.id === "signed-out") return <SignedOutPage />;
  if (match.route.id === "forbidden") return <ForbiddenPage />;
  if (match.route.id === "not-found") return <NotFoundPage />;
  if (match.route.id === "sign-in") return <SignInPage me={session.me} />;
  if (match.route.id === "root")
    return <Redirect to={session.me === null ? "/sign-in" : defaultPath(session.me)} />;
  if (session.me === null) {
    const returnTo = CONSOLE_ROUTES.some((route) => route.id === match.route.id)
      ? `?return_to=${encodeURIComponent(`${window.location.pathname}${window.location.search}`)}`
      : "";
    return <Redirect to={`/sign-in${returnTo}`} />;
  }
  if (
    !guardAllows(match.route.guard, session.me, match.params) ||
    !routeHasCapability(match.route, session.me, match.params.organization_id)
  )
    return <Redirect to="/forbidden" />;
  return <AppShell match={match} me={session.me} onSignedOut={() => setMe(null)} />;
}
