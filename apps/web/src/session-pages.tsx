import { type FormEvent, useEffect, useMemo, useState } from "react";

import {
  ApiError,
  apiRequest,
  exchangeManagementKey,
  formatDate,
  type BrowserLoginIssuer,
  type CurrentPrincipal,
  type Page,
  type SessionView,
} from "./api";
import { operationAllows } from "./operation-authority";
import { defaultPath, isSafeReturnTo } from "./routes";
import {
  ApiErrorState,
  ConfirmAction,
  DefinitionList,
  EmptyState,
  Field,
  Id,
  Link,
  LoadingState,
  PageHeader,
  Pagination,
  Panel,
  Status,
  Table,
  humanize,
  navigate,
  useApiResource,
} from "./ui";

export function SignInPage({ me }: { me: CurrentPrincipal | null }) {
  const issuers = useApiResource<BrowserLoginIssuer[]>("/auth/v1/issuers");
  const [key, setKey] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const returnTo = useMemo(() => {
    const candidate = new URLSearchParams(window.location.search).get("return_to");
    return isSafeReturnTo(candidate) ? candidate : null;
  }, []);
  useEffect(() => {
    if (me !== null) navigate(defaultPath(me), true);
  }, [me]);

  if (me !== null) {
    return <LoadingState label="Opening your authorized context" />;
  }

  async function submit(event: FormEvent): Promise<void> {
    event.preventDefault();
    const raw = key;
    setKey("");
    setError(null);
    setSubmitting(true);
    try {
      await exchangeManagementKey(raw);
      navigate(returnTo ?? "/", true);
    } catch (caught: unknown) {
      setError(
        caught instanceof ApiError
          ? caught
          : new ApiError(0, "network_error", "The server could not be reached."),
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="public-page" id="main-content">
      <div className="sign-in-card">
        <div className="brand-lockup">
          <span className="brand-mark" aria-hidden="true">
            O
          </span>
          <div>
            <strong>OwlRora</strong>
            <span>Identity and management plane</span>
          </div>
        </div>
        <PageHeader
          title="Sign in"
          description="Choose an enabled identity provider or exchange a Management API key for a secure browser session."
        />
        <div className="sign-in-sections">
          <section>
            <h2>Continue with an identity provider</h2>
            {issuers.loading ? <LoadingState label="Loading identity providers" /> : null}
            {issuers.error === null ? null : (
              <ApiErrorState error={issuers.error} retry={issuers.reload} compact />
            )}
            {issuers.value !== null && issuers.value.length === 0 ? (
              <EmptyState
                title="No browser login providers"
                description="An administrator can configure an active OIDC browser-login profile."
              />
            ) : null}
            <div className="stack-actions">
              {issuers.value?.map((issuer) => {
                const query = returnTo === null ? "" : `?return_to=${encodeURIComponent(returnTo)}`;
                return (
                  <a
                    className="button button-secondary button-wide"
                    href={`/auth/v1/issuers/${encodeURIComponent(issuer.name)}/login${query}`}
                    key={issuer.name}
                  >
                    Continue with {issuer.display_name}
                  </a>
                );
              })}
            </div>
          </section>
          <div className="divider" role="separator">
            <span>or</span>
          </div>
          <section>
            <h2>Use a Management API key</h2>
            <p className="section-copy">
              This is a scoped control-plane credential, not a Gateway API key for LLM requests. A
              seed-administrator key grants full deployment authority.
            </p>
            {error === null ? null : <ApiErrorState error={error} compact />}
            <form onSubmit={(event) => void submit(event)} autoComplete="off">
              <Field
                label="Management API key"
                required
                help="The value is submitted once, immediately cleared, and never stored by the console."
              >
                <input
                  type="password"
                  name="management-api-key"
                  value={key}
                  onChange={(event) => setKey(event.target.value)}
                  autoComplete="off"
                  spellCheck={false}
                  required
                />
              </Field>
              <button
                className="button button-primary button-wide"
                type="submit"
                disabled={submitting || key.length === 0}
              >
                {submitting ? "Signing in…" : "Sign in with key"}
              </button>
            </form>
          </section>
        </div>
      </div>
    </main>
  );
}

export function ProfilePage({ me }: { me: CurrentPrincipal }) {
  const principal = me.principal;
  const actor =
    principal.kind === "seed_admin"
      ? "Seed administrator"
      : principal.kind === "local_user"
        ? "Local user"
        : principal.kind === "deployment_management_api_key"
          ? "Deployment automation"
          : "Organization automation";
  const stableId =
    principal.kind === "seed_admin"
      ? "seed_admin"
      : principal.kind === "local_user"
        ? principal.user_id
        : principal.management_api_key_id;
  return (
    <>
      <PageHeader
        title="Profile"
        description="Server-authoritative identity, authentication origin, and effective access for this session."
      />
      {principal.kind === "seed_admin" ? (
        <div className="alert alert-warning">
          <strong>Built-in API-key-only user</strong>
          <span>
            Seed administrator is not a durable local user, organization member, key owner, or
            Gateway principal. Rotate its configured key through deployment configuration.
          </span>
        </div>
      ) : null}
      <Panel title="Current actor">
        <DefinitionList
          items={[
            { label: "Actor", value: actor },
            { label: "Stable identity", value: <Id>{stableId}</Id> },
            {
              label: "Authentication origin",
              value: humanize(me.authentication_method),
            },
            {
              label: "Resource scope",
              value:
                me.resource_scope.kind === "deployment"
                  ? "Deployment"
                  : `Organization ${me.resource_scope.organization_id}`,
            },
            {
              label: "System administrator",
              value: <Status value={me.system_administrator ? "active" : "not_granted"} />,
            },
          ]}
        />
      </Panel>
      <Panel title="Effective Management API scopes">
        <div className="tag-list">
          {me.effective_management_scopes.map((scope) => (
            <span className="tag" key={scope}>
              {scope}
            </span>
          ))}
        </div>
      </Panel>
      <Panel title="Effective capabilities">
        {me.capabilities.length === 0 ? (
          <EmptyState
            title="No management capabilities"
            description="The current credential ceiling grants no resource actions."
          />
        ) : (
          <div className="tag-list">
            {me.capabilities.map((capability) => (
              <span className="tag" key={capability}>
                {humanize(capability)}
              </span>
            ))}
          </div>
        )}
      </Panel>
    </>
  );
}

export function OrganizationSelectorPage({ me }: { me: CurrentPrincipal }) {
  return (
    <>
      <PageHeader
        title="Organizations"
        description="Select an organization currently authorized for this local-user session."
      />
      {me.allowed_organizations.length === 0 ? (
        <EmptyState
          title="No organization access"
          description="You do not currently have an active organization membership."
          action={
            <Link className="button button-secondary" href="/profile">
              View profile
            </Link>
          }
        />
      ) : (
        <div className="card-grid">
          {me.allowed_organizations.map((organization) => (
            <Link
              href={`/organizations/${encodeURIComponent(organization.organization_id)}`}
              className="selection-card"
              key={organization.organization_id}
            >
              <strong>{organization.name}</strong>
              <span>
                {organization.role === null
                  ? humanize(organization.access_reason)
                  : humanize(organization.role)}
              </span>
              <Id>{organization.organization_id}</Id>
            </Link>
          ))}
        </div>
      )}
    </>
  );
}

export function SessionsPage({ me }: { me: CurrentPrincipal }) {
  const [cursor, setCursor] = useState<string | null>(null);
  const sessions = useApiResource<Page<SessionView>>(
    `/api/v1/me/sessions?limit=50${cursor === null ? "" : `&cursor=${encodeURIComponent(cursor)}`}`,
  );
  if (sessions.loading) {
    return <LoadingState label="Loading active sessions" />;
  }
  if (sessions.error !== null) {
    return <ApiErrorState error={sessions.error} retry={sessions.reload} />;
  }
  const items = sessions.value?.items ?? [];
  return (
    <>
      <PageHeader
        title="Sessions"
        description="Review browser sessions bound to this exact principal and revoke sessions you no longer use."
      />
      {items.length === 0 ? (
        <EmptyState
          title="No active sessions"
          description="No active browser sessions were returned for this principal."
        />
      ) : (
        <Panel>
          <Table
            columns={[
              { key: "session", label: "Session" },
              { key: "origin", label: "Authentication" },
              { key: "created", label: "Created" },
              { key: "expires", label: "Expires" },
              { key: "action", label: "Action" },
            ]}
            rows={items.map((session) => ({
              session: (
                <>
                  <Id>{session.id}</Id>
                  {session.current ? <Status value="current" /> : null}
                </>
              ),
              origin: humanize(session.authentication_method),
              created: formatDate(session.created_at),
              expires: formatDate(session.expires_at),
              action: session.current ? (
                <span className="muted">Use Sign out</span>
              ) : operationAllows(me, "me.sessions.revoke") ? (
                <ConfirmAction
                  title="Revoke this session"
                  consequence="The selected browser session will immediately lose management access."
                  label="Revoke session"
                  danger
                  onConfirm={async () => {
                    await apiRequest<void>(
                      `/api/v1/me/sessions/${encodeURIComponent(session.id)}/actions/revoke`,
                      { method: "POST" },
                    );
                    sessions.reload();
                  }}
                />
              ) : (
                <span className="muted">Not permitted</span>
              ),
            }))}
            getKey={(_, index) => items[index].id}
          />
        </Panel>
      )}
      <Pagination
        canContinue={sessions.value?.next_cursor !== null && sessions.value !== null}
        onContinue={() => setCursor(sessions.value?.next_cursor ?? null)}
      />
    </>
  );
}

export function SignedOutPage() {
  return (
    <main className="public-page" id="main-content">
      <Panel className="message-panel" title="You are signed out">
        <p>The browser session and CSRF material have been cleared.</p>
        <Link className="button button-primary" href="/sign-in">
          Sign in again
        </Link>
      </Panel>
    </main>
  );
}

export function ForbiddenPage() {
  return (
    <main className="public-page" id="main-content">
      <Panel className="message-panel" title="Access denied">
        <p>
          The current principal is not authorized for this console route. The server remains the
          authority for every resource request.
        </p>
        <Link className="button button-secondary" href="/">
          Return to an authorized context
        </Link>
      </Panel>
    </main>
  );
}

export function NotFoundPage() {
  return (
    <main className="public-page" id="main-content">
      <Panel className="message-panel" title="Resource not found">
        <p>The route is absent, stale, or concealed by the current authority boundary.</p>
        <Link className="button button-secondary" href="/">
          Return to OwlRora
        </Link>
      </Panel>
    </main>
  );
}
