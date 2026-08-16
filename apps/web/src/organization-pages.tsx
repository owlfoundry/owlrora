import { type FormEvent, useState } from "react";

import {
  ApiError,
  OutcomeUnknownError,
  apiRequest,
  formatDate,
  type CurrentPrincipal,
  type Invitation,
  type Membership,
  type OneTimeInvitation,
  type Organization,
  type OrganizationRole,
  type Page,
} from "./api";
import { operationAllows } from "./operation-authority";
import { hasCapability } from "./routes";
import {
  ApiErrorState,
  ConfirmAction,
  ConflictState,
  DefinitionList,
  EmptyState,
  Field,
  FormError,
  Id,
  Link,
  LoadingState,
  OneTimeReveal,
  OutcomeUnknownState,
  PageHeader,
  Pagination,
  Panel,
  Status,
  SubmitBar,
  Table,
  humanize,
  navigate,
  useApiResource,
  useIdempotencyKey,
  useUnsavedChanges,
} from "./ui";

function organizationBase(organizationId: string): string {
  return `/organizations/${encodeURIComponent(organizationId)}`;
}

function apiOrganizationBase(organizationId: string): string {
  return `/api/v1/organizations/${encodeURIComponent(organizationId)}`;
}

function splitScopes(value: string): string[] {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter((item, index, values) => item.length > 0 && values.indexOf(item) === index);
}

function canOperate(me: CurrentPrincipal, organizationId: string, operationId: string): boolean {
  return operationAllows(me, operationId, organizationId);
}

function canManageRole(
  me: CurrentPrincipal,
  organizationId: string,
  operationId: string,
  role: OrganizationRole,
): boolean {
  return (
    canOperate(me, organizationId, operationId) &&
    (role !== "owner" || hasCapability(me, "manage_owners", organizationId))
  );
}

export function OrganizationOverviewPage({
  organizationId,
  me,
}: {
  organizationId: string;
  me: CurrentPrincipal;
}) {
  const organization = useApiResource<Organization>(apiOrganizationBase(organizationId));
  if (organization.loading) {
    return <LoadingState label="Loading organization" />;
  }
  if (organization.error !== null) {
    return <ApiErrorState error={organization.error} retry={organization.reload} />;
  }
  if (organization.value === null) {
    return null;
  }
  const value = organization.value;
  const allowed = me.allowed_organizations.find((item) => item.organization_id === organizationId);
  const systemAccess = allowed === undefined && me.system_administrator;
  return (
    <>
      <PageHeader
        eyebrow={systemAccess ? "System administrator access" : "Organization workspace"}
        title={value.name}
        description="Identity, membership, automation authority, policy, and immutable management evidence for this tenant."
        actions={
          canOperate(me, organizationId, "organization.update") ? (
            <Link
              className="button button-secondary"
              href={`${organizationBase(organizationId)}/settings`}
            >
              Organization settings
            </Link>
          ) : undefined
        }
      />
      {systemAccess ? (
        <div className="alert alert-warning">
          <strong>System administrator access</strong>
          <span>
            You are operating in explicit tenant context without a fabricated membership. All
            accepted changes are attributed to the current system principal.
          </span>
        </div>
      ) : null}
      <div className="metric-grid">
        <div className="metric-card">
          <span>Lifecycle</span>
          <Status value={value.status} />
        </div>
        <div className="metric-card">
          <span>Organization kind</span>
          <strong>{humanize(value.kind)}</strong>
        </div>
        <div className="metric-card">
          <span>Access reason</span>
          <strong>
            {systemAccess ? "System authority" : humanize(allowed?.access_reason ?? "organization")}
          </strong>
        </div>
      </div>
      <Panel title="Organization identity">
        <DefinitionList
          items={[
            { label: "Organization ID", value: <Id>{value.id}</Id> },
            { label: "Name", value: value.name },
            { label: "Slug", value: value.slug ?? "Not set" },
            { label: "Created", value: formatDate(value.created_at) },
            { label: "Updated", value: formatDate(value.updated_at) },
          ]}
        />
      </Panel>
      <Panel
        title="Module I controls"
        description="Only implemented identity and management-plane resources are exposed in this release."
      >
        <div className="action-grid">
          {canOperate(me, organizationId, "organization.memberships.list") ? (
            <Link className="action-card" href={`${organizationBase(organizationId)}/members`}>
              <strong>Members</strong>
              <span>Roles, scope ceilings, and owner invariants</span>
            </Link>
          ) : null}
          {canOperate(me, organizationId, "organization.invitations.list") ? (
            <Link className="action-card" href={`${organizationBase(organizationId)}/invitations`}>
              <strong>Invitations</strong>
              <span>One-time onboarding tokens and lifecycle</span>
            </Link>
          ) : null}
          {canOperate(me, organizationId, "organization.management_keys.list") ? (
            <Link
              className="action-card"
              href={`${organizationBase(organizationId)}/management-api-keys`}
            >
              <strong>Management API keys</strong>
              <span>Organization automation principals</span>
            </Link>
          ) : canOperate(me, organizationId, "organization.management_keys.create") ? (
            <Link
              className="action-card"
              href={`${organizationBase(organizationId)}/management-api-keys/new`}
            >
              <strong>Create Management API key</strong>
              <span>Policy-bounded member self-service issuance</span>
            </Link>
          ) : null}
          {canOperate(me, organizationId, "organization.api_key_policy.get") ? (
            <Link
              className="action-card"
              href={`${organizationBase(organizationId)}/api-key-policy`}
            >
              <strong>API key policy</strong>
              <span>Issuance and authority ceilings</span>
            </Link>
          ) : null}
          {canOperate(me, organizationId, "organization.audit.list") ? (
            <Link className="action-card" href={`${organizationBase(organizationId)}/audit`}>
              <strong>Audit</strong>
              <span>Organization-qualified immutable evidence</span>
            </Link>
          ) : null}
        </div>
      </Panel>
    </>
  );
}

export function MembersPage({
  organizationId,
  me,
}: {
  organizationId: string;
  me: CurrentPrincipal;
}) {
  const [cursor, setCursor] = useState<string | null>(null);
  const path = `${apiOrganizationBase(organizationId)}/memberships?limit=50${cursor === null ? "" : `&cursor=${encodeURIComponent(cursor)}`}`;
  const memberships = useApiResource<Page<Membership>>(path);
  const [userId, setUserId] = useState("");
  const [role, setRole] = useState<OrganizationRole>("member");
  const [scopeText, setScopeText] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const idempotencyKeyFor = useIdempotencyKey();
  const discardChanges = useUnsavedChanges(
    userId.length > 0 || role !== "member" || scopeText.length > 0,
  );

  async function create(event: FormEvent): Promise<void> {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    const body = {
      user_id: userId.trim(),
      role,
      llm_scope_ceiling: splitScopes(scopeText),
      llm_capability_ceiling: [],
      llm_route_ceiling: { kind: "none" },
    };
    try {
      await apiRequest<Membership>(
        `${apiOrganizationBase(organizationId)}/memberships/actions/create`,
        {
          method: "POST",
          idempotencyKey: idempotencyKeyFor(body),
          body,
        },
      );
      discardChanges();
      setUserId("");
      setScopeText("");
      memberships.reload();
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
    <>
      <PageHeader
        title="Members"
        description="Active organization memberships, role authority, and LLM scope ceilings."
      />
      {canOperate(me, organizationId, "organization.memberships.create") ? (
        <Panel
          title="Add an existing local user"
          description="Owner changes remain subject to the server's active-owner invariant."
        >
          {error === null ? null : <ApiErrorState error={error} compact />}
          <form className="form-grid" onSubmit={(event) => void create(event)}>
            <Field label="User ID" required>
              <input value={userId} onChange={(event) => setUserId(event.target.value)} required />
            </Field>
            <Field label="Role" required>
              <select
                value={role}
                onChange={(event) => setRole(event.target.value as OrganizationRole)}
              >
                <option value="member">Member</option>
                <option value="admin">Admin</option>
                {hasCapability(me, "manage_owners", organizationId) ? (
                  <option value="owner">Owner</option>
                ) : null}
              </select>
            </Field>
            <Field
              label="LLM scope ceiling"
              help="Optional comma-separated scopes. Empty means no LLM scopes."
            >
              <input value={scopeText} onChange={(event) => setScopeText(event.target.value)} />
            </Field>
            <div className="field field-actions">
              <button className="button button-primary" type="submit" disabled={submitting}>
                {submitting ? "Adding…" : "Add member"}
              </button>
            </div>
          </form>
        </Panel>
      ) : null}
      {memberships.loading ? <LoadingState label="Loading members" /> : null}
      {memberships.error === null ? null : (
        <ApiErrorState error={memberships.error} retry={memberships.reload} />
      )}
      {memberships.value?.items.length === 0 ? (
        <EmptyState
          title="No members"
          description="This organization currently has no visible active memberships."
        />
      ) : null}
      {memberships.value !== null && memberships.value.items.length > 0 ? (
        <Panel>
          <Table
            columns={[
              { key: "user", label: "User" },
              { key: "role", label: "Role" },
              { key: "scopes", label: "LLM scope ceiling" },
              { key: "status", label: "Status" },
              { key: "updated", label: "Updated" },
            ]}
            rows={memberships.value.items.map((membership) => ({
              user: (
                <Link
                  href={`${organizationBase(organizationId)}/members/${encodeURIComponent(membership.user_id)}`}
                >
                  <Id>{membership.user_id}</Id>
                </Link>
              ),
              role: humanize(membership.role),
              scopes:
                membership.llm_scope_ceiling.length === 0
                  ? "None"
                  : membership.llm_scope_ceiling.join(", "),
              status: <Status value={membership.status} />,
              updated: formatDate(membership.updated_at),
            }))}
            getKey={(_, index) => memberships.value?.items[index].id ?? String(index)}
          />
          {memberships.value.next_cursor === null ? null : (
            <button
              className="button button-secondary pagination"
              type="button"
              onClick={() => setCursor(memberships.value?.next_cursor ?? null)}
            >
              Next page
            </button>
          )}
        </Panel>
      ) : null}
    </>
  );
}

export function MemberDetailPage({
  organizationId,
  userId,
  me,
}: {
  organizationId: string;
  userId: string;
  me: CurrentPrincipal;
}) {
  const path = `${apiOrganizationBase(organizationId)}/memberships/${encodeURIComponent(userId)}`;
  const membership = useApiResource<Membership>(path);
  const [role, setRole] = useState<OrganizationRole | null>(null);
  const [scopeText, setScopeText] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [conflict, setConflict] = useState(false);
  const discardChanges = useUnsavedChanges(role !== null || scopeText !== null);

  if (membership.loading) return <LoadingState label="Loading membership" />;
  if (membership.error !== null)
    return <ApiErrorState error={membership.error} retry={membership.reload} />;
  if (membership.value === null) return null;
  const value = membership.value;
  const selectedRole = role ?? value.role;
  const selectedScopes = scopeText ?? value.llm_scope_ceiling.join(", ");
  const candidate = {
    role: selectedRole,
    llm_scope_ceiling: splitScopes(selectedScopes),
    llm_capability_ceiling: value.llm_capability_ceiling,
    llm_route_ceiling: value.llm_route_ceiling,
  };

  async function save(event: FormEvent): Promise<void> {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    setConflict(false);
    try {
      const response = await apiRequest<Membership>(`${path}/actions/update`, {
        method: "POST",
        ifMatch: membership.etag ?? undefined,
        body: candidate,
      });
      membership.replace(response);
      discardChanges();
      setRole(null);
      setScopeText(null);
    } catch (caught: unknown) {
      if (caught instanceof ApiError && (caught.status === 412 || caught.status === 428))
        setConflict(true);
      else
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
    <>
      <PageHeader
        title="Member"
        description="Role and scope authority for one stable local-user identity."
      />
      <Panel title="Membership evidence">
        <DefinitionList
          items={[
            { label: "User ID", value: <Id>{value.user_id}</Id> },
            { label: "Membership ID", value: <Id>{value.id}</Id> },
            { label: "Status", value: <Status value={value.status} /> },
            { label: "Created", value: formatDate(value.created_at) },
            { label: "Updated", value: formatDate(value.updated_at) },
          ]}
        />
      </Panel>
      {conflict ? (
        <ConflictState
          candidate={candidate}
          reload={() => {
            discardChanges();
            setRole(null);
            setScopeText(null);
            setConflict(false);
            membership.reload();
          }}
        />
      ) : null}
      {canManageRole(me, organizationId, "organization.memberships.update", value.role) &&
      !conflict ? (
        <Panel title="Edit membership">
          {error === null ? null : <ApiErrorState error={error} compact />}
          <form onSubmit={(event) => void save(event)}>
            <Field label="Role" required>
              <select
                value={selectedRole}
                onChange={(event) => setRole(event.target.value as OrganizationRole)}
              >
                <option value="member">Member</option>
                <option value="admin">Admin</option>
                {hasCapability(me, "manage_owners", organizationId) ? (
                  <option value="owner">Owner</option>
                ) : null}
              </select>
            </Field>
            <Field label="LLM scope ceiling" help="Comma-separated stable scope values.">
              <input
                value={selectedScopes}
                onChange={(event) => setScopeText(event.target.value)}
              />
            </Field>
            <SubmitBar
              submitting={submitting}
              submitLabel="Save changes"
              cancelHref={`${organizationBase(organizationId)}/members`}
            />
          </form>
        </Panel>
      ) : null}
      {canManageRole(me, organizationId, "organization.memberships.remove", value.role) ? (
        <Panel title="Remove membership" className="danger-zone">
          <ConfirmAction
            title={`Remove ${value.user_id}`}
            consequence="The user loses organization access and their matching external sessions are revoked. Organization-owned resources remain owned by the organization. The last active owner cannot be removed."
            label="Remove member"
            danger
            onConfirm={async () => {
              await apiRequest<void>(`${path}/actions/remove`, { method: "POST" });
              navigate(`${organizationBase(organizationId)}/members`, true);
            }}
          />
        </Panel>
      ) : null}
    </>
  );
}

export function InvitationsPage({
  organizationId,
  me,
}: {
  organizationId: string;
  me: CurrentPrincipal;
}) {
  const path = `${apiOrganizationBase(organizationId)}/invitations`;
  const [cursor, setCursor] = useState<string | null>(null);
  const invitations = useApiResource<Page<Invitation>>(
    `${path}?limit=50${cursor === null ? "" : `&cursor=${encodeURIComponent(cursor)}`}`,
  );
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<OrganizationRole>("member");
  const [scopeText, setScopeText] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [oneTime, setOneTime] = useState<OneTimeInvitation | null>(null);
  const [outcomeUnknown, setOutcomeUnknown] = useState<OutcomeUnknownError | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const discardChanges = useUnsavedChanges(
    oneTime === null &&
      outcomeUnknown === null &&
      (email.length > 0 || role !== "member" || scopeText.length > 0 || expiresAt.length > 0),
  );

  async function create(event: FormEvent): Promise<void> {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const response = await apiRequest<OneTimeInvitation>(`${path}/actions/create`, {
        method: "POST",
        body: {
          intended_email: email.trim() === "" ? null : email.trim(),
          intended_role: role,
          llm_scope_ceiling: splitScopes(scopeText),
          llm_capability_ceiling: [],
          llm_route_ceiling: { kind: "none" },
          expires_at: new Date(expiresAt).toISOString(),
        },
        nonRepeatable: true,
      });
      discardChanges();
      setEmail("");
      setScopeText("");
      setExpiresAt("");
      setOneTime(response.value);
      invitations.reload();
    } catch (caught: unknown) {
      if (caught instanceof OutcomeUnknownError) {
        discardChanges();
        setOutcomeUnknown(caught);
      } else {
        setError(
          caught instanceof ApiError
            ? caught
            : new ApiError(0, "network_error", "The server could not be reached."),
        );
      }
    } finally {
      setSubmitting(false);
    }
  }

  async function reissue(invitationId: string): Promise<void> {
    setError(null);
    try {
      const response = await apiRequest<OneTimeInvitation>(
        `${path}/${encodeURIComponent(invitationId)}/actions/resend`,
        { method: "POST", nonRepeatable: true },
      );
      discardChanges();
      setOneTime(response.value);
      invitations.reload();
    } catch (caught: unknown) {
      if (caught instanceof OutcomeUnknownError) {
        discardChanges();
        setOutcomeUnknown(caught);
      } else {
        setError(
          caught instanceof ApiError
            ? caught
            : new ApiError(0, "network_error", "The server could not be reached."),
        );
      }
    }
  }

  if (outcomeUnknown !== null) {
    return (
      <OutcomeUnknownState
        command="the invitation token issuance"
        requestId={outcomeUnknown.requestId}
        recoveryHref={`${organizationBase(organizationId)}/invitations`}
        committed={outcomeUnknown.committed}
        oneTimeMaterial
      />
    );
  }

  if (oneTime !== null) {
    return (
      <>
        <PageHeader
          title="Invitation token"
          description="One-time onboarding material for a local user."
        />
        <OneTimeReveal
          credentialClass="Invitation"
          secret={oneTime.token}
          doneHref={`${organizationBase(organizationId)}/invitations`}
          onDone={() => setOneTime(null)}
          metadata={
            <DefinitionList
              items={[
                { label: "Invitation", value: <Id>{oneTime.invitation.id}</Id> },
                { label: "Role", value: humanize(oneTime.invitation.intended_role) },
                { label: "Expires", value: formatDate(oneTime.invitation.expires_at) },
              ]}
            />
          }
        />
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Invitations"
        description="Create, reissue, and revoke bounded organization onboarding tokens."
      />
      {canOperate(me, organizationId, "organization.invitations.create") ? (
        <Panel
          title="Create invitation"
          description="The raw token is returned once. This command is never automatically retried."
        >
          {error === null ? null : <ApiErrorState error={error} compact />}
          <form className="form-grid" onSubmit={(event) => void create(event)}>
            <Field label="Intended email" help="Optional matching evidence; not an authority key.">
              <input
                type="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
              />
            </Field>
            <Field label="Role" required>
              <select
                value={role}
                onChange={(event) => setRole(event.target.value as OrganizationRole)}
              >
                <option value="member">Member</option>
                <option value="admin">Admin</option>
                {hasCapability(me, "manage_owners", organizationId) ? (
                  <option value="owner">Owner</option>
                ) : null}
              </select>
            </Field>
            <Field label="Expires at" required>
              <input
                type="datetime-local"
                value={expiresAt}
                onChange={(event) => setExpiresAt(event.target.value)}
                required
              />
            </Field>
            <Field label="LLM scope ceiling" help="Optional comma-separated scopes.">
              <input value={scopeText} onChange={(event) => setScopeText(event.target.value)} />
            </Field>
            <div className="field field-actions">
              <button className="button button-primary" type="submit" disabled={submitting}>
                {submitting ? "Creating…" : "Create invitation"}
              </button>
            </div>
          </form>
        </Panel>
      ) : null}
      {invitations.loading ? <LoadingState label="Loading invitations" /> : null}
      {invitations.error === null ? null : (
        <ApiErrorState error={invitations.error} retry={invitations.reload} />
      )}
      {invitations.value?.items.length === 0 ? (
        <EmptyState
          title="No invitations"
          description="No invitations are visible in this organization."
        />
      ) : null}
      {invitations.value !== null && invitations.value.items.length > 0 ? (
        <div className="list-stack">
          {invitations.value.items.map((invitation) => (
            <Panel key={invitation.id}>
              <div className="row-summary">
                <div>
                  <strong>{invitation.intended_email ?? "Any eligible local user"}</strong>
                  <Id>{invitation.id}</Id>
                </div>
                <Status value={invitation.state} />
              </div>
              <DefinitionList
                items={[
                  { label: "Intended role", value: humanize(invitation.intended_role) },
                  { label: "Expires", value: formatDate(invitation.expires_at) },
                  {
                    label: "Accepted by",
                    value:
                      invitation.accepted_by_user_id === null ? (
                        "Not accepted"
                      ) : (
                        <Id>{invitation.accepted_by_user_id}</Id>
                      ),
                  },
                ]}
              />
              {canManageRole(
                me,
                organizationId,
                "organization.invitations.revoke",
                invitation.intended_role,
              ) ? (
                <div className="inline-actions">
                  {canManageRole(
                    me,
                    organizationId,
                    "organization.invitations.resend",
                    invitation.intended_role,
                  ) && invitation.state === "pending" ? (
                    <button
                      className="button button-secondary"
                      type="button"
                      onClick={() => void reissue(invitation.id)}
                    >
                      Reissue token
                    </button>
                  ) : null}
                  {invitation.state === "pending" ? (
                    <ConfirmAction
                      title="Revoke invitation"
                      consequence="The outstanding token becomes unusable. Existing memberships are not changed."
                      label="Revoke"
                      danger
                      onConfirm={async () => {
                        await apiRequest<void>(
                          `${path}/${encodeURIComponent(invitation.id)}/actions/revoke`,
                          { method: "POST" },
                        );
                        invitations.reload();
                      }}
                    />
                  ) : null}
                </div>
              ) : null}
            </Panel>
          ))}
        </div>
      ) : null}
      <Pagination
        canContinue={invitations.value?.next_cursor !== null && invitations.value !== null}
        onContinue={() => setCursor(invitations.value?.next_cursor ?? null)}
      />
    </>
  );
}

export function OrganizationSettingsPage({
  organizationId,
  me,
}: {
  organizationId: string;
  me: CurrentPrincipal;
}) {
  const path = apiOrganizationBase(organizationId);
  const organization = useApiResource<Organization>(path);
  const [name, setName] = useState<string | null>(null);
  const [slug, setSlug] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [apiError, setApiError] = useState<ApiError | null>(null);
  const [conflict, setConflict] = useState(false);
  const discardChanges = useUnsavedChanges(name !== null || slug !== null);
  if (organization.loading) return <LoadingState label="Loading organization settings" />;
  if (organization.error !== null)
    return <ApiErrorState error={organization.error} retry={organization.reload} />;
  if (organization.value === null) return null;
  const current = organization.value;
  const candidate = {
    name: name ?? current.name,
    slug: (slug ?? current.slug ?? "").trim() === "" ? null : (slug ?? current.slug),
  };
  if (!canOperate(me, organizationId, "organization.update")) {
    return (
      <>
        <PageHeader
          title="Organization settings"
          description="Tenant-owned profile settings. Lifecycle suspension remains a system administration action."
        />
        <Panel title="Profile">
          <DefinitionList
            items={[
              { label: "Name", value: current.name },
              { label: "Slug", value: current.slug ?? "Not set" },
              { label: "Status", value: <Status value={current.status} /> },
            ]}
          />
          <div className="alert alert-info">
            <strong>Read-only access</strong>
            <span>The current session can view but cannot update this organization.</span>
          </div>
        </Panel>
      </>
    );
  }

  async function save(event: FormEvent): Promise<void> {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    setApiError(null);
    setConflict(false);
    if (!canOperate(me, organizationId, "organization.update")) {
      setError("The current session cannot update this organization.");
      setSubmitting(false);
      return;
    }
    try {
      const response = await apiRequest<Organization>(`${path}/actions/update`, {
        method: "POST",
        ifMatch: organization.etag ?? undefined,
        body: candidate,
      });
      organization.replace(response);
      discardChanges();
      navigate(organizationBase(organizationId), true);
    } catch (caught: unknown) {
      if (caught instanceof ApiError && (caught.status === 412 || caught.status === 428))
        setConflict(true);
      else
        setApiError(
          caught instanceof ApiError
            ? caught
            : new ApiError(0, "network_error", "The server could not be reached."),
        );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <>
      <PageHeader
        title="Organization settings"
        description="Tenant-owned profile settings. Lifecycle suspension remains a system administration action."
      />
      {conflict ? (
        <ConflictState
          candidate={candidate}
          reload={() => {
            discardChanges();
            setName(null);
            setSlug(null);
            setConflict(false);
            organization.reload();
          }}
        />
      ) : (
        <Panel title="Profile">
          <FormError message={error} />
          {apiError === null ? null : <ApiErrorState error={apiError} compact />}
          <form onSubmit={(event) => void save(event)}>
            <Field label="Name" required>
              <input
                value={name ?? current.name}
                onChange={(event) => setName(event.target.value)}
                required
              />
            </Field>
            <Field
              label="Slug"
              help="Optional display/discovery value. The stable organization ID remains the authority key."
            >
              <input
                value={slug ?? current.slug ?? ""}
                onChange={(event) => setSlug(event.target.value)}
              />
            </Field>
            <SubmitBar
              submitting={submitting}
              submitLabel="Save changes"
              cancelHref={organizationBase(organizationId)}
            />
          </form>
        </Panel>
      )}
    </>
  );
}
