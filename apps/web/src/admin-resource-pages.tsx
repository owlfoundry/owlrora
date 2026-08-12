import { type FormEvent, useState } from "react";

import {
  ApiError,
  apiRequest,
  formatDate,
  type AdministratorGrant,
  type CurrentPrincipal,
  type Organization,
  type OrganizationKind,
  type OrganizationStatus,
  type Page,
  type User,
  type UserKind,
  type UserStatus,
} from "./api";
import { operationAllows } from "./operation-authority";
import {
  ApiErrorState,
  ConfirmAction,
  ConflictState,
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
  SubmitBar,
  Table,
  humanize,
  navigate,
  useApiResource,
  useIdempotencyKey,
  useUnsavedChanges,
} from "./ui";

type OperationsOverview = {
  counts: {
    active_identity_issuers: number;
    active_organizations: number;
    active_sessions: number;
    active_users: number;
  };
  readiness: {
    database: string;
    database_revision: number;
    publication_error: string | null;
    ready: boolean;
    runtime_age_seconds: number;
    runtime_revision: number;
  };
};

export function AdminOverviewPage({ me }: { me: CurrentPrincipal }) {
  const operations = useApiResource<OperationsOverview>("/api/v1/system/operations");
  return (
    <>
      <PageHeader
        eyebrow="Deployment context"
        title="Admin"
        description="Identity, tenancy, automation authority, runtime publication, and protected operations for this OwlRora deployment."
      />
      <div className="metric-grid">
        <div className="metric-card">
          <span>Actor authority</span>
          <Status value={me.system_administrator ? "active" : "not_granted"} />
        </div>
        <div className="metric-card">
          <span>Management scopes</span>
          <strong>{me.effective_management_scopes.length}</strong>
        </div>
        <div className="metric-card">
          <span>Module</span>
          <strong>Identity and management plane</strong>
        </div>
      </div>
      <Panel title="Operations posture">
        {operations.loading ? <LoadingState label="Loading protected operations evidence" /> : null}
        {operations.error !== null ? (
          <div className="alert alert-warning">
            <strong>Operations evidence unavailable</strong>
            <span>
              The current scope or operator-network policy does not permit protected diagnostics.
              Safe identity and tenant controls remain available; the console does not reconstruct
              diagnostics from ordinary APIs.
            </span>
          </div>
        ) : null}
        {operations.value === null ? null : (
          <>
            <div className="metric-grid">
              <div className="metric-card">
                <span>Readiness</span>
                <Status value={operations.value.readiness.ready ? "ready" : "not_ready"} />
              </div>
              <div className="metric-card">
                <span>Active users</span>
                <strong>{operations.value.counts.active_users}</strong>
              </div>
              <div className="metric-card">
                <span>Active organizations</span>
                <strong>{operations.value.counts.active_organizations}</strong>
              </div>
              <div className="metric-card">
                <span>Active sessions</span>
                <strong>{operations.value.counts.active_sessions}</strong>
              </div>
            </div>
            <DefinitionList
              items={[
                { label: "Database", value: humanize(operations.value.readiness.database) },
                {
                  label: "Runtime revision",
                  value: String(operations.value.readiness.runtime_revision),
                },
                {
                  label: "Database revision",
                  value: String(operations.value.readiness.database_revision),
                },
                {
                  label: "Publication error",
                  value: operations.value.readiness.publication_error ?? "None",
                },
              ]}
            />
            <Link className="button button-secondary" href="/admin/operations">
              View operations evidence
            </Link>
          </>
        )}
      </Panel>
      <Panel title="Identity and access">
        <div className="action-grid">
          <Link className="action-card" href="/admin/users">
            <strong>Users</strong>
            <span>Human and synthetic local identities</span>
          </Link>
          <Link className="action-card" href="/admin/organizations">
            <strong>Organizations</strong>
            <span>Tenant lifecycle and workspace access</span>
          </Link>
          <Link className="action-card" href="/admin/management-api-keys">
            <strong>Management API keys</strong>
            <span>Deployment automation principals</span>
          </Link>
          <Link className="action-card" href="/admin/administrators">
            <strong>System administrators</strong>
            <span>Built-in and durable typed grants</span>
          </Link>
          <Link className="action-card" href="/admin/identity/issuers">
            <strong>Identity issuers</strong>
            <span>Direct JWT and optional OIDC browser login</span>
          </Link>
          <Link className="action-card" href="/admin/operations">
            <strong>Operations</strong>
            <span>Protected readiness and publication evidence</span>
          </Link>
        </div>
      </Panel>
    </>
  );
}

export function UsersPage({ me }: { me: CurrentPrincipal }) {
  const [cursor, setCursor] = useState<string | null>(null);
  const users = useApiResource<Page<User>>(
    `/api/v1/system/users?limit=50${cursor === null ? "" : `&cursor=${encodeURIComponent(cursor)}`}`,
  );
  if (users.loading) return <LoadingState label="Loading users" />;
  if (users.error !== null) return <ApiErrorState error={users.error} retry={users.reload} />;
  const items = users.value?.items ?? [];
  return (
    <>
      <PageHeader
        title="Users"
        description="Durable human and synthetic local identities. Seed administrator is intentionally absent from this collection."
        actions={
          operationAllows(me, "system.users.create") ? (
            <Link className="button button-primary" href="/admin/users/new">
              Create user
            </Link>
          ) : undefined
        }
      />
      {items.length === 0 ? (
        <EmptyState title="No users" description="No durable local users are currently visible." />
      ) : (
        <Panel>
          <Table
            columns={[
              { key: "identity", label: "Identity" },
              { key: "kind", label: "Kind" },
              { key: "status", label: "Status" },
              { key: "email", label: "Primary email" },
              { key: "updated", label: "Updated" },
            ]}
            rows={items.map((user) => ({
              identity: (
                <Link href={`/admin/users/${encodeURIComponent(user.id)}`}>
                  <strong>{user.display_name}</strong>
                  <Id>{user.id}</Id>
                </Link>
              ),
              kind: humanize(user.kind),
              status: <Status value={user.status} />,
              email: user.primary_email ?? "Not set",
              updated: formatDate(user.updated_at),
            }))}
            getKey={(_, index) => items[index].id}
          />
        </Panel>
      )}
      <Pagination
        canContinue={users.value?.next_cursor !== null && users.value !== null}
        onContinue={() => setCursor(users.value?.next_cursor ?? null)}
      />
    </>
  );
}

export function UserCreatePage() {
  const [kind, setKind] = useState<UserKind>("human");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const idempotencyKeyFor = useIdempotencyKey();
  const discardChanges = useUnsavedChanges(kind !== "human" || name !== "" || email !== "");
  async function create(event: FormEvent): Promise<void> {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    const body = {
      kind,
      display_name: name.trim(),
      primary_email: email.trim() === "" ? null : email.trim(),
    };
    try {
      const response = await apiRequest<User>("/api/v1/system/users/actions/create", {
        method: "POST",
        idempotencyKey: idempotencyKeyFor(body),
        body,
      });
      discardChanges();
      navigate(`/admin/users/${encodeURIComponent(response.value.id)}`, true);
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
        title="Create user"
        description="Create a durable local identity. External authentication is attached separately through an identity binding."
      />
      <Panel title="User identity">
        {error === null ? null : <ApiErrorState error={error} compact />}
        <form onSubmit={(event) => void create(event)}>
          <Field label="Kind" required>
            <select value={kind} onChange={(event) => setKind(event.target.value as UserKind)}>
              <option value="human">Human</option>
              <option value="synthetic">Synthetic</option>
            </select>
          </Field>
          <Field label="Display name" required>
            <input value={name} onChange={(event) => setName(event.target.value)} required />
          </Field>
          <Field
            label="Primary email"
            help="Optional identity metadata; never an authorization key."
          >
            <input type="email" value={email} onChange={(event) => setEmail(event.target.value)} />
          </Field>
          <SubmitBar submitting={submitting} submitLabel="Create user" cancelHref="/admin/users" />
        </form>
      </Panel>
    </>
  );
}

export function UserDetailPage({ userId, me }: { userId: string; me: CurrentPrincipal }) {
  const user = useApiResource<User>(`/api/v1/system/users/${encodeURIComponent(userId)}`);
  if (user.loading) return <LoadingState label="Loading user" />;
  if (user.error !== null) return <ApiErrorState error={user.error} retry={user.reload} />;
  if (user.value === null) return null;
  const value = user.value;
  return (
    <>
      <PageHeader
        title={value.display_name}
        description="Durable identity metadata and explicit deployment authority transitions."
        actions={
          operationAllows(me, "system.users.update") ? (
            <Link
              className="button button-secondary"
              href={`/admin/users/${encodeURIComponent(userId)}/edit`}
            >
              Edit user
            </Link>
          ) : undefined
        }
      />
      <Panel title="Identity">
        <DefinitionList
          items={[
            { label: "User ID", value: <Id>{value.id}</Id> },
            { label: "Kind", value: humanize(value.kind) },
            { label: "Status", value: <Status value={value.status} /> },
            { label: "Primary email", value: value.primary_email ?? "Not set" },
            { label: "Created", value: formatDate(value.created_at) },
            { label: "Updated", value: formatDate(value.updated_at) },
          ]}
        />
      </Panel>
      {operationAllows(me, "system.administrators.grant") ? (
        <Panel
          title="System administrator authority"
          description="Email, issuer claims, organization ownership, and creator identity never imply this grant."
        >
          <ConfirmAction
            title={`Grant system administrator to ${value.display_name}`}
            consequence="This active local user will receive deployment-wide system authority through a separately persisted typed grant. Current authentication scope and issuer ceilings continue to apply."
            label="Grant system administrator"
            onConfirm={async () => {
              await apiRequest<void>("/api/v1/system/administrators/actions/grant", {
                method: "POST",
                body: { subject_kind: "local_user", subject_id: value.id },
              });
            }}
          />
        </Panel>
      ) : null}
    </>
  );
}

export function UserEditPage({ userId }: { userId: string }) {
  const path = `/api/v1/system/users/${encodeURIComponent(userId)}`;
  const user = useApiResource<User>(path);
  const [name, setName] = useState<string | null>(null);
  const [email, setEmail] = useState<string | null>(null);
  const [status, setStatus] = useState<UserStatus | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [conflict, setConflict] = useState(false);
  const discardChanges = useUnsavedChanges(name !== null || email !== null || status !== null);
  if (user.loading) return <LoadingState label="Loading user editor" />;
  if (user.error !== null) return <ApiErrorState error={user.error} retry={user.reload} />;
  if (user.value === null) return null;
  const current = user.value;
  const candidate = {
    display_name: name ?? current.display_name,
    primary_email:
      (email ?? current.primary_email ?? "").trim() === ""
        ? null
        : (email ?? current.primary_email),
    status: status ?? current.status,
  };
  async function save(event: FormEvent): Promise<void> {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    setConflict(false);
    try {
      await apiRequest<User>(`${path}/actions/update`, {
        method: "POST",
        ifMatch: user.etag ?? undefined,
        body: candidate,
      });
      discardChanges();
      navigate(`/admin/users/${encodeURIComponent(userId)}`, true);
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
  if (conflict)
    return (
      <ConflictState
        candidate={candidate}
        reload={() => {
          setName(null);
          setEmail(null);
          setStatus(null);
          setConflict(false);
          user.reload();
        }}
      />
    );
  return (
    <>
      <PageHeader
        title="Edit user"
        description="Disabling a user revokes affected external sessions and is enforced through runtime publication."
      />
      <Panel title="Identity metadata">
        {error === null ? null : <ApiErrorState error={error} compact />}
        <form onSubmit={(event) => void save(event)}>
          <Field label="Display name" required>
            <input
              value={name ?? current.display_name}
              onChange={(event) => setName(event.target.value)}
              required
            />
          </Field>
          <Field label="Primary email">
            <input
              type="email"
              value={email ?? current.primary_email ?? ""}
              onChange={(event) => setEmail(event.target.value)}
            />
          </Field>
          <Field label="Status" required>
            <select
              value={status ?? current.status}
              onChange={(event) => setStatus(event.target.value as UserStatus)}
            >
              <option value="active">Active</option>
              <option value="disabled">Disabled</option>
            </select>
          </Field>
          <SubmitBar
            submitting={submitting}
            submitLabel="Save changes"
            cancelHref={`/admin/users/${encodeURIComponent(userId)}`}
          />
        </form>
      </Panel>
    </>
  );
}

export function AdminOrganizationsPage({ me }: { me: CurrentPrincipal }) {
  const [cursor, setCursor] = useState<string | null>(null);
  const organizations = useApiResource<Page<Organization>>(
    `/api/v1/system/organizations?limit=50${cursor === null ? "" : `&cursor=${encodeURIComponent(cursor)}`}`,
  );
  if (organizations.loading) return <LoadingState label="Loading organizations" />;
  if (organizations.error !== null)
    return <ApiErrorState error={organizations.error} retry={organizations.reload} />;
  const items = organizations.value?.items ?? [];
  return (
    <>
      <PageHeader
        title="Organizations"
        description="All deployment tenants and their global lifecycle state."
        actions={
          operationAllows(me, "system.organizations.create") ? (
            <Link className="button button-primary" href="/admin/organizations/new">
              Create organization
            </Link>
          ) : undefined
        }
      />
      {items.length === 0 ? (
        <EmptyState title="No organizations" description="No organizations are configured." />
      ) : (
        <Panel>
          <Table
            columns={[
              { key: "organization", label: "Organization" },
              { key: "kind", label: "Kind" },
              { key: "status", label: "Status" },
              { key: "slug", label: "Slug" },
              { key: "updated", label: "Updated" },
            ]}
            rows={items.map((organization) => ({
              organization: (
                <Link href={`/admin/organizations/${encodeURIComponent(organization.id)}`}>
                  <strong>{organization.name}</strong>
                  <Id>{organization.id}</Id>
                </Link>
              ),
              kind: humanize(organization.kind),
              status: <Status value={organization.status} />,
              slug: organization.slug ?? "Not set",
              updated: formatDate(organization.updated_at),
            }))}
            getKey={(_, index) => items[index].id}
          />
        </Panel>
      )}
      <Pagination
        canContinue={organizations.value?.next_cursor !== null && organizations.value !== null}
        onContinue={() => setCursor(organizations.value?.next_cursor ?? null)}
      />
    </>
  );
}

export function AdminOrganizationCreatePage() {
  const [kind, setKind] = useState<OrganizationKind>("ordinary");
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [ownerId, setOwnerId] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const idempotencyKeyFor = useIdempotencyKey();
  const discardChanges = useUnsavedChanges(
    kind !== "ordinary" || name !== "" || slug !== "" || ownerId !== "",
  );
  async function create(event: FormEvent): Promise<void> {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    const body = {
      kind,
      name: name.trim(),
      slug: slug.trim() === "" ? null : slug.trim(),
      initial_owner_user_id: ownerId.trim(),
    };
    try {
      const response = await apiRequest<Organization>(
        "/api/v1/system/organizations/actions/create",
        {
          method: "POST",
          idempotencyKey: idempotencyKeyFor(body),
          body,
        },
      );
      discardChanges();
      navigate(`/admin/organizations/${encodeURIComponent(response.value.id)}`, true);
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
        title="Create organization"
        description="An active organization begins with one eligible active local user as owner. Seed administrator is never offered as owner."
      />
      <Panel title="Organization identity">
        {error === null ? null : <ApiErrorState error={error} compact />}
        <form onSubmit={(event) => void create(event)}>
          <Field label="Kind" required>
            <select
              value={kind}
              onChange={(event) => setKind(event.target.value as OrganizationKind)}
            >
              <option value="ordinary">Ordinary</option>
              <option value="synthetic">Synthetic</option>
            </select>
          </Field>
          <Field label="Name" required>
            <input value={name} onChange={(event) => setName(event.target.value)} required />
          </Field>
          <Field label="Slug" help="Optional discovery label, never the authority ID.">
            <input value={slug} onChange={(event) => setSlug(event.target.value)} />
          </Field>
          <Field label="Initial owner user ID" required>
            <input value={ownerId} onChange={(event) => setOwnerId(event.target.value)} required />
          </Field>
          <SubmitBar
            submitting={submitting}
            submitLabel="Create organization"
            cancelHref="/admin/organizations"
          />
        </form>
      </Panel>
    </>
  );
}

export function AdminOrganizationDetailPage({
  organizationId,
  me,
}: {
  organizationId: string;
  me: CurrentPrincipal;
}) {
  const organization = useApiResource<Organization>(
    `/api/v1/system/organizations/${encodeURIComponent(organizationId)}`,
  );
  if (organization.loading) return <LoadingState label="Loading organization" />;
  if (organization.error !== null)
    return <ApiErrorState error={organization.error} retry={organization.reload} />;
  if (organization.value === null) return null;
  const value = organization.value;
  return (
    <>
      <PageHeader
        title={value.name}
        description="Global tenant lifecycle and explicit transition into the organization-qualified workspace."
        actions={
          <div className="inline-actions">
            {operationAllows(me, "system.organizations.update") ? (
              <Link
                className="button button-secondary"
                href={`/admin/organizations/${encodeURIComponent(organizationId)}/edit`}
              >
                Edit lifecycle
              </Link>
            ) : null}
            <Link
              className="button button-primary"
              href={`/organizations/${encodeURIComponent(organizationId)}`}
            >
              Open organization workspace
            </Link>
          </div>
        }
      />
      <div className="alert alert-info">
        <strong>Explicit organization context</strong>
        <span>
          Opening the workspace uses system authority without fabricating membership or owner
          identity.
        </span>
      </div>
      <Panel title="Organization evidence">
        <DefinitionList
          items={[
            { label: "Organization ID", value: <Id>{value.id}</Id> },
            { label: "Kind", value: humanize(value.kind) },
            { label: "Status", value: <Status value={value.status} /> },
            { label: "Slug", value: value.slug ?? "Not set" },
            { label: "Created", value: formatDate(value.created_at) },
            { label: "Updated", value: formatDate(value.updated_at) },
          ]}
        />
      </Panel>
    </>
  );
}

export function AdminOrganizationEditPage({ organizationId }: { organizationId: string }) {
  const path = `/api/v1/system/organizations/${encodeURIComponent(organizationId)}`;
  const organization = useApiResource<Organization>(path);
  const [name, setName] = useState<string | null>(null);
  const [slug, setSlug] = useState<string | null>(null);
  const [status, setStatus] = useState<OrganizationStatus | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [conflict, setConflict] = useState(false);
  const discardChanges = useUnsavedChanges(name !== null || slug !== null || status !== null);
  if (organization.loading) return <LoadingState label="Loading organization editor" />;
  if (organization.error !== null)
    return <ApiErrorState error={organization.error} retry={organization.reload} />;
  if (organization.value === null) return null;
  const current = organization.value;
  const candidate = {
    name: name ?? current.name,
    slug: (slug ?? current.slug ?? "").trim() === "" ? null : (slug ?? current.slug),
    status: status ?? current.status,
  };
  async function save(event: FormEvent): Promise<void> {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    setConflict(false);
    try {
      await apiRequest<Organization>(`${path}/actions/update`, {
        method: "POST",
        ifMatch: organization.etag ?? undefined,
        body: candidate,
      });
      discardChanges();
      navigate(`/admin/organizations/${encodeURIComponent(organizationId)}`, true);
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
  if (conflict)
    return (
      <ConflictState
        candidate={candidate}
        reload={() => {
          setName(null);
          setSlug(null);
          setStatus(null);
          setConflict(false);
          organization.reload();
        }}
      />
    );
  return (
    <>
      <PageHeader
        title="Edit organization"
        description="Suspension is a deployment-wide lifecycle transition and revokes affected external sessions."
      />
      <Panel title="Organization lifecycle">
        {error === null ? null : <ApiErrorState error={error} compact />}
        <form onSubmit={(event) => void save(event)}>
          <Field label="Name" required>
            <input
              value={name ?? current.name}
              onChange={(event) => setName(event.target.value)}
              required
            />
          </Field>
          <Field label="Slug">
            <input
              value={slug ?? current.slug ?? ""}
              onChange={(event) => setSlug(event.target.value)}
            />
          </Field>
          <Field label="Status" required>
            <select
              value={status ?? current.status}
              onChange={(event) => setStatus(event.target.value as OrganizationStatus)}
            >
              <option value="active">Active</option>
              <option value="suspended">Suspended</option>
            </select>
          </Field>
          <SubmitBar
            submitting={submitting}
            submitLabel="Save changes"
            cancelHref={`/admin/organizations/${encodeURIComponent(organizationId)}`}
          />
        </form>
      </Panel>
    </>
  );
}

export function AdministratorsPage({ me }: { me: CurrentPrincipal }) {
  const [cursor, setCursor] = useState<string | null>(null);
  const administrators = useApiResource<Page<AdministratorGrant>>(
    `/api/v1/system/administrators?limit=100${cursor === null ? "" : `&cursor=${encodeURIComponent(cursor)}`}`,
  );
  if (administrators.loading) return <LoadingState label="Loading system administrators" />;
  if (administrators.error !== null)
    return <ApiErrorState error={administrators.error} retry={administrators.reload} />;
  const items = administrators.value?.items ?? [];
  return (
    <>
      <PageHeader
        title="System administrators"
        description="Immutable built-in seed authority plus active typed local-user and deployment-key grants."
      />
      <div className="alert alert-warning">
        <strong>Seed path remains configured</strong>
        <span>
          The built-in seed administrator is API-key-only, has no durable user row or membership,
          and cannot be revoked here.
        </span>
      </div>
      <div className="list-stack">
        {items.map((grant) => (
          <Panel key={grant.id ?? "seed_admin"}>
            <div className="row-summary">
              <div>
                <strong>
                  {grant.subject_kind === "seed_admin"
                    ? "Seed administrator"
                    : humanize(grant.subject_kind)}
                </strong>
                <Id>{grant.subject_id}</Id>
              </div>
              <Status value={grant.status} />
            </div>
            <DefinitionList
              items={[
                { label: "Grant kind", value: grant.built_in ? "Built in" : "Durable typed grant" },
                { label: "Created", value: formatDate(grant.created_at) },
              ]}
            />
            {!grant.built_in && operationAllows(me, "system.administrators.revoke") ? (
              <ConfirmAction
                title={`Revoke ${humanize(grant.subject_kind)} administrator`}
                consequence="The subject loses deployment-wide authority. Local memberships or the deployment key itself remain, while matching sessions are revoked."
                label="Revoke administrator"
                danger
                onConfirm={async () => {
                  await apiRequest<void>(
                    `/api/v1/system/administrators/${encodeURIComponent(grant.subject_kind)}/${encodeURIComponent(grant.subject_id)}/actions/revoke`,
                    { method: "POST" },
                  );
                  administrators.reload();
                }}
              />
            ) : null}
          </Panel>
        ))}
      </div>
      <Pagination
        canContinue={administrators.value?.next_cursor !== null && administrators.value !== null}
        onContinue={() => setCursor(administrators.value?.next_cursor ?? null)}
      />
    </>
  );
}
