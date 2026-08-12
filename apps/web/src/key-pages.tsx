import { type FormEvent, useState } from "react";

import {
  ApiError,
  OutcomeUnknownError,
  apiRequest,
  formatDate,
  jsonText,
  type CurrentPrincipal,
  type DeploymentManagementKeyPolicy,
  type JsonValue,
  type ManagementApiKey,
  type ManagementScope,
  type OneTimeManagementApiKey,
  type OrganizationApiKeyPolicy,
  type Page,
} from "./api";
import { operationAllows } from "./operation-authority";
import {
  ApiErrorState,
  ConfirmAction,
  ConflictState,
  DefinitionList,
  EmptyState,
  Field,
  FormError,
  Id,
  JsonBlock,
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
  useUnsavedChanges,
} from "./ui";

export type KeyScope = { kind: "system" } | { kind: "organization"; organizationId: string };

const MANAGEMENT_SCOPES: ManagementScope[] = [
  "management:read",
  "management:write",
  "management:secrets",
  "management:operations",
  "management:authority",
];

const ORGANIZATION_CAPABILITIES = [
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
];

const SYSTEM_CAPABILITIES = [
  "system_administration",
  ...ORGANIZATION_CAPABILITIES,
  "manage_identity",
  "manage_system_keys",
  "manage_system_organizations",
  "manage_system_users",
  "manage_administrators",
  "read_operations",
  "recover_operations",
];

function apiBase(scope: KeyScope): string {
  return scope.kind === "system"
    ? "/api/v1/system/management-api-keys"
    : `/api/v1/organizations/${encodeURIComponent(scope.organizationId)}/management-api-keys`;
}

function browserBase(scope: KeyScope): string {
  return scope.kind === "system"
    ? "/admin/management-api-keys"
    : `/organizations/${encodeURIComponent(scope.organizationId)}/management-api-keys`;
}

function keyOperation(
  scope: KeyScope,
  action: "list" | "create" | "get" | "update" | "rotate",
): string {
  return `${scope.kind === "system" ? "system" : "organization"}.management_keys.${action}`;
}

function policyOperation(scope: KeyScope, action: "get" | "update"): string {
  return `${scope.kind === "system" ? "system.management_key_policy" : "organization.api_key_policy"}.${action}`;
}

function operationOrganization(scope: KeyScope): string | undefined {
  return scope.kind === "organization" ? scope.organizationId : undefined;
}

function availableCapabilities(scope: KeyScope): string[] {
  return scope.kind === "system" ? SYSTEM_CAPABILITIES : ORGANIZATION_CAPABILITIES;
}

function toggle<T>(values: T[], value: T): T[] {
  return values.includes(value) ? values.filter((item) => item !== value) : [...values, value];
}

function toLocalDateTime(value: string | null): string {
  if (value === null) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const offset = date.getTimezoneOffset() * 60_000;
  return new Date(date.getTime() - offset).toISOString().slice(0, 16);
}

function expiresValue(value: string): string | null {
  return value === "" ? null : new Date(value).toISOString();
}

export function ManagementKeyListPage({ scope, me }: { scope: KeyScope; me: CurrentPrincipal }) {
  const [cursor, setCursor] = useState<string | null>(null);
  const keys = useApiResource<Page<ManagementApiKey>>(
    `${apiBase(scope)}?limit=50${cursor === null ? "" : `&cursor=${encodeURIComponent(cursor)}`}`,
  );
  const title = scope.kind === "system" ? "Deployment Management API keys" : "Management API keys";
  if (keys.loading) return <LoadingState label="Loading Management API keys" />;
  if (keys.error !== null) return <ApiErrorState error={keys.error} retry={keys.reload} />;
  const items = keys.value?.items ?? [];
  return (
    <>
      <PageHeader
        title={title}
        description="Resource-owned automation principals with explicit scope, capability, expiry, and rotation boundaries."
        actions={
          operationAllows(me, keyOperation(scope, "create"), operationOrganization(scope)) ? (
            <Link className="button button-primary" href={`${browserBase(scope)}/new`}>
              Create key
            </Link>
          ) : undefined
        }
      />
      {scope.kind === "system" ? (
        <div className="alert alert-info">
          <strong>No implicit administrator authority</strong>
          <span>
            A deployment key remains ungranted until a separate system-administrator grant succeeds.
          </span>
        </div>
      ) : null}
      {items.length === 0 ? (
        <EmptyState
          title="No Management API keys"
          description="No durable automation principals are visible in this scope."
        />
      ) : (
        <Panel>
          <Table
            columns={[
              { key: "name", label: "Name" },
              { key: "prefix", label: "Prefix" },
              { key: "scopes", label: "Scopes" },
              { key: "status", label: "Status" },
              { key: "expiry", label: "Expiry" },
            ]}
            rows={items.map((key) => ({
              name: (
                <Link href={`${browserBase(scope)}/${encodeURIComponent(key.id)}`}>
                  <strong>{key.name}</strong>
                  <Id>{key.id}</Id>
                </Link>
              ),
              prefix: <code>{key.key_prefix}</code>,
              scopes: key.scopes.join(", "),
              status: <Status value={key.status} />,
              expiry: formatDate(key.expires_at),
            }))}
            getKey={(_, index) => items[index].id}
          />
        </Panel>
      )}
      <Pagination
        canContinue={keys.value?.next_cursor !== null && keys.value !== null}
        onContinue={() => setCursor(keys.value?.next_cursor ?? null)}
      />
    </>
  );
}

export function ManagementKeyCreatePage({ scope, me }: { scope: KeyScope; me: CurrentPrincipal }) {
  const organizationAccess =
    scope.kind === "organization"
      ? me.allowed_organizations.find(
          (organization) => organization.organization_id === scope.organizationId,
        )
      : undefined;
  const memberSelfService =
    scope.kind === "organization" &&
    me.principal.kind === "local_user" &&
    !me.system_administrator &&
    organizationAccess?.role === "member";
  const selfServicePolicy = memberSelfService
    ? (organizationAccess.management_key_self_service ?? null)
    : null;
  const permittedScopes = MANAGEMENT_SCOPES.filter(
    (scopeName) =>
      me.effective_management_scopes.includes(scopeName) &&
      (scope.kind === "system" || scopeName !== "management:operations") &&
      (selfServicePolicy === null || selfServicePolicy.allowed_scopes.includes(scopeName)),
  );
  const permittedCapabilities = availableCapabilities(scope).filter(
    (capability) =>
      (scope.kind === "system"
        ? me.capabilities.includes(capability)
        : organizationAccess?.capabilities.includes(capability) === true) &&
      (selfServicePolicy === null || selfServicePolicy.allowed_capabilities.includes(capability)),
  );
  const initialScopes = permittedScopes.slice(0, 1);
  const initialCapabilities = permittedCapabilities.slice(0, 1);
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState<ManagementScope[]>(initialScopes);
  const [capabilities, setCapabilities] = useState<string[]>(initialCapabilities);
  const [expiresAt, setExpiresAt] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [created, setCreated] = useState<OneTimeManagementApiKey | null>(null);
  const [outcomeUnknown, setOutcomeUnknown] = useState<OutcomeUnknownError | null>(null);
  const discardChanges = useUnsavedChanges(
    created === null &&
      outcomeUnknown === null &&
      (name.length > 0 ||
        expiresAt.length > 0 ||
        confirmed ||
        scopes.length !== initialScopes.length ||
        scopes.some((scopeName, index) => scopeName !== initialScopes[index]) ||
        capabilities.length !== initialCapabilities.length ||
        capabilities.some((capability, index) => capability !== initialCapabilities[index])),
  );

  async function create(event: FormEvent): Promise<void> {
    event.preventDefault();
    setError(null);
    setFormError(null);
    if (scopes.length === 0 || capabilities.length === 0) {
      setFormError("Select at least one scope and one capability.");
      return;
    }
    if (
      selfServicePolicy !== null &&
      expiresAt !== "" &&
      new Date(expiresAt).getTime() > Date.now() + selfServicePolicy.max_expiry_days * 86_400_000
    ) {
      setFormError(
        `Expiry cannot exceed the current ${selfServicePolicy.max_expiry_days}-day self-service policy ceiling.`,
      );
      return;
    }
    if (!confirmed) {
      setFormError("Confirm the standing automation authority before creating the key.");
      return;
    }
    setSubmitting(true);
    try {
      const response = await apiRequest<OneTimeManagementApiKey>(
        `${apiBase(scope)}/actions/create`,
        {
          method: "POST",
          body: {
            name: name.trim(),
            scopes,
            capability_ceiling: capabilities,
            expires_at: expiresValue(expiresAt),
          },
          nonRepeatable: true,
        },
      );
      discardChanges();
      setName("");
      setCreated(response.value);
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

  if (permittedScopes.length === 0 || permittedCapabilities.length === 0) {
    return (
      <>
        <PageHeader
          title="Create Management API key"
          description="No policy-authorized credential can be created from the current authority intersection."
        />
        <Panel>
          <div className="alert alert-warning">
            <strong>No available authority profile</strong>
            <span>
              The current principal and destination policy have no shared non-empty scope and
              capability selection. Reload after an administrator changes either authority source.
            </span>
          </div>
          <Link className="button button-secondary" href={browserBase(scope)}>
            Back to Management API keys
          </Link>
        </Panel>
      </>
    );
  }

  if (outcomeUnknown !== null) {
    return (
      <OutcomeUnknownState
        command="the Management API key creation"
        requestId={outcomeUnknown.requestId}
        recoveryHref={browserBase(scope)}
        committed={outcomeUnknown.committed}
      />
    );
  }

  if (created !== null) {
    const key = created.management_api_key;
    return (
      <>
        <PageHeader title="Management API key" description="One-time credential reveal" />
        <OneTimeReveal
          credentialClass="Management API key"
          secret={created.key}
          doneHref={`${browserBase(scope)}/${encodeURIComponent(key.id)}`}
          metadata={
            <DefinitionList
              items={[
                {
                  label: "Resource",
                  value:
                    scope.kind === "system" ? "Deployment" : `Organization ${scope.organizationId}`,
                },
                { label: "Key ID", value: <Id>{key.id}</Id> },
                { label: "Scopes", value: key.scopes.join(", ") },
                { label: "Expiry", value: formatDate(key.expires_at) },
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
        title="Create Management API key"
        description="Create a resource-owned control-plane automation principal. No local user becomes its owner."
      />
      <Panel title="Authority profile">
        {selfServicePolicy === null ? null : (
          <div className="alert alert-info">
            <strong>Member self-service policy</strong>
            <span>
              Current policy permits {selfServicePolicy.active_keys} of{" "}
              {selfServicePolicy.max_active_keys} active keys and at most{" "}
              {selfServicePolicy.max_expiry_days} days until expiry. The available scopes and
              capabilities below are the intersection of that policy and your current authority.
            </span>
          </div>
        )}
        <FormError message={formError} />
        {error === null ? null : <ApiErrorState error={error} compact />}
        <form onSubmit={(event) => void create(event)}>
          <Field label="Name" required>
            <input
              value={name}
              onChange={(event) => setName(event.target.value)}
              maxLength={120}
              required
            />
          </Field>
          <fieldset className="choice-field">
            <legend>Management scopes</legend>
            <div className="choice-grid">
              {permittedScopes.map((scopeName) => (
                <label className="check-row" key={scopeName}>
                  <input
                    type="checkbox"
                    checked={scopes.includes(scopeName)}
                    onChange={() => setScopes(toggle(scopes, scopeName))}
                  />
                  <span>{scopeName}</span>
                </label>
              ))}
            </div>
          </fieldset>
          <fieldset className="choice-field">
            <legend>Capability ceiling</legend>
            <div className="choice-grid">
              {permittedCapabilities.map((capability) => (
                <label className="check-row" key={capability}>
                  <input
                    type="checkbox"
                    checked={capabilities.includes(capability)}
                    onChange={() => setCapabilities(toggle(capabilities, capability))}
                  />
                  <span>{humanize(capability)}</span>
                </label>
              ))}
            </div>
          </fieldset>
          <Field
            label="Expires at"
            help="Optional. Policy may clamp this value from the persisted issuance time."
          >
            <input
              type="datetime-local"
              value={expiresAt}
              onChange={(event) => setExpiresAt(event.target.value)}
            />
          </Field>
          <div className="alert alert-warning">
            <strong>Standing automation authority</strong>
            <span>
              The key authenticates as its deployment or organization resource, never as the
              creator. The raw value is returned exactly once.
            </span>
          </div>
          <label className="check-row confirmation">
            <input
              type="checkbox"
              checked={confirmed}
              onChange={(event) => setConfirmed(event.target.checked)}
            />
            <span>
              I reviewed the resource scope, Management scopes, capability ceiling, and expiry.
            </span>
          </label>
          <SubmitBar
            submitting={submitting}
            submitLabel="Create key"
            cancelHref={browserBase(scope)}
          />
        </form>
      </Panel>
    </>
  );
}

export function ManagementKeyDetailPage({
  scope,
  keyId,
  me,
}: {
  scope: KeyScope;
  keyId: string;
  me: CurrentPrincipal;
}) {
  const key = useApiResource<ManagementApiKey>(`${apiBase(scope)}/${encodeURIComponent(keyId)}`);
  if (key.loading) return <LoadingState label="Loading Management API key" />;
  if (key.error !== null) return <ApiErrorState error={key.error} retry={key.reload} />;
  if (key.value === null) return null;
  const value = key.value;
  return (
    <>
      <PageHeader
        title={value.name}
        description="Safe metadata for a durable automation principal. Raw credential material is never recoverable."
        actions={
          <div className="inline-actions">
            {operationAllows(me, keyOperation(scope, "update"), operationOrganization(scope)) ? (
              <Link
                className="button button-secondary"
                href={`${browserBase(scope)}/${encodeURIComponent(keyId)}/edit`}
              >
                Edit policy
              </Link>
            ) : null}
            {operationAllows(me, keyOperation(scope, "rotate"), operationOrganization(scope)) ? (
              <Link
                className="button button-primary"
                href={`${browserBase(scope)}/${encodeURIComponent(keyId)}/rotate`}
              >
                Rotate key
              </Link>
            ) : null}
          </div>
        }
      />
      <div className="metric-grid">
        <div className="metric-card">
          <span>Lifecycle</span>
          <Status value={value.status} />
        </div>
        <div className="metric-card">
          <span>Issuance class</span>
          <strong>{humanize(value.issuance_policy_class)}</strong>
        </div>
        <div className="metric-card">
          <span>Expiry</span>
          <strong>{formatDate(value.expires_at)}</strong>
        </div>
      </div>
      <Panel title="Credential evidence">
        <DefinitionList
          items={[
            { label: "Key ID", value: <Id>{value.id}</Id> },
            { label: "Safe prefix", value: <code>{value.key_prefix}</code> },
            {
              label: "Resource scope",
              value:
                value.resource_scope.kind === "deployment"
                  ? "Deployment"
                  : `Organization ${value.resource_scope.organization_id}`,
            },
            { label: "Current secret version", value: <Id>{value.current_secret_version_id}</Id> },
            { label: "Overlap until", value: formatDate(value.overlap_until) },
            { label: "Created", value: formatDate(value.created_at) },
            { label: "Updated", value: formatDate(value.updated_at) },
          ]}
        />
      </Panel>
      <Panel title="Management scopes">
        <div className="tag-list">
          {value.scopes.map((item) => (
            <span className="tag" key={item}>
              {item}
            </span>
          ))}
        </div>
      </Panel>
      <Panel title="Capability ceiling">
        <JsonBlock value={value.capability_ceiling} />
      </Panel>
      {scope.kind === "system" && operationAllows(me, "system.administrators.grant") ? (
        <Panel
          title="System administrator grant"
          description="Key creation does not imply this grant. Existing key scopes and capability ceilings continue to narrow it."
        >
          <ConfirmAction
            title={`Grant administrator authority to ${value.name}`}
            consequence="The deployment Management API key receives deployment-wide administrator authority only while its own credential and scopes remain effective."
            label="Grant system administrator"
            onConfirm={async () => {
              await apiRequest<void>("/api/v1/system/administrators/actions/grant", {
                method: "POST",
                body: { subject_kind: "deployment_management_api_key", subject_id: value.id },
              });
            }}
          />
        </Panel>
      ) : null}
    </>
  );
}

export function ManagementKeyEditPage({ scope, keyId }: { scope: KeyScope; keyId: string }) {
  const path = `${apiBase(scope)}/${encodeURIComponent(keyId)}`;
  const key = useApiResource<ManagementApiKey>(path);
  const [name, setName] = useState<string | null>(null);
  const [scopes, setScopes] = useState<ManagementScope[] | null>(null);
  const [capabilities, setCapabilities] = useState<string[] | null>(null);
  const [status, setStatus] = useState<ManagementApiKey["status"] | null>(null);
  const [expiresAt, setExpiresAt] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [conflict, setConflict] = useState(false);
  const discardChanges = useUnsavedChanges(
    name !== null ||
      scopes !== null ||
      capabilities !== null ||
      status !== null ||
      expiresAt !== null,
  );
  if (key.loading) return <LoadingState label="Loading key policy" />;
  if (key.error !== null) return <ApiErrorState error={key.error} retry={key.reload} />;
  if (key.value === null) return null;
  const current = key.value;
  const selectedScopes = scopes ?? current.scopes;
  const rawCapabilities = Array.isArray(current.capability_ceiling)
    ? current.capability_ceiling.filter((item): item is string => typeof item === "string")
    : [];
  const selectedCapabilities = capabilities ?? rawCapabilities;
  const selectedStatus = status ?? current.status;
  const selectedExpiresAt = expiresAt ?? toLocalDateTime(current.expires_at);
  const candidate: Record<string, JsonValue> = {
    name: name ?? current.name,
    scopes: selectedScopes,
    capability_ceiling: selectedCapabilities,
    status: selectedStatus,
    expires_at: expiresValue(selectedExpiresAt),
  };

  async function save(event: FormEvent): Promise<void> {
    event.preventDefault();
    setError(null);
    setFormError(null);
    setConflict(false);
    if (selectedScopes.length === 0 || selectedCapabilities.length === 0) {
      setFormError("Select at least one scope and capability.");
      return;
    }
    setSubmitting(true);
    try {
      const response = await apiRequest<ManagementApiKey>(`${path}/actions/update`, {
        method: "POST",
        ifMatch: key.etag ?? undefined,
        body: candidate,
      });
      key.replace(response);
      discardChanges();
      navigate(`${browserBase(scope)}/${encodeURIComponent(keyId)}`, true);
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
          discardChanges();
          setName(null);
          setScopes(null);
          setCapabilities(null);
          setStatus(null);
          setExpiresAt(null);
          setConflict(false);
          key.reload();
        }}
      />
    );
  return (
    <>
      <PageHeader
        title="Edit Management API key"
        description="Every change is checked against the caller, destination policy, and the latest resource ETag."
      />
      <Panel title="Key policy">
        <FormError message={formError} />
        {error === null ? null : <ApiErrorState error={error} compact />}
        <form onSubmit={(event) => void save(event)}>
          <Field label="Name" required>
            <input
              value={name ?? current.name}
              onChange={(event) => setName(event.target.value)}
              required
            />
          </Field>
          <Field label="Status" required>
            <select
              value={selectedStatus}
              onChange={(event) => setStatus(event.target.value as ManagementApiKey["status"])}
            >
              <option value="active">Active</option>
              <option value="disabled">Disabled</option>
              <option value="revoked">Revoked</option>
            </select>
          </Field>
          <fieldset className="choice-field">
            <legend>Management scopes</legend>
            <div className="choice-grid">
              {MANAGEMENT_SCOPES.filter(
                (scopeName) => scope.kind === "system" || scopeName !== "management:operations",
              ).map((scopeName) => (
                <label className="check-row" key={scopeName}>
                  <input
                    type="checkbox"
                    checked={selectedScopes.includes(scopeName)}
                    onChange={() => setScopes(toggle(selectedScopes, scopeName))}
                  />
                  <span>{scopeName}</span>
                </label>
              ))}
            </div>
          </fieldset>
          <fieldset className="choice-field">
            <legend>Capability ceiling</legend>
            <div className="choice-grid">
              {availableCapabilities(scope).map((capability) => (
                <label className="check-row" key={capability}>
                  <input
                    type="checkbox"
                    checked={selectedCapabilities.includes(capability)}
                    onChange={() => setCapabilities(toggle(selectedCapabilities, capability))}
                  />
                  <span>{humanize(capability)}</span>
                </label>
              ))}
            </div>
          </fieldset>
          <Field
            label="Expires at"
            help="Clearing requests no expiry; current policy may still impose and persist a finite deadline."
          >
            <input
              type="datetime-local"
              value={selectedExpiresAt}
              onChange={(event) => setExpiresAt(event.target.value)}
            />
          </Field>
          <SubmitBar
            submitting={submitting}
            submitLabel="Save changes"
            cancelHref={`${browserBase(scope)}/${encodeURIComponent(keyId)}`}
          />
        </form>
      </Panel>
    </>
  );
}

export function ManagementKeyRotatePage({ scope, keyId }: { scope: KeyScope; keyId: string }) {
  const key = useApiResource<ManagementApiKey>(`${apiBase(scope)}/${encodeURIComponent(keyId)}`);
  const [overlap, setOverlap] = useState(300);
  const [confirmed, setConfirmed] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [rotated, setRotated] = useState<OneTimeManagementApiKey | null>(null);
  const [outcomeUnknown, setOutcomeUnknown] = useState<OutcomeUnknownError | null>(null);
  const discardChanges = useUnsavedChanges(
    rotated === null && outcomeUnknown === null && (overlap !== 300 || confirmed),
  );
  if (key.loading) return <LoadingState label="Loading key rotation state" />;
  if (key.error !== null) return <ApiErrorState error={key.error} retry={key.reload} />;
  if (key.value === null) return null;
  if (outcomeUnknown !== null) {
    return (
      <OutcomeUnknownState
        command="the Management API key rotation"
        requestId={outcomeUnknown.requestId}
        recoveryHref={`${browserBase(scope)}/${encodeURIComponent(keyId)}`}
        committed={outcomeUnknown.committed}
      />
    );
  }
  if (rotated !== null) {
    return (
      <OneTimeReveal
        credentialClass="Rotated Management API key"
        secret={rotated.key}
        doneHref={`${browserBase(scope)}/${encodeURIComponent(keyId)}`}
        metadata={
          <DefinitionList
            items={[
              { label: "Key ID", value: <Id>{rotated.management_api_key.id}</Id> },
              {
                label: "Old-secret overlap until",
                value: formatDate(rotated.management_api_key.overlap_until),
              },
            ]}
          />
        }
      />
    );
  }
  async function rotate(event: FormEvent): Promise<void> {
    event.preventDefault();
    if (!confirmed) return;
    setSubmitting(true);
    setError(null);
    try {
      const response = await apiRequest<OneTimeManagementApiKey>(
        `${apiBase(scope)}/${encodeURIComponent(keyId)}/actions/rotate`,
        { method: "POST", body: { overlap_seconds: overlap }, nonRepeatable: true },
      );
      discardChanges();
      setRotated(response.value);
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
  return (
    <>
      <PageHeader
        title={`Rotate ${key.value.name}`}
        description="Issue new non-recoverable material and optionally preserve a bounded overlap for the old secret."
      />
      <Panel title="Rotation">
        {error === null ? null : <ApiErrorState error={error} compact />}
        <form onSubmit={(event) => void rotate(event)}>
          <Field
            label="Overlap seconds"
            required
            help="The destination policy may clamp this duration."
          >
            <input
              type="number"
              min={0}
              max={86400}
              value={overlap}
              onChange={(event) => setOverlap(event.target.valueAsNumber)}
              required
            />
          </Field>
          <div className="alert alert-warning">
            <strong>No automatic retry</strong>
            <span>
              If the result is ambiguous, inspect metadata, disable potentially undisclosed
              material, and deliberately rotate again.
            </span>
          </div>
          <label className="check-row confirmation">
            <input
              type="checkbox"
              checked={confirmed}
              onChange={(event) => setConfirmed(event.target.checked)}
            />
            <span>
              I understand the new raw key will be shown once and the old key may remain valid only
              during the bounded overlap.
            </span>
          </label>
          <SubmitBar
            submitting={submitting || !confirmed}
            submitLabel="Rotate key"
            cancelHref={`${browserBase(scope)}/${encodeURIComponent(keyId)}`}
          />
        </form>
      </Panel>
    </>
  );
}

export function KeyPolicyPage({ scope, me }: { scope: KeyScope; me: CurrentPrincipal }) {
  const path =
    scope.kind === "system"
      ? "/api/v1/system/management-api-key-policy"
      : `/api/v1/organizations/${encodeURIComponent(scope.organizationId)}/api-key-policy`;
  const policy = useApiResource<DeploymentManagementKeyPolicy | OrganizationApiKeyPolicy>(path);
  const browserPath =
    scope.kind === "system"
      ? "/admin/management-api-key-policy"
      : `/organizations/${encodeURIComponent(scope.organizationId)}/api-key-policy`;
  if (policy.loading) return <LoadingState label="Loading API key policy" />;
  if (policy.error !== null) return <ApiErrorState error={policy.error} retry={policy.reload} />;
  if (policy.value === null) return null;
  return (
    <>
      <PageHeader
        title={scope.kind === "system" ? "Management API key policy" : "API key policy"}
        description="Current persisted issuance, authority, expiry, active-count, and rotation ceilings."
        actions={
          operationAllows(me, policyOperation(scope, "update"), operationOrganization(scope)) ? (
            <Link className="button button-primary" href={`${browserPath}/edit`}>
              Edit policy
            </Link>
          ) : undefined
        }
      />
      <Panel title="Policy document">
        <JsonBlock value={policy.value.policy} />
        <DefinitionList
          items={[{ label: "Updated", value: formatDate(policy.value.updated_at) }]}
        />
      </Panel>
    </>
  );
}

export function KeyPolicyEditPage({ scope }: { scope: KeyScope }) {
  const path =
    scope.kind === "system"
      ? "/api/v1/system/management-api-key-policy"
      : `/api/v1/organizations/${encodeURIComponent(scope.organizationId)}/api-key-policy`;
  const browserPath =
    scope.kind === "system"
      ? "/admin/management-api-key-policy"
      : `/organizations/${encodeURIComponent(scope.organizationId)}/api-key-policy`;
  const policy = useApiResource<DeploymentManagementKeyPolicy | OrganizationApiKeyPolicy>(path);
  const [text, setText] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [apiError, setApiError] = useState<ApiError | null>(null);
  const [conflict, setConflict] = useState(false);
  const discardChanges = useUnsavedChanges(text !== null);
  if (policy.loading) return <LoadingState label="Loading API key policy" />;
  if (policy.error !== null) return <ApiErrorState error={policy.error} retry={policy.reload} />;
  if (policy.value === null) return null;
  const currentText = text ?? jsonText(policy.value.policy);
  let candidate: JsonValue = policy.value.policy;
  try {
    candidate = JSON.parse(currentText) as JsonValue;
  } catch {
    /* reported at submit */
  }
  async function save(event: FormEvent): Promise<void> {
    event.preventDefault();
    setError(null);
    setApiError(null);
    setConflict(false);
    let parsed: unknown;
    try {
      parsed = JSON.parse(currentText);
    } catch {
      setError("Policy must contain valid JSON.");
      return;
    }
    if (parsed === null || Array.isArray(parsed) || typeof parsed !== "object") {
      setError("Policy must be a JSON object.");
      return;
    }
    setSubmitting(true);
    try {
      const response = await apiRequest<DeploymentManagementKeyPolicy | OrganizationApiKeyPolicy>(
        `${path}/actions/update`,
        { method: "POST", ifMatch: policy.etag ?? undefined, body: { policy: parsed } },
      );
      policy.replace(response);
      discardChanges();
      navigate(browserPath, true);
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
  if (conflict)
    return (
      <ConflictState
        candidate={candidate}
        reload={() => {
          discardChanges();
          setText(null);
          setConflict(false);
          policy.reload();
        }}
      />
    );
  return (
    <>
      <PageHeader
        title="Edit API key policy"
        description="Submit one complete validated policy document against the latest opaque ETag."
      />
      <Panel
        title="Policy JSON"
        description="This bounded Module I policy is represented by the server as a typed JSON aggregate; tightening is persisted monotonically to affected keys."
      >
        <FormError message={error} />
        {apiError === null ? null : <ApiErrorState error={apiError} compact />}
        <form onSubmit={(event) => void save(event)}>
          <Field label="Policy" required>
            <textarea
              className="code-editor"
              rows={24}
              value={currentText}
              onChange={(event) => setText(event.target.value)}
              spellCheck={false}
            />
          </Field>
          <SubmitBar submitting={submitting} submitLabel="Save policy" cancelHref={browserPath} />
        </form>
      </Panel>
    </>
  );
}
