import { type FormEvent, useState } from "react";

import {
  ApiError,
  apiRequest,
  formatDate,
  jsonText,
  type CurrentPrincipal,
  type ExternalIdentityBinding,
  type ExternalIdentityIssuer,
  type JsonValue,
  type Page,
  type ProvisioningPolicy,
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

const ISSUER_TEMPLATE: JsonValue = {
  name: "company",
  display_name: "Company identity",
  issuer: "https://identity.example.com",
  status: "disabled",
  jwks_source: { kind: "https", uri: "https://identity.example.com/.well-known/jwks.json" },
  allowed_algorithms: ["RS256"],
  accepted_audiences: ["owlrora"],
  subject_claim: "sub",
  claim_mapping: {},
  jwt_capability_ceiling: [],
  management_scope_ceiling: [],
  management_organization_ceiling: { kind: "none" },
  capability_claim_policy: "ignore",
  jwt_route_ceiling: { kind: "none" },
  organization_selector: { kind: "none" },
  provisioning_policy_id: null,
  browser_login: null,
  clock_skew_seconds: 60,
  key_cache_policy: {
    refresh_interval_seconds: 3600,
    material_acceptance_seconds: 86400,
    max_keys: 32,
    max_token_bytes: 16384,
  },
};

const PROVISIONING_TEMPLATE: JsonValue = {
  name: "bounded-onboarding",
  status: "disabled",
  user_kind: "human",
  configuration: {
    mode: "explicit",
    allowed_email_domains: [],
    organization_assignments: [],
  },
};

function parseObject(text: string): Record<string, unknown> {
  const value: unknown = JSON.parse(text);
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    throw new Error("The request must be a JSON object.");
  }
  return value as Record<string, unknown>;
}

export function IdentityIssuersPage({ me }: { me: CurrentPrincipal }) {
  const [cursor, setCursor] = useState<string | null>(null);
  const issuers = useApiResource<Page<ExternalIdentityIssuer>>(
    `/api/v1/system/identity-issuers?limit=50${cursor === null ? "" : `&cursor=${encodeURIComponent(cursor)}`}`,
  );
  if (issuers.loading) return <LoadingState label="Loading identity issuers" />;
  if (issuers.error !== null) return <ApiErrorState error={issuers.error} retry={issuers.reload} />;
  const items = issuers.value?.items ?? [];
  return (
    <>
      <PageHeader
        title="Identity issuers"
        description="Direct JWT verification and independently optional OIDC browser-login profiles."
        actions={
          operationAllows(me, "system.identity_issuers.create") ? (
            <Link className="button button-primary" href="/admin/identity/issuers/new">
              Create issuer
            </Link>
          ) : undefined
        }
      />
      {items.length === 0 ? (
        <EmptyState
          title="No identity issuers"
          description="Only Management API key authentication is currently configured."
        />
      ) : (
        <Panel>
          <Table
            columns={[
              { key: "issuer", label: "Issuer" },
              { key: "authority", label: "Authority URL" },
              { key: "status", label: "Status" },
              { key: "browser", label: "Browser login" },
              { key: "version", label: "Policy version" },
            ]}
            rows={items.map((issuer) => ({
              issuer: (
                <Link href={`/admin/identity/issuers/${encodeURIComponent(issuer.id)}`}>
                  <strong>{issuer.display_name}</strong>
                  <Id>{issuer.id}</Id>
                </Link>
              ),
              authority: <code>{issuer.issuer}</code>,
              status: <Status value={issuer.status} />,
              browser: issuer.browser_login === null ? "Not configured" : "Configured",
              version: issuer.policy_version,
            }))}
            getKey={(_, index) => items[index].id}
          />
        </Panel>
      )}
      <Pagination
        canContinue={issuers.value?.next_cursor !== null && issuers.value !== null}
        onContinue={() => setCursor(issuers.value?.next_cursor ?? null)}
      />
    </>
  );
}

export function IdentityIssuerCreatePage() {
  const [text, setText] = useState(jsonText(ISSUER_TEMPLATE));
  const [confirmed, setConfirmed] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const idempotencyKeyFor = useIdempotencyKey();
  const discardChanges = useUnsavedChanges(text !== jsonText(ISSUER_TEMPLATE) || confirmed);
  async function create(event: FormEvent): Promise<void> {
    event.preventDefault();
    setFormError(null);
    setError(null);
    if (!confirmed) {
      setFormError("Confirm the external trust boundary before creating the issuer.");
      return;
    }
    let body: Record<string, unknown>;
    try {
      body = parseObject(text);
    } catch (caught: unknown) {
      setFormError(caught instanceof Error ? caught.message : "Invalid JSON.");
      return;
    }
    setSubmitting(true);
    try {
      const response = await apiRequest<ExternalIdentityIssuer>(
        "/api/v1/system/identity-issuers/actions/create",
        { method: "POST", idempotencyKey: idempotencyKeyFor(body), body },
      );
      discardChanges();
      navigate(`/admin/identity/issuers/${encodeURIComponent(response.value.id)}`, true);
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
        title="Create identity issuer"
        description="Configure a bounded external trust adapter. Direct JWT authority remains independent from optional browser login."
      />
      <Panel
        title="Issuer aggregate"
        description="The complete typed request is shown explicitly so trust, claim, organization, route, cache, and browser-login ceilings remain reviewable together."
      >
        <FormError message={formError} />
        {error === null ? null : <ApiErrorState error={error} compact />}
        <form onSubmit={(event) => void create(event)}>
          <Field label="Issuer configuration" required>
            <textarea
              className="code-editor"
              rows={32}
              value={text}
              onChange={(event) => setText(event.target.value)}
              spellCheck={false}
            />
          </Field>
          <div className="alert alert-warning">
            <strong>External trust boundary</strong>
            <span>
              JWKS and browser endpoints are resolved through OwlRora's SSRF-resistant identity
              egress policy. Management access requires explicit issuer scopes, capabilities, and
              organization ceilings.
            </span>
          </div>
          <label className="check-row confirmation">
            <input
              type="checkbox"
              checked={confirmed}
              onChange={(event) => setConfirmed(event.target.checked)}
            />
            <span>
              I reviewed verifier material, accepted algorithms/audiences, claim mapping, and every
              management ceiling.
            </span>
          </label>
          <SubmitBar
            submitting={submitting}
            submitLabel="Create issuer"
            cancelHref="/admin/identity/issuers"
          />
        </form>
      </Panel>
    </>
  );
}

function issuerUpdateBody(issuer: ExternalIdentityIssuer): JsonValue {
  return {
    display_name: issuer.display_name,
    status: issuer.status,
    jwks_source: issuer.jwks_source,
    allowed_algorithms: issuer.allowed_algorithms,
    accepted_audiences: issuer.accepted_audiences,
    subject_claim: issuer.subject_claim,
    claim_mapping: issuer.claim_mapping,
    jwt_capability_ceiling: issuer.jwt_capability_ceiling,
    management_scope_ceiling: issuer.management_scope_ceiling,
    management_organization_ceiling: issuer.management_organization_ceiling,
    capability_claim_policy: issuer.capability_claim_policy,
    jwt_route_ceiling: issuer.jwt_route_ceiling,
    organization_selector: issuer.organization_selector,
    provisioning_policy_id: issuer.provisioning_policy_id,
    browser_login: issuer.browser_login,
    clock_skew_seconds: issuer.clock_skew_seconds,
    key_cache_policy: issuer.key_cache_policy,
  };
}

export function IdentityIssuerDetailPage({
  issuerId,
  me,
}: {
  issuerId: string;
  me: CurrentPrincipal;
}) {
  const path = `/api/v1/system/identity-issuers/${encodeURIComponent(issuerId)}`;
  const issuer = useApiResource<ExternalIdentityIssuer>(path);
  const [clientSecret, setClientSecret] = useState("");
  const [actionResult, setActionResult] = useState<JsonValue | null>(null);
  const [actionError, setActionError] = useState<ApiError | null>(null);
  const discardClientSecret = useUnsavedChanges(clientSecret.length > 0);
  if (issuer.loading) return <LoadingState label="Loading identity issuer" />;
  if (issuer.error !== null) return <ApiErrorState error={issuer.error} retry={issuer.reload} />;
  if (issuer.value === null) return null;
  const value = issuer.value;
  async function replaceSecret(event: FormEvent): Promise<void> {
    event.preventDefault();
    const raw = clientSecret;
    discardClientSecret();
    setClientSecret("");
    setActionError(null);
    try {
      await apiRequest<void>(`${path}/browser-login/actions/replace-client-secret`, {
        method: "POST",
        body: { client_secret: raw },
      });
      issuer.reload();
    } catch (caught: unknown) {
      setActionError(
        caught instanceof ApiError
          ? caught
          : new ApiError(0, "network_error", "The server could not be reached."),
      );
    }
  }
  return (
    <>
      <PageHeader
        title={value.display_name}
        description="Immutable issuer identity, verifier-material lineage, explicit management ceilings, and optional browser-login configuration."
        actions={
          operationAllows(me, "system.identity_issuers.update") ? (
            <Link
              className="button button-secondary"
              href={`/admin/identity/issuers/${encodeURIComponent(issuerId)}/edit`}
            >
              Edit issuer
            </Link>
          ) : undefined
        }
      />
      <div className="metric-grid">
        <div className="metric-card">
          <span>Status</span>
          <Status value={value.status} />
        </div>
        <div className="metric-card">
          <span>Policy version</span>
          <strong>{value.policy_version}</strong>
        </div>
        <div className="metric-card">
          <span>Browser login</span>
          <strong>{value.browser_login === null ? "Not configured" : "Configured"}</strong>
        </div>
      </div>
      <Panel title="Trust evidence">
        <DefinitionList
          items={[
            { label: "Issuer ID", value: <Id>{value.id}</Id> },
            { label: "Stable name", value: value.name },
            { label: "Issuer URL", value: <code>{value.issuer}</code> },
            { label: "Subject claim", value: value.subject_claim },
            {
              label: "Verifier material",
              value:
                value.current_verifier_material_version_id === null ? (
                  "Not loaded"
                ) : (
                  <Id>{value.current_verifier_material_version_id}</Id>
                ),
            },
            { label: "Updated", value: formatDate(value.updated_at) },
          ]}
        />
      </Panel>
      <Panel title="Effective configuration">
        <JsonBlock value={issuerUpdateBody(value)} />
      </Panel>
      <Panel title="Verifier and browser validation">
        {actionError === null ? null : <ApiErrorState error={actionError} compact />}
        {actionResult === null ? null : (
          <JsonBlock value={actionResult} label="Validation result" />
        )}
        <div className="inline-actions">
          {operationAllows(me, "system.identity_issuers.refresh") ? (
            <button
              className="button button-secondary"
              type="button"
              onClick={() =>
                void apiRequest<void>(`${path}/actions/refresh-verifier-material`, {
                  method: "POST",
                })
                  .then(() => issuer.reload())
                  .catch((caught: unknown) =>
                    setActionError(
                      caught instanceof ApiError
                        ? caught
                        : new ApiError(0, "network_error", "The server could not be reached."),
                    ),
                  )
              }
            >
              Refresh verifier material
            </button>
          ) : null}
          {value.browser_login === null ||
          !operationAllows(me, "system.identity_issuers.validate_browser_login") ? null : (
            <button
              className="button button-secondary"
              type="button"
              onClick={() =>
                void apiRequest<JsonValue>(`${path}/browser-login/actions/validate`, {
                  method: "POST",
                })
                  .then((response) => setActionResult(response.value))
                  .catch((caught: unknown) =>
                    setActionError(
                      caught instanceof ApiError
                        ? caught
                        : new ApiError(0, "network_error", "The server could not be reached."),
                    ),
                  )
              }
            >
              Validate browser login
            </button>
          )}
        </div>
      </Panel>
      {value.browser_login === null ||
      !operationAllows(me, "system.identity_issuers.replace_client_secret") ? null : (
        <Panel
          title="Replace confidential client secret"
          description="Write-only material is immediately cleared and never returned."
        >
          <form onSubmit={(event) => void replaceSecret(event)} autoComplete="off">
            <Field label="Client secret" required>
              <input
                type="password"
                value={clientSecret}
                onChange={(event) => setClientSecret(event.target.value)}
                autoComplete="new-password"
                required
              />
            </Field>
            <button
              className="button button-primary"
              type="submit"
              disabled={clientSecret.length === 0}
            >
              Replace client secret
            </button>
          </form>
        </Panel>
      )}
    </>
  );
}

export function IdentityIssuerEditPage({ issuerId }: { issuerId: string }) {
  const path = `/api/v1/system/identity-issuers/${encodeURIComponent(issuerId)}`;
  const issuer = useApiResource<ExternalIdentityIssuer>(path);
  const [text, setText] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [conflict, setConflict] = useState(false);
  const discardChanges = useUnsavedChanges(text !== null);
  if (issuer.loading) return <LoadingState label="Loading issuer editor" />;
  if (issuer.error !== null) return <ApiErrorState error={issuer.error} retry={issuer.reload} />;
  if (issuer.value === null) return null;
  const current = issuer.value;
  const currentText = text ?? jsonText(issuerUpdateBody(current));
  let candidate: JsonValue = issuerUpdateBody(current);
  try {
    candidate = JSON.parse(currentText) as JsonValue;
  } catch {
    /* submit reports */
  }
  async function save(event: FormEvent): Promise<void> {
    event.preventDefault();
    setFormError(null);
    setError(null);
    setConflict(false);
    let body: Record<string, unknown>;
    try {
      body = parseObject(currentText);
    } catch (caught: unknown) {
      setFormError(caught instanceof Error ? caught.message : "Invalid JSON.");
      return;
    }
    setSubmitting(true);
    try {
      const response = await apiRequest<ExternalIdentityIssuer>(`${path}/actions/update`, {
        method: "POST",
        ifMatch: issuer.etag ?? undefined,
        body,
      });
      issuer.replace(response);
      discardChanges();
      navigate(`/admin/identity/issuers/${encodeURIComponent(issuerId)}`, true);
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
          setText(null);
          setConflict(false);
          issuer.reload();
        }}
      />
    );
  return (
    <>
      <PageHeader
        title="Edit identity issuer"
        description="Update the complete mutable trust aggregate against its latest opaque ETag."
      />
      <Panel title="Issuer configuration">
        <FormError message={formError} />
        {error === null ? null : <ApiErrorState error={error} compact />}
        <form onSubmit={(event) => void save(event)}>
          <Field label="Mutable issuer configuration" required>
            <textarea
              className="code-editor"
              rows={32}
              value={currentText}
              onChange={(event) => setText(event.target.value)}
              spellCheck={false}
            />
          </Field>
          <SubmitBar
            submitting={submitting}
            submitLabel="Save issuer"
            cancelHref={`/admin/identity/issuers/${encodeURIComponent(issuerId)}`}
          />
        </form>
      </Panel>
    </>
  );
}

export function IdentityBindingsPage({ me }: { me: CurrentPrincipal }) {
  const [cursor, setCursor] = useState<string | null>(null);
  const bindings = useApiResource<Page<ExternalIdentityBinding>>(
    `/api/v1/system/identity-bindings?limit=50${cursor === null ? "" : `&cursor=${encodeURIComponent(cursor)}`}`,
  );
  if (bindings.loading) return <LoadingState label="Loading identity bindings" />;
  if (bindings.error !== null)
    return <ApiErrorState error={bindings.error} retry={bindings.reload} />;
  const items = bindings.value?.items ?? [];
  return (
    <>
      <PageHeader
        title="Identity bindings"
        description="Explicit external issuer subject to durable local-user mappings."
        actions={
          operationAllows(me, "system.identity_bindings.create") ? (
            <Link className="button button-primary" href="/admin/identity/bindings/new">
              Create binding
            </Link>
          ) : undefined
        }
      />
      {items.length === 0 ? (
        <EmptyState
          title="No identity bindings"
          description="No external subjects are currently linked to local users."
        />
      ) : (
        <Panel>
          <Table
            columns={[
              { key: "subject", label: "External subject" },
              { key: "issuer", label: "Issuer" },
              { key: "user", label: "Local user" },
              { key: "status", label: "Status" },
              { key: "updated", label: "Updated" },
            ]}
            rows={items.map((binding) => ({
              subject: (
                <Link href={`/admin/identity/bindings/${encodeURIComponent(binding.id)}`}>
                  <strong>{binding.external_subject}</strong>
                  <Id>{binding.id}</Id>
                </Link>
              ),
              issuer: <Id>{binding.issuer_id}</Id>,
              user: <Id>{binding.user_id}</Id>,
              status: <Status value={binding.status} />,
              updated: formatDate(binding.updated_at),
            }))}
            getKey={(_, index) => items[index].id}
          />
        </Panel>
      )}
      <Pagination
        canContinue={bindings.value?.next_cursor !== null && bindings.value !== null}
        onContinue={() => setCursor(bindings.value?.next_cursor ?? null)}
      />
    </>
  );
}

export function IdentityBindingCreatePage() {
  const [issuerId, setIssuerId] = useState("");
  const [subject, setSubject] = useState("");
  const [userId, setUserId] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const idempotencyKeyFor = useIdempotencyKey();
  const discardChanges = useUnsavedChanges(
    issuerId.length > 0 || subject.length > 0 || userId.length > 0,
  );
  async function create(event: FormEvent): Promise<void> {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    const body = {
      issuer_id: issuerId.trim(),
      external_subject: subject.trim(),
      user_id: userId.trim(),
    };
    try {
      const response = await apiRequest<ExternalIdentityBinding>(
        "/api/v1/system/identity-bindings/actions/create",
        {
          method: "POST",
          idempotencyKey: idempotencyKeyFor(body),
          body,
        },
      );
      discardChanges();
      navigate(`/admin/identity/bindings/${encodeURIComponent(response.value.id)}`, true);
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
        title="Create identity binding"
        description="Link one exact issuer subject to one durable local user. Email is not used as the binding key."
      />
      <Panel title="Binding">
        <form onSubmit={(event) => void create(event)}>
          {error === null ? null : <ApiErrorState error={error} compact />}
          <Field label="Issuer ID" required>
            <input
              value={issuerId}
              onChange={(event) => setIssuerId(event.target.value)}
              required
            />
          </Field>
          <Field label="External subject" required>
            <input value={subject} onChange={(event) => setSubject(event.target.value)} required />
          </Field>
          <Field label="Local user ID" required>
            <input value={userId} onChange={(event) => setUserId(event.target.value)} required />
          </Field>
          <SubmitBar
            submitting={submitting}
            submitLabel="Create binding"
            cancelHref="/admin/identity/bindings"
          />
        </form>
      </Panel>
    </>
  );
}

export function IdentityBindingDetailPage({
  bindingId,
  me,
}: {
  bindingId: string;
  me: CurrentPrincipal;
}) {
  const path = `/api/v1/system/identity-bindings/${encodeURIComponent(bindingId)}`;
  const binding = useApiResource<ExternalIdentityBinding>(path);
  const [userId, setUserId] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [conflict, setConflict] = useState(false);
  const discardChanges = useUnsavedChanges(userId.length > 0);
  if (binding.loading) return <LoadingState label="Loading identity binding" />;
  if (binding.error !== null) return <ApiErrorState error={binding.error} retry={binding.reload} />;
  if (binding.value === null) return null;
  const value = binding.value;
  async function relink(event: FormEvent): Promise<void> {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    setConflict(false);
    try {
      const response = await apiRequest<ExternalIdentityBinding>(`${path}/actions/relink`, {
        method: "POST",
        ifMatch: binding.etag ?? undefined,
        body: { user_id: userId.trim() },
      });
      binding.replace(response);
      discardChanges();
      setUserId("");
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
        candidate={{ user_id: userId }}
        reload={() => {
          discardChanges();
          setUserId("");
          setConflict(false);
          binding.reload();
        }}
      />
    );
  return (
    <>
      <PageHeader
        title="Identity binding"
        description="Collision-aware mapping and explicit session-tightening lifecycle."
      />
      <Panel title="Binding evidence">
        <DefinitionList
          items={[
            { label: "Binding ID", value: <Id>{value.id}</Id> },
            { label: "Issuer ID", value: <Id>{value.issuer_id}</Id> },
            { label: "External subject", value: value.external_subject },
            { label: "Local user ID", value: <Id>{value.user_id}</Id> },
            { label: "Status", value: <Status value={value.status} /> },
            { label: "Updated", value: formatDate(value.updated_at) },
          ]}
        />
      </Panel>
      {operationAllows(me, "system.identity_bindings.relink") ? (
        <Panel title="Relink local user">
          <form onSubmit={(event) => void relink(event)}>
            {error === null ? null : <ApiErrorState error={error} compact />}
            <Field label="Destination user ID" required>
              <input value={userId} onChange={(event) => setUserId(event.target.value)} required />
            </Field>
            <button className="button button-primary" type="submit" disabled={submitting}>
              {submitting ? "Relinking…" : "Relink binding"}
            </button>
          </form>
        </Panel>
      ) : null}
      {operationAllows(me, "system.identity_bindings.remove") ? (
        <Panel title="Remove binding" className="danger-zone">
          <ConfirmAction
            title="Remove external identity binding"
            consequence="The issuer subject will no longer resolve to this local user and affected external sessions are revoked. The user row remains."
            label="Remove binding"
            danger
            onConfirm={async () => {
              await apiRequest<ExternalIdentityBinding>(`${path}/actions/remove`, {
                method: "POST",
                ifMatch: binding.etag ?? undefined,
              });
              navigate("/admin/identity/bindings", true);
            }}
          />
        </Panel>
      ) : null}
    </>
  );
}

export function ProvisioningPoliciesPage({ me }: { me: CurrentPrincipal }) {
  const [cursor, setCursor] = useState<string | null>(null);
  const policies = useApiResource<Page<ProvisioningPolicy>>(
    `/api/v1/system/provisioning-policies?limit=50${cursor === null ? "" : `&cursor=${encodeURIComponent(cursor)}`}`,
  );
  if (policies.loading) return <LoadingState label="Loading provisioning policies" />;
  if (policies.error !== null)
    return <ApiErrorState error={policies.error} retry={policies.reload} />;
  const items = policies.value?.items ?? [];
  return (
    <>
      <PageHeader
        title="Provisioning policies"
        description="Explicit bounded onboarding rules. Issuer claims never create implicit administrator authority."
        actions={
          operationAllows(me, "system.provisioning_policies.create") ? (
            <Link
              className="button button-primary"
              href="/admin/identity/provisioning-policies/new"
            >
              Create policy
            </Link>
          ) : undefined
        }
      />
      {items.length === 0 ? (
        <EmptyState
          title="No provisioning policies"
          description="No external onboarding policy is configured."
        />
      ) : (
        <Panel>
          <Table
            columns={[
              { key: "name", label: "Policy" },
              { key: "status", label: "Status" },
              { key: "kind", label: "User kind" },
              { key: "updated", label: "Updated" },
            ]}
            rows={items.map((policy) => ({
              name: (
                <Link
                  href={`/admin/identity/provisioning-policies/${encodeURIComponent(policy.id)}`}
                >
                  <strong>{policy.name}</strong>
                  <Id>{policy.id}</Id>
                </Link>
              ),
              status: <Status value={policy.status} />,
              kind: humanize(policy.user_kind),
              updated: formatDate(policy.updated_at),
            }))}
            getKey={(_, index) => items[index].id}
          />
        </Panel>
      )}
      <Pagination
        canContinue={policies.value?.next_cursor !== null && policies.value !== null}
        onContinue={() => setCursor(policies.value?.next_cursor ?? null)}
      />
    </>
  );
}

export function ProvisioningPolicyCreatePage() {
  const [text, setText] = useState(jsonText(PROVISIONING_TEMPLATE));
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const idempotencyKeyFor = useIdempotencyKey();
  const discardChanges = useUnsavedChanges(text !== jsonText(PROVISIONING_TEMPLATE));
  async function create(event: FormEvent): Promise<void> {
    event.preventDefault();
    setFormError(null);
    setError(null);
    let body: Record<string, unknown>;
    try {
      body = parseObject(text);
    } catch (caught: unknown) {
      setFormError(caught instanceof Error ? caught.message : "Invalid JSON.");
      return;
    }
    setSubmitting(true);
    try {
      const response = await apiRequest<ProvisioningPolicy>(
        "/api/v1/system/provisioning-policies/actions/create",
        { method: "POST", idempotencyKey: idempotencyKeyFor(body), body },
      );
      discardChanges();
      navigate(
        `/admin/identity/provisioning-policies/${encodeURIComponent(response.value.id)}`,
        true,
      );
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
        title="Create provisioning policy"
        description="Define an explicit onboarding aggregate with bounded user kind and organization assignment rules."
      />
      <Panel title="Policy aggregate">
        <FormError message={formError} />
        {error === null ? null : <ApiErrorState error={error} compact />}
        <form onSubmit={(event) => void create(event)}>
          <Field label="Provisioning policy" required>
            <textarea
              className="code-editor"
              rows={20}
              value={text}
              onChange={(event) => setText(event.target.value)}
              spellCheck={false}
            />
          </Field>
          <SubmitBar
            submitting={submitting}
            submitLabel="Create policy"
            cancelHref="/admin/identity/provisioning-policies"
          />
        </form>
      </Panel>
    </>
  );
}

export function ProvisioningPolicyDetailPage({
  policyId,
  me,
}: {
  policyId: string;
  me: CurrentPrincipal;
}) {
  const policy = useApiResource<ProvisioningPolicy>(
    `/api/v1/system/provisioning-policies/${encodeURIComponent(policyId)}`,
  );
  if (policy.loading) return <LoadingState label="Loading provisioning policy" />;
  if (policy.error !== null) return <ApiErrorState error={policy.error} retry={policy.reload} />;
  if (policy.value === null) return null;
  const value = policy.value;
  return (
    <>
      <PageHeader
        title={value.name}
        description="Explicit onboarding configuration and lifecycle."
        actions={
          operationAllows(me, "system.provisioning_policies.update") ? (
            <Link
              className="button button-secondary"
              href={`/admin/identity/provisioning-policies/${encodeURIComponent(policyId)}/edit`}
            >
              Edit policy
            </Link>
          ) : undefined
        }
      />
      <Panel title="Policy evidence">
        <DefinitionList
          items={[
            { label: "Policy ID", value: <Id>{value.id}</Id> },
            { label: "Status", value: <Status value={value.status} /> },
            { label: "User kind", value: humanize(value.user_kind) },
            { label: "Updated", value: formatDate(value.updated_at) },
          ]}
        />
      </Panel>
      <Panel title="Configuration">
        <JsonBlock value={value.configuration} />
      </Panel>
    </>
  );
}

export function ProvisioningPolicyEditPage({ policyId }: { policyId: string }) {
  const path = `/api/v1/system/provisioning-policies/${encodeURIComponent(policyId)}`;
  const policy = useApiResource<ProvisioningPolicy>(path);
  const [text, setText] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [conflict, setConflict] = useState(false);
  const discardChanges = useUnsavedChanges(text !== null);
  if (policy.loading) return <LoadingState label="Loading policy editor" />;
  if (policy.error !== null) return <ApiErrorState error={policy.error} retry={policy.reload} />;
  if (policy.value === null) return null;
  const current = policy.value;
  const initial: JsonValue = {
    name: current.name,
    status: current.status,
    user_kind: current.user_kind,
    configuration: current.configuration,
  };
  const currentText = text ?? jsonText(initial);
  let candidate: JsonValue = initial;
  try {
    candidate = JSON.parse(currentText) as JsonValue;
  } catch {
    /* submit reports */
  }
  async function save(event: FormEvent): Promise<void> {
    event.preventDefault();
    setFormError(null);
    setError(null);
    setConflict(false);
    let body: Record<string, unknown>;
    try {
      body = parseObject(currentText);
    } catch (caught: unknown) {
      setFormError(caught instanceof Error ? caught.message : "Invalid JSON.");
      return;
    }
    setSubmitting(true);
    try {
      const response = await apiRequest<ProvisioningPolicy>(`${path}/actions/update`, {
        method: "POST",
        ifMatch: policy.etag ?? undefined,
        body,
      });
      policy.replace(response);
      discardChanges();
      navigate(`/admin/identity/provisioning-policies/${encodeURIComponent(policyId)}`, true);
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
          setText(null);
          setConflict(false);
          policy.reload();
        }}
      />
    );
  return (
    <>
      <PageHeader
        title="Edit provisioning policy"
        description="Submit one complete bounded update against the latest ETag."
      />
      <Panel title="Policy aggregate">
        <FormError message={formError} />
        {error === null ? null : <ApiErrorState error={error} compact />}
        <form onSubmit={(event) => void save(event)}>
          <Field label="Provisioning policy" required>
            <textarea
              className="code-editor"
              rows={20}
              value={currentText}
              onChange={(event) => setText(event.target.value)}
              spellCheck={false}
            />
          </Field>
          <SubmitBar
            submitting={submitting}
            submitLabel="Save policy"
            cancelHref={`/admin/identity/provisioning-policies/${encodeURIComponent(policyId)}`}
          />
        </form>
      </Panel>
    </>
  );
}
