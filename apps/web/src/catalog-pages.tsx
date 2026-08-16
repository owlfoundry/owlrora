import { useState } from "react";

import {
  ApiError,
  apiRequest,
  formatDate,
  type CurrentPrincipal,
  type JsonValue,
  type Page,
} from "./api";
import { operationAllows, operationAuthority, operationPath } from "./operation-authority";
import { SchemaCommandForm, commandIsNonRepeatable } from "./schema-form";
import {
  ApiErrorState,
  ConfirmAction,
  DefinitionList,
  EmptyState,
  Id,
  JsonBlock,
  Link,
  LoadingState,
  PageHeader,
  Pagination,
  Panel,
  Status,
  Table,
  navigate,
  useApiResource,
} from "./ui";

export type CatalogScope = "system" | "organization";

interface CatalogFamily {
  browserFamily: string;
  label: string;
  operationFamily: string;
  idLabel: string;
  description: string;
  actionOperations: Array<{ id: string; label: string; consequence: string }>;
}

const SYSTEM_FAMILIES: Record<string, CatalogFamily> = {
  "egress-network-policies": {
    browserFamily: "egress-network-policies",
    label: "Egress network policies",
    operationFamily: "system.egress_network_policies",
    idLabel: "Egress policy",
    description:
      "Deployment-owned DNS, address, proxy, TLS, redirect, connection, and body bounds.",
    actionOperations: [],
  },
  credentials: {
    browserFamily: "credentials",
    label: "Upstream credentials",
    operationFamily: "system.upstream_credentials",
    idLabel: "Credential",
    description:
      "Deployment-owned protected upstream authentication material and safe source state.",
    actionOperations: [
      {
        id: "system.upstream_credentials.reload_source",
        label: "Reload source",
        consequence:
          "Reload the configured source and publish a new safe credential version when it changed.",
      },
      {
        id: "system.upstream_credentials.validate",
        label: "Validate credential",
        consequence: "Run the bounded provider validation flow without disclosing the secret.",
      },
      {
        id: "system.upstream_credentials.refresh",
        label: "Refresh credential",
        consequence: "Request a fenced refresh for a refreshable credential source.",
      },
    ],
  },
  endpoints: {
    browserFamily: "endpoints",
    label: "Upstream endpoints",
    operationFamily: "system.upstream_endpoints",
    idLabel: "Endpoint",
    description: "Deployment-owned provider origins, adapters, and egress policy bindings.",
    actionOperations: [
      {
        id: "system.upstream_endpoints.validate",
        label: "Validate endpoint",
        consequence: "Run bounded endpoint and network-policy validation.",
      },
    ],
  },
  deployments: {
    browserFamily: "deployments",
    label: "Model deployments",
    operationFamily: "system.model_deployments",
    idLabel: "Deployment",
    description: "Reusable endpoint, credential, transport, model, and capability bindings.",
    actionOperations: [
      {
        id: "system.model_deployments.validate",
        label: "Validate deployment",
        consequence: "Validate the composed transport without routing ordinary user traffic.",
      },
    ],
  },
  "model-routes": {
    browserFamily: "model-routes",
    label: "Model routes",
    operationFamily: "system.model_routes",
    idLabel: "Route",
    description: "Client-facing model keys with explicit targets, reliability, and state policy.",
    actionOperations: [],
  },
  "pricing-policies": {
    browserFamily: "pricing-policies",
    label: "Pricing policies",
    operationFamily: "system.pricing_policies",
    idLabel: "Pricing policy",
    description: "Versioned provider pricing used for bounded cost accounting.",
    actionOperations: [],
  },
  "reliability-policies": {
    browserFamily: "reliability-policies",
    label: "Reliability policies",
    operationFamily: "system.reliability_policies",
    idLabel: "Reliability policy",
    description: "Retry, failover, commitment, deadline, probe, and circuit behavior.",
    actionOperations: [],
  },
};

const ORGANIZATION_FAMILIES: Record<string, CatalogFamily> = {
  "upstream-credentials": {
    browserFamily: "upstream-credentials",
    label: "BYOK credentials",
    operationFamily: "organization.upstream_credentials",
    idLabel: "Credential",
    description: "Organization-owned write-only provider credentials and safe validation state.",
    actionOperations: [
      {
        id: "organization.upstream_credentials.validate",
        label: "Validate credential",
        consequence: "Validate this organization-owned credential without exposing its secret.",
      },
    ],
  },
  "model-deployments": {
    browserFamily: "model-deployments",
    label: "Model deployments",
    operationFamily: "organization.model_deployments",
    idLabel: "Deployment",
    description: "Same-organization BYOK deployments over explicitly granted system endpoints.",
    actionOperations: [
      {
        id: "organization.model_deployments.validate",
        label: "Validate deployment",
        consequence: "Validate the composed BYOK deployment with its bounded endpoint grant.",
      },
    ],
  },
  "model-routes": {
    browserFamily: "model-routes",
    label: "Model routes",
    operationFamily: "organization.model_routes",
    idLabel: "Route",
    description: "Organization-owned routes composed from allowed system and BYOK deployments.",
    actionOperations: [],
  },
};

export function catalogFamily(scope: CatalogScope, family: string): CatalogFamily | null {
  return (scope === "system" ? SYSTEM_FAMILIES : ORGANIZATION_FAMILIES)[family] ?? null;
}

function apiParams(
  operationId: string,
  organizationId?: string,
  resourceId?: string,
  sessionId?: string,
): Record<string, string> {
  const path = operationAuthority(operationId)?.path ?? "";
  const params: Record<string, string> = {};
  for (const name of path.matchAll(/\{([^}]+)\}/g)) {
    const key = name[1];
    if (key === "organization_id" && organizationId !== undefined) params[key] = organizationId;
    else if ((key === "session_id" || key === "login_session_id") && sessionId !== undefined)
      params[key] = sessionId;
    else if (resourceId !== undefined) params[key] = resourceId;
  }
  return params;
}

function browserBase(scope: CatalogScope, family: string, organizationId?: string): string {
  return scope === "system"
    ? `/admin/catalog/${family}`
    : `/organizations/${encodeURIComponent(organizationId ?? "")}/${family}`;
}

function objectValue(value: JsonValue): Record<string, JsonValue> {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function resourceId(value: JsonValue): string | null {
  const object = objectValue(value);
  for (const key of [
    "id",
    "credential_id",
    "endpoint_id",
    "deployment_id",
    "route_id",
    "policy_id",
  ]) {
    if (typeof object[key] === "string") return object[key];
  }
  return null;
}

function resourceName(value: JsonValue, fallback: string): string {
  const object = objectValue(value);
  for (const key of ["name", "display_name", "model_key", "credential_kind", "adapter_kind"]) {
    if (typeof object[key] === "string" && object[key].length > 0) return object[key];
  }
  return fallback;
}

function resourceStatus(value: JsonValue): string {
  const object = objectValue(value);
  for (const key of ["status", "administrative_status", "operational_status", "state"]) {
    if (typeof object[key] === "string") return object[key];
  }
  return "configured";
}

export function CatalogResourceListPage({
  scope,
  family,
  organizationId,
  me,
}: {
  scope: CatalogScope;
  family: string;
  organizationId?: string;
  me: CurrentPrincipal;
}) {
  const definition = catalogFamily(scope, family);
  const [cursor, setCursor] = useState<string | null>(null);
  const listOperation = `${definition?.operationFamily ?? "missing"}.list`;
  const path = operationPath(listOperation, apiParams(listOperation, organizationId));
  const resources = useApiResource<Page<JsonValue>>(
    path === null
      ? "/api/v1/console-contract-missing"
      : `${path}?limit=50${cursor === null ? "" : `&cursor=${encodeURIComponent(cursor)}`}`,
  );
  if (definition === null)
    return <ApiErrorState error={new ApiError(404, "not_found", "Unknown catalog family.")} />;
  if (resources.loading)
    return <LoadingState label={`Loading ${definition.label.toLowerCase()}`} />;
  if (resources.error !== null)
    return <ApiErrorState error={resources.error} retry={resources.reload} />;
  const items = resources.value?.items ?? [];
  const base = browserBase(scope, family, organizationId);
  return (
    <>
      <PageHeader
        title={definition.label}
        description={definition.description}
        actions={
          operationAllows(me, `${definition.operationFamily}.create`, organizationId) ? (
            <Link className="button button-primary" href={`${base}/new`}>
              Create {definition.idLabel.toLowerCase()}
            </Link>
          ) : undefined
        }
      />
      {items.length === 0 ? (
        <EmptyState
          title={`No ${definition.label.toLowerCase()}`}
          description="No resources are visible in this qualified catalog scope."
        />
      ) : (
        <Panel>
          <Table
            columns={[
              { key: "resource", label: definition.idLabel },
              { key: "status", label: "Status" },
              { key: "updated", label: "Updated" },
            ]}
            rows={items.map((item, index) => {
              const id = resourceId(item) ?? `unknown-${index}`;
              const object = objectValue(item);
              return {
                resource: (
                  <Link href={`${base}/${encodeURIComponent(id)}`}>
                    <strong>{resourceName(item, definition.idLabel)}</strong>
                    <Id>{id}</Id>
                  </Link>
                ),
                status: <Status value={resourceStatus(item)} />,
                updated:
                  typeof object.updated_at === "string"
                    ? formatDate(object.updated_at)
                    : "Not reported",
              };
            })}
            getKey={(_, index) => resourceId(items[index]) ?? String(index)}
          />
        </Panel>
      )}
      <Pagination
        canContinue={resources.value !== null && resources.value.next_cursor !== null}
        onContinue={() => setCursor(resources.value?.next_cursor ?? null)}
      />
    </>
  );
}

export function CatalogResourceCreatePage({
  scope,
  family,
  organizationId,
}: {
  scope: CatalogScope;
  family: string;
  organizationId?: string;
}) {
  const definition = catalogFamily(scope, family);
  if (definition === null)
    return <ApiErrorState error={new ApiError(404, "not_found", "Unknown catalog family.")} />;
  const operationId = `${definition.operationFamily}.create`;
  const base = browserBase(scope, family, organizationId);
  return (
    <>
      <PageHeader
        title={`Create ${definition.idLabel.toLowerCase()}`}
        description={definition.description}
      />
      <Panel title="Resource definition">
        <SchemaCommandForm
          operationId={operationId}
          params={apiParams(operationId, organizationId)}
          cancelHref={base}
          successHref={base}
          submitLabel={`Create ${definition.idLabel.toLowerCase()}`}
          secretLabel={definition.idLabel}
        />
      </Panel>
    </>
  );
}

export function CatalogResourceDetailPage({
  scope,
  family,
  organizationId,
  resourceId: id,
  me,
}: {
  scope: CatalogScope;
  family: string;
  organizationId?: string;
  resourceId: string;
  me: CurrentPrincipal;
}) {
  const definition = catalogFamily(scope, family);
  const operationId = `${definition?.operationFamily ?? "missing"}.get`;
  const path = operationPath(operationId, apiParams(operationId, organizationId, id));
  const resource = useApiResource<JsonValue>(path ?? "/api/v1/console-contract-missing");
  if (definition === null)
    return <ApiErrorState error={new ApiError(404, "not_found", "Unknown catalog family.")} />;
  if (resource.loading)
    return <LoadingState label={`Loading ${definition.idLabel.toLowerCase()}`} />;
  if (resource.error !== null)
    return <ApiErrorState error={resource.error} retry={resource.reload} />;
  if (resource.value === null) return null;
  const base = browserBase(scope, family, organizationId);
  const details = objectValue(resource.value);
  return (
    <>
      <PageHeader
        title={resourceName(resource.value, definition.idLabel)}
        description={definition.description}
        actions={
          operationAllows(me, `${definition.operationFamily}.update`, organizationId) ? (
            <Link className="button button-primary" href={`${base}/${encodeURIComponent(id)}/edit`}>
              Edit
            </Link>
          ) : undefined
        }
      />
      <Panel title="Safe metadata">
        <DefinitionList
          items={[
            { label: `${definition.idLabel} ID`, value: <Id>{id}</Id> },
            { label: "Status", value: <Status value={resourceStatus(resource.value)} /> },
            {
              label: "Updated",
              value:
                typeof details.updated_at === "string"
                  ? formatDate(details.updated_at)
                  : "Not reported",
            },
          ]}
        />
        <JsonBlock value={resource.value} label={`${definition.idLabel} safe metadata`} />
      </Panel>
      {family === "credentials" &&
      operationAllows(me, "system.upstream_credentials.replace_secret") ? (
        <Panel title="Protected material">
          <Link
            className="button button-secondary"
            href={`${base}/${encodeURIComponent(id)}/replace-secret`}
          >
            Replace secret
          </Link>
        </Panel>
      ) : null}
      {family === "upstream-credentials" &&
      operationAllows(me, "organization.upstream_credentials.replace_secret", organizationId) ? (
        <Panel title="Protected material">
          <Link
            className="button button-secondary"
            href={`${base}/${encodeURIComponent(id)}/replace-secret`}
          >
            Replace secret
          </Link>
        </Panel>
      ) : null}
      {definition.actionOperations
        .filter((action) => operationAllows(me, action.id, organizationId))
        .map((action) => {
          const actionPath = operationPath(action.id, apiParams(action.id, organizationId, id));
          const actionDefinition = operationAuthority(action.id);
          const recoveryHref = `${base}/${encodeURIComponent(id)}`;
          return (
            <Panel key={action.id} title={action.label}>
              <ConfirmAction
                title={action.label}
                consequence={action.consequence}
                label={action.label}
                outcomeUnknownRecovery={{ command: action.label, href: recoveryHref }}
                onConfirm={async () => {
                  if (actionPath === null || actionDefinition === null)
                    throw new ApiError(0, "console_contract_error", "Action path is unavailable.");
                  await apiRequest<JsonValue>(actionPath, {
                    method: "POST",
                    nonRepeatable: commandIsNonRepeatable(actionDefinition),
                  });
                  resource.reload();
                }}
              />
            </Panel>
          );
        })}
      {scope === "system" &&
      family === "pricing-policies" &&
      operationAllows(me, "system.pricing_policies.publish_version") ? (
        <Panel
          title="Publish pricing version"
          description="Publish an immutable rates and rounding snapshot from this policy ETag."
        >
          <SchemaCommandForm
            operationId="system.pricing_policies.publish_version"
            params={apiParams("system.pricing_policies.publish_version", undefined, id)}
            etag={resource.etag}
            cancelHref={`${base}/${encodeURIComponent(id)}`}
            successHref={`${base}/${encodeURIComponent(id)}`}
            submitLabel="Publish version"
          />
        </Panel>
      ) : null}
      {scope === "organization" &&
      family === "model-routes" &&
      operationAllows(me, "organization.model_routes.transfer_ownership", organizationId) ? (
        <Panel
          title="Transfer route ownership"
          description="Assign this organization route to an active same-organization local user."
        >
          <SchemaCommandForm
            operationId="organization.model_routes.transfer_ownership"
            params={apiParams("organization.model_routes.transfer_ownership", organizationId, id)}
            etag={resource.etag}
            cancelHref={`${base}/${encodeURIComponent(id)}`}
            successHref={`${base}/${encodeURIComponent(id)}`}
            submitLabel="Transfer ownership"
          />
        </Panel>
      ) : null}
      {scope === "system" &&
      family === "credentials" &&
      details.credential_kind === "oauth_openai_codex" &&
      operationAllows(me, "system.upstream_credentials.codex_login.start") ? (
        <Panel
          title="Start OpenAI Codex subscription login"
          description="Begin the community-maintained device flow. A transport interruption is treated as an unknown state-machine outcome and is never retried automatically."
        >
          <SchemaCommandForm
            operationId="system.upstream_credentials.codex_login.start"
            params={apiParams("system.upstream_credentials.codex_login.start", undefined, id)}
            cancelHref={`${base}/${encodeURIComponent(id)}`}
            successHref={(response) => {
              const session = resourceId(response);
              return session === null
                ? `${base}/${encodeURIComponent(id)}`
                : `${base}/${encodeURIComponent(id)}/codex-login/${encodeURIComponent(session)}`;
            }}
            submitLabel="Start device login"
            secretLabel="OpenAI Codex device code"
          />
        </Panel>
      ) : null}
    </>
  );
}

export function CatalogResourceEditPage({
  scope,
  family,
  organizationId,
  resourceId: id,
}: {
  scope: CatalogScope;
  family: string;
  organizationId?: string;
  resourceId: string;
}) {
  const definition = catalogFamily(scope, family);
  const getOperation = `${definition?.operationFamily ?? "missing"}.get`;
  const updateOperation = `${definition?.operationFamily ?? "missing"}.update`;
  const getPath = operationPath(getOperation, apiParams(getOperation, organizationId, id));
  const resource = useApiResource<JsonValue>(getPath ?? "/api/v1/console-contract-missing");
  if (definition === null)
    return <ApiErrorState error={new ApiError(404, "not_found", "Unknown catalog family.")} />;
  if (resource.loading)
    return <LoadingState label={`Loading ${definition.idLabel.toLowerCase()} editor`} />;
  if (resource.error !== null)
    return <ApiErrorState error={resource.error} retry={resource.reload} />;
  if (resource.value === null) return null;
  const detail = `${browserBase(scope, family, organizationId)}/${encodeURIComponent(id)}`;
  return (
    <>
      <PageHeader
        title={`Edit ${resourceName(resource.value, definition.idLabel)}`}
        description="Only selected fields are sent. Unselected fields preserve their current authoritative value."
      />
      <Panel title="Changes">
        <SchemaCommandForm
          operationId={updateOperation}
          params={apiParams(updateOperation, organizationId, id)}
          etag={resource.etag}
          initialValue={resource.value}
          cancelHref={detail}
          successHref={detail}
          submitLabel="Save changes"
        />
      </Panel>
    </>
  );
}

export function CredentialReplaceSecretPage({
  scope,
  organizationId,
  credentialId,
}: {
  scope: CatalogScope;
  organizationId?: string;
  credentialId: string;
}) {
  const family = scope === "system" ? "credentials" : "upstream-credentials";
  const prefix = scope === "system" ? "system" : "organization";
  const operationId = `${prefix}.upstream_credentials.replace_secret`;
  const detail = `${browserBase(scope, family, organizationId)}/${encodeURIComponent(credentialId)}`;
  return (
    <>
      <PageHeader
        title="Replace credential secret"
        description="Submit protected material through the dedicated write-only action. It never enters ordinary metadata updates or browser URLs."
      />
      <Panel title="New protected material">
        <SchemaCommandForm
          operationId={operationId}
          params={apiParams(operationId, organizationId, credentialId)}
          cancelHref={detail}
          successHref={detail}
          submitLabel="Replace secret"
        />
      </Panel>
    </>
  );
}

export function CodexLoginPage({
  credentialId,
  sessionId,
}: {
  credentialId: string;
  sessionId: string;
}) {
  const operationId = "system.upstream_credentials.codex_login.get";
  const params = apiParams(operationId, undefined, credentialId, sessionId);
  const path = operationPath(operationId, params);
  const state = useApiResource<JsonValue>(path ?? "/api/v1/console-contract-missing");
  const [clock, setClock] = useState(() => Date.now());
  const detail = `/admin/catalog/credentials/${encodeURIComponent(credentialId)}`;
  if (state.loading) return <LoadingState label="Loading Codex login session" />;
  if (state.error !== null) return <ApiErrorState error={state.error} retry={state.reload} />;
  const session = objectValue(state.value ?? null);
  const sessionState = typeof session.state === "string" ? session.state : "unknown";
  const nextPollAt =
    typeof session.next_poll_at === "string" ? Date.parse(session.next_poll_at) : Number.NaN;
  const readyToPoll =
    sessionState === "pending" && (Number.isNaN(nextPollAt) || nextPollAt <= clock);
  const cancellable = sessionState === "pending" || sessionState === "polling";
  const terminal = ["completed", "cancelled", "expired", "failed"].includes(sessionState);
  const sessionHref = `${detail}/codex-login/${encodeURIComponent(sessionId)}`;
  return (
    <>
      <PageHeader
        title="OpenAI Codex subscription login"
        description="Community-maintained, best-effort device authorization state for this credential. OAuth tokens never enter this URL or response."
      />
      {state.value === null ? null : (
        <Panel title="Safe device-flow state">
          <JsonBlock value={state.value} />
        </Panel>
      )}
      {readyToPoll ? (
        <Panel title="Complete authorization">
          <SchemaCommandForm
            operationId="system.upstream_credentials.codex_login.complete"
            params={apiParams(
              "system.upstream_credentials.codex_login.complete",
              undefined,
              credentialId,
              sessionId,
            )}
            cancelHref={sessionHref}
            successHref={(response) =>
              objectValue(response).outcome === "pending" ? sessionHref : detail
            }
            onSuccess={(response) => {
              if (objectValue(response).outcome === "pending") {
                setClock(Date.now());
                state.reload();
              }
            }}
            submitLabel="Check and complete"
          />
        </Panel>
      ) : terminal ? (
        <Panel
          title="Device flow finished"
          description="This session is terminal. Return to the credential before starting another device flow."
        >
          <Link className="button button-primary" href={detail}>
            Return to credential
          </Link>
        </Panel>
      ) : (
        <Panel
          title="Waiting for provider cadence"
          description={
            sessionState === "pending" && typeof session.next_poll_at === "string"
              ? `The next provider check is allowed after ${formatDate(session.next_poll_at)}.`
              : "A fenced provider check is currently in progress."
          }
        >
          <button
            className="button button-secondary"
            type="button"
            onClick={() => {
              setClock(Date.now());
              state.reload();
            }}
          >
            Refresh state
          </button>
        </Panel>
      )}
      {cancellable ? (
        <Panel title="Cancel login">
          <ConfirmAction
            title="Cancel device login"
            consequence="This login session becomes unusable. Existing credential versions are not exposed."
            label="Cancel login"
            danger
            outcomeUnknownRecovery={{ command: "the device-login cancellation", href: sessionHref }}
            onConfirm={async () => {
              const cancelOperationId = "system.upstream_credentials.codex_login.cancel";
              const cancelDefinition = operationAuthority(cancelOperationId);
              const cancelPath = operationPath(
                cancelOperationId,
                apiParams(cancelOperationId, undefined, credentialId, sessionId),
              );
              if (cancelPath === null || cancelDefinition === null)
                throw new ApiError(0, "console_contract_error", "Cancel path is unavailable.");
              await apiRequest<JsonValue>(cancelPath, {
                method: "POST",
                nonRepeatable: commandIsNonRepeatable(cancelDefinition),
              });
              navigate(detail, true);
            }}
          />
        </Panel>
      ) : null}
    </>
  );
}

export function SingletonPolicyPage({
  operationFamily,
  title,
  description,
  editHref,
  me,
  organizationId,
}: {
  operationFamily: string;
  title: string;
  description: string;
  editHref: string;
  me: CurrentPrincipal;
  organizationId?: string;
}) {
  const operationId = `${operationFamily}.get`;
  const path = operationPath(operationId, apiParams(operationId, organizationId));
  const value = useApiResource<JsonValue>(path ?? "/api/v1/console-contract-missing");
  if (value.loading) return <LoadingState label={`Loading ${title.toLowerCase()}`} />;
  if (value.error !== null) return <ApiErrorState error={value.error} retry={value.reload} />;
  return (
    <>
      <PageHeader
        title={title}
        description={description}
        actions={
          operationAllows(me, `${operationFamily}.update`, organizationId) ? (
            <Link className="button button-primary" href={editHref}>
              Edit
            </Link>
          ) : undefined
        }
      />
      {value.value === null ? null : (
        <Panel title="Authoritative policy">
          <JsonBlock value={value.value} />
        </Panel>
      )}
    </>
  );
}

export function SingletonPolicyEditPage({
  operationFamily,
  title,
  returnHref,
  organizationId,
}: {
  operationFamily: string;
  title: string;
  returnHref: string;
  organizationId?: string;
}) {
  const getOperation = `${operationFamily}.get`;
  const updateOperation = `${operationFamily}.update`;
  const path = operationPath(getOperation, apiParams(getOperation, organizationId));
  const value = useApiResource<JsonValue>(path ?? "/api/v1/console-contract-missing");
  if (value.loading) return <LoadingState label={`Loading ${title.toLowerCase()} editor`} />;
  if (value.error !== null) return <ApiErrorState error={value.error} retry={value.reload} />;
  if (value.value === null) return null;
  return (
    <>
      <PageHeader
        title={`Edit ${title.toLowerCase()}`}
        description="The update uses the resource ETag and sends only explicitly selected fields."
      />
      <Panel title="Changes">
        <SchemaCommandForm
          operationId={updateOperation}
          params={apiParams(updateOperation, organizationId)}
          etag={value.etag}
          initialValue={value.value}
          cancelHref={returnHref}
          successHref={returnHref}
          submitLabel="Save policy"
        />
      </Panel>
    </>
  );
}
