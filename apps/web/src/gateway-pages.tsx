import { useState } from "react";

import { formatDate, type CurrentPrincipal, type JsonValue, type Page } from "./api";
import { operationAllows, operationAuthority, operationPath } from "./operation-authority";
import { SchemaCommandForm } from "./schema-form";
import {
  ApiErrorState,
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
  useApiResource,
} from "./ui";

function params(
  operationId: string,
  organizationId: string,
  keyId?: string,
): Record<string, string> {
  const path = operationAuthority(operationId)?.path ?? "";
  const result: Record<string, string> = { organization_id: organizationId };
  for (const match of path.matchAll(/\{([^}]+)\}/g)) {
    if (match[1] !== "organization_id" && keyId !== undefined) result[match[1]] = keyId;
  }
  return result;
}

function path(operationId: string, organizationId: string, keyId?: string): string {
  return (
    operationPath(operationId, params(operationId, organizationId, keyId)) ??
    "/api/v1/console-contract-missing"
  );
}

function object(value: JsonValue): Record<string, JsonValue> {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function stringField(value: JsonValue, name: string, fallback = "Not reported"): string {
  const candidate = object(value)[name];
  return typeof candidate === "string" ? candidate : fallback;
}

function stringArray(value: JsonValue, name: string): string[] {
  const candidate = object(value)[name];
  return Array.isArray(candidate)
    ? candidate.filter((item): item is string => typeof item === "string")
    : [];
}

function keyBase(organizationId: string): string {
  return `/organizations/${encodeURIComponent(organizationId)}/gateway-api-keys`;
}

export function GatewayKeyListPage({
  organizationId,
  me,
}: {
  organizationId: string;
  me: CurrentPrincipal;
}) {
  const [cursor, setCursor] = useState<string | null>(null);
  const list = useApiResource<Page<JsonValue>>(
    `${path("organization.gateway_api_keys.list", organizationId)}?limit=50${
      cursor === null ? "" : `&cursor=${encodeURIComponent(cursor)}`
    }`,
  );
  if (list.loading) return <LoadingState label="Loading Gateway API keys" />;
  if (list.error !== null) return <ApiErrorState error={list.error} retry={list.reload} />;
  const items = list.value?.items ?? [];
  const base = keyBase(organizationId);
  return (
    <>
      <PageHeader
        title="Gateway API keys"
        description="Organization-owned LLM request principals with a non-empty route allowlist, finite overall budget, and optional key-only limits."
        actions={
          operationAllows(me, "organization.gateway_api_keys.create", organizationId) ? (
            <Link className="button button-primary" href={`${base}/new`}>
              Create Gateway API key
            </Link>
          ) : undefined
        }
      />
      <div className="alert alert-info">
        <strong>Separate credential class</strong>
        <span>
          Gateway API keys are accepted only by LLM gateway surfaces. They cannot authenticate to
          management APIs and are never owned by their creator user.
        </span>
      </div>
      {items.length === 0 ? (
        <EmptyState
          title="No Gateway API keys"
          description="No quota-bearing LLM request principals are visible in this organization."
        />
      ) : (
        <Panel>
          <Table
            columns={[
              { key: "key", label: "Key" },
              { key: "scopes", label: "Scopes" },
              { key: "routes", label: "Allowed routes" },
              { key: "status", label: "Status" },
              { key: "expires", label: "Expiry" },
            ]}
            rows={items.map((item) => {
              const id = stringField(item, "id");
              return {
                key: (
                  <Link href={`${base}/${encodeURIComponent(id)}`}>
                    <strong>{stringField(item, "name", "Unnamed key")}</strong>
                    <Id>{id}</Id>
                  </Link>
                ),
                scopes: stringArray(item, "scopes").join(", "),
                routes: String(stringArray(item, "route_ids").length),
                status: <Status value={stringField(item, "status", "unknown")} />,
                expires: (() => {
                  const expiresAt = object(item).expires_at;
                  return formatDate(typeof expiresAt === "string" ? expiresAt : null);
                })(),
              };
            })}
            getKey={(_, index) => stringField(items[index], "id", String(index))}
          />
        </Panel>
      )}
      <Pagination
        canContinue={list.value !== null && list.value.next_cursor !== null}
        onContinue={() => setCursor(list.value?.next_cursor ?? null)}
      />
    </>
  );
}

export function GatewayKeyCreatePage({ organizationId }: { organizationId: string }) {
  const base = keyBase(organizationId);
  return (
    <>
      <PageHeader
        title="Create Gateway API key"
        description="The route allowlist must be non-empty and the overall budget finite. The raw key is returned exactly once."
      />
      <Panel title="Key and initial budget">
        <SchemaCommandForm
          operationId="organization.gateway_api_keys.create"
          params={params("organization.gateway_api_keys.create", organizationId)}
          cancelHref={base}
          successHref={base}
          submitLabel="Create Gateway API key"
          secretLabel="Gateway API key"
        />
      </Panel>
    </>
  );
}

export function GatewayKeyDetailPage({
  organizationId,
  keyId,
  me,
}: {
  organizationId: string;
  keyId: string;
  me: CurrentPrincipal;
}) {
  const key = useApiResource<JsonValue>(
    path("organization.gateway_api_keys.get", organizationId, keyId),
  );
  const budget = useApiResource<JsonValue>(
    path("organization.gateway_api_keys.budget.get", organizationId, keyId),
  );
  if (key.loading) return <LoadingState label="Loading Gateway API key" />;
  if (key.error !== null) return <ApiErrorState error={key.error} retry={key.reload} />;
  if (key.value === null) return null;
  const base = `${keyBase(organizationId)}/${encodeURIComponent(keyId)}`;
  return (
    <>
      <PageHeader
        title={stringField(key.value, "name", "Gateway API key")}
        description="Safe metadata only. Raw key material and verifier digests are never returned."
        actions={
          operationAllows(me, "organization.gateway_api_keys.update", organizationId) ? (
            <Link className="button button-primary" href={`${base}/edit`}>
              Edit key policy
            </Link>
          ) : undefined
        }
      />
      <Panel title="Key policy">
        <DefinitionList
          items={[
            { label: "Gateway key ID", value: <Id>{keyId}</Id> },
            {
              label: "Status",
              value: <Status value={stringField(key.value, "status", "unknown")} />,
            },
            { label: "Scopes", value: stringArray(key.value, "scopes").join(", ") || "None" },
            {
              label: "Route allowlist",
              value: stringArray(key.value, "route_ids").map((id) => <Id key={id}>{id}</Id>),
            },
            {
              label: "Created by principal",
              value: <JsonBlock value={object(key.value).created_by_principal ?? null} />,
            },
          ]}
        />
      </Panel>
      <div className="action-grid">
        <Link className="action-card" href={`${base}/budget`}>
          <strong>Overall budget</strong>
          <span>Finite threshold, mode, epoch, grants, and drift</span>
        </Link>
        <Link className="action-card" href={`${base}/limits`}>
          <strong>Request limits</strong>
          <span>Optional key-only rate and concurrency controls</span>
        </Link>
        {operationAllows(me, "organization.gateway_api_keys.rotate", organizationId) ? (
          <Link className="action-card" href={`${base}/rotate`}>
            <strong>Rotate key</strong>
            <span>Issue one-time material and bound overlap</span>
          </Link>
        ) : null}
      </div>
      <Panel title="Budget summary">
        {budget.loading ? <LoadingState label="Loading key budget" /> : null}
        {budget.error !== null ? (
          <ApiErrorState error={budget.error} retry={budget.reload} compact />
        ) : null}
        {budget.value === null ? null : <JsonBlock value={budget.value} />}
      </Panel>
    </>
  );
}

export function GatewayKeyEditPage({
  organizationId,
  keyId,
}: {
  organizationId: string;
  keyId: string;
}) {
  const key = useApiResource<JsonValue>(
    path("organization.gateway_api_keys.get", organizationId, keyId),
  );
  const detail = `${keyBase(organizationId)}/${encodeURIComponent(keyId)}`;
  if (key.loading) return <LoadingState label="Loading Gateway API key editor" />;
  if (key.error !== null) return <ApiErrorState error={key.error} retry={key.reload} />;
  if (key.value === null) return null;
  return (
    <>
      <PageHeader
        title="Edit Gateway API key"
        description="Only selected fields are sent; the current ETag protects the whole key policy. Budget and limits remain separate resources."
      />
      <Panel title="Policy changes">
        <SchemaCommandForm
          operationId="organization.gateway_api_keys.update"
          params={params("organization.gateway_api_keys.update", organizationId, keyId)}
          etag={key.etag}
          initialValue={key.value}
          cancelHref={detail}
          successHref={detail}
          submitLabel="Save key policy"
        />
      </Panel>
    </>
  );
}

export function GatewayKeyRotatePage({
  organizationId,
  keyId,
}: {
  organizationId: string;
  keyId: string;
}) {
  const key = useApiResource<JsonValue>(
    path("organization.gateway_api_keys.get", organizationId, keyId),
  );
  const detail = `${keyBase(organizationId)}/${encodeURIComponent(keyId)}`;
  if (key.loading) return <LoadingState label="Loading Gateway API key rotation" />;
  if (key.error !== null) return <ApiErrorState error={key.error} retry={key.reload} />;
  if (key.value === null) return null;
  return (
    <>
      <PageHeader
        title="Rotate Gateway API key"
        description="Rotation is an at-most-once command. A later positive-overlap rotation retires any older overlap before the current version enters the single overlap slot."
      />
      <Panel title="Rotation boundary">
        <SchemaCommandForm
          operationId="organization.gateway_api_keys.rotate"
          params={params("organization.gateway_api_keys.rotate", organizationId, keyId)}
          etag={key.etag}
          cancelHref={detail}
          successHref={detail}
          submitLabel="Rotate Gateway API key"
          secretLabel="Gateway API key"
        />
      </Panel>
    </>
  );
}

function PolicyEditor({
  organizationId,
  keyId,
  kind,
}: {
  organizationId: string;
  keyId: string;
  kind: "budget" | "limits";
}) {
  const family = `organization.gateway_api_keys.${kind}`;
  const getOperation = `${family}.get`;
  const updateOperation = `${family}.update`;
  const policy = useApiResource<JsonValue>(path(getOperation, organizationId, keyId));
  const href = `${keyBase(organizationId)}/${encodeURIComponent(keyId)}/${kind}`;
  if (policy.loading) return <LoadingState label={`Loading key ${kind}`} />;
  if (policy.error !== null) return <ApiErrorState error={policy.error} retry={policy.reload} />;
  if (policy.value === null) return null;
  return (
    <>
      <PageHeader
        title={kind === "budget" ? "Gateway-key overall budget" : "Gateway-key request limits"}
        description={
          kind === "budget"
            ? "Finite quota policy for this key. Actual attempts also settle against their system-provided or BYOK origin pool."
            : "Optional key-only rate and concurrency policy. These limits do not replace origin or overall budget accounting."
        }
      />
      <Panel title="Current desired and active state">
        <JsonBlock value={policy.value} />
      </Panel>
      <Panel title="Update policy">
        <SchemaCommandForm
          operationId={updateOperation}
          params={params(updateOperation, organizationId, keyId)}
          etag={policy.etag}
          initialValue={policy.value}
          cancelHref={`${keyBase(organizationId)}/${encodeURIComponent(keyId)}`}
          successHref={href}
          submitLabel={`Update ${kind}`}
        />
      </Panel>
      {kind === "budget" ? (
        <Panel
          title="Begin a new epoch"
          description="A keyed command creates a fresh bounded accounting epoch without rewriting settled usage."
        >
          <SchemaCommandForm
            operationId="organization.gateway_api_keys.budget.begin_epoch"
            params={params(
              "organization.gateway_api_keys.budget.begin_epoch",
              organizationId,
              keyId,
            )}
            cancelHref={href}
            successHref={href}
            submitLabel="Begin budget epoch"
          />
        </Panel>
      ) : null}
    </>
  );
}

export function GatewayKeyBudgetPage(props: { organizationId: string; keyId: string }) {
  return <PolicyEditor {...props} kind="budget" />;
}

export function GatewayKeyLimitsPage(props: { organizationId: string; keyId: string }) {
  return <PolicyEditor {...props} kind="limits" />;
}

function providerPath(operationId: string, organizationId: string): string {
  return (
    operationPath(operationId, { organization_id: organizationId }) ??
    "/api/v1/console-contract-missing"
  );
}

export function ProviderBudgetsPage({
  organizationId,
  me,
}: {
  organizationId: string;
  me: CurrentPrincipal;
}) {
  const system = useApiResource<JsonValue>(
    providerPath("organization.provider_budgets.system.get", organizationId),
  );
  const byok = useApiResource<JsonValue>(
    providerPath("organization.provider_budgets.byok.get", organizationId),
  );
  const base = `/organizations/${encodeURIComponent(organizationId)}/provider-budgets`;
  return (
    <>
      <PageHeader
        title="Provider budgets"
        description="System-provided allocation and organization-managed BYOK capacity remain separate origin pools. They are never presented as one merged balance."
      />
      <Panel title="System-provided pool">
        {system.loading ? <LoadingState label="Loading system-provider allocation" /> : null}
        {system.error !== null ? (
          <ApiErrorState error={system.error} retry={system.reload} compact />
        ) : null}
        {system.value === null ? null : <JsonBlock value={system.value} />}
      </Panel>
      <Panel
        title="Organization BYOK pool"
        description="Owners and administrators manage this pool within the deployment ceilings."
      >
        {byok.loading ? <LoadingState label="Loading BYOK provider budget" /> : null}
        {byok.error !== null ? (
          <ApiErrorState error={byok.error} retry={byok.reload} compact />
        ) : null}
        {byok.value === null ? null : <JsonBlock value={byok.value} />}
        {operationAllows(me, "organization.provider_budgets.byok.update", organizationId) ? (
          <Link className="button button-primary" href={`${base}/byok/edit`}>
            Edit BYOK budget
          </Link>
        ) : null}
      </Panel>
    </>
  );
}

export function ProviderBudgetEditPage({
  organizationId,
  origin,
  returnHref,
}: {
  organizationId: string;
  origin: "system" | "byok";
  returnHref: string;
}) {
  const family = `organization.provider_budgets.${origin}`;
  const getOperation = `${family}.get`;
  const updateOperation = `${family}.update`;
  const value = useApiResource<JsonValue>(providerPath(getOperation, organizationId));
  if (value.loading) return <LoadingState label={`Loading ${origin} provider budget`} />;
  if (value.error !== null) return <ApiErrorState error={value.error} retry={value.reload} />;
  if (value.value === null) return null;
  return (
    <>
      <PageHeader
        title={origin === "system" ? "System-provider allocation" : "Organization BYOK budget"}
        description="Desired and active versions remain visible separately while Redis policy activation converges."
      />
      <Panel title="Current policy">
        <JsonBlock value={value.value} />
      </Panel>
      <Panel title="Update provider budget">
        <SchemaCommandForm
          operationId={updateOperation}
          params={{ organization_id: organizationId }}
          etag={value.etag}
          initialValue={value.value}
          cancelHref={returnHref}
          successHref={returnHref}
          submitLabel="Update provider budget"
        />
      </Panel>
      <Panel title="Begin a new epoch">
        <SchemaCommandForm
          operationId={`${family}.begin_epoch`}
          params={{ organization_id: organizationId }}
          cancelHref={returnHref}
          successHref={returnHref}
          submitLabel="Begin provider-budget epoch"
        />
      </Panel>
    </>
  );
}

const GRANT_FAMILIES = [
  ["system_route_grants", "System route grants"],
  ["endpoint_grants", "Endpoint grants"],
  ["deployment_grants", "Deployment grants"],
  ["reliability_policy_grants", "Reliability policy grants"],
] as const;

function GrantPanel({
  organizationId,
  family,
  title,
}: {
  organizationId: string;
  family: string;
  title: string;
}) {
  const getOperation = `organization.${family}.get`;
  const updateOperation = `organization.${family}.update`;
  const value = useApiResource<JsonValue>(providerPath(getOperation, organizationId));
  if (value.loading) return <LoadingState label={`Loading ${title.toLowerCase()}`} />;
  if (value.error !== null)
    return <ApiErrorState error={value.error} retry={value.reload} compact />;
  if (value.value === null) return null;
  const href = `/admin/organizations/${encodeURIComponent(organizationId)}/catalog-grants`;
  return (
    <Panel title={title}>
      <JsonBlock value={value.value} />
      <SchemaCommandForm
        operationId={updateOperation}
        params={{ organization_id: organizationId }}
        etag={value.etag}
        initialValue={value.value}
        cancelHref={`/admin/organizations/${encodeURIComponent(organizationId)}`}
        successHref={href}
        submitLabel={`Update ${title.toLowerCase()}`}
      />
    </Panel>
  );
}

export function CatalogGrantsPage({ organizationId }: { organizationId: string }) {
  return (
    <>
      <PageHeader
        title="Organization catalog grants"
        description="Complete route, endpoint, deployment, and reliability-policy grant sets. Each singleton uses its own ETag and explicit organization context."
      />
      {GRANT_FAMILIES.map(([family, title]) => (
        <GrantPanel key={family} organizationId={organizationId} family={family} title={title} />
      ))}
    </>
  );
}
