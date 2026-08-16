import { type FormEvent, useState } from "react";

import {
  apiRequest,
  formatDate,
  type AuditEntry,
  type CurrentPrincipal,
  type JsonValue,
  type Page,
} from "./api";
import { operationAllows } from "./operation-authority";
import { SchemaCommandForm } from "./schema-form";
import {
  ApiErrorState,
  ConfirmAction,
  DefinitionList,
  EmptyState,
  Field,
  Id,
  JsonBlock,
  LoadingState,
  PageHeader,
  Panel,
  Status,
  humanize,
  useApiResource,
} from "./ui";

export function AuditPage({ organizationId }: { organizationId?: string }) {
  const base =
    organizationId === undefined
      ? "/api/v1/system/audit"
      : `/api/v1/organizations/${encodeURIComponent(organizationId)}/audit`;
  const [operation, setOperation] = useState("");
  const [outcome, setOutcome] = useState("");
  const [resourceKind, setResourceKind] = useState("");
  const [since, setSince] = useState("");
  const [before, setBefore] = useState("");
  const [query, setQuery] = useState("limit=50");
  const audit = useApiResource<Page<AuditEntry>>(`${base}?${query}`);
  function filter(event: FormEvent): void {
    event.preventDefault();
    const next = new URLSearchParams({ limit: "50" });
    if (operation.trim() !== "") next.set("operation_id", operation.trim());
    if (outcome !== "") next.set("outcome", outcome);
    if (resourceKind.trim() !== "") next.set("target_resource_kind", resourceKind.trim());
    if (since !== "") next.set("since", new Date(since).toISOString());
    if (before !== "") next.set("before", new Date(before).toISOString());
    setQuery(next.toString());
  }
  return (
    <>
      <PageHeader
        title="Audit"
        description={
          organizationId === undefined
            ? "Deployment-wide immutable management evidence."
            : "Immutable management evidence qualified to this organization."
        }
      />
      <Panel title="Filters">
        <form className="form-grid" onSubmit={filter}>
          <Field label="Operation ID">
            <input value={operation} onChange={(event) => setOperation(event.target.value)} />
          </Field>
          <Field label="Outcome">
            <select value={outcome} onChange={(event) => setOutcome(event.target.value)}>
              <option value="">All outcomes</option>
              <option value="accepted">Accepted</option>
              <option value="rejected">Rejected</option>
              <option value="failed">Failed</option>
            </select>
          </Field>
          <Field label="Resource kind">
            <input value={resourceKind} onChange={(event) => setResourceKind(event.target.value)} />
          </Field>
          <Field label="Since">
            <input
              type="datetime-local"
              value={since}
              onChange={(event) => setSince(event.target.value)}
            />
          </Field>
          <Field label="Before">
            <input
              type="datetime-local"
              value={before}
              onChange={(event) => setBefore(event.target.value)}
            />
          </Field>
          <div className="field field-actions">
            <button className="button button-primary" type="submit">
              Apply filters
            </button>
          </div>
        </form>
      </Panel>
      {audit.loading ? <LoadingState label="Loading audit evidence" /> : null}
      {audit.error === null ? null : <ApiErrorState error={audit.error} retry={audit.reload} />}
      {audit.value?.items.length === 0 ? (
        <EmptyState
          title="No audit entries"
          description="No immutable evidence matched this qualified filter."
        />
      ) : null}
      <div className="timeline">
        {audit.value?.items.map((entry) => (
          <Panel key={entry.id}>
            <div className="row-summary">
              <div>
                <strong>{entry.operation_id}</strong>
                <span className="muted">{formatDate(entry.created_at)}</span>
              </div>
              <Status value={entry.outcome} />
            </div>
            <DefinitionList
              items={[
                { label: "Audit ID", value: <Id>{entry.id}</Id> },
                {
                  label: "Target",
                  value: (
                    <>
                      {humanize(entry.target_resource_kind)}{" "}
                      {entry.target_resource_id === null ? null : (
                        <Id>{entry.target_resource_id}</Id>
                      )}
                    </>
                  ),
                },
                { label: "Request", value: <Id>{entry.request_id}</Id> },
                {
                  label: "Changed fields",
                  value:
                    entry.changed_fields.length === 0 ? "None" : entry.changed_fields.join(", "),
                },
              ]}
            />
            <details>
              <summary>Safe actor and command details</summary>
              <div className="details-grid">
                <JsonBlock value={entry.actor ?? null} label="Actor" />
                <JsonBlock value={entry.authentication_evidence} label="Authentication evidence" />
                <JsonBlock value={entry.safe_details} label="Safe command details" />
              </div>
            </details>
          </Panel>
        ))}
      </div>
      {audit.value?.next_cursor === null || audit.value === null ? null : (
        <button
          className="button button-secondary pagination"
          type="button"
          onClick={() => {
            const next = new URLSearchParams(query);
            next.set("cursor", audit.value?.next_cursor ?? "");
            setQuery(next.toString());
          }}
        >
          Next page
        </button>
      )}
    </>
  );
}

const OPERATIONS_PATHS: Record<
  string,
  { api: string; browser: string; title: string; description: string }
> = {
  "admin-operations": {
    api: "/api/v1/system/operations",
    browser: "/admin/operations",
    title: "Operations",
    description: "Protected identity-plane operations overview.",
  },
  "admin-operations-readiness": {
    api: "/api/v1/system/operations/readiness",
    browser: "/admin/operations/readiness",
    title: "Readiness",
    description: "Process, database, and runtime publication readiness.",
  },
  "admin-operations-runtime": {
    api: "/api/v1/system/operations/runtime",
    browser: "/admin/operations/runtime",
    title: "Runtime",
    description: "Current-process applied revision and publication state plus the durable journal.",
  },
  "admin-operations-coordination": {
    api: "/api/v1/system/operations/coordination",
    browser: "/admin/operations/coordination",
    title: "Coordination",
    description: "Bounded worker lease and coordination evidence.",
  },
  "admin-operations-recoveries": {
    api: "/api/v1/system/operations/coordination/recoveries",
    browser: "/admin/operations/coordination/recoveries",
    title: "Recoveries",
    description:
      "Durably authorized coordinator recovery generations, installation state, and bounded exposure evidence.",
  },
  "admin-operations-activations": {
    api: "/api/v1/system/operations/coordination/activations",
    browser: "/admin/operations/coordination/activations",
    title: "Policy activations",
    description: "Staged, armed, active, and finalized policy generations with bounded deadlines.",
  },
  "admin-operations-state-origins": {
    api: "/api/v1/system/operations/state-origins",
    browser: "/admin/operations/state-origins",
    title: "State origins",
    description: "Bounded state-origin bindings, expiry, and cleanup readiness.",
  },
  "admin-operations-upstream-credentials": {
    api: "/api/v1/system/operations/upstream-credentials",
    browser: "/admin/operations/upstream-credentials",
    title: "Upstream credential controllers",
    description: "Refresh, login, and controller due-work with fenced safe error categories.",
  },
  "admin-operations-target-health": {
    api: "/api/v1/system/operations/target-health",
    browser: "/admin/operations/target-health",
    title: "Target health",
    description: "Current-process circuit state and cached shared probe observations.",
  },
  "admin-operations-usage-pipeline": {
    api: "/api/v1/system/operations/usage-pipeline",
    browser: "/admin/operations/usage-pipeline",
    title: "Usage pipeline",
    description: "Current-process queue, flush, loss, and persisted aggregate receipt evidence.",
  },
  "admin-operations-secret-custody": {
    api: "/api/v1/system/operations/secret-custody",
    browser: "/admin/operations/secret-custody",
    title: "Secret custody",
    description: "Protected-format readiness without secret values or ciphertext.",
  },
  "admin-operations-telemetry": {
    api: "/api/v1/system/operations/telemetry",
    browser: "/admin/operations/telemetry",
    title: "Telemetry",
    description: "Standard OpenTelemetry export posture and bounded status.",
  },
};

export function OperationsPage({ routeId, me }: { routeId: string; me: CurrentPrincipal }) {
  const definition = OPERATIONS_PATHS[routeId] ?? OPERATIONS_PATHS["admin-operations"];
  const evidence = useApiResource<JsonValue>(definition.api);
  return (
    <>
      <PageHeader
        title={definition.title}
        description={`${definition.description} Access additionally requires management:operations, management:read, effective system authority, and operator-network policy.`}
      />
      {evidence.loading ? (
        <LoadingState label={`Loading ${definition.title.toLowerCase()} evidence`} />
      ) : null}
      {evidence.error === null ? null : (
        <ApiErrorState error={evidence.error} retry={evidence.reload} />
      )}
      {evidence.value === null ? null : (
        <Panel title="Authoritative evidence">
          <JsonBlock value={evidence.value} />
        </Panel>
      )}
      {routeId === "admin-operations-runtime" &&
      operationAllows(me, "system.operations.runtime.reconcile") ? (
        <Panel
          title="Reconcile runtime"
          description="Request an immediate runtime generation refresh and journal the accepted result."
        >
          <ConfirmAction
            title="Reconcile runtime generation"
            consequence="The process handling this request refreshes from one PostgreSQL revision fence. This is an audited operations command, not a bypass of normal publication."
            label="Reconcile runtime"
            onConfirm={async () => {
              await apiRequest<JsonValue>("/api/v1/system/operations/runtime/actions/reconcile", {
                method: "POST",
              });
              evidence.reload();
            }}
          />
        </Panel>
      ) : null}
      {routeId === "admin-operations-recoveries" &&
      operationAllows(me, "system.operations.coordination.recoveries.create") ? (
        <Panel
          title="Authorize coordinator recovery"
          description="Create the next immutable recovery generation for one incident after verified coordinator state loss."
        >
          <SchemaCommandForm
            operationId="system.operations.coordination.recoveries.create"
            params={{}}
            cancelHref={definition.browser}
            successHref={definition.browser}
            submitLabel="Authorize recovery"
            description={
              <div className="alert alert-danger">
                <strong>Destructive recovery boundary</strong>
                <span>
                  The durable allocation is authoritative and fences older local allowances. Verify
                  incident evidence and policy IDs before submitting this non-repeatable command.
                </span>
              </div>
            }
          />
        </Panel>
      ) : null}
      {routeId === "admin-operations-activations" &&
      operationAllows(me, "system.operations.coordination.activations.reconcile") ? (
        <Panel title="Reconcile policy activations">
          <ConfirmAction
            title="Reconcile policy activations"
            consequence="The controller advances only activation state whose persisted deadlines and acknowledgements permit it. The command is audited."
            label="Reconcile activations"
            onConfirm={async () => {
              await apiRequest<JsonValue>(
                "/api/v1/system/operations/coordination/activations/actions/reconcile",
                { method: "POST" },
              );
              evidence.reload();
            }}
          />
        </Panel>
      ) : null}
      {routeId === "admin-operations-state-origins" &&
      operationAllows(me, "system.operations.state_origins.cleanup") ? (
        <Panel
          title="Cleanup expired state origins"
          description="Scan one organization-qualified Redis keyspace with a bounded opaque cursor."
        >
          <SchemaCommandForm
            operationId="system.operations.state_origins.cleanup"
            params={{}}
            cancelHref={definition.browser}
            successHref={definition.browser}
            submitLabel="Cleanup state origins"
          />
        </Panel>
      ) : null}
      {routeId === "admin-operations-upstream-credentials" &&
      operationAllows(me, "system.operations.upstream_credentials.reconcile") ? (
        <Panel title="Reconcile credential controllers">
          <ConfirmAction
            title="Reconcile upstream credential controllers"
            consequence="Due source reloads, expired refresh leases, login sessions, and refreshable credentials are processed through their fenced state machines."
            label="Reconcile controllers"
            onConfirm={async () => {
              await apiRequest<JsonValue>(
                "/api/v1/system/operations/upstream-credentials/actions/reconcile",
                { method: "POST" },
              );
              evidence.reload();
            }}
          />
        </Panel>
      ) : null}
      {routeId === "admin-operations-target-health" &&
      operationAllows(me, "system.operations.target_health.probe") ? (
        <Panel
          title="Probe selected targets"
          description="Run bounded probes for up to 64 explicit target IDs without routing ordinary user traffic."
        >
          <SchemaCommandForm
            operationId="system.operations.target_health.probe"
            params={{}}
            cancelHref={definition.browser}
            successHref={definition.browser}
            submitLabel="Probe targets"
          />
        </Panel>
      ) : null}
      {routeId === "admin-operations-usage-pipeline" &&
      operationAllows(me, "system.operations.usage_pipeline.flush") ? (
        <Panel title="Flush usage pipeline">
          <ConfirmAction
            title="Flush this process usage queue"
            consequence="Currently queued usage facts are offered to the durable aggregate writer. The response reports bounded before and after counts."
            label="Flush usage"
            onConfirm={async () => {
              await apiRequest<JsonValue>(
                "/api/v1/system/operations/usage-pipeline/actions/flush",
                { method: "POST" },
              );
              evidence.reload();
            }}
          />
        </Panel>
      ) : null}
      {routeId === "admin-operations-recoveries" &&
      operationAllows(me, "system.operations.identity_state.cleanup") ? (
        <Panel
          title="Cleanup expired identity state"
          description="Deletes expired OIDC states, completed idempotency records, and old sessions in bounded SKIP LOCKED batches."
        >
          <ConfirmAction
            title="Cleanup expired identity state"
            consequence="Only expired or long-revoked identity state is removed. The accepted command and bounded count are audited."
            label="Run identity cleanup"
            danger
            onConfirm={async () => {
              await apiRequest<JsonValue>(
                "/api/v1/system/operations/identity-state/actions/cleanup",
                { method: "POST" },
              );
              evidence.reload();
            }}
          />
        </Panel>
      ) : null}
    </>
  );
}
