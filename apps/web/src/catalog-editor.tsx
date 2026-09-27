import { useEffect, useRef, useState } from "react";

import { ApiError, apiRequest, type JsonValue, type Page } from "./api";
import compatibility from "./catalog_compatibility.json";
import { operationPath, type JsonSchema } from "./operation-authority";
import {
  SchemaCommandForm,
  type CommandControlProps,
  type SchemaCommandFormProps,
} from "./schema-form";
import { ApiErrorState, Field, Link, humanize } from "./ui";

export function asObject(value: JsonValue | undefined): Record<string, JsonValue> {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value : {};
}

interface Choice {
  id: string;
  label: string;
  resource: Record<string, JsonValue>;
  granted: boolean;
}

export function catalogChoices(items: JsonValue[]): Choice[] {
  return items.flatMap((item) => {
    const wrapper = asObject(item);
    const resource = asObject(
      wrapper.deployment ?? wrapper.endpoint ?? wrapper.reliability_policy ?? wrapper.route ?? item,
    );
    return typeof resource.id !== "string"
      ? []
      : [
          {
            id: resource.id,
            label: String(resource.name ?? resource.model_key ?? resource.id),
            resource,
            granted: wrapper.granted !== false,
          },
        ];
  });
}

interface Source {
  items: Choice[];
  cursor: string | null;
  loading: boolean;
  error: ApiError | null;
}

function useCatalogSources(paths: string[]) {
  const [sources, setSources] = useState<Record<string, Source>>({});
  const controller = useRef<AbortController | null>(null);
  const key = JSON.stringify(paths);
  async function load(path: string, cursor: string | null, signal: AbortSignal) {
    setSources((current) => ({
      ...current,
      [path]: { items: current[path]?.items ?? [], cursor, loading: true, error: null },
    }));
    try {
      const response = await apiRequest<Page<JsonValue>>(
        `${path}?limit=50${cursor === null ? "" : `&cursor=${encodeURIComponent(cursor)}`}`,
        { signal },
      );
      if (signal.aborted) return;
      setSources((current) => ({
        ...current,
        [path]: {
          items: [
            ...(cursor === null ? [] : (current[path]?.items ?? [])),
            ...catalogChoices(response.value.items),
          ],
          cursor: response.value.next_cursor,
          loading: false,
          error: null,
        },
      }));
    } catch (error) {
      if (signal.aborted) return;
      setSources((current) => ({
        ...current,
        [path]: {
          items: current[path]?.items ?? [],
          cursor,
          loading: false,
          error:
            error instanceof ApiError
              ? error
              : new ApiError(0, "network_error", "Catalog could not be loaded."),
        },
      }));
    }
  }
  useEffect(() => {
    const abort = new AbortController();
    controller.current = abort;
    for (const path of JSON.parse(key) as string[]) void load(path, null, abort.signal);
    return () => abort.abort();
  }, [key]);
  return {
    choices: (selected: string[]) => selected.flatMap((path) => sources[path]?.items ?? []),
    controls: (selected: string[]) =>
      selected.map((path) => {
        const source = sources[path];
        return (
          <div key={path}>
            {source === undefined || source.loading ? (
              <p role="status">Loading catalog choices…</p>
            ) : null}
            {source?.error ? <ApiErrorState error={source.error} /> : null}
            {source && !source.loading && (source.cursor !== null || source.error !== null) ? (
              <button
                type="button"
                className="button button-secondary"
                onClick={() => {
                  if (controller.current) void load(path, source.cursor, controller.current.signal);
                }}
              >
                {source.error ? "Retry choices" : "Load more choices"}
              </button>
            ) : null}
          </div>
        );
      }),
  };
}

function ChoiceSelect({
  value,
  choices,
  onChange,
}: {
  value: string;
  choices: Choice[];
  onChange: (value: string) => void;
}) {
  return (
    <select
      aria-label="Resource"
      value={value}
      required
      onChange={(event) => onChange(event.target.value)}
    >
      <option value="">Select a resource</option>
      {value && !choices.some((choice) => choice.id === value) ? (
        <option value={value}>{value} — current selection; load choices to inspect</option>
      ) : null}
      {choices.map((choice) => (
        <option
          key={choice.id}
          value={choice.id}
          disabled={!choice.granted || choice.resource.status === "disabled"}
        >
          {choice.label} · {choice.id}{" "}
          {!choice.granted
            ? "— not granted"
            : choice.resource.status === "disabled"
              ? "— disabled"
              : ""}
        </option>
      ))}
    </select>
  );
}

function readValue(text: string, fallback: JsonValue): JsonValue {
  if (!text) return fallback;
  try {
    return JSON.parse(text) as JsonValue;
  } catch {
    return fallback;
  }
}

// Nested fields edit a complete object, retaining fields not exposed by this editor.
function ObjectControls({
  value,
  schema,
  onChange,
}: {
  value: Record<string, JsonValue>;
  schema: JsonSchema;
  onChange: (value: Record<string, JsonValue>) => void;
}) {
  return (
    <div className="form-grid">
      {Object.entries(schema.properties ?? {}).map(([name, property]) => (
        <Field key={name} label={humanize(name)} help="Leave empty to use the server default.">
          {property.enum ? (
            <select
              value={String(value[name] ?? "")}
              onChange={(event) => {
                const next = { ...value };
                if (event.target.value) next[name] = event.target.value;
                else delete next[name];
                onChange(next);
              }}
            >
              <option value="">Server default</option>
              {property.enum.map((item) => (
                <option key={String(item)} value={String(item)}>
                  {humanize(String(item))}
                </option>
              ))}
            </select>
          ) : (
            <input
              type="number"
              min={property.minimum}
              max={property.maximum}
              value={typeof value[name] === "number" ? value[name] : ""}
              onChange={(event) => {
                const next = { ...value };
                if (event.target.value) next[name] = Number(event.target.value);
                else delete next[name];
                onChange(next);
              }}
            />
          )}
        </Field>
      ))}
    </div>
  );
}

const FEATURES = [
  "streaming",
  "tools",
  "parallel_tools",
  "image_input",
  "audio_input",
  "document_input",
  "structured_output",
  "json_schema",
  "prompt_caching",
  "system_instructions",
  "developer_instructions",
  "reasoning_controls",
  "opaque_reasoning_state",
];

export function validateRouteTargets(value: JsonValue): void {
  if (!Array.isArray(value)) throw new Error("A complete route target set is required.");
  const ids = new Set<string>();
  const tiers = new Map<number, number>();
  for (const entry of value) {
    const target = asObject(entry);
    if (typeof target.deployment_id !== "string" || !target.deployment_id)
      throw new Error("Select a deployment for every target.");
    if (ids.has(target.deployment_id))
      throw new Error("Each deployment may appear only once in a route.");
    ids.add(target.deployment_id);
    const priority = Number(target.priority);
    const weight = Number(target.weight);
    if (
      !Number.isInteger(priority) ||
      priority < 0 ||
      priority > 255 ||
      !Number.isInteger(weight) ||
      weight < 1 ||
      weight > 256
    )
      throw new Error("Priorities must be 0–255; weights must be 1–256.");
    const total = (tiers.get(priority) ?? 0) + weight;
    if (total > 256) throw new Error("Weights in one priority tier may not exceed 256.");
    tiers.set(priority, total);
  }
}

export function CatalogCommandForm(props: SchemaCommandFormProps) {
  const identity = JSON.stringify([props.operationId, props.params, props.etag]);
  return <CatalogCommandSession key={identity} {...props} />;
}

function CatalogCommandSession(props: SchemaCommandFormProps) {
  const organizationId = props.params.organization_id;
  const prefix = organizationId ? "organization" : "system";
  const deploymentEditor = props.operationId.includes(".model_deployments.");
  const routeEditor = props.operationId.includes(".model_routes.");
  const endpointEditor = props.operationId.includes(".upstream_endpoints.");
  const path = (family: string) => operationPath(`${family}.list`, props.params)!;
  const endpoints = deploymentEditor
    ? [path(organizationId ? "organization.available_endpoints" : "system.upstream_endpoints")]
    : [];
  const credentials = deploymentEditor ? [path(`${prefix}.upstream_credentials`)] : [];
  const deployments = routeEditor
    ? [
        path(`${prefix}.model_deployments`),
        ...(organizationId ? [path("organization.available_deployments")] : []),
      ]
    : [];
  const reliability = routeEditor
    ? [
        path(
          organizationId
            ? "organization.available_reliability_policies"
            : "system.reliability_policies",
        ),
      ]
    : [];
  const networks = endpointEditor ? [path("system.egress_network_policies")] : [];
  const grantFamily = props.operationId.split(".")[1];
  const grantCatalog: Record<string, string> = {
    system_route_grants: "system.model_routes",
    endpoint_grants: "system.upstream_endpoints",
    deployment_grants: "system.model_deployments",
    reliability_policy_grants: "system.reliability_policies",
  };
  const grantSources = grantCatalog[grantFamily] ? [path(grantCatalog[grantFamily])] : [];
  const catalog = useCatalogSources([
    ...endpoints,
    ...credentials,
    ...deployments,
    ...reliability,
    ...networks,
    ...grantSources,
  ]);

  function renderControl(control: CommandControlProps) {
    const { name, state, states, schema, onChange } = control;
    const set = (value: JsonValue) =>
      onChange({ ...state, text: typeof value === "string" ? value : JSON.stringify(value) });
    if (name === "resource_ids" && grantSources.length) {
      const value = readValue(state.text, []);
      const selected = Array.isArray(value)
        ? value.filter((item): item is string => typeof item === "string")
        : [];
      const choices = catalog.choices(grantSources);
      const visible = new Map(choices.map((choice) => [choice.id, choice.label]));
      for (const id of selected)
        if (!visible.has(id)) visible.set(id, `${id} — selected; load choices to inspect`);
      return (
        <>
          <p>
            This replaces the complete grant set. Unloaded selections are retained until explicitly
            unchecked. Route grants permit invocation; deployment, endpoint and reliability grants
            permit composition.
          </p>
          {[...visible].map(([id, label]) => (
            <label key={id} className="check-row">
              <input
                type="checkbox"
                checked={selected.includes(id)}
                onChange={(event) =>
                  set(
                    event.target.checked
                      ? [...selected, id]
                      : selected.filter((item) => item !== id),
                  )
                }
              />
              {label}
            </label>
          ))}
          {catalog.controls(grantSources)}
        </>
      );
    }
    const selectors: Record<string, string[]> = {
      endpoint_id: endpoints,
      credential_id: credentials,
      reliability_policy_id: reliability,
      network_policy_id: networks,
    };
    if (selectors[name]?.length)
      return (
        <>
          <ChoiceSelect
            value={state.text}
            choices={catalog.choices(selectors[name])}
            onChange={set}
          />
          {catalog.controls(selectors[name])}
        </>
      );
    if (name === "transport_kind" && deploymentEditor) {
      const endpoint = catalog
        .choices(endpoints)
        .find((choice) => choice.id === states.endpoint_id?.text)?.resource;
      const credential = catalog
        .choices(credentials)
        .find((choice) => choice.id === states.credential_id?.text)?.resource;
      const transports = [
        ...new Set(
          compatibility
            .filter(
              (tuple) =>
                tuple.endpoint === endpoint?.adapter_kind &&
                tuple.credential === credential?.credential_kind,
            )
            .map((tuple) => tuple.transport),
        ),
      ];
      return (
        <>
          <p>
            Select an endpoint and credential first. Only matching native transports are offered.
          </p>
          <select
            aria-label="Compatible transport"
            required
            value={state.text}
            onChange={(event) => set(event.target.value)}
          >
            <option value="">Select transport</option>
            {state.text && !transports.includes(state.text) ? (
              <option value={state.text} disabled>
                {state.text} — incompatible or dependencies not loaded
              </option>
            ) : null}
            {transports.map((transport) => (
              <option key={transport}>{transport}</option>
            ))}
          </select>
        </>
      );
    }
    if (name === "capability_set" || name === "required_base_capabilities") {
      const value = readValue(state.text, []);
      const selected = Array.isArray(value) ? value : [];
      return (
        <div>
          {FEATURES.map((feature) => (
            <label key={feature} className="check-row">
              <input
                type="checkbox"
                checked={selected.includes(feature)}
                onChange={(event) =>
                  set(
                    event.target.checked
                      ? [...selected, feature]
                      : selected.filter((item) => item !== feature),
                  )
                }
              />
              {humanize(feature)}
            </label>
          ))}
        </div>
      );
    }
    if (name === "state_isolation_profile") {
      const value = asObject(readValue(state.text, {}));
      return (
        <Field label="Provider state isolation">
          <select
            value={String(value.mode ?? "shared")}
            onChange={(event) => set({ ...value, mode: event.target.value })}
          >
            <option value="shared">
              Shared — organization-namespaced cache; external state IDs rejected
            </option>
            {organizationId ? (
              <option value="organization_dedicated">
                Organization dedicated — organization-exclusive provider credential
              </option>
            ) : null}
          </select>
        </Field>
      );
    }
    if ((name === "request_policy" || name === "selection_policy") && schema.properties)
      return (
        <ObjectControls
          value={asObject(readValue(state.text, {}))}
          schema={schema}
          onChange={set}
        />
      );
    if (name === "targets" && routeEditor) {
      const value = readValue(state.text, []);
      const targets = Array.isArray(value) ? value.map(asObject) : [];
      const change = (index: number, patch: Record<string, JsonValue>) =>
        set(targets.map((target, i) => (i === index ? { ...target, ...patch } : target)));
      const ingress =
        states.ingress_protocol_family?.text ??
        asObject(props.initialValue).ingress_protocol_family;
      const capabilities = readValue(states.required_base_capabilities?.text ?? "", []);
      const choices = catalog.choices(deployments).map((choice) => {
        const compatible = compatibility.some(
          (tuple) =>
            tuple.ingress === ingress && tuple.transport === choice.resource.transport_kind,
        );
        const available = choice.resource.capability_set;
        const capable =
          Array.isArray(capabilities) &&
          Array.isArray(available) &&
          capabilities.every((item) => available.includes(item));
        return {
          ...choice,
          granted: choice.granted && compatible && capable,
          label: `${choice.label}${!compatible || !capable ? " — incompatible protocol/capabilities" : ""}`,
        };
      });
      return (
        <>
          <p>
            Lower priority runs first; weights distribute traffic within a tier (total ≤ 256).
            Saving sends the complete target set and preserves existing target IDs.
          </p>
          {targets.map((target, index) => (
            <fieldset key={typeof target.id === "string" ? target.id : index}>
              <legend>Target {index + 1}</legend>
              <ChoiceSelect
                value={String(target.deployment_id ?? "")}
                choices={choices}
                onChange={(deployment_id) => change(index, { deployment_id })}
              />
              <Field label="Priority">
                <input
                  type="number"
                  min={0}
                  max={255}
                  required
                  value={Number(target.priority ?? 0)}
                  onChange={(event) => change(index, { priority: Number(event.target.value) })}
                />
              </Field>
              <Field label="Weight">
                <input
                  type="number"
                  min={1}
                  max={256}
                  required
                  value={Number(target.weight ?? 1)}
                  onChange={(event) => change(index, { weight: Number(event.target.value) })}
                />
              </Field>
              <label className="check-row">
                <input
                  type="checkbox"
                  checked={target.enabled !== false}
                  onChange={(event) => change(index, { enabled: event.target.checked })}
                />
                Enabled
              </label>
              <details>
                <summary>Target ceilings and timeouts</summary>
                {["narrowing_constraints", "timeout_overrides"].map((field) => (
                  <fieldset key={field}>
                    <legend>{humanize(field)}</legend>
                    <ObjectControls
                      value={asObject(target[field])}
                      schema={schema.items?.properties?.[field] ?? {}}
                      onChange={(value) => change(index, { [field]: value })}
                    />
                  </fieldset>
                ))}
              </details>
              <button
                type="button"
                className="button button-secondary"
                onClick={() => set(targets.filter((_, i) => i !== index))}
              >
                Remove target
              </button>
            </fieldset>
          ))}
          <button
            type="button"
            className="button button-secondary"
            disabled={targets.length >= 256}
            onClick={() =>
              set([
                ...targets,
                {
                  id: crypto.randomUUID(),
                  deployment_id: "",
                  priority: 0,
                  weight: 1,
                  enabled: true,
                },
              ])
            }
          >
            Add target
          </button>
          {catalog.controls(deployments)}
        </>
      );
    }
    return undefined;
  }

  return (
    <SchemaCommandForm
      {...props}
      renderControl={renderControl}
      validateCandidate={(candidate) => {
        if (candidate.targets !== undefined) validateRouteTargets(candidate.targets);
        // The server validates the complete dependency graph transactionally, including
        // current grants, capability narrowing, pricing and timeout ceilings.
      }}
      description={
        <>
          <p>
            Choose dependencies, configure the resource, then save. The server validates the current
            dependency graph before committing; a listed resource is not automatically granted or
            operational.
          </p>
          {props.description}
        </>
      }
    />
  );
}

export function CatalogWorkflow({ organizationId }: { organizationId?: string }) {
  const base = organizationId
    ? `/organizations/${encodeURIComponent(organizationId)}`
    : "/admin/catalog";
  return (
    <section className="workflow-help">
      <h2>Make a model callable</h2>
      <ol>
        <li>
          <Link href={`${base}/${organizationId ? "upstream-credentials" : "credentials"}`}>
            Create a credential
          </Link>{" "}
          with write-only protected material.
        </li>
        <li>
          {organizationId ? (
            "Ask a system administrator to grant a compatible endpoint; endpoint access does not grant model access."
          ) : (
            <Link href={`${base}/endpoints`}>Create an endpoint with an egress policy</Link>
          )}
        </li>
        <li>
          <Link href={`${base}/${organizationId ? "model-deployments" : "deployments"}`}>
            Bind and validate a model deployment
          </Link>
          , then <Link href={`${base}/model-routes`}>compose a route</Link> with compatible targets.
        </li>
        <li>
          {organizationId ? (
            <>
              <Link href={`${base}/gateway-api-keys`}>Grant a Gateway key access</Link> through its
              route allowlist and finite budget; check{" "}
              <Link href={`${base}/provider-budgets`}>both provider-origin pools</Link>.
            </>
          ) : (
            <>
              Open the organization's Admin page to grant routes, deployment composition resources
              and a system-origin budget. Grants are distinct from discoverability.
            </>
          )}
        </li>
      </ol>
      <details>
        <summary>Why is access denied?</summary>
        <p>
          Check the route is active, the key allows its stable route ID, the organization has the
          required grants, and the selected target's credential/endpoint/deployment are active and
          validated. Check the key budget and that target's system or BYOK pool separately. A
          compatible catalog graph is not proof of provider availability.
        </p>
      </details>
    </section>
  );
}
