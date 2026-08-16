import { type FormEvent, useState } from "react";

import { type JsonValue } from "./api";
import {
  ApiErrorState,
  EmptyState,
  Field,
  JsonBlock,
  LoadingState,
  PageHeader,
  Panel,
  Table,
  useApiResource,
} from "./ui";

export function hourInput(date: Date, timezoneOffsetMinutes = date.getTimezoneOffset()): string {
  const local = new Date(date.getTime() - timezoneOffsetMinutes * 60_000);
  return local.toISOString().slice(0, 16);
}

function alignedNow(): Date {
  const now = new Date();
  now.setUTCMinutes(0, 0, 0);
  now.setUTCHours(now.getUTCHours() + 1);
  return now;
}

export function toUtcHour(value: string): string {
  const parsed = new Date(value);
  if (
    Number.isNaN(parsed.getTime()) ||
    parsed.getUTCMinutes() !== 0 ||
    parsed.getUTCSeconds() !== 0 ||
    parsed.getUTCMilliseconds() !== 0
  ) {
    throw new Error("Choose a time that resolves to an exact UTC hour boundary.");
  }
  return parsed.toISOString();
}

function object(value: JsonValue | undefined): Record<string, JsonValue> {
  return value !== null && value !== undefined && typeof value === "object" && !Array.isArray(value)
    ? value
    : {};
}

function array(value: JsonValue | undefined): JsonValue[] {
  return Array.isArray(value) ? value : [];
}

const FILTERS = [
  ["organization_id", "Organization ID"],
  ["principal_kind", "Principal kind"],
  ["user_id", "User ID"],
  ["gateway_api_key_id", "Gateway API key ID"],
  ["route_id", "Route ID"],
  ["target_id", "Target ID"],
  ["origin", "Origin"],
  ["deployment_id", "Deployment ID"],
  ["endpoint_id", "Endpoint ID"],
  ["credential_id", "Credential ID"],
  ["outcome", "Outcome"],
] as const;

const DIMENSIONS = [
  "organization",
  "principal_kind",
  "user",
  "gateway_api_key",
  "route",
  "protocol",
  "target",
  "origin",
  "deployment",
  "endpoint",
  "credential",
  "outcome",
];

export function UsagePage({ organizationId }: { organizationId?: string }) {
  const endDefault = alignedNow();
  const startDefault = new Date(endDefault.getTime() - 24 * 60 * 60 * 1000);
  const [start, setStart] = useState(hourInput(startDefault));
  const [end, setEnd] = useState(hourInput(endDefault));
  const [granularity, setGranularity] = useState("hour");
  const [filters, setFilters] = useState<Record<string, string>>({});
  const [factFamily, setFactFamily] = useState("attempts");
  const [dimension, setDimension] = useState(
    organizationId === undefined ? "organization" : "route",
  );
  const [order, setOrder] = useState("count_desc");
  const base =
    organizationId === undefined
      ? "/api/v1/system/usage"
      : `/api/v1/organizations/${encodeURIComponent(organizationId)}/usage`;
  const initialQuery = new URLSearchParams({
    start: startDefault.toISOString(),
    end: endDefault.toISOString(),
    granularity: "hour",
  });
  const [query, setQuery] = useState(initialQuery.toString());
  const [breakdownQuery, setBreakdownQuery] = useState(
    new URLSearchParams({
      ...Object.fromEntries(initialQuery),
      fact_family: "attempts",
      dimension: organizationId === undefined ? "organization" : "route",
      order: "count_desc",
      limit: "20",
    }).toString(),
  );
  const [validationError, setValidationError] = useState<string | null>(null);
  const usage = useApiResource<JsonValue>(`${base}?${query}`);
  const breakdown = useApiResource<JsonValue>(`${base}/breakdown?${breakdownQuery}`);

  function apply(event: FormEvent): void {
    event.preventDefault();
    setValidationError(null);
    try {
      const next = new URLSearchParams({
        start: toUtcHour(start),
        end: toUtcHour(end),
        granularity,
      });
      for (const [name] of FILTERS) {
        const value = filters[name]?.trim();
        if (value) next.set(name, value);
      }
      setQuery(next.toString());
      const nextBreakdown = new URLSearchParams(next);
      nextBreakdown.set("fact_family", factFamily);
      nextBreakdown.set("dimension", dimension);
      nextBreakdown.set("order", order);
      nextBreakdown.set("limit", "20");
      setBreakdownQuery(nextBreakdown.toString());
    } catch (caught: unknown) {
      setValidationError(caught instanceof Error ? caught.message : "Review the time range.");
    }
  }

  const usageObject = object(usage.value ?? undefined);
  const logical = object(usageObject.logical_requests);
  const attempts = object(usageObject.attempts);
  const breakdownObject = object(breakdown.value ?? undefined);
  const breakdownItems = array(breakdownObject.items);
  const filterDefinitions = FILTERS.filter(([name]) => {
    if (organizationId === undefined) return true;
    return name !== "organization_id" && name !== "credential_id";
  });
  return (
    <>
      <PageHeader
        title={organizationId === undefined ? "Deployment usage" : "Organization usage"}
        description="Bounded persisted aggregate explorer. Logical requests and actual provider attempts remain separate; unflushed process facts are explicitly excluded."
      />
      <Panel title="Range, filters, and breakdown">
        <form className="form-grid" onSubmit={apply}>
          <Field
            label="Start (UTC hour boundary)"
            help="Shown in local time; fractional timezone offsets may require :30 or :45."
            required
          >
            <input
              type="datetime-local"
              step="60"
              value={start}
              onChange={(event) => setStart(event.target.value)}
            />
          </Field>
          <Field
            label="End (exclusive UTC hour boundary)"
            help="Shown in local time; fractional timezone offsets may require :30 or :45."
            required
          >
            <input
              type="datetime-local"
              step="60"
              value={end}
              onChange={(event) => setEnd(event.target.value)}
            />
          </Field>
          <Field label="Granularity" required>
            <select value={granularity} onChange={(event) => setGranularity(event.target.value)}>
              <option value="hour">Hour</option>
              <option value="day">Day</option>
            </select>
          </Field>
          {filterDefinitions.map(([name, label]) => (
            <Field key={name} label={label}>
              <input
                value={filters[name] ?? ""}
                onChange={(event) =>
                  setFilters((current) => ({ ...current, [name]: event.target.value }))
                }
              />
            </Field>
          ))}
          <Field label="Breakdown fact family" required>
            <select value={factFamily} onChange={(event) => setFactFamily(event.target.value)}>
              <option value="logical_requests">Logical requests</option>
              <option value="attempts">Attempts</option>
            </select>
          </Field>
          <Field label="Breakdown dimension" required>
            <select value={dimension} onChange={(event) => setDimension(event.target.value)}>
              {DIMENSIONS.filter(
                (candidate) =>
                  organizationId === undefined ||
                  (candidate !== "organization" && candidate !== "credential"),
              ).map((candidate) => (
                <option key={candidate} value={candidate}>
                  {candidate.replaceAll("_", " ")}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Breakdown order" required>
            <select value={order} onChange={(event) => setOrder(event.target.value)}>
              <option value="count_desc">Count descending</option>
              <option value="cost_desc">Cost descending</option>
              <option value="dimension_asc">Dimension ascending</option>
            </select>
          </Field>
          <div className="field field-actions">
            <button className="button button-primary" type="submit">
              Apply query
            </button>
          </div>
        </form>
        {validationError === null ? null : (
          <div className="alert alert-danger" role="alert">
            <strong>Review the range</strong>
            <span>{validationError}</span>
          </div>
        )}
      </Panel>
      {usage.loading ? <LoadingState label="Loading persisted usage aggregates" /> : null}
      {usage.error !== null ? <ApiErrorState error={usage.error} retry={usage.reload} /> : null}
      {usage.value === null ? null : (
        <>
          <div className="alert alert-info">
            <strong>Aggregate completeness</strong>
            <span>
              {String(object(usageObject.completeness).note ?? "Persisted aggregate facts only.")}
            </span>
          </div>
          <div className="metric-grid">
            <div className="metric-card">
              <span>Logical buckets</span>
              <strong>{array(logical.items).length}</strong>
            </div>
            <div className="metric-card">
              <span>Attempt buckets</span>
              <strong>{array(attempts.items).length}</strong>
            </div>
            <div className="metric-card">
              <span>Logical applicable</span>
              <strong>{logical.applicable === false ? "No" : "Yes"}</strong>
            </div>
            <div className="metric-card">
              <span>Daily rollups</span>
              <strong>{String(object(usageObject.completeness).daily_rollups ?? "unknown")}</strong>
            </div>
          </div>
          <Panel title="Logical request series">
            <JsonBlock value={logical} />
          </Panel>
          <Panel title="Provider attempt series">
            <JsonBlock value={attempts} />
          </Panel>
        </>
      )}
      <Panel title="Top breakdown">
        {breakdown.loading ? <LoadingState label="Loading usage breakdown" /> : null}
        {breakdown.error !== null ? (
          <ApiErrorState error={breakdown.error} retry={breakdown.reload} compact />
        ) : null}
        {!breakdown.loading && breakdown.error === null && breakdownItems.length === 0 ? (
          <EmptyState
            title="No matching aggregate facts"
            description="No persisted facts matched this range and qualified filter."
          />
        ) : null}
        {breakdownItems.length === 0 ? null : (
          <Table
            columns={[
              { key: "dimension", label: String(breakdownObject.dimension ?? "Dimension") },
              { key: "count", label: "Count" },
              { key: "input", label: "Input units" },
              { key: "output", label: "Output units" },
              { key: "cost", label: "Known cost (nanos)" },
            ]}
            rows={breakdownItems.map((item) => {
              const row = object(item);
              const measures = object(row.measures);
              return {
                dimension: String(row.dimension_value ?? "Unattributed"),
                count: String(measures.count ?? "0"),
                input: String(measures.input_units ?? "0"),
                output: String(measures.output_units ?? "0"),
                cost: String(
                  measures.known_actual_cost_nanos ??
                    measures.known_cost_nanos ??
                    measures.known_estimated_cost_nanos ??
                    "Unknown",
                ),
              };
            })}
            getKey={(_, index) =>
              `${String(object(breakdownItems[index]).dimension_value)}-${index}`
            }
          />
        )}
      </Panel>
    </>
  );
}
