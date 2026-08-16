import { type FormEvent, type ReactNode, useMemo, useState } from "react";

import { ApiError, OutcomeUnknownError, apiRequest, type JsonValue } from "./api";
import {
  operationAuthority,
  operationPath,
  type JsonSchema,
  type OperationAuthority,
} from "./operation-authority";
import {
  ApiErrorState,
  ConflictState,
  Field,
  FormError,
  JsonBlock,
  OneTimeReveal,
  OutcomeUnknownState,
  SubmitBar,
  humanize,
  navigate,
  useIdempotencyKey,
  useUnsavedChanges,
} from "./ui";

export interface FieldState {
  enabled: boolean;
  clear: boolean;
  text: string;
  checked: boolean;
}

export type FieldStates = Record<string, FieldState>;

export interface SchemaCommandFormProps {
  operationId: string;
  params: Record<string, string>;
  etag?: string | null;
  initialValue?: JsonValue;
  cancelHref: string;
  successHref: string | ((response: JsonValue) => string);
  submitLabel: string;
  secretLabel?: string;
  description?: ReactNode;
  onSuccess?: (response: JsonValue) => void;
}

export function commandIsNonRepeatable(
  command: Pick<OperationAuthority, "destructive" | "idempotency">,
): boolean {
  return (
    command.destructive ||
    command.idempotency === "rejected" ||
    command.idempotency === "state_machine"
  );
}

export function deviceAuthorization(
  operationId: string,
  metadata: JsonValue,
): { verificationUrl: string } | undefined {
  if (
    operationId !== "system.upstream_credentials.codex_login.start" ||
    metadata === null ||
    typeof metadata !== "object" ||
    Array.isArray(metadata) ||
    typeof metadata.verification_url !== "string"
  ) {
    return undefined;
  }
  try {
    const verificationUrl = new URL(metadata.verification_url);
    return verificationUrl.protocol === "https:"
      ? { verificationUrl: verificationUrl.toString() }
      : undefined;
  } catch {
    return undefined;
  }
}

function schemaTypes(schema: JsonSchema): string[] {
  const direct = Array.isArray(schema.type)
    ? schema.type
    : schema.type === undefined
      ? []
      : [schema.type];
  return [...new Set([...direct, ...(schema.oneOf ?? []).flatMap(schemaTypes)])];
}

function isNullable(schema: JsonSchema): boolean {
  return schemaTypes(schema).includes("null");
}

function isRequired(parent: JsonSchema, name: string): boolean {
  return parent.required?.includes(name) === true;
}

export function optionalFieldPresenceLabel(hasInitialValue: boolean): string {
  return hasInitialValue ? "Change this value" : "Include this field";
}

function initialFieldState(
  parent: JsonSchema,
  name: string,
  schema: JsonSchema,
  initialValue: JsonValue | undefined,
): FieldState {
  const required = isRequired(parent, name);
  const enabled = required;
  if (initialValue === null) {
    return { enabled, clear: true, text: "", checked: false };
  }
  if (typeof initialValue === "boolean") {
    return { enabled, clear: false, text: "", checked: initialValue };
  }
  if (typeof initialValue === "string" || typeof initialValue === "number") {
    return { enabled, clear: false, text: String(initialValue), checked: false };
  }
  if (initialValue !== undefined) {
    return {
      enabled,
      clear: false,
      text: JSON.stringify(initialValue, null, 2),
      checked: false,
    };
  }
  const enumDefault = schema.enum?.[0];
  return {
    enabled,
    clear: false,
    text:
      typeof enumDefault === "string" || typeof enumDefault === "number" ? String(enumDefault) : "",
    checked: false,
  };
}

function initialStates(schema: JsonSchema, initialValue: JsonValue | undefined): FieldStates {
  const object =
    initialValue !== null && typeof initialValue === "object" && !Array.isArray(initialValue)
      ? initialValue
      : {};
  return Object.fromEntries(
    Object.entries(schema.properties ?? {}).map(([name, property]) => [
      name,
      initialFieldState(schema, name, property, object[name]),
    ]),
  );
}

function parseField(name: string, schema: JsonSchema, state: FieldState): JsonValue {
  if (schema.const !== undefined) return schema.const;
  if (state.clear) return null;
  const types = schemaTypes(schema);
  if (types.length === 1 && types[0] === "null") return null;
  if (types.includes("boolean")) return state.checked;
  if (types.includes("integer") || types.includes("number")) {
    const value = Number(state.text);
    if (!Number.isFinite(value) || (types.includes("integer") && !Number.isInteger(value))) {
      throw new Error(
        `${humanize(name)} must be a valid ${types.includes("integer") ? "integer" : "number"}.`,
      );
    }
    return value;
  }
  if (types.includes("object") || types.includes("array")) {
    try {
      const parsed = JSON.parse(state.text || (types.includes("array") ? "[]" : "{}")) as JsonValue;
      if (types.includes("array") && !Array.isArray(parsed)) {
        throw new Error("not an array");
      }
      if (
        types.includes("object") &&
        (parsed === null || typeof parsed !== "object" || Array.isArray(parsed))
      ) {
        throw new Error("not an object");
      }
      return parsed;
    } catch {
      throw new Error(`${humanize(name)} must contain valid JSON with the expected shape.`);
    }
  }
  return state.text;
}

export function resolveSchemaVariant(schema: JsonSchema, states: FieldStates): JsonSchema {
  const branches = schema.oneOf ?? [];
  const baseProperties = schema.properties ?? {};
  const discriminator = Object.keys(baseProperties).find((name) => {
    const values = branches.map((branch) => branch.properties?.[name]?.const);
    return (
      values.length > 0 &&
      values.every((value) => value !== undefined) &&
      new Set(values.map((value) => JSON.stringify(value))).size === values.length
    );
  });
  if (discriminator === undefined) return schema;
  const state = states[discriminator];
  if (state === undefined) return schema;
  const selectedValue: JsonValue = state.clear ? null : state.text;
  const branch = branches.find(
    (candidate) => candidate.properties?.[discriminator]?.const === selectedValue,
  );
  if (branch === undefined) return schema;
  const properties = { ...baseProperties, ...(branch.properties ?? {}) };
  properties[discriminator] = baseProperties[discriminator];
  return {
    ...schema,
    properties,
    required: [...new Set([...(schema.required ?? []), ...(branch.required ?? [])])],
  };
}

export function hasFieldStateChanges(initial: FieldStates, current: FieldStates): boolean {
  const names = new Set([...Object.keys(initial), ...Object.keys(current)]);
  return [...names].some((name) => {
    const before = initial[name];
    const after = current[name];
    return (
      before === undefined ||
      after === undefined ||
      before.enabled !== after.enabled ||
      before.clear !== after.clear ||
      before.text !== after.text ||
      before.checked !== after.checked
    );
  });
}

export function candidateFromStates(
  schema: JsonSchema,
  states: FieldStates,
): Record<string, JsonValue> {
  const candidate: Record<string, JsonValue> = {};
  for (const [name, property] of Object.entries(schema.properties ?? {})) {
    const state = states[name];
    const required = isRequired(schema, name);
    if (state === undefined || (!required && state.enabled !== true)) continue;
    candidate[name] = parseField(name, property, state);
  }
  for (const name of schema.required ?? []) {
    if (!(name in candidate)) throw new Error(`${humanize(name)} is required.`);
    const value = candidate[name];
    if (typeof value === "string" && value.length === 0) {
      throw new Error(`${humanize(name)} is required.`);
    }
  }
  if (Object.keys(candidate).length === 0 && Object.keys(schema.properties ?? {}).length > 0) {
    throw new Error("Select at least one field to change.");
  }
  return candidate;
}

export function secretResult(value: JsonValue): { secret: string; metadata: JsonValue } | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  for (const field of ["key", "token", "secret", "client_secret", "user_code"]) {
    const candidate = value[field];
    if (typeof candidate !== "string" || candidate.length === 0) continue;
    const metadata = { ...value };
    delete metadata[field];
    return { secret: candidate, metadata };
  }
  return null;
}

function enumValue(value: JsonValue): string {
  if (value === null) return "__null__";
  return String(value);
}

function SchemaField({
  parent,
  name,
  schema,
  state,
  secret,
  presenceLabel,
  onChange,
}: {
  parent: JsonSchema;
  name: string;
  schema: JsonSchema;
  state: FieldState;
  secret: boolean;
  presenceLabel: string;
  onChange: (state: FieldState) => void;
}) {
  const required = isRequired(parent, name);
  const types = schemaTypes(schema);
  const inputDisabled = (!required && !state.enabled) || state.clear;
  let control: ReactNode;
  if (schema.const !== undefined) {
    control = <input type="text" value={String(schema.const)} readOnly aria-readonly="true" />;
  } else if (schema.enum !== undefined) {
    control = (
      <select
        value={state.clear ? "__null__" : state.text}
        disabled={!state.enabled}
        required={required}
        onChange={(event) => {
          const clear = event.target.value === "__null__";
          onChange({ ...state, clear, text: clear ? "" : event.target.value });
        }}
      >
        {!required && !state.enabled ? <option value="">Select a value</option> : null}
        {schema.enum.map((value) => (
          <option key={enumValue(value)} value={enumValue(value)}>
            {value === null ? "Clear value" : humanize(String(value))}
          </option>
        ))}
      </select>
    );
  } else if (types.includes("boolean")) {
    control = (
      <label className="check-row">
        <input
          type="checkbox"
          checked={state.checked}
          disabled={inputDisabled}
          onChange={(event) => onChange({ ...state, checked: event.target.checked })}
        />
        <span>{state.checked ? "Enabled" : "Disabled"}</span>
      </label>
    );
  } else if (types.includes("object") || types.includes("array")) {
    control = (
      <textarea
        rows={8}
        value={state.text}
        disabled={inputDisabled}
        required={required}
        spellCheck={false}
        onChange={(event) => onChange({ ...state, text: event.target.value })}
      />
    );
  } else {
    control = (
      <input
        type={
          secret
            ? "password"
            : types.includes("integer") || types.includes("number")
              ? "number"
              : "text"
        }
        value={state.text}
        disabled={inputDisabled}
        required={required && !state.clear}
        min={schema.minimum}
        max={schema.maximum}
        minLength={schema.minLength}
        maxLength={schema.maxLength}
        pattern={schema.pattern}
        autoComplete={secret ? "new-password" : undefined}
        onChange={(event) => onChange({ ...state, text: event.target.value })}
      />
    );
  }
  return (
    <div className="schema-field">
      {!required ? (
        <label className="check-row field-presence">
          <input
            type="checkbox"
            checked={state.enabled}
            onChange={(event) => onChange({ ...state, enabled: event.target.checked })}
          />
          <span>{presenceLabel}</span>
        </label>
      ) : null}
      <Field
        label={humanize(name)}
        required={required}
        help={
          secret
            ? "Write-only value. OwlRora never returns the submitted secret."
            : types.includes("object") || types.includes("array")
              ? "Enter bounded JSON matching the operation contract."
              : undefined
        }
      >
        {control}
      </Field>
      {state.enabled && isNullable(schema) && schema.enum === undefined ? (
        <label className="check-row">
          <input
            type="checkbox"
            checked={state.clear}
            onChange={(event) => onChange({ ...state, clear: event.target.checked })}
          />
          <span>Clear this value</span>
        </label>
      ) : null}
    </div>
  );
}

export function SchemaCommandForm({
  operationId,
  params,
  etag,
  initialValue,
  cancelHref,
  successHref,
  submitLabel,
  secretLabel = "One-time secret",
  description,
  onSuccess,
}: SchemaCommandFormProps) {
  const operation = operationAuthority(operationId);
  const schema = operation?.request_schema ?? { type: "object", properties: {}, required: [] };
  const path = operationPath(operationId, params);
  const baselineStates = initialStates(schema, initialValue);
  const [states, setStates] = useState<FieldStates>(() => baselineStates);
  const effectiveSchema = resolveSchemaVariant(schema, states);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [conflict, setConflict] = useState<JsonValue | null>(null);
  const [outcomeUnknown, setOutcomeUnknown] = useState<OutcomeUnknownError | null>(null);
  const [revealed, setRevealed] = useState<{ secret: string; metadata: JsonValue } | null>(null);
  const changed = hasFieldStateChanges(baselineStates, states);
  const discardChanges = useUnsavedChanges(revealed === null && outcomeUnknown === null && changed);
  const idempotencyKey = useIdempotencyKey();
  const secretField = operation?.secret_input?.field;
  const requiredConfirmation = operation?.approval_recommended === true;
  const [confirmed, setConfirmed] = useState(!requiredConfirmation);
  const finalSuccessHref = useMemo(
    () => (value: JsonValue) =>
      typeof successHref === "function" ? successHref(value) : successHref,
    [successHref],
  );

  if (operation === null || path === null || operation.method !== "POST") {
    return (
      <ApiErrorState
        error={
          new ApiError(
            0,
            "console_contract_error",
            "This command is not present in the generated console contract.",
          )
        }
      />
    );
  }
  const command = operation;
  const commandPath = path;
  if (command.etag_precondition && (etag === undefined || etag === null)) {
    return (
      <ApiErrorState
        error={
          new ApiError(
            0,
            "etag_unavailable",
            "The current resource ETag is required before this editor can submit.",
          )
        }
      />
    );
  }
  if (outcomeUnknown !== null) {
    return (
      <OutcomeUnknownState
        command={operationId}
        requestId={outcomeUnknown.requestId}
        recoveryHref={cancelHref}
        committed={outcomeUnknown.committed}
        oneTimeMaterial={command.one_time_secret_response}
      />
    );
  }
  if (revealed !== null) {
    return (
      <OneTimeReveal
        credentialClass={secretLabel}
        secret={revealed.secret}
        metadata={<JsonBlock value={revealed.metadata} label="Safe created-resource metadata" />}
        doneHref={finalSuccessHref(revealed.metadata)}
        onDone={() => {
          discardChanges();
          navigate(finalSuccessHref(revealed.metadata), true);
        }}
        deviceAuthorization={deviceAuthorization(operationId, revealed.metadata)}
      />
    );
  }
  if (conflict !== null) {
    return <ConflictState candidate={conflict} reload={() => navigate(cancelHref, true)} />;
  }

  async function submit(event: FormEvent): Promise<void> {
    event.preventDefault();
    setError(null);
    setFormError(null);
    let candidate: Record<string, JsonValue>;
    try {
      candidate = candidateFromStates(effectiveSchema, states);
    } catch (caught: unknown) {
      setFormError(caught instanceof Error ? caught.message : "Review the form values.");
      return;
    }
    setSubmitting(true);
    try {
      const response = await apiRequest<JsonValue>(commandPath, {
        method: "POST",
        body: candidate,
        ifMatch: command.etag_precondition ? (etag ?? undefined) : undefined,
        idempotencyKey:
          command.idempotency === "supported" || command.client_generated_idempotency_key
            ? idempotencyKey(candidate)
            : undefined,
        nonRepeatable: commandIsNonRepeatable(command),
      });
      const oneTime = command.one_time_secret_response ? secretResult(response.value) : null;
      if (oneTime !== null) {
        setRevealed(oneTime);
        setStates(initialStates(schema, undefined));
        return;
      }
      discardChanges();
      onSuccess?.(response.value);
      navigate(finalSuccessHref(response.value), true);
    } catch (caught: unknown) {
      if (caught instanceof OutcomeUnknownError) {
        setStates(initialStates(schema, undefined));
        setOutcomeUnknown(caught);
      } else if (caught instanceof ApiError && caught.status === 412) {
        setConflict(candidate);
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
    <form className="editor-form" onSubmit={(event) => void submit(event)}>
      {description}
      {error === null ? null : <ApiErrorState error={error} />}
      <FormError message={formError} />
      <div className="form-grid">
        {Object.entries(effectiveSchema.properties ?? {})
          .filter(([, property]) => {
            const types = schemaTypes(property);
            return !(types.length === 1 && types[0] === "null");
          })
          .map(([name, property]) => (
            <SchemaField
              key={name}
              parent={effectiveSchema}
              name={name}
              schema={property}
              state={states[name]}
              secret={secretField === name}
              presenceLabel={optionalFieldPresenceLabel(initialValue !== undefined)}
              onChange={(state) => setStates((current) => ({ ...current, [name]: state }))}
            />
          ))}
      </div>
      {requiredConfirmation ? (
        <label className="check-row confirmation-row">
          <input
            type="checkbox"
            checked={confirmed}
            onChange={(event) => setConfirmed(event.target.checked)}
          />
          <span>I reviewed the target scope and understand the authority or lifecycle change.</span>
        </label>
      ) : null}
      <SubmitBar
        submitting={submitting}
        disabled={!confirmed}
        submitLabel={submitLabel}
        cancelHref={cancelHref}
        danger={operation.destructive}
      />
    </form>
  );
}
