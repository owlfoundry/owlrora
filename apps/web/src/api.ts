export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

export interface Page<T> {
  items: T[];
  next_cursor: string | null;
}

export type ManagementScope =
  | "management:read"
  | "management:write"
  | "management:secrets"
  | "management:operations"
  | "management:authority";

export type OrganizationRole = "owner" | "admin" | "member";
export type UserKind = "human" | "synthetic";
export type UserStatus = "active" | "disabled";
export type OrganizationKind = "ordinary" | "synthetic";
export type OrganizationStatus = "active" | "suspended";
export type KeyStatus = "active" | "disabled" | "revoked";

export type Principal =
  | { kind: "seed_admin" }
  | { kind: "local_user"; user_id: string }
  | {
      kind: "deployment_management_api_key";
      management_api_key_id: string;
    }
  | {
      kind: "organization_management_api_key";
      organization_id: string;
      management_api_key_id: string;
    };

export type ResourceScope =
  { kind: "deployment" } | { kind: "organization"; organization_id: string };

export interface ManagementKeySelfServiceEligibility {
  eligible: boolean;
  allowed_scopes: ManagementScope[];
  allowed_capabilities: string[];
  max_expiry_days: number;
  max_active_keys: number;
  active_keys: number;
}

export interface AllowedOrganization {
  organization_id: string;
  name: string;
  access_reason: string;
  role: OrganizationRole | null;
  capabilities: string[];
  management_key_self_service: ManagementKeySelfServiceEligibility | null;
}

export interface CurrentPrincipal {
  principal: Principal;
  authentication_method:
    "management_api_key" | "management_api_key_session" | "external_session" | "external_jwt";
  effective_management_scopes: ManagementScope[];
  resource_scope: ResourceScope;
  system_administrator: boolean;
  allowed_organizations: AllowedOrganization[];
  capabilities: string[];
}

export interface SessionView {
  id: string;
  principal: Principal;
  authentication_method: CurrentPrincipal["authentication_method"];
  created_at: string;
  expires_at: string;
  current: boolean;
}

export interface SessionCreated {
  session: SessionView;
  csrf_token: string;
}

export interface BrowserLoginIssuer {
  name: string;
  display_name: string;
}

export interface User {
  id: string;
  kind: UserKind;
  status: UserStatus;
  display_name: string;
  primary_email: string | null;
  created_by_principal: JsonValue;
  created_at: string;
  updated_at: string;
}

export interface Organization {
  id: string;
  kind: OrganizationKind;
  status: OrganizationStatus;
  name: string;
  slug: string | null;
  created_by_principal: JsonValue;
  created_at: string;
  updated_at: string;
}

export interface Membership {
  id: string;
  organization_id: string;
  user_id: string;
  role: OrganizationRole;
  status: string;
  llm_scope_ceiling: string[];
  llm_capability_ceiling: string[];
  llm_route_ceiling: JsonValue;
  created_at: string;
  updated_at: string;
}

export interface Invitation {
  id: string;
  organization_id: string;
  intended_email: string | null;
  intended_role: OrganizationRole;
  llm_scope_ceiling: string[];
  llm_capability_ceiling: string[];
  llm_route_ceiling: JsonValue;
  state: string;
  expires_at: string;
  accepted_by_user_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface OneTimeInvitation {
  invitation: Invitation;
  token: string;
}

export interface ManagementApiKey {
  id: string;
  resource_scope: ResourceScope;
  issuance_policy_class: string;
  created_by_principal: JsonValue;
  name: string;
  key_prefix: string;
  scopes: ManagementScope[];
  capability_ceiling: JsonValue;
  status: KeyStatus;
  expires_at: string | null;
  current_secret_version_id: string;
  overlap_until: string | null;
  created_at: string;
  updated_at: string;
}

export interface OneTimeManagementApiKey {
  management_api_key: ManagementApiKey;
  key: string;
}

export interface OrganizationApiKeyPolicy {
  organization_id: string;
  policy: JsonValue;
  updated_at: string;
}

export interface DeploymentManagementKeyPolicy {
  policy: JsonValue;
  updated_at: string;
}

export interface AdministratorGrant {
  id: string | null;
  subject_kind: string;
  subject_id: string;
  status: string;
  built_in: boolean;
  created_at: string | null;
}

export interface ExternalIdentityIssuer {
  id: string;
  name: string;
  display_name: string;
  issuer: string;
  status: "active" | "disabled";
  jwks_source: JsonValue;
  current_verifier_material_version_id: string | null;
  allowed_algorithms: string[];
  accepted_audiences: string[];
  subject_claim: string;
  claim_mapping: JsonValue;
  jwt_capability_ceiling: string[];
  management_scope_ceiling: ManagementScope[];
  management_capability_ceiling: string[];
  management_organization_ceiling: JsonValue;
  llm_scope_ceiling: string[];
  llm_capability_ceiling: string[];
  capability_claim_policy: "ignore" | "optional_narrowing" | "required_narrowing";
  jwt_route_ceiling: JsonValue;
  organization_selector: JsonValue;
  provisioning_policy_id: string | null;
  browser_login: JsonValue | null;
  clock_skew_seconds: number;
  key_cache_policy: JsonValue;
  policy_version: number;
  created_at: string;
  updated_at: string;
}

export interface ExternalIdentityBinding {
  id: string;
  issuer_id: string;
  external_subject: string;
  user_id: string;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface ProvisioningPolicy {
  id: string;
  name: string;
  status: string;
  user_kind: UserKind;
  configuration: JsonValue;
  created_at: string;
  updated_at: string;
}

export interface AuditEntry {
  id: string;
  actor: JsonValue | null;
  authentication_evidence: JsonValue;
  organization_id: string | null;
  target_resource_kind: string;
  target_resource_id: string | null;
  operation_id: string;
  outcome: string;
  request_id: string;
  changed_fields: string[];
  safe_details: JsonValue;
  created_at: string;
}

export interface ReadinessView {
  ready: boolean;
  database: string;
  runtime_revision: number;
  database_revision: number;
  runtime_age_seconds: number;
  publication_error: string | null;
}

interface ApiErrorEnvelope {
  error?: {
    code?: string;
    message?: string;
    request_id?: string;
    details?: Record<string, JsonValue>;
  };
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId: string | null;
  readonly details: Record<string, JsonValue>;

  constructor(
    status: number,
    code: string,
    message: string,
    requestId: string | null = null,
    details: Record<string, JsonValue> = {},
  ) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.requestId = requestId;
    this.details = details;
  }
}

export interface CommandStatus {
  persistence: "committed";
  nodePublication: "applied" | "pending";
  appliedRevision: number | null;
  databaseRevision: number | null;
}

export interface ApiResponse<T> {
  value: T;
  etag: string | null;
  commandStatus: CommandStatus | null;
}

export class OutcomeUnknownError extends Error {
  readonly requestId: string;
  readonly committed: boolean;

  constructor(requestId: string, committed = false) {
    super(
      committed
        ? "OwlRora committed the one-time command, but the response body was unavailable."
        : "The connection ended before OwlRora could confirm whether the one-time command committed.",
    );
    this.name = "OutcomeUnknownError";
    this.requestId = requestId;
    this.committed = committed;
  }
}

export const COMMAND_STATUS_EVENT = "owlrora:command-status";

export interface RequestOptions {
  method?: "GET" | "POST";
  body?: unknown;
  ifMatch?: string;
  idempotencyKey?: string;
  headers?: Record<string, string>;
  signal?: AbortSignal;
  nonRepeatable?: boolean;
}

function assertSameOriginPath(path: string): void {
  if (!path.startsWith("/") || path.startsWith("//")) {
    throw new Error("API paths must be same-origin absolute paths");
  }
}

export function readCookie(name: string, cookie = document.cookie): string | null {
  const prefix = `${name}=`;
  for (const part of cookie.split(";")) {
    const candidate = part.trim();
    if (candidate.startsWith(prefix)) {
      const value = candidate.slice(prefix.length);
      return value.length > 0 ? decodeURIComponent(value) : null;
    }
  }
  return null;
}

export function createIdempotencyKey(): string {
  return `console_${crypto.randomUUID()}`;
}

async function parseError(response: Response): Promise<ApiError> {
  let envelope: ApiErrorEnvelope = {};
  try {
    envelope = (await response.json()) as ApiErrorEnvelope;
  } catch {
    // Preserve the bounded generic error when a proxy returned a non-JSON body.
  }
  const error = envelope.error;
  return new ApiError(
    response.status,
    error?.code ?? "request_failed",
    error?.message ?? "The request could not be completed.",
    error?.request_id ?? response.headers.get("x-request-id"),
    error?.details ?? {},
  );
}

function readCommandStatus(response: Response): CommandStatus | null {
  if (response.headers.get("x-owlrora-command-status") !== "committed") {
    return null;
  }
  const publication = response.headers.get("x-owlrora-node-publication");
  const parseRevision = (name: string): number | null => {
    const value = response.headers.get(name);
    if (value === null) return null;
    const parsed = Number(value);
    return Number.isSafeInteger(parsed) ? parsed : null;
  };
  return {
    persistence: "committed",
    nodePublication: publication === "applied" ? "applied" : "pending",
    appliedRevision: parseRevision("x-owlrora-applied-revision"),
    databaseRevision: parseRevision("x-owlrora-database-revision"),
  };
}

export async function apiRequest<T>(
  path: string,
  options: RequestOptions = {},
): Promise<ApiResponse<T>> {
  assertSameOriginPath(path);
  const method = options.method ?? "GET";
  const headers = new Headers({ Accept: "application/json", ...options.headers });
  const requestId = `console_${crypto.randomUUID()}`;
  headers.set("X-Request-ID", requestId);
  if (options.body !== undefined) {
    headers.set("Content-Type", "application/json");
  }
  if (options.ifMatch !== undefined) {
    headers.set("If-Match", options.ifMatch);
  }
  if (options.idempotencyKey !== undefined) {
    headers.set("Idempotency-Key", options.idempotencyKey);
  }
  if (method === "POST" && !headers.has("Authorization")) {
    const csrf = readCookie("owlrora_csrf");
    if (csrf !== null) {
      headers.set("X-OwlRora-CSRF-Token", csrf);
    }
  }
  let response: Response;
  try {
    response = await fetch(path, {
      method,
      credentials: "include",
      cache: "no-store",
      redirect: "follow",
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      signal: options.signal,
    });
  } catch (error: unknown) {
    if (options.nonRepeatable === true) {
      throw new OutcomeUnknownError(requestId);
    }
    throw error;
  }
  if (!response.ok) {
    throw await parseError(response);
  }
  const commandStatus = readCommandStatus(response);
  if (commandStatus !== null && typeof window !== "undefined") {
    window.dispatchEvent(new CustomEvent(COMMAND_STATUS_EVENT, { detail: commandStatus }));
  }
  if (response.status === 204) {
    return {
      value: undefined as T,
      etag: response.headers.get("etag"),
      commandStatus,
    };
  }
  let value: T;
  try {
    value = (await response.json()) as T;
  } catch (error: unknown) {
    if (options.nonRepeatable === true) {
      throw new OutcomeUnknownError(requestId, commandStatus !== null);
    }
    throw error;
  }
  return {
    value,
    etag: response.headers.get("etag"),
    commandStatus,
  };
}

export async function exchangeManagementKey(key: string): Promise<SessionCreated> {
  const response = await apiRequest<SessionCreated>(
    "/auth/v1/management-api-key/session/actions/create",
    { method: "POST", headers: { Authorization: `Bearer ${key}` } },
  );
  return response.value;
}

export async function logout(): Promise<void> {
  await apiRequest<void>("/api/v1/session/actions/logout", { method: "POST" });
}

export function withPageQuery(path: string, cursor: string | null, limit = 50): string {
  const query = new URLSearchParams({ limit: String(limit) });
  if (cursor !== null) {
    query.set("cursor", cursor);
  }
  return `${path}?${query.toString()}`;
}

export function formatDate(value: string | null): string {
  if (value === null) {
    return "Not set";
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      }).format(date);
}

export function jsonText(value: JsonValue): string {
  return JSON.stringify(value, null, 2);
}

export function parseJsonObject(value: string, fieldName: string): JsonValue {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error(`${fieldName} must contain valid JSON.`);
  }
  if (parsed === null || Array.isArray(parsed) || typeof parsed !== "object") {
    throw new Error(`${fieldName} must contain a JSON object.`);
  }
  return parsed as JsonValue;
}
