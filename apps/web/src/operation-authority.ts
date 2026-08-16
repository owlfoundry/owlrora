import authorityProjection from "./operation_authority.json";
import type { CurrentPrincipal, JsonValue, ManagementScope } from "./api";

interface AuthorizationVariant {
  required_capability: string;
  condition: "local_member_self_service_policy" | null;
}

export interface JsonSchema {
  type?: string | string[];
  format?: string;
  enum?: JsonValue[];
  const?: JsonValue;
  oneOf?: JsonSchema[];
  contains?: JsonSchema;
  minContains?: number;
  properties?: Record<string, JsonSchema>;
  required?: string[];
  items?: JsonSchema;
  minLength?: number;
  maxLength?: number;
  minimum?: number;
  maximum?: number;
  minItems?: number;
  maxItems?: number;
  pattern?: string;
  additionalProperties?: boolean;
}

export interface OperationAuthority {
  id: string;
  resource_family: string;
  method: "GET" | "POST";
  path: string;
  mode: "query" | "command";
  qualification: "public" | "personal" | "system" | "organization" | "operations";
  required_scopes: ManagementScope[];
  authorization_variants: AuthorizationVariant[];
  request_schema: JsonSchema | null;
  response_schema: string;
  paginated: boolean;
  query_parameters: Array<{ name: string; schema: JsonSchema; required: boolean }>;
  etag_precondition: boolean;
  idempotency: "not_applicable" | "supported" | "rejected" | "state_machine";
  client_generated_idempotency_key: boolean;
  secret_input: { field: string; mode: "replace_body" | "merge_into_candidate" } | null;
  one_time_secret_response: boolean;
  sensitive_result: boolean;
  high_impact: boolean;
  destructive: boolean;
  approval_recommended: boolean;
}

const authorityByOperation = new Map(
  (authorityProjection as OperationAuthority[]).map((operation) => [operation.id, operation]),
);

function capabilityAllows(
  me: CurrentPrincipal,
  capability: string,
  organizationId?: string,
): boolean {
  if (organizationId === undefined) return me.capabilities.includes(capability);
  if (me.system_administrator && me.capabilities.includes(capability)) return true;
  return (
    me.allowed_organizations
      .find((organization) => organization.organization_id === organizationId)
      ?.capabilities.includes(capability) === true
  );
}

function variantAllows(
  me: CurrentPrincipal,
  variant: AuthorizationVariant,
  organizationId?: string,
): boolean {
  if (!capabilityAllows(me, variant.required_capability, organizationId)) return false;
  if (variant.condition === null) return true;
  const organization = me.allowed_organizations.find(
    (candidate) => candidate.organization_id === organizationId,
  );
  const policy = organization?.management_key_self_service;
  return (
    variant.condition === "local_member_self_service_policy" &&
    organizationId !== undefined &&
    me.principal.kind === "local_user" &&
    !me.system_administrator &&
    organization?.role === "member" &&
    policy?.eligible === true &&
    policy.allowed_scopes.some((scope) => me.effective_management_scopes.includes(scope)) &&
    policy.allowed_capabilities.some((capability) => organization.capabilities.includes(capability))
  );
}

export function operationAllows(
  me: CurrentPrincipal,
  operationId: string,
  organizationId?: string,
): boolean {
  const operation = authorityByOperation.get(operationId);
  if (operation === undefined) return false;
  if (!operation.required_scopes.every((scope) => me.effective_management_scopes.includes(scope))) {
    return false;
  }
  return (
    operation.authorization_variants.length === 0 ||
    operation.authorization_variants.some((variant) => variantAllows(me, variant, organizationId))
  );
}

export function operationAuthority(operationId: string): OperationAuthority | null {
  return authorityByOperation.get(operationId) ?? null;
}

export function operationPath(operationId: string, params: Record<string, string>): string | null {
  const operation = operationAuthority(operationId);
  if (operation === null) return null;
  let complete = true;
  const path = operation.path.replace(/\{([^}]+)\}/g, (_, name: string) => {
    const value = params[name];
    if (value === undefined || value.length === 0) {
      complete = false;
      return "";
    }
    return encodeURIComponent(value);
  });
  return complete ? path : null;
}
