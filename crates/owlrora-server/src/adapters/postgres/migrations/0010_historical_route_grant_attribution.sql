CREATE TABLE organization_route_grant_identities (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    route_id uuid NOT NULL REFERENCES model_routes(id) ON DELETE RESTRICT,
    created_by_principal jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, route_id),
    UNIQUE (organization_id, route_id, id)
);
CREATE TRIGGER organization_route_grant_identities_immutable
    BEFORE UPDATE OR DELETE ON organization_route_grant_identities
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();

INSERT INTO organization_route_grant_identities(
    id, organization_id, route_id, created_by_principal
)
SELECT gen_random_uuid(), historical.organization_id, historical.route_id,
       '{"kind":"migration_backfill"}'::jsonb
FROM (
    SELECT organization_id, route_id FROM organization_route_grants
    UNION
    SELECT usage.organization_id, usage.route_id
    FROM logical_usage_hourly usage
    JOIN model_routes route ON route.id = usage.route_id
    WHERE route.resource_scope_kind = 'deployment'
    UNION
    SELECT usage.organization_id, usage.route_id
    FROM attempt_usage_hourly usage
    JOIN model_routes route ON route.id = usage.route_id
    WHERE route.resource_scope_kind = 'deployment'
    UNION
    SELECT usage.organization_id, usage.route_id
    FROM logical_usage_daily usage
    JOIN model_routes route ON route.id = usage.route_id
    WHERE route.resource_scope_kind = 'deployment'
    UNION
    SELECT usage.organization_id, usage.route_id
    FROM attempt_usage_daily usage
    JOIN model_routes route ON route.id = usage.route_id
    WHERE route.resource_scope_kind = 'deployment'
) historical;

ALTER TABLE logical_usage_hourly ADD COLUMN route_grant_identity_id uuid;
ALTER TABLE attempt_usage_hourly ADD COLUMN route_grant_identity_id uuid;
ALTER TABLE logical_usage_daily ADD COLUMN route_grant_identity_id uuid;
ALTER TABLE attempt_usage_daily ADD COLUMN route_grant_identity_id uuid;

CREATE OR REPLACE FUNCTION validate_usage_catalog_attribution()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    route_scope text;
    route_organization_id uuid;
    deployment_scope text;
    deployment_organization_id uuid;
    deployment_endpoint_id uuid;
    deployment_credential_id uuid;
    target_route_id uuid;
    target_deployment_id uuid;
BEGIN
    SELECT resource_scope_kind, organization_id
      INTO route_scope, route_organization_id
    FROM model_routes WHERE id = NEW.route_id;
    IF route_scope IS NULL
       OR (route_scope = 'organization' AND (
            route_organization_id <> NEW.organization_id
            OR NEW.route_grant_identity_id IS NOT NULL
       ))
       OR (route_scope = 'deployment' AND (
            NEW.route_grant_identity_id IS NULL
            OR NOT EXISTS (
                SELECT 1 FROM organization_route_grant_identities identity
                WHERE identity.id = NEW.route_grant_identity_id
                  AND identity.organization_id = NEW.organization_id
                  AND identity.route_id = NEW.route_id
            )
       )) THEN
        RAISE EXCEPTION 'usage route is outside captured organization visibility';
    END IF;
    IF TG_TABLE_NAME IN ('logical_usage_hourly', 'logical_usage_daily') THEN
        RETURN NEW;
    END IF;
    SELECT resource_scope_kind, organization_id, endpoint_id, credential_id
      INTO deployment_scope, deployment_organization_id,
           deployment_endpoint_id, deployment_credential_id
    FROM model_deployments WHERE id = NEW.deployment_id;
    SELECT target.route_id, target.deployment_id
      INTO target_route_id, target_deployment_id
    FROM route_targets target WHERE target.id = NEW.target_id;
    IF target_route_id IS NULL THEN
        SELECT retired.route_id, retired.deployment_id
          INTO target_route_id, target_deployment_id
        FROM retired_route_target_identities retired
        WHERE retired.target_id = NEW.target_id;
    END IF;
    IF target_route_id IS DISTINCT FROM NEW.route_id
       OR target_deployment_id IS DISTINCT FROM NEW.deployment_id
       OR deployment_endpoint_id IS DISTINCT FROM NEW.endpoint_id
       OR deployment_credential_id IS DISTINCT FROM NEW.credential_id
       OR (NEW.origin = 'system_provided' AND deployment_scope <> 'deployment')
       OR (NEW.origin = 'organization_byok' AND (
            deployment_scope <> 'organization'
            OR deployment_organization_id <> NEW.organization_id
       )) THEN
        RAISE EXCEPTION 'attempt usage catalog/origin attribution does not match captured graph';
    END IF;
    RETURN NEW;
END;
$$;

UPDATE logical_usage_hourly usage
SET route_grant_identity_id = identity.id
FROM organization_route_grant_identities identity
WHERE identity.organization_id = usage.organization_id
  AND identity.route_id = usage.route_id;
UPDATE attempt_usage_hourly usage
SET route_grant_identity_id = identity.id
FROM organization_route_grant_identities identity
WHERE identity.organization_id = usage.organization_id
  AND identity.route_id = usage.route_id;
UPDATE logical_usage_daily usage
SET route_grant_identity_id = identity.id
FROM organization_route_grant_identities identity
WHERE identity.organization_id = usage.organization_id
  AND identity.route_id = usage.route_id;
UPDATE attempt_usage_daily usage
SET route_grant_identity_id = identity.id
FROM organization_route_grant_identities identity
WHERE identity.organization_id = usage.organization_id
  AND identity.route_id = usage.route_id;

SET CONSTRAINTS ALL IMMEDIATE;

ALTER TABLE logical_usage_hourly
    ADD CONSTRAINT logical_usage_route_grant_identity_fk
    FOREIGN KEY (organization_id, route_id, route_grant_identity_id)
    REFERENCES organization_route_grant_identities(organization_id, route_id, id)
    ON DELETE RESTRICT;
ALTER TABLE attempt_usage_hourly
    ADD CONSTRAINT attempt_usage_route_grant_identity_fk
    FOREIGN KEY (organization_id, route_id, route_grant_identity_id)
    REFERENCES organization_route_grant_identities(organization_id, route_id, id)
    ON DELETE RESTRICT;
ALTER TABLE logical_usage_daily
    ADD CONSTRAINT logical_usage_daily_route_grant_identity_fk
    FOREIGN KEY (organization_id, route_id, route_grant_identity_id)
    REFERENCES organization_route_grant_identities(organization_id, route_id, id)
    ON DELETE RESTRICT;
ALTER TABLE attempt_usage_daily
    ADD CONSTRAINT attempt_usage_daily_route_grant_identity_fk
    FOREIGN KEY (organization_id, route_id, route_grant_identity_id)
    REFERENCES organization_route_grant_identities(organization_id, route_id, id)
    ON DELETE RESTRICT;
