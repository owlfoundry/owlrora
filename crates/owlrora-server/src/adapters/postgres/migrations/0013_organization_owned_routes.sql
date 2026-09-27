-- Organization resources do not inherit an employee's membership lifecycle.
DROP TRIGGER model_routes_active_owner_membership ON model_routes;
DROP FUNCTION validate_model_route_owner_membership();
ALTER TABLE model_routes
    DROP COLUMN owner_user_id,
    DROP COLUMN owner_membership_id;
ALTER TABLE model_routes ADD CONSTRAINT model_routes_scope_binding CHECK (
    (resource_scope_kind = 'deployment' AND organization_id IS NULL)
    OR (resource_scope_kind = 'organization' AND organization_id IS NOT NULL)
);
