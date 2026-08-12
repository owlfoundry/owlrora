CREATE OR REPLACE FUNCTION enforce_active_organization_owner()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    checked_organization_id uuid;
    organization_is_active boolean;
BEGIN
    IF TG_TABLE_NAME = 'memberships' THEN
        IF TG_OP = 'DELETE' THEN
            checked_organization_id := OLD.organization_id;
        ELSE
            checked_organization_id := NEW.organization_id;
        END IF;
    ELSE
        checked_organization_id := NEW.id;
    END IF;

    SELECT status = 'active' INTO organization_is_active
    FROM organizations WHERE id = checked_organization_id;
    IF organization_is_active AND NOT EXISTS (
        SELECT 1 FROM memberships
        WHERE organization_id = checked_organization_id
          AND status = 'active' AND role = 'owner'
    ) THEN
        RAISE EXCEPTION 'active organization must retain an active owner';
    END IF;

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;
