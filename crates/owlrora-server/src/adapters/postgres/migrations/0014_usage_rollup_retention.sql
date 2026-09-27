-- Daily totals are updated in the same receipt transaction as hourly deltas.
ALTER TABLE logical_usage_daily RENAME CONSTRAINT
    logical_usage_daily_bucket_start_organization_id_principal__key
    TO logical_usage_daily_identity_unique;
ALTER TABLE attempt_usage_daily RENAME CONSTRAINT
    attempt_usage_daily_bucket_start_organization_id_principal__key
    TO attempt_usage_daily_identity_unique;

-- Fence concurrent flushes while establishing the initial daily projection.
LOCK TABLE logical_usage_hourly, attempt_usage_hourly IN SHARE ROW EXCLUSIVE MODE;
INSERT INTO logical_usage_daily (
    bucket_date, organization_id, principal_kind, gateway_api_key_id, user_id, membership_id,
    route_id, route_grant_identity_id, ingress_protocol_family, outcome_class,
    request_count, input_units, output_units, cached_input_units, cost_nanos,
    unknown_cost_count, duration_millis
)
SELECT date_trunc('day', bucket_start AT TIME ZONE 'UTC') AT TIME ZONE 'UTC',
    organization_id, principal_kind, gateway_api_key_id, user_id, membership_id,
    route_id, route_grant_identity_id, ingress_protocol_family, outcome_class,
    SUM(request_count), SUM(input_units), SUM(output_units), SUM(cached_input_units),
    SUM(cost_nanos), SUM(unknown_cost_count), SUM(duration_millis)
FROM logical_usage_hourly
GROUP BY 1,2,3,4,5,6,7,8,9,10
ON CONFLICT ON CONSTRAINT logical_usage_daily_identity_unique DO UPDATE SET
    request_count=EXCLUDED.request_count, input_units=EXCLUDED.input_units,
    output_units=EXCLUDED.output_units, cached_input_units=EXCLUDED.cached_input_units,
    cost_nanos=EXCLUDED.cost_nanos, unknown_cost_count=EXCLUDED.unknown_cost_count,
    duration_millis=EXCLUDED.duration_millis;

INSERT INTO attempt_usage_daily (
    bucket_date, organization_id, principal_kind, gateway_api_key_id, user_id, membership_id,
    route_id, route_grant_identity_id, target_id, deployment_id, endpoint_id,
    endpoint_config_version, credential_id, credential_secret_version,
    credential_state_identity_version, origin, pricing_policy_version_id,
    key_budget_policy_id, key_budget_version_id, key_budget_generation, key_budget_epoch,
    origin_budget_policy_id, origin_budget_version_id, origin_budget_generation, origin_budget_epoch,
    terminal_class, attempt_count, input_units, output_units, cached_input_units,
    estimated_cost_nanos, unknown_estimate_count, actual_cost_nanos, unknown_cost_count, duration_millis
)
SELECT date_trunc('day', bucket_start AT TIME ZONE 'UTC') AT TIME ZONE 'UTC',
    organization_id, principal_kind, gateway_api_key_id, user_id, membership_id,
    route_id, route_grant_identity_id, target_id, deployment_id, endpoint_id,
    endpoint_config_version, credential_id, credential_secret_version,
    credential_state_identity_version, origin, pricing_policy_version_id,
    key_budget_policy_id, key_budget_version_id, key_budget_generation, key_budget_epoch,
    origin_budget_policy_id, origin_budget_version_id, origin_budget_generation, origin_budget_epoch,
    terminal_class, SUM(attempt_count), SUM(input_units), SUM(output_units), SUM(cached_input_units),
    SUM(estimated_cost_nanos), SUM(unknown_estimate_count), SUM(actual_cost_nanos),
    SUM(unknown_cost_count), SUM(duration_millis)
FROM attempt_usage_hourly
GROUP BY 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26
ON CONFLICT ON CONSTRAINT attempt_usage_daily_identity_unique DO UPDATE SET
    attempt_count=EXCLUDED.attempt_count, input_units=EXCLUDED.input_units,
    output_units=EXCLUDED.output_units, cached_input_units=EXCLUDED.cached_input_units,
    estimated_cost_nanos=EXCLUDED.estimated_cost_nanos,
    unknown_estimate_count=EXCLUDED.unknown_estimate_count,
    actual_cost_nanos=EXCLUDED.actual_cost_nanos, unknown_cost_count=EXCLUDED.unknown_cost_count,
    duration_millis=EXCLUDED.duration_millis;

SET CONSTRAINTS ALL IMMEDIATE;

CREATE INDEX logical_usage_hourly_retention_idx ON logical_usage_hourly(bucket_start);
CREATE INDEX attempt_usage_hourly_retention_idx ON attempt_usage_hourly(bucket_start);
CREATE INDEX logical_usage_daily_retention_idx ON logical_usage_daily(bucket_date);
CREATE INDEX attempt_usage_daily_retention_idx ON attempt_usage_daily(bucket_date);
CREATE INDEX aggregate_flush_receipts_retention_idx ON aggregate_flush_receipts(flushed_at);

-- A flush accepts buckets only within seven days, so retaining receipts eight
-- days past commit fences delayed replay even after a receipt is pruned.
DROP TRIGGER aggregate_flush_receipts_immutable ON aggregate_flush_receipts;
CREATE TRIGGER aggregate_flush_receipts_immutable
    BEFORE UPDATE ON aggregate_flush_receipts
    FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();
CREATE FUNCTION guard_aggregate_receipt_retention() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.flushed_at >= now() - interval '8 days' THEN
        RAISE EXCEPTION 'aggregate receipt is inside the replay safety window';
    END IF;
    RETURN OLD;
END;
$$;
CREATE TRIGGER aggregate_flush_receipts_retention_guard
    BEFORE DELETE ON aggregate_flush_receipts
    FOR EACH ROW EXECUTE FUNCTION guard_aggregate_receipt_retention();
