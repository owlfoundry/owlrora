-- System-wide aggregate exploration is time-bounded without an organization prefix.
CREATE INDEX logical_usage_hourly_bucket_start_idx
    ON logical_usage_hourly (bucket_start);

CREATE INDEX attempt_usage_hourly_bucket_start_idx
    ON attempt_usage_hourly (bucket_start);

-- Operations diagnostics summarize only a recent receipt window.
CREATE INDEX aggregate_flush_receipts_flushed_at_idx
    ON aggregate_flush_receipts (flushed_at, fact_family);
