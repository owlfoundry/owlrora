use std::collections::HashMap;

use chrono::{DateTime, Duration, Timelike as _, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row as _;
use uuid::Uuid;

use crate::domain::{Capability, ManagementScope, OrganizationId};

use super::{Application, ApplicationError, AuthorizationTarget, RequestIdentity};

const MAX_USAGE_RANGE: Duration = Duration::days(366);
const DEFAULT_BREAKDOWN_LIMIT: u32 = 20;
const MAX_BREAKDOWN_LIMIT: u32 = 100;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageGranularity {
    #[default]
    Hour,
    Day,
}

impl UsageGranularity {
    const fn sql_value(self) -> &'static str {
        match self {
            Self::Hour => "hour",
            Self::Day => "day",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UsageQuery {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    #[serde(default)]
    pub granularity: UsageGranularity,
    pub organization_id: Option<Uuid>,
    pub principal_kind: Option<String>,
    pub user_id: Option<Uuid>,
    pub gateway_api_key_id: Option<Uuid>,
    pub route_id: Option<Uuid>,
    pub target_id: Option<Uuid>,
    pub origin: Option<String>,
    pub deployment_id: Option<Uuid>,
    pub endpoint_id: Option<Uuid>,
    pub credential_id: Option<Uuid>,
    pub outcome: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageFactFamily {
    LogicalRequests,
    Attempts,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageBreakdownDimension {
    Organization,
    PrincipalKind,
    User,
    GatewayApiKey,
    Route,
    Protocol,
    Target,
    Origin,
    Deployment,
    Endpoint,
    Credential,
    Outcome,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageBreakdownOrder {
    #[default]
    CountDesc,
    CostDesc,
    DimensionAsc,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsageBreakdownQuery {
    #[serde(flatten)]
    pub usage: UsageQuery,
    pub fact_family: UsageFactFamily,
    pub dimension: UsageBreakdownDimension,
    #[serde(default)]
    pub order: UsageBreakdownOrder,
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UsageScope {
    System,
    Organization { organization_id: OrganizationId },
}

#[derive(Clone, Debug, Serialize)]
pub struct UsageCompleteness {
    pub source: &'static str,
    pub includes_unflushed_process_facts: bool,
    pub daily_rollups: &'static str,
    pub note: &'static str,
}

impl Default for UsageCompleteness {
    fn default() -> Self {
        Self {
            source: "persisted_hourly_aggregates",
            includes_unflushed_process_facts: false,
            daily_rollups: "not_implemented",
            note: "Results include only aggregate facts durably flushed before this query.",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct UsageRange {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub granularity: UsageGranularity,
}

#[derive(Clone, Debug, Serialize)]
pub struct UsageSeries<T> {
    pub applicable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclusion_reason: Option<&'static str>,
    pub items: Vec<T>,
}

#[derive(Clone, Debug, Serialize)]
pub struct LogicalUsageBucket {
    pub bucket_start: DateTime<Utc>,
    pub request_count: String,
    pub input_units: String,
    pub output_units: String,
    pub cached_input_units: String,
    pub known_cost_nanos: Option<String>,
    pub unknown_cost_count: String,
    pub duration_millis: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct AttemptUsageBucket {
    pub bucket_start: DateTime<Utc>,
    pub attempt_count: String,
    pub input_units: String,
    pub output_units: String,
    pub cached_input_units: String,
    pub known_estimated_cost_nanos: Option<String>,
    pub unknown_estimate_count: String,
    pub known_actual_cost_nanos: Option<String>,
    pub unknown_cost_count: String,
    pub duration_millis: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct UsageView {
    pub scope: UsageScope,
    pub range: UsageRange,
    pub completeness: UsageCompleteness,
    pub logical_requests: UsageSeries<LogicalUsageBucket>,
    pub attempts: UsageSeries<AttemptUsageBucket>,
}

#[derive(Clone, Debug, Serialize)]
pub struct UsageBreakdownMeasures {
    pub count: String,
    pub input_units: String,
    pub output_units: String,
    pub cached_input_units: String,
    pub known_estimated_cost_nanos: Option<String>,
    pub unknown_estimate_count: Option<String>,
    pub known_actual_cost_nanos: Option<String>,
    pub known_cost_nanos: Option<String>,
    pub unknown_cost_count: String,
    pub duration_millis: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct UsageBreakdownItem {
    pub dimension_value: Option<String>,
    pub measures: UsageBreakdownMeasures,
}

#[derive(Clone, Debug, Serialize)]
pub struct UsageBreakdownView {
    pub scope: UsageScope,
    pub range: UsageRange,
    pub completeness: UsageCompleteness,
    pub fact_family: UsageFactFamily,
    pub dimension: UsageBreakdownDimension,
    pub order: UsageBreakdownOrder,
    pub limit: u32,
    pub items: Vec<UsageBreakdownItem>,
}

impl Application {
    pub async fn get_organization_usage(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
        query: &UsageQuery,
    ) -> Result<UsageView, ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Read],
            AuthorizationTarget::Organization {
                organization_id,
                capability: Capability::ReadUsage,
            },
        )?;
        let query = organization_query(organization_id, query)?;
        self.query_usage(UsageScope::Organization { organization_id }, &query)
            .await
    }

    pub async fn get_system_usage(
        &self,
        identity: &RequestIdentity,
        query: &UsageQuery,
    ) -> Result<UsageView, ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Read],
            AuthorizationTarget::System {
                capability: Capability::ReadUsage,
            },
        )?;
        validate_usage_query(query)?;
        self.query_usage(UsageScope::System, query).await
    }

    pub async fn get_organization_usage_breakdown(
        &self,
        identity: &RequestIdentity,
        organization_id: OrganizationId,
        query: &UsageBreakdownQuery,
    ) -> Result<UsageBreakdownView, ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Read],
            AuthorizationTarget::Organization {
                organization_id,
                capability: Capability::ReadUsage,
            },
        )?;
        let mut query = query.clone();
        query.usage = organization_query(organization_id, &query.usage)?;
        if query.dimension == UsageBreakdownDimension::Credential {
            return Err(ApplicationError::Validation(
                "credential breakdown is not available in organization usage".to_owned(),
            ));
        }
        self.query_usage_breakdown(UsageScope::Organization { organization_id }, &query)
            .await
    }

    pub async fn get_system_usage_breakdown(
        &self,
        identity: &RequestIdentity,
        query: &UsageBreakdownQuery,
    ) -> Result<UsageBreakdownView, ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Read],
            AuthorizationTarget::System {
                capability: Capability::ReadUsage,
            },
        )?;
        validate_breakdown_query(query)?;
        self.query_usage_breakdown(UsageScope::System, query).await
    }

    async fn query_usage(
        &self,
        scope: UsageScope,
        query: &UsageQuery,
    ) -> Result<UsageView, ApplicationError> {
        validate_usage_query(query)?;
        let logical_applicable = !has_attempt_only_filter(query);
        let logical_requests = if logical_applicable {
            UsageSeries {
                applicable: true,
                exclusion_reason: None,
                items: query_logical_usage(self, query).await?,
            }
        } else {
            UsageSeries {
                applicable: false,
                exclusion_reason: Some(
                    "target, origin, deployment, endpoint, and credential filters apply only to attempt facts",
                ),
                items: Vec::new(),
            }
        };
        let attempts = UsageSeries {
            applicable: true,
            exclusion_reason: None,
            items: query_attempt_usage(self, query).await?,
        };
        Ok(UsageView {
            scope,
            range: usage_range(query),
            completeness: UsageCompleteness::default(),
            logical_requests,
            attempts,
        })
    }

    async fn query_usage_breakdown(
        &self,
        scope: UsageScope,
        query: &UsageBreakdownQuery,
    ) -> Result<UsageBreakdownView, ApplicationError> {
        validate_breakdown_query(query)?;
        let limit = query.limit.unwrap_or(DEFAULT_BREAKDOWN_LIMIT);
        let items = query_breakdown(self, query, limit).await?;
        Ok(UsageBreakdownView {
            scope,
            range: usage_range(&query.usage),
            completeness: UsageCompleteness::default(),
            fact_family: query.fact_family,
            dimension: query.dimension,
            order: query.order,
            limit,
            items,
        })
    }
}

fn organization_query(
    organization_id: OrganizationId,
    query: &UsageQuery,
) -> Result<UsageQuery, ApplicationError> {
    if query.credential_id.is_some() {
        return Err(ApplicationError::Validation(
            "credential_id filter is not available in organization usage".to_owned(),
        ));
    }
    if query
        .organization_id
        .is_some_and(|value| value != organization_id.as_uuid())
    {
        return Err(ApplicationError::Validation(
            "organization_id filter must match the organization-qualified path".to_owned(),
        ));
    }
    let mut query = query.clone();
    query.organization_id = Some(organization_id.as_uuid());
    validate_usage_query(&query)?;
    Ok(query)
}

fn validate_usage_query(query: &UsageQuery) -> Result<(), ApplicationError> {
    if query.start >= query.end {
        return Err(ApplicationError::Validation(
            "usage start must be earlier than end".to_owned(),
        ));
    }
    if query.end - query.start > MAX_USAGE_RANGE {
        return Err(ApplicationError::Validation(
            "usage range must not exceed 366 days".to_owned(),
        ));
    }
    if !is_hour_boundary(query.start) || !is_hour_boundary(query.end) {
        return Err(ApplicationError::Validation(
            "usage start and end must be exact UTC hour boundaries".to_owned(),
        ));
    }
    validate_optional_value("principal_kind", query.principal_kind.as_deref())?;
    validate_optional_value("origin", query.origin.as_deref())?;
    validate_optional_value("outcome", query.outcome.as_deref())?;
    if let Some(principal_kind) = query.principal_kind.as_deref()
        && !matches!(
            principal_kind,
            "gateway_api_key" | "local_user" | "external_jwt"
        )
    {
        return Err(ApplicationError::Validation(
            "principal_kind must be gateway_api_key, local_user, or external_jwt".to_owned(),
        ));
    }
    if let Some(origin) = query.origin.as_deref()
        && !matches!(origin, "system_provided" | "organization_byok")
    {
        return Err(ApplicationError::Validation(
            "origin must be system_provided or organization_byok".to_owned(),
        ));
    }
    Ok(())
}

fn is_hour_boundary(value: DateTime<Utc>) -> bool {
    value.minute() == 0 && value.second() == 0 && value.nanosecond() == 0
}

fn validate_breakdown_query(query: &UsageBreakdownQuery) -> Result<(), ApplicationError> {
    validate_usage_query(&query.usage)?;
    let allowed = match query.fact_family {
        UsageFactFamily::LogicalRequests => matches!(
            query.dimension,
            UsageBreakdownDimension::Organization
                | UsageBreakdownDimension::PrincipalKind
                | UsageBreakdownDimension::User
                | UsageBreakdownDimension::GatewayApiKey
                | UsageBreakdownDimension::Route
                | UsageBreakdownDimension::Protocol
                | UsageBreakdownDimension::Outcome
        ),
        UsageFactFamily::Attempts => !matches!(query.dimension, UsageBreakdownDimension::Protocol),
    };
    if !allowed {
        return Err(ApplicationError::Validation(format!(
            "dimension {:?} is not available for {:?} facts",
            query.dimension, query.fact_family
        )));
    }
    if query.fact_family == UsageFactFamily::LogicalRequests
        && has_attempt_only_filter(&query.usage)
    {
        return Err(ApplicationError::Validation(
            "logical request facts cannot be filtered by target, origin, deployment, endpoint, or credential"
                .to_owned(),
        ));
    }
    if query
        .limit
        .is_some_and(|limit| limit == 0 || limit > MAX_BREAKDOWN_LIMIT)
    {
        return Err(ApplicationError::Validation(
            "breakdown limit must be between 1 and 100".to_owned(),
        ));
    }
    Ok(())
}

fn validate_optional_value(name: &str, value: Option<&str>) -> Result<(), ApplicationError> {
    if value.is_some_and(|value| value.is_empty() || value.len() > 64) {
        return Err(ApplicationError::Validation(format!(
            "{name} must contain between 1 and 64 characters"
        )));
    }
    Ok(())
}

fn has_attempt_only_filter(query: &UsageQuery) -> bool {
    query.target_id.is_some()
        || query.origin.is_some()
        || query.deployment_id.is_some()
        || query.endpoint_id.is_some()
        || query.credential_id.is_some()
}

fn usage_range(query: &UsageQuery) -> UsageRange {
    UsageRange {
        start: query.start,
        end: query.end,
        granularity: query.granularity,
    }
}

async fn query_logical_usage(
    application: &Application,
    query: &UsageQuery,
) -> Result<Vec<LogicalUsageBucket>, ApplicationError> {
    let rows = sqlx::query(
        "SELECT
             date_trunc($1, bucket_start AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' AS bucket_start,
             SUM(request_count)::text AS request_count,
             SUM(input_units)::text AS input_units,
             SUM(output_units)::text AS output_units,
             SUM(cached_input_units)::text AS cached_input_units,
             SUM(cost_nanos)::text AS known_cost_nanos,
             SUM(unknown_cost_count)::text AS unknown_cost_count,
             SUM(duration_millis)::text AS duration_millis
         FROM logical_usage_hourly
         WHERE bucket_start >= $2 AND bucket_start < $3
           AND ($4::uuid IS NULL OR organization_id=$4)
           AND ($5::text IS NULL OR principal_kind=$5)
           AND ($6::uuid IS NULL OR user_id=$6)
           AND ($7::uuid IS NULL OR gateway_api_key_id=$7)
           AND ($8::uuid IS NULL OR route_id=$8)
           AND ($9::text IS NULL OR outcome_class=$9)
         GROUP BY 1 ORDER BY 1",
    )
    .bind(query.granularity.sql_value())
    .bind(query.start)
    .bind(query.end)
    .bind(query.organization_id)
    .bind(query.principal_kind.as_deref())
    .bind(query.user_id)
    .bind(query.gateway_api_key_id)
    .bind(query.route_id)
    .bind(query.outcome.as_deref())
    .fetch_all(application.store.pool())
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(LogicalUsageBucket {
                bucket_start: row.try_get("bucket_start")?,
                request_count: row.try_get("request_count")?,
                input_units: row.try_get("input_units")?,
                output_units: row.try_get("output_units")?,
                cached_input_units: row.try_get("cached_input_units")?,
                known_cost_nanos: row.try_get("known_cost_nanos")?,
                unknown_cost_count: row.try_get("unknown_cost_count")?,
                duration_millis: row.try_get("duration_millis")?,
            })
        })
        .collect()
}

async fn query_attempt_usage(
    application: &Application,
    query: &UsageQuery,
) -> Result<Vec<AttemptUsageBucket>, ApplicationError> {
    let rows = sqlx::query(
        "SELECT
             date_trunc($1, bucket_start AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' AS bucket_start,
             SUM(attempt_count)::text AS attempt_count,
             SUM(input_units)::text AS input_units,
             SUM(output_units)::text AS output_units,
             SUM(cached_input_units)::text AS cached_input_units,
             SUM(estimated_cost_nanos)::text AS known_estimated_cost_nanos,
             SUM(unknown_estimate_count)::text AS unknown_estimate_count,
             SUM(actual_cost_nanos)::text AS known_actual_cost_nanos,
             SUM(unknown_cost_count)::text AS unknown_cost_count,
             SUM(duration_millis)::text AS duration_millis
         FROM attempt_usage_hourly
         WHERE bucket_start >= $2 AND bucket_start < $3
           AND ($4::uuid IS NULL OR organization_id=$4)
           AND ($5::text IS NULL OR principal_kind=$5)
           AND ($6::uuid IS NULL OR user_id=$6)
           AND ($7::uuid IS NULL OR gateway_api_key_id=$7)
           AND ($8::uuid IS NULL OR route_id=$8)
           AND ($9::uuid IS NULL OR target_id=$9)
           AND ($10::text IS NULL OR origin=$10)
           AND ($11::uuid IS NULL OR deployment_id=$11)
           AND ($12::uuid IS NULL OR endpoint_id=$12)
           AND ($13::uuid IS NULL OR credential_id=$13)
           AND ($14::text IS NULL OR terminal_class=$14)
         GROUP BY 1 ORDER BY 1",
    )
    .bind(query.granularity.sql_value())
    .bind(query.start)
    .bind(query.end)
    .bind(query.organization_id)
    .bind(query.principal_kind.as_deref())
    .bind(query.user_id)
    .bind(query.gateway_api_key_id)
    .bind(query.route_id)
    .bind(query.target_id)
    .bind(query.origin.as_deref())
    .bind(query.deployment_id)
    .bind(query.endpoint_id)
    .bind(query.credential_id)
    .bind(query.outcome.as_deref())
    .fetch_all(application.store.pool())
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(AttemptUsageBucket {
                bucket_start: row.try_get("bucket_start")?,
                attempt_count: row.try_get("attempt_count")?,
                input_units: row.try_get("input_units")?,
                output_units: row.try_get("output_units")?,
                cached_input_units: row.try_get("cached_input_units")?,
                known_estimated_cost_nanos: row.try_get("known_estimated_cost_nanos")?,
                unknown_estimate_count: row.try_get("unknown_estimate_count")?,
                known_actual_cost_nanos: row.try_get("known_actual_cost_nanos")?,
                unknown_cost_count: row.try_get("unknown_cost_count")?,
                duration_millis: row.try_get("duration_millis")?,
            })
        })
        .collect()
}

async fn query_breakdown(
    application: &Application,
    query: &UsageBreakdownQuery,
    limit: u32,
) -> Result<Vec<UsageBreakdownItem>, ApplicationError> {
    let dimension = breakdown_dimension_sql(query.fact_family, query.dimension);
    let (table, measures, count_alias, cost_alias) = match query.fact_family {
        UsageFactFamily::LogicalRequests => (
            "logical_usage_hourly",
            "SUM(request_count)::text AS count,\n             SUM(input_units)::text AS input_units,\n             SUM(output_units)::text AS output_units,\n             SUM(cached_input_units)::text AS cached_input_units,\n             NULL::text AS known_estimated_cost_nanos,\n             NULL::text AS unknown_estimate_count,\n             NULL::text AS known_actual_cost_nanos,\n             SUM(cost_nanos)::text AS known_cost_nanos,\n             SUM(unknown_cost_count)::text AS unknown_cost_count,\n             SUM(duration_millis)::text AS duration_millis",
            "request_count",
            "cost_nanos",
        ),
        UsageFactFamily::Attempts => (
            "attempt_usage_hourly",
            "SUM(attempt_count)::text AS count,\n             SUM(input_units)::text AS input_units,\n             SUM(output_units)::text AS output_units,\n             SUM(cached_input_units)::text AS cached_input_units,\n             SUM(estimated_cost_nanos)::text AS known_estimated_cost_nanos,\n             SUM(unknown_estimate_count)::text AS unknown_estimate_count,\n             SUM(actual_cost_nanos)::text AS known_actual_cost_nanos,\n             NULL::text AS known_cost_nanos,\n             SUM(unknown_cost_count)::text AS unknown_cost_count,\n             SUM(duration_millis)::text AS duration_millis",
            "attempt_count",
            "actual_cost_nanos",
        ),
    };
    let order = match query.order {
        UsageBreakdownOrder::CountDesc => format!("SUM({count_alias}) DESC, dimension_value ASC"),
        UsageBreakdownOrder::CostDesc => format!(
            "SUM({cost_alias}) DESC NULLS LAST, SUM({count_alias}) DESC, dimension_value ASC"
        ),
        UsageBreakdownOrder::DimensionAsc => "dimension_value ASC NULLS LAST".to_owned(),
    };
    let attempt_filters = if query.fact_family == UsageFactFamily::Attempts {
        "AND ($9::uuid IS NULL OR target_id=$9)\n           AND ($10::text IS NULL OR origin=$10)\n           AND ($11::uuid IS NULL OR deployment_id=$11)\n           AND ($12::uuid IS NULL OR endpoint_id=$12)\n           AND ($13::uuid IS NULL OR credential_id=$13)"
    } else {
        "AND $9::uuid IS NULL AND $10::text IS NULL AND $11::uuid IS NULL\n           AND $12::uuid IS NULL AND $13::uuid IS NULL"
    };
    let outcome_column = match query.fact_family {
        UsageFactFamily::LogicalRequests => "outcome_class",
        UsageFactFamily::Attempts => "terminal_class",
    };
    let sql = format!(
        "SELECT ({dimension})::text AS dimension_value,\n             {measures}\n         FROM {table}\n         WHERE bucket_start >= $1 AND bucket_start < $2\n           AND ($3::uuid IS NULL OR organization_id=$3)\n           AND ($4::text IS NULL OR principal_kind=$4)\n           AND ($5::uuid IS NULL OR user_id=$5)\n           AND ($6::uuid IS NULL OR gateway_api_key_id=$6)\n           AND ($7::uuid IS NULL OR route_id=$7)\n           AND ($8::text IS NULL OR {outcome_column}=$8)\n           {attempt_filters}\n         GROUP BY 1 ORDER BY {order} LIMIT $14"
    );
    let rows = sqlx::query(&sql)
        .bind(query.usage.start)
        .bind(query.usage.end)
        .bind(query.usage.organization_id)
        .bind(query.usage.principal_kind.as_deref())
        .bind(query.usage.user_id)
        .bind(query.usage.gateway_api_key_id)
        .bind(query.usage.route_id)
        .bind(query.usage.outcome.as_deref())
        .bind(query.usage.target_id)
        .bind(query.usage.origin.as_deref())
        .bind(query.usage.deployment_id)
        .bind(query.usage.endpoint_id)
        .bind(query.usage.credential_id)
        .bind(i64::from(limit))
        .fetch_all(application.store.pool())
        .await?;
    rows.into_iter()
        .map(|row| {
            Ok(UsageBreakdownItem {
                dimension_value: row.try_get("dimension_value")?,
                measures: UsageBreakdownMeasures {
                    count: row.try_get("count")?,
                    input_units: row.try_get("input_units")?,
                    output_units: row.try_get("output_units")?,
                    cached_input_units: row.try_get("cached_input_units")?,
                    known_estimated_cost_nanos: row.try_get("known_estimated_cost_nanos")?,
                    unknown_estimate_count: row.try_get("unknown_estimate_count")?,
                    known_actual_cost_nanos: row.try_get("known_actual_cost_nanos")?,
                    known_cost_nanos: row.try_get("known_cost_nanos")?,
                    unknown_cost_count: row.try_get("unknown_cost_count")?,
                    duration_millis: row.try_get("duration_millis")?,
                },
            })
        })
        .collect()
}

fn breakdown_dimension_sql(
    family: UsageFactFamily,
    dimension: UsageBreakdownDimension,
) -> &'static str {
    match dimension {
        UsageBreakdownDimension::Organization => "organization_id",
        UsageBreakdownDimension::PrincipalKind => "principal_kind",
        UsageBreakdownDimension::User => "user_id",
        UsageBreakdownDimension::GatewayApiKey => "gateway_api_key_id",
        UsageBreakdownDimension::Route => "route_id",
        UsageBreakdownDimension::Protocol => "ingress_protocol_family",
        UsageBreakdownDimension::Target => "target_id",
        UsageBreakdownDimension::Origin => "origin",
        UsageBreakdownDimension::Deployment => "deployment_id",
        UsageBreakdownDimension::Endpoint => "endpoint_id",
        UsageBreakdownDimension::Credential => "credential_id",
        UsageBreakdownDimension::Outcome => match family {
            UsageFactFamily::LogicalRequests => "outcome_class",
            UsageFactFamily::Attempts => "terminal_class",
        },
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct TargetHealthView {
    pub scope: &'static str,
    pub runtime_revision: i64,
    pub targets: Vec<TargetHealthItem>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TargetHealthItem {
    pub target_id: Uuid,
    pub route_id: Uuid,
    pub deployment_id: Uuid,
    pub endpoint_id: Uuid,
    pub credential_id: Uuid,
    pub origin: String,
    pub transport_kind: String,
    pub deployment_operational: bool,
    pub health_available: bool,
    pub unavailable_reason: Option<&'static str>,
    pub local: Option<LocalTargetHealthView>,
    pub cached_probe: Option<CachedTargetProbeView>,
}

#[derive(Clone, Debug, Serialize)]
pub struct LocalTargetHealthView {
    pub category: crate::adapters::coordinator::TargetHealthCategory,
    pub cooldown_remaining_millis: Option<u64>,
    pub recovery_elapsed_millis: Option<u64>,
    pub health_epoch: Uuid,
}

#[derive(Clone, Debug, Serialize)]
pub struct CachedTargetProbeView {
    pub category: crate::adapters::coordinator::TargetHealthCategory,
    pub runtime_revision: i64,
    pub cooldown_until_unix_ms: Option<u64>,
    pub recovery_started_at_unix_ms: Option<u64>,
    pub observed_at_unix_ms: u64,
    pub latency_millis: u64,
    pub http_status: Option<u16>,
    pub outcome: String,
}

impl Application {
    pub fn operations_target_health(
        &self,
        identity: &RequestIdentity,
    ) -> Result<TargetHealthView, ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Read, ManagementScope::Operations],
            AuthorizationTarget::Operations { write: false },
        )?;
        let generation = self.runtime.capture();
        let observations = self
            .target_probe_observations()
            .into_iter()
            .map(|observation| (observation.summary.target_id, observation))
            .collect::<HashMap<_, _>>();
        let mut routes = generation
            .snapshot
            .catalog
            .routes
            .values()
            .collect::<Vec<_>>();
        routes.sort_by_key(|route| route.id);
        let mut targets = Vec::new();
        for route in routes {
            let mut route_targets = route.targets.iter().collect::<Vec<_>>();
            route_targets.sort_by_key(|target| target.id);
            for target in route_targets {
                let Some(deployment) = generation
                    .snapshot
                    .catalog
                    .deployments
                    .get(&target.deployment_id)
                else {
                    continue;
                };
                let client_key = deployment.client_key();
                let (local, unavailable_reason) = if let Some(client) =
                    generation.credential_clients.clients.get(&client_key)
                {
                    let candidate = crate::gateway::Candidate {
                        target: target.clone(),
                        deployment: deployment.clone(),
                        client_build_fingerprint: *client.build_fingerprint(),
                    };
                    let local = self.target_protection.local_health(&candidate);
                    (
                        Some(LocalTargetHealthView {
                            category: local.category,
                            cooldown_remaining_millis: local
                                .cooldown_remaining
                                .map(duration_millis),
                            recovery_elapsed_millis: local.recovery_elapsed.map(duration_millis),
                            health_epoch: local.health_epoch,
                        }),
                        None,
                    )
                } else {
                    (
                        None,
                        Some(
                            generation
                                .credential_clients
                                .unavailable
                                .get(&client_key)
                                .copied()
                                .unwrap_or("credential_client_unavailable"),
                        ),
                    )
                };
                let cached_probe = observations.get(&target.id.as_uuid()).map(|observation| {
                    CachedTargetProbeView {
                        category: observation.summary.category,
                        runtime_revision: observation.summary.runtime_revision,
                        cooldown_until_unix_ms: observation.summary.cooldown_until_unix_ms,
                        recovery_started_at_unix_ms: observation
                            .summary
                            .recovery_started_at_unix_ms,
                        observed_at_unix_ms: observation.summary.observed_at_unix_ms,
                        latency_millis: observation.latency_millis,
                        http_status: observation.http_status,
                        outcome: observation.outcome.to_owned(),
                    }
                });
                targets.push(TargetHealthItem {
                    target_id: target.id.as_uuid(),
                    route_id: route.id.as_uuid(),
                    deployment_id: deployment.id.as_uuid(),
                    endpoint_id: deployment.endpoint_id.as_uuid(),
                    credential_id: deployment.credential_id.as_uuid(),
                    origin: deployment.origin.as_str().to_owned(),
                    transport_kind: deployment.transport_kind.as_str().to_owned(),
                    deployment_operational: deployment.operational,
                    health_available: local.is_some(),
                    unavailable_reason,
                    local,
                    cached_probe,
                });
            }
        }
        Ok(TargetHealthView {
            scope: "current_process_with_cached_shared_probe_observations",
            runtime_revision: generation.snapshot.revision,
            targets,
        })
    }

    pub async fn operations_usage_pipeline(
        &self,
        identity: &RequestIdentity,
    ) -> Result<UsagePipelineView, ApplicationError> {
        self.authorize(
            identity,
            &[ManagementScope::Read, ManagementScope::Operations],
            AuthorizationTarget::Operations { write: false },
        )?;
        let process = self.usage_status();
        let receipt_rows = sqlx::query(
            "SELECT fact_family, count(*) AS batch_count, COALESCE(sum(fact_count),0)::text AS fact_count,
                    max(flushed_at) AS last_flushed_at
             FROM aggregate_flush_receipts
             WHERE flushed_at >= now() - interval '24 hours'
             GROUP BY fact_family ORDER BY fact_family",
        )
        .fetch_all(self.store.pool())
        .await?;
        let persisted = sqlx::query(
            "SELECT
                (SELECT max(bucket_start) FROM logical_usage_hourly) AS latest_logical_bucket,
                (SELECT max(bucket_start) FROM attempt_usage_hourly) AS latest_attempt_bucket",
        )
        .fetch_one(self.store.pool())
        .await?;
        let receipts = receipt_rows
            .into_iter()
            .map(|row| {
                Ok(UsagePipelineReceiptView {
                    fact_family: row.try_get("fact_family")?,
                    batch_count: row.try_get("batch_count")?,
                    fact_count: row.try_get("fact_count")?,
                    last_flushed_at: row.try_get("last_flushed_at")?,
                })
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()?;
        Ok(UsagePipelineView {
            scope: "current_process_and_recent_persisted_aggregate_receipts",
            receipt_window_hours: 24,
            process: UsagePipelineProcessView {
                active_logical_keys: process.active_logical_keys,
                active_attempt_keys: process.active_attempt_keys,
                pending_batches: process.pending_batches,
                lost_logical_facts: process.lost_logical_facts,
                lost_attempt_facts: process.lost_attempt_facts,
                flush_status: if process.last_flush_error.is_some() {
                    "degraded"
                } else {
                    "ready"
                },
            },
            receipts,
            latest_persisted_logical_bucket: persisted.try_get("latest_logical_bucket")?,
            latest_persisted_attempt_bucket: persisted.try_get("latest_attempt_bucket")?,
            rollups: UsagePipelineRollupView {
                status: "not_implemented",
                note: "Daily aggregate tables exist, but no rollup writer is active.",
            },
            query_completeness: UsageCompleteness::default(),
        })
    }
}

fn duration_millis(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[derive(Clone, Debug, Serialize)]
pub struct UsagePipelineView {
    pub scope: &'static str,
    pub receipt_window_hours: u32,
    pub process: UsagePipelineProcessView,
    pub receipts: Vec<UsagePipelineReceiptView>,
    pub latest_persisted_logical_bucket: Option<DateTime<Utc>>,
    pub latest_persisted_attempt_bucket: Option<DateTime<Utc>>,
    pub rollups: UsagePipelineRollupView,
    pub query_completeness: UsageCompleteness,
}

#[derive(Clone, Debug, Serialize)]
pub struct UsagePipelineProcessView {
    pub active_logical_keys: usize,
    pub active_attempt_keys: usize,
    pub pending_batches: usize,
    pub lost_logical_facts: u64,
    pub lost_attempt_facts: u64,
    pub flush_status: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct UsagePipelineReceiptView {
    pub fact_family: String,
    pub batch_count: i64,
    pub fact_count: String,
    pub last_flushed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct UsagePipelineRollupView {
    pub status: &'static str,
    pub note: &'static str,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query() -> UsageQuery {
        UsageQuery {
            start: "2026-01-01T00:00:00Z".parse().unwrap(),
            end: "2026-01-02T00:00:00Z".parse().unwrap(),
            granularity: UsageGranularity::Hour,
            organization_id: None,
            principal_kind: None,
            user_id: None,
            gateway_api_key_id: None,
            route_id: None,
            target_id: None,
            origin: None,
            deployment_id: None,
            endpoint_id: None,
            credential_id: None,
            outcome: None,
        }
    }

    #[test]
    fn usage_query_requires_a_bounded_forward_range() {
        let mut value = query();
        assert!(validate_usage_query(&value).is_ok());
        value.end = value.start;
        assert!(validate_usage_query(&value).is_err());
        value.end = value.start + Duration::days(367);
        assert!(validate_usage_query(&value).is_err());
        value = query();
        value.start += Duration::minutes(30);
        assert!(validate_usage_query(&value).is_err());
        value = query();
        value.end -= Duration::seconds(1);
        assert!(validate_usage_query(&value).is_err());
    }

    #[test]
    fn organization_usage_conceals_system_credential_identity() {
        let organization_id = OrganizationId::new();
        let mut value = query();
        value.credential_id = Some(Uuid::now_v7());
        assert!(organization_query(organization_id, &value).is_err());
        value.credential_id = None;
        value.organization_id = Some(organization_id.as_uuid());
        assert!(organization_query(organization_id, &value).is_ok());
    }

    #[test]
    fn logical_breakdown_rejects_attempt_only_dimensions_and_filters() {
        let mut value = UsageBreakdownQuery {
            usage: query(),
            fact_family: UsageFactFamily::LogicalRequests,
            dimension: UsageBreakdownDimension::Deployment,
            order: UsageBreakdownOrder::CountDesc,
            limit: Some(20),
        };
        assert!(validate_breakdown_query(&value).is_err());
        value.dimension = UsageBreakdownDimension::Route;
        value.usage.origin = Some("system_provided".to_owned());
        assert!(validate_breakdown_query(&value).is_err());
    }

    #[test]
    fn breakdown_limit_and_typed_filters_are_bounded() {
        let mut value = UsageBreakdownQuery {
            usage: query(),
            fact_family: UsageFactFamily::Attempts,
            dimension: UsageBreakdownDimension::Origin,
            order: UsageBreakdownOrder::CostDesc,
            limit: Some(101),
        };
        assert!(validate_breakdown_query(&value).is_err());
        value.limit = Some(100);
        value.usage.origin = Some("organization_byok".to_owned());
        assert!(validate_breakdown_query(&value).is_ok());
        value.usage.origin = Some("arbitrary".to_owned());
        assert!(validate_breakdown_query(&value).is_err());
    }
}
