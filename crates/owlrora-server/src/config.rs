use std::{collections::BTreeMap, env, net::SocketAddr, sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ipnet::IpNet;
use thiserror::Error;
use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::domain::{ManagementKeyMaterial, seed_admin_key_version_id};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeploymentProfile {
    Full,
    Management,
    Gateway,
    Worker,
    HealthOnly,
}

impl DeploymentProfile {
    #[must_use]
    pub const fn management_enabled(self) -> bool {
        matches!(self, Self::Full | Self::Management)
    }

    #[must_use]
    pub const fn gateway_enabled(self) -> bool {
        matches!(self, Self::Full | Self::Gateway)
    }

    #[must_use]
    pub const fn management_workers_enabled(self) -> bool {
        matches!(self, Self::Full | Self::Management | Self::Worker)
    }

    #[must_use]
    pub const fn gateway_workers_enabled(self) -> bool {
        matches!(self, Self::Full | Self::Gateway | Self::Worker)
    }
}

#[derive(Clone)]
pub struct ServerConfig {
    pub address: SocketAddr,
    pub profile: DeploymentProfile,
    pub database_url: Option<String>,
    pub public_origin: Option<Url>,
    pub seed_admin_key_version_id: Option<[u8; 32]>,
    pub secret_root: Option<Arc<SecretRoot>>,
    pub redis_url: Option<Url>,
    pub operator_networks: Vec<IpNet>,
    pub database_max_connections: u32,
    pub redis_pool_size: u32,
    pub redis_connect_timeout: Duration,
    pub redis_command_timeout: Duration,
    pub policy_activation_timeout: Duration,
    pub policy_retirement_grace: Duration,
    pub session_lifetime: Duration,
    pub max_security_snapshot_age: Duration,
    pub usage_flush_interval: Duration,
    pub usage_max_aggregate_keys: usize,
    pub usage_max_pending_batches: usize,
    pub gateway_max_in_flight: usize,
    pub gateway_endpoint_max_in_flight: usize,
    pub gateway_credential_max_in_flight: usize,
    pub gateway_deployment_max_in_flight: usize,
    pub gateway_websocket_max_connections: usize,
    pub gemini_query_key_compatibility: bool,
}

impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServerConfig")
            .field("address", &self.address)
            .field("profile", &self.profile)
            .field(
                "database_url",
                &self.database_url.as_ref().map(|_| "[REDACTED]"),
            )
            .field("public_origin", &self.public_origin)
            .field(
                "seed_admin_key_version_id",
                &self.seed_admin_key_version_id.map(|_| "[REDACTED]"),
            )
            .field("secret_root", &self.secret_root)
            .field("redis_url", &self.redis_url.as_ref().map(|_| "[REDACTED]"))
            .field("operator_networks", &self.operator_networks)
            .field("database_max_connections", &self.database_max_connections)
            .field("redis_pool_size", &self.redis_pool_size)
            .field("redis_connect_timeout", &self.redis_connect_timeout)
            .field("redis_command_timeout", &self.redis_command_timeout)
            .field("policy_activation_timeout", &self.policy_activation_timeout)
            .field("policy_retirement_grace", &self.policy_retirement_grace)
            .field("session_lifetime", &self.session_lifetime)
            .field("max_security_snapshot_age", &self.max_security_snapshot_age)
            .field("usage_flush_interval", &self.usage_flush_interval)
            .field("usage_max_aggregate_keys", &self.usage_max_aggregate_keys)
            .field("usage_max_pending_batches", &self.usage_max_pending_batches)
            .field("gateway_max_in_flight", &self.gateway_max_in_flight)
            .field(
                "gateway_endpoint_max_in_flight",
                &self.gateway_endpoint_max_in_flight,
            )
            .field(
                "gateway_credential_max_in_flight",
                &self.gateway_credential_max_in_flight,
            )
            .field(
                "gateway_deployment_max_in_flight",
                &self.gateway_deployment_max_in_flight,
            )
            .field(
                "gateway_websocket_max_connections",
                &self.gateway_websocket_max_connections,
            )
            .field(
                "gemini_query_key_compatibility",
                &self.gemini_query_key_compatibility,
            )
            .finish()
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretRoot([u8; 32]);

impl SecretRoot {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for SecretRoot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SecretRoot([REDACTED])")
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("unknown OwlRora configuration key: {0}")]
    UnknownKey(String),
    #[error("missing required configuration: {0}")]
    Missing(&'static str),
    #[error("invalid configuration for {key}: {message}")]
    Invalid { key: &'static str, message: String },
}

impl ServerConfig {
    pub fn from_environment() -> Result<Self, ConfigError> {
        let values = env::vars()
            .filter(|(key, _)| key.starts_with("OWLRORA_"))
            .collect::<BTreeMap<_, _>>();
        Self::from_values(&values)
    }

    pub fn from_values(values: &BTreeMap<String, String>) -> Result<Self, ConfigError> {
        const KNOWN: &[&str] = &[
            "OWLRORA_ADDR",
            "OWLRORA_PROFILE",
            "OWLRORA_DATABASE_URL",
            "OWLRORA_PUBLIC_ORIGIN",
            "OWLRORA_SEED_ADMIN_API_KEY",
            "OWLRORA_SECRET_ROOT",
            "OWLRORA_REDIS_URL",
            "OWLRORA_OPERATOR_NETWORKS",
            "OWLRORA_DATABASE_MAX_CONNECTIONS",
            "OWLRORA_REDIS_POOL_SIZE",
            "OWLRORA_REDIS_CONNECT_TIMEOUT_MILLIS",
            "OWLRORA_REDIS_COMMAND_TIMEOUT_MILLIS",
            "OWLRORA_POLICY_ACTIVATION_TIMEOUT_SECONDS",
            "OWLRORA_POLICY_RETIREMENT_GRACE_SECONDS",
            "OWLRORA_SESSION_LIFETIME_SECONDS",
            "OWLRORA_MAX_SECURITY_SNAPSHOT_AGE_SECONDS",
            "OWLRORA_USAGE_FLUSH_INTERVAL_SECONDS",
            "OWLRORA_USAGE_MAX_AGGREGATE_KEYS",
            "OWLRORA_USAGE_MAX_PENDING_BATCHES",
            "OWLRORA_GATEWAY_MAX_IN_FLIGHT",
            "OWLRORA_GATEWAY_ENDPOINT_MAX_IN_FLIGHT",
            "OWLRORA_GATEWAY_CREDENTIAL_MAX_IN_FLIGHT",
            "OWLRORA_GATEWAY_DEPLOYMENT_MAX_IN_FLIGHT",
            "OWLRORA_GATEWAY_WEBSOCKET_MAX_CONNECTIONS",
            "OWLRORA_GEMINI_QUERY_KEY_COMPATIBILITY",
        ];
        if let Some(key) = values.keys().find(|key| !KNOWN.contains(&key.as_str())) {
            return Err(ConfigError::UnknownKey(key.clone()));
        }

        let address = parse_or(values, "OWLRORA_ADDR", "127.0.0.1:8080")?;
        let profile = match optional(values, "OWLRORA_PROFILE").unwrap_or("full") {
            "full" => DeploymentProfile::Full,
            "management" => DeploymentProfile::Management,
            "gateway" => DeploymentProfile::Gateway,
            "worker" => DeploymentProfile::Worker,
            "health-only" => DeploymentProfile::HealthOnly,
            value => {
                return Err(invalid(
                    "OWLRORA_PROFILE",
                    format!("unknown profile {value}"),
                ));
            }
        };
        let database_max_connections = parse_or(values, "OWLRORA_DATABASE_MAX_CONNECTIONS", "16")?;
        if !(2..=128).contains(&database_max_connections) {
            return Err(invalid(
                "OWLRORA_DATABASE_MAX_CONNECTIONS",
                "must be between 2 and 128".to_owned(),
            ));
        }
        let redis_pool_size = parse_or(values, "OWLRORA_REDIS_POOL_SIZE", "8")?;
        if !(1..=128).contains(&redis_pool_size) {
            return Err(invalid(
                "OWLRORA_REDIS_POOL_SIZE",
                "must be between 1 and 128".to_owned(),
            ));
        }
        let redis_connect_timeout = duration_millis(
            values,
            "OWLRORA_REDIS_CONNECT_TIMEOUT_MILLIS",
            500,
            50..=30_000,
        )?;
        let redis_command_timeout = duration_millis(
            values,
            "OWLRORA_REDIS_COMMAND_TIMEOUT_MILLIS",
            250,
            10..=10_000,
        )?;
        let policy_activation_timeout = duration(
            values,
            "OWLRORA_POLICY_ACTIVATION_TIMEOUT_SECONDS",
            30,
            5..=600,
        )?;
        let policy_retirement_grace = duration(
            values,
            "OWLRORA_POLICY_RETIREMENT_GRACE_SECONDS",
            60,
            5..=3600,
        )?;
        let session_lifetime = duration(
            values,
            "OWLRORA_SESSION_LIFETIME_SECONDS",
            8 * 60 * 60,
            300..=7 * 24 * 60 * 60,
        )?;
        let max_security_snapshot_age = duration(
            values,
            "OWLRORA_MAX_SECURITY_SNAPSHOT_AGE_SECONDS",
            30,
            5..=300,
        )?;
        let usage_flush_interval =
            duration(values, "OWLRORA_USAGE_FLUSH_INTERVAL_SECONDS", 5, 1..=300)?;
        let usage_max_aggregate_keys =
            parse_or(values, "OWLRORA_USAGE_MAX_AGGREGATE_KEYS", "4096")?;
        if !(128..=1_000_000).contains(&usage_max_aggregate_keys) {
            return Err(invalid(
                "OWLRORA_USAGE_MAX_AGGREGATE_KEYS",
                "must be between 128 and 1000000".to_owned(),
            ));
        }
        let usage_max_pending_batches =
            parse_or(values, "OWLRORA_USAGE_MAX_PENDING_BATCHES", "16")?;
        if !(1..=1024).contains(&usage_max_pending_batches) {
            return Err(invalid(
                "OWLRORA_USAGE_MAX_PENDING_BATCHES",
                "must be between 1 and 1024".to_owned(),
            ));
        }
        let gateway_max_in_flight =
            bounded_gateway_capacity(values, "OWLRORA_GATEWAY_MAX_IN_FLIGHT", "4096")?;
        let gateway_endpoint_max_in_flight =
            bounded_gateway_capacity(values, "OWLRORA_GATEWAY_ENDPOINT_MAX_IN_FLIGHT", "512")?;
        let gateway_credential_max_in_flight =
            bounded_gateway_capacity(values, "OWLRORA_GATEWAY_CREDENTIAL_MAX_IN_FLIGHT", "512")?;
        let gateway_deployment_max_in_flight =
            bounded_gateway_capacity(values, "OWLRORA_GATEWAY_DEPLOYMENT_MAX_IN_FLIGHT", "256")?;
        let gateway_websocket_max_connections =
            parse_or(values, "OWLRORA_GATEWAY_WEBSOCKET_MAX_CONNECTIONS", "1024")?;
        let gemini_query_key_compatibility =
            parse_or(values, "OWLRORA_GEMINI_QUERY_KEY_COMPATIBILITY", "false")?;
        if !(1..=1_000_000).contains(&gateway_websocket_max_connections) {
            return Err(invalid(
                "OWLRORA_GATEWAY_WEBSOCKET_MAX_CONNECTIONS",
                "must be between 1 and 1000000".to_owned(),
            ));
        }
        let operator_networks = optional(values, "OWLRORA_OPERATOR_NETWORKS")
            .unwrap_or("127.0.0.0/8,::1/128")
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| {
                value
                    .parse::<IpNet>()
                    .map_err(|error| invalid("OWLRORA_OPERATOR_NETWORKS", error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if operator_networks.is_empty() {
            return Err(invalid(
                "OWLRORA_OPERATOR_NETWORKS",
                "at least one network is required".to_owned(),
            ));
        }

        let mut config = Self {
            address,
            profile,
            database_url: None,
            public_origin: None,
            seed_admin_key_version_id: None,
            secret_root: None,
            redis_url: None,
            operator_networks,
            database_max_connections,
            redis_pool_size,
            redis_connect_timeout,
            redis_command_timeout,
            policy_activation_timeout,
            policy_retirement_grace,
            session_lifetime,
            max_security_snapshot_age,
            usage_flush_interval,
            usage_max_aggregate_keys,
            usage_max_pending_batches,
            gateway_max_in_flight,
            gateway_endpoint_max_in_flight,
            gateway_credential_max_in_flight,
            gateway_deployment_max_in_flight,
            gateway_websocket_max_connections,
            gemini_query_key_compatibility,
        };
        if profile == DeploymentProfile::HealthOnly {
            return Ok(config);
        }

        config.database_url = Some(required(values, "OWLRORA_DATABASE_URL")?.to_owned());
        let redis_url = required(values, "OWLRORA_REDIS_URL")?
            .parse::<Url>()
            .map_err(|error| invalid("OWLRORA_REDIS_URL", error.to_string()))?;
        validate_redis_url(&redis_url)?;
        config.redis_url = Some(redis_url);

        if profile.management_enabled() {
            let public_origin = required(values, "OWLRORA_PUBLIC_ORIGIN")?
                .parse::<Url>()
                .map_err(|error| invalid("OWLRORA_PUBLIC_ORIGIN", error.to_string()))?;
            validate_public_origin(&public_origin)?;
            config.public_origin = Some(public_origin);

            let seed_key =
                ManagementKeyMaterial::parse(required(values, "OWLRORA_SEED_ADMIN_API_KEY")?)
                    .map_err(|error| invalid("OWLRORA_SEED_ADMIN_API_KEY", error.to_string()))?;
            config.seed_admin_key_version_id = Some(seed_admin_key_version_id(&seed_key));
        }

        let Some(encoded_root) = optional(values, "OWLRORA_SECRET_ROOT") else {
            return Ok(config);
        };
        if encoded_root.contains('=') {
            return Err(invalid(
                "OWLRORA_SECRET_ROOT",
                "must use canonical base64url without padding".to_owned(),
            ));
        }
        let root = URL_SAFE_NO_PAD
            .decode(encoded_root)
            .map_err(|error| invalid("OWLRORA_SECRET_ROOT", error.to_string()))?;
        if root.len() != 32 || URL_SAFE_NO_PAD.encode(&root) != encoded_root {
            return Err(invalid(
                "OWLRORA_SECRET_ROOT",
                "must canonically encode exactly 32 bytes".to_owned(),
            ));
        }
        let root: [u8; 32] = root.try_into().map_err(|_| {
            invalid(
                "OWLRORA_SECRET_ROOT",
                "must decode to exactly 32 bytes".to_owned(),
            )
        })?;
        config.secret_root = Some(Arc::new(SecretRoot(root)));
        Ok(config)
    }
}

fn optional<'a>(values: &'a BTreeMap<String, String>, key: &str) -> Option<&'a str> {
    values
        .get(key)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
}

fn required<'a>(
    values: &'a BTreeMap<String, String>,
    key: &'static str,
) -> Result<&'a str, ConfigError> {
    optional(values, key).ok_or(ConfigError::Missing(key))
}

fn parse_or<T>(
    values: &BTreeMap<String, String>,
    key: &'static str,
    default: &str,
) -> Result<T, ConfigError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    optional(values, key)
        .unwrap_or(default)
        .parse()
        .map_err(|error: T::Err| invalid(key, error.to_string()))
}

fn bounded_gateway_capacity(
    values: &BTreeMap<String, String>,
    key: &'static str,
    default: &str,
) -> Result<usize, ConfigError> {
    let value = parse_or(values, key, default)?;
    if !(1..=1_000_000).contains(&value) {
        return Err(invalid(key, "must be between 1 and 1000000".to_owned()));
    }
    Ok(value)
}

fn duration(
    values: &BTreeMap<String, String>,
    key: &'static str,
    default: u64,
    range: std::ops::RangeInclusive<u64>,
) -> Result<Duration, ConfigError> {
    let seconds = parse_or(values, key, &default.to_string())?;
    if !range.contains(&seconds) {
        return Err(invalid(key, format!("must be within {range:?} seconds")));
    }
    Ok(Duration::from_secs(seconds))
}

fn duration_millis(
    values: &BTreeMap<String, String>,
    key: &'static str,
    default: u64,
    range: std::ops::RangeInclusive<u64>,
) -> Result<Duration, ConfigError> {
    let millis = parse_or(values, key, &default.to_string())?;
    if !range.contains(&millis) {
        return Err(invalid(
            key,
            format!("must be within {range:?} milliseconds"),
        ));
    }
    Ok(Duration::from_millis(millis))
}

fn invalid(key: &'static str, message: String) -> ConfigError {
    ConfigError::Invalid { key, message }
}

fn validate_redis_url(url: &Url) -> Result<(), ConfigError> {
    if !matches!(url.scheme(), "redis" | "rediss")
        || url.host_str().is_none()
        || url.fragment().is_some()
        || url.query().is_some()
    {
        return Err(invalid(
            "OWLRORA_REDIS_URL",
            "must be a redis:// or rediss:// URL without query or fragment".to_owned(),
        ));
    }
    Ok(())
}

fn validate_public_origin(origin: &Url) -> Result<(), ConfigError> {
    if origin.cannot_be_a_base()
        || origin.host_str().is_none()
        || origin.username() != ""
        || origin.password().is_some()
        || origin.query().is_some()
        || origin.fragment().is_some()
        || origin.path() != "/"
    {
        return Err(invalid(
            "OWLRORA_PUBLIC_ORIGIN",
            "must be an origin without credentials, path, query, or fragment".to_owned(),
        ));
    }
    let loopback = origin.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if origin.scheme() != "https" && !(origin.scheme() == "http" && loopback) {
        return Err(invalid(
            "OWLRORA_PUBLIC_ORIGIN",
            "must use HTTPS except for an explicit loopback development origin".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::generate_management_key;

    fn valid_values() -> BTreeMap<String, String> {
        BTreeMap::from([
            (
                "OWLRORA_DATABASE_URL".to_owned(),
                "postgres://localhost/owlrora".to_owned(),
            ),
            (
                "OWLRORA_PUBLIC_ORIGIN".to_owned(),
                "http://127.0.0.1:8080".to_owned(),
            ),
            (
                "OWLRORA_SEED_ADMIN_API_KEY".to_owned(),
                generate_management_key().expose_once(),
            ),
            (
                "OWLRORA_SECRET_ROOT".to_owned(),
                URL_SAFE_NO_PAD.encode([7_u8; 32]),
            ),
            (
                "OWLRORA_REDIS_URL".to_owned(),
                "redis://127.0.0.1:6379/0".to_owned(),
            ),
        ])
    }

    #[test]
    fn full_profile_requires_management_security_root() {
        let mut values = valid_values();
        values.remove("OWLRORA_SEED_ADMIN_API_KEY");
        assert!(matches!(
            ServerConfig::from_values(&values),
            Err(ConfigError::Missing("OWLRORA_SEED_ADMIN_API_KEY"))
        ));
    }

    #[test]
    fn health_only_profile_has_no_management_authentication_surface() {
        let values = BTreeMap::from([("OWLRORA_PROFILE".to_owned(), "health-only".to_owned())]);
        let config = ServerConfig::from_values(&values).unwrap();
        assert_eq!(config.profile, DeploymentProfile::HealthOnly);
        assert!(config.seed_admin_key_version_id.is_none());
    }

    #[test]
    fn gateway_profile_requires_coordination_but_not_management_secrets() {
        let mut values = valid_values();
        values.insert("OWLRORA_PROFILE".to_owned(), "gateway".to_owned());
        values.remove("OWLRORA_PUBLIC_ORIGIN");
        values.remove("OWLRORA_SEED_ADMIN_API_KEY");
        let config = ServerConfig::from_values(&values).unwrap();
        assert_eq!(config.profile, DeploymentProfile::Gateway);
        assert!(config.public_origin.is_none());
        assert!(config.seed_admin_key_version_id.is_none());
        assert!(config.redis_url.is_some());
    }

    #[test]
    fn non_health_profiles_require_redis_coordination() {
        let mut values = valid_values();
        values.remove("OWLRORA_REDIS_URL");
        assert!(matches!(
            ServerConfig::from_values(&values),
            Err(ConfigError::Missing("OWLRORA_REDIS_URL"))
        ));
    }

    #[test]
    fn unknown_keys_and_noncanonical_roots_fail_closed() {
        let mut values = valid_values();
        values.insert("OWLRORA_UNKNOWN".to_owned(), "value".to_owned());
        assert!(matches!(
            ServerConfig::from_values(&values),
            Err(ConfigError::UnknownKey(_))
        ));

        let mut values = valid_values();
        values.insert(
            "OWLRORA_NODE_INSTANCE_ID".to_owned(),
            "obsolete-replica-identity".to_owned(),
        );
        assert!(matches!(
            ServerConfig::from_values(&values),
            Err(ConfigError::UnknownKey(key)) if key == "OWLRORA_NODE_INSTANCE_ID"
        ));

        let mut values = valid_values();
        values.insert("OWLRORA_SECRET_ROOT".to_owned(), "AA==".to_owned());
        assert!(ServerConfig::from_values(&values).is_err());
    }

    #[test]
    fn non_loopback_origins_require_https() {
        let mut values = valid_values();
        values.insert(
            "OWLRORA_PUBLIC_ORIGIN".to_owned(),
            "http://example.com".to_owned(),
        );
        assert!(ServerConfig::from_values(&values).is_err());
    }
}
