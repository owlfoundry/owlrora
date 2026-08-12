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
    HealthOnly,
}

#[derive(Clone)]
pub struct ServerConfig {
    pub address: SocketAddr,
    pub profile: DeploymentProfile,
    pub database_url: Option<String>,
    pub public_origin: Option<Url>,
    pub seed_admin_key_version_id: Option<[u8; 32]>,
    pub secret_root: Option<Arc<SecretRoot>>,
    pub operator_networks: Vec<IpNet>,
    pub database_max_connections: u32,
    pub session_lifetime: Duration,
    pub max_security_snapshot_age: Duration,
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
            .field("operator_networks", &self.operator_networks)
            .field("database_max_connections", &self.database_max_connections)
            .field("session_lifetime", &self.session_lifetime)
            .field("max_security_snapshot_age", &self.max_security_snapshot_age)
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
            "OWLRORA_OPERATOR_NETWORKS",
            "OWLRORA_DATABASE_MAX_CONNECTIONS",
            "OWLRORA_SESSION_LIFETIME_SECONDS",
            "OWLRORA_MAX_SECURITY_SNAPSHOT_AGE_SECONDS",
        ];
        if let Some(key) = values.keys().find(|key| !KNOWN.contains(&key.as_str())) {
            return Err(ConfigError::UnknownKey(key.clone()));
        }

        let address = parse_or(values, "OWLRORA_ADDR", "127.0.0.1:8080")?;
        let profile = match optional(values, "OWLRORA_PROFILE").unwrap_or("full") {
            "full" => DeploymentProfile::Full,
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
            operator_networks,
            database_max_connections,
            session_lifetime,
            max_security_snapshot_age,
        };
        if profile == DeploymentProfile::HealthOnly {
            return Ok(config);
        }

        config.database_url = Some(required(values, "OWLRORA_DATABASE_URL")?.to_owned());
        let public_origin = required(values, "OWLRORA_PUBLIC_ORIGIN")?
            .parse::<Url>()
            .map_err(|error| invalid("OWLRORA_PUBLIC_ORIGIN", error.to_string()))?;
        validate_public_origin(&public_origin)?;
        config.public_origin = Some(public_origin);

        let seed_key =
            ManagementKeyMaterial::parse(required(values, "OWLRORA_SEED_ADMIN_API_KEY")?)
                .map_err(|error| invalid("OWLRORA_SEED_ADMIN_API_KEY", error.to_string()))?;
        config.seed_admin_key_version_id = Some(seed_admin_key_version_id(&seed_key));

        let encoded_root = required(values, "OWLRORA_SECRET_ROOT")?;
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

fn invalid(key: &'static str, message: String) -> ConfigError {
    ConfigError::Invalid { key, message }
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
        ])
    }

    #[test]
    fn full_profile_requires_every_security_root() {
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
    fn unknown_keys_and_noncanonical_roots_fail_closed() {
        let mut values = valid_values();
        values.insert("OWLRORA_UNKNOWN".to_owned(), "value".to_owned());
        assert!(matches!(
            ServerConfig::from_values(&values),
            Err(ConfigError::UnknownKey(_))
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
