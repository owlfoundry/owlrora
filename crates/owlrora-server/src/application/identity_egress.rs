use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
    sync::LazyLock,
    time::Duration,
};

use ipnet::IpNet;
use url::{Host, Url};

use super::{Application, ApplicationError};

const MAX_RESOLVED_ADDRESSES: usize = 16;

static DENIED_NETWORKS: LazyLock<Vec<IpNet>> = LazyLock::new(|| {
    [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "::ffff:0:0/96",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "100::/64",
        "2001::/32",
        "2001:2::/48",
        "2001:10::/28",
        "2001:db8::/32",
        "2002::/16",
        "3ffe::/16",
        "fc00::/7",
        "fec0::/10",
        "fe80::/10",
        "ff00::/8",
    ]
    .into_iter()
    .map(|network| network.parse().expect("static network is valid"))
    .collect()
});

impl Application {
    pub(crate) async fn identity_http_client(
        &self,
        endpoint: &Url,
    ) -> Result<reqwest::Client, ApplicationError> {
        let (host, addresses) = resolve_identity_endpoint(endpoint).await?;
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .no_proxy()
            .resolve_to_addrs(&host, &addresses)
            .build()
            .map_err(|_| ApplicationError::Internal)
    }

    pub(crate) async fn validate_identity_endpoint_resolution(
        &self,
        endpoint: &Url,
    ) -> Result<(), ApplicationError> {
        resolve_identity_endpoint(endpoint).await.map(|_| ())
    }
}

async fn resolve_identity_endpoint(
    endpoint: &Url,
) -> Result<(String, Vec<SocketAddr>), ApplicationError> {
    validate_identity_endpoint(endpoint)?;
    let host = endpoint
        .host_str()
        .ok_or_else(|| ApplicationError::Validation("identity endpoint needs a host".to_owned()))?
        .to_ascii_lowercase();
    let addresses = tokio::net::lookup_host((host.as_str(), 443))
        .await
        .map_err(|_| ApplicationError::DependencyUnavailable)?
        .collect::<BTreeSet<_>>();
    if addresses.is_empty() || addresses.len() > MAX_RESOLVED_ADDRESSES {
        return Err(ApplicationError::DependencyUnavailable);
    }
    if addresses
        .iter()
        .any(|address| !is_public_address(address.ip()))
    {
        return Err(ApplicationError::Validation(
            "identity endpoint resolves to a prohibited network".to_owned(),
        ));
    }
    Ok((host, addresses.into_iter().collect()))
}

fn validate_identity_endpoint(endpoint: &Url) -> Result<(), ApplicationError> {
    if endpoint.scheme() != "https"
        || endpoint.port_or_known_default() != Some(443)
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(ApplicationError::Validation(
            "identity endpoints must use HTTPS on port 443 without userinfo or fragments"
                .to_owned(),
        ));
    }
    match endpoint.host() {
        Some(Host::Domain(host)) => {
            if host.is_empty()
                || host.ends_with('.')
                || host.eq_ignore_ascii_case("localhost")
                || host.to_ascii_lowercase().ends_with(".localhost")
            {
                return Err(ApplicationError::Validation(
                    "identity endpoint host is prohibited".to_owned(),
                ));
            }
        }
        Some(Host::Ipv4(address)) if !is_public_address(IpAddr::V4(address)) => {
            return Err(ApplicationError::Validation(
                "identity endpoint address is prohibited".to_owned(),
            ));
        }
        Some(Host::Ipv6(address)) if !is_public_address(IpAddr::V6(address)) => {
            return Err(ApplicationError::Validation(
                "identity endpoint address is prohibited".to_owned(),
            ));
        }
        Some(_) => {}
        None => {
            return Err(ApplicationError::Validation(
                "identity endpoint needs a host".to_owned(),
            ));
        }
    }
    Ok(())
}

pub(super) async fn read_bounded_response(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, ApplicationError> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(ApplicationError::DependencyUnavailable);
    }
    let mut body = Vec::with_capacity(
        response
            .content_length()
            .and_then(|length| usize::try_from(length).ok())
            .unwrap_or(0)
            .min(limit),
    );
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| ApplicationError::DependencyUnavailable)?
    {
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(ApplicationError::DependencyUnavailable);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn is_public_address(address: IpAddr) -> bool {
    !DENIED_NETWORKS
        .iter()
        .any(|network| network.contains(&address))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_policy_rejects_local_networks_and_nonstandard_ports() {
        assert!(
            validate_identity_endpoint(&Url::parse("https://127.0.0.1/jwks").unwrap()).is_err()
        );
        assert!(validate_identity_endpoint(&Url::parse("https://[::1]/jwks").unwrap()).is_err());
        assert!(
            validate_identity_endpoint(&Url::parse("https://localhost/jwks").unwrap()).is_err()
        );
        assert!(
            validate_identity_endpoint(&Url::parse("https://example.com:8443/jwks").unwrap())
                .is_err()
        );
        assert!(
            validate_identity_endpoint(&Url::parse("https://example.com/jwks").unwrap()).is_ok()
        );
    }
}
