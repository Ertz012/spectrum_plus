// TODO(zjn): use IPv6 if available
// TODO(zjn): use portpicker when https://github.com/Dentosal/portpicker-rs/pull/1 merged
use port_check::free_local_port;
use std::{fmt, net::SocketAddr};
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity, ServerTlsConfig};

use crate::Error;

#[derive(Clone)]
pub struct TlsConfig {
    identity: Identity,
    ca_certificate: Certificate,
    domain_name: Option<String>,
}

impl TlsConfig {
    pub fn new(
        identity: Identity,
        ca_certificate: Certificate,
        domain_name: Option<String>,
    ) -> Self {
        Self {
            identity,
            ca_certificate,
            domain_name,
        }
    }

    fn client_config(&self) -> ClientTlsConfig {
        let config = ClientTlsConfig::new()
            .ca_certificate(self.ca_certificate.clone())
            .identity(self.identity.clone());
        match &self.domain_name {
            Some(domain_name) => config.domain_name(domain_name),
            None => config,
        }
    }

    fn server_config(&self) -> ServerTlsConfig {
        ServerTlsConfig::new()
            .identity(self.identity.clone())
            .client_ca_root(self.ca_certificate.clone())
    }
}

impl fmt::Debug for TlsConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TlsConfig { redacted }")
    }
}

pub fn endpoint(address: &str, tls: Option<&TlsConfig>) -> Result<Endpoint, Error> {
    let scheme = if tls.is_some() { "https" } else { "http" };
    let mut endpoint = Endpoint::from_shared(format!("{}://{}", scheme, address))
        .map_err(|error| Error::new(&format!("Invalid service address: {}", error)))?;
    if let Some(tls) = tls {
        endpoint = endpoint
            .tls_config(tls.client_config())
            .map_err(|error| Error::new(&format!("Invalid TLS configuration: {}", error)))?;
    }
    Ok(endpoint)
}

/// Common configuration for a network service.
#[derive(Debug, Clone)]
pub struct Config {
    /// Port on which the service should bind (localhost interface).
    local_port: u16,

    /// Host (and optional port) to publish as the address of this service.
    public_addr: String,

    tls: Option<TlsConfig>,
}

impl Config {
    pub fn new(local_port: u16, public_addr: String, tls: Option<TlsConfig>) -> Self {
        Self {
            local_port,
            public_addr,
            tls,
        }
    }

    pub fn new_localhost(local_port: u16, tls: Option<TlsConfig>) -> Self {
        Self {
            local_port,
            public_addr: format!("localhost:{}", local_port),
            tls,
        }
    }

    pub fn tls_config(&self) -> Option<TlsConfig> {
        self.tls.clone()
    }

    pub fn server_tls_config(&self) -> Option<ServerTlsConfig> {
        self.tls.as_ref().map(TlsConfig::server_config)
    }

    pub fn endpoint(&self) -> Result<Endpoint, Error> {
        endpoint(&self.public_addr, self.tls.as_ref())
    }

    pub fn endpoint_for(&self, address: &str) -> Result<Endpoint, Error> {
        endpoint(address, self.tls.as_ref())
    }

    /// A network configuration useful for running locally.
    pub fn with_free_port_localhost(tls: Option<TlsConfig>) -> Self {
        let local_port = free_local_port().expect("No ports free");
        Self::new_localhost(local_port, tls)
    }

    pub fn with_free_port(public_addr: String, tls: Option<TlsConfig>) -> Self {
        let mut config = Self::with_free_port_localhost(tls);
        config.public_addr = public_addr;
        config
    }

    pub fn set_public_addr(&mut self, public_addr: String) {
        self.public_addr = public_addr;
    }

    pub fn local_socket_addr(&self) -> SocketAddr {
        SocketAddr::new("0.0.0.0".parse().unwrap(), self.local_port)
    }

    pub fn public_addr(&self) -> String {
        self.public_addr.clone()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::services::health::{
        wait_for_health, AllGoodHealthServer, HealthCheckRequest, HealthClient, HealthServer,
    };
    use proptest::prelude::*;
    use tokio::sync::oneshot;
    use tonic::{transport::Server, Request};

    fn test_tls_config() -> TlsConfig {
        TlsConfig::new(
            Identity::from_pem(
                include_bytes!("../data/server.crt"),
                include_bytes!("../data/server.key"),
            ),
            Certificate::from_pem(include_bytes!("../data/ca.crt")),
            Some("spectrum.example.com".to_string()),
        )
    }

    pub fn addrs() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("127.0.0.1:8080".to_string()),
            Just("localhost:8080".to_string()),
        ]
    }

    #[test]
    fn tls_config_debug_is_redacted() {
        assert_eq!(format!("{:?}", test_tls_config()), "TlsConfig { redacted }");
    }

    #[tokio::test]
    async fn mtls_server_rejects_client_without_certificate() {
        let tls = test_tls_config();
        let net = Config::with_free_port_localhost(Some(tls.clone()));
        let (stop_tx, stop_rx) = oneshot::channel();
        let server = Server::builder()
            .tls_config(net.server_tls_config().unwrap())
            .unwrap()
            .add_service(HealthServer::new(AllGoodHealthServer::default()))
            .serve_with_shutdown(net.local_socket_addr(), async {
                let _ = stop_rx.await;
            });
        let server_task = tokio::spawn(server);
        wait_for_health(net.public_addr(), Some(tls.clone()))
            .await
            .unwrap();

        let endpoint = Endpoint::from_shared(format!("https://{}", net.public_addr()))
            .unwrap()
            .tls_config(
                ClientTlsConfig::new()
                    .domain_name("spectrum.example.com")
                    .ca_certificate(tls.ca_certificate.clone()),
            )
            .unwrap();
        let rejected = match endpoint.connect().await {
            Err(_) => true,
            Ok(channel) => HealthClient::new(channel)
                .check(Request::new(HealthCheckRequest {
                    service: String::new(),
                }))
                .await
                .is_err(),
        };

        let _ = stop_tx.send(());
        server_task.await.unwrap().unwrap();
        assert!(
            rejected,
            "mTLS server accepted a client without a certificate"
        );
    }
}
