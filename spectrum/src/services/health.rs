use crate::{
    config::store::Error,
    net::{self, TlsConfig},
};
use log::debug;
use std::time::Duration;
use tokio::time::sleep;
use tonic::{Request, Response, Status};

pub mod spectrum {
    tonic::include_proto!("grpc.health.v1");
}

pub use spectrum::{
    health_check_response::ServingStatus,
    health_client::HealthClient,
    health_server::{Health, HealthServer},
    HealthCheckRequest, HealthCheckResponse,
};

const RETRY_DELAY: Duration = Duration::from_millis(50);
const RETRY_ATTEMPTS: usize = 10;

#[derive(Default)]
pub struct AllGoodHealthServer {}

#[tonic::async_trait]
impl Health for AllGoodHealthServer {
    async fn check(
        &self,
        _request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        let reply = HealthCheckResponse {
            status: ServingStatus::Serving as i32,
        };
        Ok(Response::new(reply))
    }
}

async fn is_healthy(addr: &str, tls: Option<&TlsConfig>) -> Result<bool, Error> {
    if tls.is_some() {
        debug!("mTLS for health client.");
    }
    let channel = net::endpoint(addr, tls)
        .map_err(|error| error.to_string())?
        .connect()
        .await
        .map_err(|error| error.to_string())?;
    let mut client = HealthClient::new(channel);
    let req = Request::new(HealthCheckRequest {
        service: "".to_string(),
    });
    let response = client.check(req).await.map_err(|err| err.to_string())?;
    Ok(response.into_inner().status == ServingStatus::Serving as i32)
}

pub async fn wait_for_health_helper(
    addr: String,
    delay: Duration,
    attempts: usize,
    tls: Option<TlsConfig>,
) -> Result<(), Error> {
    let mut last_error = None;
    for _ in 0..attempts {
        match is_healthy(&addr, tls.as_ref()).await {
            Ok(response) => {
                if response {
                    return Ok(());
                }
            }
            Err(err) => {
                debug!("Error checking health: {}", err);
                last_error = Some(err.to_string());
            }
        }
        sleep(delay).await;
    }
    let cause = last_error.unwrap_or_else(|| "service reported a non-serving status".to_string());
    Err(Error::new(&format!(
        "Service at {} not healthy after {} attempts: {}",
        addr, attempts, cause
    )))
}

pub async fn wait_for_health(addr: String, tls: Option<TlsConfig>) -> Result<(), Error> {
    wait_for_health_helper(addr, RETRY_DELAY, RETRY_ATTEMPTS, tls).await
}
