use crate::proto::{
    expect_field,
    publisher_server::{Publisher, PublisherServer},
    validate_round, AggregateGroupRequest, AggregateGroupResponse, Share,
};
use crate::{
    accumulator::Accumulator,
    config::store::Store,
    experiment,
    net::Config as NetConfig,
    protocols::{wrapper::ProtocolWrapper, Protocol},
    services::{
        discovery::{register, Node},
        health::{wait_for_health, AllGoodHealthServer, HealthServer},
        quorum::{delay_until, set_start_time, wait_for_quorum},
        PublisherInfo,
    },
};

use chrono::prelude::*;
use futures::prelude::*;
use log::{debug, error, info, trace};
use spectrum_primitives::Bytes;
use std::{collections::HashSet, convert::TryInto, fmt::Debug, sync::Arc};
use tokio::{spawn, sync::Mutex};
use tonic::{Request, Response, Status};

const LEGACY_WINDOW: u64 = 1;
const LEGACY_ROUND: u32 = 1;

#[tonic::async_trait]
pub trait Remote: Sync + Send + Clone {
    async fn start(&self);
    async fn done(&self);
}

#[derive(Clone)]
pub struct NoopRemote;

#[tonic::async_trait]
impl Remote for NoopRemote {
    async fn start(&self) {}
    async fn done(&self) {}
}

fn record_group(
    received_groups: &mut HashSet<usize>,
    group: usize,
    total_groups: usize,
) -> Result<(), Status> {
    if group >= total_groups {
        return Err(Status::invalid_argument(format!(
            "Invalid group ID: got {}, expected a value below {}",
            group, total_groups
        )));
    }

    if !received_groups.insert(group) {
        return Err(Status::already_exists(format!(
            "Aggregate from group {} was already received",
            group
        )));
    }

    Ok(())
}

pub struct MyPublisher<R, P>
where
    R: Remote,
    P: Protocol,
{
    accumulator: Arc<Accumulator<Vec<P::Accumulator>>>,
    received_groups: Mutex<HashSet<usize>>,
    expected_window: u64,
    expected_round: u32,
    total_groups: usize,
    remote: R,
}

impl<R, P> MyPublisher<R, P>
where
    R: Remote,
    P: Protocol,
    P::Accumulator: Clone,
{
    fn from_protocol(protocol: P, expected_window: u64, expected_round: u32, remote: R) -> Self {
        let total_groups = protocol.num_parties();

        MyPublisher {
            accumulator: Arc::new(Accumulator::new(protocol.new_accumulator())),
            received_groups: Mutex::new(HashSet::with_capacity(total_groups)),
            expected_window,
            expected_round,
            total_groups,
            remote,
        }
    }
}

#[tonic::async_trait]
impl<R, P> Publisher for MyPublisher<R, P>
where
    R: Remote + 'static,
    P: Protocol + 'static,
    P::Accumulator: Clone + Sync + Send + Into<Bytes>,
    Share: TryInto<Vec<P::Accumulator>>,
    <Share as TryInto<Vec<P::Accumulator>>>::Error: Debug,
{
    async fn aggregate_group(
        &self,
        request: Request<AggregateGroupRequest>,
    ) -> Result<Response<AggregateGroupResponse>, Status> {
        let request = request.into_inner();

        validate_round(
            request.window,
            request.round,
            self.expected_window,
            self.expected_round,
        )?;

        let group: usize = request
            .group
            .try_into()
            .map_err(|_| Status::invalid_argument("Group ID does not fit usize"))?;

        let share: Share = expect_field(request.share, "Share")?;
        let data: Vec<P::Accumulator> = share.try_into().map_err(|error| {
            Status::invalid_argument(format!("Invalid aggregate share: {:?}", error))
        })?;

        let total_groups = self.total_groups;

        {
            let mut received_groups = self.received_groups.lock().await;
            record_group(&mut received_groups, group, total_groups)?;
        }

        trace!("Publisher accepted aggregate from group {}", group);

        let accumulator = self.accumulator.clone();
        let remote = self.remote.clone();
        // TODO: factor out?
        spawn(async move {
            // TODO: spawn_blocking for heavy computation?
            let group_count = accumulator.accumulate(data).await;
            if group_count < total_groups {
                trace!(
                    "Publisher receieved {}/{} shares",
                    group_count,
                    total_groups
                );
                return;
            }
            if group_count > total_groups {
                error!(
                    "Too many shares recieved! Got {}, expected {}",
                    group_count, total_groups
                );
                return;
            }

            let result = accumulator.get().await;
            // in seed-homomorphic case this is expensive, so it needs to happen
            // before we call remote.done(). we log the length so the into()
            // call won't get optimized away!
            let result: Vec<Bytes> = result.into_iter().map(Into::into).collect();
            info!("Publisher finished!");
            trace!("Recovered value len: {:?}", result.len());
            remote.done().await;
        });

        Ok(Response::new(AggregateGroupResponse {}))
    }
}

async fn inner_run<C, F, R, P>(
    config: C,
    protocol: P,
    info: PublisherInfo,
    expected_window: u64,
    expected_round: u32,
    net: NetConfig,
    remote: R,
    shutdown: F,
    delay_ms: i64,
) -> Result<(), Box<dyn std::error::Error + Sync + Send>>
where
    C: Store + Sync + Send,
    R: Remote + 'static,
    F: Future<Output = ()> + Send + 'static,
    P: Protocol + 'static,
    P::Accumulator: Clone + Sync + Send + Into<Bytes>,
    Share: TryInto<Vec<P::Accumulator>>,
    <Share as TryInto<Vec<P::Accumulator>>>::Error: Debug,
{
    let state =
        MyPublisher::from_protocol(protocol, expected_window, expected_round, remote.clone());
    info!("Publisher starting up.");
    let local_socket_addr = net.local_socket_addr();
    let server_task = tokio::spawn(async move {
        tonic::transport::server::Server::builder()
            .add_service(HealthServer::new(AllGoodHealthServer::default()))
            .add_service(PublisherServer::new(state))
            .serve_with_shutdown(local_socket_addr, shutdown)
            .await
    });

    wait_for_health(format!("http://{}", net.public_addr()), None).await?;
    trace!("Publisher {:?} healthy and serving.", info);

    let node = Node::new(info.into(), net.public_addr());
    register(&config, node).await?;
    debug!("Registered with config server.");

    let experiment = experiment::read_from_store(&config).await?;
    wait_for_quorum(&config, &experiment).await?;

    // TODO(zjn): should be more in the future
    let start =
        DateTime::<FixedOffset>::from(Utc::now()) + chrono::Duration::milliseconds(delay_ms);
    info!("Registering experiment start time: {}", start);
    set_start_time(&config, start).await?;
    delay_until(start).await;
    remote.start().await;

    server_task.await??;
    info!("Publisher shutting down.");

    Ok(())
}

pub async fn run<C, R, F>(
    config: C,
    protocol: ProtocolWrapper,
    info: PublisherInfo,
    net: NetConfig,
    remote: R,
    shutdown: F,
    delay_ms: i64,
) -> Result<(), Box<dyn std::error::Error + Sync + Send>>
where
    C: Store + Sync + Send,
    R: Remote + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    run_for_round(
        config,
        protocol,
        info,
        LEGACY_WINDOW,
        LEGACY_ROUND,
        net,
        remote,
        shutdown,
        delay_ms,
    )
    .await
}

pub async fn run_for_round<C, R, F>(
    config: C,
    protocol: ProtocolWrapper,
    info: PublisherInfo,
    expected_window: u64,
    expected_round: u32,
    net: NetConfig,
    remote: R,
    shutdown: F,
    delay_ms: i64,
) -> Result<(), Box<dyn std::error::Error + Sync + Send>>
where
    C: Store + Sync + Send,
    R: Remote + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    match protocol {
        ProtocolWrapper::Secure(protocol) => {
            inner_run(
                config,
                protocol,
                info,
                expected_window,
                expected_round,
                net,
                remote,
                shutdown,
                delay_ms,
            )
            .await?;
        }
        ProtocolWrapper::SecurePub(protocol) => {
            inner_run(
                config,
                protocol,
                info,
                expected_window,
                expected_round,
                net,
                remote,
                shutdown,
                delay_ms,
            )
            .await?;
        }
        ProtocolWrapper::SecureMultiKey(protocol) => {
            inner_run(
                config,
                protocol,
                info,
                expected_window,
                expected_round,
                net,
                remote,
                shutdown,
                delay_ms,
            )
            .await?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_can_only_be_recorded_once() {
        let mut received_groups = HashSet::new();

        assert!(record_group(&mut received_groups, 0, 2).is_ok());
        assert!(record_group(&mut received_groups, 1, 2).is_ok());

        let duplicate = record_group(&mut received_groups, 0, 2).unwrap_err();
        assert_eq!(duplicate.code(), tonic::Code::AlreadyExists);

        let unknown = record_group(&mut received_groups, 2, 2).unwrap_err();
        assert_eq!(unknown.code(), tonic::Code::InvalidArgument);
    }
}
