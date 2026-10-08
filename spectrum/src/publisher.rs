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
use std::{collections::HashSet, convert::TryInto, fmt::Debug, sync::Arc};
use tokio::{spawn, sync::Mutex};
use tonic::{Request, Response, Status};

const LEGACY_WINDOW: u64 = 1;
const LEGACY_ROUND: u32 = 1;

#[tonic::async_trait]
pub trait Remote: Sync + Send + Clone {
    async fn start(&self);
    fn validate_aggregate(&self, _request: &AggregateGroupRequest) -> Result<(), Status> {
        Ok(())
    }
    async fn done(&self, result: Vec<Vec<u8>>);
}

#[derive(Clone)]
pub struct NoopRemote;

#[tonic::async_trait]
impl Remote for NoopRemote {
    async fn start(&self) {}
    async fn done(&self, _result: Vec<Vec<u8>>) {}
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
    P::Accumulator: Clone + Sync + Send + Into<Vec<u8>>,
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

        self.remote.validate_aggregate(&request)?;

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
            let result: Vec<Vec<u8>> = result.into_iter().map(Into::into).collect();
            info!("Publisher finished!");
            trace!("Recovered value len: {:?}", result.len());
            remote.done(result).await;
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
    P::Accumulator: Clone + Sync + Send + Into<Vec<u8>>,
    Share: TryInto<Vec<P::Accumulator>>,
    <Share as TryInto<Vec<P::Accumulator>>>::Error: Debug,
{
    let state =
        MyPublisher::from_protocol(protocol, expected_window, expected_round, remote.clone());
    info!("Publisher starting up.");
    let local_socket_addr = net.local_socket_addr();
    let mut builder = tonic::transport::server::Server::builder();
    if let Some(tls) = net.server_tls_config() {
        info!("Adding mTLS config.");
        builder = builder.tls_config(tls)?;
    }
    let server = builder
        .add_service(HealthServer::new(AllGoodHealthServer::default()))
        .add_service(PublisherServer::new(state))
        .serve_with_shutdown(local_socket_addr, shutdown);
    let server_task = tokio::spawn(server);

    wait_for_health(net.public_addr(), net.tls_config()).await?;
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
    use spectrum_primitives::Bytes;
    use tokio::sync::Notify;

    #[derive(Clone)]
    struct TestProtocol;

    impl Protocol for TestProtocol {
        type ChannelKey = ();
        type WriteToken = ();
        type AuditShare = ();
        type Accumulator = Bytes;

        fn num_parties(&self) -> usize {
            2
        }
        fn num_channels(&self) -> usize {
            1
        }
        fn message_len(&self) -> usize {
            3
        }
        fn broadcast(&self, _: Bytes, _: usize, _: ()) -> Vec<()> {
            unreachable!()
        }
        fn cover(&self) -> Vec<()> {
            unreachable!()
        }
        fn gen_audit(&self, _: &[()], _: ()) -> Vec<()> {
            unreachable!()
        }
        fn check_audit(&self, _: Vec<()>) -> bool {
            unreachable!()
        }
        fn new_accumulator(&self) -> Vec<Bytes> {
            vec![Bytes::empty(self.message_len())]
        }
        fn to_accumulator(&self, _: ()) -> Vec<Bytes> {
            unreachable!()
        }
    }

    #[derive(Clone, Default)]
    struct CapturingRemote {
        result: Arc<Mutex<Option<Vec<Vec<u8>>>>>,
        completed: Arc<Notify>,
    }

    #[tonic::async_trait]
    impl Remote for CapturingRemote {
        async fn start(&self) {}
        async fn done(&self, result: Vec<Vec<u8>>) {
            *self.result.lock().await = Some(result);
            self.completed.notify_one();
        }
    }

    #[derive(Clone)]
    struct RejectingRemote;

    #[tonic::async_trait]
    impl Remote for RejectingRemote {
        async fn start(&self) {}
        fn validate_aggregate(&self, _: &AggregateGroupRequest) -> Result<(), Status> {
            Err(Status::unauthenticated("rejected by test verifier"))
        }
        async fn done(&self, _: Vec<Vec<u8>>) {
            unreachable!()
        }
    }

    fn aggregate(group: u32, data: Vec<u8>) -> Request<AggregateGroupRequest> {
        Request::new(AggregateGroupRequest {
            share: Some(Share { data: vec![data] }),
            group,
            window: 7,
            round: 2,
            version: 0,
            configuration_hash: Vec::new(),
            signature: Vec::new(),
        })
    }

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

    #[tokio::test]
    async fn reconstructed_channels_are_delivered_to_the_remote() {
        let remote = CapturingRemote::default();
        let publisher = MyPublisher::from_protocol(TestProtocol, 7, 2, remote.clone());
        publisher
            .aggregate_group(aggregate(0, vec![1, 2, 3]))
            .await
            .unwrap();
        publisher
            .aggregate_group(aggregate(1, vec![4, 5, 6]))
            .await
            .unwrap();
        remote.completed.notified().await;
        assert_eq!(*remote.result.lock().await, Some(vec![vec![5, 7, 5]]));
    }

    #[tokio::test]
    async fn rejected_aggregate_does_not_change_publisher_state() {
        let publisher = MyPublisher::from_protocol(TestProtocol, 7, 2, RejectingRemote);
        let error = publisher
            .aggregate_group(aggregate(0, vec![1, 2, 3]))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unauthenticated);
        assert!(publisher.received_groups.lock().await.is_empty());
        assert_eq!(publisher.accumulator.get().await, vec![Bytes::empty(3)]);
    }
}
