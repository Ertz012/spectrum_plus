use crate::proto::{
    expect_field,
    leader_server::{Leader, LeaderServer},
    publisher_client::PublisherClient,
    validate_round, AggregateGroupRequest, AggregateWorkerRequest, AggregateWorkerResponse, Share,
};
use crate::{
    accumulator::Accumulator,
    config::store::Store,
    experiment::Experiment,
    net::Config as NetConfig,
    protocols::{wrapper::ProtocolWrapper, Protocol},
    services::{
        discovery::{register, resolve_all, Node},
        health::{wait_for_health, AllGoodHealthServer, HealthServer},
        quorum::wait_for_start_time_set,
        Group, LeaderInfo, Service, WorkerInfo,
    },
};
use spectrum_primitives::Bytes;

use futures::Future;
use log::{debug, error, info, trace};
use std::{
    collections::HashSet,
    convert::{TryFrom, TryInto},
    fmt::Debug,
    sync::Arc,
};
use tokio::{
    spawn,
    sync::{watch, Mutex},
};
use tonic::{transport::Channel, Request, Response, Status};

type SharedPublisherClient = Arc<Mutex<PublisherClient<Channel>>>;
const LEGACY_WINDOW: u64 = 1;
const LEGACY_ROUND: u32 = 1;

fn record_worker(
    received_workers: &mut HashSet<WorkerInfo>,
    worker: WorkerInfo,
    expected_group: Group,
    total_workers: usize,
) -> Result<(), Status> {
    let belongs_to_group =
        worker.group == expected_group && usize::from(worker.idx) < total_workers;

    if !belongs_to_group {
        return Err(Status::permission_denied(format!(
            "Worker {:?} does not belong to leader group {:?}",
            worker, expected_group
        )));
    }

    if !received_workers.insert(worker) {
        return Err(Status::already_exists(format!(
            "Aggregate from worker {:?} was already received",
            worker
        )));
    }

    Ok(())
}

pub struct MyLeader<P: Protocol> {
    accumulator: Arc<Accumulator<Vec<P::Accumulator>>>,
    received_workers: Mutex<HashSet<WorkerInfo>>,
    group: Group,
    window: u64,
    round: u32,
    total_workers: usize,
    publisher_client: watch::Receiver<Option<SharedPublisherClient>>,
}

impl<P> MyLeader<P>
where
    P: Protocol,
    P::Accumulator: Clone,
{
    fn from_protocol(
        protocol: P,
        group: Group,
        window: u64,
        round: u32,
        workers_per_group: u16,
        publisher_client: watch::Receiver<Option<SharedPublisherClient>>,
    ) -> Self {
        MyLeader {
            accumulator: Arc::new(Accumulator::new(protocol.new_accumulator())),
            received_workers: Mutex::new(HashSet::with_capacity(workers_per_group as usize)),
            group,
            window,
            round,
            total_workers: workers_per_group as usize,
            publisher_client,
        }
    }
}

#[tonic::async_trait]
impl<P> Leader for MyLeader<P>
where
    P: Protocol + 'static,
    P::Accumulator: Clone + Sync + Send + Into<Vec<u8>>,
    Share: TryInto<Vec<P::Accumulator>>,
    <Share as TryInto<Vec<P::Accumulator>>>::Error: Debug,
{
    async fn aggregate_worker(
        &self,
        request: Request<AggregateWorkerRequest>,
    ) -> Result<Response<AggregateWorkerResponse>, Status> {
        let request = request.into_inner();

        validate_round(request.window, request.round, self.window, self.round)?;

        let worker_id = expect_field(request.worker_id, "Worker ID")?;
        let worker_group = u16::try_from(worker_id.group)
            .map_err(|_| Status::invalid_argument("Worker group does not fit u16"))?;
        let worker_index = u16::try_from(worker_id.idx)
            .map_err(|_| Status::invalid_argument("Worker index does not fit u16"))?;
        let worker = WorkerInfo::new(Group::new(worker_group), worker_index);

        let data = expect_field(request.share, "Share")?;
        let data: Vec<P::Accumulator> = data.try_into().map_err(|error| {
            Status::invalid_argument(format!("Invalid worker aggregate: {:?}", error))
        })?;
        {
            let mut received_workers = self.received_workers.lock().await;

            record_worker(
                &mut received_workers,
                worker,
                self.group,
                self.total_workers,
            )?;
        }
        let accumulator = self.accumulator.clone();
        let total_workers = self.total_workers;
        let publisher = self
            .publisher_client
            .borrow()
            .as_ref()
            .expect("Should have a publisher by now.")
            .clone();
        let group = u32::from(self.group.idx);
        let window = self.window;
        let round = self.round;

        spawn(async move {
            // TODO: spawn_blocking for heavy computation?
            let worker_count = accumulator.accumulate(data).await;
            if worker_count < total_workers {
                trace!("Leader receieved {}/{} shares", worker_count, total_workers);
                return;
            }
            if worker_count > total_workers {
                error!(
                    "Too many shares recieved! Got {}, expected {}",
                    worker_count, total_workers
                );
                return;
            }

            let share = accumulator.get().await;
            let share: Vec<Vec<u8>> = share.into_iter().map(Into::<Vec<u8>>::into).collect();
            // trace!("Leader final shares: {:?}", share);
            let req = Request::new(AggregateGroupRequest {
                share: Some(Share { data: share }),
                group,
                window,
                round,
            });
            publisher.lock().await.aggregate_group(req).await.unwrap();
        });

        Ok(Response::new(AggregateWorkerResponse {}))
    }
}

async fn inner_run<C, F, P>(
    config: C,
    experiment: Experiment,
    protocol: P,
    info: LeaderInfo,
    window: u64,
    round: u32,
    net: NetConfig,
    shutdown: F,
) -> Result<(), Box<dyn std::error::Error + Sync + Send>>
where
    C: Store,
    F: Future<Output = ()> + Send + 'static,
    P: Protocol + 'static,
    P::Accumulator: Sync + Send + Clone + TryFrom<Bytes> + Into<Vec<u8>>,
    Share: TryInto<Vec<P::Accumulator>>,
    <Share as TryInto<Vec<P::Accumulator>>>::Error: Debug,
{
    let (tx, rx) = watch::channel(None);
    let state = MyLeader::from_protocol(
        protocol,
        info.group,
        window,
        round,
        experiment.group_size(),
        rx,
    );
    info!("Leader starting up.");
    let server_task = tokio::spawn(
        tonic::transport::server::Server::builder()
            .add_service(HealthServer::new(AllGoodHealthServer::default()))
            .add_service(LeaderServer::new(state))
            .serve_with_shutdown(net.local_socket_addr(), shutdown),
    );

    wait_for_health(format!("http://{}", net.public_addr()), None).await?;
    trace!("Leader {:?} healthy and serving.", info);

    let node = Node::new(info.into(), net.public_addr());
    register(&config, node).await?;
    debug!("Registered with config server.");

    wait_for_start_time_set(&config).await.unwrap();
    debug!("Got start time.");
    let publisher_addr = resolve_all(&config)
        .await?
        .into_iter()
        .find_map(|node| match node.service {
            Service::Publisher(_) => Some(node.addr),
            _ => None,
        })
        .expect("Should have a publisher registered");

    let publisher = Arc::new(Mutex::new(
        PublisherClient::connect(format!("http://{}", publisher_addr)).await?,
    ));
    tx.send(Some(publisher))
        .map_err(|_| "Error sending service registry.")?;

    server_task.await??;
    info!("Leader shutting down.");
    Ok(())
}

pub async fn run<C, F>(
    config: C,
    experiment: Experiment,
    protocol: ProtocolWrapper,
    info: LeaderInfo,
    net: NetConfig,
    shutdown: F,
) -> Result<(), Box<dyn std::error::Error + Sync + Send>>
where
    C: Store,
    F: Future<Output = ()> + Send + 'static,
{
    run_for_round(
        config,
        experiment,
        protocol,
        info,
        LEGACY_WINDOW,
        LEGACY_ROUND,
        net,
        shutdown,
    )
    .await
}

pub async fn run_for_round<C, F>(
    config: C,
    experiment: Experiment,
    protocol: ProtocolWrapper,
    info: LeaderInfo,
    window: u64,
    round: u32,
    net: NetConfig,
    shutdown: F,
) -> Result<(), Box<dyn std::error::Error + Sync + Send>>
where
    C: Store,
    F: Future<Output = ()> + Send + 'static,
{
    match protocol {
        ProtocolWrapper::Secure(protocol) => {
            inner_run(
                config, experiment, protocol, info, window, round, net, shutdown,
            )
            .await?;
        }
        ProtocolWrapper::SecurePub(protocol) => {
            inner_run(
                config, experiment, protocol, info, window, round, net, shutdown,
            )
            .await?;
        }
        ProtocolWrapper::SecureMultiKey(protocol) => {
            inner_run(
                config, experiment, protocol, info, window, round, net, shutdown,
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
    fn workers_can_only_be_recorded_once() {
        let group = Group::new(0);
        let worker_zero = WorkerInfo::new(group, 0);
        let worker_one = WorkerInfo::new(group, 1);
        let mut received_workers = HashSet::new();

        assert!(record_worker(&mut received_workers, worker_zero, group, 2,).is_ok());

        assert!(record_worker(&mut received_workers, worker_one, group, 2,).is_ok());

        let duplicate = record_worker(&mut received_workers, worker_zero, group, 2).unwrap_err();

        assert_eq!(duplicate.code(), tonic::Code::AlreadyExists);
    }

    #[test]
    fn worker_must_belong_to_the_leaders_group() {
        let expected_group = Group::new(0);
        let wrong_group_worker = WorkerInfo::new(Group::new(1), 0);
        let unknown_worker = WorkerInfo::new(expected_group, 2);
        let mut received_workers = HashSet::new();

        let wrong_group =
            record_worker(&mut received_workers, wrong_group_worker, expected_group, 2)
                .unwrap_err();

        assert_eq!(wrong_group.code(), tonic::Code::PermissionDenied);

        let unknown =
            record_worker(&mut received_workers, unknown_worker, expected_group, 2).unwrap_err();

        assert_eq!(unknown.code(), tonic::Code::PermissionDenied);

        assert!(received_workers.is_empty());
    }
}
