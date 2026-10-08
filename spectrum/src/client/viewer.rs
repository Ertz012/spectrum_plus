use crate::proto::{self, UploadRequest};
use crate::{
    client::connections,
    config,
    net::TlsConfig,
    protocols::{wrapper::ChannelKeyWrapper, wrapper::ProtocolWrapper, Protocol},
    services::{
        quorum::{delay_until, wait_for_start_time_set},
        ClientInfo,
    },
};
use spectrum_primitives::Bytes;

use config::store::Store;
use futures::prelude::*;
use futures::stream::FuturesUnordered;
use log::{debug, error, info, trace, warn};
use tokio::time::sleep;

use std::fmt;
use std::time::Duration;
use std::{
    convert::{TryFrom, TryInto},
    time::Instant,
};

const LEGACY_WINDOW: u64 = 1;
const LEGACY_ROUND: u32 = 1;

type TokioError = Box<dyn std::error::Error + Sync + Send>;

async fn inner_run<C, F, P>(
    config: C,
    protocol: P,
    info: ClientInfo,
    window: u64,
    round: u32,
    hammer: bool,
    tls: Option<TlsConfig>,
    max_jitter: u64,
    shutdown: F,
) -> Result<(), TokioError>
where
    C: Store,
    F: Future<Output = ()> + Send + 'static,
    P: Protocol,
    P::ChannelKey: TryFrom<ChannelKeyWrapper>,
    <P::ChannelKey as TryFrom<ChannelKeyWrapper>>::Error: fmt::Debug,
    P::WriteToken: Into<proto::WriteToken>
        + fmt::Debug
        + Send
        + Clone
        + TryFrom<proto::WriteToken>
        + PartialEq,
    Bytes: TryInto<P::Accumulator> + TryFrom<P::Accumulator>,
    <Bytes as TryInto<P::Accumulator>>::Error: fmt::Debug,
    <Bytes as TryFrom<P::Accumulator>>::Error: fmt::Debug,
{
    info!("Client starting");
    let start_time = wait_for_start_time_set(&config).await?;
    debug!("Received configuration from configuration server; initializing.");

    let clients: Vec<_> = connections::connect_and_register(&config, info.clone(), tls).await?;
    let client_id = info.to_proto(); // before we move info

    let jitter = Duration::from_millis(rand::random::<u64>() % max_jitter);
    sleep(jitter).await;

    {
        // free the write token memory after send!
        let broadcast_channel = info.broadcast_channel;
        let client_idx = info.idx;
        let mut write_tokens = match info.broadcast {
            Some((msg, key)) => {
                info!("Broadcaster about to send write token.");
                debug!("Write token prepared: msg.len()={}", msg.len());
                let channel = broadcast_channel
                    .unwrap_or_else(|| client_idx.try_into().expect("idx should be small"));
                protocol.broadcast(msg.try_into().unwrap(), channel, key.try_into().unwrap())
            }
            None => protocol.cover(),
        };

        delay_until(start_time).await;
        debug!("Client detected start time ready.");

        loop {
            clients
                .iter()
                .cloned()
                .zip(write_tokens.into_iter())
                .map(|(mut client, write_token)| {
                    let client_id = client_id.clone();
                    let write_token = write_token.into();
                    let window = window;
                    let round = round;
                    tokio::spawn(async move {
                        let response;
                        let start_time = Instant::now();
                        loop {
                            let req = tonic::Request::new(UploadRequest {
                                client_id: Some(client_id.clone()),
                                write_token: Some(write_token.clone()),
                                window,
                                round,
                            });
                            trace!("About to send upload request.");
                            {
                                match client.upload(req).await {
                                    Ok(r) => {
                                        response = r;
                                        break;
                                    }
                                    Err(err) => warn!("Error, trying again: {}", err),
                                };
                            }
                            sleep(Duration::from_millis(100)).await;
                        }
                        info!("Request took {}ms.", start_time.elapsed().as_millis());
                        let _ = response.into_inner();
                        debug!("Upload completed.");
                    })
                })
                .collect::<FuturesUnordered<_>>()
                .inspect_err(|err| error!("{:?}", err))
                .try_collect::<Vec<_>>()
                .await
                .expect("tokio spawn should succeed");
            if !hammer {
                break;
            }
            write_tokens = protocol.cover();
        }
    }

    shutdown.await;

    Ok(())
}

pub async fn run<C, F>(
    config: C,
    protocol: ProtocolWrapper,
    info: ClientInfo,
    hammer: bool,
    tls: Option<TlsConfig>,
    max_jitter: u64,
    shutdown: F,
) -> Result<(), TokioError>
where
    C: Store,
    F: Future<Output = ()> + Send + 'static,
{
    run_for_round(
        config,
        protocol,
        info,
        LEGACY_WINDOW,
        LEGACY_ROUND,
        hammer,
        tls,
        max_jitter,
        shutdown,
    )
    .await
}

pub async fn run_for_round<C, F>(
    config: C,
    protocol: ProtocolWrapper,
    info: ClientInfo,
    window: u64,
    round: u32,
    hammer: bool,
    tls: Option<TlsConfig>,
    max_jitter: u64,
    shutdown: F,
) -> Result<(), TokioError>
where
    C: Store,
    F: Future<Output = ()> + Send + 'static,
{
    match protocol {
        ProtocolWrapper::Secure(protocol) => {
            inner_run(
                config, protocol, info, window, round, hammer, tls, max_jitter, shutdown,
            )
            .await?;
        }
        ProtocolWrapper::SecurePub(protocol) => {
            inner_run(
                config, protocol, info, window, round, hammer, tls, max_jitter, shutdown,
            )
            .await?;
        }
        ProtocolWrapper::SecureMultiKey(protocol) => {
            inner_run(
                config, protocol, info, window, round, hammer, tls, max_jitter, shutdown,
            )
            .await?;
        }
    }
    Ok(())
}
