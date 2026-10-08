use crate::{AggregateSharePayload, ConfigurationHash, MainRoundContext, SignedAggregateShare};
use ed25519_dalek::SigningKey;
use spectrum::{
    config::Store,
    experiment::Experiment,
    leader::{self, AggregateDecorator},
    net::Config as NetConfig,
    proto::AggregateGroupRequest,
    services::{Group, LeaderInfo, WorkerInfo},
    worker,
};
use std::{fmt, future::Future, str::FromStr};
use tonic::Status;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShareServerId {
    A,
    B,
}

impl fmt::Display for ShareServerId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::A => formatter.write_str("A"),
            Self::B => formatter.write_str("B"),
        }
    }
}

impl FromStr for ShareServerId {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "a" | "A" => Ok(Self::A),
            "b" | "B" => Ok(Self::B),
            _ => Err("expected ShareServer A or B"),
        }
    }
}

impl ShareServerId {
    fn spectrum_group(self) -> Group {
        match self {
            Self::A => Group::new(0),
            Self::B => Group::new(1),
        }
    }
}

struct ChorusAggregateDecorator {
    server: ShareServerId,
    context: MainRoundContext,
    configuration_hash: ConfigurationHash,
    signing_key: SigningKey,
}

impl ChorusAggregateDecorator {
    fn new(
        server: ShareServerId,
        context: MainRoundContext,
        configuration_hash: ConfigurationHash,
        signing_key: SigningKey,
    ) -> Self {
        Self {
            server,
            context,
            configuration_hash,
            signing_key,
        }
    }
}

impl AggregateDecorator for ChorusAggregateDecorator {
    fn decorate(&self, request: &mut AggregateGroupRequest) -> Result<(), Status> {
        let expected_group = u32::from(self.server.spectrum_group().idx);
        let expected_window = self.context.window().get();
        let expected_round = self.context.round().get();

        if request.group != expected_group
            || request.window != expected_window
            || request.round != expected_round
        {
            return Err(Status::failed_precondition(
                "aggregate context does not match \
                 the ShareServer signing context",
            ));
        }

        let mut share = request
            .share
            .take()
            .ok_or_else(|| Status::invalid_argument("Aggregate share must be set"))?;

        let channel_data = std::mem::take(&mut share.data);

        let payload = AggregateSharePayload::new(
            self.server,
            self.context,
            self.configuration_hash,
            channel_data,
        );

        let signed = SignedAggregateShare::sign(payload, &self.signing_key).map_err(|error| {
            Status::internal(format!("Could not sign aggregate share: {}", error))
        })?;

        request.version = u32::from(signed.payload().version());
        request.configuration_hash = self.configuration_hash.as_bytes().to_vec();

        let (payload, signature) = signed.into_parts();

        request.signature = signature.to_vec();
        share.data = payload.into_channel_data();
        request.share = Some(share);

        Ok(())
    }
}

/// Runs one CHORUS ShareServer using one Spectrum worker and leader.
///
/// This compatibility stage uses Spectrum groups internally:
/// ShareServer A is group 0 and ShareServer B is group 1.
pub async fn run_development<C, WF, LF>(
    id: ShareServerId,
    expected_round: MainRoundContext,
    configuration_hash: ConfigurationHash,
    signing_key: SigningKey,
    config: C,
    experiment: Experiment,
    worker_net: NetConfig,
    leader_net: NetConfig,
    worker_shutdown: WF,
    leader_shutdown: LF,
) -> Result<(), Box<dyn std::error::Error + Sync + Send>>
where
    C: Store + Clone,
    WF: Future<Output = ()> + Send + 'static,
    LF: Future<Output = ()> + Send + 'static,
{
    let window = expected_round.window().get();
    let round = expected_round.round().get();
    let group = id.spectrum_group();
    let protocol = experiment.get_protocol().clone();
    let decorator =
        ChorusAggregateDecorator::new(id, expected_round, configuration_hash, signing_key);

    let worker = worker::run_for_round(
        config.clone(),
        experiment.clone(),
        protocol.clone(),
        WorkerInfo::new(group, 0),
        window,
        round,
        worker_net,
        worker_shutdown,
    );

    let leader = leader::run_for_round_with_decorator(
        config,
        experiment,
        protocol,
        LeaderInfo::new(group),
        window,
        round,
        decorator,
        leader_net,
        leader_shutdown,
    );

    tokio::try_join!(worker, leader)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RoundId, WindowId, AGGREGATE_SHARE_VERSION};
    use ed25519_dalek::{Signature, VerifyingKey};
    use spectrum::proto::Share;

    #[test]
    fn share_servers_map_to_different_spectrum_groups() {
        assert_eq!(ShareServerId::A.spectrum_group().idx, 0);
        assert_eq!(ShareServerId::B.spectrum_group().idx, 1);
    }

    #[test]
    fn share_server_id_can_be_parsed() {
        assert_eq!("a".parse(), Ok(ShareServerId::A));
        assert_eq!("A".parse(), Ok(ShareServerId::A));
        assert_eq!("b".parse(), Ok(ShareServerId::B));
        assert_eq!("B".parse(), Ok(ShareServerId::B));
        assert!("c".parse::<ShareServerId>().is_err());
    }
    #[test]
    fn chorus_decorator_signs_the_transport_envelope() {
        let context = MainRoundContext::new(WindowId::new(7), RoundId::try_from(2).unwrap());
        let configuration_hash = ConfigurationHash::new([0x42; 32]);
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let verifying_key: VerifyingKey = signing_key.verifying_key();

        let decorator = ChorusAggregateDecorator::new(
            ShareServerId::A,
            context,
            configuration_hash,
            signing_key,
        );

        let mut request = AggregateGroupRequest {
            share: Some(Share {
                data: vec![vec![1, 2], vec![3]],
            }),
            group: 0,
            window: 7,
            round: 2,
            version: 0,
            configuration_hash: Vec::new(),
            signature: Vec::new(),
        };

        decorator.decorate(&mut request).unwrap();

        assert_eq!(request.version, u32::from(AGGREGATE_SHARE_VERSION));
        assert_eq!(request.configuration_hash, configuration_hash.as_bytes());
        assert_eq!(request.signature.len(), 64);

        let signature = Signature::try_from(request.signature.as_slice()).unwrap();

        let reconstructed_payload = AggregateSharePayload::new(
            ShareServerId::A,
            context,
            configuration_hash,
            request.share.unwrap().data,
        );

        assert!(verifying_key
            .verify_strict(&reconstructed_payload.signing_bytes().unwrap(), &signature,)
            .is_ok());
    }

    #[test]
    fn chorus_decorator_rejects_wrong_round() {
        let context = MainRoundContext::new(WindowId::new(7), RoundId::try_from(2).unwrap());

        let decorator = ChorusAggregateDecorator::new(
            ShareServerId::A,
            context,
            ConfigurationHash::new([0x42; 32]),
            SigningKey::from_bytes(&[7; 32]),
        );

        let mut request = AggregateGroupRequest {
            share: Some(Share {
                data: vec![vec![1, 2, 3]],
            }),
            group: 0,
            window: 7,
            round: 3,
            version: 0,
            configuration_hash: Vec::new(),
            signature: Vec::new(),
        };

        let error = decorator.decorate(&mut request).unwrap_err();

        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(request.signature.is_empty());
    }
}
