use spectrum::{
    config::Store,
    experiment::Experiment,
    leader,
    net::Config as NetConfig,
    services::{Group, LeaderInfo, WorkerInfo},
    worker,
};
use std::{future::Future, str::FromStr};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShareServerId {
    A,
    B,
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

/// Runs one CHORUS ShareServer using one Spectrum worker and leader.
///
/// This compatibility stage uses Spectrum groups internally:
/// ShareServer A is group 0 and ShareServer B is group 1.
pub async fn run_development<C, WF, LF>(
    id: ShareServerId,
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
    let group = id.spectrum_group();
    let protocol = experiment.get_protocol().clone();

    let worker = worker::run(
        config.clone(),
        experiment.clone(),
        protocol.clone(),
        WorkerInfo::new(group, 0),
        worker_net,
        worker_shutdown,
    );

    let leader = leader::run(
        config,
        experiment,
        protocol,
        LeaderInfo::new(group),
        leader_net,
        leader_shutdown,
    );

    tokio::try_join!(worker, leader)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
