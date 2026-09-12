use super::*;
use spectrum_primitives::Bytes;

#[derive(Clone)]
struct RejectingProtocol;

impl Protocol for RejectingProtocol {
    type ChannelKey = String;
    type WriteToken = u8;
    type AuditShare = ();
    type Accumulator = Bytes;

    fn num_parties(&self) -> usize {
        2
    }

    fn num_channels(&self) -> usize {
        1
    }

    fn message_len(&self) -> usize {
        1
    }

    fn broadcast(
        &self,
        _message: Self::Accumulator,
        _idx: usize,
        _key: Self::ChannelKey,
    ) -> Vec<Self::WriteToken> {
        vec![1; self.num_parties()]
    }

    fn cover(&self) -> Vec<Self::WriteToken> {
        vec![0; self.num_parties()]
    }

    fn gen_audit(
        &self,
        _keys: &[Self::ChannelKey],
        _token: Self::WriteToken,
    ) -> Vec<Self::AuditShare> {
        vec![(); self.num_parties()]
    }

    fn check_audit(&self, shares: Vec<Self::AuditShare>) -> bool {
        assert_eq!(shares.len(), self.num_parties());
        false
    }

    fn new_accumulator(&self) -> Vec<Self::Accumulator> {
        vec![Bytes::empty(self.message_len())]
    }

    fn to_accumulator(&self, token: Self::WriteToken) -> Vec<Self::Accumulator> {
        vec![vec![token].into()]
    }
}

#[tokio::test]
async fn test_rejected_write_uses_neutral_contribution() {
    let protocol = ProtocolWrapper::new(true, false, 2, 1, 1, false);
    let experiment = Experiment::new_sample_keys(protocol, 1, 1, true);
    let state = WorkerState::from_experiment(experiment, RejectingProtocol);
    let client = ClientInfo::new(0);

    state.audit_registry.lock().await.init(&client, 1).await;

    let status = state.verify(&client, ()).await.unwrap();
    assert!(matches!(status, VerifyStatus::AwaitingShares));

    let status = state.verify(&client, ()).await.unwrap();
    assert!(matches!(status, VerifyStatus::ShareVerified { clients: 1 }));
    assert_eq!(state.accumulator.get().await, vec![Bytes::empty(1)]);
}
