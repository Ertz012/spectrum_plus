use crate::{
    bootstrap::ActivatedMainWindow, compute_atom_fingerprints, ChannelCryptoError, ChannelPayload,
    ContentProofError, CredentialPublicParameters, FingerprintError, MainRoundContext,
    MemberCredentialBundle, CHANNEL_SLOT_SIZE,
};
use spectrum::{
    client::viewer,
    config::Store,
    net::TlsConfig,
    protocols::wrapper::{ChannelKeyWrapper, ProtocolWrapper},
    services::ClientInfo,
};
use std::{error::Error, fmt, future::Future};

type BoxedError = Box<dyn Error + Sync + Send>;

/// The one main-phase action a member performs in a round.
#[derive(Debug)]
pub enum MainSubmission {
    Broadcast(ChannelPayload),
    Cover,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MainSubmissionError {
    MissingBroadcastChannel,
    InvalidBroadcastKey,
    BroadcastChannelNotRegistered,
    InvalidMessageLength { configured: usize },
}

#[derive(Debug)]
pub enum BroadcastPayloadError {
    Fingerprint(FingerprintError),
    Proof(ContentProofError),
    Payload(ChannelCryptoError),
}

impl fmt::Display for MainSubmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingBroadcastChannel => {
                formatter.write_str("member has no broadcast channel in this window")
            }
            Self::InvalidBroadcastKey => formatter.write_str("invalid private broadcast key"),
            Self::BroadcastChannelNotRegistered => {
                formatter.write_str("private broadcast key is not registered in the active window")
            }
            Self::InvalidMessageLength { configured } => write!(
                formatter,
                "Spectrum message length must be {} bytes for CHORUS; got {}",
                CHANNEL_SLOT_SIZE, configured
            ),
        }
    }
}

impl Error for MainSubmissionError {}

impl fmt::Display for BroadcastPayloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fingerprint(error) => {
                write!(formatter, "could not fingerprint STIX bundle: {error}")
            }
            Self::Proof(error) => write!(
                formatter,
                "could not prove membership and pseudonym binding: {error}"
            ),
            Self::Payload(error) => write!(formatter, "could not encode channel payload: {error}"),
        }
    }
}

impl Error for BroadcastPayloadError {}

pub fn configure_broadcaster(
    member_id: u128,
    active_window: &ActivatedMainWindow,
    private_key: [u8; 32],
) -> Result<ClientInfo, MainSubmissionError> {
    let key = ChannelKeyWrapper::secure_private_from_bytes(private_key)
        .map_err(|_| MainSubmissionError::InvalidBroadcastKey)?;
    let public_key = key
        .public_key_bytes()
        .ok_or(MainSubmissionError::InvalidBroadcastKey)?;
    let channel = active_window
        .verification_keys()
        .iter()
        .position(|registered| registered.public_key_bytes() == Some(public_key))
        .ok_or(MainSubmissionError::BroadcastChannelNotRegistered)?;
    Ok(ClientInfo::new_broadcaster_for_channel(
        member_id,
        channel,
        Vec::new().into(),
        key,
    ))
}

pub fn create_broadcast_payload(
    credentials: &MemberCredentialBundle,
    parameters: &CredentialPublicParameters,
    stix_bundle: Vec<u8>,
) -> Result<ChannelPayload, BroadcastPayloadError> {
    let fingerprints =
        compute_atom_fingerprints(&stix_bundle).map_err(BroadcastPayloadError::Fingerprint)?;
    let (pseudonyms, proof) = credentials
        .prove_content_binding(&fingerprints, parameters)
        .map_err(BroadcastPayloadError::Proof)?;
    ChannelPayload::from_content_binding(fingerprints, &pseudonyms, &proof, stix_bundle)
        .map_err(BroadcastPayloadError::Payload)
}

/// Runs one CHORUS member for exactly one main round.
///
/// CHORUS selects and encodes the submission. The existing Spectrum client
/// generates and sends the two DPF shares.
pub async fn run_development<C, F>(
    context: MainRoundContext,
    config: C,
    protocol: ProtocolWrapper,
    info: ClientInfo,
    submission: MainSubmission,
    tls: Option<TlsConfig>,
    max_jitter: u64,
    shutdown: F,
) -> Result<(), BoxedError>
where
    C: Store,
    F: Future<Output = ()> + Send + 'static,
{
    if protocol.message_len() != CHANNEL_SLOT_SIZE {
        return Err(MainSubmissionError::InvalidMessageLength {
            configured: protocol.message_len(),
        }
        .into());
    }
    let info = prepare_client(info, submission)?;
    viewer::run_for_round(
        config,
        protocol,
        info,
        context.window().get(),
        context.round().get(),
        false,
        tls,
        max_jitter,
        shutdown,
    )
    .await
}

fn prepare_client(
    mut info: ClientInfo,
    submission: MainSubmission,
) -> Result<ClientInfo, MainSubmissionError> {
    match submission {
        MainSubmission::Broadcast(payload) => {
            let (_, key) = info
                .broadcast
                .take()
                .ok_or(MainSubmissionError::MissingBroadcastChannel)?;
            info.broadcast = Some((payload.encode().into(), key));
        }
        MainSubmission::Cover => info.broadcast = None,
    }
    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        authority::{
            AuthorityKeyManager, ContentProofStatus, DecodedChannel, DecodedRound,
            SelfBindingStatus,
        },
        bootstrap::{
            ChannelSet, ChannelSetSignature, ChannelVerificationKey, MainWindowActivator,
            SignedChannelSet,
        },
        share_server::ShareServerId,
        AtomEntry, CredentialAttributes, MemberSecret, WindowId,
    };
    use ark_bls12_381::Fr;
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use rand::{rngs::StdRng, SeedableRng};
    use spectrum::{experiment::Experiment, services::Service};

    fn payload() -> ChannelPayload {
        ChannelPayload::new(
            vec![AtomEntry::new([1; 32], [2; 48])],
            vec![3, 4],
            vec![5, 6],
        )
        .unwrap()
    }

    fn configured_broadcaster() -> ClientInfo {
        let protocol = ProtocolWrapper::new(true, false, 2, 1, CHANNEL_SLOT_SIZE, false);
        Experiment::new_sample_keys(protocol, 1, 1, false)
            .iter_clients()
            .find_map(|service| match service {
                Service::Client(info) => Some(info),
                _ => None,
            })
            .unwrap()
    }

    fn signed_channel_set(public_keys: Vec<[u8; 32]>) -> (Vec<u8>, VerifyingKey, VerifyingKey) {
        let server_a = SigningKey::from_bytes(&[7; 32]);
        let server_b = SigningKey::from_bytes(&[8; 32]);
        let channel_set = ChannelSet::new(
            WindowId::new(3),
            public_keys
                .into_iter()
                .map(ChannelVerificationKey::new)
                .collect(),
        )
        .unwrap();
        let signature_a =
            ChannelSetSignature::sign(&channel_set, ShareServerId::A, &server_a).unwrap();
        let signature_b =
            ChannelSetSignature::sign(&channel_set, ShareServerId::B, &server_b).unwrap();
        let encoded = SignedChannelSet::assemble(channel_set, signature_a, signature_b)
            .unwrap()
            .encode()
            .unwrap();
        (encoded, server_a.verifying_key(), server_b.verifying_key())
    }

    fn private_key(value: u8) -> [u8; 32] {
        let mut key = [0; 32];
        key[0] = value;
        key
    }

    fn public_key(private_key: [u8; 32]) -> [u8; 32] {
        ChannelKeyWrapper::secure_private_from_bytes(private_key)
            .unwrap()
            .public_key_bytes()
            .unwrap()
    }

    #[test]
    fn broadcaster_is_bound_to_its_channel_in_the_active_window() {
        let own_private_key = private_key(2);
        let (encoded, server_a, server_b) = signed_channel_set(vec![
            public_key(private_key(1)),
            public_key(own_private_key),
        ]);
        let mut activator = MainWindowActivator::new();
        let active = activator.activate(&encoded, &server_a, &server_b).unwrap();
        let info = configure_broadcaster(42, active, own_private_key).unwrap();
        assert_eq!(info.idx, 42);
        assert_eq!(info.broadcast_channel, Some(1));
        assert!(info.broadcast.unwrap().1.contains_private_key());
    }

    #[test]
    fn unregistered_private_key_cannot_configure_a_broadcaster() {
        let (encoded, server_a, server_b) = signed_channel_set(vec![public_key(private_key(1))]);
        let mut activator = MainWindowActivator::new();
        let active = activator.activate(&encoded, &server_a, &server_b).unwrap();
        assert_eq!(
            configure_broadcaster(42, active, private_key(2)),
            Err(MainSubmissionError::BroadcastChannelNotRegistered)
        );
    }

    #[test]
    fn broadcast_replaces_dummy_message_and_preserves_channel_key() {
        let info = configured_broadcaster();
        let original_key = info.broadcast.as_ref().unwrap().1.clone();
        let original_channel = info.broadcast_channel;
        let expected = payload().encode();
        let prepared = prepare_client(info, MainSubmission::Broadcast(payload())).unwrap();
        let (message, key) = prepared.broadcast.unwrap();
        assert_eq!(message.as_ref(), expected);
        assert_eq!(key, original_key);
        assert_eq!(prepared.broadcast_channel, original_channel);
    }

    #[test]
    fn cover_removes_broadcast_configuration() {
        let prepared = prepare_client(configured_broadcaster(), MainSubmission::Cover).unwrap();
        assert!(prepared.broadcast.is_none());
    }

    #[test]
    fn broadcast_requires_a_channel_for_the_current_window() {
        assert_eq!(
            prepare_client(ClientInfo::new(7), MainSubmission::Broadcast(payload())),
            Err(MainSubmissionError::MissingBroadcastChannel)
        );
    }

    #[test]
    fn persisted_member_credentials_create_a_payload_the_authority_accepts() {
        let authority = AuthorityKeyManager::generate_with_rng(&mut StdRng::seed_from_u64(1));
        let parameters = authority.public_parameters();
        let secret = MemberSecret::generate_with_rng(&mut StdRng::seed_from_u64(2));
        let attributes = CredentialAttributes::from_scalars(Fr::from(7), Fr::from(8), Fr::from(9));
        let (request, pending) = secret.start_credential_request(parameters).unwrap();
        let blind_credential = authority
            .issue_blind_credential(&request, &attributes)
            .unwrap();
        let credential = pending
            .finish(&secret, blind_credential, attributes, parameters)
            .unwrap();
        let credentials = MemberCredentialBundle::new(secret, credential, parameters).unwrap();
        let encoded = credentials.encode(parameters).unwrap();
        let restored = MemberCredentialBundle::decode(&encoded, parameters).unwrap();
        let stix = br#"{"objects":[{"type":"domain-name","value":"example.com"}]}"#.to_vec();
        let payload = create_broadcast_payload(&restored, parameters, stix).unwrap();
        let round = DecodedRound::decode_with_credentials(
            MainRoundContext::new(
                crate::WindowId::new(1),
                crate::RoundId::try_from(1).unwrap(),
            ),
            vec![payload.encode()],
            parameters,
        );
        assert!(matches!(
            &round.channels()[0],
            DecodedChannel::Payload {
                self_binding: SelfBindingStatus::Valid,
                content_proof: ContentProofStatus::Valid,
                ..
            }
        ));
    }
}
