use super::seen_set::{PersistentSeenSet, SeenSetError};
use crate::{
    compute_atom_fingerprints, share_server::ShareServerId, AggregateSharePayload,
    ChannelCryptoError, ChannelPayload, ChannelPayloadError, ConfigurationHash,
    CredentialPublicParameters, MainRoundContext, AGGREGATE_SHARE_VERSION, CHANNEL_SLOT_SIZE,
};
use ed25519_dalek::{Signature, VerifyingKey};
use spectrum::proto::AggregateGroupRequest;
use std::{collections::HashSet, error::Error, fmt};
use tonic::Status;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelfBindingStatus {
    Valid,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentProofStatus {
    NotChecked,
    Valid,
    Malformed,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AtomDuplicateStatus {
    NotChecked,
    New,
    Duplicate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodedChannel {
    Empty,
    Payload {
        payload: ChannelPayload,
        self_binding: SelfBindingStatus,
        content_proof: ContentProofStatus,
        duplicate_statuses: Vec<AtomDuplicateStatus>,
    },
    Malformed(ChannelPayloadError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedRound {
    context: MainRoundContext,
    channels: Vec<DecodedChannel>,
}

#[derive(Debug)]
pub enum RoundDeduplicationError {
    InvalidVerifiedPayload(ChannelCryptoError),
    SeenSet(SeenSetError),
}

impl fmt::Display for RoundDeduplicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVerifiedPayload(error) => {
                write!(
                    formatter,
                    "verified channel payload became invalid: {error}"
                )
            }
            Self::SeenSet(error) => write!(formatter, "could not update seen-set: {error}"),
        }
    }
}

impl Error for RoundDeduplicationError {}

impl DecodedRound {
    pub(super) fn empty(context: MainRoundContext) -> Self {
        Self {
            context,
            channels: Vec::new(),
        }
    }

    pub const fn context(&self) -> MainRoundContext {
        self.context
    }

    pub fn channels(&self) -> &[DecodedChannel] {
        &self.channels
    }

    pub fn deduplicate(
        mut self,
        seen: &PersistentSeenSet,
    ) -> Result<Self, RoundDeduplicationError> {
        for channel in &mut self.channels {
            let DecodedChannel::Payload {
                payload,
                self_binding,
                content_proof,
                duplicate_statuses,
            } = channel
            else {
                continue;
            };
            if *self_binding != SelfBindingStatus::Valid
                || *content_proof != ContentProofStatus::Valid
            {
                continue;
            }
            let (_, pseudonyms, _) = payload
                .content_binding()
                .map_err(RoundDeduplicationError::InvalidVerifiedPayload)?;
            *duplicate_statuses = pseudonyms
                .iter()
                .map(|pseudonym| {
                    seen.insert_if_absent(pseudonym)
                        .map(|inserted| {
                            if inserted {
                                AtomDuplicateStatus::New
                            } else {
                                AtomDuplicateStatus::Duplicate
                            }
                        })
                        .map_err(RoundDeduplicationError::SeenSet)
                })
                .collect::<Result<Vec<_>, _>>()?;
        }
        Ok(self)
    }

    pub(super) fn classify_duplicates(
        mut self,
        seen: &PersistentSeenSet,
    ) -> Result<Self, RoundDeduplicationError> {
        let mut new_in_round = HashSet::new();
        for channel in &mut self.channels {
            let DecodedChannel::Payload {
                payload,
                self_binding,
                content_proof,
                duplicate_statuses,
            } = channel
            else {
                continue;
            };
            if *self_binding != SelfBindingStatus::Valid
                || *content_proof != ContentProofStatus::Valid
            {
                continue;
            }
            let (_, pseudonyms, _) = payload
                .content_binding()
                .map_err(RoundDeduplicationError::InvalidVerifiedPayload)?;
            *duplicate_statuses = pseudonyms
                .iter()
                .map(|pseudonym| {
                    let encoded = pseudonym
                        .to_bytes()
                        .map_err(ChannelCryptoError::Pseudonym)
                        .map_err(RoundDeduplicationError::InvalidVerifiedPayload)?;
                    let already_seen = seen
                        .contains(pseudonym)
                        .map_err(RoundDeduplicationError::SeenSet)?;
                    Ok(if already_seen || !new_in_round.insert(encoded) {
                        AtomDuplicateStatus::Duplicate
                    } else {
                        AtomDuplicateStatus::New
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
        }
        Ok(self)
    }

    pub fn decode_with_credentials(
        context: MainRoundContext,
        channels: Vec<Vec<u8>>,
        parameters: &CredentialPublicParameters,
    ) -> Self {
        let channels = channels
            .into_iter()
            .map(|slot| {
                if slot.len() == CHANNEL_SLOT_SIZE && slot.iter().all(|byte| *byte == 0) {
                    return DecodedChannel::Empty;
                }
                match ChannelPayload::decode(&slot) {
                    Ok(payload) => {
                        let (self_binding, content_proof) = verify_payload(&payload, parameters);
                        let duplicate_statuses =
                            vec![AtomDuplicateStatus::NotChecked; payload.atoms().len()];
                        DecodedChannel::Payload {
                            payload,
                            self_binding,
                            content_proof,
                            duplicate_statuses,
                        }
                    }
                    Err(error) => DecodedChannel::Malformed(error),
                }
            })
            .collect();
        Self { context, channels }
    }
}

fn verify_payload(
    payload: &ChannelPayload,
    parameters: &CredentialPublicParameters,
) -> (SelfBindingStatus, ContentProofStatus) {
    let Some(recomputed_fingerprints) = self_bound_fingerprints(payload) else {
        return (SelfBindingStatus::Failed, ContentProofStatus::NotChecked);
    };
    let Ok((_, pseudonyms, proof)) = payload.content_binding() else {
        return (SelfBindingStatus::Valid, ContentProofStatus::Malformed);
    };
    let content_proof = if proof
        .verify(&recomputed_fingerprints, &pseudonyms, parameters)
        .is_ok()
    {
        ContentProofStatus::Valid
    } else {
        ContentProofStatus::Failed
    };
    (SelfBindingStatus::Valid, content_proof)
}

fn self_bound_fingerprints(payload: &ChannelPayload) -> Option<Vec<[u8; 32]>> {
    let recomputed = compute_atom_fingerprints(payload.stix_bundle()).ok()?;
    let mut recomputed_set = recomputed.clone();
    let mut claimed = payload
        .atoms()
        .iter()
        .map(|atom| *atom.fingerprint())
        .collect::<Vec<_>>();
    recomputed_set.sort_unstable();
    claimed.sort_unstable();
    if claimed == recomputed_set {
        Some(recomputed)
    } else {
        None
    }
}

#[derive(Clone)]
pub(super) struct AggregateVerifier {
    expected_context: MainRoundContext,
    expected_configuration_hash: ConfigurationHash,
    server_a_key: VerifyingKey,
    server_b_key: VerifyingKey,
}

impl AggregateVerifier {
    pub(super) fn new(
        expected_context: MainRoundContext,
        expected_configuration_hash: ConfigurationHash,
        server_a_key: VerifyingKey,
        server_b_key: VerifyingKey,
    ) -> Self {
        Self {
            expected_context,
            expected_configuration_hash,
            server_a_key,
            server_b_key,
        }
    }

    pub(super) fn verify(&self, request: &AggregateGroupRequest) -> Result<(), Status> {
        if request.version != u32::from(AGGREGATE_SHARE_VERSION) {
            return Err(Status::failed_precondition(
                "unsupported aggregate-share version",
            ));
        }

        if request.window != self.expected_context.window().get()
            || request.round != self.expected_context.round().get()
        {
            return Err(Status::failed_precondition(
                "unexpected aggregate-share context",
            ));
        }

        let configuration_hash = ConfigurationHash::new(
            request
                .configuration_hash
                .as_slice()
                .try_into()
                .map_err(|_| Status::invalid_argument("configuration hash must be 32 bytes"))?,
        );

        if configuration_hash != self.expected_configuration_hash {
            return Err(Status::failed_precondition("unexpected configuration hash"));
        }

        let (server, verifying_key) = match request.group {
            0 => (ShareServerId::A, &self.server_a_key),
            1 => (ShareServerId::B, &self.server_b_key),
            _ => return Err(Status::invalid_argument("unknown ShareServer group")),
        };

        let channel_data = &request
            .share
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("aggregate share must be set"))?
            .data;

        let signature = Signature::try_from(request.signature.as_slice())
            .map_err(|_| Status::invalid_argument("signature must be 64 bytes"))?;

        let signing_bytes = AggregateSharePayload::signing_bytes_from_parts(
            AGGREGATE_SHARE_VERSION,
            server,
            self.expected_context,
            configuration_hash,
            channel_data,
        )
        .map_err(|error| Status::invalid_argument(error.to_string()))?;

        verifying_key
            .verify_strict(&signing_bytes, &signature)
            .map_err(|_| Status::unauthenticated("invalid aggregate-share signature"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        compute_atom_fingerprints, AtomEntry, CredentialAttributes, MemberCredential, MemberSecret,
        RoundId, SignedAggregateShare, WindowId,
    };
    use ark_bls12_381::Fr;
    use ed25519_dalek::SigningKey;
    use rand::{rngs::StdRng, SeedableRng};
    use spectrum::proto::Share;
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };
    use tonic::Code;

    struct TestFile(PathBuf);

    impl TestFile {
        fn new(name: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            Self(
                std::env::temp_dir()
                    .join(format!("chorus-{name}-{}-{nonce}.bin", std::process::id())),
            )
        }
    }

    impl Drop for TestFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    fn context() -> MainRoundContext {
        MainRoundContext::new(WindowId::new(7), RoundId::try_from(2).unwrap())
    }

    fn issued_credential() -> (MemberSecret, MemberCredential, CredentialPublicParameters) {
        let authority =
            crate::authority::AuthorityKeyManager::generate_with_rng(&mut StdRng::seed_from_u64(1));
        let parameters = authority.public_parameters().clone();
        let secret = MemberSecret::generate_with_rng(&mut StdRng::seed_from_u64(2));
        let attributes = CredentialAttributes::from_scalars(Fr::from(7), Fr::from(8), Fr::from(9));
        let (request, pending) = secret.start_credential_request(&parameters).unwrap();
        let blind_credential = authority
            .issue_blind_credential(&request, &attributes)
            .unwrap();
        let credential = pending
            .finish(&secret, blind_credential, attributes, &parameters)
            .unwrap();
        (secret, credential, parameters)
    }

    fn signed_request(server: ShareServerId) -> (AggregateVerifier, AggregateGroupRequest) {
        let context = context();
        let configuration_hash = ConfigurationHash::new([0x42; 32]);
        let server_a_key = SigningKey::from_bytes(&[7; 32]);
        let server_b_key = SigningKey::from_bytes(&[9; 32]);

        let signing_key = match server {
            ShareServerId::A => &server_a_key,
            ShareServerId::B => &server_b_key,
        };

        let signed = SignedAggregateShare::sign(
            AggregateSharePayload::new(server, context, configuration_hash, vec![vec![1, 2, 3]]),
            signing_key,
        )
        .unwrap();

        let (payload, signature) = signed.into_parts();
        let group = match server {
            ShareServerId::A => 0,
            ShareServerId::B => 1,
        };

        let verifier = AggregateVerifier::new(
            context,
            configuration_hash,
            server_a_key.verifying_key(),
            server_b_key.verifying_key(),
        );

        let request = AggregateGroupRequest {
            share: Some(Share {
                data: payload.into_channel_data(),
            }),
            group,
            window: context.window().get(),
            round: context.round().get(),
            version: u32::from(AGGREGATE_SHARE_VERSION),
            configuration_hash: configuration_hash.as_bytes().to_vec(),
            signature: signature.to_vec(),
        };

        (verifier, request)
    }

    #[test]
    fn valid_shares_from_both_servers_are_accepted() {
        for server in [ShareServerId::A, ShareServerId::B] {
            let (verifier, request) = signed_request(server);
            assert!(verifier.verify(&request).is_ok());
        }
    }

    #[test]
    fn changed_channel_data_is_rejected() {
        let (verifier, mut request) = signed_request(ShareServerId::A);
        request.share.as_mut().unwrap().data[0][0] ^= 0xff;
        let error = verifier.verify(&request).unwrap_err();
        assert_eq!(error.code(), Code::Unauthenticated);
    }

    #[test]
    fn changed_server_role_is_rejected() {
        let (verifier, mut request) = signed_request(ShareServerId::A);
        request.group = 1;
        let error = verifier.verify(&request).unwrap_err();
        assert_eq!(error.code(), Code::Unauthenticated);
    }

    #[test]
    fn unexpected_configuration_is_rejected() {
        let (verifier, mut request) = signed_request(ShareServerId::A);
        request.configuration_hash = vec![0x99; 32];
        let error = verifier.verify(&request).unwrap_err();
        assert_eq!(error.code(), Code::FailedPrecondition);
    }

    #[test]
    fn unexpected_round_is_rejected() {
        let (verifier, mut request) = signed_request(ShareServerId::A);
        request.round += 1;
        let error = verifier.verify(&request).unwrap_err();
        assert_eq!(error.code(), Code::FailedPrecondition);
    }

    #[test]
    fn decoded_round_distinguishes_empty_and_payload_channels() {
        let (_, _, parameters) = issued_credential();
        let stix = br#"{"objects":[{"type":"domain-name","value":"example.com"}]}"#.to_vec();
        let fingerprint = compute_atom_fingerprints(&stix).unwrap()[0];
        let payload =
            ChannelPayload::new(vec![AtomEntry::new(fingerprint, [2; 48])], vec![3], stix).unwrap();
        let round = DecodedRound::decode_with_credentials(
            context(),
            vec![vec![0; CHANNEL_SLOT_SIZE], payload.encode()],
            &parameters,
        );
        assert_eq!(round.context(), context());
        assert_eq!(
            round.channels(),
            &[
                DecodedChannel::Empty,
                DecodedChannel::Payload {
                    payload,
                    self_binding: SelfBindingStatus::Valid,
                    content_proof: ContentProofStatus::Malformed,
                    duplicate_statuses: vec![AtomDuplicateStatus::NotChecked],
                }
            ]
        );
    }

    #[test]
    fn wrong_claimed_fingerprint_is_marked_as_self_binding_failed() {
        let (_, _, parameters) = issued_credential();
        let stix = br#"{"objects":[{"type":"domain-name","value":"example.com"}]}"#.to_vec();
        let payload =
            ChannelPayload::new(vec![AtomEntry::new([0xff; 32], [2; 48])], vec![3], stix).unwrap();
        let round =
            DecodedRound::decode_with_credentials(context(), vec![payload.encode()], &parameters);
        assert!(matches!(
            &round.channels()[0],
            DecodedChannel::Payload {
                self_binding: SelfBindingStatus::Failed,
                content_proof: ContentProofStatus::NotChecked,
                ..
            }
        ));
    }

    #[test]
    fn atom_order_does_not_affect_self_binding() {
        let stix = br#"{"objects":[
            {"type":"domain-name","value":"example.com"},
            {"type":"ipv4-addr","value":"192.0.2.1"}
        ]}"#
        .to_vec();
        let mut fingerprints = compute_atom_fingerprints(&stix).unwrap();
        fingerprints.reverse();
        let atoms = fingerprints
            .into_iter()
            .map(|fingerprint| AtomEntry::new(fingerprint, [2; 48]))
            .collect();
        let payload = ChannelPayload::new(atoms, vec![3], stix).unwrap();
        assert!(self_bound_fingerprints(&payload).is_some());
    }

    #[test]
    fn malformed_channel_does_not_hide_other_channels() {
        let (_, _, parameters) = issued_credential();
        let round = DecodedRound::decode_with_credentials(
            context(),
            vec![
                vec![0; CHANNEL_SLOT_SIZE],
                vec![1],
                vec![0; CHANNEL_SLOT_SIZE],
            ],
            &parameters,
        );
        assert_eq!(
            round.channels(),
            &[
                DecodedChannel::Empty,
                DecodedChannel::Malformed(ChannelPayloadError::InvalidSlotLength(1)),
                DecodedChannel::Empty
            ]
        );
    }

    #[test]
    fn valid_content_proof_is_accepted_after_self_binding() {
        let (secret, credential, parameters) = issued_credential();
        let stix = br#"{"objects":[{"type":"domain-name","value":"example.com"}]}"#.to_vec();
        let fingerprints = compute_atom_fingerprints(&stix).unwrap();
        let (pseudonyms, proof) = credential
            .prove_content_binding(&secret, &fingerprints, &parameters)
            .unwrap();
        let payload =
            ChannelPayload::from_content_binding(fingerprints, &pseudonyms, &proof, stix).unwrap();
        let round =
            DecodedRound::decode_with_credentials(context(), vec![payload.encode()], &parameters);
        assert!(matches!(
            &round.channels()[0],
            DecodedChannel::Payload {
                self_binding: SelfBindingStatus::Valid,
                content_proof: ContentProofStatus::Valid,
                ..
            }
        ));
    }

    #[test]
    fn valid_atoms_are_marked_new_or_duplicate_independently() {
        let (secret, credential, parameters) = issued_credential();
        let stix = br#"{"objects":[
            {"type":"domain-name","value":"example.com"},
            {"type":"ipv4-addr","value":"192.0.2.1"}
        ]}"#
        .to_vec();
        let fingerprints = compute_atom_fingerprints(&stix).unwrap();
        let (pseudonyms, proof) = credential
            .prove_content_binding(&secret, &fingerprints, &parameters)
            .unwrap();
        let payload =
            ChannelPayload::from_content_binding(fingerprints, &pseudonyms, &proof, stix).unwrap();
        let path = TestFile::new("round-deduplication");
        let seen = PersistentSeenSet::open(&path.0).unwrap();
        assert!(seen.insert_if_absent(&pseudonyms[0]).unwrap());

        let round =
            DecodedRound::decode_with_credentials(context(), vec![payload.encode()], &parameters)
                .deduplicate(&seen)
                .unwrap();
        assert!(matches!(
            &round.channels()[0],
            DecodedChannel::Payload {
                duplicate_statuses,
                ..
            } if duplicate_statuses == &[
                AtomDuplicateStatus::Duplicate,
                AtomDuplicateStatus::New
            ]
        ));
        assert_eq!(seen.len().unwrap(), 2);

        drop(seen);
        let reopened = PersistentSeenSet::open(&path.0).unwrap();
        let repeated =
            DecodedRound::decode_with_credentials(context(), vec![payload.encode()], &parameters)
                .deduplicate(&reopened)
                .unwrap();
        assert!(matches!(
            &repeated.channels()[0],
            DecodedChannel::Payload {
                duplicate_statuses,
                ..
            } if duplicate_statuses == &[
                AtomDuplicateStatus::Duplicate,
                AtomDuplicateStatus::Duplicate
            ]
        ));
    }

    #[test]
    fn malformed_content_proof_is_distinguished_from_invalid_proof() {
        let (_, _, parameters) = issued_credential();
        let stix = br#"{"objects":[{"type":"domain-name","value":"example.com"}]}"#.to_vec();
        let fingerprint = compute_atom_fingerprints(&stix).unwrap()[0];
        let payload =
            ChannelPayload::new(vec![AtomEntry::new(fingerprint, [2; 48])], vec![3], stix).unwrap();
        let round =
            DecodedRound::decode_with_credentials(context(), vec![payload.encode()], &parameters);
        assert!(matches!(
            &round.channels()[0],
            DecodedChannel::Payload {
                self_binding: SelfBindingStatus::Valid,
                content_proof: ContentProofStatus::Malformed,
                ..
            }
        ));
    }

    #[test]
    fn well_formed_proof_with_wrong_pseudonym_is_marked_failed() {
        let (secret, credential, parameters) = issued_credential();
        let stix = br#"{"objects":[{"type":"domain-name","value":"example.com"}]}"#.to_vec();
        let fingerprints = compute_atom_fingerprints(&stix).unwrap();
        let (_, proof) = credential
            .prove_content_binding(&secret, &fingerprints, &parameters)
            .unwrap();
        let other_secret = MemberSecret::generate_with_rng(&mut StdRng::seed_from_u64(4));
        let wrong_pseudonym = other_secret
            .content_pseudonym(&fingerprints[0])
            .unwrap()
            .to_bytes()
            .unwrap();
        let payload = ChannelPayload::new(
            vec![AtomEntry::new(fingerprints[0], wrong_pseudonym)],
            proof.encode().unwrap(),
            stix,
        )
        .unwrap();
        let path = TestFile::new("failed-proof-deduplication");
        let seen = PersistentSeenSet::open(&path.0).unwrap();
        let round =
            DecodedRound::decode_with_credentials(context(), vec![payload.encode()], &parameters)
                .deduplicate(&seen)
                .unwrap();
        assert!(matches!(
            &round.channels()[0],
            DecodedChannel::Payload {
                self_binding: SelfBindingStatus::Valid,
                content_proof: ContentProofStatus::Failed,
                duplicate_statuses,
                ..
            } if duplicate_statuses == &[AtomDuplicateStatus::NotChecked]
        ));
        assert!(seen.is_empty().unwrap());
    }
}
