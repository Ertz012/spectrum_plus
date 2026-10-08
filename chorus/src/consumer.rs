use crate::{
    authority::{
        PublicationEncodingError, PublicationVerificationError, PublishedAtomStatus,
        PublishedChannel, PublishedChannelStatus, SignedPublishedRound,
    },
    MainRoundContext,
};
use ed25519_dalek::VerifyingKey;
use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    error::Error,
    fmt,
    num::NonZeroU32,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThresholdAlert {
    context: MainRoundContext,
    channel_index: u32,
    fingerprint: [u8; 32],
    evidence_count: u32,
    record_hash: [u8; 32],
    stix_bundle: Vec<u8>,
}

impl ThresholdAlert {
    pub const fn context(&self) -> MainRoundContext {
        self.context
    }

    pub const fn channel_index(&self) -> u32 {
        self.channel_index
    }

    pub const fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }

    pub const fn evidence_count(&self) -> u32 {
        self.evidence_count
    }

    pub const fn record_hash(&self) -> &[u8; 32] {
        &self.record_hash
    }

    pub fn stix_bundle(&self) -> &[u8] {
        &self.stix_bundle
    }
}

pub trait ConsumerSink {
    type Error;

    fn emit(&mut self, alert: ThresholdAlert) -> Result<(), Self::Error>;
}

#[derive(Debug, Default)]
pub struct InMemorySink {
    alerts: Vec<ThresholdAlert>,
}

impl InMemorySink {
    pub fn alerts(&self) -> &[ThresholdAlert] {
        &self.alerts
    }

    pub fn into_alerts(self) -> Vec<ThresholdAlert> {
        self.alerts
    }
}

impl ConsumerSink for InMemorySink {
    type Error = Infallible;

    fn emit(&mut self, alert: ThresholdAlert) -> Result<(), Self::Error> {
        self.alerts.push(alert);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsumerConfigError {
    ZeroThreshold,
}

impl fmt::Display for ConsumerConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroThreshold => formatter.write_str("consumer threshold must be positive"),
        }
    }
}

impl Error for ConsumerConfigError {}

#[derive(Debug)]
pub enum ConsumerError<E> {
    Publication(PublicationEncodingError),
    InvalidAuthoritySignature(PublicationVerificationError),
    Sink(E),
}

impl<E: fmt::Display> fmt::Display for ConsumerError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Publication(error) => write!(formatter, "invalid publication: {error}"),
            Self::InvalidAuthoritySignature(error) => {
                write!(
                    formatter,
                    "publication is not signed by the Authority: {error}"
                )
            }
            Self::Sink(error) => write!(formatter, "consumer output failed: {error}"),
        }
    }
}

impl<E: Error + 'static> Error for ConsumerError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Publication(error) => Some(error),
            Self::InvalidAuthoritySignature(error) => Some(error),
            Self::Sink(error) => Some(error),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsumerIngestSummary {
    context: MainRoundContext,
    new_contributions: u32,
    ignored_atoms: u32,
    emitted_alerts: u32,
}

impl ConsumerIngestSummary {
    pub const fn context(&self) -> MainRoundContext {
        self.context
    }

    pub const fn new_contributions(&self) -> u32 {
        self.new_contributions
    }

    pub const fn ignored_atoms(&self) -> u32 {
        self.ignored_atoms
    }

    pub const fn emitted_alerts(&self) -> u32 {
        self.emitted_alerts
    }
}

pub struct ThresholdConsumer<S> {
    threshold: NonZeroU32,
    authority_key: VerifyingKey,
    contributions: HashMap<[u8; 32], HashSet<[u8; 48]>>,
    emitted: HashSet<[u8; 32]>,
    sink: S,
}

impl<S: ConsumerSink> ThresholdConsumer<S> {
    pub fn new(
        threshold: u32,
        authority_key: VerifyingKey,
        sink: S,
    ) -> Result<Self, ConsumerConfigError> {
        let threshold = NonZeroU32::new(threshold).ok_or(ConsumerConfigError::ZeroThreshold)?;
        Ok(Self {
            threshold,
            authority_key,
            contributions: HashMap::new(),
            emitted: HashSet::new(),
            sink,
        })
    }

    pub const fn threshold(&self) -> u32 {
        self.threshold.get()
    }

    pub fn sink(&self) -> &S {
        &self.sink
    }

    pub fn into_sink(self) -> S {
        self.sink
    }

    pub fn corroboration_count(&self, fingerprint: &[u8; 32]) -> usize {
        self.contributions.get(fingerprint).map_or(0, HashSet::len)
    }

    pub fn ingest(
        &mut self,
        encoded: &[u8],
    ) -> Result<ConsumerIngestSummary, ConsumerError<S::Error>> {
        let publication =
            SignedPublishedRound::decode(encoded).map_err(ConsumerError::Publication)?;
        publication
            .verify(&self.authority_key)
            .map_err(ConsumerError::InvalidAuthoritySignature)?;
        self.ingest_verified(&publication)
    }

    fn ingest_verified(
        &mut self,
        publication: &SignedPublishedRound,
    ) -> Result<ConsumerIngestSummary, ConsumerError<S::Error>> {
        let context = publication.round().context();
        let mut summary = ConsumerIngestSummary {
            context,
            new_contributions: 0,
            ignored_atoms: 0,
            emitted_alerts: 0,
        };
        for channel in publication.round().channels() {
            let PublishedChannel::Payload {
                index,
                status,
                record_hash,
                stix_bundle,
                atoms,
            } = channel
            else {
                continue;
            };
            if *status != PublishedChannelStatus::Ok {
                summary.ignored_atoms = summary
                    .ignored_atoms
                    .saturating_add(u32::try_from(atoms.len()).unwrap_or(u32::MAX));
                continue;
            }
            for atom in atoms {
                if atom.status() != PublishedAtomStatus::New {
                    summary.ignored_atoms = summary.ignored_atoms.saturating_add(1);
                    continue;
                }
                let evidence_count = {
                    let pseudonyms = self.contributions.entry(*atom.fingerprint()).or_default();
                    if pseudonyms.insert(*atom.pseudonym()) {
                        summary.new_contributions = summary.new_contributions.saturating_add(1);
                    }
                    u32::try_from(pseudonyms.len()).unwrap_or(u32::MAX)
                };
                if evidence_count >= self.threshold.get()
                    && !self.emitted.contains(atom.fingerprint())
                {
                    self.sink
                        .emit(ThresholdAlert {
                            context,
                            channel_index: *index,
                            fingerprint: *atom.fingerprint(),
                            evidence_count,
                            record_hash: *record_hash,
                            stix_bundle: stix_bundle.clone(),
                        })
                        .map_err(ConsumerError::Sink)?;
                    self.emitted.insert(*atom.fingerprint());
                    summary.emitted_alerts = summary.emitted_alerts.saturating_add(1);
                }
            }
        }
        Ok(summary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        authority::{AuthorityKeyManager, DecodedRound, PersistentSeenSet, PublishedRound},
        member, ChannelPayload, CredentialAttributes, MemberCredentialBundle, MemberSecret,
        RoundId, WindowId,
    };
    use ark_bls12_381::Fr;
    use ed25519_dalek::SigningKey;
    use rand::{rngs::StdRng, SeedableRng};
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

    struct TestFile(PathBuf);

    impl TestFile {
        fn new() -> Self {
            let id = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
            Self(
                std::env::temp_dir()
                    .join(format!("chorus-consumer-{}-{id}.bin", std::process::id())),
            )
        }
    }

    impl Drop for TestFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    fn credentials(authority: &AuthorityKeyManager, seed: u64) -> MemberCredentialBundle {
        let parameters = authority.public_parameters();
        let secret = MemberSecret::generate_with_rng(&mut StdRng::seed_from_u64(seed));
        let attributes = CredentialAttributes::from_scalars(Fr::from(1), Fr::from(2), Fr::from(3));
        let (request, pending) = secret.start_credential_request(parameters).unwrap();
        let blind = authority
            .issue_blind_credential(&request, &attributes)
            .unwrap();
        let credential = pending
            .finish(&secret, blind, attributes, parameters)
            .unwrap();
        MemberCredentialBundle::new(secret, credential, parameters).unwrap()
    }

    fn publication(
        authority: &AuthorityKeyManager,
        credentials: &MemberCredentialBundle,
        seen: &PersistentSeenSet,
        signing_key: &SigningKey,
        round: u32,
        stix_bundle: Vec<u8>,
    ) -> Vec<u8> {
        let payload = member::create_broadcast_payload(
            credentials,
            authority.public_parameters(),
            stix_bundle,
        )
        .unwrap();
        publication_from_payload(authority, seen, signing_key, round, payload)
    }

    fn publication_from_payload(
        authority: &AuthorityKeyManager,
        seen: &PersistentSeenSet,
        signing_key: &SigningKey,
        round: u32,
        payload: ChannelPayload,
    ) -> Vec<u8> {
        let context = MainRoundContext::new(WindowId::new(1), RoundId::try_from(round).unwrap());
        let decoded = DecodedRound::decode_with_credentials(
            context,
            vec![payload.encode()],
            authority.public_parameters(),
        )
        .deduplicate(seen)
        .unwrap();
        let round = PublishedRound::from_decoded(&decoded, u64::from(round), [0; 32]).unwrap();
        SignedPublishedRound::sign(round, signing_key)
            .unwrap()
            .encode()
            .unwrap()
    }

    #[test]
    fn distinct_members_reach_threshold_once_while_duplicates_do_not_count() {
        let authority = AuthorityKeyManager::generate_with_rng(&mut StdRng::seed_from_u64(1));
        let first_member = credentials(&authority, 2);
        let second_member = credentials(&authority, 3);
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let file = TestFile::new();
        let seen = PersistentSeenSet::open(&file.0).unwrap();
        let stix = br#"{"objects":[{"type":"domain-name","value":"example.com"}]}"#.to_vec();
        let first = publication(
            &authority,
            &first_member,
            &seen,
            &signing_key,
            1,
            stix.clone(),
        );
        let duplicate = publication(
            &authority,
            &first_member,
            &seen,
            &signing_key,
            2,
            stix.clone(),
        );
        let second = publication(&authority, &second_member, &seen, &signing_key, 3, stix);
        let mut consumer =
            ThresholdConsumer::new(2, signing_key.verifying_key(), InMemorySink::default())
                .unwrap();

        let first_summary = consumer.ingest(&first).unwrap();
        let duplicate_summary = consumer.ingest(&duplicate).unwrap();
        assert_eq!(first_summary.new_contributions(), 1);
        assert_eq!(duplicate_summary.new_contributions(), 0);
        assert_eq!(duplicate_summary.ignored_atoms(), 1);
        assert!(consumer.sink().alerts().is_empty());

        let second_summary = consumer.ingest(&second).unwrap();
        assert_eq!(second_summary.new_contributions(), 1);
        assert_eq!(second_summary.emitted_alerts(), 1);
        assert_eq!(consumer.sink().alerts().len(), 1);
        assert_eq!(consumer.sink().alerts()[0].evidence_count(), 2);

        let replay_summary = consumer.ingest(&second).unwrap();
        assert_eq!(replay_summary.new_contributions(), 0);
        assert_eq!(replay_summary.emitted_alerts(), 0);
        assert_eq!(consumer.sink().alerts().len(), 1);
    }

    #[test]
    fn marked_channels_are_ignored() {
        let authority = AuthorityKeyManager::generate_with_rng(&mut StdRng::seed_from_u64(4));
        let member = credentials(&authority, 5);
        let signing_key = SigningKey::from_bytes(&[8; 32]);
        let file = TestFile::new();
        let seen = PersistentSeenSet::open(&file.0).unwrap();
        let valid_stix = br#"{"objects":[{"type":"ipv4-addr","value":"192.0.2.1"}]}"#.to_vec();
        let payload =
            member::create_broadcast_payload(&member, authority.public_parameters(), valid_stix)
                .unwrap();
        let invalid_payload = ChannelPayload::new(
            payload.atoms().to_vec(),
            payload.proof().to_vec(),
            br#"{"objects":[]}"#.to_vec(),
        )
        .unwrap();
        let encoded = publication_from_payload(&authority, &seen, &signing_key, 1, invalid_payload);
        let mut consumer =
            ThresholdConsumer::new(1, signing_key.verifying_key(), InMemorySink::default())
                .unwrap();

        let summary = consumer.ingest(&encoded).unwrap();
        assert_eq!(summary.new_contributions(), 0);
        assert_eq!(summary.ignored_atoms(), 1);
        assert!(consumer.sink().alerts().is_empty());
    }

    #[test]
    fn invalid_signatures_and_versions_are_rejected_before_counting() {
        let authority = AuthorityKeyManager::generate_with_rng(&mut StdRng::seed_from_u64(6));
        let member = credentials(&authority, 7);
        let signing_key = SigningKey::from_bytes(&[9; 32]);
        let file = TestFile::new();
        let seen = PersistentSeenSet::open(&file.0).unwrap();
        let stix = br#"{"objects":[{"type":"domain-name","value":"example.org"}]}"#.to_vec();
        let encoded = publication(&authority, &member, &seen, &signing_key, 1, stix);
        let mut consumer = ThresholdConsumer::new(
            1,
            SigningKey::from_bytes(&[10; 32]).verifying_key(),
            InMemorySink::default(),
        )
        .unwrap();
        assert!(matches!(
            consumer.ingest(&encoded),
            Err(ConsumerError::InvalidAuthoritySignature(_))
        ));
        assert!(consumer.sink().alerts().is_empty());

        let mut invalid_version = encoded;
        invalid_version[8..10].copy_from_slice(&2_u16.to_be_bytes());
        assert!(matches!(
            consumer.ingest(&invalid_version),
            Err(ConsumerError::Publication(
                PublicationEncodingError::UnsupportedVersion(2)
            ))
        ));
        assert!(consumer.sink().alerts().is_empty());
    }

    #[test]
    fn threshold_must_be_positive() {
        assert!(matches!(
            ThresholdConsumer::new(
                0,
                SigningKey::from_bytes(&[11; 32]).verifying_key(),
                InMemorySink::default()
            ),
            Err(ConsumerConfigError::ZeroThreshold)
        ));
    }
}
