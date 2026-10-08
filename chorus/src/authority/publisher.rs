use super::{
    publication::{
        PublishedAtomStatus, PublishedChannel, PublishedChannelStatus, PublishedRound,
        SignedPublishedRound,
    },
    publication_log::{PersistentPublicationLog, PublicationAppendStatus},
    seen_set::PersistentSeenSet,
    verifier::{AggregateVerifier, DecodedRound},
};
use crate::{
    ConfigurationHash, ContentPseudonym, CredentialPublicParameters, MainRoundContext,
    RoundLifecycle, RoundLifecycleError,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use spectrum::{
    config::Store,
    net::Config as NetConfig,
    proto::AggregateGroupRequest,
    protocols::wrapper::ProtocolWrapper,
    publisher::{self as spectrum_publisher, Remote},
    services::PublisherInfo,
};
use std::{
    error::Error,
    future::Future,
    io,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex, Notify};
use tonic::Status;

type BoxedError = Box<dyn Error + Sync + Send>;

struct AuthorityRoundState {
    lifecycle: RoundLifecycle,
    completion: Option<Result<Vec<Vec<u8>>, RoundLifecycleError>>,
}

#[derive(Clone)]
struct AuthorityRemote {
    expected_context: MainRoundContext,
    verifier: AggregateVerifier,
    state: Arc<Mutex<AuthorityRoundState>>,
    completed: Arc<Notify>,
}

impl AuthorityRemote {
    fn new(
        expected_context: MainRoundContext,
        verifier: AggregateVerifier,
        completed: Arc<Notify>,
    ) -> Self {
        Self {
            expected_context,
            verifier,
            state: Arc::new(Mutex::new(AuthorityRoundState {
                lifecycle: RoundLifecycle::new(expected_context),
                completion: None,
            })),
            completed,
        }
    }

    async fn take_completion(&self) -> Option<Result<Vec<Vec<u8>>, RoundLifecycleError>> {
        self.state.lock().await.completion.take()
    }
}

#[tonic::async_trait]
impl Remote for AuthorityRemote {
    async fn start(&self) {}

    fn validate_aggregate(&self, request: &AggregateGroupRequest) -> Result<(), Status> {
        self.verifier.verify(request)
    }

    async fn done(&self, result: Vec<Vec<u8>>) {
        let mut state = self.state.lock().await;
        let completion = state
            .lifecycle
            .finalize(self.expected_context)
            .map(|()| result);
        state.completion = Some(completion);
        drop(state);
        self.completed.notify_one();
    }
}

/// Runs the Authority data path using Spectrum's existing publisher.
///
/// This stage verifies aggregate shares and credential proofs, classifies
/// pseudonyms, and appends a signed publication to the Authority log.
pub async fn run_development<C, F>(
    expected_context: MainRoundContext,
    configuration_hash: ConfigurationHash,
    server_a_key: VerifyingKey,
    server_b_key: VerifyingKey,
    credential_parameters: CredentialPublicParameters,
    seen_set: PersistentSeenSet,
    authority_signing_key: SigningKey,
    publication_log: PersistentPublicationLog,
    config: C,
    protocol: Option<ProtocolWrapper>,
    net: NetConfig,
    shutdown: F,
    delay_ms: i64,
) -> Result<Option<SignedPublishedRound>, BoxedError>
where
    C: Store + Sync + Send,
    F: Future<Output = ()> + Send + 'static,
{
    if let Some(existing) = publication_log.get(expected_context)? {
        reconcile_seen_set(&publication_log, &seen_set)?;
        return Ok(Some(existing));
    }
    let published_at_unix = || {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
            .map(|duration| duration.as_secs())
    };
    let Some(protocol) = protocol else {
        return publish_decoded_round(
            DecodedRound::empty(expected_context),
            published_at_unix()?,
            &seen_set,
            &publication_log,
            &authority_signing_key,
        )
        .map(Some);
    };
    let expected_window = expected_context.window().get();
    let expected_round = expected_context.round().get();

    let completed = Arc::new(Notify::new());
    let verifier = AggregateVerifier::new(
        expected_context,
        configuration_hash,
        server_a_key,
        server_b_key,
    );
    let remote = AuthorityRemote::new(expected_context, verifier, completed.clone());
    let remote_result = remote.clone();

    let round_shutdown = async move {
        tokio::select! {
            _ = shutdown => {}
            _ = completed.notified() => {}
        }
    };

    spectrum_publisher::run_for_round(
        config,
        protocol,
        PublisherInfo::new(),
        expected_window,
        expected_round,
        net,
        remote,
        round_shutdown,
        delay_ms,
    )
    .await?;

    match remote_result.take_completion().await {
        Some(Ok(result)) => {
            let decoded = DecodedRound::decode_with_credentials(
                expected_context,
                result,
                &credential_parameters,
            );
            publish_decoded_round(
                decoded,
                published_at_unix()?,
                &seen_set,
                &publication_log,
                &authority_signing_key,
            )
            .map(Some)
        }
        Some(Err(error)) => Err(Box::new(error)),
        None => Ok(None),
    }
}

fn publish_decoded_round(
    decoded: DecodedRound,
    published_at_unix: u64,
    seen_set: &PersistentSeenSet,
    publication_log: &PersistentPublicationLog,
    signing_key: &SigningKey,
) -> Result<SignedPublishedRound, BoxedError> {
    reconcile_seen_set(publication_log, seen_set)?;
    if let Some(existing) = publication_log.get(decoded.context())? {
        return Ok(existing);
    }
    let classified = decoded.classify_duplicates(seen_set)?;
    let previous_hash = publication_log.last_hash()?.unwrap_or([0; 32]);
    let round = PublishedRound::from_decoded(&classified, published_at_unix, previous_hash)?;
    let signed = SignedPublishedRound::sign(round, signing_key)?;
    let result = signed.clone();
    let committed = match publication_log.append_if_absent(signed)? {
        PublicationAppendStatus::Inserted => result,
        PublicationAppendStatus::AlreadyPresent => {
            publication_log.get(classified.context())?.ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "published round disappeared")
            })?
        }
    };
    apply_publication_to_seen_set(&committed, seen_set)?;
    Ok(committed)
}

fn reconcile_seen_set(
    publication_log: &PersistentPublicationLog,
    seen_set: &PersistentSeenSet,
) -> Result<(), BoxedError> {
    for publication in publication_log.publications()? {
        apply_publication_to_seen_set(&publication, seen_set)?;
    }
    Ok(())
}

fn apply_publication_to_seen_set(
    publication: &SignedPublishedRound,
    seen_set: &PersistentSeenSet,
) -> Result<(), BoxedError> {
    for channel in publication.round().channels() {
        let PublishedChannel::Payload { status, atoms, .. } = channel else {
            continue;
        };
        if *status != PublishedChannelStatus::Ok {
            continue;
        }
        for atom in atoms {
            if atom.status() == PublishedAtomStatus::New {
                let pseudonym = ContentPseudonym::from_bytes(atom.pseudonym())?;
                seen_set.insert_if_absent(&pseudonym)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        authority::AuthorityKeyManager, member, CredentialAttributes, MemberCredentialBundle,
        MemberSecret, RoundId, RoundStatus, WindowId,
    };
    use ark_bls12_381::Fr;
    use rand::{rngs::StdRng, SeedableRng};
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

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

    fn context(window: u64, round: u32) -> MainRoundContext {
        MainRoundContext::new(WindowId::new(window), RoundId::try_from(round).unwrap())
    }

    fn decoded_round() -> DecodedRound {
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
        let stix = br#"{"objects":[{"type":"domain-name","value":"example.com"}]}"#.to_vec();
        let payload = member::create_broadcast_payload(&credentials, parameters, stix).unwrap();
        DecodedRound::decode_with_credentials(context(3, 2), vec![payload.encode()], parameters)
    }

    #[tokio::test]
    async fn publisher_completion_finalizes_the_round() {
        let expected_context = context(3, 2);
        let completed = Arc::new(Notify::new());
        let verifier = AggregateVerifier::new(
            expected_context,
            ConfigurationHash::new([0x42; 32]),
            ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key(),
            ed25519_dalek::SigningKey::from_bytes(&[9; 32]).verifying_key(),
        );
        let remote = AuthorityRemote::new(expected_context, verifier, completed.clone());
        let result = vec![vec![1, 2, 3], vec![4, 5]];
        remote.done(result.clone()).await;
        let state = remote.state.lock().await;
        assert_eq!(state.lifecycle.status(), RoundStatus::Finalized);
        assert_eq!(state.completion, Some(Ok(result)));
    }

    #[test]
    fn publishing_the_same_round_returns_the_first_signed_bytes() {
        let seen_path = TestFile::new("publisher-seen");
        let log_path = TestFile::new("publisher-log");
        let seen = PersistentSeenSet::open(&seen_path.0).unwrap();
        let signing_key = SigningKey::from_bytes(&[11; 32]);
        let log = PersistentPublicationLog::open(&log_path.0, signing_key.verifying_key()).unwrap();
        let decoded = decoded_round();
        let first = publish_decoded_round(decoded.clone(), 10, &seen, &log, &signing_key).unwrap();
        let repeated = publish_decoded_round(decoded, 20, &seen, &log, &signing_key).unwrap();
        assert_eq!(first.encode().unwrap(), repeated.encode().unwrap());
        assert_eq!(seen.len().unwrap(), 1);
        assert_eq!(log.len().unwrap(), 1);
    }

    #[test]
    fn publication_log_repairs_an_empty_seen_set() {
        let first_seen_path = TestFile::new("publisher-first-seen");
        let repaired_seen_path = TestFile::new("publisher-repaired-seen");
        let log_path = TestFile::new("publisher-recovery-log");
        let first_seen = PersistentSeenSet::open(&first_seen_path.0).unwrap();
        let repaired_seen = PersistentSeenSet::open(&repaired_seen_path.0).unwrap();
        let signing_key = SigningKey::from_bytes(&[11; 32]);
        let log = PersistentPublicationLog::open(&log_path.0, signing_key.verifying_key()).unwrap();
        publish_decoded_round(decoded_round(), 10, &first_seen, &log, &signing_key).unwrap();
        assert!(repaired_seen.is_empty().unwrap());
        reconcile_seen_set(&log, &repaired_seen).unwrap();
        assert_eq!(repaired_seen.len().unwrap(), 1);
    }

    #[test]
    fn empty_window_creates_a_signed_empty_publication() {
        let seen_path = TestFile::new("publisher-empty-seen");
        let log_path = TestFile::new("publisher-empty-log");
        let seen = PersistentSeenSet::open(&seen_path.0).unwrap();
        let signing_key = SigningKey::from_bytes(&[12; 32]);
        let log = PersistentPublicationLog::open(&log_path.0, signing_key.verifying_key()).unwrap();
        let published = publish_decoded_round(
            DecodedRound::empty(context(4, 1)),
            10,
            &seen,
            &log,
            &signing_key,
        )
        .unwrap();

        assert!(published.round().channels().is_empty());
        assert!(published.verify(&signing_key.verifying_key()).is_ok());
        assert_eq!(log.len().unwrap(), 1);
        assert!(seen.is_empty().unwrap());
    }

    #[tokio::test]
    async fn empty_window_runtime_publishes_without_spectrum() {
        let seen_path = TestFile::new("publisher-empty-runtime-seen");
        let log_path = TestFile::new("publisher-empty-runtime-log");
        let seen = PersistentSeenSet::open(&seen_path.0).unwrap();
        let authority_signing_key = SigningKey::from_bytes(&[12; 32]);
        let log =
            PersistentPublicationLog::open(&log_path.0, authority_signing_key.verifying_key())
                .unwrap();
        let credential_authority =
            AuthorityKeyManager::generate_with_rng(&mut StdRng::seed_from_u64(13));
        let config = spectrum::config::factory::from_string("").await.unwrap();

        let published = run_development(
            context(4, 1),
            ConfigurationHash::new([0x42; 32]),
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
            SigningKey::from_bytes(&[8; 32]).verifying_key(),
            credential_authority.public_parameters().clone(),
            seen,
            authority_signing_key,
            log,
            config,
            None,
            NetConfig::with_free_port_localhost(None),
            std::future::pending(),
            0,
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(published.round().context(), context(4, 1));
        assert!(published.round().channels().is_empty());
    }
}
