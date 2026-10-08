use super::publication::{
    PublicationEncodingError, PublicationVerificationError, SignedPublishedRound,
};
use crate::MainRoundContext;
use ed25519_dalek::VerifyingKey;
use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
    sync::Mutex,
};

const MAGIC: &[u8; 8] = b"CHPUBLOG";
const HEADER_SIZE: usize = MAGIC.len() + 2;
pub const PUBLICATION_LOG_VERSION: u16 = 1;

pub struct PersistentPublicationLog {
    verifying_key: VerifyingKey,
    state: Mutex<PublicationLogState>,
}

struct PublicationLogState {
    file: File,
    rounds: BTreeMap<MainRoundContext, SignedPublishedRound>,
    last_hash: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationAppendStatus {
    Inserted,
    AlreadyPresent,
}

#[derive(Debug)]
pub enum PublicationLogError {
    Io(io::Error),
    TruncatedHeader,
    InvalidMagic,
    UnsupportedVersion(u16),
    TruncatedRecord,
    RecordTooLarge(usize),
    Publication(PublicationEncodingError),
    Verification(PublicationVerificationError),
    NonIncreasingContext {
        previous: MainRoundContext,
        next: MainRoundContext,
    },
    BrokenHashChain {
        context: MainRoundContext,
    },
    ConflictingRound(MainRoundContext),
    LockPoisoned,
}

impl fmt::Display for PublicationLogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "publication-log I/O failed: {error}"),
            Self::TruncatedHeader => formatter.write_str("publication-log header is truncated"),
            Self::InvalidMagic => formatter.write_str("file is not a CHORUS publication-log"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported publication-log version: {version}")
            }
            Self::TruncatedRecord => {
                formatter.write_str("publication-log contains a truncated record")
            }
            Self::RecordTooLarge(length) => {
                write!(
                    formatter,
                    "publication-log record is too large: {length} bytes"
                )
            }
            Self::Publication(error) => {
                write!(formatter, "invalid publication-log record: {error}")
            }
            Self::Verification(error) => {
                write!(formatter, "untrusted publication-log record: {error}")
            }
            Self::NonIncreasingContext { previous, next } => write!(
                formatter,
                "publication context {next:?} must be later than {previous:?}"
            ),
            Self::BrokenHashChain { context } => {
                write!(
                    formatter,
                    "publication {context:?} has the wrong previous hash"
                )
            }
            Self::ConflictingRound(context) => {
                write!(
                    formatter,
                    "publication {context:?} already exists with different bytes"
                )
            }
            Self::LockPoisoned => formatter.write_str("publication-log lock is poisoned"),
        }
    }
}

impl Error for PublicationLogError {}

impl From<io::Error> for PublicationLogError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl PersistentPublicationLog {
    pub fn open(
        path: impl AsRef<Path>,
        verifying_key: VerifyingKey,
    ) -> Result<Self, PublicationLogError> {
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(path)?;
        let mut encoded = Vec::new();
        file.read_to_end(&mut encoded)?;
        if encoded.is_empty() {
            file.write_all(MAGIC)?;
            file.write_all(&PUBLICATION_LOG_VERSION.to_be_bytes())?;
            file.sync_all()?;
            encoded.extend_from_slice(MAGIC);
            encoded.extend_from_slice(&PUBLICATION_LOG_VERSION.to_be_bytes());
        }
        let (rounds, last_hash) = decode_records(&encoded, &verifying_key)?;
        Ok(Self {
            verifying_key,
            state: Mutex::new(PublicationLogState {
                file,
                rounds,
                last_hash,
            }),
        })
    }

    pub fn get(
        &self,
        context: MainRoundContext,
    ) -> Result<Option<SignedPublishedRound>, PublicationLogError> {
        self.state
            .lock()
            .map(|state| state.rounds.get(&context).cloned())
            .map_err(|_| PublicationLogError::LockPoisoned)
    }

    pub fn last_hash(&self) -> Result<Option<[u8; 32]>, PublicationLogError> {
        self.state
            .lock()
            .map(|state| state.last_hash)
            .map_err(|_| PublicationLogError::LockPoisoned)
    }

    pub fn publications(&self) -> Result<Vec<SignedPublishedRound>, PublicationLogError> {
        self.state
            .lock()
            .map(|state| state.rounds.values().cloned().collect())
            .map_err(|_| PublicationLogError::LockPoisoned)
    }

    pub fn append_if_absent(
        &self,
        publication: SignedPublishedRound,
    ) -> Result<PublicationAppendStatus, PublicationLogError> {
        publication
            .verify(&self.verifying_key)
            .map_err(PublicationLogError::Verification)?;
        let context = publication.round().context();
        let encoded = publication
            .encode()
            .map_err(PublicationLogError::Publication)?;
        let hash = publication
            .hash()
            .map_err(PublicationLogError::Publication)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| PublicationLogError::LockPoisoned)?;
        if let Some(existing) = state.rounds.get(&context) {
            let existing = existing
                .encode()
                .map_err(PublicationLogError::Publication)?;
            return if existing == encoded {
                Ok(PublicationAppendStatus::AlreadyPresent)
            } else {
                Err(PublicationLogError::ConflictingRound(context))
            };
        }
        if let Some(previous) = state.rounds.last_key_value().map(|(context, _)| *context) {
            if context <= previous {
                return Err(PublicationLogError::NonIncreasingContext {
                    previous,
                    next: context,
                });
            }
        }
        let expected_previous_hash = state.last_hash.unwrap_or([0; 32]);
        if publication.round().previous_round_hash() != &expected_previous_hash {
            return Err(PublicationLogError::BrokenHashChain { context });
        }
        let length = u32::try_from(encoded.len())
            .map_err(|_| PublicationLogError::RecordTooLarge(encoded.len()))?;
        let previous_length = state.file.metadata()?.len();
        if let Err(error) = state
            .file
            .write_all(&length.to_be_bytes())
            .and_then(|()| state.file.write_all(&encoded))
            .and_then(|()| state.file.sync_data())
        {
            state.file.set_len(previous_length)?;
            state.file.sync_data()?;
            return Err(PublicationLogError::Io(error));
        }
        state.rounds.insert(context, publication);
        state.last_hash = Some(hash);
        Ok(PublicationAppendStatus::Inserted)
    }

    pub fn len(&self) -> Result<usize, PublicationLogError> {
        self.state
            .lock()
            .map(|state| state.rounds.len())
            .map_err(|_| PublicationLogError::LockPoisoned)
    }
}

fn decode_records(
    encoded: &[u8],
    verifying_key: &VerifyingKey,
) -> Result<
    (
        BTreeMap<MainRoundContext, SignedPublishedRound>,
        Option<[u8; 32]>,
    ),
    PublicationLogError,
> {
    if encoded.len() < HEADER_SIZE {
        return Err(PublicationLogError::TruncatedHeader);
    }
    if &encoded[..MAGIC.len()] != MAGIC {
        return Err(PublicationLogError::InvalidMagic);
    }
    let version = u16::from_be_bytes([encoded[MAGIC.len()], encoded[MAGIC.len() + 1]]);
    if version != PUBLICATION_LOG_VERSION {
        return Err(PublicationLogError::UnsupportedVersion(version));
    }
    let mut position = HEADER_SIZE;
    let mut rounds = BTreeMap::new();
    let mut last_context = None;
    let mut last_hash = None;
    while position < encoded.len() {
        let length_end = position
            .checked_add(4)
            .ok_or(PublicationLogError::TruncatedRecord)?;
        let length = encoded
            .get(position..length_end)
            .ok_or(PublicationLogError::TruncatedRecord)?;
        let length = usize::try_from(u32::from_be_bytes(length.try_into().unwrap()))
            .map_err(|_| PublicationLogError::TruncatedRecord)?;
        position = length_end;
        let record_end = position
            .checked_add(length)
            .ok_or(PublicationLogError::TruncatedRecord)?;
        let record = encoded
            .get(position..record_end)
            .ok_or(PublicationLogError::TruncatedRecord)?;
        let publication =
            SignedPublishedRound::decode(record).map_err(PublicationLogError::Publication)?;
        publication
            .verify(verifying_key)
            .map_err(PublicationLogError::Verification)?;
        let context = publication.round().context();
        if let Some(previous) = last_context {
            if context <= previous {
                return Err(PublicationLogError::NonIncreasingContext {
                    previous,
                    next: context,
                });
            }
        }
        let expected_previous_hash = last_hash.unwrap_or([0; 32]);
        if publication.round().previous_round_hash() != &expected_previous_hash {
            return Err(PublicationLogError::BrokenHashChain { context });
        }
        last_hash = Some(
            publication
                .hash()
                .map_err(PublicationLogError::Publication)?,
        );
        last_context = Some(context);
        rounds.insert(context, publication);
        position = record_end;
    }
    Ok((rounds, last_hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        authority::{AuthorityKeyManager, PublishedRound},
        CredentialPublicParameters, RoundId, WindowId, CHANNEL_SLOT_SIZE,
    };
    use rand::{rngs::StdRng, SeedableRng};
    use std::{
        fs,
        path::PathBuf,
        sync::Arc,
        thread,
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

    fn context(round: u32) -> MainRoundContext {
        MainRoundContext::new(WindowId::new(7), RoundId::try_from(round).unwrap())
    }

    fn credential_parameters() -> CredentialPublicParameters {
        AuthorityKeyManager::generate_with_rng(&mut StdRng::seed_from_u64(1))
            .public_parameters()
            .clone()
    }

    fn publication(
        round: u32,
        timestamp: u64,
        previous_hash: [u8; 32],
        signing_key: &ed25519_dalek::SigningKey,
    ) -> SignedPublishedRound {
        let decoded = super::super::verifier::DecodedRound::decode_with_credentials(
            context(round),
            vec![vec![0; CHANNEL_SLOT_SIZE]],
            &credential_parameters(),
        );
        SignedPublishedRound::sign(
            PublishedRound::from_decoded(&decoded, timestamp, previous_hash).unwrap(),
            signing_key,
        )
        .unwrap()
    }

    #[test]
    fn publications_survive_reopening() {
        let path = TestFile::new("publication-restart");
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let log = PersistentPublicationLog::open(&path.0, signing_key.verifying_key()).unwrap();
        let first = publication(1, 10, [0; 32], &signing_key);
        let first_hash = first.hash().unwrap();
        assert_eq!(
            log.append_if_absent(first).unwrap(),
            PublicationAppendStatus::Inserted
        );
        assert_eq!(
            log.append_if_absent(publication(2, 20, first_hash, &signing_key))
                .unwrap(),
            PublicationAppendStatus::Inserted
        );
        drop(log);

        let reopened =
            PersistentPublicationLog::open(&path.0, signing_key.verifying_key()).unwrap();
        assert_eq!(reopened.len().unwrap(), 2);
        assert_eq!(
            reopened.last_hash().unwrap(),
            reopened
                .get(context(2))
                .unwrap()
                .map(|round| round.hash().unwrap())
        );
    }

    #[test]
    fn identical_round_is_idempotent_but_different_bytes_conflict() {
        let path = TestFile::new("publication-idempotence");
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let log = PersistentPublicationLog::open(&path.0, signing_key.verifying_key()).unwrap();
        let first = publication(1, 10, [0; 32], &signing_key);
        assert_eq!(
            log.append_if_absent(first.clone()).unwrap(),
            PublicationAppendStatus::Inserted
        );
        assert_eq!(
            log.append_if_absent(first).unwrap(),
            PublicationAppendStatus::AlreadyPresent
        );
        assert!(matches!(
            log.append_if_absent(publication(1, 11, [0; 32], &signing_key)),
            Err(PublicationLogError::ConflictingRound(actual)) if actual == context(1)
        ));
    }

    #[test]
    fn parallel_identical_appends_have_one_writer() {
        let path = TestFile::new("publication-parallel");
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let log =
            Arc::new(PersistentPublicationLog::open(&path.0, signing_key.verifying_key()).unwrap());
        let publication = Arc::new(publication(1, 10, [0; 32], &signing_key));
        let handles = (0..16)
            .map(|_| {
                let log = Arc::clone(&log);
                let publication = Arc::clone(&publication);
                thread::spawn(move || log.append_if_absent((*publication).clone()).unwrap())
            })
            .collect::<Vec<_>>();
        let inserted = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(|status| *status == PublicationAppendStatus::Inserted)
            .count();
        assert_eq!(inserted, 1);
        assert_eq!(log.len().unwrap(), 1);
    }

    #[test]
    fn wrong_hash_chain_is_rejected() {
        let path = TestFile::new("publication-chain");
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let log = PersistentPublicationLog::open(&path.0, signing_key.verifying_key()).unwrap();
        log.append_if_absent(publication(1, 10, [0; 32], &signing_key))
            .unwrap();
        assert!(matches!(
            log.append_if_absent(publication(2, 20, [9; 32], &signing_key)),
            Err(PublicationLogError::BrokenHashChain { context: actual }) if actual == context(2)
        ));
    }
}
