use crate::{ContentPseudonym, PseudonymEncodingError};
use std::{
    collections::HashSet,
    error::Error,
    fmt,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
    sync::Mutex,
};

const MAGIC: &[u8; 8] = b"CHRSEEN\0";
const HEADER_SIZE: usize = MAGIC.len() + 2;
pub const SEEN_SET_VERSION: u16 = 1;

pub struct PersistentSeenSet {
    state: Mutex<SeenSetState>,
}

struct SeenSetState {
    file: File,
    entries: HashSet<[u8; ContentPseudonym::ENCODED_SIZE]>,
}

#[derive(Debug)]
pub enum SeenSetError {
    Io(io::Error),
    TruncatedHeader,
    InvalidMagic,
    UnsupportedVersion(u16),
    TruncatedRecord,
    InvalidPseudonym {
        index: usize,
        source: PseudonymEncodingError,
    },
    DuplicateRecord(usize),
    LockPoisoned,
}

impl fmt::Display for SeenSetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "seen-set I/O failed: {error}"),
            Self::TruncatedHeader => formatter.write_str("seen-set header is truncated"),
            Self::InvalidMagic => formatter.write_str("file is not a CHORUS seen-set"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported seen-set version: {version}")
            }
            Self::TruncatedRecord => formatter.write_str("seen-set contains a truncated record"),
            Self::InvalidPseudonym { index, source } => {
                write!(formatter, "seen-set record {index} is invalid: {source}")
            }
            Self::DuplicateRecord(index) => {
                write!(formatter, "seen-set record {index} is duplicated")
            }
            Self::LockPoisoned => formatter.write_str("seen-set lock is poisoned"),
        }
    }
}

impl Error for SeenSetError {}

impl From<io::Error> for SeenSetError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl PersistentSeenSet {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SeenSetError> {
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(path)?;
        let mut encoded = Vec::new();
        file.read_to_end(&mut encoded)?;
        if encoded.is_empty() {
            file.write_all(MAGIC)?;
            file.write_all(&SEEN_SET_VERSION.to_be_bytes())?;
            file.sync_all()?;
            encoded.extend_from_slice(MAGIC);
            encoded.extend_from_slice(&SEEN_SET_VERSION.to_be_bytes());
        }
        let entries = decode_entries(&encoded)?;
        Ok(Self {
            state: Mutex::new(SeenSetState { file, entries }),
        })
    }

    pub fn insert_if_absent(&self, pseudonym: &ContentPseudonym) -> Result<bool, SeenSetError> {
        let encoded = pseudonym
            .to_bytes()
            .map_err(|source| SeenSetError::InvalidPseudonym { index: 0, source })?;
        let mut state = self.state.lock().map_err(|_| SeenSetError::LockPoisoned)?;
        if state.entries.contains(&encoded) {
            return Ok(false);
        }
        let previous_length = state.file.metadata()?.len();
        if let Err(error) = state
            .file
            .write_all(&encoded)
            .and_then(|()| state.file.sync_data())
        {
            state.file.set_len(previous_length)?;
            state.file.sync_data()?;
            return Err(SeenSetError::Io(error));
        }
        state.entries.insert(encoded);
        Ok(true)
    }

    pub fn contains(&self, pseudonym: &ContentPseudonym) -> Result<bool, SeenSetError> {
        let encoded = pseudonym
            .to_bytes()
            .map_err(|source| SeenSetError::InvalidPseudonym { index: 0, source })?;
        self.state
            .lock()
            .map(|state| state.entries.contains(&encoded))
            .map_err(|_| SeenSetError::LockPoisoned)
    }

    pub fn len(&self) -> Result<usize, SeenSetError> {
        self.state
            .lock()
            .map(|state| state.entries.len())
            .map_err(|_| SeenSetError::LockPoisoned)
    }

    pub fn is_empty(&self) -> Result<bool, SeenSetError> {
        self.len().map(|length| length == 0)
    }
}

fn decode_entries(
    encoded: &[u8],
) -> Result<HashSet<[u8; ContentPseudonym::ENCODED_SIZE]>, SeenSetError> {
    if encoded.len() < HEADER_SIZE {
        return Err(SeenSetError::TruncatedHeader);
    }
    if &encoded[..MAGIC.len()] != MAGIC {
        return Err(SeenSetError::InvalidMagic);
    }
    let version = u16::from_be_bytes([encoded[MAGIC.len()], encoded[MAGIC.len() + 1]]);
    if version != SEEN_SET_VERSION {
        return Err(SeenSetError::UnsupportedVersion(version));
    }
    let records = &encoded[HEADER_SIZE..];
    if records.len() % ContentPseudonym::ENCODED_SIZE != 0 {
        return Err(SeenSetError::TruncatedRecord);
    }
    let mut entries = HashSet::with_capacity(records.len() / ContentPseudonym::ENCODED_SIZE);
    for (index, record) in records
        .chunks_exact(ContentPseudonym::ENCODED_SIZE)
        .enumerate()
    {
        let encoded = <[u8; ContentPseudonym::ENCODED_SIZE]>::try_from(record).unwrap();
        ContentPseudonym::from_bytes(&encoded)
            .map_err(|source| SeenSetError::InvalidPseudonym { index, source })?;
        if !entries.insert(encoded) {
            return Err(SeenSetError::DuplicateRecord(index));
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemberSecret;
    use rand::{rngs::StdRng, SeedableRng};
    use std::{
        fs,
        path::PathBuf,
        sync::{Arc, Barrier},
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

    fn pseudonym(seed: u64) -> ContentPseudonym {
        MemberSecret::generate_with_rng(&mut StdRng::seed_from_u64(seed))
            .content_pseudonym(&[7; 32])
            .unwrap()
    }

    #[test]
    fn pseudonym_is_new_exactly_once() {
        let path = TestFile::new("seen-once");
        let seen = PersistentSeenSet::open(&path.0).unwrap();
        let pseudonym = pseudonym(1);
        assert!(seen.insert_if_absent(&pseudonym).unwrap());
        assert!(!seen.insert_if_absent(&pseudonym).unwrap());
        assert_eq!(seen.len().unwrap(), 1);
    }

    #[test]
    fn entries_survive_reopening_the_file() {
        let path = TestFile::new("seen-restart");
        let pseudonym = pseudonym(1);
        assert!(PersistentSeenSet::open(&path.0)
            .unwrap()
            .insert_if_absent(&pseudonym)
            .unwrap());
        let reopened = PersistentSeenSet::open(&path.0).unwrap();
        assert!(!reopened.insert_if_absent(&pseudonym).unwrap());
        assert_eq!(reopened.len().unwrap(), 1);
    }

    #[test]
    fn parallel_inserts_have_exactly_one_winner() {
        let path = TestFile::new("seen-parallel");
        let seen = Arc::new(PersistentSeenSet::open(&path.0).unwrap());
        let pseudonym = Arc::new(pseudonym(1));
        let barrier = Arc::new(Barrier::new(16));
        let handles = (0..16)
            .map(|_| {
                let seen = Arc::clone(&seen);
                let pseudonym = Arc::clone(&pseudonym);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    seen.insert_if_absent(&pseudonym).unwrap()
                })
            })
            .collect::<Vec<_>>();
        let winners = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(|inserted| *inserted)
            .count();
        assert_eq!(winners, 1);
        assert_eq!(seen.len().unwrap(), 1);
    }

    #[test]
    fn truncated_records_are_rejected() {
        let path = TestFile::new("seen-truncated");
        fs::write(
            &path.0,
            [MAGIC.as_slice(), &SEEN_SET_VERSION.to_be_bytes(), &[0]].concat(),
        )
        .unwrap();
        assert!(matches!(
            PersistentSeenSet::open(&path.0),
            Err(SeenSetError::TruncatedRecord)
        ));
    }
}
