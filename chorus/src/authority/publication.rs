use super::verifier::{
    AtomDuplicateStatus, ContentProofStatus, DecodedChannel, DecodedRound, SelfBindingStatus,
};
use crate::{MainRoundContext, RoundId, WindowId};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::{error::Error, fmt};

const ROUND_MAGIC: &[u8; 8] = b"CHPUBRND";
const SIGNED_MAGIC: &[u8; 8] = b"CHPUBSIG";
const SIGNING_DOMAIN: &[u8] = b"CHORUS-PUBLISHED-ROUND-v1\0";
const SIGNATURE_SIZE: usize = 64;
pub const PUBLISHED_ROUND_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublishedChannelStatus {
    Ok,
    SelfBindingFailed,
    ContentProofFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublishedAtomStatus {
    New,
    Duplicate,
    NotChecked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedAtom {
    fingerprint: [u8; 32],
    pseudonym: [u8; 48],
    status: PublishedAtomStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublishedChannel {
    Empty {
        index: u32,
    },
    Payload {
        index: u32,
        status: PublishedChannelStatus,
        record_hash: [u8; 32],
        stix_bundle: Vec<u8>,
        atoms: Vec<PublishedAtom>,
    },
    Malformed {
        index: u32,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedRound {
    context: MainRoundContext,
    published_at_unix: u64,
    previous_round_hash: [u8; 32],
    channels: Vec<PublishedChannel>,
}

#[derive(Clone, Debug)]
pub struct SignedPublishedRound {
    round: PublishedRound,
    signature: Signature,
}

#[derive(Debug)]
pub enum PublicationEncodingError {
    TooManyChannels(usize),
    TooManyAtoms { channel: usize, count: usize },
    StixBundleTooLarge { channel: usize, length: usize },
    IncompleteDeduplication { channel: usize, atom: usize },
    AtomStatusCountMismatch { channel: usize },
    Truncated(&'static str),
    InvalidMagic,
    UnsupportedVersion(u16),
    InvalidRound,
    InvalidChannelTag(u8),
    InvalidChannelStatus(u8),
    InvalidAtomStatus(u8),
    UnexpectedChannelIndex { expected: u32, actual: u32 },
    TrailingBytes,
}

#[derive(Debug)]
pub enum PublicationVerificationError {
    Encoding(PublicationEncodingError),
    InvalidSignature(ed25519_dalek::SignatureError),
}

impl fmt::Display for PublicationEncodingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyChannels(count) => {
                write!(formatter, "too many published channels: {count}")
            }
            Self::TooManyAtoms { channel, count } => {
                write!(
                    formatter,
                    "published channel {channel} has too many atoms: {count}"
                )
            }
            Self::StixBundleTooLarge { channel, length } => write!(
                formatter,
                "published channel {channel} has an oversized STIX bundle: {length} bytes"
            ),
            Self::IncompleteDeduplication { channel, atom } => write!(
                formatter,
                "published channel {channel} atom {atom} was not deduplicated"
            ),
            Self::AtomStatusCountMismatch { channel } => {
                write!(
                    formatter,
                    "published channel {channel} has mismatched atom statuses"
                )
            }
            Self::Truncated(field) => write!(formatter, "published round is truncated at {field}"),
            Self::InvalidMagic => formatter.write_str("invalid published-round magic"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported published-round version: {version}")
            }
            Self::InvalidRound => formatter.write_str("published round number must be positive"),
            Self::InvalidChannelTag(tag) => {
                write!(formatter, "invalid published channel tag: {tag}")
            }
            Self::InvalidChannelStatus(status) => {
                write!(formatter, "invalid published channel status: {status}")
            }
            Self::InvalidAtomStatus(status) => {
                write!(formatter, "invalid published atom status: {status}")
            }
            Self::UnexpectedChannelIndex { expected, actual } => write!(
                formatter,
                "published channel index {actual} does not match position {expected}"
            ),
            Self::TrailingBytes => formatter.write_str("published round contains trailing bytes"),
        }
    }
}

impl Error for PublicationEncodingError {}

impl fmt::Display for PublicationVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoding(error) => write!(formatter, "could not encode published round: {error}"),
            Self::InvalidSignature(error) => {
                write!(formatter, "invalid Authority signature: {error}")
            }
        }
    }
}

impl Error for PublicationVerificationError {}

impl PublishedAtom {
    pub const fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }

    pub const fn pseudonym(&self) -> &[u8; 48] {
        &self.pseudonym
    }

    pub const fn status(&self) -> PublishedAtomStatus {
        self.status
    }
}

impl PublishedRound {
    pub fn from_decoded(
        decoded: &DecodedRound,
        published_at_unix: u64,
        previous_round_hash: [u8; 32],
    ) -> Result<Self, PublicationEncodingError> {
        let channel_count = u32::try_from(decoded.channels().len())
            .map_err(|_| PublicationEncodingError::TooManyChannels(decoded.channels().len()))?;
        let mut channels = Vec::with_capacity(decoded.channels().len());
        for (position, channel) in decoded.channels().iter().enumerate() {
            let index = u32::try_from(position)
                .map_err(|_| PublicationEncodingError::TooManyChannels(position + 1))?;
            channels.push(match channel {
                DecodedChannel::Empty => PublishedChannel::Empty { index },
                DecodedChannel::Malformed(_) => PublishedChannel::Malformed { index },
                DecodedChannel::Payload {
                    payload,
                    self_binding,
                    content_proof,
                    duplicate_statuses,
                } => {
                    if payload.atoms().len() != duplicate_statuses.len() {
                        return Err(PublicationEncodingError::AtomStatusCountMismatch {
                            channel: position,
                        });
                    }
                    let channel_status = published_channel_status(*self_binding, *content_proof);
                    let atoms = payload
                        .atoms()
                        .iter()
                        .zip(duplicate_statuses)
                        .enumerate()
                        .map(|(atom, (entry, duplicate_status))| {
                            let atom_status = published_atom_status(*duplicate_status);
                            if atom_status == PublishedAtomStatus::NotChecked
                                && channel_status == PublishedChannelStatus::Ok
                            {
                                return Err(PublicationEncodingError::IncompleteDeduplication {
                                    channel: position,
                                    atom,
                                });
                            }
                            Ok(PublishedAtom {
                                fingerprint: *entry.fingerprint(),
                                pseudonym: *entry.pseudonym(),
                                status: atom_status,
                            })
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    PublishedChannel::Payload {
                        index,
                        status: channel_status,
                        record_hash: *blake3::hash(&payload.encode()).as_bytes(),
                        stix_bundle: payload.stix_bundle().to_vec(),
                        atoms,
                    }
                }
            });
        }
        debug_assert_eq!(channels.len(), channel_count as usize);
        Ok(Self {
            context: decoded.context(),
            published_at_unix,
            previous_round_hash,
            channels,
        })
    }

    pub const fn context(&self) -> MainRoundContext {
        self.context
    }

    pub const fn published_at_unix(&self) -> u64 {
        self.published_at_unix
    }

    pub const fn previous_round_hash(&self) -> &[u8; 32] {
        &self.previous_round_hash
    }

    pub fn channels(&self) -> &[PublishedChannel] {
        &self.channels
    }

    pub fn encode(&self) -> Result<Vec<u8>, PublicationEncodingError> {
        let channel_count = u32::try_from(self.channels.len())
            .map_err(|_| PublicationEncodingError::TooManyChannels(self.channels.len()))?;
        let mut encoded = Vec::new();
        encoded.extend_from_slice(ROUND_MAGIC);
        encoded.extend_from_slice(&PUBLISHED_ROUND_VERSION.to_be_bytes());
        encoded.extend_from_slice(&self.context.window().get().to_be_bytes());
        encoded.extend_from_slice(&self.context.round().get().to_be_bytes());
        encoded.extend_from_slice(&self.published_at_unix.to_be_bytes());
        encoded.extend_from_slice(&self.previous_round_hash);
        encoded.extend_from_slice(&channel_count.to_be_bytes());
        for (position, channel) in self.channels.iter().enumerate() {
            encode_channel(channel, position, &mut encoded)?;
        }
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, PublicationEncodingError> {
        let mut reader = Reader::new(encoded);
        if reader.read_array::<8>("magic")? != *ROUND_MAGIC {
            return Err(PublicationEncodingError::InvalidMagic);
        }
        let version = reader.read_u16("version")?;
        if version != PUBLISHED_ROUND_VERSION {
            return Err(PublicationEncodingError::UnsupportedVersion(version));
        }
        let window = WindowId::new(reader.read_u64("window")?);
        let round = RoundId::try_from(reader.read_u32("round")?)
            .map_err(|_| PublicationEncodingError::InvalidRound)?;
        let published_at_unix = reader.read_u64("publication time")?;
        let previous_round_hash = reader.read_array("previous round hash")?;
        let channel_count = usize::try_from(reader.read_u32("channel count")?)
            .map_err(|_| PublicationEncodingError::TooManyChannels(usize::MAX))?;
        if channel_count > reader.remaining_len() / 5 {
            return Err(PublicationEncodingError::Truncated("channels"));
        }
        let mut channels = Vec::with_capacity(channel_count);
        for expected_index in 0..channel_count {
            channels.push(decode_channel(&mut reader, expected_index)?);
        }
        if !reader.is_empty() {
            return Err(PublicationEncodingError::TrailingBytes);
        }
        Ok(Self {
            context: MainRoundContext::new(window, round),
            published_at_unix,
            previous_round_hash,
            channels,
        })
    }
}

impl SignedPublishedRound {
    pub fn sign(
        round: PublishedRound,
        signing_key: &SigningKey,
    ) -> Result<Self, PublicationEncodingError> {
        let signature = signing_key.sign(&signing_bytes(&round)?);
        Ok(Self { round, signature })
    }

    pub fn round(&self) -> &PublishedRound {
        &self.round
    }

    pub fn signature_bytes(&self) -> [u8; SIGNATURE_SIZE] {
        self.signature.to_bytes()
    }

    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<(), PublicationVerificationError> {
        let bytes = signing_bytes(&self.round).map_err(PublicationVerificationError::Encoding)?;
        verifying_key
            .verify_strict(&bytes, &self.signature)
            .map_err(PublicationVerificationError::InvalidSignature)
    }

    pub fn encode(&self) -> Result<Vec<u8>, PublicationEncodingError> {
        let round = self.round.encode()?;
        let round_length = u32::try_from(round.len())
            .map_err(|_| PublicationEncodingError::TooManyChannels(self.round.channels.len()))?;
        let mut encoded = Vec::with_capacity(8 + 2 + 4 + round.len() + SIGNATURE_SIZE);
        encoded.extend_from_slice(SIGNED_MAGIC);
        encoded.extend_from_slice(&PUBLISHED_ROUND_VERSION.to_be_bytes());
        encoded.extend_from_slice(&round_length.to_be_bytes());
        encoded.extend_from_slice(&round);
        encoded.extend_from_slice(&self.signature.to_bytes());
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, PublicationEncodingError> {
        let mut reader = Reader::new(encoded);
        if reader.read_array::<8>("signed magic")? != *SIGNED_MAGIC {
            return Err(PublicationEncodingError::InvalidMagic);
        }
        let version = reader.read_u16("signed version")?;
        if version != PUBLISHED_ROUND_VERSION {
            return Err(PublicationEncodingError::UnsupportedVersion(version));
        }
        let round_length = usize::try_from(reader.read_u32("published round length")?)
            .map_err(|_| PublicationEncodingError::Truncated("published round"))?;
        let round = PublishedRound::decode(reader.take(round_length, "published round")?)?;
        let signature = Signature::from_bytes(&reader.read_array("Authority signature")?);
        if !reader.is_empty() {
            return Err(PublicationEncodingError::TrailingBytes);
        }
        Ok(Self { round, signature })
    }

    pub fn hash(&self) -> Result<[u8; 32], PublicationEncodingError> {
        Ok(*blake3::hash(&self.encode()?).as_bytes())
    }
}

fn published_channel_status(
    self_binding: SelfBindingStatus,
    content_proof: ContentProofStatus,
) -> PublishedChannelStatus {
    if self_binding == SelfBindingStatus::Failed {
        PublishedChannelStatus::SelfBindingFailed
    } else if content_proof == ContentProofStatus::Valid {
        PublishedChannelStatus::Ok
    } else {
        PublishedChannelStatus::ContentProofFailed
    }
}

fn published_atom_status(status: AtomDuplicateStatus) -> PublishedAtomStatus {
    match status {
        AtomDuplicateStatus::NotChecked => PublishedAtomStatus::NotChecked,
        AtomDuplicateStatus::New => PublishedAtomStatus::New,
        AtomDuplicateStatus::Duplicate => PublishedAtomStatus::Duplicate,
    }
}

fn encode_channel(
    channel: &PublishedChannel,
    position: usize,
    encoded: &mut Vec<u8>,
) -> Result<(), PublicationEncodingError> {
    let expected = u32::try_from(position)
        .map_err(|_| PublicationEncodingError::TooManyChannels(position + 1))?;
    let index = match channel {
        PublishedChannel::Empty { index }
        | PublishedChannel::Payload { index, .. }
        | PublishedChannel::Malformed { index } => *index,
    };
    if index != expected {
        return Err(PublicationEncodingError::UnexpectedChannelIndex {
            expected,
            actual: index,
        });
    }
    match channel {
        PublishedChannel::Empty { index } => {
            encoded.push(0);
            encoded.extend_from_slice(&index.to_be_bytes());
        }
        PublishedChannel::Payload {
            index,
            status,
            record_hash,
            stix_bundle,
            atoms,
        } => {
            let stix_length = u32::try_from(stix_bundle.len()).map_err(|_| {
                PublicationEncodingError::StixBundleTooLarge {
                    channel: position,
                    length: stix_bundle.len(),
                }
            })?;
            let atom_count =
                u16::try_from(atoms.len()).map_err(|_| PublicationEncodingError::TooManyAtoms {
                    channel: position,
                    count: atoms.len(),
                })?;
            encoded.push(1);
            encoded.extend_from_slice(&index.to_be_bytes());
            encoded.push(channel_status_tag(*status));
            encoded.extend_from_slice(record_hash);
            encoded.extend_from_slice(&stix_length.to_be_bytes());
            encoded.extend_from_slice(stix_bundle);
            encoded.extend_from_slice(&atom_count.to_be_bytes());
            for atom in atoms {
                encoded.extend_from_slice(&atom.fingerprint);
                encoded.extend_from_slice(&atom.pseudonym);
                encoded.push(atom_status_tag(atom.status));
            }
        }
        PublishedChannel::Malformed { index } => {
            encoded.push(2);
            encoded.extend_from_slice(&index.to_be_bytes());
        }
    }
    Ok(())
}

fn decode_channel(
    reader: &mut Reader<'_>,
    expected_position: usize,
) -> Result<PublishedChannel, PublicationEncodingError> {
    let tag = reader.read_u8("channel tag")?;
    let index = reader.read_u32("channel index")?;
    let expected = u32::try_from(expected_position)
        .map_err(|_| PublicationEncodingError::TooManyChannels(expected_position + 1))?;
    if index != expected {
        return Err(PublicationEncodingError::UnexpectedChannelIndex {
            expected,
            actual: index,
        });
    }
    match tag {
        0 => Ok(PublishedChannel::Empty { index }),
        1 => {
            let status = decode_channel_status(reader.read_u8("channel status")?)?;
            let record_hash = reader.read_array("record hash")?;
            let stix_length =
                usize::try_from(reader.read_u32("STIX bundle length")?).map_err(|_| {
                    PublicationEncodingError::StixBundleTooLarge {
                        channel: expected_position,
                        length: usize::MAX,
                    }
                })?;
            let stix_bundle = reader.take(stix_length, "STIX bundle")?.to_vec();
            let atom_count = usize::from(reader.read_u16("atom count")?);
            if atom_count > reader.remaining_len() / 81 {
                return Err(PublicationEncodingError::Truncated("atoms"));
            }
            let mut atoms = Vec::with_capacity(atom_count);
            for _ in 0..atom_count {
                atoms.push(PublishedAtom {
                    fingerprint: reader.read_array("atom fingerprint")?,
                    pseudonym: reader.read_array("atom pseudonym")?,
                    status: decode_atom_status(reader.read_u8("atom status")?)?,
                });
            }
            Ok(PublishedChannel::Payload {
                index,
                status,
                record_hash,
                stix_bundle,
                atoms,
            })
        }
        2 => Ok(PublishedChannel::Malformed { index }),
        other => Err(PublicationEncodingError::InvalidChannelTag(other)),
    }
}

fn channel_status_tag(status: PublishedChannelStatus) -> u8 {
    match status {
        PublishedChannelStatus::Ok => 0,
        PublishedChannelStatus::SelfBindingFailed => 1,
        PublishedChannelStatus::ContentProofFailed => 2,
    }
}

fn decode_channel_status(status: u8) -> Result<PublishedChannelStatus, PublicationEncodingError> {
    match status {
        0 => Ok(PublishedChannelStatus::Ok),
        1 => Ok(PublishedChannelStatus::SelfBindingFailed),
        2 => Ok(PublishedChannelStatus::ContentProofFailed),
        other => Err(PublicationEncodingError::InvalidChannelStatus(other)),
    }
}

fn atom_status_tag(status: PublishedAtomStatus) -> u8 {
    match status {
        PublishedAtomStatus::New => 0,
        PublishedAtomStatus::Duplicate => 3,
        PublishedAtomStatus::NotChecked => u8::MAX,
    }
}

fn decode_atom_status(status: u8) -> Result<PublishedAtomStatus, PublicationEncodingError> {
    match status {
        0 => Ok(PublishedAtomStatus::New),
        3 => Ok(PublishedAtomStatus::Duplicate),
        u8::MAX => Ok(PublishedAtomStatus::NotChecked),
        other => Err(PublicationEncodingError::InvalidAtomStatus(other)),
    }
}

fn signing_bytes(round: &PublishedRound) -> Result<Vec<u8>, PublicationEncodingError> {
    let encoded = round.encode()?;
    let mut signing_bytes = Vec::with_capacity(SIGNING_DOMAIN.len() + encoded.len());
    signing_bytes.extend_from_slice(SIGNING_DOMAIN);
    signing_bytes.extend_from_slice(&encoded);
    Ok(signing_bytes)
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(
        &mut self,
        length: usize,
        field: &'static str,
    ) -> Result<&'a [u8], PublicationEncodingError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(PublicationEncodingError::Truncated(field))?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(PublicationEncodingError::Truncated(field))?;
        self.position = end;
        Ok(value)
    }

    fn read_array<const N: usize>(
        &mut self,
        field: &'static str,
    ) -> Result<[u8; N], PublicationEncodingError> {
        self.take(N, field)?
            .try_into()
            .map_err(|_| PublicationEncodingError::Truncated(field))
    }

    fn read_u8(&mut self, field: &'static str) -> Result<u8, PublicationEncodingError> {
        Ok(self.read_array::<1>(field)?[0])
    }

    fn read_u16(&mut self, field: &'static str) -> Result<u16, PublicationEncodingError> {
        Ok(u16::from_be_bytes(self.read_array(field)?))
    }

    fn read_u32(&mut self, field: &'static str) -> Result<u32, PublicationEncodingError> {
        Ok(u32::from_be_bytes(self.read_array(field)?))
    }

    fn read_u64(&mut self, field: &'static str) -> Result<u64, PublicationEncodingError> {
        Ok(u64::from_be_bytes(self.read_array(field)?))
    }

    fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn remaining_len(&self) -> usize {
        self.bytes.len() - self.position
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        authority::{AuthorityKeyManager, PersistentSeenSet},
        member, CredentialAttributes, MemberCredentialBundle, MemberSecret,
    };
    use ark_bls12_381::Fr;
    use rand::{rngs::StdRng, SeedableRng};
    use std::{fs, path::PathBuf, time::SystemTime};

    struct TestFile(PathBuf);

    impl TestFile {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            Self(std::env::temp_dir().join(format!(
                "chorus-publication-{}-{nonce}.bin",
                std::process::id()
            )))
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

    fn decoded_round(deduplicate: bool) -> (TestFile, DecodedRound) {
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
        let round = DecodedRound::decode_with_credentials(
            context(),
            vec![vec![0; crate::CHANNEL_SLOT_SIZE], payload.encode()],
            parameters,
        );
        let path = TestFile::new();
        if deduplicate {
            let seen = PersistentSeenSet::open(&path.0).unwrap();
            (path, round.deduplicate(&seen).unwrap())
        } else {
            (path, round)
        }
    }

    #[test]
    fn published_round_roundtrips_with_channel_and_atom_statuses() {
        let (_path, decoded) = decoded_round(true);
        let round = PublishedRound::from_decoded(&decoded, 1_700_000_000, [9; 32]).unwrap();
        let restored = PublishedRound::decode(&round.encode().unwrap()).unwrap();
        assert_eq!(restored, round);
        assert!(matches!(
            restored.channels()[0],
            PublishedChannel::Empty { index: 0 }
        ));
        assert!(matches!(
            &restored.channels()[1],
            PublishedChannel::Payload { status, atoms, .. }
                if *status == PublishedChannelStatus::Ok
                    && atoms[0].status() == PublishedAtomStatus::New
        ));
    }

    #[test]
    fn valid_payload_must_be_deduplicated_before_publication() {
        let (_path, decoded) = decoded_round(false);
        assert!(matches!(
            PublishedRound::from_decoded(&decoded, 1_700_000_000, [0; 32]),
            Err(PublicationEncodingError::IncompleteDeduplication {
                channel: 1,
                atom: 0
            })
        ));
    }

    #[test]
    fn signed_publication_roundtrips_and_verifies() {
        let (_path, decoded) = decoded_round(true);
        let round = PublishedRound::from_decoded(&decoded, 1_700_000_000, [9; 32]).unwrap();
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let signed = SignedPublishedRound::sign(round, &signing_key).unwrap();
        let encoded = signed.encode().unwrap();
        let restored = SignedPublishedRound::decode(&encoded).unwrap();
        assert!(restored.verify(&signing_key.verifying_key()).is_ok());
        assert_eq!(restored.hash().unwrap(), signed.hash().unwrap());
        assert!(restored
            .verify(&SigningKey::from_bytes(&[8; 32]).verifying_key())
            .is_err());
    }

    #[test]
    fn published_round_rejects_unknown_versions_and_trailing_bytes() {
        let (_path, decoded) = decoded_round(true);
        let round = PublishedRound::from_decoded(&decoded, 1_700_000_000, [9; 32]).unwrap();
        let mut encoded = round.encode().unwrap();
        encoded[ROUND_MAGIC.len()..ROUND_MAGIC.len() + 2].copy_from_slice(&2_u16.to_be_bytes());
        assert!(matches!(
            PublishedRound::decode(&encoded),
            Err(PublicationEncodingError::UnsupportedVersion(2))
        ));
        encoded[ROUND_MAGIC.len()..ROUND_MAGIC.len() + 2]
            .copy_from_slice(&PUBLISHED_ROUND_VERSION.to_be_bytes());
        encoded.push(0);
        assert!(matches!(
            PublishedRound::decode(&encoded),
            Err(PublicationEncodingError::TrailingBytes)
        ));
    }
}
