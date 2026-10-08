use crate::{share_server::ShareServerId, ConfigurationHash, WindowId, CHANNEL_SLOT_SIZE};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use spectrum::protocols::wrapper::{ChannelKeyWrapper, ProtocolWrapper};
use std::{error::Error, fmt};

const CHANNEL_SET_MAGIC: &[u8; 8] = b"CHCHNSET";
const SIGNED_CHANNEL_SET_MAGIC: &[u8; 8] = b"CHCHNSIG";
const SIGNING_DOMAIN: &[u8] = b"CHORUS-CHANNEL-SET-v1\0";
const CHANNEL_KEY_SIZE: usize = 32;
const SIGNATURE_SIZE: usize = 64;
pub const CHANNEL_SET_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ChannelVerificationKey([u8; CHANNEL_KEY_SIZE]);

impl ChannelVerificationKey {
    pub const fn new(bytes: [u8; CHANNEL_KEY_SIZE]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; CHANNEL_KEY_SIZE] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelSet {
    window: WindowId,
    channels: Vec<ChannelVerificationKey>,
}

#[derive(Clone, Debug)]
pub struct ChannelSetSignature {
    server: ShareServerId,
    signature: Signature,
}

#[derive(Clone, Debug)]
pub struct SignedChannelSet {
    channel_set: ChannelSet,
    server_a_signature: Signature,
    server_b_signature: Signature,
}

#[derive(Clone, Debug)]
pub struct ActivatedMainWindow {
    signed_channel_set: SignedChannelSet,
    configuration_hash: ConfigurationHash,
    protocol: Option<ProtocolWrapper>,
    verification_keys: Vec<ChannelKeyWrapper>,
}

#[derive(Debug, Default)]
pub struct MainWindowActivator {
    active: Option<ActivatedMainWindow>,
}

#[derive(Debug)]
pub enum ChannelSetEncodingError {
    TooManyChannels(usize),
    DuplicateChannelKey {
        first: usize,
        duplicate: usize,
    },
    Truncated(&'static str),
    InvalidMagic,
    UnsupportedVersion(u16),
    UnexpectedSigner {
        expected: ShareServerId,
        actual: ShareServerId,
    },
    TrailingBytes,
}

#[derive(Debug)]
pub enum ChannelSetVerificationError {
    Encoding(ChannelSetEncodingError),
    InvalidServerSignature {
        server: ShareServerId,
        source: ed25519_dalek::SignatureError,
    },
}

#[derive(Debug)]
pub enum MainWindowActivationError {
    Encoding(ChannelSetEncodingError),
    Verification(ChannelSetVerificationError),
    InvalidChannelKey {
        index: usize,
    },
    NonIncreasingWindow {
        active: WindowId,
        received: WindowId,
    },
}

impl fmt::Display for ChannelSetEncodingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyChannels(count) => write!(formatter, "too many channels: {count}"),
            Self::DuplicateChannelKey { first, duplicate } => write!(
                formatter,
                "channel key at position {duplicate} duplicates position {first}"
            ),
            Self::Truncated(field) => write!(formatter, "channel set is truncated at {field}"),
            Self::InvalidMagic => formatter.write_str("invalid channel-set magic"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported channel-set version: {version}")
            }
            Self::UnexpectedSigner { expected, actual } => write!(
                formatter,
                "expected ShareServer {expected} signature, got ShareServer {actual}"
            ),
            Self::TrailingBytes => formatter.write_str("channel set contains trailing bytes"),
        }
    }
}

impl Error for ChannelSetEncodingError {}

impl fmt::Display for ChannelSetVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoding(error) => write!(formatter, "could not encode channel set: {error}"),
            Self::InvalidServerSignature { server, source } => {
                write!(
                    formatter,
                    "invalid ShareServer {server} signature: {source}"
                )
            }
        }
    }
}

impl Error for ChannelSetVerificationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Encoding(error) => Some(error),
            Self::InvalidServerSignature { source, .. } => Some(source),
        }
    }
}

impl fmt::Display for MainWindowActivationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoding(error) => write!(formatter, "invalid signed channel set: {error}"),
            Self::Verification(error) => write!(formatter, "untrusted signed channel set: {error}"),
            Self::InvalidChannelKey { index } => {
                write!(formatter, "channel {index} has an invalid verification key")
            }
            Self::NonIncreasingWindow { active, received } => write!(
                formatter,
                "channel set window {} does not follow active window {}",
                received.get(),
                active.get()
            ),
        }
    }
}

impl Error for MainWindowActivationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Encoding(error) => Some(error),
            Self::Verification(error) => Some(error),
            Self::InvalidChannelKey { .. } => None,
            Self::NonIncreasingWindow { .. } => None,
        }
    }
}

impl ChannelSet {
    pub fn new(
        window: WindowId,
        channels: Vec<ChannelVerificationKey>,
    ) -> Result<Self, ChannelSetEncodingError> {
        u32::try_from(channels.len())
            .map_err(|_| ChannelSetEncodingError::TooManyChannels(channels.len()))?;
        let mut positions = std::collections::HashMap::with_capacity(channels.len());
        for (position, key) in channels.iter().enumerate() {
            if let Some(first) = positions.insert(*key.as_bytes(), position) {
                return Err(ChannelSetEncodingError::DuplicateChannelKey {
                    first,
                    duplicate: position,
                });
            }
        }
        Ok(Self { window, channels })
    }

    pub const fn window(&self) -> WindowId {
        self.window
    }

    pub fn channels(&self) -> &[ChannelVerificationKey] {
        &self.channels
    }

    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    pub fn is_empty(&self) -> bool {
        self.channels.is_empty()
    }

    pub fn configuration_hash(&self) -> Result<ConfigurationHash, ChannelSetEncodingError> {
        Ok(ConfigurationHash::new(
            *blake3::hash(&self.encode()?).as_bytes(),
        ))
    }

    pub fn encode(&self) -> Result<Vec<u8>, ChannelSetEncodingError> {
        let channel_count = u32::try_from(self.channels.len())
            .map_err(|_| ChannelSetEncodingError::TooManyChannels(self.channels.len()))?;
        let mut encoded = Vec::with_capacity(8 + 2 + 8 + 4 + self.channels.len() * 32);
        encoded.extend_from_slice(CHANNEL_SET_MAGIC);
        encoded.extend_from_slice(&CHANNEL_SET_VERSION.to_be_bytes());
        encoded.extend_from_slice(&self.window.get().to_be_bytes());
        encoded.extend_from_slice(&channel_count.to_be_bytes());
        for channel in &self.channels {
            encoded.extend_from_slice(channel.as_bytes());
        }
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, ChannelSetEncodingError> {
        let mut reader = Reader::new(encoded);
        if reader.read_array::<8>("magic")? != *CHANNEL_SET_MAGIC {
            return Err(ChannelSetEncodingError::InvalidMagic);
        }
        let version = reader.read_u16("version")?;
        if version != CHANNEL_SET_VERSION {
            return Err(ChannelSetEncodingError::UnsupportedVersion(version));
        }
        let window = WindowId::new(reader.read_u64("window")?);
        let channel_count = usize::try_from(reader.read_u32("channel count")?)
            .map_err(|_| ChannelSetEncodingError::TooManyChannels(usize::MAX))?;
        if channel_count > reader.remaining_len() / CHANNEL_KEY_SIZE {
            return Err(ChannelSetEncodingError::Truncated("channel keys"));
        }
        let mut channels = Vec::with_capacity(channel_count);
        for _ in 0..channel_count {
            channels.push(ChannelVerificationKey::new(
                reader.read_array("channel key")?,
            ));
        }
        if !reader.is_empty() {
            return Err(ChannelSetEncodingError::TrailingBytes);
        }
        Self::new(window, channels)
    }
}

impl ChannelSetSignature {
    pub fn sign(
        channel_set: &ChannelSet,
        server: ShareServerId,
        signing_key: &SigningKey,
    ) -> Result<Self, ChannelSetEncodingError> {
        let signature = signing_key.sign(&signing_bytes(channel_set, server)?);
        Ok(Self { server, signature })
    }

    pub const fn server(&self) -> ShareServerId {
        self.server
    }

    pub fn signature_bytes(&self) -> [u8; SIGNATURE_SIZE] {
        self.signature.to_bytes()
    }
}

impl SignedChannelSet {
    pub fn assemble(
        channel_set: ChannelSet,
        server_a: ChannelSetSignature,
        server_b: ChannelSetSignature,
    ) -> Result<Self, ChannelSetEncodingError> {
        if server_a.server != ShareServerId::A {
            return Err(ChannelSetEncodingError::UnexpectedSigner {
                expected: ShareServerId::A,
                actual: server_a.server,
            });
        }
        if server_b.server != ShareServerId::B {
            return Err(ChannelSetEncodingError::UnexpectedSigner {
                expected: ShareServerId::B,
                actual: server_b.server,
            });
        }
        Ok(Self {
            channel_set,
            server_a_signature: server_a.signature,
            server_b_signature: server_b.signature,
        })
    }

    pub fn channel_set(&self) -> &ChannelSet {
        &self.channel_set
    }

    pub fn verify(
        &self,
        server_a_key: &VerifyingKey,
        server_b_key: &VerifyingKey,
    ) -> Result<(), ChannelSetVerificationError> {
        let server_a_bytes = signing_bytes(&self.channel_set, ShareServerId::A)
            .map_err(ChannelSetVerificationError::Encoding)?;
        server_a_key
            .verify_strict(&server_a_bytes, &self.server_a_signature)
            .map_err(
                |source| ChannelSetVerificationError::InvalidServerSignature {
                    server: ShareServerId::A,
                    source,
                },
            )?;
        let server_b_bytes = signing_bytes(&self.channel_set, ShareServerId::B)
            .map_err(ChannelSetVerificationError::Encoding)?;
        server_b_key
            .verify_strict(&server_b_bytes, &self.server_b_signature)
            .map_err(
                |source| ChannelSetVerificationError::InvalidServerSignature {
                    server: ShareServerId::B,
                    source,
                },
            )
    }

    pub fn encode(&self) -> Result<Vec<u8>, ChannelSetEncodingError> {
        let channel_set = self.channel_set.encode()?;
        let channel_set_length = u32::try_from(channel_set.len()).map_err(|_| {
            ChannelSetEncodingError::TooManyChannels(self.channel_set.channels.len())
        })?;
        let mut encoded = Vec::with_capacity(8 + 2 + 4 + channel_set.len() + 2 * SIGNATURE_SIZE);
        encoded.extend_from_slice(SIGNED_CHANNEL_SET_MAGIC);
        encoded.extend_from_slice(&CHANNEL_SET_VERSION.to_be_bytes());
        encoded.extend_from_slice(&channel_set_length.to_be_bytes());
        encoded.extend_from_slice(&channel_set);
        encoded.extend_from_slice(&self.server_a_signature.to_bytes());
        encoded.extend_from_slice(&self.server_b_signature.to_bytes());
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, ChannelSetEncodingError> {
        let mut reader = Reader::new(encoded);
        if reader.read_array::<8>("signed magic")? != *SIGNED_CHANNEL_SET_MAGIC {
            return Err(ChannelSetEncodingError::InvalidMagic);
        }
        let version = reader.read_u16("signed version")?;
        if version != CHANNEL_SET_VERSION {
            return Err(ChannelSetEncodingError::UnsupportedVersion(version));
        }
        let channel_set_length = usize::try_from(reader.read_u32("channel-set length")?)
            .map_err(|_| ChannelSetEncodingError::Truncated("channel set"))?;
        let channel_set = ChannelSet::decode(reader.take(channel_set_length, "channel set")?)?;
        let server_a_signature = Signature::from_bytes(&reader.read_array("server A signature")?);
        let server_b_signature = Signature::from_bytes(&reader.read_array("server B signature")?);
        if !reader.is_empty() {
            return Err(ChannelSetEncodingError::TrailingBytes);
        }
        Ok(Self {
            channel_set,
            server_a_signature,
            server_b_signature,
        })
    }
}

impl ActivatedMainWindow {
    pub fn signed_channel_set(&self) -> &SignedChannelSet {
        &self.signed_channel_set
    }

    pub const fn configuration_hash(&self) -> ConfigurationHash {
        self.configuration_hash
    }

    pub fn protocol(&self) -> Option<&ProtocolWrapper> {
        self.protocol.as_ref()
    }

    pub fn verification_keys(&self) -> &[ChannelKeyWrapper] {
        &self.verification_keys
    }

    pub const fn window(&self) -> WindowId {
        self.signed_channel_set.channel_set.window
    }

    pub fn channel_count(&self) -> usize {
        self.signed_channel_set.channel_set.channel_count()
    }

    pub fn accepts_main_submissions(&self) -> bool {
        self.protocol.is_some()
    }
}

impl MainWindowActivator {
    pub const fn new() -> Self {
        Self { active: None }
    }

    pub fn active(&self) -> Option<&ActivatedMainWindow> {
        self.active.as_ref()
    }

    pub fn activate(
        &mut self,
        encoded: &[u8],
        server_a_key: &VerifyingKey,
        server_b_key: &VerifyingKey,
    ) -> Result<&ActivatedMainWindow, MainWindowActivationError> {
        let signed_channel_set =
            SignedChannelSet::decode(encoded).map_err(MainWindowActivationError::Encoding)?;
        signed_channel_set
            .verify(server_a_key, server_b_key)
            .map_err(MainWindowActivationError::Verification)?;
        let window = signed_channel_set.channel_set.window();
        if let Some(active) = &self.active {
            if window <= active.window() {
                return Err(MainWindowActivationError::NonIncreasingWindow {
                    active: active.window(),
                    received: window,
                });
            }
        }
        let configuration_hash = signed_channel_set
            .channel_set
            .configuration_hash()
            .map_err(MainWindowActivationError::Encoding)?;
        let verification_keys = signed_channel_set
            .channel_set
            .channels()
            .iter()
            .enumerate()
            .map(|(index, key)| {
                ChannelKeyWrapper::secure_public_from_bytes(*key.as_bytes())
                    .map_err(|_| MainWindowActivationError::InvalidChannelKey { index })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let protocol = if signed_channel_set.channel_set.is_empty() {
            None
        } else {
            Some(ProtocolWrapper::new(
                true,
                false,
                2,
                signed_channel_set.channel_set.channel_count(),
                CHANNEL_SLOT_SIZE,
                true,
            ))
        };
        let next = ActivatedMainWindow {
            signed_channel_set,
            configuration_hash,
            protocol,
            verification_keys,
        };
        Ok(self.active.insert(next))
    }
}

fn signing_bytes(
    channel_set: &ChannelSet,
    server: ShareServerId,
) -> Result<Vec<u8>, ChannelSetEncodingError> {
    let channel_set = channel_set.encode()?;
    let mut bytes = Vec::with_capacity(SIGNING_DOMAIN.len() + 1 + channel_set.len());
    bytes.extend_from_slice(SIGNING_DOMAIN);
    bytes.push(match server {
        ShareServerId::A => 0,
        ShareServerId::B => 1,
    });
    bytes.extend_from_slice(&channel_set);
    Ok(bytes)
}

struct Reader<'a> {
    encoded: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(encoded: &'a [u8]) -> Self {
        Self { encoded, offset: 0 }
    }

    fn take(
        &mut self,
        length: usize,
        field: &'static str,
    ) -> Result<&'a [u8], ChannelSetEncodingError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ChannelSetEncodingError::Truncated(field))?;
        let value = self
            .encoded
            .get(self.offset..end)
            .ok_or(ChannelSetEncodingError::Truncated(field))?;
        self.offset = end;
        Ok(value)
    }

    fn read_array<const N: usize>(
        &mut self,
        field: &'static str,
    ) -> Result<[u8; N], ChannelSetEncodingError> {
        self.take(N, field)?
            .try_into()
            .map_err(|_| ChannelSetEncodingError::Truncated(field))
    }

    fn read_u16(&mut self, field: &'static str) -> Result<u16, ChannelSetEncodingError> {
        Ok(u16::from_be_bytes(self.read_array(field)?))
    }

    fn read_u32(&mut self, field: &'static str) -> Result<u32, ChannelSetEncodingError> {
        Ok(u32::from_be_bytes(self.read_array(field)?))
    }

    fn read_u64(&mut self, field: &'static str) -> Result<u64, ChannelSetEncodingError> {
        Ok(u64::from_be_bytes(self.read_array(field)?))
    }

    fn remaining_len(&self) -> usize {
        self.encoded.len() - self.offset
    }

    fn is_empty(&self) -> bool {
        self.offset == self.encoded.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spectrum::experiment::Experiment;

    fn channel_set() -> ChannelSet {
        ChannelSet::new(
            WindowId::new(7),
            vec![
                ChannelVerificationKey::new([2; 32]),
                ChannelVerificationKey::new([1; 32]),
            ],
        )
        .unwrap()
    }

    fn signed_channel_set() -> (SignedChannelSet, SigningKey, SigningKey) {
        let channel_set = channel_set();
        let server_a_key = SigningKey::from_bytes(&[7; 32]);
        let server_b_key = SigningKey::from_bytes(&[8; 32]);
        let server_a =
            ChannelSetSignature::sign(&channel_set, ShareServerId::A, &server_a_key).unwrap();
        let server_b =
            ChannelSetSignature::sign(&channel_set, ShareServerId::B, &server_b_key).unwrap();
        (
            SignedChannelSet::assemble(channel_set, server_a, server_b).unwrap(),
            server_a_key,
            server_b_key,
        )
    }

    fn encoded_channel_set(
        window: u64,
        channel_count: u8,
        server_a_key: &SigningKey,
        server_b_key: &SigningKey,
    ) -> Vec<u8> {
        let channels = if channel_count == 0 {
            Vec::new()
        } else {
            let protocol = ProtocolWrapper::new(
                true,
                false,
                2,
                usize::from(channel_count),
                CHANNEL_SLOT_SIZE,
                true,
            );
            Experiment::new_sample_keys(protocol, 1, u128::from(channel_count), false)
                .get_keys()
                .into_iter()
                .map(|key| ChannelVerificationKey::new(key.public_key_bytes().unwrap()))
                .collect()
        };
        let channel_set = ChannelSet::new(WindowId::new(window), channels).unwrap();
        let server_a =
            ChannelSetSignature::sign(&channel_set, ShareServerId::A, server_a_key).unwrap();
        let server_b =
            ChannelSetSignature::sign(&channel_set, ShareServerId::B, server_b_key).unwrap();
        SignedChannelSet::assemble(channel_set, server_a, server_b)
            .unwrap()
            .encode()
            .unwrap()
    }

    #[test]
    fn channel_set_preserves_bootstrap_order_and_roundtrips() {
        let channel_set = channel_set();
        assert_eq!(channel_set.channels()[0].as_bytes(), &[2; 32]);
        assert_eq!(channel_set.channels()[1].as_bytes(), &[1; 32]);
        assert_eq!(
            ChannelSet::decode(&channel_set.encode().unwrap()).unwrap(),
            channel_set
        );
    }

    #[test]
    fn configuration_hash_binds_window_and_channel_order() {
        let original = channel_set();
        let reordered = ChannelSet::new(
            original.window(),
            original.channels().iter().copied().rev().collect(),
        )
        .unwrap();
        let next_window = ChannelSet::new(WindowId::new(8), original.channels().to_vec()).unwrap();
        assert_ne!(
            original.configuration_hash().unwrap(),
            reordered.configuration_hash().unwrap()
        );
        assert_ne!(
            original.configuration_hash().unwrap(),
            next_window.configuration_hash().unwrap()
        );
    }

    #[test]
    fn both_server_signatures_are_required_and_verified() {
        let (signed, server_a_key, server_b_key) = signed_channel_set();
        let restored = SignedChannelSet::decode(&signed.encode().unwrap()).unwrap();
        assert!(restored
            .verify(&server_a_key.verifying_key(), &server_b_key.verifying_key())
            .is_ok());
        assert!(matches!(
            restored.verify(
                &SigningKey::from_bytes(&[9; 32]).verifying_key(),
                &server_b_key.verifying_key()
            ),
            Err(ChannelSetVerificationError::InvalidServerSignature {
                server: ShareServerId::A,
                ..
            })
        ));
    }

    #[test]
    fn signatures_cannot_be_assigned_to_the_other_server() {
        let channel_set = channel_set();
        let key = SigningKey::from_bytes(&[7; 32]);
        let server_b = ChannelSetSignature::sign(&channel_set, ShareServerId::B, &key).unwrap();
        let server_a = ChannelSetSignature::sign(&channel_set, ShareServerId::A, &key).unwrap();
        assert!(matches!(
            SignedChannelSet::assemble(channel_set, server_b, server_a),
            Err(ChannelSetEncodingError::UnexpectedSigner {
                expected: ShareServerId::A,
                actual: ShareServerId::B
            })
        ));
    }

    #[test]
    fn empty_channel_set_is_a_valid_signed_result() {
        let channel_set = ChannelSet::new(WindowId::new(7), Vec::new()).unwrap();
        assert!(channel_set.is_empty());
        let server_a_key = SigningKey::from_bytes(&[7; 32]);
        let server_b_key = SigningKey::from_bytes(&[8; 32]);
        let server_a =
            ChannelSetSignature::sign(&channel_set, ShareServerId::A, &server_a_key).unwrap();
        let server_b =
            ChannelSetSignature::sign(&channel_set, ShareServerId::B, &server_b_key).unwrap();
        let signed = SignedChannelSet::assemble(channel_set, server_a, server_b).unwrap();
        let restored = SignedChannelSet::decode(&signed.encode().unwrap()).unwrap();
        assert_eq!(restored.channel_set().channel_count(), 0);
        assert!(restored
            .verify(&server_a_key.verifying_key(), &server_b_key.verifying_key())
            .is_ok());
    }

    #[test]
    fn duplicate_channel_keys_are_rejected() {
        assert!(matches!(
            ChannelSet::new(
                WindowId::new(7),
                vec![
                    ChannelVerificationKey::new([1; 32]),
                    ChannelVerificationKey::new([1; 32])
                ]
            ),
            Err(ChannelSetEncodingError::DuplicateChannelKey {
                first: 0,
                duplicate: 1
            })
        ));
    }

    #[test]
    fn unknown_versions_and_trailing_bytes_are_rejected() {
        let mut encoded = channel_set().encode().unwrap();
        encoded[CHANNEL_SET_MAGIC.len()..CHANNEL_SET_MAGIC.len() + 2]
            .copy_from_slice(&2_u16.to_be_bytes());
        assert!(matches!(
            ChannelSet::decode(&encoded),
            Err(ChannelSetEncodingError::UnsupportedVersion(2))
        ));
        encoded[CHANNEL_SET_MAGIC.len()..CHANNEL_SET_MAGIC.len() + 2]
            .copy_from_slice(&CHANNEL_SET_VERSION.to_be_bytes());
        encoded.push(0);
        assert!(matches!(
            ChannelSet::decode(&encoded),
            Err(ChannelSetEncodingError::TrailingBytes)
        ));
    }

    #[test]
    fn non_empty_channel_set_activates_matching_spectrum_protocol() {
        let server_a_key = SigningKey::from_bytes(&[7; 32]);
        let server_b_key = SigningKey::from_bytes(&[8; 32]);
        let encoded = encoded_channel_set(7, 3, &server_a_key, &server_b_key);
        let mut activator = MainWindowActivator::new();

        let active = activator
            .activate(
                &encoded,
                &server_a_key.verifying_key(),
                &server_b_key.verifying_key(),
            )
            .unwrap();
        let protocol = active.protocol().unwrap();
        assert_eq!(active.window(), WindowId::new(7));
        assert_eq!(active.channel_count(), 3);
        assert_eq!(protocol.num_channels(), 3);
        assert_eq!(protocol.num_parties(), 2);
        assert_eq!(protocol.message_len(), CHANNEL_SLOT_SIZE);
        assert!(active.accepts_main_submissions());
        assert_eq!(active.verification_keys().len(), 3);
        assert!(active
            .verification_keys()
            .iter()
            .all(|key| !key.contains_private_key()));
    }

    #[test]
    fn all_main_roles_derive_the_same_active_window() {
        let server_a_key = SigningKey::from_bytes(&[7; 32]);
        let server_b_key = SigningKey::from_bytes(&[8; 32]);
        let encoded = encoded_channel_set(7, 3, &server_a_key, &server_b_key);
        let signed = SignedChannelSet::decode(&encoded).unwrap();
        let expected_hash = signed.channel_set().configuration_hash().unwrap();
        let expected_keys: Vec<_> = signed
            .channel_set()
            .channels()
            .iter()
            .map(|key| *key.as_bytes())
            .collect();
        let mut activators = [
            MainWindowActivator::new(),
            MainWindowActivator::new(),
            MainWindowActivator::new(),
            MainWindowActivator::new(),
        ];

        for (role, activator) in ["Member", "ShareServer A", "ShareServer B", "Authority"]
            .into_iter()
            .zip(&mut activators)
        {
            {
                let active = activator
                    .activate(
                        &encoded,
                        &server_a_key.verifying_key(),
                        &server_b_key.verifying_key(),
                    )
                    .unwrap();
                let actual_keys: Vec<_> = active
                    .verification_keys()
                    .iter()
                    .map(|key| key.public_key_bytes().unwrap())
                    .collect();
                assert_eq!(active.window(), WindowId::new(7), "{role}");
                assert_eq!(active.configuration_hash(), expected_hash, "{role}");
                assert_eq!(actual_keys, expected_keys, "{role}");
                assert_eq!(active.protocol().unwrap().num_channels(), 3, "{role}");
            }
            assert!(matches!(
                activator.activate(
                    &encoded,
                    &server_a_key.verifying_key(),
                    &server_b_key.verifying_key()
                ),
                Err(MainWindowActivationError::NonIncreasingWindow { .. })
            ));
        }
    }

    #[test]
    fn valid_next_window_atomically_replaces_the_active_window() {
        let server_a_key = SigningKey::from_bytes(&[7; 32]);
        let server_b_key = SigningKey::from_bytes(&[8; 32]);
        let first = encoded_channel_set(7, 2, &server_a_key, &server_b_key);
        let next = encoded_channel_set(8, 3, &server_a_key, &server_b_key);
        let expected_hash = SignedChannelSet::decode(&next)
            .unwrap()
            .channel_set()
            .configuration_hash()
            .unwrap();
        let mut activator = MainWindowActivator::new();
        activator
            .activate(
                &first,
                &server_a_key.verifying_key(),
                &server_b_key.verifying_key(),
            )
            .unwrap();

        let active = activator
            .activate(
                &next,
                &server_a_key.verifying_key(),
                &server_b_key.verifying_key(),
            )
            .unwrap();
        assert_eq!(active.window(), WindowId::new(8));
        assert_eq!(active.configuration_hash(), expected_hash);
        assert_eq!(active.channel_count(), 3);
        assert_eq!(active.protocol().unwrap().num_channels(), 3);
    }

    #[test]
    fn empty_channel_set_activates_without_spectrum_protocol() {
        let server_a_key = SigningKey::from_bytes(&[7; 32]);
        let server_b_key = SigningKey::from_bytes(&[8; 32]);
        let encoded = encoded_channel_set(7, 0, &server_a_key, &server_b_key);
        let mut activator = MainWindowActivator::new();

        let active = activator
            .activate(
                &encoded,
                &server_a_key.verifying_key(),
                &server_b_key.verifying_key(),
            )
            .unwrap();
        assert_eq!(active.channel_count(), 0);
        assert!(active.protocol().is_none());
        assert!(!active.accepts_main_submissions());
    }

    #[test]
    fn invalid_candidate_does_not_replace_active_window() {
        let server_a_key = SigningKey::from_bytes(&[7; 32]);
        let server_b_key = SigningKey::from_bytes(&[8; 32]);
        let first = encoded_channel_set(7, 2, &server_a_key, &server_b_key);
        let mut invalid_next = encoded_channel_set(8, 3, &server_a_key, &server_b_key);
        let last = invalid_next.len() - 1;
        invalid_next[last] ^= 1;
        let mut activator = MainWindowActivator::new();
        activator
            .activate(
                &first,
                &server_a_key.verifying_key(),
                &server_b_key.verifying_key(),
            )
            .unwrap();
        let original_hash = activator.active().unwrap().configuration_hash();

        assert!(matches!(
            activator.activate(
                &invalid_next,
                &server_a_key.verifying_key(),
                &server_b_key.verifying_key()
            ),
            Err(MainWindowActivationError::Verification(_))
        ));
        assert_eq!(activator.active().unwrap().window(), WindowId::new(7));
        assert_eq!(
            activator.active().unwrap().configuration_hash(),
            original_hash
        );
    }

    #[test]
    fn active_or_older_window_cannot_be_started_again() {
        let server_a_key = SigningKey::from_bytes(&[7; 32]);
        let server_b_key = SigningKey::from_bytes(&[8; 32]);
        let current = encoded_channel_set(7, 2, &server_a_key, &server_b_key);
        let older = encoded_channel_set(6, 2, &server_a_key, &server_b_key);
        let mut activator = MainWindowActivator::new();
        activator
            .activate(
                &current,
                &server_a_key.verifying_key(),
                &server_b_key.verifying_key(),
            )
            .unwrap();

        for encoded in [&current, &older] {
            assert!(matches!(
                activator.activate(
                    encoded,
                    &server_a_key.verifying_key(),
                    &server_b_key.verifying_key()
                ),
                Err(MainWindowActivationError::NonIncreasingWindow {
                    active,
                    ..
                }) if active == WindowId::new(7)
            ));
        }
        assert_eq!(activator.active().unwrap().window(), WindowId::new(7));
    }

    #[test]
    fn invalid_curve_point_does_not_activate_window() {
        let server_a_key = SigningKey::from_bytes(&[7; 32]);
        let server_b_key = SigningKey::from_bytes(&[8; 32]);
        let channel_set = ChannelSet::new(
            WindowId::new(7),
            vec![ChannelVerificationKey::new([0xff; 32])],
        )
        .unwrap();
        let server_a =
            ChannelSetSignature::sign(&channel_set, ShareServerId::A, &server_a_key).unwrap();
        let server_b =
            ChannelSetSignature::sign(&channel_set, ShareServerId::B, &server_b_key).unwrap();
        let encoded = SignedChannelSet::assemble(channel_set, server_a, server_b)
            .unwrap()
            .encode()
            .unwrap();
        let mut activator = MainWindowActivator::new();

        assert!(matches!(
            activator.activate(
                &encoded,
                &server_a_key.verifying_key(),
                &server_b_key.verifying_key()
            ),
            Err(MainWindowActivationError::InvalidChannelKey { index: 0 })
        ));
        assert!(activator.active().is_none());
    }
}
