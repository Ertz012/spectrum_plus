use crate::{share_server::ShareServerId, MainRoundContext};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::{error::Error, fmt};

pub const AGGREGATE_SHARE_VERSION: u16 = 1;

const SIGNING_DOMAIN: &[u8] = b"CHORUS-AGGREGATE-SHARE";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ConfigurationHash([u8; 32]);

impl ConfigurationHash {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateSharePayload {
    version: u16,
    server: ShareServerId,
    context: MainRoundContext,
    configuration_hash: ConfigurationHash,
    channel_data: Vec<Vec<u8>>,
}

impl AggregateSharePayload {
    pub fn new(
        server: ShareServerId,
        context: MainRoundContext,
        configuration_hash: ConfigurationHash,
        channel_data: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            version: AGGREGATE_SHARE_VERSION,
            server,
            context,
            configuration_hash,
            channel_data,
        }
    }

    pub const fn version(&self) -> u16 {
        self.version
    }

    pub const fn server(&self) -> ShareServerId {
        self.server
    }

    pub const fn context(&self) -> MainRoundContext {
        self.context
    }

    pub const fn configuration_hash(&self) -> ConfigurationHash {
        self.configuration_hash
    }

    pub fn channel_data(&self) -> &[Vec<u8>] {
        &self.channel_data
    }

    pub fn into_channel_data(self) -> Vec<Vec<u8>> {
        self.channel_data
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, AggregateShareEncodingError> {
        Self::signing_bytes_from_parts(
            self.version,
            self.server,
            self.context,
            self.configuration_hash,
            &self.channel_data,
        )
    }

    pub(crate) fn signing_bytes_from_parts(
        version: u16,
        server: ShareServerId,
        context: MainRoundContext,
        configuration_hash: ConfigurationHash,
        channel_data: &[Vec<u8>],
    ) -> Result<Vec<u8>, AggregateShareEncodingError> {
        let channel_count = u32::try_from(channel_data.len())
            .map_err(|_| AggregateShareEncodingError::TooManyChannels(channel_data.len()))?;
        let mut bytes = Vec::new();

        bytes.extend_from_slice(SIGNING_DOMAIN);
        bytes.extend_from_slice(&version.to_be_bytes());
        bytes.push(server_tag(server));
        bytes.extend_from_slice(&context.window().get().to_be_bytes());
        bytes.extend_from_slice(&context.round().get().to_be_bytes());
        bytes.extend_from_slice(configuration_hash.as_bytes());
        bytes.extend_from_slice(&channel_count.to_be_bytes());

        for (index, channel) in channel_data.iter().enumerate() {
            let channel_length = u32::try_from(channel.len()).map_err(|_| {
                AggregateShareEncodingError::ChannelTooLarge {
                    index,
                    length: channel.len(),
                }
            })?;

            bytes.extend_from_slice(&channel_length.to_be_bytes());
            bytes.extend_from_slice(channel);
        }

        Ok(bytes)
    }
}

#[derive(Clone, Debug)]
pub struct SignedAggregateShare {
    payload: AggregateSharePayload,
    signature: Signature,
}

impl SignedAggregateShare {
    pub fn sign(
        payload: AggregateSharePayload,
        signing_key: &SigningKey,
    ) -> Result<Self, AggregateShareEncodingError> {
        let signing_bytes = payload.signing_bytes()?;
        let signature = signing_key.sign(&signing_bytes);

        Ok(Self { payload, signature })
    }

    pub fn payload(&self) -> &AggregateSharePayload {
        &self.payload
    }

    pub fn signature_bytes(&self) -> [u8; 64] {
        self.signature.to_bytes()
    }

    pub fn into_parts(self) -> (AggregateSharePayload, [u8; 64]) {
        (self.payload, self.signature.to_bytes())
    }

    pub fn verify(
        &self,
        verifying_key: &VerifyingKey,
    ) -> Result<(), AggregateShareVerificationError> {
        let signing_bytes = self
            .payload
            .signing_bytes()
            .map_err(AggregateShareVerificationError::Encoding)?;

        verifying_key
            .verify_strict(&signing_bytes, &self.signature)
            .map_err(AggregateShareVerificationError::InvalidSignature)
    }
}

fn server_tag(server: ShareServerId) -> u8 {
    match server {
        ShareServerId::A => 0,
        ShareServerId::B => 1,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregateShareEncodingError {
    TooManyChannels(usize),
    ChannelTooLarge { index: usize, length: usize },
}

impl fmt::Display for AggregateShareEncodingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyChannels(count) => {
                write!(formatter, "aggregate contains too many channels: {}", count)
            }
            Self::ChannelTooLarge { index, length } => write!(
                formatter,
                "aggregate channel {} is too large: {} bytes",
                index, length
            ),
        }
    }
}

impl Error for AggregateShareEncodingError {}

#[derive(Debug)]
pub enum AggregateShareVerificationError {
    Encoding(AggregateShareEncodingError),
    InvalidSignature(ed25519_dalek::SignatureError),
}

impl fmt::Display for AggregateShareVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoding(error) => {
                write!(formatter, "could not encode aggregate share: {}", error)
            }
            Self::InvalidSignature(error) => {
                write!(formatter, "invalid aggregate signature: {}", error)
            }
        }
    }
}

impl Error for AggregateShareVerificationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Encoding(error) => Some(error),
            Self::InvalidSignature(error) => Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RoundId, WindowId};

    fn context(round: u32) -> MainRoundContext {
        MainRoundContext::new(WindowId::new(7), RoundId::try_from(round).unwrap())
    }

    fn payload(
        server: ShareServerId,
        round: u32,
        channel_data: Vec<Vec<u8>>,
    ) -> AggregateSharePayload {
        AggregateSharePayload::new(
            server,
            context(round),
            ConfigurationHash::new([0x42; 32]),
            channel_data,
        )
    }

    #[test]
    fn signing_bytes_are_deterministic() {
        let payload = payload(ShareServerId::A, 1, vec![vec![1, 2], vec![3]]);

        assert_eq!(
            payload.signing_bytes().unwrap(),
            payload.signing_bytes().unwrap()
        );
    }

    #[test]
    fn signing_bytes_bind_the_server_role() {
        let channels = vec![vec![1, 2, 3]];

        let server_a = payload(ShareServerId::A, 1, channels.clone());
        let server_b = payload(ShareServerId::B, 1, channels);

        assert_ne!(
            server_a.signing_bytes().unwrap(),
            server_b.signing_bytes().unwrap()
        );
    }

    #[test]
    fn signing_bytes_bind_the_round() {
        let round_one = payload(ShareServerId::A, 1, vec![vec![1, 2, 3]]);
        let round_two = payload(ShareServerId::A, 2, vec![vec![1, 2, 3]]);

        assert_ne!(
            round_one.signing_bytes().unwrap(),
            round_two.signing_bytes().unwrap()
        );
    }

    #[test]
    fn channel_boundaries_are_unambiguous() {
        let first = payload(ShareServerId::A, 1, vec![b"ab".to_vec(), b"c".to_vec()]);
        let second = payload(ShareServerId::A, 1, vec![b"a".to_vec(), b"bc".to_vec()]);

        assert_ne!(
            first.signing_bytes().unwrap(),
            second.signing_bytes().unwrap()
        );
    }
    fn test_signing_key(value: u8) -> SigningKey {
        SigningKey::from_bytes(&[value; 32])
    }

    #[test]
    fn correctly_signed_aggregate_is_accepted() {
        let signing_key = test_signing_key(7);
        let verifying_key = signing_key.verifying_key();

        let signed = SignedAggregateShare::sign(
            payload(ShareServerId::A, 1, vec![vec![1, 2, 3]]),
            &signing_key,
        )
        .unwrap();

        assert!(signed.verify(&verifying_key).is_ok());
    }

    #[test]
    fn another_servers_key_is_rejected() {
        let server_a_key = test_signing_key(7);
        let server_b_key = test_signing_key(9);

        let signed = SignedAggregateShare::sign(
            payload(ShareServerId::A, 1, vec![vec![1, 2, 3]]),
            &server_a_key,
        )
        .unwrap();

        assert!(signed.verify(&server_b_key.verifying_key()).is_err());
    }

    #[test]
    fn changing_the_payload_invalidates_the_signature() {
        let signing_key = test_signing_key(7);
        let verifying_key = signing_key.verifying_key();

        let signed = SignedAggregateShare::sign(
            payload(ShareServerId::A, 1, vec![vec![1, 2, 3]]),
            &signing_key,
        )
        .unwrap();

        let tampered = SignedAggregateShare {
            payload: payload(ShareServerId::A, 2, vec![vec![1, 2, 3]]),
            signature: signed.signature,
        };

        assert!(tampered.verify(&verifying_key).is_err());
    }
}
