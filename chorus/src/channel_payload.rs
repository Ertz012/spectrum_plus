use std::{error::Error, fmt};

pub const CHANNEL_PAYLOAD_VERSION: u16 = 2;
pub const CHANNEL_SLOT_SIZE: usize = 32_768;

const FINGERPRINT_SIZE: usize = 32;
const PSEUDONYM_SIZE: usize = 48;
const ATOM_SIZE: usize = FINGERPRINT_SIZE + PSEUDONYM_SIZE;
const FIXED_FIELDS_SIZE: usize = 2 + 2 + 2 + 4;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtomEntry {
    fingerprint: [u8; FINGERPRINT_SIZE],
    pseudonym: [u8; PSEUDONYM_SIZE],
}

impl AtomEntry {
    pub const fn new(fingerprint: [u8; FINGERPRINT_SIZE], pseudonym: [u8; PSEUDONYM_SIZE]) -> Self {
        Self {
            fingerprint,
            pseudonym,
        }
    }

    pub const fn fingerprint(&self) -> &[u8; FINGERPRINT_SIZE] {
        &self.fingerprint
    }

    pub const fn pseudonym(&self) -> &[u8; PSEUDONYM_SIZE] {
        &self.pseudonym
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelPayload {
    atoms: Vec<AtomEntry>,
    proof: Vec<u8>,
    stix_bundle: Vec<u8>,
}

impl ChannelPayload {
    pub fn new(
        atoms: Vec<AtomEntry>,
        proof: Vec<u8>,
        stix_bundle: Vec<u8>,
    ) -> Result<Self, ChannelPayloadError> {
        validate_lengths(atoms.len(), proof.len(), stix_bundle.len())?;
        Ok(Self {
            atoms,
            proof,
            stix_bundle,
        })
    }

    pub const fn format_version(&self) -> u16 {
        CHANNEL_PAYLOAD_VERSION
    }

    pub fn atoms(&self) -> &[AtomEntry] {
        &self.atoms
    }

    pub fn proof(&self) -> &[u8] {
        &self.proof
    }

    pub fn stix_bundle(&self) -> &[u8] {
        &self.stix_bundle
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(CHANNEL_SLOT_SIZE);
        encoded.extend_from_slice(&CHANNEL_PAYLOAD_VERSION.to_be_bytes());
        encoded.extend_from_slice(&(self.atoms.len() as u16).to_be_bytes());
        for atom in &self.atoms {
            encoded.extend_from_slice(atom.fingerprint());
            encoded.extend_from_slice(atom.pseudonym());
        }
        encoded.extend_from_slice(&(self.proof.len() as u16).to_be_bytes());
        encoded.extend_from_slice(&self.proof);
        encoded.extend_from_slice(&(self.stix_bundle.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&self.stix_bundle);
        encoded.resize(CHANNEL_SLOT_SIZE, 0);
        encoded
    }

    pub fn decode(slot: &[u8]) -> Result<Self, ChannelPayloadError> {
        if slot.len() != CHANNEL_SLOT_SIZE {
            return Err(ChannelPayloadError::InvalidSlotLength(slot.len()));
        }
        let mut reader = Reader::new(slot);
        let version = reader.read_u16("format version")?;
        if version != CHANNEL_PAYLOAD_VERSION {
            return Err(ChannelPayloadError::UnsupportedVersion(version));
        }
        let atom_count = usize::from(reader.read_u16("atom count")?);
        validate_lengths(atom_count, 0, 0)?;
        let mut atoms = Vec::with_capacity(atom_count);
        for _ in 0..atom_count {
            atoms.push(AtomEntry::new(
                reader.read_array("fingerprint")?,
                reader.read_array("pseudonym")?,
            ));
        }
        let proof_len = usize::from(reader.read_u16("proof length")?);
        let proof = reader.take(proof_len, "proof")?.to_vec();
        let stix_len = usize::try_from(reader.read_u32("STIX bundle length")?)
            .map_err(|_| ChannelPayloadError::LengthOverflow)?;
        let stix_bundle = reader.take(stix_len, "STIX bundle")?.to_vec();
        if reader.remaining().iter().any(|byte| *byte != 0) {
            return Err(ChannelPayloadError::NonZeroPadding);
        }
        Self::new(atoms, proof, stix_bundle)
    }
}

fn validate_lengths(
    atoms: usize,
    proof: usize,
    stix_bundle: usize,
) -> Result<(), ChannelPayloadError> {
    u16::try_from(atoms).map_err(|_| ChannelPayloadError::TooManyAtoms(atoms))?;
    u16::try_from(proof).map_err(|_| ChannelPayloadError::ProofTooLarge(proof))?;
    u32::try_from(stix_bundle).map_err(|_| ChannelPayloadError::StixBundleTooLarge(stix_bundle))?;
    let encoded = FIXED_FIELDS_SIZE
        .checked_add(
            atoms
                .checked_mul(ATOM_SIZE)
                .ok_or(ChannelPayloadError::LengthOverflow)?,
        )
        .and_then(|size| size.checked_add(proof))
        .and_then(|size| size.checked_add(stix_bundle))
        .ok_or(ChannelPayloadError::LengthOverflow)?;
    if encoded > CHANNEL_SLOT_SIZE {
        return Err(ChannelPayloadError::PayloadTooLarge(encoded));
    }
    Ok(())
}

struct Reader<'a> {
    slot: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(slot: &'a [u8]) -> Self {
        Self { slot, offset: 0 }
    }

    fn take(
        &mut self,
        length: usize,
        field: &'static str,
    ) -> Result<&'a [u8], ChannelPayloadError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ChannelPayloadError::LengthOverflow)?;
        let bytes = self
            .slot
            .get(self.offset..end)
            .ok_or(ChannelPayloadError::Truncated(field))?;
        self.offset = end;
        Ok(bytes)
    }

    fn read_u16(&mut self, field: &'static str) -> Result<u16, ChannelPayloadError> {
        let bytes = self.take(2, field)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self, field: &'static str) -> Result<u32, ChannelPayloadError> {
        let bytes = self.take(4, field)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_array<const N: usize>(
        &mut self,
        field: &'static str,
    ) -> Result<[u8; N], ChannelPayloadError> {
        let mut result = [0; N];
        result.copy_from_slice(self.take(N, field)?);
        Ok(result)
    }

    fn remaining(&self) -> &'a [u8] {
        &self.slot[self.offset..]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelPayloadError {
    InvalidSlotLength(usize),
    UnsupportedVersion(u16),
    TooManyAtoms(usize),
    ProofTooLarge(usize),
    StixBundleTooLarge(usize),
    PayloadTooLarge(usize),
    Truncated(&'static str),
    NonZeroPadding,
    LengthOverflow,
}

impl fmt::Display for ChannelPayloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSlotLength(length) => write!(
                formatter,
                "channel slot must contain {} bytes; got {}",
                CHANNEL_SLOT_SIZE, length
            ),
            Self::UnsupportedVersion(version) => write!(
                formatter,
                "unsupported channel payload version: {}",
                version
            ),
            Self::TooManyAtoms(count) => write!(
                formatter,
                "channel payload contains too many atoms: {}",
                count
            ),
            Self::ProofTooLarge(length) => {
                write!(formatter, "channel proof is too large: {} bytes", length)
            }
            Self::StixBundleTooLarge(length) => {
                write!(formatter, "STIX bundle is too large: {} bytes", length)
            }
            Self::PayloadTooLarge(length) => write!(
                formatter,
                "encoded channel payload exceeds {} bytes: {}",
                CHANNEL_SLOT_SIZE, length
            ),
            Self::Truncated(field) => write!(
                formatter,
                "channel payload is truncated while reading {}",
                field
            ),
            Self::NonZeroPadding => {
                formatter.write_str("channel payload contains non-zero padding")
            }
            Self::LengthOverflow => formatter.write_str("channel payload length overflow"),
        }
    }
}

impl Error for ChannelPayloadError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> ChannelPayload {
        ChannelPayload::new(
            vec![AtomEntry::new([1; FINGERPRINT_SIZE], [2; PSEUDONYM_SIZE])],
            vec![3, 4, 5],
            br#"{"type":"bundle"}"#.to_vec(),
        )
        .unwrap()
    }

    #[test]
    fn payload_roundtrip_preserves_all_fields() {
        let payload = payload();
        let encoded = payload.encode();
        assert_eq!(encoded.len(), CHANNEL_SLOT_SIZE);
        assert_eq!(ChannelPayload::decode(&encoded), Ok(payload));
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let mut encoded = payload().encode();
        encoded[..2].copy_from_slice(&3_u16.to_be_bytes());
        assert_eq!(
            ChannelPayload::decode(&encoded),
            Err(ChannelPayloadError::UnsupportedVersion(3))
        );
    }

    #[test]
    fn non_zero_padding_is_rejected() {
        let mut encoded = payload().encode();
        *encoded.last_mut().unwrap() = 1;
        assert_eq!(
            ChannelPayload::decode(&encoded),
            Err(ChannelPayloadError::NonZeroPadding)
        );
    }

    #[test]
    fn oversized_payload_is_rejected() {
        let result = ChannelPayload::new(Vec::new(), Vec::new(), vec![0; CHANNEL_SLOT_SIZE]);
        assert_eq!(
            result,
            Err(ChannelPayloadError::PayloadTooLarge(
                CHANNEL_SLOT_SIZE + FIXED_FIELDS_SIZE
            ))
        );
    }
}
