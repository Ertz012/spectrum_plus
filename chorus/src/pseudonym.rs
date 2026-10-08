use crate::MemberSecret;
use ark_bls12_381::{g1, G1Affine, G1Projective};
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    AffineRepr, CurveGroup,
};
use ark_ff::{field_hashers::DefaultFieldHasher, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use sha2::Sha256;
use std::{error::Error, fmt};

const PSEUDONYM_DOMAIN: &[u8] = b"CHORUS-PSEUDONYM-H2C-v1";
const PSEUDONYM_ENCODED_SIZE: usize = 48;

type PseudonymHasher =
    MapToCurveBasedHasher<G1Projective, DefaultFieldHasher<Sha256, 128>, WBMap<g1::Config>>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentPseudonym(G1Affine);

#[derive(Debug)]
pub struct PseudonymError(ark_ec::hashing::HashToCurveError);

#[derive(Debug)]
pub enum PseudonymEncodingError {
    InvalidEncoding(SerializationError),
    Identity,
}

impl fmt::Display for PseudonymError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "fingerprint hash-to-curve failed: {}", self.0)
    }
}

impl Error for PseudonymError {}

impl fmt::Display for PseudonymEncodingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEncoding(error) => {
                write!(formatter, "invalid pseudonym encoding: {error}")
            }
            Self::Identity => formatter.write_str("pseudonym must not be the identity point"),
        }
    }
}

impl Error for PseudonymEncodingError {}

impl MemberSecret {
    pub fn content_pseudonym(
        &self,
        fingerprint: &[u8; 32],
    ) -> Result<ContentPseudonym, PseudonymError> {
        Ok(ContentPseudonym::from_base(
            &pseudonym_base(fingerprint)?,
            self,
        ))
    }
}

impl ContentPseudonym {
    pub const ENCODED_SIZE: usize = PSEUDONYM_ENCODED_SIZE;

    pub fn to_bytes(&self) -> Result<[u8; PSEUDONYM_ENCODED_SIZE], PseudonymEncodingError> {
        let mut encoded = [0; PSEUDONYM_ENCODED_SIZE];
        self.0
            .serialize_compressed(&mut encoded[..])
            .map_err(PseudonymEncodingError::InvalidEncoding)?;
        Ok(encoded)
    }

    pub fn from_bytes(
        encoded: &[u8; PSEUDONYM_ENCODED_SIZE],
    ) -> Result<Self, PseudonymEncodingError> {
        let mut reader = &encoded[..];
        let point = G1Affine::deserialize_compressed(&mut reader)
            .map_err(PseudonymEncodingError::InvalidEncoding)?;
        if point.is_zero() {
            return Err(PseudonymEncodingError::Identity);
        }
        Ok(Self(point))
    }

    pub(crate) fn from_base(base: &G1Affine, secret: &MemberSecret) -> Self {
        Self(base.mul_bigint(secret.scalar().into_bigint()).into_affine())
    }

    pub(crate) fn point(&self) -> &G1Affine {
        &self.0
    }
}

pub(crate) fn pseudonym_base(fingerprint: &[u8; 32]) -> Result<G1Affine, PseudonymError> {
    PseudonymHasher::new(PSEUDONYM_DOMAIN)
        .and_then(|hasher| hasher.hash(fingerprint))
        .map_err(PseudonymError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn same_member_and_fingerprint_produce_same_pseudonym() {
        let secret = MemberSecret::generate_with_rng(&mut StdRng::seed_from_u64(1));
        let fingerprint = [7; 32];
        let pseudonym = secret.content_pseudonym(&fingerprint).unwrap();
        assert!(!pseudonym.0.is_zero());
        assert_eq!(pseudonym, secret.content_pseudonym(&fingerprint).unwrap());
    }

    #[test]
    fn fingerprint_changes_the_pseudonym() {
        let secret = MemberSecret::generate_with_rng(&mut StdRng::seed_from_u64(1));
        assert_ne!(
            secret.content_pseudonym(&[7; 32]).unwrap(),
            secret.content_pseudonym(&[8; 32]).unwrap()
        );
    }

    #[test]
    fn member_secret_changes_the_pseudonym() {
        let first = MemberSecret::generate_with_rng(&mut StdRng::seed_from_u64(1));
        let second = MemberSecret::generate_with_rng(&mut StdRng::seed_from_u64(2));
        let fingerprint = [7; 32];
        assert_ne!(
            first.content_pseudonym(&fingerprint).unwrap(),
            second.content_pseudonym(&fingerprint).unwrap()
        );
    }

    #[test]
    fn compressed_encoding_roundtrips() {
        let secret = MemberSecret::generate_with_rng(&mut StdRng::seed_from_u64(1));
        let pseudonym = secret.content_pseudonym(&[7; 32]).unwrap();
        let encoded = pseudonym.to_bytes().unwrap();
        assert_eq!(encoded.len(), ContentPseudonym::ENCODED_SIZE);
        assert_eq!(ContentPseudonym::from_bytes(&encoded).unwrap(), pseudonym);
    }
}
