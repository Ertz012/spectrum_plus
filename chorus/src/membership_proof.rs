use crate::{
    pseudonym::pseudonym_base, ContentPseudonym, CredentialPublicParameters, MemberCredential,
    MemberCredentialBundle, MemberSecret, PseudonymError,
};
use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{collections::BTreeMap, collections::BTreeSet, UniformRand};
use bbs_plus::{
    error::BBSPlusError,
    proof::{PoKOfSignatureG1Proof, PoKOfSignatureG1Protocol},
};
use blake2::Blake2b512;
use dock_crypto_utils::signature::MessageOrBlinding;
use rand::{rngs::OsRng, CryptoRng, RngCore};
use schnorr_pok::{
    discrete_log::PokDiscreteLogProtocol, error::SchnorrError, partial::PartialPokDiscreteLog,
    pok_generalized_pedersen::compute_random_oracle_challenge,
};
use std::{error::Error, fmt};

const PROOF_TRANSCRIPT_DOMAIN: &[u8] = b"CHORUS-CONTENT-BINDING-PROOF-v1";
const BATCH_COEFFICIENT_DOMAIN: &[u8] = b"CHORUS-PSEUDONYM-BATCH-COEFFICIENT-v1";
const MEMBER_SECRET_INDEX: usize = 0;
pub const CONTENT_BINDING_PROOF_VERSION: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentBindingProof {
    credential_proof: PoKOfSignatureG1Proof<Bls12_381>,
    pseudonym_proof: PartialPokDiscreteLog<G1Affine>,
    challenge: Fr,
}

#[derive(Debug)]
pub enum ContentProofError {
    NoFingerprints,
    CountMismatch,
    TooManyFingerprints,
    InvalidPublicParameters,
    InvalidCredential,
    InvalidPseudonym,
    DegenerateBatch,
    Pseudonym(PseudonymError),
    Bbs(BBSPlusError),
    Schnorr(SchnorrError),
    Serialization(SerializationError),
    InvalidChallenge,
    InvalidBinding,
}

#[derive(Debug)]
pub enum ContentProofEncodingError {
    TruncatedVersion,
    UnsupportedVersion(u16),
    InvalidEncoding(SerializationError),
    TrailingBytes,
}

impl fmt::Display for ContentProofError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoFingerprints => {
                formatter.write_str("content proof needs at least one fingerprint")
            }
            Self::CountMismatch => formatter.write_str("fingerprint and pseudonym counts differ"),
            Self::TooManyFingerprints => {
                formatter.write_str("too many fingerprints in content proof")
            }
            Self::InvalidPublicParameters => formatter.write_str("invalid credential parameters"),
            Self::InvalidCredential => {
                formatter.write_str("credential does not match member secret")
            }
            Self::InvalidPseudonym => formatter.write_str("invalid content pseudonym"),
            Self::DegenerateBatch => formatter.write_str("pseudonym batch is degenerate"),
            Self::Pseudonym(error) => write!(formatter, "could not derive pseudonym: {error}"),
            Self::Bbs(error) => write!(formatter, "BBS+ proof failed: {error:?}"),
            Self::Schnorr(error) => write!(formatter, "Schnorr proof failed: {error:?}"),
            Self::Serialization(error) => write!(formatter, "proof transcript failed: {error}"),
            Self::InvalidChallenge => formatter.write_str("content proof challenge is invalid"),
            Self::InvalidBinding => formatter.write_str("pseudonym is not bound to the credential"),
        }
    }
}

impl Error for ContentProofError {}

impl fmt::Display for ContentProofEncodingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedVersion => formatter.write_str("content proof version is truncated"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported content proof version: {version}")
            }
            Self::InvalidEncoding(error) => write!(formatter, "invalid content proof: {error}"),
            Self::TrailingBytes => formatter.write_str("content proof contains trailing bytes"),
        }
    }
}

impl Error for ContentProofEncodingError {}

impl MemberCredential {
    pub fn prove_content_binding(
        &self,
        secret: &MemberSecret,
        fingerprints: &[[u8; 32]],
        parameters: &CredentialPublicParameters,
    ) -> Result<(Vec<ContentPseudonym>, ContentBindingProof), ContentProofError> {
        self.prove_content_binding_with_rng(secret, fingerprints, parameters, &mut OsRng)
    }

    fn prove_content_binding_with_rng<R: CryptoRng + RngCore>(
        &self,
        secret: &MemberSecret,
        fingerprints: &[[u8; 32]],
        parameters: &CredentialPublicParameters,
        rng: &mut R,
    ) -> Result<(Vec<ContentPseudonym>, ContentBindingProof), ContentProofError> {
        validate_inputs(fingerprints, fingerprints.len(), parameters)?;
        self.verify(secret, parameters)
            .map_err(|_| ContentProofError::InvalidCredential)?;
        let bases = pseudonym_bases(fingerprints)?;
        let pseudonyms = bases
            .iter()
            .map(|base| ContentPseudonym::from_base(base, secret))
            .collect::<Vec<_>>();
        let (aggregate_base, aggregate_pseudonym) = aggregate_pseudonyms(&bases, &pseudonyms)?;
        let shared_blinding = Fr::rand(rng);
        let messages = self.messages(secret);
        let credential_protocol = PoKOfSignatureG1Protocol::init(
            rng,
            self.signature(),
            &parameters.signature_parameters,
            messages.iter().enumerate().map(|(index, message)| {
                if index == MEMBER_SECRET_INDEX {
                    MessageOrBlinding::BlindMessageWithConcreteBlinding {
                        message,
                        blinding: shared_blinding,
                    }
                } else {
                    MessageOrBlinding::BlindMessageRandomly(message)
                }
            }),
        )
        .map_err(ContentProofError::Bbs)?;
        let pseudonym_protocol =
            PokDiscreteLogProtocol::init(*secret.scalar(), shared_blinding, &aggregate_base);
        let challenge = prover_challenge(
            parameters,
            &bases,
            &pseudonyms,
            &aggregate_base,
            &aggregate_pseudonym,
            &credential_protocol,
            &pseudonym_protocol,
        )?;
        let credential_proof = credential_protocol
            .gen_proof(&challenge)
            .map_err(ContentProofError::Bbs)?;
        let pseudonym_proof = pseudonym_protocol.gen_partial_proof();
        Ok((
            pseudonyms,
            ContentBindingProof {
                credential_proof,
                pseudonym_proof,
                challenge,
            },
        ))
    }
}

impl MemberCredentialBundle {
    pub fn prove_content_binding(
        &self,
        fingerprints: &[[u8; 32]],
        parameters: &CredentialPublicParameters,
    ) -> Result<(Vec<ContentPseudonym>, ContentBindingProof), ContentProofError> {
        let (secret, credential) = self.secret_and_credential();
        credential.prove_content_binding(secret, fingerprints, parameters)
    }
}

impl ContentBindingProof {
    pub fn encode(&self) -> Result<Vec<u8>, ContentProofEncodingError> {
        let mut encoded = CONTENT_BINDING_PROOF_VERSION.to_be_bytes().to_vec();
        self.credential_proof
            .serialize_compressed(&mut encoded)
            .map_err(ContentProofEncodingError::InvalidEncoding)?;
        self.pseudonym_proof
            .serialize_compressed(&mut encoded)
            .map_err(ContentProofEncodingError::InvalidEncoding)?;
        self.challenge
            .serialize_compressed(&mut encoded)
            .map_err(ContentProofEncodingError::InvalidEncoding)?;
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, ContentProofEncodingError> {
        let version = encoded
            .get(..2)
            .ok_or(ContentProofEncodingError::TruncatedVersion)?;
        let version = u16::from_be_bytes([version[0], version[1]]);
        if version != CONTENT_BINDING_PROOF_VERSION {
            return Err(ContentProofEncodingError::UnsupportedVersion(version));
        }
        let mut reader = &encoded[2..];
        let credential_proof = PoKOfSignatureG1Proof::deserialize_compressed(&mut reader)
            .map_err(ContentProofEncodingError::InvalidEncoding)?;
        let pseudonym_proof = PartialPokDiscreteLog::deserialize_compressed(&mut reader)
            .map_err(ContentProofEncodingError::InvalidEncoding)?;
        let challenge = Fr::deserialize_compressed(&mut reader)
            .map_err(ContentProofEncodingError::InvalidEncoding)?;
        if !reader.is_empty() {
            return Err(ContentProofEncodingError::TrailingBytes);
        }
        Ok(Self {
            credential_proof,
            pseudonym_proof,
            challenge,
        })
    }

    pub fn verify(
        &self,
        fingerprints: &[[u8; 32]],
        pseudonyms: &[ContentPseudonym],
        parameters: &CredentialPublicParameters,
    ) -> Result<(), ContentProofError> {
        validate_inputs(fingerprints, pseudonyms.len(), parameters)?;
        let bases = pseudonym_bases(fingerprints)?;
        let (aggregate_base, aggregate_pseudonym) = aggregate_pseudonyms(&bases, pseudonyms)?;
        let expected_challenge = verifier_challenge(
            parameters,
            &bases,
            pseudonyms,
            &aggregate_base,
            &aggregate_pseudonym,
            &self.credential_proof,
            &self.pseudonym_proof,
        )?;
        if expected_challenge != self.challenge {
            return Err(ContentProofError::InvalidChallenge);
        }
        let revealed_messages = BTreeMap::new();
        self.credential_proof
            .verify(
                &revealed_messages,
                &self.challenge,
                parameters.issuer_public_key.clone(),
                parameters.signature_parameters.clone(),
            )
            .map_err(ContentProofError::Bbs)?;
        let response = self
            .credential_proof
            .get_resp_for_message(MEMBER_SECRET_INDEX, &BTreeSet::new())
            .map_err(ContentProofError::Bbs)?;
        if !self.pseudonym_proof.verify(
            &aggregate_pseudonym,
            &aggregate_base,
            &self.challenge,
            response,
        ) {
            return Err(ContentProofError::InvalidBinding);
        }
        Ok(())
    }
}

fn validate_inputs(
    fingerprints: &[[u8; 32]],
    pseudonym_count: usize,
    parameters: &CredentialPublicParameters,
) -> Result<(), ContentProofError> {
    if fingerprints.is_empty() {
        return Err(ContentProofError::NoFingerprints);
    }
    if fingerprints.len() != pseudonym_count {
        return Err(ContentProofError::CountMismatch);
    }
    if u32::try_from(fingerprints.len()).is_err() {
        return Err(ContentProofError::TooManyFingerprints);
    }
    if !parameters.is_valid() {
        return Err(ContentProofError::InvalidPublicParameters);
    }
    Ok(())
}

fn pseudonym_bases(fingerprints: &[[u8; 32]]) -> Result<Vec<G1Affine>, ContentProofError> {
    fingerprints
        .iter()
        .map(|fingerprint| pseudonym_base(fingerprint).map_err(ContentProofError::Pseudonym))
        .collect()
}

fn aggregate_pseudonyms(
    bases: &[G1Affine],
    pseudonyms: &[ContentPseudonym],
) -> Result<(G1Affine, G1Affine), ContentProofError> {
    if pseudonyms
        .iter()
        .any(|pseudonym| pseudonym.point().is_zero())
    {
        return Err(ContentProofError::InvalidPseudonym);
    }
    let coefficients = batch_coefficients(bases, pseudonyms)?;
    let pseudonym_points = pseudonyms
        .iter()
        .map(|pseudonym| *pseudonym.point())
        .collect::<Vec<_>>();
    let aggregate_base = G1Projective::msm_unchecked(bases, &coefficients).into_affine();
    let aggregate_pseudonym =
        G1Projective::msm_unchecked(&pseudonym_points, &coefficients).into_affine();
    if aggregate_base.is_zero() || aggregate_pseudonym.is_zero() {
        return Err(ContentProofError::DegenerateBatch);
    }
    Ok((aggregate_base, aggregate_pseudonym))
}

fn batch_coefficients(
    bases: &[G1Affine],
    pseudonyms: &[ContentPseudonym],
) -> Result<Vec<Fr>, ContentProofError> {
    (0..bases.len())
        .map(|index| {
            let mut transcript = BATCH_COEFFICIENT_DOMAIN.to_vec();
            transcript.extend_from_slice(&(index as u32).to_be_bytes());
            transcript.extend_from_slice(&(bases.len() as u32).to_be_bytes());
            for base in bases {
                base.serialize_compressed(&mut transcript)
                    .map_err(ContentProofError::Serialization)?;
            }
            for pseudonym in pseudonyms {
                pseudonym
                    .point()
                    .serialize_compressed(&mut transcript)
                    .map_err(ContentProofError::Serialization)?;
            }
            Ok(compute_random_oracle_challenge::<Fr, Blake2b512>(
                &transcript,
            ))
        })
        .collect()
}

fn transcript_prefix(
    parameters: &CredentialPublicParameters,
    bases: &[G1Affine],
    pseudonyms: &[ContentPseudonym],
) -> Result<Vec<u8>, ContentProofError> {
    let mut transcript = PROOF_TRANSCRIPT_DOMAIN.to_vec();
    transcript.extend_from_slice(&(bases.len() as u32).to_be_bytes());
    parameters
        .issuer_public_key
        .serialize_compressed(&mut transcript)
        .map_err(ContentProofError::Serialization)?;
    for base in bases {
        base.serialize_compressed(&mut transcript)
            .map_err(ContentProofError::Serialization)?;
    }
    for pseudonym in pseudonyms {
        pseudonym
            .point()
            .serialize_compressed(&mut transcript)
            .map_err(ContentProofError::Serialization)?;
    }
    Ok(transcript)
}

fn prover_challenge(
    parameters: &CredentialPublicParameters,
    bases: &[G1Affine],
    pseudonyms: &[ContentPseudonym],
    aggregate_base: &G1Affine,
    aggregate_pseudonym: &G1Affine,
    credential_protocol: &PoKOfSignatureG1Protocol<Bls12_381>,
    pseudonym_protocol: &PokDiscreteLogProtocol<G1Affine>,
) -> Result<Fr, ContentProofError> {
    let mut transcript = transcript_prefix(parameters, bases, pseudonyms)?;
    credential_protocol
        .challenge_contribution(
            &BTreeMap::new(),
            &parameters.signature_parameters,
            &mut transcript,
        )
        .map_err(ContentProofError::Bbs)?;
    pseudonym_protocol
        .challenge_contribution(aggregate_base, aggregate_pseudonym, &mut transcript)
        .map_err(ContentProofError::Schnorr)?;
    Ok(compute_random_oracle_challenge::<Fr, Blake2b512>(
        &transcript,
    ))
}

fn verifier_challenge(
    parameters: &CredentialPublicParameters,
    bases: &[G1Affine],
    pseudonyms: &[ContentPseudonym],
    aggregate_base: &G1Affine,
    aggregate_pseudonym: &G1Affine,
    credential_proof: &PoKOfSignatureG1Proof<Bls12_381>,
    pseudonym_proof: &PartialPokDiscreteLog<G1Affine>,
) -> Result<Fr, ContentProofError> {
    let mut transcript = transcript_prefix(parameters, bases, pseudonyms)?;
    credential_proof
        .challenge_contribution(
            &BTreeMap::new(),
            &parameters.signature_parameters,
            &mut transcript,
        )
        .map_err(ContentProofError::Bbs)?;
    pseudonym_proof
        .challenge_contribution(aggregate_base, aggregate_pseudonym, &mut transcript)
        .map_err(ContentProofError::Schnorr)?;
    Ok(compute_random_oracle_challenge::<Fr, Blake2b512>(
        &transcript,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{authority::AuthorityKeyManager, CredentialAttributes};
    use rand::{rngs::StdRng, SeedableRng};

    fn issued_credential() -> (MemberSecret, MemberCredential, CredentialPublicParameters) {
        let authority = AuthorityKeyManager::generate_with_rng(&mut StdRng::seed_from_u64(1));
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

    #[test]
    fn proves_credential_and_all_pseudonyms_share_the_same_secret() {
        let (secret, credential, parameters) = issued_credential();
        let fingerprints = [[7; 32], [8; 32]];
        let (pseudonyms, proof) = credential
            .prove_content_binding_with_rng(
                &secret,
                &fingerprints,
                &parameters,
                &mut StdRng::seed_from_u64(3),
            )
            .unwrap();
        assert!(proof
            .verify(&fingerprints, &pseudonyms, &parameters)
            .is_ok());
    }

    #[test]
    fn rejects_a_proof_for_different_fingerprints() {
        let (secret, credential, parameters) = issued_credential();
        let fingerprints = [[7; 32], [8; 32]];
        let (pseudonyms, proof) = credential
            .prove_content_binding(&secret, &fingerprints, &parameters)
            .unwrap();
        assert!(proof
            .verify(&[[7; 32], [9; 32]], &pseudonyms, &parameters)
            .is_err());
    }

    #[test]
    fn rejects_a_pseudonym_from_another_member_secret() {
        let (secret, credential, parameters) = issued_credential();
        let fingerprints = [[7; 32], [8; 32]];
        let (mut pseudonyms, proof) = credential
            .prove_content_binding(&secret, &fingerprints, &parameters)
            .unwrap();
        let other_secret = MemberSecret::generate_with_rng(&mut StdRng::seed_from_u64(4));
        pseudonyms[0] = other_secret.content_pseudonym(&fingerprints[0]).unwrap();
        assert!(proof
            .verify(&fingerprints, &pseudonyms, &parameters)
            .is_err());
    }

    #[test]
    fn rejects_an_empty_fingerprint_set() {
        let (secret, credential, parameters) = issued_credential();
        assert!(matches!(
            credential.prove_content_binding(&secret, &[], &parameters),
            Err(ContentProofError::NoFingerprints)
        ));
    }

    #[test]
    fn proof_encoding_roundtrips_and_remains_valid() {
        let (secret, credential, parameters) = issued_credential();
        let fingerprints = [[7; 32], [8; 32]];
        let (pseudonyms, proof) = credential
            .prove_content_binding(&secret, &fingerprints, &parameters)
            .unwrap();
        let encoded = proof.encode().unwrap();
        let decoded = ContentBindingProof::decode(&encoded).unwrap();
        assert_eq!(decoded, proof);
        assert!(decoded
            .verify(&fingerprints, &pseudonyms, &parameters)
            .is_ok());
    }

    #[test]
    fn proof_encoding_rejects_trailing_bytes() {
        let (secret, credential, parameters) = issued_credential();
        let (_, proof) = credential
            .prove_content_binding(&secret, &[[7; 32]], &parameters)
            .unwrap();
        let mut encoded = proof.encode().unwrap();
        encoded.push(0);
        assert!(matches!(
            ContentBindingProof::decode(&encoded),
            Err(ContentProofEncodingError::TrailingBytes)
        ));
    }
}
