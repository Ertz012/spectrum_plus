use ark_bls12_381::{Bls12_381, Fr, G1Affine};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{UniformRand, Zero};
use bbs_plus::{
    error::BBSPlusError,
    setup::{PublicKeyG2, SecretKey, SignatureParamsG1},
    signature::SignatureG1,
};
use blake2::Blake2b512;
use rand::{rngs::OsRng, CryptoRng, RngCore};
use schnorr_pok::{
    discrete_log::{PokPedersenCommitment, PokPedersenCommitmentProtocol},
    error::SchnorrError,
    pok_generalized_pedersen::compute_random_oracle_challenge,
};
use std::{error::Error, fmt};

const CREDENTIAL_MESSAGE_COUNT: u32 = 4;
const CREDENTIAL_PARAMETER_LABEL: &[u8] = b"CHORUS-BBS+-CREDENTIAL-PARAMETERS-v1";
const BLIND_REQUEST_TRANSCRIPT_LABEL: &[u8] = b"CHORUS-BBS+-BLIND-REQUEST-v1";
const MEMBER_SECRET_INDEX: usize = 0;
const MEMBER_ID_INDEX: usize = 1;
const SECTOR_INDEX: usize = 2;
const JURISDICTION_INDEX: usize = 3;
pub const CREDENTIAL_PUBLIC_PARAMETERS_VERSION: u16 = 1;
pub const MEMBER_CREDENTIAL_BUNDLE_VERSION: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialPublicParameters {
    pub(crate) signature_parameters: SignatureParamsG1<Bls12_381>,
    pub(crate) issuer_public_key: PublicKeyG2<Bls12_381>,
}

impl CredentialPublicParameters {
    pub fn message_count(&self) -> usize {
        self.signature_parameters.h.len()
    }

    pub fn is_valid(&self) -> bool {
        self.signature_parameters == credential_signature_parameters()
            && self.issuer_public_key.is_valid()
    }

    pub fn encode(&self) -> Result<Vec<u8>, CredentialPublicParametersEncodingError> {
        if !self.is_valid() {
            return Err(CredentialPublicParametersEncodingError::InvalidParameters);
        }
        let mut encoded = CREDENTIAL_PUBLIC_PARAMETERS_VERSION.to_be_bytes().to_vec();
        self.issuer_public_key
            .serialize_compressed(&mut encoded)
            .map_err(CredentialPublicParametersEncodingError::InvalidEncoding)?;
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, CredentialPublicParametersEncodingError> {
        let version = encoded
            .get(..2)
            .ok_or(CredentialPublicParametersEncodingError::TruncatedVersion)?;
        let version = u16::from_be_bytes([version[0], version[1]]);
        if version != CREDENTIAL_PUBLIC_PARAMETERS_VERSION {
            return Err(CredentialPublicParametersEncodingError::UnsupportedVersion(
                version,
            ));
        }
        let mut reader = &encoded[2..];
        let issuer_public_key = PublicKeyG2::deserialize_compressed(&mut reader)
            .map_err(CredentialPublicParametersEncodingError::InvalidEncoding)?;
        if !reader.is_empty() {
            return Err(CredentialPublicParametersEncodingError::TrailingBytes);
        }
        let parameters = Self {
            signature_parameters: credential_signature_parameters(),
            issuer_public_key,
        };
        if !parameters.is_valid() {
            return Err(CredentialPublicParametersEncodingError::InvalidParameters);
        }
        Ok(parameters)
    }
}

pub struct MemberSecret(SecretKey<Fr>);

#[derive(Clone, PartialEq, Eq)]
pub struct CredentialAttributes {
    member_id: Fr,
    sector: Fr,
    jurisdiction: Fr,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlindCredentialRequest {
    commitment: G1Affine,
    proof: PokPedersenCommitment<G1Affine>,
}

pub struct PendingCredentialRequest {
    blinding: SecretKey<Fr>,
}

pub struct BlindCredential(pub(crate) SignatureG1<Bls12_381>);

pub struct MemberCredential {
    signature: SignatureG1<Bls12_381>,
    attributes: CredentialAttributes,
}

pub struct MemberCredentialBundle {
    secret: MemberSecret,
    credential: MemberCredential,
}

#[derive(Debug)]
pub enum BlindCredentialRequestError {
    InvalidPublicParameters,
    Commitment(BBSPlusError),
    Transcript(SchnorrError),
}

#[derive(Debug)]
pub enum CredentialIssuanceError {
    InvalidPublicParameters,
    InvalidRequestProof,
    Signature(BBSPlusError),
    InvalidCredential(BBSPlusError),
}

#[derive(Debug)]
pub enum CredentialPublicParametersEncodingError {
    TruncatedVersion,
    UnsupportedVersion(u16),
    InvalidEncoding(SerializationError),
    InvalidParameters,
    TrailingBytes,
}

#[derive(Debug)]
pub enum MemberCredentialBundleError {
    TruncatedVersion,
    UnsupportedVersion(u16),
    InvalidEncoding(SerializationError),
    InvalidSecret,
    InvalidCredential(CredentialIssuanceError),
    TrailingBytes,
}

impl fmt::Display for BlindCredentialRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPublicParameters => formatter.write_str("invalid credential parameters"),
            Self::Commitment(error) => write!(formatter, "could not create commitment: {error:?}"),
            Self::Transcript(error) => {
                write!(formatter, "could not create proof transcript: {error:?}")
            }
        }
    }
}

impl Error for BlindCredentialRequestError {}

impl fmt::Display for CredentialIssuanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPublicParameters => formatter.write_str("invalid credential parameters"),
            Self::InvalidRequestProof => formatter.write_str("invalid blind credential request"),
            Self::Signature(error) => write!(formatter, "could not issue credential: {error:?}"),
            Self::InvalidCredential(error) => {
                write!(formatter, "issued credential is invalid: {error:?}")
            }
        }
    }
}

impl Error for CredentialIssuanceError {}

impl fmt::Display for CredentialPublicParametersEncodingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedVersion => {
                formatter.write_str("credential parameter version is truncated")
            }
            Self::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "unsupported credential parameter version: {version}"
                )
            }
            Self::InvalidEncoding(error) => {
                write!(formatter, "invalid credential public key: {error}")
            }
            Self::InvalidParameters => formatter.write_str("invalid credential public parameters"),
            Self::TrailingBytes => {
                formatter.write_str("credential public parameters contain trailing bytes")
            }
        }
    }
}

impl Error for CredentialPublicParametersEncodingError {}

impl fmt::Display for MemberCredentialBundleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedVersion => formatter.write_str("member credential version is truncated"),
            Self::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "unsupported member credential version: {version}"
                )
            }
            Self::InvalidEncoding(error) => {
                write!(formatter, "invalid member credential encoding: {error}")
            }
            Self::InvalidSecret => formatter.write_str("member secret must not be zero"),
            Self::InvalidCredential(error) => {
                write!(formatter, "member credential verification failed: {error}")
            }
            Self::TrailingBytes => formatter.write_str("member credential contains trailing bytes"),
        }
    }
}

impl Error for MemberCredentialBundleError {}

impl CredentialAttributes {
    pub fn from_scalars(member_id: Fr, sector: Fr, jurisdiction: Fr) -> Self {
        Self {
            member_id,
            sector,
            jurisdiction,
        }
    }

    pub(crate) fn indexed_messages(&self) -> [(usize, &Fr); 3] {
        [
            (MEMBER_ID_INDEX, &self.member_id),
            (SECTOR_INDEX, &self.sector),
            (JURISDICTION_INDEX, &self.jurisdiction),
        ]
    }

    fn messages(&self, secret: &MemberSecret) -> [Fr; CREDENTIAL_MESSAGE_COUNT as usize] {
        [secret.0 .0, self.member_id, self.sector, self.jurisdiction]
    }
}

impl MemberSecret {
    pub fn generate() -> Self {
        Self::generate_with_rng(&mut OsRng)
    }

    pub fn start_credential_request(
        &self,
        parameters: &CredentialPublicParameters,
    ) -> Result<(BlindCredentialRequest, PendingCredentialRequest), BlindCredentialRequestError>
    {
        self.start_credential_request_with_rng(parameters, &mut OsRng)
    }

    pub(crate) fn generate_with_rng<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let mut secret = Fr::rand(rng);
        while secret.is_zero() {
            secret = Fr::rand(rng);
        }
        Self(SecretKey(secret))
    }

    pub(crate) fn scalar(&self) -> &Fr {
        &self.0 .0
    }

    fn start_credential_request_with_rng<R: CryptoRng + RngCore>(
        &self,
        parameters: &CredentialPublicParameters,
        rng: &mut R,
    ) -> Result<(BlindCredentialRequest, PendingCredentialRequest), BlindCredentialRequestError>
    {
        if !parameters.is_valid() {
            return Err(BlindCredentialRequestError::InvalidPublicParameters);
        }
        let blinding = SecretKey(Fr::rand(rng));
        let commitment = parameters
            .signature_parameters
            .commit_to_messages([(MEMBER_SECRET_INDEX, &self.0 .0)], &blinding.0)
            .map_err(BlindCredentialRequestError::Commitment)?;
        let protocol = PokPedersenCommitmentProtocol::init(
            self.0 .0,
            Fr::rand(rng),
            &parameters.signature_parameters.h[MEMBER_SECRET_INDEX],
            blinding.0,
            Fr::rand(rng),
            &parameters.signature_parameters.h_0,
        );
        let challenge = blind_request_challenge(parameters, &commitment, &protocol.t)?;
        Ok((
            BlindCredentialRequest {
                commitment,
                proof: protocol.gen_proof(&challenge),
            },
            PendingCredentialRequest { blinding },
        ))
    }
}

impl BlindCredentialRequest {
    pub(crate) fn verify(
        &self,
        parameters: &CredentialPublicParameters,
    ) -> Result<bool, BlindCredentialRequestError> {
        if !parameters.is_valid() {
            return Err(BlindCredentialRequestError::InvalidPublicParameters);
        }
        let challenge = blind_request_challenge(parameters, &self.commitment, &self.proof.t)?;
        Ok(self.proof.verify(
            &self.commitment,
            &parameters.signature_parameters.h[MEMBER_SECRET_INDEX],
            &parameters.signature_parameters.h_0,
            &challenge,
        ))
    }

    pub(crate) fn commitment(&self) -> &G1Affine {
        &self.commitment
    }
}

impl PendingCredentialRequest {
    pub fn matches(
        &self,
        secret: &MemberSecret,
        request: &BlindCredentialRequest,
        parameters: &CredentialPublicParameters,
    ) -> Result<bool, BlindCredentialRequestError> {
        let commitment = parameters
            .signature_parameters
            .commit_to_messages([(MEMBER_SECRET_INDEX, &secret.0 .0)], &self.blinding.0)
            .map_err(BlindCredentialRequestError::Commitment)?;
        Ok(commitment == request.commitment)
    }

    pub fn finish(
        self,
        secret: &MemberSecret,
        blind_credential: BlindCredential,
        attributes: CredentialAttributes,
        parameters: &CredentialPublicParameters,
    ) -> Result<MemberCredential, CredentialIssuanceError> {
        if !parameters.is_valid() {
            return Err(CredentialIssuanceError::InvalidPublicParameters);
        }
        let signature = blind_credential.0.unblind(&self.blinding.0);
        signature
            .verify(
                &attributes.messages(secret),
                parameters.issuer_public_key.clone(),
                parameters.signature_parameters.clone(),
            )
            .map_err(CredentialIssuanceError::InvalidCredential)?;
        Ok(MemberCredential {
            signature,
            attributes,
        })
    }
}

impl MemberCredential {
    pub fn verify(
        &self,
        secret: &MemberSecret,
        parameters: &CredentialPublicParameters,
    ) -> Result<(), CredentialIssuanceError> {
        if !parameters.is_valid() {
            return Err(CredentialIssuanceError::InvalidPublicParameters);
        }
        self.signature
            .verify(
                &self.attributes.messages(secret),
                parameters.issuer_public_key.clone(),
                parameters.signature_parameters.clone(),
            )
            .map_err(CredentialIssuanceError::InvalidCredential)
    }

    pub(crate) fn signature(&self) -> &SignatureG1<Bls12_381> {
        &self.signature
    }

    pub(crate) fn messages(
        &self,
        secret: &MemberSecret,
    ) -> [Fr; CREDENTIAL_MESSAGE_COUNT as usize] {
        self.attributes.messages(secret)
    }
}

impl MemberCredentialBundle {
    pub fn new(
        secret: MemberSecret,
        credential: MemberCredential,
        parameters: &CredentialPublicParameters,
    ) -> Result<Self, MemberCredentialBundleError> {
        credential
            .verify(&secret, parameters)
            .map_err(MemberCredentialBundleError::InvalidCredential)?;
        Ok(Self { secret, credential })
    }

    pub fn encode(
        &self,
        parameters: &CredentialPublicParameters,
    ) -> Result<Vec<u8>, MemberCredentialBundleError> {
        self.credential
            .verify(&self.secret, parameters)
            .map_err(MemberCredentialBundleError::InvalidCredential)?;
        let mut encoded = MEMBER_CREDENTIAL_BUNDLE_VERSION.to_be_bytes().to_vec();
        self.secret
            .0
            .serialize_compressed(&mut encoded)
            .map_err(MemberCredentialBundleError::InvalidEncoding)?;
        self.credential
            .signature
            .serialize_compressed(&mut encoded)
            .map_err(MemberCredentialBundleError::InvalidEncoding)?;
        self.credential
            .attributes
            .member_id
            .serialize_compressed(&mut encoded)
            .map_err(MemberCredentialBundleError::InvalidEncoding)?;
        self.credential
            .attributes
            .sector
            .serialize_compressed(&mut encoded)
            .map_err(MemberCredentialBundleError::InvalidEncoding)?;
        self.credential
            .attributes
            .jurisdiction
            .serialize_compressed(&mut encoded)
            .map_err(MemberCredentialBundleError::InvalidEncoding)?;
        Ok(encoded)
    }

    pub fn decode(
        encoded: &[u8],
        parameters: &CredentialPublicParameters,
    ) -> Result<Self, MemberCredentialBundleError> {
        let version = encoded
            .get(..2)
            .ok_or(MemberCredentialBundleError::TruncatedVersion)?;
        let version = u16::from_be_bytes([version[0], version[1]]);
        if version != MEMBER_CREDENTIAL_BUNDLE_VERSION {
            return Err(MemberCredentialBundleError::UnsupportedVersion(version));
        }
        let mut reader = &encoded[2..];
        let secret = SecretKey::<Fr>::deserialize_compressed(&mut reader)
            .map(MemberSecret)
            .map_err(MemberCredentialBundleError::InvalidEncoding)?;
        let signature = SignatureG1::deserialize_compressed(&mut reader)
            .map_err(MemberCredentialBundleError::InvalidEncoding)?;
        let member_id = Fr::deserialize_compressed(&mut reader)
            .map_err(MemberCredentialBundleError::InvalidEncoding)?;
        let sector = Fr::deserialize_compressed(&mut reader)
            .map_err(MemberCredentialBundleError::InvalidEncoding)?;
        let jurisdiction = Fr::deserialize_compressed(&mut reader)
            .map_err(MemberCredentialBundleError::InvalidEncoding)?;
        if !reader.is_empty() {
            return Err(MemberCredentialBundleError::TrailingBytes);
        }
        if secret.0 .0.is_zero() {
            return Err(MemberCredentialBundleError::InvalidSecret);
        }
        Self::new(
            secret,
            MemberCredential {
                signature,
                attributes: CredentialAttributes {
                    member_id,
                    sector,
                    jurisdiction,
                },
            },
            parameters,
        )
    }

    pub(crate) fn secret_and_credential(&self) -> (&MemberSecret, &MemberCredential) {
        (&self.secret, &self.credential)
    }
}

pub(crate) fn credential_signature_parameters() -> SignatureParamsG1<Bls12_381> {
    SignatureParamsG1::new::<Blake2b512>(CREDENTIAL_PARAMETER_LABEL, CREDENTIAL_MESSAGE_COUNT)
}

fn blind_request_challenge(
    parameters: &CredentialPublicParameters,
    commitment: &G1Affine,
    proof_commitment: &G1Affine,
) -> Result<Fr, BlindCredentialRequestError> {
    let mut transcript = BLIND_REQUEST_TRANSCRIPT_LABEL.to_vec();
    PokPedersenCommitmentProtocol::compute_challenge_contribution(
        &parameters.signature_parameters.h[MEMBER_SECRET_INDEX],
        &parameters.signature_parameters.h_0,
        commitment,
        proof_commitment,
        &mut transcript,
    )
    .map_err(BlindCredentialRequestError::Transcript)?;
    Ok(compute_random_oracle_challenge::<Fr, Blake2b512>(
        &transcript,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::AuthorityKeyManager;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn authority_accepts_proof_for_matching_commitment() {
        let authority = AuthorityKeyManager::generate_with_rng(&mut StdRng::seed_from_u64(1));
        let secret = MemberSecret::generate_with_rng(&mut StdRng::seed_from_u64(2));
        let (request, pending) = secret
            .start_credential_request_with_rng(
                authority.public_parameters(),
                &mut StdRng::seed_from_u64(3),
            )
            .unwrap();
        assert!(pending
            .matches(&secret, &request, authority.public_parameters())
            .unwrap());
        assert!(authority.verify_blind_credential_request(&request).unwrap());
    }

    #[test]
    fn authority_rejects_proof_attached_to_another_commitment() {
        let authority = AuthorityKeyManager::generate_with_rng(&mut StdRng::seed_from_u64(1));
        let first_secret = MemberSecret::generate_with_rng(&mut StdRng::seed_from_u64(2));
        let second_secret = MemberSecret::generate_with_rng(&mut StdRng::seed_from_u64(3));
        let (mut first_request, _) = first_secret
            .start_credential_request_with_rng(
                authority.public_parameters(),
                &mut StdRng::seed_from_u64(4),
            )
            .unwrap();
        let (second_request, _) = second_secret
            .start_credential_request_with_rng(
                authority.public_parameters(),
                &mut StdRng::seed_from_u64(5),
            )
            .unwrap();
        first_request.commitment = second_request.commitment;
        assert!(!authority
            .verify_blind_credential_request(&first_request)
            .unwrap());
    }

    #[test]
    fn authority_does_not_sign_an_invalid_blind_request() {
        let authority = AuthorityKeyManager::generate_with_rng(&mut StdRng::seed_from_u64(1));
        let first_secret = MemberSecret::generate_with_rng(&mut StdRng::seed_from_u64(2));
        let second_secret = MemberSecret::generate_with_rng(&mut StdRng::seed_from_u64(3));
        let attributes = CredentialAttributes::from_scalars(Fr::from(7), Fr::from(8), Fr::from(9));
        let (mut first_request, _) = first_secret
            .start_credential_request_with_rng(
                authority.public_parameters(),
                &mut StdRng::seed_from_u64(4),
            )
            .unwrap();
        let (second_request, _) = second_secret
            .start_credential_request_with_rng(
                authority.public_parameters(),
                &mut StdRng::seed_from_u64(5),
            )
            .unwrap();
        first_request.commitment = second_request.commitment;
        assert!(matches!(
            authority.issue_blind_credential(&first_request, &attributes),
            Err(CredentialIssuanceError::InvalidRequestProof)
        ));
    }

    #[test]
    fn member_rejects_a_credential_with_different_attributes() {
        let authority = AuthorityKeyManager::generate_with_rng(&mut StdRng::seed_from_u64(1));
        let secret = MemberSecret::generate_with_rng(&mut StdRng::seed_from_u64(2));
        let signed_attributes =
            CredentialAttributes::from_scalars(Fr::from(7), Fr::from(8), Fr::from(9));
        let different_attributes =
            CredentialAttributes::from_scalars(Fr::from(7), Fr::from(8), Fr::from(10));
        let (request, pending) = secret
            .start_credential_request_with_rng(
                authority.public_parameters(),
                &mut StdRng::seed_from_u64(3),
            )
            .unwrap();
        let blind_credential = authority
            .issue_blind_credential(&request, &signed_attributes)
            .unwrap();
        assert!(matches!(
            pending.finish(
                &secret,
                blind_credential,
                different_attributes,
                authority.public_parameters(),
            ),
            Err(CredentialIssuanceError::InvalidCredential(_))
        ));
    }

    #[test]
    fn public_parameters_encoding_roundtrips_without_issuer_secret() {
        let authority = AuthorityKeyManager::generate_with_rng(&mut StdRng::seed_from_u64(1));
        let encoded = authority.public_parameters().encode().unwrap();
        let decoded = CredentialPublicParameters::decode(&encoded).unwrap();
        assert_eq!(&decoded, authority.public_parameters());
    }

    #[test]
    fn public_parameters_reject_unknown_version_and_trailing_bytes() {
        let authority = AuthorityKeyManager::generate_with_rng(&mut StdRng::seed_from_u64(1));
        let mut encoded = authority.public_parameters().encode().unwrap();
        encoded[..2].copy_from_slice(&2_u16.to_be_bytes());
        assert!(matches!(
            CredentialPublicParameters::decode(&encoded),
            Err(CredentialPublicParametersEncodingError::UnsupportedVersion(
                2
            ))
        ));
        encoded[..2].copy_from_slice(&CREDENTIAL_PUBLIC_PARAMETERS_VERSION.to_be_bytes());
        encoded.push(0);
        assert!(matches!(
            CredentialPublicParameters::decode(&encoded),
            Err(CredentialPublicParametersEncodingError::TrailingBytes)
        ));
    }

    #[test]
    fn member_credential_bundle_roundtrips_and_verifies() {
        let authority = AuthorityKeyManager::generate_with_rng(&mut StdRng::seed_from_u64(1));
        let secret = MemberSecret::generate_with_rng(&mut StdRng::seed_from_u64(2));
        let attributes = CredentialAttributes::from_scalars(Fr::from(7), Fr::from(8), Fr::from(9));
        let (request, pending) = secret
            .start_credential_request(authority.public_parameters())
            .unwrap();
        let blind_credential = authority
            .issue_blind_credential(&request, &attributes)
            .unwrap();
        let credential = pending
            .finish(
                &secret,
                blind_credential,
                attributes,
                authority.public_parameters(),
            )
            .unwrap();
        let bundle =
            MemberCredentialBundle::new(secret, credential, authority.public_parameters()).unwrap();
        let encoded = bundle.encode(authority.public_parameters()).unwrap();
        let restored =
            MemberCredentialBundle::decode(&encoded, authority.public_parameters()).unwrap();
        let (secret, credential) = restored.secret_and_credential();
        assert!(credential
            .verify(secret, authority.public_parameters())
            .is_ok());
    }

    #[test]
    fn member_credential_bundle_rejects_another_issuer() {
        let authority = AuthorityKeyManager::generate_with_rng(&mut StdRng::seed_from_u64(1));
        let other_authority = AuthorityKeyManager::generate_with_rng(&mut StdRng::seed_from_u64(2));
        let secret = MemberSecret::generate_with_rng(&mut StdRng::seed_from_u64(3));
        let attributes = CredentialAttributes::from_scalars(Fr::from(7), Fr::from(8), Fr::from(9));
        let (request, pending) = secret
            .start_credential_request(authority.public_parameters())
            .unwrap();
        let blind_credential = authority
            .issue_blind_credential(&request, &attributes)
            .unwrap();
        let credential = pending
            .finish(
                &secret,
                blind_credential,
                attributes,
                authority.public_parameters(),
            )
            .unwrap();
        let bundle =
            MemberCredentialBundle::new(secret, credential, authority.public_parameters()).unwrap();
        let encoded = bundle.encode(authority.public_parameters()).unwrap();
        assert!(matches!(
            MemberCredentialBundle::decode(&encoded, other_authority.public_parameters()),
            Err(MemberCredentialBundleError::InvalidCredential(_))
        ));
    }

    #[test]
    fn member_credential_bundle_rejects_trailing_bytes() {
        let authority = AuthorityKeyManager::generate_with_rng(&mut StdRng::seed_from_u64(1));
        let secret = MemberSecret::generate_with_rng(&mut StdRng::seed_from_u64(2));
        let attributes = CredentialAttributes::from_scalars(Fr::from(7), Fr::from(8), Fr::from(9));
        let (request, pending) = secret
            .start_credential_request(authority.public_parameters())
            .unwrap();
        let blind_credential = authority
            .issue_blind_credential(&request, &attributes)
            .unwrap();
        let credential = pending
            .finish(
                &secret,
                blind_credential,
                attributes,
                authority.public_parameters(),
            )
            .unwrap();
        let bundle =
            MemberCredentialBundle::new(secret, credential, authority.public_parameters()).unwrap();
        let mut encoded = bundle.encode(authority.public_parameters()).unwrap();
        encoded.push(0);
        assert!(matches!(
            MemberCredentialBundle::decode(&encoded, authority.public_parameters()),
            Err(MemberCredentialBundleError::TrailingBytes)
        ));
    }
}
