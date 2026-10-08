//! Authority-owned BBS+ issuer keys and public credential parameters.

use crate::{
    credential::credential_signature_parameters, BlindCredential, BlindCredentialRequest,
    BlindCredentialRequestError, CredentialAttributes, CredentialIssuanceError,
    CredentialPublicParameters,
};
use ark_bls12_381::{Bls12_381, Fr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::Zero;
use bbs_plus::setup::{KeypairG2, PublicKeyG2, SecretKey};
use bbs_plus::signature::SignatureG1;
use rand::{rngs::OsRng, CryptoRng, RngCore};
use std::{collections::BTreeMap, error::Error, fmt};

pub const AUTHORITY_KEY_MANAGER_STATE_VERSION: u16 = 1;

pub struct AuthorityKeyManager {
    issuer_keypair: KeypairG2<Bls12_381>,
    public_parameters: CredentialPublicParameters,
}

#[derive(Debug)]
pub enum AuthorityKeyManagerStateError {
    TruncatedVersion,
    UnsupportedVersion(u16),
    InvalidEncoding(SerializationError),
    InvalidSecretKey,
    InconsistentState,
    TrailingBytes,
}

impl fmt::Display for AuthorityKeyManagerStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedVersion => {
                formatter.write_str("authority key state version is truncated")
            }
            Self::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "unsupported authority key state version: {version}"
                )
            }
            Self::InvalidEncoding(error) => {
                write!(formatter, "invalid authority secret key: {error}")
            }
            Self::InvalidSecretKey => formatter.write_str("authority secret key must not be zero"),
            Self::InconsistentState => formatter.write_str("authority key state is inconsistent"),
            Self::TrailingBytes => {
                formatter.write_str("authority key state contains trailing bytes")
            }
        }
    }
}

impl Error for AuthorityKeyManagerStateError {}

impl AuthorityKeyManager {
    pub fn generate() -> Self {
        Self::generate_with_rng(&mut OsRng)
    }

    pub fn public_parameters(&self) -> &CredentialPublicParameters {
        &self.public_parameters
    }

    pub fn encode_state(&self) -> Result<Vec<u8>, AuthorityKeyManagerStateError> {
        if !self.is_consistent() {
            return Err(AuthorityKeyManagerStateError::InconsistentState);
        }
        let mut encoded = AUTHORITY_KEY_MANAGER_STATE_VERSION.to_be_bytes().to_vec();
        self.issuer_keypair
            .secret_key
            .serialize_compressed(&mut encoded)
            .map_err(AuthorityKeyManagerStateError::InvalidEncoding)?;
        Ok(encoded)
    }

    pub fn decode_state(encoded: &[u8]) -> Result<Self, AuthorityKeyManagerStateError> {
        let version = encoded
            .get(..2)
            .ok_or(AuthorityKeyManagerStateError::TruncatedVersion)?;
        let version = u16::from_be_bytes([version[0], version[1]]);
        if version != AUTHORITY_KEY_MANAGER_STATE_VERSION {
            return Err(AuthorityKeyManagerStateError::UnsupportedVersion(version));
        }
        let mut reader = &encoded[2..];
        let secret_key = SecretKey::<Fr>::deserialize_compressed(&mut reader)
            .map_err(AuthorityKeyManagerStateError::InvalidEncoding)?;
        if !reader.is_empty() {
            return Err(AuthorityKeyManagerStateError::TrailingBytes);
        }
        if secret_key.0.is_zero() {
            return Err(AuthorityKeyManagerStateError::InvalidSecretKey);
        }
        let signature_parameters = credential_signature_parameters();
        let public_key = PublicKeyG2::generate_using_secret_key(&secret_key, &signature_parameters);
        let manager = Self {
            public_parameters: CredentialPublicParameters {
                signature_parameters,
                issuer_public_key: public_key.clone(),
            },
            issuer_keypair: KeypairG2 {
                secret_key,
                public_key,
            },
        };
        if !manager.is_consistent() {
            return Err(AuthorityKeyManagerStateError::InconsistentState);
        }
        Ok(manager)
    }

    pub fn is_consistent(&self) -> bool {
        PublicKeyG2::generate_using_secret_key(
            &self.issuer_keypair.secret_key,
            &self.public_parameters.signature_parameters,
        ) == self.public_parameters.issuer_public_key
    }

    pub fn verify_blind_credential_request(
        &self,
        request: &BlindCredentialRequest,
    ) -> Result<bool, BlindCredentialRequestError> {
        request.verify(&self.public_parameters)
    }

    pub fn issue_blind_credential(
        &self,
        request: &BlindCredentialRequest,
        attributes: &CredentialAttributes,
    ) -> Result<BlindCredential, CredentialIssuanceError> {
        self.issue_blind_credential_with_rng(request, attributes, &mut OsRng)
    }

    fn issue_blind_credential_with_rng<R: CryptoRng + RngCore>(
        &self,
        request: &BlindCredentialRequest,
        attributes: &CredentialAttributes,
        rng: &mut R,
    ) -> Result<BlindCredential, CredentialIssuanceError> {
        if !self.public_parameters.is_valid() {
            return Err(CredentialIssuanceError::InvalidPublicParameters);
        }
        if !request
            .verify(&self.public_parameters)
            .map_err(|_| CredentialIssuanceError::InvalidRequestProof)?
        {
            return Err(CredentialIssuanceError::InvalidRequestProof);
        }
        let messages = BTreeMap::from(attributes.indexed_messages());
        SignatureG1::new_with_committed_messages(
            rng,
            request.commitment(),
            messages,
            &self.issuer_keypair.secret_key,
            &self.public_parameters.signature_parameters,
        )
        .map(BlindCredential)
        .map_err(CredentialIssuanceError::Signature)
    }

    pub(crate) fn generate_with_rng<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let signature_parameters = credential_signature_parameters();
        let issuer_keypair = loop {
            let keypair = KeypairG2::generate_using_rng(rng, &signature_parameters);
            if keypair.public_key.is_valid() {
                break keypair;
            }
        };
        Self {
            public_parameters: CredentialPublicParameters {
                signature_parameters,
                issuer_public_key: issuer_keypair.public_key.clone(),
            },
            issuer_keypair,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemberSecret;
    use ark_bls12_381::Fr;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn creates_valid_public_parameters_for_all_credential_messages() {
        let manager = AuthorityKeyManager::generate_with_rng(&mut StdRng::seed_from_u64(1));
        assert!(manager.public_parameters().is_valid());
        assert_eq!(manager.public_parameters().message_count(), 4);
        assert!(manager.is_consistent());
    }

    #[test]
    fn authorities_share_parameters_but_have_distinct_issuer_keys() {
        let first = AuthorityKeyManager::generate_with_rng(&mut StdRng::seed_from_u64(1));
        let second = AuthorityKeyManager::generate_with_rng(&mut StdRng::seed_from_u64(2));
        assert_eq!(
            first.public_parameters.signature_parameters,
            second.public_parameters.signature_parameters
        );
        assert_ne!(
            first.public_parameters.issuer_public_key,
            second.public_parameters.issuer_public_key
        );
    }

    #[test]
    fn issues_and_unblinds_a_valid_credential() {
        let authority = AuthorityKeyManager::generate_with_rng(&mut StdRng::seed_from_u64(1));
        let secret = MemberSecret::generate();
        let attributes = CredentialAttributes::from_scalars(Fr::from(7), Fr::from(8), Fr::from(9));
        let (request, pending) = secret
            .start_credential_request(authority.public_parameters())
            .unwrap();
        let blind_credential = authority
            .issue_blind_credential_with_rng(&request, &attributes, &mut StdRng::seed_from_u64(4))
            .unwrap();
        let credential = pending
            .finish(
                &secret,
                blind_credential,
                attributes,
                authority.public_parameters(),
            )
            .unwrap();
        assert!(credential
            .verify(&secret, authority.public_parameters())
            .is_ok());
    }

    #[test]
    fn persisted_state_roundtrips_and_can_still_issue_credentials() {
        let authority = AuthorityKeyManager::generate_with_rng(&mut StdRng::seed_from_u64(1));
        let encoded = authority.encode_state().unwrap();
        let restored = AuthorityKeyManager::decode_state(&encoded).unwrap();
        assert_eq!(restored.public_parameters(), authority.public_parameters());
        assert!(restored.is_consistent());

        let secret = MemberSecret::generate_with_rng(&mut StdRng::seed_from_u64(2));
        let attributes = CredentialAttributes::from_scalars(Fr::from(7), Fr::from(8), Fr::from(9));
        let (request, pending) = secret
            .start_credential_request(restored.public_parameters())
            .unwrap();
        let blind_credential = restored
            .issue_blind_credential(&request, &attributes)
            .unwrap();
        assert!(pending
            .finish(
                &secret,
                blind_credential,
                attributes,
                restored.public_parameters()
            )
            .is_ok());
    }

    #[test]
    fn issuing_a_credential_does_not_add_member_state() {
        let authority = AuthorityKeyManager::generate_with_rng(&mut StdRng::seed_from_u64(1));
        let before = authority.encode_state().unwrap();
        let secret = MemberSecret::generate_with_rng(&mut StdRng::seed_from_u64(2));
        let attributes = CredentialAttributes::from_scalars(Fr::from(7), Fr::from(8), Fr::from(9));
        let (request, _) = secret
            .start_credential_request(authority.public_parameters())
            .unwrap();
        authority
            .issue_blind_credential(&request, &attributes)
            .unwrap();
        assert_eq!(authority.encode_state().unwrap(), before);
    }

    #[test]
    fn persisted_state_rejects_unknown_versions_and_trailing_bytes() {
        let authority = AuthorityKeyManager::generate_with_rng(&mut StdRng::seed_from_u64(1));
        let mut encoded = authority.encode_state().unwrap();
        encoded[..2].copy_from_slice(&2_u16.to_be_bytes());
        assert!(matches!(
            AuthorityKeyManager::decode_state(&encoded),
            Err(AuthorityKeyManagerStateError::UnsupportedVersion(2))
        ));
        encoded[..2].copy_from_slice(&AUTHORITY_KEY_MANAGER_STATE_VERSION.to_be_bytes());
        encoded.push(0);
        assert!(matches!(
            AuthorityKeyManager::decode_state(&encoded),
            Err(AuthorityKeyManagerStateError::TrailingBytes)
        ));
    }
}
