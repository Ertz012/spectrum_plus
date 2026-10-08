use crate::{
    AtomEntry, ChannelPayload, ChannelPayloadError, ContentBindingProof, ContentProofEncodingError,
    ContentPseudonym, PseudonymEncodingError,
};
use std::{error::Error, fmt};

#[derive(Debug)]
pub enum ChannelCryptoError {
    NoAtoms,
    CountMismatch,
    Pseudonym(PseudonymEncodingError),
    Proof(ContentProofEncodingError),
    Payload(ChannelPayloadError),
}

impl fmt::Display for ChannelCryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAtoms => formatter.write_str("content-bound payload needs at least one atom"),
            Self::CountMismatch => formatter.write_str("fingerprint and pseudonym counts differ"),
            Self::Pseudonym(error) => write!(formatter, "invalid channel pseudonym: {error}"),
            Self::Proof(error) => write!(formatter, "invalid channel proof: {error}"),
            Self::Payload(error) => write!(formatter, "invalid channel payload: {error}"),
        }
    }
}

impl Error for ChannelCryptoError {}

impl ChannelPayload {
    pub fn from_content_binding(
        fingerprints: Vec<[u8; 32]>,
        pseudonyms: &[ContentPseudonym],
        proof: &ContentBindingProof,
        stix_bundle: Vec<u8>,
    ) -> Result<Self, ChannelCryptoError> {
        if fingerprints.is_empty() {
            return Err(ChannelCryptoError::NoAtoms);
        }
        if fingerprints.len() != pseudonyms.len() {
            return Err(ChannelCryptoError::CountMismatch);
        }
        let atoms = fingerprints
            .into_iter()
            .zip(pseudonyms)
            .map(|(fingerprint, pseudonym)| {
                pseudonym
                    .to_bytes()
                    .map(|encoded| AtomEntry::new(fingerprint, encoded))
                    .map_err(ChannelCryptoError::Pseudonym)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let proof = proof.encode().map_err(ChannelCryptoError::Proof)?;
        Self::new(atoms, proof, stix_bundle).map_err(ChannelCryptoError::Payload)
    }

    pub fn content_binding(
        &self,
    ) -> Result<(Vec<[u8; 32]>, Vec<ContentPseudonym>, ContentBindingProof), ChannelCryptoError>
    {
        if self.atoms().is_empty() {
            return Err(ChannelCryptoError::NoAtoms);
        }
        let fingerprints = self
            .atoms()
            .iter()
            .map(|atom| *atom.fingerprint())
            .collect();
        let pseudonyms = self
            .atoms()
            .iter()
            .map(|atom| {
                ContentPseudonym::from_bytes(atom.pseudonym())
                    .map_err(ChannelCryptoError::Pseudonym)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let proof = ContentBindingProof::decode(self.proof()).map_err(ChannelCryptoError::Proof)?;
        Ok((fingerprints, pseudonyms, proof))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        authority::AuthorityKeyManager, CredentialAttributes, CredentialPublicParameters,
        MemberCredential, MemberSecret,
    };
    use ark_bls12_381::Fr;
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
    fn cryptographic_content_survives_channel_roundtrip() {
        let (secret, credential, parameters) = issued_credential();
        let fingerprints = vec![[7; 32], [8; 32]];
        let (pseudonyms, proof) = credential
            .prove_content_binding(&secret, &fingerprints, &parameters)
            .unwrap();
        let payload = ChannelPayload::from_content_binding(
            fingerprints.clone(),
            &pseudonyms,
            &proof,
            br#"{"type":"bundle"}"#.to_vec(),
        )
        .unwrap();
        let decoded_payload = ChannelPayload::decode(&payload.encode()).unwrap();
        let (decoded_fingerprints, decoded_pseudonyms, decoded_proof) =
            decoded_payload.content_binding().unwrap();
        assert_eq!(decoded_fingerprints, fingerprints);
        assert_eq!(decoded_pseudonyms, pseudonyms);
        assert!(decoded_proof
            .verify(&decoded_fingerprints, &decoded_pseudonyms, &parameters)
            .is_ok());
    }

    #[test]
    fn malformed_pseudonym_is_rejected_at_typed_boundary() {
        let payload = ChannelPayload::new(
            vec![AtomEntry::new([7; 32], [0; ContentPseudonym::ENCODED_SIZE])],
            vec![0; 2],
            Vec::new(),
        )
        .unwrap();
        assert!(matches!(
            payload.content_binding(),
            Err(ChannelCryptoError::Pseudonym(_))
        ));
    }
}
