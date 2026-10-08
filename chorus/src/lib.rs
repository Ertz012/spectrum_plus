//! CHORUS integration layer built on Spectrum.
mod aggregate;
pub mod bootstrap;
mod channel_crypto;
mod channel_payload;
mod credential;
mod fingerprint;
mod membership_proof;
mod pseudonym;
mod round;

pub mod authority;
pub mod consumer;
pub mod member;
pub mod share_server;

pub use aggregate::{
    AggregateShareEncodingError, AggregateSharePayload, AggregateShareVerificationError,
    ConfigurationHash, SignedAggregateShare, AGGREGATE_SHARE_VERSION,
};
pub use channel_crypto::ChannelCryptoError;
pub use channel_payload::{
    AtomEntry, ChannelPayload, ChannelPayloadError, CHANNEL_PAYLOAD_VERSION, CHANNEL_SLOT_SIZE,
};
pub use credential::{
    BlindCredential, BlindCredentialRequest, BlindCredentialRequestError, CredentialAttributes,
    CredentialIssuanceError, CredentialPublicParameters, CredentialPublicParametersEncodingError,
    MemberCredential, MemberCredentialBundle, MemberCredentialBundleError, MemberSecret,
    PendingCredentialRequest, CREDENTIAL_PUBLIC_PARAMETERS_VERSION,
    MEMBER_CREDENTIAL_BUNDLE_VERSION,
};
pub use fingerprint::{compute_atom_fingerprints, FingerprintError};
pub use membership_proof::{
    ContentBindingProof, ContentProofEncodingError, ContentProofError,
    CONTENT_BINDING_PROOF_VERSION,
};
pub use pseudonym::{ContentPseudonym, PseudonymEncodingError, PseudonymError};

pub use round::{
    InvalidRoundId, MainRoundContext, RoundId, RoundLifecycle, RoundLifecycleError, RoundStatus,
    WindowId,
};
