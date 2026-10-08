//! CHORUS Authority: key management, verification, and publication.

mod key_manager;
mod publication;
mod publication_log;
mod publisher;
mod seen_set;
mod verifier;

pub use crate::CredentialPublicParameters;
pub use key_manager::{
    AuthorityKeyManager, AuthorityKeyManagerStateError, AUTHORITY_KEY_MANAGER_STATE_VERSION,
};
pub use publication::{
    PublicationEncodingError, PublicationVerificationError, PublishedAtom, PublishedAtomStatus,
    PublishedChannel, PublishedChannelStatus, PublishedRound, SignedPublishedRound,
    PUBLISHED_ROUND_VERSION,
};
pub use publication_log::{
    PersistentPublicationLog, PublicationAppendStatus, PublicationLogError, PUBLICATION_LOG_VERSION,
};
pub use publisher::run_development;
pub use seen_set::{PersistentSeenSet, SeenSetError, SEEN_SET_VERSION};
pub use verifier::{
    AtomDuplicateStatus, ContentProofStatus, DecodedChannel, DecodedRound, RoundDeduplicationError,
    SelfBindingStatus,
};
