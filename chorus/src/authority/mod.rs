//! CHORUS Authority: key management, verification, and publication.

mod key_manager;
mod publisher;
mod verifier;

pub use publisher::run_development;