use spectrum::{
    config::Store, net::Config as NetConfig, protocols::wrapper::ProtocolWrapper,
    publisher::NoopRemote, services::PublisherInfo,
};
use std::future::Future;

/// Runs the initial Authority data path using Spectrum's existing publisher.
///
/// This compatibility stage does not yet perform CHORUS verification,
/// credential issuance, or signed publication.
pub async fn run_development<C, F>(
    config: C,
    protocol: ProtocolWrapper,
    net: NetConfig,
    shutdown: F,
    delay_ms: i64,
) -> Result<(), Box<dyn std::error::Error + Sync + Send>>
where
    C: Store + Sync + Send,
    F: Future<Output = ()> + Send + 'static,
{
    spectrum::publisher::run(
        config,
        protocol,
        PublisherInfo::new(),
        net,
        NoopRemote,
        shutdown,
        delay_ms,
    )
    .await
}
