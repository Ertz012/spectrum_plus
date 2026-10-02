use crate::MainRoundContext;
use spectrum::{
    client::viewer, config::Store, protocols::wrapper::ProtocolWrapper, services::ClientInfo,
};
use std::{error::Error, future::Future};

type BoxedError = Box<dyn Error + Sync + Send>;

/// Runs one CHORUS member for exactly one main round.
///
/// The existing Spectrum client generates and sends the two DPF shares.
/// CHORUS supplies the explicit window and round identity.
pub async fn run_development<C, F>(
    context: MainRoundContext,
    config: C,
    protocol: ProtocolWrapper,
    info: ClientInfo,
    max_jitter: u64,
    shutdown: F,
) -> Result<(), BoxedError>
where
    C: Store,
    F: Future<Output = ()> + Send + 'static,
{
    viewer::run_for_round(
        config,
        protocol,
        info,
        context.window().get(),
        context.round().get(),
        false,
        None,
        max_jitter,
        shutdown,
    )
    .await
}
