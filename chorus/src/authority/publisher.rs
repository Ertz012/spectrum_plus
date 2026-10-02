use crate::{MainRoundContext, RoundLifecycle, RoundLifecycleError};
use spectrum::{
    config::Store,
    net::Config as NetConfig,
    protocols::wrapper::ProtocolWrapper,
    publisher::{self as spectrum_publisher, Remote},
    services::PublisherInfo,
};
use std::{future::Future, sync::Arc};
use tokio::sync::{Mutex, Notify};

struct AuthorityRoundState {
    lifecycle: RoundLifecycle,
    completion: Option<Result<(), RoundLifecycleError>>,
}

#[derive(Clone)]
struct AuthorityRemote {
    expected_context: MainRoundContext,
    state: Arc<Mutex<AuthorityRoundState>>,
    completed: Arc<Notify>,
}

impl AuthorityRemote {
    fn new(expected_context: MainRoundContext, completed: Arc<Notify>) -> Self {
        Self {
            expected_context,
            state: Arc::new(Mutex::new(AuthorityRoundState {
                lifecycle: RoundLifecycle::new(expected_context),
                completion: None,
            })),
            completed,
        }
    }

    async fn completion(&self) -> Option<Result<(), RoundLifecycleError>> {
        self.state.lock().await.completion
    }
}

#[tonic::async_trait]
impl Remote for AuthorityRemote {
    async fn start(&self) {}

    async fn done(&self) {
        {
            let mut state = self.state.lock().await;
            let result = state.lifecycle.finalize(self.expected_context);
            state.completion = Some(result);
        }

        self.completed.notify_one();
    }
}

/// Runs the initial Authority data path using Spectrum's existing publisher.
///
/// This compatibility stage does not yet perform CHORUS verification,
/// credential issuance, or signed publication.
pub async fn run_development<C, F>(
    expected_context: MainRoundContext,
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
    let expected_window = expected_context.window().get();
    let expected_round = expected_context.round().get();

    let completed = Arc::new(Notify::new());
    let remote = AuthorityRemote::new(expected_context, completed.clone());
    let remote_result = remote.clone();

    let round_shutdown = async move {
        tokio::select! {
            _ = shutdown => {}
            _ = completed.notified() => {}
        }
    };

    spectrum_publisher::run_for_round(
        config,
        protocol,
        PublisherInfo::new(),
        expected_window,
        expected_round,
        net,
        remote,
        round_shutdown,
        delay_ms,
    )
    .await?;

    if let Some(Err(error)) = remote_result.completion().await {
        return Err(Box::new(error));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RoundId, RoundStatus, WindowId};

    fn context(window: u64, round: u32) -> MainRoundContext {
        MainRoundContext::new(WindowId::new(window), RoundId::try_from(round).unwrap())
    }

    #[tokio::test]
    async fn publisher_completion_finalizes_the_round() {
        let expected_context = context(3, 2);
        let completed = Arc::new(Notify::new());
        let remote = AuthorityRemote::new(expected_context, completed);

        remote.done().await;

        let state = remote.state.lock().await;

        assert_eq!(state.lifecycle.status(), RoundStatus::Finalized);
        assert_eq!(state.completion, Some(Ok(())));
    }
}
