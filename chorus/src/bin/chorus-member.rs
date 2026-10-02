use chorus::{member, MainRoundContext, RoundId, WindowId};
use clap::{crate_authors, crate_version, Parser};
use spectrum::{cli, config, experiment, services::Service};
use std::io::{Error, ErrorKind};
use tokio::signal::ctrl_c;

#[derive(Parser)]
#[clap(version = crate_version!(), author = crate_authors!())]
struct Args {
    #[clap(flatten)]
    logs: cli::LogArgs,

    /// Member identity from the configured Spectrum development experiment.
    #[clap(long, env = "CHORUS_MEMBER_ID")]
    member_id: u128,

    /// Current CHORUS window.
    #[clap(long, env = "CHORUS_WINDOW", default_value = "1")]
    window: u64,

    /// Current main-round number within the window.
    #[clap(long, env = "CHORUS_ROUND", default_value = "1")]
    round: u32,

    /// Maximum random delay before sending the submission.
    #[clap(long, env = "CHORUS_MAX_JITTER_MILLIS", default_value = "100")]
    max_jitter: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
    let args = Args::parse();
    args.logs.init();

    let context = MainRoundContext::new(WindowId::new(args.window), RoundId::try_from(args.round)?);

    let config = config::from_env().await?;
    let experiment = experiment::read_from_store(&config).await?;

    if experiment.hammer {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "CHORUS requires hammer mode to be disabled",
        )
        .into());
    }

    let protocol = experiment.get_protocol().clone();

    let info = experiment
        .iter_clients()
        .find_map(|service| match service {
            Service::Client(info) if info.idx == args.member_id => Some(info),
            _ => None,
        })
        .ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "member ID {} is outside the configured range 0..{}",
                    args.member_id,
                    experiment.clients(),
                ),
            )
        })?;

    member::run_development(context, config, protocol, info, args.max_jitter, async {
        let _ = ctrl_c().await;
    })
    .await
}
