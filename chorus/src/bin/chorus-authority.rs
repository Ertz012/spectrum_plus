use chorus::authority;
use clap::{crate_authors, crate_version, Parser};
use spectrum::{cli, config, experiment};
use tokio::signal::ctrl_c;

#[derive(Parser)]
#[clap(version = crate_version!(), author = crate_authors!())]
struct Args {
    #[clap(flatten)]
    logs: cli::LogArgs,

    #[clap(flatten)]
    net: cli::NetArgs,

    /// Delay between reaching quorum and starting the round.
    #[clap(long, env = "CHORUS_DELAY_MS", default_value = "5000")]
    delay_ms: i64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
    let args = Args::parse();
    args.logs.init();

    let config = config::from_env().await?;
    let experiment = experiment::read_from_store(&config).await?;
    let protocol = experiment.get_protocol().clone();

    let shutdown = async {
        if let Err(error) = ctrl_c().await {
            eprintln!("Failed to listen for Ctrl+C: {error}");
        }
    };

    authority::run_development(config, protocol, args.net.into(), shutdown, args.delay_ms).await
}
