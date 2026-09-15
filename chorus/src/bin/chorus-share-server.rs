use chorus::share_server::{self, ShareServerId};
use clap::{crate_authors, crate_version, Parser};
use spectrum::{cli, config, experiment, net::Config as NetConfig};
use tokio::{signal::ctrl_c, sync::watch};

#[derive(Parser)]
#[clap(version = crate_version!(), author = crate_authors!())]
struct Args {
    #[clap(flatten)]
    logs: cli::LogArgs,

    /// The CHORUS ShareServer identity: A or B.
    #[clap(long, env = "CHORUS_SHARE_SERVER")]
    server: ShareServerId,
}

async fn wait_for_shutdown(mut receiver: watch::Receiver<bool>) {
    loop {
        if *receiver.borrow() {
            return;
        }

        if receiver.changed().await.is_err() {
            return;
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
    let args = Args::parse();
    args.logs.init();

    let config = config::from_env().await?;
    let experiment = experiment::read_from_store(&config).await?;

    let worker_net = NetConfig::with_free_port_localhost(None);
    let leader_net = NetConfig::with_free_port_localhost(None);

    let (shutdown_sender, shutdown_receiver) = watch::channel(false);

    let server = share_server::run_development(
        args.server,
        config,
        experiment,
        worker_net,
        leader_net,
        wait_for_shutdown(shutdown_receiver.clone()),
        wait_for_shutdown(shutdown_receiver),
    );

    tokio::pin!(server);

    tokio::select! {
        result = &mut server => result,
        signal = ctrl_c() => {
            if let Err(error) = signal {
                eprintln!("Failed to listen for Ctrl+C: {error}");
            }

            let _ = shutdown_sender.send(true);
            server.await
        }
    }
}
