use chorus::{
    bootstrap::MainWindowActivator,
    share_server::{self, ShareServerId},
    MainRoundContext, RoundId,
};
use clap::{crate_authors, crate_version, Parser};
use ed25519_dalek::{SigningKey, VerifyingKey};
use spectrum::{
    cli, config, experiment,
    net::{Config as NetConfig, TlsConfig},
};
use std::{
    fs,
    io::{self, ErrorKind},
    path::{Path, PathBuf},
};
use tokio::{signal::ctrl_c, sync::watch};

fn read_32_byte_file(path: &Path, description: &str) -> Result<[u8; 32], io::Error> {
    let bytes = fs::read(path)?;
    let length = bytes.len();

    <[u8; 32]>::try_from(bytes).map_err(|_| {
        io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "{} file {} must contain exactly 32 raw bytes; got {}",
                description,
                path.display(),
                length,
            ),
        )
    })
}

#[derive(Parser)]
#[clap(version = crate_version!(), author = crate_authors!())]
struct Args {
    #[clap(flatten)]
    logs: cli::LogArgs,

    #[clap(flatten)]
    tls: cli::TlsServerArgs,

    /// The CHORUS ShareServer identity: A or B.
    #[clap(long, env = "CHORUS_SHARE_SERVER")]
    server: ShareServerId,

    /// Current main-round number within the window.
    #[clap(long, env = "CHORUS_ROUND", default_value = "1")]
    round: u32,

    /// File containing the 32 raw bytes of this ShareServer's Ed25519 secret key.
    #[clap(long, env = "CHORUS_SIGNING_KEY_FILE")]
    signing_key_file: PathBuf,

    /// File containing the peer ShareServer's 32-byte Ed25519 public key.
    #[clap(long, env = "CHORUS_PEER_VERIFYING_KEY_FILE")]
    peer_verifying_key_file: PathBuf,

    /// File containing the signed Bootstrap channel set for the active window.
    #[clap(long, env = "CHORUS_CHANNEL_SET_FILE")]
    channel_set_file: PathBuf,
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
    let tls: Option<TlsConfig> = args.tls.into();
    let signing_key =
        SigningKey::from_bytes(&read_32_byte_file(&args.signing_key_file, "signing key")?);
    let peer_key = VerifyingKey::from_bytes(&read_32_byte_file(
        &args.peer_verifying_key_file,
        "peer ShareServer verifying key",
    )?)?;
    let (server_a_key, server_b_key) = match args.server {
        ShareServerId::A => (signing_key.verifying_key(), peer_key),
        ShareServerId::B => (peer_key, signing_key.verifying_key()),
    };
    let mut window_activator = MainWindowActivator::new();
    let active_window = window_activator.activate(
        &fs::read(&args.channel_set_file)?,
        &server_a_key,
        &server_b_key,
    )?;
    let expected_round =
        MainRoundContext::new(active_window.window(), RoundId::try_from(args.round)?);
    let Some(protocol) = active_window.protocol().cloned() else {
        eprintln!(
            "ShareServer {} has no main submissions for empty window {}.",
            args.server,
            active_window.window().get()
        );
        return Ok(());
    };
    let configuration_hash = active_window.configuration_hash();
    let config = config::from_env().await?;
    let template = experiment::read_from_store(&config).await?;
    if template.hammer {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "CHORUS requires hammer mode to be disabled",
        )
        .into());
    }
    if active_window.channel_count() as u128 > template.clients() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!(
                "Bootstrap produced {} channels for only {} configured members",
                active_window.channel_count(),
                template.clients()
            ),
        )
        .into());
    }
    let experiment = experiment::Experiment::new(
        protocol,
        template.group_size(),
        template.clients(),
        false,
        active_window.verification_keys().to_vec(),
    );

    let worker_net = NetConfig::with_free_port_localhost(tls.clone());
    let leader_net = NetConfig::with_free_port_localhost(tls);

    let (shutdown_sender, shutdown_receiver) = watch::channel(false);

    let server = share_server::run_development(
        args.server,
        expected_round,
        configuration_hash,
        signing_key,
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
