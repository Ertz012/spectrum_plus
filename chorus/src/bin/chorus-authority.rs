use chorus::{
    authority::{self, PersistentPublicationLog, PersistentSeenSet},
    bootstrap::MainWindowActivator,
    CredentialPublicParameters, MainRoundContext, RoundId,
};
use clap::{crate_authors, crate_version, Parser};
use ed25519_dalek::{SigningKey, VerifyingKey};
use spectrum::{cli, config};
use std::{
    fs,
    io::{self, ErrorKind},
    path::{Path, PathBuf},
};
use tokio::signal::ctrl_c;

fn read_32_byte_file(path: &Path, description: &str) -> Result<[u8; 32], io::Error> {
    let bytes = fs::read(path)?;
    let length = bytes.len();

    bytes.try_into().map_err(|_| {
        io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "{} file {} must contain exactly 32 raw bytes; got {}",
                description,
                path.display(),
                length
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
    net: cli::NetArgs,

    /// Delay between reaching quorum and starting the round.
    #[clap(long, env = "CHORUS_DELAY_MS", default_value = "5000")]
    delay_ms: i64,

    /// Current main-round number within the window.
    #[clap(long, env = "CHORUS_ROUND", default_value = "1")]
    round: u32,

    /// File containing ShareServer A's 32-byte Ed25519 public key.
    #[clap(long, env = "CHORUS_SERVER_A_VERIFYING_KEY_FILE")]
    server_a_verifying_key_file: PathBuf,

    /// File containing ShareServer B's 32-byte Ed25519 public key.
    #[clap(long, env = "CHORUS_SERVER_B_VERIFYING_KEY_FILE")]
    server_b_verifying_key_file: PathBuf,

    /// File containing the signed Bootstrap channel set for the active window.
    #[clap(long, env = "CHORUS_CHANNEL_SET_FILE")]
    channel_set_file: PathBuf,

    /// File containing the versioned BBS+ issuer public parameters.
    #[clap(long, env = "CHORUS_CREDENTIAL_PUBLIC_PARAMETERS_FILE")]
    credential_public_parameters_file: PathBuf,

    /// Persistent exact set of previously accepted content pseudonyms.
    #[clap(long, env = "CHORUS_SEEN_SET_FILE")]
    seen_set_file: PathBuf,

    /// File containing the Authority's 32-byte Ed25519 publication signing key.
    #[clap(long, env = "CHORUS_AUTHORITY_SIGNING_KEY_FILE")]
    authority_signing_key_file: PathBuf,

    /// Append-only log containing signed Authority publications.
    #[clap(long, env = "CHORUS_PUBLICATION_LOG_FILE")]
    publication_log_file: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
    let args = Args::parse();
    args.logs.init();

    let server_a_key = VerifyingKey::from_bytes(&read_32_byte_file(
        &args.server_a_verifying_key_file,
        "ShareServer A verifying key",
    )?)?;
    let server_b_key = VerifyingKey::from_bytes(&read_32_byte_file(
        &args.server_b_verifying_key_file,
        "ShareServer B verifying key",
    )?)?;
    let mut window_activator = MainWindowActivator::new();
    let active_window = window_activator.activate(
        &fs::read(&args.channel_set_file)?,
        &server_a_key,
        &server_b_key,
    )?;
    let expected_round =
        MainRoundContext::new(active_window.window(), RoundId::try_from(args.round)?);
    let configuration_hash = active_window.configuration_hash();
    let protocol = active_window.protocol().cloned();
    let credential_parameters =
        CredentialPublicParameters::decode(&fs::read(&args.credential_public_parameters_file)?)
            .map_err(|error| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "credential public parameter file {} is invalid: {}",
                        args.credential_public_parameters_file.display(),
                        error
                    ),
                )
            })?;
    let seen_set = PersistentSeenSet::open(&args.seen_set_file)?;
    let authority_signing_key = SigningKey::from_bytes(&read_32_byte_file(
        &args.authority_signing_key_file,
        "Authority publication signing key",
    )?);
    let publication_log = PersistentPublicationLog::open(
        &args.publication_log_file,
        authority_signing_key.verifying_key(),
    )?;
    let config = config::from_env().await?;

    let shutdown = async {
        if let Err(error) = ctrl_c().await {
            eprintln!("Failed to listen for Ctrl+C: {error}");
        }
    };

    let result = authority::run_development(
        expected_round,
        configuration_hash,
        server_a_key,
        server_b_key,
        credential_parameters,
        seen_set,
        authority_signing_key,
        publication_log,
        config,
        protocol,
        args.net.into(),
        shutdown,
        args.delay_ms,
    )
    .await?;

    if let Some(round) = result {
        eprintln!(
            "Authority published {} channels for window {}, round {}.",
            round.round().channels().len(),
            round.round().context().window().get(),
            round.round().context().round().get()
        );
    }
    Ok(())
}
