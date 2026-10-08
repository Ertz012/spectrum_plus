use chorus::{
    bootstrap::MainWindowActivator, member, CredentialPublicParameters, MainRoundContext,
    MemberCredentialBundle, RoundId,
};
use clap::{crate_authors, crate_version, Parser};
use ed25519_dalek::VerifyingKey;
use spectrum::{cli, config, experiment, net::TlsConfig, services::ClientInfo};
use std::{
    fs,
    io::{self, Error, ErrorKind},
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
    tls: cli::TlsServerArgs,

    /// Development network identity of this member; this is not a channel index.
    #[clap(long, env = "CHORUS_MEMBER_ID")]
    member_id: u128,

    /// Current main-round number within the window.
    #[clap(long, env = "CHORUS_ROUND", default_value = "1")]
    round: u32,

    /// Maximum random delay before sending the submission.
    #[clap(long, env = "CHORUS_MAX_JITTER_MILLIS", default_value = "100")]
    max_jitter: u64,

    /// STIX bundle to broadcast. Without this option, the member sends cover traffic.
    #[clap(long, env = "CHORUS_STIX_BUNDLE")]
    stix_bundle: Option<PathBuf>,

    /// File containing ShareServer A's 32-byte Ed25519 public key.
    #[clap(long, env = "CHORUS_SERVER_A_VERIFYING_KEY_FILE")]
    server_a_verifying_key_file: PathBuf,

    /// File containing ShareServer B's 32-byte Ed25519 public key.
    #[clap(long, env = "CHORUS_SERVER_B_VERIFYING_KEY_FILE")]
    server_b_verifying_key_file: PathBuf,

    /// File containing the signed Bootstrap channel set for the active window.
    #[clap(long, env = "CHORUS_CHANNEL_SET_FILE")]
    channel_set_file: PathBuf,

    /// This broadcaster's 32-byte private channel key for the active window.
    #[clap(long, env = "CHORUS_CHANNEL_PRIVATE_KEY_FILE")]
    channel_private_key_file: Option<PathBuf>,

    /// File containing the versioned BBS+ issuer public parameters.
    #[clap(long, env = "CHORUS_CREDENTIAL_PUBLIC_PARAMETERS_FILE")]
    credential_public_parameters_file: PathBuf,

    /// File containing this member's versioned secret and BBS+ credential.
    #[clap(long, env = "CHORUS_MEMBER_CREDENTIAL_FILE")]
    member_credential_file: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
    let args = Args::parse();
    args.logs.init();
    let tls: Option<TlsConfig> = args.tls.into();

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
    let context = MainRoundContext::new(active_window.window(), RoundId::try_from(args.round)?);
    let Some(protocol) = active_window.protocol().cloned() else {
        eprintln!(
            "Member has no main submission for empty window {}.",
            active_window.window().get()
        );
        return Ok(());
    };
    let credential_parameters =
        CredentialPublicParameters::decode(&fs::read(&args.credential_public_parameters_file)?)
            .map_err(|error| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "credential public parameter file {} is invalid: {}",
                        args.credential_public_parameters_file.display(),
                        error
                    ),
                )
            })?;
    let credentials = MemberCredentialBundle::decode(
        &fs::read(&args.member_credential_file)?,
        &credential_parameters,
    )
    .map_err(|error| {
        Error::new(
            ErrorKind::InvalidData,
            format!(
                "member credential file {} is invalid: {}",
                args.member_credential_file.display(),
                error
            ),
        )
    })?;

    let config = config::from_env().await?;
    let experiment = experiment::read_from_store(&config).await?;

    if experiment.hammer {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "CHORUS requires hammer mode to be disabled",
        )
        .into());
    }
    if args.member_id >= experiment.clients() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!(
                "member ID {} is outside the configured range 0..{}",
                args.member_id,
                experiment.clients(),
            ),
        )
        .into());
    }
    if active_window.channel_count() as u128 > experiment.clients() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!(
                "Bootstrap produced {} channels for only {} configured members",
                active_window.channel_count(),
                experiment.clients()
            ),
        )
        .into());
    }

    // The network-visible ID is fresh and does not reveal the local member slot.
    let submission_id = rand::random::<u128>();
    let (info, submission) = match args.stix_bundle {
        Some(path) => {
            let private_key_file = args.channel_private_key_file.as_ref().ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidInput,
                    "--channel-private-key-file is required for a broadcast",
                )
            })?;
            let info = member::configure_broadcaster(
                submission_id,
                active_window,
                read_32_byte_file(private_key_file, "private channel key")?,
            )?;
            let stix_bundle = fs::read(path)?;
            let submission = member::MainSubmission::Broadcast(member::create_broadcast_payload(
                &credentials,
                &credential_parameters,
                stix_bundle,
            )?);
            (info, submission)
        }
        None => (
            ClientInfo::new(submission_id),
            member::MainSubmission::Cover,
        ),
    };

    member::run_development(
        context,
        config,
        protocol,
        info,
        submission,
        tls,
        args.max_jitter,
        async {
            let _ = ctrl_c().await;
        },
    )
    .await
}
