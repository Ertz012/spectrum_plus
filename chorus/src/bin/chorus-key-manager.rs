use chorus::authority::AuthorityKeyManager;
use clap::{crate_authors, crate_version, Parser};
use std::{
    fs::OpenOptions,
    io::{self, ErrorKind, Write},
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[clap(version = crate_version!(), author = crate_authors!())]
struct Args {
    /// New file for the versioned BBS+ issuer secret state. Existing files are never overwritten.
    #[clap(long, env = "CHORUS_ISSUER_STATE_FILE")]
    issuer_state_file: PathBuf,

    /// New file for the matching versioned public credential parameters.
    #[clap(long, env = "CHORUS_CREDENTIAL_PUBLIC_PARAMETERS_FILE")]
    public_parameters_file: PathBuf,
}

fn write_new(path: &Path, bytes: &[u8], _secret: bool) -> Result<(), io::Error> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if _secret {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn main() -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
    let args = Args::parse();
    if args.issuer_state_file == args.public_parameters_file {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "issuer state and public parameters need different files",
        )
        .into());
    }
    for path in [&args.issuer_state_file, &args.public_parameters_file] {
        if path.exists() {
            return Err(io::Error::new(
                ErrorKind::AlreadyExists,
                format!("refusing to overwrite {}", path.display()),
            )
            .into());
        }
    }

    let manager = AuthorityKeyManager::generate();
    let public_parameters = manager.public_parameters().encode()?;
    let issuer_state = manager.encode_state()?;
    write_new(&args.public_parameters_file, &public_parameters, false)?;
    write_new(&args.issuer_state_file, &issuer_state, true)?;
    eprintln!(
        "Created issuer state {} and public parameters {}.",
        args.issuer_state_file.display(),
        args.public_parameters_file.display()
    );
    Ok(())
}
