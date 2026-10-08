extern crate spectrum;

use simplelog::{LevelFilter, TermLogger, TerminalMode};
use spectrum::{
    config, experiment::Experiment, net::TlsConfig, protocols::wrapper::ProtocolWrapper,
    run_in_process_for_round,
};
use tonic::transport::{Certificate, Identity};

#[tokio::test]
async fn plaintext_and_mtls_main_rounds_run_in_sequence() {
    TermLogger::init(
        LevelFilter::Info,
        simplelog::ConfigBuilder::new()
            .add_filter_allow_str("spectrum")
            .build(),
        TerminalMode::Stderr,
    )
    .unwrap();

    let protocol = ProtocolWrapper::new(true, false, 2, 1, 100, false);

    let experiment = Experiment::new_sample_keys(protocol, 1, 3, false);

    for round in 1_u32..=2_u32 {
        let config = config::from_string("").await.unwrap();
        let tls = (round == 2).then(|| {
            TlsConfig::new(
                Identity::from_pem(
                    include_bytes!("../data/server.crt"),
                    include_bytes!("../data/server.key"),
                ),
                Certificate::from_pem(include_bytes!("../data/ca.crt")),
                Some("spectrum.example.com".to_string()),
            )
        });

        run_in_process_for_round(experiment.clone(), config, 7, round, tls)
            .await
            .unwrap();
    }
}
