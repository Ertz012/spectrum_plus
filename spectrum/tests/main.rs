extern crate spectrum;

use simplelog::{LevelFilter, TermLogger, TerminalMode};
use spectrum::{
    config, experiment::Experiment, protocols::wrapper::ProtocolWrapper, run_in_process_for_round,
};

#[tokio::test]
async fn two_main_rounds_run_in_sequence() {
    TermLogger::init(
        LevelFilter::Trace,
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

        run_in_process_for_round(experiment.clone(), config, 7, round, None)
            .await
            .unwrap();
    }
}
