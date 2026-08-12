use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use mcloving_destination_observer::{ObserverError, load_loopback_test_observer, serve_stdio};

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "destination observer loopback test terminated: {}",
                error.code()
            );
            ExitCode::from(2)
        }
    }
}

async fn run() -> Result<(), ObserverError> {
    let arguments = env::args_os()
        .skip(1)
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    if arguments.len() != 7 {
        return Err(ObserverError::InvalidConfig);
    }
    let observer = load_loopback_test_observer(
        &arguments[0],
        &arguments[1],
        &arguments[2],
        &arguments[3],
        &arguments[4],
        &arguments[5],
        &arguments[6],
    )?;
    serve_stdio(&observer).await
}
