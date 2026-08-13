use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use mcloving_external_connector::{ConnectorError, load_connector, serve_connector_stdio};

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("external connector terminated: {}", error.code());
            ExitCode::from(2)
        }
    }
}

async fn run() -> Result<(), ConnectorError> {
    let arguments = env::args_os()
        .skip(1)
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    if arguments.len() != 8 {
        return Err(ConnectorError::InvalidConfig);
    }
    let connector = load_connector(
        &arguments[0],
        &arguments[1],
        &arguments[2],
        &arguments[3],
        &arguments[4],
        &arguments[5],
        &arguments[6],
        &arguments[7],
    )?;
    serve_connector_stdio(&connector).await
}
