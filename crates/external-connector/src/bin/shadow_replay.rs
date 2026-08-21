use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use mcloving_external_connector::{
    ConnectorError, load_shadow_replayer, require_shadow_apparmor_enforcement, serve_shadow_stdio,
};

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("external shadow replay terminated: {}", error.code());
            ExitCode::from(2)
        }
    }
}

async fn run() -> Result<(), ConnectorError> {
    require_shadow_apparmor_enforcement()?;
    let arguments = env::args_os()
        .skip(1)
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    if arguments.len() != 6 {
        return Err(ConnectorError::InvalidConfig);
    }
    let shadow = load_shadow_replayer(
        &arguments[0],
        &arguments[1],
        &arguments[2],
        &arguments[3],
        &arguments[4],
        &arguments[5],
    )?;
    serve_shadow_stdio(&shadow).await
}
