use std::env;
use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

use mcloving_destination_observer::{
    ObserverCommand, ObserverError, ObserverResponse, load_observer, parse_json_no_duplicates,
    read_bounded_frame, write_response,
};

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("destination observer terminated: {}", error.code());
            ExitCode::from(2)
        }
    }
}

async fn run() -> Result<(), ObserverError> {
    let arguments = env::args_os()
        .skip(1)
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    if arguments.len() != 6 {
        return Err(ObserverError::InvalidConfig);
    }
    let executable = env::current_exe().map_err(|_| ObserverError::StateUnavailable)?;
    let observer = load_observer(
        &arguments[0],
        &arguments[1],
        &arguments[2],
        &arguments[3],
        &arguments[4],
        &arguments[5],
        &executable,
    )?;
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    loop {
        let frame = match read_bounded_frame(&mut input) {
            Ok(Some(frame)) => frame,
            Ok(None) => return Ok(()),
            Err(error) => {
                write_response(&mut output, &ObserverResponse::from_error(&error))?;
                continue;
            }
        };
        let response = match parse_json_no_duplicates::<ObserverCommand>(&frame) {
            Ok(ObserverCommand::Observe { request }) => observer
                .observe(request)
                .await
                .map(|receipt| ObserverResponse::Observed {
                    receipt: Box::new(receipt),
                })
                .unwrap_or_else(|error| ObserverResponse::from_error(&error)),
            Err(error) => ObserverResponse::from_error(&error),
        };
        write_response(&mut output, &response)?;
    }
}
