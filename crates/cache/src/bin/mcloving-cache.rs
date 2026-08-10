use std::io::{BufReader, BufWriter};
use std::path::Path;

use mcloving_cache::{
    CacheCommand, CacheError, CacheResponse, CacheStore, FrameReadError, load_config,
    parse_json_no_duplicates, read_bounded_frame, read_private_receipt_key, sha256_file,
    write_response,
};

fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    if run().is_err() {
        std::process::exit(1);
    }
}

fn run() -> Result<(), CacheError> {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--config")) {
        return Err(CacheError::InvalidConfig);
    }
    let config_path = arguments.next().ok_or(CacheError::InvalidConfig)?;
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--receipt-key")) {
        return Err(CacheError::InvalidConfig);
    }
    let receipt_key_path = arguments.next().ok_or(CacheError::InvalidConfig)?;
    if arguments.next().is_some() {
        return Err(CacheError::InvalidConfig);
    }
    let config = load_config(Path::new(&config_path))?;
    let running_executable = std::env::current_exe().map_err(|_| CacheError::InvalidConfig)?;
    if sha256_file(&running_executable)? != config.implementation_sha256 {
        return Err(CacheError::InvalidConfig);
    }
    let receipt_key = read_private_receipt_key(Path::new(&receipt_key_path))?;
    let maximum = usize::try_from(config.max_frame_bytes).map_err(|_| CacheError::InvalidConfig)?;
    let operator_identity = config.operator_identity.clone();
    let store = CacheStore::open(config, receipt_key)?;
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut input = BufReader::new(stdin.lock());
    let mut output = BufWriter::new(stdout.lock());
    loop {
        let frame = match read_bounded_frame(&mut input, maximum) {
            Ok(Some(frame)) => frame,
            Ok(None) => break,
            Err(FrameReadError::Oversized | FrameReadError::Unterminated) => {
                write_response(
                    &mut output,
                    &CacheResponse::from_error(CacheError::MalformedProtocol),
                    maximum as u64,
                )?;
                continue;
            }
            Err(FrameReadError::Io) => return Err(CacheError::StateUnavailable),
        };
        let response = parse_json_no_duplicates::<CacheCommand>(&frame)
            .map_or_else(CacheResponse::from_error, |command| {
                command.execute(&store, &operator_identity)
            });
        write_response(&mut output, &response, maximum as u64)?;
    }
    Ok(())
}
