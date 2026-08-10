use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

use mcloving_dependency_resolver::{
    DependencyResolver, FrameReadError, MAX_PUBLICATION_WORKER_BYTES, ResolverResponse,
    SerializedOutputGuard, load_certified_config, parse_resolution_frame, read_bounded_frame,
    run_publication_worker, serialized_response_fits_frame, verify_running_executable,
};

fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(_) => std::process::exit(1),
    };
    if runtime.block_on(run()).is_err() {
        std::process::exit(1);
    }
}

async fn run() -> Result<(), (&'static str, &'static str)> {
    let mut arguments = std::env::args_os().skip(1);
    let mode = arguments
        .next()
        .ok_or(("DEP_CLI_USAGE", "resolver requires --config <path>"))?;
    if mode == std::ffi::OsStr::new("--publication-worker") {
        if arguments.next().is_some() {
            return Err(("DEP_CLI_USAGE", "publication worker accepts no arguments"));
        }
        return run_worker();
    }
    if mode != std::ffi::OsStr::new("--config") {
        return Err(("DEP_CLI_USAGE", "resolver requires --config <path>"));
    }
    let config_path = arguments
        .next()
        .ok_or(("DEP_CLI_USAGE", "resolver requires --config <path>"))?;
    if arguments.next().is_some() {
        return Err(("DEP_CLI_USAGE", "resolver accepts no additional arguments"));
    }
    let config = load_certified_config(Path::new(&config_path))
        .map_err(|error| (error.code, error.message))?;
    verify_running_executable(&config).map_err(|error| (error.code, error.message))?;
    let max_frame = usize::try_from(config.limits.max_frame_bytes).map_err(|_| {
        (
            "DEP_CONFIG_LIMITS_INVALID",
            "dependency resolution was denied",
        )
    })?;
    let resolver = DependencyResolver::new(config).map_err(|error| (error.code, error.message))?;
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut input = BufReader::new(stdin.lock());
    let mut output = BufWriter::new(stdout.lock());
    let mut output_guard = resolver.serialized_output_guard();
    loop {
        let frame = match read_bounded_frame(&mut input, max_frame) {
            Ok(Some(frame)) => frame,
            Ok(None) => break,
            Err(FrameReadError::Oversized) => {
                write_response(
                    &mut output,
                    &resolver,
                    &mut output_guard,
                    ResolverResponse::Error {
                        code: "DEP_REQUEST_FRAME_OVERSIZED",
                        message: "dependency resolution was denied",
                    },
                    max_frame,
                )
                .await?;
                continue;
            }
            Err(FrameReadError::Io) => {
                return Err((
                    "DEP_REQUEST_STREAM_FAILED",
                    "dependency resolution was denied",
                ));
            }
        };
        let response = match parse_resolution_frame(&frame) {
            Ok(frame) => ResolverResponse::from(resolver.resolve_frame_for_output(frame).await),
            Err(error) => ResolverResponse::Error {
                code: error.code,
                message: error.message,
            },
        };
        write_response(
            &mut output,
            &resolver,
            &mut output_guard,
            response,
            max_frame,
        )
        .await?;
    }
    Ok(())
}

fn run_worker() -> Result<(), (&'static str, &'static str)> {
    let mut input = Vec::new();
    std::io::stdin()
        .take((MAX_PUBLICATION_WORKER_BYTES + 1) as u64)
        .read_to_end(&mut input)
        .map_err(|_| {
            (
                "DEP_STORE_PUBLICATION_WORKER_FRAME_INVALID",
                "dependency resolution was denied",
            )
        })?;
    let response = run_publication_worker(&input);
    let mut output = BufWriter::new(std::io::stdout().lock());
    serde_json::to_writer(&mut output, &response).map_err(|_| {
        (
            "DEP_STORE_PUBLICATION_WORKER_FAILED",
            "dependency resolution was denied",
        )
    })?;
    output.flush().map_err(|_| {
        (
            "DEP_STORE_PUBLICATION_WORKER_FAILED",
            "dependency resolution was denied",
        )
    })
}

async fn write_response<W: Write>(
    output: &mut W,
    resolver: &DependencyResolver,
    output_guard: &mut SerializedOutputGuard,
    response: ResolverResponse,
    max_frame: usize,
) -> Result<(), (&'static str, &'static str)> {
    let mut bytes = serde_json::to_vec(&response).map_err(|_| {
        (
            "DEP_RESPONSE_SERIALIZATION_FAILED",
            "dependency resolution was denied",
        )
    })?;
    let oversized = !serialized_response_fits_frame(bytes.len(), max_frame as u64);
    if oversized {
        bytes = serde_json::to_vec(&ResolverResponse::Error {
            code: "DEP_RESPONSE_FRAME_OVERSIZED",
            message: "dependency resolution was denied",
        })
        .map_err(|_| {
            (
                "DEP_RESPONSE_SERIALIZATION_FAILED",
                "dependency resolution was denied",
            )
        })?;
    }
    bytes.push(b'\n');
    if !output_guard.admit(&bytes) {
        return Err(("DEP_RESPONSE_SECRET_MARKER_DETECTED", "response suppressed"));
    }
    output
        .write_all(&bytes)
        .and_then(|()| output.flush())
        .map_err(|_| {
            (
                "DEP_RESPONSE_STREAM_FAILED",
                "dependency resolution was denied",
            )
        })?;
    if !oversized && let ResolverResponse::Ok { receipt } = &response {
        resolver.acknowledge_response_delivery(receipt).await;
    }
    Ok(())
}
