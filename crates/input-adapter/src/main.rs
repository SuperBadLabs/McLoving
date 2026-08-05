use std::path::PathBuf;

use mcloving_input_adapter::{AdapterConfig, CaptureRequest, InputAdapter, sha256_file};
use serde::Serialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const MAX_REQUEST_BYTES: u64 = 64 * 1_024;

#[derive(Serialize)]
#[serde(untagged)]
enum Output {
    Success {
        ok: bool,
        receipt: Box<mcloving_input_adapter::CaptureReceipt>,
    },
    Failure {
        ok: bool,
        code: &'static str,
        message: String,
    },
}

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        std::process::exit(1);
    }
}

async fn run() -> Result<(), ()> {
    let config_path = required_path("MCLOVING_INPUT_ADAPTER_CONFIG")?;
    let token_path = required_path("MCLOVING_INPUT_ADAPTER_READ_TOKEN_FILE")?;
    let signing_key_path = required_path("MCLOVING_INPUT_ADAPTER_SIGNING_KEY_FILE")?;
    let secret_markers_path = required_path("MCLOVING_INPUT_ADAPTER_SECRET_MARKERS_FILE")?;
    let config_bytes = tokio::fs::read(&config_path).await.map_err(|_| ())?;
    let config: AdapterConfig = serde_json::from_slice(&config_bytes).map_err(|_| ())?;
    if config.test_allow_http_loopback
        && std::env::var("MCLOVING_INPUT_ADAPTER_TEST_MODE").as_deref() != Ok("1")
    {
        return Err(());
    }
    let read_token = tokio::fs::read_to_string(token_path)
        .await
        .map_err(|_| ())?
        .trim()
        .to_owned();
    let signing_key = tokio::fs::read(signing_key_path).await.map_err(|_| ())?;
    let secret_markers = tokio::fs::read(secret_markers_path)
        .await
        .map_err(|_| ())?
        .split(|byte| *byte == b'\n')
        .filter(|marker| !marker.is_empty())
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    let implementation_sha256 = sha256_file(&std::env::current_exe().map_err(|_| ())?)
        .await
        .map_err(|_| ())?;
    let adapter = InputAdapter::new(
        config,
        implementation_sha256,
        read_token,
        signing_key,
        secret_markers,
    )
    .await
    .map_err(|_| ())?;

    let mut input = BufReader::new(tokio::io::stdin());
    let mut output = tokio::io::stdout();
    loop {
        let line = match read_bounded_line(&mut input).await {
            Ok(Some(line)) => line,
            Ok(None) => break,
            Err(()) => {
                write_output(
                    &mut output,
                    &Output::Failure {
                        ok: false,
                        code: "oversized_request",
                        message: "capture request exceeds the bounded NDJSON frame".to_owned(),
                    },
                )
                .await?;
                return Err(());
            }
        };
        let response = match serde_json::from_slice::<CaptureRequest>(&line) {
            Ok(request) => match adapter.capture(&request).await {
                Ok(receipt) => Output::Success {
                    ok: true,
                    receipt: Box::new(receipt),
                },
                Err(error) => Output::Failure {
                    ok: false,
                    code: error.code(),
                    message: error.to_string(),
                },
            },
            Err(_) => Output::Failure {
                ok: false,
                code: "malformed_request",
                message: "capture request is malformed".to_owned(),
            },
        };
        write_output(&mut output, &response).await?;
    }
    Ok(())
}

async fn read_bounded_line(input: &mut BufReader<tokio::io::Stdin>) -> Result<Option<Vec<u8>>, ()> {
    let mut line = Vec::new();
    loop {
        let buffer = input.fill_buf().await.map_err(|_| ())?;
        if buffer.is_empty() {
            return if line.is_empty() { Ok(None) } else { Err(()) };
        }
        let consumed = buffer
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(buffer.len(), |index| index + 1);
        if line.len() as u64 + consumed as u64 > MAX_REQUEST_BYTES + 1 {
            return Err(());
        }
        let complete = buffer.get(consumed.saturating_sub(1)) == Some(&b'\n');
        line.extend_from_slice(&buffer[..consumed]);
        input.consume(consumed);
        if complete {
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(Some(line));
        }
    }
}

async fn write_output(output: &mut tokio::io::Stdout, response: &Output) -> Result<(), ()> {
    let mut bytes = serde_json::to_vec(response).map_err(|_| ())?;
    bytes.push(b'\n');
    output.write_all(&bytes).await.map_err(|_| ())?;
    output.flush().await.map_err(|_| ())
}

fn required_path(name: &str) -> Result<PathBuf, ()> {
    std::env::var_os(name).map(PathBuf::from).ok_or(())
}
