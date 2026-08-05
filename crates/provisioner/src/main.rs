use std::path::PathBuf;

use mcloving_provisioner::{
    Command, Provisioner, Receipt, parse_json_no_duplicates, read_bounded_regular_file,
    read_private_bounded_regular_file, sha256_file,
};
use serde::Serialize;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};

const MAX_COMMAND_BYTES: u64 = 128 * 1_024;
const MAX_CONFIG_BYTES: usize = 256 * 1_024;
const MAX_CREDENTIAL_BYTES: usize = 4 * 1_024;
const MAX_PUBLIC_KEY_BYTES: usize = 1_024;

#[derive(Serialize)]
#[serde(untagged)]
enum Output {
    Success {
        ok: bool,
        receipt: Box<Receipt>,
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
    let config_path = required_path("MCLOVING_PROVISIONER_CONFIG")?;
    let provider_token_path = required_path("MCLOVING_PROVISIONER_PROVIDER_TOKEN_FILE")?;
    let provider_public_key_path = required_path("MCLOVING_PROVISIONER_PROVIDER_PUBLIC_KEY_FILE")?;
    let receipt_signing_key_path = required_path("MCLOVING_PROVISIONER_RECEIPT_SIGNING_KEY_FILE")?;
    let config_bytes = read_bounded_regular_file(&config_path, MAX_CONFIG_BYTES)
        .await
        .map_err(|_| ())?;
    let config: mcloving_provisioner::ProvisionerConfig =
        parse_json_no_duplicates(&config_bytes).map_err(|_| ())?;
    if config.test_allow_http_loopback
        && std::env::var("MCLOVING_PROVISIONER_TEST_MODE").as_deref() != Ok("1")
    {
        return Err(());
    }
    let provider_token = String::from_utf8(
        read_private_bounded_regular_file(&provider_token_path, MAX_CREDENTIAL_BYTES)
            .await
            .map_err(|_| ())?,
    )
    .map_err(|_| ())?
    .trim()
    .to_owned();
    let provider_public_key =
        read_bounded_regular_file(&provider_public_key_path, MAX_PUBLIC_KEY_BYTES)
            .await
            .map_err(|_| ())?;
    let receipt_signing_key =
        read_private_bounded_regular_file(&receipt_signing_key_path, MAX_CREDENTIAL_BYTES)
            .await
            .map_err(|_| ())?;
    let implementation_sha256 = sha256_file(&std::env::current_exe().map_err(|_| ())?)
        .await
        .map_err(|_| ())?;
    let provisioner = Provisioner::new(
        config,
        implementation_sha256,
        provider_token,
        provider_public_key,
        receipt_signing_key,
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
                        code: "oversized_command",
                        message: "provisioner command exceeds the bounded NDJSON frame".to_owned(),
                    },
                )
                .await?;
                return Err(());
            }
        };
        let response = match parse_json_no_duplicates::<Command>(&line) {
            Ok(command) => match provisioner.execute(&command).await {
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
                code: "malformed_command",
                message: "provisioner command is malformed".to_owned(),
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
        if line.len() as u64 + consumed as u64 > MAX_COMMAND_BYTES + 1 {
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
