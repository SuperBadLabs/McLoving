use std::path::PathBuf;

use mcloving_source_acquirer::{
    AcquisitionRequest, SourceAcquirer, SourceConfig, parse_json_no_duplicates,
    read_bounded_regular_file, read_private_bounded_regular_file, sha256_file,
};
use serde::Serialize;
use tokio::io::{AsyncBufRead, AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};

const MAX_REQUEST_BYTES: u64 = 64 * 1_024;
const MAX_CONFIG_BYTES: usize = 256 * 1_024;
const MAX_CREDENTIAL_BYTES: usize = 64 * 1_024;
const MAX_SIGNING_KEY_BYTES: usize = 64 * 1_024;
const MAX_MARKER_FILE_BYTES: usize = 256 * 1_024;

#[derive(Serialize)]
#[serde(untagged)]
enum Output {
    Success {
        ok: bool,
        receipt: Box<mcloving_source_acquirer::AcquisitionReceipt>,
    },
    Failure {
        ok: bool,
        code: &'static str,
        message: String,
    },
}

#[tokio::main]
async fn main() {
    let result = if std::env::var("MCLOVING_SOURCE_ACQUIRER_ASKPASS").as_deref() == Ok("1") {
        run_askpass().await
    } else {
        run().await
    };
    if result.is_err() {
        std::process::exit(1);
    }
}

async fn run_askpass() -> Result<(), ()> {
    let prompt = std::env::args().nth(1).ok_or(())?;
    let value = if prompt.contains("Username") {
        std::env::var("MCLOVING_SOURCE_ACQUIRER_CREDENTIAL_USERNAME").map_err(|_| ())?
    } else if prompt.contains("Password") {
        let path = required_path("MCLOVING_SOURCE_ACQUIRER_CREDENTIAL_FILE")?;
        String::from_utf8(
            read_private_bounded_regular_file(&path, MAX_CREDENTIAL_BYTES)
                .await
                .map_err(|_| ())?,
        )
        .map_err(|_| ())?
    } else {
        return Err(());
    };
    if value.is_empty() || value.contains(['\r', '\n']) {
        return Err(());
    }
    let mut output = tokio::io::stdout();
    output.write_all(value.as_bytes()).await.map_err(|_| ())?;
    output.write_all(b"\n").await.map_err(|_| ())?;
    output.flush().await.map_err(|_| ())
}

async fn run() -> Result<(), ()> {
    let config_path = required_path("MCLOVING_SOURCE_ACQUIRER_CONFIG")?;
    let credential_path = required_path("MCLOVING_SOURCE_ACQUIRER_CREDENTIAL_FILE")?;
    let signing_key_path = required_path("MCLOVING_SOURCE_ACQUIRER_SIGNING_KEY_FILE")?;
    let markers_path = required_path("MCLOVING_SOURCE_ACQUIRER_SECRET_MARKERS_FILE")?;
    let config_bytes = read_bounded_regular_file(&config_path, MAX_CONFIG_BYTES)
        .await
        .map_err(|_| ())?;
    let config: SourceConfig = parse_json_no_duplicates(&config_bytes).map_err(|_| ())?;
    if (config.test_allow_file_repositories || config.test_allow_http_loopback)
        && std::env::var("MCLOVING_SOURCE_ACQUIRER_TEST_MODE").as_deref() != Ok("1")
    {
        return Err(());
    }
    let credential = read_private_bounded_regular_file(&credential_path, MAX_CREDENTIAL_BYTES)
        .await
        .map_err(|_| ())?;
    let signing_key = read_private_bounded_regular_file(&signing_key_path, MAX_SIGNING_KEY_BYTES)
        .await
        .map_err(|_| ())?;
    let secret_markers = read_bounded_regular_file(&markers_path, MAX_MARKER_FILE_BYTES)
        .await
        .map_err(|_| ())?
        .split(|byte| *byte == b'\n')
        .filter(|marker| !marker.is_empty())
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    let implementation_sha256 = sha256_file(&std::env::current_exe().map_err(|_| ())?)
        .await
        .map_err(|_| ())?;
    let acquirer = SourceAcquirer::new(
        config,
        implementation_sha256,
        credential_path,
        &credential,
        signing_key,
        secret_markers,
    )
    .await
    .map_err(|_| ())?;

    let mut input = BufReader::new(tokio::io::stdin());
    let mut output = tokio::io::stdout();
    while let Some(line) = match read_bounded_line(&mut input).await {
        Ok(line) => line,
        Err(()) => {
            write_output(
                &mut output,
                &Output::Failure {
                    ok: false,
                    code: "oversized_request",
                    message: "source acquisition request exceeds the bounded NDJSON frame"
                        .to_owned(),
                },
            )
            .await?;
            return Err(());
        }
    } {
        let response = match parse_json_no_duplicates::<AcquisitionRequest>(&line) {
            Ok(request) => match acquirer.acquire(&request).await {
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
                message: "source acquisition request is malformed".to_owned(),
            },
        };
        write_output(&mut output, &response).await?;
    }
    Ok(())
}

async fn read_bounded_line<R>(input: &mut R) -> Result<Option<Vec<u8>>, ()>
where
    R: AsyncBufRead + Unpin,
{
    let mut line = Vec::new();
    loop {
        let buffer = input.fill_buf().await.map_err(|_| ())?;
        if buffer.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else if line.len() as u64 > MAX_REQUEST_BYTES {
                Err(())
            } else {
                Ok(Some(line))
            };
        }
        let consumed = buffer
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(buffer.len(), |index| index + 1);
        if line.len() as u64 + consumed as u64 > MAX_REQUEST_BYTES + 2 {
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
            if line.len() as u64 > MAX_REQUEST_BYTES {
                return Err(());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bounded_ndjson_accepts_crlf_and_final_unterminated_frame() {
        let mut input = BufReader::new(&b"first\r\nsecond"[..]);
        assert_eq!(
            read_bounded_line(&mut input).await,
            Ok(Some(b"first".to_vec()))
        );
        assert_eq!(
            read_bounded_line(&mut input).await,
            Ok(Some(b"second".to_vec()))
        );
        assert_eq!(read_bounded_line(&mut input).await, Ok(None));
    }

    #[tokio::test]
    async fn bounded_ndjson_rejects_frame_over_64_kib() {
        let oversized = vec![b'x'; usize::try_from(MAX_REQUEST_BYTES).unwrap() + 1];
        let mut input = BufReader::new(oversized.as_slice());
        assert!(read_bounded_line(&mut input).await.is_err());
    }

    #[tokio::test]
    async fn bounded_ndjson_accepts_exact_64_kib_crlf_frame() {
        let mut exact = vec![b'x'; usize::try_from(MAX_REQUEST_BYTES).unwrap()];
        exact.extend_from_slice(b"\r\n");
        let mut input = BufReader::new(exact.as_slice());
        assert_eq!(
            read_bounded_line(&mut input).await.unwrap().unwrap().len() as u64,
            MAX_REQUEST_BYTES
        );
    }

    #[test]
    fn duplicate_json_members_are_rejected_recursively() {
        assert!(
            parse_json_no_duplicates::<serde_json::Value>(br#"{"outer":{"value":1,"value":2}}"#)
                .is_err()
        );
    }
}
