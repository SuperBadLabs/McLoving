use std::io::ErrorKind;
use std::path::Path;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};

use crate::{
    ActionRequest, ConnectorConfig, ConnectorError, ExternalConnector, OutcomeReceipt,
    ReconcileRequest, ShadowReplayConfig, ShadowReplayReceipt, ShadowReplayRequest, ShadowReplayer,
    parse_json_no_duplicates, read_private_bounded_regular_file,
};

pub const MAX_FRAME_BYTES: usize = 256 * 1024;
const MAX_CONFIG_BYTES: usize = 128 * 1024;
const MAX_KEY_BYTES: usize = 16 * 1024;
const MAX_TOKEN_BYTES: usize = 64 * 1024;
const MAX_MARKER_BYTES: usize = 256 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConnectorCommand {
    Execute { request: Box<ActionRequest> },
    Reconcile { request: Box<ReconcileRequest> },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConnectorResponse {
    Ok { receipt: Box<OutcomeReceipt> },
    Error { code: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum ShadowCommand {
    Replay { request: Box<ShadowReplayRequest> },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ShadowResponse {
    Ok { receipt: Box<ShadowReplayReceipt> },
    Error { code: String },
}

#[allow(clippy::too_many_arguments)]
pub fn load_connector(
    config_path: &Path,
    image_attestation_path: &Path,
    request_key_path: &Path,
    destination_key_path: &Path,
    outcome_seed_path: &Path,
    observer_key_path: &Path,
    token_path: &Path,
    marker_path: &Path,
) -> Result<ExternalConnector, ConnectorError> {
    let config: ConnectorConfig = parse_config(&read_private_bounded_regular_file(
        config_path,
        MAX_CONFIG_BYTES,
    )?)?;
    if crate::sha256_running_executable()? != config.implementation_sha256 {
        return Err(ConnectorError::InvalidConfig);
    }
    let image_attestation = read_private_bounded_regular_file(image_attestation_path, 128)?;
    let image_sha256 = std::str::from_utf8(&image_attestation)
        .map_err(|_| ConnectorError::InvalidConfig)?
        .trim();
    if image_sha256 != config.image_sha256
        || image_sha256.len() != 64
        || !image_sha256
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(ConnectorError::InvalidConfig);
    }
    let request_key = decode_single_key(request_key_path)?;
    let destination_key = decode_single_key(destination_key_path)?;
    let outcome_seed = decode_single_key(outcome_seed_path)?;
    let observer_key = decode_single_key(observer_key_path)?;
    let token = read_private_bounded_regular_file(token_path, MAX_TOKEN_BYTES)?;
    let markers = decode_markers(marker_path)?;
    ExternalConnector::new(
        config,
        request_key,
        destination_key,
        outcome_seed,
        observer_key,
        token,
        markers,
    )
}

pub fn load_shadow_replayer(
    config_path: &Path,
    connector_key_path: &Path,
    replay_seed_path: &Path,
) -> Result<ShadowReplayer, ConnectorError> {
    let config: ShadowReplayConfig = parse_config(&read_private_bounded_regular_file(
        config_path,
        MAX_CONFIG_BYTES,
    )?)?;
    ShadowReplayer::new(
        config,
        decode_single_key(connector_key_path)?,
        decode_single_key(replay_seed_path)?,
    )
}

pub async fn serve_connector_stdio(connector: &ExternalConnector) -> Result<(), ConnectorError> {
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut stdout = tokio::io::stdout();
    loop {
        let Some(frame) = read_frame(&mut reader).await? else {
            return Ok(());
        };
        let response = match parse_json_no_duplicates::<ConnectorCommand>(&frame) {
            Ok(ConnectorCommand::Execute { request }) => match connector.execute(*request).await {
                Ok(receipt) => ConnectorResponse::Ok {
                    receipt: Box::new(receipt),
                },
                Err(error) => ConnectorResponse::Error {
                    code: error.code().to_owned(),
                },
            },
            Ok(ConnectorCommand::Reconcile { request }) => match connector.reconcile(*request) {
                Ok(receipt) => ConnectorResponse::Ok {
                    receipt: Box::new(receipt),
                },
                Err(error) => ConnectorResponse::Error {
                    code: error.code().to_owned(),
                },
            },
            Err(error) => ConnectorResponse::Error {
                code: error.code().to_owned(),
            },
        };
        write_frame(&mut stdout, &response).await?;
    }
}

pub async fn serve_shadow_stdio(shadow: &ShadowReplayer) -> Result<(), ConnectorError> {
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut stdout = tokio::io::stdout();
    loop {
        let Some(frame) = read_frame(&mut reader).await? else {
            return Ok(());
        };
        let response = match parse_json_no_duplicates::<ShadowCommand>(&frame) {
            Ok(ShadowCommand::Replay { request }) => match shadow.replay(*request) {
                Ok(receipt) => ShadowResponse::Ok {
                    receipt: Box::new(receipt),
                },
                Err(error) => ShadowResponse::Error {
                    code: error.code().to_owned(),
                },
            },
            Err(error) => ShadowResponse::Error {
                code: error.code().to_owned(),
            },
        };
        write_frame(&mut stdout, &response).await?;
    }
}

async fn read_frame<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
) -> Result<Option<Vec<u8>>, ConnectorError> {
    let mut frame = Vec::new();
    let read = reader
        .take((MAX_FRAME_BYTES as u64).saturating_add(1))
        .read_until(b'\n', &mut frame)
        .await
        .map_err(|_| ConnectorError::MalformedRequest)?;
    if read == 0 {
        return Ok(None);
    }
    if frame.len() > MAX_FRAME_BYTES || frame.last() != Some(&b'\n') {
        return Err(ConnectorError::OversizedRequest);
    }
    frame.pop();
    if frame.last() == Some(&b'\r') {
        frame.pop();
    }
    if frame.is_empty() {
        return Err(ConnectorError::MalformedRequest);
    }
    Ok(Some(frame))
}

async fn write_frame<W: tokio::io::AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    response: &T,
) -> Result<(), ConnectorError> {
    let mut bytes = serde_json::to_vec(response).map_err(|_| ConnectorError::StateUnavailable)?;
    if bytes.len().saturating_add(1) > MAX_FRAME_BYTES {
        return Err(ConnectorError::CapacityExceeded);
    }
    bytes.push(b'\n');
    writer
        .write_all(&bytes)
        .await
        .map_err(|error| match error.kind() {
            ErrorKind::BrokenPipe => ConnectorError::StateUnavailable,
            _ => ConnectorError::StateUnavailable,
        })?;
    writer
        .flush()
        .await
        .map_err(|_| ConnectorError::StateUnavailable)
}

fn parse_config<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, ConnectorError> {
    parse_json_no_duplicates(bytes).map_err(|_| ConnectorError::InvalidConfig)
}

fn decode_single_key(path: &Path) -> Result<Vec<u8>, ConnectorError> {
    let bytes = read_private_bounded_regular_file(path, MAX_KEY_BYTES)?;
    let encoded = std::str::from_utf8(&bytes)
        .map_err(|_| ConnectorError::InvalidConfig)?
        .trim();
    BASE64
        .decode(encoded)
        .map_err(|_| ConnectorError::InvalidConfig)
}

fn decode_markers(path: &Path) -> Result<Vec<Vec<u8>>, ConnectorError> {
    let bytes = read_private_bounded_regular_file(path, MAX_MARKER_BYTES)?;
    let encoded: Vec<String> = parse_config(&bytes)?;
    encoded
        .into_iter()
        .map(|marker| {
            BASE64
                .decode(marker)
                .map_err(|_| ConnectorError::InvalidConfig)
        })
        .collect()
}
