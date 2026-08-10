use std::io::{Read, Write};
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};

use crate::{
    DestinationObserver, ObservationReceipt, ObservationRequest, ObserverConfig, ObserverError,
    parse_json_no_duplicates, read_bounded_regular_file, read_private_bounded_regular_file,
    sha256_file,
};

pub const MAX_FRAME_BYTES: usize = 256 * 1024;
const MAX_CONFIG_BYTES: usize = 256 * 1024;
const MAX_AUTHORITY_BYTES: usize = 4096;
const MAX_MARKER_FILE_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObserverCommand {
    Observe { request: ObservationRequest },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ObserverResponse {
    Observed {
        receipt: Box<ObservationReceipt>,
    },
    Error {
        code: &'static str,
        message: &'static str,
    },
}

impl ObserverResponse {
    pub fn from_error(error: &ObserverError) -> Self {
        Self::Error {
            code: error.code(),
            message: "destination observation was denied",
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn load_observer(
    config_path: &Path,
    token_path: &Path,
    request_public_key_path: &Path,
    destination_public_key_path: &Path,
    receipt_seed_path: &Path,
    secret_marker_path: &Path,
    executable_path: &Path,
) -> Result<DestinationObserver, ObserverError> {
    let config_bytes = read_bounded_regular_file(config_path, MAX_CONFIG_BYTES)?;
    let config: ObserverConfig =
        parse_json_no_duplicates(&config_bytes).map_err(|_| ObserverError::InvalidConfig)?;
    let read_token = read_private_bounded_regular_file(token_path, MAX_AUTHORITY_BYTES)?;
    let request_public_key =
        read_bounded_regular_file(request_public_key_path, MAX_AUTHORITY_BYTES)?;
    let destination_public_key =
        read_bounded_regular_file(destination_public_key_path, MAX_AUTHORITY_BYTES)?;
    let receipt_seed = read_private_bounded_regular_file(receipt_seed_path, MAX_AUTHORITY_BYTES)?;
    let marker_bytes =
        read_private_bounded_regular_file(secret_marker_path, MAX_MARKER_FILE_BYTES)?;
    let encoded_markers: Vec<String> =
        parse_json_no_duplicates(&marker_bytes).map_err(|_| ObserverError::InvalidConfig)?;
    let secret_markers = encoded_markers
        .into_iter()
        .map(|marker| {
            BASE64
                .decode(marker)
                .map_err(|_| ObserverError::InvalidConfig)
        })
        .collect::<Result<Vec<_>, _>>()?;
    DestinationObserver::new(
        config,
        sha256_file(executable_path)?,
        read_token,
        request_public_key,
        destination_public_key,
        receipt_seed,
        secret_markers,
    )
}

pub fn read_bounded_frame<R: Read>(input: &mut R) -> Result<Option<Vec<u8>>, ObserverError> {
    let mut frame = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        match input.read(&mut byte) {
            Ok(0) if frame.is_empty() => return Ok(None),
            Ok(0) => return Err(ObserverError::MalformedRequest),
            Ok(_) if byte[0] == b'\n' => {
                if frame.last() == Some(&b'\r') {
                    frame.pop();
                }
                return Ok(Some(frame));
            }
            Ok(_) if frame.len() >= MAX_FRAME_BYTES => {
                discard_to_newline(input)?;
                return Err(ObserverError::OversizedResponse);
            }
            Ok(_) => frame.push(byte[0]),
            Err(_) => return Err(ObserverError::StateUnavailable),
        }
    }
}

fn discard_to_newline<R: Read>(input: &mut R) -> Result<(), ObserverError> {
    let mut byte = [0_u8; 1];
    loop {
        match input.read(&mut byte) {
            Ok(0) => return Ok(()),
            Ok(_) if byte[0] == b'\n' => return Ok(()),
            Ok(_) => {}
            Err(_) => return Err(ObserverError::StateUnavailable),
        }
    }
}

pub fn write_response<W: Write>(
    output: &mut W,
    response: &ObserverResponse,
) -> Result<(), ObserverError> {
    let mut bytes = serde_json::to_vec(response).map_err(|_| ObserverError::StateUnavailable)?;
    if bytes.len() >= MAX_FRAME_BYTES {
        bytes = serde_json::to_vec(&ObserverResponse::from_error(
            &ObserverError::OversizedResponse,
        ))
        .map_err(|_| ObserverError::StateUnavailable)?;
    }
    bytes.push(b'\n');
    output
        .write_all(&bytes)
        .map_err(|_| ObserverError::StateUnavailable)?;
    output.flush().map_err(|_| ObserverError::StateUnavailable)
}
