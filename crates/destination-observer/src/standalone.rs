use std::io::{Read, Write};
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};

use crate::{
    DestinationObserver, ObservationReceipt, ObservationRequest, ObserverConfig, ObserverError,
    parse_json_no_duplicates, read_bounded_regular_file, read_private_bounded_regular_file,
    sha256_running_executable,
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
    runtime_image_sha256_path: &Path,
    token_path: &Path,
    request_public_key_path: &Path,
    destination_public_key_path: &Path,
    receipt_seed_path: &Path,
    secret_marker_path: &Path,
) -> Result<DestinationObserver, ObserverError> {
    let config = read_config(config_path)?;
    let runtime_image_sha256 = read_private_bounded_regular_file(runtime_image_sha256_path, 64)?;
    let runtime_image_sha256 =
        String::from_utf8(runtime_image_sha256).map_err(|_| ObserverError::InvalidConfig)?;
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
        sha256_running_executable()?,
        runtime_image_sha256,
        read_token,
        request_public_key,
        destination_public_key,
        receipt_seed,
        secret_markers,
    )
}

fn read_config(path: &Path) -> Result<ObserverConfig, ObserverError> {
    let bytes = read_private_bounded_regular_file(path, MAX_CONFIG_BYTES)?;
    parse_json_no_duplicates(&bytes).map_err(|_| ObserverError::InvalidConfig)
}

pub fn read_bounded_frame<R: Read>(input: &mut R) -> Result<Option<Vec<u8>>, ObserverError> {
    let mut frame = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        match input.read(&mut byte) {
            Ok(0) if frame.is_empty() => return Ok(None),
            Ok(0) => return Err(ObserverError::MalformedRequest),
            Ok(_) if byte[0] == b'\n' => {
                if frame.len() >= MAX_FRAME_BYTES {
                    return Err(ObserverError::OversizedRequest);
                }
                if frame.last() == Some(&b'\r') {
                    frame.pop();
                }
                return Ok(Some(frame));
            }
            Ok(_) if frame.len() >= MAX_FRAME_BYTES => {
                return Err(ObserverError::OversizedRequest);
            }
            Ok(_) => frame.push(byte[0]),
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

pub(crate) fn observed_response_fits(receipt: &ObservationReceipt) -> bool {
    serde_json::to_vec(&ObserverResponse::Observed {
        receipt: Box::new(receipt.clone()),
    })
    .is_ok_and(|bytes| {
        bytes
            .len()
            .checked_add(1)
            .is_some_and(|size| size <= MAX_FRAME_BYTES)
    })
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use super::read_config;
    use crate::ObserverError;

    #[test]
    fn configuration_must_be_owner_private_before_it_is_parsed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("observer.json");
        fs::write(&path, b"{}").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(read_config(&path), Err(ObserverError::StateUnavailable));

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_config(&path), Err(ObserverError::InvalidConfig));
    }
}
