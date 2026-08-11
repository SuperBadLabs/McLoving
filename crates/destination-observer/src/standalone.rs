use std::io::{self, Read, Write};
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};

use crate::{
    DestinationObserver, ObservationReceipt, ObservationRequest, ObserverConfig, ObserverError,
    parse_json_no_duplicates, read_private_bounded_regular_file, sha256_running_executable,
};

pub const MAX_FRAME_BYTES: usize = 256 * 1024;
const MAX_CONFIG_BYTES: usize = 256 * 1024;
const MAX_AUTHORITY_BYTES: usize = 4096;
const MAX_MARKER_FILE_BYTES: usize = 64 * 1024;
const MAX_RUNTIME_IMAGE_DIGEST_BYTES: usize = 66;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
    load_observer_with_mode(
        config_path,
        runtime_image_sha256_path,
        token_path,
        request_public_key_path,
        destination_public_key_path,
        receipt_seed_path,
        secret_marker_path,
        false,
    )
}

/// Loads the standalone observer through the literal-loopback integration-test boundary.
///
/// This entry point is absent from production builds. The production loader rejects the
/// test-only loopback flag even when a supplied configuration enables it.
#[cfg(feature = "loopback-test")]
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn load_loopback_test_observer(
    config_path: &Path,
    runtime_image_sha256_path: &Path,
    token_path: &Path,
    request_public_key_path: &Path,
    destination_public_key_path: &Path,
    receipt_seed_path: &Path,
    secret_marker_path: &Path,
) -> Result<DestinationObserver, ObserverError> {
    load_observer_with_mode(
        config_path,
        runtime_image_sha256_path,
        token_path,
        request_public_key_path,
        destination_public_key_path,
        receipt_seed_path,
        secret_marker_path,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn load_observer_with_mode(
    config_path: &Path,
    runtime_image_sha256_path: &Path,
    token_path: &Path,
    request_public_key_path: &Path,
    destination_public_key_path: &Path,
    receipt_seed_path: &Path,
    secret_marker_path: &Path,
    allow_loopback_test: bool,
) -> Result<DestinationObserver, ObserverError> {
    let config = read_config(config_path)?;
    if config.test_allow_http_loopback != allow_loopback_test {
        return Err(ObserverError::InvalidConfig);
    }
    let runtime_image_sha256 = read_runtime_image_sha256(runtime_image_sha256_path)?;
    let read_token = read_private_bounded_regular_file(token_path, MAX_AUTHORITY_BYTES)?;
    let request_public_key =
        read_private_bounded_regular_file(request_public_key_path, MAX_AUTHORITY_BYTES)?;
    let destination_public_key =
        read_private_bounded_regular_file(destination_public_key_path, MAX_AUTHORITY_BYTES)?;
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
    let implementation_sha256 = sha256_running_executable()?;
    if allow_loopback_test {
        #[cfg(feature = "loopback-test")]
        {
            return DestinationObserver::new_for_loopback_test(
                config,
                implementation_sha256,
                runtime_image_sha256,
                read_token,
                request_public_key,
                destination_public_key,
                receipt_seed,
                secret_markers,
            );
        }
        #[cfg(not(feature = "loopback-test"))]
        {
            return Err(ObserverError::InvalidConfig);
        }
    }
    DestinationObserver::new_measured(
        config,
        implementation_sha256,
        runtime_image_sha256,
        read_token,
        request_public_key,
        destination_public_key,
        receipt_seed,
        secret_markers,
    )
}

pub async fn serve_stdio(observer: &DestinationObserver) -> Result<(), ObserverError> {
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    loop {
        let frame = match read_bounded_frame(&mut input) {
            Ok(Some(frame)) => frame,
            Ok(None) => return Ok(()),
            Err(error) => {
                write_response(&mut output, &ObserverResponse::from_error(&error))?;
                if is_fatal_frame_read_error(&error) {
                    return Err(error);
                }
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
            Err(_) => ObserverResponse::from_error(&ObserverError::MalformedRequest),
        };
        write_response(&mut output, &response)?;
    }
}

fn is_fatal_frame_read_error(error: &ObserverError) -> bool {
    matches!(
        error,
        ObserverError::OversizedRequest | ObserverError::StateUnavailable
    )
}

fn read_config(path: &Path) -> Result<ObserverConfig, ObserverError> {
    let bytes = read_private_bounded_regular_file(path, MAX_CONFIG_BYTES)?;
    parse_json_no_duplicates(&bytes).map_err(|_| ObserverError::InvalidConfig)
}

fn read_runtime_image_sha256(path: &Path) -> Result<String, ObserverError> {
    let bytes = read_private_bounded_regular_file(path, MAX_RUNTIME_IMAGE_DIGEST_BYTES)?;
    let value = std::str::from_utf8(&bytes).map_err(|_| ObserverError::InvalidConfig)?;
    let digest = value
        .strip_suffix("\r\n")
        .or_else(|| value.strip_suffix('\n'))
        .unwrap_or(value);
    if digest.len() != 64 {
        return Err(ObserverError::InvalidConfig);
    }
    Ok(digest.to_owned())
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
                if frame.len() >= MAX_FRAME_BYTES {
                    return Err(ObserverError::OversizedRequest);
                }
                return Ok(Some(frame));
            }
            Ok(_) => {
                frame.push(byte[0]);
                if frame.len() >= MAX_FRAME_BYTES {
                    return Err(ObserverError::OversizedRequest);
                }
            }
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

    use super::{is_fatal_frame_read_error, read_config, read_runtime_image_sha256};
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

    #[test]
    fn runtime_image_digest_accepts_one_text_line_only() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("runtime-image.sha256");
        fs::write(&path, format!("{}\n", "a".repeat(64))).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_runtime_image_sha256(&path).unwrap(), "a".repeat(64));

        fs::write(&path, format!("{} \n", "a".repeat(64))).unwrap();
        assert_eq!(
            read_runtime_image_sha256(&path),
            Err(ObserverError::InvalidConfig)
        );
    }

    #[test]
    fn persistent_frame_io_errors_are_fatal() {
        assert!(is_fatal_frame_read_error(&ObserverError::StateUnavailable));
        assert!(is_fatal_frame_read_error(&ObserverError::OversizedRequest));
        assert!(!is_fatal_frame_read_error(&ObserverError::MalformedRequest));
    }
}
