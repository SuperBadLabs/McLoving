use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    CacheConfig, CacheError, CacheKeyRequest, CacheReceipt, CacheStore, CleanupResult,
    PublishResult, ReadResult, parse_json_no_duplicates,
};

const MAX_CONFIG_BYTES: usize = 256 * 1_024;
const MAX_RECEIPT_KEY_BYTES: usize = 4 * 1_024;
const MAX_RECEIPT_RESPONSE_BYTES: u64 = 4 * 1_024;
const RESPONSE_ENVELOPE_BYTES: u64 = 1_024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum CacheCommand {
    Publish {
        caller_id: String,
        caller_trust_class: String,
        key: CacheKeyRequest,
        content_base64: String,
    },
    Read {
        caller_id: String,
        caller_trust_class: String,
        key: CacheKeyRequest,
    },
    Cleanup {
        caller_id: String,
    },
    VerifyAudit {
        caller_id: String,
        expected_events: u64,
        expected_head_sha256: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CacheResponse {
    Published {
        outcome: crate::PublishStatus,
        receipts: Vec<CacheReceipt>,
    },
    Read {
        outcome: crate::ReadStatus,
        content_base64: Option<String>,
        receipts: Vec<CacheReceipt>,
    },
    Cleaned {
        removed: u64,
        receipts: Vec<CacheReceipt>,
    },
    AuditVerified {
        events: u64,
    },
    Error {
        code: &'static str,
        message: &'static str,
    },
}

impl CacheCommand {
    pub fn execute(self, store: &CacheStore, operator_identity: &str) -> CacheResponse {
        match self {
            Self::Publish {
                caller_id,
                caller_trust_class,
                key,
                content_base64,
            } => match BASE64.decode(content_base64) {
                Ok(content) => CacheResponse::from_result(store.publish(
                    &caller_id,
                    &caller_trust_class,
                    &key,
                    &content,
                )),
                Err(_) => CacheResponse::from_error(CacheError::MalformedProtocol),
            },
            Self::Read {
                caller_id,
                caller_trust_class,
                key,
            } => CacheResponse::from_result(store.read(&caller_id, &caller_trust_class, &key)),
            Self::Cleanup { caller_id } => CacheResponse::from_result(store.cleanup(&caller_id)),
            Self::VerifyAudit {
                caller_id,
                expected_events,
                expected_head_sha256,
            } => {
                if caller_id != operator_identity {
                    CacheResponse::from_error(CacheError::Unauthorized)
                } else {
                    match store.verify_audit_chain_against(expected_events, &expected_head_sha256) {
                        Ok(()) => CacheResponse::AuditVerified {
                            events: expected_events,
                        },
                        Err(error) => CacheResponse::from_error(error),
                    }
                }
            }
        }
    }
}

trait IntoCacheResponse {
    fn into_response(self) -> CacheResponse;
}

impl IntoCacheResponse for PublishResult {
    fn into_response(self) -> CacheResponse {
        CacheResponse::Published {
            outcome: self.status,
            receipts: self.receipts,
        }
    }
}

impl IntoCacheResponse for ReadResult {
    fn into_response(self) -> CacheResponse {
        CacheResponse::Read {
            outcome: self.status,
            content_base64: self.content.map(|content| BASE64.encode(content)),
            receipts: self.receipts,
        }
    }
}

impl IntoCacheResponse for CleanupResult {
    fn into_response(self) -> CacheResponse {
        CacheResponse::Cleaned {
            removed: self.removed,
            receipts: self.receipts,
        }
    }
}

impl IntoCacheResponse for u64 {
    fn into_response(self) -> CacheResponse {
        CacheResponse::AuditVerified { events: self }
    }
}

impl CacheResponse {
    fn from_result<T: IntoCacheResponse>(result: Result<T, CacheError>) -> Self {
        result.map_or_else(Self::from_error, IntoCacheResponse::into_response)
    }

    pub fn from_error(error: CacheError) -> Self {
        Self::Error {
            code: error.code(),
            message: "cache request was denied",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameReadError {
    Io,
    Oversized,
    Unterminated,
}

pub fn read_bounded_frame<R: Read>(
    input: &mut R,
    maximum: usize,
) -> Result<Option<Vec<u8>>, FrameReadError> {
    let mut frame = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        match input.read(&mut byte) {
            Ok(0) if frame.is_empty() => return Ok(None),
            Ok(0) => return Err(FrameReadError::Unterminated),
            Ok(_) if byte[0] == b'\n' => {
                if frame.last() == Some(&b'\r') {
                    frame.pop();
                }
                return Ok(Some(frame));
            }
            Ok(_) if frame.len() >= maximum => {
                discard_to_newline(input)?;
                return Err(FrameReadError::Oversized);
            }
            Ok(_) => frame.push(byte[0]),
            Err(_) => return Err(FrameReadError::Io),
        }
    }
}

fn discard_to_newline<R: Read>(input: &mut R) -> Result<(), FrameReadError> {
    let mut byte = [0_u8; 1];
    loop {
        match input.read(&mut byte) {
            Ok(0) => return Ok(()),
            Ok(_) if byte[0] == b'\n' => return Ok(()),
            Ok(_) => {}
            Err(_) => return Err(FrameReadError::Io),
        }
    }
}

pub fn serialized_response_fits_frame(serialized_bytes: usize, maximum: u64) -> bool {
    u64::try_from(serialized_bytes)
        .ok()
        .and_then(|bytes| bytes.checked_add(1))
        .is_some_and(|bytes| bytes <= maximum)
}

pub fn load_config(path: &Path) -> Result<CacheConfig, CacheError> {
    let bytes = read_bounded_regular_file(path, MAX_CONFIG_BYTES, true, true)?;
    let config: CacheConfig = parse_json_no_duplicates(&bytes)?;
    let largest_entry = config
        .policies
        .iter()
        .map(|policy| policy.max_entry_bytes)
        .max()
        .unwrap_or(0);
    let encoded = largest_entry
        .checked_add(2)
        .and_then(|bytes| bytes.checked_div(3))
        .and_then(|groups| groups.checked_mul(4))
        .ok_or(CacheError::InvalidConfig)?;
    let read_response_minimum = encoded
        .checked_add(MAX_RECEIPT_RESPONSE_BYTES)
        .and_then(|bytes| bytes.checked_add(RESPONSE_ENVELOPE_BYTES))
        .ok_or(CacheError::InvalidConfig)?;
    let receipt_response_minimum = config
        .max_cleanup_rows
        .checked_add(1)
        .and_then(|receipts| receipts.checked_mul(MAX_RECEIPT_RESPONSE_BYTES))
        .and_then(|bytes| bytes.checked_add(RESPONSE_ENVELOPE_BYTES))
        .ok_or(CacheError::InvalidConfig)?;
    if config.max_frame_bytes < read_response_minimum.max(receipt_response_minimum) {
        return Err(CacheError::InvalidConfig);
    }
    Ok(config)
}

pub fn read_private_receipt_key(path: &Path) -> Result<Vec<u8>, CacheError> {
    read_bounded_regular_file(path, MAX_RECEIPT_KEY_BYTES, true, false)
}

#[cfg(unix)]
fn read_bounded_regular_file(
    path: &Path,
    maximum: usize,
    private: bool,
    immutable: bool,
) -> Result<Vec<u8>, CacheError> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    let mut options = OpenOptions::new();
    options.read(true).custom_flags(nix::libc::O_NOFOLLOW);
    let file = options.open(path).map_err(|_| CacheError::InvalidConfig)?;
    let metadata = file.metadata().map_err(|_| CacheError::InvalidConfig)?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.len() > maximum as u64
        || (private
            && (metadata.uid() != nix::unistd::geteuid().as_raw() || metadata.mode() & 0o077 != 0))
        || (immutable && metadata.mode() & 0o777 != 0o400)
    {
        return Err(CacheError::InvalidConfig);
    }
    let mut bytes = Vec::new();
    file.take((maximum as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| CacheError::InvalidConfig)?;
    if bytes.len() > maximum {
        return Err(CacheError::InvalidConfig);
    }
    Ok(bytes)
}

#[cfg(not(unix))]
fn read_bounded_regular_file(
    _path: &Path,
    _maximum: usize,
    _private: bool,
    _immutable: bool,
) -> Result<Vec<u8>, CacheError> {
    Err(CacheError::InvalidConfig)
}

pub fn sha256_file(path: &Path) -> Result<String, CacheError> {
    let mut file = File::open(path).map_err(|_| CacheError::InvalidConfig)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1_024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| CacheError::InvalidConfig)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(encode_digest(&digest.finalize()))
}

pub fn write_response<W: Write>(
    output: &mut W,
    response: &CacheResponse,
    maximum: u64,
) -> Result<(), CacheError> {
    let mut bytes = serde_json::to_vec(response).map_err(|_| CacheError::StateUnavailable)?;
    if !serialized_response_fits_frame(bytes.len(), maximum) {
        bytes = serde_json::to_vec(&CacheResponse::Error {
            code: "CACHE_RESPONSE_OVERSIZED",
            message: "cache request was denied",
        })
        .map_err(|_| CacheError::StateUnavailable)?;
    }
    bytes.push(b'\n');
    output
        .write_all(&bytes)
        .and_then(|()| output.flush())
        .map_err(|_| CacheError::StateUnavailable)
}

fn encode_digest(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}
