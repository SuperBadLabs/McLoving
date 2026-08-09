use std::fs::{File, OpenOptions};
use std::io::{BufRead, Read};
use std::path::Path;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{CertifiedConfig, ResolutionReceipt, ResolverError};

const MAX_CONFIG_BYTES: u64 = 1_048_576;
const MAX_EXECUTABLE_BYTES: u64 = 256 * 1_048_576;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FrameReadError {
    Oversized,
    Io,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ResolverResponse {
    Ok {
        receipt: Box<ResolutionReceipt>,
    },
    Error {
        code: &'static str,
        message: &'static str,
    },
}

impl From<Result<ResolutionReceipt, ResolverError>> for ResolverResponse {
    fn from(result: Result<ResolutionReceipt, ResolverError>) -> Self {
        match result {
            Ok(receipt) => Self::Ok {
                receipt: Box::new(receipt),
            },
            Err(error) => Self::Error {
                code: error.code,
                message: error.message,
            },
        }
    }
}

pub fn serialized_response_fits_frame(serialized_bytes: usize, max_frame_bytes: u64) -> bool {
    u64::try_from(serialized_bytes)
        .ok()
        .and_then(|bytes| bytes.checked_add(1))
        .is_some_and(|emitted_bytes| emitted_bytes <= max_frame_bytes)
}

pub fn load_certified_config(path: &Path) -> Result<CertifiedConfig, ResolverError> {
    let bytes = read_private_config(path)?;
    let config: CertifiedConfig = crate::strict_json::from_slice(&bytes)
        .map_err(|_| ResolverError::denied("DEP_CONFIG_FILE_INVALID"))?;
    crate::validate_config(&config).map_err(|error| ResolverError::denied(error.code))?;
    Ok(config)
}

pub fn verify_running_executable(config: &CertifiedConfig) -> Result<(), ResolverError> {
    let digest = hash_running_executable(MAX_EXECUTABLE_BYTES)?;
    if digest != config.executable_sha256 {
        return Err(ResolverError::denied("DEP_EXECUTABLE_IDENTITY_MISMATCH"));
    }
    Ok(())
}

pub(crate) fn verify_executable_path(
    config: &CertifiedConfig,
    path: &Path,
) -> Result<(), ResolverError> {
    let path = std::fs::canonicalize(path)
        .map_err(|_| ResolverError::denied("DEP_EXECUTABLE_IDENTITY_INVALID"))?;
    let digest = hash_regular_file(&path, MAX_EXECUTABLE_BYTES)?;
    if digest != config.executable_sha256 {
        return Err(ResolverError::denied("DEP_EXECUTABLE_IDENTITY_MISMATCH"));
    }
    Ok(())
}

pub fn read_bounded_frame<R: BufRead>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>, FrameReadError> {
    let mut frame = Vec::new();
    let mut oversized = false;
    loop {
        let available = reader.fill_buf().map_err(|_| FrameReadError::Io)?;
        if available.is_empty() {
            if oversized {
                return Err(FrameReadError::Oversized);
            }
            return if frame.is_empty() {
                Ok(None)
            } else {
                Ok(Some(frame))
            };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(available.len(), |position| position + 1);
        let content_len = newline.unwrap_or(available.len());
        if !oversized {
            if frame.len().saturating_add(content_len) > max_bytes {
                oversized = true;
                frame.clear();
            } else {
                frame.extend_from_slice(&available[..content_len]);
            }
        }
        reader.consume(consumed);
        if newline.is_some() {
            return if oversized {
                Err(FrameReadError::Oversized)
            } else {
                Ok(Some(frame))
            };
        }
    }
}

#[cfg(target_os = "linux")]
fn read_private_config(path: &Path) -> Result<Vec<u8>, ResolverError> {
    use nix::unistd::Uid;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let file = open_pinned_regular(path, "DEP_CONFIG_FILE_POLICY_DENIED")?;
    let metadata = file
        .metadata()
        .map_err(|_| ResolverError::denied("DEP_CONFIG_FILE_POLICY_DENIED"))?;
    if !metadata.is_file()
        || metadata.uid() != Uid::effective().as_raw()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() == 0
        || metadata.len() > MAX_CONFIG_BYTES
    {
        return Err(ResolverError::denied("DEP_CONFIG_FILE_POLICY_DENIED"));
    }
    read_bounded(file, MAX_CONFIG_BYTES)
}

#[cfg(not(target_os = "linux"))]
fn read_private_config(_path: &Path) -> Result<Vec<u8>, ResolverError> {
    Err(ResolverError::denied("DEP_CONFIG_PLATFORM_UNSUPPORTED"))
}

#[cfg(target_os = "linux")]
fn hash_regular_file(path: &Path, max_bytes: u64) -> Result<String, ResolverError> {
    let file = open_pinned_regular(path, "DEP_EXECUTABLE_IDENTITY_INVALID")?;
    hash_open_regular(file, max_bytes)
}

#[cfg(target_os = "linux")]
fn hash_running_executable(max_bytes: u64) -> Result<String, ResolverError> {
    use nix::fcntl::OFlag;
    use std::os::unix::fs::OpenOptionsExt as _;

    // /proc/self/exe is a kernel-owned reference to the executable inode that
    // created this process. Opening it directly keeps that inode pinned even
    // if the deployment pathname is atomically replaced while we are running.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_CLOEXEC | OFlag::O_NONBLOCK).bits())
        .open("/proc/self/exe")
        .map_err(|_| ResolverError::denied("DEP_EXECUTABLE_IDENTITY_INVALID"))?;
    hash_open_regular(file, max_bytes)
}

#[cfg(target_os = "linux")]
fn hash_open_regular(mut file: File, max_bytes: u64) -> Result<String, ResolverError> {
    use std::os::unix::fs::MetadataExt as _;

    let denied = || ResolverError::denied("DEP_EXECUTABLE_IDENTITY_INVALID");
    let metadata = file.metadata().map_err(|_| denied())?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > max_bytes {
        return Err(denied());
    }
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 65_536];
    loop {
        let read = file.read(&mut buffer).map_err(|_| denied())?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .filter(|total| *total <= max_bytes)
            .ok_or_else(&denied)?;
        hasher.update(&buffer[..read]);
    }
    let after = file.metadata().map_err(|_| denied())?;
    if total != metadata.len()
        || after.dev() != metadata.dev()
        || after.ino() != metadata.ino()
        || after.len() != metadata.len()
    {
        return Err(denied());
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(target_os = "linux")]
fn open_pinned_regular(path: &Path, code: &'static str) -> Result<File, ResolverError> {
    use nix::fcntl::OFlag;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    let denied = || ResolverError::denied(code);
    let inspection = OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_PATH | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW).bits())
        .open(path)
        .map_err(|_| denied())?;
    let inspected = inspection.metadata().map_err(|_| denied())?;
    if !inspected.is_file() {
        return Err(denied());
    }
    let pinned_path = format!("/proc/self/fd/{}", inspection.as_raw_fd());
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_CLOEXEC | OFlag::O_NONBLOCK).bits())
        .open(pinned_path)
        .map_err(|_| denied())?;
    let opened = file.metadata().map_err(|_| denied())?;
    if !opened.is_file() || opened.dev() != inspected.dev() || opened.ino() != inspected.ino() {
        return Err(denied());
    }
    Ok(file)
}

#[cfg(not(target_os = "linux"))]
fn hash_regular_file(_path: &Path, _max_bytes: u64) -> Result<String, ResolverError> {
    Err(ResolverError::denied("DEP_CONFIG_PLATFORM_UNSUPPORTED"))
}

#[cfg(not(target_os = "linux"))]
fn hash_running_executable(_max_bytes: u64) -> Result<String, ResolverError> {
    Err(ResolverError::denied("DEP_CONFIG_PLATFORM_UNSUPPORTED"))
}

fn read_bounded(file: File, max_bytes: u64) -> Result<Vec<u8>, ResolverError> {
    let metadata = file
        .metadata()
        .map_err(|_| ResolverError::denied("DEP_CONFIG_FILE_POLICY_DENIED"))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ResolverError::denied("DEP_CONFIG_FILE_POLICY_DENIED"))?;
    if bytes.is_empty() || bytes.len() as u64 > max_bytes {
        return Err(ResolverError::denied("DEP_CONFIG_FILE_POLICY_DENIED"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::{FrameReadError, read_bounded_frame, serialized_response_fits_frame};

    #[cfg(target_os = "linux")]
    #[test]
    fn running_executable_hash_is_bound_to_the_proc_inode() {
        use super::{MAX_EXECUTABLE_BYTES, hash_open_regular, hash_running_executable};
        use nix::fcntl::OFlag;
        use std::fs::OpenOptions;
        use std::os::unix::fs::OpenOptionsExt as _;

        let proc_inode = OpenOptions::new()
            .read(true)
            .custom_flags((OFlag::O_CLOEXEC | OFlag::O_NONBLOCK).bits())
            .open("/proc/self/exe")
            .expect("running executable inode");
        assert_eq!(
            hash_running_executable(MAX_EXECUTABLE_BYTES).expect("running executable digest"),
            hash_open_regular(proc_inode, MAX_EXECUTABLE_BYTES).expect("pinned inode digest")
        );
    }

    #[test]
    fn frame_cap_is_enforced_before_unbounded_allocation_and_reader_recovers() {
        let mut input = Cursor::new(b"123456789\nok\npartial".to_vec());
        assert_eq!(
            read_bounded_frame(&mut input, 8),
            Err(FrameReadError::Oversized)
        );
        assert_eq!(
            read_bounded_frame(&mut input, 8).expect("second frame"),
            Some(b"ok".to_vec())
        );
        assert_eq!(
            read_bounded_frame(&mut input, 8).expect("EOF frame"),
            Some(b"partial".to_vec())
        );
        assert_eq!(read_bounded_frame(&mut input, 8).expect("EOF"), None);
    }

    #[test]
    fn response_frame_cap_includes_the_line_terminator() {
        assert!(serialized_response_fits_frame(127, 128));
        assert!(!serialized_response_fits_frame(128, 128));
        assert!(!serialized_response_fits_frame(usize::MAX, u64::MAX));
    }
}
