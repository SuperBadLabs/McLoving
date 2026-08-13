use std::fs::OpenOptions;
use std::io::Read as _;
use std::path::Path;

use crate::ConnectorError;

pub fn read_bounded_regular_file(path: &Path, maximum: usize) -> Result<Vec<u8>, ConnectorError> {
    read_file(path, maximum, false)
}

#[cfg(target_os = "linux")]
pub fn sha256_running_executable() -> Result<String, ConnectorError> {
    use sha2::{Digest as _, Sha256};
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC)
        .open("/proc/self/exe")
        .map_err(|_| ConnectorError::StateUnavailable)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| ConnectorError::StateUnavailable)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    let mut encoded = String::with_capacity(64);
    for byte in digest.finalize() {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    Ok(encoded)
}

#[cfg(not(target_os = "linux"))]
pub fn sha256_running_executable() -> Result<String, ConnectorError> {
    Err(ConnectorError::StateUnavailable)
}

pub fn read_private_bounded_regular_file(
    path: &Path,
    maximum: usize,
) -> Result<Vec<u8>, ConnectorError> {
    read_file(path, maximum, true)
}

fn read_file(path: &Path, maximum: usize, private: bool) -> Result<Vec<u8>, ConnectorError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK | nix::libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| ConnectorError::StateUnavailable)?;
        let metadata = file
            .metadata()
            .map_err(|_| ConnectorError::StateUnavailable)?;
        use std::os::unix::fs::MetadataExt as _;
        if !metadata.file_type().is_file()
            || metadata.nlink() != 1
            || metadata.len() > maximum as u64
            || (private
                && (metadata.uid() != nix::unistd::geteuid().as_raw()
                    || metadata.mode() & 0o077 != 0))
        {
            return Err(ConnectorError::StateUnavailable);
        }
        let mut bytes = Vec::new();
        file.take((maximum as u64).saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| ConnectorError::StateUnavailable)?;
        if bytes.len() > maximum {
            return Err(ConnectorError::StateUnavailable);
        }
        Ok(bytes)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, maximum, private);
        Err(ConnectorError::StateUnavailable)
    }
}
