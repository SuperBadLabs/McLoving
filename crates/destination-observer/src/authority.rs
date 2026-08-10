use std::fs::{File, OpenOptions};
use std::io::Read as _;
use std::path::Path;

use sha2::{Digest as _, Sha256};

use crate::ObserverError;

pub fn content_sha256(bytes: &[u8]) -> String {
    crate::crypto::content_sha256(bytes)
}

pub fn read_bounded_regular_file(path: &Path, maximum: usize) -> Result<Vec<u8>, ObserverError> {
    read_file(path, maximum, false)
}

pub fn read_private_bounded_regular_file(
    path: &Path,
    maximum: usize,
) -> Result<Vec<u8>, ObserverError> {
    read_file(path, maximum, true)
}

#[cfg(unix)]
fn read_file(path: &Path, maximum: usize, private: bool) -> Result<Vec<u8>, ObserverError> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK | nix::libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| ObserverError::StateUnavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| ObserverError::StateUnavailable)?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.len() > maximum as u64
        || (private
            && (metadata.uid() != nix::unistd::geteuid().as_raw() || metadata.mode() & 0o077 != 0))
    {
        return Err(ObserverError::StateUnavailable);
    }
    let mut bytes = Vec::new();
    file.take((maximum as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| ObserverError::StateUnavailable)?;
    if bytes.len() > maximum {
        return Err(ObserverError::StateUnavailable);
    }
    Ok(bytes)
}

#[cfg(not(unix))]
fn read_file(_path: &Path, _maximum: usize, _private: bool) -> Result<Vec<u8>, ObserverError> {
    Err(ObserverError::StateUnavailable)
}

#[cfg(target_os = "linux")]
pub fn sha256_running_executable() -> Result<String, ObserverError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC)
        .open("/proc/self/exe")
        .map_err(|_| ObserverError::StateUnavailable)?;
    sha256_open_file(file)
}

#[cfg(not(target_os = "linux"))]
pub fn sha256_running_executable() -> Result<String, ObserverError> {
    Err(ObserverError::StateUnavailable)
}

fn sha256_open_file(mut file: File) -> Result<String, ObserverError> {
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1_024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| ObserverError::StateUnavailable)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    let bytes = digest.finalize();
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    Ok(encoded)
}

#[cfg(all(test, unix))]
mod tests {
    use std::path::Path;
    use std::time::{Duration, Instant};

    use nix::sys::stat::Mode;
    use nix::unistd::mkfifo;

    use super::read_private_bounded_regular_file;
    use crate::ObserverError;

    #[test]
    fn authority_special_files_fail_without_blocking() {
        let directory = tempfile::tempdir().unwrap();
        let fifo = directory.path().join("authority.fifo");
        mkfifo(&fifo, Mode::S_IRUSR | Mode::S_IWUSR).unwrap();

        let started = Instant::now();
        assert_eq!(
            read_private_bounded_regular_file(&fifo, 64),
            Err(ObserverError::StateUnavailable)
        );
        assert!(started.elapsed() < Duration::from_secs(1));

        let started = Instant::now();
        assert_eq!(
            read_private_bounded_regular_file(Path::new("/dev/null"), 64),
            Err(ObserverError::StateUnavailable)
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
