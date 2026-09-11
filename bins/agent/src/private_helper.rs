//! Mechanical private file and sealed executable custody shared by closed typed helpers.
use crate::AgentError;
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};
use std::fs::File;
#[cfg(unix)]
use std::io::Read;
#[cfg(target_os = "linux")]
use std::io::Write;
use std::path::{Path, PathBuf};
fn denied() -> AgentError {
    AgentError::InvalidConfig("sealed helper custody")
}
#[cfg(target_os = "linux")]
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
#[cfg(unix)]
pub(crate) fn read_private(
    path: &Path,
    maximum: usize,
    immutable: bool,
) -> Result<Vec<u8>, AgentError> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    if !path.is_absolute() || path.canonicalize().map_err(|_| denied())? != path {
        return Err(denied());
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| denied())?;
    let metadata = file.metadata().map_err(|_| denied())?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || (immutable && metadata.mode() & 0o777 != 0o400)
        || metadata.len() > maximum as u64
    {
        return Err(denied());
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| denied())?;
    if bytes.len() > maximum {
        return Err(denied());
    }
    Ok(bytes)
}
#[cfg(not(unix))]
pub(crate) fn read_private(_: &Path, _: usize, _: bool) -> Result<Vec<u8>, AgentError> {
    Err(denied())
}

#[cfg(target_os = "linux")]
pub(crate) fn seal_executable(path: &Path, expected: &str) -> Result<(File, PathBuf), AgentError> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    if !path.is_absolute() || path.canonicalize().map_err(|_| denied())? != path {
        return Err(denied());
    }
    let input = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| denied())?;
    let metadata = input.metadata().map_err(|_| denied())?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 512 * 1024 * 1024 {
        return Err(denied());
    }
    let fd = nix::sys::memfd::memfd_create(
        "mcloving-sealed-cache",
        nix::sys::memfd::MFdFlags::MFD_CLOEXEC | nix::sys::memfd::MFdFlags::MFD_ALLOW_SEALING,
    )
    .map_err(|_| denied())?;
    let mut file = File::from(fd);
    let mut digest = Sha256::new();
    let mut input = input.take(512 * 1024 * 1024 + 1);
    let mut copied = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let count = input.read(&mut buffer).map_err(|_| denied())?;
        if count == 0 {
            break;
        }
        copied += count as u64;
        if copied > metadata.len() {
            return Err(denied());
        }
        digest.update(&buffer[..count]);
        file.write_all(&buffer[..count]).map_err(|_| denied())?;
    }
    if copied != metadata.len() || hex(&digest.finalize()) != expected {
        return Err(denied());
    }
    nix::fcntl::fcntl(
        &file,
        nix::fcntl::FcntlArg::F_ADD_SEALS(
            nix::fcntl::SealFlag::F_SEAL_WRITE
                | nix::fcntl::SealFlag::F_SEAL_GROW
                | nix::fcntl::SealFlag::F_SEAL_SHRINK
                | nix::fcntl::SealFlag::F_SEAL_SEAL,
        ),
    )
    .map_err(|_| denied())?;
    nix::fcntl::fcntl(
        &file,
        nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
    )
    .map_err(|_| denied())?;
    let program = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
    Ok((file, program))
}
#[cfg(not(target_os = "linux"))]
pub(crate) fn seal_executable(_: &Path, _: &str) -> Result<(File, PathBuf), AgentError> {
    Err(denied())
}

/// Closed typed dispatch: no submitted command, environment or validator hooks.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) enum PreparedHelper {
    Cache(Box<crate::cache::PreparedCache>),
    Input(Box<crate::input::PreparedInput>),
    #[cfg(target_os = "linux")]
    Source(Box<crate::source::PreparedSource>),
}
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl PreparedHelper {
    pub fn program(&self) -> &Path {
        match self {
            Self::Cache(v) => &v.program,
            Self::Input(v) => &v.program,
            #[cfg(target_os = "linux")]
            Self::Source(v) => &v.program,
        }
    }
    pub fn arguments(&self) -> &[std::ffi::OsString] {
        match self {
            Self::Cache(v) => &v.arguments,
            Self::Input(v) => &v.arguments,
            #[cfg(target_os = "linux")]
            Self::Source(v) => &v.arguments,
        }
    }
    pub fn environment(&self) -> std::collections::BTreeMap<String, String> {
        match self {
            Self::Cache(_) => Default::default(),
            Self::Input(v) => v.environment.clone(),
            #[cfg(target_os = "linux")]
            Self::Source(v) => v.environment.clone(),
        }
    }
    /// Opens whatever time window the helper's request carries, immediately
    /// before its spawn. Cache and input requests carry none.
    pub fn begin(&self) -> Result<(), crate::AgentError> {
        match self {
            Self::Cache(_) | Self::Input(_) => Ok(()),
            #[cfg(target_os = "linux")]
            Self::Source(v) => v.begin(),
        }
    }
    pub fn request(&self) -> Vec<u8> {
        match self {
            Self::Cache(v) => v.request.clone(),
            Self::Input(v) => v.request.clone(),
            #[cfg(target_os = "linux")]
            Self::Source(v) => v.request(),
        }
    }
    pub fn output_limit(&self) -> u64 {
        match self {
            Self::Cache(v) => v.output_limit,
            Self::Input(v) => v.output_limit,
            #[cfg(target_os = "linux")]
            Self::Source(v) => v.output_limit,
        }
    }
    pub fn response_failure(&self) -> &'static str {
        match self {
            Self::Cache(_) => "cache_response_rejected",
            Self::Input(_) => "input_response_rejected",
            #[cfg(target_os = "linux")]
            Self::Source(_) => "source_response_rejected",
        }
    }
    pub fn transform(
        &self,
        stdout: &[u8],
        stderr: &[u8],
    ) -> mcloving_agent_runtime::executor::PrivateExecutionOutput {
        match self {
            Self::Cache(v) => v.transform(stdout, stderr),
            Self::Input(v) => v.transform(stdout, stderr),
            #[cfg(target_os = "linux")]
            Self::Source(v) => v.transform(stdout, stderr),
        }
    }
    /// The step reason when the helper's answer was not accepted: the fixed
    /// rejection name, extended with the sealed acquirer's closed failure
    /// code for a checkout so the terminal summary says why.
    pub fn failure_reason(&self) -> String {
        match self {
            Self::Cache(_) | Self::Input(_) => self.response_failure().to_owned(),
            #[cfg(target_os = "linux")]
            Self::Source(v) => match v.last_outcome() {
                Some(outcome) if outcome != "acquired" => {
                    format!("{}:{outcome}", self.response_failure())
                }
                _ => self.response_failure().to_owned(),
            },
        }
    }
    /// Where this helper's step will leave what it acquires, journaled
    /// before the spawn so recovery can reclaim it: a checkout's acquisition
    /// directory. Cache and input helpers leave nothing.
    pub fn acquisition_directory(&self) -> Option<String> {
        match self {
            Self::Cache(_) | Self::Input(_) => None,
            #[cfg(target_os = "linux")]
            Self::Source(v) => Some(v.acquisition_directory()),
        }
    }
    /// Cleanup a helper owes when its step did not end in a completed
    /// publication: a checkout removes the tree its acquisition may have left
    /// under the output root. Cache and input helpers leave nothing behind.
    pub fn discard(&self) -> Result<(), String> {
        match self {
            Self::Cache(_) | Self::Input(_) => Ok(()),
            #[cfg(target_os = "linux")]
            Self::Source(v) => v.discard(),
        }
    }
    /// Work a helper still owes once its process has exited and its answer
    /// was accepted: a checkout publishes its verified tree into the
    /// workspace. Cache and input helpers owe nothing.
    pub fn complete(&self, workspace: &Path) -> Result<Option<String>, String> {
        match self {
            Self::Cache(_) | Self::Input(_) => {
                let _ = workspace;
                Ok(None)
            }
            #[cfg(target_os = "linux")]
            Self::Source(v) => v.publish(workspace).map(|published| {
                Some(format!(
                    "checkout {} at {} ({} files)",
                    published.destination, published.resolved_commit, published.materialized_files
                ))
            }),
        }
    }
}
