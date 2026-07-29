//! Cross-platform process execution with bounded workspaces and durable logs.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::fs;
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;

use crate::{JournalError, SpoolEntry, validate_relative_path};

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub use unix::{execute, execute_with_spawn_hook};
#[cfg(windows)]
pub use windows::{execute, execute_with_spawn_hook};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ExecutionMode {
    #[default]
    Direct,
    WindowsCmd,
    PowerShell,
}

#[derive(Clone, Debug)]
pub struct ExecutionRequest {
    pub workspace_root: PathBuf,
    pub workspace: PathBuf,
    pub mode: ExecutionMode,
    pub program: PathBuf,
    pub arguments: Vec<OsString>,
    pub environment: BTreeMap<OsString, OsString>,
    pub timeout: Duration,
    pub termination_grace: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Termination {
    Exited,
    TimedOut,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Containment {
    UnixProcessGroup,
    WindowsJobObject,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionOutcome {
    pub termination: Termination,
    pub exit_code: Option<i32>,
    pub process_id: u32,
    pub containment: Containment,
    pub stdout: SpoolEntry,
    pub stderr: SpoolEntry,
}

#[derive(Debug, Error)]
pub enum ExecutionError {
    #[error("invalid workspace path: {0}")]
    InvalidWorkspace(#[from] JournalError),
    #[error("workspace root must resolve to an existing directory")]
    InvalidWorkspaceRoot,
    #[error("workspace already exists")]
    WorkspaceAlreadyExists,
    #[error("workspace contains a symlink or reparse-point component")]
    SymlinkWorkspaceComponent,
    #[error("process did not expose a valid process ID")]
    MissingProcessId,
    #[error("process spawn could not be recorded durably: {0}")]
    SpawnHook(String),
    #[error("execution mode {0:?} is unsupported on this platform")]
    UnsupportedMode(ExecutionMode),
    #[error("cmd.exe program or argument contains unsupported shell metacharacters")]
    UnsafeWindowsShellArgument,
    #[error("Windows Job Object operation failed: {0}")]
    WindowsJob(String),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[cfg(unix)]
    #[error("signal error: {0}")]
    Signal(#[from] nix::errno::Errno),
}

pub async fn execute_portable(
    request: &ExecutionRequest,
    cancellation: CancellationToken,
) -> Result<ExecutionOutcome, ExecutionError> {
    execute(request, cancellation).await
}

fn create_workspace(root: &Path, relative: &Path) -> Result<PathBuf, ExecutionError> {
    validate_relative_path(relative)?;
    let root = root
        .canonicalize()
        .map_err(|_| ExecutionError::InvalidWorkspaceRoot)?;
    if !root.is_dir() || is_link_or_reparse_point(&std::fs::symlink_metadata(&root)?) {
        return Err(ExecutionError::InvalidWorkspaceRoot);
    }

    let mut current = root.clone();
    let components: Vec<_> = relative.components().collect();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            return Err(ExecutionError::InvalidWorkspace(
                JournalError::InvalidRelativePath,
            ));
        };
        current.push(name);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if is_link_or_reparse_point(&metadata) => {
                return Err(ExecutionError::SymlinkWorkspaceComponent);
            }
            Ok(_) if index + 1 == components.len() => {
                return Err(ExecutionError::WorkspaceAlreadyExists);
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(ExecutionError::InvalidWorkspaceRoot);
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                std::fs::create_dir(&current)?;
                let parent = current
                    .parent()
                    .ok_or(ExecutionError::InvalidWorkspaceRoot)?;
                sync_directory(parent)?;
            }
            Err(error) => return Err(error.into()),
        }
    }

    let canonical = current.canonicalize()?;
    if !canonical.starts_with(&root) {
        return Err(ExecutionError::SymlinkWorkspaceComponent);
    }
    Ok(canonical)
}

fn is_link_or_reparse_point(metadata: &std::fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

async fn sync_file(path: &Path) -> Result<(), io::Error> {
    #[cfg(unix)]
    {
        fs::OpenOptions::new()
            .read(true)
            .open(path)
            .await?
            .sync_all()
            .await
    }
    #[cfg(windows)]
    {
        // FlushFileBuffers requires GENERIC_WRITE even when no further bytes
        // will be appended. Reopen the completed spool file with write access
        // so sync_all maps to the documented Win32 durability primitive.
        fs::OpenOptions::new()
            .write(true)
            .open(path)
            .await?
            .sync_all()
            .await
    }
}

fn sync_directory(path: &Path) -> Result<(), io::Error> {
    #[cfg(unix)]
    {
        std::fs::File::open(path)?.sync_all()
    }
    #[cfg(windows)]
    {
        // FlushFileBuffers requires a GENERIC_WRITE handle, but Win32 does not
        // grant that access for directory handles opened by an unprivileged
        // service. Directory handles are therefore not a Windows equivalent
        // of POSIX directory fsync. Keep this check explicit: every durable
        // payload file is flushed above, SQLite remains the authoritative
        // journal, and directory-entry power-loss survival is a separate
        // persistent-host reboot gate rather than an inferred guarantee.
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.is_dir() && !is_link_or_reparse_point(&metadata) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "directory durability boundary is not a plain directory",
            ))
        }
    }
}

async fn spool_entry(
    workspace: &Path,
    suffix: &str,
    sequence: u64,
    path: &Path,
) -> Result<SpoolEntry, ExecutionError> {
    let metadata = fs::metadata(path).await?;
    Ok(SpoolEntry {
        sequence,
        relative_path: workspace.join(suffix),
        digest: digest_file(path).await?,
        bytes: metadata.len(),
    })
}

async fn digest_file(path: &Path) -> Result<[u8; 32], io::Error> {
    let mut file = fs::File::open(path).await?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(digest.finalize().into())
}
