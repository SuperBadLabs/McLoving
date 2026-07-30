//! Cross-platform process execution with bounded workspaces and durable logs.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::{JournalError, SpoolEntry, validate_relative_path};

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
use unix::{
    ensure_original_workspace_root as platform_ensure_original_workspace_root,
    open_workspace_root as platform_open_workspace_root,
};
#[cfg(unix)]
pub use unix::{execute, execute_with_spawn_hook, execute_with_spawn_hook_and_redactions};
#[cfg(windows)]
use windows::{
    ensure_original_workspace_root as platform_ensure_original_workspace_root,
    open_workspace_root as platform_open_workspace_root,
};
#[cfg(windows)]
pub use windows::{execute, execute_with_spawn_hook, execute_with_spawn_hook_and_redactions};

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
    /// Maximum combined durable stdout/stderr bytes for this execution.
    pub output_limit_bytes: Option<u64>,
    pub timeout: Duration,
    pub termination_grace: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Termination {
    Exited,
    TimedOut,
    Cancelled,
    OutputLimitExceeded,
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
    #[error("executor-owned spool path no longer names its original file")]
    ReplacedSpoolPath,
    #[error("configured workspace root no longer names its original directory")]
    ReplacedWorkspaceRoot,
    #[error("process did not expose a valid process ID")]
    MissingProcessId,
    #[error("process spawn could not be recorded durably: {0}")]
    SpawnHook(String),
    #[error("process {process_id} containment could not be verified: {reason}")]
    ContainmentUnverified { process_id: u32, reason: String },
    #[error("execution mode {0:?} is unsupported on this platform")]
    UnsupportedMode(ExecutionMode),
    #[error("cmd.exe program or argument contains unsupported shell metacharacters")]
    UnsafeWindowsShellArgument,
    #[error("Windows Job Object operation failed: {0}")]
    WindowsJob(String),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("credential-bearing execution requires a bounded output quota")]
    UnboundedCredentialOutput,
    #[error("output capture task failed: {0}")]
    OutputCapture(String),
    #[cfg(unix)]
    #[error("signal error: {0}")]
    Signal(#[from] nix::errno::Errno),
}

struct OutputCapture {
    stdout: Option<JoinHandle<Result<Vec<u8>, io::Error>>>,
    stderr: Option<JoinHandle<Result<Vec<u8>, io::Error>>>,
    limit_exceeded: CancellationToken,
    limit: u64,
}

struct CapturedOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exceeded: bool,
}

impl OutputCapture {
    fn start(stdout: File, stderr: File, limit: u64, redactions: &[Vec<u8>]) -> Self {
        let total = Arc::new(AtomicU64::new(0));
        let limit_exceeded = CancellationToken::new();
        let overlap = redactions
            .iter()
            .map(Vec::len)
            .max()
            .and_then(|length| length.checked_sub(1))
            .and_then(|length| u64::try_from(length).ok())
            .unwrap_or(0);
        // A complete secret prefix may be present independently on stdout and
        // stderr. Keep both provisional suffixes beyond the durable quota so
        // a later byte can finish a secret before fail-closed cancellation.
        let provisional_limit = limit.saturating_add(overlap.saturating_mul(2));
        Self {
            stdout: Some(tokio::spawn(capture_pipe(
                stdout,
                provisional_limit,
                redactions.to_vec(),
                Arc::clone(&total),
                limit_exceeded.clone(),
            ))),
            stderr: Some(tokio::spawn(capture_pipe(
                stderr,
                provisional_limit,
                redactions.to_vec(),
                total,
                limit_exceeded.clone(),
            ))),
            limit_exceeded,
            limit,
        }
    }

    #[cfg(unix)]
    async fn limit_exceeded(&self) {
        self.limit_exceeded.cancelled().await;
    }

    fn was_exceeded(&self) -> bool {
        self.limit_exceeded.is_cancelled()
    }

    async fn finish(mut self) -> Result<CapturedOutput, ExecutionError> {
        let stdout = self
            .stdout
            .take()
            .expect("stdout capture handle exists")
            .await
            .map_err(|error| ExecutionError::OutputCapture(error.to_string()))??;
        let stderr = self
            .stderr
            .take()
            .expect("stderr capture handle exists")
            .await
            .map_err(|error| ExecutionError::OutputCapture(error.to_string()))??;
        let final_bytes = u64::try_from(stdout.len())
            .expect("captured stdout length fits u64")
            .saturating_add(u64::try_from(stderr.len()).expect("captured stderr length fits u64"));
        Ok(CapturedOutput {
            stdout,
            stderr,
            exceeded: self.limit_exceeded.is_cancelled() || final_bytes > self.limit,
        })
    }
}

impl Drop for OutputCapture {
    fn drop(&mut self) {
        if let Some(handle) = self.stdout.take() {
            handle.abort();
        }
        if let Some(handle) = self.stderr.take() {
            handle.abort();
        }
    }
}

async fn capture_pipe(
    reader: File,
    provisional_limit: u64,
    redactions: Vec<Vec<u8>>,
    total: Arc<AtomicU64>,
    limit_exceeded: CancellationToken,
) -> Result<Vec<u8>, io::Error> {
    let mut reader = tokio::fs::File::from_std(reader);
    let capacity = usize::try_from(provisional_limit.min(1024 * 1024)).unwrap_or(1024 * 1024);
    let mut captured = Vec::with_capacity(capacity);
    let mut secrets = redactions
        .iter()
        .map(Vec::as_slice)
        .filter(|secret| !secret.is_empty())
        .collect::<Vec<_>>();
    secrets.sort_unstable_by_key(|secret| std::cmp::Reverse(secret.len()));
    let mut buffer = [0_u8; 8192];
    loop {
        let bytes = reader.read(&mut buffer).await?;
        if bytes == 0 {
            return Ok(captured);
        }
        for byte in &buffer[..bytes] {
            let previous_len = captured.len();
            captured.push(*byte);
            while let Some(secret) = secrets.iter().find(|secret| captured.ends_with(secret)) {
                captured.truncate(captured.len() - secret.len());
            }
            let current_len = captured.len();
            let current_total = if current_len >= previous_len {
                let added =
                    u64::try_from(current_len - previous_len).expect("captured growth fits u64");
                total
                    .fetch_add(added, Ordering::AcqRel)
                    .saturating_add(added)
            } else {
                let removed =
                    u64::try_from(previous_len - current_len).expect("captured shrinkage fits u64");
                total
                    .fetch_sub(removed, Ordering::AcqRel)
                    .saturating_sub(removed)
            };
            if current_total > provisional_limit {
                limit_exceeded.cancel();
                return Ok(captured);
            }
            if limit_exceeded.is_cancelled() {
                return Ok(captured);
            }
        }
    }
}

fn write_redacted_output(
    file: &mut File,
    captured: &[u8],
    redactions: &[Vec<u8>],
) -> Result<(), ExecutionError> {
    let redacted = redact_to_fixed_point(captured, redactions)?;
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&redacted)?;
    Ok(())
}

fn redact_to_fixed_point(
    content: &[u8],
    redactions: &[Vec<u8>],
) -> Result<Vec<u8>, ExecutionError> {
    validate_redactions(redactions)?;
    let mut secrets = redactions
        .iter()
        .map(Vec::as_slice)
        .filter(|secret| !secret.is_empty())
        .collect::<Vec<_>>();
    secrets.sort_unstable_by_key(|secret| std::cmp::Reverse(secret.len()));
    let mut output = Vec::with_capacity(content.len());
    for byte in content {
        output.push(*byte);
        while let Some(secret) = secrets.iter().find(|secret| output.ends_with(secret)) {
            output.truncate(output.len() - secret.len());
        }
    }
    Ok(output)
}

fn validate_redactions(redactions: &[Vec<u8>]) -> Result<(), ExecutionError> {
    if redactions.is_empty() {
        return Ok(());
    }
    redaction_matcher(redactions).map(|_| ())
}

fn redaction_matcher(redactions: &[Vec<u8>]) -> Result<AhoCorasick, ExecutionError> {
    AhoCorasickBuilder::new()
        .match_kind(MatchKind::LeftmostLongest)
        .build(redactions)
        .map_err(|error| ExecutionError::OutputCapture(error.to_string()))
}

/// Pins the configured workspace root so path-based maintenance can fail
/// closed if untrusted work replaces that root before cleanup completes.
pub struct WorkspaceRootGuard {
    file: std::fs::File,
}

impl WorkspaceRootGuard {
    pub fn open(path: &Path) -> Result<Self, ExecutionError> {
        Ok(Self {
            file: platform_open_workspace_root(path)?,
        })
    }

    pub fn ensure_original(&self, path: &Path) -> Result<(), ExecutionError> {
        platform_ensure_original_workspace_root(&self.file, path)
    }
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

pub fn is_link_or_reparse_point(metadata: &std::fs::Metadata) -> bool {
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

/// Flushes the directory durability boundary used by executor-owned spools.
///
/// Callers that create additional replay-critical files must flush their
/// containing directory before committing a reference to durable state.
pub fn sync_directory(path: &Path) -> Result<(), io::Error> {
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

#[cfg(test)]
mod tests {
    use super::redact_to_fixed_point;

    #[test]
    fn redaction_removes_matches_exposed_by_prior_deletions() {
        assert_eq!(
            redact_to_fixed_point(b"abc", &[b"b".to_vec(), b"ac".to_vec()]).unwrap(),
            b""
        );
    }
}
