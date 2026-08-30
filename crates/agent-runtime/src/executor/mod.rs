//! Cross-platform process execution with bounded workspaces and durable logs.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::{JournalError, SpoolEntry, validate_relative_path};

mod cleanup;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

pub use cleanup::{flush_terminal_cleanup, remove_terminal_relative_path};

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
    redactions: Vec<Vec<u8>>,
}

struct CapturedOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exceeded: bool,
}

impl OutputCapture {
    fn start(stdout: File, stderr: File, limit: u64, redactions: &[Vec<u8>]) -> Self {
        let limit_exceeded = CancellationToken::new();
        let overlap = redactions
            .iter()
            .map(|secret| secret.len().saturating_sub(1))
            .filter_map(|length| u64::try_from(length).ok())
            .fold(0_u64, u64::saturating_add);
        // Each pipe owns an independent provisional suffix. A noisy stderr
        // stream must not consume the overlap needed to finish redacting a
        // credential prefix already captured on stdout, or vice versa.
        let provisional_limit = limit.saturating_add(overlap);
        Self {
            stdout: Some(tokio::spawn(capture_pipe(
                stdout,
                provisional_limit,
                redactions.to_vec(),
                limit_exceeded.clone(),
            ))),
            stderr: Some(tokio::spawn(capture_pipe(
                stderr,
                provisional_limit,
                redactions.to_vec(),
                limit_exceeded.clone(),
            ))),
            limit_exceeded,
            limit,
            redactions: redactions.to_vec(),
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
        let (stdout, stderr) =
            bound_redacted_output(&stdout, &stderr, self.limit, &self.redactions)?;
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
            captured.push(*byte);
            while let Some(secret) = secrets.iter().find(|secret| captured.ends_with(secret)) {
                captured.truncate(captured.len() - secret.len());
            }
            if u64::try_from(captured.len()).expect("captured length fits u64") > provisional_limit
            {
                limit_exceeded.cancel();
                return Ok(captured);
            }
        }
    }
}

fn bound_redacted_output(
    stdout: &[u8],
    stderr: &[u8],
    limit: u64,
    redactions: &[Vec<u8>],
) -> Result<(Vec<u8>, Vec<u8>), ExecutionError> {
    let mut stdout = redact_to_fixed_point(stdout, redactions)?;
    let mut stderr = redact_to_fixed_point(stderr, redactions)?;
    let stdout_limit = usize::try_from(limit).unwrap_or(usize::MAX);
    stdout.truncate(stdout_limit);
    strip_partial_secret_suffixes(&mut stdout, redactions);
    let remaining = limit.saturating_sub(
        u64::try_from(stdout.len()).expect("bounded captured stdout length fits u64"),
    );
    stderr.truncate(usize::try_from(remaining).unwrap_or(usize::MAX));
    strip_partial_secret_suffixes(&mut stderr, redactions);
    Ok((stdout, stderr))
}

fn strip_partial_secret_suffixes(output: &mut Vec<u8>, redactions: &[Vec<u8>]) {
    loop {
        let mut removed = false;
        for secret in redactions.iter().filter(|secret| !secret.is_empty()) {
            let maximum = output.len().min(secret.len().saturating_sub(1));
            if let Some(length) = (1..=maximum)
                .rev()
                .find(|length| output.ends_with(&secret[..*length]))
            {
                output.truncate(output.len() - length);
                removed = true;
                break;
            }
        }
        if !removed {
            return;
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
    let mut changed_parents = Vec::new();
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
            }
            Err(error) => return Err(error.into()),
        }
        // The parent is flushed whether this walk created the component or
        // found one left by a predecessor that failed before its own flush:
        // existence does not prove a durable entry.
        changed_parents.push(
            current
                .parent()
                .ok_or(ExecutionError::InvalidWorkspaceRoot)?
                .to_owned(),
        );
    }
    // Each directory entry on the chain gets a parent-directory flush before
    // the workspace is used; the parents are independent entries with no
    // ordering requirement among themselves, so they flush as one batch.
    sync_directories(&changed_parents)?;

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

/// Flushes independent durability boundaries — plain files and directory
/// entries — concurrently, returning only when every one is durable.
///
/// The entries in one batch have no ordering requirement among themselves:
/// every caller's actual requirement is a barrier, everything here durable
/// before the caller commits (or acknowledges) a journal record that
/// references it, and that barrier is this function's return. On a
/// journaling filesystem the overlapping flushes coalesce into shared
/// filesystem-journal commits, so a batch costs roughly one flush rather
/// than one per entry serialized.
pub fn sync_boundaries(files: &[&std::fs::File], directories: &[PathBuf]) -> io::Result<()> {
    if files.len() + directories.len() <= 1 {
        for file in files {
            file.sync_all()?;
        }
        for directory in directories {
            sync_directory(directory)?;
        }
        return Ok(());
    }
    std::thread::scope(|scope| {
        let mut flushes = Vec::with_capacity(files.len() + directories.len());
        for file in files {
            flushes.push(scope.spawn(move || file.sync_all()));
        }
        for directory in directories {
            flushes.push(scope.spawn(move || sync_directory(directory)));
        }
        for flush in flushes {
            flush
                .join()
                .map_err(|_| io::Error::other("durability flush thread panicked"))??;
        }
        Ok(())
    })
}

/// Flushes independent directory entries as one concurrent batch.
pub fn sync_directories(directories: &[PathBuf]) -> io::Result<()> {
    sync_boundaries(&[], directories)
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
    use super::{bound_redacted_output, redact_to_fixed_point};

    #[test]
    fn redaction_removes_matches_exposed_by_prior_deletions() {
        assert_eq!(
            redact_to_fixed_point(b"abc", &[b"b".to_vec(), b"ac".to_vec()]).unwrap(),
            b""
        );
    }

    #[test]
    fn bounded_streams_never_retain_a_partial_secret_suffix() {
        let secret = b"credential".to_vec();
        let (stdout, stderr) =
            bound_redacted_output(b"safe-cred", b"1234567890123456", 16, &[secret])
                .expect("bound redacted streams");
        assert_eq!(stdout, b"safe-");
        assert_eq!(stderr, b"12345678901");
        assert_eq!(stdout.len() + stderr.len(), 16);
    }
}
