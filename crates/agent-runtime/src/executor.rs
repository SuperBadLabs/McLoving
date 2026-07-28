//! Unix process-group execution with bounded workspaces and durable logs.

use std::ffi::OsString;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use nix::errno::Errno;
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::fs;
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use tokio::time::{Instant, sleep_until};
use tokio_util::sync::CancellationToken;

use crate::{JournalError, SpoolEntry, validate_relative_path};

#[derive(Clone, Debug)]
pub struct ExecutionRequest {
    pub workspace_root: PathBuf,
    pub workspace: PathBuf,
    pub program: PathBuf,
    pub arguments: Vec<OsString>,
    pub timeout: Duration,
    pub termination_grace: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Termination {
    Exited,
    TimedOut,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionOutcome {
    pub termination: Termination,
    pub exit_code: Option<i32>,
    pub process_group_id: i32,
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
    #[error("workspace contains a symlink component")]
    SymlinkWorkspaceComponent,
    #[error("process did not expose a valid process ID")]
    MissingProcessId,
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("signal error: {0}")]
    Signal(#[from] Errno),
}

/// Executes one process in a new process group.
///
/// Timeout and cancellation signal the whole group, first with `SIGTERM` and
/// then with `SIGKILL` after the configured grace period. Standard streams are
/// fsynced and hashed before the result is returned.
pub async fn execute(
    request: &ExecutionRequest,
    cancellation: CancellationToken,
) -> Result<ExecutionOutcome, ExecutionError> {
    validate_relative_path(&request.workspace)?;
    let workspace = create_workspace(&request.workspace_root, &request.workspace)?;
    let spool = workspace.join("spool");
    fs::create_dir(&spool).await?;

    let stdout_path = spool.join("stdout.log");
    let stderr_path = spool.join("stderr.log");
    let stdout = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&stdout_path)?;
    let stderr = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&stderr_path)?;

    let mut command = Command::new(&request.program);
    command
        .args(&request.arguments)
        .current_dir(&workspace)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .process_group(0);
    let mut child = command.spawn()?;
    let process_group_id = i32::try_from(child.id().ok_or(ExecutionError::MissingProcessId)?)
        .map_err(|_| ExecutionError::MissingProcessId)?;

    let deadline = Instant::now() + request.timeout;
    let termination = tokio::select! {
        status = child.wait() => (Termination::Exited, status?),
        () = cancellation.cancelled() => {
            let status = terminate_group(&mut child, process_group_id, request.termination_grace)
                .await?;
            (Termination::Cancelled, status)
        }
        () = sleep_until(deadline) => {
            let status = terminate_group(&mut child, process_group_id, request.termination_grace)
                .await?;
            (Termination::TimedOut, status)
        }
    };

    sync_file(&stdout_path).await?;
    sync_file(&stderr_path).await?;
    sync_directory(&spool)?;
    sync_directory(&workspace)?;

    Ok(ExecutionOutcome {
        termination: termination.0,
        exit_code: termination.1.code(),
        process_group_id,
        stdout: spool_entry(&request.workspace, "spool/stdout.log", 0, &stdout_path).await?,
        stderr: spool_entry(&request.workspace, "spool/stderr.log", 1, &stderr_path).await?,
    })
}

fn create_workspace(root: &Path, relative: &Path) -> Result<PathBuf, ExecutionError> {
    let root = root
        .canonicalize()
        .map_err(|_| ExecutionError::InvalidWorkspaceRoot)?;
    if !root.is_dir() {
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
            Ok(metadata) if metadata.file_type().is_symlink() => {
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

async fn terminate_group(
    child: &mut Child,
    process_group_id: i32,
    grace: Duration,
) -> Result<std::process::ExitStatus, ExecutionError> {
    signal_group(process_group_id, Signal::SIGTERM)?;
    let deadline = Instant::now() + grace;
    let leader_status = tokio::select! {
        status = child.wait() => Some(status?),
        () = sleep_until(deadline) => {
            signal_group(process_group_id, Signal::SIGKILL)?;
            None
        }
    };

    if let Some(status) = leader_status {
        if process_group_exists(process_group_id)? {
            sleep_until(deadline).await;
            signal_group(process_group_id, Signal::SIGKILL)?;
        }
        Ok(status)
    } else {
        Ok(child.wait().await?)
    }
}

fn signal_group(process_group_id: i32, signal: Signal) -> Result<(), ExecutionError> {
    match killpg(Pid::from_raw(process_group_id), signal) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn process_group_exists(process_group_id: i32) -> Result<bool, ExecutionError> {
    match killpg(Pid::from_raw(process_group_id), None) {
        Ok(()) | Err(Errno::EPERM) => Ok(true),
        Err(Errno::ESRCH) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

async fn sync_file(path: &Path) -> Result<(), io::Error> {
    fs::OpenOptions::new()
        .read(true)
        .open(path)
        .await?
        .sync_all()
        .await
}

fn sync_directory(path: &Path) -> Result<(), io::Error> {
    std::fs::File::open(path)?.sync_all()
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

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::signal::kill;

    async fn descendant_pid(path: &Path) -> i32 {
        for _ in 0..100 {
            if let Ok(value) = fs::read_to_string(path).await
                && let Ok(pid) = value.trim().parse()
            {
                return pid;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("descendant PID was not written");
    }

    async fn assert_process_gone(pid: i32) {
        for _ in 0..100 {
            #[cfg(target_os = "linux")]
            {
                let status_path = PathBuf::from(format!("/proc/{pid}/stat"));
                match fs::read_to_string(status_path).await {
                    Ok(status) if process_state(&status) == Some('Z') => return,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => return,
                    Ok(_) => {}
                    Err(error) => panic!("unexpected process status error: {error}"),
                }
            }
            match kill(Pid::from_raw(pid), None) {
                Err(Errno::ESRCH) => return,
                Ok(()) | Err(Errno::EPERM) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => panic!("unexpected process probe error: {error}"),
            }
        }
        panic!("descendant process {pid} escaped cleanup");
    }

    #[cfg(target_os = "linux")]
    fn process_state(stat: &str) -> Option<char> {
        stat.rsplit_once(") ")?.1.chars().next()
    }

    fn request(root: &Path, workspace: &str, timeout: Duration) -> ExecutionRequest {
        ExecutionRequest {
            workspace_root: root.to_owned(),
            workspace: PathBuf::from(workspace),
            program: PathBuf::from("/bin/sh"),
            arguments: vec![
                OsString::from("-c"),
                OsString::from("sleep 30 & child=$!; printf '%s\\n' \"$child\" > child.pid; wait"),
            ],
            timeout,
            termination_grace: Duration::from_millis(100),
        }
    }

    fn resistant_request(root: &Path, workspace: &str) -> ExecutionRequest {
        ExecutionRequest {
            workspace_root: root.to_owned(),
            workspace: PathBuf::from(workspace),
            program: PathBuf::from("/bin/sh"),
            arguments: vec![
                OsString::from("-c"),
                OsString::from(
                    "trap 'exit 0' TERM; sh -c 'trap \"\" TERM; printf \"%s\\n\" \"$$\" > resistant.pid; exec sleep 30' & wait",
                ),
            ],
            timeout: Duration::from_secs(30),
            termination_grace: Duration::from_millis(100),
        }
    }

    #[tokio::test]
    async fn timeout_kills_descendants_and_returns_durable_logs() {
        let root = tempfile::tempdir().unwrap();
        let request = request(root.path(), "org/timeout", Duration::from_millis(200));
        let child_pid_path = root.path().join("org/timeout/child.pid");
        let outcome = execute(&request, CancellationToken::new()).await.unwrap();
        let pid = descendant_pid(&child_pid_path).await;

        assert_eq!(outcome.termination, Termination::TimedOut);
        assert_process_gone(pid).await;
        assert_eq!(
            outcome.stdout.relative_path,
            PathBuf::from("org/timeout/spool/stdout.log")
        );
        assert!(root.path().join(outcome.stdout.relative_path).is_file());
    }

    #[tokio::test]
    async fn cancellation_kills_descendants_without_waiting_for_timeout() {
        let root = tempfile::tempdir().unwrap();
        let request = request(root.path(), "org/cancel", Duration::from_secs(30));
        let child_pid_path = root.path().join("org/cancel/child.pid");
        let cancellation = CancellationToken::new();
        let task_cancellation = cancellation.clone();

        let execution = tokio::spawn(async move { execute(&request, task_cancellation).await });
        let pid = descendant_pid(&child_pid_path).await;
        cancellation.cancel();
        let outcome = execution.await.unwrap().unwrap();

        assert_eq!(outcome.termination, Termination::Cancelled);
        assert_process_gone(pid).await;
    }

    #[tokio::test]
    async fn cancellation_escalates_when_leader_exits_but_descendant_ignores_term() {
        let root = tempfile::tempdir().unwrap();
        let request = resistant_request(root.path(), "org/resistant");
        let descendant_path = root.path().join("org/resistant/resistant.pid");
        let cancellation = CancellationToken::new();
        let task_cancellation = cancellation.clone();

        let execution = tokio::spawn(async move { execute(&request, task_cancellation).await });
        let pid = descendant_pid(&descendant_path).await;
        cancellation.cancel();
        let outcome = execution.await.unwrap().unwrap();

        assert_eq!(outcome.termination, Termination::Cancelled);
        assert_process_gone(pid).await;
    }

    #[tokio::test]
    async fn successful_exit_preserves_output_and_digest() {
        let root = tempfile::tempdir().unwrap();
        let request = ExecutionRequest {
            workspace_root: root.path().to_owned(),
            workspace: PathBuf::from("org/success"),
            program: PathBuf::from("/bin/sh"),
            arguments: vec![OsString::from("-c"), OsString::from("printf mcloving")],
            timeout: Duration::from_secs(5),
            termination_grace: Duration::from_millis(100),
        };

        let outcome = execute(&request, CancellationToken::new()).await.unwrap();
        assert_eq!(outcome.termination, Termination::Exited);
        assert_eq!(outcome.exit_code, Some(0));
        assert_eq!(outcome.stdout.bytes, 8);
        let expected_digest: [u8; 32] = Sha256::digest(b"mcloving").into();
        assert_eq!(outcome.stdout.digest, expected_digest);
    }

    #[tokio::test]
    async fn existing_or_symlinked_workspace_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("existing")).unwrap();
        let existing = ExecutionRequest {
            workspace_root: root.path().to_owned(),
            workspace: PathBuf::from("existing"),
            program: PathBuf::from("/bin/true"),
            arguments: Vec::new(),
            timeout: Duration::from_secs(1),
            termination_grace: Duration::from_millis(10),
        };
        assert!(matches!(
            execute(&existing, CancellationToken::new()).await,
            Err(ExecutionError::WorkspaceAlreadyExists)
        ));

        std::os::unix::fs::symlink("/tmp", root.path().join("linked")).unwrap();
        let linked = ExecutionRequest {
            workspace: PathBuf::from("linked/escape"),
            ..existing
        };
        assert!(matches!(
            execute(&linked, CancellationToken::new()).await,
            Err(ExecutionError::SymlinkWorkspaceComponent)
        ));
    }
}
