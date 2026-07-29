//! Unix process-group execution.

use std::fs::File;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use nix::errno::Errno;
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use sha2::{Digest, Sha256};
use tokio::process::{Child, Command};
use tokio::time::{Instant, sleep, sleep_until};
use tokio_util::sync::CancellationToken;

use crate::SpoolEntry;

use super::{
    Containment, ExecutionError, ExecutionMode, ExecutionOutcome, ExecutionRequest, Termination,
    create_workspace, sync_directory,
};

/// Executes one process in a new process group.
///
/// Timeout and cancellation signal the whole group, first with `SIGTERM` and
/// then with `SIGKILL` after the configured grace period. Standard streams are
/// fsynced and hashed before the result is returned.
pub async fn execute(
    request: &ExecutionRequest,
    cancellation: CancellationToken,
) -> Result<ExecutionOutcome, ExecutionError> {
    execute_with_spawn_hook(request, cancellation, |_| Ok(())).await
}

/// Executes one process and durably exposes its process-group identity before
/// waiting for any terminal outcome.
pub async fn execute_with_spawn_hook<F>(
    request: &ExecutionRequest,
    cancellation: CancellationToken,
    on_spawn: F,
) -> Result<ExecutionOutcome, ExecutionError>
where
    F: FnOnce(u32) -> Result<(), ExecutionError>,
{
    if request.mode != ExecutionMode::Direct {
        return Err(ExecutionError::UnsupportedMode(request.mode));
    }
    let workspace = create_workspace(&request.workspace_root, &request.workspace)?;
    let spool = workspace.join("spool");
    tokio::fs::create_dir(&spool).await?;

    let stdout_path = spool.join("stdout.log");
    let stderr_path = spool.join("stderr.log");
    let stdout = std::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&stdout_path)?;
    let stderr = std::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&stderr_path)?;
    // The workload may rename or unlink its visible spool paths. Retain
    // independent handles to the exact files created by the executor so quota,
    // truncation, durability, and digest decisions cannot be redirected.
    let stdout_control = stdout.try_clone()?;
    let stderr_control = stderr.try_clone()?;

    let mut command = Command::new(&request.program);
    command
        .args(&request.arguments)
        .envs(&request.environment)
        .current_dir(&workspace)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .process_group(0);
    let mut child = command.spawn()?;
    let process_id = child.id().ok_or(ExecutionError::MissingProcessId)?;
    let process_group_id =
        i32::try_from(process_id).map_err(|_| ExecutionError::MissingProcessId)?;
    if let Err(error) = on_spawn(process_id) {
        terminate_group(&mut child, process_group_id, request.termination_grace).await?;
        return Err(error);
    }

    let deadline = Instant::now() + request.timeout;
    let mut termination = tokio::select! {
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
        result = wait_for_output_limit(
            &stdout_control,
            &stderr_control,
            request.output_limit_bytes,
        ) => {
            if let Err(error) = result {
                terminate_group(&mut child, process_group_id, request.termination_grace).await?;
                terminate_remaining_group(process_group_id, request.termination_grace).await?;
                return Err(error.into());
            }
            let status =
                terminate_group(&mut child, process_group_id, request.termination_grace).await?;
            (Termination::OutputLimitExceeded, status)
        }
    };

    terminate_remaining_group(process_group_id, request.termination_grace).await?;
    let exceeded =
        output_limit_exceeded(&stdout_control, &stderr_control, request.output_limit_bytes)?;
    if termination.0 == Termination::Exited && exceeded {
        termination.0 = Termination::OutputLimitExceeded;
    }
    if termination.0 == Termination::OutputLimitExceeded || exceeded {
        truncate_output_to_limit(&stdout_control, &stderr_control, request.output_limit_bytes)?;
    }
    stdout_control.sync_all()?;
    stderr_control.sync_all()?;
    ensure_original_spool_path(&stdout_control, &stdout_path)?;
    ensure_original_spool_path(&stderr_control, &stderr_path)?;
    sync_directory(&spool)?;
    sync_directory(&workspace)?;

    Ok(ExecutionOutcome {
        termination: termination.0,
        exit_code: termination.1.code(),
        process_id,
        containment: Containment::UnixProcessGroup,
        stdout: spool_entry(&request.workspace, "spool/stdout.log", 0, &stdout_control).await?,
        stderr: spool_entry(&request.workspace, "spool/stderr.log", 1, &stderr_control).await?,
    })
}

fn output_limit_exceeded(
    stdout: &File,
    stderr: &File,
    limit: Option<u64>,
) -> Result<bool, std::io::Error> {
    let Some(limit) = limit else {
        return Ok(false);
    };
    Ok(stdout
        .metadata()?
        .len()
        .saturating_add(stderr.metadata()?.len())
        > limit)
}

async fn wait_for_output_limit(
    stdout: &File,
    stderr: &File,
    limit: Option<u64>,
) -> Result<(), std::io::Error> {
    let Some(limit) = limit else {
        std::future::pending::<()>().await;
        unreachable!();
    };
    loop {
        if output_limit_exceeded(stdout, stderr, Some(limit))? {
            return Ok(());
        }
        sleep(Duration::from_millis(10)).await;
    }
}

fn truncate_output_to_limit(
    stdout: &File,
    stderr: &File,
    limit: Option<u64>,
) -> Result<(), std::io::Error> {
    let Some(limit) = limit else {
        return Ok(());
    };
    let stdout_bytes = stdout.metadata()?.len();
    let stderr_bytes = stderr.metadata()?.len();
    let retained_stdout = stdout_bytes.min(limit);
    let retained_stderr = stderr_bytes.min(limit - retained_stdout);
    stdout.set_len(retained_stdout)?;
    stderr.set_len(retained_stderr)
}

fn ensure_original_spool_path(file: &File, path: &Path) -> Result<(), ExecutionError> {
    let opened = file.metadata()?;
    let named = std::fs::metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            ExecutionError::ReplacedSpoolPath
        } else {
            error.into()
        }
    })?;
    if opened.dev() == named.dev() && opened.ino() == named.ino() {
        Ok(())
    } else {
        Err(ExecutionError::ReplacedSpoolPath)
    }
}

async fn spool_entry(
    workspace: &Path,
    suffix: &str,
    sequence: u64,
    file: &File,
) -> Result<SpoolEntry, ExecutionError> {
    let bytes = file.metadata()?.len();
    let file = file.try_clone()?;
    let digest = tokio::task::spawn_blocking(move || digest_file(&file))
        .await
        .map_err(|error| std::io::Error::other(format!("spool digest task failed: {error}")))??;
    Ok(SpoolEntry {
        sequence,
        relative_path: workspace.join(suffix),
        digest,
        bytes,
    })
}

fn digest_file(file: &File) -> Result<[u8; 32], std::io::Error> {
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut offset = 0_u64;
    loop {
        let read = file.read_at(&mut buffer, offset)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        offset += u64::try_from(read).expect("buffer read length fits in u64");
    }
    Ok(digest.finalize().into())
}

async fn terminate_remaining_group(
    process_group_id: i32,
    grace: Duration,
) -> Result<(), ExecutionError> {
    if !process_group_exists(process_group_id)? {
        return Ok(());
    }
    signal_group(process_group_id, Signal::SIGTERM)?;
    sleep_until(Instant::now() + grace).await;
    if process_group_exists(process_group_id)? {
        signal_group(process_group_id, Signal::SIGKILL)?;
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while process_group_exists(process_group_id)? {
        if Instant::now() >= deadline {
            return Err(ExecutionError::Io(std::io::Error::other(
                "terminated process group remained alive for five seconds",
            )));
        }
        sleep(Duration::from_millis(10)).await;
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::io;
    use std::path::{Path, PathBuf};

    use nix::sys::signal::kill;
    use sha2::{Digest, Sha256};
    use tokio::fs;

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
            mode: ExecutionMode::Direct,
            program: PathBuf::from("/bin/sh"),
            arguments: vec![
                OsString::from("-c"),
                OsString::from("sleep 30 & child=$!; printf '%s\\n' \"$child\" > child.pid; wait"),
            ],
            environment: BTreeMap::new(),
            output_limit_bytes: None,
            timeout,
            termination_grace: Duration::from_millis(100),
        }
    }

    fn resistant_request(root: &Path, workspace: &str) -> ExecutionRequest {
        ExecutionRequest {
            workspace_root: root.to_owned(),
            workspace: PathBuf::from(workspace),
            mode: ExecutionMode::Direct,
            program: PathBuf::from("/bin/sh"),
            arguments: vec![
                OsString::from("-c"),
                OsString::from(
                    "trap 'exit 0' TERM; sh -c 'trap \"\" TERM; printf \"%s\\n\" \"$$\" > resistant.pid; exec sleep 30' & wait",
                ),
            ],
            environment: BTreeMap::new(),
            output_limit_bytes: None,
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
            mode: ExecutionMode::Direct,
            program: PathBuf::from("/bin/sh"),
            arguments: vec![OsString::from("-c"), OsString::from("printf mcloving")],
            environment: BTreeMap::new(),
            output_limit_bytes: None,
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
    async fn successful_leader_exit_stabilizes_inherited_log_handles() {
        let root = tempfile::tempdir().unwrap();
        let request = ExecutionRequest {
            workspace_root: root.path().to_owned(),
            workspace: PathBuf::from("org/inherited-handle"),
            mode: ExecutionMode::Direct,
            program: PathBuf::from("/bin/sh"),
            arguments: vec![
                OsString::from("-c"),
                OsString::from(
                    "sh -c 'printf \"%s\\n\" \"$$\" > child.pid; trap \"\" TERM; \
                     while :; do printf x; done' & while [ ! -s child.pid ]; do :; done; exit 0",
                ),
            ],
            environment: BTreeMap::new(),
            output_limit_bytes: Some(65_536),
            timeout: Duration::from_secs(5),
            termination_grace: Duration::from_millis(50),
        };
        let child_pid_path = root.path().join("org/inherited-handle/child.pid");

        let outcome = execute(&request, CancellationToken::new()).await.unwrap();
        let pid = descendant_pid(&child_pid_path).await;

        assert_process_gone(pid).await;
        assert!(outcome.stdout.bytes + outcome.stderr.bytes <= 65_536);
        let stable_bytes = fs::metadata(root.path().join(&outcome.stdout.relative_path))
            .await
            .unwrap()
            .len();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            fs::metadata(root.path().join(&outcome.stdout.relative_path))
                .await
                .unwrap()
                .len(),
            stable_bytes
        );
    }

    #[tokio::test]
    async fn output_limit_terminates_and_caps_the_durable_spool() {
        let root = tempfile::tempdir().unwrap();
        let request = ExecutionRequest {
            workspace_root: root.path().to_owned(),
            workspace: PathBuf::from("org/quota"),
            mode: ExecutionMode::Direct,
            program: PathBuf::from("/bin/sh"),
            arguments: vec![
                OsString::from("-c"),
                OsString::from("while :; do printf 0123456789abcdef; done"),
            ],
            environment: BTreeMap::new(),
            output_limit_bytes: Some(4_096),
            timeout: Duration::from_secs(30),
            termination_grace: Duration::from_millis(50),
        };

        let outcome = execute(&request, CancellationToken::new()).await.unwrap();
        assert_eq!(outcome.termination, Termination::OutputLimitExceeded);
        assert!(outcome.stdout.bytes + outcome.stderr.bytes <= 4_096);
    }

    #[tokio::test]
    async fn renamed_spool_cannot_evade_the_output_quota() {
        let root = tempfile::tempdir().unwrap();
        let request = ExecutionRequest {
            workspace_root: root.path().to_owned(),
            workspace: PathBuf::from("org/renamed-log"),
            mode: ExecutionMode::Direct,
            program: PathBuf::from("/bin/sh"),
            arguments: vec![
                OsString::from("-c"),
                OsString::from(
                    "printf '%s\\n' \"$$\" > child.pid; \
                     mv spool/stdout.log spool/renamed.log; : > spool/stdout.log; \
                     while :; do printf 0123456789abcdef; done",
                ),
            ],
            environment: BTreeMap::new(),
            output_limit_bytes: Some(4_096),
            timeout: Duration::from_secs(30),
            termination_grace: Duration::from_millis(50),
        };
        let child_pid_path = root.path().join("org/renamed-log/child.pid");

        assert!(matches!(
            execute(&request, CancellationToken::new()).await,
            Err(ExecutionError::ReplacedSpoolPath)
        ));
        let pid = descendant_pid(&child_pid_path).await;
        assert_process_gone(pid).await;
        assert!(
            fs::metadata(root.path().join("org/renamed-log/spool/renamed.log"))
                .await
                .unwrap()
                .len()
                <= 4_096
        );
    }

    #[tokio::test]
    async fn existing_or_symlinked_workspace_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("existing")).unwrap();
        let existing = ExecutionRequest {
            workspace_root: root.path().to_owned(),
            workspace: PathBuf::from("existing"),
            mode: ExecutionMode::Direct,
            program: PathBuf::from("/bin/true"),
            arguments: Vec::new(),
            environment: BTreeMap::new(),
            output_limit_bytes: None,
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
