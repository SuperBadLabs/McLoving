//! Unix process-group execution.

use std::fs::File;
use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};
use std::path::{Component, Path};
use std::process::Stdio;
use std::time::Duration;

use nix::errno::Errno;
use nix::sys::signal::{Signal, killpg};
#[cfg(target_os = "linux")]
use nix::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid};
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
    let workspace_root_control = open_workspace_root(&request.workspace_root)?;
    ensure_original_workspace_root(&workspace_root_control, &request.workspace_root)?;

    let workspace = create_workspace(&request.workspace_root, &request.workspace)?;
    let spool = workspace.join("spool");
    tokio::fs::create_dir(&spool).await?;
    // Keep handles to every agent-owned directory before untrusted code starts.
    // A workload runs as the agent OS user and can revoke pathname traversal;
    // retained handles let the agent restore the minimum owner access only
    // after containment has been proven empty.
    let directory_controls =
        retain_workspace_directory_chain(&request.workspace_root, &request.workspace, &spool)?;

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
    // Pin the configured root itself, not merely a canonical path derived from
    // it. A sibling workload running as the same OS account may rename it.
    ensure_original_workspace_root(&workspace_root_control, &request.workspace_root)?;

    let mut command = Command::new(&request.program);
    command
        .args(&request.arguments)
        .env_clear()
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .env("LANG", "C.UTF-8")
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
        terminate_and_prove_group_empty(
            &mut child,
            process_id,
            process_group_id,
            request.termination_grace,
        )
        .await?;
        return Err(error);
    }

    let deadline = Instant::now() + request.timeout;
    let mut termination = tokio::select! {
        status = wait_for_leader_exit_and_cleanup(
            &mut child,
            process_id,
            process_group_id,
            request.termination_grace,
        ) => match status {
            Ok(status) => (Termination::Exited, status),
            Err(error) => return Err(error),
        },
        () = cancellation.cancelled() => {
            let status = terminate_and_prove_group_empty(
                &mut child,
                process_id,
                process_group_id,
                request.termination_grace,
            )
            .await?;
            (Termination::Cancelled, status)
        }
        () = sleep_until(deadline) => {
            let status = terminate_and_prove_group_empty(
                &mut child,
                process_id,
                process_group_id,
                request.termination_grace,
            )
            .await?;
            (Termination::TimedOut, status)
        }
        result = wait_for_output_limit(
            &stdout_control,
            &stderr_control,
            request.output_limit_bytes,
        ) => {
            if let Err(error) = result {
                terminate_and_prove_group_empty(
                    &mut child,
                    process_id,
                    process_group_id,
                    request.termination_grace,
                )
                .await?;
                return Err(error.into());
            }
            let status = terminate_and_prove_group_empty(
                &mut child,
                process_id,
                process_group_id,
                request.termination_grace,
            )
            .await?;
            (Termination::OutputLimitExceeded, status)
        }
    };

    let exceeded =
        output_limit_exceeded(&stdout_control, &stderr_control, request.output_limit_bytes)?;
    if termination.0 == Termination::Exited && exceeded {
        termination.0 = Termination::OutputLimitExceeded;
    }
    if termination.0 == Termination::OutputLimitExceeded || exceeded {
        truncate_output_to_limit(&stdout_control, &stderr_control, request.output_limit_bytes)?;
    }
    for directory in &directory_controls {
        restore_agent_permissions(directory, 0o700)?;
    }
    restore_agent_spool_permissions(&stdout_control)?;
    restore_agent_spool_permissions(&stderr_control)?;
    ensure_original_workspace_root(&workspace_root_control, &request.workspace_root)?;
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

fn restore_agent_spool_permissions(file: &File) -> Result<(), std::io::Error> {
    restore_agent_permissions(file, 0o600)
}

fn restore_agent_permissions(file: &File, required_mode: u32) -> Result<(), std::io::Error> {
    let metadata = file.metadata()?;
    let mut permissions = metadata.permissions();
    permissions.set_mode(permissions.mode() | required_mode);
    file.set_permissions(permissions)
}

fn retain_workspace_directory_chain(
    workspace_root: &Path,
    workspace: &Path,
    spool: &Path,
) -> Result<Vec<File>, std::io::Error> {
    let mut controls = vec![File::open(workspace_root)?];
    let mut current = workspace_root.to_owned();
    for component in workspace.components() {
        let Component::Normal(component) = component else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "workspace directory chain must be normalized and relative",
            ));
        };
        current.push(component);
        controls.push(File::open(&current)?);
    }
    controls.push(File::open(spool)?);
    Ok(controls)
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

pub(super) fn open_workspace_root(path: &Path) -> Result<File, ExecutionError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| ExecutionError::InvalidWorkspaceRoot)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(ExecutionError::InvalidWorkspaceRoot);
    }
    File::open(path).map_err(ExecutionError::Io)
}

pub(super) fn ensure_original_workspace_root(
    file: &File,
    path: &Path,
) -> Result<(), ExecutionError> {
    let named_link =
        std::fs::symlink_metadata(path).map_err(|_| ExecutionError::ReplacedWorkspaceRoot)?;
    if !named_link.is_dir() || named_link.file_type().is_symlink() {
        return Err(ExecutionError::ReplacedWorkspaceRoot);
    }
    let opened = file
        .metadata()
        .map_err(|_| ExecutionError::ReplacedWorkspaceRoot)?;
    let named = std::fs::metadata(path).map_err(|_| ExecutionError::ReplacedWorkspaceRoot)?;
    if opened.dev() == named.dev() && opened.ino() == named.ino() {
        Ok(())
    } else {
        Err(ExecutionError::ReplacedWorkspaceRoot)
    }
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

async fn wait_for_leader_exit_and_cleanup(
    child: &mut Child,
    process_id: u32,
    process_group_id: i32,
    grace: Duration,
) -> Result<std::process::ExitStatus, ExecutionError> {
    #[cfg(target_os = "linux")]
    {
        if let Err(error) = wait_for_unreaped_leader_exit(process_id).await {
            signal_group(process_group_id, Signal::SIGKILL)?;
            let containment =
                wait_for_anchored_descendants_to_exit(process_id, process_group_id).await;
            child.wait().await?;
            containment.map_err(|cleanup| containment_unverified(process_id, cleanup))?;
            return Err(containment_unverified(process_id, error));
        }
        let containment =
            terminate_descendants_while_leader_anchors_group(process_id, process_group_id, grace)
                .await;
        // Reap only after no descendants remain. Until this wait, the zombie
        // leader keeps its numeric PID/PGID unavailable for reuse.
        let status = child.wait().await?;
        containment.map_err(|error| containment_unverified(process_id, error))?;
        Ok(status)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let status = child.wait().await?;
        terminate_remaining_group(process_group_id, grace)
            .await
            .map_err(|error| containment_unverified(process_id, error))?;
        Ok(status)
    }
}

#[cfg(not(target_os = "linux"))]
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

async fn terminate_and_prove_group_empty(
    child: &mut Child,
    process_id: u32,
    process_group_id: i32,
    grace: Duration,
) -> Result<std::process::ExitStatus, ExecutionError> {
    #[cfg(target_os = "linux")]
    {
        signal_group(process_group_id, Signal::SIGTERM)?;
        sleep(grace).await;
        if !leader_exited_without_reaping(process_id)?
            || group_has_members_other_than(process_group_id, process_id)?
        {
            signal_group(process_group_id, Signal::SIGKILL)?;
        }
        wait_for_unreaped_leader_exit_bounded(process_id, Duration::from_secs(5)).await?;
        let containment = wait_for_anchored_descendants_to_exit(process_id, process_group_id).await;
        let status = child.wait().await?;
        containment.map_err(|error| containment_unverified(process_id, error))?;
        Ok(status)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let leader_result = terminate_group(child, process_group_id, grace).await;
        let containment_result = terminate_remaining_group(process_group_id, grace).await;
        if let Err(error) = containment_result {
            return Err(containment_unverified(process_id, error));
        }
        leader_result
    }
}

fn containment_unverified(process_id: u32, error: ExecutionError) -> ExecutionError {
    ExecutionError::ContainmentUnverified {
        process_id,
        reason: error.to_string(),
    }
}

#[cfg(not(target_os = "linux"))]
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

#[cfg(target_os = "linux")]
async fn terminate_descendants_while_leader_anchors_group(
    process_id: u32,
    process_group_id: i32,
    grace: Duration,
) -> Result<(), ExecutionError> {
    if !group_has_members_other_than(process_group_id, process_id)? {
        return Ok(());
    }
    signal_group(process_group_id, Signal::SIGTERM)?;
    sleep(grace).await;
    if group_has_members_other_than(process_group_id, process_id)? {
        signal_group(process_group_id, Signal::SIGKILL)?;
    }
    wait_for_anchored_descendants_to_exit(process_id, process_group_id).await
}

#[cfg(target_os = "linux")]
async fn wait_for_anchored_descendants_to_exit(
    process_id: u32,
    process_group_id: i32,
) -> Result<(), ExecutionError> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while group_has_members_other_than(process_group_id, process_id)? {
        if Instant::now() >= deadline {
            return Err(ExecutionError::Io(std::io::Error::other(
                "terminated process group retained descendants for five seconds",
            )));
        }
        sleep(Duration::from_millis(10)).await;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn wait_for_unreaped_leader_exit(process_id: u32) -> Result<(), ExecutionError> {
    loop {
        if leader_exited_without_reaping(process_id)? {
            return Ok(());
        }
        sleep(Duration::from_millis(10)).await;
    }
}

#[cfg(target_os = "linux")]
async fn wait_for_unreaped_leader_exit_bounded(
    process_id: u32,
    timeout: Duration,
) -> Result<(), ExecutionError> {
    tokio::time::timeout(timeout, wait_for_unreaped_leader_exit(process_id))
        .await
        .map_err(|_| {
            ExecutionError::Io(std::io::Error::other(
                "process-group leader did not exit within the bounded termination wait",
            ))
        })?
}

#[cfg(target_os = "linux")]
fn leader_exited_without_reaping(process_id: u32) -> Result<bool, ExecutionError> {
    let process_id = i32::try_from(process_id).map_err(|_| ExecutionError::MissingProcessId)?;
    let status = waitid(
        Id::Pid(Pid::from_raw(process_id)),
        WaitPidFlag::WEXITED | WaitPidFlag::WNOWAIT | WaitPidFlag::WNOHANG,
    )?;
    Ok(matches!(
        status,
        WaitStatus::Exited(..) | WaitStatus::Signaled(..)
    ))
}

#[cfg(target_os = "linux")]
fn group_has_members_other_than(
    process_group_id: i32,
    process_id: u32,
) -> Result<bool, ExecutionError> {
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(candidate) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        if candidate == process_id {
            continue;
        }
        let stat = match std::fs::read_to_string(entry.path().join("stat")) {
            Ok(stat) => stat,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let Some((_, suffix)) = stat.rsplit_once(") ") else {
            continue;
        };
        let Some(group) = suffix
            .split_ascii_whitespace()
            .nth(2)
            .and_then(|value| value.parse::<i32>().ok())
        else {
            continue;
        };
        if group == process_group_id {
            return Ok(true);
        }
    }
    Ok(false)
}

fn signal_group(process_group_id: i32, signal: Signal) -> Result<(), ExecutionError> {
    match killpg(Pid::from_raw(process_group_id), signal) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(not(target_os = "linux"))]
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

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn normal_execution_is_not_capped_by_the_containment_wait() {
        let root = tempfile::tempdir().unwrap();
        let request = ExecutionRequest {
            workspace_root: root.path().to_owned(),
            workspace: PathBuf::from("org/long-running-success"),
            mode: ExecutionMode::Direct,
            program: PathBuf::from("/bin/sh"),
            arguments: vec![
                OsString::from("-c"),
                OsString::from("sleep 6; printf completed"),
            ],
            environment: BTreeMap::new(),
            output_limit_bytes: None,
            timeout: Duration::from_secs(10),
            termination_grace: Duration::from_millis(100),
        };

        let outcome = execute(&request, CancellationToken::new()).await.unwrap();
        assert_eq!(outcome.termination, Termination::Exited);
        assert_eq!(outcome.exit_code, Some(0));
        assert_eq!(
            fs::read(root.path().join(outcome.stdout.relative_path))
                .await
                .unwrap(),
            b"completed"
        );
    }

    #[tokio::test]
    async fn workload_cannot_revoke_agent_access_to_log_spools() {
        let root = tempfile::tempdir().unwrap();
        let request = ExecutionRequest {
            workspace_root: root.path().to_owned(),
            workspace: PathBuf::from("org/revoked-spool-mode"),
            mode: ExecutionMode::Direct,
            program: PathBuf::from("/bin/sh"),
            arguments: vec![
                OsString::from("-c"),
                OsString::from(
                    "printf retained; chmod 000 spool/stdout.log spool/stderr.log spool .",
                ),
            ],
            environment: BTreeMap::new(),
            output_limit_bytes: None,
            timeout: Duration::from_secs(5),
            termination_grace: Duration::from_millis(100),
        };

        let outcome = execute(&request, CancellationToken::new()).await.unwrap();
        assert_eq!(
            fs::read(root.path().join(outcome.stdout.relative_path))
                .await
                .unwrap(),
            b"retained"
        );
    }

    #[tokio::test]
    async fn workload_environment_is_allowlisted_and_explicit() {
        assert!(std::env::var_os("HOME").is_some());
        let root = tempfile::tempdir().unwrap();
        let request = ExecutionRequest {
            workspace_root: root.path().to_owned(),
            workspace: PathBuf::from("org/environment"),
            mode: ExecutionMode::Direct,
            program: PathBuf::from("/bin/sh"),
            arguments: vec![
                OsString::from("-c"),
                OsString::from(
                    "test -z \"${HOME+x}\" && test \"$EXPLICIT_VALUE\" = allowed && printf clean",
                ),
            ],
            environment: BTreeMap::from([(
                OsString::from("EXPLICIT_VALUE"),
                OsString::from("allowed"),
            )]),
            output_limit_bytes: None,
            timeout: Duration::from_secs(5),
            termination_grace: Duration::from_millis(100),
        };

        let outcome = execute(&request, CancellationToken::new()).await.unwrap();
        assert_eq!(outcome.exit_code, Some(0));
        assert_eq!(
            fs::read(root.path().join(outcome.stdout.relative_path))
                .await
                .unwrap(),
            b"clean"
        );
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

    #[tokio::test]
    async fn replaced_workspace_root_is_rejected_without_following_the_replacement() {
        let parent = tempfile::tempdir().unwrap();
        let workspace_root = parent.path().join("workspace");
        let displaced_root = parent.path().join("displaced-workspace");
        let outside = parent.path().join("outside");
        std::fs::create_dir(&workspace_root).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("sentinel"), "outside").unwrap();

        let request = ExecutionRequest {
            workspace_root: workspace_root.clone(),
            workspace: PathBuf::from("org/replaced-root"),
            mode: ExecutionMode::Direct,
            program: PathBuf::from("/bin/sh"),
            arguments: vec![
                OsString::from("-c"),
                OsString::from(
                    "mv \"$WORKSPACE_ROOT\" \"$DISPLACED_ROOT\"; \
                     ln -s \"$OUTSIDE\" \"$WORKSPACE_ROOT\"",
                ),
            ],
            environment: BTreeMap::from([
                (
                    OsString::from("WORKSPACE_ROOT"),
                    workspace_root.as_os_str().to_owned(),
                ),
                (
                    OsString::from("DISPLACED_ROOT"),
                    displaced_root.as_os_str().to_owned(),
                ),
                (OsString::from("OUTSIDE"), outside.as_os_str().to_owned()),
            ]),
            output_limit_bytes: None,
            timeout: Duration::from_secs(5),
            termination_grace: Duration::from_millis(100),
        };

        assert!(matches!(
            execute(&request, CancellationToken::new()).await,
            Err(ExecutionError::ReplacedWorkspaceRoot)
        ));
        assert_eq!(
            std::fs::read_to_string(outside.join("sentinel")).unwrap(),
            "outside"
        );
        assert!(displaced_root.join("org/replaced-root/spool").is_dir());
    }
}
