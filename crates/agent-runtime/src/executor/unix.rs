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
use nix::unistd::{Pid, pipe};
use sha2::{Digest, Sha256};
use tokio::process::{Child, Command};
use tokio::time::{Instant, sleep, sleep_until};
use tokio_util::sync::CancellationToken;

use crate::SpoolEntry;

use super::{
    Containment, ExecutionError, ExecutionMode, ExecutionOutcome, ExecutionRequest, OutputCapture,
    Termination, create_workspace, sync_directory, validate_redactions, write_redacted_output,
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
    execute_with_spawn_hook_and_redactions(request, cancellation, &[], on_spawn).await
}

/// Executes one process while keeping credential-bearing output in bounded
/// memory until exact secret values have been removed.
pub async fn execute_with_spawn_hook_and_redactions<F>(
    request: &ExecutionRequest,
    cancellation: CancellationToken,
    redactions: &[Vec<u8>],
    on_spawn: F,
) -> Result<ExecutionOutcome, ExecutionError>
where
    F: FnOnce(u32) -> Result<(), ExecutionError>,
{
    if request.mode != ExecutionMode::Direct {
        return Err(ExecutionError::UnsupportedMode(request.mode));
    }
    validate_redactions(redactions)?;
    let capture_limit = if redactions.is_empty() {
        None
    } else {
        Some(
            request
                .output_limit_bytes
                .ok_or(ExecutionError::UnboundedCredentialOutput)?,
        )
    };
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
    let mut stdout_control = stdout.try_clone()?;
    let mut stderr_control = stderr.try_clone()?;
    let (stdout_destination, stdout_reader) = if capture_limit.is_some() {
        let (reader, writer) = pipe()?;
        (Stdio::from(File::from(writer)), Some(File::from(reader)))
    } else {
        (Stdio::from(stdout), None)
    };
    let (stderr_destination, stderr_reader) = if capture_limit.is_some() {
        let (reader, writer) = pipe()?;
        (Stdio::from(File::from(writer)), Some(File::from(reader)))
    } else {
        (Stdio::from(stderr), None)
    };
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
        .stdout(stdout_destination)
        .stderr(stderr_destination)
        .process_group(0);
    let mut child = command.spawn()?;
    drop(command);
    let mut capture = match (stdout_reader, stderr_reader, capture_limit) {
        (Some(stdout), Some(stderr), Some(limit)) => {
            Some(OutputCapture::start(stdout, stderr, limit, redactions))
        }
        (None, None, None) => None,
        _ => unreachable!("capture configuration is internally consistent"),
    };
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
        result = wait_for_output_limit_mode(
            capture.as_ref(),
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

    let exceeded = capture.as_ref().is_some_and(OutputCapture::was_exceeded)
        || output_limit_exceeded(&stdout_control, &stderr_control, request.output_limit_bytes)?;
    if termination.0 == Termination::Exited && exceeded {
        termination.0 = Termination::OutputLimitExceeded;
    }
    if let Some(capture) = capture.take() {
        let captured = capture.finish().await?;
        if captured.exceeded {
            termination.0 = Termination::OutputLimitExceeded;
        }
        write_redacted_output(&mut stdout_control, &captured.stdout, redactions)?;
        write_redacted_output(&mut stderr_control, &captured.stderr, redactions)?;
        truncate_output_to_limit(&stdout_control, &stderr_control, request.output_limit_bytes)?;
    } else if termination.0 == Termination::OutputLimitExceeded || exceeded {
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

async fn wait_for_output_limit_mode(
    capture: Option<&OutputCapture>,
    stdout: &File,
    stderr: &File,
    limit: Option<u64>,
) -> Result<(), std::io::Error> {
    if let Some(capture) = capture {
        capture.limit_exceeded().await;
        Ok(())
    } else {
        wait_for_output_limit(stdout, stderr, limit).await
    }
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
            signal_group(process_group_id, Signal::SIGKILL)
                .map_err(|kill_error| containment_unverified(process_id, kill_error))?;
            let containment =
                wait_for_anchored_descendants_to_exit(process_id, process_group_id).await;
            child
                .wait()
                .await
                .map_err(|wait_error| containment_unverified(process_id, wait_error.into()))?;
            containment.map_err(|cleanup| containment_unverified(process_id, cleanup))?;
            return Err(containment_unverified(process_id, error));
        }
        let containment =
            terminate_descendants_while_leader_anchors_group(process_id, process_group_id, grace)
                .await;
        // Reap only after no descendants remain. Until this wait, the zombie
        // leader keeps its numeric PID/PGID unavailable for reuse.
        let status = child
            .wait()
            .await
            .map_err(|wait_error| containment_unverified(process_id, wait_error.into()))?;
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
        // Every failure below leaves the group possibly alive or the leader
        // possibly unreaped. That is unverified containment: it must never
        // surface as a plain error a caller could finalize as an ordinary
        // terminal while processes may still be running.
        let quiesced: Result<(), ExecutionError> = async {
            signal_group(process_group_id, Signal::SIGTERM)?;
            sleep(grace).await;
            if !leader_exited_without_reaping(process_id)?
                || group_has_members_other_than(process_group_id, process_id)?
            {
                signal_group(process_group_id, Signal::SIGKILL)?;
            }
            wait_for_unreaped_leader_exit_bounded(process_id, Duration::from_secs(5)).await
        }
        .await;
        quiesced.map_err(|error| containment_unverified(process_id, error))?;
        let containment = wait_for_anchored_descendants_to_exit(process_id, process_group_id).await;
        let status = child
            .wait()
            .await
            .map_err(|wait_error| containment_unverified(process_id, wait_error.into()))?;
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
                if proc_stat_read_lost_the_process(&error)
                    || error.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let Some((state, group)) = proc_stat_state_and_group(&stat) else {
            continue;
        };
        if group == process_group_id && state != b'Z' {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether a `/proc/<pid>/stat` read failed only because that process ceased
/// to exist. `NotFound` covers the entry vanishing before open; a task that
/// exits between open and read fails with raw `ESRCH`, which std leaves
/// uncategorized. Either way the process is not a live group member, and a
/// scan over all of `/proc` must not let an unrelated process's death read
/// as unverifiable containment.
#[cfg(target_os = "linux")]
fn proc_stat_read_lost_the_process(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::NotFound
        || error.raw_os_error() == Some(Errno::ESRCH as i32)
}

#[cfg(target_os = "linux")]
fn proc_stat_state_and_group(stat: &str) -> Option<(u8, i32)> {
    let (_, suffix) = stat.rsplit_once(") ")?;
    let mut fields = suffix.split_ascii_whitespace();
    let state = *fields.next()?.as_bytes().first()?;
    let _parent_process_id = fields.next()?;
    let process_group_id = fields.next()?.parse().ok()?;
    Some((state, process_group_id))
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

    #[test]
    fn proc_scan_tolerates_processes_that_vanish_mid_read() {
        // ESRCH is what /proc/<pid>/stat returns when the task exits between
        // open and read; the group scan visits every process on the host, so
        // an unrelated death must not read as unverifiable containment.
        assert!(proc_stat_read_lost_the_process(
            &io::Error::from_raw_os_error(Errno::ESRCH as i32)
        ));
        assert!(proc_stat_read_lost_the_process(&io::Error::new(
            io::ErrorKind::NotFound,
            "no entry"
        )));
        assert!(!proc_stat_read_lost_the_process(
            &io::Error::from_raw_os_error(Errno::EACCES as i32)
        ));
        assert!(!proc_stat_read_lost_the_process(&io::Error::other(
            "unrelated"
        )));
    }

    #[test]
    fn proc_stat_distinguishes_live_and_zombie_group_members() {
        assert_eq!(
            proc_stat_state_and_group("42 (worker (nested)) S 1 42 42 0"),
            Some((b'S', 42))
        );
        assert_eq!(
            proc_stat_state_and_group("43 (worker) Z 1 42 42 0"),
            Some((b'Z', 42))
        );
        assert_eq!(proc_stat_state_and_group("malformed"), None);
    }

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
    async fn credential_output_is_redacted_before_any_spool_write() {
        let root = tempfile::tempdir().unwrap();
        let mut request = request(root.path(), "credential-redaction", Duration::from_secs(5));
        request.arguments = vec![
            OsString::from("-c"),
            OsString::from("printf 'before marker-secret after'; printf 'err marker-secret' >&2"),
        ];
        request.output_limit_bytes = Some(65_536);

        let outcome = execute_with_spawn_hook_and_redactions(
            &request,
            CancellationToken::new(),
            &[b"marker-secret".to_vec()],
            |_| Ok(()),
        )
        .await
        .unwrap();

        let stdout = fs::read(root.path().join(&outcome.stdout.relative_path))
            .await
            .unwrap();
        let stderr = fs::read(root.path().join(&outcome.stderr.relative_path))
            .await
            .unwrap();
        assert_eq!(stdout, b"before  after");
        assert_eq!(stderr, b"err ");
        let stdout_digest: [u8; 32] = Sha256::digest(&stdout).into();
        let stderr_digest: [u8; 32] = Sha256::digest(&stderr).into();
        assert_eq!(outcome.stdout.digest, stdout_digest);
        assert_eq!(outcome.stderr.digest, stderr_digest);
    }

    #[tokio::test]
    async fn credential_crossing_output_limit_is_redacted_before_truncation() {
        let root = tempfile::tempdir().unwrap();
        let mut boundary_request = request(
            root.path(),
            "credential-limit-boundary",
            Duration::from_secs(5),
        );
        boundary_request.arguments = vec![
            OsString::from("-c"),
            OsString::from("printf '123456789012345marker-secret'"),
        ];
        boundary_request.output_limit_bytes = Some(16);

        let outcome = execute_with_spawn_hook_and_redactions(
            &boundary_request,
            CancellationToken::new(),
            &[b"marker-secret".to_vec()],
            |_| Ok(()),
        )
        .await
        .unwrap();

        let stdout = fs::read(root.path().join(&outcome.stdout.relative_path))
            .await
            .unwrap();
        assert_eq!(stdout, b"123456789012345");
        assert!(outcome.stdout.bytes <= 16);
        assert!(!stdout.ends_with(b"m"));

        let mut repeated_request = request(
            root.path(),
            "credential-repeated-deletion-boundary",
            Duration::from_secs(5),
        );
        repeated_request.arguments = vec![
            OsString::from("-c"),
            OsString::from("printf 'AAAAAAAAAAAAAAAASECRZ'"),
        ];
        repeated_request.output_limit_bytes = Some(16);
        let outcome = execute_with_spawn_hook_and_redactions(
            &repeated_request,
            CancellationToken::new(),
            &[b"AAAA".to_vec(), b"SECR".to_vec()],
            |_| Ok(()),
        )
        .await
        .unwrap();
        let stdout = fs::read(root.path().join(&outcome.stdout.relative_path))
            .await
            .unwrap();
        assert_eq!(stdout, b"Z");

        let mut cascading_request = request(
            root.path(),
            "credential-cascading-deletion-boundary",
            Duration::from_secs(5),
        );
        cascading_request.arguments = vec![
            OsString::from("-c"),
            OsString::from("printf 'Zaxxbaxxbaxxbaxxbaxxbaxxbaxxbaxxb'"),
        ];
        cascading_request.output_limit_bytes = Some(1);
        let outcome = execute_with_spawn_hook_and_redactions(
            &cascading_request,
            CancellationToken::new(),
            &[b"xx".to_vec(), b"ab".to_vec()],
            |_| Ok(()),
        )
        .await
        .unwrap();
        let stdout = fs::read(root.path().join(&outcome.stdout.relative_path))
            .await
            .unwrap();
        assert_eq!(stdout, b"Z");
        assert_eq!(outcome.termination, Termination::Exited);

        let mut split_stream_request = request(
            root.path(),
            "credential-split-stream-boundary",
            Duration::from_secs(5),
        );
        split_stream_request.arguments = vec![
            OsString::from("-c"),
            OsString::from(
                "printf 'safe-cred'; printf '12345678901234567890123456' >&2; sleep 1; printf 'ential'",
            ),
        ];
        split_stream_request.output_limit_bytes = Some(16);
        let outcome = execute_with_spawn_hook_and_redactions(
            &split_stream_request,
            CancellationToken::new(),
            &[b"credential".to_vec()],
            |_| Ok(()),
        )
        .await
        .unwrap();
        let stdout = fs::read(root.path().join(&outcome.stdout.relative_path))
            .await
            .unwrap();
        let stderr = fs::read(root.path().join(&outcome.stderr.relative_path))
            .await
            .unwrap();
        assert_eq!(outcome.termination, Termination::OutputLimitExceeded);
        assert_eq!(stdout, b"safe-");
        assert_eq!(stderr, b"12345678901");
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
