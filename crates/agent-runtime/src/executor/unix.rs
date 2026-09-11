//! Unix process-group execution.

use std::fs::File;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};
use std::path::{Component, Path};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use nix::errno::Errno;
use nix::sys::signal::{Signal, killpg};
#[cfg(target_os = "linux")]
use nix::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid};
use nix::unistd::{Pid, pipe};
#[cfg(target_os = "linux")]
use rustix::process::{Pid as RustixPid, PidfdFlags, pidfd_open};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt as _;
#[cfg(target_os = "linux")]
use tokio::io::unix::AsyncFd;
use tokio::process::{Child, Command};
use tokio::time::{Instant, sleep, sleep_until};
use tokio_util::sync::CancellationToken;

use crate::SpoolEntry;

use super::{
    CONTAINER_EXISTENCE_TIMEOUT, CONTAINER_REMOVAL_TIMEOUT, ContainerSpec, Containment,
    ExecutionError, ExecutionMode, ExecutionOutcome, ExecutionRequest, OutputCapture, Termination,
    create_workspace, sync_boundaries, validate_redactions, write_redacted_output,
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
    execute_with_io(request, cancellation, redactions, None, on_spawn).await
}

/// Uses the ordinary fenced process lifecycle, with request bytes withheld
/// until the spawn hook has committed and all output kept in bounded memory.
pub async fn execute_with_spawn_hook_and_private_io<F>(
    request: &ExecutionRequest,
    cancellation: CancellationToken,
    private_io: super::PrivateExecutionIo<'_>,
    on_spawn: F,
) -> Result<ExecutionOutcome, ExecutionError>
where
    F: FnOnce(u32) -> Result<(), ExecutionError>,
{
    if private_io.request.is_empty()
        || private_io.request.len() > 262_144
        || !matches!(request.output_limit_bytes, Some(1..=262_144))
        || request.workspace_seed.is_some()
    {
        return Err(ExecutionError::InvalidPrivateIo);
    }
    execute_with_io(request, cancellation, &[], Some(private_io), on_spawn).await
}

async fn execute_with_io<F>(
    request: &ExecutionRequest,
    cancellation: CancellationToken,
    redactions: &[Vec<u8>],
    private_io: Option<super::PrivateExecutionIo<'_>>,
    on_spawn: F,
) -> Result<ExecutionOutcome, ExecutionError>
where
    F: FnOnce(u32) -> Result<(), ExecutionError>,
{
    if request.mode != ExecutionMode::Direct {
        return Err(ExecutionError::UnsupportedMode(request.mode));
    }
    validate_redactions(redactions)?;
    if request.workspace_seed.is_some()
        && (!cfg!(target_os = "linux") || !request.environment.is_empty() || !redactions.is_empty())
    {
        return Err(ExecutionError::WorkspaceTransfer(
            "unsupported_platform_or_environment".to_owned(),
        ));
    }
    let capture_limit = if redactions.is_empty() && private_io.is_none() {
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

    // A later step of a multi-step attempt re-enters the workspace its first
    // step created; every other execution gets a fresh one.
    let workspace = match request.step_ordinal {
        Some(ordinal) if ordinal > 0 => {
            super::open_step_workspace(&request.workspace_root, &request.workspace)?
        }
        _ => create_workspace(&request.workspace_root, &request.workspace)?,
    };
    let workspace_control = File::open(&workspace)?;
    if let Some(seed) = &request.workspace_seed {
        super::workspace_transfer::seed(&workspace, seed)
            .map_err(ExecutionError::WorkspaceTransfer)?;
    }
    let attempt_spool = workspace.join("spool");
    if !matches!(request.step_ordinal, Some(ordinal) if ordinal > 0) {
        tokio::fs::create_dir(&attempt_spool).await?;
    }
    let (spool, spool_suffix) = match request.step_ordinal {
        None => (attempt_spool.clone(), "spool".to_owned()),
        Some(ordinal) => {
            let step = attempt_spool.join(format!("step-{ordinal}"));
            tokio::fs::create_dir(&step).await?;
            (step, format!("spool/step-{ordinal}"))
        }
    };
    // Keep handles to every agent-owned directory before untrusted code starts.
    // A workload runs as the agent OS user and can revoke pathname traversal;
    // retained handles let the agent restore the minimum owner access only
    // after containment has been proven empty.
    let mut directory_controls =
        retain_workspace_directory_chain(&request.workspace_root, &request.workspace, &spool)?;
    if request.step_ordinal.is_some() {
        directory_controls.push(File::open(&attempt_spool)?);
    }

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

    // A container step runs the pinned podman client as the process-group
    // leader; the image's program becomes the container entrypoint and the
    // attempt workspace its working directory. Nothing else of the host is
    // mounted. Environment reaches the container only by name, so secret
    // values never appear in the podman argument vector.
    // Held only until the podman client has been spawned with its inherited
    // copy; no other child may inherit it.
    let mut env_transport: Option<File> = None;
    let mut command = match &request.container {
        Some(container) => {
            if private_io.is_some() || request.workspace_seed.is_some() {
                return Err(ExecutionError::ContainerUnsupported(
                    "helper private IO and workspace transfer run on the host only",
                ));
            }
            if !mcloving_domain::container::is_digest_pinned_image(&container.image) {
                return Err(ExecutionError::ContainerUnsupported(
                    "image reference is not digest-pinned",
                ));
            }
            // Workload variables travel in a memory-only env file the podman
            // client reads through an inherited descriptor: they never share
            // the client's own environment, where names such as
            // CONTAINERS_CONF, HOME or XDG_RUNTIME_DIR would redirect the
            // runtime; they never enter the argument vector, where values are
            // visible; and they never touch the workspace or any durable
            // path, so a crash retains nothing and the container cannot read
            // the file back through /workspace.
            let mut env_lines = Vec::new();
            for (key, value) in &request.environment {
                let (key, value) = (key.to_string_lossy(), value.to_string_lossy());
                if key.contains(['=', '\n', '\0']) || value.contains(['\n', '\0']) {
                    return Err(ExecutionError::ContainerUnsupported(
                        "environment entries must not contain newlines, NUL or '=' in names",
                    ));
                }
                env_lines.push(format!("{key}={value}\n"));
            }
            let transport = {
                use std::io::{Seek as _, Write as _};
                let fd = nix::sys::memfd::memfd_create(
                    c"mcloving-container-env",
                    nix::sys::memfd::MFdFlags::empty(),
                )?;
                let mut file = File::from(fd);
                for line in &env_lines {
                    file.write_all(line.as_bytes())?;
                }
                file.seek(std::io::SeekFrom::Start(0))?;
                file
            };
            let env_path = format!("/proc/self/fd/{}", transport.as_raw_fd());
            env_transport = Some(transport);
            // The child starts inside the workspace, and podman reads a
            // volume source that does not begin with `/` or `.` as a named
            // volume, so a relative workspace root would mount the wrong
            // storage and drop the cidfile under a duplicated path. Both
            // paths are made absolute against this process's directory.
            let mounted_workspace = std::path::absolute(&workspace)?;
            let cidfile = std::path::absolute(spool.join("container.cid"))?;
            let mut command = Command::new(&container.runtime);
            command
                .arg("run")
                .arg("--rm")
                .arg("--name")
                .arg(&container.name)
                .arg("--cidfile")
                .arg(cidfile)
                .arg("--userns=keep-id")
                .arg("--volume")
                .arg(format!("{}:/workspace:Z", mounted_workspace.display()))
                .arg("--workdir")
                .arg("/workspace")
                .arg("--env-file")
                .arg(&env_path)
                .arg("--entrypoint")
                .arg(&request.program)
                .arg(&container.image)
                .args(&request.arguments);
            command
        }
        None => {
            let mut command = Command::new(&request.program);
            command.args(&request.arguments);
            command
        }
    };
    command
        .env_clear()
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .env("LANG", "C.UTF-8");
    if request.container.is_some() {
        // The podman client's control environment is fixed by the agent and
        // never touched by the workload; rootless podman needs these four.
        command.envs(std::env::vars_os().filter(|(key, _)| {
            matches!(
                key.to_str(),
                Some("HOME" | "XDG_RUNTIME_DIR" | "USER" | "TMPDIR")
            )
        }));
    } else {
        command.envs(&request.environment);
    }
    command
        .current_dir(&workspace)
        .stdin(if private_io.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(stdout_destination)
        .stderr(stderr_destination)
        .process_group(0);
    // Workspace preparation may await I/O while lease authority is lost.
    // A cancelled request must not resurrect work after that preparation.
    if cancellation.is_cancelled() {
        return Err(ExecutionError::CancelledBeforeSpawn);
    }
    let mut child = command.spawn()?;
    drop(command);
    // The client holds its own descriptor now; closing ours means no later
    // child of this process can inherit the credential-bearing transport.
    drop(env_transport.take());
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
        terminate_group_reaping_on_failure(
            &mut child,
            process_id,
            process_group_id,
            request.termination_grace,
            request.container.as_ref(),
        )
        .await?;
        if let Some(container) = &request.container {
            reap_container(&container.runtime, &container.name).await?;
        }
        return Err(error);
    }

    let mut input_task = PrivateInputTask(if let Some(io) = &private_io {
        let mut stdin = child.stdin.take().ok_or(ExecutionError::InvalidPrivateIo)?;
        let bytes = io.request.to_vec();
        let cancelled = cancellation.clone();
        Some(tokio::spawn(async move {
            tokio::select! {
                biased;
                () = cancelled.cancelled() => Err(std::io::Error::other("helper input cancelled")),
                result = async { stdin.write_all(&bytes).await?; stdin.shutdown().await } => result,
            }
        }))
    } else {
        None
    });

    let deadline = Instant::now() + request.timeout;
    let mut termination = tokio::select! {
        status = wait_for_leader_exit_and_cleanup(
            &mut child,
            process_id,
            process_group_id,
            request.termination_grace,
        ) => match status {
            Ok(status) => (Termination::Exited, status),
            Err(error) => {
                // The leader cleanup already forces unverified containment;
                // still reap the container now so it does not keep the
                // workspace mounted until a recovery session. The original
                // error is what the caller must see either way, and recovery
                // retries the absence proof if this reap did not succeed.
                if let Some(container) = &request.container {
                    let _ = reap_container(&container.runtime, &container.name).await;
                }
                return Err(error);
            }
        },
        () = cancellation.cancelled() => {
            let status = terminate_group_reaping_on_failure(
                &mut child,
                process_id,
                process_group_id,
                request.termination_grace,
                request.container.as_ref(),
            )
            .await?;
            (Termination::Cancelled, status)
        }
        () = sleep_until(deadline) => {
            let status = terminate_group_reaping_on_failure(
                &mut child,
                process_id,
                process_group_id,
                request.termination_grace,
                request.container.as_ref(),
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
                terminate_group_reaping_on_failure(
                    &mut child,
                    process_id,
                    process_group_id,
                    request.termination_grace,
                    request.container.as_ref(),
                )
                .await?;
                // The monitor failed, not the workload: the container may
                // still be running with the workspace mounted, so it is
                // reaped here exactly as on every other teardown arm.
                if let Some(container) = &request.container {
                    reap_container(&container.runtime, &container.name).await?;
                }
                return Err(error.into());
            }
            let status = terminate_group_reaping_on_failure(
                &mut child,
                process_id,
                process_group_id,
                request.termination_grace,
                request.container.as_ref(),
            )
            .await?;
            (Termination::OutputLimitExceeded, status)
        }
    };
    // The group is empty on every arm above, but a container outlives its
    // killed client. Reap it before any output is inspected or made durable,
    // so nothing keeps writing into the mounted workspace meanwhile, and
    // before any later fallible step could skip the proof.
    if let Some(container) = &request.container {
        reap_container(&container.runtime, &container.name).await?;
    }

    let exceeded = capture.as_ref().is_some_and(OutputCapture::was_exceeded)
        || output_limit_exceeded(&stdout_control, &stderr_control, request.output_limit_bytes)?;
    if termination.0 == Termination::Exited && exceeded {
        termination.0 = Termination::OutputLimitExceeded;
    }
    let input_delivered = if let Some(mut task) = input_task.0.take() {
        // Containment is already empty. A peer holding an inherited pipe must
        // not strand completion; aborting a pending writer sends no more bytes.
        tokio::select! {
            result = &mut task => result.is_ok_and(|result| result.is_ok()),
            () = sleep(Duration::from_millis(100)) => { task.abort(); false },
        }
    } else {
        true
    };
    let mut private_response_accepted = private_io.as_ref().map(|_| false);
    if let Some(capture) = capture.take() {
        let captured = capture.finish().await?;
        if captured.exceeded {
            termination.0 = Termination::OutputLimitExceeded;
        }
        if let Some(io) = &private_io {
            // Parsing a truncated frame, nonzero exit or incomplete request
            // could turn a plausible forged prefix into successful work.
            if input_delivered
                && !captured.exceeded
                && termination.0 == Termination::Exited
                && termination.1.success()
            {
                let public = (io.transform)(&captured.stdout, &captured.stderr);
                if public.stdout.len() as u64 <= request.output_limit_bytes.unwrap_or(0) {
                    write_redacted_output(&mut stdout_control, &public.stdout, &[])?;
                    private_response_accepted = Some(public.accepted);
                }
            }
            // stderr remains the original empty spool, including every error path.
        } else {
            write_redacted_output(&mut stdout_control, &captured.stdout, redactions)?;
            write_redacted_output(&mut stderr_control, &captured.stderr, redactions)?;
        }
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
    ensure_original_spool_path(&stdout_control, &stdout_path)?;
    ensure_original_spool_path(&stderr_control, &stderr_path)?;
    // The barrier the finalization journal record depends on: both spool
    // files and both directory entries durable before this returns. The four
    // flushes are independent of one another, so they run as one batch.
    sync_boundaries(
        &[&stdout_control, &stderr_control],
        &[spool.clone(), attempt_spool.clone(), workspace.clone()],
    )?;

    let workspace_snapshot = request.workspace_seed.as_ref().map(|_| {
        if termination.0 != Termination::Exited {
            return Err("execution_not_completed".to_owned());
        }
        super::workspace_transfer::capture(&workspace, &workspace_control)
    });
    Ok(ExecutionOutcome {
        private_response_accepted,
        workspace_snapshot,
        termination: termination.0,
        exit_code: termination.1.code(),
        process_id,
        containment: if request.container.is_some() {
            Containment::PodmanContainer
        } else {
            Containment::UnixProcessGroup
        },
        stdout: spool_entry(
            &request.workspace,
            &format!("{spool_suffix}/stdout.log"),
            0,
            &stdout_control,
        )
        .await?,
        stderr: spool_entry(
            &request.workspace,
            &format!("{spool_suffix}/stderr.log"),
            1,
            &stderr_control,
        )
        .await?,
    })
}

/// Removes the named container if it still exists and proves it is absent.
///
/// `podman run --rm` removes the container when its client exits normally,
/// but a client killed by timeout or cancellation leaves conmon holding the
/// container. Removal is idempotent, and absence is checked by a separate
/// `container exists` query whose exit status 1 is the only accepted proof.
/// Terminates the client group like [`terminate_and_prove_group_empty`], but
/// when that proof fails on a container attempt the container is reaped
/// before the cleanup error propagates. The group error is what the caller
/// must see: it already forces unverified containment, and recovery retries
/// the absence proof if this best-effort reap did not succeed. Without this,
/// every cancellation, timeout, output-limit and spawn-hook arm would leave
/// the container running with the workspace mounted until a recovery
/// session, exactly as the leader-exit arm used to.
async fn terminate_group_reaping_on_failure(
    child: &mut Child,
    process_id: u32,
    process_group_id: i32,
    termination_grace: Duration,
    container: Option<&ContainerSpec>,
) -> Result<ExitStatus, ExecutionError> {
    match terminate_and_prove_group_empty(child, process_id, process_group_id, termination_grace)
        .await
    {
        Ok(status) => Ok(status),
        Err(error) => {
            if let Some(container) = container {
                let _ = reap_container(&container.runtime, &container.name).await;
            }
            Err(error)
        }
    }
}

async fn reap_container(runtime: &Path, name: &str) -> Result<(), ExecutionError> {
    let unverified = |reason: String| ExecutionError::ContainerUnverified {
        name: name.to_owned(),
        reason,
    };
    // `--time 0` kills rather than asks: the client group is already empty,
    // so nothing inside deserves a stop timeout, and the whole reap has to
    // fit the lease reserve the worker set aside for it.
    let remove = tokio::time::timeout(
        CONTAINER_REMOVAL_TIMEOUT,
        Command::new(runtime)
            .args(["rm", "--force", "--time", "0", "--ignore", name])
            .env_clear()
            .env(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            )
            .envs(std::env::vars().filter(|(key, _)| {
                matches!(key.as_str(), "HOME" | "XDG_RUNTIME_DIR" | "USER" | "TMPDIR")
            }))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| {
        unverified(format!(
            "container removal did not return within {} seconds",
            CONTAINER_REMOVAL_TIMEOUT.as_secs()
        ))
    })?
    .map_err(|error| unverified(format!("container removal could not start: {error}")))?;
    if !remove.status.success() {
        return Err(unverified(format!(
            "container removal exited {:?}: {}",
            remove.status.code(),
            String::from_utf8_lossy(&remove.stderr).trim()
        )));
    }
    let exists = tokio::time::timeout(
        CONTAINER_EXISTENCE_TIMEOUT,
        Command::new(runtime)
            .args(["container", "exists", name])
            .env_clear()
            .env(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            )
            .envs(std::env::vars().filter(|(key, _)| {
                matches!(key.as_str(), "HOME" | "XDG_RUNTIME_DIR" | "USER" | "TMPDIR")
            }))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| {
        unverified(format!(
            "container existence query did not return within {} seconds",
            CONTAINER_EXISTENCE_TIMEOUT.as_secs()
        ))
    })?
    .map_err(|error| {
        unverified(format!(
            "container existence query could not start: {error}"
        ))
    })?;
    match exists.status.code() {
        Some(1) => Ok(()),
        Some(0) => Err(unverified(
            "container still exists after removal".to_owned(),
        )),
        other => Err(unverified(format!(
            "container existence query exited {other:?}: {}",
            String::from_utf8_lossy(&exists.stderr).trim()
        ))),
    }
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
    let raw_process_id = i32::try_from(process_id).map_err(|_| ExecutionError::MissingProcessId)?;
    let pid = RustixPid::from_raw(raw_process_id).ok_or(ExecutionError::MissingProcessId)?;
    let pidfd = match pidfd_open(pid, PidfdFlags::empty()) {
        Ok(pidfd) => Some(AsyncFd::new(pidfd)?),
        // Linux before 5.3 has no pidfd. Keep a compatibility fallback rather
        // than weakening containment on older supported hosts.
        Err(rustix::io::Errno::NOSYS) => None,
        Err(error) => return Err(std::io::Error::from(error).into()),
    };
    loop {
        if leader_exited_without_reaping(process_id)? {
            return Ok(());
        }
        if let Some(pidfd) = &pidfd {
            // A pidfd becomes readable when the exact process exits and is not
            // vulnerable to numeric PID reuse. WNOWAIT below still leaves the
            // zombie unreaped as the process-group anchor.
            let mut ready = pidfd.readable().await?;
            ready.clear_ready();
        } else {
            sleep(Duration::from_millis(10)).await;
        }
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
            workspace_seed: None,
            step_ordinal: None,
            container: None,
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
            workspace_seed: None,
            step_ordinal: None,
            container: None,
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
    async fn already_cancelled_execution_never_spawns_a_process() {
        let root = tempfile::tempdir().unwrap();
        let request = request(root.path(), "cancelled", Duration::from_secs(30));
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let result = execute_with_spawn_hook(&request, cancellation, |_| {
            panic!("cancelled execution must not invoke the spawn hook")
        })
        .await;
        assert!(matches!(result, Err(ExecutionError::CancelledBeforeSpawn)));
        assert!(!root.path().join("cancelled/child.pid").exists());
        assert!(!root.path().join("cancelled/spawned.marker").exists());
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
            workspace_seed: None,
            step_ordinal: None,
            container: None,
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
            workspace_seed: None,
            step_ordinal: None,
            container: None,
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
            workspace_seed: None,
            step_ordinal: None,
            container: None,
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
            workspace_seed: None,
            step_ordinal: None,
            container: None,
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
            workspace_seed: None,
            step_ordinal: None,
            container: None,
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
            workspace_seed: None,
            step_ordinal: None,
            container: None,
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
            workspace_seed: None,
            step_ordinal: None,
            container: None,
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
            workspace_seed: None,
            step_ordinal: None,
            container: None,
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
            workspace_seed: None,
            step_ordinal: None,
            container: None,
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
            workspace_seed: None,
            step_ordinal: None,
            container: None,
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

struct PrivateInputTask(Option<tokio::task::JoinHandle<Result<(), std::io::Error>>>);
impl Drop for PrivateInputTask {
    fn drop(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
        }
    }
}

#[cfg(test)]
mod private_io_tests {
    use super::*;
    use crate::executor::{PrivateExecutionIo, PrivateExecutionOutput};
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    fn request(root: &Path, script: &str) -> ExecutionRequest {
        ExecutionRequest {
            workspace_seed: None,
            step_ordinal: None,
            container: None,
            workspace_root: root.to_owned(),
            workspace: "org/private".into(),
            mode: ExecutionMode::Direct,
            program: "/bin/sh".into(),
            arguments: vec!["-c".into(), script.into()],
            environment: BTreeMap::new(),
            output_limit_bytes: Some(262_144),
            timeout: Duration::from_secs(3),
            termination_grace: Duration::from_millis(50),
        }
    }
    #[tokio::test]
    async fn private_exchange_drains_before_stdin_and_publishes_only_transformed_bytes() {
        let root = tempfile::tempdir().unwrap();
        let request = request(
            root.path(),
            "head -c 70000 /dev/zero; head -c 70000 /dev/zero >&2; cat >/dev/null; printf private-marker",
        );
        let called = AtomicBool::new(false);
        let transform = |stdout: &[u8], stderr: &[u8]| {
            assert_eq!(stdout.len(), 70000 + 14);
            assert_eq!(stderr.len(), 70000);
            assert!(stdout.ends_with(b"private-marker"));
            called.store(true, Ordering::SeqCst);
            PrivateExecutionOutput {
                stdout: b"public-receipt\n".to_vec(),
                accepted: true,
            }
        };
        let input = vec![b'x'; 200_000];
        let result = execute_with_spawn_hook_and_private_io(
            &request,
            CancellationToken::new(),
            PrivateExecutionIo {
                request: &input,
                transform: &transform,
            },
            |_| Ok(()),
        )
        .await
        .unwrap();
        assert_eq!(result.private_response_accepted, Some(true));
        assert!(called.load(Ordering::SeqCst));
        assert_eq!(
            std::fs::read(root.path().join(result.stdout.relative_path)).unwrap(),
            b"public-receipt\n"
        );
        assert!(
            std::fs::read(root.path().join(result.stderr.relative_path))
                .unwrap()
                .is_empty()
        );
    }
    #[tokio::test]
    async fn private_request_is_withheld_on_spawn_hook_failure_or_preexisting_cancellation() {
        for cancelled in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let request = request(root.path(), "read value; printf reached > request-observed");
            let token = CancellationToken::new();
            if cancelled {
                token.cancel();
            }
            let transform = |_: &[u8], _: &[u8]| panic!("no response may be transformed");
            let result = execute_with_spawn_hook_and_private_io(
                &request,
                token,
                PrivateExecutionIo {
                    request: b"request\n",
                    transform: &transform,
                },
                |_| Err(ExecutionError::SpawnHook("durability denied".to_owned())),
            )
            .await;
            assert!(result.is_err());
            assert!(!root.path().join("org/private/request-observed").exists());
        }
    }
    #[tokio::test]
    async fn blocked_private_stdin_is_cancelled_and_descendants_end_before_transform() {
        for timed_out in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let mut request = request(
                root.path(),
                "trap '' TERM; (trap '' TERM; sleep 30) & echo $! > child.pid; while :; do sleep 1; done",
            );
            request.timeout = if timed_out {
                Duration::from_millis(200)
            } else {
                Duration::from_secs(30)
            };
            let token = CancellationToken::new();
            let trigger = token.clone();
            if !timed_out {
                tokio::spawn(async move {
                    sleep(Duration::from_millis(200)).await;
                    trigger.cancel();
                });
            }
            let transform =
                |_: &[u8], _: &[u8]| panic!("incomplete request cannot become a receipt");
            let input = vec![b'x'; 200_000];
            let started = Instant::now();
            let result = execute_with_spawn_hook_and_private_io(
                &request,
                token,
                PrivateExecutionIo {
                    request: &input,
                    transform: &transform,
                },
                |_| Ok(()),
            )
            .await
            .unwrap();
            let elapsed = started.elapsed();
            eprintln!(
                "blocked private stdin: timed_out={timed_out}, elapsed={elapsed:?}, termination={:?}",
                result.termination
            );
            assert_eq!(result.private_response_accepted, Some(false));
            assert_eq!(
                result.termination,
                if timed_out {
                    Termination::TimedOut
                } else {
                    Termination::Cancelled
                }
            );
            let pid: i32 = std::fs::read_to_string(root.path().join("org/private/child.pid"))
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            assert!(matches!(
                nix::sys::signal::kill(Pid::from_raw(pid), None),
                Err(Errno::ESRCH)
            ));
            assert!(
                std::fs::read(root.path().join(result.stdout.relative_path))
                    .unwrap()
                    .is_empty()
            );
            assert!(
                std::fs::read(root.path().join(result.stderr.relative_path))
                    .unwrap()
                    .is_empty()
            );
            // Measure the complete execution contract, including its existing
            // bounded leader/descendant waits and final durability work, not
            // just the private writer's 100 ms post-containment join. This
            // remains well below the hostile helper's 30 second lifetime.
            let completion_bound = Duration::from_millis(200)
                + request.termination_grace
                + Duration::from_secs(5) // unreaped leader exit
                + Duration::from_secs(5) // anchored descendants
                + Duration::from_millis(100) // private writer join
                + Duration::from_secs(2); // setup, scheduling and spool durability
            assert!(completion_bound < Duration::from_secs(30));
            assert!(
                elapsed < completion_bound,
                "timed_out={timed_out}, elapsed={elapsed:?}, bound={completion_bound:?}, termination={:?}",
                result.termination
            );
        }
    }
    #[tokio::test]
    async fn private_overflow_and_nonzero_exit_never_transform_a_plausible_prefix() {
        for script in ["printf plausible-receipt; exit 1", "yes private-marker"] {
            let root = tempfile::tempdir().unwrap();
            let mut request = request(root.path(), script);
            request.output_limit_bytes = Some(1024);
            let transform =
                |_: &[u8], _: &[u8]| panic!("invalid process result must never reach parser");
            let result = execute_with_spawn_hook_and_private_io(
                &request,
                CancellationToken::new(),
                PrivateExecutionIo {
                    request: b"request\n",
                    transform: &transform,
                },
                |_| Ok(()),
            )
            .await
            .unwrap();
            assert_eq!(result.private_response_accepted, Some(false));
            assert!(
                std::fs::read(root.path().join(result.stdout.relative_path))
                    .unwrap()
                    .is_empty()
            );
        }
    }
}
