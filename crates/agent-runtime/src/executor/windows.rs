//! Windows execution using race-free kill-on-close Job Objects.

use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::windows::fs::OpenOptionsExt;
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
#[cfg(test)]
use std::process::Command;
use std::process::ExitStatus;
use std::time::Duration;

use mcloving_windows_job::{JobProcess, SpawnSpec, anonymous_pipe, file_identity};
use sha2::{Digest, Sha256};
use tokio::time::{Instant, sleep, sleep_until};
use tokio_util::sync::CancellationToken;

use crate::SpoolEntry;

use super::{
    Containment, ExecutionError, ExecutionMode, ExecutionOutcome, ExecutionRequest, OutputCapture,
    Termination, create_workspace, is_link_or_reparse_point, sync_directory, validate_redactions,
    write_redacted_output,
};

const TERMINATED_EXIT_CODE: u32 = 0xC000_013A;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_SHARE_DELETE: u32 = 0x0000_0004;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

pub async fn execute(
    request: &ExecutionRequest,
    cancellation: CancellationToken,
) -> Result<ExecutionOutcome, ExecutionError> {
    execute_with_spawn_hook(request, cancellation, |_| Ok(())).await
}

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

    let stdout_path = spool.join("stdout.log");
    let stderr_path = spool.join("stderr.log");
    let stdin = std::fs::OpenOptions::new().read(true).open("NUL")?;
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
    let mut stdout_control = stdout.try_clone()?;
    let mut stderr_control = stderr.try_clone()?;
    let (stdout_destination, stdout_reader) = if capture_limit.is_some() {
        let (reader, writer) =
            anonymous_pipe().map_err(|error| ExecutionError::WindowsJob(error.to_string()))?;
        (writer, Some(reader))
    } else {
        (stdout, None)
    };
    let (stderr_destination, stderr_reader) = if capture_limit.is_some() {
        let (reader, writer) =
            anonymous_pipe().map_err(|error| ExecutionError::WindowsJob(error.to_string()))?;
        (writer, Some(reader))
    } else {
        (stderr, None)
    };

    ensure_original_workspace_root(&workspace_root_control, &request.workspace_root)?;
    let command = windows_command(request)?;
    let mut child = JobProcess::spawn_suspended(&SpawnSpec {
        program: &command.program,
        arguments: &command.arguments,
        raw_argument_suffix: command.raw_argument_suffix.as_deref(),
        environment: &request.environment,
        current_directory: &workspace,
        stdin: &stdin,
        stdout: &stdout_destination,
        stderr: &stderr_destination,
    })
    .map_err(|error| ExecutionError::WindowsJob(error.to_string()))?;
    drop(stdout_destination);
    drop(stderr_destination);
    let mut capture = match (stdout_reader, stderr_reader, capture_limit) {
        (Some(stdout), Some(stderr), Some(limit)) => {
            Some(OutputCapture::start(stdout, stderr, limit))
        }
        (None, None, None) => None,
        _ => unreachable!("capture configuration is internally consistent"),
    };
    let process_id = child.process_id();
    if let Err(error) = on_spawn(process_id) {
        terminate_job(&child, process_id).await?;
        return Err(error);
    }
    if let Err(error) = child.resume() {
        terminate_job(&child, process_id).await?;
        return Err(ExecutionError::WindowsJob(error.to_string()));
    }

    let deadline = Instant::now() + request.timeout;
    let (mut termination, status) = loop {
        if let Some(status) = child.try_wait().map_err(|error| {
            containment_unverified(process_id, ExecutionError::WindowsJob(error.to_string()))
        })? {
            break (Termination::Exited, status);
        }
        if capture.as_ref().is_some_and(OutputCapture::was_exceeded)
            || (capture.is_none()
                && output_limit_exceeded(
                    &stdout_control,
                    &stderr_control,
                    request.output_limit_bytes,
                )
                .map_err(|error| containment_unverified(process_id, ExecutionError::Io(error)))?)
        {
            break (
                Termination::OutputLimitExceeded,
                terminate_job(&child, process_id).await?,
            );
        }
        tokio::select! {
            () = cancellation.cancelled() => {
                break (
                    Termination::Cancelled,
                    terminate_job(&child, process_id).await?,
                );
            }
            () = sleep_until(deadline) => {
                break (
                    Termination::TimedOut,
                    terminate_job(&child, process_id).await?,
                );
            }
            () = sleep(Duration::from_millis(20)) => {}
        }
    };

    // A leader may exit while descendants still hold inherited spool handles.
    // Terminate the complete job and observe zero active processes before
    // syncing or hashing either log.
    terminate_job(&child, process_id).await?;
    drop(child);
    let exceeded = capture.as_ref().is_some_and(OutputCapture::was_exceeded)
        || output_limit_exceeded(&stdout_control, &stderr_control, request.output_limit_bytes)?;
    if exceeded {
        termination = Termination::OutputLimitExceeded;
    }
    if let Some(capture) = capture.take() {
        let (captured_stdout, captured_stderr) = capture.finish().await?;
        write_redacted_output(&mut stdout_control, &captured_stdout, redactions)?;
        write_redacted_output(&mut stderr_control, &captured_stderr, redactions)?;
    } else if termination == Termination::OutputLimitExceeded {
        truncate_output_to_limit(&stdout_control, &stderr_control, request.output_limit_bytes)?;
    }
    ensure_original_workspace_root(&workspace_root_control, &request.workspace_root)?;
    stdout_control.sync_all()?;
    stderr_control.sync_all()?;
    ensure_original_spool_path(&stdout_control, &stdout_path)?;
    ensure_original_spool_path(&stderr_control, &stderr_path)?;
    sync_directory(&spool)?;
    sync_directory(&workspace)?;

    Ok(ExecutionOutcome {
        termination,
        exit_code: status.code(),
        process_id,
        containment: Containment::WindowsJobObject,
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
    if !metadata.is_dir() || is_link_or_reparse_point(&metadata) {
        return Err(ExecutionError::InvalidWorkspaceRoot);
    }
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(ExecutionError::Io)
}

pub(super) fn ensure_original_workspace_root(
    file: &File,
    path: &Path,
) -> Result<(), ExecutionError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| ExecutionError::ReplacedWorkspaceRoot)?;
    if !metadata.is_dir() || is_link_or_reparse_point(&metadata) {
        return Err(ExecutionError::ReplacedWorkspaceRoot);
    }
    let named = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| ExecutionError::ReplacedWorkspaceRoot)?;
    let opened_identity = file_identity(file).map_err(|_| ExecutionError::ReplacedWorkspaceRoot)?;
    let named_identity =
        file_identity(&named).map_err(|_| ExecutionError::ReplacedWorkspaceRoot)?;
    if opened_identity == named_identity {
        Ok(())
    } else {
        Err(ExecutionError::ReplacedWorkspaceRoot)
    }
}

fn ensure_original_spool_path(file: &File, path: &Path) -> Result<(), ExecutionError> {
    let named = std::fs::File::open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            ExecutionError::ReplacedSpoolPath
        } else {
            error.into()
        }
    })?;
    let opened_identity =
        file_identity(file).map_err(|error| ExecutionError::WindowsJob(error.to_string()))?;
    let named_identity =
        file_identity(&named).map_err(|error| ExecutionError::WindowsJob(error.to_string()))?;
    if opened_identity == named_identity {
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
    let mut file = file.try_clone()?;
    let digest = tokio::task::spawn_blocking(move || digest_file(&mut file))
        .await
        .map_err(|error| std::io::Error::other(format!("spool digest task failed: {error}")))??;
    Ok(SpoolEntry {
        sequence,
        relative_path: workspace.join(suffix),
        digest,
        bytes,
    })
}

fn digest_file(file: &mut File) -> Result<[u8; 32], std::io::Error> {
    file.seek(SeekFrom::Start(0))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(digest.finalize().into())
}

struct WindowsCommand {
    program: OsString,
    arguments: Vec<OsString>,
    raw_argument_suffix: Option<OsString>,
}

fn windows_command(request: &ExecutionRequest) -> Result<WindowsCommand, ExecutionError> {
    match request.mode {
        ExecutionMode::Direct => Ok(WindowsCommand {
            program: request.program.as_os_str().to_owned(),
            arguments: request.arguments.clone(),
            raw_argument_suffix: None,
        }),
        ExecutionMode::WindowsCmd => {
            let command_string = cmd_command_string(&request.program, &request.arguments)?;
            Ok(WindowsCommand {
                program: OsString::from("cmd.exe"),
                arguments: ["/D", "/S", "/C"].into_iter().map(OsString::from).collect(),
                // cmd.exe has its own parser rather than the C argv decoder.
                // Append the validated nested quote sequence verbatim so /S
                // strips only its outer pair.
                raw_argument_suffix: Some(OsString::from(command_string)),
            })
        }
        ExecutionMode::PowerShell => Ok(WindowsCommand {
            program: OsString::from("powershell.exe"),
            arguments: [
                OsString::from("-NoLogo"),
                OsString::from("-NoProfile"),
                OsString::from("-NonInteractive"),
                OsString::from("-ExecutionPolicy"),
                OsString::from("RemoteSigned"),
                OsString::from("-File"),
                request.program.as_os_str().to_owned(),
            ]
            .into_iter()
            .chain(request.arguments.iter().cloned())
            .collect(),
            raw_argument_suffix: None,
        }),
    }
}

fn cmd_command_string(
    program: &std::path::Path,
    arguments: &[OsString],
) -> Result<String, ExecutionError> {
    let program = program
        .to_str()
        .ok_or(ExecutionError::UnsafeWindowsShellArgument)?;
    let mut values = Vec::with_capacity(arguments.len() + 1);
    values.push(program);
    for argument in arguments {
        values.push(
            argument
                .to_str()
                .ok_or(ExecutionError::UnsafeWindowsShellArgument)?,
        );
    }
    if values.iter().any(|value| {
        value.chars().any(|character| {
            matches!(
                character,
                '"' | '\r' | '\n' | '%' | '!' | '^' | '&' | '|' | '<' | '>'
            )
        })
    }) {
        return Err(ExecutionError::UnsafeWindowsShellArgument);
    }

    // /S strips the first and last quote after /C. One outer quote pair keeps
    // the inner program-path quotes intact; each value then remains one cmd
    // token even when normal Windows paths or arguments contain spaces.
    let mut command = String::from("\"");
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            command.push(' ');
        }
        command.push('"');
        command.push_str(value);
        command.push('"');
    }
    command.push('"');
    Ok(command)
}

async fn terminate_job(child: &JobProcess, process_id: u32) -> Result<ExitStatus, ExecutionError> {
    child.terminate(TERMINATED_EXIT_CODE).map_err(|error| {
        containment_unverified(process_id, ExecutionError::WindowsJob(error.to_string()))
    })?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|error| {
            containment_unverified(process_id, ExecutionError::WindowsJob(error.to_string()))
        })? {
            break status;
        }
        if Instant::now() >= deadline {
            return Err(containment_unverified(
                process_id,
                ExecutionError::WindowsJob(
                    "terminated process did not become waitable within five seconds".to_owned(),
                ),
            ));
        }
        sleep(Duration::from_millis(10)).await;
    };
    wait_for_empty_job(child, process_id).await?;
    Ok(status)
}

async fn wait_for_empty_job(job: &JobProcess, process_id: u32) -> Result<(), ExecutionError> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let active = job.active_processes().map_err(|error| {
            containment_unverified(process_id, ExecutionError::WindowsJob(error.to_string()))
        })?;
        if active == 0 {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(containment_unverified(
                process_id,
                ExecutionError::WindowsJob(format!(
                    "terminated Job Object still contains {active} process(es)"
                )),
            ));
        }
        sleep(Duration::from_millis(10)).await;
    }
}

fn containment_unverified(process_id: u32, error: ExecutionError) -> ExecutionError {
    ExecutionError::ContainmentUnverified {
        process_id,
        reason: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    fn request(
        root: &Path,
        workspace: &str,
        mode: ExecutionMode,
        program: impl Into<PathBuf>,
        arguments: Vec<OsString>,
    ) -> ExecutionRequest {
        ExecutionRequest {
            workspace_root: root.to_owned(),
            workspace: PathBuf::from(workspace),
            mode,
            program: program.into(),
            arguments,
            environment: BTreeMap::new(),
            output_limit_bytes: None,
            timeout: Duration::from_secs(10),
            termination_grace: Duration::from_millis(100),
        }
    }

    #[test]
    fn post_spawn_cleanup_failure_preserves_recovery_identity() {
        let error = containment_unverified(
            4_242,
            ExecutionError::WindowsJob("QueryInformationJobObject failed".to_owned()),
        );

        assert!(matches!(
            error,
            ExecutionError::ContainmentUnverified {
                process_id: 4_242,
                reason
            } if reason.contains("QueryInformationJobObject")
        ));
    }

    #[tokio::test]
    async fn credential_output_is_redacted_before_any_spool_write() {
        let root = tempfile::tempdir().unwrap();
        let mut request = request(
            root.path(),
            "credential-redaction",
            ExecutionMode::Direct,
            "cmd.exe",
            vec![
                OsString::from("/D"),
                OsString::from("/S"),
                OsString::from("/C"),
                OsString::from("echo before marker-secret after & echo err marker-secret 1>&2"),
            ],
        );
        request.output_limit_bytes = Some(65_536);

        let outcome = execute_with_spawn_hook_and_redactions(
            &request,
            CancellationToken::new(),
            &[b"marker-secret".to_vec()],
            |_| Ok(()),
        )
        .await
        .unwrap();

        let stdout = fs::read(root.path().join(&outcome.stdout.relative_path)).unwrap();
        let stderr = fs::read(root.path().join(&outcome.stderr.relative_path)).unwrap();
        assert!(
            !stdout
                .windows(b"marker-secret".len())
                .any(|value| value == b"marker-secret")
        );
        assert!(
            !stderr
                .windows(b"marker-secret".len())
                .any(|value| value == b"marker-secret")
        );
        assert!(
            stdout
                .windows(b"before".len())
                .any(|value| value == b"before")
        );
        assert!(stderr.windows(b"err".len()).any(|value| value == b"err"));
    }

    #[tokio::test]
    async fn direct_cmd_and_powershell_modes_preserve_logs() {
        let root = tempfile::tempdir().unwrap();

        let direct = request(
            root.path(),
            "direct",
            ExecutionMode::Direct,
            "cmd.exe",
            vec![
                OsString::from("/D"),
                OsString::from("/S"),
                OsString::from("/C"),
                OsString::from("echo direct"),
            ],
        );
        let direct = execute(&direct, CancellationToken::new()).await.unwrap();
        assert_eq!(direct.termination, Termination::Exited);
        assert_eq!(
            direct.exit_code,
            Some(0),
            "stdout={:?}; stderr={:?}",
            fs::read_to_string(root.path().join("direct/spool/stdout.log")),
            fs::read_to_string(root.path().join("direct/spool/stderr.log"))
        );
        assert_eq!(direct.containment, Containment::WindowsJobObject);

        let command_directory = root.path().join("script directory");
        fs::create_dir(&command_directory).unwrap();
        let command_script = command_directory.join("mode.cmd");
        fs::write(&command_script, "@echo off\r\necho cmd-%~1\r\n").unwrap();
        let cmd = request(
            root.path(),
            "cmd",
            ExecutionMode::WindowsCmd,
            command_script,
            vec![OsString::from("hello world")],
        );
        let cmd = execute(&cmd, CancellationToken::new()).await.unwrap();
        assert_eq!(
            cmd.exit_code,
            Some(0),
            "stdout={:?}; stderr={:?}",
            fs::read_to_string(root.path().join("cmd/spool/stdout.log")),
            fs::read_to_string(root.path().join("cmd/spool/stderr.log"))
        );
        assert!(
            fs::read_to_string(root.path().join("cmd/spool/stdout.log"))
                .unwrap()
                .contains("cmd-hello world")
        );

        let powershell_script = root.path().join("mode.ps1");
        fs::write(
            &powershell_script,
            "param($Value)\nWrite-Output \"ps-$Value\"\n",
        )
        .unwrap();
        let powershell = request(
            root.path(),
            "powershell",
            ExecutionMode::PowerShell,
            powershell_script,
            vec![OsString::from("ok")],
        );
        let powershell = execute(&powershell, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(
            powershell.exit_code,
            Some(0),
            "stdout={:?}; stderr={:?}",
            fs::read_to_string(root.path().join("powershell/spool/stdout.log")),
            fs::read_to_string(root.path().join("powershell/spool/stderr.log"))
        );
        assert!(
            fs::read_to_string(root.path().join("powershell/spool/stdout.log"))
                .unwrap()
                .contains("ps-ok")
        );
    }

    #[tokio::test]
    async fn renamed_spool_cannot_evade_the_output_quota() {
        let root = tempfile::tempdir().unwrap();
        let script = root.path().join("rename-spool.ps1");
        fs::write(
            &script,
            r#"
while ($true) { [Console]::Out.Write("0123456789abcdef") }
"#,
        )
        .unwrap();
        let mut request = request(
            root.path(),
            "renamed-log",
            ExecutionMode::PowerShell,
            script,
            Vec::new(),
        );
        request.output_limit_bytes = Some(4_096);
        request.timeout = Duration::from_secs(30);

        let process_id = Arc::new(AtomicU32::new(0));
        let recorded_process_id = Arc::clone(&process_id);
        let public_path = root.path().join("renamed-log/spool/stdout.log");
        let renamed_path = root.path().join("renamed-log/spool/renamed.log");
        let result = execute_with_spawn_hook(&request, CancellationToken::new(), move |spawned| {
            recorded_process_id.store(spawned, Ordering::SeqCst);
            fs::rename(&public_path, &renamed_path)?;
            File::create(public_path)?;
            Ok(())
        })
        .await;
        assert!(
            matches!(result, Err(ExecutionError::ReplacedSpoolPath)),
            "unexpected execution result: {result:?}"
        );
        assert!(
            fs::metadata(root.path().join("renamed-log/spool/renamed.log"))
                .unwrap()
                .len()
                <= 4_096
        );
        let process_id = process_id.load(Ordering::SeqCst);
        assert_ne!(process_id, 0, "spawn hook did not record the workload PID");
        let status = Command::new("powershell.exe")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!(
                    "if (Get-Process -Id {process_id} -ErrorAction SilentlyContinue) {{ exit 1 }}"
                ),
            ])
            .status()
            .unwrap();
        assert!(status.success(), "workload {process_id} escaped its Job");
    }

    #[tokio::test]
    async fn cancellation_kills_the_job_object_process_tree() {
        let root = tempfile::tempdir().unwrap();
        let script = root.path().join("tree.ps1");
        fs::write(
            &script,
            r#"
param([string]$PidPath)
$child = Start-Process powershell.exe -PassThru -ArgumentList @(
  "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 30"
)
$child.Id | Set-Content -LiteralPath $PidPath -Encoding ascii
Wait-Process -Id $child.Id
"#,
        )
        .unwrap();
        let pid_path = root.path().join("cancel-child.pid");
        let request = request(
            root.path(),
            "cancel",
            ExecutionMode::PowerShell,
            script,
            vec![pid_path.as_os_str().to_owned()],
        );
        let token = CancellationToken::new();
        let cancel = token.clone();
        let cancellation_pid_path = pid_path.clone();
        let cancellation = tokio::spawn(async move {
            for _ in 0..1_500 {
                if cancellation_pid_path.exists() {
                    cancel.cancel();
                    return;
                }
                sleep(Duration::from_millis(10)).await;
            }
            panic!("descendant PID was not written within 15 seconds");
        });

        let outcome = execute(&request, token).await.unwrap();
        cancellation.await.unwrap();
        assert_eq!(outcome.termination, Termination::Cancelled);
        let child_pid = fs::read_to_string(pid_path)
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap();
        let status = Command::new("powershell.exe")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!(
                    "if (Get-Process -Id {child_pid} -ErrorAction SilentlyContinue) {{ exit 1 }}"
                ),
            ])
            .status()
            .unwrap();
        assert!(
            status.success(),
            "descendant {child_pid} escaped the Job Object"
        );
    }

    #[test]
    fn replaced_workspace_root_is_rejected_by_handle_identity() {
        let parent = tempfile::tempdir().unwrap();
        let workspace_root = parent.path().join("workspace");
        let displaced_root = parent.path().join("displaced-workspace");
        fs::create_dir(&workspace_root).unwrap();
        let control = open_workspace_root(&workspace_root).unwrap();
        ensure_original_workspace_root(&control, &workspace_root).unwrap();

        fs::rename(&workspace_root, &displaced_root).unwrap();
        fs::create_dir(&workspace_root).unwrap();

        assert!(matches!(
            ensure_original_workspace_root(&control, &workspace_root),
            Err(ExecutionError::ReplacedWorkspaceRoot)
        ));
        assert!(displaced_root.is_dir());
    }
}
