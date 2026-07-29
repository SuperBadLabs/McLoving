//! Windows execution using race-free kill-on-close Job Objects.

use std::ffi::OsString;
#[cfg(test)]
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::process::Command;
use std::process::ExitStatus;
use std::time::Duration;

use mcloving_windows_job::{JobProcess, SpawnSpec};
use tokio::time::{Instant, sleep, sleep_until};
use tokio_util::sync::CancellationToken;

use super::{
    Containment, ExecutionError, ExecutionMode, ExecutionOutcome, ExecutionRequest, Termination,
    create_workspace, spool_entry, sync_directory, sync_file,
};

const TERMINATED_EXIT_CODE: u32 = 0xC000_013A;

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
    let workspace = create_workspace(&request.workspace_root, &request.workspace)?;
    let spool = workspace.join("spool");
    tokio::fs::create_dir(&spool).await?;

    let stdout_path = spool.join("stdout.log");
    let stderr_path = spool.join("stderr.log");
    let stdin = std::fs::OpenOptions::new().read(true).open("NUL")?;
    let stdout = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&stdout_path)?;
    let stderr = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&stderr_path)?;

    let command = windows_command(request)?;
    let mut child = JobProcess::spawn_suspended(&SpawnSpec {
        program: &command.program,
        arguments: &command.arguments,
        raw_argument_suffix: command.raw_argument_suffix.as_deref(),
        environment: &request.environment,
        current_directory: &workspace,
        stdin: &stdin,
        stdout: &stdout,
        stderr: &stderr,
    })
    .map_err(|error| ExecutionError::WindowsJob(error.to_string()))?;
    let process_id = child.process_id();
    if let Err(error) = on_spawn(process_id) {
        terminate_job(&child).await?;
        return Err(error);
    }
    if let Err(error) = child.resume() {
        terminate_job(&child).await?;
        return Err(ExecutionError::WindowsJob(error.to_string()));
    }

    let deadline = Instant::now() + request.timeout;
    let (termination, status) = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| ExecutionError::WindowsJob(error.to_string()))?
        {
            break (Termination::Exited, status);
        }
        tokio::select! {
            () = cancellation.cancelled() => {
                break (
                    Termination::Cancelled,
                    terminate_job(&child).await?,
                );
            }
            () = sleep_until(deadline) => {
                break (
                    Termination::TimedOut,
                    terminate_job(&child).await?,
                );
            }
            () = sleep(Duration::from_millis(20)) => {}
        }
    };

    // A leader may exit while descendants still hold inherited spool handles.
    // Terminate the complete job and observe zero active processes before
    // syncing or hashing either log.
    child
        .terminate(TERMINATED_EXIT_CODE)
        .map_err(|error| ExecutionError::WindowsJob(error.to_string()))?;
    wait_for_empty_job(&child).await?;
    drop(child);
    sync_file(&stdout_path).await?;
    sync_file(&stderr_path).await?;
    sync_directory(&spool)?;
    sync_directory(&workspace)?;

    Ok(ExecutionOutcome {
        termination,
        exit_code: status.code(),
        process_id,
        containment: Containment::WindowsJobObject,
        stdout: spool_entry(&request.workspace, "spool/stdout.log", 0, &stdout_path).await?,
        stderr: spool_entry(&request.workspace, "spool/stderr.log", 1, &stderr_path).await?,
    })
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

async fn terminate_job(child: &JobProcess) -> Result<ExitStatus, ExecutionError> {
    child
        .terminate(TERMINATED_EXIT_CODE)
        .map_err(|error| ExecutionError::WindowsJob(error.to_string()))?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| ExecutionError::WindowsJob(error.to_string()))?
        {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err(ExecutionError::WindowsJob(
                "terminated process did not become waitable within five seconds".to_owned(),
            ));
        }
        sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_for_empty_job(job: &JobProcess) -> Result<(), ExecutionError> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let active = job
            .active_processes()
            .map_err(|error| ExecutionError::WindowsJob(error.to_string()))?;
        if active == 0 {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(ExecutionError::WindowsJob(format!(
                "terminated Job Object still contains {active} process(es)"
            )));
        }
        sleep(Duration::from_millis(10)).await;
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;

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
            timeout: Duration::from_secs(10),
            termination_grace: Duration::from_millis(100),
        }
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
    async fn cancellation_kills_the_job_object_process_tree() {
        let root = tempfile::tempdir().unwrap();
        let script = root.path().join("tree.ps1");
        fs::write(
            &script,
            r#"
$child = Start-Process powershell.exe -PassThru -ArgumentList @(
  "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 30"
)
$child.Id | Set-Content -Encoding ascii child.pid
Wait-Process -Id $child.Id
"#,
        )
        .unwrap();
        let request = request(
            root.path(),
            "cancel",
            ExecutionMode::PowerShell,
            script,
            Vec::new(),
        );
        let token = CancellationToken::new();
        let cancel = token.clone();
        let pid_path = root.path().join("cancel/child.pid");
        let cancellation = tokio::spawn(async move {
            for _ in 0..1_500 {
                if pid_path.exists() {
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
        let child_pid = fs::read_to_string(root.path().join("cancel/child.pid"))
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
}
