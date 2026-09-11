//! Container stage support (PAR-011): the scheduling capability an agent
//! advertises only when its deployment-pinned podman actually answers, and
//! the recovery-time reap of a container whose client the agent lost.

use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use crate::AgentConfig;

const PINNED_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const PROBE_DEADLINE: Duration = Duration::from_secs(10);
const REAP_DEADLINE: Duration = Duration::from_secs(60);

/// `container-podman-v1` when a podman path is configured and `--version`
/// succeeds within a bounded time under the same minimal environment the
/// executor will give it; otherwise nothing, reported once per process.
pub(crate) fn scheduling_capabilities(config: &AgentConfig) -> Vec<String> {
    let Some(runtime) = &config.podman_path else {
        return Vec::new();
    };
    if !cfg!(unix) {
        return Vec::new();
    }
    if runtime_answers(runtime) {
        vec![mcloving_domain::container::CONTAINER_CAPABILITY.to_owned()]
    } else {
        // Session opens repeat on every reconnect; the report is worth one
        // line per process, not one per reconnect.
        static REPORTED: std::sync::Once = std::sync::Once::new();
        REPORTED.call_once(|| {
            eprintln!(
                "container runtime {} did not answer --version within {}s; \
                 container-podman-v1 is not advertised",
                runtime.display(),
                PROBE_DEADLINE.as_secs()
            );
        });
        Vec::new()
    }
}

/// The name the executor gives step `ordinal` of `attempt_id`'s container.
pub(crate) fn container_name(attempt_id: &str, ordinal: u32) -> String {
    format!("mcloving-{attempt_id}-{ordinal}")
}

/// Removes a recovered attempt's container and proves it gone (PAR-011).
///
/// Restart recovery terminates the journaled process group, which is only
/// the podman client; the container it started outlives that client. The
/// journal recorded the container's name before the spawn, so only attempts
/// that actually launched one reach here. Returns `true` only when
/// `container exists` answers "no" afterwards; any other outcome leaves
/// containment unverified and the caller parks the attempt.
pub(crate) fn reap_recovered_container(runtime: &Path, name: &str) -> bool {
    let removed = bounded_status(
        runtime_command(runtime).args(["rm", "--force", "--ignore", name]),
        REAP_DEADLINE,
    );
    if !removed.is_some_and(|status| status.success()) {
        return false;
    }
    bounded_status(
        runtime_command(runtime).args(["container", "exists", name]),
        PROBE_DEADLINE,
    )
    .is_some_and(|status| status.code() == Some(1))
}

fn runtime_answers(runtime: &Path) -> bool {
    bounded_status(runtime_command(runtime).arg("--version"), PROBE_DEADLINE)
        .is_some_and(|status| status.success())
}

fn runtime_command(runtime: &Path) -> Command {
    let mut command = Command::new(runtime);
    command
        .env_clear()
        .env("PATH", PINNED_PATH)
        .envs(std::env::vars().filter(|(key, _)| {
            matches!(key.as_str(), "HOME" | "XDG_RUNTIME_DIR" | "USER" | "TMPDIR")
        }))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

/// Runs a command with a hard deadline: a stalled runtime is killed and
/// reported as no answer rather than blocking session open or recovery.
fn bounded_status(command: &mut Command, deadline: Duration) -> Option<ExitStatus> {
    let mut child = command.spawn().ok()?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if started.elapsed() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{bounded_status, container_name, runtime_answers};
    use std::path::Path;
    use std::process::Command;
    use std::time::Duration;

    #[test]
    fn a_missing_runtime_does_not_answer() {
        assert!(!runtime_answers(Path::new("/nonexistent/podman")));
    }

    #[cfg(unix)]
    #[test]
    fn a_runtime_that_exits_nonzero_does_not_answer() {
        assert!(!runtime_answers(Path::new("/bin/false")));
    }

    #[cfg(unix)]
    #[test]
    fn a_runtime_that_exits_zero_answers() {
        assert!(runtime_answers(Path::new("/bin/true")));
    }

    #[cfg(unix)]
    #[test]
    fn a_stalled_runtime_is_killed_at_the_deadline() {
        let started = std::time::Instant::now();
        let status = bounded_status(
            Command::new("/bin/sleep").arg("30"),
            Duration::from_millis(300),
        );
        assert!(status.is_none());
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn container_names_bind_attempt_and_step() {
        assert_eq!(
            container_name("2b3a5a1e-0000-4000-8000-000000000001", 2),
            "mcloving-2b3a5a1e-0000-4000-8000-000000000001-2"
        );
    }
}
