//! Container stage support (PAR-011): the scheduling capability an agent
//! advertises only when its deployment-pinned podman actually answers, so a
//! node that names an image is never offered to an agent that cannot run it.

use std::path::Path;
use std::process::{Command, Stdio};

use crate::AgentConfig;

const PINNED_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// `container-podman-v1` when a podman path is configured and `--version`
/// succeeds under the same minimal environment the executor will give it;
/// otherwise nothing, and a configured-but-silent runtime is reported once.
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
                "container runtime {} did not answer --version; container-podman-v1 is not advertised",
                runtime.display()
            );
        });
        Vec::new()
    }
}

fn runtime_answers(runtime: &Path) -> bool {
    Command::new(runtime)
        .arg("--version")
        .env_clear()
        .env("PATH", PINNED_PATH)
        .envs(std::env::vars().filter(|(key, _)| {
            matches!(key.as_str(), "HOME" | "XDG_RUNTIME_DIR" | "USER" | "TMPDIR")
        }))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(test)]
mod tests {
    use super::runtime_answers;
    use std::path::Path;

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
}
