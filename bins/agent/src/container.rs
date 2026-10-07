//! Container stage custody: a session resolves storage once, then every
//! operation uses the exact journaled store and agent-owned configuration.
use crate::AgentConfig;
use mcloving_agent_runtime::executor::podman::{PodmanContext, validate_configuration};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const PROBE_DEADLINE: Duration = Duration::from_secs(10);
const REAP_DEADLINE: Duration = Duration::from_secs(60);
const MAX_INFO_BYTES: u64 = 65_536;

pub(crate) fn scheduling_capabilities(config: &AgentConfig) -> Vec<String> {
    if config.podman_context.is_some() {
        vec![mcloving_domain::container::CONTAINER_CAPABILITY.to_owned()]
    } else {
        Vec::new()
    }
}
pub(crate) fn container_name(attempt_id: &str, ordinal: u32) -> String {
    format!("mcloving-{attempt_id}-{ordinal}")
}

/// Discovery is the sole bootstrap command. Its info output selects the
/// effective store; the confirming probe and all later commands pin it.
pub(crate) fn resolve(config: &AgentConfig) -> Option<PodmanContext> {
    if !cfg!(unix) {
        return None;
    }
    let runtime = config.podman_path.as_deref()?;
    let configuration = config.podman_config_path.as_deref()?;
    resolve_runtime(runtime, configuration)
}

fn resolve_runtime(runtime: &Path, configuration: &Path) -> Option<PodmanContext> {
    validate_configuration(configuration).ok()?;
    let mut context = PodmanContext {
        graph_root: PathBuf::new(),
        run_root: PathBuf::new(),
        driver: String::new(),
        storage_options: Vec::new(),
        config_path: configuration.to_owned(),
        home: std::env::var_os("HOME"),
        runtime_dir: std::env::var_os("XDG_RUNTIME_DIR"),
        user: std::env::var_os("USER"),
        temporary_dir: std::env::var_os("TMPDIR"),
    };
    let mut command = Command::new(runtime);
    command.env_clear().envs(context.environment());
    // Discovery executes no workload and preserves the original HOME for
    // default rootless storage selection. All confirming/workload/teardown
    // commands use controlled HOME plus explicitly selected storage options.
    if let Some(home) = &context.home {
        command.env("HOME", home);
    } else {
        command.env_remove("HOME");
    }
    // Select the deployment's original rootless/user or system storage.conf.
    let storage_file = std::env::var_os("CONTAINERS_STORAGE_CONF")
        .map(PathBuf::from)
        .or_else(|| {
            let base = std::env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .or_else(|| {
                    context
                        .home
                        .as_ref()
                        .map(|home| PathBuf::from(home).join(".config"))
                })?;
            let file = base.join("containers/storage.conf");
            file.exists().then_some(file)
        })
        .or_else(|| {
            Path::new("/etc/containers/storage.conf")
                .exists()
                .then(|| PathBuf::from("/etc/containers/storage.conf"))
        });
    if let Some(file) = storage_file {
        command.env("CONTAINERS_STORAGE_CONF", file);
    } else {
        command.env_remove("CONTAINERS_STORAGE_CONF");
    }
    command
        .args(["info", "--format", "json"])
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    let info = bounded_output(&mut command)?;
    let value: serde_json::Value = serde_json::from_slice(&info).ok()?;
    if value.pointer("/host/security/rootless")?.as_bool() != Some(true) {
        return None;
    }
    let store = value.get("store")?;
    let (root, runroot, driver, options) = parse_store(store)?;
    context.graph_root = root;
    context.run_root = runroot;
    context.driver = driver;
    context.storage_options = options;
    // Root/driver flags discard ambient storage options. Prove that the
    // explicitly supplied options open the identical store before advertising.
    let confirmed: serde_json::Value = serde_json::from_slice(&bounded_output(
        runtime_command(runtime, &context).args(["info", "--format", "json"]),
    )?)
    .ok()?;
    if parse_store(confirmed.get("store")?)? != parse_store(store)? {
        return None;
    }
    Some(context)
}

fn parse_store(store: &serde_json::Value) -> Option<(PathBuf, PathBuf, String, Vec<String>)> {
    let root = PathBuf::from(store.get("graphRoot")?.as_str()?);
    let runroot = PathBuf::from(store.get("runRoot")?.as_str()?);
    let driver = store.get("graphDriverName")?.as_str()?.to_owned();
    if !root.is_absolute()
        || !runroot.is_absolute()
        || driver.is_empty()
        || driver.len() > 128
        || !driver
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        || store
            .get("transientStore")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    {
        return None;
    }
    let mut options = Vec::new();
    if let Some(value) = store.get("graphOptions")
        && !value.is_null()
    {
        let map = value.as_object()?;
        if map.len() > 32 {
            return None;
        }
        for (key, value) in map {
            if key.is_empty()
                || key.len() > 128
                || !key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
            {
                return None;
            }
            let value = value
                .as_str()
                .or_else(|| value.get("Executable").and_then(|v| v.as_str()))?;
            if value.len() > 4096 || value.contains(['\n', '\0']) {
                return None;
            }
            options.push(format!("{key}={value}"));
        }
    }
    options.sort();
    Some((root, runroot, driver, options))
}

pub(crate) fn recovered_container_gone(
    config: &AgentConfig,
    attempt: &mcloving_agent_runtime::ReconciliationAttempt,
) -> bool {
    let Some(name) = &attempt.container_name else {
        return true;
    };
    let Some(runtime) = &config.podman_path else {
        return false;
    };
    // Re-resolve on each recovery pass. A cached session value cannot detect
    // a later storage.conf edit, including while an agent remains connected.
    let Some(current) = resolve(config) else {
        return false;
    };
    if attempt.container_context.as_deref() != Some(current.identity(runtime).as_str()) {
        eprintln!("recovered container {name}: effective store changed; absence unproven");
        return false;
    }
    eprintln!(
        "recovered container {name}: effective store matches journal; proving original-store absence"
    );
    reap_recovered_container(runtime, &current, name)
}
fn reap_recovered_container(runtime: &Path, context: &PodmanContext, name: &str) -> bool {
    if context.validate_configuration().is_err() {
        return false;
    }
    let removed = bounded_status(
        runtime_command(runtime, context).args(["rm", "--force", "--time", "0", "--ignore", name]),
        REAP_DEADLINE,
    );
    removed.is_some_and(|status| status.success())
        && bounded_status(
            runtime_command(runtime, context).args(["container", "exists", name]),
            PROBE_DEADLINE,
        )
        .is_some_and(|status| status.code() == Some(1))
}
fn runtime_command(runtime: &Path, context: &PodmanContext) -> Command {
    let mut command = Command::new(runtime);
    command
        .args(context.arguments())
        .env_clear()
        .envs(context.environment())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}
fn bounded_status(command: &mut Command, deadline: Duration) -> Option<ExitStatus> {
    let mut child = command.spawn().ok()?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if started.elapsed() < deadline => {
                std::thread::sleep(Duration::from_millis(25))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}
fn bounded_output(command: &mut Command) -> Option<Vec<u8>> {
    bounded_output_with_deadline(command, PROBE_DEADLINE)
}

fn bounded_output_with_deadline(command: &mut Command, deadline: Duration) -> Option<Vec<u8>> {
    use std::io::Read;
    command.stdout(Stdio::piped()).stderr(Stdio::null());
    let mut child = command.spawn().ok()?;
    let stdout = child.stdout.take()?;
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout.take(MAX_INFO_BYTES + 1).read_to_end(&mut bytes);
        let _ = sender.send((result, bytes));
    });
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(None) if started.elapsed() < deadline => {
                std::thread::sleep(Duration::from_millis(25))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let (result, bytes) = receiver
        .recv_timeout(deadline.saturating_sub(started.elapsed()))
        .ok()?;
    reader.join().ok()?;
    if result.is_err() || bytes.len() as u64 > MAX_INFO_BYTES {
        None
    } else {
        Some(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn effective_store_preserves_mount_program_options_and_refuses_unknown_shapes() {
        let root = tempfile::tempdir().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let graph_root = root_path.join("graph");
        let run_root = root_path.join("run");
        let mut store = serde_json::json!({
            "graphRoot": graph_root,
            "runRoot": run_root,
            "graphDriverName": "overlay",
            "graphOptions": {
                "overlay.mount_program": {
                    "Executable": "/usr/bin/fuse-overlayfs",
                    "Version": "ignored presentation"
                }
            }
        });
        assert_eq!(
            parse_store(&store).unwrap().3,
            vec!["overlay.mount_program=/usr/bin/fuse-overlayfs"]
        );
        store["graphRoot"] = "relative".into();
        assert!(parse_store(&store).is_none());
        store["graphRoot"] = serde_json::json!(graph_root);
        store["graphOptions"]["overlay.mount_program"] = serde_json::json!({"unknown":"value"});
        assert!(parse_store(&store).is_none());
    }
    #[test]
    fn container_names_bind_attempt_and_step() {
        assert_eq!(container_name("attempt", 2), "mcloving-attempt-2");
    }
    #[cfg(unix)]
    fn fake_runtime(script: &str) -> (tempfile::TempDir, PathBuf, PathBuf) {
        use mcloving_agent_runtime::executor::podman::{
            CONTAINERS_CONFIGURATION, STORAGE_CONFIGURATION,
        };
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("controlled");
        std::fs::create_dir_all(dir.join(".config/containers")).unwrap();
        for ancestor in dir
            .join(".config/containers")
            .ancestors()
            .take_while(|p| p.starts_with(root.path()))
        {
            std::fs::set_permissions(ancestor, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        for (path, bytes) in [
            (dir.join("containers.conf"), CONTAINERS_CONFIGURATION),
            (dir.join("storage.conf"), STORAGE_CONFIGURATION),
            (dir.join(".config/containers/mounts.conf"), b"".as_slice()),
        ] {
            std::fs::write(&path, bytes).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
        let runtime = root.path().join("runtime");
        std::fs::write(&runtime, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        (root, runtime, dir.join("containers.conf"))
    }
    #[cfg(unix)]
    #[test]
    fn discovery_refuses_missing_and_nonzero_runtimes() {
        let (_root, runtime, config) = fake_runtime("exit 1");
        assert!(resolve_runtime(&runtime, &config).is_none());
        assert!(resolve_runtime(Path::new("/nonexistent/podman"), &config).is_none());
    }
    #[cfg(unix)]
    #[test]
    fn discovery_refuses_malformed_info_and_oversize_output() {
        let (_root, runtime, config) = fake_runtime("printf not-json");
        assert!(resolve_runtime(&runtime, &config).is_none());
        let (_root, runtime, config) = fake_runtime("head -c 65537 /dev/zero");
        assert!(resolve_runtime(&runtime, &config).is_none());
    }
    #[cfg(unix)]
    #[test]
    fn discovery_confirms_an_effective_rootless_store_before_advertising() {
        let (_root, runtime, config) = fake_runtime(
            r#"printf '%s' '{"host":{"security":{"rootless":true}},"store":{"graphRoot":"/private/graph","runRoot":"/private/run","graphDriverName":"vfs","graphOptions":{}}}'"#,
        );
        let context = resolve_runtime(&runtime, &config).unwrap();
        assert_eq!(context.graph_root, Path::new("/private/graph"));
        assert_eq!(context.run_root, Path::new("/private/run"));
        assert_eq!(context.driver, "vfs");
    }
    #[cfg(unix)]
    #[test]
    fn a_stalled_discovery_is_killed_at_the_deadline() {
        let (_root, runtime, _config) = fake_runtime("exec sleep 30");
        let started = Instant::now();
        assert!(
            bounded_output_with_deadline(&mut Command::new(runtime), Duration::from_millis(300))
                .is_none()
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
