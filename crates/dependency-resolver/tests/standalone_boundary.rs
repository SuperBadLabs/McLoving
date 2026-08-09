#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use mcloving_dependency_resolver::{
    AdapterConfig, CertifiedConfig, Ecosystem, RepositoryConfig, ResolverLimits,
    load_certified_config, verify_running_executable,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

#[test]
fn config_mode_symlink_duplicate_members_and_executable_substitution_fail_closed() {
    let root = TempDir::new().expect("standalone boundary root");
    let mut config = config();
    let path = root.path().join("resolver.json");
    write_private(&path, &serde_json::to_vec(&config).expect("config JSON"));
    assert_eq!(load_certified_config(&path).expect("valid config"), config);

    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("relaxed mode");
    assert_eq!(
        load_certified_config(&path)
            .expect_err("relaxed config mode")
            .code,
        "DEP_CONFIG_FILE_POLICY_DENIED"
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("restore mode");

    let link = root.path().join("resolver-link.json");
    symlink(&path, &link).expect("config symlink");
    assert_eq!(
        load_certified_config(&link)
            .expect_err("config symlink")
            .code,
        "DEP_CONFIG_FILE_POLICY_DENIED"
    );

    let duplicate = serde_json::to_string(&config)
        .expect("config JSON")
        .replacen(
            r#""schema_version":"mcloving.dependency-config/v1""#,
            r#""schema_version":"mcloving.dependency-config/v1","schema_version":"mcloving.dependency-config/v1""#,
            1,
        );
    write_private(&path, duplicate.as_bytes());
    assert_eq!(
        load_certified_config(&path)
            .expect_err("duplicate configuration member")
            .code,
        "DEP_CONFIG_FILE_INVALID"
    );

    write_private(&path, &serde_json::to_vec(&config).expect("config JSON"));
    assert_eq!(
        verify_running_executable(&config)
            .expect_err("executable substitution")
            .code,
        "DEP_EXECUTABLE_IDENTITY_MISMATCH"
    );
    let executable = std::env::current_exe().expect("test executable");
    config.executable_sha256 = sha256(&fs::read(executable).expect("test executable bytes"));
    verify_running_executable(&config).expect("exact running executable");
}

#[test]
fn public_verifier_keeps_the_running_inode_after_path_replacement() {
    const CHILD_ROOT: &str = "MCLOVING_EXECUTABLE_REPLACEMENT_CHILD_ROOT";

    if let Some(root) = std::env::var_os(CHILD_ROOT) {
        let root = PathBuf::from(root);
        let mut config = config();
        config.executable_sha256 =
            sha256(&fs::read("/proc/self/exe").expect("kernel-pinned running executable bytes"));
        fs::write(root.join("ready"), b"ready").expect("replacement child ready");
        wait_for_path(&root.join("continue"));
        verify_running_executable(&config)
            .expect("public verifier must retain the running executable inode");
        return;
    }

    let root = TempDir::new().expect("executable replacement root");
    let deployed = root.path().join("deployed-test");
    fs::copy(std::env::current_exe().expect("test executable"), &deployed)
        .expect("copied executable");
    let mut child = Command::new(&deployed)
        .arg("--exact")
        .arg("public_verifier_keeps_the_running_inode_after_path_replacement")
        .arg("--nocapture")
        .env(CHILD_ROOT, root.path())
        .spawn()
        .expect("replacement child");
    wait_for_path(&root.path().join("ready"));

    let replacement = root.path().join("replacement");
    fs::write(&replacement, b"different replacement bytes").expect("replacement bytes");
    fs::rename(&replacement, &deployed).expect("atomic deployment replacement");
    fs::write(root.path().join("continue"), b"continue").expect("continue child");

    let status = child.wait().expect("replacement child status");
    assert!(
        status.success(),
        "public verifier rejected its running inode"
    );
}

#[test]
fn config_fifo_and_device_are_rejected_before_blocking_open() {
    use nix::sys::stat::Mode;
    use nix::unistd::mkfifo;

    let root = TempDir::new().expect("standalone boundary root");
    let fifo = root.path().join("resolver-fifo.json");
    mkfifo(&fifo, Mode::S_IRUSR | Mode::S_IWUSR).expect("configuration fifo");

    let started = Instant::now();
    assert_eq!(
        load_certified_config(&fifo)
            .expect_err("configuration fifo")
            .code,
        "DEP_CONFIG_FILE_POLICY_DENIED"
    );
    assert!(started.elapsed() < Duration::from_secs(1));

    let started = Instant::now();
    assert_eq!(
        load_certified_config(Path::new("/dev/null"))
            .expect_err("configuration device")
            .code,
        "DEP_CONFIG_FILE_POLICY_DENIED"
    );
    assert!(started.elapsed() < Duration::from_secs(1));
}

fn config() -> CertifiedConfig {
    CertifiedConfig {
        schema_version: "mcloving.dependency-config/v1".to_owned(),
        protocol_version: "mcloving.dependency-resolver/v1".to_owned(),
        configuration_id: "standalone-boundary".to_owned(),
        deployment_id: "contained".to_owned(),
        operator_id: "operator".to_owned(),
        generation: 1,
        executable_sha256: "a".repeat(64),
        resolver_toolchain_id: "toolchain".to_owned(),
        resolver_toolchain_sha256: "b".repeat(64),
        adapters: vec![
            AdapterConfig {
                ecosystem: Ecosystem::Maven,
                adapter_id: "maven-v1".to_owned(),
                implementation_sha256: "c".repeat(64),
            },
            AdapterConfig {
                ecosystem: Ecosystem::Npm,
                adapter_id: "npm-v1".to_owned(),
                implementation_sha256: "d".repeat(64),
            },
            AdapterConfig {
                ecosystem: Ecosystem::Pypi,
                adapter_id: "pypi-v1".to_owned(),
                implementation_sha256: "e".repeat(64),
            },
        ],
        repositories: vec![RepositoryConfig {
            repository_id: "repository".to_owned(),
            ecosystem: Ecosystem::Maven,
            base_url: "https://127.0.0.1/repository/".to_owned(),
            coordinate_prefixes: vec!["com.example:".to_owned()],
            credential_path: None,
            credential_sha256: None,
            permits_untrusted_source: true,
            attestation_key_id: "key".to_owned(),
            attestation_key_path: "/authority/key.pub".to_owned(),
            attestation_key_sha256: "f".repeat(64),
            private_ca_path: Some("/authority/ca.pem".to_owned()),
            private_ca_sha256: Some("1".repeat(64)),
            grant: None,
        }],
        source_attestation_key_id: "source-key".to_owned(),
        source_attestation_key_path: "/authority/source-key.pub".to_owned(),
        source_attestation_key_sha256: "4".repeat(64),
        receipt_key_id: "receipt-key".to_owned(),
        receipt_key_path: "/authority/receipt.key".to_owned(),
        receipt_key_sha256: "2".repeat(64),
        secret_marker_set_path: "/authority/markers.json".to_owned(),
        secret_marker_set_sha256: "3".repeat(64),
        output_root: "/var/lib/mcloving/dependencies".to_owned(),
        transport_root: "/mnt/mcloving-dependency-transport".to_owned(),
        limits: ResolverLimits {
            max_frame_bytes: 1_048_576,
            max_lock_bytes: 262_144,
            max_repositories: 4,
            max_nodes: 100,
            max_edges: 1_000,
            max_artifacts: 100,
            max_artifact_bytes: 1_048_576,
            max_total_artifact_bytes: 4_194_304,
            transport_capacity_bytes: 4_194_304,
            max_path_bytes: 4_096,
            max_header_bytes: 16_384,
            max_request_lifetime_ms: 60_000,
        },
        loopback_fixture: false,
    }
}

fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("write config fixture");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("private config mode");
}

fn wait_for_path(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        assert!(Instant::now() < deadline, "timed out waiting for {path:?}");
        thread::sleep(Duration::from_millis(10));
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
