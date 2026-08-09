#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::Path;

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

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
