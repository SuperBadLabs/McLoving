#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use mcloving_dependency_resolver::{
    AdapterConfig, CertifiedConfig, Ecosystem, LoadedAuthorities, RepositoryConfig,
    RepositoryGrant, ResolverLimits,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

struct Fixture {
    _root: TempDir,
    config: CertifiedConfig,
    credential_path: PathBuf,
    marker_path: PathBuf,
    credential: Vec<u8>,
    attestation: Vec<u8>,
    ca: Vec<u8>,
    receipt: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let root = TempDir::new().expect("temporary authority root");
        let credential = b"contained-repository-credential".to_vec();
        let attestation = vec![7_u8; 32];
        let ca = b"contained-private-ca".to_vec();
        let receipt = b"contained-receipt-key-material-v1".to_vec();
        let marker = marker_document(&[&credential, &receipt]);
        let credential_path = authority_file(root.path(), "repository.credential", &credential);
        let attestation_path = authority_file(root.path(), "repository.pub", &attestation);
        let ca_path = authority_file(root.path(), "repository.ca", &ca);
        let receipt_path = authority_file(root.path(), "receipt.key", &receipt);
        let marker_path = authority_file(root.path(), "markers.json", &marker);
        fs::create_dir(root.path().join("output")).expect("output root");
        fs::create_dir(root.path().join("transport")).expect("transport root");
        let config = CertifiedConfig {
            schema_version: "mcloving.dependency-config/v1".to_owned(),
            protocol_version: "mcloving.dependency-resolver/v1".to_owned(),
            configuration_id: "authority-test".to_owned(),
            deployment_id: "contained".to_owned(),
            operator_id: "test-operator".to_owned(),
            generation: 1,
            executable_sha256: "a".repeat(64),
            resolver_toolchain_id: "contained-toolchain".to_owned(),
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
                repository_id: "contained-maven".to_owned(),
                ecosystem: Ecosystem::Maven,
                base_url: "https://127.0.0.1:18443/repository/".to_owned(),
                coordinate_prefixes: vec!["com.example:".to_owned()],
                credential_path: Some(path_string(&credential_path)),
                credential_sha256: Some(sha256(&credential)),
                permits_untrusted_source: false,
                attestation_key_id: "contained-key".to_owned(),
                attestation_key_path: path_string(&attestation_path),
                attestation_key_sha256: sha256(&attestation),
                private_ca_path: Some(path_string(&ca_path)),
                private_ca_sha256: Some(sha256(&ca)),
                grant: Some(RepositoryGrant {
                    grant_id: "contained-grant".to_owned(),
                    version: 1,
                    scope: "read:com.example".to_owned(),
                    expires_at_unix_ms: 100,
                }),
            }],
            receipt_key_id: "receipt-v1".to_owned(),
            receipt_key_path: path_string(&receipt_path),
            receipt_key_sha256: sha256(&receipt),
            secret_marker_set_path: path_string(&marker_path),
            secret_marker_set_sha256: sha256(&marker),
            output_root: path_string(&root.path().join("output")),
            transport_root: path_string(&root.path().join("transport")),
            limits: ResolverLimits {
                max_frame_bytes: 1_048_576,
                max_lock_bytes: 262_144,
                max_repositories: 4,
                max_nodes: 100,
                max_edges: 1_000,
                max_artifacts: 100,
                max_artifact_bytes: 1_024,
                max_total_artifact_bytes: 4_096,
                transport_capacity_bytes: 4_096,
                max_path_bytes: 4_096,
                max_header_bytes: 16_384,
                max_request_lifetime_ms: 10_000,
            },
            loopback_fixture: false,
        };
        Self {
            _root: root,
            config,
            credential_path,
            marker_path,
            credential,
            attestation,
            ca,
            receipt,
        }
    }
}

#[test]
fn exact_private_authorities_are_loaded_without_exposure() {
    let fixture = Fixture::new();
    let loaded = LoadedAuthorities::load(&fixture.config).expect("authority load");
    assert_eq!(loaded.receipt_key(), fixture.receipt);
    assert_eq!(
        loaded.repository_credential("contained-maven"),
        Some(fixture.credential.as_slice())
    );
    assert_eq!(
        loaded.repository_attestation_key("contained-maven"),
        Some(fixture.attestation.as_slice())
    );
    assert_eq!(
        loaded.repository_private_ca("contained-maven"),
        Some(fixture.ca.as_slice())
    );
    assert_eq!(loaded.markers().count(), 2);
}

#[test]
fn permissive_mode_symlink_and_missing_credential_marker_fail_closed() {
    let fixture = Fixture::new();
    fs::set_permissions(&fixture.credential_path, fs::Permissions::from_mode(0o640))
        .expect("relax credential mode");
    let error = LoadedAuthorities::load(&fixture.config).expect_err("permissive mode");
    assert_eq!(error.code, "DEP_AUTHORITY_FILE_POLICY_DENIED");

    let mut fixture = Fixture::new();
    let target = fixture.credential_path.with_extension("target");
    fs::rename(&fixture.credential_path, &target).expect("move credential target");
    symlink(&target, &fixture.credential_path).expect("credential symlink");
    let error = LoadedAuthorities::load(&fixture.config).expect_err("symlink");
    assert_eq!(error.code, "DEP_AUTHORITY_READ_FAILED");

    let alternate_marker = marker_document(&[&fixture.receipt]);
    write_private(&fixture.marker_path, &alternate_marker);
    fixture.config.secret_marker_set_sha256 = sha256(&alternate_marker);
    fs::remove_file(&fixture.credential_path).expect("remove symlink");
    fs::rename(target, &fixture.credential_path).expect("restore credential");
    let error = LoadedAuthorities::load(&fixture.config).expect_err("missing marker");
    assert_eq!(error.code, "DEP_AUTHORITY_CREDENTIAL_MARKER_MISSING");
}

#[test]
fn receipt_key_strength_and_marker_membership_fail_closed() {
    let mut fixture = Fixture::new();
    let missing = marker_document(&[&fixture.credential]);
    write_private(&fixture.marker_path, &missing);
    fixture.config.secret_marker_set_sha256 = sha256(&missing);
    let error = LoadedAuthorities::load(&fixture.config).expect_err("missing receipt marker");
    assert_eq!(error.code, "DEP_AUTHORITY_RECEIPT_MARKER_MISSING");

    let mut fixture = Fixture::new();
    let weak = b"weak-receipt-key";
    let receipt_path = PathBuf::from(&fixture.config.receipt_key_path);
    write_private(&receipt_path, weak);
    fixture.config.receipt_key_sha256 = sha256(weak);
    let markers = marker_document(&[&fixture.credential, weak]);
    write_private(&fixture.marker_path, &markers);
    fixture.config.secret_marker_set_sha256 = sha256(&markers);
    let error = LoadedAuthorities::load(&fixture.config).expect_err("weak receipt key");
    assert_eq!(error.code, "DEP_AUTHORITY_RECEIPT_KEY_INVALID");
}

#[test]
fn authority_ancestor_symlink_into_mutable_root_fails_closed() {
    let mut fixture = Fixture::new();
    let output = PathBuf::from(&fixture.config.output_root);
    let aliased_receipt = output.join("aliased-receipt.key");
    write_private(&aliased_receipt, &fixture.receipt);
    let alias = fixture._root.path().join("authority-alias");
    symlink(&output, &alias).expect("authority ancestor alias");
    fixture.config.receipt_key_path = path_string(&alias.join("aliased-receipt.key"));

    let error = LoadedAuthorities::load(&fixture.config).expect_err("resolved mutable authority");
    assert_eq!(error.code, "DEP_CONFIG_AUTHORITY_ROOT_OVERLAP");
}

#[test]
fn authority_hard_link_inside_mutable_root_fails_closed() {
    let fixture = Fixture::new();
    let mutable_receipts = PathBuf::from(&fixture.config.output_root).join("receipts");
    fs::create_dir(&mutable_receipts).expect("mutable receipts directory");
    fs::hard_link(
        &fixture.config.receipt_key_path,
        mutable_receipts.join("exposed-receipt.key"),
    )
    .expect("hard-linked authority alias");

    let error = LoadedAuthorities::load(&fixture.config).expect_err("multi-linked authority");
    assert_eq!(error.code, "DEP_AUTHORITY_FILE_POLICY_DENIED");
}

#[test]
fn one_authority_inode_cannot_serve_receipt_and_credential_roles() {
    let mut fixture = Fixture::new();
    fixture.config.repositories[0].credential_path = Some(fixture.config.receipt_key_path.clone());
    fixture.config.repositories[0].credential_sha256 =
        Some(fixture.config.receipt_key_sha256.clone());

    let error = LoadedAuthorities::load(&fixture.config).expect_err("cross-role inode alias");
    assert_eq!(error.code, "DEP_AUTHORITY_ROLE_ALIAS_DENIED");
}

#[test]
fn one_authority_value_cannot_serve_receipt_and_credential_roles() {
    let mut fixture = Fixture::new();
    let copied_receipt = authority_file(
        fixture._root.path(),
        "copied-receipt.credential",
        &fixture.receipt,
    );
    fixture.config.repositories[0].credential_path = Some(path_string(&copied_receipt));
    fixture.config.repositories[0].credential_sha256 = Some(sha256(&fixture.receipt));

    let error = LoadedAuthorities::load(&fixture.config).expect_err("cross-role content alias");
    assert_eq!(error.code, "DEP_AUTHORITY_ROLE_CONTENT_ALIAS_DENIED");
}

fn authority_file(root: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = root.join(name);
    write_private(&path, bytes);
    path
}

fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("write authority fixture");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("private authority mode");
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn marker_document(markers: &[&[u8]]) -> Vec<u8> {
    let mut markers = markers.iter().map(|value| hex(value)).collect::<Vec<_>>();
    markers.sort();
    format!(
        r#"{{"schema_version":"mcloving.secret-markers/v1","markers_hex":[{}]}}"#,
        markers
            .iter()
            .map(|value| format!(r#""{value}""#))
            .collect::<Vec<_>>()
            .join(",")
    )
    .into_bytes()
}

fn path_string(path: &Path) -> String {
    path.to_str().expect("UTF-8 test path").to_owned()
}
