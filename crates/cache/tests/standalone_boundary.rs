use std::io::Write as _;
use std::process::{Command, Stdio};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use mcloving_cache::{
    CacheConfig, CacheKeyRequest, CacheKind, CachePolicy, FrameReadError, read_bounded_frame,
    serialized_response_fits_frame,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn private_temp() -> TempDir {
    let temp = TempDir::new().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    temp
}

fn fixture(temp: &TempDir, binary: &[u8], receipt_key: &[u8]) -> (CacheConfig, CacheKeyRequest) {
    let config = CacheConfig {
        protocol_version: "mcloving.cache/v1".to_owned(),
        service_id: "standalone-cache".to_owned(),
        implementation_sha256: digest(binary),
        deployment_identity: "standalone-deployment".to_owned(),
        operator_identity: "operator".to_owned(),
        cache_generation: 1,
        restore_epoch: 9,
        database_path: temp.path().join("cache.sqlite3").display().to_string(),
        receipt_key_id: "standalone-receipt-key".to_owned(),
        receipt_key_sha256: digest(receipt_key),
        max_frame_bytes: 128 * 1_024,
        max_database_bytes: 1_024,
        max_cleanup_rows: 16,
        policies: vec![CachePolicy {
            policy_id: "policy-a".to_owned(),
            tenant_id: "tenant-a".to_owned(),
            project_id: "project-a".to_owned(),
            pipeline_id: "pipeline-a".to_owned(),
            trust_class: "trusted".to_owned(),
            allowed_kinds: vec![CacheKind::Dependency],
            read_principals: vec!["reader".to_owned()],
            write_principals: vec!["writer".to_owned()],
            max_entry_bytes: 32,
            max_total_bytes: 64,
            max_entries: 2,
            ttl_ms: 60_000,
        }],
    };
    let request = CacheKeyRequest {
        policy_id: "policy-a".to_owned(),
        tenant_id: "tenant-a".to_owned(),
        project_id: "project-a".to_owned(),
        pipeline_id: "pipeline-a".to_owned(),
        trust_class: "trusted".to_owned(),
        cache_kind: CacheKind::Dependency,
        restore_epoch: 9,
        logical_key_sha256: digest(b"logical"),
        input_sha256: digest(b"input"),
        toolchain_sha256: digest(b"toolchain"),
        platform_sha256: digest(b"linux-amd64"),
    };
    (config, request)
}

fn write_fixture(temp: &TempDir, config: &CacheConfig, receipt_key: &[u8]) -> (String, String) {
    let config_path = temp.path().join("cache.json");
    let key_path = temp.path().join("receipt.key");
    std::fs::write(&config_path, serde_json::to_vec(config).unwrap()).unwrap();
    std::fs::write(&key_path, receipt_key).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    (
        config_path.display().to_string(),
        key_path.display().to_string(),
    )
}

#[test]
fn standalone_process_is_strict_bounded_and_preserves_byte_exact_hits() {
    let binary_path = env!("CARGO_BIN_EXE_mcloving-cache");
    let binary = std::fs::read(binary_path).unwrap();
    let receipt_key = [21_u8; 32];
    let temp = private_temp();
    let (config, request) = fixture(&temp, &binary, &receipt_key);
    let (config_path, key_path) = write_fixture(&temp, &config, &receipt_key);
    let mut child = Command::new(binary_path)
        .args(["--config", &config_path, "--receipt-key", &key_path])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let commands = [
        json!({
            "operation": "read",
            "caller_id": "reader",
            "caller_trust_class": "trusted",
            "key": request,
        }),
        json!({
            "operation": "publish",
            "caller_id": "writer",
            "caller_trust_class": "trusted",
            "key": request,
            "content_base64": BASE64.encode(b"sealed"),
        }),
        json!({
            "operation": "read",
            "caller_id": "reader",
            "caller_trust_class": "trusted",
            "key": request,
        }),
        json!({"operation": "verify_audit", "caller_id": "operator"}),
    ];
    for command in commands {
        serde_json::to_writer(&mut input, &command).unwrap();
        input.write_all(b"\n").unwrap();
    }
    input
        .write_all(b"{\"operation\":\"cleanup\",\"caller_id\":\"operator\",\"extra\":true}\n")
        .unwrap();
    input
        .write_all(&vec![
            b'x';
            usize::try_from(config.max_frame_bytes).unwrap() + 1
        ])
        .unwrap();
    input.write_all(b"\n").unwrap();
    drop(input);
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let responses: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(responses.len(), 6);
    assert_eq!(responses[0]["status"], "read");
    assert_eq!(responses[0]["outcome"], "miss");
    assert_eq!(responses[1]["status"], "published");
    assert_eq!(responses[1]["outcome"], "published");
    assert_eq!(responses[2]["status"], "read");
    assert_eq!(responses[2]["outcome"], "hit");
    assert_eq!(responses[2]["content_base64"], BASE64.encode(b"sealed"));
    assert_eq!(responses[3]["status"], "audit_verified");
    assert_eq!(responses[3]["events"], 3);
    assert_eq!(responses[4]["status"], "error");
    assert_eq!(responses[5]["status"], "error");
}

#[test]
fn executable_and_private_key_substitution_fail_before_state_creation() {
    let binary_path = env!("CARGO_BIN_EXE_mcloving-cache");
    let binary = std::fs::read(binary_path).unwrap();
    let receipt_key = [22_u8; 32];
    let temp = private_temp();
    let (mut config, _) = fixture(&temp, &binary, &receipt_key);
    config.implementation_sha256 = digest(b"substituted-binary");
    let (config_path, key_path) = write_fixture(&temp, &config, &receipt_key);
    let output = Command::new(binary_path)
        .args(["--config", &config_path, "--receipt-key", &key_path])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    assert!(!temp.path().join("cache.sqlite3").exists());

    config.implementation_sha256 = digest(&binary);
    let (config_path, key_path) = write_fixture(&temp, &config, &receipt_key);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let output = Command::new(binary_path)
        .args(["--config", &config_path, "--receipt-key", &key_path])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    assert!(!temp.path().join("cache.sqlite3").exists());

    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let hardlink = temp.path().join("receipt-key-hardlink");
        std::fs::hard_link(&key_path, &hardlink).unwrap();
        let output = Command::new(binary_path)
            .args(["--config", &config_path, "--receipt-key", &key_path])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
        std::fs::remove_file(hardlink).unwrap();

        let config_link = temp.path().join("config-link");
        symlink(&config_path, &config_link).unwrap();
        let output = Command::new(binary_path)
            .args([
                "--config",
                config_link.to_str().unwrap(),
                "--receipt-key",
                &key_path,
            ])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn bounded_frame_reader_discards_only_the_oversized_frame() {
    let mut input = std::io::Cursor::new(b"12345\nok\n".as_slice());
    assert_eq!(
        read_bounded_frame(&mut input, 4),
        Err(FrameReadError::Oversized)
    );
    assert_eq!(
        read_bounded_frame(&mut input, 4).unwrap(),
        Some(b"ok".to_vec())
    );
    assert!(serialized_response_fits_frame(3, 4));
    assert!(!serialized_response_fits_frame(4, 4));
}
