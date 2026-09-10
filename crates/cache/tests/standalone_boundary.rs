use std::io::Write as _;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::process::{Command, Stdio};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use mcloving_cache::{
    CacheConfig, CacheError, CacheKeyRequest, CacheKind, CachePolicy, FrameReadError,
    derive_generation_sha256, load_config, read_bounded_frame, serialized_response_fits_frame,
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
        max_audit_events: 1_024,
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
        generation_sha256: derive_generation_sha256(&config).unwrap(),
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
    #[cfg(unix)]
    if config_path.exists() {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    std::fs::write(&config_path, serde_json::to_vec(config).unwrap()).unwrap();
    std::fs::write(&key_path, receipt_key).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o400)).unwrap();
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
            "operation": "verify_audit",
            "caller_id": "operator",
            "expected_events": 0,
            "expected_head_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
        }),
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
    assert_eq!(responses[0]["status"], "audit_verified");
    assert_eq!(responses[0]["events"], 0);
    assert_eq!(responses[1]["status"], "read");
    assert_eq!(responses[1]["outcome"], "miss");
    assert_eq!(responses[2]["status"], "published");
    assert_eq!(responses[2]["outcome"], "published");
    assert_eq!(responses[3]["status"], "read");
    assert_eq!(responses[3]["outcome"], "hit");
    assert_eq!(responses[3]["content_base64"], BASE64.encode(b"sealed"));
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
fn mutable_configuration_fails_before_state_creation() {
    let binary_path = env!("CARGO_BIN_EXE_mcloving-cache");
    let binary = std::fs::read(binary_path).unwrap();
    let receipt_key = [24_u8; 32];
    let temp = private_temp();
    let (config, _) = fixture(&temp, &binary, &receipt_key);
    let (config_path, key_path) = write_fixture(&temp, &config, &receipt_key);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let output = Command::new(binary_path)
        .args(["--config", &config_path, "--receipt-key", &key_path])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    assert!(!temp.path().join("cache.sqlite3").exists());
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
    let mut unterminated = std::io::Cursor::new(b"ok".as_slice());
    assert_eq!(
        read_bounded_frame(&mut unterminated, 4),
        Err(FrameReadError::Unterminated)
    );
}

#[test]
fn config_rejects_a_frame_too_small_for_a_committed_receipt_batch() {
    let receipt_key = [23_u8; 32];
    let temp = private_temp();
    let (mut config, _) = fixture(&temp, b"binary", &receipt_key);
    config.max_frame_bytes = (config.max_cleanup_rows + 1) * 4 * 1_024;
    let config_path = temp.path().join("undersized-frame.json");
    std::fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o400)).unwrap();
    }
    assert!(matches!(
        load_config(&config_path),
        Err(CacheError::InvalidConfig)
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn sealed_actual_cache_uses_running_bytes_and_config_pin_precedes_state_open() {
    use nix::fcntl::{FcntlArg, FdFlag, SealFlag, fcntl};
    use std::os::fd::AsRawFd as _;
    let binary = std::fs::read(env!("CARGO_BIN_EXE_mcloving-cache")).unwrap();
    let fd = nix::sys::memfd::memfd_create(
        "cache-actual-sealed-test",
        nix::sys::memfd::MFdFlags::MFD_ALLOW_SEALING,
    )
    .unwrap();
    let mut sealed = std::fs::File::from(fd);
    sealed.write_all(&binary).unwrap();
    fcntl(
        &sealed,
        FcntlArg::F_ADD_SEALS(
            SealFlag::F_SEAL_SEAL
                | SealFlag::F_SEAL_SHRINK
                | SealFlag::F_SEAL_GROW
                | SealFlag::F_SEAL_WRITE,
        ),
    )
    .unwrap();
    fcntl(&sealed, FcntlArg::F_SETFD(FdFlag::empty())).unwrap();
    let program = format!("/proc/self/fd/{}", sealed.as_raw_fd());
    for substituted in [false, true] {
        let root = private_temp();
        let key = [42u8; 32];
        let (config, request) = fixture(&root, &binary, &key);
        let (config_path, key_path) = write_fixture(&root, &config, &key);
        let expected = if substituted {
            "f".repeat(64)
        } else {
            mcloving_cache::configuration_sha256(&config).unwrap()
        };
        let mut child = Command::new(&program)
            .args([
                "--config",
                &config_path,
                "--receipt-key",
                &key_path,
                "--expected-config-sha256",
                &expected,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if !substituted {
            let mut stdin = child.stdin.take().unwrap();
            writeln!(stdin,"{}",json!({"operation":"read","caller_id":"reader","caller_trust_class":"trusted","key":request})).unwrap();
        }
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.success(), !substituted);
        assert!(output.stderr.is_empty());
        if substituted {
            assert!(output.stdout.is_empty());
            assert!(!Path::new(&config.database_path).exists());
        } else {
            let response: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(response["outcome"], "miss");
            assert_eq!(
                response["receipts"][0]["event"]["implementation_sha256"],
                digest(&binary)
            );
        }
    }
}

#[test]
fn pure_client_authenticates_all_receipts_and_rejects_content_or_scope_substitution() {
    use mcloving_cache::{CacheCommand, CacheStore, Clock, SystemClock, verify_operation_response};
    let root = private_temp();
    let key = [43u8; 32];
    let (config, request) = fixture(&root, b"binary", &key);
    let store = CacheStore::open(config.clone(), key.to_vec()).unwrap();
    let start = SystemClock.now_unix_ms().unwrap();
    let command = CacheCommand::Publish {
        caller_id: "writer".into(),
        caller_trust_class: "trusted".into(),
        key: request.clone(),
        content_base64: BASE64.encode(b"private"),
    };
    let response = command.execute(&store, "operator");
    let mut frame = serde_json::to_vec(&response).unwrap();
    frame.push(b'\n');
    let now = SystemClock.now_unix_ms().unwrap();
    let verify = |bytes: &[u8]| {
        verify_operation_response(
            &config,
            &key,
            "writer",
            "trusted",
            &request,
            Some(b"private"),
            bytes,
            start,
            now,
        )
    };
    assert_eq!(verify(&frame).unwrap().outcome, "published");
    for field in ["signature", "event_sha256"] {
        let mut v: Value = serde_json::from_slice(&frame).unwrap();
        v["receipts"][0][field] = json!("substituted");
        let mut bytes = serde_json::to_vec(&v).unwrap();
        bytes.push(b'\n');
        assert!(verify(&bytes).is_err());
    }
    let mut wrong = request.clone();
    wrong.logical_key_sha256 = "f".repeat(64);
    assert!(
        verify_operation_response(
            &config,
            &key,
            "writer",
            "trusted",
            &wrong,
            Some(b"private"),
            &frame,
            start,
            now
        )
        .is_err()
    );
    assert!(
        verify_operation_response(
            &config,
            &key,
            "writer",
            "trusted",
            &request,
            Some(b"different"),
            &frame,
            start,
            now
        )
        .is_err()
    );
    let mut trailing = frame.clone();
    trailing.extend_from_slice(b"{}\n");
    assert!(verify(&trailing).is_err());
    let mut unknown: Value = serde_json::from_slice(&frame).unwrap();
    unknown["extra"] = json!(true);
    let mut bytes = serde_json::to_vec(&unknown).unwrap();
    bytes.push(b'\n');
    assert!(verify(&bytes).is_err());
    let duplicate = String::from_utf8(frame.clone()).unwrap().replacen(
        "\"status\":",
        "\"status\":\"published\",\"status\":",
        1,
    );
    assert!(verify(duplicate.as_bytes()).is_err());
    let read = CacheCommand::Read {
        caller_id: "reader".into(),
        caller_trust_class: "trusted".into(),
        key: request.clone(),
    }
    .execute(&store, "operator");
    let mut read_value = serde_json::to_value(read).unwrap();
    let mut read_frame = serde_json::to_vec(&read_value).unwrap();
    read_frame.push(b'\n');
    assert_eq!(
        verify_operation_response(
            &config,
            &key,
            "reader",
            "trusted",
            &request,
            None,
            &read_frame,
            start,
            SystemClock.now_unix_ms().unwrap()
        )
        .unwrap()
        .outcome,
        "hit"
    );
    read_value["content_base64"] = json!(BASE64.encode(b"forged"));
    let mut bad = serde_json::to_vec(&read_value).unwrap();
    bad.push(b'\n');
    assert!(
        verify_operation_response(
            &config,
            &key,
            "reader",
            "trusted",
            &request,
            None,
            &bad,
            start,
            SystemClock.now_unix_ms().unwrap()
        )
        .is_err()
    );
}

#[test]
fn pure_client_checks_principal_time_outcome_and_every_multi_receipt_link() {
    use mcloving_cache::{CacheCommand, CacheStore, Clock, SystemClock, verify_operation_response};
    let root = private_temp();
    let key = [44u8; 32];
    let (mut config, mut request) = fixture(&root, b"binary", &key);
    config.policies[0].max_entries = 4;
    request.generation_sha256 = derive_generation_sha256(&config).unwrap();
    let store = CacheStore::open(config.clone(), key.to_vec()).unwrap();
    for index in 0..3 {
        request.logical_key_sha256 = digest(format!("prior-{index}").as_bytes());
        store
            .publish("writer", "trusted", &request, &[index; 20])
            .unwrap();
    }
    request.logical_key_sha256 = digest(b"large-entry");
    let publication = [9u8; 32];
    let start = SystemClock.now_unix_ms().unwrap();
    let response = CacheCommand::Publish {
        caller_id: "writer".into(),
        caller_trust_class: "trusted".into(),
        key: request.clone(),
        content_base64: BASE64.encode(publication),
    }
    .execute(&store, "operator");
    let value = serde_json::to_value(response).unwrap();
    assert_eq!(value["receipts"].as_array().unwrap().len(), 3);
    let encode = |value: &Value| {
        let mut bytes = serde_json::to_vec(value).unwrap();
        bytes.push(b'\n');
        bytes
    };
    let frame = encode(&value);
    let now = SystemClock.now_unix_ms().unwrap();
    let verify = |bytes: &[u8]| {
        verify_operation_response(
            &config,
            &key,
            "writer",
            "trusted",
            &request,
            Some(&publication),
            bytes,
            start,
            now,
        )
    };
    assert!(verify(&frame).unwrap().succeeded);
    for (caller, trust) in [("reader", "trusted"), ("writer", "untrusted")] {
        assert!(
            verify_operation_response(
                &config,
                &key,
                caller,
                trust,
                &request,
                Some(&publication),
                &frame,
                start,
                now
            )
            .is_err()
        );
    }
    let mut wrong = value.clone();
    wrong["outcome"] = json!("replay");
    assert!(verify(&encode(&wrong)).is_err());
    let observed = value["receipts"][0]["event"]["observed_at_unix_ms"]
        .as_i64()
        .unwrap();
    assert!(
        verify_operation_response(
            &config,
            &key,
            "writer",
            "trusted",
            &request,
            Some(&publication),
            &frame,
            observed + 1,
            observed + 2
        )
        .is_err()
    );
    let mut reversed = value.clone();
    reversed["receipts"].as_array_mut().unwrap().swap(0, 1);
    assert!(verify(&encode(&reversed)).is_err());
    let mut gap = value;
    gap["receipts"].as_array_mut().unwrap().remove(1);
    assert!(verify(&encode(&gap)).is_err());
}
