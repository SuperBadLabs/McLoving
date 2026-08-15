#[path = "../../test-support/diff003.rs"]
mod diff003;

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::routing::get;
use axum::{
    Router,
    body::{Body, Bytes},
    response::IntoResponse,
};
use mcloving_input_adapter::{
    AdapterConfig, AdapterError, CaptureRequest, Confidentiality, FieldSchema, InputAdapter,
    JsonKind, PROTOCOL_VERSION, content_sha256, marker_set_digest, sha256_file,
};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

const READ_TOKEN: &str = "fixture-read-token-32-bytes-minimum-value";
const WRONG_TOKEN: &str = "wrong-read-token-32-bytes-minimum-value";
const SIGNING_KEY: &[u8] = b"fixture-adapter-signing-key-32-bytes-minimum";
const SECRET_MARKER: &[u8] = b"mcloving-secret-marker-never-disclose";
const IMPLEMENTATION_SHA256: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[derive(Default)]
struct FixtureState {
    reads: AtomicUsize,
    writes: AtomicUsize,
    retry_reads: AtomicUsize,
    timeout_reads: AtomicUsize,
    body_failure_reads: AtomicUsize,
}

struct Fixture {
    endpoint: String,
    state: Arc<FixtureState>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn start_fixture() -> Fixture {
    let state = Arc::new(FixtureState::default());
    let app = Router::new()
        .route("/input", get(read_input).post(write_input))
        .with_state(Arc::clone(&state));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture");
    let address = listener.local_addr().expect("fixture address");
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve fixture");
    });
    Fixture {
        endpoint: format!("http://{address}/input"),
        state,
        task,
    }
}

async fn read_input(
    State(state): State<Arc<FixtureState>>,
    Query(query): Query<BTreeMap<String, String>>,
    headers: HeaderMap,
) -> axum::response::Response {
    state.reads.fetch_add(1, Ordering::SeqCst);
    if headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        != Some("Bearer fixture-read-token-32-bytes-minimum-value")
        || headers
            .get("x-mcloving-grant-scope")
            .and_then(|value| value.to_str().ok())
            != Some("flags:read")
    {
        return (StatusCode::UNAUTHORIZED, HeaderMap::new(), String::new()).into_response();
    }

    let mode = query.get("mode").map(String::as_str).unwrap_or("valid");
    if mode == "retry" && state.retry_reads.fetch_add(1, Ordering::SeqCst) < 2 {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            HeaderMap::new(),
            String::new(),
        )
            .into_response();
    }
    if mode == "timeout_then_valid" && state.timeout_reads.fetch_add(1, Ordering::SeqCst) == 0 {
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }
    if mode == "retry_after_expiry" {
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            HeaderMap::new(),
            String::new(),
        )
            .into_response();
    }

    let branch = query.get("branch").map(String::as_str).unwrap_or("main");
    let mut response_headers = HeaderMap::new();
    response_headers.insert("content-type", HeaderValue::from_static("application/json"));
    response_headers.insert(
        "x-mcloving-cursor",
        if mode == "blank_cursor" {
            HeaderValue::from_static("")
        } else {
            HeaderValue::from_str(&format!("{branch}-cursor-v1")).expect("cursor")
        },
    );
    response_headers.insert(
        "x-mcloving-observed-at-ms",
        HeaderValue::from_str(&match mode {
            "stale" | "stale_oversized" => (now_ms() - 60_000).to_string(),
            "future_oversized" => (now_ms() + 60_000).to_string(),
            "minimum_timestamp" => i64::MIN.to_string(),
            _ => now_ms().to_string(),
        })
        .expect("observed time"),
    );
    response_headers.insert(
        "x-mcloving-confidentiality",
        HeaderValue::from_static(if mode == "secret" {
            "secret"
        } else {
            "internal"
        }),
    );
    if mode == "header_marker" {
        response_headers.insert(
            "x-mcloving-provenance",
            HeaderValue::from_bytes(SECRET_MARKER).expect("marker header"),
        );
    } else if mode == "blank_provenance" {
        response_headers.insert("x-mcloving-provenance", HeaderValue::from_static("   "));
    } else if mode != "missing_provenance" {
        response_headers.insert(
            "x-mcloving-provenance",
            HeaderValue::from_static("fixture://flags/v1"),
        );
    }
    response_headers.insert("etag", HeaderValue::from_static("\"fixture-v1\""));
    match mode {
        "duplicate_content_type" => response_headers.append(
            "content-type",
            HeaderValue::from_static("application/octet-stream"),
        ),
        "duplicate_cursor" => response_headers.append(
            "x-mcloving-cursor",
            HeaderValue::from_static("conflicting-cursor"),
        ),
        "duplicate_provenance" => response_headers.append(
            "x-mcloving-provenance",
            HeaderValue::from_static("fixture://conflicting/v1"),
        ),
        "duplicate_observed_at" => {
            response_headers.append("x-mcloving-observed-at-ms", HeaderValue::from_static("0"))
        }
        "duplicate_confidentiality" => response_headers.append(
            "x-mcloving-confidentiality",
            HeaderValue::from_static("secret"),
        ),
        "duplicate_etag" => {
            response_headers.append("etag", HeaderValue::from_static("\"conflicting\""))
        }
        _ => false,
    };

    let body = match mode {
        "malformed" => "{".to_owned(),
        "oversized" | "stale_oversized" | "future_oversized" => {
            json!({"enabled": true, "value": "x".repeat(4_096)}).to_string()
        }
        "wrong_schema" => json!({"enabled": "yes", "value": branch}).to_string(),
        "marker" | "secret" => json!({
            "enabled": true,
            "value": String::from_utf8_lossy(SECRET_MARKER)
        })
        .to_string(),
        "escaped_marker" => {
            r#"{"enabled":true,"value":"mcloving-secret-marker-never-\u0064isclose"}"#.to_owned()
        }
        "duplicate_escaped_marker" => {
            r#"{"enabled":true,"value":"mcloving-secret-marker-never-\u0064isclose","value":"safe"}"#.to_owned()
        }
        "precise_number" => {
            r#"{"enabled":true,"value":0.123456789012345678901234567890}"#.to_owned()
        }
        _ => json!({"enabled": branch == "main", "value": branch}).to_string(),
    };
    if mode == "body_failure_then_valid"
        && state.body_failure_reads.fetch_add(1, Ordering::SeqCst) == 0
    {
        let stream = tokio_stream::iter([Err::<Bytes, _>(std::io::Error::other(
            "contained response-body reset",
        ))]);
        (StatusCode::OK, response_headers, Body::from_stream(stream)).into_response()
    } else if mode == "slow_body" {
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        let midpoint = body.len() / 2;
        let first = body[..midpoint].to_owned();
        let second = body[midpoint..].to_owned();
        tokio::spawn(async move {
            sender
                .send(Ok::<_, Infallible>(first))
                .await
                .expect("send first body chunk");
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            sender
                .send(Ok::<_, Infallible>(second))
                .await
                .expect("send second body chunk");
        });
        (
            StatusCode::OK,
            response_headers,
            Body::from_stream(ReceiverStream::new(receiver)),
        )
            .into_response()
    } else {
        (StatusCode::OK, response_headers, body).into_response()
    }
}

async fn write_input(State(state): State<Arc<FixtureState>>) -> StatusCode {
    state.writes.fetch_add(1, Ordering::SeqCst);
    StatusCode::NO_CONTENT
}

fn now_ms() -> i64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_millis();
    i64::try_from(millis).expect("timestamp")
}

fn config(endpoint: &str, spool_dir: &Path) -> AdapterConfig {
    let markers = vec![SECRET_MARKER.to_vec()];
    AdapterConfig {
        protocol_version: PROTOCOL_VERSION.to_owned(),
        schema_version: "flags/v1".to_owned(),
        adapter_id: "contained-flags".to_owned(),
        deployment_identity: "fixture-input-adapter".to_owned(),
        operator_identity: "fixture-independent-operator".to_owned(),
        generation: 1,
        endpoint_url: endpoint.to_owned(),
        endpoint_identity: "fixture-flags-service".to_owned(),
        data_source_identity: "fixture-flags-dataset".to_owned(),
        allowed_query_keys: vec!["branch".to_owned(), "mode".to_owned()],
        response_schema: vec![
            FieldSchema {
                name: "enabled".to_owned(),
                kind: JsonKind::Boolean,
                required: true,
            },
            FieldSchema {
                name: "value".to_owned(),
                kind: JsonKind::String,
                required: true,
            },
        ],
        grant_id: "fixture-read-grant".to_owned(),
        grant_version: "1".to_owned(),
        grant_scope: "flags:read".to_owned(),
        grant_expires_unix_ms: now_ms() + 60_000,
        read_token_sha256: content_sha256(READ_TOKEN.as_bytes()),
        signing_key_id: "fixture-signing-key-v1".to_owned(),
        signing_key_sha256: content_sha256(SIGNING_KEY),
        secret_marker_set_sha256: marker_set_digest(&markers),
        max_confidentiality: Confidentiality::Internal,
        max_response_bytes: 1_024,
        max_requests_per_minute: 100,
        timeout_ms: 2_000,
        max_age_ms: 5_000,
        retry_attempts: 2,
        spool_dir: spool_dir.to_path_buf(),
        ca_bundle_path: None,
        ca_bundle_sha256: None,
        test_allow_http_loopback: true,
    }
}

async fn make_adapter(config: AdapterConfig, token: &str) -> InputAdapter {
    #[cfg(unix)]
    if config.spool_dir.exists() {
        use std::os::unix::fs::PermissionsExt as _;
        tokio::fs::set_permissions(&config.spool_dir, std::fs::Permissions::from_mode(0o700))
            .await
            .expect("make test spool private");
    }
    InputAdapter::new(
        config,
        IMPLEMENTATION_SHA256.to_owned(),
        token.to_owned(),
        SIGNING_KEY.to_vec(),
        vec![SECRET_MARKER.to_vec()],
    )
    .await
    .expect("create adapter")
}

fn request(adapter: &InputAdapter, branch: &str, mode: &str) -> CaptureRequest {
    let mut query = BTreeMap::new();
    query.insert("branch".to_owned(), branch.to_owned());
    if mode != "valid" {
        query.insert("mode".to_owned(), mode.to_owned());
    }
    CaptureRequest {
        capture_id: Uuid::new_v4(),
        organization_id: Uuid::new_v4(),
        project_id: Uuid::new_v4(),
        pipeline_id: Uuid::new_v4(),
        build_id: Uuid::new_v4(),
        attempt_id: Uuid::new_v4(),
        input_name: "release_enabled".to_owned(),
        adapter_id: "contained-flags".to_owned(),
        expected_implementation_sha256: IMPLEMENTATION_SHA256.to_owned(),
        expected_config_sha256: adapter.config_sha256().to_owned(),
        protocol_version: PROTOCOL_VERSION.to_owned(),
        schema_version: "flags/v1".to_owned(),
        expected_generation: 1,
        rollback_from_generation: None,
        endpoint_identity: "fixture-flags-service".to_owned(),
        data_source_identity: "fixture-flags-dataset".to_owned(),
        grant_id: "fixture-read-grant".to_owned(),
        grant_version: "1".to_owned(),
        grant_scope: "flags:read".to_owned(),
        query,
        expected_cursor: None,
        requested_at_unix_ms: now_ms() - 10,
        expires_at_unix_ms: now_ms() + 10_000,
        confidentiality_ceiling: Confidentiality::Internal,
        audit_lineage: "audit://fixture/input-001".to_owned(),
    }
}

#[tokio::test]
async fn contained_boundary_is_typed_bounded_replay_safe_and_read_only() {
    let fixture = start_fixture().await;
    let temp = TempDir::new().expect("temp dir");
    let adapter_config = config(&fixture.endpoint, temp.path());
    let adapter = make_adapter(adapter_config.clone(), READ_TOKEN).await;

    let main_request = request(&adapter, "main", "valid");
    let main_receipt = adapter.capture(&main_request).await.expect("main capture");
    assert_eq!(main_receipt.response["enabled"], Value::Bool(true));
    assert_eq!(main_receipt.source_cursor, "main-cursor-v1");
    adapter
        .verify_receipt(&main_receipt)
        .expect("verify receipt");
    assert!(main_receipt.publication_deadline_unix_ms > main_receipt.captured_at_unix_ms);
    assert!(main_receipt.publication_deadline_unix_ms <= main_request.expires_at_unix_ms);
    assert!(main_receipt.publication_deadline_unix_ms <= adapter_config.grant_expires_unix_ms);
    let claim: Value = serde_json::from_slice(
        &tokio::fs::read(
            temp.path()
                .join(format!("{}.claim", main_receipt.capture_id)),
        )
        .await
        .expect("read durable capture claim"),
    )
    .expect("parse durable capture claim");
    assert_eq!(
        claim["request_sha256"],
        Value::String(main_receipt.request_sha256.clone())
    );
    assert_eq!(
        claim["publication_deadline_unix_ms"],
        Value::Number(main_receipt.publication_deadline_unix_ms.into())
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        assert_eq!(
            std::fs::metadata(temp.path())
                .expect("spool metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        for path in [
            temp.path().join(".coordination-v1.lock"),
            temp.path().join(".rate-v1.json"),
            temp.path()
                .join(format!("{}.claim", main_receipt.capture_id)),
            temp.path()
                .join(format!("{}.json", main_receipt.capture_id)),
        ] {
            assert_eq!(
                std::fs::metadata(&path)
                    .expect("private state metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600,
                "private mode for {}",
                path.display()
            );
        }
    }

    let dev_receipt = adapter
        .capture(&request(&adapter, "dev", "valid"))
        .await
        .expect("branch-varying capture");
    assert_eq!(dev_receipt.response["enabled"], Value::Bool(false));
    assert_ne!(main_receipt.response_sha256, dev_receipt.response_sha256);

    let restarted = make_adapter(adapter_config, READ_TOKEN).await;
    assert_eq!(
        restarted
            .capture(&main_request)
            .await
            .expect("restart replay"),
        main_receipt
    );
    let mut substituted_replay = main_request.clone();
    substituted_replay
        .query
        .insert("branch".to_owned(), "dev".to_owned());
    let replay_result = restarted.capture(&substituted_replay).await;
    let replay_denied = matches!(replay_result, Err(AdapterError::ReplayMismatch));
    assert!(replay_denied);
    diff003::record_assertion(
        "input_replay_denied",
        "denied",
        serde_json::json!({
            "capture_id": substituted_replay.capture_id,
            "substituted_branch": substituted_replay.query.get("branch"),
            "result": "replay_mismatch",
        }),
        replay_denied,
    );

    let mut wrong_binding = request(&adapter, "main", "valid");
    wrong_binding.endpoint_identity = "substituted-service".to_owned();
    assert!(matches!(
        adapter.capture(&wrong_binding).await,
        Err(AdapterError::BindingMismatch)
    ));
    let mut unauthorized_query = request(&adapter, "main", "valid");
    unauthorized_query
        .query
        .insert("write".to_owned(), "true".to_owned());
    assert!(matches!(
        adapter.capture(&unauthorized_query).await,
        Err(AdapterError::QueryDenied)
    ));

    let mut cursor_mismatch = request(&adapter, "main", "valid");
    cursor_mismatch.expected_cursor = Some("other-cursor".to_owned());
    assert!(matches!(
        adapter.capture(&cursor_mismatch).await,
        Err(AdapterError::StaleResponse)
    ));
    let mut oversized_cursor_mismatch = request(&adapter, "main", "oversized");
    oversized_cursor_mismatch.expected_cursor = Some("other-cursor".to_owned());
    assert!(matches!(
        adapter.capture(&oversized_cursor_mismatch).await,
        Err(AdapterError::StaleResponse)
    ));
    for (mode, expected) in [
        ("stale", "stale_response"),
        ("stale_oversized", "stale_response"),
        ("future_oversized", "stale_response"),
        ("minimum_timestamp", "stale_response"),
        ("missing_provenance", "missing_provenance"),
        ("blank_cursor", "missing_provenance"),
        ("blank_provenance", "missing_provenance"),
        ("malformed", "malformed_response"),
        ("wrong_schema", "malformed_response"),
        ("oversized", "oversized_response"),
        ("secret", "confidentiality_denied"),
        ("marker", "confidentiality_denied"),
        ("escaped_marker", "confidentiality_denied"),
        ("duplicate_escaped_marker", "malformed_response"),
        ("header_marker", "confidentiality_denied"),
        ("duplicate_content_type", "malformed_response"),
        ("duplicate_cursor", "missing_provenance"),
        ("duplicate_provenance", "missing_provenance"),
        ("duplicate_observed_at", "missing_provenance"),
        ("duplicate_confidentiality", "missing_provenance"),
        ("duplicate_etag", "missing_provenance"),
    ] {
        let error = adapter
            .capture(&request(&adapter, "main", mode))
            .await
            .expect_err(mode);
        assert_eq!(error.code(), expected, "mode {mode}");
        assert!(!error.to_string().contains("mcloving-secret-marker"));
    }

    let unauthorized_dir = TempDir::new().expect("unauthorized dir");
    let mut unauthorized_config = config(&fixture.endpoint, unauthorized_dir.path());
    unauthorized_config.read_token_sha256 = content_sha256(WRONG_TOKEN.as_bytes());
    let unauthorized = make_adapter(unauthorized_config, WRONG_TOKEN).await;
    assert!(matches!(
        unauthorized
            .capture(&request(&unauthorized, "main", "valid"))
            .await,
        Err(AdapterError::Unauthorized)
    ));

    let retry_receipt = adapter
        .capture(&request(&adapter, "main", "retry"))
        .await
        .expect("bounded retry");
    assert_eq!(retry_receipt.retry_count, 2);

    let body_retry_receipt = adapter
        .capture(&request(&adapter, "main", "body_failure_then_valid"))
        .await
        .expect("retry after a successful status with a failed body stream");
    assert_eq!(body_retry_receipt.retry_count, 1);

    let concurrent_request = request(&adapter, "main", "valid");
    let reads_before = fixture.state.reads.load(Ordering::SeqCst);
    let (first, second) = tokio::join!(
        adapter.capture(&concurrent_request),
        adapter.capture(&concurrent_request)
    );
    assert_eq!(
        first.expect("first capture"),
        second.expect("deduplicated capture")
    );
    assert_eq!(fixture.state.reads.load(Ordering::SeqCst) - reads_before, 1);
    assert_eq!(fixture.state.writes.load(Ordering::SeqCst), 0);

    let shared_spool = TempDir::new().expect("shared spool");
    let mut shared_config = config(&fixture.endpoint, shared_spool.path());
    shared_config.max_requests_per_minute = 1;
    shared_config.retry_attempts = 0;
    let first_process = make_adapter(shared_config.clone(), READ_TOKEN).await;
    let second_process = make_adapter(shared_config, READ_TOKEN).await;
    let cross_process_request = request(&first_process, "main", "valid");
    let reads_before = fixture.state.reads.load(Ordering::SeqCst);
    let (first, second) = tokio::join!(
        first_process.capture(&cross_process_request),
        second_process.capture(&cross_process_request)
    );
    assert_eq!(
        first.expect("first process capture"),
        second.expect("second process convergence")
    );
    assert_eq!(fixture.state.reads.load(Ordering::SeqCst) - reads_before, 1);

    let shared_rate_spool = TempDir::new().expect("shared rate spool");
    let mut shared_rate_config = config(&fixture.endpoint, shared_rate_spool.path());
    shared_rate_config.max_requests_per_minute = 1;
    shared_rate_config.retry_attempts = 0;
    let first_rate_process = make_adapter(shared_rate_config.clone(), READ_TOKEN).await;
    let second_rate_process = make_adapter(shared_rate_config, READ_TOKEN).await;
    let first_distinct = request(&first_rate_process, "main", "valid");
    let second_distinct = request(&second_rate_process, "dev", "valid");
    let reads_before = fixture.state.reads.load(Ordering::SeqCst);
    let (first, second) = tokio::join!(
        first_rate_process.capture(&first_distinct),
        second_rate_process.capture(&second_distinct)
    );
    assert!(first.is_ok() ^ second.is_ok());
    assert!(
        matches!(first, Err(AdapterError::RateLimited))
            || matches!(second, Err(AdapterError::RateLimited))
    );
    assert_eq!(fixture.state.reads.load(Ordering::SeqCst) - reads_before, 1);

    let retry_wait_spool = TempDir::new().expect("retry wait spool");
    let mut retry_wait_config = config(&fixture.endpoint, retry_wait_spool.path());
    retry_wait_config.timeout_ms = 100;
    retry_wait_config.retry_attempts = 1;
    retry_wait_config.max_requests_per_minute = 2;
    let retry_wait_adapter = make_adapter(retry_wait_config, READ_TOKEN).await;
    let retry_wait_request = request(&retry_wait_adapter, "main", "timeout_then_valid");
    let reads_before = fixture.state.reads.load(Ordering::SeqCst);
    let first = retry_wait_adapter.capture(&retry_wait_request);
    let duplicate = async {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        retry_wait_adapter.capture(&retry_wait_request).await
    };
    let (first, duplicate) = tokio::join!(first, duplicate);
    assert_eq!(
        first.expect("retrying claimant"),
        duplicate.expect("full-window duplicate waiter")
    );
    assert_eq!(fixture.state.reads.load(Ordering::SeqCst) - reads_before, 2);
    if let Ok(root) = std::env::var("MCLOVING_DIFF003_RUNTIME_OUTPUT_DIR") {
        std::fs::write(
            std::path::Path::new(&root).join("INPUT-001.json"),
            diff003::receipt(
                "INPUT-001",
                serde_json::to_value(&main_receipt).expect("encode DIFF-003 input receipt"),
            ),
        )
        .expect("write DIFF-003 input receipt");
    }
}

#[tokio::test]
async fn exact_json_number_is_preserved_in_the_signed_receipt() {
    let fixture = start_fixture().await;
    let directory = TempDir::new().expect("precise number dir");
    let mut adapter_config = config(&fixture.endpoint, directory.path());
    adapter_config.response_schema[1].kind = JsonKind::Number;
    let adapter = make_adapter(adapter_config, READ_TOKEN).await;

    let receipt = adapter
        .capture(&request(&adapter, "main", "precise_number"))
        .await
        .expect("capture exact JSON number");

    assert_eq!(
        receipt.response["value"].to_string(),
        "0.123456789012345678901234567890"
    );
    let stored = std::fs::read_to_string(
        directory
            .path()
            .join(format!("{}.json", receipt.capture_id)),
    )
    .expect("read signed receipt");
    assert!(stored.contains("0.123456789012345678901234567890"));
}

#[tokio::test]
async fn outage_rate_generation_and_rollback_are_fail_closed() {
    let fixture = start_fixture().await;
    let temp = TempDir::new().expect("temp dir");
    let mut limited_config = config(&fixture.endpoint, temp.path());
    limited_config.max_requests_per_minute = 1;
    limited_config.retry_attempts = 0;
    let limited = make_adapter(limited_config, READ_TOKEN).await;
    let duplicate_request = request(&limited, "main", "valid");
    let reads_before = fixture.state.reads.load(Ordering::SeqCst);
    let (first, duplicate) = tokio::join!(
        limited.capture(&duplicate_request),
        limited.capture(&duplicate_request)
    );
    assert_eq!(
        first.expect("first request"),
        duplicate.expect("duplicate request")
    );
    assert_eq!(fixture.state.reads.load(Ordering::SeqCst) - reads_before, 1);
    let rate_limited_request = request(&limited, "dev", "valid");
    assert!(matches!(
        limited.capture(&rate_limited_request).await,
        Err(AdapterError::RateLimited)
    ));
    assert!(
        !temp
            .path()
            .join(format!("{}.claim", rate_limited_request.capture_id))
            .exists(),
        "rate denial must not strand a capture claim"
    );

    let retry_limited_dir = TempDir::new().expect("retry-limited dir");
    let mut retry_limited_config = config(&fixture.endpoint, retry_limited_dir.path());
    retry_limited_config.max_requests_per_minute = 3;
    let retry_limited = make_adapter(retry_limited_config, READ_TOKEN).await;
    let reads_before = fixture.state.reads.load(Ordering::SeqCst);
    let retried = retry_limited
        .capture(&request(&retry_limited, "main", "retry"))
        .await
        .expect("reserved bounded retry budget");
    assert_eq!(retried.retry_count, 2);
    assert_eq!(fixture.state.reads.load(Ordering::SeqCst) - reads_before, 3);
    let denied_after_retry = request(&retry_limited, "dev", "valid");
    assert!(matches!(
        retry_limited.capture(&denied_after_retry).await,
        Err(AdapterError::RateLimited)
    ));
    assert!(
        !retry_limited_dir
            .path()
            .join(format!("{}.claim", denied_after_retry.capture_id))
            .exists(),
        "retry-budget denial must not strand a capture claim"
    );

    let distant_expiry_dir = TempDir::new().expect("distant expiry dir");
    let mut distant_expiry_config = config(&fixture.endpoint, distant_expiry_dir.path());
    distant_expiry_config.grant_expires_unix_ms = i64::MAX;
    let distant_expiry = make_adapter(distant_expiry_config, READ_TOKEN).await;
    let mut distant_request = request(&distant_expiry, "main", "valid");
    distant_request.expires_at_unix_ms = i64::MAX;
    let reads_before = fixture.state.reads.load(Ordering::SeqCst);
    distant_expiry
        .capture(&distant_request)
        .await
        .expect("claim deadline safely bounds distant authority expiry");
    assert_eq!(fixture.state.reads.load(Ordering::SeqCst) - reads_before, 1);

    let outage_dir = TempDir::new().expect("outage dir");
    let outage = make_adapter(
        config("http://127.0.0.1:9/input", outage_dir.path()),
        READ_TOKEN,
    )
    .await;
    let outage_result = outage.capture(&request(&outage, "main", "valid")).await;
    let outage_denied = matches!(outage_result, Err(AdapterError::SourceUnavailable));
    assert!(outage_denied);
    diff003::record_assertion(
        "input_outage_denied",
        "denied",
        serde_json::json!({
            "endpoint": "http://127.0.0.1:9/input",
            "result": "source_unavailable",
            "claim_exists": outage_dir.path().read_dir().unwrap().count() > 0,
        }),
        outage_denied,
    );

    let cutover_dir = TempDir::new().expect("cutover dir");
    let mut cutover_config = config(&fixture.endpoint, cutover_dir.path());
    cutover_config.generation = 2;
    cutover_config.endpoint_identity = "fixture-flags-service-v2".to_owned();
    let cutover = make_adapter(cutover_config, READ_TOKEN).await;
    let stale_request = request(&cutover, "main", "valid");
    let stale_result = cutover.capture(&stale_request).await;
    let stale_denied = matches!(stale_result, Err(AdapterError::BindingMismatch));
    assert!(stale_denied);
    diff003::record_assertion(
        "input_stale_denied",
        "denied",
        serde_json::json!({
            "presented_generation": stale_request.expected_generation,
            "active_generation": 2,
            "result": "binding_mismatch",
        }),
        stale_denied,
    );
    let mut cutover_request = request(&cutover, "main", "valid");
    cutover_request.expected_generation = 2;
    cutover_request.endpoint_identity = "fixture-flags-service-v2".to_owned();
    let cutover_receipt = cutover
        .capture(&cutover_request)
        .await
        .expect("cutover generation");
    assert_eq!(cutover_receipt.generation, 2);

    let rollback_dir = TempDir::new().expect("rollback dir");
    let mut rollback_config = config(&fixture.endpoint, rollback_dir.path());
    rollback_config.generation = 3;
    let rollback = make_adapter(rollback_config, READ_TOKEN).await;
    let mut rollback_request = request(&rollback, "main", "valid");
    rollback_request.expected_generation = 3;
    rollback_request.rollback_from_generation = Some(2);
    let rollback_receipt = rollback
        .capture(&rollback_request)
        .await
        .expect("rollback generation");
    assert_eq!(rollback_receipt.rollback_from_generation, Some(2));
}

#[tokio::test]
async fn credential_ca_and_expiry_substitution_fail_before_use() {
    let fixture = start_fixture().await;
    let temp = TempDir::new().expect("temp dir");
    let bound_config = config(&fixture.endpoint, temp.path());

    let mut relative_spool_config = bound_config.clone();
    let relative_spool =
        Path::new(&format!("relative-input-spool-{}", Uuid::new_v4())).to_path_buf();
    relative_spool_config.spool_dir = relative_spool.clone();
    assert!(matches!(
        InputAdapter::new(
            relative_spool_config,
            IMPLEMENTATION_SHA256.to_owned(),
            READ_TOKEN.to_owned(),
            SIGNING_KEY.to_vec(),
            vec![SECRET_MARKER.to_vec()],
        )
        .await,
        Err(AdapterError::InvalidConfig)
    ));
    assert!(!relative_spool.exists());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        use std::os::unix::fs::symlink;

        let permissive_spool = temp.path().join("permissive-spool");
        tokio::fs::create_dir(&permissive_spool)
            .await
            .expect("create permissive spool");
        tokio::fs::set_permissions(&permissive_spool, std::fs::Permissions::from_mode(0o755))
            .await
            .expect("set permissive mode");
        assert!(matches!(
            InputAdapter::new(
                config(&fixture.endpoint, &permissive_spool),
                IMPLEMENTATION_SHA256.to_owned(),
                READ_TOKEN.to_owned(),
                SIGNING_KEY.to_vec(),
                vec![SECRET_MARKER.to_vec()],
            )
            .await,
            Err(AdapterError::InvalidConfig)
        ));

        let symlink_target = temp.path().join("symlink-spool-target");
        tokio::fs::create_dir(&symlink_target)
            .await
            .expect("create symlink target");
        tokio::fs::set_permissions(&symlink_target, std::fs::Permissions::from_mode(0o700))
            .await
            .expect("make symlink target private");
        let symlink_spool = temp.path().join("symlink-spool");
        symlink(&symlink_target, &symlink_spool).expect("create spool symlink");
        let trailing_symlink_spool = PathBuf::from(format!("{}/", symlink_spool.display()));
        assert!(matches!(
            InputAdapter::new(
                config(&fixture.endpoint, &trailing_symlink_spool),
                IMPLEMENTATION_SHA256.to_owned(),
                READ_TOKEN.to_owned(),
                SIGNING_KEY.to_vec(),
                vec![SECRET_MARKER.to_vec()],
            )
            .await,
            Err(AdapterError::InvalidConfig)
        ));
    }
    assert!(matches!(
        InputAdapter::new(
            bound_config.clone(),
            IMPLEMENTATION_SHA256.to_owned(),
            WRONG_TOKEN.to_owned(),
            SIGNING_KEY.to_vec(),
            vec![SECRET_MARKER.to_vec()],
        )
        .await,
        Err(AdapterError::InvalidConfig)
    ));

    let invalid_header_token = format!("{READ_TOKEN}\nsubstituted");
    let invalid_header_spool = temp.path().join("invalid-header-spool");
    let mut invalid_header_config = config(&fixture.endpoint, &invalid_header_spool);
    invalid_header_config.read_token_sha256 = content_sha256(invalid_header_token.as_bytes());
    assert!(matches!(
        InputAdapter::new(
            invalid_header_config,
            IMPLEMENTATION_SHA256.to_owned(),
            invalid_header_token,
            SIGNING_KEY.to_vec(),
            vec![SECRET_MARKER.to_vec()],
        )
        .await,
        Err(AdapterError::InvalidConfig)
    ));
    assert!(
        !invalid_header_spool.exists(),
        "invalid authorization must fail before private spool creation"
    );

    let invalid_grant_spool = temp.path().join("invalid-grant-header-spool");
    let mut invalid_grant_config = config(&fixture.endpoint, &invalid_grant_spool);
    invalid_grant_config.grant_scope = "flags:read\nsubstituted".to_owned();
    assert!(matches!(
        InputAdapter::new(
            invalid_grant_config,
            IMPLEMENTATION_SHA256.to_owned(),
            READ_TOKEN.to_owned(),
            SIGNING_KEY.to_vec(),
            vec![SECRET_MARKER.to_vec()],
        )
        .await,
        Err(AdapterError::InvalidConfig)
    ));
    assert!(
        !invalid_grant_spool.exists(),
        "invalid grant header must fail before private spool creation"
    );
    assert!(matches!(
        InputAdapter::new(
            bound_config.clone(),
            IMPLEMENTATION_SHA256.to_owned(),
            READ_TOKEN.to_owned(),
            b"substituted-signing-key-32-bytes-minimum".to_vec(),
            vec![SECRET_MARKER.to_vec()],
        )
        .await,
        Err(AdapterError::InvalidConfig)
    ));

    let duplicate_marker_spool = temp.path().join("duplicate-marker-spool");
    let duplicate_markers = vec![SECRET_MARKER.to_vec(), SECRET_MARKER.to_vec()];
    let mut duplicate_marker_config = config(&fixture.endpoint, &duplicate_marker_spool);
    duplicate_marker_config.secret_marker_set_sha256 = marker_set_digest(&duplicate_markers);
    assert!(matches!(
        InputAdapter::new(
            duplicate_marker_config,
            IMPLEMENTATION_SHA256.to_owned(),
            READ_TOKEN.to_owned(),
            SIGNING_KEY.to_vec(),
            duplicate_markers,
        )
        .await,
        Err(AdapterError::InvalidConfig)
    ));
    assert!(!duplicate_marker_spool.exists());

    let marker_work_spool = temp.path().join("marker-work-spool");
    let marker_work = (0_u8..17)
        .map(|index| vec![index.saturating_add(1)])
        .collect::<Vec<_>>();
    let mut marker_work_config = config(&fixture.endpoint, &marker_work_spool);
    marker_work_config.max_response_bytes = 8 * 1_024 * 1_024;
    marker_work_config.secret_marker_set_sha256 = marker_set_digest(&marker_work);
    assert!(matches!(
        InputAdapter::new(
            marker_work_config,
            IMPLEMENTATION_SHA256.to_owned(),
            READ_TOKEN.to_owned(),
            SIGNING_KEY.to_vec(),
            marker_work,
        )
        .await,
        Err(AdapterError::InvalidConfig)
    ));
    assert!(!marker_work_spool.exists());

    let header_marker_work_spool = temp.path().join("header-marker-work-spool");
    let header_marker_work = (0_u8..5)
        .map(|index| {
            let mut marker = vec![b'x'; 1_024];
            marker[0] = index.saturating_add(1);
            marker
        })
        .collect::<Vec<_>>();
    let mut header_marker_work_config = config(&fixture.endpoint, &header_marker_work_spool);
    header_marker_work_config.max_response_bytes = 1;
    header_marker_work_config.secret_marker_set_sha256 = marker_set_digest(&header_marker_work);
    assert!(matches!(
        InputAdapter::new(
            header_marker_work_config,
            IMPLEMENTATION_SHA256.to_owned(),
            READ_TOKEN.to_owned(),
            SIGNING_KEY.to_vec(),
            header_marker_work,
        )
        .await,
        Err(AdapterError::InvalidConfig)
    ));
    assert!(!header_marker_work_spool.exists());

    let racing_spool = temp.path().join("racing-shared-spool");
    let racing_config = config(&fixture.endpoint, &racing_spool);
    let first = InputAdapter::new(
        racing_config.clone(),
        IMPLEMENTATION_SHA256.to_owned(),
        READ_TOKEN.to_owned(),
        SIGNING_KEY.to_vec(),
        vec![SECRET_MARKER.to_vec()],
    );
    let second = InputAdapter::new(
        racing_config,
        IMPLEMENTATION_SHA256.to_owned(),
        READ_TOKEN.to_owned(),
        SIGNING_KEY.to_vec(),
        vec![SECRET_MARKER.to_vec()],
    );
    let (first, second) = tokio::join!(first, second);
    assert!(first.is_ok());
    assert!(second.is_ok());

    let https_dir = TempDir::new().expect("https dir");
    let https_without_ca = config("https://inputs.example.test/v1", https_dir.path());
    assert!(matches!(
        InputAdapter::new(
            https_without_ca,
            IMPLEMENTATION_SHA256.to_owned(),
            READ_TOKEN.to_owned(),
            SIGNING_KEY.to_vec(),
            vec![SECRET_MARKER.to_vec()],
        )
        .await,
        Err(AdapterError::InvalidConfig)
    ));

    let adapter = make_adapter(bound_config, READ_TOKEN).await;
    let mut substituted_endpoint = request(&adapter, "main", "valid");
    substituted_endpoint.endpoint_identity = "substituted-input-service".to_owned();
    let endpoint_result = adapter.capture(&substituted_endpoint).await;
    let endpoint_substitution_denied =
        matches!(endpoint_result, Err(AdapterError::BindingMismatch));
    assert!(endpoint_substitution_denied);
    diff003::record_assertion(
        "input_endpoint_substitution_denied",
        "denied",
        serde_json::json!({
            "presented_endpoint_identity": substituted_endpoint.endpoint_identity,
            "result": "binding_mismatch",
            "fixture_writes": fixture.state.writes.load(Ordering::SeqCst),
        }),
        endpoint_substitution_denied,
    );
    let mut expired_request = request(&adapter, "main", "valid");
    expired_request.requested_at_unix_ms = now_ms() - 20_000;
    expired_request.expires_at_unix_ms = now_ms() - 10_000;
    assert!(matches!(
        adapter.capture(&expired_request).await,
        Err(AdapterError::ExpiredRequest)
    ));

    let expired_grant_dir = TempDir::new().expect("expired grant dir");
    let mut expired_grant_config = config(&fixture.endpoint, expired_grant_dir.path());
    expired_grant_config.grant_expires_unix_ms = now_ms() - 1;
    let expired_grant = make_adapter(expired_grant_config, READ_TOKEN).await;
    assert!(matches!(
        expired_grant
            .capture(&request(&expired_grant, "main", "valid"))
            .await,
        Err(AdapterError::ExpiredGrant)
    ));
    assert_eq!(fixture.state.writes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn freshness_is_checked_after_the_complete_body_is_captured() {
    let fixture = start_fixture().await;
    let slow_spool = TempDir::new().expect("slow spool");
    let mut slow_config = config(&fixture.endpoint, slow_spool.path());
    slow_config.max_age_ms = 25;
    let slow_adapter = make_adapter(slow_config, READ_TOKEN).await;
    assert!(matches!(
        slow_adapter
            .capture(&request(&slow_adapter, "main", "slow_body"))
            .await,
        Err(AdapterError::StaleResponse)
    ));
}

#[tokio::test]
async fn request_and_grant_must_remain_live_through_complete_capture() {
    let fixture = start_fixture().await;

    let request_spool = TempDir::new().expect("request expiry spool");
    let request_adapter =
        make_adapter(config(&fixture.endpoint, request_spool.path()), READ_TOKEN).await;
    let mut expiring_request = request(&request_adapter, "main", "slow_body");
    expiring_request.expires_at_unix_ms = now_ms() + 25;
    assert!(matches!(
        request_adapter.capture(&expiring_request).await,
        Err(AdapterError::ExpiredRequest)
    ));

    let grant_spool = TempDir::new().expect("grant expiry spool");
    let mut grant_config = config(&fixture.endpoint, grant_spool.path());
    grant_config.grant_expires_unix_ms = now_ms() + 25;
    let grant_adapter = make_adapter(grant_config, READ_TOKEN).await;
    assert!(matches!(
        grant_adapter
            .capture(&request(&grant_adapter, "main", "slow_body"))
            .await,
        Err(AdapterError::ExpiredGrant)
    ));
}

#[tokio::test]
async fn request_and_grant_are_rechecked_before_every_source_attempt() {
    let fixture = start_fixture().await;

    let request_spool = TempDir::new().expect("request retry expiry spool");
    let request_adapter =
        make_adapter(config(&fixture.endpoint, request_spool.path()), READ_TOKEN).await;
    let mut expiring_request = request(&request_adapter, "main", "retry_after_expiry");
    expiring_request.expires_at_unix_ms = now_ms() + 500;
    let reads_before_request = fixture.state.reads.load(Ordering::SeqCst);
    assert!(matches!(
        request_adapter.capture(&expiring_request).await,
        Err(AdapterError::ExpiredRequest)
    ));
    assert_eq!(
        fixture.state.reads.load(Ordering::SeqCst) - reads_before_request,
        1,
        "an expired request must not authorize a retry GET"
    );

    let grant_spool = TempDir::new().expect("grant retry expiry spool");
    let mut grant_config = config(&fixture.endpoint, grant_spool.path());
    grant_config.grant_expires_unix_ms = now_ms() + 500;
    let grant_adapter = make_adapter(grant_config, READ_TOKEN).await;
    let reads_before_grant = fixture.state.reads.load(Ordering::SeqCst);
    assert!(matches!(
        grant_adapter
            .capture(&request(&grant_adapter, "main", "retry_after_expiry"))
            .await,
        Err(AdapterError::ExpiredGrant)
    ));
    assert_eq!(
        fixture.state.reads.load(Ordering::SeqCst) - reads_before_grant,
        1,
        "an expired grant must not authorize a retry GET"
    );
}

#[tokio::test]
async fn binary_boundary_uses_files_for_secrets_and_ndjson_for_receipts() {
    let fixture = start_fixture().await;
    let temp = TempDir::new().expect("temp dir");
    let executable = Path::new(env!("CARGO_BIN_EXE_mcloving-input-adapter"));
    let implementation_sha256 = sha256_file(executable).await.expect("binary digest");
    let config_path = temp.path().join("config.json");
    let token_path = temp.path().join("read-token");
    let signing_key_path = temp.path().join("signing-key");
    let markers_path = temp.path().join("secret-markers");
    let config = config(&fixture.endpoint, &temp.path().join("spool"));
    tokio::fs::write(
        &config_path,
        serde_json::to_vec_pretty(&config).expect("serialize config"),
    )
    .await
    .expect("write config");
    tokio::fs::write(&token_path, READ_TOKEN)
        .await
        .expect("write token");
    tokio::fs::write(&signing_key_path, SIGNING_KEY)
        .await
        .expect("write signing key");
    tokio::fs::write(&markers_path, SECRET_MARKER)
        .await
        .expect("write markers");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        tokio::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o644))
            .await
            .expect("make token insecure");
        tokio::fs::set_permissions(&signing_key_path, std::fs::Permissions::from_mode(0o600))
            .await
            .expect("make signing key owner-only");
        let insecure_token_status = Command::new(executable)
            .env("MCLOVING_INPUT_ADAPTER_CONFIG", &config_path)
            .env("MCLOVING_INPUT_ADAPTER_READ_TOKEN_FILE", &token_path)
            .env("MCLOVING_INPUT_ADAPTER_SIGNING_KEY_FILE", &signing_key_path)
            .env("MCLOVING_INPUT_ADAPTER_SECRET_MARKERS_FILE", &markers_path)
            .env("MCLOVING_INPUT_ADAPTER_TEST_MODE", "1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await
            .expect("run with insecure token");
        assert!(!insecure_token_status.success());

        tokio::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600))
            .await
            .expect("make token owner-only");
        tokio::fs::set_permissions(&signing_key_path, std::fs::Permissions::from_mode(0o644))
            .await
            .expect("make signing key insecure");
        let insecure_signing_key_status = Command::new(executable)
            .env("MCLOVING_INPUT_ADAPTER_CONFIG", &config_path)
            .env("MCLOVING_INPUT_ADAPTER_READ_TOKEN_FILE", &token_path)
            .env("MCLOVING_INPUT_ADAPTER_SIGNING_KEY_FILE", &signing_key_path)
            .env("MCLOVING_INPUT_ADAPTER_SECRET_MARKERS_FILE", &markers_path)
            .env("MCLOVING_INPUT_ADAPTER_TEST_MODE", "1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await
            .expect("run with insecure signing key");
        assert!(!insecure_signing_key_status.success());

        tokio::fs::set_permissions(&signing_key_path, std::fs::Permissions::from_mode(0o600))
            .await
            .expect("make signing key owner-only");
    }

    let config_sha256 = config.canonical_digest().expect("config digest");
    let mut query = BTreeMap::new();
    query.insert("branch".to_owned(), "main".to_owned());
    let capture = CaptureRequest {
        capture_id: Uuid::new_v4(),
        organization_id: Uuid::new_v4(),
        project_id: Uuid::new_v4(),
        pipeline_id: Uuid::new_v4(),
        build_id: Uuid::new_v4(),
        attempt_id: Uuid::new_v4(),
        input_name: "release_enabled".to_owned(),
        adapter_id: config.adapter_id.clone(),
        expected_implementation_sha256: implementation_sha256,
        expected_config_sha256: config_sha256,
        protocol_version: PROTOCOL_VERSION.to_owned(),
        schema_version: config.schema_version.clone(),
        expected_generation: 1,
        rollback_from_generation: None,
        endpoint_identity: config.endpoint_identity.clone(),
        data_source_identity: config.data_source_identity.clone(),
        grant_id: config.grant_id.clone(),
        grant_version: config.grant_version.clone(),
        grant_scope: config.grant_scope.clone(),
        query,
        expected_cursor: Some("main-cursor-v1".to_owned()),
        requested_at_unix_ms: now_ms() - 10,
        expires_at_unix_ms: now_ms() + 10_000,
        confidentiality_ceiling: Confidentiality::Internal,
        audit_lineage: "audit://fixture/process-boundary".to_owned(),
    };

    let mut child = Command::new(executable)
        .env("MCLOVING_INPUT_ADAPTER_CONFIG", &config_path)
        .env("MCLOVING_INPUT_ADAPTER_READ_TOKEN_FILE", &token_path)
        .env("MCLOVING_INPUT_ADAPTER_SIGNING_KEY_FILE", &signing_key_path)
        .env("MCLOVING_INPUT_ADAPTER_SECRET_MARKERS_FILE", &markers_path)
        .env("MCLOVING_INPUT_ADAPTER_TEST_MODE", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn adapter");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut input = serde_json::to_vec(&capture).expect("capture json");
    input.push(b'\n');
    stdin.write_all(&input).await.expect("send capture");
    drop(stdin);
    let output = child.wait_with_output().await.expect("adapter output");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: Value = serde_json::from_slice(&output.stdout).expect("output envelope");
    assert_eq!(envelope["ok"], Value::Bool(true));
    assert_eq!(
        envelope["receipt"]["response"]["enabled"],
        Value::Bool(true)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("mcloving-secret-marker"));
    assert_eq!(fixture.state.writes.load(Ordering::SeqCst), 0);
}
