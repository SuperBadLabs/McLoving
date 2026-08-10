use std::collections::BTreeMap;
use std::fs;
#[cfg(target_os = "linux")]
use std::io::Write as _;
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
#[cfg(target_os = "linux")]
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Response, StatusCode};
use axum::routing::get;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use mcloving_destination_observer::{
    ActivationMode, CONFIG_SCHEMA_VERSION, Confidentiality, DESTINATION_STATE_SCHEMA_VERSION,
    DestinationObserver, DestinationStateBody, JsonKind, MAX_FRAME_BYTES, ObservationPhase,
    ObservationReceipt, ObservationRequest, ObserverConfig, ObserverError, ObserverLimits,
    PROTOCOL_VERSION, REQUEST_SCHEMA_VERSION, RequestAuthorization, SignedDestinationState,
    StateFieldSchema, content_sha256, destination_state_message, observation_receipt_digest,
    sign_observation_request, verify_observation_receipt,
};
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;
use uuid::Uuid;

const NOW: i64 = 2_000_000_000_000;
const TOKEN: &[u8] = b"read-only-observer-token";
const SECRET: &[u8] = b"never-publish-this-secret";

#[derive(Clone, Copy)]
enum Mode {
    Good,
    Stale,
    PredatesRequest,
    Substitute,
    Secret,
    HeaderSecret,
    OversizedHeader,
    DuplicateContentType,
    Malformed,
    Oversized,
    Unauthorized,
    UnauthorizedSecret,
    Outage,
    OutageSecret,
    Timeout,
    Slow,
    OversizedHeaderSecret,
}

struct DestinationState {
    seed: Vec<u8>,
    request: Mutex<Option<ObservationRequest>>,
    mode: Mutex<Mode>,
    cursor: AtomicU64,
    observed_at_unix_ms: AtomicI64,
    reads: AtomicU64,
}

struct Rig {
    directory: TempDir,
    observer: DestinationObserver,
    server: Arc<DestinationState>,
    request_seed: Vec<u8>,
    receipt_public_key: Vec<u8>,
    config: ObserverConfig,
    request_public_key: Vec<u8>,
    destination_public_key: Vec<u8>,
    receipt_seed: Vec<u8>,
    implementation_sha256: String,
    image_sha256: String,
}

impl Rig {
    async fn new() -> Self {
        let request_seed = vec![1_u8; 32];
        let destination_seed = vec![2_u8; 32];
        let receipt_seed = vec![3_u8; 32];
        let request_public_key = public_key(&request_seed);
        let destination_public_key = public_key(&destination_seed);
        let receipt_public_key = public_key(&receipt_seed);
        let server = Arc::new(DestinationState {
            seed: destination_seed,
            request: Mutex::new(None),
            mode: Mutex::new(Mode::Good),
            cursor: AtomicU64::new(10),
            observed_at_unix_ms: AtomicI64::new(NOW),
            reads: AtomicU64::new(0),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let application = Router::new()
            .route("/state", get(destination_handler))
            .with_state(Arc::clone(&server));
        tokio::spawn(async move { axum::serve(listener, application).await.unwrap() });

        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let implementation_sha256 = "a".repeat(64);
        let image_sha256 = "b".repeat(64);
        let marker_digests = vec![content_sha256(TOKEN), content_sha256(SECRET)];
        let config = ObserverConfig {
            schema_version: CONFIG_SCHEMA_VERSION.to_owned(),
            protocol_version: PROTOCOL_VERSION.to_owned(),
            observer_id: "observer-release-state".to_owned(),
            image_sha256: image_sha256.clone(),
            deployment_identity: "deployment/observer".to_owned(),
            operator_trust_identity: "operator/security".to_owned(),
            runtime_boundary_identity: "runtime/observer".to_owned(),
            service_identity: "service/destination-read-api".to_owned(),
            credential_issuance_path_identity: "issuer/read-only".to_owned(),
            configuration_authority_identity: "config/security".to_owned(),
            request_authority_identity: "authority/reconciler".to_owned(),
            generation: 1,
            activation_mode: ActivationMode::Current,
            previous_generation: None,
            previous_config_sha256: None,
            rollback_from_generation: None,
            endpoint_url: format!("http://{address}/state"),
            endpoint_identity: "endpoint/release-state".to_owned(),
            account_identity: "account/customer-a".to_owned(),
            resource_identity: "release/app-a".to_owned(),
            effect_class: "release_publication".to_owned(),
            state_schema_version: "release-state/v1".to_owned(),
            allowed_query_keys: vec!["release_id".to_owned()],
            response_schema: vec![StateFieldSchema {
                name: "published".to_owned(),
                kind: JsonKind::Boolean,
                required: true,
            }],
            read_grant_id: "grant/observer".to_owned(),
            read_grant_version: "7".to_owned(),
            read_grant_scope: "release:read".to_owned(),
            read_grant_expires_unix_ms: NOW + 60_000,
            read_token_sha256: content_sha256(TOKEN),
            request_authority_key_id: "request-key/1".to_owned(),
            request_authority_key_sha256: content_sha256(&request_public_key),
            destination_attestation_key_id: "destination-key/1".to_owned(),
            destination_attestation_key_sha256: content_sha256(&destination_public_key),
            receipt_signing_key_id: "receipt-key/1".to_owned(),
            receipt_signing_seed_sha256: content_sha256(&receipt_seed),
            receipt_signing_public_key_sha256: content_sha256(&receipt_public_key),
            secret_marker_set_sha256: domain_digest(
                b"mcloving-secret-marker-set-v1",
                &marker_digests,
            ),
            denied_peer_identities: vec![
                "runner/untrusted".to_owned(),
                "connector/effectful".to_owned(),
            ],
            denied_authority_sha256: vec![content_sha256(b"runner-controlled-key")],
            limits: ObserverLimits {
                max_response_bytes: 16 * 1024,
                max_header_bytes: 8 * 1024,
                max_requests_per_minute: 100,
                max_evidence_bytes: 1024 * 1024,
                max_receipts: 100,
                timeout_ms: 200,
                max_age_ms: 10_000,
                retry_attempts: 3,
            },
            state_dir: directory.path().to_path_buf(),
            ca_bundle_path: None,
            ca_bundle_sha256: None,
            test_allow_http_loopback: true,
        };
        let observer = DestinationObserver::new_for_loopback_test(
            config.clone(),
            implementation_sha256.clone(),
            image_sha256.clone(),
            TOKEN.to_vec(),
            request_public_key.clone(),
            destination_public_key.clone(),
            receipt_seed.clone(),
            vec![TOKEN.to_vec(), SECRET.to_vec()],
        )
        .unwrap();
        Self {
            directory,
            observer,
            server,
            request_seed,
            receipt_public_key,
            config,
            request_public_key,
            destination_public_key,
            receipt_seed,
            implementation_sha256,
            image_sha256,
        }
    }

    fn request(&self, phase: ObservationPhase) -> ObservationRequest {
        let mut query = BTreeMap::new();
        query.insert("release_id".to_owned(), "release-42".to_owned());
        ObservationRequest {
            schema_version: REQUEST_SCHEMA_VERSION.to_owned(),
            protocol_version: PROTOCOL_VERSION.to_owned(),
            observation_id: Uuid::new_v4(),
            tenant_id: Uuid::from_u128(1),
            project_id: Uuid::from_u128(2),
            pipeline_id: Uuid::from_u128(3),
            build_id: Uuid::from_u128(4),
            attempt_id: Uuid::from_u128(5),
            effect_fence: 17,
            phase,
            observer_id: "observer-release-state".to_owned(),
            request_authority_identity: "authority/reconciler".to_owned(),
            expected_implementation_sha256: self.implementation_sha256.clone(),
            expected_image_sha256: self.image_sha256.clone(),
            expected_config_sha256: self.observer.config_sha256().to_owned(),
            expected_generation: 1,
            activation_mode: ActivationMode::Current,
            previous_generation: None,
            rollback_from_generation: None,
            endpoint_identity: "endpoint/release-state".to_owned(),
            account_identity: "account/customer-a".to_owned(),
            resource_identity: "release/app-a".to_owned(),
            effect_class: "release_publication".to_owned(),
            read_grant_id: "grant/observer".to_owned(),
            read_grant_version: "7".to_owned(),
            read_grant_scope: "release:read".to_owned(),
            query,
            expected_previous_cursor: None,
            predecessor_receipt_sha256: None,
            requested_at_unix_ms: NOW - 1,
            expires_at_unix_ms: NOW + 1_000,
            audit_provenance: "audit/controller/42".to_owned(),
            authorization: RequestAuthorization {
                key_id: "request-key/1".to_owned(),
                signature_base64: String::new(),
            },
        }
    }

    fn prepare(&self, mut request: ObservationRequest) -> ObservationRequest {
        sign_observation_request(&mut request, &self.request_seed).unwrap();
        *self.server.request.lock().unwrap() = Some(request.clone());
        request
    }

    fn set_mode(&self, mode: Mode) {
        *self.server.mode.lock().unwrap() = mode;
    }

    fn restart(&self) -> DestinationObserver {
        self.observer_for_config(self.config.clone()).unwrap()
    }

    fn observer_for_config(
        &self,
        config: ObserverConfig,
    ) -> Result<DestinationObserver, ObserverError> {
        DestinationObserver::new_for_loopback_test(
            config,
            self.implementation_sha256.clone(),
            self.image_sha256.clone(),
            TOKEN.to_vec(),
            self.request_public_key.clone(),
            self.destination_public_key.clone(),
            self.receipt_seed.clone(),
            vec![TOKEN.to_vec(), SECRET.to_vec()],
        )
    }
}

async fn destination_handler(
    State(server): State<Arc<DestinationState>>,
    headers: HeaderMap,
) -> Response<Body> {
    let mode = *server.mode.lock().unwrap();
    if matches!(mode, Mode::Unauthorized | Mode::UnauthorizedSecret)
        || headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            != Some("Bearer read-only-observer-token")
    {
        let mut response = Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Body::empty())
            .unwrap();
        if matches!(mode, Mode::UnauthorizedSecret) {
            response.headers_mut().insert(
                "x-debug-credential",
                axum::http::HeaderValue::from_static("read-only-observer-token"),
            );
        }
        return response;
    }
    let request = server.request.lock().unwrap().clone().unwrap();
    let query_sha256 = domain_digest(b"mcloving-observer-query-v1", &request.query);
    let request_sha256 = domain_digest(b"mcloving-observer-request-digest-v1", &request);
    let valid_attestation_headers = [
        (
            "x-mcloving-observation-id",
            request.observation_id.to_string(),
        ),
        ("x-mcloving-effect-fence", request.effect_fence.to_string()),
        (
            "x-mcloving-observation-phase",
            match request.phase {
                ObservationPhase::PreAction => "pre_action",
                ObservationPhase::PostAction => "post_action",
                ObservationPhase::Reconciliation => "reconciliation",
            }
            .to_owned(),
        ),
        ("x-mcloving-query-sha256", query_sha256.clone()),
        ("x-mcloving-request-sha256", request_sha256),
    ]
    .into_iter()
    .all(|(name, expected)| {
        headers.get(name).and_then(|value| value.to_str().ok()) == Some(expected.as_str())
    });
    if !valid_attestation_headers {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::empty())
            .unwrap();
    }
    server.reads.fetch_add(1, Ordering::SeqCst);
    if matches!(mode, Mode::Malformed) {
        return json_response(StatusCode::OK, b"{\"body\":".to_vec());
    }
    if matches!(mode, Mode::Oversized) {
        return json_response(StatusCode::OK, vec![b'x'; 32 * 1024]);
    }
    if matches!(mode, Mode::Outage | Mode::OutageSecret) {
        let mut response = json_response(StatusCode::SERVICE_UNAVAILABLE, b"{}".to_vec());
        if matches!(mode, Mode::OutageSecret) {
            response.headers_mut().insert(
                "x-debug-credential",
                axum::http::HeaderValue::from_static("read-only-observer-token"),
            );
        }
        return response;
    }
    if matches!(mode, Mode::Timeout) {
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    }
    if matches!(mode, Mode::Slow) {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let mut body = DestinationStateBody {
        schema_version: DESTINATION_STATE_SCHEMA_VERSION.to_owned(),
        observation_id: request.observation_id,
        observer_id: request.observer_id.clone(),
        service_identity: "service/destination-read-api".to_owned(),
        endpoint_identity: request.endpoint_identity.clone(),
        account_identity: request.account_identity.clone(),
        resource_identity: request.resource_identity.clone(),
        effect_class: request.effect_class.clone(),
        effect_fence: request.effect_fence,
        phase: request.phase,
        canonical_query_sha256: query_sha256,
        cursor: server.cursor.load(Ordering::SeqCst),
        observed_at_unix_ms: server.observed_at_unix_ms.load(Ordering::SeqCst),
        state_schema_version: "release-state/v1".to_owned(),
        confidentiality: Confidentiality::Internal,
        state: json!({"published": true}),
        grant_id: request.read_grant_id.clone(),
        grant_version: request.read_grant_version.clone(),
        grant_scope: request.read_grant_scope.clone(),
        attestation_key_id: "destination-key/1".to_owned(),
    };
    match mode {
        Mode::Stale => body.observed_at_unix_ms = NOW - 20_000,
        Mode::PredatesRequest => {
            body.observed_at_unix_ms = request.requested_at_unix_ms - 1;
        }
        Mode::Substitute => body.resource_identity = "release/substituted".to_owned(),
        Mode::Secret => body.state = json!({"published": true, "leak": BASE64.encode(SECRET)}),
        _ => {}
    }
    let mut signed = SignedDestinationState {
        body,
        signature_base64: String::new(),
    };
    let pair = Ed25519KeyPair::from_seed_unchecked(&server.seed).unwrap();
    signed.signature_base64 =
        BASE64.encode(pair.sign(&destination_state_message(&signed).unwrap()));
    let mut response = json_response(StatusCode::OK, serde_json::to_vec(&signed).unwrap());
    if matches!(mode, Mode::HeaderSecret) {
        response.headers_mut().insert(
            "x-debug-credential",
            axum::http::HeaderValue::from_static("read-only-observer-token"),
        );
    }
    if matches!(mode, Mode::OversizedHeader | Mode::OversizedHeaderSecret) {
        response.headers_mut().insert(
            "x-oversized",
            axum::http::HeaderValue::from_str(&"x".repeat(9 * 1024)).unwrap(),
        );
    }
    if matches!(mode, Mode::OversizedHeaderSecret) {
        response.headers_mut().insert(
            "x-debug-credential",
            axum::http::HeaderValue::from_static("read-only-observer-token"),
        );
    }
    if matches!(mode, Mode::DuplicateContentType) {
        response.headers_mut().append(
            "content-type",
            axum::http::HeaderValue::from_static("text/plain"),
        );
    }
    response
}

fn json_response(status: StatusCode, bytes: Vec<u8>) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(bytes))
        .unwrap()
}

#[tokio::test]
async fn pre_post_reconciliation_receipts_are_ordered_signed_and_replay_safe() {
    let rig = Rig::new().await;
    let pre_request = rig.prepare(rig.request(ObservationPhase::PreAction));
    let pre = rig
        .observer
        .observe_at(pre_request.clone(), NOW)
        .await
        .unwrap();
    verify_observation_receipt(&pre, &rig.receipt_public_key).unwrap();
    assert_eq!(pre.destination_cursor, 10);
    assert_eq!(pre.retry_count, 0);
    assert_eq!(pre.publication_deadline_unix_ms, NOW + 1_000);

    let expired_replay = rig
        .observer
        .observe_at(pre_request.clone(), NOW + 70_000)
        .await
        .unwrap();
    assert_eq!(expired_replay, pre);

    rig.set_mode(Mode::Unauthorized);
    let replay = rig.observer.observe_at(pre_request, NOW).await.unwrap();
    assert_eq!(replay, pre);

    rig.set_mode(Mode::Good);
    rig.server.cursor.store(11, Ordering::SeqCst);
    let mut substituted_query = rig.request(ObservationPhase::PostAction);
    substituted_query
        .query
        .insert("release_id".to_owned(), "release-43".to_owned());
    substituted_query.expected_previous_cursor = Some(pre.destination_cursor);
    substituted_query.predecessor_receipt_sha256 = Some(receipt_digest(&pre));
    assert_eq!(
        rig.observer
            .observe_at(rig.prepare(substituted_query), NOW)
            .await,
        Err(ObserverError::PhaseMismatch)
    );

    let mut post_request = rig.request(ObservationPhase::PostAction);
    post_request.expected_previous_cursor = Some(pre.destination_cursor);
    post_request.predecessor_receipt_sha256 = Some(receipt_digest(&pre));
    let post = rig
        .observer
        .observe_at(rig.prepare(post_request), NOW)
        .await
        .unwrap();
    assert_eq!(post.destination_cursor, 11);

    rig.server.cursor.store(12, Ordering::SeqCst);
    let mut reconciliation_request = rig.request(ObservationPhase::Reconciliation);
    reconciliation_request.expected_previous_cursor = Some(post.destination_cursor);
    reconciliation_request.predecessor_receipt_sha256 = Some(receipt_digest(&post));
    let reconciliation = rig
        .observer
        .observe_at(rig.prepare(reconciliation_request), NOW)
        .await
        .unwrap();
    assert_eq!(reconciliation.destination_cursor, 12);
    assert_eq!(reconciliation.evidence_sequence, 3);
    verify_observation_receipt(&reconciliation, &rig.receipt_public_key).unwrap();
}

#[tokio::test]
async fn stale_substituted_secret_malformed_oversized_and_permission_denials_fail_closed() {
    for (mode, expected) in [
        (Mode::Stale, ObserverError::StaleObservation),
        (Mode::PredatesRequest, ObserverError::StaleObservation),
        (Mode::Substitute, ObserverError::MalformedResponse),
        (Mode::Secret, ObserverError::ConfidentialityDenied),
        (Mode::HeaderSecret, ObserverError::ConfidentialityDenied),
        (Mode::DuplicateContentType, ObserverError::MalformedResponse),
        (Mode::Malformed, ObserverError::MalformedResponse),
        (Mode::Oversized, ObserverError::OversizedResponse),
        (Mode::Unauthorized, ObserverError::DestinationUnauthorized),
        (
            Mode::UnauthorizedSecret,
            ObserverError::ConfidentialityDenied,
        ),
        (Mode::OutageSecret, ObserverError::ConfidentialityDenied),
        (
            Mode::OversizedHeaderSecret,
            ObserverError::ConfidentialityDenied,
        ),
    ] {
        let rig = Rig::new().await;
        rig.set_mode(mode);
        let request = rig.prepare(rig.request(ObservationPhase::PreAction));
        assert_eq!(
            rig.observer.observe_at(request.clone(), NOW).await,
            Err(expected.clone())
        );
        assert_eq!(rig.observer.observe_at(request, NOW).await, Err(expected));
        rig.set_mode(Mode::Good);
        let replacement = rig.prepare(rig.request(ObservationPhase::PreAction));
        rig.observer.observe_at(replacement, NOW).await.unwrap();
    }

    for mode in [Mode::Outage, Mode::Timeout, Mode::OversizedHeader] {
        let rig = Rig::new().await;
        rig.set_mode(mode);
        let request = rig.prepare(rig.request(ObservationPhase::PreAction));
        assert_eq!(
            rig.observer.observe_at(request, NOW).await,
            Err(ObserverError::DestinationUnavailable)
        );
        let competing = rig.prepare(rig.request(ObservationPhase::PreAction));
        assert_eq!(
            rig.observer.observe_at(competing, NOW).await,
            Err(ObserverError::ObservationPending)
        );
    }
}

#[tokio::test]
async fn restart_waits_for_the_shared_ledger_writer() {
    let rig = Rig::new().await;
    let connection =
        rusqlite::Connection::open(rig.directory.path().join("observer.sqlite3")).unwrap();
    connection.execute_batch("BEGIN IMMEDIATE").unwrap();

    let config = rig.config.clone();
    let implementation_sha256 = rig.implementation_sha256.clone();
    let image_sha256 = rig.image_sha256.clone();
    let request_public_key = rig.request_public_key.clone();
    let destination_public_key = rig.destination_public_key.clone();
    let receipt_seed = rig.receipt_seed.clone();
    let restart = std::thread::spawn(move || {
        DestinationObserver::new_for_loopback_test(
            config,
            implementation_sha256,
            image_sha256,
            TOKEN.to_vec(),
            request_public_key,
            destination_public_key,
            receipt_seed,
            vec![TOKEN.to_vec(), SECRET.to_vec()],
        )
    });
    std::thread::sleep(std::time::Duration::from_millis(100));
    connection.execute_batch("COMMIT").unwrap();
    assert!(restart.join().unwrap().is_ok());
}

#[tokio::test]
async fn authority_is_rechecked_after_store_delay_before_any_get() {
    let rig = Rig::new().await;
    let database_path = rig.directory.path().join("observer.sqlite3");
    let (ready_sender, ready_receiver) = std::sync::mpsc::channel();
    let blocker = std::thread::spawn(move || {
        let connection = rusqlite::Connection::open(database_path).unwrap();
        connection.execute_batch("BEGIN IMMEDIATE").unwrap();
        ready_sender.send(()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        connection.execute_batch("COMMIT").unwrap();
    });
    ready_receiver.recv().unwrap();

    let mut request = rig.request(ObservationPhase::PreAction);
    request.expires_at_unix_ms = NOW + 50;
    let request = rig.prepare(request);
    assert_eq!(
        rig.observer.observe_at(request, NOW).await,
        Err(ObserverError::ExpiredRequest)
    );
    blocker.join().unwrap();
    assert_eq!(rig.server.reads.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn durable_pending_claim_resumes_after_outage_and_process_restart() {
    let rig = Rig::new().await;
    rig.set_mode(Mode::Outage);
    let request = rig.prepare(rig.request(ObservationPhase::PreAction));
    assert_eq!(
        rig.observer.observe_at(request.clone(), NOW).await,
        Err(ObserverError::DestinationUnavailable)
    );
    rig.set_mode(Mode::Good);
    let restarted = rig.restart();
    let receipt = restarted.observe_at(request, NOW).await.unwrap();
    assert_eq!(receipt.retry_count, 1);
    verify_observation_receipt(&receipt, &rig.receipt_public_key).unwrap();
}

#[tokio::test]
async fn expired_pending_replay_is_tombstoned_before_destination_lease_contention() {
    let rig = Rig::new().await;
    rig.set_mode(Mode::Outage);
    let request = rig.prepare(rig.request(ObservationPhase::PreAction));
    assert_eq!(
        rig.observer.observe_at(request.clone(), NOW).await,
        Err(ObserverError::DestinationUnavailable)
    );

    let lock_path = fs::read_dir(rig.directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("destination-") && name.ends_with(".lock"))
        })
        .unwrap();
    let lease = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(lock_path)
        .unwrap();
    lease.lock().unwrap();

    assert_eq!(
        rig.observer.observe_at(request.clone(), NOW + 2_000).await,
        Err(ObserverError::ExpiredRequest)
    );
    drop(lease);

    let connection =
        rusqlite::Connection::open(rig.directory.path().join("observer.sqlite3")).unwrap();
    let status: (String, String) = connection
        .query_row(
            "SELECT status, failure_code FROM observations WHERE observation_id=?1",
            [request.observation_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(status, ("failed".to_owned(), "expired_request".to_owned()));
}

#[tokio::test]
async fn crash_gap_reservation_does_not_consume_the_destination_retry_budget() {
    let rig = Rig::new().await;
    rig.set_mode(Mode::Outage);
    let request = rig.prepare(rig.request(ObservationPhase::PreAction));
    assert_eq!(
        rig.observer.observe_at(request.clone(), NOW).await,
        Err(ObserverError::DestinationUnavailable)
    );

    // This is the durable state left by a process that reserved its outbound
    // intent but exited before a destination-unavailable outcome was recorded.
    let connection =
        rusqlite::Connection::open(rig.directory.path().join("observer.sqlite3")).unwrap();
    connection
        .execute(
            "UPDATE observations SET retry_count=0 WHERE observation_id=?1 AND status='pending'",
            [request.observation_id.to_string()],
        )
        .unwrap();
    drop(connection);

    rig.set_mode(Mode::Good);
    let receipt = rig.restart().observe_at(request, NOW).await.unwrap();
    assert_eq!(receipt.retry_count, 0);
}

#[tokio::test]
async fn outbound_retries_consume_the_durable_request_rate_budget() {
    let rig = Rig::new().await;
    let state = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut config = rig.config.clone();
    config.state_dir = state.path().to_path_buf();
    config.limits.max_requests_per_minute = 1;
    let observer = rig.observer_for_config(config).unwrap();

    rig.set_mode(Mode::Outage);
    let mut request = rig.request(ObservationPhase::PreAction);
    request.expected_config_sha256 = observer.config_sha256().to_owned();
    let request = rig.prepare(request);
    assert_eq!(
        observer.observe_at(request.clone(), NOW).await,
        Err(ObserverError::DestinationUnavailable)
    );

    rig.set_mode(Mode::Good);
    assert_eq!(
        observer.observe_at(request, NOW).await,
        Err(ObserverError::CapacityExceeded)
    );
    let connection = rusqlite::Connection::open(state.path().join("observer.sqlite3")).unwrap();
    let attempts: u64 = connection
        .query_row("SELECT COUNT(*) FROM request_attempts", [], |row| {
            row.get(0)
        })
        .unwrap();
    let retry_count: u8 = connection
        .query_row("SELECT retry_count FROM observations", [], |row| row.get(0))
        .unwrap();
    assert_eq!(attempts, 1);
    assert_eq!(retry_count, 1);
}

#[tokio::test]
async fn competing_pending_claims_do_not_starve_the_legitimate_retry_budget() {
    let rig = Rig::new().await;
    let state = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut config = rig.config.clone();
    config.state_dir = state.path().to_path_buf();
    config.limits.max_requests_per_minute = 2;
    let observer = rig.observer_for_config(config).unwrap();

    rig.set_mode(Mode::Outage);
    let mut original = rig.request(ObservationPhase::PreAction);
    original.expected_config_sha256 = observer.config_sha256().to_owned();
    let original = rig.prepare(original);
    assert_eq!(
        observer.observe_at(original.clone(), NOW).await,
        Err(ObserverError::DestinationUnavailable)
    );

    for effect_fence in 18..22 {
        let mut competing = rig.request(ObservationPhase::PreAction);
        competing.effect_fence = effect_fence;
        competing.expected_config_sha256 = observer.config_sha256().to_owned();
        let competing = rig.prepare(competing);
        assert_eq!(
            observer.observe_at(competing, NOW).await,
            Err(ObserverError::ObservationPending)
        );
    }
    let connection = rusqlite::Connection::open(state.path().join("observer.sqlite3")).unwrap();
    let attempts: u64 = connection
        .query_row("SELECT COUNT(*) FROM request_attempts", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(attempts, 1);
    drop(connection);

    rig.set_mode(Mode::Good);
    let original = rig.prepare(original);
    observer.observe_at(original, NOW).await.unwrap();
}

#[tokio::test]
async fn expired_failed_claim_frees_destination_without_consuming_receipt_capacity() {
    let rig = Rig::new().await;
    rig.set_mode(Mode::Outage);
    let failed = rig.prepare(rig.request(ObservationPhase::PreAction));
    assert_eq!(
        rig.observer.observe_at(failed, NOW).await,
        Err(ObserverError::DestinationUnavailable)
    );

    rig.set_mode(Mode::Good);
    rig.server
        .observed_at_unix_ms
        .store(NOW + 2_000, Ordering::SeqCst);
    let mut replacement = rig.request(ObservationPhase::PreAction);
    replacement.requested_at_unix_ms = NOW + 1_999;
    replacement.expires_at_unix_ms = NOW + 2_999;
    let replacement = rig.prepare(replacement);
    let receipt = rig
        .observer
        .observe_at(replacement, NOW + 2_000)
        .await
        .unwrap();
    assert_eq!(receipt.destination_cursor, 10);
}

#[tokio::test]
async fn concurrent_builds_are_serialized_before_destination_access() {
    let rig = Rig::new().await;
    rig.set_mode(Mode::Timeout);
    let first = rig.prepare(rig.request(ObservationPhase::PreAction));
    let mut second = rig.request(ObservationPhase::PreAction);
    second.effect_fence = 18;
    let second = rig.prepare(second);
    let first_observation = rig.observer.observe_at(first, NOW);
    let second_observation = async {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        rig.observer.observe_at(second, NOW).await
    };
    let (_, second_result) = tokio::join!(first_observation, second_observation);
    assert_eq!(second_result, Err(ObserverError::ObservationPending));
}

#[tokio::test]
async fn concurrent_retry_of_the_same_observation_does_not_duplicate_the_get() {
    let rig = Rig::new().await;
    rig.set_mode(Mode::Slow);
    let request = rig.prepare(rig.request(ObservationPhase::PreAction));
    let first_observation = rig.observer.observe_at(request.clone(), NOW);
    let concurrent_retry = async {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        rig.observer.observe_at(request, NOW).await
    };
    let (first_result, retry_result) = tokio::join!(first_observation, concurrent_retry);
    first_result.unwrap();
    assert_eq!(retry_result, Err(ObserverError::ObservationPending));
}

#[tokio::test]
async fn expired_retry_tombstone_wins_over_an_in_flight_transport_failure() {
    let rig = Rig::new().await;
    rig.set_mode(Mode::Timeout);
    let mut request = rig.request(ObservationPhase::PreAction);
    request.expires_at_unix_ms = NOW + 50;
    let request = rig.prepare(request);

    let first_observation = rig.observer.observe_at(request.clone(), NOW);
    let expired_retry = async {
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        rig.observer.observe_at(request, NOW + 80).await
    };
    let (first_result, retry_result) = tokio::join!(first_observation, expired_retry);

    assert_eq!(first_result, Err(ObserverError::ExpiredRequest));
    assert_eq!(retry_result, Err(ObserverError::ExpiredRequest));
}

#[tokio::test]
async fn transport_failure_that_crosses_expiry_is_immediately_tombstoned() {
    let rig = Rig::new().await;
    rig.set_mode(Mode::Timeout);
    let mut request = rig.request(ObservationPhase::PreAction);
    request.expires_at_unix_ms = NOW + 50;
    let request = rig.prepare(request);

    assert_eq!(
        rig.observer.observe_at(request.clone(), NOW).await,
        Err(ObserverError::ExpiredRequest)
    );
    assert_eq!(
        rig.observer.observe_at(request.clone(), NOW).await,
        Err(ObserverError::ExpiredRequest)
    );

    let connection =
        rusqlite::Connection::open(rig.directory.path().join("observer.sqlite3")).unwrap();
    let status: (String, String) = connection
        .query_row(
            "SELECT status, failure_code FROM observations WHERE observation_id=?1",
            [request.observation_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(status, ("failed".to_owned(), "expired_request".to_owned()));
}

#[tokio::test]
async fn completed_replay_bypasses_an_unrelated_live_destination_read() {
    let rig = Rig::new().await;
    let completed_request = rig.prepare(rig.request(ObservationPhase::PreAction));
    let completed_receipt = rig
        .observer
        .observe_at(completed_request.clone(), NOW)
        .await
        .unwrap();

    rig.server.cursor.store(11, Ordering::SeqCst);
    rig.set_mode(Mode::Slow);
    let mut next_fence = rig.request(ObservationPhase::PreAction);
    next_fence.effect_fence = 18;
    let next_fence = rig.prepare(next_fence);
    let live_read = rig.observer.observe_at(next_fence, NOW);
    let stored_replay = async {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        rig.observer.observe_at(completed_request, NOW).await
    };
    let (live_result, replay_result) = tokio::join!(live_read, stored_replay);

    live_result.unwrap();
    assert_eq!(replay_result.unwrap(), completed_receipt);
}

#[tokio::test]
async fn controller_retry_ids_cannot_create_a_second_phase_chain() {
    let rig = Rig::new().await;
    let first = rig.prepare(rig.request(ObservationPhase::PreAction));
    rig.observer.observe_at(first, NOW).await.unwrap();

    let mut retry = rig.request(ObservationPhase::PreAction);
    retry.build_id = Uuid::from_u128(40);
    retry.attempt_id = Uuid::from_u128(50);
    let retry = rig.prepare(retry);
    assert_eq!(
        rig.observer.observe_at(retry, NOW).await,
        Err(ObserverError::PhaseMismatch)
    );
}

#[tokio::test]
async fn response_limit_must_leave_room_for_the_maximum_receipt_envelope() {
    let rig = Rig::new().await;
    let state = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut config = rig.config.clone();
    config.state_dir = state.path().to_path_buf();
    config.limits.max_response_bytes = MAX_FRAME_BYTES - 1;
    config.response_schema.push(StateFieldSchema {
        name: "padding".to_owned(),
        kind: JsonKind::String,
        required: true,
    });
    assert!(matches!(
        rig.observer_for_config(config),
        Err(ObserverError::InvalidConfig)
    ));
    assert!(!state.path().join("observer.sqlite3").exists());
}

#[tokio::test]
async fn impossible_header_and_query_budgets_fail_before_ledger_creation() {
    let rig = Rig::new().await;
    for invalid_config in [
        {
            let mut config = rig.config.clone();
            config.limits.max_header_bytes = 33;
            config
        },
        {
            let mut config = rig.config.clone();
            config.limits.max_header_bytes = 256 * 1024 + 1;
            config
        },
        {
            let mut config = rig.config.clone();
            config.allowed_query_keys = vec!["q".repeat(129)];
            config
        },
        {
            let mut config = rig.config.clone();
            config.allowed_query_keys = (0..24).map(|index| format!("query_{index:02}")).collect();
            config
        },
    ] {
        let state = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut invalid_config = invalid_config;
        invalid_config.state_dir = state.path().to_path_buf();
        assert!(matches!(
            rig.observer_for_config(invalid_config),
            Err(ObserverError::InvalidConfig)
        ));
        assert!(!state.path().join("observer.sqlite3").exists());
    }
}

#[tokio::test]
async fn evidence_capacity_failure_releases_the_destination_claim() {
    let rig = Rig::new().await;
    let state = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut config = rig.config.clone();
    config.state_dir = state.path().to_path_buf();
    config.limits.max_evidence_bytes = 1;
    let observer = rig.observer_for_config(config).unwrap();

    for _ in 0..2 {
        let mut request = rig.request(ObservationPhase::PreAction);
        request.expected_config_sha256 = observer.config_sha256().to_owned();
        let request = rig.prepare(request);
        assert_eq!(
            observer.observe_at(request, NOW).await,
            Err(ObserverError::CapacityExceeded)
        );
    }

    let connection = rusqlite::Connection::open(state.path().join("observer.sqlite3")).unwrap();
    let pending_count: u64 = connection
        .query_row(
            "SELECT COUNT(*) FROM observations WHERE status='pending'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(pending_count, 0);
}

#[tokio::test]
async fn grant_expiry_and_credential_or_configuration_substitution_are_denied() {
    let rig = Rig::new().await;
    let mut expired = rig.request(ObservationPhase::PreAction);
    expired.requested_at_unix_ms = NOW + 60_000;
    expired.expires_at_unix_ms = NOW + 61_500;
    let expired = rig.prepare(expired);
    assert_eq!(
        rig.observer.observe_at(expired, NOW + 61_000).await,
        Err(ObserverError::ExpiredGrant)
    );

    rig.set_mode(Mode::Slow);
    let mut expires_during_read = rig.request(ObservationPhase::PreAction);
    expires_during_read.expires_at_unix_ms = NOW + 50;
    let expires_during_read = rig.prepare(expires_during_read);
    assert_eq!(
        rig.observer.observe_at(expires_during_read, NOW).await,
        Err(ObserverError::ExpiredRequest)
    );
    rig.set_mode(Mode::Good);
    let replacement = rig.prepare(rig.request(ObservationPhase::PreAction));
    rig.observer.observe_at(replacement, NOW).await.unwrap();

    assert!(matches!(
        DestinationObserver::new_for_loopback_test(
            rig.config.clone(),
            rig.implementation_sha256.clone(),
            rig.image_sha256.clone(),
            b"substituted-token".to_vec(),
            rig.request_public_key.clone(),
            rig.destination_public_key.clone(),
            rig.receipt_seed.clone(),
            vec![b"substituted-token".to_vec(), SECRET.to_vec()],
        ),
        Err(ObserverError::InvalidConfig)
    ));
    assert!(matches!(
        DestinationObserver::new_for_loopback_test(
            rig.config.clone(),
            rig.implementation_sha256.clone(),
            "f".repeat(64),
            TOKEN.to_vec(),
            rig.request_public_key.clone(),
            rig.destination_public_key.clone(),
            rig.receipt_seed.clone(),
            vec![TOKEN.to_vec(), SECRET.to_vec()],
        ),
        Err(ObserverError::InvalidConfig)
    ));

    let mut excessive_markers = vec![TOKEN.to_vec(), SECRET.to_vec()];
    for index in 0..31 {
        excessive_markers.push(format!("marker-{index:02}").into_bytes());
    }
    let mut excessive_marker_config = rig.config.clone();
    let marker_digests: Vec<String> = excessive_markers
        .iter()
        .map(|marker| content_sha256(marker))
        .collect();
    excessive_marker_config.secret_marker_set_sha256 =
        domain_digest(b"mcloving-secret-marker-set-v1", &marker_digests);
    assert!(matches!(
        DestinationObserver::new_for_loopback_test(
            excessive_marker_config,
            rig.implementation_sha256.clone(),
            rig.image_sha256.clone(),
            TOKEN.to_vec(),
            rig.request_public_key.clone(),
            rig.destination_public_key.clone(),
            rig.receipt_seed.clone(),
            excessive_markers,
        ),
        Err(ObserverError::InvalidConfig)
    ));

    let mut substituted_config = rig.config.clone();
    substituted_config.observer_id = "observer-substituted".to_owned();
    assert!(matches!(
        DestinationObserver::new_for_loopback_test(
            substituted_config,
            rig.implementation_sha256.clone(),
            rig.image_sha256.clone(),
            TOKEN.to_vec(),
            rig.request_public_key.clone(),
            rig.destination_public_key.clone(),
            rig.receipt_seed.clone(),
            vec![TOKEN.to_vec(), SECRET.to_vec()],
        ),
        Err(ObserverError::RuntimeFenced)
    ));

    let empty_ca = rig.directory.path().join("empty-ca.pem");
    fs::write(&empty_ca, b"").unwrap();
    let mut empty_ca_config = rig.config.clone();
    empty_ca_config.endpoint_url = "https://observer.invalid/state".to_owned();
    empty_ca_config.ca_bundle_path = Some(empty_ca);
    empty_ca_config.ca_bundle_sha256 = Some(content_sha256(b""));
    empty_ca_config.test_allow_http_loopback = false;
    assert!(matches!(
        rig.observer_for_config(empty_ca_config),
        Err(ObserverError::InvalidConfig)
    ));
}

#[tokio::test]
async fn runtime_attestation_denylist_and_production_constructor_boundary_fail_closed() {
    let rig = Rig::new().await;
    for denied_digest in [
        rig.implementation_sha256.clone(),
        rig.image_sha256.clone(),
        rig.config.secret_marker_set_sha256.clone(),
    ] {
        let state = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut config = rig.config.clone();
        config.state_dir = state.path().to_path_buf();
        config.denied_authority_sha256.push(denied_digest);
        assert!(matches!(
            rig.observer_for_config(config),
            Err(ObserverError::InvalidConfig)
        ));
        assert!(!state.path().join("observer.sqlite3").exists());
    }

    let state = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut non_test_config = rig.config.clone();
    non_test_config.state_dir = state.path().to_path_buf();
    non_test_config.test_allow_http_loopback = false;
    assert!(matches!(
        DestinationObserver::new_for_loopback_test(
            non_test_config,
            "f".repeat(64),
            "e".repeat(64),
            TOKEN.to_vec(),
            rig.request_public_key.clone(),
            rig.destination_public_key.clone(),
            rig.receipt_seed.clone(),
            vec![TOKEN.to_vec(), SECRET.to_vec()],
        ),
        Err(ObserverError::InvalidConfig)
    ));
    assert!(!state.path().join("observer.sqlite3").exists());
}

#[tokio::test]
async fn cutover_fences_old_process_and_rollback_requires_an_exact_historical_target() {
    let rig = Rig::new().await;
    let old_digest = rig.observer.config_sha256().to_owned();
    let old_request = rig.prepare(rig.request(ObservationPhase::PreAction));

    let empty_state = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(empty_state.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut unanchored_generation = rig.config.clone();
    unanchored_generation.state_dir = empty_state.path().to_path_buf();
    unanchored_generation.generation = 2;
    assert!(matches!(
        rig.observer_for_config(unanchored_generation),
        Err(ObserverError::InvalidConfig)
    ));

    let mut cutover_config = rig.config.clone();
    cutover_config.generation = 2;
    cutover_config.activation_mode = ActivationMode::Cutover;
    cutover_config.previous_generation = Some(1);
    cutover_config.previous_config_sha256 = Some(old_digest.clone());
    let cutover = rig.observer_for_config(cutover_config.clone()).unwrap();
    let cutover_digest = cutover.config_sha256().to_owned();
    let cutover_restart = rig.observer_for_config(cutover_config).unwrap();
    assert_eq!(cutover_restart.config_sha256(), cutover.config_sha256());
    assert_eq!(
        rig.observer.observe_at(old_request, NOW).await,
        Err(ObserverError::RuntimeFenced)
    );

    let mut same_generation_rollback = rig.config.clone();
    same_generation_rollback.generation = 3;
    same_generation_rollback.activation_mode = ActivationMode::Rollback;
    same_generation_rollback.previous_generation = Some(2);
    same_generation_rollback.previous_config_sha256 = Some(cutover_digest);
    same_generation_rollback.rollback_from_generation = Some(2);
    assert!(matches!(
        rig.observer_for_config(same_generation_rollback),
        Err(ObserverError::InvalidConfig)
    ));

    let mut invalid_rollback = rig.config.clone();
    invalid_rollback.generation = 3;
    invalid_rollback.activation_mode = ActivationMode::Rollback;
    invalid_rollback.previous_generation = Some(1);
    invalid_rollback.previous_config_sha256 = Some("f".repeat(64));
    invalid_rollback.rollback_from_generation = Some(2);
    assert!(matches!(
        rig.observer_for_config(invalid_rollback),
        Err(ObserverError::InvalidConfig)
    ));

    let mut rollback_config = rig.config.clone();
    rollback_config.generation = 3;
    rollback_config.activation_mode = ActivationMode::Rollback;
    rollback_config.previous_generation = Some(1);
    rollback_config.previous_config_sha256 = Some(old_digest);
    rollback_config.rollback_from_generation = Some(2);
    let rollback = rig.observer_for_config(rollback_config.clone()).unwrap();
    assert_ne!(rollback.config_sha256(), cutover.config_sha256());
    let rollback_restart = rig.observer_for_config(rollback_config).unwrap();
    assert_eq!(rollback_restart.config_sha256(), rollback.config_sha256());
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn standalone_process_emits_a_verified_receipt_and_exposes_no_write_operation() {
    let rig = Rig::new().await;
    let binary_path = env!("CARGO_BIN_EXE_mcloving-destination-observer");
    let binary = fs::read(binary_path).unwrap();
    let process_directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(process_directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut config = rig.config.clone();
    config.state_dir = process_directory.path().join("state");
    fs::create_dir(&config.state_dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&config.state_dir, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let config_sha256 = config.canonical_digest().unwrap();
    let implementation_sha256 = content_sha256(&binary);
    let process_now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    rig.server
        .observed_at_unix_ms
        .store(process_now, Ordering::SeqCst);
    let mut request = rig.request(ObservationPhase::PreAction);
    request.expected_config_sha256 = config_sha256;
    request.expected_implementation_sha256 = implementation_sha256;
    request.requested_at_unix_ms = process_now - 1;
    request.expires_at_unix_ms = process_now + 9_000;
    let request = rig.prepare(request);

    let config_path = process_directory.path().join("observer.json");
    let image_sha256_path = process_directory.path().join("runtime-image.sha256");
    let token_path = process_directory.path().join("read.token");
    let request_key_path = process_directory.path().join("request.pub");
    let destination_key_path = process_directory.path().join("destination.pub");
    let receipt_seed_path = process_directory.path().join("receipt.seed");
    let markers_path = process_directory.path().join("markers.json");
    fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    fs::write(&image_sha256_path, config.image_sha256.as_bytes()).unwrap();
    fs::write(&token_path, TOKEN).unwrap();
    fs::write(&request_key_path, &rig.request_public_key).unwrap();
    fs::write(&destination_key_path, &rig.destination_public_key).unwrap();
    fs::write(&receipt_seed_path, &rig.receipt_seed).unwrap();
    fs::write(
        &markers_path,
        serde_json::to_vec(&vec![BASE64.encode(TOKEN), BASE64.encode(SECRET)]).unwrap(),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        for path in [
            &config_path,
            &image_sha256_path,
            &token_path,
            &request_key_path,
            &destination_key_path,
            &receipt_seed_path,
            &markers_path,
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    let command = serde_json::to_vec(&json!({
        "operation": "observe",
        "request": request,
    }))
    .unwrap();
    let paths = [
        config_path,
        image_sha256_path,
        token_path,
        request_key_path,
        destination_key_path,
        receipt_seed_path,
        markers_path,
    ];
    let output = tokio::task::spawn_blocking(move || {
        let mut child = Command::new(binary_path)
            .args(paths)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        input.write_all(&command).unwrap();
        input.write_all(b"\n").unwrap();
        input
            .write_all(b"{\"operation\":\"write\",\"request\":{}}\n")
            .unwrap();
        drop(input);
        child.wait_with_output().unwrap()
    })
    .await
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let responses: Vec<serde_json::Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(responses.len(), 2);
    assert_eq!(
        responses[0]["status"], "observed",
        "unexpected standalone response: {}",
        responses[0]
    );
    let receipt: ObservationReceipt =
        serde_json::from_value(responses[0]["receipt"].clone()).unwrap();
    verify_observation_receipt(&receipt, &rig.receipt_public_key).unwrap();
    assert_eq!(responses[1]["status"], "error");
    assert_eq!(responses[1]["code"], "malformed_request");
}

#[tokio::test]
async fn signature_binding_phase_cursor_and_replay_substitution_fail_closed() {
    let rig = Rig::new().await;
    let unsigned = rig.request(ObservationPhase::PreAction);
    assert_eq!(
        rig.observer.observe_at(unsigned, NOW).await,
        Err(ObserverError::UnauthorizedRequest)
    );

    let first = rig.prepare(rig.request(ObservationPhase::PreAction));
    let receipt = rig.observer.observe_at(first.clone(), NOW).await.unwrap();
    let mut substituted = first;
    substituted.audit_provenance = "audit/forged".to_owned();
    sign_observation_request(&mut substituted, &rig.request_seed).unwrap();
    assert_eq!(
        rig.observer.observe_at(substituted, NOW).await,
        Err(ObserverError::ReplayMismatch)
    );

    let mut post = rig.request(ObservationPhase::PostAction);
    post.expected_previous_cursor = Some(receipt.destination_cursor);
    post.predecessor_receipt_sha256 = Some(receipt_digest(&receipt));
    rig.server
        .cursor
        .store(receipt.destination_cursor, Ordering::SeqCst);
    assert_eq!(
        rig.observer.observe_at(rig.prepare(post), NOW).await,
        Err(ObserverError::CursorRollback)
    );
}

#[tokio::test]
async fn cursor_history_is_chain_scoped_and_stored_replay_is_reverified() {
    let rig = Rig::new().await;
    let first_request = rig.prepare(rig.request(ObservationPhase::PreAction));
    let mut first_receipt = rig
        .observer
        .observe_at(first_request.clone(), NOW)
        .await
        .unwrap();

    let mut next_fence = rig.request(ObservationPhase::PreAction);
    next_fence.effect_fence = 18;
    let next_fence = rig.prepare(next_fence);
    let next_fence_receipt = rig
        .observer
        .observe_at(next_fence.clone(), NOW)
        .await
        .unwrap();
    assert_eq!(
        rig.observer.observe_at(next_fence, NOW).await.unwrap(),
        next_fence_receipt
    );
    let mut later_fence = rig.request(ObservationPhase::PreAction);
    later_fence.effect_fence = 19;
    let later_fence = rig.prepare(later_fence);
    rig.observer.observe_at(later_fence, NOW).await.unwrap();

    let mut other_query = rig.request(ObservationPhase::PreAction);
    other_query
        .query
        .insert("release_id".to_owned(), "release-43".to_owned());
    let other_query = rig.prepare(other_query);
    rig.observer.observe_at(other_query, NOW).await.unwrap();

    first_receipt.signature_base64 = "AAAA".to_owned();
    let connection =
        rusqlite::Connection::open(rig.directory.path().join("observer.sqlite3")).unwrap();
    connection
        .execute(
            "UPDATE observations SET receipt_json=?2 WHERE observation_id=?1",
            rusqlite::params![
                first_request.observation_id.to_string(),
                serde_json::to_vec(&first_receipt).unwrap()
            ],
        )
        .unwrap();
    assert_eq!(
        rig.observer.observe_at(first_request, NOW).await,
        Err(ObserverError::InvalidReceipt)
    );
}

#[tokio::test]
async fn stored_receipt_with_duplicate_keys_is_rejected() {
    let rig = Rig::new().await;
    let request = rig.prepare(rig.request(ObservationPhase::PreAction));
    rig.observer.observe_at(request.clone(), NOW).await.unwrap();

    let connection =
        rusqlite::Connection::open(rig.directory.path().join("observer.sqlite3")).unwrap();
    let receipt: Vec<u8> = connection
        .query_row(
            "SELECT receipt_json FROM observations WHERE observation_id=?1",
            [request.observation_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    let mut duplicate = br#"{"schema_version":"substituted","#.to_vec();
    duplicate.extend_from_slice(&receipt[1..]);
    connection
        .execute(
            "UPDATE observations SET receipt_json=?2 WHERE observation_id=?1",
            rusqlite::params![request.observation_id.to_string(), duplicate],
        )
        .unwrap();

    assert_eq!(
        rig.observer.observe_at(request, NOW).await,
        Err(ObserverError::InvalidReceipt)
    );
}

#[tokio::test]
async fn cursor_outside_the_ledger_range_is_terminal_and_releases_the_destination() {
    let rig = Rig::new().await;
    rig.server
        .cursor
        .store(i64::MAX as u64 + 1, Ordering::SeqCst);
    let invalid = rig.prepare(rig.request(ObservationPhase::PreAction));
    assert_eq!(
        rig.observer.observe_at(invalid.clone(), NOW).await,
        Err(ObserverError::MalformedResponse)
    );
    assert_eq!(
        rig.observer.observe_at(invalid, NOW).await,
        Err(ObserverError::MalformedResponse)
    );

    rig.server.cursor.store(10, Ordering::SeqCst);
    let replacement = rig.prepare(rig.request(ObservationPhase::PreAction));
    rig.observer.observe_at(replacement, NOW).await.unwrap();
}

fn public_key(seed: &[u8]) -> Vec<u8> {
    Ed25519KeyPair::from_seed_unchecked(seed)
        .unwrap()
        .public_key()
        .as_ref()
        .to_vec()
}

fn domain_digest<T: Serialize>(domain: &[u8], value: &T) -> String {
    let encoded = serde_json::to_vec(value).unwrap();
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update([0]);
    digest.update(encoded);
    let mut output = String::new();
    for byte in digest.finalize() {
        use std::fmt::Write as _;
        write!(output, "{byte:02x}").unwrap();
    }
    output
}

fn receipt_digest(receipt: &ObservationReceipt) -> String {
    observation_receipt_digest(receipt).unwrap()
}
