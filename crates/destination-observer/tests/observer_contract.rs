#![cfg(feature = "loopback-test")]

#[path = "../../test-support/diff003.rs"]
mod diff003;

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::fs;
#[cfg(target_os = "linux")]
use std::io::Write as _;
#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt as _;
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
#[cfg(target_os = "linux")]
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, Response, StatusCode};
use axum::routing::get;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use http_body_util::{BodyExt as _, Full};
use mcloving_destination_observer::{
    ActivationMode, CONFIG_SCHEMA_VERSION, Confidentiality, DESTINATION_STATE_SCHEMA_VERSION,
    DestinationObserver, DestinationStateBody, JsonKind, MAX_FRAME_BYTES, ObservationPhase,
    ObservationReceipt, ObservationRequest, ObserverCommand, ObserverConfig, ObserverError,
    ObserverLimits, PROTOCOL_VERSION, REQUEST_SCHEMA_VERSION, RequestAuthorization,
    SignedDestinationState, StateFieldSchema, content_sha256, destination_state_message,
    observation_receipt_digest, sign_observation_request, verify_observation_receipt,
};
use mcloving_external_connector::{
    OutcomeReceipt as ConnectorOutcomeReceipt, OutcomeStatus as ConnectorOutcomeStatus,
    verify_outcome_receipt,
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
    CompactUuid,
    Stale,
    PredatesRequest,
    Substitute,
    RequestDigestSubstitute,
    Secret,
    EscapedEnvelopeSecret,
    PostErrorEscapedSecret,
    TrailingEscapedSecret,
    MalformedLiteralEscapedSecret,
    UnterminatedEscapedSecret,
    HeaderSecret,
    OversizedHeader,
    OversizedHeaderBodySecret,
    OversizedHeaderOversizedBody,
    DuplicateContentType,
    Trailer,
    TrailerSecret,
    Malformed,
    Oversized,
    Unauthorized,
    UnauthorizedOversizedHeader,
    UnauthorizedOversizedBody,
    UnauthorizedSecret,
    UnauthorizedStreamError,
    Outage,
    OutageOversizedChunked,
    OutageOversizedChunkedSecret,
    OutageOversized,
    OutageOversizedSecret,
    OutageSecret,
    OutageBase64Secret,
    OutageTypedEnvelopeBase64Secret,
    MalformedContentTypeSecret,
    Timeout,
    Slow,
    SlowMalformed,
    OversizedHeaderSecret,
}

struct DestinationState {
    seed: Vec<u8>,
    request: Mutex<Option<ObservationRequest>>,
    mode: Mutex<Mode>,
    cursor: AtomicU64,
    observed_at_unix_ms: AtomicI64,
    reads: AtomicU64,
    shared_effect_published: Option<bool>,
}

#[derive(Clone)]
struct Diff003ConnectorBinding {
    tenant_id: Uuid,
    project_id: Uuid,
    pipeline_id: Uuid,
    build_id: Uuid,
    attempt_id: Uuid,
    effect_fence: u64,
    endpoint_identity: String,
    account_identity: String,
    resource_identity: String,
    effect_class: String,
    release_id: String,
    receipt_sha256: String,
    authenticated_outcome: bool,
    effect_published: bool,
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
    connector_binding: Option<Diff003ConnectorBinding>,
}

impl Rig {
    async fn new() -> Self {
        let request_seed = vec![1_u8; 32];
        let destination_seed = vec![2_u8; 32];
        let receipt_seed = vec![4_u8; 32];
        let request_public_key = public_key(&request_seed);
        let destination_public_key = public_key(&destination_seed);
        let receipt_public_key = public_key(&receipt_seed);
        let connector_binding = diff003_connector_binding();
        let server = Arc::new(DestinationState {
            seed: destination_seed,
            request: Mutex::new(None),
            mode: Mutex::new(Mode::Good),
            cursor: AtomicU64::new(10),
            observed_at_unix_ms: AtomicI64::new(NOW),
            reads: AtomicU64::new(0),
            shared_effect_published: connector_binding
                .as_ref()
                .map(|binding| binding.effect_published),
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
            implementation_sha256: implementation_sha256.clone(),
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
            endpoint_identity: connector_binding
                .as_ref()
                .map(|binding| binding.endpoint_identity.clone())
                .unwrap_or_else(|| "endpoint/release-state".to_owned()),
            account_identity: connector_binding
                .as_ref()
                .map(|binding| binding.account_identity.clone())
                .unwrap_or_else(|| "account/customer-a".to_owned()),
            resource_identity: connector_binding
                .as_ref()
                .map(|binding| binding.resource_identity.clone())
                .unwrap_or_else(|| "release/app-a".to_owned()),
            effect_class: connector_binding
                .as_ref()
                .map(|binding| binding.effect_class.clone())
                .unwrap_or_else(|| "release_publication".to_owned()),
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
                max_observations: 200,
                max_runtime_history: 100,
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
            connector_binding,
        }
    }

    fn request(&self, phase: ObservationPhase) -> ObservationRequest {
        let mut query = BTreeMap::new();
        query.insert(
            "release_id".to_owned(),
            self.connector_binding
                .as_ref()
                .map(|binding| binding.release_id.clone())
                .unwrap_or_else(|| "release-42".to_owned()),
        );
        ObservationRequest {
            schema_version: REQUEST_SCHEMA_VERSION.to_owned(),
            protocol_version: PROTOCOL_VERSION.to_owned(),
            observation_id: Uuid::new_v4(),
            tenant_id: self
                .connector_binding
                .as_ref()
                .map(|binding| binding.tenant_id)
                .unwrap_or_else(|| Uuid::from_u128(1)),
            project_id: self
                .connector_binding
                .as_ref()
                .map(|binding| binding.project_id)
                .unwrap_or_else(|| Uuid::from_u128(2)),
            pipeline_id: self
                .connector_binding
                .as_ref()
                .map(|binding| binding.pipeline_id)
                .unwrap_or_else(|| Uuid::from_u128(3)),
            build_id: self
                .connector_binding
                .as_ref()
                .map(|binding| binding.build_id)
                .unwrap_or_else(|| Uuid::from_u128(4)),
            attempt_id: self
                .connector_binding
                .as_ref()
                .map(|binding| binding.attempt_id)
                .unwrap_or_else(|| Uuid::from_u128(5)),
            effect_fence: self
                .connector_binding
                .as_ref()
                .map(|binding| binding.effect_fence)
                .unwrap_or(17),
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
            endpoint_identity: self.config.endpoint_identity.clone(),
            account_identity: self.config.account_identity.clone(),
            resource_identity: self.config.resource_identity.clone(),
            effect_class: self.config.effect_class.clone(),
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

fn diff003_connector_binding() -> Option<Diff003ConnectorBinding> {
    let path = std::env::var_os("MCLOVING_DIFF003_CONNECTOR_RECEIPT")?;
    let bytes = fs::read(path).ok()?;
    let mut connector: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let receipt_sha256 = content_sha256(&bytes);
    connector.as_object_mut()?.remove("_diff003");
    connector.as_object_mut()?.remove("release_binding");
    connector.as_object_mut()?.remove("secret_grant_binding");
    connector
        .as_object_mut()?
        .remove("observer_receipt_signing_public_key_sha256");
    let outcome: ConnectorOutcomeReceipt = serde_json::from_value(connector.clone()).ok()?;
    let outcome_public_key = fs::read(std::env::var_os(
        "MCLOVING_DIFF003_CONNECTOR_OUTCOME_PUBLIC_KEY",
    )?)
    .ok()?;
    if content_sha256(&outcome_public_key) != outcome.outcome_signing_public_key_sha256 {
        return None;
    }
    verify_outcome_receipt(&outcome, &outcome_public_key).ok()?;
    Some(Diff003ConnectorBinding {
        tenant_id: Uuid::parse_str(connector["tenant_id"].as_str()?).ok()?,
        project_id: Uuid::parse_str(connector["project_id"].as_str()?).ok()?,
        pipeline_id: Uuid::parse_str(connector["pipeline_id"].as_str()?).ok()?,
        build_id: Uuid::parse_str(connector["build_id"].as_str()?).ok()?,
        attempt_id: Uuid::parse_str(connector["attempt_id"].as_str()?).ok()?,
        effect_fence: connector["effect_fence"].as_u64()?,
        endpoint_identity: connector["endpoint_identity"].as_str()?.to_owned(),
        account_identity: connector["account_identity"].as_str()?.to_owned(),
        resource_identity: connector["resource_identity"].as_str()?.to_owned(),
        effect_class: connector["effect_class"].as_str()?.to_owned(),
        release_id: connector["external_ids"]["release_id"].as_str()?.to_owned(),
        receipt_sha256,
        authenticated_outcome: true,
        effect_published: outcome.status == ConnectorOutcomeStatus::Succeeded,
    })
}

async fn destination_handler(
    State(server): State<Arc<DestinationState>>,
    headers: HeaderMap,
) -> Response<Body> {
    let mode = *server.mode.lock().unwrap();
    if matches!(
        mode,
        Mode::Unauthorized
            | Mode::UnauthorizedOversizedHeader
            | Mode::UnauthorizedOversizedBody
            | Mode::UnauthorizedSecret
            | Mode::UnauthorizedStreamError
    ) || headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        != Some("Bearer read-only-observer-token")
    {
        let mut response = Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(match mode {
                Mode::UnauthorizedSecret => Body::from(TOKEN),
                Mode::UnauthorizedOversizedBody => Body::from(vec![b'x'; 32 * 1024]),
                Mode::UnauthorizedStreamError => {
                    let (sender, receiver) =
                        tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(2);
                    tokio::spawn(async move {
                        sender.send(Ok(Bytes::from_static(b"{"))).await.unwrap();
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        sender
                            .send(Err(std::io::Error::other("unauthorized stream reset")))
                            .await
                            .unwrap();
                    });
                    Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(receiver))
                }
                _ => Body::empty(),
            })
            .unwrap();
        if matches!(mode, Mode::UnauthorizedOversizedHeader) {
            response.headers_mut().insert(
                "x-oversized",
                axum::http::HeaderValue::from_str(&"x".repeat(9 * 1024)).unwrap(),
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
        ("x-mcloving-request-sha256", request_sha256.clone()),
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
    if matches!(mode, Mode::EscapedEnvelopeSecret) {
        return json_response(
            StatusCode::OK,
            br#"{"unknown":"read-only-observer-\u0074oken","unknown":"safe"}"#.to_vec(),
        );
    }
    if matches!(mode, Mode::PostErrorEscapedSecret) {
        return json_response(
            StatusCode::OK,
            br#"{"bad":"\q"} junk "read-only-observer-\u0074oken""#.to_vec(),
        );
    }
    if matches!(mode, Mode::TrailingEscapedSecret) {
        return json_response(
            StatusCode::OK,
            br#"{"safe":true} trailing "read-only-observer-\u0074oken""#.to_vec(),
        );
    }
    if matches!(mode, Mode::MalformedLiteralEscapedSecret) {
        return json_response(
            StatusCode::OK,
            br#"{"bad":"\qread-only-observer-\u0074oken"}"#.to_vec(),
        );
    }
    if matches!(mode, Mode::UnterminatedEscapedSecret) {
        return json_response(
            StatusCode::OK,
            br#"{"bad":"read-only-observer-\u0074oken"#.to_vec(),
        );
    }
    if matches!(mode, Mode::Oversized) {
        return json_response(StatusCode::OK, vec![b'x'; 32 * 1024]);
    }
    if matches!(mode, Mode::OversizedHeaderOversizedBody) {
        return Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .header("x-oversized", "x".repeat(9 * 1024))
            .body(Body::from(vec![b'x'; 32 * 1024]))
            .unwrap();
    }
    if matches!(
        mode,
        Mode::OutageOversizedChunked | Mode::OutageOversizedChunkedSecret
    ) {
        let first = if matches!(mode, Mode::OutageOversizedChunkedSecret) {
            oversized_escaped_secret_body(12 * 1024)
        } else {
            vec![b'x'; 12 * 1024]
        };
        let stream = tokio_stream::iter([
            Ok::<_, Infallible>(first),
            Ok::<_, Infallible>(vec![b'x'; 12 * 1024]),
        ]);
        return Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header("content-type", "application/json")
            .body(Body::from_stream(stream))
            .unwrap();
    }
    if matches!(
        mode,
        Mode::Outage
            | Mode::OutageOversized
            | Mode::OutageOversizedSecret
            | Mode::OutageSecret
            | Mode::OutageBase64Secret
    ) {
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            if matches!(mode, Mode::OutageSecret) {
                TOKEN.to_vec()
            } else if matches!(mode, Mode::OutageBase64Secret) {
                BASE64
                    .encode([b"x".as_slice(), TOKEN].concat())
                    .into_bytes()
            } else if matches!(mode, Mode::OutageOversizedSecret) {
                oversized_escaped_secret_body(32 * 1024)
            } else if matches!(mode, Mode::OutageOversized) {
                vec![b'x'; 32 * 1024]
            } else {
                b"{}".to_vec()
            },
        );
    }
    if matches!(mode, Mode::MalformedContentTypeSecret) {
        return Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain")
            .body(Body::from(TOKEN))
            .unwrap();
    }
    if matches!(mode, Mode::Timeout) {
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    }
    if matches!(mode, Mode::Slow | Mode::SlowMalformed) {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    if matches!(mode, Mode::SlowMalformed) {
        return json_response(StatusCode::OK, b"{\"body\":".to_vec());
    }
    let mut body = DestinationStateBody {
        schema_version: DESTINATION_STATE_SCHEMA_VERSION.to_owned(),
        observation_id: request.observation_id,
        request_sha256: request_sha256.clone(),
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
        state: json!({
            "published": server.shared_effect_published.unwrap_or(true),
        }),
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
        Mode::RequestDigestSubstitute => body.request_sha256 = "f".repeat(64),
        Mode::OutageTypedEnvelopeBase64Secret => {
            body.request_sha256 = BASE64.encode([b"x".as_slice(), TOKEN].concat());
        }
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
    if matches!(mode, Mode::Trailer | Mode::TrailerSecret) {
        let mut trailers = HeaderMap::new();
        trailers.insert(
            "x-destination-trailer",
            if matches!(mode, Mode::TrailerSecret) {
                axum::http::HeaderValue::from_static("read-only-observer-token")
            } else {
                axum::http::HeaderValue::from_static("unexpected")
            },
        );
        let body = Full::new(Bytes::from(serde_json::to_vec(&signed).unwrap()))
            .with_trailers(std::future::ready(Some(Ok::<_, Infallible>(trailers))));
        return Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Body::new(body))
            .unwrap();
    }
    let mut response_bytes = if matches!(mode, Mode::OversizedHeaderBodySecret) {
        TOKEN.to_vec()
    } else {
        serde_json::to_vec(&signed).unwrap()
    };
    if matches!(mode, Mode::CompactUuid) {
        let hyphenated = signed.body.observation_id.hyphenated().to_string();
        let compact = signed.body.observation_id.simple().to_string();
        response_bytes = String::from_utf8(response_bytes)
            .unwrap()
            .replacen(&hyphenated, &compact, 1)
            .into_bytes();
    }
    if matches!(mode, Mode::OutageTypedEnvelopeBase64Secret) {
        return json_response(StatusCode::SERVICE_UNAVAILABLE, response_bytes);
    }
    let mut response = json_response(StatusCode::OK, response_bytes);
    if matches!(mode, Mode::HeaderSecret) {
        response.headers_mut().insert(
            "x-debug-credential",
            axum::http::HeaderValue::from_static("read-only-observer-token"),
        );
    }
    if matches!(
        mode,
        Mode::OversizedHeader | Mode::OversizedHeaderBodySecret | Mode::OversizedHeaderSecret
    ) {
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

fn oversized_escaped_secret_body(size: usize) -> Vec<u8> {
    let mut body = br#"{"leak":"read-only-observer-\u0074oken"}"#.to_vec();
    body.resize(size, b'x');
    body
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
        .observe_at(pre_request.clone(), NOW + 2_000)
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
    if let Ok(root) = std::env::var("MCLOVING_DIFF003_RUNTIME_OUTPUT_DIR") {
        let connector_receipt = fs::read(
            std::env::var_os("MCLOVING_DIFF003_CONNECTOR_RECEIPT")
                .expect("DIFF-003 connector receipt path"),
        )
        .expect("read live DIFF-003 connector receipt");
        std::fs::write(
            std::path::Path::new(&root).join("OBS-001.json"),
            diff003::receipt(
                "OBS-001",
                serde_json::json!({
                    "pre": pre,
                    "post": post,
                    "reconciliation": reconciliation,
                    "connector_receipt_sha256": content_sha256(&connector_receipt),
                    "connector_outcome_authenticated": rig.connector_binding
                        .as_ref()
                        .is_some_and(|binding| binding.authenticated_outcome),
                    "shared_effect_state_sha256": rig.connector_binding
                        .as_ref()
                        .map(|binding| binding.receipt_sha256.clone()),
                }),
            ),
        )
        .expect("write DIFF-003 observer receipts");
    }
}

#[tokio::test]
async fn publication_deadline_is_anchored_to_signed_destination_freshness() {
    let rig = Rig::new().await;
    rig.set_mode(Mode::Slow);
    rig.server
        .observed_at_unix_ms
        .store(NOW - 9_000, Ordering::SeqCst);
    let mut request = rig.request(ObservationPhase::PreAction);
    request.requested_at_unix_ms = NOW - 9_000;
    request.expires_at_unix_ms = NOW + 1_000;
    let receipt = rig
        .observer
        .observe_at(rig.prepare(request), NOW)
        .await
        .unwrap();

    assert!(receipt.captured_at_unix_ms > NOW);
    assert_eq!(receipt.publication_deadline_unix_ms, NOW + 1_000);
}

#[tokio::test]
async fn stale_substituted_secret_malformed_oversized_and_permission_denials_fail_closed() {
    let mut stale_denials = 0;
    for (mode, expected) in [
        (Mode::Stale, ObserverError::StaleObservation),
        (Mode::PredatesRequest, ObserverError::StaleObservation),
        (Mode::Substitute, ObserverError::MalformedResponse),
        (
            Mode::RequestDigestSubstitute,
            ObserverError::MalformedResponse,
        ),
        (Mode::Secret, ObserverError::ConfidentialityDenied),
        (
            Mode::EscapedEnvelopeSecret,
            ObserverError::ConfidentialityDenied,
        ),
        (
            Mode::PostErrorEscapedSecret,
            ObserverError::ConfidentialityDenied,
        ),
        (
            Mode::TrailingEscapedSecret,
            ObserverError::ConfidentialityDenied,
        ),
        (
            Mode::MalformedLiteralEscapedSecret,
            ObserverError::ConfidentialityDenied,
        ),
        (
            Mode::UnterminatedEscapedSecret,
            ObserverError::ConfidentialityDenied,
        ),
        (Mode::HeaderSecret, ObserverError::ConfidentialityDenied),
        (Mode::Trailer, ObserverError::MalformedResponse),
        (Mode::TrailerSecret, ObserverError::ConfidentialityDenied),
        (Mode::DuplicateContentType, ObserverError::MalformedResponse),
        (Mode::Malformed, ObserverError::MalformedResponse),
        (Mode::Oversized, ObserverError::OversizedResponse),
        (Mode::Unauthorized, ObserverError::DestinationUnauthorized),
        (
            Mode::UnauthorizedOversizedHeader,
            ObserverError::DestinationUnauthorized,
        ),
        (
            Mode::UnauthorizedSecret,
            ObserverError::ConfidentialityDenied,
        ),
        (
            Mode::UnauthorizedStreamError,
            ObserverError::DestinationUnauthorized,
        ),
        (Mode::OutageSecret, ObserverError::ConfidentialityDenied),
        (
            Mode::OutageBase64Secret,
            ObserverError::ConfidentialityDenied,
        ),
        (
            Mode::OutageTypedEnvelopeBase64Secret,
            ObserverError::ConfidentialityDenied,
        ),
        (
            Mode::OutageOversizedSecret,
            ObserverError::ConfidentialityDenied,
        ),
        (
            Mode::OutageOversizedChunkedSecret,
            ObserverError::ConfidentialityDenied,
        ),
        (
            Mode::MalformedContentTypeSecret,
            ObserverError::ConfidentialityDenied,
        ),
        (
            Mode::OversizedHeaderSecret,
            ObserverError::ConfidentialityDenied,
        ),
        (
            Mode::OversizedHeaderBodySecret,
            ObserverError::ConfidentialityDenied,
        ),
    ] {
        let rig = Rig::new().await;
        rig.set_mode(mode);
        let request = rig.prepare(rig.request(ObservationPhase::PreAction));
        let first_result = rig.observer.observe_at(request.clone(), NOW).await;
        let second_result = rig.observer.observe_at(request, NOW).await;
        assert_eq!(first_result, Err(expected.clone()));
        assert_eq!(second_result, Err(expected.clone()));
        if matches!(mode, Mode::Stale | Mode::PredatesRequest)
            && first_result == Err(ObserverError::StaleObservation)
            && second_result == Err(ObserverError::StaleObservation)
        {
            stale_denials += 1;
        }
        rig.set_mode(Mode::Good);
        let replacement = rig.prepare(rig.request(ObservationPhase::PreAction));
        rig.observer.observe_at(replacement, NOW).await.unwrap();
    }
    diff003::record_assertion(
        "observer_stale_denied",
        "denied",
        serde_json::json!({
            "stale_modes_executed": 2,
            "stale_modes_denied_twice": stale_denials,
            "result": "stale_observation",
        }),
        stale_denials == 2,
    );

    for mode in [
        Mode::Outage,
        Mode::OutageOversizedChunked,
        Mode::OutageOversized,
        Mode::UnauthorizedOversizedBody,
        Mode::Timeout,
        Mode::OversizedHeader,
        Mode::OversizedHeaderOversizedBody,
    ] {
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
async fn outbound_rate_reservation_uses_the_post_database_wait_time() {
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
    let database_path = state.path().join("observer.sqlite3");
    let connection = rusqlite::Connection::open(&database_path).unwrap();
    connection
        .execute(
            "INSERT INTO request_attempts(attempted_at_ms) VALUES(?1)",
            [NOW - 59_950],
        )
        .unwrap();
    drop(connection);

    let (ready_sender, ready_receiver) = std::sync::mpsc::channel();
    let blocker = std::thread::spawn(move || {
        let connection = rusqlite::Connection::open(database_path).unwrap();
        connection.execute_batch("BEGIN IMMEDIATE").unwrap();
        ready_sender.send(()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(150));
        connection.execute_batch("COMMIT").unwrap();
    });
    ready_receiver.recv().unwrap();

    let mut request = rig.request(ObservationPhase::PreAction);
    request.expected_config_sha256 = observer.config_sha256().to_owned();
    observer
        .observe_at(rig.prepare(request), NOW)
        .await
        .unwrap();
    blocker.join().unwrap();
}

#[tokio::test]
async fn durable_pending_claim_resumes_after_outage_and_process_restart() {
    let rig = Rig::new().await;
    rig.set_mode(Mode::Outage);
    let request = rig.prepare(rig.request(ObservationPhase::PreAction));
    let outage_result = rig.observer.observe_at(request.clone(), NOW).await;
    let outage_denied = outage_result == Err(ObserverError::DestinationUnavailable);
    assert!(outage_denied);
    rig.set_mode(Mode::Good);
    let restarted = rig.restart();
    let receipt = restarted.observe_at(request, NOW).await.unwrap();
    assert_eq!(receipt.retry_count, 1);
    verify_observation_receipt(&receipt, &rig.receipt_public_key).unwrap();
    diff003::record_assertion(
        "observer_outage_denied",
        "denied",
        serde_json::json!({
            "initial_result": "destination_unavailable",
            "restart_retry_count": receipt.retry_count,
            "receipt_verified": true,
        }),
        outage_denied && receipt.retry_count == 1,
    );
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
            "UPDATE observations SET retry_count=0, reservation_reached=1 WHERE observation_id=?1 AND status='pending'",
            [request.observation_id.to_string()],
        )
        .unwrap();
    drop(connection);

    rig.set_mode(Mode::Good);
    let receipt = rig.restart().observe_at(request, NOW).await.unwrap();
    assert_eq!(receipt.retry_count, 0);
}

#[tokio::test]
async fn pre_reservation_crash_state_becomes_a_nonblocking_rate_tombstone() {
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
    let observer = rig.observer_for_config(config.clone()).unwrap();

    rig.set_mode(Mode::Outage);
    let mut request = rig.request(ObservationPhase::PreAction);
    request.expected_config_sha256 = observer.config_sha256().to_owned();
    let request = rig.prepare(request);
    assert_eq!(
        observer.observe_at(request.clone(), NOW).await,
        Err(ObserverError::DestinationUnavailable)
    );

    // Rewind only the durable claim state to the exact crash gap after claim commit and before
    // the rate-reservation transaction. The retained attempt keeps the rate window saturated.
    let database_path = state.path().join("observer.sqlite3");
    let connection = rusqlite::Connection::open(&database_path).unwrap();
    connection
        .execute(
            "UPDATE observations SET retry_count=0, reservation_reached=0 WHERE observation_id=?1 AND status='pending'",
            [request.observation_id.to_string()],
        )
        .unwrap();
    drop(connection);

    rig.set_mode(Mode::Good);
    let restarted = rig.observer_for_config(config).unwrap();
    assert_eq!(
        restarted.observe_at(request, NOW).await,
        Err(ObserverError::CapacityExceeded)
    );
    let connection = rusqlite::Connection::open(&database_path).unwrap();
    let stored: (String, String, bool) = connection
        .query_row(
            "SELECT status, failure_code, reservation_reached FROM observations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        stored,
        ("failed".to_owned(), "rate_limited".to_owned(), false)
    );

    connection
        .execute("DELETE FROM request_attempts", [])
        .unwrap();
    drop(connection);
    let mut next = rig.request(ObservationPhase::PreAction);
    next.expected_config_sha256 = restarted.config_sha256().to_owned();
    restarted.observe_at(rig.prepare(next), NOW).await.unwrap();
}

#[tokio::test]
async fn completed_failure_resets_reservation_for_the_next_retry_cycle() {
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
    let observer = rig.observer_for_config(config.clone()).unwrap();

    rig.set_mode(Mode::Outage);
    let mut request = rig.request(ObservationPhase::PreAction);
    request.expected_config_sha256 = observer.config_sha256().to_owned();
    let request = rig.prepare(request);
    assert_eq!(
        observer.observe_at(request.clone(), NOW).await,
        Err(ObserverError::DestinationUnavailable)
    );

    let database_path = state.path().join("observer.sqlite3");
    let connection = rusqlite::Connection::open(&database_path).unwrap();
    let stored: (u8, bool) = connection
        .query_row(
            "SELECT retry_count, reservation_reached FROM observations WHERE observation_id=?1",
            [request.observation_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(stored, (1, false));
    drop(connection);

    // A crash after the next idempotent claim leaves this same durable state. The saturated rate
    // window must therefore convert the replay to a nonblocking tombstone instead of stranding it.
    rig.set_mode(Mode::Good);
    assert_eq!(
        rig.observer_for_config(config)
            .unwrap()
            .observe_at(request, NOW)
            .await,
        Err(ObserverError::CapacityExceeded)
    );
    let connection = rusqlite::Connection::open(&database_path).unwrap();
    let stored: (String, String, bool) = connection
        .query_row(
            "SELECT status, failure_code, reservation_reached FROM observations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        stored,
        ("failed".to_owned(), "rate_limited".to_owned(), false)
    );
}

#[tokio::test]
async fn rate_limit_rejection_releases_a_fresh_destination_claim() {
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
    let database_path = state.path().join("observer.sqlite3");
    let connection = rusqlite::Connection::open(&database_path).unwrap();
    connection
        .execute(
            "INSERT INTO request_attempts(attempted_at_ms) VALUES(?1)",
            [NOW],
        )
        .unwrap();
    drop(connection);

    let mut rejected = rig.request(ObservationPhase::PreAction);
    rejected.expected_config_sha256 = observer.config_sha256().to_owned();
    let rejected = rig.prepare(rejected);
    assert_eq!(
        observer.observe_at(rejected.clone(), NOW).await,
        Err(ObserverError::CapacityExceeded)
    );
    let connection = rusqlite::Connection::open(&database_path).unwrap();
    let status: (String, String) = connection
        .query_row("SELECT status, failure_code FROM observations", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap();
    assert_eq!(status, ("failed".to_owned(), "rate_limited".to_owned()));

    let mut substituted = rejected;
    substituted.audit_provenance = "audit/substituted-after-rate-limit".to_owned();
    sign_observation_request(&mut substituted, &rig.request_seed).unwrap();
    assert_eq!(
        observer.observe_at(substituted, NOW).await,
        Err(ObserverError::ReplayMismatch)
    );
    connection
        .execute("DELETE FROM request_attempts", [])
        .unwrap();
    drop(connection);

    let mut admitted = rig.request(ObservationPhase::PreAction);
    admitted.expected_config_sha256 = observer.config_sha256().to_owned();
    observer
        .observe_at(rig.prepare(admitted), NOW)
        .await
        .unwrap();
}

#[tokio::test]
async fn retained_observation_quota_bounds_rate_limit_tombstones() {
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
    config.limits.max_receipts = 1;
    config.limits.max_observations = 2;
    let observer = rig.observer_for_config(config).unwrap();
    let database_path = state.path().join("observer.sqlite3");
    let connection = rusqlite::Connection::open(&database_path).unwrap();
    connection
        .execute(
            "INSERT INTO request_attempts(attempted_at_ms) VALUES(?1)",
            [NOW],
        )
        .unwrap();
    drop(connection);

    for effect_fence in [18_u64, 19] {
        let mut request = rig.request(ObservationPhase::PreAction);
        request.effect_fence = effect_fence;
        request.expected_config_sha256 = observer.config_sha256().to_owned();
        assert_eq!(
            observer.observe_at(rig.prepare(request), NOW).await,
            Err(ObserverError::CapacityExceeded)
        );
    }

    let reads_before = rig.server.reads.load(Ordering::SeqCst);
    let mut overflow = rig.request(ObservationPhase::PreAction);
    overflow.effect_fence = 20;
    overflow.expected_config_sha256 = observer.config_sha256().to_owned();
    assert_eq!(
        observer.observe_at(rig.prepare(overflow), NOW).await,
        Err(ObserverError::CapacityExceeded)
    );
    assert_eq!(rig.server.reads.load(Ordering::SeqCst), reads_before);
    let connection = rusqlite::Connection::open(database_path).unwrap();
    let retained: u64 = connection
        .query_row("SELECT COUNT(*) FROM observations", [], |row| row.get(0))
        .unwrap();
    assert_eq!(retained, 2);
}

#[tokio::test]
async fn legacy_preview_rate_tombstone_is_normalized_on_restart() {
    let rig = Rig::new().await;
    let state = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let database_path = state.path().join("observer.sqlite3");
    let connection = rusqlite::Connection::open(&database_path).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE observations (
               observation_id TEXT PRIMARY KEY,
               scope_sha256 TEXT NOT NULL,
               destination_scope_sha256 TEXT NOT NULL,
               request_sha256 TEXT NOT NULL,
               phase TEXT NOT NULL,
               status TEXT NOT NULL CHECK(status IN ('pending', 'rate_limited', 'complete', 'failed')),
               retry_count INTEGER NOT NULL,
               created_at_ms INTEGER NOT NULL,
               expires_at_ms INTEGER NOT NULL,
               receipt_sha256 TEXT,
               receipt_json BLOB,
               evidence_bytes INTEGER,
               failure_code TEXT
             );",
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO observations(
               observation_id, scope_sha256, destination_scope_sha256, request_sha256,
               phase, status, retry_count, created_at_ms, expires_at_ms, failure_code
             ) VALUES(?1, ?2, ?3, ?4, 'pre_action', 'rate_limited', 0, ?5, ?6, 'capacity_exceeded')",
            rusqlite::params![
                Uuid::new_v4().to_string(),
                "a".repeat(64),
                "b".repeat(64),
                "c".repeat(64),
                NOW,
                NOW + 1_000,
            ],
        )
        .unwrap();
    drop(connection);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&database_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let mut config = rig.config.clone();
    config.state_dir = state.path().to_path_buf();
    let observer = rig.observer_for_config(config.clone()).unwrap();
    drop(observer);
    let restarted = rig.observer_for_config(config).unwrap();
    drop(restarted);

    let connection = rusqlite::Connection::open(database_path).unwrap();
    let normalized: (String, String) = connection
        .query_row("SELECT status, failure_code FROM observations", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap();
    assert_eq!(normalized, ("failed".to_owned(), "rate_limited".to_owned()));
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
async fn successful_and_terminal_reads_converge_on_a_concurrent_tombstone() {
    for mode in [Mode::Slow, Mode::SlowMalformed] {
        let rig = Rig::new().await;
        rig.set_mode(mode);
        let mut request = rig.request(ObservationPhase::PreAction);
        request.expires_at_unix_ms = NOW + 1_000;
        let request = rig.prepare(request);

        let first_observation = rig.observer.observe_at(request.clone(), NOW);
        let expired_retry = async {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            rig.observer.observe_at(request.clone(), NOW + 2_000).await
        };
        let (first_result, retry_result) = tokio::join!(first_observation, expired_retry);

        assert_eq!(first_result, Err(ObserverError::ExpiredRequest));
        assert_eq!(retry_result, Err(ObserverError::ExpiredRequest));
        assert_eq!(
            rig.observer.observe_at(request, NOW).await,
            Err(ObserverError::ExpiredRequest)
        );
    }
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
async fn response_limit_does_not_reserve_an_impossible_full_size_state() {
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
    assert!(rig.observer_for_config(config).is_ok());
}

#[tokio::test]
async fn schema_work_cap_does_not_reject_linear_growable_required_sizing() {
    let rig = Rig::new().await;
    let state = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut config = rig.config.clone();
    config.state_dir = state.path().to_path_buf();
    config.response_schema = vec![StateFieldSchema {
        name: "required_padding".to_owned(),
        kind: JsonKind::String,
        required: true,
    }];
    config
        .response_schema
        .extend((0..256).map(|index| StateFieldSchema {
            name: format!("optional_{index:03}"),
            kind: JsonKind::Null,
            required: false,
        }));
    assert!(rig.observer_for_config(config).is_ok());
}

#[tokio::test]
async fn boolean_response_and_receipt_sizing_admit_the_shorter_true_value() {
    let rig = Rig::new().await;
    let state = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let maximum_envelope = |published| SignedDestinationState {
        body: DestinationStateBody {
            schema_version: DESTINATION_STATE_SCHEMA_VERSION.to_owned(),
            observation_id: Uuid::from_u128(u128::MAX),
            request_sha256: "f".repeat(64),
            observer_id: rig.config.observer_id.clone(),
            service_identity: rig.config.service_identity.clone(),
            endpoint_identity: rig.config.endpoint_identity.clone(),
            account_identity: rig.config.account_identity.clone(),
            resource_identity: rig.config.resource_identity.clone(),
            effect_class: rig.config.effect_class.clone(),
            effect_fence: u64::MAX,
            phase: ObservationPhase::Reconciliation,
            canonical_query_sha256: "f".repeat(64),
            cursor: i64::MAX as u64,
            observed_at_unix_ms: i64::MAX,
            state_schema_version: rig.config.state_schema_version.clone(),
            confidentiality: Confidentiality::Internal,
            state: json!({"published": published}),
            grant_id: rig.config.read_grant_id.clone(),
            grant_version: rig.config.read_grant_version.clone(),
            grant_scope: rig.config.read_grant_scope.clone(),
            attestation_key_id: rig.config.destination_attestation_key_id.clone(),
        },
        signature_base64: "A".repeat(88),
    };
    let true_len = serde_json::to_vec(&maximum_envelope(true)).unwrap().len();
    assert_eq!(
        serde_json::to_vec(&maximum_envelope(false)).unwrap().len(),
        true_len + 1
    );

    let mut config = rig.config.clone();
    config.state_dir = state.path().to_path_buf();
    config.limits.max_response_bytes = true_len;
    assert!(rig.observer_for_config(config).is_ok());
}

#[tokio::test]
async fn response_sizing_admits_compact_uuid_syntax_at_the_exact_maximum() {
    let rig = Rig::new().await;
    const LATE_NOW: i64 = i64::MAX - 20_000;
    let state = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let maximum = SignedDestinationState {
        body: DestinationStateBody {
            schema_version: DESTINATION_STATE_SCHEMA_VERSION.to_owned(),
            observation_id: Uuid::from_u128(u128::MAX),
            request_sha256: "f".repeat(64),
            observer_id: rig.config.observer_id.clone(),
            service_identity: rig.config.service_identity.clone(),
            endpoint_identity: rig.config.endpoint_identity.clone(),
            account_identity: rig.config.account_identity.clone(),
            resource_identity: rig.config.resource_identity.clone(),
            effect_class: rig.config.effect_class.clone(),
            effect_fence: u64::MAX,
            phase: ObservationPhase::Reconciliation,
            canonical_query_sha256: "f".repeat(64),
            cursor: i64::MAX as u64,
            observed_at_unix_ms: LATE_NOW,
            state_schema_version: rig.config.state_schema_version.clone(),
            confidentiality: Confidentiality::Internal,
            state: json!({"published": true}),
            grant_id: rig.config.read_grant_id.clone(),
            grant_version: rig.config.read_grant_version.clone(),
            grant_scope: rig.config.read_grant_scope.clone(),
            attestation_key_id: rig.config.destination_attestation_key_id.clone(),
        },
        signature_base64: "A".repeat(88),
    };
    let hyphenated = serde_json::to_string(&maximum).unwrap();
    let compact = hyphenated.replacen(
        &Uuid::from_u128(u128::MAX).hyphenated().to_string(),
        &Uuid::from_u128(u128::MAX).simple().to_string(),
        1,
    );
    assert_eq!(hyphenated.len(), compact.len() + 4);

    let mut config = rig.config.clone();
    config.state_dir = state.path().to_path_buf();
    config.limits.max_response_bytes = compact.len();
    config.read_grant_expires_unix_ms = i64::MAX;
    let observer = rig.observer_for_config(config).unwrap();

    rig.server
        .cursor
        .store(i64::MAX as u64 - 2, Ordering::SeqCst);
    rig.server
        .observed_at_unix_ms
        .store(LATE_NOW, Ordering::SeqCst);
    rig.set_mode(Mode::CompactUuid);
    let request_for_phase = |phase| {
        let mut request = rig.request(phase);
        request.effect_fence = u64::MAX;
        request.expected_config_sha256 = observer.config_sha256().to_owned();
        request.requested_at_unix_ms = LATE_NOW - 1;
        request.expires_at_unix_ms = LATE_NOW + 1_000;
        request
    };
    let pre = observer
        .observe_at(
            rig.prepare(request_for_phase(ObservationPhase::PreAction)),
            LATE_NOW,
        )
        .await
        .unwrap();

    rig.server
        .cursor
        .store(i64::MAX as u64 - 1, Ordering::SeqCst);
    let mut post = request_for_phase(ObservationPhase::PostAction);
    post.expected_previous_cursor = Some(pre.destination_cursor);
    post.predecessor_receipt_sha256 = Some(observation_receipt_digest(&pre).unwrap());
    let post = observer
        .observe_at(rig.prepare(post), LATE_NOW)
        .await
        .unwrap();

    rig.server.cursor.store(i64::MAX as u64, Ordering::SeqCst);
    let mut reconciliation = request_for_phase(ObservationPhase::Reconciliation);
    reconciliation.expected_previous_cursor = Some(post.destination_cursor);
    reconciliation.predecessor_receipt_sha256 = Some(observation_receipt_digest(&post).unwrap());
    let receipt = observer
        .observe_at(rig.prepare(reconciliation), LATE_NOW)
        .await
        .unwrap();
    assert_eq!(receipt.destination_cursor, i64::MAX as u64);
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
            config.limits.timeout_ms = u64::try_from(config.limits.max_age_ms).unwrap() + 1;
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
        {
            let mut config = rig.config.clone();
            // Admission covers the complete standalone command wrapper and newline, so an
            // authority identifier cannot push the otherwise valid request past the frame cap.
            config.request_authority_key_id = "k".repeat(MAX_FRAME_BYTES);
            config
        },
        {
            let mut config = rig.config.clone();
            config.response_schema = vec![StateFieldSchema {
                name: "x".repeat(config.limits.max_response_bytes),
                kind: JsonKind::Boolean,
                required: true,
            }];
            config
        },
        {
            let mut config = rig.config.clone();
            config
                .response_schema
                .extend((0..512).map(|index| StateFieldSchema {
                    name: format!("optional_{index:03}"),
                    kind: JsonKind::Null,
                    required: false,
                }));
            config
        },
        {
            let mut config = rig.config.clone();
            config.limits.max_observations = config.limits.max_receipts - 1;
            config
        },
        {
            let mut config = rig.config.clone();
            config.limits.max_runtime_history = 0;
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
async fn request_sizing_admits_all_six_compact_uuids_at_the_frame_boundary() {
    let rig = Rig::new().await;
    let accepts_key_length = |key_length| {
        let mut config = rig.config.clone();
        let state = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        config.state_dir = state.path().to_path_buf();
        config.request_authority_key_id = "k".repeat(key_length);
        rig.observer_for_config(config).is_ok()
    };

    // Find the exact configuration-admission boundary. The accepted wire contract has six UUID
    // fields, each four bytes shorter in compact syntax; the next byte must still fail closed.
    let mut accepted = 1_usize;
    let mut rejected = MAX_FRAME_BYTES;
    while accepted + 1 < rejected {
        let candidate = accepted + (rejected - accepted) / 2;
        if accepts_key_length(candidate) {
            accepted = candidate;
        } else {
            rejected = candidate;
        }
    }
    assert!(accepts_key_length(accepted));
    assert!(!accepts_key_length(rejected));
    assert_eq!(rejected, accepted + 1);

    let mut config = rig.config.clone();
    config.request_authority_key_id = "k".repeat(accepted);
    let maximum = ObservationRequest {
        schema_version: REQUEST_SCHEMA_VERSION.to_owned(),
        protocol_version: PROTOCOL_VERSION.to_owned(),
        observation_id: Uuid::from_u128(u128::MAX),
        tenant_id: Uuid::from_u128(u128::MAX),
        project_id: Uuid::from_u128(u128::MAX),
        pipeline_id: Uuid::from_u128(u128::MAX),
        build_id: Uuid::from_u128(u128::MAX),
        attempt_id: Uuid::from_u128(u128::MAX),
        effect_fence: u64::MAX,
        phase: ObservationPhase::Reconciliation,
        observer_id: config.observer_id.clone(),
        request_authority_identity: config.request_authority_identity.clone(),
        expected_implementation_sha256: rig.implementation_sha256.clone(),
        expected_image_sha256: config.image_sha256.clone(),
        expected_config_sha256: "f".repeat(64),
        expected_generation: config.generation,
        activation_mode: config.activation_mode,
        previous_generation: config.previous_generation,
        rollback_from_generation: config.rollback_from_generation,
        endpoint_identity: config.endpoint_identity.clone(),
        account_identity: config.account_identity.clone(),
        resource_identity: config.resource_identity.clone(),
        effect_class: config.effect_class.clone(),
        read_grant_id: config.read_grant_id.clone(),
        read_grant_version: config.read_grant_version.clone(),
        read_grant_scope: config.read_grant_scope.clone(),
        query: BTreeMap::from([("release_id".to_owned(), "\0".repeat(2048))]),
        expected_previous_cursor: Some(i64::MAX as u64),
        predecessor_receipt_sha256: Some("f".repeat(64)),
        requested_at_unix_ms: NOW,
        expires_at_unix_ms: NOW,
        audit_provenance: "\0".repeat(4096),
        authorization: RequestAuthorization {
            key_id: config.request_authority_key_id,
            signature_base64: "A".repeat(88),
        },
    };
    let hyphenated = serde_json::to_string(&ObserverCommand::Observe { request: maximum }).unwrap();
    let compact = hyphenated.replace(
        &Uuid::from_u128(u128::MAX).hyphenated().to_string(),
        &Uuid::from_u128(u128::MAX).simple().to_string(),
    );
    assert_eq!(hyphenated.len(), compact.len() + 6 * 4);
    assert_eq!(compact.len() + 1, MAX_FRAME_BYTES);
    assert!(hyphenated.len() + 1 > MAX_FRAME_BYTES);
}

#[tokio::test]
async fn v1_config_without_observation_quota_is_explicitly_incompatible() {
    let rig = Rig::new().await;
    let mut legacy_value = serde_json::to_value(&rig.config).unwrap();
    legacy_value["schema_version"] =
        serde_json::Value::String("mcloving.destination-observer-config/v1".to_owned());
    legacy_value
        .get_mut("limits")
        .and_then(serde_json::Value::as_object_mut)
        .unwrap()
        .remove("max_observations");
    assert!(serde_json::from_value::<ObserverConfig>(legacy_value).is_err());
}

#[tokio::test]
async fn v2_config_without_implementation_binding_is_explicitly_incompatible() {
    let rig = Rig::new().await;
    let mut legacy_value = serde_json::to_value(&rig.config).unwrap();
    legacy_value["schema_version"] =
        serde_json::Value::String("mcloving.destination-observer-config/v2".to_owned());
    legacy_value
        .as_object_mut()
        .unwrap()
        .remove("implementation_sha256");
    assert!(serde_json::from_value::<ObserverConfig>(legacy_value).is_err());
}

#[tokio::test]
async fn v3_config_without_schema_work_bounds_is_explicitly_incompatible() {
    let rig = Rig::new().await;
    let mut legacy_config = rig.config.clone();
    legacy_config.schema_version = "mcloving.destination-observer-config/v3".to_owned();
    assert!(matches!(
        rig.observer_for_config(legacy_config),
        Err(ObserverError::InvalidConfig)
    ));
}

#[tokio::test]
async fn v4_config_without_runtime_history_quota_is_explicitly_incompatible() {
    let rig = Rig::new().await;
    let mut legacy_value = serde_json::to_value(&rig.config).unwrap();
    legacy_value["schema_version"] =
        serde_json::Value::String("mcloving.destination-observer-config/v4".to_owned());
    legacy_value
        .get_mut("limits")
        .and_then(serde_json::Value::as_object_mut)
        .unwrap()
        .remove("max_runtime_history");
    assert!(serde_json::from_value::<ObserverConfig>(legacy_value).is_err());
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
async fn exhausted_evidence_bytes_are_rejected_before_destination_access() {
    let rig = Rig::new().await;
    let first = rig.prepare(rig.request(ObservationPhase::PreAction));
    rig.observer.observe_at(first, NOW).await.unwrap();
    let connection =
        rusqlite::Connection::open(rig.directory.path().join("observer.sqlite3")).unwrap();
    connection
        .execute(
            "UPDATE observations SET evidence_bytes=?1 WHERE status='complete'",
            [rig.config.limits.max_evidence_bytes],
        )
        .unwrap();
    drop(connection);

    let reads_before = rig.server.reads.load(Ordering::SeqCst);
    let mut second = rig.request(ObservationPhase::PreAction);
    second.effect_fence = 18;
    assert_eq!(
        rig.observer.observe_at(rig.prepare(second), NOW).await,
        Err(ObserverError::CapacityExceeded)
    );
    assert_eq!(rig.server.reads.load(Ordering::SeqCst), reads_before);
}

#[tokio::test]
async fn completed_evidence_is_pruned_after_the_bounded_replay_window() {
    let rig = Rig::new().await;
    let state = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut config = rig.config.clone();
    config.state_dir = state.path().to_path_buf();
    config.limits.max_receipts = 1;
    let observer = rig.observer_for_config(config).unwrap();

    let mut first = rig.request(ObservationPhase::PreAction);
    first.expected_config_sha256 = observer.config_sha256().to_owned();
    let first = rig.prepare(first);
    observer.observe_at(first.clone(), NOW).await.unwrap();

    let later = NOW + 12_000;
    rig.server
        .observed_at_unix_ms
        .store(later, Ordering::SeqCst);
    let reads = rig.server.reads.load(Ordering::SeqCst);
    assert_eq!(
        observer.observe_at(first, later).await,
        Err(ObserverError::MalformedRequest)
    );
    assert_eq!(rig.server.reads.load(Ordering::SeqCst), reads);
    let connection = rusqlite::Connection::open(state.path().join("observer.sqlite3")).unwrap();
    let pruned: (u64, u64, u64) = connection
        .query_row(
            "SELECT
               (SELECT COUNT(*) FROM observations),
               (SELECT COUNT(*) FROM scope_heads),
               (SELECT COUNT(*) FROM destination_heads)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(pruned, (0, 1, 1));
    drop(connection);

    let mut duplicate_chain = rig.request(ObservationPhase::PreAction);
    duplicate_chain.requested_at_unix_ms = later - 1;
    duplicate_chain.expires_at_unix_ms = later + 1_000;
    duplicate_chain.expected_config_sha256 = observer.config_sha256().to_owned();
    assert_eq!(
        observer
            .observe_at(rig.prepare(duplicate_chain), later)
            .await,
        Err(ObserverError::PhaseMismatch)
    );

    let mut second = rig.request(ObservationPhase::PreAction);
    second.effect_fence = 18;
    second.requested_at_unix_ms = later - 1;
    second.expires_at_unix_ms = later + 1_000;
    second.expected_config_sha256 = observer.config_sha256().to_owned();
    observer
        .observe_at(rig.prepare(second), later)
        .await
        .unwrap();

    let connection = rusqlite::Connection::open(state.path().join("observer.sqlite3")).unwrap();
    let retained: (u64, u64, u64) = connection
        .query_row(
            "SELECT
               (SELECT COUNT(*) FROM observations WHERE status='complete'),
               (SELECT COUNT(*) FROM scope_heads),
               (SELECT COUNT(*) FROM destination_heads)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(retained, (1, 2, 1));
    drop(connection);

    let after_second_retention_window = later + 12_000;
    rig.server
        .observed_at_unix_ms
        .store(after_second_retention_window, Ordering::SeqCst);
    rig.server.cursor.store(9, Ordering::SeqCst);
    let mut rollback = rig.request(ObservationPhase::PreAction);
    rollback.effect_fence = 19;
    rollback.requested_at_unix_ms = after_second_retention_window - 1;
    rollback.expires_at_unix_ms = after_second_retention_window + 1_000;
    rollback.expected_config_sha256 = observer.config_sha256().to_owned();
    assert_eq!(
        observer
            .observe_at(rig.prepare(rollback), after_second_retention_window)
            .await,
        Err(ObserverError::CursorRollback)
    );
}

#[tokio::test]
async fn durable_scope_heads_obey_the_observation_quota_after_receipt_pruning() {
    let rig = Rig::new().await;
    let state = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut config = rig.config.clone();
    config.state_dir = state.path().to_path_buf();
    config.limits.max_receipts = 2;
    config.limits.max_observations = 2;
    let observer = rig.observer_for_config(config).unwrap();

    for effect_fence in [17, 18] {
        let mut request = rig.request(ObservationPhase::PreAction);
        request.effect_fence = effect_fence;
        request.expected_config_sha256 = observer.config_sha256().to_owned();
        observer
            .observe_at(rig.prepare(request), NOW)
            .await
            .unwrap();
    }

    let later = NOW + 12_000;
    rig.server
        .observed_at_unix_ms
        .store(later, Ordering::SeqCst);
    let reads_before = rig.server.reads.load(Ordering::SeqCst);
    let mut third = rig.request(ObservationPhase::PreAction);
    third.effect_fence = 19;
    third.requested_at_unix_ms = later - 1;
    third.expires_at_unix_ms = later + 1_000;
    third.expected_config_sha256 = observer.config_sha256().to_owned();
    assert_eq!(
        observer.observe_at(rig.prepare(third), later).await,
        Err(ObserverError::CapacityExceeded)
    );
    assert_eq!(rig.server.reads.load(Ordering::SeqCst), reads_before);

    let connection = rusqlite::Connection::open(state.path().join("observer.sqlite3")).unwrap();
    let retained: (u64, u64) = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM observations), (SELECT COUNT(*) FROM scope_heads)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(retained, (0, 2));
}

#[tokio::test]
async fn pending_observation_reserves_its_scope_head_until_finalize() {
    let rig = Rig::new().await;
    let state = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut config = rig.config.clone();
    config.state_dir = state.path().to_path_buf();
    config.limits.max_receipts = 2;
    config.limits.max_observations = 2;
    let observer = rig.observer_for_config(config).unwrap();

    let mut first = rig.request(ObservationPhase::PreAction);
    first.effect_fence = 17;
    first.expected_config_sha256 = observer.config_sha256().to_owned();
    observer.observe_at(rig.prepare(first), NOW).await.unwrap();

    rig.set_mode(Mode::Outage);
    let mut reserved = rig.request(ObservationPhase::PreAction);
    reserved.effect_fence = 18;
    reserved.expected_config_sha256 = observer.config_sha256().to_owned();
    let reserved = rig.prepare(reserved);
    assert_eq!(
        observer.observe_at(reserved.clone(), NOW).await,
        Err(ObserverError::DestinationUnavailable)
    );

    rig.set_mode(Mode::Good);
    let reads_before = rig.server.reads.load(Ordering::SeqCst);
    let mut overflow = rig.request(ObservationPhase::PreAction);
    overflow.effect_fence = 19;
    overflow.expected_config_sha256 = observer.config_sha256().to_owned();
    assert_eq!(
        observer.observe_at(rig.prepare(overflow), NOW).await,
        Err(ObserverError::CapacityExceeded)
    );
    assert_eq!(rig.server.reads.load(Ordering::SeqCst), reads_before);

    *rig.server.request.lock().unwrap() = Some(reserved.clone());
    observer.observe_at(reserved, NOW).await.unwrap();
    let connection = rusqlite::Connection::open(state.path().join("observer.sqlite3")).unwrap();
    let retained: (u64, u64) = connection
        .query_row(
            "SELECT
               (SELECT COUNT(*) FROM scope_heads),
               (SELECT COUNT(*) FROM observations WHERE status='pending')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(retained, (2, 0));
}

#[tokio::test]
async fn expired_pending_head_reservation_does_not_block_admission() {
    let rig = Rig::new().await;
    let state = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut config = rig.config.clone();
    config.state_dir = state.path().to_path_buf();
    config.limits.max_receipts = 2;
    config.limits.max_observations = 2;
    let observer = rig.observer_for_config(config).unwrap();

    let mut first = rig.request(ObservationPhase::PreAction);
    first.effect_fence = 17;
    first.expected_config_sha256 = observer.config_sha256().to_owned();
    observer.observe_at(rig.prepare(first), NOW).await.unwrap();

    rig.set_mode(Mode::Outage);
    let mut abandoned = rig.request(ObservationPhase::PreAction);
    abandoned.effect_fence = 18;
    abandoned.expected_config_sha256 = observer.config_sha256().to_owned();
    assert_eq!(
        observer.observe_at(rig.prepare(abandoned), NOW).await,
        Err(ObserverError::DestinationUnavailable)
    );

    let later = NOW + 12_000;
    rig.server
        .observed_at_unix_ms
        .store(later, Ordering::SeqCst);
    rig.set_mode(Mode::Good);
    let mut replacement = rig.request(ObservationPhase::PreAction);
    replacement.effect_fence = 19;
    replacement.requested_at_unix_ms = later - 1;
    replacement.expires_at_unix_ms = later + 1_000;
    replacement.expected_config_sha256 = observer.config_sha256().to_owned();
    observer
        .observe_at(rig.prepare(replacement), later)
        .await
        .unwrap();

    let connection = rusqlite::Connection::open(state.path().join("observer.sqlite3")).unwrap();
    let retained: (u64, u64, u64) = connection
        .query_row(
            "SELECT
               (SELECT COUNT(*) FROM observations),
               (SELECT COUNT(*) FROM observations WHERE status='pending'),
               (SELECT COUNT(*) FROM scope_heads)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(retained, (1, 0, 2));
}

#[tokio::test]
async fn finalize_prunes_receipts_that_expire_during_the_destination_read() {
    let rig = Rig::new().await;
    let state = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut config = rig.config.clone();
    config.state_dir = state.path().to_path_buf();
    config.limits.max_receipts = 2;
    config.limits.max_evidence_bytes = 8 * 1024;
    let observer = rig.observer_for_config(config).unwrap();

    let mut first = rig.request(ObservationPhase::PreAction);
    first.expected_config_sha256 = observer.config_sha256().to_owned();
    first.audit_provenance = "a".repeat(4096);
    let first_receipt = observer.observe_at(rig.prepare(first), NOW).await.unwrap();

    let finalization_base = NOW + 10_950;
    rig.server
        .observed_at_unix_ms
        .store(finalization_base, Ordering::SeqCst);
    rig.set_mode(Mode::Slow);
    let mut second = rig.request(ObservationPhase::PreAction);
    second.effect_fence = 18;
    second.requested_at_unix_ms = finalization_base - 1;
    second.expires_at_unix_ms = finalization_base + 1_000;
    second.expected_config_sha256 = observer.config_sha256().to_owned();
    second.audit_provenance = "b".to_owned();
    let second_receipt = observer
        .observe_at(rig.prepare(second), finalization_base)
        .await
        .unwrap();

    let first_bytes = serde_json::to_vec(&first_receipt).unwrap().len();
    let second_bytes = serde_json::to_vec(&second_receipt).unwrap().len();
    assert!(first_bytes < 8 * 1024);
    assert!(second_bytes < 8 * 1024);
    assert!(first_bytes + second_bytes > 8 * 1024);
    let connection = rusqlite::Connection::open(state.path().join("observer.sqlite3")).unwrap();
    let complete: u64 = connection
        .query_row(
            "SELECT COUNT(*) FROM observations WHERE status='complete'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(complete, 1);
}

#[tokio::test]
async fn grant_expiry_and_credential_or_configuration_substitution_are_denied() {
    let rig = Rig::new().await;
    let mut expired = rig.request(ObservationPhase::PreAction);
    expired.requested_at_unix_ms = NOW + 60_000;
    expired.expires_at_unix_ms = NOW + 61_500;
    let expired = rig.prepare(expired);
    let expired_result = rig.observer.observe_at(expired, NOW + 61_000).await;
    assert_eq!(expired_result, Err(ObserverError::ExpiredGrant));

    rig.set_mode(Mode::Slow);
    let mut expires_during_read = rig.request(ObservationPhase::PreAction);
    expires_during_read.expires_at_unix_ms = NOW + 50;
    let expires_during_read = rig.prepare(expires_during_read);
    assert_eq!(
        rig.observer.observe_at(expires_during_read, NOW).await,
        Err(ObserverError::ExpiredRequest)
    );

    let grant_rig = Rig::new().await;
    grant_rig.set_mode(Mode::SlowMalformed);
    let grant_state = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(grant_state.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut grant_config = grant_rig.config.clone();
    grant_config.state_dir = grant_state.path().to_path_buf();
    grant_config.read_grant_expires_unix_ms = NOW + 50;
    let grant_observer = grant_rig.observer_for_config(grant_config).unwrap();
    let mut expires_grant_during_terminal_read = grant_rig.request(ObservationPhase::PreAction);
    expires_grant_during_terminal_read.expected_config_sha256 =
        grant_observer.config_sha256().to_owned();
    let expires_grant_during_terminal_read = grant_rig.prepare(expires_grant_during_terminal_read);
    assert_eq!(
        grant_observer
            .observe_at(expires_grant_during_terminal_read, NOW)
            .await,
        Err(ObserverError::ExpiredGrant)
    );
    rig.set_mode(Mode::Good);
    let replacement = rig.prepare(rig.request(ObservationPhase::PreAction));
    rig.observer.observe_at(replacement, NOW).await.unwrap();

    let substituted_markers = vec![b"substituted-token".to_vec(), SECRET.to_vec()];
    let substituted_marker_digests: Vec<String> = substituted_markers
        .iter()
        .map(|marker| content_sha256(marker))
        .collect();
    let mut substituted_credential_config = rig.config.clone();
    substituted_credential_config.secret_marker_set_sha256 = domain_digest(
        b"mcloving-secret-marker-set-v1",
        &substituted_marker_digests,
    );
    let substituted_credential = DestinationObserver::new_for_loopback_test(
        substituted_credential_config,
        rig.implementation_sha256.clone(),
        rig.image_sha256.clone(),
        b"substituted-token".to_vec(),
        rig.request_public_key.clone(),
        rig.destination_public_key.clone(),
        rig.receipt_seed.clone(),
        substituted_markers,
    );
    let identity_substitution_denied =
        matches!(substituted_credential, Err(ObserverError::InvalidConfig));
    assert!(identity_substitution_denied);
    diff003::record_assertion(
        "observer_identity_substitution_denied",
        "denied",
        serde_json::json!({
            "presented_credential_sha256": content_sha256(b"substituted-token"),
            "expected_credential_sha256": rig.config.read_token_sha256.clone(),
            "result": "invalid_config",
        }),
        identity_substitution_denied,
    );
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&empty_ca, fs::Permissions::from_mode(0o600)).unwrap();
    }
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
    let mut revoked_config = rig.config.clone();
    revoked_config.state_dir = state.path().to_path_buf();
    let revocation_digest = revoked_config.revocation_digest().unwrap();
    revoked_config
        .denied_authority_sha256
        .push(revocation_digest);
    assert!(matches!(
        rig.observer_for_config(revoked_config),
        Err(ObserverError::InvalidConfig)
    ));
    assert!(!state.path().join("observer.sqlite3").exists());

    let state = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut substituted_implementation = rig.config.clone();
    substituted_implementation.state_dir = state.path().to_path_buf();
    substituted_implementation.implementation_sha256 = "f".repeat(64);
    assert!(matches!(
        rig.observer_for_config(substituted_implementation),
        Err(ObserverError::InvalidConfig)
    ));
    assert!(!state.path().join("observer.sqlite3").exists());

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
async fn secret_bearing_public_configuration_is_rejected_before_ledger_creation() {
    let rig = Rig::new().await;
    for secret_value in [
        String::from_utf8(TOKEN.to_vec()).unwrap(),
        BASE64.encode(TOKEN),
    ] {
        let state = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut config = rig.config.clone();
        config.state_dir = state.path().to_path_buf();
        config.resource_identity = secret_value;
        assert!(matches!(
            rig.observer_for_config(config),
            Err(ObserverError::InvalidConfig)
        ));
        assert!(!state.path().join("observer.sqlite3").exists());
    }
}

#[cfg(unix)]
#[tokio::test]
async fn ledger_is_owner_private_and_rejects_a_preexisting_symlink() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

    let rig = Rig::new().await;
    for path in [
        rig.directory.path().join("observer.sqlite3"),
        rig.directory.path().join("observer.sqlite3-wal"),
        rig.directory.path().join("observer.sqlite3-shm"),
    ] {
        let Ok(metadata) = fs::symlink_metadata(path) else {
            continue;
        };
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.uid(), nix::unistd::geteuid().as_raw());
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
    }

    let state = tempfile::tempdir().unwrap();
    fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let outside = tempfile::tempdir().unwrap();
    let target = outside.path().join("do-not-open.sqlite3");
    fs::write(&target, b"sentinel").unwrap();
    symlink(&target, state.path().join("observer.sqlite3")).unwrap();
    let mut config = rig.config.clone();
    config.state_dir = state.path().to_path_buf();
    assert!(matches!(
        rig.observer_for_config(config),
        Err(ObserverError::StateUnavailable)
    ));
    assert_eq!(fs::read(target).unwrap(), b"sentinel");

    let dangling_state = tempfile::tempdir().unwrap();
    fs::set_permissions(dangling_state.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let dangling_target = outside.path().join("must-not-be-created.sqlite3");
    symlink(
        &dangling_target,
        dangling_state.path().join("observer.sqlite3"),
    )
    .unwrap();
    let mut dangling_config = rig.config.clone();
    dangling_config.state_dir = dangling_state.path().to_path_buf();
    assert!(matches!(
        rig.observer_for_config(dangling_config),
        Err(ObserverError::StateUnavailable)
    ));
    assert!(!dangling_target.exists());

    let hardlink_state = tempfile::tempdir().unwrap();
    fs::set_permissions(hardlink_state.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let hardlink_target = outside.path().join("must-not-lock");
    fs::write(&hardlink_target, b"lease-sentinel").unwrap();
    fs::set_permissions(&hardlink_target, fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(
        &hardlink_target,
        hardlink_state.path().join("destination-observer.lock"),
    )
    .unwrap();
    let mut hardlink_config = rig.config.clone();
    hardlink_config.state_dir = hardlink_state.path().to_path_buf();
    assert!(matches!(
        rig.observer_for_config(hardlink_config),
        Err(ObserverError::StateUnavailable)
    ));
    assert_eq!(fs::read(&hardlink_target).unwrap(), b"lease-sentinel");
    assert_eq!(fs::metadata(&hardlink_target).unwrap().nlink(), 2);

    let permissive_state = tempfile::tempdir().unwrap();
    fs::set_permissions(permissive_state.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let permissive_lease = permissive_state.path().join("destination-observer.lock");
    fs::write(&permissive_lease, b"preexisting").unwrap();
    fs::set_permissions(&permissive_lease, fs::Permissions::from_mode(0o640)).unwrap();
    let mut permissive_config = rig.config.clone();
    permissive_config.state_dir = permissive_state.path().to_path_buf();
    assert!(matches!(
        rig.observer_for_config(permissive_config),
        Err(ObserverError::StateUnavailable)
    ));
    assert_eq!(
        fs::metadata(&permissive_lease).unwrap().mode() & 0o777,
        0o640
    );

    for suffix in ["-wal", "-shm"] {
        let state = tempfile::tempdir().unwrap();
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let target = outside.path().join(format!("do-not-open{suffix}"));
        fs::write(&target, b"sidecar-sentinel").unwrap();
        symlink(
            &target,
            state.path().join(format!("observer.sqlite3{suffix}")),
        )
        .unwrap();
        let mut config = rig.config.clone();
        config.state_dir = state.path().to_path_buf();
        assert!(matches!(
            rig.observer_for_config(config),
            Err(ObserverError::StateUnavailable)
        ));
        assert_eq!(fs::read(target).unwrap(), b"sidecar-sentinel");
    }
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
    cutover_config.resource_identity = "release/scope-changing-cutover".to_owned();
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
    assert!(matches!(
        rig.observer_for_config(cutover_config.clone()),
        Err(ObserverError::ObservationPending)
    ));
    drop(lease);
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

#[tokio::test]
async fn runtime_history_quota_blocks_growth_but_allows_exact_generation_restart() {
    let rig = Rig::new().await;
    let old_digest = rig.observer.config_sha256().to_owned();

    let mut cutover_config = rig.config.clone();
    cutover_config.limits.max_runtime_history = 2;
    cutover_config.generation = 2;
    cutover_config.activation_mode = ActivationMode::Cutover;
    cutover_config.previous_generation = Some(1);
    cutover_config.previous_config_sha256 = Some(old_digest.clone());
    cutover_config.resource_identity = "release/history-bounded-cutover".to_owned();
    let cutover = rig.observer_for_config(cutover_config.clone()).unwrap();
    let cutover_digest = cutover.config_sha256().to_owned();
    assert!(rig.observer_for_config(cutover_config).is_ok());

    let mut rollback_config = rig.config.clone();
    rollback_config.limits.max_runtime_history = 2;
    rollback_config.generation = 3;
    rollback_config.activation_mode = ActivationMode::Rollback;
    rollback_config.previous_generation = Some(1);
    rollback_config.previous_config_sha256 = Some(old_digest);
    rollback_config.rollback_from_generation = Some(2);
    rollback_config.resource_identity = "release/history-bounded-rollback".to_owned();
    assert!(matches!(
        rig.observer_for_config(rollback_config),
        Err(ObserverError::CapacityExceeded)
    ));

    let connection =
        rusqlite::Connection::open(rig.directory.path().join("observer.sqlite3")).unwrap();
    let history_count: usize = connection
        .query_row("SELECT COUNT(*) FROM runtime_history", [], |row| row.get(0))
        .unwrap();
    let active: (u64, String) = connection
        .query_row(
            "SELECT generation, config_sha256 FROM active_runtime WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(history_count, 2);
    assert_eq!(active, (2, cutover_digest));
}

#[cfg(all(target_os = "linux", feature = "loopback-test"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn standalone_process_emits_a_verified_receipt_and_exposes_no_write_operation() {
    let rig = Rig::new().await;
    let production_binary_path = env!("CARGO_BIN_EXE_mcloving-destination-observer");
    let binary_path = env!("CARGO_BIN_EXE_mcloving-destination-observer-loopback-test");
    let binary = fs::read(binary_path).unwrap();
    let process_directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(process_directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut config = rig.config.clone();
    config.implementation_sha256 = content_sha256(&binary);
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
    fs::write(&image_sha256_path, format!("{}\n", config.image_sha256)).unwrap();
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
    let mut write_request = rig.request(ObservationPhase::PostAction);
    sign_observation_request(&mut write_request, &rig.request_seed).unwrap();
    let write_command = serde_json::to_vec(&ObserverCommand::Write {
        request: write_request,
    })
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

    for key_index in [3_usize, 4] {
        fs::set_permissions(&paths[key_index], fs::Permissions::from_mode(0o640)).unwrap();
        let rejected_key = Command::new(binary_path)
            .args(paths.clone())
            .output()
            .unwrap();
        assert_eq!(rejected_key.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&rejected_key.stderr).contains("state_unavailable"));
        assert!(!config.state_dir.join("observer.sqlite3").exists());
        fs::set_permissions(&paths[key_index], fs::Permissions::from_mode(0o600)).unwrap();
    }

    let rejected = Command::new(production_binary_path)
        .args(paths.clone())
        .output()
        .unwrap();
    assert_eq!(rejected.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("invalid_config"));
    assert!(!config.state_dir.join("observer.sqlite3").exists());

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
        input.write_all(&write_command).unwrap();
        input.write_all(b"\n").unwrap();
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
    assert_eq!(responses[1]["code"], "unauthorized_request");
    let write_permission_denied = responses[0]["status"] == "observed"
        && responses[1]["status"] == "error"
        && responses[1]["code"] == "unauthorized_request";
    diff003::record_assertion(
        "observer_write_permission_denied",
        "denied",
        serde_json::json!({
            "read_operation_status": responses[0]["status"],
            "write_request_well_formed": true,
            "read_only_boundary": true,
            "write_operation_status": responses[1]["status"],
            "write_operation_code": responses[1]["code"],
        }),
        write_permission_denied,
    );
}

#[tokio::test]
async fn signature_binding_phase_cursor_and_replay_substitution_fail_closed() {
    let rig = Rig::new().await;
    let unsigned = rig.request(ObservationPhase::PreAction);
    assert_eq!(
        rig.observer.observe_at(unsigned, NOW).await,
        Err(ObserverError::UnauthorizedRequest)
    );

    let reads_before_confidential_request = rig.server.reads.load(Ordering::SeqCst);
    let mut secret_query = rig.request(ObservationPhase::PreAction);
    secret_query.query.insert(
        "release_id".to_owned(),
        String::from_utf8(SECRET.to_vec()).unwrap(),
    );
    assert_eq!(
        rig.observer
            .observe_at(rig.prepare(secret_query), NOW)
            .await,
        Err(ObserverError::ConfidentialityDenied)
    );
    let mut embedded_secret_query = rig.request(ObservationPhase::PreAction);
    embedded_secret_query.query.insert(
        "release_id".to_owned(),
        format!(
            "prefix:{}:suffix",
            BASE64.encode([b"x".as_slice(), SECRET].concat())
        ),
    );
    assert_eq!(
        rig.observer
            .observe_at(rig.prepare(embedded_secret_query), NOW)
            .await,
        Err(ObserverError::ConfidentialityDenied)
    );
    let mut secret_audit = rig.request(ObservationPhase::PreAction);
    secret_audit.audit_provenance = String::from_utf8(SECRET.to_vec()).unwrap();
    assert_eq!(
        rig.observer
            .observe_at(rig.prepare(secret_audit), NOW)
            .await,
        Err(ObserverError::ConfidentialityDenied)
    );
    assert_eq!(
        rig.server.reads.load(Ordering::SeqCst),
        reads_before_confidential_request
    );

    let first = rig.prepare(rig.request(ObservationPhase::PreAction));
    let receipt = rig.observer.observe_at(first.clone(), NOW).await.unwrap();
    let observation_id = first.observation_id;
    let mut substituted = first;
    substituted.audit_provenance = "audit/forged".to_owned();
    sign_observation_request(&mut substituted, &rig.request_seed).unwrap();
    let replay_result = rig.observer.observe_at(substituted, NOW).await;
    let replay_denied = replay_result == Err(ObserverError::ReplayMismatch);
    assert!(replay_denied);
    diff003::record_assertion(
        "observer_replay_denied",
        "denied",
        serde_json::json!({
            "observation_id": observation_id,
            "mutation": "audit_provenance",
            "result": "replay_mismatch",
        }),
        replay_denied,
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
async fn locally_invalid_phase_is_rejected_before_destination_lease_contention() {
    let rig = Rig::new().await;
    let pre = rig.prepare(rig.request(ObservationPhase::PreAction));
    rig.observer.observe_at(pre, NOW).await.unwrap();

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

    let invalid_pre = rig.prepare(rig.request(ObservationPhase::PreAction));
    assert_eq!(
        rig.observer.observe_at(invalid_pre, NOW).await,
        Err(ObserverError::PhaseMismatch)
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

    rig.server.cursor.store(11, Ordering::SeqCst);
    let mut advanced_scope = rig.request(ObservationPhase::PreAction);
    advanced_scope.effect_fence = 20;
    rig.observer
        .observe_at(rig.prepare(advanced_scope), NOW)
        .await
        .unwrap();

    rig.server.cursor.store(10, Ordering::SeqCst);
    let mut rolled_back_scope = rig.request(ObservationPhase::PreAction);
    rolled_back_scope.effect_fence = 21;
    assert_eq!(
        rig.observer
            .observe_at(rig.prepare(rolled_back_scope), NOW)
            .await,
        Err(ObserverError::CursorRollback)
    );

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

#[tokio::test]
async fn effect_fence_accepts_the_complete_unsigned_range() {
    let rig = Rig::new().await;
    let mut request = rig.request(ObservationPhase::PreAction);
    request.effect_fence = u64::MAX;
    let receipt = rig
        .observer
        .observe_at(rig.prepare(request), NOW)
        .await
        .unwrap();
    assert_eq!(receipt.effect_fence, u64::MAX);
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
