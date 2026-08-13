use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Router, response::IntoResponse};
use mcloving_destination_observer::{
    ActivationMode as ObserverActivationMode, Confidentiality, ObservationPhase, ObservationReceipt,
};
use mcloving_external_connector::*;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::net::TcpListener;
use uuid::Uuid;

const NOW: i64 = 1_800_000_000_000;
const TOKEN: &[u8] = b"connector-only-token";
const SECRET: &[u8] = b"never-publish-connector-secret";

#[derive(Clone, Copy)]
enum Mode {
    Success,
    FailOnce,
    Timeout,
    Substitute,
    Secret,
    Malformed,
    Denied,
    SignedFailure,
    SignedRetryOnce,
}

#[derive(Clone)]
struct DestinationState {
    mode: Mode,
    calls: Arc<AtomicUsize>,
    seed: Vec<u8>,
}

struct Rig {
    _state: TempDir,
    config: ConnectorConfig,
    request_seed: Vec<u8>,
    destination_seed: Vec<u8>,
    outcome_seed: Vec<u8>,
    observer_seed: Vec<u8>,
    connector: ExternalConnector,
    calls: Arc<AtomicUsize>,
}

impl Rig {
    async fn new(mode: Mode, _class: IdempotencyClass) -> Self {
        let request_seed = vec![1; 32];
        let destination_seed = vec![2; 32];
        let outcome_seed = vec![3; 32];
        let observer_seed = vec![4; 32];
        let calls = Arc::new(AtomicUsize::new(0));
        let destination_state = DestinationState {
            mode,
            calls: Arc::clone(&calls),
            seed: destination_seed.clone(),
        };
        let app = Router::new()
            .route("/effect", post(destination))
            .with_state(destination_state);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let state = tempfile::tempdir().unwrap();
        make_private(state.path());
        let mut public_output_schema = BTreeMap::new();
        public_output_schema.insert("url".to_owned(), JsonKind::String);
        let config = ConnectorConfig {
            schema_version: CONFIG_SCHEMA_VERSION.to_owned(),
            protocol_version: PROTOCOL_VERSION.to_owned(),
            connector_id: "connector/release/v1".to_owned(),
            implementation_sha256: "a".repeat(64),
            image_sha256: "b".repeat(64),
            deployment_identity: "deployment/connector".to_owned(),
            operator_trust_identity: "operator/connector".to_owned(),
            runtime_boundary_identity: "runtime/connector".to_owned(),
            service_identity: "service/connector".to_owned(),
            configuration_authority_identity: "authority/config".to_owned(),
            request_authority_identity: "authority/request".to_owned(),
            credential_issuance_path_identity: "issuer/connector".to_owned(),
            generation: 1,
            activation_mode: ActivationMode::Current,
            previous_generation: None,
            rollback_from_generation: None,
            endpoint_url: format!("http://{address}/effect"),
            endpoint_identity: "endpoint/releases".to_owned(),
            account_identity: "account/production".to_owned(),
            resource_identity: "resource/release".to_owned(),
            effect_class: "release_publication".to_owned(),
            action_name: "publish_release".to_owned(),
            action_schema_version: "release-publication/v1".to_owned(),
            public_output_schema,
            allowed_secret_taints: BTreeSet::from(["release-token".to_owned()]),
            credential_grant_id: "grant/release".to_owned(),
            credential_grant_version: "generation/7".to_owned(),
            credential_grant_scope: "release:write".to_owned(),
            credential_grant_expires_unix_ms: NOW + 60_000,
            credential_token_sha256: content_sha256(TOKEN),
            request_authority_key_id: "key/request".to_owned(),
            request_authority_key_sha256: content_sha256(
                &public_key_from_seed(&request_seed).unwrap(),
            ),
            destination_attestation_key_id: "key/destination".to_owned(),
            destination_attestation_key_sha256: content_sha256(
                &public_key_from_seed(&destination_seed).unwrap(),
            ),
            outcome_signing_key_id: "key/outcome".to_owned(),
            outcome_signing_seed_sha256: content_sha256(&outcome_seed),
            outcome_signing_public_key_sha256: content_sha256(
                &public_key_from_seed(&outcome_seed).unwrap(),
            ),
            observer_id: "observer/releases".to_owned(),
            observer_receipt_key_sha256: content_sha256(
                &public_key_from_seed(&observer_seed).unwrap(),
            ),
            denied_peer_identities: vec![
                "scheduler/controller".to_owned(),
                "database/controller".to_owned(),
                "agent/runtime".to_owned(),
                "shadow/replay".to_owned(),
            ],
            denied_authority_sha256: Vec::new(),
            limits: ConnectorLimits {
                max_request_bytes: 64 * 1024,
                max_response_bytes: 64 * 1024,
                max_public_output_bytes: 8 * 1024,
                max_receipts: 64,
                max_attempts: 2,
                timeout_ms: 50,
                max_authority_window_ms: 60_000,
            },
            state_dir: state.path().to_path_buf(),
            ca_bundle_path: None,
            ca_bundle_sha256: None,
            test_allow_http_loopback: true,
        };
        let connector = ExternalConnector::new_loopback_test(
            config.clone(),
            public_key_from_seed(&request_seed).unwrap(),
            public_key_from_seed(&destination_seed).unwrap(),
            outcome_seed.clone(),
            public_key_from_seed(&observer_seed).unwrap(),
            TOKEN.to_vec(),
            vec![TOKEN.to_vec(), SECRET.to_vec()],
        )
        .unwrap();
        Self {
            _state: state,
            config,
            request_seed,
            destination_seed,
            outcome_seed,
            observer_seed,
            connector,
            calls,
        }
    }

    fn request(&self, class: IdempotencyClass) -> ActionRequest {
        let mut request = ActionRequest {
            schema_version: REQUEST_SCHEMA_VERSION.to_owned(),
            protocol_version: PROTOCOL_VERSION.to_owned(),
            request_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            pipeline_id: Uuid::new_v4(),
            build_id: Uuid::new_v4(),
            attempt_id: Uuid::new_v4(),
            effect_fence: 9,
            effect_key: "publish/release-1".to_owned(),
            connector_id: self.config.connector_id.clone(),
            expected_implementation_sha256: self.config.implementation_sha256.clone(),
            expected_image_sha256: self.config.image_sha256.clone(),
            expected_config_sha256: self.connector.config_sha256().to_owned(),
            expected_generation: self.config.generation,
            endpoint_identity: self.config.endpoint_identity.clone(),
            account_identity: self.config.account_identity.clone(),
            resource_identity: self.config.resource_identity.clone(),
            effect_class: self.config.effect_class.clone(),
            idempotency_class: class,
            action_name: self.config.action_name.clone(),
            action_schema_version: self.config.action_schema_version.clone(),
            request_payload: json!({"release": "v1.0.0"}),
            credential_grant_id: self.config.credential_grant_id.clone(),
            credential_grant_version: self.config.credential_grant_version.clone(),
            credential_grant_scope: self.config.credential_grant_scope.clone(),
            requested_at_unix_ms: NOW,
            expires_at_unix_ms: NOW + 30_000,
            audit_provenance: "audit/effect/1".to_owned(),
            authorization: RequestAuthorization {
                key_id: self.config.request_authority_key_id.clone(),
                signature_base64: String::new(),
            },
        };
        sign_action_request(&mut request, &self.request_seed).unwrap();
        request
    }

    fn restart(&self) -> ExternalConnector {
        ExternalConnector::new_loopback_test(
            self.config.clone(),
            public_key_from_seed(&self.request_seed).unwrap(),
            public_key_from_seed(&self.destination_seed).unwrap(),
            self.outcome_seed.clone(),
            public_key_from_seed(&self.observer_seed).unwrap(),
            TOKEN.to_vec(),
            vec![TOKEN.to_vec(), SECRET.to_vec()],
        )
        .unwrap()
    }
}

async fn destination(
    State(state): State<DestinationState>,
    headers: HeaderMap,
    Json(envelope): Json<DestinationActionEnvelope>,
) -> impl IntoResponse {
    let call = state.calls.fetch_add(1, Ordering::SeqCst);
    if headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        != Some("Bearer connector-only-token")
    {
        return (StatusCode::FORBIDDEN, Json(json!({"error":"denied"}))).into_response();
    }
    match state.mode {
        Mode::FailOnce if call == 0 => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":"retry"})),
            )
                .into_response();
        }
        Mode::Timeout => {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        Mode::Malformed => {
            return (StatusCode::OK, [("content-type", "application/json")], "{").into_response();
        }
        Mode::Denied => {
            return (StatusCode::FORBIDDEN, Json(json!({"error":"denied"}))).into_response();
        }
        _ => {}
    }
    let request = envelope.request;
    let mut body = DestinationOutcomeBody {
        schema_version: DESTINATION_RESPONSE_SCHEMA_VERSION.to_owned(),
        request_id: request.request_id,
        request_sha256: envelope.request_sha256,
        connector_id: request.connector_id,
        service_identity: "service/connector".to_owned(),
        endpoint_identity: request.endpoint_identity,
        account_identity: request.account_identity,
        resource_identity: request.resource_identity,
        effect_class: request.effect_class,
        effect_fence: request.effect_fence,
        action_name: request.action_name,
        status: OutcomeStatus::Succeeded,
        status_code: "published".to_owned(),
        public_values: BTreeMap::from([(
            "url".to_owned(),
            Value::String("https://releases.invalid/v1.0.0".to_owned()),
        )]),
        protected_secret_refs: vec![ProtectedSecretRef {
            provider_identity: "secrets/release".to_owned(),
            reference: "receipt/credential".to_owned(),
            version: "7".to_owned(),
            taint: "release-token".to_owned(),
        }],
        external_ids: BTreeMap::from([("release_id".to_owned(), "rel-1".to_owned())]),
        downstream_control_digest: content_sha256(b"continue"),
        later_intents_digest: content_sha256(b"notify"),
        completed_at_unix_ms: NOW + 1,
        credential_grant_id: request.credential_grant_id,
        credential_grant_version: request.credential_grant_version,
        credential_grant_scope: request.credential_grant_scope,
        attestation_key_id: "key/destination".to_owned(),
    };
    if matches!(state.mode, Mode::Substitute) {
        body.resource_identity = "resource/substituted".to_owned();
    }
    if matches!(state.mode, Mode::Secret) {
        body.public_values.insert(
            "url".to_owned(),
            Value::String(String::from_utf8(SECRET.to_vec()).unwrap()),
        );
    }
    let mut response = SignedDestinationOutcome {
        body,
        signature_base64: String::new(),
    };
    if matches!(state.mode, Mode::SignedFailure) {
        response.body.status = OutcomeStatus::Failed;
        response.body.status_code = "destination_rejected".to_owned();
    }
    if matches!(state.mode, Mode::SignedRetryOnce) && call == 0 {
        response.body.status = OutcomeStatus::RetryableFailure;
        response.body.status_code = "destination_busy".to_owned();
    }
    sign_destination_outcome(&mut response, &state.seed).unwrap();
    (StatusCode::OK, Json(response)).into_response()
}

#[tokio::test]
async fn success_is_signed_exactly_once_and_restart_replays_without_transport() {
    let rig = Rig::new(Mode::Success, IdempotencyClass::ExternallyIdempotent).await;
    let request = rig.request(IdempotencyClass::ExternallyIdempotent);
    let first = rig
        .connector
        .execute_at(request.clone(), NOW)
        .await
        .unwrap();
    assert_eq!(first.status, OutcomeStatus::Succeeded);
    assert_eq!(first.attempt_count, 1);
    verify_outcome_receipt(&first, &public_key_from_seed(&rig.outcome_seed).unwrap()).unwrap();
    let replay = rig.restart().execute_at(request, NOW + 10).await.unwrap();
    assert_eq!(replay, first);
    assert_eq!(rig.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn retry_safe_action_retries_with_one_stable_request_identity() {
    let rig = Rig::new(Mode::FailOnce, IdempotencyClass::ExternallyIdempotent).await;
    let receipt = rig
        .connector
        .execute_at(rig.request(IdempotencyClass::ExternallyIdempotent), NOW)
        .await
        .unwrap();
    assert_eq!(receipt.status, OutcomeStatus::Succeeded);
    assert_eq!(receipt.attempt_count, 2);
    assert_eq!(rig.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn signed_failure_is_terminal_and_signed_retryable_outcome_is_bounded() {
    let failed = Rig::new(Mode::SignedFailure, IdempotencyClass::ExternallyIdempotent).await;
    let failed_receipt = failed
        .connector
        .execute_at(failed.request(IdempotencyClass::ExternallyIdempotent), NOW)
        .await
        .unwrap();
    assert_eq!(failed_receipt.status, OutcomeStatus::Failed);
    assert_eq!(failed_receipt.status_code, "destination_rejected");
    assert_eq!(failed.calls.load(Ordering::SeqCst), 1);

    let retry = Rig::new(
        Mode::SignedRetryOnce,
        IdempotencyClass::ExternallyIdempotent,
    )
    .await;
    let retry_receipt = retry
        .connector
        .execute_at(retry.request(IdempotencyClass::ExternallyIdempotent), NOW)
        .await
        .unwrap();
    assert_eq!(retry_receipt.status, OutcomeStatus::Succeeded);
    assert_eq!(retry_receipt.attempt_count, 2);
    assert_eq!(retry.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn non_idempotent_timeout_is_ambiguous_and_never_retried() {
    let rig = Rig::new(Mode::Timeout, IdempotencyClass::NonIdempotent).await;
    let request = rig.request(IdempotencyClass::NonIdempotent);
    let receipt = rig
        .connector
        .execute_at(request.clone(), NOW)
        .await
        .unwrap();
    assert_eq!(receipt.status, OutcomeStatus::Ambiguous);
    assert!(receipt.ambiguous_requires_observation);
    let replay = rig.restart().execute_at(request, NOW + 1).await.unwrap();
    assert_eq!(replay, receipt);
    assert_eq!(rig.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn malformed_substituted_and_secret_bearing_outcomes_fail_closed() {
    for (mode, code) in [
        (Mode::Malformed, "malformed_response"),
        (Mode::Substitute, "malformed_response"),
        (Mode::Secret, "confidentiality_denied"),
    ] {
        let rig = Rig::new(mode, IdempotencyClass::ExternallyIdempotent).await;
        let receipt = rig
            .connector
            .execute_at(rig.request(IdempotencyClass::ExternallyIdempotent), NOW)
            .await
            .unwrap();
        assert_eq!(receipt.status, OutcomeStatus::Failed);
        assert_eq!(receipt.status_code, code);
    }
}

#[tokio::test]
async fn stale_substituted_replayed_and_permission_negative_requests_are_denied() {
    let rig = Rig::new(Mode::Success, IdempotencyClass::ExternallyIdempotent).await;
    let mut stale = rig.request(IdempotencyClass::ExternallyIdempotent);
    stale.expires_at_unix_ms = NOW + 1;
    sign_action_request(&mut stale, &rig.request_seed).unwrap();
    assert_eq!(
        rig.connector.execute_at(stale, NOW + 2).await,
        Err(ConnectorError::ExpiredAuthority)
    );

    let mut substituted = rig.request(IdempotencyClass::ExternallyIdempotent);
    sign_action_request(&mut substituted, &rig.request_seed).unwrap();
    substituted.resource_identity = "resource/substituted-after-signing".to_owned();
    assert_eq!(
        rig.connector.execute_at(substituted, NOW).await,
        Err(ConnectorError::UnauthorizedRequest)
    );

    let request = rig.request(IdempotencyClass::ExternallyIdempotent);
    rig.connector
        .execute_at(request.clone(), NOW)
        .await
        .unwrap();
    let mut divergent_replay = request;
    divergent_replay.audit_provenance = "audit/divergent-replay".to_owned();
    sign_action_request(&mut divergent_replay, &rig.request_seed).unwrap();
    assert_eq!(
        rig.connector.execute_at(divergent_replay, NOW).await,
        Err(ConnectorError::ReplayMismatch)
    );

    let denied = Rig::new(Mode::Denied, IdempotencyClass::ExternallyIdempotent).await;
    let receipt = denied
        .connector
        .execute_at(denied.request(IdempotencyClass::ExternallyIdempotent), NOW)
        .await
        .unwrap();
    assert_eq!(receipt.status, OutcomeStatus::Failed);
    assert_eq!(receipt.status_code, "destination_unauthorized");
}

#[tokio::test]
async fn signed_reconciliation_is_the_only_ambiguous_unfreeze_path() {
    let rig = Rig::new(Mode::Timeout, IdempotencyClass::NonIdempotent).await;
    let action = rig.request(IdempotencyClass::NonIdempotent);
    let ambiguous = rig.connector.execute_at(action.clone(), NOW).await.unwrap();
    let ambiguous_digest = outcome_receipt_digest(&ambiguous).unwrap();
    let mut stale_observation = observation_for(&rig, &ambiguous, true);
    stale_observation.destination_observed_at_unix_ms = NOW - 1;
    stale_observation.captured_at_unix_ms = NOW - 1;
    mcloving_destination_observer::sign_receipt(&mut stale_observation, &rig.observer_seed)
        .unwrap();
    assert_eq!(
        rig.connector.reconcile_at(
            ReconcileRequest {
                schema_version: RECONCILE_REQUEST_SCHEMA_VERSION.to_owned(),
                request_id: action.request_id,
                expected_request_sha256: ambiguous.request_sha256.clone(),
                expected_ambiguous_receipt_sha256: ambiguous_digest.clone(),
                observed_effect: true,
                observation_receipt: stale_observation,
                audit_provenance: "audit/reconcile/stale".to_owned(),
            },
            NOW + 500,
        ),
        Err(ConnectorError::InvalidObservation)
    );
    let mut observation = observation_for(&rig, &ambiguous, true);
    mcloving_destination_observer::sign_receipt(&mut observation, &rig.observer_seed).unwrap();
    let reconciled = rig
        .connector
        .reconcile_at(
            ReconcileRequest {
                schema_version: RECONCILE_REQUEST_SCHEMA_VERSION.to_owned(),
                request_id: action.request_id,
                expected_request_sha256: ambiguous.request_sha256.clone(),
                expected_ambiguous_receipt_sha256: ambiguous_digest,
                observed_effect: true,
                observation_receipt: observation,
                audit_provenance: "audit/reconcile/1".to_owned(),
            },
            NOW + 500,
        )
        .unwrap();
    assert_eq!(reconciled.status, OutcomeStatus::Succeeded);
    assert_eq!(reconciled.status_code, "reconciled_effect_observed");
    assert!(reconciled.observation_receipt_sha256.is_some());
}

#[tokio::test]
async fn shadow_replay_is_exactly_once_signed_and_has_no_endpoint_configuration() {
    let rig = Rig::new(Mode::Success, IdempotencyClass::ExternallyIdempotent).await;
    let outcome = rig
        .connector
        .execute_at(rig.request(IdempotencyClass::ExternallyIdempotent), NOW)
        .await
        .unwrap();
    let outcome_key = public_key_from_seed(&rig.outcome_seed).unwrap();
    let replay_seed = vec![8; 32];
    let shadow_state = tempfile::tempdir().unwrap();
    make_private(shadow_state.path());
    let config = ShadowReplayConfig {
        schema_version: SHADOW_REPLAY_SCHEMA_VERSION.to_owned(),
        shadow_identity: "shadow/replay".to_owned(),
        replay_authority_identity: "authority/shadow-replay".to_owned(),
        connector_id: rig.config.connector_id.clone(),
        connector_receipt_key_sha256: content_sha256(&outcome_key),
        replay_signing_key_id: "key/shadow".to_owned(),
        replay_signing_seed_sha256: content_sha256(&replay_seed),
        replay_signing_public_key_sha256: content_sha256(
            &public_key_from_seed(&replay_seed).unwrap(),
        ),
        denied_endpoint_identities: BTreeSet::from([rig.config.endpoint_identity.clone()]),
        max_receipts: 8,
        state_dir: shadow_state.path().to_path_buf(),
    };
    let replayer =
        ShadowReplayer::new_loopback_test(config.clone(), outcome_key.clone(), replay_seed.clone())
            .unwrap();
    let replay_id = Uuid::new_v4();
    let request = ShadowReplayRequest {
        schema_version: SHADOW_REPLAY_SCHEMA_VERSION.to_owned(),
        replay_id,
        expected_outcome_receipt_sha256: outcome_receipt_digest(&outcome).unwrap(),
        expected_shadow_identity: config.shadow_identity.clone(),
        outcome_receipt: outcome,
        replayed_at_unix_ms: NOW + 2,
        audit_provenance: "audit/shadow/1".to_owned(),
    };
    let first = replayer.replay(request.clone()).unwrap();
    verify_shadow_receipt(&first, &public_key_from_seed(&replay_seed).unwrap()).unwrap();
    let restarted = ShadowReplayer::new_loopback_test(config, outcome_key, replay_seed).unwrap();
    assert_eq!(restarted.replay(request).unwrap(), first);
    assert_eq!(rig.calls.load(Ordering::SeqCst), 1);
}

fn observation_for(rig: &Rig, outcome: &OutcomeReceipt, observed: bool) -> ObservationReceipt {
    ObservationReceipt {
        schema_version: mcloving_destination_observer::RECEIPT_SCHEMA_VERSION.to_owned(),
        protocol_version: mcloving_destination_observer::PROTOCOL_VERSION.to_owned(),
        evidence_sequence: 1,
        observation_id: Uuid::new_v4(),
        request_sha256: content_sha256(b"observation-request"),
        tenant_id: outcome.tenant_id,
        project_id: outcome.project_id,
        pipeline_id: outcome.pipeline_id,
        build_id: outcome.build_id,
        attempt_id: outcome.attempt_id,
        effect_fence: outcome.effect_fence,
        phase: ObservationPhase::Reconciliation,
        predecessor_receipt_sha256: None,
        observer_id: rig.config.observer_id.clone(),
        observer_implementation_sha256: "c".repeat(64),
        observer_image_sha256: "d".repeat(64),
        observer_config_sha256: "e".repeat(64),
        deployment_identity: "deployment/observer".to_owned(),
        operator_trust_identity: "operator/observer".to_owned(),
        runtime_boundary_identity: "runtime/observer".to_owned(),
        service_identity: "service/observer".to_owned(),
        credential_issuance_path_identity: "issuer/observer".to_owned(),
        configuration_authority_identity: "authority/observer-config".to_owned(),
        request_authority_identity: "authority/observer-request".to_owned(),
        generation: 1,
        activation_mode: ObserverActivationMode::Current,
        previous_generation: None,
        rollback_from_generation: None,
        endpoint_identity: outcome.endpoint_identity.clone(),
        account_identity: outcome.account_identity.clone(),
        resource_identity: outcome.resource_identity.clone(),
        effect_class: outcome.effect_class.clone(),
        read_grant_id: "grant/observe".to_owned(),
        read_grant_version: "1".to_owned(),
        read_grant_scope: "release:read".to_owned(),
        canonical_query: BTreeMap::new(),
        destination_cursor: 10,
        destination_observed_at_unix_ms: NOW + 400,
        captured_at_unix_ms: NOW + 401,
        publication_deadline_unix_ms: NOW + 10_000,
        state_schema_version: "connector-reconciliation/v1".to_owned(),
        confidentiality: Confidentiality::Public,
        destination_response_sha256: content_sha256(b"observation-response"),
        destination_signature_base64: "destination-signature".to_owned(),
        destination_attestation_key_id: "key/observer-destination".to_owned(),
        state: json!({
            "connector_request_sha256": outcome.request_sha256,
            "effect_observed": observed
        }),
        retry_count: 0,
        audit_provenance: "audit/observation/1".to_owned(),
        receipt_signing_key_id: "key/observer-receipt".to_owned(),
        receipt_signing_public_key_sha256: content_sha256(
            &public_key_from_seed(&rig.observer_seed).unwrap(),
        ),
        signature_base64: String::new(),
    }
}

#[cfg(unix)]
fn make_private(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[cfg(not(unix))]
fn make_private(_path: &std::path::Path) {}
