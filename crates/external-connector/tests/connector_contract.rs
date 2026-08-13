use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Router, response::IntoResponse};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE as BASE64_URL_SAFE},
};
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
    PercentEncodedSecret,
    PercentEncodedBase64Secret,
    Base64AliasSecret,
    Malformed,
    Denied,
    SignedFailure,
    SignedRetryOnce,
    Created,
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
            runtime_attestation_authority_key_id: "key/runtime-attestation".to_owned(),
            runtime_attestation_authority_key_sha256: "9".repeat(64),
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
            previous_config_sha256: None,
            rollback_from_generation: None,
            endpoint_url: format!("http://{address}/effect"),
            endpoint_identity: "endpoint/releases".to_owned(),
            account_identity: "account/production".to_owned(),
            resource_identity: "resource/release".to_owned(),
            effect_class: "release_publication".to_owned(),
            action_name: "publish_release".to_owned(),
            action_schema_version: "release-publication/v1".to_owned(),
            request_payload_schema: BTreeMap::from([("release".to_owned(), JsonKind::String)]),
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
            observer_binding: ObserverReceiptBinding {
                observer_id: "observer/releases".to_owned(),
                implementation_sha256: "c".repeat(64),
                image_sha256: "d".repeat(64),
                config_sha256: "e".repeat(64),
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
                endpoint_identity: "endpoint/releases".to_owned(),
                account_identity: "account/production".to_owned(),
                resource_identity: "resource/release".to_owned(),
                effect_class: "release_publication".to_owned(),
                read_grant_id: "grant/observe".to_owned(),
                read_grant_version: "1".to_owned(),
                read_grant_scope: "release:read".to_owned(),
                canonical_query: BTreeMap::new(),
                state_schema_version: "connector-reconciliation/v1".to_owned(),
                confidentiality: Confidentiality::Public,
                destination_attestation_key_id: "key/observer-destination".to_owned(),
                receipt_signing_key_id: "key/observer-receipt".to_owned(),
                receipt_signing_public_key_sha256: content_sha256(
                    &public_key_from_seed(&observer_seed).unwrap(),
                ),
            },
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
                max_runtime_history: 16,
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
    if matches!(state.mode, Mode::PercentEncodedSecret) {
        body.public_values.insert(
            "url".to_owned(),
            Value::String("never%2Dpublish%2Dconnector%2Dsecret".to_owned()),
        );
    }
    if matches!(state.mode, Mode::PercentEncodedBase64Secret) {
        body.public_values.insert(
            "url".to_owned(),
            Value::String("b%6DV2ZXItcHVibGlzaC1jb25uZWN0b3Itc2VjcmV0".to_owned()),
        );
    }
    if matches!(state.mode, Mode::Base64AliasSecret) {
        let mut alias = BASE64.encode(TOKEN).into_bytes();
        let content_end = alias.iter().position(|byte| *byte == b'=').unwrap();
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let last = content_end - 1;
        let canonical_index = alphabet
            .iter()
            .position(|byte| *byte == alias[last])
            .unwrap();
        assert_eq!(canonical_index & 0b11, 0);
        alias[last] = alphabet[canonical_index | 0b01];
        body.public_values.insert(
            "url".to_owned(),
            Value::String(String::from_utf8(alias).unwrap()),
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
    let status = if matches!(state.mode, Mode::Created) {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    (status, Json(response)).into_response()
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

    let created = Rig::new(Mode::Created, IdempotencyClass::ExternallyIdempotent).await;
    let created_receipt = created
        .connector
        .execute_at(created.request(IdempotencyClass::ExternallyIdempotent), NOW)
        .await
        .unwrap();
    assert_eq!(created_receipt.status, OutcomeStatus::RetryableFailure);
    assert_eq!(created_receipt.status_code, "bounded_retry_exhausted");
    assert_eq!(created.calls.load(Ordering::SeqCst), 2);
    let mut different_request_same_scope = request.clone();
    different_request_same_scope.request_id = Uuid::new_v4();
    sign_action_request(&mut different_request_same_scope, &rig.request_seed).unwrap();
    let replay = rig.restart().execute_at(request, NOW + 1).await.unwrap();
    assert_eq!(replay, receipt);
    assert_eq!(
        rig.connector
            .execute_at(different_request_same_scope, NOW + 1)
            .await,
        Err(ConnectorError::EffectPending)
    );
    assert_eq!(rig.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn malformed_substituted_and_secret_bearing_outcomes_fail_closed() {
    for (mode, code) in [
        (Mode::Malformed, "malformed_response"),
        (Mode::Substitute, "malformed_response"),
        (Mode::Secret, "confidentiality_denied"),
        (Mode::PercentEncodedSecret, "confidentiality_denied"),
        (Mode::PercentEncodedBase64Secret, "confidentiality_denied"),
        (Mode::Base64AliasSecret, "confidentiality_denied"),
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

    let rig = Rig::new(Mode::Malformed, IdempotencyClass::NonIdempotent).await;
    let receipt = rig
        .connector
        .execute_at(rig.request(IdempotencyClass::NonIdempotent), NOW)
        .await
        .unwrap();
    assert_eq!(receipt.status, OutcomeStatus::Ambiguous);
    assert_eq!(
        receipt.status_code,
        "ambiguous_post_dispatch_malformed_response"
    );
    assert!(receipt.ambiguous_requires_observation);
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

    let mut too_short_for_transport = rig.request(IdempotencyClass::ExternallyIdempotent);
    too_short_for_transport.expires_at_unix_ms = NOW + 49;
    sign_action_request(&mut too_short_for_transport, &rig.request_seed).unwrap();
    assert_eq!(
        rig.connector
            .execute_at(too_short_for_transport.clone(), NOW)
            .await,
        Err(ConnectorError::ExpiredAuthority)
    );
    too_short_for_transport.expires_at_unix_ms = NOW + 30_000;
    sign_action_request(&mut too_short_for_transport, &rig.request_seed).unwrap();
    assert!(
        rig.connector
            .execute_at(too_short_for_transport, NOW)
            .await
            .is_ok()
    );

    let calls_before_zero_fence = rig.calls.load(Ordering::SeqCst);
    let mut zero_fence = rig.request(IdempotencyClass::NonIdempotent);
    zero_fence.effect_fence = 0;
    sign_action_request(&mut zero_fence, &rig.request_seed).unwrap();
    assert_eq!(
        rig.connector.execute_at(zero_fence, NOW).await,
        Err(ConnectorError::MalformedRequest)
    );
    assert_eq!(rig.calls.load(Ordering::SeqCst), calls_before_zero_fence);

    let mut substituted = rig.request(IdempotencyClass::ExternallyIdempotent);
    sign_action_request(&mut substituted, &rig.request_seed).unwrap();
    substituted.resource_identity = "resource/substituted-after-signing".to_owned();
    assert_eq!(
        rig.connector.execute_at(substituted, NOW).await,
        Err(ConnectorError::UnauthorizedRequest)
    );

    let mut schema_substituted = rig.request(IdempotencyClass::ExternallyIdempotent);
    schema_substituted.request_payload = json!({"release": "v1.0.0", "force": true});
    sign_action_request(&mut schema_substituted, &rig.request_seed).unwrap();
    assert_eq!(
        rig.connector.execute_at(schema_substituted, NOW).await,
        Err(ConnectorError::BindingMismatch)
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
async fn empty_physical_authority_mapping_is_rejected_at_construction() {
    let rig = Rig::new(Mode::Success, IdempotencyClass::ExternallyIdempotent).await;
    let mut config = rig.config.clone();
    config.endpoint_identity.clear();
    assert!(matches!(
        ExternalConnector::new_loopback_test(
            config,
            public_key_from_seed(&rig.request_seed).unwrap(),
            public_key_from_seed(&rig.destination_seed).unwrap(),
            rig.outcome_seed.clone(),
            public_key_from_seed(&rig.observer_seed).unwrap(),
            TOKEN.to_vec(),
            vec![TOKEN.to_vec(), SECRET.to_vec()],
        ),
        Err(ConnectorError::InvalidConfig)
    ));

    let mut shared_authority_keys = rig.config.clone();
    let request_public = public_key_from_seed(&rig.request_seed).unwrap();
    shared_authority_keys.destination_attestation_key_sha256 = content_sha256(&request_public);
    assert!(matches!(
        ExternalConnector::new_loopback_test(
            shared_authority_keys,
            request_public.clone(),
            request_public,
            rig.outcome_seed.clone(),
            public_key_from_seed(&rig.observer_seed).unwrap(),
            TOKEN.to_vec(),
            vec![TOKEN.to_vec(), SECRET.to_vec()],
        ),
        Err(ConnectorError::InvalidConfig)
    ));

    let mut open_nested_schema = rig.config.clone();
    open_nested_schema.request_payload_schema =
        BTreeMap::from([("release".to_owned(), JsonKind::Object)]);
    assert!(matches!(
        ExternalConnector::new_loopback_test(
            open_nested_schema,
            public_key_from_seed(&rig.request_seed).unwrap(),
            public_key_from_seed(&rig.destination_seed).unwrap(),
            rig.outcome_seed.clone(),
            public_key_from_seed(&rig.observer_seed).unwrap(),
            TOKEN.to_vec(),
            vec![TOKEN.to_vec(), SECRET.to_vec()],
        ),
        Err(ConnectorError::InvalidConfig)
    ));

    let mut open_public_output_schema = rig.config.clone();
    open_public_output_schema.public_output_schema =
        BTreeMap::from([("url".to_owned(), JsonKind::Array)]);
    assert!(matches!(
        ExternalConnector::new_loopback_test(
            open_public_output_schema,
            public_key_from_seed(&rig.request_seed).unwrap(),
            public_key_from_seed(&rig.destination_seed).unwrap(),
            rig.outcome_seed.clone(),
            public_key_from_seed(&rig.observer_seed).unwrap(),
            TOKEN.to_vec(),
            vec![TOKEN.to_vec(), SECRET.to_vec()],
        ),
        Err(ConnectorError::InvalidConfig)
    ));

    let timeout_state = tempfile::tempdir().unwrap();
    make_private(timeout_state.path());
    let mut unrepresentable_timeout = rig.config.clone();
    unrepresentable_timeout.state_dir = timeout_state.path().to_path_buf();
    unrepresentable_timeout.limits.timeout_ms = 60_001;
    assert!(matches!(
        ExternalConnector::new_loopback_test(
            unrepresentable_timeout,
            public_key_from_seed(&rig.request_seed).unwrap(),
            public_key_from_seed(&rig.destination_seed).unwrap(),
            rig.outcome_seed.clone(),
            public_key_from_seed(&rig.observer_seed).unwrap(),
            TOKEN.to_vec(),
            vec![TOKEN.to_vec(), SECRET.to_vec()],
        ),
        Err(ConnectorError::InvalidConfig)
    ));
    assert!(
        !timeout_state
            .path()
            .join("external-connector.sqlite3")
            .exists()
    );

    for invalid_observer_lineage in [
        (ObserverActivationMode::Current, 2, None, None),
        (ObserverActivationMode::Cutover, 2, None, None),
        (ObserverActivationMode::Rollback, 3, Some(2), Some(2)),
    ] {
        let observer_state = tempfile::tempdir().unwrap();
        make_private(observer_state.path());
        let mut config = rig.config.clone();
        config.state_dir = observer_state.path().to_path_buf();
        config.observer_binding.activation_mode = invalid_observer_lineage.0;
        config.observer_binding.generation = invalid_observer_lineage.1;
        config.observer_binding.previous_generation = invalid_observer_lineage.2;
        config.observer_binding.rollback_from_generation = invalid_observer_lineage.3;
        assert!(matches!(
            ExternalConnector::new_loopback_test(
                config,
                public_key_from_seed(&rig.request_seed).unwrap(),
                public_key_from_seed(&rig.destination_seed).unwrap(),
                rig.outcome_seed.clone(),
                public_key_from_seed(&rig.observer_seed).unwrap(),
                TOKEN.to_vec(),
                vec![TOKEN.to_vec(), SECRET.to_vec()],
            ),
            Err(ConnectorError::InvalidConfig)
        ));
        assert!(
            !observer_state
                .path()
                .join("external-connector.sqlite3")
                .exists()
        );
    }

    let frame_state = tempfile::tempdir().unwrap();
    make_private(frame_state.path());
    let mut oversized_receipt = rig.config.clone();
    oversized_receipt.state_dir = frame_state.path().to_path_buf();
    oversized_receipt.limits.max_request_bytes = MAX_FRAME_BYTES;
    assert!(matches!(
        ExternalConnector::new_loopback_test(
            oversized_receipt,
            public_key_from_seed(&rig.request_seed).unwrap(),
            public_key_from_seed(&rig.destination_seed).unwrap(),
            rig.outcome_seed.clone(),
            public_key_from_seed(&rig.observer_seed).unwrap(),
            TOKEN.to_vec(),
            vec![TOKEN.to_vec(), SECRET.to_vec()],
        ),
        Err(ConnectorError::InvalidConfig)
    ));
    assert!(
        !frame_state
            .path()
            .join("external-connector.sqlite3")
            .exists()
    );

    let reused_credential = rig.outcome_seed.clone();
    let mut shared_secret_roles = rig.config.clone();
    shared_secret_roles.credential_token_sha256 = content_sha256(&reused_credential);
    assert!(matches!(
        ExternalConnector::new_loopback_test(
            shared_secret_roles,
            public_key_from_seed(&rig.request_seed).unwrap(),
            public_key_from_seed(&rig.destination_seed).unwrap(),
            rig.outcome_seed.clone(),
            public_key_from_seed(&rig.observer_seed).unwrap(),
            reused_credential.clone(),
            vec![reused_credential, SECRET.to_vec()],
        ),
        Err(ConnectorError::InvalidConfig)
    ));

    let encoded_credential = BASE64.encode(&rig.outcome_seed).into_bytes();
    let mut encoded_secret_roles = rig.config.clone();
    encoded_secret_roles.credential_token_sha256 = content_sha256(&encoded_credential);
    assert!(matches!(
        ExternalConnector::new_loopback_test(
            encoded_secret_roles,
            public_key_from_seed(&rig.request_seed).unwrap(),
            public_key_from_seed(&rig.destination_seed).unwrap(),
            rig.outcome_seed.clone(),
            public_key_from_seed(&rig.observer_seed).unwrap(),
            encoded_credential.clone(),
            vec![encoded_credential, SECRET.to_vec()],
        ),
        Err(ConnectorError::InvalidConfig)
    ));

    let raw_request_seed = b"12345678901234567890123456789012".to_vec();
    let raw_request_credential = raw_request_seed.clone();
    let raw_request_state = tempfile::tempdir().unwrap();
    make_private(raw_request_state.path());
    let mut raw_request_config = rig.config.clone();
    raw_request_config.state_dir = raw_request_state.path().to_path_buf();
    raw_request_config.request_authority_key_sha256 =
        content_sha256(&public_key_from_seed(&raw_request_seed).unwrap());
    raw_request_config.credential_token_sha256 = content_sha256(&raw_request_credential);
    assert!(matches!(
        ExternalConnector::new_loopback_test(
            raw_request_config,
            public_key_from_seed(&raw_request_seed).unwrap(),
            public_key_from_seed(&rig.destination_seed).unwrap(),
            rig.outcome_seed.clone(),
            public_key_from_seed(&rig.observer_seed).unwrap(),
            raw_request_credential.clone(),
            vec![raw_request_credential, SECRET.to_vec()],
        ),
        Err(ConnectorError::InvalidConfig)
    ));

    let canonical_request_seed = BASE64.encode(&rig.request_seed);
    let extra_padding_credential = format!("{canonical_request_seed}=").into_bytes();
    let mut discarded_bit_credential = BASE64.encode(&rig.request_seed).into_bytes();
    let content_end = discarded_bit_credential
        .iter()
        .position(|byte| *byte == b'=')
        .unwrap();
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let last = content_end - 1;
    let canonical_index = alphabet
        .iter()
        .position(|byte| *byte == discarded_bit_credential[last])
        .unwrap();
    assert_eq!(canonical_index & 0b11, 0);
    discarded_bit_credential[last] = alphabet[canonical_index | 0b01];
    for noncanonical_credential in [extra_padding_credential, discarded_bit_credential] {
        let noncanonical_state = tempfile::tempdir().unwrap();
        make_private(noncanonical_state.path());
        let mut noncanonical_config = rig.config.clone();
        noncanonical_config.state_dir = noncanonical_state.path().to_path_buf();
        noncanonical_config.credential_token_sha256 = content_sha256(&noncanonical_credential);
        assert!(matches!(
            ExternalConnector::new_loopback_test(
                noncanonical_config,
                public_key_from_seed(&rig.request_seed).unwrap(),
                public_key_from_seed(&rig.destination_seed).unwrap(),
                rig.outcome_seed.clone(),
                public_key_from_seed(&rig.observer_seed).unwrap(),
                noncanonical_credential.clone(),
                vec![noncanonical_credential, SECRET.to_vec()],
            ),
            Err(ConnectorError::InvalidConfig)
        ));
        assert!(
            !noncanonical_state
                .path()
                .join("external-connector.sqlite3")
                .exists()
        );
    }

    let encoded_destination_credential = BASE64.encode(&rig.destination_seed).into_bytes();
    let encoded_destination_state = tempfile::tempdir().unwrap();
    make_private(encoded_destination_state.path());
    let mut encoded_destination_config = rig.config.clone();
    encoded_destination_config.state_dir = encoded_destination_state.path().to_path_buf();
    encoded_destination_config.credential_token_sha256 =
        content_sha256(&encoded_destination_credential);
    assert!(matches!(
        ExternalConnector::new_loopback_test(
            encoded_destination_config,
            public_key_from_seed(&rig.request_seed).unwrap(),
            public_key_from_seed(&rig.destination_seed).unwrap(),
            rig.outcome_seed.clone(),
            public_key_from_seed(&rig.observer_seed).unwrap(),
            encoded_destination_credential.clone(),
            vec![encoded_destination_credential, SECRET.to_vec()],
        ),
        Err(ConnectorError::InvalidConfig)
    ));

    let hexadecimal_observer_credential = rig
        .observer_seed
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
        .into_bytes();
    let hexadecimal_observer_state = tempfile::tempdir().unwrap();
    make_private(hexadecimal_observer_state.path());
    let mut hexadecimal_observer_config = rig.config.clone();
    hexadecimal_observer_config.state_dir = hexadecimal_observer_state.path().to_path_buf();
    hexadecimal_observer_config.credential_token_sha256 =
        content_sha256(&hexadecimal_observer_credential);
    assert!(matches!(
        ExternalConnector::new_loopback_test(
            hexadecimal_observer_config,
            public_key_from_seed(&rig.request_seed).unwrap(),
            public_key_from_seed(&rig.destination_seed).unwrap(),
            rig.outcome_seed.clone(),
            public_key_from_seed(&rig.observer_seed).unwrap(),
            hexadecimal_observer_credential.clone(),
            vec![hexadecimal_observer_credential, SECRET.to_vec()],
        ),
        Err(ConnectorError::InvalidConfig)
    ));

    let runtime_attestation_seed = vec![5; 32];
    let encoded_attestation_credential = BASE64_URL_SAFE
        .encode(&runtime_attestation_seed)
        .into_bytes();
    let encoded_attestation_state = tempfile::tempdir().unwrap();
    make_private(encoded_attestation_state.path());
    let mut encoded_attestation_config = rig.config.clone();
    encoded_attestation_config.state_dir = encoded_attestation_state.path().to_path_buf();
    encoded_attestation_config.runtime_attestation_authority_key_sha256 =
        content_sha256(&public_key_from_seed(&runtime_attestation_seed).unwrap());
    encoded_attestation_config.credential_token_sha256 =
        content_sha256(&encoded_attestation_credential);
    assert!(matches!(
        ExternalConnector::new_loopback_test(
            encoded_attestation_config,
            public_key_from_seed(&rig.request_seed).unwrap(),
            public_key_from_seed(&rig.destination_seed).unwrap(),
            rig.outcome_seed.clone(),
            public_key_from_seed(&rig.observer_seed).unwrap(),
            encoded_attestation_credential.clone(),
            vec![encoded_attestation_credential, SECRET.to_vec()],
        ),
        Err(ConnectorError::InvalidConfig)
    ));

    let urlsafe_seed = vec![255; 32];
    let urlsafe_credential = BASE64_URL_SAFE.encode(&urlsafe_seed).into_bytes();
    assert_ne!(BASE64.encode(&urlsafe_seed).as_bytes(), urlsafe_credential);
    let mut mixed_alphabet_credential = BASE64.encode(&urlsafe_seed).into_bytes();
    let first_slash = mixed_alphabet_credential
        .iter()
        .position(|byte| *byte == b'/')
        .unwrap();
    mixed_alphabet_credential[first_slash] = b'_';
    assert!(mixed_alphabet_credential.contains(&b'/'));
    assert!(mixed_alphabet_credential.contains(&b'_'));
    let urlsafe_state = tempfile::tempdir().unwrap();
    make_private(urlsafe_state.path());
    let mut urlsafe_secret_roles = rig.config.clone();
    urlsafe_secret_roles.state_dir = urlsafe_state.path().to_path_buf();
    urlsafe_secret_roles.outcome_signing_seed_sha256 = content_sha256(&urlsafe_seed);
    urlsafe_secret_roles.outcome_signing_public_key_sha256 =
        content_sha256(&public_key_from_seed(&urlsafe_seed).unwrap());
    urlsafe_secret_roles.credential_token_sha256 = content_sha256(&urlsafe_credential);
    assert!(matches!(
        ExternalConnector::new_loopback_test(
            urlsafe_secret_roles,
            public_key_from_seed(&rig.request_seed).unwrap(),
            public_key_from_seed(&rig.destination_seed).unwrap(),
            urlsafe_seed.clone(),
            public_key_from_seed(&rig.observer_seed).unwrap(),
            urlsafe_credential.clone(),
            vec![urlsafe_credential, SECRET.to_vec()],
        ),
        Err(ConnectorError::InvalidConfig)
    ));
    let mixed_alphabet_state = tempfile::tempdir().unwrap();
    make_private(mixed_alphabet_state.path());
    let mut mixed_alphabet_config = rig.config.clone();
    mixed_alphabet_config.state_dir = mixed_alphabet_state.path().to_path_buf();
    mixed_alphabet_config.outcome_signing_seed_sha256 = content_sha256(&urlsafe_seed);
    mixed_alphabet_config.outcome_signing_public_key_sha256 =
        content_sha256(&public_key_from_seed(&urlsafe_seed).unwrap());
    mixed_alphabet_config.credential_token_sha256 = content_sha256(&mixed_alphabet_credential);
    assert!(matches!(
        ExternalConnector::new_loopback_test(
            mixed_alphabet_config,
            public_key_from_seed(&rig.request_seed).unwrap(),
            public_key_from_seed(&rig.destination_seed).unwrap(),
            urlsafe_seed,
            public_key_from_seed(&rig.observer_seed).unwrap(),
            mixed_alphabet_credential.clone(),
            vec![mixed_alphabet_credential, SECRET.to_vec()],
        ),
        Err(ConnectorError::InvalidConfig)
    ));
    assert!(
        !mixed_alphabet_state
            .path()
            .join("external-connector.sqlite3")
            .exists()
    );

    for invalid_credential in [
        vec![0xff; 8],
        b"valid\ninvalid".to_vec(),
        b"invalid token".to_vec(),
        b"invalid:token".to_vec(),
        b"invalid=padding=placement".to_vec(),
    ] {
        let invalid_state = tempfile::tempdir().unwrap();
        make_private(invalid_state.path());
        let mut invalid_token_config = rig.config.clone();
        invalid_token_config.state_dir = invalid_state.path().to_path_buf();
        invalid_token_config.credential_token_sha256 = content_sha256(&invalid_credential);
        assert!(matches!(
            ExternalConnector::new_loopback_test(
                invalid_token_config,
                public_key_from_seed(&rig.request_seed).unwrap(),
                public_key_from_seed(&rig.destination_seed).unwrap(),
                rig.outcome_seed.clone(),
                public_key_from_seed(&rig.observer_seed).unwrap(),
                invalid_credential.clone(),
                vec![invalid_credential, SECRET.to_vec()],
            ),
            Err(ConnectorError::InvalidConfig)
        ));
        assert!(
            !invalid_state
                .path()
                .join("external-connector.sqlite3")
                .exists()
        );
    }

    for invalid_rotation_credential in [vec![0xff; 8], b"invalid token".to_vec()] {
        let mut invalid_rotation = rig.config.clone();
        invalid_rotation.generation = 2;
        invalid_rotation.activation_mode = ActivationMode::Cutover;
        invalid_rotation.previous_generation = Some(1);
        invalid_rotation.previous_config_sha256 = Some(rig.connector.config_sha256().to_owned());
        invalid_rotation.credential_token_sha256 = content_sha256(&invalid_rotation_credential);
        assert!(matches!(
            ExternalConnector::new_loopback_test(
                invalid_rotation,
                public_key_from_seed(&rig.request_seed).unwrap(),
                public_key_from_seed(&rig.destination_seed).unwrap(),
                rig.outcome_seed.clone(),
                public_key_from_seed(&rig.observer_seed).unwrap(),
                invalid_rotation_credential.clone(),
                vec![invalid_rotation_credential, SECRET.to_vec()],
            ),
            Err(ConnectorError::InvalidConfig)
        ));
    }
    for malformed_key_role in 0..3 {
        let malformed_key = vec![7; 31];
        let mut malformed_rotation = rig.config.clone();
        malformed_rotation.generation = 2;
        malformed_rotation.activation_mode = ActivationMode::Cutover;
        malformed_rotation.previous_generation = Some(1);
        malformed_rotation.previous_config_sha256 = Some(rig.connector.config_sha256().to_owned());
        let mut request_key = public_key_from_seed(&rig.request_seed).unwrap();
        let mut destination_key = public_key_from_seed(&rig.destination_seed).unwrap();
        let mut observer_key = public_key_from_seed(&rig.observer_seed).unwrap();
        match malformed_key_role {
            0 => {
                request_key = malformed_key.clone();
                malformed_rotation.request_authority_key_sha256 = content_sha256(&request_key);
            }
            1 => {
                destination_key = malformed_key.clone();
                malformed_rotation.destination_attestation_key_sha256 =
                    content_sha256(&destination_key);
            }
            _ => {
                observer_key = malformed_key.clone();
                malformed_rotation
                    .observer_binding
                    .receipt_signing_public_key_sha256 = content_sha256(&observer_key);
            }
        }
        assert!(matches!(
            ExternalConnector::new_loopback_test(
                malformed_rotation,
                request_key,
                destination_key,
                rig.outcome_seed.clone(),
                observer_key,
                TOKEN.to_vec(),
                vec![TOKEN.to_vec(), SECRET.to_vec()],
            ),
            Err(ConnectorError::InvalidConfig)
        ));
    }
    let mut expired_rotation = rig.config.clone();
    expired_rotation.generation = 2;
    expired_rotation.activation_mode = ActivationMode::Cutover;
    expired_rotation.previous_generation = Some(1);
    expired_rotation.previous_config_sha256 = Some(rig.connector.config_sha256().to_owned());
    expired_rotation.credential_grant_expires_unix_ms = 0;
    assert!(matches!(
        ExternalConnector::new_loopback_test(
            expired_rotation,
            public_key_from_seed(&rig.request_seed).unwrap(),
            public_key_from_seed(&rig.destination_seed).unwrap(),
            rig.outcome_seed.clone(),
            public_key_from_seed(&rig.observer_seed).unwrap(),
            TOKEN.to_vec(),
            vec![TOKEN.to_vec(), SECRET.to_vec()],
        ),
        Err(ConnectorError::InvalidConfig)
    ));
    let old_generation_receipt = rig
        .connector
        .execute_at(rig.request(IdempotencyClass::ExternallyIdempotent), NOW)
        .await
        .unwrap();
    assert_eq!(old_generation_receipt.generation, 1);

    let mut impossible_rollback = rig.config.clone();
    impossible_rollback.activation_mode = ActivationMode::Rollback;
    impossible_rollback.rollback_from_generation = Some(1);
    assert!(matches!(
        ExternalConnector::new_loopback_test(
            impossible_rollback,
            public_key_from_seed(&rig.request_seed).unwrap(),
            public_key_from_seed(&rig.destination_seed).unwrap(),
            rig.outcome_seed.clone(),
            public_key_from_seed(&rig.observer_seed).unwrap(),
            TOKEN.to_vec(),
            vec![TOKEN.to_vec(), SECRET.to_vec()],
        ),
        Err(ConnectorError::InvalidConfig)
    ));
}

#[tokio::test]
async fn signed_reconciliation_is_the_only_ambiguous_unfreeze_path() {
    let rig = Rig::new(Mode::Timeout, IdempotencyClass::NonIdempotent).await;
    let action = rig.request(IdempotencyClass::NonIdempotent);
    let ambiguous = rig.connector.execute_at(action.clone(), NOW).await.unwrap();
    let ambiguous_digest = outcome_receipt_digest(&ambiguous).unwrap();
    let mut oversized_observation = observation_for(&rig, &ambiguous, true);
    mcloving_destination_observer::sign_receipt(&mut oversized_observation, &rig.observer_seed)
        .unwrap();
    assert_eq!(
        rig.connector.reconcile_at(
            ReconcileRequest {
                schema_version: RECONCILE_REQUEST_SCHEMA_VERSION.to_owned(),
                request_id: action.request_id,
                expected_request_sha256: ambiguous.request_sha256.clone(),
                expected_ambiguous_receipt_sha256: ambiguous_digest.clone(),
                observed_effect: true,
                observation_receipt: oversized_observation,
                audit_provenance: "x".repeat(rig.config.limits.max_request_bytes),
            },
            NOW + 500,
        ),
        Err(ConnectorError::OversizedRequest)
    );
    let mut stale_observation = observation_for(&rig, &ambiguous, true);
    stale_observation.destination_observed_at_unix_ms = NOW;
    stale_observation.captured_at_unix_ms = NOW;
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
    let mut substituted_observer = observation_for(&rig, &ambiguous, true);
    substituted_observer.observer_config_sha256 = "f".repeat(64);
    mcloving_destination_observer::sign_receipt(&mut substituted_observer, &rig.observer_seed)
        .unwrap();
    assert_eq!(
        rig.connector.reconcile_at(
            ReconcileRequest {
                schema_version: RECONCILE_REQUEST_SCHEMA_VERSION.to_owned(),
                request_id: action.request_id,
                expected_request_sha256: ambiguous.request_sha256.clone(),
                expected_ambiguous_receipt_sha256: ambiguous_digest.clone(),
                observed_effect: true,
                observation_receipt: substituted_observer,
                audit_provenance: "audit/reconcile/substituted-observer".to_owned(),
            },
            NOW + 500,
        ),
        Err(ConnectorError::InvalidObservation)
    );
    let mut absence_observation = observation_for(&rig, &ambiguous, false);
    mcloving_destination_observer::sign_receipt(&mut absence_observation, &rig.observer_seed)
        .unwrap();
    assert_eq!(
        rig.connector.reconcile_at(
            ReconcileRequest {
                schema_version: RECONCILE_REQUEST_SCHEMA_VERSION.to_owned(),
                request_id: action.request_id,
                expected_request_sha256: ambiguous.request_sha256.clone(),
                expected_ambiguous_receipt_sha256: ambiguous_digest.clone(),
                observed_effect: false,
                observation_receipt: absence_observation,
                audit_provenance: "audit/reconcile/absence-without-barrier".to_owned(),
            },
            NOW + 500,
        ),
        Err(ConnectorError::InvalidObservation)
    );
    assert_eq!(
        rig.connector
            .execute_at(action.clone(), NOW + 501)
            .await
            .unwrap(),
        ambiguous
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
        implementation_sha256: "6".repeat(64),
        image_sha256: "7".repeat(64),
        deployment_identity: "deployment/shadow".to_owned(),
        runtime_boundary_identity: "runtime/shadow".to_owned(),
        runtime_attestation_authority_key_id: "key/runtime-attestation".to_owned(),
        runtime_attestation_authority_key_sha256: "9".repeat(64),
        connector_binding: ConnectorReceiptBinding {
            connector_id: outcome.connector_id.clone(),
            implementation_sha256: outcome.connector_implementation_sha256.clone(),
            image_sha256: outcome.connector_image_sha256.clone(),
            config_sha256: outcome.connector_config_sha256.clone(),
            deployment_identity: outcome.deployment_identity.clone(),
            operator_trust_identity: outcome.operator_trust_identity.clone(),
            runtime_boundary_identity: outcome.runtime_boundary_identity.clone(),
            service_identity: outcome.service_identity.clone(),
            configuration_authority_identity: outcome.configuration_authority_identity.clone(),
            request_authority_identity: outcome.request_authority_identity.clone(),
            credential_issuance_path_identity: outcome.credential_issuance_path_identity.clone(),
            generation: outcome.generation,
            activation_mode: outcome.activation_mode,
            previous_generation: outcome.previous_generation,
            previous_config_sha256: outcome.previous_config_sha256.clone(),
            rollback_from_generation: outcome.rollback_from_generation,
            endpoint_identity: outcome.endpoint_identity.clone(),
            account_identity: outcome.account_identity.clone(),
            resource_identity: outcome.resource_identity.clone(),
            effect_class: outcome.effect_class.clone(),
            action_name: outcome.action_name.clone(),
            action_schema_version: outcome.action_schema_version.clone(),
            credential_grant_id: outcome.credential_grant_id.clone(),
            credential_grant_version: outcome.credential_grant_version.clone(),
            credential_grant_scope: outcome.credential_grant_scope.clone(),
            outcome_signing_key_id: outcome.outcome_signing_key_id.clone(),
            outcome_signing_public_key_sha256: outcome.outcome_signing_public_key_sha256.clone(),
        },
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
    for (mode, generation, previous_generation, previous_digest, rollback_from_generation) in [
        (ActivationMode::Current, 2, None, None, None),
        (ActivationMode::Cutover, 2, None, None, None),
        (
            ActivationMode::Rollback,
            3,
            Some(2),
            Some("a".repeat(64)),
            Some(2),
        ),
    ] {
        let invalid_lineage_state = tempfile::tempdir().unwrap();
        make_private(invalid_lineage_state.path());
        let mut invalid_lineage = config.clone();
        invalid_lineage.state_dir = invalid_lineage_state.path().to_path_buf();
        invalid_lineage.connector_binding.activation_mode = mode;
        invalid_lineage.connector_binding.generation = generation;
        invalid_lineage.connector_binding.previous_generation = previous_generation;
        invalid_lineage.connector_binding.previous_config_sha256 = previous_digest;
        invalid_lineage.connector_binding.rollback_from_generation = rollback_from_generation;
        assert!(matches!(
            ShadowReplayer::new_loopback_test(
                invalid_lineage,
                outcome_key.clone(),
                replay_seed.clone(),
            ),
            Err(ConnectorError::InvalidConfig)
        ));
        assert!(
            !invalid_lineage_state
                .path()
                .join("external-shadow-replay.sqlite3")
                .exists()
        );
    }
    let malformed_key = vec![7; 31];
    let malformed_state = tempfile::tempdir().unwrap();
    make_private(malformed_state.path());
    let mut malformed_key_config = config.clone();
    malformed_key_config.state_dir = malformed_state.path().to_path_buf();
    malformed_key_config.connector_receipt_key_sha256 = content_sha256(&malformed_key);
    malformed_key_config
        .connector_binding
        .outcome_signing_public_key_sha256 = content_sha256(&malformed_key);
    assert!(matches!(
        ShadowReplayer::new_loopback_test(malformed_key_config, malformed_key, replay_seed.clone(),),
        Err(ConnectorError::InvalidConfig)
    ));
    assert!(
        !malformed_state
            .path()
            .join("external-shadow-replay.sqlite3")
            .exists()
    );
    let mut shared_key_config = config.clone();
    shared_key_config.replay_signing_seed_sha256 = content_sha256(&rig.outcome_seed);
    shared_key_config.replay_signing_public_key_sha256 = content_sha256(&outcome_key);
    assert!(matches!(
        ShadowReplayer::new_loopback_test(
            shared_key_config,
            outcome_key.clone(),
            rig.outcome_seed.clone(),
        ),
        Err(ConnectorError::InvalidConfig)
    ));
    let replay_public = public_key_from_seed(&replay_seed).unwrap();
    let mut shared_attestation_key = config.clone();
    shared_attestation_key.runtime_attestation_authority_key_sha256 =
        content_sha256(&replay_public);
    assert!(matches!(
        ShadowReplayer::new_loopback_test(
            shared_attestation_key,
            outcome_key.clone(),
            replay_seed.clone(),
        ),
        Err(ConnectorError::InvalidConfig)
    ));
    let mut changed_config = config.clone();
    changed_config.implementation_sha256 = "5".repeat(64);
    assert!(matches!(
        ShadowReplayer::new_loopback_test(changed_config, outcome_key.clone(), replay_seed.clone(),),
        Err(ConnectorError::RuntimeFenced)
    ));
    let mut substituted_outcome = outcome.clone();
    substituted_outcome.connector_image_sha256 = "f".repeat(64);
    sign_outcome_receipt(&mut substituted_outcome, &rig.outcome_seed).unwrap();
    assert_eq!(
        replayer.replay(ShadowReplayRequest {
            schema_version: SHADOW_REPLAY_SCHEMA_VERSION.to_owned(),
            replay_id: Uuid::new_v4(),
            expected_outcome_receipt_sha256: outcome_receipt_digest(&substituted_outcome).unwrap(),
            expected_shadow_identity: config.shadow_identity.clone(),
            outcome_receipt: substituted_outcome,
            replayed_at_unix_ms: NOW + 1,
            audit_provenance: "audit/shadow/substituted".to_owned(),
        }),
        Err(ConnectorError::InvalidReplay)
    );
    let replay_id = Uuid::new_v4();
    let large_output_state = tempfile::tempdir().unwrap();
    make_private(large_output_state.path());
    let mut large_output_config = config.clone();
    large_output_config.state_dir = large_output_state.path().to_path_buf();
    large_output_config.replay_authority_identity = "authority/".to_owned() + &"r".repeat(40_000);
    large_output_config.replay_signing_key_id = "key/".to_owned() + &"k".repeat(40_000);
    let large_output_replayer = ShadowReplayer::new_loopback_test(
        large_output_config.clone(),
        outcome_key.clone(),
        replay_seed.clone(),
    )
    .unwrap();
    let mut oversized_request = ShadowReplayRequest {
        schema_version: SHADOW_REPLAY_SCHEMA_VERSION.to_owned(),
        replay_id,
        expected_outcome_receipt_sha256: outcome_receipt_digest(&outcome).unwrap(),
        expected_shadow_identity: large_output_config.shadow_identity.clone(),
        outcome_receipt: outcome.clone(),
        replayed_at_unix_ms: NOW + 2,
        audit_provenance: String::new(),
    };
    let empty_request_size = serde_json::to_vec(&ShadowCommand::Replay {
        request: Box::new(oversized_request.clone()),
    })
    .unwrap()
    .len();
    oversized_request.audit_provenance =
        "x".repeat(MAX_FRAME_BYTES.saturating_sub(empty_request_size + 1));
    let input_frame = serde_json::to_vec(&ShadowCommand::Replay {
        request: Box::new(oversized_request.clone()),
    })
    .unwrap();
    assert_eq!(input_frame.len() + 1, MAX_FRAME_BYTES);
    assert_eq!(
        large_output_replayer.replay(oversized_request),
        Err(ConnectorError::CapacityExceeded)
    );
    let small_request = ShadowReplayRequest {
        schema_version: SHADOW_REPLAY_SCHEMA_VERSION.to_owned(),
        replay_id,
        expected_outcome_receipt_sha256: outcome_receipt_digest(&outcome).unwrap(),
        expected_shadow_identity: large_output_config.shadow_identity,
        outcome_receipt: outcome.clone(),
        replayed_at_unix_ms: NOW + 2,
        audit_provenance: "audit/shadow/frame-retry".to_owned(),
    };
    assert!(large_output_replayer.replay(small_request).is_ok());
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
        observer_id: rig.config.observer_binding.observer_id.clone(),
        observer_implementation_sha256: rig.config.observer_binding.implementation_sha256.clone(),
        observer_image_sha256: rig.config.observer_binding.image_sha256.clone(),
        observer_config_sha256: rig.config.observer_binding.config_sha256.clone(),
        deployment_identity: rig.config.observer_binding.deployment_identity.clone(),
        operator_trust_identity: rig.config.observer_binding.operator_trust_identity.clone(),
        runtime_boundary_identity: rig
            .config
            .observer_binding
            .runtime_boundary_identity
            .clone(),
        service_identity: rig.config.observer_binding.service_identity.clone(),
        credential_issuance_path_identity: rig
            .config
            .observer_binding
            .credential_issuance_path_identity
            .clone(),
        configuration_authority_identity: rig
            .config
            .observer_binding
            .configuration_authority_identity
            .clone(),
        request_authority_identity: rig
            .config
            .observer_binding
            .request_authority_identity
            .clone(),
        generation: rig.config.observer_binding.generation,
        activation_mode: rig.config.observer_binding.activation_mode,
        previous_generation: rig.config.observer_binding.previous_generation,
        rollback_from_generation: rig.config.observer_binding.rollback_from_generation,
        endpoint_identity: outcome.endpoint_identity.clone(),
        account_identity: outcome.account_identity.clone(),
        resource_identity: outcome.resource_identity.clone(),
        effect_class: outcome.effect_class.clone(),
        read_grant_id: rig.config.observer_binding.read_grant_id.clone(),
        read_grant_version: rig.config.observer_binding.read_grant_version.clone(),
        read_grant_scope: rig.config.observer_binding.read_grant_scope.clone(),
        canonical_query: rig.config.observer_binding.canonical_query.clone(),
        destination_cursor: 10,
        destination_observed_at_unix_ms: NOW + 400,
        captured_at_unix_ms: NOW + 401,
        publication_deadline_unix_ms: NOW + 10_000,
        state_schema_version: rig.config.observer_binding.state_schema_version.clone(),
        confidentiality: rig.config.observer_binding.confidentiality,
        destination_response_sha256: content_sha256(b"observation-response"),
        destination_signature_base64: "destination-signature".to_owned(),
        destination_attestation_key_id: rig
            .config
            .observer_binding
            .destination_attestation_key_id
            .clone(),
        state: json!({
            "connector_request_sha256": outcome.request_sha256,
            "effect_observed": observed
        }),
        retry_count: 0,
        audit_provenance: "audit/observation/1".to_owned(),
        receipt_signing_key_id: rig.config.observer_binding.receipt_signing_key_id.clone(),
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
