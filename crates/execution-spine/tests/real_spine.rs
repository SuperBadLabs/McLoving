use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mcloving_agent_runtime::{Acceptance, AttemptPhase, Journal};
use mcloving_controller_api::{
    ApiState, Client, ExplainResponse, PipelineBuildRequest, PipelineUpsertRequest, router,
};
use mcloving_controller_store::{
    BuildAdmission, ClaimRequest, NewBuild, NewLogChunk, PipelinePutOutcome, PipelineWrite, Store,
    StoreError, TerminalOutcome,
    authz::{Principal, PrincipalKind, ServiceScope},
};
use mcloving_destination_observer::{
    ActivationMode as ObserverActivationMode, ObservationPhase, ObservationRequest,
    PROTOCOL_VERSION as OBSERVER_PROTOCOL_V1, REQUEST_SCHEMA_VERSION as OBSERVER_REQUEST_V1,
    RequestAuthorization as ObserverAuthorization, sign_observation_request,
};
use mcloving_execution_spine::{
    EffectExecutionPlan, EffectRuntimeFreeze, FreshOneActionGrant, PinnedServiceCommand,
    SpineError, WorkerConfig, run_claim,
};
use mcloving_external_connector::{
    ActionRequest, IdempotencyClass, PROTOCOL_VERSION as CONNECTOR_PROTOCOL_V1,
    REQUEST_SCHEMA_VERSION as CONNECTOR_REQUEST_V1, RequestAuthorization, action_request_digest,
    public_key_from_seed, sign_action_request,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;
use uuid::Uuid;

const TOKEN: &str = "mcloving-e2e-token-exactly-32-bytes-or-more";

fn api_state(store: Store, organization_id: Uuid) -> ApiState {
    ApiState::new(
        store,
        TOKEN,
        Principal {
            subject: "service:test-client".to_owned(),
            kind: PrincipalKind::Service,
            organization_id,
            project_roles: Default::default(),
            service_scopes: [
                ServiceScope::ProjectRead,
                ServiceScope::BuildSubmit,
                ServiceScope::BuildCancel,
                ServiceScope::ProjectAdmin,
                ServiceScope::SchedulerControl,
            ]
            .into(),
            mapped_projects: Default::default(),
            action_grants: Default::default(),
        },
    )
    .expect("configure API")
}
const PIPELINE: &str = r#"
version: 1
name: wave1
stages:
  - id: execute
    name: Execute
    steps:
      - process:
          program: /bin/sh
          args: [-c, "printf 'hello-from-mcloving\n'; printf 'diagnostic\n' >&2"]
          env:
            MCLOVING_E2E: enabled
          timeout_seconds: 10
"#;
const CANCELLATION_PIPELINE: &str = r#"
version: 1
name: cancellation
stages:
  - id: execute
    name: Execute
    steps:
      - process:
          program: /bin/sh
          args: [-c, "sleep 30 & child=$!; printf '%s\n' \"$child\" > child.pid; wait"]
          timeout_seconds: 60
"#;

async fn test_store() -> Option<Store> {
    let url = std::env::var("MCLOVING_TEST_DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .expect("connect to configured PostgreSQL");
    let store = Store::new(pool);
    store.migrate().await.expect("install controller schema");
    Some(store)
}

async fn admit_bound_test_build(
    store: &Store,
    mut input: NewBuild,
) -> Result<BuildAdmission, StoreError> {
    let current = store
        .pipeline(input.organization_id, input.project_id, input.pipeline_id)
        .await?;
    let pipeline = if current
        .as_ref()
        .is_some_and(|pipeline| pipeline.semantic_digest == input.pipeline_digest)
    {
        current.expect("matching pipeline exists")
    } else {
        let source = format!("test pipeline {:?}", input.pipeline_digest);
        let outcome = store
            .put_pipeline(
                &PipelineWrite {
                    organization_id: input.organization_id,
                    project_id: input.project_id,
                    pipeline_id: input.pipeline_id,
                    slug: format!("test-{}", input.project_id),
                    source_sha256: Sha256::digest(source.as_bytes()).into(),
                    source,
                    semantic_digest: input.pipeline_digest,
                    schema_major: 1,
                    schema_minor: 0,
                    parameter_schema: json!({}),
                },
                Some(current.as_ref().map_or(0, |pipeline| pipeline.revision)),
            )
            .await?;
        match outcome {
            PipelinePutOutcome::Created(record)
            | PipelinePutOutcome::Updated(record)
            | PipelinePutOutcome::Unchanged(record) => record,
            PipelinePutOutcome::PreconditionFailed { current_revision } => {
                return Err(StoreError::ProductConflict(format!(
                    "test pipeline raced at revision {current_revision}"
                )));
            }
        }
    };
    input.pipeline_revision = pipeline.revision;
    input.pipeline_operational_generation = pipeline.operational_generation;
    store.admit_build(&input).await
}

async fn save_test_pipeline(
    client: &Client,
    organization_id: Uuid,
    project_id: Uuid,
    pipeline_id: Uuid,
    slug: &str,
    source: &str,
) {
    client
        .put_pipeline(
            organization_id,
            project_id,
            pipeline_id,
            0,
            &PipelineUpsertRequest {
                slug: slug.to_owned(),
                source: source.to_owned(),
                parameters: Default::default(),
            },
        )
        .await
        .expect("save test pipeline");
}

#[tokio::test]
async fn strict_yaml_crosses_the_real_public_and_execution_spine() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    store
        .create_project(
            organization_id,
            &format!("org-{organization_id}"),
            project_id,
            "e2e",
        )
        .await
        .expect("create project");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind API");
    let address = listener.local_addr().expect("read API address");
    let server = tokio::spawn(
        axum::serve(listener, router(api_state(store.clone(), organization_id))).into_future(),
    );
    let client = Client::new(&format!("http://{address}"), TOKEN);
    let pipeline_id = Uuid::new_v4();
    save_test_pipeline(
        &client,
        organization_id,
        project_id,
        pipeline_id,
        "e2e",
        PIPELINE,
    )
    .await;
    let admission = client
        .submit_pipeline_on_platform_in_pool(
            organization_id,
            project_id,
            pipeline_id,
            "e2e-001",
            "linux",
            "trusted-linux",
            &PipelineBuildRequest::default(),
        )
        .await
        .expect("submit saved pipeline through HTTP");
    assert!(admission.created);
    let replay = client
        .submit_pipeline_on_platform_in_pool(
            organization_id,
            project_id,
            pipeline_id,
            "e2e-001",
            "linux",
            "trusted-linux",
            &PipelineBuildRequest::default(),
        )
        .await
        .expect("replay idempotent HTTP submission");
    assert!(!replay.created);
    assert_eq!(replay.build_id, admission.build_id);
    assert!(matches!(
        client
            .explain(organization_id, &["platform:linux".to_owned()])
            .await
            .expect("explain ready work"),
        ExplainResponse::Ready
    ));

    let claim = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "scheduler-e2e".to_owned(),
            agent_id: "agent-e2e".to_owned(),
            capabilities: vec!["platform:linux".to_owned()],
            trust_pool: "trusted-linux".into(),
            lease_seconds: 60,
            fairness_seed: 1,
        })
        .await
        .expect("scheduler claim")
        .expect("claim exists");
    let root = tempfile::tempdir().expect("workspace root");
    let receipt = run_claim(
        &store,
        &claim,
        &WorkerConfig {
            agent_id: "agent-e2e".to_owned(),
            session_epoch: 1,
            workspace_root: root.path().to_owned(),
            journal_path: root.path().join("agent.db"),
            cancellation_poll: Duration::from_millis(10),
            lease_seconds: 60,
            termination_grace: Duration::from_millis(100),
            effect_plan: None,
        },
    )
    .await
    .expect("run through durable agent");
    assert_eq!(receipt.outcome, TerminalOutcome::Succeeded);

    let status = client
        .status(organization_id, project_id, admission.build_id)
        .await
        .expect("read terminal status through HTTP");
    assert_eq!(status.status, "succeeded");
    assert_eq!(status.attempt_status, "succeeded");
    let logs = client
        .logs(organization_id, project_id, admission.build_id)
        .await
        .expect("read committed logs through HTTP");
    assert_eq!(logs.len(), 2);
    assert_eq!(logs[0].text.as_deref(), Some("hello-from-mcloving\n"));
    assert_eq!(
        logs[0].content_hex,
        "68656c6c6f2d66726f6d2d6d636c6f76696e670a"
    );
    assert_eq!(logs[1].text.as_deref(), Some("diagnostic\n"));
    assert_eq!(logs[1].content_hex, "646961676e6f737469630a");
    assert!(logs.iter().all(|log| log.sha256.len() == 64));

    let events = store
        .publish_outbox(organization_id, 100)
        .await
        .expect("publish transactional outbox");
    let topics = events
        .iter()
        .map(|event| event.topic.as_str())
        .collect::<Vec<_>>();
    assert!(topics.contains(&"dag.admitted"));
    assert!(topics.contains(&"attempt.offered"));
    assert!(topics.contains(&"attempt.accepted"));
    assert!(topics.contains(&"attempt.running"));
    assert!(topics.contains(&"attempt.terminal"));
    assert!(
        store
            .publish_outbox(organization_id, 100)
            .await
            .expect("outbox replay")
            .is_empty()
    );
    server.abort();
}

#[tokio::test]
async fn controller_restart_replay_is_logically_exactly_once() {
    let Some(initial) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let pool = initial.pool().clone();
    let restart = || Store::new(pool.clone());
    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    initial
        .create_project(
            organization_id,
            &format!("org-{organization_id}"),
            project_id,
            "restart",
        )
        .await
        .expect("create project");
    let input = NewBuild {
        organization_id,
        project_id,
        pipeline_id: project_id,
        pipeline_revision: 1,
        pipeline_operational_generation: 1,
        idempotency_key: "e2e-002".to_owned(),
        pipeline_digest: [42; 32],
        node_key: "execute".to_owned(),
        required_capabilities: vec!["linux".to_owned()],
        required_trust_pool: "trusted".into(),
        priority: 0,
        execution_spec: json!({
            "version": 1,
            "steps": [{
                "kind": "process",
                "program": "/bin/true",
                "args": [],
                "env": {},
                "timeout_seconds": 10
            }]
        }),
    };
    let admission = admit_bound_test_build(&initial, input.clone())
        .await
        .expect("admit");
    drop(initial);
    let store = restart();
    let replay = admit_bound_test_build(&store, input.clone())
        .await
        .expect("replay admission");
    assert!(!replay.created);
    assert_eq!(replay.build_id, admission.build_id);

    let claim = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "restart-scheduler".to_owned(),
            agent_id: "restart-agent".to_owned(),
            capabilities: vec!["linux".to_owned()],
            trust_pool: "trusted".into(),
            lease_seconds: 60,
            fairness_seed: 9,
        })
        .await
        .expect("claim")
        .expect("work exists");
    drop(store);
    let store = restart();
    assert!(
        store
            .claim_next(&ClaimRequest {
                organization_id,
                scheduler_id: "restart-scheduler".to_owned(),
                agent_id: "restart-agent".to_owned(),
                capabilities: vec!["linux".to_owned()],
                trust_pool: "trusted".into(),
                lease_seconds: 60,
                fairness_seed: 9,
            })
            .await
            .expect("repeated claim")
            .is_none()
    );
    assert!(
        store
            .accept_offer(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "restart-agent",
            )
            .await
            .expect("accept")
    );
    drop(store);
    let store = restart();
    assert!(
        store
            .accept_offer(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "restart-agent",
            )
            .await
            .expect("replay acceptance")
    );
    assert!(
        store
            .mark_attempt_running(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "restart-agent",
            )
            .await
            .expect("running")
    );
    drop(store);
    let store = restart();
    assert!(
        store
            .mark_attempt_running(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "restart-agent",
            )
            .await
            .expect("replay running")
    );
    let log = b"one durable line\n";
    let chunk = NewLogChunk {
        organization_id,
        attempt_id: claim.attempt_id,
        fence: claim.fence,
        restore_epoch: claim.restore_epoch,
        agent_id: "restart-agent",
        sequence: 0,
        stream: "stdout",
        content: log,
    };
    assert!(store.append_log(&chunk).await.expect("commit log"));
    drop(store);
    let store = restart();
    assert!(store.append_log(&chunk).await.expect("replay log"));
    assert!(
        store
            .finalize_attempt(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "restart-agent",
                TerminalOutcome::Succeeded,
                json!({"sha256": hex(&Sha256::digest(log))}),
            )
            .await
            .expect("finalize")
    );
    drop(store);
    let store = restart();
    assert!(
        store
            .finalize_attempt(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "restart-agent",
                TerminalOutcome::Succeeded,
                json!({"sha256": hex(&Sha256::digest(log))}),
            )
            .await
            .expect("exact terminal replay is accepted without duplication")
    );
    assert!(
        !store
            .finalize_attempt(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "restart-agent",
                TerminalOutcome::Failed,
                json!({"reason": "conflicting replay"}),
            )
            .await
            .expect("conflicting terminal replay is rejected")
    );
    let snapshot = store
        .build_snapshot(organization_id, project_id, admission.build_id)
        .await
        .expect("snapshot")
        .expect("build exists");
    assert_eq!(snapshot.build_status, "succeeded");
    assert_eq!(
        store
            .build_logs(organization_id, project_id, admission.build_id)
            .await
            .unwrap()
            .len(),
        1
    );
    let published = store.publish_outbox(organization_id, 100).await.unwrap();
    assert_eq!(
        published
            .iter()
            .filter(|event| event.topic == "build.admitted")
            .count(),
        1
    );
    assert_eq!(
        published
            .iter()
            .filter(|event| event.topic == "attempt.accepted")
            .count(),
        1
    );
    assert_eq!(
        published
            .iter()
            .filter(|event| event.topic == "attempt.running")
            .count(),
        1
    );
    assert_eq!(
        published
            .iter()
            .filter(|event| event.topic == "attempt.terminal")
            .count(),
        1
    );
    drop(store);
    assert!(
        restart()
            .publish_outbox(organization_id, 100)
            .await
            .unwrap()
            .is_empty()
    );
}

#[test]
fn restore_epoch_fences_same_numeric_attempt_in_the_agent_journal() {
    let root = tempfile::tempdir().expect("journal root");
    let mut journal = Journal::open(root.path().join("agent.db")).expect("open journal");
    let authority = |restore_epoch: u64, fence: u64| (restore_epoch << 32) | fence;
    let old = Acceptance {
        organization_id: "restore-org".into(),
        attempt_id: "rewound-attempt".into(),
        fence_token: authority(1, 1),
        session_epoch: 7,
        payload_digest: [71; 32],
        workspace: "restore-org/rewound-attempt/1-1".into(),
    };
    journal.accept(&old).expect("accept discarded timeline");
    let current = Acceptance {
        fence_token: authority(2, 1),
        workspace: "restore-org/rewound-attempt/2-1".into(),
        ..old.clone()
    };
    journal.accept(&current).expect("accept current epoch");
    let report = journal.reconcile().expect("reconcile epochs");
    assert_eq!(report.attempts.len(), 2);
    assert_eq!(
        report.attempts[0].phase,
        AttemptPhase::ReconciliationRequired
    );
    assert_eq!(report.attempts[0].fence_token, authority(1, 1));
    assert_eq!(report.attempts[1].phase, AttemptPhase::Accepted);
    assert_eq!(report.attempts[1].fence_token, authority(2, 1));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn write_test_pkcs8(path: &Path, seed: &[u8; 32]) {
    let mut encoded = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    encoded.extend_from_slice(seed);
    std::fs::write(path, encoded).expect("write test-only Ed25519 PKCS#8 key");
}

fn pinned_effect_fixture(root: &Path) -> PinnedServiceCommand {
    pinned_effect_fixture_scenario(root, "success", 5_000)
}

fn pinned_effect_fixture_scenario(
    root: &Path,
    scenario: &str,
    timeout_millis: u64,
) -> PinnedServiceCommand {
    let fixture = std::fs::canonicalize(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/effect_service.py"),
    )
    .expect("canonical effect fixture");
    let openssl = std::fs::canonicalize("/usr/bin/openssl").expect("canonical openssl");
    let outcome_key = root.join("outcome-key.pkcs8");
    let observer_key = root.join("observer-key.pkcs8");
    let shadow_key = root.join("shadow-key.pkcs8");
    let observer_request_key = root.join("observer-request-key.pkcs8");
    let diagnostic = root.join("effect-fixture-error.txt");
    let scenario_path = root.join("effect-fixture-scenario.txt");
    let state_path = root.join("effect-fixture-state.json");
    let dispatch_ledger = root.join("effect-fixture-dispatches.txt");
    let preflight_ledger = root.join("effect-fixture-preflights.txt");
    write_test_pkcs8(&outcome_key, &[12_u8; 32]);
    write_test_pkcs8(&observer_key, &[13_u8; 32]);
    write_test_pkcs8(&shadow_key, &[14_u8; 32]);
    write_test_pkcs8(&observer_request_key, &[15_u8; 32]);
    std::fs::write(&scenario_path, scenario).expect("write effect fixture scenario");
    let executable_sha256 = hex(&Sha256::digest(
        std::fs::read(&fixture).expect("read effect fixture"),
    ));
    PinnedServiceCommand {
        executable: fixture,
        executable_sha256,
        arguments: vec![
            openssl,
            outcome_key,
            observer_key,
            shadow_key,
            observer_request_key,
            diagnostic,
            scenario_path,
            state_path,
            dispatch_ledger,
            preflight_ledger,
        ],
        timeout_millis,
    }
}

fn runtime_effect_spec() -> serde_json::Value {
    json!({
        "version": 2,
        "steps": [{
            "kind": "connector_intent",
            "mapping_id": "notification.v1",
            "mapping_digest": format!("sha256:{}", "a".repeat(64)),
            "effect_class": "externally_idempotent",
            "effect_key_template": "build.notification",
            "public_input_schema": {"message": "string"},
            "protected_secret_ref_schema": {"token": "string"},
            "expected_public_result_schema": {"delivery_id": "string"},
            "timeout_seconds": 30,
            "ambiguity_policy": "observe_then_reconcile",
            "downstream_control_digest": format!("sha256:{}", "b".repeat(64)),
        }]
    })
}

fn runtime_effect_plan(
    root: &Path,
    organization_id: Uuid,
    project_id: Uuid,
    admission: &BuildAdmission,
    claim: &mcloving_controller_store::ClaimedAttempt,
    scenario: &str,
    timeout_millis: u64,
) -> EffectExecutionPlan {
    let fence = u64::try_from(claim.fence).unwrap();
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    let request_seed = [11_u8; 32];
    let mut action_request = ActionRequest {
        schema_version: CONNECTOR_REQUEST_V1.into(),
        protocol_version: CONNECTOR_PROTOCOL_V1.into(),
        request_id: Uuid::new_v4(),
        tenant_id: organization_id,
        project_id,
        pipeline_id: project_id,
        build_id: admission.build_id,
        attempt_id: admission.attempt_id,
        effect_fence: fence,
        effect_key: "build.notification".into(),
        connector_id: "fixture-connector".into(),
        expected_implementation_sha256: "1".repeat(64),
        expected_image_sha256: "2".repeat(64),
        expected_config_sha256: "3".repeat(64),
        expected_generation: 1,
        endpoint_identity: "fixture-endpoint".into(),
        account_identity: "fixture-account".into(),
        resource_identity: "fixture-resource".into(),
        effect_class: "notification".into(),
        idempotency_class: IdempotencyClass::ExternallyIdempotent,
        action_name: "notify".into(),
        action_schema_version: "fixture.notify/v1".into(),
        request_payload: json!({"message": "hello"}),
        credential_grant_id: "fixture-grant".into(),
        credential_grant_version: "v1".into(),
        credential_grant_scope: "one-notification".into(),
        requested_at_unix_ms: now - 1_000,
        expires_at_unix_ms: now + 29_000,
        audit_provenance: format!("ext-002/{scenario}/request"),
        authorization: RequestAuthorization {
            key_id: "request-key".into(),
            signature_base64: String::new(),
        },
    };
    sign_action_request(&mut action_request, &request_seed).unwrap();
    let connector_request_sha256 = action_request_digest(&action_request).unwrap();
    let mut observation_request = ObservationRequest {
        schema_version: OBSERVER_REQUEST_V1.into(),
        protocol_version: OBSERVER_PROTOCOL_V1.into(),
        observation_id: Uuid::new_v4(),
        tenant_id: organization_id,
        project_id,
        pipeline_id: project_id,
        build_id: admission.build_id,
        attempt_id: admission.attempt_id,
        effect_fence: fence,
        phase: ObservationPhase::PostAction,
        observer_id: "fixture-observer".into(),
        request_authority_identity: "controller".into(),
        expected_implementation_sha256: "4".repeat(64),
        expected_image_sha256: "5".repeat(64),
        expected_config_sha256: "6".repeat(64),
        expected_generation: 1,
        activation_mode: ObserverActivationMode::Current,
        previous_generation: None,
        rollback_from_generation: None,
        endpoint_identity: "fixture-endpoint".into(),
        account_identity: "fixture-account".into(),
        resource_identity: "fixture-resource".into(),
        effect_class: "notification".into(),
        read_grant_id: "fixture-read".into(),
        read_grant_version: "v1".into(),
        read_grant_scope: "fixture-resource".into(),
        query: [(
            "connector_request_sha256".to_owned(),
            connector_request_sha256,
        )]
        .into_iter()
        .collect(),
        expected_previous_cursor: None,
        predecessor_receipt_sha256: Some("a".repeat(64)),
        requested_at_unix_ms: now - 1_000,
        expires_at_unix_ms: now + 59_000,
        audit_provenance: format!("ext-002/{scenario}/observation"),
        authorization: ObserverAuthorization {
            key_id: "observer-request-key".into(),
            signature_base64: "fixture-request-signature".into(),
        },
    };
    sign_observation_request(&mut observation_request, &[15_u8; 32]).unwrap();
    let service = pinned_effect_fixture_scenario(root, scenario, timeout_millis);
    EffectExecutionPlan {
        schema_version: "mcloving.controller-effect-plan/v1".into(),
        freeze: EffectRuntimeFreeze {
            mapping_id: "notification.v1".into(),
            mapping_digest: format!("sha256:{}", "a".repeat(64)),
            deployment_binding_sha256: "8".repeat(64),
            runtime_attestation_sha256: "9".repeat(64),
            credential_mapping_generation: 1,
            pre_action_observation_sha256: "a".repeat(64),
            grant: FreshOneActionGrant {
                grant_sha256: "b".repeat(64),
                request_id: action_request.request_id,
                attempt_id: admission.attempt_id,
                effect_fence: fence,
                issued_at_unix_ms: now - 2_000,
                expires_at_unix_ms: now + 60_000,
                max_actions: 1,
                consumed_actions: 0,
            },
            action_request,
            request_authority_public_key: public_key_from_seed(&request_seed).unwrap(),
            connector_outcome_public_key: public_key_from_seed(&[12_u8; 32]).unwrap(),
            observer_receipt_public_key: public_key_from_seed(&[13_u8; 32]).unwrap(),
            shadow_replay_public_key: public_key_from_seed(&[14_u8; 32]).unwrap(),
            expected_observer_id: "fixture-observer".into(),
            expected_shadow_identity: "fixture-shadow".into(),
        },
        connector_service: service.clone(),
        observer_service: service.clone(),
        shadow_service: service,
        observation_request,
        audit_provenance: format!("ext-002/{scenario}/plan"),
    }
}

fn runtime_effect_worker(root: &Path, plan: EffectExecutionPlan) -> WorkerConfig {
    WorkerConfig {
        agent_id: "agent-regression".into(),
        session_epoch: 1,
        workspace_root: root.join("workspace"),
        journal_path: root.join("agent.db"),
        cancellation_poll: Duration::from_millis(10),
        lease_seconds: 60,
        termination_grace: Duration::from_millis(100),
        effect_plan: Some(plan),
    }
}

fn dispatch_count(root: &Path) -> usize {
    std::fs::read_to_string(root.join("effect-fixture-dispatches.txt"))
        .map(|entries| entries.lines().count())
        .unwrap_or_default()
}

fn preflight_count(root: &Path) -> usize {
    std::fs::read_to_string(root.join("effect-fixture-preflights.txt"))
        .map(|contents| {
            contents
                .lines()
                .filter(|line| !line.starts_with("release:"))
                .count()
        })
        .unwrap_or(0)
}

fn reservation_release_count(root: &Path) -> usize {
    std::fs::read_to_string(root.join("effect-fixture-preflights.txt"))
        .map(|contents| {
            contents
                .lines()
                .filter(|line| line.starts_with("release:"))
                .count()
        })
        .unwrap_or(0)
}

#[tokio::test]
async fn agent_reconnect_reconciles_and_cancellation_removes_descendants() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    store
        .create_project(
            organization_id,
            &format!("org-{organization_id}"),
            project_id,
            "agent-recovery",
        )
        .await
        .expect("create project");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind API");
    let address = listener.local_addr().expect("API address");
    let server = tokio::spawn(
        axum::serve(listener, router(api_state(store.clone(), organization_id))).into_future(),
    );
    let client = Client::new(&format!("http://{address}"), TOKEN);
    let pipeline_id = Uuid::new_v4();
    save_test_pipeline(
        &client,
        organization_id,
        project_id,
        pipeline_id,
        "agent-recovery",
        CANCELLATION_PIPELINE,
    )
    .await;
    let admission = client
        .submit_pipeline_on_platform_in_pool(
            organization_id,
            project_id,
            pipeline_id,
            "e2e-003",
            "linux",
            "trusted-linux",
            &PipelineBuildRequest::default(),
        )
        .await
        .expect("submit");
    let claim = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "scheduler-recovery".to_owned(),
            agent_id: "agent-recovery".to_owned(),
            capabilities: vec!["platform:linux".to_owned()],
            trust_pool: "trusted-linux".into(),
            lease_seconds: 60,
            fairness_seed: 3,
        })
        .await
        .expect("claim")
        .expect("work exists");
    let execution = store
        .attempt_execution(
            organization_id,
            claim.attempt_id,
            claim.fence,
            claim.restore_epoch,
            "agent-recovery",
        )
        .await
        .expect("execution query")
        .expect("execution exists");
    let root = tempfile::tempdir().expect("workspace root");
    let journal_path = root.path().join("agent.db");
    let workspace = std::path::PathBuf::from(format!(
        "{organization_id}/{}/{}-{fence}",
        claim.attempt_id,
        claim.restore_epoch,
        fence = claim.fence
    ));
    let payload_digest: [u8; 32] =
        Sha256::digest(serde_json::to_vec(&execution.execution_spec).unwrap()).into();
    {
        let mut journal = Journal::open(&journal_path).expect("open journal");
        journal
            .accept(&Acceptance {
                organization_id: organization_id.to_string(),
                attempt_id: claim.attempt_id.to_string(),
                fence_token: (u64::try_from(claim.restore_epoch).unwrap() << 32)
                    | u64::try_from(claim.fence).unwrap(),
                session_epoch: 7,
                payload_digest,
                workspace: workspace.clone(),
            })
            .expect("durable acceptance before disconnect");
    }
    let recovered = Journal::open(&journal_path).expect("reopen after disconnect");
    let report = recovered.reconcile().expect("reconcile journal");
    assert_eq!(report.attempts.len(), 1);
    assert_eq!(report.attempts[0].phase, AttemptPhase::Accepted);
    drop(recovered);

    let config = WorkerConfig {
        agent_id: "agent-recovery".to_owned(),
        session_epoch: 7,
        workspace_root: root.path().to_owned(),
        journal_path: journal_path.clone(),
        cancellation_poll: Duration::from_millis(5),
        lease_seconds: 60,
        termination_grace: Duration::from_millis(100),
        effect_plan: None,
    };
    let run_store = store.clone();
    let run_claim_value = claim.clone();
    let run = tokio::spawn(async move { run_claim(&run_store, &run_claim_value, &config).await });
    let pid_path = root.path().join(&workspace).join("child.pid");
    let child_pid = read_pid(&pid_path).await;
    let live_journal = Journal::open(&journal_path).expect("inspect live journal");
    let live_report = live_journal.reconcile().expect("reconcile live process");
    assert_eq!(live_report.attempts.len(), 1);
    assert_eq!(live_report.attempts[0].phase, AttemptPhase::Running);
    assert!(
        live_report.attempts[0]
            .process_id
            .is_some_and(|process_id| process_id > 0)
    );
    drop(live_journal);
    assert!(
        client
            .cancel(organization_id, project_id, admission.build_id)
            .await
            .expect("request cancellation")
            .accepted
    );
    let receipt = run.await.expect("worker task").expect("worker result");
    assert_eq!(receipt.outcome, TerminalOutcome::Aborted);
    assert_process_gone(child_pid).await;
    let status = client
        .status(organization_id, project_id, admission.build_id)
        .await
        .expect("terminal status");
    assert_eq!(status.status, "aborted");
    assert!(status.cancellation_requested);
    let journal = Journal::open(&journal_path).expect("final journal reopen");
    assert!(
        journal
            .reconcile()
            .expect("final reconcile")
            .attempts
            .is_empty()
    );
    assert_eq!(journal.integrity_check().expect("integrity"), "ok");
    server.abort();
}

#[tokio::test]
async fn cancellation_between_offer_and_acceptance_finishes_without_spawning() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    store
        .create_project(
            organization_id,
            &format!("org-{organization_id}"),
            project_id,
            "pre-accept-cancel",
        )
        .await
        .expect("create project");
    let admission = admit_bound_test_build(
        &store,
        NewBuild {
            organization_id,
            project_id,
            pipeline_id: project_id,
            pipeline_revision: 1,
            pipeline_operational_generation: 1,
            idempotency_key: "pre-accept-cancel".into(),
            pipeline_digest: [21; 32],
            node_key: "execute".into(),
            required_capabilities: vec!["linux".into()],
            required_trust_pool: "trusted".into(),
            priority: 0,
            execution_spec: serde_json::from_str(
                r#"{"version":1,"steps":[{"kind":"process","program":"/bin/sh","args":["-c","touch should-not-exist"],"env":{},"timeout_seconds":10}]}"#,
            )
            .unwrap(),
        },
    )
        .await
        .expect("admit build");
    let claim = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "scheduler-pre-cancel".into(),
            agent_id: "agent-pre-cancel".into(),
            capabilities: vec!["linux".into()],
            trust_pool: "trusted".into(),
            lease_seconds: 30,
            fairness_seed: 1,
        })
        .await
        .expect("claim")
        .expect("claim exists");
    assert!(
        store
            .request_cancellation(organization_id, project_id, admission.build_id)
            .await
            .expect("cancel offered work")
    );
    let root = tempfile::tempdir().expect("worker root");
    let receipt = run_claim(
        &store,
        &claim,
        &WorkerConfig {
            agent_id: "agent-pre-cancel".into(),
            session_epoch: 1,
            workspace_root: root.path().to_owned(),
            journal_path: root.path().join("agent.db"),
            cancellation_poll: Duration::from_millis(10),
            lease_seconds: 30,
            termination_grace: Duration::from_millis(100),
            effect_plan: None,
        },
    )
    .await
    .expect("finish cancellation");
    assert_eq!(receipt.outcome, TerminalOutcome::Aborted);
    assert!(
        !root
            .path()
            .join(format!(
                "{organization_id}/{}/{}-{}/should-not-exist",
                claim.attempt_id, claim.restore_epoch, claim.fence
            ))
            .exists()
    );
    let snapshot = store
        .build_snapshot(organization_id, project_id, admission.build_id)
        .await
        .expect("snapshot")
        .expect("build exists");
    assert_eq!(snapshot.build_status, "aborted");
    assert_eq!(snapshot.attempt_status, "aborted");
}

#[tokio::test]
async fn lease_is_renewed_while_a_long_process_runs() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let (organization_id, project_id, admission, claim) = admitted_claim(
        &store,
        json!({
            "version": 1,
            "steps": [{
                "kind": "process",
                "program": "/bin/sh",
                "args": ["-c", "sleep 2; printf 'renewed\\n'"],
                "env": {},
                "timeout_seconds": 10
            }]
        }),
        "lease-renewal",
        1,
    )
    .await;
    let root = tempfile::tempdir().expect("worker root");
    let receipt = run_claim(
        &store,
        &claim,
        &WorkerConfig {
            agent_id: "agent-regression".into(),
            session_epoch: 1,
            workspace_root: root.path().to_owned(),
            journal_path: root.path().join("agent.db"),
            cancellation_poll: Duration::from_millis(100),
            lease_seconds: 1,
            termination_grace: Duration::from_millis(100),
            effect_plan: None,
        },
    )
    .await
    .expect("lease-renewed execution");
    assert_eq!(receipt.outcome, TerminalOutcome::Succeeded);
    let snapshot = store
        .build_snapshot(organization_id, project_id, admission.build_id)
        .await
        .expect("snapshot")
        .expect("build exists");
    assert_eq!(snapshot.build_status, "succeeded");
}

#[tokio::test]
async fn process_spawn_failure_is_published_as_terminal_failure() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let (organization_id, project_id, admission, claim) = admitted_claim(
        &store,
        json!({
            "version": 1,
            "steps": [{
                "kind": "process",
                "program": "/definitely/not/a/mcloving-program",
                "args": [],
                "env": {},
                "timeout_seconds": 10
            }]
        }),
        "missing-program",
        30,
    )
    .await;
    let root = tempfile::tempdir().expect("worker root");
    let journal_path = root.path().join("agent.db");
    let receipt = run_claim(
        &store,
        &claim,
        &WorkerConfig {
            agent_id: "agent-regression".into(),
            session_epoch: 1,
            workspace_root: root.path().to_owned(),
            journal_path: journal_path.clone(),
            cancellation_poll: Duration::from_millis(10),
            lease_seconds: 30,
            termination_grace: Duration::from_millis(100),
            effect_plan: None,
        },
    )
    .await
    .expect("spawn failure becomes a result");
    assert_eq!(receipt.outcome, TerminalOutcome::Failed);
    let snapshot = store
        .build_snapshot(organization_id, project_id, admission.build_id)
        .await
        .expect("snapshot")
        .expect("build exists");
    assert_eq!(snapshot.build_status, "failed");
    assert_eq!(snapshot.attempt_status, "failed");
    assert!(
        snapshot
            .terminal_summary
            .and_then(|summary| summary["reason"].as_str().map(str::to_owned))
            .is_some_and(|reason| reason.starts_with("process_spawn_failed:"))
    );
    assert!(
        Journal::open(journal_path)
            .expect("reopen journal")
            .reconcile()
            .expect("reconcile")
            .attempts
            .is_empty()
    );
}

#[tokio::test]
async fn post_dispatch_timeout_freezes_retry_and_dispatches_exactly_once() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let (organization_id, project_id, admission, claim) = admitted_claim(
        &store,
        runtime_effect_spec(),
        "effect-timeout-after-dispatch",
        60,
    )
    .await;
    let root = tempfile::tempdir().unwrap();
    let plan = runtime_effect_plan(
        root.path(),
        organization_id,
        project_id,
        &admission,
        &claim,
        "timeout_after_dispatch",
        100,
    );
    let config = runtime_effect_worker(root.path(), plan);
    assert!(matches!(
        run_claim(&store, &claim, &config).await,
        Err(SpineError::EffectReconciliationRequired)
    ));
    assert_eq!(dispatch_count(root.path()), 1);
    let state: (String, String, i64) = sqlx::query_as(
        "SELECT a.status, e.status,
                ((e.outcome_receipt IS NOT NULL)::int
                 + (e.reconciliation_receipt IS NOT NULL)::int
                 + (e.observation_receipt IS NOT NULL)::int
                 + (e.shadow_replay_receipt IS NOT NULL)::int)::bigint
         FROM attempts AS a
         JOIN attempt_effects AS e
           ON e.organization_id = a.organization_id AND e.attempt_id = a.id
         WHERE a.organization_id = $1 AND a.id = $2",
    )
    .bind(organization_id)
    .bind(admission.attempt_id)
    .fetch_one(store.pool())
    .await
    .expect("read timeout reconciliation state");
    assert_eq!(
        state,
        ("reconciliation_required".into(), "uncertain".into(), 0)
    );
    assert!(matches!(
        run_claim(&store, &claim, &config).await,
        Err(SpineError::StaleAuthority)
    ));
    assert_eq!(dispatch_count(root.path()), 1);
}

#[tokio::test]
async fn signed_response_substitution_is_uncertain_at_every_post_dispatch_join() {
    for scenario in [
        "substituted_connector_response",
        "substituted_observer_response",
        "substituted_observer_binding",
        "substituted_shadow_response",
    ] {
        let Some(store) = test_store().await else {
            eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
            return;
        };
        let (organization_id, project_id, admission, claim) = admitted_claim(
            &store,
            runtime_effect_spec(),
            &format!("effect-{scenario}"),
            60,
        )
        .await;
        let root = tempfile::tempdir().unwrap();
        let plan = runtime_effect_plan(
            root.path(),
            organization_id,
            project_id,
            &admission,
            &claim,
            scenario,
            5_000,
        );
        let config = runtime_effect_worker(root.path(), plan);
        assert!(matches!(
            run_claim(&store, &claim, &config).await,
            Err(SpineError::EffectReconciliationRequired)
        ));
        assert_eq!(dispatch_count(root.path()), 1, "scenario {scenario}");
        let state: (String, String) = sqlx::query_as(
            "SELECT a.status, e.status
             FROM attempts AS a
             JOIN attempt_effects AS e
               ON e.organization_id = a.organization_id AND e.attempt_id = a.id
             WHERE a.organization_id = $1 AND a.id = $2",
        )
        .bind(organization_id)
        .bind(admission.attempt_id)
        .fetch_one(store.pool())
        .await
        .expect("read response-substitution state");
        assert_eq!(
            state,
            ("reconciliation_required".into(), "uncertain".into())
        );
    }
}

#[tokio::test]
async fn signed_runtime_scope_must_match_the_durable_build_before_dispatch() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let (organization_id, project_id, admission, claim) = admitted_claim(
        &store,
        runtime_effect_spec(),
        "effect-wrong-durable-scope",
        60,
    )
    .await;
    let root = tempfile::tempdir().unwrap();
    let mut plan = runtime_effect_plan(
        root.path(),
        organization_id,
        project_id,
        &admission,
        &claim,
        "success",
        5_000,
    );
    plan.freeze.action_request.project_id = Uuid::new_v4();
    plan.freeze.action_request.pipeline_id = Uuid::new_v4();
    sign_action_request(&mut plan.freeze.action_request, &[11_u8; 32]).unwrap();
    let receipt = run_claim(&store, &claim, &runtime_effect_worker(root.path(), plan))
        .await
        .expect("scope mismatch is durably terminalized before dispatch");
    assert_eq!(receipt.outcome, TerminalOutcome::Failed);
    assert_eq!(dispatch_count(root.path()), 0);
    let snapshot = store
        .build_snapshot(organization_id, project_id, admission.build_id)
        .await
        .expect("read scope-mismatch build")
        .expect("scope-mismatch build exists");
    assert_eq!(snapshot.build_status, "failed");
    assert_eq!(snapshot.attempt_status, "failed");
    sqlx::query(
        "UPDATE attempts SET lease_expires_at=NOW() - INTERVAL '1 second'
         WHERE organization_id=$1 AND id=$2",
    )
    .bind(organization_id)
    .bind(admission.attempt_id)
    .execute(store.pool())
    .await
    .expect("force the old lease timestamp behind the requeue boundary");
    assert!(
        !store
            .requeue_one_expired(organization_id)
            .await
            .expect("terminal mismatch must not requeue")
    );
    assert!(
        store
            .claim_next(&ClaimRequest {
                organization_id,
                scheduler_id: "scheduler-after-scope-mismatch".into(),
                agent_id: "agent-after-scope-mismatch".into(),
                capabilities: vec!["linux".into()],
                trust_pool: "trusted".into(),
                lease_seconds: 30,
                fairness_seed: 1,
            })
            .await
            .expect("claim after terminal scope mismatch")
            .is_none()
    );
}

#[tokio::test]
async fn observer_predecessor_must_match_the_frozen_pre_action_receipt_before_dispatch() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let (organization_id, project_id, admission, claim) = admitted_claim(
        &store,
        runtime_effect_spec(),
        "effect-wrong-observer-predecessor",
        60,
    )
    .await;
    let root = tempfile::tempdir().unwrap();
    let mut plan = runtime_effect_plan(
        root.path(),
        organization_id,
        project_id,
        &admission,
        &claim,
        "success",
        5_000,
    );
    plan.observation_request.predecessor_receipt_sha256 = Some("f".repeat(64));
    let receipt = run_claim(&store, &claim, &runtime_effect_worker(root.path(), plan))
        .await
        .expect("invalid observer predecessor fails as a terminal preflight error");
    assert_eq!(receipt.outcome, TerminalOutcome::Failed);
    assert_eq!(dispatch_count(root.path()), 0);
    let effect: (String, i64) = sqlx::query_as(
        "SELECT status,
                ((outcome_receipt IS NOT NULL)::int
                 + (observation_receipt IS NOT NULL)::int
                 + (shadow_replay_receipt IS NOT NULL)::int)::bigint
         FROM attempt_effects
         WHERE organization_id = $1 AND attempt_id = $2",
    )
    .bind(organization_id)
    .bind(admission.attempt_id)
    .fetch_one(store.pool())
    .await
    .expect("read predecessor-preflight effect");
    assert_eq!(effect, ("abandoned".into(), 0));
}

#[tokio::test]
async fn signed_effect_requests_must_be_fully_admissible_before_dispatch() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    for case in [
        "bad_signature",
        "expired",
        "insufficient_action_validity",
        "insufficient_validity",
        "wrong_protocol",
        "wrong_binding",
    ] {
        let (organization_id, project_id, admission, claim) = admitted_claim(
            &store,
            runtime_effect_spec(),
            &format!("effect-observer-request-{case}"),
            60,
        )
        .await;
        let root = tempfile::tempdir().unwrap();
        let mut plan = runtime_effect_plan(
            root.path(),
            organization_id,
            project_id,
            &admission,
            &claim,
            "success",
            5_000,
        );
        match case {
            "insufficient_action_validity" => {
                let now = i64::try_from(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_millis(),
                )
                .unwrap();
                plan.freeze.action_request.requested_at_unix_ms = now - 1_000;
                plan.freeze.action_request.expires_at_unix_ms = now + 1_000;
                sign_action_request(&mut plan.freeze.action_request, &[11_u8; 32]).unwrap();
            }
            "bad_signature" => {
                plan.observation_request.authorization.signature_base64 = "AAAA".into();
            }
            "expired" => {
                let now = i64::try_from(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_millis(),
                )
                .unwrap();
                plan.observation_request.requested_at_unix_ms = now - 10_000;
                plan.observation_request.expires_at_unix_ms = now - 1;
                sign_observation_request(&mut plan.observation_request, &[15_u8; 32]).unwrap();
            }
            "insufficient_validity" => {
                let now = i64::try_from(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_millis(),
                )
                .unwrap();
                plan.observation_request.requested_at_unix_ms = now - 1_000;
                plan.observation_request.expires_at_unix_ms = now + 1_000;
                sign_observation_request(&mut plan.observation_request, &[15_u8; 32]).unwrap();
            }
            "wrong_protocol" => {
                plan.observation_request.protocol_version =
                    "mcloving.destination-observer/substituted".into();
                sign_observation_request(&mut plan.observation_request, &[15_u8; 32]).unwrap();
            }
            "wrong_binding" => {
                plan.observation_request.expected_config_sha256 = "f".repeat(64);
                sign_observation_request(&mut plan.observation_request, &[15_u8; 32]).unwrap();
            }
            _ => unreachable!(),
        }
        let result = run_claim(&store, &claim, &runtime_effect_worker(root.path(), plan)).await;
        assert_eq!(dispatch_count(root.path()), 0, "case={case}");
        if case == "insufficient_action_validity" {
            let receipt = result.expect("locally expired action authority is terminal");
            assert_eq!(receipt.outcome, TerminalOutcome::Failed, "case={case}");
            let effect_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM attempt_effects
                 WHERE organization_id = $1 AND attempt_id = $2",
            )
            .bind(organization_id)
            .bind(admission.attempt_id)
            .fetch_one(store.pool())
            .await
            .expect("count action-authority effects");
            assert_eq!(effect_count, 0, "case={case}");
            continue;
        }
        assert!(
            matches!(result, Err(SpineError::EffectReconciliationRequired)),
            "observer transport closure after a potentially delivered verify is ambiguous: case={case}"
        );
        let effect: (String, i64) = sqlx::query_as(
            "SELECT status,
                    ((outcome_receipt IS NOT NULL)::int
                     + (observation_receipt IS NOT NULL)::int
                     + (shadow_replay_receipt IS NOT NULL)::int)::bigint
             FROM attempt_effects
             WHERE organization_id = $1 AND attempt_id = $2",
        )
        .bind(organization_id)
        .bind(admission.attempt_id)
        .fetch_one(store.pool())
        .await
        .expect("read rejected observation-request effect");
        assert_eq!(effect, ("release_pending".into(), 0), "case={case}");
    }
}

#[tokio::test]
async fn exhausted_effect_timeout_budget_is_terminal_before_dispatch() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let (organization_id, project_id, admission, claim) = admitted_claim(
        &store,
        runtime_effect_spec(),
        "effect-timeout-budget-exhausted",
        60,
    )
    .await;
    let root = tempfile::tempdir().unwrap();
    let mut plan = runtime_effect_plan(
        root.path(),
        organization_id,
        project_id,
        &admission,
        &claim,
        "success",
        5_000,
    );
    plan.observer_service.timeout_millis = 30_000;
    let config = runtime_effect_worker(root.path(), plan);

    let receipt = run_claim(&store, &claim, &config)
        .await
        .expect("deterministic timeout exhaustion is terminal");
    assert_eq!(receipt.outcome, TerminalOutcome::Failed);
    assert_eq!(dispatch_count(root.path()), 0);
    assert_eq!(preflight_count(root.path()), 0);
    let effect_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM attempt_effects WHERE organization_id=$1 AND attempt_id=$2",
    )
    .bind(organization_id)
    .bind(admission.attempt_id)
    .fetch_one(store.pool())
    .await
    .expect("count timeout-budget effects");
    assert_eq!(effect_count, 0);

    sqlx::query(
        "UPDATE attempts SET lease_expires_at=NOW() - INTERVAL '1 second'
         WHERE organization_id=$1 AND id=$2",
    )
    .bind(organization_id)
    .bind(admission.attempt_id)
    .execute(store.pool())
    .await
    .expect("force timeout lease timestamp behind the requeue boundary");
    assert!(
        !store
            .requeue_one_expired(organization_id)
            .await
            .expect("terminal timeout failure must not requeue")
    );
    assert!(
        store
            .claim_next(&ClaimRequest {
                organization_id,
                scheduler_id: "scheduler-after-timeout-exhaustion".into(),
                agent_id: "agent-after-timeout-exhaustion".into(),
                capabilities: vec!["linux".into()],
                trust_pool: "trusted".into(),
                lease_seconds: 30,
                fairness_seed: 1,
            })
            .await
            .expect("claim after timeout terminalization")
            .is_none()
    );
}

#[tokio::test]
async fn cancellation_during_effect_preflight_abandons_before_connector_dispatch() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let (organization_id, project_id, admission, claim) = admitted_claim(
        &store,
        runtime_effect_spec(),
        "effect-cancel-during-preflight",
        60,
    )
    .await;
    let root = tempfile::tempdir().unwrap();
    let plan = runtime_effect_plan(
        root.path(),
        organization_id,
        project_id,
        &admission,
        &claim,
        "slow_preflight_release_failure_once",
        5_000,
    );
    let config = runtime_effect_worker(root.path(), plan);
    let run_store = store.clone();
    let run_claim_value = claim.clone();
    let execution =
        tokio::spawn(async move { run_claim(&run_store, &run_claim_value, &config).await });
    for _ in 0..200 {
        if preflight_count(root.path()) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(preflight_count(root.path()), 1);
    assert!(
        store
            .request_cancellation(organization_id, project_id, admission.build_id)
            .await
            .expect("request cancellation during observer preflight")
    );
    let receipt = execution
        .await
        .expect("worker task")
        .expect("pre-dispatch cancellation outcome");
    assert_eq!(receipt.outcome, TerminalOutcome::Aborted);
    assert_eq!(dispatch_count(root.path()), 0);
    assert_eq!(
        reservation_release_count(root.path()),
        2,
        "the attempt must remain non-terminal until idempotent release succeeds"
    );
    let effect: (String, i64) = sqlx::query_as(
        "SELECT status,
                ((outcome_receipt IS NOT NULL)::int
                 + (observation_receipt IS NOT NULL)::int
                 + (shadow_replay_receipt IS NOT NULL)::int)::bigint
         FROM attempt_effects
         WHERE organization_id = $1 AND attempt_id = $2",
    )
    .bind(organization_id)
    .bind(admission.attempt_id)
    .fetch_one(store.pool())
    .await
    .expect("read cancelled preflight effect");
    assert_eq!(effect, ("abandoned".into(), 0));
}

#[tokio::test]
async fn dead_observer_release_session_routes_to_durable_reconciliation() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let (organization_id, project_id, admission, claim) = admitted_claim(
        &store,
        runtime_effect_spec(),
        "effect-dead-observer-release",
        60,
    )
    .await;
    let root = tempfile::tempdir().unwrap();
    let plan = runtime_effect_plan(
        root.path(),
        organization_id,
        project_id,
        &admission,
        &claim,
        "slow_preflight_release_session_exit",
        5_000,
    );
    let config = runtime_effect_worker(root.path(), plan);
    let run_store = store.clone();
    let run_claim_value = claim.clone();
    let execution =
        tokio::spawn(async move { run_claim(&run_store, &run_claim_value, &config).await });
    for _ in 0..200 {
        if preflight_count(root.path()) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(preflight_count(root.path()), 1);
    assert!(
        store
            .request_cancellation(organization_id, project_id, admission.build_id)
            .await
            .expect("request cancellation during observer preflight")
    );
    let result = tokio::time::timeout(Duration::from_secs(2), execution)
        .await
        .expect("dead observer release must not pin the worker or lease")
        .expect("worker task");
    assert!(matches!(
        result,
        Err(SpineError::EffectReconciliationRequired)
    ));
    assert_eq!(dispatch_count(root.path()), 0);
    assert_eq!(
        reservation_release_count(root.path()),
        1,
        "the dead retained session cannot accept a second release command"
    );
    let state: (String, String, i64) = sqlx::query_as(
        "SELECT a.status, e.status,
                ((e.outcome_receipt IS NOT NULL)::int
                 + (e.reconciliation_receipt IS NOT NULL)::int
                 + (e.observation_receipt IS NOT NULL)::int
                 + (e.shadow_replay_receipt IS NOT NULL)::int)::bigint
         FROM attempts AS a
         JOIN attempt_effects AS e
           ON e.organization_id = a.organization_id AND e.attempt_id = a.id
         WHERE a.organization_id = $1 AND a.id = $2",
    )
    .bind(organization_id)
    .bind(admission.attempt_id)
    .fetch_one(store.pool())
    .await
    .expect("read observer-release reconciliation state");
    assert_eq!(
        state,
        (
            "reconciliation_required".into(),
            "release_pending".into(),
            0
        )
    );
}

#[tokio::test]
async fn ambiguous_observer_verify_failure_retains_release_reconciliation() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let (organization_id, project_id, admission, claim) = admitted_claim(
        &store,
        runtime_effect_spec(),
        "effect-ambiguous-observer-verify",
        60,
    )
    .await;
    let root = tempfile::tempdir().unwrap();
    let plan = runtime_effect_plan(
        root.path(),
        organization_id,
        project_id,
        &admission,
        &claim,
        "verify_session_exit",
        5_000,
    );
    let result = run_claim(&store, &claim, &runtime_effect_worker(root.path(), plan)).await;
    assert!(matches!(
        result,
        Err(SpineError::EffectReconciliationRequired)
    ));
    assert_eq!(preflight_count(root.path()), 1);
    assert_eq!(dispatch_count(root.path()), 0);
    assert_eq!(
        reservation_release_count(root.path()),
        0,
        "the dead observer session cannot consume the idempotent release command"
    );
    let state: (String, String, i64) = sqlx::query_as(
        "SELECT a.status, e.status,
                ((e.outcome_receipt IS NOT NULL)::int
                 + (e.reconciliation_receipt IS NOT NULL)::int
                 + (e.observation_receipt IS NOT NULL)::int
                 + (e.shadow_replay_receipt IS NOT NULL)::int)::bigint
         FROM attempts AS a
         JOIN attempt_effects AS e
           ON e.organization_id = a.organization_id AND e.attempt_id = a.id
         WHERE a.organization_id = $1 AND a.id = $2",
    )
    .bind(organization_id)
    .bind(admission.attempt_id)
    .fetch_one(store.pool())
    .await
    .expect("read ambiguous observer verification state");
    assert_eq!(
        state,
        (
            "reconciliation_required".into(),
            "release_pending".into(),
            0
        )
    );
}

#[tokio::test]
async fn authority_loss_after_observer_verification_records_release_pending() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let (organization_id, project_id, admission, claim) = admitted_claim(
        &store,
        runtime_effect_spec(),
        "effect-authority-loss-after-observer-verification",
        60,
    )
    .await;
    let root = tempfile::tempdir().unwrap();
    let plan = runtime_effect_plan(
        root.path(),
        organization_id,
        project_id,
        &admission,
        &claim,
        "slow_preflight_release_session_exit",
        5_000,
    );
    let mut config = runtime_effect_worker(root.path(), plan);
    config.lease_seconds = 1;
    let run_store = store.clone();
    let run_claim_value = claim.clone();
    let execution =
        tokio::spawn(async move { run_claim(&run_store, &run_claim_value, &config).await });
    for _ in 0..200 {
        if preflight_count(root.path()) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(preflight_count(root.path()), 1);
    let mut authority_loss = store.pool().begin().await.expect("begin renewal race");
    let authority_loss_backend_pid = sqlx::query_scalar::<_, i32>("SELECT pg_backend_pid()")
        .fetch_one(&mut *authority_loss)
        .await
        .expect("read renewal-race blocker backend PID");
    sqlx::query(
        "UPDATE attempts
         SET lease_expires_at=clock_timestamp() - interval '1 second'
         WHERE organization_id=$1 AND id=$2",
    )
    .bind(organization_id)
    .bind(claim.attempt_id)
    .execute(&mut *authority_loss)
    .await
    .expect("stage authority expiry while observer verification is in flight");
    let mut renewal_blocked = false;
    for _ in 0..200 {
        renewal_blocked = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (
                 SELECT 1 FROM pg_stat_activity
                 WHERE $1 = ANY(pg_blocking_pids(pid))
             )",
        )
        .bind(authority_loss_backend_pid)
        .fetch_one(store.pool())
        .await
        .expect("inspect lease-renewal waiter");
        if renewal_blocked {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        renewal_blocked,
        "lease renewal must be in flight behind the held authority row"
    );
    authority_loss
        .commit()
        .await
        .expect("commit authority expiry before the dispatch gate");
    let result = tokio::time::timeout(Duration::from_secs(2), execution)
        .await
        .expect("authority-loss cleanup must not pin the worker")
        .expect("worker task");
    assert!(matches!(result, Err(SpineError::StaleAuthority)));
    assert_eq!(dispatch_count(root.path()), 0);
    assert_eq!(reservation_release_count(root.path()), 1);
    let effect_status = sqlx::query_scalar::<_, String>(
        "SELECT status FROM attempt_effects
         WHERE organization_id=$1 AND attempt_id=$2 AND fence=$3",
    )
    .bind(organization_id)
    .bind(claim.attempt_id)
    .bind(claim.fence)
    .fetch_one(store.pool())
    .await
    .expect("read authority-loss release state");
    assert_eq!(effect_status, "release_pending");
    assert!(
        store
            .requeue_one_expired(organization_id)
            .await
            .expect("route expired release-pending attempt")
    );
    let state: (String, String) = sqlx::query_as(
        "SELECT a.status, e.status
         FROM attempts AS a
         JOIN attempt_effects AS e
           ON e.organization_id=a.organization_id AND e.attempt_id=a.id
         WHERE a.organization_id=$1 AND a.id=$2 AND e.fence=$3",
    )
    .bind(organization_id)
    .bind(claim.attempt_id)
    .bind(claim.fence)
    .fetch_one(store.pool())
    .await
    .expect("read expired release-pending reconciliation state");
    assert_eq!(
        state,
        ("reconciliation_required".into(), "release_pending".into())
    );
}

#[tokio::test]
async fn effect_path_renews_a_short_lease_until_all_joins_are_durable() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let (organization_id, project_id, admission, claim) = admitted_claim(
        &store,
        runtime_effect_spec(),
        "effect-short-lease-renewal",
        1,
    )
    .await;
    let root = tempfile::tempdir().unwrap();
    let plan = runtime_effect_plan(
        root.path(),
        organization_id,
        project_id,
        &admission,
        &claim,
        "slow_success",
        5_000,
    );
    let mut config = runtime_effect_worker(root.path(), plan);
    config.lease_seconds = 1;
    let receipt = run_claim(&store, &claim, &config)
        .await
        .expect("renew short lease through connector, observer, and shadow joins");
    assert_eq!(receipt.outcome, TerminalOutcome::Succeeded);
    assert_eq!(dispatch_count(root.path()), 1);
}

#[tokio::test]
async fn ambiguous_outcome_reconciles_without_a_second_dispatch() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let (organization_id, project_id, admission, claim) = admitted_claim(
        &store,
        runtime_effect_spec(),
        "effect-ambiguous-reconcile",
        60,
    )
    .await;
    let root = tempfile::tempdir().unwrap();
    let plan = runtime_effect_plan(
        root.path(),
        organization_id,
        project_id,
        &admission,
        &claim,
        "ambiguous_then_reconcile",
        5_000,
    );
    let receipt = run_claim(&store, &claim, &runtime_effect_worker(root.path(), plan))
        .await
        .expect("ambiguous outcome reconciles through independent observation");
    assert_eq!(receipt.outcome, TerminalOutcome::Succeeded);
    assert_eq!(dispatch_count(root.path()), 1);
    let state: (String, i64) = sqlx::query_as(
        "SELECT status,
                ((outcome_receipt IS NOT NULL)::int
                 + (reconciliation_receipt IS NOT NULL)::int
                 + (observation_receipt IS NOT NULL)::int
                 + (shadow_replay_receipt IS NOT NULL)::int)::bigint
         FROM attempt_effects
         WHERE organization_id = $1 AND attempt_id = $2",
    )
    .bind(organization_id)
    .bind(admission.attempt_id)
    .fetch_one(store.pool())
    .await
    .expect("read reconciled effect join");
    assert_eq!(state, ("confirmed".into(), 4));
}

#[tokio::test]
async fn controller_crash_after_dispatch_and_lease_loss_never_reoffers_runtime_effect() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let (organization_id, project_id, admission, claim) = admitted_claim(
        &store,
        runtime_effect_spec(),
        "effect-crash-after-dispatch",
        1,
    )
    .await;
    let root = tempfile::tempdir().unwrap();
    let plan = runtime_effect_plan(
        root.path(),
        organization_id,
        project_id,
        &admission,
        &claim,
        "crash_after_dispatch",
        10_000,
    );
    let mut config = runtime_effect_worker(root.path(), plan);
    config.lease_seconds = 1;
    let run_store = store.clone();
    let run_claim_value = claim.clone();
    let execution =
        tokio::spawn(async move { run_claim(&run_store, &run_claim_value, &config).await });
    for _ in 0..200 {
        if dispatch_count(root.path()) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(dispatch_count(root.path()), 1);
    execution.abort();
    let _ = execution.await;
    drop(store);
    let restarted = test_store().await.expect("reconnect controller store");
    let mut expired_effect_routed = false;
    for _ in 0..40 {
        if restarted
            .requeue_one_expired(organization_id)
            .await
            .expect("route expired runtime effect")
        {
            expired_effect_routed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    if !expired_effect_routed {
        let state: (String, Option<String>, String, String) = sqlx::query_as(
            "SELECT a.status, a.lease_expires_at::text, clock_timestamp()::text, e.status
             FROM attempts AS a
             JOIN attempt_effects AS e
               ON e.organization_id = a.organization_id AND e.attempt_id = a.id
             WHERE a.organization_id = $1 AND a.id = $2",
        )
        .bind(organization_id)
        .bind(admission.attempt_id)
        .fetch_one(restarted.pool())
        .await
        .expect("inspect non-expiring runtime effect lease");
        panic!("runtime effect lease did not expire: {state:?}");
    }
    let state: (String, String) = sqlx::query_as(
        "SELECT a.status, e.status
         FROM attempts AS a
         JOIN attempt_effects AS e
           ON e.organization_id = a.organization_id AND e.attempt_id = a.id
         WHERE a.organization_id = $1 AND a.id = $2",
    )
    .bind(organization_id)
    .bind(admission.attempt_id)
    .fetch_one(restarted.pool())
    .await
    .expect("read restarted controller state");
    assert_eq!(
        state,
        ("reconciliation_required".into(), "uncertain".into())
    );
    assert!(
        restarted
            .claim_next(&ClaimRequest {
                organization_id,
                scheduler_id: "scheduler-after-crash".into(),
                agent_id: "agent-after-crash".into(),
                capabilities: vec!["linux".into()],
                trust_pool: "trusted".into(),
                lease_seconds: 60,
                fairness_seed: 2,
            })
            .await
            .expect("look for reoffered work")
            .is_none()
    );
    assert_eq!(dispatch_count(root.path()), 1);
}

#[tokio::test]
async fn cancellation_after_dispatch_joins_evidence_then_aborts_without_duplicate_effect() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let (organization_id, project_id, admission, claim) = admitted_claim(
        &store,
        runtime_effect_spec(),
        "effect-cancel-after-dispatch",
        60,
    )
    .await;
    let root = tempfile::tempdir().unwrap();
    let plan = runtime_effect_plan(
        root.path(),
        organization_id,
        project_id,
        &admission,
        &claim,
        "success",
        5_000,
    );
    let config = runtime_effect_worker(root.path(), plan);
    let run_store = store.clone();
    let run_claim_value = claim.clone();
    let execution =
        tokio::spawn(async move { run_claim(&run_store, &run_claim_value, &config).await });
    for _ in 0..200 {
        if dispatch_count(root.path()) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(dispatch_count(root.path()), 1);
    assert!(
        store
            .request_cancellation(organization_id, project_id, admission.build_id)
            .await
            .expect("request cancellation after dispatch")
    );
    let receipt = execution
        .await
        .expect("worker task")
        .expect("joined cancellation outcome");
    assert_eq!(receipt.outcome, TerminalOutcome::Aborted);
    assert_eq!(dispatch_count(root.path()), 1);
    let state: (String, String, i64) = sqlx::query_as(
        "SELECT a.status, e.status,
                ((e.outcome_receipt IS NOT NULL)::int
                 + (e.observation_receipt IS NOT NULL)::int
                 + (e.shadow_replay_receipt IS NOT NULL)::int)::bigint
         FROM attempts AS a
         JOIN attempt_effects AS e
           ON e.organization_id = a.organization_id AND e.attempt_id = a.id
         WHERE a.organization_id = $1 AND a.id = $2",
    )
    .bind(organization_id)
    .bind(admission.attempt_id)
    .fetch_one(store.pool())
    .await
    .expect("read post-dispatch cancellation join");
    assert_eq!(state, ("aborted".into(), "confirmed".into(), 3));
}

#[tokio::test]
async fn signed_effect_join_withholds_terminal_until_shadow_is_durable() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let mapping_digest = format!("sha256:{}", "a".repeat(64));
    let downstream_digest = format!("sha256:{}", "b".repeat(64));
    let execution_spec = json!({
        "version": 2,
        "steps": [{
            "kind": "connector_intent",
            "mapping_id": "notification.v1",
            "mapping_digest": mapping_digest,
            "effect_class": "externally_idempotent",
            "effect_key_template": "build.notification",
            "public_input_schema": {"message": "string"},
            "protected_secret_ref_schema": {"token": "string"},
            "expected_public_result_schema": {"delivery_id": "string"},
            "timeout_seconds": 30,
            "ambiguity_policy": "observe_then_reconcile",
            "downstream_control_digest": downstream_digest,
        }]
    });
    let (organization_id, project_id, admission, claim) =
        admitted_claim(&store, execution_spec, "effect-plan-positive", 60).await;
    let fence = u64::try_from(claim.fence).unwrap();
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    let request_seed = [11_u8; 32];
    let request_key = public_key_from_seed(&request_seed).unwrap();
    let mut action_request = ActionRequest {
        schema_version: CONNECTOR_REQUEST_V1.into(),
        protocol_version: CONNECTOR_PROTOCOL_V1.into(),
        request_id: Uuid::new_v4(),
        tenant_id: organization_id,
        project_id,
        pipeline_id: project_id,
        build_id: admission.build_id,
        attempt_id: admission.attempt_id,
        effect_fence: fence,
        effect_key: "build.notification".into(),
        connector_id: "fixture-connector".into(),
        expected_implementation_sha256: "1".repeat(64),
        expected_image_sha256: "2".repeat(64),
        expected_config_sha256: "3".repeat(64),
        expected_generation: 1,
        endpoint_identity: "fixture-endpoint".into(),
        account_identity: "fixture-account".into(),
        resource_identity: "fixture-resource".into(),
        effect_class: "notification".into(),
        idempotency_class: IdempotencyClass::ExternallyIdempotent,
        action_name: "notify".into(),
        action_schema_version: "fixture.notify/v1".into(),
        request_payload: json!({"message": "hello"}),
        credential_grant_id: "fixture-grant".into(),
        credential_grant_version: "v1".into(),
        credential_grant_scope: "one-notification".into(),
        requested_at_unix_ms: now - 1_000,
        expires_at_unix_ms: now + 20_000,
        audit_provenance: "effect-free-positive-test".into(),
        authorization: RequestAuthorization {
            key_id: "request-key".into(),
            signature_base64: String::new(),
        },
    };
    sign_action_request(&mut action_request, &request_seed).unwrap();
    let connector_request_sha256 = action_request_digest(&action_request).unwrap();
    let mut observation_request = ObservationRequest {
        schema_version: OBSERVER_REQUEST_V1.into(),
        protocol_version: OBSERVER_PROTOCOL_V1.into(),
        observation_id: Uuid::new_v4(),
        tenant_id: organization_id,
        project_id,
        pipeline_id: project_id,
        build_id: admission.build_id,
        attempt_id: admission.attempt_id,
        effect_fence: fence,
        phase: ObservationPhase::PostAction,
        observer_id: "fixture-observer".into(),
        request_authority_identity: "controller".into(),
        expected_implementation_sha256: "4".repeat(64),
        expected_image_sha256: "5".repeat(64),
        expected_config_sha256: "6".repeat(64),
        expected_generation: 1,
        activation_mode: ObserverActivationMode::Current,
        previous_generation: None,
        rollback_from_generation: None,
        endpoint_identity: "fixture-endpoint".into(),
        account_identity: "fixture-account".into(),
        resource_identity: "fixture-resource".into(),
        effect_class: "notification".into(),
        read_grant_id: "fixture-read".into(),
        read_grant_version: "v1".into(),
        read_grant_scope: "fixture-resource".into(),
        query: [(
            "connector_request_sha256".to_owned(),
            connector_request_sha256,
        )]
        .into_iter()
        .collect(),
        expected_previous_cursor: None,
        predecessor_receipt_sha256: Some("a".repeat(64)),
        requested_at_unix_ms: now - 1_000,
        expires_at_unix_ms: now + 20_000,
        audit_provenance: "effect-free-positive-test".into(),
        authorization: ObserverAuthorization {
            key_id: "observer-request-key".into(),
            signature_base64: "fixture-request-signature".into(),
        },
    };
    sign_observation_request(&mut observation_request, &[15_u8; 32]).unwrap();
    let root = tempfile::tempdir().unwrap();
    let service = pinned_effect_fixture(root.path());
    let plan = EffectExecutionPlan {
        schema_version: "mcloving.controller-effect-plan/v1".into(),
        freeze: EffectRuntimeFreeze {
            mapping_id: "notification.v1".into(),
            mapping_digest,
            deployment_binding_sha256: "8".repeat(64),
            runtime_attestation_sha256: "9".repeat(64),
            credential_mapping_generation: 1,
            pre_action_observation_sha256: "a".repeat(64),
            grant: FreshOneActionGrant {
                grant_sha256: "b".repeat(64),
                request_id: action_request.request_id,
                attempt_id: admission.attempt_id,
                effect_fence: fence,
                issued_at_unix_ms: now - 2_000,
                expires_at_unix_ms: now + 60_000,
                max_actions: 1,
                consumed_actions: 0,
            },
            action_request,
            request_authority_public_key: request_key,
            connector_outcome_public_key: public_key_from_seed(&[12_u8; 32]).unwrap(),
            observer_receipt_public_key: public_key_from_seed(&[13_u8; 32]).unwrap(),
            shadow_replay_public_key: public_key_from_seed(&[14_u8; 32]).unwrap(),
            expected_observer_id: "fixture-observer".into(),
            expected_shadow_identity: "fixture-shadow".into(),
        },
        connector_service: service.clone(),
        observer_service: service.clone(),
        shadow_service: service,
        observation_request,
        audit_provenance: "effect-free-positive-test".into(),
    };
    let config = WorkerConfig {
        agent_id: "agent-regression".into(),
        session_epoch: 1,
        workspace_root: root.path().join("workspace"),
        journal_path: root.path().join("agent.db"),
        cancellation_poll: Duration::from_millis(10),
        lease_seconds: 60,
        termination_grace: Duration::from_millis(100),
        effect_plan: Some(plan),
    };
    let mut execution = Box::pin(run_claim(&store, &claim, &config));
    let before_shadow = loop {
        tokio::select! {
            result = &mut execution => {
                let state: Option<(String, i64)> = sqlx::query_as(
                    "SELECT e.status,
                            ((e.outcome_receipt IS NOT NULL)::int
                             + (e.observation_receipt IS NOT NULL)::int
                             + (e.shadow_replay_receipt IS NOT NULL)::int)::bigint
                     FROM attempt_effects AS e
                     WHERE e.organization_id = $1 AND e.attempt_id = $2",
                )
                .bind(organization_id)
                .bind(admission.attempt_id)
                .fetch_optional(store.pool())
                .await
                .expect("read early effect termination state");
                let diagnostic = std::fs::read_to_string(root.path().join("effect-fixture-error.txt"))
                    .unwrap_or_else(|_| "no fixture diagnostic".into());
                panic!(
                    "effect execution terminated before the shadow join checkpoint: {result:?}; durable state: {state:?}; fixture: {diagnostic}"
                );
            },
            () = tokio::time::sleep(Duration::from_millis(10)) => {
            let state: Option<(String, i64)> = sqlx::query_as(
                "SELECT a.status,
                        ((e.outcome_receipt IS NOT NULL)::int
                         + (e.observation_receipt IS NOT NULL)::int
                         + (e.shadow_replay_receipt IS NOT NULL)::int)::bigint
                 FROM attempts AS a
                 JOIN attempt_effects AS e
                   ON e.organization_id = a.organization_id
                  AND e.attempt_id = a.id
                 WHERE a.organization_id = $1 AND a.id = $2",
            )
            .bind(organization_id)
            .bind(admission.attempt_id)
            .fetch_optional(store.pool())
            .await
            .expect("observe effect join before shadow");
            if state.as_ref().is_some_and(|(_, evidence)| *evidence == 2) {
                    break state.unwrap();
                }
            }
        }
    };
    assert_eq!(before_shadow, ("running".into(), 2));
    let receipt = execution.await.expect("signed effect join completes");
    assert_eq!(receipt.outcome, TerminalOutcome::Succeeded);
    let joined: (String, i64) = sqlx::query_as(
        "SELECT status,
                ((outcome_receipt IS NOT NULL)::int
                 + (observation_receipt IS NOT NULL)::int
                 + (shadow_replay_receipt IS NOT NULL)::int)::bigint
         FROM attempt_effects
         WHERE organization_id = $1 AND attempt_id = $2",
    )
    .bind(organization_id)
    .bind(admission.attempt_id)
    .fetch_one(store.pool())
    .await
    .expect("read complete effect join");
    assert_eq!(joined, ("confirmed".into(), 3));
    let summaries = store
        .effect_evidence_summaries(organization_id, admission.attempt_id)
        .await
        .expect("read redacted public effect evidence");
    assert_eq!(summaries.len(), 1);
    let summary = &summaries[0];
    assert_eq!(summary.fence, claim.fence);
    assert_eq!(summary.effect_key, "build.notification");
    assert_eq!(summary.status, "confirmed");
    assert!(summary.payload_digest.iter().any(|byte| *byte != 0));
    assert!(summary.outcome_receipt_digest.is_some());
    assert!(summary.reconciliation_receipt_digest.is_none());
    assert!(summary.observation_receipt_digest.is_some());
    assert!(summary.shadow_replay_receipt_digest.is_some());

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind API");
    let address = listener.local_addr().expect("read API address");
    let server = tokio::spawn(
        axum::serve(listener, router(api_state(store.clone(), organization_id))).into_future(),
    );
    let status = Client::new(&format!("http://{address}"), TOKEN)
        .status(organization_id, project_id, admission.build_id)
        .await
        .expect("read redacted effect evidence through HTTP");
    assert_eq!(status.effects.len(), 1);
    let effect = &status.effects[0];
    assert_eq!(effect.fence, claim.fence);
    assert_eq!(effect.effect_key, "build.notification");
    assert_eq!(effect.status, "confirmed");
    assert_eq!(effect.payload_sha256.len(), 64);
    assert!(effect.outcome_receipt_sha256.is_some());
    assert!(effect.reconciliation_receipt_sha256.is_none());
    assert!(effect.observation_receipt_sha256.is_some());
    assert!(effect.shadow_replay_receipt_sha256.is_some());
    server.abort();
}

#[tokio::test]
async fn connector_plan_preflight_failure_abandons_without_dispatch_or_downstream_release() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let mapping_digest = format!("sha256:{}", "a".repeat(64));
    let downstream_digest = format!("sha256:{}", "b".repeat(64));
    let execution_spec = json!({
        "version": 2,
        "steps": [{
            "kind": "connector_intent",
            "mapping_id": "notification.v1",
            "mapping_digest": mapping_digest,
            "effect_class": "externally_idempotent",
            "effect_key_template": "build.notification",
            "public_input_schema": {"message": "string"},
            "protected_secret_ref_schema": {"token": "string"},
            "expected_public_result_schema": {"delivery_id": "string"},
            "timeout_seconds": 30,
            "ambiguity_policy": "observe_then_reconcile",
            "downstream_control_digest": downstream_digest,
        }]
    });
    let (organization_id, project_id, admission, claim) =
        admitted_claim(&store, execution_spec, "effect-plan-preflight", 60).await;
    let fence = u64::try_from(claim.fence).unwrap();
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    let request_seed = [11_u8; 32];
    let request_key = public_key_from_seed(&request_seed).unwrap();
    let mut action_request = ActionRequest {
        schema_version: CONNECTOR_REQUEST_V1.into(),
        protocol_version: CONNECTOR_PROTOCOL_V1.into(),
        request_id: Uuid::new_v4(),
        tenant_id: organization_id,
        project_id,
        pipeline_id: project_id,
        build_id: admission.build_id,
        attempt_id: admission.attempt_id,
        effect_fence: fence,
        effect_key: "build.notification".into(),
        connector_id: "fixture-connector".into(),
        expected_implementation_sha256: "1".repeat(64),
        expected_image_sha256: "2".repeat(64),
        expected_config_sha256: "3".repeat(64),
        expected_generation: 1,
        endpoint_identity: "fixture-endpoint".into(),
        account_identity: "fixture-account".into(),
        resource_identity: "fixture-resource".into(),
        effect_class: "notification".into(),
        idempotency_class: IdempotencyClass::ExternallyIdempotent,
        action_name: "notify".into(),
        action_schema_version: "fixture.notify/v1".into(),
        request_payload: json!({"message": "hello"}),
        credential_grant_id: "fixture-grant".into(),
        credential_grant_version: "v1".into(),
        credential_grant_scope: "one-notification".into(),
        requested_at_unix_ms: now - 1_000,
        expires_at_unix_ms: now + 20_000,
        audit_provenance: "effect-free-preflight-test".into(),
        authorization: RequestAuthorization {
            key_id: "request-key".into(),
            signature_base64: String::new(),
        },
    };
    sign_action_request(&mut action_request, &request_seed).unwrap();
    let connector_request_sha256 = action_request_digest(&action_request).unwrap();
    let observation_request = ObservationRequest {
        schema_version: OBSERVER_REQUEST_V1.into(),
        protocol_version: OBSERVER_PROTOCOL_V1.into(),
        observation_id: Uuid::new_v4(),
        tenant_id: organization_id,
        project_id,
        pipeline_id: project_id,
        build_id: admission.build_id,
        attempt_id: admission.attempt_id,
        effect_fence: fence,
        phase: ObservationPhase::PostAction,
        observer_id: "fixture-observer".into(),
        request_authority_identity: "controller".into(),
        expected_implementation_sha256: "4".repeat(64),
        expected_image_sha256: "5".repeat(64),
        expected_config_sha256: "6".repeat(64),
        expected_generation: 1,
        activation_mode: ObserverActivationMode::Current,
        previous_generation: None,
        rollback_from_generation: None,
        endpoint_identity: "fixture-endpoint".into(),
        account_identity: "fixture-account".into(),
        resource_identity: "fixture-resource".into(),
        effect_class: "notification".into(),
        read_grant_id: "fixture-read".into(),
        read_grant_version: "v1".into(),
        read_grant_scope: "fixture-resource".into(),
        query: [(
            "connector_request_sha256".to_owned(),
            connector_request_sha256,
        )]
        .into_iter()
        .collect(),
        expected_previous_cursor: None,
        predecessor_receipt_sha256: Some("a".repeat(64)),
        requested_at_unix_ms: now - 1_000,
        expires_at_unix_ms: now + 60_000,
        audit_provenance: "effect-free-preflight-test".into(),
        authorization: ObserverAuthorization {
            key_id: "observer-request-key".into(),
            signature_base64: "not-reached".into(),
        },
    };
    let root = tempfile::tempdir().unwrap();
    let valid_service = pinned_effect_fixture(root.path());
    let mut unavailable_observer = valid_service.clone();
    unavailable_observer.executable_sha256 = "0".repeat(64);
    let plan = EffectExecutionPlan {
        schema_version: "mcloving.controller-effect-plan/v1".into(),
        freeze: EffectRuntimeFreeze {
            mapping_id: "notification.v1".into(),
            mapping_digest,
            deployment_binding_sha256: "8".repeat(64),
            runtime_attestation_sha256: "9".repeat(64),
            credential_mapping_generation: 1,
            pre_action_observation_sha256: "a".repeat(64),
            grant: FreshOneActionGrant {
                grant_sha256: "b".repeat(64),
                request_id: action_request.request_id,
                attempt_id: admission.attempt_id,
                effect_fence: fence,
                issued_at_unix_ms: now - 2_000,
                expires_at_unix_ms: now + 60_000,
                max_actions: 1,
                consumed_actions: 0,
            },
            action_request,
            request_authority_public_key: request_key,
            connector_outcome_public_key: public_key_from_seed(&[12_u8; 32]).unwrap(),
            observer_receipt_public_key: public_key_from_seed(&[13_u8; 32]).unwrap(),
            shadow_replay_public_key: public_key_from_seed(&[14_u8; 32]).unwrap(),
            expected_observer_id: "fixture-observer".into(),
            expected_shadow_identity: "fixture-shadow".into(),
        },
        connector_service: valid_service.clone(),
        observer_service: unavailable_observer,
        shadow_service: valid_service,
        observation_request,
        audit_provenance: "effect-free-preflight-test".into(),
    };
    let receipt = run_claim(
        &store,
        &claim,
        &WorkerConfig {
            agent_id: "agent-regression".into(),
            session_epoch: 1,
            workspace_root: root.path().to_owned(),
            journal_path: root.path().join("agent.db"),
            cancellation_poll: Duration::from_millis(10),
            lease_seconds: 60,
            termination_grace: Duration::from_millis(100),
            effect_plan: Some(plan),
        },
    )
    .await
    .expect("pre-dispatch service substitution becomes a terminal failure");
    assert_eq!(receipt.outcome, TerminalOutcome::Failed);
    assert_eq!(dispatch_count(root.path()), 0);
    let effect: (String, i64) = sqlx::query_as(
        "SELECT status,
                ((outcome_receipt IS NOT NULL)::int
                 + (observation_receipt IS NOT NULL)::int
                 + (shadow_replay_receipt IS NOT NULL)::int)::bigint
         FROM attempt_effects
         WHERE organization_id = $1 AND attempt_id = $2",
    )
    .bind(organization_id)
    .bind(admission.attempt_id)
    .fetch_one(store.pool())
    .await
    .expect("read abandoned effect");
    assert_eq!(effect, ("abandoned".into(), 0));
}

async fn admitted_claim(
    store: &Store,
    execution_spec: serde_json::Value,
    idempotency_key: &str,
    lease_seconds: i32,
) -> (
    Uuid,
    Uuid,
    mcloving_controller_store::BuildAdmission,
    mcloving_controller_store::ClaimedAttempt,
) {
    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    store
        .create_project(
            organization_id,
            &format!("org-{organization_id}"),
            project_id,
            idempotency_key,
        )
        .await
        .expect("create project");
    let admission = admit_bound_test_build(
        store,
        NewBuild {
            organization_id,
            project_id,
            pipeline_id: project_id,
            pipeline_revision: 1,
            pipeline_operational_generation: 1,
            idempotency_key: idempotency_key.into(),
            pipeline_digest: Sha256::digest(idempotency_key).into(),
            node_key: "execute".into(),
            required_capabilities: vec!["linux".into()],
            required_trust_pool: "trusted".into(),
            priority: 0,
            execution_spec,
        },
    )
    .await
    .expect("admit build");
    let claim = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "scheduler-regression".into(),
            agent_id: "agent-regression".into(),
            capabilities: vec!["linux".into()],
            trust_pool: "trusted".into(),
            lease_seconds,
            fairness_seed: 1,
        })
        .await
        .expect("claim")
        .expect("claim exists");
    (organization_id, project_id, admission, claim)
}

async fn read_pid(path: &std::path::Path) -> i32 {
    for _ in 0..200 {
        if let Ok(value) = tokio::fs::read_to_string(path).await
            && let Ok(pid) = value.trim().parse()
        {
            return pid;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("descendant PID was not written");
}

async fn assert_process_gone(pid: i32) {
    for _ in 0..200 {
        match tokio::fs::read_to_string(format!("/proc/{pid}/stat")).await {
            Ok(status)
                if status
                    .rsplit_once(") ")
                    .and_then(|(_, tail)| tail.chars().next())
                    == Some('Z') =>
            {
                return;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Ok(_) => {}
            Err(error) => panic!("unexpected process probe error: {error}"),
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("descendant process {pid} escaped cancellation");
}
