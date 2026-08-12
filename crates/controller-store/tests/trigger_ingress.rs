use mcloving_controller_store::{
    DagNodeKind, NewDagBuild, NewDagNode, NewTriggerDelivery, PipelineOperationalState,
    PipelineOperationalStateTransition, PipelineOperationalStateTransitionOutcome,
    PipelinePutOutcome, PipelineTriggerState, PipelineTriggerWrite, PipelineWrite, Store,
    StoreError, TRIGGER_DAG_IDEMPOTENCY_PREFIX, TriggerDeliveryAdmission,
    TriggerDeliveryClaimOutcome, TriggerDeliveryClaimRequest, TriggerDeliveryDagAdmission,
    TriggerDeliveryDagAdmissionRequest, TriggerDeliveryFailure, TriggerDeliveryFailureRequest,
    TriggerDeliveryRedrive, TriggerDeliveryStatus, TriggerKind, TriggerPutOutcome,
    TriggerScheduleSlot, compute_audit_event_hash, compute_trigger_transfer_snapshot_digest,
    compute_trigger_transfer_snapshot_ledger_digest, verify_trigger_transfer_snapshot,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

const SOURCE: &str = r#"version: 1
name: trigger-test
stages:
  - id: run
    name: Run
    steps:
      - process:
          program: echo
          args: [ok]
"#;

async fn test_store() -> Option<Store> {
    let url = std::env::var("MCLOVING_TEST_DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(16)
        .connect(&url)
        .await
        .expect("connect to the explicitly configured PostgreSQL test database");
    let store = Store::new(pool);
    store.migrate().await.expect("install controller schema");
    Some(store)
}

async fn fixture(store: &Store) -> (Uuid, Uuid, Uuid) {
    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    let pipeline_id = Uuid::new_v4();
    store
        .create_project(
            organization_id,
            &format!("org-{organization_id}"),
            project_id,
            &format!("project-{project_id}"),
        )
        .await
        .expect("create trigger fixture project");
    assert!(matches!(
        store
            .put_pipeline_as(
                &PipelineWrite {
                    organization_id,
                    project_id,
                    pipeline_id,
                    slug: format!("pipeline-{pipeline_id}"),
                    source: SOURCE.to_owned(),
                    source_sha256: Sha256::digest(SOURCE.as_bytes()).into(),
                    semantic_digest: Sha256::digest(b"trigger-semantic-v1").into(),
                    schema_major: 1,
                    schema_minor: 0,
                    parameter_schema: json!({}),
                },
                Some(0),
                "creator@example.test",
            )
            .await
            .expect("create trigger fixture pipeline"),
        PipelinePutOutcome::Created(_)
    ));
    (organization_id, project_id, pipeline_id)
}

async fn database_unix_ms(store: &Store) -> i64 {
    sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
        .fetch_one(store.pool())
        .await
        .expect("sample PostgreSQL clock")
}

async fn lock_audit_head(
    store: &Store,
    organization_id: Uuid,
) -> (Transaction<'static, Postgres>, i32) {
    let mut tx = store
        .pool()
        .begin()
        .await
        .expect("begin audit lock fixture");
    sqlx::query("SELECT set_config('mcloving.organization_id', $1, true)")
        .bind(organization_id.to_string())
        .execute(&mut *tx)
        .await
        .expect("scope audit lock fixture");
    sqlx::query(
        "INSERT INTO audit_chain_heads (organization_id)
         VALUES ($1) ON CONFLICT (organization_id) DO NOTHING",
    )
    .bind(organization_id)
    .execute(&mut *tx)
    .await
    .expect("ensure audit head fixture");
    sqlx::query(
        "SELECT next_sequence FROM audit_chain_heads
         WHERE organization_id = $1 FOR UPDATE",
    )
    .bind(organization_id)
    .fetch_one(&mut *tx)
    .await
    .expect("lock audit head fixture");
    let backend_pid = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *tx)
        .await
        .expect("read audit lock backend PID");
    (tx, backend_pid)
}

async fn wait_until_blocked_by(store: &Store, backend_pid: i32) {
    for _ in 0..100 {
        let blocked = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (
                 SELECT 1 FROM pg_stat_activity
                 WHERE $1 = ANY(pg_blocking_pids(pid))
             )",
        )
        .bind(backend_pid)
        .fetch_one(store.pool())
        .await
        .expect("inspect PostgreSQL lock waiters");
        if blocked {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("trigger transaction did not reach the held audit-head lock");
}

#[allow(clippy::too_many_arguments)]
fn trigger_write(
    organization_id: Uuid,
    project_id: Uuid,
    pipeline_id: Uuid,
    trigger_id: Uuid,
    expected_generation: i64,
    kind: TriggerKind,
    state: PipelineTriggerState,
    event_source_identity: &str,
    configuration: Value,
    idempotency_key: &str,
    max_delivery_attempts: i32,
) -> PipelineTriggerWrite {
    let filter = configuration
        .get("filter")
        .expect("test trigger configuration includes filter");
    PipelineTriggerWrite {
        organization_id,
        project_id,
        pipeline_id,
        trigger_id,
        expected_generation,
        kind,
        state,
        implementation_sha256: Sha256::digest(b"trigger-implementation-v1").into(),
        configuration_sha256: Sha256::digest(
            serde_json::to_vec(&configuration)
                .expect("serialize configuration")
                .as_slice(),
        )
        .into(),
        filter_sha256: Sha256::digest(
            serde_json::to_vec(filter)
                .expect("serialize filter")
                .as_slice(),
        )
        .into(),
        event_source_identity: event_source_identity.to_owned(),
        source_generation: format!("source-{expected_generation}"),
        configuration,
        deduplication_window_seconds: 3_600,
        max_delivery_attempts,
        delivery_ttl_seconds: 7_200,
        actor_subject: "operator@example.test".to_owned(),
        reason: "reviewed trigger configuration".to_owned(),
        idempotency_key: idempotency_key.to_owned(),
    }
}

#[allow(clippy::too_many_arguments)]
fn delivery(
    organization_id: Uuid,
    project_id: Uuid,
    pipeline_id: Uuid,
    trigger_id: Uuid,
    generation: i64,
    delivery_id: &str,
    event_id: &str,
    accepted_at_unix_ms: i64,
) -> NewTriggerDelivery {
    let canonical_payload = json!({
        "event_kind": "push",
        "event_time_unix_ms": accepted_at_unix_ms - 1_000,
        "payload": {
            "repository_identity": "github:superbadlabs/mcloving",
            "revision": "0123456789abcdef",
            "branch": "main",
            "paths": ["src/lib.rs"]
        },
    });
    NewTriggerDelivery {
        organization_id,
        project_id,
        pipeline_id,
        trigger_id,
        expected_trigger_generation: generation,
        delivery_id: delivery_id.to_owned(),
        event_id: event_id.to_owned(),
        event_kind: "push".to_owned(),
        caller_identity: "scm:github:installation:42".to_owned(),
        payload_sha256: Sha256::digest(
            serde_json::to_vec(&canonical_payload)
                .expect("serialize delivery")
                .as_slice(),
        )
        .into(),
        canonical_payload,
        parameters: json!({}),
        requested_platform: "linux".to_owned(),
        requested_trust_pool: "trusted-linux".to_owned(),
        event_time_unix_ms: accepted_at_unix_ms - 1_000,
        accepted_at_unix_ms,
        schedule_slot: None,
    }
}

fn remote_delivery(mut input: NewTriggerDelivery) -> NewTriggerDelivery {
    input.event_kind = "remote".to_owned();
    input.canonical_payload = json!({
        "event_kind": "remote",
        "event_time_unix_ms": input.event_time_unix_ms,
        "payload": {
            "audience": "mcloving:remote-build",
            "request_id": input.event_id.clone(),
            "request_method": "POST",
        },
    });
    input.payload_sha256 = Sha256::digest(
        serde_json::to_vec(&input.canonical_payload)
            .expect("serialize remote delivery")
            .as_slice(),
    )
    .into();
    input
}

fn delivery_with_event_time(
    mut input: NewTriggerDelivery,
    event_time_unix_ms: i64,
) -> NewTriggerDelivery {
    input.event_time_unix_ms = event_time_unix_ms;
    input.canonical_payload["event_time_unix_ms"] = json!(event_time_unix_ms);
    input.payload_sha256 = Sha256::digest(
        serde_json::to_vec(&input.canonical_payload)
            .expect("serialize retimed delivery")
            .as_slice(),
    )
    .into();
    input
}

fn claim(
    organization_id: Uuid,
    trigger_id: Uuid,
    delivery_id: &str,
    worker_identity: &str,
    now_unix_ms: i64,
) -> TriggerDeliveryClaimRequest {
    TriggerDeliveryClaimRequest {
        organization_id,
        trigger_id,
        delivery_id: delivery_id.to_owned(),
        worker_identity: worker_identity.to_owned(),
        now_unix_ms,
        lease_expires_at_unix_ms: now_unix_ms + 60_000,
    }
}

fn dag(
    organization_id: Uuid,
    project_id: Uuid,
    pipeline_id: Uuid,
    idempotency_key: &str,
) -> NewDagBuild {
    NewDagBuild {
        organization_id,
        project_id,
        pipeline_id,
        pipeline_revision: 1,
        pipeline_operational_generation: 1,
        idempotency_key: idempotency_key.to_owned(),
        pipeline_digest: Sha256::digest(b"trigger-semantic-v1").into(),
        priority: 0,
        nodes: vec![NewDagNode {
            node_key: "run".to_owned(),
            kind: DagNodeKind::Work,
            dependencies: Vec::new(),
            required_capabilities: Vec::new(),
            required_platform: "linux".to_owned(),
            required_trust_pool: "trusted-linux".to_owned(),
            priority: 0,
            execution_spec: json!({"steps": []}),
            fail_fast: true,
            max_attempts: 1,
        }],
    }
}

#[tokio::test]
async fn delivery_dedup_claim_retry_and_operational_fences_are_durable() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let (organization_id, project_id, pipeline_id) = fixture(&store).await;
    let reserved = dag(
        organization_id,
        project_id,
        pipeline_id,
        &format!("{TRIGGER_DAG_IDEMPOTENCY_PREFIX}forged"),
    );
    assert!(matches!(
        store.admit_dag(&reserved).await,
        Err(StoreError::InvalidDag(message))
            if message == "trigger DAG idempotency namespace is reserved"
    ));
    let trigger_id = Uuid::new_v4();
    let write = trigger_write(
        organization_id,
        project_id,
        pipeline_id,
        trigger_id,
        0,
        TriggerKind::ScmWebhook,
        PipelineTriggerState::Enabled,
        "scm:github:installation:42",
        json!({
            "provider": "github",
            "repository_identity": "github:superbadlabs/mcloving",
            "filter": {"event_kinds": ["push"], "branches": ["main"]},
        }),
        "trigger-create",
        3,
    );
    let (left, right) = tokio::join!(
        store.put_pipeline_trigger(&write),
        store.put_pipeline_trigger(&write)
    );
    let outcomes = [left.unwrap(), right.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, TriggerPutOutcome::Created(_)))
            .count(),
        1
    );
    let mut divergent_audit_retry = write.clone();
    divergent_audit_retry.reason = "different audit reason".to_owned();
    assert!(matches!(
        store.put_pipeline_trigger(&divergent_audit_retry).await,
        Err(StoreError::TriggerIngressConflict(_))
    ));
    let unknown_configuration = trigger_write(
        organization_id,
        project_id,
        pipeline_id,
        Uuid::new_v4(),
        0,
        TriggerKind::ScmWebhook,
        PipelineTriggerState::Enabled,
        "scm:github:installation:42",
        json!({
            "provider": "github",
            "repository_identity": "github:superbadlabs/mcloving",
            "filter": {},
            "unreviewed_extension": true,
        }),
        "trigger-unknown-config",
        3,
    );
    assert!(matches!(
        store.put_pipeline_trigger(&unknown_configuration).await,
        Err(StoreError::InvalidTriggerIngress(_))
    ));
    let unordered_filter_trigger_id = Uuid::new_v4();
    let unordered_unique_filter = trigger_write(
        organization_id,
        project_id,
        pipeline_id,
        unordered_filter_trigger_id,
        0,
        TriggerKind::ScmWebhook,
        PipelineTriggerState::Enabled,
        "scm:github:installation:42",
        json!({
            "provider": "github",
            "repository_identity": "github:superbadlabs/mcloving",
            "filter": {
                "event_kinds": ["push", "pull_request"],
                "branches": ["release", "main"]
            },
        }),
        "trigger-unordered-unique-filter",
        3,
    );
    assert!(matches!(
        store
            .put_pipeline_trigger(&unordered_unique_filter)
            .await
            .unwrap(),
        TriggerPutOutcome::Created(_)
    ));
    let unordered_filter_now = database_unix_ms(&store).await;
    assert!(matches!(
        store
            .accept_trigger_delivery(&delivery(
                organization_id,
                project_id,
                pipeline_id,
                unordered_filter_trigger_id,
                1,
                "delivery-unordered-filter",
                "event-unordered-filter",
                unordered_filter_now,
            ))
            .await
            .unwrap(),
        TriggerDeliveryAdmission::Created(_)
    ));
    let duplicate_filter = trigger_write(
        organization_id,
        project_id,
        pipeline_id,
        Uuid::new_v4(),
        0,
        TriggerKind::ScmWebhook,
        PipelineTriggerState::Enabled,
        "scm:github:installation:42",
        json!({
            "provider": "github",
            "repository_identity": "github:superbadlabs/mcloving",
            "filter": {"event_kinds": ["push", "push"]},
        }),
        "trigger-duplicate-filter",
        3,
    );
    assert!(matches!(
        store.put_pipeline_trigger(&duplicate_filter).await,
        Err(StoreError::InvalidTriggerIngress(_))
    ));
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, TriggerPutOutcome::Replayed(_)))
            .count(),
        1
    );

    let now = database_unix_ms(&store).await;
    let mut input = delivery(
        organization_id,
        project_id,
        pipeline_id,
        trigger_id,
        1,
        "delivery-1",
        "event-1",
        now,
    );
    input.accepted_at_unix_ms = now + 10 * 60_000;
    let mut future = delivery_with_event_time(input.clone(), now + 310_000);
    future.delivery_id = "delivery-future".to_owned();
    future.event_id = "event-future".to_owned();
    assert!(matches!(
        store.accept_trigger_delivery(&future).await,
        Err(StoreError::InvalidTriggerIngress(_))
    ));
    let mut delayed = delivery_with_event_time(input.clone(), now - 3_610_000);
    delayed.delivery_id = "delivery-delayed".to_owned();
    delayed.event_id = "event-delayed".to_owned();
    assert!(matches!(
        store.accept_trigger_delivery(&delayed).await,
        Err(StoreError::InvalidTriggerIngress(_))
    ));
    let mut substituted_repository = input.clone();
    substituted_repository.delivery_id = "delivery-substituted-repository".to_owned();
    substituted_repository.event_id = "event-substituted-repository".to_owned();
    substituted_repository.canonical_payload["payload"]["repository_identity"] =
        json!("github:superbadlabs/another-repository");
    substituted_repository.payload_sha256 = Sha256::digest(
        serde_json::to_vec(&substituted_repository.canonical_payload)
            .unwrap()
            .as_slice(),
    )
    .into();
    assert!(matches!(
        store.accept_trigger_delivery(&substituted_repository).await,
        Err(StoreError::TriggerIngressConflict(_))
    ));
    let mut unknown_payload = input.clone();
    unknown_payload.delivery_id = "delivery-unknown-payload".to_owned();
    unknown_payload.event_id = "event-unknown-payload".to_owned();
    unknown_payload.canonical_payload["payload"]["unreviewed_extension"] = json!(true);
    unknown_payload.payload_sha256 = Sha256::digest(
        serde_json::to_vec(&unknown_payload.canonical_payload)
            .unwrap()
            .as_slice(),
    )
    .into();
    assert!(matches!(
        store.accept_trigger_delivery(&unknown_payload).await,
        Err(StoreError::InvalidTriggerIngress(_))
    ));
    let database_before_accept = database_unix_ms(&store).await;
    let (left, right) = tokio::join!(
        store.accept_trigger_delivery(&input),
        store.accept_trigger_delivery(&input)
    );
    let database_after_accept = database_unix_ms(&store).await;
    let concurrent_outcomes = [left.unwrap(), right.unwrap()];
    let accepted = concurrent_outcomes
        .iter()
        .find_map(|outcome| match outcome {
            TriggerDeliveryAdmission::Created(delivery) => Some(delivery),
            TriggerDeliveryAdmission::Replayed(_) => None,
        })
        .expect("one active-active accept creates the delivery");
    assert!(accepted.accepted_at_unix_ms >= database_before_accept);
    assert!(accepted.accepted_at_unix_ms <= database_after_accept);
    assert_eq!(
        accepted.expires_at_unix_ms,
        accepted.accepted_at_unix_ms + 7_200_000
    );
    assert_eq!(
        concurrent_outcomes
            .iter()
            .filter(|outcome| matches!(outcome, TriggerDeliveryAdmission::Created(_)))
            .count(),
        1
    );
    assert_eq!(
        concurrent_outcomes
            .iter()
            .filter(|outcome| matches!(outcome, TriggerDeliveryAdmission::Replayed(_)))
            .count(),
        1
    );
    assert!(matches!(
        store.accept_trigger_delivery(&input).await.unwrap(),
        TriggerDeliveryAdmission::Replayed(_)
    ));
    let mut substituted = input.clone();
    substituted.event_kind = "pull_request".to_owned();
    assert!(matches!(
        store.accept_trigger_delivery(&substituted).await,
        Err(StoreError::TriggerIngressConflict(_))
    ));

    let first_claim = match store
        .claim_trigger_delivery(&claim(
            organization_id,
            trigger_id,
            "delivery-1",
            "worker-1",
            now,
        ))
        .await
        .unwrap()
    {
        TriggerDeliveryClaimOutcome::Claimed(delivery) => delivery,
        other => panic!("unexpected first claim: {other:?}"),
    };
    assert_eq!(first_claim.claim_fence, 1);
    let database_after_claim = sqlx::query_scalar::<_, i64>(
        "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(first_claim.claim_expires_at_unix_ms.unwrap() > database_after_claim);
    assert!(first_claim.claim_expires_at_unix_ms.unwrap() <= database_after_claim + 60_000);
    assert!(matches!(
        store
            .claim_trigger_delivery(&claim(
                organization_id,
                trigger_id,
                "delivery-1",
                "worker-2",
                now + 1,
            ))
            .await
            .unwrap(),
        TriggerDeliveryClaimOutcome::Leased(_)
    ));
    assert!(matches!(
        store
            .claim_trigger_delivery(&claim(
                organization_id,
                trigger_id,
                "delivery-1",
                "worker-fast-clock",
                now + 10 * 60_000,
            ))
            .await
            .unwrap(),
        TriggerDeliveryClaimOutcome::Leased(_)
    ));
    let retry_database_before = database_unix_ms(&store).await;
    let retry_caller_clock = retry_database_before + 10 * 60_000;
    let retry = store
        .fail_trigger_delivery(&TriggerDeliveryFailureRequest {
            organization_id,
            trigger_id,
            delivery_id: "delivery-1".to_owned(),
            worker_identity: "worker-1".to_owned(),
            claim_fence: first_claim.claim_fence,
            now_unix_ms: retry_caller_clock,
            retry_at_unix_ms: retry_caller_clock + 500,
            retryable: true,
            reason: "contained outage".to_owned(),
        })
        .await
        .unwrap();
    let TriggerDeliveryFailure::RetryScheduled(retry) = retry else {
        panic!("a fast caller clock must not dead-letter a live delivery")
    };
    let retry_database_after = database_unix_ms(&store).await;
    assert!(retry.next_attempt_at_unix_ms >= retry_database_before + 500);
    assert!(retry.next_attempt_at_unix_ms <= retry_database_after + 500);
    assert!(
        store
            .due_trigger_deliveries(organization_id, i64::MAX, 128)
            .await
            .unwrap()
            .iter()
            .all(|delivery| delivery.delivery_id != "delivery-1"),
        "retry worker cannot claim before the durable due time"
    );
    assert!(matches!(
        store
            .claim_trigger_delivery(&claim(
                organization_id,
                trigger_id,
                "delivery-1",
                "worker-2",
                now + 30_000,
            ))
            .await
            .unwrap(),
        TriggerDeliveryClaimOutcome::NotDue(_)
    ));
    sqlx::query("SELECT pg_sleep(0.6)")
        .execute(store.pool())
        .await
        .unwrap();
    let due = store
        .due_trigger_deliveries(organization_id, 0, 128)
        .await
        .unwrap();
    assert_eq!(
        due.iter()
            .filter(|delivery| delivery.trigger_id == trigger_id)
            .map(|delivery| delivery.delivery_id.as_str())
            .collect::<Vec<_>>(),
        vec!["delivery-1"],
        "retry worker discovers the exact durable due delivery"
    );
    let second_claim = match store
        .claim_trigger_delivery(&claim(
            organization_id,
            trigger_id,
            "delivery-1",
            "worker-2",
            now - 10 * 60_000,
        ))
        .await
        .unwrap()
    {
        TriggerDeliveryClaimOutcome::Claimed(delivery) => delivery,
        other => panic!("unexpected second claim: {other:?}"),
    };
    assert_eq!(second_claim.claim_fence, 2);
    let trigger_dag = dag(
        organization_id,
        project_id,
        pipeline_id,
        "trigger-delivery-1",
    );
    assert!(matches!(
        store
            .admit_trigger_delivery_dag(
                &TriggerDeliveryDagAdmissionRequest {
                    organization_id,
                    trigger_id,
                    delivery_id: "delivery-1".to_owned(),
                    worker_identity: "worker-1".to_owned(),
                    claim_fence: 1,
                },
                &trigger_dag,
            )
            .await,
        Err(StoreError::TriggerIngressConflict(_))
    ));
    let completed = store
        .admit_trigger_delivery_dag(
            &TriggerDeliveryDagAdmissionRequest {
                organization_id,
                trigger_id,
                delivery_id: "delivery-1".to_owned(),
                worker_identity: "worker-2".to_owned(),
                claim_fence: second_claim.claim_fence,
            },
            &trigger_dag,
        )
        .await
        .unwrap();
    let TriggerDeliveryDagAdmission::Admitted {
        delivery: completed,
        admission,
    } = completed
    else {
        panic!("valid trigger DAG admission must be atomic")
    };
    assert_eq!(completed.status, TriggerDeliveryStatus::Admitted);
    assert_eq!(completed.build_id, Some(admission.build_id));

    let expiring_trigger_id = Uuid::new_v4();
    let mut expiring_write = write.clone();
    expiring_write.trigger_id = expiring_trigger_id;
    expiring_write.expected_generation = 0;
    expiring_write.delivery_ttl_seconds = 1;
    expiring_write.idempotency_key = "trigger-expiry-create".to_owned();
    store.put_pipeline_trigger(&expiring_write).await.unwrap();

    let acceptance_contention_now = database_unix_ms(&store).await;
    let acceptance_contention_delivery = delivery(
        organization_id,
        project_id,
        pipeline_id,
        expiring_trigger_id,
        1,
        "delivery-audit-contention-accept",
        "event-audit-contention-accept",
        acceptance_contention_now,
    );
    let (audit_lock, audit_backend_pid) = lock_audit_head(&store, organization_id).await;
    let contention_store = store.clone();
    let acceptance_task = tokio::spawn(async move {
        contention_store
            .accept_trigger_delivery(&acceptance_contention_delivery)
            .await
    });
    wait_until_blocked_by(&store, audit_backend_pid).await;
    sqlx::query("SELECT pg_sleep(1.1)")
        .execute(store.pool())
        .await
        .unwrap();
    let audit_release_time = database_unix_ms(&store).await;
    audit_lock.rollback().await.unwrap();
    let TriggerDeliveryAdmission::Created(accepted_after_audit_wait) =
        acceptance_task.await.unwrap().unwrap()
    else {
        panic!("audit-contention acceptance must create one delivery")
    };
    assert!(accepted_after_audit_wait.accepted_at_unix_ms >= audit_release_time);
    assert_eq!(
        accepted_after_audit_wait.expires_at_unix_ms,
        accepted_after_audit_wait.accepted_at_unix_ms + 1_000
    );
    assert!(accepted_after_audit_wait.expires_at_unix_ms > database_unix_ms(&store).await);

    let claim_contention_now = database_unix_ms(&store).await;
    let claim_contention_delivery = delivery(
        organization_id,
        project_id,
        pipeline_id,
        expiring_trigger_id,
        1,
        "delivery-audit-contention-claim",
        "event-audit-contention-claim",
        claim_contention_now,
    );
    store
        .accept_trigger_delivery(&claim_contention_delivery)
        .await
        .unwrap();
    let (audit_lock, audit_backend_pid) = lock_audit_head(&store, organization_id).await;
    let contention_store = store.clone();
    let claim_task = tokio::spawn(async move {
        contention_store
            .claim_trigger_delivery(&claim(
                organization_id,
                expiring_trigger_id,
                "delivery-audit-contention-claim",
                "worker-audit-contention-claim",
                claim_contention_now,
            ))
            .await
    });
    wait_until_blocked_by(&store, audit_backend_pid).await;
    sqlx::query("SELECT pg_sleep(1.1)")
        .execute(store.pool())
        .await
        .unwrap();
    audit_lock.rollback().await.unwrap();
    let TriggerDeliveryClaimOutcome::Terminal(claim_after_audit_wait) =
        claim_task.await.unwrap().unwrap()
    else {
        panic!("audit contention past delivery TTL must not commit a claim")
    };
    assert_eq!(
        claim_after_audit_wait.status,
        TriggerDeliveryStatus::DeadLettered
    );
    assert!(claim_after_audit_wait.claim_owner.is_none());

    let failure_contention_now = database_unix_ms(&store).await;
    let failure_contention_delivery = delivery(
        organization_id,
        project_id,
        pipeline_id,
        trigger_id,
        1,
        "delivery-audit-contention-failure",
        "event-audit-contention-failure",
        failure_contention_now,
    );
    store
        .accept_trigger_delivery(&failure_contention_delivery)
        .await
        .unwrap();
    let failure_contention_claim = match store
        .claim_trigger_delivery(&TriggerDeliveryClaimRequest {
            organization_id,
            trigger_id,
            delivery_id: "delivery-audit-contention-failure".to_owned(),
            worker_identity: "worker-audit-contention-failure".to_owned(),
            now_unix_ms: failure_contention_now,
            lease_expires_at_unix_ms: failure_contention_now + 1_000,
        })
        .await
        .unwrap()
    {
        TriggerDeliveryClaimOutcome::Claimed(delivery) => delivery,
        other => panic!("unexpected audit-contention failure claim: {other:?}"),
    };
    let (audit_lock, audit_backend_pid) = lock_audit_head(&store, organization_id).await;
    let contention_store = store.clone();
    let failure_task = tokio::spawn(async move {
        contention_store
            .fail_trigger_delivery(&TriggerDeliveryFailureRequest {
                organization_id,
                trigger_id,
                delivery_id: "delivery-audit-contention-failure".to_owned(),
                worker_identity: "worker-audit-contention-failure".to_owned(),
                claim_fence: failure_contention_claim.claim_fence,
                now_unix_ms: failure_contention_now,
                retry_at_unix_ms: failure_contention_now + 1_000,
                retryable: true,
                reason: "audit-head contention".to_owned(),
            })
            .await
    });
    wait_until_blocked_by(&store, audit_backend_pid).await;
    sqlx::query("SELECT pg_sleep(1.1)")
        .execute(store.pool())
        .await
        .unwrap();
    audit_lock.rollback().await.unwrap();
    let TriggerDeliveryFailure::LeaseLost(failure_after_audit_wait) =
        failure_task.await.unwrap().unwrap()
    else {
        panic!("audit contention past the claim lease must return typed lease loss")
    };
    assert_eq!(failure_after_audit_wait.attempt_count, 0);

    let wall_now = database_unix_ms(&store).await;
    let expires_during_admission = delivery(
        organization_id,
        project_id,
        pipeline_id,
        expiring_trigger_id,
        1,
        "delivery-expires-during-admission",
        "event-expires-during-admission",
        wall_now,
    );
    match store
        .accept_trigger_delivery(&expires_during_admission)
        .await
        .unwrap()
    {
        TriggerDeliveryAdmission::Created(_) => {}
        other => panic!("unexpected expiring delivery capture: {other:?}"),
    }
    let expiring_claim = match store
        .claim_trigger_delivery(&claim(
            organization_id,
            expiring_trigger_id,
            "delivery-expires-during-admission",
            "worker-expiring-admission",
            wall_now,
        ))
        .await
        .unwrap()
    {
        TriggerDeliveryClaimOutcome::Claimed(delivery) => delivery,
        other => panic!("unexpected expiring delivery claim: {other:?}"),
    };
    let expiring_dag = dag(
        organization_id,
        project_id,
        pipeline_id,
        "trigger-delivery-expiring-admission",
    );
    sqlx::query(
        "CREATE OR REPLACE FUNCTION trig001_delay_ttl_build_insert()
         RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN
           IF NEW.idempotency_key = 'trigger-delivery-expiring-admission' THEN
             PERFORM pg_sleep(1.1);
           END IF;
           RETURN NEW;
         END
         $$",
    )
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER trig001_delay_ttl_build_insert
         BEFORE INSERT ON builds
         FOR EACH ROW EXECUTE FUNCTION trig001_delay_ttl_build_insert()",
    )
    .execute(store.pool())
    .await
    .unwrap();
    let expired = store
        .admit_trigger_delivery_dag(
            &TriggerDeliveryDagAdmissionRequest {
                organization_id,
                trigger_id: expiring_trigger_id,
                delivery_id: "delivery-expires-during-admission".to_owned(),
                worker_identity: "worker-expiring-admission".to_owned(),
                claim_fence: expiring_claim.claim_fence,
            },
            &expiring_dag,
        )
        .await
        .unwrap();
    sqlx::query("DROP TRIGGER trig001_delay_ttl_build_insert ON builds")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION trig001_delay_ttl_build_insert()")
        .execute(store.pool())
        .await
        .unwrap();
    let TriggerDeliveryDagAdmission::DeadLettered(expired) = expired else {
        panic!("expired trigger must not admit a DAG")
    };
    assert_eq!(expired.status, TriggerDeliveryStatus::DeadLettered);
    assert_eq!(expired.attempt_count, 1);
    assert!(expired.build_id.is_none());
    assert_eq!(
        expired.terminal_reason.as_deref(),
        Some("delivery expired before atomic DAG admission")
    );
    assert!(
        store
            .dag_replay_binding(
                organization_id,
                project_id,
                "trigger-delivery-expiring-admission",
            )
            .await
            .unwrap()
            .is_none(),
        "expired admission must leave no runnable or replayable build"
    );

    let expired_claim_delivery = delivery(
        organization_id,
        project_id,
        pipeline_id,
        trigger_id,
        1,
        "delivery-expired-claim-admission",
        "event-expired-claim-admission",
        wall_now - 120_000,
    );
    assert!(matches!(
        store
            .accept_trigger_delivery(&expired_claim_delivery)
            .await
            .unwrap(),
        TriggerDeliveryAdmission::Created(_)
    ));
    let expired_claim = match store
        .claim_trigger_delivery(&TriggerDeliveryClaimRequest {
            organization_id,
            trigger_id,
            delivery_id: "delivery-expired-claim-admission".to_owned(),
            worker_identity: "worker-expired-claim-admission".to_owned(),
            now_unix_ms: wall_now,
            lease_expires_at_unix_ms: wall_now + 1,
        })
        .await
        .unwrap()
    {
        TriggerDeliveryClaimOutcome::Claimed(delivery) => delivery,
        other => panic!("unexpected expired-claim fixture: {other:?}"),
    };
    sqlx::query("SELECT pg_sleep(0.01)")
        .execute(store.pool())
        .await
        .unwrap();
    let expired_claim_dag = dag(
        organization_id,
        project_id,
        pipeline_id,
        "trigger-delivery-expired-claim-admission",
    );
    let TriggerDeliveryDagAdmission::LeaseLost(lease_lost) = store
        .admit_trigger_delivery_dag(
            &TriggerDeliveryDagAdmissionRequest {
                organization_id,
                trigger_id,
                delivery_id: "delivery-expired-claim-admission".to_owned(),
                worker_identity: "worker-expired-claim-admission".to_owned(),
                claim_fence: expired_claim.claim_fence,
            },
            &expired_claim_dag,
        )
        .await
        .unwrap()
    else {
        panic!("an already-expired claim must return the typed lease-lost outcome")
    };
    assert_eq!(lease_lost.attempt_count, 0);
    let expired_failure = store
        .fail_trigger_delivery(&TriggerDeliveryFailureRequest {
            organization_id,
            trigger_id,
            delivery_id: "delivery-expired-claim-admission".to_owned(),
            worker_identity: "worker-expired-claim-admission".to_owned(),
            claim_fence: expired_claim.claim_fence,
            now_unix_ms: wall_now,
            retry_at_unix_ms: wall_now + 1_000,
            retryable: true,
            reason: "stale worker failure".to_owned(),
        })
        .await
        .unwrap();
    let TriggerDeliveryFailure::LeaseLost(expired_failure) = expired_failure else {
        panic!("an expired claim cannot spend failure accounting")
    };
    assert_eq!(expired_failure.attempt_count, 0);
    assert!(
        store
            .dag_replay_binding(
                organization_id,
                project_id,
                "trigger-delivery-expired-claim-admission",
            )
            .await
            .unwrap()
            .is_none(),
        "expired claim admission must roll back every staged DAG row"
    );
    assert!(
        store
            .due_trigger_deliveries(organization_id, wall_now + 1_000, 128)
            .await
            .unwrap()
            .iter()
            .any(|delivery| delivery.delivery_id == "delivery-expired-claim-admission"),
        "claim expiry leaves the durable delivery retryable by a newly fenced worker"
    );

    sqlx::query("DROP TRIGGER IF EXISTS trig001_delay_build_insert ON builds")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query(
        "CREATE OR REPLACE FUNCTION trig001_delay_build_insert()
         RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN
           IF NEW.idempotency_key = 'trigger-delivery-claim-expires-during-admission' THEN
             PERFORM pg_sleep(1);
           END IF;
           RETURN NEW;
         END
         $$",
    )
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER trig001_delay_build_insert
         BEFORE INSERT ON builds
         FOR EACH ROW EXECUTE FUNCTION trig001_delay_build_insert()",
    )
    .execute(store.pool())
    .await
    .unwrap();
    let lease_race_now = sqlx::query_scalar::<_, i64>(
        "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    let lease_race_delivery = delivery(
        organization_id,
        project_id,
        pipeline_id,
        trigger_id,
        1,
        "delivery-claim-expires-during-admission",
        "event-claim-expires-during-admission",
        lease_race_now - 1_000,
    );
    store
        .accept_trigger_delivery(&lease_race_delivery)
        .await
        .unwrap();
    let lease_race_claim = match store
        .claim_trigger_delivery(&TriggerDeliveryClaimRequest {
            organization_id,
            trigger_id,
            delivery_id: "delivery-claim-expires-during-admission".to_owned(),
            worker_identity: "worker-claim-expires-during-admission".to_owned(),
            now_unix_ms: lease_race_now,
            lease_expires_at_unix_ms: lease_race_now + 500,
        })
        .await
        .unwrap()
    {
        TriggerDeliveryClaimOutcome::Claimed(delivery) => delivery,
        other => panic!("unexpected lease-race claim: {other:?}"),
    };
    let lease_race_result = store
        .admit_trigger_delivery_dag(
            &TriggerDeliveryDagAdmissionRequest {
                organization_id,
                trigger_id,
                delivery_id: "delivery-claim-expires-during-admission".to_owned(),
                worker_identity: "worker-claim-expires-during-admission".to_owned(),
                claim_fence: lease_race_claim.claim_fence,
            },
            &dag(
                organization_id,
                project_id,
                pipeline_id,
                "trigger-delivery-claim-expires-during-admission",
            ),
        )
        .await;
    sqlx::query("DROP TRIGGER trig001_delay_build_insert ON builds")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION trig001_delay_build_insert()")
        .execute(store.pool())
        .await
        .unwrap();
    let TriggerDeliveryDagAdmission::LeaseLost(lease_lost) = lease_race_result.unwrap() else {
        panic!("mid-admission lease expiry must return a non-failure-accounting outcome")
    };
    assert_eq!(lease_lost.status, TriggerDeliveryStatus::Pending);
    assert_eq!(lease_lost.attempt_count, 0);
    assert!(
        store
            .dag_replay_binding(
                organization_id,
                project_id,
                "trigger-delivery-claim-expires-during-admission",
            )
            .await
            .unwrap()
            .is_none(),
        "a claim that expires during DAG staging must leave no persisted DAG rows"
    );

    let active_active = delivery(
        organization_id,
        project_id,
        pipeline_id,
        trigger_id,
        1,
        "delivery-active-active",
        "event-active-active",
        now,
    );
    store
        .accept_trigger_delivery(&active_active)
        .await
        .expect("capture active-active claim fixture");
    let left_claim = claim(
        organization_id,
        trigger_id,
        "delivery-active-active",
        "worker-active-left",
        now,
    );
    let right_claim = claim(
        organization_id,
        trigger_id,
        "delivery-active-active",
        "worker-active-right",
        now,
    );
    let (left, right) = tokio::join!(
        store.claim_trigger_delivery(&left_claim),
        store.claim_trigger_delivery(&right_claim)
    );
    let claims = [left.unwrap(), right.unwrap()];
    assert_eq!(
        claims
            .iter()
            .filter(|outcome| matches!(outcome, TriggerDeliveryClaimOutcome::Claimed(_)))
            .count(),
        1
    );
    assert_eq!(
        claims
            .iter()
            .filter(|outcome| matches!(outcome, TriggerDeliveryClaimOutcome::Leased(_)))
            .count(),
        1
    );

    let lock_order_delivery = delivery(
        organization_id,
        project_id,
        pipeline_id,
        trigger_id,
        1,
        "delivery-lock-order",
        "event-lock-order",
        now,
    );
    store
        .accept_trigger_delivery(&lock_order_delivery)
        .await
        .expect("capture configuration/claim lock-order fixture");
    let mut pause_for_lock_order = write.clone();
    pause_for_lock_order.expected_generation = 1;
    pause_for_lock_order.state = PipelineTriggerState::Paused;
    pause_for_lock_order.reason = "lock-order pause".to_owned();
    pause_for_lock_order.idempotency_key = "trigger-lock-order-pause".to_owned();
    pause_for_lock_order.source_generation = "source-lock-order-pause".to_owned();
    let lock_order_claim = claim(
        organization_id,
        trigger_id,
        "delivery-lock-order",
        "worker-lock-order",
        now,
    );
    let (configuration_result, claim_result) = tokio::join!(
        store.put_pipeline_trigger(&pause_for_lock_order),
        store.claim_trigger_delivery(&lock_order_claim)
    );
    assert!(matches!(
        configuration_result.unwrap(),
        TriggerPutOutcome::Revised(_)
    ));
    assert!(matches!(
        claim_result,
        Ok(TriggerDeliveryClaimOutcome::Claimed(_)) | Err(StoreError::TriggerPaused { .. })
    ));
    let mut resume_after_lock_order = write.clone();
    resume_after_lock_order.expected_generation = 2;
    resume_after_lock_order.reason = "resume after lock-order proof".to_owned();
    resume_after_lock_order.idempotency_key = "trigger-lock-order-resume".to_owned();
    resume_after_lock_order.source_generation = "source-lock-order-resume".to_owned();
    assert!(matches!(
        store
            .put_pipeline_trigger(&resume_after_lock_order)
            .await
            .unwrap(),
        TriggerPutOutcome::Revised(_)
    ));

    let disabled = store
        .transition_pipeline_operational_state(&PipelineOperationalStateTransition {
            organization_id,
            project_id,
            pipeline_id,
            expected_generation: 1,
            state: PipelineOperationalState::Disabled,
            reason: "reviewed disable".to_owned(),
            actor_subject: "operator@example.test".to_owned(),
            source_identity: "test:operator".to_owned(),
            source_generation: "disable-1".to_owned(),
            source_effective_at_unix_ms: now + 70_000,
            source_provenance_sha256: Sha256::digest(b"disable-1").into(),
            idempotency_key: "disable-1".to_owned(),
        })
        .await
        .unwrap();
    assert!(matches!(
        disabled,
        PipelineOperationalStateTransitionOutcome::Applied(_)
    ));
    assert!(matches!(
        store.accept_trigger_delivery(&input).await.unwrap(),
        TriggerDeliveryAdmission::Replayed(ref replay)
            if replay.status == TriggerDeliveryStatus::Admitted
    ));
    let denied = delivery(
        organization_id,
        project_id,
        pipeline_id,
        trigger_id,
        3,
        "delivery-disabled",
        "event-disabled",
        now + 80_000,
    );
    assert!(matches!(
        store.accept_trigger_delivery(&denied).await,
        Err(StoreError::PipelineDisabled { .. })
    ));
}

#[tokio::test]
async fn dead_letters_require_explicit_fenced_redrive_and_caller_rotation_denies_new_events() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let (organization_id, project_id, pipeline_id) = fixture(&store).await;
    let trigger_id = Uuid::new_v4();
    let write = trigger_write(
        organization_id,
        project_id,
        pipeline_id,
        trigger_id,
        0,
        TriggerKind::RemoteApi,
        PipelineTriggerState::Enabled,
        "scm:github:installation:42",
        json!({"audience": "mcloving:remote-build", "filter": {"event_kinds": ["remote"], "request_methods": ["POST"]}}),
        "remote-create",
        1,
    );
    store.put_pipeline_trigger(&write).await.unwrap();
    let now = database_unix_ms(&store).await;
    let input = remote_delivery(delivery(
        organization_id,
        project_id,
        pipeline_id,
        trigger_id,
        1,
        "dead-1",
        "dead-event-1",
        now,
    ));
    store.accept_trigger_delivery(&input).await.unwrap();
    let claimed = match store
        .claim_trigger_delivery(&claim(
            organization_id,
            trigger_id,
            "dead-1",
            "worker-dead",
            now,
        ))
        .await
        .unwrap()
    {
        TriggerDeliveryClaimOutcome::Claimed(delivery) => delivery,
        other => panic!("unexpected claim: {other:?}"),
    };
    let failed = store
        .fail_trigger_delivery(&TriggerDeliveryFailureRequest {
            organization_id,
            trigger_id,
            delivery_id: "dead-1".to_owned(),
            worker_identity: "worker-dead".to_owned(),
            claim_fence: claimed.claim_fence,
            now_unix_ms: now + 1,
            retry_at_unix_ms: now + 60_000,
            retryable: true,
            reason: "attempt budget exhausted".to_owned(),
        })
        .await
        .unwrap();
    assert!(matches!(failed, TriggerDeliveryFailure::DeadLettered(_)));

    let redrive = TriggerDeliveryRedrive {
        organization_id,
        project_id,
        pipeline_id,
        trigger_id,
        dead_letter_delivery_id: "dead-1".to_owned(),
        new_delivery_id: "redrive-1".to_owned(),
        new_event_id: "redrive-event-1".to_owned(),
        actor_subject: "recovery@example.test".to_owned(),
        accepted_at_unix_ms: now + 10 * 60_000,
    };
    let database_before_redrive = database_unix_ms(&store).await;
    let (left, right) = tokio::join!(
        store.redrive_trigger_delivery(&redrive),
        store.redrive_trigger_delivery(&redrive)
    );
    let database_after_redrive = database_unix_ms(&store).await;
    let redrive_outcomes = [left.unwrap(), right.unwrap()];
    assert_eq!(
        redrive_outcomes
            .iter()
            .filter(|outcome| matches!(outcome, TriggerDeliveryAdmission::Created(_)))
            .count(),
        1
    );
    assert_eq!(
        redrive_outcomes
            .iter()
            .filter(|outcome| matches!(outcome, TriggerDeliveryAdmission::Replayed(_)))
            .count(),
        1
    );
    let redriven = redrive_outcomes
        .into_iter()
        .find_map(|outcome| match outcome {
            TriggerDeliveryAdmission::Created(delivery) => Some(delivery),
            TriggerDeliveryAdmission::Replayed(_) => None,
        })
        .expect("one concurrent first redrive creates the delivery");
    assert_eq!(redriven.status, TriggerDeliveryStatus::Pending);
    assert!(redriven.accepted_at_unix_ms >= database_before_redrive);
    assert!(redriven.accepted_at_unix_ms <= database_after_redrive);
    assert_eq!(
        redriven.expires_at_unix_ms,
        redriven.accepted_at_unix_ms + 7_200_000
    );
    assert_eq!(redriven.redrive_of_delivery_id.as_deref(), Some("dead-1"));
    assert_eq!(redriven.redrive_ordinal, Some(1));
    assert!(matches!(
        store.redrive_trigger_delivery(&redrive).await.unwrap(),
        TriggerDeliveryAdmission::Replayed(_)
    ));

    let second_dead_letter = remote_delivery(delivery(
        organization_id,
        project_id,
        pipeline_id,
        trigger_id,
        1,
        "dead-2",
        "dead-event-2",
        now + 3,
    ));
    store
        .accept_trigger_delivery(&second_dead_letter)
        .await
        .expect("capture divergent redrive source");
    let second_claim = match store
        .claim_trigger_delivery(&claim(
            organization_id,
            trigger_id,
            "dead-2",
            "worker-dead-2",
            now + 3,
        ))
        .await
        .unwrap()
    {
        TriggerDeliveryClaimOutcome::Claimed(delivery) => delivery,
        other => panic!("unexpected second dead-letter claim: {other:?}"),
    };
    assert!(matches!(
        store
            .fail_trigger_delivery(&TriggerDeliveryFailureRequest {
                organization_id,
                trigger_id,
                delivery_id: "dead-2".to_owned(),
                worker_identity: "worker-dead-2".to_owned(),
                claim_fence: second_claim.claim_fence,
                now_unix_ms: now + 4,
                retry_at_unix_ms: now + 60_000,
                retryable: true,
                reason: "second attempt budget exhausted".to_owned(),
            })
            .await
            .unwrap(),
        TriggerDeliveryFailure::DeadLettered(_)
    ));
    let conflict_from_first = TriggerDeliveryRedrive {
        dead_letter_delivery_id: "dead-1".to_owned(),
        new_delivery_id: "redrive-conflicting-id".to_owned(),
        new_event_id: "redrive-conflicting-event".to_owned(),
        accepted_at_unix_ms: now + 5,
        ..redrive.clone()
    };
    let conflict_from_second = TriggerDeliveryRedrive {
        dead_letter_delivery_id: "dead-2".to_owned(),
        ..conflict_from_first.clone()
    };
    let (first_source, second_source) = tokio::join!(
        store.redrive_trigger_delivery(&conflict_from_first),
        store.redrive_trigger_delivery(&conflict_from_second)
    );
    let conflicting_redrives = [first_source, second_source];
    assert_eq!(
        conflicting_redrives
            .iter()
            .filter(|outcome| matches!(outcome, Ok(TriggerDeliveryAdmission::Created(_))))
            .count(),
        1
    );
    assert_eq!(
        conflicting_redrives
            .iter()
            .filter(|outcome| matches!(outcome, Err(StoreError::TriggerIngressConflict(_))))
            .count(),
        1
    );

    let paused = trigger_write(
        organization_id,
        project_id,
        pipeline_id,
        trigger_id,
        1,
        TriggerKind::RemoteApi,
        PipelineTriggerState::Paused,
        "scm:github:installation:42",
        json!({"audience": "mcloving:remote-build", "filter": {"event_kinds": ["remote"], "request_methods": ["POST"]}}),
        "remote-pause",
        2,
    );
    assert!(matches!(
        store.put_pipeline_trigger(&paused).await.unwrap(),
        TriggerPutOutcome::Revised(_)
    ));
    let paused_delivery = remote_delivery(delivery(
        organization_id,
        project_id,
        pipeline_id,
        trigger_id,
        2,
        "paused-delivery",
        "paused-event",
        now + 3,
    ));
    assert!(matches!(
        store.accept_trigger_delivery(&paused_delivery).await,
        Err(StoreError::TriggerPaused { generation: 2, .. })
    ));
    let mut resumed = trigger_write(
        organization_id,
        project_id,
        pipeline_id,
        trigger_id,
        2,
        TriggerKind::RemoteApi,
        PipelineTriggerState::Enabled,
        "remote:caller:rotated",
        json!({"audience": "mcloving:remote-build", "filter": {"event_kinds": ["remote"], "request_methods": ["POST"]}}),
        "remote-resume-rotate",
        2,
    );
    resumed.source_generation = "remote-revocation-3".to_owned();
    assert!(matches!(
        store.put_pipeline_trigger(&resumed).await.unwrap(),
        TriggerPutOutcome::Revised(_)
    ));
    let mut revoked = remote_delivery(delivery(
        organization_id,
        project_id,
        pipeline_id,
        trigger_id,
        3,
        "revoked-delivery",
        "revoked-event",
        now + 4,
    ));
    revoked.caller_identity = "scm:github:installation:42".to_owned();
    assert!(matches!(
        store.accept_trigger_delivery(&revoked).await,
        Err(StoreError::TriggerIngressConflict(_))
    ));
    assert!(matches!(
        store
            .export_quiesced_trigger_state(
                organization_id,
                project_id,
                pipeline_id,
                trigger_id,
                "handoff@example.test",
            )
            .await,
        Err(StoreError::TriggerIngressConflict(_))
    ));
    let handoff_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let mut expired_handoff_claim = remote_delivery(delivery(
        organization_id,
        project_id,
        pipeline_id,
        trigger_id,
        3,
        "expired-handoff-claim",
        "expired-handoff-event",
        handoff_now - 120_000,
    ));
    expired_handoff_claim.caller_identity = "remote:caller:rotated".to_owned();
    store
        .accept_trigger_delivery(&expired_handoff_claim)
        .await
        .expect("capture expired handoff claim fixture");
    assert!(matches!(
        store
            .claim_trigger_delivery(&TriggerDeliveryClaimRequest {
                organization_id,
                trigger_id,
                delivery_id: "expired-handoff-claim".to_owned(),
                worker_identity: "crashed-handoff-worker".to_owned(),
                now_unix_ms: handoff_now,
                lease_expires_at_unix_ms: handoff_now + 1,
            })
            .await
            .unwrap(),
        TriggerDeliveryClaimOutcome::Claimed(_)
    ));
    sqlx::query("SELECT pg_sleep(0.01)")
        .execute(store.pool())
        .await
        .unwrap();
    let configuration = json!({"audience": "mcloving:remote-build", "filter": {"event_kinds": ["remote"], "request_methods": ["POST"]}});
    let pause_for_handoff = trigger_write(
        organization_id,
        project_id,
        pipeline_id,
        trigger_id,
        3,
        TriggerKind::RemoteApi,
        PipelineTriggerState::Paused,
        "remote:caller:rotated",
        configuration.clone(),
        "remote-handoff-pause",
        2,
    );
    store
        .put_pipeline_trigger(&pause_for_handoff)
        .await
        .unwrap();
    let handoff = store
        .export_quiesced_trigger_state(
            organization_id,
            project_id,
            pipeline_id,
            trigger_id,
            "handoff@example.test",
        )
        .await
        .expect("export complete paused trigger ledger");
    let trusted_handoff_audit_hash = handoff.audit_event_hash;
    verify_trigger_transfer_snapshot(&handoff, trusted_handoff_audit_hash)
        .expect("verify handoff snapshot against independently retained audit hash");
    assert!(handoff.audit_sequence > 0);
    assert_ne!(handoff.audit_event_hash, [0; 32]);
    assert!(handoff.versions.iter().all(|version| {
        version.audit_sequence > 0
            && version.audit_event_hash != [0; 32]
            && !version.actor_subject.is_empty()
            && !version.reason.is_empty()
            && !version.idempotency_key.is_empty()
    }));
    assert!(
        handoff.deliveries.iter().all(|delivery| {
            delivery.audit_sequence > 0 && delivery.audit_event_hash != [0; 32]
        })
    );
    assert!(
        handoff
            .deliveries
            .iter()
            .any(|delivery| delivery.status == TriggerDeliveryStatus::DeadLettered)
    );
    assert!(
        handoff
            .deliveries
            .iter()
            .any(|delivery| { delivery.redrive_of_delivery_id.as_deref() == Some("dead-1") })
    );
    let reaped_handoff_claim = handoff
        .deliveries
        .iter()
        .find(|delivery| delivery.delivery_id == "expired-handoff-claim")
        .expect("expired claimed delivery remains in the exported ledger");
    assert!(reaped_handoff_claim.claim_owner.is_none());
    assert!(reaped_handoff_claim.claim_expires_at_unix_ms.is_none());
    let mut tampered = handoff.clone();
    tampered.deliveries[0].event_id.push_str("-substituted");
    let tampered_ledger = compute_trigger_transfer_snapshot_ledger_digest(&tampered)
        .expect("attacker recomputes the exported ledger digest");
    tampered.handoff_audit_event.payload["ledger_sha256"] = json!(hex::encode(tampered_ledger));
    tampered.handoff_audit_event.event_hash =
        compute_audit_event_hash(tampered.organization_id, &tampered.handoff_audit_event)
            .expect("attacker recomputes the self-contained audit event hash");
    tampered.audit_event_hash = tampered.handoff_audit_event.event_hash;
    tampered.state_sha256 = compute_trigger_transfer_snapshot_digest(&tampered)
        .expect("attacker can recompute the unkeyed snapshot digest");
    assert!(
        matches!(
            verify_trigger_transfer_snapshot(&tampered, trusted_handoff_audit_hash),
            Err(StoreError::TriggerIngressConflict(_))
        ),
        "the independent audit anchor rejects a fully recomputed substituted snapshot"
    );
    let mut provenance_stripped = handoff.clone();
    provenance_stripped.deliveries[0].audit_sequence = 0;
    assert!(matches!(
        verify_trigger_transfer_snapshot(&provenance_stripped, trusted_handoff_audit_hash),
        Err(StoreError::TriggerIngressConflict(_))
    ));

    let resume_after_handoff = trigger_write(
        organization_id,
        project_id,
        pipeline_id,
        trigger_id,
        4,
        TriggerKind::RemoteApi,
        PipelineTriggerState::Enabled,
        "remote:caller:rotated",
        configuration.clone(),
        "remote-handoff-resume",
        2,
    );
    store
        .put_pipeline_trigger(&resume_after_handoff)
        .await
        .unwrap();
    let rollback_pause = trigger_write(
        organization_id,
        project_id,
        pipeline_id,
        trigger_id,
        5,
        TriggerKind::RemoteApi,
        PipelineTriggerState::Paused,
        "remote:caller:rotated",
        configuration,
        "remote-rollback-restore",
        2,
    );
    store.put_pipeline_trigger(&rollback_pause).await.unwrap();
    let restored = store
        .export_quiesced_trigger_state(
            organization_id,
            project_id,
            pipeline_id,
            trigger_id,
            "rollback@example.test",
        )
        .await
        .expect("export rollback-restored trigger ledger");
    verify_trigger_transfer_snapshot(&restored, restored.audit_event_hash)
        .expect("verify rollback snapshot against its retained audit hash");
    let before = handoff.versions.last().unwrap();
    let after = restored.versions.last().unwrap();
    assert_eq!(after.kind, before.kind);
    assert_eq!(after.state, before.state);
    assert_eq!(after.implementation_sha256, before.implementation_sha256);
    assert_eq!(after.configuration_sha256, before.configuration_sha256);
    assert_eq!(after.filter_sha256, before.filter_sha256);
    assert_eq!(after.event_source_identity, before.event_source_identity);
    assert_eq!(after.configuration, before.configuration);
    assert_eq!(restored.deliveries, handoff.deliveries);

    let foreign_organization = Uuid::new_v4();
    let foreign_project = Uuid::new_v4();
    store
        .create_project(
            foreign_organization,
            &format!("trigger-foreign-{foreign_organization}"),
            foreign_project,
            "trigger-foreign",
        )
        .await
        .expect("create foreign trigger tenant");
    let mut tx = store
        .pool()
        .begin()
        .await
        .expect("open foreign transaction");
    sqlx::query("SET LOCAL ROLE mcloving_tenant")
        .execute(&mut *tx)
        .await
        .expect("use constrained runtime role");
    sqlx::query("SELECT set_config('mcloving.organization_id', $1, true)")
        .bind(foreign_organization.to_string())
        .execute(&mut *tx)
        .await
        .expect("scope foreign tenant transaction");
    let visible: i64 =
        sqlx::query_scalar("SELECT count(*) FROM trigger_deliveries WHERE organization_id = $1")
            .bind(organization_id)
            .fetch_one(&mut *tx)
            .await
            .expect("query forced-RLS trigger ledger");
    assert_eq!(visible, 0, "foreign tenant cannot read trigger deliveries");
    tx.rollback().await.unwrap();
    assert!(
        sqlx::query(
            "UPDATE pipeline_trigger_versions SET state = 'enabled'
             WHERE organization_id = $1 AND trigger_id = $2 AND generation = 6",
        )
        .bind(organization_id)
        .bind(trigger_id)
        .execute(store.pool())
        .await
        .is_err(),
        "append-only trigger version rejects privileged mutation"
    );
}

fn digest_hex(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

fn schedule_configuration(expression: &str, first_slot_unix_ms: i64) -> Value {
    let resolved_slots = json!([
        first_slot_unix_ms,
        first_slot_unix_ms + 1_000,
        first_slot_unix_ms + 2_000
    ]);
    let resolved_slots_sha256 = digest_hex(&serde_json::to_vec(&resolved_slots).unwrap());
    json!({
        "timezone": "America/Chicago",
        "calendar": "gregorian:tzdata-2026a",
        "expression": expression,
        "schedule_identity_sha256": digest_hex(b"schedule-identity"),
        "resolver_implementation_sha256": digest_hex(b"resolver-implementation"),
        "resolved_slots_sha256": resolved_slots_sha256,
        "resolved_slots_unix_ms": resolved_slots,
        "jenkins_hash_algorithm_version": "jenkins-core-2.516.1:cron-hash-v1",
        "jenkins_full_item_name": "folder/nightly",
        "jenkins_hash_inputs_sha256": digest_hex(b"jenkins-hash-inputs"),
        "filter": {"event_kinds": ["schedule"]},
    })
}

#[tokio::test]
async fn schedule_identity_watermark_restart_and_generation_changes_fail_closed() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let (organization_id, project_id, pipeline_id) = fixture(&store).await;
    let trigger_id = Uuid::new_v4();
    let slot1 = database_unix_ms(&store).await;
    let incomplete = schedule_configuration("H H * * *", slot1);
    let incomplete = trigger_write(
        organization_id,
        project_id,
        pipeline_id,
        trigger_id,
        0,
        TriggerKind::Schedule,
        PipelineTriggerState::Enabled,
        "scheduler:mcloving:primary",
        incomplete,
        "schedule-incomplete",
        3,
    );
    assert!(matches!(
        store.put_pipeline_trigger(&incomplete).await,
        Err(StoreError::InvalidTriggerIngress(_))
    ));

    let configuration = schedule_configuration("0 2 * * *", slot1);
    let write = trigger_write(
        organization_id,
        project_id,
        pipeline_id,
        trigger_id,
        0,
        TriggerKind::Schedule,
        PipelineTriggerState::Enabled,
        "scheduler:mcloving:primary",
        configuration,
        "schedule-create",
        3,
    );
    store.put_pipeline_trigger(&write).await.unwrap();
    let identity: [u8; 32] = Sha256::digest(b"schedule-identity").into();
    let schedule_delivery = |delivery_id: &str,
                             event_id: &str,
                             expected: Option<i64>,
                             slot: i64,
                             schedule_identity_sha256: [u8; 32]| {
        let canonical_payload = json!({
            "event_kind": "schedule",
            "event_time_unix_ms": slot,
            "payload": {
                "timezone": "America/Chicago",
                "calendar": "gregorian:tzdata-2026a",
                "expression": "0 2 * * *",
                "schedule_identity_sha256": hex::encode(schedule_identity_sha256),
                "resolved_slot_unix_ms": slot,
                "expected_last_resolved_slot_unix_ms": expected,
            },
        });
        NewTriggerDelivery {
            organization_id,
            project_id,
            pipeline_id,
            trigger_id,
            expected_trigger_generation: 1,
            delivery_id: delivery_id.to_owned(),
            event_id: event_id.to_owned(),
            event_kind: "schedule".to_owned(),
            caller_identity: "scheduler:mcloving:primary".to_owned(),
            payload_sha256: Sha256::digest(
                serde_json::to_vec(&canonical_payload)
                    .expect("serialize schedule delivery")
                    .as_slice(),
            )
            .into(),
            canonical_payload,
            parameters: json!({}),
            requested_platform: "linux".to_owned(),
            requested_trust_pool: "trusted-linux".to_owned(),
            event_time_unix_ms: slot,
            accepted_at_unix_ms: slot,
            schedule_slot: Some(TriggerScheduleSlot {
                timezone: "America/Chicago".to_owned(),
                calendar: "gregorian:tzdata-2026a".to_owned(),
                expression: "0 2 * * *".to_owned(),
                schedule_identity_sha256,
                expected_last_resolved_slot_unix_ms: expected,
                resolved_slot_unix_ms: slot,
            }),
        }
    };
    let first = schedule_delivery("schedule-slot-1", "schedule-event-1", None, slot1, identity);
    assert!(matches!(
        store.accept_trigger_delivery(&first).await.unwrap(),
        TriggerDeliveryAdmission::Created(_)
    ));
    assert!(matches!(
        store.accept_trigger_delivery(&first).await.unwrap(),
        TriggerDeliveryAdmission::Replayed(_)
    ));
    let stale = schedule_delivery(
        "schedule-slot-stale",
        "schedule-event-stale",
        None,
        slot1 - 60_000,
        identity,
    );
    assert!(matches!(
        store.accept_trigger_delivery(&stale).await,
        Err(StoreError::TriggerIngressConflict(_))
    ));
    let restarted = Store::new(store.pool().clone());
    let restored = restarted
        .trigger_schedule_watermark(organization_id, trigger_id, 1)
        .await
        .unwrap()
        .expect("watermark survives controller restart");
    assert_eq!(restored.last_resolved_slot_unix_ms, Some(slot1));
    let second = schedule_delivery(
        "schedule-slot-2",
        "schedule-event-2",
        Some(slot1),
        slot1 + 1_000,
        identity,
    );
    assert!(matches!(
        restarted.accept_trigger_delivery(&second).await.unwrap(),
        TriggerDeliveryAdmission::Created(_)
    ));
    let substituted = schedule_delivery(
        "schedule-slot-substituted",
        "schedule-event-substituted",
        Some(slot1 + 1_000),
        slot1 + 2_000,
        Sha256::digest(b"substituted").into(),
    );
    assert!(matches!(
        restarted.accept_trigger_delivery(&substituted).await,
        Err(StoreError::TriggerIngressConflict(_))
    ));
    let final_watermark = restarted
        .trigger_schedule_watermark(organization_id, trigger_id, 1)
        .await
        .unwrap()
        .expect("schedule watermark remains readable");
    assert_eq!(
        final_watermark.last_resolved_slot_unix_ms,
        Some(slot1 + 1_000)
    );
    assert!(
        sqlx::query(
            "UPDATE trigger_schedule_watermarks
             SET last_resolved_slot_unix_ms = $4
             WHERE organization_id = $1 AND trigger_id = $2
               AND trigger_generation = $3",
        )
        .bind(organization_id)
        .bind(trigger_id)
        .bind(1_i64)
        .bind(slot1)
        .execute(store.pool())
        .await
        .is_err(),
        "database guard rejects privileged schedule watermark rollback"
    );

    let paused = trigger_write(
        organization_id,
        project_id,
        pipeline_id,
        trigger_id,
        1,
        TriggerKind::Schedule,
        PipelineTriggerState::Paused,
        "scheduler:mcloving:primary",
        schedule_configuration("0 2 * * *", slot1),
        "schedule-handoff-pause",
        3,
    );
    store.put_pipeline_trigger(&paused).await.unwrap();
    let handoff = store
        .export_quiesced_trigger_state(
            organization_id,
            project_id,
            pipeline_id,
            trigger_id,
            "schedule-handoff@example.test",
        )
        .await
        .expect("export schedule handoff with exact watermark lineage");
    let trusted_schedule_audit_hash = handoff.audit_event_hash;
    verify_trigger_transfer_snapshot(&handoff, trusted_schedule_audit_hash)
        .expect("verify schedule handoff watermark lineage");
    let mut stripped_link = handoff.clone();
    stripped_link.schedule_watermarks[0].last_delivery_id = None;
    assert!(matches!(
        verify_trigger_transfer_snapshot(&stripped_link, trusted_schedule_audit_hash),
        Err(StoreError::TriggerIngressConflict(_))
    ));
    let mut substituted_link = handoff.clone();
    substituted_link.schedule_watermarks[0].last_delivery_id = Some("schedule-slot-1".to_owned());
    assert!(matches!(
        verify_trigger_transfer_snapshot(&substituted_link, trusted_schedule_audit_hash),
        Err(StoreError::TriggerIngressConflict(_))
    ));
}

#[tokio::test]
async fn upstream_identity_status_filters_and_unimplemented_plugin_classes_fail_closed() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let (organization_id, project_id, pipeline_id) = fixture(&store).await;
    let trigger_id = Uuid::new_v4();
    let upstream_pipeline_id = Uuid::new_v4();
    let upstream = trigger_write(
        organization_id,
        project_id,
        pipeline_id,
        trigger_id,
        0,
        TriggerKind::Upstream,
        PipelineTriggerState::Enabled,
        "controller:upstream-events",
        json!({
            "upstream_pipeline_id": upstream_pipeline_id,
            "filter": {"event_kinds": ["upstream"], "statuses": ["succeeded"]},
        }),
        "upstream-create",
        3,
    );
    store.put_pipeline_trigger(&upstream).await.unwrap();
    let now = database_unix_ms(&store).await;
    let upstream_delivery = |delivery_id: &str, event_id: &str, status: &str| {
        let canonical_payload = json!({
            "event_kind": "upstream",
            "event_time_unix_ms": now,
            "payload": {
                "upstream_pipeline_id": upstream_pipeline_id,
                "upstream_build_id": Uuid::new_v4(),
                "status": status,
            },
        });
        NewTriggerDelivery {
            organization_id,
            project_id,
            pipeline_id,
            trigger_id,
            expected_trigger_generation: 1,
            delivery_id: delivery_id.to_owned(),
            event_id: event_id.to_owned(),
            event_kind: "upstream".to_owned(),
            caller_identity: "controller:upstream-events".to_owned(),
            payload_sha256: Sha256::digest(
                serde_json::to_vec(&canonical_payload)
                    .expect("serialize upstream event")
                    .as_slice(),
            )
            .into(),
            canonical_payload,
            parameters: json!({}),
            requested_platform: "linux".to_owned(),
            requested_trust_pool: "trusted-linux".to_owned(),
            event_time_unix_ms: now,
            accepted_at_unix_ms: now,
            schedule_slot: None,
        }
    };
    assert!(matches!(
        store
            .accept_trigger_delivery(&upstream_delivery(
                "upstream-success",
                "upstream-event-success",
                "succeeded",
            ))
            .await
            .unwrap(),
        TriggerDeliveryAdmission::Created(_)
    ));
    assert!(matches!(
        store
            .accept_trigger_delivery(&upstream_delivery(
                "upstream-failure",
                "upstream-event-failure",
                "failed",
            ))
            .await,
        Err(StoreError::TriggerIngressConflict(_))
    ));

    let plugin = trigger_write(
        organization_id,
        project_id,
        pipeline_id,
        Uuid::new_v4(),
        0,
        TriggerKind::Plugin,
        PipelineTriggerState::Enabled,
        "plugin:generic-webhook",
        json!({"plugin_source_type": "generic-webhook", "filter": {}}),
        "plugin-unimplemented",
        3,
    );
    assert!(matches!(
        store.put_pipeline_trigger(&plugin).await,
        Err(StoreError::InvalidTriggerIngress(_))
    ));
}
