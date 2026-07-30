use std::sync::Arc;
use std::time::Duration;

use mcloving_controller_store::{
    AgentCancellationCompletion, AgentCancellationDisposition, AgentCancellationOutcome,
    AgentReconciliationDisposition, ClaimRequest, DagDependency, DagNodeKind, DependencyCondition,
    EffectClass, EffectStatus, JunitLimits, MAX_OBJECT_RETENTION_SECONDS, NewAuditEvent, NewBuild,
    NewCredentialGrant, NewDagBuild, NewDagNode, NewEnvironmentApproval, NewLogChunk, ObjectKind,
    ObjectStatus, ReconciliationTrustPoolAuthorization, RetryDecision, Store, StoreError,
    TerminalOutcome, TestOutcome, TestReportSource, WaitReason, parse_junit, verify_audit_page,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use uuid::Uuid;

async fn test_store() -> Option<Store> {
    let url = std::env::var("MCLOVING_TEST_DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .expect("connect to the explicitly configured PostgreSQL test database");
    let store = Store::new(pool);
    store.migrate().await.expect("install controller schema");
    Some(store)
}

fn dag_node(
    node_key: &str,
    kind: DagNodeKind,
    dependencies: Vec<DagDependency>,
    platform: &str,
    capability: &str,
) -> NewDagNode {
    NewDagNode {
        node_key: node_key.to_owned(),
        kind,
        dependencies,
        required_capabilities: vec![capability.to_owned()],
        required_platform: platform.to_owned(),
        required_trust_pool: "trusted".to_owned(),
        priority: 0,
        execution_spec: json!({"program": "true", "node": node_key}),
        fail_fast: false,
        max_attempts: 1,
    }
}

fn dag_claim(
    organization_id: Uuid,
    agent_id: &str,
    platform: &str,
    capability: &str,
) -> ClaimRequest {
    ClaimRequest {
        organization_id,
        scheduler_id: format!("scheduler-{agent_id}"),
        agent_id: agent_id.to_owned(),
        capabilities: vec![format!("platform:{platform}"), capability.to_owned()],
        trust_pool: "trusted".to_owned(),
        lease_seconds: 30,
        fairness_seed: 0,
    }
}

async fn run_dag_claim(store: &Store, claim: &mcloving_controller_store::ClaimedAttempt) {
    assert!(
        store
            .accept_offer(
                claim.organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                &claim.agent_id,
            )
            .await
            .expect("accept DAG offer")
    );
    assert!(
        store
            .mark_attempt_running(
                claim.organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                &claim.agent_id,
            )
            .await
            .expect("mark DAG attempt running")
    );
}

async fn unprivileged_store(admin: &Store) -> Store {
    let mut setup = admin
        .pool()
        .begin()
        .await
        .expect("begin unprivileged-role setup");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind("mcloving.test.role-login")
        .execute(&mut *setup)
        .await
        .expect("serialize unprivileged-role setup");
    let login_enabled: bool =
        sqlx::query_scalar("SELECT rolcanlogin FROM pg_roles WHERE rolname = 'mcloving_tenant'")
            .fetch_one(&mut *setup)
            .await
            .expect("inspect unprivileged role");
    if !login_enabled {
        sqlx::query("ALTER ROLE mcloving_tenant LOGIN")
            .execute(&mut *setup)
            .await
            .expect("enable test-only login for the unprivileged role");
    }
    setup
        .commit()
        .await
        .expect("commit unprivileged-role setup");
    let url = std::env::var("MCLOVING_TEST_DATABASE_URL").expect("database URL remains configured");
    let options = url
        .parse::<PgConnectOptions>()
        .expect("parse PostgreSQL test URL")
        .username("mcloving_tenant");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(options)
        .await
        .expect("connect as the unprivileged tenant role");
    Store::new(pool)
}

#[tokio::test]
async fn agent_session_epoch_is_durable_and_monotonic() {
    let Some(admin) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let store = unprivileged_store(&admin).await;
    let agent_id = format!("windows-{}", Uuid::new_v4());
    assert!(
        store
            .open_agent_session(
                &agent_id,
                "trusted",
                5,
                0,
                &["journal-v1".to_owned()],
                &["windows".to_owned()],
            )
            .await
            .expect("open first durable session")
    );
    assert!(
        !store
            .open_agent_session(&agent_id, "trusted", 5, 0, &[], &[])
            .await
            .expect("reject repeated session epoch")
    );
    assert!(
        store
            .authorize_agent_session(&agent_id, 5)
            .await
            .expect("authorize exact epoch")
    );
    assert!(
        !store
            .authorize_agent_session(&agent_id, 4)
            .await
            .expect("reject stale epoch")
    );
}

#[tokio::test]
async fn work_mutations_are_fenced_inside_the_current_session_transaction() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    let agent_id = format!("session-fence-{}", Uuid::new_v4());
    store
        .create_project(
            organization_id,
            &format!("org-{organization_id}"),
            project_id,
            "project",
        )
        .await
        .expect("create tenant");
    store
        .admit_build(&NewBuild {
            organization_id,
            project_id,
            idempotency_key: "session-fenced-work".into(),
            pipeline_digest: [0x5e; 32],
            node_key: "execute".into(),
            required_capabilities: vec!["linux".into()],
            required_trust_pool: "trusted".into(),
            priority: 0,
            execution_spec: json!({}),
        })
        .await
        .expect("admit work");
    assert!(
        store
            .open_agent_session(
                &agent_id,
                "trusted",
                10,
                0,
                &["work-delivery-v1".into()],
                &["linux".into()],
            )
            .await
            .expect("open original session")
    );
    let claim = store
        .claim_next_in_session(
            &ClaimRequest {
                organization_id,
                scheduler_id: "session-fence".into(),
                agent_id: agent_id.clone(),
                capabilities: vec!["linux".into()],
                trust_pool: "trusted".into(),
                lease_seconds: 30,
                fairness_seed: 0,
            },
            10,
        )
        .await
        .expect("claim under original session")
        .expect("claim available work");
    assert!(
        store
            .open_agent_session(
                &agent_id,
                "trusted",
                11,
                0,
                &["work-delivery-v1".into()],
                &["linux".into()],
            )
            .await
            .expect("advance session")
    );

    assert!(
        !store
            .accept_offer_in_session(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                &agent_id,
                10,
            )
            .await
            .expect("reject stale acceptance")
    );
    assert!(
        store
            .attempt_execution_in_session(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                &agent_id,
                10,
            )
            .await
            .expect("reject stale execution read")
            .is_none()
    );
    assert!(
        store
            .accept_offer_in_session(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                &agent_id,
                11,
            )
            .await
            .expect("accept under current session")
    );
    assert!(
        !store
            .mark_attempt_running_in_session(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                &agent_id,
                10,
            )
            .await
            .expect("reject stale start")
    );
    assert!(
        store
            .mark_attempt_running_in_session(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                &agent_id,
                11,
            )
            .await
            .expect("start under current session")
    );
    assert!(
        store
            .renew_attempt_lease_in_session(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                &agent_id,
                10,
                30,
            )
            .await
            .expect("reject stale renewal")
            .is_none()
    );
    assert!(
        store
            .renew_attempt_lease_in_session(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                &agent_id,
                11,
                30,
            )
            .await
            .expect("renew current session")
            .is_some()
    );
    let chunk = NewLogChunk {
        organization_id,
        attempt_id: claim.attempt_id,
        fence: claim.fence,
        restore_epoch: claim.restore_epoch,
        agent_id: &agent_id,
        sequence: 0,
        stream: "stdout",
        content: b"session-fenced",
    };
    assert!(
        !store
            .append_log_in_session(&chunk, 10)
            .await
            .expect("reject stale log")
    );
    assert!(
        store
            .append_log_in_session(&chunk, 11)
            .await
            .expect("commit current log")
    );
    assert!(
        !store
            .finalize_attempt_in_session(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                &agent_id,
                10,
                TerminalOutcome::Succeeded,
                json!({"session": 10}),
            )
            .await
            .expect("reject stale terminal publication")
    );
    assert!(
        store
            .finalize_attempt_in_session(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                &agent_id,
                11,
                TerminalOutcome::Succeeded,
                json!({"session": 11}),
            )
            .await
            .expect("commit current terminal publication")
    );
    assert_eq!(
        store
            .renew_attempt_lease_in_session(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                &agent_id,
                11,
                30,
            )
            .await
            .expect("terminal replay renewal is an idempotent no-op"),
        Some(false)
    );
}

#[tokio::test]
async fn admission_is_atomic_and_idempotent() {
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
            "project",
        )
        .await
        .expect("create tenant");
    let input = NewBuild {
        organization_id,
        project_id,
        idempotency_key: "submission-1".into(),
        pipeline_digest: [7; 32],
        node_key: "stage-1".into(),
        required_capabilities: vec!["linux".into()],
        required_trust_pool: "trusted".into(),
        priority: 10,
        execution_spec: json!({}),
    };

    let first = store.admit_build(&input).await.expect("first admission");
    let second = store.admit_build(&input).await.expect("repeat admission");
    assert!(first.created);
    assert!(!second.created);
    assert_eq!(first.build_id, second.build_id);
    assert_eq!(first.node_id, second.node_id);
    assert_eq!(first.attempt_id, second.attempt_id);

    let counts: (i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT
           (SELECT count(*) FROM builds WHERE organization_id = $1),
           (SELECT count(*) FROM nodes WHERE organization_id = $1),
           (SELECT count(*) FROM attempts WHERE organization_id = $1),
           (SELECT count(*) FROM build_events WHERE organization_id = $1),
           (SELECT count(*) FROM outbox WHERE organization_id = $1)",
    )
    .bind(organization_id)
    .fetch_one(store.pool())
    .await
    .expect("count durable records");
    assert_eq!(counts, (1, 1, 1, 1, 1));
}

#[tokio::test]
async fn queued_cancellation_is_terminal_idempotent_and_unclaimable() {
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
            "project",
        )
        .await
        .expect("create tenant");
    let admission = store
        .admit_build(&NewBuild {
            organization_id,
            project_id,
            idempotency_key: "cancel-before-claim".into(),
            pipeline_digest: [8; 32],
            node_key: "stage-1".into(),
            required_capabilities: vec!["linux".into()],
            required_trust_pool: "trusted".into(),
            priority: 10,
            execution_spec: json!({}),
        })
        .await
        .expect("admit queued build");

    assert!(
        store
            .request_cancellation(organization_id, project_id, admission.build_id)
            .await
            .expect("first cancellation")
    );
    assert!(
        !store
            .request_cancellation(organization_id, project_id, admission.build_id)
            .await
            .expect("idempotent repeated cancellation")
    );
    assert!(
        store
            .claim_next(&ClaimRequest {
                organization_id,
                scheduler_id: "scheduler-a".into(),
                agent_id: "agent-a".into(),
                capabilities: vec!["linux".into()],
                trust_pool: "trusted".into(),
                lease_seconds: 30,
                fairness_seed: 1,
            })
            .await
            .expect("claim query")
            .is_none()
    );

    let snapshot = store
        .build_snapshot(organization_id, project_id, admission.build_id)
        .await
        .expect("read terminal snapshot")
        .expect("build exists");
    assert_eq!(snapshot.build_status, "aborted");
    assert_eq!(snapshot.attempt_status, "aborted");
    assert!(snapshot.cancellation_requested);
    assert_eq!(
        snapshot.terminal_summary,
        Some(json!({"reason": "cancelled_before_execution"}))
    );
    let counts: (i64, i64) = sqlx::query_as(
        "SELECT
           (SELECT count(*) FROM build_events
            WHERE organization_id = $1 AND build_id = $2),
           (SELECT count(*) FROM outbox
            WHERE organization_id = $1 AND aggregate_id = $2)",
    )
    .bind(organization_id)
    .bind(admission.build_id)
    .fetch_one(store.pool())
    .await
    .expect("count admission and cancellation publications");
    assert_eq!(counts, (2, 2));
}

#[tokio::test]
async fn agent_cancellation_completion_is_fenced_durable_and_idempotent() {
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
            "agent-cancellation",
        )
        .await
        .expect("create tenant");
    assert!(
        store
            .open_agent_session(
                "windows-1",
                "trusted",
                1,
                0,
                &["journal-v1".to_owned(), "windows-job-object-v1".to_owned()],
                &["windows".to_owned()],
            )
            .await
            .expect("open agent session")
    );
    let admission = store
        .admit_build(&NewBuild {
            organization_id,
            project_id,
            idempotency_key: "agent-cancellation-complete".into(),
            pipeline_digest: [0xAC; 32],
            node_key: "stage-1".into(),
            required_capabilities: vec!["windows".into()],
            required_trust_pool: "trusted".into(),
            priority: 10,
            execution_spec: json!({}),
        })
        .await
        .expect("admit active build");
    let claim = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "scheduler-a".into(),
            agent_id: "windows-1".into(),
            capabilities: vec!["windows".into()],
            trust_pool: "trusted".into(),
            lease_seconds: 30,
            fairness_seed: 1,
        })
        .await
        .expect("claim query")
        .expect("claim exists");
    assert!(
        store
            .accept_offer(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "windows-1",
            )
            .await
            .expect("accept offer")
    );
    assert!(
        store
            .request_cancellation(organization_id, project_id, admission.build_id)
            .await
            .expect("request active cancellation")
    );
    sqlx::query(
        "UPDATE attempts
         SET lease_expires_at = clock_timestamp() - interval '1 second'
         WHERE organization_id = $1 AND id = $2",
    )
    .bind(organization_id)
    .bind(claim.attempt_id)
    .execute(store.pool())
    .await
    .expect("expire lease to model reconnect after deadline");

    assert_eq!(
        store
            .complete_agent_cancellation(AgentCancellationCompletion {
                organization_id,
                attempt_id: claim.attempt_id,
                fence: claim.fence + 1,
                restore_epoch: claim.restore_epoch,
                agent_id: "windows-1",
                session_epoch: 1,
                outcome: AgentCancellationOutcome::Terminated,
            })
            .await
            .expect("reject stale fence"),
        AgentCancellationDisposition::RetireStale
    );
    assert_eq!(
        store
            .complete_agent_cancellation(AgentCancellationCompletion {
                organization_id,
                attempt_id: claim.attempt_id,
                fence: claim.fence,
                restore_epoch: claim.restore_epoch,
                agent_id: "windows-1",
                session_epoch: 1,
                outcome: AgentCancellationOutcome::Terminated,
            })
            .await
            .expect("complete fenced cancellation"),
        AgentCancellationDisposition::Completed
    );
    assert_eq!(
        store
            .complete_agent_cancellation(AgentCancellationCompletion {
                organization_id,
                attempt_id: claim.attempt_id,
                fence: claim.fence,
                restore_epoch: claim.restore_epoch,
                agent_id: "windows-1",
                session_epoch: 1,
                outcome: AgentCancellationOutcome::Terminated,
            })
            .await
            .expect("replay completion"),
        AgentCancellationDisposition::Completed
    );

    let snapshot = store
        .build_snapshot(organization_id, project_id, admission.build_id)
        .await
        .expect("read terminal snapshot")
        .expect("build exists");
    assert_eq!(snapshot.build_status, "aborted");
    assert_eq!(snapshot.attempt_status, "aborted");
    assert_eq!(
        snapshot.terminal_summary,
        Some(json!({"reason": "agent_confirmed_cancellation"}))
    );
    let completions = sqlx::query_scalar::<_, i64>(
        "SELECT count(*)
         FROM build_events
         WHERE organization_id = $1
           AND build_id = $2
           AND kind = 'attempt.cancellation_completed'",
    )
    .bind(organization_id)
    .bind(admission.build_id)
    .fetch_one(store.pool())
    .await
    .expect("count cancellation completion events");
    assert_eq!(completions, 1);

    let recovered = store
        .admit_build(&NewBuild {
            organization_id,
            project_id,
            idempotency_key: "agent-recovery-termination".into(),
            pipeline_digest: [0xAE; 32],
            node_key: "stage-recovery".into(),
            required_capabilities: vec!["windows".into()],
            required_trust_pool: "trusted".into(),
            priority: 10,
            execution_spec: json!({}),
        })
        .await
        .expect("admit interrupted agent build");
    let recovered_claim = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "scheduler-a".into(),
            agent_id: "windows-1".into(),
            capabilities: vec!["windows".into()],
            trust_pool: "trusted".into(),
            lease_seconds: 30,
            fairness_seed: 1,
        })
        .await
        .expect("claim interrupted work")
        .expect("interrupted claim exists");
    assert!(
        store
            .accept_offer(
                organization_id,
                recovered_claim.attempt_id,
                recovered_claim.fence,
                recovered_claim.restore_epoch,
                "windows-1",
            )
            .await
            .expect("accept interrupted work")
    );
    assert!(
        store
            .mark_attempt_running_in_session(
                organization_id,
                recovered_claim.attempt_id,
                recovered_claim.fence,
                recovered_claim.restore_epoch,
                "windows-1",
                1,
            )
            .await
            .expect("start interrupted work")
    );
    assert!(
        store
            .recover_agent_finalization_in_session(
                organization_id,
                recovered_claim.attempt_id,
                recovered_claim.fence,
                recovered_claim.restore_epoch,
                "windows-1",
                1,
                "cancelling",
                30,
            )
            .await
            .expect("retain interrupted cancellation replay")
    );
    let replay_snapshot = store
        .build_snapshot(organization_id, project_id, recovered.build_id)
        .await
        .expect("read interrupted cancellation replay")
        .expect("interrupted cancellation replay exists");
    assert_eq!(replay_snapshot.build_status, "running");
    assert_eq!(replay_snapshot.attempt_status, "cancelling");
    assert_eq!(
        store
            .complete_agent_cancellation(AgentCancellationCompletion {
                organization_id,
                attempt_id: recovered_claim.attempt_id,
                fence: recovered_claim.fence,
                restore_epoch: recovered_claim.restore_epoch,
                agent_id: "windows-1",
                session_epoch: 1,
                outcome: AgentCancellationOutcome::AlreadyExited,
            })
            .await
            .expect("settle interrupted work without an owner cancellation"),
        AgentCancellationDisposition::Completed
    );
    let recovered_snapshot = store
        .build_snapshot(organization_id, project_id, recovered.build_id)
        .await
        .expect("read interrupted build")
        .expect("interrupted build exists");
    assert_eq!(recovered_snapshot.build_status, "aborted");
    assert_eq!(
        recovered_snapshot.terminal_summary,
        Some(json!({"reason": "agent_recovery_process_already_exited"}))
    );
    let recovery_events = sqlx::query_scalar::<_, i64>(
        "SELECT count(*)
         FROM build_events
         WHERE organization_id = $1
           AND build_id = $2
           AND kind = 'attempt.recovery_process_already_exited'",
    )
    .bind(organization_id)
    .bind(recovered.build_id)
    .fetch_one(store.pool())
    .await
    .expect("count recovery completion events");
    assert_eq!(recovery_events, 1);

    let retained = store
        .admit_build(&NewBuild {
            organization_id,
            project_id,
            idempotency_key: "agent-cancellation-unverifiable".into(),
            pipeline_digest: [0xAD; 32],
            node_key: "stage-unverifiable".into(),
            required_capabilities: vec!["windows".into()],
            required_trust_pool: "trusted".into(),
            priority: 10,
            execution_spec: json!({}),
        })
        .await
        .expect("admit unverifiable cancellation build");
    let retained_claim = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "scheduler-a".into(),
            agent_id: "windows-1".into(),
            capabilities: vec!["windows".into()],
            trust_pool: "trusted".into(),
            lease_seconds: 30,
            fairness_seed: 2,
        })
        .await
        .expect("claim unverifiable cancellation")
        .expect("unverifiable cancellation claim exists");
    assert!(
        store
            .accept_offer(
                organization_id,
                retained_claim.attempt_id,
                retained_claim.fence,
                retained_claim.restore_epoch,
                "windows-1",
            )
            .await
            .expect("accept unverifiable cancellation offer")
    );
    assert!(
        store
            .request_cancellation(organization_id, project_id, retained.build_id)
            .await
            .expect("request unverifiable cancellation")
    );
    for label in [
        "retain unverifiable cancellation",
        "replay retained outcome",
    ] {
        assert_eq!(
            store
                .complete_agent_cancellation(AgentCancellationCompletion {
                    organization_id,
                    attempt_id: retained_claim.attempt_id,
                    fence: retained_claim.fence,
                    restore_epoch: retained_claim.restore_epoch,
                    agent_id: "windows-1",
                    session_epoch: 1,
                    outcome: AgentCancellationOutcome::ReconciliationRequired,
                })
                .await
                .expect(label),
            AgentCancellationDisposition::ReconciliationRequired
        );
    }
    let retained_snapshot = store
        .build_snapshot(organization_id, project_id, retained.build_id)
        .await
        .expect("read retained cancellation")
        .expect("retained build exists");
    assert_eq!(retained_snapshot.build_status, "reconciliation_required");
    assert_eq!(retained_snapshot.attempt_status, "reconciliation_required");
    let retained_events = sqlx::query_scalar::<_, i64>(
        "SELECT count(*)
         FROM build_events
         WHERE organization_id = $1
           AND build_id = $2
           AND kind = 'attempt.cancellation_reconciliation_required'",
    )
    .bind(organization_id)
    .bind(retained.build_id)
    .fetch_one(store.pool())
    .await
    .expect("count retained cancellation events");
    assert_eq!(retained_events, 1);

    let recycled = store
        .admit_build(&NewBuild {
            organization_id,
            project_id,
            idempotency_key: "agent-cancellation-recycled-pid".into(),
            pipeline_digest: [0xAE; 32],
            node_key: "stage-recycled".into(),
            required_capabilities: vec!["windows".into()],
            required_trust_pool: "trusted".into(),
            priority: 10,
            execution_spec: json!({}),
        })
        .await
        .expect("admit recycled PID cancellation build");
    let recycled_claim = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "scheduler-a".into(),
            agent_id: "windows-1".into(),
            capabilities: vec!["windows".into()],
            trust_pool: "trusted".into(),
            lease_seconds: 30,
            fairness_seed: 3,
        })
        .await
        .expect("claim recycled PID cancellation")
        .expect("recycled PID cancellation claim exists");
    assert!(
        store
            .accept_offer(
                organization_id,
                recycled_claim.attempt_id,
                recycled_claim.fence,
                recycled_claim.restore_epoch,
                "windows-1",
            )
            .await
            .expect("accept recycled PID cancellation offer")
    );
    assert!(
        store
            .request_cancellation(organization_id, project_id, recycled.build_id)
            .await
            .expect("request recycled PID cancellation")
    );
    for label in ["retire recycled PID", "replay recycled PID retirement"] {
        assert_eq!(
            store
                .complete_agent_cancellation(AgentCancellationCompletion {
                    organization_id,
                    attempt_id: recycled_claim.attempt_id,
                    fence: recycled_claim.fence,
                    restore_epoch: recycled_claim.restore_epoch,
                    agent_id: "windows-1",
                    session_epoch: 1,
                    outcome: AgentCancellationOutcome::IdentityMismatch,
                })
                .await
                .expect(label),
            AgentCancellationDisposition::RetireStale
        );
    }
    let recycled_snapshot = store
        .build_snapshot(organization_id, project_id, recycled.build_id)
        .await
        .expect("read recycled PID cancellation")
        .expect("recycled PID build exists");
    assert_eq!(recycled_snapshot.build_status, "aborted");
    assert_eq!(
        recycled_snapshot.terminal_summary,
        Some(json!({"reason": "agent_process_identity_mismatch"}))
    );
    let recycled_events = sqlx::query_scalar::<_, i64>(
        "SELECT count(*)
         FROM build_events
         WHERE organization_id = $1
           AND build_id = $2
           AND kind = 'attempt.cancellation_stale_process'",
    )
    .bind(organization_id)
    .bind(recycled.build_id)
    .fetch_one(store.pool())
    .await
    .expect("count recycled PID cancellation events");
    assert_eq!(recycled_events, 1);

    let re_enrolled = store
        .admit_build(&NewBuild {
            organization_id,
            project_id,
            idempotency_key: "agent-cancellation-re-enrolled-trust-pool".into(),
            pipeline_digest: [0xAF; 32],
            node_key: "stage-re-enrolled".into(),
            required_capabilities: vec!["windows".into()],
            required_trust_pool: "trusted".into(),
            priority: 10,
            execution_spec: json!({}),
        })
        .await
        .expect("admit trust-pool cancellation build");
    let re_enrolled_claim = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "scheduler-a".into(),
            agent_id: "windows-1".into(),
            capabilities: vec!["windows".into()],
            trust_pool: "trusted".into(),
            lease_seconds: 30,
            fairness_seed: 4,
        })
        .await
        .expect("claim trust-pool cancellation")
        .expect("trust-pool cancellation claim exists");
    assert!(
        store
            .accept_offer(
                organization_id,
                re_enrolled_claim.attempt_id,
                re_enrolled_claim.fence,
                re_enrolled_claim.restore_epoch,
                "windows-1",
            )
            .await
            .expect("accept trust-pool cancellation offer")
    );
    assert!(
        store
            .request_cancellation(organization_id, project_id, re_enrolled.build_id)
            .await
            .expect("request trust-pool cancellation")
    );
    assert!(
        store
            .open_agent_session(
                "windows-1",
                "untrusted",
                2,
                0,
                &["journal-v1".to_owned(), "windows-job-object-v1".to_owned()],
                &["windows".to_owned()],
            )
            .await
            .expect("re-enroll agent in lower trust pool")
    );
    assert_eq!(
        store
            .complete_agent_cancellation(AgentCancellationCompletion {
                organization_id,
                attempt_id: re_enrolled_claim.attempt_id,
                fence: re_enrolled_claim.fence,
                restore_epoch: re_enrolled_claim.restore_epoch,
                agent_id: "windows-1",
                session_epoch: 2,
                outcome: AgentCancellationOutcome::Terminated,
            })
            .await
            .expect("reject lower-trust cancellation completion"),
        AgentCancellationDisposition::RetireStale
    );
    let re_enrolled_snapshot = store
        .build_snapshot(organization_id, project_id, re_enrolled.build_id)
        .await
        .expect("read trust-pool cancellation")
        .expect("trust-pool build exists");
    assert_eq!(re_enrolled_snapshot.build_status, "running");
    assert_eq!(re_enrolled_snapshot.attempt_status, "cancelling");
    assert_eq!(re_enrolled_snapshot.terminal_summary, None);
}

#[tokio::test]
async fn cancellation_with_uncertain_effect_is_retained_for_reconciliation() {
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
            "agent-cancellation-reconciliation",
        )
        .await
        .expect("create tenant");
    assert!(
        store
            .open_agent_session(
                "windows-reconciliation-1",
                "trusted",
                1,
                0,
                &["journal-v1".to_owned(), "windows-job-object-v1".to_owned()],
                &["windows".to_owned()],
            )
            .await
            .expect("open agent session")
    );
    let admission = store
        .admit_build(&NewBuild {
            organization_id,
            project_id,
            idempotency_key: "agent-cancellation-reconciliation".into(),
            pipeline_digest: [0xCE; 32],
            node_key: "stage-1".into(),
            required_capabilities: vec!["windows".into()],
            required_trust_pool: "trusted".into(),
            priority: 10,
            execution_spec: json!({}),
        })
        .await
        .expect("admit active build");
    let claim = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "scheduler-a".into(),
            agent_id: "windows-reconciliation-1".into(),
            capabilities: vec!["windows".into()],
            trust_pool: "trusted".into(),
            lease_seconds: 30,
            fairness_seed: 1,
        })
        .await
        .expect("claim query")
        .expect("claim exists");
    assert!(
        store
            .accept_offer(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "windows-reconciliation-1",
            )
            .await
            .expect("accept offer")
    );
    let effect_payload = json!({"destination": "production"});
    for (status, label) in [
        (EffectStatus::Prepared, "prepare effect"),
        (EffectStatus::Uncertain, "mark effect uncertain"),
    ] {
        assert!(
            store
                .checkpoint_effect(
                    organization_id,
                    claim.attempt_id,
                    claim.fence,
                    claim.restore_epoch,
                    "windows-reconciliation-1",
                    "deploy",
                    EffectClass::NonIdempotent,
                    status,
                    &effect_payload,
                )
                .await
                .expect(label)
        );
    }
    assert!(
        store
            .request_cancellation(organization_id, project_id, admission.build_id)
            .await
            .expect("request active cancellation")
    );
    assert_eq!(
        store
            .complete_agent_cancellation(AgentCancellationCompletion {
                organization_id,
                attempt_id: claim.attempt_id,
                fence: claim.fence,
                restore_epoch: claim.restore_epoch,
                agent_id: "windows-reconciliation-1",
                session_epoch: 1,
                outcome: AgentCancellationOutcome::Terminated,
            })
            .await
            .expect("route uncertain cancellation to reconciliation"),
        AgentCancellationDisposition::ReconciliationRequired
    );
    assert_eq!(
        store
            .agent_reconciliation_disposition(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "windows-reconciliation-1",
            )
            .await
            .expect("reconcile current uncertain cancellation"),
        AgentReconciliationDisposition::Retain
    );

    let snapshot = store
        .build_snapshot(organization_id, project_id, admission.build_id)
        .await
        .expect("read reconciliation snapshot")
        .expect("build exists");
    assert_eq!(snapshot.build_status, "reconciliation_required");
    assert_eq!(snapshot.attempt_status, "reconciliation_required");
    let reconciliation_events = sqlx::query_scalar::<_, i64>(
        "SELECT count(*)
         FROM build_events
         WHERE organization_id = $1
           AND build_id = $2
           AND kind = 'attempt.cancellation_reconciliation_required'",
    )
    .bind(organization_id)
    .bind(admission.build_id)
    .fetch_one(store.pool())
    .await
    .expect("count cancellation reconciliation events");
    assert_eq!(reconciliation_events, 1);

    assert!(
        store
            .confirm_uncertain_effect(
                organization_id,
                claim.attempt_id,
                claim.fence,
                "deploy",
                EffectClass::NonIdempotent,
                &effect_payload,
            )
            .await
            .expect("confirm cancellation effect through operator reconciliation")
    );
    assert!(
        store
            .finalize_reconciled_attempt(
                organization_id,
                claim.attempt_id,
                claim.fence,
                "operator-1",
                TerminalOutcome::Aborted,
                json!({"reason": "cancelled_after_effect_reconciliation"}),
            )
            .await
            .expect("terminalize cancellation after operator reconciliation")
    );
    let terminal = store
        .build_snapshot(organization_id, project_id, admission.build_id)
        .await
        .expect("read terminal reconciliation snapshot")
        .expect("build exists");
    assert_eq!(terminal.build_status, "aborted");
    assert_eq!(terminal.attempt_status, "aborted");
    assert_eq!(
        terminal.terminal_summary,
        Some(json!({"reason": "cancelled_after_effect_reconciliation"}))
    );
}

#[tokio::test]
async fn cancellation_targets_the_latest_retry_attempt() {
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
            "retry-cancellation",
        )
        .await
        .expect("create tenant");
    let admission = store
        .admit_build(&NewBuild {
            organization_id,
            project_id,
            idempotency_key: "cancel-current-retry".into(),
            pipeline_digest: [9; 32],
            node_key: "stage-1".into(),
            required_capabilities: vec!["linux".into()],
            required_trust_pool: "trusted".into(),
            priority: 0,
            execution_spec: json!({}),
        })
        .await
        .expect("admit build");
    let first = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "scheduler-a".into(),
            agent_id: "agent-a".into(),
            capabilities: vec!["linux".into()],
            trust_pool: "trusted".into(),
            lease_seconds: 30,
            fairness_seed: 1,
        })
        .await
        .expect("claim first")
        .expect("first claim exists");
    assert!(
        store
            .accept_offer(
                organization_id,
                first.attempt_id,
                first.fence,
                first.restore_epoch,
                "agent-a",
            )
            .await
            .expect("accept first")
    );
    assert!(
        store
            .finalize_attempt(
                organization_id,
                first.attempt_id,
                first.fence,
                first.restore_epoch,
                "agent-a",
                TerminalOutcome::Failed,
                json!({"reason": "retry"}),
            )
            .await
            .expect("fail first")
    );
    let RetryDecision::Scheduled {
        attempt_id: second_id,
        ordinal: 2,
        created: true,
    } = store
        .schedule_retry(organization_id, first.attempt_id, 3, "retry")
        .await
        .expect("schedule retry")
    else {
        panic!("expected second attempt");
    };
    assert!(
        store
            .request_cancellation(organization_id, project_id, admission.build_id)
            .await
            .expect("cancel retry")
    );
    let attempts = sqlx::query_as::<_, (Uuid, i32, String)>(
        "SELECT id, ordinal, status
         FROM attempts
         WHERE organization_id = $1
           AND node_id = $2
         ORDER BY ordinal",
    )
    .bind(organization_id)
    .bind(admission.node_id)
    .fetch_all(store.pool())
    .await
    .expect("read attempts");
    assert_eq!(
        attempts,
        vec![
            (first.attempt_id, 1, "failed".to_owned()),
            (second_id, 2, "aborted".to_owned()),
        ]
    );
    let snapshot = store
        .build_snapshot(organization_id, project_id, admission.build_id)
        .await
        .expect("read snapshot")
        .expect("build exists");
    assert_eq!(snapshot.attempt_id, second_id);
    assert_eq!(snapshot.attempt_status, "aborted");
    assert_eq!(snapshot.build_status, "aborted");
}

#[tokio::test]
async fn unprivileged_runtime_role_admits_but_cannot_bootstrap() {
    let Some(admin) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let can_create = sqlx::query_scalar::<_, bool>(
        "SELECT has_schema_privilege('mcloving_tenant', 'public', 'CREATE')",
    )
    .fetch_one(admin.pool())
    .await
    .expect("inspect tenant schema privilege");
    assert!(!can_create);

    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    admin
        .create_project(
            organization_id,
            &format!("org-{organization_id}"),
            project_id,
            "project",
        )
        .await
        .expect("bootstrap through privileged connection");
    let store = unprivileged_store(&admin).await;
    let can_mutate_grants = sqlx::query_scalar::<_, bool>(
        "SELECT
           has_table_privilege('mcloving_tenant', 'identities', 'INSERT')
           OR has_table_privilege(
             'mcloving_tenant', 'project_memberships', 'INSERT'
           )
           OR has_table_privilege(
             'mcloving_tenant', 'service_scopes', 'INSERT'
           )",
    )
    .fetch_one(store.pool())
    .await
    .expect("inspect authorization-table privileges");
    assert!(!can_mutate_grants);
    let can_observe_global_deletion_state = sqlx::query_scalar::<_, bool>(
        "SELECT
           has_table_privilege(
             'mcloving_tenant', 'object_deletion_claims', 'SELECT'
           )
           OR has_function_privilege(
             'mcloving_tenant',
             'mcloving_guard_object_deletion_write()',
             'EXECUTE'
           )",
    )
    .fetch_one(store.pool())
    .await
    .expect("inspect global deletion-state privileges");
    assert!(!can_observe_global_deletion_state);
    let mut escalation = store.pool().begin().await.expect("begin escalation test");
    sqlx::query("SELECT set_config('mcloving.organization_id', $1, true)")
        .bind(organization_id.to_string())
        .execute(&mut *escalation)
        .await
        .expect("bind tenant context for escalation test");
    let cross_tenant_probe = sqlx::query_scalar::<_, bool>(
        "SELECT mcloving_owned_object_publication_allowed(
             $1, $2, 1, 'artifact', 'foreign', $3
         )",
    )
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .bind([0x6a_u8; 32].as_slice())
    .fetch_one(&mut *escalation)
    .await
    .expect("invoke tenant-scoped publication guard");
    assert!(
        !cross_tenant_probe,
        "the definer function must not expose foreign deletion state"
    );
    let self_grant = sqlx::query(
        "INSERT INTO identities (id, organization_id, subject, kind)
         VALUES ($1, $2, 'service:attacker', 'service')",
    )
    .bind(Uuid::new_v4())
    .bind(organization_id)
    .execute(&mut *escalation)
    .await;
    assert!(self_grant.is_err());
    escalation
        .rollback()
        .await
        .expect("roll back escalation test");
    let forbidden_organization = Uuid::new_v4();
    assert!(
        store
            .create_project(
                forbidden_organization,
                &format!("org-{forbidden_organization}"),
                Uuid::new_v4(),
                "forbidden",
            )
            .await
            .is_err(),
        "runtime role must not bootstrap tenant metadata"
    );
    let admission = store
        .admit_build(&NewBuild {
            organization_id,
            project_id,
            idempotency_key: "runtime-role".into(),
            pipeline_digest: [8; 32],
            node_key: "stage-1".into(),
            required_capabilities: Vec::new(),
            required_trust_pool: "trusted".into(),
            priority: 0,
            execution_spec: json!({}),
        })
        .await
        .expect("admit through runtime role using identity sequences");
    let mut tenant = store.pool().begin().await.expect("begin tenant read");
    sqlx::query("SELECT set_config('mcloving.organization_id', $1, true)")
        .bind(organization_id.to_string())
        .execute(&mut *tenant)
        .await
        .expect("bind tenant context");
    let event_count = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM build_events
         WHERE organization_id = $1 AND build_id = $2",
    )
    .bind(organization_id)
    .bind(admission.build_id)
    .fetch_one(&mut *tenant)
    .await
    .expect("read emitted event through forced RLS");
    assert_eq!(event_count, 1);
    tenant.commit().await.expect("commit tenant read");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_terminal_publication_has_one_winner() {
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
            "project",
        )
        .await
        .expect("create tenant");
    let admission = store
        .admit_build(&NewBuild {
            organization_id,
            project_id,
            idempotency_key: "terminal-race".into(),
            pipeline_digest: [9; 32],
            node_key: "stage-1".into(),
            required_capabilities: Vec::new(),
            required_trust_pool: "trusted".into(),
            priority: 0,
            execution_spec: json!({}),
        })
        .await
        .expect("admit build");
    assert!(
        !store
            .finalize_attempt(
                organization_id,
                admission.attempt_id,
                0,
                store.current_restore_epoch().await.expect("restore epoch"),
                "unleased-agent",
                TerminalOutcome::Succeeded,
                json!({"publisher": "unleased"}),
            )
            .await
            .expect("reject unleased publication")
    );
    let claim = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "scheduler-a".into(),
            agent_id: "agent-a".into(),
            capabilities: Vec::new(),
            trust_pool: "trusted".into(),
            lease_seconds: 30,
            fairness_seed: 1,
        })
        .await
        .expect("claim work")
        .expect("claim exists");
    assert!(
        store
            .accept_offer(
                organization_id,
                admission.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "agent-a",
            )
            .await
            .expect("accept offer")
    );
    let store = Arc::new(store);

    let contenders = (0..16).map(|index| {
        let store = Arc::clone(&store);
        tokio::spawn(async move {
            store
                .finalize_attempt(
                    organization_id,
                    admission.attempt_id,
                    claim.fence,
                    claim.restore_epoch,
                    "agent-a",
                    TerminalOutcome::Succeeded,
                    json!({"publisher": index}),
                )
                .await
                .expect("terminal publication")
        })
    });
    let mut winners = 0;
    for contender in contenders {
        winners += usize::from(contender.await.expect("join publisher"));
    }
    assert_eq!(winners, 1);

    let terminal_records: (i64, i64) = sqlx::query_as(
        "SELECT
           (SELECT count(*) FROM build_events
             WHERE organization_id = $1 AND kind = 'attempt.terminal'),
           (SELECT count(*) FROM outbox
             WHERE organization_id = $1 AND topic = 'attempt.terminal')",
    )
    .bind(organization_id)
    .fetch_one(store.pool())
    .await
    .expect("count terminal records");
    assert_eq!(terminal_records, (1, 1));
}

#[tokio::test]
async fn scheduler_requires_the_nodes_designated_trust_pool() {
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
            "project",
        )
        .await
        .expect("create tenant");
    let build = store
        .admit_build(&NewBuild {
            organization_id,
            project_id,
            idempotency_key: "release-pool".into(),
            pipeline_digest: [0x71; 32],
            node_key: "release".into(),
            required_capabilities: vec!["linux".into()],
            required_trust_pool: "release".into(),
            priority: 10,
            execution_spec: json!({}),
        })
        .await
        .expect("admit release work");

    assert_eq!(
        store
            .explain_wait(organization_id, &["linux".into()], "untrusted")
            .await
            .expect("explain mismatched pool"),
        WaitReason::TrustPoolMismatch {
            required: "release".into(),
            offered: "untrusted".into(),
        }
    );
    assert_eq!(
        store
            .explain_wait(organization_id, &["linux".into()], "release")
            .await
            .expect("explain matching pool"),
        WaitReason::Ready
    );
    assert!(
        store
            .claim_next(&ClaimRequest {
                organization_id,
                scheduler_id: "scheduler-untrusted".into(),
                agent_id: "agent-untrusted".into(),
                capabilities: vec!["linux".into()],
                trust_pool: "untrusted".into(),
                lease_seconds: 30,
                fairness_seed: 0,
            })
            .await
            .expect("evaluate mismatched pool")
            .is_none()
    );
    let claim = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "scheduler-release".into(),
            agent_id: "agent-release".into(),
            capabilities: vec!["linux".into()],
            trust_pool: "release".into(),
            lease_seconds: 30,
            fairness_seed: 0,
        })
        .await
        .expect("claim from matching pool")
        .expect("matching pool receives work");
    assert_eq!(claim.node_id, build.node_id);
    assert!(
        store
            .authorize_attempt_trust_pool(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                &claim.agent_id,
                "release",
            )
            .await
            .expect("authorize matching attempt pool")
    );
    assert!(
        !store
            .authorize_attempt_trust_pool(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                &claim.agent_id,
                "untrusted",
            )
            .await
            .expect("reject mismatched attempt pool")
    );
    assert_eq!(
        store
            .authorize_reconciliation_trust_pool(organization_id, claim.attempt_id, "release")
            .await
            .expect("authorize matching reconciliation pool"),
        ReconciliationTrustPoolAuthorization::Matching
    );
    assert_eq!(
        store
            .authorize_reconciliation_trust_pool(organization_id, claim.attempt_id, "untrusted")
            .await
            .expect("reject mismatched reconciliation pool"),
        ReconciliationTrustPoolAuthorization::Mismatched
    );
    assert_eq!(
        store
            .authorize_reconciliation_trust_pool(organization_id, Uuid::new_v4(), "release")
            .await
            .expect("allow a missing restored attempt to retire"),
        ReconciliationTrustPoolAuthorization::Missing
    );
    assert!(
        !store
            .authorize_attempt_trust_pool(
                organization_id,
                claim.attempt_id,
                claim.fence + 1,
                claim.restore_epoch,
                &claim.agent_id,
                "release",
            )
            .await
            .expect("reject stale attempt authority")
    );
    assert_eq!(
        store
            .agent_reconciliation_disposition(
                organization_id,
                claim.attempt_id,
                claim.fence + 1,
                claim.restore_epoch,
                &claim.agent_id,
            )
            .await
            .expect("cancel stale authority after pool authorization"),
        AgentReconciliationDisposition::Cancel
    );
}

#[tokio::test]
async fn scheduler_explains_the_offered_pool_before_higher_priority_other_pool_work() {
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
            "project",
        )
        .await
        .expect("create tenant");
    store
        .admit_build(&NewBuild {
            organization_id,
            project_id,
            idempotency_key: "higher-release".into(),
            pipeline_digest: [0x72; 32],
            node_key: "release".into(),
            required_capabilities: vec!["linux".into()],
            required_trust_pool: "release".into(),
            priority: 100,
            execution_spec: json!({}),
        })
        .await
        .expect("admit higher-priority release work");
    store
        .admit_build(&NewBuild {
            organization_id,
            project_id,
            idempotency_key: "lower-trusted".into(),
            pipeline_digest: [0x73; 32],
            node_key: "trusted".into(),
            required_capabilities: vec!["linux".into(), "powershell".into()],
            required_trust_pool: "trusted".into(),
            priority: 10,
            execution_spec: json!({}),
        })
        .await
        .expect("admit lower-priority trusted work");

    assert_eq!(
        store
            .explain_wait(organization_id, &["linux".into()], "trusted")
            .await
            .expect("explain offered pool"),
        WaitReason::CapabilityMismatch {
            required: ["linux".into(), "powershell".into()].into(),
            missing: ["powershell".into()].into(),
        }
    );
}

#[tokio::test]
async fn scheduler_filters_capabilities_and_explains_the_wait() {
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
            "project",
        )
        .await
        .expect("create tenant");
    let windows = store
        .admit_build(&NewBuild {
            organization_id,
            project_id,
            idempotency_key: "windows".into(),
            pipeline_digest: [1; 32],
            node_key: "windows-stage".into(),
            required_capabilities: vec!["windows".into(), "powershell".into()],
            required_trust_pool: "trusted".into(),
            priority: 100,
            execution_spec: json!({}),
        })
        .await
        .expect("admit Windows work");
    let linux = store
        .admit_build(&NewBuild {
            organization_id,
            project_id,
            idempotency_key: "linux".into(),
            pipeline_digest: [2; 32],
            node_key: "linux-stage".into(),
            required_capabilities: vec!["linux".into()],
            required_trust_pool: "trusted".into(),
            priority: 10,
            execution_spec: json!({}),
        })
        .await
        .expect("admit Linux work");

    let claim = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "scheduler-a".into(),
            agent_id: "linux-agent".into(),
            capabilities: vec!["linux".into(), "podman".into()],
            trust_pool: "trusted".into(),
            lease_seconds: 30,
            fairness_seed: 17,
        })
        .await
        .expect("claim compatible work")
        .expect("one compatible claim");
    assert_eq!(claim.node_id, linux.node_id);
    assert_eq!(claim.fence, 1);
    assert!(
        !store
            .accept_offer(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "wrong-agent",
            )
            .await
            .expect("reject wrong lease owner")
    );
    assert!(
        store
            .accept_offer(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "linux-agent",
            )
            .await
            .expect("accept exact lease owner")
    );

    let tenant_store = unprivileged_store(&store).await;
    let reason = tenant_store
        .explain_wait(organization_id, &["linux".into()], "trusted")
        .await
        .expect("explain queue");
    assert_eq!(
        reason,
        WaitReason::CapabilityMismatch {
            required: ["powershell".into(), "windows".into()].into(),
            missing: ["powershell".into(), "windows".into()].into(),
        }
    );
    assert_ne!(claim.node_id, windows.node_id);
}

#[tokio::test]
async fn expired_accepted_attempt_is_reclaimed_with_a_new_fence() {
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
            "project",
        )
        .await
        .expect("create tenant");
    let admission = store
        .admit_build(&NewBuild {
            organization_id,
            project_id,
            idempotency_key: "reclaim".into(),
            pipeline_digest: [3; 32],
            node_key: "stage".into(),
            required_capabilities: vec!["linux".into()],
            required_trust_pool: "trusted".into(),
            priority: 0,
            execution_spec: json!({}),
        })
        .await
        .expect("admit work");
    let first = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "scheduler-a".into(),
            agent_id: "agent-a".into(),
            capabilities: vec!["linux".into()],
            trust_pool: "trusted".into(),
            lease_seconds: 1,
            fairness_seed: 1,
        })
        .await
        .expect("first claim")
        .expect("claim exists");
    assert!(
        store
            .accept_offer(
                organization_id,
                admission.attempt_id,
                first.fence,
                first.restore_epoch,
                "agent-a",
            )
            .await
            .expect("accept first offer")
    );
    sqlx::query(
        "UPDATE attempts SET lease_expires_at = clock_timestamp() - interval '1 second'
         WHERE id = $1",
    )
    .bind(admission.attempt_id)
    .execute(store.pool())
    .await
    .expect("expire lease under test");
    assert!(
        store
            .requeue_one_expired(organization_id)
            .await
            .expect("requeue expired accepted attempt")
    );
    let second = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "scheduler-b".into(),
            agent_id: "agent-b".into(),
            capabilities: vec!["linux".into()],
            trust_pool: "trusted".into(),
            lease_seconds: 30,
            fairness_seed: 1,
        })
        .await
        .expect("second claim")
        .expect("claim exists");
    assert_eq!(first.attempt_id, second.attempt_id);
    assert_eq!(first.fence + 1, second.fence);
    assert!(
        !store
            .finalize_attempt(
                organization_id,
                first.attempt_id,
                first.fence,
                first.restore_epoch,
                "agent-a",
                TerminalOutcome::Succeeded,
                json!({"agent": "stale"}),
            )
            .await
            .expect("reject stale terminal publication")
    );
}

#[tokio::test]
async fn expired_non_idempotent_effect_requires_reconciliation() {
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
            "effect-expiry",
        )
        .await
        .expect("create tenant");
    let admission = store
        .admit_build(&NewBuild {
            organization_id,
            project_id,
            idempotency_key: "effect-expiry".into(),
            pipeline_digest: [39; 32],
            node_key: "deploy".into(),
            required_capabilities: vec!["linux".into()],
            required_trust_pool: "trusted".into(),
            priority: 0,
            execution_spec: json!({}),
        })
        .await
        .expect("admit effect work");
    let claim = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "scheduler-a".into(),
            agent_id: "agent-a".into(),
            capabilities: vec!["linux".into()],
            trust_pool: "trusted".into(),
            lease_seconds: 300,
            fairness_seed: 1,
        })
        .await
        .expect("claim effect work")
        .expect("claim exists");
    assert!(
        store
            .accept_offer(
                organization_id,
                admission.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "agent-a",
            )
            .await
            .expect("accept effect work")
    );
    let payload = json!({"destination": "production", "release": "r1"});
    assert!(
        store
            .checkpoint_effect(
                organization_id,
                admission.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "agent-a",
                "deploy",
                EffectClass::NonIdempotent,
                EffectStatus::Prepared,
                &payload,
            )
            .await
            .expect("prepare non-idempotent effect")
    );
    sqlx::query(
        "UPDATE attempts SET lease_expires_at = clock_timestamp() - interval '1 second'
         WHERE organization_id = $1 AND id = $2",
    )
    .bind(organization_id)
    .bind(admission.attempt_id)
    .execute(store.pool())
    .await
    .expect("expire effect lease");
    assert!(
        store
            .requeue_one_expired(organization_id)
            .await
            .expect("route expired effect")
    );

    let snapshot = store
        .build_snapshot(organization_id, project_id, admission.build_id)
        .await
        .expect("load reconciled build")
        .expect("build exists");
    assert_eq!(snapshot.build_status, "reconciliation_required");
    assert_eq!(snapshot.attempt_status, "reconciliation_required");
    assert!(snapshot.lease_owner.is_none());
    let node_status = sqlx::query_scalar::<_, String>(
        "SELECT status
         FROM nodes
         WHERE organization_id = $1 AND id = $2",
    )
    .bind(organization_id)
    .bind(snapshot.node_id)
    .fetch_one(store.pool())
    .await
    .expect("read reconciled node");
    assert_eq!(node_status, "reconciliation_required");
    assert!(
        store
            .claim_next(&ClaimRequest {
                organization_id,
                scheduler_id: "scheduler-b".into(),
                agent_id: "agent-b".into(),
                capabilities: vec!["linux".into()],
                trust_pool: "trusted".into(),
                lease_seconds: 300,
                fairness_seed: 2,
            })
            .await
            .expect("check for runnable duplicate")
            .is_none()
    );
    let uncertain = store
        .uncertain_effects(organization_id)
        .await
        .expect("list uncertain effect");
    assert_eq!(uncertain.len(), 1);
    assert_eq!(uncertain[0].attempt_id, admission.attempt_id);
    assert_eq!(uncertain[0].fence, claim.fence);
    assert_eq!(uncertain[0].effect_key, "deploy");
    assert_eq!(uncertain[0].effect_class, EffectClass::NonIdempotent);
    assert_eq!(uncertain[0].status, EffectStatus::Uncertain);
    assert_eq!(uncertain[0].payload, payload);
    let event_count = sqlx::query_scalar::<_, i64>(
        "SELECT count(*)
         FROM build_events
         WHERE organization_id = $1
           AND kind = 'attempt.lease_expired_reconciliation_required'",
    )
    .bind(organization_id)
    .fetch_one(store.pool())
    .await
    .expect("count reconciliation event");
    let outbox_count = sqlx::query_scalar::<_, i64>(
        "SELECT count(*)
         FROM outbox
         WHERE organization_id = $1
           AND topic = 'attempt.lease_expired_reconciliation_required'",
    )
    .bind(organization_id)
    .fetch_one(store.pool())
    .await
    .expect("count reconciliation outbox");
    assert_eq!(event_count, 1);
    assert_eq!(outbox_count, 1);
    assert!(
        !store
            .finalize_reconciled_attempt(
                organization_id,
                admission.attempt_id,
                claim.fence,
                "operator-a",
                TerminalOutcome::Succeeded,
                json!({"resolution": "verified externally"}),
            )
            .await
            .expect("unresolved effect blocks terminal reconciliation")
    );
    assert!(
        store
            .confirm_uncertain_effect(
                organization_id,
                admission.attempt_id,
                claim.fence,
                "deploy",
                EffectClass::NonIdempotent,
                &payload,
            )
            .await
            .expect("confirm current-epoch uncertain effect")
    );
    assert!(
        store
            .uncertain_effects(organization_id)
            .await
            .expect("list after current-epoch reconciliation")
            .is_empty()
    );
    assert!(
        store
            .finalize_reconciled_attempt(
                organization_id,
                admission.attempt_id,
                claim.fence,
                "operator-a",
                TerminalOutcome::Succeeded,
                json!({"resolution": "verified externally"}),
            )
            .await
            .expect("finish current-epoch reconciliation")
    );
    let terminal = store
        .build_snapshot(organization_id, project_id, admission.build_id)
        .await
        .expect("load terminal reconciled build")
        .expect("terminal build exists");
    assert_eq!(terminal.build_status, "succeeded");
    assert_eq!(terminal.attempt_status, "succeeded");
    let reconciliation_publications: (i64, i64) = sqlx::query_as(
        "SELECT
           (SELECT count(*) FROM build_events
            WHERE organization_id = $1
              AND build_id = $2
              AND kind = 'attempt.reconciliation_terminal'
              AND payload->>'actor' = 'operator-a'),
           (SELECT count(*) FROM outbox
            WHERE organization_id = $1
              AND aggregate_id = $2
              AND topic = 'attempt.reconciliation_terminal'
              AND payload->>'actor' = 'operator-a')",
    )
    .bind(organization_id)
    .bind(admission.build_id)
    .fetch_one(store.pool())
    .await
    .expect("read reconciliation audit publications");
    assert_eq!(reconciliation_publications, (1, 1));
}

#[tokio::test]
async fn expired_confirmed_non_idempotent_effect_cannot_be_replayed() {
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
            "confirmed-effect-expiry",
        )
        .await
        .expect("create tenant");
    let admission = store
        .admit_build(&NewBuild {
            organization_id,
            project_id,
            idempotency_key: "confirmed-effect-expiry".into(),
            pipeline_digest: [40; 32],
            node_key: "deploy".into(),
            required_capabilities: vec!["linux".into()],
            required_trust_pool: "trusted".into(),
            priority: 0,
            execution_spec: json!({}),
        })
        .await
        .expect("admit confirmed effect work");
    let claim = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "scheduler-a".into(),
            agent_id: "agent-a".into(),
            capabilities: vec!["linux".into()],
            trust_pool: "trusted".into(),
            lease_seconds: 300,
            fairness_seed: 1,
        })
        .await
        .expect("claim confirmed effect work")
        .expect("claim exists");
    assert!(
        store
            .accept_offer(
                organization_id,
                admission.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "agent-a",
            )
            .await
            .expect("accept confirmed effect work")
    );
    let payload = json!({"destination": "production", "release": "r2"});
    for status in [
        EffectStatus::Prepared,
        EffectStatus::Applied,
        EffectStatus::Confirmed,
    ] {
        assert!(
            store
                .checkpoint_effect(
                    organization_id,
                    admission.attempt_id,
                    claim.fence,
                    claim.restore_epoch,
                    "agent-a",
                    "deploy",
                    EffectClass::NonIdempotent,
                    status,
                    &payload,
                )
                .await
                .expect("advance confirmed non-idempotent effect")
        );
    }
    sqlx::query(
        "UPDATE attempts SET lease_expires_at = clock_timestamp() - interval '1 second'
         WHERE organization_id = $1 AND id = $2",
    )
    .bind(organization_id)
    .bind(admission.attempt_id)
    .execute(store.pool())
    .await
    .expect("expire confirmed effect lease");
    assert!(
        store
            .requeue_one_expired(organization_id)
            .await
            .expect("route confirmed effect to reconciliation")
    );
    let snapshot = store
        .build_snapshot(organization_id, project_id, admission.build_id)
        .await
        .expect("load confirmed reconciliation")
        .expect("build exists");
    assert_eq!(snapshot.attempt_status, "reconciliation_required");
    let effect_status = sqlx::query_scalar::<_, String>(
        "SELECT status
         FROM attempt_effects
         WHERE organization_id = $1
           AND attempt_id = $2
           AND fence = $3
           AND effect_key = 'deploy'",
    )
    .bind(organization_id)
    .bind(admission.attempt_id)
    .bind(claim.fence)
    .fetch_one(store.pool())
    .await
    .expect("read confirmed effect");
    assert_eq!(effect_status, "confirmed");
    assert!(
        store
            .claim_next(&ClaimRequest {
                organization_id,
                scheduler_id: "scheduler-b".into(),
                agent_id: "agent-b".into(),
                capabilities: vec!["linux".into()],
                trust_pool: "trusted".into(),
                lease_seconds: 300,
                fairness_seed: 2,
            })
            .await
            .expect("check for automatic replay")
            .is_none()
    );
    assert_eq!(
        store
            .schedule_retry(
                organization_id,
                admission.attempt_id,
                3,
                "agent disappeared after confirmation",
            )
            .await
            .expect("refuse non-idempotent retry"),
        RetryDecision::Ineligible
    );
    assert!(
        store
            .finalize_reconciled_attempt(
                organization_id,
                admission.attempt_id,
                claim.fence,
                "operator-b",
                TerminalOutcome::Succeeded,
                json!({"resolution": "effect confirmation was durable"}),
            )
            .await
            .expect("finish confirmed-effect reconciliation")
    );
    let terminal = store
        .build_snapshot(organization_id, project_id, admission.build_id)
        .await
        .expect("load terminal confirmed-effect build")
        .expect("terminal build exists");
    assert_eq!(terminal.build_status, "succeeded");
    assert_eq!(terminal.attempt_status, "succeeded");
}

#[tokio::test]
async fn reconciliation_retry_and_terminal_decisions_are_mutually_exclusive() {
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
            "reconciliation-decision",
        )
        .await
        .expect("create tenant");
    let admission = store
        .admit_build(&NewBuild {
            organization_id,
            project_id,
            idempotency_key: "reconciliation-decision".into(),
            pipeline_digest: [42; 32],
            node_key: "recover".into(),
            required_capabilities: vec!["linux".into()],
            required_trust_pool: "trusted".into(),
            priority: 0,
            execution_spec: json!({}),
        })
        .await
        .expect("admit reconciliation work");
    let mut reconciliation_tx = store.pool().begin().await.expect("begin reconciliation");
    sqlx::query(
        "UPDATE attempts
         SET status = 'reconciliation_required',
             lease_owner = NULL,
             lease_expires_at = NULL
         WHERE organization_id = $1 AND id = $2",
    )
    .bind(organization_id)
    .bind(admission.attempt_id)
    .execute(&mut *reconciliation_tx)
    .await
    .expect("route attempt to reconciliation");
    sqlx::query(
        "UPDATE nodes
         SET status = 'reconciliation_required'
         WHERE organization_id = $1 AND id = $2",
    )
    .bind(organization_id)
    .bind(admission.node_id)
    .execute(&mut *reconciliation_tx)
    .await
    .expect("route node to reconciliation");
    sqlx::query(
        "UPDATE builds
         SET status = 'reconciliation_required'
         WHERE organization_id = $1 AND id = $2",
    )
    .bind(organization_id)
    .bind(admission.build_id)
    .execute(&mut *reconciliation_tx)
    .await
    .expect("route build to reconciliation");
    reconciliation_tx
        .commit()
        .await
        .expect("commit reconciliation state");
    let retry = store
        .schedule_retry(
            organization_id,
            admission.attempt_id,
            3,
            "operator selected retry",
        )
        .await
        .expect("schedule reconciliation retry");
    let RetryDecision::Scheduled {
        attempt_id: child_id,
        created: true,
        ..
    } = retry
    else {
        panic!("expected new retry child, got {retry:?}");
    };
    assert!(
        !store
            .finalize_reconciled_attempt(
                organization_id,
                admission.attempt_id,
                0,
                "operator-d",
                TerminalOutcome::Succeeded,
                json!({"resolution": "must not override scheduled retry"}),
            )
            .await
            .expect("terminal reconciliation loses after retry decision")
    );
    let child = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "scheduler-after-reconciliation".into(),
            agent_id: "agent-after-reconciliation".into(),
            capabilities: vec!["linux".into()],
            trust_pool: "trusted".into(),
            lease_seconds: 300,
            fairness_seed: 1,
        })
        .await
        .expect("claim scheduled retry")
        .expect("retry remains claimable");
    assert_eq!(child.attempt_id, child_id);

    let exhausted = store
        .admit_build(&NewBuild {
            organization_id,
            project_id,
            idempotency_key: "reconciliation-dead-letter".into(),
            pipeline_digest: [43; 32],
            node_key: "exhausted".into(),
            required_capabilities: vec!["linux".into()],
            required_trust_pool: "trusted".into(),
            priority: 0,
            execution_spec: json!({}),
        })
        .await
        .expect("admit exhausted reconciliation work");
    let mut exhausted_tx = store.pool().begin().await.expect("begin exhausted state");
    for (table, id) in [
        ("attempts", exhausted.attempt_id),
        ("nodes", exhausted.node_id),
        ("builds", exhausted.build_id),
    ] {
        sqlx::query(&format!(
            "UPDATE {table}
             SET status = 'reconciliation_required'
             WHERE organization_id = $1 AND id = $2"
        ))
        .bind(organization_id)
        .bind(id)
        .execute(&mut *exhausted_tx)
        .await
        .expect("route exhausted hierarchy to reconciliation");
    }
    exhausted_tx
        .commit()
        .await
        .expect("commit exhausted reconciliation state");
    assert_eq!(
        store
            .schedule_retry(
                organization_id,
                exhausted.attempt_id,
                1,
                "retry budget exhausted",
            )
            .await
            .expect("dead-letter exhausted reconciliation"),
        RetryDecision::DeadLettered
    );
    assert_eq!(
        store
            .schedule_retry(
                organization_id,
                exhausted.attempt_id,
                3,
                "larger later budget cannot overturn the dead letter",
            )
            .await
            .expect("dead-letter replay remains terminal"),
        RetryDecision::DeadLettered
    );
    let exhausted_snapshot = store
        .build_snapshot(organization_id, project_id, exhausted.build_id)
        .await
        .expect("load dead-lettered reconciliation")
        .expect("dead-lettered build exists");
    assert_eq!(exhausted_snapshot.attempt_status, "failed");
    assert_eq!(exhausted_snapshot.build_status, "failed");
    let exhausted_node_status = sqlx::query_scalar::<_, String>(
        "SELECT status
         FROM nodes
         WHERE organization_id = $1 AND id = $2",
    )
    .bind(organization_id)
    .bind(exhausted.node_id)
    .fetch_one(store.pool())
    .await
    .expect("read dead-lettered node");
    assert_eq!(exhausted_node_status, "failed");
    let exhausted_children = sqlx::query_scalar::<_, i64>(
        "SELECT count(*)
         FROM attempts
         WHERE organization_id = $1 AND retry_of = $2",
    )
    .bind(organization_id)
    .bind(exhausted.attempt_id)
    .fetch_one(store.pool())
    .await
    .expect("count exhausted retry children");
    assert_eq!(exhausted_children, 0);
    assert!(
        !store
            .finalize_reconciled_attempt(
                organization_id,
                exhausted.attempt_id,
                0,
                "operator-d",
                TerminalOutcome::Failed,
                json!({"resolution": "must not override dead letter"}),
            )
            .await
            .expect("terminal reconciliation loses after dead-letter decision")
    );

    let terminal_first = store
        .admit_build(&NewBuild {
            organization_id,
            project_id,
            idempotency_key: "reconciliation-terminal-first".into(),
            pipeline_digest: [44; 32],
            node_key: "terminal-first".into(),
            required_capabilities: vec!["linux".into()],
            required_trust_pool: "trusted".into(),
            priority: 0,
            execution_spec: json!({}),
        })
        .await
        .expect("admit terminal-first reconciliation work");
    let mut terminal_first_tx = store
        .pool()
        .begin()
        .await
        .expect("begin terminal-first state");
    for (table, id) in [
        ("attempts", terminal_first.attempt_id),
        ("nodes", terminal_first.node_id),
        ("builds", terminal_first.build_id),
    ] {
        sqlx::query(&format!(
            "UPDATE {table}
             SET status = 'reconciliation_required'
             WHERE organization_id = $1 AND id = $2"
        ))
        .bind(organization_id)
        .bind(id)
        .execute(&mut *terminal_first_tx)
        .await
        .expect("route terminal-first hierarchy to reconciliation");
    }
    terminal_first_tx
        .commit()
        .await
        .expect("commit terminal-first reconciliation state");
    let terminal_first_summary = json!({"resolution": "terminal reconciliation wins"});
    assert!(
        store
            .finalize_reconciled_attempt(
                organization_id,
                terminal_first.attempt_id,
                0,
                "operator-d",
                TerminalOutcome::Failed,
                terminal_first_summary.clone(),
            )
            .await
            .expect("terminalize reconciliation before retry")
    );
    assert!(
        store
            .finalize_reconciled_attempt(
                organization_id,
                terminal_first.attempt_id,
                0,
                "operator-d",
                TerminalOutcome::Failed,
                terminal_first_summary,
            )
            .await
            .expect("response-loss terminal reconciliation replay succeeds")
    );
    assert!(
        !store
            .finalize_reconciled_attempt(
                organization_id,
                terminal_first.attempt_id,
                0,
                "different-operator",
                TerminalOutcome::Failed,
                json!({"resolution": "terminal reconciliation wins"}),
            )
            .await
            .expect("conflicting terminal reconciliation replay is rejected")
    );
    let terminal_publications: (i64, i64) = sqlx::query_as(
        "SELECT
           (SELECT count(*) FROM build_events
            WHERE organization_id = $1
              AND build_id = $2
              AND kind = 'attempt.reconciliation_terminal'),
           (SELECT count(*) FROM outbox
            WHERE organization_id = $1
              AND aggregate_id = $2
              AND topic = 'attempt.reconciliation_terminal')",
    )
    .bind(organization_id)
    .bind(terminal_first.build_id)
    .fetch_one(store.pool())
    .await
    .expect("count response-loss terminal publications");
    assert_eq!(terminal_publications, (1, 1));
    assert_eq!(
        store
            .schedule_retry(
                organization_id,
                terminal_first.attempt_id,
                3,
                "must not override terminal reconciliation",
            )
            .await
            .expect("retry loses after terminal reconciliation"),
        RetryDecision::Ineligible
    );
}

#[tokio::test]
async fn build_logs_exclude_chunks_from_a_superseded_fence() {
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
            "logs",
        )
        .await
        .expect("create tenant");
    let admission = store
        .admit_build(&NewBuild {
            organization_id,
            project_id,
            idempotency_key: "fenced-logs".into(),
            pipeline_digest: [19; 32],
            node_key: "stage-1".into(),
            required_capabilities: vec!["linux".into()],
            required_trust_pool: "trusted".into(),
            priority: 0,
            execution_spec: json!({}),
        })
        .await
        .expect("admit build");
    let first = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "scheduler-a".into(),
            agent_id: "agent-a".into(),
            capabilities: vec!["linux".into()],
            trust_pool: "trusted".into(),
            lease_seconds: 30,
            fairness_seed: 1,
        })
        .await
        .expect("first claim")
        .expect("first claim exists");
    assert!(
        store
            .accept_offer(
                organization_id,
                first.attempt_id,
                first.fence,
                first.restore_epoch,
                "agent-a",
            )
            .await
            .expect("accept first")
    );
    assert!(
        store
            .append_log(&NewLogChunk {
                organization_id,
                attempt_id: first.attempt_id,
                fence: first.fence,
                restore_epoch: first.restore_epoch,
                agent_id: "agent-a",
                sequence: 0,
                stream: "stdout",
                content: b"superseded\n",
            })
            .await
            .expect("append first-fence log")
    );
    sqlx::query(
        "UPDATE attempts SET lease_expires_at = clock_timestamp() - interval '1 second'
         WHERE id = $1",
    )
    .bind(first.attempt_id)
    .execute(store.pool())
    .await
    .expect("expire first fence");
    assert!(
        store
            .requeue_one_expired(organization_id)
            .await
            .expect("requeue first fence")
    );
    let second = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "scheduler-b".into(),
            agent_id: "agent-b".into(),
            capabilities: vec!["linux".into()],
            trust_pool: "trusted".into(),
            lease_seconds: 30,
            fairness_seed: 1,
        })
        .await
        .expect("second claim")
        .expect("second claim exists");
    assert_eq!(second.fence, first.fence + 1);
    assert!(
        store
            .accept_offer(
                organization_id,
                second.attempt_id,
                second.fence,
                second.restore_epoch,
                "agent-b",
            )
            .await
            .expect("accept second")
    );
    assert!(
        store
            .append_log(&NewLogChunk {
                organization_id,
                attempt_id: second.attempt_id,
                fence: second.fence,
                restore_epoch: second.restore_epoch,
                agent_id: "agent-b",
                sequence: 0,
                stream: "stdout",
                content: b"current\n",
            })
            .await
            .expect("append current-fence log")
    );
    assert!(
        !store
            .append_log(&NewLogChunk {
                organization_id,
                attempt_id: second.attempt_id,
                fence: second.fence,
                restore_epoch: second.restore_epoch,
                agent_id: "agent-b",
                sequence: 66,
                stream: "stdout",
                content: b"",
            })
            .await
            .expect("reject out-of-range empty log chunk")
    );
    let logs = store
        .build_logs(organization_id, project_id, admission.build_id)
        .await
        .expect("read build logs");
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].fence, second.fence);
    assert_eq!(logs[0].content, b"current\n");
}

#[tokio::test]
async fn effects_are_monotonic_and_uncertain_work_is_explicit() {
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
            "effects",
        )
        .await
        .expect("create tenant");
    let admission = store
        .admit_build(&NewBuild {
            organization_id,
            project_id,
            idempotency_key: "effect-ledger".into(),
            pipeline_digest: [23; 32],
            node_key: "stage-1".into(),
            required_capabilities: vec!["linux".into()],
            required_trust_pool: "trusted".into(),
            priority: 0,
            execution_spec: json!({}),
        })
        .await
        .expect("admit build");
    let claim = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "effect-scheduler".into(),
            agent_id: "effect-agent".into(),
            capabilities: vec!["linux".into()],
            trust_pool: "trusted".into(),
            lease_seconds: 300,
            fairness_seed: 1,
        })
        .await
        .expect("claim effect work")
        .expect("effect work exists");
    assert!(
        store
            .accept_offer(
                organization_id,
                admission.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "effect-agent",
            )
            .await
            .expect("accept effect work")
    );
    let payload = json!({"destination": "deploy/production", "release": "r1"});
    assert!(
        !store
            .checkpoint_effect(
                organization_id,
                admission.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "wrong-agent",
                "deploy",
                EffectClass::NonIdempotent,
                EffectStatus::Prepared,
                &payload,
            )
            .await
            .expect("reject effect from non-owner")
    );
    let (first_prepare, concurrent_replay) = tokio::join!(
        store.checkpoint_effect(
            organization_id,
            admission.attempt_id,
            claim.fence,
            claim.restore_epoch,
            "effect-agent",
            "deploy",
            EffectClass::NonIdempotent,
            EffectStatus::Prepared,
            &payload,
        ),
        store.checkpoint_effect(
            organization_id,
            admission.attempt_id,
            claim.fence,
            claim.restore_epoch,
            "effect-agent",
            "deploy",
            EffectClass::NonIdempotent,
            EffectStatus::Prepared,
            &payload,
        ),
    );
    assert!(first_prepare.expect("prepare effect"));
    assert!(concurrent_replay.expect("concurrent prepared replay"));
    assert!(
        store
            .checkpoint_effect(
                organization_id,
                admission.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "effect-agent",
                "deploy",
                EffectClass::NonIdempotent,
                EffectStatus::Uncertain,
                &payload,
            )
            .await
            .expect("mark uncertain")
    );
    assert!(
        !store
            .checkpoint_effect(
                organization_id,
                admission.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "effect-agent",
                "deploy",
                EffectClass::NonIdempotent,
                EffectStatus::Applied,
                &payload,
            )
            .await
            .expect("reject regression")
    );
    assert!(
        !store
            .checkpoint_effect(
                organization_id,
                admission.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "effect-agent",
                "deploy",
                EffectClass::NonIdempotent,
                EffectStatus::Confirmed,
                &json!({"destination": "deploy/production", "release": "r2"}),
            )
            .await
            .expect("reject payload substitution")
    );
    let updated_at_before: String = sqlx::query_scalar(
        "SELECT updated_at::text
         FROM attempt_effects
         WHERE organization_id = $1
           AND attempt_id = $2
           AND fence = $3
           AND effect_key = 'deploy'",
    )
    .bind(organization_id)
    .bind(admission.attempt_id)
    .bind(claim.fence)
    .fetch_one(store.pool())
    .await
    .expect("read effect timestamp before replay");
    assert!(
        store
            .checkpoint_effect(
                organization_id,
                admission.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "effect-agent",
                "deploy",
                EffectClass::NonIdempotent,
                EffectStatus::Uncertain,
                &payload,
            )
            .await
            .expect("replay uncertain checkpoint")
    );
    let updated_at_after: String = sqlx::query_scalar(
        "SELECT updated_at::text
         FROM attempt_effects
         WHERE organization_id = $1
           AND attempt_id = $2
           AND fence = $3
           AND effect_key = 'deploy'",
    )
    .bind(organization_id)
    .bind(admission.attempt_id)
    .bind(claim.fence)
    .fetch_one(store.pool())
    .await
    .expect("read effect timestamp after replay");
    assert_eq!(updated_at_after, updated_at_before);
    let uncertain = store
        .uncertain_effects(organization_id)
        .await
        .expect("list uncertain effects");
    assert_eq!(uncertain.len(), 1);
    assert_eq!(uncertain[0].attempt_id, admission.attempt_id);
    assert_eq!(uncertain[0].fence, claim.fence);
    assert_eq!(uncertain[0].effect_key, "deploy");
    assert_eq!(uncertain[0].effect_class, EffectClass::NonIdempotent);
    assert_eq!(uncertain[0].status, EffectStatus::Uncertain);
    assert_eq!(uncertain[0].payload, payload);
    assert!(
        !store
            .finalize_attempt(
                organization_id,
                admission.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "effect-agent",
                TerminalOutcome::Succeeded,
                json!({"result": "must reconcile"}),
            )
            .await
            .expect("reject ordinary terminal publication with uncertain effect")
    );
    let routed_status: (String, Option<String>, String, String) = sqlx::query_as(
        "SELECT a.status, a.lease_owner, n.status, b.status
         FROM attempts AS a
         JOIN nodes AS n
           ON n.organization_id = a.organization_id
          AND n.id = a.node_id
         JOIN builds AS b
           ON b.organization_id = n.organization_id
          AND b.id = n.build_id
         WHERE a.organization_id = $1 AND a.id = $2",
    )
    .bind(organization_id)
    .bind(admission.attempt_id)
    .fetch_one(store.pool())
    .await
    .expect("read reconciliation route");
    assert_eq!(
        routed_status,
        (
            "reconciliation_required".into(),
            None,
            "reconciliation_required".into(),
            "reconciliation_required".into(),
        )
    );
    let route_publications: (i64, i64) = sqlx::query_as(
        "SELECT
           (SELECT count(*)
            FROM build_events
            WHERE organization_id = $1
              AND build_id = $2
              AND kind = 'attempt.terminal_reconciliation_required'),
           (SELECT count(*)
            FROM outbox
            WHERE organization_id = $1
              AND aggregate_id = $2
              AND topic = 'attempt.terminal_reconciliation_required')",
    )
    .bind(organization_id)
    .bind(admission.build_id)
    .fetch_one(store.pool())
    .await
    .expect("count reconciliation route publications");
    assert_eq!(route_publications, (1, 1));
    assert!(
        !store
            .checkpoint_effect(
                organization_id,
                admission.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "effect-agent",
                "deploy",
                EffectClass::NonIdempotent,
                EffectStatus::Confirmed,
                &payload,
            )
            .await
            .expect("ordinary checkpoint authority stays fenced")
    );
    assert!(
        store
            .confirm_uncertain_effect(
                organization_id,
                admission.attempt_id,
                claim.fence,
                "deploy",
                EffectClass::NonIdempotent,
                &payload,
            )
            .await
            .expect("confirm uncertain effect through reconciliation")
    );
    assert!(
        store
            .uncertain_effects(organization_id)
            .await
            .expect("list after reconciliation")
            .is_empty()
    );
    assert!(
        store
            .finalize_reconciled_attempt(
                organization_id,
                admission.attempt_id,
                claim.fence,
                "effect-operator",
                TerminalOutcome::Succeeded,
                json!({"result": "reconciled"}),
            )
            .await
            .expect("publish reconciled terminal outcome")
    );
}

#[tokio::test]
async fn retry_history_is_immutable_idempotent_and_bounded() {
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
            "retry",
        )
        .await
        .expect("create tenant");
    let admission = store
        .admit_build(&NewBuild {
            organization_id,
            project_id,
            idempotency_key: "bounded-retry".into(),
            pipeline_digest: [24; 32],
            node_key: "stage-1".into(),
            required_capabilities: vec!["linux".into()],
            required_trust_pool: "trusted".into(),
            priority: 0,
            execution_spec: json!({}),
        })
        .await
        .expect("admit build");
    let first = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "scheduler-a".into(),
            agent_id: "agent-a".into(),
            capabilities: vec!["linux".into()],
            trust_pool: "trusted".into(),
            lease_seconds: 30,
            fairness_seed: 1,
        })
        .await
        .expect("claim first")
        .expect("first claim exists");
    assert!(
        store
            .accept_offer(
                organization_id,
                first.attempt_id,
                first.fence,
                first.restore_epoch,
                "agent-a",
            )
            .await
            .expect("accept first")
    );
    assert!(
        store
            .append_log(&NewLogChunk {
                organization_id,
                attempt_id: first.attempt_id,
                fence: first.fence,
                restore_epoch: first.restore_epoch,
                agent_id: "agent-a",
                sequence: 0,
                stream: "stdout",
                content: b"first attempt\n",
            })
            .await
            .expect("append first-attempt log")
    );
    assert!(
        store
            .finalize_attempt(
                organization_id,
                first.attempt_id,
                first.fence,
                first.restore_epoch,
                "agent-a",
                TerminalOutcome::Failed,
                json!({"reason": "transient"}),
            )
            .await
            .expect("fail first")
    );
    assert_eq!(
        store
            .schedule_retry(organization_id, first.attempt_id, 2, &"x".repeat(1025))
            .await
            .expect("reject oversized retry reason"),
        RetryDecision::Ineligible
    );
    let scheduled = store
        .schedule_retry(organization_id, first.attempt_id, 2, "transient")
        .await
        .expect("schedule retry");
    let RetryDecision::Scheduled {
        attempt_id: second_id,
        ordinal: 2,
        created: true,
    } = scheduled
    else {
        panic!("expected new second attempt, got {scheduled:?}");
    };
    assert_eq!(
        store
            .schedule_retry(organization_id, first.attempt_id, 2, "transient")
            .await
            .expect("replay retry decision"),
        RetryDecision::Scheduled {
            attempt_id: second_id,
            ordinal: 2,
            created: false,
        }
    );
    let snapshot = store
        .build_snapshot(organization_id, project_id, admission.build_id)
        .await
        .expect("read current snapshot")
        .expect("build exists");
    assert_eq!(snapshot.attempt_id, second_id);
    assert_eq!(snapshot.attempt_status, "queued");
    let second = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "scheduler-b".into(),
            agent_id: "agent-b".into(),
            capabilities: vec!["linux".into()],
            trust_pool: "trusted".into(),
            lease_seconds: 30,
            fairness_seed: 1,
        })
        .await
        .expect("claim second")
        .expect("second claim exists");
    assert_eq!(second.attempt_id, second_id);
    assert!(
        store
            .accept_offer(
                organization_id,
                second.attempt_id,
                second.fence,
                second.restore_epoch,
                "agent-b",
            )
            .await
            .expect("accept second")
    );
    assert!(
        store
            .append_log(&NewLogChunk {
                organization_id,
                attempt_id: second.attempt_id,
                fence: second.fence,
                restore_epoch: second.restore_epoch,
                agent_id: "agent-b",
                sequence: 0,
                stream: "stdout",
                content: b"second attempt\n",
            })
            .await
            .expect("append second-attempt log")
    );
    assert!(
        store
            .finalize_attempt(
                organization_id,
                second.attempt_id,
                second.fence,
                second.restore_epoch,
                "agent-b",
                TerminalOutcome::Failed,
                json!({"reason": "persistent"}),
            )
            .await
            .expect("fail second")
    );
    let logs = store
        .build_logs(organization_id, project_id, admission.build_id)
        .await
        .expect("read retry logs");
    assert_eq!(
        logs.iter()
            .map(|chunk| chunk.content.as_slice())
            .collect::<Vec<_>>(),
        vec![
            b"first attempt\n".as_slice(),
            b"second attempt\n".as_slice()
        ]
    );
    assert_eq!(
        store
            .schedule_retry(organization_id, second.attempt_id, 2, "persistent")
            .await
            .expect("exhaust retry"),
        RetryDecision::DeadLettered
    );
    assert_eq!(
        store
            .schedule_retry(organization_id, second.attempt_id, 2, "persistent")
            .await
            .expect("replay exhausted retry"),
        RetryDecision::DeadLettered
    );
    let rows = sqlx::query_as::<_, (Uuid, i32, Option<Uuid>, String)>(
        "SELECT id, ordinal, retry_of, status
         FROM attempts
         WHERE organization_id = $1
         ORDER BY ordinal",
    )
    .bind(organization_id)
    .fetch_all(store.pool())
    .await
    .expect("read immutable attempt history");
    assert_eq!(
        rows,
        vec![
            (first.attempt_id, 1, None, "failed".to_owned()),
            (
                second.attempt_id,
                2,
                Some(first.attempt_id),
                "failed".to_owned()
            ),
        ]
    );
    let dead_letters = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM dead_letters
         WHERE organization_id = $1 AND attempt_id = $2",
    )
    .bind(organization_id)
    .bind(second.attempt_id)
    .fetch_one(store.pool())
    .await
    .expect("read dead letter");
    assert_eq!(dead_letters, 1);
    let dead_letter_publications: (i64, i64) = sqlx::query_as(
        "SELECT
           (SELECT count(*) FROM build_events
            WHERE organization_id = $1
              AND build_id = $2
              AND kind = 'attempt.dead_lettered'),
           (SELECT count(*) FROM outbox
            WHERE organization_id = $1
              AND aggregate_id = $2
              AND topic = 'attempt.dead_lettered')",
    )
    .bind(organization_id)
    .bind(admission.build_id)
    .fetch_one(store.pool())
    .await
    .expect("count one dead-letter publication");
    assert_eq!(dead_letter_publications, (1, 1));
}

#[tokio::test]
async fn object_references_are_fenced_immutable_and_report_gaps() {
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
            "objects",
        )
        .await
        .expect("create tenant");
    let admission = store
        .admit_build(&NewBuild {
            organization_id,
            project_id,
            idempotency_key: "object-reference".into(),
            pipeline_digest: [25; 32],
            node_key: "stage-1".into(),
            required_capabilities: vec!["linux".into()],
            required_trust_pool: "trusted".into(),
            priority: 0,
            execution_spec: json!({}),
        })
        .await
        .expect("admit build");
    let claim = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "scheduler".into(),
            agent_id: "agent".into(),
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
            .accept_offer(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "agent",
            )
            .await
            .expect("accept")
    );
    let digest: [u8; 32] = Sha256::digest(organization_id.as_bytes()).into();
    assert!(
        store
            .register_object(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "agent",
                ObjectKind::Artifact,
                "distribution.tar.zst",
                digest,
                1024,
            )
            .await
            .expect("register object")
    );
    assert!(
        !store
            .register_object(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "agent",
                ObjectKind::Artifact,
                "distribution.tar.zst",
                [42; 32],
                1024,
            )
            .await
            .expect("reject identity mutation")
    );
    assert!(
        !store
            .register_object(
                organization_id,
                claim.attempt_id,
                claim.fence + 1,
                claim.restore_epoch,
                "agent",
                ObjectKind::Artifact,
                "stale.tar.zst",
                [43; 32],
                1,
            )
            .await
            .expect("reject stale fence")
    );
    assert!(
        store
            .set_object_status(
                organization_id,
                claim.attempt_id,
                claim.fence,
                ObjectKind::Artifact,
                "distribution.tar.zst",
                digest,
                ObjectStatus::Missing,
            )
            .await
            .expect("record missing object")
    );
    assert!(
        !store
            .set_object_status(
                organization_id,
                claim.attempt_id,
                claim.fence,
                ObjectKind::Artifact,
                "distribution.tar.zst",
                [99; 32],
                ObjectStatus::Available,
            )
            .await
            .expect("reject wrong digest")
    );
    sqlx::query(
        "INSERT INTO object_deletion_claims (
             object_digest, claim_token, status
         )
         VALUES ($1, $2, 'claimed')",
    )
    .bind(digest.as_slice())
    .bind(Uuid::new_v4())
    .execute(store.pool())
    .await
    .expect("install an exact deletion fence");
    assert!(
        !store
            .set_object_status(
                organization_id,
                claim.attempt_id,
                claim.fence,
                ObjectKind::Artifact,
                "distribution.tar.zst",
                digest,
                ObjectStatus::Available,
            )
            .await
            .expect("fence restoration against deletion")
    );
    let objects = store
        .build_objects(organization_id, project_id, admission.build_id)
        .await
        .expect("read object references");
    assert_eq!(objects.len(), 1);
    assert_eq!(objects[0].digest, digest);
    assert_eq!(objects[0].status, ObjectStatus::Missing);
}

#[tokio::test]
async fn retention_is_monotonic_and_legal_holds_block_deletion() {
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
            "retention",
        )
        .await
        .expect("create tenant");
    let admission = store
        .admit_build(&NewBuild {
            organization_id,
            project_id,
            idempotency_key: "retained-object".into(),
            pipeline_digest: [51; 32],
            node_key: "stage-1".into(),
            required_capabilities: Vec::new(),
            required_trust_pool: "trusted".into(),
            priority: 0,
            execution_spec: json!({}),
        })
        .await
        .expect("admit build");
    let claim = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "scheduler".into(),
            agent_id: "agent".into(),
            capabilities: Vec::new(),
            trust_pool: "trusted".into(),
            lease_seconds: 30,
            fairness_seed: 1,
        })
        .await
        .expect("claim")
        .expect("claim exists");
    assert!(
        store
            .accept_offer(
                organization_id,
                admission.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "agent",
            )
            .await
            .expect("accept")
    );
    let digest = [52; 32];
    assert!(
        store
            .register_object(
                organization_id,
                admission.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "agent",
                ObjectKind::Artifact,
                "evidence.tar.zst",
                digest,
                4096,
            )
            .await
            .expect("register retained object")
    );
    assert!(
        store
            .retain_object_for(organization_id, digest, 0)
            .await
            .expect("assign expired retention")
    );
    assert!(
        store
            .objects_globally_eligible_for_deletion(10_000)
            .await
            .expect("list expired content")
            .contains(&digest)
    );

    let second_organization_id = Uuid::new_v4();
    let second_project_id = Uuid::new_v4();
    store
        .create_project(
            second_organization_id,
            &format!("org-{second_organization_id}"),
            second_project_id,
            "shared-retention",
        )
        .await
        .expect("create second tenant");
    let second_admission = store
        .admit_build(&NewBuild {
            organization_id: second_organization_id,
            project_id: second_project_id,
            idempotency_key: "shared-digest".into(),
            pipeline_digest: [53; 32],
            node_key: "stage-1".into(),
            required_capabilities: Vec::new(),
            required_trust_pool: "trusted".into(),
            priority: 0,
            execution_spec: json!({}),
        })
        .await
        .expect("admit second tenant build");
    let second_claim = store
        .claim_next(&ClaimRequest {
            organization_id: second_organization_id,
            scheduler_id: "scheduler".into(),
            agent_id: "agent".into(),
            capabilities: Vec::new(),
            trust_pool: "trusted".into(),
            lease_seconds: 30,
            fairness_seed: 1,
        })
        .await
        .expect("claim second tenant build")
        .expect("second tenant claim exists");
    assert!(
        store
            .accept_offer(
                second_organization_id,
                second_admission.attempt_id,
                second_claim.fence,
                second_claim.restore_epoch,
                "agent",
            )
            .await
            .expect("accept second tenant offer")
    );
    assert!(
        store
            .register_object(
                second_organization_id,
                second_admission.attempt_id,
                second_claim.fence,
                second_claim.restore_epoch,
                "agent",
                ObjectKind::Artifact,
                "shared-evidence.tar.zst",
                digest,
                4096,
            )
            .await
            .expect("register shared digest")
    );
    assert!(
        !store
            .objects_globally_eligible_for_deletion(10)
            .await
            .expect("missing second-tenant retention is fail-closed")
            .contains(&digest)
    );
    assert!(
        store
            .retain_object_for(second_organization_id, digest, 0)
            .await
            .expect("expire second-tenant retention")
    );
    assert!(
        store
            .objects_globally_eligible_for_deletion(10_000)
            .await
            .expect("all referencing tenants have expired retention")
            .contains(&digest)
    );
    assert!(
        store
            .acquire_legal_hold(
                second_organization_id,
                digest,
                "shared-case",
                "second-tenant preservation",
            )
            .await
            .expect("acquire second-tenant hold")
    );
    assert!(
        !store
            .objects_globally_eligible_for_deletion(10)
            .await
            .expect("one tenant hold blocks global deletion")
            .contains(&digest)
    );
    assert!(
        store
            .release_legal_hold(second_organization_id, digest, "shared-case")
            .await
            .expect("release second-tenant hold")
    );
    assert!(
        store
            .acquire_legal_hold(
                organization_id,
                digest,
                "case-2026-07",
                "regulatory preservation",
            )
            .await
            .expect("acquire legal hold")
    );
    assert!(
        store
            .acquire_legal_hold(
                organization_id,
                digest,
                "case-2026-07",
                "regulatory preservation",
            )
            .await
            .expect("repeat legal hold idempotently")
    );
    assert!(
        !store
            .objects_globally_eligible_for_deletion(10)
            .await
            .expect("held content is not deletable")
            .contains(&digest)
    );
    assert!(
        !store
            .acquire_legal_hold(
                organization_id,
                digest,
                "case-2026-07",
                "silently changed reason",
            )
            .await
            .expect("reject changed hold identity")
    );
    assert!(
        store
            .release_legal_hold(organization_id, digest, "case-2026-07")
            .await
            .expect("release legal hold")
    );
    assert!(
        !store
            .release_legal_hold(organization_id, digest, "case-2026-07")
            .await
            .expect("repeat release is idempotent")
    );
    let changed_reason = sqlx::query(
        "UPDATE legal_holds
         SET reason = 'rewritten audit history'
         WHERE organization_id = $1
           AND object_digest = $2
           AND hold_key = 'case-2026-07'",
    )
    .bind(organization_id)
    .bind(digest.as_slice())
    .execute(store.pool())
    .await;
    assert!(changed_reason.is_err());
    let reactivated_hold = sqlx::query(
        "UPDATE legal_holds
         SET released_at = NULL
         WHERE organization_id = $1
           AND object_digest = $2
           AND hold_key = 'case-2026-07'",
    )
    .bind(organization_id)
    .bind(digest.as_slice())
    .execute(store.pool())
    .await;
    assert!(reactivated_hold.is_err());
    assert!(
        store
            .objects_globally_eligible_for_deletion(10_000)
            .await
            .expect("released content is deletable")
            .contains(&digest)
    );
    let deletion_claims = store
        .claim_objects_globally_for_deletion(10_000)
        .await
        .expect("claim released content for deletion");
    let deletion_claim = *deletion_claims
        .iter()
        .find(|claim| claim.digest == digest)
        .expect("target digest received a deletion claim");
    assert!(
        store
            .pending_object_deletion_claims(10_000)
            .await
            .expect("recover committed claim after worker restart")
            .contains(&deletion_claim)
    );
    assert!(
        !store
            .complete_object_deletion(deletion_claim)
            .await
            .expect("claim cannot complete before physical-delete authorization")
    );
    assert!(
        !store
            .retain_object_for(organization_id, digest, 3600)
            .await
            .expect("deletion claim blocks retention extension")
    );
    assert!(
        !store
            .acquire_legal_hold(
                organization_id,
                digest,
                "late-case",
                "must lose to deletion claim",
            )
            .await
            .expect("deletion claim blocks legal hold")
    );
    assert!(
        store
            .abandon_object_deletion(deletion_claim)
            .await
            .expect("abandon deletion while physical content exists")
    );
    assert!(
        !store
            .begin_object_deletion(deletion_claim)
            .await
            .expect("abandoned token cannot authorize physical deletion")
    );
    assert!(
        store
            .retain_object_for(organization_id, digest, 3600)
            .await
            .expect("extend retention")
    );
    assert!(
        store
            .retain_object_for(organization_id, digest, 0)
            .await
            .expect("shortening attempt remains idempotent")
    );
    assert!(
        !store
            .objects_globally_eligible_for_deletion(10)
            .await
            .expect("retention extension is monotonic")
            .contains(&digest)
    );

    let disposable_digest = [54; 32];
    assert!(
        store
            .register_object(
                organization_id,
                admission.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "agent",
                ObjectKind::Artifact,
                "disposable.tar.zst",
                disposable_digest,
                1024,
            )
            .await
            .expect("register disposable content")
    );
    assert!(
        store
            .retain_object_for(organization_id, disposable_digest, 0)
            .await
            .expect("expire disposable retention")
    );
    let completed_claims = store
        .claim_objects_globally_for_deletion(10_000)
        .await
        .expect("eligible content is not starved by protected digest prefix");
    let completed_claim = *completed_claims
        .iter()
        .find(|claim| claim.digest == disposable_digest)
        .expect("disposable digest received a deletion claim");
    assert!(
        store
            .pending_object_deletion_claims(10)
            .await
            .expect("recover disposable claim")
            .contains(&completed_claim)
    );
    assert!(
        store
            .begin_object_deletion(completed_claim)
            .await
            .expect("authorize physical deletion")
    );
    assert!(
        store
            .begin_object_deletion(completed_claim)
            .await
            .expect("physical deletion authorization is idempotent")
    );
    assert!(
        !store
            .abandon_object_deletion(completed_claim)
            .await
            .expect("authorized physical deletion cannot be abandoned")
    );
    assert!(
        !store
            .register_object(
                second_organization_id,
                second_admission.attempt_id,
                second_claim.fence,
                second_claim.restore_epoch,
                "agent",
                ObjectKind::Artifact,
                "late-disposable.tar.zst",
                disposable_digest,
                1024,
            )
            .await
            .expect("active deletion claim blocks a new reference")
    );
    assert!(
        store
            .complete_object_deletion(completed_claim)
            .await
            .expect("complete physical deletion claim")
    );
    let first_completion = sqlx::query_scalar::<_, String>(
        "SELECT completed_at::text
         FROM object_deletion_claims
         WHERE object_digest = $1 AND claim_token = $2",
    )
    .bind(completed_claim.digest.as_slice())
    .bind(completed_claim.token)
    .fetch_one(store.pool())
    .await
    .expect("read first completion timestamp");
    assert!(
        store
            .complete_object_deletion(completed_claim)
            .await
            .expect("response-loss completion replay succeeds")
    );
    let replay_completion = sqlx::query_scalar::<_, String>(
        "SELECT completed_at::text
         FROM object_deletion_claims
         WHERE object_digest = $1 AND claim_token = $2",
    )
    .bind(completed_claim.digest.as_slice())
    .bind(completed_claim.token)
    .fetch_one(store.pool())
    .await
    .expect("read replay completion timestamp");
    assert_eq!(replay_completion, first_completion);
    assert!(
        !store
            .pending_object_deletion_claims(10)
            .await
            .expect("completed tombstone is not pending")
            .contains(&completed_claim)
    );
    assert!(
        !store
            .retain_object_for(organization_id, disposable_digest, 3600)
            .await
            .expect("deleted tombstone blocks stale retention")
    );
    assert!(
        !store
            .abandon_object_deletion(completed_claim)
            .await
            .expect("completed tombstone cannot be abandoned")
    );
}

fn recovery_canary_ids() -> (Uuid, Uuid) {
    (
        Uuid::from_u128(0x4d63_4c6f_7669_6e67_0000_0000_0000_0001),
        Uuid::from_u128(0x4d63_4c6f_7669_6e67_0000_0000_0000_0002),
    )
}

#[tokio::test]
#[ignore = "run only by scripts/test-backup-restore.sh against an isolated source"]
async fn backup_restore_canary_seed() {
    let store = test_store().await.expect("isolated source database URL");
    let (organization_id, project_id) = recovery_canary_ids();
    store
        .create_project(
            organization_id,
            "recovery-canary",
            project_id,
            "backup-source",
        )
        .await
        .expect("create recovery canary");
    let admission = store
        .admit_build(&NewBuild {
            organization_id,
            project_id,
            idempotency_key: "backup-restore-canary".into(),
            pipeline_digest: [61; 32],
            node_key: "stage-1".into(),
            required_capabilities: vec!["linux".into()],
            required_trust_pool: "trusted".into(),
            priority: 10,
            execution_spec: json!({"command": "preserve-me"}),
        })
        .await
        .expect("admit recovery canary");
    let claim = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "recovery-scheduler".into(),
            agent_id: "pre-restore-agent".into(),
            capabilities: vec!["linux".into()],
            trust_pool: "trusted".into(),
            lease_seconds: 300,
            fairness_seed: 1,
        })
        .await
        .expect("claim recovery canary")
        .expect("claim exists");
    assert!(
        store
            .accept_offer(
                organization_id,
                admission.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "pre-restore-agent",
            )
            .await
            .expect("accept recovery canary")
    );
    assert!(
        store
            .register_object(
                organization_id,
                admission.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "pre-restore-agent",
                ObjectKind::Result,
                "result.cbor",
                [62; 32],
                2048,
            )
            .await
            .expect("register recovery object")
    );
    let historical_effect = json!({"cache_key": "backup-canary"});
    assert!(
        store
            .checkpoint_effect(
                organization_id,
                admission.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "pre-restore-agent",
                "publish-cache",
                EffectClass::ExternallyIdempotent,
                EffectStatus::Prepared,
                &historical_effect,
            )
            .await
            .expect("prepare effect on historical fence")
    );
    sqlx::query(
        "UPDATE attempts
         SET lease_expires_at = clock_timestamp() - interval '1 second'
         WHERE organization_id = $1 AND id = $2",
    )
    .bind(organization_id)
    .bind(admission.attempt_id)
    .execute(store.pool())
    .await
    .expect("expire first recovery fence");
    assert!(
        store
            .requeue_one_expired(organization_id)
            .await
            .expect("requeue first recovery fence")
    );
    let reclaimed = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "recovery-scheduler".into(),
            agent_id: "post-reclaim-agent".into(),
            capabilities: vec!["linux".into()],
            trust_pool: "trusted".into(),
            lease_seconds: 300,
            fairness_seed: 2,
        })
        .await
        .expect("reclaim recovery canary")
        .expect("reclaimed claim exists");
    assert_eq!(reclaimed.attempt_id, admission.attempt_id);
    assert_eq!(reclaimed.fence, claim.fence + 1);
    assert!(
        store
            .accept_offer(
                organization_id,
                admission.attempt_id,
                reclaimed.fence,
                reclaimed.restore_epoch,
                "post-reclaim-agent",
            )
            .await
            .expect("accept reclaimed recovery canary")
    );
    let recovery_effect = json!({
        "destination": "deployment/production",
        "release": "backup-canary"
    });
    assert!(
        store
            .checkpoint_effect(
                organization_id,
                admission.attempt_id,
                reclaimed.fence,
                reclaimed.restore_epoch,
                "post-reclaim-agent",
                "deploy",
                EffectClass::NonIdempotent,
                EffectStatus::Prepared,
                &recovery_effect,
            )
            .await
            .expect("prepare recovery effect")
    );
    store
        .admit_build(&NewBuild {
            organization_id,
            project_id,
            idempotency_key: "queued-rewind-canary".into(),
            pipeline_digest: [64; 32],
            node_key: "queued-stage".into(),
            required_capabilities: vec!["linux".into()],
            required_trust_pool: "trusted".into(),
            priority: 100,
            execution_spec: json!({"command": "claim-after-restore"}),
        })
        .await
        .expect("admit queued rewind canary");
    let lsn_before = sqlx::query_scalar::<_, String>("SELECT pg_current_wal_lsn()::text")
        .fetch_one(store.pool())
        .await
        .expect("read WAL position before sealing");
    let point = store
        .seal_recovery_point("compact-drill-001")
        .await
        .expect("seal recovery point");
    assert_eq!(point.restore_epoch, 1);
    assert!(!point.sealed_lsn.is_empty());
    assert!(!point.recovery_lsn.is_empty());
    let checkpoint_is_later = sqlx::query_scalar::<_, bool>("SELECT $1::pg_lsn > $2::pg_lsn")
        .bind(&point.recovery_lsn)
        .bind(lsn_before)
        .fetch_one(store.pool())
        .await
        .expect("compare recovery checkpoint");
    assert!(checkpoint_is_later);
    let stored_lsn = sqlx::query_scalar::<_, String>(
        "SELECT recovery_lsn::text
         FROM recovery_points
         WHERE backup_id = 'compact-drill-001'",
    )
    .fetch_one(store.pool())
    .await
    .expect("read finalized recovery checkpoint");
    assert_eq!(stored_lsn, point.sealed_lsn);
    let advertised_boundary_includes_seal =
        sqlx::query_scalar::<_, bool>("SELECT $1::pg_lsn > $2::pg_lsn")
            .bind(&point.recovery_lsn)
            .bind(&point.sealed_lsn)
            .fetch_one(store.pool())
            .await
            .expect("compare advertised recovery boundary");
    assert!(advertised_boundary_includes_seal);
    store
        .seal_recovery_point("compact-drill-stale")
        .await
        .expect("seal unused recovery point in the original epoch");
}

#[tokio::test]
#[ignore = "run only by scripts/test-backup-restore.sh against an isolated restore"]
async fn backup_restore_canary_verify() {
    let store = test_store().await.expect("isolated restore database URL");
    let (organization_id, project_id) = recovery_canary_ids();
    let admission = sqlx::query_as::<_, (Uuid, Uuid, i64, i64)>(
        "SELECT b.id, a.id, a.fence, a.restore_epoch
         FROM builds AS b
         JOIN nodes AS n
           ON n.build_id = b.id AND n.organization_id = b.organization_id
         JOIN attempts AS a
           ON a.node_id = n.id AND a.organization_id = n.organization_id
         WHERE b.organization_id = $1
           AND b.project_id = $2
           AND b.idempotency_key = 'backup-restore-canary'",
    )
    .bind(organization_id)
    .bind(project_id)
    .fetch_one(store.pool())
    .await
    .expect("restored canary exists");
    let activation = store
        .activate_restore_epoch("compact-drill-001", "automated restore drill")
        .await
        .expect("activate restored truth")
        .expect("sealed recovery point exists");
    assert_eq!(activation.restore_epoch, 2);
    assert_eq!(activation.affected_attempts, 1);
    assert!(!activation.sealed_lsn.is_empty());
    assert_eq!(store.current_restore_epoch().await.expect("read epoch"), 2);
    let replayed_activation = store
        .activate_restore_epoch("compact-drill-001", "replayed restore response")
        .await
        .expect("replay activation")
        .expect("activation remains queryable");
    assert_eq!(replayed_activation, activation);
    assert_eq!(
        store
            .current_restore_epoch()
            .await
            .expect("epoch after replay"),
        activation.restore_epoch
    );
    assert!(matches!(
        store
            .activate_restore_epoch("compact-drill-stale", "reject stale recovery point")
            .await,
        Err(StoreError::InvalidRecoveryOperation(_))
    ));
    let snapshot = store
        .build_snapshot(organization_id, project_id, admission.0)
        .await
        .expect("read restored build")
        .expect("restored build exists");
    assert_eq!(snapshot.build_status, "reconciliation_required");
    assert_eq!(snapshot.attempt_status, "reconciliation_required");
    assert!(snapshot.lease_owner.is_none());
    let recovery_effect = json!({
        "destination": "deployment/production",
        "release": "backup-canary"
    });
    let historical_effect = json!({"cache_key": "backup-canary"});
    let uncertain = store
        .uncertain_effects(organization_id)
        .await
        .expect("list restored uncertain effects");
    assert_eq!(uncertain.len(), 2);
    let restored_current = uncertain
        .iter()
        .find(|effect| effect.effect_key == "deploy")
        .expect("current-fence restored effect exists");
    assert_eq!(restored_current.attempt_id, admission.1);
    assert_eq!(restored_current.fence, admission.2);
    assert_eq!(restored_current.status, EffectStatus::Uncertain);
    assert_eq!(restored_current.payload, recovery_effect);
    let restored_historical = uncertain
        .iter()
        .find(|effect| effect.effect_key == "publish-cache")
        .expect("historical-fence restored effect exists");
    assert_eq!(restored_historical.attempt_id, admission.1);
    assert_eq!(restored_historical.fence, admission.2 - 1);
    assert_eq!(restored_historical.status, EffectStatus::Uncertain);
    assert_eq!(restored_historical.payload, historical_effect);
    assert!(
        !store
            .checkpoint_effect(
                organization_id,
                admission.1,
                restored_current.fence,
                activation.restore_epoch,
                "post-reclaim-agent",
                "deploy",
                EffectClass::NonIdempotent,
                EffectStatus::Confirmed,
                &recovery_effect,
            )
            .await
            .expect("general checkpoint API preserves restore fence")
    );
    assert!(
        store
            .confirm_uncertain_effect(
                organization_id,
                admission.1,
                restored_current.fence,
                "deploy",
                EffectClass::NonIdempotent,
                &recovery_effect,
            )
            .await
            .expect("confirm restored uncertain effect")
    );
    assert!(
        store
            .confirm_uncertain_effect(
                organization_id,
                admission.1,
                restored_current.fence,
                "deploy",
                EffectClass::NonIdempotent,
                &recovery_effect,
            )
            .await
            .expect("replay restored effect confirmation")
    );
    assert!(
        !store
            .finalize_reconciled_attempt(
                organization_id,
                admission.1,
                admission.2,
                "restore-operator",
                TerminalOutcome::Succeeded,
                json!({"resolution": "current effect verified only"}),
            )
            .await
            .expect("historical uncertainty blocks terminal reconciliation")
    );
    assert!(
        store
            .confirm_uncertain_effect(
                organization_id,
                admission.1,
                restored_historical.fence,
                "publish-cache",
                EffectClass::ExternallyIdempotent,
                &historical_effect,
            )
            .await
            .expect("confirm restored historical-fence effect")
    );
    assert!(
        store
            .uncertain_effects(organization_id)
            .await
            .expect("list after restored effect reconciliation")
            .is_empty()
    );
    let rewind_claim = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "post-restore-scheduler".into(),
            agent_id: "reused-agent".into(),
            capabilities: vec!["linux".into()],
            trust_pool: "trusted".into(),
            lease_seconds: 300,
            fairness_seed: 3,
        })
        .await
        .expect("claim restored queued work")
        .expect("queued rewind canary exists");
    assert_eq!(rewind_claim.fence, 1);
    assert_eq!(rewind_claim.restore_epoch, activation.restore_epoch);
    assert!(
        !store
            .accept_offer(
                organization_id,
                rewind_claim.attempt_id,
                rewind_claim.fence,
                admission.3,
                "reused-agent",
            )
            .await
            .expect("reject stale same-fence authority")
    );
    assert!(
        store
            .accept_offer(
                organization_id,
                rewind_claim.attempt_id,
                rewind_claim.fence,
                rewind_claim.restore_epoch,
                "reused-agent",
            )
            .await
            .expect("accept current restore-epoch authority")
    );
    assert_eq!(
        store
            .schedule_retry(
                organization_id,
                admission.1,
                3,
                "restore reconciliation complete",
            )
            .await
            .expect("refuse replay of restored non-idempotent work"),
        RetryDecision::Ineligible
    );
    assert!(
        store
            .renew_attempt_lease(
                organization_id,
                admission.1,
                admission.2,
                admission.3,
                "post-reclaim-agent",
                30,
            )
            .await
            .expect("old renewal is rejected")
            .is_none()
    );
    assert!(
        !store
            .finalize_attempt(
                organization_id,
                admission.1,
                admission.2,
                admission.3,
                "post-reclaim-agent",
                TerminalOutcome::Succeeded,
                json!({"stale": true}),
            )
            .await
            .expect("old terminal publication is rejected")
    );
    assert!(
        !store
            .register_object(
                organization_id,
                admission.1,
                admission.2,
                admission.3,
                "post-reclaim-agent",
                ObjectKind::Artifact,
                "stale.tar",
                [63; 32],
                1,
            )
            .await
            .expect("old object publication is rejected")
    );
    assert!(
        !store
            .checkpoint_effect(
                organization_id,
                admission.1,
                admission.2,
                admission.3,
                "post-reclaim-agent",
                "stale-effect",
                EffectClass::NonIdempotent,
                EffectStatus::Prepared,
                &json!({"stale": true}),
            )
            .await
            .expect("old effect checkpoint is rejected")
    );
    assert!(
        store
            .finalize_reconciled_attempt(
                organization_id,
                admission.1,
                admission.2,
                "restore-operator",
                TerminalOutcome::Succeeded,
                json!({"resolution": "restored effect verified externally"}),
            )
            .await
            .expect("finish restored reconciliation")
    );
    let objects = store
        .build_objects(organization_id, project_id, admission.0)
        .await
        .expect("read restored object references");
    assert_eq!(objects.len(), 1);
    assert_eq!(objects[0].digest, [62; 32]);
    let publications: (i64, i64) = sqlx::query_as(
        "SELECT
           (SELECT count(*) FROM build_events
            WHERE organization_id = $1
              AND build_id = $2
              AND kind = 'attempt.restore_reconciliation_required'),
           (SELECT count(*) FROM outbox
            WHERE organization_id = $1
              AND aggregate_id = $2
              AND topic = 'attempt.restore_reconciliation_required')",
    )
    .bind(organization_id)
    .bind(admission.0)
    .fetch_one(store.pool())
    .await
    .expect("read restore publications");
    assert_eq!(publications, (1, 1));
}

#[tokio::test]
async fn claim_order_index_is_tenant_prefixed() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let definition = sqlx::query_scalar::<_, String>(
        "SELECT pg_get_indexdef(indexrelid)
         FROM pg_index
         WHERE indexrelid = 'nodes_claim_order_idx'::regclass",
    )
    .fetch_one(store.pool())
    .await
    .expect("inspect scheduler claim index");
    assert!(
        definition.contains(
            "USING btree (organization_id, priority DESC, queued_at, id) WHERE (status = 'queued'::text)"
        ),
        "unexpected claim index: {definition}"
    );
}

#[tokio::test]
async fn protected_credentials_are_approval_bound_fenced_and_one_time() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    let pipeline_digest = [0xa1; 32];
    store
        .create_project(
            organization_id,
            &format!("org-{organization_id}"),
            project_id,
            "protected",
        )
        .await
        .expect("create protected project");
    assert!(
        store
            .configure_protected_environment(
                organization_id,
                project_id,
                "production",
                "deploy",
                2,
            )
            .await
            .expect("configure protected environment")
    );
    assert!(
        !store
            .configure_protected_environment(
                organization_id,
                project_id,
                "production",
                "deploy",
                2,
            )
            .await
            .expect("idempotent protected environment configuration")
    );
    assert!(
        store
            .configure_protected_environment(
                organization_id,
                project_id,
                "production",
                "deploy",
                1,
            )
            .await
            .expect("change protected environment configuration")
    );
    assert!(
        store
            .configure_protected_environment(
                organization_id,
                project_id,
                "production",
                "deploy",
                2,
            )
            .await
            .expect("restore protected environment configuration")
    );
    let policy_audit = store
        .export_audit_events(organization_id)
        .await
        .expect("export protected environment policy audit");
    let policy_events = policy_audit
        .events
        .iter()
        .filter(|event| event.action == "protected_environment.configured")
        .collect::<Vec<_>>();
    assert_eq!(
        policy_events
            .iter()
            .map(|event| event.payload["required_approvals"].as_i64())
            .collect::<Vec<_>>(),
        vec![Some(2), Some(1), Some(2)],
        "create and actual policy changes are audited while a no-op is not"
    );
    let admission = store
        .admit_build(&NewBuild {
            organization_id,
            project_id,
            idempotency_key: "protected-deploy".into(),
            pipeline_digest,
            node_key: "deploy".into(),
            required_capabilities: vec!["linux".into()],
            required_trust_pool: "trusted".into(),
            priority: 0,
            execution_spec: json!({}),
        })
        .await
        .expect("admit protected build");
    assert!(
        store
            .open_agent_session(
                "agent-protected",
                "trusted",
                1,
                3,
                &[
                    "work-delivery-v1".to_owned(),
                    "attempt-credentials-v1".to_owned(),
                ],
                &["linux".to_owned()],
            )
            .await
            .expect("open protected agent session")
    );
    let claim = store
        .claim_next_in_session(
            &ClaimRequest {
                organization_id,
                scheduler_id: "scheduler-protected".into(),
                agent_id: "agent-protected".into(),
                capabilities: vec!["linux".into()],
                trust_pool: "trusted".into(),
                lease_seconds: 300,
                fairness_seed: 0,
            },
            1,
        )
        .await
        .expect("claim protected build")
        .expect("protected build is ready");
    let approvals = [Uuid::new_v4(), Uuid::new_v4()];
    for (approval_id, subject) in approvals
        .into_iter()
        .zip(["oidc:release-owner", "oidc:security-owner"])
    {
        assert!(
            store
                .approve_environment(&NewEnvironmentApproval {
                    id: approval_id,
                    organization_id,
                    project_id,
                    build_id: admission.build_id,
                    pipeline_digest,
                    environment: "production",
                    action: "deploy",
                    approver_subject: subject,
                    ttl_seconds: 300,
                })
                .await
                .expect("approve protected environment")
        );
    }
    assert!(
        !store
            .approve_environment(&NewEnvironmentApproval {
                id: approvals[0],
                organization_id,
                project_id,
                build_id: admission.build_id,
                pipeline_digest,
                environment: "production",
                action: "deploy",
                approver_subject: "oidc:release-owner",
                ttl_seconds: 300,
            })
            .await
            .expect("reject approval replay")
    );
    let expired_secret = b"expired-secret-value";
    let secret = b"marker-secret-value";
    let grant_id = Uuid::new_v4();
    let mut grant = NewCredentialGrant {
        id: Uuid::new_v4(),
        organization_id,
        project_id,
        build_id: admission.build_id,
        attempt_id: claim.attempt_id,
        fence: claim.fence,
        pipeline_digest,
        environment: "production",
        action: "deploy",
        target_name: "DEPLOY_TOKEN",
        secret_value: expired_secret,
        approval_ids: &approvals[..1],
        ttl_seconds: 1,
    };
    assert!(
        !store
            .issue_credential_grant(&grant)
            .await
            .expect("reject insufficient approvals")
    );
    grant.approval_ids = &approvals;
    assert!(
        store
            .issue_credential_grant(&grant)
            .await
            .expect("issue protected grant")
    );
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    grant.id = grant_id;
    grant.secret_value = secret;
    grant.ttl_seconds = 300;
    assert!(
        store
            .issue_credential_grant(&grant)
            .await
            .expect("renew an expired undelivered protected grant")
    );
    let renewed = sqlx::query_as::<_, (Uuid, Vec<u8>, bool, bool)>(
        "SELECT id, secret_value, delivered_at IS NULL,
                expires_at > clock_timestamp()
         FROM credential_grants
         WHERE organization_id = $1
           AND attempt_id = $2
           AND fence = $3
           AND target_name = $4",
    )
    .bind(organization_id)
    .bind(claim.attempt_id)
    .bind(claim.fence)
    .bind("DEPLOY_TOKEN")
    .fetch_one(store.pool())
    .await
    .expect("read renewed protected grant");
    assert_eq!(renewed, (grant_id, secret.to_vec(), true, true));
    assert!(
        store
            .approve_environment(&NewEnvironmentApproval {
                id: Uuid::new_v4(),
                organization_id,
                project_id,
                build_id: admission.build_id,
                pipeline_digest,
                environment: "production",
                action: "deploy",
                approver_subject: "oidc:release-owner",
                ttl_seconds: 300,
            })
            .await
            .expect("renew consumed approval for a later attempt")
    );
    assert!(
        !store
            .issue_credential_grant(&grant)
            .await
            .expect("reject grant replay")
    );
    assert!(
        store
            .accept_offer_in_session(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "agent-protected",
                1,
            )
            .await
            .expect("accept protected work")
    );
    assert!(
        store
            .redeem_credential_grants(
                organization_id,
                claim.attempt_id,
                claim.fence + 1,
                claim.restore_epoch,
                "agent-protected",
                1,
                &["DEPLOY_TOKEN".to_owned()],
            )
            .await
            .expect("reject another fence")
            .is_none()
    );
    assert!(
        store
            .redeem_credential_grants(
                organization_id,
                Uuid::new_v4(),
                claim.fence,
                claim.restore_epoch,
                "agent-protected",
                1,
                &["DEPLOY_TOKEN".to_owned()],
            )
            .await
            .expect("reject another attempt")
            .is_none()
    );
    assert!(
        store
            .redeem_credential_grants(
                Uuid::new_v4(),
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "agent-protected",
                1,
                &["DEPLOY_TOKEN".to_owned()],
            )
            .await
            .expect("reject another tenant")
            .is_none()
    );
    assert!(
        store
            .redeem_credential_grants(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "another-agent",
                1,
                &["DEPLOY_TOKEN".to_owned()],
            )
            .await
            .expect("reject another agent")
            .is_none()
    );
    assert!(
        store
            .open_agent_session(
                "agent-protected",
                "trusted",
                2,
                3,
                &["work-delivery-v1".to_owned()],
                &["linux".to_owned()],
            )
            .await
            .expect("replace the session without credential support")
    );
    assert!(
        store
            .redeem_credential_grants(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "agent-protected",
                2,
                &["DEPLOY_TOKEN".to_owned()],
            )
            .await
            .expect("reject a session without credential support")
            .is_none()
    );
    assert!(
        store
            .open_agent_session(
                "agent-protected",
                "trusted",
                3,
                3,
                &[
                    "work-delivery-v1".to_owned(),
                    "attempt-credentials-v1".to_owned(),
                ],
                &["linux".to_owned()],
            )
            .await
            .expect("restore credential support")
    );
    let delivered = store
        .redeem_credential_grants(
            organization_id,
            claim.attempt_id,
            claim.fence,
            claim.restore_epoch,
            "agent-protected",
            3,
            &["DEPLOY_TOKEN".to_owned()],
        )
        .await
        .expect("redeem exact grant")
        .expect("exact grant set is ready");
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].grant_id, grant_id);
    assert_eq!(delivered[0].target_name, "DEPLOY_TOKEN");
    assert_eq!(delivered[0].secret_value, secret);
    let replayed = store
        .redeem_credential_grants(
            organization_id,
            claim.attempt_id,
            claim.fence,
            claim.restore_epoch,
            "agent-protected",
            3,
            &["DEPLOY_TOKEN".to_owned()],
        )
        .await
        .expect("replay delivery after response loss")
        .expect("same accepted authority recovers its exact envelope");
    assert_eq!(replayed, delivered);
    assert!(
        store
            .mark_attempt_running_in_session(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "agent-protected",
                3,
            )
            .await
            .expect("start protected work")
    );
    assert!(
        store
            .redeem_credential_grants(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "agent-protected",
                3,
                &["DEPLOY_TOKEN".to_owned()],
            )
            .await
            .expect("reject delivery replay after execution start")
            .is_none()
    );
    assert!(
        store
            .append_log_in_session(
                &NewLogChunk {
                    organization_id,
                    attempt_id: claim.attempt_id,
                    fence: claim.fence,
                    restore_epoch: claim.restore_epoch,
                    agent_id: "agent-protected",
                    sequence: 0,
                    stream: "stdout",
                    content: b"before marker-secret-value after",
                },
                3,
            )
            .await
            .expect("persist redacted credential-bearing log")
    );
    let persisted_log = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT content
         FROM attempt_log_chunks
         WHERE organization_id = $1
           AND attempt_id = $2
           AND fence = $3
           AND sequence = 0",
    )
    .bind(organization_id)
    .bind(claim.attempt_id)
    .bind(claim.fence)
    .fetch_one(store.pool())
    .await
    .expect("read redacted log");
    assert_eq!(persisted_log, b"before  after");

    let payloads = sqlx::query_scalar::<_, String>(
        "SELECT string_agg(payload::text, '')
         FROM (
             SELECT payload FROM build_events
             WHERE organization_id = $1 AND build_id = $2
             UNION ALL
             SELECT payload FROM outbox
             WHERE organization_id = $1 AND aggregate_id = $2
         ) AS publications",
    )
    .bind(organization_id)
    .bind(admission.build_id)
    .fetch_one(store.pool())
    .await
    .expect("read security publications");
    assert!(!payloads.contains("marker-secret-value"));
    let rewritten = sqlx::query(
        "UPDATE credential_grants
         SET secret_value = 'rewritten'::bytea
         WHERE organization_id = $1 AND id = $2",
    )
    .bind(organization_id)
    .bind(grant_id)
    .execute(store.pool())
    .await;
    assert!(rewritten.is_err());
}

#[tokio::test]
async fn postgres_rls_hides_and_rejects_cross_tenant_rows() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let organization_a = Uuid::new_v4();
    let project_a = Uuid::new_v4();
    let organization_b = Uuid::new_v4();
    let project_b = Uuid::new_v4();
    store
        .create_project(
            organization_a,
            &format!("org-{organization_a}"),
            project_a,
            "project",
        )
        .await
        .expect("create tenant A");
    store
        .create_project(
            organization_b,
            &format!("org-{organization_b}"),
            project_b,
            "project",
        )
        .await
        .expect("create tenant B");
    for (organization_id, project_id, key) in [
        (organization_a, project_a, "tenant-a"),
        (organization_b, project_b, "tenant-b"),
    ] {
        store
            .admit_build(&NewBuild {
                organization_id,
                project_id,
                idempotency_key: key.into(),
                pipeline_digest: [4; 32],
                node_key: "stage".into(),
                required_capabilities: Vec::new(),
                required_trust_pool: "trusted".into(),
                priority: 0,
                execution_spec: json!({}),
            })
            .await
            .expect("admit tenant build");
    }

    let mut tenant = store.pool().begin().await.expect("begin tenant session");
    sqlx::query("SET LOCAL ROLE mcloving_tenant")
        .execute(&mut *tenant)
        .await
        .expect("assume unprivileged application role");
    sqlx::query("SELECT set_config('mcloving.organization_id', $1, true)")
        .bind(organization_a.to_string())
        .execute(&mut *tenant)
        .await
        .expect("bind tenant context");
    let visible = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM builds")
        .fetch_one(&mut *tenant)
        .await
        .expect("read tenant-scoped builds");
    assert_eq!(visible, 1);
    let cross_tenant =
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM builds WHERE organization_id = $1")
            .bind(organization_b)
            .fetch_one(&mut *tenant)
            .await
            .expect("cross-tenant read is filtered");
    assert_eq!(cross_tenant, 0);
    let substituted_write = sqlx::query(
        "INSERT INTO builds (
             id, organization_id, project_id, idempotency_key,
             pipeline_digest, status, priority
         )
         VALUES ($1, $2, $3, 'substitution', $4, 'queued', 0)",
    )
    .bind(Uuid::new_v4())
    .bind(organization_b)
    .bind(project_b)
    .bind([5_u8; 32].as_slice())
    .execute(&mut *tenant)
    .await;
    assert!(substituted_write.is_err());
    tenant.rollback().await.expect("roll back tenant test");
}

#[tokio::test]
async fn dag_parallel_retry_join_post_and_restart_truth_are_transactional() {
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
            "dag",
        )
        .await
        .expect("create DAG project");
    let mut linux = dag_node("linux", DagNodeKind::Work, vec![], "linux", "build");
    linux.max_attempts = 2;
    let windows = dag_node("windows", DagNodeKind::Work, vec![], "windows", "build");
    let join = dag_node(
        "join",
        DagNodeKind::Join,
        vec![
            DagDependency {
                node_key: "linux".to_owned(),
                condition: DependencyCondition::Succeeded,
            },
            DagDependency {
                node_key: "windows".to_owned(),
                condition: DependencyCondition::Succeeded,
            },
        ],
        "linux",
        "join",
    );
    let post = dag_node(
        "post",
        DagNodeKind::Post,
        vec![DagDependency {
            node_key: "join".to_owned(),
            condition: DependencyCondition::Completed,
        }],
        "linux",
        "post",
    );
    let admission = store
        .admit_dag(&NewDagBuild {
            organization_id,
            project_id,
            idempotency_key: "parallel-retry-join-post".to_owned(),
            pipeline_digest: [0xd4; 32],
            priority: 0,
            nodes: vec![linux, windows, join, post],
        })
        .await
        .expect("admit DAG");
    assert!(admission.created);
    let replay = store
        .admit_dag(&NewDagBuild {
            organization_id,
            project_id,
            idempotency_key: "parallel-retry-join-post".to_owned(),
            pipeline_digest: [0xd4; 32],
            priority: 0,
            nodes: vec![
                {
                    let mut node = dag_node("linux", DagNodeKind::Work, vec![], "linux", "build");
                    node.max_attempts = 2;
                    node
                },
                dag_node("windows", DagNodeKind::Work, vec![], "windows", "build"),
                dag_node(
                    "join",
                    DagNodeKind::Join,
                    vec![
                        DagDependency {
                            node_key: "linux".to_owned(),
                            condition: DependencyCondition::Succeeded,
                        },
                        DagDependency {
                            node_key: "windows".to_owned(),
                            condition: DependencyCondition::Succeeded,
                        },
                    ],
                    "linux",
                    "join",
                ),
                dag_node(
                    "post",
                    DagNodeKind::Post,
                    vec![DagDependency {
                        node_key: "join".to_owned(),
                        condition: DependencyCondition::Completed,
                    }],
                    "linux",
                    "post",
                ),
            ],
        })
        .await
        .expect("replay exact DAG admission");
    assert!(!replay.created);
    assert_eq!(replay.build_id, admission.build_id);
    let mut changed_linux = dag_node("linux", DagNodeKind::Work, vec![], "linux", "build");
    changed_linux.max_attempts = 2;
    changed_linux.execution_spec = json!({"program": "false", "node": "linux"});
    let changed_replay = store
        .admit_dag(&NewDagBuild {
            organization_id,
            project_id,
            idempotency_key: "parallel-retry-join-post".to_owned(),
            pipeline_digest: [0xd4; 32],
            priority: 0,
            nodes: vec![
                changed_linux,
                dag_node("windows", DagNodeKind::Work, vec![], "windows", "build"),
                dag_node(
                    "join",
                    DagNodeKind::Join,
                    vec![
                        DagDependency {
                            node_key: "linux".to_owned(),
                            condition: DependencyCondition::Succeeded,
                        },
                        DagDependency {
                            node_key: "windows".to_owned(),
                            condition: DependencyCondition::Succeeded,
                        },
                    ],
                    "linux",
                    "join",
                ),
                dag_node(
                    "post",
                    DagNodeKind::Post,
                    vec![DagDependency {
                        node_key: "join".to_owned(),
                        condition: DependencyCondition::Completed,
                    }],
                    "linux",
                    "post",
                ),
            ],
        })
        .await;
    assert!(matches!(changed_replay, Err(StoreError::InvalidDag(_))));

    let linux_store = store.clone();
    let windows_store = store.clone();
    let linux_request = dag_claim(organization_id, "agent-linux", "linux", "build");
    let windows_request = dag_claim(organization_id, "agent-windows", "windows", "build");
    let (linux_claim, windows_claim) = tokio::join!(
        linux_store.claim_next(&linux_request),
        windows_store.claim_next(&windows_request)
    );
    let linux_claim = linux_claim
        .expect("claim Linux root")
        .expect("Linux root ready");
    let windows_claim = windows_claim
        .expect("claim Windows root")
        .expect("Windows root ready");
    assert_ne!(linux_claim.node_id, windows_claim.node_id);
    run_dag_claim(&store, &linux_claim).await;
    run_dag_claim(&store, &windows_claim).await;

    let linux_terminal = store.finalize_attempt(
        organization_id,
        linux_claim.attempt_id,
        linux_claim.fence,
        linux_claim.restore_epoch,
        &linux_claim.agent_id,
        TerminalOutcome::Failed,
        json!({"try": 1}),
    );
    let windows_terminal = store.finalize_attempt(
        organization_id,
        windows_claim.attempt_id,
        windows_claim.fence,
        windows_claim.restore_epoch,
        &windows_claim.agent_id,
        TerminalOutcome::Succeeded,
        json!({"try": 1}),
    );
    let (linux_terminal, windows_terminal) = tokio::join!(linux_terminal, windows_terminal);
    assert!(linux_terminal.expect("terminalize first Linux attempt"));
    assert!(windows_terminal.expect("terminalize Windows attempt"));

    let retry = store
        .claim_next(&dag_claim(
            organization_id,
            "agent-linux-retry",
            "linux",
            "build",
        ))
        .await
        .expect("claim Linux retry")
        .expect("retry is ready");
    assert_eq!(retry.node_id, linux_claim.node_id);
    assert_ne!(retry.attempt_id, linux_claim.attempt_id);
    run_dag_claim(&store, &retry).await;
    assert!(
        store
            .finalize_attempt(
                organization_id,
                retry.attempt_id,
                retry.fence,
                retry.restore_epoch,
                &retry.agent_id,
                TerminalOutcome::Succeeded,
                json!({"try": 2}),
            )
            .await
            .expect("terminalize Linux retry")
    );

    let restarted = Store::new(store.pool().clone());
    let join_claim = restarted
        .claim_next(&dag_claim(organization_id, "agent-join", "linux", "join"))
        .await
        .expect("claim join after controller restart")
        .expect("join becomes ready exactly once");
    assert_eq!(join_claim.node_id, admission.nodes["join"].node_id);
    run_dag_claim(&restarted, &join_claim).await;
    let join_summary = json!({"join": "failed"});
    assert!(
        restarted
            .finalize_attempt(
                organization_id,
                join_claim.attempt_id,
                join_claim.fence,
                join_claim.restore_epoch,
                &join_claim.agent_id,
                TerminalOutcome::Failed,
                join_summary.clone(),
            )
            .await
            .expect("terminalize join")
    );
    assert!(
        restarted
            .finalize_attempt(
                organization_id,
                join_claim.attempt_id,
                join_claim.fence,
                join_claim.restore_epoch,
                &join_claim.agent_id,
                TerminalOutcome::Failed,
                join_summary,
            )
            .await
            .expect("replay identical terminal outcome")
    );
    assert!(
        !restarted
            .finalize_attempt(
                organization_id,
                join_claim.attempt_id,
                join_claim.fence,
                join_claim.restore_epoch,
                &join_claim.agent_id,
                TerminalOutcome::Succeeded,
                json!({"join": "conflicting"}),
            )
            .await
            .expect("reject conflicting terminal outcome")
    );

    let post_claim = restarted
        .claim_next(&dag_claim(organization_id, "agent-post", "linux", "post"))
        .await
        .expect("claim completion-only post")
        .expect("post runs after failed join");
    assert_eq!(post_claim.node_id, admission.nodes["post"].node_id);
    run_dag_claim(&restarted, &post_claim).await;
    assert!(
        restarted
            .finalize_attempt(
                organization_id,
                post_claim.attempt_id,
                post_claim.fence,
                post_claim.restore_epoch,
                &post_claim.agent_id,
                TerminalOutcome::Succeeded,
                json!({"post": "complete"}),
            )
            .await
            .expect("terminalize post")
    );

    let build_status: String = sqlx::query_scalar("SELECT status FROM builds WHERE id = $1")
        .bind(admission.build_id)
        .fetch_one(restarted.pool())
        .await
        .expect("read DAG build outcome");
    assert_eq!(build_status, "failed");
    let outcomes = sqlx::query_as::<_, (String, Option<String>)>(
        "SELECT node_key, logical_outcome
         FROM nodes
         WHERE build_id = $1
         ORDER BY node_key",
    )
    .bind(admission.build_id)
    .fetch_all(restarted.pool())
    .await
    .expect("read one logical outcome per node");
    assert_eq!(
        outcomes,
        vec![
            ("join".to_owned(), Some("failed".to_owned())),
            ("linux".to_owned(), Some("succeeded".to_owned())),
            ("post".to_owned(), Some("succeeded".to_owned())),
            ("windows".to_owned(), Some("succeeded".to_owned())),
        ]
    );
    let linux_attempts: i64 =
        sqlx::query_scalar("SELECT count(*) FROM attempts WHERE node_id = $1")
            .bind(linux_claim.node_id)
            .fetch_one(restarted.pool())
            .await
            .expect("count bounded retry history");
    assert_eq!(linux_attempts, 2);
}

#[tokio::test]
async fn dag_retry_refuses_confirmed_non_idempotent_effects() {
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
            "dag-non-idempotent",
        )
        .await
        .expect("create DAG project");
    let mut deploy = dag_node("deploy", DagNodeKind::Work, vec![], "linux", "deploy");
    deploy.max_attempts = 2;
    let admission = store
        .admit_dag(&NewDagBuild {
            organization_id,
            project_id,
            idempotency_key: "dag-non-idempotent".to_owned(),
            pipeline_digest: [0xe4; 32],
            priority: 0,
            nodes: vec![deploy],
        })
        .await
        .expect("admit DAG");
    let claim = store
        .claim_next(&dag_claim(
            organization_id,
            "agent-deploy",
            "linux",
            "deploy",
        ))
        .await
        .expect("claim deploy")
        .expect("deploy ready");
    run_dag_claim(&store, &claim).await;
    let payload = json!({"release": "r1"});
    for status in [
        EffectStatus::Prepared,
        EffectStatus::Applied,
        EffectStatus::Confirmed,
    ] {
        assert!(
            store
                .checkpoint_effect(
                    organization_id,
                    claim.attempt_id,
                    claim.fence,
                    claim.restore_epoch,
                    &claim.agent_id,
                    "deploy",
                    EffectClass::NonIdempotent,
                    status,
                    &payload,
                )
                .await
                .expect("checkpoint non-idempotent effect")
        );
    }
    assert!(
        store
            .finalize_attempt(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                &claim.agent_id,
                TerminalOutcome::Failed,
                json!({"failure": "after confirmed effect"}),
            )
            .await
            .expect("terminalize deploy")
    );

    let attempts = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM attempts WHERE node_id = $1")
        .bind(claim.node_id)
        .fetch_one(store.pool())
        .await
        .expect("count DAG attempts");
    assert_eq!(attempts, 1);
    let outcome =
        sqlx::query_scalar::<_, Option<String>>("SELECT logical_outcome FROM nodes WHERE id = $1")
            .bind(admission.nodes["deploy"].node_id)
            .fetch_one(store.pool())
            .await
            .expect("read deploy outcome");
    assert_eq!(outcome.as_deref(), Some("failed"));
    assert!(
        store
            .claim_next(&dag_claim(
                organization_id,
                "agent-retry",
                "linux",
                "deploy",
            ))
            .await
            .expect("check retry absence")
            .is_none()
    );
}

#[tokio::test]
async fn dag_reconciliation_required_pauses_other_ready_work() {
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
            "dag-reconciliation",
        )
        .await
        .expect("create DAG reconciliation project");
    let mut uncertain = dag_node("uncertain", DagNodeKind::Work, vec![], "linux", "build");
    uncertain.priority = 20;
    uncertain.max_attempts = 2;
    let mut peer = dag_node("peer", DagNodeKind::Work, vec![], "linux", "build");
    peer.priority = 10;
    let mut after = dag_node("after", DagNodeKind::Work, vec![], "linux", "build");
    after.priority = 0;
    let admission = store
        .admit_dag(&NewDagBuild {
            organization_id,
            project_id,
            idempotency_key: "reconciliation-pauses-dag".to_owned(),
            pipeline_digest: [0xd5; 32],
            priority: 0,
            nodes: vec![uncertain, peer, after],
        })
        .await
        .expect("admit reconciliation DAG");

    let first = store
        .claim_next(&dag_claim(
            organization_id,
            "agent-uncertain",
            "linux",
            "build",
        ))
        .await
        .expect("claim uncertain node")
        .expect("uncertain node ready");
    let second = store
        .claim_next(&dag_claim(organization_id, "agent-peer", "linux", "build"))
        .await
        .expect("claim peer node")
        .expect("peer node ready");
    run_dag_claim(&store, &first).await;
    run_dag_claim(&store, &second).await;
    assert_eq!(first.node_id, admission.nodes["uncertain"].node_id);
    assert_eq!(second.node_id, admission.nodes["peer"].node_id);

    sqlx::query(
        "UPDATE attempts
         SET status = 'reconciliation_required',
             lease_owner = NULL,
             lease_expires_at = NULL
         WHERE organization_id = $1 AND id = $2",
    )
    .bind(organization_id)
    .bind(first.attempt_id)
    .execute(store.pool())
    .await
    .expect("mark attempt reconciliation required");
    sqlx::query(
        "UPDATE nodes
         SET status = 'reconciliation_required'
         WHERE organization_id = $1 AND id = $2",
    )
    .bind(organization_id)
    .bind(first.node_id)
    .execute(store.pool())
    .await
    .expect("mark node reconciliation required");
    sqlx::query(
        "UPDATE builds
         SET status = 'reconciliation_required'
         WHERE organization_id = $1 AND id = $2",
    )
    .bind(organization_id)
    .bind(admission.build_id)
    .execute(store.pool())
    .await
    .expect("pause build for reconciliation");

    assert!(
        store
            .finalize_attempt(
                organization_id,
                second.attempt_id,
                second.fence,
                second.restore_epoch,
                &second.agent_id,
                TerminalOutcome::Succeeded,
                json!({"peer": "complete"}),
            )
            .await
            .expect("terminalize peer while reconciliation is pending")
    );

    let status: String =
        sqlx::query_scalar("SELECT status FROM builds WHERE organization_id = $1 AND id = $2")
            .bind(organization_id)
            .bind(admission.build_id)
            .fetch_one(store.pool())
            .await
            .expect("read paused build");
    assert_eq!(status, "reconciliation_required");
    assert!(
        store
            .claim_next(&dag_claim(organization_id, "agent-after", "linux", "build",))
            .await
            .expect("poll paused DAG")
            .is_none()
    );
    assert_eq!(
        store
            .explain_wait(organization_id, &["linux".to_owned()], "build")
            .await
            .expect("explain paused DAG"),
        WaitReason::NoQueuedWork
    );
    assert!(
        store
            .finalize_reconciled_attempt(
                organization_id,
                first.attempt_id,
                first.fence,
                "operator-retry",
                TerminalOutcome::Failed,
                json!({"resolution": "safe to retry"}),
            )
            .await
            .expect("schedule retry after reconciliation")
    );
    let retry = store
        .claim_next(&dag_claim(organization_id, "agent-retry", "linux", "build"))
        .await
        .expect("claim reconciliation retry")
        .expect("reconciliation retry is not stranded");
    assert_eq!(retry.node_id, first.node_id);
    assert_ne!(retry.attempt_id, first.attempt_id);
}

#[tokio::test]
async fn dag_fail_fast_cancels_active_skips_queued_and_still_runs_post() {
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
            "fail-fast",
        )
        .await
        .expect("create fail-fast project");
    let mut fast = dag_node("fast", DagNodeKind::Work, vec![], "linux", "fast");
    fast.fail_fast = true;
    let slow = dag_node("slow", DagNodeKind::Work, vec![], "linux", "slow");
    let queued = dag_node("queued", DagNodeKind::Work, vec![], "linux", "queued");
    let post = dag_node(
        "post",
        DagNodeKind::Post,
        vec![
            DagDependency {
                node_key: "fast".to_owned(),
                condition: DependencyCondition::Completed,
            },
            DagDependency {
                node_key: "slow".to_owned(),
                condition: DependencyCondition::Completed,
            },
            DagDependency {
                node_key: "queued".to_owned(),
                condition: DependencyCondition::Completed,
            },
        ],
        "linux",
        "post",
    );
    let admission = store
        .admit_dag(&NewDagBuild {
            organization_id,
            project_id,
            idempotency_key: "fail-fast".to_owned(),
            pipeline_digest: [0xf4; 32],
            priority: 0,
            nodes: vec![fast, slow, queued, post],
        })
        .await
        .expect("admit fail-fast DAG");
    let fast_claim = store
        .claim_next(&dag_claim(organization_id, "agent-fast", "linux", "fast"))
        .await
        .expect("claim fail-fast node")
        .expect("fail-fast node ready");
    let slow_claim = store
        .claim_next(&dag_claim(organization_id, "agent-slow", "linux", "slow"))
        .await
        .expect("claim slow peer")
        .expect("slow peer ready");
    run_dag_claim(&store, &fast_claim).await;
    run_dag_claim(&store, &slow_claim).await;
    assert!(
        store
            .finalize_attempt(
                organization_id,
                fast_claim.attempt_id,
                fast_claim.fence,
                fast_claim.restore_epoch,
                &fast_claim.agent_id,
                TerminalOutcome::Failed,
                json!({"failure": "fail-fast"}),
            )
            .await
            .expect("terminalize fail-fast node")
    );
    assert_eq!(
        store
            .renew_attempt_lease(
                organization_id,
                slow_claim.attempt_id,
                slow_claim.fence,
                slow_claim.restore_epoch,
                &slow_claim.agent_id,
                30,
            )
            .await
            .expect("poll peer cancellation"),
        Some(true)
    );
    let queued_status: (String, Option<String>) =
        sqlx::query_as("SELECT status, logical_outcome FROM nodes WHERE id = $1")
            .bind(admission.nodes["queued"].node_id)
            .fetch_one(store.pool())
            .await
            .expect("read skipped queued peer");
    assert_eq!(
        queued_status,
        ("skipped".to_owned(), Some("skipped".to_owned()))
    );
    sqlx::query(
        "UPDATE attempts
         SET lease_expires_at = clock_timestamp() - interval '1 second'
         WHERE id = $1",
    )
    .bind(slow_claim.attempt_id)
    .execute(store.pool())
    .await
    .expect("simulate fail-fast peer crash");
    let restarted = Store::new(store.pool().clone());
    assert!(
        restarted
            .requeue_one_expired(organization_id)
            .await
            .expect("recover expired fail-fast cancellation")
    );
    let slow_outcome: (String, Option<String>) =
        sqlx::query_as("SELECT status, logical_outcome FROM nodes WHERE id = $1")
            .bind(slow_claim.node_id)
            .fetch_one(restarted.pool())
            .await
            .expect("read crash-recovered peer");
    assert_eq!(
        slow_outcome,
        ("aborted".to_owned(), Some("aborted".to_owned()))
    );
    let post_claim = restarted
        .claim_next(&dag_claim(organization_id, "agent-post", "linux", "post"))
        .await
        .expect("claim fail-fast post")
        .expect("post waits for all completion dependencies");
    run_dag_claim(&restarted, &post_claim).await;
    assert!(
        restarted
            .finalize_attempt(
                organization_id,
                post_claim.attempt_id,
                post_claim.fence,
                post_claim.restore_epoch,
                &post_claim.agent_id,
                TerminalOutcome::Succeeded,
                json!({"post": "ran"}),
            )
            .await
            .expect("finish fail-fast post")
    );
    let status: String = sqlx::query_scalar("SELECT status FROM builds WHERE id = $1")
        .bind(admission.build_id)
        .fetch_one(restarted.pool())
        .await
        .expect("read fail-fast build");
    assert_eq!(status, "failed");
}

#[tokio::test]
async fn dag_fail_fast_cooperative_cancellation_and_retry_race_converge() {
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
            "fail-fast-cooperative",
        )
        .await
        .expect("create cooperative fail-fast project");
    assert!(
        store
            .open_agent_session("agent-cooperative", "trusted", 1, 0, &[], &[])
            .await
            .expect("open cooperative agent session")
    );

    let mut fast = dag_node("fast", DagNodeKind::Work, vec![], "linux", "fast");
    fast.fail_fast = true;
    fast.priority = 30;
    let mut cooperative = dag_node(
        "cooperative",
        DagNodeKind::Work,
        vec![],
        "linux",
        "cooperative",
    );
    cooperative.priority = 20;
    let mut retry_race = dag_node(
        "retry-race",
        DagNodeKind::Work,
        vec![],
        "linux",
        "retry-race",
    );
    retry_race.priority = 10;
    retry_race.max_attempts = 2;
    let post = dag_node(
        "post",
        DagNodeKind::Post,
        vec![
            DagDependency {
                node_key: "fast".to_owned(),
                condition: DependencyCondition::Completed,
            },
            DagDependency {
                node_key: "cooperative".to_owned(),
                condition: DependencyCondition::Completed,
            },
            DagDependency {
                node_key: "retry-race".to_owned(),
                condition: DependencyCondition::Completed,
            },
        ],
        "linux",
        "post",
    );
    let admission = store
        .admit_dag(&NewDagBuild {
            organization_id,
            project_id,
            idempotency_key: "fail-fast-cooperative".to_owned(),
            pipeline_digest: [0xf5; 32],
            priority: 0,
            nodes: vec![fast, cooperative, retry_race, post],
        })
        .await
        .expect("admit cooperative fail-fast DAG");

    let fast_claim = store
        .claim_next(&dag_claim(organization_id, "agent-fast", "linux", "fast"))
        .await
        .expect("claim fail-fast node")
        .expect("fail-fast node ready");
    let cooperative_claim = store
        .claim_next(&dag_claim(
            organization_id,
            "agent-cooperative",
            "linux",
            "cooperative",
        ))
        .await
        .expect("claim cooperative peer")
        .expect("cooperative peer ready");
    let race_claim = store
        .claim_next(&dag_claim(
            organization_id,
            "agent-race",
            "linux",
            "retry-race",
        ))
        .await
        .expect("claim retry-race peer")
        .expect("retry-race peer ready");
    run_dag_claim(&store, &fast_claim).await;
    run_dag_claim(&store, &cooperative_claim).await;
    run_dag_claim(&store, &race_claim).await;

    assert!(
        store
            .finalize_attempt(
                organization_id,
                fast_claim.attempt_id,
                fast_claim.fence,
                fast_claim.restore_epoch,
                &fast_claim.agent_id,
                TerminalOutcome::Failed,
                json!({"failure": "fail-fast"}),
            )
            .await
            .expect("terminalize fail-fast node")
    );
    assert!(
        store
            .finalize_attempt(
                organization_id,
                race_claim.attempt_id,
                race_claim.fence,
                race_claim.restore_epoch,
                &race_claim.agent_id,
                TerminalOutcome::Failed,
                json!({"failure": "raced cancellation"}),
            )
            .await
            .expect("terminalize retry race")
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM attempts WHERE node_id = $1")
            .bind(race_claim.node_id)
            .fetch_one(store.pool())
            .await
            .expect("count retry-race attempts"),
        1
    );

    assert_eq!(
        store
            .complete_agent_cancellation(AgentCancellationCompletion {
                organization_id,
                attempt_id: cooperative_claim.attempt_id,
                fence: cooperative_claim.fence,
                restore_epoch: cooperative_claim.restore_epoch,
                agent_id: &cooperative_claim.agent_id,
                session_epoch: 1,
                outcome: AgentCancellationOutcome::Terminated,
            })
            .await
            .expect("complete cooperative DAG cancellation"),
        AgentCancellationDisposition::Completed
    );
    let cooperative_outcome: (String, Option<String>) =
        sqlx::query_as("SELECT status, logical_outcome FROM nodes WHERE id = $1")
            .bind(cooperative_claim.node_id)
            .fetch_one(store.pool())
            .await
            .expect("read cooperative node outcome");
    assert_eq!(
        cooperative_outcome,
        ("aborted".to_owned(), Some("aborted".to_owned()))
    );

    let post_claim = store
        .claim_next(&dag_claim(organization_id, "agent-post", "linux", "post"))
        .await
        .expect("claim cooperative fail-fast post")
        .expect("post remains schedulable");
    run_dag_claim(&store, &post_claim).await;
    assert!(
        store
            .finalize_attempt(
                organization_id,
                post_claim.attempt_id,
                post_claim.fence,
                post_claim.restore_epoch,
                &post_claim.agent_id,
                TerminalOutcome::Succeeded,
                json!({"post": "ran"}),
            )
            .await
            .expect("finish cooperative fail-fast post")
    );
    let status: String = sqlx::query_scalar("SELECT status FROM builds WHERE id = $1")
        .bind(admission.build_id)
        .fetch_one(store.pool())
        .await
        .expect("read cooperative fail-fast build");
    assert_eq!(status, "failed");
}

#[tokio::test]
async fn dag_owner_cancellation_is_durable_idempotent_and_monotonic() {
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
            "cancel-dag",
        )
        .await
        .expect("create cancellation project");
    let admission = store
        .admit_dag(&NewDagBuild {
            organization_id,
            project_id,
            idempotency_key: "cancel-dag".to_owned(),
            pipeline_digest: [0xca; 32],
            priority: 0,
            nodes: vec![
                dag_node("active", DagNodeKind::Work, vec![], "linux", "active"),
                dag_node("queued", DagNodeKind::Work, vec![], "linux", "queued"),
            ],
        })
        .await
        .expect("admit cancellation DAG");
    let active = store
        .claim_next(&dag_claim(
            organization_id,
            "agent-active",
            "linux",
            "active",
        ))
        .await
        .expect("claim active cancellation node")
        .expect("active node ready");
    run_dag_claim(&store, &active).await;
    assert!(
        store
            .request_cancellation(organization_id, project_id, admission.build_id)
            .await
            .expect("request DAG cancellation")
    );
    assert!(
        !store
            .request_cancellation(organization_id, project_id, admission.build_id)
            .await
            .expect("repeat DAG cancellation")
    );
    assert_eq!(
        store
            .renew_attempt_lease(
                organization_id,
                active.attempt_id,
                active.fence,
                active.restore_epoch,
                &active.agent_id,
                30,
            )
            .await
            .expect("poll owner cancellation"),
        Some(true)
    );
    assert!(
        store
            .finalize_attempt(
                organization_id,
                active.attempt_id,
                active.fence,
                active.restore_epoch,
                &active.agent_id,
                TerminalOutcome::Aborted,
                json!({"termination": "cancelled"}),
            )
            .await
            .expect("terminalize cancelled active node")
    );
    let rows = sqlx::query_as::<_, (String, String, Option<String>)>(
        "SELECT node_key, status, logical_outcome
         FROM nodes
         WHERE build_id = $1
         ORDER BY node_key",
    )
    .bind(admission.build_id)
    .fetch_all(store.pool())
    .await
    .expect("read cancelled DAG nodes");
    assert_eq!(
        rows,
        vec![
            (
                "active".to_owned(),
                "aborted".to_owned(),
                Some("aborted".to_owned())
            ),
            (
                "queued".to_owned(),
                "aborted".to_owned(),
                Some("aborted".to_owned())
            ),
        ]
    );
    let build_status: String = sqlx::query_scalar("SELECT status FROM builds WHERE id = $1")
        .bind(admission.build_id)
        .fetch_one(store.pool())
        .await
        .expect("read cancelled build");
    assert_eq!(build_status, "aborted");
}

#[tokio::test]
async fn tenant_audit_is_hash_chained_exportable_immutable_and_retained() {
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
            "audited",
        )
        .await
        .expect("create audited project");
    let admission = store
        .admit_build(&NewBuild {
            organization_id,
            project_id,
            idempotency_key: "audit-build".to_owned(),
            pipeline_digest: [0x71; 32],
            node_key: "build".to_owned(),
            required_capabilities: vec![],
            required_trust_pool: "default".to_owned(),
            priority: 0,
            execution_spec: json!({"program": "true"}),
        })
        .await
        .expect("admit an automatically audited build");
    for (category, action, subject) in [
        ("identity", "identity.bound", "identity:operator"),
        ("authentication", "session.opened", "session:one"),
        ("credential_grant", "credential.issued", "attempt:one"),
        ("approval", "environment.approved", "environment:production"),
        ("artifact", "artifact.committed", "artifact:report"),
        ("admin", "retention.changed", "tenant:self"),
    ] {
        store
            .append_audit_event(&NewAuditEvent {
                organization_id,
                category,
                actor_subject: "oidc:operator",
                action,
                subject,
                payload: json!({"build_id": admission.build_id}),
            })
            .await
            .expect("append explicit audit category");
    }
    store
        .append_audit_event(&NewAuditEvent {
            organization_id,
            category: "admin",
            actor_subject: "oidc:operator",
            action: "numeric.canonicalized",
            subject: "tenant:self",
            payload: json!({"negative_zero": -0.0}),
        })
        .await
        .expect("append a payload PostgreSQL JSONB normalizes");

    let export = store
        .verify_audit_chain(organization_id)
        .await
        .expect("verify the complete tenant chain");
    assert!(export.events.len() >= 7);
    let categories = export
        .events
        .iter()
        .map(|event| event.category.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    for category in [
        "scheduling",
        "identity",
        "authentication",
        "credential_grant",
        "approval",
        "artifact",
        "admin",
    ] {
        assert!(categories.contains(category), "missing {category} audit");
    }
    let mut paged_sequences = Vec::new();
    let mut after_sequence = 0;
    let mut first_page = None;
    loop {
        let page = store
            .export_audit_page(organization_id, after_sequence, 2)
            .await
            .expect("export a bounded, independently verifiable audit page");
        if first_page.is_none() {
            first_page = Some(page.clone());
        }
        paged_sequences.extend(page.events.iter().map(|event| event.sequence));
        let Some(next) = page.next_after_sequence else {
            break;
        };
        after_sequence = next;
    }
    assert_eq!(
        paged_sequences,
        export
            .events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>()
    );
    let mut tampered_page = first_page.expect("the audited build produces a first page");
    tampered_page.events[0].payload = json!({"tampered": true});
    assert!(matches!(
        verify_audit_page(&tampered_page),
        Err(StoreError::CorruptAuditChain { .. })
    ));

    assert_eq!(
        store
            .extend_audit_retention(organization_id, 10_000)
            .await
            .expect("extend audit retention")
            .retain_until_unix_ms,
        10_000
    );
    assert_eq!(
        store
            .extend_audit_retention(organization_id, 1)
            .await
            .expect("refuse to shorten audit retention")
            .retain_until_unix_ms,
        10_000
    );
    assert!(
        store
            .set_audit_legal_hold(organization_id, true)
            .await
            .expect("place audit legal hold")
            .legal_hold
    );
    assert!(
        !store
            .set_audit_legal_hold(organization_id, false)
            .await
            .expect("explicitly release audit legal hold")
            .legal_hold
    );
    let retained = store
        .verify_audit_chain(organization_id)
        .await
        .expect("export retained chain");
    assert_eq!(
        retained
            .retention
            .expect("retention policy")
            .retain_until_unix_ms,
        10_000
    );

    let writer_store = store.clone();
    let reader_store = store.clone();
    let writer = async move {
        for index in 0..32 {
            let subject = format!("concurrency:{index}");
            writer_store
                .append_audit_event(&NewAuditEvent {
                    organization_id,
                    category: "admin",
                    actor_subject: "system:concurrency-test",
                    action: "audit.concurrent.appended",
                    subject: &subject,
                    payload: json!({"index": index}),
                })
                .await?;
        }
        Ok::<(), StoreError>(())
    };
    let reader = async move {
        for _ in 0..32 {
            reader_store.verify_audit_chain(organization_id).await?;
        }
        Ok::<(), StoreError>(())
    };
    let (writer_result, reader_result) = tokio::join!(writer, reader);
    writer_result.expect("append while exports hold consistent snapshots");
    reader_result.expect("concurrent audit exports never mix chain versions");

    let policy_store = store.clone();
    let policy_writer = async move {
        for index in 0..32 {
            policy_store
                .extend_audit_retention(organization_id, 10_001 + index)
                .await?;
            policy_store
                .set_audit_legal_hold(organization_id, index % 2 == 0)
                .await?;
        }
        Ok::<(), StoreError>(())
    };
    let policy_reader_store = store.clone();
    let policy_reader = async move {
        for _ in 0..32 {
            policy_reader_store
                .verify_audit_chain(organization_id)
                .await?;
        }
        Ok::<(), StoreError>(())
    };
    let (policy_result, policy_export_result) =
        tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(policy_writer, policy_reader)
        })
        .await
        .expect("audit policy writes and exports do not deadlock");
    policy_result.expect("retention and legal-hold updates remain serializable");
    policy_export_result.expect("exports remain consistent during policy changes");

    let retained = store
        .verify_audit_chain(organization_id)
        .await
        .expect("verify the post-concurrency tenant chain");

    let mutation = sqlx::query(
        "UPDATE audit_events
         SET payload = '{\"rewritten\":true}'::jsonb
         WHERE organization_id = $1 AND sequence = 1",
    )
    .bind(organization_id)
    .execute(store.pool())
    .await;
    assert!(mutation.is_err(), "audit payload mutation must be denied");
    let deletion = sqlx::query(
        "DELETE FROM audit_events
         WHERE organization_id = $1 AND sequence = 1",
    )
    .bind(organization_id)
    .execute(store.pool())
    .await;
    assert!(deletion.is_err(), "audit event deletion must be denied");

    sqlx::query(
        "UPDATE audit_chain_heads
         SET next_sequence = next_sequence + 1
         WHERE organization_id = $1",
    )
    .bind(organization_id)
    .execute(store.pool())
    .await
    .expect("inject a sequence gap");
    assert!(matches!(
        store.verify_audit_chain(organization_id).await,
        Err(StoreError::CorruptAuditChain { .. })
    ));
    sqlx::query(
        "UPDATE audit_chain_heads
         SET next_sequence = next_sequence - 1,
             last_hash = decode(repeat('ff', 32), 'hex')
         WHERE organization_id = $1",
    )
    .bind(organization_id)
    .execute(store.pool())
    .await
    .expect("inject a head-hash substitution");
    assert!(matches!(
        store.verify_audit_chain(organization_id).await,
        Err(StoreError::CorruptAuditChain { .. })
    ));
    sqlx::query(
        "UPDATE audit_chain_heads
         SET last_hash = $2
         WHERE organization_id = $1",
    )
    .bind(organization_id)
    .bind(retained.head_hash.as_slice())
    .execute(store.pool())
    .await
    .expect("restore the verified head");
    store
        .verify_audit_chain(organization_id)
        .await
        .expect("chain recovers after restoring the known head");
}

#[tokio::test]
async fn artifact_metadata_is_exact_fenced_retained_and_no_overwrite() {
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
            "artifact-product",
        )
        .await
        .expect("create artifact project");
    let admission = store
        .admit_build(&NewBuild {
            organization_id,
            project_id,
            idempotency_key: "artifact-build".to_owned(),
            pipeline_digest: [0x81; 32],
            node_key: "package".to_owned(),
            required_capabilities: vec!["linux".to_owned()],
            required_trust_pool: "trusted".to_owned(),
            priority: 0,
            execution_spec: json!({"program": "true"}),
        })
        .await
        .expect("admit artifact build");
    let claim = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "artifact-scheduler".to_owned(),
            agent_id: "artifact-agent".to_owned(),
            capabilities: vec!["linux".to_owned()],
            trust_pool: "trusted".to_owned(),
            lease_seconds: 60,
            fairness_seed: 0,
        })
        .await
        .expect("claim artifact work")
        .expect("artifact work is ready");
    assert!(
        store
            .accept_offer(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "artifact-agent",
            )
            .await
            .expect("accept artifact work")
    );
    let publication_fence_digest = [0x83; 32];
    assert!(
        store
            .register_artifact(
                organization_id,
                admission.build_id,
                admission.node_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "artifact-agent",
                "reports/retained-publication.xml",
                publication_fence_digest,
                64,
                "application/xml",
                86_400,
            )
            .await
            .expect("reserve retained artifact")
    );
    assert!(
        !store
            .objects_globally_eligible_for_deletion(10_000)
            .await
            .expect("inspect pending retained artifact")
            .contains(&publication_fence_digest),
        "pending publication must protect its digest from deletion eligibility"
    );
    assert!(
        !store
            .claim_objects_globally_for_deletion(10_000)
            .await
            .expect("try to claim pending retained artifact")
            .iter()
            .any(|claim| claim.digest == publication_fence_digest),
        "pending publication must not receive a durable deletion claim"
    );
    assert!(
        store
            .mark_artifact_available(
                organization_id,
                admission.build_id,
                admission.node_id,
                claim.attempt_id,
                claim.fence,
                "reports/retained-publication.xml",
                publication_fence_digest,
                64,
                "application/xml",
                0,
            )
            .await
            .expect("publish retained artifact")
    );
    assert!(
        !store
            .objects_globally_eligible_for_deletion(10_000)
            .await
            .expect("inspect published retained artifact")
            .contains(&publication_fence_digest),
        "publication must preserve the requested retention"
    );
    let digest = [0x82; 32];
    assert!(
        !store
            .register_artifact(
                organization_id,
                admission.build_id,
                admission.node_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "artifact-agent",
                "reports/overflow.xml",
                digest,
                4096,
                "application/xml",
                MAX_OBJECT_RETENTION_SECONDS + 1,
            )
            .await
            .expect("reject retention overflow before database interval arithmetic")
    );
    assert!(
        store
            .build_artifacts(organization_id, project_id, admission.build_id)
            .await
            .expect("list artifacts after rejected retention")
            .iter()
            .all(|artifact| artifact.name != "reports/overflow.xml")
    );
    assert!(
        store
            .register_artifact(
                organization_id,
                admission.build_id,
                admission.node_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "artifact-agent",
                "reports/result.xml",
                digest,
                4096,
                "application/xml",
                86_400,
            )
            .await
            .expect("register exact artifact")
    );
    let reserved = store
        .build_artifacts(organization_id, project_id, admission.build_id)
        .await
        .expect("list reserved artifact");
    let reserved = reserved
        .iter()
        .find(|artifact| artifact.name == "reports/result.xml")
        .expect("reserved exact artifact");
    assert_eq!(reserved.status, ObjectStatus::Pending);
    assert!(
        store
            .artifact_publication_claim_active(organization_id, digest, 4096)
            .await
            .expect("inspect live publication claim"),
        "a current live reservation must protect its filesystem claim"
    );
    sqlx::query(
        "UPDATE attempts
         SET lease_expires_at = clock_timestamp() - interval '1 second'
         WHERE organization_id = $1 AND id = $2",
    )
    .bind(organization_id)
    .bind(claim.attempt_id)
    .execute(store.pool())
    .await
    .expect("expire the publishing lease after metadata reservation");
    assert!(
        !store
            .artifact_publication_claim_active(organization_id, digest, 4096)
            .await
            .expect("inspect abandoned publication claim"),
        "an expired reservation must become reclaimable"
    );
    assert!(
        store
            .register_artifact(
                organization_id,
                admission.build_id,
                admission.node_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "artifact-agent",
                "reports/result.xml",
                digest,
                4096,
                "application/xml",
                172_800,
            )
            .await
            .expect("resume exact reservation after lease expiry and extend retention")
    );
    assert!(
        store
            .mark_artifact_available(
                organization_id,
                admission.build_id,
                admission.node_id,
                claim.attempt_id,
                claim.fence,
                "reports/result.xml",
                digest,
                4096,
                "application/xml",
                86_400,
            )
            .await
            .expect("publish exact artifact")
    );
    assert!(
        store
            .mark_artifact_available(
                organization_id,
                admission.build_id,
                admission.node_id,
                claim.attempt_id,
                claim.fence,
                "reports/result.xml",
                digest,
                4096,
                "application/xml",
                86_400,
            )
            .await
            .expect("idempotently replay artifact publication")
    );
    assert!(
        !store
            .register_artifact(
                organization_id,
                admission.build_id,
                admission.node_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "artifact-agent",
                "reports/result.xml",
                [0x83; 32],
                4096,
                "application/xml",
                86_400,
            )
            .await
            .expect("reject digest substitution")
    );
    assert!(
        !store
            .register_artifact(
                organization_id,
                Uuid::new_v4(),
                admission.node_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "artifact-agent",
                "reports/other.xml",
                digest,
                4096,
                "application/xml",
                86_400,
            )
            .await
            .expect("reject another build")
    );
    assert!(
        !store
            .register_artifact(
                organization_id,
                admission.build_id,
                admission.node_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch + 1,
                "artifact-agent",
                "reports/stale.xml",
                digest,
                4096,
                "application/xml",
                86_400,
            )
            .await
            .expect("reject another restore epoch")
    );
    let artifacts = store
        .build_artifacts(organization_id, project_id, admission.build_id)
        .await
        .expect("list build artifacts");
    let artifact = artifacts
        .iter()
        .find(|artifact| artifact.name == "reports/result.xml")
        .expect("exact result artifact");
    assert_eq!(artifact.build_id, admission.build_id);
    assert_eq!(artifact.node_id, admission.node_id);
    assert_eq!(artifact.attempt_id, claim.attempt_id);
    assert_eq!(artifact.fence, claim.fence);
    assert_eq!(artifact.digest, digest);
    assert_eq!(artifact.bytes, 4096);
    assert_eq!(artifact.media_type, "application/xml");
    assert_eq!(artifact.status, ObjectStatus::Available);
    let retained: bool = sqlx::query_scalar(
        "SELECT retain_until >= clock_timestamp() + interval '47 hours'
         FROM object_retention
         WHERE organization_id = $1 AND object_digest = $2",
    )
    .bind(organization_id)
    .bind(digest.as_slice())
    .fetch_one(store.pool())
    .await
    .expect("read atomic artifact retention");
    assert!(retained);
    let audit = store
        .verify_audit_chain(organization_id)
        .await
        .expect("verify artifact audit");
    assert!(audit.events.iter().any(|event| {
        event.category == "artifact"
            && event.action == "artifact.committed"
            && event.payload["attempt_id"] == claim.attempt_id.to_string()
    }));
}

#[tokio::test]
async fn junit_evidence_is_bounded_immutable_and_preserves_flaky_history() {
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
            "test-truth",
        )
        .await
        .expect("create test-truth project");
    let admission = store
        .admit_build(&NewBuild {
            organization_id,
            project_id,
            idempotency_key: "test-truth-build".to_owned(),
            pipeline_digest: [0x91; 32],
            node_key: "test".to_owned(),
            required_capabilities: vec!["linux".to_owned()],
            required_trust_pool: "trusted".to_owned(),
            priority: 0,
            execution_spec: json!({"program": "true"}),
        })
        .await
        .expect("admit test-truth build");
    let claim = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "test-truth-scheduler".to_owned(),
            agent_id: "test-truth-agent".to_owned(),
            capabilities: vec!["linux".to_owned()],
            trust_pool: "trusted".to_owned(),
            lease_seconds: 60,
            fairness_seed: 0,
        })
        .await
        .expect("claim test-truth work")
        .expect("test-truth work is ready");
    assert!(
        store
            .accept_offer(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                "test-truth-agent",
            )
            .await
            .expect("accept test-truth work")
    );

    let failed_xml = br#"<testsuite name="unit"><testcase classname="core" name="sometimes" time="0.2"><failure message="first"/></testcase><testcase classname="core" name="same"/><testcase classname="core" name="same"/></testsuite>"#;
    let passed_xml = br#"<testsuite name="unit"><testcase classname="core" name="sometimes" time="0.1"/></testsuite>"#;
    for (name, bytes) in [
        ("reports/junit-1.xml", failed_xml.as_slice()),
        ("reports/junit-2.xml", passed_xml.as_slice()),
    ] {
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        assert!(
            store
                .register_artifact(
                    organization_id,
                    admission.build_id,
                    admission.node_id,
                    claim.attempt_id,
                    claim.fence,
                    claim.restore_epoch,
                    "test-truth-agent",
                    name,
                    digest,
                    i64::try_from(bytes.len()).expect("small report"),
                    "application/junit+xml",
                    86_400,
                )
                .await
                .expect("register raw immutable JUnit artifact")
        );
        assert!(
            store
                .mark_artifact_available(
                    organization_id,
                    admission.build_id,
                    admission.node_id,
                    claim.attempt_id,
                    claim.fence,
                    name,
                    digest,
                    i64::try_from(bytes.len()).expect("small report"),
                    "application/junit+xml",
                    86_400,
                )
                .await
                .expect("publish raw immutable JUnit artifact")
        );
        let report = parse_junit(
            bytes,
            TestReportSource {
                organization_id,
                project_id,
                build_id: admission.build_id,
                node_id: admission.node_id,
                attempt_id: claim.attempt_id,
                fence: claim.fence,
                artifact_name: name.to_owned(),
            },
            JunitLimits::default(),
        )
        .expect("normalize bounded JUnit");
        assert!(
            store
                .ingest_test_report(&report)
                .await
                .expect("ingest normalized test truth")
        );
        assert!(
            !store
                .ingest_test_report(&report)
                .await
                .expect("idempotent replay is explicit")
        );
        if name.ends_with("-1.xml") {
            assert_eq!(report.suites[0].cases[1].duplicate_ordinal, 0);
            assert_eq!(report.suites[0].cases[2].duplicate_ordinal, 1);
        }
    }

    let history = store
        .test_case_history(
            organization_id,
            project_id,
            "unit",
            "core",
            "sometimes",
            100,
        )
        .await
        .expect("read append-only test history");
    assert_eq!(history.observations.len(), 2);
    assert_eq!(history.observations[0].outcome, TestOutcome::Failed);
    assert_eq!(history.observations[1].outcome, TestOutcome::Passed);
    assert!(history.flaky);
    let limited_history = store
        .test_case_history(organization_id, project_id, "unit", "core", "sometimes", 1)
        .await
        .expect("limit observations without truncating flakiness truth");
    assert_eq!(limited_history.observations.len(), 1);
    assert!(limited_history.flaky);
    let raw_retention_extended: bool = sqlx::query_scalar(
        "SELECT bool_and(retain_until >= clock_timestamp() + interval '29 days')
         FROM object_retention
         WHERE organization_id = $1
           AND object_digest IN ($2, $3)",
    )
    .bind(organization_id)
    .bind(Sha256::digest(failed_xml).as_slice())
    .bind(Sha256::digest(passed_xml).as_slice())
    .fetch_one(store.pool())
    .await
    .expect("read normalized-source retention");
    assert!(raw_retention_extended);

    let mutation_error = sqlx::query(
        "UPDATE normalized_test_cases
         SET outcome = 'passed'
         WHERE organization_id = $1",
    )
    .bind(organization_id)
    .execute(store.pool())
    .await
    .expect_err("normalized test evidence is immutable");
    assert_eq!(
        mutation_error
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some("23514")
    );
    let audit = store
        .verify_audit_chain(organization_id)
        .await
        .expect("verify test-result audit");
    assert_eq!(
        audit
            .events
            .iter()
            .filter(|event| event.action == "test_report.ingested")
            .count(),
        2
    );
}
