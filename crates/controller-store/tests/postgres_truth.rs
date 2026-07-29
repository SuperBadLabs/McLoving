use std::sync::Arc;

use mcloving_controller_store::{
    AgentCancellationCompletion, AgentCancellationDisposition, AgentCancellationOutcome,
    AgentReconciliationDisposition, ClaimRequest, EffectClass, EffectStatus, NewBuild, NewLogChunk,
    ObjectKind, ObjectStatus, RetryDecision, Store, StoreError, TerminalOutcome, WaitReason,
};
use serde_json::json;
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
                "trusted-windows",
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
                "trusted-windows",
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
    let digest = [41; 32];
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
    assert_eq!(
        store
            .objects_globally_eligible_for_deletion(10)
            .await
            .expect("list expired content"),
        vec![digest]
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
        store
            .objects_globally_eligible_for_deletion(10)
            .await
            .expect("missing second-tenant retention is fail-closed")
            .is_empty()
    );
    assert!(
        store
            .retain_object_for(second_organization_id, digest, 0)
            .await
            .expect("expire second-tenant retention")
    );
    assert_eq!(
        store
            .objects_globally_eligible_for_deletion(10)
            .await
            .expect("all referencing tenants have expired retention"),
        vec![digest]
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
        store
            .objects_globally_eligible_for_deletion(10)
            .await
            .expect("one tenant hold blocks global deletion")
            .is_empty()
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
        store
            .objects_globally_eligible_for_deletion(10)
            .await
            .expect("held content is not deletable")
            .is_empty()
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
    assert_eq!(
        store
            .objects_globally_eligible_for_deletion(10)
            .await
            .expect("released content is deletable"),
        vec![digest]
    );
    let deletion_claims = store
        .claim_objects_globally_for_deletion(10)
        .await
        .expect("claim released content for deletion");
    assert_eq!(deletion_claims.len(), 1);
    let deletion_claim = deletion_claims[0];
    assert_eq!(deletion_claim.digest, digest);
    assert_eq!(
        store
            .pending_object_deletion_claims(10)
            .await
            .expect("recover committed claim after worker restart"),
        vec![deletion_claim]
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
        store
            .objects_globally_eligible_for_deletion(10)
            .await
            .expect("retention extension is monotonic")
            .is_empty()
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
        .claim_objects_globally_for_deletion(1)
        .await
        .expect("eligible content is not starved by protected digest prefix");
    assert_eq!(completed_claims.len(), 1);
    let completed_claim = completed_claims[0];
    assert_eq!(completed_claim.digest, disposable_digest);
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
