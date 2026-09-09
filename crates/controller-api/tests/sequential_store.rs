use mcloving_controller_api::sequential::{SequentialBuildBinding, plan_sequential_build};
use mcloving_controller_store::{
    ClaimRequest, ClaimedAttempt, PipelineOperationalState, PipelineOperationalStateTransition,
    PipelineWrite, RetryDecision, SequentialDagBuild, Store, StoreError, TerminalOutcome,
};
use mcloving_pipeline_ir::{ParseLimits, compile_strict_yaml};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

async fn fixture() -> Option<(Store, SequentialDagBuild)> {
    let Ok(url) = std::env::var("MCLOVING_TEST_DATABASE_URL") else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return None;
    };
    let store = Store::new(
        PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .unwrap(),
    );
    store.migrate().await.unwrap();
    let org = Uuid::new_v4();
    let project = Uuid::new_v4();
    let pipeline_id = Uuid::new_v4();
    store
        .create_project(org, &format!("seq-{org}"), project, "sequential-store")
        .await
        .unwrap();
    let source = json!({"version": 1, "name": "sequential-store", "stages": [
        {"id":"first", "name":"First", "steps": [
            {"process":{"program":"/bin/sh", "args":["-xe", "-c", ": first"]}},
            {"process":{"program":"/bin/sh", "args":["-xe", "-c", ": second"]}}]},
        {"id":"last", "name":"Last", "steps":[{"process":{"program":"/bin/sh", "args":["-xe", "-c", ": third"]}}]}
    ]}).to_string();
    let ir =
        compile_strict_yaml("saved:sequential-store", &source, ParseLimits::default()).unwrap();
    store
        .put_pipeline(
            &PipelineWrite {
                organization_id: org,
                project_id: project,
                pipeline_id,
                slug: "sequential-store".to_owned(),
                source_sha256: Sha256::digest(source.as_bytes()).into(),
                source,
                semantic_digest: ir.semantic_digest().unwrap(),
                schema_major: 1,
                schema_minor: 0,
                parameter_schema: json!({}),
            },
            Some(0),
        )
        .await
        .unwrap();
    let plan = plan_sequential_build(
        &ir,
        SequentialBuildBinding {
            organization_id: org,
            project_id: project,
            pipeline_id,
            pipeline_revision: 1,
            pipeline_operational_generation: 1,
            idempotency_key: "sequential-store".to_owned(),
        },
    )
    .unwrap();
    Some((store, plan))
}

fn claim(plan: &SequentialDagBuild) -> ClaimRequest {
    ClaimRequest {
        organization_id: plan.dag().organization_id,
        scheduler_id: "seq-store".to_owned(),
        agent_id: "seq-store".to_owned(),
        capabilities: vec!["platform:linux".to_owned()],
        trust_pool: "migration-deny-authority".to_owned(),
        lease_seconds: 30,
        fairness_seed: 0,
    }
}

async fn running(store: &Store, plan: &SequentialDagBuild) -> ClaimedAttempt {
    let claim = store.claim_next(&claim(plan)).await.unwrap().unwrap();
    assert!(
        store
            .accept_offer(
                claim.organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                &claim.agent_id
            )
            .await
            .unwrap()
    );
    assert!(
        store
            .mark_attempt_running(
                claim.organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                &claim.agent_id
            )
            .await
            .unwrap()
    );
    claim
}

async fn finish(store: &Store, claim: &ClaimedAttempt, outcome: TerminalOutcome) {
    assert!(
        store
            .finalize_attempt(
                claim.organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                &claim.agent_id,
                outcome,
                json!({"store_accounting_test": true})
            )
            .await
            .unwrap()
    );
}

async fn observe_snapshots(store: &Store, plan: &SequentialDagBuild, build: Uuid) {
    for _ in 0..40 {
        let result = store
            .sequential_build_result(
                plan.dag().organization_id,
                plan.dag().project_id,
                build,
                100,
            )
            .await
            .unwrap()
            .unwrap();
        let mut all_succeeded = true;
        for step in result.stages.iter().flat_map(|stage| &stage.steps) {
            let latest = &step.attempts.last().unwrap().accounting;
            match step.status.as_str() {
                "succeeded" | "failed" => assert_eq!(latest.status, step.status),
                "skipped" => assert_eq!(latest.status, "aborted"),
                "queued" | "blocked" => assert_eq!(latest.status, "queued"),
                _ => {}
            }
            all_succeeded &= step.status == "succeeded";
        }
        assert_eq!(result.status == "succeeded", all_succeeded);
    }
}

#[tokio::test]
async fn atomic_digest_binding_replay_disabled_generation_and_scope() {
    let Some((store, plan)) = fixture().await else {
        return;
    };
    let dag = plan.dag();
    let mut changed = dag.clone();
    changed.pipeline_digest = [7; 32];
    let changed = SequentialDagBuild::new(changed, plan.layout().to_vec()).unwrap();
    assert!(matches!(
        store.admit_sequential_dag(&changed).await,
        Err(StoreError::InvalidDag(_))
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM builds WHERE organization_id = $1")
            .bind(dag.organization_id)
            .fetch_one(store.pool())
            .await
            .unwrap(),
        0
    );
    // Fail the second node write, after the build and first node/attempt were inserted.
    // The trigger is restricted to this fresh disposable tenant and removed before assertions.
    let fault_name = format!("seq_fault_{}", dag.organization_id.simple());
    sqlx::raw_sql(&format!("CREATE FUNCTION {fault_name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.organization_id = '{}'::uuid AND NEW.node_key = 'first[step=02]' THEN RAISE EXCEPTION 'contained admission write fault'; END IF; RETURN NEW; END $$; CREATE TRIGGER {fault_name} BEFORE INSERT ON nodes FOR EACH ROW EXECUTE FUNCTION {fault_name}();", dag.organization_id))
        .execute(store.pool()).await.unwrap();
    let failed_write = store.admit_sequential_dag(&plan).await;
    sqlx::raw_sql(&format!(
        "DROP TRIGGER {fault_name} ON nodes; DROP FUNCTION {fault_name}();"
    ))
    .execute(store.pool())
    .await
    .unwrap();
    assert!(matches!(failed_write, Err(StoreError::Database(_))));
    for table in ["builds", "nodes", "attempts"] {
        assert_eq!(
            sqlx::query_scalar::<_, i64>(&format!(
                "SELECT count(*) FROM {table} WHERE organization_id=$1"
            ))
            .bind(dag.organization_id)
            .fetch_one(store.pool())
            .await
            .unwrap(),
            0
        );
    }
    let (one, two) = tokio::join!(
        store.admit_sequential_dag(&plan),
        store.admit_sequential_dag(&plan)
    );
    let one = one.unwrap();
    let two = two.unwrap();
    assert_ne!(one.created, two.created);
    assert_eq!(one.build_id, two.build_id);
    assert_eq!(one.nodes, two.nodes);
    let mut substituted_layout = plan.layout().to_vec();
    for row in substituted_layout.iter_mut().take(2) {
        row.stage_id = "renamed".to_owned();
        row.stage_name = "Renamed".to_owned();
    }
    let substituted = SequentialDagBuild::new(dag.clone(), substituted_layout).unwrap();
    assert!(matches!(
        store.admit_sequential_dag(&substituted).await,
        Err(StoreError::IdempotencyConflict(_))
    ));

    let projected = store
        .sequential_build_result(dag.organization_id, dag.project_id, one.build_id, 100)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(projected.stages.len(), 2);
    assert_eq!(projected.stages[0].steps.len(), 2);
    assert_eq!(projected.stages[0].status, "queued");
    assert_eq!(projected.stages[1].status, "blocked");
    assert!(matches!(
        store
            .sequential_build_result(dag.organization_id, dag.project_id, one.build_id, 2)
            .await,
        Err(StoreError::SequentialReadIncomplete)
    ));
    assert!(
        store
            .sequential_build_result(Uuid::new_v4(), dag.project_id, one.build_id, 100)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .sequential_build_result(dag.organization_id, Uuid::new_v4(), one.build_id, 100)
            .await
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        store.admit_dag(dag).await,
        Err(StoreError::IdempotencyConflict(_))
    ));
    assert!(matches!(
        store.admit_sequential_dag(&changed).await,
        Err(StoreError::IdempotencyConflict(_))
    ));
    // Edit the saved revision, then disable the definition: exact original replay remains stable.
    let mut revision = store
        .pipeline(dag.organization_id, dag.project_id, dag.pipeline_id)
        .await
        .unwrap()
        .unwrap();
    revision.source.push('\n');
    store
        .put_pipeline(
            &PipelineWrite {
                organization_id: dag.organization_id,
                project_id: dag.project_id,
                pipeline_id: dag.pipeline_id,
                slug: "sequential-store".to_owned(),
                source_sha256: Sha256::digest(revision.source.as_bytes()).into(),
                source: revision.source,
                semantic_digest: [9; 32],
                schema_major: 1,
                schema_minor: 0,
                parameter_schema: json!({}),
            },
            Some(1),
        )
        .await
        .unwrap();
    store
        .transition_pipeline_operational_state(&PipelineOperationalStateTransition {
            organization_id: dag.organization_id,
            project_id: dag.project_id,
            pipeline_id: dag.pipeline_id,
            expected_generation: 1,
            state: PipelineOperationalState::Disabled,
            reason: "contained test".to_owned(),
            actor_subject: "operator@test".to_owned(),
            source_identity: "test:sequential".to_owned(),
            source_generation: "1".to_owned(),
            source_effective_at_unix_ms: 1_800_000_000_000,
            source_provenance_sha256: [2; 32],
            idempotency_key: "disable".to_owned(),
        })
        .await
        .unwrap();
    let replay = store.admit_sequential_dag(&plan).await.unwrap();
    assert!(!replay.created);
    assert_eq!(replay.nodes, one.nodes);
    let mut fresh = dag.clone();
    fresh.idempotency_key = "fresh-disabled".to_owned();
    assert!(
        store
            .admit_sequential_dag(&SequentialDagBuild::new(fresh, plan.layout().to_vec()).unwrap())
            .await
            .is_err()
    );
    let mut wrong = dag.clone();
    wrong.project_id = Uuid::new_v4();
    assert!(
        store
            .admit_sequential_dag(&SequentialDagBuild::new(wrong, plan.layout().to_vec()).unwrap())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn retry_preserves_original_admission_and_projects_current_outcomes() {
    let Some((store, plan)) = fixture().await else {
        return;
    };
    let dag = plan.dag();
    let admission = store.admit_sequential_dag(&plan).await.unwrap();
    let first = running(&store, &plan).await;
    finish(&store, &first, TerminalOutcome::Succeeded).await;
    let second = running(&store, &plan).await;
    assert!(
        !store
            .finalize_attempt(
                second.organization_id,
                second.attempt_id,
                second.fence + 1,
                second.restore_epoch,
                &second.agent_id,
                TerminalOutcome::Succeeded,
                json!({})
            )
            .await
            .unwrap()
    );
    assert!(
        !store
            .finalize_attempt(
                second.organization_id,
                second.attempt_id,
                second.fence,
                second.restore_epoch + 1,
                &second.agent_id,
                TerminalOutcome::Succeeded,
                json!({})
            )
            .await
            .unwrap()
    );
    assert!(store.claim_next(&claim(&plan)).await.unwrap().is_none());
    finish(&store, &second, TerminalOutcome::Failed).await;
    let failed = store
        .sequential_build_result(dag.organization_id, dag.project_id, admission.build_id, 100)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(failed.status, "failed");
    assert_eq!(failed.stages[0].status, "failed");
    assert_eq!(failed.stages[1].status, "skipped");
    assert!(
        failed.stages[1].steps[0].attempts[0]
            .accounting
            .started_at_unix_ms
            .is_none()
    );
    let (retry, ()) = tokio::join!(
        store.schedule_retry(dag.organization_id, second.attempt_id, 2, "contained retry"),
        observe_snapshots(&store, &plan, admission.build_id)
    );
    assert!(matches!(retry.unwrap(), RetryDecision::Scheduled { .. }));
    let replay = store.admit_sequential_dag(&plan).await.unwrap();
    assert_eq!(replay.nodes, admission.nodes);
    let current = store
        .sequential_build_result(dag.organization_id, dag.project_id, admission.build_id, 100)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.stages[0].status, "running");
    assert_eq!(current.stages[0].steps[0].attempts.len(), 1);
    assert_eq!(current.stages[0].steps[1].attempts.len(), 2);
    assert_eq!(current.stages[1].steps[0].attempts.len(), 2);
    assert_eq!(current.stages[1].steps[0].max_attempts, 1);
    let retried = running(&store, &plan).await;
    assert_eq!(retried.node_id, second.node_id);
    finish(&store, &retried, TerminalOutcome::Succeeded).await;
    let last = running(&store, &plan).await;
    tokio::join!(
        finish(&store, &last, TerminalOutcome::Succeeded),
        observe_snapshots(&store, &plan, admission.build_id)
    );
    let completed = store
        .sequential_build_result(dag.organization_id, dag.project_id, admission.build_id, 100)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(completed.status, "succeeded");
    assert!(
        completed
            .stages
            .iter()
            .all(|stage| stage.status == "succeeded")
    );
    assert_eq!(
        completed.stages[0].steps[1].attempts[0].accounting.status,
        "failed"
    );
    assert_eq!(
        store.admit_sequential_dag(&plan).await.unwrap().nodes,
        admission.nodes
    );
}

#[tokio::test]
async fn coherent_cancellation_and_immutable_projection_integrity() {
    let Some((store, plan)) = fixture().await else {
        return;
    };
    let dag = plan.dag();
    let admission = store.admit_sequential_dag(&plan).await.unwrap();
    let reader = store.clone();
    let org = dag.organization_id;
    let project = dag.project_id;
    let build = admission.build_id;
    let read = async move {
        for _ in 0..40 {
            let result = reader
                .sequential_build_result(org, project, build, 100)
                .await
                .unwrap()
                .unwrap();
            let all_aborted = result
                .stages
                .iter()
                .flat_map(|stage| &stage.steps)
                .all(|step| step.status == "aborted");
            assert_eq!(result.status == "aborted", all_aborted);
        }
    };
    let cancel = store.request_cancellation(org, project, build);
    let ((), cancelled) = tokio::join!(read, cancel);
    assert!(cancelled.unwrap());
    let result = store
        .sequential_build_result(org, project, build, 100)
        .await
        .unwrap()
        .unwrap();
    for step in result.stages.iter().flat_map(|stage| &stage.steps) {
        assert_eq!(step.status, "aborted");
        assert!(step.attempts[0].accounting.started_at_unix_ms.is_none());
        assert!(step.attempts[0].logs.is_empty());
    }
    let original: Value = sqlx::query_scalar("SELECT dag_contract FROM builds WHERE id = $1")
        .bind(build)
        .fetch_one(store.pool())
        .await
        .unwrap();
    for mutation in 0..3 {
        let mut broken = original.clone();
        match mutation {
            0 => broken["sequential_layout"]["version"] = json!(2),
            1 => broken["sequential_layout"]["steps"][0]["stage_name"] = json!("Changed"),
            _ => broken["sequential_layout"] = Value::Null,
        }
        sqlx::query("UPDATE builds SET dag_contract = $2 WHERE id = $1")
            .bind(build)
            .bind(broken)
            .execute(store.pool())
            .await
            .unwrap();
        assert!(matches!(
            store
                .sequential_build_result(org, project, build, 100)
                .await,
            Err(StoreError::SequentialIntegrity(_))
        ));
    }
    sqlx::query("UPDATE builds SET dag_contract = $2 WHERE id = $1")
        .bind(build)
        .bind(original)
        .execute(store.pool())
        .await
        .unwrap();
    let node = admission.nodes.values().next().unwrap().node_id;
    sqlx::query("UPDATE nodes SET execution_spec = '{}'::jsonb WHERE id = $1")
        .bind(node)
        .execute(store.pool())
        .await
        .unwrap();
    assert!(matches!(
        store
            .sequential_build_result(org, project, build, 100)
            .await,
        Err(StoreError::SequentialIntegrity(_))
    ));
}

#[tokio::test]
async fn expired_prestart_requeues_but_started_sequential_work_requires_reconciliation() {
    let Some((store, plan)) = fixture().await else {
        return;
    };
    let dag = plan.dag();
    let admission = store.admit_sequential_dag(&plan).await.unwrap();
    let offered = store.claim_next(&claim(&plan)).await.unwrap().unwrap();
    sqlx::query(
        "UPDATE attempts SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1",
    )
    .bind(offered.attempt_id)
    .execute(store.pool())
    .await
    .unwrap();
    assert!(
        store
            .requeue_one_expired(dag.organization_id)
            .await
            .unwrap()
    );
    let active = running(&store, &plan).await;
    assert_eq!(active.attempt_id, offered.attempt_id);
    assert_eq!(active.fence, offered.fence + 1);
    assert!(
        !store
            .finalize_attempt(
                active.organization_id,
                active.attempt_id,
                offered.fence,
                active.restore_epoch,
                &active.agent_id,
                TerminalOutcome::Succeeded,
                json!({})
            )
            .await
            .unwrap()
    );

    sqlx::query(
        "UPDATE attempts SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1",
    )
    .bind(active.attempt_id)
    .execute(store.pool())
    .await
    .unwrap();
    assert!(
        store
            .requeue_one_expired(dag.organization_id)
            .await
            .unwrap()
    );
    assert!(store.claim_next(&claim(&plan)).await.unwrap().is_none());
    let result = store
        .sequential_build_result(dag.organization_id, dag.project_id, admission.build_id, 100)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result.status, "reconciliation_required");
    assert_eq!(result.stages[0].status, "reconciliation_required");
    assert_eq!(result.stages[1].status, "blocked");
    assert_eq!(result.stages[0].steps[0].attempts.len(), 1);
    assert_eq!(
        store.admit_sequential_dag(&plan).await.unwrap().nodes,
        admission.nodes
    );
}
