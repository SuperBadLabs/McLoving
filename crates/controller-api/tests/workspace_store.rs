use mcloving_controller_api::sequential::{SequentialBuildBinding, plan_sequential_build};
use mcloving_controller_store::{
    ClaimRequest, ClaimedAttempt, PipelineWrite, RetryDecision, SequentialDagBuild, Store,
    TerminalOutcome,
};
use mcloving_domain::workspace::{
    WORKSPACE_TRANSFER_CAPABILITY, WorkspaceEntry, WorkspaceGrant, WorkspaceSnapshot,
    WorkspaceTransferResult,
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
        capabilities: vec![
            "platform:linux".to_owned(),
            WORKSPACE_TRANSFER_CAPABILITY.to_owned(),
        ],
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

async fn grant(store: &Store, claim: &ClaimedAttempt) -> WorkspaceGrant {
    store
        .attempt_execution(
            claim.organization_id,
            claim.attempt_id,
            claim.fence,
            claim.restore_epoch,
            &claim.agent_id,
        )
        .await
        .unwrap()
        .unwrap()
        .workspace_transfer
        .unwrap()
}
fn summary(grant: &WorkspaceGrant, snapshot: WorkspaceSnapshot) -> Value {
    json!({"store_accounting_test": true, "workspace_transfer": WorkspaceTransferResult {
        version: 1, organization_id: grant.organization_id.clone(), build_id: grant.build_id.clone(), namespace_id: grant.namespace_id.clone(), generation: grant.generation, input_digest: grant.digest, snapshot: Some(snapshot), error: None,
    }})
}
async fn finish(
    store: &Store,
    claim: &ClaimedAttempt,
    value: Value,
) -> Result<bool, mcloving_controller_store::StoreError> {
    store
        .finalize_attempt(
            claim.organization_id,
            claim.attempt_id,
            claim.fence,
            claim.restore_epoch,
            &claim.agent_id,
            TerminalOutcome::Succeeded,
            value,
        )
        .await
}

fn assert_workspace_receipt_constraint(error: sqlx::Error) {
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("23514")
    );
    assert_eq!(
        error.as_database_error().unwrap().constraint(),
        Some("builds_workspace_receipt_shape")
    );
}

#[tokio::test]
async fn workspace_fenced_transfer_replay_final_receipts_and_cleanup() {
    let Some((store, plain)) = fixture().await else {
        return;
    };
    let plan = plain.clone().with_workspace_transfer().unwrap();
    let admission = store.admit_sequential_dag(&plan).await.unwrap();
    assert!(store.admit_sequential_dag(&plain).await.is_err());
    let mut missing_capability = claim(&plan);
    missing_capability.capabilities = vec!["platform:linux".to_owned()];
    assert!(
        store
            .claim_next(&missing_capability)
            .await
            .unwrap()
            .is_none()
    );
    let first = running(&store, &plan).await;
    let seed = grant(&store, &first).await;
    assert_eq!(seed.generation, 0);
    assert!(seed.snapshot.entries.is_empty());
    // PostgreSQL enforces receipt presence even when a writer bypasses Rust validation.
    assert_workspace_receipt_constraint(
        sqlx::query("UPDATE builds SET workspace_receipt=$2 WHERE id=$1")
            .bind(admission.build_id)
            .bind(serde_json::to_value(seed.snapshot.receipt().unwrap()).unwrap())
            .execute(store.pool())
            .await
            .unwrap_err(),
    );
    let snapshot = WorkspaceSnapshot {
        version: 1,
        entries: vec![
            WorkspaceEntry::Directory {
                path: "nested".to_owned(),
            },
            WorkspaceEntry::File {
                path: "shared.txt".to_owned(),
                executable: false,
                contents: b"retained payload\n".to_vec(),
            },
        ],
    };
    let exact = summary(&seed, snapshot.clone());
    for field in ["organization_id", "build_id", "namespace_id"] {
        let mut forged = exact.clone();
        forged["workspace_transfer"][field] = json!(Uuid::new_v4());
        assert!(finish(&store, &first, forged).await.is_err());
    }
    let mut stale = exact.clone();
    stale["workspace_transfer"]["generation"] = json!(1);
    assert!(finish(&store, &first, stale).await.is_err());
    assert!(finish(&store, &first, json!({})).await.is_err());
    let mut stale_fence = first.clone();
    stale_fence.fence -= 1;
    assert!(!finish(&store, &stale_fence, exact.clone()).await.unwrap());
    assert!(finish(&store, &first, exact.clone()).await.unwrap());
    assert!(finish(&store, &first, exact.clone()).await.unwrap());
    let changed = WorkspaceSnapshot {
        version: 1,
        entries: vec![],
    };
    assert!(
        !finish(&store, &first, summary(&seed, changed))
            .await
            .unwrap()
    );
    for generation in 1..=2 {
        let current = running(&store, &plan).await;
        if generation == 1 {
            assert_workspace_receipt_constraint(
                sqlx::query("UPDATE builds SET workspace_receipt=NULL WHERE id=$1")
                    .bind(admission.build_id)
                    .execute(store.pool())
                    .await
                    .unwrap_err(),
            );
            let original: (i64, Option<Value>, Option<Value>) = sqlx::query_as("SELECT workspace_generation,workspace_snapshot,workspace_receipt FROM builds WHERE id=$1").bind(admission.build_id).fetch_one(store.pool()).await.unwrap();
            let mut bad_receipt = original.2.clone().unwrap();
            bad_receipt["total_bytes"] = json!(0);
            for changed in [
                (
                    original.0,
                    Some(json!({"version":1,"entries":[]})),
                    original.2.clone(),
                ),
                (original.0, original.1.clone(), Some(bad_receipt)),
                (65, original.1.clone(), original.2.clone()),
                (0, original.1.clone(), None),
            ] {
                sqlx::query("UPDATE builds SET workspace_generation=$2,workspace_snapshot=$3,workspace_receipt=$4 WHERE id=$1").bind(admission.build_id).bind(changed.0).bind(changed.1).bind(changed.2).execute(store.pool()).await.unwrap();
                assert!(
                    store
                        .attempt_execution(
                            current.organization_id,
                            current.attempt_id,
                            current.fence,
                            current.restore_epoch,
                            &current.agent_id
                        )
                        .await
                        .is_err()
                );
            }
            sqlx::query("UPDATE builds SET workspace_generation=$2,workspace_snapshot=$3,workspace_receipt=$4 WHERE id=$1").bind(admission.build_id).bind(original.0).bind(original.1).bind(original.2).execute(store.pool()).await.unwrap();
        }
        let next = grant(&store, &current).await;
        assert_eq!(next.namespace_id, seed.namespace_id);
        assert_eq!(next.generation, generation);
        assert_eq!(next.snapshot, snapshot);
        assert!(
            finish(&store, &current, summary(&next, snapshot.clone()))
                .await
                .unwrap()
        );
    }
    // Replay remains valid after whole-build closure and deletion of the checkpoint bytes.
    assert!(finish(&store, &first, exact).await.unwrap());
    let result = store
        .sequential_build_result(
            plan.dag().organization_id,
            plan.dag().project_id,
            admission.build_id,
            100,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result.status, "succeeded");
    assert!(result.workspace_closed);
    assert_eq!(result.workspace_generation, 3);
    assert!(result.workspace_receipt.is_some());
    let original = result.workspace_receipt.clone().unwrap();
    let mut altered_digest = original.clone();
    altered_digest["digest"][0] = json!(255);
    if altered_digest == original {
        altered_digest["digest"][0] = json!(0);
    }
    let mut invalid_version = original.clone();
    invalid_version["version"] = json!(2);
    for (generation, receipt) in [
        (65, Some(original.clone())),
        (3, Some(altered_digest)),
        (3, Some(invalid_version)),
    ] {
        sqlx::query("UPDATE builds SET workspace_generation=$2,workspace_receipt=$3 WHERE id=$1")
            .bind(admission.build_id)
            .bind(generation)
            .bind(receipt)
            .execute(store.pool())
            .await
            .unwrap();
        assert!(
            store
                .sequential_build_result(
                    plan.dag().organization_id,
                    plan.dag().project_id,
                    admission.build_id,
                    100
                )
                .await
                .is_err()
        );
    }
    sqlx::query("UPDATE builds SET workspace_generation=3,workspace_receipt=$2 WHERE id=$1")
        .bind(admission.build_id)
        .bind(original)
        .execute(store.pool())
        .await
        .unwrap();
    for query in [
        "UPDATE builds SET workspace_receipt=NULL WHERE id=$1",
        "UPDATE builds SET workspace_generation=0 WHERE id=$1",
    ] {
        assert_workspace_receipt_constraint(
            sqlx::query(query)
                .bind(admission.build_id)
                .execute(store.pool())
                .await
                .unwrap_err(),
        );
    }
    let original_terminal: Value =
        sqlx::query_scalar("SELECT terminal_summary FROM attempts WHERE id=$1")
            .bind(first.attempt_id)
            .fetch_one(store.pool())
            .await
            .unwrap();
    let mut wrong_namespace = original_terminal.clone();
    wrong_namespace["workspace_transfer"]["namespace_id"] = json!(Uuid::new_v4());
    sqlx::query("UPDATE attempts SET terminal_summary=$2 WHERE id=$1")
        .bind(first.attempt_id)
        .bind(wrong_namespace)
        .execute(store.pool())
        .await
        .unwrap();
    assert!(
        store
            .sequential_build_result(
                plan.dag().organization_id,
                plan.dag().project_id,
                admission.build_id,
                100
            )
            .await
            .is_err()
    );
    sqlx::query("UPDATE attempts SET terminal_summary=$2 WHERE id=$1")
        .bind(first.attempt_id)
        .bind(original_terminal)
        .execute(store.pool())
        .await
        .unwrap();

    let raw: Option<Value> =
        sqlx::query_scalar("SELECT workspace_snapshot FROM builds WHERE id = $1")
            .bind(admission.build_id)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert!(raw.is_none());
    for attempt in result
        .stages
        .iter()
        .flat_map(|stage| &stage.steps)
        .flat_map(|step| &step.attempts)
    {
        let receipt = &attempt.accounting.terminal_summary.as_ref().unwrap()["workspace_transfer"];
        assert!(receipt.get("snapshot").is_none());
        assert!(receipt.get("receipt").is_some());
    }
    assert!(matches!(
        store
            .schedule_retry(
                first.organization_id,
                first.attempt_id,
                2,
                "closed workspace"
            )
            .await
            .unwrap(),
        RetryDecision::Ineligible
    ));
    assert_eq!(
        store.admit_sequential_dag(&plan).await.unwrap().build_id,
        admission.build_id
    );
}

#[tokio::test]
async fn workspace_build_namespaces_cancellation_and_legacy_payload_refusal() {
    let Some((store, plain)) = fixture().await else {
        return;
    };
    let plan = plain.clone().with_workspace_transfer().unwrap();
    let first = store.admit_sequential_dag(&plan).await.unwrap();
    let mut different_dag = plain.dag().clone();
    different_dag.idempotency_key = "different-build".to_owned();
    let different = SequentialDagBuild::new(different_dag, plain.layout().to_vec())
        .unwrap()
        .with_workspace_transfer()
        .unwrap();
    let second = store.admit_sequential_dag(&different).await.unwrap();
    let first_namespace: Uuid =
        sqlx::query_scalar("SELECT workspace_namespace FROM builds WHERE id = $1")
            .bind(first.build_id)
            .fetch_one(store.pool())
            .await
            .unwrap();
    let second_namespace: Uuid =
        sqlx::query_scalar("SELECT workspace_namespace FROM builds WHERE id = $1")
            .bind(second.build_id)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_ne!(first_namespace, second_namespace);
    for build in [first.build_id, second.build_id] {
        assert!(
            store
                .request_cancellation(plan.dag().organization_id, plan.dag().project_id, build)
                .await
                .unwrap()
        );
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
        assert_eq!(result.status, "aborted");
        assert!(result.workspace_closed);
        assert!(result.workspace_receipt.is_none());
    }
    let mut legacy_dag = plain.dag().clone();
    legacy_dag.idempotency_key = "legacy".to_owned();
    let legacy = SequentialDagBuild::new(legacy_dag, plain.layout().to_vec()).unwrap();
    store.admit_sequential_dag(&legacy).await.unwrap();
    let running = running(&store, &legacy).await;
    let snapshot = WorkspaceSnapshot {
        version: 1,
        entries: vec![],
    };
    let forged = WorkspaceGrant {
        version: 1,
        organization_id: running.organization_id.to_string(),
        build_id: running.build_id.to_string(),
        namespace_id: Uuid::new_v4().to_string(),
        generation: 0,
        digest: snapshot.digest().unwrap(),
        snapshot: snapshot.clone(),
    };
    assert!(
        finish(&store, &running, summary(&forged, snapshot))
            .await
            .is_err()
    );
    assert!(
        finish(&store, &running, json!({"legacy":true}))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn workspace_failure_and_cancelled_publication_keep_receipts_without_reopening() {
    for cancelled in [false, true] {
        let Some((store, plain)) = fixture().await else {
            return;
        };
        let plan = plain.with_workspace_transfer().unwrap();
        let admission = store.admit_sequential_dag(&plan).await.unwrap();
        let current = running(&store, &plan).await;
        let seed = grant(&store, &current).await;
        let snapshot = WorkspaceSnapshot {
            version: 1,
            entries: vec![WorkspaceEntry::File {
                path: "before-failure.txt".to_owned(),
                executable: false,
                contents: b"observed before cleanup".to_vec(),
            }],
        };
        let original = summary(&seed, snapshot);
        if cancelled {
            assert!(
                store
                    .request_cancellation(
                        current.organization_id,
                        plan.dag().project_id,
                        admission.build_id
                    )
                    .await
                    .unwrap()
            );
        }
        let expected = if cancelled {
            TerminalOutcome::Aborted
        } else {
            TerminalOutcome::Failed
        };
        for _ in 0..2 {
            let result = store
                .finalize_attempt_cancellation_aware(
                    current.organization_id,
                    current.attempt_id,
                    current.fence,
                    current.restore_epoch,
                    &current.agent_id,
                    TerminalOutcome::Failed,
                    original.clone(),
                )
                .await
                .unwrap();
            assert_eq!(result, Some(expected));
        }
        let result = store
            .sequential_build_result(
                current.organization_id,
                plan.dag().project_id,
                admission.build_id,
                100,
            )
            .await
            .unwrap()
            .unwrap();
        assert!(result.workspace_closed);
        assert_eq!(result.workspace_generation, 1);
        assert!(result.workspace_receipt.is_some());
        let encoded = serde_json::to_string(&result).unwrap();
        assert!(!encoded.contains("\"contents\""));
        assert!(store.claim_next(&claim(&plan)).await.unwrap().is_none());
        assert!(matches!(
            store
                .schedule_retry(
                    current.organization_id,
                    current.attempt_id,
                    2,
                    "workspace already closed"
                )
                .await
                .unwrap(),
            RetryDecision::Ineligible
        ));
    }
}

#[tokio::test]
async fn workspace_reconciliation_cannot_publish_success_or_transfer_and_closes_without_advancing()
{
    for (outcome, expected_status) in [
        (TerminalOutcome::Failed, "failed"),
        (TerminalOutcome::Aborted, "aborted"),
    ] {
        let Some((store, plain)) = fixture().await else {
            return;
        };
        let plan = plain.with_workspace_transfer().unwrap();
        let admission = store.admit_sequential_dag(&plan).await.unwrap();
        let first = running(&store, &plan).await;
        let seed = grant(&store, &first).await;
        let snapshot = WorkspaceSnapshot {
            version: 1,
            entries: vec![WorkspaceEntry::File {
                path: "verified.txt".to_owned(),
                executable: false,
                contents: b"last verified checkpoint".to_vec(),
            }],
        };
        assert!(
            finish(&store, &first, summary(&seed, snapshot))
                .await
                .unwrap()
        );
        let current = running(&store, &plan).await;
        let input = grant(&store, &current).await;
        sqlx::query(
            "UPDATE attempts SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1",
        )
        .bind(current.attempt_id)
        .execute(store.pool())
        .await
        .unwrap();
        assert!(
            store
                .requeue_one_expired(current.organization_id)
                .await
                .unwrap()
        );
        let before = store
            .sequential_build_result(
                current.organization_id,
                plan.dag().project_id,
                admission.build_id,
                100,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(before.status, "reconciliation_required");
        assert_eq!(before.workspace_generation, 1);
        assert!(!before.workspace_closed);
        let transfer = summary(&input, input.snapshot.clone());
        for (requested, value) in [
            (TerminalOutcome::Succeeded, json!({"operator": "resolved"})),
            (TerminalOutcome::Succeeded, transfer.clone()),
            (outcome, transfer.clone()),
            (outcome, json!({"requested_summary": transfer})),
        ] {
            assert!(
                !store
                    .finalize_reconciled_attempt(
                        current.organization_id,
                        current.attempt_id,
                        current.fence,
                        "workspace-test-operator",
                        requested,
                        value,
                    )
                    .await
                    .unwrap()
            );
            assert!(store.claim_next(&claim(&plan)).await.unwrap().is_none());
            assert_eq!(
                store
                    .sequential_build_result(
                        current.organization_id,
                        plan.dag().project_id,
                        admission.build_id,
                        100,
                    )
                    .await
                    .unwrap()
                    .unwrap(),
                before
            );
        }
        let terminal = json!({"reason": "uncertain workspace discarded by operator"});
        for _ in 0..2 {
            assert!(
                store
                    .finalize_reconciled_attempt(
                        current.organization_id,
                        current.attempt_id,
                        current.fence,
                        "workspace-test-operator",
                        outcome,
                        terminal.clone(),
                    )
                    .await
                    .unwrap()
            );
            let result = store
                .sequential_build_result(
                    current.organization_id,
                    plan.dag().project_id,
                    admission.build_id,
                    100,
                )
                .await
                .unwrap()
                .unwrap();
            assert_eq!(result.status, expected_status);
            assert!(result.workspace_closed);
            assert_eq!(result.workspace_generation, before.workspace_generation);
            assert_eq!(result.workspace_receipt, before.workspace_receipt);
            assert!(store.claim_next(&claim(&plan)).await.unwrap().is_none());
            let raw: Option<Value> =
                sqlx::query_scalar("SELECT workspace_snapshot FROM builds WHERE id=$1")
                    .bind(admission.build_id)
                    .fetch_one(store.pool())
                    .await
                    .unwrap();
            assert!(raw.is_none());
            let events: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM build_events WHERE build_id=$1 AND kind='attempt.reconciliation_terminal'",
            )
            .bind(admission.build_id)
            .fetch_one(store.pool())
            .await
            .unwrap();
            assert_eq!(events, 1);
        }
    }
}
