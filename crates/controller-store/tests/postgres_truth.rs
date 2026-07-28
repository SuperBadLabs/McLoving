use std::sync::Arc;

use mcloving_controller_store::{ClaimRequest, NewBuild, Store, TerminalOutcome, WaitReason};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
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
        priority: 10,
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
            priority: 0,
        })
        .await
        .expect("admit build");
    let store = Arc::new(store);

    let contenders = (0..16).map(|index| {
        let store = Arc::clone(&store);
        tokio::spawn(async move {
            store
                .finalize_attempt(
                    organization_id,
                    admission.attempt_id,
                    0,
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
            priority: 100,
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
            priority: 10,
        })
        .await
        .expect("admit Linux work");

    let claim = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "scheduler-a".into(),
            agent_id: "linux-agent".into(),
            capabilities: vec!["linux".into(), "podman".into()],
            lease_seconds: 30,
            fairness_seed: 17,
        })
        .await
        .expect("claim compatible work")
        .expect("one compatible claim");
    assert_eq!(claim.node_id, linux.node_id);
    assert_eq!(claim.fence, 1);

    let reason = store
        .explain_wait(organization_id, &["linux".into()])
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
async fn expired_offer_is_reclaimed_with_a_new_fence() {
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
            priority: 0,
        })
        .await
        .expect("admit work");
    let first = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "scheduler-a".into(),
            agent_id: "agent-a".into(),
            capabilities: vec!["linux".into()],
            lease_seconds: 1,
            fairness_seed: 1,
        })
        .await
        .expect("first claim")
        .expect("claim exists");
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
            .expect("requeue expired")
    );
    let second = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "scheduler-b".into(),
            agent_id: "agent-b".into(),
            capabilities: vec!["linux".into()],
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
                TerminalOutcome::Succeeded,
                json!({"agent": "stale"}),
            )
            .await
            .expect("reject stale terminal publication")
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
                priority: 0,
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
