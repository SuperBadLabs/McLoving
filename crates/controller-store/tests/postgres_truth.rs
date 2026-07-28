use std::sync::Arc;

use mcloving_controller_store::{NewBuild, Store, TerminalOutcome};
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
