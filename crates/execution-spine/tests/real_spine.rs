use std::time::Duration;

use mcloving_controller_api::{ApiState, Client, ExplainResponse, router};
use mcloving_controller_store::{ClaimRequest, NewBuild, NewLogChunk, Store, TerminalOutcome};
use mcloving_execution_spine::{WorkerConfig, run_claim};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;
use uuid::Uuid;

const TOKEN: &str = "mcloving-e2e-token-exactly-32-bytes-or-more";
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
        axum::serve(
            listener,
            router(ApiState::new(store.clone(), TOKEN).expect("configure API")),
        )
        .into_future(),
    );
    let client = Client::new(&format!("http://{address}"), TOKEN);
    let admission = client
        .submit(organization_id, project_id, "e2e-001", PIPELINE.to_owned())
        .await
        .expect("submit strict YAML through HTTP");
    assert!(admission.created);
    let replay = client
        .submit(organization_id, project_id, "e2e-001", PIPELINE.to_owned())
        .await
        .expect("replay idempotent HTTP submission");
    assert!(!replay.created);
    assert_eq!(replay.build_id, admission.build_id);
    assert!(matches!(
        client
            .explain(organization_id, &["linux".to_owned()])
            .await
            .expect("explain ready work"),
        ExplainResponse::Ready
    ));

    let claim = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "scheduler-e2e".to_owned(),
            agent_id: "agent-e2e".to_owned(),
            capabilities: vec!["linux".to_owned()],
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
            termination_grace: Duration::from_millis(100),
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
    assert_eq!(logs[0].text, "hello-from-mcloving\n");
    assert_eq!(logs[1].text, "diagnostic\n");
    assert!(logs.iter().all(|log| log.sha256.len() == 64));

    let events = store
        .publish_outbox(organization_id, 100)
        .await
        .expect("publish transactional outbox");
    let topics = events
        .iter()
        .map(|event| event.topic.as_str())
        .collect::<Vec<_>>();
    assert!(topics.contains(&"build.admitted"));
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
        idempotency_key: "e2e-002".to_owned(),
        pipeline_digest: [42; 32],
        node_key: "execute".to_owned(),
        required_capabilities: vec!["linux".to_owned()],
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
    let admission = initial.admit_build(&input).await.expect("admit");
    drop(initial);
    let store = restart();
    let replay = store.admit_build(&input).await.expect("replay admission");
    assert!(!replay.created);
    assert_eq!(replay.build_id, admission.build_id);

    let claim = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "restart-scheduler".to_owned(),
            agent_id: "restart-agent".to_owned(),
            capabilities: vec!["linux".to_owned()],
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
        !store
            .finalize_attempt(
                organization_id,
                claim.attempt_id,
                claim.fence,
                "restart-agent",
                TerminalOutcome::Succeeded,
                json!({"sha256": hex(&Sha256::digest(log))}),
            )
            .await
            .expect("terminal replay is rejected without duplication")
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
