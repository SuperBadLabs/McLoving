use std::time::Duration;

use mcloving_agent_runtime::{Acceptance, AttemptPhase, Journal};
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
        axum::serve(
            listener,
            router(ApiState::new(store.clone(), TOKEN).expect("API state")),
        )
        .into_future(),
    );
    let client = Client::new(&format!("http://{address}"), TOKEN);
    let admission = client
        .submit(
            organization_id,
            project_id,
            "e2e-003",
            CANCELLATION_PIPELINE.to_owned(),
        )
        .await
        .expect("submit");
    let claim = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "scheduler-recovery".to_owned(),
            agent_id: "agent-recovery".to_owned(),
            capabilities: vec!["linux".to_owned()],
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
    let admission = store
        .admit_build(&NewBuild {
            organization_id,
            project_id,
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
        })
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
    let admission = store
        .admit_build(&NewBuild {
            organization_id,
            project_id,
            idempotency_key: idempotency_key.into(),
            pipeline_digest: Sha256::digest(idempotency_key).into(),
            node_key: "execute".into(),
            required_capabilities: vec!["linux".into()],
            required_trust_pool: "trusted".into(),
            priority: 0,
            execution_spec,
        })
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
