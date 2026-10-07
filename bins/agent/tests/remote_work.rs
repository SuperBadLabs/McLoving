use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::process::Stdio;
use std::time::Duration;

use mcloving_controller_api::{Client, PipelineBuildRequest, PipelineUpsertRequest};
use mcloving_controller_store::{
    BuildAdmission, NewBuild, NewCredentialGrant, NewEnvironmentApproval, PipelinePutOutcome,
    PipelineWrite, Store, StoreError,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::postgres::{PgListener, PgPoolOptions};
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use uuid::Uuid;

const TOKEN: &str = "mcloving-remote-agent-test-token";
const PIPELINE: &str = r#"
version: 1
name: remote-agent
stages:
  - id: execute
    name: Execute
    steps:
      - process:
          program: /bin/sh
          args: [-c, "printf 'remote-agent-ran\n'; printf 'remote-agent-stderr\n' >&2"]
          timeout_seconds: 10
"#;
const DRAIN_PIPELINE: &str = r#"
version: 1
name: drain-gate
stages:
  - id: s0
    name: S0
    steps:
      - process:
          program: /bin/sh
          args: [-c, "true"]
          timeout_seconds: 10
  - id: s1
    name: S1
    steps:
      - process:
          program: /bin/sh
          args: [-c, "true"]
          timeout_seconds: 10
  - id: s2
    name: S2
    steps:
      - process:
          program: /bin/sh
          args: [-c, "true"]
          timeout_seconds: 10
"#;

/// Both shipped-binary tests run this catalog update concurrently, and
/// PostgreSQL surfaces the race as `tuple concurrently updated`; retry until
/// one writer wins.
async fn enable_runtime_login(pool: &sqlx::PgPool) {
    for _ in 0..50 {
        if sqlx::query("ALTER ROLE mcloving_tenant LOGIN")
            .execute(pool)
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    sqlx::query("ALTER ROLE mcloving_tenant LOGIN")
        .execute(pool)
        .await
        .expect("enable test-only runtime login");
}

async fn admit_bound_test_build(
    store: &Store,
    mut input: NewBuild,
) -> Result<BuildAdmission, StoreError> {
    let current = store
        .pipeline(input.organization_id, input.project_id, input.pipeline_id)
        .await?;
    let source = format!("test pipeline {:?}", input.pipeline_digest);
    let outcome = store
        .put_pipeline(
            &PipelineWrite {
                organization_id: input.organization_id,
                project_id: input.project_id,
                pipeline_id: input.pipeline_id,
                slug: format!("test-{}", input.pipeline_id),
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
    let pipeline = match outcome {
        PipelinePutOutcome::Created(record)
        | PipelinePutOutcome::Updated(record)
        | PipelinePutOutcome::Unchanged(record) => record,
        PipelinePutOutcome::PreconditionFailed { current_revision } => {
            return Err(StoreError::ProductConflict(format!(
                "test pipeline raced at revision {current_revision}"
            )));
        }
    };
    input.pipeline_revision = pipeline.revision;
    input.pipeline_operational_generation = pipeline.operational_generation;
    store.admit_build(&input).await
}

const TRIVIAL_PIPELINE: &str = r#"
version: 1
name: remote-agent-transaction-receipt
stages:
  - id: execute
    name: Execute
    steps:
      - process:
          program: /bin/sh
          args: [-c, "true"]
          timeout_seconds: 10
"#;

#[tokio::test]
async fn shipped_agent_executes_fenced_work_over_mtls() {
    let Ok(migration_url) = std::env::var("MCLOVING_TEST_DATABASE_URL") else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let controller_binary = std::env::var_os("MCLOVING_CONTROLLER_BINARY")
        .map(PathBuf::from)
        .expect("MCLOVING_CONTROLLER_BINARY must name the shipped controller binary");
    let runtime_url =
        migration_url.replacen("postgres://mcloving@", "postgres://mcloving_tenant@", 1);
    assert_ne!(migration_url, runtime_url);

    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&migration_url)
        .await
        .expect("connect migration role");
    let store = Store::new(pool.clone());
    store.migrate().await.expect("install schema");
    enable_runtime_login(&pool).await;
    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    store
        .create_project(
            organization_id,
            &format!("remote-org-{organization_id}"),
            project_id,
            "remote-agent",
        )
        .await
        .expect("create test project");

    let directory = tempfile::tempdir().expect("test root");
    let tls = create_mtls(directory.path(), organization_id, "remote-test-agent");
    let api_port = free_port();
    let agent_port = free_port();
    let workspace = directory.path().join("workspace");
    std::fs::create_dir(&workspace).expect("create remote workspace root");

    let mut controller = Command::new(controller_binary)
        .env("MCLOVING_MIGRATION_DATABASE_URL", &migration_url)
        .env("MCLOVING_DATABASE_URL", &runtime_url)
        .env("MCLOVING_API_TOKEN", TOKEN)
        .env(
            "MCLOVING_ARTIFACT_AGENT_TOKEN",
            "remote-artifact-agent-token-32-bytes",
        )
        .env("MCLOVING_LISTEN", format!("127.0.0.1:{api_port}"))
        .env("MCLOVING_AGENT_LISTEN", format!("127.0.0.1:{agent_port}"))
        .env("MCLOVING_AGENT_SERVER_CERT_PATH", &tls.server_certificate)
        .env("MCLOVING_AGENT_SERVER_KEY_PATH", &tls.server_key)
        .env("MCLOVING_AGENT_CLIENT_CA_PATH", &tls.ca_certificate)
        .env("MCLOVING_AGENT_IDENTITY_BINDINGS_PATH", &tls.bindings)
        .env("MCLOVING_ORGANIZATION_ID", organization_id.to_string())
        .env("MCLOVING_AGENT_ID", "embedded-disabled")
        .env("MCLOVING_AGENT_CAPABILITIES", "disabled")
        .env("MCLOVING_AGENT_TRUST_POOL", "trusted-linux")
        .env("MCLOVING_LEASE_SECONDS", "5")
        .env("MCLOVING_POLL_MILLISECONDS", "10")
        .env("MCLOVING_CANCELLATION_POLL_MILLISECONDS", "50")
        .env("MCLOVING_TERMINATION_GRACE_MILLISECONDS", "100")
        .env("MCLOVING_TEST_DROP_START_RESPONSE_ONCE", "1")
        .env("MCLOVING_SESSION_EPOCH", "1")
        .env(
            "MCLOVING_WORKSPACE_ROOT",
            directory.path().join("embedded-workspace"),
        )
        .env(
            "MCLOVING_AGENT_JOURNAL",
            directory.path().join("embedded-agent.db"),
        )
        .env(
            "MCLOVING_OBJECT_ROOT",
            directory.path().join("embedded-objects"),
        )
        .kill_on_drop(true)
        .spawn()
        .expect("start shipped controller");
    let client = Client::new(&format!("http://127.0.0.1:{api_port}"), TOKEN);
    wait_until_listening(&client, organization_id).await;

    let journal = directory.path().join("remote-agent.db");
    let mut agent = agent_command(
        "remote-test-agent",
        organization_id,
        agent_port,
        &tls,
        &journal,
        &workspace,
    )
    .env("MCLOVING_TEST_CRASH_AFTER_TERMINAL_COMMIT", "1")
    .kill_on_drop(true)
    .spawn()
    .expect("start shipped remote agent");

    let pipeline_id = Uuid::new_v4();
    client
        .put_pipeline(
            organization_id,
            project_id,
            pipeline_id,
            0,
            &PipelineUpsertRequest {
                slug: "remote-agent-e2e".to_owned(),
                source: PIPELINE.to_owned(),
                parameters: Default::default(),
            },
        )
        .await
        .expect("save remote-agent pipeline");
    let admission = client
        .submit_pipeline_on_platform_in_pool(
            organization_id,
            project_id,
            pipeline_id,
            "remote-agent-e2e",
            "linux",
            "trusted-linux",
            &PipelineBuildRequest::default(),
        )
        .await
        .expect("submit work");
    let first_exit = tokio::time::timeout(Duration::from_secs(15), agent.wait())
        .await
        .expect("fault-injected agent exits within bound")
        .expect("wait for fault-injected agent");
    assert_eq!(first_exit.code(), Some(86));
    assert_eq!(
        mcloving_agent::journal_health(&journal)
            .expect("read crashed agent journal")
            .2,
        1,
        "controller committed terminal truth before the agent journal advanced"
    );

    let probe_status = tokio::time::timeout(
        Duration::from_secs(10),
        agent_command(
            "remote-test-agent",
            organization_id,
            agent_port,
            &tls,
            &journal,
            &workspace,
        )
        .arg("probe")
        .status(),
    )
    .await
    .expect("probe exits within bound")
    .expect("run shipped agent probe");
    assert!(probe_status.success(), "probe replays durable finalization");
    assert_eq!(
        mcloving_agent::journal_health(&journal)
            .expect("read probe-recovered agent journal")
            .2,
        0,
        "probe must not renew and strand a replayable finalization"
    );

    let mut agent = agent_command(
        "remote-test-agent",
        organization_id,
        agent_port,
        &tls,
        &journal,
        &workspace,
    )
    .kill_on_drop(true)
    .spawn()
    .expect("restart shipped remote agent");
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if mcloving_agent::journal_health(&journal)
                .expect("read recovering agent journal")
                .2
                == 0
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("finalizing journal converges after response-loss restart");
    let status = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let status = client
                .status(organization_id, project_id, admission.build_id)
                .await
                .expect("read build status");
            if matches!(status.status.as_str(), "succeeded" | "failed" | "aborted") {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("remote work completes within bound");
    assert_eq!(status.status, "succeeded");
    assert_eq!(status.attempt_status, "succeeded");
    assert_eq!(status.lease_owner.as_deref(), Some("remote-test-agent"));
    let logs = client
        .logs(organization_id, project_id, admission.build_id)
        .await
        .expect("read remote logs");
    assert_eq!(logs.len(), 2);
    assert_eq!(logs[0].stream, "stdout");
    assert_eq!(logs[0].text.as_deref(), Some("remote-agent-ran\n"));
    assert_eq!(logs[0].content_hex, "72656d6f74652d6167656e742d72616e0a");
    assert_eq!(logs[1].stream, "stderr");
    assert_eq!(logs[1].text.as_deref(), Some("remote-agent-stderr\n"));
    assert_eq!(
        logs[1].content_hex,
        "72656d6f74652d6167656e742d7374646572720a"
    );
    let terminal_events = sqlx::query_scalar::<_, i64>(
        "SELECT count(*)
         FROM build_events
         WHERE organization_id = $1
           AND build_id = $2
           AND kind = 'attempt.terminal'",
    )
    .bind(organization_id)
    .bind(admission.build_id)
    .fetch_one(&pool)
    .await
    .expect("count terminal events");
    assert_eq!(terminal_events, 1, "response-loss replay is idempotent");

    stop(&mut agent).await;

    store
        .configure_protected_environment(organization_id, project_id, "production", "deploy", 2)
        .await
        .expect("configure protected environment");
    let protected_digest = [0xc3; 32];
    let secret = ["mcloving", "e2e", "redaction", "probe"].join("-");
    let protected = admit_bound_test_build(
        &store,
        NewBuild {
            organization_id,
            project_id,
            pipeline_id: project_id,
            pipeline_revision: 1,
            pipeline_operational_generation: 1,
            idempotency_key: "remote-agent-protected-e2e".to_owned(),
            pipeline_digest: protected_digest,
            node_key: "protected-deploy".to_owned(),
            required_capabilities: vec!["linux".to_owned()],
            required_trust_pool: "trusted-linux".to_owned(),
            priority: 100,
            execution_spec: json!({
                "version": 1,
                "steps": [{
                    "kind": "process",
                    "program": "/bin/sh",
                    "args": [
                        "-c",
                        "printf 'stdout:%s\\n' \"$DEPLOY_TOKEN\"; printf 'stderr:%s\\n' \"$DEPLOY_TOKEN\" >&2"
                    ],
                    "credentials": ["DEPLOY_TOKEN"],
                    "timeout_seconds": 10
                }]
            }),
        },
    )
        .await
        .expect("admit protected remote work");
    let approval_ids = [Uuid::new_v4(), Uuid::new_v4()];
    for (id, subject) in approval_ids
        .into_iter()
        .zip(["oidc:release-owner", "oidc:security-owner"])
    {
        assert!(
            store
                .approve_environment(&NewEnvironmentApproval {
                    id,
                    organization_id,
                    project_id,
                    build_id: protected.build_id,
                    pipeline_digest: protected_digest,
                    environment: "production",
                    action: "deploy",
                    approver_subject: subject,
                    ttl_seconds: 300,
                })
                .await
                .expect("approve protected remote work")
        );
    }
    let mut agent = agent_command(
        "remote-test-agent",
        organization_id,
        agent_port,
        &tls,
        &journal,
        &workspace,
    )
    .kill_on_drop(true)
    .spawn()
    .expect("start protected remote agent");
    let accepted = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let snapshot = store
                .build_snapshot(organization_id, project_id, protected.build_id)
                .await
                .expect("read protected build")
                .expect("protected build exists");
            if snapshot.attempt_status == "accepted" {
                break snapshot;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    let accepted = match accepted {
        Ok(snapshot) => snapshot,
        Err(_) => {
            let snapshot = store
                .build_snapshot(organization_id, project_id, protected.build_id)
                .await
                .expect("read timed-out protected build");
            let process_status = agent.try_wait().expect("inspect protected agent");
            let wait_reason = store
                .explain_wait(organization_id, &[], "trusted-linux")
                .await
                .expect("explain protected scheduling wait");
            panic!(
                "protected attempt was not accepted: snapshot={snapshot:?} process={process_status:?} wait={wait_reason:?}"
            );
        }
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    let still_waiting = store
        .build_snapshot(organization_id, project_id, protected.build_id)
        .await
        .expect("read waiting protected build")
        .expect("protected build exists");
    assert_eq!(
        still_waiting.attempt_status, "accepted",
        "the process must not start before its exact grants are ready"
    );
    assert!(
        store
            .build_logs(organization_id, project_id, protected.build_id)
            .await
            .expect("read pre-grant logs")
            .is_empty()
    );
    assert!(
        store
            .issue_credential_grant(&NewCredentialGrant {
                id: Uuid::new_v4(),
                organization_id,
                project_id,
                build_id: protected.build_id,
                attempt_id: accepted.attempt_id,
                fence: accepted.fence,
                pipeline_digest: protected_digest,
                environment: "production",
                action: "deploy",
                target_name: "DEPLOY_TOKEN",
                secret_value: secret.as_bytes(),
                approval_ids: &approval_ids,
                ttl_seconds: 300,
            })
            .await
            .expect("issue protected remote grant")
    );
    let protected_status = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let snapshot = store
                .build_snapshot(organization_id, project_id, protected.build_id)
                .await
                .expect("read protected result")
                .expect("protected build exists");
            if matches!(
                snapshot.attempt_status.as_str(),
                "succeeded" | "failed" | "aborted"
            ) {
                break snapshot;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("protected remote work completes within bound");
    assert_eq!(protected_status.attempt_status, "succeeded");
    let protected_logs = store
        .build_logs(organization_id, project_id, protected.build_id)
        .await
        .expect("read protected logs");
    assert_eq!(protected_logs.len(), 2);
    for log in &protected_logs {
        let text = String::from_utf8_lossy(&log.content);
        assert!(
            !text.contains(&secret),
            "published log retained a credential"
        );
    }
    assert_eq!(protected_logs[0].content, b"stdout:\n");
    assert_eq!(protected_logs[1].content, b"stderr:\n");
    let credential_events = sqlx::query_scalar::<_, i64>(
        "SELECT count(*)
         FROM build_events
         WHERE organization_id = $1
           AND build_id = $2
           AND kind = 'credential.grants_delivered'",
    )
    .bind(organization_id)
    .bind(protected.build_id)
    .fetch_one(&pool)
    .await
    .expect("count credential delivery events");
    assert_eq!(credential_events, 1);

    let mut progress = PgListener::connect_with(&pool)
        .await
        .expect("connect remote transaction receipt listener");
    progress
        .listen("mcloving_work_ready_v1")
        .await
        .expect("listen for remote transaction receipt progress");
    let trivial_pipeline_id = Uuid::new_v4();
    client
        .put_pipeline(
            organization_id,
            project_id,
            trivial_pipeline_id,
            0,
            &PipelineUpsertRequest {
                slug: "remote-agent-transaction-receipt".to_owned(),
                source: TRIVIAL_PIPELINE.to_owned(),
                parameters: Default::default(),
            },
        )
        .await
        .expect("save trivial remote pipeline");
    // Saved-pipeline setup is not part of the attempt lifecycle budget. Start
    // the receipt after setup so the counter measures admission through
    // terminal publication, including every remote-agent round trip.
    let before_transactions = client
        .performance(organization_id)
        .await
        .expect("read initial remote transaction counter")
        .tenant_transactions_started;
    let trivial = client
        .submit_pipeline_on_platform_in_pool(
            organization_id,
            project_id,
            trivial_pipeline_id,
            "remote-agent-transaction-receipt",
            "linux",
            "trusted-linux",
            &PipelineBuildRequest::default(),
        )
        .await
        .expect("submit trivial remote work");
    // A work-ready notification is a wakeup, not a lifecycle event. Admission,
    // claim, lease release, and terminal publication can all wake this tenant,
    // and concurrent work may add more. Counting two notifications mistook a
    // delivery detail for terminal truth and raced with the terminal commit.
    // Re-read PostgreSQL after every matching wakeup and stop only on durable
    // terminal truth; this remains event-driven and adds no status polling.
    let trivial_status = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let notification = progress.recv().await.expect("receive remote progress");
            if notification.payload() != organization_id.to_string() {
                continue;
            }
            let status = sqlx::query_scalar::<_, String>(
                "SELECT status FROM builds WHERE organization_id = $1 AND id = $2",
            )
            .bind(organization_id)
            .bind(trivial.build_id)
            .fetch_one(&pool)
            .await
            .expect("read trivial remote progress status");
            if matches!(status.as_str(), "succeeded" | "failed" | "aborted") {
                break status;
            }
        }
    })
    .await
    .expect("trivial remote work reaches durable terminal truth without status polling");
    assert_eq!(trivial_status, "succeeded");
    assert!(
        store
            .build_logs(organization_id, project_id, trivial.build_id)
            .await
            .expect("read trivial remote logs")
            .is_empty(),
        "empty streams must not cause controller log transactions"
    );
    let after_transactions = client
        .performance(organization_id)
        .await
        .expect("read final remote transaction counter")
        .tenant_transactions_started;
    let transaction_delta = after_transactions.saturating_sub(before_transactions);
    eprintln!("trivial_remote_tenant_transactions={transaction_delta}");
    // The agent immediately arms its next server-side wait after terminal
    // acknowledgement. A fully armed empty wait has three authoritative
    // boundaries: claim, expired-lease reconciliation, and next-expiry
    // calculation. Depending on how far that arm advances before this
    // observation, the process-wide delta is 22 through 25. The required
    // pre-claim expired-lease reconciliation accounts for the additional
    // lifecycle boundary. The pre-armed
    // PostgreSQL listener makes the settled 25-boundary case deterministic
    // enough to exercise; it does not add a tenant transaction itself.
    assert!(
        transaction_delta <= 25,
        "trivial remote work regressed above the transaction budget: {transaction_delta}"
    );
    stop(&mut agent).await;
    assert!(
        !directory_contains(directory.path(), secret.as_bytes()),
        "credential escaped into the agent workspace, journal, or result files"
    );
    stop(&mut controller).await;
}

/// EXEC-001 regression gate for the shipped remote agent: an execution spec
/// injected behind validate (100 process steps in one node) must be finalized
/// as a named terminal failure within one lease term of being claimed. The
/// measured defect kept exactly this shape `running` through 1,460+ build
/// events while the agent retried a permanent refusal forever.
#[tokio::test]
async fn unsupported_execution_spec_is_finalized_failed_within_one_lease_term() {
    let Ok(migration_url) = std::env::var("MCLOVING_TEST_DATABASE_URL") else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let agent_id = "exec001-unsupported-agent";
    let controller_binary = std::env::var_os("MCLOVING_CONTROLLER_BINARY")
        .map(PathBuf::from)
        .expect("MCLOVING_CONTROLLER_BINARY must name the shipped controller binary");
    let runtime_url =
        migration_url.replacen("postgres://mcloving@", "postgres://mcloving_tenant@", 1);
    assert_ne!(migration_url, runtime_url);
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&migration_url)
        .await
        .expect("connect migration role");
    let store = Store::new(pool.clone());
    store.migrate().await.expect("install schema");
    enable_runtime_login(&pool).await;
    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    store
        .create_project(
            organization_id,
            &format!("exec001-org-{organization_id}"),
            project_id,
            "unsupported-spec",
        )
        .await
        .expect("create test project");

    let directory = tempfile::tempdir().expect("test root");
    let tls = create_mtls(directory.path(), organization_id, agent_id);
    let api_port = free_port();
    let agent_port = free_port();
    let workspace = directory.path().join("workspace");
    std::fs::create_dir(&workspace).expect("create remote workspace root");
    let mut controller = Command::new(controller_binary)
        .env("MCLOVING_MIGRATION_DATABASE_URL", &migration_url)
        .env("MCLOVING_DATABASE_URL", &runtime_url)
        .env("MCLOVING_API_TOKEN", TOKEN)
        .env(
            "MCLOVING_ARTIFACT_AGENT_TOKEN",
            "remote-artifact-agent-token-32-bytes",
        )
        .env("MCLOVING_LISTEN", format!("127.0.0.1:{api_port}"))
        .env("MCLOVING_AGENT_LISTEN", format!("127.0.0.1:{agent_port}"))
        .env("MCLOVING_AGENT_SERVER_CERT_PATH", &tls.server_certificate)
        .env("MCLOVING_AGENT_SERVER_KEY_PATH", &tls.server_key)
        .env("MCLOVING_AGENT_CLIENT_CA_PATH", &tls.ca_certificate)
        .env("MCLOVING_AGENT_IDENTITY_BINDINGS_PATH", &tls.bindings)
        .env("MCLOVING_ORGANIZATION_ID", organization_id.to_string())
        .env("MCLOVING_AGENT_ID", "exec001-embedded-disabled")
        .env("MCLOVING_AGENT_CAPABILITIES", "disabled")
        .env("MCLOVING_AGENT_TRUST_POOL", "trusted-linux")
        .env("MCLOVING_LEASE_SECONDS", "5")
        .env("MCLOVING_POLL_MILLISECONDS", "10")
        .env("MCLOVING_CANCELLATION_POLL_MILLISECONDS", "50")
        .env("MCLOVING_TERMINATION_GRACE_MILLISECONDS", "100")
        .env("MCLOVING_SESSION_EPOCH", "1")
        .env(
            "MCLOVING_WORKSPACE_ROOT",
            directory.path().join("embedded-workspace"),
        )
        .env(
            "MCLOVING_AGENT_JOURNAL",
            directory.path().join("embedded-agent.db"),
        )
        .env(
            "MCLOVING_OBJECT_ROOT",
            directory.path().join("embedded-objects"),
        )
        .kill_on_drop(true)
        .spawn()
        .expect("start shipped controller");
    let client = Client::new(&format!("http://127.0.0.1:{api_port}"), TOKEN);
    wait_until_listening(&client, organization_id).await;

    let steps = (0..100)
        .map(|index| {
            json!({
                "kind": "process",
                "program": "/bin/sh",
                "args": ["-c", format!("echo step-{index}")],
                "timeout_seconds": 10
            })
        })
        .collect::<Vec<_>>();
    let admission = admit_bound_test_build(
        &store,
        NewBuild {
            organization_id,
            project_id,
            pipeline_id: project_id,
            pipeline_revision: 1,
            pipeline_operational_generation: 1,
            idempotency_key: "exec001-unsupported-spec".to_owned(),
            pipeline_digest: [0xe1; 32],
            node_key: "hundred-steps".to_owned(),
            required_capabilities: vec!["linux".to_owned()],
            required_trust_pool: "trusted-linux".to_owned(),
            priority: 0,
            execution_spec: json!({"version": 1, "steps": steps}),
        },
    )
    .await
    .expect("admit the unrunnable build behind validate");

    let journal = directory.path().join("exec001-agent.db");
    let mut agent = agent_command(
        agent_id,
        organization_id,
        agent_port,
        &tls,
        &journal,
        &workspace,
    )
    .kill_on_drop(true)
    .spawn()
    .expect("start shipped remote agent");

    let lease_term = Duration::from_secs(5);
    let mut claim_observed_at = None;
    let snapshot = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let snapshot = store
                .build_snapshot(organization_id, project_id, admission.build_id)
                .await
                .expect("read build snapshot")
                .expect("build exists");
            if matches!(
                snapshot.attempt_status.as_str(),
                "succeeded" | "failed" | "aborted"
            ) {
                break snapshot;
            }
            if snapshot.attempt_status != "queued" {
                let observed_at = *claim_observed_at.get_or_insert_with(std::time::Instant::now);
                assert!(
                    observed_at.elapsed() < lease_term,
                    "claimed refusal must reach a terminal state within one lease term, still {}",
                    snapshot.attempt_status
                );
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the unsupported build reaches a terminal state instead of running forever");
    assert_eq!(snapshot.build_status, "failed");
    assert_eq!(snapshot.attempt_status, "failed");
    let reason = snapshot
        .terminal_summary
        .and_then(|summary| summary["reason"].as_str().map(str::to_owned))
        .expect("terminal summary names the refusal");
    assert_eq!(
        reason,
        "unsupported_execution_spec: execution spec declares 100 steps (expected exactly 1 process step)"
    );
    let terminal_events = sqlx::query_scalar::<_, i64>(
        "SELECT count(*)
         FROM build_events
         WHERE organization_id = $1
           AND build_id = $2
           AND kind = 'attempt.terminal'",
    )
    .bind(organization_id)
    .bind(admission.build_id)
    .fetch_one(&pool)
    .await
    .expect("count terminal events");
    assert_eq!(terminal_events, 1, "the refusal is finalized exactly once");
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if mcloving_agent::journal_health(&journal)
                .expect("read agent journal")
                .2
                == 0
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the refused attempt retires from the agent journal");
    assert!(
        agent.try_wait().expect("inspect agent").is_none(),
        "the agent session must survive a refused assignment"
    );
    stop(&mut agent).await;
    stop(&mut controller).await;
}

/// Regression gate for the work-loop drain: the agent's poll interval paces
/// how often an idle session asks for work, and must not pace how fast queued
/// work is done. Every other agent test runs at a 10 ms poll, where a ~240 ms
/// stage body absorbs the tick and the defect is invisible; this one pins the
/// interval at 8 s so a single waited tick between stages breaks the bound.
/// The measured defect drained one stage per interval — ~496 ms/stage at the
/// shipped 500 ms default — because `poll_and_run_one` could not tell the
/// session loop that its pass had just executed an assignment.
#[tokio::test]
async fn queued_stages_drain_without_waiting_out_the_poll_interval() {
    let Ok(migration_url) = std::env::var("MCLOVING_TEST_DATABASE_URL") else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let agent_id = "drain-gate-agent";
    let controller_binary = std::env::var_os("MCLOVING_CONTROLLER_BINARY")
        .map(PathBuf::from)
        .expect("MCLOVING_CONTROLLER_BINARY must name the shipped controller binary");
    let runtime_url =
        migration_url.replacen("postgres://mcloving@", "postgres://mcloving_tenant@", 1);
    assert_ne!(migration_url, runtime_url);
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&migration_url)
        .await
        .expect("connect migration role");
    let store = Store::new(pool.clone());
    store.migrate().await.expect("install schema");
    enable_runtime_login(&pool).await;
    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    store
        .create_project(
            organization_id,
            &format!("drain-org-{organization_id}"),
            project_id,
            "drain-gate",
        )
        .await
        .expect("create test project");

    let directory = tempfile::tempdir().expect("test root");
    let tls = create_mtls(directory.path(), organization_id, agent_id);
    let api_port = free_port();
    let agent_port = free_port();
    let workspace = directory.path().join("workspace");
    std::fs::create_dir(&workspace).expect("create remote workspace root");
    let mut controller = Command::new(controller_binary)
        .env("MCLOVING_MIGRATION_DATABASE_URL", &migration_url)
        .env("MCLOVING_DATABASE_URL", &runtime_url)
        .env("MCLOVING_API_TOKEN", TOKEN)
        .env(
            "MCLOVING_ARTIFACT_AGENT_TOKEN",
            "remote-artifact-agent-token-32-bytes",
        )
        .env("MCLOVING_LISTEN", format!("127.0.0.1:{api_port}"))
        .env("MCLOVING_AGENT_LISTEN", format!("127.0.0.1:{agent_port}"))
        .env("MCLOVING_AGENT_SERVER_CERT_PATH", &tls.server_certificate)
        .env("MCLOVING_AGENT_SERVER_KEY_PATH", &tls.server_key)
        .env("MCLOVING_AGENT_CLIENT_CA_PATH", &tls.ca_certificate)
        .env("MCLOVING_AGENT_IDENTITY_BINDINGS_PATH", &tls.bindings)
        .env("MCLOVING_ORGANIZATION_ID", organization_id.to_string())
        // Refusing every PublishLog proves this build's log streams ride
        // WorkCompletion.inline_log_chunks (inline-terminal-logs-v1): any
        // silent fallback to the serialized round trips fails the build.
        .env("MCLOVING_TEST_REFUSE_PUBLISH_LOG", "1")
        .env("MCLOVING_AGENT_ID", "drain-embedded-disabled")
        .env("MCLOVING_AGENT_CAPABILITIES", "disabled")
        .env("MCLOVING_AGENT_TRUST_POOL", "trusted-linux")
        .env("MCLOVING_LEASE_SECONDS", "5")
        .env("MCLOVING_POLL_MILLISECONDS", "10")
        .env("MCLOVING_CANCELLATION_POLL_MILLISECONDS", "50")
        .env("MCLOVING_TERMINATION_GRACE_MILLISECONDS", "100")
        .env("MCLOVING_SESSION_EPOCH", "1")
        .env(
            "MCLOVING_WORKSPACE_ROOT",
            directory.path().join("embedded-workspace"),
        )
        .env(
            "MCLOVING_AGENT_JOURNAL",
            directory.path().join("embedded-agent.db"),
        )
        .env(
            "MCLOVING_OBJECT_ROOT",
            directory.path().join("embedded-objects"),
        )
        .kill_on_drop(true)
        .spawn()
        .expect("start shipped controller");
    let client = Client::new(&format!("http://127.0.0.1:{api_port}"), TOKEN);
    wait_until_listening(&client, organization_id).await;

    let pipeline_id = Uuid::new_v4();
    client
        .put_pipeline(
            organization_id,
            project_id,
            pipeline_id,
            0,
            &PipelineUpsertRequest {
                slug: "drain-gate-e2e".to_owned(),
                source: DRAIN_PIPELINE.to_owned(),
                parameters: Default::default(),
            },
        )
        .await
        .expect("save drain-gate pipeline");
    let admission = client
        .submit_pipeline_on_platform_in_pool(
            organization_id,
            project_id,
            pipeline_id,
            "drain-gate-e2e",
            "linux",
            "trusted-linux",
            &PipelineBuildRequest::default(),
        )
        .await
        .expect("submit work");

    let journal = directory.path().join("drain-agent.db");
    let mut agent = agent_command(
        agent_id,
        organization_id,
        agent_port,
        &tls,
        &journal,
        &workspace,
    )
    .env("MCLOVING_AGENT_POLL_MILLISECONDS", "8000")
    .kill_on_drop(true)
    .spawn()
    .expect("start shipped remote agent");

    // The deliberately huge legacy client poll interval must not pace either
    // initial notice or queue draining. Start the stage-to-stage clock at the
    // first observed activity; the pre-fix loop needed one interval per
    // remaining stage.
    let activity = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let status = client
                .status(organization_id, project_id, admission.build_id)
                .await
                .expect("read build status");
            if status.status != "queued" {
                break std::time::Instant::now();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the queued build is noticed within bound");
    let status = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let status = client
                .status(organization_id, project_id, admission.build_id)
                .await
                .expect("read build status");
            if matches!(status.status.as_str(), "succeeded" | "failed" | "aborted") {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("three queued stages complete without draining one per interval");
    if status.status != "succeeded" {
        let events: Vec<(String, serde_json::Value)> = sqlx::query_as(
            "SELECT kind, payload
             FROM build_events
             WHERE organization_id = $1 AND build_id = $2
             ORDER BY id ASC",
        )
        .bind(organization_id)
        .bind(admission.build_id)
        .fetch_all(&pool)
        .await
        .unwrap_or_default();
        let nodes: Vec<(String, Option<String>, String)> = sqlx::query_as(
            "SELECT node_key, logical_outcome, status FROM nodes
             WHERE organization_id = $1 AND build_id = $2
             ORDER BY queued_at ASC NULLS LAST, id ASC",
        )
        .bind(organization_id)
        .bind(admission.build_id)
        .fetch_all(&pool)
        .await
        .unwrap_or_default();
        let attempts: Vec<(String, String, Option<serde_json::Value>)> = sqlx::query_as(
            "SELECT n.node_key, a.status, a.terminal_summary
             FROM attempts AS a
             JOIN nodes AS n
               ON n.organization_id = a.organization_id AND n.id = a.node_id
             WHERE a.organization_id = $1 AND n.build_id = $2
             ORDER BY a.created_at ASC NULLS LAST, a.id ASC",
        )
        .bind(organization_id)
        .bind(admission.build_id)
        .fetch_all(&pool)
        .await
        .unwrap_or_default();
        panic!(
            "drain-gate expected succeeded, got {}; nodes={nodes:?}; attempts={attempts:?}; events={events:?}",
            status.status
        );
    }
    let drained_in = activity.elapsed();
    assert!(
        drained_in < Duration::from_millis(7500),
        "queued stages drained at the poll interval instead of at work speed: \
         three stages took {drained_in:?} against an 8 s interval"
    );
    // Empty streams are no evidence at all: neither the refused PublishLog RPC
    // nor the negotiated inline completion path may create log rows.
    let log_chunks = sqlx::query_scalar::<_, i64>(
        "SELECT count(*)
         FROM attempt_log_chunks AS l
         JOIN attempts AS a
           ON a.organization_id = l.organization_id AND a.id = l.attempt_id
         JOIN nodes AS n
           ON n.organization_id = a.organization_id AND n.id = a.node_id
         WHERE l.organization_id = $1
           AND n.build_id = $2",
    )
    .bind(organization_id)
    .bind(admission.build_id)
    .fetch_one(&pool)
    .await
    .expect("count published log chunks");
    assert_eq!(
        log_chunks, 0,
        "empty stage streams must not create log rows"
    );
    stop(&mut agent).await;
    stop(&mut controller).await;
}

fn directory_contains(root: &Path, needle: &[u8]) -> bool {
    let entries = std::fs::read_dir(root).expect("read test directory");
    for entry in entries {
        let path = entry.expect("read test entry").path();
        if path.is_dir() {
            if directory_contains(&path, needle) {
                return true;
            }
        } else if std::fs::read(&path)
            .is_ok_and(|content| content.windows(needle.len()).any(|window| window == needle))
        {
            return true;
        }
    }
    false
}

fn agent_command(
    agent_id: &str,
    organization_id: Uuid,
    agent_port: u16,
    tls: &MtlsFiles,
    journal: &Path,
    workspace: &Path,
) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mcloving-agent"));
    command
        // The harness needs migration authority; the shipped agent must not
        // inherit direct database authority that it never has in production.
        .env_remove("MCLOVING_TEST_DATABASE_URL")
        .env("MCLOVING_AGENT_ID", agent_id)
        .env("MCLOVING_AGENT_TRUST_POOL", "trusted-linux")
        .env(
            "MCLOVING_AGENT_ORGANIZATION_ID",
            organization_id.to_string(),
        )
        .env(
            "MCLOVING_CONTROLLER_URI",
            format!("https://127.0.0.1:{agent_port}"),
        )
        .env("MCLOVING_CONTROLLER_DNS_NAME", "controller.internal")
        .env("MCLOVING_CONTROLLER_CA_PATH", &tls.ca_certificate)
        .env("MCLOVING_AGENT_CERTIFICATE_PATH", &tls.agent_certificate)
        .env("MCLOVING_AGENT_PRIVATE_KEY_PATH", &tls.agent_key)
        .env("MCLOVING_AGENT_JOURNAL_PATH", journal)
        .env("MCLOVING_AGENT_WORKSPACE_ROOT", workspace)
        .env("MCLOVING_AGENT_LEASE_SECONDS", "5")
        .env("MCLOVING_AGENT_POLL_MILLISECONDS", "10")
        .env("MCLOVING_AGENT_RENEW_MILLISECONDS", "100")
        .env("MCLOVING_AGENT_TERMINATION_GRACE_MILLISECONDS", "100");
    command
}

async fn wait_until_listening(client: &Client, organization_id: Uuid) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if client.explain(organization_id, &[]).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("controller listens within bound");
}

async fn stop(child: &mut Child) {
    child.kill().await.expect("stop child");
    child.wait().await.expect("reap child");
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("reserve port")
        .local_addr()
        .expect("read port")
        .port()
}

struct MtlsFiles {
    ca_certificate: PathBuf,
    server_certificate: PathBuf,
    server_key: PathBuf,
    agent_certificate: PathBuf,
    agent_key: PathBuf,
    bindings: PathBuf,
}

fn create_mtls(root: &Path, organization_id: Uuid, agent_id: &str) -> MtlsFiles {
    let ca_certificate = root.join("ca.pem");
    let ca_key = root.join("ca-key.pem");
    openssl([
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-x509",
        "-days",
        "1",
        "-subj",
        "/CN=mcloving-test-ca",
        "-keyout",
        path(&ca_key),
        "-out",
        path(&ca_certificate),
    ]);
    let server_key = root.join("server-key.pem");
    let server_csr = root.join("server.csr");
    let server_certificate = root.join("server.pem");
    let server_extensions = root.join("server.ext");
    std::fs::write(
        &server_extensions,
        "subjectAltName=DNS:controller.internal,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n",
    )
    .expect("write server extensions");
    openssl([
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-subj",
        "/CN=controller.internal",
        "-keyout",
        path(&server_key),
        "-out",
        path(&server_csr),
    ]);
    sign(
        &server_csr,
        &server_certificate,
        &server_extensions,
        &ca_certificate,
        &ca_key,
    );

    let agent_key = root.join("agent-key.pem");
    let agent_csr = root.join("agent.csr");
    let agent_certificate = root.join("agent.pem");
    let agent_extensions = root.join("agent.ext");
    std::fs::write(&agent_extensions, "extendedKeyUsage=clientAuth\n")
        .expect("write agent extensions");
    openssl([
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-subj",
        &format!("/CN={agent_id}"),
        "-keyout",
        path(&agent_key),
        "-out",
        path(&agent_csr),
    ]);
    sign(
        &agent_csr,
        &agent_certificate,
        &agent_extensions,
        &ca_certificate,
        &ca_key,
    );
    let agent_der = root.join("agent.der");
    openssl([
        "x509",
        "-in",
        path(&agent_certificate),
        "-outform",
        "DER",
        "-out",
        path(&agent_der),
    ]);
    let digest: [u8; 32] = Sha256::digest(std::fs::read(agent_der).expect("read agent DER")).into();
    let bindings = root.join("identity-bindings.txt");
    std::fs::write(
        &bindings,
        format!(
            "{} {agent_id} trusted-linux {organization_id}\n",
            hex(&digest)
        ),
    )
    .expect("write identity binding");
    MtlsFiles {
        ca_certificate,
        server_certificate,
        server_key,
        agent_certificate,
        agent_key,
        bindings,
    }
}

fn sign(csr: &Path, certificate: &Path, extensions: &Path, ca_certificate: &Path, ca_key: &Path) {
    openssl([
        "x509",
        "-req",
        "-days",
        "1",
        "-in",
        path(csr),
        "-CA",
        path(ca_certificate),
        "-CAkey",
        path(ca_key),
        "-CAcreateserial",
        "-extfile",
        path(extensions),
        "-out",
        path(certificate),
    ]);
}

fn openssl<const N: usize>(arguments: [&str; N]) {
    let status = StdCommand::new("openssl")
        .args(arguments)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run openssl");
    assert!(status.success(), "openssl command failed");
}

fn path(value: &Path) -> &str {
    value.to_str().expect("test path is UTF-8")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// PAR-010: several process steps in one stage run as one attempt, in order,
/// under one lease, with each step's output kept apart by step ordinal, and
/// execution stops at the first step that does not succeed.
const MULTI_STEP_PIPELINE: &str = r#"
version: 1
name: multi-step
stages:
  - id: build
    name: Build
    steps:
      - process:
          program: /bin/sh
          args: [-c, "printf 'step-zero\n'"]
          timeout_seconds: 10
      - process:
          program: /bin/sh
          args: [-c, "rm -rf spool/step-0; printf 'step-one-err\n' >&2; exit 3"]
          timeout_seconds: 10
      - process:
          program: /bin/sh
          args: [-c, "printf 'never\n'"]
          timeout_seconds: 10
"#;

struct MultiStepHarness {
    _directory: tempfile::TempDir,
    controller: Child,
    client: Client,
    pool: sqlx::PgPool,
    organization_id: Uuid,
    project_id: Uuid,
    tls: MtlsFiles,
    agent_port: u16,
    journal: PathBuf,
    workspace: PathBuf,
    scratch: PathBuf,
}

async fn multi_step_harness(agent_id: &str, slug: &str) -> Option<MultiStepHarness> {
    let Ok(migration_url) = std::env::var("MCLOVING_TEST_DATABASE_URL") else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return None;
    };
    let controller_binary = std::env::var_os("MCLOVING_CONTROLLER_BINARY")
        .map(PathBuf::from)
        .expect("MCLOVING_CONTROLLER_BINARY must name the shipped controller binary");
    let runtime_url =
        migration_url.replacen("postgres://mcloving@", "postgres://mcloving_tenant@", 1);
    assert_ne!(migration_url, runtime_url);
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&migration_url)
        .await
        .expect("connect migration role");
    let store = Store::new(pool.clone());
    store.migrate().await.expect("install schema");
    enable_runtime_login(&pool).await;
    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    store
        .create_project(
            organization_id,
            &format!("{slug}-org-{organization_id}"),
            project_id,
            slug,
        )
        .await
        .expect("create test project");

    let directory = tempfile::tempdir().expect("test root");
    let tls = create_mtls(directory.path(), organization_id, agent_id);
    let api_port = free_port();
    let agent_port = free_port();
    let workspace = directory.path().join("workspace");
    std::fs::create_dir(&workspace).expect("create remote workspace root");
    let scratch = directory.path().join("scratch");
    std::fs::create_dir(&scratch).expect("create scratch root");
    let controller = Command::new(controller_binary)
        .env("MCLOVING_MIGRATION_DATABASE_URL", &migration_url)
        .env("MCLOVING_DATABASE_URL", &runtime_url)
        .env("MCLOVING_API_TOKEN", TOKEN)
        .env(
            "MCLOVING_ARTIFACT_AGENT_TOKEN",
            "remote-artifact-agent-token-32-bytes",
        )
        .env("MCLOVING_LISTEN", format!("127.0.0.1:{api_port}"))
        .env("MCLOVING_AGENT_LISTEN", format!("127.0.0.1:{agent_port}"))
        .env("MCLOVING_AGENT_SERVER_CERT_PATH", &tls.server_certificate)
        .env("MCLOVING_AGENT_SERVER_KEY_PATH", &tls.server_key)
        .env("MCLOVING_AGENT_CLIENT_CA_PATH", &tls.ca_certificate)
        .env("MCLOVING_AGENT_IDENTITY_BINDINGS_PATH", &tls.bindings)
        .env("MCLOVING_ORGANIZATION_ID", organization_id.to_string())
        .env("MCLOVING_AGENT_ID", format!("{agent_id}-embedded-disabled"))
        .env("MCLOVING_AGENT_CAPABILITIES", "disabled")
        .env("MCLOVING_AGENT_TRUST_POOL", "trusted-linux")
        .env("MCLOVING_LEASE_SECONDS", "5")
        .env("MCLOVING_POLL_MILLISECONDS", "10")
        .env("MCLOVING_CANCELLATION_POLL_MILLISECONDS", "50")
        .env("MCLOVING_TERMINATION_GRACE_MILLISECONDS", "100")
        .env("MCLOVING_SESSION_EPOCH", "1")
        .env(
            "MCLOVING_WORKSPACE_ROOT",
            directory.path().join("embedded-workspace"),
        )
        .env(
            "MCLOVING_AGENT_JOURNAL",
            directory.path().join("embedded-agent.db"),
        )
        .env(
            "MCLOVING_OBJECT_ROOT",
            directory.path().join("embedded-objects"),
        )
        .kill_on_drop(true)
        .spawn()
        .expect("start shipped controller");
    let client = Client::new(&format!("http://127.0.0.1:{api_port}"), TOKEN);
    wait_until_listening(&client, organization_id).await;
    let journal = directory.path().join("agent.db");
    Some(MultiStepHarness {
        _directory: directory,
        controller,
        client,
        pool,
        organization_id,
        project_id,
        tls,
        agent_port,
        journal,
        workspace,
        scratch,
    })
}

async fn wait_for_terminal(
    client: &Client,
    organization_id: Uuid,
    project_id: Uuid,
    build_id: Uuid,
) -> mcloving_controller_api::BuildResponse {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let status = client
                .status(organization_id, project_id, build_id)
                .await
                .expect("read build status");
            if matches!(status.status.as_str(), "succeeded" | "failed" | "aborted") {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("build reaches a terminal within bound")
}

#[tokio::test]
async fn multi_step_stage_runs_in_order_and_stops_at_the_first_failure() {
    let Some(mut harness) = multi_step_harness("multi-step-agent", "multi-step").await else {
        return;
    };
    let mut agent = agent_command(
        "multi-step-agent",
        harness.organization_id,
        harness.agent_port,
        &harness.tls,
        &harness.journal,
        &harness.workspace,
    )
    .kill_on_drop(true)
    .spawn()
    .expect("start shipped remote agent");

    let pipeline_id = Uuid::new_v4();
    harness
        .client
        .put_pipeline(
            harness.organization_id,
            harness.project_id,
            pipeline_id,
            0,
            &PipelineUpsertRequest {
                slug: "multi-step-e2e".to_owned(),
                source: MULTI_STEP_PIPELINE.to_owned(),
                parameters: Default::default(),
            },
        )
        .await
        .expect("a three-step stage validates and saves");
    let admission = harness
        .client
        .submit_pipeline_on_platform_in_pool(
            harness.organization_id,
            harness.project_id,
            pipeline_id,
            "multi-step-e2e",
            "linux",
            "trusted-linux",
            &PipelineBuildRequest::default(),
        )
        .await
        .expect("submit work");

    // The node routes on the multi-step capability, so an agent from a
    // release without it is never offered this work.
    let required: Vec<String> = sqlx::query_scalar(
        "SELECT required_capabilities FROM nodes WHERE organization_id = $1 AND build_id = $2",
    )
    .bind(harness.organization_id)
    .bind(admission.build_id)
    .fetch_one(&harness.pool)
    .await
    .expect("read the node's required capabilities");
    assert!(
        required
            .iter()
            .any(|capability| capability == "multi-step-v1"),
        "{required:?}"
    );

    let status = wait_for_terminal(
        &harness.client,
        harness.organization_id,
        harness.project_id,
        admission.build_id,
    )
    .await;
    assert_eq!(status.status, "failed");
    assert_eq!(status.attempt_status, "failed");
    let summary = status
        .terminal_summary
        .expect("terminal summary is published");
    assert_eq!(summary["exit_code"], 3, "{summary}");
    let steps = summary["steps"]
        .as_array()
        .expect("multi-step summary lists its steps");
    assert_eq!(steps.len(), 2, "the third step never ran: {summary}");
    assert_eq!(steps[0]["ordinal"], 0);
    assert_eq!(steps[0]["outcome"], "succeeded");
    assert_eq!(steps[1]["ordinal"], 1);
    assert_eq!(steps[1]["outcome"], "failed");
    assert_eq!(steps[1]["exit_code"], 3);

    let logs = harness
        .client
        .logs(
            harness.organization_id,
            harness.project_id,
            admission.build_id,
        )
        .await
        .expect("read logs");
    let chunks = logs
        .iter()
        .map(|log| (log.step_ordinal, log.stream.as_str(), log.text.clone()))
        .collect::<Vec<_>>();
    assert_eq!(
        chunks,
        vec![
            (0, "stdout", Some("step-zero\n".to_owned())),
            (1, "stderr", Some("step-one-err\n".to_owned())),
        ],
        "each step's output is its own chunk under its own ordinal; empty streams and the unrun step publish nothing"
    );
    assert!(
        logs.iter().all(|log| log.attempt_id == status.attempt_id),
        "one attempt ran every step"
    );

    stop(&mut agent).await;
    stop(&mut harness.controller).await;
}

/// The ambiguity window: a step's process has exited and nothing about that
/// exit is durable yet. A restart from exactly there must report the step
/// interrupted, never run it again and never skip past it.
#[tokio::test]
async fn crash_between_a_step_exit_and_its_record_is_reported_not_rerun() {
    let Some(mut harness) = multi_step_harness("multi-step-crash-agent", "multi-step-crash").await
    else {
        return;
    };
    let marker = harness.scratch.join("marker");
    let pipeline = format!(
        r#"
version: 1
name: multi-step-crash
stages:
  - id: build
    name: Build
    steps:
      - process:
          program: /bin/sh
          args: [-c, "printf 'ran\n' >> {marker}"]
          timeout_seconds: 10
      - process:
          program: /bin/sh
          args: [-c, "printf 'second\n' >> {marker}"]
          timeout_seconds: 10
"#,
        marker = marker.display()
    );
    let mut agent = agent_command(
        "multi-step-crash-agent",
        harness.organization_id,
        harness.agent_port,
        &harness.tls,
        &harness.journal,
        &harness.workspace,
    )
    .env("MCLOVING_TEST_CRASH_AFTER_STEP_EXIT", "0")
    .kill_on_drop(true)
    .spawn()
    .expect("start fault-injected agent");

    let pipeline_id = Uuid::new_v4();
    harness
        .client
        .put_pipeline(
            harness.organization_id,
            harness.project_id,
            pipeline_id,
            0,
            &PipelineUpsertRequest {
                slug: "multi-step-crash-e2e".to_owned(),
                source: pipeline,
                parameters: Default::default(),
            },
        )
        .await
        .expect("save pipeline");
    let admission = harness
        .client
        .submit_pipeline_on_platform_in_pool(
            harness.organization_id,
            harness.project_id,
            pipeline_id,
            "multi-step-crash-e2e",
            "linux",
            "trusted-linux",
            &PipelineBuildRequest::default(),
        )
        .await
        .expect("submit work");
    let first_exit = tokio::time::timeout(Duration::from_secs(20), agent.wait())
        .await
        .expect("fault-injected agent exits within bound")
        .expect("wait for fault-injected agent");
    assert_eq!(
        first_exit.code(),
        Some(88),
        "crashed exactly after step 0 exited"
    );
    assert_eq!(
        std::fs::read_to_string(&marker).expect("step 0 ran before the crash"),
        "ran\n"
    );

    let mut agent = agent_command(
        "multi-step-crash-agent",
        harness.organization_id,
        harness.agent_port,
        &harness.tls,
        &harness.journal,
        &harness.workspace,
    )
    .stderr(Stdio::piped())
    .kill_on_drop(true)
    .spawn()
    .expect("restart shipped remote agent");
    // The recovered leader has exited and its birth identity is gone, so the
    // journal cannot prove its descendants are gone either: the attempt parks
    // reconciliation-required under the existing fail-closed rule, naming the
    // interrupted step. Give a wrong implementation every chance to re-run or
    // to skip ahead before checking that it did neither.
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert_eq!(
        std::fs::read_to_string(&marker).expect("marker survives recovery"),
        "ran\n",
        "step 0 ran exactly once and step 1 never ran"
    );
    assert_eq!(
        mcloving_agent::journal_health(&harness.journal)
            .expect("read recovered agent journal")
            .2,
        1,
        "the interrupted attempt stays parked rather than being discharged"
    );
    let status = harness
        .client
        .status(
            harness.organization_id,
            harness.project_id,
            admission.build_id,
        )
        .await
        .expect("read build status");
    assert_ne!(
        status.status, "succeeded",
        "an interrupted step cannot be skipped: {status:?}"
    );
    let mut stderr = agent.stderr.take().expect("agent stderr is piped");
    stop(&mut agent).await;
    let mut report = String::new();
    stderr
        .read_to_string(&mut report)
        .await
        .expect("read agent stderr");
    assert!(
        report.contains("interrupted_at_step:0"),
        "the parked attempt names its interrupted step: {report}"
    );
    stop(&mut harness.controller).await;
}

/// PAR-011: a digest-pinned alpine the container tests run in.
const ALPINE_DIGEST: &str = "docker.io/library/alpine@sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e";

/// Container tests need a rootless podman on the agent host; they run only
/// when the caller says so, and skip (rather than fail) elsewhere.
fn podman_for_tests() -> Option<PathBuf> {
    if std::env::var_os("MCLOVING_TEST_PODMAN").is_none() {
        eprintln!("skipped: MCLOVING_TEST_PODMAN is not set");
        return None;
    }
    let output = StdCommand::new("which")
        .arg("podman")
        .output()
        .expect("locate podman");
    assert!(
        output.status.success(),
        "MCLOVING_TEST_PODMAN is set but podman is not on PATH"
    );
    Some(PathBuf::from(
        String::from_utf8(output.stdout)
            .expect("podman path is UTF-8")
            .trim(),
    ))
}

#[cfg(unix)]
#[tokio::test]
async fn container_stage_runs_in_the_pinned_image_and_sees_only_the_workspace() {
    let Some(podman) = podman_for_tests() else {
        return;
    };
    let Some(mut harness) = multi_step_harness("container-agent", "container").await else {
        return;
    };
    let container_host = IsolatedPodman::new(podman.clone());
    let mut agent = agent_command(
        "container-agent",
        harness.organization_id,
        harness.agent_port,
        &harness.tls,
        &harness.journal,
        &harness.workspace,
    )
    .envs(container_host.agent_environment())
    // A container attempt reserves the bounded reap inside its lease on top
    // of the grace and cadence; the harness's 5 s term cannot hold it.
    .env("MCLOVING_AGENT_LEASE_SECONDS", "30")
    .kill_on_drop(true)
    .spawn()
    .expect("start shipped remote agent with a container runtime");

    // The host workspace root must not be visible from inside the container;
    // only the attempt workspace is mounted, at /workspace.
    let host_root = harness.workspace.display().to_string();
    let pipeline = format!(
        r#"
version: 1
name: container
stages:
  - id: build
    name: Build
    image: {ALPINE_DIGEST}
    steps:
      - process:
          program: /bin/sh
          args: [-c, "cat /etc/os-release"]
          timeout_seconds: 120
      - process:
          program: /bin/sh
          args: [-c, "test ! -e '{host_root}' && test -w /workspace && printf 'host-hidden\n'"]
          timeout_seconds: 30
      - process:
          program: /bin/sh
          args: [-c, "printf 'greeting=%s home=%s\n' \"$GREETING\" \"$HOME\""]
          env:
            GREETING: hello-from-env-file
            HOME: /workspace
          timeout_seconds: 30
"#
    );
    let pipeline_id = Uuid::new_v4();
    harness
        .client
        .put_pipeline(
            harness.organization_id,
            harness.project_id,
            pipeline_id,
            0,
            &PipelineUpsertRequest {
                slug: "container-e2e".to_owned(),
                source: pipeline,
                parameters: Default::default(),
            },
        )
        .await
        .expect("a digest-pinned container stage validates and saves");
    let admission = harness
        .client
        .submit_pipeline_on_platform_in_pool(
            harness.organization_id,
            harness.project_id,
            pipeline_id,
            "container-e2e",
            "linux",
            "trusted-linux",
            &PipelineBuildRequest::default(),
        )
        .await
        .expect("submit work");
    let required: Vec<String> = sqlx::query_scalar(
        "SELECT required_capabilities FROM nodes WHERE organization_id = $1 AND build_id = $2",
    )
    .bind(harness.organization_id)
    .bind(admission.build_id)
    .fetch_one(&harness.pool)
    .await
    .expect("read the node's required capabilities");
    assert!(
        required
            .iter()
            .any(|capability| capability == "container-podman-v1"),
        "{required:?}"
    );
    let status = wait_for_terminal(
        &harness.client,
        harness.organization_id,
        harness.project_id,
        admission.build_id,
    )
    .await;
    let logs = harness
        .client
        .logs(
            harness.organization_id,
            harness.project_id,
            admission.build_id,
        )
        .await
        .expect("read logs");
    let text = logs
        .iter()
        .map(|log| {
            format!(
                "[{} {}] {}",
                log.step_ordinal,
                log.stream,
                log.text.clone().unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join("");
    assert_eq!(status.status, "succeeded", "{status:?}\n{text}");
    assert!(
        text.contains("Alpine Linux"),
        "step 0 ran inside the image: {text}"
    );
    assert!(
        text.contains("host-hidden"),
        "the host root is not visible and /workspace is writable: {text}"
    );
    // Workload variables reach the container through the agent-owned env
    // file, including names the podman client itself would honour if they
    // were in its own environment.
    assert!(
        text.contains("greeting=hello-from-env-file home=/workspace"),
        "env reaches the container by file, not by the client's environment: {text}"
    );

    stop(&mut agent).await;
    stop(&mut harness.controller).await;
}

#[cfg(unix)]
#[tokio::test]
async fn timed_out_container_step_leaves_no_container_behind() {
    let Some(podman) = podman_for_tests() else {
        return;
    };
    let Some(mut harness) =
        multi_step_harness("container-timeout-agent", "container-timeout").await
    else {
        return;
    };
    let container_host = IsolatedPodman::new(podman.clone());
    let mut agent = agent_command(
        "container-timeout-agent",
        harness.organization_id,
        harness.agent_port,
        &harness.tls,
        &harness.journal,
        &harness.workspace,
    )
    .envs(container_host.agent_environment())
    // A container attempt reserves the bounded reap inside its lease on top
    // of the grace and cadence; the harness's 5 s term cannot hold it.
    .env("MCLOVING_AGENT_LEASE_SECONDS", "30")
    .kill_on_drop(true)
    .spawn()
    .expect("start shipped remote agent with a container runtime");
    let pipeline = format!(
        r#"
version: 1
name: container-timeout
stages:
  - id: build
    name: Build
    image: {ALPINE_DIGEST}
    steps:
      - process:
          program: /bin/sh
          args: [-c, "sleep 300"]
          timeout_seconds: 3
"#
    );
    let pipeline_id = Uuid::new_v4();
    harness
        .client
        .put_pipeline(
            harness.organization_id,
            harness.project_id,
            pipeline_id,
            0,
            &PipelineUpsertRequest {
                slug: "container-timeout-e2e".to_owned(),
                source: pipeline,
                parameters: Default::default(),
            },
        )
        .await
        .expect("save pipeline");
    let admission = harness
        .client
        .submit_pipeline_on_platform_in_pool(
            harness.organization_id,
            harness.project_id,
            pipeline_id,
            "container-timeout-e2e",
            "linux",
            "trusted-linux",
            &PipelineBuildRequest::default(),
        )
        .await
        .expect("submit work");
    let status = wait_for_terminal(
        &harness.client,
        harness.organization_id,
        harness.project_id,
        admission.build_id,
    )
    .await;
    assert_eq!(status.status, "failed", "{status:?}");
    let summary = status
        .terminal_summary
        .expect("terminal summary is published");
    assert_eq!(summary["steps"][0]["termination"], "timed_out", "{summary}");

    // The container is named after the attempt and step; after teardown the
    // runtime must not know it at all (`container exists` exits 1).
    let name = format!("mcloving-{}-0", status.attempt_id);
    let exists = container_host
        .command()
        .args(["container", "exists", &name])
        .status()
        .expect("query the container runtime");
    assert_eq!(
        exists.code(),
        Some(1),
        "container {name} must be gone after a timed-out step"
    );

    stop(&mut agent).await;
    stop(&mut harness.controller).await;
}

/// One process step writes files; the stage declares two of them by pattern
/// and one file that no pattern names (PAR-014).
const ARTIFACT_PIPELINE: &str = r#"
version: 1
name: artifacts
stages:
  - id: build
    name: Build
    steps:
      - process:
          program: /bin/sh
          args: [-c, "mkdir -p out target/debug && printf 'hello' > out/a.txt && printf 'log-line' > target/debug/x.log && printf 'not collected' > out/skip.bin"]
          timeout_seconds: 10
    artifacts:
      - name: outputs
        paths: ["out/*.txt", "target/**/*.log"]
"#;

/// The step plants a link to a host file where a declaration would collect
/// it: the whole set is refused by the link's name and nothing is uploaded.
const PLANTED_LINK_PIPELINE: &str = r#"
version: 1
name: planted-link
stages:
  - id: build
    name: Build
    steps:
      - process:
          program: /bin/sh
          args: [-c, "mkdir -p out && printf 'fine' > out/a.txt && ln -s /etc/hostname out/planted.txt"]
          timeout_seconds: 10
    artifacts:
      - name: outputs
        paths: ["out/*"]
"#;

#[tokio::test]
async fn declared_artifacts_are_uploaded_and_downloadable() {
    let Some(mut harness) = multi_step_harness("artifact-agent", "artifacts").await else {
        return;
    };
    let mut agent = agent_command(
        "artifact-agent",
        harness.organization_id,
        harness.agent_port,
        &harness.tls,
        &harness.journal,
        &harness.workspace,
    )
    .kill_on_drop(true)
    .spawn()
    .expect("start shipped remote agent");

    let pipeline_id = Uuid::new_v4();
    harness
        .client
        .put_pipeline(
            harness.organization_id,
            harness.project_id,
            pipeline_id,
            0,
            &PipelineUpsertRequest {
                slug: "artifacts-e2e".to_owned(),
                source: ARTIFACT_PIPELINE.to_owned(),
                parameters: Default::default(),
            },
        )
        .await
        .expect("a stage with declared artifacts validates and saves");
    let admission = harness
        .client
        .submit_pipeline_on_platform_in_pool(
            harness.organization_id,
            harness.project_id,
            pipeline_id,
            "artifacts-e2e",
            "linux",
            "trusted-linux",
            &PipelineBuildRequest::default(),
        )
        .await
        .expect("submit work");
    // The node routes on the upload capability, so an agent from a release
    // without the collector is never offered this work.
    let required: Vec<String> = sqlx::query_scalar(
        "SELECT required_capabilities FROM nodes WHERE organization_id = $1 AND build_id = $2",
    )
    .bind(harness.organization_id)
    .bind(admission.build_id)
    .fetch_one(&harness.pool)
    .await
    .expect("read the node's required capabilities");
    assert!(
        required
            .iter()
            .any(|capability| capability == "artifact-upload-v1"),
        "{required:?}"
    );

    let status = wait_for_terminal(
        &harness.client,
        harness.organization_id,
        harness.project_id,
        admission.build_id,
    )
    .await;
    assert_eq!(status.status, "succeeded", "{:?}", status.terminal_summary);
    let mut artifacts = harness
        .client
        .artifacts(
            harness.organization_id,
            harness.project_id,
            admission.build_id,
        )
        .await
        .expect("list the build's artifacts");
    artifacts.sort_by(|a, b| a.name.cmp(&b.name));
    let listed = artifacts
        .iter()
        .map(|artifact| {
            (
                artifact.name.as_str(),
                artifact.bytes,
                artifact.status.as_str(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        listed,
        vec![
            ("outputs/out/a.txt", 5, "available"),
            ("outputs/target/debug/x.log", 8, "available"),
        ],
        "each matching regular file is one object under the declared name; the undeclared file is not"
    );
    assert!(
        artifacts
            .iter()
            .all(|artifact| artifact.attempt_id == status.attempt_id),
        "the attempt that ran the step owns its artifacts"
    );
    let bytes = harness
        .client
        .download_artifact(
            harness.organization_id,
            harness.project_id,
            admission.build_id,
            status.attempt_id,
            "outputs/out/a.txt",
        )
        .await
        .expect("download the collected file");
    assert_eq!(bytes, b"hello");
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        artifacts[0].sha256,
        "the listing's digest is the digest of the bytes the step wrote"
    );

    stop(&mut agent).await;
    stop(&mut harness.controller).await;
}

#[tokio::test]
async fn a_planted_link_refuses_the_artifact_set_by_name() {
    let Some(mut harness) = multi_step_harness("planted-link-agent", "planted-link").await else {
        return;
    };
    let mut agent = agent_command(
        "planted-link-agent",
        harness.organization_id,
        harness.agent_port,
        &harness.tls,
        &harness.journal,
        &harness.workspace,
    )
    .kill_on_drop(true)
    .spawn()
    .expect("start shipped remote agent");

    let pipeline_id = Uuid::new_v4();
    harness
        .client
        .put_pipeline(
            harness.organization_id,
            harness.project_id,
            pipeline_id,
            0,
            &PipelineUpsertRequest {
                slug: "planted-link-e2e".to_owned(),
                source: PLANTED_LINK_PIPELINE.to_owned(),
                parameters: Default::default(),
            },
        )
        .await
        .expect("the pipeline validates and saves");
    let admission = harness
        .client
        .submit_pipeline_on_platform_in_pool(
            harness.organization_id,
            harness.project_id,
            pipeline_id,
            "planted-link-e2e",
            "linux",
            "trusted-linux",
            &PipelineBuildRequest::default(),
        )
        .await
        .expect("submit work");
    let status = wait_for_terminal(
        &harness.client,
        harness.organization_id,
        harness.project_id,
        admission.build_id,
    )
    .await;
    assert_eq!(status.status, "failed", "{:?}", status.terminal_summary);
    let summary = status
        .terminal_summary
        .expect("terminal summary is published");
    assert_eq!(
        summary["reason"], "artifact_refused:link:out/planted.txt",
        "the refusal names the link, not the file beside it: {summary}"
    );
    let artifacts = harness
        .client
        .artifacts(
            harness.organization_id,
            harness.project_id,
            admission.build_id,
        )
        .await
        .expect("list the build's artifacts");
    assert!(
        artifacts.is_empty(),
        "nothing of a refused set is uploaded: {artifacts:?}"
    );

    stop(&mut agent).await;
    stop(&mut harness.controller).await;
}

/// Every test Podman operation owns fresh config, runtime and storage roots.
#[cfg(unix)]
struct IsolatedPodman {
    _root: Option<tempfile::TempDir>,
    runtime: PathBuf,
    graph: PathBuf,
    run: PathBuf,
    xdg: PathBuf,
    storage: PathBuf,
    controlled: PathBuf,
    custody_qualified: bool,
}
#[cfg(unix)]
impl IsolatedPodman {
    fn new(runtime: PathBuf) -> Self {
        use mcloving_agent_runtime::executor::podman::{
            CONTAINERS_CONFIGURATION, STORAGE_CONFIGURATION,
        };
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let graph = root.path().join("graph");
        let run = root.path().join("run/containers");
        let xdg = root.path().join("host-config");
        let controlled_root = root.path().join("controlled");
        for dir in [
            run.clone(),
            xdg.join("containers"),
            controlled_root.join(".config/containers"),
        ] {
            std::fs::create_dir_all(&dir).unwrap();
            for ancestor in dir.ancestors().take_while(|p| p.starts_with(root.path())) {
                std::fs::set_permissions(ancestor, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
        }
        let storage = xdg.join("containers/storage.conf");
        std::fs::write(
            &storage,
            format!(
                "[storage]\ndriver = \"vfs\"\ngraphroot = \"{}\"\nrootless_storage_path = \"{}\"\nrunroot = \"{}\"\n",
                graph.display(),
                graph.display(),
                run.display()
            ),
        )
        .unwrap();
        std::fs::create_dir_all(xdg.join(".config/containers")).unwrap();
        let controlled = controlled_root.join("containers.conf");
        for (path, bytes) in [
            (controlled.clone(), CONTAINERS_CONFIGURATION),
            (controlled_root.join("storage.conf"), STORAGE_CONFIGURATION),
            (
                controlled_root.join(".config/containers/mounts.conf"),
                b"".as_slice(),
            ),
        ] {
            std::fs::write(&path, bytes).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
        eprintln!(
            "owned Podman fixture: root={} mode=0700 graph={} run={} driver=vfs storage={} controlled={}",
            root.path().display(),
            graph.display(),
            run.display(),
            storage.display(),
            controlled.display()
        );
        let mut fixture = Self {
            _root: Some(root),
            runtime,
            graph,
            run,
            xdg,
            storage,
            controlled,
            custody_qualified: false,
        };
        fixture.preflight_owned_context().expect("bootstrap and controlled confirmation must select the exact owned store before any workload");
        fixture.custody_qualified = true;
        fixture
    }
    fn root_path(&self) -> &Path {
        self._root.as_ref().expect("owned fixture is live").path()
    }
    fn preflight_owned_context(&self) -> Result<(), String> {
        use mcloving_agent_runtime::executor::podman::PodmanContext;
        let context = PodmanContext {
            graph_root: self.graph.clone(),
            run_root: self.run.clone(),
            driver: "vfs".into(),
            storage_options: Vec::new(),
            config_path: self.controlled.clone(),
            home: Some(self.xdg.clone().into_os_string()),
            runtime_dir: Some(self.run.parent().unwrap().as_os_str().to_owned()),
            user: std::env::var_os("USER"),
            temporary_dir: None,
        };
        context
            .validate_configuration()
            .map_err(|e| e.to_string())?;
        let mut bootstrap = StdCommand::new(&self.runtime);
        bootstrap
            .env_clear()
            .envs(context.environment())
            .env("HOME", &self.xdg)
            .env("CONTAINERS_STORAGE_CONF", &self.storage)
            .args(["info", "--format", "json"]);
        let first = self.bounded_fixture_command(bootstrap, "bootstrap-info")?;
        Self::require_owned_store_info(&first, &self.graph, &self.run)?;
        let mut confirmation = StdCommand::new(&self.runtime);
        confirmation
            .env_clear()
            .envs(context.environment())
            .args(context.arguments())
            .args(["info", "--format", "json"]);
        let second = self.bounded_fixture_command(confirmation, "controlled-confirmation-info")?;
        Self::require_owned_store_info(&second, &self.graph, &self.run)?;
        let a: serde_json::Value = serde_json::from_slice(&first).map_err(|e| e.to_string())?;
        let b: serde_json::Value = serde_json::from_slice(&second).map_err(|e| e.to_string())?;
        if a["store"]["graphOptions"] != b["store"]["graphOptions"] {
            return Err("owned store options changed during confirmation".into());
        }
        eprintln!(
            "actual owned bootstrap and controlled confirmation: graph={} run={} driver=vfs options={} effective_HOME={} mounts={}",
            self.graph.display(),
            self.run.display(),
            b["store"]["graphOptions"],
            self.controlled.parent().unwrap().display(),
            context
                .config_root()
                .join("containers/mounts.conf")
                .display()
        );
        Ok(())
    }
    fn require_owned_store_info(bytes: &[u8], graph: &Path, run: &Path) -> Result<(), String> {
        let info: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if info["host"]["security"]["rootless"] != true
            || info["store"]["graphRoot"].as_str() != graph.to_str()
            || info["store"]["runRoot"].as_str() != run.to_str()
            || info["store"]["graphDriverName"] != "vfs"
            || info["store"]["graphOptions"]
                .as_object()
                .is_none_or(|m| !m.is_empty())
        {
            return Err(format!(
                "effective store mismatch; mutation forbidden: expected graph={} run={} driver=vfs options={{}}, actual={}",
                graph.display(),
                run.display(),
                info["store"]
            ));
        }
        Ok(())
    }
    // Cleanup is bounded and inspects the exact owned store before deleting
    // its backing paths. Failure preserves config, runtime, store and logs.
    fn cleanup_owned_store(&self) -> Result<(), String> {
        if !self.custody_qualified {
            return Err(
                "fixture store preflight unqualified; no cleanup mutation attempted".into(),
            );
        }
        if self.graph != self.root_path().join("graph")
            || self.run != self.root_path().join("run/containers")
        {
            return Err("cleanup storage identity is outside its owned fixture".into());
        }
        for (graph, run, prefix) in [
            (self.graph.clone(), self.run.clone(), "original"),
            (
                self.root_path().join("other-graph"),
                self.run.clone(),
                "replacement",
            ),
        ] {
            self.cleanup_store(&graph, &run, prefix)?;
        }
        Ok(())
    }
    fn cleanup_store(
        &self,
        graph_path: &Path,
        run_path: &Path,
        prefix: &str,
    ) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt;
        if !graph_path.exists() {
            return Ok(());
        }
        let root = std::fs::symlink_metadata(self.root_path()).map_err(|e| e.to_string())?;
        let graph = std::fs::symlink_metadata(graph_path).map_err(|e| e.to_string())?;
        if !root.is_dir()
            || root.mode() & 0o777 != 0o700
            || root.uid() != nix::unistd::geteuid().as_raw()
            || !graph.is_dir()
            || graph.uid() != root.uid()
            || graph.mode() & 0o022 != 0
        {
            return Err("cleanup fixture/store custody cannot be established".into());
        }
        let info = self.cleanup_command(
            graph_path,
            run_path,
            &["info", "--format", "json"],
            &format!("{prefix}-custody-info"),
        )?;
        Self::require_owned_store_info(&info, graph_path, run_path)?;
        for (args, phase, require_empty) in [
            (vec!["rm", "--force", "--all"], "remove", false),
            (vec!["ps", "--all", "--format", "{{.ID}}"], "absence", true),
            (vec!["system", "reset", "--force"], "reset", false),
            (
                vec!["ps", "--all", "--format", "{{.ID}}"],
                "post-reset-containers",
                true,
            ),
            (
                vec!["images", "--all", "--format", "{{.ID}}"],
                "post-reset-images",
                true,
            ),
        ] {
            let output =
                self.cleanup_command(graph_path, run_path, &args, &format!("{prefix}-{phase}"))?;
            if require_empty && !output.iter().all(u8::is_ascii_whitespace) {
                return Err(format!("owned {prefix} store still has objects ({phase})"));
            }
        }
        // A successful reset can recreate empty database/driver scaffolding.
        // Bound the filesystem inspection and refuse unexpected substitutions.
        let entries = std::fs::read_dir(graph_path).map_err(|e| e.to_string())?;
        let mut count = 0;
        for entry in entries {
            count += 1;
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry.file_name();
            if count > 16
                || !matches!(
                    name.to_str(),
                    Some(
                        "storage.lock"
                            | "userns.lock"
                            | "vfs"
                            | "vfs-images"
                            | "vfs-layers"
                            | "vfs-containers"
                            | "libpod"
                            | "mounts"
                            | "db.sql"
                            | "db.sql-shm"
                            | "db.sql-wal"
                            | "defaultNetworkBackend"
                            | "networks"
                    )
                )
            {
                return Err(format!(
                    "unexpected owned store entry: {}",
                    entry.path().display()
                ));
            }
            let metadata = std::fs::symlink_metadata(entry.path()).map_err(|e| e.to_string())?;
            if metadata.file_type().is_symlink() || metadata.uid() != root.uid() {
                return Err("owned store entry custody changed".into());
            }
        }
        eprintln!(
            "exact owned {prefix} store empty after rm/ps/reset/ps/images; graph={} run={} bounded_entries={count}",
            graph_path.display(),
            run_path.display()
        );
        Ok(())
    }
    fn cleanup_command(
        &self,
        graph: &Path,
        run: &Path,
        args: &[&str],
        phase: &str,
    ) -> Result<Vec<u8>, String> {
        self.bounded_fixture_command(
            {
                let mut command = self.command_for_store(graph, run);
                command.args(args);
                command
            },
            phase,
        )
    }
    fn bounded_fixture_command(
        &self,
        mut command: StdCommand,
        phase: &str,
    ) -> Result<Vec<u8>, String> {
        let stdout_path = self.root_path().join(format!("cleanup-{phase}.stdout"));
        let stderr_path = self.root_path().join(format!("cleanup-{phase}.stderr"));
        let stdout = std::fs::File::create(&stdout_path).map_err(|e| e.to_string())?;
        let stderr = std::fs::File::create(&stderr_path).map_err(|e| e.to_string())?;
        eprintln!("owned fixture invocation {phase}: {command:?}");
        let mut child = command
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .map_err(|e| format!("cleanup {phase}: {e}"))?;
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            match child.try_wait().map_err(|e| e.to_string())? {
                Some(status) if status.success() => break,
                Some(status) => {
                    return Err(format!(
                        "cleanup {phase} exited {status}; see {}",
                        stderr_path.display()
                    ));
                }
                None if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(25))
                }
                None => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("cleanup {phase} timed out; store preserved"));
                }
            }
        }
        let size = std::fs::metadata(&stdout_path)
            .map_err(|e| e.to_string())?
            .len();
        if size > 65_536 {
            return Err(format!("cleanup {phase} output exceeded bound"));
        }
        std::fs::read(stdout_path).map_err(|e| e.to_string())
    }
    fn agent_environment(&self) -> Vec<(&'static str, PathBuf)> {
        vec![
            ("MCLOVING_AGENT_PODMAN_PATH", self.runtime.clone()),
            ("MCLOVING_AGENT_PODMAN_CONFIG_PATH", self.controlled.clone()),
            ("HOME", self.xdg.clone()),
            ("XDG_CONFIG_HOME", self.xdg.clone()),
            ("XDG_RUNTIME_DIR", self.run.parent().unwrap().to_owned()),
            ("CONTAINERS_STORAGE_CONF", self.storage.clone()),
        ]
    }
    fn command(&self) -> StdCommand {
        self.command_for_store(&self.graph, &self.run)
    }
    fn command_for_store(&self, graph: &Path, run: &Path) -> StdCommand {
        assert!(
            self.custody_qualified,
            "no workload or cleanup command before exact private-store preflight"
        );
        let mut command = StdCommand::new(&self.runtime);
        command
            .env_clear()
            .env(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            )
            .envs(std::env::vars_os().filter(|(k, _)| matches!(k.to_str(), Some("HOME" | "USER"))))
            .env("XDG_CONFIG_HOME", &self.xdg)
            .env("HOME", &self.xdg)
            .env("XDG_RUNTIME_DIR", self.run.parent().unwrap())
            .env("CONTAINERS_STORAGE_CONF", &self.storage)
            .args(["--root"])
            .arg(graph)
            .arg("--runroot")
            .arg(run)
            .args([
                "--storage-driver",
                "vfs",
                "--storage-opt=",
                "--transient-store=false",
            ]);
        command
    }
}
#[cfg(unix)]
impl Drop for IsolatedPodman {
    fn drop(&mut self) {
        if let Err(reason) = self.cleanup_owned_store() {
            let failure = self.root_path().join("cleanup-failure.txt");
            let _ = std::fs::write(
                &failure,
                format!(
                    "{reason}\nExplicit original graph={} run={} driver=vfs\n",
                    self.graph.display(),
                    self.run.display()
                ),
            );
            let preserved = self._root.take().expect("owned fixture is live").keep();
            eprintln!(
                "unverified Podman store preserved at {}: {reason}",
                preserved.display()
            );
            if !std::thread::panicking() {
                panic!(
                    "owned Podman store cleanup unverified; evidence at {}",
                    preserved.display()
                );
            }
        } else {
            eprintln!(
                "verified owned Podman cleanup: graph={} run={} driver=vfs; exact store contains no containers or images after reset",
                self.graph.display(),
                self.run.display()
            );
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn controlled_podman_configuration_excludes_a_genuine_implicit_mount() {
    let Some(podman) = podman_for_tests() else {
        return;
    };
    let Some(mut harness) = multi_step_harness("implicit-mount-agent", "implicit-mount").await
    else {
        return;
    };
    let host = IsolatedPodman::new(podman);
    let sentinel = host.root_path().join("host-secret");
    std::fs::create_dir(&sentinel).unwrap();
    std::fs::write(sentinel.join("sentinel"), b"host-only-mount-secret").unwrap();
    std::fs::write(
        host.xdg.join(".config/containers/mounts.conf"),
        format!("{}:/implicit-secret\n", sentinel.display()),
    )
    .unwrap();
    let control = host
        .command()
        .args([
            "run",
            "--rm",
            "--entrypoint",
            "/bin/sh",
            ALPINE_DIGEST,
            "-c",
            "cat /implicit-secret/sentinel",
        ])
        .output()
        .unwrap();
    assert!(
        control.status.success(),
        "uncontrolled mount must actually expose sentinel: {}",
        String::from_utf8_lossy(&control.stderr)
    );
    assert!(String::from_utf8_lossy(&control.stdout).contains("host-only-mount-secret"));
    eprintln!(
        "uncontrolled real implicit mount exposes sentinel: {}",
        String::from_utf8_lossy(&control.stdout)
    );
    let mut agent = agent_command(
        "implicit-mount-agent",
        harness.organization_id,
        harness.agent_port,
        &harness.tls,
        &harness.journal,
        &harness.workspace,
    )
    .envs(host.agent_environment())
    .env("MCLOVING_AGENT_LEASE_SECONDS", "30")
    .kill_on_drop(true)
    .spawn()
    .unwrap();
    let pipeline = format!(
        "version: 1\nname: implicit-mount\nstages:\n  - id: build\n    name: Build\n    image: {ALPINE_DIGEST}\n    steps:\n      - process:\n          program: /bin/sh\n          args: [-c, \"if ! test -w /workspace; then printf workspace-not-writable; exit 83; fi; printf workspace-writable; if test -e /implicit-secret/sentinel; then printf unintended-sentinel-present:; cat /implicit-secret/sentinel; exit 84; fi; printf mount-excluded\"]\n          timeout_seconds: 30\n"
    );
    let id = Uuid::new_v4();
    harness
        .client
        .put_pipeline(
            harness.organization_id,
            harness.project_id,
            id,
            0,
            &PipelineUpsertRequest {
                slug: "implicit-mount".into(),
                source: pipeline,
                parameters: Default::default(),
            },
        )
        .await
        .unwrap();
    let admission = harness
        .client
        .submit_pipeline_on_platform_in_pool(
            harness.organization_id,
            harness.project_id,
            id,
            "implicit-mount",
            "linux",
            "trusted-linux",
            &PipelineBuildRequest::default(),
        )
        .await
        .unwrap();
    let result = wait_for_terminal(
        &harness.client,
        harness.organization_id,
        harness.project_id,
        admission.build_id,
    )
    .await;
    let logs = harness
        .client
        .logs(
            harness.organization_id,
            harness.project_id,
            admission.build_id,
        )
        .await
        .unwrap();
    assert_eq!(
        result.status, "succeeded",
        "actual mount step status with logs: {logs:?}"
    );
    assert!(
        logs.iter().any(|log| log
            .text
            .as_deref()
            .unwrap_or("")
            .contains("workspace-writable")),
        "actual workspace writability witness: {logs:?}"
    );
    assert!(
        logs.iter()
            .any(|log| log.text.as_deref().unwrap_or("").contains("mount-excluded"))
    );
    eprintln!(
        "controlled real implicit mount excluded; workspace writable; build={} status={}",
        admission.build_id, result.status
    );
    stop(&mut agent).await;
    stop(&mut harness.controller).await;
}

#[cfg(unix)]
#[tokio::test]
async fn storage_configuration_drift_parks_recovery_while_original_container_survives() {
    let Some(podman) = podman_for_tests() else {
        return;
    };
    let Some(mut harness) = multi_step_harness("storage-drift-agent", "storage-drift").await else {
        return;
    };
    let host = IsolatedPodman::new(podman);
    let start_agent = || {
        let mut command = agent_command(
            "storage-drift-agent",
            harness.organization_id,
            harness.agent_port,
            &harness.tls,
            &harness.journal,
            &harness.workspace,
        );
        command
            .envs(host.agent_environment())
            .env("MCLOVING_AGENT_LEASE_SECONDS", "30")
            .kill_on_drop(true);
        command
    };
    let mut agent = start_agent().spawn().unwrap();
    let id = Uuid::new_v4();
    let source = format!(
        "version: 1\nname: storage-drift\nstages:\n  - id: build\n    name: Build\n    image: {ALPINE_DIGEST}\n    steps:\n      - process:\n          program: /bin/sh\n          args: [-c, \"printf running > /workspace/running; sleep 300\"]\n          timeout_seconds: 300\n"
    );
    harness
        .client
        .put_pipeline(
            harness.organization_id,
            harness.project_id,
            id,
            0,
            &PipelineUpsertRequest {
                slug: "storage-drift".into(),
                source,
                parameters: Default::default(),
            },
        )
        .await
        .unwrap();
    let admission = harness
        .client
        .submit_pipeline_on_platform_in_pool(
            harness.organization_id,
            harness.project_id,
            id,
            "storage-drift",
            "linux",
            "trusted-linux",
            &PipelineBuildRequest::default(),
        )
        .await
        .unwrap();
    let attempt = tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            let status = harness
                .client
                .status(
                    harness.organization_id,
                    harness.project_id,
                    admission.build_id,
                )
                .await
                .unwrap();
            if matches!(status.status.as_str(), "failed" | "aborted" | "succeeded") {
                let logs = harness
                    .client
                    .logs(
                        harness.organization_id,
                        harness.project_id,
                        admission.build_id,
                    )
                    .await
                    .unwrap();
                panic!(
                    "storage fixture exited before recovery semantics: status={} logs={logs:?}",
                    status.status
                );
            }
            let journal = mcloving_agent_runtime::Journal::open(&harness.journal).unwrap();
            for attempt in journal.reconcile().unwrap().attempts {
                if let Some(name) = &attempt.container_name
                    && attempt.process_id.is_some()
                    && host
                        .command()
                        .args(["container", "exists", name])
                        .status()
                        .unwrap()
                        .success()
                {
                    return attempt;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("container launched and durably journaled");
    let admitted_status = harness
        .client
        .status(
            harness.organization_id,
            harness.project_id,
            admission.build_id,
        )
        .await
        .unwrap();
    assert_eq!(admitted_status.build_id, admission.build_id);
    assert_eq!(admitted_status.attempt_id.to_string(), attempt.attempt_id);
    let controller_restore_epoch: i64 =
        sqlx::query_scalar("SELECT restore_epoch FROM attempts WHERE organization_id=$1 AND id=$2")
            .bind(harness.organization_id)
            .bind(admitted_status.attempt_id)
            .fetch_one(&harness.pool)
            .await
            .unwrap();
    assert_eq!(
        (u64::try_from(controller_restore_epoch).unwrap() << 32)
            | u64::try_from(admitted_status.fence).unwrap(),
        attempt.fence_token,
        "journal authority binds the real controller restore epoch and fence"
    );
    let identity = attempt.container_context.as_deref().unwrap();
    let hex = |v: &std::ffi::OsStr| {
        v.as_encoded_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    assert!(identity.starts_with("v3|runtime="));
    assert!(
        identity.contains(&format!("|root={}|", hex(host.graph.as_os_str()))),
        "journal pins exact expected graph root: {identity}"
    );
    assert!(
        identity.contains(&format!("|runroot={}|", hex(host.run.as_os_str()))),
        "journal pins exact expected runtime root: {identity}"
    );
    assert!(
        identity.contains("|driver=766673|"),
        "journal pins vfs, not a field-name placeholder: {identity}"
    );
    let name = attempt.container_name.as_deref().unwrap();
    stop(&mut agent).await;
    // Kill the original client after the agent, leaving conmon's container alive.
    assert!(
        StdCommand::new("kill")
            .args(["-KILL", &attempt.process_id.unwrap().to_string()])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        host.command()
            .args(["container", "exists", name])
            .status()
            .unwrap()
            .success()
    );
    let original = std::fs::read(&host.storage).unwrap();
    let replacement_graph = host.root_path().join("other-graph");
    let replacement_run = host.run.clone();
    std::fs::write(
        &host.storage,
        format!(
            "[storage]\ndriver = \"vfs\"\ngraphroot = \"{}\"\nrootless_storage_path = \"{}\"\nrunroot = \"{}\"\n",
            replacement_graph.display(),
            replacement_graph.display(),
            replacement_run.display()
        ),
    )
    .unwrap();
    let refusal_log = host.root_path().join("recovery-store-refusal.log");
    let mut recovering = start_agent()
        .stderr(Stdio::from(std::fs::File::create(&refusal_log).unwrap()))
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let rows = mcloving_agent_runtime::Journal::open(&harness.journal)
                .unwrap()
                .reconcile()
                .unwrap()
                .attempts;
            if rows.iter().any(|a| {
                a.attempt_id == attempt.attempt_id
                    && a.phase == mcloving_agent_runtime::AttemptPhase::ReconciliationRequired
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("storage drift must park, not terminalize");
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let report = std::fs::read_to_string(&refusal_log).unwrap();
            let status = harness.client.status(harness.organization_id, harness.project_id, admission.build_id).await.unwrap();
            if report.contains(&format!("recovered container {name}: effective store changed; absence unproven")) && status.status == "reconciliation_required" {
                assert_eq!(status.attempt_id.to_string(), attempt.attempt_id);
                assert_eq!(status.attempt_status, "reconciliation_required");
                assert!(status.terminal_summary.is_none()); break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }).await.expect("actual storage comparison refuses the exact matching build, independently of PGID uncertainty");
    let terminal_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM attempts AS a JOIN nodes AS n ON n.organization_id = a.organization_id AND n.id = a.node_id WHERE a.organization_id = $1 AND n.build_id = $2 AND a.id = $3 AND (a.completed_at IS NOT NULL OR a.terminal_summary IS NOT NULL OR a.status IN ('succeeded', 'failed', 'aborted'))")
        .bind(harness.organization_id).bind(admission.build_id).bind(admitted_status.attempt_id).fetch_one(&harness.pool).await.unwrap();
    assert_eq!(
        terminal_rows, 0,
        "parked attempt must not publish a terminal outcome"
    );
    let terminal_events: i64 = sqlx::query_scalar("SELECT count(*) FROM build_events WHERE organization_id = $1 AND build_id = $2 AND kind IN ('attempt.terminal', 'attempt.reconciliation_terminal', 'attempt.cancellation_completed', 'attempt.recovery_terminated', 'attempt.recovery_process_already_exited', 'attempt.recovery_stale_process')")
        .bind(harness.organization_id).bind(admission.build_id).fetch_one(&harness.pool).await.unwrap();
    assert_eq!(terminal_events, 0);
    assert!(
        host.command()
            .args(["container", "exists", name])
            .status()
            .unwrap()
            .success(),
        "original store still contains the container"
    );
    eprintln!(
        "storage drift witness: build={} attempt={} fence={} journal_context={} parked=true terminal_rows={} terminal_events={} original_container={} alive=true refusal={}",
        admission.build_id,
        attempt.attempt_id,
        attempt.fence_token,
        identity,
        terminal_rows,
        terminal_events,
        name,
        std::fs::read_to_string(&refusal_log).unwrap()
    );
    stop(&mut recovering).await;
    std::fs::write(&host.storage, original).unwrap();
    let restored_log = host.root_path().join("recovery-restored.log");
    let mut restored = start_agent()
        .stderr(Stdio::from(std::fs::File::create(&restored_log).unwrap()))
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if host
                .command()
                .args(["container", "exists", name])
                .status()
                .unwrap()
                .code()
                == Some(1)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("restoring store identity permits original-store cleanup");
    // The matched restored control reaps the original store, while the
    // independent dead-client process-group uncertainty remains fail-closed.
    let restored_report = std::fs::read_to_string(&restored_log).unwrap();
    assert!(!restored_report.contains("effective store changed; absence unproven"));
    assert!(restored_report.contains(&format!("recovered container {name}: effective store matches journal; proving original-store absence")), "matched restored identity must reach the real original-store reap: {restored_report}");
    let before_operator = harness
        .client
        .status(
            harness.organization_id,
            harness.project_id,
            admission.build_id,
        )
        .await
        .unwrap();
    assert_eq!(before_operator.attempt_id, admitted_status.attempt_id);
    assert_eq!(before_operator.status, "reconciliation_required");
    assert!(before_operator.terminal_summary.is_none());
    assert_eq!(
        host.command()
            .args(["container", "exists", name])
            .status()
            .unwrap()
            .code(),
        Some(1),
        "absence precedes any operator terminal decision"
    );
    stop(&mut restored).await;
    eprintln!(
        "restored identity witness: build={} original_container={} absent=true controller_parked=true before_operator=true matched_report={}",
        admission.build_id, name, restored_report
    );
    // Use the existing controller-side operator reconciliation entry point
    // on this explicitly owned fixture; never mutate SQL truth to bypass it.
    let actor = "AGENT-009-owned-storage-fixture-operator";
    let summary = json!({"reason":"container_absence_verified_after_storage_restore", "container":name, "journal_context":identity, "owned_graphroot":host.graph, "owned_runroot":host.run, "independent_process_group_uncertainty":true});
    assert!(
        Store::new(harness.pool.clone())
            .finalize_reconciled_attempt(
                harness.organization_id,
                admitted_status.attempt_id,
                admitted_status.fence,
                actor,
                mcloving_controller_store::TerminalOutcome::Aborted,
                summary.clone()
            )
            .await
            .unwrap()
    );
    let terminal = wait_for_terminal(
        &harness.client,
        harness.organization_id,
        harness.project_id,
        admission.build_id,
    )
    .await;
    assert_eq!(terminal.status, "aborted");
    assert_eq!(terminal.attempt_status, "aborted");
    assert_eq!(terminal.attempt_id, admitted_status.attempt_id);
    let authorization_count: i64 = sqlx::query_scalar("SELECT count(*) FROM build_events WHERE organization_id = $1 AND build_id = $2 AND kind = 'attempt.reconciliation_terminal' AND payload ->> 'attempt_id' = $3::text AND payload ->> 'actor' = $4 AND payload -> 'summary' = $5::jsonb")
        .bind(harness.organization_id).bind(admission.build_id).bind(admitted_status.attempt_id).bind(actor).bind(&summary).fetch_one(&harness.pool).await.unwrap();
    assert_eq!(
        authorization_count, 1,
        "terminal receipt binds existing operator authority to this exact fixture"
    );
    let mut discharged = start_agent().spawn().unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if !mcloving_agent_runtime::Journal::open(&harness.journal).unwrap().reconcile().unwrap().attempts.iter().any(|a| a.attempt_id == attempt.attempt_id) { break; }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }).await.expect("real controller authorizes retirement only after original-store absence and explicit terminal reconciliation");
    let discharge_count: i64 = sqlx::query_scalar("SELECT count(*) FROM build_events WHERE organization_id = $1 AND build_id = $2 AND kind = 'attempt.recovered_discharge_authorized' AND payload ->> 'attempt_id' = $3::text")
        .bind(harness.organization_id).bind(admission.build_id).bind(admitted_status.attempt_id).fetch_one(&harness.pool).await.unwrap();
    assert_eq!(discharge_count, 1);
    eprintln!(
        "explicit operator discharge witness: build={} attempt={} actor={} summary={} authorization_count={} terminal_status={} local_retired=true discharge_count={}",
        admission.build_id,
        admitted_status.attempt_id,
        actor,
        summary,
        authorization_count,
        terminal.status,
        discharge_count
    );
    stop(&mut discharged).await;
    stop(&mut harness.controller).await;
}
