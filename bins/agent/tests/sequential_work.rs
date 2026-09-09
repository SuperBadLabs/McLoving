//! Real shipped-controller/remote-agent campaign; no mocked executor and no imported jobs.
use mcloving_controller_api::{
    Client,
    sequential::{SequentialBuildBinding, plan_sequential_build},
};
use mcloving_controller_store::{
    DagAdmission, PipelineWrite, SequentialBuildResult, SequentialDagBuild, Store, TerminalOutcome,
};
use mcloving_pipeline_ir::{ParseLimits, compile_strict_yaml};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use std::collections::BTreeSet;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command as StdCommand, Stdio};
use std::time::Duration;
use tokio::process::{Child, Command};
use uuid::Uuid;

const TOKEN: &str = "sequential-contained-test-token-32-bytes";
struct Harness {
    store: Store,
    agent_id: String,
    org: Uuid,
    project: Uuid,
    root: tempfile::TempDir,
    tls: MtlsFiles,
    api_port: u16,
    agent_port: u16,
    controller: Child,
    migration_url: String,
    runtime_url: String,
}

impl Harness {
    async fn new() -> Option<Self> {
        let Ok(migration_url) = std::env::var("MCLOVING_TEST_DATABASE_URL") else {
            eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
            return None;
        };
        let runtime_url =
            migration_url.replacen("postgres://mcloving@", "postgres://mcloving_tenant@", 1);
        assert_ne!(migration_url, runtime_url);
        let store = Store::new(
            PgPoolOptions::new()
                .max_connections(8)
                .connect(&migration_url)
                .await
                .unwrap(),
        );
        store.migrate().await.unwrap();
        sqlx::query("ALTER ROLE mcloving_tenant LOGIN")
            .execute(store.pool())
            .await
            .unwrap();
        let org = Uuid::new_v4();
        let project = Uuid::new_v4();
        store
            .create_project(
                org,
                &format!("sequential-{org}"),
                project,
                "sequential-contained",
            )
            .await
            .unwrap();
        let root = tempfile::tempdir().unwrap();
        let agent_id = format!("sequential-{org}");
        let tls = create_mtls(root.path(), org, &agent_id);
        std::fs::create_dir(root.path().join("workspace")).unwrap();
        let api_port = free_port();
        let agent_port = free_port();
        let controller = controller_command(
            &migration_url,
            &runtime_url,
            org,
            root.path(),
            &tls,
            api_port,
            agent_port,
        )
        .spawn()
        .unwrap();
        let harness = Self {
            store,
            agent_id,
            org,
            project,
            root,
            tls,
            api_port,
            agent_port,
            controller,
            migration_url,
            runtime_url,
        };
        harness.ready().await;
        for (kind, binary) in [
            (
                "controller",
                PathBuf::from(std::env::var_os("MCLOVING_CONTROLLER_BINARY").unwrap()),
            ),
            ("agent", PathBuf::from(env!("CARGO_BIN_EXE_mcloving-agent"))),
        ] {
            println!(
                "sequential-executed-binary {kind} {}",
                hex(&Sha256::digest(std::fs::read(binary).unwrap()))
            );
        }
        Some(harness)
    }
    async fn ready(&self) {
        let client = Client::new(&format!("http://127.0.0.1:{}", self.api_port), TOKEN);
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if client.explain(self.org, &[]).await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        })
        .await
        .expect("shipped controller ready");
    }
    fn agent(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_mcloving-agent"));
        command
            .env_remove("MCLOVING_TEST_DATABASE_URL")
            .env("MCLOVING_AGENT_ID", &self.agent_id)
            .env("MCLOVING_AGENT_TRUST_POOL", "migration-deny-authority")
            .env("MCLOVING_AGENT_ORGANIZATION_ID", self.org.to_string())
            .env(
                "MCLOVING_CONTROLLER_URI",
                format!("https://127.0.0.1:{}", self.agent_port),
            )
            .env("MCLOVING_CONTROLLER_DNS_NAME", "controller.internal")
            .env("MCLOVING_CONTROLLER_CA_PATH", &self.tls.ca_certificate)
            .env(
                "MCLOVING_AGENT_CERTIFICATE_PATH",
                &self.tls.agent_certificate,
            )
            .env("MCLOVING_AGENT_PRIVATE_KEY_PATH", &self.tls.agent_key)
            .env(
                "MCLOVING_AGENT_JOURNAL_PATH",
                self.root.path().join("agent.db"),
            )
            .env(
                "MCLOVING_AGENT_WORKSPACE_ROOT",
                self.root.path().join("workspace"),
            )
            .env("MCLOVING_AGENT_LEASE_SECONDS", "5")
            .env("MCLOVING_AGENT_POLL_MILLISECONDS", "10")
            .env("MCLOVING_AGENT_RENEW_MILLISECONDS", "100")
            .env("MCLOVING_AGENT_TERMINATION_GRACE_MILLISECONDS", "100")
            .kill_on_drop(true);
        command
    }
    async fn admit(&self, scripts: &[String]) -> (SequentialDagBuild, DagAdmission) {
        assert_eq!(scripts.len(), 4);
        let pipeline_id = Uuid::new_v4();
        let source = json!({"version":1, "name":"contained-sequential", "stages": (0..2).map(|stage| json!({
            "id":format!("stage-{stage}"), "name":format!("Stage {stage}"),
            "steps":scripts[stage*2..stage*2+2].iter().map(|script|json!({"process":{"program":"/bin/sh","args":["-xe","-c",script]}})).collect::<Vec<_>>()
        })).collect::<Vec<_>>()}).to_string();
        let ir = compile_strict_yaml(
            "saved:contained-sequential",
            &source,
            ParseLimits::default(),
        )
        .unwrap();
        self.store
            .put_pipeline(
                &PipelineWrite {
                    organization_id: self.org,
                    project_id: self.project,
                    pipeline_id,
                    slug: format!("sequential-{pipeline_id}"),
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
        // Recompile the actual saved revision, never a parallel hand-authored DAG.
        let saved = self
            .store
            .pipeline(self.org, self.project, pipeline_id)
            .await
            .unwrap()
            .unwrap();
        println!(
            "sequential-source {}",
            json!({"organization_id": self.org, "project_id": self.project,
            "pipeline_id": pipeline_id, "revision": saved.revision, "source": saved.source,
            "source_sha256": hex(&Sha256::digest(saved.source.as_bytes())), "semantic_digest": hex(&saved.semantic_digest)})
        );
        let ir = compile_strict_yaml(
            "saved:contained-sequential",
            &saved.source,
            ParseLimits::default(),
        )
        .unwrap();
        let plan = plan_sequential_build(
            &ir,
            SequentialBuildBinding {
                organization_id: self.org,
                project_id: self.project,
                pipeline_id,
                pipeline_revision: saved.revision,
                pipeline_operational_generation: saved.operational_generation,
                idempotency_key: format!("sequential-{pipeline_id}"),
            },
        )
        .unwrap();
        let admission = self.store.admit_sequential_dag(&plan).await.unwrap();
        (plan, admission)
    }
    async fn result(&self, build: Uuid) -> SequentialBuildResult {
        self.store
            .sequential_build_result(self.org, self.project, build, 100)
            .await
            .unwrap()
            .unwrap()
    }
    async fn terminal(&self, build: Uuid) -> SequentialBuildResult {
        let result = tokio::time::timeout(Duration::from_secs(45), async {
            loop {
                let result = self.result(build).await;
                if matches!(
                    result.status.as_str(),
                    "succeeded" | "failed" | "aborted" | "reconciliation_required"
                ) {
                    break result;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("sequential build reaches bounded durable result");
        println!(
            "sequential-result {}",
            serde_json::to_string(&result).unwrap()
        );
        result
    }
    async fn stdout(&self, attempt: Uuid) -> String {
        let chunks = sqlx::query_scalar::<_,Vec<u8>>("SELECT content FROM attempt_log_chunks WHERE organization_id=$1 AND attempt_id=$2 AND stream='stdout' ORDER BY sequence")
            .bind(self.org).bind(attempt).fetch_all(self.store.pool()).await.unwrap();
        let stdout = String::from_utf8(chunks.concat()).unwrap();
        println!(
            "sequential-stdout {}",
            json!({"attempt_id": attempt, "stdout": stdout})
        );
        stdout
    }
    async fn process_started(&self) {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if contains_marker(&self.root.path().join("workspace"), "process-started") {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("actual shell created its private process-start marker");
    }
    async fn stop(mut self, mut agent: Option<Child>) {
        if let Some(agent) = agent.as_mut() {
            let _ = agent.kill().await;
            let _ = agent.wait().await;
        }
        let _ = self.controller.kill().await;
        let _ = self.controller.wait().await;
    }
}

fn controller_command(
    migration_url: &str,
    runtime_url: &str,
    org: Uuid,
    root: &Path,
    tls: &MtlsFiles,
    api_port: u16,
    agent_port: u16,
) -> Command {
    let mut command = Command::new(
        std::env::var_os("MCLOVING_CONTROLLER_BINARY").expect("shipped controller binary required"),
    );
    command
        .env("MCLOVING_MIGRATION_DATABASE_URL", migration_url)
        .env("MCLOVING_DATABASE_URL", runtime_url)
        .env("MCLOVING_API_TOKEN", TOKEN)
        .env(
            "MCLOVING_ARTIFACT_AGENT_TOKEN",
            "sequential-artifact-token-32-bytes",
        )
        .env("MCLOVING_LISTEN", format!("127.0.0.1:{api_port}"))
        .env("MCLOVING_AGENT_LISTEN", format!("127.0.0.1:{agent_port}"))
        .env("MCLOVING_AGENT_SERVER_CERT_PATH", &tls.server_certificate)
        .env("MCLOVING_AGENT_SERVER_KEY_PATH", &tls.server_key)
        .env("MCLOVING_AGENT_CLIENT_CA_PATH", &tls.ca_certificate)
        .env("MCLOVING_AGENT_IDENTITY_BINDINGS_PATH", &tls.bindings)
        .env("MCLOVING_ORGANIZATION_ID", org.to_string())
        .env("MCLOVING_AGENT_ID", "sequential-embedded-disabled")
        .env("MCLOVING_AGENT_CAPABILITIES", "disabled")
        .env("MCLOVING_AGENT_TRUST_POOL", "migration-deny-authority")
        .env("MCLOVING_LEASE_SECONDS", "5")
        .env("MCLOVING_POLL_MILLISECONDS", "10")
        .env("MCLOVING_CANCELLATION_POLL_MILLISECONDS", "50")
        .env("MCLOVING_TERMINATION_GRACE_MILLISECONDS", "100")
        .env("MCLOVING_SESSION_EPOCH", "1")
        .env("MCLOVING_WORKSPACE_ROOT", root.join("embedded-workspace"))
        .env("MCLOVING_AGENT_JOURNAL", root.join("embedded.db"))
        .env("MCLOVING_OBJECT_ROOT", root.join("objects"))
        .kill_on_drop(true);
    command
}
fn scripts(failure: Option<usize>) -> Vec<String> {
    (0..4)
        .map(|index| {
            format!(
                "printf 'seq-step-{index}:%s\\n' \"$$\"; {}",
                if failure == Some(index) {
                    "exit 7"
                } else {
                    ":"
                }
            )
        })
        .collect()
}
fn contains_marker(root: &Path, name: &str) -> bool {
    let Ok(entries) = std::fs::read_dir(root) else {
        return false;
    };
    entries.filter_map(Result::ok).any(|entry| {
        let path = entry.path();
        path.file_name().is_some_and(|value| value == name)
            || (path.is_dir() && contains_marker(&path, name))
    })
}

#[tokio::test]
async fn fresh_shells_order_and_distinct_step_results() {
    let Some(h) = Harness::new().await else {
        return;
    };
    let mut input = scripts(None);
    input[0].push_str("; export MCLOVING_SEQUENTIAL_LOCAL=changed; cd /");
    input[1].push_str("; test -z \"${MCLOVING_SEQUENTIAL_LOCAL:-}\"; test \"$PWD\" != /");
    let (plan, admission) = h.admit(&input).await;
    let agent = h.agent().spawn().unwrap();
    let result = h.terminal(admission.build_id).await;
    assert_eq!(result.status, "succeeded");
    let mut pids = BTreeSet::new();
    let mut previous_completed = None;
    for (index, step) in result
        .stages
        .iter()
        .flat_map(|stage| &stage.steps)
        .enumerate()
    {
        assert_eq!(step.status, "succeeded");
        assert_eq!(step.attempts.len(), 1);
        let attempt = &step.attempts[0];
        let stdout = h.stdout(attempt.accounting.attempt_id).await;
        let expected = format!("seq-step-{index}:");
        assert_eq!(stdout.lines().count(), 1);
        assert!(stdout.starts_with(&expected), "{stdout:?}");
        let pid = stdout
            .trim()
            .strip_prefix(&expected)
            .unwrap()
            .parse::<u32>()
            .unwrap();
        assert!(pid > 0 && pids.insert(pid));
        assert!(!attempt.logs.is_empty());
        let started = attempt.accounting.started_at_unix_ms.unwrap();
        if let Some(completed) = previous_completed {
            assert!(started >= completed);
        }
        previous_completed = attempt.accounting.completed_at_unix_ms;
    }
    assert_eq!(
        h.store.admit_sequential_dag(&plan).await.unwrap().nodes,
        admission.nodes
    );
    println!("sequential-runtime-evidence fresh_shells=4 ordered_steps=4 build=succeeded");
    h.stop(Some(agent)).await;
}

#[tokio::test]
async fn first_middle_last_failures_skip_downstream_without_process_evidence() {
    let Some(h) = Harness::new().await else {
        return;
    };
    let agent = h.agent().spawn().unwrap();
    for failed in [0, 1, 3] {
        let (_, admission) = h.admit(&scripts(Some(failed))).await;
        let result = h.terminal(admission.build_id).await;
        assert_eq!(result.status, "failed");
        for (index, step) in result
            .stages
            .iter()
            .flat_map(|stage| &stage.steps)
            .enumerate()
        {
            let expected = if index < failed {
                "succeeded"
            } else if index == failed {
                "failed"
            } else {
                "skipped"
            };
            assert_eq!(step.status, expected);
            let attempt = &step.attempts[0];
            let stdout = h.stdout(attempt.accounting.attempt_id).await;
            if index > failed {
                assert!(
                    attempt
                        .accounting
                        .terminal_summary
                        .as_ref()
                        .and_then(|value| value.get("exit_code"))
                        .is_none()
                );
                assert!(stdout.is_empty());
                assert!(attempt.logs.is_empty());
                assert!(attempt.accounting.started_at_unix_ms.is_none());
                assert_eq!(attempt.accounting.status, "aborted");
            } else {
                assert_eq!(
                    attempt.accounting.terminal_summary.as_ref().unwrap()["exit_code"],
                    if index == failed { 7 } else { 0 }
                );
                assert!(stdout.starts_with(&format!("seq-step-{index}:")));
                assert_eq!(stdout.lines().count(), 1);
            }
        }
        println!(
            "sequential-runtime-evidence failure_index={failed} downstream_skipped={} build=failed",
            3 - failed
        );
    }
    h.stop(Some(agent)).await;
}

#[tokio::test]
async fn owner_cancellation_before_start_and_during_actual_process() {
    let Some(h) = Harness::new().await else {
        return;
    };
    let (_, before) = h.admit(&scripts(None)).await;
    assert!(
        h.store
            .request_cancellation(h.org, h.project, before.build_id)
            .await
            .unwrap()
    );
    let result = h.terminal(before.build_id).await;
    assert_eq!(result.status, "aborted");
    assert!(
        result
            .stages
            .iter()
            .flat_map(|stage| &stage.steps)
            .all(|step| step.status == "aborted"
                && step.attempts[0].logs.is_empty()
                && step.attempts[0].accounting.started_at_unix_ms.is_none())
    );
    // Establish an earlier valid session before the actual worker enrolls again.
    let probe = tokio::time::timeout(Duration::from_secs(15), h.agent().arg("probe").status())
        .await
        .unwrap()
        .unwrap();
    assert!(probe.success());
    let mut input = scripts(None);
    input[0].push_str("; printf started > process-started; sleep 30");
    let (_, active) = h.admit(&input).await;
    let agent = h.agent().spawn().unwrap();
    h.process_started().await;
    let result = h.result(active.build_id).await;
    let attempt = &result.stages[0].steps[0].attempts[0].accounting;
    let restore: i64 = sqlx::query_scalar("SELECT restore_epoch FROM attempts WHERE id=$1")
        .bind(attempt.attempt_id)
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    let session = h
        .store
        .agent_session_epoch(&h.agent_id)
        .await
        .unwrap()
        .unwrap();
    assert!(session > 1);
    for (fence, epoch, session) in [
        (attempt.fence + 1, restore, session),
        (attempt.fence, restore + 1, session),
        (attempt.fence, restore, session - 1),
    ] {
        assert!(
            !h.store
                .finalize_attempt_in_session(
                    h.org,
                    attempt.attempt_id,
                    fence,
                    epoch,
                    &h.agent_id,
                    session,
                    TerminalOutcome::Succeeded,
                    json!({})
                )
                .await
                .unwrap()
        );
    }
    assert!(
        h.store
            .request_cancellation(h.org, h.project, active.build_id)
            .await
            .unwrap()
    );
    let result = h.terminal(active.build_id).await;
    assert_eq!(result.status, "aborted");
    assert!(
        result
            .stages
            .iter()
            .flat_map(|stage| &stage.steps)
            .all(|step| step.status == "aborted")
    );
    for step in result.stages.iter().flat_map(|stage| &stage.steps).skip(1) {
        assert!(step.attempts[0].logs.is_empty());
        assert!(step.attempts[0].accounting.started_at_unix_ms.is_none());
    }
    println!(
        "sequential-runtime-evidence cancellation=prestart,active stale_refusals=fence,restore,session"
    );
    h.stop(Some(agent)).await;
}

#[tokio::test]
async fn terminal_commit_crash_replay_runs_each_process_once() {
    let Some(h) = Harness::new().await else {
        return;
    };
    let (plan, admission) = h.admit(&scripts(None)).await;
    let mut agent = h
        .agent()
        .env("MCLOVING_TEST_CRASH_AFTER_TERMINAL_COMMIT", "1")
        .spawn()
        .unwrap();
    let exit = tokio::time::timeout(Duration::from_secs(20), agent.wait())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(exit.code(), Some(86));
    let mut agent = h.agent().spawn().unwrap();
    let result = h.terminal(admission.build_id).await;
    assert_eq!(result.status, "succeeded");
    for (index, step) in result
        .stages
        .iter()
        .flat_map(|stage| &stage.steps)
        .enumerate()
    {
        assert_eq!(step.attempts.len(), 1);
        let stdout = h.stdout(step.attempts[0].accounting.attempt_id).await;
        assert_eq!(stdout.lines().count(), 1);
        assert!(stdout.starts_with(&format!("seq-step-{index}:")));
    }
    assert_eq!(
        h.store.admit_sequential_dag(&plan).await.unwrap().nodes,
        admission.nodes
    );
    let _ = agent.kill().await;
    let _ = agent.wait().await;
    println!(
        "sequential-runtime-evidence terminal_commit_crash=recovered process_outputs=4 duplicates=0"
    );
    h.stop(None).await;
}

#[tokio::test]
async fn lease_loss_cannot_advance_the_sequential_chain() {
    let Some(mut h) = Harness::new().await else {
        return;
    };
    let mut input = scripts(None);
    input[0]
        .push_str("; printf started > process-started; sleep 10; printf survived > lease-survived");
    let (_, admission) = h.admit(&input).await;
    let agent = h.agent().spawn().unwrap();
    h.process_started().await;
    h.controller.kill().await.unwrap();
    h.controller.wait().await.unwrap();
    // Existing lease deadline is five seconds; the shell's later marker must not execute.
    tokio::time::sleep(Duration::from_secs(12)).await;
    h.controller = controller_command(
        &h.migration_url,
        &h.runtime_url,
        h.org,
        h.root.path(),
        &h.tls,
        h.api_port,
        h.agent_port,
    )
    .spawn()
    .unwrap();
    h.ready().await;
    let result = h.terminal(admission.build_id).await;
    assert!(matches!(
        result.status.as_str(),
        "aborted" | "failed" | "reconciliation_required"
    ));
    assert!(!contains_marker(
        &h.root.path().join("workspace"),
        "lease-survived"
    ));
    assert_eq!(result.stages[0].steps[0].attempts.len(), 1);
    assert_eq!(result.stages[0].steps[0].attempts[0].accounting.fence, 1);
    for step in result.stages.iter().flat_map(|stage| &stage.steps).skip(1) {
        assert_ne!(step.status, "succeeded");
        assert!(
            step.attempts
                .iter()
                .all(|attempt| attempt.accounting.started_at_unix_ms.is_none()
                    && attempt.logs.is_empty())
        );
    }
    println!(
        "sequential-runtime-evidence lease_loss={} successor_processes=0",
        result.status
    );
    h.stop(Some(agent)).await;
}

#[tokio::test]
async fn authorized_retry_reexecutes_only_the_failed_step_and_preserves_history() {
    let Some(h) = Harness::new().await else {
        return;
    };
    let (plan, admission) = h.admit(&scripts(Some(1))).await;
    let agent = h.agent().spawn().unwrap();
    let failed = h.terminal(admission.build_id).await;
    assert_eq!(failed.status, "failed");
    let original = failed.stages[0].steps[1].attempts[0].accounting.attempt_id;
    assert!(matches!(
        h.store
            .schedule_retry(h.org, original, 2, "contained runtime retry")
            .await
            .unwrap(),
        mcloving_controller_store::RetryDecision::Scheduled { .. }
    ));
    let repeated = h.terminal(admission.build_id).await;
    assert_eq!(repeated.status, "failed");
    assert_eq!(repeated.stages[0].steps[0].attempts.len(), 1);
    assert_eq!(repeated.stages[0].steps[1].attempts.len(), 2);
    for attempt in &repeated.stages[0].steps[1].attempts {
        assert_eq!(attempt.accounting.status, "failed");
        let stdout = h.stdout(attempt.accounting.attempt_id).await;
        assert_eq!(stdout.lines().count(), 1);
        assert!(stdout.starts_with("seq-step-1:"));
    }
    for step in &repeated.stages[1].steps {
        assert_eq!(step.status, "skipped");
        assert_eq!(step.attempts.len(), 2);
        assert!(
            step.attempts.iter().all(|attempt| attempt.logs.is_empty()
                && attempt.accounting.started_at_unix_ms.is_none())
        );
    }
    assert_eq!(
        h.store.admit_sequential_dag(&plan).await.unwrap().nodes,
        admission.nodes
    );
    println!(
        "sequential-runtime-evidence authorized_retry=failed_step_only original_admission=preserved"
    );
    h.stop(Some(agent)).await;
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
            "{} {agent_id} migration-deny-authority {organization_id}\n",
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
