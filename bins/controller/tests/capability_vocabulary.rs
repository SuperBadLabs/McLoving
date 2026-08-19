//! EXEC-002 gates for the sealed capability vocabulary
//! (docs/architecture/CAPABILITY_VOCABULARY_V1.md).
//!
//! The negative gates run without PostgreSQL: startup classifies
//! `MCLOVING_AGENT_CAPABILITIES` before any database connection, so the
//! measured misconfiguration must exit with its named error unconditionally.
//! The embedded-only execution gate needs `MCLOVING_TEST_DATABASE_URL` and
//! skips silently without it.

use std::net::TcpListener;
use std::time::Duration;

use mcloving_controller_api::{Client, PipelineBuildRequest, PipelineUpsertRequest};
use mcloving_controller_store::Store;
use sqlx::postgres::PgPoolOptions;
use tokio::process::Command;
use uuid::Uuid;

const TOKEN: &str = "mcloving-exec-002-controller-token-32b";
const ARTIFACT_TOKEN: &str = "mcloving-exec-002-artifact-token-32-b";
const PIPELINE: &str = r#"
version: 1
name: default-platform-embedded
stages:
  - id: execute
    name: Execute
    steps:
      - process:
          program: /bin/sh
          args: [-c, "printf 'exec-002-embedded-ran\n'"]
          timeout_seconds: 10
"#;

fn controller_command(capabilities: &str, agent_id: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mcloving-controller"));
    command
        .env(
            "MCLOVING_MIGRATION_DATABASE_URL",
            "postgres://mcloving@127.0.0.1:1/unused",
        )
        .env(
            "MCLOVING_DATABASE_URL",
            "postgres://mcloving_tenant@127.0.0.1:1/unused",
        )
        .env("MCLOVING_API_TOKEN", TOKEN)
        .env("MCLOVING_ARTIFACT_AGENT_TOKEN", ARTIFACT_TOKEN)
        .env("MCLOVING_LISTEN", "127.0.0.1:0")
        .env("MCLOVING_ORGANIZATION_ID", Uuid::new_v4().to_string())
        .env("MCLOVING_AGENT_ID", agent_id)
        .env("MCLOVING_AGENT_CAPABILITIES", capabilities)
        .kill_on_drop(true);
    command
}

async fn assert_startup_rejects(capabilities: &str, named_error: &str) {
    let output = controller_command(capabilities, "exec-002-negative-gate")
        .output()
        .await
        .expect("run controller with rejected capability declaration");
    assert!(
        !output.status.success(),
        "MCLOVING_AGENT_CAPABILITIES={capabilities} must fail startup"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(named_error),
        "startup rejection of {capabilities:?} must name {named_error}; stderr: {stderr}"
    );
    assert!(
        stderr.contains("CAPABILITY_VOCABULARY_V1"),
        "startup rejection must cite the vocabulary document; stderr: {stderr}"
    );
}

/// The measured 2026-08 defect: `MCLOVING_AGENT_CAPABILITIES=linux` queued
/// every default submission forever. It must now be a named startup failure,
/// never a silently inert worker.
#[tokio::test]
async fn measured_misconfiguration_fails_startup_with_named_error() {
    assert_startup_rejects(
        "linux",
        "EmbeddedWorkerCapabilityError::NoSchedulablePlatform",
    )
    .await;
    assert_startup_rejects(
        "platform:macos",
        "EmbeddedWorkerCapabilityError::NoSchedulablePlatform",
    )
    .await;
    assert_startup_rejects(
        "disabled,platform:linux",
        "EmbeddedWorkerCapabilityError::DisableSentinelNotAlone",
    )
    .await;
    assert_startup_rejects(" , ", "EmbeddedWorkerCapabilityError::EmptyDeclaration").await;
}

/// Embedded-only execution: a controller whose embedded worker declares the
/// documented `platform:linux` capability executes a public-API submission
/// that names no platform at all (the `platform:linux` default), with no
/// remote agent transport configured.
#[tokio::test]
async fn embedded_worker_executes_default_platform_submission() {
    let Ok(migration_url) = std::env::var("MCLOVING_TEST_DATABASE_URL") else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let runtime_url =
        migration_url.replacen("postgres://mcloving@", "postgres://mcloving_tenant@", 1);
    assert_ne!(migration_url, runtime_url, "expected split database roles");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&migration_url)
        .await
        .expect("connect migration role");
    let store = Store::new(pool.clone());
    store.migrate().await.expect("install schema");
    sqlx::query("ALTER ROLE mcloving_tenant LOGIN")
        .execute(&pool)
        .await
        .expect("enable test-only runtime login");

    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    store
        .create_project(
            organization_id,
            &format!("exec-002-{organization_id}"),
            project_id,
            "default-platform",
        )
        .await
        .expect("create isolated project");

    let port = TcpListener::bind("127.0.0.1:0")
        .expect("reserve port")
        .local_addr()
        .expect("read port")
        .port();
    let root = tempfile::tempdir().expect("isolated worker root");
    let agent_id = format!("exec-002-embedded-{}", Uuid::new_v4());
    let mut controller = controller_command("platform:linux", &agent_id)
        .env("MCLOVING_MIGRATION_DATABASE_URL", &migration_url)
        .env("MCLOVING_DATABASE_URL", &runtime_url)
        .env("MCLOVING_LISTEN", format!("127.0.0.1:{port}"))
        .env("MCLOVING_ORGANIZATION_ID", organization_id.to_string())
        .env("MCLOVING_AGENT_TRUST_POOL", "trusted-linux")
        .env("MCLOVING_LEASE_SECONDS", "5")
        .env("MCLOVING_POLL_MILLISECONDS", "10")
        .env("MCLOVING_CANCELLATION_POLL_MILLISECONDS", "50")
        .env("MCLOVING_TERMINATION_GRACE_MILLISECONDS", "100")
        .env("MCLOVING_SESSION_EPOCH", "1")
        .env("MCLOVING_WORKSPACE_ROOT", root.path().join("workspace"))
        .env("MCLOVING_AGENT_JOURNAL", root.path().join("agent.db"))
        .env("MCLOVING_OBJECT_ROOT", root.path().join("objects"))
        .spawn()
        .expect("start shipped controller with embedded worker only");

    let client = Client::new(&format!("http://127.0.0.1:{port}"), TOKEN);
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

    let pipeline_id = Uuid::new_v4();
    client
        .put_pipeline(
            organization_id,
            project_id,
            pipeline_id,
            0,
            &PipelineUpsertRequest {
                slug: "exec-002-defaults".to_owned(),
                source: PIPELINE.to_owned(),
                parameters: Default::default(),
            },
        )
        .await
        .expect("save default-platform pipeline");
    let admission = client
        .submit_pipeline_with_defaults(
            organization_id,
            project_id,
            pipeline_id,
            "exec-002-defaults",
            &PipelineBuildRequest::default(),
        )
        .await
        .expect("submit with the default platform and trust pool");

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
    .expect("default-platform submission reaches a terminal state");
    assert_eq!(status.status, "succeeded");
    assert_eq!(status.attempt_status, "succeeded");

    controller.kill().await.expect("stop controller");
}
