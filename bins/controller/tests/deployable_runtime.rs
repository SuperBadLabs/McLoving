use std::net::TcpListener;
use std::time::Duration;

use mcloving_controller_api::{ArtifactCommitRequest, Client};
use mcloving_controller_store::Store;
use sqlx::postgres::PgPoolOptions;
use tokio::process::Command;
use uuid::Uuid;

const TOKEN: &str = "mcloving-controller-binary-test-token";
const PIPELINE: &str = r#"
version: 1
name: deployed-controller
stages:
  - id: execute
    name: Execute
    steps:
      - process:
          program: /bin/sh
          args: [-c, "printf 'controller-binary-ran\n'; sleep 2"]
          timeout_seconds: 10
"#;

#[tokio::test]
async fn shipped_controller_uses_split_credentials_and_executes_submissions() {
    let Ok(migration_url) = std::env::var("MCLOVING_TEST_DATABASE_URL") else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let runtime_url =
        migration_url.replacen("postgres://mcloving@", "postgres://mcloving_tenant@", 1);
    assert_ne!(
        migration_url, runtime_url,
        "test URL must use the expected migration role"
    );
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
            &format!("org-{organization_id}"),
            project_id,
            "runtime",
        )
        .await
        .expect("create test project");

    let port = TcpListener::bind("127.0.0.1:0")
        .expect("reserve port")
        .local_addr()
        .expect("read port")
        .port();
    let root = tempfile::tempdir().expect("worker root");
    let artifact_agent_token = "artifact-agent-contract-token-32-bytes";
    let mut controller = Command::new(env!("CARGO_BIN_EXE_mcloving-controller"))
        .env("MCLOVING_MIGRATION_DATABASE_URL", &migration_url)
        .env("MCLOVING_DATABASE_URL", &runtime_url)
        .env("MCLOVING_API_TOKEN", TOKEN)
        .env("MCLOVING_ARTIFACT_AGENT_TOKEN", artifact_agent_token)
        .env("MCLOVING_LISTEN", format!("127.0.0.1:{port}"))
        .env("MCLOVING_ORGANIZATION_ID", organization_id.to_string())
        .env("MCLOVING_AGENT_ID", "embedded-test-agent")
        .env("MCLOVING_AGENT_CAPABILITIES", "platform:windows")
        .env("MCLOVING_AGENT_TRUST_POOL", "trusted-windows")
        .env("MCLOVING_LEASE_SECONDS", "5")
        .env("MCLOVING_POLL_MILLISECONDS", "10")
        .env("MCLOVING_CANCELLATION_POLL_MILLISECONDS", "50")
        .env("MCLOVING_TERMINATION_GRACE_MILLISECONDS", "100")
        .env("MCLOVING_SESSION_EPOCH", "1")
        .env("MCLOVING_WORKSPACE_ROOT", root.path().join("workspace"))
        .env("MCLOVING_AGENT_JOURNAL", root.path().join("agent.db"))
        .env("MCLOVING_OBJECT_ROOT", root.path().join("objects"))
        .env("MCLOVING_STAGED_UPLOAD_TTL_SECONDS", "1")
        .kill_on_drop(true)
        .spawn()
        .expect("start shipped controller");
    let client = Client::new(&format!("http://127.0.0.1:{port}"), TOKEN)
        .with_artifact_agent_token(artifact_agent_token);
    wait_until_listening(&client, organization_id).await;
    let admission = client
        .submit_on_platform_in_pool(
            organization_id,
            project_id,
            "binary-e2e",
            "windows",
            "trusted-windows",
            PIPELINE.to_owned(),
        )
        .await
        .expect("submit through shipped controller");

    let running = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let status = client
                .status(organization_id, project_id, admission.build_id)
                .await
                .expect("read running build status");
            if status.attempt_status == "running" {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("embedded worker enters running state");
    let abandoned = client
        .stage_artifact(
            organization_id,
            project_id,
            admission.build_id,
            "reports/abandoned.bin",
            "application/octet-stream",
            b"abandoned".to_vec(),
        )
        .await
        .expect("stage abandoned artifact through shipped controller");
    let abandoned_path = root
        .path()
        .join("objects")
        .join("staging")
        .join(&abandoned.upload_token);
    assert!(abandoned_path.exists(), "staged upload is durable");
    let abandoned_claim_path =
        abandoned_path.with_file_name(format!("{}.publishing", abandoned.upload_token));
    tokio::fs::rename(&abandoned_path, &abandoned_claim_path)
        .await
        .expect("simulate a crash after publication claim");
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let rejected = client
        .stage_artifact(
            organization_id,
            project_id,
            admission.build_id,
            "reports/rejected.bin",
            "application/octet-stream",
            b"must-not-publish".to_vec(),
        )
        .await
        .expect("stage rejected artifact through shipped controller");
    assert!(
        !abandoned_path.exists() && !abandoned_claim_path.exists(),
        "a later upload must reclaim an expired abandoned publication claim"
    );
    let rejected_commit = ArtifactCommitRequest {
        node_id: admission.node_id,
        attempt_id: admission.attempt_id,
        fence: running.fence + 1,
        restore_epoch: 1,
        agent_id: running.lease_owner.clone().expect("running lease owner"),
        name: rejected.name.clone(),
        media_type: rejected.media_type.clone(),
        sha256: rejected.sha256.clone(),
        bytes: rejected.bytes,
        retention_seconds: 3600,
    };
    assert!(
        client
            .commit_artifact(
                organization_id,
                project_id,
                admission.build_id,
                &rejected.upload_token,
                &rejected_commit,
            )
            .await
            .is_err(),
        "stale authority must be rejected before immutable publication"
    );
    assert!(
        !root
            .path()
            .join("objects")
            .join("staging")
            .join(&rejected.upload_token)
            .exists(),
        "rejected authority must release its staging reservation"
    );
    assert!(
        !root
            .path()
            .join("objects")
            .join("objects")
            .join("sha256")
            .join(&rejected.sha256[..2])
            .join(&rejected.sha256)
            .exists(),
        "rejected authority must not publish immutable bytes"
    );

    let artifact_content = vec![0xA5; 3 * 1024 * 1024];
    let staged = client
        .stage_artifact(
            organization_id,
            project_id,
            admission.build_id,
            "reports/result.bin",
            "application/octet-stream",
            artifact_content.clone(),
        )
        .await
        .expect("configured upload limit must admit artifacts above Axum's 2 MiB default");
    let mut commit = ArtifactCommitRequest {
        node_id: admission.node_id,
        attempt_id: admission.attempt_id,
        fence: running.fence,
        restore_epoch: 1,
        agent_id: running.lease_owner.expect("running lease owner"),
        name: staged.name.clone(),
        media_type: staged.media_type.clone(),
        sha256: "00".repeat(32),
        bytes: staged.bytes,
        retention_seconds: 3600,
    };
    assert!(
        client
            .commit_artifact(
                organization_id,
                project_id,
                admission.build_id,
                &staged.upload_token,
                &commit,
            )
            .await
            .is_err(),
        "digest substitution must not reserve metadata or publish staged bytes"
    );
    commit.sha256.clone_from(&staged.sha256);
    let artifact = client
        .commit_artifact(
            organization_id,
            project_id,
            admission.build_id,
            &staged.upload_token,
            &commit,
        )
        .await
        .expect("commit artifact through shipped controller");
    assert_eq!(artifact.name, "reports/result.bin");
    assert_eq!(
        client
            .artifacts(organization_id, project_id, admission.build_id)
            .await
            .expect("list artifacts"),
        vec![artifact.clone()]
    );
    assert_eq!(
        client
            .artifact_metadata(
                organization_id,
                project_id,
                admission.build_id,
                admission.attempt_id,
                "reports/result.bin",
            )
            .await
            .expect("read artifact metadata"),
        artifact
    );
    assert_eq!(
        client
            .download_artifact(
                organization_id,
                project_id,
                admission.build_id,
                admission.attempt_id,
                "reports/result.bin",
            )
            .await
            .expect("download verified artifact"),
        artifact_content
    );
    let object_path = root
        .path()
        .join("objects")
        .join("objects")
        .join("sha256")
        .join(&staged.sha256[..2])
        .join(&staged.sha256);
    tokio::fs::remove_file(&object_path)
        .await
        .expect("remove immutable object for restore drill");
    tokio::fs::write(&object_path, b"corrupt")
        .await
        .expect("install corrupt object for restore drill");
    assert!(
        client
            .download_artifact(
                organization_id,
                project_id,
                admission.build_id,
                admission.attempt_id,
                "reports/result.bin",
            )
            .await
            .is_err(),
        "verified download must record corrupt restored bytes"
    );
    assert_eq!(
        client
            .artifact_metadata(
                organization_id,
                project_id,
                admission.build_id,
                admission.attempt_id,
                "reports/result.bin",
            )
            .await
            .expect("read corrupt artifact metadata")
            .status,
        "corrupt"
    );
    tokio::fs::remove_file(&object_path)
        .await
        .expect("remove corrupt object");
    tokio::fs::write(&object_path, &artifact_content)
        .await
        .expect("restore exact immutable object bytes");
    assert_eq!(
        client
            .download_artifact(
                organization_id,
                project_id,
                admission.build_id,
                admission.attempt_id,
                "reports/result.bin",
            )
            .await
            .expect("download restored artifact"),
        artifact_content
    );
    assert_eq!(
        client
            .artifact_metadata(
                organization_id,
                project_id,
                admission.build_id,
                admission.attempt_id,
                "reports/result.bin",
            )
            .await
            .expect("read restored artifact metadata")
            .status,
        "available"
    );

    let status = tokio::time::timeout(Duration::from_secs(10), async {
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
    .expect("controller completes build within bound");
    assert_eq!(status.status, "succeeded");
    let logs = client
        .logs(organization_id, project_id, admission.build_id)
        .await
        .expect("read logs");
    assert_eq!(logs[0].text.as_deref(), Some("controller-binary-ran\n"));
    assert_eq!(
        logs[0].content_hex,
        "636f6e74726f6c6c65722d62696e6172792d72616e0a"
    );
    controller.kill().await.expect("stop test controller");
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
