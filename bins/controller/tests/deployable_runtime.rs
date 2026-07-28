use std::net::TcpListener;
use std::time::Duration;

use mcloving_controller_api::Client;
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
          args: [-c, "printf 'controller-binary-ran\n'"]
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
    let mut controller = Command::new(env!("CARGO_BIN_EXE_mcloving-controller"))
        .env("MCLOVING_MIGRATION_DATABASE_URL", &migration_url)
        .env("MCLOVING_DATABASE_URL", &runtime_url)
        .env("MCLOVING_API_TOKEN", TOKEN)
        .env("MCLOVING_LISTEN", format!("127.0.0.1:{port}"))
        .env("MCLOVING_ORGANIZATION_ID", organization_id.to_string())
        .env("MCLOVING_AGENT_ID", "embedded-test-agent")
        .env("MCLOVING_AGENT_CAPABILITIES", "linux")
        .env("MCLOVING_LEASE_SECONDS", "5")
        .env("MCLOVING_POLL_MILLISECONDS", "10")
        .env("MCLOVING_CANCELLATION_POLL_MILLISECONDS", "50")
        .env("MCLOVING_TERMINATION_GRACE_MILLISECONDS", "100")
        .env("MCLOVING_SESSION_EPOCH", "1")
        .env("MCLOVING_WORKSPACE_ROOT", root.path().join("workspace"))
        .env("MCLOVING_AGENT_JOURNAL", root.path().join("agent.db"))
        .kill_on_drop(true)
        .spawn()
        .expect("start shipped controller");
    let client = Client::new(&format!("http://127.0.0.1:{port}"), TOKEN);
    wait_until_listening(&client, organization_id).await;
    let admission = client
        .submit(
            organization_id,
            project_id,
            "binary-e2e",
            PIPELINE.to_owned(),
        )
        .await
        .expect("submit through shipped controller");

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
    assert_eq!(logs[0].text, "controller-binary-ran\n");
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
