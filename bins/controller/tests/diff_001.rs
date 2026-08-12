use std::net::TcpListener;
use std::path::Path;
use std::time::Duration;

use mcloving_controller_api::{Client, PipelineBuildRequest, PipelineUpsertRequest};
use mcloving_controller_store::Store;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use tokio::process::Command;
use uuid::Uuid;

const TOKEN: &str = "mcloving-diff-001-controller-token";
const ARTIFACT_TOKEN: &str = "mcloving-diff-001-artifact-token";
const PIPELINE: &str =
    include_str!("../../../migration/mario-jenkins-oracle-228/corpus-v1/compiler-v1/pipeline.yaml");
const SOURCE: &[u8] = include_bytes!(
    "../../../migration/mario-jenkins-oracle-228/corpus-v1/sources/cinqict_jenkinsdev.Jenkinsfile"
);
const SOURCE_SHA256: &str = "666ac2275ea75730e27cf7b565d757691b094c508355adc0199d745278a23100";
const PIPELINE_SHA256: &str = "551d489ca13bf5d130bdc5c10ce35e5d3d988bdaa1c5488dd9bc79b30674acdc";

#[tokio::test]
async fn admitted_jenkins_case_executes_with_a_canonical_trace() {
    let Ok(migration_url) = std::env::var("MCLOVING_TEST_DATABASE_URL") else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    assert_eq!(hex(&Sha256::digest(SOURCE)), SOURCE_SHA256);
    assert_eq!(hex(&Sha256::digest(PIPELINE.as_bytes())), PIPELINE_SHA256);
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
            &format!("diff-001-{organization_id}"),
            project_id,
            "native-semantics",
        )
        .await
        .expect("create isolated project");

    let port = TcpListener::bind("127.0.0.1:0")
        .expect("reserve port")
        .local_addr()
        .expect("read port")
        .port();
    let root = tempfile::tempdir().expect("isolated worker root");
    let workspace = root.path().join("workspace");
    let mut controller = Command::new(env!("CARGO_BIN_EXE_mcloving-controller"))
        .env("MCLOVING_MIGRATION_DATABASE_URL", &migration_url)
        .env("MCLOVING_DATABASE_URL", &runtime_url)
        .env("MCLOVING_API_TOKEN", TOKEN)
        .env("MCLOVING_ARTIFACT_AGENT_TOKEN", ARTIFACT_TOKEN)
        .env("MCLOVING_LISTEN", format!("127.0.0.1:{port}"))
        .env("MCLOVING_ORGANIZATION_ID", organization_id.to_string())
        .env("MCLOVING_AGENT_ID", "diff-001-agent")
        .env("MCLOVING_AGENT_CAPABILITIES", "platform:linux")
        .env("MCLOVING_AGENT_TRUST_POOL", "migration-deny-authority")
        .env("MCLOVING_LEASE_SECONDS", "5")
        .env("MCLOVING_POLL_MILLISECONDS", "10")
        .env("MCLOVING_CANCELLATION_POLL_MILLISECONDS", "25")
        .env("MCLOVING_TERMINATION_GRACE_MILLISECONDS", "100")
        .env("MCLOVING_SESSION_EPOCH", "1")
        .env("MCLOVING_WORKSPACE_ROOT", &workspace)
        .env("MCLOVING_AGENT_JOURNAL", root.path().join("agent.db"))
        .env("MCLOVING_OBJECT_ROOT", root.path().join("objects"))
        .kill_on_drop(true)
        .spawn()
        .expect("start shipped controller");

    let client = Client::new(&format!("http://127.0.0.1:{port}"), TOKEN)
        .with_artifact_agent_token(ARTIFACT_TOKEN);
    wait_until_listening(&client, organization_id).await;
    let pipeline_id = Uuid::new_v4();
    client
        .put_pipeline(
            organization_id,
            project_id,
            pipeline_id,
            0,
            &PipelineUpsertRequest {
                slug: "diff-001-admitted".to_owned(),
                source: PIPELINE.to_owned(),
                parameters: Default::default(),
            },
        )
        .await
        .expect("save exact compiled pipeline");
    let admission = client
        .submit_pipeline_on_platform_in_pool(
            organization_id,
            project_id,
            pipeline_id,
            "diff-001-admitted",
            "linux",
            "migration-deny-authority",
            &PipelineBuildRequest::default(),
        )
        .await
        .expect("submit exact compiled pipeline");
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
    .expect("exact admitted build completes within bound");
    let graph = client
        .build_graph(organization_id, project_id, admission.build_id)
        .await
        .expect("read build graph");
    let logs = client
        .logs(organization_id, project_id, admission.build_id)
        .await
        .expect("read exact logs");
    let artifacts = client
        .artifacts(organization_id, project_id, admission.build_id)
        .await
        .expect("read artifacts");
    let tests = client
        .test_reports(organization_id, project_id, admission.build_id)
        .await
        .expect("read test reports");
    let approvals = client
        .approvals(organization_id, project_id, admission.build_id)
        .await
        .expect("read approvals");
    let grants = client
        .credential_grants(organization_id, project_id, admission.build_id)
        .await
        .expect("read credential grants");

    assert_eq!(status.status, "succeeded");
    assert_eq!(status.attempt_status, "succeeded");
    assert_eq!(graph.nodes.len(), 1);
    assert_eq!(graph.attempts.len(), 1);
    assert!(graph.dependencies.is_empty());
    assert_eq!(graph.nodes[0].node_key, "build");
    assert_eq!(graph.nodes[0].status, "succeeded");
    assert_eq!(graph.attempts[0].ordinal, 1);
    assert_eq!(graph.attempts[0].status, "succeeded");
    assert!(
        logs.iter()
            .any(|log| { log.stream == "stdout" && log.content_hex == "48656c6c6f20576f726c640a" }),
        "stdout must contain the admitted semantic output"
    );
    assert!(artifacts.is_empty());
    assert!(tests.is_empty());
    assert!(approvals.is_empty());
    assert!(grants.is_empty());
    let workspace_entries = count_user_workspace_entries(
        &workspace,
        organization_id,
        admission.attempt_id,
        status.fence,
    );
    assert_eq!(
        workspace_entries, 0,
        "the admitted process must not create user-visible workspace entries"
    );

    if let Ok(evidence_dir) = std::env::var("MCLOVING_DIFF001_EVIDENCE_DIR") {
        let raw = json!({
            "admission": admission,
            "status": status,
            "graph": graph,
            "logs": logs,
            "artifacts": artifacts,
            "tests": tests,
            "approvals": approvals,
            "credential_grants": grants,
        });
        write_evidence(Path::new(&evidence_dir), &raw, workspace_entries);
    }
    controller.kill().await.expect("stop test controller");
}

fn write_evidence(root: &Path, raw: &serde_json::Value, workspace_entries: usize) {
    std::fs::create_dir_all(root).expect("create evidence directory");
    std::fs::write(
        root.join("mcloving-raw.json"),
        serde_json::to_vec_pretty(&raw).expect("serialize raw evidence"),
    )
    .expect("write raw evidence");
    let trace = json!({
        "schema": "mcloving.jenkins.differential-trace/v1",
        "case": "corpus-052-cinqict_jenkinsdev",
        "source_sha256": SOURCE_SHA256,
        "pipeline_sha256": hex(&Sha256::digest(PIPELINE.as_bytes())),
        "stage_order": ["Build"],
        "process": {
            "program": "/bin/sh",
            "args": ["-xe", "-c", "echo \"Hello World\""]
        },
        "terminal_outcome": "success",
        "semantic_stdout_hex": "48656c6c6f20576f726c640a",
        "attempt_ordinals": [1],
        "workspace_entries": workspace_entries,
        "artifacts": 0,
        "tests": 0,
        "approvals": 0,
        "credential_grants": 0,
        "external_effects": 0
    });
    std::fs::write(
        root.join("mcloving-trace.json"),
        serde_json::to_vec_pretty(&trace).expect("serialize canonical trace"),
    )
    .expect("write canonical trace");
}

fn count_user_workspace_entries(
    root: &Path,
    organization_id: Uuid,
    attempt_id: Uuid,
    fence: i64,
) -> usize {
    let organization = root.join(organization_id.to_string());
    let attempt = organization.join(attempt_id.to_string());
    let execution = attempt.join(format!("1-{fence}"));
    assert_only_child_directory(root, &organization);
    assert_only_child_directory(&organization, &attempt);
    assert_only_child_directory(&attempt, &execution);

    let mut spool_seen = false;
    let count = std::fs::read_dir(&execution)
        .unwrap_or_else(|error| panic!("read execution workspace {}: {error}", execution.display()))
        .map(|entry| entry.expect("read execution workspace entry"))
        .map(|entry| {
            let file_type = entry.file_type().expect("read execution entry type");
            if entry.file_name() == "spool" {
                assert!(file_type.is_dir(), "reserved spool must be a directory");
                spool_seen = true;
                0
            } else {
                1 + count_descendants_without_following(&entry.path(), file_type.is_dir())
            }
        })
        .sum();
    assert!(spool_seen, "reserved spool directory must be present");
    count
}

fn assert_only_child_directory(parent: &Path, expected: &Path) {
    let children = std::fs::read_dir(parent)
        .unwrap_or_else(|error| panic!("read workspace parent {}: {error}", parent.display()))
        .map(|entry| entry.expect("read workspace scaffold"))
        .collect::<Vec<_>>();
    assert_eq!(children.len(), 1, "workspace scaffold is not exact");
    assert_eq!(children[0].path(), expected);
    assert!(
        children[0]
            .file_type()
            .expect("read workspace scaffold type")
            .is_dir(),
        "workspace scaffold must use real directories"
    );
}

fn count_descendants_without_following(path: &Path, is_directory: bool) -> usize {
    if !is_directory {
        return 0;
    }
    std::fs::read_dir(path)
        .unwrap_or_else(|error| panic!("read user workspace {}: {error}", path.display()))
        .map(|entry| entry.expect("read user workspace entry"))
        .map(|entry| {
            let file_type = entry.file_type().expect("read user workspace entry type");
            1 + count_descendants_without_following(&entry.path(), file_type.is_dir())
        })
        .sum()
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
