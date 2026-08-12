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
use sqlx::postgres::PgPoolOptions;
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
    sqlx::query("ALTER ROLE mcloving_tenant LOGIN")
        .execute(&pool)
        .await
        .expect("enable test-only runtime login");
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
    let tls = create_mtls(directory.path(), organization_id);
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
    let mut agent = agent_command(organization_id, agent_port, &tls, &journal, &workspace)
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
        agent_command(organization_id, agent_port, &tls, &journal, &workspace)
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

    let mut agent = agent_command(organization_id, agent_port, &tls, &journal, &workspace)
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
    let mut agent = agent_command(organization_id, agent_port, &tls, &journal, &workspace)
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
    stop(&mut agent).await;
    assert!(
        !directory_contains(directory.path(), secret.as_bytes()),
        "credential escaped into the agent workspace, journal, or result files"
    );
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
    organization_id: Uuid,
    agent_port: u16,
    tls: &MtlsFiles,
    journal: &Path,
    workspace: &Path,
) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mcloving-agent"));
    command
        .env("MCLOVING_AGENT_ID", "remote-test-agent")
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

fn create_mtls(root: &Path, organization_id: Uuid) -> MtlsFiles {
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
        "/CN=remote-test-agent",
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
            "{} remote-test-agent trusted-linux {organization_id}\n",
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
