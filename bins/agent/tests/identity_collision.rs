//! EXEC-003 gates over the shipped controller and agent binaries:
//!
//! 1. a single agent whose journal lags the controller's durable session
//!    floor (the documented journal-replacement recovery) enrolls without
//!    emitting the stale-epoch retry line;
//! 2. a `reconciliation_required` journal attempt whose fenced authority the
//!    controller disowns is discharged by explicit directive, preserves and
//!    reclaims its evidence, and the agent resumes polling;
//! 3. two executors misconfigured with one agent identity produce named
//!    identity-collision diagnostics on both the controller and agent
//!    streams while every stale-epoch rejection stays fail-closed.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mcloving_agent_runtime::{Acceptance, AttemptPhase, Finalization, Journal, SpoolEntry};
use mcloving_controller_api::{Client, PipelineBuildRequest, PipelineUpsertRequest};
use mcloving_controller_store::Store;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use tokio::process::{Child, Command};
use uuid::Uuid;

const TOKEN: &str = "mcloving-identity-collision-test-token";
const PIPELINE: &str = r#"
version: 1
name: identity-gates
stages:
  - id: execute
    name: Execute
    steps:
      - process:
          program: /bin/sh
          args: [-c, "printf 'identity-gate-ran\n'"]
          timeout_seconds: 10
"#;

#[tokio::test]
async fn identity_collision_is_named_and_recovered_attempts_discharge() {
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
            &format!("identity-org-{organization_id}"),
            project_id,
            "identity-gates",
        )
        .await
        .expect("create test project");

    // agent_sessions is keyed by agent_id across the whole database, so fixed
    // ids leak session epochs from one run into the next (the seeded epoch-7
    // floor below would collide with the epoch 8 a previous run left behind).
    let cold_start_agent_id = format!("exec003-coldstart-agent-{}", Uuid::new_v4());
    let discharge_agent_id = format!("exec003-discharge-agent-{}", Uuid::new_v4());
    let collision_agent_id = format!("exec003-collision-agent-{}", Uuid::new_v4());

    let directory = tempfile::tempdir().expect("test root");
    let tls = create_mtls(
        directory.path(),
        organization_id,
        &[
            cold_start_agent_id.as_str(),
            discharge_agent_id.as_str(),
            collision_agent_id.as_str(),
        ],
    );
    let api_port = free_port();
    let agent_port = free_port();

    let mut controller = Command::new(controller_binary)
        .env("MCLOVING_MIGRATION_DATABASE_URL", &migration_url)
        .env("MCLOVING_DATABASE_URL", &runtime_url)
        .env("MCLOVING_API_TOKEN", TOKEN)
        .env(
            "MCLOVING_ARTIFACT_AGENT_TOKEN",
            "identity-artifact-agent-token-32-byte",
        )
        .env("MCLOVING_LISTEN", format!("127.0.0.1:{api_port}"))
        .env("MCLOVING_AGENT_LISTEN", format!("127.0.0.1:{agent_port}"))
        .env("MCLOVING_AGENT_SERVER_CERT_PATH", &tls.server_certificate)
        .env("MCLOVING_AGENT_SERVER_KEY_PATH", &tls.server_key)
        .env("MCLOVING_AGENT_CLIENT_CA_PATH", &tls.ca_certificate)
        .env("MCLOVING_AGENT_IDENTITY_BINDINGS_PATH", &tls.bindings)
        .env("MCLOVING_ORGANIZATION_ID", organization_id.to_string())
        .env("MCLOVING_AGENT_ID", "exec003-embedded-disabled")
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
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("start shipped controller");
    let controller_stderr = capture_stderr(&mut controller);
    let client = Client::new(&format!("http://127.0.0.1:{api_port}"), TOKEN);
    wait_until_listening(&client, organization_id).await;

    // Gate (c): a documented journal replacement leaves the controller
    // remembering session epoch 7 while the fresh journal restarts at 1. The
    // rejection's epoch floor lets enrollment settle in one silent catch-up
    // instead of a stale-epoch retry storm.
    assert!(
        store
            .open_agent_session(&cold_start_agent_id, "trusted-linux", 7, 0, &[], &[])
            .await
            .expect("seed durable session floor"),
        "seeding the pre-replacement session epoch must succeed"
    );
    let cold_workspace = directory.path().join("coldstart-workspace");
    std::fs::create_dir(&cold_workspace).expect("create cold-start workspace root");
    let cold_journal = directory.path().join("coldstart-agent.db");
    let mut cold_agent = agent_command(
        &cold_start_agent_id,
        organization_id,
        agent_port,
        &tls,
        &cold_journal,
        &cold_workspace,
    )
    .stderr(Stdio::piped())
    .kill_on_drop(true)
    .spawn()
    .expect("start cold-start agent");
    let cold_stderr = capture_stderr(&mut cold_agent);
    let cold_build = submit_build(&client, organization_id, project_id, "coldstart").await;
    let cold_status =
        wait_for_terminal_build(&client, organization_id, project_id, cold_build).await;
    assert_eq!(cold_status.status, "succeeded");
    assert_eq!(
        cold_status.lease_owner.as_deref(),
        Some(cold_start_agent_id.as_str())
    );
    stop(&mut cold_agent).await;
    let cold_log = snapshot(&cold_stderr);
    assert!(
        !cold_log.contains("stale agent session epoch"),
        "cold start must enroll without the stale-epoch retry line: {cold_log}"
    );
    assert!(
        cold_log.contains("advancing agent session epoch to 8"),
        "cold start must catch up past the controller's durable floor: {cold_log}"
    );

    // Gate (b): a journal wrecked into `reconciliation_required` for a fence
    // this controller has disowned (here: unknown to it) is discharged by the
    // explicit directive, its evidence survives the transition and is
    // reclaimed under the existing terminal spool rules, and the agent
    // resumes polling.
    let discharge_workspace = directory.path().join("discharge-workspace");
    std::fs::create_dir(&discharge_workspace).expect("create discharge workspace root");
    let discharge_journal = directory.path().join("discharge-agent.db");
    let orphan_organization = organization_id.to_string();
    let orphan_attempt = Uuid::new_v4().to_string();
    let orphan_workspace = PathBuf::from(format!("{orphan_organization}/{orphan_attempt}/1"));
    let orphan_result = orphan_workspace.join("spool/result.json");
    {
        let mut journal = Journal::open(&discharge_journal).expect("create orphan journal");
        let session_epoch = journal
            .reserve_session_epoch(0)
            .expect("reserve orphan session epoch");
        journal
            .accept(&Acceptance {
                organization_id: orphan_organization.clone(),
                attempt_id: orphan_attempt.clone(),
                fence_token: 1,
                session_epoch,
                payload_digest: [0x33; 32],
                workspace: orphan_workspace.clone(),
            })
            .expect("accept orphan attempt");
        journal
            .transition(
                &orphan_organization,
                &orphan_attempt,
                1,
                session_epoch,
                AttemptPhase::Running,
                None,
            )
            .expect("run orphan attempt");
        let logs = [SpoolEntry {
            sequence: 0,
            relative_path: orphan_workspace.join("spool/stdout.log"),
            digest: [0x44; 32],
            bytes: 6,
        }];
        let result = SpoolEntry {
            sequence: 0,
            relative_path: orphan_result.clone(),
            digest: [0x55; 32],
            bytes: 2,
        };
        journal
            .begin_finalization(&Finalization {
                organization_id: &orphan_organization,
                attempt_id: &orphan_attempt,
                fence_token: 1,
                session_epoch,
                phase: AttemptPhase::Cancelling,
                process_id: None,
                logs: &logs,
                result: &result,
            })
            .expect("record orphan spool evidence");
        journal
            .transition(
                &orphan_organization,
                &orphan_attempt,
                1,
                session_epoch,
                AttemptPhase::ReconciliationRequired,
                None,
            )
            .expect("park orphan attempt");
    }
    let orphan_spool_dir = discharge_workspace.join(&orphan_workspace).join("spool");
    std::fs::create_dir_all(&orphan_spool_dir).expect("create orphan spool directory");
    std::fs::write(orphan_spool_dir.join("stdout.log"), b"orphan").expect("write orphan log");
    std::fs::write(orphan_spool_dir.join("result.json"), b"{}").expect("write orphan result");
    assert_eq!(
        mcloving_agent::journal_health(&discharge_journal)
            .expect("read parked journal")
            .2,
        1,
        "the crafted journal must start with one parked attempt"
    );

    let mut discharge_agent = agent_command(
        &discharge_agent_id,
        organization_id,
        agent_port,
        &tls,
        &discharge_journal,
        &discharge_workspace,
    )
    .stderr(Stdio::piped())
    .kill_on_drop(true)
    .spawn()
    .expect("start discharge agent");
    let discharge_stderr = capture_stderr(&mut discharge_agent);
    wait_for("orphan attempt discharge and spool reclaim", 30, || {
        mcloving_agent::journal_health(&discharge_journal).is_ok_and(|(_, _, active)| active == 0)
            && !discharge_workspace.join(&orphan_workspace).exists()
    })
    .await;
    let discharge_build = submit_build(&client, organization_id, project_id, "discharge").await;
    let discharge_status =
        wait_for_terminal_build(&client, organization_id, project_id, discharge_build).await;
    assert_eq!(discharge_status.status, "succeeded");
    assert_eq!(
        discharge_status.lease_owner.as_deref(),
        Some(discharge_agent_id.as_str()),
        "the agent must resume polling after the discharge"
    );
    stop(&mut discharge_agent).await;
    let discharge_log = snapshot(&discharge_stderr);
    assert!(
        discharge_log.contains("discharged recovered attempt")
            && discharge_log.contains(&orphan_attempt),
        "the discharge must be named on the agent stream: {discharge_log}"
    );
    assert!(
        !discharge_log.contains("unresolved recovered attempt"),
        "a directive-covered recovered attempt must not park the session: {discharge_log}"
    );
    wait_for("controller discharge record", 10, || {
        snapshot(&controller_stderr).contains("authorized discharge of recovered attempt")
    })
    .await;

    // Gate (a): two shipped agents share one identity against one controller.
    // Both sides must name the suspected collision while every stale-epoch
    // rejection keeps refusing work.
    let mut twins = Vec::new();
    let mut twin_logs = Vec::new();
    for twin in ["twin-a", "twin-b"] {
        let workspace = directory.path().join(format!("{twin}-workspace"));
        std::fs::create_dir(&workspace).expect("create twin workspace root");
        let journal = directory.path().join(format!("{twin}-agent.db"));
        let mut agent = agent_command(
            &collision_agent_id,
            organization_id,
            agent_port,
            &tls,
            &journal,
            &workspace,
        )
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("start collision twin");
        twin_logs.push(capture_stderr(&mut agent));
        twins.push(agent);
    }
    wait_for("controller collision diagnostic", 90, || {
        snapshot(&controller_stderr).contains(&format!(
            "agent identity collision suspected for {collision_agent_id}"
        ))
    })
    .await;
    wait_for("agent collision diagnostic", 90, || {
        twin_logs.iter().any(|log| {
            let log = snapshot(log);
            log.contains("agent identity collision suspected")
                && log.contains(collision_agent_id.as_str())
        })
    })
    .await;
    // Fail-closed: the fenced-out twin observed refused authority and ended
    // its session rather than continuing under a stale epoch.
    assert!(
        twin_logs.iter().any(|log| {
            let log = snapshot(log);
            log.contains("agent session ended; retrying")
                && log.contains("stale agent session epoch")
        }),
        "stale-epoch rejections must end the fenced-out session"
    );
    let controller_log = snapshot(&controller_stderr);
    assert!(
        controller_log.contains("session epoch advanced")
            && controller_log.contains("a second executor may be sharing this agent identity"),
        "the controller record must explain the churn: {controller_log}"
    );
    for mut twin in twins {
        stop(&mut twin).await;
    }
    stop(&mut controller).await;
}

async fn submit_build(
    client: &Client,
    organization_id: Uuid,
    project_id: Uuid,
    label: &str,
) -> Uuid {
    let pipeline_id = Uuid::new_v4();
    client
        .put_pipeline(
            organization_id,
            project_id,
            pipeline_id,
            0,
            &PipelineUpsertRequest {
                slug: format!("identity-{label}"),
                source: PIPELINE.to_owned(),
                parameters: Default::default(),
            },
        )
        .await
        .expect("save gate pipeline");
    client
        .submit_pipeline_on_platform_in_pool(
            organization_id,
            project_id,
            pipeline_id,
            &format!("identity-{label}-build"),
            "linux",
            "trusted-linux",
            &PipelineBuildRequest::default(),
        )
        .await
        .expect("submit gate build")
        .build_id
}

async fn wait_for_terminal_build(
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
    .expect("gate build completes within bound")
}

async fn wait_for(label: &str, seconds: u64, mut ready: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(seconds), async {
        loop {
            if ready() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {label}"))
}

fn capture_stderr(child: &mut Child) -> Arc<Mutex<String>> {
    let stderr = child.stderr.take().expect("child stderr is piped");
    let buffer = Arc::new(Mutex::new(String::new()));
    let sink = buffer.clone();
    tokio::spawn(async move {
        use tokio::io::AsyncBufReadExt;
        let mut lines = tokio::io::BufReader::new(stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let mut captured = sink.lock().expect("stderr capture lock");
            captured.push_str(&line);
            captured.push('\n');
        }
    });
    buffer
}

fn snapshot(buffer: &Arc<Mutex<String>>) -> String {
    buffer.lock().expect("stderr capture lock").clone()
}

fn agent_command(
    agent_id: &str,
    organization_id: Uuid,
    agent_port: u16,
    tls: &MtlsFiles,
    journal: &Path,
    workspace: &Path,
) -> Command {
    let identity = tls
        .agents
        .iter()
        .find(|identity| identity.agent_id == agent_id)
        .expect("agent identity was generated");
    let mut command = Command::new(env!("CARGO_BIN_EXE_mcloving-agent"));
    command
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
        .env("MCLOVING_AGENT_CERTIFICATE_PATH", &identity.certificate)
        .env("MCLOVING_AGENT_PRIVATE_KEY_PATH", &identity.key)
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

struct AgentTlsIdentity {
    agent_id: String,
    certificate: PathBuf,
    key: PathBuf,
}

struct MtlsFiles {
    ca_certificate: PathBuf,
    server_certificate: PathBuf,
    server_key: PathBuf,
    bindings: PathBuf,
    agents: Vec<AgentTlsIdentity>,
}

fn create_mtls(root: &Path, organization_id: Uuid, agent_ids: &[&str]) -> MtlsFiles {
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

    let mut bindings_rows = String::new();
    let mut agents = Vec::new();
    for agent_id in agent_ids {
        let agent_key = root.join(format!("{agent_id}-key.pem"));
        let agent_csr = root.join(format!("{agent_id}.csr"));
        let agent_certificate = root.join(format!("{agent_id}.pem"));
        let agent_extensions = root.join(format!("{agent_id}.ext"));
        std::fs::write(&agent_extensions, "extendedKeyUsage=clientAuth\n")
            .expect("write agent extensions");
        let subject = format!("/CN={agent_id}");
        openssl([
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            &subject,
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
        let agent_der = root.join(format!("{agent_id}.der"));
        openssl([
            "x509",
            "-in",
            path(&agent_certificate),
            "-outform",
            "DER",
            "-out",
            path(&agent_der),
        ]);
        let digest: [u8; 32] =
            Sha256::digest(std::fs::read(agent_der).expect("read agent DER")).into();
        bindings_rows.push_str(&format!(
            "{} {agent_id} trusted-linux {organization_id}\n",
            hex(&digest)
        ));
        agents.push(AgentTlsIdentity {
            agent_id: (*agent_id).to_owned(),
            certificate: agent_certificate,
            key: agent_key,
        });
    }
    let bindings = root.join("identity-bindings.txt");
    std::fs::write(&bindings, bindings_rows).expect("write identity bindings");
    MtlsFiles {
        ca_certificate,
        server_certificate,
        server_key,
        bindings,
        agents,
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
