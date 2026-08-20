//! EXEC-004 gates: authority must hold WHILE work happens.
//!
//! Gate one runs a single process step across at least three lease terms on
//! the production remote-agent lane and requires terminal success with the
//! lease renewed concurrently throughout — never a requeue, a silent expiry,
//! or a `reconciliation_required` parking.
//!
//! Gate two DENIES a renewal deliberately while the step is mid-flight and
//! requires the loss to be named on both sides: the agent cancels promptly,
//! records `lease_lost_during_execution` in its durable result and on stderr,
//! the replayed terminal summary carries the same named reason, and the agent
//! resumes claiming later work without a wrecked journal.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::process::Stdio;
use std::time::Duration;

use mcloving_controller_api::{Client, PipelineBuildRequest, PipelineUpsertRequest};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use tokio::process::{Child, Command};
use uuid::Uuid;

const TOKEN: &str = "mcloving-long-step-lease-test-token";

/// One step spanning at least three five-second lease terms.
const LONG_STEP_PIPELINE: &str = r#"
version: 1
name: long-step
stages:
  - id: execute
    name: Execute
    steps:
      - process:
          program: /bin/sh
          args: [-c, "sleep 17; printf 'long-step-ran\n'"]
          timeout_seconds: 60
"#;

/// A step that can only end through cancellation inside the test bound.
const BLOCKED_RENEWAL_PIPELINE: &str = r#"
version: 1
name: blocked-renewal
stages:
  - id: execute
    name: Execute
    steps:
      - process:
          program: /bin/sh
          args: [-c, "sleep 45"]
          timeout_seconds: 55
"#;

const RECOVERY_PROOF_PIPELINE: &str = r#"
version: 1
name: recovery-proof
stages:
  - id: execute
    name: Execute
    steps:
      - process:
          program: /bin/sh
          args: [-c, "printf 'recovered-after-lease-loss\n'"]
          timeout_seconds: 10
"#;

#[tokio::test]
async fn shipped_agent_holds_lease_across_a_step_longer_than_three_lease_terms() {
    let Some(harness) = Harness::from_environment("long-step").await else {
        return;
    };
    let mut controller = harness.spawn_controller("5", None);
    let client = harness.client();
    wait_until_listening(&client, harness.organization_id).await;
    let mut agent = harness
        .agent_command("5")
        .kill_on_drop(true)
        .spawn()
        .expect("start shipped remote agent");

    let admission = harness
        .submit(&client, "long-step-e2e", LONG_STEP_PIPELINE)
        .await;
    let status = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let status = client
                .status(harness.organization_id, harness.project_id, admission)
                .await
                .expect("read build status");
            assert_ne!(
                status.attempt_status.as_str(),
                "reconciliation_required",
                "a step longer than one lease term parked in reconciliation: {status:?}"
            );
            if matches!(status.status.as_str(), "succeeded" | "failed" | "aborted") {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("long-step work completes within bound");
    assert_eq!(
        status.status, "succeeded",
        "long step must succeed under concurrent lease renewal: {status:?}"
    );
    assert_eq!(status.attempt_status, "succeeded");
    assert_eq!(status.lease_owner.as_deref(), Some("long-step-agent"));

    let logs = client
        .logs(harness.organization_id, harness.project_id, admission)
        .await
        .expect("read long-step logs");
    assert!(
        logs.iter()
            .any(|log| log.stream == "stdout" && log.text.as_deref() == Some("long-step-ran\n")),
        "step output must survive the full run: {logs:?}"
    );
    assert_eq!(
        harness.count_events(admission, "attempt.terminal").await,
        1,
        "exactly one logical terminal outcome"
    );
    for silent_expiry in ["attempt.lease_expired", "attempt.lease_renewal_rejected"] {
        assert_eq!(
            harness.count_events(admission, silent_expiry).await,
            0,
            "authority must never waver across the step: unexpected {silent_expiry}"
        );
    }

    stop(&mut agent).await;
    stop(&mut controller).await;
}

#[tokio::test]
async fn deliberately_blocked_renewal_cancels_the_step_with_named_diagnostics() {
    let Some(harness) = Harness::from_environment("blocked-renewal").await else {
        return;
    };
    // Renewal ordinal three — issued while the step is mid-flight — is denied.
    let mut controller = harness.spawn_controller("10", Some("2,1"));
    let client = harness.client();
    wait_until_listening(&client, harness.organization_id).await;
    let stderr_path = harness.directory.path().join("agent-stderr.log");
    let stderr_file = std::fs::File::create(&stderr_path).expect("create agent stderr capture");
    let mut agent = harness
        .agent_command("10")
        .stderr(Stdio::from(stderr_file))
        .kill_on_drop(true)
        .spawn()
        .expect("start shipped remote agent");

    let admission = harness
        .submit(&client, "blocked-renewal-e2e", BLOCKED_RENEWAL_PIPELINE)
        .await;
    let status = tokio::time::timeout(Duration::from_secs(40), async {
        loop {
            let status = client
                .status(harness.organization_id, harness.project_id, admission)
                .await
                .expect("read build status");
            assert_ne!(
                status.attempt_status.as_str(),
                "reconciliation_required",
                "a denied renewal must converge through named cancellation, \
                 not reconciliation parking: {status:?}"
            );
            if matches!(status.status.as_str(), "succeeded" | "failed" | "aborted") {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("denied-renewal work converges within bound");
    assert_eq!(
        status.status, "aborted",
        "a lease lost mid-step must abort, not park or succeed: {status:?}"
    );
    assert_eq!(status.attempt_status, "aborted");

    let summary = sqlx::query(
        "SELECT a.terminal_summary::text AS summary
         FROM attempts AS a
         JOIN nodes AS n ON n.id = a.node_id
         WHERE n.build_id = $1",
    )
    .bind(admission)
    .fetch_one(&harness.pool)
    .await
    .expect("read terminal summary")
    .try_get::<String, _>("summary")
    .expect("terminal summary is recorded");
    assert!(
        summary.contains("lease_lost_during_execution:renewal_rejected"),
        "the controller terminal summary must name the lease loss: {summary}"
    );
    assert_eq!(
        harness.count_events(admission, "attempt.terminal").await,
        1,
        "exactly one logical terminal outcome after lease loss"
    );

    let stderr = std::fs::read_to_string(&stderr_path).expect("read agent stderr capture");
    assert!(
        stderr.contains("lease_lost_during_execution: renewal_rejected"),
        "the agent must name the renewal denial on its diagnostic stream: {stderr}"
    );

    // The rejection window is exhausted; the same agent process must claim
    // and complete later work — a lost lease never wrecks the journal.
    let recovery = harness
        .submit(&client, "recovery-proof-e2e", RECOVERY_PROOF_PIPELINE)
        .await;
    let recovered = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let status = client
                .status(harness.organization_id, harness.project_id, recovery)
                .await
                .expect("read recovery build status");
            if matches!(status.status.as_str(), "succeeded" | "failed" | "aborted") {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("post-loss work completes within bound");
    assert_eq!(
        recovered.status, "succeeded",
        "the agent must keep working after a named lease loss: {recovered:?}"
    );

    stop(&mut agent).await;
    stop(&mut controller).await;
}

struct Harness {
    agent_id: String,
    pool: PgPool,
    migration_url: String,
    runtime_url: String,
    controller_binary: PathBuf,
    organization_id: Uuid,
    project_id: Uuid,
    directory: tempfile::TempDir,
    tls: MtlsFiles,
    api_port: u16,
    agent_port: u16,
    workspace: PathBuf,
    journal: PathBuf,
}

impl Harness {
    async fn from_environment(label: &str) -> Option<Self> {
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
        // Schema installation and the test-only role flip race when both
        // gates set up concurrently against one server; serialize them.
        static SETUP_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
        let setup = SETUP_LOCK.lock().await;
        let store = mcloving_controller_store::Store::new(pool.clone());
        store.migrate().await.expect("install schema");
        sqlx::query("ALTER ROLE mcloving_tenant LOGIN")
            .execute(&pool)
            .await
            .expect("enable test-only runtime login");
        drop(setup);
        let organization_id = Uuid::new_v4();
        let project_id = Uuid::new_v4();
        store
            .create_project(
                organization_id,
                &format!("{label}-org-{organization_id}"),
                project_id,
                label,
            )
            .await
            .expect("create test project");

        let directory = tempfile::tempdir().expect("test root");
        let agent_id = format!("{label}-agent");
        let tls = create_mtls(directory.path(), organization_id, &agent_id);
        let workspace = directory.path().join("workspace");
        std::fs::create_dir(&workspace).expect("create remote workspace root");
        Some(Self {
            agent_id,
            pool,
            migration_url,
            runtime_url,
            controller_binary,
            organization_id,
            project_id,
            journal: directory.path().join("remote-agent.db"),
            api_port: free_port(),
            agent_port: free_port(),
            workspace,
            directory,
            tls,
        })
    }

    fn client(&self) -> Client {
        Client::new(&format!("http://127.0.0.1:{}", self.api_port), TOKEN)
    }

    fn spawn_controller(&self, lease_seconds: &str, reject_renewals: Option<&str>) -> Child {
        let mut command = Command::new(&self.controller_binary);
        command
            .env("MCLOVING_MIGRATION_DATABASE_URL", &self.migration_url)
            .env("MCLOVING_DATABASE_URL", &self.runtime_url)
            .env("MCLOVING_API_TOKEN", TOKEN)
            .env(
                "MCLOVING_ARTIFACT_AGENT_TOKEN",
                "long-step-artifact-agent-token-32b",
            )
            .env("MCLOVING_LISTEN", format!("127.0.0.1:{}", self.api_port))
            .env(
                "MCLOVING_AGENT_LISTEN",
                format!("127.0.0.1:{}", self.agent_port),
            )
            .env(
                "MCLOVING_AGENT_SERVER_CERT_PATH",
                &self.tls.server_certificate,
            )
            .env("MCLOVING_AGENT_SERVER_KEY_PATH", &self.tls.server_key)
            .env("MCLOVING_AGENT_CLIENT_CA_PATH", &self.tls.ca_certificate)
            .env("MCLOVING_AGENT_IDENTITY_BINDINGS_PATH", &self.tls.bindings)
            .env("MCLOVING_ORGANIZATION_ID", self.organization_id.to_string())
            .env("MCLOVING_AGENT_ID", "embedded-disabled")
            .env("MCLOVING_AGENT_CAPABILITIES", "disabled")
            .env("MCLOVING_AGENT_TRUST_POOL", "trusted-linux")
            .env("MCLOVING_LEASE_SECONDS", lease_seconds)
            .env("MCLOVING_POLL_MILLISECONDS", "10")
            .env("MCLOVING_CANCELLATION_POLL_MILLISECONDS", "50")
            .env("MCLOVING_TERMINATION_GRACE_MILLISECONDS", "100")
            .env("MCLOVING_SESSION_EPOCH", "1")
            .env(
                "MCLOVING_WORKSPACE_ROOT",
                self.directory.path().join("embedded-workspace"),
            )
            .env(
                "MCLOVING_AGENT_JOURNAL",
                self.directory.path().join("embedded-agent.db"),
            )
            .env(
                "MCLOVING_OBJECT_ROOT",
                self.directory.path().join("embedded-objects"),
            )
            .kill_on_drop(true);
        if let Some(window) = reject_renewals {
            command.env("MCLOVING_TEST_REJECT_RENEWALS", window);
        }
        command.spawn().expect("start shipped controller")
    }

    fn agent_command(&self, lease_seconds: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_mcloving-agent"));
        command
            .env("MCLOVING_AGENT_ID", &self.agent_id)
            .env("MCLOVING_AGENT_TRUST_POOL", "trusted-linux")
            .env(
                "MCLOVING_AGENT_ORGANIZATION_ID",
                self.organization_id.to_string(),
            )
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
            .env("MCLOVING_AGENT_JOURNAL_PATH", &self.journal)
            .env("MCLOVING_AGENT_WORKSPACE_ROOT", &self.workspace)
            .env("MCLOVING_AGENT_LEASE_SECONDS", lease_seconds)
            .env("MCLOVING_AGENT_POLL_MILLISECONDS", "10")
            .env("MCLOVING_AGENT_RENEW_MILLISECONDS", "1000")
            .env("MCLOVING_AGENT_TERMINATION_GRACE_MILLISECONDS", "100");
        command
    }

    async fn submit(&self, client: &Client, slug: &str, pipeline: &str) -> Uuid {
        let pipeline_id = Uuid::new_v4();
        client
            .put_pipeline(
                self.organization_id,
                self.project_id,
                pipeline_id,
                0,
                &PipelineUpsertRequest {
                    slug: slug.to_owned(),
                    source: pipeline.to_owned(),
                    parameters: Default::default(),
                },
            )
            .await
            .expect("save test pipeline");
        client
            .submit_pipeline_on_platform_in_pool(
                self.organization_id,
                self.project_id,
                pipeline_id,
                slug,
                "linux",
                "trusted-linux",
                &PipelineBuildRequest::default(),
            )
            .await
            .expect("submit test work")
            .build_id
    }

    async fn count_events(&self, build_id: Uuid, kind: &str) -> i64 {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*)
             FROM build_events
             WHERE organization_id = $1
               AND build_id = $2
               AND kind = $3",
        )
        .bind(self.organization_id)
        .bind(build_id)
        .bind(kind)
        .fetch_one(&self.pool)
        .await
        .expect("count build events")
    }
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
