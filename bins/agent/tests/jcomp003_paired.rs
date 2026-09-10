//! JCOMP-003 fixed-fixture observer. External containment and frozen inputs are mandatory.
#![cfg(unix)]
use mcloving_controller_api::{
    Client,
    sequential::{SequentialBuildBinding, plan_sequential_build},
};
use mcloving_controller_store::{DagAdmission, PipelineWrite, SequentialBuildResult, Store};
use mcloving_pipeline_ir::{ParseLimits, compile_strict_yaml};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
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
}

impl Harness {
    async fn new() -> Option<Self> {
        let migration_url = std::env::var("MCLOVING_TEST_DATABASE_URL")
            .expect("explicit contained PostgreSQL required");
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
        let mut command =
            Command::new(std::env::var_os("JCOMP_STRACE").expect("independent argv tracer"));
        command
            .args([
                "-f",
                "-qq",
                "-ttt",
                "-s",
                "65536",
                "-xx",
                "-e",
                "trace=execve,exit_group",
                "-o",
            ])
            .arg(self.root.path().join("execve.trace"))
            .arg(env!("CARGO_BIN_EXE_mcloving-agent"))
            .process_group(0);
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

async fn wait_clean(h: &Harness, root: &Path, builds: &[Uuid]) {
    let mut paths = Vec::new();
    for build in builds {
        let attempts = sqlx::query_as::<_, (Uuid, i64, i64)>(
            "SELECT a.id, a.restore_epoch, a.fence FROM attempts a JOIN nodes n ON n.id=a.node_id AND n.organization_id=a.organization_id WHERE a.organization_id=$1 AND n.build_id=$2",
        ).bind(h.org).bind(build).fetch_all(h.store.pool()).await.unwrap();
        for (attempt, restore, fence) in attempts {
            // Match the controller's composite wire authority token.
            let token = (u64::from(u32::try_from(restore).unwrap()) << 32)
                | u64::from(u32::try_from(fence).unwrap());
            paths.push(PathBuf::from(format!("{}/{attempt}/{token}", h.org)));
        }
    }
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let gone = paths.iter().all(|relative| {
                matches!(std::fs::symlink_metadata(root.join(relative)), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
                    && !contains_marker(&root.join(".agent-results").join(relative), "result.json")
            });
            if gone {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("exact attempt workspace and result spool files cleaned");
}

impl Harness {
    async fn admit_compiled(&self, fixture: &serde_json::Value) -> DagAdmission {
        let pipeline_id = Uuid::new_v4();
        let source = fixture["pipeline_yaml"].as_str().unwrap().to_owned();
        assert_eq!(
            hex(&Sha256::digest(source.as_bytes())),
            fixture["receipt"]["pipeline_yaml_sha256"]
        );
        let disabled_definition = fixture["disabled_definition_yaml"].as_str().unwrap();
        assert_eq!(
            hex(&Sha256::digest(disabled_definition.as_bytes())),
            fixture["receipt"]["definition_yaml_sha256"]
        );
        assert!(
            disabled_definition
                .lines()
                .any(|line| line == "state: disabled")
        );
        assert_eq!(fixture["receipt"]["state"], "disabled");
        assert_eq!(fixture["receipt"]["execution_authority"], "false");
        let ir = compile_strict_yaml("contained:compiler-output", &source, ParseLimits::default())
            .unwrap();
        assert_eq!(
            hex(&ir.semantic_digest().unwrap()),
            fixture["receipt"]["semantic_ir_sha256"]
        );
        self.store
            .put_pipeline(
                &PipelineWrite {
                    organization_id: self.org,
                    project_id: self.project,
                    pipeline_id,
                    slug: format!("contained-{pipeline_id}"),
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
        let saved = self
            .store
            .pipeline(self.org, self.project, pipeline_id)
            .await
            .unwrap()
            .unwrap();
        let ir = compile_strict_yaml(
            "saved:contained-compiler-output",
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
                idempotency_key: format!("contained-{pipeline_id}"),
            },
        )
        .unwrap()
        .with_workspace_transfer()
        .unwrap();
        assert_eq!(
            saved.operational_state,
            mcloving_controller_store::PipelineOperationalState::Enabled
        );
        let admitted = self.store.admit_sequential_dag(&plan).await.unwrap();
        println!(
            "jcomp003-submission {}",
            json!({"fixture":fixture["id"], "pipeline_id":pipeline_id,
            "build_id":admitted.build_id,"source":saved.source,"semantic_digest":hex(&saved.semantic_digest),
            "compiler_disabled_definition_sha256":hex(&Sha256::digest(disabled_definition.as_bytes())),
            "compiler_disabled_definition_bytes":disabled_definition,
            "compiler_definition_state":"disabled", "contained_submission_saved_state":saved.operational_state, "submission_authority":"explicit-contained-fixture"})
        );
        admitted
    }
}

#[tokio::test]
#[ignore = "requires the dedicated network-none JCOMP-003 evidence runner"]
async fn fixed_compiler_outputs_on_shipped_controller_and_agent() {
    println!(
        "jcomp003-observer-build-provenance source_head={} source_tree={}",
        env!("MCLOVING_BUILD_SOURCE_HEAD"),
        env!("MCLOVING_BUILD_SOURCE_TREE")
    );
    println!(
        "jcomp003-observer-binary {}",
        hex(&Sha256::digest(
            std::fs::read(std::env::current_exe().unwrap()).unwrap()
        ))
    );
    assert!(std::env::var_os("JCOMP_STEP_SENTINEL").is_none());
    let input = PathBuf::from(std::env::var_os("JCOMP_INPUT").expect("frozen inputs required"));
    let output =
        PathBuf::from(std::env::var_os("JCOMP_OUTPUT").expect("dedicated observations required"));
    std::fs::create_dir(&output).unwrap();
    let input_bytes = std::fs::read(&input).unwrap();
    let fixtures: serde_json::Value = serde_json::from_slice(&input_bytes).unwrap();
    assert_eq!(fixtures["fixtures"].as_array().unwrap().len(), 23);
    let mut h = Harness::new().await.unwrap();
    let mut agent = h.agent().spawn().unwrap();
    let mut builds = Vec::new();
    let mut records = Vec::new();
    let mut namespaces = std::collections::BTreeSet::new();
    for fixture in fixtures["fixtures"].as_array().unwrap() {
        let id = fixture["id"].as_str().unwrap();
        if fixture["receipt"]["status"] != "admitted" {
            let count_before: i64 =
                sqlx::query_scalar("SELECT count(*) FROM nodes WHERE organization_id=$1")
                    .bind(h.org)
                    .fetch_one(h.store.pool())
                    .await
                    .unwrap();
            assert!(fixture.get("pipeline_yaml").is_none());
            assert!(
                fixture["receipt"]["status"] == "rejected"
                    || fixture["receipt"]["status"] == "unsupported"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
            let count_after: i64 =
                sqlx::query_scalar("SELECT count(*) FROM nodes WHERE organization_id=$1")
                    .bind(h.org)
                    .fetch_one(h.store.pool())
                    .await
                    .unwrap();
            assert_eq!(count_before, count_after);
            records.push(json!({"fixture":id,"compilation":fixture["receipt"]["status"],
                "scheduler_nodes_before":count_before,"scheduler_nodes_after":count_after,"scheduled_work":0}));
            continue;
        }
        let admission = h.admit_compiled(fixture).await;
        let result = h.terminal(admission.build_id).await;
        assert!(result.workspace_closed);
        assert!(namespaces.insert(result.workspace_namespace.unwrap()));
        let checkpoint: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT workspace_snapshot FROM builds WHERE organization_id=$1 AND id=$2",
        )
        .bind(h.org)
        .bind(admission.build_id)
        .fetch_one(h.store.pool())
        .await
        .unwrap();
        assert!(checkpoint.is_none());
        let mut logs = Vec::new();
        for stage in &result.stages {
            for step in &stage.steps {
                assert_eq!(step.attempts.len(), 1);
                let attempt = &step.attempts[0];
                let chunks = sqlx::query_as::<_, (i64, i64, String, Vec<u8>, Vec<u8>, i64)>(
                    "SELECT fence,sequence,stream,content,digest,cursor_id FROM attempt_log_chunks WHERE organization_id=$1 AND attempt_id=$2 ORDER BY cursor_id")
                    .bind(h.org).bind(attempt.accounting.attempt_id).fetch_all(h.store.pool()).await.unwrap();
                let chunks = chunks
                    .into_iter()
                    .map(|(fence, sequence, stream, content, digest, cursor_id)| {
                        assert_eq!(digest.as_slice(), Sha256::digest(&content).as_slice());
                        json!({"fence":fence,"sequence":sequence,"stream":stream,"content":content,
                        "digest":hex(&digest),"cursor_id":cursor_id})
                    })
                    .collect::<Vec<_>>();
                if step.status == "skipped" {
                    assert!(chunks.is_empty());
                }
                logs.push(json!({"attempt_id":attempt.accounting.attempt_id,"chunks":chunks}));
            }
        }
        wait_clean(&h, &h.root.path().join("workspace"), &[admission.build_id]).await;
        let record = json!({"fixture":id,"source_sha256":fixture["source_sha256"],"result":result,"logs":logs,
            "checkpoint_raw_bytes_removed":true,"attempt_workspace_cleanup":true});
        std::fs::write(
            output.join(format!("{id}.json")),
            serde_json::to_vec_pretty(&record).unwrap(),
        )
        .unwrap();
        records.push(json!({"fixture":id,"build_id":admission.build_id}));
        builds.push(admission.build_id);
    }
    assert_eq!(builds.len(), 11);
    assert_eq!(namespaces.len(), 11);
    let database_builds: i64 = sqlx::query_scalar("SELECT count(*) FROM builds")
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    let database_nodes: i64 = sqlx::query_scalar("SELECT count(*) FROM nodes")
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    assert_eq!(database_builds, 11);
    assert_eq!(database_nodes, 23);
    wait_clean(&h, &h.root.path().join("workspace"), &builds).await;
    // Kill the observer's private group after all work and cleanup; include the traced agent.
    nix::sys::signal::killpg(
        nix::unistd::Pid::from_raw(i32::try_from(agent.id().unwrap()).unwrap()),
        nix::sys::signal::Signal::SIGTERM,
    )
    .unwrap();
    let _ = agent.wait().await;
    let _ = h.controller.kill().await;
    let _ = h.controller.wait().await;
    std::fs::copy(
        h.root.path().join("execve.trace"),
        output.join("execve.trace"),
    )
    .unwrap();
    std::fs::write(output.join("complete.json"), serde_json::to_vec_pretty(&json!({
        "schema":"mcloving.sequential-product-observations/1","input_sha256":hex(&Sha256::digest(&input_bytes)),
        "records":records,"positive_builds":11,"negative_inputs":12,"distinct_workspace_namespaces":11,
        "observed_database_builds":database_builds,"observed_database_nodes":database_nodes,
        "production_authority":false})).unwrap()).unwrap();
    println!("jcomp003-product-evidence positive_builds=11 negative_inputs=12 cleanup=complete");
}
