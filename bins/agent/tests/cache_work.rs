//! Actual submitted-job cache gate. Helper-library calls and fabricated assignments
//! never serve as positive execution evidence here.
#![cfg(target_os = "linux")]

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use mcloving_agent::cache::{CacheBinding, CacheBindings};
use mcloving_cache::{CacheConfig, CacheKind, CachePolicy};
use mcloving_controller_api::{Client, ClientError, PipelineBuildRequest, PipelineUpsertRequest};
use mcloving_controller_store::Store;
use mcloving_domain::cache_intent::{CacheOperation, CacheWorkContext, cache_assignment_digest};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command as StdCommand, Stdio};
use std::time::Duration;
use tokio::process::{Child, Command};
use uuid::Uuid;

const TOKEN: &str = "contained-cache-product-test-token";
const AGENT: &str = "cache-product-agent";
const OTHER_AGENT: &str = "cache-product-ineligible-agent";
const CONTENT: &[u8] = b"distinctive-cache-content-not-public-result-1957";
const RECEIPT_KEY: &[u8] = b"synthetic-cache-fixture-receipt-key-32-bytes";

struct Harness {
    pool: sqlx::PgPool,
    client: Client,
    org: Uuid,
    project: Uuid,
    pipeline: Uuid,
    revision: i64,
    binding: CacheBinding,
    tls: MtlsFiles,
    other_tls: MtlsFiles,
    other_agent: Option<Child>,
    agent_port: u16,
    controller: Child,
    agent: Option<Child>,
    root: tempfile::TempDir,
}

impl Harness {
    async fn new(migration_url: &str) -> Self {
        // This explicitly supplied fixture URL is never inherited by the agent.
        let controller_binary = PathBuf::from(
            std::env::var_os("MCLOVING_CONTROLLER_BINARY").expect("shipped controller required"),
        );
        let cache_binary = std::fs::canonicalize(
            std::env::var_os("MCLOVING_CACHE_BINARY").expect("shipped cache required"),
        )
        .unwrap();
        let runtime_url =
            migration_url.replacen("postgres://mcloving@", "postgres://mcloving_tenant@", 1);
        assert_ne!(
            runtime_url, migration_url,
            "disposable migration role must be distinct"
        );
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(migration_url)
            .await
            .unwrap();
        let store = Store::new(pool.clone());
        store.migrate().await.unwrap();
        for retry in 0..50 {
            if sqlx::query("ALTER ROLE mcloving_tenant LOGIN")
                .execute(&pool)
                .await
                .is_ok()
            {
                break;
            }
            assert!(retry < 49, "fixture runtime role must be enabled");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let (org, project, pipeline) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        store
            .create_project(org, &format!("cache-{org}"), project, "cache-product")
            .await
            .unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let private = root.path().join("cache-private");
        std::fs::create_dir(&private).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        let executable_sha256 = digest(&std::fs::read(&cache_binary).unwrap());
        let config = CacheConfig {
            protocol_version: "mcloving.cache/v1".into(),
            service_id: "cache-product".into(),
            implementation_sha256: executable_sha256.clone(),
            deployment_identity: "cache-fixture-deployment".into(),
            operator_identity: "cache-operator".into(),
            cache_generation: 1,
            restore_epoch: 1,
            database_path: private.join("cache.sqlite3").display().to_string(),
            receipt_key_id: "fixture-key".into(),
            receipt_key_sha256: digest(RECEIPT_KEY),
            max_frame_bytes: 128 * 1024,
            max_database_bytes: 16 * 1024 * 1024,
            max_audit_events: 1024,
            max_cleanup_rows: 16,
            policies: vec![CachePolicy {
                policy_id: "product-policy".into(),
                tenant_id: org.to_string(),
                project_id: project.to_string(),
                pipeline_id: pipeline.to_string(),
                trust_class: "trusted".into(),
                allowed_kinds: vec![CacheKind::Build],
                read_principals: vec!["product-caller".into()],
                write_principals: vec!["product-caller".into()],
                max_entry_bytes: 12 * 1024,
                max_total_bytes: 64 * 1024,
                max_entries: 16,
                ttl_ms: 600_000,
            }],
        };
        let config_path = private.join("config.json");
        write_private(&config_path, &serde_json::to_vec(&config).unwrap(), 0o400);
        let receipt_key_path = private.join("receipt.key");
        write_private(&receipt_key_path, RECEIPT_KEY, 0o600);
        let binding = CacheBinding {
            mapping_id: "product-cache".into(),
            organization_id: org.to_string(),
            project_id: project.to_string(),
            pipeline_id: pipeline.to_string(),
            trust_pool: "trusted-linux".into(),
            allowed_operations: vec![CacheOperation::Read, CacheOperation::Publish],
            executable: cache_binary,
            executable_sha256,
            config_path,
            config_sha256: mcloving_cache::configuration_sha256(&config).unwrap(),
            receipt_key_path,
            policy_id: "product-policy".into(),
            caller_id: "product-caller".into(),
            trust_class: "trusted".into(),
            cache_kind: CacheKind::Build,
            toolchain_sha256: digest(b"fixture-toolchain"),
            platform_sha256: digest(b"linux-fixture"),
        };
        let bindings = CacheBindings {
            schema_version: "mcloving.agent-cache-bindings/v1".into(),
            mappings: vec![binding.clone()],
        };
        write_private(
            &root.path().join("agent-bindings.json"),
            &serde_json::to_vec(&bindings).unwrap(),
            0o400,
        );
        let catalog = json!({"schema_version":"mcloving.cache-mapping-catalog/v1","profile":"product-fixture","generation":1,"mappings":[{
            "mapping_id":binding.mapping_id,"mapping_digest":binding.mapping_digest().unwrap(),"organization_id":org,"project_id":project,"pipeline_id":pipeline,
            "trust_pool":"trusted-linux","allowed_operations":["read","publish"]}]});
        let catalog_path = root.path().join("catalog.json");
        write_private(&catalog_path, &serde_json::to_vec(&catalog).unwrap(), 0o400);
        let tls = create_mtls(root.path(), org, AGENT);
        let other_tls = create_additional_agent(root.path(), &tls, org);
        let api_port = free_port();
        let mut agent_port = free_port();
        while agent_port == api_port {
            agent_port = free_port();
        }
        std::fs::create_dir(root.path().join("workspace")).unwrap();
        let controller = Command::new(controller_binary)
            .env("MCLOVING_MIGRATION_DATABASE_URL", migration_url)
            .env("MCLOVING_DATABASE_URL", runtime_url)
            .env("MCLOVING_API_TOKEN", TOKEN)
            .env(
                "MCLOVING_ARTIFACT_AGENT_TOKEN",
                "cache-product-artifact-token-32-bytes",
            )
            .env("MCLOVING_LISTEN", format!("127.0.0.1:{api_port}"))
            .env("MCLOVING_AGENT_LISTEN", format!("127.0.0.1:{agent_port}"))
            .env("MCLOVING_AGENT_SERVER_CERT_PATH", &tls.server_certificate)
            .env("MCLOVING_AGENT_SERVER_KEY_PATH", &tls.server_key)
            .env("MCLOVING_AGENT_CLIENT_CA_PATH", &tls.ca_certificate)
            .env("MCLOVING_AGENT_IDENTITY_BINDINGS_PATH", &tls.bindings)
            .env("MCLOVING_CACHE_MAPPING_CATALOG", &catalog_path)
            .env(
                "MCLOVING_CACHE_MAPPING_CATALOG_SHA256",
                digest(&std::fs::read(&catalog_path).unwrap()),
            )
            .env("MCLOVING_ORGANIZATION_ID", org.to_string())
            .env("MCLOVING_AGENT_ID", "cache-embedded-disabled")
            .env("MCLOVING_AGENT_CAPABILITIES", "disabled")
            .env("MCLOVING_AGENT_TRUST_POOL", "trusted-linux")
            .env("MCLOVING_LEASE_SECONDS", "5")
            .env("MCLOVING_POLL_MILLISECONDS", "10")
            .env("MCLOVING_CANCELLATION_POLL_MILLISECONDS", "50")
            .env("MCLOVING_TERMINATION_GRACE_MILLISECONDS", "100")
            .env("MCLOVING_SESSION_EPOCH", "1")
            .env(
                "MCLOVING_WORKSPACE_ROOT",
                root.path().join("embedded-workspace"),
            )
            .env("MCLOVING_AGENT_JOURNAL", root.path().join("embedded.db"))
            .env("MCLOVING_OBJECT_ROOT", root.path().join("objects"))
            .stdout(std::fs::File::create(root.path().join("controller.log")).unwrap())
            .stderr(std::fs::File::create(root.path().join("controller-errors.log")).unwrap())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let client = Client::new(&format!("http://127.0.0.1:{api_port}"), TOKEN);
        wait_until_listening(&client, org).await;
        assert!(
            !Path::new(&config.database_path).exists(),
            "fixture must not initialize cache before product invokes it"
        );
        Self {
            root,
            pool,
            client,
            org,
            project,
            pipeline,
            revision: 0,
            binding,
            tls,
            other_tls,
            other_agent: None,
            agent_port,
            controller,
            agent: None,
        }
    }

    fn agent_command(&self) -> Command {
        let mut command = agent_command(
            AGENT,
            self.org,
            self.agent_port,
            &self.tls,
            &self.root.path().join("agent.db"),
            &self.root.path().join("workspace"),
        );
        let bindings = self.root.path().join("agent-bindings.json");
        command
            .env("MCLOVING_AGENT_CACHE_BINDINGS_PATH", &bindings)
            .env(
                "MCLOVING_AGENT_CACHE_BINDINGS_SHA256",
                digest(&std::fs::read(&bindings).unwrap()),
            )
            .stdout(
                std::fs::File::options()
                    .create(true)
                    .append(true)
                    .open(self.root.path().join("agent.log"))
                    .unwrap(),
            )
            .stderr(
                std::fs::File::options()
                    .create(true)
                    .append(true)
                    .open(self.root.path().join("agent-errors.log"))
                    .unwrap(),
            );
        command
    }

    fn start_agent(&mut self, fault: Option<&str>) {
        assert!(self.agent.is_none());
        let mut command = self.agent_command();
        if let Some(fault) = fault {
            command.env(fault, "1");
        }
        self.agent = Some(command.kill_on_drop(true).spawn().unwrap());
    }

    async fn stop_agent(&mut self) {
        if let Some(mut agent) = self.agent.take() {
            stop(&mut agent).await;
        }
    }

    fn source(&self, steps: &[(&str, &str, Option<&[u8]>)]) -> String {
        let mut source = "version: 1\nname: cache-product\nstages:\n".to_owned();
        for (index, (operation, key, content)) in steps.iter().enumerate() {
            source.push_str(&format!("  - id: cache{index}\n    name: Cache{index}\n    steps:\n      - cache_intent:\n          mapping_id: {}\n          mapping_digest: {}\n          operation: {operation}\n          logical_key_sha256: {}\n          input_sha256: {}\n", self.binding.mapping_id, self.binding.mapping_digest().unwrap(), digest(key.as_bytes()), digest(b"public-input")));
            if let Some(bytes) = content {
                source.push_str(&format!(
                    "          content_base64: {}\n",
                    BASE64.encode(bytes)
                ));
            }
            source.push_str("          timeout_seconds: 30\n");
        }
        source
    }

    async fn save(&mut self, source: String) {
        let saved = self
            .client
            .put_pipeline(
                self.org,
                self.project,
                self.pipeline,
                self.revision,
                &PipelineUpsertRequest {
                    slug: "cache-product".into(),
                    source,
                    parameters: Default::default(),
                },
            )
            .await
            .expect("API saves scoped cache source");
        self.revision = saved.revision;
    }
    async fn submit(&self, key: &str) -> Uuid {
        self.client
            .submit_pipeline_on_platform_in_pool(
                self.org,
                self.project,
                self.pipeline,
                key,
                "linux",
                "trusted-linux",
                &PipelineBuildRequest::default(),
            )
            .await
            .expect("API submits cache job")
            .build_id
    }
    async fn terminal(&self, build: Uuid) -> String {
        tokio::time::timeout(Duration::from_secs(45), async {
            loop {
                let status = self
                    .client
                    .status(self.org, self.project, build)
                    .await
                    .unwrap();
                if matches!(status.status.as_str(), "succeeded" | "failed" | "aborted") {
                    return status.status;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("actual cache job reaches bounded terminal result")
    }
    async fn summaries(&self, build: Uuid) -> Vec<Value> {
        let logs = self
            .client
            .logs(self.org, self.project, build)
            .await
            .unwrap();
        let mut summaries = Vec::new();
        for log in logs {
            let text = log.text.unwrap_or_default();
            assert!(!text.contains(std::str::from_utf8(CONTENT).unwrap()));
            assert!(!text.contains(&BASE64.encode(CONTENT)));
            assert!(!text.contains(std::str::from_utf8(RECEIPT_KEY).unwrap()));
            for line in text.lines().filter(|l| !l.is_empty()) {
                let value: Value =
                    serde_json::from_str(line).expect("only typed public cache summary");
                assert_eq!(value["protocol"], "mcloving.cache-invocation/v1");
                assert!(value.get("content_sha256").is_none());
                summaries.push(value);
            }
        }
        summaries
    }
    fn audit(&self) -> Vec<Value> {
        // Independent, read-only SQLite/HMAC observation AFTER real product work.
        let script = r#"import sqlite3,sys,json,hashlib,hmac,base64,pathlib
p=pathlib.Path(sys.argv[1]); key=pathlib.Path(sys.argv[2]).read_bytes()
if not p.exists(): print('[]'); sys.exit(0)
c=sqlite3.connect(p.as_uri()+'?mode=ro',uri=True); result=[]; previous='0'*64
for expected,row in enumerate(c.execute('SELECT sequence,event_json,event_sha256,signature FROM audit_events ORDER BY sequence'),1):
 sequence,raw,digest,signature=row; raw=bytes(raw); event=json.loads(raw)
 assert sequence==expected and event['previous_event_sha256']==previous
 assert hashlib.sha256(b'mcloving.cache-event/v1\0'+raw).hexdigest()==digest
 assert hmac.compare_digest(hmac.new(key,digest.encode(),hashlib.sha256).digest(),base64.b64decode(signature,validate=True))
 result.append({'sequence':sequence,'event':event,'event_sha256':digest});previous=digest
print(json.dumps(result))"#;
        python_json(
            script,
            &[
                &self.root.path().join("cache-private/cache.sqlite3"),
                &self.binding.receipt_key_path,
            ],
        )
        .as_array()
        .unwrap()
        .clone()
    }
    async fn assert_bindings(&self, build: Uuid, summaries: &[Value]) {
        let rows: Vec<(Uuid, Uuid, i64, i64, String, Value)> = sqlx::query_as("SELECT a.id,n.id,a.restore_epoch,a.fence,a.lease_owner,n.execution_spec FROM attempts a JOIN nodes n ON n.organization_id=a.organization_id AND n.id=a.node_id WHERE a.organization_id=$1 AND n.build_id=$2 ORDER BY n.node_key,a.ordinal")
            .bind(self.org).bind(build).fetch_all(&self.pool).await.unwrap();
        assert_eq!(
            rows.len(),
            summaries.len(),
            "exactly one actual attempt per cache stage"
        );
        let journal = python_json(
            "import sqlite3,sys,json,pathlib\nc=sqlite3.connect(pathlib.Path(sys.argv[1]).as_uri()+'?mode=ro',uri=True)\nprint(json.dumps([{'attempt':a,'fence':f,'digest':bytes(d).hex()} for a,f,d in c.execute('SELECT attempt_id,fence_token,payload_digest FROM attempts')]))",
            &[&self.root.path().join("agent.db")],
        );
        for (attempt, node, restore_epoch, fence, owner, execution) in rows {
            let wire_fence = (u64::from(u32::try_from(restore_epoch).unwrap()) << 32)
                | u64::from(u32::try_from(fence).unwrap());
            assert_eq!(owner, AGENT);
            assert!(fence > 0);
            let context = CacheWorkContext {
                organization_id: self.org.to_string(),
                project_id: self.project.to_string(),
                pipeline_id: self.pipeline.to_string(),
                build_id: build.to_string(),
                node_id: node.to_string(),
                attempt_id: attempt.to_string(),
                fence_token: wire_fence,
            };
            let digest = hex(&cache_assignment_digest(
                &serde_json::to_vec(&execution).unwrap(),
                &context,
            ));
            assert!(
                journal
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|row| row["attempt"] == attempt.to_string()
                        && row["fence"] == wire_fence
                        && row["digest"] == digest)
            );
            assert!(
                summaries
                    .iter()
                    .any(|s| s["invocation_id"] == format!("sha256:{digest}")),
                "public result binds authenticated journal commitment"
            );
        }
    }
    async fn build_count(&self) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM builds WHERE organization_id=$1")
            .bind(self.org)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
    async fn finish(mut self) {
        self.stop_agent().await;
        if let Some(mut agent) = self.other_agent.take() {
            stop(&mut agent).await;
        }
        stop(&mut self.controller).await;
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        // Reap owned handles before TempDir destruction, including assertion unwind.
        for child in self
            .agent
            .iter_mut()
            .chain(self.other_agent.iter_mut())
            .chain(std::iter::once(&mut self.controller))
        {
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.start_kill();
            }
            for _ in 0..200 {
                if child.try_wait().ok().flatten().is_some() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        if std::thread::panicking() {
            let directory = tempfile::Builder::new()
                .prefix("mcloving-cache-product-failure-")
                .tempdir()
                .expect("retain failed gate diagnostics")
                .keep();
            for name in [
                "agent.log",
                "agent-errors.log",
                "controller.log",
                "controller-errors.log",
                "other-agent.log",
                "other-agent-errors.log",
            ] {
                let source = self.root.path().join(name);
                if source.is_file() {
                    let mut bytes = std::fs::read(source).expect("retain complete diagnostics");
                    for marker in [
                        CONTENT,
                        BASE64.encode(CONTENT).as_bytes(),
                        RECEIPT_KEY,
                        TOKEN.as_bytes(),
                    ] {
                        while let Some(offset) =
                            bytes.windows(marker.len()).position(|part| part == marker)
                        {
                            bytes.splice(
                                offset..offset + marker.len(),
                                b"[REDACTED]".iter().copied(),
                            );
                        }
                    }
                    std::fs::write(directory.join(name), bytes)
                        .expect("write redacted diagnostics");
                }
            }
            eprintln!(
                "cache product failure diagnostics retained: {} (no fixture keys/config/database copied)",
                directory.display()
            );
        }
    }
}
fn assert_denied<T>(result: Result<T, ClientError>, codes: &[&str]) {
    match result {
        Err(ClientError::Response { status, body }) => {
            assert!(
                status.is_client_error(),
                "expected admission refusal, got {status}"
            );
            let response: Value =
                serde_json::from_str(&body).expect("structured admission refusal");
            assert!(
                codes.contains(&response["code"].as_str().unwrap_or("")),
                "unexpected denial {response}"
            );
        }
        Err(error) => panic!("transport failure is not admission evidence: {error}"),
        Ok(_) => panic!("unconfigured authority was admitted"),
    }
}

async fn mixed_agent_mapping_eligibility(database: &str) {
    let mut h = Harness::new(database).await;
    let cache_source = h.source(&[("read", "eligibility", None)]);
    h.save(cache_source).await;
    let cache_build = h.submit("eligibility-cache-first").await;
    let before_agent: Vec<(Uuid, String, Option<String>, i64)> = sqlx::query_as(
        "SELECT a.id,a.status,a.lease_owner,a.fence FROM attempts a JOIN nodes n ON n.id=a.node_id AND n.organization_id=a.organization_id WHERE a.organization_id=$1 AND n.build_id=$2",
    ).bind(h.org).bind(cache_build).fetch_all(&h.pool).await.unwrap();
    assert_eq!(before_agent.len(), 1);
    assert_eq!(before_agent[0].1, "queued");
    assert!(before_agent[0].2.is_none());
    assert_eq!(before_agent[0].3, 0);
    // Queue a real ordinary job AFTER cache. Its completed attempt proves the
    // mismatched agent actually polled/claimed work while cache stayed queued.
    h.save("version: 1\nname: barrier\nstages:\n  - id: barrier\n    name: Barrier\n    steps:\n      - process:\n          program: /bin/true\n          timeout_seconds: 30\n".to_owned()).await;
    let barrier = h.submit("eligibility-process-barrier").await;
    let mut wrong = h.binding.clone();
    wrong.mapping_id = "disjoint-cache".into();
    let bindings = h.root.path().join("other-bindings.json");
    write_private(
        &bindings,
        &serde_json::to_vec(&CacheBindings {
            schema_version: "mcloving.agent-cache-bindings/v1".into(),
            mappings: vec![wrong],
        })
        .unwrap(),
        0o400,
    );
    let workspace = h.root.path().join("other-workspace");
    std::fs::create_dir(&workspace).unwrap();
    h.other_agent = Some(
        agent_command(
            OTHER_AGENT,
            h.org,
            h.agent_port,
            &h.other_tls,
            &h.root.path().join("other-agent.db"),
            &workspace,
        )
        .env("MCLOVING_AGENT_CACHE_BINDINGS_PATH", &bindings)
        .env(
            "MCLOVING_AGENT_CACHE_BINDINGS_SHA256",
            digest(&std::fs::read(&bindings).unwrap()),
        )
        .stdout(std::fs::File::create(h.root.path().join("other-agent.log")).unwrap())
        .stderr(std::fs::File::create(h.root.path().join("other-agent-errors.log")).unwrap())
        .kill_on_drop(true)
        .spawn()
        .unwrap(),
    );
    assert_eq!(h.terminal(barrier).await, "succeeded");
    let owner: String = sqlx::query_scalar("SELECT a.lease_owner FROM attempts a JOIN nodes n ON n.id=a.node_id AND n.organization_id=a.organization_id WHERE a.organization_id=$1 AND n.build_id=$2 AND a.status='succeeded'")
        .bind(h.org).bind(barrier).fetch_one(&h.pool).await.unwrap();
    assert_eq!(
        owner, OTHER_AGENT,
        "ineligible agent must actually complete scheduler barrier"
    );
    let queued: Vec<(Uuid,String,Option<String>,i64)> = sqlx::query_as("SELECT a.id,a.status,a.lease_owner,a.fence FROM attempts a JOIN nodes n ON n.id=a.node_id AND n.organization_id=a.organization_id WHERE a.organization_id=$1 AND n.build_id=$2")
        .bind(h.org).bind(cache_build).fetch_all(&h.pool).await.unwrap();
    assert_eq!(
        queued.len(),
        1,
        "only original admitted queued attempt exists"
    );
    assert_eq!(
        queued, before_agent,
        "real ineligible polling leaves original cache attempt untouched"
    );
    assert_eq!(queued[0].1, "queued");
    assert!(
        queued[0].2.is_none(),
        "mismatched agent must never claim cache"
    );
    assert_eq!(queued[0].3, 0);
    assert!(
        h.audit().is_empty(),
        "ineligible agent performs no cache operation"
    );
    let other_attempts = python_json(
        "import sqlite3,sys,json,pathlib\nc=sqlite3.connect(pathlib.Path(sys.argv[1]).as_uri()+'?mode=ro',uri=True)\nprint(json.dumps([r[0] for r in c.execute('SELECT attempt_id FROM attempts')]))",
        &[&h.root.path().join("other-agent.db")],
    );
    assert!(
        !other_attempts
            .as_array()
            .unwrap()
            .iter()
            .any(|id| id.as_str() == Some(&queued[0].0.to_string())),
        "cache assignment never reaches ineligible journal"
    );
    h.start_agent(None);
    assert_eq!(h.terminal(cache_build).await, "succeeded");
    assert!(
        h.other_agent
            .as_mut()
            .unwrap()
            .try_wait()
            .unwrap()
            .is_none(),
        "ineligible agent remains live in same pool"
    );
    let claimed: (Uuid,String) = sqlx::query_as("SELECT a.id,a.lease_owner FROM attempts a JOIN nodes n ON n.id=a.node_id AND n.organization_id=a.organization_id WHERE a.organization_id=$1 AND n.build_id=$2 AND a.status='succeeded'")
        .bind(h.org).bind(cache_build).fetch_one(&h.pool).await.unwrap();
    assert_eq!(claimed, (queued[0].0, AGENT.to_owned()));
    assert_eq!(h.audit().len(), 1);
    assert_eq!(h.summaries(cache_build).await[0]["outcome"], "miss");
    h.finish().await;
}

#[tokio::test]
async fn submitted_cache_jobs_execute_real_helper_without_authority_or_output_bypass() {
    let Ok(database) = std::env::var("MCLOVING_TEST_DATABASE_URL") else {
        eprintln!(
            "skipped: MCLOVING_TEST_DATABASE_URL is not configured; cache product proof unavailable"
        );
        return;
    };
    mixed_agent_mapping_eligibility(&database).await;
    let mut h = Harness::new(&database).await;
    let source = h.source(&[
        ("read", "main", None),
        ("publish", "main", Some(CONTENT)),
        ("read", "main", None),
    ]);
    h.save(source).await;
    h.start_agent(None);
    let build = h.submit("cache-positive").await;
    assert_eq!(h.terminal(build).await, "succeeded");
    let summaries = h.summaries(build).await;
    assert_eq!(
        summaries
            .iter()
            .map(|s| s["outcome"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["miss", "published", "hit"]
    );
    h.assert_bindings(build, &summaries).await;
    let audit = h.audit();
    assert_eq!(
        audit.len(),
        3,
        "three primary operations performed by real helper"
    );
    for (event, summary) in audit.iter().zip(&summaries) {
        assert_eq!(event["event_sha256"], summary["event_sha256"]);
        assert_eq!(event["event"]["caller_id"], "product-caller");
        assert_eq!(
            event["event"]["configuration_sha256"],
            h.binding.config_sha256
        );
        assert_eq!(
            event["event"]["implementation_sha256"],
            h.binding.executable_sha256
        );
        assert_eq!(event["event"]["policy_id"], h.binding.policy_id);
    }
    for marker in [CONTENT, BASE64.encode(CONTENT).as_bytes(), RECEIPT_KEY] {
        assert!(
            !directory_contains(&h.root.path().join("workspace"), marker),
            "private response marker escaped to agent workspace"
        );
        for name in [
            "agent.db",
            "agent.db-wal",
            "agent.db-shm",
            "agent.log",
            "agent-errors.log",
        ] {
            let path = h.root.path().join(name);
            if path
                .try_exists()
                .expect("inspect private-output boundary file")
            {
                let bytes = std::fs::read(path).expect("read complete output boundary file");
                assert!(
                    !bytes.windows(marker.len()).any(|bytes| bytes == marker),
                    "private marker escaped to {name}"
                );
            }
        }
    }
    // API rejections must create neither a build nor a cache event.
    let builds = h.build_count().await;
    let good = h.source(&[("read", "main", None)]);
    for (bad, code) in [
        (
            good.replace("mapping_id: product-cache", "mapping_id: unknown"),
            "cache_mapping_denied",
        ),
        (
            good.replace(
                &h.binding.mapping_digest().unwrap(),
                &format!("sha256:{}", "0".repeat(64)),
            ),
            "cache_mapping_denied",
        ),
        (
            good.replace("operation: read", "operation: cleanup"),
            "pipeline_rejected",
        ),
    ] {
        assert_denied(
            h.client
                .put_pipeline(
                    h.org,
                    h.project,
                    h.pipeline,
                    h.revision,
                    &PipelineUpsertRequest {
                        slug: "cache-product".into(),
                        source: bad,
                        parameters: Default::default(),
                    },
                )
                .await,
            &[code],
        );
    }
    assert_denied(
        h.client
            .put_pipeline(
                h.org,
                h.project,
                Uuid::new_v4(),
                0,
                &PipelineUpsertRequest {
                    slug: "wrong-scope".into(),
                    source: good,
                    parameters: Default::default(),
                },
            )
            .await,
        &["cache_mapping_denied"],
    );
    for (platform, pool) in [("windows", "trusted-linux"), ("linux", "untrusted")] {
        assert_denied(
            h.client
                .submit_pipeline_on_platform_in_pool(
                    h.org,
                    h.project,
                    h.pipeline,
                    "cache-positive",
                    platform,
                    pool,
                    &PipelineBuildRequest::default(),
                )
                .await,
            &["cache_mapping_denied"],
        );
    }
    assert_eq!(h.build_count().await, builds);
    assert_eq!(h.audit().len(), 3);
    // A real conflicting publication fails and prevents its downstream read.
    let conflicting = h.source(&[
        ("publish", "main", Some(b"conflicting-content")),
        ("read", "main", None),
    ]);
    h.save(conflicting).await;
    let conflict = h.submit("cache-conflict").await;
    assert_eq!(h.terminal(conflict).await, "failed");
    assert_eq!(
        h.audit().len(),
        4,
        "conflict cannot execute downstream cache read"
    );
    let downstream_status: String = sqlx::query_scalar(
        "SELECT status FROM nodes WHERE organization_id=$1 AND build_id=$2 AND node_key='cache1'",
    )
    .bind(h.org)
    .bind(conflict)
    .fetch_one(&h.pool)
    .await
    .expect("observe downstream node after conflicting publication");
    assert_eq!(
        downstream_status, "skipped",
        "conflict skips downstream node"
    );
    assert!(
        h.summaries(conflict)
            .await
            .iter()
            .any(|s| s["outcome"] == "conflict")
    );
    h.stop_agent().await;
    // Receipt produced and verified, but no terminal journal result: recovery
    // must preserve ambiguity and must not blindly dispatch a fresh invocation.
    let uncertain = h.source(&[("publish", "uncertain", Some(CONTENT))]);
    h.save(uncertain).await;
    h.start_agent(Some("MCLOVING_TEST_CRASH_AFTER_HELPER_RECEIPT"));
    let uncertain_build = h.submit("cache-uncertain").await;
    let exit = tokio::time::timeout(Duration::from_secs(45), h.agent.as_mut().unwrap().wait())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(exit.code(), Some(87));
    h.agent.take();
    let before_restart = h.audit();
    assert_eq!(before_restart.len(), 5);
    let journal_before = python_json(
        "import sqlite3,sys,json,pathlib\nc=sqlite3.connect(pathlib.Path(sys.argv[1]).as_uri()+'?mode=ro',uri=True)\nprint(json.dumps([list(r) for r in c.execute(\"SELECT attempt_id,fence_token,hex(payload_digest),phase FROM attempts WHERE phase='running'\")]))",
        &[&h.root.path().join("agent.db")],
    );
    assert_eq!(
        journal_before.as_array().unwrap().len(),
        1,
        "request authority durably journaled before helper execution"
    );
    h.start_agent(None);
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let errors = std::fs::read_to_string(h.root.path().join("agent-errors.log"))
                .expect("read recovery diagnostic");
            if errors.contains("unresolved recovered attempt and will not poll for more work") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("recovery explicitly parks ambiguous invocation");
    // Observe beyond the five-second lease: a parked invocation must remain
    // unsuccessful and cannot acquire a new attempt or execute another helper.
    tokio::time::sleep(Duration::from_secs(6)).await;
    let status = h
        .client
        .status(h.org, h.project, uncertain_build)
        .await
        .unwrap();
    assert_ne!(
        status.status, "succeeded",
        "lost result cannot become success"
    );
    assert_eq!(
        h.audit(),
        before_restart,
        "recovery must not dispatch a second helper operation"
    );
    let recovered_journal = python_json(
        "import sqlite3,sys,json,pathlib\nc=sqlite3.connect(pathlib.Path(sys.argv[1]).as_uri()+'?mode=ro',uri=True)\nprint(json.dumps([list(r) for r in c.execute('SELECT attempt_id,fence_token,hex(payload_digest),phase FROM attempts')]))",
        &[&h.root.path().join("agent.db")],
    );
    let prior = &journal_before.as_array().unwrap()[0];
    let same: Vec<_> = recovered_journal
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row[0] == prior[0])
        .collect();
    assert_eq!(same.len(), 1);
    assert_eq!(
        &same[0].as_array().unwrap()[..3],
        &prior.as_array().unwrap()[..3],
        "recovery retains original attempt/fence/request commitment"
    );
    let attempt_count:i64=sqlx::query_scalar("SELECT count(*) FROM attempts a JOIN nodes n ON n.id=a.node_id AND n.organization_id=a.organization_id WHERE a.organization_id=$1 AND n.build_id=$2").bind(h.org).bind(uncertain_build).fetch_one(&h.pool).await.unwrap();
    assert_eq!(attempt_count, 1, "ambiguity cannot create a fresh attempt");
    h.stop_agent().await;
    h.finish().await;
    // A parked journal is deliberately preserved until fixture teardown. Use
    // a separate organization/controller/agent for the terminal replay case.
    let mut h = Harness::new(&database).await;
    // Terminal-commit crash has the opposite recovery result: replay existing
    // terminal truth without invoking the helper again.
    let terminal_source = h.source(&[("publish", "terminal", Some(CONTENT))]);
    h.save(terminal_source).await;
    h.start_agent(Some("MCLOVING_TEST_CRASH_AFTER_TERMINAL_COMMIT"));
    let replay = h.submit("cache-terminal-replay").await;
    let exit = tokio::time::timeout(Duration::from_secs(45), h.agent.as_mut().unwrap().wait())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(exit.code(), Some(86));
    h.agent.take();
    let before_replay = h.audit();
    assert_eq!(before_replay.len(), 1);
    let probe = tokio::time::timeout(
        Duration::from_secs(15),
        h.agent_command().arg("probe").status(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(probe.success());
    h.start_agent(None);
    assert_eq!(h.terminal(replay).await, "succeeded");
    assert_eq!(h.audit(), before_replay);
    let terminal_events:i64=sqlx::query_scalar("SELECT count(*) FROM build_events WHERE organization_id=$1 AND build_id=$2 AND kind='attempt.terminal'").bind(h.org).bind(replay).fetch_one(&h.pool).await.unwrap();
    assert_eq!(terminal_events, 1);
    h.finish().await;
}

fn python_json(script: &str, paths: &[&Path]) -> Value {
    let output = StdCommand::new("python3")
        .arg("-c")
        .arg(script)
        .args(paths)
        .output()
        .expect("independent read-only SQLite observer");
    assert!(
        output.status.success(),
        "SQLite observation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
fn write_private(path: &Path, bytes: &[u8], mode: u32) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}
fn digest(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn directory_contains(root: &Path, needle: &[u8]) -> bool {
    let entries = std::fs::read_dir(root).expect("read test directory");
    for entry in entries {
        let path = entry.expect("read test entry").path();
        let metadata = std::fs::symlink_metadata(&path).expect("inspect output-boundary entry");
        assert!(
            !metadata.file_type().is_symlink(),
            "unexpected output boundary symlink"
        );
        if metadata.is_dir() {
            if directory_contains(&path, needle) {
                return true;
            }
        } else if std::fs::read(&path)
            .expect("read complete output boundary file")
            .windows(needle.len())
            .any(|window| window == needle)
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

fn create_additional_agent(root: &Path, tls: &MtlsFiles, organization: Uuid) -> MtlsFiles {
    use std::io::Write as _;
    let key = root.join("other-agent-key.pem");
    let csr = root.join("other-agent.csr");
    let certificate = root.join("other-agent.pem");
    let extensions = root.join("other-agent.ext");
    std::fs::write(&extensions, "extendedKeyUsage=clientAuth\n").unwrap();
    openssl([
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-subj",
        &format!("/CN={OTHER_AGENT}"),
        "-keyout",
        path(&key),
        "-out",
        path(&csr),
    ]);
    sign(
        &csr,
        &certificate,
        &extensions,
        &tls.ca_certificate,
        &root.join("ca-key.pem"),
    );
    let der = root.join("other-agent.der");
    openssl([
        "x509",
        "-in",
        path(&certificate),
        "-outform",
        "DER",
        "-out",
        path(&der),
    ]);
    writeln!(
        std::fs::OpenOptions::new()
            .append(true)
            .open(&tls.bindings)
            .unwrap(),
        "{} {OTHER_AGENT} trusted-linux {organization}",
        digest(&std::fs::read(der).unwrap())
    )
    .unwrap();
    MtlsFiles {
        ca_certificate: tls.ca_certificate.clone(),
        server_certificate: tls.server_certificate.clone(),
        server_key: tls.server_key.clone(),
        agent_certificate: certificate,
        agent_key: key,
        bindings: tls.bindings.clone(),
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
