//! Actual submitted-job input gate. Helper-library calls and fabricated assignments
//! never serve as positive execution evidence here.
#![cfg(target_os = "linux")]

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use mcloving_agent::input::{InputBinding, InputBindings};
use mcloving_controller_api::{Client, ClientError, PipelineBuildRequest, PipelineUpsertRequest};
use mcloving_controller_store::Store;
use mcloving_input_adapter::{
    AdapterConfig, CaptureRequest, Confidentiality, FieldSchema, JsonKind, PROTOCOL_VERSION,
    marker_set_digest,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use std::collections::BTreeMap;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command as StdCommand, Stdio};
use std::time::Duration;
use tokio::process::{Child, Command};
use uuid::Uuid;

const TOKEN: &str = "contained-input-product-test-token";
const AGENT: &str = "input-product-agent";
const OTHER_AGENT: &str = "input-product-ineligible-agent";
const CONTENT: &[u8] = b"distinctive-input-content-not-public-result-1957";
const READ_TOKEN: &[u8] = b"fixture-input-provider-read-token-32-bytes";
const SECRET_MARKER: &[u8] = b"fixture-input-secret-marker-never-disclose";
const RECEIPT_KEY: &[u8] = b"synthetic-input-fixture-receipt-key-32-bytes";

struct Harness {
    pool: sqlx::PgPool,
    client: Client,
    org: Uuid,
    project: Uuid,
    pipeline: Uuid,
    revision: i64,
    binding: InputBinding,
    config: AdapterConfig,
    provider: Child,
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
        Self::with_variant(migration_url, "valid").await
    }

    async fn with_variant(migration_url: &str, variant: &str) -> Self {
        // This explicitly supplied fixture URL is never inherited by the agent.
        let controller_binary = PathBuf::from(
            std::env::var_os("MCLOVING_CONTROLLER_BINARY").expect("shipped controller required"),
        );
        let input_binary = std::fs::canonicalize(
            std::env::var_os("MCLOVING_INPUT_ADAPTER_BINARY").expect("shipped input required"),
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
            .create_project(org, &format!("input-{org}"), project, "input-product")
            .await
            .unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let private = root.path().join("input-private");
        std::fs::create_dir(&private).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        let provider = start_provider(root.path()).await;
        let endpoint = std::fs::read_to_string(root.path().join("provider-endpoint")).unwrap();
        let executable = private.join("input-helper");
        std::fs::copy(input_binary, &executable).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o500)).unwrap();
        let executable_sha256 = digest(&std::fs::read(&executable).unwrap());
        let config = AdapterConfig {
            protocol_version: PROTOCOL_VERSION.into(),
            schema_version: "flags/v1".into(),
            adapter_id: "input-product".into(),
            deployment_identity: "fixture-input-deployment".into(),
            operator_identity: "fixture-independent-operator".into(),
            generation: 1,
            endpoint_url: endpoint,
            endpoint_identity: "fixture-flags-service".into(),
            data_source_identity: "fixture-flags-dataset".into(),
            allowed_query_keys: vec!["branch".into()],
            response_schema: vec![
                FieldSchema {
                    name: "enabled".into(),
                    kind: JsonKind::Boolean,
                    required: true,
                },
                FieldSchema {
                    name: "value".into(),
                    kind: JsonKind::String,
                    required: true,
                },
            ],
            grant_id: "fixture-read-grant".into(),
            grant_version: "1".into(),
            grant_scope: "flags:read".into(),
            grant_expires_unix_ms: if variant == "expired-grant" {
                now_ms() - 1
            } else {
                now_ms() + 600_000
            },
            read_token_sha256: digest(READ_TOKEN),
            signing_key_id: "fixture-signing-key-v1".into(),
            signing_key_sha256: digest(RECEIPT_KEY),
            secret_marker_set_sha256: marker_set_digest(&[SECRET_MARKER.to_vec()]),
            max_confidentiality: Confidentiality::Public,
            max_response_bytes: 12 * 1024,
            max_requests_per_minute: 100,
            timeout_ms: 2_000,
            max_age_ms: 5_000,
            retry_attempts: 0,
            spool_dir: private.join("spool"),
            ca_bundle_path: None,
            ca_bundle_sha256: None,
            test_allow_http_loopback: true,
        };
        let config_path = private.join("config.json");
        write_private(&config_path, &serde_json::to_vec(&config).unwrap(), 0o400);
        let signing_key_path = private.join("receipt.key");
        write_private(&signing_key_path, RECEIPT_KEY, 0o400);
        let read_token_path = private.join("read.token");
        write_private(&read_token_path, READ_TOKEN, 0o400);
        let secret_markers_path = private.join("markers");
        write_private(&secret_markers_path, SECRET_MARKER, 0o400);
        let binding = InputBinding {
            mapping_id: "product-input".into(),
            organization_id: org.to_string(),
            project_id: project.to_string(),
            pipeline_id: pipeline.to_string(),
            trust_pool: "trusted-linux".into(),
            executable,
            executable_sha256,
            config_path,
            config_sha256: config.canonical_digest().unwrap(),
            read_token_path,
            signing_key_path,
            secret_markers_path,
            input_name: "release_enabled".into(),
            query: BTreeMap::from([(
                if variant == "unauthorized-query" {
                    "unapproved"
                } else {
                    "branch"
                }
                .into(),
                "main".into(),
            )]),
            expected_cursor: Some("main-cursor-v1".into()),
            confidentiality_ceiling: Confidentiality::Public,
            test_allow_http_loopback: true,
        };
        let bindings = InputBindings {
            schema_version: "mcloving.agent-input-bindings/v1".into(),
            mappings: vec![binding.clone()],
        };
        write_private(
            &root.path().join("agent-bindings.json"),
            &serde_json::to_vec(&bindings).unwrap(),
            0o400,
        );
        let catalog = json!({"schema_version":"mcloving.input-mapping-catalog/v1","profile":"product-fixture","generation":1,"mappings":[{
            "mapping_id":binding.mapping_id,"mapping_digest":binding.mapping_digest().unwrap(),"organization_id":org,"project_id":project,"pipeline_id":pipeline,
            "trust_pool":"trusted-linux"}]});
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
                "input-product-artifact-token-32-bytes",
            )
            .env("MCLOVING_LISTEN", format!("127.0.0.1:{api_port}"))
            .env("MCLOVING_AGENT_LISTEN", format!("127.0.0.1:{agent_port}"))
            .env("MCLOVING_AGENT_SERVER_CERT_PATH", &tls.server_certificate)
            .env("MCLOVING_AGENT_SERVER_KEY_PATH", &tls.server_key)
            .env("MCLOVING_AGENT_CLIENT_CA_PATH", &tls.ca_certificate)
            .env("MCLOVING_AGENT_IDENTITY_BINDINGS_PATH", &tls.bindings)
            .env("MCLOVING_INPUT_MAPPING_CATALOG", &catalog_path)
            .env(
                "MCLOVING_INPUT_MAPPING_CATALOG_SHA256",
                digest(&std::fs::read(&catalog_path).unwrap()),
            )
            .env("MCLOVING_ORGANIZATION_ID", org.to_string())
            .env("MCLOVING_AGENT_ID", "input-embedded-disabled")
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
            !config.spool_dir.exists(),
            "fixture must not initialize input before product invokes it"
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
            config,
            provider,
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
            .env("MCLOVING_AGENT_INPUT_BINDINGS_PATH", &bindings)
            .env(
                "MCLOVING_AGENT_INPUT_BINDINGS_SHA256",
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

    fn source(&self, stages: usize) -> String {
        let mut source = "version: 1\nname: input-product\nstages:\n".to_owned();
        for index in 0..stages {
            source.push_str(&format!("  - id: input{index}\n    name: Input{index}\n    steps:\n      - input_intent:\n          mapping_id: {}\n          mapping_digest: {}\n          timeout_seconds: 30\n", self.binding.mapping_id, self.binding.mapping_digest().unwrap()));
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
                    slug: "input-product".into(),
                    source,
                    parameters: Default::default(),
                },
            )
            .await
            .expect("API saves scoped input source");
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
            .expect("API submits input job")
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
        .expect("actual input job reaches bounded terminal result")
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
                    serde_json::from_str(line).expect("only typed public input summary");
                assert_eq!(value["protocol"], "mcloving.input-invocation/v1");
                assert_eq!(
                    value
                        .as_object()
                        .unwrap()
                        .keys()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                    [
                        "capture_id",
                        "invocation_id",
                        "mapping_id",
                        "outcome",
                        "protocol",
                        "request_sha256"
                    ],
                    "public result has exactly the approved opaque fields"
                );
                assert_eq!(value["mapping_id"], self.binding.mapping_id);
                summaries.push(value);
            }
        }
        summaries
    }
    fn audit(&self) -> Vec<Value> {
        // Independent read-only observer authenticates native stored receipt bytes.
        // It does not call InputAdapter or its verifier and cannot cause provider IO.
        python_json(r#"import sys,json,hashlib,hmac,base64,pathlib
p=pathlib.Path(sys.argv[1]); key=pathlib.Path(sys.argv[2]).read_bytes(); result=[]
for f in sorted(p.glob('*.json')):
 r=json.loads(f.read_bytes())
 if 'capture_id' not in r or 'signature' not in r: continue
 signature=base64.b64decode(r['signature']+'=',altchars=b'-_',validate=True); assert base64.urlsafe_b64encode(signature).rstrip(b'=').decode()==r['signature']; unsigned=dict(r);unsigned['signature']=''
 raw=json.dumps(unsigned,separators=(',',':'),ensure_ascii=False).encode()
 assert hmac.compare_digest(hmac.new(key,raw,hashlib.sha256).digest(),signature)
 assert hashlib.sha256(json.dumps(r['response'],sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()==r['response_sha256']
 assert f.stem==r['capture_id']
 result.append(r)
print(json.dumps(result))"#, &[&self.config.spool_dir,&self.binding.signing_key_path]).as_array().unwrap().clone()
    }

    fn provider_requests(&self) -> Vec<Value> {
        std::fs::read_to_string(self.root.path().join("provider-requests.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn assert_reads(&self, expected: usize) {
        let requests = self.provider_requests();
        assert_eq!(
            requests.len(),
            expected,
            "exact provider request count, including refused reads/writes"
        );
        for request in requests {
            assert_eq!(request["method"], "GET", "provider must receive no writes");
            assert_eq!(
                request["path"], "/input?branch=main",
                "operator-fixed exact endpoint and query"
            );
            assert_eq!(
                request["authorized"], true,
                "exact helper-owned token and read-only grant"
            );
        }
    }

    async fn observe_sealed_helper(&self) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while self.provider_requests().is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("real helper reaches counted provider before inspection");
        let pid = self.agent.as_ref().unwrap().id().unwrap().to_string();
        let observed = python_json(
            r#"import pathlib,sys,os,fcntl,hashlib,json
parent=int(sys.argv[1]);found=[]
for p in pathlib.Path('/proc').iterdir():
 if not p.name.isdigit(): continue
 try:
  status=dict(line.split(':',1) for line in (p/'status').read_text().splitlines())
  if int(status['PPid'])!=parent: continue
  target=os.readlink(p/'exe')
  if 'memfd:' not in target: continue
  with (p/'exe').open('rb') as f:
   seals=fcntl.fcntl(f,fcntl.F_GET_SEALS)
   required=fcntl.F_SEAL_SEAL|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_GROW|fcntl.F_SEAL_WRITE
   assert seals&required==required
   digest=hashlib.sha256(f.read()).hexdigest()
  found.append({'sha256':digest,'parent':parent,'pid':int(p.name),'sealed':True})
 except (FileNotFoundError,ProcessLookupError,PermissionError):continue
assert len(found)==1,found
print(json.dumps(found[0]))"#,
            &[Path::new(&pid)],
        );
        assert_eq!(
            observed["sha256"], self.binding.executable_sha256,
            "observed running memfd is the pinned shipped native input helper"
        );
        assert_eq!(observed["sealed"], true);
        std::fs::write(self.root.path().join("provider-release"), b"release").unwrap();
    }

    fn journal(&self) -> Value {
        python_json(
            "import sqlite3,sys,json,pathlib\nc=sqlite3.connect(pathlib.Path(sys.argv[1]).as_uri()+'?mode=ro',uri=True)\nprint(json.dumps([{'attempt':a,'fence':f,'digest':bytes(d).hex(),'accepted_ms':t,'phase':p} for a,f,d,t,p in c.execute('SELECT attempt_id,fence_token,payload_digest,accepted_at_unix_ms,phase FROM attempts')]))",
            &[&self.root.path().join("agent.db")],
        )
    }

    async fn assert_bindings(&self, build: Uuid, summaries: &[Value]) {
        let rows: Vec<(Uuid, Uuid, i64, i64, String, Value)> = sqlx::query_as("SELECT a.id,n.id,a.restore_epoch,a.fence,a.lease_owner,n.execution_spec FROM attempts a JOIN nodes n ON n.organization_id=a.organization_id AND n.id=a.node_id WHERE a.organization_id=$1 AND n.build_id=$2 ORDER BY n.node_key,a.ordinal")
            .bind(self.org).bind(build).fetch_all(&self.pool).await.unwrap();
        assert_eq!(
            rows.len(),
            summaries.len(),
            "one actual attempt per input stage"
        );
        let journal = self.journal();
        let native = self.audit();
        for (attempt, node, restore_epoch, fence, owner, execution) in rows {
            assert_eq!(owner, AGENT);
            assert_eq!(execution["version"], 4);
            let wire_fence = (u64::from(u32::try_from(restore_epoch).unwrap()) << 32)
                | u64::from(u32::try_from(fence).unwrap());
            // Independent implementation of the wire commitment, not the production helper.
            let mut hash = Sha256::new();
            hash.update(b"mcloving.input-assignment/v1\0");
            for value in [
                self.org.to_string(),
                self.project.to_string(),
                self.pipeline.to_string(),
                build.to_string(),
                node.to_string(),
                attempt.to_string(),
            ] {
                hash.update((value.len() as u64).to_be_bytes());
                hash.update(value.as_bytes());
            }
            let bytes = serde_json::to_vec(&execution).unwrap();
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(&bytes);
            hash.update(wire_fence.to_be_bytes());
            let assignment: [u8; 32] = hash.finalize().into();
            let invocation = format!("sha256:{}", hex(&assignment));
            let row = journal
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["attempt"] == attempt.to_string())
                .unwrap();
            assert_eq!(row["fence"], wire_fence);
            assert_eq!(row["digest"], hex(&assignment));
            let accepted = row["accepted_ms"].as_i64().unwrap();
            let mut id_hash = Sha256::new();
            id_hash.update(b"mcloving.input-capture-id/v1\0");
            id_hash.update(assignment);
            let id_digest = id_hash.finalize();
            let mut id_bytes = [0u8; 16];
            id_bytes.copy_from_slice(&id_digest[..16]);
            id_bytes[6] = (id_bytes[6] & 0x0f) | 0x80;
            id_bytes[8] = (id_bytes[8] & 0x3f) | 0x80;
            let capture = Uuid::from_bytes(id_bytes);
            let request = CaptureRequest {
                capture_id: capture,
                organization_id: self.org,
                project_id: self.project,
                pipeline_id: self.pipeline,
                build_id: build,
                attempt_id: attempt,
                input_name: self.binding.input_name.clone(),
                adapter_id: self.config.adapter_id.clone(),
                expected_implementation_sha256: self.binding.executable_sha256.clone(),
                expected_config_sha256: self.binding.config_sha256.clone(),
                protocol_version: self.config.protocol_version.clone(),
                schema_version: self.config.schema_version.clone(),
                expected_generation: self.config.generation,
                rollback_from_generation: None,
                endpoint_identity: self.config.endpoint_identity.clone(),
                data_source_identity: self.config.data_source_identity.clone(),
                grant_id: self.config.grant_id.clone(),
                grant_version: self.config.grant_version.clone(),
                grant_scope: self.config.grant_scope.clone(),
                query: self.binding.query.clone(),
                expected_cursor: self.binding.expected_cursor.clone(),
                requested_at_unix_ms: accepted,
                expires_at_unix_ms: accepted
                    .checked_add(30_000)
                    .unwrap()
                    .min(self.config.grant_expires_unix_ms),
                confidentiality_ceiling: Confidentiality::Public,
                audit_lineage: invocation.clone(),
            };
            let request_hash = digest(&serde_json::to_vec(&request).unwrap());
            let summary = summaries
                .iter()
                .find(|s| s["invocation_id"] == invocation)
                .unwrap();
            assert_eq!(summary["capture_id"], capture.to_string());
            assert_eq!(summary["request_sha256"], request_hash);
            let receipt = native
                .iter()
                .find(|r| r["capture_id"] == capture.to_string())
                .unwrap();
            assert_eq!(receipt["request_sha256"], request_hash);
            for (field, expected) in [
                ("organization_id", self.org.to_string()),
                ("project_id", self.project.to_string()),
                ("pipeline_id", self.pipeline.to_string()),
                ("build_id", build.to_string()),
                ("attempt_id", attempt.to_string()),
                ("audit_lineage", invocation),
                (
                    "adapter_implementation_sha256",
                    self.binding.executable_sha256.clone(),
                ),
                ("adapter_config_sha256", self.binding.config_sha256.clone()),
                (
                    "deployment_identity",
                    self.config.deployment_identity.clone(),
                ),
                ("operator_identity", self.config.operator_identity.clone()),
                ("endpoint_identity", self.config.endpoint_identity.clone()),
                (
                    "data_source_identity",
                    self.config.data_source_identity.clone(),
                ),
                ("grant_id", self.config.grant_id.clone()),
                ("grant_version", self.config.grant_version.clone()),
                ("grant_scope", self.config.grant_scope.clone()),
                ("input_name", self.binding.input_name.clone()),
                ("adapter_id", self.config.adapter_id.clone()),
                ("schema_version", self.config.schema_version.clone()),
                ("protocol_version", self.config.protocol_version.clone()),
                ("signing_key_id", self.config.signing_key_id.clone()),
                (
                    "secret_marker_set_sha256",
                    self.config.secret_marker_set_sha256.clone(),
                ),
            ] {
                assert_eq!(receipt[field], expected, "native receipt {field}");
            }
            assert_eq!(receipt["generation"], self.config.generation);
            assert!(receipt["rollback_from_generation"].is_null());
            assert_eq!(
                receipt["canonical_query"],
                serde_json::to_value(&self.binding.query).unwrap()
            );
            assert_eq!(receipt["source_cursor"], "main-cursor-v1");
            assert_eq!(receipt["source_provenance"], "fixture://flags/v1");
            assert_eq!(receipt["source_etag"], "\"fixture-v1\"");
            assert_eq!(receipt["confidentiality"], "public");
            assert_eq!(receipt["retry_count"], 0);
            assert_eq!(
                receipt["response"],
                json!({"enabled":true,"value":std::str::from_utf8(CONTENT).unwrap()})
            );
            let captured = receipt["captured_at_unix_ms"].as_i64().unwrap();
            let observed = receipt["source_observed_at_unix_ms"].as_i64().unwrap();
            let deadline = receipt["publication_deadline_unix_ms"].as_i64().unwrap();
            assert!(
                accepted <= observed
                    && observed <= captured
                    && captured < request.expires_at_unix_ms
                    && captured < deadline
                    && deadline <= request.expires_at_unix_ms
                    && deadline <= self.config.grant_expires_unix_ms
            );
            assert!(captured - observed <= self.config.max_age_ms);
        }
    }

    async fn assert_private(&self, build: Uuid) {
        let logs = serde_json::to_vec(
            &self
                .client
                .logs(self.org, self.project, build)
                .await
                .unwrap(),
        )
        .unwrap();
        let response_bytes = serde_json::to_vec(
            &json!({"enabled":true,"value":std::str::from_utf8(CONTENT).unwrap()}),
        )
        .unwrap();
        let response_digest = digest(&response_bytes);
        let content_hex = hex(CONTENT);
        for marker in [
            response_digest.as_bytes(),
            response_bytes.as_slice(),
            content_hex.as_bytes(),
            CONTENT,
            BASE64.encode(CONTENT).as_bytes(),
            READ_TOKEN,
            RECEIPT_KEY,
            SECRET_MARKER,
            b"fixture://flags/v1",
            b"main-cursor-v1",
        ] {
            assert!(
                !logs.windows(marker.len()).any(|window| window == marker),
                "private marker escaped into API logs"
            );
            assert!(
                !directory_contains(&self.root.path().join("workspace"), marker),
                "private marker escaped into workspace"
            );
            for name in [
                "agent.db",
                "agent.db-wal",
                "agent.db-shm",
                "agent.log",
                "agent-errors.log",
            ] {
                let path = self.root.path().join(name);
                if path.exists() {
                    let bytes = std::fs::read(&path).unwrap();
                    assert!(
                        !bytes.windows(marker.len()).any(|window| window == marker),
                        "private marker escaped into {name}"
                    );
                }
            }
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
        stop(&mut self.provider).await;
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
            .chain(std::iter::once(&mut self.provider))
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
                .prefix("mcloving-input-product-failure-")
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
                        READ_TOKEN,
                        SECRET_MARKER,
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
                "input product failure diagnostics retained: {} (no fixture keys/config/database copied)",
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

async fn mixed_agent_mapping_eligibility(database: &str, mismatch: &str) {
    let mut h = Harness::new(database).await;
    let input_source = h.source(1);
    h.save(input_source).await;
    let input_build = h.submit("eligibility-input-first").await;
    let before_agent: Vec<(Uuid, String, Option<String>, i64)> = sqlx::query_as(
        "SELECT a.id,a.status,a.lease_owner,a.fence FROM attempts a JOIN nodes n ON n.id=a.node_id AND n.organization_id=a.organization_id WHERE a.organization_id=$1 AND n.build_id=$2",
    ).bind(h.org).bind(input_build).fetch_all(&h.pool).await.unwrap();
    assert_eq!(before_agent.len(), 1);
    assert_eq!(before_agent[0].1, "queued");
    assert!(before_agent[0].2.is_none());
    assert_eq!(before_agent[0].3, 0);
    // Queue a real ordinary job AFTER input. Its completed attempt proves the
    // mismatched agent actually polled/claimed work while input stayed queued.
    h.save("version: 1\nname: barrier\nstages:\n  - id: barrier\n    name: Barrier\n    steps:\n      - process:\n          program: /bin/true\n          timeout_seconds: 30\n".to_owned()).await;
    let barrier = h.submit("eligibility-process-barrier").await;
    let mut wrong = h.binding.clone();
    if mismatch == "mapping-id" {
        wrong.mapping_id = "disjoint-input".into();
    } else {
        wrong.query.insert("branch".into(), "other".into());
        assert_eq!(wrong.mapping_id, h.binding.mapping_id);
        assert_ne!(
            wrong.mapping_digest().unwrap(),
            h.binding.mapping_digest().unwrap()
        );
    }
    let bindings = h.root.path().join("other-bindings.json");
    write_private(
        &bindings,
        &serde_json::to_vec(&InputBindings {
            schema_version: "mcloving.agent-input-bindings/v1".into(),
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
        .env("MCLOVING_AGENT_INPUT_BINDINGS_PATH", &bindings)
        .env(
            "MCLOVING_AGENT_INPUT_BINDINGS_SHA256",
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
        .bind(h.org).bind(input_build).fetch_all(&h.pool).await.unwrap();
    assert_eq!(
        queued.len(),
        1,
        "only original admitted queued attempt exists"
    );
    assert_eq!(
        queued, before_agent,
        "real ineligible polling leaves original input attempt untouched"
    );
    assert_eq!(queued[0].1, "queued");
    assert!(
        queued[0].2.is_none(),
        "mismatched agent must never claim input"
    );
    assert_eq!(queued[0].3, 0);
    assert!(
        h.audit().is_empty(),
        "ineligible agent performs no input operation"
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
        "input assignment never reaches ineligible journal"
    );
    h.start_agent(None);
    assert_eq!(h.terminal(input_build).await, "succeeded");
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
        .bind(h.org).bind(input_build).fetch_one(&h.pool).await.unwrap();
    assert_eq!(claimed, (queued[0].0, AGENT.to_owned()));
    assert_eq!(h.audit().len(), 1);
    assert_eq!(h.summaries(input_build).await[0]["outcome"], "captured");
    h.assert_reads(1);
    h.assert_bindings(input_build, &h.summaries(input_build).await)
        .await;
    h.assert_private(input_build).await;
    h.finish().await;
}

#[tokio::test]
async fn submitted_input_jobs_execute_real_helper_without_authority_or_output_bypass() {
    let Ok(database) = std::env::var("MCLOVING_TEST_DATABASE_URL") else {
        eprintln!(
            "skipped: MCLOVING_TEST_DATABASE_URL is not configured; input product proof unavailable"
        );
        return;
    };
    for mismatch in ["mapping-id", "mapping-digest"] {
        mixed_agent_mapping_eligibility(&database, mismatch).await;
    }
    for variant in ["expired-grant", "unauthorized-query"] {
        let mut refused = Harness::with_variant(&database, variant).await;
        refused.save(refused.source(2)).await;
        refused.start_agent(None);
        let build = refused.submit(variant).await;
        assert_eq!(
            refused.terminal(build).await,
            "failed",
            "operator mapping variant {variant}"
        );
        refused.assert_reads(0);
        assert!(refused.audit().is_empty());
        assert!(
            !refused.config.spool_dir.exists(),
            "preexecution refusal cannot initialize helper spool"
        );
        assert_downstream_skipped(&refused, build).await;
        refused.assert_private(build).await;
        refused.finish().await;
    }
    let mut h = Harness::new(&database).await;
    h.save(h.source(1)).await;
    h.start_agent(None);
    std::fs::write(h.root.path().join("provider-mode"), "observe-seal").unwrap();
    let build = h.submit("input-positive").await;
    h.observe_sealed_helper().await;
    std::fs::write(h.root.path().join("provider-mode"), "valid").unwrap();
    assert_eq!(h.terminal(build).await, "succeeded");
    let summaries = h.summaries(build).await;
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0]["outcome"], "captured");
    h.assert_bindings(build, &summaries).await;
    h.assert_reads(1);
    assert_eq!(h.audit().len(), 1);
    h.assert_private(build).await;
    // Saved-submit replay reuses the original build without a second capture.
    assert_eq!(h.submit("input-positive").await, build);
    h.assert_reads(1);
    let builds = h.build_count().await;
    let good = h.source(1);
    for (bad, code) in [
        (
            good.replace("mapping_id: product-input", "mapping_id: unknown"),
            "input_mapping_denied",
        ),
        (
            good.replace(
                &h.binding.mapping_digest().unwrap(),
                &format!("sha256:{}", "0".repeat(64)),
            ),
            "input_mapping_denied",
        ),
        (
            good.replace(
                "timeout_seconds: 30",
                "timeout_seconds: 30\n          query: {branch: attacker}",
            ),
            "pipeline_rejected",
        ),
        (
            good.replace(
                "timeout_seconds: 30",
                "timeout_seconds: 30\n          endpoint_url: http://attacker.invalid",
            ),
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
                        slug: "input-product".into(),
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
        &["input_mapping_denied"],
    );
    for (platform, pool) in [("windows", "trusted-linux"), ("linux", "untrusted")] {
        assert_denied(
            h.client
                .submit_pipeline_on_platform_in_pool(
                    h.org,
                    h.project,
                    h.pipeline,
                    "input-positive",
                    platform,
                    pool,
                    &PipelineBuildRequest::default(),
                )
                .await,
            &["input_mapping_denied"],
        );
    }
    assert_eq!(h.build_count().await, builds);
    h.assert_reads(1);
    assert_eq!(h.audit().len(), 1);
    eprintln!(
        "input product: real API submit, exact scheduling, native receipt/journal/request linkage, private-output and admission gates passed"
    );
    // Actual provider failures execute one authorized read and block downstream.
    h.save(h.source(2)).await;
    let mut reads = 1;
    for mode in [
        "cursor",
        "stale",
        "future",
        "secret",
        "marker",
        "escaped_marker",
        "duplicate",
        "trailing",
        "schema",
    ] {
        std::fs::write(h.root.path().join("provider-mode"), mode).unwrap();
        let rejected = h.submit(&format!("input-provider-{mode}")).await;
        assert_eq!(h.terminal(rejected).await, "failed", "provider mode {mode}");
        reads += 1;
        h.assert_reads(reads);
        assert_eq!(
            h.audit().len(),
            1,
            "rejected provider response cannot publish native receipt"
        );
        assert_downstream_skipped(&h, rejected).await;
        h.assert_private(rejected).await;
    }
    std::fs::write(h.root.path().join("provider-mode"), "valid").unwrap();
    // Substituted private files cannot bypass the startup-frozen mapping pins.
    for (label, path, replacement) in [
        ("config", h.binding.config_path.clone(), b"{}".to_vec()),
        (
            "key",
            h.binding.signing_key_path.clone(),
            b"substituted-receipt-key-32-bytes-minimum".to_vec(),
        ),
        (
            "token",
            h.binding.read_token_path.clone(),
            b"substituted-provider-token-32-bytes-minimum".to_vec(),
        ),
        (
            "markers",
            h.binding.secret_markers_path.clone(),
            b"substituted-secret-marker".to_vec(),
        ),
        (
            "executable",
            h.binding.executable.clone(),
            b"#!/bin/sh\nexit 0\n".to_vec(),
        ),
    ] {
        let original = std::fs::read(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        write_private(&path, &replacement, mode);
        let rejected = h.submit(&format!("input-substituted-{label}")).await;
        assert_eq!(h.terminal(rejected).await, "failed", "substitution {label}");
        h.assert_reads(reads);
        // Restore before authenticating historical receipts using the original key.
        write_private(&path, &original, mode);
        assert_eq!(h.audit().len(), 1);
        assert_downstream_skipped(&h, rejected).await;
        h.assert_private(rejected).await;
    }
    eprintln!(
        "input product: actual provider rejection and private-file substitution gates passed"
    );
    h.stop_agent().await;
    h.save(h.source(1)).await;
    h.start_agent(Some("MCLOVING_TEST_CRASH_AFTER_HELPER_RECEIPT"));
    let uncertain = h.submit("input-uncertain").await;
    let exit = tokio::time::timeout(Duration::from_secs(45), h.agent.as_mut().unwrap().wait())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(exit.code(), Some(87));
    h.agent.take();
    reads += 1;
    h.assert_reads(reads);
    let before_restart = h.audit();
    assert_eq!(before_restart.len(), 2);
    let journal_before = h.journal();
    let running: Vec<_> = journal_before
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["phase"] == "running")
        .cloned()
        .collect();
    assert_eq!(running.len(), 1);
    assert!(running[0]["accepted_ms"].as_i64().unwrap() > 0);
    // Build a public-shaped observation from authenticated native receipt solely
    // to reuse independent request recomputation for the crash window. This is
    // not credited as successful public output or terminal product completion.
    let receipt = before_restart
        .iter()
        .find(|r| r["build_id"] == uncertain.to_string())
        .unwrap();
    h.assert_bindings(uncertain,&[json!({"invocation_id":receipt["audit_lineage"],"capture_id":receipt["capture_id"],"request_sha256":receipt["request_sha256"]})]).await;
    h.start_agent(None);
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let errors = std::fs::read_to_string(h.root.path().join("agent-errors.log")).unwrap();
            if errors.contains("unresolved recovered attempt and will not poll for more work") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("recovery explicitly parks ambiguous invocation");
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert_ne!(
        h.client
            .status(h.org, h.project, uncertain)
            .await
            .unwrap()
            .status,
        "succeeded"
    );
    h.assert_reads(reads);
    assert_eq!(h.audit(), before_restart);
    let journal_after = h.journal();
    let retained: Vec<_> = journal_after
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["attempt"] == running[0]["attempt"])
        .collect();
    assert_eq!(retained.len(), 1);
    for field in ["attempt", "fence", "digest", "accepted_ms"] {
        assert_eq!(
            retained[0][field], running[0][field],
            "recovery retains original {field}"
        );
    }
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM attempts a JOIN nodes n ON n.id=a.node_id AND n.organization_id=a.organization_id WHERE a.organization_id=$1 AND n.build_id=$2").bind(h.org).bind(uncertain).fetch_one(&h.pool).await.unwrap();
    assert_eq!(count, 1);
    h.assert_private(uncertain).await;
    h.finish().await;
    // Separate fixture: parked ambiguity never gets erased to run the replay case.
    let mut h = Harness::new(&database).await;
    h.save(h.source(1)).await;
    h.start_agent(Some("MCLOVING_TEST_CRASH_AFTER_TERMINAL_COMMIT"));
    let replay = h.submit("input-terminal-replay").await;
    let exit = tokio::time::timeout(Duration::from_secs(45), h.agent.as_mut().unwrap().wait())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(exit.code(), Some(86));
    h.agent.take();
    h.assert_reads(1);
    let before = h.audit();
    assert_eq!(before.len(), 1);
    let journal_before = h.journal();
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
    h.assert_reads(1);
    assert_eq!(h.audit(), before);
    let summaries = h.summaries(replay).await;
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0]["outcome"], "captured");
    h.assert_bindings(replay, &summaries).await;
    let journal_after = h.journal();
    assert_eq!(journal_before.as_array().unwrap().len(), 1);
    assert_eq!(journal_after.as_array().unwrap().len(), 1);
    for field in ["attempt", "fence", "digest", "accepted_ms"] {
        assert_eq!(journal_before[0][field], journal_after[0][field]);
    }
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM build_events WHERE organization_id=$1 AND build_id=$2 AND kind='attempt.terminal'").bind(h.org).bind(replay).fetch_one(&h.pool).await.unwrap();
    assert_eq!(count, 1);
    h.assert_private(replay).await;
    h.finish().await;
    eprintln!(
        "input product: crash after real capture parks original identity without provider replay; terminal commit replays one result without recapture"
    );
}

async fn assert_downstream_skipped(h: &Harness, build: Uuid) {
    let status: String = sqlx::query_scalar(
        "SELECT status FROM nodes WHERE organization_id=$1 AND build_id=$2 AND node_key='input1'",
    )
    .bind(h.org)
    .bind(build)
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(
        status, "skipped",
        "failed capture prevents downstream execution"
    );
}

async fn start_provider(root: &Path) -> Child {
    // The counter observes every HTTP request before serving it, including
    // unknown methods, bad authority and bad paths. No hidden endpoint mutates data.
    let script = r#"import http.server,json,pathlib,sys,time,os
root=pathlib.Path(sys.argv[1]); counter=root/'provider-requests.jsonl';counter.write_text('')
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args): pass
 def handle_request(self):
  authorized=self.headers.get('Authorization')=='Bearer fixture-input-provider-read-token-32-bytes' and self.headers.get('x-mcloving-grant-scope')=='flags:read' and self.headers.get('x-mcloving-grant-id')=='fixture-read-grant' and self.headers.get('x-mcloving-grant-version')=='1'
  with counter.open('a') as f:
   f.write(json.dumps({'method':self.command,'path':self.path,'authorized':authorized})+'\n');f.flush();os.fsync(f.fileno())
  if self.command!='GET' or self.path!='/input?branch=main' or not authorized:
   self.send_response(403);self.send_header('Content-Length','0');self.end_headers();return
  mode=(root/'provider-mode').read_text()
  if mode=='observe-seal':
   deadline=time.monotonic()+10
   while not (root/'provider-release').exists():
    assert time.monotonic()<deadline,'sealed native process observer did not release provider'
    time.sleep(0.005)
  now=int(time.time()*1000)
  body=json.dumps({'enabled':True,'value':'distinctive-input-content-not-public-result-1957'},separators=(',',':'))
  if mode=='marker':body=json.dumps({'enabled':True,'value':'fixture-input-secret-marker-never-disclose'})
  if mode=='escaped_marker':body='{"enabled":true,"value":"fixture-input-secret-marker-never-\\u0064isclose"}'
  if mode=='duplicate':body='{"enabled":true,"value":"safe","value":"other"}'
  if mode=='trailing':body+=' {}'
  if mode=='schema':body='{"enabled":"wrong","value":"safe"}'
  body=body.encode();self.send_response(200)
  for key,value in [('Content-Type','application/json'),('Content-Length',str(len(body))),('x-mcloving-cursor','wrong-cursor' if mode=='cursor' else 'main-cursor-v1'),('x-mcloving-observed-at-ms',str(now-60000 if mode=='stale' else now+60000 if mode=='future' else now)),('x-mcloving-confidentiality','secret' if mode=='secret' else 'public'),('x-mcloving-provenance','fixture://flags/v1'),('etag','"fixture-v1"')]:self.send_header(key,value)
  self.end_headers();self.wfile.write(body)
 def __getattr__(self,name):
  if name.startswith('do_'):return self.handle_request
  raise AttributeError(name)
server=http.server.HTTPServer(('127.0.0.1',0),Handler)
(root/'provider-endpoint').write_text('http://127.0.0.1:'+str(server.server_port)+'/input')
server.serve_forever()
"#;
    let script_path = root.join("provider.py");
    write_private(&script_path, script.as_bytes(), 0o400);
    std::fs::write(root.join("provider-mode"), "valid").unwrap();
    let mut child = Command::new("python3")
        .arg(&script_path)
        .arg(root)
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(root.join("provider-errors.log")).unwrap())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !root.join("provider-endpoint").exists() {
            assert!(
                child.try_wait().unwrap().is_none(),
                "provider fixture unexpectedly exited"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("counted provider starts");
    child
}

fn now_ms() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
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
    if path.exists() {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
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
