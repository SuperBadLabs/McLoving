//! Actual submitted-job checkout gate (PAR-012). A saved pipeline with a
//! `checkout` step is submitted through the API, claimed by the shipped agent,
//! acquired by the shipped sealed source acquirer, published into the attempt
//! workspace, and built by the following process step. Helper-library calls
//! and fabricated assignments never serve as positive execution evidence here.
#![cfg(target_os = "linux")]

use mcloving_agent::source::{SourceBinding, SourceBindings, SourceLauncher};
use mcloving_controller_api::{Client, ClientError, PipelineBuildRequest, PipelineUpsertRequest};
use mcloving_controller_store::Store;
use mcloving_source_acquirer::{
    PROTOCOL_VERSION, RepositoryBinding, SourceConfig, content_sha256, inspect_runtime_closure,
    marker_set_digest, runtime_closure_digest, sha256_file,
};
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

const TOKEN: &str = "contained-source-product-test-token";
const AGENT: &str = "source-product-agent";
const OTHER_AGENT: &str = "source-product-ineligible-agent";
const CREDENTIAL: &[u8] = b"fixture-source-credential-never-disclosed-1957";
const SIGNING_KEY: &[u8] = b"synthetic-source-fixture-signing-key-32-bytes";
const PROFILE: &str = "mcloving-source-acquirer";
const TRANSPORT_ROOT: &str = "/tmp/mcloving-source-transport-16m";
const TRANSPORT_CAPACITY: u64 = 16 * 1_024 * 1_024;
const CA_BUNDLE: &str = "/etc/ssl/certs/ca-certificates.crt";

/// Where the checkout comes from: a file repository this harness seeds, or a
/// real https repository named by the environment for the owner's proof.
struct Origin {
    provider_identity: String,
    repository_identity: String,
    repository_url: String,
    /// The branch head, which the pipeline requests.
    commit: String,
    /// For the seeded repository: the head's parent, which its README names.
    seed: Option<String>,
    /// File repositories are a fixture-only acquirer opt-in.
    test_mode: bool,
}

impl Origin {
    fn seeded(root: &Path) -> Self {
        let repository = seed_repository(root);
        Self {
            provider_identity: "fixture-git".to_owned(),
            repository_identity: "fixture/product".to_owned(),
            repository_url: url::Url::from_file_path(&repository.bare)
                .unwrap()
                .to_string(),
            commit: repository.commit,
            seed: Some(repository.seed),
            test_mode: true,
        }
    }
    fn https(url: &str, commit: &str) -> Self {
        let parsed = url::Url::parse(url).expect("https repository URL");
        assert_eq!(parsed.scheme(), "https");
        Self {
            provider_identity: parsed.host_str().expect("repository host").to_owned(),
            repository_identity: parsed
                .path()
                .trim_matches('/')
                .trim_end_matches(".git")
                .to_owned(),
            repository_url: url.to_owned(),
            commit: commit.to_owned(),
            seed: None,
            test_mode: false,
        }
    }
}

struct Repository {
    bare: PathBuf,
    commit: String,
    seed: String,
}

struct Harness {
    pool: sqlx::PgPool,
    client: Client,
    org: Uuid,
    project: Uuid,
    pipeline: Uuid,
    revision: i64,
    binding: SourceBinding,
    origin: Origin,
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
        Self::with_origin(migration_url, None).await
    }

    async fn with_origin(migration_url: &str, origin: Option<Origin>) -> Self {
        // This explicitly supplied fixture URL is never inherited by the agent.
        let controller_binary = PathBuf::from(
            std::env::var_os("MCLOVING_CONTROLLER_BINARY").expect("shipped controller required"),
        );
        let acquirer_binary = std::fs::canonicalize(
            std::env::var_os("MCLOVING_SOURCE_ACQUIRER_BINARY")
                .expect("shipped source acquirer required"),
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
            .create_project(org, &format!("source-{org}"), project, "source-product")
            .await
            .unwrap();
        // The acquirer refuses an output root whose parent is not canonical,
        // so the whole fixture lives under the canonical temp path.
        let root = tempfile::Builder::new()
            .prefix("mcloving-source-product-")
            .disable_cleanup(std::env::var_os("MCLOVING_TEST_KEEP_ROOT").is_some())
            .tempdir_in(std::fs::canonicalize(std::env::temp_dir()).unwrap())
            .unwrap();
        eprintln!("fixture root: {}", root.path().display());
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let private = root.path().join("source-private");
        std::fs::create_dir(&private).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        let origin = origin.unwrap_or_else(|| Origin::seeded(root.path()));
        let executable = private.join("source-acquirer");
        std::fs::copy(&acquirer_binary, &executable).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o500)).unwrap();
        let executable_sha256 = digest(&std::fs::read(&executable).unwrap());
        let git = git_executable();
        let git_remote_https = git_remote_https_executable(&git);
        let runtime_closure =
            inspect_runtime_closure(&[git.clone(), git_remote_https.clone(), executable.clone()])
                .await
                .expect("runtime closure of the shipped acquirer");
        // The output root shares the workspace root's filesystem, which the
        // no-replace rename publication requires. The transport root must be
        // a dedicated filesystem of exactly the configured capacity, which
        // the acquirer verifies; it is the same bounded tmpfs the acquirer's
        // own suite uses, prepared by
        // scripts/prepare-source-transport-test-filesystems.sh, and shared
        // host-wide, so this gate must not run concurrently with that suite.
        let output_root = root.path().join("source-output");
        let transport_root = PathBuf::from(TRANSPORT_ROOT);
        assert!(
            transport_root.is_dir(),
            "{TRANSPORT_ROOT} is missing: run scripts/prepare-source-transport-test-filesystems.sh"
        );
        let config = SourceConfig {
            protocol_version: PROTOCOL_VERSION.to_owned(),
            schema_version: "source-acquisition-v1".to_owned(),
            acquirer_id: "product-source-acquirer".to_owned(),
            deployment_identity: "fixture-source-deployment".to_owned(),
            operator_identity: "fixture-independent-operator".to_owned(),
            generation: 1,
            primary_repository: RepositoryBinding {
                provider_identity: origin.provider_identity.clone(),
                repository_identity: origin.repository_identity.clone(),
                repository_url: origin.repository_url.clone(),
            },
            allow_untrusted_forks: false,
            allowed_fork_repositories: Vec::new(),
            allowed_submodule_repositories: Vec::new(),
            allowed_ref_prefixes: vec!["refs/heads/".to_owned()],
            allowed_sparse_roots: Vec::new(),
            git_executable_path: git.clone(),
            git_executable_sha256: sha256_file(&git).await.unwrap(),
            git_remote_https_executable_path: git_remote_https.clone(),
            git_remote_https_executable_sha256: sha256_file(&git_remote_https).await.unwrap(),
            runtime_closure_sha256: runtime_closure_digest(&runtime_closure).unwrap(),
            runtime_closure,
            git_version: git_version(&git),
            grant_id: "fixture-read-grant".to_owned(),
            grant_version: "grant-v1".to_owned(),
            grant_scope: "repository:read".to_owned(),
            grant_expires_unix_ms: now_ms() + 600_000,
            credential_username: "git".to_owned(),
            credential_sha256: content_sha256(CREDENTIAL),
            receipt_signing_key_id: "fixture-signing-key-v1".to_owned(),
            receipt_signing_key_sha256: content_sha256(SIGNING_KEY),
            secret_marker_set_sha256: marker_set_digest(&[CREDENTIAL.to_vec()]),
            max_depth: 8,
            max_files: 1_000,
            max_total_bytes: 4 * 1_024 * 1_024,
            max_file_bytes: 1_024 * 1_024,
            max_transport_bytes: TRANSPORT_CAPACITY,
            max_path_bytes: 512,
            max_submodules: 0,
            command_timeout_ms: 30_000,
            transport_root,
            output_root,
            // A real https origin verifies the server against the system
            // bundle, pinned by digest like every other acquirer input.
            ca_bundle_path: (!origin.test_mode).then(|| PathBuf::from(CA_BUNDLE)),
            ca_bundle_sha256: (!origin.test_mode)
                .then(|| digest(&std::fs::read(CA_BUNDLE).expect("system CA bundle"))),
            test_allow_file_repositories: origin.test_mode,
            test_allow_http_loopback: false,
        };
        let config_path = private.join("config.json");
        write_private(&config_path, &serde_json::to_vec(&config).unwrap(), 0o400);
        let credential_path = private.join("credential");
        write_private(&credential_path, CREDENTIAL, 0o400);
        let signing_key_path = private.join("signing.key");
        write_private(&signing_key_path, SIGNING_KEY, 0o400);
        let secret_markers_path = private.join("markers");
        write_private(&secret_markers_path, &[CREDENTIAL, b"\n"].concat(), 0o400);
        let binding = SourceBinding {
            mapping_id: "product-source".into(),
            organization_id: org.to_string(),
            project_id: project.to_string(),
            pipeline_id: pipeline.to_string(),
            trust_pool: "trusted-linux".into(),
            executable,
            executable_sha256,
            config_path,
            config_sha256: config.canonical_digest().unwrap(),
            credential_path,
            signing_key_path,
            secret_markers_path,
            launcher: launcher(),
            test_mode: origin.test_mode,
        };
        let bindings = SourceBindings {
            schema_version: "mcloving.agent-source-bindings/v1".into(),
            mappings: vec![binding.clone()],
        };
        write_private(
            &root.path().join("agent-bindings.json"),
            &serde_json::to_vec(&bindings).unwrap(),
            0o400,
        );
        let catalog = json!({"schema_version":"mcloving.source-mapping-catalog/v1","profile":"product-fixture","generation":1,"mappings":[{
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
                "source-product-artifact-token-32-bytes",
            )
            .env("MCLOVING_LISTEN", format!("127.0.0.1:{api_port}"))
            .env("MCLOVING_AGENT_LISTEN", format!("127.0.0.1:{agent_port}"))
            .env("MCLOVING_AGENT_SERVER_CERT_PATH", &tls.server_certificate)
            .env("MCLOVING_AGENT_SERVER_KEY_PATH", &tls.server_key)
            .env("MCLOVING_AGENT_CLIENT_CA_PATH", &tls.ca_certificate)
            .env("MCLOVING_AGENT_IDENTITY_BINDINGS_PATH", &tls.bindings)
            .env("MCLOVING_SOURCE_MAPPING_CATALOG", &catalog_path)
            .env(
                "MCLOVING_SOURCE_MAPPING_CATALOG_SHA256",
                digest(&std::fs::read(&catalog_path).unwrap()),
            )
            .env("MCLOVING_ORGANIZATION_ID", org.to_string())
            .env("MCLOVING_AGENT_ID", "source-embedded-disabled")
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
            !config.output_root.exists(),
            "fixture must not create the acquirer's output root before product invokes it"
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
            origin,
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
            .env("MCLOVING_AGENT_SOURCE_BINDINGS_PATH", &bindings)
            .env(
                "MCLOVING_AGENT_SOURCE_BINDINGS_SHA256",
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

    fn start_agent(&mut self) {
        assert!(self.agent.is_none());
        self.agent = Some(self.agent_command().kill_on_drop(true).spawn().unwrap());
    }

    async fn stop_agent(&mut self) {
        if let Some(mut agent) = self.agent.take() {
            stop(&mut agent).await;
        }
    }

    fn checkout_step(&self, destination: &str) -> String {
        format!(
            "      - checkout:\n          mapping_id: {}\n          mapping_digest: {}\n          ref: refs/heads/main\n          commit: {}\n          destination: {destination}\n          timeout_seconds: 120\n",
            self.binding.mapping_id,
            self.binding.mapping_digest().unwrap(),
            self.origin.commit
        )
    }

    fn source(&self, steps: &str) -> String {
        format!(
            "version: 1\nname: source-product\nstages:\n  - id: build\n    name: Build\n    steps:\n{steps}"
        )
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
                    slug: "source-product".into(),
                    source,
                    parameters: Default::default(),
                },
            )
            .await
            .expect("API saves scoped checkout source");
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
            .expect("API submits checkout job")
            .build_id
    }
    async fn terminal(&self, build: Uuid) -> mcloving_controller_api::BuildResponse {
        tokio::time::timeout(Duration::from_secs(120), async {
            loop {
                let status = self
                    .client
                    .status(self.org, self.project, build)
                    .await
                    .unwrap();
                if matches!(status.status.as_str(), "succeeded" | "failed" | "aborted") {
                    return status;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("actual checkout job reaches bounded terminal result")
    }
    /// Every log chunk of the build, keyed by step ordinal, with the private
    /// material proven absent from all of it.
    async fn logs(&self, build: Uuid) -> Vec<(i32, String, String)> {
        let logs = self
            .client
            .logs(self.org, self.project, build)
            .await
            .unwrap();
        let mut chunks = Vec::new();
        for log in logs {
            let text = log.text.unwrap_or_default();
            assert!(!text.contains(std::str::from_utf8(CREDENTIAL).unwrap()));
            assert!(!text.contains(std::str::from_utf8(SIGNING_KEY).unwrap()));
            chunks.push((log.step_ordinal, log.stream, text));
        }
        chunks
    }
    fn invocation_summary(chunks: &[(i32, String, String)], ordinal: i32) -> Value {
        let text = chunks
            .iter()
            .find(|(step, stream, _)| *step == ordinal && stream == "stdout")
            .map(|(_, _, text)| text.clone())
            .expect("checkout step wrote its public summary");
        let lines = text.lines().filter(|l| !l.is_empty()).collect::<Vec<_>>();
        assert_eq!(lines.len(), 1, "one typed summary line: {text}");
        let value: Value = serde_json::from_str(lines[0]).expect("typed public source summary");
        assert_eq!(value["protocol"], "mcloving.source-invocation/v1");
        value
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
            for name in ["agent-errors.log", "controller-errors.log", "agent.log"] {
                if let Ok(text) = std::fs::read_to_string(self.root.path().join(name)) {
                    eprintln!("== {name}\n{text}");
                }
            }
        }
    }
}

/// An ineligible agent, one whose source binding names a different mapping,
/// must never claim a checkout build even while it serves other work; the
/// binding capability is what routes the node.
async fn mixed_agent_mapping_eligibility(h: &mut Harness) {
    let checkout = h.source(&format!(
        "{}      - process:\n          program: /bin/true\n",
        h.checkout_step("source")
    ));
    h.save(checkout).await;
    let checkout_build = h.submit("eligibility-checkout-first").await;
    h.save("version: 1\nname: barrier\nstages:\n  - id: barrier\n    name: Barrier\n    steps:\n      - process:\n          program: /bin/true\n          timeout_seconds: 30\n".to_owned()).await;
    let barrier = h.submit("eligibility-process-barrier").await;
    let mut wrong = h.binding.clone();
    wrong.mapping_id = "disjoint-source".into();
    let bindings = h.root.path().join("other-bindings.json");
    write_private(
        &bindings,
        &serde_json::to_vec(&SourceBindings {
            schema_version: "mcloving.agent-source-bindings/v1".into(),
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
        .env("MCLOVING_AGENT_SOURCE_BINDINGS_PATH", &bindings)
        .env(
            "MCLOVING_AGENT_SOURCE_BINDINGS_SHA256",
            digest(&std::fs::read(&bindings).unwrap()),
        )
        .stdout(std::fs::File::create(h.root.path().join("other-agent.log")).unwrap())
        .stderr(std::fs::File::create(h.root.path().join("other-agent-errors.log")).unwrap())
        .kill_on_drop(true)
        .spawn()
        .unwrap(),
    );
    assert_eq!(h.terminal(barrier).await.status, "succeeded");
    let owner: String = sqlx::query_scalar("SELECT a.lease_owner FROM attempts a JOIN nodes n ON n.id=a.node_id AND n.organization_id=a.organization_id WHERE a.organization_id=$1 AND n.build_id=$2 AND a.status='succeeded'")
        .bind(h.org).bind(barrier).fetch_one(&h.pool).await.unwrap();
    assert_eq!(
        owner, OTHER_AGENT,
        "ineligible agent must actually complete the scheduler barrier"
    );
    let queued: Vec<(String, Option<String>)> = sqlx::query_as("SELECT a.status,a.lease_owner FROM attempts a JOIN nodes n ON n.id=a.node_id AND n.organization_id=a.organization_id WHERE a.organization_id=$1 AND n.build_id=$2")
        .bind(h.org).bind(checkout_build).fetch_all(&h.pool).await.unwrap();
    assert_eq!(queued.len(), 1);
    assert_eq!(
        queued[0].0, "queued",
        "checkout stayed queued for the bound agent"
    );
    assert!(queued[0].1.is_none());
    if let Some(mut agent) = h.other_agent.take() {
        stop(&mut agent).await;
    }
    // The eligible agent then runs exactly that build.
    h.start_agent();
    let status = h.terminal(checkout_build).await;
    assert_eq!(status.status, "succeeded", "{:?}", status.terminal_summary);
    h.stop_agent().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn submitted_checkout_lands_the_exact_commit_and_the_next_step_builds_in_it() {
    let Ok(database) = std::env::var("MCLOVING_TEST_DATABASE_URL") else {
        eprintln!(
            "skipped: MCLOVING_TEST_DATABASE_URL is not configured; checkout product proof unavailable"
        );
        return;
    };
    let mut h = Harness::new(&database).await;
    mixed_agent_mapping_eligibility(&mut h).await;

    // The product path: checkout, then a build step that reads the tree,
    // runs the repository's own script, and writes into the checkout.
    let source = h.source(&format!(
        "{}      - process:\n          program: /bin/sh\n          args: [\"-ec\", \"cat source/README; ./source/run-tests.sh; echo built > source/build-output; test ! -e source/.git\"]\n          timeout_seconds: 30\n",
        h.checkout_step("source")
    ));
    h.save(source).await;
    h.start_agent();
    let build = h.submit("checkout-positive").await;
    let status = h.terminal(build).await;
    assert_eq!(status.status, "succeeded", "{:?}", status.terminal_summary);
    let summary = status
        .terminal_summary
        .expect("terminal summary is published");
    let steps = summary["steps"].as_array().expect("multi-step summary");
    assert_eq!(steps.len(), 2, "{summary}");
    assert_eq!(steps[0]["outcome"], "succeeded");
    assert_eq!(steps[1]["outcome"], "succeeded");
    let chunks = h.logs(build).await;
    let invocation = Harness::invocation_summary(&chunks, 0);
    assert_eq!(invocation["outcome"], "acquired", "{invocation}");
    assert_eq!(invocation["mapping_id"], "product-source");
    assert_eq!(invocation["destination"], "source");
    assert_eq!(invocation["resolved_commit"], h.origin.commit);
    assert_eq!(invocation["materialized_files"], 2);
    let build_output = chunks
        .iter()
        .find(|(step, stream, _)| *step == 1 && stream == "stdout")
        .map(|(_, _, text)| text.clone())
        .expect("build step output");
    assert!(
        build_output.contains(&format!(
            "hello from {}",
            h.origin.seed.as_deref().expect("seeded origin")
        )),
        "{build_output}"
    );
    assert!(build_output.contains("tests-ok"), "{build_output}");
    // The acquirer's own output root holds no tree any more: publication
    // moved it rather than copying it, and nothing private went with it.
    let output_root = h.root.path().join("source-output");
    let acquisitions = std::fs::read_dir(&output_root)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .collect::<Vec<_>>();
    assert!(
        !acquisitions.is_empty(),
        "the acquirer retained its receipt"
    );
    for acquisition in acquisitions {
        assert!(!acquisition.path().join("tree").exists());
        assert!(acquisition.path().join("receipt.json").exists());
    }
    for marker in [CREDENTIAL, SIGNING_KEY] {
        assert!(
            !directory_contains(&h.root.path().join("workspace"), marker),
            "private source material escaped to the agent workspace"
        );
    }

    // A destination an earlier step pre-created is refused by name, and the
    // stage stops there: nothing is written through the planted link.
    let elsewhere = h.root.path().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    let planted = h.source(&format!(
        "      - process:\n          program: /bin/sh\n          args: [\"-ec\", \"ln -s {} source\"]\n          timeout_seconds: 30\n{}      - process:\n          program: /bin/true\n",
        elsewhere.display(),
        h.checkout_step("source")
    ));
    h.save(planted).await;
    let build = h.submit("checkout-planted-destination").await;
    let status = h.terminal(build).await;
    assert_eq!(status.status, "failed");
    let summary = status
        .terminal_summary
        .expect("terminal summary is published");
    let steps = summary["steps"].as_array().expect("multi-step summary");
    assert_eq!(
        steps.len(),
        2,
        "the step after the refused checkout never ran: {summary}"
    );
    assert_eq!(steps[1]["outcome"], "failed");
    assert_eq!(
        steps[1]["reason"], "checkout_publication_rejected:checkout_destination_preexists:source",
        "{summary}"
    );
    assert_eq!(
        summary["reason"],
        "checkout_publication_rejected:checkout_destination_preexists:source"
    );
    let chunks = h.logs(build).await;
    let invocation = Harness::invocation_summary(&chunks, 1);
    assert_eq!(
        invocation["outcome"], "acquired",
        "the acquisition itself succeeded"
    );
    assert!(
        std::fs::read_dir(&elsewhere).unwrap().next().is_none(),
        "nothing was written through the planted link"
    );

    // API refusals create no build: an unknown mapping, a wrong digest, a
    // malformed commit, and the Windows platform.
    let builds = h.build_count().await;
    let good = h.source(&format!(
        "{}      - process:\n          program: /bin/true\n",
        h.checkout_step("source")
    ));
    for (bad, code) in [
        (
            good.replace("mapping_id: product-source", "mapping_id: unknown"),
            "source_mapping_denied",
        ),
        (
            good.replace(
                &h.binding.mapping_digest().unwrap(),
                &format!("sha256:{}", "0".repeat(64)),
            ),
            "source_mapping_denied",
        ),
        (good.replace(&h.origin.commit, "main"), "pipeline_rejected"),
        (
            good.replace("destination: source", "destination: ../escape"),
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
                        slug: "source-product".into(),
                        source: bad,
                        parameters: Default::default(),
                    },
                )
                .await,
            &[code],
        );
    }
    h.save(good).await;
    assert_denied(
        h.client
            .submit_pipeline_on_platform_in_pool(
                h.org,
                h.project,
                h.pipeline,
                "checkout-on-windows",
                "windows",
                "trusted-windows",
                &PipelineBuildRequest::default(),
            )
            .await,
        &["unsupported_execution_spec", "source_mapping_denied"],
    );
    assert_eq!(h.build_count().await, builds, "refusals create no build");
    h.finish().await;
}

/// The owner's proof: a real GitHub repository over https, checked out at an
/// exact commit through the product path, with the repository's own command
/// run in the checkout by the next step. Configured by
/// `MCLOVING_TEST_GITHUB_REPOSITORY_URL`, `MCLOVING_TEST_GITHUB_COMMIT` (the
/// branch head) and `MCLOVING_TEST_GITHUB_COMMAND` (shell text run inside the
/// checkout); skipped otherwise, since Foundation runners hold no network
/// evidence this ticket may claim.
#[tokio::test(flavor = "multi_thread")]
async fn submitted_checkout_of_a_github_repository_when_configured() {
    let (Ok(database), Ok(url), Ok(commit), Ok(command)) = (
        std::env::var("MCLOVING_TEST_DATABASE_URL"),
        std::env::var("MCLOVING_TEST_GITHUB_REPOSITORY_URL"),
        std::env::var("MCLOVING_TEST_GITHUB_COMMIT"),
        std::env::var("MCLOVING_TEST_GITHUB_COMMAND"),
    ) else {
        eprintln!("skipped: GitHub checkout proof is not configured");
        return;
    };
    let reference =
        std::env::var("MCLOVING_TEST_GITHUB_REF").unwrap_or_else(|_| "refs/heads/main".to_owned());
    let mut h = Harness::with_origin(&database, Some(Origin::https(&url, &commit))).await;
    let source = h.source(&format!(
        "{}      - process:\n          program: /bin/sh\n          args: [\"-ec\", \"cd source && {}\"]\n          timeout_seconds: 600\n",
        h.checkout_step("source")
            .replace("ref: refs/heads/main", &format!("ref: {reference}")),
        command.replace('"', "\\\"")
    ));
    h.save(source).await;
    h.start_agent();
    let build = h.submit("checkout-github-proof").await;
    let status = h.terminal(build).await;
    let summary = status
        .terminal_summary
        .clone()
        .expect("terminal summary is published");
    let chunks = h.logs(build).await;
    eprintln!("== build {build}: {}", status.status);
    eprintln!("== terminal summary: {summary}");
    for (step, stream, text) in &chunks {
        eprintln!("== step {step} {stream}:\n{text}");
    }
    assert_eq!(status.status, "succeeded", "{summary}");
    let invocation = Harness::invocation_summary(&chunks, 0);
    assert_eq!(invocation["outcome"], "acquired", "{invocation}");
    assert_eq!(invocation["resolved_commit"], commit);
    h.finish().await;
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
        Ok(_) => panic!("admission must be refused"),
    }
}

/// Under the Ubuntu unprivileged-user-namespace restriction the acquirer
/// is entered through its AppArmor profile; elsewhere it is entered directly.
fn launcher() -> Option<SourceLauncher> {
    let restricted =
        std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
            .map(|text| text.trim() == "1")
            .unwrap_or(false);
    if !restricted {
        return None;
    }
    let aa_exec = ["/usr/bin/aa-exec", "/usr/sbin/aa-exec"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .expect("aa-exec is required under the user-namespace restriction");
    let available = StdCommand::new(&aa_exec)
        .args(["-p", PROFILE, "--", "/bin/true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    assert!(
        available,
        "the {PROFILE} AppArmor profile must be loaded under the user-namespace restriction"
    );
    Some(SourceLauncher {
        aa_exec_sha256: digest(&std::fs::read(&aa_exec).expect("read aa-exec")),
        aa_exec,
        profile: PROFILE.to_owned(),
    })
}

fn seed_repository(root: &Path) -> Repository {
    let work = root.join("repository-work");
    let bare = root.join("repository.git");
    run_git(root, ["init", "--bare", path(&bare)]);
    run_git(&bare, ["symbolic-ref", "HEAD", "refs/heads/main"]);
    run_git(&bare, ["config", "uploadpack.allowFilter", "true"]);
    run_git(&bare, ["config", "uploadpack.allowAnySHA1InWant", "true"]);
    run_git(root, ["init", "-b", "main", path(&work)]);
    run_git(&work, ["config", "user.email", "source@example.invalid"]);
    run_git(&work, ["config", "user.name", "Product Source"]);
    run_git(&work, ["remote", "add", "origin", path(&bare)]);
    std::fs::write(work.join("README"), b"placeholder\n").unwrap();
    std::fs::write(
        work.join("run-tests.sh"),
        b"#!/bin/sh\nset -e\ntest -f \"$(dirname \"$0\")/README\"\necho tests-ok\n",
    )
    .unwrap();
    std::fs::set_permissions(
        work.join("run-tests.sh"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    run_git(&work, ["add", "--all"]);
    run_git(&work, ["commit", "-m", "seed"]);
    let seed = git_output(&work, ["rev-parse", "HEAD"]);
    // The branch head's README names its parent, so a build step reading it
    // proves the head's tree landed and not the seed's; the acquirer itself
    // requires the requested commit to be exactly what the ref resolves to.
    std::fs::write(work.join("README"), format!("hello from {seed}\n")).unwrap();
    run_git(&work, ["add", "--all"]);
    run_git(&work, ["commit", "-m", "name the seed"]);
    let head = git_output(&work, ["rev-parse", "HEAD"]);
    run_git(&work, ["push", "--force", "origin", "main"]);
    Repository {
        bare,
        commit: head,
        seed,
    }
}

fn git_executable() -> PathBuf {
    ["/usr/bin/git", "/usr/local/bin/git"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .expect("absolute Git executable")
}

fn git_remote_https_executable(git: &Path) -> PathBuf {
    let exec_path = git_output(Path::new("/"), ["--exec-path"]);
    let _ = git;
    std::fs::canonicalize(Path::new(&exec_path).join("git-remote-https"))
        .expect("canonical Git HTTPS helper")
}

fn git_version(git: &Path) -> String {
    let _ = git;
    git_output(Path::new("/"), ["--version"])
}

fn run_git<'a, I>(directory: &Path, arguments: I)
where
    I: IntoIterator<Item = &'a str>,
{
    let output = StdCommand::new(git_executable())
        .current_dir(directory)
        .args(arguments)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .expect("run fixture Git");
    assert!(
        output.status.success(),
        "fixture Git failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git_output<'a, I>(directory: &Path, arguments: I) -> String
where
    I: IntoIterator<Item = &'a str>,
{
    let output = StdCommand::new(git_executable())
        .current_dir(directory)
        .args(arguments)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .expect("run fixture Git");
    assert!(output.status.success(), "fixture Git failed");
    String::from_utf8(output.stdout)
        .expect("Git output UTF-8")
        .trim()
        .to_owned()
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
        if metadata.file_type().is_symlink() {
            continue;
        }
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
        .env("MCLOVING_AGENT_LEASE_SECONDS", "30")
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
