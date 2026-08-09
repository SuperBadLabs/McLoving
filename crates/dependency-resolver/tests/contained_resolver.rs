#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, Response, StatusCode};
use axum::routing::get;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use mcloving_dependency_resolver::{
    AdapterBindings, AdapterConfig, CertifiedConfig, Ecosystem, GrantUse, PackageNode,
    RepositoryBinding, RepositoryConfig, RepositoryGrant, ResolutionFrame, ResolutionRequest,
    ResolverLimits, SourceTrustClass, canonical_attestation_message, configuration_sha256,
    parse_maven_lock,
};
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::io::AsyncWriteExt as _;
use tokio::process::Command;
use uuid::Uuid;

#[derive(Clone)]
struct RepositoryState {
    node: PackageNode,
    body: Vec<u8>,
    key: Arc<Ed25519KeyPair>,
    credential: Vec<u8>,
    requests: Arc<AtomicUsize>,
}

async fn artifact(State(state): State<RepositoryState>, request: Request<Body>) -> Response<Body> {
    state.requests.fetch_add(1, Ordering::SeqCst);
    if request
        .headers()
        .get("authorization")
        .map(|value| value.as_bytes())
        != Some(state.credential.as_slice())
    {
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Body::empty())
            .expect("unauthorized response");
    }
    let message = canonical_attestation_message(&state.node, "contained-key", 7, b"maven");
    let signature = BASE64.encode(state.key.sign(&message).as_ref());
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/octet-stream")
        .header("content-length", state.body.len().to_string())
        .header("x-mcloving-repository-id", "contained-maven")
        .header("x-mcloving-publication-generation", "7")
        .header("x-mcloving-attestation", signature)
        .body(Body::from(state.body))
        .expect("artifact response")
}

#[tokio::test]
#[ignore = "requires the dedicated tmpfs boundary created by scripts/dependency-resolver-contained.sh"]
async fn standalone_exact_resolution_and_offline_restart_replay() {
    let transport_root = PathBuf::from(
        std::env::var_os("MCLOVING_DEPENDENCY_TRANSPORT_ROOT").expect("contained transport root"),
    );
    let transport_capacity = std::env::var("MCLOVING_DEPENDENCY_TRANSPORT_CAPACITY")
        .expect("contained transport capacity")
        .parse::<u64>()
        .expect("numeric transport capacity");
    let fixture = TempDir::new().expect("contained fixture root");
    let output_root = fixture.path().join("output");
    create_private_directory(&output_root);
    let credential = b"Bearer contained-dependency-credential".to_vec();
    let receipt_key = b"contained-dependency-receipt-key".to_vec();
    let key =
        Arc::new(Ed25519KeyPair::from_seed_unchecked(&[11_u8; 32]).expect("contained Ed25519 key"));
    let attestation_key = key.public_key().as_ref().to_vec();
    let marker_document = format!(
        r#"{{"schema_version":"mcloving.secret-markers/v1","markers_hex":["{}"]}}"#,
        hex(&credential)
    )
    .into_bytes();
    let credential_path = private_file(fixture.path(), "repository.credential", &credential);
    let attestation_path = private_file(fixture.path(), "repository.pub", &attestation_key);
    let receipt_path = private_file(fixture.path(), "receipt.key", &receipt_key);
    let markers_path = private_file(fixture.path(), "markers.json", &marker_document);

    let body = b"standalone contained dependency artifact".to_vec();
    let lock = maven_lock(&body);
    let preliminary_plan = parse_maven_lock(
        &lock,
        &AdapterBindings {
            adapter_id: "maven-v1".to_owned(),
            adapter_sha256: "a".repeat(64),
            source_tree_sha256: "b".repeat(64),
            resolver_toolchain_id: "contained-toolchain".to_owned(),
            resolver_toolchain_sha256: "d".repeat(64),
            source_trust_class: SourceTrustClass::Trusted,
            repositories: vec![RepositoryBinding {
                repository_id: "contained-maven".to_owned(),
                credentialed: true,
                permits_untrusted_source: false,
            }],
        },
    )
    .expect("contained plan");
    let node = preliminary_plan.nodes[0].clone();
    let requests = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/repository/com/example/app/1.0.0/app.jar", get(artifact))
        .with_state(RepositoryState {
            node,
            body,
            key,
            credential: credential.clone(),
            requests: Arc::clone(&requests),
        });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("contained repository listener");
    let address = listener.local_addr().expect("repository address");
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("repository server");
    });

    let resolver_binary = PathBuf::from(env!("CARGO_BIN_EXE_mcloving-dependency-resolver"));
    let now = unix_ms();
    let mut config = CertifiedConfig {
        schema_version: "mcloving.dependency-config/v1".to_owned(),
        protocol_version: "mcloving.dependency-resolver/v1".to_owned(),
        configuration_id: "contained-standalone".to_owned(),
        deployment_id: "contained-deployment".to_owned(),
        operator_id: "contained-operator".to_owned(),
        generation: 7,
        executable_sha256: sha256(&fs::read(&resolver_binary).expect("resolver binary")),
        resolver_toolchain_id: "contained-toolchain".to_owned(),
        resolver_toolchain_sha256: "d".repeat(64),
        adapters: vec![
            AdapterConfig {
                ecosystem: Ecosystem::Maven,
                adapter_id: "maven-v1".to_owned(),
                implementation_sha256: "a".repeat(64),
            },
            AdapterConfig {
                ecosystem: Ecosystem::Npm,
                adapter_id: "npm-v1".to_owned(),
                implementation_sha256: "1".repeat(64),
            },
            AdapterConfig {
                ecosystem: Ecosystem::Pypi,
                adapter_id: "pypi-v1".to_owned(),
                implementation_sha256: "2".repeat(64),
            },
        ],
        repositories: vec![RepositoryConfig {
            repository_id: "contained-maven".to_owned(),
            ecosystem: Ecosystem::Maven,
            base_url: format!("http://{address}/repository/"),
            coordinate_prefixes: vec!["com.example:".to_owned()],
            credential_path: Some(path_string(&credential_path)),
            credential_sha256: Some(sha256(&credential)),
            permits_untrusted_source: false,
            attestation_key_id: "contained-key".to_owned(),
            attestation_key_path: path_string(&attestation_path),
            attestation_key_sha256: sha256(&attestation_key),
            private_ca_path: None,
            private_ca_sha256: None,
            grant: Some(RepositoryGrant {
                grant_id: "contained-grant".to_owned(),
                version: 3,
                scope: "read:com.example".to_owned(),
                expires_at_unix_ms: now + 120_000,
            }),
        }],
        receipt_key_id: "contained-receipt-key".to_owned(),
        receipt_key_path: path_string(&receipt_path),
        receipt_key_sha256: sha256(&receipt_key),
        secret_marker_set_path: path_string(&markers_path),
        secret_marker_set_sha256: sha256(&marker_document),
        output_root: path_string(&output_root),
        transport_root: path_string(&transport_root),
        limits: ResolverLimits {
            max_frame_bytes: 1_048_576,
            max_lock_bytes: 262_144,
            max_repositories: 4,
            max_nodes: 100,
            max_edges: 1_000,
            max_artifacts: 100,
            max_artifact_bytes: 1_048_576,
            max_total_artifact_bytes: transport_capacity,
            transport_capacity_bytes: transport_capacity,
            max_path_bytes: 4_096,
            max_header_bytes: 16_384,
            max_request_lifetime_ms: 120_000,
        },
        loopback_fixture: true,
    };
    let config_digest = configuration_sha256(&config).expect("configuration digest");
    let request = ResolutionRequest {
        schema_version: "mcloving.dependency-request/v1".to_owned(),
        protocol_version: config.protocol_version.clone(),
        resolution_id: Uuid::new_v4().to_string(),
        tenant_id: "tenant-a".to_owned(),
        project_id: "project-a".to_owned(),
        pipeline_id: "pipeline-a".to_owned(),
        build_id: Uuid::new_v4().to_string(),
        attempt_id: Uuid::new_v4().to_string(),
        audit_lineage: "audit/contained/standalone".to_owned(),
        source_trust_class: SourceTrustClass::Trusted,
        expected_executable_sha256: config.executable_sha256.clone(),
        expected_configuration_sha256: config_digest,
        expected_adapter_id: preliminary_plan.adapter_id.clone(),
        expected_adapter_sha256: preliminary_plan.adapter_sha256.clone(),
        expected_resolver_toolchain_id: preliminary_plan.resolver_toolchain_id.clone(),
        expected_resolver_toolchain_sha256: preliminary_plan.resolver_toolchain_sha256.clone(),
        expected_generation: config.generation,
        acquisition_receipt_sha256: "7".repeat(64),
        source_tree_sha256: preliminary_plan.source_tree_sha256.clone(),
        logical_lock_path: "dependency-locks/maven.json".to_owned(),
        expected_lock_sha256: preliminary_plan.lock_sha256.clone(),
        ecosystem: Ecosystem::Maven,
        expected_graph_sha256: preliminary_plan.graph_sha256.clone(),
        repository_ids: vec!["contained-maven".to_owned()],
        grants: vec![GrantUse {
            repository_id: "contained-maven".to_owned(),
            grant_id: "contained-grant".to_owned(),
            version: 3,
            scope: "read:com.example".to_owned(),
        }],
        requested_at_unix_ms: now,
        expires_at_unix_ms: now + 60_000,
        rollback_from_generation: None,
    };
    let frame = ResolutionFrame {
        request,
        lock_base64: BASE64.encode(&lock),
    };
    let config_path = fixture.path().join("resolver-config.json");
    config.executable_sha256 = sha256(&fs::read(&resolver_binary).expect("resolver binary"));
    write_private(
        &config_path,
        &serde_json::to_vec(&config).expect("serialized config"),
    );
    let input = serde_json::to_vec(&frame).expect("serialized frame");
    let first = run_resolver(&resolver_binary, &config_path, &input).await;
    assert_eq!(first["status"], "ok", "first resolver response: {first}");
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    server.abort();
    let second = run_resolver(&resolver_binary, &config_path, &input).await;
    assert_eq!(
        second, first,
        "offline restart replay must be byte-equivalent JSON"
    );
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    assert!(!contains_bytes(
        serde_json::to_vec(&second)
            .expect("response bytes")
            .as_slice(),
        &credential
    ));
}

async fn run_resolver(binary: &Path, config: &Path, input: &[u8]) -> serde_json::Value {
    let mut child = Command::new(binary)
        .arg("--config")
        .arg(config)
        .env("MCLOVING_DEPENDENCY_RESOLVER_TEST_MODE", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("standalone resolver process");
    let mut stdin = child.stdin.take().expect("resolver stdin");
    stdin.write_all(input).await.expect("request frame");
    stdin.write_all(b"\n").await.expect("request newline");
    drop(stdin);
    let output = child.wait_with_output().await.expect("resolver output");
    assert!(
        output.status.success(),
        "resolver failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut lines = output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty());
    let response = lines.next().expect("one resolver response");
    assert!(lines.next().is_none(), "unexpected extra resolver response");
    serde_json::from_slice(response).expect("resolver JSON response")
}

fn maven_lock(body: &[u8]) -> Vec<u8> {
    format!(
        r#"{{"schema_version":"mcloving.maven-lock/v1","nodes":[{{"key":"app","group":"com.example","artifact":"app","artifact_type":"jar","classifier":null,"version":"1.0.0","repository_id":"contained-maven","artifact_path":"com/example/app/1.0.0/app.jar","declared_size":{},"sha256":"{}","attestation_key_id":"contained-key","dependencies":[]}}],"roots":["app"]}}"#,
        body.len(),
        sha256(body)
    )
    .into_bytes()
}

fn private_file(root: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = root.join(name);
    write_private(&path, bytes);
    path
}

fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("write private fixture");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("private file mode");
}

fn create_private_directory(path: &Path) {
    fs::create_dir(path).expect("create private directory");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private directory mode");
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn path_string(path: &Path) -> String {
    path.to_str().expect("UTF-8 fixture path").to_owned()
}

fn unix_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("wall clock")
            .as_millis(),
    )
    .expect("millisecond clock")
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}
