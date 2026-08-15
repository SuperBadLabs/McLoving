#![cfg(target_os = "linux")]

#[path = "../../test-support/diff003.rs"]
mod diff003;

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, Response, StatusCode};
use axum::routing::get;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::engine::general_purpose::STANDARD_NO_PAD as SOURCE_BASE64;
use mcloving_dependency_resolver::{
    AdapterBindings, AdapterConfig, CertifiedConfig, DependencyResolver, Ecosystem, GrantUse,
    LoadedAuthorities, PackageNode, RepositoryBinding, RepositoryConfig, RepositoryGrant,
    ResolutionFrame, ResolutionRequest, ResolverLimits, SourceProvenance, SourceTrustClass,
    canonical_attestation_message, configuration_sha256, parse_maven_lock,
    source_provenance_message,
};
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::io::AsyncWriteExt as _;
use tokio::process::Command;
use uuid::Uuid;

#[derive(Clone)]
struct RepositoryState {
    artifacts: Arc<BTreeMap<String, RepositoryArtifact>>,
    key: Arc<Ed25519KeyPair>,
    credential: Vec<u8>,
    requests: Arc<AtomicUsize>,
}

#[derive(Clone)]
struct RepositoryArtifact {
    node: PackageNode,
    body: Vec<u8>,
}

async fn artifact(State(state): State<RepositoryState>, request: Request<Body>) -> Response<Body> {
    state.requests.fetch_add(1, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(50)).await;
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
    let artifact = match state.artifacts.get(request.uri().path()) {
        Some(artifact) => artifact,
        None => {
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::empty())
                .expect("missing response");
        }
    };
    let message = canonical_attestation_message(&artifact.node, "contained-key", 7, b"maven");
    let signature = BASE64.encode(state.key.sign(&message).as_ref());
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/octet-stream")
        .header("content-length", artifact.body.len().to_string())
        .header("x-mcloving-repository-id", "contained-maven")
        .header("x-mcloving-publication-generation", "7")
        .header("x-mcloving-attestation", signature)
        .body(Body::from(artifact.body.clone()))
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
    let receipt_key = b"contained-dependency-receipt-key-material-v1".to_vec();
    let key =
        Arc::new(Ed25519KeyPair::from_seed_unchecked(&[11_u8; 32]).expect("contained Ed25519 key"));
    let source_key = Ed25519KeyPair::from_seed_unchecked(&[12_u8; 32])
        .expect("contained source attestation key");
    let source_attestation_key = source_key.public_key().as_ref().to_vec();
    let attestation_key = key.public_key().as_ref().to_vec();
    let marker_document = marker_document(&[&credential, &receipt_key]);
    let credential_path = private_file(fixture.path(), "repository.credential", &credential);
    let attestation_path = private_file(fixture.path(), "repository.pub", &attestation_key);
    let source_attestation_path = private_file(
        fixture.path(),
        "source-attestation.pub",
        &source_attestation_key,
    );
    let receipt_path = private_file(fixture.path(), "receipt.key", &receipt_key);
    let markers_path = private_file(fixture.path(), "markers.json", &marker_document);

    let body = b"standalone contained dependency artifact".to_vec();
    let lock = maven_lock(&body, "app", "com/example/app/1.0.0/app.jar");
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
    let full_body =
        vec![b'x'; usize::try_from(transport_capacity).expect("transport capacity fits memory")];
    let full_lock = maven_lock(&full_body, "full", "com/example/full/1.0.0/full.jar");
    let full_plan = parse_maven_lock(
        &full_lock,
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
    .expect("disk-full plan");
    let full_node = full_plan.nodes[0].clone();
    let artifacts = BTreeMap::from([
        (
            "/repository/com/example/app/1.0.0/app.jar".to_owned(),
            RepositoryArtifact { node, body },
        ),
        (
            "/repository/com/example/full/1.0.0/full.jar".to_owned(),
            RepositoryArtifact {
                node: full_node,
                body: full_body,
            },
        ),
    ]);
    let requests = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/repository/com/example/app/1.0.0/app.jar", get(artifact))
        .route("/repository/com/example/full/1.0.0/full.jar", get(artifact))
        .with_state(RepositoryState {
            artifacts: Arc::new(artifacts),
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
                expires_at_unix_ms: now + 600_000,
            }),
        }],
        source_attestation_key_id: "contained-source-key".to_owned(),
        source_attestation_key_path: path_string(&source_attestation_path),
        source_attestation_key_sha256: sha256(&source_attestation_key),
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
            max_artifact_bytes: transport_capacity,
            max_total_artifact_bytes: transport_capacity,
            transport_capacity_bytes: transport_capacity,
            max_path_bytes: 4_096,
            max_header_bytes: 16_384,
            max_request_lifetime_ms: 120_000,
        },
        loopback_fixture: true,
    };
    let diff003_direct_mount = std::env::var_os("MCLOVING_DIFF003_MOUNT_DIRECT").is_some();
    if std::env::var_os("MCLOVING_DIFF003_CONTAINED").is_none() || diff003_direct_mount {
        let mutable_receipts = output_root.join("receipts");
        create_private_directory(&mutable_receipts);
        let mutable_receipt = private_file(&mutable_receipts, "mutable.key", &receipt_key);
        let receipt_alias = private_file(fixture.path(), "bind-receipt.key", b"mount target");
        let mut mount_command = Command::new(if diff003_direct_mount {
            "mount"
        } else {
            "sudo"
        });
        if !diff003_direct_mount {
            mount_command.arg("mount");
        }
        let mount_status = mount_command
            .arg("--bind")
            .arg(&mutable_receipt)
            .arg(&receipt_alias)
            .status()
            .await
            .expect("bind authority alias");
        assert!(mount_status.success(), "bind authority alias");
        let mut bind_alias_config = config.clone();
        bind_alias_config.receipt_key_path = path_string(&receipt_alias);
        let bind_alias_result = LoadedAuthorities::load(&bind_alias_config);
        let mut unmount_command = Command::new(if diff003_direct_mount {
            "umount"
        } else {
            "sudo"
        });
        if !diff003_direct_mount {
            unmount_command.arg("umount");
        }
        let unmount_status = unmount_command
            .arg(&receipt_alias)
            .status()
            .await
            .expect("unmount authority alias");
        assert!(unmount_status.success(), "unmount authority alias");
        fs::remove_file(&receipt_alias).expect("remove bind target");
        fs::remove_file(&mutable_receipt).expect("remove mutable receipt source");
        fs::remove_dir(&mutable_receipts).expect("remove mutable receipt directory");
        let bind_alias_error = bind_alias_result.expect_err("bind-mounted mutable authority alias");
        assert_eq!(
            bind_alias_error.code,
            "DEP_AUTHORITY_MUTABLE_IDENTITY_ALIAS_DENIED"
        );

        let topology_alias = output_root.join("topology-alias");
        let topology_nested = output_root.join("topology-nested");
        create_private_directory(&topology_alias);
        create_private_directory(&topology_nested);
        let mut topology_mount_command = Command::new(if diff003_direct_mount {
            "mount"
        } else {
            "sudo"
        });
        if !diff003_direct_mount {
            topology_mount_command.arg("mount");
        }
        let topology_mount_status = topology_mount_command
            .arg("--bind")
            .arg(&output_root)
            .arg(&topology_alias)
            .status()
            .await
            .expect("bind mutable root alias");
        assert!(topology_mount_status.success(), "bind mutable root alias");
        let nested_authority_path = topology_alias.join("topology-nested");
        let mut nested_mount_command = Command::new(if diff003_direct_mount {
            "mount"
        } else {
            "sudo"
        });
        if !diff003_direct_mount {
            nested_mount_command.arg("mount");
        }
        let nested_mount_status = nested_mount_command
            .arg("--bind")
            .arg(fixture.path())
            .arg(&nested_authority_path)
            .status()
            .await
            .expect("bind nested authority topology");
        assert!(
            nested_mount_status.success(),
            "bind nested authority topology"
        );
        let nested_topology_result = LoadedAuthorities::load(&config);
        let mut nested_unmount_command = Command::new(if diff003_direct_mount {
            "umount"
        } else {
            "sudo"
        });
        if !diff003_direct_mount {
            nested_unmount_command.arg("umount");
        }
        let nested_unmount_status = nested_unmount_command
            .arg(&nested_authority_path)
            .status()
            .await
            .expect("unmount nested authority topology");
        assert!(
            nested_unmount_status.success(),
            "unmount nested authority topology"
        );
        let mut topology_unmount_command = Command::new(if diff003_direct_mount {
            "umount"
        } else {
            "sudo"
        });
        if !diff003_direct_mount {
            topology_unmount_command.arg("umount");
        }
        let topology_unmount_status = topology_unmount_command
            .arg(&topology_alias)
            .status()
            .await
            .expect("unmount mutable root alias");
        assert!(
            topology_unmount_status.success(),
            "unmount mutable root alias"
        );
        fs::remove_dir(&topology_alias).expect("remove mutable root alias");
        fs::remove_dir(&topology_nested).expect("remove topology mount point");
        let nested_topology_error =
            nested_topology_result.expect_err("path-distinct nested bind topology");
        assert_eq!(
            nested_topology_error.code,
            "DEP_AUTHORITY_MUTABLE_IDENTITY_ALIAS_DENIED"
        );
    }

    let config_digest = configuration_sha256(&config).expect("configuration digest");
    let mut request = ResolutionRequest {
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
        source_provenance: SourceProvenance {
            schema_version: "mcloving.source-provenance/v1".to_owned(),
            key_id: config.source_attestation_key_id.clone(),
            issued_at_unix_ms: now,
            expires_at_unix_ms: now + 120_000,
            signature_base64: String::new(),
        },
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
        expires_at_unix_ms: now + 120_000,
        rollback_from_generation: None,
    };
    sign_source_request(&mut request, &source_key);
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
    let concurrent_output = fixture.path().join("concurrent-output");
    create_private_directory(&concurrent_output);
    let mut concurrent_config = config.clone();
    concurrent_config.configuration_id = "contained-concurrent".to_owned();
    concurrent_config.output_root = path_string(&concurrent_output);
    let mut concurrent_frame = frame.clone();
    concurrent_frame.request.resolution_id = Uuid::new_v4().to_string();
    concurrent_frame.request.build_id = Uuid::new_v4().to_string();
    concurrent_frame.request.attempt_id = Uuid::new_v4().to_string();
    concurrent_frame.request.expected_configuration_sha256 =
        configuration_sha256(&concurrent_config).expect("concurrent config digest");
    sign_source_request(&mut concurrent_frame.request, &source_key);
    let resolver = Arc::new(
        DependencyResolver::new_with_publication_worker(concurrent_config, resolver_binary.clone())
            .expect("concurrent contained resolver"),
    );
    let left_resolver = Arc::clone(&resolver);
    let left_frame = concurrent_frame.clone();
    let right_resolver = Arc::clone(&resolver);
    let right_frame = concurrent_frame;
    let (left, right) = tokio::join!(
        async move { left_resolver.resolve_frame(left_frame).await },
        async move { right_resolver.resolve_frame(right_frame).await }
    );
    let left = left.expect("left concurrent receipt");
    let right = right.expect("right concurrent receipt");
    assert_eq!(left, right);
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    if let Ok(root) = std::env::var("MCLOVING_DIFF003_RUNTIME_OUTPUT_DIR") {
        std::fs::write(
            std::path::Path::new(&root).join("DEP-001.json"),
            diff003::receipt(
                "DEP-001",
                serde_json::to_value(&left).expect("encode DIFF-003 dependency receipt"),
            ),
        )
        .expect("write DIFF-003 dependency receipt");
    }
    drop(resolver);

    let mut forged_trusted = frame.clone();
    forged_trusted.request.resolution_id = Uuid::new_v4().to_string();
    forged_trusted.request.source_trust_class = SourceTrustClass::Untrusted;
    sign_source_request(&mut forged_trusted.request, &source_key);
    forged_trusted.request.source_trust_class = SourceTrustClass::Trusted;
    let denied = run_resolver(
        &resolver_binary,
        &config_path,
        &serde_json::to_vec(&forged_trusted).expect("forged trusted frame"),
        &credential,
        &receipt_key,
    )
    .await;
    assert_eq!(denied["status"], "error");
    assert_eq!(denied["code"], "DEP_REQUEST_SOURCE_PROVENANCE_INVALID");
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    let substitution_denied = denied["status"] == "error"
        && denied["code"] == "DEP_REQUEST_SOURCE_PROVENANCE_INVALID"
        && requests.load(Ordering::SeqCst) == 1;
    diff003::record_assertion(
        "dependency_resolver_substitution_denied",
        "denied",
        serde_json::json!({
            "result_code": denied["code"],
            "repository_requests": requests.load(Ordering::SeqCst),
            "substitution": "source_provenance",
        }),
        substitution_denied,
    );

    let mut disk_full = frame.clone();
    disk_full.request.resolution_id = Uuid::new_v4().to_string();
    disk_full.request.logical_lock_path = "dependency-locks/full-maven.json".to_owned();
    disk_full.request.expected_lock_sha256 = full_plan.lock_sha256;
    disk_full.request.expected_graph_sha256 = full_plan.graph_sha256;
    disk_full.lock_base64 = BASE64.encode(&full_lock);
    sign_source_request(&mut disk_full.request, &source_key);
    let denied = run_resolver(
        &resolver_binary,
        &config_path,
        &serde_json::to_vec(&disk_full).expect("disk-full frame"),
        &credential,
        &receipt_key,
    )
    .await;
    assert_eq!(denied["status"], "error");
    assert_eq!(denied["code"], "DEP_TRANSPORT_CONTENT_MISMATCH");
    assert_eq!(requests.load(Ordering::SeqCst), 2);

    let mut wrong_graph = frame.clone();
    wrong_graph.request.expected_graph_sha256 = "f".repeat(64);
    sign_source_request(&mut wrong_graph.request, &source_key);
    let denied = run_resolver(
        &resolver_binary,
        &config_path,
        &serde_json::to_vec(&wrong_graph).expect("wrong graph frame"),
        &credential,
        &receipt_key,
    )
    .await;
    assert_eq!(denied["status"], "error");
    assert_eq!(denied["code"], "DEP_REQUEST_PLAN_BINDING_MISMATCH");
    assert_eq!(requests.load(Ordering::SeqCst), 2);

    let mut untrusted = frame.clone();
    untrusted.request.resolution_id = Uuid::new_v4().to_string();
    untrusted.request.source_trust_class = SourceTrustClass::Untrusted;
    sign_source_request(&mut untrusted.request, &source_key);
    let denied = run_resolver(
        &resolver_binary,
        &config_path,
        &serde_json::to_vec(&untrusted).expect("untrusted frame"),
        &credential,
        &receipt_key,
    )
    .await;
    assert_eq!(denied["status"], "error");
    assert_eq!(denied["code"], "DEP_UNTRUSTED_REPOSITORY_DENIED");
    assert_eq!(requests.load(Ordering::SeqCst), 2);

    let replay_now = unix_ms();
    let mut replay = frame.clone();
    replay.request.resolution_id = Uuid::new_v4().to_string();
    replay.request.build_id = Uuid::new_v4().to_string();
    replay.request.attempt_id = Uuid::new_v4().to_string();
    replay.request.requested_at_unix_ms = replay_now;
    replay.request.expires_at_unix_ms = replay_now + 120_000;
    replay.request.source_provenance.issued_at_unix_ms = replay_now;
    replay.request.source_provenance.expires_at_unix_ms = replay_now + 120_000;
    sign_source_request(&mut replay.request, &source_key);
    let replay_input = serde_json::to_vec(&replay).expect("serialized replay frame");
    let first = run_resolver(
        &resolver_binary,
        &config_path,
        &replay_input,
        &credential,
        &receipt_key,
    )
    .await;
    assert_eq!(first["status"], "ok", "first resolver response: {first}");
    assert_eq!(requests.load(Ordering::SeqCst), 3);
    server.abort();

    let second = run_resolver(
        &resolver_binary,
        &config_path,
        &replay_input,
        &credential,
        &receipt_key,
    )
    .await;
    assert_eq!(
        second, first,
        "offline restart replay must be byte-equivalent JSON"
    );
    assert_eq!(requests.load(Ordering::SeqCst), 3);
    let outage_now = unix_ms();
    let outage_lock = String::from_utf8(lock.clone())
        .expect("UTF-8 lock")
        .replace("1.0.0", "2.0.0")
        .into_bytes();
    let outage_plan = parse_maven_lock(
        &outage_lock,
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
    .expect("outage exact plan");
    let mut outage = frame.clone();
    outage.request.resolution_id = Uuid::new_v4().to_string();
    outage.request.build_id = Uuid::new_v4().to_string();
    outage.request.attempt_id = Uuid::new_v4().to_string();
    outage.request.requested_at_unix_ms = outage_now;
    outage.request.expires_at_unix_ms = outage_now + 120_000;
    outage.request.source_provenance.issued_at_unix_ms = outage_now;
    outage.request.source_provenance.expires_at_unix_ms = outage_now + 120_000;
    outage.request.logical_lock_path = "dependency-locks/outage-maven.json".to_owned();
    outage.request.expected_lock_sha256 = outage_plan.lock_sha256;
    outage.request.expected_graph_sha256 = outage_plan.graph_sha256;
    outage.lock_base64 = BASE64.encode(&outage_lock);
    sign_source_request(&mut outage.request, &source_key);
    let outage_result = run_resolver(
        &resolver_binary,
        &config_path,
        &serde_json::to_vec(&outage).expect("outage frame"),
        &credential,
        &receipt_key,
    )
    .await;
    let outage_denied = outage_result["status"] == "error"
        && outage_result["code"] == "DEP_TRANSPORT_IO_FAILED"
        && requests.load(Ordering::SeqCst) == 3;
    diff003::record_assertion(
        "dependency_outage_denied",
        "denied",
        serde_json::json!({
            "repository_aborted": true,
            "repository_requests_before_restart": 3,
            "repository_requests_after_restart": requests.load(Ordering::SeqCst),
            "uncached_resolution_id": outage.request.resolution_id,
            "result_code": outage_result["code"],
        }),
        outage_denied,
    );

    let later_lock = String::from_utf8(lock.clone())
        .expect("UTF-8 lock")
        .replace("1.0.0", "2.0.0")
        .into_bytes();
    let later_plan = parse_maven_lock(
        &later_lock,
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
    .expect("later exact plan");
    let mut later = replay;
    later.lock_base64 = BASE64.encode(&later_lock);
    later.request.expected_lock_sha256 = later_plan.lock_sha256;
    later.request.expected_graph_sha256 = later_plan.graph_sha256;
    sign_source_request(&mut later.request, &source_key);
    let denied = run_resolver(
        &resolver_binary,
        &config_path,
        &serde_json::to_vec(&later).expect("later frame"),
        &credential,
        &receipt_key,
    )
    .await;
    assert_eq!(denied["status"], "error");
    assert_eq!(denied["code"], "DEP_STORE_RECEIPT_INVALID");
    assert_eq!(requests.load(Ordering::SeqCst), 3);
    let replay_denied = denied["status"] == "error"
        && denied["code"] == "DEP_STORE_RECEIPT_INVALID"
        && requests.load(Ordering::SeqCst) == 3;
    diff003::record_assertion(
        "dependency_replay_denied",
        "denied",
        serde_json::json!({
            "result_code": denied["code"],
            "divergent_lock_sha256": later.request.expected_lock_sha256,
            "repository_requests": requests.load(Ordering::SeqCst),
        }),
        replay_denied,
    );

    assert!(!contains_bytes(
        serde_json::to_vec(&second)
            .expect("response bytes")
            .as_slice(),
        &credential
    ));
}

async fn run_resolver(
    binary: &Path,
    config: &Path,
    input: &[u8],
    credential: &[u8],
    receipt_key: &[u8],
) -> serde_json::Value {
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
    assert!(!contains_bytes(&output.stdout, credential));
    assert!(!contains_bytes(&output.stderr, credential));
    assert!(!contains_bytes(&output.stdout, receipt_key));
    assert!(!contains_bytes(&output.stderr, receipt_key));
    let mut lines = output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty());
    let response = lines.next().expect("one resolver response");
    assert!(lines.next().is_none(), "unexpected extra resolver response");
    serde_json::from_slice(response).expect("resolver JSON response")
}

fn maven_lock(body: &[u8], artifact: &str, artifact_path: &str) -> Vec<u8> {
    format!(
        r#"{{"schema_version":"mcloving.maven-lock/v1","nodes":[{{"key":"{artifact}","group":"com.example","artifact":"{artifact}","artifact_type":"jar","classifier":null,"version":"1.0.0","repository_id":"contained-maven","artifact_path":"{artifact_path}","declared_size":{},"sha256":"{}","attestation_key_id":"contained-key","dependencies":[]}}],"roots":["{artifact}"]}}"#,
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

fn sign_source_request(request: &mut ResolutionRequest, key: &Ed25519KeyPair) {
    request.source_provenance.signature_base64.clear();
    let message = source_provenance_message(request).expect("source provenance message");
    request.source_provenance.signature_base64 = SOURCE_BASE64.encode(key.sign(&message).as_ref());
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn marker_document(markers: &[&[u8]]) -> Vec<u8> {
    let mut markers = markers.iter().map(|value| hex(value)).collect::<Vec<_>>();
    markers.sort();
    format!(
        r#"{{"schema_version":"mcloving.secret-markers/v1","markers_hex":[{}]}}"#,
        markers
            .iter()
            .map(|value| format!(r#""{value}""#))
            .collect::<Vec<_>>()
            .join(",")
    )
    .into_bytes()
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
