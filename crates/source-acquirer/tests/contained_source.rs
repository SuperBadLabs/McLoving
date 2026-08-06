#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use axum::response::Response;
use axum::routing::any;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use mcloving_source_acquirer::{
    AcquisitionRequest, PROTOCOL_VERSION, RepositoryBinding, SourceAcquirer, SourceConfig,
    SourceError, SubmoduleRequest, TrustClass, content_sha256, marker_set_digest, sha256_file,
};
use tempfile::TempDir;
use tokio::io::AsyncWriteExt as _;
use url::Url;
use uuid::Uuid;

const CREDENTIAL: &[u8] = b"contained-source-credential-marker-00000001";
const SIGNING_KEY: &[u8] = b"contained-source-receipt-signing-key-00000000000000000001";

struct RepositoryFixture {
    work: PathBuf,
    bare: PathBuf,
}

impl RepositoryFixture {
    fn new(root: &Path, name: &str) -> Self {
        let work = root.join(format!("{name}-work"));
        let bare = root.join(format!("{name}.git"));
        run_git(root, ["init", "--bare", path_text(&bare)]);
        run_git(root, ["init", "-b", "main", path_text(&work)]);
        run_git(&work, ["config", "user.email", "source@example.invalid"]);
        run_git(&work, ["config", "user.name", "Contained Source"]);
        run_git(&work, ["remote", "add", "origin", path_text(&bare)]);
        Self { work, bare }
    }

    fn new_sha256(root: &Path, name: &str) -> Self {
        let work = root.join(format!("{name}-work"));
        let bare = root.join(format!("{name}.git"));
        run_git(
            root,
            ["init", "--bare", "--object-format=sha256", path_text(&bare)],
        );
        run_git(
            root,
            [
                "init",
                "-b",
                "main",
                "--object-format=sha256",
                path_text(&work),
            ],
        );
        run_git(&work, ["config", "user.email", "source@example.invalid"]);
        run_git(&work, ["config", "user.name", "Contained Source"]);
        run_git(&work, ["remote", "add", "origin", path_text(&bare)]);
        Self { work, bare }
    }

    fn write(&self, path: &str, bytes: &[u8]) {
        let destination = self.work.join(path);
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent).expect("fixture parent");
        }
        std::fs::write(destination, bytes).expect("fixture file");
    }

    fn commit(&self, message: &str) -> String {
        run_git(&self.work, ["add", "--all"]);
        run_git(&self.work, ["commit", "-m", message]);
        let commit = git_output(&self.work, ["rev-parse", "HEAD"]);
        run_git(&self.work, ["push", "--force", "origin", "main"]);
        commit
    }

    fn url(&self) -> String {
        Url::from_file_path(&self.bare)
            .expect("file repository URL")
            .to_string()
    }
}

struct Context {
    _temporary: TempDir,
    acquirer: SourceAcquirer,
    config: SourceConfig,
    implementation_sha256: String,
    credential_path: PathBuf,
}

impl Context {
    async fn new(
        root_repository: &RepositoryFixture,
        submodules: Vec<RepositoryBinding>,
        forks: Vec<RepositoryBinding>,
        allow_untrusted_forks: bool,
    ) -> Self {
        let temporary = tempfile::tempdir().expect("context tempdir");
        let credential_path = temporary.path().join("credential");
        let signing_key_path = temporary.path().join("signing-key");
        write_private(&credential_path, CREDENTIAL);
        write_private(&signing_key_path, SIGNING_KEY);
        let git_executable_path = git_executable();
        let git_sha256 = sha256_file(&git_executable_path).await.expect("git digest");
        let git_version = git_output(
            git_executable_path.parent().expect("git parent"),
            ["--version"],
        );
        let implementation_sha256 = content_sha256(b"contained-source-acquirer-implementation");
        let config = SourceConfig {
            protocol_version: PROTOCOL_VERSION.to_owned(),
            schema_version: "source-acquisition-v1".to_owned(),
            acquirer_id: "contained-source-acquirer".to_owned(),
            deployment_identity: "contained/deployment".to_owned(),
            operator_identity: "contained/operator".to_owned(),
            generation: 7,
            primary_repository: RepositoryBinding {
                provider_identity: "contained-git".to_owned(),
                repository_identity: "repository/root".to_owned(),
                repository_url: root_repository.url(),
            },
            allow_untrusted_forks,
            allowed_fork_repositories: forks,
            allowed_submodule_repositories: submodules,
            allowed_ref_prefixes: vec!["refs/heads/".to_owned()],
            allowed_sparse_roots: vec!["src".to_owned(), "deps".to_owned()],
            git_executable_path,
            git_executable_sha256: git_sha256,
            git_version,
            grant_id: "contained-grant".to_owned(),
            grant_version: "grant-v1".to_owned(),
            grant_scope: "repository:read".to_owned(),
            grant_expires_unix_ms: now_ms() + 120_000,
            credential_username: "git".to_owned(),
            credential_sha256: content_sha256(CREDENTIAL),
            receipt_signing_key_id: "contained-signing-key".to_owned(),
            receipt_signing_key_sha256: content_sha256(SIGNING_KEY),
            secret_marker_set_sha256: marker_set_digest(&[CREDENTIAL.to_vec()]),
            max_depth: 32,
            max_files: 1_000,
            max_total_bytes: 2 * 1_024 * 1_024,
            max_file_bytes: 1024 * 1_024,
            max_path_bytes: 512,
            max_submodules: 16,
            command_timeout_ms: 30_000,
            output_root: temporary.path().join("output"),
            ca_bundle_path: None,
            ca_bundle_sha256: None,
            test_allow_file_repositories: true,
            test_allow_http_loopback: false,
        };
        let acquirer = SourceAcquirer::new(
            config.clone(),
            implementation_sha256.clone(),
            credential_path.clone(),
            CREDENTIAL,
            SIGNING_KEY.to_vec(),
            vec![CREDENTIAL.to_vec()],
        )
        .await
        .expect("source acquirer");
        Self {
            _temporary: temporary,
            acquirer,
            config,
            implementation_sha256,
            credential_path,
        }
    }

    fn request(&self, commit: &str) -> AcquisitionRequest {
        AcquisitionRequest {
            acquisition_id: Uuid::new_v4(),
            organization_id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            pipeline_id: Uuid::new_v4(),
            build_id: Uuid::new_v4(),
            attempt_id: Uuid::new_v4(),
            checkout_name: "source".to_owned(),
            acquirer_id: self.config.acquirer_id.clone(),
            expected_implementation_sha256: self.implementation_sha256.clone(),
            expected_git_sha256: self.config.git_executable_sha256.clone(),
            expected_config_sha256: self.acquirer.config_sha256().to_owned(),
            protocol_version: PROTOCOL_VERSION.to_owned(),
            schema_version: self.config.schema_version.clone(),
            expected_generation: self.config.generation,
            rollback_from_generation: None,
            provider_identity: self.config.primary_repository.provider_identity.clone(),
            repository_identity: self.config.primary_repository.repository_identity.clone(),
            repository_url: self.config.primary_repository.repository_url.clone(),
            authenticated_ref: "refs/heads/main".to_owned(),
            exact_commit: commit.to_owned(),
            source_identity: "trusted/main".to_owned(),
            trust_class: TrustClass::Trusted,
            depth: 0,
            sparse_roots: Vec::new(),
            submodules: Vec::new(),
            requested_at_unix_ms: now_ms() - 1_000,
            expires_at_unix_ms: now_ms() + 60_000,
            audit_lineage: "audit/source/contained".to_owned(),
        }
    }

    async fn second_acquirer(&self) -> SourceAcquirer {
        SourceAcquirer::new(
            self.config.clone(),
            self.implementation_sha256.clone(),
            self.credential_path.clone(),
            CREDENTIAL,
            SIGNING_KEY.to_vec(),
            vec![CREDENTIAL.to_vec()],
        )
        .await
        .expect("second source acquirer")
    }
}

#[tokio::test]
async fn exact_revision_replay_later_commit_and_sparse_truth() {
    let repositories = tempfile::tempdir().expect("repositories tempdir");
    let root = RepositoryFixture::new(repositories.path(), "root");
    root.write("README.md", b"first\n");
    root.write("src/main.txt", b"alpha\n");
    let first = root.commit("first");
    let context = Context::new(&root, Vec::new(), Vec::new(), false).await;

    let request = context.request(&first);
    let receipt = context
        .acquirer
        .acquire(&request)
        .await
        .expect("exact first acquisition");
    assert_eq!(receipt.repository_trees[0].resolved_commit, first);
    assert_eq!(receipt.materialized_files, 2);
    let output = context
        .config
        .output_root
        .join(&receipt.output_relative_path);
    assert_eq!(std::fs::read(output.join("README.md")).unwrap(), b"first\n");
    assert_eq!(
        context.acquirer.acquire(&request).await.unwrap(),
        receipt,
        "same acquisition replays one signed receipt"
    );

    root.write("README.md", b"second\n");
    root.write("src/later.txt", b"later\n");
    let second = root.commit("second");
    let mut later = context.request(&second);
    later.sparse_roots = vec!["src".to_owned()];
    let later_receipt = context
        .acquirer
        .acquire(&later)
        .await
        .expect("later exact acquisition");
    assert_ne!(later_receipt.content_sha256, receipt.content_sha256);
    let later_output = context
        .config
        .output_root
        .join(&later_receipt.output_relative_path);
    assert!(!later_output.join("README.md").exists());
    assert_eq!(
        std::fs::read(later_output.join("src/later.txt")).unwrap(),
        b"later\n"
    );

    let stale = context.request(&first);
    assert!(matches!(
        context.acquirer.acquire(&stale).await,
        Err(SourceError::RevisionMismatch)
    ));
}

#[tokio::test]
async fn sha256_object_format_is_fetched_and_materialized_exactly() {
    let repositories = tempfile::tempdir().expect("repositories tempdir");
    let root = RepositoryFixture::new_sha256(repositories.path(), "sha256-root");
    root.write("README.md", b"sha256 source\n");
    let commit = root.commit("sha256 source");
    assert_eq!(commit.len(), 64);
    let context = Context::new(&root, Vec::new(), Vec::new(), false).await;
    let request = context.request(&commit);
    let receipt = context.acquirer.acquire(&request).await.unwrap();
    assert_eq!(receipt.repository_trees[0].resolved_commit, commit);
    assert_eq!(receipt.repository_trees[0].resolved_tree.len(), 64);
    assert_eq!(
        std::fs::read(
            context
                .config
                .output_root
                .join(receipt.output_relative_path)
                .join("README.md")
        )
        .unwrap(),
        b"sha256 source\n"
    );
}

#[tokio::test]
async fn untrusted_fork_is_denied_before_source_access() {
    let repositories = tempfile::tempdir().expect("repositories tempdir");
    let root = RepositoryFixture::new(repositories.path(), "root");
    root.write("README.md", b"trusted\n");
    let commit = root.commit("trusted");
    let fork = RepositoryFixture::new(repositories.path(), "fork");
    fork.write("README.md", b"fork\n");
    let _ = fork.commit("fork");
    let context = Context::new(&root, Vec::new(), Vec::new(), false).await;
    let mut request = context.request(&commit);
    request.trust_class = TrustClass::UntrustedFork;
    request.repository_identity = "repository/fork".to_owned();
    request.repository_url = fork.url();
    assert!(matches!(
        context.acquirer.acquire(&request).await,
        Err(SourceError::BindingMismatch)
    ));
    assert!(
        !context
            .config
            .output_root
            .join(format!("{}.claim.json", request.acquisition_id))
            .exists()
    );
}

#[tokio::test]
async fn exact_submodule_graph_is_materialized_without_submodule_commands() {
    let repositories = tempfile::tempdir().expect("repositories tempdir");
    let child = RepositoryFixture::new(repositories.path(), "child");
    child.write("child.txt", b"child source\n");
    let child_commit = child.commit("child");
    let root = RepositoryFixture::new(repositories.path(), "root");
    root.write("README.md", b"root source\n");
    run_git(
        &root.work,
        [
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            &child.url(),
            "deps/child",
        ],
    );
    let root_commit = root.commit("root with child");
    let child_binding = RepositoryBinding {
        provider_identity: "contained-git".to_owned(),
        repository_identity: "repository/child".to_owned(),
        repository_url: child.url(),
    };
    let context = Context::new(&root, vec![child_binding.clone()], Vec::new(), false).await;
    let mut request = context.request(&root_commit);
    request.submodules.push(SubmoduleRequest {
        path: "deps/child".to_owned(),
        provider_identity: child_binding.provider_identity,
        repository_identity: child_binding.repository_identity,
        repository_url: child_binding.repository_url,
        authenticated_ref: "refs/heads/main".to_owned(),
        exact_commit: child_commit.clone(),
    });
    let receipt = context
        .acquirer
        .acquire(&request)
        .await
        .expect("submodule acquisition");
    assert_eq!(receipt.repository_trees.len(), 2);
    assert!(
        receipt
            .repository_trees
            .iter()
            .any(|tree| { tree.path == "deps/child" && tree.resolved_commit == child_commit })
    );
    let output = context
        .config
        .output_root
        .join(receipt.output_relative_path);
    assert_eq!(
        std::fs::read(output.join("deps/child/child.txt")).unwrap(),
        b"child source\n"
    );

    let mut substituted = context.request(&root_commit);
    let mut wrong = request.submodules[0].clone();
    wrong.repository_identity = "repository/substituted".to_owned();
    substituted.submodules.push(wrong);
    assert!(matches!(
        context.acquirer.acquire(&substituted).await,
        Err(SourceError::SubmoduleMismatch)
    ));
}

#[tokio::test]
async fn unsafe_symlink_fails_closed_and_retains_ambiguity_claim() {
    use std::os::unix::fs::symlink;

    let repositories = tempfile::tempdir().expect("repositories tempdir");
    let root = RepositoryFixture::new(repositories.path(), "root");
    root.write("README.md", b"root\n");
    symlink("../../escape", root.work.join("escape-link")).expect("unsafe fixture symlink");
    let commit = root.commit("unsafe symlink");
    let context = Context::new(&root, Vec::new(), Vec::new(), false).await;
    let request = context.request(&commit);
    assert!(matches!(
        context.acquirer.acquire(&request).await,
        Err(SourceError::UnsafeTree)
    ));
    assert!(matches!(
        context.acquirer.acquire(&request).await,
        Err(SourceError::AmbiguousClaim)
    ));
}

#[tokio::test]
async fn retained_tree_tampering_is_rejected_on_replay() {
    use std::os::unix::fs::PermissionsExt as _;

    let repositories = tempfile::tempdir().expect("repositories tempdir");
    let root = RepositoryFixture::new(repositories.path(), "root");
    root.write("README.md", b"trusted content\n");
    let commit = root.commit("trusted");
    let context = Context::new(&root, Vec::new(), Vec::new(), false).await;
    let request = context.request(&commit);
    let receipt = context.acquirer.acquire(&request).await.unwrap();
    let retained = context
        .config
        .output_root
        .join(receipt.output_relative_path)
        .join("README.md");
    std::fs::set_permissions(&retained, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&retained, b"substituted content\n").unwrap();
    assert!(matches!(
        context.acquirer.acquire(&request).await,
        Err(SourceError::InvalidStoredReceipt)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_first_writer_replays_exactly_and_changed_request_is_denied() {
    let repositories = tempfile::tempdir().expect("repositories tempdir");
    let root = RepositoryFixture::new(repositories.path(), "root");
    root.write("README.md", b"concurrent source\n");
    let commit = root.commit("concurrent");
    let context = Context::new(&root, Vec::new(), Vec::new(), false).await;
    let second = context.second_acquirer().await;
    let request = context.request(&commit);

    let (left, right) = tokio::join!(context.acquirer.acquire(&request), second.acquire(&request));
    assert_eq!(left.unwrap(), right.unwrap());

    let mut substituted = request.clone();
    substituted.audit_lineage = "audit/source/substituted".to_owned();
    assert!(matches!(
        second.acquire(&substituted).await,
        Err(SourceError::ReplayMismatch)
    ));
}

#[tokio::test]
async fn safe_symlink_executable_and_generation_rollback_bind_exact_tree_truth() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let repositories = tempfile::tempdir().expect("repositories tempdir");
    let root = RepositoryFixture::new(repositories.path(), "root");
    root.write("src/data.txt", b"differential bytes\n");
    root.write("src/run.sh", b"#!/bin/sh\nexit 0\n");
    std::fs::set_permissions(
        root.work.join("src/run.sh"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    symlink("data.txt", root.work.join("src/data-link")).unwrap();
    let commit = root.commit("tree modes");
    let context = Context::new(&root, Vec::new(), Vec::new(), false).await;
    let mut request = context.request(&commit);
    request.rollback_from_generation = Some(context.config.generation - 1);
    let receipt = context.acquirer.acquire(&request).await.unwrap();
    assert_eq!(receipt.rollback_from_generation, Some(6));
    let tree = context
        .config
        .output_root
        .join(&receipt.output_relative_path);
    assert_eq!(
        std::fs::read(tree.join("src/data.txt")).unwrap(),
        b"differential bytes\n"
    );
    assert_eq!(
        std::fs::read_link(tree.join("src/data-link")).unwrap(),
        PathBuf::from("data.txt")
    );
    assert_eq!(
        std::fs::metadata(tree.join("src/data.txt"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o400
    );
    assert_eq!(
        std::fs::metadata(tree.join("src/run.sh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o500
    );

    let mut invalid_rollback = context.request(&commit);
    invalid_rollback.rollback_from_generation = Some(context.config.generation);
    assert!(matches!(
        context.acquirer.acquire(&invalid_rollback).await,
        Err(SourceError::BindingMismatch)
    ));
}

#[tokio::test]
async fn file_bound_failure_cleans_stage_and_runtime_credential_drift_precedes_claim() {
    let repositories = tempfile::tempdir().expect("repositories tempdir");
    let root = RepositoryFixture::new(repositories.path(), "root");
    root.write("oversized.txt", b"five!\n");
    let commit = root.commit("bounded");
    let context = Context::new(&root, Vec::new(), Vec::new(), false).await;

    let mut limited_config = context.config.clone();
    limited_config.generation += 1;
    limited_config.max_file_bytes = 4;
    limited_config.output_root = context
        .credential_path
        .parent()
        .unwrap()
        .join("limited-output");
    let limited = SourceAcquirer::new(
        limited_config.clone(),
        context.implementation_sha256.clone(),
        context.credential_path.clone(),
        CREDENTIAL,
        SIGNING_KEY.to_vec(),
        vec![CREDENTIAL.to_vec()],
    )
    .await
    .unwrap();
    let mut request = context.request(&commit);
    request.expected_generation = limited_config.generation;
    request.expected_config_sha256 = limited.config_sha256().to_owned();
    assert!(matches!(
        limited.acquire(&request).await,
        Err(SourceError::LimitExceeded)
    ));
    assert!(
        std::fs::read_dir(&limited_config.output_root)
            .unwrap()
            .all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".stage-"))
    );

    let mut control_request = context.request(&commit);
    control_request.audit_lineage = "audit/source\nsubstituted".to_owned();
    assert!(matches!(
        context.acquirer.acquire(&control_request).await,
        Err(SourceError::BindingMismatch)
    ));
    assert!(
        !context
            .config
            .output_root
            .join(format!("{}.claim.json", control_request.acquisition_id))
            .exists()
    );

    let drift_request = context.request(&commit);
    write_private(
        &context.credential_path,
        b"rotated-without-generation-change",
    );
    assert!(matches!(
        context.acquirer.acquire(&drift_request).await,
        Err(SourceError::BindingMismatch)
    ));
    assert!(
        !context
            .config
            .output_root
            .join(format!("{}.claim.json", drift_request.acquisition_id))
            .exists()
    );
}

#[tokio::test]
async fn extra_retained_output_is_rejected_on_replay() {
    use std::os::unix::fs::PermissionsExt as _;

    let repositories = tempfile::tempdir().expect("repositories tempdir");
    let root = RepositoryFixture::new(repositories.path(), "root");
    root.write("README.md", b"trusted content\n");
    let commit = root.commit("trusted");
    let context = Context::new(&root, Vec::new(), Vec::new(), false).await;
    let request = context.request(&commit);
    let receipt = context.acquirer.acquire(&request).await.unwrap();
    let tree = context
        .config
        .output_root
        .join(receipt.output_relative_path);
    std::fs::set_permissions(&tree, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(tree.join("injected.txt"), b"not in manifest\n").unwrap();
    std::fs::set_permissions(&tree, std::fs::Permissions::from_mode(0o500)).unwrap();
    assert!(matches!(
        context.acquirer.acquire(&request).await,
        Err(SourceError::InvalidStoredReceipt)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn standalone_binary_uses_askpass_without_disclosing_the_credential() {
    let temporary = tempfile::tempdir().expect("standalone tempdir");
    let repository = RepositoryFixture::new(temporary.path(), "private");
    repository.write("source.txt", b"credentialed source\n");
    let commit = repository.commit("private source");
    let authorized_requests = Arc::new(AtomicUsize::new(0));
    let unauthorized_requests = Arc::new(AtomicUsize::new(0));
    let state = SmartHttpState {
        project_root: temporary.path().to_owned(),
        expected_authorization: format!(
            "Basic {}",
            STANDARD.encode(format!("git:{}", String::from_utf8_lossy(CREDENTIAL)))
        ),
        authorized_requests: Arc::clone(&authorized_requests),
        unauthorized_requests: Arc::clone(&unauthorized_requests),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("smart HTTP listener");
    let address = listener.local_addr().expect("smart HTTP address");
    let server = tokio::spawn(
        axum::serve(
            listener,
            Router::new()
                .route("/{*path}", any(smart_http))
                .with_state(state),
        )
        .into_future(),
    );

    let binary = PathBuf::from(env!("CARGO_BIN_EXE_mcloving-source-acquirer"));
    let git = git_executable();
    let credential_path = temporary.path().join("credential");
    let signing_key_path = temporary.path().join("signing-key");
    let marker_path = temporary.path().join("markers");
    let config_path = temporary.path().join("config.json");
    write_private(&credential_path, CREDENTIAL);
    write_private(&signing_key_path, SIGNING_KEY);
    write_private(&marker_path, &[CREDENTIAL, b"\n"].concat());
    let repository_url = format!("http://{address}/private.git");
    let mut config = SourceConfig {
        protocol_version: PROTOCOL_VERSION.to_owned(),
        schema_version: "source-acquisition-v1".to_owned(),
        acquirer_id: "standalone-source-acquirer".to_owned(),
        deployment_identity: "contained/http-deployment".to_owned(),
        operator_identity: "contained/http-operator".to_owned(),
        generation: 1,
        primary_repository: RepositoryBinding {
            provider_identity: "contained-http-git".to_owned(),
            repository_identity: "repository/private".to_owned(),
            repository_url: repository_url.clone(),
        },
        allow_untrusted_forks: false,
        allowed_fork_repositories: Vec::new(),
        allowed_submodule_repositories: Vec::new(),
        allowed_ref_prefixes: vec!["refs/heads/".to_owned()],
        allowed_sparse_roots: Vec::new(),
        git_executable_path: git.clone(),
        git_executable_sha256: sha256_file(&git).await.unwrap(),
        git_version: git_output(git.parent().unwrap(), ["--version"]),
        grant_id: "contained-http-grant".to_owned(),
        grant_version: "grant-v1".to_owned(),
        grant_scope: "repository/private:read".to_owned(),
        grant_expires_unix_ms: now_ms() + 120_000,
        credential_username: "git".to_owned(),
        credential_sha256: content_sha256(CREDENTIAL),
        receipt_signing_key_id: "contained-http-signing-key".to_owned(),
        receipt_signing_key_sha256: content_sha256(SIGNING_KEY),
        secret_marker_set_sha256: marker_set_digest(&[CREDENTIAL.to_vec()]),
        max_depth: 8,
        max_files: 100,
        max_total_bytes: 1024 * 1024,
        max_file_bytes: 1024 * 1024,
        max_path_bytes: 512,
        max_submodules: 0,
        command_timeout_ms: 30_000,
        output_root: temporary.path().join("standalone-output"),
        ca_bundle_path: None,
        ca_bundle_sha256: None,
        test_allow_file_repositories: false,
        test_allow_http_loopback: true,
    };
    let implementation_sha256 = sha256_file(&binary).await.unwrap();
    let mut request = AcquisitionRequest {
        acquisition_id: Uuid::new_v4(),
        organization_id: Uuid::new_v4(),
        project_id: Uuid::new_v4(),
        pipeline_id: Uuid::new_v4(),
        build_id: Uuid::new_v4(),
        attempt_id: Uuid::new_v4(),
        checkout_name: "private-source".to_owned(),
        acquirer_id: config.acquirer_id.clone(),
        expected_implementation_sha256: implementation_sha256,
        expected_git_sha256: config.git_executable_sha256.clone(),
        expected_config_sha256: config.canonical_digest().unwrap(),
        protocol_version: PROTOCOL_VERSION.to_owned(),
        schema_version: config.schema_version.clone(),
        expected_generation: config.generation,
        rollback_from_generation: None,
        provider_identity: config.primary_repository.provider_identity.clone(),
        repository_identity: config.primary_repository.repository_identity.clone(),
        repository_url,
        authenticated_ref: "refs/heads/main".to_owned(),
        exact_commit: commit,
        source_identity: "trusted/private-main".to_owned(),
        trust_class: TrustClass::Trusted,
        depth: 1,
        sparse_roots: Vec::new(),
        submodules: Vec::new(),
        requested_at_unix_ms: now_ms() - 1_000,
        expires_at_unix_ms: now_ms() + 60_000,
        audit_lineage: "audit/source/http-contained".to_owned(),
    };
    std::fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    let mut child = tokio::process::Command::new(&binary)
        .env_clear()
        .env("MCLOVING_SOURCE_ACQUIRER_CONFIG", &config_path)
        .env("MCLOVING_SOURCE_ACQUIRER_CREDENTIAL_FILE", &credential_path)
        .env(
            "MCLOVING_SOURCE_ACQUIRER_SIGNING_KEY_FILE",
            &signing_key_path,
        )
        .env("MCLOVING_SOURCE_ACQUIRER_SECRET_MARKERS_FILE", &marker_path)
        .env("MCLOVING_SOURCE_ACQUIRER_TEST_MODE", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("standalone source acquirer");
    let mut stdin = child.stdin.take().unwrap();
    let request_bytes = serde_json::to_vec(&request).unwrap();
    stdin.write_all(&request_bytes).await.unwrap();
    drop(stdin);
    let output = child.wait_with_output().await.unwrap();
    assert!(output.status.success(), "standalone status: {output:?}");
    assert!(!contains(&output.stdout, CREDENTIAL));
    assert!(!contains(&output.stderr, CREDENTIAL));
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["ok"], true);
    assert_eq!(
        response["receipt"]["repository_trees"][0]["resolved_commit"],
        request.exact_commit
    );
    assert!(authorized_requests.load(Ordering::SeqCst) >= 2);
    assert!(unauthorized_requests.load(Ordering::SeqCst) >= 1);

    let denied_credential: &[u8] = b"denied-source-credential-marker-00000001";
    write_private(&credential_path, denied_credential);
    write_private(&marker_path, &[denied_credential, b"\n"].concat());
    config.credential_sha256 = content_sha256(denied_credential);
    config.secret_marker_set_sha256 = marker_set_digest(&[denied_credential.to_vec()]);
    config.output_root = temporary.path().join("denied-output");
    request.acquisition_id = Uuid::new_v4();
    request.expected_config_sha256 = config.canonical_digest().unwrap();
    request.requested_at_unix_ms = now_ms() - 1_000;
    request.expires_at_unix_ms = now_ms() + 60_000;
    std::fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    let mut denied = tokio::process::Command::new(&binary)
        .env_clear()
        .env("MCLOVING_SOURCE_ACQUIRER_CONFIG", &config_path)
        .env("MCLOVING_SOURCE_ACQUIRER_CREDENTIAL_FILE", &credential_path)
        .env(
            "MCLOVING_SOURCE_ACQUIRER_SIGNING_KEY_FILE",
            &signing_key_path,
        )
        .env("MCLOVING_SOURCE_ACQUIRER_SECRET_MARKERS_FILE", &marker_path)
        .env("MCLOVING_SOURCE_ACQUIRER_TEST_MODE", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("denied standalone source acquirer");
    denied
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&request).unwrap())
        .await
        .unwrap();
    let denied_output = denied.wait_with_output().await.unwrap();
    server.abort();
    assert!(denied_output.status.success());
    assert!(!contains(&denied_output.stdout, denied_credential));
    assert!(!contains(&denied_output.stderr, denied_credential));
    let denied_response: serde_json::Value = serde_json::from_slice(&denied_output.stdout).unwrap();
    assert_eq!(denied_response["ok"], false);
    assert_eq!(denied_response["code"], "source_unavailable");
}

#[derive(Clone)]
struct SmartHttpState {
    project_root: PathBuf,
    expected_authorization: String,
    authorized_requests: Arc<AtomicUsize>,
    unauthorized_requests: Arc<AtomicUsize>,
}

async fn smart_http(
    State(state): State<SmartHttpState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response<Body> {
    let authorized = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        == Some(state.expected_authorization.as_str());
    if !authorized {
        state.unauthorized_requests.fetch_add(1, Ordering::SeqCst);
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("www-authenticate", "Basic realm=\"contained-git\"")
            .body(Body::empty())
            .unwrap();
    }
    state.authorized_requests.fetch_add(1, Ordering::SeqCst);
    let body = match to_bytes(body, 2 * 1024 * 1024).await {
        Ok(body) => body.to_vec(),
        Err(_) => {
            return Response::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .body(Body::empty())
                .unwrap();
        }
    };
    let path = uri.path().to_owned();
    let query = uri.query().unwrap_or_default().to_owned();
    let content_type = headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let project_root = state.project_root;
    let method = method.as_str().to_owned();
    let output = tokio::task::spawn_blocking(move || {
        use std::io::Write as _;

        let mut child = Command::new(git_executable())
            .arg("http-backend")
            .env_clear()
            .env("GIT_PROJECT_ROOT", project_root)
            .env("GIT_HTTP_EXPORT_ALL", "1")
            .env("PATH_INFO", path)
            .env("QUERY_STRING", query)
            .env("REQUEST_METHOD", method)
            .env("CONTENT_TYPE", content_type)
            .env("CONTENT_LENGTH", body.len().to_string())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("git http-backend");
        child.stdin.take().unwrap().write_all(&body).unwrap();
        child.wait_with_output().expect("git http-backend output")
    })
    .await
    .unwrap();
    if !output.status.success() {
        return Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Body::from(output.stderr))
            .unwrap();
    }
    cgi_response(&output.stdout)
}

fn cgi_response(bytes: &[u8]) -> Response<Body> {
    let split = bytes
        .windows(4)
        .position(|candidate| candidate == b"\r\n\r\n")
        .expect("CGI header terminator");
    let headers = std::str::from_utf8(&bytes[..split]).expect("CGI headers");
    let mut builder = Response::builder().status(StatusCode::OK);
    for line in headers.split("\r\n") {
        let (name, value) = line.split_once(':').expect("CGI header");
        if name.eq_ignore_ascii_case("status") {
            let status = value
                .trim()
                .split_once(' ')
                .map_or(value.trim(), |(code, _)| code)
                .parse::<u16>()
                .unwrap();
            builder = builder.status(status);
        } else {
            builder = builder.header(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value.trim()).unwrap(),
            );
        }
    }
    builder
        .body(Body::from(bytes[split + 4..].to_vec()))
        .unwrap()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|candidate| candidate == needle)
}

fn git_executable() -> PathBuf {
    ["/usr/bin/git", "/usr/local/bin/git"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .expect("absolute Git executable")
}

fn run_git<'a, I>(directory: &Path, arguments: I)
where
    I: IntoIterator<Item = &'a str>,
{
    let output = Command::new(git_executable())
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
    let output = Command::new(git_executable())
        .current_dir(directory)
        .args(arguments)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .expect("run fixture Git");
    assert!(output.status.success(), "fixture Git output failed");
    String::from_utf8(output.stdout)
        .expect("fixture Git UTF-8")
        .trim()
        .to_owned()
}

fn path_text(path: &Path) -> &str {
    path.to_str().expect("fixture UTF-8 path")
}

fn write_private(path: &Path, bytes: &[u8]) {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::write(path, bytes).expect("private fixture file");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .expect("private fixture permissions");
}

fn now_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_millis(),
    )
    .expect("millisecond clock")
}
