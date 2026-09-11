use super::*;
use mcloving_source_acquirer::{AcquisitionReceipt, ManifestEntry};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::PermissionsExt as _;

#[path = "../source_lifetime_fixture/mod.rs"]
mod source_lifetime_fixture;

#[derive(Default)]
struct ReadCounts {
    reads: AtomicUsize,
    writes: AtomicUsize,
    upload_posts: AtomicUsize,
    descendant_heartbeats: AtomicUsize,
    release: AtomicBool,
}
#[derive(Clone)]
struct StrictHttp {
    backend: SmartHttpState,
    counts: Arc<ReadCounts>,
}
async fn read_only_http(
    State(state): State<StrictHttp>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response<Body> {
    if uri.path() == "/fixture-descendant-heartbeat" {
        if method == Method::GET
            && headers.get("authorization").and_then(|v| v.to_str().ok())
                == Some(state.backend.expected_authorization.as_str())
        {
            state
                .counts
                .descendant_heartbeats
                .fetch_add(1, Ordering::SeqCst);
            return Response::builder()
                .status(StatusCode::OK)
                .body(Body::empty())
                .unwrap();
        }
        state.counts.writes.fetch_add(1, Ordering::SeqCst);
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Body::empty())
            .unwrap();
    }
    let read = (method == Method::GET
        && uri.path() == "/private.git/info/refs"
        && uri.query() == Some("service=git-upload-pack"))
        || (method == Method::POST
            && uri.path() == "/private.git/git-upload-pack"
            && uri.query().is_none());
    if !read {
        state.counts.writes.fetch_add(1, Ordering::SeqCst);
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Body::empty())
            .unwrap();
    }
    if headers.get("authorization").and_then(|v| v.to_str().ok())
        == Some(state.backend.expected_authorization.as_str())
    {
        state.counts.reads.fetch_add(1, Ordering::SeqCst);
        if method == Method::POST {
            state.counts.upload_posts.fetch_add(1, Ordering::SeqCst);
        }
        while !state.counts.release.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    smart_http(State(state.backend), method, uri, headers, body).await
}

#[tokio::test(flavor = "multi_thread")]
async fn sealed_native_source_joins_authenticated_read_receipt_and_retained_tree() {
    run_sealed_native_source(None).await;
}

async fn run_sealed_native_source(scenario: Option<source_lifetime_fixture::Scenario>) {
    let temporary = source_lifetime_fixture::RetainFailedFixture::new();
    let repository = RepositoryFixture::new(temporary.path(), "private");
    repository.write("source.txt", b"credentialed source\n");
    let commit = repository.commit("private source");
    let authorized_requests = Arc::new(AtomicUsize::new(0));
    let unauthorized_requests = Arc::new(AtomicUsize::new(0));
    let response_delay_ms = Arc::new(AtomicU64::new(0));
    let rotate_credential_on_unauthorized = Arc::new(AtomicBool::new(false));
    let credential_path = temporary.path().join("credential");
    let state = SmartHttpState {
        project_root: temporary.path().to_owned(),
        expected_authorization: format!(
            "Basic {}",
            STANDARD.encode(format!("git:{}", String::from_utf8_lossy(CREDENTIAL)))
        ),
        authorized_requests: Arc::clone(&authorized_requests),
        unauthorized_requests: Arc::clone(&unauthorized_requests),
        response_delay_ms: Arc::clone(&response_delay_ms),
        credential_path: credential_path.clone(),
        rotate_credential_on_unauthorized: Arc::clone(&rotate_credential_on_unauthorized),
    };
    let counts = Arc::new(ReadCounts::default());
    let strict = StrictHttp {
        backend: state,
        counts: Arc::clone(&counts),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("smart HTTP listener");
    let address = listener.local_addr().expect("smart HTTP address");
    let server = tokio::spawn(
        axum::serve(
            listener,
            Router::new()
                .route("/{*path}", any(read_only_http))
                .with_state(strict),
        )
        .into_future(),
    );

    let binary = PathBuf::from(env!("CARGO_BIN_EXE_mcloving-source-acquirer"));
    let git = git_executable();
    let deliberate_descendant =
        scenario.is_some_and(source_lifetime_fixture::uses_deliberate_descendant);
    let git = if deliberate_descendant {
        source_lifetime_fixture::wrap_git(&git, temporary.path(), address.port())
    } else {
        git
    };
    let git_remote_https = git_remote_https_executable(&git);
    let bound_git_remote_https = temporary.path().join("bound-git-remote-https");
    std::fs::copy(&git_remote_https, &bound_git_remote_https).unwrap();
    std::fs::set_permissions(
        &bound_git_remote_https,
        std::fs::Permissions::from_mode(0o500),
    )
    .unwrap();
    let signing_key_path = temporary.path().join("signing-key");
    let marker_path = temporary.path().join("markers");
    let config_path = temporary.path().join("config.json");
    write_private(&credential_path, CREDENTIAL);
    write_private(&signing_key_path, SIGNING_KEY);
    write_private(&marker_path, &[CREDENTIAL, b"\n"].concat());
    let repository_url = format!("http://localhost:{}/private.git", address.port());
    let runtime_closure =
        inspect_runtime_closure(&[git.clone(), bound_git_remote_https.clone(), binary.clone()])
            .await
            .unwrap();
    let runtime_closure_sha256 = runtime_closure_digest(&runtime_closure).unwrap();
    let config = SourceConfig {
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
        git_remote_https_executable_path: bound_git_remote_https.clone(),
        git_remote_https_executable_sha256: sha256_file(&bound_git_remote_https).await.unwrap(),
        runtime_closure,
        runtime_closure_sha256,
        git_version: git_output(git.parent().unwrap(), ["--version"]),
        grant_id: "contained-http-grant".to_owned(),
        grant_version: "grant-v1".to_owned(),
        grant_scope: "repository/private:read".to_owned(),
        grant_expires_unix_ms: now_ms() + FIXTURE_AUTHORITY_WINDOW_MS,
        credential_username: "git".to_owned(),
        credential_sha256: content_sha256(CREDENTIAL),
        receipt_signing_key_id: "contained-http-signing-key".to_owned(),
        receipt_signing_key_sha256: content_sha256(SIGNING_KEY),
        secret_marker_set_sha256: marker_set_digest(&[CREDENTIAL.to_vec()]),
        max_depth: 8,
        max_files: 100,
        max_total_bytes: 1024 * 1024,
        max_file_bytes: 1024 * 1024,
        max_transport_bytes: TRANSPORT_CAPACITY_16M,
        max_path_bytes: 512,
        max_submodules: 0,
        command_timeout_ms: HOSTED_SMART_HTTP_COMMAND_TIMEOUT_MS,
        transport_root: bounded_transport_root(TRANSPORT_CAPACITY_16M),
        output_root: temporary.path().join("standalone-output"),
        ca_bundle_path: None,
        ca_bundle_sha256: None,
        test_allow_file_repositories: false,
        test_allow_http_loopback: true,
    };
    let implementation_sha256 = sha256_file(&binary).await.unwrap();
    let request = AcquisitionRequest {
        acquisition_id: Uuid::new_v4(),
        organization_id: Uuid::new_v4(),
        project_id: Uuid::new_v4(),
        pipeline_id: Uuid::new_v4(),
        build_id: Uuid::new_v4(),
        attempt_id: Uuid::new_v4(),
        checkout_name: "private-source".to_owned(),
        acquirer_id: config.acquirer_id.clone(),
        expected_implementation_sha256: implementation_sha256.clone(),
        expected_git_sha256: config.git_executable_sha256.clone(),
        expected_git_remote_https_sha256: config.git_remote_https_executable_sha256.clone(),
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
        expires_at_unix_ms: now_ms() + FIXTURE_AUTHORITY_WINDOW_MS,
        audit_lineage: "audit/source/http-contained".to_owned(),
    };
    std::fs::write(&config_path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    assert_ne!(
        content_sha256(&std::fs::read(&config_path).unwrap()),
        config.canonical_digest().unwrap(),
        "canonical configuration pin must not be a raw-file pin"
    );
    let bare_before = inventory(&repository.bare);
    // A pathname replacement after sealing must not affect the executed image.
    let replaced = temporary.path().join("formerly-selected-helper");
    std::fs::copy(&binary, &replaced).unwrap();
    let original = std::fs::read(&replaced).unwrap();
    assert_eq!(content_sha256(&original), implementation_sha256);
    let sealed = sealed_image(&replaced);
    let fd = sealed.as_raw_fd();
    std::fs::write(&replaced, b"replacement must never execute").unwrap();
    // Real inotify positive control distinguishes pin refusal from a later
    // credential-reader error, including the non-Unicode environment case.
    use std::os::unix::ffi::OsStringExt as _;
    for pin in [
        std::ffi::OsString::from("0".repeat(64)),
        std::ffi::OsString::from("not-a-sha256"),
        std::ffi::OsString::from_vec(vec![0xff]),
    ] {
        let mut probe = native_command(
            "python3",
            &config_path,
            &credential_path,
            &signing_key_path,
            &marker_path,
        );
        probe
            .arg("-I")
            .arg("-c")
            .arg(include_str!("observe_startup.py"))
            .arg(fd.to_string())
            .arg(&credential_path)
            .arg(&signing_key_path)
            .arg(&marker_path)
            .env("MCLOVING_SOURCE_ACQUIRER_EXPECTED_CONFIG_SHA256", pin);
        let result = tokio::time::timeout(Duration::from_secs(15), probe.output())
            .await
            .unwrap()
            .unwrap();
        assert!(
            result.status.success(),
            "startup observer: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let observed: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_ne!(observed["status"], 0);
        assert_eq!(observed["stdout_base64"], "");
        assert_eq!(observed["private_access_event_bytes"], 0);
        assert!(observed["positive_control_event_bytes"].as_u64().unwrap() > 0);
        assert!(!config.output_root.exists());
        assert_eq!(counts.reads.load(Ordering::SeqCst), 0);
        assert_eq!(unauthorized_requests.load(Ordering::SeqCst), 0);
        assert_private_absent(&result.stdout);
    }
    // Every CLI file reader touched by the custody change must refuse an
    // ordinary symlink or FIFO promptly, without admitting native state.
    for field in 0..4 {
        for fifo in [false, true] {
            let alias = temporary
                .path()
                .join(format!("refused-reader-{field}-{fifo}"));
            let originals = [
                &config_path,
                &credential_path,
                &signing_key_path,
                &marker_path,
            ];
            if fifo {
                nix::unistd::mkfifo(
                    &alias,
                    nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
                )
                .unwrap();
            } else {
                std::os::unix::fs::symlink(originals[field], &alias).unwrap();
            }
            let mut paths = originals;
            paths[field] = &alias;
            let mut probe = native_command(
                &format!("/proc/self/fd/{fd}"),
                paths[0],
                paths[1],
                paths[2],
                paths[3],
            );
            probe.env(
                "MCLOVING_SOURCE_ACQUIRER_EXPECTED_CONFIG_SHA256",
                config.canonical_digest().unwrap(),
            );
            let result = tokio::time::timeout(Duration::from_secs(5), probe.output())
                .await
                .expect("symlink/FIFO reader refusal is bounded")
                .unwrap();
            assert!(!result.status.success(), "reader {field}, FIFO={fifo}");
            assert!(result.stdout.is_empty());
            assert_private_absent(&result.stderr);
            assert!(!config.output_root.exists());
            assert_eq!(counts.reads.load(Ordering::SeqCst), 0);
            assert_eq!(unauthorized_requests.load(Ordering::SeqCst), 0);
        }
    }
    let mut command = if matches!(
        scenario,
        Some(source_lifetime_fixture::Scenario::ParentDeath)
    ) {
        source_lifetime_fixture::parent_command(
            &config_path,
            &credential_path,
            &signing_key_path,
            &marker_path,
        )
    } else if scenario.is_some() {
        source_lifetime_fixture::command(
            &sealed,
            &config_path,
            &credential_path,
            &signing_key_path,
            &marker_path,
        )
    } else {
        native_command(
            &format!("/proc/self/fd/{fd}"),
            &config_path,
            &credential_path,
            &signing_key_path,
            &marker_path,
        )
    };
    command.env(
        "MCLOVING_SOURCE_ACQUIRER_EXPECTED_CONFIG_SHA256",
        config.canonical_digest().unwrap(),
    );
    let expected_profile = if scenario.is_some() {
        "mcloving-source-acquirer (unconfined)\n".to_owned()
    } else {
        std::fs::read_to_string("/proc/self/attr/current").unwrap()
    };
    let named_source_profile =
        expected_profile.split_whitespace().next() == Some("mcloving-source-acquirer");
    let namespace_denied = scenario.is_none() && host_denies_sealed_launcher_userns();
    assert!(
        !named_source_profile || !namespace_denied,
        "named source-profile gate owes the full sealed acquisition: {}",
        userns_policy_diagnostics()
    );
    let started_ms = now_ms();
    let (mut child, containment) = if scenario.is_some() {
        let mut launch = source_lifetime_fixture::Launch::spawn(command, &sealed);
        if matches!(
            scenario,
            Some(source_lifetime_fixture::Scenario::ParentDeath)
        ) {
            launch.identify_proxy().await;
        }
        if !source_lifetime_fixture::host_requires_positive() {
            launch.expect_unavailable().await;
            assert_eq!(counts.reads.load(Ordering::SeqCst), 0);
            assert_eq!(unauthorized_requests.load(Ordering::SeqCst), 0);
            assert!(
                !config
                    .output_root
                    .join(request.acquisition_id.to_string())
                    .exists()
            );
            server.abort();
            return;
        }
        launch.admit().await;
        // Keep the phase gate and exact parent/init pidfds alive until cleanup.
        (launch.child.take().unwrap(), Some(launch))
    } else {
        (command.spawn().unwrap(), None)
    };
    let pid = containment
        .as_ref()
        .map_or_else(|| child.id().unwrap(), |launch| launch.outer.pid as u32);
    let mut stdin = child.stdin.take().unwrap();
    stdin
        .write_all(&serde_json::to_vec(&request).unwrap())
        .await
        .unwrap();
    stdin.write_all(b"\n").await.unwrap();
    drop(stdin);
    if namespace_denied {
        // This is an executed native refusal, not a skipped positive test.
        let output = tokio::time::timeout(Duration::from_secs(30), child.wait_with_output())
            .await
            .expect("namespace refusal is bounded")
            .unwrap();
        assert!(output.status.success());
        assert_private_absent(&output.stdout);
        assert_private_absent(&output.stderr);
        let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(response["ok"], false);
        assert_eq!(response["code"], "transport_namespace_unavailable");
        assert!(contains(&output.stderr, b"transport_namespace_unusable"));
        assert_eq!(counts.reads.load(Ordering::SeqCst), 0);
        assert_eq!(counts.writes.load(Ordering::SeqCst), 0);
        assert_eq!(counts.upload_posts.load(Ordering::SeqCst), 0);
        assert_eq!(authorized_requests.load(Ordering::SeqCst), 0);
        assert_eq!(unauthorized_requests.load(Ordering::SeqCst), 0);
        assert!(
            !config
                .output_root
                .join(request.acquisition_id.to_string())
                .exists()
        );
        assert!(
            !config
                .output_root
                .join(format!("{}.claim.json", request.acquisition_id))
                .exists()
        );
        assert!(
            std::fs::read_dir(&config.output_root)
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".stage-"))
        );
        assert_eq!(inventory(&repository.bare), bare_before);
        scan_private_absent(&config.output_root);
        server.abort();
        eprintln!(
            "sealed source prerequisite: actual sealed helper asserted transport_namespace_unavailable with zero provider requests/publication; positive acquisition remains required in named source host gate"
        );
        return;
    }
    tokio::time::timeout(Duration::from_secs(60), async {
        while counts.reads.load(Ordering::SeqCst) == 0 {
            if let Some(status) = child.try_wait().unwrap() {
                use tokio::io::AsyncReadExt as _;
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                child.stdout.take().unwrap().read_to_end(&mut stdout).await.unwrap();
                child.stderr.take().unwrap().read_to_end(&mut stderr).await.unwrap();
                assert_private_absent(&stdout);
                assert_private_absent(&stderr);
                panic!("sealed native helper exited before authenticated provider read: {status}, stdout={}, stderr={}", String::from_utf8_lossy(&stdout), String::from_utf8_lossy(&stderr));
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("authenticated native fetch reaches held provider");
    let profile = std::fs::read_to_string(format!("/proc/{pid}/attr/current")).unwrap();
    assert_eq!(
        profile, expected_profile,
        "native helper retains externally selected profile"
    );
    let running = std::fs::File::open(format!("/proc/{pid}/exe")).unwrap();
    assert_eq!(
        content_sha256(&std::fs::read(format!("/proc/{pid}/exe")).unwrap()),
        implementation_sha256
    );
    assert_eq!(
        nix::fcntl::fcntl(&running, nix::fcntl::FcntlArg::F_GET_SEALS).unwrap() & 15,
        15
    );
    assert!(
        std::fs::read_link(format!("/proc/{pid}/exe"))
            .unwrap()
            .to_string_lossy()
            .contains("memfd:")
    );
    if deliberate_descendant {
        tokio::time::timeout(Duration::from_secs(10), async {
            while counts.descendant_heartbeats.load(Ordering::SeqCst) == 0 {
                assert!(child.try_wait().unwrap().is_none());
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("deliberate descendant must actually emit fixture heartbeat");
    }
    let observed = containment
        .as_ref()
        .map(|_| source_lifetime_fixture::descendants(pid as i32));
    if let Some(
        action @ (source_lifetime_fixture::Scenario::Terminate
        | source_lifetime_fixture::Scenario::Kill
        | source_lifetime_fixture::Scenario::ParentDeath),
    ) = scenario
    {
        let launch = containment.as_ref().unwrap();
        match action {
            source_lifetime_fixture::Scenario::Terminate => {
                launch.outer.signal(rustix::process::Signal::TERM)
            }
            source_lifetime_fixture::Scenario::Kill => {
                launch.outer.signal(rustix::process::Signal::KILL)
            }
            source_lifetime_fixture::Scenario::ParentDeath => launch.kill_parent(),
            source_lifetime_fixture::Scenario::Complete
            | source_lifetime_fixture::Scenario::CompleteWithDescendant => unreachable!(),
        }
        let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
            .await
            .unwrap()
            .unwrap();
        source_lifetime_fixture::prove_exited(std::slice::from_ref(launch.init.as_ref().unwrap()))
            .await;
        source_lifetime_fixture::prove_exited(observed.as_ref().unwrap()).await;
        assert!(!output.status.success());
        assert!(
            output.stdout.is_empty(),
            "outer cancellation must not return a receipt"
        );
        assert_private_absent(&output.stderr);
        source_lifetime_fixture::assert_observed_descendants(
            observed.as_ref().unwrap(),
            deliberate_descendant,
        );
        let before = counts.reads.load(Ordering::SeqCst);
        let heartbeat_before = counts.descendant_heartbeats.load(Ordering::SeqCst);
        counts.release.store(true, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            counts.reads.load(Ordering::SeqCst),
            before,
            "no authenticated provider activity after cleanup"
        );
        assert_eq!(counts.writes.load(Ordering::SeqCst), 0);
        assert!(heartbeat_before > 0);
        assert_eq!(
            counts.descendant_heartbeats.load(Ordering::SeqCst),
            heartbeat_before,
            "no deliberately detached descendant activity after namespace cleanup"
        );
        eprintln!(
            "synthetic descendant heartbeat stopped: {heartbeat_before} observed heartbeats before stable post-cleanup interval"
        );
        let claim = config
            .output_root
            .join(format!("{}.claim.json", request.acquisition_id));
        let claim_bytes = std::fs::read(&claim)
            .expect("crashed acquisition retains its original ambiguity claim");
        let claim_digest = content_sha256(&claim_bytes);
        source_lifetime_fixture::retire_owned_fixture_transport(
            &config.transport_root,
            request.acquisition_id,
            launch.init.as_ref().unwrap(),
        );
        assert_eq!(
            std::fs::read(&claim).unwrap(),
            claim_bytes,
            "transport fixture teardown preserves acquisition ambiguity"
        );
        eprintln!(
            "synthetic crash claim retained through transport retirement: acquisition={}, claim_sha256={claim_digest}",
            request.acquisition_id
        );
        eprintln!(
            "source containment {action:?}: {} pinned native descendants exited; {before} authenticated reads then stable provider count",
            observed.as_ref().unwrap().len()
        );
        server.abort();
        return;
    }
    counts.release.store(true, Ordering::SeqCst);
    let output = tokio::time::timeout(Duration::from_secs(120), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    if let Some(identities) = &observed {
        source_lifetime_fixture::prove_exited(std::slice::from_ref(
            containment.as_ref().unwrap().init.as_ref().unwrap(),
        ))
        .await;
        source_lifetime_fixture::prove_exited(identities).await;
        source_lifetime_fixture::assert_observed_descendants(identities, deliberate_descendant);
    }
    assert!(
        output.status.success(),
        "native helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    if deliberate_descendant {
        let heartbeat_count = counts.descendant_heartbeats.load(Ordering::SeqCst);
        assert!(heartbeat_count > 0);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            counts.descendant_heartbeats.load(Ordering::SeqCst),
            heartbeat_count,
            "normal completion also tears down detached descendants"
        );
    }
    let completed_ms = now_ms();
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["ok"], true, "native source response: {envelope}");
    let receipt: AcquisitionReceipt = serde_json::from_value(envelope["receipt"].clone()).unwrap();
    let acquisition = config.output_root.join(request.acquisition_id.to_string());
    let stored: AcquisitionReceipt =
        serde_json::from_slice(&std::fs::read(acquisition.join("receipt.json")).unwrap()).unwrap();
    assert_eq!(stored, receipt);
    let pure_verifier = mcloving_source_acquirer::receipt_auth::ReceiptVerifier::new(
        config.clone(),
        implementation_sha256.clone(),
        SIGNING_KEY.to_vec(),
        vec![CREDENTIAL.to_vec()],
    )
    .unwrap();
    pure_verifier.authenticate(&receipt, &request).unwrap();
    pure_verifier
        .authenticate_frame(
            &std::fs::read(acquisition.join("receipt.json")).unwrap(),
            &request,
        )
        .unwrap();
    use hmac::{Hmac, Mac as _};
    let mut unsigned = receipt.clone();
    unsigned.signature.clear();
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(SIGNING_KEY).unwrap();
    mac.update(&serde_json::to_vec(&unsigned).unwrap());
    mac.verify_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&receipt.signature)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        receipt.request_sha256,
        content_sha256(&serde_json::to_vec(&request).unwrap())
    );
    assert_eq!(
        receipt.acquirer_implementation_sha256,
        implementation_sha256
    );
    assert_eq!(
        receipt.acquirer_config_sha256,
        config.canonical_digest().unwrap()
    );
    assert_eq!(
        receipt.git_implementation_sha256,
        config.git_executable_sha256
    );
    assert_eq!(
        receipt.git_remote_https_implementation_sha256,
        config.git_remote_https_executable_sha256
    );
    assert_eq!(
        receipt.runtime_closure_sha256,
        config.runtime_closure_sha256
    );
    let request_json = serde_json::to_value(&request).unwrap();
    let receipt_json = serde_json::to_value(&receipt).unwrap();
    for field in [
        "acquisition_id",
        "organization_id",
        "project_id",
        "pipeline_id",
        "build_id",
        "attempt_id",
        "checkout_name",
        "acquirer_id",
        "source_identity",
        "trust_class",
        "depth",
        "sparse_roots",
        "audit_lineage",
        "protocol_version",
        "schema_version",
        "rollback_from_generation",
    ] {
        assert_eq!(
            receipt_json[field], request_json[field],
            "request identity {field}"
        );
    }
    let config_json = serde_json::to_value(&config).unwrap();
    for field in [
        "deployment_identity",
        "operator_identity",
        "generation",
        "grant_id",
        "grant_version",
        "grant_scope",
        "git_version",
        "secret_marker_set_sha256",
    ] {
        assert_eq!(
            receipt_json[field], config_json[field],
            "configured receipt authority {field}"
        );
    }
    assert_eq!(receipt.signing_key_id, config.receipt_signing_key_id);
    assert!(
        receipt.acquired_at_unix_ms >= started_ms && receipt.acquired_at_unix_ms <= completed_ms
    );
    assert!(receipt.acquired_at_unix_ms >= request.requested_at_unix_ms);
    assert!(receipt.acquired_at_unix_ms < request.expires_at_unix_ms);
    assert!(receipt.acquired_at_unix_ms < config.grant_expires_unix_ms);
    assert!(receipt.publication_deadline_unix_ms >= receipt.acquired_at_unix_ms);
    assert!(receipt.transport_bytes <= config.max_transport_bytes);
    assert_eq!(receipt.repository_trees.len(), 1);
    let tree_receipt = &receipt.repository_trees[0];
    assert_eq!(tree_receipt.resolved_commit, request.exact_commit);
    assert_eq!(tree_receipt.repository_url, request.repository_url);
    assert_eq!(tree_receipt.authenticated_ref, request.authenticated_ref);
    assert_eq!(
        tree_receipt.resolved_tree,
        git_output(&repository.work, ["rev-parse", "HEAD^{tree}"])
    );
    assert_eq!(
        receipt.output_relative_path,
        format!("{}/tree", request.acquisition_id)
    );
    let manifest_bytes = std::fs::read(acquisition.join("manifest.json")).unwrap();
    assert_eq!(receipt.manifest_sha256, content_sha256(&manifest_bytes));
    assert_eq!(receipt.content_sha256, receipt.manifest_sha256);
    let manifest: Vec<ManifestEntry> = serde_json::from_slice(&manifest_bytes).unwrap();
    assert_eq!(manifest.len(), 1);
    let entry = &manifest[0];
    assert_eq!(entry.path, "source.txt");
    assert_eq!(entry.git_mode, "100644");
    assert_eq!(
        entry.git_object_id,
        git_output(&repository.work, ["rev-parse", "HEAD:source.txt"])
    );
    let tree = acquisition.join("tree");
    let retained = std::fs::read(tree.join(&entry.path)).unwrap();
    assert_eq!(retained, b"credentialed source\n");
    assert_eq!(entry.sha256, content_sha256(&retained));
    assert_eq!(entry.bytes, retained.len() as u64);
    assert_eq!(receipt.materialized_files, 1);
    assert_eq!(receipt.materialized_bytes, retained.len() as u64);
    assert_eq!(std::fs::read_dir(&tree).unwrap().count(), 1);
    for path in [&acquisition, &tree] {
        assert_eq!(
            std::fs::symlink_metadata(path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o500
        );
    }
    for path in [
        acquisition.join("receipt.json"),
        acquisition.join("manifest.json"),
        tree.join("source.txt"),
    ] {
        let meta = std::fs::symlink_metadata(path).unwrap();
        assert!(meta.is_file());
        assert_eq!(meta.permissions().mode() & 0o777, 0o400);
    }
    for bytes in [&output.stdout, &output.stderr] {
        assert_private_absent(bytes);
        assert!(!contains(bytes, b"credentialed source\n"));
    }
    scan_private_absent(&config.output_root);
    assert_eq!(
        inventory(&repository.bare),
        bare_before,
        "read-only fetch changed provider repository"
    );
    assert!(
        unauthorized_requests.load(Ordering::SeqCst) > 0,
        "real askpass challenge missing"
    );
    assert!(authorized_requests.load(Ordering::SeqCst) > 0);
    assert!(
        counts.upload_posts.load(Ordering::SeqCst) > 0,
        "Git read uses upload-pack POST"
    );
    assert_eq!(counts.writes.load(Ordering::SeqCst), 0);
    eprintln!(
        "sealed source prerequisite: original memfd+four seals, authenticated read-only upload-pack, native signed receipt/request/manifest and retained tree verified"
    );
    server.abort();
}

fn sealed_image(binary: &Path) -> std::fs::File {
    use std::io::Write as _;
    let fd = nix::sys::memfd::memfd_create(
        c"source-prerequisite-fixture",
        nix::sys::memfd::MFdFlags::MFD_ALLOW_SEALING,
    )
    .unwrap();
    let mut file = std::fs::File::from(fd);
    file.write_all(&std::fs::read(binary).unwrap()).unwrap();
    nix::fcntl::fcntl(
        &file,
        nix::fcntl::FcntlArg::F_ADD_SEALS(
            nix::fcntl::SealFlag::F_SEAL_SEAL
                | nix::fcntl::SealFlag::F_SEAL_SHRINK
                | nix::fcntl::SealFlag::F_SEAL_GROW
                | nix::fcntl::SealFlag::F_SEAL_WRITE,
        ),
    )
    .unwrap();
    file
}
fn native_command(
    binary: &str,
    config: &Path,
    credential: &Path,
    key: &Path,
    markers: &Path,
) -> tokio::process::Command {
    let mut c = tokio::process::Command::new(binary);
    c.env_clear()
        .env("MCLOVING_SOURCE_ACQUIRER_CONFIG", config)
        .env("MCLOVING_SOURCE_ACQUIRER_CREDENTIAL_FILE", credential)
        .env("MCLOVING_SOURCE_ACQUIRER_SIGNING_KEY_FILE", key)
        .env("MCLOVING_SOURCE_ACQUIRER_SECRET_MARKERS_FILE", markers)
        .env("MCLOVING_SOURCE_ACQUIRER_TEST_MODE", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    c
}
fn inventory(root: &Path) -> std::collections::BTreeMap<PathBuf, String> {
    fn visit(root: &Path, here: &Path, out: &mut std::collections::BTreeMap<PathBuf, String>) {
        for entry in std::fs::read_dir(here).unwrap() {
            let p = entry.unwrap().path();
            let m = std::fs::symlink_metadata(&p).unwrap();
            assert!(!m.file_type().is_symlink());
            if m.is_dir() {
                visit(root, &p, out);
            } else {
                out.insert(
                    p.strip_prefix(root).unwrap().to_owned(),
                    content_sha256(&std::fs::read(&p).unwrap()),
                );
            }
        }
    }
    let mut out = std::collections::BTreeMap::new();
    visit(root, root, &mut out);
    out
}
fn assert_private_absent(bytes: &[u8]) {
    for secret in [CREDENTIAL, SIGNING_KEY] {
        assert!(!contains(bytes, secret));
        let hex = secret
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert!(!contains(bytes, hex.as_bytes()));
        assert!(!contains(bytes, STANDARD.encode(secret).as_bytes()));
    }
}
fn scan_private_absent(root: &Path) {
    for entry in std::fs::read_dir(root).unwrap() {
        let p = entry.unwrap().path();
        let m = std::fs::symlink_metadata(&p).unwrap();
        assert!(!m.file_type().is_symlink());
        if m.is_dir() {
            scan_private_absent(&p);
        } else {
            assert_private_absent(&std::fs::read(&p).unwrap());
        }
    }
}
