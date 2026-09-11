//! Pure authentication of retained receipt evidence against the original request.
//! This does not verify retained filesystem custody or authorize a new acquisition.
use super::*;

pub(super) fn validate_request(
    config: &SourceConfig,
    config_sha256: &str,
    implementation_sha256: &str,
    request: &AcquisitionRequest,
    now: i64,
) -> Result<String, SourceError> {
    let expected_binding = RepositoryBinding {
        provider_identity: request.provider_identity.clone(),
        repository_identity: request.repository_identity.clone(),
        repository_url: request.repository_url.clone(),
    };
    let repository_admitted = match request.trust_class {
        TrustClass::Trusted => expected_binding == config.primary_repository,
        TrustClass::UntrustedFork => {
            config.allow_untrusted_forks
                && config.allowed_fork_repositories.contains(&expected_binding)
        }
    };
    if request.acquisition_id.is_nil()
        || request.organization_id.is_nil()
        || request.project_id.is_nil()
        || request.pipeline_id.is_nil()
        || request.build_id.is_nil()
        || request.attempt_id.is_nil()
        || request.checkout_name.trim().is_empty()
        || request.source_identity.trim().is_empty()
        || request.audit_lineage.trim().is_empty()
        || request.acquirer_id != config.acquirer_id
        || request.expected_implementation_sha256 != implementation_sha256
        || request.expected_git_sha256 != config.git_executable_sha256
        || request.expected_git_remote_https_sha256 != config.git_remote_https_executable_sha256
        || request.expected_config_sha256 != config_sha256
        || request.protocol_version != PROTOCOL_VERSION
        || request.schema_version != config.schema_version
        || request.expected_generation != config.generation
        || request
            .rollback_from_generation
            .is_some_and(|generation| generation >= config.generation)
        || request.requested_at_unix_ms > now
        || request.expires_at_unix_ms <= request.requested_at_unix_ms
        || request.depth == 0
        || request.depth > config.max_depth
        || request.submodules.len() > config.max_submodules
        || !repository_admitted
        || !valid_ref(&request.authenticated_ref)
        || !ref_allowed(config, &request.authenticated_ref)
        || !is_object_id(&request.exact_commit)
    {
        return Err(SourceError::BindingMismatch);
    }
    if request.expires_at_unix_ms <= now {
        return Err(SourceError::ExpiredRequest);
    }
    if config.grant_expires_unix_ms <= now {
        return Err(SourceError::ExpiredGrant);
    }
    if [
        &request.checkout_name,
        &request.source_identity,
        &request.audit_lineage,
        &request.repository_identity,
        &request.repository_url,
        &request.authenticated_ref,
    ]
    .iter()
    .any(|value| !valid_binding_text(value))
    {
        return Err(SourceError::BindingMismatch);
    }
    validate_sparse_roots(
        &request.sparse_roots,
        &config.allowed_sparse_roots,
        config.max_path_bytes,
    )
    .map_err(|_| SourceError::BindingMismatch)?;
    let mut submodule_paths = BTreeSet::new();
    for submodule in &request.submodules {
        validate_repository_url(
            &submodule.repository_url,
            config.test_allow_file_repositories,
            config.test_allow_http_loopback,
        )
        .map_err(|_| SourceError::SubmoduleMismatch)?;
        validate_relative_path(&submodule.path, config.max_path_bytes)
            .map_err(|_| SourceError::SubmoduleMismatch)?;
        if !submodule_paths.insert(submodule.path.clone())
            || !is_object_id(&submodule.exact_commit)
            || !valid_ref(&submodule.authenticated_ref)
            || !ref_allowed(config, &submodule.authenticated_ref)
        {
            return Err(SourceError::SubmoduleMismatch);
        }
    }
    canonical_digest(request)
}

// Native publication starts its allowance before acquisition finishes. A
// verifier has no admission-start timestamp, so this is an upper bound on
// remaining publication time, never a reconstruction of the original deadline.
pub(super) fn publication_lifetime_ms(
    command_timeout_ms: u64,
    submodule_count: usize,
) -> Result<i64, SourceError> {
    u64::try_from(submodule_count)
        .ok()
        .and_then(|count| count.checked_add(1))
        .and_then(|count| count.checked_mul(8))
        .and_then(|commands| command_timeout_ms.checked_mul(commands))
        .and_then(|duration| duration.checked_add(MAX_LOCAL_PUBLICATION_MS))
        .and_then(|duration| i64::try_from(duration).ok())
        .ok_or(SourceError::InvalidConfig)
}

fn ref_allowed(config: &SourceConfig, reference: &str) -> bool {
    config
        .allowed_ref_prefixes
        .iter()
        .any(|prefix| reference.starts_with(prefix))
}

pub(super) fn authenticate_authority(
    config: &SourceConfig,
    config_sha256: &str,
    implementation_sha256: &str,
    signing_key: &[u8],
    receipt: &AcquisitionReceipt,
) -> Result<(), SourceError> {
    if receipt.protocol_version != PROTOCOL_VERSION
        || receipt.schema_version != config.schema_version
        || receipt.acquirer_id != config.acquirer_id
        || receipt.acquirer_implementation_sha256 != implementation_sha256
        || receipt.git_implementation_sha256 != config.git_executable_sha256
        || receipt.git_remote_https_implementation_sha256
            != config.git_remote_https_executable_sha256
        || receipt.runtime_closure_sha256 != config.runtime_closure_sha256
        || receipt.git_version != config.git_version
        || receipt.acquirer_config_sha256 != config_sha256
        || receipt.deployment_identity != config.deployment_identity
        || receipt.operator_identity != config.operator_identity
        || receipt.generation != config.generation
        || receipt.signing_key_id != config.receipt_signing_key_id
        || receipt.secret_marker_set_sha256 != config.secret_marker_set_sha256
        || receipt.output_relative_path != format!("{}/tree", receipt.acquisition_id)
        || receipt.transport_bytes > config.max_transport_bytes
    {
        return Err(SourceError::InvalidStoredReceipt);
    }
    verify_signature(signing_key, receipt)?;
    Ok(())
}

fn verify_signature(signing_key: &[u8], receipt: &AcquisitionReceipt) -> Result<(), SourceError> {
    let signature = URL_SAFE_NO_PAD
        .decode(receipt.signature.as_bytes())
        .map_err(|_| SourceError::InvalidStoredReceipt)?;
    let mut unsigned = receipt.clone();
    unsigned.signature.clear();
    let bytes = serde_json::to_vec(&unsigned).map_err(|_| SourceError::InvalidStoredReceipt)?;
    let mut mac =
        HmacSha256::new_from_slice(signing_key).map_err(|_| SourceError::InvalidConfig)?;
    mac.update(&bytes);
    mac.verify_slice(&signature)
        .map_err(|_| SourceError::InvalidStoredReceipt)
}

/// Immutable authentication authority. Construction only inspects supplied bytes;
/// it never opens paths, creates native state, or contacts a provider. In particular,
/// this is not certification that the configured runtime paths still exist.
/// Callers supply a size-controlled configuration snapshot and original request;
/// the stored-frame entrypoint separately bounds hostile receipt bytes.
/// Key and marker material deliberately have no Debug implementation.
pub struct ReceiptVerifier {
    config: SourceConfig,
    config_sha256: String,
    implementation_sha256: String,
    signing_key: Vec<u8>,
}

impl ReceiptVerifier {
    pub fn new(
        config: SourceConfig,
        implementation_sha256: String,
        signing_key: Vec<u8>,
        secret_markers: Vec<Vec<u8>>,
    ) -> Result<Self, SourceError> {
        if signing_key.len() > MAX_AUTHORITY_BYTES
            || secret_markers.len() > MAX_MARKERS
            || secret_markers
                .iter()
                .try_fold(0usize, |n, marker| n.checked_add(marker.len()))
                .is_none_or(|n| n > MAX_MARKER_BYTES)
        {
            return Err(SourceError::InvalidConfig);
        }
        // The marker snapshot already contains the credential marker by native
        // contract. Validate that contract without reading any credential file.
        let credential_marker = secret_markers
            .iter()
            .find(|marker| sha256_hex(marker) == config.credential_sha256)
            .ok_or(SourceError::InvalidConfig)?;
        if credential_marker.len() > MAX_AUTHORITY_BYTES {
            return Err(SourceError::InvalidConfig);
        }
        validate_config_snapshot(
            &config,
            &implementation_sha256,
            credential_marker,
            &signing_key,
            &secret_markers,
        )?;
        let config_sha256 = config.canonical_digest()?;
        Ok(Self {
            config,
            config_sha256,
            implementation_sha256,
            signing_key,
        })
    }

    /// Authenticate a bounded, single strict JSON receipt frame. Filesystem tree
    /// verification and present-time acquisition admission remain separate gates.
    pub fn authenticate_frame(
        &self,
        frame: &[u8],
        request: &AcquisitionRequest,
    ) -> Result<AcquisitionReceipt, SourceError> {
        if frame.len() > MAX_GIT_METADATA_BYTES {
            return Err(SourceError::InvalidStoredReceipt);
        }
        let receipt =
            parse_json_no_duplicates(frame).map_err(|_| SourceError::InvalidStoredReceipt)?;
        self.authenticate(&receipt, request)?;
        Ok(receipt)
    }

    /// Consistent historical evidence remains authentic after request/grant expiry. Validate
    /// its acquisition time against the original window, never mint a new window.
    /// The typed request and receipt are trusted-size inputs. Use
    /// `authenticate_frame` for untrusted stored receipt bytes.
    pub fn authenticate(
        &self,
        receipt: &AcquisitionReceipt,
        request: &AcquisitionRequest,
    ) -> Result<(), SourceError> {
        authenticate_request(
            &self.config,
            &self.config_sha256,
            &self.implementation_sha256,
            &self.signing_key,
            receipt,
            request,
        )
    }
}

pub(super) fn authenticate_request(
    config: &SourceConfig,
    config_sha256: &str,
    implementation_sha256: &str,
    signing_key: &[u8],
    receipt: &AcquisitionReceipt,
    request: &AcquisitionRequest,
) -> Result<(), SourceError> {
    authenticate_authority(
        config,
        config_sha256,
        implementation_sha256,
        signing_key,
        receipt,
    )?;
    let lifetime = publication_lifetime_ms(config.command_timeout_ms, request.submodules.len())
        .map_err(|_| SourceError::InvalidStoredReceipt)?;
    let request_digest = validate_request(
        config,
        config_sha256,
        implementation_sha256,
        request,
        receipt.acquired_at_unix_ms,
    )
    .map_err(|_| SourceError::InvalidStoredReceipt)?;
    if receipt.request_sha256 != request_digest
        || receipt.acquisition_id != request.acquisition_id
        || receipt.organization_id != request.organization_id
        || receipt.project_id != request.project_id
        || receipt.pipeline_id != request.pipeline_id
        || receipt.build_id != request.build_id
        || receipt.attempt_id != request.attempt_id
        || receipt.checkout_name != request.checkout_name
        || receipt.rollback_from_generation != request.rollback_from_generation
        || receipt.source_identity != request.source_identity
        || receipt.trust_class != request.trust_class
        || receipt.grant_id != config.grant_id
        || receipt.grant_version != config.grant_version
        || receipt.grant_scope != config.grant_scope
        || receipt.depth != request.depth
        || receipt.sparse_roots != request.sparse_roots
        || receipt.audit_lineage != request.audit_lineage
        || receipt.output_relative_path != format!("{}/tree", request.acquisition_id)
        || receipt.acquired_at_unix_ms < 0
        || receipt
            .publication_deadline_unix_ms
            .checked_sub(receipt.acquired_at_unix_ms)
            .is_none_or(|remaining| remaining <= 0 || remaining > lifetime)
        || receipt.publication_deadline_unix_ms > request.expires_at_unix_ms
        || receipt.publication_deadline_unix_ms > config.grant_expires_unix_ms
        || receipt.materialized_files == 0
        || receipt.materialized_files > config.max_files
        || receipt.materialized_bytes > config.max_total_bytes
        || !is_sha256_hex(&receipt.manifest_sha256)
        || receipt.content_sha256 != receipt.manifest_sha256
        || receipt.repository_trees.len() != request.submodules.len().saturating_add(1)
        || receipt
            .repository_trees
            .windows(2)
            .any(|pair| pair[0].path >= pair[1].path)
    {
        return Err(SourceError::InvalidStoredReceipt);
    }
    let primary = receipt
        .repository_trees
        .first()
        .ok_or(SourceError::InvalidStoredReceipt)?;
    if !primary.path.is_empty()
        || primary.provider_identity != request.provider_identity
        || primary.repository_identity != request.repository_identity
        || primary.repository_url != request.repository_url
        || primary.authenticated_ref != request.authenticated_ref
        || primary.resolved_commit != request.exact_commit
        || !is_object_id(&primary.resolved_tree)
    {
        return Err(SourceError::InvalidStoredReceipt);
    }
    for tree in receipt.repository_trees.iter().skip(1) {
        let submodule = request
            .submodules
            .iter()
            .find(|submodule| submodule.path == tree.path)
            .ok_or(SourceError::InvalidStoredReceipt)?;
        let binding = RepositoryBinding {
            provider_identity: tree.provider_identity.clone(),
            repository_identity: tree.repository_identity.clone(),
            repository_url: tree.repository_url.clone(),
        };
        if tree.provider_identity != submodule.provider_identity
            || tree.repository_identity != submodule.repository_identity
            || tree.repository_url != submodule.repository_url
            || tree.authenticated_ref != submodule.authenticated_ref
            || tree.resolved_commit != submodule.exact_commit
            || !is_object_id(&tree.resolved_tree)
            || !config.allowed_submodule_repositories.contains(&binding)
        {
            return Err(SourceError::InvalidStoredReceipt);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const CREDENTIAL: &[u8] = b"receipt-test-credential-000000";
    const SIGNING_KEY: &[u8] = b"receipt-test-signing-key-00000000000000000";

    fn fixture() -> (ReceiptVerifier, AcquisitionRequest, AcquisitionReceipt) {
        // Deliberately absent runtime/output paths: construction must not open them.
        let abs = std::env::temp_dir().join("mcloving-pure-receipt-nonexistent");
        let git_executable_path = abs.join("git");
        let git_remote_https_executable_path = abs.join("git-remote-https");
        let git_sha256 = "1".repeat(64);
        let git_remote_https_sha256 = "2".repeat(64);
        let implementation_sha256 = "3".repeat(64);
        let git_version = "git fixture".to_owned();
        let runtime_closure = vec![RuntimeBinding {
            path: abs.join("loader"),
            sha256: "4".repeat(64),
        }];
        let runtime_closure_sha256 = runtime_closure_digest(&runtime_closure).unwrap();
        let config = SourceConfig {
            protocol_version: PROTOCOL_VERSION.to_owned(),
            schema_version: "source-acquisition-v1".to_owned(),
            acquirer_id: "contained-source-acquirer".to_owned(),
            deployment_identity: "contained/deployment".to_owned(),
            operator_identity: "contained/operator".to_owned(),
            generation: 7,
            primary_repository: RepositoryBinding {
                provider_identity: "contained-git".to_owned(),
                repository_identity: "github:superbadlabs/mcloving".to_owned(),
                repository_url: "https://example.invalid/repo.git".to_owned(),
            },
            allow_untrusted_forks: false,
            allowed_fork_repositories: vec![],
            allowed_submodule_repositories: vec![],
            allowed_ref_prefixes: vec!["refs/heads/".to_owned()],
            allowed_sparse_roots: vec!["src".to_owned(), "deps".to_owned()],
            git_executable_path,
            git_executable_sha256: git_sha256,
            git_remote_https_executable_path,
            git_remote_https_executable_sha256: git_remote_https_sha256,
            runtime_closure,
            runtime_closure_sha256,
            git_version,
            grant_id: "contained-grant".to_owned(),
            grant_version: "grant-v1".to_owned(),
            grant_scope: "repository:read".to_owned(),
            grant_expires_unix_ms: 10_000,
            credential_username: "git".to_owned(),
            credential_sha256: sha256_hex(CREDENTIAL),
            receipt_signing_key_id: "contained-signing-key".to_owned(),
            receipt_signing_key_sha256: sha256_hex(SIGNING_KEY),
            secret_marker_set_sha256: marker_set_digest(&[CREDENTIAL.to_vec()]),
            max_depth: 32,
            max_files: 1_000,
            max_total_bytes: 2 * 1_024 * 1_024,
            max_file_bytes: 1024 * 1_024,
            max_transport_bytes: 16_777_216,
            max_path_bytes: 512,
            max_submodules: 16,
            command_timeout_ms: 30_000,
            transport_root: abs.join("transport"),
            output_root: abs.join("output"),
            ca_bundle_path: None,
            ca_bundle_sha256: None,
            test_allow_file_repositories: true,
            test_allow_http_loopback: false,
        };
        let request = AcquisitionRequest {
            acquisition_id: Uuid::new_v4(),
            organization_id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            pipeline_id: Uuid::new_v4(),
            build_id: Uuid::new_v4(),
            attempt_id: Uuid::new_v4(),
            checkout_name: "source".to_owned(),
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
            repository_url: config.primary_repository.repository_url.clone(),
            authenticated_ref: "refs/heads/main".to_owned(),
            exact_commit: "a".repeat(40),
            source_identity: "trusted/main".to_owned(),
            trust_class: TrustClass::Trusted,
            depth: 1,
            sparse_roots: Vec::new(),
            submodules: Vec::new(),
            requested_at_unix_ms: 100,
            expires_at_unix_ms: 9_000,
            audit_lineage: "audit/source/contained".to_owned(),
        };
        let mut receipt = AcquisitionReceipt {
            protocol_version: PROTOCOL_VERSION.to_owned(),
            schema_version: config.schema_version.clone(),
            acquisition_id: request.acquisition_id,
            request_sha256: canonical_digest(&request).unwrap(),
            organization_id: request.organization_id,
            project_id: request.project_id,
            pipeline_id: request.pipeline_id,
            build_id: request.build_id,
            attempt_id: request.attempt_id,
            checkout_name: request.checkout_name.clone(),
            acquirer_id: config.acquirer_id.clone(),
            acquirer_implementation_sha256: implementation_sha256.clone(),
            git_implementation_sha256: config.git_executable_sha256.clone(),
            git_remote_https_implementation_sha256: config
                .git_remote_https_executable_sha256
                .clone(),
            runtime_closure_sha256: config.runtime_closure_sha256.clone(),
            git_version: config.git_version.clone(),
            acquirer_config_sha256: config.canonical_digest().unwrap(),
            deployment_identity: config.deployment_identity.clone(),
            operator_identity: config.operator_identity.clone(),
            generation: config.generation,
            rollback_from_generation: request.rollback_from_generation,
            source_identity: request.source_identity.clone(),
            trust_class: request.trust_class,
            grant_id: config.grant_id.clone(),
            grant_version: config.grant_version.clone(),
            grant_scope: config.grant_scope.clone(),
            depth: request.depth,
            sparse_roots: request.sparse_roots.clone(),
            repository_trees: vec![RepositoryTreeReceipt {
                path: String::new(),
                provider_identity: request.provider_identity.clone(),
                repository_identity: request.repository_identity.clone(),
                repository_url: request.repository_url.clone(),
                authenticated_ref: request.authenticated_ref.clone(),
                resolved_commit: request.exact_commit.clone(),
                resolved_tree: "b".repeat(40),
            }],
            manifest_sha256: "c".repeat(64),
            content_sha256: "c".repeat(64),
            materialized_files: 1,
            materialized_bytes: 20,
            transport_bytes: 30,
            output_relative_path: format!("{}/tree", request.acquisition_id),
            acquired_at_unix_ms: 200,
            publication_deadline_unix_ms: 8_000,
            audit_lineage: request.audit_lineage.clone(),
            signing_key_id: config.receipt_signing_key_id.clone(),
            secret_marker_set_sha256: config.secret_marker_set_sha256.clone(),
            signature: String::new(),
        };
        sign(&mut receipt);
        let verifier = ReceiptVerifier::new(
            config,
            implementation_sha256,
            SIGNING_KEY.to_vec(),
            vec![CREDENTIAL.to_vec()],
        )
        .unwrap();
        (verifier, request, receipt)
    }

    fn sign(receipt: &mut AcquisitionReceipt) {
        receipt.signature.clear();
        let mut mac = HmacSha256::new_from_slice(SIGNING_KEY).unwrap();
        mac.update(&serde_json::to_vec(receipt).unwrap());
        receipt.signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    }
    #[test]
    fn pure_constructor_and_historical_authentication_need_no_native_state() {
        let (verifier, request, receipt) = fixture();
        assert!(receipt.publication_deadline_unix_ms < now_unix_ms().unwrap());
        verifier.authenticate(&receipt, &request).unwrap();
        assert_eq!(
            verifier
                .authenticate_frame(&serde_json::to_vec(&receipt).unwrap(), &request)
                .unwrap(),
            receipt
        );
    }

    #[test]
    fn signed_context_and_authority_mutations_fail_independently_of_hmac() {
        let (verifier, request, receipt) = fixture();
        let original = serde_json::to_value(&receipt).unwrap();
        let mutations = [
            ("protocol_version", serde_json::json!("other")),
            ("schema_version", serde_json::json!("other")),
            ("acquisition_id", serde_json::json!(Uuid::new_v4())),
            ("request_sha256", serde_json::json!("d".repeat(64))),
            ("organization_id", serde_json::json!(Uuid::new_v4())),
            ("project_id", serde_json::json!(Uuid::new_v4())),
            ("pipeline_id", serde_json::json!(Uuid::new_v4())),
            ("build_id", serde_json::json!(Uuid::new_v4())),
            ("attempt_id", serde_json::json!(Uuid::new_v4())),
            ("checkout_name", serde_json::json!("other")),
            ("acquirer_id", serde_json::json!("other")),
            (
                "acquirer_implementation_sha256",
                serde_json::json!("d".repeat(64)),
            ),
            (
                "git_implementation_sha256",
                serde_json::json!("d".repeat(64)),
            ),
            (
                "git_remote_https_implementation_sha256",
                serde_json::json!("d".repeat(64)),
            ),
            ("runtime_closure_sha256", serde_json::json!("d".repeat(64))),
            ("git_version", serde_json::json!("other")),
            ("acquirer_config_sha256", serde_json::json!("d".repeat(64))),
            ("deployment_identity", serde_json::json!("other")),
            ("operator_identity", serde_json::json!("other")),
            ("generation", serde_json::json!(8)),
            ("rollback_from_generation", serde_json::json!(6)),
            ("source_identity", serde_json::json!("other")),
            ("trust_class", serde_json::json!("untrusted_fork")),
            ("grant_id", serde_json::json!("other")),
            ("grant_version", serde_json::json!("other")),
            ("grant_scope", serde_json::json!("other")),
            ("depth", serde_json::json!(2)),
            ("sparse_roots", serde_json::json!(["src"])),
            ("manifest_sha256", serde_json::json!("invalid")),
            ("content_sha256", serde_json::json!("d".repeat(64))),
            ("materialized_files", serde_json::json!(1001)),
            ("materialized_bytes", serde_json::json!(2_097_153)),
            ("transport_bytes", serde_json::json!(16_777_217)),
            ("output_relative_path", serde_json::json!("elsewhere/tree")),
            ("acquired_at_unix_ms", serde_json::json!(99)),
            ("publication_deadline_unix_ms", serde_json::json!(10_001)),
            ("audit_lineage", serde_json::json!("other")),
            ("signing_key_id", serde_json::json!("other")),
            (
                "secret_marker_set_sha256",
                serde_json::json!("d".repeat(64)),
            ),
        ];
        for (field, value) in mutations {
            let mut changed = original.clone();
            changed[field] = value;
            let mut changed: AcquisitionReceipt = serde_json::from_value(changed).unwrap();
            sign(&mut changed);
            verify_signature(SIGNING_KEY, &changed).unwrap();
            assert!(
                matches!(
                    verifier.authenticate(&changed, &request),
                    Err(SourceError::InvalidStoredReceipt)
                ),
                "accepted signed {field} mutation"
            );
        }
    }

    #[test]
    fn every_original_request_field_is_committed() {
        let (verifier, request, receipt) = fixture();
        let original = serde_json::to_value(&request).unwrap();
        for (field, value) in original.as_object().unwrap() {
            let changed_value = match value {
                serde_json::Value::String(text) if Uuid::parse_str(text).is_ok() => {
                    serde_json::json!(Uuid::new_v4())
                }
                serde_json::Value::String(_) if field == "trust_class" => {
                    serde_json::json!("untrusted_fork")
                }
                serde_json::Value::String(text) => serde_json::json!(format!("{text}x")),
                serde_json::Value::Number(n) => serde_json::json!(n.as_i64().unwrap() + 1),
                serde_json::Value::Null => serde_json::json!(6),
                serde_json::Value::Array(_) if field == "sparse_roots" => {
                    serde_json::json!(["src"])
                }
                serde_json::Value::Array(_) => {
                    serde_json::json!([{"path":"deps/module", "provider_identity":"p", "repository_identity":"r", "repository_url":"https://example.invalid/module.git", "authenticated_ref":"refs/heads/main", "exact_commit":"a".repeat(40)}])
                }
                _ => panic!("unhandled request field {field}"),
            };
            let mut changed = original.clone();
            changed[field] = changed_value;
            let changed: AcquisitionRequest = serde_json::from_value(changed).unwrap();
            assert!(
                verifier.authenticate(&receipt, &changed).is_err(),
                "uncommitted request field {field}"
            );
        }
    }

    #[test]
    fn strict_frames_reject_duplicate_unknown_trailing_and_oversize_data() {
        let (verifier, request, receipt) = fixture();
        let frame = serde_json::to_string(&receipt).unwrap();
        let duplicate = frame.replacen("{", "{\"protocol_version\":\"ignored\",", 1);
        let unknown = frame.replacen("{", "{\"unknown\":true,", 1);
        for bad in [
            duplicate,
            unknown,
            format!("{frame}{{}}"),
            format!("{frame} garbage"),
        ] {
            assert!(matches!(
                verifier.authenticate_frame(bad.as_bytes(), &request),
                Err(SourceError::InvalidStoredReceipt)
            ));
        }
        assert!(
            verifier
                .authenticate_frame(&vec![b' '; MAX_GIT_METADATA_BYTES + 1], &request)
                .is_err()
        );
        let mut bad = receipt.clone();
        bad.signature.push('A');
        assert!(verifier.authenticate(&bad, &request).is_err());
    }

    #[test]
    fn inconsistent_authority_snapshots_fail_without_native_paths() {
        let (verifier, _, _) = fixture();
        let mut bad = verifier.config.clone();
        bad.max_files = 0;
        assert!(
            ReceiptVerifier::new(
                bad,
                verifier.implementation_sha256.clone(),
                SIGNING_KEY.to_vec(),
                vec![CREDENTIAL.to_vec()]
            )
            .is_err()
        );
        let mut bad = verifier.config.clone();
        bad.runtime_closure_sha256 = "f".repeat(64);
        assert!(
            ReceiptVerifier::new(
                bad,
                verifier.implementation_sha256.clone(),
                SIGNING_KEY.to_vec(),
                vec![CREDENTIAL.to_vec()]
            )
            .is_err()
        );
        assert!(
            ReceiptVerifier::new(
                verifier.config.clone(),
                verifier.implementation_sha256.clone(),
                vec![1; 32],
                vec![CREDENTIAL.to_vec()]
            )
            .is_err()
        );
        // Native credential reads are bounded even when the supplied marker
        // set itself fits its larger aggregate allowance.
        let oversized_credential = vec![b'x'; MAX_AUTHORITY_BYTES + 1];
        let mut bad = verifier.config.clone();
        bad.credential_sha256 = sha256_hex(&oversized_credential);
        bad.secret_marker_set_sha256 =
            marker_set_digest(std::slice::from_ref(&oversized_credential));
        assert!(
            ReceiptVerifier::new(
                bad,
                verifier.implementation_sha256.clone(),
                SIGNING_KEY.to_vec(),
                vec![oversized_credential],
            )
            .is_err()
        );
        assert!(
            ReceiptVerifier::new(
                verifier.config,
                verifier.implementation_sha256,
                SIGNING_KEY.to_vec(),
                vec![b"other marker".to_vec()]
            )
            .is_err()
        );
    }
    #[test]
    fn signed_repository_and_time_substitutions_fail() {
        let (verifier, request, receipt) = fixture();
        let original = serde_json::to_value(&receipt).unwrap();
        for field in [
            "path",
            "provider_identity",
            "repository_identity",
            "repository_url",
            "authenticated_ref",
            "resolved_commit",
            "resolved_tree",
        ] {
            let mut changed = original.clone();
            changed["repository_trees"][0][field] = serde_json::json!("substituted");
            let mut changed: AcquisitionReceipt = serde_json::from_value(changed).unwrap();
            sign(&mut changed);
            verify_signature(SIGNING_KEY, &changed).unwrap();
            assert!(
                verifier.authenticate(&changed, &request).is_err(),
                "accepted repository {field}"
            );
        }
        for (acquired, deadline) in [
            (100, 100),
            (200, 199),
            (9_000, 9_001),
            (200, 9_001),
            (i64::MAX, i64::MAX),
        ] {
            let mut changed = receipt.clone();
            changed.acquired_at_unix_ms = acquired;
            changed.publication_deadline_unix_ms = deadline;
            sign(&mut changed);
            assert!(verifier.authenticate(&changed, &request).is_err());
        }
        let mut changed = receipt.clone();
        changed.materialized_files = 0;
        sign(&mut changed);
        assert!(verifier.authenticate(&changed, &request).is_err());

        // Native acquisition samples duration_since(UNIX_EPOCH), so it cannot
        // issue a negative acquisition time even for a negative requested-at.
        let mut old_request = request.clone();
        old_request.requested_at_unix_ms = -10;
        let mut changed = receipt.clone();
        changed.request_sha256 = canonical_digest(&old_request).unwrap();
        sign(&mut changed);
        verifier.authenticate(&changed, &old_request).unwrap();
        changed.acquired_at_unix_ms = -1;
        sign(&mut changed);
        verify_signature(SIGNING_KEY, &changed).unwrap();
        assert!(verifier.authenticate(&changed, &old_request).is_err());
    }

    #[test]
    fn signed_submodule_graph_binds_full_original_request_and_allowlist() {
        let (mut verifier, mut request, mut receipt) = fixture();
        let submodule = SubmoduleRequest {
            path: "deps/module".to_owned(),
            provider_identity: "module-provider".to_owned(),
            repository_identity: "module-repo".to_owned(),
            repository_url: "https://example.invalid/module.git".to_owned(),
            authenticated_ref: "refs/heads/main".to_owned(),
            exact_commit: "d".repeat(40),
        };
        verifier
            .config
            .allowed_submodule_repositories
            .push(RepositoryBinding {
                provider_identity: submodule.provider_identity.clone(),
                repository_identity: submodule.repository_identity.clone(),
                repository_url: submodule.repository_url.clone(),
            });
        verifier.config_sha256 = verifier.config.canonical_digest().unwrap();
        request.expected_config_sha256 = verifier.config_sha256.clone();
        request.submodules.push(submodule.clone());
        receipt.acquirer_config_sha256 = verifier.config_sha256.clone();
        receipt.request_sha256 = canonical_digest(&request).unwrap();
        receipt.repository_trees.push(RepositoryTreeReceipt {
            path: submodule.path,
            provider_identity: submodule.provider_identity,
            repository_identity: submodule.repository_identity,
            repository_url: submodule.repository_url,
            authenticated_ref: submodule.authenticated_ref,
            resolved_commit: submodule.exact_commit,
            resolved_tree: "e".repeat(40),
        });
        sign(&mut receipt);
        verifier.authenticate(&receipt, &request).unwrap();
        let original = serde_json::to_value(&receipt).unwrap();
        for field in [
            "path",
            "provider_identity",
            "repository_identity",
            "repository_url",
            "authenticated_ref",
            "resolved_commit",
            "resolved_tree",
        ] {
            let mut changed = original.clone();
            changed["repository_trees"][1][field] = serde_json::json!("substituted");
            let mut changed: AcquisitionReceipt = serde_json::from_value(changed).unwrap();
            sign(&mut changed);
            assert!(
                verifier.authenticate(&changed, &request).is_err(),
                "accepted submodule {field}"
            );
        }
        let mut changed = receipt.clone();
        changed.repository_trees.swap(0, 1);
        sign(&mut changed);
        assert!(verifier.authenticate(&changed, &request).is_err());
        let mut changed = receipt.clone();
        changed
            .repository_trees
            .push(changed.repository_trees[1].clone());
        sign(&mut changed);
        assert!(verifier.authenticate(&changed, &request).is_err());
        verifier.config.allowed_submodule_repositories.clear();
        verifier.config_sha256 = verifier.config.canonical_digest().unwrap();
        request.expected_config_sha256 = verifier.config_sha256.clone();
        receipt.acquirer_config_sha256 = verifier.config_sha256.clone();
        receipt.request_sha256 = canonical_digest(&request).unwrap();
        sign(&mut receipt);
        assert!(verifier.authenticate(&receipt, &request).is_err());
    }

    #[test]
    fn signed_publication_window_respects_checked_native_lifetime_bound() {
        let (mut verifier, mut request, mut receipt) = fixture();
        verifier.config.command_timeout_ms = 1;
        verifier.config.grant_expires_unix_ms = 1_000_000;
        verifier.config_sha256 = verifier.config.canonical_digest().unwrap();
        request.expected_config_sha256 = verifier.config_sha256.clone();
        request.expires_at_unix_ms = 1_000_000;
        receipt.acquirer_config_sha256 = verifier.config_sha256.clone();
        receipt.request_sha256 = canonical_digest(&request).unwrap();
        receipt.publication_deadline_unix_ms = receipt.acquired_at_unix_ms + 120_008;
        sign(&mut receipt);
        verifier.authenticate(&receipt, &request).unwrap();
        receipt.publication_deadline_unix_ms += 1;
        sign(&mut receipt);
        verify_signature(SIGNING_KEY, &receipt).unwrap();
        assert!(matches!(
            verifier.authenticate(&receipt, &request),
            Err(SourceError::InvalidStoredReceipt)
        ));

        assert_eq!(publication_lifetime_ms(30_000, 0).unwrap(), 360_000);
        assert_eq!(publication_lifetime_ms(30_000, 2).unwrap(), 840_000);
        assert!(publication_lifetime_ms(u64::MAX, 0).is_err());
        assert!(publication_lifetime_ms(u64::MAX, usize::MAX).is_err());
        #[cfg(target_pointer_width = "64")]
        assert!(publication_lifetime_ms(1, usize::MAX).is_err());
        assert!(publication_lifetime_ms(i64::MAX as u64, 0).is_err());

        // Subtraction, rather than acquired+allowance, avoids falsely rejecting
        // a small remaining window near the representable timestamp ceiling.
        verifier.config.grant_expires_unix_ms = i64::MAX;
        verifier.config_sha256 = verifier.config.canonical_digest().unwrap();
        request.expected_config_sha256 = verifier.config_sha256.clone();
        request.requested_at_unix_ms = i64::MAX - 240_016;
        request.expires_at_unix_ms = i64::MAX;
        receipt.acquirer_config_sha256 = verifier.config_sha256.clone();
        receipt.request_sha256 = canonical_digest(&request).unwrap();
        receipt.acquired_at_unix_ms = i64::MAX - 2;
        receipt.publication_deadline_unix_ms = i64::MAX;
        sign(&mut receipt);
        verifier.authenticate(&receipt, &request).unwrap();

        request.requested_at_unix_ms = i64::MIN;
        receipt.request_sha256 = canonical_digest(&request).unwrap();
        receipt.acquired_at_unix_ms = i64::MIN;
        sign(&mut receipt);
        assert!(verifier.authenticate(&receipt, &request).is_err());
    }
}
