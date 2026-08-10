use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use mcloving_dependency_resolver::{
    AdapterBindings, AdapterConfig, CertifiedConfig, Ecosystem, GrantUse, RepositoryBinding,
    RepositoryConfig, RepositoryGrant, ResolutionRequest, ResolverLimits, SourceProvenance,
    SourceTrustClass, admit_request, configuration_sha256, parse_maven_lock,
    source_provenance_message, validate_config,
};
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use sha2::{Digest, Sha256};

const NOW: u64 = 1_000;

fn source_key_pair() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[17_u8; 32]).expect("source attestation key")
}

fn source_public_key() -> Vec<u8> {
    source_key_pair().public_key().as_ref().to_vec()
}

fn sign_request(request: &mut ResolutionRequest) {
    request.source_provenance.signature_base64.clear();
    let message = source_provenance_message(request).expect("source provenance message");
    request.source_provenance.signature_base64 =
        STANDARD_NO_PAD.encode(source_key_pair().sign(&message).as_ref());
}

fn admit(
    config: &CertifiedConfig,
    request: &ResolutionRequest,
    plan: &mcloving_dependency_resolver::CanonicalPlan,
    lock: &[u8],
    now: u64,
) -> Result<mcloving_dependency_resolver::AdmittedRequest, mcloving_dependency_resolver::RequestError>
{
    admit_request(config, &source_public_key(), request, plan, lock, now)
}

fn lock_bytes() -> Vec<u8> {
    format!(
        r#"{{
          "schema_version":"mcloving.maven-lock/v1",
          "nodes":[{{
            "key":"app",
            "group":"com.example",
            "artifact":"app",
            "artifact_type":"jar",
            "classifier":null,
            "version":"1.0.0",
            "repository_id":"contained-maven",
            "artifact_path":"com/example/app/1.0.0/app-1.0.0.jar",
            "declared_size":12,
            "sha256":"{}",
            "attestation_key_id":"contained-key",
            "dependencies":[]
          }}],
          "roots":["app"]
        }}"#,
        "d".repeat(64)
    )
    .into_bytes()
}

fn config() -> CertifiedConfig {
    CertifiedConfig {
        schema_version: "mcloving.dependency-config/v1".to_owned(),
        protocol_version: "mcloving.dependency-resolver/v1".to_owned(),
        configuration_id: "contained-dependency-config".to_owned(),
        deployment_id: "contained-deployment".to_owned(),
        operator_id: "contained-operator".to_owned(),
        generation: 7,
        executable_sha256: "f".repeat(64),
        resolver_toolchain_id: "maven-exporter-1".to_owned(),
        resolver_toolchain_sha256: "c".repeat(64),
        adapters: vec![
            AdapterConfig {
                ecosystem: Ecosystem::Maven,
                adapter_id: "maven-lock-v1".to_owned(),
                implementation_sha256: "a".repeat(64),
            },
            AdapterConfig {
                ecosystem: Ecosystem::Npm,
                adapter_id: "npm-package-lock-v3".to_owned(),
                implementation_sha256: "1".repeat(64),
            },
            AdapterConfig {
                ecosystem: Ecosystem::Pypi,
                adapter_id: "pypi-requirements-v1".to_owned(),
                implementation_sha256: "2".repeat(64),
            },
        ],
        repositories: vec![RepositoryConfig {
            repository_id: "contained-maven".to_owned(),
            ecosystem: Ecosystem::Maven,
            base_url: "http://127.0.0.1:18443/repository/".to_owned(),
            coordinate_prefixes: vec!["com.example:".to_owned()],
            credential_path: Some("/etc/mcloving/dependency/maven.credential".to_owned()),
            credential_sha256: Some("3".repeat(64)),
            permits_untrusted_source: false,
            attestation_key_id: "contained-key".to_owned(),
            attestation_key_path: "/etc/mcloving/dependency/maven-attestation.pub".to_owned(),
            attestation_key_sha256: "4".repeat(64),
            private_ca_path: None,
            private_ca_sha256: None,
            grant: Some(RepositoryGrant {
                grant_id: "contained-grant".to_owned(),
                version: 2,
                scope: "read:com.example".to_owned(),
                expires_at_unix_ms: 2_000,
            }),
        }],
        source_attestation_key_id: "contained-source-key".to_owned(),
        source_attestation_key_path: "/etc/mcloving/dependency/source-attestation.pub".to_owned(),
        source_attestation_key_sha256: format!("{:x}", Sha256::digest(source_public_key())),
        receipt_key_id: "contained-receipt-key".to_owned(),
        receipt_key_path: "/etc/mcloving/dependency/receipt.key".to_owned(),
        receipt_key_sha256: "5".repeat(64),
        secret_marker_set_path: "/etc/mcloving/dependency/secret-markers".to_owned(),
        secret_marker_set_sha256: "6".repeat(64),
        output_root: "/var/lib/mcloving/dependencies".to_owned(),
        transport_root: "/mnt/mcloving-dependency-transport".to_owned(),
        limits: ResolverLimits {
            max_frame_bytes: 1_048_576,
            max_lock_bytes: 262_144,
            max_repositories: 8,
            max_nodes: 1_000,
            max_edges: 10_000,
            max_artifacts: 1_000,
            max_artifact_bytes: 1024 * 1024,
            max_total_artifact_bytes: 16 * 1024 * 1024,
            transport_capacity_bytes: 16 * 1024 * 1024,
            max_path_bytes: 4_096,
            max_header_bytes: 16_384,
            max_request_lifetime_ms: 10_000,
        },
        loopback_fixture: true,
    }
}

fn fixture() -> (
    CertifiedConfig,
    Vec<u8>,
    mcloving_dependency_resolver::CanonicalPlan,
    ResolutionRequest,
) {
    let config = config();
    let lock = lock_bytes();
    let plan = parse_maven_lock(
        &lock,
        &AdapterBindings {
            adapter_id: "maven-lock-v1".to_owned(),
            adapter_sha256: "a".repeat(64),
            source_tree_sha256: "b".repeat(64),
            resolver_toolchain_id: "maven-exporter-1".to_owned(),
            resolver_toolchain_sha256: "c".repeat(64),
            source_trust_class: SourceTrustClass::Trusted,
            repositories: vec![RepositoryBinding {
                repository_id: "contained-maven".to_owned(),
                credentialed: true,
                permits_untrusted_source: false,
            }],
        },
    )
    .expect("contained Maven plan");
    let mut request = ResolutionRequest {
        schema_version: "mcloving.dependency-request/v1".to_owned(),
        protocol_version: config.protocol_version.clone(),
        resolution_id: "11111111-1111-4111-8111-111111111111".to_owned(),
        tenant_id: "tenant-a".to_owned(),
        project_id: "project-a".to_owned(),
        pipeline_id: "pipeline-a".to_owned(),
        build_id: "22222222-2222-4222-8222-222222222222".to_owned(),
        attempt_id: "33333333-3333-4333-8333-333333333333".to_owned(),
        audit_lineage: "audit/contained/1".to_owned(),
        source_trust_class: SourceTrustClass::Trusted,
        source_provenance: SourceProvenance {
            schema_version: "mcloving.source-provenance/v1".to_owned(),
            key_id: config.source_attestation_key_id.clone(),
            issued_at_unix_ms: 900,
            expires_at_unix_ms: 1_500,
            signature_base64: String::new(),
        },
        expected_executable_sha256: config.executable_sha256.clone(),
        expected_configuration_sha256: configuration_sha256(&config).expect("config digest"),
        expected_adapter_id: plan.adapter_id.clone(),
        expected_adapter_sha256: plan.adapter_sha256.clone(),
        expected_resolver_toolchain_id: plan.resolver_toolchain_id.clone(),
        expected_resolver_toolchain_sha256: plan.resolver_toolchain_sha256.clone(),
        expected_generation: config.generation,
        acquisition_receipt_sha256: "7".repeat(64),
        source_tree_sha256: plan.source_tree_sha256.clone(),
        logical_lock_path: "dependency-locks/maven-lock.json".to_owned(),
        expected_lock_sha256: plan.lock_sha256.clone(),
        ecosystem: Ecosystem::Maven,
        expected_graph_sha256: plan.graph_sha256.clone(),
        repository_ids: vec!["contained-maven".to_owned()],
        grants: vec![GrantUse {
            repository_id: "contained-maven".to_owned(),
            grant_id: "contained-grant".to_owned(),
            version: 2,
            scope: "read:com.example".to_owned(),
        }],
        requested_at_unix_ms: 900,
        expires_at_unix_ms: 1_500,
        rollback_from_generation: None,
    };
    sign_request(&mut request);
    (config, lock, plan, request)
}

#[test]
fn exact_configuration_request_plan_and_lock_are_admitted() {
    let (config, lock, plan, request) = fixture();
    let admitted = admit(&config, &request, &plan, &lock, NOW).expect("admitted");
    assert_eq!(
        admitted.configuration_sha256,
        request.expected_configuration_sha256
    );
    assert_eq!(admitted.absolute_expiry_unix_ms, 1_500);
    assert_eq!(admitted.repository_ids, vec!["contained-maven"]);
}

fn assert_source_provenance_denied(
    config: &CertifiedConfig,
    lock: &[u8],
    plan: &mcloving_dependency_resolver::CanonicalPlan,
    request: &ResolutionRequest,
) {
    assert_eq!(
        admit(config, request, plan, lock, NOW)
            .expect_err("source provenance substitution")
            .code,
        "DEP_REQUEST_SOURCE_PROVENANCE_INVALID"
    );
}

#[test]
fn source_provenance_binds_trust_source_lock_scope_and_receipt() {
    let (config, lock, plan, request) = fixture();

    let mut substituted = request.clone();
    substituted.source_trust_class = SourceTrustClass::Untrusted;
    assert_source_provenance_denied(&config, &lock, &plan, &substituted);

    let mut substituted = request.clone();
    substituted.acquisition_receipt_sha256 = "8".repeat(64);
    assert_source_provenance_denied(&config, &lock, &plan, &substituted);

    let mut substituted = request.clone();
    substituted.source_tree_sha256 = "8".repeat(64);
    assert_source_provenance_denied(&config, &lock, &plan, &substituted);

    let mut substituted = request.clone();
    substituted.logical_lock_path = "dependency-locks/substituted.json".to_owned();
    assert_source_provenance_denied(&config, &lock, &plan, &substituted);

    let mut substituted = request.clone();
    substituted.expected_lock_sha256 = "8".repeat(64);
    assert_source_provenance_denied(&config, &lock, &plan, &substituted);

    let mut substituted = request;
    substituted.tenant_id = "tenant-b".to_owned();
    assert_source_provenance_denied(&config, &lock, &plan, &substituted);
}

#[test]
fn source_provenance_authority_lifetime_and_signature_fail_closed() {
    let (config, lock, plan, request) = fixture();

    let mut substituted = request.clone();
    substituted.source_provenance.key_id = "attacker-key".to_owned();
    assert_source_provenance_denied(&config, &lock, &plan, &substituted);

    let mut substituted = request.clone();
    substituted.source_provenance.issued_at_unix_ms += 1;
    assert_source_provenance_denied(&config, &lock, &plan, &substituted);

    let mut substituted = request.clone();
    substituted.source_provenance.expires_at_unix_ms -= 1;
    assert_source_provenance_denied(&config, &lock, &plan, &substituted);

    let mut substituted = request.clone();
    substituted
        .source_provenance
        .signature_base64
        .replace_range(..1, "A");
    if substituted.source_provenance.signature_base64 == request.source_provenance.signature_base64
    {
        substituted
            .source_provenance
            .signature_base64
            .replace_range(..1, "B");
    }
    assert_source_provenance_denied(&config, &lock, &plan, &substituted);

    assert_eq!(
        admit_request(&config, &[99_u8; 32], &request, &plan, &lock, NOW)
            .expect_err("wrong source authority")
            .code,
        "DEP_REQUEST_SOURCE_PROVENANCE_INVALID"
    );
}

#[test]
fn configuration_tls_trust_and_limits_fail_closed() {
    let mut invalid = config();
    invalid.loopback_fixture = false;
    assert_eq!(
        validate_config(&invalid)
            .expect_err("cleartext production URL")
            .code,
        "DEP_CONFIG_REPOSITORY_TLS_INVALID"
    );

    let mut invalid = config();
    invalid.repositories[0].permits_untrusted_source = true;
    assert_eq!(
        validate_config(&invalid)
            .expect_err("credential trust")
            .code,
        "DEP_CONFIG_REPOSITORY_TRUST_INVALID"
    );

    let mut invalid = config();
    invalid.limits.max_artifact_bytes = invalid.limits.max_total_artifact_bytes + 1;
    assert_eq!(
        validate_config(&invalid)
            .expect_err("inconsistent limits")
            .code,
        "DEP_CONFIG_LIMITS_INVALID"
    );

    let mut invalid = config();
    invalid.limits.max_frame_bytes = 1;
    invalid.limits.max_lock_bytes = 1;
    assert_eq!(
        validate_config(&invalid)
            .expect_err("frame too small for a bounded error")
            .code,
        "DEP_CONFIG_LIMITS_INVALID"
    );

    let mut invalid = config();
    invalid.limits.max_path_bytes = 4_097;
    assert_eq!(
        validate_config(&invalid)
            .expect_err("path limit exceeds protocol ceiling")
            .code,
        "DEP_CONFIG_LIMITS_INVALID"
    );

    let mut invalid = config();
    invalid.transport_root = format!("{}/bundles", invalid.output_root);
    assert_eq!(
        validate_config(&invalid)
            .expect_err("nested transport and output roots")
            .code,
        "DEP_CONFIG_ROOT_OVERLAP"
    );

    let mut invalid = config();
    invalid.receipt_key_path = format!("{}/receipts/raw-key", invalid.output_root);
    assert_eq!(
        validate_config(&invalid)
            .expect_err("authority beneath mutable output")
            .code,
        "DEP_CONFIG_AUTHORITY_ROOT_OVERLAP"
    );
}

#[test]
fn runtime_lock_plan_and_repository_substitution_are_denied() {
    let (config, lock, plan, mut request) = fixture();
    request.expected_generation += 1;
    assert_eq!(
        admit(&config, &request, &plan, &lock, NOW)
            .expect_err("generation substitution")
            .code,
        "DEP_REQUEST_RUNTIME_BINDING_MISMATCH"
    );

    let (config, _lock, plan, request) = fixture();
    assert_eq!(
        admit(&config, &request, &plan, b"substituted", NOW)
            .expect_err("lock substitution")
            .code,
        "DEP_REQUEST_LOCK_MISMATCH"
    );

    let (mut config, lock, plan, mut request) = fixture();
    config.repositories[0].coordinate_prefixes = vec!["org.other:".to_owned()];
    request.expected_configuration_sha256 = configuration_sha256(&config).expect("new digest");
    sign_request(&mut request);
    assert_eq!(
        admit(&config, &request, &plan, &lock, NOW)
            .expect_err("coordinate policy")
            .code,
        "DEP_REQUEST_REPOSITORY_POLICY_DENIED"
    );
}

#[test]
fn repository_and_grant_bindings_unused_by_the_graph_are_denied() {
    let (mut config, lock, mut plan, mut request) = fixture();
    let mut unused = config.repositories[0].clone();
    unused.repository_id = "unused-maven".to_owned();
    unused.base_url = "http://127.0.0.1:18444/unused/".to_owned();
    unused.credential_path = Some("/etc/mcloving/dependency/unused.credential".to_owned());
    unused.credential_sha256 = Some("8".repeat(64));
    unused.attestation_key_id = "unused-key".to_owned();
    unused.attestation_key_path = "/etc/mcloving/dependency/unused-attestation.pub".to_owned();
    unused.attestation_key_sha256 = "9".repeat(64);
    unused.grant = Some(RepositoryGrant {
        grant_id: "unused-grant".to_owned(),
        version: 1,
        scope: "read:unused".to_owned(),
        expires_at_unix_ms: 2_000,
    });
    config.repositories.push(unused);

    plan.repositories.push(RepositoryBinding {
        repository_id: "unused-maven".to_owned(),
        credentialed: true,
        permits_untrusted_source: false,
    });
    plan.graph_sha256 = mcloving_dependency_resolver::canonical_graph_sha256(&plan)
        .expect("graph with unused repository binding");

    request.expected_configuration_sha256 =
        configuration_sha256(&config).expect("configuration with unused repository");
    request.expected_graph_sha256 = plan.graph_sha256.clone();
    request.repository_ids.push("unused-maven".to_owned());
    request.grants.push(GrantUse {
        repository_id: "unused-maven".to_owned(),
        grant_id: "unused-grant".to_owned(),
        version: 1,
        scope: "read:unused".to_owned(),
    });
    sign_request(&mut request);

    assert_eq!(
        admit(&config, &request, &plan, &lock, NOW)
            .expect_err("unused repository binding")
            .code,
        "DEP_REQUEST_REPOSITORY_SET_MISMATCH"
    );
}

#[test]
fn grants_expiry_rollback_and_resource_bounds_are_denied() {
    let (config, lock, plan, mut request) = fixture();
    request.grants.clear();
    sign_request(&mut request);
    assert_eq!(
        admit(&config, &request, &plan, &lock, NOW)
            .expect_err("grant omission")
            .code,
        "DEP_REQUEST_GRANT_MISMATCH"
    );

    let (config, lock, plan, mut request) = fixture();
    request.rollback_from_generation = Some(config.generation);
    sign_request(&mut request);
    assert_eq!(
        admit(&config, &request, &plan, &lock, NOW)
            .expect_err("rollback")
            .code,
        "DEP_REQUEST_ROLLBACK_INVALID"
    );

    let (mut config, lock, plan, mut request) = fixture();
    config.limits.max_artifact_bytes = 1;
    request.expected_configuration_sha256 = configuration_sha256(&config).expect("new digest");
    sign_request(&mut request);
    assert_eq!(
        admit(&config, &request, &plan, &lock, NOW)
            .expect_err("artifact bound")
            .code,
        "DEP_REQUEST_RESOURCE_LIMIT_EXCEEDED"
    );

    let (mut config, lock, plan, mut request) = fixture();
    config.limits.max_path_bytes = 10;
    request.expected_configuration_sha256 = configuration_sha256(&config).expect("new digest");
    sign_request(&mut request);
    assert_eq!(
        admit(&config, &request, &plan, &lock, NOW)
            .expect_err("logical lock path bound")
            .code,
        "DEP_REQUEST_LOCK_PATH_INVALID"
    );

    let (mut config, lock, plan, mut request) = fixture();
    config.limits.max_path_bytes = 10;
    request.logical_lock_path = "lock.json".to_owned();
    request.expected_configuration_sha256 = configuration_sha256(&config).expect("new digest");
    sign_request(&mut request);
    assert_eq!(
        admit(&config, &request, &plan, &lock, NOW)
            .expect_err("artifact path bound")
            .code,
        "DEP_REQUEST_RESOURCE_LIMIT_EXCEEDED"
    );
}
