#[path = "../../test-support/diff003.rs"]
mod diff003;

use std::cell::RefCell;
use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use mcloving_secret_broker::{
    BrokerError, ConsumerBinding, ConsumerGrantBinding, CredentialMapping, GRANT_PROTOCOL_VERSION,
    GrantRequest, InventoryCredential, MappingDisposition, ProviderRequest, ProviderSecret,
    RedemptionRequest, SCHEMA_VERSION, SecretBroker, SecretMaterial, SecretProvider, TaintClass,
    WorkloadChannel, reconcile_inventory,
};
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;
use uuid::Uuid;

const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER_DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SECRET: &[u8] = b"unique-secret-marker-do-not-disclose";
const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const OWNER_SEED: [u8; 32] = [7; 32];

fn owner_key_pair() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&OWNER_SEED).expect("fixed owner key")
}

fn owner_public_key() -> Vec<u8> {
    owner_key_pair().public_key().as_ref().to_vec()
}

fn trusted_owner_keys() -> BTreeMap<String, Vec<u8>> {
    BTreeMap::from([("owner-key:release:v1".to_owned(), owner_public_key())])
}

fn approve(mapping: &mut CredentialMapping) {
    let key = owner_key_pair();
    mapping.owner_approval_public_key_sha256 = format!("{:x}", Sha256::digest(key.public_key()));
    mapping.owner_approval_sha256 = ZERO_DIGEST.to_owned();
    mapping.owner_approval_signature.clear();
    let payload = mapping
        .owner_approval_payload()
        .expect("owner approval payload");
    mapping.owner_approval_sha256 = format!("{:x}", Sha256::digest(&payload));
    mapping.owner_approval_signature = STANDARD.encode(
        key.sign(
            &mapping
                .owner_approval_message()
                .expect("owner approval message"),
        )
        .as_ref(),
    );
}

fn install(broker: &mut SecretBroker, mapping: &CredentialMapping, now: i64) {
    broker
        .install_mapping(mapping, now)
        .expect("install approved mapping");
}

fn connector() -> ConsumerBinding {
    ConsumerBinding::ExternalConnector {
        connector_id: "connector/release/v1".to_owned(),
        implementation_sha256: DIGEST.to_owned(),
        configuration_sha256: OTHER_DIGEST.to_owned(),
    }
}

fn source_acquirer() -> ConsumerBinding {
    ConsumerBinding::SourceAcquirer {
        acquirer_id: "source:checkout:v1".to_owned(),
        implementation_sha256: DIGEST.to_owned(),
        configuration_sha256: OTHER_DIGEST.to_owned(),
    }
}

fn mapping(consumer: ConsumerBinding) -> CredentialMapping {
    let declared_taint = consumer.taint_class();
    let disposition = match consumer {
        ConsumerBinding::ExternalConnector { .. } | ConsumerBinding::SourceAcquirer { .. } => {
            MappingDisposition::GrantEligible
        }
        ConsumerBinding::Controller { .. } => MappingDisposition::IneligibleControllerVisible,
        ConsumerBinding::Workload { .. } => MappingDisposition::IneligibleWorkloadVisible,
    };
    let mut mapping = CredentialMapping {
        schema_version: SCHEMA_VERSION.to_owned(),
        mapping_id: Uuid::from_u128(1),
        inventory_epoch_sha256: DIGEST.to_owned(),
        inventory_job_id: "folder/job".to_owned(),
        inventory_dependency_id: "credential:deploy".to_owned(),
        jenkins_credential_reference: "jenkins-credential:deploy".to_owned(),
        organization_id: Uuid::from_u128(2),
        project_id: Uuid::from_u128(3),
        environment: "production".to_owned(),
        action: "deploy".to_owned(),
        owner_identity: "owner:release".to_owned(),
        owner_approval_signer_key_id: "owner-key:release:v1".to_owned(),
        owner_approval_public_key_sha256: ZERO_DIGEST.to_owned(),
        owner_approved_at_unix_ms: 500,
        owner_approval_expires_unix_ms: 30_000,
        owner_approval_sha256: ZERO_DIGEST.to_owned(),
        owner_approval_signature: "pending".to_owned(),
        provider_identity: "provider:vault:production".to_owned(),
        provider_version: "vault-api/v1".to_owned(),
        provider_implementation_sha256: OTHER_DIGEST.to_owned(),
        provider_configuration_sha256: DIGEST.to_owned(),
        provider_reference: "secret/data/release/deploy".to_owned(),
        secret_version: "version-7".to_owned(),
        rotation_generation: 1,
        declared_taint,
        taint_path: vec!["connector".to_owned(), "authorization-header".to_owned()],
        classification_evidence_sha256: OTHER_DIGEST.to_owned(),
        consumer,
        disposition,
    };
    approve(&mut mapping);
    mapping
}

fn inventory(mapping: &CredentialMapping) -> InventoryCredential {
    InventoryCredential {
        inventory_epoch_sha256: mapping.inventory_epoch_sha256.clone(),
        job_id: mapping.inventory_job_id.clone(),
        dependency_id: mapping.inventory_dependency_id.clone(),
        jenkins_credential_reference: mapping.jenkins_credential_reference.clone(),
        owner_identity: mapping.owner_identity.clone(),
        declared_taint: mapping.declared_taint,
        taint_path: mapping.taint_path.clone(),
        classification_evidence_sha256: mapping.classification_evidence_sha256.clone(),
        consumer: mapping.consumer.clone(),
    }
}

fn grant(mapping: &CredentialMapping) -> GrantRequest {
    GrantRequest {
        protocol_version: GRANT_PROTOCOL_VERSION.to_owned(),
        grant_id: Uuid::from_u128(10),
        mapping_id: mapping.mapping_id,
        expected_rotation_generation: mapping.rotation_generation,
        expected_provider_version: mapping.provider_version.clone(),
        organization_id: mapping.organization_id,
        project_id: mapping.project_id,
        build_id: Uuid::from_u128(4),
        attempt_id: Uuid::from_u128(5),
        environment: mapping.environment.clone(),
        action: mapping.action.clone(),
        fence: 9,
        consumer: mapping.consumer.clone(),
        requested_at_unix_ms: 1_000,
        expires_at_unix_ms: 20_000,
        audit_provenance: "audit:build:4:attempt:5".to_owned(),
    }
}

fn redemption(request: &GrantRequest) -> RedemptionRequest {
    RedemptionRequest {
        grant_id: request.grant_id,
        organization_id: request.organization_id,
        project_id: request.project_id,
        build_id: request.build_id,
        attempt_id: request.attempt_id,
        fence: request.fence,
        consumer: request.consumer.clone(),
    }
}

type RedemptionMutation = Box<dyn Fn(&mut RedemptionRequest)>;

fn broker() -> (TempDir, SecretBroker) {
    let root = TempDir::new().expect("temporary broker root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private temp root");
    }
    let broker = SecretBroker::open(
        &root.path().join("broker.sqlite"),
        trusted_owner_keys(),
        denied_public_markers(),
    )
    .expect("open broker");
    (root, broker)
}

fn denied_public_markers() -> Vec<Vec<u8>> {
    vec![SECRET.to_vec()]
}

struct ExactProvider {
    expected: ProviderRequest,
    calls: RefCell<usize>,
    returned_version: String,
}

impl ExactProvider {
    fn new(expected: ProviderRequest) -> Self {
        Self {
            returned_version: expected.secret_version.clone(),
            expected,
            calls: RefCell::new(0),
        }
    }
}

impl SecretProvider for ExactProvider {
    fn resolve(&self, request: &ProviderRequest) -> Result<ProviderSecret, BrokerError> {
        assert_eq!(request, &self.expected);
        *self.calls.borrow_mut() += 1;
        Ok(ProviderSecret {
            secret_version: self.returned_version.clone(),
            material: SecretMaterial::new(SECRET.to_vec())?,
        })
    }
}

fn provider_request(mapping: &CredentialMapping, request: &GrantRequest) -> ProviderRequest {
    ProviderRequest {
        provider_identity: mapping.provider_identity.clone(),
        provider_version: mapping.provider_version.clone(),
        provider_implementation_sha256: mapping.provider_implementation_sha256.clone(),
        provider_configuration_sha256: mapping.provider_configuration_sha256.clone(),
        provider_reference: mapping.provider_reference.clone(),
        secret_version: mapping.secret_version.clone(),
        organization_id: request.organization_id,
        project_id: request.project_id,
        build_id: request.build_id,
        attempt_id: request.attempt_id,
        environment: request.environment.clone(),
        action: request.action.clone(),
        fence: request.fence,
        consumer: request.consumer.clone(),
        expires_at_unix_ms: request.expires_at_unix_ms,
    }
}

#[test]
fn inventory_reconciliation_requires_exact_complete_owner_and_taint_truth() {
    let mapping = mapping(connector());
    let inventory = inventory(&mapping);
    reconcile_inventory(
        std::slice::from_ref(&inventory),
        std::slice::from_ref(&mapping),
    )
    .expect("exact inventory reconciles");

    let mut missing = mapping.clone();
    missing.inventory_dependency_id = "credential:other".to_owned();
    assert!(matches!(
        reconcile_inventory(&[inventory], &[missing]),
        Err(BrokerError::InventoryMismatch)
    ));
}

#[test]
fn workload_and_controller_visible_mappings_never_become_grant_eligible() {
    let workload = ConsumerBinding::Workload {
        channel: WorkloadChannel::EnvironmentVariable,
        target: "DEPLOY_TOKEN".to_owned(),
    };
    let mut workload_mapping = mapping(workload);
    workload_mapping.disposition = MappingDisposition::GrantEligible;
    let (_root, mut broker) = broker();
    let workload_result = broker.install_mapping(&workload_mapping, 1_000);
    let workload_denied = matches!(workload_result, Err(BrokerError::InvalidMapping));
    assert!(workload_denied);

    let mut mismatched = mapping(connector());
    mismatched.declared_taint = TaintClass::SourceAcquisitionOnly;
    assert!(matches!(
        broker.install_mapping(&mismatched, 1_000),
        Err(BrokerError::InvalidMapping)
    ));
    diff003::record_assertion(
        "secret_taint_ineligible_denied",
        "denied",
        serde_json::json!({
            "consumer_channel": "environment_variable",
            "requested_disposition": "grant_eligible",
            "result": "invalid_mapping",
        }),
        workload_denied,
    );
}

#[test]
fn owner_signature_key_payload_and_expiry_are_verified_before_mapping_install() {
    let (_root, mut broker) = broker();
    let mut untrusted_signer = mapping(connector());
    untrusted_signer.owner_approval_signer_key_id = "owner-key:untrusted:v1".to_owned();
    approve(&mut untrusted_signer);
    assert!(matches!(
        broker.install_mapping(&untrusted_signer, 1_000),
        Err(BrokerError::OwnerApprovalDenied)
    ));

    let mut substituted = mapping(connector());
    substituted.provider_reference = "secret/data/attacker/substitution".to_owned();
    assert!(matches!(
        broker.install_mapping(&substituted, 1_000),
        Err(BrokerError::OwnerApprovalDenied)
    ));

    let approved = mapping(connector());
    let wrong_key = Ed25519KeyPair::from_seed_unchecked(&[8; 32]).expect("wrong key");
    assert!(matches!(
        SecretBroker::open(
            &_root.path().join("wrong-key.sqlite"),
            BTreeMap::from([(
                "owner-key:release:v1".to_owned(),
                wrong_key.public_key().as_ref().to_vec(),
            )]),
            denied_public_markers(),
        )
        .expect("open wrong-key broker")
        .install_mapping(&approved, 1_000),
        Err(BrokerError::OwnerApprovalDenied)
    ));
    assert!(matches!(
        broker.install_mapping(&approved, approved.owner_approval_expires_unix_ms),
        Err(BrokerError::OwnerApprovalDenied)
    ));
}

#[test]
fn broker_requires_a_nonempty_unambiguous_trusted_owner_key_registry() {
    let root = TempDir::new().expect("temporary broker root");
    assert!(matches!(
        SecretBroker::open(
            &root.path().join("empty.sqlite"),
            BTreeMap::new(),
            denied_public_markers(),
        ),
        Err(BrokerError::OwnerApprovalDenied)
    ));

    let key = owner_public_key();
    let duplicate_keys = BTreeMap::from([
        ("owner-key:release:v1".to_owned(), key.clone()),
        ("owner-key:alias:v1".to_owned(), key),
    ]);
    assert!(matches!(
        SecretBroker::open(
            &root.path().join("ambiguous.sqlite"),
            duplicate_keys,
            denied_public_markers(),
        ),
        Err(BrokerError::OwnerApprovalDenied)
    ));
}

#[test]
fn broker_requires_a_nonempty_unambiguous_public_marker_registry() {
    let root = TempDir::new().expect("temporary broker root");
    assert!(matches!(
        SecretBroker::open(
            &root.path().join("empty-markers.sqlite"),
            trusted_owner_keys(),
            Vec::new(),
        ),
        Err(BrokerError::InvalidMapping)
    ));
    assert!(matches!(
        SecretBroker::open(
            &root.path().join("duplicate-markers.sqlite"),
            trusted_owner_keys(),
            vec![SECRET.to_vec(), SECRET.to_vec()],
        ),
        Err(BrokerError::InvalidMapping)
    ));
}

#[test]
fn broker_rejects_legacy_mappings_that_conflict_with_the_active_marker_registry() {
    let root = TempDir::new().expect("temporary broker root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private temp root");
    }
    let path = root.path().join("legacy.sqlite");
    let mut mapping = mapping(connector());
    let raw = String::from_utf8(SECRET.to_vec()).expect("ASCII marker");
    mapping.provider_reference = format!("secret/{raw}");
    approve(&mut mapping);
    let mut legacy = SecretBroker::open(
        &path,
        trusted_owner_keys(),
        vec![b"different-owner-private-marker-0001".to_vec()],
    )
    .expect("open legacy broker");
    legacy
        .install_mapping(&mapping, 900)
        .expect("install previously admitted mapping");
    drop(legacy);

    assert!(matches!(
        SecretBroker::open(&path, trusted_owner_keys(), denied_public_markers()),
        Err(BrokerError::ConfidentialityDenied)
    ));
}

#[test]
fn exact_connector_grant_redeems_once_without_disclosing_secret_in_receipts_or_audit() {
    let mapping = mapping(connector());
    let request = grant(&mapping);
    let (_root, mut broker) = broker();
    install(&mut broker, &mapping, 900);
    let grant_receipt = broker.issue_grant(&request, 1_000).expect("issue grant");
    match grant_receipt.consumer_binding().expect("connector binding") {
        ConsumerGrantBinding::ExternalConnector {
            grant_version,
            connector_id,
            implementation_sha256,
            configuration_sha256,
            grant_scope,
            ..
        } => {
            assert_eq!(grant_version, GRANT_PROTOCOL_VERSION);
            assert_eq!(connector_id, "connector/release/v1");
            assert_eq!(implementation_sha256, DIGEST);
            assert_eq!(configuration_sha256, OTHER_DIGEST);
            assert!(grant_scope.contains(&request.attempt_id.to_string()));
            assert!(grant_scope.ends_with("/fence/9"));
        }
        ConsumerGrantBinding::SourceAcquirer { .. } => panic!("wrong consumer binding"),
    }

    let provider = ExactProvider::new(provider_request(&mapping, &request));
    let redemption_request = redemption(&request);
    let redeemed = broker
        .redeem_grant(&redemption_request, &provider, 2_000)
        .expect("redeem grant");
    assert_eq!(redeemed.material.expose_secret(), SECRET);
    assert_eq!(*provider.calls.borrow(), 1);
    assert!(matches!(
        broker.redeem_grant(&redemption_request, &provider, 2_000),
        Err(BrokerError::GrantDenied)
    ));
    assert_eq!(*provider.calls.borrow(), 1);

    let mut public = serde_json::to_vec(&grant_receipt).expect("grant receipt JSON");
    public.extend(serde_json::to_vec(&redeemed.receipt).expect("redemption receipt JSON"));
    for event in broker.audit_events_json().expect("audit events") {
        public.extend(event);
    }
    assert!(!public.windows(SECRET.len()).any(|window| window == SECRET));
    assert!(
        !String::from_utf8(public)
            .expect("public evidence is UTF-8")
            .contains("unique-secret-marker")
    );
    if let Ok(root) = std::env::var("MCLOVING_DIFF003_RUNTIME_OUTPUT_DIR") {
        std::fs::write(
            std::path::Path::new(&root).join("SECRET-001.json"),
            diff003::receipt(
                "SECRET-001",
                serde_json::json!({
                    "grant": grant_receipt,
                    "redemption": redeemed.receipt,
                    "provider_calls": *provider.calls.borrow(),
                }),
            ),
        )
        .expect("write DIFF-003 secret receipts");
    }
}

#[test]
fn source_acquirer_binding_uses_the_same_public_grant_protocol_without_provider_reference() {
    let mapping = mapping(source_acquirer());
    let request = grant(&mapping);
    let (_root, mut broker) = broker();
    install(&mut broker, &mapping, 900);
    let receipt = broker.issue_grant(&request, 1_000).expect("source grant");
    let binding = receipt.consumer_binding().expect("source binding");
    match &binding {
        ConsumerGrantBinding::SourceAcquirer {
            grant_version,
            acquirer_id,
            implementation_sha256,
            configuration_sha256,
            ..
        } => {
            assert_eq!(grant_version, GRANT_PROTOCOL_VERSION);
            assert_eq!(acquirer_id, "source:checkout:v1");
            assert_eq!(implementation_sha256, DIGEST);
            assert_eq!(configuration_sha256, OTHER_DIGEST);
        }
        ConsumerGrantBinding::ExternalConnector { .. } => panic!("wrong consumer binding"),
    }
    let public = serde_json::to_string(&binding).expect("binding JSON");
    assert!(!public.contains(&mapping.provider_reference));
    assert!(!public.contains("provider_identity"));
}

#[test]
fn cross_tenant_attempt_fence_consumer_expiry_and_replay_are_denied_before_provider_use() {
    let mapping = mapping(source_acquirer());
    let request = grant(&mapping);
    let (_root, mut broker) = broker();
    install(&mut broker, &mapping, 900);
    broker.issue_grant(&request, 1_000).expect("grant");
    let provider = ExactProvider::new(provider_request(&mapping, &request));

    let mutations: Vec<RedemptionMutation> = vec![
        Box::new(|value| value.organization_id = Uuid::from_u128(99)),
        Box::new(|value| value.project_id = Uuid::from_u128(99)),
        Box::new(|value| value.build_id = Uuid::from_u128(99)),
        Box::new(|value| value.attempt_id = Uuid::from_u128(99)),
        Box::new(|value| value.fence += 1),
        Box::new(|value| value.consumer = connector()),
    ];
    let mutation_count = mutations.len();
    let mut denied_mutations = 0;
    for mutate in mutations {
        let mut denied = redemption(&request);
        mutate(&mut denied);
        let denied_result = broker.redeem_grant(&denied, &provider, 2_000);
        let denied = matches!(denied_result, Err(BrokerError::GrantDenied));
        assert!(denied);
        denied_mutations += usize::from(denied);
    }
    assert!(matches!(
        broker.redeem_grant(&redemption(&request), &provider, 20_000),
        Err(BrokerError::GrantDenied)
    ));
    assert_eq!(*provider.calls.borrow(), 0);
    let consumer_substitution_denied =
        denied_mutations == mutation_count && *provider.calls.borrow() == 0;
    diff003::record_assertion(
        "secret_consumer_substitution_denied",
        "denied",
        serde_json::json!({
            "mutations_attempted": mutation_count,
            "mutations_denied": denied_mutations,
            "provider_calls": *provider.calls.borrow(),
        }),
        consumer_substitution_denied,
    );
}

#[test]
fn rotation_and_emergency_revocation_fence_every_old_grant() {
    let first = mapping(connector());
    let first_grant = grant(&first);
    let (_root, mut broker) = broker();
    install(&mut broker, &first, 900);
    broker
        .issue_grant(&first_grant, 1_000)
        .expect("generation one grant");

    let mut second = first.clone();
    second.rotation_generation = 2;
    second.provider_version = "vault-api/v2".to_owned();
    second.provider_configuration_sha256 = OTHER_DIGEST.to_owned();
    second.provider_reference = "secret/data/release/deploy-v2".to_owned();
    second.secret_version = "version-8".to_owned();
    second.owner_approval_sha256 = DIGEST.to_owned();
    approve(&mut second);
    install(&mut broker, &second, 1_500);
    let old_provider = ExactProvider::new(provider_request(&first, &first_grant));
    assert!(matches!(
        broker.redeem_grant(&redemption(&first_grant), &old_provider, 2_000),
        Err(BrokerError::GrantDenied)
    ));

    let mut second_grant = grant(&second);
    second_grant.grant_id = Uuid::from_u128(11);
    second_grant.expected_provider_version = second.provider_version.clone();
    second_grant.expected_rotation_generation = 2;
    second_grant.requested_at_unix_ms = 2_000;
    second_grant.expires_at_unix_ms = 3_000;
    broker
        .issue_grant(&second_grant, 2_000)
        .expect("generation two grant");
    broker
        .revoke_mapping(second.mapping_id, 2, 1, 2_100, "emergency rotation")
        .expect("emergency revoke");
    let second_provider = ExactProvider::new(provider_request(&second, &second_grant));
    let second_redemption = redemption(&second_grant);
    assert!(matches!(
        broker.redeem_grant(&second_redemption, &second_provider, 2_200),
        Err(BrokerError::GrantDenied)
    ));
    assert_eq!(*old_provider.calls.borrow(), 0);
    assert_eq!(*second_provider.calls.borrow(), 0);
}

#[test]
fn provider_version_substitution_is_denied_without_a_redemption_receipt() {
    let mapping = mapping(connector());
    let request = grant(&mapping);
    let (_root, mut broker) = broker();
    install(&mut broker, &mapping, 900);
    broker.issue_grant(&request, 1_000).expect("grant");
    let mut provider = ExactProvider::new(provider_request(&mapping, &request));
    provider.returned_version = "substituted-version".to_owned();
    assert!(matches!(
        broker.redeem_grant(&redemption(&request), &provider, 2_000),
        Err(BrokerError::ProviderDenied)
    ));
    assert_eq!(*provider.calls.borrow(), 1);
    assert_eq!(broker.audit_events_json().expect("audit").len(), 2);
}

#[test]
fn trusted_time_and_per_fence_scope_prevent_stale_or_renamed_grants() {
    let mapping = mapping(connector());
    let request = grant(&mapping);
    let (_root, mut broker) = broker();
    install(&mut broker, &mapping, 900);
    assert!(matches!(
        broker.issue_grant(&request, request.expires_at_unix_ms),
        Err(BrokerError::InvalidGrant)
    ));

    let first = broker.issue_grant(&request, 1_100).expect("first grant");
    assert_eq!(
        broker.issue_grant(&request, 1_200).expect("exact retry"),
        first
    );
    let mut renamed = request.clone();
    renamed.grant_id = Uuid::from_u128(12);
    assert!(matches!(
        broker.issue_grant(&renamed, 1_200),
        Err(BrokerError::GrantDenied)
    ));

    let provider = ExactProvider::new(provider_request(&mapping, &request));
    broker
        .redeem_grant(&redemption(&request), &provider, 2_000)
        .expect("redeem");
    assert!(matches!(
        broker.issue_grant(&request, 2_100),
        Err(BrokerError::GrantDenied)
    ));
}

#[test]
fn raw_encoded_hex_and_percent_secret_material_are_denied_in_public_mapping_fields() {
    let lower_hex = SECRET
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let percent = SECRET
        .iter()
        .map(|byte| format!("%{byte:02X}"))
        .collect::<String>();
    let raw = String::from_utf8(SECRET.to_vec()).expect("ASCII marker");
    let base64 = STANDARD.encode(SECRET);
    let mixed_percent = raw.replacen('-', "%2D", 1);
    let nested_percent = raw.replacen('-', &format!("%{}2D", "25".repeat(7)), 1);
    let representations = [
        ("raw", raw.clone(), format!("secret/{raw}")),
        ("base64", base64.clone(), format!("credential:{base64}")),
        (
            "hex",
            lower_hex.clone(),
            format!("opaque-{lower_hex}-reference"),
        ),
        ("percent", percent.clone(), format!("vault/path/{percent}")),
        (
            "mixed_percent",
            mixed_percent.clone(),
            format!("secret/{mixed_percent}"),
        ),
        (
            "nested_percent",
            nested_percent.clone(),
            format!("secret/{nested_percent}"),
        ),
    ];
    let representation_count = representations.len();
    let mut pre_persistence_denials = 0;
    let mut persisted_rows = 0_i64;
    let mut persisted_marker_bytes = 0;
    for (index, (_name, representation, provider_reference)) in
        representations.into_iter().enumerate()
    {
        let mut mapping = mapping(connector());
        mapping.mapping_id = Uuid::from_u128(100 + index as u128);
        mapping.provider_reference = provider_reference;
        approve(&mut mapping);
        let (root, mut broker) = broker();
        let install_result = broker.install_mapping(&mapping, 900);
        let denied_before_persistence =
            matches!(install_result, Err(BrokerError::ConfidentialityDenied));
        assert!(denied_before_persistence);
        pre_persistence_denials += usize::from(denied_before_persistence);

        let connection = rusqlite::Connection::open(root.path().join("broker.sqlite"))
            .expect("inspect broker state");
        for table in [
            "mapping_versions",
            "mapping_heads",
            "grants",
            "audit_events",
        ] {
            let count: i64 = connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .expect("count persisted rows");
            persisted_rows += count;
            assert_eq!(count, 0, "{table} persisted a rejected marker mapping");
        }
        drop(connection);
        drop(broker);
        let database = std::fs::read(root.path().join("broker.sqlite")).expect("read broker state");
        let marker_persisted = database
            .windows(representation.len())
            .any(|window| window == representation.as_bytes());
        persisted_marker_bytes += usize::from(marker_persisted);
        assert!(!marker_persisted);
    }
    diff003::record_assertion(
        "secret_marker_disclosure_denied",
        "denied",
        serde_json::json!({
            "representations_attempted": representation_count,
            "pre_persistence_denials": pre_persistence_denials,
            "persisted_rows": persisted_rows,
            "persisted_marker_representations": persisted_marker_bytes,
            "representations": [
                "raw", "base64", "hex", "percent", "mixed_percent", "nested_percent"
            ],
        }),
        pre_persistence_denials == representation_count
            && persisted_rows == 0
            && persisted_marker_bytes == 0,
    );
}

#[test]
fn over_depth_percent_encoding_fails_closed_before_mapping_persistence() {
    let over_depth = format!("opaque-%{}41-reference", "25".repeat(8));
    let mut mapping = mapping(connector());
    mapping.provider_reference = over_depth;
    approve(&mut mapping);
    let (root, mut broker) = broker();
    assert!(matches!(
        broker.install_mapping(&mapping, 900),
        Err(BrokerError::ConfidentialityDenied)
    ));
    let connection = rusqlite::Connection::open(root.path().join("broker.sqlite"))
        .expect("inspect broker state");
    let rows: i64 = connection
        .query_row("SELECT COUNT(*) FROM mapping_versions", [], |row| {
            row.get(0)
        })
        .expect("count persisted mappings");
    assert_eq!(rows, 0);
}

#[test]
fn opaque_and_uri_provider_references_remain_provider_neutral() {
    for (index, provider_reference) in [
        "opaque-credential-id",
        "https://vault.example/v1/secrets/release?id=deploy",
    ]
    .into_iter()
    .enumerate()
    {
        let mut mapping = mapping(connector());
        mapping.mapping_id = Uuid::from_u128(200 + index as u128);
        mapping.provider_reference = provider_reference.to_owned();
        approve(&mut mapping);
        let (_root, mut broker) = broker();
        broker
            .install_mapping(&mapping, 900)
            .expect("provider-neutral reference");
    }
}

#[test]
fn audit_chain_detects_persisted_event_tampering() {
    let root = TempDir::new().expect("temporary broker root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private temp root");
    }
    let path = root.path().join("broker.sqlite");
    let mut broker = SecretBroker::open(&path, trusted_owner_keys(), denied_public_markers())
        .expect("open broker");
    let mapping = mapping(connector());
    install(&mut broker, &mapping, 900);
    assert_eq!(broker.verify_audit_chain().expect("valid chain"), 1);

    let attacker = rusqlite::Connection::open(path).expect("open second connection");
    attacker
        .execute(
            "UPDATE audit_events SET canonical_payload = ?1 WHERE sequence = 1",
            [b"{}".as_slice()],
        )
        .expect("tamper audit payload");
    assert!(matches!(
        broker.verify_audit_chain(),
        Err(BrokerError::AuditInvalid)
    ));
}

#[cfg(unix)]
#[test]
fn broker_state_rejects_public_parent_symlink_and_hardlink_paths() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let public_root = TempDir::new().expect("public root");
    assert!(matches!(
        SecretBroker::open(
            &public_root.path().join("broker.sqlite"),
            trusted_owner_keys(),
            denied_public_markers(),
        ),
        Err(BrokerError::InvalidStatePath)
    ));

    let private_root = TempDir::new().expect("private root");
    std::fs::set_permissions(private_root.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private permissions");
    let target = private_root.path().join("target.sqlite");
    std::fs::write(&target, []).expect("target file");
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
        .expect("target permissions");
    let symlink_path = private_root.path().join("symlink.sqlite");
    symlink(&target, &symlink_path).expect("state symlink");
    assert!(matches!(
        SecretBroker::open(&symlink_path, trusted_owner_keys(), denied_public_markers(),),
        Err(BrokerError::InvalidStatePath)
    ));

    let hardlink_path = private_root.path().join("hardlink.sqlite");
    std::fs::hard_link(&target, &hardlink_path).expect("state hardlink");
    assert!(matches!(
        SecretBroker::open(
            &hardlink_path,
            trusted_owner_keys(),
            denied_public_markers(),
        ),
        Err(BrokerError::InvalidStatePath)
    ));

    let sidecar_database = private_root.path().join("sidecar.sqlite");
    let sidecar_symlink = private_root.path().join("sidecar.sqlite-wal");
    symlink(&target, &sidecar_symlink).expect("state sidecar symlink");
    assert!(matches!(
        SecretBroker::open(
            &sidecar_database,
            trusted_owner_keys(),
            denied_public_markers(),
        ),
        Err(BrokerError::InvalidStatePath)
    ));
}
