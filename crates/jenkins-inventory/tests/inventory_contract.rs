use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use mcloving_jenkins_inventory::{
    AclEntry, ApprovedDisposition, ClientCaller, ClientDirection, ClientRecord,
    CompatibilityDisposition, CountEvidence, DependencyMutability, HistoricalNameClaim,
    IDENTITY_CLIENT_FILE, IdentityClientManifest, JOB_GRAPH_FILE, JobDependencies,
    JobGraphManifest, JobRecord, JobRequirement, JobStateRecords, LegalHold, OperationalState,
    PERSISTENT_STATE_FILE, PersistentStateManifest, Principal, PrincipalKind, PrincipalLifecycle,
    RUNTIME_DEPENDENCY_FILE, RuntimeDependency, RuntimeDependencyKind, RuntimeDependencyManifest,
    SCHEMA_VERSION, ScopeDisposition, SecretConsumer, SecretConsumerEvidence, SecretTaint,
    SecurityRealm, SetEvidence, SnapshotBinding, StateRecord, StateTransformEvidence,
    WorkloadSecretChannel, load_bundle, reconcile as reconcile_for_snapshot,
    seal_manifest_directory, snapshot_binding_sha256, validate_ledger_output_path, write_ledger,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DIGEST_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn reconcile(
    bundle: &mcloving_jenkins_inventory::InventoryBundle,
) -> Result<mcloving_jenkins_inventory::EligibilityLedger, mcloving_jenkins_inventory::InventoryError>
{
    let expected = snapshot_binding_sha256(&bundle.job_graph.binding);
    reconcile_for_snapshot(bundle, &expected)
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(name: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "mcloving-inventory-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create test directory");
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn sealed_inventory_reconciles_to_a_conservative_ledger() {
    let directory = TestDirectory::new("valid");
    write_bundle(&directory.0, &fixture());
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let bundle = load_bundle(&directory.0).expect("load sealed inventory");
    let ledger = reconcile(&bundle).expect("reconcile inventory");

    assert_eq!(ledger.population.controllers, 1);
    assert_eq!(ledger.population.jobs_total, 3);
    assert_eq!(ledger.population.jobs_in_scope, 2);
    assert_eq!(ledger.population.principals, 3);
    assert_eq!(ledger.population.read_clients, 1);
    assert_eq!(ledger.population.write_clients, 1);
    assert_eq!(ledger.jobs[0].job_id, "folder");
    assert_eq!(
        ledger.jobs[1].disposition,
        CompatibilityDisposition::Mappable
    );
    assert_eq!(ledger.jobs[0].disposition, CompatibilityDisposition::Native);
    assert_eq!(ledger.state_transform_records, 8);

    let output = directory.0.join("ledger.yaml");
    write_ledger(&output, &ledger).expect("write ledger");
    let bytes = fs::read(&output).expect("read ledger");
    assert!(!bytes.is_empty());
    let error = write_ledger(&output, &ledger).expect_err("ledger is immutable");
    assert_eq!(error.code, "INV_IMMUTABLE");
    let error = seal_manifest_directory(&directory.0).expect_err("seal is immutable");
    assert_eq!(error.code, "INV_IMMUTABLE");
}

#[test]
fn seal_rejects_unexpected_root_entries() {
    let directory = TestDirectory::new("unexpected-entry");
    write_bundle(&directory.0, &fixture());
    fs::write(
        directory.0.join("eligibility-ledger.yaml"),
        "unverified: secret-bearing-stale-output\n",
    )
    .expect("write unexpected entry");

    let error = seal_manifest_directory(&directory.0).expect_err("extra entry must fail");
    assert_eq!(error.code, "INV_UNEXPECTED_ENTRY");
    assert!(!directory.0.join("SHA256SUMS").exists());
}

#[test]
fn verification_rejects_entries_injected_after_sealing() {
    let directory = TestDirectory::new("post-seal-injection");
    write_bundle(&directory.0, &fixture());
    seal_manifest_directory(&directory.0).expect("seal inventory");
    fs::write(
        directory.0.join("unsealed-export.txt"),
        "secret-bearing stale export\n",
    )
    .expect("inject unsealed entry");

    let error = load_bundle(&directory.0).expect_err("post-seal injection must fail");
    assert_eq!(error.code, "INV_UNEXPECTED_ENTRY");
}

#[test]
fn verification_accepts_only_the_exact_published_ledger() {
    let directory = TestDirectory::new("published-ledger");
    write_bundle(&directory.0, &fixture());
    seal_manifest_directory(&directory.0).expect("seal inventory");
    let bundle = load_bundle(&directory.0).expect("load sealed inventory");
    let ledger = reconcile(&bundle).expect("reconcile inventory");
    let output = directory.0.join("eligibility-ledger.yaml");
    write_ledger(&output, &ledger).expect("publish ledger");

    let reloaded = load_bundle(&directory.0).expect("load inventory with ledger");
    reconcile(&reloaded).expect("exact published ledger must verify");
    fs::write(&output, "schema: stale\n").expect("replace published ledger");
    let reloaded = load_bundle(&directory.0).expect("load inventory with stale ledger");
    let error = reconcile(&reloaded).expect_err("stale published ledger must fail");
    assert_eq!(error.code, "INV_LEDGER_MISMATCH");
}

#[test]
fn ledger_output_layout_is_canonical_and_fail_closed() {
    let directory = TestDirectory::new("ledger-output-layout");
    let standard = directory.0.join("eligibility-ledger.yaml");
    validate_ledger_output_path(&directory.0, &standard).expect("standard ledger is allowed");

    let custom = directory.0.join("custom-ledger.yaml");
    let error =
        validate_ledger_output_path(&directory.0, &custom).expect_err("custom root output fails");
    assert_eq!(error.code, "INV_OUTPUT_LAYOUT");

    let nested = directory.0.join("nested");
    fs::create_dir(&nested).expect("create nested directory");
    let error = validate_ledger_output_path(&directory.0, &nested.join("eligibility-ledger.yaml"))
        .expect_err("nested root output fails");
    assert_eq!(error.code, "INV_OUTPUT_LAYOUT");

    let external = directory.0.with_extension("ledger.yaml");
    validate_ledger_output_path(&directory.0, &external).expect("external output is allowed");
}

#[test]
fn verification_path_is_read_only() {
    let directory = TestDirectory::new("verify");
    write_bundle(&directory.0, &fixture());
    seal_manifest_directory(&directory.0).expect("seal inventory");
    let checksum_before =
        fs::read(directory.0.join("SHA256SUMS")).expect("read checksum before verify");

    let bundle = load_bundle(&directory.0).expect("verify bundle");
    let ledger = reconcile(&bundle).expect("verify reconciliation");
    assert_eq!(ledger.population.jobs_in_scope, 2);
    assert!(!directory.0.join("eligibility-ledger.yaml").exists());
    assert_eq!(
        fs::read(directory.0.join("SHA256SUMS")).expect("read checksum after verify"),
        checksum_before
    );
}

#[test]
fn detached_manifest_digest_rejects_tampering() {
    let directory = TestDirectory::new("tamper");
    write_bundle(&directory.0, &fixture());
    seal_manifest_directory(&directory.0).expect("seal inventory");
    fs::write(directory.0.join(JOB_GRAPH_FILE), "schema: tampered\n").expect("tamper file");

    let error = load_bundle(&directory.0).expect_err("tamper must fail");
    assert_eq!(error.code, "INV_DIGEST_MISMATCH");
}

#[test]
fn reconciliation_rejects_mixed_snapshot_epochs() {
    let directory = TestDirectory::new("mixed-epoch");
    let mut bundle = fixture();
    bundle.identity_clients.binding.epoch_id = "epoch-2".to_owned();
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("mixed epoch must fail");
    assert_eq!(error.code, "INV_MIXED_EPOCH");
}

#[test]
fn reconciliation_rejects_unclassified_runtime_dependency() {
    let directory = TestDirectory::new("unclassified");
    let mut bundle = fixture();
    bundle.runtime_dependencies.jobs[1].dependencies[0].disposition =
        CompatibilityDisposition::Unclassified;
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("unclassified dependency must fail");
    assert_eq!(error.code, "INV_UNCLASSIFIED");
}

#[test]
fn reconciliation_rejects_native_mutable_dependencies() {
    let directory = TestDirectory::new("native-mutable");
    let mut bundle = fixture();
    let dependency = &mut bundle.runtime_dependencies.jobs[1].dependencies[0];
    dependency.mutability = DependencyMutability::Mutable;
    dependency.disposition = CompatibilityDisposition::Native;
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("native mutable dependency must fail");
    assert_eq!(error.code, "INV_MUTABLE_NATIVE");
}

#[test]
fn secret_dependencies_require_typed_references() {
    let directory = TestDirectory::new("secret");
    let mut bundle = fixture();
    let dependency = &mut bundle.runtime_dependencies.jobs[1].dependencies[0];
    dependency.confidentiality = "secret".to_owned();
    dependency.credential_reference = None;
    dependency.redaction_reference = None;
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("secret literal path must fail");
    assert_eq!(error.code, "INV_SECRET_REFERENCE_REQUIRED");
}

#[test]
fn secret_dependencies_require_consumer_and_taint_evidence() {
    let directory = TestDirectory::new("secret-consumer");
    let mut bundle = fixture();
    bundle.runtime_dependencies.jobs[1].dependencies[0].secret_consumer = None;
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("unclassified secret consumer must fail");
    assert_eq!(error.code, "INV_SECRET_CONSUMER_REQUIRED");
}

#[test]
fn credential_references_cannot_downgrade_confidentiality() {
    let directory = TestDirectory::new("credential-confidentiality");
    let mut bundle = fixture();
    bundle.runtime_dependencies.jobs[1].dependencies[0].confidentiality = "confidential".to_owned();
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("credential-label downgrade must fail");
    assert_eq!(error.code, "INV_CREDENTIAL_CONFIDENTIALITY");
}

#[test]
fn secret_consumer_evidence_cannot_downgrade_confidentiality() {
    let directory = TestDirectory::new("consumer-confidentiality");
    let mut bundle = fixture();
    let dependency = &mut bundle.runtime_dependencies.jobs[1].dependencies[0];
    dependency.confidentiality = "public".to_owned();
    dependency.credential_reference = None;
    dependency.redaction_reference = None;
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("secret-consumer label downgrade must fail");
    assert_eq!(error.code, "INV_CREDENTIAL_CONFIDENTIALITY");
}

#[test]
fn secret_consumer_taint_must_match_and_have_a_path() {
    let directory = TestDirectory::new("secret-taint-mismatch");
    let mut bundle = fixture();
    bundle.runtime_dependencies.jobs[1].dependencies[0]
        .secret_consumer
        .as_mut()
        .expect("fixture secret consumer")
        .taint = SecretTaint::WorkloadVisible;
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");
    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("inconsistent secret taint must fail");
    assert_eq!(error.code, "INV_SECRET_TAINT_MISMATCH");

    let directory = TestDirectory::new("secret-taint-path");
    let mut bundle = fixture();
    bundle.runtime_dependencies.jobs[1].dependencies[0]
        .secret_consumer
        .as_mut()
        .expect("fixture secret consumer")
        .taint_path
        .clear();
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");
    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("empty secret taint path must fail");
    assert_eq!(error.code, "INV_REQUIRED");
}

#[test]
fn workload_visible_secrets_are_never_native_eligible() {
    let directory = TestDirectory::new("workload-visible-secret");
    let mut bundle = fixture();
    let dependency = &mut bundle.runtime_dependencies.jobs[1].dependencies[0];
    dependency.secret_consumer = Some(SecretConsumerEvidence {
        consumer: SecretConsumer::Workload {
            channel: WorkloadSecretChannel::EnvironmentVariable,
            target: "DEPLOY_TOKEN".to_owned(),
        },
        taint: SecretTaint::WorkloadVisible,
        taint_path: vec![
            "credential/deploy-token".to_owned(),
            "workload/environment/DEPLOY_TOKEN".to_owned(),
        ],
        provenance: "jenkins/job/folder/build/workload-secret".to_owned(),
        evidence_sha256: DIGEST_C.to_owned(),
    });
    dependency.disposition = CompatibilityDisposition::Native;
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("workload-visible secret must be unsupported");
    assert_eq!(error.code, "INV_WORKLOAD_SECRET_DISPOSITION");

    let directory = TestDirectory::new("workload-visible-secret-unsupported");
    let mut bundle = fixture();
    let dependency = &mut bundle.runtime_dependencies.jobs[1].dependencies[0];
    dependency.secret_consumer = Some(SecretConsumerEvidence {
        consumer: SecretConsumer::Workload {
            channel: WorkloadSecretChannel::EnvironmentVariable,
            target: "DEPLOY_TOKEN".to_owned(),
        },
        taint: SecretTaint::WorkloadVisible,
        taint_path: vec![
            "credential/deploy-token".to_owned(),
            "workload/environment/DEPLOY_TOKEN".to_owned(),
        ],
        provenance: "jenkins/job/folder/build/workload-secret".to_owned(),
        evidence_sha256: DIGEST_C.to_owned(),
    });
    dependency.disposition = CompatibilityDisposition::Unsupported;
    refresh_dependency_set(&mut bundle.runtime_dependencies.jobs[1]);
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let ledger = reconcile(&loaded).expect("unsupported workload secret is explicit");
    assert_eq!(
        ledger.jobs[1].disposition,
        CompatibilityDisposition::Unsupported
    );
}

#[test]
fn every_declared_job_requirement_needs_typed_compatibility_evidence() {
    let directory = TestDirectory::new("missing-requirement");
    let mut bundle = fixture();
    bundle.runtime_dependencies.jobs[1].dependencies[0]
        .requirements
        .retain(|requirement| !matches!(requirement, JobRequirement::Trigger { .. }));
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("unclassified trigger must fail");
    assert_eq!(error.code, "INV_REQUIREMENT_COVERAGE");
}

#[test]
fn requirement_evidence_must_be_declared_and_unique() {
    let directory = TestDirectory::new("undeclared-requirement");
    let mut bundle = fixture();
    bundle.runtime_dependencies.jobs[1].dependencies[0]
        .requirements
        .push(JobRequirement::SharedLibrary {
            reference: "unlisted-library".to_owned(),
        });
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("undeclared requirement evidence must fail");
    assert_eq!(error.code, "INV_UNDECLARED_REQUIREMENT");

    let directory = TestDirectory::new("duplicate-requirement");
    let mut bundle = fixture();
    let duplicate = bundle.runtime_dependencies.jobs[1].dependencies[0].requirements[0].clone();
    bundle.runtime_dependencies.jobs[1].dependencies[0]
        .requirements
        .push(duplicate);
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("duplicate requirement evidence must fail");
    assert_eq!(error.code, "INV_DUPLICATE_REQUIREMENT_EVIDENCE");
}

#[test]
fn duplicate_job_requirement_declarations_are_rejected() {
    let directory = TestDirectory::new("duplicate-requirement-declaration");
    let mut bundle = fixture();
    bundle.job_graph.jobs[1].triggers.push("manual".to_owned());
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("duplicate job requirement must fail");
    assert_eq!(error.code, "INV_DUPLICATE_REQUIREMENT_DECLARATION");
}

#[test]
fn strict_yaml_rejects_aliases_before_deserialization() {
    let directory = TestDirectory::new("strict-yaml");
    write_bundle(&directory.0, &fixture());
    fs::write(
        directory.0.join(JOB_GRAPH_FILE),
        "binding: &binding\n  schema: value\njobs: *binding\n",
    )
    .expect("write hostile YAML");
    seal_manifest_directory(&directory.0).expect("seal hostile input");

    let error = load_bundle(&directory.0).expect_err("alias must fail");
    assert_eq!(error.code, "INV_STRICT_YAML");
}

#[test]
fn oversized_checksum_is_rejected_before_parsing() {
    let directory = TestDirectory::new("oversized-checksum");
    write_bundle(&directory.0, &fixture());
    seal_manifest_directory(&directory.0).expect("seal inventory");
    let checksum = directory.0.join("SHA256SUMS");
    fs::remove_file(&checksum).expect("remove checksum");
    let file = fs::File::create(&checksum).expect("create oversized checksum");
    file.set_len((16 * 1024 * 1024) + 1)
        .expect("size oversized checksum");

    let error = load_bundle(&directory.0).expect_err("oversized checksum must fail");
    assert_eq!(error.code, "INV_FILE_TOO_LARGE");
}

#[cfg(unix)]
#[test]
fn checksum_symlink_is_rejected() {
    use std::os::unix::fs::symlink;

    let directory = TestDirectory::new("checksum-symlink");
    write_bundle(&directory.0, &fixture());
    seal_manifest_directory(&directory.0).expect("seal inventory");
    let checksum = directory.0.join("SHA256SUMS");
    fs::remove_file(&checksum).expect("remove checksum");
    symlink(directory.0.join(JOB_GRAPH_FILE), &checksum).expect("link checksum");

    let error = load_bundle(&directory.0).expect_err("checksum symlink must fail");
    assert_eq!(error.code, "INV_FILE_TYPE");
}

#[cfg(unix)]
#[test]
fn seal_refuses_a_broken_checksum_symlink_without_creating_its_target() {
    use std::os::unix::fs::symlink;

    let directory = TestDirectory::new("seal-symlink");
    write_bundle(&directory.0, &fixture());
    let outside = directory.0.join("outside-checksum");
    symlink(&outside, directory.0.join("SHA256SUMS")).expect("link checksum");

    let error =
        seal_manifest_directory(&directory.0).expect_err("checksum symlink must be refused");
    assert_eq!(error.code, "INV_FILE_TYPE");
    assert!(!outside.exists());
}

#[test]
fn reconciliation_rejects_unknown_acl_principal() {
    let directory = TestDirectory::new("acl");
    let mut bundle = fixture();
    bundle.identity_clients.acl_entries[0].principal_id = "user/missing".to_owned();
    refresh_fixture_sets(&mut bundle);
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("unknown principal must fail");
    assert_eq!(error.code, "INV_UNKNOWN_ACL_PRINCIPAL");
}

#[test]
fn reconciliation_rejects_blank_exclusion_approval() {
    let directory = TestDirectory::new("blank-approval");
    let mut bundle = fixture();
    bundle.job_graph.jobs[2].scope.approval = Some(" \t ".to_owned());
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("blank approval must fail");
    assert_eq!(error.code, "INV_MISSING_APPROVAL");
}

#[test]
fn reconciliation_rejects_invalid_security_realm_digest() {
    let directory = TestDirectory::new("realm-digest");
    let mut bundle = fixture();
    bundle.identity_clients.security_realm.config_sha256 = "not-a-digest".to_owned();
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("invalid realm digest must fail");
    assert_eq!(error.code, "INV_DIGEST");
}

#[test]
fn reconciliation_requires_complete_security_realm_identity() {
    let directory = TestDirectory::new("realm-identity");
    let mut bundle = fixture();
    bundle
        .identity_clients
        .security_realm
        .identity_provider_generation = "  ".to_owned();
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("blank realm generation must fail");
    assert_eq!(error.code, "INV_REQUIRED");
}

#[test]
fn reconciliation_rejects_empty_in_scope_population() {
    let directory = TestDirectory::new("empty-population");
    let mut bundle = fixture();
    for job in &mut bundle.job_graph.jobs {
        job.scope = ApprovedDisposition {
            disposition: ScopeDisposition::Retired,
            approval: Some("owner-approval/retire-all".to_owned()),
        };
    }
    bundle.runtime_dependencies.jobs.clear();
    bundle.persistent_state.jobs.clear();
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("empty population must fail");
    assert_eq!(error.code, "INV_EMPTY_POPULATION");
}

#[test]
fn reconciliation_requires_operational_state_evidence() {
    let directory = TestDirectory::new("operational-state");
    let mut bundle = fixture();
    bundle.job_graph.jobs[0].operational_state.actor = "\t".to_owned();
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("blank operational actor must fail");
    assert_eq!(error.code, "INV_REQUIRED");
}

#[test]
fn reconciliation_rejects_controller_job_count_mismatch() {
    let directory = TestDirectory::new("controller-count");
    let mut bundle = fixture();
    bundle.job_graph.controller_job_count.count = 4;
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("controller count mismatch must fail");
    assert_eq!(error.code, "INV_JOB_COUNT_MISMATCH");
}

#[test]
fn reconciliation_requires_an_independent_count_collector() {
    let directory = TestDirectory::new("count-collector");
    let mut bundle = fixture();
    bundle.job_graph.controller_job_count.collector_id =
        bundle.job_graph.binding.exporter_id.clone();
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("same exporter and count collector must fail");
    assert_eq!(error.code, "INV_COUNT_NOT_INDEPENDENT");
}

#[test]
fn reconciliation_rejects_direct_child_count_mismatch() {
    let directory = TestDirectory::new("child-count");
    let mut bundle = fixture();
    bundle.job_graph.jobs[0].direct_child_count.count = 2;
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("direct child count mismatch must fail");
    assert_eq!(error.code, "INV_CHILD_COUNT_MISMATCH");
}

#[test]
fn reconciliation_rejects_identity_population_omissions() {
    for (name, mutate, expected) in [
        (
            "principal-count",
            (|bundle: &mut Fixture| bundle.identity_clients.principals.clear()) as fn(&mut Fixture),
            "INV_PRINCIPAL_COUNT_MISMATCH",
        ),
        (
            "acl-count",
            (|bundle: &mut Fixture| bundle.identity_clients.acl_entries.clear())
                as fn(&mut Fixture),
            "INV_ACL_COUNT_MISMATCH",
        ),
        (
            "client-count",
            (|bundle: &mut Fixture| bundle.identity_clients.clients.clear()) as fn(&mut Fixture),
            "INV_CLIENT_COUNT_MISMATCH",
        ),
    ] {
        let directory = TestDirectory::new(name);
        let mut bundle = fixture();
        mutate(&mut bundle);
        write_bundle(&directory.0, &bundle);
        seal_manifest_directory(&directory.0).expect("seal inventory");

        let loaded = load_bundle(&directory.0).expect("load bundle");
        let error = reconcile(&loaded).expect_err("identity population omission must fail");
        assert_eq!(error.code, expected);
    }
}

#[test]
fn reconciliation_rejects_same_cardinality_population_substitution() {
    for (name, mutate, expected) in [
        (
            "job-set",
            (|bundle: &mut Fixture| {
                bundle.job_graph.jobs[2].id = "replacement".to_owned();
                refresh_direct_child_count_subject(&mut bundle.job_graph.jobs[2]);
            }) as fn(&mut Fixture),
            "INV_UNKNOWN_RUNTIME_JOB",
        ),
        (
            "job-parent-set",
            (|bundle: &mut Fixture| {
                bundle.job_graph.jobs[1].parent_id = None;
                bundle.job_graph.jobs[2].parent_id = Some("folder".to_owned());
            }) as fn(&mut Fixture),
            "INV_JOB_SET_MISMATCH",
        ),
        (
            "job-semantic-set",
            (|bundle: &mut Fixture| {
                bundle.job_graph.jobs[1].owner = "replacement-owner".to_owned();
            }) as fn(&mut Fixture),
            "INV_JOB_SET_MISMATCH",
        ),
        (
            "principal-set",
            (|bundle: &mut Fixture| {
                bundle.identity_clients.principals[2].id = "group/replacement".to_owned();
            }) as fn(&mut Fixture),
            "INV_UNKNOWN_GROUP",
        ),
        (
            "principal-semantic-set",
            (|bundle: &mut Fixture| {
                bundle.identity_clients.principals[0].lifecycle = PrincipalLifecycle::Disabled;
            }) as fn(&mut Fixture),
            "INV_PRINCIPAL_SET_MISMATCH",
        ),
        (
            "acl-set",
            (|bundle: &mut Fixture| {
                bundle.identity_clients.acl_entries[0].scope = "replacement".to_owned();
            }) as fn(&mut Fixture),
            "INV_ACL_SET_MISMATCH",
        ),
        (
            "acl-permission-set",
            (|bundle: &mut Fixture| {
                bundle.identity_clients.acl_entries[0].permissions =
                    vec!["job/configure".to_owned()];
            }) as fn(&mut Fixture),
            "INV_ACL_SET_MISMATCH",
        ),
        (
            "acl-generation-set",
            (|bundle: &mut Fixture| {
                bundle.identity_clients.acl_entries[0].generation =
                    "acl-generation-replacement".to_owned();
            }) as fn(&mut Fixture),
            "INV_ACL_SET_MISMATCH",
        ),
        (
            "client-set",
            (|bundle: &mut Fixture| {
                bundle.identity_clients.clients[0].id = "replacement".to_owned();
            }) as fn(&mut Fixture),
            "INV_UNKNOWN_STATE_CONSUMER",
        ),
        (
            "client-direction-set",
            (|bundle: &mut Fixture| {
                bundle.identity_clients.clients[0].direction = ClientDirection::Write;
            }) as fn(&mut Fixture),
            "INV_STATE_CONSUMER_DIRECTION",
        ),
        (
            "client-semantic-set",
            (|bundle: &mut Fixture| {
                bundle.identity_clients.clients[0].endpoint =
                    "/job/replacement/api/json".to_owned();
            }) as fn(&mut Fixture),
            "INV_CLIENT_SET_MISMATCH",
        ),
        (
            "dependency-set",
            (|bundle: &mut Fixture| {
                bundle.runtime_dependencies.jobs[1].dependencies[0].kind =
                    RuntimeDependencyKind::ExternalEffect;
            }) as fn(&mut Fixture),
            "INV_DEPENDENCY_SET_MISMATCH",
        ),
        (
            "dependency-semantic-set",
            (|bundle: &mut Fixture| {
                bundle.runtime_dependencies.jobs[1].dependencies[0].disposition =
                    CompatibilityDisposition::Scripted;
            }) as fn(&mut Fixture),
            "INV_DEPENDENCY_SET_MISMATCH",
        ),
        (
            "state-semantic-set",
            (|bundle: &mut Fixture| {
                bundle.persistent_state.jobs[1].records[0]
                    .forward_transform
                    .disposition = CompatibilityDisposition::Scripted;
            }) as fn(&mut Fixture),
            "INV_STATE_CLASS_SET_MISMATCH",
        ),
    ] {
        let directory = TestDirectory::new(name);
        let mut bundle = fixture();
        mutate(&mut bundle);
        write_bundle(&directory.0, &bundle);
        seal_manifest_directory(&directory.0).expect("seal inventory");

        let loaded = load_bundle(&directory.0).expect("load bundle");
        let error = reconcile(&loaded).expect_err("same-cardinality substitution must fail");
        assert_eq!(error.code, expected);
    }
}

#[test]
fn reconciliation_rejects_per_job_population_ownership_substitution() {
    let directory = TestDirectory::new("runtime-job-ownership");
    let mut bundle = fixture();
    bundle.runtime_dependencies.jobs[0].dependency_set =
        bundle.runtime_dependencies.jobs[1].dependency_set.clone();
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("runtime ownership substitution must fail");
    assert_eq!(error.code, "INV_DEPENDENCY_SET_MISMATCH");

    let directory = TestDirectory::new("state-job-ownership");
    let mut bundle = fixture();
    bundle.persistent_state.jobs[0].record_class_set =
        bundle.persistent_state.jobs[1].record_class_set.clone();
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("state ownership substitution must fail");
    assert_eq!(error.code, "INV_STATE_CLASS_SET_MISMATCH");
}

#[test]
fn reconciliation_rejects_state_instance_count_ownership_substitution() {
    let directory = TestDirectory::new("state-count-ownership");
    let mut bundle = fixture();
    add_excluded_obligations(&mut bundle);
    let in_scope_count = bundle.persistent_state.jobs[1].records[0]
        .record_count
        .clone();
    bundle.persistent_state.jobs[1].records[0].record_count = bundle.persistent_state.jobs[2]
        .records[0]
        .record_count
        .clone();
    bundle.persistent_state.jobs[2].records[0].record_count = in_scope_count;
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("state count ownership substitution must fail");
    assert_eq!(error.code, "INV_COUNT_SUBJECT_MISMATCH");
}

#[test]
fn reconciliation_rejects_cross_domain_empty_population_evidence() {
    let directory = TestDirectory::new("empty-population-domain");
    let mut bundle = fixture();
    bundle.persistent_state.jobs[0].record_class_set =
        bundle.runtime_dependencies.jobs[0].dependency_set.clone();
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("cross-domain empty evidence must fail");
    assert_eq!(error.code, "INV_STATE_CLASS_SET_MISMATCH");
}

#[test]
fn reconciliation_requires_runtime_coverage_for_excluded_jobs() {
    let directory = TestDirectory::new("excluded-runtime-coverage");
    let mut bundle = fixture();
    bundle
        .runtime_dependencies
        .jobs
        .retain(|job| job.job_id != "legacy");
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("excluded runtime omission must fail");
    assert_eq!(error.code, "INV_RUNTIME_COVERAGE");
}

#[test]
fn reconciliation_rejects_cross_epoch_per_job_evidence_replay() {
    let directory = TestDirectory::new("cross-epoch-runtime-replay");
    let mut bundle = fixture();
    let stale_runtime = bundle.runtime_dependencies.jobs[1].clone();
    for binding in [
        &mut bundle.job_graph.binding,
        &mut bundle.identity_clients.binding,
        &mut bundle.runtime_dependencies.binding,
        &mut bundle.persistent_state.binding,
    ] {
        binding.epoch_id = "epoch-2".to_owned();
        binding.source_generation = "generation-43".to_owned();
    }
    refresh_population_commitments(&mut bundle);
    bundle.runtime_dependencies.jobs[1] = stale_runtime;
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("stale runtime evidence must fail");
    assert_eq!(error.code, "INV_COUNT_SUBJECT_MISMATCH");
}

#[test]
fn reconciliation_rejects_stale_evidence_after_snapshot_configuration_changes() {
    let directory = TestDirectory::new("stale-snapshot-configuration");
    let mut bundle = fixture();
    let trusted_snapshot_sha256 = snapshot_binding_sha256(&bundle.job_graph.binding);
    for binding in [
        &mut bundle.job_graph.binding,
        &mut bundle.identity_clients.binding,
        &mut bundle.runtime_dependencies.binding,
        &mut bundle.persistent_state.binding,
    ] {
        binding.global_config_sha256 = DIGEST_A.to_owned();
    }
    refresh_population_commitments(&mut bundle);
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile_for_snapshot(&loaded, &trusted_snapshot_sha256)
        .expect_err("stale snapshot evidence must fail");
    assert_eq!(error.code, "INV_SNAPSHOT_EXPECTATION_MISMATCH");
}

#[test]
fn reconciliation_rejects_cross_domain_empty_identity_set_evidence() {
    let directory = TestDirectory::new("empty-identity-domain");
    let mut bundle = fixture();
    bundle.identity_clients.principals.clear();
    bundle.identity_clients.acl_entries.clear();
    bundle.identity_clients.clients.clear();
    bundle.identity_clients.principal_count.count = 0;
    bundle.identity_clients.acl_entry_count.count = 0;
    bundle.identity_clients.client_count.count = 0;
    bundle.persistent_state.jobs[1].records[0]
        .external_consumers
        .clear();
    refresh_population_commitments(&mut bundle);
    bundle.identity_clients.acl_entry_set = bundle.identity_clients.principal_set.clone();
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("cross-domain identity evidence must fail");
    assert_eq!(error.code, "INV_ACL_SET_MISMATCH");
}

#[test]
fn reconciliation_rejects_runtime_dependency_population_omission() {
    let directory = TestDirectory::new("runtime-dependency-count");
    let mut bundle = fixture();
    bundle.runtime_dependencies.jobs[1].dependencies.clear();
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("runtime dependency omission must fail");
    assert_eq!(error.code, "INV_DEPENDENCY_COUNT_MISMATCH");
}

#[test]
fn reconciliation_rejects_state_record_class_population_omission() {
    let directory = TestDirectory::new("state-record-class-count");
    let mut bundle = fixture();
    bundle.persistent_state.jobs[1].records.clear();
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("state-record class omission must fail");
    assert_eq!(error.code, "INV_STATE_CLASS_COUNT_MISMATCH");
}

#[test]
fn reconciliation_requires_state_coverage_for_out_of_scope_jobs() {
    let directory = TestDirectory::new("out-of-scope-state-coverage");
    let mut bundle = fixture();
    bundle.job_graph.jobs[2].scope = ApprovedDisposition {
        disposition: ScopeDisposition::OutOfScope,
        approval: Some("owner-approval/defer-legacy".to_owned()),
    };
    bundle.persistent_state.jobs.remove(2);
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("out-of-scope state omission must fail");
    assert_eq!(error.code, "INV_STATE_COVERAGE");
}

#[test]
fn reconciliation_requires_state_coverage_for_retired_jobs() {
    let directory = TestDirectory::new("retired-state-coverage");
    let mut bundle = fixture();
    bundle.persistent_state.jobs.remove(2);
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("retired state omission must fail");
    assert_eq!(error.code, "INV_STATE_COVERAGE");
}

#[test]
fn state_record_instance_counts_require_independent_evidence() {
    let directory = TestDirectory::new("state-instance-count-collector");
    let mut bundle = fixture();
    bundle.persistent_state.jobs[1].records[0]
        .record_count
        .collector_id = bundle.persistent_state.binding.exporter_id.clone();
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("dependent state instance count must fail");
    assert_eq!(error.code, "INV_COUNT_NOT_INDEPENDENT");
}

#[test]
fn reconciliation_binds_state_class_identities_to_source_evidence() {
    let directory = TestDirectory::new("state-class-set");
    let mut bundle = fixture();
    bundle.persistent_state.jobs[1].records[0].kind = "workspace".to_owned();
    refresh_record_count_subject(
        "folder/build",
        &mut bundle.persistent_state.jobs[1].records[0],
    );
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("substituted state class must fail");
    assert_eq!(error.code, "INV_STATE_CLASS_SET_MISMATCH");
}

#[test]
fn state_class_sets_require_an_independent_collector() {
    let directory = TestDirectory::new("state-class-set-collector");
    let mut bundle = fixture();
    bundle.persistent_state.jobs[1]
        .record_class_set
        .collector_id = bundle.persistent_state.binding.exporter_id.clone();
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("dependent state class collector must fail");
    assert_eq!(error.code, "INV_SET_NOT_INDEPENDENT");
}

#[test]
fn every_population_count_requires_an_independent_collector() {
    let directory = TestDirectory::new("population-count-collector");
    let mut bundle = fixture();
    bundle.runtime_dependencies.jobs[1]
        .dependency_count
        .collector_id = bundle.runtime_dependencies.binding.exporter_id.clone();
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("dependent population collector must fail");
    assert_eq!(error.code, "INV_COUNT_NOT_INDEPENDENT");
}

#[test]
fn reconciliation_rejects_in_scope_jobs_with_excluded_parents() {
    let directory = TestDirectory::new("excluded-parent");
    let mut bundle = fixture();
    bundle.job_graph.jobs[0].scope = ApprovedDisposition {
        disposition: ScopeDisposition::Retired,
        approval: Some("owner-approval/retire-folder".to_owned()),
    };
    bundle.runtime_dependencies.jobs.remove(0);
    bundle.persistent_state.jobs.remove(0);
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("excluded parent must fail");
    assert_eq!(error.code, "INV_EXCLUDED_PARENT");
}

#[test]
fn reconciliation_preserves_excluded_job_obligations_without_counting_them_as_eligible() {
    let directory = TestDirectory::new("excluded-obligations");
    let mut bundle = fixture();
    add_excluded_obligations(&mut bundle);
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let ledger = reconcile(&loaded).expect("excluded evidence must remain admissible");
    assert_eq!(ledger.jobs.len(), 2);
    assert_eq!(ledger.population.runtime_dependencies, 2);
    assert_eq!(ledger.population.persistent_record_classes, 2);
    assert_eq!(ledger.parity_demands["source-checkout"], 1);
    assert_eq!(ledger.state_transform_records, 8);
}

#[test]
fn reconciliation_validates_excluded_job_obligations() {
    let directory = TestDirectory::new("excluded-invalid-state");
    let mut bundle = fixture();
    add_excluded_obligations(&mut bundle);
    bundle.persistent_state.jobs[2].records[0].restore_target = " ".to_owned();
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("invalid excluded state must fail");
    assert_eq!(error.code, "INV_REQUIRED");

    let directory = TestDirectory::new("excluded-unclassified-runtime");
    let mut bundle = fixture();
    add_excluded_obligations(&mut bundle);
    bundle.runtime_dependencies.jobs[2].dependencies[0].disposition =
        CompatibilityDisposition::Unclassified;
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");
    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("unclassified excluded dependency must fail");
    assert_eq!(error.code, "INV_UNCLASSIFIED");
}

#[test]
fn reconciliation_rejects_principal_alias_collisions() {
    let directory = TestDirectory::new("principal-alias");
    let mut bundle = fixture();
    let colliding_id = bundle.identity_clients.principals[1].id.clone();
    bundle.identity_clients.principals[0].aliases = vec![colliding_id];
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("alias collision must fail");
    assert_eq!(error.code, "INV_PRINCIPAL_NAME_COLLISION");
}

#[test]
fn reconciliation_preserves_deleted_historical_name_reuse() {
    let directory = TestDirectory::new("deleted-name-reuse");
    let mut bundle = fixture();
    bundle.identity_clients.principals.push(Principal {
        id: "user/deleted-operator".to_owned(),
        kind: PrincipalKind::User,
        aliases: Vec::new(),
        historical_names: vec![HistoricalNameClaim {
            name: "operator-old".to_owned(),
            generation: "identity-generation-1".to_owned(),
            provenance: "jenkins/deleted-user/operator-old".to_owned(),
        }],
        groups: Vec::new(),
        membership_generation: "membership-deleted-1".to_owned(),
        lifecycle: PrincipalLifecycle::Deleted,
        provenance: "jenkins/deleted-user/operator".to_owned(),
    });
    bundle.identity_clients.principal_count.count = 4;
    refresh_fixture_sets(&mut bundle);
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let ledger = reconcile(&loaded).expect("historical name reuse is evidence, not ambiguity");
    assert_eq!(ledger.population.principals, 4);
}

#[test]
fn reconciliation_accepts_observed_source_clients_without_fabricated_principals() {
    let directory = TestDirectory::new("observed-source-client");
    let mut bundle = fixture();
    bundle.identity_clients.clients[0].caller = ClientCaller::ObservedSource {
        source: "reverse-proxy/access-log/public-dashboard".to_owned(),
    };
    refresh_fixture_sets(&mut bundle);
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    reconcile(&loaded).expect("observed caller source must be admissible");
}

#[test]
fn reconciliation_rejects_unknown_client_principals() {
    let directory = TestDirectory::new("unknown-client-principal");
    let mut bundle = fixture();
    bundle.identity_clients.clients[0].caller = ClientCaller::Principal {
        principal_id: "user/missing".to_owned(),
    };
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("unknown caller principal must fail");
    assert_eq!(error.code, "INV_UNKNOWN_CLIENT_PRINCIPAL");
}

#[test]
fn reconciliation_requires_principal_client_and_acl_evidence() {
    let directory = TestDirectory::new("identity-required");
    let mut bundle = fixture();
    bundle.identity_clients.principals[0].provenance = " ".to_owned();
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("blank principal provenance must fail");
    assert_eq!(error.code, "INV_REQUIRED");

    let directory = TestDirectory::new("client-required");
    let mut bundle = fixture();
    bundle.identity_clients.clients[0].actions.clear();
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");
    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("empty client actions must fail");
    assert_eq!(error.code, "INV_REQUIRED");

    let directory = TestDirectory::new("acl-required");
    let mut bundle = fixture();
    bundle.identity_clients.acl_entries[0].permissions.clear();
    refresh_fixture_sets(&mut bundle);
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");
    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("empty ACL permissions must fail");
    assert_eq!(error.code, "INV_REQUIRED");
}

#[test]
fn reconciliation_rejects_parent_cycles() {
    let directory = TestDirectory::new("parent-cycle");
    let mut bundle = fixture();
    bundle.job_graph.jobs[0].parent_id = Some("folder/build".to_owned());
    bundle.job_graph.jobs[1].direct_child_count.count = 1;
    refresh_fixture_sets(&mut bundle);
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("parent cycle must fail");
    assert_eq!(error.code, "INV_JOB_GRAPH_CYCLE");
}

#[test]
fn reconciliation_rejects_blank_secret_references() {
    let directory = TestDirectory::new("blank-secret-reference");
    let mut bundle = fixture();
    bundle.runtime_dependencies.jobs[1].dependencies[0].credential_reference =
        Some("   ".to_owned());
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("blank secret reference must fail");
    assert_eq!(error.code, "INV_SECRET_REFERENCE_REQUIRED");
}

#[test]
fn reconciliation_rejects_unknown_confidentiality_labels() {
    let directory = TestDirectory::new("confidentiality");
    let mut bundle = fixture();
    bundle.runtime_dependencies.jobs[1].dependencies[0].confidentiality = "Secret ".to_owned();
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("unknown confidentiality must fail");
    assert_eq!(error.code, "INV_CONFIDENTIALITY");
}

#[test]
fn reconciliation_requires_runtime_dependency_metadata() {
    let directory = TestDirectory::new("runtime-required");
    let mut bundle = fixture();
    bundle.runtime_dependencies.jobs[1].dependencies[0].resource_scope = " ".to_owned();
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("blank runtime scope must fail");
    assert_eq!(error.code, "INV_REQUIRED");
}

#[test]
fn reconciliation_rejects_blank_retention_deadline() {
    let directory = TestDirectory::new("blank-retention");
    let mut bundle = fixture();
    bundle.persistent_state.jobs[1].records[0].retention_deadline = " \n ".to_owned();
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("blank retention deadline must fail");
    assert_eq!(error.code, "INV_TIMESTAMP");
}

#[test]
fn reconciliation_rejects_invalid_retention_deadlines() {
    let directory = TestDirectory::new("invalid-retention");
    let mut bundle = fixture();
    bundle.persistent_state.jobs[1].records[0].retention_deadline =
        "2027-99-99T25:61:61Z".to_owned();
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("invalid retention deadline must fail");
    assert_eq!(error.code, "INV_TIMESTAMP");
}

#[test]
fn reconciliation_requires_bound_retention_policies() {
    let directory = TestDirectory::new("blank-retention-policy");
    let mut bundle = fixture();
    bundle.persistent_state.jobs[1].records[0].retention_policy_id = " ".to_owned();
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");
    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("blank retention policy must fail");
    assert_eq!(error.code, "INV_REQUIRED");

    let directory = TestDirectory::new("invalid-retention-policy-digest");
    let mut bundle = fixture();
    bundle.persistent_state.jobs[1].records[0].retention_policy_sha256 = "not-a-digest".to_owned();
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");
    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("invalid retention policy digest must fail");
    assert_eq!(error.code, "INV_DIGEST");
}

#[test]
fn reconciliation_rejects_conflicting_retention_policy_definitions() {
    let directory = TestDirectory::new("retention-policy-conflict");
    let mut bundle = fixture();
    let mut second = bundle.persistent_state.jobs[1].records[0].clone();
    second.id = "folder-history".to_owned();
    second.retention_policy_sha256 = DIGEST_C.to_owned();
    second.external_consumers.clear();
    refresh_record_count_subject("folder", &mut second);
    bundle.persistent_state.jobs[0].records.push(second);
    bundle.persistent_state.jobs[0].record_class_count.count = 1;
    refresh_state_class_set(&mut bundle.persistent_state.jobs[0]);
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("conflicting retention policies must fail");
    assert_eq!(error.code, "INV_RETENTION_POLICY_CONFLICT");
}

#[test]
fn state_transform_disposition_constrains_job_eligibility() {
    let directory = TestDirectory::new("state-disposition");
    let mut bundle = fixture();
    bundle.persistent_state.jobs[1].records[0]
        .rollback_transform
        .disposition = CompatibilityDisposition::Unsupported;
    refresh_state_class_set(&mut bundle.persistent_state.jobs[1]);
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let ledger = reconcile(&loaded).expect("classified unsupported state must reconcile");
    let job = ledger
        .jobs
        .iter()
        .find(|job| job.job_id == "folder/build")
        .expect("fixture job");
    assert_eq!(job.disposition, CompatibilityDisposition::Unsupported);
}

#[test]
fn reconciliation_rejects_unclassified_state_transforms() {
    let directory = TestDirectory::new("state-unclassified");
    let mut bundle = fixture();
    bundle.persistent_state.jobs[1].records[0]
        .forward_transform
        .disposition = CompatibilityDisposition::Unclassified;
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("unclassified state transform must fail");
    assert_eq!(error.code, "INV_STATE_UNCLASSIFIED");
}

#[test]
fn reconciliation_rejects_invalid_collection_timestamp() {
    let directory = TestDirectory::new("invalid-collection-time");
    let mut bundle = fixture();
    let invalid = "2026-02-30T12:00:00Z".to_owned();
    bundle.job_graph.binding.collected_at = invalid.clone();
    bundle.identity_clients.binding.collected_at = invalid.clone();
    bundle.runtime_dependencies.binding.collected_at = invalid.clone();
    bundle.persistent_state.binding.collected_at = invalid;
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("invalid collection timestamp must fail");
    assert_eq!(error.code, "INV_TIMESTAMP");
}

#[test]
fn reconciliation_requires_state_restoration_metadata() {
    let directory = TestDirectory::new("state-restore");
    let mut bundle = fixture();
    bundle.persistent_state.jobs[1].records[0].restore_target = "\n".to_owned();
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("blank restore target must fail");
    assert_eq!(error.code, "INV_REQUIRED");
}

#[test]
fn reconciliation_requires_legal_hold_identity() {
    let directory = TestDirectory::new("hold-identity");
    let mut bundle = fixture();
    bundle.persistent_state.jobs[1].records[0].legal_holds[0].id = " ".to_owned();
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("blank hold identity must fail");
    assert_eq!(error.code, "INV_REQUIRED");
}

#[test]
fn reconciliation_rejects_conflicting_legal_hold_definitions() {
    let directory = TestDirectory::new("hold-conflict");
    let mut bundle = fixture();
    let mut second = bundle.persistent_state.jobs[1].records[0].clone();
    second.id = "artifact-history".to_owned();
    second.legal_holds[0].scope = "artifacts-only".to_owned();
    refresh_record_count_subject("folder/build", &mut second);
    bundle.persistent_state.jobs[1].records.push(second);
    bundle.persistent_state.jobs[1].record_class_count.count = 2;
    refresh_state_class_set(&mut bundle.persistent_state.jobs[1]);
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("conflicting legal hold definitions must fail");
    assert_eq!(error.code, "INV_HOLD_CONFLICT");
}

#[test]
fn reconciliation_rejects_state_record_count_overflow() {
    let directory = TestDirectory::new("state-count-overflow");
    let mut bundle = fixture();
    let records = &mut bundle.persistent_state.jobs[1].records;
    records[0].record_count.count = i64::MAX as u64;
    let mut second = records[0].clone();
    second.id = "state/folder/overflow".to_owned();
    refresh_record_count_subject("folder/build", &mut second);
    records.push(second);
    let mut third = records[0].clone();
    third.id = "state/folder/overflow-final".to_owned();
    third.record_count.count = 2;
    refresh_record_count_subject("folder/build", &mut third);
    records.push(third);
    bundle.persistent_state.jobs[1].record_class_count.count = 3;
    refresh_state_class_set(&mut bundle.persistent_state.jobs[1]);
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("state record count overflow must fail");
    assert_eq!(error.code, "INV_COUNT_OVERFLOW");
}

#[test]
fn reconciliation_rejects_unknown_group_membership() {
    let directory = TestDirectory::new("group");
    let mut bundle = fixture();
    bundle.identity_clients.principals[0].groups = vec!["group/missing".to_owned()];
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("unknown group must fail");
    assert_eq!(error.code, "INV_UNKNOWN_GROUP");
}

#[test]
fn strict_schema_rejects_unknown_principal_kind() {
    let directory = TestDirectory::new("principal-kind");
    write_bundle(&directory.0, &fixture());
    let path = directory.0.join(IDENTITY_CLIENT_FILE);
    let source = fs::read_to_string(&path).expect("read identity manifest");
    let hostile = source.replacen("kind: user", "kind: groupp", 1);
    assert_ne!(hostile, source, "fixture must contain a user principal");
    fs::write(path, hostile).expect("write hostile identity manifest");
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let error = load_bundle(&directory.0).expect_err("unknown principal kind must fail");
    assert_eq!(error.code, "INV_SCHEMA");
}

#[test]
fn strict_schema_rejects_unknown_principal_lifecycle() {
    let directory = TestDirectory::new("principal-lifecycle");
    write_bundle(&directory.0, &fixture());
    let path = directory.0.join(IDENTITY_CLIENT_FILE);
    let source = fs::read_to_string(&path).expect("read identity manifest");
    let hostile = source.replacen("lifecycle: active", "lifecycle: deletd", 1);
    assert_ne!(hostile, source, "fixture must contain an active principal");
    fs::write(path, hostile).expect("write hostile identity manifest");
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let error = load_bundle(&directory.0).expect_err("unknown principal lifecycle must fail");
    assert_eq!(error.code, "INV_SCHEMA");
}

#[test]
fn reconciliation_rejects_unknown_state_consumer() {
    let directory = TestDirectory::new("state-consumer");
    let mut bundle = fixture();
    bundle.persistent_state.jobs[1].records[0].external_consumers =
        vec!["missing-client".to_owned()];
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("unknown state consumer must fail");
    assert_eq!(error.code, "INV_UNKNOWN_STATE_CONSUMER");
}

#[test]
fn reconciliation_rejects_write_only_state_consumers() {
    let directory = TestDirectory::new("write-only-state-consumer");
    let mut bundle = fixture();
    bundle.persistent_state.jobs[1].records[0].external_consumers = vec!["seed-service".to_owned()];
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("write-only state consumer must fail");
    assert_eq!(error.code, "INV_STATE_CONSUMER_DIRECTION");
}

#[test]
fn strict_schema_rejects_unknown_runtime_dependency_kind() {
    let directory = TestDirectory::new("unknown-runtime-dependency-kind");
    write_bundle(&directory.0, &fixture());
    let path = directory.0.join(RUNTIME_DEPENDENCY_FILE);
    let source = fs::read_to_string(&path).expect("read runtime manifest");
    fs::write(
        &path,
        source.replacen("kind: source-checkout", "kind: source-checkoutt", 1),
    )
    .expect("write hostile runtime manifest");
    seal_manifest_directory(&directory.0).expect("seal hostile inventory");

    let error = load_bundle(&directory.0).expect_err("unknown dependency kind must fail");
    assert_eq!(error.code, "INV_SCHEMA");
}

#[test]
fn reconciliation_rejects_duplicate_acl_scope() {
    let directory = TestDirectory::new("duplicate-acl");
    let mut bundle = fixture();
    bundle
        .identity_clients
        .acl_entries
        .push(bundle.identity_clients.acl_entries[0].clone());
    bundle.identity_clients.acl_entry_count.count = 2;
    refresh_fixture_sets(&mut bundle);
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("duplicate ACL must fail");
    assert_eq!(error.code, "INV_DUPLICATE_ACL");
}

#[derive(Clone)]
struct Fixture {
    job_graph: JobGraphManifest,
    identity_clients: IdentityClientManifest,
    runtime_dependencies: RuntimeDependencyManifest,
    persistent_state: PersistentStateManifest,
}

fn fixture() -> Fixture {
    let binding = binding();
    let mut folder = job("folder", None, ScopeDisposition::InScope);
    folder.direct_child_count.count = 1;
    let mut fixture = Fixture {
        job_graph: JobGraphManifest {
            binding: binding.clone(),
            controller_job_count: count_evidence(
                3,
                "jenkins/controller/item-count",
                &[b"controller-job-count"],
            ),
            job_set: placeholder_set_evidence("jenkins/controller/item-set"),
            jobs: vec![
                folder,
                job("folder/build", Some("folder"), ScopeDisposition::InScope),
                JobRecord {
                    scope: ApprovedDisposition {
                        disposition: ScopeDisposition::Retired,
                        approval: Some("owner-approval/retire-legacy".to_owned()),
                    },
                    ..job("legacy", None, ScopeDisposition::Retired)
                },
            ],
        },
        identity_clients: IdentityClientManifest {
            binding: binding.clone(),
            security_realm: SecurityRealm {
                implementation: "jenkins.security.HudsonPrivateSecurityRealm".to_owned(),
                config_sha256: DIGEST_A.to_owned(),
                identity_provider_generation: "realm-generation-7".to_owned(),
            },
            principal_count: count_evidence(
                3,
                "jenkins/security-realm/principal-count",
                &[b"principal-count"],
            ),
            principal_set: placeholder_set_evidence("jenkins/security-realm/principal-set"),
            principals: vec![
                Principal {
                    id: "user/operator".to_owned(),
                    kind: PrincipalKind::User,
                    aliases: vec!["operator-old".to_owned()],
                    historical_names: Vec::new(),
                    groups: vec!["group/builders".to_owned()],
                    membership_generation: "membership-3".to_owned(),
                    lifecycle: PrincipalLifecycle::Active,
                    provenance: "jenkins/user/operator".to_owned(),
                },
                Principal {
                    id: "service/seed".to_owned(),
                    kind: PrincipalKind::Service,
                    aliases: Vec::new(),
                    historical_names: Vec::new(),
                    groups: Vec::new(),
                    membership_generation: "service-1".to_owned(),
                    lifecycle: PrincipalLifecycle::Active,
                    provenance: "jenkins/service/seed".to_owned(),
                },
                Principal {
                    id: "group/builders".to_owned(),
                    kind: PrincipalKind::Group,
                    aliases: Vec::new(),
                    historical_names: Vec::new(),
                    groups: Vec::new(),
                    membership_generation: "group-4".to_owned(),
                    lifecycle: PrincipalLifecycle::Active,
                    provenance: "jenkins/group/builders".to_owned(),
                },
            ],
            acl_entry_count: count_evidence(
                1,
                "jenkins/authorization/acl-entry-count",
                &[b"acl-count"],
            ),
            acl_entry_set: placeholder_set_evidence("jenkins/authorization/acl-entry-set"),
            acl_entries: vec![AclEntry {
                job_id: "folder/build".to_owned(),
                principal_id: "user/operator".to_owned(),
                scope: "job".to_owned(),
                permissions: vec!["job/read".to_owned(), "job/build".to_owned()],
                generation: "acl-12".to_owned(),
            }],
            client_count: count_evidence(2, "jenkins/access-log/client-count", &[b"client-count"]),
            client_set: placeholder_set_evidence("jenkins/access-log/client-set"),
            clients: vec![
                ClientRecord {
                    id: "dashboard".to_owned(),
                    direction: ClientDirection::Read,
                    caller: ClientCaller::Principal {
                        principal_id: "user/operator".to_owned(),
                    },
                    authentication: "session".to_owned(),
                    endpoint: "/job/folder/job/build/api/json".to_owned(),
                    actions: vec!["read-status".to_owned()],
                    scope: "folder/build".to_owned(),
                    owner: "ci-platform".to_owned(),
                    observed_use: "2026-07-30T12:00:00Z".to_owned(),
                    generation: "client-2".to_owned(),
                },
                ClientRecord {
                    id: "seed-service".to_owned(),
                    direction: ClientDirection::Write,
                    caller: ClientCaller::Principal {
                        principal_id: "service/seed".to_owned(),
                    },
                    authentication: "api-token".to_owned(),
                    endpoint: "/createItem".to_owned(),
                    actions: vec!["create-job".to_owned()],
                    scope: "folder".to_owned(),
                    owner: "ci-platform".to_owned(),
                    observed_use: "2026-07-30T12:00:00Z".to_owned(),
                    generation: "client-5".to_owned(),
                },
            ],
        },
        runtime_dependencies: RuntimeDependencyManifest {
            binding: binding.clone(),
            jobs: vec![
                job_dependencies("folder", Vec::new()),
                job_dependencies(
                    "folder/build",
                    vec![RuntimeDependency {
                        id: "credential/source".to_owned(),
                        kind: RuntimeDependencyKind::SourceCheckout,
                        requirements: vec![
                            JobRequirement::Trigger {
                                declaration: "manual".to_owned(),
                            },
                            JobRequirement::Platform {
                                name: "linux".to_owned(),
                            },
                            JobRequirement::AgentLabel {
                                label: "linux".to_owned(),
                            },
                            JobRequirement::Toolchain {
                                name: "jdk-21".to_owned(),
                            },
                        ],
                        owner: "ci-platform".to_owned(),
                        implementation_sha256: DIGEST_A.to_owned(),
                        config_sha256: DIGEST_B.to_owned(),
                        resource_scope: "repo/example".to_owned(),
                        mutability: DependencyMutability::PinnedRevision,
                        provenance: "jenkins/credentials/source".to_owned(),
                        confidentiality: "secret".to_owned(),
                        credential_reference: Some("protected-evidence/credential-7".to_owned()),
                        redaction_reference: None,
                        secret_consumer: Some(SecretConsumerEvidence {
                            consumer: SecretConsumer::SourceAcquisition {
                                checkout_id: "source-checkout/provider-auth".to_owned(),
                            },
                            taint: SecretTaint::SourceAcquisitionOnly,
                            taint_path: vec![
                                "credential/provider-token".to_owned(),
                                "checkout/auth-header".to_owned(),
                            ],
                            provenance: "jenkins/job/folder/build/credential-usage".to_owned(),
                            evidence_sha256: DIGEST_C.to_owned(),
                        }),
                        disposition: CompatibilityDisposition::Mappable,
                    }],
                ),
                job_dependencies("legacy", Vec::new()),
            ],
        },
        persistent_state: PersistentStateManifest {
            binding,
            jobs: vec![
                job_state_records("folder", Vec::new()),
                job_state_records(
                    "folder/build",
                    vec![StateRecord {
                        id: "build-history".to_owned(),
                        kind: "build-number-and-result".to_owned(),
                        owner: "ci-platform".to_owned(),
                        record_count: count_evidence(
                            8,
                            "jenkins/job/folder/build/build-history-count",
                            &[
                                b"state-record-instance-count",
                                b"folder/build",
                                b"build-history",
                                b"build-number-and-result",
                            ],
                        ),
                        source_sha256: DIGEST_C.to_owned(),
                        confidentiality: "internal".to_owned(),
                        restore_target: "jenkins/folder/build".to_owned(),
                        conflict_policy: "reject".to_owned(),
                        retention_policy_id: "jenkins/job-log-rotator".to_owned(),
                        retention_policy_sha256: DIGEST_B.to_owned(),
                        retention_deadline: "2027-07-30T00:00:00Z".to_owned(),
                        forward_transform: state_transform(CompatibilityDisposition::Native),
                        rollback_transform: state_transform(CompatibilityDisposition::Native),
                        legal_holds: vec![LegalHold {
                            id: "hold-7".to_owned(),
                            scope: "all-history".to_owned(),
                            reason: "incident".to_owned(),
                            generation: "hold-generation-1".to_owned(),
                            release_authority: "legal/service".to_owned(),
                        }],
                        external_consumers: vec!["dashboard".to_owned()],
                        provenance: "jenkins/build-history/folder/build".to_owned(),
                    }],
                ),
                job_state_records("legacy", Vec::new()),
            ],
        },
    };
    refresh_fixture_sets(&mut fixture);
    fixture
}

fn add_excluded_obligations(fixture: &mut Fixture) {
    let mut dependency = fixture.runtime_dependencies.jobs[1].dependencies[0].clone();
    dependency.id = "credential/legacy".to_owned();
    dependency.requirements.clear();
    dependency.provenance = "jenkins/credentials/legacy".to_owned();
    fixture.runtime_dependencies.jobs[2] = job_dependencies("legacy", vec![dependency]);

    let mut state = fixture.persistent_state.jobs[1].records[0].clone();
    state.id = "legacy-history".to_owned();
    state.record_count = count_evidence(
        13,
        "jenkins/job/legacy/build-history-count",
        &[
            b"state-record-instance-count",
            b"legacy",
            b"legacy-history",
            b"build-number-and-result",
        ],
    );
    state.restore_target = "retention-vault/legacy".to_owned();
    state.external_consumers.clear();
    state.provenance = "jenkins/build-history/legacy".to_owned();
    fixture.persistent_state.jobs[2] = job_state_records("legacy", vec![state]);
}

fn binding() -> SnapshotBinding {
    SnapshotBinding {
        schema: SCHEMA_VERSION.to_owned(),
        controller_id: "jenkins/oracle".to_owned(),
        controller_url: "https://jenkins.invalid".to_owned(),
        controller_core_version: "2.516.2".to_owned(),
        plugin_profile_sha256: DIGEST_A.to_owned(),
        global_config_sha256: DIGEST_B.to_owned(),
        epoch_id: "epoch-1".to_owned(),
        source_generation: "generation-42".to_owned(),
        collected_at: "2026-07-30T12:00:00Z".to_owned(),
        exporter_id: "mcloving-inventory-export".to_owned(),
        exporter_version: "1".to_owned(),
        exporter_sha256: DIGEST_C.to_owned(),
        provenance: "contained-fixture".to_owned(),
    }
}

fn job(id: &str, parent_id: Option<&str>, disposition: ScopeDisposition) -> JobRecord {
    let is_pipeline = parent_id.is_some();
    JobRecord {
        id: id.to_owned(),
        parent_id: parent_id.map(str::to_owned),
        kind: if parent_id.is_some() {
            "pipeline".to_owned()
        } else {
            "folder".to_owned()
        },
        owner: "ci-platform".to_owned(),
        canonical_source: format!("jenkins://oracle/{id}/config.xml"),
        source_sha256: DIGEST_A.to_owned(),
        config_sha256: DIGEST_B.to_owned(),
        definition_kind: "declarative".to_owned(),
        operational_state: OperationalState {
            enabled: true,
            generation: "job-generation-1".to_owned(),
            reason: "source-state".to_owned(),
            actor: "jenkins/system".to_owned(),
        },
        shared_library_refs: Vec::new(),
        triggers: is_pipeline
            .then(|| "manual".to_owned())
            .into_iter()
            .collect(),
        platforms: is_pipeline
            .then(|| "linux".to_owned())
            .into_iter()
            .collect(),
        agent_labels: is_pipeline
            .then(|| "linux".to_owned())
            .into_iter()
            .collect(),
        toolchains: is_pipeline
            .then(|| "jdk-21".to_owned())
            .into_iter()
            .collect(),
        node_authority: "trusted-linux".to_owned(),
        publishes_artifacts: true,
        publishes_tests: true,
        direct_child_count: count_evidence(
            0,
            &format!("jenkins/job/{id}/child-count"),
            &[b"direct-child-count", id.as_bytes()],
        ),
        scope: ApprovedDisposition {
            disposition,
            approval: None,
        },
    }
}

fn count_evidence(count: u64, provenance: &str, subject_fields: &[&[u8]]) -> CountEvidence {
    CountEvidence {
        count,
        collector_id: "jenkins/count-api-v1".to_owned(),
        provenance: provenance.to_owned(),
        source_sha256: DIGEST_C.to_owned(),
        subject_sha256: count_subject_sha256(subject_fields),
    }
}

fn refresh_direct_child_count_subject(job: &mut JobRecord) {
    job.direct_child_count.subject_sha256 =
        count_subject_sha256(&[b"direct-child-count", job.id.as_bytes()]);
}

fn refresh_record_count_subject(job_id: &str, record: &mut StateRecord) {
    record.record_count.subject_sha256 = count_subject_sha256(&[
        b"state-record-instance-count",
        job_id.as_bytes(),
        record.id.as_bytes(),
        record.kind.as_bytes(),
    ]);
}

fn placeholder_set_evidence(provenance: &str) -> SetEvidence {
    set_evidence(provenance, Vec::new())
}

fn refresh_fixture_sets(fixture: &mut Fixture) {
    let mut job_entries = vec![set_subject_entry_for(
        &fixture.job_graph.binding,
        b"job-graph-set",
        &[],
    )];
    job_entries.extend(fixture.job_graph.jobs.iter().map(|job| {
        vec![
            b"job-record-v1".to_vec(),
            job.id.as_bytes().to_vec(),
            serde_saphyr::to_string(job)
                .expect("serialize job commitment")
                .into_bytes(),
        ]
    }));
    fixture.job_graph.job_set = owned_set_evidence("jenkins/controller/item-set", job_entries);
    let mut principal_entries = vec![set_subject_entry_for(
        &fixture.identity_clients.binding,
        b"principal-set",
        &[],
    )];
    principal_entries.push(vec![
        b"security-realm-record-v1".to_vec(),
        serde_saphyr::to_string(&fixture.identity_clients.security_realm)
            .expect("serialize security-realm commitment")
            .into_bytes(),
    ]);
    principal_entries.extend(fixture.identity_clients.principals.iter().map(|principal| {
        vec![
            b"principal-record-v1".to_vec(),
            principal.id.as_bytes().to_vec(),
            serde_saphyr::to_string(principal)
                .expect("serialize principal commitment")
                .into_bytes(),
        ]
    }));
    fixture.identity_clients.principal_set =
        owned_set_evidence("jenkins/security-realm/principal-set", principal_entries);
    let mut acl_entries = vec![set_subject_entry_for(
        &fixture.identity_clients.binding,
        b"acl-set",
        &[],
    )];
    acl_entries.extend(fixture.identity_clients.acl_entries.iter().map(|acl| {
        let mut canonical_acl = acl.clone();
        canonical_acl.permissions.sort();
        vec![
            b"acl-record-v1".to_vec(),
            acl.job_id.as_bytes().to_vec(),
            acl.principal_id.as_bytes().to_vec(),
            acl.scope.as_bytes().to_vec(),
            serde_saphyr::to_string(&canonical_acl)
                .expect("serialize ACL commitment")
                .into_bytes(),
        ]
    }));
    fixture.identity_clients.acl_entry_set =
        owned_set_evidence("jenkins/authorization/acl-entry-set", acl_entries);
    let mut client_entries = vec![set_subject_entry_for(
        &fixture.identity_clients.binding,
        b"client-set",
        &[],
    )];
    client_entries.extend(fixture.identity_clients.clients.iter().map(|client| {
        vec![
            b"client-record-v1".to_vec(),
            client.id.as_bytes().to_vec(),
            serde_saphyr::to_string(client)
                .expect("serialize client commitment")
                .into_bytes(),
        ]
    }));
    fixture.identity_clients.client_set =
        owned_set_evidence("jenkins/access-log/client-set", client_entries);
}

fn refresh_population_commitments(fixture: &mut Fixture) {
    fixture.job_graph.controller_job_count.subject_sha256 =
        count_subject_sha256_for(&fixture.job_graph.binding, &[b"controller-job-count"]);
    for job in &mut fixture.job_graph.jobs {
        job.direct_child_count.subject_sha256 = count_subject_sha256_for(
            &fixture.job_graph.binding,
            &[b"direct-child-count", job.id.as_bytes()],
        );
    }
    fixture.identity_clients.principal_count.subject_sha256 =
        count_subject_sha256_for(&fixture.identity_clients.binding, &[b"principal-count"]);
    fixture.identity_clients.acl_entry_count.subject_sha256 =
        count_subject_sha256_for(&fixture.identity_clients.binding, &[b"acl-count"]);
    fixture.identity_clients.client_count.subject_sha256 =
        count_subject_sha256_for(&fixture.identity_clients.binding, &[b"client-count"]);
    for job in &mut fixture.runtime_dependencies.jobs {
        job.dependency_count.subject_sha256 = count_subject_sha256_for(
            &fixture.runtime_dependencies.binding,
            &[b"runtime-dependency-count", job.job_id.as_bytes()],
        );
        job.dependency_set = owned_set_evidence(
            &format!("jenkins/job/{}/runtime-dependency-set", job.job_id),
            dependency_set_entries_for(
                &fixture.runtime_dependencies.binding,
                &job.job_id,
                &job.dependencies,
            ),
        );
    }
    for job in &mut fixture.persistent_state.jobs {
        job.record_class_count.subject_sha256 = count_subject_sha256_for(
            &fixture.persistent_state.binding,
            &[b"state-class-count", job.job_id.as_bytes()],
        );
        job.record_class_set = state_class_set_evidence_for(
            &fixture.persistent_state.binding,
            &job.job_id,
            &job.records,
        );
        for record in &mut job.records {
            record.record_count.subject_sha256 = count_subject_sha256_for(
                &fixture.persistent_state.binding,
                &[
                    b"state-record-instance-count",
                    job.job_id.as_bytes(),
                    record.id.as_bytes(),
                    record.kind.as_bytes(),
                ],
            );
        }
    }
    refresh_fixture_sets(fixture);
}

fn job_dependencies(job_id: &str, dependencies: Vec<RuntimeDependency>) -> JobDependencies {
    JobDependencies {
        job_id: job_id.to_owned(),
        dependency_count: count_evidence(
            dependencies.len() as u64,
            &format!("jenkins/job/{job_id}/runtime-dependency-count"),
            &[b"runtime-dependency-count", job_id.as_bytes()],
        ),
        dependency_set: owned_set_evidence(
            &format!("jenkins/job/{job_id}/runtime-dependency-set"),
            dependency_set_entries(job_id, &dependencies),
        ),
        dependencies,
    }
}

fn refresh_dependency_set(job: &mut JobDependencies) {
    job.dependency_set = owned_set_evidence(
        &format!("jenkins/job/{}/runtime-dependency-set", job.job_id),
        dependency_set_entries(&job.job_id, &job.dependencies),
    );
}

fn dependency_set_entries(job_id: &str, dependencies: &[RuntimeDependency]) -> Vec<Vec<Vec<u8>>> {
    dependency_set_entries_for(&binding(), job_id, dependencies)
}

fn dependency_set_entries_for(
    binding: &SnapshotBinding,
    job_id: &str,
    dependencies: &[RuntimeDependency],
) -> Vec<Vec<Vec<u8>>> {
    let mut entries = vec![set_subject_entry_for(
        binding,
        b"runtime-dependency-set",
        &[job_id.as_bytes()],
    )];
    entries.extend(dependencies.iter().map(|dependency| {
        vec![
            b"dependency-record-v1".to_vec(),
            job_id.as_bytes().to_vec(),
            dependency.id.as_bytes().to_vec(),
            serde_saphyr::to_string(dependency)
                .expect("serialize dependency commitment")
                .into_bytes(),
        ]
    }));
    entries
}

fn job_state_records(job_id: &str, records: Vec<StateRecord>) -> JobStateRecords {
    let record_class_count = count_evidence(
        records.len() as u64,
        &format!("jenkins/job/{job_id}/state-record-class-count"),
        &[b"state-class-count", job_id.as_bytes()],
    );
    let record_class_set = state_class_set_evidence(job_id, &records);
    JobStateRecords {
        job_id: job_id.to_owned(),
        record_class_count,
        record_class_set,
        records,
    }
}

fn refresh_state_class_set(job: &mut JobStateRecords) {
    job.record_class_set = state_class_set_evidence(&job.job_id, &job.records);
}

fn state_class_set_evidence(job_id: &str, records: &[StateRecord]) -> SetEvidence {
    state_class_set_evidence_for(&binding(), job_id, records)
}

fn state_class_set_evidence_for(
    binding: &SnapshotBinding,
    job_id: &str,
    records: &[StateRecord],
) -> SetEvidence {
    let mut entries = vec![set_subject_entry_for(
        binding,
        b"state-class-set",
        &[job_id.as_bytes()],
    )];
    entries.extend(records.iter().map(|record| {
        vec![
            b"state-record-v1".to_vec(),
            job_id.as_bytes().to_vec(),
            record.id.as_bytes().to_vec(),
            serde_saphyr::to_string(record)
                .expect("serialize state commitment")
                .into_bytes(),
        ]
    }));
    owned_set_evidence(
        &format!("jenkins/job/{job_id}/state-record-class-set"),
        entries,
    )
}

fn set_evidence(provenance: &str, entries: Vec<Vec<&[u8]>>) -> SetEvidence {
    SetEvidence {
        collector_id: "jenkins/set-api-v1".to_owned(),
        provenance: provenance.to_owned(),
        source_sha256: DIGEST_C.to_owned(),
        entries_sha256: canonical_entries_sha256(entries),
    }
}

fn owned_set_evidence(provenance: &str, entries: Vec<Vec<Vec<u8>>>) -> SetEvidence {
    SetEvidence {
        collector_id: "jenkins/set-api-v1".to_owned(),
        provenance: provenance.to_owned(),
        source_sha256: DIGEST_C.to_owned(),
        entries_sha256: canonical_owned_entries_sha256(entries),
    }
}

fn canonical_entries_sha256(mut entries: Vec<Vec<&[u8]>>) -> String {
    entries.sort();
    let mut canonical = Vec::new();
    for entry in entries {
        append_test_length_prefixed(&mut canonical, &(entry.len() as u64).to_be_bytes());
        for field in entry {
            append_test_length_prefixed(&mut canonical, field);
        }
    }
    format!("{:x}", Sha256::digest(canonical))
}

fn canonical_owned_entries_sha256(mut entries: Vec<Vec<Vec<u8>>>) -> String {
    entries.sort();
    let mut canonical = Vec::new();
    for entry in entries {
        append_test_length_prefixed(&mut canonical, &(entry.len() as u64).to_be_bytes());
        for field in entry {
            append_test_length_prefixed(&mut canonical, &field);
        }
    }
    format!("{:x}", Sha256::digest(canonical))
}

fn append_test_length_prefixed(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

fn set_subject_entry_for(
    binding: &SnapshotBinding,
    family: &[u8],
    owner_fields: &[&[u8]],
) -> Vec<Vec<u8>> {
    population_subject_entry(b"set-subject-v1", binding, family, owner_fields)
}

fn population_subject_entry(
    commitment_kind: &[u8],
    binding: &SnapshotBinding,
    family: &[u8],
    owner_fields: &[&[u8]],
) -> Vec<Vec<u8>> {
    let mut fields = vec![
        commitment_kind.to_vec(),
        family.to_vec(),
        b"snapshot-binding-v1".to_vec(),
        binding.schema.as_bytes().to_vec(),
        binding.controller_id.as_bytes().to_vec(),
        binding.controller_url.as_bytes().to_vec(),
        binding.controller_core_version.as_bytes().to_vec(),
        binding.plugin_profile_sha256.as_bytes().to_vec(),
        binding.global_config_sha256.as_bytes().to_vec(),
        binding.epoch_id.as_bytes().to_vec(),
        binding.source_generation.as_bytes().to_vec(),
        binding.collected_at.as_bytes().to_vec(),
        binding.exporter_id.as_bytes().to_vec(),
        binding.exporter_version.as_bytes().to_vec(),
        binding.exporter_sha256.as_bytes().to_vec(),
        binding.provenance.as_bytes().to_vec(),
    ];
    fields.extend(owner_fields.iter().map(|field| field.to_vec()));
    fields
}

fn count_subject_sha256(fields: &[&[u8]]) -> String {
    count_subject_sha256_for(&binding(), fields)
}

fn count_subject_sha256_for(binding: &SnapshotBinding, fields: &[&[u8]]) -> String {
    canonical_owned_entries_sha256(vec![population_subject_entry(
        b"count-subject-v1",
        binding,
        fields[0],
        &fields[1..],
    )])
}

fn state_transform(disposition: CompatibilityDisposition) -> StateTransformEvidence {
    StateTransformEvidence {
        mapping_id: "state/native-copy-v1".to_owned(),
        disposition,
        evidence_sha256: DIGEST_A.to_owned(),
        provenance: "contained/state-transform-certification".to_owned(),
    }
}

fn write_bundle(root: &Path, fixture: &Fixture) {
    write_yaml(root.join(JOB_GRAPH_FILE), &fixture.job_graph);
    write_yaml(root.join(IDENTITY_CLIENT_FILE), &fixture.identity_clients);
    write_yaml(
        root.join(RUNTIME_DEPENDENCY_FILE),
        &fixture.runtime_dependencies,
    );
    write_yaml(root.join(PERSISTENT_STATE_FILE), &fixture.persistent_state);
}

fn write_yaml(path: PathBuf, value: &impl Serialize) {
    let rendered = serde_saphyr::to_string(value).expect("serialize fixture");
    fs::write(path, rendered).expect("write fixture");
}
