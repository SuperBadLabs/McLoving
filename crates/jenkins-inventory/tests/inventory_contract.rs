use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use mcloving_jenkins_inventory::{
    AclEntry, ApprovedDisposition, ClientDirection, ClientRecord, CompatibilityDisposition,
    DependencyMutability, IDENTITY_CLIENT_FILE, IdentityClientManifest, JOB_GRAPH_FILE,
    JobDependencies, JobGraphManifest, JobRecord, JobStateRecords, LegalHold, OperationalState,
    PERSISTENT_STATE_FILE, PersistentStateManifest, Principal, PrincipalKind, PrincipalLifecycle,
    RUNTIME_DEPENDENCY_FILE, RuntimeDependency, RuntimeDependencyManifest, SCHEMA_VERSION,
    ScopeDisposition, SecurityRealm, SnapshotBinding, StateRecord, load_bundle, reconcile,
    seal_manifest_directory, validate_ledger_output_path, write_ledger,
};
use serde::Serialize;

const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DIGEST_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

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
    bundle.persistent_state.jobs[1].records.push(second);
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
    records[0].record_count = i64::MAX as u64;
    let mut second = records[0].clone();
    second.id = "state/folder/overflow".to_owned();
    records.push(second);
    let mut third = records[0].clone();
    third.id = "state/folder/overflow-final".to_owned();
    third.record_count = 2;
    records.push(third);
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
fn reconciliation_strictly_validates_the_derived_ledger() {
    let directory = TestDirectory::new("derived-ledger-limit");
    let mut bundle = fixture();
    let template = bundle.runtime_dependencies.jobs[1].dependencies[0].clone();
    for index in 0..256 {
        let mut dependency = template.clone();
        dependency.id = format!("runtime/extra-{index}");
        dependency.kind = format!("kind-{index}");
        dependency.confidentiality = "internal".to_owned();
        dependency.credential_reference = None;
        dependency.redaction_reference = None;
        bundle.runtime_dependencies.jobs[1]
            .dependencies
            .push(dependency);
    }
    write_bundle(&directory.0, &bundle);
    seal_manifest_directory(&directory.0).expect("seal inventory");

    let loaded = load_bundle(&directory.0).expect("load bundle");
    let error = reconcile(&loaded).expect_err("oversized derived ledger mapping must fail");
    assert_eq!(error.code, "INV_RENDER_STRICT");
}

#[test]
fn reconciliation_rejects_duplicate_acl_scope() {
    let directory = TestDirectory::new("duplicate-acl");
    let mut bundle = fixture();
    bundle
        .identity_clients
        .acl_entries
        .push(bundle.identity_clients.acl_entries[0].clone());
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
    Fixture {
        job_graph: JobGraphManifest {
            binding: binding.clone(),
            jobs: vec![
                job("folder", None, ScopeDisposition::InScope),
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
            principals: vec![
                Principal {
                    id: "user/operator".to_owned(),
                    kind: PrincipalKind::User,
                    aliases: vec!["operator-old".to_owned()],
                    groups: vec!["group/builders".to_owned()],
                    membership_generation: "membership-3".to_owned(),
                    lifecycle: PrincipalLifecycle::Active,
                    provenance: "jenkins/user/operator".to_owned(),
                },
                Principal {
                    id: "service/seed".to_owned(),
                    kind: PrincipalKind::Service,
                    aliases: Vec::new(),
                    groups: Vec::new(),
                    membership_generation: "service-1".to_owned(),
                    lifecycle: PrincipalLifecycle::Active,
                    provenance: "jenkins/service/seed".to_owned(),
                },
                Principal {
                    id: "group/builders".to_owned(),
                    kind: PrincipalKind::Group,
                    aliases: Vec::new(),
                    groups: Vec::new(),
                    membership_generation: "group-4".to_owned(),
                    lifecycle: PrincipalLifecycle::Active,
                    provenance: "jenkins/group/builders".to_owned(),
                },
            ],
            acl_entries: vec![AclEntry {
                job_id: "folder/build".to_owned(),
                principal_id: "user/operator".to_owned(),
                scope: "job".to_owned(),
                permissions: vec!["job/read".to_owned(), "job/build".to_owned()],
                generation: "acl-12".to_owned(),
            }],
            clients: vec![
                ClientRecord {
                    id: "dashboard".to_owned(),
                    direction: ClientDirection::Read,
                    caller_identity: "user/operator".to_owned(),
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
                    caller_identity: "service/seed".to_owned(),
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
                JobDependencies {
                    job_id: "folder".to_owned(),
                    dependencies: Vec::new(),
                },
                JobDependencies {
                    job_id: "folder/build".to_owned(),
                    dependencies: vec![RuntimeDependency {
                        id: "credential/source".to_owned(),
                        kind: "source-checkout".to_owned(),
                        owner: "ci-platform".to_owned(),
                        implementation_sha256: DIGEST_A.to_owned(),
                        config_sha256: DIGEST_B.to_owned(),
                        resource_scope: "repo/example".to_owned(),
                        mutability: DependencyMutability::PinnedRevision,
                        provenance: "jenkins/credentials/source".to_owned(),
                        confidentiality: "secret".to_owned(),
                        credential_reference: Some("protected-evidence/credential-7".to_owned()),
                        redaction_reference: None,
                        disposition: CompatibilityDisposition::Mappable,
                    }],
                },
            ],
        },
        persistent_state: PersistentStateManifest {
            binding,
            jobs: vec![
                JobStateRecords {
                    job_id: "folder".to_owned(),
                    records: Vec::new(),
                },
                JobStateRecords {
                    job_id: "folder/build".to_owned(),
                    records: vec![StateRecord {
                        id: "build-history".to_owned(),
                        kind: "build-number-and-result".to_owned(),
                        owner: "ci-platform".to_owned(),
                        record_count: 8,
                        source_sha256: DIGEST_C.to_owned(),
                        confidentiality: "internal".to_owned(),
                        restore_target: "jenkins/folder/build".to_owned(),
                        conflict_policy: "reject".to_owned(),
                        retention_deadline: "2027-07-30T00:00:00Z".to_owned(),
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
                },
            ],
        },
    }
}

fn add_excluded_obligations(fixture: &mut Fixture) {
    let mut dependency = fixture.runtime_dependencies.jobs[1].dependencies[0].clone();
    dependency.id = "credential/legacy".to_owned();
    dependency.provenance = "jenkins/credentials/legacy".to_owned();
    fixture.runtime_dependencies.jobs.push(JobDependencies {
        job_id: "legacy".to_owned(),
        dependencies: vec![dependency],
    });

    let mut state = fixture.persistent_state.jobs[1].records[0].clone();
    state.id = "legacy-history".to_owned();
    state.record_count = 13;
    state.restore_target = "retention-vault/legacy".to_owned();
    state.external_consumers.clear();
    state.provenance = "jenkins/build-history/legacy".to_owned();
    fixture.persistent_state.jobs.push(JobStateRecords {
        job_id: "legacy".to_owned(),
        records: vec![state],
    });
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
        triggers: vec!["manual".to_owned()],
        platforms: vec!["linux".to_owned()],
        agent_labels: vec!["linux".to_owned()],
        toolchains: vec!["jdk-21".to_owned()],
        node_authority: "trusted-linux".to_owned(),
        publishes_artifacts: true,
        publishes_tests: true,
        scope: ApprovedDisposition {
            disposition,
            approval: None,
        },
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
