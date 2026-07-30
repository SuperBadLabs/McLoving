use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use mcloving_jenkins_inventory::{
    AclEntry, ApprovedDisposition, ClientDirection, ClientRecord, CompatibilityDisposition,
    IDENTITY_CLIENT_FILE, IdentityClientManifest, JOB_GRAPH_FILE, JobDependencies,
    JobGraphManifest, JobRecord, JobStateRecords, LegalHold, OperationalState,
    PERSISTENT_STATE_FILE, PersistentStateManifest, Principal, RUNTIME_DEPENDENCY_FILE,
    RuntimeDependency, RuntimeDependencyManifest, SCHEMA_VERSION, ScopeDisposition, SecurityRealm,
    SnapshotBinding, StateRecord, load_bundle, reconcile, seal_manifest_directory, write_ledger,
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
                    kind: "user".to_owned(),
                    aliases: vec!["operator-old".to_owned()],
                    groups: vec!["group/builders".to_owned()],
                    membership_generation: "membership-3".to_owned(),
                    lifecycle: "active".to_owned(),
                    provenance: "jenkins/user/operator".to_owned(),
                },
                Principal {
                    id: "service/seed".to_owned(),
                    kind: "service".to_owned(),
                    aliases: Vec::new(),
                    groups: Vec::new(),
                    membership_generation: "service-1".to_owned(),
                    lifecycle: "active".to_owned(),
                    provenance: "jenkins/service/seed".to_owned(),
                },
                Principal {
                    id: "group/builders".to_owned(),
                    kind: "group".to_owned(),
                    aliases: Vec::new(),
                    groups: Vec::new(),
                    membership_generation: "group-4".to_owned(),
                    lifecycle: "active".to_owned(),
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
                        mutability: "pinned-revision".to_owned(),
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
