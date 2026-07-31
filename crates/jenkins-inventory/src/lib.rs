//! Fail-closed Jenkins source inventory and reconciliation.
//!
//! The four inventory families are deliberately separate evidence producers.
//! Reconciliation accepts them only when their detached digests verify and all
//! four bind the same controller snapshot.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use mcloving_pipeline_ir::{ParseLimits, parse_strict};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

pub const SCHEMA_VERSION: &str = "mcloving.jenkins.inventory/v1";
pub const LEDGER_SCHEMA_VERSION: &str = "mcloving.jenkins.eligibility/v1";
pub const JOB_GRAPH_FILE: &str = "job-graph.yaml";
pub const IDENTITY_CLIENT_FILE: &str = "identity-clients.yaml";
pub const RUNTIME_DEPENDENCY_FILE: &str = "runtime-dependencies.yaml";
pub const PERSISTENT_STATE_FILE: &str = "persistent-state.yaml";
pub const CHECKSUM_FILE: &str = "SHA256SUMS";
pub const LEDGER_FILE: &str = "eligibility-ledger.yaml";

const MANIFEST_FILES: [&str; 4] = [
    JOB_GRAPH_FILE,
    IDENTITY_CLIENT_FILE,
    RUNTIME_DEPENDENCY_FILE,
    PERSISTENT_STATE_FILE,
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotBinding {
    pub schema: String,
    pub controller_id: String,
    pub controller_url: String,
    pub controller_core_version: String,
    pub plugin_profile_sha256: String,
    pub global_config_sha256: String,
    pub epoch_id: String,
    pub source_generation: String,
    pub collected_at: String,
    pub exporter_id: String,
    pub exporter_version: String,
    pub exporter_sha256: String,
    pub provenance: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScopeDisposition {
    InScope,
    Retired,
    OutOfScope,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedDisposition {
    pub disposition: ScopeDisposition,
    #[serde(default)]
    pub approval: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobGraphManifest {
    pub binding: SnapshotBinding,
    pub controller_job_count: CountEvidence,
    pub jobs: Vec<JobRecord>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CountEvidence {
    pub count: u64,
    pub collector_id: String,
    pub provenance: String,
    pub source_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobRecord {
    pub id: String,
    #[serde(default)]
    pub parent_id: Option<String>,
    pub kind: String,
    pub owner: String,
    pub canonical_source: String,
    pub source_sha256: String,
    pub config_sha256: String,
    pub definition_kind: String,
    pub operational_state: OperationalState,
    #[serde(default)]
    pub shared_library_refs: Vec<String>,
    #[serde(default)]
    pub triggers: Vec<String>,
    #[serde(default)]
    pub platforms: Vec<String>,
    #[serde(default)]
    pub agent_labels: Vec<String>,
    #[serde(default)]
    pub toolchains: Vec<String>,
    pub node_authority: String,
    pub publishes_artifacts: bool,
    pub publishes_tests: bool,
    pub direct_child_count: CountEvidence,
    pub scope: ApprovedDisposition,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalState {
    pub enabled: bool,
    pub generation: String,
    pub reason: String,
    pub actor: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityClientManifest {
    pub binding: SnapshotBinding,
    pub security_realm: SecurityRealm,
    pub principals: Vec<Principal>,
    pub acl_entries: Vec<AclEntry>,
    pub clients: Vec<ClientRecord>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityRealm {
    pub implementation: String,
    pub config_sha256: String,
    pub identity_provider_generation: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    pub id: String,
    pub kind: PrincipalKind,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub historical_names: Vec<HistoricalNameClaim>,
    #[serde(default)]
    pub groups: Vec<String>,
    pub membership_generation: String,
    pub lifecycle: PrincipalLifecycle,
    pub provenance: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrincipalKind {
    User,
    Service,
    Group,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrincipalLifecycle {
    Active,
    Disabled,
    Retired,
    Deleted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalNameClaim {
    pub name: String,
    pub generation: String,
    pub provenance: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AclEntry {
    pub job_id: String,
    pub principal_id: String,
    pub scope: String,
    pub permissions: Vec<String>,
    pub generation: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClientDirection {
    Read,
    Write,
    ReadWrite,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ClientCaller {
    Principal { principal_id: String },
    ObservedSource { source: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientRecord {
    pub id: String,
    pub direction: ClientDirection,
    pub caller: ClientCaller,
    pub authentication: String,
    pub endpoint: String,
    pub actions: Vec<String>,
    pub scope: String,
    pub owner: String,
    pub observed_use: String,
    pub generation: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeDependencyManifest {
    pub binding: SnapshotBinding,
    pub jobs: Vec<JobDependencies>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobDependencies {
    pub job_id: String,
    pub dependencies: Vec<RuntimeDependency>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompatibilityDisposition {
    Native,
    Mappable,
    Scripted,
    Unsupported,
    Unclassified,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DependencyMutability {
    Immutable,
    PinnedRevision,
    Mutable,
    Floating,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecretTaint {
    ConnectorOnly,
    ControllerOnly,
    SourceAcquisitionOnly,
    WorkloadVisible,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SecretConsumer {
    Connector {
        connector_id: String,
    },
    Controller {
        operation: String,
    },
    SourceAcquisition {
        checkout_id: String,
    },
    Workload {
        channel: WorkloadSecretChannel,
        target: String,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkloadSecretChannel {
    Argument,
    EnvironmentVariable,
    File,
    StandardInput,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecretConsumerEvidence {
    pub consumer: SecretConsumer,
    pub taint: SecretTaint,
    pub taint_path: Vec<String>,
    pub provenance: String,
    pub evidence_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeDependency {
    pub id: String,
    pub kind: String,
    pub owner: String,
    pub implementation_sha256: String,
    pub config_sha256: String,
    pub resource_scope: String,
    pub mutability: DependencyMutability,
    pub provenance: String,
    pub confidentiality: String,
    #[serde(default)]
    pub credential_reference: Option<String>,
    #[serde(default)]
    pub redaction_reference: Option<String>,
    #[serde(default)]
    pub secret_consumer: Option<SecretConsumerEvidence>,
    pub disposition: CompatibilityDisposition,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PersistentStateManifest {
    pub binding: SnapshotBinding,
    pub jobs: Vec<JobStateRecords>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobStateRecords {
    pub job_id: String,
    pub records: Vec<StateRecord>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StateRecord {
    pub id: String,
    pub kind: String,
    pub owner: String,
    pub record_count: u64,
    pub source_sha256: String,
    pub confidentiality: String,
    pub restore_target: String,
    pub conflict_policy: String,
    pub retention_policy_id: String,
    pub retention_policy_sha256: String,
    pub retention_deadline: String,
    pub forward_transform: StateTransformEvidence,
    pub rollback_transform: StateTransformEvidence,
    #[serde(default)]
    pub legal_holds: Vec<LegalHold>,
    #[serde(default)]
    pub external_consumers: Vec<String>,
    pub provenance: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StateTransformEvidence {
    pub mapping_id: String,
    pub disposition: CompatibilityDisposition,
    pub evidence_sha256: String,
    pub provenance: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LegalHold {
    pub id: String,
    pub scope: String,
    pub reason: String,
    pub generation: String,
    pub release_authority: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventoryBundle {
    pub job_graph: JobGraphManifest,
    pub identity_clients: IdentityClientManifest,
    pub runtime_dependencies: RuntimeDependencyManifest,
    pub persistent_state: PersistentStateManifest,
    pub file_digests: BTreeMap<String, String>,
    published_ledger: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EligibilityLedger {
    pub schema: String,
    pub binding: SnapshotBinding,
    pub manifest_sha256: BTreeMap<String, String>,
    pub population: PopulationCounts,
    pub jobs: Vec<JobEligibility>,
    pub parity_demands: BTreeMap<String, u64>,
    pub state_transform_records: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PopulationCounts {
    pub controllers: u64,
    pub jobs_total: u64,
    pub jobs_in_scope: u64,
    pub principals: u64,
    pub acl_entries: u64,
    pub read_clients: u64,
    pub write_clients: u64,
    pub runtime_dependencies: u64,
    pub persistent_record_classes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobEligibility {
    pub job_id: String,
    pub owner: String,
    pub operational_state: OperationalState,
    pub disposition: CompatibilityDisposition,
    pub runtime_dependency_ids: Vec<String>,
    pub persistent_state_ids: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventoryError {
    pub code: &'static str,
    pub message: String,
}

impl InventoryError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for InventoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for InventoryError {}

pub fn load_bundle(root: &Path) -> Result<InventoryBundle, InventoryError> {
    let allowed = MANIFEST_FILES
        .into_iter()
        .chain([CHECKSUM_FILE, LEDGER_FILE])
        .collect::<BTreeSet<_>>();
    validate_directory_entries(root, &allowed)?;
    let expected = load_checksums(root)?;
    let job_graph = load_manifest(root, JOB_GRAPH_FILE, &expected)?;
    let identity_clients = load_manifest(root, IDENTITY_CLIENT_FILE, &expected)?;
    let runtime_dependencies = load_manifest(root, RUNTIME_DEPENDENCY_FILE, &expected)?;
    let persistent_state = load_manifest(root, PERSISTENT_STATE_FILE, &expected)?;
    let ledger_path = root.join(LEDGER_FILE);
    let published_ledger = match fs::symlink_metadata(&ledger_path) {
        Ok(_) => Some(read_regular_file(&ledger_path)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(InventoryError::new(
                "INV_IO",
                format!("cannot inspect {}: {error}", ledger_path.display()),
            ));
        }
    };
    Ok(InventoryBundle {
        job_graph,
        identity_clients,
        runtime_dependencies,
        persistent_state,
        file_digests: expected,
        published_ledger,
    })
}

pub fn reconcile(bundle: &InventoryBundle) -> Result<EligibilityLedger, InventoryError> {
    validate_bindings(bundle)?;
    validate_binding(&bundle.job_graph.binding)?;
    validate_nonempty(
        "security-realm implementation",
        &bundle.identity_clients.security_realm.implementation,
    )?;
    validate_nonempty(
        "security-realm identity-provider generation",
        &bundle
            .identity_clients
            .security_realm
            .identity_provider_generation,
    )?;
    validate_digest(
        "security-realm configuration",
        &bundle.identity_clients.security_realm.config_sha256,
    )?;
    validate_count_evidence(
        "controller job count",
        &bundle.job_graph.controller_job_count,
        &bundle.job_graph.binding.exporter_id,
    )?;

    let mut job_ids = BTreeSet::new();
    let mut in_scope = BTreeSet::new();
    for job in &bundle.job_graph.jobs {
        validate_identifier("job", &job.id)?;
        validate_nonempty("job owner", &job.owner)?;
        validate_nonempty("job kind", &job.kind)?;
        validate_nonempty("job canonical source", &job.canonical_source)?;
        validate_nonempty("job definition kind", &job.definition_kind)?;
        validate_nonempty("job node authority", &job.node_authority)?;
        validate_nonempty(
            "job operational-state generation",
            &job.operational_state.generation,
        )?;
        validate_nonempty(
            "job operational-state reason",
            &job.operational_state.reason,
        )?;
        validate_nonempty("job operational-state actor", &job.operational_state.actor)?;
        for value in job
            .shared_library_refs
            .iter()
            .chain(&job.triggers)
            .chain(&job.platforms)
            .chain(&job.agent_labels)
            .chain(&job.toolchains)
        {
            validate_nonempty("job list value", value)?;
        }
        validate_digest("job source", &job.source_sha256)?;
        validate_digest("job configuration", &job.config_sha256)?;
        validate_count_evidence(
            "job direct-child count",
            &job.direct_child_count,
            &bundle.job_graph.binding.exporter_id,
        )?;
        if !job_ids.insert(job.id.clone()) {
            return Err(InventoryError::new(
                "INV_DUPLICATE_JOB",
                format!("job {} appears more than once", job.id),
            ));
        }
        if job.scope.disposition != ScopeDisposition::InScope
            && job
                .scope
                .approval
                .as_deref()
                .is_none_or(|approval| approval.trim().is_empty())
        {
            return Err(InventoryError::new(
                "INV_MISSING_APPROVAL",
                format!("job {} is excluded without owner approval", job.id),
            ));
        }
        if job.scope.disposition == ScopeDisposition::InScope {
            in_scope.insert(job.id.clone());
        }
    }
    if bundle.job_graph.controller_job_count.count != u64_count(job_ids.len())? {
        return Err(InventoryError::new(
            "INV_JOB_COUNT_MISMATCH",
            format!(
                "controller source reports {} jobs but the manifest contains {}",
                bundle.job_graph.controller_job_count.count,
                job_ids.len()
            ),
        ));
    }
    let mut direct_child_counts = BTreeMap::new();
    for job in &bundle.job_graph.jobs {
        if let Some(parent) = &job.parent_id {
            *direct_child_counts.entry(parent.as_str()).or_insert(0_u64) += 1;
        }
    }
    for job in &bundle.job_graph.jobs {
        if let Some(parent) = &job.parent_id
            && !job_ids.contains(parent)
        {
            return Err(InventoryError::new(
                "INV_UNKNOWN_PARENT",
                format!("job {} references unknown parent {parent}", job.id),
            ));
        }
        if job.scope.disposition == ScopeDisposition::InScope
            && let Some(parent) = &job.parent_id
            && !in_scope.contains(parent)
        {
            return Err(InventoryError::new(
                "INV_EXCLUDED_PARENT",
                format!("in-scope job {} has excluded parent {parent}", job.id),
            ));
        }
        let observed = direct_child_counts
            .get(job.id.as_str())
            .copied()
            .unwrap_or(0);
        if job.direct_child_count.count != observed {
            return Err(InventoryError::new(
                "INV_CHILD_COUNT_MISMATCH",
                format!(
                    "job {} source reports {} direct children but the manifest contains {observed}",
                    job.id, job.direct_child_count.count
                ),
            ));
        }
    }
    validate_job_graph_acyclic(&bundle.job_graph.jobs)?;
    if in_scope.is_empty() {
        return Err(InventoryError::new(
            "INV_EMPTY_POPULATION",
            "inventory contains no in-scope jobs",
        ));
    }

    let principal_ids = unique_ids(
        "principal",
        bundle
            .identity_clients
            .principals
            .iter()
            .map(|principal| principal.id.as_str()),
    )?;
    validate_principal_namespace(&bundle.identity_clients.principals)?;
    let principal_kinds = bundle
        .identity_clients
        .principals
        .iter()
        .map(|principal| (principal.id.as_str(), principal.kind))
        .collect::<BTreeMap<_, _>>();
    for principal in &bundle.identity_clients.principals {
        validate_nonempty(
            "principal membership generation",
            &principal.membership_generation,
        )?;
        validate_nonempty("principal provenance", &principal.provenance)?;
        for group in &principal.groups {
            match principal_kinds.get(group.as_str()) {
                Some(PrincipalKind::Group) => {}
                Some(_) => {
                    return Err(InventoryError::new(
                        "INV_GROUP_KIND",
                        format!(
                            "principal {} references non-group principal {group}",
                            principal.id
                        ),
                    ));
                }
                None => {
                    return Err(InventoryError::new(
                        "INV_UNKNOWN_GROUP",
                        format!(
                            "principal {} references unknown group {group}",
                            principal.id
                        ),
                    ));
                }
            }
        }
    }
    unique_ids(
        "client",
        bundle
            .identity_clients
            .clients
            .iter()
            .map(|client| client.id.as_str()),
    )?;
    for client in &bundle.identity_clients.clients {
        validate_nonempty("client owner", &client.owner)?;
        validate_nonempty("client authentication", &client.authentication)?;
        validate_nonempty("client endpoint", &client.endpoint)?;
        validate_nonempty("client scope", &client.scope)?;
        validate_nonempty("client observed use", &client.observed_use)?;
        validate_nonempty("client generation", &client.generation)?;
        validate_nonempty_collection("client action", &client.actions)?;
        match &client.caller {
            ClientCaller::Principal { principal_id } => {
                validate_identifier("client caller principal", principal_id)?;
                if !principal_ids.contains(principal_id) {
                    return Err(InventoryError::new(
                        "INV_UNKNOWN_CLIENT_PRINCIPAL",
                        format!(
                            "client {} references unknown principal {principal_id}",
                            client.id
                        ),
                    ));
                }
            }
            ClientCaller::ObservedSource { source } => {
                validate_nonempty("client observed caller source", source)?;
            }
        }
    }
    let client_directions = bundle
        .identity_clients
        .clients
        .iter()
        .map(|client| (client.id.clone(), client.direction))
        .collect::<BTreeMap<_, _>>();
    let mut acl_keys = BTreeSet::new();
    for acl in &bundle.identity_clients.acl_entries {
        validate_nonempty("ACL scope", &acl.scope)?;
        validate_nonempty("ACL generation", &acl.generation)?;
        validate_nonempty_collection("ACL permission", &acl.permissions)?;
        if !job_ids.contains(&acl.job_id) {
            return Err(InventoryError::new(
                "INV_UNKNOWN_ACL_JOB",
                format!("ACL references unknown job {}", acl.job_id),
            ));
        }
        if !principal_ids.contains(&acl.principal_id) {
            return Err(InventoryError::new(
                "INV_UNKNOWN_ACL_PRINCIPAL",
                format!("ACL references unknown principal {}", acl.principal_id),
            ));
        }
        if !acl_keys.insert((
            acl.job_id.as_str(),
            acl.principal_id.as_str(),
            acl.scope.as_str(),
        )) {
            return Err(InventoryError::new(
                "INV_DUPLICATE_ACL",
                format!(
                    "ACL for job {}, principal {}, scope {} appears more than once",
                    acl.job_id, acl.principal_id, acl.scope
                ),
            ));
        }
    }

    let runtime = index_runtime(&bundle.runtime_dependencies.jobs, &job_ids)?;
    let state = index_state(&bundle.persistent_state.jobs, &job_ids)?;
    if !in_scope.iter().all(|job_id| runtime.contains_key(job_id)) {
        return Err(InventoryError::new(
            "INV_RUNTIME_COVERAGE",
            "every in-scope job must have exactly one runtime-dependency record",
        ));
    }
    if !in_scope.iter().all(|job_id| state.contains_key(job_id)) {
        return Err(InventoryError::new(
            "INV_STATE_COVERAGE",
            "every in-scope job must have exactly one persistent-state record",
        ));
    }

    let mut runtime_dispositions = BTreeMap::new();
    for (job_id, dependencies) in &runtime {
        runtime_dispositions.insert(
            job_id.as_str(),
            validate_runtime_dependencies(job_id, dependencies)?,
        );
    }
    let mut state_dispositions = BTreeMap::new();
    let mut legal_hold_definitions = BTreeMap::new();
    let mut retention_policy_definitions = BTreeMap::new();
    for (job_id, records) in &state {
        state_dispositions.insert(
            job_id.as_str(),
            validate_state_records(
                job_id,
                records,
                &client_directions,
                &mut legal_hold_definitions,
                &mut retention_policy_definitions,
            )?,
        );
    }

    let mut parity_demands = BTreeMap::new();
    let mut jobs = Vec::new();
    let mut state_transform_records = 0_u64;
    for job in bundle
        .job_graph
        .jobs
        .iter()
        .filter(|job| job.scope.disposition == ScopeDisposition::InScope)
    {
        let dependencies = *runtime.get(&job.id).expect("coverage checked");
        let records = *state.get(&job.id).expect("coverage checked");
        let runtime_disposition = *runtime_dispositions
            .get(job.id.as_str())
            .expect("validated coverage");
        let state_disposition = *state_dispositions
            .get(job.id.as_str())
            .expect("validated coverage");
        let disposition = runtime_disposition.max(state_disposition);
        for dependency in dependencies {
            *parity_demands.entry(dependency.kind.clone()).or_insert(0) += 1;
        }
        for record in records {
            state_transform_records = state_transform_records
                .checked_add(record.record_count)
                .ok_or_else(|| {
                    InventoryError::new(
                        "INV_COUNT_OVERFLOW",
                        format!(
                            "state-record demand overflows u64 at record {} for job {}",
                            record.id, job.id
                        ),
                    )
                })?;
        }
        jobs.push(JobEligibility {
            job_id: job.id.clone(),
            owner: job.owner.clone(),
            operational_state: job.operational_state.clone(),
            disposition,
            runtime_dependency_ids: dependencies
                .iter()
                .map(|dependency| dependency.id.clone())
                .collect(),
            persistent_state_ids: records.iter().map(|record| record.id.clone()).collect(),
        });
    }
    jobs.sort_by(|left, right| left.job_id.cmp(&right.job_id));

    let read_clients = bundle
        .identity_clients
        .clients
        .iter()
        .filter(|client| {
            matches!(
                client.direction,
                ClientDirection::Read | ClientDirection::ReadWrite
            )
        })
        .count();
    let write_clients = bundle
        .identity_clients
        .clients
        .iter()
        .filter(|client| {
            matches!(
                client.direction,
                ClientDirection::Write | ClientDirection::ReadWrite
            )
        })
        .count();
    let runtime_dependencies = runtime.values().map(|records| records.len()).sum::<usize>();
    let persistent_record_classes = state.values().map(|records| records.len()).sum::<usize>();

    let ledger = EligibilityLedger {
        schema: LEDGER_SCHEMA_VERSION.to_owned(),
        binding: bundle.job_graph.binding.clone(),
        manifest_sha256: bundle.file_digests.clone(),
        population: PopulationCounts {
            controllers: 1,
            jobs_total: u64_count(job_ids.len())?,
            jobs_in_scope: u64_count(in_scope.len())?,
            principals: u64_count(principal_ids.len())?,
            acl_entries: u64_count(bundle.identity_clients.acl_entries.len())?,
            read_clients: u64_count(read_clients)?,
            write_clients: u64_count(write_clients)?,
            runtime_dependencies: u64_count(runtime_dependencies)?,
            persistent_record_classes: u64_count(persistent_record_classes)?,
        },
        jobs,
        parity_demands,
        state_transform_records,
    };
    let rendered = render_ledger(&ledger)?;
    if let Some(published) = &bundle.published_ledger
        && published.as_slice() != rendered.as_bytes()
    {
        return Err(InventoryError::new(
            "INV_LEDGER_MISMATCH",
            "published eligibility ledger does not match the reconciled source evidence",
        ));
    }
    Ok(ledger)
}

pub fn render_ledger(ledger: &EligibilityLedger) -> Result<String, InventoryError> {
    let rendered = serde_saphyr::to_string(ledger)
        .map_err(|error| InventoryError::new("INV_RENDER", error.to_string()))?;
    parse_strict(&rendered, inventory_limits())
        .map_err(|error| InventoryError::new("INV_RENDER_STRICT", error.to_string()))?;
    Ok(rendered)
}

pub fn seal_manifest_directory(root: &Path) -> Result<(), InventoryError> {
    let checksum_path = root.join(CHECKSUM_FILE);
    match fs::symlink_metadata(&checksum_path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(InventoryError::new(
                "INV_FILE_TYPE",
                format!("{} is a symbolic link", checksum_path.display()),
            ));
        }
        Ok(_) => {
            return Err(InventoryError::new(
                "INV_IMMUTABLE",
                format!("{} already exists", checksum_path.display()),
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(InventoryError::new(
                "INV_IO",
                format!("cannot inspect {}: {error}", checksum_path.display()),
            ));
        }
    }
    let allowed = MANIFEST_FILES.into_iter().collect::<BTreeSet<_>>();
    validate_directory_entries(root, &allowed)?;
    let mut lines = String::new();
    for filename in MANIFEST_FILES {
        let path = root.join(filename);
        let bytes = read_regular_file(&path)?;
        lines.push_str(&sha256_hex(&bytes));
        lines.push_str("  ");
        lines.push_str(filename);
        lines.push('\n');
    }
    write_new(&checksum_path, lines.as_bytes())
}

fn validate_directory_entries(root: &Path, allowed: &BTreeSet<&str>) -> Result<(), InventoryError> {
    for entry in fs::read_dir(root).map_err(|error| {
        InventoryError::new(
            "INV_IO",
            format!("cannot inspect {}: {error}", root.display()),
        )
    })? {
        let entry = entry.map_err(|error| {
            InventoryError::new(
                "INV_IO",
                format!("cannot inspect an entry in {}: {error}", root.display()),
            )
        })?;
        let filename = entry.file_name();
        let Some(filename) = filename.to_str() else {
            return Err(InventoryError::new(
                "INV_UNEXPECTED_ENTRY",
                format!("{} contains a non-UTF-8 entry", root.display()),
            ));
        };
        if !allowed.contains(filename) {
            return Err(InventoryError::new(
                "INV_UNEXPECTED_ENTRY",
                format!("{} contains unexpected entry {filename}", root.display()),
            ));
        }
    }
    Ok(())
}

pub fn write_ledger(output: &Path, ledger: &EligibilityLedger) -> Result<(), InventoryError> {
    if output.exists() {
        return Err(InventoryError::new(
            "INV_IMMUTABLE",
            format!("{} already exists", output.display()),
        ));
    }
    let rendered = render_ledger(ledger)?;
    write_new(output, rendered.as_bytes())
}

pub fn validate_ledger_output_path(root: &Path, output: &Path) -> Result<(), InventoryError> {
    let canonical_root = fs::canonicalize(root).map_err(|error| {
        InventoryError::new(
            "INV_OUTPUT_LAYOUT",
            format!("cannot resolve inventory root {}: {error}", root.display()),
        )
    })?;
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let canonical_parent = fs::canonicalize(parent).map_err(|error| {
        InventoryError::new(
            "INV_OUTPUT_LAYOUT",
            format!("cannot resolve output parent {}: {error}", parent.display()),
        )
    })?;
    if canonical_parent.starts_with(&canonical_root)
        && (canonical_parent != canonical_root
            || output.file_name().and_then(|name| name.to_str()) != Some(LEDGER_FILE))
    {
        return Err(InventoryError::new(
            "INV_OUTPUT_LAYOUT",
            format!(
                "the only ledger output permitted inside {} is {}",
                canonical_root.display(),
                LEDGER_FILE
            ),
        ));
    }
    Ok(())
}

fn load_manifest<T: DeserializeOwned>(
    root: &Path,
    filename: &str,
    expected: &BTreeMap<String, String>,
) -> Result<T, InventoryError> {
    let path = root.join(filename);
    let bytes = read_regular_file(&path)?;
    let digest = sha256_hex(&bytes);
    if expected.get(filename) != Some(&digest) {
        return Err(InventoryError::new(
            "INV_DIGEST_MISMATCH",
            format!("{filename} does not match {CHECKSUM_FILE}"),
        ));
    }
    let source = std::str::from_utf8(&bytes).map_err(|error| {
        InventoryError::new(
            "INV_UTF8",
            format!("{} is not UTF-8: {error}", path.display()),
        )
    })?;
    parse_strict(source, inventory_limits())
        .map_err(|error| InventoryError::new("INV_STRICT_YAML", error.to_string()))?;
    serde_saphyr::from_str(source)
        .map_err(|error| InventoryError::new("INV_SCHEMA", format!("{}: {error}", path.display())))
}

fn load_checksums(root: &Path) -> Result<BTreeMap<String, String>, InventoryError> {
    let path = root.join(CHECKSUM_FILE);
    let bytes = read_regular_file(&path)?;
    let source = std::str::from_utf8(&bytes).map_err(|error| {
        InventoryError::new(
            "INV_UTF8",
            format!("{} is not UTF-8: {error}", path.display()),
        )
    })?;
    let mut checksums = BTreeMap::new();
    for (line_number, line) in source.lines().enumerate() {
        let Some((digest, filename)) = line.split_once("  ") else {
            return Err(InventoryError::new(
                "INV_CHECKSUM_FORMAT",
                format!("{}:{} is malformed", path.display(), line_number + 1),
            ));
        };
        validate_digest("manifest", digest)?;
        if !MANIFEST_FILES.contains(&filename) {
            return Err(InventoryError::new(
                "INV_CHECKSUM_FILE",
                format!("unexpected manifest filename {filename}"),
            ));
        }
        if checksums
            .insert(filename.to_owned(), digest.to_owned())
            .is_some()
        {
            return Err(InventoryError::new(
                "INV_CHECKSUM_DUPLICATE",
                format!("duplicate checksum for {filename}"),
            ));
        }
    }
    if checksums.len() != MANIFEST_FILES.len() {
        return Err(InventoryError::new(
            "INV_CHECKSUM_COVERAGE",
            "checksum file must cover exactly the four inventory manifests",
        ));
    }
    Ok(checksums)
}

fn validate_bindings(bundle: &InventoryBundle) -> Result<(), InventoryError> {
    let expected = &bundle.job_graph.binding;
    for (family, binding) in [
        ("identity-clients", &bundle.identity_clients.binding),
        ("runtime-dependencies", &bundle.runtime_dependencies.binding),
        ("persistent-state", &bundle.persistent_state.binding),
    ] {
        if binding != expected {
            return Err(InventoryError::new(
                "INV_MIXED_EPOCH",
                format!("{family} does not bind the same controller snapshot"),
            ));
        }
    }
    Ok(())
}

fn validate_binding(binding: &SnapshotBinding) -> Result<(), InventoryError> {
    if binding.schema != SCHEMA_VERSION {
        return Err(InventoryError::new(
            "INV_SCHEMA_VERSION",
            format!("unsupported inventory schema {}", binding.schema),
        ));
    }
    for (name, value) in [
        ("controller id", &binding.controller_id),
        ("controller URL", &binding.controller_url),
        ("controller core version", &binding.controller_core_version),
        ("epoch id", &binding.epoch_id),
        ("source generation", &binding.source_generation),
        ("collection time", &binding.collected_at),
        ("exporter id", &binding.exporter_id),
        ("exporter version", &binding.exporter_version),
        ("provenance", &binding.provenance),
    ] {
        validate_nonempty(name, value)?;
    }
    validate_utc_timestamp("collection time", &binding.collected_at)?;
    validate_digest("plugin profile", &binding.plugin_profile_sha256)?;
    validate_digest("global configuration", &binding.global_config_sha256)?;
    validate_digest("exporter", &binding.exporter_sha256)
}

fn index_runtime<'a>(
    jobs: &'a [JobDependencies],
    known_jobs: &BTreeSet<String>,
) -> Result<BTreeMap<String, &'a [RuntimeDependency]>, InventoryError> {
    let mut indexed = BTreeMap::new();
    for job in jobs {
        if !known_jobs.contains(&job.job_id) {
            return Err(InventoryError::new(
                "INV_UNKNOWN_RUNTIME_JOB",
                format!("runtime inventory references unknown job {}", job.job_id),
            ));
        }
        if indexed
            .insert(job.job_id.clone(), job.dependencies.as_slice())
            .is_some()
        {
            return Err(InventoryError::new(
                "INV_DUPLICATE_RUNTIME_JOB",
                format!("runtime inventory repeats job {}", job.job_id),
            ));
        }
        unique_ids(
            "runtime dependency",
            job.dependencies
                .iter()
                .map(|dependency| dependency.id.as_str()),
        )?;
    }
    Ok(indexed)
}

fn index_state<'a>(
    jobs: &'a [JobStateRecords],
    known_jobs: &BTreeSet<String>,
) -> Result<BTreeMap<String, &'a [StateRecord]>, InventoryError> {
    let mut indexed = BTreeMap::new();
    for job in jobs {
        if !known_jobs.contains(&job.job_id) {
            return Err(InventoryError::new(
                "INV_UNKNOWN_STATE_JOB",
                format!("state inventory references unknown job {}", job.job_id),
            ));
        }
        if indexed
            .insert(job.job_id.clone(), job.records.as_slice())
            .is_some()
        {
            return Err(InventoryError::new(
                "INV_DUPLICATE_STATE_JOB",
                format!("state inventory repeats job {}", job.job_id),
            ));
        }
        unique_ids(
            "state record",
            job.records.iter().map(|record| record.id.as_str()),
        )?;
    }
    Ok(indexed)
}

fn validate_runtime_dependencies(
    job_id: &str,
    dependencies: &[RuntimeDependency],
) -> Result<CompatibilityDisposition, InventoryError> {
    let disposition = classify(dependencies)?;
    for dependency in dependencies {
        validate_nonempty("runtime dependency kind", &dependency.kind)?;
        validate_nonempty("runtime dependency owner", &dependency.owner)?;
        validate_nonempty(
            "runtime dependency resource scope",
            &dependency.resource_scope,
        )?;
        validate_nonempty("runtime dependency provenance", &dependency.provenance)?;
        if matches!(
            dependency.mutability,
            DependencyMutability::Mutable | DependencyMutability::Floating
        ) && dependency.disposition == CompatibilityDisposition::Native
        {
            return Err(InventoryError::new(
                "INV_MUTABLE_NATIVE",
                format!(
                    "mutable dependency {} for job {job_id} cannot be classified native",
                    dependency.id
                ),
            ));
        }
        validate_confidentiality(
            "runtime dependency confidentiality",
            &dependency.confidentiality,
        )?;
        if dependency.confidentiality == "secret"
            && ![
                dependency.credential_reference.as_deref(),
                dependency.redaction_reference.as_deref(),
            ]
            .into_iter()
            .flatten()
            .any(|reference| !reference.trim().is_empty())
        {
            return Err(InventoryError::new(
                "INV_SECRET_REFERENCE_REQUIRED",
                format!(
                    "secret dependency {} for job {job_id} has no typed reference",
                    dependency.id
                ),
            ));
        }
        let has_secret_reference = [
            dependency.credential_reference.as_deref(),
            dependency.redaction_reference.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(|reference| !reference.trim().is_empty());
        let has_secret_evidence = has_secret_reference || dependency.secret_consumer.is_some();
        if has_secret_evidence && dependency.confidentiality != "secret" {
            return Err(InventoryError::new(
                "INV_CREDENTIAL_CONFIDENTIALITY",
                format!(
                    "credential-bearing dependency {} for job {job_id} must be classified secret",
                    dependency.id
                ),
            ));
        }
        if (dependency.confidentiality == "secret" || has_secret_evidence)
            && dependency.secret_consumer.is_none()
        {
            return Err(InventoryError::new(
                "INV_SECRET_CONSUMER_REQUIRED",
                format!(
                    "secret dependency {} for job {job_id} has no typed consumer and taint evidence",
                    dependency.id
                ),
            ));
        }
        if let Some(consumer) = &dependency.secret_consumer {
            validate_secret_consumer(job_id, &dependency.id, consumer)?;
        }
        for reference in [
            dependency.credential_reference.as_deref(),
            dependency.redaction_reference.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_nonempty("runtime dependency typed reference", reference)?;
        }
        validate_digest(
            "runtime dependency implementation",
            &dependency.implementation_sha256,
        )?;
        validate_digest(
            "runtime dependency configuration",
            &dependency.config_sha256,
        )?;
    }
    Ok(disposition)
}

fn validate_secret_consumer(
    job_id: &str,
    dependency_id: &str,
    consumer: &SecretConsumerEvidence,
) -> Result<(), InventoryError> {
    let expected_taint = match &consumer.consumer {
        SecretConsumer::Connector { connector_id } => {
            validate_identifier("secret connector consumer", connector_id)?;
            SecretTaint::ConnectorOnly
        }
        SecretConsumer::Controller { operation } => {
            validate_nonempty("secret controller operation", operation)?;
            SecretTaint::ControllerOnly
        }
        SecretConsumer::SourceAcquisition { checkout_id } => {
            validate_identifier("secret source-acquisition consumer", checkout_id)?;
            SecretTaint::SourceAcquisitionOnly
        }
        SecretConsumer::Workload { target, .. } => {
            validate_nonempty("secret workload target", target)?;
            SecretTaint::WorkloadVisible
        }
    };
    if consumer.taint != expected_taint {
        return Err(InventoryError::new(
            "INV_SECRET_TAINT_MISMATCH",
            format!(
                "secret dependency {dependency_id} for job {job_id} has a taint inconsistent with its consumer"
            ),
        ));
    }
    validate_nonempty_collection("secret taint path", &consumer.taint_path)?;
    validate_nonempty("secret consumer provenance", &consumer.provenance)?;
    validate_digest("secret consumer evidence", &consumer.evidence_sha256)
}

fn validate_state_records(
    job_id: &str,
    records: &[StateRecord],
    client_directions: &BTreeMap<String, ClientDirection>,
    legal_hold_definitions: &mut BTreeMap<String, LegalHold>,
    retention_policy_definitions: &mut BTreeMap<String, String>,
) -> Result<CompatibilityDisposition, InventoryError> {
    let mut disposition = CompatibilityDisposition::Native;
    for record in records {
        validate_nonempty("state kind", &record.kind)?;
        validate_nonempty("state owner", &record.owner)?;
        validate_confidentiality("state confidentiality", &record.confidentiality)?;
        validate_nonempty("state restore target", &record.restore_target)?;
        validate_nonempty("state conflict policy", &record.conflict_policy)?;
        validate_identifier("state retention policy", &record.retention_policy_id)?;
        validate_digest("state retention policy", &record.retention_policy_sha256)?;
        if let Some(existing) = retention_policy_definitions.get(&record.retention_policy_id) {
            if existing != &record.retention_policy_sha256 {
                return Err(InventoryError::new(
                    "INV_RETENTION_POLICY_CONFLICT",
                    format!(
                        "retention policy {} has conflicting digests across state records",
                        record.retention_policy_id
                    ),
                ));
            }
        } else {
            retention_policy_definitions.insert(
                record.retention_policy_id.clone(),
                record.retention_policy_sha256.clone(),
            );
        }
        validate_utc_timestamp("state retention deadline", &record.retention_deadline)?;
        disposition = disposition.max(validate_state_transform(
            job_id,
            &record.id,
            "forward",
            &record.forward_transform,
        )?);
        disposition = disposition.max(validate_state_transform(
            job_id,
            &record.id,
            "rollback",
            &record.rollback_transform,
        )?);
        validate_nonempty("state provenance", &record.provenance)?;
        validate_digest("state source", &record.source_sha256)?;
        for consumer in &record.external_consumers {
            match client_directions.get(consumer) {
                Some(ClientDirection::Read | ClientDirection::ReadWrite) => {}
                Some(ClientDirection::Write) => {
                    return Err(InventoryError::new(
                        "INV_STATE_CONSUMER_DIRECTION",
                        format!(
                            "state record {} for job {job_id} references write-only client {consumer}",
                            record.id
                        ),
                    ));
                }
                None => {
                    return Err(InventoryError::new(
                        "INV_UNKNOWN_STATE_CONSUMER",
                        format!(
                            "state record {} for job {job_id} references unknown client {consumer}",
                            record.id
                        ),
                    ));
                }
            }
        }
        let mut hold_ids = BTreeSet::new();
        for hold in &record.legal_holds {
            validate_identifier("legal hold", &hold.id)?;
            if !hold_ids.insert(&hold.id) {
                return Err(InventoryError::new(
                    "INV_DUPLICATE_HOLD",
                    format!(
                        "state record {} for job {job_id} repeats legal hold {}",
                        record.id, hold.id
                    ),
                ));
            }
            validate_nonempty("legal-hold scope", &hold.scope)?;
            validate_nonempty("legal-hold reason", &hold.reason)?;
            validate_nonempty("legal-hold generation", &hold.generation)?;
            validate_nonempty("legal-hold release authority", &hold.release_authority)?;
            if let Some(existing) = legal_hold_definitions.get(&hold.id) {
                if existing != hold {
                    return Err(InventoryError::new(
                        "INV_HOLD_CONFLICT",
                        format!(
                            "legal hold {} has conflicting definitions across state records",
                            hold.id
                        ),
                    ));
                }
            } else {
                legal_hold_definitions.insert(hold.id.clone(), hold.clone());
            }
        }
    }
    Ok(disposition)
}

fn validate_state_transform(
    job_id: &str,
    record_id: &str,
    direction: &str,
    transform: &StateTransformEvidence,
) -> Result<CompatibilityDisposition, InventoryError> {
    validate_identifier("state transform mapping", &transform.mapping_id)?;
    validate_nonempty("state transform provenance", &transform.provenance)?;
    validate_digest("state transform evidence", &transform.evidence_sha256)?;
    if transform.disposition == CompatibilityDisposition::Unclassified {
        return Err(InventoryError::new(
            "INV_STATE_UNCLASSIFIED",
            format!(
                "{direction} transform for state record {record_id} in job {job_id} is unclassified"
            ),
        ));
    }
    Ok(transform.disposition)
}

fn classify(
    dependencies: &[RuntimeDependency],
) -> Result<CompatibilityDisposition, InventoryError> {
    let mut disposition = CompatibilityDisposition::Native;
    for dependency in dependencies {
        if dependency.disposition == CompatibilityDisposition::Unclassified {
            return Err(InventoryError::new(
                "INV_UNCLASSIFIED",
                format!("runtime dependency {} is unclassified", dependency.id),
            ));
        }
        disposition = disposition.max(dependency.disposition);
    }
    Ok(disposition)
}

fn unique_ids<'a>(
    kind: &str,
    values: impl Iterator<Item = &'a str>,
) -> Result<BTreeSet<String>, InventoryError> {
    let mut unique = BTreeSet::new();
    for value in values {
        validate_identifier(kind, value)?;
        if !unique.insert(value.to_owned()) {
            return Err(InventoryError::new(
                "INV_DUPLICATE_ID",
                format!("{kind} {value} appears more than once"),
            ));
        }
    }
    Ok(unique)
}

fn validate_count_evidence(
    kind: &str,
    evidence: &CountEvidence,
    manifest_exporter_id: &str,
) -> Result<(), InventoryError> {
    validate_identifier(&format!("{kind} collector"), &evidence.collector_id)?;
    if evidence.collector_id == manifest_exporter_id {
        return Err(InventoryError::new(
            "INV_COUNT_NOT_INDEPENDENT",
            format!("{kind} must use a collector distinct from the manifest exporter"),
        ));
    }
    validate_nonempty(&format!("{kind} provenance"), &evidence.provenance)?;
    validate_digest(&format!("{kind} source"), &evidence.source_sha256)
}

fn validate_identifier(kind: &str, value: &str) -> Result<(), InventoryError> {
    validate_nonempty(kind, value)?;
    if value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'))
    {
        return Err(InventoryError::new(
            "INV_IDENTIFIER",
            format!("{kind} identifier {value:?} is invalid"),
        ));
    }
    Ok(())
}

fn validate_nonempty(name: &str, value: &str) -> Result<(), InventoryError> {
    if value.trim().is_empty() {
        return Err(InventoryError::new(
            "INV_REQUIRED",
            format!("{name} must not be empty"),
        ));
    }
    Ok(())
}

fn validate_utc_timestamp(name: &str, value: &str) -> Result<(), InventoryError> {
    let bytes = value.as_bytes();
    let shape_is_valid = bytes.len() == 20
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[19] == b'Z'
        && bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19) || byte.is_ascii_digit()
        });
    if !shape_is_valid {
        return Err(InventoryError::new(
            "INV_TIMESTAMP",
            format!("{name} must be an exact UTC timestamp YYYY-MM-DDTHH:MM:SSZ"),
        ));
    }

    let year = decimal(bytes, 0, 4);
    let month = decimal(bytes, 5, 7);
    let day = decimal(bytes, 8, 10);
    let hour = decimal(bytes, 11, 13);
    let minute = decimal(bytes, 14, 16);
    let second = decimal(bytes, 17, 19);
    let leap_year =
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let maximum_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year => 29,
        2 => 28,
        _ => 0,
    };
    if year == 0 || day == 0 || day > maximum_day || hour > 23 || minute > 59 || second > 59 {
        return Err(InventoryError::new(
            "INV_TIMESTAMP",
            format!("{name} is not a valid UTC calendar timestamp"),
        ));
    }
    Ok(())
}

fn decimal(bytes: &[u8], start: usize, end: usize) -> u32 {
    bytes[start..end]
        .iter()
        .fold(0_u32, |value, byte| value * 10 + u32::from(byte - b'0'))
}

fn validate_nonempty_collection(name: &str, values: &[String]) -> Result<(), InventoryError> {
    if values.is_empty() {
        return Err(InventoryError::new(
            "INV_REQUIRED",
            format!("{name} collection must not be empty"),
        ));
    }
    let mut unique = BTreeSet::new();
    for value in values {
        validate_nonempty(name, value)?;
        if !unique.insert(value) {
            return Err(InventoryError::new(
                "INV_DUPLICATE_VALUE",
                format!("{name} {value:?} appears more than once"),
            ));
        }
    }
    Ok(())
}

fn validate_digest(name: &str, value: &str) -> Result<(), InventoryError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(InventoryError::new(
            "INV_DIGEST",
            format!("{name} digest must be 64 lowercase hexadecimal characters"),
        ));
    }
    Ok(())
}

fn validate_job_graph_acyclic(jobs: &[JobRecord]) -> Result<(), InventoryError> {
    let parents = jobs
        .iter()
        .map(|job| (job.id.as_str(), job.parent_id.as_deref()))
        .collect::<BTreeMap<_, _>>();
    let mut complete = BTreeSet::new();

    for start in parents.keys().copied() {
        if complete.contains(start) {
            continue;
        }
        let mut path = Vec::new();
        let mut positions = BTreeMap::new();
        let mut current = Some(start);
        while let Some(job_id) = current {
            if complete.contains(job_id) {
                break;
            }
            if let Some(position) = positions.insert(job_id, path.len()) {
                let mut cycle = path[position..].to_vec();
                cycle.push(job_id);
                return Err(InventoryError::new(
                    "INV_JOB_GRAPH_CYCLE",
                    format!("job parent graph contains cycle {}", cycle.join(" -> ")),
                ));
            }
            path.push(job_id);
            current = parents.get(job_id).copied().flatten();
        }
        complete.extend(path);
    }
    Ok(())
}

fn validate_principal_namespace(principals: &[Principal]) -> Result<(), InventoryError> {
    let mut names = BTreeMap::new();
    let mut historical_names = BTreeMap::new();
    for principal in principals {
        for name in std::iter::once(principal.id.as_str())
            .chain(principal.aliases.iter().map(String::as_str))
        {
            validate_identifier("principal name", name)?;
            if let Some(existing) = names.insert(name, principal.id.as_str()) {
                return Err(InventoryError::new(
                    "INV_PRINCIPAL_NAME_COLLISION",
                    format!(
                        "principal name {name} is claimed by both {existing} and {}",
                        principal.id
                    ),
                ));
            }
        }
        for claim in &principal.historical_names {
            validate_identifier("historical principal name", &claim.name)?;
            validate_nonempty("historical-name generation", &claim.generation)?;
            validate_nonempty("historical-name provenance", &claim.provenance)?;
            let key = (claim.name.as_str(), claim.generation.as_str());
            if let Some(existing) = historical_names.insert(key, principal.id.as_str()) {
                return Err(InventoryError::new(
                    "INV_HISTORICAL_NAME_CONFLICT",
                    format!(
                        "historical principal name {} at generation {} is claimed by both {existing} and {}",
                        claim.name, claim.generation, principal.id
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn validate_confidentiality(name: &str, value: &str) -> Result<(), InventoryError> {
    if !matches!(value, "public" | "internal" | "confidential" | "secret") {
        return Err(InventoryError::new(
            "INV_CONFIDENTIALITY",
            format!("{name} {value:?} is not a supported label"),
        ));
    }
    Ok(())
}

fn inventory_limits() -> ParseLimits {
    ParseLimits {
        max_source_bytes: 16 * 1024 * 1024,
        max_nodes: 250_000,
        max_depth: 32,
        max_scalar_bytes: 256 * 1024,
        max_mapping_entries: 256,
        max_sequence_items: 100_000,
    }
}

fn read_regular_file(path: &Path) -> Result<Vec<u8>, InventoryError> {
    use std::io::Read;

    let path_metadata = fs::symlink_metadata(path).map_err(|error| {
        InventoryError::new(
            "INV_READ",
            format!("failed to inspect {}: {error}", path.display()),
        )
    })?;
    if !path_metadata.file_type().is_file() {
        return Err(InventoryError::new(
            "INV_FILE_TYPE",
            format!("{} is not a regular file", path.display()),
        ));
    }

    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(|error| {
        InventoryError::new(
            "INV_READ",
            format!("failed to read {}: {error}", path.display()),
        )
    })?;
    let metadata = file.metadata().map_err(|error| {
        InventoryError::new(
            "INV_READ",
            format!("failed to inspect open file {}: {error}", path.display()),
        )
    })?;
    if !metadata.file_type().is_file() {
        return Err(InventoryError::new(
            "INV_FILE_TYPE",
            format!("{} is not a regular file", path.display()),
        ));
    }

    let max_bytes = inventory_limits().max_source_bytes;
    let max_bytes_u64 = u64::try_from(max_bytes)
        .map_err(|_| InventoryError::new("INV_SIZE_LIMIT", "source limit exceeds u64"))?;
    if metadata.len() > max_bytes_u64 {
        return Err(InventoryError::new(
            "INV_FILE_TOO_LARGE",
            format!(
                "{} is {} bytes; the limit is {max_bytes}",
                path.display(),
                metadata.len()
            ),
        ));
    }

    let capacity = usize::try_from(metadata.len()).unwrap_or(max_bytes);
    let mut bytes = Vec::with_capacity(capacity.min(max_bytes));
    file.take(max_bytes_u64.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| {
            InventoryError::new(
                "INV_READ",
                format!("failed to read {}: {error}", path.display()),
            )
        })?;
    if bytes.len() > max_bytes {
        return Err(InventoryError::new(
            "INV_FILE_TOO_LARGE",
            format!("{} exceeds the {max_bytes}-byte limit", path.display()),
        ));
    }
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), InventoryError> {
    use std::io::Write;

    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(InventoryError::new(
                "INV_FILE_TYPE",
                format!("{} is a symbolic link", path.display()),
            ));
        }
        Ok(_) => {
            return Err(InventoryError::new(
                "INV_IMMUTABLE",
                format!("{} already exists", path.display()),
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(InventoryError::new(
                "INV_WRITE",
                format!("failed to inspect {}: {error}", path.display()),
            ));
        }
    }

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).map_err(|error| {
        InventoryError::new(
            "INV_WRITE",
            format!("failed to create {}: {error}", path.display()),
        )
    })?;
    let metadata = match file.metadata() {
        Ok(metadata) => metadata,
        Err(error) => {
            drop(file);
            let _ = fs::remove_file(path);
            return Err(InventoryError::new(
                "INV_WRITE",
                format!("failed to inspect created file {}: {error}", path.display()),
            ));
        }
    };
    if !metadata.file_type().is_file() {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(InventoryError::new(
            "INV_FILE_TYPE",
            format!("{} is not a regular file", path.display()),
        ));
    }
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(InventoryError::new(
            "INV_WRITE",
            format!("failed to write {}: {error}", path.display()),
        ));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut rendered = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        write!(&mut rendered, "{byte:02x}").expect("writing into String cannot fail");
    }
    rendered
}

fn u64_count(count: usize) -> Result<u64, InventoryError> {
    u64::try_from(count)
        .map_err(|_| InventoryError::new("INV_COUNT_OVERFLOW", "inventory count exceeds u64"))
}

pub fn inventory_paths(root: &Path) -> [PathBuf; 4] {
    MANIFEST_FILES.map(|filename| root.join(filename))
}
