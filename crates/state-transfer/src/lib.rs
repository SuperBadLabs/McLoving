//! Deterministic, lossless Jenkins/McLoving persistent-state transforms.
//!
//! The transfer boundary is deliberately pure. It validates an immutable source
//! export against an independently pinned binding, merges only stronger
//! destination protections, and returns canonical bytes plus a verification
//! digest. Persistence and execution authority remain separate concerns.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const STATE_TRANSFER_SCHEMA_V1: &str = "mcloving.state-transfer/v1";
pub const MAX_TRANSFER_JOBS: usize = 10_000;
pub const MAX_TRANSFER_RECORDS: usize = 1_000_000;
pub const MAX_CANONICAL_BUNDLE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_FILESYSTEM_ENTRIES_PER_OBJECT: usize = 1_000_000;
pub const MAX_FILESYSTEM_PATH_BYTES: usize = 4_096;
pub type Digest = [u8; 32];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferDirection {
    JenkinsToMcLoving,
    McLovingToJenkins,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictPolicy {
    RejectDivergence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SystemIdentity {
    pub kind: String,
    pub instance_id: String,
    pub generation: String,
    pub configuration_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransferBinding {
    pub schema: String,
    pub direction: TransferDirection,
    pub source: SystemIdentity,
    pub destination: SystemIdentity,
    pub source_export_digest: Digest,
    pub transform_implementation_digest: Digest,
    pub transform_configuration_digest: Digest,
    pub conflict_policy: ConflictPolicy,
    pub provenance: String,
}

/// Independently pinned identities required before source bytes are trusted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedBinding {
    pub direction: TransferDirection,
    pub source: SystemIdentity,
    pub destination: SystemIdentity,
    pub source_export_digest: Digest,
    pub transform_implementation_digest: Digest,
    pub transform_configuration_digest: Digest,
    pub conflict_policy: ConflictPolicy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecordProvenance {
    pub id: String,
    pub source_digest: Digest,
    pub provenance: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildResult {
    Succeeded,
    Failed,
    Aborted,
    Unstable,
    NotBuilt,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RetentionPolicy {
    pub policy_id: String,
    pub policy_version: String,
    pub policy_digest: Digest,
    pub retain_until_unix_ms: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LegalHold {
    pub record: RecordProvenance,
    pub hold_id: String,
    pub scope: String,
    pub reason: String,
    pub placed_at_unix_ms: i64,
    pub generation: u64,
    pub release_authority: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Protection {
    pub retention: RetentionPolicy,
    /// Only active holds cross the boundary. A transfer can never release one.
    pub active_holds: Vec<LegalHold>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChangeEntry {
    pub record: RecordProvenance,
    pub commit: String,
    pub author: String,
    pub message_digest: Digest,
    pub paths: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScmState {
    pub record: RecordProvenance,
    pub provider: String,
    pub repository: String,
    pub reference: String,
    pub revision: String,
    pub previous_revision: Option<String>,
    pub changes: Vec<ChangeEntry>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    Artifact,
    RetainedWorkspace,
    PersistentState,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClassification {
    Public,
    Internal,
    Confidential,
    SecretMaterial,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SecretReference {
    pub provider: String,
    pub reference: String,
    pub version: String,
    pub keyed_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HeldEvidence {
    pub custodian: String,
    pub reference: String,
    pub content_digest: Digest,
    pub release_authority: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SecretDisposition {
    Reference(SecretReference),
    HeldEvidence(HeldEvidence),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DataBinding {
    pub classification: DataClassification,
    pub secret_disposition: Option<SecretDisposition>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemEntryKind {
    Directory,
    RegularFile,
}

/// A canonical, non-following filesystem inventory. Symlinks, hard links,
/// devices, sockets and FIFOs are intentionally not representable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FilesystemEntry {
    pub path: String,
    pub kind: FilesystemEntryKind,
    pub content_digest: Option<Digest>,
    pub bytes: u64,
    pub data_binding: DataBinding,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObjectState {
    pub record: RecordProvenance,
    pub kind: ObjectKind,
    pub logical_name: String,
    pub content_digest: Digest,
    pub bytes: u64,
    pub producer_build_number: Option<u64>,
    pub retrieval: RetrievalMetadata,
    pub data_binding: DataBinding,
    pub filesystem_entries: Vec<FilesystemEntry>,
    pub protection: Protection,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PersistentDependency {
    pub record: RecordProvenance,
    pub key: String,
    pub value_digest: Digest,
    pub data_binding: DataBinding,
    pub protection: Protection,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RetrievalMetadata {
    pub media_type: String,
    pub logical_locator: String,
    pub content_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TriggerCause {
    pub record: RecordProvenance,
    pub trigger_kind: String,
    pub external_id: String,
    pub actor_subject: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvocationParameter {
    pub record: RecordProvenance,
    pub name: String,
    pub type_name: String,
    pub public_value_digest: Option<Digest>,
    pub data_binding: DataBinding,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttemptState {
    pub record: RecordProvenance,
    pub ordinal: u32,
    pub result: BuildResult,
    pub started_at_unix_ms: i64,
    pub ended_at_unix_ms: i64,
    pub audit_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GraphNodeState {
    pub record: RecordProvenance,
    pub node_id: String,
    pub stage_path: String,
    pub node_kind: String,
    pub parent_node_ids: Vec<String>,
    pub result: BuildResult,
    pub attempts: Vec<AttemptState>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ApprovalState {
    pub record: RecordProvenance,
    pub approval_id: String,
    pub policy_digest: Digest,
    pub approver_subject: String,
    pub submitted_value_digests: BTreeMap<String, Digest>,
    pub decided_at_unix_ms: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NormalizedTestState {
    pub record: RecordProvenance,
    pub suite: String,
    pub name: String,
    pub status: String,
    pub duration_ms: u64,
    pub details_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LogState {
    pub record: RecordProvenance,
    pub sequence: u64,
    pub content_digest: Digest,
    pub bytes: u64,
    pub data_binding: DataBinding,
    pub retrieval: RetrievalMetadata,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BuildState {
    pub record: RecordProvenance,
    pub source_queue_id: String,
    pub source_build_id: String,
    pub trigger: TriggerCause,
    pub invocation_parameters: Vec<InvocationParameter>,
    pub number: u64,
    pub result: BuildResult,
    pub queued_at_unix_ms: i64,
    pub started_at_unix_ms: i64,
    pub ended_at_unix_ms: i64,
    pub checkouts: Vec<ScmState>,
    pub graph_nodes: Vec<GraphNodeState>,
    pub approvals: Vec<ApprovalState>,
    pub normalized_tests: Vec<NormalizedTestState>,
    pub logs: Vec<LogState>,
    pub artifacts: Vec<ObjectState>,
    pub protection: Protection,
    pub audit_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JobState {
    pub record: RecordProvenance,
    pub source_job_id: String,
    pub target_pipeline_id: String,
    pub next_build_number: u64,
    pub previous_result: Option<BuildResult>,
    pub builds: Vec<BuildState>,
    pub retained_workspaces: Vec<ObjectState>,
    pub persistent_dependencies: Vec<PersistentDependency>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StateBundle {
    pub binding: TransferBinding,
    /// Complete record denominator from the immutable source export.
    pub expected_record_ids: Vec<String>,
    pub jobs: Vec<JobState>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferPlan {
    pub bundle: StateBundle,
    pub binding_digest: Digest,
    pub bundle_digest: Digest,
    pub canonical_bytes: Vec<u8>,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum TransferError {
    #[error("unsupported state-transfer schema {0}")]
    UnsupportedSchema(String),
    #[error("state-transfer binding mismatch: {0}")]
    BindingMismatch(&'static str),
    #[error("invalid state-transfer field {0}")]
    InvalidField(String),
    #[error("duplicate state-transfer record {0}")]
    DuplicateRecord(String),
    #[error("missing state-transfer records: {0:?}")]
    MissingRecords(Vec<String>),
    #[error("unexpected state-transfer records: {0:?}")]
    UnexpectedRecords(Vec<String>),
    #[error("duplicate state-transfer job identity {0}")]
    DuplicateJob(String),
    #[error("build sequence gap for job {job}: expected {expected}, found {found}")]
    BuildGap {
        job: String,
        expected: u64,
        found: u64,
    },
    #[error("previous-result mismatch for job {0}")]
    PreviousResultMismatch(String),
    #[error("SCM baseline mismatch for job {job} build {build}")]
    ScmBaselineMismatch { job: String, build: u64 },
    #[error("divergent active legal hold {0}")]
    DivergentHold(String),
    #[error("equal retention deadline has divergent policy for subject {0:?}")]
    DivergentRetention(Digest),
    #[error("canonical state serialization failed: {0}")]
    Serialization(String),
}

/// Validates and transforms one immutable bundle.
///
/// `existing_protections` is keyed by the protected record's source digest.
/// Retention is merged monotonically and active holds are unioned. The same
/// inputs always produce byte-identical output.
pub fn transform(
    bundle: &StateBundle,
    expected: &ExpectedBinding,
    existing_protections: &BTreeMap<Digest, Protection>,
) -> Result<TransferPlan, TransferError> {
    validate_bundle(bundle, expected)?;
    for (subject, protection) in existing_protections {
        validate_digest(*subject, "existing protection subject digest")?;
        validate_protection(protection)?;
    }

    let mut transformed = bundle.clone();
    for job in &mut transformed.jobs {
        for build in &mut job.builds {
            merge_existing(
                build.record.source_digest,
                &mut build.protection,
                existing_protections,
            )?;
            for artifact in &mut build.artifacts {
                merge_existing(
                    artifact.record.source_digest,
                    &mut artifact.protection,
                    existing_protections,
                )?;
            }
        }
        for workspace in &mut job.retained_workspaces {
            merge_existing(
                workspace.record.source_digest,
                &mut workspace.protection,
                existing_protections,
            )?;
        }
        for dependency in &mut job.persistent_dependencies {
            merge_existing(
                dependency.record.source_digest,
                &mut dependency.protection,
                existing_protections,
            )?;
        }
    }
    let protected_subjects = protected_subjects(&transformed);
    let mut expected_records: BTreeSet<_> = transformed.expected_record_ids.drain(..).collect();
    for subject in protected_subjects {
        if let Some(protection) = existing_protections.get(&subject) {
            expected_records.extend(
                protection
                    .active_holds
                    .iter()
                    .map(|hold| hold.record.id.clone()),
            );
        }
    }
    transformed.expected_record_ids = expected_records.into_iter().collect();
    validate_bundle(&transformed, expected)?;
    let canonical_bytes = canonical_bytes(&transformed)?;
    if canonical_bytes.len() > MAX_CANONICAL_BUNDLE_BYTES {
        return Err(TransferError::InvalidField(
            "canonical bundle exceeds byte limit".to_owned(),
        ));
    }
    let bundle_digest = sha256(&canonical_bytes);
    let binding_digest = sha256(&canonical_bytes_of(&transformed.binding)?);
    Ok(TransferPlan {
        bundle: transformed,
        binding_digest,
        bundle_digest,
        canonical_bytes,
    })
}

fn protected_subjects(bundle: &StateBundle) -> BTreeSet<Digest> {
    let mut subjects = BTreeSet::new();
    for job in &bundle.jobs {
        for build in &job.builds {
            subjects.insert(build.record.source_digest);
            subjects.extend(
                build
                    .artifacts
                    .iter()
                    .map(|artifact| artifact.record.source_digest),
            );
        }
        subjects.extend(
            job.retained_workspaces
                .iter()
                .map(|workspace| workspace.record.source_digest),
        );
        subjects.extend(
            job.persistent_dependencies
                .iter()
                .map(|dependency| dependency.record.source_digest),
        );
    }
    subjects
}

pub fn canonical_bytes(bundle: &StateBundle) -> Result<Vec<u8>, TransferError> {
    canonical_bytes_of(bundle)
}

/// Returns all record-level provenance in canonical record-ID order.
pub fn record_provenance(bundle: &StateBundle) -> Vec<RecordProvenance> {
    let mut records = BTreeMap::new();
    for job in &bundle.jobs {
        collect_record(&mut records, &job.record);
        for build in &job.builds {
            collect_record(&mut records, &build.record);
            collect_record(&mut records, &build.trigger.record);
            for parameter in &build.invocation_parameters {
                collect_record(&mut records, &parameter.record);
            }
            collect_hold_records(&mut records, &build.protection);
            for scm in &build.checkouts {
                collect_record(&mut records, &scm.record);
                for change in &scm.changes {
                    collect_record(&mut records, &change.record);
                }
            }
            for node in &build.graph_nodes {
                collect_record(&mut records, &node.record);
                for attempt in &node.attempts {
                    collect_record(&mut records, &attempt.record);
                }
            }
            for approval in &build.approvals {
                collect_record(&mut records, &approval.record);
            }
            for test in &build.normalized_tests {
                collect_record(&mut records, &test.record);
            }
            for log in &build.logs {
                collect_record(&mut records, &log.record);
            }
            for artifact in &build.artifacts {
                collect_record(&mut records, &artifact.record);
                collect_hold_records(&mut records, &artifact.protection);
            }
        }
        for workspace in &job.retained_workspaces {
            collect_record(&mut records, &workspace.record);
            collect_hold_records(&mut records, &workspace.protection);
        }
        for dependency in &job.persistent_dependencies {
            collect_record(&mut records, &dependency.record);
            collect_hold_records(&mut records, &dependency.protection);
        }
    }
    records.into_values().collect()
}

/// Returns effective protections keyed by the protected record digest.
pub fn protections(bundle: &StateBundle) -> Result<BTreeMap<Digest, Protection>, TransferError> {
    let mut protections = BTreeMap::new();
    for job in &bundle.jobs {
        for build in &job.builds {
            insert_protection(
                &mut protections,
                build.record.source_digest,
                &build.protection,
            )?;
            for artifact in &build.artifacts {
                insert_protection(
                    &mut protections,
                    artifact.record.source_digest,
                    &artifact.protection,
                )?;
            }
        }
        for workspace in &job.retained_workspaces {
            insert_protection(
                &mut protections,
                workspace.record.source_digest,
                &workspace.protection,
            )?;
        }
        for dependency in &job.persistent_dependencies {
            insert_protection(
                &mut protections,
                dependency.record.source_digest,
                &dependency.protection,
            )?;
        }
    }
    Ok(protections)
}

pub fn sha256(bytes: &[u8]) -> Digest {
    Sha256::digest(bytes).into()
}

fn canonical_bytes_of<T: Serialize>(value: &T) -> Result<Vec<u8>, TransferError> {
    serde_json::to_vec(value).map_err(|error| TransferError::Serialization(error.to_string()))
}

fn validate_bundle(bundle: &StateBundle, expected: &ExpectedBinding) -> Result<(), TransferError> {
    validate_binding(&bundle.binding, expected)?;
    validate_sorted_unique_strings(&bundle.expected_record_ids, "expected record IDs")?;
    if bundle.expected_record_ids.is_empty() {
        return Err(TransferError::InvalidField(
            "expected record IDs must not be empty".to_owned(),
        ));
    }

    let mut records = BTreeMap::new();
    if bundle.jobs.len() > MAX_TRANSFER_JOBS {
        return Err(TransferError::InvalidField(
            "bundle exceeds job limit".to_owned(),
        ));
    }
    let mut source_jobs = BTreeSet::new();
    let mut target_jobs = BTreeSet::new();
    let mut prior_source_job: Option<&str> = None;
    for job in &bundle.jobs {
        validate_job(job, &mut records)?;
        if prior_source_job.is_some_and(|prior| prior >= job.source_job_id.as_str()) {
            return Err(TransferError::InvalidField(
                "jobs must be strictly sorted by source_job_id".to_owned(),
            ));
        }
        prior_source_job = Some(&job.source_job_id);
        if !source_jobs.insert(&job.source_job_id) {
            return Err(TransferError::DuplicateJob(job.source_job_id.clone()));
        }
        if !target_jobs.insert(&job.target_pipeline_id) {
            return Err(TransferError::DuplicateJob(job.target_pipeline_id.clone()));
        }
    }

    let expected: BTreeSet<_> = bundle.expected_record_ids.iter().cloned().collect();
    if expected.len() > MAX_TRANSFER_RECORDS {
        return Err(TransferError::InvalidField(
            "bundle exceeds record limit".to_owned(),
        ));
    }
    let actual: BTreeSet<_> = records.into_keys().collect();
    let missing: Vec<_> = expected.difference(&actual).cloned().collect();
    if !missing.is_empty() {
        return Err(TransferError::MissingRecords(missing));
    }
    let unexpected: Vec<_> = actual.difference(&expected).cloned().collect();
    if !unexpected.is_empty() {
        return Err(TransferError::UnexpectedRecords(unexpected));
    }
    Ok(())
}

fn validate_binding(
    binding: &TransferBinding,
    expected: &ExpectedBinding,
) -> Result<(), TransferError> {
    if binding.schema != STATE_TRANSFER_SCHEMA_V1 {
        return Err(TransferError::UnsupportedSchema(binding.schema.clone()));
    }
    if binding.direction != expected.direction {
        return Err(TransferError::BindingMismatch("direction"));
    }
    if binding.source != expected.source {
        return Err(TransferError::BindingMismatch("source identity"));
    }
    if binding.destination != expected.destination {
        return Err(TransferError::BindingMismatch("destination identity"));
    }
    if binding.source_export_digest != expected.source_export_digest {
        return Err(TransferError::BindingMismatch("source export digest"));
    }
    if binding.transform_implementation_digest != expected.transform_implementation_digest {
        return Err(TransferError::BindingMismatch(
            "transform implementation digest",
        ));
    }
    if binding.transform_configuration_digest != expected.transform_configuration_digest {
        return Err(TransferError::BindingMismatch(
            "transform configuration digest",
        ));
    }
    if binding.conflict_policy != expected.conflict_policy {
        return Err(TransferError::BindingMismatch("conflict policy"));
    }
    validate_system_identity(&binding.source, "source")?;
    validate_system_identity(&binding.destination, "destination")?;
    if binding.source == binding.destination {
        return Err(TransferError::InvalidField(
            "source and destination identities must differ".to_owned(),
        ));
    }
    validate_digest(binding.source_export_digest, "source export digest")?;
    validate_digest(
        binding.transform_implementation_digest,
        "transform implementation digest",
    )?;
    validate_digest(
        binding.transform_configuration_digest,
        "transform configuration digest",
    )?;
    validate_text(&binding.provenance, 4096, "binding provenance")
}

fn validate_system_identity(identity: &SystemIdentity, role: &str) -> Result<(), TransferError> {
    validate_text(&identity.kind, 64, &format!("{role} system kind"))?;
    validate_text(&identity.instance_id, 512, &format!("{role} instance ID"))?;
    validate_text(&identity.generation, 512, &format!("{role} generation"))?;
    validate_digest(
        identity.configuration_digest,
        &format!("{role} configuration digest"),
    )
}

fn validate_job(
    job: &JobState,
    records: &mut BTreeMap<String, Digest>,
) -> Result<(), TransferError> {
    insert_record(records, &job.record)?;
    validate_text(&job.source_job_id, 512, "source job ID")?;
    validate_text(&job.target_pipeline_id, 512, "target pipeline ID")?;
    if job.next_build_number == 0 {
        return Err(TransferError::InvalidField(format!(
            "job {} next build number must be positive",
            job.source_job_id
        )));
    }

    let mut previous_build: Option<&BuildState> = None;
    for build in &job.builds {
        if let Some(previous) = previous_build {
            let expected = previous.number.checked_add(1).ok_or_else(|| {
                TransferError::InvalidField(format!(
                    "job {} build number overflow",
                    job.source_job_id
                ))
            })?;
            if build.number != expected {
                return Err(TransferError::BuildGap {
                    job: job.source_job_id.clone(),
                    expected,
                    found: build.number,
                });
            }
            validate_scm_baseline(&job.source_job_id, previous, build)?;
        }
        validate_build(build, records)?;
        previous_build = Some(build);
    }
    match job.builds.last() {
        Some(last) => {
            let expected_next = last.number.checked_add(1).ok_or_else(|| {
                TransferError::InvalidField(format!(
                    "job {} next build number overflow",
                    job.source_job_id
                ))
            })?;
            if job.next_build_number != expected_next {
                return Err(TransferError::BuildGap {
                    job: job.source_job_id.clone(),
                    expected: expected_next,
                    found: job.next_build_number,
                });
            }
            if job.previous_result != Some(last.result) {
                return Err(TransferError::PreviousResultMismatch(
                    job.source_job_id.clone(),
                ));
            }
        }
        None if job.previous_result.is_some() => {
            return Err(TransferError::PreviousResultMismatch(
                job.source_job_id.clone(),
            ));
        }
        None => {}
    }
    validate_object_list(&job.retained_workspaces, records, "retained workspaces")?;
    let mut previous_dependency: Option<&str> = None;
    for dependency in &job.persistent_dependencies {
        if previous_dependency.is_some_and(|previous| previous >= dependency.record.id.as_str()) {
            return Err(TransferError::InvalidField(
                "persistent dependencies must be strictly sorted by record ID".to_owned(),
            ));
        }
        previous_dependency = Some(&dependency.record.id);
        insert_record(records, &dependency.record)?;
        validate_text(&dependency.key, 512, "persistent dependency key")?;
        validate_digest(dependency.value_digest, "persistent dependency digest")?;
        validate_data_binding(&dependency.data_binding)?;
        validate_protection(&dependency.protection)?;
        insert_hold_records(records, &dependency.protection)?;
    }
    Ok(())
}

fn validate_build(
    build: &BuildState,
    records: &mut BTreeMap<String, Digest>,
) -> Result<(), TransferError> {
    insert_record(records, &build.record)?;
    validate_text(&build.source_queue_id, 512, "source queue ID")?;
    validate_text(&build.source_build_id, 512, "source build ID")?;
    validate_trigger(&build.trigger, records)?;
    validate_invocation_parameters(&build.invocation_parameters, records)?;
    if build.number == 0 {
        return Err(TransferError::InvalidField(
            "build number must be positive".to_owned(),
        ));
    }
    validate_digest(build.audit_digest, "build audit digest")?;
    validate_time_range(
        build.queued_at_unix_ms,
        build.started_at_unix_ms,
        build.ended_at_unix_ms,
        "build timing",
    )?;
    validate_protection(&build.protection)?;
    insert_hold_records(records, &build.protection)?;
    let mut prior_checkout: Option<&str> = None;
    for scm in &build.checkouts {
        if prior_checkout.is_some_and(|value| value >= scm.record.id.as_str()) {
            return Err(TransferError::InvalidField(
                "SCM checkouts must be strictly sorted by record ID".to_owned(),
            ));
        }
        prior_checkout = Some(&scm.record.id);
        validate_scm(scm, records)?;
    }
    validate_graph_nodes(&build.graph_nodes, records)?;
    validate_approvals(&build.approvals, records)?;
    validate_normalized_tests(&build.normalized_tests, records)?;
    validate_logs(&build.logs, records)?;
    validate_object_list(&build.artifacts, records, "build artifacts")
}

fn validate_scm(
    scm: &ScmState,
    records: &mut BTreeMap<String, Digest>,
) -> Result<(), TransferError> {
    insert_record(records, &scm.record)?;
    validate_text(&scm.provider, 128, "SCM provider")?;
    validate_text(&scm.repository, 2048, "SCM repository")?;
    validate_text(&scm.reference, 512, "SCM reference")?;
    validate_text(&scm.revision, 512, "SCM revision")?;
    if let Some(previous) = &scm.previous_revision {
        validate_text(previous, 512, "SCM previous revision")?;
    }
    let mut prior: Option<&str> = None;
    for change in &scm.changes {
        if prior.is_some_and(|value| value >= change.record.id.as_str()) {
            return Err(TransferError::InvalidField(
                "SCM changes must be strictly sorted by record ID".to_owned(),
            ));
        }
        prior = Some(&change.record.id);
        insert_record(records, &change.record)?;
        validate_text(&change.commit, 512, "change commit")?;
        validate_text(&change.author, 512, "change author")?;
        validate_digest(change.message_digest, "change message digest")?;
        validate_sorted_unique_strings(&change.paths, "change paths")?;
    }
    Ok(())
}

fn validate_scm_baseline(
    job: &str,
    previous: &BuildState,
    current: &BuildState,
) -> Result<(), TransferError> {
    for current_scm in &current.checkouts {
        if let Some(previous_scm) = previous.checkouts.iter().find(|candidate| {
            candidate.provider == current_scm.provider
                && candidate.repository == current_scm.repository
                && candidate.reference == current_scm.reference
        }) && current_scm.previous_revision.as_deref() != Some(previous_scm.revision.as_str())
        {
            return Err(TransferError::ScmBaselineMismatch {
                job: job.to_owned(),
                build: current.number,
            });
        }
    }
    Ok(())
}

fn validate_trigger(
    trigger: &TriggerCause,
    records: &mut BTreeMap<String, Digest>,
) -> Result<(), TransferError> {
    insert_record(records, &trigger.record)?;
    validate_text(&trigger.trigger_kind, 128, "trigger kind")?;
    validate_text(&trigger.external_id, 512, "trigger external ID")?;
    validate_text(&trigger.actor_subject, 512, "trigger actor subject")
}

fn validate_invocation_parameters(
    parameters: &[InvocationParameter],
    records: &mut BTreeMap<String, Digest>,
) -> Result<(), TransferError> {
    let mut prior: Option<&str> = None;
    for parameter in parameters {
        if prior.is_some_and(|value| value >= parameter.name.as_str()) {
            return Err(TransferError::InvalidField(
                "invocation parameters must be strictly sorted by name".to_owned(),
            ));
        }
        prior = Some(&parameter.name);
        insert_record(records, &parameter.record)?;
        validate_text(&parameter.name, 256, "invocation parameter name")?;
        validate_text(&parameter.type_name, 128, "invocation parameter type")?;
        validate_data_binding(&parameter.data_binding)?;
        match parameter.data_binding.classification {
            DataClassification::SecretMaterial if parameter.public_value_digest.is_some() => {
                return Err(TransferError::InvalidField(
                    "secret invocation parameter must not persist a public value".to_owned(),
                ));
            }
            DataClassification::SecretMaterial => {}
            _ => validate_digest(
                parameter.public_value_digest.ok_or_else(|| {
                    TransferError::InvalidField(
                        "public invocation parameter requires a resolved value digest".to_owned(),
                    )
                })?,
                "invocation parameter public value digest",
            )?,
        }
    }
    Ok(())
}

fn validate_graph_nodes(
    nodes: &[GraphNodeState],
    records: &mut BTreeMap<String, Digest>,
) -> Result<(), TransferError> {
    let mut prior: Option<&str> = None;
    let mut known_ids = BTreeSet::new();
    for node in nodes {
        if prior.is_some_and(|value| value >= node.node_id.as_str()) {
            return Err(TransferError::InvalidField(
                "graph nodes must be strictly sorted by node ID".to_owned(),
            ));
        }
        prior = Some(&node.node_id);
        insert_record(records, &node.record)?;
        validate_text(&node.node_id, 512, "graph node ID")?;
        validate_text(&node.stage_path, 1024, "graph node stage path")?;
        validate_text(&node.node_kind, 128, "graph node kind")?;
        validate_sorted_unique_strings(&node.parent_node_ids, "parent node IDs")?;
        let mut expected_ordinal = 1_u32;
        for attempt in &node.attempts {
            insert_record(records, &attempt.record)?;
            if attempt.ordinal != expected_ordinal {
                return Err(TransferError::InvalidField(
                    "attempt ordinals must be contiguous from one".to_owned(),
                ));
            }
            expected_ordinal = expected_ordinal.checked_add(1).ok_or_else(|| {
                TransferError::InvalidField("attempt ordinal overflow".to_owned())
            })?;
            validate_time_range(
                attempt.started_at_unix_ms,
                attempt.started_at_unix_ms,
                attempt.ended_at_unix_ms,
                "attempt timing",
            )?;
            validate_digest(attempt.audit_digest, "attempt audit digest")?;
        }
        known_ids.insert(node.node_id.as_str());
    }
    for node in nodes {
        if node
            .parent_node_ids
            .iter()
            .any(|parent| !known_ids.contains(parent.as_str()) || parent == &node.node_id)
        {
            return Err(TransferError::InvalidField(
                "graph node parent must name another node in the same build".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_approvals(
    approvals: &[ApprovalState],
    records: &mut BTreeMap<String, Digest>,
) -> Result<(), TransferError> {
    let mut prior: Option<&str> = None;
    for approval in approvals {
        if prior.is_some_and(|value| value >= approval.approval_id.as_str()) {
            return Err(TransferError::InvalidField(
                "approvals must be strictly sorted by approval ID".to_owned(),
            ));
        }
        prior = Some(&approval.approval_id);
        insert_record(records, &approval.record)?;
        validate_text(&approval.approval_id, 512, "approval ID")?;
        validate_digest(approval.policy_digest, "approval policy digest")?;
        validate_text(&approval.approver_subject, 512, "approval subject")?;
        if approval.decided_at_unix_ms < 0 {
            return Err(TransferError::InvalidField(
                "approval decision time must be non-negative".to_owned(),
            ));
        }
        for (name, digest) in &approval.submitted_value_digests {
            validate_text(name, 256, "approval submitted value name")?;
            validate_digest(*digest, "approval submitted value digest")?;
        }
    }
    Ok(())
}

fn validate_normalized_tests(
    tests: &[NormalizedTestState],
    records: &mut BTreeMap<String, Digest>,
) -> Result<(), TransferError> {
    let mut prior: Option<&str> = None;
    for test in tests {
        if prior.is_some_and(|value| value >= test.record.id.as_str()) {
            return Err(TransferError::InvalidField(
                "normalized tests must be strictly sorted by record ID".to_owned(),
            ));
        }
        prior = Some(&test.record.id);
        insert_record(records, &test.record)?;
        validate_text(&test.suite, 512, "test suite")?;
        validate_text(&test.name, 1024, "test name")?;
        validate_text(&test.status, 64, "test status")?;
        validate_digest(test.details_digest, "test details digest")?;
    }
    Ok(())
}

fn validate_logs(
    logs: &[LogState],
    records: &mut BTreeMap<String, Digest>,
) -> Result<(), TransferError> {
    for (expected_sequence, log) in logs.iter().enumerate() {
        if log.sequence != expected_sequence as u64 {
            return Err(TransferError::InvalidField(
                "log sequence must be contiguous from zero".to_owned(),
            ));
        }
        insert_record(records, &log.record)?;
        validate_digest(log.content_digest, "log content digest")?;
        validate_data_binding(&log.data_binding)?;
        validate_retrieval(&log.retrieval)?;
        if log.content_digest != log.retrieval.content_digest {
            return Err(TransferError::InvalidField(
                "log retrieval digest mismatch".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_time_range(
    queued: i64,
    started: i64,
    ended: i64,
    label: &str,
) -> Result<(), TransferError> {
    if queued < 0 || queued > started || started > ended {
        return Err(TransferError::InvalidField(label.to_owned()));
    }
    Ok(())
}

fn validate_retrieval(retrieval: &RetrievalMetadata) -> Result<(), TransferError> {
    validate_text(&retrieval.media_type, 256, "retrieval media type")?;
    validate_text(
        &retrieval.logical_locator,
        2048,
        "retrieval logical locator",
    )?;
    validate_digest(retrieval.content_digest, "retrieval content digest")
}

fn validate_object_list(
    objects: &[ObjectState],
    records: &mut BTreeMap<String, Digest>,
    label: &str,
) -> Result<(), TransferError> {
    let mut previous: Option<&str> = None;
    for object in objects {
        if previous.is_some_and(|value| value >= object.record.id.as_str()) {
            return Err(TransferError::InvalidField(format!(
                "{label} must be strictly sorted by record ID"
            )));
        }
        previous = Some(&object.record.id);
        insert_record(records, &object.record)?;
        validate_text(&object.logical_name, 1024, "object logical name")?;
        validate_digest(object.content_digest, "object content digest")?;
        if object.producer_build_number == Some(0) {
            return Err(TransferError::InvalidField(
                "object producer build number must be positive".to_owned(),
            ));
        }
        validate_retrieval(&object.retrieval)?;
        if object.content_digest != object.retrieval.content_digest {
            return Err(TransferError::InvalidField(
                "object retrieval digest mismatch".to_owned(),
            ));
        }
        validate_data_binding(&object.data_binding)?;
        validate_filesystem_entries(object)?;
        validate_protection(&object.protection)?;
        insert_hold_records(records, &object.protection)?;
    }
    Ok(())
}

fn validate_filesystem_entries(object: &ObjectState) -> Result<(), TransferError> {
    if object.filesystem_entries.len() > MAX_FILESYSTEM_ENTRIES_PER_OBJECT {
        return Err(TransferError::InvalidField(
            "object exceeds filesystem entry limit".to_owned(),
        ));
    }
    let mut prior: Option<&str> = None;
    let mut total_bytes = 0_u64;
    for entry in &object.filesystem_entries {
        validate_relative_path(&entry.path)?;
        if prior.is_some_and(|value| value >= entry.path.as_str()) {
            return Err(TransferError::InvalidField(
                "filesystem entries must be strictly sorted by path".to_owned(),
            ));
        }
        prior = Some(&entry.path);
        validate_data_binding(&entry.data_binding)?;
        match entry.kind {
            FilesystemEntryKind::Directory => {
                if entry.content_digest.is_some() || entry.bytes != 0 {
                    return Err(TransferError::InvalidField(
                        "directory entry must not carry content".to_owned(),
                    ));
                }
            }
            FilesystemEntryKind::RegularFile => {
                let digest = entry.content_digest.ok_or_else(|| {
                    TransferError::InvalidField(
                        "regular file entry requires content digest".to_owned(),
                    )
                })?;
                validate_digest(digest, "filesystem entry content digest")?;
                total_bytes = total_bytes.checked_add(entry.bytes).ok_or_else(|| {
                    TransferError::InvalidField("filesystem byte count overflow".to_owned())
                })?;
            }
        }
    }
    if !object.filesystem_entries.is_empty() && total_bytes != object.bytes {
        return Err(TransferError::InvalidField(
            "filesystem entry byte total does not match object bytes".to_owned(),
        ));
    }
    Ok(())
}

fn validate_relative_path(path: &str) -> Result<(), TransferError> {
    validate_text(path, MAX_FILESYSTEM_PATH_BYTES, "filesystem entry path")?;
    if path.starts_with('/')
        || path.contains('\\')
        || path
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(TransferError::InvalidField(
            "filesystem entry path must be canonical and relative".to_owned(),
        ));
    }
    Ok(())
}

fn validate_data_binding(binding: &DataBinding) -> Result<(), TransferError> {
    match (&binding.classification, &binding.secret_disposition) {
        (DataClassification::SecretMaterial, Some(disposition)) => {
            validate_secret_disposition(disposition)
        }
        (DataClassification::SecretMaterial, None) => Err(TransferError::InvalidField(
            "secret material requires a reference or held-evidence disposition".to_owned(),
        )),
        (_, Some(_)) => Err(TransferError::InvalidField(
            "non-secret data must not carry a secret disposition".to_owned(),
        )),
        (_, None) => Ok(()),
    }
}

fn validate_secret_disposition(disposition: &SecretDisposition) -> Result<(), TransferError> {
    match disposition {
        SecretDisposition::Reference(reference) => {
            validate_text(&reference.provider, 256, "secret reference provider")?;
            validate_text(&reference.reference, 2048, "secret reference")?;
            validate_text(&reference.version, 512, "secret reference version")?;
            validate_digest(reference.keyed_digest, "secret reference keyed digest")
        }
        SecretDisposition::HeldEvidence(evidence) => {
            validate_text(&evidence.custodian, 512, "held-evidence custodian")?;
            validate_text(&evidence.reference, 2048, "held-evidence reference")?;
            validate_digest(evidence.content_digest, "held-evidence content digest")?;
            validate_text(
                &evidence.release_authority,
                512,
                "held-evidence release authority",
            )
        }
    }
}

fn insert_record(
    records: &mut BTreeMap<String, Digest>,
    record: &RecordProvenance,
) -> Result<(), TransferError> {
    validate_text(&record.id, 1024, "record ID")?;
    validate_digest(record.source_digest, "record source digest")?;
    validate_text(&record.provenance, 4096, "record provenance")?;
    if records
        .insert(record.id.clone(), record.source_digest)
        .is_some()
    {
        return Err(TransferError::DuplicateRecord(record.id.clone()));
    }
    Ok(())
}

fn collect_record(records: &mut BTreeMap<String, RecordProvenance>, record: &RecordProvenance) {
    records.insert(record.id.clone(), record.clone());
}

fn collect_hold_records(records: &mut BTreeMap<String, RecordProvenance>, protection: &Protection) {
    for hold in &protection.active_holds {
        collect_record(records, &hold.record);
    }
}

fn insert_protection(
    protections: &mut BTreeMap<Digest, Protection>,
    subject: Digest,
    protection: &Protection,
) -> Result<(), TransferError> {
    match protections.get(&subject) {
        Some(existing) if existing != protection => Err(TransferError::DivergentRetention(subject)),
        Some(_) => Ok(()),
        None => {
            protections.insert(subject, protection.clone());
            Ok(())
        }
    }
}

fn insert_hold_records(
    records: &mut BTreeMap<String, Digest>,
    protection: &Protection,
) -> Result<(), TransferError> {
    for hold in &protection.active_holds {
        insert_record(records, &hold.record)?;
    }
    Ok(())
}

fn validate_protection(protection: &Protection) -> Result<(), TransferError> {
    validate_text(&protection.retention.policy_id, 512, "retention policy ID")?;
    validate_text(
        &protection.retention.policy_version,
        128,
        "retention policy version",
    )?;
    validate_digest(
        protection.retention.policy_digest,
        "retention policy digest",
    )?;
    if protection.retention.retain_until_unix_ms < 0 {
        return Err(TransferError::InvalidField(
            "retention deadline must be non-negative".to_owned(),
        ));
    }
    let mut prior: Option<&str> = None;
    for hold in &protection.active_holds {
        if prior.is_some_and(|value| value >= hold.hold_id.as_str()) {
            return Err(TransferError::InvalidField(
                "active legal holds must be strictly sorted by hold ID".to_owned(),
            ));
        }
        prior = Some(&hold.hold_id);
        validate_record(&hold.record)?;
        validate_text(&hold.hold_id, 256, "legal hold ID")?;
        validate_text(&hold.scope, 1024, "legal hold scope")?;
        validate_text(&hold.reason, 1024, "legal hold reason")?;
        if hold.placed_at_unix_ms < 0 {
            return Err(TransferError::InvalidField(
                "legal hold placement time must be non-negative".to_owned(),
            ));
        }
        if hold.generation == 0 {
            return Err(TransferError::InvalidField(
                "legal hold generation must be positive".to_owned(),
            ));
        }
        validate_text(&hold.release_authority, 512, "legal hold release authority")?;
    }
    Ok(())
}

fn validate_record(record: &RecordProvenance) -> Result<(), TransferError> {
    validate_text(&record.id, 1024, "record ID")?;
    validate_digest(record.source_digest, "record source digest")?;
    validate_text(&record.provenance, 4096, "record provenance")
}

fn merge_existing(
    subject: Digest,
    incoming: &mut Protection,
    existing: &BTreeMap<Digest, Protection>,
) -> Result<(), TransferError> {
    let Some(existing) = existing.get(&subject) else {
        return Ok(());
    };
    incoming.retention = merge_retention(subject, &incoming.retention, &existing.retention)?;
    incoming.active_holds = merge_holds(&incoming.active_holds, &existing.active_holds)?;
    Ok(())
}

fn merge_retention(
    subject: Digest,
    incoming: &RetentionPolicy,
    existing: &RetentionPolicy,
) -> Result<RetentionPolicy, TransferError> {
    match incoming
        .retain_until_unix_ms
        .cmp(&existing.retain_until_unix_ms)
    {
        std::cmp::Ordering::Greater => Ok(incoming.clone()),
        std::cmp::Ordering::Less => Ok(existing.clone()),
        std::cmp::Ordering::Equal if incoming == existing => Ok(incoming.clone()),
        std::cmp::Ordering::Equal => Err(TransferError::DivergentRetention(subject)),
    }
}

fn merge_holds(
    incoming: &[LegalHold],
    existing: &[LegalHold],
) -> Result<Vec<LegalHold>, TransferError> {
    let mut holds = BTreeMap::new();
    for hold in incoming.iter().chain(existing) {
        match holds.get(&hold.hold_id) {
            Some(prior) if prior != hold => {
                return Err(TransferError::DivergentHold(hold.hold_id.clone()));
            }
            Some(_) => {}
            None => {
                holds.insert(hold.hold_id.clone(), hold.clone());
            }
        }
    }
    Ok(holds.into_values().collect())
}

fn validate_sorted_unique_strings(values: &[String], label: &str) -> Result<(), TransferError> {
    let mut prior: Option<&str> = None;
    for value in values {
        validate_text(value, 2048, label)?;
        if prior.is_some_and(|previous| previous >= value.as_str()) {
            return Err(TransferError::InvalidField(format!(
                "{label} must be strictly sorted and unique"
            )));
        }
        prior = Some(value);
    }
    Ok(())
}

fn validate_text(value: &str, max_bytes: usize, field: &str) -> Result<(), TransferError> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(TransferError::InvalidField(field.to_owned()));
    }
    Ok(())
}

fn validate_digest(digest: Digest, field: &str) -> Result<(), TransferError> {
    if digest == [0; 32] {
        return Err(TransferError::InvalidField(field.to_owned()));
    }
    Ok(())
}
