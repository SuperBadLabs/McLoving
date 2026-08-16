//! Fail-closed Jenkins build-history normalization for the MIG-005A boundary.
//!
//! Literal private Jenkins bytes remain in owner-held evidence. This crate
//! authenticates the exact bounded file graph and emits only normalized state,
//! content digests, and opaque retrieval locators.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Read as _;
use std::path::Path;

use mcloving_state_transfer::{
    AttemptState, AttemptTerminalReason, BuildResult, BuildState, ConflictPolicy, DataBinding,
    DataClassification, Digest, ExpectedBinding, GraphNodeState, JobState, LogState,
    PersistentDependency, Protection, RecordProvenance, RetentionPolicy, RetrievalMetadata,
    STATE_TRANSFER_SCHEMA_V1, StateBundle, SystemIdentity, TransferBinding, TransferDirection,
    canonical_bytes, record_provenance, sha256, transform,
};
use quick_xml::{Reader, events::Event};
use sha2::{Digest as _, Sha256};

const MAX_XML_BYTES: usize = 4 * 1024 * 1024;
const MAX_LOG_BYTES: usize = 16 * 1024 * 1024;
const MAX_SOURCE_BYTES: u64 = 32 * 1024 * 1024;
const ADMITTED_JOB_ID: &str = "corpus-052-cinqict_jenkinsdev";
const ADMITTED_TREE_DIGEST: Digest = [
    0xb4, 0x7c, 0xc3, 0xe1, 0xc1, 0x9e, 0x1d, 0x48, 0x6a, 0x2d, 0xf2, 0xfc, 0x76, 0x34, 0x3e, 0x30,
    0x31, 0xee, 0x37, 0x0a, 0x79, 0x56, 0x4f, 0xe8, 0x8a, 0x47, 0x1a, 0xdb, 0xf6, 0xe5, 0x31, 0x07,
];
const EXPECTED_PATHS: [&str; 5] = [
    "1/build.xml",
    "1/log",
    "1/log-index",
    "1/workflow-completed/flowNodeStore.xml",
    "permalinks",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedHistory {
    pub files: BTreeMap<String, Vec<u8>>,
    pub expected_tree_digest: Digest,
    pub opaque_evidence_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportBinding {
    pub source: SystemIdentity,
    pub destination: SystemIdentity,
    pub transform_implementation_digest: Digest,
    pub transform_configuration_digest: Digest,
    pub provenance: String,
    pub source_job_id: String,
    pub target_pipeline_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedHistory {
    bundle: StateBundle,
    expected: ExpectedBinding,
}

impl ParsedHistory {
    pub fn bundle(&self) -> &StateBundle {
        &self.bundle
    }

    pub fn expected(&self) -> &ExpectedBinding {
        &self.expected
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReverseBinding {
    pub source: SystemIdentity,
    pub destination: SystemIdentity,
    pub transform_implementation_digest: Digest,
    pub transform_configuration_digest: Digest,
    pub provenance: String,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum HistoryError {
    #[error("invalid sealed Jenkins history: {0}")]
    Invalid(String),
    #[error("sealed Jenkins history tree digest mismatch")]
    TreeDigest,
    #[error("state-transfer serialization failed: {0}")]
    Serialization(String),
}

pub fn admitted_source_identity() -> SystemIdentity {
    SystemIdentity {
        kind: "jenkins".to_owned(),
        instance_id: "jenkins/mario/jenkins-oracle-228".to_owned(),
        generation: "offline-frozen-source-state".to_owned(),
        configuration_digest: sha256(b"mario-jenkins-oracle-228-frozen-profile"),
    }
}

pub fn admitted_destination_identity() -> SystemIdentity {
    SystemIdentity {
        kind: "mcloving".to_owned(),
        instance_id: "mcloving/disposable-postgres".to_owned(),
        generation: "migration-18".to_owned(),
        configuration_digest: sha256(b"mcloving-postgresql-v18-effect-free"),
    }
}

pub const fn admitted_tree_digest() -> Digest {
    ADMITTED_TREE_DIGEST
}

pub fn load_admitted_history(
    root: &Path,
    opaque_evidence_id: String,
) -> Result<SealedHistory, HistoryError> {
    require_plain_directory(root)?;
    require_plain_directory(&root.join("1"))?;
    require_plain_directory(&root.join("1/workflow-completed"))?;
    let actual = regular_files(root)?;
    let expected = EXPECTED_PATHS
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(invalid("sealed source file denominator is divergent"));
    }

    let mut files = BTreeMap::new();
    let mut total = 0_u64;
    for relative in EXPECTED_PATHS {
        let path = root.join(relative);
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
        }
        let mut file = options
            .open(&path)
            .map_err(|error| invalid(format!("cannot open sealed source entry: {error}")))?;
        let metadata = file
            .metadata()
            .map_err(|error| invalid(format!("cannot inspect sealed source entry: {error}")))?;
        if !metadata.is_file() {
            return Err(invalid(format!(
                "sealed source entry {relative} is not regular"
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if metadata.nlink() != 1 {
                return Err(invalid(format!(
                    "sealed source entry {relative} is hard-linked"
                )));
            }
        }
        total = total
            .checked_add(metadata.len())
            .ok_or_else(|| invalid("sealed source byte count overflow"))?;
        if total > MAX_SOURCE_BYTES {
            return Err(invalid("sealed source exceeds byte limit"));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.by_ref()
            .take(metadata.len() + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| invalid(format!("cannot read sealed source entry: {error}")))?;
        if bytes.len() as u64 != metadata.len() {
            return Err(invalid(format!(
                "sealed source entry {relative} changed while reading"
            )));
        }
        files.insert(relative.to_owned(), bytes);
    }
    let history = SealedHistory {
        files,
        expected_tree_digest: ADMITTED_TREE_DIGEST,
        opaque_evidence_id,
    };
    validate_history_input(&history, true)?;
    Ok(history)
}

pub fn authenticate_forward_bundle(
    history: &SealedHistory,
    candidate: &StateBundle,
) -> Result<ParsedHistory, HistoryError> {
    authenticate_forward_bundle_inner(history, candidate, true)
}

fn authenticate_forward_bundle_inner(
    history: &SealedHistory,
    candidate: &StateBundle,
    require_admitted_tree: bool,
) -> Result<ParsedHistory, HistoryError> {
    let job = candidate
        .jobs
        .first()
        .ok_or_else(|| invalid("forward candidate has no admitted job"))?;
    let normalized = normalize_single_aborted_workflow_inner(
        history,
        &ImportBinding {
            source: candidate.binding.source.clone(),
            destination: candidate.binding.destination.clone(),
            transform_implementation_digest: candidate.binding.transform_implementation_digest,
            transform_configuration_digest: candidate.binding.transform_configuration_digest,
            provenance: candidate.binding.provenance.clone(),
            source_job_id: job.source_job_id.clone(),
            target_pipeline_id: job.target_pipeline_id.clone(),
        },
        require_admitted_tree,
    )?;
    if normalized.bundle != *candidate {
        return Err(invalid(
            "forward candidate differs from exact admitted normalization",
        ));
    }
    Ok(normalized)
}

pub fn normalize_single_aborted_workflow(
    history: &SealedHistory,
    binding: &ImportBinding,
) -> Result<ParsedHistory, HistoryError> {
    normalize_single_aborted_workflow_inner(history, binding, true)
}

fn normalize_single_aborted_workflow_inner(
    history: &SealedHistory,
    binding: &ImportBinding,
    require_admitted_tree: bool,
) -> Result<ParsedHistory, HistoryError> {
    validate_history_input(history, require_admitted_tree)?;
    validate_text(&binding.source_job_id, "source job ID")?;
    validate_text(&binding.target_pipeline_id, "target pipeline ID")?;
    validate_text(&binding.provenance, "binding provenance")?;
    if binding.source_job_id != ADMITTED_JOB_ID || binding.target_pipeline_id != ADMITTED_JOB_ID {
        return Err(invalid(
            "source and target job identities do not match the exact admitted job",
        ));
    }
    if binding.source != admitted_source_identity()
        || binding.destination != admitted_destination_identity()
    {
        return Err(invalid(
            "source and destination systems do not match the exact admitted identities",
        ));
    }

    let build_xml = history_file(history, "1/build.xml")?;
    let flow_xml = history_file(history, "1/workflow-completed/flowNodeStore.xml")?;
    let log = history_file(history, "1/log")?;
    let parsed = parse_build(build_xml)?;
    let flow = parse_flow_nodes(flow_xml)?;
    if parsed.result != BuildResult::Aborted {
        return Err(invalid("the admitted source build must be aborted"));
    }
    if parsed.number != 1 {
        return Err(invalid("the admitted source build number must be one"));
    }
    if flow.first_started_at < parsed.started_at || flow.ended_at > parsed.ended_at {
        return Err(invalid("workflow timestamps escape the build interval"));
    }
    verify_permalinks(history_file(history, "permalinks")?)?;

    let protection = indefinite_protection();
    let build_digest = sha256(build_xml);
    let flow_digest = sha256(flow_xml);
    let log_digest = sha256(log);
    let trigger_bytes = format!("{}:{}", parsed.queue_id, parsed.actor_subject);
    let node_record = record(
        "node:corpus-052-cinqict_jenkinsdev:1:agent-wait",
        flow_digest,
        "sealed Jenkins WorkflowRun flow graph",
    );
    let attempt_record = record(
        "attempt:corpus-052-cinqict_jenkinsdev:1:agent-wait:1",
        sha256_many(&[
            flow_xml,
            &flow.first_started_at.to_be_bytes(),
            &flow.ended_at.to_be_bytes(),
        ]),
        "Jenkins agent wait aborted before workload execution",
    );
    let build = BuildState {
        record: record(
            "build:corpus-052-cinqict_jenkinsdev:1",
            build_digest,
            "sealed Jenkins WorkflowRun build.xml",
        ),
        source_queue_id: parsed.queue_id.clone(),
        source_build_id: parsed.number.to_string(),
        trigger: mcloving_state_transfer::TriggerCause {
            record: record(
                "trigger:corpus-052-cinqict_jenkinsdev:1",
                sha256(trigger_bytes.as_bytes()),
                "sealed Jenkins user trigger",
            ),
            trigger_kind: "jenkins-user".to_owned(),
            external_id: format!("jenkins-queue:{}", parsed.queue_id),
            actor_subject: parsed.actor_subject,
        },
        invocation_parameters: Vec::new(),
        number: parsed.number,
        result: parsed.result,
        queued_at_unix_ms: parsed.queued_at,
        started_at_unix_ms: parsed.started_at,
        ended_at_unix_ms: parsed.ended_at,
        checkouts: Vec::new(),
        graph_nodes: vec![GraphNodeState {
            record: node_record,
            node_id: "agent-wait".to_owned(),
            stage_path: "Declarative: Agent Setup".to_owned(),
            node_kind: "work".to_owned(),
            dependencies: Vec::new(),
            result: BuildResult::Aborted,
            attempts: vec![AttemptState {
                record: attempt_record,
                ordinal: 1,
                retry: None,
                result: BuildResult::Aborted,
                terminal_reason: Some(AttemptTerminalReason::CancelledBeforeExecution),
                queued_at_unix_ms: flow.first_started_at,
                ready_at_unix_ms: None,
                started_at_unix_ms: None,
                ended_at_unix_ms: flow.ended_at,
                audit_digest: flow_digest,
            }],
        }],
        approvals: Vec::new(),
        normalized_tests: Vec::new(),
        logs: vec![LogState {
            record: record(
                "log:corpus-052-cinqict_jenkinsdev:1:0",
                log_digest,
                "owner-held Jenkins build log",
            ),
            sequence: 0,
            content_digest: log_digest,
            bytes: log.len() as u64,
            data_binding: internal_data(),
            retrieval: RetrievalMetadata {
                media_type: "text/plain".to_owned(),
                logical_locator: format!(
                    "held-evidence:{}/builds/1/log",
                    history.opaque_evidence_id
                ),
                content_digest: log_digest,
            },
        }],
        artifacts: Vec::new(),
        protection: protection.clone(),
        audit_digest: sha256_many(&[build_xml, flow_xml]),
    };

    let dependency = PersistentDependency {
        record: record(
            "dependency:corpus-052-cinqict_jenkinsdev:build-history",
            history.expected_tree_digest,
            "owner-held exact Jenkins build-history tree",
        ),
        key: "build-history".to_owned(),
        value_digest: history.expected_tree_digest,
        data_binding: internal_data(),
        protection,
    };
    let mut bundle = StateBundle {
        binding: TransferBinding {
            schema: STATE_TRANSFER_SCHEMA_V1.to_owned(),
            direction: TransferDirection::JenkinsToMcLoving,
            source: binding.source.clone(),
            destination: binding.destination.clone(),
            source_export_digest: history.expected_tree_digest,
            transform_implementation_digest: binding.transform_implementation_digest,
            transform_configuration_digest: binding.transform_configuration_digest,
            conflict_policy: ConflictPolicy::RejectDivergence,
            provenance: binding.provenance.clone(),
        },
        expected_record_ids: Vec::new(),
        jobs: vec![JobState {
            record: record(
                "job:corpus-052-cinqict_jenkinsdev",
                history.expected_tree_digest,
                "MIG-005A admitted Jenkins job",
            ),
            source_job_id: binding.source_job_id.clone(),
            target_pipeline_id: binding.target_pipeline_id.clone(),
            next_build_number: 2,
            previous_result: Some(BuildResult::Aborted),
            builds: vec![build],
            retained_workspaces: Vec::new(),
            persistent_dependencies: vec![dependency],
        }],
    };
    bundle.expected_record_ids = record_provenance(&bundle)
        .into_iter()
        .map(|record| record.id)
        .collect();
    let input_bundle_digest = sha256(
        &canonical_bytes(&bundle)
            .map_err(|error| HistoryError::Serialization(error.to_string()))?,
    );
    let expected = ExpectedBinding {
        direction: bundle.binding.direction,
        source: bundle.binding.source.clone(),
        destination: bundle.binding.destination.clone(),
        source_export_digest: bundle.binding.source_export_digest,
        input_bundle_digest,
        transform_implementation_digest: bundle.binding.transform_implementation_digest,
        transform_configuration_digest: bundle.binding.transform_configuration_digest,
        conflict_policy: bundle.binding.conflict_policy,
    };
    Ok(ParsedHistory { bundle, expected })
}

pub fn digest_tree(files: &BTreeMap<String, Vec<u8>>) -> Result<Digest, HistoryError> {
    let mut hasher = Sha256::new();
    for (path, bytes) in files {
        validate_relative_path(path)?;
        hasher.update((path.len() as u64).to_be_bytes());
        hasher.update(path.as_bytes());
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    Ok(hasher.finalize().into())
}

/// Appends one durably observed McLoving build and prepares the exact reverse
/// bundle that Jenkins must retrieve before it may resume at the next number.
///
/// The caller remains responsible for constructing `completed_build` only
/// from controller-store graph, log, artifact, audit, and protection truth.
/// This boundary rejects gaps and divergent direction/identity, advances the
/// previous-result and build-number cursor exactly once, refreshes the
/// build-history dependency, and runs the canonical state-transfer validator
/// before returning any reverse bytes.
pub fn prepare_reverse_history(
    authenticated_forward: &ParsedHistory,
    completed_build: BuildState,
    binding: &ReverseBinding,
) -> Result<ParsedHistory, HistoryError> {
    let forward = &authenticated_forward.bundle;
    validate_text(&binding.provenance, "reverse binding provenance")?;
    if forward.binding.direction != TransferDirection::JenkinsToMcLoving {
        return Err(invalid(
            "reverse preparation requires a Jenkins-to-McLoving bundle",
        ));
    }
    if forward.jobs.len() != 1 {
        return Err(invalid(
            "reverse preparation requires exactly one admitted job",
        ));
    }
    if forward.binding.source != admitted_source_identity()
        || forward.binding.destination != admitted_destination_identity()
    {
        return Err(invalid(
            "forward systems do not match the exact admitted identities",
        ));
    }
    let forward_job = &forward.jobs[0];
    if forward_job.source_job_id != ADMITTED_JOB_ID
        || forward_job.target_pipeline_id != ADMITTED_JOB_ID
    {
        return Err(invalid(
            "forward job identities do not match the exact admitted job",
        ));
    }
    if binding.source.kind != "mcloving" || binding.destination.kind != "jenkins" {
        return Err(invalid("reverse system identities are divergent"));
    }
    if binding.source != forward.binding.destination
        || binding.destination != forward.binding.source
    {
        return Err(invalid(
            "reverse system identities do not invert the forward binding",
        ));
    }

    let mut bundle = forward.clone();
    let job = bundle
        .jobs
        .first_mut()
        .ok_or_else(|| invalid("reverse bundle has no admitted job"))?;
    if completed_build.number != job.next_build_number {
        return Err(invalid("reverse build number is not the exact next number"));
    }
    if completed_build.source_build_id.is_empty()
        || job
            .builds
            .iter()
            .any(|build| build.source_build_id == completed_build.source_build_id)
    {
        return Err(invalid("reverse build identity is empty or duplicated"));
    }
    let next_build_number = completed_build
        .number
        .checked_add(1)
        .ok_or_else(|| invalid("reverse next build number overflows"))?;
    let previous_result = completed_build.result;
    job.builds.push(completed_build);
    job.next_build_number = next_build_number;
    job.previous_result = Some(previous_result);

    let history_bytes = serde_json::to_vec(&job.builds)
        .map_err(|error| HistoryError::Serialization(error.to_string()))?;
    let history_digest = sha256(&history_bytes);
    let dependency = job
        .persistent_dependencies
        .iter_mut()
        .find(|dependency| dependency.key == "build-history")
        .ok_or_else(|| invalid("reverse bundle lost its build-history dependency"))?;
    dependency.value_digest = history_digest;
    dependency.record.source_digest = history_digest;
    dependency.record.provenance = format!(
        "canonical McLoving execution history through build {}",
        next_build_number - 1
    );

    let source_export_bytes = serde_json::to_vec(&(STATE_TRANSFER_SCHEMA_V1, &bundle.jobs))
        .map_err(|error| HistoryError::Serialization(error.to_string()))?;
    bundle.binding = TransferBinding {
        schema: STATE_TRANSFER_SCHEMA_V1.to_owned(),
        direction: TransferDirection::McLovingToJenkins,
        source: binding.source.clone(),
        destination: binding.destination.clone(),
        source_export_digest: sha256(&source_export_bytes),
        transform_implementation_digest: binding.transform_implementation_digest,
        transform_configuration_digest: binding.transform_configuration_digest,
        conflict_policy: ConflictPolicy::RejectDivergence,
        provenance: binding.provenance.clone(),
    };
    bundle.expected_record_ids = record_provenance(&bundle)
        .into_iter()
        .map(|record| record.id)
        .collect();
    let input_bundle_digest = sha256(
        &canonical_bytes(&bundle)
            .map_err(|error| HistoryError::Serialization(error.to_string()))?,
    );
    let expected = ExpectedBinding {
        direction: bundle.binding.direction,
        source: bundle.binding.source.clone(),
        destination: bundle.binding.destination.clone(),
        source_export_digest: bundle.binding.source_export_digest,
        input_bundle_digest,
        transform_implementation_digest: bundle.binding.transform_implementation_digest,
        transform_configuration_digest: bundle.binding.transform_configuration_digest,
        conflict_policy: bundle.binding.conflict_policy,
    };
    transform(&bundle, &expected, &BTreeMap::new())
        .map_err(|error| invalid(format!("reverse bundle validation failed: {error}")))?;
    Ok(ParsedHistory { bundle, expected })
}

fn regular_files(root: &Path) -> Result<BTreeSet<String>, HistoryError> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = BTreeSet::new();
    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(&directory)
            .map_err(|error| invalid(format!("cannot enumerate sealed source: {error}")))?;
        for entry in entries {
            let entry = entry
                .map_err(|error| invalid(format!("cannot read sealed source entry: {error}")))?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|error| invalid(format!("cannot inspect sealed source entry: {error}")))?;
            if file_type.is_symlink() {
                return Err(invalid("sealed source contains a symbolic link"));
            }
            if file_type.is_dir() {
                pending.push(path);
            } else if file_type.is_file() {
                let relative = path
                    .strip_prefix(root)
                    .map_err(|_| invalid("sealed source entry escapes its root"))?
                    .to_str()
                    .ok_or_else(|| invalid("sealed source path is not UTF-8"))?
                    .replace('\\', "/");
                files.insert(relative);
            } else {
                return Err(invalid("sealed source contains an unsupported file type"));
            }
        }
    }
    Ok(files)
}

fn require_plain_directory(path: &Path) -> Result<(), HistoryError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| invalid(format!("cannot inspect sealed source directory: {error}")))?;
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        Ok(())
    } else {
        Err(invalid("sealed source parent is not a plain directory"))
    }
}

fn validate_history_input(
    history: &SealedHistory,
    require_admitted_tree: bool,
) -> Result<(), HistoryError> {
    validate_text(&history.opaque_evidence_id, "opaque evidence ID")?;
    let actual_paths = history
        .files
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_paths = EXPECTED_PATHS.into_iter().collect::<BTreeSet<_>>();
    if actual_paths != expected_paths {
        return Err(invalid("sealed history has an unexpected file denominator"));
    }
    if [
        "1/build.xml",
        "1/log",
        "1/workflow-completed/flowNodeStore.xml",
        "permalinks",
    ]
    .into_iter()
    .any(|path| history.files.get(path).is_some_and(Vec::is_empty))
    {
        return Err(invalid("sealed history contains an empty required payload"));
    }
    if history_file(history, "1/build.xml")?.len() > MAX_XML_BYTES
        || history_file(history, "1/workflow-completed/flowNodeStore.xml")?.len() > MAX_XML_BYTES
        || history_file(history, "1/log")?.len() > MAX_LOG_BYTES
    {
        return Err(invalid("sealed history exceeds a byte limit"));
    }
    if (require_admitted_tree && history.expected_tree_digest != ADMITTED_TREE_DIGEST)
        || digest_tree(&history.files)? != history.expected_tree_digest
    {
        return Err(HistoryError::TreeDigest);
    }
    Ok(())
}

#[derive(Debug)]
struct ParsedBuild {
    queue_id: String,
    number: u64,
    result: BuildResult,
    queued_at: i64,
    started_at: i64,
    ended_at: i64,
    actor_subject: String,
}

fn parse_build(bytes: &[u8]) -> Result<ParsedBuild, HistoryError> {
    let direct = ["queueId", "timestamp", "duration", "result", "keepLog"]
        .into_iter()
        .collect::<BTreeSet<_>>();
    let nested = ["queuingDurationMillis", "startTime", "userId"]
        .into_iter()
        .collect::<BTreeSet<_>>();
    let fields = selected_xml_text(bytes, "flow-build", |path| {
        let Some(name) = path.last().map(String::as_str) else {
            return false;
        };
        (path.len() == 2 && direct.contains(name)) || nested.contains(name)
    })?;
    require_single(&fields, "keepLog", Some("false"))?;
    let queue_id = require_single(&fields, "queueId", None)?.to_owned();
    let timestamp = parse_i64(require_single(&fields, "timestamp", None)?, "timestamp")?;
    let duration = parse_i64(require_single(&fields, "duration", None)?, "duration")?;
    let started_at = parse_i64(require_single(&fields, "startTime", None)?, "startTime")?;
    let queue_duration = parse_i64(
        require_single(&fields, "queuingDurationMillis", None)?,
        "queuingDurationMillis",
    )?;
    let result = match require_single(&fields, "result", Some("ABORTED"))? {
        "ABORTED" => BuildResult::Aborted,
        _ => return Err(invalid("unsupported Jenkins build result")),
    };
    let actor_subject = require_single(&fields, "userId", None)?.to_owned();
    let ended_at = timestamp
        .checked_add(duration)
        .ok_or_else(|| invalid("build end timestamp overflows"))?;
    let queued_at = timestamp
        .checked_sub(queue_duration)
        .ok_or_else(|| invalid("build queue timestamp underflows"))?;
    if duration < 0 || queue_duration < 0 || queued_at > started_at || started_at > ended_at {
        return Err(invalid("Jenkins build timestamps are inconsistent"));
    }
    Ok(ParsedBuild {
        queue_id,
        number: 1,
        result,
        queued_at,
        started_at,
        ended_at,
        actor_subject,
    })
}

#[derive(Debug)]
struct ParsedFlow {
    first_started_at: i64,
    ended_at: i64,
}

fn parse_flow_nodes(bytes: &[u8]) -> Result<ParsedFlow, HistoryError> {
    let fields = selected_xml_text(bytes, "linked-hash-map", |path| {
        if path.len() < 2 {
            return false;
        }
        matches!(
            (
                path[path.len() - 2].as_str(),
                path.last().map(String::as_str)
            ),
            ("node", Some("id")) | ("wf.a.TimingAction", Some("startTime"))
        )
    })?;
    let ids = fields
        .get("id")
        .ok_or_else(|| invalid("flow graph has no node IDs"))?;
    if ids != &["2", "3", "4", "5"] {
        return Err(invalid(
            "flow graph node denominator is not the exact aborted case",
        ));
    }
    let times = fields
        .get("startTime")
        .ok_or_else(|| invalid("flow graph has no node timestamps"))?
        .iter()
        .map(|value| parse_i64(value, "flow startTime"))
        .collect::<Result<Vec<_>, _>>()?;
    if times.len() != 4 || times.windows(2).any(|pair| pair[0] > pair[1]) {
        return Err(invalid("flow graph timestamps are noncanonical"));
    }
    Ok(ParsedFlow {
        first_started_at: times[0],
        ended_at: times[3],
    })
}

fn selected_xml_text<Select>(
    bytes: &[u8],
    expected_root: &str,
    mut select: Select,
) -> Result<BTreeMap<String, Vec<String>>, HistoryError>
where
    Select: FnMut(&[String]) -> bool,
{
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(true);
    let mut path = Vec::new();
    let mut values = BTreeMap::<String, Vec<String>>::new();
    loop {
        match reader.read_event() {
            Ok(Event::Start(start)) => {
                path.push(String::from_utf8_lossy(start.name().as_ref()).into_owned());
                if path.len() == 1 && path[0] != expected_root {
                    return Err(invalid("Jenkins XML root is divergent"));
                }
                if select(&path) {
                    let name = path
                        .last()
                        .ok_or_else(|| invalid("XML field has no name"))?;
                    values.entry(name.clone()).or_default().push(String::new());
                }
            }
            Ok(Event::Text(text)) => {
                if select(&path) {
                    let name = path
                        .last()
                        .ok_or_else(|| invalid("XML text has no owner"))?;
                    let decoded = text
                        .decode()
                        .map_err(|error| invalid(format!("invalid XML text: {error}")))?;
                    let value = quick_xml::escape::unescape(&decoded)
                        .map_err(|error| invalid(format!("invalid XML escape: {error}")))?
                        .into_owned();
                    values
                        .get_mut(name)
                        .and_then(|fields| fields.last_mut())
                        .ok_or_else(|| invalid("XML text has no selected field"))?
                        .push_str(&value);
                }
            }
            Ok(Event::GeneralRef(reference)) => {
                let decoded = reference
                    .decode()
                    .map_err(|error| invalid(format!("invalid XML reference: {error}")))?;
                let value = quick_xml::escape::unescape(&format!("&{decoded};"))
                    .map_err(|error| invalid(format!("invalid XML reference: {error}")))?
                    .into_owned();
                if select(&path) && !value.is_empty() {
                    let name = path
                        .last()
                        .ok_or_else(|| invalid("XML reference has no owner"))?;
                    values
                        .get_mut(name)
                        .and_then(|fields| fields.last_mut())
                        .ok_or_else(|| invalid("XML reference has no selected field"))?
                        .push_str(&value);
                }
            }
            Ok(Event::End(_)) => {
                path.pop();
            }
            Ok(Event::DocType(_)) => {
                return Err(invalid("XML document type declarations are denied"));
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => return Err(invalid(format!("cannot parse Jenkins XML: {error}"))),
        }
    }
    Ok(values)
}

fn verify_permalinks(bytes: &[u8]) -> Result<(), HistoryError> {
    let text = std::str::from_utf8(bytes).map_err(|_| invalid("permalinks are not UTF-8"))?;
    let expected = BTreeMap::from([
        ("lastCompletedBuild", "1"),
        ("lastSuccessfulBuild", "-1"),
        ("lastUnsuccessfulBuild", "1"),
    ]);
    let mut seen = BTreeMap::new();
    for line in text.lines() {
        let (name, number) = line
            .split_once(' ')
            .ok_or_else(|| invalid("permalink line is malformed"))?;
        if seen.insert(name, number).is_some() {
            return Err(invalid("permalink identity is duplicated"));
        }
    }
    if seen != expected {
        return Err(invalid("permalink target or denominator is divergent"));
    }
    Ok(())
}

fn require_single<'a>(
    fields: &'a BTreeMap<String, Vec<String>>,
    name: &str,
    exact: Option<&str>,
) -> Result<&'a str, HistoryError> {
    let values = fields
        .get(name)
        .ok_or_else(|| invalid(format!("missing Jenkins XML field {name}")))?;
    if values.len() != 1 {
        return Err(invalid(format!("Jenkins XML field {name} is ambiguous")));
    }
    let value = values[0].trim();
    if value.is_empty() {
        return Err(invalid(format!("Jenkins XML field {name} is empty")));
    }
    if exact.is_some_and(|expected| value != expected) {
        return Err(invalid(format!("Jenkins XML field {name} is divergent")));
    }
    Ok(value)
}

fn parse_i64(value: &str, name: &str) -> Result<i64, HistoryError> {
    value
        .parse()
        .map_err(|_| invalid(format!("Jenkins XML field {name} is not an integer")))
}

fn history_file<'a>(history: &'a SealedHistory, path: &str) -> Result<&'a [u8], HistoryError> {
    history
        .files
        .get(path)
        .map(Vec::as_slice)
        .ok_or_else(|| invalid(format!("sealed history is missing {path}")))
}

fn validate_relative_path(path: &str) -> Result<(), HistoryError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(invalid("history path is not canonical and relative"));
    }
    Ok(())
}

fn validate_text(value: &str, name: &str) -> Result<(), HistoryError> {
    if value.is_empty() || value.len() > 2_048 || value.chars().any(char::is_control) {
        return Err(invalid(format!("{name} is invalid")));
    }
    Ok(())
}

fn indefinite_protection() -> Protection {
    Protection {
        retention: RetentionPolicy {
            policy_id: "jenkins-indefinite-build-history".to_owned(),
            policy_version: "v1".to_owned(),
            policy_digest: sha256(b"jenkins-indefinite-build-history:v1"),
            retain_until_unix_ms: i64::MAX,
        },
        active_holds: Vec::new(),
    }
}

fn internal_data() -> DataBinding {
    DataBinding {
        classification: DataClassification::Internal,
        secret_disposition: None,
    }
}

fn record(id: &str, digest: Digest, provenance: &str) -> RecordProvenance {
    RecordProvenance {
        id: id.to_owned(),
        source_digest: digest,
        provenance: provenance.to_owned(),
    }
}

fn sha256_many(parts: &[&[u8]]) -> Digest {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn invalid(message: impl Into<String>) -> HistoryError {
    HistoryError::Invalid(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcloving_state_transfer::transform;

    const BUILD_XML: &[u8] = br#"<flow-build>
  <actions>
    <hudson.model.CauseAction><causes><hudson.model.Cause_-UserIdCause><userId>oracle-admin</userId></hudson.model.Cause_-UserIdCause></causes></hudson.model.CauseAction>
    <jenkins.metrics.impl.TimeInQueueAction><queuingDurationMillis>1</queuingDurationMillis></jenkins.metrics.impl.TimeInQueueAction>
    <execution><startTime>1239</startTime><result>nested-value-must-not-win</result></execution>
  </actions>
  <queueId>92</queueId>
  <timestamp>1233</timestamp>
  <result>ABORTED</result>
  <duration>376</duration>
  <keepLog>false</keepLog>
</flow-build>
"#;

    const FLOW_XML: &[u8] = br#"<linked-hash-map>
  <entry><string>2</string><Tag><node class="org.jenkinsci.plugins.workflow.graph.FlowStartNode"><id>2</id><parentIds/></node><actions><wf.a.TimingAction><startTime>1254</startTime></wf.a.TimingAction></actions></Tag></entry>
  <entry><string>3</string><Tag><node class="cps.n.StepStartNode"><id>3</id><parentIds><string>2</string></parentIds></node><actions><wf.a.TimingAction><startTime>1363</startTime></wf.a.TimingAction></actions></Tag></entry>
  <entry><string>4</string><Tag><node class="cps.n.StepEndNode"><id>4</id><parentIds><string>3</string></parentIds><error><id>ignored-error-id</id></error></node><actions><wf.a.TimingAction><startTime>1576</startTime></wf.a.TimingAction></actions></Tag></entry>
  <entry><string>5</string><Tag><node class="org.jenkinsci.plugins.workflow.graph.FlowEndNode"><id>5</id><parentIds><string>4</string></parentIds></node><actions><wf.a.TimingAction><startTime>1601</startTime></wf.a.TimingAction></actions></Tag></entry>
</linked-hash-map>
"#;

    #[test]
    fn exact_aborted_history_normalizes_and_validates() {
        let history = history();
        let parsed = normalize_test_workflow(&history, &binding()).unwrap();
        transform(&parsed.bundle, &parsed.expected, &BTreeMap::new()).unwrap();

        let job = &parsed.bundle.jobs[0];
        assert_eq!(job.next_build_number, 2);
        assert_eq!(job.previous_result, Some(BuildResult::Aborted));
        assert_eq!(job.persistent_dependencies[0].key, "build-history");
        let build = &job.builds[0];
        assert_eq!(build.source_queue_id, "92");
        assert_eq!(build.queued_at_unix_ms, 1232);
        assert_eq!(build.started_at_unix_ms, 1239);
        assert_eq!(build.ended_at_unix_ms, 1609);
        assert_eq!(build.result, BuildResult::Aborted);
        assert_eq!(build.graph_nodes[0].attempts[0].started_at_unix_ms, None);
        assert_eq!(
            build.graph_nodes[0].attempts[0].terminal_reason,
            Some(AttemptTerminalReason::CancelledBeforeExecution)
        );
    }

    #[test]
    fn completed_mcloving_build_prepares_valid_exact_reverse_history() {
        let parsed = normalize_test_workflow(&history(), &binding()).unwrap();
        let reverse = prepare_reverse_history(
            &parsed,
            completed_build(&parsed.bundle.jobs[0].builds[0]),
            &reverse_binding(&parsed.bundle),
        )
        .unwrap();

        assert_eq!(
            reverse.bundle.binding.direction,
            TransferDirection::McLovingToJenkins
        );
        let job = &reverse.bundle.jobs[0];
        assert_eq!(job.builds.len(), 2);
        assert_eq!(job.next_build_number, 3);
        assert_eq!(job.previous_result, Some(BuildResult::Succeeded));
        assert_eq!(job.builds[1].number, 2);
        assert_eq!(job.builds[1].result, BuildResult::Succeeded);
        assert_eq!(job.persistent_dependencies[0].key, "build-history");
        assert_ne!(
            job.persistent_dependencies[0].value_digest,
            parsed.bundle.jobs[0].persistent_dependencies[0].value_digest
        );
        let source_export_bytes =
            serde_json::to_vec(&(STATE_TRANSFER_SCHEMA_V1, &reverse.bundle.jobs)).unwrap();
        assert_eq!(
            reverse.bundle.binding.source_export_digest,
            sha256(&source_export_bytes)
        );
        transform(&reverse.bundle, &reverse.expected, &BTreeMap::new()).unwrap();
    }

    #[test]
    fn reverse_requires_an_exact_freshly_normalized_forward_bundle() {
        let history = history();
        let parsed = normalize_test_workflow(&history, &binding()).unwrap();
        let authenticated =
            authenticate_forward_bundle_inner(&history, &parsed.bundle, false).unwrap();
        assert_eq!(authenticated, parsed);

        let mut substituted = parsed.bundle.clone();
        substituted.jobs[0].builds[0].result = BuildResult::Succeeded;
        assert!(matches!(
            authenticate_forward_bundle_inner(&history, &substituted, false),
            Err(HistoryError::Invalid(message))
                if message.contains("exact admitted normalization")
        ));
    }

    #[test]
    fn divergent_exact_job_binding_fails_closed() {
        let mut source_substitution = binding();
        source_substitution.source_job_id = "corpus-052-substituted".to_owned();
        assert!(matches!(
            normalize_test_workflow(&history(), &source_substitution),
            Err(HistoryError::Invalid(message)) if message.contains("exact admitted job")
        ));

        let mut target_substitution = binding();
        target_substitution.target_pipeline_id = "corpus-052-substituted".to_owned();
        assert!(matches!(
            normalize_test_workflow(&history(), &target_substitution),
            Err(HistoryError::Invalid(message)) if message.contains("exact admitted job")
        ));
    }

    #[test]
    fn divergent_exact_system_binding_fails_closed() {
        let mut source_substitution = binding();
        source_substitution.source.configuration_digest = sha256(b"substituted-source-profile");
        assert!(matches!(
            normalize_test_workflow(&history(), &source_substitution),
            Err(HistoryError::Invalid(message)) if message.contains("exact admitted identities")
        ));

        let mut destination_substitution = binding();
        destination_substitution.destination.generation = "substituted-generation".to_owned();
        assert!(matches!(
            normalize_test_workflow(&history(), &destination_substitution),
            Err(HistoryError::Invalid(message)) if message.contains("exact admitted identities")
        ));
    }

    #[test]
    fn reverse_history_rejects_gap_duplicate_and_noninverse_identity() {
        let parsed = normalize_test_workflow(&history(), &binding()).unwrap();
        let mut gap = completed_build(&parsed.bundle.jobs[0].builds[0]);
        gap.number = 3;
        assert!(matches!(
            prepare_reverse_history(&parsed, gap, &reverse_binding(&parsed.bundle)),
            Err(HistoryError::Invalid(message)) if message.contains("exact next number")
        ));

        let mut duplicate = completed_build(&parsed.bundle.jobs[0].builds[0]);
        duplicate.source_build_id = parsed.bundle.jobs[0].builds[0].source_build_id.clone();
        assert!(matches!(
            prepare_reverse_history(
                &parsed,
                duplicate,
                &reverse_binding(&parsed.bundle)
            ),
            Err(HistoryError::Invalid(message)) if message.contains("duplicated")
        ));

        let mut divergent = reverse_binding(&parsed.bundle);
        divergent.destination.generation = "substituted-generation".to_owned();
        assert!(matches!(
            prepare_reverse_history(
                &parsed,
                completed_build(&parsed.bundle.jobs[0].builds[0]),
                &divergent
            ),
            Err(HistoryError::Invalid(message)) if message.contains("do not invert")
        ));

        let mut unrelated = parsed.clone();
        unrelated.bundle.jobs[0].source_job_id = "unrelated-source-job".to_owned();
        unrelated.bundle.jobs[0].target_pipeline_id = "unrelated-target-job".to_owned();
        assert!(matches!(
            prepare_reverse_history(
                &unrelated,
                completed_build(&parsed.bundle.jobs[0].builds[0]),
                &reverse_binding(&unrelated.bundle)
            ),
            Err(HistoryError::Invalid(message)) if message.contains("exact admitted job")
        ));

        let mut substituted_system = parsed.clone();
        substituted_system.bundle.binding.source.generation = "substituted-generation".to_owned();
        assert!(matches!(
            prepare_reverse_history(
                &substituted_system,
                completed_build(&parsed.bundle.jobs[0].builds[0]),
                &reverse_binding(&substituted_system.bundle)
            ),
            Err(HistoryError::Invalid(message)) if message.contains("exact admitted identities")
        ));
    }

    #[test]
    fn source_byte_substitution_is_denied_before_normalization() {
        let mut history = history();
        history.files.get_mut("1/log").unwrap().push(b'!');
        assert_eq!(
            normalize_test_workflow(&history, &binding()),
            Err(HistoryError::TreeDigest)
        );
    }

    #[test]
    fn caller_supplied_self_consistent_tree_digest_is_not_admitted() {
        let mut substituted = history();
        substituted.files.get_mut("1/log").unwrap().push(b'!');
        substituted.expected_tree_digest = digest_tree(&substituted.files).unwrap();
        assert_eq!(
            normalize_single_aborted_workflow(&substituted, &binding()),
            Err(HistoryError::TreeDigest)
        );
    }

    #[test]
    fn unexpected_file_or_flow_node_denominator_is_denied() {
        let mut extra_file = history();
        extra_file
            .files
            .insert("1/injected".to_owned(), b"unexpected".to_vec());
        extra_file.expected_tree_digest = digest_tree(&extra_file.files).unwrap();
        assert!(matches!(
            normalize_test_workflow(&extra_file, &binding()),
            Err(HistoryError::Invalid(message)) if message.contains("file denominator")
        ));

        let mut extra_node = history();
        let flow = String::from_utf8(extra_node.files["1/workflow-completed/flowNodeStore.xml"].clone())
            .unwrap()
            .replace("</linked-hash-map>", "<entry><string>6</string><Tag><node><id>6</id></node><actions><wf.a.TimingAction><startTime>1602</startTime></wf.a.TimingAction></actions></Tag></entry></linked-hash-map>");
        extra_node.files.insert(
            "1/workflow-completed/flowNodeStore.xml".to_owned(),
            flow.into_bytes(),
        );
        extra_node.expected_tree_digest = digest_tree(&extra_node.files).unwrap();
        assert!(matches!(
            normalize_test_workflow(&extra_node, &binding()),
            Err(HistoryError::Invalid(message)) if message.contains("node denominator")
        ));
    }

    #[test]
    fn xml_entities_and_divergent_permalinks_fail_closed() {
        let mut entity = history();
        entity.files.insert(
            "1/build.xml".to_owned(),
            b"<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///etc/passwd'>]><flow-build>&e;</flow-build>"
                .to_vec(),
        );
        entity.expected_tree_digest = digest_tree(&entity.files).unwrap();
        assert!(normalize_test_workflow(&entity, &binding()).is_err());

        let mut permalink = history();
        permalink
            .files
            .insert("permalinks".to_owned(), b"lastCompletedBuild 2\n".to_vec());
        permalink.expected_tree_digest = digest_tree(&permalink.files).unwrap();
        assert!(matches!(
            normalize_test_workflow(&permalink, &binding()),
            Err(HistoryError::Invalid(message)) if message.contains("permalink")
        ));
    }

    fn normalize_test_workflow(
        history: &SealedHistory,
        binding: &ImportBinding,
    ) -> Result<ParsedHistory, HistoryError> {
        normalize_single_aborted_workflow_inner(history, binding, false)
    }

    fn history() -> SealedHistory {
        let files = BTreeMap::from([
            ("1/build.xml".to_owned(), BUILD_XML.to_vec()),
            (
                "1/log".to_owned(),
                b"Started by user oracle-admin\nFinished: ABORTED\n".to_vec(),
            ),
            ("1/log-index".to_owned(), Vec::new()),
            (
                "1/workflow-completed/flowNodeStore.xml".to_owned(),
                FLOW_XML.to_vec(),
            ),
            (
                "permalinks".to_owned(),
                b"lastCompletedBuild 1\nlastSuccessfulBuild -1\nlastUnsuccessfulBuild 1\n".to_vec(),
            ),
        ]);
        let expected_tree_digest = digest_tree(&files).unwrap();
        SealedHistory {
            files,
            expected_tree_digest,
            opaque_evidence_id: "mig005a-corpus052-private-v1".to_owned(),
        }
    }

    fn binding() -> ImportBinding {
        ImportBinding {
            source: admitted_source_identity(),
            destination: admitted_destination_identity(),
            transform_implementation_digest: sha256(b"jenkins-state-transfer-test"),
            transform_configuration_digest: sha256(b"corpus052-transform-configuration"),
            provenance: "MIG-005A exact admitted-case test".to_owned(),
            source_job_id: "corpus-052-cinqict_jenkinsdev".to_owned(),
            target_pipeline_id: "corpus-052-cinqict_jenkinsdev".to_owned(),
        }
    }

    fn reverse_binding(bundle: &StateBundle) -> ReverseBinding {
        ReverseBinding {
            source: bundle.binding.destination.clone(),
            destination: bundle.binding.source.clone(),
            transform_implementation_digest: sha256(b"jenkins-state-transfer-test"),
            transform_configuration_digest: sha256(b"corpus052-transform-configuration"),
            provenance: "MIG-005A exact admitted-case reverse test".to_owned(),
        }
    }

    fn completed_build(source: &BuildState) -> BuildState {
        let mut build = source.clone();
        build.record = record(
            "build:corpus-052-cinqict_jenkinsdev:2",
            sha256(b"mcloving-build-2"),
            "durable McLoving effect-free build",
        );
        build.source_queue_id = "mcloving-admission:build-2".to_owned();
        build.source_build_id = "mcloving-build-2".to_owned();
        build.trigger.record = record(
            "trigger:corpus-052-cinqict_jenkinsdev:2",
            sha256(b"mcloving-trigger-2"),
            "contained McLoving rehearsal trigger",
        );
        build.trigger.trigger_kind = "contained-rehearsal".to_owned();
        build.trigger.external_id = "mcloving-admission:build-2".to_owned();
        build.number = 2;
        build.result = BuildResult::Succeeded;
        build.queued_at_unix_ms = 2_000;
        build.started_at_unix_ms = 2_010;
        build.ended_at_unix_ms = 2_020;
        build.graph_nodes[0].record = record(
            "node:corpus-052-cinqict_jenkinsdev:2:build",
            sha256(b"mcloving-node-2"),
            "durable McLoving Build node",
        );
        build.graph_nodes[0].node_id = "build".to_owned();
        build.graph_nodes[0].stage_path = "Build".to_owned();
        build.graph_nodes[0].result = BuildResult::Succeeded;
        build.graph_nodes[0].attempts[0].record = record(
            "attempt:corpus-052-cinqict_jenkinsdev:2:build:1",
            sha256(b"mcloving-attempt-2"),
            "durable McLoving effect-free attempt",
        );
        build.graph_nodes[0].attempts[0].result = BuildResult::Succeeded;
        build.graph_nodes[0].attempts[0].terminal_reason = None;
        build.graph_nodes[0].attempts[0].queued_at_unix_ms = 2_000;
        build.graph_nodes[0].attempts[0].ready_at_unix_ms = Some(2_005);
        build.graph_nodes[0].attempts[0].started_at_unix_ms = Some(2_010);
        build.graph_nodes[0].attempts[0].ended_at_unix_ms = 2_020;
        build.graph_nodes[0].attempts[0].audit_digest = sha256(b"mcloving-attempt-audit-2");
        build.logs[0].record = record(
            "log:corpus-052-cinqict_jenkinsdev:2:0",
            sha256(b"Hello World\n"),
            "durable McLoving effect-free console log",
        );
        build.logs[0].content_digest = sha256(b"Hello World\n");
        build.logs[0].bytes = 12;
        build.logs[0].retrieval.logical_locator =
            "mcloving-held-evidence:corpus-052/builds/2/log".to_owned();
        build.logs[0].retrieval.content_digest = sha256(b"Hello World\n");
        build.audit_digest = sha256(b"mcloving-build-audit-2");
        build
    }
}
