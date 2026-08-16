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
use quick_xml::{
    Reader,
    events::{BytesStart, Event},
};
use sha2::{Digest as _, Sha256};

const MAX_XML_BYTES: usize = 4 * 1024 * 1024;
const MAX_LOG_BYTES: usize = 16 * 1024 * 1024;
const MAX_SOURCE_BYTES: u64 = 32 * 1024 * 1024;
const ADMITTED_JOB_ID: &str = "corpus-052-cinqict_jenkinsdev";
const ADMITTED_TREE_DIGEST: Digest = [
    0xb4, 0x7c, 0xc3, 0xe1, 0xc1, 0x9e, 0x1d, 0x48, 0x6a, 0x2d, 0xf2, 0xfc, 0x76, 0x34, 0x3e, 0x30,
    0x31, 0xee, 0x37, 0x0a, 0x79, 0x56, 0x4f, 0xe8, 0x8a, 0x47, 0x1a, 0xdb, 0xf6, 0xe5, 0x31, 0x07,
];
const ADMITTED_RETENTION_POLICY_ID: &str = "jenkins-indefinite-oracle-retention";
const ADMITTED_RETENTION_POLICY_VERSION: &str = "v1";
const ADMITTED_TRANSFORM_CONFIGURATION: &[u8] = b"corpus052-single-aborted-workflow-v1";
const ADMITTED_FORWARD_PROVENANCE: &str = "MIG-005A owner-held exact admitted-case source";
const ADMITTED_REVERSE_PROVENANCE: &str = "MIG-005A contained corpus-052 reverse reconciliation";
const ADMITTED_RETENTION_POLICY_DIGEST: Digest = [
    0xc2, 0xb7, 0x8e, 0x73, 0x52, 0x03, 0xec, 0x18, 0x77, 0xcc, 0xe3, 0xec, 0xb3, 0xc2, 0x97, 0x8b,
    0xcf, 0xb6, 0x1c, 0x81, 0x59, 0x80, 0x35, 0x12, 0x54, 0xf2, 0xb0, 0x1d, 0xda, 0x11, 0xd3, 0x2a,
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

/// Exact admitted forward history reconstructed under independently pinned
/// implementation trust. The inner value is intentionally opaque so direct
/// normalization cannot mint the token required by reverse preparation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedForwardHistory {
    parsed: ParsedHistory,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReverseBinding {
    pub source: SystemIdentity,
    pub destination: SystemIdentity,
    pub transform_implementation_digest: Digest,
    pub transform_configuration_digest: Digest,
    pub provenance: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedBuildRecord {
    pub result: BuildResult,
    pub started_at_unix_ms: i64,
    pub duration_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedSourceBuildRecord {
    pub queue_id: String,
    pub result: BuildResult,
    pub timestamp_unix_ms: i64,
    pub duration_ms: i64,
    pub queued_at_unix_ms: i64,
    pub started_at_unix_ms: i64,
    pub ended_at_unix_ms: i64,
    pub actor_subject: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum JobConfigToken {
    Start(String, Vec<(String, String)>),
    Text(String, String),
    End(String),
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

/// Parses the bounded direct identity/result/timing projection from a retained
/// Jenkins WorkflowRun `build.xml`. Nested lookalike fields, duplicate values,
/// entity declarations, and unsupported results fail closed.
pub fn parse_retained_build_record(bytes: &[u8]) -> Result<RetainedBuildRecord, HistoryError> {
    if bytes.len() > MAX_XML_BYTES {
        return Err(invalid("retained Jenkins build XML exceeds its byte limit"));
    }
    let direct = ["timestamp", "duration", "result"]
        .into_iter()
        .collect::<BTreeSet<_>>();
    let fields = selected_xml_text(bytes, "flow-build", |path| {
        path.len() == 2
            && path
                .last()
                .is_some_and(|name| direct.contains(name.as_str()))
    })?;
    let started_at_unix_ms = parse_i64(
        require_single(&fields, "timestamp", None)?,
        "retained timestamp",
    )?;
    let duration_ms = parse_i64(
        require_single(&fields, "duration", None)?,
        "retained duration",
    )?;
    if started_at_unix_ms < 0 || duration_ms < 0 {
        return Err(invalid("retained Jenkins build timing is negative"));
    }
    let result = match require_single(&fields, "result", None)? {
        "SUCCESS" => BuildResult::Succeeded,
        "ABORTED" => BuildResult::Aborted,
        _ => return Err(invalid("retained Jenkins build result is unsupported")),
    };
    Ok(RetainedBuildRecord {
        result,
        started_at_unix_ms,
        duration_ms,
    })
}

/// Parses the authenticated source-build projection after Jenkins has loaded
/// and retained it. This reuses the exact admitted source parser so queue,
/// trigger actor, result, and all timing boundaries remain duplicate-safe.
pub fn parse_retained_source_build_record(
    bytes: &[u8],
) -> Result<RetainedSourceBuildRecord, HistoryError> {
    let parsed = parse_build(bytes)?;
    Ok(RetainedSourceBuildRecord {
        queue_id: parsed.queue_id,
        result: parsed.result,
        timestamp_unix_ms: parsed.timestamp,
        duration_ms: parsed.duration,
        queued_at_unix_ms: parsed.queued_at,
        started_at_unix_ms: parsed.started_at,
        ended_at_unix_ms: parsed.ended_at,
        actor_subject: parsed.actor_subject,
    })
}

#[derive(Default)]
struct RetainedWorkflowEntry {
    map_keys: Vec<String>,
    node_ids: Vec<String>,
    parent_ids: Vec<String>,
    descriptor_ids: Vec<String>,
    labels: Vec<String>,
    start_ids: Vec<String>,
    results: Vec<String>,
}

#[derive(Debug)]
struct RetainedWorkflowNode {
    parent_ids: Vec<String>,
    descriptor_id: Option<String>,
    label: Option<String>,
    start_id: Option<String>,
    result: Option<String>,
}

/// Verifies the Jenkins workflow graph and annotated-log storage that will be
/// loaded after another restart. The stage and ShellStep identities must join
/// the independently captured workflow receipts, every graph reference must
/// resolve, and the bytes attributed to the ShellStep must exactly reconstruct
/// its independently captured log.
pub fn verify_retained_workflow_storage(
    flow_store: &[u8],
    log_index: &[u8],
    console_log: &[u8],
    expected_stage_id: &str,
    expected_shell_id: &str,
    expected_shell_log: &[u8],
) -> Result<(), HistoryError> {
    validate_numeric_id(expected_stage_id, "expected stage ID")?;
    validate_numeric_id(expected_shell_id, "expected shell ID")?;
    let nodes = parse_retained_workflow_nodes(flow_store)?;
    if !(8..=64).contains(&nodes.len()) {
        return Err(invalid("retained workflow node denominator is divergent"));
    }

    let stage_ids = nodes
        .iter()
        .filter_map(|(id, node)| (node.label.as_deref() == Some("Build")).then_some(id.as_str()))
        .collect::<Vec<_>>();
    let shell_ids = nodes
        .iter()
        .filter_map(|(id, node)| {
            (node.descriptor_id.as_deref()
                == Some("org.jenkinsci.plugins.workflow.steps.durable_task.ShellStep"))
            .then_some(id.as_str())
        })
        .collect::<Vec<_>>();
    let results = nodes
        .values()
        .filter_map(|node| node.result.as_deref())
        .collect::<Vec<_>>();
    if stage_ids != [expected_stage_id]
        || shell_ids != [expected_shell_id]
        || results != ["SUCCESS"]
    {
        return Err(invalid(
            "retained workflow identities or terminal result are divergent",
        ));
    }
    if !retained_workflow_reaches_ancestor(&nodes, expected_shell_id, expected_stage_id) {
        return Err(invalid(
            "retained ShellStep is not a descendant of the verified Build stage",
        ));
    }
    for (id, node) in &nodes {
        let numeric_id = validate_numeric_id(id, "retained workflow node ID")?;
        for reference in node.parent_ids.iter().chain(node.start_id.iter()) {
            let numeric_reference =
                validate_numeric_id(reference, "retained workflow node reference")?;
            if !nodes.contains_key(reference) || numeric_reference >= numeric_id {
                return Err(invalid(
                    "retained workflow graph contains a missing or cyclic reference",
                ));
            }
        }
    }
    verify_retained_log_index(
        log_index,
        console_log,
        &nodes,
        expected_shell_id,
        expected_shell_log,
    )
}

fn retained_workflow_reaches_ancestor(
    nodes: &BTreeMap<String, RetainedWorkflowNode>,
    descendant: &str,
    ancestor: &str,
) -> bool {
    let mut pending = vec![descendant];
    let mut visited = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if !visited.insert(id) {
            continue;
        }
        let Some(node) = nodes.get(id) else {
            return false;
        };
        for reference in &node.parent_ids {
            if reference == ancestor {
                return true;
            }
            pending.push(reference);
        }
    }
    false
}

fn parse_retained_workflow_nodes(
    bytes: &[u8],
) -> Result<BTreeMap<String, RetainedWorkflowNode>, HistoryError> {
    if bytes.is_empty() || bytes.len() > MAX_XML_BYTES {
        return Err(invalid(
            "retained workflow XML has an invalid byte denominator",
        ));
    }
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(true);
    let mut path = Vec::<String>::new();
    let mut current = None::<RetainedWorkflowEntry>;
    let mut nodes = BTreeMap::new();
    loop {
        match reader.read_event() {
            Ok(Event::Start(start)) => {
                path.push(String::from_utf8_lossy(start.name().as_ref()).into_owned());
                if path.len() == 1 && path[0] != "linked-hash-map" {
                    return Err(invalid("retained workflow XML root is divergent"));
                }
                if path.len() == 2
                    && path[1] == "entry"
                    && current.replace(RetainedWorkflowEntry::default()).is_some()
                {
                    return Err(invalid("retained workflow entries overlap"));
                }
                if let (Some(entry), Some(field)) =
                    (current.as_mut(), retained_workflow_field(&path))
                {
                    retained_workflow_values(entry, field).push(String::new());
                }
            }
            Ok(Event::Text(text)) => {
                if let (Some(entry), Some(field)) =
                    (current.as_mut(), retained_workflow_field(&path))
                {
                    let decoded = text
                        .decode()
                        .map_err(|error| invalid(format!("invalid workflow text: {error}")))?;
                    let value = quick_xml::escape::unescape(&decoded)
                        .map_err(|error| invalid(format!("invalid workflow escape: {error}")))?;
                    retained_workflow_values(entry, field)
                        .last_mut()
                        .ok_or_else(|| invalid("workflow text has no selected field"))?
                        .push_str(&value);
                }
            }
            Ok(Event::CData(text)) => {
                if let (Some(entry), Some(field)) =
                    (current.as_mut(), retained_workflow_field(&path))
                {
                    let value = text
                        .decode()
                        .map_err(|error| invalid(format!("invalid workflow CDATA: {error}")))?;
                    retained_workflow_values(entry, field)
                        .last_mut()
                        .ok_or_else(|| invalid("workflow CDATA has no selected field"))?
                        .push_str(&value);
                }
            }
            Ok(Event::GeneralRef(reference)) => {
                if retained_workflow_field(&path).is_some() {
                    let decoded = reference
                        .decode()
                        .map_err(|error| invalid(format!("invalid workflow reference: {error}")))?;
                    let encoded = format!("&{decoded};");
                    let value = quick_xml::escape::unescape(&encoded)
                        .map_err(|error| invalid(format!("invalid workflow reference: {error}")))?;
                    let field = retained_workflow_field(&path)
                        .ok_or_else(|| invalid("workflow reference has no selected field"))?;
                    retained_workflow_values(
                        current
                            .as_mut()
                            .ok_or_else(|| invalid("workflow reference escapes an entry"))?,
                        field,
                    )
                    .last_mut()
                    .ok_or_else(|| invalid("workflow reference has no selected field"))?
                    .push_str(&value);
                }
            }
            Ok(Event::End(end)) => {
                let name = String::from_utf8_lossy(end.name().as_ref()).into_owned();
                if path.last() != Some(&name) {
                    return Err(invalid("retained workflow element nesting is divergent"));
                }
                if path.len() == 2 && path[1] == "entry" {
                    let entry = current
                        .take()
                        .ok_or_else(|| invalid("retained workflow entry is missing"))?;
                    insert_retained_workflow_node(&mut nodes, entry)?;
                }
                path.pop();
            }
            Ok(Event::DocType(_)) => {
                return Err(invalid("XML document type declarations are denied"));
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => {
                return Err(invalid(format!(
                    "cannot parse retained Jenkins workflow XML: {error}"
                )));
            }
        }
        if nodes.len() > 64 || path.len() > 16 {
            return Err(invalid("retained workflow XML is unbounded"));
        }
    }
    if !path.is_empty() || current.is_some() || nodes.is_empty() {
        return Err(invalid("retained workflow XML is incomplete"));
    }
    Ok(nodes)
}

fn retained_workflow_field(path: &[String]) -> Option<&'static str> {
    if path.len() == 3 && path[0] == "linked-hash-map" && path[1] == "entry" {
        return (path[2] == "string").then_some("map-key");
    }
    if path.len() >= 5
        && path[0] == "linked-hash-map"
        && path[1] == "entry"
        && path[2] == "Tag"
        && path[3] == "node"
    {
        return match path[4..]
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .as_slice()
        {
            ["id"] => Some("node-id"),
            ["parentIds", "string"] => Some("parent-id"),
            ["descriptorId"] => Some("descriptor-id"),
            ["startId"] => Some("start-id"),
            ["result", "name"] => Some("result"),
            _ => None,
        };
    }
    if path.len() == 6
        && path[0] == "linked-hash-map"
        && path[1] == "entry"
        && path[2] == "Tag"
        && path[3] == "actions"
        && path[4] == "wf.a.LabelAction"
        && path[5] == "displayName"
    {
        return Some("label");
    }
    None
}

fn retained_workflow_values<'a>(
    entry: &'a mut RetainedWorkflowEntry,
    field: &str,
) -> &'a mut Vec<String> {
    match field {
        "map-key" => &mut entry.map_keys,
        "node-id" => &mut entry.node_ids,
        "parent-id" => &mut entry.parent_ids,
        "descriptor-id" => &mut entry.descriptor_ids,
        "label" => &mut entry.labels,
        "start-id" => &mut entry.start_ids,
        "result" => &mut entry.results,
        _ => unreachable!("retained workflow field is internal"),
    }
}

fn insert_retained_workflow_node(
    nodes: &mut BTreeMap<String, RetainedWorkflowNode>,
    entry: RetainedWorkflowEntry,
) -> Result<(), HistoryError> {
    let map_key = retained_workflow_single(entry.map_keys, "map key")?
        .ok_or_else(|| invalid("retained workflow entry has no map key"))?;
    let node_id = retained_workflow_single(entry.node_ids, "node ID")?
        .ok_or_else(|| invalid("retained workflow entry has no node ID"))?;
    validate_numeric_id(&map_key, "retained workflow map key")?;
    validate_numeric_id(&node_id, "retained workflow node ID")?;
    if map_key != node_id
        || nodes
            .insert(
                node_id,
                RetainedWorkflowNode {
                    parent_ids: entry.parent_ids,
                    descriptor_id: retained_workflow_single(entry.descriptor_ids, "descriptor ID")?,
                    label: retained_workflow_single(entry.labels, "label")?,
                    start_id: retained_workflow_single(entry.start_ids, "start ID")?,
                    result: retained_workflow_single(entry.results, "result")?,
                },
            )
            .is_some()
    {
        return Err(invalid(
            "retained workflow node identity is duplicated or divergent",
        ));
    }
    Ok(())
}

fn retained_workflow_single(
    values: Vec<String>,
    role: &str,
) -> Result<Option<String>, HistoryError> {
    if values.len() > 1 {
        return Err(invalid(format!("retained workflow {role} is ambiguous")));
    }
    values
        .into_iter()
        .next()
        .map(|value| {
            let value = value.trim().to_owned();
            if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
                Err(invalid(format!("retained workflow {role} is invalid")))
            } else {
                Ok(value)
            }
        })
        .transpose()
}

fn validate_numeric_id(value: &str, role: &str) -> Result<u64, HistoryError> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| invalid(format!("{role} is nonnumeric")))?;
    if parsed.to_string() != value {
        return Err(invalid(format!("{role} is noncanonical")));
    }
    Ok(parsed)
}

fn verify_retained_log_index(
    bytes: &[u8],
    console_log: &[u8],
    nodes: &BTreeMap<String, RetainedWorkflowNode>,
    expected_shell_id: &str,
    expected_shell_log: &[u8],
) -> Result<(), HistoryError> {
    if bytes.is_empty() || bytes.len() > MAX_XML_BYTES || !bytes.ends_with(b"\n") {
        return Err(invalid(
            "retained log index has an invalid byte denominator",
        ));
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| invalid("retained log index is not UTF-8"))?;
    let mut previous_offset = 0_u64;
    let mut active = None::<(&str, usize)>;
    let mut shell_chunks = Vec::<&[u8]>::new();
    let lines = text.lines().collect::<Vec<_>>();
    if lines.is_empty() || lines.len() > nodes.len() * 2 {
        return Err(invalid("retained log index denominator is divergent"));
    }
    for line in lines {
        let fields = line.split(' ').collect::<Vec<_>>();
        if !(1..=2).contains(&fields.len()) || fields.iter().any(|field| field.is_empty()) {
            return Err(invalid("retained log index row is malformed"));
        }
        let offset = validate_numeric_id(fields[0], "retained log offset")?;
        if offset < previous_offset || offset > console_log.len() as u64 {
            return Err(invalid("retained log offsets are divergent"));
        }
        if let Some((active_id, start)) = active
            && active_id == expected_shell_id
        {
            shell_chunks.push(&console_log[start..offset as usize]);
        }
        active = if fields.len() == 2 {
            if active.is_some() {
                return Err(invalid("retained log annotations overlap"));
            }
            validate_numeric_id(fields[1], "retained log node ID")?;
            if !nodes.contains_key(fields[1]) {
                return Err(invalid(
                    "retained log index references a missing workflow node",
                ));
            }
            Some((fields[1], offset as usize))
        } else {
            if active.is_none() {
                return Err(invalid("retained log annotation closes no workflow node"));
            }
            None
        };
        previous_offset = offset;
    }
    if let Some((active_id, start)) = active
        && active_id == expected_shell_id
    {
        shell_chunks.push(&console_log[start..]);
    }
    if shell_chunks.len() != 1 || shell_chunks[0] != expected_shell_log {
        return Err(invalid(
            "retained log index does not reconstruct the verified ShellStep output",
        ));
    }
    Ok(())
}

/// Compares a retained Jenkins job configuration with its reviewed fixture
/// while ignoring only formatting and Jenkins-populated `plugin` version
/// attributes. Element names, non-plugin attributes, values, pipeline script,
/// trigger denominator, retention policy, sandbox, and disabled state remain
/// exact and duplicate-safe.
pub fn verify_retained_job_configuration(
    bytes: &[u8],
    reviewed: &[u8],
) -> Result<(), HistoryError> {
    let actual = canonical_job_configuration(bytes)?;
    let expected = canonical_job_configuration(reviewed)?;
    if actual != expected {
        let index = actual
            .iter()
            .zip(&expected)
            .position(|(actual, expected)| actual != expected)
            .unwrap_or_else(|| actual.len().min(expected.len()));
        let actual_category = actual
            .get(index)
            .map(job_config_token_category)
            .unwrap_or_else(|| "end-of-document".to_owned());
        let expected_category = expected
            .get(index)
            .map(job_config_token_category)
            .unwrap_or_else(|| "end-of-document".to_owned());
        return Err(invalid(format!(
            "retained Jenkins job configuration is behaviorally divergent at token {index}: {actual_category} != {expected_category}"
        )));
    }
    Ok(())
}

fn job_config_token_category(token: &JobConfigToken) -> String {
    match token {
        JobConfigToken::Start(name, attributes) => format!(
            "start:{name}[{}]",
            attributes
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>()
                .join(",")
        ),
        JobConfigToken::Text(path, _) => format!("text:{path}"),
        JobConfigToken::End(name) => format!("end:{name}"),
    }
}

fn canonical_job_configuration(bytes: &[u8]) -> Result<Vec<JobConfigToken>, HistoryError> {
    if bytes.len() > MAX_XML_BYTES {
        return Err(invalid(
            "retained Jenkins job configuration exceeds its byte limit",
        ));
    }
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(false);
    let mut stack = Vec::<String>::new();
    let mut tokens = Vec::<JobConfigToken>::new();
    loop {
        match reader.read_event() {
            Ok(Event::Start(start)) => {
                let token = job_config_start_token(&reader, &start)?;
                if stack.is_empty() && token.0 != "flow-definition" {
                    return Err(invalid(
                        "retained Jenkins job configuration root is divergent",
                    ));
                }
                let ignore = inside_job_action_payload(&stack);
                stack.push(token.0.clone());
                if !ignore {
                    tokens.push(JobConfigToken::Start(token.0, token.1));
                }
            }
            Ok(Event::Empty(start)) => {
                let token = job_config_start_token(&reader, &start)?;
                if stack.is_empty() && token.0 != "flow-definition" {
                    return Err(invalid(
                        "retained Jenkins job configuration root is divergent",
                    ));
                }
                if !inside_job_action_payload(&stack) {
                    tokens.push(JobConfigToken::Start(token.0.clone(), token.1));
                    tokens.push(JobConfigToken::End(token.0));
                }
            }
            Ok(Event::Text(text)) => {
                let decoded = text
                    .decode()
                    .map_err(|error| invalid(format!("invalid job configuration text: {error}")))?;
                let value = quick_xml::escape::unescape(&decoded).map_err(|error| {
                    invalid(format!("invalid job configuration escape: {error}"))
                })?;
                if !inside_job_action_payload(&stack) {
                    push_job_config_text(&mut tokens, &stack, &value);
                }
            }
            Ok(Event::CData(text)) => {
                let value = text.decode().map_err(|error| {
                    invalid(format!("invalid job configuration CDATA: {error}"))
                })?;
                if !inside_job_action_payload(&stack) {
                    push_job_config_text(&mut tokens, &stack, &value);
                }
            }
            Ok(Event::GeneralRef(reference)) => {
                let decoded = reference.decode().map_err(|error| {
                    invalid(format!("invalid job configuration reference: {error}"))
                })?;
                let encoded = format!("&{decoded};");
                let value = quick_xml::escape::unescape(&encoded).map_err(|error| {
                    invalid(format!("invalid job configuration reference: {error}"))
                })?;
                if !inside_job_action_payload(&stack) {
                    push_job_config_text(&mut tokens, &stack, &value);
                }
            }
            Ok(Event::End(end)) => {
                let name = std::str::from_utf8(end.name().as_ref())
                    .map_err(|_| invalid("job configuration element name is not UTF-8"))?
                    .to_owned();
                let ignore = inside_job_action_child(&stack, &name);
                if stack.pop().as_deref() != Some(name.as_str()) {
                    return Err(invalid("job configuration element nesting is divergent"));
                }
                if !ignore {
                    tokens.push(JobConfigToken::End(name));
                }
            }
            Ok(Event::DocType(_)) => {
                return Err(invalid("XML document type declarations are denied"));
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => {
                return Err(invalid(format!(
                    "cannot parse retained Jenkins job configuration: {error}"
                )));
            }
        }
        if tokens.len() > 256 {
            return Err(invalid(
                "retained Jenkins job configuration token denominator is unbounded",
            ));
        }
    }
    let tokens = normalize_job_config_text_tokens(tokens);
    if !stack.is_empty()
        || !matches!(
            tokens.first(),
            Some(JobConfigToken::Start(name, _)) if name == "flow-definition"
        )
    {
        return Err(invalid("retained Jenkins job configuration is incomplete"));
    }
    Ok(remove_false_remove_last_build_default(tokens))
}

fn inside_job_action_payload(stack: &[String]) -> bool {
    stack.len() >= 2 && stack[0] == "flow-definition" && stack[1] == "actions"
}

fn inside_job_action_child(stack_before_pop: &[String], ended_name: &str) -> bool {
    stack_before_pop.len() > 2
        && inside_job_action_payload(stack_before_pop)
        && ended_name != "actions"
}

fn remove_false_remove_last_build_default(tokens: Vec<JobConfigToken>) -> Vec<JobConfigToken> {
    let mut normalized = Vec::with_capacity(tokens.len());
    let mut index = 0;
    while index < tokens.len() {
        let is_false_default = matches!(
            tokens.get(index..index + 3),
            Some([
                JobConfigToken::Start(name, attributes),
                JobConfigToken::Text(path, value),
                JobConfigToken::End(end),
            ]) if name == "removeLastBuild"
                && attributes.is_empty()
                && path == "flow-definition/properties/jenkins.model.BuildDiscarderProperty/strategy/removeLastBuild"
                && value == "false"
                && end == name
        );
        if is_false_default {
            index += 3;
        } else {
            normalized.push(tokens[index].clone());
            index += 1;
        }
    }
    normalized
}

fn normalize_job_config_text_tokens(tokens: Vec<JobConfigToken>) -> Vec<JobConfigToken> {
    tokens
        .into_iter()
        .filter_map(|token| match token {
            JobConfigToken::Text(path, value) => {
                let value = value.trim();
                (!value.is_empty()).then(|| JobConfigToken::Text(path, value.to_owned()))
            }
            token => Some(token),
        })
        .collect()
}

fn job_config_start_token<R>(
    reader: &Reader<R>,
    start: &BytesStart<'_>,
) -> Result<(String, Vec<(String, String)>), HistoryError> {
    let name = std::str::from_utf8(start.name().as_ref())
        .map_err(|_| invalid("job configuration element name is not UTF-8"))?
        .to_owned();
    let mut attributes = Vec::new();
    for attribute in start.attributes().with_checks(true) {
        let attribute = attribute
            .map_err(|error| invalid(format!("invalid job configuration attribute: {error}")))?;
        let key = std::str::from_utf8(attribute.key.as_ref())
            .map_err(|_| invalid("job configuration attribute name is not UTF-8"))?
            .to_owned();
        if key == "plugin" {
            continue;
        }
        let decoded = reader
            .decoder()
            .decode(attribute.value.as_ref())
            .map_err(|error| invalid(format!("invalid job configuration attribute: {error}")))?;
        let value = quick_xml::escape::unescape(&decoded)
            .map_err(|error| invalid(format!("invalid job configuration attribute: {error}")))?
            .into_owned();
        attributes.push((key, value));
    }
    attributes.sort();
    if attributes.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(invalid("job configuration attribute is duplicated"));
    }
    Ok((name, attributes))
}

fn push_job_config_text(tokens: &mut Vec<JobConfigToken>, stack: &[String], value: &str) {
    let normalized = value.replace("\r\n", "\n").replace('\r', "\n");
    if normalized.is_empty() {
        return;
    }
    let path = stack.join("/");
    if let Some(JobConfigToken::Text(existing_path, existing)) = tokens.last_mut()
        && existing_path == &path
    {
        existing.push_str(&normalized);
    } else {
        tokens.push(JobConfigToken::Text(path, normalized));
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
    load_admitted_history_with_policy(root, opaque_evidence_id, false)
}

/// Loads the admitted history while enforcing the owner-private boundary used
/// by migration packaging. Every traversed directory and every admitted file
/// must deny group/other access in addition to the ordinary type/link checks.
pub fn load_admitted_history_owner_only(
    root: &Path,
    opaque_evidence_id: String,
) -> Result<SealedHistory, HistoryError> {
    load_admitted_history_with_policy(root, opaque_evidence_id, true)
}

fn load_admitted_history_with_policy(
    root: &Path,
    opaque_evidence_id: String,
    require_owner_only: bool,
) -> Result<SealedHistory, HistoryError> {
    require_plain_directory(root, require_owner_only)?;
    require_plain_directory(&root.join("1"), require_owner_only)?;
    require_plain_directory(&root.join("1/workflow-completed"), require_owner_only)?;
    let actual = regular_files(root, require_owner_only)?;
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
            if metadata.nlink() != 1
                || (require_owner_only
                    && (metadata.uid() != nix::unistd::geteuid().as_raw()
                        || metadata.mode() & 0o077 != 0))
            {
                return Err(invalid(format!(
                    "sealed source entry {relative} is hard-linked, has the wrong owner, or grants group/other access"
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
    expected_transform_implementation_digest: Digest,
) -> Result<AuthenticatedForwardHistory, HistoryError> {
    authenticate_forward_bundle_inner(
        history,
        candidate,
        expected_transform_implementation_digest,
        true,
    )
}

fn authenticate_forward_bundle_inner(
    history: &SealedHistory,
    candidate: &StateBundle,
    expected_transform_implementation_digest: Digest,
    require_admitted_tree: bool,
) -> Result<AuthenticatedForwardHistory, HistoryError> {
    let normalized = normalize_single_aborted_workflow_inner(
        history,
        &admitted_forward_binding(expected_transform_implementation_digest),
        require_admitted_tree,
    )?;
    if normalized.bundle != *candidate {
        return Err(invalid(
            "forward candidate differs from exact admitted normalization",
        ));
    }
    Ok(AuthenticatedForwardHistory { parsed: normalized })
}

pub fn admitted_forward_binding(transform_implementation_digest: Digest) -> ImportBinding {
    ImportBinding {
        source: admitted_source_identity(),
        destination: admitted_destination_identity(),
        transform_implementation_digest,
        transform_configuration_digest: sha256(ADMITTED_TRANSFORM_CONFIGURATION),
        provenance: ADMITTED_FORWARD_PROVENANCE.to_owned(),
        source_job_id: ADMITTED_JOB_ID.to_owned(),
        target_pipeline_id: ADMITTED_JOB_ID.to_owned(),
    }
}

pub fn admitted_reverse_binding(transform_implementation_digest: Digest) -> ReverseBinding {
    ReverseBinding {
        source: admitted_destination_identity(),
        destination: admitted_source_identity(),
        transform_implementation_digest,
        transform_configuration_digest: sha256(ADMITTED_TRANSFORM_CONFIGURATION),
        provenance: ADMITTED_REVERSE_PROVENANCE.to_owned(),
    }
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
    authenticated_forward: &AuthenticatedForwardHistory,
    completed_build: BuildState,
    binding: &ReverseBinding,
) -> Result<ParsedHistory, HistoryError> {
    let forward = &authenticated_forward.parsed.bundle;
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

/// Reconstructs the exact admitted reverse bundle from an authenticated
/// forward token and an independently pinned reverse implementation digest.
/// The candidate supplies only the completed build observation; every binding
/// and provenance field is rebuilt from the admitted contract before the full
/// canonical bundle is compared.
pub fn authenticate_reverse_bundle(
    authenticated_forward: &AuthenticatedForwardHistory,
    candidate: &StateBundle,
    expected_transform_implementation_digest: Digest,
) -> Result<ParsedHistory, HistoryError> {
    let completed_build = candidate
        .jobs
        .first()
        .and_then(|job| job.builds.get(1))
        .cloned()
        .ok_or_else(|| invalid("reverse candidate is missing the exact completed build"))?;
    let reconstructed = prepare_reverse_history(
        authenticated_forward,
        completed_build,
        &admitted_reverse_binding(expected_transform_implementation_digest),
    )?;
    if reconstructed.bundle != *candidate {
        return Err(invalid(
            "reverse candidate differs from exact admitted reconstruction",
        ));
    }
    Ok(reconstructed)
}

fn regular_files(root: &Path, require_owner_only: bool) -> Result<BTreeSet<String>, HistoryError> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = BTreeSet::new();
    while let Some(directory) = pending.pop() {
        require_plain_directory(&directory, require_owner_only)?;
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

fn require_plain_directory(path: &Path, require_owner_only: bool) -> Result<(), HistoryError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| invalid(format!("cannot inspect sealed source directory: {error}")))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid("sealed source parent is not a plain directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if require_owner_only
            && (metadata.uid() != nix::unistd::geteuid().as_raw() || metadata.mode() & 0o077 != 0)
        {
            return Err(invalid(
                "sealed source directory has the wrong owner or grants group/other access",
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = require_owner_only;
    Ok(())
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
    timestamp: i64,
    duration: i64,
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
        timestamp,
        duration,
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
            policy_id: ADMITTED_RETENTION_POLICY_ID.to_owned(),
            policy_version: ADMITTED_RETENTION_POLICY_VERSION.to_owned(),
            policy_digest: ADMITTED_RETENTION_POLICY_DIGEST,
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
        assert_eq!(
            build.protection.retention.policy_id,
            ADMITTED_RETENTION_POLICY_ID
        );
        assert_eq!(
            build.protection.retention.policy_version,
            ADMITTED_RETENTION_POLICY_VERSION
        );
        assert_eq!(
            build.protection.retention.policy_digest,
            ADMITTED_RETENTION_POLICY_DIGEST
        );
        assert_eq!(
            job.persistent_dependencies[0].protection.retention,
            build.protection.retention
        );
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
        let authenticated = authenticated_history();
        let parsed = &authenticated.parsed;
        let reverse = prepare_reverse_history(
            &authenticated,
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
        let authenticated_reverse = authenticate_reverse_bundle(
            &authenticated,
            &reverse.bundle,
            sha256(b"jenkins-state-transfer-test"),
        )
        .unwrap();
        assert_eq!(authenticated_reverse, reverse);

        let mut substituted = reverse.bundle.clone();
        substituted.binding.provenance = "substituted reverse provenance".to_owned();
        assert!(matches!(
            authenticate_reverse_bundle(
                &authenticated,
                &substituted,
                sha256(b"jenkins-state-transfer-test")
            ),
            Err(HistoryError::Invalid(message))
                if message.contains("exact admitted reconstruction")
        ));
    }

    #[test]
    fn reverse_requires_an_exact_freshly_normalized_forward_bundle() {
        let history = history();
        let expected_implementation = sha256(b"independently-pinned-forward-transform");
        let parsed =
            normalize_test_workflow(&history, &admitted_forward_binding(expected_implementation))
                .unwrap();
        let authenticated = authenticate_forward_bundle_inner(
            &history,
            &parsed.bundle,
            expected_implementation,
            false,
        )
        .unwrap();
        assert_eq!(authenticated.parsed, parsed);

        let mut substituted = parsed.bundle.clone();
        substituted.jobs[0].builds[0].result = BuildResult::Succeeded;
        assert!(matches!(
            authenticate_forward_bundle_inner(
                &history,
                &substituted,
                expected_implementation,
                false
            ),
            Err(HistoryError::Invalid(message))
                if message.contains("exact admitted normalization")
        ));

        let mut implementation = parsed.bundle.clone();
        implementation.binding.transform_implementation_digest = sha256(b"substituted");
        assert!(
            authenticate_forward_bundle_inner(
                &history,
                &implementation,
                expected_implementation,
                false,
            )
            .is_err()
        );

        let mut configuration = parsed.bundle.clone();
        configuration.binding.transform_configuration_digest = sha256(b"substituted");
        assert!(
            authenticate_forward_bundle_inner(
                &history,
                &configuration,
                expected_implementation,
                false,
            )
            .is_err()
        );

        let mut provenance = parsed.bundle.clone();
        provenance.binding.provenance = "substituted provenance".to_owned();
        assert!(
            authenticate_forward_bundle_inner(
                &history,
                &provenance,
                expected_implementation,
                false,
            )
            .is_err()
        );
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
        let authenticated = authenticated_history();
        let parsed = &authenticated.parsed;
        let mut gap = completed_build(&parsed.bundle.jobs[0].builds[0]);
        gap.number = 3;
        assert!(matches!(
            prepare_reverse_history(&authenticated, gap, &reverse_binding(&parsed.bundle)),
            Err(HistoryError::Invalid(message)) if message.contains("exact next number")
        ));

        let mut duplicate = completed_build(&parsed.bundle.jobs[0].builds[0]);
        duplicate.source_build_id = parsed.bundle.jobs[0].builds[0].source_build_id.clone();
        assert!(matches!(
            prepare_reverse_history(
                &authenticated,
                duplicate,
                &reverse_binding(&parsed.bundle)
            ),
            Err(HistoryError::Invalid(message)) if message.contains("duplicated")
        ));

        let mut divergent = reverse_binding(&parsed.bundle);
        divergent.destination.generation = "substituted-generation".to_owned();
        assert!(matches!(
            prepare_reverse_history(
                &authenticated,
                completed_build(&parsed.bundle.jobs[0].builds[0]),
                &divergent
            ),
            Err(HistoryError::Invalid(message)) if message.contains("do not invert")
        ));

        let mut unrelated = authenticated.clone();
        unrelated.parsed.bundle.jobs[0].source_job_id = "unrelated-source-job".to_owned();
        unrelated.parsed.bundle.jobs[0].target_pipeline_id = "unrelated-target-job".to_owned();
        assert!(matches!(
            prepare_reverse_history(
                &unrelated,
                completed_build(&parsed.bundle.jobs[0].builds[0]),
                &reverse_binding(&unrelated.parsed.bundle)
            ),
            Err(HistoryError::Invalid(message)) if message.contains("exact admitted job")
        ));

        let mut substituted_system = authenticated.clone();
        substituted_system.parsed.bundle.binding.source.generation =
            "substituted-generation".to_owned();
        assert!(matches!(
            prepare_reverse_history(
                &substituted_system,
                completed_build(&parsed.bundle.jobs[0].builds[0]),
                &reverse_binding(&substituted_system.parsed.bundle)
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

    fn authenticated_history() -> AuthenticatedForwardHistory {
        let history = history();
        let expected_implementation = sha256(b"independently-pinned-forward-transform");
        let parsed =
            normalize_test_workflow(&history, &admitted_forward_binding(expected_implementation))
                .unwrap();
        authenticate_forward_bundle_inner(&history, &parsed.bundle, expected_implementation, false)
            .unwrap()
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

    fn reverse_binding(_bundle: &StateBundle) -> ReverseBinding {
        admitted_reverse_binding(sha256(b"jenkins-state-transfer-test"))
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

    #[test]
    fn retained_build_projection_is_exact_and_duplicate_safe() {
        let xml = br#"<flow-build><timestamp>2000</timestamp><duration>20</duration><result>SUCCESS</result></flow-build>"#;
        let record = parse_retained_build_record(xml).unwrap();
        assert_eq!(record.result, BuildResult::Succeeded);
        assert_eq!(record.started_at_unix_ms, 2_000);
        assert_eq!(record.duration_ms, 20);

        let duplicated = br#"<flow-build><timestamp>2000</timestamp><timestamp>3000</timestamp><duration>20</duration><result>SUCCESS</result></flow-build>"#;
        assert!(parse_retained_build_record(duplicated).is_err());
    }

    #[test]
    fn retained_source_build_projection_preserves_authenticated_metadata() {
        let record = parse_retained_source_build_record(BUILD_XML).unwrap();
        assert_eq!(record.queue_id, "92");
        assert_eq!(record.result, BuildResult::Aborted);
        assert_eq!(record.timestamp_unix_ms, 1_233);
        assert_eq!(record.duration_ms, 376);
        assert_eq!(record.queued_at_unix_ms, 1_232);
        assert_eq!(record.started_at_unix_ms, 1_239);
        assert_eq!(record.ended_at_unix_ms, 1_609);
        assert_eq!(record.actor_subject, "oracle-admin");

        let divergent = String::from_utf8(BUILD_XML.to_vec())
            .unwrap()
            .replace("<queueId>92</queueId>", "<queueId>93</queueId>");
        assert_ne!(
            parse_retained_source_build_record(divergent.as_bytes()).unwrap(),
            record
        );
    }

    #[test]
    fn retained_workflow_storage_joins_graph_index_and_shell_bytes() {
        let flow = br#"<linked-hash-map>
  <entry><string>1</string><Tag><node><id>1</id></node><actions/></Tag></entry>
  <entry><string>2</string><Tag><node><parentIds><string>1</string></parentIds><id>2</id><descriptorId>executor</descriptorId></node><actions/></Tag></entry>
  <entry><string>3</string><Tag><node><parentIds><string>2</string></parentIds><id>3</id><descriptorId>stage</descriptorId></node><actions><wf.a.LabelAction><displayName>Build</displayName></wf.a.LabelAction></actions></Tag></entry>
  <entry><string>4</string><Tag><node><parentIds><string>3</string></parentIds><id>4</id><descriptorId>org.jenkinsci.plugins.workflow.steps.durable_task.ShellStep</descriptorId></node><actions/></Tag></entry>
  <entry><string>5</string><Tag><node><parentIds><string>4</string></parentIds><id>5</id><startId>4</startId></node><actions/></Tag></entry>
  <entry><string>6</string><Tag><node><parentIds><string>5</string></parentIds><id>6</id><startId>3</startId></node><actions/></Tag></entry>
  <entry><string>7</string><Tag><node><parentIds><string>6</string></parentIds><id>7</id><startId>2</startId></node><actions/></Tag></entry>
  <entry><string>8</string><Tag><node><parentIds><string>7</string></parentIds><id>8</id><result><name>SUCCESS</name></result></node><actions/></Tag></entry>
</linked-hash-map>"#;
        let shell = b"+ echo Hello World\nHello World\n";
        let mut console = b"controller prefix\n".to_vec();
        let start = console.len();
        console.extend_from_slice(shell);
        let end = console.len();
        console.extend_from_slice(b"controller suffix\n");
        let index = format!("{start} 4\n{end}\n");
        verify_retained_workflow_storage(flow, index.as_bytes(), &console, "3", "4", shell)
            .unwrap();

        let detached_node = index.replace(" 4\n", " 99\n");
        assert!(
            verify_retained_workflow_storage(
                flow,
                detached_node.as_bytes(),
                &console,
                "3",
                "4",
                shell,
            )
            .is_err()
        );
        assert!(
            verify_retained_workflow_storage(
                flow,
                index.as_bytes(),
                &console,
                "3",
                "4",
                b"different\n",
            )
            .is_err()
        );
        let corrupted_graph = String::from_utf8(flow.to_vec()).unwrap().replacen(
            "<string>4</string>",
            "<string>40</string>",
            1,
        );
        assert!(
            verify_retained_workflow_storage(
                corrupted_graph.as_bytes(),
                index.as_bytes(),
                &console,
                "3",
                "4",
                shell,
            )
            .is_err()
        );
        let detached_shell = String::from_utf8(flow.to_vec()).unwrap().replace(
            "<parentIds><string>3</string></parentIds><id>4</id>",
            "<parentIds><string>2</string></parentIds><id>4</id><startId>3</startId>",
        );
        assert!(
            verify_retained_workflow_storage(
                detached_shell.as_bytes(),
                index.as_bytes(),
                &console,
                "3",
                "4",
                shell,
            )
            .is_err()
        );
        let doctype = format!(
            "<!DOCTYPE linked-hash-map>{}",
            String::from_utf8_lossy(flow)
        );
        assert!(
            verify_retained_workflow_storage(
                doctype.as_bytes(),
                index.as_bytes(),
                &console,
                "3",
                "4",
                shell,
            )
            .is_err()
        );
    }

    #[test]
    fn retained_job_configuration_allows_only_serialization_metadata_drift() {
        let reviewed = include_bytes!(
            "../../../migration/state-transfer-v1/fixtures/corpus052-job-config.xml"
        );
        verify_retained_job_configuration(reviewed, reviewed).unwrap();

        let reviewed_text = std::str::from_utf8(reviewed).unwrap();
        let rewritten_plugins = reviewed_text
            .replace(
                "plugin=\"workflow-job\"",
                "plugin=\"workflow-job@1400.v7fd111b_ec82f\"",
            )
            .replace(
                "plugin=\"workflow-cps\"",
                "plugin=\"workflow-cps@4209.v83c4e257f1e9\"",
            )
            .replace(
                "<actions/>",
                "<actions><org.jenkinsci.plugins.pipeline.modeldefinition.actions.DeclarativeJobAction><owner>derived-cache</owner></org.jenkinsci.plugins.pipeline.modeldefinition.actions.DeclarativeJobAction></actions>",
            )
            .replace(
                "<artifactNumToKeep>-1</artifactNumToKeep>",
                "<artifactNumToKeep>-1</artifactNumToKeep><removeLastBuild>false</removeLastBuild>",
            );
        verify_retained_job_configuration(rewritten_plugins.as_bytes(), reviewed).unwrap();
        let reviewed_lf = reviewed_text.replace("\r\n", "\n").replace('\r', "\n");
        verify_retained_job_configuration(reviewed_lf.replace('\n', "\r\n").as_bytes(), reviewed)
            .unwrap();
        let escaped_script = reviewed_text
            .replace("<script><![CDATA[", "<script>")
            .replace("]]></script>", "</script>")
            .replace(
                "sh 'echo \"Hello World\"'",
                "sh 'echo &quot;Hello World&quot;'",
            );
        verify_retained_job_configuration(escaped_script.as_bytes(), reviewed).unwrap();

        for divergent in [
            reviewed_text.replace("<disabled>false</disabled>", "<disabled>true</disabled>"),
            reviewed_text.replace("Hello World", "Hello Divergent World"),
            reviewed_text.replace(
                "<triggers/>",
                "<triggers><hudson.triggers.TimerTrigger/></triggers>",
            ),
            reviewed_text.replace(
                "<artifactNumToKeep>-1</artifactNumToKeep>",
                "<artifactNumToKeep>-1</artifactNumToKeep><removeLastBuild>true</removeLastBuild>",
            ),
        ] {
            assert!(verify_retained_job_configuration(divergent.as_bytes(), reviewed).is_err());
        }
        assert!(
            verify_retained_job_configuration(
                b"<!DOCTYPE flow-definition><flow-definition/>",
                reviewed,
            )
            .is_err()
        );
    }
}
