use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use crate::{Store, StoreError};

const MAX_TEXT_BYTES: usize = 512;
const MAX_PATH_BYTES: usize = 1024;
const MAX_REASON_BYTES: usize = 2048;
const MAX_SET_ITEMS: usize = 4096;
const MAX_JSONB_TEXT_BYTES: usize = 65_536;

type DiscoveryIdentityRow = (
    String,
    Uuid,
    String,
    String,
    String,
    Option<i64>,
    String,
    bool,
);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryParentKind {
    MultibranchPipeline,
    OrganizationFolder,
}

impl DiscoveryParentKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::MultibranchPipeline => "multibranch_pipeline",
            Self::OrganizationFolder => "organization_folder",
        }
    }

    fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "multibranch_pipeline" => Ok(Self::MultibranchPipeline),
            "organization_folder" => Ok(Self::OrganizationFolder),
            _ => invalid(format!("stored discovery parent kind '{value}' is invalid")),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryParentState {
    Enabled,
    Quiesced,
}

impl DiscoveryParentState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Quiesced => "quiesced",
        }
    }

    fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "enabled" => Ok(Self::Enabled),
            "quiesced" => Ok(Self::Quiesced),
            _ => invalid(format!(
                "stored discovery parent state '{value}' is invalid"
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PullRequestDiscoveryStrategy {
    None,
    OriginOnly,
    OriginAndForks,
}

impl PullRequestDiscoveryStrategy {
    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::OriginOnly => "origin_only",
            Self::OriginAndForks => "origin_and_forks",
        }
    }

    fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "none" => Ok(Self::None),
            "origin_only" => Ok(Self::OriginOnly),
            "origin_and_forks" => Ok(Self::OriginAndForks),
            _ => invalid(format!("stored pull-request strategy '{value}' is invalid")),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ForkTrustStrategy {
    None,
    NamedRepositories,
    All,
}

impl ForkTrustStrategy {
    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::NamedRepositories => "named_repositories",
            Self::All => "all",
        }
    }

    fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "none" => Ok(Self::None),
            "named_repositories" => Ok(Self::NamedRepositories),
            "all" => Ok(Self::All),
            _ => invalid(format!("stored fork-trust strategy '{value}' is invalid")),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrphanPolicy {
    Retain,
    Retire,
}

impl OrphanPolicy {
    fn as_str(self) -> &'static str {
        match self {
            Self::Retain => "retain",
            Self::Retire => "retire",
        }
    }

    fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "retain" => Ok(Self::Retain),
            "retire" => Ok(Self::Retire),
            _ => invalid(format!("stored orphan policy '{value}' is invalid")),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryScanSource {
    Webhook,
    Periodic,
    Recovery,
}

impl DiscoveryScanSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Webhook => "webhook",
            Self::Periodic => "periodic",
            Self::Recovery => "recovery",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveredRefKind {
    Branch,
    PullRequest,
}

impl DiscoveredRefKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Branch => "branch",
            Self::PullRequest => "pull_request",
        }
    }

    fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "branch" => Ok(Self::Branch),
            "pull_request" => Ok(Self::PullRequest),
            _ => invalid(format!("stored discovered ref kind '{value}' is invalid")),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryChildState {
    Active,
    Quarantined,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryObservationDisposition {
    Active,
    Quarantined,
    Filtered,
    Absent,
}

impl DiscoveryObservationDisposition {
    fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Quarantined => "quarantined",
            Self::Filtered => "filtered",
            Self::Absent => "absent",
        }
    }

    fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "active" => Ok(Self::Active),
            "quarantined" => Ok(Self::Quarantined),
            "filtered" => Ok(Self::Filtered),
            "absent" => Ok(Self::Absent),
            _ => invalid(format!(
                "stored discovery observation disposition '{value}' is invalid"
            )),
        }
    }
}

impl DiscoveryChildState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Quarantined => "quarantined",
            Self::Retired => "retired",
        }
    }

    fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "active" => Ok(Self::Active),
            "quarantined" => Ok(Self::Quarantined),
            "retired" => Ok(Self::Retired),
            _ => invalid(format!("stored discovery child state '{value}' is invalid")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryParentWrite {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub pipeline_id: Uuid,
    pub parent_id: Uuid,
    pub expected_generation: i64,
    pub kind: DiscoveryParentKind,
    pub state: DiscoveryParentState,
    pub implementation_sha256: [u8; 32],
    pub protocol_version: String,
    pub expected_configuration_sha256: [u8; 32],
    pub provider: String,
    pub provider_identity: String,
    pub organization_identity: Option<String>,
    pub repositories: Vec<String>,
    pub branch_includes: Vec<String>,
    pub branch_excludes: Vec<String>,
    pub pull_request_strategy: PullRequestDiscoveryStrategy,
    pub fork_trust_strategy: ForkTrustStrategy,
    pub trusted_fork_repositories: Vec<String>,
    pub jenkinsfile_path: String,
    pub child_configuration_policy_sha256: [u8; 32],
    pub orphan_policy: OrphanPolicy,
    pub authorization_generation: i64,
    pub authorization_policy_sha256: [u8; 32],
    pub trigger_id: Uuid,
    pub trigger_generation: i64,
    pub trigger_configuration_sha256: [u8; 32],
    pub source_implementation_sha256: [u8; 32],
    pub source_protocol_version: String,
    pub source_configuration_sha256: [u8; 32],
    pub restored_from_generation: Option<i64>,
    pub actor_subject: String,
    pub reason: String,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiscoveryParent {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub pipeline_id: Uuid,
    pub parent_id: Uuid,
    pub generation: i64,
    pub kind: DiscoveryParentKind,
    pub state: DiscoveryParentState,
    pub implementation_sha256: [u8; 32],
    pub protocol_version: String,
    pub configuration_sha256: [u8; 32],
    pub provider: String,
    pub provider_identity: String,
    pub organization_identity: Option<String>,
    pub repositories: Vec<String>,
    pub branch_includes: Vec<String>,
    pub branch_excludes: Vec<String>,
    pub pull_request_strategy: PullRequestDiscoveryStrategy,
    pub fork_trust_strategy: ForkTrustStrategy,
    pub trusted_fork_repositories: Vec<String>,
    pub jenkinsfile_path: String,
    pub child_configuration_policy_sha256: [u8; 32],
    pub orphan_policy: OrphanPolicy,
    pub authorization_generation: i64,
    pub authorization_policy_sha256: [u8; 32],
    pub trigger_id: Uuid,
    pub trigger_generation: i64,
    pub trigger_configuration_sha256: [u8; 32],
    pub source_implementation_sha256: [u8; 32],
    pub source_protocol_version: String,
    pub source_configuration_sha256: [u8; 32],
    pub restored_from_generation: Option<i64>,
    pub actor_subject: String,
    pub reason: String,
    pub idempotency_key: String,
    pub audit_sequence: i64,
    pub audit_event_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiscoveryParentPutOutcome {
    Created(DiscoveryParent),
    Revised(DiscoveryParent),
    Replayed(DiscoveryParent),
    PreconditionFailed { current_generation: i64 },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiscoveryObservationWrite {
    pub child_key: String,
    pub child_pipeline_id: Uuid,
    pub repository_identity: String,
    pub ref_kind: DiscoveredRefKind,
    pub ref_name: String,
    pub pull_request_number: Option<i64>,
    pub head_repository_identity: String,
    pub present: bool,
    pub revision: String,
    pub provenance_sha256: [u8; 32],
    pub jenkinsfile_path: String,
    pub jenkinsfile_sha256: [u8; 32],
    pub child_configuration_sha256: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryScanWrite {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub pipeline_id: Uuid,
    pub parent_id: Uuid,
    pub expected_parent_generation: i64,
    pub scan_id: String,
    pub source: DiscoveryScanSource,
    pub source_event_id: Option<String>,
    pub source_cursor: i64,
    pub complete_snapshot: bool,
    pub provider_snapshot_sha256: [u8; 32],
    pub observations: Vec<DiscoveryObservationWrite>,
    pub expected_request_sha256: [u8; 32],
    pub actor_subject: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiscoveryScanReceipt {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub pipeline_id: Uuid,
    pub parent_id: Uuid,
    pub parent_generation: i64,
    pub scan_id: String,
    pub source: DiscoveryScanSource,
    pub source_event_id: Option<String>,
    pub source_cursor: i64,
    pub complete_snapshot: bool,
    pub provider_snapshot_sha256: [u8; 32],
    pub request_sha256: [u8; 32],
    pub observation_count: usize,
    pub selected_count: usize,
    pub active_count: usize,
    pub quarantined_count: usize,
    pub retired_count: usize,
    pub audit_sequence: i64,
    pub audit_event_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiscoveryScanOutcome {
    Reconciled(DiscoveryScanReceipt),
    Replayed(DiscoveryScanReceipt),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiscoveryChild {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub pipeline_id: Uuid,
    pub parent_id: Uuid,
    pub child_key: String,
    pub child_pipeline_id: Uuid,
    pub repository_identity: String,
    pub ref_kind: DiscoveredRefKind,
    pub ref_name: String,
    pub pull_request_number: Option<i64>,
    pub head_repository_identity: String,
    pub is_fork: bool,
    pub state: DiscoveryChildState,
    pub state_generation: i64,
    pub revision: String,
    pub provenance_sha256: [u8; 32],
    pub jenkinsfile_path: String,
    pub jenkinsfile_sha256: [u8; 32],
    pub child_configuration_sha256: [u8; 32],
    pub parent_generation: i64,
    pub source_cursor: i64,
    pub last_scan_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiscoveryScanRecord {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub pipeline_id: Uuid,
    pub parent_id: Uuid,
    pub parent_generation: i64,
    pub scan_id: String,
    pub source: DiscoveryScanSource,
    pub source_event_id: Option<String>,
    pub source_cursor: i64,
    pub complete_snapshot: bool,
    pub provider_snapshot_sha256: [u8; 32],
    pub request_sha256: [u8; 32],
    pub observation_count: usize,
    pub selected_count: usize,
    pub active_count: usize,
    pub quarantined_count: usize,
    pub retired_count: usize,
    pub actor_subject: String,
    pub audit_sequence: i64,
    pub audit_event_hash: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiscoveryObservation {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub pipeline_id: Uuid,
    pub parent_id: Uuid,
    pub scan_id: String,
    pub child_key: String,
    pub child_pipeline_id: Uuid,
    pub repository_identity: String,
    pub ref_kind: DiscoveredRefKind,
    pub ref_name: String,
    pub pull_request_number: Option<i64>,
    pub head_repository_identity: String,
    pub is_fork: bool,
    pub present: bool,
    pub trusted: bool,
    pub authorized: bool,
    pub disposition: DiscoveryObservationDisposition,
    pub revision: String,
    pub provenance_sha256: [u8; 32],
    pub jenkinsfile_path: String,
    pub jenkinsfile_sha256: [u8; 32],
    pub child_configuration_sha256: [u8; 32],
    pub observation_sha256: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiscoveryTransferSnapshot {
    pub schema_version: u16,
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub pipeline_id: Uuid,
    pub parent_id: Uuid,
    pub current_generation: i64,
    pub versions: Vec<DiscoveryParent>,
    pub scans: Vec<DiscoveryScanRecord>,
    pub observations: Vec<DiscoveryObservation>,
    pub children: Vec<DiscoveryChild>,
    pub ledger_sha256: [u8; 32],
    pub handoff_audit_event: crate::AuditEvent,
    pub audit_sequence: i64,
    pub audit_event_hash: [u8; 32],
    pub state_sha256: [u8; 32],
}

pub fn compute_discovery_transfer_ledger_sha256(
    snapshot: &DiscoveryTransferSnapshot,
) -> Result<[u8; 32], StoreError> {
    canonical_sha256(&json!({
        "schema": "mcloving.discovery-transfer-ledger/v1",
        "organization_id": snapshot.organization_id,
        "project_id": snapshot.project_id,
        "pipeline_id": snapshot.pipeline_id,
        "parent_id": snapshot.parent_id,
        "current_generation": snapshot.current_generation,
        "versions": snapshot.versions,
        "scans": snapshot.scans,
        "observations": snapshot.observations,
        "children": snapshot.children,
    }))
}

pub fn compute_discovery_transfer_snapshot_sha256(
    snapshot: &DiscoveryTransferSnapshot,
) -> Result<[u8; 32], StoreError> {
    canonical_sha256(&json!({
        "schema": "mcloving.discovery-transfer-snapshot/v1",
        "ledger_sha256": snapshot.ledger_sha256,
        "handoff_audit_event": snapshot.handoff_audit_event,
        "audit_sequence": snapshot.audit_sequence,
        "audit_event_hash": snapshot.audit_event_hash,
    }))
}

pub fn verify_discovery_transfer_snapshot(
    snapshot: &DiscoveryTransferSnapshot,
    trusted_handoff_audit_event_hash: [u8; 32],
) -> Result<(), StoreError> {
    if snapshot.schema_version != 1
        || snapshot.current_generation <= 0
        || snapshot.audit_sequence <= 0
        || trusted_handoff_audit_event_hash == [0; 32]
        || snapshot.audit_event_hash != trusted_handoff_audit_event_hash
        || snapshot.handoff_audit_event.sequence != snapshot.audit_sequence
        || snapshot.handoff_audit_event.event_hash != trusted_handoff_audit_event_hash
    {
        return conflict(
            "discovery transfer does not match the independently retained audit anchor",
        );
    }
    crate::audit::verify_audit_event_hash(snapshot.organization_id, &snapshot.handoff_audit_event)
        .map_err(|_| {
            StoreError::DiscoveryConflict(
                "discovery transfer handoff audit event hash is invalid".to_owned(),
            )
        })?;
    for (expected, version) in (1_i64..).zip(&snapshot.versions) {
        if version.organization_id != snapshot.organization_id
            || version.project_id != snapshot.project_id
            || version.pipeline_id != snapshot.pipeline_id
            || version.parent_id != snapshot.parent_id
            || version.generation != expected
            || version.audit_sequence <= 0
            || version.audit_event_hash == [0; 32]
        {
            return conflict("discovery transfer version lineage is incomplete or substituted");
        }
    }
    if snapshot.versions.last().map(|version| version.generation)
        != Some(snapshot.current_generation)
        || snapshot
            .versions
            .last()
            .is_none_or(|version| version.state != DiscoveryParentState::Quiesced)
    {
        return conflict("discovery transfer requires a complete lineage ending quiesced");
    }
    let Some((quiesced, prior_versions)) = snapshot.versions.split_last() else {
        return conflict("discovery transfer parent lineage is empty");
    };
    let Some(enabled) = prior_versions.last() else {
        return conflict("discovery transfer quiescence has no enabled predecessor");
    };
    if enabled.state != DiscoveryParentState::Enabled
        || !same_parent_behavior(enabled, quiesced)
        || snapshot
            .scans
            .last()
            .is_none_or(|scan| scan.parent_generation != enabled.generation)
    {
        return conflict(
            "discovery transfer quiescence is not state-only from the latest reconciled enabled generation",
        );
    }
    let mut prior_cursor = 0;
    let mut scan_ids = BTreeSet::new();
    for scan in &snapshot.scans {
        if scan.organization_id != snapshot.organization_id
            || scan.project_id != snapshot.project_id
            || scan.pipeline_id != snapshot.pipeline_id
            || scan.parent_id != snapshot.parent_id
            || scan.source_cursor <= prior_cursor
            || !scan_ids.insert(scan.scan_id.as_str())
            || scan.audit_sequence <= 0
            || scan.audit_event_hash == [0; 32]
        {
            return conflict(
                "discovery transfer scan ledger is incomplete, reordered, or substituted",
            );
        }
        prior_cursor = scan.source_cursor;
    }
    let mut observation_counts = std::collections::BTreeMap::new();
    let mut selected_counts = std::collections::BTreeMap::new();
    for observation in &snapshot.observations {
        if observation.organization_id != snapshot.organization_id
            || observation.project_id != snapshot.project_id
            || observation.pipeline_id != snapshot.pipeline_id
            || observation.parent_id != snapshot.parent_id
            || !scan_ids.contains(observation.scan_id.as_str())
            || observation.observation_sha256 == [0; 32]
        {
            return conflict("discovery transfer observation lineage is incomplete or substituted");
        }
        *observation_counts
            .entry(observation.scan_id.as_str())
            .or_insert(0_usize) += 1;
        if observation.disposition != DiscoveryObservationDisposition::Filtered {
            *selected_counts
                .entry(observation.scan_id.as_str())
                .or_insert(0_usize) += 1;
        }
    }
    if snapshot.scans.iter().any(|scan| {
        observation_counts
            .get(scan.scan_id.as_str())
            .copied()
            .unwrap_or(0)
            != scan.observation_count
            || selected_counts
                .get(scan.scan_id.as_str())
                .copied()
                .unwrap_or(0)
                != scan.selected_count
    }) {
        return conflict("discovery transfer observation counts do not match the scan ledger");
    }
    let mut child_keys = BTreeSet::new();
    let mut child_ids = BTreeSet::new();
    let mut current_counts = (0_usize, 0_usize, 0_usize);
    for child in &snapshot.children {
        if child.organization_id != snapshot.organization_id
            || child.project_id != snapshot.project_id
            || child.pipeline_id != snapshot.pipeline_id
            || child.parent_id != snapshot.parent_id
            || !scan_ids.contains(child.last_scan_id.as_str())
            || !child_keys.insert(child.child_key.as_str())
            || !child_ids.insert(child.child_pipeline_id)
        {
            return conflict("discovery transfer child set is duplicated or substituted");
        }
        match child.state {
            DiscoveryChildState::Active => current_counts.0 += 1,
            DiscoveryChildState::Quarantined => current_counts.1 += 1,
            DiscoveryChildState::Retired => current_counts.2 += 1,
        }
    }
    match snapshot.scans.last() {
        None if !snapshot.children.is_empty() => {
            return conflict("discovery transfer has children without a scan ledger");
        }
        Some(scan)
            if (
                scan.active_count,
                scan.quarantined_count,
                scan.retired_count,
            ) != current_counts =>
        {
            return conflict(
                "discovery transfer current child counts do not match the latest scan",
            );
        }
        None | Some(_) => {}
    }
    let ledger_sha256 = compute_discovery_transfer_ledger_sha256(snapshot)?;
    let ledger_hex = hex::encode(ledger_sha256);
    if ledger_sha256 != snapshot.ledger_sha256
        || snapshot.handoff_audit_event.category != "discovery"
        || snapshot.handoff_audit_event.action != "discovery.handoff.exported"
        || snapshot
            .handoff_audit_event
            .payload
            .get("ledger_sha256")
            .and_then(serde_json::Value::as_str)
            != Some(ledger_hex.as_str())
        || compute_discovery_transfer_snapshot_sha256(snapshot)? != snapshot.state_sha256
    {
        return conflict("discovery transfer digest or audit commitment was substituted");
    }
    Ok(())
}

#[derive(Serialize)]
struct ParentDigest<'a> {
    schema: &'static str,
    kind: DiscoveryParentKind,
    state: DiscoveryParentState,
    implementation_sha256: [u8; 32],
    protocol_version: &'a str,
    provider: &'a str,
    provider_identity: &'a str,
    organization_identity: &'a Option<String>,
    repositories: Vec<&'a str>,
    branch_includes: Vec<&'a str>,
    branch_excludes: Vec<&'a str>,
    pull_request_strategy: PullRequestDiscoveryStrategy,
    fork_trust_strategy: ForkTrustStrategy,
    trusted_fork_repositories: Vec<&'a str>,
    jenkinsfile_path: &'a str,
    jenkinsfile_selection: &'static str,
    child_configuration_policy_sha256: [u8; 32],
    orphan_policy: OrphanPolicy,
    authorization_generation: i64,
    authorization_policy_sha256: [u8; 32],
    trigger_id: Uuid,
    trigger_generation: i64,
    trigger_configuration_sha256: [u8; 32],
    source_implementation_sha256: [u8; 32],
    source_protocol_version: &'a str,
    source_configuration_sha256: [u8; 32],
    restored_from_generation: Option<i64>,
}

pub fn compute_discovery_parent_configuration_sha256(
    input: &DiscoveryParentWrite,
) -> Result<[u8; 32], StoreError> {
    let digest = ParentDigest {
        schema: "mcloving.discovery-parent/v1",
        kind: input.kind,
        state: input.state,
        implementation_sha256: input.implementation_sha256,
        protocol_version: &input.protocol_version,
        provider: &input.provider,
        provider_identity: &input.provider_identity,
        organization_identity: &input.organization_identity,
        repositories: sorted_refs(&input.repositories),
        branch_includes: sorted_refs(&input.branch_includes),
        branch_excludes: sorted_refs(&input.branch_excludes),
        pull_request_strategy: input.pull_request_strategy,
        fork_trust_strategy: input.fork_trust_strategy,
        trusted_fork_repositories: sorted_refs(&input.trusted_fork_repositories),
        jenkinsfile_path: &input.jenkinsfile_path,
        jenkinsfile_selection: "exact_path",
        child_configuration_policy_sha256: input.child_configuration_policy_sha256,
        orphan_policy: input.orphan_policy,
        authorization_generation: input.authorization_generation,
        authorization_policy_sha256: input.authorization_policy_sha256,
        trigger_id: input.trigger_id,
        trigger_generation: input.trigger_generation,
        trigger_configuration_sha256: input.trigger_configuration_sha256,
        source_implementation_sha256: input.source_implementation_sha256,
        source_protocol_version: &input.source_protocol_version,
        source_configuration_sha256: input.source_configuration_sha256,
        restored_from_generation: input.restored_from_generation,
    };
    canonical_sha256(&digest)
}

pub fn compute_discovery_scan_request_sha256(
    input: &DiscoveryScanWrite,
) -> Result<[u8; 32], StoreError> {
    let mut observations = input.observations.iter().collect::<Vec<_>>();
    observations.sort_by(|left, right| left.child_key.cmp(&right.child_key));
    canonical_sha256(&json!({
        "schema": "mcloving.discovery-scan/v1",
        "organization_id": input.organization_id,
        "project_id": input.project_id,
        "pipeline_id": input.pipeline_id,
        "parent_id": input.parent_id,
        "parent_generation": input.expected_parent_generation,
        "scan_id": input.scan_id,
        "source": input.source,
        "source_event_id": input.source_event_id,
        "source_cursor": input.source_cursor,
        "complete_snapshot": input.complete_snapshot,
        "provider_snapshot_sha256": input.provider_snapshot_sha256,
        "observations": observations,
    }))
}

impl Store {
    pub async fn discovery_parent(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        pipeline_id: Uuid,
        parent_id: Uuid,
    ) -> Result<Option<DiscoveryParent>, StoreError> {
        let mut tx = self.tenant_transaction(organization_id).await?;
        let row = sqlx::query(&parent_select("d.current_generation", false))
            .bind(organization_id)
            .bind(project_id)
            .bind(pipeline_id)
            .bind(parent_id)
            .fetch_optional(&mut *tx)
            .await?;
        tx.commit().await?;
        row.map(parent_from_row).transpose()
    }

    pub async fn put_discovery_parent(
        &self,
        input: &DiscoveryParentWrite,
    ) -> Result<DiscoveryParentPutOutcome, StoreError> {
        validate_parent_write(input)?;
        let configuration_sha256 = compute_discovery_parent_configuration_sha256(input)?;
        if configuration_sha256 != input.expected_configuration_sha256 {
            return invalid(
                "discovery parent configuration digest does not match canonical content",
            );
        }
        let mut tx = self.tenant_transaction(input.organization_id).await?;
        lock_parent(&mut tx, input.organization_id, input.parent_id).await?;

        if let Some(row) = sqlx::query(&parent_select("v.generation", true))
            .bind(input.organization_id)
            .bind(input.project_id)
            .bind(input.pipeline_id)
            .bind(input.parent_id)
            .bind(&input.idempotency_key)
            .fetch_optional(&mut *tx)
            .await?
        {
            let parent = parent_from_row(row)?;
            if parent.configuration_sha256 != configuration_sha256
                || parent.actor_subject != input.actor_subject
                || parent.reason != input.reason
                || input.expected_generation != parent.generation - 1
            {
                return conflict(
                    "discovery parent idempotency key was reused for different content",
                );
            }
            tx.commit().await?;
            return Ok(DiscoveryParentPutOutcome::Replayed(parent));
        }
        lock_and_validate_dependencies(&mut tx, input).await?;

        let current = sqlx::query_scalar::<_, i64>(
            "SELECT current_generation FROM discovery_parent_definitions
             WHERE organization_id = $1 AND project_id = $2
               AND pipeline_id = $3 AND parent_id = $4 FOR UPDATE",
        )
        .bind(input.organization_id)
        .bind(input.project_id)
        .bind(input.pipeline_id)
        .bind(input.parent_id)
        .fetch_optional(&mut *tx)
        .await?;
        let (generation, created) = match current {
            None if input.expected_generation == 0 => (1, true),
            None => {
                tx.rollback().await?;
                return Ok(DiscoveryParentPutOutcome::PreconditionFailed {
                    current_generation: 0,
                });
            }
            Some(value) if value != input.expected_generation => {
                tx.rollback().await?;
                return Ok(DiscoveryParentPutOutcome::PreconditionFailed {
                    current_generation: value,
                });
            }
            Some(value) => (
                value.checked_add(1).ok_or_else(|| {
                    StoreError::InvalidDiscovery("discovery generation overflow".to_owned())
                })?,
                false,
            ),
        };
        if input.state == DiscoveryParentState::Quiesced {
            if created {
                return invalid("discovery parent must reconcile before it can be quiesced");
            }
            let previous_row = sqlx::query(&parent_select("d.current_generation", false))
                .bind(input.organization_id)
                .bind(input.project_id)
                .bind(input.pipeline_id)
                .bind(input.parent_id)
                .fetch_one(&mut *tx)
                .await?;
            let previous = parent_from_row(previous_row)?;
            let latest_scan_generation = sqlx::query_scalar::<_, i64>(
                "SELECT parent_generation FROM discovery_scans
                 WHERE organization_id = $1 AND parent_id = $2
                 ORDER BY source_cursor DESC LIMIT 1",
            )
            .bind(input.organization_id)
            .bind(input.parent_id)
            .fetch_optional(&mut *tx)
            .await?;
            if previous.state != DiscoveryParentState::Enabled
                || !same_parent_behavior_write(input, &previous)
                || latest_scan_generation != Some(previous.generation)
            {
                return conflict(
                    "quiescence must be a state-only transition from the latest reconciled enabled generation",
                );
            }
        }
        if let Some(restored) = input.restored_from_generation
            && (restored >= generation
                || !sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS (
                         SELECT 1 FROM discovery_parent_versions
                         WHERE organization_id = $1 AND parent_id = $2 AND generation = $3
                     )",
                )
                .bind(input.organization_id)
                .bind(input.parent_id)
                .bind(restored)
                .fetch_one(&mut *tx)
                .await?)
        {
            return invalid("discovery rollback source generation is not retained");
        }
        if created {
            sqlx::query(
                "INSERT INTO discovery_parent_definitions (
                     organization_id, project_id, pipeline_id, parent_id, current_generation
                 ) VALUES ($1, $2, $3, $4, 1)",
            )
            .bind(input.organization_id)
            .bind(input.project_id)
            .bind(input.pipeline_id)
            .bind(input.parent_id)
            .execute(&mut *tx)
            .await?;
        }
        let audit = crate::audit::append_audit_record(
            &mut tx,
            input.organization_id,
            "discovery",
            &input.actor_subject,
            if created {
                "discovery.parent.created"
            } else {
                "discovery.parent.revised"
            },
            &format!(
                "pipeline:{}:discovery-parent:{}",
                input.pipeline_id, input.parent_id
            ),
            json!({
                "project_id": input.project_id,
                "pipeline_id": input.pipeline_id,
                "parent_id": input.parent_id,
                "generation": generation,
                "kind": input.kind.as_str(),
                "state": input.state.as_str(),
                "configuration_sha256": hex::encode(configuration_sha256),
                "authorization_generation": input.authorization_generation,
                "trigger_id": input.trigger_id,
                "trigger_generation": input.trigger_generation,
                "restored_from_generation": input.restored_from_generation,
                "reason": input.reason,
            }),
        )
        .await?;
        sqlx::query(
            "INSERT INTO discovery_parent_versions (
                 organization_id, project_id, pipeline_id, parent_id, generation,
                 parent_kind, state, implementation_sha256, protocol_version,
                 configuration_sha256, provider, provider_identity,
                 organization_identity, repositories, branch_includes, branch_excludes,
                 pull_request_strategy, fork_trust_strategy, trusted_fork_repositories,
                 jenkinsfile_path, jenkinsfile_selection,
                 child_configuration_policy_sha256, orphan_policy,
                 authorization_generation, authorization_policy_sha256,
                 trigger_id, trigger_generation, trigger_configuration_sha256,
                 source_implementation_sha256, source_protocol_version,
                 source_configuration_sha256, restored_from_generation,
                 actor_subject, reason, idempotency_key, audit_sequence, audit_event_hash
             ) VALUES (
                 $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
                 $17,$18,$19,$20,'exact_path',$21,$22,$23,$24,$25,$26,$27,
                 $28,$29,$30,$31,$32,$33,$34,$35,$36
             )",
        )
        .bind(input.organization_id)
        .bind(input.project_id)
        .bind(input.pipeline_id)
        .bind(input.parent_id)
        .bind(generation)
        .bind(input.kind.as_str())
        .bind(input.state.as_str())
        .bind(input.implementation_sha256.as_slice())
        .bind(&input.protocol_version)
        .bind(configuration_sha256.as_slice())
        .bind(&input.provider)
        .bind(&input.provider_identity)
        .bind(&input.organization_identity)
        .bind(json!(sorted_owned(&input.repositories)))
        .bind(json!(sorted_owned(&input.branch_includes)))
        .bind(json!(sorted_owned(&input.branch_excludes)))
        .bind(input.pull_request_strategy.as_str())
        .bind(input.fork_trust_strategy.as_str())
        .bind(json!(sorted_owned(&input.trusted_fork_repositories)))
        .bind(&input.jenkinsfile_path)
        .bind(input.child_configuration_policy_sha256.as_slice())
        .bind(input.orphan_policy.as_str())
        .bind(input.authorization_generation)
        .bind(input.authorization_policy_sha256.as_slice())
        .bind(input.trigger_id)
        .bind(input.trigger_generation)
        .bind(input.trigger_configuration_sha256.as_slice())
        .bind(input.source_implementation_sha256.as_slice())
        .bind(&input.source_protocol_version)
        .bind(input.source_configuration_sha256.as_slice())
        .bind(input.restored_from_generation)
        .bind(&input.actor_subject)
        .bind(&input.reason)
        .bind(&input.idempotency_key)
        .bind(audit.sequence)
        .bind(audit.event_hash.as_slice())
        .execute(&mut *tx)
        .await?;
        if !created {
            sqlx::query(
                "UPDATE discovery_parent_definitions
                 SET current_generation = $5, updated_at = clock_timestamp()
                 WHERE organization_id = $1 AND project_id = $2
                   AND pipeline_id = $3 AND parent_id = $4",
            )
            .bind(input.organization_id)
            .bind(input.project_id)
            .bind(input.pipeline_id)
            .bind(input.parent_id)
            .bind(generation)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        let parent = self
            .discovery_parent(
                input.organization_id,
                input.project_id,
                input.pipeline_id,
                input.parent_id,
            )
            .await?
            .ok_or_else(|| {
                StoreError::DiscoveryConflict("committed discovery parent is missing".to_owned())
            })?;
        Ok(if created {
            DiscoveryParentPutOutcome::Created(parent)
        } else {
            DiscoveryParentPutOutcome::Revised(parent)
        })
    }

    pub async fn reconcile_discovery_scan(
        &self,
        input: &DiscoveryScanWrite,
    ) -> Result<DiscoveryScanOutcome, StoreError> {
        validate_scan(input)?;
        let request_sha256 = compute_discovery_scan_request_sha256(input)?;
        if request_sha256 != input.expected_request_sha256 {
            return invalid("discovery scan digest does not match canonical content");
        }
        let mut tx = self.tenant_transaction(input.organization_id).await?;
        lock_parent(&mut tx, input.organization_id, input.parent_id).await?;
        if let Some(row) = sqlx::query(
            "SELECT scan.organization_id, scan.project_id, scan.pipeline_id,
                    scan.parent_id, scan.parent_generation, scan.scan_id,
                    scan.source_kind, scan.source_event_id, scan.source_cursor,
                    scan.complete_snapshot, scan.provider_snapshot_sha256,
                    scan.request_sha256, scan.observation_count,
                    result.active_count, result.quarantined_count, result.retired_count,
                    result.selected_count,
                    scan.audit_sequence, scan.audit_event_hash
             FROM discovery_scans AS scan
             JOIN discovery_scan_results AS result
               ON result.organization_id = scan.organization_id
              AND result.parent_id = scan.parent_id AND result.scan_id = scan.scan_id
             WHERE scan.organization_id = $1 AND scan.parent_id = $2 AND scan.scan_id = $3",
        )
        .bind(input.organization_id)
        .bind(input.parent_id)
        .bind(&input.scan_id)
        .fetch_optional(&mut *tx)
        .await?
        {
            let receipt = scan_receipt_from_row(row)?;
            if receipt.request_sha256 != request_sha256 {
                return conflict("discovery scan identity was reused for different content");
            }
            tx.commit().await?;
            return Ok(DiscoveryScanOutcome::Replayed(receipt));
        }
        if let Some(event_id) = &input.source_event_id
            && let Some(row) = sqlx::query(
                "SELECT scan.organization_id, scan.project_id, scan.pipeline_id,
                        scan.parent_id, scan.parent_generation, scan.scan_id,
                        scan.source_kind, scan.source_event_id, scan.source_cursor,
                        scan.complete_snapshot, scan.provider_snapshot_sha256,
                        scan.request_sha256, scan.observation_count,
                        result.active_count, result.quarantined_count, result.retired_count,
                        result.selected_count,
                        scan.audit_sequence, scan.audit_event_hash
                 FROM discovery_scans AS scan
                 JOIN discovery_scan_results AS result
                   ON result.organization_id = scan.organization_id
                  AND result.parent_id = scan.parent_id AND result.scan_id = scan.scan_id
                 WHERE scan.organization_id = $1 AND scan.parent_id = $2
                   AND scan.source_event_id = $3",
            )
            .bind(input.organization_id)
            .bind(input.parent_id)
            .bind(event_id)
            .fetch_optional(&mut *tx)
            .await?
        {
            let receipt = scan_receipt_from_row(row)?;
            if receipt.request_sha256 != request_sha256 {
                return conflict("discovery source event was replayed with different content");
            }
            tx.commit().await?;
            return Ok(DiscoveryScanOutcome::Replayed(receipt));
        }

        let parent_row = sqlx::query(&parent_select("d.current_generation", false))
            .bind(input.organization_id)
            .bind(input.project_id)
            .bind(input.pipeline_id)
            .bind(input.parent_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| {
                StoreError::DiscoveryConflict("discovery parent does not exist".to_owned())
            })?;
        let parent = parent_from_row(parent_row)?;
        if parent.generation != input.expected_parent_generation {
            return conflict("discovery parent generation changed before scan reconciliation");
        }
        if parent.state != DiscoveryParentState::Enabled {
            return Err(StoreError::DiscoveryQuiesced {
                parent_id: input.parent_id,
                generation: parent.generation,
            });
        }
        validate_live_authorities(&mut tx, &parent).await?;
        let last_cursor = sqlx::query_scalar::<_, i64>(
            "SELECT COALESCE(MAX(source_cursor), 0) FROM discovery_scans
             WHERE organization_id = $1 AND parent_id = $2",
        )
        .bind(input.organization_id)
        .bind(input.parent_id)
        .fetch_one(&mut *tx)
        .await?;
        if input.source_cursor <= last_cursor {
            return conflict("discovery source cursor is duplicate or reordered");
        }

        let evaluated = evaluate_observations(&parent, &input.observations)?;
        let selected_count = evaluated
            .iter()
            .filter(|(_, _, disposition)| *disposition != DiscoveryObservationDisposition::Filtered)
            .count();
        let audit = crate::audit::append_audit_record(
            &mut tx,
            input.organization_id,
            "discovery",
            &input.actor_subject,
            "discovery.scan.reconciled",
            &format!(
                "pipeline:{}:discovery-parent:{}:scan:{}",
                input.pipeline_id, input.parent_id, input.scan_id
            ),
            json!({
                "project_id": input.project_id,
                "pipeline_id": input.pipeline_id,
                "parent_id": input.parent_id,
                "parent_generation": parent.generation,
                "scan_id": input.scan_id,
                "source": input.source.as_str(),
                "source_event_id": input.source_event_id,
                "source_cursor": input.source_cursor,
                "complete_snapshot": input.complete_snapshot,
                "provider_snapshot_sha256": hex::encode(input.provider_snapshot_sha256),
                "request_sha256": hex::encode(request_sha256),
                "reported_observations": input.observations.len(),
                "selected_observations": selected_count,
            }),
        )
        .await?;
        sqlx::query(
            "INSERT INTO discovery_scans (
                 organization_id, project_id, pipeline_id, parent_id,
                 parent_generation, scan_id, source_kind, source_event_id,
                 source_cursor, complete_snapshot, provider_snapshot_sha256,
                 request_sha256, observation_count, actor_subject,
                 audit_sequence, audit_event_hash
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
        )
        .bind(input.organization_id)
        .bind(input.project_id)
        .bind(input.pipeline_id)
        .bind(input.parent_id)
        .bind(parent.generation)
        .bind(&input.scan_id)
        .bind(input.source.as_str())
        .bind(&input.source_event_id)
        .bind(input.source_cursor)
        .bind(input.complete_snapshot)
        .bind(input.provider_snapshot_sha256.as_slice())
        .bind(request_sha256.as_slice())
        .bind(
            i32::try_from(input.observations.len())
                .map_err(|_| StoreError::InvalidDiscovery("too many observations".to_owned()))?,
        )
        .bind(&input.actor_subject)
        .bind(audit.sequence)
        .bind(audit.event_hash.as_slice())
        .execute(&mut *tx)
        .await?;

        let mut seen = BTreeSet::new();
        for (observation, trusted, disposition) in &evaluated {
            if *disposition != DiscoveryObservationDisposition::Filtered {
                seen.insert(observation.child_key.clone());
            }
            let expected_fork =
                observation.head_repository_identity != observation.repository_identity;
            let retained_mismatch = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS (
                     SELECT 1
                     FROM discovery_observations
                     WHERE organization_id = $1 AND parent_id = $2
                       AND (child_key = $3 OR child_pipeline_id = $4)
                       AND NOT (
                           child_key = $3
                           AND child_pipeline_id = $4
                           AND repository_identity = $5
                           AND ref_kind = $6
                           AND ref_name = $7
                           AND pull_request_number IS NOT DISTINCT FROM $8
                           AND head_repository_identity = $9
                           AND is_fork = $10
                       )
                     LIMIT 1
                 )",
            )
            .bind(input.organization_id)
            .bind(input.parent_id)
            .bind(&observation.child_key)
            .bind(observation.child_pipeline_id)
            .bind(&observation.repository_identity)
            .bind(observation.ref_kind.as_str())
            .bind(&observation.ref_name)
            .bind(observation.pull_request_number)
            .bind(&observation.head_repository_identity)
            .bind(expected_fork)
            .fetch_one(&mut *tx)
            .await?;
            if retained_mismatch {
                return conflict("discovery observation key or pipeline identity was substituted");
            }
            let existing = sqlx::query_as::<_, DiscoveryIdentityRow>(
                "SELECT child_key, child_pipeline_id, repository_identity, ref_kind, ref_name,
                        pull_request_number, head_repository_identity, is_fork
                 FROM discovery_children
                 WHERE organization_id = $1 AND parent_id = $2
                   AND (child_key = $3 OR child_pipeline_id = $4)
                 FOR UPDATE",
            )
            .bind(input.organization_id)
            .bind(input.parent_id)
            .bind(&observation.child_key)
            .bind(observation.child_pipeline_id)
            .fetch_all(&mut *tx)
            .await?;
            if existing.len() > 1
                || existing.iter().any(|existing| {
                    !discovery_identity_matches(existing, observation, expected_fork)
                })
            {
                return conflict("discovery child key or pipeline identity was substituted");
            }
            let authorized = *disposition == DiscoveryObservationDisposition::Active;
            let observation_sha256 = observation_digest(
                observation,
                *trusted,
                authorized,
                *disposition,
                parent.authorization_policy_sha256,
            )?;
            sqlx::query(
                "INSERT INTO discovery_observations (
                     organization_id, project_id, pipeline_id, parent_id, scan_id,
                     child_key, child_pipeline_id, repository_identity, ref_kind,
                     ref_name, pull_request_number, head_repository_identity,
                     is_fork, present, trusted, authorized, disposition, revision,
                     provenance_sha256, jenkinsfile_path, jenkinsfile_sha256,
                     child_configuration_sha256, observation_sha256
                 ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,
                           $16,$17,$18,$19,$20,$21,$22,$23)",
            )
            .bind(input.organization_id)
            .bind(input.project_id)
            .bind(input.pipeline_id)
            .bind(input.parent_id)
            .bind(&input.scan_id)
            .bind(&observation.child_key)
            .bind(observation.child_pipeline_id)
            .bind(&observation.repository_identity)
            .bind(observation.ref_kind.as_str())
            .bind(&observation.ref_name)
            .bind(observation.pull_request_number)
            .bind(&observation.head_repository_identity)
            .bind(observation.head_repository_identity != observation.repository_identity)
            .bind(observation.present)
            .bind(*trusted)
            .bind(authorized)
            .bind(disposition.as_str())
            .bind(&observation.revision)
            .bind(observation.provenance_sha256.as_slice())
            .bind(&observation.jenkinsfile_path)
            .bind(observation.jenkinsfile_sha256.as_slice())
            .bind(observation.child_configuration_sha256.as_slice())
            .bind(observation_sha256.as_slice())
            .execute(&mut *tx)
            .await?;
            match (*disposition, !existing.is_empty()) {
                (DiscoveryObservationDisposition::Filtered, true) => {
                    upsert_child(
                        &mut tx,
                        input,
                        &parent,
                        observation,
                        DiscoveryObservationDisposition::Absent,
                    )
                    .await?;
                }
                (DiscoveryObservationDisposition::Filtered, false) => {}
                (disposition, _) => {
                    upsert_child(&mut tx, input, &parent, observation, disposition).await?;
                }
            }
        }

        if input.complete_snapshot && parent.orphan_policy == OrphanPolicy::Retire {
            let seen = seen.into_iter().collect::<Vec<_>>();
            sqlx::query(
                "UPDATE discovery_children
                 SET state = 'retired', state_generation = state_generation + 1,
                     parent_generation = $3, source_cursor = $4,
                     last_scan_id = $5, updated_at = clock_timestamp()
                 WHERE organization_id = $1 AND parent_id = $2
                   AND state <> 'retired'
                   AND NOT (child_key = ANY($6::text[]))",
            )
            .bind(input.organization_id)
            .bind(input.parent_id)
            .bind(parent.generation)
            .bind(input.source_cursor)
            .bind(&input.scan_id)
            .bind(&seen)
            .execute(&mut *tx)
            .await?;
        }
        let counts = child_counts(&mut tx, input.organization_id, input.parent_id).await?;
        sqlx::query(
            "INSERT INTO discovery_scan_results (
                 organization_id, parent_id, scan_id,
                 active_count, quarantined_count, retired_count, selected_count
             ) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(input.organization_id)
        .bind(input.parent_id)
        .bind(&input.scan_id)
        .bind(
            i32::try_from(counts.0).map_err(|_| {
                StoreError::InvalidDiscovery("active child count overflow".to_owned())
            })?,
        )
        .bind(i32::try_from(counts.1).map_err(|_| {
            StoreError::InvalidDiscovery("quarantined child count overflow".to_owned())
        })?)
        .bind(
            i32::try_from(counts.2).map_err(|_| {
                StoreError::InvalidDiscovery("retired child count overflow".to_owned())
            })?,
        )
        .bind(i32::try_from(selected_count).map_err(|_| {
            StoreError::InvalidDiscovery("selected observation count overflow".to_owned())
        })?)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(DiscoveryScanOutcome::Reconciled(DiscoveryScanReceipt {
            organization_id: input.organization_id,
            project_id: input.project_id,
            pipeline_id: input.pipeline_id,
            parent_id: input.parent_id,
            parent_generation: parent.generation,
            scan_id: input.scan_id.clone(),
            source: input.source,
            source_event_id: input.source_event_id.clone(),
            source_cursor: input.source_cursor,
            complete_snapshot: input.complete_snapshot,
            provider_snapshot_sha256: input.provider_snapshot_sha256,
            request_sha256,
            observation_count: input.observations.len(),
            selected_count,
            active_count: counts.0,
            quarantined_count: counts.1,
            retired_count: counts.2,
            audit_sequence: audit.sequence,
            audit_event_hash: audit.event_hash,
        }))
    }

    pub async fn export_quiesced_discovery_state(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        pipeline_id: Uuid,
        parent_id: Uuid,
        actor_subject: &str,
    ) -> Result<DiscoveryTransferSnapshot, StoreError> {
        validate_text("actor subject", actor_subject, MAX_TEXT_BYTES)?;
        let mut tx = self.tenant_transaction(organization_id).await?;
        lock_parent(&mut tx, organization_id, parent_id).await?;
        let versions = sqlx::query(&format!(
            "{} ORDER BY v.generation",
            parent_select("v.generation", false)
        ))
        .bind(organization_id)
        .bind(project_id)
        .bind(pipeline_id)
        .bind(parent_id)
        .fetch_all(&mut *tx)
        .await?
        .into_iter()
        .map(parent_from_row)
        .collect::<Result<Vec<_>, _>>()?;
        let current_generation = versions
            .last()
            .map(|version| version.generation)
            .ok_or_else(|| {
                StoreError::DiscoveryConflict("discovery parent does not exist".to_owned())
            })?;
        if versions
            .last()
            .is_none_or(|version| version.state != DiscoveryParentState::Quiesced)
        {
            return conflict("discovery parent must be quiesced before transfer export");
        }
        let scans = sqlx::query(
            "SELECT scan.organization_id, scan.project_id, scan.pipeline_id,
                    scan.parent_id, scan.parent_generation, scan.scan_id,
                    scan.source_kind, scan.source_event_id, scan.source_cursor,
                    scan.complete_snapshot, scan.provider_snapshot_sha256,
                    scan.request_sha256, scan.observation_count,
                    result.active_count, result.quarantined_count, result.retired_count,
                    result.selected_count,
                    scan.actor_subject, scan.audit_sequence, scan.audit_event_hash
             FROM discovery_scans AS scan
             JOIN discovery_scan_results AS result
               ON result.organization_id = scan.organization_id
              AND result.parent_id = scan.parent_id AND result.scan_id = scan.scan_id
             WHERE scan.organization_id = $1 AND scan.parent_id = $2
             ORDER BY scan.source_cursor, scan.scan_id",
        )
        .bind(organization_id)
        .bind(parent_id)
        .fetch_all(&mut *tx)
        .await?
        .into_iter()
        .map(scan_record_from_row)
        .collect::<Result<Vec<_>, _>>()?;
        let observations = sqlx::query(
            "SELECT organization_id, project_id, pipeline_id, parent_id, scan_id,
                    child_key, child_pipeline_id, repository_identity, ref_kind,
                    ref_name, pull_request_number, head_repository_identity,
                    is_fork, present, trusted, authorized, disposition, revision,
                    provenance_sha256, jenkinsfile_path, jenkinsfile_sha256,
                    child_configuration_sha256, observation_sha256
             FROM discovery_observations
             WHERE organization_id = $1 AND parent_id = $2
             ORDER BY scan_id, child_key",
        )
        .bind(organization_id)
        .bind(parent_id)
        .fetch_all(&mut *tx)
        .await?
        .into_iter()
        .map(observation_from_row)
        .collect::<Result<Vec<_>, _>>()?;
        let children = sqlx::query(
            "SELECT organization_id, project_id, pipeline_id, parent_id,
                    child_key, child_pipeline_id, repository_identity, ref_kind,
                    ref_name, pull_request_number, head_repository_identity, is_fork,
                    state, state_generation, revision, provenance_sha256,
                    jenkinsfile_path, jenkinsfile_sha256,
                    child_configuration_sha256, parent_generation,
                    source_cursor, last_scan_id
             FROM discovery_children
             WHERE organization_id = $1 AND parent_id = $2 ORDER BY child_key",
        )
        .bind(organization_id)
        .bind(parent_id)
        .fetch_all(&mut *tx)
        .await?
        .into_iter()
        .map(child_from_row)
        .collect::<Result<Vec<_>, _>>()?;
        let placeholder_audit = crate::AuditEvent {
            sequence: 1,
            event_id: Uuid::nil(),
            category: String::new(),
            actor_subject: String::new(),
            action: String::new(),
            subject: String::new(),
            payload: serde_json::Value::Null,
            occurred_at_unix_ms: 0,
            previous_hash: [0; 32],
            event_hash: [0; 32],
        };
        let mut snapshot = DiscoveryTransferSnapshot {
            schema_version: 1,
            organization_id,
            project_id,
            pipeline_id,
            parent_id,
            current_generation,
            versions,
            scans,
            observations,
            children,
            ledger_sha256: [0; 32],
            handoff_audit_event: placeholder_audit,
            audit_sequence: 0,
            audit_event_hash: [0; 32],
            state_sha256: [0; 32],
        };
        snapshot.ledger_sha256 = compute_discovery_transfer_ledger_sha256(&snapshot)?;
        let audit = crate::audit::append_audit_record(
            &mut tx,
            organization_id,
            "discovery",
            actor_subject,
            "discovery.handoff.exported",
            &format!("pipeline:{pipeline_id}:discovery-parent:{parent_id}"),
            json!({
                "project_id": project_id,
                "pipeline_id": pipeline_id,
                "parent_id": parent_id,
                "current_generation": current_generation,
                "ledger_sha256": hex::encode(snapshot.ledger_sha256),
                "scan_count": snapshot.scans.len(),
                "observation_count": snapshot.observations.len(),
                "child_count": snapshot.children.len(),
            }),
        )
        .await?;
        snapshot.audit_sequence = audit.sequence;
        snapshot.audit_event_hash = audit.event_hash;
        snapshot.handoff_audit_event = audit;
        snapshot.state_sha256 = compute_discovery_transfer_snapshot_sha256(&snapshot)?;
        tx.commit().await?;
        Ok(snapshot)
    }

    pub async fn discovery_children(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        pipeline_id: Uuid,
        parent_id: Uuid,
    ) -> Result<Vec<DiscoveryChild>, StoreError> {
        let mut tx = self.tenant_transaction(organization_id).await?;
        let rows = sqlx::query(
            "SELECT organization_id, project_id, pipeline_id, parent_id,
                    child_key, child_pipeline_id, repository_identity, ref_kind,
                    ref_name, pull_request_number, head_repository_identity, is_fork,
                    state, state_generation, revision, provenance_sha256,
                    jenkinsfile_path, jenkinsfile_sha256,
                    child_configuration_sha256, parent_generation,
                    source_cursor, last_scan_id
             FROM discovery_children
             WHERE organization_id = $1 AND project_id = $2
               AND pipeline_id = $3 AND parent_id = $4 ORDER BY child_key",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(pipeline_id)
        .bind(parent_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.into_iter().map(child_from_row).collect()
    }
}

fn same_parent_behavior_write(input: &DiscoveryParentWrite, current: &DiscoveryParent) -> bool {
    input.kind == current.kind
        && input.implementation_sha256 == current.implementation_sha256
        && input.protocol_version == current.protocol_version
        && input.provider == current.provider
        && input.provider_identity == current.provider_identity
        && input.organization_identity == current.organization_identity
        && sorted_owned(&input.repositories) == current.repositories
        && sorted_owned(&input.branch_includes) == current.branch_includes
        && sorted_owned(&input.branch_excludes) == current.branch_excludes
        && input.pull_request_strategy == current.pull_request_strategy
        && input.fork_trust_strategy == current.fork_trust_strategy
        && sorted_owned(&input.trusted_fork_repositories) == current.trusted_fork_repositories
        && input.jenkinsfile_path == current.jenkinsfile_path
        && input.child_configuration_policy_sha256 == current.child_configuration_policy_sha256
        && input.orphan_policy == current.orphan_policy
        && input.authorization_generation == current.authorization_generation
        && input.authorization_policy_sha256 == current.authorization_policy_sha256
        && input.trigger_id == current.trigger_id
        && input.trigger_generation == current.trigger_generation
        && input.trigger_configuration_sha256 == current.trigger_configuration_sha256
        && input.source_implementation_sha256 == current.source_implementation_sha256
        && input.source_protocol_version == current.source_protocol_version
        && input.source_configuration_sha256 == current.source_configuration_sha256
        && input.restored_from_generation == current.restored_from_generation
}

fn same_parent_behavior(left: &DiscoveryParent, right: &DiscoveryParent) -> bool {
    left.kind == right.kind
        && left.implementation_sha256 == right.implementation_sha256
        && left.protocol_version == right.protocol_version
        && left.provider == right.provider
        && left.provider_identity == right.provider_identity
        && left.organization_identity == right.organization_identity
        && left.repositories == right.repositories
        && left.branch_includes == right.branch_includes
        && left.branch_excludes == right.branch_excludes
        && left.pull_request_strategy == right.pull_request_strategy
        && left.fork_trust_strategy == right.fork_trust_strategy
        && left.trusted_fork_repositories == right.trusted_fork_repositories
        && left.jenkinsfile_path == right.jenkinsfile_path
        && left.child_configuration_policy_sha256 == right.child_configuration_policy_sha256
        && left.orphan_policy == right.orphan_policy
        && left.authorization_generation == right.authorization_generation
        && left.authorization_policy_sha256 == right.authorization_policy_sha256
        && left.trigger_id == right.trigger_id
        && left.trigger_generation == right.trigger_generation
        && left.trigger_configuration_sha256 == right.trigger_configuration_sha256
        && left.source_implementation_sha256 == right.source_implementation_sha256
        && left.source_protocol_version == right.source_protocol_version
        && left.source_configuration_sha256 == right.source_configuration_sha256
        && left.restored_from_generation == right.restored_from_generation
}

fn validate_parent_write(input: &DiscoveryParentWrite) -> Result<(), StoreError> {
    if input.expected_generation < 0
        || input.authorization_generation <= 0
        || input.trigger_generation <= 0
    {
        return invalid("discovery generation bindings are invalid");
    }
    for (name, digest) in [
        ("implementation", input.implementation_sha256),
        ("configuration", input.expected_configuration_sha256),
        ("child policy", input.child_configuration_policy_sha256),
        ("authorization policy", input.authorization_policy_sha256),
        ("trigger configuration", input.trigger_configuration_sha256),
        ("source implementation", input.source_implementation_sha256),
        ("source configuration", input.source_configuration_sha256),
    ] {
        validate_digest(name, digest)?;
    }
    validate_text("protocol version", &input.protocol_version, 128)?;
    validate_text(
        "source protocol version",
        &input.source_protocol_version,
        128,
    )?;
    validate_text(
        "provider identity",
        &input.provider_identity,
        MAX_TEXT_BYTES,
    )?;
    if !matches!(
        input.provider.as_str(),
        "github" | "gitlab" | "bitbucket" | "gitea"
    ) {
        return invalid("discovery provider is unsupported");
    }
    if let Some(value) = &input.organization_identity {
        validate_text("organization identity", value, MAX_TEXT_BYTES)?;
    }
    validate_text("Jenkinsfile path", &input.jenkinsfile_path, MAX_PATH_BYTES)?;
    validate_relative_path(&input.jenkinsfile_path)?;
    validate_text("actor subject", &input.actor_subject, MAX_TEXT_BYTES)?;
    validate_text("reason", &input.reason, MAX_REASON_BYTES)?;
    validate_text("idempotency key", &input.idempotency_key, 256)?;
    for (name, values) in [
        ("repositories", &input.repositories),
        ("branch includes", &input.branch_includes),
        ("branch excludes", &input.branch_excludes),
        (
            "trusted fork repositories",
            &input.trusted_fork_repositories,
        ),
    ] {
        validate_string_set(name, values)?;
    }
    if input.repositories.is_empty() {
        return invalid("discovery repository set must be non-empty");
    }
    if input.kind == DiscoveryParentKind::OrganizationFolder
        && input.organization_identity.is_none()
    {
        return invalid("organization-folder discovery requires an organization identity");
    }
    if input.fork_trust_strategy != ForkTrustStrategy::NamedRepositories
        && !input.trusted_fork_repositories.is_empty()
    {
        return invalid("named trusted forks require the named-repositories trust strategy");
    }
    if input.fork_trust_strategy == ForkTrustStrategy::NamedRepositories
        && input.trusted_fork_repositories.is_empty()
    {
        return invalid("named-repositories trust strategy requires at least one repository");
    }
    Ok(())
}

fn validate_scan(input: &DiscoveryScanWrite) -> Result<(), StoreError> {
    if input.expected_parent_generation <= 0 || input.source_cursor <= 0 {
        return invalid("discovery scan generation and cursor must be positive");
    }
    validate_text("scan id", &input.scan_id, MAX_TEXT_BYTES)?;
    validate_text("actor subject", &input.actor_subject, MAX_TEXT_BYTES)?;
    validate_digest("provider snapshot", input.provider_snapshot_sha256)?;
    validate_digest("request", input.expected_request_sha256)?;
    match input.source {
        DiscoveryScanSource::Webhook
            if input.source_event_id.is_some() && !input.complete_snapshot => {}
        DiscoveryScanSource::Periodic | DiscoveryScanSource::Recovery
            if input.source_event_id.is_none() && input.complete_snapshot => {}
        _ => {
            return invalid(
                "webhook scans must be deltas with an event; periodic/recovery scans must be complete snapshots",
            );
        }
    }
    if let Some(event_id) = &input.source_event_id {
        validate_text("source event id", event_id, MAX_TEXT_BYTES)?;
    }
    if input.observations.len() > MAX_SET_ITEMS {
        return invalid("discovery scan exceeds the observation bound");
    }
    let mut child_keys = BTreeSet::new();
    let mut pipeline_ids = BTreeSet::new();
    for observation in &input.observations {
        validate_observation(observation)?;
        if !child_keys.insert(&observation.child_key)
            || !pipeline_ids.insert(observation.child_pipeline_id)
        {
            return invalid("discovery scan repeats a child identity");
        }
    }
    Ok(())
}

fn validate_observation(input: &DiscoveryObservationWrite) -> Result<(), StoreError> {
    validate_text("child key", &input.child_key, MAX_PATH_BYTES)?;
    validate_text(
        "repository identity",
        &input.repository_identity,
        MAX_TEXT_BYTES,
    )?;
    validate_text("ref name", &input.ref_name, MAX_TEXT_BYTES)?;
    validate_text(
        "head repository identity",
        &input.head_repository_identity,
        MAX_TEXT_BYTES,
    )?;
    validate_text("revision", &input.revision, 128)?;
    if input.revision.len() < 7 || !input.revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return invalid(
            "discovered revision must be a 7-128 character hexadecimal object identity",
        );
    }
    validate_text("Jenkinsfile path", &input.jenkinsfile_path, MAX_PATH_BYTES)?;
    validate_relative_path(&input.jenkinsfile_path)?;
    for (name, digest) in [
        ("provenance", input.provenance_sha256),
        ("Jenkinsfile", input.jenkinsfile_sha256),
        ("child configuration", input.child_configuration_sha256),
    ] {
        validate_digest(name, digest)?;
    }
    match (input.ref_kind, input.pull_request_number) {
        (DiscoveredRefKind::Branch, None) => {}
        (DiscoveredRefKind::PullRequest, Some(value)) if value > 0 => {}
        _ => return invalid("branch and pull-request identities are inconsistent"),
    }
    Ok(())
}

async fn lock_and_validate_dependencies(
    tx: &mut Transaction<'_, Postgres>,
    input: &DiscoveryParentWrite,
) -> Result<(), StoreError> {
    let pipeline_exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (
             SELECT 1 FROM pipeline_definitions
             WHERE organization_id = $1 AND project_id = $2 AND pipeline_id = $3
         )",
    )
    .bind(input.organization_id)
    .bind(input.project_id)
    .bind(input.pipeline_id)
    .fetch_one(&mut **tx)
    .await?;
    if !pipeline_exists {
        return conflict("discovery parent does not identify a saved pipeline");
    }
    let authorization = sqlx::query_as::<_, (i64, Vec<u8>)>(
        "SELECT current.current_generation, version.policy_digest
         FROM authorization_project_policies AS current
         JOIN authorization_policy_versions AS version
           ON version.organization_id = current.organization_id
          AND version.project_id = current.project_id
          AND version.generation = current.current_generation
         WHERE current.organization_id = $1 AND current.project_id = $2 FOR UPDATE OF current",
    )
    .bind(input.organization_id)
    .bind(input.project_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((generation, digest)) = authorization else {
        return conflict("discovery parent requires an installed authorization policy");
    };
    if generation != input.authorization_generation
        || digest_array(&digest)? != input.authorization_policy_sha256
    {
        return conflict("discovery authorization generation or digest was substituted");
    }
    let trigger = sqlx::query_as::<_, (i64, String, String, Vec<u8>, String, String)>(
        "SELECT definition.current_generation, version.trigger_kind, version.state,
                version.configuration_sha256, version.event_source_identity,
                version.configuration ->> 'provider'
         FROM pipeline_trigger_definitions AS definition
         JOIN pipeline_trigger_versions AS version
           ON version.organization_id = definition.organization_id
          AND version.trigger_id = definition.trigger_id
          AND version.generation = definition.current_generation
         WHERE definition.organization_id = $1 AND definition.project_id = $2
           AND definition.pipeline_id = $3 AND definition.trigger_id = $4
         FOR UPDATE OF definition",
    )
    .bind(input.organization_id)
    .bind(input.project_id)
    .bind(input.pipeline_id)
    .bind(input.trigger_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((generation, kind, state, digest, source_identity, provider)) = trigger else {
        return conflict("discovery parent requires a saved SCM webhook trigger");
    };
    if generation != input.trigger_generation
        || kind != "scm_webhook"
        || state != "enabled"
        || digest_array(&digest)? != input.trigger_configuration_sha256
        || source_identity != input.provider_identity
        || provider != input.provider
    {
        return conflict(
            "discovery trigger generation, configuration, state, provider, or provider identity was substituted",
        );
    }
    Ok(())
}

async fn validate_live_authorities(
    tx: &mut Transaction<'_, Postgres>,
    parent: &DiscoveryParent,
) -> Result<(), StoreError> {
    let authorization = sqlx::query_as::<_, (i64, Vec<u8>)>(
        "SELECT current.current_generation, version.policy_digest
         FROM authorization_project_policies AS current
         JOIN authorization_policy_versions AS version
           ON version.organization_id = current.organization_id
          AND version.project_id = current.project_id
          AND version.generation = current.current_generation
         WHERE current.organization_id = $1 AND current.project_id = $2 FOR UPDATE OF current",
    )
    .bind(parent.organization_id)
    .bind(parent.project_id)
    .fetch_optional(&mut **tx)
    .await?;
    let authorization_matches = match authorization {
        Some((generation, digest)) => {
            generation == parent.authorization_generation
                && digest_array(&digest)? == parent.authorization_policy_sha256
        }
        None => false,
    };
    if !authorization_matches {
        return conflict("discovery authorization authority drifted before reconciliation");
    }
    let trigger = sqlx::query_as::<_, (i64, String, String, Vec<u8>, String, String)>(
        "SELECT definition.current_generation, version.trigger_kind, version.state,
                version.configuration_sha256, version.event_source_identity,
                version.configuration ->> 'provider'
         FROM pipeline_trigger_definitions AS definition
         JOIN pipeline_trigger_versions AS version
           ON version.organization_id = definition.organization_id
          AND version.trigger_id = definition.trigger_id
          AND version.generation = definition.current_generation
         WHERE definition.organization_id = $1 AND definition.trigger_id = $2
           AND definition.project_id = $3 AND definition.pipeline_id = $4
         FOR UPDATE OF definition",
    )
    .bind(parent.organization_id)
    .bind(parent.trigger_id)
    .bind(parent.project_id)
    .bind(parent.pipeline_id)
    .fetch_optional(&mut **tx)
    .await?;
    let trigger_matches = match trigger {
        Some((generation, kind, state, digest, source_identity, provider)) => {
            generation == parent.trigger_generation
                && kind == "scm_webhook"
                && state == "enabled"
                && digest_array(&digest)? == parent.trigger_configuration_sha256
                && source_identity == parent.provider_identity
                && provider == parent.provider
        }
        None => false,
    };
    if !trigger_matches {
        return conflict("discovery trigger authority drifted before reconciliation");
    }
    Ok(())
}

fn evaluate_observations<'a>(
    parent: &DiscoveryParent,
    observations: &'a [DiscoveryObservationWrite],
) -> Result<
    Vec<(
        &'a DiscoveryObservationWrite,
        bool,
        DiscoveryObservationDisposition,
    )>,
    StoreError,
> {
    let repositories = parent.repositories.iter().collect::<BTreeSet<_>>();
    let trusted_forks = parent
        .trusted_fork_repositories
        .iter()
        .collect::<BTreeSet<_>>();
    let mut evaluated = Vec::new();
    for observation in observations {
        let is_fork = observation.head_repository_identity != observation.repository_identity;
        if observation.ref_kind == DiscoveredRefKind::Branch && is_fork {
            return invalid("branch observation cannot substitute a fork head repository");
        }
        if !repositories.contains(&observation.repository_identity)
            || !matches_branch_filters(parent, &observation.ref_name)
            || observation.jenkinsfile_path != parent.jenkinsfile_path
        {
            evaluated.push((
                observation,
                false,
                DiscoveryObservationDisposition::Filtered,
            ));
            continue;
        }
        if observation.ref_kind == DiscoveredRefKind::PullRequest {
            match parent.pull_request_strategy {
                PullRequestDiscoveryStrategy::None => {
                    evaluated.push((
                        observation,
                        false,
                        DiscoveryObservationDisposition::Filtered,
                    ));
                    continue;
                }
                PullRequestDiscoveryStrategy::OriginOnly if is_fork => {
                    evaluated.push((
                        observation,
                        false,
                        DiscoveryObservationDisposition::Filtered,
                    ));
                    continue;
                }
                PullRequestDiscoveryStrategy::OriginOnly
                | PullRequestDiscoveryStrategy::OriginAndForks => {}
            }
        }
        let trusted = !is_fork
            || match parent.fork_trust_strategy {
                ForkTrustStrategy::None => false,
                ForkTrustStrategy::NamedRepositories => {
                    trusted_forks.contains(&observation.head_repository_identity)
                }
                ForkTrustStrategy::All => true,
            };
        let disposition = if !observation.present {
            DiscoveryObservationDisposition::Absent
        } else if trusted {
            DiscoveryObservationDisposition::Active
        } else {
            DiscoveryObservationDisposition::Quarantined
        };
        evaluated.push((observation, trusted, disposition));
    }
    Ok(evaluated)
}

fn matches_branch_filters(parent: &DiscoveryParent, name: &str) -> bool {
    let included = parent.branch_includes.is_empty()
        || parent
            .branch_includes
            .iter()
            .any(|prefix| name.starts_with(prefix));
    let excluded = parent
        .branch_excludes
        .iter()
        .any(|prefix| name.starts_with(prefix));
    included && !excluded
}

async fn upsert_child(
    tx: &mut Transaction<'_, Postgres>,
    scan: &DiscoveryScanWrite,
    parent: &DiscoveryParent,
    observation: &DiscoveryObservationWrite,
    disposition: DiscoveryObservationDisposition,
) -> Result<(), StoreError> {
    let state = match disposition {
        DiscoveryObservationDisposition::Active => DiscoveryChildState::Active,
        DiscoveryObservationDisposition::Quarantined => DiscoveryChildState::Quarantined,
        DiscoveryObservationDisposition::Absent => DiscoveryChildState::Retired,
        DiscoveryObservationDisposition::Filtered => {
            return invalid("filtered observation cannot materialize a discovery child");
        }
    };
    sqlx::query(
        "INSERT INTO discovery_children (
             organization_id, project_id, pipeline_id, parent_id, child_key,
             child_pipeline_id, repository_identity, ref_kind, ref_name,
             pull_request_number, head_repository_identity, is_fork, state,
             state_generation, revision, provenance_sha256, jenkinsfile_path,
             jenkinsfile_sha256, child_configuration_sha256, parent_generation,
             source_cursor, last_scan_id
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,1,$14,$15,$16,$17,$18,$19,$20,$21)
         ON CONFLICT (organization_id, parent_id, child_key) DO UPDATE
         SET project_id = EXCLUDED.project_id,
             pipeline_id = EXCLUDED.pipeline_id,
             child_pipeline_id = EXCLUDED.child_pipeline_id,
             repository_identity = EXCLUDED.repository_identity,
             ref_kind = EXCLUDED.ref_kind,
             ref_name = EXCLUDED.ref_name,
             pull_request_number = EXCLUDED.pull_request_number,
             head_repository_identity = EXCLUDED.head_repository_identity,
             is_fork = EXCLUDED.is_fork,
             state = EXCLUDED.state,
             state_generation = discovery_children.state_generation + 1,
             revision = EXCLUDED.revision,
             provenance_sha256 = EXCLUDED.provenance_sha256,
             jenkinsfile_path = EXCLUDED.jenkinsfile_path,
             jenkinsfile_sha256 = EXCLUDED.jenkinsfile_sha256,
             child_configuration_sha256 = EXCLUDED.child_configuration_sha256,
             parent_generation = EXCLUDED.parent_generation,
             source_cursor = EXCLUDED.source_cursor,
             last_scan_id = EXCLUDED.last_scan_id,
             updated_at = clock_timestamp()",
    )
    .bind(scan.organization_id)
    .bind(scan.project_id)
    .bind(scan.pipeline_id)
    .bind(scan.parent_id)
    .bind(&observation.child_key)
    .bind(observation.child_pipeline_id)
    .bind(&observation.repository_identity)
    .bind(observation.ref_kind.as_str())
    .bind(&observation.ref_name)
    .bind(observation.pull_request_number)
    .bind(&observation.head_repository_identity)
    .bind(observation.head_repository_identity != observation.repository_identity)
    .bind(state.as_str())
    .bind(&observation.revision)
    .bind(observation.provenance_sha256.as_slice())
    .bind(&observation.jenkinsfile_path)
    .bind(observation.jenkinsfile_sha256.as_slice())
    .bind(observation.child_configuration_sha256.as_slice())
    .bind(parent.generation)
    .bind(scan.source_cursor)
    .bind(&scan.scan_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn child_counts(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    parent_id: Uuid,
) -> Result<(usize, usize, usize), StoreError> {
    let (active, quarantined, retired) = sqlx::query_as::<_, (i64, i64, i64)>(
        "SELECT COUNT(*) FILTER (WHERE state = 'active'),
                COUNT(*) FILTER (WHERE state = 'quarantined'),
                COUNT(*) FILTER (WHERE state = 'retired')
         FROM discovery_children WHERE organization_id = $1 AND parent_id = $2",
    )
    .bind(organization_id)
    .bind(parent_id)
    .fetch_one(&mut **tx)
    .await?;
    Ok((
        usize::try_from(active).unwrap_or(usize::MAX),
        usize::try_from(quarantined).unwrap_or(usize::MAX),
        usize::try_from(retired).unwrap_or(usize::MAX),
    ))
}

fn scan_receipt_from_row(row: sqlx::postgres::PgRow) -> Result<DiscoveryScanReceipt, StoreError> {
    let organization_id: Uuid = row.try_get("organization_id")?;
    let parent_id: Uuid = row.try_get("parent_id")?;
    let source = match row.try_get::<String, _>("source_kind")?.as_str() {
        "webhook" => DiscoveryScanSource::Webhook,
        "periodic" => DiscoveryScanSource::Periodic,
        "recovery" => DiscoveryScanSource::Recovery,
        value => return invalid(format!("stored discovery scan source '{value}' is invalid")),
    };
    Ok(DiscoveryScanReceipt {
        organization_id,
        project_id: row.try_get("project_id")?,
        pipeline_id: row.try_get("pipeline_id")?,
        parent_id,
        parent_generation: row.try_get("parent_generation")?,
        scan_id: row.try_get("scan_id")?,
        source,
        source_event_id: row.try_get("source_event_id")?,
        source_cursor: row.try_get("source_cursor")?,
        complete_snapshot: row.try_get("complete_snapshot")?,
        provider_snapshot_sha256: digest_array(
            &row.try_get::<Vec<u8>, _>("provider_snapshot_sha256")?,
        )?,
        request_sha256: digest_array(&row.try_get::<Vec<u8>, _>("request_sha256")?)?,
        observation_count: usize::try_from(row.try_get::<i32, _>("observation_count")?).map_err(
            |_| StoreError::InvalidDiscovery("stored observation count is invalid".to_owned()),
        )?,
        selected_count: usize::try_from(row.try_get::<i32, _>("selected_count")?).map_err(
            |_| StoreError::InvalidDiscovery("stored selected count is invalid".to_owned()),
        )?,
        active_count: usize::try_from(row.try_get::<i32, _>("active_count")?).map_err(|_| {
            StoreError::InvalidDiscovery("stored active child count is invalid".to_owned())
        })?,
        quarantined_count: usize::try_from(row.try_get::<i32, _>("quarantined_count")?).map_err(
            |_| {
                StoreError::InvalidDiscovery("stored quarantined child count is invalid".to_owned())
            },
        )?,
        retired_count: usize::try_from(row.try_get::<i32, _>("retired_count")?).map_err(|_| {
            StoreError::InvalidDiscovery("stored retired child count is invalid".to_owned())
        })?,
        audit_sequence: row.try_get("audit_sequence")?,
        audit_event_hash: digest_array(&row.try_get::<Vec<u8>, _>("audit_event_hash")?)?,
    })
}

fn parent_select(generation: &str, idempotency: bool) -> String {
    let idempotency_predicate = if idempotency {
        " AND v.idempotency_key = $5"
    } else {
        ""
    };
    format!(
        "SELECT d.organization_id, d.project_id, d.pipeline_id, d.parent_id,
                v.generation, v.parent_kind, v.state, v.implementation_sha256,
                v.protocol_version, v.configuration_sha256, v.provider,
                v.provider_identity, v.organization_identity, v.repositories,
                v.branch_includes, v.branch_excludes, v.pull_request_strategy,
                v.fork_trust_strategy, v.trusted_fork_repositories,
                v.jenkinsfile_path, v.child_configuration_policy_sha256,
                v.orphan_policy, v.authorization_generation,
                v.authorization_policy_sha256, v.trigger_id, v.trigger_generation,
                v.trigger_configuration_sha256, v.source_implementation_sha256,
                v.source_protocol_version, v.source_configuration_sha256,
                v.restored_from_generation, v.actor_subject, v.reason,
                v.idempotency_key, v.audit_sequence, v.audit_event_hash
         FROM discovery_parent_definitions AS d
         JOIN discovery_parent_versions AS v
           ON v.organization_id = d.organization_id AND v.parent_id = d.parent_id
          AND v.generation = {generation}
         WHERE d.organization_id = $1 AND d.project_id = $2
           AND d.pipeline_id = $3 AND d.parent_id = $4{idempotency_predicate}"
    )
}

fn parent_from_row(row: sqlx::postgres::PgRow) -> Result<DiscoveryParent, StoreError> {
    Ok(DiscoveryParent {
        organization_id: row.try_get("organization_id")?,
        project_id: row.try_get("project_id")?,
        pipeline_id: row.try_get("pipeline_id")?,
        parent_id: row.try_get("parent_id")?,
        generation: row.try_get("generation")?,
        kind: DiscoveryParentKind::parse(&row.try_get::<String, _>("parent_kind")?)?,
        state: DiscoveryParentState::parse(&row.try_get::<String, _>("state")?)?,
        implementation_sha256: digest_array(&row.try_get::<Vec<u8>, _>("implementation_sha256")?)?,
        protocol_version: row.try_get("protocol_version")?,
        configuration_sha256: digest_array(&row.try_get::<Vec<u8>, _>("configuration_sha256")?)?,
        provider: row.try_get("provider")?,
        provider_identity: row.try_get("provider_identity")?,
        organization_identity: row.try_get("organization_identity")?,
        repositories: json_strings(row.try_get("repositories")?)?,
        branch_includes: json_strings(row.try_get("branch_includes")?)?,
        branch_excludes: json_strings(row.try_get("branch_excludes")?)?,
        pull_request_strategy: PullRequestDiscoveryStrategy::parse(
            &row.try_get::<String, _>("pull_request_strategy")?,
        )?,
        fork_trust_strategy: ForkTrustStrategy::parse(
            &row.try_get::<String, _>("fork_trust_strategy")?,
        )?,
        trusted_fork_repositories: json_strings(row.try_get("trusted_fork_repositories")?)?,
        jenkinsfile_path: row.try_get("jenkinsfile_path")?,
        child_configuration_policy_sha256: digest_array(
            &row.try_get::<Vec<u8>, _>("child_configuration_policy_sha256")?,
        )?,
        orphan_policy: OrphanPolicy::parse(&row.try_get::<String, _>("orphan_policy")?)?,
        authorization_generation: row.try_get("authorization_generation")?,
        authorization_policy_sha256: digest_array(
            &row.try_get::<Vec<u8>, _>("authorization_policy_sha256")?,
        )?,
        trigger_id: row.try_get("trigger_id")?,
        trigger_generation: row.try_get("trigger_generation")?,
        trigger_configuration_sha256: digest_array(
            &row.try_get::<Vec<u8>, _>("trigger_configuration_sha256")?,
        )?,
        source_implementation_sha256: digest_array(
            &row.try_get::<Vec<u8>, _>("source_implementation_sha256")?,
        )?,
        source_protocol_version: row.try_get("source_protocol_version")?,
        source_configuration_sha256: digest_array(
            &row.try_get::<Vec<u8>, _>("source_configuration_sha256")?,
        )?,
        restored_from_generation: row.try_get("restored_from_generation")?,
        actor_subject: row.try_get("actor_subject")?,
        reason: row.try_get("reason")?,
        idempotency_key: row.try_get("idempotency_key")?,
        audit_sequence: row.try_get("audit_sequence")?,
        audit_event_hash: digest_array(&row.try_get::<Vec<u8>, _>("audit_event_hash")?)?,
    })
}

fn child_from_row(row: sqlx::postgres::PgRow) -> Result<DiscoveryChild, StoreError> {
    Ok(DiscoveryChild {
        organization_id: row.try_get("organization_id")?,
        project_id: row.try_get("project_id")?,
        pipeline_id: row.try_get("pipeline_id")?,
        parent_id: row.try_get("parent_id")?,
        child_key: row.try_get("child_key")?,
        child_pipeline_id: row.try_get("child_pipeline_id")?,
        repository_identity: row.try_get("repository_identity")?,
        ref_kind: DiscoveredRefKind::parse(&row.try_get::<String, _>("ref_kind")?)?,
        ref_name: row.try_get("ref_name")?,
        pull_request_number: row.try_get("pull_request_number")?,
        head_repository_identity: row.try_get("head_repository_identity")?,
        is_fork: row.try_get("is_fork")?,
        state: DiscoveryChildState::parse(&row.try_get::<String, _>("state")?)?,
        state_generation: row.try_get("state_generation")?,
        revision: row.try_get("revision")?,
        provenance_sha256: digest_array(&row.try_get::<Vec<u8>, _>("provenance_sha256")?)?,
        jenkinsfile_path: row.try_get("jenkinsfile_path")?,
        jenkinsfile_sha256: digest_array(&row.try_get::<Vec<u8>, _>("jenkinsfile_sha256")?)?,
        child_configuration_sha256: digest_array(
            &row.try_get::<Vec<u8>, _>("child_configuration_sha256")?,
        )?,
        parent_generation: row.try_get("parent_generation")?,
        source_cursor: row.try_get("source_cursor")?,
        last_scan_id: row.try_get("last_scan_id")?,
    })
}

fn scan_record_from_row(row: sqlx::postgres::PgRow) -> Result<DiscoveryScanRecord, StoreError> {
    let source = match row.try_get::<String, _>("source_kind")?.as_str() {
        "webhook" => DiscoveryScanSource::Webhook,
        "periodic" => DiscoveryScanSource::Periodic,
        "recovery" => DiscoveryScanSource::Recovery,
        value => return invalid(format!("stored discovery scan source '{value}' is invalid")),
    };
    Ok(DiscoveryScanRecord {
        organization_id: row.try_get("organization_id")?,
        project_id: row.try_get("project_id")?,
        pipeline_id: row.try_get("pipeline_id")?,
        parent_id: row.try_get("parent_id")?,
        parent_generation: row.try_get("parent_generation")?,
        scan_id: row.try_get("scan_id")?,
        source,
        source_event_id: row.try_get("source_event_id")?,
        source_cursor: row.try_get("source_cursor")?,
        complete_snapshot: row.try_get("complete_snapshot")?,
        provider_snapshot_sha256: digest_array(
            &row.try_get::<Vec<u8>, _>("provider_snapshot_sha256")?,
        )?,
        request_sha256: digest_array(&row.try_get::<Vec<u8>, _>("request_sha256")?)?,
        observation_count: usize::try_from(row.try_get::<i32, _>("observation_count")?).map_err(
            |_| StoreError::InvalidDiscovery("stored observation count is invalid".to_owned()),
        )?,
        selected_count: usize::try_from(row.try_get::<i32, _>("selected_count")?).map_err(
            |_| StoreError::InvalidDiscovery("stored selected count is invalid".to_owned()),
        )?,
        active_count: usize::try_from(row.try_get::<i32, _>("active_count")?).map_err(|_| {
            StoreError::InvalidDiscovery("stored active child count is invalid".to_owned())
        })?,
        quarantined_count: usize::try_from(row.try_get::<i32, _>("quarantined_count")?).map_err(
            |_| {
                StoreError::InvalidDiscovery("stored quarantined child count is invalid".to_owned())
            },
        )?,
        retired_count: usize::try_from(row.try_get::<i32, _>("retired_count")?).map_err(|_| {
            StoreError::InvalidDiscovery("stored retired child count is invalid".to_owned())
        })?,
        actor_subject: row.try_get("actor_subject")?,
        audit_sequence: row.try_get("audit_sequence")?,
        audit_event_hash: digest_array(&row.try_get::<Vec<u8>, _>("audit_event_hash")?)?,
    })
}

fn observation_from_row(row: sqlx::postgres::PgRow) -> Result<DiscoveryObservation, StoreError> {
    Ok(DiscoveryObservation {
        organization_id: row.try_get("organization_id")?,
        project_id: row.try_get("project_id")?,
        pipeline_id: row.try_get("pipeline_id")?,
        parent_id: row.try_get("parent_id")?,
        scan_id: row.try_get("scan_id")?,
        child_key: row.try_get("child_key")?,
        child_pipeline_id: row.try_get("child_pipeline_id")?,
        repository_identity: row.try_get("repository_identity")?,
        ref_kind: DiscoveredRefKind::parse(&row.try_get::<String, _>("ref_kind")?)?,
        ref_name: row.try_get("ref_name")?,
        pull_request_number: row.try_get("pull_request_number")?,
        head_repository_identity: row.try_get("head_repository_identity")?,
        is_fork: row.try_get("is_fork")?,
        present: row.try_get("present")?,
        trusted: row.try_get("trusted")?,
        authorized: row.try_get("authorized")?,
        disposition: DiscoveryObservationDisposition::parse(
            &row.try_get::<String, _>("disposition")?,
        )?,
        revision: row.try_get("revision")?,
        provenance_sha256: digest_array(&row.try_get::<Vec<u8>, _>("provenance_sha256")?)?,
        jenkinsfile_path: row.try_get("jenkinsfile_path")?,
        jenkinsfile_sha256: digest_array(&row.try_get::<Vec<u8>, _>("jenkinsfile_sha256")?)?,
        child_configuration_sha256: digest_array(
            &row.try_get::<Vec<u8>, _>("child_configuration_sha256")?,
        )?,
        observation_sha256: digest_array(&row.try_get::<Vec<u8>, _>("observation_sha256")?)?,
    })
}

fn observation_digest(
    observation: &DiscoveryObservationWrite,
    trusted: bool,
    authorized: bool,
    disposition: DiscoveryObservationDisposition,
    authorization_policy_sha256: [u8; 32],
) -> Result<[u8; 32], StoreError> {
    canonical_sha256(&json!({
        "schema": "mcloving.discovery-observation/v1",
        "observation": observation,
        "trusted": trusted,
        "authorized": authorized,
        "disposition": disposition,
        "authorization_policy_sha256": authorization_policy_sha256,
    }))
}

async fn lock_parent(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    parent_id: Uuid,
) -> Result<(), StoreError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("discovery:{organization_id}:{parent_id}"))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

fn validate_relative_path(value: &str) -> Result<(), StoreError> {
    if value.starts_with('/')
        || value.ends_with('/')
        || value.contains('\\')
        || value
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return invalid("Jenkinsfile path must be a normalized relative path");
    }
    Ok(())
}

fn discovery_identity_matches(
    existing: &DiscoveryIdentityRow,
    observation: &DiscoveryObservationWrite,
    expected_fork: bool,
) -> bool {
    existing.0 == observation.child_key
        && existing.1 == observation.child_pipeline_id
        && existing.2 == observation.repository_identity
        && existing.3 == observation.ref_kind.as_str()
        && existing.4 == observation.ref_name
        && existing.5 == observation.pull_request_number
        && existing.6 == observation.head_repository_identity
        && existing.7 == expected_fork
}

fn validate_string_set(name: &str, values: &[String]) -> Result<(), StoreError> {
    if values.len() > MAX_SET_ITEMS {
        return invalid(format!("{name} exceeds its item bound"));
    }
    let mut unique = BTreeSet::new();
    for value in values {
        validate_text(name, value, MAX_TEXT_BYTES)?;
        if !unique.insert(value) {
            return invalid(format!("{name} contains duplicates"));
        }
    }
    // PostgreSQL renders JSONB array separators as `, `, while serde_json's
    // compact representation uses `,`. Account for those spaces so validation
    // exactly fences the migration's `octet_length(value::text)` constraint.
    let compact_bytes = serde_json::to_vec(values)
        .map_err(|error| StoreError::InvalidDiscovery(error.to_string()))?
        .len();
    let database_text_bytes = compact_bytes
        .checked_add(values.len().saturating_sub(1))
        .ok_or_else(|| {
            StoreError::InvalidDiscovery(format!("{name} exceeds its serialized size bound"))
        })?;
    if database_text_bytes > MAX_JSONB_TEXT_BYTES {
        return invalid(format!("{name} exceeds its serialized size bound"));
    }
    Ok(())
}

fn validate_text(name: &str, value: &str, maximum: usize) -> Result<(), StoreError> {
    if value.is_empty()
        || value.trim() != value
        || value.len() > maximum
        || value.chars().any(char::is_control)
    {
        return invalid(format!("{name} is outside its bounds"));
    }
    Ok(())
}

fn validate_digest(name: &str, digest: [u8; 32]) -> Result<(), StoreError> {
    if digest == [0; 32] {
        return invalid(format!("{name} digest cannot be all zeroes"));
    }
    Ok(())
}

fn canonical_sha256<T: Serialize>(value: &T) -> Result<[u8; 32], StoreError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| StoreError::InvalidDiscovery(error.to_string()))?;
    Ok(Sha256::digest(bytes).into())
}

fn sorted_refs(values: &[String]) -> Vec<&str> {
    let mut values = values.iter().map(String::as_str).collect::<Vec<_>>();
    values.sort_unstable();
    values
}

fn sorted_owned(values: &[String]) -> Vec<String> {
    let mut values = values.to_vec();
    values.sort();
    values
}

fn json_strings(value: serde_json::Value) -> Result<Vec<String>, StoreError> {
    serde_json::from_value(value).map_err(|error| {
        StoreError::InvalidDiscovery(format!("stored string set is invalid: {error}"))
    })
}

fn digest_array(bytes: &[u8]) -> Result<[u8; 32], StoreError> {
    bytes
        .try_into()
        .map_err(|_| StoreError::InvalidDiscovery("stored digest has an invalid length".to_owned()))
}

fn invalid<T>(message: impl Into<String>) -> Result<T, StoreError> {
    Err(StoreError::InvalidDiscovery(message.into()))
}

fn conflict<T>(message: impl Into<String>) -> Result<T, StoreError> {
    Err(StoreError::DiscoveryConflict(message.into()))
}
