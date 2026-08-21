//! Fail-closed verification for the DIFF-002 Jenkins/McLoving state and policy
//! differential. The verifier grants no execution or effect authority; it
//! certifies only the exact immutable observations in the admitted bundle.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::Path;

use serde::Deserialize;
use sha2::{Digest, Sha256};

pub const SCHEMA: &str = "mcloving.jenkins.state-policy-differential/v1";
pub const CASE: &str = "mig005a-state-policy-exact-profile";
pub const EVIDENCE_FILE: &str = "state-policy.json";
pub const EVIDENCE_SHA256: &str =
    "70607ab0b64cb35c5b875dea7b1f94db14e6df7e931671e2f96828e1c7a52a78";
pub const JENKINS_IMAGE_SHA256: &str =
    "f4f65e6cd1405cd889b7f5ac33f9d5cdc2a099de6b87fe8a3933b9c5d53d1d02";
pub const POSTGRES_IMAGE_SHA256: &str =
    "ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94";
pub const MIG005A_FORWARD_SHA256: &str =
    "af172be8893e282b72fc20b820382c8236e18c7b981bc3b4acbf57884ead55e4";
pub const MIG005A_REVERSE_SHA256: &str =
    "1a66f2c6354011abd23f45671674291e0b22faeea1043791920fc5ee0123ef52";
pub const MIG005A_EVIDENCE_SHA256: &str =
    "e28b47d2aa70ec2ad8cdaa2c48e1100c8862c9a47765d22a355c1660e96cafe7";
pub const IDP001_IMPLEMENTATION_HEAD: &str = "1da73ee8362e5977b922e531cf03f89cfc760e6f";
pub const AUTHZ001_IMPLEMENTATION_HEAD: &str = "8b9b11dcb6a51f491b3c052beb7cdf2282e55702";
pub const JOBSTATE001_IMPLEMENTATION_HEAD: &str = "4c07ad57f50d694965d2fb6b2e43f7888afda200";
pub const AUDIT001_REVIEW_SHA256: &str =
    "12b8839ebc44bfde3467d66d5c4567872da52c25a828721d9292420c7155337c";

const MAX_EVIDENCE_BYTES: u64 = 1_048_576;
const MAX_MANIFEST_BYTES: u64 = 256;
const REQUIRED_ACTIONS: [&str; 4] = [
    "project_view",
    "build_trigger",
    "build_cancel",
    "project_configure",
];
const REQUIRED_INGRESS: [&str; 5] = ["api", "manual", "schedule", "upstream", "webhook"];
const REQUIRED_SCENARIOS: [&str; 20] = [
    "approval_expiry_denied",
    "approval_identity_denied",
    "approval_value_substitution_denied",
    "deleted_identity_reuse_denied",
    "disable_race_fenced",
    "disabled_api_ingress",
    "disabled_manual_ingress",
    "disabled_schedule_ingress",
    "disabled_upstream_ingress",
    "disabled_webhook_ingress",
    "first_authoritative_run_effect_free",
    "group_change_fences_stale_generation",
    "history_gap_denied",
    "hold_omission_denied",
    "hold_release_denied",
    "rename_preserves_immutable_identity",
    "restart_preserves_state",
    "reverse_reconciliation_exact",
    "rollback_restores_state",
    "same_name_collision_denied",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationReceipt {
    pub schema: &'static str,
    pub case: &'static str,
    pub principals: usize,
    pub decisions: usize,
    pub operational_cases: usize,
    pub adversarial_scenarios: usize,
    pub evidence_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationError {
    pub code: &'static str,
    pub message: String,
}

impl VerificationError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for VerificationError {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    schema: String,
    case: String,
    frozen: FrozenEvidence,
    principals: Vec<PrincipalMapping>,
    operational_cases: Vec<OperationalCase>,
    history: HistoryPair,
    adversarial_scenarios: Vec<Scenario>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrozenEvidence {
    jenkins_image_sha256: String,
    postgres_image_sha256: String,
    mig005a_forward_sha256: String,
    mig005a_reverse_sha256: String,
    mig005a_evidence_sha256: String,
    idp001_implementation_head: String,
    authz001_implementation_head: String,
    jobstate001_implementation_head: String,
    audit001_review: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrincipalMapping {
    name: String,
    source: SourceIdentity,
    target: TargetIdentity,
    decisions: Vec<DecisionComparison>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceIdentity {
    realm_digest: String,
    immutable_id: String,
    aliases: Vec<String>,
    membership_generation: u64,
    lifecycle: Lifecycle,
    acl_entry_id: String,
    acl_scope: String,
    acl_generation: String,
    replacement_immutable_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetIdentity {
    issuer: String,
    external_subject: String,
    principal_id: String,
    lifecycle: Lifecycle,
    lifecycle_generation: u64,
    group_generation: u64,
    provenance_digest: String,
    replacement_external_subject: Option<String>,
    replacement_principal_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Lifecycle {
    Active,
    Disabled,
    Deleted,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionComparison {
    action: String,
    source: Decision,
    target: Decision,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Decision {
    Allow,
    Deny,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationalCase {
    name: String,
    source: OperationalObservation,
    target: OperationalObservation,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct OperationalObservation {
    state: OperationalState,
    generation: u64,
    ingress: Vec<IngressObservation>,
    queued_builds: u64,
    grants: u64,
    approvals: u64,
    effects: u64,
    audit_outcome: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum OperationalState {
    Enabled,
    Disabled,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct IngressObservation {
    kind: String,
    outcome: IngressOutcome,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum IngressOutcome {
    Accepted,
    RejectedBeforeQueue,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryPair {
    source: HistoryObservation,
    target: HistoryObservation,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct HistoryObservation {
    build_numbers: Vec<u64>,
    next_build_number: u64,
    previous_result: String,
    scm_revisions: Vec<String>,
    predicate_selected: Vec<bool>,
    cross_build_artifacts: BTreeMap<String, String>,
    retained_workspace_digest: String,
    persistent_state_digest: String,
    retention_deadline_unix_ms: u64,
    active_holds: Vec<HoldObservation>,
    approval: ApprovalObservation,
    retry_history: Vec<RetryObservation>,
    first_authoritative_run: FirstAuthoritativeRun,
    restart_digest: String,
    rollback_digest: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct HoldObservation {
    id: String,
    generation: u64,
    release_authority: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ApprovalObservation {
    approval_id: String,
    approver_subject: String,
    submitted_value_digests: BTreeMap<String, String>,
    expires_at_unix_ms: u64,
    expired_submission: Decision,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct RetryObservation {
    node: String,
    outcomes: Vec<String>,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct FirstAuthoritativeRun {
    build_number: u64,
    external_effect_authority: bool,
    result: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Scenario {
    name: String,
    source_outcome: ScenarioOutcome,
    target_outcome: ScenarioOutcome,
    expected_outcome: ScenarioOutcome,
    queued_builds: u64,
    grants: u64,
    approvals: u64,
    effects: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ScenarioOutcome {
    Denied,
    Preserved,
}

pub fn verify_bundle(root: &Path) -> Result<VerificationReceipt, VerificationError> {
    verify_tree(root)?;
    let bytes = fs::read(root.join(EVIDENCE_FILE))
        .map_err(|error| VerificationError::new("E_IO", error.to_string()))?;
    verify_evidence_bytes(&bytes)
}

/// Verifies already authenticated evidence bytes without reopening a path.
pub fn verify_evidence_bytes(bytes: &[u8]) -> Result<VerificationReceipt, VerificationError> {
    if bytes.len() as u64 > MAX_EVIDENCE_BYTES {
        return Err(VerificationError::new(
            "E_SIZE",
            "evidence exceeds byte ceiling",
        ));
    }
    let evidence_sha256 = sha256(bytes);
    if evidence_sha256 != EVIDENCE_SHA256 {
        return Err(VerificationError::new(
            "E_EVIDENCE_DIGEST",
            "state-policy evidence does not match the compiled detached digest",
        ));
    }
    let evidence: Evidence = serde_json::from_slice(bytes)
        .map_err(|error| VerificationError::new("E_SCHEMA", error.to_string()))?;

    let decisions = verify_evidence(&evidence)?;

    Ok(VerificationReceipt {
        schema: SCHEMA,
        case: CASE,
        principals: evidence.principals.len(),
        decisions,
        operational_cases: evidence.operational_cases.len(),
        adversarial_scenarios: evidence.adversarial_scenarios.len(),
        evidence_sha256,
    })
}

fn verify_evidence(evidence: &Evidence) -> Result<usize, VerificationError> {
    verify_frozen(evidence)?;
    let decisions = verify_principals(&evidence.principals)?;
    verify_operational_cases(&evidence.operational_cases)?;
    verify_history(&evidence.history)?;
    verify_scenarios(&evidence.adversarial_scenarios)?;
    Ok(decisions)
}

fn verify_tree(root: &Path) -> Result<(), VerificationError> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| VerificationError::new("E_IO", error.to_string()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(VerificationError::new(
            "E_TREE",
            "bundle root must be a directory",
        ));
    }
    let mut names = Vec::new();
    for entry in
        fs::read_dir(root).map_err(|error| VerificationError::new("E_IO", error.to_string()))?
    {
        let entry = entry.map_err(|error| VerificationError::new("E_IO", error.to_string()))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| VerificationError::new("E_TREE", "non-UTF-8 bundle entry"))?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| VerificationError::new("E_IO", error.to_string()))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(VerificationError::new(
                "E_TREE",
                "bundle entries must be regular files",
            ));
        }
        names.push(name);
    }
    names.sort();
    if names != ["SHA256SUMS", EVIDENCE_FILE] {
        return Err(VerificationError::new(
            "E_TREE",
            "bundle file set is not exact",
        ));
    }
    let manifest_path = root.join("SHA256SUMS");
    let manifest_metadata = fs::symlink_metadata(&manifest_path)
        .map_err(|error| VerificationError::new("E_MANIFEST", error.to_string()))?;
    if manifest_metadata.len() > MAX_MANIFEST_BYTES {
        return Err(VerificationError::new(
            "E_MANIFEST",
            "manifest exceeds byte ceiling",
        ));
    }
    let manifest = fs::read_to_string(manifest_path)
        .map_err(|error| VerificationError::new("E_MANIFEST", error.to_string()))?;
    let expected = format!("{}  {}\n", EVIDENCE_SHA256, EVIDENCE_FILE);
    if manifest != expected {
        return Err(VerificationError::new(
            "E_MANIFEST",
            "manifest is not canonical",
        ));
    }
    Ok(())
}

fn verify_frozen(evidence: &Evidence) -> Result<(), VerificationError> {
    if evidence.schema != SCHEMA || evidence.case != CASE {
        return Err(VerificationError::new(
            "E_IDENTITY",
            "schema or case mismatch",
        ));
    }
    let frozen = &evidence.frozen;
    for (actual, expected, name) in [
        (
            &frozen.jenkins_image_sha256,
            JENKINS_IMAGE_SHA256,
            "Jenkins image",
        ),
        (
            &frozen.postgres_image_sha256,
            POSTGRES_IMAGE_SHA256,
            "PostgreSQL image",
        ),
        (
            &frozen.mig005a_forward_sha256,
            MIG005A_FORWARD_SHA256,
            "forward bundle",
        ),
        (
            &frozen.mig005a_reverse_sha256,
            MIG005A_REVERSE_SHA256,
            "reverse bundle",
        ),
        (
            &frozen.mig005a_evidence_sha256,
            MIG005A_EVIDENCE_SHA256,
            "MIG-005A evidence",
        ),
    ] {
        if actual != expected {
            return Err(VerificationError::new(
                "E_FROZEN",
                format!("{name} digest mismatch"),
            ));
        }
    }
    for (actual, expected, name) in [
        (
            &frozen.idp001_implementation_head,
            IDP001_IMPLEMENTATION_HEAD,
            "IDP-001 implementation head",
        ),
        (
            &frozen.authz001_implementation_head,
            AUTHZ001_IMPLEMENTATION_HEAD,
            "AUTHZ-001 implementation head",
        ),
        (
            &frozen.jobstate001_implementation_head,
            JOBSTATE001_IMPLEMENTATION_HEAD,
            "JOBSTATE-001 implementation head",
        ),
    ] {
        require_git_oid(actual, name)?;
        if actual != expected {
            return Err(VerificationError::new(
                "E_FROZEN",
                format!("{name} mismatch"),
            ));
        }
    }
    require_digest(&frozen.audit001_review, "AUDIT-001 review")?;
    if frozen.audit001_review != AUDIT001_REVIEW_SHA256 {
        return Err(VerificationError::new(
            "E_FROZEN",
            "AUDIT-001 review digest mismatch",
        ));
    }
    Ok(())
}

fn verify_principals(principals: &[PrincipalMapping]) -> Result<usize, VerificationError> {
    if principals.len() != 2 {
        return Err(VerificationError::new(
            "E_PRINCIPAL_DENOMINATOR",
            "expected two principal cases",
        ));
    }
    let mut names = BTreeSet::new();
    let mut source_ids = BTreeSet::new();
    let mut target_ids = BTreeSet::new();
    let mut target_subjects = BTreeSet::new();
    let mut total_decisions = 0;
    for (index, principal) in principals.iter().enumerate() {
        require_text(&principal.name, "principal case")?;
        require_text(&principal.source.immutable_id, "immutable source identity")?;
        require_text(&principal.source.acl_entry_id, "source ACL entry")?;
        require_text(&principal.source.acl_scope, "source ACL scope")?;
        require_text(&principal.source.acl_generation, "source ACL generation")?;
        require_digest(&principal.source.realm_digest, "source realm")?;
        require_text(&principal.target.issuer, "target issuer")?;
        require_text(
            &principal.target.external_subject,
            "target external subject",
        )?;
        require_text(&principal.target.principal_id, "target principal")?;
        require_digest(&principal.target.provenance_digest, "target provenance")?;
        if principal.source.membership_generation == 0
            || principal.target.lifecycle_generation == 0
            || principal.target.group_generation == 0
        {
            return Err(VerificationError::new(
                "E_GENERATION",
                "identity generations must be positive",
            ));
        }
        if principal.source.lifecycle != principal.target.lifecycle {
            return Err(VerificationError::new(
                "E_LIFECYCLE",
                "source and target lifecycle diverge",
            ));
        }
        require_sorted_unique(&principal.source.aliases, "source aliases")?;
        if !names.insert(&principal.name)
            || !source_ids.insert(&principal.source.immutable_id)
            || !target_ids.insert(&principal.target.principal_id)
            || !target_subjects.insert(&principal.target.external_subject)
        {
            return Err(VerificationError::new(
                "E_PRINCIPAL_IDENTITY",
                "principal identities must be unique",
            ));
        }
        let mut actions = Vec::new();
        for decision in &principal.decisions {
            if decision.source != decision.target {
                return Err(VerificationError::new(
                    "E_AUTHORIZATION",
                    format!("{} {} diverges", principal.name, decision.action),
                ));
            }
            actions.push(decision.action.as_str());
        }
        if actions != REQUIRED_ACTIONS {
            return Err(VerificationError::new(
                "E_AUTHORIZATION_DENOMINATOR",
                "required action matrix is incomplete or unordered",
            ));
        }
        let expected_name = if index == 0 {
            "active-renamed-human"
        } else {
            "deleted-name-reuse"
        };
        if principal.name != expected_name {
            return Err(VerificationError::new(
                "E_PRINCIPAL_DENOMINATOR",
                "principal cases are incomplete or unordered",
            ));
        }
        let expected_lifecycle = if index == 0 {
            Lifecycle::Active
        } else {
            Lifecycle::Deleted
        };
        if principal.source.lifecycle != expected_lifecycle {
            return Err(VerificationError::new(
                "E_LIFECYCLE",
                "principal lifecycle does not match its case",
            ));
        }
        match index {
            0 => {
                if principal.source.replacement_immutable_id.is_some()
                    || principal.target.replacement_external_subject.is_some()
                    || principal.target.replacement_principal_id.is_some()
                {
                    return Err(VerificationError::new(
                        "E_PRINCIPAL_IDENTITY",
                        "active principal cannot carry replacement identity bindings",
                    ));
                }
            }
            1 => {
                let replacement_source = principal
                    .source
                    .replacement_immutable_id
                    .as_deref()
                    .ok_or_else(|| {
                        VerificationError::new(
                            "E_PRINCIPAL_IDENTITY",
                            "deleted-name-reuse source replacement binding is missing",
                        )
                    })?;
                let replacement_subject = principal
                    .target
                    .replacement_external_subject
                    .as_deref()
                    .ok_or_else(|| {
                        VerificationError::new(
                            "E_PRINCIPAL_IDENTITY",
                            "deleted-name-reuse replacement subject binding is missing",
                        )
                    })?;
                let replacement_target = principal
                    .target
                    .replacement_principal_id
                    .as_deref()
                    .ok_or_else(|| {
                        VerificationError::new(
                            "E_PRINCIPAL_IDENTITY",
                            "deleted-name-reuse target replacement binding is missing",
                        )
                    })?;
                require_text(replacement_source, "replacement source identity")?;
                require_text(replacement_subject, "replacement external subject")?;
                require_text(replacement_target, "replacement target identity")?;
                if replacement_source == principal.source.immutable_id
                    || replacement_source == principals[0].source.immutable_id
                    || replacement_subject == principal.target.external_subject
                    || replacement_subject == principals[0].target.external_subject
                    || replacement_target == principal.target.principal_id
                    || replacement_target == principals[0].target.principal_id
                {
                    return Err(VerificationError::new(
                        "E_PRINCIPAL_IDENTITY",
                        "replacement identity must be distinct from its deleted predecessor",
                    ));
                }
            }
            _ => unreachable!("principal denominator was checked before iteration"),
        }
        let expected_decisions = if index == 0 {
            [
                Decision::Allow,
                Decision::Deny,
                Decision::Deny,
                Decision::Deny,
            ]
        } else {
            [Decision::Deny; 4]
        };
        if principal
            .decisions
            .iter()
            .map(|decision| decision.target)
            .collect::<Vec<_>>()
            != expected_decisions
        {
            return Err(VerificationError::new(
                "E_AUTHORIZATION",
                "positive/negative decision matrix diverges",
            ));
        }
        if principal.source.lifecycle != Lifecycle::Active
            && principal
                .decisions
                .iter()
                .any(|decision| decision.target != Decision::Deny)
        {
            return Err(VerificationError::new(
                "E_LIFECYCLE_AUTHORITY",
                "inactive principal retained authority",
            ));
        }
        total_decisions += principal.decisions.len();
    }
    Ok(total_decisions)
}

fn verify_operational_cases(cases: &[OperationalCase]) -> Result<(), VerificationError> {
    let required_names = [
        "disabled_generation_2",
        "enabled_generation_1",
        "rollback_enabled_generation_3",
    ];
    let names = cases
        .iter()
        .map(|case| case.name.as_str())
        .collect::<Vec<_>>();
    if names != required_names {
        return Err(VerificationError::new(
            "E_OPERATIONAL_DENOMINATOR",
            "operational cases are incomplete or unordered",
        ));
    }
    for case in cases {
        if case.source != case.target {
            return Err(VerificationError::new(
                "E_OPERATIONAL",
                format!("{} diverges", case.name),
            ));
        }
        if case.source.generation == 0 {
            return Err(VerificationError::new(
                "E_GENERATION",
                "operational generation must be positive",
            ));
        }
        let ingress = case
            .source
            .ingress
            .iter()
            .map(|item| item.kind.as_str())
            .collect::<Vec<_>>();
        if ingress != REQUIRED_INGRESS {
            return Err(VerificationError::new(
                "E_INGRESS_DENOMINATOR",
                "ingress matrix is incomplete or unordered",
            ));
        }
        match case.source.state {
            OperationalState::Disabled => {
                if case
                    .source
                    .ingress
                    .iter()
                    .any(|item| item.outcome != IngressOutcome::RejectedBeforeQueue)
                    || case.source.queued_builds != 0
                    || case.source.grants != 0
                    || case.source.approvals != 0
                    || case.source.effects != 0
                    || case.source.audit_outcome != "pipeline_disabled"
                {
                    return Err(VerificationError::new(
                        "E_DISABLED_AUTHORITY",
                        "disabled state minted authority",
                    ));
                }
            }
            OperationalState::Enabled => {
                if case
                    .source
                    .ingress
                    .iter()
                    .any(|item| item.outcome != IngressOutcome::Accepted)
                    || case.source.audit_outcome != "accepted"
                {
                    return Err(VerificationError::new(
                        "E_ENABLED_INGRESS",
                        "enabled state did not admit all ingress",
                    ));
                }
                if case.source.queued_builds != 5
                    || case.source.grants != 0
                    || case.source.approvals != 0
                    || case.source.effects != 0
                {
                    return Err(VerificationError::new(
                        "E_ENABLED_AUTHORITY",
                        "enabled ingress count or pre-execution authority diverges",
                    ));
                }
            }
        }
        let (expected_state, expected_generation) = match case.name.as_str() {
            "enabled_generation_1" => (OperationalState::Enabled, 1),
            "disabled_generation_2" => (OperationalState::Disabled, 2),
            "rollback_enabled_generation_3" => (OperationalState::Enabled, 3),
            _ => unreachable!("case names were checked before iteration"),
        };
        if case.source.state != expected_state || case.source.generation != expected_generation {
            return Err(VerificationError::new(
                "E_GENERATION",
                "operational state/generation does not match its case",
            ));
        }
    }
    Ok(())
}

fn verify_history(history: &HistoryPair) -> Result<(), VerificationError> {
    if history.source != history.target {
        return Err(VerificationError::new(
            "E_HISTORY",
            "source and target history diverge",
        ));
    }
    let observation = &history.source;
    if observation.build_numbers != [1, 2, 3, 4]
        || observation.next_build_number != 5
        || observation.previous_result != "succeeded"
        || observation.predicate_selected != [false, true, true, false]
    {
        return Err(VerificationError::new(
            "E_HISTORY_SEQUENCE",
            "build/result/predicate baseline diverges",
        ));
    }
    if observation.scm_revisions.len() != 4
        || observation
            .scm_revisions
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != 4
        || observation
            .cross_build_artifacts
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>()
            != ["build-1", "build-2", "build-3", "build-4"]
        || observation
            .cross_build_artifacts
            .values()
            .collect::<BTreeSet<_>>()
            .len()
            != 4
    {
        return Err(VerificationError::new(
            "E_HISTORY_DENOMINATOR",
            "SCM or artifact denominator is incomplete",
        ));
    }
    for (value, name) in observation
        .scm_revisions
        .iter()
        .map(|value| (value, "SCM revision"))
        .chain(
            observation
                .cross_build_artifacts
                .values()
                .map(|value| (value, "artifact")),
        )
        .chain([
            (&observation.retained_workspace_digest, "workspace"),
            (&observation.persistent_state_digest, "persistent state"),
            (&observation.restart_digest, "restart"),
            (&observation.rollback_digest, "rollback"),
        ])
    {
        require_digest(value, name)?;
    }
    if observation.retention_deadline_unix_ms != 2_000_000_000_000
        || observation.active_holds.len() != 3
    {
        return Err(VerificationError::new(
            "E_PROTECTION",
            "retention or hold denominator diverges",
        ));
    }
    let mut prior_hold = None;
    for hold in &observation.active_holds {
        require_text(&hold.id, "hold ID")?;
        require_text(&hold.release_authority, "hold release authority")?;
        if hold.generation == 0 || prior_hold.is_some_and(|prior| prior >= hold.id.as_str()) {
            return Err(VerificationError::new(
                "E_PROTECTION",
                "holds must be positive and strictly sorted",
            ));
        }
        prior_hold = Some(hold.id.as_str());
    }
    if observation
        .active_holds
        .iter()
        .map(|hold| hold.id.as_str())
        .collect::<Vec<_>>()
        != ["hold-artifact", "hold-build", "hold-workspace"]
    {
        return Err(VerificationError::new(
            "E_PROTECTION",
            "active hold identities diverge",
        ));
    }
    require_text(&observation.approval.approval_id, "approval ID")?;
    require_text(&observation.approval.approver_subject, "approver subject")?;
    if observation.approval.expires_at_unix_ms == 0
        || observation.approval.expired_submission != Decision::Deny
        || observation.approval.submitted_value_digests.is_empty()
    {
        return Err(VerificationError::new(
            "E_APPROVAL",
            "approval value/expiry contract is incomplete",
        ));
    }
    for digest in observation.approval.submitted_value_digests.values() {
        require_digest(digest, "approval submitted value")?;
    }
    if observation.retry_history.len() != 4 {
        return Err(VerificationError::new(
            "E_RETRY",
            "retry history denominator is incomplete",
        ));
    }
    let expected_retry_nodes = [
        "checkout",
        "changelog-predicate",
        "changeset-predicate",
        "effect-free-state",
    ];
    for (retry, expected_node) in observation.retry_history.iter().zip(expected_retry_nodes) {
        require_text(&retry.node, "retry node")?;
        if retry.node != expected_node {
            return Err(VerificationError::new(
                "E_RETRY",
                "retry node denominator is incomplete or unordered",
            ));
        }
        let expected = if expected_node == "checkout" {
            ["failed", "succeeded"]
        } else {
            ["fail_fast_skipped", "succeeded"]
        };
        if retry
            .outcomes
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            != expected
        {
            return Err(VerificationError::new(
                "E_RETRY",
                "retry lineage outcome is unknown",
            ));
        }
    }
    if observation.first_authoritative_run.build_number != 3
        || observation
            .first_authoritative_run
            .external_effect_authority
        || observation.first_authoritative_run.result != "succeeded"
    {
        return Err(VerificationError::new(
            "E_FIRST_AUTHORITY",
            "first authoritative run was not effect-free build 3",
        ));
    }
    Ok(())
}

fn verify_scenarios(scenarios: &[Scenario]) -> Result<(), VerificationError> {
    let names = scenarios
        .iter()
        .map(|scenario| scenario.name.as_str())
        .collect::<Vec<_>>();
    if names != REQUIRED_SCENARIOS {
        return Err(VerificationError::new(
            "E_SCENARIO_DENOMINATOR",
            "adversarial scenario set is incomplete or unordered",
        ));
    }
    for scenario in scenarios {
        if scenario.source_outcome != scenario.target_outcome
            || scenario.source_outcome != scenario.expected_outcome
        {
            return Err(VerificationError::new(
                "E_SCENARIO",
                format!("{} diverges", scenario.name),
            ));
        }
        let expected = match scenario.name.as_str() {
            "first_authoritative_run_effect_free"
            | "rename_preserves_immutable_identity"
            | "restart_preserves_state"
            | "reverse_reconciliation_exact"
            | "rollback_restores_state" => ScenarioOutcome::Preserved,
            _ => ScenarioOutcome::Denied,
        };
        if scenario.expected_outcome != expected {
            return Err(VerificationError::new(
                "E_SCENARIO",
                format!("{} has the wrong expected outcome", scenario.name),
            ));
        }
        if scenario.queued_builds != 0
            || scenario.grants != 0
            || scenario.approvals != 0
            || scenario.effects != 0
        {
            return Err(VerificationError::new(
                "E_SCENARIO_AUTHORITY",
                format!("{} minted authority", scenario.name),
            ));
        }
    }
    Ok(())
}

fn require_text(value: &str, name: &str) -> Result<(), VerificationError> {
    if value.is_empty() || value.len() > 1024 || value.trim() != value || value.contains('\0') {
        return Err(VerificationError::new(
            "E_FIELD",
            format!("{name} is not canonical"),
        ));
    }
    Ok(())
}

fn require_digest(value: &str, name: &str) -> Result<(), VerificationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(VerificationError::new(
            "E_DIGEST",
            format!("{name} is not a lowercase SHA-256 digest"),
        ));
    }
    Ok(())
}

fn require_git_oid(value: &str, name: &str) -> Result<(), VerificationError> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(VerificationError::new(
            "E_GIT_OID",
            format!("{name} is not a lowercase 40-character Git object ID"),
        ));
    }
    Ok(())
}

fn require_sorted_unique(values: &[String], name: &str) -> Result<(), VerificationError> {
    if values.is_empty() || values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(VerificationError::new(
            "E_FIELD",
            format!("{name} must be non-empty and strictly sorted"),
        ));
    }
    for value in values {
        require_text(value, name)?;
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use serde_json::Value;

    use super::{Evidence, verify_bundle, verify_evidence};

    fn fixture() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migration/state-policy-differential-v1")
    }

    fn evidence() -> Value {
        serde_json::from_slice(
            &fs::read(fixture().join("state-policy.json")).expect("read exact fixture"),
        )
        .expect("parse exact fixture")
    }

    fn assert_mutation_fails(mutator: impl FnOnce(&mut Value), expected_code: &str) {
        let mut value = evidence();
        mutator(&mut value);
        let mutated: Evidence =
            serde_json::from_value(value).expect("mutation remains schema-valid");
        let error = verify_evidence(&mutated).expect_err("semantic mutation must fail closed");
        assert_eq!(error.code, expected_code);
    }

    #[test]
    fn exact_sealed_bundle_is_certified() {
        let receipt = verify_bundle(&fixture()).expect("verify exact DIFF-002 bundle");
        assert_eq!(receipt.principals, 2);
        assert_eq!(receipt.decisions, 8);
        assert_eq!(receipt.operational_cases, 3);
        assert_eq!(receipt.adversarial_scenarios, 20);
    }

    #[test]
    fn frozen_dependency_substitution_fails_closed() {
        assert_mutation_fails(
            |value| {
                value["frozen"]["mig005a_forward_sha256"] = Value::String("0".repeat(64));
            },
            "E_FROZEN",
        );
        assert_mutation_fails(
            |value| {
                value["frozen"]["idp001_implementation_head"] = Value::String("0".repeat(40));
            },
            "E_FROZEN",
        );
    }

    #[test]
    fn principal_and_decision_substitutions_fail_closed() {
        for (path, replacement, code) in [
            (
                vec!["principals", "0", "target", "lifecycle"],
                Value::String("deleted".to_owned()),
                "E_LIFECYCLE",
            ),
            (
                vec!["principals", "0", "decisions", "0", "target"],
                Value::String("deny".to_owned()),
                "E_AUTHORIZATION",
            ),
            (
                vec!["principals", "1", "decisions", "0", "target"],
                Value::String("allow".to_owned()),
                "E_AUTHORIZATION",
            ),
            (
                vec!["principals", "1", "source", "replacement_immutable_id"],
                Value::String("jenkins-user-deleted-2041".to_owned()),
                "E_PRINCIPAL_IDENTITY",
            ),
        ] {
            assert_mutation_fails(
                |value| {
                    let mut current = value;
                    for component in &path[..path.len() - 1] {
                        current = if let Ok(index) = component.parse::<usize>() {
                            &mut current[index]
                        } else {
                            &mut current[*component]
                        };
                    }
                    current[path[path.len() - 1]] = replacement;
                },
                code,
            );
        }
        assert_mutation_fails(
            |value| {
                value["principals"][0]["decisions"][1]["source"] =
                    Value::String("allow".to_owned());
                value["principals"][0]["decisions"][1]["target"] =
                    Value::String("allow".to_owned());
            },
            "E_AUTHORIZATION",
        );
    }

    #[test]
    fn rename_collision_and_reuse_denominator_is_exact() {
        assert_mutation_fails(
            |value| {
                value["principals"][0]["source"]["immutable_id"] =
                    value["principals"][1]["source"]["immutable_id"].clone();
            },
            "E_PRINCIPAL_IDENTITY",
        );
        assert_mutation_fails(
            |value| {
                value["principals"][0]["source"]["aliases"] =
                    serde_json::json!(["alice.renamed", "alice"]);
            },
            "E_FIELD",
        );
        assert_mutation_fails(
            |value| {
                value["principals"][1]["source"]["lifecycle"] = Value::String("active".to_owned());
                value["principals"][1]["target"]["lifecycle"] = Value::String("active".to_owned());
            },
            "E_LIFECYCLE",
        );
        assert_mutation_fails(
            |value| {
                value["principals"][1]["target"]["external_subject"] =
                    value["principals"][0]["target"]["external_subject"].clone();
            },
            "E_PRINCIPAL_IDENTITY",
        );
        assert_mutation_fails(
            |value| {
                value["adversarial_scenarios"]
                    .as_array_mut()
                    .expect("scenario array")
                    .pop();
            },
            "E_SCENARIO_DENOMINATOR",
        );
    }

    #[test]
    fn disabled_and_stale_generation_authority_fails_closed() {
        assert_mutation_fails(
            |value| {
                value["operational_cases"][0]["target"]["queued_builds"] = Value::from(1_u64);
            },
            "E_OPERATIONAL",
        );
        assert_mutation_fails(
            |value| {
                value["operational_cases"][0]["source"]["effects"] = Value::from(1_u64);
                value["operational_cases"][0]["target"]["effects"] = Value::from(1_u64);
            },
            "E_DISABLED_AUTHORITY",
        );
        assert_mutation_fails(
            |value| {
                let scenario = value["adversarial_scenarios"]
                    .as_array_mut()
                    .expect("scenario array")
                    .iter_mut()
                    .find(|scenario| scenario["name"] == "group_change_fences_stale_generation")
                    .expect("stale generation scenario");
                scenario["grants"] = Value::from(1_u64);
            },
            "E_SCENARIO_AUTHORITY",
        );
        assert_mutation_fails(
            |value| {
                let scenario = value["adversarial_scenarios"]
                    .as_array_mut()
                    .expect("scenario array")
                    .iter_mut()
                    .find(|scenario| scenario["name"] == "history_gap_denied")
                    .expect("history gap scenario");
                scenario["source_outcome"] = Value::String("preserved".to_owned());
                scenario["target_outcome"] = Value::String("preserved".to_owned());
                scenario["expected_outcome"] = Value::String("preserved".to_owned());
            },
            "E_SCENARIO",
        );
        assert_mutation_fails(
            |value| {
                let scenario = value["adversarial_scenarios"]
                    .as_array_mut()
                    .expect("scenario array")
                    .iter_mut()
                    .find(|scenario| scenario["name"] == "restart_preserves_state")
                    .expect("restart scenario");
                scenario["effects"] = Value::from(1_u64);
            },
            "E_SCENARIO_AUTHORITY",
        );
    }

    #[test]
    fn history_gap_hold_approval_retry_and_effect_mutations_fail_closed() {
        for (field, replacement, code) in [
            ("build_numbers", serde_json::json!([1, 2, 4]), "E_HISTORY"),
            ("active_holds", serde_json::json!([]), "E_HISTORY"),
            ("retry_history", serde_json::json!([]), "E_HISTORY"),
        ] {
            assert_mutation_fails(
                |value| {
                    value["history"]["target"][field] = replacement;
                },
                code,
            );
        }
        assert_mutation_fails(
            |value| {
                value["history"]["source"]["approval"]["expired_submission"] =
                    Value::String("allow".to_owned());
                value["history"]["target"]["approval"]["expired_submission"] =
                    Value::String("allow".to_owned());
            },
            "E_APPROVAL",
        );
        assert_mutation_fails(
            |value| {
                value["history"]["source"]["first_authoritative_run"]["external_effect_authority"] =
                    Value::Bool(true);
                value["history"]["target"]["first_authoritative_run"]["external_effect_authority"] =
                    Value::Bool(true);
            },
            "E_FIRST_AUTHORITY",
        );
        assert_mutation_fails(
            |value| {
                for side in ["source", "target"] {
                    value["history"][side]["retry_history"][1]["node"] =
                        Value::String("unknown-node".to_owned());
                }
            },
            "E_RETRY",
        );
        assert_mutation_fails(
            |value| {
                for side in ["source", "target"] {
                    let artifacts = value["history"][side]["cross_build_artifacts"]
                        .as_object_mut()
                        .expect("artifact map");
                    let digest = artifacts.remove("build-4").expect("build-4 digest");
                    artifacts.insert("build-5".to_owned(), digest);
                }
            },
            "E_HISTORY_DENOMINATOR",
        );
        assert_mutation_fails(
            |value| {
                for side in ["source", "target"] {
                    let build_1 =
                        value["history"][side]["cross_build_artifacts"]["build-1"].clone();
                    value["history"][side]["cross_build_artifacts"]["build-4"] = build_1;
                }
            },
            "E_HISTORY_DENOMINATOR",
        );
    }

    #[test]
    fn restart_and_rollback_substitution_fails_closed() {
        for field in ["restart_digest", "rollback_digest"] {
            assert_mutation_fails(
                |value| {
                    value["history"]["target"][field] = Value::String("0".repeat(64));
                },
                "E_HISTORY",
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn extra_files_and_symlinks_fail_closed() {
        use std::os::unix::fs::symlink;

        let extra = tempfile::tempdir().expect("create extra-file bundle");
        copy_fixture(extra.path());
        fs::write(extra.path().join("extra"), b"unexpected").expect("write extra file");
        assert_eq!(
            verify_bundle(extra.path())
                .expect_err("extra file must fail")
                .code,
            "E_TREE"
        );

        let oversized = tempfile::tempdir().expect("create oversized-manifest bundle");
        copy_fixture(oversized.path());
        fs::write(oversized.path().join("SHA256SUMS"), vec![b'a'; 257])
            .expect("write oversized manifest");
        assert_eq!(
            verify_bundle(oversized.path())
                .expect_err("oversized manifest must fail")
                .code,
            "E_MANIFEST"
        );

        let linked = tempfile::tempdir().expect("create symlink bundle");
        fs::copy(
            fixture().join("SHA256SUMS"),
            linked.path().join("SHA256SUMS"),
        )
        .expect("copy manifest");
        symlink(
            fixture().join("state-policy.json"),
            linked.path().join("state-policy.json"),
        )
        .expect("create evidence symlink");
        assert_eq!(
            verify_bundle(linked.path())
                .expect_err("symlink must fail")
                .code,
            "E_TREE"
        );
    }

    fn copy_fixture(destination: &Path) {
        for name in ["SHA256SUMS", "state-policy.json"] {
            fs::copy(fixture().join(name), destination.join(name)).expect("copy fixture file");
        }
    }
}
