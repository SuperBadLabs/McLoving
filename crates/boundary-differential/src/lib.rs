//! Independent fail-closed verification for the DIFF-003 external-boundary
//! differential. The verifier grants no production authority. It certifies
//! only the exact contained observations and zero-authority denominator in the
//! admitted repository bundle.

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::Path;

use serde::Deserialize;
use sha2::{Digest, Sha256};

pub const SCHEMA: &str = "mcloving.jenkins.boundary-differential/v1";
pub const CASE: &str = "mario-contained-boundaries-zero-authority";
pub const EVIDENCE_FILE: &str = "boundary-differential.json";
pub const EVIDENCE_SHA256: &str =
    "d79047f200db9b96eaeecacb6419e9ff40f45fc1b7e26ceffab2393512fb7eb9";

const MAX_EVIDENCE_BYTES: u64 = 262_144;
const MAX_MANIFEST_BYTES: u64 = 256;
const JENKINS_IMAGE_SHA256: &str =
    "f4f65e6cd1405cd889b7f5ac33f9d5cdc2a099de6b87fe8a3933b9c5d53d1d02";
const RUST_IMAGE_SHA256: &str = "77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa";
const POSTGRES_IMAGE_SHA256: &str =
    "ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94";
const RUNTIME_DEPENDENCY_MANIFEST_SHA256: &str =
    "238ed4cc59ff67bbb1dc40bb1bd3ec28dce914c4dffd701f1a8505d760ba11a4";
const IDENTITY_CLIENT_MANIFEST_SHA256: &str =
    "a4227af8021c7d5fb6f7cc72be84af756ce1f95d33cd2ec9bad721beab587549";
const RELEASE_ID: &str = "3d38cc2c-a88b-4fac-aae2-7d9459c36ee5";
const RELEASE_ENVELOPE_SHA256: &str =
    "09fea3d02f5bdb55fd4835a6bf92339eb47cfbba9f33b8b4a3bc4925596e293e";
const RELEASE_EVIDENCE_MANIFEST_SHA256: &str =
    "0ccc39a48217524efe681d984fea41f4f1afe1d3fa1be3177fa4598e6ddf8a41";
const RELEASE_VERIFICATION_RECEIPT_SHA256: &str =
    "6c11cc651b1f4daab6647b43947a433ae565b1a11dfa09cf5cf48e9f789f139f";

const EXPECTED_BOUNDARIES: [(&str, &str, &str); 13] = [
    (
        "TRIG-001",
        "mcloving.trigger-ingress/v1",
        "686f7bdf2312db386fbcb443c312b950fcbb9eba792676abb42fa65427003810",
    ),
    (
        "SCM-001",
        "mcloving.source-acquirer/v1",
        "d7578b04c0ebcfd80e162e5e67a1477d350768710379b6d9f4c9fcc578eec9d8",
    ),
    (
        "SECRET-001",
        "mcloving.secret-grant/v1",
        "600deb4ee224353782f5b5c5c1a3b04075da4e1481c9b00e457c96297b5bea87",
    ),
    (
        "INPUT-001",
        "mcloving.input-adapter/v1",
        "a1bfac3f4d088ce2426fa353c0bf6fe6594a50d1097aab3fe2705f96dcb82441",
    ),
    (
        "PROV-001",
        "mcloving.provisioner.v1",
        "b87c420a8261a7890409e3039df62437580f2338b58da772e785eedc053c462f",
    ),
    (
        "EXT-001",
        "mcloving.external-connector/v1",
        "980c95b72e53d024b7f311768365e504313e9cba4bf4789bd1a3169877cd2d89",
    ),
    (
        "OBS-001",
        "mcloving.destination-observer/v1",
        "430c64296388b64ee735b3594d88b37648ddee24fa2d094a7fbc07c35533a156",
    ),
    (
        "DISC-001",
        "mcloving.discovery/v1",
        "686f7bdf2312db386fbcb443c312b950fcbb9eba792676abb42fa65427003810",
    ),
    (
        "DEP-001",
        "mcloving.dependency-resolver/v1",
        "462d751af4532ee64403c3dedfda35029049a8f5a62f9a688d09707c09eb4a18",
    ),
    (
        "CACHE-001",
        "mcloving.cache/v1",
        "de5a465f540957249a57c7a7da79cbc34d8e01bfc7d4eee23bd83702a2b2a609",
    ),
    (
        "CONSUMER-001",
        "mcloving.external-read-consumer/v1",
        "686f7bdf2312db386fbcb443c312b950fcbb9eba792676abb42fa65427003810",
    ),
    (
        "ADMIN-001",
        "mcloving.external-admin-client/v1",
        "686f7bdf2312db386fbcb443c312b950fcbb9eba792676abb42fa65427003810",
    ),
    (
        "REL-001",
        "mcloving.release-provenance/v2",
        "141f716f1a500829dfbf72ef5f7c59851696ef4e9bde56ea1971bbf73943ba4a",
    ),
];

const EXPECTED_SCENARIOS: [(&str, &str, ScenarioOutcome); 48] = [
    (
        "trigger_substitution_denied",
        "TRIG-001",
        ScenarioOutcome::Denied,
    ),
    ("trigger_replay_denied", "TRIG-001", ScenarioOutcome::Denied),
    (
        "trigger_stale_generation_denied",
        "TRIG-001",
        ScenarioOutcome::Denied,
    ),
    (
        "trigger_attempt_budget_denied",
        "TRIG-001",
        ScenarioOutcome::Denied,
    ),
    (
        "source_revision_substitution_denied",
        "SCM-001",
        ScenarioOutcome::Denied,
    ),
    (
        "source_later_revision_preserved",
        "SCM-001",
        ScenarioOutcome::Preserved,
    ),
    ("source_outage_denied", "SCM-001", ScenarioOutcome::Denied),
    (
        "secret_consumer_substitution_denied",
        "SECRET-001",
        ScenarioOutcome::Denied,
    ),
    (
        "secret_taint_ineligible_denied",
        "SECRET-001",
        ScenarioOutcome::Denied,
    ),
    (
        "secret_marker_disclosure_denied",
        "SECRET-001",
        ScenarioOutcome::Denied,
    ),
    (
        "input_endpoint_substitution_denied",
        "INPUT-001",
        ScenarioOutcome::Denied,
    ),
    ("input_replay_denied", "INPUT-001", ScenarioOutcome::Denied),
    ("input_stale_denied", "INPUT-001", ScenarioOutcome::Denied),
    ("input_outage_denied", "INPUT-001", ScenarioOutcome::Denied),
    (
        "provisioner_template_substitution_denied",
        "PROV-001",
        ScenarioOutcome::Denied,
    ),
    (
        "provisioner_exhaustion_denied",
        "PROV-001",
        ScenarioOutcome::Denied,
    ),
    (
        "provisioner_interruption_reconciled",
        "PROV-001",
        ScenarioOutcome::Reconciled,
    ),
    (
        "provisioner_orphan_cleaned",
        "PROV-001",
        ScenarioOutcome::Cleaned,
    ),
    (
        "provisioner_stale_instance_denied",
        "PROV-001",
        ScenarioOutcome::Denied,
    ),
    (
        "connector_identity_substitution_denied",
        "EXT-001",
        ScenarioOutcome::Denied,
    ),
    (
        "connector_replay_denied",
        "EXT-001",
        ScenarioOutcome::Denied,
    ),
    ("connector_stale_denied", "EXT-001", ScenarioOutcome::Denied),
    (
        "connector_outage_reconciled",
        "EXT-001",
        ScenarioOutcome::Reconciled,
    ),
    (
        "connector_ambiguous_retry_reconciled",
        "EXT-001",
        ScenarioOutcome::Reconciled,
    ),
    (
        "observer_identity_substitution_denied",
        "OBS-001",
        ScenarioOutcome::Denied,
    ),
    ("observer_replay_denied", "OBS-001", ScenarioOutcome::Denied),
    ("observer_stale_denied", "OBS-001", ScenarioOutcome::Denied),
    ("observer_outage_denied", "OBS-001", ScenarioOutcome::Denied),
    (
        "observer_write_permission_denied",
        "OBS-001",
        ScenarioOutcome::Denied,
    ),
    (
        "discovery_config_substitution_denied",
        "DISC-001",
        ScenarioOutcome::Denied,
    ),
    (
        "discovery_replay_denied",
        "DISC-001",
        ScenarioOutcome::Denied,
    ),
    (
        "discovery_stale_denied",
        "DISC-001",
        ScenarioOutcome::Denied,
    ),
    (
        "dependency_resolver_substitution_denied",
        "DEP-001",
        ScenarioOutcome::Denied,
    ),
    (
        "dependency_replay_denied",
        "DEP-001",
        ScenarioOutcome::Denied,
    ),
    (
        "dependency_outage_denied",
        "DEP-001",
        ScenarioOutcome::Denied,
    ),
    (
        "cache_generation_substitution_denied",
        "CACHE-001",
        ScenarioOutcome::Denied,
    ),
    ("cache_replay_denied", "CACHE-001", ScenarioOutcome::Denied),
    ("cache_stale_denied", "CACHE-001", ScenarioOutcome::Denied),
    (
        "consumer_residual_jenkins_read_denied",
        "CONSUMER-001",
        ScenarioOutcome::Denied,
    ),
    (
        "consumer_target_substitution_denied",
        "CONSUMER-001",
        ScenarioOutcome::Denied,
    ),
    (
        "consumer_rollback_restored",
        "CONSUMER-001",
        ScenarioOutcome::Restored,
    ),
    (
        "admin_residual_jenkins_write_denied",
        "ADMIN-001",
        ScenarioOutcome::Denied,
    ),
    (
        "admin_target_substitution_denied",
        "ADMIN-001",
        ScenarioOutcome::Denied,
    ),
    (
        "admin_rollback_restored",
        "ADMIN-001",
        ScenarioOutcome::Restored,
    ),
    (
        "release_artifact_substitution_denied",
        "REL-001",
        ScenarioOutcome::Denied,
    ),
    ("release_replay_denied", "REL-001", ScenarioOutcome::Denied),
    (
        "release_untrusted_key_denied",
        "REL-001",
        ScenarioOutcome::Denied,
    ),
    (
        "release_timestamp_outage_denied",
        "REL-001",
        ScenarioOutcome::Denied,
    ),
];

const EXPECTED_JOINS: [(&str, &str, &str, u64, bool); 11] = [
    ("trigger_capture_to_source", "TRIG-001", "SCM-001", 0, false),
    (
        "source_later_revision_to_dependency",
        "SCM-001",
        "DEP-001",
        0,
        false,
    ),
    (
        "secret_grant_to_connector",
        "SECRET-001",
        "EXT-001",
        1,
        false,
    ),
    (
        "input_capture_to_control_flow",
        "INPUT-001",
        "TRIG-001",
        0,
        false,
    ),
    ("dependency_to_cache", "DEP-001", "CACHE-001", 0, false),
    ("discovery_to_trigger", "DISC-001", "TRIG-001", 0, false),
    (
        "provisioner_to_source_transport",
        "PROV-001",
        "SCM-001",
        0,
        false,
    ),
    ("connector_to_observer", "EXT-001", "OBS-001", 1, false),
    (
        "consumer_cutover_rollback",
        "CONSUMER-001",
        "TRIG-001",
        0,
        true,
    ),
    ("admin_cutover_rollback", "ADMIN-001", "TRIG-001", 0, true),
    ("release_to_connector", "REL-001", "EXT-001", 1, false),
];

const EXPECTED_MARKER_SURFACES: [&str; 11] = [
    "artifact",
    "audit",
    "cache",
    "controller_api",
    "destination_response",
    "log",
    "receipt",
    "retained_state",
    "reverse_transform",
    "test_report",
    "workspace",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationReceipt {
    pub schema: &'static str,
    pub case: &'static str,
    pub boundaries: usize,
    pub scenarios: usize,
    pub joins: usize,
    pub production_boundary_mappings: u64,
    pub duplicate_effects: u64,
    pub secret_marker_disclosures: u64,
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
    authority: AuthorityBoundary,
    network: NetworkBoundary,
    actors: Vec<Actor>,
    boundaries: Vec<Boundary>,
    scenarios: Vec<Scenario>,
    joins: Vec<Join>,
    clients: ClientMigration,
    marker_scan: MarkerScan,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrozenEvidence {
    jenkins_image_sha256: String,
    rust_image_sha256: String,
    postgres_image_sha256: String,
    runtime_dependency_manifest_sha256: String,
    identity_client_manifest_sha256: String,
    release_id: String,
    release_envelope_sha256: String,
    release_evidence_manifest_sha256: String,
    release_verification_receipt_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityBoundary {
    certification_scope: String,
    mario_jobs: u64,
    production_boundary_mappings: u64,
    production_external_effects: u64,
    production_credentials: bool,
    binary_placement_performed: bool,
    production_client_authority: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkBoundary {
    separate_private_stacks: bool,
    external_endpoint_count: u64,
    cross_stack_mount_count: u64,
    shadow_production_endpoint_count: u64,
    public_network_reachable: bool,
    jenkins_destroyed_before_target: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Actor {
    role: String,
    implementation_sha256: String,
    configuration_sha256: String,
    deployment_identity: String,
    service_account_sha256: String,
    permissions: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Boundary {
    id: String,
    protocol: String,
    implementation_source_manifest_sha256: String,
    configuration_sha256: String,
    account_identity: String,
    resource_identity: String,
    content_sha256: String,
    generation: u64,
    positive_receipt_sha256: String,
    fixture_effects: u64,
    production_authority: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ScenarioOutcome {
    Denied,
    Preserved,
    Reconciled,
    Cleaned,
    Restored,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Scenario {
    name: String,
    boundary: String,
    source_outcome: ScenarioOutcome,
    target_outcome: ScenarioOutcome,
    expected_outcome: ScenarioOutcome,
    effect_intents: u64,
    effects: u64,
    duplicate_effects: u64,
    secret_marker_disclosures: u64,
    fresh_observation: bool,
    rollback_restored: bool,
    cleanup_confirmed: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Join {
    name: String,
    source_boundary: String,
    target_boundary: String,
    compatibility_rule: String,
    independent_live_observations: bool,
    fresh_observation: bool,
    effects: u64,
    duplicate_effects: u64,
    rollback_restored: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientMigration {
    inventory_sha256: String,
    client_identity: String,
    production_authority: String,
    fixture_generation: u64,
    fixture_reads_after_cutover: u64,
    fixture_writes_after_cutover: u64,
    fixture_rollback_restored: bool,
    production_cutover_claimed: bool,
    unsupported_operations_retired: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MarkerScan {
    injected_markers: u64,
    disclosed_markers: u64,
    scanned_surfaces: Vec<String>,
}

pub fn verify_bundle(root: &Path) -> Result<VerificationReceipt, VerificationError> {
    verify_tree(root)?;
    let bytes = fs::read(root.join(EVIDENCE_FILE))
        .map_err(|error| VerificationError::new("E_IO", error.to_string()))?;
    if bytes.len() as u64 > MAX_EVIDENCE_BYTES {
        return Err(VerificationError::new(
            "E_SIZE",
            "evidence exceeds byte ceiling",
        ));
    }
    let evidence_sha256 = sha256(&bytes);
    if evidence_sha256 != EVIDENCE_SHA256 {
        return Err(VerificationError::new(
            "E_EVIDENCE_DIGEST",
            "boundary evidence does not match the compiled detached digest",
        ));
    }
    let evidence: Evidence = serde_json::from_slice(&bytes)
        .map_err(|error| VerificationError::new("E_SCHEMA", error.to_string()))?;
    verify_evidence(&evidence)?;
    Ok(VerificationReceipt {
        schema: SCHEMA,
        case: CASE,
        boundaries: evidence.boundaries.len(),
        scenarios: evidence.scenarios.len(),
        joins: evidence.joins.len(),
        production_boundary_mappings: evidence.authority.production_boundary_mappings,
        duplicate_effects: evidence
            .scenarios
            .iter()
            .map(|value| value.duplicate_effects)
            .sum(),
        secret_marker_disclosures: evidence.marker_scan.disclosed_markers,
        evidence_sha256,
    })
}

fn verify_evidence(evidence: &Evidence) -> Result<(), VerificationError> {
    verify_frozen(evidence)?;
    verify_authority(&evidence.authority, &evidence.network)?;
    verify_actors(&evidence.actors)?;
    verify_boundaries(&evidence.boundaries)?;
    verify_scenarios(&evidence.scenarios)?;
    verify_joins(&evidence.joins)?;
    verify_clients(&evidence.clients)?;
    verify_markers(&evidence.marker_scan)?;
    Ok(())
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
    let metadata = fs::symlink_metadata(&manifest_path)
        .map_err(|error| VerificationError::new("E_MANIFEST", error.to_string()))?;
    if metadata.len() > MAX_MANIFEST_BYTES {
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
        (&frozen.rust_image_sha256, RUST_IMAGE_SHA256, "Rust image"),
        (
            &frozen.postgres_image_sha256,
            POSTGRES_IMAGE_SHA256,
            "PostgreSQL image",
        ),
        (
            &frozen.runtime_dependency_manifest_sha256,
            RUNTIME_DEPENDENCY_MANIFEST_SHA256,
            "runtime inventory",
        ),
        (
            &frozen.identity_client_manifest_sha256,
            IDENTITY_CLIENT_MANIFEST_SHA256,
            "client inventory",
        ),
        (
            &frozen.release_envelope_sha256,
            RELEASE_ENVELOPE_SHA256,
            "release envelope",
        ),
        (
            &frozen.release_evidence_manifest_sha256,
            RELEASE_EVIDENCE_MANIFEST_SHA256,
            "release evidence",
        ),
        (
            &frozen.release_verification_receipt_sha256,
            RELEASE_VERIFICATION_RECEIPT_SHA256,
            "release receipt",
        ),
    ] {
        if actual != expected {
            return Err(VerificationError::new(
                "E_FROZEN",
                format!("{name} digest mismatch"),
            ));
        }
        require_digest(actual, name)?;
    }
    if frozen.release_id != RELEASE_ID {
        return Err(VerificationError::new(
            "E_FROZEN",
            "release identity mismatch",
        ));
    }
    Ok(())
}

fn verify_authority(
    authority: &AuthorityBoundary,
    network: &NetworkBoundary,
) -> Result<(), VerificationError> {
    if authority.certification_scope != "contained_fixture_only"
        || authority.mario_jobs != 228
        || authority.production_boundary_mappings != 0
        || authority.production_external_effects != 0
        || authority.production_credentials
        || authority.binary_placement_performed
        || authority.production_client_authority != "jenkins_source"
    {
        return Err(VerificationError::new(
            "E_AUTHORITY",
            "contained zero-authority claim was broadened",
        ));
    }
    if !network.separate_private_stacks
        || network.external_endpoint_count != 0
        || network.cross_stack_mount_count != 0
        || network.shadow_production_endpoint_count != 0
        || network.public_network_reachable
        || !network.jenkins_destroyed_before_target
    {
        return Err(VerificationError::new(
            "E_NETWORK",
            "fixture containment was broadened",
        ));
    }
    Ok(())
}

fn verify_actors(actors: &[Actor]) -> Result<(), VerificationError> {
    let expected = [
        (
            "runner",
            RUST_IMAGE_SHA256,
            "f8546900d13684f886a2fc6dc80a482999fc05072123ba22d82427bfc7a4c21d",
            "diff003-runner-deployment-v1",
            "e1b02115de3b3455ff107cb8d7c1a6f4e05561cef535f52b25c7a73879d82a52",
            ["contained_workspace_transform"].as_slice(),
        ),
        (
            "connector",
            "6ff2c15869581662f7d08311baf654d5758f0e57f2ecc209ee35b82a16bdbcb2",
            "b398032b40f55a726b161f328447a376cd3431a30bbe4bd605d7c993d4c24331",
            "diff003-connector-deployment-v1",
            "149a8b9270dc6f304bf4c485a884703de1805166dae4f2335baf4908bb7aa175",
            ["fixture_destination_write"].as_slice(),
        ),
        (
            "observer",
            "cd8ec1aba2da65c8224b96c7085c354c2249bf7c9543520882c6b9ae01ff22ea",
            "3c241c7db0321e8ab9b8ee25e0714a3edf142d7dd228995c8f210badc3069481",
            "diff003-observer-deployment-v1",
            "b4fc6e3a99860433a8849e9cb72e6e6ab2450507b06d9b6d05a7537bcf49addd",
            ["fixture_destination_read"].as_slice(),
        ),
    ];
    if actors.len() != expected.len() {
        return Err(VerificationError::new(
            "E_ACTOR",
            "actor denominator is incomplete",
        ));
    }
    let mut deployments = BTreeSet::new();
    let mut accounts = BTreeSet::new();
    for (actor, expected) in actors.iter().zip(expected) {
        if actor.role != expected.0
            || actor.implementation_sha256 != expected.1
            || actor.configuration_sha256 != expected.2
            || actor.deployment_identity != expected.3
            || actor.service_account_sha256 != expected.4
            || actor
                .permissions
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                != expected.5
        {
            return Err(VerificationError::new(
                "E_ACTOR",
                format!("{} identity or permission mismatch", actor.role),
            ));
        }
        require_digest(&actor.implementation_sha256, "actor implementation")?;
        require_digest(&actor.configuration_sha256, "actor configuration")?;
        require_digest(&actor.service_account_sha256, "actor account")?;
        if !deployments.insert(actor.deployment_identity.as_str())
            || !accounts.insert(actor.service_account_sha256.as_str())
        {
            return Err(VerificationError::new(
                "E_COLLUSION",
                "runner, connector, and observer identities are not distinct",
            ));
        }
    }
    Ok(())
}

fn verify_boundaries(boundaries: &[Boundary]) -> Result<(), VerificationError> {
    if boundaries.len() != EXPECTED_BOUNDARIES.len() {
        return Err(VerificationError::new(
            "E_BOUNDARY_DENOMINATOR",
            "boundary denominator is incomplete",
        ));
    }
    let mut accounts = BTreeSet::new();
    let mut resources = BTreeSet::new();
    for (boundary, expected) in boundaries.iter().zip(EXPECTED_BOUNDARIES) {
        if boundary.id != expected.0
            || boundary.protocol != expected.1
            || boundary.implementation_source_manifest_sha256 != expected.2
            || boundary.generation != 1
            || boundary.production_authority
        {
            return Err(VerificationError::new(
                "E_BOUNDARY",
                format!("{} identity was substituted", boundary.id),
            ));
        }
        let expected_effects = u64::from(boundary.id == "EXT-001");
        if boundary.fixture_effects != expected_effects {
            return Err(VerificationError::new(
                "E_BOUNDARY_EFFECT",
                format!("{} has the wrong contained effect count", boundary.id),
            ));
        }
        for (value, name) in [
            (
                &boundary.implementation_source_manifest_sha256,
                "boundary implementation",
            ),
            (&boundary.configuration_sha256, "boundary configuration"),
            (&boundary.content_sha256, "boundary content"),
            (&boundary.positive_receipt_sha256, "boundary receipt"),
        ] {
            require_digest(value, name)?;
        }
        require_text(&boundary.account_identity, "boundary account")?;
        require_text(&boundary.resource_identity, "boundary resource")?;
        if !accounts.insert(boundary.account_identity.as_str())
            || !resources.insert(boundary.resource_identity.as_str())
        {
            return Err(VerificationError::new(
                "E_BOUNDARY",
                "boundary account or resource identity collided",
            ));
        }
    }
    Ok(())
}

fn verify_scenarios(scenarios: &[Scenario]) -> Result<(), VerificationError> {
    if scenarios.len() != EXPECTED_SCENARIOS.len() {
        return Err(VerificationError::new(
            "E_SCENARIO_DENOMINATOR",
            "scenario denominator is incomplete",
        ));
    }
    for (scenario, expected) in scenarios.iter().zip(EXPECTED_SCENARIOS) {
        if scenario.name != expected.0
            || scenario.boundary != expected.1
            || scenario.source_outcome != expected.2
            || scenario.target_outcome != expected.2
            || scenario.expected_outcome != expected.2
        {
            return Err(VerificationError::new(
                "E_SCENARIO",
                format!("{} diverges", scenario.name),
            ));
        }
        if scenario.duplicate_effects != 0 || scenario.secret_marker_disclosures != 0 {
            return Err(VerificationError::new(
                "E_SCENARIO_AUTHORITY",
                format!("{} disclosed or duplicated an effect", scenario.name),
            ));
        }
        let ambiguous_retry = scenario.name == "connector_ambiguous_retry_reconciled";
        let cleanup = matches!(expected.2, ScenarioOutcome::Cleaned)
            || scenario.name == "provisioner_interruption_reconciled";
        let rollback = matches!(expected.2, ScenarioOutcome::Restored);
        let fresh = !matches!(expected.2, ScenarioOutcome::Denied);
        if scenario.effect_intents != u64::from(ambiguous_retry)
            || scenario.effects != u64::from(ambiguous_retry)
            || scenario.cleanup_confirmed != cleanup
            || scenario.rollback_restored != rollback
            || scenario.fresh_observation != fresh
        {
            return Err(VerificationError::new(
                "E_SCENARIO_SAFETY",
                format!("{} has an unsafe outcome shape", scenario.name),
            ));
        }
    }
    Ok(())
}

fn verify_joins(joins: &[Join]) -> Result<(), VerificationError> {
    if joins.len() != EXPECTED_JOINS.len() {
        return Err(VerificationError::new(
            "E_JOIN_DENOMINATOR",
            "join denominator is incomplete",
        ));
    }
    for (join, expected) in joins.iter().zip(EXPECTED_JOINS) {
        if join.name != expected.0
            || join.source_boundary != expected.1
            || join.target_boundary != expected.2
            || join.effects != expected.3
            || join.rollback_restored != expected.4
        {
            return Err(VerificationError::new(
                "E_JOIN",
                format!("{} identity or outcome mismatch", join.name),
            ));
        }
        let expected_rule = format!("mcloving.diff003.compatibility/{}/v2", join.name);
        if join.compatibility_rule != expected_rule
            || !join.independent_live_observations
            || !join.fresh_observation
            || join.duplicate_effects != 0
        {
            return Err(VerificationError::new(
                "E_JOIN_PARITY",
                format!("{} failed independent compatibility declaration", join.name),
            ));
        }
    }
    Ok(())
}

fn verify_clients(clients: &ClientMigration) -> Result<(), VerificationError> {
    if clients.inventory_sha256 != IDENTITY_CLIENT_MANIFEST_SHA256
        || clients.client_identity != "owner-operator"
        || clients.production_authority != "jenkins_source"
        || clients.fixture_generation != 3
        || clients.fixture_reads_after_cutover != 0
        || clients.fixture_writes_after_cutover != 0
        || !clients.fixture_rollback_restored
        || clients.production_cutover_claimed
        || clients.unsupported_operations_retired
    {
        return Err(VerificationError::new(
            "E_CLIENT",
            "client cutover or rollback truth was broadened",
        ));
    }
    Ok(())
}

fn verify_markers(markers: &MarkerScan) -> Result<(), VerificationError> {
    if markers.injected_markers != 13
        || markers.disclosed_markers != 0
        || markers
            .scanned_surfaces
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            != EXPECTED_MARKER_SURFACES
    {
        return Err(VerificationError::new(
            "E_MARKER",
            "secret-marker denominator or non-disclosure changed",
        ));
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
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migration/boundary-differential-v1")
    }

    fn value() -> Value {
        serde_json::from_slice(
            &fs::read(fixture().join("boundary-differential.json")).expect("read fixture"),
        )
        .expect("parse fixture")
    }

    fn assert_mutation_fails(mutator: impl FnOnce(&mut Value), expected_code: &str) {
        let mut value = value();
        mutator(&mut value);
        let mutated: Evidence =
            serde_json::from_value(value).expect("mutation remains schema-valid");
        let error = verify_evidence(&mutated).expect_err("semantic mutation must fail closed");
        assert_eq!(error.code, expected_code);
    }

    #[test]
    fn exact_bundle_verifies() {
        let receipt = verify_bundle(&fixture()).expect("verify exact boundary bundle");
        assert_eq!(receipt.boundaries, 13);
        assert_eq!(receipt.scenarios, 48);
        assert_eq!(receipt.joins, 11);
        assert_eq!(receipt.production_boundary_mappings, 0);
        assert_eq!(receipt.duplicate_effects, 0);
        assert_eq!(receipt.secret_marker_disclosures, 0);
    }

    #[test]
    fn frozen_authority_network_and_actor_substitution_fail_closed() {
        assert_mutation_fails(
            |value| value["frozen"]["release_id"] = Value::String("substituted".into()),
            "E_FROZEN",
        );
        assert_mutation_fails(
            |value| value["authority"]["production_boundary_mappings"] = Value::from(1),
            "E_AUTHORITY",
        );
        assert_mutation_fails(
            |value| value["network"]["shadow_production_endpoint_count"] = Value::from(1),
            "E_NETWORK",
        );
        assert_mutation_fails(
            |value| {
                value["actors"][2]["service_account_sha256"] =
                    value["actors"][1]["service_account_sha256"].clone()
            },
            "E_ACTOR",
        );
    }

    #[test]
    fn boundary_scenario_and_join_substitution_fail_closed() {
        assert_mutation_fails(
            |value| {
                value["boundaries"][5]["implementation_source_manifest_sha256"] =
                    Value::String("0".repeat(64))
            },
            "E_BOUNDARY",
        );
        assert_mutation_fails(
            |value| value["scenarios"][0]["effects"] = Value::from(1),
            "E_SCENARIO_SAFETY",
        );
        assert_mutation_fails(
            |value| value["scenarios"][23]["duplicate_effects"] = Value::from(1),
            "E_SCENARIO_AUTHORITY",
        );
        assert_mutation_fails(
            |value| value["joins"][8]["independent_live_observations"] = Value::Bool(false),
            "E_JOIN_PARITY",
        );
    }

    #[test]
    fn residual_client_and_marker_disclosure_fail_closed() {
        assert_mutation_fails(
            |value| value["clients"]["fixture_reads_after_cutover"] = Value::from(1),
            "E_CLIENT",
        );
        assert_mutation_fails(
            |value| value["clients"]["production_cutover_claimed"] = Value::Bool(true),
            "E_CLIENT",
        );
        assert_mutation_fails(
            |value| value["marker_scan"]["disclosed_markers"] = Value::from(1),
            "E_MARKER",
        );
    }

    #[test]
    fn extra_and_symlinked_bundle_entries_fail_closed() {
        let extra = tempfile::tempdir().expect("tempdir");
        for name in ["SHA256SUMS", "boundary-differential.json"] {
            fs::copy(fixture().join(name), extra.path().join(name)).expect("copy fixture");
        }
        fs::write(extra.path().join("extra"), b"extra").expect("write extra");
        assert_eq!(
            verify_bundle(extra.path())
                .expect_err("extra file rejected")
                .code,
            "E_TREE"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let linked = tempfile::tempdir().expect("tempdir");
            fs::copy(
                fixture().join("SHA256SUMS"),
                linked.path().join("SHA256SUMS"),
            )
            .expect("copy manifest");
            symlink(
                fixture().join("boundary-differential.json"),
                linked.path().join("boundary-differential.json"),
            )
            .expect("create symlink");
            assert_eq!(
                verify_bundle(linked.path())
                    .expect_err("symlink rejected")
                    .code,
                "E_TREE"
            );
        }
    }
}
