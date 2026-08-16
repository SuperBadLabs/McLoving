//! Fail-closed SHADOW-001 qualification over one owner-private MIG-007 package.
//!
//! This crate owns no trigger, scheduler, credential, database, controller,
//! agent-protocol, connector, effect, canary, cutover, rollback, or
//! decommission authority. It verifies an owner-private session in memory and
//! returns only bounded counts and booleans.

use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use mcloving_migration_package::{
    MAX_PRIVATE_PACKAGE_BYTES, PrivateVerificationInputs, verify_private,
};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair as _, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

pub const SCHEMA: &str = "mcloving.jenkins.shadow-qualification/private-v1";
pub const DENIAL_RECEIPT_SCHEMA: &str = "mcloving.jenkins.shadow-denial-receipt/v1";
pub const MIG007_PROTECTED_MAIN: &str = "4b2d38a6aa2988d4320731475bfad5a6815ac995";

const MAX_SESSION_BYTES: usize = 262_144;
const JOB_ID: &str = "corpus-052-cinqict_jenkinsdev";
const SOURCE_CONTROLLER: &str = "mario/jenkins-oracle-228";
const SOURCE_DEFINITION_KIND: &str = "org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition";
const INVENTORY_EPOCH: &str = "mario-oracle-20260731T064417Z-r2";
const SOURCE_SHA256: &str = "666ac2275ea75730e27cf7b565d757691b094c508355adc0199d745278a23100";
const PIPELINE_SHA256: &str = "551d489ca13bf5d130bdc5c10ce35e5d3d988bdaa1c5488dd9bc79b30674acdc";
const OPERATIONAL_GENERATION: &str =
    "e76362bbc8e899510b8498808ffd0d2f83bb64d3215cf2c5b31690895f251d97";
const INVENTORY_SHA256: &str = "b1c2f81c74ec0ffc36971f358f920b2d0775c6009f474bea924448cd2a1915c1";
const JENKINS_IMAGE_SHA256: &str =
    "f4f65e6cd1405cd889b7f5ac33f9d5cdc2a099de6b87fe8a3933b9c5d53d1d02";
const JENKINS_PLUGINS_SHA256: &str =
    "e33fa87646e6e360e7614373cc0057ba2e92ff18b9a9ea9419dea796dcb950b0";
const RUST_IMAGE_SHA256: &str = "77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa";
const POSTGRES_IMAGE_SHA256: &str =
    "ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94";
const RELEASE_ID: &str = "3d38cc2c-a88b-4fac-aae2-7d9459c36ee5";
const RELEASE_VERSION: &str = "v0.1.0";
const RELEASE_PROFILE: &str = "private-linux-x86_64";
const RELEASE_ENVELOPE_SHA256: &str =
    "09fea3d02f5bdb55fd4835a6bf92339eb47cfbba9f33b8b4a3bc4925596e293e";
const DIFF001_TRACE_SHA256: &str =
    "e1465ed5261dc046222045657c2f0e1ab774f63bd50d70f5e263bc7a6e94c4f6";
const STDERR_LOG_SHA256: &str = "dd0b88f8948e42d79e88c9fee0a6825c96a07800d0d6cff497d60bf092d4609c";
const STDOUT_LOG_SHA256: &str = "d2a84f4b8b650937ec8f73cd8be2c74add5a911ba64df27458ed8229da804a26";
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const SIGNATURE_DOMAIN: &[u8] = b"mcloving-shadow-denial-receipt-v1\0";
const SOURCE_SESSION_BINDING_SCHEMA: &str = "mcloving.jenkins.shadow-source-session-binding/v1";
const SOURCE_PROBE_SCHEMA: &str = "mcloving.shadow001.jenkins-source-probe/v1";
const TARGET_REPLAY_SCHEMA: &str = "mcloving.shadow001.target-replay/v1";
const TRACE_OBSERVATION_SCHEMA: &str = "mcloving.shadow001.trace-observation/v1";
const ISOLATION_OBSERVATION_SCHEMA: &str = "mcloving.shadow001.isolation-observation/v1";
const CAPTURE_BINDING_SCHEMA: &str = "mcloving.shadow001.capture-binding/v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationReceipt {
    pub schema: &'static str,
    pub session_id: Uuid,
    pub captured_events: usize,
    pub replayed_events: usize,
    pub compared_traces: usize,
    pub mismatches: usize,
    pub packaged_cases: usize,
    pub rejected_cases: usize,
    pub shadow_qualified: bool,
    pub production_authority: bool,
}

pub struct IndependentPins<'a> {
    pub session_sha256: &'a str,
    pub source_capture_public_key_sha256: &'a str,
    pub authz_generation_sha256: &'a str,
    pub verifier_binary_sha256: &'a str,
    pub shadow_implementation_head: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualificationError {
    pub code: &'static str,
    pub message: String,
}

impl QualificationError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for QualificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for QualificationError {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Session {
    schema: String,
    session_id: Uuid,
    ticket: String,
    shadow_implementation_head: String,
    mig007_protected_main: String,
    migration_package_sha256: String,
    freeze: Freeze,
    comparison_inputs: ComparisonInputs,
    events: Vec<PairedEvent>,
    trace: TraceComparison,
    isolation: Isolation,
    authority: Authority,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Freeze {
    source_controller: String,
    inventory_epoch: String,
    inventory_sha256: String,
    job_id: String,
    source_sha256: String,
    pipeline_sha256: String,
    source_state: String,
    source_generation: String,
    target_state: String,
    target_generation: String,
    authz_generation_sha256: String,
    agent_inputs_sha256: String,
    release_id: String,
    release_version: String,
    release_profile: String,
    release_envelope_sha256: String,
    jenkins_image_sha256: String,
    jenkins_plugins_sha256: String,
    rust_image_sha256: String,
    postgres_image_sha256: String,
    verifier_binary_sha256: String,
    source_capture_public_key_base64: String,
    shadow_replay_public_key_base64: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ComparisonInputs {
    captured_wall_clock_unix_ms: i64,
    wall_clock_stream_sha256: String,
    wall_clock_consumption_events: u64,
    semantic_time_dependencies: bool,
    entropy_stream_sha256: String,
    entropy_consumption_events: u64,
    semantic_entropy_dependencies: bool,
    security_entropy_influences_semantics: bool,
    external_input_receipts: u64,
    secret_outcome_receipts: u64,
    connector_outcome_receipts: u64,
    administrative_operation_receipts: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PairedEvent {
    source: SignedDenialReceipt,
    shadow: SignedDenialReceipt,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SignedDenialReceipt {
    schema: String,
    event_id: Uuid,
    event_kind: String,
    capture_sha256: String,
    runner_identity: String,
    state: String,
    generation: String,
    outcome: String,
    replayed: bool,
    queued_builds: u64,
    scheduled_attempts: u64,
    credential_grants: u64,
    connector_requests: u64,
    production_effects: u64,
    audit_sha256: String,
    session_binding_sha256: String,
    signing_public_key_sha256: String,
    signature_base64: String,
}

#[derive(Serialize)]
struct SourceSessionBinding<'a> {
    schema: &'static str,
    session_id: Uuid,
    ticket: &'a str,
    shadow_implementation_head: &'a str,
    mig007_protected_main: &'a str,
    migration_package_sha256: &'a str,
    captured_wall_clock_unix_ms: i64,
    freeze: Freeze,
    comparison_inputs: &'a ComparisonInputs,
    trace: &'a TraceComparison,
    isolation: &'a Isolation,
    authority: &'a Authority,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TraceComparison {
    certified_trace_sha256: String,
    source_trace_sha256: String,
    target_trace_sha256: String,
    source_log: Vec<NormalizedLogEntry>,
    target_log: Vec<NormalizedLogEntry>,
    source_result: String,
    target_result: String,
    artifacts: u64,
    external_effect_intents: u64,
    isolated_replay_executed: bool,
    compared_traces: usize,
    mismatches: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NormalizedLogEntry {
    sequence: u64,
    stream: String,
    content_sha256: String,
    bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Isolation {
    source_fixture_identity: String,
    target_fixture_identity: String,
    source_network_sha256: String,
    target_network_sha256: String,
    reachability_receipt_sha256: String,
    source_and_target_networks_disjoint: bool,
    production_network_requests: u64,
    production_endpoint_mappings: u64,
    production_credentials: u64,
    host_mounts: u64,
    cross_fixture_mounts: u64,
    teardown_complete: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Authority {
    trigger: bool,
    scheduler: bool,
    controller_database: bool,
    controller_filesystem: bool,
    agent_protocol: bool,
    credentials: bool,
    connector: bool,
    external_effects: bool,
    canary: bool,
    cutover: bool,
    rollback: bool,
    decommission: bool,
}

/// Exact inputs accepted from the independently reviewed SHADOW-001 runtime
/// sidecar when it prepares the source-authenticated, shadow-unsigned session
/// template. Durable publication and complete MIG-007 verification remain the
/// responsibility of the `seal` operation.
pub struct SourceTemplateInputs<'a> {
    pub source_probe_bytes: &'a [u8],
    pub target_replay_bytes: &'a [u8],
    pub trace_observation_bytes: &'a [u8],
    pub isolation_observation_bytes: &'a [u8],
    pub private_package_bytes: &'a [u8],
    pub expected_private_package_sha256: &'a str,
    pub source_capture_pkcs8: &'a [u8],
    pub expected_source_capture_public_key_sha256: &'a str,
    pub shadow_replay_public_key_base64: &'a str,
    pub authz_generation_sha256: &'a str,
    pub verifier_binary_sha256: &'a str,
    pub shadow_implementation_head: &'a str,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ActivityObservation {
    builds: u64,
    queued: u64,
    next_build_number: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceIngressObservation {
    kind: String,
    path: String,
    outcome: String,
    queued_builds: u64,
    scheduled_attempts: u64,
    credential_grants: u64,
    connector_requests: u64,
    production_effects: u64,
    detail: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceProbe {
    schema: String,
    job_id: String,
    source_state: String,
    definition_kind: String,
    source_sha256: String,
    source_config_sha256: String,
    captured_wall_clock_unix_ms: i64,
    original_activity: ActivityObservation,
    terminal_activity: ActivityObservation,
    observations: Vec<SourceIngressObservation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TargetIngressObservation {
    kind: String,
    path: String,
    outcome: String,
    queued_builds: u64,
    scheduled_attempts: u64,
    credential_grants: u64,
    connector_requests: u64,
    production_effects: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TargetReplay {
    schema: String,
    job_id: String,
    target_state: String,
    target_generation: String,
    observations: Vec<TargetIngressObservation>,
    terminal_queued_builds: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct IsolationObservation {
    schema: String,
    source_fixture_identity: String,
    target_fixture_identity: String,
    source_network_sha256: String,
    target_network_sha256: String,
    reachability_receipt_sha256: String,
    source_and_target_networks_disjoint: bool,
    production_network_requests: u64,
    production_endpoint_mappings: u64,
    production_credentials: u64,
    host_mounts: u64,
    cross_fixture_mounts: u64,
    teardown_complete: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TraceObservation {
    schema: String,
    certified_trace_sha256: String,
    source_trace_sha256: String,
    target_trace_sha256: String,
    source_log: Vec<NormalizedLogEntry>,
    target_log: Vec<NormalizedLogEntry>,
    source_result: String,
    target_result: String,
    artifacts: u64,
    external_effect_intents: u64,
    isolated_replay_executed: bool,
    compared_traces: usize,
    mismatches: usize,
}

#[derive(Serialize)]
struct CaptureBinding<'a> {
    schema: &'static str,
    event_kind: &'a str,
    source_path: &'a str,
    source: &'a SourceIngressObservation,
}

struct VerifiedPackage {
    sha256: String,
    packaged_cases: usize,
    rejected_cases: usize,
}

/// Builds one canonical owner-private session template from the live Jenkins
/// observation, the isolated McLoving replay, and the post-teardown isolation
/// observation. Only the five source receipts are signed. The shadow half is
/// deliberately left unsigned for [`seal_private_session`].
pub fn prepare_source_authenticated_template(
    inputs: &SourceTemplateInputs<'_>,
) -> Result<Vec<u8>, QualificationError> {
    if inputs.source_probe_bytes.is_empty()
        || inputs.source_probe_bytes.len() > MAX_SESSION_BYTES
        || inputs.target_replay_bytes.is_empty()
        || inputs.target_replay_bytes.len() > MAX_SESSION_BYTES
        || inputs.trace_observation_bytes.is_empty()
        || inputs.trace_observation_bytes.len() > MAX_SESSION_BYTES
        || inputs.isolation_observation_bytes.is_empty()
        || inputs.isolation_observation_bytes.len() > MAX_SESSION_BYTES
        || inputs.private_package_bytes.is_empty()
        || inputs.private_package_bytes.len() > MAX_PRIVATE_PACKAGE_BYTES
    {
        return Err(QualificationError::new(
            "E_SIZE",
            "one or more shadow runtime inputs are empty or oversized",
        ));
    }
    let source: SourceProbe = serde_json::from_slice(inputs.source_probe_bytes)
        .map_err(|error| QualificationError::new("E_SOURCE_PROBE", error.to_string()))?;
    let target: TargetReplay = serde_json::from_slice(inputs.target_replay_bytes)
        .map_err(|error| QualificationError::new("E_TARGET_REPLAY", error.to_string()))?;
    let trace_observation: TraceObservation =
        serde_json::from_slice(inputs.trace_observation_bytes)
            .map_err(|error| QualificationError::new("E_TRACE", error.to_string()))?;
    let isolation_observation: IsolationObservation =
        serde_json::from_slice(inputs.isolation_observation_bytes)
            .map_err(|error| QualificationError::new("E_ISOLATION", error.to_string()))?;
    validate_runtime_observations(&source, &target, &trace_observation, &isolation_observation)?;

    let package_sha256 = sha256(inputs.private_package_bytes);
    if !is_sha256(inputs.expected_private_package_sha256)
        || package_sha256 != inputs.expected_private_package_sha256
    {
        return Err(QualificationError::new(
            "E_PACKAGE_PIN",
            "private migration package does not match its independent owner pin",
        ));
    }
    if !is_git_sha1(inputs.shadow_implementation_head)
        || !is_sha256(inputs.authz_generation_sha256)
        || !is_sha256(inputs.verifier_binary_sha256)
    {
        return Err(QualificationError::new(
            "E_FREEZE",
            "reviewed head, authorization generation, or verifier identity is invalid",
        ));
    }
    let source_key = Ed25519KeyPair::from_pkcs8(inputs.source_capture_pkcs8)
        .map_err(|_| QualificationError::new("E_KEY", "invalid source-capture Ed25519 key"))?;
    if !is_sha256(inputs.expected_source_capture_public_key_sha256)
        || sha256(source_key.public_key().as_ref())
            != inputs.expected_source_capture_public_key_sha256
    {
        return Err(QualificationError::new(
            "E_SOURCE_CAPTURE_KEY",
            "source-capture key does not match its independent owner pin",
        ));
    }
    let shadow_public_key = decode_public_key(inputs.shadow_replay_public_key_base64)?;
    if source_key.public_key().as_ref() == shadow_public_key {
        return Err(QualificationError::new(
            "E_KEY",
            "source-capture and shadow-replay keys must be distinct",
        ));
    }

    let mut events = Vec::with_capacity(source.observations.len());
    for (source_observation, target_observation) in
        source.observations.iter().zip(&target.observations)
    {
        let capture_sha256 = sha256(&canonical_bytes(&CaptureBinding {
            schema: CAPTURE_BINDING_SCHEMA,
            event_kind: &source_observation.kind,
            source_path: &source_observation.path,
            source: source_observation,
        })?);
        let event_id = Uuid::new_v4();
        let source_receipt = SignedDenialReceipt {
            schema: DENIAL_RECEIPT_SCHEMA.to_owned(),
            event_id,
            event_kind: source_observation.kind.clone(),
            capture_sha256: capture_sha256.clone(),
            runner_identity: "jenkins-source".to_owned(),
            state: "disabled".to_owned(),
            generation: OPERATIONAL_GENERATION.to_owned(),
            outcome: "disabled_pre_queue".to_owned(),
            replayed: false,
            queued_builds: source_observation.queued_builds,
            scheduled_attempts: source_observation.scheduled_attempts,
            credential_grants: source_observation.credential_grants,
            connector_requests: source_observation.connector_requests,
            production_effects: source_observation.production_effects,
            audit_sha256: sha256(&canonical_bytes(source_observation)?),
            session_binding_sha256: String::new(),
            signing_public_key_sha256: sha256(source_key.public_key().as_ref()),
            signature_base64: String::new(),
        };
        let shadow_receipt = SignedDenialReceipt {
            schema: DENIAL_RECEIPT_SCHEMA.to_owned(),
            event_id,
            event_kind: target_observation.kind.clone(),
            capture_sha256,
            runner_identity: "mcloving-shadow".to_owned(),
            state: "disabled".to_owned(),
            generation: OPERATIONAL_GENERATION.to_owned(),
            outcome: "disabled_pre_queue".to_owned(),
            replayed: true,
            queued_builds: target_observation.queued_builds,
            scheduled_attempts: target_observation.scheduled_attempts,
            credential_grants: target_observation.credential_grants,
            connector_requests: target_observation.connector_requests,
            production_effects: target_observation.production_effects,
            audit_sha256: sha256(&canonical_bytes(target_observation)?),
            session_binding_sha256: String::new(),
            signing_public_key_sha256: String::new(),
            signature_base64: String::new(),
        };
        events.push(PairedEvent {
            source: source_receipt,
            shadow: shadow_receipt,
        });
    }

    let mut session = Session {
        schema: SCHEMA.to_owned(),
        session_id: Uuid::new_v4(),
        ticket: "SHADOW-001".to_owned(),
        shadow_implementation_head: inputs.shadow_implementation_head.to_owned(),
        mig007_protected_main: MIG007_PROTECTED_MAIN.to_owned(),
        migration_package_sha256: package_sha256,
        freeze: Freeze {
            source_controller: SOURCE_CONTROLLER.to_owned(),
            inventory_epoch: INVENTORY_EPOCH.to_owned(),
            inventory_sha256: INVENTORY_SHA256.to_owned(),
            job_id: JOB_ID.to_owned(),
            source_sha256: SOURCE_SHA256.to_owned(),
            pipeline_sha256: PIPELINE_SHA256.to_owned(),
            source_state: "disabled".to_owned(),
            source_generation: OPERATIONAL_GENERATION.to_owned(),
            target_state: "disabled".to_owned(),
            target_generation: OPERATIONAL_GENERATION.to_owned(),
            authz_generation_sha256: inputs.authz_generation_sha256.to_owned(),
            agent_inputs_sha256: EMPTY_SHA256.to_owned(),
            release_id: RELEASE_ID.to_owned(),
            release_version: RELEASE_VERSION.to_owned(),
            release_profile: RELEASE_PROFILE.to_owned(),
            release_envelope_sha256: RELEASE_ENVELOPE_SHA256.to_owned(),
            jenkins_image_sha256: JENKINS_IMAGE_SHA256.to_owned(),
            jenkins_plugins_sha256: JENKINS_PLUGINS_SHA256.to_owned(),
            rust_image_sha256: RUST_IMAGE_SHA256.to_owned(),
            postgres_image_sha256: POSTGRES_IMAGE_SHA256.to_owned(),
            verifier_binary_sha256: inputs.verifier_binary_sha256.to_owned(),
            source_capture_public_key_base64: BASE64.encode(source_key.public_key().as_ref()),
            shadow_replay_public_key_base64: inputs.shadow_replay_public_key_base64.to_owned(),
        },
        comparison_inputs: ComparisonInputs {
            captured_wall_clock_unix_ms: source.captured_wall_clock_unix_ms,
            wall_clock_stream_sha256: EMPTY_SHA256.to_owned(),
            wall_clock_consumption_events: 0,
            semantic_time_dependencies: false,
            entropy_stream_sha256: EMPTY_SHA256.to_owned(),
            entropy_consumption_events: 0,
            semantic_entropy_dependencies: false,
            security_entropy_influences_semantics: false,
            external_input_receipts: 0,
            secret_outcome_receipts: 0,
            connector_outcome_receipts: 0,
            administrative_operation_receipts: 0,
        },
        events,
        trace: TraceComparison {
            certified_trace_sha256: trace_observation.certified_trace_sha256,
            source_trace_sha256: trace_observation.source_trace_sha256,
            target_trace_sha256: trace_observation.target_trace_sha256,
            source_log: trace_observation.source_log,
            target_log: trace_observation.target_log,
            source_result: trace_observation.source_result,
            target_result: trace_observation.target_result,
            artifacts: trace_observation.artifacts,
            external_effect_intents: trace_observation.external_effect_intents,
            isolated_replay_executed: trace_observation.isolated_replay_executed,
            compared_traces: trace_observation.compared_traces,
            mismatches: trace_observation.mismatches,
        },
        isolation: Isolation {
            source_fixture_identity: isolation_observation.source_fixture_identity,
            target_fixture_identity: isolation_observation.target_fixture_identity,
            source_network_sha256: isolation_observation.source_network_sha256,
            target_network_sha256: isolation_observation.target_network_sha256,
            reachability_receipt_sha256: isolation_observation.reachability_receipt_sha256,
            source_and_target_networks_disjoint: isolation_observation
                .source_and_target_networks_disjoint,
            production_network_requests: isolation_observation.production_network_requests,
            production_endpoint_mappings: isolation_observation.production_endpoint_mappings,
            production_credentials: isolation_observation.production_credentials,
            host_mounts: isolation_observation.host_mounts,
            cross_fixture_mounts: isolation_observation.cross_fixture_mounts,
            teardown_complete: isolation_observation.teardown_complete,
        },
        authority: denied_authority(),
    };
    let binding = source_session_binding_sha256(&session)?;
    for event in &mut session.events {
        event.source.session_binding_sha256 = binding.clone();
        sign_receipt(&mut event.source, &source_key)?;
    }
    let bytes = canonical_bytes(&session)?;
    if bytes.len() > MAX_SESSION_BYTES {
        return Err(QualificationError::new(
            "E_SIZE",
            "prepared shadow session template exceeds its byte ceiling",
        ));
    }
    Ok(bytes)
}

fn validate_runtime_observations(
    source: &SourceProbe,
    target: &TargetReplay,
    trace: &TraceObservation,
    isolation: &IsolationObservation,
) -> Result<(), QualificationError> {
    let order = ["api", "manual", "schedule", "upstream", "webhook"];
    let source_paths = [
        "WorkflowJob.doBuild(StaplerRequest2,StaplerResponse2,TimeDuration)",
        "WorkflowJob.scheduleBuild2(UserIdCause)",
        "TimerTrigger.run()",
        "ReverseBuildTrigger.RunListenerImpl.onCompleted",
        "SCMTrigger.run(Action[])",
    ];
    let target_paths = [
        "Store.accept_trigger_delivery(remote_api)",
        "Store.admit_dag",
        "Store.accept_trigger_delivery(schedule)",
        "Store.accept_trigger_delivery(upstream)",
        "Store.accept_trigger_delivery(scm_webhook)",
    ];
    let source_details = [
        serde_json::json!({"rejection": "org.kohsuke.stapler.HttpResponses$3"}),
        serde_json::json!({"returned_future": false}),
        serde_json::json!({}),
        serde_json::json!({"upstream_result": "ABORTED"}),
        serde_json::json!({}),
    ];
    if source.schema != SOURCE_PROBE_SCHEMA
        || source.job_id != JOB_ID
        || source.source_state != "disabled"
        || source.definition_kind != SOURCE_DEFINITION_KIND
        || source.source_sha256 != SOURCE_SHA256
        || source.source_config_sha256 != OPERATIONAL_GENERATION
        || source.captured_wall_clock_unix_ms <= 0
        || source.original_activity != source.terminal_activity
        || source.original_activity.builds != 1
        || source.original_activity.queued != 0
        || source.original_activity.next_build_number != 2
        || source.observations.len() != order.len()
        || target.schema != TARGET_REPLAY_SCHEMA
        || target.job_id != JOB_ID
        || target.target_state != "disabled"
        || target.target_generation != OPERATIONAL_GENERATION
        || target.terminal_queued_builds != 0
        || target.observations.len() != order.len()
    {
        return Err(QualificationError::new(
            "E_RUNTIME_OBSERVATION",
            "source or target runtime denominator, state, or activity mismatch",
        ));
    }
    for (index, kind) in order.iter().enumerate() {
        let source_observation = &source.observations[index];
        let target_observation = &target.observations[index];
        if source_observation.kind != *kind
            || target_observation.kind != *kind
            || source_observation.path != source_paths[index]
            || target_observation.path != target_paths[index]
            || source_observation.detail != source_details[index]
            || source_observation.path == target_observation.path
            || !is_zero_denial(
                &source_observation.outcome,
                source_observation.queued_builds,
                source_observation.scheduled_attempts,
                source_observation.credential_grants,
                source_observation.connector_requests,
                source_observation.production_effects,
            )
            || !is_zero_denial(
                &target_observation.outcome,
                target_observation.queued_builds,
                target_observation.scheduled_attempts,
                target_observation.credential_grants,
                target_observation.connector_requests,
                target_observation.production_effects,
            )
        {
            return Err(QualificationError::new(
                "E_RUNTIME_OBSERVATION",
                "source and target ingress observations are not exact paired denials",
            ));
        }
    }
    if isolation.schema != ISOLATION_OBSERVATION_SCHEMA {
        return Err(QualificationError::new(
            "E_ISOLATION",
            "isolation observation schema mismatch",
        ));
    }
    if trace.schema != TRACE_OBSERVATION_SCHEMA {
        return Err(QualificationError::new(
            "E_TRACE",
            "trace observation schema mismatch",
        ));
    }
    verify_trace(&TraceComparison {
        certified_trace_sha256: trace.certified_trace_sha256.clone(),
        source_trace_sha256: trace.source_trace_sha256.clone(),
        target_trace_sha256: trace.target_trace_sha256.clone(),
        source_log: trace.source_log.clone(),
        target_log: trace.target_log.clone(),
        source_result: trace.source_result.clone(),
        target_result: trace.target_result.clone(),
        artifacts: trace.artifacts,
        external_effect_intents: trace.external_effect_intents,
        isolated_replay_executed: trace.isolated_replay_executed,
        compared_traces: trace.compared_traces,
        mismatches: trace.mismatches,
    })?;
    verify_isolation(&Isolation {
        source_fixture_identity: isolation.source_fixture_identity.clone(),
        target_fixture_identity: isolation.target_fixture_identity.clone(),
        source_network_sha256: isolation.source_network_sha256.clone(),
        target_network_sha256: isolation.target_network_sha256.clone(),
        reachability_receipt_sha256: isolation.reachability_receipt_sha256.clone(),
        source_and_target_networks_disjoint: isolation.source_and_target_networks_disjoint,
        production_network_requests: isolation.production_network_requests,
        production_endpoint_mappings: isolation.production_endpoint_mappings,
        production_credentials: isolation.production_credentials,
        host_mounts: isolation.host_mounts,
        cross_fixture_mounts: isolation.cross_fixture_mounts,
        teardown_complete: isolation.teardown_complete,
    })
}

fn is_zero_denial(
    outcome: &str,
    queued_builds: u64,
    scheduled_attempts: u64,
    credential_grants: u64,
    connector_requests: u64,
    production_effects: u64,
) -> bool {
    outcome == "disabled_pre_queue"
        && queued_builds == 0
        && scheduled_attempts == 0
        && credential_grants == 0
        && connector_requests == 0
        && production_effects == 0
}

pub fn verify_private_session(
    session_bytes: &[u8],
    independent_pins: &IndependentPins<'_>,
    private_package_bytes: &[u8],
    repository_root: &Path,
    package_inputs: &PrivateVerificationInputs<'_>,
) -> Result<VerificationReceipt, QualificationError> {
    verify_session_pin(session_bytes, independent_pins.session_sha256)?;
    let package = verify_private(private_package_bytes, repository_root, package_inputs)
        .map_err(|error| QualificationError::new("E_PACKAGE", error.to_string()))?;
    if package.packaged_cases != 1
        || package.rejected_cases != 227
        || package.admitted_state_dependencies != 1
        || !package.package_complete
        || !package.shadow_eligible
        || package.production_authority
    {
        return Err(QualificationError::new(
            "E_PACKAGE_AUTHORITY",
            "private migration package is not the exact shadow-only denominator",
        ));
    }
    verify_session(
        session_bytes,
        independent_pins.shadow_implementation_head,
        independent_pins.source_capture_public_key_sha256,
        independent_pins.authz_generation_sha256,
        independent_pins.verifier_binary_sha256,
        &VerifiedPackage {
            sha256: sha256(private_package_bytes),
            packaged_cases: package.packaged_cases,
            rejected_cases: package.rejected_cases,
        },
    )
}

/// Authenticates independently signed source-capture receipts and signs only
/// the shadow-replay half of an owner-private session template. The returned
/// bytes are structurally verified, but the caller must still compose
/// [`verify_private_session`] before durable publication so the private MIG-007
/// package and all owner pins are authenticated.
pub fn seal_private_session(
    template_bytes: &[u8],
    expected_source_capture_public_key_sha256: &str,
    shadow_replay_pkcs8: &[u8],
) -> Result<Vec<u8>, QualificationError> {
    if template_bytes.is_empty() || template_bytes.len() > MAX_SESSION_BYTES {
        return Err(QualificationError::new(
            "E_SIZE",
            "shadow session template is empty or exceeds its byte ceiling",
        ));
    }
    let mut session: Session = serde_json::from_slice(template_bytes)
        .map_err(|error| QualificationError::new("E_SCHEMA", error.to_string()))?;
    if canonical_bytes(&session)? != template_bytes {
        return Err(QualificationError::new(
            "E_CANONICAL",
            "shadow session template is not canonical pretty JSON",
        ));
    }
    if session.freeze.source_capture_public_key_base64.is_empty()
        || session.freeze.shadow_replay_public_key_base64.is_empty()
        || session.events.iter().any(|event| {
            event.source.signing_public_key_sha256.is_empty()
                || event.source.signature_base64.is_empty()
                || event.source.session_binding_sha256.is_empty()
                || !event.shadow.session_binding_sha256.is_empty()
                || !event.shadow.signing_public_key_sha256.is_empty()
                || !event.shadow.signature_base64.is_empty()
        })
    {
        return Err(QualificationError::new(
            "E_CAPTURE_TEMPLATE",
            "session template must contain only preauthenticated source-capture receipts",
        ));
    }
    let source_public_key = decode_public_key(&session.freeze.source_capture_public_key_base64)?;
    let expected_shadow_public_key =
        decode_public_key(&session.freeze.shadow_replay_public_key_base64)?;
    if !is_sha256(expected_source_capture_public_key_sha256)
        || sha256(&source_public_key) != expected_source_capture_public_key_sha256
    {
        return Err(QualificationError::new(
            "E_SOURCE_CAPTURE_KEY",
            "source-capture identity does not match its independent owner pin",
        ));
    }
    let shadow_key = Ed25519KeyPair::from_pkcs8(shadow_replay_pkcs8).map_err(|_| {
        QualificationError::new("E_KEY", "invalid shadow-replay Ed25519 PKCS#8 key")
    })?;
    if shadow_key.public_key().as_ref() != expected_shadow_public_key {
        return Err(QualificationError::new(
            "E_SHADOW_REPLAY_KEY",
            "shadow-replay key does not match the source-authenticated ceremony identity",
        ));
    }
    if source_public_key == shadow_key.public_key().as_ref() {
        return Err(QualificationError::new(
            "E_KEY",
            "source-capture and shadow-replay keys must be distinct",
        ));
    }
    let session_binding_sha256 = source_session_binding_sha256(&session)?;
    verify_source_captures(&session.events, &source_public_key, &session_binding_sha256)?;
    for event in &mut session.events {
        event.shadow.session_binding_sha256 = session_binding_sha256.clone();
        sign_receipt(&mut event.shadow, &shadow_key)?;
    }
    let bytes = canonical_bytes(&session)?;
    verify_session(
        &bytes,
        &session.shadow_implementation_head,
        expected_source_capture_public_key_sha256,
        &session.freeze.authz_generation_sha256,
        &session.freeze.verifier_binary_sha256,
        &VerifiedPackage {
            sha256: session.migration_package_sha256.clone(),
            packaged_cases: 1,
            rejected_cases: 227,
        },
    )?;
    Ok(bytes)
}

fn sign_receipt(
    receipt: &mut SignedDenialReceipt,
    key: &Ed25519KeyPair,
) -> Result<(), QualificationError> {
    receipt.signing_public_key_sha256 = sha256(key.public_key().as_ref());
    receipt.signature_base64.clear();
    receipt.signature_base64 = BASE64.encode(key.sign(&signature_message(receipt)?).as_ref());
    Ok(())
}

fn verify_session_pin(
    session_bytes: &[u8],
    expected_session_sha256: &str,
) -> Result<(), QualificationError> {
    if !is_sha256(expected_session_sha256) || sha256(session_bytes) != expected_session_sha256 {
        return Err(QualificationError::new(
            "E_SESSION_PIN",
            "owner-held shadow session pin mismatch",
        ));
    }
    Ok(())
}

fn verify_session(
    bytes: &[u8],
    expected_shadow_implementation_head: &str,
    expected_source_capture_public_key_sha256: &str,
    expected_authz_generation_sha256: &str,
    expected_verifier_binary_sha256: &str,
    package: &VerifiedPackage,
) -> Result<VerificationReceipt, QualificationError> {
    if bytes.is_empty() || bytes.len() > MAX_SESSION_BYTES {
        return Err(QualificationError::new(
            "E_SIZE",
            "shadow session is empty or exceeds its byte ceiling",
        ));
    }
    if !is_git_sha1(expected_shadow_implementation_head) {
        return Err(QualificationError::new(
            "E_IMPLEMENTATION_HEAD",
            "expected implementation head must be a lowercase full Git SHA-1",
        ));
    }
    let session: Session = serde_json::from_slice(bytes)
        .map_err(|error| QualificationError::new("E_SCHEMA", error.to_string()))?;
    let canonical = canonical_bytes(&session)?;
    if canonical != bytes {
        return Err(QualificationError::new(
            "E_CANONICAL",
            "shadow session bytes are not canonical pretty JSON",
        ));
    }
    if session.schema != SCHEMA
        || session.session_id.is_nil()
        || session.ticket != "SHADOW-001"
        || session.shadow_implementation_head != expected_shadow_implementation_head
        || session.mig007_protected_main != MIG007_PROTECTED_MAIN
        || session.migration_package_sha256 != package.sha256
    {
        return Err(QualificationError::new(
            "E_IDENTITY",
            "shadow session identity or package binding mismatch",
        ));
    }
    verify_freeze(
        &session.freeze,
        expected_source_capture_public_key_sha256,
        expected_authz_generation_sha256,
        expected_verifier_binary_sha256,
    )?;
    verify_comparison_inputs(&session.comparison_inputs)?;
    verify_events(&session)?;
    verify_trace(&session.trace)?;
    verify_isolation(&session.isolation)?;
    if session.authority != denied_authority() {
        return Err(QualificationError::new(
            "E_AUTHORITY",
            "shadow session contains non-denied authority",
        ));
    }
    Ok(VerificationReceipt {
        schema: SCHEMA,
        session_id: session.session_id,
        captured_events: session.events.len(),
        replayed_events: session.events.len(),
        compared_traces: session.trace.compared_traces,
        mismatches: 0,
        packaged_cases: package.packaged_cases,
        rejected_cases: package.rejected_cases,
        shadow_qualified: true,
        production_authority: false,
    })
}

fn verify_freeze(
    freeze: &Freeze,
    expected_source_capture_public_key_sha256: &str,
    expected_authz_generation_sha256: &str,
    expected_verifier_binary_sha256: &str,
) -> Result<(), QualificationError> {
    let source_key = decode_public_key(&freeze.source_capture_public_key_base64)?;
    let shadow_key = decode_public_key(&freeze.shadow_replay_public_key_base64)?;
    if source_key == shadow_key
        || !is_sha256(expected_source_capture_public_key_sha256)
        || sha256(&source_key) != expected_source_capture_public_key_sha256
        || freeze.source_controller != SOURCE_CONTROLLER
        || freeze.inventory_epoch != INVENTORY_EPOCH
        || freeze.inventory_sha256 != INVENTORY_SHA256
        || freeze.job_id != JOB_ID
        || freeze.source_sha256 != SOURCE_SHA256
        || freeze.pipeline_sha256 != PIPELINE_SHA256
        || freeze.source_state != "disabled"
        || freeze.source_generation != OPERATIONAL_GENERATION
        || freeze.target_state != "disabled"
        || freeze.target_generation != OPERATIONAL_GENERATION
        || !is_sha256(expected_authz_generation_sha256)
        || freeze.authz_generation_sha256 != expected_authz_generation_sha256
        || freeze.agent_inputs_sha256 != EMPTY_SHA256
        || freeze.release_id != RELEASE_ID
        || freeze.release_version != RELEASE_VERSION
        || freeze.release_profile != RELEASE_PROFILE
        || freeze.release_envelope_sha256 != RELEASE_ENVELOPE_SHA256
        || freeze.jenkins_image_sha256 != JENKINS_IMAGE_SHA256
        || freeze.jenkins_plugins_sha256 != JENKINS_PLUGINS_SHA256
        || freeze.rust_image_sha256 != RUST_IMAGE_SHA256
        || freeze.postgres_image_sha256 != POSTGRES_IMAGE_SHA256
        || !is_sha256(expected_verifier_binary_sha256)
        || freeze.verifier_binary_sha256 != expected_verifier_binary_sha256
    {
        return Err(QualificationError::new(
            "E_FREEZE",
            "source, target, release, runtime, or authority freeze mismatch",
        ));
    }
    Ok(())
}

fn verify_comparison_inputs(inputs: &ComparisonInputs) -> Result<(), QualificationError> {
    if inputs.captured_wall_clock_unix_ms <= 0
        || inputs.wall_clock_stream_sha256 != EMPTY_SHA256
        || inputs.wall_clock_consumption_events != 0
        || inputs.semantic_time_dependencies
        || inputs.entropy_stream_sha256 != EMPTY_SHA256
        || inputs.entropy_consumption_events != 0
        || inputs.semantic_entropy_dependencies
        || inputs.security_entropy_influences_semantics
        || inputs.external_input_receipts != 0
        || inputs.secret_outcome_receipts != 0
        || inputs.connector_outcome_receipts != 0
        || inputs.administrative_operation_receipts != 0
    {
        return Err(QualificationError::new(
            "E_COMPARISON_INPUT",
            "comparison input capture does not match the exact no-input case",
        ));
    }
    Ok(())
}

fn verify_events(session: &Session) -> Result<(), QualificationError> {
    let source_key = decode_public_key(&session.freeze.source_capture_public_key_base64)?;
    let shadow_key = decode_public_key(&session.freeze.shadow_replay_public_key_base64)?;
    let session_binding_sha256 = source_session_binding_sha256(session)?;
    verify_source_captures(&session.events, &source_key, &session_binding_sha256)?;
    for event in &session.events {
        verify_denial_receipt(
            &event.shadow,
            &shadow_key,
            true,
            "mcloving-shadow",
            &session_binding_sha256,
        )?;
        if event.source.event_id != event.shadow.event_id
            || event.source.event_kind != event.shadow.event_kind
            || event.source.capture_sha256 != event.shadow.capture_sha256
            || event.source.state != event.shadow.state
            || event.source.generation != event.shadow.generation
            || event.source.outcome != event.shadow.outcome
        {
            return Err(QualificationError::new(
                "E_EVENT_JOIN",
                "source capture and shadow replay do not form a unique exact pair",
            ));
        }
    }
    Ok(())
}

fn verify_source_captures(
    events: &[PairedEvent],
    source_key: &[u8],
    session_binding_sha256: &str,
) -> Result<(), QualificationError> {
    let required_order = ["api", "manual", "schedule", "upstream", "webhook"];
    let required = BTreeSet::from([
        "api".to_owned(),
        "manual".to_owned(),
        "schedule".to_owned(),
        "upstream".to_owned(),
        "webhook".to_owned(),
    ]);
    if events.len() != required.len() {
        return Err(QualificationError::new(
            "E_EVENT_DENOMINATOR",
            "shadow session must contain exactly five ingress classes",
        ));
    }
    let mut kinds = BTreeSet::new();
    let mut ids = BTreeSet::new();
    let mut captures = BTreeSet::new();
    for (index, event) in events.iter().enumerate() {
        if event.source.event_kind != required_order[index] {
            return Err(QualificationError::new(
                "E_EVENT_ORDER",
                "shadow session ingress observations are not in canonical order",
            ));
        }
        verify_denial_receipt(
            &event.source,
            source_key,
            false,
            "jenkins-source",
            session_binding_sha256,
        )?;
        if !kinds.insert(event.source.event_kind.clone())
            || !ids.insert(event.source.event_id)
            || !captures.insert(event.source.capture_sha256.clone())
        {
            return Err(QualificationError::new(
                "E_EVENT_JOIN",
                "source captures are not unique",
            ));
        }
    }
    if kinds != required {
        return Err(QualificationError::new(
            "E_EVENT_DENOMINATOR",
            "shadow session ingress class set mismatch",
        ));
    }
    Ok(())
}

fn verify_denial_receipt(
    receipt: &SignedDenialReceipt,
    public_key: &[u8],
    replayed: bool,
    runner: &str,
    expected_session_binding_sha256: &str,
) -> Result<(), QualificationError> {
    if !is_sha256(expected_session_binding_sha256)
        || receipt.session_binding_sha256 != expected_session_binding_sha256
    {
        return Err(QualificationError::new(
            "E_CAPTURE_BINDING",
            "signed ingress receipt does not bind the exact frozen session",
        ));
    }
    if receipt.schema != DENIAL_RECEIPT_SCHEMA
        || receipt.event_id.is_nil()
        || !is_sha256(&receipt.capture_sha256)
        || receipt.runner_identity != runner
        || receipt.state != "disabled"
        || receipt.generation != OPERATIONAL_GENERATION
        || receipt.outcome != "disabled_pre_queue"
        || receipt.replayed != replayed
        || receipt.queued_builds != 0
        || receipt.scheduled_attempts != 0
        || receipt.credential_grants != 0
        || receipt.connector_requests != 0
        || receipt.production_effects != 0
        || !is_sha256(&receipt.audit_sha256)
        || receipt.signing_public_key_sha256 != sha256(public_key)
    {
        return Err(QualificationError::new(
            "E_DENIAL_RECEIPT",
            "signed ingress denial receipt mismatch",
        ));
    }
    let mut unsigned = receipt.clone();
    unsigned.signature_base64.clear();
    let message = signature_message(&unsigned)?;
    let signature = BASE64
        .decode(&receipt.signature_base64)
        .map_err(|_| QualificationError::new("E_SIGNATURE", "invalid signature encoding"))?;
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&message, &signature)
        .map_err(|_| QualificationError::new("E_SIGNATURE", "invalid denial receipt signature"))
}

fn source_session_binding_sha256(session: &Session) -> Result<String, QualificationError> {
    let binding = SourceSessionBinding {
        schema: SOURCE_SESSION_BINDING_SCHEMA,
        session_id: session.session_id,
        ticket: &session.ticket,
        shadow_implementation_head: &session.shadow_implementation_head,
        mig007_protected_main: &session.mig007_protected_main,
        migration_package_sha256: &session.migration_package_sha256,
        captured_wall_clock_unix_ms: session.comparison_inputs.captured_wall_clock_unix_ms,
        freeze: session.freeze.clone(),
        comparison_inputs: &session.comparison_inputs,
        trace: &session.trace,
        isolation: &session.isolation,
        authority: &session.authority,
    };
    Ok(sha256(&canonical_bytes(&binding)?))
}

fn verify_trace(trace: &TraceComparison) -> Result<(), QualificationError> {
    if trace.certified_trace_sha256 != DIFF001_TRACE_SHA256
        || trace.source_trace_sha256 != DIFF001_TRACE_SHA256
        || trace.target_trace_sha256 != DIFF001_TRACE_SHA256
        || trace.source_log != trace.target_log
        || trace.source_result != "SUCCESS"
        || trace.target_result != "SUCCESS"
        || trace.artifacts != 0
        || trace.external_effect_intents != 0
        || !trace.isolated_replay_executed
        || trace.compared_traces != 1
        || trace.mismatches != 0
    {
        return Err(QualificationError::new(
            "E_TRACE",
            "paired execution trace does not match the certified exact case",
        ));
    }
    let required = [
        ("stderr", STDERR_LOG_SHA256, 19_u64),
        ("stdout", STDOUT_LOG_SHA256, 12_u64),
    ];
    if trace.source_log.len() != required.len() {
        return Err(QualificationError::new(
            "E_TRACE_LOG",
            "paired trace must contain the exact two ordered process log entries",
        ));
    }
    for (index, entry) in trace.source_log.iter().enumerate() {
        let (stream, content_sha256, bytes) = required[index];
        if entry.sequence != u64::try_from(index + 1).expect("bounded trace index")
            || entry.stream != stream
            || entry.content_sha256 != content_sha256
            || entry.bytes != bytes
        {
            return Err(QualificationError::new(
                "E_TRACE_LOG",
                "paired trace log entry mismatch",
            ));
        }
    }
    Ok(())
}

fn verify_isolation(isolation: &Isolation) -> Result<(), QualificationError> {
    if isolation.source_fixture_identity.is_empty()
        || isolation.target_fixture_identity.is_empty()
        || isolation.source_fixture_identity == isolation.target_fixture_identity
        || !is_sha256(&isolation.source_network_sha256)
        || !is_sha256(&isolation.target_network_sha256)
        || isolation.source_network_sha256 == isolation.target_network_sha256
        || !is_sha256(&isolation.reachability_receipt_sha256)
        || !isolation.source_and_target_networks_disjoint
        || isolation.production_network_requests != 0
        || isolation.production_endpoint_mappings != 0
        || isolation.production_credentials != 0
        || isolation.host_mounts != 0
        || isolation.cross_fixture_mounts != 0
        || !isolation.teardown_complete
    {
        return Err(QualificationError::new(
            "E_ISOLATION",
            "shadow isolation or teardown receipt mismatch",
        ));
    }
    Ok(())
}

fn denied_authority() -> Authority {
    Authority {
        trigger: false,
        scheduler: false,
        controller_database: false,
        controller_filesystem: false,
        agent_protocol: false,
        credentials: false,
        connector: false,
        external_effects: false,
        canary: false,
        cutover: false,
        rollback: false,
        decommission: false,
    }
}

fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, QualificationError> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| QualificationError::new("E_CANONICAL", error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn signature_message<T: Serialize>(value: &T) -> Result<Vec<u8>, QualificationError> {
    let bytes = canonical_bytes(value)?;
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + bytes.len());
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(&bytes);
    Ok(message)
}

fn decode_public_key(encoded: &str) -> Result<Vec<u8>, QualificationError> {
    let key = BASE64
        .decode(encoded)
        .map_err(|_| QualificationError::new("E_KEY", "invalid public-key encoding"))?;
    if key.len() != 32 {
        return Err(QualificationError::new(
            "E_KEY",
            "Ed25519 public key must contain exactly 32 bytes",
        ));
    }
    Ok(key)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_git_sha1(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair as _};

    use super::*;

    const HEAD: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const TEST_AUTHZ_SHA256: &str =
        "11d3b170d09e175e366abe551cf0db9b6444b077155081c3a515a1015f003540";
    const TEST_VERIFIER_SHA256: &str =
        "151a2ee8646801158552126fb666ea0d7055c8ea2f7a728ddcb51e373c78a272";

    fn pair(seed_byte: u8) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[seed_byte; 32]).expect("test key")
    }

    fn source_pin() -> String {
        sha256(pair(7).public_key().as_ref())
    }

    fn sign(receipt: &mut SignedDenialReceipt, key: &Ed25519KeyPair) {
        receipt.signature_base64.clear();
        receipt.signature_base64 = BASE64.encode(
            key.sign(&signature_message(receipt).expect("message"))
                .as_ref(),
        );
    }

    fn denial(
        kind: &str,
        id: Uuid,
        capture: &str,
        runner: &str,
        replayed: bool,
    ) -> SignedDenialReceipt {
        SignedDenialReceipt {
            schema: DENIAL_RECEIPT_SCHEMA.to_owned(),
            event_id: id,
            event_kind: kind.to_owned(),
            capture_sha256: capture.to_owned(),
            runner_identity: runner.to_owned(),
            state: "disabled".to_owned(),
            generation: OPERATIONAL_GENERATION.to_owned(),
            outcome: "disabled_pre_queue".to_owned(),
            replayed,
            queued_builds: 0,
            scheduled_attempts: 0,
            credential_grants: 0,
            connector_requests: 0,
            production_effects: 0,
            audit_sha256: sha256(format!("audit-{runner}-{kind}").as_bytes()),
            session_binding_sha256: String::new(),
            signing_public_key_sha256: String::new(),
            signature_base64: String::new(),
        }
    }

    fn source_probe() -> SourceProbe {
        let observations = [
            (
                "api",
                "WorkflowJob.doBuild(StaplerRequest2,StaplerResponse2,TimeDuration)",
                serde_json::json!({"rejection": "org.kohsuke.stapler.HttpResponses$3"}),
            ),
            (
                "manual",
                "WorkflowJob.scheduleBuild2(UserIdCause)",
                serde_json::json!({"returned_future": false}),
            ),
            ("schedule", "TimerTrigger.run()", serde_json::json!({})),
            (
                "upstream",
                "ReverseBuildTrigger.RunListenerImpl.onCompleted",
                serde_json::json!({"upstream_result": "ABORTED"}),
            ),
            ("webhook", "SCMTrigger.run(Action[])", serde_json::json!({})),
        ]
        .into_iter()
        .map(|(kind, path, detail)| SourceIngressObservation {
            kind: kind.to_owned(),
            path: path.to_owned(),
            outcome: "disabled_pre_queue".to_owned(),
            queued_builds: 0,
            scheduled_attempts: 0,
            credential_grants: 0,
            connector_requests: 0,
            production_effects: 0,
            detail,
        })
        .collect();
        SourceProbe {
            schema: SOURCE_PROBE_SCHEMA.to_owned(),
            job_id: JOB_ID.to_owned(),
            source_state: "disabled".to_owned(),
            definition_kind: SOURCE_DEFINITION_KIND.to_owned(),
            source_sha256: SOURCE_SHA256.to_owned(),
            source_config_sha256: OPERATIONAL_GENERATION.to_owned(),
            captured_wall_clock_unix_ms: 1_786_904_213_797,
            original_activity: ActivityObservation {
                builds: 1,
                queued: 0,
                next_build_number: 2,
            },
            terminal_activity: ActivityObservation {
                builds: 1,
                queued: 0,
                next_build_number: 2,
            },
            observations,
        }
    }

    fn target_replay() -> TargetReplay {
        TargetReplay {
            schema: TARGET_REPLAY_SCHEMA.to_owned(),
            job_id: JOB_ID.to_owned(),
            target_state: "disabled".to_owned(),
            target_generation: OPERATIONAL_GENERATION.to_owned(),
            observations: [
                ("api", "Store.accept_trigger_delivery(remote_api)"),
                ("manual", "Store.admit_dag"),
                ("schedule", "Store.accept_trigger_delivery(schedule)"),
                ("upstream", "Store.accept_trigger_delivery(upstream)"),
                ("webhook", "Store.accept_trigger_delivery(scm_webhook)"),
            ]
            .into_iter()
            .map(|(kind, path)| TargetIngressObservation {
                kind: kind.to_owned(),
                path: path.to_owned(),
                outcome: "disabled_pre_queue".to_owned(),
                queued_builds: 0,
                scheduled_attempts: 0,
                credential_grants: 0,
                connector_requests: 0,
                production_effects: 0,
            })
            .collect(),
            terminal_queued_builds: 0,
        }
    }

    fn isolation_observation() -> IsolationObservation {
        IsolationObservation {
            schema: ISOLATION_OBSERVATION_SCHEMA.to_owned(),
            source_fixture_identity: "source-fixture".to_owned(),
            target_fixture_identity: "target-fixture".to_owned(),
            source_network_sha256: sha256(b"source-network"),
            target_network_sha256: sha256(b"target-network"),
            reachability_receipt_sha256: sha256(b"reachability"),
            source_and_target_networks_disjoint: true,
            production_network_requests: 0,
            production_endpoint_mappings: 0,
            production_credentials: 0,
            host_mounts: 0,
            cross_fixture_mounts: 0,
            teardown_complete: true,
        }
    }

    fn trace_observation() -> TraceObservation {
        let log = vec![
            NormalizedLogEntry {
                sequence: 1,
                stream: "stderr".to_owned(),
                content_sha256: STDERR_LOG_SHA256.to_owned(),
                bytes: 19,
            },
            NormalizedLogEntry {
                sequence: 2,
                stream: "stdout".to_owned(),
                content_sha256: STDOUT_LOG_SHA256.to_owned(),
                bytes: 12,
            },
        ];
        TraceObservation {
            schema: TRACE_OBSERVATION_SCHEMA.to_owned(),
            certified_trace_sha256: DIFF001_TRACE_SHA256.to_owned(),
            source_trace_sha256: DIFF001_TRACE_SHA256.to_owned(),
            target_trace_sha256: DIFF001_TRACE_SHA256.to_owned(),
            source_log: log.clone(),
            target_log: log,
            source_result: "SUCCESS".to_owned(),
            target_result: "SUCCESS".to_owned(),
            artifacts: 0,
            external_effect_intents: 0,
            isolated_replay_executed: true,
            compared_traces: 1,
            mismatches: 0,
        }
    }

    fn fixture() -> (Session, VerifiedPackage) {
        let source_key = pair(7);
        let shadow_key = pair(9);
        let package = VerifiedPackage {
            sha256: sha256(b"private-package"),
            packaged_cases: 1,
            rejected_cases: 227,
        };
        let kinds = ["api", "manual", "schedule", "upstream", "webhook"];
        let events = kinds
            .iter()
            .enumerate()
            .map(|(index, kind)| {
                let id = Uuid::from_u128(u128::try_from(index + 1).expect("index"));
                let capture = sha256(format!("capture-{kind}").as_bytes());
                let mut source = denial(kind, id, &capture, "jenkins-source", false);
                source.signing_public_key_sha256 = sha256(source_key.public_key().as_ref());
                sign(&mut source, &source_key);
                let mut shadow = denial(kind, id, &capture, "mcloving-shadow", true);
                shadow.signing_public_key_sha256 = sha256(shadow_key.public_key().as_ref());
                sign(&mut shadow, &shadow_key);
                PairedEvent { source, shadow }
            })
            .collect();
        let mut session = Session {
            schema: SCHEMA.to_owned(),
            session_id: Uuid::from_u128(99),
            ticket: "SHADOW-001".to_owned(),
            shadow_implementation_head: HEAD.to_owned(),
            mig007_protected_main: MIG007_PROTECTED_MAIN.to_owned(),
            migration_package_sha256: package.sha256.clone(),
            freeze: Freeze {
                source_controller: SOURCE_CONTROLLER.to_owned(),
                inventory_epoch: INVENTORY_EPOCH.to_owned(),
                inventory_sha256: INVENTORY_SHA256.to_owned(),
                job_id: JOB_ID.to_owned(),
                source_sha256: SOURCE_SHA256.to_owned(),
                pipeline_sha256: PIPELINE_SHA256.to_owned(),
                source_state: "disabled".to_owned(),
                source_generation: OPERATIONAL_GENERATION.to_owned(),
                target_state: "disabled".to_owned(),
                target_generation: OPERATIONAL_GENERATION.to_owned(),
                authz_generation_sha256: TEST_AUTHZ_SHA256.to_owned(),
                agent_inputs_sha256: EMPTY_SHA256.to_owned(),
                release_id: RELEASE_ID.to_owned(),
                release_version: RELEASE_VERSION.to_owned(),
                release_profile: RELEASE_PROFILE.to_owned(),
                release_envelope_sha256: RELEASE_ENVELOPE_SHA256.to_owned(),
                jenkins_image_sha256: JENKINS_IMAGE_SHA256.to_owned(),
                jenkins_plugins_sha256: JENKINS_PLUGINS_SHA256.to_owned(),
                rust_image_sha256: RUST_IMAGE_SHA256.to_owned(),
                postgres_image_sha256: POSTGRES_IMAGE_SHA256.to_owned(),
                verifier_binary_sha256: TEST_VERIFIER_SHA256.to_owned(),
                source_capture_public_key_base64: BASE64.encode(source_key.public_key().as_ref()),
                shadow_replay_public_key_base64: BASE64.encode(shadow_key.public_key().as_ref()),
            },
            comparison_inputs: ComparisonInputs {
                captured_wall_clock_unix_ms: 1_786_895_400_000,
                wall_clock_stream_sha256: EMPTY_SHA256.to_owned(),
                wall_clock_consumption_events: 0,
                semantic_time_dependencies: false,
                entropy_stream_sha256: EMPTY_SHA256.to_owned(),
                entropy_consumption_events: 0,
                semantic_entropy_dependencies: false,
                security_entropy_influences_semantics: false,
                external_input_receipts: 0,
                secret_outcome_receipts: 0,
                connector_outcome_receipts: 0,
                administrative_operation_receipts: 0,
            },
            events,
            trace: TraceComparison {
                certified_trace_sha256: DIFF001_TRACE_SHA256.to_owned(),
                source_trace_sha256: DIFF001_TRACE_SHA256.to_owned(),
                target_trace_sha256: DIFF001_TRACE_SHA256.to_owned(),
                source_log: vec![
                    NormalizedLogEntry {
                        sequence: 1,
                        stream: "stderr".to_owned(),
                        content_sha256: STDERR_LOG_SHA256.to_owned(),
                        bytes: 19,
                    },
                    NormalizedLogEntry {
                        sequence: 2,
                        stream: "stdout".to_owned(),
                        content_sha256: STDOUT_LOG_SHA256.to_owned(),
                        bytes: 12,
                    },
                ],
                target_log: vec![
                    NormalizedLogEntry {
                        sequence: 1,
                        stream: "stderr".to_owned(),
                        content_sha256: STDERR_LOG_SHA256.to_owned(),
                        bytes: 19,
                    },
                    NormalizedLogEntry {
                        sequence: 2,
                        stream: "stdout".to_owned(),
                        content_sha256: STDOUT_LOG_SHA256.to_owned(),
                        bytes: 12,
                    },
                ],
                source_result: "SUCCESS".to_owned(),
                target_result: "SUCCESS".to_owned(),
                artifacts: 0,
                external_effect_intents: 0,
                isolated_replay_executed: true,
                compared_traces: 1,
                mismatches: 0,
            },
            isolation: Isolation {
                source_fixture_identity: "shadow-source-fixture".to_owned(),
                target_fixture_identity: "shadow-target-fixture".to_owned(),
                source_network_sha256: sha256(b"source-network"),
                target_network_sha256: sha256(b"target-network"),
                reachability_receipt_sha256: sha256(b"reachability"),
                source_and_target_networks_disjoint: true,
                production_network_requests: 0,
                production_endpoint_mappings: 0,
                production_credentials: 0,
                host_mounts: 0,
                cross_fixture_mounts: 0,
                teardown_complete: true,
            },
            authority: denied_authority(),
        };
        let binding = source_session_binding_sha256(&session).expect("session binding");
        for event in &mut session.events {
            event.source.session_binding_sha256 = binding.clone();
            event.shadow.session_binding_sha256 = binding.clone();
            sign(&mut event.source, &source_key);
            sign(&mut event.shadow, &shadow_key);
        }
        (session, package)
    }

    fn verify_fixture(
        session: &Session,
        package: &VerifiedPackage,
    ) -> Result<VerificationReceipt, QualificationError> {
        verify_session(
            &canonical_bytes(session).expect("fixture bytes"),
            HEAD,
            &source_pin(),
            TEST_AUTHZ_SHA256,
            TEST_VERIFIER_SHA256,
            package,
        )
    }

    #[test]
    fn exact_disabled_shadow_session_is_qualified_without_authority() {
        let (session, package) = fixture();
        let receipt = verify_fixture(&session, &package).expect("qualified");
        assert_eq!(receipt.captured_events, 5);
        assert_eq!(receipt.replayed_events, 5);
        assert_eq!(receipt.compared_traces, 1);
        assert!(receipt.shadow_qualified);
        assert!(!receipt.production_authority);
    }

    #[test]
    fn live_observations_prepare_only_authenticated_source_receipts() {
        let random = SystemRandom::new();
        let source_pkcs8 = Ed25519KeyPair::generate_pkcs8(&random).expect("source key");
        let source_pair = Ed25519KeyPair::from_pkcs8(source_pkcs8.as_ref()).expect("source pair");
        let shadow_pkcs8 = Ed25519KeyPair::generate_pkcs8(&random).expect("shadow key");
        let shadow_pair = Ed25519KeyPair::from_pkcs8(shadow_pkcs8.as_ref()).expect("shadow pair");
        let source_bytes = serde_json::to_vec(&source_probe()).expect("source observation");
        let target_bytes = serde_json::to_vec(&target_replay()).expect("target observation");
        let trace_bytes = serde_json::to_vec(&trace_observation()).expect("trace observation");
        let isolation_bytes =
            serde_json::to_vec(&isolation_observation()).expect("isolation observation");
        let package = b"private-package";
        let package_sha256 = sha256(package);
        let source_pin = sha256(source_pair.public_key().as_ref());
        let shadow_public = BASE64.encode(shadow_pair.public_key().as_ref());
        let template = prepare_source_authenticated_template(&SourceTemplateInputs {
            source_probe_bytes: &source_bytes,
            target_replay_bytes: &target_bytes,
            trace_observation_bytes: &trace_bytes,
            isolation_observation_bytes: &isolation_bytes,
            private_package_bytes: package,
            expected_private_package_sha256: &package_sha256,
            source_capture_pkcs8: source_pkcs8.as_ref(),
            expected_source_capture_public_key_sha256: &source_pin,
            shadow_replay_public_key_base64: &shadow_public,
            authz_generation_sha256: TEST_AUTHZ_SHA256,
            verifier_binary_sha256: TEST_VERIFIER_SHA256,
            shadow_implementation_head: HEAD,
        })
        .expect("prepare source-authenticated template");
        let prepared: Session = serde_json::from_slice(&template).expect("prepared session");
        assert_eq!(prepared.events.len(), 5);
        assert!(prepared.events.iter().all(|event| {
            !event.source.signature_base64.is_empty()
                && !event.source.session_binding_sha256.is_empty()
                && event.shadow.signature_base64.is_empty()
                && event.shadow.signing_public_key_sha256.is_empty()
                && event.shadow.session_binding_sha256.is_empty()
        }));
        assert_eq!(
            prepared
                .events
                .iter()
                .map(|event| &event.source.capture_sha256)
                .collect::<BTreeSet<_>>()
                .len(),
            5
        );

        let sealed = seal_private_session(&template, &source_pin, shadow_pkcs8.as_ref())
            .expect("seal shadow receipts");
        let receipt = verify_session(
            &sealed,
            HEAD,
            &source_pin,
            TEST_AUTHZ_SHA256,
            TEST_VERIFIER_SHA256,
            &VerifiedPackage {
                sha256: package_sha256,
                packaged_cases: 1,
                rejected_cases: 227,
            },
        )
        .expect("verify prepared and sealed session");
        assert!(receipt.shadow_qualified);
        assert!(!receipt.production_authority);
    }

    #[test]
    fn prepared_template_rejects_runtime_pin_key_and_isolation_drift() {
        let random = SystemRandom::new();
        let source_pkcs8 = Ed25519KeyPair::generate_pkcs8(&random).expect("source key");
        let source_pair = Ed25519KeyPair::from_pkcs8(source_pkcs8.as_ref()).expect("source pair");
        let shadow_pkcs8 = Ed25519KeyPair::generate_pkcs8(&random).expect("shadow key");
        let shadow_pair = Ed25519KeyPair::from_pkcs8(shadow_pkcs8.as_ref()).expect("shadow pair");
        let package = b"private-package";
        let package_sha256 = sha256(package);
        let source_pin = sha256(source_pair.public_key().as_ref());
        let shadow_public = BASE64.encode(shadow_pair.public_key().as_ref());
        let target_bytes = serde_json::to_vec(&target_replay()).expect("target");
        let trace_bytes = serde_json::to_vec(&trace_observation()).expect("trace");
        let valid_isolation = isolation_observation();
        let isolation_bytes = serde_json::to_vec(&valid_isolation).expect("isolation");

        let mut changed_source = source_probe();
        changed_source.terminal_activity.next_build_number += 1;
        let changed_source_bytes = serde_json::to_vec(&changed_source).expect("changed source");
        macro_rules! inputs {
            ($source:expr, $isolation:expr, $package_pin:expr, $source_pin:expr, $shadow:expr $(,)?) => {
                SourceTemplateInputs {
                    source_probe_bytes: $source,
                    target_replay_bytes: &target_bytes,
                    trace_observation_bytes: &trace_bytes,
                    isolation_observation_bytes: $isolation,
                    private_package_bytes: package,
                    expected_private_package_sha256: $package_pin,
                    source_capture_pkcs8: source_pkcs8.as_ref(),
                    expected_source_capture_public_key_sha256: $source_pin,
                    shadow_replay_public_key_base64: $shadow,
                    authz_generation_sha256: TEST_AUTHZ_SHA256,
                    verifier_binary_sha256: TEST_VERIFIER_SHA256,
                    shadow_implementation_head: HEAD,
                }
            };
        }
        assert_eq!(
            prepare_source_authenticated_template(&inputs!(
                &changed_source_bytes,
                &isolation_bytes,
                &package_sha256,
                &source_pin,
                &shadow_public,
            ))
            .expect_err("activity drift")
            .code,
            "E_RUNTIME_OBSERVATION"
        );
        let mut changed_source_identity = source_probe();
        changed_source_identity.source_sha256 = sha256(b"changed-live-source");
        let changed_source_identity_bytes =
            serde_json::to_vec(&changed_source_identity).expect("changed source identity");
        assert_eq!(
            prepare_source_authenticated_template(&inputs!(
                &changed_source_identity_bytes,
                &isolation_bytes,
                &package_sha256,
                &source_pin,
                &shadow_public,
            ))
            .expect_err("live source drift")
            .code,
            "E_RUNTIME_OBSERVATION"
        );
        let mut changed_source_generation = source_probe();
        changed_source_generation.source_config_sha256 = sha256(b"changed-live-configuration");
        let changed_source_generation_bytes =
            serde_json::to_vec(&changed_source_generation).expect("changed source generation");
        assert_eq!(
            prepare_source_authenticated_template(&inputs!(
                &changed_source_generation_bytes,
                &isolation_bytes,
                &package_sha256,
                &source_pin,
                &shadow_public,
            ))
            .expect_err("live configuration generation drift")
            .code,
            "E_RUNTIME_OBSERVATION"
        );
        let valid_source_bytes = serde_json::to_vec(&source_probe()).expect("source");
        assert_eq!(
            prepare_source_authenticated_template(&inputs!(
                &valid_source_bytes,
                &isolation_bytes,
                EMPTY_SHA256,
                &source_pin,
                &shadow_public,
            ))
            .expect_err("package substitution")
            .code,
            "E_PACKAGE_PIN"
        );
        assert_eq!(
            prepare_source_authenticated_template(&inputs!(
                &valid_source_bytes,
                &isolation_bytes,
                &package_sha256,
                EMPTY_SHA256,
                &shadow_public,
            ))
            .expect_err("source-key substitution")
            .code,
            "E_SOURCE_CAPTURE_KEY"
        );
        let mut incomplete_isolation = valid_isolation;
        incomplete_isolation.teardown_complete = false;
        let incomplete_isolation_bytes =
            serde_json::to_vec(&incomplete_isolation).expect("incomplete isolation");
        assert_eq!(
            prepare_source_authenticated_template(&inputs!(
                &valid_source_bytes,
                &incomplete_isolation_bytes,
                &package_sha256,
                &source_pin,
                &shadow_public,
            ))
            .expect_err("incomplete teardown")
            .code,
            "E_ISOLATION"
        );
        let shared_public = BASE64.encode(source_pair.public_key().as_ref());
        assert_eq!(
            prepare_source_authenticated_template(&inputs!(
                &valid_source_bytes,
                &isolation_bytes,
                &package_sha256,
                &source_pin,
                &shared_public,
            ))
            .expect_err("shared signing identity")
            .code,
            "E_KEY"
        );
    }

    #[test]
    fn owner_session_pin_is_mandatory_and_exact() {
        let bytes = b"owner-private-session";
        verify_session_pin(bytes, &sha256(bytes)).expect("exact owner pin");
        assert_eq!(
            verify_session_pin(bytes, EMPTY_SHA256)
                .expect_err("substituted pin")
                .code,
            "E_SESSION_PIN"
        );
        assert_eq!(
            verify_session_pin(bytes, "not-a-digest")
                .expect_err("malformed pin")
                .code,
            "E_SESSION_PIN"
        );
    }

    #[test]
    fn authenticated_source_template_is_sealed_with_a_distinct_shadow_key() {
        let (_, package) = fixture();
        let source_key = pair(7);
        let source_pin = sha256(source_key.public_key().as_ref());
        let random = SystemRandom::new();
        let shadow_pkcs8 = Ed25519KeyPair::generate_pkcs8(&random).expect("shadow key");
        let shadow_pair = Ed25519KeyPair::from_pkcs8(shadow_pkcs8.as_ref()).expect("shadow pair");
        let session = source_template_for_keys(&source_key, &shadow_pair);
        let sealed = seal_private_session(
            &canonical_bytes(&session).expect("template"),
            &source_pin,
            shadow_pkcs8.as_ref(),
        )
        .expect("sealed");
        let receipt = verify_session(
            &sealed,
            HEAD,
            &source_pin,
            TEST_AUTHZ_SHA256,
            TEST_VERIFIER_SHA256,
            &package,
        )
        .expect("verified");
        assert_eq!(receipt.captured_events, 5);
        assert!(!receipt.production_authority);

        let replacement_shadow_pkcs8 =
            Ed25519KeyPair::generate_pkcs8(&random).expect("replacement shadow key");
        let replacement_shadow_pair = Ed25519KeyPair::from_pkcs8(replacement_shadow_pkcs8.as_ref())
            .expect("replacement shadow pair");
        assert_eq!(
            seal_private_session(
                &canonical_bytes(&session).expect("precommitted template"),
                &source_pin,
                replacement_shadow_pkcs8.as_ref(),
            )
            .expect_err("replacement shadow identity")
            .code,
            "E_SHADOW_REPLAY_KEY"
        );
        let mut rebound_shadow_identity = session.clone();
        rebound_shadow_identity
            .freeze
            .shadow_replay_public_key_base64 =
            BASE64.encode(replacement_shadow_pair.public_key().as_ref());
        assert_eq!(
            seal_private_session(
                &canonical_bytes(&rebound_shadow_identity).expect("rebound shadow identity"),
                &source_pin,
                replacement_shadow_pkcs8.as_ref(),
            )
            .expect_err("capture transplanted to another shadow identity")
            .code,
            "E_CAPTURE_BINDING"
        );

        let mut substituted = session.clone();
        let substituted_source = pair(11);
        substituted.freeze.source_capture_public_key_base64 =
            BASE64.encode(substituted_source.public_key().as_ref());
        for event in &mut substituted.events {
            event.source.signing_public_key_sha256 =
                sha256(substituted_source.public_key().as_ref());
            sign(&mut event.source, &substituted_source);
        }
        assert_eq!(
            seal_private_session(
                &canonical_bytes(&substituted).expect("substituted template"),
                &source_pin,
                shadow_pkcs8.as_ref(),
            )
            .expect_err("unpinned source identity")
            .code,
            "E_SOURCE_CAPTURE_KEY"
        );
        let mut forged_source = session.clone();
        forged_source.events[0].source.signature_base64 = BASE64.encode([0_u8; 64]);
        assert_eq!(
            seal_private_session(
                &canonical_bytes(&forged_source).expect("forged source template"),
                &source_pin,
                shadow_pkcs8.as_ref(),
            )
            .expect_err("forged source receipt")
            .code,
            "E_SIGNATURE"
        );
        let mut transplanted_session = session.clone();
        transplanted_session.session_id = Uuid::from_u128(100);
        assert_eq!(
            seal_private_session(
                &canonical_bytes(&transplanted_session).expect("transplanted session"),
                &source_pin,
                shadow_pkcs8.as_ref(),
            )
            .expect_err("source receipts from another session")
            .code,
            "E_CAPTURE_BINDING"
        );
        let mut transplanted_capture_time = session.clone();
        transplanted_capture_time
            .comparison_inputs
            .captured_wall_clock_unix_ms += 1;
        assert_eq!(
            seal_private_session(
                &canonical_bytes(&transplanted_capture_time).expect("transplanted capture time"),
                &source_pin,
                shadow_pkcs8.as_ref(),
            )
            .expect_err("source receipts from another capture time")
            .code,
            "E_CAPTURE_BINDING"
        );
        let mut transplanted_freeze = session.clone();
        transplanted_freeze.freeze.job_id = "another-disabled-job".to_owned();
        assert_eq!(
            seal_private_session(
                &canonical_bytes(&transplanted_freeze).expect("transplanted freeze"),
                &source_pin,
                shadow_pkcs8.as_ref(),
            )
            .expect_err("source receipts from another frozen case")
            .code,
            "E_CAPTURE_BINDING"
        );
        let mut substituted_isolation = session.clone();
        substituted_isolation.isolation.source_fixture_identity =
            "substituted-source-fixture".to_owned();
        substituted_isolation.isolation.target_fixture_identity =
            "substituted-target-fixture".to_owned();
        substituted_isolation.isolation.source_network_sha256 = sha256(b"other-source-network");
        substituted_isolation.isolation.target_network_sha256 = sha256(b"other-target-network");
        substituted_isolation.isolation.reachability_receipt_sha256 = sha256(b"other-reachability");
        assert_eq!(
            seal_private_session(
                &canonical_bytes(&substituted_isolation).expect("substituted isolation"),
                &source_pin,
                shadow_pkcs8.as_ref(),
            )
            .expect_err("source receipts must authenticate isolation evidence")
            .code,
            "E_CAPTURE_BINDING"
        );
        let source_pkcs8 = Ed25519KeyPair::generate_pkcs8(&random).expect("source key");
        let source_pair =
            Ed25519KeyPair::from_pkcs8(source_pkcs8.as_ref()).expect("source key pair");
        let same_key_template = source_template_for_keys(&source_pair, &source_pair);
        assert_eq!(
            seal_private_session(
                &canonical_bytes(&same_key_template).expect("same-key template"),
                &sha256(source_pair.public_key().as_ref()),
                source_pkcs8.as_ref(),
            )
            .expect_err("same key")
            .code,
            "E_KEY"
        );
    }

    fn source_template_for_keys(
        source_key: &Ed25519KeyPair,
        shadow_key: &Ed25519KeyPair,
    ) -> Session {
        let (mut session, _) = fixture();
        session.freeze.source_capture_public_key_base64 =
            BASE64.encode(source_key.public_key().as_ref());
        session.freeze.shadow_replay_public_key_base64 =
            BASE64.encode(shadow_key.public_key().as_ref());
        let binding = source_session_binding_sha256(&session).expect("source binding");
        for event in &mut session.events {
            event.source.session_binding_sha256 = binding.clone();
            event.source.signing_public_key_sha256 = sha256(source_key.public_key().as_ref());
            sign(&mut event.source, source_key);
            event.shadow.session_binding_sha256.clear();
            event.shadow.signing_public_key_sha256.clear();
            event.shadow.signature_base64.clear();
        }
        session
    }

    #[test]
    fn every_authority_bit_fails_closed() {
        let (session, package) = fixture();
        let fields: [fn(&mut Authority); 12] = [
            |a| a.trigger = true,
            |a| a.scheduler = true,
            |a| a.controller_database = true,
            |a| a.controller_filesystem = true,
            |a| a.agent_protocol = true,
            |a| a.credentials = true,
            |a| a.connector = true,
            |a| a.external_effects = true,
            |a| a.canary = true,
            |a| a.cutover = true,
            |a| a.rollback = true,
            |a| a.decommission = true,
        ];
        for mutate in fields {
            let mut candidate = session.clone();
            mutate(&mut candidate.authority);
            assert_eq!(
                verify_fixture(&candidate, &package)
                    .expect_err("authority denied")
                    .code,
                "E_CAPTURE_BINDING"
            );
        }
    }

    #[test]
    fn event_omission_duplication_substitution_and_bad_signatures_are_denied() {
        let (session, package) = fixture();

        let mut omitted = session.clone();
        omitted.events.pop();
        assert_eq!(
            verify_fixture(&omitted, &package)
                .expect_err("omission")
                .code,
            "E_EVENT_DENOMINATOR"
        );

        let mut duplicated = session.clone();
        duplicated.events[1].source.event_id = duplicated.events[0].source.event_id;
        duplicated.events[1].shadow.event_id = duplicated.events[0].shadow.event_id;
        duplicated.events[1].source.capture_sha256 =
            duplicated.events[0].source.capture_sha256.clone();
        duplicated.events[1].shadow.capture_sha256 =
            duplicated.events[0].shadow.capture_sha256.clone();
        sign(&mut duplicated.events[1].source, &pair(7));
        sign(&mut duplicated.events[1].shadow, &pair(9));
        assert_eq!(
            verify_fixture(&duplicated, &package)
                .expect_err("duplicate")
                .code,
            "E_EVENT_JOIN"
        );

        let mut reordered = session.clone();
        reordered.events.swap(0, 1);
        assert_eq!(
            verify_fixture(&reordered, &package)
                .expect_err("reordered")
                .code,
            "E_EVENT_ORDER"
        );

        let mut substituted = session.clone();
        substituted.events[0].shadow.capture_sha256 = sha256(b"substituted");
        assert_eq!(
            verify_fixture(&substituted, &package)
                .expect_err("substitution")
                .code,
            "E_SIGNATURE"
        );

        let mut bad_signature = session;
        bad_signature.events[0].source.signature_base64 = BASE64.encode([0_u8; 64]);
        assert_eq!(
            verify_fixture(&bad_signature, &package)
                .expect_err("bad signature")
                .code,
            "E_SIGNATURE"
        );
    }

    #[test]
    fn package_drift_runtime_drift_inputs_and_isolation_fail_closed() {
        let (session, package) = fixture();

        let mut wrong_package = package;
        wrong_package.sha256 = sha256(b"other-package");
        assert_eq!(
            verify_fixture(&session, &wrong_package)
                .expect_err("package drift")
                .code,
            "E_IDENTITY"
        );

        let (_, package) = fixture();
        let session_bytes = canonical_bytes(&session).expect("session bytes");
        assert_eq!(
            verify_session(
                &session_bytes,
                HEAD,
                &sha256(b"wrong-independent-source-key-pin"),
                TEST_AUTHZ_SHA256,
                TEST_VERIFIER_SHA256,
                &package,
            )
            .expect_err("independent source-capture key pin")
            .code,
            "E_FREEZE"
        );
        assert_eq!(
            verify_session(
                &session_bytes,
                HEAD,
                &source_pin(),
                &sha256(b"wrong-independent-authz-pin"),
                TEST_VERIFIER_SHA256,
                &package,
            )
            .expect_err("independent authorization pin")
            .code,
            "E_FREEZE"
        );
        assert_eq!(
            verify_session(
                &session_bytes,
                HEAD,
                &source_pin(),
                TEST_AUTHZ_SHA256,
                &sha256(b"wrong-independent-verifier-pin"),
                &package,
            )
            .expect_err("independent verifier pin")
            .code,
            "E_FREEZE"
        );

        let mut runtime = session.clone();
        runtime.freeze.rust_image_sha256 = sha256(b"other-runtime");
        assert_eq!(
            verify_fixture(&runtime, &package)
                .expect_err("runtime drift")
                .code,
            "E_FREEZE"
        );

        let mut authz = session.clone();
        authz.freeze.authz_generation_sha256 = sha256(b"other-authz-generation");
        assert_eq!(
            verify_fixture(&authz, &package)
                .expect_err("authorization pin drift")
                .code,
            "E_FREEZE"
        );

        let mut verifier = session.clone();
        verifier.freeze.verifier_binary_sha256 = sha256(b"other-verifier");
        assert_eq!(
            verify_fixture(&verifier, &package)
                .expect_err("verifier pin drift")
                .code,
            "E_FREEZE"
        );

        let mut input = session.clone();
        input.comparison_inputs.external_input_receipts = 1;
        assert_eq!(
            verify_fixture(&input, &package)
                .expect_err("undeclared input")
                .code,
            "E_COMPARISON_INPUT"
        );

        let mut isolation = session;
        isolation.isolation.production_network_requests = 1;
        assert_eq!(
            verify_fixture(&isolation, &package)
                .expect_err("production reachability")
                .code,
            "E_CAPTURE_BINDING"
        );
    }

    #[test]
    fn trace_logs_must_be_equal_ordered_bounded_and_effect_free() {
        let (session, package) = fixture();

        let mut divergent = session.clone();
        divergent.trace.target_log[1].content_sha256 = sha256(b"different");
        assert_eq!(
            verify_fixture(&divergent, &package)
                .expect_err("divergent logs")
                .code,
            "E_CAPTURE_BINDING"
        );

        let mut reordered = session.clone();
        reordered.trace.source_log.swap(0, 1);
        reordered.trace.target_log.swap(0, 1);
        assert_eq!(
            verify_fixture(&reordered, &package)
                .expect_err("reordered logs")
                .code,
            "E_CAPTURE_BINDING"
        );

        let mut effect = session;
        effect.trace.external_effect_intents = 1;
        assert_eq!(
            verify_fixture(&effect, &package)
                .expect_err("effect intent")
                .code,
            "E_CAPTURE_BINDING"
        );
    }

    #[test]
    fn noncanonical_unknown_or_oversized_sessions_are_denied() {
        let (session, package) = fixture();
        let compact = serde_json::to_vec(&session).expect("compact");
        assert_eq!(
            verify_session(
                &compact,
                HEAD,
                &source_pin(),
                TEST_AUTHZ_SHA256,
                TEST_VERIFIER_SHA256,
                &package,
            )
            .expect_err("noncanonical")
            .code,
            "E_CANONICAL"
        );

        let mut value = serde_json::to_value(&session).expect("value");
        value
            .as_object_mut()
            .expect("object")
            .insert("unknown".to_owned(), serde_json::Value::Bool(true));
        let bytes = serde_json::to_vec_pretty(&value).expect("unknown");
        assert_eq!(
            verify_session(
                &bytes,
                HEAD,
                &source_pin(),
                TEST_AUTHZ_SHA256,
                TEST_VERIFIER_SHA256,
                &package,
            )
            .expect_err("unknown")
            .code,
            "E_SCHEMA"
        );

        assert_eq!(
            verify_session(
                &vec![b' '; MAX_SESSION_BYTES + 1],
                HEAD,
                &source_pin(),
                TEST_AUTHZ_SHA256,
                TEST_VERIFIER_SHA256,
                &package,
            )
            .expect_err("oversized")
            .code,
            "E_SIZE"
        );
    }
}
