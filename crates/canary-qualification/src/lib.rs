//! Effect-free verification of one CANARY-001 production-action ceremony.
//!
//! This crate never grants authority or contacts a production endpoint. It
//! verifies that independently signed pre-action gates, one fenced connector
//! outcome, its effect-free shadow replay, and an independent destination
//! observation all describe the same single action.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use mcloving_destination_observer::{
    ObservationPhase, ObservationReceipt, observation_receipt_digest, verify_observation_receipt,
};
use mcloving_external_connector::{
    OutcomeReceipt, OutcomeStatus, ShadowReplayReceipt, canonical_digest, content_sha256,
    outcome_receipt_digest, parse_json_no_duplicates, verify_outcome_receipt,
    verify_shadow_receipt,
};
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

pub const SESSION_SCHEMA: &str = "mcloving.canary-qualification/private-v1";
pub const RECEIPT_SCHEMA: &str = "mcloving.canary-gate-receipt/v1";
pub const MAX_SESSION_BYTES: usize = 1_048_576;

const RECEIPT_DOMAIN: &[u8] = b"mcloving-canary-gate-receipt-v1\0";
const REQUIRED_FREEZE_COMPONENTS: [&str; 20] = [
    "agent",
    "authorization",
    "cache",
    "compiler",
    "components",
    "credential_mapping",
    "dependencies",
    "destination",
    "discovery",
    "external_connector",
    "jenkins_controller_inputs",
    "mapping",
    "platform",
    "release",
    "scm_acquisition",
    "shared_libraries",
    "source",
    "state_transforms",
    "toolchain",
    "trigger",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationReceipt {
    pub schema: &'static str,
    pub session_id: Uuid,
    pub job_id: String,
    pub action_id: Uuid,
    pub verified_pre_action_gates: usize,
    pub verified_authoritative_outcomes: usize,
    pub verified_shadow_replays: usize,
    pub verified_destination_observations: usize,
    pub duplicate_effects: u64,
    pub canary_qualified: bool,
    pub authority_granted_by_verifier: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IndependentPins {
    pub session_sha256: String,
    pub threat_model_key_sha256: String,
    pub inventory_key_sha256: String,
    pub freeze_key_sha256: String,
    pub quiescence_key_sha256: String,
    pub history_key_sha256: String,
    pub intent_key_sha256: String,
    pub grant_key_sha256: String,
    pub connector_outcome_key_sha256: String,
    pub shadow_replay_key_sha256: String,
    pub observer_receipt_key_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualificationError {
    pub code: &'static str,
}

impl QualificationError {
    const fn new(code: &'static str) -> Self {
        Self { code }
    }
}

impl fmt::Display for QualificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code)
    }
}

impl std::error::Error for QualificationError {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanarySession {
    pub schema: String,
    pub session_id: Uuid,
    pub ticket: String,
    pub job_id: String,
    pub action_id: Uuid,
    pub implementation_head: String,
    pub package_sha256: String,
    pub mig006_receipt_sha256: String,
    pub shadow_session_sha256: String,
    pub platform: Platform,
    pub threat_model: SignedReceipt<ThreatModelReview>,
    pub inventory: SignedReceipt<InventoryReconciliation>,
    pub freeze: SignedReceipt<RuntimeFreeze>,
    pub quiescence: SignedReceipt<QuiescenceProof>,
    pub history: SignedReceipt<HistoryTransfer>,
    pub intent: SignedReceipt<IntentMatch>,
    pub grant: SignedReceipt<EffectGrant>,
    pub connector_outcome_public_key_base64: String,
    pub connector_outcome: OutcomeReceipt,
    pub shadow_replay_public_key_base64: String,
    pub shadow_replay: ShadowReplayReceipt,
    pub observer_receipt_public_key_base64: String,
    pub pre_action_observation: ObservationReceipt,
    pub destination_observation: ObservationReceipt,
    pub windows_interruption: Option<SignedReceipt<WindowsInterruptionProof>>,
    pub authority: AuthorityLedger,
    pub completed_at_unix_ms: i64,
    pub downstream_released_at_unix_ms: i64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    LinuxX86_64,
    WindowsX86_64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReceipt<T> {
    pub body: T,
    pub signing_key_id: String,
    pub signing_public_key_base64: String,
    pub signature_base64: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptContext {
    pub schema: String,
    pub session_id: Uuid,
    pub ticket: String,
    pub job_id: String,
    pub action_id: Uuid,
    pub implementation_head: String,
    pub package_sha256: String,
    pub mig006_receipt_sha256: String,
    pub shadow_session_sha256: String,
    pub collected_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub evidence_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ThreatModelReview {
    pub context: ReceiptContext,
    pub threat_model_sha256: String,
    pub mitigations_sha256: String,
    pub verification_evidence_sha256: String,
    pub residual_risk_sha256: String,
    pub reviewers: Vec<String>,
    pub residual_risk_accepted: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryReconciliation {
    pub context: ReceiptContext,
    pub source_controller: String,
    pub inventory_epoch: String,
    pub certified_inventory_sha256: String,
    pub observed_inventory_sha256: String,
    pub external_readers_remaining: u64,
    pub administrative_writers_remaining: u64,
    pub job_enabled: bool,
    pub canary_eligible: bool,
    pub effect_class: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeFreeze {
    pub context: ReceiptContext,
    pub certified_components: BTreeMap<String, String>,
    pub observed_components: BTreeMap<String, String>,
    pub atomic_reread: bool,
    pub frozen_before_grant: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QuiescenceProof {
    pub context: ReceiptContext,
    pub relinquishing_runner: String,
    pub gaining_runner: String,
    pub ingress_paused: bool,
    pub scheduling_frozen: bool,
    pub grants_frozen: bool,
    pub queued_work: u64,
    pub running_work: u64,
    pub issued_credentials: u64,
    pub connector_authorities: u64,
    pub leases: u64,
    pub locks: u64,
    pub retries: u64,
    pub uncertain_effects: u64,
    pub relinquishing_runner_effect_authority: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryTransfer {
    pub context: ReceiptContext,
    pub source_export_sha256: String,
    pub transform_implementation_sha256: String,
    pub transform_configuration_sha256: String,
    pub transformed_state_sha256: String,
    pub destination_verification_sha256: String,
    pub exported_records: u64,
    pub imported_records: u64,
    pub retention_not_shortened: bool,
    pub every_hold_preserved: bool,
    pub secret_scan_clean: bool,
    pub complete_since_prior_transfer: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IntentMatch {
    pub context: ReceiptContext,
    pub source_intent_sha256: String,
    pub target_intent_sha256: String,
    pub effect_key: String,
    pub effect_fence: u64,
    pub matched_before_grant: bool,
    pub buffered_source_intents: u64,
    pub buffered_target_intents: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectGrant {
    pub context: ReceiptContext,
    pub authoritative_runner: String,
    pub connector_id: String,
    pub connector_implementation_sha256: String,
    pub connector_image_sha256: String,
    pub connector_config_sha256: String,
    pub endpoint_identity: String,
    pub account_identity: String,
    pub resource_identity: String,
    pub effect_class: String,
    pub effect_key: String,
    pub effect_fence: u64,
    pub intent_sha256: String,
    pub request_id: Uuid,
    pub tenant_id: Uuid,
    pub project_id: Uuid,
    pub pipeline_id: Uuid,
    pub build_id: Uuid,
    pub attempt_id: Uuid,
    pub request_sha256: String,
    pub pre_action_observation_sha256: String,
    pub expected_post_state_sha256: String,
    pub issued_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub max_actions: u64,
    pub max_attempts: u8,
    pub max_authority_window_ms: i64,
    pub abort_after_failures: u64,
    pub retention_deadline_unix_ms: i64,
    pub audit_policy_sha256: String,
    pub abort_rules_sha256: String,
    pub ambiguity_freezes_new_effects: bool,
    pub one_action_only: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsInterruptionProof {
    pub context: ReceiptContext,
    pub persistent_host_identity: String,
    pub interruption_receipt_sha256: String,
    pub reboot_receipt_sha256: String,
    pub no_orphan_process: bool,
    pub no_duplicate_effect: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityLedger {
    pub relinquishing_runner_effect_authority_before_grant: bool,
    pub authoritative_runner_effect_authority_during_action: bool,
    pub shadow_effect_authority: bool,
    pub shadow_production_endpoint: bool,
    pub grant_consumed_actions: u64,
    pub duplicate_effects: u64,
    pub ambiguous_effects: u64,
    pub new_effects_frozen_after_action: bool,
}

pub fn verify_session_bytes(
    bytes: &[u8],
    pins: &IndependentPins,
) -> Result<VerificationReceipt, QualificationError> {
    if bytes.is_empty()
        || bytes.len() > MAX_SESSION_BYTES
        || !is_sha256(&pins.session_sha256)
        || content_sha256(bytes) != pins.session_sha256
    {
        return Err(QualificationError::new("CANARY_SESSION_PIN_MISMATCH"));
    }
    let session: CanarySession = parse_json_no_duplicates(bytes)
        .map_err(|_| QualificationError::new("CANARY_SESSION_INVALID"))?;
    let canonical = serde_json::to_vec(&session)
        .map_err(|_| QualificationError::new("CANARY_SESSION_INVALID"))?;
    if canonical != bytes {
        return Err(QualificationError::new("CANARY_SESSION_NONCANONICAL"));
    }
    verify_session(&session, pins)
}

fn verify_session(
    session: &CanarySession,
    pins: &IndependentPins,
) -> Result<VerificationReceipt, QualificationError> {
    verify_root(session)?;
    verify_pin_set(pins)?;

    verify_signed(&session.threat_model, &pins.threat_model_key_sha256)?;
    verify_signed(&session.inventory, &pins.inventory_key_sha256)?;
    verify_signed(&session.freeze, &pins.freeze_key_sha256)?;
    verify_signed(&session.quiescence, &pins.quiescence_key_sha256)?;
    verify_signed(&session.history, &pins.history_key_sha256)?;
    verify_signed(&session.intent, &pins.intent_key_sha256)?;
    verify_signed(&session.grant, &pins.grant_key_sha256)?;

    for context in [
        &session.threat_model.body.context,
        &session.inventory.body.context,
        &session.freeze.body.context,
        &session.quiescence.body.context,
        &session.history.body.context,
        &session.intent.body.context,
        &session.grant.body.context,
    ] {
        verify_context(session, context)?;
    }

    verify_threat_model(&session.threat_model.body)?;
    verify_inventory(&session.inventory.body)?;
    verify_freeze(&session.freeze.body)?;
    verify_quiescence(&session.quiescence.body)?;
    verify_history(&session.history.body)?;
    verify_intent(&session.intent.body)?;
    verify_grant(session)?;
    verify_windows(session, pins)?;
    verify_effect_receipts(session, pins)?;
    verify_authority(session)?;

    Ok(VerificationReceipt {
        schema: SESSION_SCHEMA,
        session_id: session.session_id,
        job_id: session.job_id.clone(),
        action_id: session.action_id,
        verified_pre_action_gates: 7 + usize::from(session.windows_interruption.is_some()),
        verified_authoritative_outcomes: 1,
        verified_shadow_replays: 1,
        verified_destination_observations: 2,
        duplicate_effects: 0,
        canary_qualified: true,
        authority_granted_by_verifier: false,
    })
}

fn verify_root(session: &CanarySession) -> Result<(), QualificationError> {
    if session.schema != SESSION_SCHEMA
        || session.ticket != "CANARY-001"
        || session.session_id.is_nil()
        || session.action_id.is_nil()
        || session.job_id.is_empty()
        || !is_git_oid(&session.implementation_head)
        || !is_sha256(&session.package_sha256)
        || !is_sha256(&session.mig006_receipt_sha256)
        || !is_sha256(&session.shadow_session_sha256)
        || session.completed_at_unix_ms <= 0
        || session.downstream_released_at_unix_ms < session.completed_at_unix_ms
    {
        return Err(QualificationError::new("CANARY_ROOT_BINDING_INVALID"));
    }
    Ok(())
}

fn verify_pin_set(pins: &IndependentPins) -> Result<(), QualificationError> {
    let values = [
        &pins.threat_model_key_sha256,
        &pins.inventory_key_sha256,
        &pins.freeze_key_sha256,
        &pins.quiescence_key_sha256,
        &pins.history_key_sha256,
        &pins.intent_key_sha256,
        &pins.grant_key_sha256,
        &pins.connector_outcome_key_sha256,
        &pins.shadow_replay_key_sha256,
        &pins.observer_receipt_key_sha256,
    ];
    if values.iter().any(|value| !is_sha256(value))
        || values.iter().collect::<BTreeSet<_>>().len() != values.len()
    {
        return Err(QualificationError::new("CANARY_ROLE_KEYS_NOT_INDEPENDENT"));
    }
    Ok(())
}

fn verify_signed<T: Serialize>(
    receipt: &SignedReceipt<T>,
    expected_key_sha256: &str,
) -> Result<(), QualificationError> {
    let public_key = BASE64
        .decode(&receipt.signing_public_key_base64)
        .map_err(|_| QualificationError::new("CANARY_GATE_SIGNATURE_INVALID"))?;
    let signature = BASE64
        .decode(&receipt.signature_base64)
        .map_err(|_| QualificationError::new("CANARY_GATE_SIGNATURE_INVALID"))?;
    if receipt.signing_key_id.is_empty()
        || public_key.len() != 32
        || content_sha256(&public_key) != expected_key_sha256
    {
        return Err(QualificationError::new("CANARY_GATE_KEY_MISMATCH"));
    }
    let body = serde_json::to_vec(&receipt.body)
        .map_err(|_| QualificationError::new("CANARY_GATE_SIGNATURE_INVALID"))?;
    let mut message = Vec::with_capacity(RECEIPT_DOMAIN.len() + body.len());
    message.extend_from_slice(RECEIPT_DOMAIN);
    message.extend_from_slice(&body);
    UnparsedPublicKey::new(&ED25519, &public_key)
        .verify(&message, &signature)
        .map_err(|_| QualificationError::new("CANARY_GATE_SIGNATURE_INVALID"))
}

fn verify_context(
    session: &CanarySession,
    context: &ReceiptContext,
) -> Result<(), QualificationError> {
    if context.schema != RECEIPT_SCHEMA
        || context.session_id != session.session_id
        || context.ticket != session.ticket
        || context.job_id != session.job_id
        || context.action_id != session.action_id
        || context.implementation_head != session.implementation_head
        || context.package_sha256 != session.package_sha256
        || context.mig006_receipt_sha256 != session.mig006_receipt_sha256
        || context.shadow_session_sha256 != session.shadow_session_sha256
        || context.collected_at_unix_ms <= 0
        || context.expires_at_unix_ms <= context.collected_at_unix_ms
        || context.expires_at_unix_ms < session.grant.body.issued_at_unix_ms
        || !is_sha256(&context.evidence_sha256)
    {
        return Err(QualificationError::new("CANARY_GATE_CONTEXT_MISMATCH"));
    }
    Ok(())
}

fn verify_threat_model(review: &ThreatModelReview) -> Result<(), QualificationError> {
    let reviewers = review.reviewers.iter().collect::<BTreeSet<_>>();
    if !review.residual_risk_accepted
        || reviewers.len() < 2
        || review.reviewers.iter().any(|reviewer| reviewer.is_empty())
        || [
            &review.threat_model_sha256,
            &review.mitigations_sha256,
            &review.verification_evidence_sha256,
            &review.residual_risk_sha256,
        ]
        .iter()
        .any(|digest| !is_sha256(digest))
    {
        return Err(QualificationError::new(
            "CANARY_THREAT_MODEL_REVIEW_INVALID",
        ));
    }
    Ok(())
}

fn verify_inventory(inventory: &InventoryReconciliation) -> Result<(), QualificationError> {
    if inventory.source_controller.is_empty()
        || inventory.inventory_epoch.is_empty()
        || !is_sha256(&inventory.certified_inventory_sha256)
        || inventory.certified_inventory_sha256 != inventory.observed_inventory_sha256
        || inventory.external_readers_remaining != 0
        || inventory.administrative_writers_remaining != 0
        || !inventory.job_enabled
        || !inventory.canary_eligible
        || inventory.effect_class.is_empty()
    {
        return Err(QualificationError::new("CANARY_INVENTORY_INELIGIBLE"));
    }
    Ok(())
}

fn verify_freeze(freeze: &RuntimeFreeze) -> Result<(), QualificationError> {
    let required = REQUIRED_FREEZE_COMPONENTS
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<BTreeSet<_>>();
    let actual = freeze
        .certified_components
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    if !freeze.atomic_reread
        || !freeze.frozen_before_grant
        || actual != required
        || freeze.certified_components != freeze.observed_components
        || freeze
            .certified_components
            .values()
            .any(|digest| !is_sha256(digest))
    {
        return Err(QualificationError::new("CANARY_RUNTIME_FREEZE_INVALID"));
    }
    Ok(())
}

fn verify_quiescence(proof: &QuiescenceProof) -> Result<(), QualificationError> {
    if proof.relinquishing_runner.is_empty()
        || proof.gaining_runner.is_empty()
        || proof.relinquishing_runner == proof.gaining_runner
        || !proof.ingress_paused
        || !proof.scheduling_frozen
        || !proof.grants_frozen
        || proof.relinquishing_runner_effect_authority
        || [
            proof.queued_work,
            proof.running_work,
            proof.issued_credentials,
            proof.connector_authorities,
            proof.leases,
            proof.locks,
            proof.retries,
            proof.uncertain_effects,
        ]
        .iter()
        .any(|count| *count != 0)
    {
        return Err(QualificationError::new("CANARY_QUIESCENCE_INVALID"));
    }
    Ok(())
}

fn verify_history(history: &HistoryTransfer) -> Result<(), QualificationError> {
    if [
        &history.source_export_sha256,
        &history.transform_implementation_sha256,
        &history.transform_configuration_sha256,
        &history.transformed_state_sha256,
        &history.destination_verification_sha256,
    ]
    .iter()
    .any(|digest| !is_sha256(digest))
        || history.exported_records != history.imported_records
        || !history.retention_not_shortened
        || !history.every_hold_preserved
        || !history.secret_scan_clean
        || !history.complete_since_prior_transfer
    {
        return Err(QualificationError::new("CANARY_HISTORY_TRANSFER_INVALID"));
    }
    Ok(())
}

fn verify_intent(intent: &IntentMatch) -> Result<(), QualificationError> {
    if !is_sha256(&intent.source_intent_sha256)
        || intent.source_intent_sha256 != intent.target_intent_sha256
        || intent.effect_key.is_empty()
        || intent.effect_fence == 0
        || !intent.matched_before_grant
        || intent.buffered_source_intents != 1
        || intent.buffered_target_intents != 1
    {
        return Err(QualificationError::new("CANARY_INTENT_MISMATCH"));
    }
    Ok(())
}

fn verify_grant(session: &CanarySession) -> Result<(), QualificationError> {
    let grant = &session.grant.body;
    let intent = &session.intent.body;
    let inventory = &session.inventory.body;
    let quiescence = &session.quiescence.body;
    if grant.authoritative_runner != quiescence.gaining_runner
        || grant.effect_class != inventory.effect_class
        || grant.effect_key != intent.effect_key
        || grant.effect_fence != intent.effect_fence
        || grant.intent_sha256 != intent.source_intent_sha256
        || grant.request_id.is_nil()
        || grant.tenant_id.is_nil()
        || grant.project_id.is_nil()
        || grant.pipeline_id.is_nil()
        || grant.build_id.is_nil()
        || grant.attempt_id.is_nil()
        || !is_sha256(&grant.request_sha256)
        || !is_sha256(&grant.pre_action_observation_sha256)
        || !is_sha256(&grant.expected_post_state_sha256)
        || grant.connector_id.is_empty()
        || [
            &grant.connector_implementation_sha256,
            &grant.connector_image_sha256,
            &grant.connector_config_sha256,
            &grant.audit_policy_sha256,
            &grant.abort_rules_sha256,
        ]
        .iter()
        .any(|digest| !is_sha256(digest))
        || grant.endpoint_identity.is_empty()
        || grant.account_identity.is_empty()
        || grant.resource_identity.is_empty()
        || grant.issued_at_unix_ms < grant.context.collected_at_unix_ms
        || grant.expires_at_unix_ms <= grant.issued_at_unix_ms
        || grant.expires_at_unix_ms - grant.issued_at_unix_ms > grant.max_authority_window_ms
        || session.completed_at_unix_ms > grant.expires_at_unix_ms
        || grant.max_actions != 1
        || grant.max_attempts == 0
        || grant.max_authority_window_ms <= 0
        || grant.abort_after_failures != 1
        || grant.retention_deadline_unix_ms < session.completed_at_unix_ms
        || !grant.ambiguity_freezes_new_effects
        || !grant.one_action_only
    {
        return Err(QualificationError::new("CANARY_EFFECT_GRANT_INVALID"));
    }
    Ok(())
}

fn verify_windows(
    session: &CanarySession,
    pins: &IndependentPins,
) -> Result<(), QualificationError> {
    match (session.platform, &session.windows_interruption) {
        (Platform::LinuxX86_64, None) => Ok(()),
        (Platform::LinuxX86_64, Some(_)) | (Platform::WindowsX86_64, None) => {
            Err(QualificationError::new("CANARY_WINDOWS_PROOF_INVALID"))
        }
        (Platform::WindowsX86_64, Some(proof)) => {
            // Windows evidence is signed by the independently pinned freeze role,
            // so it cannot be introduced by the effectful runner.
            verify_signed(proof, &pins.freeze_key_sha256)?;
            verify_context(session, &proof.body.context)?;
            if proof.body.persistent_host_identity.is_empty()
                || !is_sha256(&proof.body.interruption_receipt_sha256)
                || !is_sha256(&proof.body.reboot_receipt_sha256)
                || !proof.body.no_orphan_process
                || !proof.body.no_duplicate_effect
            {
                return Err(QualificationError::new("CANARY_WINDOWS_PROOF_INVALID"));
            }
            Ok(())
        }
    }
}

fn verify_effect_receipts(
    session: &CanarySession,
    pins: &IndependentPins,
) -> Result<(), QualificationError> {
    let outcome_key = decode_pinned_key(
        &session.connector_outcome_public_key_base64,
        &pins.connector_outcome_key_sha256,
    )?;
    verify_outcome_receipt(&session.connector_outcome, &outcome_key)
        .map_err(|_| QualificationError::new("CANARY_CONNECTOR_OUTCOME_INVALID"))?;
    let shadow_key = decode_pinned_key(
        &session.shadow_replay_public_key_base64,
        &pins.shadow_replay_key_sha256,
    )?;
    verify_shadow_receipt(&session.shadow_replay, &shadow_key)
        .map_err(|_| QualificationError::new("CANARY_SHADOW_REPLAY_INVALID"))?;
    let observer_key = decode_pinned_key(
        &session.observer_receipt_public_key_base64,
        &pins.observer_receipt_key_sha256,
    )?;
    verify_observation_receipt(&session.pre_action_observation, &observer_key)
        .map_err(|_| QualificationError::new("CANARY_PRE_ACTION_OBSERVATION_INVALID"))?;
    verify_observation_receipt(&session.destination_observation, &observer_key)
        .map_err(|_| QualificationError::new("CANARY_DESTINATION_OBSERVATION_INVALID"))?;

    let grant = &session.grant.body;
    let outcome = &session.connector_outcome;
    let shadow = &session.shadow_replay;
    let pre_action = &session.pre_action_observation;
    let observation = &session.destination_observation;
    let outcome_digest = outcome_receipt_digest(outcome)
        .map_err(|_| QualificationError::new("CANARY_CONNECTOR_OUTCOME_INVALID"))?;
    let observation_digest = observation_receipt_digest(observation)
        .map_err(|_| QualificationError::new("CANARY_DESTINATION_OBSERVATION_INVALID"))?;
    let pre_action_digest = observation_receipt_digest(pre_action)
        .map_err(|_| QualificationError::new("CANARY_PRE_ACTION_OBSERVATION_INVALID"))?;
    let observed_state_sha256 =
        canonical_digest(b"mcloving-canary-destination-state-v1", &observation.state)
            .map_err(|_| QualificationError::new("CANARY_DESTINATION_OBSERVATION_INVALID"))?;

    if outcome.connector_id != grant.connector_id
        || outcome.connector_implementation_sha256 != grant.connector_implementation_sha256
        || outcome.connector_image_sha256 != grant.connector_image_sha256
        || outcome.connector_config_sha256 != grant.connector_config_sha256
        || outcome.endpoint_identity != grant.endpoint_identity
        || outcome.account_identity != grant.account_identity
        || outcome.resource_identity != grant.resource_identity
        || outcome.effect_class != grant.effect_class
        || outcome.effect_key != grant.effect_key
        || outcome.effect_fence != grant.effect_fence
        || outcome.request_id != grant.request_id
        || outcome.tenant_id != grant.tenant_id
        || outcome.project_id != grant.project_id
        || outcome.pipeline_id != grant.pipeline_id
        || outcome.build_id != grant.build_id
        || outcome.attempt_id != grant.attempt_id
        || outcome.request_sha256 != grant.request_sha256
        || outcome.status != OutcomeStatus::Succeeded
        || outcome.ambiguous_requires_observation
        || outcome.attempt_count == 0
        || outcome.attempt_count > grant.max_attempts
        || outcome.observation_receipt_sha256.as_deref() != Some(observation_digest.as_str())
        || shadow.outcome_receipt_sha256 != outcome_digest
        || shadow.request_id != outcome.request_id
        || shadow.tenant_id != outcome.tenant_id
        || shadow.project_id != outcome.project_id
        || shadow.build_id != outcome.build_id
        || shadow.attempt_id != outcome.attempt_id
        || shadow.effect_fence != outcome.effect_fence
        || shadow.effect_key != outcome.effect_key
        || shadow.status != outcome.status
        || shadow.status_code != outcome.status_code
        || shadow.public_values != outcome.public_values
        || shadow.protected_secret_refs != outcome.protected_secret_refs
        || shadow.external_ids != outcome.external_ids
        || shadow.downstream_control_digest != outcome.downstream_control_digest
        || shadow.later_intents_digest != outcome.later_intents_digest
        || shadow.replayed_at_unix_ms < outcome.captured_at_unix_ms
        || shadow.replayed_at_unix_ms > session.downstream_released_at_unix_ms
        || pre_action_digest != grant.pre_action_observation_sha256
        || pre_action.phase != ObservationPhase::PreAction
        || pre_action.predecessor_receipt_sha256.is_some()
        || pre_action.tenant_id != grant.tenant_id
        || pre_action.project_id != grant.project_id
        || pre_action.pipeline_id != grant.pipeline_id
        || pre_action.build_id != grant.build_id
        || pre_action.attempt_id != grant.attempt_id
        || pre_action.effect_fence != grant.effect_fence
        || pre_action.endpoint_identity != grant.endpoint_identity
        || pre_action.account_identity != grant.account_identity
        || pre_action.resource_identity != grant.resource_identity
        || pre_action.effect_class != grant.effect_class
        || pre_action.destination_observed_at_unix_ms > grant.issued_at_unix_ms
        || pre_action.captured_at_unix_ms > grant.issued_at_unix_ms
        || pre_action.captured_at_unix_ms < pre_action.destination_observed_at_unix_ms
        || pre_action.publication_deadline_unix_ms < grant.issued_at_unix_ms
        || observation.phase != ObservationPhase::PostAction
        || observation.predecessor_receipt_sha256.as_deref() != Some(pre_action_digest.as_str())
        || observation.observer_id != pre_action.observer_id
        || observation.observer_implementation_sha256 != pre_action.observer_implementation_sha256
        || observation.observer_image_sha256 != pre_action.observer_image_sha256
        || observation.observer_config_sha256 != pre_action.observer_config_sha256
        || observation.deployment_identity != pre_action.deployment_identity
        || observation.operator_trust_identity != pre_action.operator_trust_identity
        || observation.runtime_boundary_identity != pre_action.runtime_boundary_identity
        || observation.service_identity != pre_action.service_identity
        || observation.credential_issuance_path_identity
            != pre_action.credential_issuance_path_identity
        || observation.configuration_authority_identity
            != pre_action.configuration_authority_identity
        || observation.request_authority_identity != pre_action.request_authority_identity
        || observation.generation != pre_action.generation
        || observation.activation_mode != pre_action.activation_mode
        || observation.read_grant_id != pre_action.read_grant_id
        || observation.read_grant_version != pre_action.read_grant_version
        || observation.read_grant_scope != pre_action.read_grant_scope
        || observation.destination_attestation_key_id != pre_action.destination_attestation_key_id
        || observation.receipt_signing_key_id != pre_action.receipt_signing_key_id
        || observation.state_schema_version != pre_action.state_schema_version
        || observation.confidentiality != pre_action.confidentiality
        || observation.destination_cursor <= pre_action.destination_cursor
        || observation.destination_observed_at_unix_ms < pre_action.destination_observed_at_unix_ms
        || observation.tenant_id != outcome.tenant_id
        || observation.project_id != outcome.project_id
        || observation.pipeline_id != outcome.pipeline_id
        || observation.build_id != outcome.build_id
        || observation.attempt_id != outcome.attempt_id
        || observation.effect_fence != outcome.effect_fence
        || observation.endpoint_identity != outcome.endpoint_identity
        || observation.account_identity != outcome.account_identity
        || observation.resource_identity != outcome.resource_identity
        || observation.effect_class != outcome.effect_class
        || observed_state_sha256 != grant.expected_post_state_sha256
        || outcome.captured_at_unix_ms < grant.issued_at_unix_ms
        || outcome.captured_at_unix_ms > grant.expires_at_unix_ms
        || observation.destination_observed_at_unix_ms < outcome.captured_at_unix_ms
        || observation.captured_at_unix_ms < observation.destination_observed_at_unix_ms
        || observation.captured_at_unix_ms > observation.publication_deadline_unix_ms
        || session.completed_at_unix_ms < observation.captured_at_unix_ms
        || session.completed_at_unix_ms < shadow.replayed_at_unix_ms
        || observation.publication_deadline_unix_ms < session.completed_at_unix_ms
        || outcome.deployment_identity == observation.deployment_identity
        || outcome.runtime_boundary_identity == observation.runtime_boundary_identity
        || outcome.service_identity == observation.service_identity
        || outcome.credential_issuance_path_identity
            == observation.credential_issuance_path_identity
    {
        return Err(QualificationError::new(
            "CANARY_EFFECT_RECEIPT_JOIN_INVALID",
        ));
    }
    Ok(())
}

fn verify_authority(session: &CanarySession) -> Result<(), QualificationError> {
    let authority = &session.authority;
    if authority.relinquishing_runner_effect_authority_before_grant
        || !authority.authoritative_runner_effect_authority_during_action
        || authority.shadow_effect_authority
        || authority.shadow_production_endpoint
        || authority.grant_consumed_actions != 1
        || authority.duplicate_effects != 0
        || authority.ambiguous_effects != 0
        || !authority.new_effects_frozen_after_action
    {
        return Err(QualificationError::new("CANARY_AUTHORITY_LEDGER_INVALID"));
    }
    Ok(())
}

fn decode_pinned_key(encoded: &str, expected: &str) -> Result<Vec<u8>, QualificationError> {
    let key = BASE64
        .decode(encoded)
        .map_err(|_| QualificationError::new("CANARY_EXTERNAL_KEY_INVALID"))?;
    if key.len() != 32 || content_sha256(&key) != expected {
        return Err(QualificationError::new("CANARY_EXTERNAL_KEY_INVALID"));
    }
    Ok(key)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_git_oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn session_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

pub fn canonical_session_bytes(session: &CanarySession) -> Result<Vec<u8>, QualificationError> {
    serde_json::to_vec(session).map_err(|_| QualificationError::new("CANARY_SESSION_INVALID"))
}

pub fn parse_independent_pins(bytes: &[u8]) -> Result<IndependentPins, QualificationError> {
    let pins: IndependentPins = parse_json_no_duplicates(bytes)
        .map_err(|_| QualificationError::new("CANARY_PINS_INVALID"))?;
    let canonical =
        serde_json::to_vec(&pins).map_err(|_| QualificationError::new("CANARY_PINS_INVALID"))?;
    if canonical != bytes {
        return Err(QualificationError::new("CANARY_PINS_NONCANONICAL"));
    }
    Ok(pins)
}

pub fn signed_receipt_message<T: Serialize>(body: &T) -> Result<Vec<u8>, QualificationError> {
    let body = serde_json::to_vec(body)
        .map_err(|_| QualificationError::new("CANARY_GATE_SIGNATURE_INVALID"))?;
    let mut message = Vec::with_capacity(RECEIPT_DOMAIN.len() + body.len());
    message.extend_from_slice(RECEIPT_DOMAIN);
    message.extend_from_slice(&body);
    Ok(message)
}

pub fn parse_canonical<T>(bytes: &[u8]) -> Result<T, QualificationError>
where
    T: DeserializeOwned + Serialize,
{
    let value: T = parse_json_no_duplicates(bytes)
        .map_err(|_| QualificationError::new("CANARY_JSON_INVALID"))?;
    if serde_json::to_vec(&value).map_err(|_| QualificationError::new("CANARY_JSON_INVALID"))?
        != bytes
    {
        return Err(QualificationError::new("CANARY_JSON_NONCANONICAL"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use mcloving_destination_observer::{
        ActivationMode as ObserverActivationMode, Confidentiality, ObservationPhase,
        ObservationReceipt, PROTOCOL_VERSION as OBSERVER_PROTOCOL, RECEIPT_SCHEMA_VERSION,
        sign_receipt,
    };
    use mcloving_external_connector::{
        ActivationMode, OUTCOME_RECEIPT_SCHEMA_VERSION, OutcomeReceipt, OutcomeStatus,
        PROTOCOL_VERSION as CONNECTOR_PROTOCOL, SHADOW_RECEIPT_SCHEMA_VERSION, ShadowReplayReceipt,
        sign_outcome_receipt, sign_shadow_receipt,
    };
    use ring::signature::{Ed25519KeyPair, KeyPair as _};
    use serde::Serialize;
    use uuid::Uuid;

    use super::*;

    const SESSION_ID: Uuid = Uuid::from_u128(1);
    const ACTION_ID: Uuid = Uuid::from_u128(2);
    const TENANT_ID: Uuid = Uuid::from_u128(3);
    const PROJECT_ID: Uuid = Uuid::from_u128(4);
    const PIPELINE_ID: Uuid = Uuid::from_u128(5);
    const BUILD_ID: Uuid = Uuid::from_u128(6);
    const ATTEMPT_ID: Uuid = Uuid::from_u128(7);
    const REQUEST_ID: Uuid = Uuid::from_u128(8);

    #[test]
    fn exact_single_action_session_is_accepted_without_granting_authority() {
        let (session, mut pins) = fixture();
        let bytes = canonical_session_bytes(&session).unwrap();
        pins.session_sha256 = session_sha256(&bytes);
        let receipt = verify_session_bytes(&bytes, &pins).unwrap();
        assert!(receipt.canary_qualified);
        assert!(!receipt.authority_granted_by_verifier);
        assert_eq!(receipt.verified_pre_action_gates, 7);
        assert_eq!(receipt.verified_destination_observations, 2);
        assert_eq!(receipt.duplicate_effects, 0);
    }

    #[test]
    fn ineligible_inventory_cannot_be_promoted_by_a_valid_signature() {
        let (mut session, pins) = fixture();
        session.inventory.body.canary_eligible = false;
        resign(&mut session.inventory, seed(2));
        assert_eq!(
            verify_session(&session, &pins).unwrap_err().code,
            "CANARY_INVENTORY_INELIGIBLE"
        );
    }

    #[test]
    fn partial_runtime_freeze_is_rejected() {
        let (mut session, pins) = fixture();
        session.freeze.body.observed_components.remove("cache");
        resign(&mut session.freeze, seed(3));
        assert_eq!(
            verify_session(&session, &pins).unwrap_err().code,
            "CANARY_RUNTIME_FREEZE_INVALID"
        );
    }

    #[test]
    fn shadow_must_replay_the_exact_authoritative_outcome() {
        let (mut session, pins) = fixture();
        session.shadow_replay.status_code = "substituted".to_owned();
        sign_shadow_receipt(&mut session.shadow_replay, &seed(9)).unwrap();
        assert_eq!(
            verify_session(&session, &pins).unwrap_err().code,
            "CANARY_EFFECT_RECEIPT_JOIN_INVALID"
        );
    }

    #[test]
    fn observed_destination_state_must_match_the_precommitted_result() {
        let (mut session, pins) = fixture();
        session.grant.body.expected_post_state_sha256 = hash('f');
        resign(&mut session.grant, seed(7));
        assert_eq!(
            verify_session(&session, &pins).unwrap_err().code,
            "CANARY_EFFECT_RECEIPT_JOIN_INVALID"
        );
    }

    #[test]
    fn observer_identity_cannot_change_between_precondition_and_result() {
        let (mut session, pins) = fixture();
        session.destination_observation.observer_config_sha256 = hash('f');
        sign_receipt(&mut session.destination_observation, &seed(10)).unwrap();
        let observation_digest =
            observation_receipt_digest(&session.destination_observation).unwrap();
        session.connector_outcome.observation_receipt_sha256 = Some(observation_digest);
        sign_outcome_receipt(&mut session.connector_outcome, &seed(8)).unwrap();
        session.shadow_replay.outcome_receipt_sha256 =
            outcome_receipt_digest(&session.connector_outcome).unwrap();
        sign_shadow_receipt(&mut session.shadow_replay, &seed(9)).unwrap();
        assert_eq!(
            verify_session(&session, &pins).unwrap_err().code,
            "CANARY_EFFECT_RECEIPT_JOIN_INVALID"
        );
    }

    #[test]
    fn signing_roles_cannot_share_a_key() {
        let (session, mut pins) = fixture();
        pins.observer_receipt_key_sha256 = pins.connector_outcome_key_sha256.clone();
        assert_eq!(
            verify_session(&session, &pins).unwrap_err().code,
            "CANARY_ROLE_KEYS_NOT_INDEPENDENT"
        );
    }

    #[test]
    fn noncanonical_or_duplicate_json_is_rejected() {
        let (session, mut pins) = fixture();
        let canonical = canonical_session_bytes(&session).unwrap();
        let mut padded = canonical.clone();
        padded.push(b'\n');
        pins.session_sha256 = session_sha256(&padded);
        assert_eq!(
            verify_session_bytes(&padded, &pins).unwrap_err().code,
            "CANARY_SESSION_NONCANONICAL"
        );

        let canonical = String::from_utf8(canonical).unwrap();
        let duplicate = canonical.replacen(
            "{\"schema\":",
            "{\"schema\":\"mcloving.canary-qualification/private-v1\",\"schema\":",
            1,
        );
        pins.session_sha256 = session_sha256(duplicate.as_bytes());
        assert_eq!(
            verify_session_bytes(duplicate.as_bytes(), &pins)
                .unwrap_err()
                .code,
            "CANARY_SESSION_INVALID"
        );
    }

    #[test]
    fn windows_action_requires_persistent_host_interruption_and_reboot_proof() {
        let (mut session, pins) = fixture();
        session.platform = Platform::WindowsX86_64;
        assert_eq!(
            verify_session(&session, &pins).unwrap_err().code,
            "CANARY_WINDOWS_PROOF_INVALID"
        );
    }

    fn fixture() -> (CanarySession, IndependentPins) {
        let contexts = context();
        let components = REQUIRED_FREEZE_COMPONENTS
            .iter()
            .map(|name| ((*name).to_owned(), digest(name.as_bytes())))
            .collect::<BTreeMap<_, _>>();

        let threat_model = signed(
            ThreatModelReview {
                context: contexts.clone(),
                threat_model_sha256: hash('1'),
                mitigations_sha256: hash('2'),
                verification_evidence_sha256: hash('3'),
                residual_risk_sha256: hash('4'),
                reviewers: vec![
                    "security-architecture".to_owned(),
                    "independent-review".to_owned(),
                ],
                residual_risk_accepted: true,
            },
            1,
        );
        let inventory = signed(
            InventoryReconciliation {
                context: contexts.clone(),
                source_controller: "mario".to_owned(),
                inventory_epoch: "epoch-2".to_owned(),
                certified_inventory_sha256: hash('5'),
                observed_inventory_sha256: hash('5'),
                external_readers_remaining: 0,
                administrative_writers_remaining: 0,
                job_enabled: true,
                canary_eligible: true,
                effect_class: "deployment".to_owned(),
            },
            2,
        );
        let freeze = signed(
            RuntimeFreeze {
                context: contexts.clone(),
                certified_components: components.clone(),
                observed_components: components,
                atomic_reread: true,
                frozen_before_grant: true,
            },
            3,
        );
        let quiescence = signed(
            QuiescenceProof {
                context: contexts.clone(),
                relinquishing_runner: "jenkins/mario".to_owned(),
                gaining_runner: "mcloving/canary".to_owned(),
                ingress_paused: true,
                scheduling_frozen: true,
                grants_frozen: true,
                queued_work: 0,
                running_work: 0,
                issued_credentials: 0,
                connector_authorities: 0,
                leases: 0,
                locks: 0,
                retries: 0,
                uncertain_effects: 0,
                relinquishing_runner_effect_authority: false,
            },
            4,
        );
        let history = signed(
            HistoryTransfer {
                context: contexts.clone(),
                source_export_sha256: hash('6'),
                transform_implementation_sha256: hash('7'),
                transform_configuration_sha256: hash('8'),
                transformed_state_sha256: hash('9'),
                destination_verification_sha256: hash('a'),
                exported_records: 2,
                imported_records: 2,
                retention_not_shortened: true,
                every_hold_preserved: true,
                secret_scan_clean: true,
                complete_since_prior_transfer: true,
            },
            5,
        );
        let intent = signed(
            IntentMatch {
                context: contexts.clone(),
                source_intent_sha256: hash('b'),
                target_intent_sha256: hash('b'),
                effect_key: "deploy/service/one".to_owned(),
                effect_fence: 17,
                matched_before_grant: true,
                buffered_source_intents: 1,
                buffered_target_intents: 1,
            },
            6,
        );
        let observer_seed = seed(10);
        let observer_public = public_key(&observer_seed);
        let mut pre_action_observation = pre_action_observation(&observer_public);
        sign_receipt(&mut pre_action_observation, &observer_seed).unwrap();
        let pre_action_digest = observation_receipt_digest(&pre_action_observation).unwrap();
        let grant = signed(
            EffectGrant {
                context: contexts,
                authoritative_runner: "mcloving/canary".to_owned(),
                connector_id: "connector/deploy".to_owned(),
                connector_implementation_sha256: hash('c'),
                connector_image_sha256: hash('d'),
                connector_config_sha256: hash('e'),
                endpoint_identity: "endpoint/production".to_owned(),
                account_identity: "account/production".to_owned(),
                resource_identity: "resource/service/one".to_owned(),
                effect_class: "deployment".to_owned(),
                effect_key: "deploy/service/one".to_owned(),
                effect_fence: 17,
                intent_sha256: hash('b'),
                request_id: REQUEST_ID,
                tenant_id: TENANT_ID,
                project_id: PROJECT_ID,
                pipeline_id: PIPELINE_ID,
                build_id: BUILD_ID,
                attempt_id: ATTEMPT_ID,
                request_sha256: hash('1'),
                pre_action_observation_sha256: pre_action_digest.clone(),
                expected_post_state_sha256: canonical_digest(
                    b"mcloving-canary-destination-state-v1",
                    &serde_json::json!({"revision": "one"}),
                )
                .unwrap(),
                issued_at_unix_ms: 200,
                expires_at_unix_ms: 1_000,
                max_actions: 1,
                max_attempts: 2,
                max_authority_window_ms: 800,
                abort_after_failures: 1,
                retention_deadline_unix_ms: 10_000,
                audit_policy_sha256: hash('f'),
                abort_rules_sha256: hash('0'),
                ambiguity_freezes_new_effects: true,
                one_action_only: true,
            },
            7,
        );

        let mut observation = observation(&observer_public, pre_action_digest);
        sign_receipt(&mut observation, &observer_seed).unwrap();
        let observation_digest = observation_receipt_digest(&observation).unwrap();

        let outcome_seed = seed(8);
        let outcome_public = public_key(&outcome_seed);
        let mut outcome = outcome(&outcome_public, observation_digest);
        sign_outcome_receipt(&mut outcome, &outcome_seed).unwrap();
        let outcome_digest = outcome_receipt_digest(&outcome).unwrap();

        let shadow_seed = seed(9);
        let shadow_public = public_key(&shadow_seed);
        let mut shadow = shadow(&shadow_public, outcome_digest, &outcome);
        sign_shadow_receipt(&mut shadow, &shadow_seed).unwrap();

        let session = CanarySession {
            schema: SESSION_SCHEMA.to_owned(),
            session_id: SESSION_ID,
            ticket: "CANARY-001".to_owned(),
            job_id: "job/effectful".to_owned(),
            action_id: ACTION_ID,
            implementation_head: hash40('1'),
            package_sha256: hash('2'),
            mig006_receipt_sha256: hash('3'),
            shadow_session_sha256: hash('4'),
            platform: Platform::LinuxX86_64,
            threat_model,
            inventory,
            freeze,
            quiescence,
            history,
            intent,
            grant,
            connector_outcome_public_key_base64: BASE64.encode(&outcome_public),
            connector_outcome: outcome,
            shadow_replay_public_key_base64: BASE64.encode(&shadow_public),
            shadow_replay: shadow,
            observer_receipt_public_key_base64: BASE64.encode(&observer_public),
            pre_action_observation,
            destination_observation: observation,
            windows_interruption: None,
            authority: AuthorityLedger {
                relinquishing_runner_effect_authority_before_grant: false,
                authoritative_runner_effect_authority_during_action: true,
                shadow_effect_authority: false,
                shadow_production_endpoint: false,
                grant_consumed_actions: 1,
                duplicate_effects: 0,
                ambiguous_effects: 0,
                new_effects_frozen_after_action: true,
            },
            completed_at_unix_ms: 500,
            downstream_released_at_unix_ms: 600,
        };
        let pins = IndependentPins {
            session_sha256: String::new(),
            threat_model_key_sha256: key_digest(1),
            inventory_key_sha256: key_digest(2),
            freeze_key_sha256: key_digest(3),
            quiescence_key_sha256: key_digest(4),
            history_key_sha256: key_digest(5),
            intent_key_sha256: key_digest(6),
            grant_key_sha256: key_digest(7),
            connector_outcome_key_sha256: content_sha256(&outcome_public),
            shadow_replay_key_sha256: content_sha256(&shadow_public),
            observer_receipt_key_sha256: content_sha256(&observer_public),
        };
        (session, pins)
    }

    fn context() -> ReceiptContext {
        ReceiptContext {
            schema: RECEIPT_SCHEMA.to_owned(),
            session_id: SESSION_ID,
            ticket: "CANARY-001".to_owned(),
            job_id: "job/effectful".to_owned(),
            action_id: ACTION_ID,
            implementation_head: hash40('1'),
            package_sha256: hash('2'),
            mig006_receipt_sha256: hash('3'),
            shadow_session_sha256: hash('4'),
            collected_at_unix_ms: 100,
            expires_at_unix_ms: 900,
            evidence_sha256: hash('5'),
        }
    }

    fn signed<T: Clone + Serialize>(body: T, key: u8) -> SignedReceipt<T> {
        let mut receipt = SignedReceipt {
            body,
            signing_key_id: format!("canary-role/{key}"),
            signing_public_key_base64: BASE64.encode(public_key(&seed(key))),
            signature_base64: String::new(),
        };
        resign(&mut receipt, seed(key));
        receipt
    }

    fn resign<T: Serialize>(receipt: &mut SignedReceipt<T>, seed: Vec<u8>) {
        let pair = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        receipt.signature_base64 = BASE64.encode(
            pair.sign(&signed_receipt_message(&receipt.body).unwrap())
                .as_ref(),
        );
    }

    fn outcome(public_key: &[u8], observation_digest: String) -> OutcomeReceipt {
        OutcomeReceipt {
            schema_version: OUTCOME_RECEIPT_SCHEMA_VERSION.to_owned(),
            protocol_version: CONNECTOR_PROTOCOL.to_owned(),
            evidence_sequence: 1,
            request_id: REQUEST_ID,
            request_sha256: hash('1'),
            tenant_id: TENANT_ID,
            project_id: PROJECT_ID,
            pipeline_id: PIPELINE_ID,
            build_id: BUILD_ID,
            attempt_id: ATTEMPT_ID,
            effect_fence: 17,
            effect_key: "deploy/service/one".to_owned(),
            connector_id: "connector/deploy".to_owned(),
            connector_implementation_sha256: hash('c'),
            connector_image_sha256: hash('d'),
            connector_config_sha256: hash('e'),
            deployment_identity: "deployment/connector".to_owned(),
            operator_trust_identity: "operator/connector".to_owned(),
            runtime_boundary_identity: "runtime/connector".to_owned(),
            service_identity: "service/connector".to_owned(),
            configuration_authority_identity: "config/connector".to_owned(),
            request_authority_identity: "request/canary".to_owned(),
            credential_issuance_path_identity: "issuer/connector".to_owned(),
            generation: 2,
            activation_mode: ActivationMode::Current,
            previous_generation: None,
            previous_config_sha256: None,
            rollback_from_generation: None,
            endpoint_identity: "endpoint/production".to_owned(),
            account_identity: "account/production".to_owned(),
            resource_identity: "resource/service/one".to_owned(),
            effect_class: "deployment".to_owned(),
            idempotency_class: mcloving_external_connector::IdempotencyClass::ExternallyIdempotent,
            action_name: "deploy".to_owned(),
            action_schema_version: "v1".to_owned(),
            credential_grant_id: "grant/one".to_owned(),
            credential_grant_version: "1".to_owned(),
            credential_grant_scope: "deploy:one".to_owned(),
            request_payload_sha256: hash('2'),
            status: OutcomeStatus::Succeeded,
            status_code: "deployed".to_owned(),
            public_values: BTreeMap::from([(
                "revision".to_owned(),
                serde_json::Value::String("one".to_owned()),
            )]),
            protected_secret_refs: Vec::new(),
            external_ids: BTreeMap::from([("deployment".to_owned(), "one".to_owned())]),
            downstream_control_digest: hash('3'),
            later_intents_digest: hash('4'),
            destination_response_sha256: Some(hash('5')),
            destination_signature_base64: Some("destination-signature".to_owned()),
            destination_attestation_key_id: Some("destination/key".to_owned()),
            attempt_count: 1,
            ambiguous_requires_observation: false,
            observation_receipt_sha256: Some(observation_digest),
            captured_at_unix_ms: 300,
            audit_provenance: "audit/canary".to_owned(),
            outcome_signing_key_id: "connector/outcome".to_owned(),
            outcome_signing_public_key_sha256: content_sha256(public_key),
            signature_base64: String::new(),
        }
    }

    fn shadow(
        public_key: &[u8],
        outcome_digest: String,
        outcome: &OutcomeReceipt,
    ) -> ShadowReplayReceipt {
        ShadowReplayReceipt {
            schema_version: SHADOW_RECEIPT_SCHEMA_VERSION.to_owned(),
            replay_id: Uuid::from_u128(9),
            outcome_receipt_sha256: outcome_digest,
            request_id: outcome.request_id,
            tenant_id: outcome.tenant_id,
            project_id: outcome.project_id,
            build_id: outcome.build_id,
            attempt_id: outcome.attempt_id,
            effect_fence: outcome.effect_fence,
            effect_key: outcome.effect_key.clone(),
            shadow_identity: "shadow/canary".to_owned(),
            replay_authority_identity: "authority/shadow-replay".to_owned(),
            status: outcome.status,
            status_code: outcome.status_code.clone(),
            public_values: outcome.public_values.clone(),
            protected_secret_refs: outcome.protected_secret_refs.clone(),
            external_ids: outcome.external_ids.clone(),
            downstream_control_digest: outcome.downstream_control_digest.clone(),
            later_intents_digest: outcome.later_intents_digest.clone(),
            replayed_at_unix_ms: 400,
            audit_provenance: "audit/shadow".to_owned(),
            replay_signing_key_id: "shadow/replay".to_owned(),
            replay_signing_public_key_sha256: content_sha256(public_key),
            signature_base64: String::new(),
        }
    }

    fn pre_action_observation(public_key: &[u8]) -> ObservationReceipt {
        let mut receipt = observation(public_key, String::new());
        receipt.observation_id = Uuid::from_u128(10);
        receipt.phase = ObservationPhase::PreAction;
        receipt.predecessor_receipt_sha256 = None;
        receipt.destination_cursor = 3;
        receipt.destination_observed_at_unix_ms = 150;
        receipt.captured_at_unix_ms = 160;
        receipt.publication_deadline_unix_ms = 250;
        receipt.state = serde_json::json!({"revision": "zero"});
        receipt.signature_base64.clear();
        receipt.receipt_signing_public_key_sha256 = content_sha256(public_key);
        receipt
    }

    fn observation(public_key: &[u8], predecessor_receipt_sha256: String) -> ObservationReceipt {
        ObservationReceipt {
            schema_version: RECEIPT_SCHEMA_VERSION.to_owned(),
            protocol_version: OBSERVER_PROTOCOL.to_owned(),
            evidence_sequence: 1,
            observation_id: Uuid::from_u128(11),
            request_sha256: hash('6'),
            tenant_id: TENANT_ID,
            project_id: PROJECT_ID,
            pipeline_id: PIPELINE_ID,
            build_id: BUILD_ID,
            attempt_id: ATTEMPT_ID,
            effect_fence: 17,
            phase: ObservationPhase::PostAction,
            predecessor_receipt_sha256: Some(predecessor_receipt_sha256),
            observer_id: "observer/production".to_owned(),
            observer_implementation_sha256: hash('8'),
            observer_image_sha256: hash('9'),
            observer_config_sha256: hash('a'),
            deployment_identity: "deployment/observer".to_owned(),
            operator_trust_identity: "operator/observer".to_owned(),
            runtime_boundary_identity: "runtime/observer".to_owned(),
            service_identity: "service/observer".to_owned(),
            credential_issuance_path_identity: "issuer/observer".to_owned(),
            configuration_authority_identity: "config/observer".to_owned(),
            request_authority_identity: "request/observer".to_owned(),
            generation: 3,
            activation_mode: ObserverActivationMode::Current,
            previous_generation: None,
            rollback_from_generation: None,
            endpoint_identity: "endpoint/production".to_owned(),
            account_identity: "account/production".to_owned(),
            resource_identity: "resource/service/one".to_owned(),
            effect_class: "deployment".to_owned(),
            read_grant_id: "grant/observer".to_owned(),
            read_grant_version: "1".to_owned(),
            read_grant_scope: "read:one".to_owned(),
            canonical_query: BTreeMap::from([("resource".to_owned(), "one".to_owned())]),
            destination_cursor: 4,
            destination_observed_at_unix_ms: 350,
            captured_at_unix_ms: 360,
            publication_deadline_unix_ms: 700,
            state_schema_version: "deployment-state/v1".to_owned(),
            confidentiality: Confidentiality::Internal,
            destination_response_sha256: hash('b'),
            destination_signature_base64: "destination-state-signature".to_owned(),
            destination_attestation_key_id: "destination/key".to_owned(),
            state: serde_json::json!({"revision": "one"}),
            retry_count: 0,
            audit_provenance: "audit/observer".to_owned(),
            receipt_signing_key_id: "observer/receipt".to_owned(),
            receipt_signing_public_key_sha256: content_sha256(public_key),
            signature_base64: String::new(),
        }
    }

    fn seed(value: u8) -> Vec<u8> {
        vec![value; 32]
    }

    fn public_key(seed: &[u8]) -> Vec<u8> {
        Ed25519KeyPair::from_seed_unchecked(seed)
            .unwrap()
            .public_key()
            .as_ref()
            .to_vec()
    }

    fn key_digest(value: u8) -> String {
        content_sha256(&public_key(&seed(value)))
    }

    fn hash(value: char) -> String {
        value.to_string().repeat(64)
    }

    fn hash40(value: char) -> String {
        value.to_string().repeat(40)
    }

    fn digest(value: &[u8]) -> String {
        content_sha256(value)
    }
}
