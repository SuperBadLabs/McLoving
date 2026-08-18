use mcloving_controller_store::{
    ClaimedAttempt, EffectClass, EffectEvidenceKind, EffectStatus, Store, StoreError,
    TerminalOutcome,
};
use mcloving_destination_observer::{
    ObservationPhase, ObservationReceipt, ObservationRequest,
    content_sha256 as observer_content_sha256, observation_receipt_digest,
    observation_request_message, verify_observation_receipt,
};
use mcloving_external_connector::{
    ActionRequest, IdempotencyClass, OutcomeReceipt, OutcomeStatus, ShadowReplayReceipt,
    action_request_digest, content_sha256, outcome_receipt_digest, verify_action_request,
    verify_outcome_receipt, verify_shadow_receipt,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{ConnectorEffectClass, ConnectorIntentSpec, JsonFieldType};

/// Fresh owner/deployment authority for exactly one fenced request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FreshOneActionGrant {
    pub grant_sha256: String,
    pub request_id: uuid::Uuid,
    pub attempt_id: uuid::Uuid,
    pub effect_fence: u64,
    pub issued_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub max_actions: u64,
    pub consumed_actions: u64,
}

/// Deployment-owned immutable bindings. None of these values originate in
/// pipeline source or agent output.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectRuntimeFreeze {
    pub mapping_id: String,
    pub mapping_digest: String,
    pub deployment_binding_sha256: String,
    pub runtime_attestation_sha256: String,
    pub credential_mapping_generation: u64,
    pub pre_action_observation_sha256: String,
    pub action_request: ActionRequest,
    pub grant: FreshOneActionGrant,
    pub request_authority_public_key: Vec<u8>,
    pub connector_outcome_public_key: Vec<u8>,
    pub observer_receipt_public_key: Vec<u8>,
    pub shadow_replay_public_key: Vec<u8>,
    pub expected_observer_id: String,
    pub expected_shadow_identity: String,
}

/// Immutable payload recorded before the connector can be called.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedEffect {
    pub effect_key: String,
    pub effect_class: EffectClass,
    pub payload: Value,
    pub request_sha256: String,
}

#[derive(Debug, thiserror::Error)]
pub enum EffectRuntimeError {
    #[error("controller store failed: {0}")]
    Store(#[from] StoreError),
    #[error("effect runtime binding is invalid: {0}")]
    InvalidBinding(&'static str),
    #[error("connector receipt is invalid")]
    InvalidOutcome,
    #[error("observer receipt is invalid")]
    InvalidObservation,
    #[error("shadow receipt is invalid")]
    InvalidShadow,
    #[error("controller rejected the current fenced effect authority")]
    StaleAuthority,
    #[error("effect receipt serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Persist the exact frozen request before any external dispatch is permitted.
pub async fn prepare_effect(
    store: &Store,
    claim: &ClaimedAttempt,
    agent_id: &str,
    intent: &ConnectorIntentSpec,
    freeze: &EffectRuntimeFreeze,
    now_unix_ms: i64,
) -> Result<PreparedEffect, EffectRuntimeError> {
    validate_freeze(claim, intent, freeze, now_unix_ms)?;
    let request_sha256 = action_request_digest(&freeze.action_request)
        .map_err(|_| EffectRuntimeError::InvalidBinding("action request digest"))?;
    let effect_class = store_effect_class(intent.effect_class);
    let payload = json!({
        "schema_version": "mcloving.controller-effect-prepared/v1",
        "mapping_id": freeze.mapping_id.clone(),
        "mapping_digest": freeze.mapping_digest.clone(),
        "deployment_binding_sha256": freeze.deployment_binding_sha256.clone(),
        "runtime_attestation_sha256": freeze.runtime_attestation_sha256.clone(),
        "credential_mapping_generation": freeze.credential_mapping_generation,
        "pre_action_observation_sha256": freeze.pre_action_observation_sha256.clone(),
        "grant_sha256": freeze.grant.grant_sha256.clone(),
        "request_sha256": request_sha256,
        "request": freeze.action_request.clone(),
        "connector_outcome_key_sha256": content_sha256(&freeze.connector_outcome_public_key),
        "observer_receipt_key_sha256": mcloving_destination_observer::content_sha256(&freeze.observer_receipt_public_key),
        "shadow_replay_key_sha256": content_sha256(&freeze.shadow_replay_public_key),
        "expected_observer_id": freeze.expected_observer_id.clone(),
        "expected_shadow_identity": freeze.expected_shadow_identity.clone(),
        "downstream_control_digest": intent.downstream_control_digest.clone(),
    });
    if !store
        .checkpoint_effect(
            claim.organization_id,
            claim.attempt_id,
            claim.fence,
            claim.restore_epoch,
            agent_id,
            &freeze.action_request.effect_key,
            effect_class,
            EffectStatus::Prepared,
            &payload,
        )
        .await?
    {
        return Err(EffectRuntimeError::StaleAuthority);
    }
    Ok(PreparedEffect {
        effect_key: freeze.action_request.effect_key.clone(),
        effect_class,
        payload,
        request_sha256,
    })
}

/// Close a prepared intent only when no dispatch or receipt was ever recorded.
/// This is the cancellation path before the connector call begins.
pub async fn abandon_prepared_effect(
    store: &Store,
    claim: &ClaimedAttempt,
    agent_id: &str,
    prepared: &PreparedEffect,
) -> Result<(), EffectRuntimeError> {
    if !store
        .checkpoint_effect(
            claim.organization_id,
            claim.attempt_id,
            claim.fence,
            claim.restore_epoch,
            agent_id,
            &prepared.effect_key,
            prepared.effect_class,
            EffectStatus::Abandoned,
            &prepared.payload,
        )
        .await?
    {
        return Err(EffectRuntimeError::StaleAuthority);
    }
    Ok(())
}

/// Freeze retry when dispatch or a post-dispatch join becomes ambiguous.
pub async fn mark_effect_uncertain(
    store: &Store,
    claim: &ClaimedAttempt,
    agent_id: &str,
    prepared: &PreparedEffect,
) -> Result<(), EffectRuntimeError> {
    if !store
        .checkpoint_effect(
            claim.organization_id,
            claim.attempt_id,
            claim.fence,
            claim.restore_epoch,
            agent_id,
            &prepared.effect_key,
            prepared.effect_class,
            EffectStatus::Uncertain,
            &prepared.payload,
        )
        .await?
    {
        return Err(EffectRuntimeError::StaleAuthority);
    }
    Ok(())
}

/// Verify and durably record the connector response before any retry decision.
pub async fn record_effect_outcome(
    store: &Store,
    claim: &ClaimedAttempt,
    agent_id: &str,
    intent: &ConnectorIntentSpec,
    freeze: &EffectRuntimeFreeze,
    prepared: &PreparedEffect,
    outcome: &OutcomeReceipt,
) -> Result<EffectStatus, EffectRuntimeError> {
    verify_outcome_receipt(outcome, &freeze.connector_outcome_public_key)
        .map_err(|_| EffectRuntimeError::InvalidOutcome)?;
    validate_outcome(claim, intent, freeze, prepared, outcome)?;
    let receipt = serde_json::to_value(outcome)?;
    if !store
        .append_effect_evidence(
            claim.organization_id,
            claim.attempt_id,
            claim.fence,
            claim.restore_epoch,
            agent_id,
            &prepared.effect_key,
            EffectEvidenceKind::Outcome,
            &receipt,
        )
        .await?
    {
        return Err(EffectRuntimeError::StaleAuthority);
    }
    let status =
        if outcome.status == OutcomeStatus::Ambiguous || outcome.ambiguous_requires_observation {
            EffectStatus::Uncertain
        } else {
            EffectStatus::Applied
        };
    if !store
        .checkpoint_effect(
            claim.organization_id,
            claim.attempt_id,
            claim.fence,
            claim.restore_epoch,
            agent_id,
            &prepared.effect_key,
            prepared.effect_class,
            status,
            &prepared.payload,
        )
        .await?
    {
        return Err(EffectRuntimeError::StaleAuthority);
    }
    Ok(status)
}

/// Join the independently signed destination state and move to confirmed.
#[allow(clippy::too_many_arguments)]
pub async fn confirm_effect_observation(
    store: &Store,
    claim: &ClaimedAttempt,
    agent_id: &str,
    freeze: &EffectRuntimeFreeze,
    prepared: &PreparedEffect,
    outcome: &OutcomeReceipt,
    observation_request: &ObservationRequest,
    observation: &ObservationReceipt,
) -> Result<(), EffectRuntimeError> {
    verify_observation_receipt(observation, &freeze.observer_receipt_public_key)
        .map_err(|_| EffectRuntimeError::InvalidObservation)?;
    validate_observation(claim, freeze, outcome, observation_request, observation)?;
    let receipt = serde_json::to_value(observation)?;
    if !store
        .append_effect_evidence(
            claim.organization_id,
            claim.attempt_id,
            claim.fence,
            claim.restore_epoch,
            agent_id,
            &prepared.effect_key,
            EffectEvidenceKind::Observation,
            &receipt,
        )
        .await?
    {
        return Err(EffectRuntimeError::StaleAuthority);
    }
    if outcome.status == OutcomeStatus::Ambiguous || outcome.ambiguous_requires_observation {
        return Ok(());
    }
    if !store
        .checkpoint_effect(
            claim.organization_id,
            claim.attempt_id,
            claim.fence,
            claim.restore_epoch,
            agent_id,
            &prepared.effect_key,
            prepared.effect_class,
            EffectStatus::Confirmed,
            &prepared.payload,
        )
        .await?
    {
        return Err(EffectRuntimeError::StaleAuthority);
    }
    Ok(())
}

/// Persist a reconciliation result without replacing the original ambiguous
/// receipt, then confirm the already joined independent observation.
#[allow(clippy::too_many_arguments)]
pub async fn record_reconciled_effect_outcome(
    store: &Store,
    claim: &ClaimedAttempt,
    agent_id: &str,
    intent: &ConnectorIntentSpec,
    freeze: &EffectRuntimeFreeze,
    prepared: &PreparedEffect,
    ambiguous: &OutcomeReceipt,
    observation: &ObservationReceipt,
    reconciled: &OutcomeReceipt,
) -> Result<(), EffectRuntimeError> {
    verify_outcome_receipt(reconciled, &freeze.connector_outcome_public_key)
        .map_err(|_| EffectRuntimeError::InvalidOutcome)?;
    validate_outcome(claim, intent, freeze, prepared, reconciled)?;
    if ambiguous.status != OutcomeStatus::Ambiguous
        || !ambiguous.ambiguous_requires_observation
        || reconciled.status == OutcomeStatus::Ambiguous
        || reconciled.ambiguous_requires_observation
        || reconciled.evidence_sequence <= ambiguous.evidence_sequence
        || reconciled.request_id != ambiguous.request_id
        || reconciled.request_sha256 != ambiguous.request_sha256
        || reconciled.observation_receipt_sha256.as_deref()
            != Some(
                observation_receipt_digest(observation)
                    .map_err(|_| EffectRuntimeError::InvalidObservation)?
                    .as_str(),
            )
    {
        return Err(EffectRuntimeError::InvalidOutcome);
    }
    let receipt = serde_json::to_value(reconciled)?;
    if !store
        .append_effect_evidence(
            claim.organization_id,
            claim.attempt_id,
            claim.fence,
            claim.restore_epoch,
            agent_id,
            &prepared.effect_key,
            EffectEvidenceKind::ReconciliationOutcome,
            &receipt,
        )
        .await?
        || !store
            .checkpoint_effect(
                claim.organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                agent_id,
                &prepared.effect_key,
                prepared.effect_class,
                EffectStatus::Confirmed,
                &prepared.payload,
            )
            .await?
    {
        return Err(EffectRuntimeError::StaleAuthority);
    }
    Ok(())
}

/// Persist the exact deny-authority shadow replay and only then publish the
/// terminal node outcome, which is what releases downstream DAG work.
pub async fn finalize_effect_shadow_join(
    store: &Store,
    claim: &ClaimedAttempt,
    agent_id: &str,
    freeze: &EffectRuntimeFreeze,
    prepared: &PreparedEffect,
    outcome: &OutcomeReceipt,
    shadow: &ShadowReplayReceipt,
) -> Result<TerminalOutcome, EffectRuntimeError> {
    finalize_effect_shadow_join_as(
        store, claim, agent_id, freeze, prepared, outcome, shadow, None,
    )
    .await
}

/// Variant used when a cancellation arrived after dispatch. Evidence still
/// completes before the attempt is published as aborted.
#[allow(clippy::too_many_arguments)]
pub async fn finalize_effect_shadow_join_as(
    store: &Store,
    claim: &ClaimedAttempt,
    agent_id: &str,
    freeze: &EffectRuntimeFreeze,
    prepared: &PreparedEffect,
    outcome: &OutcomeReceipt,
    shadow: &ShadowReplayReceipt,
    terminal_override: Option<TerminalOutcome>,
) -> Result<TerminalOutcome, EffectRuntimeError> {
    verify_shadow_receipt(shadow, &freeze.shadow_replay_public_key)
        .map_err(|_| EffectRuntimeError::InvalidShadow)?;
    validate_shadow(claim, freeze, outcome, shadow)?;
    let receipt = serde_json::to_value(shadow)?;
    if !store
        .append_effect_evidence(
            claim.organization_id,
            claim.attempt_id,
            claim.fence,
            claim.restore_epoch,
            agent_id,
            &prepared.effect_key,
            EffectEvidenceKind::ShadowReplay,
            &receipt,
        )
        .await?
    {
        return Err(EffectRuntimeError::StaleAuthority);
    }
    let evidence = store
        .effect_evidence(
            claim.organization_id,
            claim.attempt_id,
            claim.fence,
            &prepared.effect_key,
        )
        .await?;
    let has_reconciliation = evidence
        .iter()
        .any(|item| item.kind == EffectEvidenceKind::ReconciliationOutcome);
    let expected_evidence = if has_reconciliation { 4 } else { 3 };
    if evidence.len() != expected_evidence {
        return Err(EffectRuntimeError::InvalidBinding(
            "incomplete effect evidence join",
        ));
    }
    let outcome_terminal = match outcome.status {
        OutcomeStatus::Succeeded => TerminalOutcome::Succeeded,
        OutcomeStatus::Failed | OutcomeStatus::RetryableFailure => TerminalOutcome::Failed,
        OutcomeStatus::Ambiguous => {
            return Err(EffectRuntimeError::InvalidBinding(
                "ambiguous outcome requires reconciliation",
            ));
        }
    };
    let terminal = match terminal_override {
        None => outcome_terminal,
        Some(TerminalOutcome::Aborted) => TerminalOutcome::Aborted,
        Some(_) => {
            return Err(EffectRuntimeError::InvalidBinding(
                "only cancellation may override a joined effect outcome",
            ));
        }
    };
    if !store
        .finalize_attempt(
            claim.organization_id,
            claim.attempt_id,
            claim.fence,
            claim.restore_epoch,
            agent_id,
            terminal,
            json!({
                "effect_key": prepared.effect_key.clone(),
                "request_sha256": prepared.request_sha256.clone(),
                "outcome_receipt_sha256": outcome_receipt_digest(outcome).map_err(|_| EffectRuntimeError::InvalidOutcome)?,
                "observation_joined": true,
                "shadow_replay_joined": true,
            }),
        )
        .await?
    {
        return Err(EffectRuntimeError::StaleAuthority);
    }
    Ok(terminal)
}

fn validate_freeze(
    claim: &ClaimedAttempt,
    intent: &ConnectorIntentSpec,
    freeze: &EffectRuntimeFreeze,
    now_unix_ms: i64,
) -> Result<(), EffectRuntimeError> {
    let request = &freeze.action_request;
    let timeout_millis = intent
        .timeout_seconds
        .checked_mul(1_000)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or(EffectRuntimeError::InvalidBinding("intent timeout"))?;
    let request_window_millis = request
        .expires_at_unix_ms
        .checked_sub(request.requested_at_unix_ms)
        .ok_or(EffectRuntimeError::InvalidBinding(
            "request authority window",
        ))?;
    let fence = u64::try_from(claim.fence)
        .map_err(|_| EffectRuntimeError::InvalidBinding("negative effect fence"))?;
    verify_action_request(request, &freeze.request_authority_public_key)
        .map_err(|_| EffectRuntimeError::InvalidBinding("request signature"))?;
    if freeze.mapping_id != intent.mapping_id
        || freeze.mapping_digest != intent.mapping_digest
        || request.tenant_id != claim.organization_id
        || request.build_id != claim.build_id
        || request.attempt_id != claim.attempt_id
        || request.effect_fence != fence
        || request.effect_key != intent.effect_key_template
        || request.idempotency_class != connector_effect_class(intent.effect_class)
        || !public_payload_matches(&intent.public_input_schema, &request.request_payload)
        || request.requested_at_unix_ms > now_unix_ms
        || request.expires_at_unix_ms <= now_unix_ms
        || request_window_millis <= 0
        || request_window_millis > timeout_millis
        || request.expires_at_unix_ms > freeze.grant.expires_at_unix_ms
        || request.requested_at_unix_ms < freeze.grant.issued_at_unix_ms
        || freeze.grant.request_id != request.request_id
        || freeze.grant.attempt_id != claim.attempt_id
        || freeze.grant.effect_fence != fence
        || freeze.grant.max_actions != 1
        || freeze.grant.consumed_actions != 0
        || freeze.grant.issued_at_unix_ms > now_unix_ms
        || freeze.grant.expires_at_unix_ms <= now_unix_ms
        || freeze.credential_mapping_generation == 0
        || freeze.expected_observer_id.is_empty()
        || freeze.expected_shadow_identity.is_empty()
        || [
            &freeze.deployment_binding_sha256,
            &freeze.runtime_attestation_sha256,
            &freeze.pre_action_observation_sha256,
            &freeze.grant.grant_sha256,
        ]
        .iter()
        .any(|digest| !is_sha256(digest))
    {
        return Err(EffectRuntimeError::InvalidBinding(
            "frozen request or grant",
        ));
    }
    Ok(())
}

fn validate_outcome(
    claim: &ClaimedAttempt,
    intent: &ConnectorIntentSpec,
    freeze: &EffectRuntimeFreeze,
    prepared: &PreparedEffect,
    outcome: &OutcomeReceipt,
) -> Result<(), EffectRuntimeError> {
    let request = &freeze.action_request;
    let fence = u64::try_from(claim.fence).map_err(|_| EffectRuntimeError::InvalidOutcome)?;
    if outcome.request_id != request.request_id
        || outcome.request_sha256 != prepared.request_sha256
        || outcome.tenant_id != claim.organization_id
        || outcome.build_id != claim.build_id
        || outcome.attempt_id != claim.attempt_id
        || outcome.effect_fence != fence
        || outcome.effect_key != prepared.effect_key
        || outcome.connector_id != request.connector_id
        || outcome.connector_implementation_sha256 != request.expected_implementation_sha256
        || outcome.connector_image_sha256 != request.expected_image_sha256
        || outcome.connector_config_sha256 != request.expected_config_sha256
        || outcome.endpoint_identity != request.endpoint_identity
        || outcome.account_identity != request.account_identity
        || outcome.resource_identity != request.resource_identity
        || outcome.effect_class != request.effect_class
        || outcome.idempotency_class != request.idempotency_class
        || outcome.action_name != request.action_name
        || outcome.action_schema_version != request.action_schema_version
        || outcome.credential_grant_id != request.credential_grant_id
        || outcome.credential_grant_version != request.credential_grant_version
        || outcome.credential_grant_scope != request.credential_grant_scope
        || outcome.downstream_control_digest != intent.downstream_control_digest
        || outcome.attempt_count != 1
        || !public_values_match(
            &intent.expected_public_result_schema,
            &outcome.public_values,
        )
    {
        return Err(EffectRuntimeError::InvalidOutcome);
    }
    Ok(())
}

fn validate_observation(
    claim: &ClaimedAttempt,
    freeze: &EffectRuntimeFreeze,
    outcome: &OutcomeReceipt,
    request: &ObservationRequest,
    observation: &ObservationReceipt,
) -> Result<(), EffectRuntimeError> {
    let fence = u64::try_from(claim.fence).map_err(|_| EffectRuntimeError::InvalidObservation)?;
    let request_sha256 = observer_content_sha256(
        &observation_request_message(request)
            .map_err(|_| EffectRuntimeError::InvalidObservation)?,
    );
    if observation.observation_id != request.observation_id
        || observation.request_sha256 != request_sha256
        || observation.observer_id != freeze.expected_observer_id
        || observation.observer_id != request.observer_id
        || observation.tenant_id != claim.organization_id
        || observation.tenant_id != request.tenant_id
        || observation.project_id != outcome.project_id
        || observation.project_id != request.project_id
        || observation.pipeline_id != outcome.pipeline_id
        || observation.pipeline_id != request.pipeline_id
        || observation.build_id != claim.build_id
        || observation.build_id != request.build_id
        || observation.attempt_id != claim.attempt_id
        || observation.attempt_id != request.attempt_id
        || observation.effect_fence != fence
        || observation.effect_fence != request.effect_fence
        || observation.phase != request.phase
        || !matches!(
            observation.phase,
            ObservationPhase::PostAction | ObservationPhase::Reconciliation
        )
        || observation.predecessor_receipt_sha256 != request.predecessor_receipt_sha256
        || observation.observer_implementation_sha256 != request.expected_implementation_sha256
        || observation.observer_image_sha256 != request.expected_image_sha256
        || observation.observer_config_sha256 != request.expected_config_sha256
        || observation.request_authority_identity != request.request_authority_identity
        || observation.generation != request.expected_generation
        || observation.activation_mode != request.activation_mode
        || observation.previous_generation != request.previous_generation
        || observation.rollback_from_generation != request.rollback_from_generation
        || observation.endpoint_identity != outcome.endpoint_identity
        || observation.endpoint_identity != request.endpoint_identity
        || observation.account_identity != outcome.account_identity
        || observation.account_identity != request.account_identity
        || observation.resource_identity != outcome.resource_identity
        || observation.resource_identity != request.resource_identity
        || observation.effect_class != outcome.effect_class
        || observation.effect_class != request.effect_class
        || observation.read_grant_id != request.read_grant_id
        || observation.read_grant_version != request.read_grant_version
        || observation.read_grant_scope != request.read_grant_scope
        || observation.canonical_query != request.query
        || request
            .query
            .get("connector_request_sha256")
            .map(String::as_str)
            != Some(outcome.request_sha256.as_str())
        || observation
            .state
            .get("connector_request_sha256")
            .and_then(Value::as_str)
            != Some(outcome.request_sha256.as_str())
        || observation.destination_observed_at_unix_ms < request.requested_at_unix_ms
        || observation.destination_observed_at_unix_ms > observation.captured_at_unix_ms
        || observation.captured_at_unix_ms > request.expires_at_unix_ms
        || observation.publication_deadline_unix_ms != request.expires_at_unix_ms
    {
        return Err(EffectRuntimeError::InvalidObservation);
    }
    Ok(())
}

fn validate_shadow(
    claim: &ClaimedAttempt,
    freeze: &EffectRuntimeFreeze,
    outcome: &OutcomeReceipt,
    shadow: &ShadowReplayReceipt,
) -> Result<(), EffectRuntimeError> {
    let fence = u64::try_from(claim.fence).map_err(|_| EffectRuntimeError::InvalidShadow)?;
    let outcome_sha256 =
        outcome_receipt_digest(outcome).map_err(|_| EffectRuntimeError::InvalidOutcome)?;
    if shadow.shadow_identity != freeze.expected_shadow_identity
        || shadow.outcome_receipt_sha256 != outcome_sha256
        || shadow.request_id != outcome.request_id
        || shadow.tenant_id != claim.organization_id
        || shadow.project_id != outcome.project_id
        || shadow.build_id != claim.build_id
        || shadow.attempt_id != claim.attempt_id
        || shadow.effect_fence != fence
        || shadow.effect_key != outcome.effect_key
        || shadow.status != outcome.status
        || shadow.public_values != outcome.public_values
        || shadow.protected_secret_refs != outcome.protected_secret_refs
        || shadow.external_ids != outcome.external_ids
        || shadow.downstream_control_digest != outcome.downstream_control_digest
        || shadow.later_intents_digest != outcome.later_intents_digest
    {
        return Err(EffectRuntimeError::InvalidShadow);
    }
    Ok(())
}

fn store_effect_class(value: ConnectorEffectClass) -> EffectClass {
    match value {
        ConnectorEffectClass::Idempotent => EffectClass::Idempotent,
        ConnectorEffectClass::ExternallyIdempotent => EffectClass::ExternallyIdempotent,
        ConnectorEffectClass::NonIdempotent => EffectClass::NonIdempotent,
    }
}

fn connector_effect_class(value: ConnectorEffectClass) -> IdempotencyClass {
    match value {
        ConnectorEffectClass::Idempotent => IdempotencyClass::Idempotent,
        ConnectorEffectClass::ExternallyIdempotent => IdempotencyClass::ExternallyIdempotent,
        ConnectorEffectClass::NonIdempotent => IdempotencyClass::NonIdempotent,
    }
}

fn public_values_match(
    schema: &std::collections::BTreeMap<String, JsonFieldType>,
    values: &std::collections::BTreeMap<String, Value>,
) -> bool {
    schema.len() == values.len()
        && schema.iter().all(|(name, kind)| {
            values
                .get(name)
                .is_some_and(|value| json_kind_matches(*kind, value))
        })
}

fn public_payload_matches(
    schema: &std::collections::BTreeMap<String, JsonFieldType>,
    payload: &Value,
) -> bool {
    let Some(values) = payload.as_object() else {
        return false;
    };
    schema.len() == values.len()
        && schema.iter().all(|(name, kind)| {
            values
                .get(name)
                .is_some_and(|value| json_kind_matches(*kind, value))
        })
}

fn json_kind_matches(kind: JsonFieldType, value: &Value) -> bool {
    match kind {
        JsonFieldType::Array => value.is_array(),
        JsonFieldType::Boolean => value.is_boolean(),
        JsonFieldType::Null => value.is_null(),
        JsonFieldType::Number => value.is_number(),
        JsonFieldType::Object => value.is_object(),
        JsonFieldType::String => value.is_string(),
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
