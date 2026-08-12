use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Acquire, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::{DagAdmission, NewDagBuild, Store, StoreError};

const MAX_TEXT_BYTES: usize = 512;
const MAX_REASON_BYTES: usize = 2048;
const MAX_CONFIGURATION_BYTES: usize = 64 * 1024;
const MAX_PAYLOAD_BYTES: usize = 256 * 1024;
const MAX_CLOCK_SKEW_MS: i64 = 5 * 60 * 1000;
const MAX_WINDOW_SECONDS: i64 = 30 * 24 * 60 * 60;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerKind {
    ScmWebhook,
    Schedule,
    Upstream,
    RemoteApi,
    Plugin,
}

impl TriggerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ScmWebhook => "scm_webhook",
            Self::Schedule => "schedule",
            Self::Upstream => "upstream",
            Self::RemoteApi => "remote_api",
            Self::Plugin => "plugin",
        }
    }

    fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "scm_webhook" => Ok(Self::ScmWebhook),
            "schedule" => Ok(Self::Schedule),
            "upstream" => Ok(Self::Upstream),
            "remote_api" => Ok(Self::RemoteApi),
            "plugin" => Ok(Self::Plugin),
            _ => Err(StoreError::InvalidTriggerIngress(format!(
                "stored trigger kind '{value}' is invalid"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineTriggerState {
    Enabled,
    Paused,
}

impl PipelineTriggerState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Paused => "paused",
        }
    }

    fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "enabled" => Ok(Self::Enabled),
            "paused" => Ok(Self::Paused),
            _ => Err(StoreError::InvalidTriggerIngress(format!(
                "stored trigger state '{value}' is invalid"
            ))),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PipelineTriggerWrite {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub pipeline_id: Uuid,
    pub trigger_id: Uuid,
    pub expected_generation: i64,
    pub kind: TriggerKind,
    pub state: PipelineTriggerState,
    pub implementation_sha256: [u8; 32],
    pub configuration_sha256: [u8; 32],
    pub filter_sha256: [u8; 32],
    pub event_source_identity: String,
    pub source_generation: String,
    pub configuration: Value,
    pub deduplication_window_seconds: i64,
    pub max_delivery_attempts: i32,
    pub delivery_ttl_seconds: i64,
    pub actor_subject: String,
    pub reason: String,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PipelineTrigger {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub pipeline_id: Uuid,
    pub trigger_id: Uuid,
    pub generation: i64,
    pub kind: TriggerKind,
    pub state: PipelineTriggerState,
    pub implementation_sha256: [u8; 32],
    pub configuration_sha256: [u8; 32],
    pub filter_sha256: [u8; 32],
    pub event_source_identity: String,
    pub source_generation: String,
    pub configuration: Value,
    pub deduplication_window_seconds: i64,
    pub max_delivery_attempts: i32,
    pub delivery_ttl_seconds: i64,
    pub actor_subject: String,
    pub reason: String,
    pub idempotency_key: String,
    pub audit_sequence: i64,
    pub audit_event_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TriggerPutOutcome {
    Created(PipelineTrigger),
    Revised(PipelineTrigger),
    Replayed(PipelineTrigger),
    PreconditionFailed { current_generation: i64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewTriggerDelivery {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub pipeline_id: Uuid,
    pub trigger_id: Uuid,
    pub expected_trigger_generation: i64,
    pub delivery_id: String,
    pub event_id: String,
    pub event_kind: String,
    pub caller_identity: String,
    pub payload_sha256: [u8; 32],
    pub canonical_payload: Value,
    pub parameters: Value,
    pub requested_platform: String,
    pub requested_trust_pool: String,
    pub event_time_unix_ms: i64,
    pub accepted_at_unix_ms: i64,
    pub schedule_slot: Option<TriggerScheduleSlot>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TriggerScheduleSlot {
    pub timezone: String,
    pub calendar: String,
    pub expression: String,
    pub schedule_identity_sha256: [u8; 32],
    pub expected_last_resolved_slot_unix_ms: Option<i64>,
    pub resolved_slot_unix_ms: i64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerDeliveryStatus {
    Pending,
    RetryWait,
    Admitted,
    DeadLettered,
}

impl TriggerDeliveryStatus {
    fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "pending" => Ok(Self::Pending),
            "retry_wait" => Ok(Self::RetryWait),
            "admitted" => Ok(Self::Admitted),
            "dead_lettered" => Ok(Self::DeadLettered),
            _ => Err(StoreError::InvalidTriggerIngress(format!(
                "stored trigger delivery status '{value}' is invalid"
            ))),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TriggerDelivery {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub pipeline_id: Uuid,
    pub trigger_id: Uuid,
    pub trigger_generation: i64,
    pub delivery_id: String,
    pub event_id: String,
    pub event_kind: String,
    pub caller_identity: String,
    pub payload_sha256: [u8; 32],
    pub canonical_payload: Value,
    pub parameters: Value,
    pub requested_platform: String,
    pub requested_trust_pool: String,
    pub event_time_unix_ms: i64,
    pub accepted_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub status: TriggerDeliveryStatus,
    pub attempt_count: i32,
    pub next_attempt_at_unix_ms: i64,
    pub claim_owner: Option<String>,
    pub claim_fence: i64,
    pub claim_expires_at_unix_ms: Option<i64>,
    pub redrive_of_delivery_id: Option<String>,
    pub redrive_ordinal: Option<i32>,
    pub build_id: Option<Uuid>,
    pub terminal_reason: Option<String>,
    pub audit_sequence: i64,
    pub audit_event_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TriggerDeliveryAdmission {
    Created(TriggerDelivery),
    Replayed(TriggerDelivery),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TriggerDeliveryFailure {
    RetryScheduled(TriggerDelivery),
    DeadLettered(TriggerDelivery),
    LeaseLost(TriggerDelivery),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TriggerDeliveryDagAdmissionRequest {
    pub organization_id: Uuid,
    pub trigger_id: Uuid,
    pub delivery_id: String,
    pub worker_identity: String,
    pub claim_fence: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TriggerDeliveryDagAdmission {
    Admitted {
        delivery: TriggerDelivery,
        admission: DagAdmission,
    },
    DeadLettered(TriggerDelivery),
    LeaseLost(TriggerDelivery),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TriggerDeliveryFailureRequest {
    pub organization_id: Uuid,
    pub trigger_id: Uuid,
    pub delivery_id: String,
    pub worker_identity: String,
    pub claim_fence: i64,
    pub now_unix_ms: i64,
    pub retry_at_unix_ms: i64,
    pub retryable: bool,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TriggerDeliveryClaimRequest {
    pub organization_id: Uuid,
    pub trigger_id: Uuid,
    pub delivery_id: String,
    pub worker_identity: String,
    pub now_unix_ms: i64,
    pub lease_expires_at_unix_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TriggerDeliveryClaimOutcome {
    Claimed(TriggerDelivery),
    NotDue(TriggerDelivery),
    Leased(TriggerDelivery),
    Terminal(TriggerDelivery),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TriggerDeliveryRedrive {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub pipeline_id: Uuid,
    pub trigger_id: Uuid,
    pub dead_letter_delivery_id: String,
    pub new_delivery_id: String,
    pub new_event_id: String,
    pub actor_subject: String,
    pub accepted_at_unix_ms: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TriggerScheduleWatermark {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub pipeline_id: Uuid,
    pub trigger_id: Uuid,
    pub trigger_generation: i64,
    pub timezone: String,
    pub calendar: String,
    pub expression: String,
    pub schedule_identity_sha256: [u8; 32],
    pub last_resolved_slot_unix_ms: Option<i64>,
    pub last_delivery_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TriggerTransferSnapshot {
    pub schema_version: u16,
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub pipeline_id: Uuid,
    pub trigger_id: Uuid,
    pub current_generation: i64,
    pub versions: Vec<PipelineTrigger>,
    pub deliveries: Vec<TriggerDelivery>,
    pub schedule_watermarks: Vec<TriggerScheduleWatermark>,
    pub handoff_audit_event: crate::AuditEvent,
    pub audit_sequence: i64,
    pub audit_event_hash: [u8; 32],
    pub state_sha256: [u8; 32],
}

pub fn verify_trigger_transfer_snapshot(
    snapshot: &TriggerTransferSnapshot,
    trusted_handoff_audit_event_hash: [u8; 32],
) -> Result<(), StoreError> {
    if snapshot.schema_version != 1
        || snapshot.current_generation <= 0
        || snapshot.audit_sequence <= 0
        || snapshot.audit_event_hash == [0; 32]
        || trusted_handoff_audit_event_hash == [0; 32]
    {
        return Err(StoreError::InvalidTriggerIngress(
            "trigger transfer snapshot schema or generation is invalid".to_owned(),
        ));
    }
    if snapshot.audit_event_hash != trusted_handoff_audit_event_hash
        || snapshot.handoff_audit_event.sequence != snapshot.audit_sequence
        || snapshot.handoff_audit_event.event_hash != trusted_handoff_audit_event_hash
    {
        return Err(StoreError::TriggerIngressConflict(
            "trigger transfer does not match the independently retained audit anchor".to_owned(),
        ));
    }
    crate::audit::verify_audit_event_hash(snapshot.organization_id, &snapshot.handoff_audit_event)
        .map_err(|_| {
            StoreError::TriggerIngressConflict(
                "trigger transfer handoff audit event hash is invalid".to_owned(),
            )
        })?;
    for (expected_generation, version) in (1_i64..).zip(snapshot.versions.iter()) {
        if version.organization_id != snapshot.organization_id
            || version.project_id != snapshot.project_id
            || version.pipeline_id != snapshot.pipeline_id
            || version.trigger_id != snapshot.trigger_id
            || version.generation != expected_generation
            || version.actor_subject.is_empty()
            || version.reason.is_empty()
            || version.idempotency_key.is_empty()
            || version.audit_sequence <= 0
            || version.audit_event_hash == [0; 32]
        {
            return Err(StoreError::TriggerIngressConflict(
                "trigger transfer version lineage is incomplete or substituted".to_owned(),
            ));
        }
    }
    if snapshot.versions.last().map(|version| version.generation)
        != Some(snapshot.current_generation)
        || snapshot
            .versions
            .last()
            .is_none_or(|version| version.state != PipelineTriggerState::Paused)
    {
        return Err(StoreError::TriggerIngressConflict(
            "trigger transfer requires a complete lineage ending in a paused generation".to_owned(),
        ));
    }
    let mut deliveries_by_id = std::collections::BTreeMap::new();
    let mut event_ids = std::collections::BTreeSet::new();
    for delivery in &snapshot.deliveries {
        if delivery.organization_id != snapshot.organization_id
            || delivery.project_id != snapshot.project_id
            || delivery.pipeline_id != snapshot.pipeline_id
            || delivery.trigger_id != snapshot.trigger_id
            || !snapshot
                .versions
                .iter()
                .any(|version| version.generation == delivery.trigger_generation)
            || deliveries_by_id
                .insert(delivery.delivery_id.as_str(), delivery)
                .is_some()
            || !event_ids.insert(delivery.event_id.as_str())
            || delivery.claim_owner.is_some()
            || delivery.claim_expires_at_unix_ms.is_some()
            || delivery.audit_sequence <= 0
            || delivery.audit_event_hash == [0; 32]
        {
            return Err(StoreError::TriggerIngressConflict(
                "trigger transfer delivery ledger is incomplete, duplicated, claimed, or substituted"
                    .to_owned(),
            ));
        }
    }
    let mut watermark_generations = std::collections::BTreeSet::new();
    for watermark in &snapshot.schedule_watermarks {
        if watermark.organization_id != snapshot.organization_id
            || watermark.project_id != snapshot.project_id
            || watermark.pipeline_id != snapshot.pipeline_id
            || watermark.trigger_id != snapshot.trigger_id
            || !snapshot
                .versions
                .iter()
                .any(|version| version.generation == watermark.trigger_generation)
            || !watermark_generations.insert(watermark.trigger_generation)
        {
            return Err(StoreError::TriggerIngressConflict(
                "trigger transfer schedule watermark is incomplete or substituted".to_owned(),
            ));
        }
        let Some(last_delivery_id) = watermark.last_delivery_id.as_deref() else {
            return Err(StoreError::TriggerIngressConflict(
                "trigger transfer schedule watermark omits its delivery lineage".to_owned(),
            ));
        };
        let Some(last_resolved_slot_unix_ms) = watermark.last_resolved_slot_unix_ms else {
            return Err(StoreError::TriggerIngressConflict(
                "trigger transfer schedule watermark omits its resolved slot".to_owned(),
            ));
        };
        let Some(delivery) = deliveries_by_id.get(last_delivery_id) else {
            return Err(StoreError::TriggerIngressConflict(
                "trigger transfer schedule watermark references an unknown delivery".to_owned(),
            ));
        };
        let payload = delivery
            .canonical_payload
            .get("payload")
            .and_then(Value::as_object);
        if delivery.trigger_generation != watermark.trigger_generation
            || delivery.event_kind != "schedule"
            || delivery.event_time_unix_ms != last_resolved_slot_unix_ms
            || payload.and_then(|value| value.get("resolved_slot_unix_ms"))
                != Some(&Value::from(last_resolved_slot_unix_ms))
            || payload
                .and_then(|value| value.get("schedule_identity_sha256"))
                .and_then(Value::as_str)
                != Some(hex::encode(watermark.schedule_identity_sha256).as_str())
            || payload
                .and_then(|value| value.get("timezone"))
                .and_then(Value::as_str)
                != Some(watermark.timezone.as_str())
            || payload
                .and_then(|value| value.get("calendar"))
                .and_then(Value::as_str)
                != Some(watermark.calendar.as_str())
            || payload
                .and_then(|value| value.get("expression"))
                .and_then(Value::as_str)
                != Some(watermark.expression.as_str())
        {
            return Err(StoreError::TriggerIngressConflict(
                "trigger transfer schedule watermark does not match its exact delivery".to_owned(),
            ));
        }
    }
    let ledger_sha256 = compute_trigger_transfer_snapshot_ledger_digest(snapshot)?;
    let expected_audit_payload = json!({
        "project_id": snapshot.project_id,
        "pipeline_id": snapshot.pipeline_id,
        "trigger_id": snapshot.trigger_id,
        "current_generation": snapshot.current_generation,
        "version_count": snapshot.versions.len(),
        "delivery_count": snapshot.deliveries.len(),
        "schedule_watermark_count": snapshot.schedule_watermarks.len(),
        "ledger_sha256": hex::encode(ledger_sha256),
    });
    if snapshot.handoff_audit_event.category != "trigger"
        || snapshot.handoff_audit_event.action != "trigger.handoff_exported"
        || snapshot.handoff_audit_event.subject
            != format!(
                "pipeline:{}:trigger:{}",
                snapshot.pipeline_id, snapshot.trigger_id
            )
        || snapshot.handoff_audit_event.actor_subject.is_empty()
        || snapshot.handoff_audit_event.payload != expected_audit_payload
    {
        return Err(StoreError::TriggerIngressConflict(
            "trigger transfer handoff audit commitment does not match its ledger".to_owned(),
        ));
    }
    let actual = compute_trigger_transfer_snapshot_digest(snapshot)?;
    if actual != snapshot.state_sha256 {
        return Err(StoreError::TriggerIngressConflict(
            "trigger transfer snapshot digest does not match its state".to_owned(),
        ));
    }
    Ok(())
}

pub fn compute_trigger_transfer_snapshot_digest(
    snapshot: &TriggerTransferSnapshot,
) -> Result<[u8; 32], StoreError> {
    #[derive(Serialize)]
    struct DigestInput<'a> {
        schema_version: u16,
        organization_id: Uuid,
        project_id: Uuid,
        pipeline_id: Uuid,
        trigger_id: Uuid,
        current_generation: i64,
        versions: &'a [PipelineTrigger],
        deliveries: &'a [TriggerDelivery],
        schedule_watermarks: &'a [TriggerScheduleWatermark],
        handoff_audit_event: &'a crate::AuditEvent,
        audit_sequence: i64,
        audit_event_hash: [u8; 32],
    }
    let canonical = serde_json::to_vec(&DigestInput {
        schema_version: snapshot.schema_version,
        organization_id: snapshot.organization_id,
        project_id: snapshot.project_id,
        pipeline_id: snapshot.pipeline_id,
        trigger_id: snapshot.trigger_id,
        current_generation: snapshot.current_generation,
        versions: &snapshot.versions,
        deliveries: &snapshot.deliveries,
        schedule_watermarks: &snapshot.schedule_watermarks,
        handoff_audit_event: &snapshot.handoff_audit_event,
        audit_sequence: snapshot.audit_sequence,
        audit_event_hash: snapshot.audit_event_hash,
    })
    .map_err(|error| StoreError::InvalidTriggerIngress(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(b"mcloving-trigger-transfer-v1\0");
    hasher.update(canonical);
    Ok(hasher.finalize().into())
}

#[allow(clippy::too_many_arguments)]
fn trigger_transfer_ledger_digest(
    schema_version: u16,
    organization_id: Uuid,
    project_id: Uuid,
    pipeline_id: Uuid,
    trigger_id: Uuid,
    current_generation: i64,
    versions: &[PipelineTrigger],
    deliveries: &[TriggerDelivery],
    schedule_watermarks: &[TriggerScheduleWatermark],
) -> Result<[u8; 32], StoreError> {
    #[derive(Serialize)]
    struct LedgerDigestInput<'a> {
        schema_version: u16,
        organization_id: Uuid,
        project_id: Uuid,
        pipeline_id: Uuid,
        trigger_id: Uuid,
        current_generation: i64,
        versions: &'a [PipelineTrigger],
        deliveries: &'a [TriggerDelivery],
        schedule_watermarks: &'a [TriggerScheduleWatermark],
    }
    let canonical = serde_json::to_vec(&LedgerDigestInput {
        schema_version,
        organization_id,
        project_id,
        pipeline_id,
        trigger_id,
        current_generation,
        versions,
        deliveries,
        schedule_watermarks,
    })
    .map_err(|error| StoreError::InvalidTriggerIngress(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(b"mcloving-trigger-transfer-ledger-v1\0");
    hasher.update(canonical);
    Ok(hasher.finalize().into())
}

pub fn compute_trigger_transfer_snapshot_ledger_digest(
    snapshot: &TriggerTransferSnapshot,
) -> Result<[u8; 32], StoreError> {
    trigger_transfer_ledger_digest(
        snapshot.schema_version,
        snapshot.organization_id,
        snapshot.project_id,
        snapshot.pipeline_id,
        snapshot.trigger_id,
        snapshot.current_generation,
        &snapshot.versions,
        &snapshot.deliveries,
        &snapshot.schedule_watermarks,
    )
}

impl Store {
    pub async fn pipeline_trigger(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        pipeline_id: Uuid,
        trigger_id: Uuid,
    ) -> Result<Option<PipelineTrigger>, StoreError> {
        let mut tx = self.tenant_transaction(organization_id).await?;
        let row = sqlx::query(
            "SELECT d.organization_id, d.project_id, d.pipeline_id, d.trigger_id,
                    d.current_generation, v.trigger_kind, v.state,
                    v.implementation_sha256, v.configuration_sha256,
                    v.filter_sha256, v.event_source_identity,
                    v.source_generation, v.configuration,
                    v.deduplication_window_seconds, v.max_delivery_attempts,
                    v.delivery_ttl_seconds, v.actor_subject, v.reason,
                    v.idempotency_key, v.audit_sequence, v.audit_event_hash
             FROM pipeline_trigger_definitions AS d
             JOIN pipeline_trigger_versions AS v
               ON v.organization_id = d.organization_id
              AND v.trigger_id = d.trigger_id
              AND v.generation = d.current_generation
             WHERE d.organization_id = $1 AND d.project_id = $2
               AND d.pipeline_id = $3 AND d.trigger_id = $4",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(pipeline_id)
        .bind(trigger_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        row.map(trigger_from_row).transpose()
    }

    pub async fn pipeline_trigger_generation(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        pipeline_id: Uuid,
        trigger_id: Uuid,
        generation: i64,
    ) -> Result<Option<PipelineTrigger>, StoreError> {
        if generation <= 0 {
            return Err(StoreError::InvalidTriggerIngress(
                "trigger generation must be positive".to_owned(),
            ));
        }
        let mut tx = self.tenant_transaction(organization_id).await?;
        let row = sqlx::query(
            "SELECT definition.organization_id, definition.project_id,
                    definition.pipeline_id, definition.trigger_id,
                    version.generation AS current_generation,
                    version.trigger_kind, version.state,
                    version.implementation_sha256, version.configuration_sha256,
                    version.filter_sha256, version.event_source_identity,
                    version.source_generation, version.configuration,
                    version.deduplication_window_seconds,
                    version.max_delivery_attempts, version.delivery_ttl_seconds,
                    version.actor_subject, version.reason, version.idempotency_key,
                    version.audit_sequence, version.audit_event_hash
             FROM pipeline_trigger_definitions AS definition
             JOIN pipeline_trigger_versions AS version
               ON version.organization_id = definition.organization_id
              AND version.trigger_id = definition.trigger_id
             WHERE definition.organization_id = $1
               AND definition.project_id = $2 AND definition.pipeline_id = $3
               AND definition.trigger_id = $4 AND version.generation = $5",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(pipeline_id)
        .bind(trigger_id)
        .bind(generation)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        row.map(trigger_from_row).transpose()
    }

    pub async fn put_pipeline_trigger(
        &self,
        input: &PipelineTriggerWrite,
    ) -> Result<TriggerPutOutcome, StoreError> {
        validate_trigger_write(input)?;
        let mut tx = self.tenant_transaction(input.organization_id).await?;
        lock_trigger_transaction(&mut tx, input.organization_id, input.trigger_id).await?;
        let pipeline_exists = sqlx::query_scalar::<_, Uuid>(
            "SELECT pipeline_id FROM pipeline_definitions
             WHERE organization_id = $1 AND project_id = $2 AND pipeline_id = $3
             FOR UPDATE",
        )
        .bind(input.organization_id)
        .bind(input.project_id)
        .bind(input.pipeline_id)
        .fetch_optional(&mut *tx)
        .await?;
        if pipeline_exists.is_none() {
            tx.rollback().await?;
            return Err(StoreError::TriggerIngressConflict(
                "trigger does not identify a saved pipeline".to_owned(),
            ));
        }
        if let Some(replay) = sqlx::query(
            "SELECT d.organization_id, d.project_id, d.pipeline_id, d.trigger_id,
                    v.generation AS current_generation, v.trigger_kind, v.state,
                    v.implementation_sha256, v.configuration_sha256,
                    v.filter_sha256, v.event_source_identity,
                    v.source_generation, v.configuration,
                    v.deduplication_window_seconds, v.max_delivery_attempts,
                    v.delivery_ttl_seconds, v.actor_subject, v.reason,
                    v.idempotency_key, v.audit_sequence, v.audit_event_hash
             FROM pipeline_trigger_versions AS v
             JOIN pipeline_trigger_definitions AS d
               ON d.organization_id = v.organization_id
              AND d.trigger_id = v.trigger_id
             WHERE v.organization_id = $1 AND v.trigger_id = $2
               AND v.idempotency_key = $3",
        )
        .bind(input.organization_id)
        .bind(input.trigger_id)
        .bind(&input.idempotency_key)
        .fetch_optional(&mut *tx)
        .await?
        {
            let trigger = trigger_from_row(replay)?;
            if !trigger_matches_write(&trigger, input) {
                tx.rollback().await?;
                return Err(StoreError::TriggerIngressConflict(
                    "trigger idempotency key was reused for a different configuration".to_owned(),
                ));
            }
            tx.commit().await?;
            return Ok(TriggerPutOutcome::Replayed(trigger));
        }

        let current = sqlx::query_scalar::<_, i64>(
            "SELECT current_generation
             FROM pipeline_trigger_definitions
             WHERE organization_id = $1 AND project_id = $2
               AND pipeline_id = $3 AND trigger_id = $4
             FOR UPDATE",
        )
        .bind(input.organization_id)
        .bind(input.project_id)
        .bind(input.pipeline_id)
        .bind(input.trigger_id)
        .fetch_optional(&mut *tx)
        .await?;
        let (generation, created) = match current {
            None if input.expected_generation == 0 => {
                sqlx::query(
                    "INSERT INTO pipeline_trigger_definitions (
                         organization_id, project_id, pipeline_id, trigger_id,
                         current_generation
                     ) VALUES ($1, $2, $3, $4, 1)",
                )
                .bind(input.organization_id)
                .bind(input.project_id)
                .bind(input.pipeline_id)
                .bind(input.trigger_id)
                .execute(&mut *tx)
                .await?;
                (1, true)
            }
            None => {
                tx.rollback().await?;
                return Ok(TriggerPutOutcome::PreconditionFailed {
                    current_generation: 0,
                });
            }
            Some(current) if current != input.expected_generation => {
                tx.rollback().await?;
                return Ok(TriggerPutOutcome::PreconditionFailed {
                    current_generation: current,
                });
            }
            Some(current) => (current + 1, false),
        };

        let audit = crate::audit::append_audit_record(
            &mut tx,
            input.organization_id,
            "trigger",
            &input.actor_subject,
            if created {
                "trigger.created"
            } else {
                "trigger.revised"
            },
            &format!(
                "pipeline:{}:trigger:{}",
                input.pipeline_id, input.trigger_id
            ),
            json!({
                "project_id": input.project_id,
                "pipeline_id": input.pipeline_id,
                "trigger_id": input.trigger_id,
                "generation": generation,
                "kind": input.kind.as_str(),
                "state": input.state.as_str(),
                "implementation_sha256": hex::encode(input.implementation_sha256),
                "configuration_sha256": hex::encode(input.configuration_sha256),
                "filter_sha256": hex::encode(input.filter_sha256),
                "event_source_identity": input.event_source_identity,
                "source_generation": input.source_generation,
                "reason": input.reason,
            }),
        )
        .await?;
        sqlx::query(
            "INSERT INTO pipeline_trigger_versions (
                 organization_id, project_id, pipeline_id, trigger_id,
                 generation, trigger_kind, state, implementation_sha256,
                 configuration_sha256, filter_sha256, event_source_identity,
                 source_generation, configuration, deduplication_window_seconds,
                 max_delivery_attempts, delivery_ttl_seconds, actor_subject,
                 reason, idempotency_key, audit_sequence, audit_event_hash
             ) VALUES (
                 $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                 $13, $14, $15, $16, $17, $18, $19, $20, $21
             )",
        )
        .bind(input.organization_id)
        .bind(input.project_id)
        .bind(input.pipeline_id)
        .bind(input.trigger_id)
        .bind(generation)
        .bind(input.kind.as_str())
        .bind(input.state.as_str())
        .bind(input.implementation_sha256.as_slice())
        .bind(input.configuration_sha256.as_slice())
        .bind(input.filter_sha256.as_slice())
        .bind(&input.event_source_identity)
        .bind(&input.source_generation)
        .bind(&input.configuration)
        .bind(input.deduplication_window_seconds)
        .bind(input.max_delivery_attempts)
        .bind(input.delivery_ttl_seconds)
        .bind(&input.actor_subject)
        .bind(&input.reason)
        .bind(&input.idempotency_key)
        .bind(audit.sequence)
        .bind(audit.event_hash.as_slice())
        .execute(&mut *tx)
        .await?;
        if !created {
            sqlx::query(
                "UPDATE pipeline_trigger_definitions
                 SET current_generation = $5, updated_at = clock_timestamp()
                 WHERE organization_id = $1 AND project_id = $2
                   AND pipeline_id = $3 AND trigger_id = $4",
            )
            .bind(input.organization_id)
            .bind(input.project_id)
            .bind(input.pipeline_id)
            .bind(input.trigger_id)
            .bind(generation)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        let trigger = self
            .pipeline_trigger(
                input.organization_id,
                input.project_id,
                input.pipeline_id,
                input.trigger_id,
            )
            .await?
            .ok_or_else(|| {
                StoreError::TriggerIngressConflict(
                    "committed trigger configuration is missing".to_owned(),
                )
            })?;
        Ok(if created {
            TriggerPutOutcome::Created(trigger)
        } else {
            TriggerPutOutcome::Revised(trigger)
        })
    }

    pub async fn accept_trigger_delivery(
        &self,
        input: &NewTriggerDelivery,
    ) -> Result<TriggerDeliveryAdmission, StoreError> {
        validate_delivery(input)?;
        let mut tx = self.tenant_transaction(input.organization_id).await?;
        lock_trigger_transaction(&mut tx, input.organization_id, input.trigger_id).await?;
        let existing = sqlx::query(
            "SELECT * FROM trigger_deliveries
             WHERE organization_id = $1 AND trigger_id = $2
               AND (delivery_id = $3 OR event_id = $4)
             FOR UPDATE",
        )
        .bind(input.organization_id)
        .bind(input.trigger_id)
        .bind(&input.delivery_id)
        .bind(&input.event_id)
        .fetch_all(&mut *tx)
        .await?;
        if existing.len() > 1 {
            tx.rollback().await?;
            return Err(StoreError::TriggerIngressConflict(
                "delivery and event IDs identify different accepted deliveries".to_owned(),
            ));
        }
        if let Some(existing) = existing.into_iter().next() {
            let delivery = delivery_from_row(existing)?;
            if !delivery_matches(&delivery, input) {
                tx.rollback().await?;
                return Err(StoreError::TriggerIngressConflict(
                    "delivery or event ID was reused for different trigger input".to_owned(),
                ));
            }
            tx.commit().await?;
            return Ok(TriggerDeliveryAdmission::Replayed(delivery));
        }
        let trigger_row = sqlx::query(
            "SELECT d.current_generation, v.trigger_kind, v.state,
                    v.event_source_identity, v.configuration,
                    v.deduplication_window_seconds, v.delivery_ttl_seconds
             FROM pipeline_trigger_definitions AS d
             JOIN pipeline_trigger_versions AS v
               ON v.organization_id = d.organization_id
              AND v.trigger_id = d.trigger_id
              AND v.generation = d.current_generation
             WHERE d.organization_id = $1 AND d.project_id = $2
               AND d.pipeline_id = $3 AND d.trigger_id = $4
             FOR UPDATE OF d",
        )
        .bind(input.organization_id)
        .bind(input.project_id)
        .bind(input.pipeline_id)
        .bind(input.trigger_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(trigger_row) = trigger_row else {
            tx.rollback().await?;
            return Err(StoreError::TriggerIngressConflict(
                "delivery does not identify a configured trigger".to_owned(),
            ));
        };
        // The first lookup cannot lock an absent unique key. Recheck after the
        // trigger-definition lock serializes first acceptance so an
        // active-active waiter observes the committed delivery as replay
        // instead of surfacing a database uniqueness error.
        let serialized_existing = sqlx::query(
            "SELECT * FROM trigger_deliveries
             WHERE organization_id = $1 AND trigger_id = $2
               AND (delivery_id = $3 OR event_id = $4)
             FOR UPDATE",
        )
        .bind(input.organization_id)
        .bind(input.trigger_id)
        .bind(&input.delivery_id)
        .bind(&input.event_id)
        .fetch_all(&mut *tx)
        .await?;
        if serialized_existing.len() > 1 {
            tx.rollback().await?;
            return Err(StoreError::TriggerIngressConflict(
                "delivery and event IDs identify different accepted deliveries".to_owned(),
            ));
        }
        if let Some(existing) = serialized_existing.into_iter().next() {
            let delivery = delivery_from_row(existing)?;
            if !delivery_matches(&delivery, input) {
                tx.rollback().await?;
                return Err(StoreError::TriggerIngressConflict(
                    "delivery or event ID was reused for different trigger input".to_owned(),
                ));
            }
            tx.commit().await?;
            return Ok(TriggerDeliveryAdmission::Replayed(delivery));
        }
        let generation: i64 = trigger_row.try_get("current_generation")?;
        if generation != input.expected_trigger_generation {
            tx.rollback().await?;
            return Err(StoreError::TriggerIngressConflict(format!(
                "trigger generation changed from {} to {generation}",
                input.expected_trigger_generation
            )));
        }
        let state: &str = trigger_row.try_get("state")?;
        if state == "paused" {
            tx.rollback().await?;
            return Err(StoreError::TriggerPaused {
                trigger_id: input.trigger_id,
                generation,
            });
        }
        if state != "enabled" {
            tx.rollback().await?;
            return Err(StoreError::InvalidTriggerIngress(format!(
                "stored trigger state '{state}' is invalid"
            )));
        }
        let expected_caller: &str = trigger_row.try_get("event_source_identity")?;
        if expected_caller != input.caller_identity {
            tx.rollback().await?;
            return Err(StoreError::TriggerIngressConflict(
                "authenticated caller does not match the configured event source".to_owned(),
            ));
        }
        let window_seconds: i64 = trigger_row.try_get("deduplication_window_seconds")?;
        let ttl_seconds: i64 = trigger_row.try_get("delivery_ttl_seconds")?;
        let trigger_kind = TriggerKind::parse(trigger_row.try_get("trigger_kind")?)?;
        let trigger_configuration: Value = trigger_row.try_get("configuration")?;
        validate_delivery_against_configuration(trigger_kind, input, &trigger_configuration)?;
        match (trigger_kind, input.schedule_slot.as_ref()) {
            (TriggerKind::Schedule, Some(slot)) => {
                advance_schedule_for_delivery(
                    &mut tx,
                    input,
                    generation,
                    slot,
                    &trigger_configuration,
                )
                .await?;
            }
            (TriggerKind::Schedule, None) => {
                tx.rollback().await?;
                return Err(StoreError::InvalidTriggerIngress(
                    "schedule delivery requires an exact resolved slot".to_owned(),
                ));
            }
            (_, Some(_)) => {
                tx.rollback().await?;
                return Err(StoreError::InvalidTriggerIngress(
                    "only schedule triggers may carry a resolved schedule slot".to_owned(),
                ));
            }
            (_, None) => {}
        }
        let pipeline = sqlx::query_as::<_, (i64, String)>(
            "SELECT d.operational_generation, h.state
             FROM pipeline_definitions AS d
             JOIN pipeline_operational_state_history AS h
               ON h.organization_id = d.organization_id
              AND h.pipeline_id = d.pipeline_id
              AND h.generation = d.operational_generation
             WHERE d.organization_id = $1 AND d.project_id = $2
               AND d.pipeline_id = $3
             FOR UPDATE OF d",
        )
        .bind(input.organization_id)
        .bind(input.project_id)
        .bind(input.pipeline_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((pipeline_generation, pipeline_state)) = pipeline else {
            tx.rollback().await?;
            return Err(StoreError::TriggerIngressConflict(
                "trigger pipeline no longer exists".to_owned(),
            ));
        };
        if pipeline_state == "disabled" {
            tx.rollback().await?;
            return Err(StoreError::PipelineDisabled {
                pipeline_id: input.pipeline_id,
                generation: pipeline_generation,
            });
        }
        if pipeline_state != "enabled" {
            tx.rollback().await?;
            return Err(StoreError::InvalidPipelineState(format!(
                "stored pipeline operational state '{pipeline_state}' is invalid"
            )));
        }

        // Acceptance time is sampled only after every later blocking row lock,
        // including the organization-wide audit head, is already held.
        let _ = crate::audit::lock_audit_head(&mut tx, input.organization_id).await?;
        let database_accepted_at_unix_ms = trigger_database_unix_ms(&mut tx).await?;
        if input.event_time_unix_ms > database_accepted_at_unix_ms.saturating_add(MAX_CLOCK_SKEW_MS)
            || input.event_time_unix_ms
                < database_accepted_at_unix_ms.saturating_sub(window_seconds * 1000)
        {
            tx.rollback().await?;
            return Err(StoreError::InvalidTriggerIngress(
                "trigger event is outside its configured replay/skew window".to_owned(),
            ));
        }
        let expires_at = database_accepted_at_unix_ms
            .checked_add(ttl_seconds * 1000)
            .ok_or_else(|| {
                StoreError::InvalidTriggerIngress("trigger delivery expiry overflows".to_owned())
            })?;
        let audit = crate::audit::append_audit_record(
            &mut tx,
            input.organization_id,
            "trigger",
            &input.caller_identity,
            "trigger.delivery_accepted",
            &format!(
                "trigger:{}:delivery:{}",
                input.trigger_id, input.delivery_id
            ),
            json!({
                "project_id": input.project_id,
                "pipeline_id": input.pipeline_id,
                "trigger_id": input.trigger_id,
                "trigger_generation": generation,
                "delivery_id": input.delivery_id,
                "event_id": input.event_id,
                "event_kind": input.event_kind,
                "payload_sha256": hex::encode(input.payload_sha256),
                "event_time_unix_ms": input.event_time_unix_ms,
                "accepted_at_unix_ms": database_accepted_at_unix_ms,
                "expires_at_unix_ms": expires_at,
                "schedule_slot": input.schedule_slot.as_ref(),
            }),
        )
        .await?;
        sqlx::query(
            "INSERT INTO trigger_deliveries (
                 organization_id, project_id, pipeline_id, trigger_id,
                 trigger_generation, delivery_id, event_id, event_kind,
                 caller_identity, payload_sha256, canonical_payload, parameters,
                 requested_platform, requested_trust_pool, event_time_unix_ms,
                 accepted_at_unix_ms, expires_at_unix_ms, status,
                 next_attempt_at_unix_ms, audit_sequence, audit_event_hash
             ) VALUES (
                 $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                 $13, $14, $15, $16, $17, 'pending', $16, $18, $19
             )",
        )
        .bind(input.organization_id)
        .bind(input.project_id)
        .bind(input.pipeline_id)
        .bind(input.trigger_id)
        .bind(generation)
        .bind(&input.delivery_id)
        .bind(&input.event_id)
        .bind(&input.event_kind)
        .bind(&input.caller_identity)
        .bind(input.payload_sha256.as_slice())
        .bind(&input.canonical_payload)
        .bind(&input.parameters)
        .bind(&input.requested_platform)
        .bind(&input.requested_trust_pool)
        .bind(input.event_time_unix_ms)
        .bind(database_accepted_at_unix_ms)
        .bind(expires_at)
        .bind(audit.sequence)
        .bind(audit.event_hash.as_slice())
        .execute(&mut *tx)
        .await?;
        let row = sqlx::query(
            "SELECT * FROM trigger_deliveries
             WHERE organization_id = $1 AND trigger_id = $2 AND delivery_id = $3",
        )
        .bind(input.organization_id)
        .bind(input.trigger_id)
        .bind(&input.delivery_id)
        .fetch_one(&mut *tx)
        .await?;
        let delivery = delivery_from_row(row)?;
        tx.commit().await?;
        Ok(TriggerDeliveryAdmission::Created(delivery))
    }

    pub async fn claim_trigger_delivery(
        &self,
        input: &TriggerDeliveryClaimRequest,
    ) -> Result<TriggerDeliveryClaimOutcome, StoreError> {
        validate_text("delivery_id", &input.delivery_id, MAX_TEXT_BYTES)?;
        validate_text("worker_identity", &input.worker_identity, MAX_TEXT_BYTES)?;
        if input.now_unix_ms < 0
            || input.lease_expires_at_unix_ms <= input.now_unix_ms
            || input.lease_expires_at_unix_ms - input.now_unix_ms > 15 * 60 * 1000
        {
            return Err(StoreError::InvalidTriggerIngress(
                "delivery claim requires a positive lease of at most fifteen minutes".to_owned(),
            ));
        }
        let mut tx = self.tenant_transaction(input.organization_id).await?;
        lock_trigger_transaction(&mut tx, input.organization_id, input.trigger_id).await?;
        let row = sqlx::query(
            "SELECT * FROM trigger_deliveries
             WHERE organization_id = $1 AND trigger_id = $2 AND delivery_id = $3
             FOR UPDATE",
        )
        .bind(input.organization_id)
        .bind(input.trigger_id)
        .bind(&input.delivery_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| {
            StoreError::TriggerIngressConflict("trigger delivery does not exist".to_owned())
        })?;
        let current = delivery_from_row(row)?;
        if matches!(
            current.status,
            TriggerDeliveryStatus::Admitted | TriggerDeliveryStatus::DeadLettered
        ) {
            tx.commit().await?;
            return Ok(TriggerDeliveryClaimOutcome::Terminal(current));
        }
        let current_trigger = sqlx::query_as::<_, (i64, String)>(
            "SELECT definition.current_generation, version.state
             FROM pipeline_trigger_definitions AS definition
             JOIN pipeline_trigger_versions AS version
               ON version.organization_id = definition.organization_id
              AND version.trigger_id = definition.trigger_id
              AND version.generation = definition.current_generation
             WHERE definition.organization_id = $1 AND definition.trigger_id = $2
             FOR UPDATE OF definition",
        )
        .bind(input.organization_id)
        .bind(input.trigger_id)
        .fetch_one(&mut *tx)
        .await?;
        if current_trigger.1 == "paused" {
            tx.rollback().await?;
            return Err(StoreError::TriggerPaused {
                trigger_id: input.trigger_id,
                generation: current_trigger.0,
            });
        }
        if current_trigger.1 != "enabled" {
            tx.rollback().await?;
            return Err(StoreError::InvalidTriggerIngress(format!(
                "stored trigger state '{}' is invalid",
                current_trigger.1
            )));
        }
        let pipeline = sqlx::query_as::<_, (i64, String)>(
            "SELECT definition.operational_generation, history.state
             FROM pipeline_definitions AS definition
             JOIN pipeline_operational_state_history AS history
               ON history.organization_id = definition.organization_id
              AND history.pipeline_id = definition.pipeline_id
              AND history.generation = definition.operational_generation
             WHERE definition.organization_id = $1
               AND definition.project_id = $2 AND definition.pipeline_id = $3
             FOR UPDATE OF definition",
        )
        .bind(input.organization_id)
        .bind(current.project_id)
        .bind(current.pipeline_id)
        .fetch_one(&mut *tx)
        .await?;
        if pipeline.1 == "disabled" {
            tx.rollback().await?;
            return Err(StoreError::PipelineDisabled {
                pipeline_id: current.pipeline_id,
                generation: pipeline.0,
            });
        }
        if pipeline.1 != "enabled" {
            tx.rollback().await?;
            return Err(StoreError::InvalidPipelineState(format!(
                "stored pipeline operational state '{}' is invalid",
                pipeline.1
            )));
        }
        // Read-only not-due and live-lease outcomes need no audit mutation and
        // therefore cannot become stale behind a later audit-head wait.
        let preliminary_database_now_unix_ms = trigger_database_unix_ms(&mut tx).await?;
        if current.next_attempt_at_unix_ms > preliminary_database_now_unix_ms {
            tx.commit().await?;
            return Ok(TriggerDeliveryClaimOutcome::NotDue(current));
        }
        if current.expires_at_unix_ms > preliminary_database_now_unix_ms
            && current.claim_owner.is_some()
            && current.claim_expires_at_unix_ms.unwrap_or(0) > preliminary_database_now_unix_ms
        {
            tx.commit().await?;
            return Ok(TriggerDeliveryClaimOutcome::Leased(current));
        }
        // Claim due/TTL/lease authority is sampled only after the trigger,
        // pipeline, and organization audit-head locks are all held.
        let _ = crate::audit::lock_audit_head(&mut tx, input.organization_id).await?;
        let database_now_unix_ms = trigger_database_unix_ms(&mut tx).await?;
        if current.next_attempt_at_unix_ms > database_now_unix_ms {
            tx.commit().await?;
            return Ok(TriggerDeliveryClaimOutcome::NotDue(current));
        }
        if current.expires_at_unix_ms <= database_now_unix_ms {
            crate::audit::append_audit_record(
                &mut tx,
                input.organization_id,
                "trigger",
                &input.worker_identity,
                "trigger.delivery_dead_lettered",
                &format!(
                    "trigger:{}:delivery:{}",
                    input.trigger_id, input.delivery_id
                ),
                json!({"reason": "delivery expired before claim"}),
            )
            .await?;
            sqlx::query(
                "UPDATE trigger_deliveries
                 SET status = 'dead_lettered',
                     terminal_reason = 'delivery expired before claim',
                     claim_owner = NULL, claim_expires_at_unix_ms = NULL,
                     updated_at = clock_timestamp()
                 WHERE organization_id = $1 AND trigger_id = $2 AND delivery_id = $3",
            )
            .bind(input.organization_id)
            .bind(input.trigger_id)
            .bind(&input.delivery_id)
            .execute(&mut *tx)
            .await?;
            let row = sqlx::query(
                "SELECT * FROM trigger_deliveries
                 WHERE organization_id = $1 AND trigger_id = $2 AND delivery_id = $3",
            )
            .bind(input.organization_id)
            .bind(input.trigger_id)
            .bind(&input.delivery_id)
            .fetch_one(&mut *tx)
            .await?;
            let delivery = delivery_from_row(row)?;
            tx.commit().await?;
            return Ok(TriggerDeliveryClaimOutcome::Terminal(delivery));
        }
        if current.claim_owner.is_some()
            && current.claim_expires_at_unix_ms.unwrap_or(0) > database_now_unix_ms
        {
            tx.commit().await?;
            return Ok(TriggerDeliveryClaimOutcome::Leased(current));
        }
        let next_fence = current.claim_fence + 1;
        let lease_duration_ms = input.lease_expires_at_unix_ms - input.now_unix_ms;
        let lease_expires_at_unix_ms = database_now_unix_ms
            .checked_add(lease_duration_ms)
            .ok_or_else(|| {
                StoreError::InvalidTriggerIngress("delivery claim lease overflows".to_owned())
            })?;
        crate::audit::append_audit_record(
            &mut tx,
            input.organization_id,
            "trigger",
            &input.worker_identity,
            "trigger.delivery_claimed",
            &format!(
                "trigger:{}:delivery:{}",
                input.trigger_id, input.delivery_id
            ),
            json!({
                "claim_fence": next_fence,
                "lease_expires_at_unix_ms": lease_expires_at_unix_ms,
            }),
        )
        .await?;
        sqlx::query(
            "UPDATE trigger_deliveries
             SET claim_owner = $4, claim_fence = $5,
                 claim_expires_at_unix_ms = $6, updated_at = clock_timestamp()
             WHERE organization_id = $1 AND trigger_id = $2 AND delivery_id = $3",
        )
        .bind(input.organization_id)
        .bind(input.trigger_id)
        .bind(&input.delivery_id)
        .bind(&input.worker_identity)
        .bind(next_fence)
        .bind(lease_expires_at_unix_ms)
        .execute(&mut *tx)
        .await?;
        let row = sqlx::query(
            "SELECT * FROM trigger_deliveries
             WHERE organization_id = $1 AND trigger_id = $2 AND delivery_id = $3",
        )
        .bind(input.organization_id)
        .bind(input.trigger_id)
        .bind(&input.delivery_id)
        .fetch_one(&mut *tx)
        .await?;
        let delivery = delivery_from_row(row)?;
        tx.commit().await?;
        Ok(TriggerDeliveryClaimOutcome::Claimed(delivery))
    }

    pub async fn due_trigger_deliveries(
        &self,
        organization_id: Uuid,
        now_unix_ms: i64,
        limit: i64,
    ) -> Result<Vec<TriggerDelivery>, StoreError> {
        if now_unix_ms < 0 || !(1..=128).contains(&limit) {
            return Err(StoreError::InvalidTriggerIngress(
                "due trigger delivery scan requires a non-negative time and limit from 1 to 128"
                    .to_owned(),
            ));
        }
        let mut tx = self.tenant_transaction(organization_id).await?;
        let rows = sqlx::query(
            "WITH timing AS (
                 SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint AS now_unix_ms
             )
             SELECT delivery.*
             FROM trigger_deliveries AS delivery
             CROSS JOIN timing
             JOIN pipeline_trigger_definitions AS trigger
               ON trigger.organization_id = delivery.organization_id
              AND trigger.trigger_id = delivery.trigger_id
             JOIN pipeline_trigger_versions AS trigger_version
               ON trigger_version.organization_id = trigger.organization_id
              AND trigger_version.trigger_id = trigger.trigger_id
              AND trigger_version.generation = trigger.current_generation
             JOIN pipeline_definitions AS pipeline
               ON pipeline.organization_id = delivery.organization_id
              AND pipeline.project_id = delivery.project_id
              AND pipeline.pipeline_id = delivery.pipeline_id
             JOIN pipeline_operational_state_history AS pipeline_state
               ON pipeline_state.organization_id = pipeline.organization_id
              AND pipeline_state.pipeline_id = pipeline.pipeline_id
              AND pipeline_state.generation = pipeline.operational_generation
             WHERE delivery.organization_id = $1
               AND delivery.status IN ('pending', 'retry_wait')
               AND delivery.next_attempt_at_unix_ms <= timing.now_unix_ms
               AND (delivery.claim_owner IS NULL
                    OR delivery.claim_expires_at_unix_ms <= timing.now_unix_ms)
               AND trigger_version.state = 'enabled'
               AND pipeline_state.state = 'enabled'
             ORDER BY delivery.next_attempt_at_unix_ms,
                      delivery.accepted_at_unix_ms, delivery.delivery_id
             LIMIT $2",
        )
        .bind(organization_id)
        .bind(limit)
        .fetch_all(&mut *tx)
        .await?;
        let deliveries = rows
            .into_iter()
            .map(delivery_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        tx.commit().await?;
        Ok(deliveries)
    }

    pub async fn admit_trigger_delivery_dag(
        &self,
        input: &TriggerDeliveryDagAdmissionRequest,
        dag: &NewDagBuild,
    ) -> Result<TriggerDeliveryDagAdmission, StoreError> {
        validate_text("delivery_id", &input.delivery_id, MAX_TEXT_BYTES)?;
        validate_text("worker_identity", &input.worker_identity, MAX_TEXT_BYTES)?;
        if input.claim_fence <= 0 {
            return Err(StoreError::InvalidTriggerIngress(
                "trigger DAG admission requires a positive claim fence".to_owned(),
            ));
        }
        if dag.organization_id != input.organization_id {
            return Err(StoreError::TriggerIngressConflict(
                "trigger delivery and DAG organizations differ".to_owned(),
            ));
        }
        let mut tx = self.tenant_transaction(input.organization_id).await?;
        lock_trigger_transaction(&mut tx, input.organization_id, input.trigger_id).await?;
        let row = sqlx::query(
            "SELECT * FROM trigger_deliveries
             WHERE organization_id = $1 AND trigger_id = $2 AND delivery_id = $3
             FOR UPDATE",
        )
        .bind(input.organization_id)
        .bind(input.trigger_id)
        .bind(&input.delivery_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| {
            StoreError::TriggerIngressConflict("trigger delivery does not exist".to_owned())
        })?;
        let current = delivery_from_row(row)?;
        if matches!(
            current.status,
            TriggerDeliveryStatus::Admitted | TriggerDeliveryStatus::DeadLettered
        ) {
            tx.rollback().await?;
            return Err(StoreError::TriggerIngressConflict(
                "terminal trigger delivery cannot admit another DAG".to_owned(),
            ));
        }
        if current.project_id != dag.project_id || current.pipeline_id != dag.pipeline_id {
            tx.rollback().await?;
            return Err(StoreError::TriggerIngressConflict(
                "trigger delivery and DAG pipeline bindings differ".to_owned(),
            ));
        }
        if current.claim_owner.as_deref() != Some(input.worker_identity.as_str())
            || current.claim_fence != input.claim_fence
        {
            tx.rollback().await?;
            return Err(StoreError::TriggerIngressConflict(
                "delivery completion claim is stale or belongs to another worker".to_owned(),
            ));
        }
        let admitted_at_unix_ms = trigger_database_unix_ms(&mut tx).await?;
        if current.expires_at_unix_ms <= admitted_at_unix_ms {
            let delivery =
                dead_letter_expired_trigger_dag_admission(&mut tx, input, admitted_at_unix_ms)
                    .await?;
            tx.commit().await?;
            return Ok(TriggerDeliveryDagAdmission::DeadLettered(delivery));
        }
        if current.claim_expires_at_unix_ms.unwrap_or(0) <= admitted_at_unix_ms {
            tx.commit().await?;
            return Ok(TriggerDeliveryDagAdmission::LeaseLost(current));
        }
        let mut admission_tx = tx.begin().await?;
        let admission = crate::dag::admit_dag_transaction(&mut admission_tx, dag).await?;
        let bound = sqlx::query_scalar::<_, String>(
            "UPDATE trigger_deliveries
             SET status = 'admitted', build_id = $4,
                 attempt_count = attempt_count + 1,
                 claim_owner = NULL, claim_expires_at_unix_ms = NULL,
                 updated_at = clock_timestamp()
             WHERE organization_id = $1 AND trigger_id = $2 AND delivery_id = $3
               AND claim_owner = $5 AND claim_fence = $6
               AND expires_at_unix_ms >
                   floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint
               AND claim_expires_at_unix_ms >
                   floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint
             RETURNING delivery_id",
        )
        .bind(input.organization_id)
        .bind(input.trigger_id)
        .bind(&input.delivery_id)
        .bind(admission.build_id)
        .bind(&input.worker_identity)
        .bind(input.claim_fence)
        .fetch_optional(&mut *admission_tx)
        .await?;
        if bound.is_none() {
            let admitted_at_unix_ms = trigger_database_unix_ms(&mut admission_tx).await?;
            admission_tx.rollback().await?;
            if current.expires_at_unix_ms <= admitted_at_unix_ms {
                let delivery =
                    dead_letter_expired_trigger_dag_admission(&mut tx, input, admitted_at_unix_ms)
                        .await?;
                tx.commit().await?;
                return Ok(TriggerDeliveryDagAdmission::DeadLettered(delivery));
            }
            let row = sqlx::query(
                "SELECT * FROM trigger_deliveries
                 WHERE organization_id = $1 AND trigger_id = $2 AND delivery_id = $3",
            )
            .bind(input.organization_id)
            .bind(input.trigger_id)
            .bind(&input.delivery_id)
            .fetch_one(&mut *tx)
            .await?;
            let delivery = delivery_from_row(row)?;
            tx.commit().await?;
            return Ok(TriggerDeliveryDagAdmission::LeaseLost(delivery));
        }
        crate::audit::append_audit_record(
            &mut admission_tx,
            input.organization_id,
            "trigger",
            &input.worker_identity,
            "trigger.delivery_admitted",
            &format!(
                "trigger:{}:delivery:{}",
                input.trigger_id, input.delivery_id
            ),
            json!({"build_id": admission.build_id}),
        )
        .await?;
        admission_tx.commit().await?;
        let row = sqlx::query(
            "SELECT * FROM trigger_deliveries
             WHERE organization_id = $1 AND trigger_id = $2 AND delivery_id = $3",
        )
        .bind(input.organization_id)
        .bind(input.trigger_id)
        .bind(&input.delivery_id)
        .fetch_one(&mut *tx)
        .await?;
        let delivery = delivery_from_row(row)?;
        tx.commit().await?;
        Ok(TriggerDeliveryDagAdmission::Admitted {
            delivery,
            admission,
        })
    }

    pub async fn fail_trigger_delivery(
        &self,
        input: &TriggerDeliveryFailureRequest,
    ) -> Result<TriggerDeliveryFailure, StoreError> {
        validate_text("delivery_id", &input.delivery_id, MAX_TEXT_BYTES)?;
        validate_text("worker_identity", &input.worker_identity, MAX_TEXT_BYTES)?;
        validate_text("reason", &input.reason, MAX_REASON_BYTES)?;
        if input.claim_fence <= 0
            || input.now_unix_ms < 0
            || (input.retryable && input.retry_at_unix_ms <= input.now_unix_ms)
        {
            return Err(StoreError::InvalidTriggerIngress(
                "delivery failure requires a positive future retry time".to_owned(),
            ));
        }
        let mut tx = self.tenant_transaction(input.organization_id).await?;
        let row = sqlx::query(
            "SELECT delivery.*, version.max_delivery_attempts
             FROM trigger_deliveries AS delivery
             JOIN pipeline_trigger_versions AS version
               ON version.organization_id = delivery.organization_id
              AND version.trigger_id = delivery.trigger_id
              AND version.generation = delivery.trigger_generation
             WHERE delivery.organization_id = $1
               AND delivery.trigger_id = $2 AND delivery.delivery_id = $3
             FOR UPDATE OF delivery",
        )
        .bind(input.organization_id)
        .bind(input.trigger_id)
        .bind(&input.delivery_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| {
            StoreError::TriggerIngressConflict("trigger delivery does not exist".to_owned())
        })?;
        let max_attempts: i32 = row.try_get("max_delivery_attempts")?;
        let current = delivery_from_row(row)?;
        if matches!(
            current.status,
            TriggerDeliveryStatus::Admitted | TriggerDeliveryStatus::DeadLettered
        ) {
            tx.rollback().await?;
            return Err(StoreError::TriggerIngressConflict(
                "terminal trigger delivery cannot fail again".to_owned(),
            ));
        }
        if current.claim_owner.as_deref() != Some(input.worker_identity.as_str())
            || current.claim_fence != input.claim_fence
        {
            tx.rollback().await?;
            return Err(StoreError::TriggerIngressConflict(
                "delivery failure claim is stale or belongs to another worker".to_owned(),
            ));
        }
        // Hold the later audit-head lock before sampling lease/TTL authority so
        // contention cannot make the failure decision stale before it commits.
        let _ = crate::audit::lock_audit_head(&mut tx, input.organization_id).await?;
        let database_now_unix_ms = trigger_database_unix_ms(&mut tx).await?;
        if current.claim_expires_at_unix_ms.unwrap_or(0) <= database_now_unix_ms {
            tx.commit().await?;
            return Ok(TriggerDeliveryFailure::LeaseLost(current));
        }
        let retry_at_unix_ms = if input.retryable {
            let retry_delay_ms = input
                .retry_at_unix_ms
                .checked_sub(input.now_unix_ms)
                .ok_or_else(|| {
                    StoreError::InvalidTriggerIngress("delivery retry time overflows".to_owned())
                })?;
            database_now_unix_ms
                .checked_add(retry_delay_ms)
                .ok_or_else(|| {
                    StoreError::InvalidTriggerIngress("delivery retry time overflows".to_owned())
                })?
        } else {
            current.next_attempt_at_unix_ms
        };
        let next_attempt = current.attempt_count + 1;
        let dead_letter = !input.retryable
            || next_attempt >= max_attempts
            || database_now_unix_ms >= current.expires_at_unix_ms;
        crate::audit::append_audit_record(
            &mut tx,
            input.organization_id,
            "trigger",
            &input.worker_identity,
            if dead_letter {
                "trigger.delivery_dead_lettered"
            } else {
                "trigger.delivery_retry_scheduled"
            },
            &format!(
                "trigger:{}:delivery:{}",
                input.trigger_id, input.delivery_id
            ),
            json!({
                "attempt_count": next_attempt,
                "reason": input.reason,
                "retry_at_unix_ms": if dead_letter { Value::Null } else { json!(retry_at_unix_ms) },
            }),
        )
        .await?;
        sqlx::query(
            "UPDATE trigger_deliveries
             SET status = CASE WHEN $4 THEN 'dead_lettered' ELSE 'retry_wait' END,
                 attempt_count = $5,
                 next_attempt_at_unix_ms = CASE WHEN $4 THEN next_attempt_at_unix_ms ELSE $6 END,
                 terminal_reason = CASE WHEN $4 THEN $7 ELSE NULL END,
                 claim_owner = NULL, claim_expires_at_unix_ms = NULL,
                 updated_at = clock_timestamp()
             WHERE organization_id = $1 AND trigger_id = $2 AND delivery_id = $3",
        )
        .bind(input.organization_id)
        .bind(input.trigger_id)
        .bind(&input.delivery_id)
        .bind(dead_letter)
        .bind(next_attempt)
        .bind(retry_at_unix_ms)
        .bind(&input.reason)
        .execute(&mut *tx)
        .await?;
        let row = sqlx::query(
            "SELECT * FROM trigger_deliveries
             WHERE organization_id = $1 AND trigger_id = $2 AND delivery_id = $3",
        )
        .bind(input.organization_id)
        .bind(input.trigger_id)
        .bind(&input.delivery_id)
        .fetch_one(&mut *tx)
        .await?;
        let delivery = delivery_from_row(row)?;
        tx.commit().await?;
        Ok(if dead_letter {
            TriggerDeliveryFailure::DeadLettered(delivery)
        } else {
            TriggerDeliveryFailure::RetryScheduled(delivery)
        })
    }

    pub async fn redrive_trigger_delivery(
        &self,
        input: &TriggerDeliveryRedrive,
    ) -> Result<TriggerDeliveryAdmission, StoreError> {
        validate_text(
            "dead_letter_delivery_id",
            &input.dead_letter_delivery_id,
            MAX_TEXT_BYTES,
        )?;
        validate_text("new_delivery_id", &input.new_delivery_id, MAX_TEXT_BYTES)?;
        validate_text("new_event_id", &input.new_event_id, MAX_TEXT_BYTES)?;
        validate_text("actor_subject", &input.actor_subject, MAX_TEXT_BYTES)?;
        if input.accepted_at_unix_ms < 0 || input.dead_letter_delivery_id == input.new_delivery_id {
            return Err(StoreError::InvalidTriggerIngress(
                "redrive requires a new delivery identity and valid acceptance time".to_owned(),
            ));
        }
        let mut tx = self.tenant_transaction(input.organization_id).await?;
        lock_trigger_transaction(&mut tx, input.organization_id, input.trigger_id).await?;
        let replay_rows = sqlx::query(
            "SELECT * FROM trigger_deliveries
             WHERE organization_id = $1 AND project_id = $2 AND pipeline_id = $3
               AND trigger_id = $4 AND (delivery_id = $5 OR event_id = $6)
             FOR UPDATE",
        )
        .bind(input.organization_id)
        .bind(input.project_id)
        .bind(input.pipeline_id)
        .bind(input.trigger_id)
        .bind(&input.new_delivery_id)
        .bind(&input.new_event_id)
        .fetch_all(&mut *tx)
        .await?;
        if replay_rows.len() > 1 {
            tx.rollback().await?;
            return Err(StoreError::TriggerIngressConflict(
                "redrive delivery and event IDs identify different deliveries".to_owned(),
            ));
        }
        if let Some(row) = replay_rows.into_iter().next() {
            let replay = delivery_from_row(row)?;
            if replay.delivery_id != input.new_delivery_id
                || replay.event_id != input.new_event_id
                || replay.redrive_of_delivery_id.as_deref()
                    != Some(input.dead_letter_delivery_id.as_str())
            {
                tx.rollback().await?;
                return Err(StoreError::TriggerIngressConflict(
                    "redrive delivery or event identity was reused".to_owned(),
                ));
            }
            tx.commit().await?;
            return Ok(TriggerDeliveryAdmission::Replayed(replay));
        }
        let original_row = sqlx::query(
            "SELECT * FROM trigger_deliveries
             WHERE organization_id = $1 AND project_id = $2 AND pipeline_id = $3
               AND trigger_id = $4 AND delivery_id = $5
             FOR UPDATE",
        )
        .bind(input.organization_id)
        .bind(input.project_id)
        .bind(input.pipeline_id)
        .bind(input.trigger_id)
        .bind(&input.dead_letter_delivery_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| {
            StoreError::TriggerIngressConflict(
                "dead-letter delivery selected for redrive does not exist".to_owned(),
            )
        })?;
        let original = delivery_from_row(original_row)?;
        if original.status != TriggerDeliveryStatus::DeadLettered {
            tx.rollback().await?;
            return Err(StoreError::TriggerIngressConflict(
                "only a dead-lettered delivery can be redriven".to_owned(),
            ));
        }
        // As with first delivery acceptance, an absent redrive key cannot be
        // locked. The outer trigger scope serializes every first-redrive
        // identity decision, including different source dead letters, so this
        // repeated lookup converges exact replay and rejects divergent reuse
        // rather than leaking a uniqueness error.
        let serialized_replay_rows = sqlx::query(
            "SELECT * FROM trigger_deliveries
             WHERE organization_id = $1 AND project_id = $2 AND pipeline_id = $3
               AND trigger_id = $4 AND (delivery_id = $5 OR event_id = $6)
             FOR UPDATE",
        )
        .bind(input.organization_id)
        .bind(input.project_id)
        .bind(input.pipeline_id)
        .bind(input.trigger_id)
        .bind(&input.new_delivery_id)
        .bind(&input.new_event_id)
        .fetch_all(&mut *tx)
        .await?;
        if serialized_replay_rows.len() > 1 {
            tx.rollback().await?;
            return Err(StoreError::TriggerIngressConflict(
                "redrive delivery and event IDs identify different deliveries".to_owned(),
            ));
        }
        if let Some(row) = serialized_replay_rows.into_iter().next() {
            let replay = delivery_from_row(row)?;
            if replay.delivery_id != input.new_delivery_id
                || replay.event_id != input.new_event_id
                || replay.redrive_of_delivery_id.as_deref()
                    != Some(input.dead_letter_delivery_id.as_str())
            {
                tx.rollback().await?;
                return Err(StoreError::TriggerIngressConflict(
                    "redrive delivery or event identity was reused".to_owned(),
                ));
            }
            tx.commit().await?;
            return Ok(TriggerDeliveryAdmission::Replayed(replay));
        }
        let trigger = sqlx::query(
            "SELECT definition.current_generation, version.state,
                    version.event_source_identity
             FROM pipeline_trigger_definitions AS definition
             JOIN pipeline_trigger_versions AS version
               ON version.organization_id = definition.organization_id
              AND version.trigger_id = definition.trigger_id
              AND version.generation = definition.current_generation
             WHERE definition.organization_id = $1 AND definition.trigger_id = $2
             FOR UPDATE OF definition",
        )
        .bind(input.organization_id)
        .bind(input.trigger_id)
        .fetch_one(&mut *tx)
        .await?;
        let trigger_generation: i64 = trigger.try_get("current_generation")?;
        let trigger_state: &str = trigger.try_get("state")?;
        if trigger_state == "paused" {
            tx.rollback().await?;
            return Err(StoreError::TriggerPaused {
                trigger_id: input.trigger_id,
                generation: trigger_generation,
            });
        }
        if trigger_state != "enabled" {
            tx.rollback().await?;
            return Err(StoreError::InvalidTriggerIngress(format!(
                "stored trigger state '{trigger_state}' is invalid"
            )));
        }
        let current_event_source: &str = trigger.try_get("event_source_identity")?;
        if current_event_source != original.caller_identity {
            tx.rollback().await?;
            return Err(StoreError::TriggerIngressConflict(
                "dead-letter redrive is denied after event-source identity rotation".to_owned(),
            ));
        }
        let pipeline = sqlx::query_as::<_, (i64, String)>(
            "SELECT definition.operational_generation, history.state
             FROM pipeline_definitions AS definition
             JOIN pipeline_operational_state_history AS history
               ON history.organization_id = definition.organization_id
              AND history.pipeline_id = definition.pipeline_id
              AND history.generation = definition.operational_generation
             WHERE definition.organization_id = $1
               AND definition.project_id = $2 AND definition.pipeline_id = $3
             FOR UPDATE OF definition",
        )
        .bind(input.organization_id)
        .bind(original.project_id)
        .bind(original.pipeline_id)
        .fetch_one(&mut *tx)
        .await?;
        if pipeline.1 == "disabled" {
            tx.rollback().await?;
            return Err(StoreError::PipelineDisabled {
                pipeline_id: original.pipeline_id,
                generation: pipeline.0,
            });
        }
        if pipeline.1 != "enabled" {
            tx.rollback().await?;
            return Err(StoreError::InvalidPipelineState(format!(
                "stored pipeline operational state '{}' is invalid",
                pipeline.1
            )));
        }
        let ttl_seconds: i64 = sqlx::query_scalar(
            "SELECT delivery_ttl_seconds FROM pipeline_trigger_versions
             WHERE organization_id = $1 AND trigger_id = $2 AND generation = $3",
        )
        .bind(input.organization_id)
        .bind(input.trigger_id)
        .bind(original.trigger_generation)
        .fetch_one(&mut *tx)
        .await?;
        let ordinal: i32 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(redrive_ordinal), 0) + 1
             FROM trigger_deliveries
             WHERE organization_id = $1 AND trigger_id = $2
               AND redrive_of_delivery_id = $3",
        )
        .bind(input.organization_id)
        .bind(input.trigger_id)
        .bind(&input.dead_letter_delivery_id)
        .fetch_one(&mut *tx)
        .await?;
        // Redrive uses the same post-lock acceptance-time boundary as first
        // delivery capture.
        let _ = crate::audit::lock_audit_head(&mut tx, input.organization_id).await?;
        let database_accepted_at_unix_ms = trigger_database_unix_ms(&mut tx).await?;
        let expires_at = database_accepted_at_unix_ms
            .checked_add(ttl_seconds * 1000)
            .ok_or_else(|| {
                StoreError::InvalidTriggerIngress("redrive expiry overflows".to_owned())
            })?;
        let audit = crate::audit::append_audit_record(
            &mut tx,
            input.organization_id,
            "trigger",
            &input.actor_subject,
            "trigger.delivery_redriven",
            &format!(
                "trigger:{}:delivery:{}",
                input.trigger_id, input.new_delivery_id
            ),
            json!({
                "dead_letter_delivery_id": input.dead_letter_delivery_id,
                "redrive_ordinal": ordinal,
                "trigger_generation": original.trigger_generation,
            }),
        )
        .await?;
        sqlx::query(
            "INSERT INTO trigger_deliveries (
                 organization_id, project_id, pipeline_id, trigger_id,
                 trigger_generation, delivery_id, event_id, event_kind,
                 caller_identity, payload_sha256, canonical_payload, parameters,
                 requested_platform, requested_trust_pool, event_time_unix_ms,
                 accepted_at_unix_ms, expires_at_unix_ms, status,
                 next_attempt_at_unix_ms, redrive_of_delivery_id,
                 redrive_ordinal, audit_sequence, audit_event_hash
             ) VALUES (
                 $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                 $13, $14, $15, $16, $17, 'pending', $16, $18, $19, $20, $21
             )",
        )
        .bind(input.organization_id)
        .bind(original.project_id)
        .bind(original.pipeline_id)
        .bind(input.trigger_id)
        .bind(original.trigger_generation)
        .bind(&input.new_delivery_id)
        .bind(&input.new_event_id)
        .bind(&original.event_kind)
        .bind(&original.caller_identity)
        .bind(original.payload_sha256.as_slice())
        .bind(&original.canonical_payload)
        .bind(&original.parameters)
        .bind(&original.requested_platform)
        .bind(&original.requested_trust_pool)
        .bind(original.event_time_unix_ms)
        .bind(database_accepted_at_unix_ms)
        .bind(expires_at)
        .bind(&input.dead_letter_delivery_id)
        .bind(ordinal)
        .bind(audit.sequence)
        .bind(audit.event_hash.as_slice())
        .execute(&mut *tx)
        .await?;
        let row = sqlx::query(
            "SELECT * FROM trigger_deliveries
             WHERE organization_id = $1 AND trigger_id = $2 AND delivery_id = $3",
        )
        .bind(input.organization_id)
        .bind(input.trigger_id)
        .bind(&input.new_delivery_id)
        .fetch_one(&mut *tx)
        .await?;
        let delivery = delivery_from_row(row)?;
        tx.commit().await?;
        Ok(TriggerDeliveryAdmission::Created(delivery))
    }

    pub async fn trigger_schedule_watermark(
        &self,
        organization_id: Uuid,
        trigger_id: Uuid,
        trigger_generation: i64,
    ) -> Result<Option<TriggerScheduleWatermark>, StoreError> {
        let mut tx = self.tenant_transaction(organization_id).await?;
        let row = sqlx::query(
            "SELECT * FROM trigger_schedule_watermarks
             WHERE organization_id = $1 AND trigger_id = $2
               AND trigger_generation = $3",
        )
        .bind(organization_id)
        .bind(trigger_id)
        .bind(trigger_generation)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        row.map(schedule_watermark_from_row).transpose()
    }

    pub async fn export_quiesced_trigger_state(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        pipeline_id: Uuid,
        trigger_id: Uuid,
        actor_subject: &str,
    ) -> Result<TriggerTransferSnapshot, StoreError> {
        validate_text("actor_subject", actor_subject, MAX_TEXT_BYTES)?;
        let mut tx = self.tenant_transaction(organization_id).await?;
        lock_trigger_transaction(&mut tx, organization_id, trigger_id).await?;
        let current = sqlx::query_scalar::<_, i64>(
            "SELECT definition.current_generation
             FROM pipeline_trigger_definitions AS definition
             JOIN pipeline_trigger_versions AS version
               ON version.organization_id = definition.organization_id
              AND version.trigger_id = definition.trigger_id
              AND version.generation = definition.current_generation
             WHERE definition.organization_id = $1 AND definition.project_id = $2
               AND definition.pipeline_id = $3 AND definition.trigger_id = $4
               AND version.state = 'paused'
             FOR UPDATE OF definition",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(pipeline_id)
        .bind(trigger_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| {
            StoreError::TriggerIngressConflict(
                "trigger handoff requires the exact current generation to be paused".to_owned(),
            )
        })?;
        // A paused trigger has no worker path that may safely steal an expired
        // lease. Reap only database-clock-expired claims under the same trigger
        // scope and definition lock used by the export; a genuinely live claim
        // remains a hard quiescence failure below.
        sqlx::query(
            "UPDATE trigger_deliveries
             SET claim_owner = NULL, claim_expires_at_unix_ms = NULL,
                 updated_at = clock_timestamp()
             WHERE organization_id = $1 AND project_id = $2
               AND pipeline_id = $3 AND trigger_id = $4
               AND claim_owner IS NOT NULL
               AND claim_expires_at_unix_ms <=
                   floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(pipeline_id)
        .bind(trigger_id)
        .execute(&mut *tx)
        .await?;
        let version_rows = sqlx::query(
            "SELECT definition.organization_id, definition.project_id,
                    definition.pipeline_id, definition.trigger_id,
                    version.generation AS current_generation,
                    version.trigger_kind, version.state,
                    version.implementation_sha256, version.configuration_sha256,
                    version.filter_sha256, version.event_source_identity,
                    version.source_generation, version.configuration,
                    version.deduplication_window_seconds,
                    version.max_delivery_attempts, version.delivery_ttl_seconds,
                    version.actor_subject, version.reason, version.idempotency_key,
                    version.audit_sequence, version.audit_event_hash
             FROM pipeline_trigger_definitions AS definition
             JOIN pipeline_trigger_versions AS version
               ON version.organization_id = definition.organization_id
              AND version.trigger_id = definition.trigger_id
             WHERE definition.organization_id = $1 AND definition.project_id = $2
               AND definition.pipeline_id = $3 AND definition.trigger_id = $4
             ORDER BY version.generation
             FOR SHARE OF version",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(pipeline_id)
        .bind(trigger_id)
        .fetch_all(&mut *tx)
        .await?;
        let versions = version_rows
            .into_iter()
            .map(trigger_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        let delivery_rows = sqlx::query(
            "SELECT * FROM trigger_deliveries
             WHERE organization_id = $1 AND project_id = $2
               AND pipeline_id = $3 AND trigger_id = $4
             ORDER BY delivery_id
             FOR SHARE",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(pipeline_id)
        .bind(trigger_id)
        .fetch_all(&mut *tx)
        .await?;
        let deliveries = delivery_rows
            .into_iter()
            .map(delivery_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        if deliveries.iter().any(|delivery| {
            delivery.claim_owner.is_some() || delivery.claim_expires_at_unix_ms.is_some()
        }) {
            tx.rollback().await?;
            return Err(StoreError::TriggerIngressConflict(
                "trigger handoff cannot export an actively claimed delivery".to_owned(),
            ));
        }
        let watermark_rows = sqlx::query(
            "SELECT * FROM trigger_schedule_watermarks
             WHERE organization_id = $1 AND project_id = $2
               AND pipeline_id = $3 AND trigger_id = $4
             ORDER BY trigger_generation
             FOR SHARE",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(pipeline_id)
        .bind(trigger_id)
        .fetch_all(&mut *tx)
        .await?;
        let schedule_watermarks = watermark_rows
            .into_iter()
            .map(schedule_watermark_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        let ledger_sha256 = trigger_transfer_ledger_digest(
            1,
            organization_id,
            project_id,
            pipeline_id,
            trigger_id,
            current,
            &versions,
            &deliveries,
            &schedule_watermarks,
        )?;
        let audit = crate::audit::append_audit_record(
            &mut tx,
            organization_id,
            "trigger",
            actor_subject,
            "trigger.handoff_exported",
            &format!("pipeline:{pipeline_id}:trigger:{trigger_id}"),
            json!({
                "project_id": project_id,
                "pipeline_id": pipeline_id,
                "trigger_id": trigger_id,
                "current_generation": current,
                "version_count": versions.len(),
                "delivery_count": deliveries.len(),
                "schedule_watermark_count": schedule_watermarks.len(),
                "ledger_sha256": hex::encode(ledger_sha256),
            }),
        )
        .await?;
        let mut snapshot = TriggerTransferSnapshot {
            schema_version: 1,
            organization_id,
            project_id,
            pipeline_id,
            trigger_id,
            current_generation: current,
            versions,
            deliveries,
            schedule_watermarks,
            handoff_audit_event: audit.clone(),
            audit_sequence: audit.sequence,
            audit_event_hash: audit.event_hash,
            state_sha256: [0; 32],
        };
        snapshot.state_sha256 = compute_trigger_transfer_snapshot_digest(&snapshot)?;
        verify_trigger_transfer_snapshot(&snapshot, audit.event_hash)?;
        tx.commit().await?;
        Ok(snapshot)
    }
}

async fn trigger_database_unix_ms(tx: &mut Transaction<'_, Postgres>) -> Result<i64, StoreError> {
    Ok(sqlx::query_scalar::<_, i64>(
        "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint",
    )
    .fetch_one(&mut **tx)
    .await?)
}

async fn dead_letter_expired_trigger_dag_admission(
    tx: &mut Transaction<'_, Postgres>,
    input: &TriggerDeliveryDagAdmissionRequest,
    admitted_at_unix_ms: i64,
) -> Result<TriggerDelivery, StoreError> {
    let reason = "delivery expired before atomic DAG admission";
    crate::audit::append_audit_record(
        tx,
        input.organization_id,
        "trigger",
        &input.worker_identity,
        "trigger.delivery_dead_lettered",
        &format!(
            "trigger:{}:delivery:{}",
            input.trigger_id, input.delivery_id
        ),
        json!({"reason": reason, "admitted_at_unix_ms": admitted_at_unix_ms}),
    )
    .await?;
    sqlx::query(
        "UPDATE trigger_deliveries
         SET status = 'dead_lettered', attempt_count = attempt_count + 1,
             terminal_reason = $4, claim_owner = NULL,
             claim_expires_at_unix_ms = NULL, updated_at = clock_timestamp()
         WHERE organization_id = $1 AND trigger_id = $2 AND delivery_id = $3",
    )
    .bind(input.organization_id)
    .bind(input.trigger_id)
    .bind(&input.delivery_id)
    .bind(reason)
    .execute(&mut **tx)
    .await?;
    let row = sqlx::query(
        "SELECT * FROM trigger_deliveries
         WHERE organization_id = $1 AND trigger_id = $2 AND delivery_id = $3",
    )
    .bind(input.organization_id)
    .bind(input.trigger_id)
    .bind(&input.delivery_id)
    .fetch_one(&mut **tx)
    .await?;
    delivery_from_row(row)
}

fn validate_trigger_write(input: &PipelineTriggerWrite) -> Result<(), StoreError> {
    if input.expected_generation < 0 {
        return Err(StoreError::InvalidTriggerIngress(
            "expected trigger generation cannot be negative".to_owned(),
        ));
    }
    validate_digest("implementation_sha256", input.implementation_sha256)?;
    validate_digest("configuration_sha256", input.configuration_sha256)?;
    validate_digest("filter_sha256", input.filter_sha256)?;
    validate_text(
        "event_source_identity",
        &input.event_source_identity,
        MAX_TEXT_BYTES,
    )?;
    validate_text(
        "source_generation",
        &input.source_generation,
        MAX_TEXT_BYTES,
    )?;
    validate_text("actor_subject", &input.actor_subject, MAX_TEXT_BYTES)?;
    validate_text("reason", &input.reason, MAX_REASON_BYTES)?;
    validate_text("idempotency_key", &input.idempotency_key, 256)?;
    validate_object(
        "configuration",
        &input.configuration,
        MAX_CONFIGURATION_BYTES,
    )?;
    if !(1..=MAX_WINDOW_SECONDS).contains(&input.deduplication_window_seconds)
        || !(1..=100).contains(&input.max_delivery_attempts)
        || !(1..=MAX_WINDOW_SECONDS).contains(&input.delivery_ttl_seconds)
    {
        return Err(StoreError::InvalidTriggerIngress(
            "trigger windows and attempt limit are outside their bounds".to_owned(),
        ));
    }
    let canonical = serde_json::to_vec(&input.configuration)
        .map_err(|error| StoreError::InvalidTriggerIngress(error.to_string()))?;
    let actual: [u8; 32] = Sha256::digest(&canonical).into();
    if actual != input.configuration_sha256 {
        return Err(StoreError::InvalidTriggerIngress(
            "configuration SHA-256 does not match canonical JSON".to_owned(),
        ));
    }
    let filter = input.configuration.get("filter").ok_or_else(|| {
        StoreError::InvalidTriggerIngress(
            "trigger configuration requires a filter object".to_owned(),
        )
    })?;
    validate_object("configuration.filter", filter, MAX_CONFIGURATION_BYTES)?;
    let filter_canonical = serde_json::to_vec(filter)
        .map_err(|error| StoreError::InvalidTriggerIngress(error.to_string()))?;
    let actual_filter: [u8; 32] = Sha256::digest(&filter_canonical).into();
    if actual_filter != input.filter_sha256 {
        return Err(StoreError::InvalidTriggerIngress(
            "filter SHA-256 does not match canonical filter JSON".to_owned(),
        ));
    }
    validate_filter_configuration(input.kind, filter)?;
    validate_kind_configuration(input.kind, &input.configuration)
}

fn validate_kind_configuration(kind: TriggerKind, configuration: &Value) -> Result<(), StoreError> {
    let object = configuration.as_object().ok_or_else(|| {
        StoreError::InvalidTriggerIngress("trigger configuration must be an object".to_owned())
    })?;
    let allowed: &[&str] = match kind {
        TriggerKind::ScmWebhook => &["provider", "repository_identity", "filter"],
        TriggerKind::Schedule => &[
            "timezone",
            "calendar",
            "expression",
            "schedule_identity_sha256",
            "resolver_implementation_sha256",
            "resolved_slots_sha256",
            "resolved_slots_unix_ms",
            "jenkins_hash_algorithm_version",
            "jenkins_full_item_name",
            "jenkins_hash_inputs_sha256",
            "filter",
        ],
        TriggerKind::Upstream => &["upstream_pipeline_id", "filter"],
        TriggerKind::RemoteApi => &["audience", "filter"],
        TriggerKind::Plugin => &[],
    };
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(StoreError::InvalidTriggerIngress(format!(
                "unsupported {} trigger configuration field '{key}'",
                kind.as_str()
            )));
        }
    }
    let require_text = |field: &str| -> Result<(), StoreError> {
        let value = configuration
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| {
                StoreError::InvalidTriggerIngress(format!(
                    "{} trigger configuration requires '{field}'",
                    kind.as_str()
                ))
            })?;
        validate_text(field, value, MAX_TEXT_BYTES)
    };
    match kind {
        TriggerKind::ScmWebhook => {
            require_text("provider")?;
            require_text("repository_identity")
        }
        TriggerKind::Schedule => {
            require_text("timezone")?;
            require_text("calendar")?;
            require_text("expression")?;
            require_text("schedule_identity_sha256")?;
            require_text("resolver_implementation_sha256")?;
            require_text("resolved_slots_sha256")?;
            let expression = configuration
                .get("expression")
                .and_then(Value::as_str)
                .expect("required schedule expression was validated");
            if expression.split_ascii_whitespace().count() != 5 {
                return Err(StoreError::InvalidTriggerIngress(
                    "schedule expression must contain exactly five fields".to_owned(),
                ));
            }
            if expression.contains('H') {
                return Err(StoreError::InvalidTriggerIngress(
                    "Jenkins H schedules are ineligible until an exact hash resolver is installed and differentially certified"
                        .to_owned(),
                ));
            }
            for field in [
                "schedule_identity_sha256",
                "resolver_implementation_sha256",
                "resolved_slots_sha256",
            ] {
                parse_configuration_digest(configuration, field)?;
            }
            let resolved_slots = configuration
                .get("resolved_slots_unix_ms")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    StoreError::InvalidTriggerIngress(
                        "schedule configuration requires resolved_slots_unix_ms".to_owned(),
                    )
                })?;
            if resolved_slots.is_empty() || resolved_slots.len() > 4096 {
                return Err(StoreError::InvalidTriggerIngress(
                    "schedule requires between one and 4096 resolved slots".to_owned(),
                ));
            }
            let mut previous = None;
            for value in resolved_slots {
                let slot = value.as_i64().filter(|slot| *slot >= 0).ok_or_else(|| {
                    StoreError::InvalidTriggerIngress(
                        "resolved schedule slots must be non-negative integers".to_owned(),
                    )
                })?;
                if previous.is_some_and(|prior| slot <= prior) {
                    return Err(StoreError::InvalidTriggerIngress(
                        "resolved schedule slots must be strictly increasing".to_owned(),
                    ));
                }
                previous = Some(slot);
            }
            let resolved_canonical = serde_json::to_vec(resolved_slots)
                .map_err(|error| StoreError::InvalidTriggerIngress(error.to_string()))?;
            let expected_slots =
                parse_configuration_digest(configuration, "resolved_slots_sha256")?;
            let actual_slots: [u8; 32] = Sha256::digest(&resolved_canonical).into();
            if actual_slots != expected_slots {
                return Err(StoreError::InvalidTriggerIngress(
                    "resolved_slots_sha256 does not match resolved_slots_unix_ms".to_owned(),
                ));
            }
            let jenkins_hash_fields = [
                "jenkins_hash_algorithm_version",
                "jenkins_full_item_name",
                "jenkins_hash_inputs_sha256",
            ];
            let supplied_hash_fields = jenkins_hash_fields
                .iter()
                .filter(|field| configuration.get(**field).is_some())
                .count();
            if supplied_hash_fields != 0 && supplied_hash_fields != jenkins_hash_fields.len() {
                return Err(StoreError::InvalidTriggerIngress(
                    "Jenkins hash evidence must supply algorithm, full item name, and input digest together"
                        .to_owned(),
                ));
            }
            if supplied_hash_fields == jenkins_hash_fields.len() {
                require_text("jenkins_hash_algorithm_version")?;
                require_text("jenkins_full_item_name")?;
                parse_configuration_digest(configuration, "jenkins_hash_inputs_sha256")?;
            }
            Ok(())
        }
        TriggerKind::Upstream => {
            require_text("upstream_pipeline_id")?;
            let upstream = configuration
                .get("upstream_pipeline_id")
                .and_then(Value::as_str)
                .expect("required upstream identity was validated");
            Uuid::parse_str(upstream).map_err(|_| {
                StoreError::InvalidTriggerIngress("upstream_pipeline_id must be a UUID".to_owned())
            })?;
            Ok(())
        }
        TriggerKind::RemoteApi => require_text("audience"),
        TriggerKind::Plugin => Err(StoreError::InvalidTriggerIngress(
            "plugin trigger class has no installed admitted implementation".to_owned(),
        )),
    }
}

fn validate_filter_configuration(kind: TriggerKind, filter: &Value) -> Result<(), StoreError> {
    let object = filter.as_object().ok_or_else(|| {
        StoreError::InvalidTriggerIngress("trigger filter must be an object".to_owned())
    })?;
    let allowed: &[&str] = match kind {
        TriggerKind::ScmWebhook => &["event_kinds", "branches", "path_prefixes"],
        TriggerKind::Schedule => &["event_kinds"],
        TriggerKind::Upstream => &["event_kinds", "statuses"],
        TriggerKind::RemoteApi => &["event_kinds", "request_methods"],
        TriggerKind::Plugin => &[],
    };
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(StoreError::InvalidTriggerIngress(format!(
                "unsupported {} trigger filter '{key}'",
                kind.as_str()
            )));
        }
    }
    for (field, value) in object {
        let values = value.as_array().ok_or_else(|| {
            StoreError::InvalidTriggerIngress(format!("trigger filter '{field}' must be an array"))
        })?;
        if values.len() > 128 {
            return Err(StoreError::InvalidTriggerIngress(format!(
                "trigger filter '{field}' exceeds 128 entries"
            )));
        }
        let mut seen = std::collections::BTreeSet::new();
        for value in values {
            let value = value.as_str().ok_or_else(|| {
                StoreError::InvalidTriggerIngress(format!(
                    "trigger filter '{field}' contains a non-string"
                ))
            })?;
            validate_text(&format!("filter.{field}"), value, MAX_TEXT_BYTES)?;
            if !seen.insert(value) {
                return Err(StoreError::InvalidTriggerIngress(format!(
                    "trigger filter '{field}' must contain unique values"
                )));
            }
        }
    }
    Ok(())
}

fn parse_configuration_digest(configuration: &Value, field: &str) -> Result<[u8; 32], StoreError> {
    let value = configuration
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            StoreError::InvalidTriggerIngress(format!("trigger configuration requires '{field}'"))
        })?;
    let bytes = hex::decode(value).map_err(|_| {
        StoreError::InvalidTriggerIngress(format!(
            "trigger configuration '{field}' is not hexadecimal"
        ))
    })?;
    let digest: [u8; 32] = bytes.try_into().map_err(|_| {
        StoreError::InvalidTriggerIngress(format!(
            "trigger configuration '{field}' is not SHA-256 sized"
        ))
    })?;
    validate_digest(field, digest)?;
    Ok(digest)
}

fn verify_schedule_configuration(
    slot: &TriggerScheduleSlot,
    configuration: &Value,
) -> Result<(), StoreError> {
    let matches = configuration.get("timezone").and_then(Value::as_str)
        == Some(slot.timezone.as_str())
        && configuration.get("calendar").and_then(Value::as_str) == Some(slot.calendar.as_str())
        && configuration.get("expression").and_then(Value::as_str)
            == Some(slot.expression.as_str())
        && parse_configuration_digest(configuration, "schedule_identity_sha256")?
            == slot.schedule_identity_sha256;
    if !matches {
        return Err(StoreError::TriggerIngressConflict(
            "schedule watermark identity differs from the configured schedule".to_owned(),
        ));
    }
    let resolved_slots = configuration
        .get("resolved_slots_unix_ms")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            StoreError::InvalidTriggerIngress(
                "stored schedule is missing resolved slots".to_owned(),
            )
        })?;
    if resolved_slots
        .binary_search_by_key(&slot.resolved_slot_unix_ms, |value| {
            value.as_i64().unwrap_or(-1)
        })
        .is_err()
    {
        return Err(StoreError::TriggerIngressConflict(
            "resolved schedule slot is outside the configured Jenkins slot set".to_owned(),
        ));
    }
    Ok(())
}

fn schedule_watermark_from_row(
    row: sqlx::postgres::PgRow,
) -> Result<TriggerScheduleWatermark, StoreError> {
    Ok(TriggerScheduleWatermark {
        organization_id: row.try_get("organization_id")?,
        project_id: row.try_get("project_id")?,
        pipeline_id: row.try_get("pipeline_id")?,
        trigger_id: row.try_get("trigger_id")?,
        trigger_generation: row.try_get("trigger_generation")?,
        timezone: row.try_get("timezone")?,
        calendar: row.try_get("calendar")?,
        expression: row.try_get("expression")?,
        schedule_identity_sha256: digest_from_row(&row, "schedule_identity_sha256")?,
        last_resolved_slot_unix_ms: row.try_get("last_resolved_slot_unix_ms")?,
        last_delivery_id: row.try_get("last_delivery_id")?,
    })
}

fn validate_delivery(input: &NewTriggerDelivery) -> Result<(), StoreError> {
    if input.expected_trigger_generation <= 0 {
        return Err(StoreError::InvalidTriggerIngress(
            "expected trigger generation must be positive".to_owned(),
        ));
    }
    validate_text("delivery_id", &input.delivery_id, MAX_TEXT_BYTES)?;
    validate_text("event_id", &input.event_id, MAX_TEXT_BYTES)?;
    validate_text("event_kind", &input.event_kind, 256)?;
    validate_text("caller_identity", &input.caller_identity, MAX_TEXT_BYTES)?;
    validate_digest("payload_sha256", input.payload_sha256)?;
    validate_object(
        "canonical_payload",
        &input.canonical_payload,
        MAX_PAYLOAD_BYTES,
    )?;
    validate_object("parameters", &input.parameters, MAX_CONFIGURATION_BYTES)?;
    validate_text("requested_platform", &input.requested_platform, 128)?;
    validate_text("requested_trust_pool", &input.requested_trust_pool, 128)?;
    if input.event_time_unix_ms < 0 || input.accepted_at_unix_ms < 0 {
        return Err(StoreError::InvalidTriggerIngress(
            "trigger timestamps cannot be negative".to_owned(),
        ));
    }
    let canonical = serde_json::to_vec(&input.canonical_payload)
        .map_err(|error| StoreError::InvalidTriggerIngress(error.to_string()))?;
    let actual: [u8; 32] = Sha256::digest(&canonical).into();
    if actual != input.payload_sha256 {
        return Err(StoreError::InvalidTriggerIngress(
            "payload SHA-256 does not match canonical JSON".to_owned(),
        ));
    }
    Ok(())
}

fn validate_delivery_against_configuration(
    kind: TriggerKind,
    input: &NewTriggerDelivery,
    configuration: &Value,
) -> Result<(), StoreError> {
    let payload = input
        .canonical_payload
        .get("payload")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            StoreError::InvalidTriggerIngress("trigger payload body must be an object".to_owned())
        })?;
    let filter = configuration
        .get("filter")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            StoreError::InvalidTriggerIngress("stored trigger filter is invalid".to_owned())
        })?;
    let allowed_payload: &[&str] = match kind {
        TriggerKind::ScmWebhook => &["repository_identity", "revision", "branch", "paths"],
        TriggerKind::Schedule => &[
            "timezone",
            "calendar",
            "expression",
            "schedule_identity_sha256",
            "expected_last_resolved_slot_unix_ms",
            "resolved_slot_unix_ms",
        ],
        TriggerKind::Upstream => &["upstream_pipeline_id", "upstream_build_id", "status"],
        TriggerKind::RemoteApi => &["audience", "request_id", "request_method"],
        TriggerKind::Plugin => &[],
    };
    for key in payload.keys() {
        if !allowed_payload.contains(&key.as_str()) {
            return Err(StoreError::InvalidTriggerIngress(format!(
                "unsupported {} trigger payload field '{key}'",
                kind.as_str()
            )));
        }
    }
    if !filter_allows(filter, "event_kinds", &input.event_kind)? {
        return Err(StoreError::TriggerIngressConflict(
            "trigger event kind is filtered".to_owned(),
        ));
    }
    let required_payload_text = |field: &str| -> Result<&str, StoreError> {
        let value = payload.get(field).and_then(Value::as_str).ok_or_else(|| {
            StoreError::InvalidTriggerIngress(format!(
                "{} trigger payload requires '{field}'",
                kind.as_str()
            ))
        })?;
        validate_text(field, value, MAX_TEXT_BYTES)?;
        Ok(value)
    };
    match kind {
        TriggerKind::ScmWebhook => {
            let configured = configuration
                .get("repository_identity")
                .and_then(Value::as_str)
                .expect("validated SCM repository identity");
            if required_payload_text("repository_identity")? != configured {
                return Err(StoreError::TriggerIngressConflict(
                    "SCM repository identity was substituted".to_owned(),
                ));
            }
            required_payload_text("revision")?;
            let branch = required_payload_text("branch")?;
            if !filter_allows(filter, "branches", branch)? {
                return Err(StoreError::TriggerIngressConflict(
                    "SCM branch is filtered".to_owned(),
                ));
            }
            if let Some(prefixes) = filter.get("path_prefixes") {
                let prefixes = filter_strings(prefixes, "path_prefixes")?;
                if !prefixes.is_empty() {
                    let paths =
                        payload
                            .get("paths")
                            .and_then(Value::as_array)
                            .ok_or_else(|| {
                                StoreError::InvalidTriggerIngress(
                                    "SCM trigger payload requires paths".to_owned(),
                                )
                            })?;
                    let mut matched = false;
                    for path in paths {
                        let path = path.as_str().ok_or_else(|| {
                            StoreError::InvalidTriggerIngress(
                                "SCM trigger path must be a string".to_owned(),
                            )
                        })?;
                        validate_text("path", path, MAX_TEXT_BYTES)?;
                        matched |= prefixes.iter().any(|prefix| path.starts_with(prefix));
                    }
                    if !matched {
                        return Err(StoreError::TriggerIngressConflict(
                            "SCM path is filtered".to_owned(),
                        ));
                    }
                }
            }
        }
        TriggerKind::Schedule => {
            if input.event_kind != "schedule" {
                return Err(StoreError::TriggerIngressConflict(
                    "schedule trigger requires schedule event kind".to_owned(),
                ));
            }
        }
        TriggerKind::Upstream => {
            let configured = configuration
                .get("upstream_pipeline_id")
                .and_then(Value::as_str)
                .expect("validated upstream configuration");
            if required_payload_text("upstream_pipeline_id")? != configured {
                return Err(StoreError::TriggerIngressConflict(
                    "upstream pipeline identity was substituted".to_owned(),
                ));
            }
            Uuid::parse_str(required_payload_text("upstream_build_id")?).map_err(|_| {
                StoreError::InvalidTriggerIngress(
                    "upstream build identity must be a UUID".to_owned(),
                )
            })?;
            let status = required_payload_text("status")?;
            if !filter_allows(filter, "statuses", status)? {
                return Err(StoreError::TriggerIngressConflict(
                    "upstream result status is filtered".to_owned(),
                ));
            }
        }
        TriggerKind::RemoteApi => {
            let configured = configuration
                .get("audience")
                .and_then(Value::as_str)
                .expect("validated remote API configuration");
            if required_payload_text("audience")? != configured {
                return Err(StoreError::TriggerIngressConflict(
                    "remote-build audience was substituted".to_owned(),
                ));
            }
            if required_payload_text("request_id")? != input.event_id {
                return Err(StoreError::TriggerIngressConflict(
                    "remote-build request identity must equal the durable event identity"
                        .to_owned(),
                ));
            }
            let method = required_payload_text("request_method")?;
            if !filter_allows(filter, "request_methods", method)? {
                return Err(StoreError::TriggerIngressConflict(
                    "remote-build request method is filtered".to_owned(),
                ));
            }
        }
        TriggerKind::Plugin => {
            return Err(StoreError::InvalidTriggerIngress(
                "plugin trigger class has no installed admitted implementation".to_owned(),
            ));
        }
    }
    Ok(())
}

fn filter_allows(
    filter: &serde_json::Map<String, Value>,
    field: &str,
    supplied: &str,
) -> Result<bool, StoreError> {
    let Some(value) = filter.get(field) else {
        return Ok(true);
    };
    let allowed = filter_strings(value, field)?;
    Ok(allowed.is_empty() || allowed.contains(&supplied))
}

fn filter_strings<'a>(value: &'a Value, field: &str) -> Result<Vec<&'a str>, StoreError> {
    value
        .as_array()
        .ok_or_else(|| {
            StoreError::InvalidTriggerIngress(format!("stored trigger filter '{field}' is invalid"))
        })?
        .iter()
        .map(|value| {
            value.as_str().ok_or_else(|| {
                StoreError::InvalidTriggerIngress(format!(
                    "stored trigger filter '{field}' is invalid"
                ))
            })
        })
        .collect()
}

async fn advance_schedule_for_delivery(
    tx: &mut Transaction<'_, Postgres>,
    input: &NewTriggerDelivery,
    trigger_generation: i64,
    slot: &TriggerScheduleSlot,
    configuration: &Value,
) -> Result<(), StoreError> {
    validate_text("timezone", &slot.timezone, 128)?;
    validate_text("calendar", &slot.calendar, 128)?;
    validate_text("expression", &slot.expression, MAX_TEXT_BYTES)?;
    validate_digest("schedule_identity_sha256", slot.schedule_identity_sha256)?;
    if slot.resolved_slot_unix_ms < 0
        || input.event_time_unix_ms != slot.resolved_slot_unix_ms
        || slot
            .expected_last_resolved_slot_unix_ms
            .is_some_and(|previous| previous < 0 || previous >= slot.resolved_slot_unix_ms)
    {
        return Err(StoreError::InvalidTriggerIngress(
            "schedule delivery must bind its exact monotonic resolved slot".to_owned(),
        ));
    }
    verify_schedule_configuration(slot, configuration)?;
    let existing = sqlx::query(
        "SELECT * FROM trigger_schedule_watermarks
         WHERE organization_id = $1 AND trigger_id = $2
           AND trigger_generation = $3
         FOR UPDATE",
    )
    .bind(input.organization_id)
    .bind(input.trigger_id)
    .bind(trigger_generation)
    .fetch_optional(&mut **tx)
    .await?;
    if let Some(row) = existing {
        let current = schedule_watermark_from_row(row)?;
        if current.last_resolved_slot_unix_ms != slot.expected_last_resolved_slot_unix_ms
            || current
                .last_resolved_slot_unix_ms
                .is_some_and(|previous| slot.resolved_slot_unix_ms <= previous)
        {
            return Err(StoreError::TriggerIngressConflict(
                "schedule delivery is duplicate, reordered, or based on a stale watermark"
                    .to_owned(),
            ));
        }
        sqlx::query(
            "UPDATE trigger_schedule_watermarks
             SET last_resolved_slot_unix_ms = $4, last_delivery_id = $5,
                 updated_at = clock_timestamp()
             WHERE organization_id = $1 AND trigger_id = $2
               AND trigger_generation = $3",
        )
        .bind(input.organization_id)
        .bind(input.trigger_id)
        .bind(trigger_generation)
        .bind(slot.resolved_slot_unix_ms)
        .bind(&input.delivery_id)
        .execute(&mut **tx)
        .await?;
    } else {
        if slot.expected_last_resolved_slot_unix_ms.is_some() {
            return Err(StoreError::TriggerIngressConflict(
                "initial schedule delivery expected a prior watermark".to_owned(),
            ));
        }
        sqlx::query(
            "INSERT INTO trigger_schedule_watermarks (
                 organization_id, project_id, pipeline_id, trigger_id,
                 trigger_generation, timezone, calendar, expression,
                 schedule_identity_sha256, last_resolved_slot_unix_ms,
                 last_delivery_id
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(input.organization_id)
        .bind(input.project_id)
        .bind(input.pipeline_id)
        .bind(input.trigger_id)
        .bind(trigger_generation)
        .bind(&slot.timezone)
        .bind(&slot.calendar)
        .bind(&slot.expression)
        .bind(slot.schedule_identity_sha256.as_slice())
        .bind(slot.resolved_slot_unix_ms)
        .bind(&input.delivery_id)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

fn trigger_matches_write(trigger: &PipelineTrigger, input: &PipelineTriggerWrite) -> bool {
    trigger.organization_id == input.organization_id
        && trigger.project_id == input.project_id
        && trigger.pipeline_id == input.pipeline_id
        && trigger.trigger_id == input.trigger_id
        && trigger.kind == input.kind
        && trigger.state == input.state
        && trigger.implementation_sha256 == input.implementation_sha256
        && trigger.configuration_sha256 == input.configuration_sha256
        && trigger.filter_sha256 == input.filter_sha256
        && trigger.event_source_identity == input.event_source_identity
        && trigger.source_generation == input.source_generation
        && trigger.configuration == input.configuration
        && trigger.deduplication_window_seconds == input.deduplication_window_seconds
        && trigger.max_delivery_attempts == input.max_delivery_attempts
        && trigger.delivery_ttl_seconds == input.delivery_ttl_seconds
        && trigger.actor_subject == input.actor_subject
        && trigger.reason == input.reason
        && trigger.idempotency_key == input.idempotency_key
}

fn delivery_matches(delivery: &TriggerDelivery, input: &NewTriggerDelivery) -> bool {
    delivery.organization_id == input.organization_id
        && delivery.project_id == input.project_id
        && delivery.pipeline_id == input.pipeline_id
        && delivery.trigger_id == input.trigger_id
        && delivery.trigger_generation == input.expected_trigger_generation
        && delivery.delivery_id == input.delivery_id
        && delivery.event_id == input.event_id
        && delivery.event_kind == input.event_kind
        && delivery.caller_identity == input.caller_identity
        && delivery.payload_sha256 == input.payload_sha256
        && delivery.canonical_payload == input.canonical_payload
        && delivery.parameters == input.parameters
        && delivery.requested_platform == input.requested_platform
        && delivery.requested_trust_pool == input.requested_trust_pool
        && delivery.event_time_unix_ms == input.event_time_unix_ms
        && schedule_slot_matches_delivery(delivery, input.schedule_slot.as_ref())
}

fn schedule_slot_matches_delivery(
    delivery: &TriggerDelivery,
    schedule_slot: Option<&TriggerScheduleSlot>,
) -> bool {
    let Some(slot) = schedule_slot else {
        return true;
    };
    let identity = hex::encode(slot.schedule_identity_sha256);
    delivery.event_time_unix_ms == slot.resolved_slot_unix_ms
        && delivery
            .canonical_payload
            .get("payload")
            .and_then(|payload| payload.get("schedule_identity_sha256"))
            .and_then(Value::as_str)
            == Some(identity.as_str())
}

fn trigger_from_row(row: sqlx::postgres::PgRow) -> Result<PipelineTrigger, StoreError> {
    Ok(PipelineTrigger {
        organization_id: row.try_get("organization_id")?,
        project_id: row.try_get("project_id")?,
        pipeline_id: row.try_get("pipeline_id")?,
        trigger_id: row.try_get("trigger_id")?,
        generation: row.try_get("current_generation")?,
        kind: TriggerKind::parse(row.try_get("trigger_kind")?)?,
        state: PipelineTriggerState::parse(row.try_get("state")?)?,
        implementation_sha256: digest_from_row(&row, "implementation_sha256")?,
        configuration_sha256: digest_from_row(&row, "configuration_sha256")?,
        filter_sha256: digest_from_row(&row, "filter_sha256")?,
        event_source_identity: row.try_get("event_source_identity")?,
        source_generation: row.try_get("source_generation")?,
        configuration: row.try_get("configuration")?,
        deduplication_window_seconds: row.try_get("deduplication_window_seconds")?,
        max_delivery_attempts: row.try_get("max_delivery_attempts")?,
        delivery_ttl_seconds: row.try_get("delivery_ttl_seconds")?,
        actor_subject: row.try_get("actor_subject")?,
        reason: row.try_get("reason")?,
        idempotency_key: row.try_get("idempotency_key")?,
        audit_sequence: row.try_get("audit_sequence")?,
        audit_event_hash: digest_from_row(&row, "audit_event_hash")?,
    })
}

fn delivery_from_row(row: sqlx::postgres::PgRow) -> Result<TriggerDelivery, StoreError> {
    Ok(TriggerDelivery {
        organization_id: row.try_get("organization_id")?,
        project_id: row.try_get("project_id")?,
        pipeline_id: row.try_get("pipeline_id")?,
        trigger_id: row.try_get("trigger_id")?,
        trigger_generation: row.try_get("trigger_generation")?,
        delivery_id: row.try_get("delivery_id")?,
        event_id: row.try_get("event_id")?,
        event_kind: row.try_get("event_kind")?,
        caller_identity: row.try_get("caller_identity")?,
        payload_sha256: digest_from_row(&row, "payload_sha256")?,
        canonical_payload: row.try_get("canonical_payload")?,
        parameters: row.try_get("parameters")?,
        requested_platform: row.try_get("requested_platform")?,
        requested_trust_pool: row.try_get("requested_trust_pool")?,
        event_time_unix_ms: row.try_get("event_time_unix_ms")?,
        accepted_at_unix_ms: row.try_get("accepted_at_unix_ms")?,
        expires_at_unix_ms: row.try_get("expires_at_unix_ms")?,
        status: TriggerDeliveryStatus::parse(row.try_get("status")?)?,
        attempt_count: row.try_get("attempt_count")?,
        next_attempt_at_unix_ms: row.try_get("next_attempt_at_unix_ms")?,
        claim_owner: row.try_get("claim_owner")?,
        claim_fence: row.try_get("claim_fence")?,
        claim_expires_at_unix_ms: row.try_get("claim_expires_at_unix_ms")?,
        redrive_of_delivery_id: row.try_get("redrive_of_delivery_id")?,
        redrive_ordinal: row.try_get("redrive_ordinal")?,
        build_id: row.try_get("build_id")?,
        terminal_reason: row.try_get("terminal_reason")?,
        audit_sequence: row.try_get("audit_sequence")?,
        audit_event_hash: digest_from_row(&row, "audit_event_hash")?,
    })
}

fn digest_from_row(row: &sqlx::postgres::PgRow, field: &str) -> Result<[u8; 32], StoreError> {
    row.try_get::<Vec<u8>, _>(field)?.try_into().map_err(|_| {
        StoreError::InvalidTriggerIngress(format!("stored {field} is not SHA-256 sized"))
    })
}

async fn lock_trigger_transaction(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    trigger_id: Uuid,
) -> Result<(), StoreError> {
    // Every transaction that can combine trigger, delivery, and pipeline row
    // locks enters through this common scope first. Besides making the row-lock
    // order acyclic, this supplies the missing-key serialization needed for
    // delivery/event identities that PostgreSQL cannot lock before insertion.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("mcloving.trigger.{organization_id}.{trigger_id}"))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

fn validate_text(field: &str, value: &str, maximum: usize) -> Result<(), StoreError> {
    if value.is_empty()
        || value.len() > maximum
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(StoreError::InvalidTriggerIngress(format!(
            "{field} must be non-empty, canonical, and at most {maximum} bytes"
        )));
    }
    Ok(())
}

fn validate_object(field: &str, value: &Value, maximum: usize) -> Result<(), StoreError> {
    if !value.is_object() {
        return Err(StoreError::InvalidTriggerIngress(format!(
            "{field} must be an object"
        )));
    }
    let bytes = serde_json::to_vec(value)
        .map_err(|error| StoreError::InvalidTriggerIngress(error.to_string()))?;
    if bytes.len() > maximum {
        return Err(StoreError::InvalidTriggerIngress(format!(
            "{field} exceeds {maximum} bytes"
        )));
    }
    Ok(())
}

fn validate_digest(field: &str, digest: [u8; 32]) -> Result<(), StoreError> {
    if digest == [0; 32] {
        return Err(StoreError::InvalidTriggerIngress(format!(
            "{field} cannot be all zero"
        )));
    }
    Ok(())
}
