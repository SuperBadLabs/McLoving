use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{ConnectorError, canonical_digest};

pub const PROTOCOL_VERSION: &str = "mcloving.external-connector/v1";
pub const CONFIG_SCHEMA_VERSION: &str = "mcloving.external-connector-config/v1";
pub const REQUEST_SCHEMA_VERSION: &str = "mcloving.external-action-request/v1";
pub const DESTINATION_RESPONSE_SCHEMA_VERSION: &str = "mcloving.external-action-response/v1";
pub const OUTCOME_RECEIPT_SCHEMA_VERSION: &str = "mcloving.external-outcome-receipt/v1";
pub const RECONCILE_REQUEST_SCHEMA_VERSION: &str = "mcloving.external-reconcile-request/v1";
pub const SHADOW_REPLAY_SCHEMA_VERSION: &str = "mcloving.external-shadow-replay/v1";
pub const SHADOW_RECEIPT_SCHEMA_VERSION: &str = "mcloving.external-shadow-receipt/v1";
pub const RUNTIME_IMAGE_ATTESTATION_SCHEMA_VERSION: &str = "mcloving.runtime-image-attestation/v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationMode {
    Current,
    Cutover,
    Rollback,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdempotencyClass {
    Idempotent,
    ExternallyIdempotent,
    NonIdempotent,
}

impl IdempotencyClass {
    #[must_use]
    pub const fn retry_safe(self) -> bool {
        !matches!(self, Self::NonIdempotent)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeStatus {
    Succeeded,
    Failed,
    RetryableFailure,
    Ambiguous,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JsonKind {
    Array,
    Boolean,
    Null,
    Number,
    Object,
    String,
}

impl JsonKind {
    #[must_use]
    pub fn matches(self, value: &Value) -> bool {
        match self {
            Self::Array => value.is_array(),
            Self::Boolean => value.is_boolean(),
            Self::Null => value.is_null(),
            Self::Number => value.is_number(),
            Self::Object => value.is_object(),
            Self::String => value.is_string(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorLimits {
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub max_public_output_bytes: usize,
    pub max_receipts: usize,
    pub max_runtime_history: usize,
    pub max_attempts: u8,
    pub timeout_ms: u64,
    pub max_authority_window_ms: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeImageAttestation {
    pub schema_version: String,
    pub workload_kind: String,
    pub workload_identity: String,
    pub implementation_sha256: String,
    pub image_sha256: String,
    pub config_sha256: String,
    pub deployment_identity: String,
    pub runtime_boundary_identity: String,
    pub linux_boot_id: String,
    pub mount_namespace_inode: u64,
    pub cgroup_sha256: String,
    pub issued_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub authority_key_id: String,
    pub signature_base64: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverReceiptBinding {
    pub observer_id: String,
    pub implementation_sha256: String,
    pub image_sha256: String,
    pub config_sha256: String,
    pub deployment_identity: String,
    pub operator_trust_identity: String,
    pub runtime_boundary_identity: String,
    pub service_identity: String,
    pub credential_issuance_path_identity: String,
    pub configuration_authority_identity: String,
    pub request_authority_identity: String,
    pub generation: u64,
    pub activation_mode: mcloving_destination_observer::ActivationMode,
    pub previous_generation: Option<u64>,
    pub rollback_from_generation: Option<u64>,
    pub endpoint_identity: String,
    pub account_identity: String,
    pub resource_identity: String,
    pub effect_class: String,
    pub read_grant_id: String,
    pub read_grant_version: String,
    pub read_grant_scope: String,
    pub canonical_query: BTreeMap<String, String>,
    pub state_schema_version: String,
    pub confidentiality: mcloving_destination_observer::Confidentiality,
    pub destination_attestation_key_id: String,
    pub receipt_signing_key_id: String,
    pub receipt_signing_public_key_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorConfig {
    pub schema_version: String,
    pub protocol_version: String,
    pub connector_id: String,
    pub implementation_sha256: String,
    pub image_sha256: String,
    pub runtime_attestation_authority_key_id: String,
    pub runtime_attestation_authority_key_sha256: String,
    pub deployment_identity: String,
    pub operator_trust_identity: String,
    pub runtime_boundary_identity: String,
    pub service_identity: String,
    pub configuration_authority_identity: String,
    pub request_authority_identity: String,
    pub credential_issuance_path_identity: String,
    pub generation: u64,
    pub activation_mode: ActivationMode,
    pub previous_generation: Option<u64>,
    pub previous_config_sha256: Option<String>,
    pub rollback_from_generation: Option<u64>,
    pub endpoint_url: String,
    pub endpoint_identity: String,
    pub account_identity: String,
    pub resource_identity: String,
    pub effect_class: String,
    pub action_name: String,
    pub action_schema_version: String,
    pub request_payload_schema: BTreeMap<String, JsonKind>,
    pub public_output_schema: BTreeMap<String, JsonKind>,
    pub allowed_secret_taints: BTreeSet<String>,
    pub credential_grant_id: String,
    pub credential_grant_version: String,
    pub credential_grant_scope: String,
    pub credential_grant_expires_unix_ms: i64,
    pub credential_token_sha256: String,
    pub request_authority_key_id: String,
    pub request_authority_key_sha256: String,
    pub destination_attestation_key_id: String,
    pub destination_attestation_key_sha256: String,
    pub outcome_signing_key_id: String,
    pub outcome_signing_seed_sha256: String,
    pub outcome_signing_public_key_sha256: String,
    pub observer_binding: ObserverReceiptBinding,
    pub denied_peer_identities: Vec<String>,
    pub denied_authority_sha256: Vec<String>,
    pub limits: ConnectorLimits,
    pub state_dir: PathBuf,
    #[serde(default)]
    pub ca_bundle_path: Option<PathBuf>,
    #[serde(default)]
    pub ca_bundle_sha256: Option<String>,
    #[serde(default)]
    pub test_allow_http_loopback: bool,
}

impl ConnectorConfig {
    pub fn canonical_digest(&self) -> Result<String, ConnectorError> {
        canonical_digest(b"mcloving-external-connector-config-v1", self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestAuthorization {
    pub key_id: String,
    pub signature_base64: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActionRequest {
    pub schema_version: String,
    pub protocol_version: String,
    pub request_id: Uuid,
    pub tenant_id: Uuid,
    pub project_id: Uuid,
    pub pipeline_id: Uuid,
    pub build_id: Uuid,
    pub attempt_id: Uuid,
    pub effect_fence: u64,
    pub effect_key: String,
    pub connector_id: String,
    pub expected_implementation_sha256: String,
    pub expected_image_sha256: String,
    pub expected_config_sha256: String,
    pub expected_generation: u64,
    pub endpoint_identity: String,
    pub account_identity: String,
    pub resource_identity: String,
    pub effect_class: String,
    pub idempotency_class: IdempotencyClass,
    pub action_name: String,
    pub action_schema_version: String,
    pub request_payload: Value,
    pub credential_grant_id: String,
    pub credential_grant_version: String,
    pub credential_grant_scope: String,
    pub requested_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub audit_provenance: String,
    pub authorization: RequestAuthorization,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedSecretRef {
    pub provider_identity: String,
    pub reference: String,
    pub version: String,
    pub taint: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationActionEnvelope {
    pub protocol_version: String,
    pub connector_id: String,
    pub connector_config_sha256: String,
    pub request_sha256: String,
    pub request: ActionRequest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationOutcomeBody {
    pub schema_version: String,
    pub request_id: Uuid,
    pub request_sha256: String,
    pub connector_id: String,
    pub service_identity: String,
    pub endpoint_identity: String,
    pub account_identity: String,
    pub resource_identity: String,
    pub effect_class: String,
    pub effect_fence: u64,
    pub action_name: String,
    pub status: OutcomeStatus,
    pub status_code: String,
    pub public_values: BTreeMap<String, Value>,
    pub protected_secret_refs: Vec<ProtectedSecretRef>,
    pub external_ids: BTreeMap<String, String>,
    pub downstream_control_digest: String,
    pub later_intents_digest: String,
    pub completed_at_unix_ms: i64,
    pub credential_grant_id: String,
    pub credential_grant_version: String,
    pub credential_grant_scope: String,
    pub attestation_key_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedDestinationOutcome {
    pub body: DestinationOutcomeBody,
    pub signature_base64: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeReceipt {
    pub schema_version: String,
    pub protocol_version: String,
    pub evidence_sequence: u64,
    pub request_id: Uuid,
    pub request_sha256: String,
    pub tenant_id: Uuid,
    pub project_id: Uuid,
    pub pipeline_id: Uuid,
    pub build_id: Uuid,
    pub attempt_id: Uuid,
    pub effect_fence: u64,
    pub effect_key: String,
    pub connector_id: String,
    pub connector_implementation_sha256: String,
    pub connector_image_sha256: String,
    pub connector_config_sha256: String,
    pub deployment_identity: String,
    pub operator_trust_identity: String,
    pub runtime_boundary_identity: String,
    pub service_identity: String,
    pub configuration_authority_identity: String,
    pub request_authority_identity: String,
    pub credential_issuance_path_identity: String,
    pub generation: u64,
    pub activation_mode: ActivationMode,
    pub previous_generation: Option<u64>,
    pub previous_config_sha256: Option<String>,
    pub rollback_from_generation: Option<u64>,
    pub endpoint_identity: String,
    pub account_identity: String,
    pub resource_identity: String,
    pub effect_class: String,
    pub idempotency_class: IdempotencyClass,
    pub action_name: String,
    pub action_schema_version: String,
    pub credential_grant_id: String,
    pub credential_grant_version: String,
    pub credential_grant_scope: String,
    pub request_payload_sha256: String,
    pub status: OutcomeStatus,
    pub status_code: String,
    pub public_values: BTreeMap<String, Value>,
    pub protected_secret_refs: Vec<ProtectedSecretRef>,
    pub external_ids: BTreeMap<String, String>,
    pub downstream_control_digest: String,
    pub later_intents_digest: String,
    pub destination_response_sha256: Option<String>,
    pub destination_signature_base64: Option<String>,
    pub destination_attestation_key_id: Option<String>,
    pub attempt_count: u8,
    pub ambiguous_requires_observation: bool,
    pub observation_receipt_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispatched_at_unix_ms: Option<i64>,
    pub captured_at_unix_ms: i64,
    pub audit_provenance: String,
    pub outcome_signing_key_id: String,
    pub outcome_signing_public_key_sha256: String,
    pub signature_base64: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorReceiptBinding {
    pub connector_id: String,
    pub implementation_sha256: String,
    pub image_sha256: String,
    pub config_sha256: String,
    pub deployment_identity: String,
    pub operator_trust_identity: String,
    pub runtime_boundary_identity: String,
    pub service_identity: String,
    pub configuration_authority_identity: String,
    pub request_authority_identity: String,
    pub credential_issuance_path_identity: String,
    pub generation: u64,
    pub activation_mode: ActivationMode,
    pub previous_generation: Option<u64>,
    pub previous_config_sha256: Option<String>,
    pub rollback_from_generation: Option<u64>,
    pub endpoint_identity: String,
    pub account_identity: String,
    pub resource_identity: String,
    pub effect_class: String,
    pub action_name: String,
    pub action_schema_version: String,
    pub credential_grant_id: String,
    pub credential_grant_version: String,
    pub credential_grant_scope: String,
    pub outcome_signing_key_id: String,
    pub outcome_signing_public_key_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconcileRequest {
    pub schema_version: String,
    pub request_id: Uuid,
    pub expected_request_sha256: String,
    pub expected_ambiguous_receipt_sha256: String,
    pub observed_effect: bool,
    pub observation_receipt: mcloving_destination_observer::ObservationReceipt,
    pub audit_provenance: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowReplayConfig {
    pub schema_version: String,
    pub shadow_identity: String,
    pub replay_authority_identity: String,
    pub implementation_sha256: String,
    pub image_sha256: String,
    pub deployment_identity: String,
    pub runtime_boundary_identity: String,
    pub runtime_attestation_authority_key_id: String,
    pub runtime_attestation_authority_key_sha256: String,
    pub connector_binding: ConnectorReceiptBinding,
    pub connector_receipt_key_sha256: String,
    pub replay_signing_key_id: String,
    pub replay_signing_seed_sha256: String,
    pub replay_signing_public_key_sha256: String,
    pub denied_endpoint_identities: BTreeSet<String>,
    pub max_receipts: usize,
    pub state_dir: PathBuf,
}

impl ShadowReplayConfig {
    pub fn canonical_digest(&self) -> Result<String, ConnectorError> {
        canonical_digest(b"mcloving-external-shadow-config-v1", self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowReplayRequest {
    pub schema_version: String,
    pub replay_id: Uuid,
    pub expected_outcome_receipt_sha256: String,
    pub expected_shadow_identity: String,
    pub outcome_receipt: OutcomeReceipt,
    pub replayed_at_unix_ms: i64,
    pub audit_provenance: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowReplayReceipt {
    pub schema_version: String,
    pub replay_id: Uuid,
    pub outcome_receipt_sha256: String,
    pub request_id: Uuid,
    pub tenant_id: Uuid,
    pub project_id: Uuid,
    pub build_id: Uuid,
    pub attempt_id: Uuid,
    pub effect_fence: u64,
    pub effect_key: String,
    pub shadow_identity: String,
    pub replay_authority_identity: String,
    pub status: OutcomeStatus,
    pub status_code: String,
    pub public_values: BTreeMap<String, Value>,
    pub protected_secret_refs: Vec<ProtectedSecretRef>,
    pub external_ids: BTreeMap<String, String>,
    pub downstream_control_digest: String,
    pub later_intents_digest: String,
    pub replayed_at_unix_ms: i64,
    pub audit_provenance: String,
    pub replay_signing_key_id: String,
    pub replay_signing_public_key_sha256: String,
    pub signature_base64: String,
}
