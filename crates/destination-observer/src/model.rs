use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::error::ObserverError;

pub const PROTOCOL_VERSION: &str = "mcloving.destination-observer/v1";
pub const CONFIG_SCHEMA_VERSION: &str = "mcloving.destination-observer-config/v4";
pub const REQUEST_SCHEMA_VERSION: &str = "mcloving.destination-observation-request/v1";
pub const DESTINATION_STATE_SCHEMA_VERSION: &str = "mcloving.destination-state/v1";
pub const RECEIPT_SCHEMA_VERSION: &str = "mcloving.destination-observation-receipt/v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationMode {
    Current,
    Cutover,
    Rollback,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationPhase {
    PreAction,
    PostAction,
    Reconciliation,
}

impl ObservationPhase {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::PreAction => "pre_action",
            Self::PostAction => "post_action",
            Self::Reconciliation => "reconciliation",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidentiality {
    Public,
    Internal,
    Secret,
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
    pub(crate) fn matches(self, value: &Value) -> bool {
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
pub struct StateFieldSchema {
    pub name: String,
    pub kind: JsonKind,
    pub required: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverLimits {
    pub max_response_bytes: usize,
    pub max_header_bytes: usize,
    pub max_requests_per_minute: usize,
    pub max_evidence_bytes: u64,
    pub max_receipts: usize,
    pub max_observations: usize,
    pub timeout_ms: u64,
    pub max_age_ms: i64,
    pub retry_attempts: u8,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverConfig {
    pub schema_version: String,
    pub protocol_version: String,
    pub observer_id: String,
    pub implementation_sha256: String,
    pub image_sha256: String,
    pub deployment_identity: String,
    pub operator_trust_identity: String,
    pub runtime_boundary_identity: String,
    pub service_identity: String,
    pub credential_issuance_path_identity: String,
    pub configuration_authority_identity: String,
    pub request_authority_identity: String,
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
    pub state_schema_version: String,
    pub allowed_query_keys: Vec<String>,
    pub response_schema: Vec<StateFieldSchema>,
    pub read_grant_id: String,
    pub read_grant_version: String,
    pub read_grant_scope: String,
    pub read_grant_expires_unix_ms: i64,
    pub read_token_sha256: String,
    pub request_authority_key_id: String,
    pub request_authority_key_sha256: String,
    pub destination_attestation_key_id: String,
    pub destination_attestation_key_sha256: String,
    pub receipt_signing_key_id: String,
    pub receipt_signing_seed_sha256: String,
    pub receipt_signing_public_key_sha256: String,
    pub secret_marker_set_sha256: String,
    pub denied_peer_identities: Vec<String>,
    pub denied_authority_sha256: Vec<String>,
    pub limits: ObserverLimits,
    pub state_dir: PathBuf,
    #[serde(default)]
    pub ca_bundle_path: Option<PathBuf>,
    #[serde(default)]
    pub ca_bundle_sha256: Option<String>,
    #[serde(default)]
    pub test_allow_http_loopback: bool,
}

impl ObserverConfig {
    pub fn canonical_digest(&self) -> Result<String, ObserverError> {
        crate::crypto::canonical_digest(b"mcloving-observer-config-v1", self)
    }

    pub fn revocation_digest(&self) -> Result<String, ObserverError> {
        let mut revocable = self.clone();
        revocable.denied_authority_sha256.clear();
        crate::crypto::canonical_digest(b"mcloving-observer-config-revocation-v1", &revocable)
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
pub struct ObservationRequest {
    pub schema_version: String,
    pub protocol_version: String,
    pub observation_id: Uuid,
    pub tenant_id: Uuid,
    pub project_id: Uuid,
    pub pipeline_id: Uuid,
    pub build_id: Uuid,
    pub attempt_id: Uuid,
    pub effect_fence: u64,
    pub phase: ObservationPhase,
    pub observer_id: String,
    pub request_authority_identity: String,
    pub expected_implementation_sha256: String,
    pub expected_image_sha256: String,
    pub expected_config_sha256: String,
    pub expected_generation: u64,
    pub activation_mode: ActivationMode,
    pub previous_generation: Option<u64>,
    pub rollback_from_generation: Option<u64>,
    pub endpoint_identity: String,
    pub account_identity: String,
    pub resource_identity: String,
    pub effect_class: String,
    pub read_grant_id: String,
    pub read_grant_version: String,
    pub read_grant_scope: String,
    pub query: BTreeMap<String, String>,
    pub expected_previous_cursor: Option<u64>,
    pub predecessor_receipt_sha256: Option<String>,
    pub requested_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub audit_provenance: String,
    pub authorization: RequestAuthorization,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationStateBody {
    pub schema_version: String,
    pub observation_id: Uuid,
    pub request_sha256: String,
    pub observer_id: String,
    pub service_identity: String,
    pub endpoint_identity: String,
    pub account_identity: String,
    pub resource_identity: String,
    pub effect_class: String,
    pub effect_fence: u64,
    pub phase: ObservationPhase,
    pub canonical_query_sha256: String,
    pub cursor: u64,
    pub observed_at_unix_ms: i64,
    pub state_schema_version: String,
    pub confidentiality: Confidentiality,
    pub state: Value,
    pub grant_id: String,
    pub grant_version: String,
    pub grant_scope: String,
    pub attestation_key_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedDestinationState {
    pub body: DestinationStateBody,
    pub signature_base64: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationReceipt {
    pub schema_version: String,
    pub protocol_version: String,
    pub evidence_sequence: u64,
    pub observation_id: Uuid,
    pub request_sha256: String,
    pub tenant_id: Uuid,
    pub project_id: Uuid,
    pub pipeline_id: Uuid,
    pub build_id: Uuid,
    pub attempt_id: Uuid,
    pub effect_fence: u64,
    pub phase: ObservationPhase,
    pub predecessor_receipt_sha256: Option<String>,
    pub observer_id: String,
    pub observer_implementation_sha256: String,
    pub observer_image_sha256: String,
    pub observer_config_sha256: String,
    pub deployment_identity: String,
    pub operator_trust_identity: String,
    pub runtime_boundary_identity: String,
    pub service_identity: String,
    pub credential_issuance_path_identity: String,
    pub configuration_authority_identity: String,
    pub request_authority_identity: String,
    pub generation: u64,
    pub activation_mode: ActivationMode,
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
    pub destination_cursor: u64,
    pub destination_observed_at_unix_ms: i64,
    pub captured_at_unix_ms: i64,
    pub publication_deadline_unix_ms: i64,
    pub state_schema_version: String,
    pub confidentiality: Confidentiality,
    pub destination_response_sha256: String,
    pub destination_signature_base64: String,
    pub destination_attestation_key_id: String,
    pub state: Value,
    pub retry_count: u8,
    pub audit_provenance: String,
    pub receipt_signing_key_id: String,
    pub receipt_signing_public_key_sha256: String,
    pub signature_base64: String,
}
