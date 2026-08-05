//! Scoped, out-of-process dynamic-agent provisioning boundary.
//!
//! The standalone provisioner owns only one certified provider/account/region
//! and one immutable agent class. It durably records intent before contacting
//! the provider, uses request identifiers as provider idempotency keys, fences
//! every build attempt, and retains signed lifecycle evidence through cleanup.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use hmac::{Hmac, Mac};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use ring::signature::{ED25519, UnparsedPublicKey};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

struct DuplicateRejectingSeed;

impl<'de> DeserializeSeed<'de> for DuplicateRejectingSeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateRejectingVisitor)
    }
}

struct DuplicateRejectingVisitor;

impl<'de> Visitor<'de> for DuplicateRejectingVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON without duplicate object members")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        DuplicateRejectingSeed.deserialize(deserializer)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        DuplicateRejectingSeed.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence
            .next_element_seed(DuplicateRejectingSeed)?
            .is_some()
        {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut members = HashSet::new();
        while let Some(member) = map.next_key::<String>()? {
            if !members.insert(member) {
                return Err(A::Error::custom("duplicate JSON object member"));
            }
            map.next_value_seed(DuplicateRejectingSeed)?;
        }
        Ok(())
    }
}

pub const PROTOCOL_VERSION: &str = "mcloving.provisioner.v1";
const MAX_BINDING_BYTES: usize = 256;
const MAX_AUDIT_BYTES: usize = 2_048;
const MAX_PROVIDER_RESPONSE_BYTES: usize = 256 * 1_024;
const MAX_CA_BUNDLE_BYTES: usize = 1024 * 1024;
const MAX_PROVIDER_INSTANCES: usize = 2_000;
const MAX_COMMAND_WINDOW_MS: i64 = 5 * 60 * 1_000;
const MAX_CLOCK_SKEW_MS: i64 = 5_000;
const MAX_INSTANCE_LIFETIME_MS: i64 = 24 * 60 * 60 * 1_000;
const MAX_STARTUP_TIMEOUT_MS: u64 = 15 * 60 * 1_000;
const MAX_PROVIDER_TIMEOUT_MS: u64 = 60 * 1_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    pub policy_id: String,
    pub policy_sha256: String,
    pub allow_ingress: bool,
    pub allow_instance_metadata: bool,
    pub egress_allowlist: BTreeSet<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeGrant {
    pub volume_class: String,
    pub mount_path: String,
    pub read_only: bool,
    pub max_bytes: u64,
    pub destroy_on_release: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VolumePolicy {
    pub policy_id: String,
    pub policy_sha256: String,
    pub allow_host_mounts: bool,
    pub grants: Vec<VolumeGrant>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspacePolicy {
    pub policy_id: String,
    pub policy_sha256: String,
    pub max_bytes: u64,
    pub encrypted: bool,
    pub ephemeral: bool,
    pub destroy_on_release: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheMode {
    Disabled,
    ReadOnly,
    IsolatedReadWrite,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CachePolicy {
    pub policy_id: String,
    pub policy_sha256: String,
    pub mode: CacheMode,
    pub namespace: Option<String>,
    pub max_bytes: u64,
    pub trust_class: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSpecification {
    pub agent_class_id: String,
    pub template_id: String,
    pub template_sha256: String,
    pub image_id: String,
    pub image_sha256: String,
    pub bootstrap_sha256: String,
    pub toolchain_sha256: String,
    pub platform: String,
    pub capabilities: BTreeSet<String>,
    pub trust_pool: String,
    pub network: NetworkPolicy,
    pub volumes: VolumePolicy,
    pub workspace: WorkspacePolicy,
    pub cache: CachePolicy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceIdentityPolicy {
    pub issuer: String,
    pub audience: String,
    pub role: String,
    pub iam_policy_sha256: String,
    pub max_ttl_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaPolicy {
    pub max_active_global: u32,
    pub max_active_per_tenant: u32,
    pub max_active_per_project: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisionerConfig {
    pub protocol_version: String,
    pub provisioner_id: String,
    pub implementation_id: String,
    pub deployment_identity: String,
    pub operator_identity: String,
    pub generation: u64,
    pub provider_id: String,
    pub provider_endpoint: String,
    pub provider_endpoint_identity: String,
    pub provider_account_id: String,
    pub provider_region: String,
    pub provider_api_version: String,
    pub provider_grant_id: String,
    pub provider_grant_scope: String,
    pub provider_grant_expires_unix_ms: i64,
    pub provider_token_sha256: String,
    pub provider_attestation_key_id: String,
    pub provider_attestation_key_sha256: String,
    pub receipt_signing_key_id: String,
    pub receipt_signing_key_sha256: String,
    pub agent: AgentSpecification,
    pub instance_identity: InstanceIdentityPolicy,
    pub quotas: QuotaPolicy,
    pub provider_timeout_ms: u64,
    pub startup_timeout_ms: u64,
    pub startup_poll_interval_ms: u64,
    pub max_instance_lifetime_ms: u64,
    pub state_dir: PathBuf,
    #[serde(default)]
    pub ca_bundle_path: Option<PathBuf>,
    #[serde(default)]
    pub ca_bundle_sha256: Option<String>,
    #[serde(default)]
    pub test_allow_http_loopback: bool,
}

impl ProvisionerConfig {
    pub fn canonical_digest(&self) -> Result<String, ProvisionerError> {
        canonical_digest(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationMode {
    Current,
    Cutover,
    Rollback,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisionRequest {
    pub request_id: Uuid,
    pub tenant_id: Uuid,
    pub project_id: Uuid,
    pub build_id: Uuid,
    pub attempt_id: Uuid,
    pub fence_token: u64,
    pub provisioner_id: String,
    pub expected_implementation_sha256: String,
    pub expected_config_sha256: String,
    pub expected_generation: u64,
    pub activation_mode: ActivationMode,
    pub previous_generation: Option<u64>,
    pub provider_id: String,
    pub provider_endpoint_identity: String,
    pub provider_account_id: String,
    pub provider_region: String,
    pub provider_grant_id: String,
    pub provider_grant_scope: String,
    pub agent: AgentSpecification,
    pub requested_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub instance_expires_at_unix_ms: i64,
    pub audit_lineage: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CancelRequest {
    pub request_id: Uuid,
    pub tenant_id: Uuid,
    pub project_id: Uuid,
    pub build_id: Uuid,
    pub attempt_id: Uuid,
    pub fence_token: u64,
    pub expected_request_sha256: String,
    pub expected_implementation_sha256: String,
    pub expected_config_sha256: String,
    pub expected_generation: u64,
    pub requested_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub reason: String,
    pub audit_lineage: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconcileRequest {
    pub reconciliation_id: Uuid,
    pub expected_implementation_sha256: String,
    pub expected_config_sha256: String,
    pub expected_generation: u64,
    pub requested_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub audit_lineage: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Provision { request: Box<ProvisionRequest> },
    Cancel { request: CancelRequest },
    Reconcile { request: ReconcileRequest },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCreateRequest {
    pub protocol_version: String,
    pub provisioner_id: String,
    pub provisioner_config_sha256: String,
    pub request_sha256: String,
    pub request: ProvisionRequest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceIdentity {
    pub instance_subject: String,
    pub issuer: String,
    pub audience: String,
    pub role: String,
    pub iam_policy_sha256: String,
    pub grant_id: String,
    pub issued_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderInstanceState {
    Pending,
    Ready,
    StartupFailed,
    AgentLost,
    Deleting,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderInstance {
    pub instance_id: Uuid,
    pub create: ProviderCreateRequest,
    pub effective_agent: AgentSpecification,
    pub identity: InstanceIdentity,
    pub state: ProviderInstanceState,
    pub created_at_unix_ms: i64,
    pub observed_at_unix_ms: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderLookup {
    pub request_id: Uuid,
    pub observed_at_unix_ms: i64,
    pub instance: Option<ProviderInstance>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderInventory {
    pub provisioner_id: String,
    pub complete: bool,
    pub observed_at_unix_ms: i64,
    pub instances: Vec<ProviderInstance>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupReason {
    Cancelled,
    Expired,
    StartupFailed,
    StartupTimeout,
    AgentLost,
    Substitution,
    Orphan,
    Superseded,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderDeleteRequest {
    pub protocol_version: String,
    pub provisioner_id: String,
    pub provisioner_config_sha256: String,
    pub request_id: Uuid,
    pub instance_id: Uuid,
    pub tenant_id: Uuid,
    pub project_id: Uuid,
    pub build_id: Uuid,
    pub attempt_id: Uuid,
    pub fence_token: u64,
    pub reason: CleanupReason,
    pub requested_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderDeleteResult {
    pub request_id: Uuid,
    pub instance_id: Uuid,
    pub absent: bool,
    pub observed_at_unix_ms: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedProviderEnvelope<T> {
    pub protocol_version: String,
    pub provider_id: String,
    pub provider_endpoint_identity: String,
    pub provider_account_id: String,
    pub provider_region: String,
    pub provider_api_version: String,
    pub attestation_key_id: String,
    pub payload: T,
    pub signature: String,
}

#[derive(Serialize)]
struct ProviderEnvelopeBody<'a, T> {
    protocol_version: &'a str,
    provider_id: &'a str,
    provider_endpoint_identity: &'a str,
    provider_account_id: &'a str,
    provider_region: &'a str,
    provider_api_version: &'a str,
    attestation_key_id: &'a str,
    payload: &'a T,
}

/// Canonical bytes signed by the contained or production provider.
pub fn provider_attestation_message<T: Serialize>(
    envelope: &SignedProviderEnvelope<T>,
) -> Result<Vec<u8>, ProvisionerError> {
    canonical_json(&ProviderEnvelopeBody {
        protocol_version: &envelope.protocol_version,
        provider_id: &envelope.provider_id,
        provider_endpoint_identity: &envelope.provider_endpoint_identity,
        provider_account_id: &envelope.provider_account_id,
        provider_region: &envelope.provider_region,
        provider_api_version: &envelope.provider_api_version,
        attestation_key_id: &envelope.attestation_key_id,
        payload: &envelope.payload,
    })
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleOutcome {
    Ready,
    CreateAmbiguous,
    Cancelled,
    ExpiredCleaned,
    StartupFailedCleaned,
    StartupTimeoutCleaned,
    AgentLostCleaned,
    SubstitutionDeniedCleaned,
    ReconciliationRequired,
}

fn cleanup_directive(outcome: LifecycleOutcome) -> Option<(CleanupReason, LifecycleOutcome)> {
    match outcome {
        LifecycleOutcome::Cancelled => {
            Some((CleanupReason::Cancelled, LifecycleOutcome::Cancelled))
        }
        LifecycleOutcome::ExpiredCleaned => {
            Some((CleanupReason::Expired, LifecycleOutcome::ExpiredCleaned))
        }
        LifecycleOutcome::StartupFailedCleaned => Some((
            CleanupReason::StartupFailed,
            LifecycleOutcome::StartupFailedCleaned,
        )),
        LifecycleOutcome::StartupTimeoutCleaned => Some((
            CleanupReason::StartupTimeout,
            LifecycleOutcome::StartupTimeoutCleaned,
        )),
        LifecycleOutcome::AgentLostCleaned => {
            Some((CleanupReason::AgentLost, LifecycleOutcome::AgentLostCleaned))
        }
        LifecycleOutcome::SubstitutionDeniedCleaned => Some((
            CleanupReason::Substitution,
            LifecycleOutcome::SubstitutionDeniedCleaned,
        )),
        LifecycleOutcome::Ready
        | LifecycleOutcome::CreateAmbiguous
        | LifecycleOutcome::ReconciliationRequired => None,
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleReceiptBody {
    pub protocol_version: String,
    pub receipt_sequence: u64,
    pub outcome: LifecycleOutcome,
    pub request_id: Uuid,
    pub request_sha256: String,
    pub tenant_id: Uuid,
    pub project_id: Uuid,
    pub build_id: Uuid,
    pub attempt_id: Uuid,
    pub fence_token: u64,
    pub provisioner_id: String,
    pub provisioner_implementation_sha256: String,
    pub provisioner_config_sha256: String,
    pub request_expected_implementation_sha256: String,
    pub request_expected_config_sha256: String,
    pub request_expected_generation: u64,
    pub deployment_identity: String,
    pub operator_identity: String,
    pub generation: u64,
    pub activation_mode: ActivationMode,
    pub previous_generation: Option<u64>,
    pub provider_id: String,
    pub provider_endpoint_identity: String,
    pub provider_account_id: String,
    pub provider_region: String,
    pub provider_grant_id: String,
    pub agent: AgentSpecification,
    pub instance_id: Option<Uuid>,
    pub instance_identity: Option<InstanceIdentity>,
    pub requested_at_unix_ms: i64,
    pub instance_expires_at_unix_ms: i64,
    pub observed_at_unix_ms: i64,
    pub cleanup_confirmed: bool,
    pub ambiguity: bool,
    pub audit_lineage: String,
    pub signing_key_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleReceipt {
    #[serde(flatten)]
    pub body: LifecycleReceiptBody,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconcileReceiptBody {
    pub protocol_version: String,
    pub reconciliation_id: Uuid,
    pub provisioner_id: String,
    pub provisioner_implementation_sha256: String,
    pub provisioner_config_sha256: String,
    pub generation: u64,
    pub provider_id: String,
    pub provider_account_id: String,
    pub provider_region: String,
    pub observed_at_unix_ms: i64,
    pub active_ready: u32,
    pub recovered: u32,
    pub cleaned: u32,
    pub orphan_cleaned: u32,
    pub ambiguous: u32,
    pub escaped_compute_remaining: u32,
    pub initial_inventory_sha256: String,
    pub final_inventory_sha256: String,
    pub active_instance_ids: BTreeSet<Uuid>,
    pub cleaned_request_ids: BTreeSet<Uuid>,
    pub orphan_instance_ids: BTreeSet<Uuid>,
    pub ambiguous_request_ids: BTreeSet<Uuid>,
    pub audit_lineage: String,
    pub signing_key_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconcileReceipt {
    #[serde(flatten)]
    pub body: ReconcileReceiptBody,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "receipt_type", rename_all = "snake_case")]
pub enum Receipt {
    Lifecycle { receipt: Box<LifecycleReceipt> },
    Reconcile { receipt: Box<ReconcileReceipt> },
}

#[derive(Debug, Error)]
pub enum ProvisionerError {
    #[error("provisioner configuration is invalid")]
    InvalidConfig,
    #[error("request does not match the certified provisioner configuration")]
    BindingMismatch,
    #[error("request is expired or outside its bounded time window")]
    ExpiredRequest,
    #[error("provider grant is expired")]
    ExpiredGrant,
    #[error("request identifier was replayed with different bound content")]
    ReplayMismatch,
    #[error("attempt fence is stale or reordered")]
    StaleFence,
    #[error("a newer fence requires cleanup before another instance can be admitted")]
    CleanupRequired,
    #[error("certified capacity is exhausted")]
    CapacityExhausted,
    #[error("provider denied the scoped grant")]
    ProviderUnauthorized,
    #[error("provider response is malformed, incomplete, or unauthenticated")]
    InvalidProviderResponse,
    #[error("provider lifecycle operation is ambiguous and requires reconciliation")]
    ReconciliationRequired,
    #[error("stored provisioner state or evidence is unavailable")]
    StateUnavailable,
    #[error("stored receipt failed integrity verification")]
    InvalidStoredReceipt,
}

impl ProvisionerError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidConfig => "invalid_config",
            Self::BindingMismatch => "binding_mismatch",
            Self::ExpiredRequest => "expired_request",
            Self::ExpiredGrant => "expired_grant",
            Self::ReplayMismatch => "replay_mismatch",
            Self::StaleFence => "stale_fence",
            Self::CleanupRequired => "cleanup_required",
            Self::CapacityExhausted => "capacity_exhausted",
            Self::ProviderUnauthorized => "provider_unauthorized",
            Self::InvalidProviderResponse => "invalid_provider_response",
            Self::ReconciliationRequired => "reconciliation_required",
            Self::StateUnavailable => "state_unavailable",
            Self::InvalidStoredReceipt => "invalid_stored_receipt",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StoredState {
    Intent,
    Ambiguous,
    Pending,
    Ready,
    Deleting,
    Deleted,
    Failed,
}

impl StoredState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Intent => "intent",
            Self::Ambiguous => "ambiguous",
            Self::Pending => "pending",
            Self::Ready => "ready",
            Self::Deleting => "deleting",
            Self::Deleted => "deleted",
            Self::Failed => "failed",
        }
    }

    fn parse(value: &str) -> Result<Self, ProvisionerError> {
        match value {
            "intent" => Ok(Self::Intent),
            "ambiguous" => Ok(Self::Ambiguous),
            "pending" => Ok(Self::Pending),
            "ready" => Ok(Self::Ready),
            "deleting" => Ok(Self::Deleting),
            "deleted" => Ok(Self::Deleted),
            "failed" => Ok(Self::Failed),
            _ => Err(ProvisionerError::StateUnavailable),
        }
    }
}

#[derive(Clone, Debug)]
struct StoredRequest {
    request: ProvisionRequest,
    request_sha256: String,
    state: StoredState,
    instance: Option<ProviderInstance>,
    latest_receipt: Option<LifecycleReceipt>,
    updated_at_unix_ms: i64,
}

struct LifecycleEvidence<'a> {
    request_sha256: &'a str,
    instance: Option<&'a ProviderInstance>,
    outcome: LifecycleOutcome,
    cleanup_confirmed: bool,
    ambiguity: bool,
    audit_lineage: &'a str,
    observed_at_unix_ms: i64,
}

#[derive(Serialize)]
struct LedgerScopeBinding<'a> {
    protocol_version: &'a str,
    provisioner_id: &'a str,
    provider_id: &'a str,
    provider_endpoint: &'a str,
    provider_endpoint_identity: &'a str,
    provider_account_id: &'a str,
    provider_region: &'a str,
    provider_api_version: &'a str,
    provider_grant_scope: &'a str,
    provider_attestation_key_id: &'a str,
    provider_attestation_key_sha256: &'a str,
    agent: &'a AgentSpecification,
    instance_identity: &'a InstanceIdentityPolicy,
}

pub struct Provisioner {
    config: ProvisionerConfig,
    config_sha256: String,
    implementation_sha256: String,
    provider_public_key: Vec<u8>,
    receipt_signing_key: Vec<u8>,
    provider_authorization: HeaderValue,
    provisioner_id_header: HeaderValue,
    provider_grant_id_header: HeaderValue,
    provider_grant_scope_header: HeaderValue,
    client: reqwest::Client,
    endpoint: Url,
    database_path: PathBuf,
}

impl Provisioner {
    pub async fn new(
        config: ProvisionerConfig,
        implementation_sha256: String,
        provider_token: String,
        provider_public_key: Vec<u8>,
        receipt_signing_key: Vec<u8>,
    ) -> Result<Self, ProvisionerError> {
        validate_config(
            &config,
            &implementation_sha256,
            &provider_token,
            &provider_public_key,
            &receipt_signing_key,
        )?;
        let endpoint = validate_endpoint(&config)?;
        let provider_authorization = bearer(&provider_token)?;
        let provisioner_id_header = request_header(&config.provisioner_id)?;
        let provider_grant_id_header = request_header(&config.provider_grant_id)?;
        let provider_grant_scope_header = request_header(&config.provider_grant_scope)?;
        prepare_private_state_dir(&config.state_dir)?;
        let database_path = config.state_dir.join("provisioner.sqlite3");
        prepare_private_database_file(&database_path)?;

        let mut builder = reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(config.provider_timeout_ms))
            .timeout(Duration::from_millis(config.provider_timeout_ms))
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .user_agent(PROTOCOL_VERSION);
        if let Some(path) = &config.ca_bundle_path {
            let pem = read_bounded_regular_file(path, MAX_CA_BUNDLE_BYTES).await?;
            if Some(content_sha256(&pem)) != config.ca_bundle_sha256 {
                return Err(ProvisionerError::InvalidConfig);
            }
            let certificates = reqwest::Certificate::from_pem_bundle(&pem)
                .map_err(|_| ProvisionerError::InvalidConfig)?;
            if certificates.is_empty() {
                return Err(ProvisionerError::InvalidConfig);
            }
            builder = builder.tls_built_in_root_certs(false);
            for certificate in certificates {
                builder = builder.add_root_certificate(certificate);
            }
        }
        let client = builder
            .build()
            .map_err(|_| ProvisionerError::InvalidConfig)?;
        let config_sha256 = config.canonical_digest()?;
        let ledger_scope_sha256 = ledger_scope_digest(&config)?;
        initialize_database(
            &database_path,
            &config.provisioner_id,
            &ledger_scope_sha256,
            &implementation_sha256,
            &config_sha256,
            config.generation,
        )?;

        Ok(Self {
            config,
            config_sha256,
            implementation_sha256,
            provider_public_key,
            receipt_signing_key,
            provider_authorization,
            provisioner_id_header,
            provider_grant_id_header,
            provider_grant_scope_header,
            client,
            endpoint,
            database_path,
        })
    }

    #[must_use]
    pub fn config_sha256(&self) -> &str {
        &self.config_sha256
    }

    #[must_use]
    pub fn implementation_sha256(&self) -> &str {
        &self.implementation_sha256
    }

    pub async fn execute(&self, command: &Command) -> Result<Receipt, ProvisionerError> {
        match command {
            Command::Provision { request } => {
                self.provision(request)
                    .await
                    .map(|receipt| Receipt::Lifecycle {
                        receipt: Box::new(receipt),
                    })
            }
            Command::Cancel { request } => {
                self.cancel(request)
                    .await
                    .map(|receipt| Receipt::Lifecycle {
                        receipt: Box::new(receipt),
                    })
            }
            Command::Reconcile { request } => {
                self.reconcile(request)
                    .await
                    .map(|receipt| Receipt::Reconcile {
                        receipt: Box::new(receipt),
                    })
            }
        }
    }

    pub async fn provision(
        &self,
        request: &ProvisionRequest,
    ) -> Result<LifecycleReceipt, ProvisionerError> {
        let now = now_unix_ms()?;
        self.validate_provision_request(request, now)?;
        let request_sha256 = canonical_digest(request)?;
        let startup_deadline = self.startup_deadline(request, now)?;

        if let Some(stored) = self.admit_or_load(request, &request_sha256, now)? {
            if let Some(receipt) = stored.latest_receipt {
                self.verify_lifecycle_receipt(&receipt)?;
                return Ok(receipt);
            }
            return self
                .wait_for_peer_or_recover(stored, &request.audit_lineage)
                .await;
        }

        let create = ProviderCreateRequest {
            protocol_version: PROTOCOL_VERSION.to_owned(),
            provisioner_id: self.config.provisioner_id.clone(),
            provisioner_config_sha256: self.config_sha256.clone(),
            request_sha256: request_sha256.clone(),
            request: request.clone(),
        };
        let instance = match self.provider_create(&create).await {
            Ok(instance) => instance,
            Err(ProvisionerError::ProviderUnauthorized) => {
                self.set_state(request.request_id, StoredState::Failed, None, now)?;
                return Err(ProvisionerError::ProviderUnauthorized);
            }
            Err(_) => {
                self.set_state(request.request_id, StoredState::Ambiguous, None, now)?;
                return self.append_lifecycle_receipt(
                    request,
                    LifecycleEvidence {
                        request_sha256: &request_sha256,
                        instance: None,
                        outcome: LifecycleOutcome::CreateAmbiguous,
                        cleanup_confirmed: false,
                        ambiguity: true,
                        audit_lineage: &request.audit_lineage,
                        observed_at_unix_ms: now,
                    },
                );
            }
        };

        let now = now_unix_ms()?;
        if !self.set_state_from(
            request.request_id,
            StoredState::Intent,
            StoredState::Pending,
            Some(&instance),
            now,
        )? {
            return self
                .recover_create_admission_race(request, &request_sha256, &instance)
                .await;
        }
        if now >= startup_deadline {
            return self
                .cleanup_instance(
                    request,
                    &request_sha256,
                    &instance,
                    CleanupReason::StartupTimeout,
                    LifecycleOutcome::StartupTimeoutCleaned,
                    &request.audit_lineage,
                )
                .await;
        }

        if self.validate_instance(&instance, &create, now).is_err() {
            return self
                .cleanup_instance(
                    request,
                    &request_sha256,
                    &instance,
                    CleanupReason::Substitution,
                    LifecycleOutcome::SubstitutionDeniedCleaned,
                    &request.audit_lineage,
                )
                .await;
        }

        match instance.state {
            ProviderInstanceState::Ready => {
                if !self.set_state_from(
                    request.request_id,
                    StoredState::Pending,
                    StoredState::Ready,
                    Some(&instance),
                    now,
                )? {
                    return self
                        .recover_create_admission_race(request, &request_sha256, &instance)
                        .await;
                }
                self.append_lifecycle_receipt(
                    request,
                    LifecycleEvidence {
                        request_sha256: &request_sha256,
                        instance: Some(&instance),
                        outcome: LifecycleOutcome::Ready,
                        cleanup_confirmed: false,
                        ambiguity: false,
                        audit_lineage: &request.audit_lineage,
                        observed_at_unix_ms: now,
                    },
                )
            }
            ProviderInstanceState::StartupFailed | ProviderInstanceState::AgentLost => {
                let (reason, outcome) = if instance.state == ProviderInstanceState::StartupFailed {
                    (
                        CleanupReason::StartupFailed,
                        LifecycleOutcome::StartupFailedCleaned,
                    )
                } else {
                    (CleanupReason::AgentLost, LifecycleOutcome::AgentLostCleaned)
                };
                self.set_state(
                    request.request_id,
                    StoredState::Deleting,
                    Some(&instance),
                    now,
                )?;
                self.cleanup_instance(
                    request,
                    &request_sha256,
                    &instance,
                    reason,
                    outcome,
                    &request.audit_lineage,
                )
                .await
            }
            ProviderInstanceState::Pending | ProviderInstanceState::Deleting => {
                self.await_startup(request, &request_sha256, instance, startup_deadline)
                    .await
            }
        }
    }

    pub async fn cancel(
        &self,
        request: &CancelRequest,
    ) -> Result<LifecycleReceipt, ProvisionerError> {
        let now = now_unix_ms()?;
        self.validate_cancel_request(request, now)?;
        let mut stored = self
            .load_stored_request(request.request_id)?
            .ok_or(ProvisionerError::BindingMismatch)?;
        if stored.request.tenant_id != request.tenant_id
            || stored.request.project_id != request.project_id
            || stored.request.build_id != request.build_id
            || stored.request.attempt_id != request.attempt_id
            || stored.request.fence_token != request.fence_token
            || stored.request_sha256 != request.expected_request_sha256
        {
            return Err(ProvisionerError::BindingMismatch);
        }
        if stored.state == StoredState::Deleted {
            if let Some(receipt) = stored.latest_receipt {
                self.verify_lifecycle_receipt(&receipt)?;
                return Ok(receipt);
            }
            return Err(ProvisionerError::StateUnavailable);
        }
        let instance = match stored.instance.take() {
            Some(instance) => instance,
            None => match self.provider_lookup(request.request_id).await {
                Ok(Some(instance)) => instance,
                Ok(None) => {
                    let (_, cancel_outcome) = self.record_cleanup_intent(
                        request.request_id,
                        CleanupReason::Cancelled,
                        LifecycleOutcome::Cancelled,
                    )?;
                    self.set_state(request.request_id, StoredState::Deleted, None, now)?;
                    return self.append_lifecycle_receipt(
                        &stored.request,
                        LifecycleEvidence {
                            request_sha256: &stored.request_sha256,
                            instance: None,
                            outcome: cancel_outcome,
                            cleanup_confirmed: true,
                            ambiguity: false,
                            audit_lineage: &request.audit_lineage,
                            observed_at_unix_ms: now,
                        },
                    );
                }
                Err(_) => {
                    self.record_cleanup_intent(
                        request.request_id,
                        CleanupReason::Cancelled,
                        LifecycleOutcome::Cancelled,
                    )?;
                    self.set_state(request.request_id, StoredState::Deleting, None, now)?;
                    return self.append_lifecycle_receipt(
                        &stored.request,
                        LifecycleEvidence {
                            request_sha256: &stored.request_sha256,
                            instance: None,
                            outcome: LifecycleOutcome::ReconciliationRequired,
                            cleanup_confirmed: false,
                            ambiguity: true,
                            audit_lineage: &request.audit_lineage,
                            observed_at_unix_ms: now,
                        },
                    );
                }
            },
        };
        let create = ProviderCreateRequest {
            protocol_version: PROTOCOL_VERSION.to_owned(),
            provisioner_id: self.config.provisioner_id.clone(),
            provisioner_config_sha256: stored.request.expected_config_sha256.clone(),
            request_sha256: stored.request_sha256.clone(),
            request: stored.request.clone(),
        };
        if self
            .validate_instance(&instance, &create, now_unix_ms()?)
            .is_err()
        {
            return self
                .cleanup_instance(
                    &stored.request,
                    &stored.request_sha256,
                    &instance,
                    CleanupReason::Substitution,
                    LifecycleOutcome::SubstitutionDeniedCleaned,
                    &request.audit_lineage,
                )
                .await;
        }
        self.cleanup_instance(
            &stored.request,
            &stored.request_sha256,
            &instance,
            CleanupReason::Cancelled,
            LifecycleOutcome::Cancelled,
            &request.audit_lineage,
        )
        .await
    }

    pub async fn reconcile(
        &self,
        request: &ReconcileRequest,
    ) -> Result<ReconcileReceipt, ProvisionerError> {
        let now = now_unix_ms()?;
        self.validate_reconcile_request(request, now)?;
        let initial = self.provider_inventory().await?;
        if !initial.complete || initial.instances.len() > MAX_PROVIDER_INSTANCES {
            return Err(ProvisionerError::InvalidProviderResponse);
        }
        let initial_inventory_sha256 = canonical_digest(&initial)?;
        let mut provider_by_request = HashMap::with_capacity(initial.instances.len());
        let mut provider_instance_ids = BTreeSet::new();
        for instance in initial.instances {
            if !provider_instance_ids.insert(instance.instance_id)
                || provider_by_request
                    .insert(instance.create.request.request_id, instance)
                    .is_some()
            {
                return Err(ProvisionerError::InvalidProviderResponse);
            }
        }

        let stored = self.load_active_requests()?;
        let mut known = BTreeSet::new();
        let mut recovered = 0_u32;
        let mut cleaned = 0_u32;
        let mut ambiguous = 0_u32;
        let mut cleaned_request_ids = BTreeSet::new();
        let mut orphan_instance_ids = BTreeSet::new();
        let mut ambiguous_request_ids = BTreeSet::new();
        for item in &stored {
            if let Some(receipt) = &item.latest_receipt {
                self.verify_lifecycle_receipt(receipt)?;
            }
            known.insert(item.request.request_id);
            let Some(instance) = provider_by_request.get(&item.request.request_id) else {
                let peer_deadline = item
                    .updated_at_unix_ms
                    .checked_add(
                        i64::try_from(self.config.provider_timeout_ms)
                            .map_err(|_| ProvisionerError::InvalidConfig)?
                            .checked_add(1_000)
                            .ok_or(ProvisionerError::InvalidConfig)?,
                    )
                    .ok_or(ProvisionerError::StateUnavailable)?
                    .min(item.request.expires_at_unix_ms);
                let possibly_creating = item.state == StoredState::Intent
                    || item.state == StoredState::Pending
                    || (item.state == StoredState::Ambiguous && item.instance.is_none());
                if possibly_creating && now < peer_deadline {
                    ambiguous = ambiguous
                        .checked_add(1)
                        .ok_or(ProvisionerError::StateUnavailable)?;
                    ambiguous_request_ids.insert(item.request.request_id);
                    continue;
                }
                let (terminal, outcome) = match item.state {
                    StoredState::Ready => {
                        (StoredState::Deleted, LifecycleOutcome::AgentLostCleaned)
                    }
                    StoredState::Deleting => {
                        let (_, outcome) = self
                            .load_cleanup_intent(item.request.request_id)?
                            .unwrap_or((CleanupReason::Cancelled, LifecycleOutcome::Cancelled));
                        (StoredState::Deleted, outcome)
                    }
                    StoredState::Deleted => {
                        let (_, outcome) = self
                            .load_cleanup_intent(item.request.request_id)?
                            .unwrap_or((CleanupReason::Cancelled, LifecycleOutcome::Cancelled));
                        (StoredState::Deleted, outcome)
                    }
                    StoredState::Intent
                    | StoredState::Ambiguous
                    | StoredState::Pending
                    | StoredState::Failed => {
                        (StoredState::Failed, LifecycleOutcome::StartupFailedCleaned)
                    }
                };
                self.set_state(item.request.request_id, terminal, None, now)?;
                self.append_lifecycle_receipt(
                    &item.request,
                    LifecycleEvidence {
                        request_sha256: &item.request_sha256,
                        instance: None,
                        outcome,
                        cleanup_confirmed: true,
                        ambiguity: false,
                        audit_lineage: &request.audit_lineage,
                        observed_at_unix_ms: now,
                    },
                )?;
                cleaned = cleaned
                    .checked_add(1)
                    .ok_or(ProvisionerError::StateUnavailable)?;
                cleaned_request_ids.insert(item.request.request_id);
                continue;
            };
            let create = ProviderCreateRequest {
                protocol_version: PROTOCOL_VERSION.to_owned(),
                provisioner_id: self.config.provisioner_id.clone(),
                provisioner_config_sha256: item.request.expected_config_sha256.clone(),
                request_sha256: item.request_sha256.clone(),
                request: item.request.clone(),
            };
            if self.validate_instance(instance, &create, now).is_err() {
                let receipt = self
                    .cleanup_instance(
                        &item.request,
                        &item.request_sha256,
                        instance,
                        CleanupReason::Substitution,
                        LifecycleOutcome::SubstitutionDeniedCleaned,
                        &request.audit_lineage,
                    )
                    .await?;
                if receipt.body.cleanup_confirmed {
                    cleaned = cleaned
                        .checked_add(1)
                        .ok_or(ProvisionerError::StateUnavailable)?;
                    cleaned_request_ids.insert(item.request.request_id);
                } else {
                    ambiguous = ambiguous
                        .checked_add(1)
                        .ok_or(ProvisionerError::StateUnavailable)?;
                    ambiguous_request_ids.insert(item.request.request_id);
                }
                continue;
            }
            let startup_expired = matches!(
                item.state,
                StoredState::Intent | StoredState::Ambiguous | StoredState::Pending
            ) && now
                >= self.startup_deadline(&item.request, item.updated_at_unix_ms)?;
            let expired = item.request.instance_expires_at_unix_ms <= now;
            let cleanup = match (startup_expired, expired, item.state, instance.state) {
                (true, _, _, _) => Some((
                    CleanupReason::StartupTimeout,
                    LifecycleOutcome::StartupTimeoutCleaned,
                )),
                (_, true, _, _) => Some((CleanupReason::Expired, LifecycleOutcome::ExpiredCleaned)),
                (_, _, StoredState::Deleting, _) => Some(
                    self.load_cleanup_intent(item.request.request_id)?
                        .unwrap_or((CleanupReason::Cancelled, LifecycleOutcome::Cancelled)),
                ),
                (_, _, _, ProviderInstanceState::StartupFailed) => Some((
                    CleanupReason::StartupFailed,
                    LifecycleOutcome::StartupFailedCleaned,
                )),
                (_, _, _, ProviderInstanceState::AgentLost) => {
                    Some((CleanupReason::AgentLost, LifecycleOutcome::AgentLostCleaned))
                }
                (_, _, _, ProviderInstanceState::Deleting) => {
                    Some((CleanupReason::Superseded, LifecycleOutcome::Cancelled))
                }
                _ => None,
            };
            if let Some((reason, outcome)) = cleanup {
                let receipt = self
                    .cleanup_instance(
                        &item.request,
                        &item.request_sha256,
                        instance,
                        reason,
                        outcome,
                        &request.audit_lineage,
                    )
                    .await?;
                if receipt.body.cleanup_confirmed {
                    cleaned = cleaned
                        .checked_add(1)
                        .ok_or(ProvisionerError::StateUnavailable)?;
                    cleaned_request_ids.insert(item.request.request_id);
                } else {
                    ambiguous = ambiguous
                        .checked_add(1)
                        .ok_or(ProvisionerError::StateUnavailable)?;
                    ambiguous_request_ids.insert(item.request.request_id);
                }
            } else if instance.state == ProviderInstanceState::Ready {
                let transitioned = self.set_state_from(
                    item.request.request_id,
                    item.state,
                    StoredState::Ready,
                    Some(instance),
                    now,
                )?;
                if transitioned && item.state != StoredState::Ready {
                    self.append_lifecycle_receipt(
                        &item.request,
                        LifecycleEvidence {
                            request_sha256: &item.request_sha256,
                            instance: Some(instance),
                            outcome: LifecycleOutcome::Ready,
                            cleanup_confirmed: false,
                            ambiguity: false,
                            audit_lineage: &request.audit_lineage,
                            observed_at_unix_ms: now,
                        },
                    )?;
                    recovered = recovered
                        .checked_add(1)
                        .ok_or(ProvisionerError::StateUnavailable)?;
                }
            } else {
                ambiguous = ambiguous
                    .checked_add(1)
                    .ok_or(ProvisionerError::StateUnavailable)?;
                ambiguous_request_ids.insert(item.request.request_id);
            }
        }

        let mut orphan_cleaned = 0_u32;
        for (request_id, instance) in provider_by_request {
            if known.contains(&request_id) {
                continue;
            }
            if instance.create.provisioner_id != self.config.provisioner_id {
                return Err(ProvisionerError::InvalidProviderResponse);
            }
            if self
                .delete_orphan(&instance, &request.audit_lineage)
                .await
                .is_ok()
            {
                orphan_cleaned = orphan_cleaned
                    .checked_add(1)
                    .ok_or(ProvisionerError::StateUnavailable)?;
                orphan_instance_ids.insert(instance.instance_id);
            } else {
                ambiguous = ambiguous
                    .checked_add(1)
                    .ok_or(ProvisionerError::StateUnavailable)?;
                ambiguous_request_ids.insert(request_id);
            }
        }

        let final_inventory = self.provider_inventory().await?;
        if !final_inventory.complete || final_inventory.instances.len() > MAX_PROVIDER_INSTANCES {
            return Err(ProvisionerError::InvalidProviderResponse);
        }
        let final_inventory_sha256 = canonical_digest(&final_inventory)?;
        let final_observed_at = now_unix_ms()?;
        let final_active = self.load_active_requests()?;
        let admitted_ready = final_active
            .iter()
            .filter(|item| item.state == StoredState::Ready)
            .map(|item| (item.request.request_id, item))
            .collect::<HashMap<_, _>>();
        let mut active_instance_ids = BTreeSet::new();
        let mut final_request_ids = BTreeSet::new();
        let mut final_instance_ids = BTreeSet::new();
        let mut escaped_compute_remaining = 0_usize;
        for instance in &final_inventory.instances {
            if !final_request_ids.insert(instance.create.request.request_id)
                || !final_instance_ids.insert(instance.instance_id)
            {
                return Err(ProvisionerError::InvalidProviderResponse);
            }
            let Some(stored) = admitted_ready.get(&instance.create.request.request_id) else {
                escaped_compute_remaining = escaped_compute_remaining
                    .checked_add(1)
                    .ok_or(ProvisionerError::StateUnavailable)?;
                continue;
            };
            let expected_create = ProviderCreateRequest {
                protocol_version: PROTOCOL_VERSION.to_owned(),
                provisioner_id: self.config.provisioner_id.clone(),
                provisioner_config_sha256: stored.request.expected_config_sha256.clone(),
                request_sha256: stored.request_sha256.clone(),
                request: stored.request.clone(),
            };
            let retained_instance_matches = stored
                .instance
                .as_ref()
                .is_some_and(|retained| retained.instance_id == instance.instance_id);
            if instance.state == ProviderInstanceState::Ready
                && instance.create.request.instance_expires_at_unix_ms > final_observed_at
                && retained_instance_matches
                && self
                    .validate_instance(instance, &expected_create, final_observed_at)
                    .is_ok()
            {
                active_instance_ids.insert(instance.instance_id);
            } else {
                escaped_compute_remaining = escaped_compute_remaining
                    .checked_add(1)
                    .ok_or(ProvisionerError::StateUnavailable)?;
            }
        }
        let active_ready = active_instance_ids.len();
        let body = ReconcileReceiptBody {
            protocol_version: PROTOCOL_VERSION.to_owned(),
            reconciliation_id: request.reconciliation_id,
            provisioner_id: self.config.provisioner_id.clone(),
            provisioner_implementation_sha256: self.implementation_sha256.clone(),
            provisioner_config_sha256: self.config_sha256.clone(),
            generation: self.config.generation,
            provider_id: self.config.provider_id.clone(),
            provider_account_id: self.config.provider_account_id.clone(),
            provider_region: self.config.provider_region.clone(),
            observed_at_unix_ms: final_observed_at,
            active_ready: u32::try_from(active_ready)
                .map_err(|_| ProvisionerError::StateUnavailable)?,
            recovered,
            cleaned,
            orphan_cleaned,
            ambiguous,
            escaped_compute_remaining: u32::try_from(escaped_compute_remaining)
                .map_err(|_| ProvisionerError::StateUnavailable)?,
            initial_inventory_sha256,
            final_inventory_sha256,
            active_instance_ids,
            cleaned_request_ids,
            orphan_instance_ids,
            ambiguous_request_ids,
            audit_lineage: request.audit_lineage.clone(),
            signing_key_id: self.config.receipt_signing_key_id.clone(),
        };
        let receipt = ReconcileReceipt {
            signature: self.sign(&body)?,
            body,
        };
        self.store_reconcile_evidence(&receipt)?;
        Ok(receipt)
    }

    pub fn verify_lifecycle_receipt(
        &self,
        receipt: &LifecycleReceipt,
    ) -> Result<(), ProvisionerError> {
        if receipt.body.protocol_version != PROTOCOL_VERSION
            || receipt.body.provisioner_id != self.config.provisioner_id
            || receipt.body.signing_key_id != self.config.receipt_signing_key_id
        {
            return Err(ProvisionerError::InvalidStoredReceipt);
        }
        self.verify_signature(&receipt.body, &receipt.signature)
    }

    pub fn verify_reconcile_receipt(
        &self,
        receipt: &ReconcileReceipt,
    ) -> Result<(), ProvisionerError> {
        if receipt.body.protocol_version != PROTOCOL_VERSION
            || receipt.body.provisioner_id != self.config.provisioner_id
            || receipt.body.signing_key_id != self.config.receipt_signing_key_id
        {
            return Err(ProvisionerError::InvalidStoredReceipt);
        }
        self.verify_signature(&receipt.body, &receipt.signature)
    }

    async fn await_startup(
        &self,
        request: &ProvisionRequest,
        request_sha256: &str,
        mut instance: ProviderInstance,
        deadline: i64,
    ) -> Result<LifecycleReceipt, ProvisionerError> {
        loop {
            let now = now_unix_ms()?;
            if now >= deadline {
                self.set_state(
                    request.request_id,
                    StoredState::Deleting,
                    Some(&instance),
                    now,
                )?;
                return self
                    .cleanup_instance(
                        request,
                        request_sha256,
                        &instance,
                        CleanupReason::StartupTimeout,
                        LifecycleOutcome::StartupTimeoutCleaned,
                        &request.audit_lineage,
                    )
                    .await;
            }
            let remaining_ms = u64::try_from(deadline.saturating_sub(now))
                .map_err(|_| ProvisionerError::InvalidConfig)?;
            tokio::time::sleep(Duration::from_millis(
                self.config.startup_poll_interval_ms.min(remaining_ms),
            ))
            .await;
            instance = match self.provider_lookup(request.request_id).await {
                Ok(Some(candidate)) => candidate,
                Ok(None) => {
                    self.set_state(request.request_id, StoredState::Deleted, None, now)?;
                    return self.append_lifecycle_receipt(
                        request,
                        LifecycleEvidence {
                            request_sha256,
                            instance: None,
                            outcome: LifecycleOutcome::StartupFailedCleaned,
                            cleanup_confirmed: true,
                            ambiguity: false,
                            audit_lineage: &request.audit_lineage,
                            observed_at_unix_ms: now,
                        },
                    );
                }
                Err(_) => {
                    self.set_state(
                        request.request_id,
                        StoredState::Ambiguous,
                        Some(&instance),
                        now,
                    )?;
                    return self.append_lifecycle_receipt(
                        request,
                        LifecycleEvidence {
                            request_sha256,
                            instance: Some(&instance),
                            outcome: LifecycleOutcome::ReconciliationRequired,
                            cleanup_confirmed: false,
                            ambiguity: true,
                            audit_lineage: &request.audit_lineage,
                            observed_at_unix_ms: now,
                        },
                    );
                }
            };
            let now = now_unix_ms()?;
            if now >= deadline {
                self.set_state(
                    request.request_id,
                    StoredState::Deleting,
                    Some(&instance),
                    now,
                )?;
                return self
                    .cleanup_instance(
                        request,
                        request_sha256,
                        &instance,
                        CleanupReason::StartupTimeout,
                        LifecycleOutcome::StartupTimeoutCleaned,
                        &request.audit_lineage,
                    )
                    .await;
            }
            let create = ProviderCreateRequest {
                protocol_version: PROTOCOL_VERSION.to_owned(),
                provisioner_id: self.config.provisioner_id.clone(),
                provisioner_config_sha256: self.config_sha256.clone(),
                request_sha256: request_sha256.to_owned(),
                request: request.clone(),
            };
            if self.validate_instance(&instance, &create, now).is_err() {
                self.set_state(
                    request.request_id,
                    StoredState::Deleting,
                    Some(&instance),
                    now,
                )?;
                return self
                    .cleanup_instance(
                        request,
                        request_sha256,
                        &instance,
                        CleanupReason::Substitution,
                        LifecycleOutcome::SubstitutionDeniedCleaned,
                        &request.audit_lineage,
                    )
                    .await;
            }
            match instance.state {
                ProviderInstanceState::Ready => {
                    if !self.set_state_from(
                        request.request_id,
                        StoredState::Pending,
                        StoredState::Ready,
                        Some(&instance),
                        now,
                    )? {
                        return self
                            .recover_create_admission_race(request, request_sha256, &instance)
                            .await;
                    }
                    return self.append_lifecycle_receipt(
                        request,
                        LifecycleEvidence {
                            request_sha256,
                            instance: Some(&instance),
                            outcome: LifecycleOutcome::Ready,
                            cleanup_confirmed: false,
                            ambiguity: false,
                            audit_lineage: &request.audit_lineage,
                            observed_at_unix_ms: now,
                        },
                    );
                }
                ProviderInstanceState::StartupFailed | ProviderInstanceState::AgentLost => {
                    let (reason, outcome) =
                        if instance.state == ProviderInstanceState::StartupFailed {
                            (
                                CleanupReason::StartupFailed,
                                LifecycleOutcome::StartupFailedCleaned,
                            )
                        } else {
                            (CleanupReason::AgentLost, LifecycleOutcome::AgentLostCleaned)
                        };
                    self.set_state(
                        request.request_id,
                        StoredState::Deleting,
                        Some(&instance),
                        now,
                    )?;
                    return self
                        .cleanup_instance(
                            request,
                            request_sha256,
                            &instance,
                            reason,
                            outcome,
                            &request.audit_lineage,
                        )
                        .await;
                }
                ProviderInstanceState::Pending | ProviderInstanceState::Deleting => {
                    self.set_state(
                        request.request_id,
                        StoredState::Pending,
                        Some(&instance),
                        now,
                    )?;
                }
            }
        }
    }

    async fn recover_one(
        &self,
        stored: StoredRequest,
        audit_lineage: &str,
    ) -> Result<LifecycleReceipt, ProvisionerError> {
        match self.provider_lookup(stored.request.request_id).await {
            Ok(Some(instance)) => {
                let now = now_unix_ms()?;
                let create = ProviderCreateRequest {
                    protocol_version: PROTOCOL_VERSION.to_owned(),
                    provisioner_id: self.config.provisioner_id.clone(),
                    provisioner_config_sha256: stored.request.expected_config_sha256.clone(),
                    request_sha256: stored.request_sha256.clone(),
                    request: stored.request.clone(),
                };
                if self.validate_instance(&instance, &create, now).is_err() {
                    return self
                        .cleanup_instance(
                            &stored.request,
                            &stored.request_sha256,
                            &instance,
                            CleanupReason::Substitution,
                            LifecycleOutcome::SubstitutionDeniedCleaned,
                            audit_lineage,
                        )
                        .await;
                }
                if stored.state == StoredState::Deleting {
                    let (reason, outcome) = self
                        .load_cleanup_intent(stored.request.request_id)?
                        .unwrap_or((CleanupReason::Cancelled, LifecycleOutcome::Cancelled));
                    return self
                        .cleanup_instance(
                            &stored.request,
                            &stored.request_sha256,
                            &instance,
                            reason,
                            outcome,
                            audit_lineage,
                        )
                        .await;
                }
                let startup_deadline =
                    self.startup_deadline(&stored.request, stored.updated_at_unix_ms)?;
                if matches!(
                    stored.state,
                    StoredState::Intent | StoredState::Ambiguous | StoredState::Pending
                ) && now >= startup_deadline
                {
                    return self
                        .cleanup_instance(
                            &stored.request,
                            &stored.request_sha256,
                            &instance,
                            CleanupReason::StartupTimeout,
                            LifecycleOutcome::StartupTimeoutCleaned,
                            audit_lineage,
                        )
                        .await;
                }
                match instance.state {
                    ProviderInstanceState::Ready => {
                        if !self.set_state_from(
                            stored.request.request_id,
                            stored.state,
                            StoredState::Ready,
                            Some(&instance),
                            now,
                        )? {
                            return self
                                .recover_create_admission_race(
                                    &stored.request,
                                    &stored.request_sha256,
                                    &instance,
                                )
                                .await;
                        }
                        self.append_lifecycle_receipt(
                            &stored.request,
                            LifecycleEvidence {
                                request_sha256: &stored.request_sha256,
                                instance: Some(&instance),
                                outcome: LifecycleOutcome::Ready,
                                cleanup_confirmed: false,
                                ambiguity: false,
                                audit_lineage,
                                observed_at_unix_ms: now,
                            },
                        )
                    }
                    ProviderInstanceState::Pending => {
                        self.await_startup(
                            &stored.request,
                            &stored.request_sha256,
                            instance,
                            startup_deadline,
                        )
                        .await
                    }
                    ProviderInstanceState::StartupFailed
                    | ProviderInstanceState::AgentLost
                    | ProviderInstanceState::Deleting => {
                        let (reason, outcome) = match instance.state {
                            ProviderInstanceState::StartupFailed => (
                                CleanupReason::StartupFailed,
                                LifecycleOutcome::StartupFailedCleaned,
                            ),
                            ProviderInstanceState::AgentLost => {
                                (CleanupReason::AgentLost, LifecycleOutcome::AgentLostCleaned)
                            }
                            _ => (CleanupReason::Superseded, LifecycleOutcome::Cancelled),
                        };
                        self.cleanup_instance(
                            &stored.request,
                            &stored.request_sha256,
                            &instance,
                            reason,
                            outcome,
                            audit_lineage,
                        )
                        .await
                    }
                }
            }
            Ok(None) => {
                let now = now_unix_ms()?;
                let (terminal, outcome) = match stored.state {
                    StoredState::Ready => {
                        (StoredState::Deleted, LifecycleOutcome::AgentLostCleaned)
                    }
                    StoredState::Deleting => {
                        let (_, outcome) = self
                            .load_cleanup_intent(stored.request.request_id)?
                            .unwrap_or((CleanupReason::Cancelled, LifecycleOutcome::Cancelled));
                        (StoredState::Deleted, outcome)
                    }
                    StoredState::Deleted => {
                        let (_, outcome) = self
                            .load_cleanup_intent(stored.request.request_id)?
                            .unwrap_or((CleanupReason::Cancelled, LifecycleOutcome::Cancelled));
                        (StoredState::Deleted, outcome)
                    }
                    StoredState::Intent
                    | StoredState::Ambiguous
                    | StoredState::Pending
                    | StoredState::Failed => {
                        (StoredState::Failed, LifecycleOutcome::StartupFailedCleaned)
                    }
                };
                self.set_state(stored.request.request_id, terminal, None, now)?;
                self.append_lifecycle_receipt(
                    &stored.request,
                    LifecycleEvidence {
                        request_sha256: &stored.request_sha256,
                        instance: None,
                        outcome,
                        cleanup_confirmed: true,
                        ambiguity: false,
                        audit_lineage,
                        observed_at_unix_ms: now,
                    },
                )
            }
            Err(_) => {
                let now = now_unix_ms()?;
                let retained_state = if stored.state == StoredState::Deleting {
                    StoredState::Deleting
                } else {
                    StoredState::Ambiguous
                };
                self.set_state(
                    stored.request.request_id,
                    retained_state,
                    stored.instance.as_ref(),
                    now,
                )?;
                self.append_lifecycle_receipt(
                    &stored.request,
                    LifecycleEvidence {
                        request_sha256: &stored.request_sha256,
                        instance: stored.instance.as_ref(),
                        outcome: LifecycleOutcome::ReconciliationRequired,
                        cleanup_confirmed: false,
                        ambiguity: true,
                        audit_lineage,
                        observed_at_unix_ms: now,
                    },
                )
            }
        }
    }

    fn startup_deadline(
        &self,
        request: &ProvisionRequest,
        started_at_unix_ms: i64,
    ) -> Result<i64, ProvisionerError> {
        Ok(started_at_unix_ms
            .checked_add(
                i64::try_from(self.config.startup_timeout_ms)
                    .map_err(|_| ProvisionerError::InvalidConfig)?,
            )
            .ok_or(ProvisionerError::InvalidConfig)?
            .min(request.expires_at_unix_ms)
            .min(request.instance_expires_at_unix_ms)
            .min(self.config.provider_grant_expires_unix_ms))
    }

    async fn recover_create_admission_race(
        &self,
        request: &ProvisionRequest,
        request_sha256: &str,
        instance: &ProviderInstance,
    ) -> Result<LifecycleReceipt, ProvisionerError> {
        let stored = self
            .load_stored_request(request.request_id)?
            .ok_or(ProvisionerError::StateUnavailable)?;
        if matches!(stored.state, StoredState::Pending | StoredState::Ready)
            && stored.latest_receipt.as_ref().is_some_and(|receipt| {
                receipt.body.outcome == LifecycleOutcome::Ready
                    && !receipt.body.cleanup_confirmed
                    && !receipt.body.ambiguity
            })
        {
            let receipt = stored
                .latest_receipt
                .ok_or(ProvisionerError::StateUnavailable)?;
            self.verify_lifecycle_receipt(&receipt)?;
            return Ok(receipt);
        }
        if matches!(
            stored.state,
            StoredState::Intent | StoredState::Pending | StoredState::Ready
        ) && stored.latest_receipt.is_none()
        {
            return Box::pin(self.recover_one(stored, &request.audit_lineage)).await;
        }
        let (reason, outcome) = self
            .load_cleanup_intent(request.request_id)?
            .or_else(|| {
                stored
                    .latest_receipt
                    .as_ref()
                    .and_then(|receipt| cleanup_directive(receipt.body.outcome))
            })
            .unwrap_or((CleanupReason::Superseded, LifecycleOutcome::Cancelled));
        self.cleanup_instance(
            request,
            request_sha256,
            instance,
            reason,
            outcome,
            &request.audit_lineage,
        )
        .await
    }

    async fn wait_for_peer_or_recover(
        &self,
        mut stored: StoredRequest,
        audit_lineage: &str,
    ) -> Result<LifecycleReceipt, ProvisionerError> {
        let peer_window = i64::try_from(self.config.provider_timeout_ms)
            .map_err(|_| ProvisionerError::InvalidConfig)?
            .checked_add(1_000)
            .ok_or(ProvisionerError::InvalidConfig)?;
        let deadline = stored
            .updated_at_unix_ms
            .checked_add(peer_window)
            .ok_or(ProvisionerError::StateUnavailable)?
            .min(stored.request.expires_at_unix_ms);
        loop {
            if let Some(receipt) = stored.latest_receipt {
                self.verify_lifecycle_receipt(&receipt)?;
                return Ok(receipt);
            }
            if stored.instance.is_some() || stored.state != StoredState::Intent {
                return self.recover_one(stored, audit_lineage).await;
            }
            if now_unix_ms()? >= deadline {
                return self.recover_one(stored, audit_lineage).await;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
            stored = self
                .load_stored_request(stored.request.request_id)?
                .ok_or(ProvisionerError::StateUnavailable)?;
        }
    }

    async fn cleanup_instance(
        &self,
        request: &ProvisionRequest,
        request_sha256: &str,
        instance: &ProviderInstance,
        reason: CleanupReason,
        success_outcome: LifecycleOutcome,
        audit_lineage: &str,
    ) -> Result<LifecycleReceipt, ProvisionerError> {
        let now = now_unix_ms()?;
        let (reason, success_outcome) =
            self.record_cleanup_intent(request.request_id, reason, success_outcome)?;
        self.set_state(
            request.request_id,
            StoredState::Deleting,
            Some(instance),
            now,
        )?;
        let deletion = match self.provider_delete(request, instance, reason).await {
            Ok(deletion) => deletion,
            Err(_) => {
                self.set_state(
                    request.request_id,
                    StoredState::Deleting,
                    Some(instance),
                    now,
                )?;
                return self.append_lifecycle_receipt(
                    request,
                    LifecycleEvidence {
                        request_sha256,
                        instance: Some(instance),
                        outcome: LifecycleOutcome::ReconciliationRequired,
                        cleanup_confirmed: false,
                        ambiguity: true,
                        audit_lineage,
                        observed_at_unix_ms: now,
                    },
                );
            }
        };
        if deletion.request_id != request.request_id
            || deletion.instance_id != instance.instance_id
            || !deletion.absent
        {
            self.set_state(
                request.request_id,
                StoredState::Deleting,
                Some(instance),
                now,
            )?;
            return self.append_lifecycle_receipt(
                request,
                LifecycleEvidence {
                    request_sha256,
                    instance: Some(instance),
                    outcome: LifecycleOutcome::ReconciliationRequired,
                    cleanup_confirmed: false,
                    ambiguity: true,
                    audit_lineage,
                    observed_at_unix_ms: now,
                },
            );
        }
        match self.provider_lookup(request.request_id).await {
            Ok(None) => {
                let terminal = if success_outcome == LifecycleOutcome::Ready {
                    StoredState::Failed
                } else {
                    StoredState::Deleted
                };
                self.set_state(request.request_id, terminal, Some(instance), now)?;
                self.append_lifecycle_receipt(
                    request,
                    LifecycleEvidence {
                        request_sha256,
                        instance: Some(instance),
                        outcome: success_outcome,
                        cleanup_confirmed: true,
                        ambiguity: false,
                        audit_lineage,
                        observed_at_unix_ms: now_unix_ms()?,
                    },
                )
            }
            Ok(Some(_)) | Err(_) => {
                self.set_state(
                    request.request_id,
                    StoredState::Deleting,
                    Some(instance),
                    now,
                )?;
                self.append_lifecycle_receipt(
                    request,
                    LifecycleEvidence {
                        request_sha256,
                        instance: Some(instance),
                        outcome: LifecycleOutcome::ReconciliationRequired,
                        cleanup_confirmed: false,
                        ambiguity: true,
                        audit_lineage,
                        observed_at_unix_ms: now,
                    },
                )
            }
        }
    }

    async fn delete_orphan(
        &self,
        instance: &ProviderInstance,
        _audit_lineage: &str,
    ) -> Result<(), ProvisionerError> {
        let request = &instance.create.request;
        let deletion = self
            .provider_delete(request, instance, CleanupReason::Orphan)
            .await?;
        if deletion.request_id != request.request_id
            || deletion.instance_id != instance.instance_id
            || !deletion.absent
            || self.provider_lookup(request.request_id).await?.is_some()
        {
            return Err(ProvisionerError::ReconciliationRequired);
        }
        Ok(())
    }

    fn validate_provision_request(
        &self,
        request: &ProvisionRequest,
        now: i64,
    ) -> Result<(), ProvisionerError> {
        validate_command_window(
            request.requested_at_unix_ms,
            request.expires_at_unix_ms,
            now,
        )?;
        if self.config.provider_grant_expires_unix_ms <= now {
            return Err(ProvisionerError::ExpiredGrant);
        }
        let identity = request.provisioner_id == self.config.provisioner_id
            && request.expected_implementation_sha256 == self.implementation_sha256
            && request.expected_config_sha256 == self.config_sha256
            && request.expected_generation == self.config.generation
            && request.provider_id == self.config.provider_id
            && request.provider_endpoint_identity == self.config.provider_endpoint_identity
            && request.provider_account_id == self.config.provider_account_id
            && request.provider_region == self.config.provider_region
            && request.provider_grant_id == self.config.provider_grant_id
            && request.provider_grant_scope == self.config.provider_grant_scope
            && request.agent == self.config.agent
            && request.instance_expires_at_unix_ms > now
            && request.instance_expires_at_unix_ms
                <= now
                    .checked_add(
                        i64::try_from(self.config.max_instance_lifetime_ms)
                            .map_err(|_| ProvisionerError::InvalidConfig)?,
                    )
                    .ok_or(ProvisionerError::ExpiredRequest)?
            && valid_text(&request.audit_lineage, MAX_AUDIT_BYTES);
        if !identity {
            return Err(ProvisionerError::BindingMismatch);
        }
        let generation_valid = match request.activation_mode {
            ActivationMode::Current => request.previous_generation.is_none(),
            ActivationMode::Cutover => request
                .previous_generation
                .is_some_and(|previous| previous < request.expected_generation),
            ActivationMode::Rollback => request
                .previous_generation
                .is_some_and(|previous| previous > request.expected_generation),
        };
        if !generation_valid {
            return Err(ProvisionerError::BindingMismatch);
        }
        Ok(())
    }

    fn validate_cancel_request(
        &self,
        request: &CancelRequest,
        now: i64,
    ) -> Result<(), ProvisionerError> {
        validate_command_window(
            request.requested_at_unix_ms,
            request.expires_at_unix_ms,
            now,
        )?;
        if request.expected_implementation_sha256 != self.implementation_sha256
            || request.expected_config_sha256 != self.config_sha256
            || request.expected_generation != self.config.generation
            || !valid_digest(&request.expected_request_sha256)
            || !valid_text(&request.reason, MAX_BINDING_BYTES)
            || !valid_text(&request.audit_lineage, MAX_AUDIT_BYTES)
        {
            return Err(ProvisionerError::BindingMismatch);
        }
        Ok(())
    }

    fn validate_reconcile_request(
        &self,
        request: &ReconcileRequest,
        now: i64,
    ) -> Result<(), ProvisionerError> {
        validate_command_window(
            request.requested_at_unix_ms,
            request.expires_at_unix_ms,
            now,
        )?;
        if request.expected_implementation_sha256 != self.implementation_sha256
            || request.expected_config_sha256 != self.config_sha256
            || request.expected_generation != self.config.generation
            || !valid_text(&request.audit_lineage, MAX_AUDIT_BYTES)
        {
            return Err(ProvisionerError::BindingMismatch);
        }
        Ok(())
    }

    fn validate_instance(
        &self,
        instance: &ProviderInstance,
        expected_create: &ProviderCreateRequest,
        now: i64,
    ) -> Result<(), ProvisionerError> {
        let identity = &instance.identity;
        let earliest_observation = now
            .checked_sub(
                i64::try_from(self.config.provider_timeout_ms)
                    .map_err(|_| ProvisionerError::InvalidConfig)?
                    .checked_add(MAX_CLOCK_SKEW_MS)
                    .ok_or(ProvisionerError::InvalidConfig)?,
            )
            .ok_or(ProvisionerError::InvalidProviderResponse)?;
        if instance.create != *expected_create
            || instance.effective_agent != expected_create.request.agent
            || !valid_text(&identity.instance_subject, MAX_BINDING_BYTES)
            || identity.issuer != self.config.instance_identity.issuer
            || identity.audience != self.config.instance_identity.audience
            || identity.role != self.config.instance_identity.role
            || identity.iam_policy_sha256 != self.config.instance_identity.iam_policy_sha256
            || !valid_text(&identity.grant_id, MAX_BINDING_BYTES)
            || identity.issued_at_unix_ms > instance.observed_at_unix_ms
            || identity.expires_at_unix_ms <= instance.observed_at_unix_ms
            || identity.expires_at_unix_ms > expected_create.request.instance_expires_at_unix_ms
            || identity
                .expires_at_unix_ms
                .checked_sub(identity.issued_at_unix_ms)
                .is_none_or(|ttl| {
                    ttl > i64::try_from(self.config.instance_identity.max_ttl_ms)
                        .unwrap_or(i64::MAX)
                })
            || instance.created_at_unix_ms > instance.observed_at_unix_ms
            || instance.observed_at_unix_ms < earliest_observation
            || instance.observed_at_unix_ms
                > now
                    .checked_add(MAX_CLOCK_SKEW_MS)
                    .ok_or(ProvisionerError::InvalidProviderResponse)?
        {
            return Err(ProvisionerError::BindingMismatch);
        }
        Ok(())
    }

    async fn provider_create(
        &self,
        request: &ProviderCreateRequest,
    ) -> Result<ProviderInstance, ProvisionerError> {
        let started_at_unix_ms = now_unix_ms()?;
        let url = self
            .endpoint
            .join("v1/instances")
            .map_err(|_| ProvisionerError::InvalidConfig)?;
        let envelope: SignedProviderEnvelope<ProviderInstance> = self
            .send_provider(self.client.post(url).json(request))
            .await?;
        self.verify_provider_envelope(&envelope)?;
        validate_provider_observation(envelope.payload.observed_at_unix_ms, started_at_unix_ms)?;
        Ok(envelope.payload)
    }

    async fn provider_lookup(
        &self,
        request_id: Uuid,
    ) -> Result<Option<ProviderInstance>, ProvisionerError> {
        let started_at_unix_ms = now_unix_ms()?;
        let url = self
            .endpoint
            .join(&format!("v1/requests/{request_id}"))
            .map_err(|_| ProvisionerError::InvalidConfig)?;
        let envelope: SignedProviderEnvelope<ProviderLookup> =
            self.send_provider(self.client.get(url)).await?;
        self.verify_provider_envelope(&envelope)?;
        if envelope.payload.request_id != request_id {
            return Err(ProvisionerError::InvalidProviderResponse);
        }
        validate_provider_observation(envelope.payload.observed_at_unix_ms, started_at_unix_ms)?;
        Ok(envelope.payload.instance)
    }

    async fn provider_inventory(&self) -> Result<ProviderInventory, ProvisionerError> {
        let started_at_unix_ms = now_unix_ms()?;
        let mut url = self
            .endpoint
            .join("v1/instances")
            .map_err(|_| ProvisionerError::InvalidConfig)?;
        url.query_pairs_mut()
            .append_pair("provisioner_id", &self.config.provisioner_id);
        let envelope: SignedProviderEnvelope<ProviderInventory> =
            self.send_provider(self.client.get(url)).await?;
        self.verify_provider_envelope(&envelope)?;
        if envelope.payload.provisioner_id != self.config.provisioner_id {
            return Err(ProvisionerError::InvalidProviderResponse);
        }
        validate_provider_observation(envelope.payload.observed_at_unix_ms, started_at_unix_ms)?;
        Ok(envelope.payload)
    }

    async fn provider_delete(
        &self,
        request: &ProvisionRequest,
        instance: &ProviderInstance,
        reason: CleanupReason,
    ) -> Result<ProviderDeleteResult, ProvisionerError> {
        let now = now_unix_ms()?;
        if self.config.provider_grant_expires_unix_ms <= now {
            return Err(ProvisionerError::ExpiredGrant);
        }
        let expires_at_unix_ms = now
            .checked_add(
                i64::try_from(self.config.provider_timeout_ms)
                    .map_err(|_| ProvisionerError::InvalidConfig)?
                    .checked_mul(2)
                    .ok_or(ProvisionerError::InvalidConfig)?,
            )
            .ok_or(ProvisionerError::InvalidConfig)?
            .min(self.config.provider_grant_expires_unix_ms);
        if expires_at_unix_ms <= now {
            return Err(ProvisionerError::ExpiredGrant);
        }
        let body = ProviderDeleteRequest {
            protocol_version: PROTOCOL_VERSION.to_owned(),
            provisioner_id: self.config.provisioner_id.clone(),
            provisioner_config_sha256: self.config_sha256.clone(),
            request_id: request.request_id,
            instance_id: instance.instance_id,
            tenant_id: request.tenant_id,
            project_id: request.project_id,
            build_id: request.build_id,
            attempt_id: request.attempt_id,
            fence_token: request.fence_token,
            reason,
            requested_at_unix_ms: now,
            expires_at_unix_ms,
        };
        let url = self
            .endpoint
            .join(&format!("v1/instances/{}", instance.instance_id))
            .map_err(|_| ProvisionerError::InvalidConfig)?;
        let envelope: SignedProviderEnvelope<ProviderDeleteResult> = self
            .send_provider(self.client.delete(url).json(&body))
            .await?;
        self.verify_provider_envelope(&envelope)?;
        validate_provider_observation(envelope.payload.observed_at_unix_ms, now)?;
        Ok(envelope.payload)
    }

    async fn send_provider<T: DeserializeOwned + Serialize>(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<SignedProviderEnvelope<T>, ProvisionerError> {
        if self.config.provider_grant_expires_unix_ms <= now_unix_ms()? {
            return Err(ProvisionerError::ExpiredGrant);
        }
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, self.provider_authorization.clone());
        headers.insert(
            "x-mcloving-provisioner-id",
            self.provisioner_id_header.clone(),
        );
        headers.insert(
            "x-mcloving-provider-grant-id",
            self.provider_grant_id_header.clone(),
        );
        headers.insert(
            "x-mcloving-provider-grant-scope",
            self.provider_grant_scope_header.clone(),
        );
        let mut response = request
            .headers(headers)
            .send()
            .await
            .map_err(|_| ProvisionerError::ReconciliationRequired)?;
        if matches!(response.status().as_u16(), 401 | 403) {
            return Err(ProvisionerError::ProviderUnauthorized);
        }
        if !response.status().is_success() {
            return Err(ProvisionerError::ReconciliationRequired);
        }
        let header_bytes = response
            .headers()
            .values()
            .try_fold(0_usize, |total, value| {
                total
                    .checked_add(value.as_bytes().len())
                    .ok_or(ProvisionerError::InvalidProviderResponse)
            })?;
        if header_bytes > 64 * 1_024 {
            return Err(ProvisionerError::InvalidProviderResponse);
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_PROVIDER_RESPONSE_BYTES as u64)
        {
            return Err(ProvisionerError::InvalidProviderResponse);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| ProvisionerError::ReconciliationRequired)?
        {
            if bytes
                .len()
                .checked_add(chunk.len())
                .is_none_or(|length| length > MAX_PROVIDER_RESPONSE_BYTES)
            {
                return Err(ProvisionerError::InvalidProviderResponse);
            }
            bytes.extend_from_slice(&chunk);
        }
        parse_json_no_duplicates(&bytes).map_err(|_| ProvisionerError::InvalidProviderResponse)
    }

    fn verify_provider_envelope<T: Serialize>(
        &self,
        envelope: &SignedProviderEnvelope<T>,
    ) -> Result<(), ProvisionerError> {
        if envelope.protocol_version != PROTOCOL_VERSION
            || envelope.provider_id != self.config.provider_id
            || envelope.provider_endpoint_identity != self.config.provider_endpoint_identity
            || envelope.provider_account_id != self.config.provider_account_id
            || envelope.provider_region != self.config.provider_region
            || envelope.provider_api_version != self.config.provider_api_version
            || envelope.attestation_key_id != self.config.provider_attestation_key_id
        {
            return Err(ProvisionerError::InvalidProviderResponse);
        }
        let signature = BASE64
            .decode(&envelope.signature)
            .map_err(|_| ProvisionerError::InvalidProviderResponse)?;
        let message = provider_attestation_message(envelope)?;
        UnparsedPublicKey::new(&ED25519, &self.provider_public_key)
            .verify(&message, &signature)
            .map_err(|_| ProvisionerError::InvalidProviderResponse)
    }

    fn admit_or_load(
        &self,
        request: &ProvisionRequest,
        request_sha256: &str,
        now: i64,
    ) -> Result<Option<StoredRequest>, ProvisionerError> {
        let mut connection = open_database(&self.database_path)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProvisionerError::StateUnavailable)?;
        if let Some(stored) = load_stored_request_tx(&transaction, request.request_id)? {
            if stored.request_sha256 != request_sha256 || stored.request != *request {
                return Err(ProvisionerError::ReplayMismatch);
            }
            transaction
                .commit()
                .map_err(|_| ProvisionerError::StateUnavailable)?;
            return Ok(Some(stored));
        }
        let maximum_fence: Option<i64> = transaction
            .query_row(
                "SELECT max(fence_token) FROM requests
                 WHERE tenant_id = ?1 AND project_id = ?2 AND build_id = ?3 AND attempt_id = ?4",
                params![
                    request.tenant_id.to_string(),
                    request.project_id.to_string(),
                    request.build_id.to_string(),
                    request.attempt_id.to_string(),
                ],
                |row| row.get(0),
            )
            .map_err(|_| ProvisionerError::StateUnavailable)?;
        if let Some(maximum) = maximum_fence {
            let maximum = u64::try_from(maximum).map_err(|_| ProvisionerError::StateUnavailable)?;
            if request.fence_token <= maximum {
                return Err(ProvisionerError::StaleFence);
            }
            let active: i64 = transaction
                .query_row(
                    "SELECT count(*) FROM requests
                     WHERE tenant_id = ?1 AND project_id = ?2 AND build_id = ?3 AND attempt_id = ?4
                       AND state IN ('intent','ambiguous','pending','ready','deleting')",
                    params![
                        request.tenant_id.to_string(),
                        request.project_id.to_string(),
                        request.build_id.to_string(),
                        request.attempt_id.to_string(),
                    ],
                    |row| row.get(0),
                )
                .map_err(|_| ProvisionerError::StateUnavailable)?;
            if active != 0 {
                return Err(ProvisionerError::CleanupRequired);
            }
        }
        self.enforce_quota(&transaction, request)?;
        let request_json = canonical_json(request)?;
        let fence =
            i64::try_from(request.fence_token).map_err(|_| ProvisionerError::BindingMismatch)?;
        transaction
            .execute(
                "INSERT INTO requests(
                    request_id, tenant_id, project_id, build_id, attempt_id, fence_token,
                    request_sha256, request_json, provisioner_config_sha256,
                    implementation_sha256, generation, state, instance_json,
                    latest_receipt_json, created_at_unix_ms, updated_at_unix_ms
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,'intent',NULL,NULL,?12,?12)",
                params![
                    request.request_id.to_string(),
                    request.tenant_id.to_string(),
                    request.project_id.to_string(),
                    request.build_id.to_string(),
                    request.attempt_id.to_string(),
                    fence,
                    request_sha256,
                    request_json,
                    self.config_sha256,
                    self.implementation_sha256,
                    i64::try_from(self.config.generation)
                        .map_err(|_| ProvisionerError::BindingMismatch)?,
                    now,
                ],
            )
            .map_err(|_| ProvisionerError::StateUnavailable)?;
        transaction
            .commit()
            .map_err(|_| ProvisionerError::StateUnavailable)?;
        sync_database_parent(&self.database_path)?;
        Ok(None)
    }

    fn enforce_quota(
        &self,
        transaction: &Transaction<'_>,
        request: &ProvisionRequest,
    ) -> Result<(), ProvisionerError> {
        let active = "state IN ('intent','ambiguous','pending','ready','deleting')";
        let global: i64 = transaction
            .query_row(
                &format!("SELECT count(*) FROM requests WHERE {active}"),
                [],
                |row| row.get(0),
            )
            .map_err(|_| ProvisionerError::StateUnavailable)?;
        let tenant: i64 = transaction
            .query_row(
                &format!("SELECT count(*) FROM requests WHERE {active} AND tenant_id = ?1"),
                [request.tenant_id.to_string()],
                |row| row.get(0),
            )
            .map_err(|_| ProvisionerError::StateUnavailable)?;
        let project: i64 = transaction
            .query_row(
                &format!(
                    "SELECT count(*) FROM requests WHERE {active} AND tenant_id = ?1 AND project_id = ?2"
                ),
                params![request.tenant_id.to_string(), request.project_id.to_string()],
                |row| row.get(0),
            )
            .map_err(|_| ProvisionerError::StateUnavailable)?;
        if global >= i64::from(self.config.quotas.max_active_global)
            || tenant >= i64::from(self.config.quotas.max_active_per_tenant)
            || project >= i64::from(self.config.quotas.max_active_per_project)
        {
            return Err(ProvisionerError::CapacityExhausted);
        }
        Ok(())
    }

    fn set_state(
        &self,
        request_id: Uuid,
        state: StoredState,
        instance: Option<&ProviderInstance>,
        now: i64,
    ) -> Result<(), ProvisionerError> {
        let instance_json = instance.map(canonical_json).transpose()?;
        let connection = open_database(&self.database_path)?;
        let changed = connection
            .execute(
                "UPDATE requests SET state = ?2, instance_json = ?3, updated_at_unix_ms = ?4
                 WHERE request_id = ?1",
                params![request_id.to_string(), state.as_str(), instance_json, now],
            )
            .map_err(|_| ProvisionerError::StateUnavailable)?;
        if changed != 1 {
            return Err(ProvisionerError::StateUnavailable);
        }
        sync_database_parent(&self.database_path)
    }

    fn set_state_from(
        &self,
        request_id: Uuid,
        expected: StoredState,
        state: StoredState,
        instance: Option<&ProviderInstance>,
        now: i64,
    ) -> Result<bool, ProvisionerError> {
        let instance_json = instance.map(canonical_json).transpose()?;
        let connection = open_database(&self.database_path)?;
        let changed = connection
            .execute(
                "UPDATE requests SET state = ?3, instance_json = ?4, updated_at_unix_ms = ?5
                 WHERE request_id = ?1 AND state = ?2",
                params![
                    request_id.to_string(),
                    expected.as_str(),
                    state.as_str(),
                    instance_json,
                    now,
                ],
            )
            .map_err(|_| ProvisionerError::StateUnavailable)?;
        sync_database_parent(&self.database_path)?;
        Ok(changed == 1)
    }

    fn record_cleanup_intent(
        &self,
        request_id: Uuid,
        reason: CleanupReason,
        outcome: LifecycleOutcome,
    ) -> Result<(CleanupReason, LifecycleOutcome), ProvisionerError> {
        let mut connection = open_database(&self.database_path)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProvisionerError::StateUnavailable)?;
        transaction
            .execute(
                "INSERT INTO cleanup_intents(request_id, reason_json, outcome_json)
                 VALUES (?1, ?2, ?3) ON CONFLICT(request_id) DO NOTHING",
                params![
                    request_id.to_string(),
                    canonical_json(&reason)?,
                    canonical_json(&outcome)?,
                ],
            )
            .map_err(|_| ProvisionerError::StateUnavailable)?;
        let stored: (Vec<u8>, Vec<u8>) = transaction
            .query_row(
                "SELECT reason_json, outcome_json FROM cleanup_intents WHERE request_id = ?1",
                [request_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| ProvisionerError::StateUnavailable)?;
        transaction
            .commit()
            .map_err(|_| ProvisionerError::StateUnavailable)?;
        sync_database_parent(&self.database_path)?;
        Ok((
            serde_json::from_slice(&stored.0).map_err(|_| ProvisionerError::StateUnavailable)?,
            serde_json::from_slice(&stored.1).map_err(|_| ProvisionerError::StateUnavailable)?,
        ))
    }

    fn load_cleanup_intent(
        &self,
        request_id: Uuid,
    ) -> Result<Option<(CleanupReason, LifecycleOutcome)>, ProvisionerError> {
        let connection = open_database(&self.database_path)?;
        let stored: Option<(Vec<u8>, Vec<u8>)> = connection
            .query_row(
                "SELECT reason_json, outcome_json FROM cleanup_intents WHERE request_id = ?1",
                [request_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| ProvisionerError::StateUnavailable)?;
        stored
            .map(|(reason, outcome)| {
                Ok((
                    serde_json::from_slice(&reason)
                        .map_err(|_| ProvisionerError::StateUnavailable)?,
                    serde_json::from_slice(&outcome)
                        .map_err(|_| ProvisionerError::StateUnavailable)?,
                ))
            })
            .transpose()
    }

    fn load_stored_request(
        &self,
        request_id: Uuid,
    ) -> Result<Option<StoredRequest>, ProvisionerError> {
        let connection = open_database(&self.database_path)?;
        load_stored_request_connection(&connection, request_id)
    }

    fn load_active_requests(&self) -> Result<Vec<StoredRequest>, ProvisionerError> {
        let connection = open_database(&self.database_path)?;
        let mut statement = connection
            .prepare(
                "SELECT request_json, request_sha256, state, instance_json, latest_receipt_json,
                        updated_at_unix_ms
                 FROM requests
                 WHERE state IN ('intent','ambiguous','pending','ready','deleting')
                 ORDER BY request_id",
            )
            .map_err(|_| ProvisionerError::StateUnavailable)?;
        let rows = statement
            .query_map([], stored_request_from_row)
            .map_err(|_| ProvisionerError::StateUnavailable)?;
        let mut stored = Vec::new();
        for row in rows {
            stored.push(row.map_err(|_| ProvisionerError::StateUnavailable)??);
            if stored.len() > MAX_PROVIDER_INSTANCES {
                return Err(ProvisionerError::StateUnavailable);
            }
        }
        Ok(stored)
    }

    fn append_lifecycle_receipt(
        &self,
        request: &ProvisionRequest,
        evidence: LifecycleEvidence<'_>,
    ) -> Result<LifecycleReceipt, ProvisionerError> {
        let mut connection = open_database(&self.database_path)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProvisionerError::StateUnavailable)?;
        let existing: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT latest_receipt_json FROM requests WHERE request_id = ?1",
                [request.request_id.to_string()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ProvisionerError::StateUnavailable)?
            .flatten();
        if let Some(existing) = existing {
            let existing: LifecycleReceipt = parse_json_no_duplicates(&existing)
                .map_err(|_| ProvisionerError::InvalidStoredReceipt)?;
            self.verify_lifecycle_receipt(&existing)?;
            if evidence.outcome == LifecycleOutcome::Ready && existing.body.cleanup_confirmed {
                transaction
                    .commit()
                    .map_err(|_| ProvisionerError::StateUnavailable)?;
                return Ok(existing);
            }
            if existing.body.outcome == evidence.outcome
                && existing.body.cleanup_confirmed == evidence.cleanup_confirmed
                && existing.body.ambiguity == evidence.ambiguity
                && existing.body.instance_id == evidence.instance.map(|value| value.instance_id)
            {
                transaction
                    .commit()
                    .map_err(|_| ProvisionerError::StateUnavailable)?;
                return Ok(existing);
            }
        }
        let sequence: i64 = transaction
            .query_row(
                "SELECT coalesce(max(sequence), 0) + 1 FROM evidence",
                [],
                |row| row.get(0),
            )
            .map_err(|_| ProvisionerError::StateUnavailable)?;
        let receipt_sequence =
            u64::try_from(sequence).map_err(|_| ProvisionerError::StateUnavailable)?;
        let body = LifecycleReceiptBody {
            protocol_version: PROTOCOL_VERSION.to_owned(),
            receipt_sequence,
            outcome: evidence.outcome,
            request_id: request.request_id,
            request_sha256: evidence.request_sha256.to_owned(),
            tenant_id: request.tenant_id,
            project_id: request.project_id,
            build_id: request.build_id,
            attempt_id: request.attempt_id,
            fence_token: request.fence_token,
            provisioner_id: self.config.provisioner_id.clone(),
            provisioner_implementation_sha256: self.implementation_sha256.clone(),
            provisioner_config_sha256: self.config_sha256.clone(),
            request_expected_implementation_sha256: request.expected_implementation_sha256.clone(),
            request_expected_config_sha256: request.expected_config_sha256.clone(),
            request_expected_generation: request.expected_generation,
            deployment_identity: self.config.deployment_identity.clone(),
            operator_identity: self.config.operator_identity.clone(),
            generation: self.config.generation,
            activation_mode: request.activation_mode,
            previous_generation: request.previous_generation,
            provider_id: self.config.provider_id.clone(),
            provider_endpoint_identity: self.config.provider_endpoint_identity.clone(),
            provider_account_id: self.config.provider_account_id.clone(),
            provider_region: self.config.provider_region.clone(),
            provider_grant_id: self.config.provider_grant_id.clone(),
            agent: request.agent.clone(),
            instance_id: evidence.instance.map(|value| value.instance_id),
            instance_identity: evidence.instance.map(|value| value.identity.clone()),
            requested_at_unix_ms: request.requested_at_unix_ms,
            instance_expires_at_unix_ms: request.instance_expires_at_unix_ms,
            observed_at_unix_ms: evidence.observed_at_unix_ms,
            cleanup_confirmed: evidence.cleanup_confirmed,
            ambiguity: evidence.ambiguity,
            audit_lineage: evidence.audit_lineage.to_owned(),
            signing_key_id: self.config.receipt_signing_key_id.clone(),
        };
        let receipt = LifecycleReceipt {
            signature: self.sign(&body)?,
            body,
        };
        let receipt_json = canonical_json(&receipt)?;
        transaction
            .execute(
                "INSERT INTO evidence(sequence, request_id, evidence_kind, receipt_json)
                 VALUES (?1, ?2, 'lifecycle', ?3)",
                params![sequence, request.request_id.to_string(), receipt_json],
            )
            .map_err(|_| ProvisionerError::StateUnavailable)?;
        let changed = transaction
            .execute(
                "UPDATE requests SET latest_receipt_json = ?2, updated_at_unix_ms = ?3
                 WHERE request_id = ?1",
                params![
                    request.request_id.to_string(),
                    canonical_json(&receipt)?,
                    evidence.observed_at_unix_ms,
                ],
            )
            .map_err(|_| ProvisionerError::StateUnavailable)?;
        if changed != 1 {
            return Err(ProvisionerError::StateUnavailable);
        }
        transaction
            .commit()
            .map_err(|_| ProvisionerError::StateUnavailable)?;
        sync_database_parent(&self.database_path)?;
        Ok(receipt)
    }

    fn store_reconcile_evidence(&self, receipt: &ReconcileReceipt) -> Result<(), ProvisionerError> {
        self.verify_reconcile_receipt(receipt)?;
        let connection = open_database(&self.database_path)?;
        connection
            .execute(
                "INSERT INTO evidence(request_id, evidence_kind, receipt_json)
                 VALUES (NULL, 'reconcile', ?1)",
                [canonical_json(receipt)?],
            )
            .map_err(|_| ProvisionerError::StateUnavailable)?;
        sync_database_parent(&self.database_path)
    }

    fn sign<T: Serialize>(&self, value: &T) -> Result<String, ProvisionerError> {
        let mut mac = HmacSha256::new_from_slice(&self.receipt_signing_key)
            .map_err(|_| ProvisionerError::InvalidConfig)?;
        mac.update(&canonical_json(value)?);
        Ok(BASE64.encode(mac.finalize().into_bytes()))
    }

    fn verify_signature<T: Serialize>(
        &self,
        value: &T,
        signature: &str,
    ) -> Result<(), ProvisionerError> {
        let signature = BASE64
            .decode(signature)
            .map_err(|_| ProvisionerError::InvalidStoredReceipt)?;
        let mut mac = HmacSha256::new_from_slice(&self.receipt_signing_key)
            .map_err(|_| ProvisionerError::InvalidConfig)?;
        mac.update(&canonical_json(value)?);
        mac.verify_slice(&signature)
            .map_err(|_| ProvisionerError::InvalidStoredReceipt)
    }
}

fn initialize_database(
    path: &Path,
    provisioner_id: &str,
    ledger_scope_sha256: &str,
    implementation_sha256: &str,
    config_sha256: &str,
    generation: u64,
) -> Result<(), ProvisionerError> {
    let connection = open_database(path)?;
    connection
        .execute_batch(
            "PRAGMA journal_mode = DELETE;
             PRAGMA synchronous = FULL;
             PRAGMA foreign_keys = ON;
             PRAGMA trusted_schema = OFF;

             CREATE TABLE IF NOT EXISTS metadata (
                 singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                 schema_version INTEGER NOT NULL CHECK (schema_version = 1),
                 provisioner_id TEXT NOT NULL,
                 ledger_scope_sha256 TEXT NOT NULL
             ) STRICT;
             CREATE TABLE IF NOT EXISTS runtime_generations (
                 config_sha256 TEXT PRIMARY KEY,
                 implementation_sha256 TEXT NOT NULL,
                 generation INTEGER NOT NULL CHECK (generation > 0),
                 admitted_at_unix_ms INTEGER NOT NULL
             ) STRICT;
             CREATE TABLE IF NOT EXISTS requests (
                 request_id TEXT PRIMARY KEY,
                 tenant_id TEXT NOT NULL,
                 project_id TEXT NOT NULL,
                 build_id TEXT NOT NULL,
                 attempt_id TEXT NOT NULL,
                 fence_token INTEGER NOT NULL CHECK (fence_token >= 0),
                 request_sha256 TEXT NOT NULL,
                 request_json BLOB NOT NULL,
                 provisioner_config_sha256 TEXT NOT NULL,
                 implementation_sha256 TEXT NOT NULL,
                 generation INTEGER NOT NULL CHECK (generation > 0),
                 state TEXT NOT NULL CHECK (state IN (
                     'intent','ambiguous','pending','ready','deleting','deleted','failed'
                 )),
                 instance_json BLOB,
                 latest_receipt_json BLOB,
                 created_at_unix_ms INTEGER NOT NULL,
                 updated_at_unix_ms INTEGER NOT NULL,
                 UNIQUE (tenant_id, project_id, build_id, attempt_id, fence_token)
             ) STRICT;
             CREATE INDEX IF NOT EXISTS requests_active_scope
                 ON requests(tenant_id, project_id, state);
             CREATE TABLE IF NOT EXISTS cleanup_intents (
                 request_id TEXT PRIMARY KEY,
                 reason_json BLOB NOT NULL,
                 outcome_json BLOB NOT NULL,
                 FOREIGN KEY(request_id) REFERENCES requests(request_id)
             ) STRICT;
             CREATE TABLE IF NOT EXISTS evidence (
                 sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                 request_id TEXT,
                 evidence_kind TEXT NOT NULL CHECK (evidence_kind IN ('lifecycle','reconcile')),
                 receipt_json BLOB NOT NULL,
                 FOREIGN KEY(request_id) REFERENCES requests(request_id)
             ) STRICT;",
        )
        .map_err(|_| ProvisionerError::StateUnavailable)?;
    connection
        .execute(
            "INSERT INTO metadata(
                 singleton, schema_version, provisioner_id, ledger_scope_sha256
             ) VALUES (1, 1, ?1, ?2) ON CONFLICT(singleton) DO NOTHING",
            params![provisioner_id, ledger_scope_sha256],
        )
        .map_err(|_| ProvisionerError::StateUnavailable)?;
    let stored_scope: (String, String) = connection
        .query_row(
            "SELECT provisioner_id, ledger_scope_sha256
             FROM metadata WHERE singleton = 1 AND schema_version = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| ProvisionerError::StateUnavailable)?;
    if stored_scope.0 != provisioner_id || stored_scope.1 != ledger_scope_sha256 {
        return Err(ProvisionerError::StateUnavailable);
    }
    connection
        .execute(
            "INSERT INTO runtime_generations(
                config_sha256, implementation_sha256, generation, admitted_at_unix_ms
             ) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(config_sha256) DO NOTHING",
            params![
                config_sha256,
                implementation_sha256,
                i64::try_from(generation).map_err(|_| ProvisionerError::InvalidConfig)?,
                now_unix_ms()?,
            ],
        )
        .map_err(|_| ProvisionerError::StateUnavailable)?;
    let stored_runtime: (String, i64) = connection
        .query_row(
            "SELECT implementation_sha256, generation
             FROM runtime_generations WHERE config_sha256 = ?1",
            [config_sha256],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| ProvisionerError::StateUnavailable)?;
    if stored_runtime.0 != implementation_sha256
        || u64::try_from(stored_runtime.1).map_err(|_| ProvisionerError::StateUnavailable)?
            != generation
    {
        return Err(ProvisionerError::StateUnavailable);
    }
    sync_database_parent(path)
}

fn ledger_scope_digest(config: &ProvisionerConfig) -> Result<String, ProvisionerError> {
    canonical_digest(&LedgerScopeBinding {
        protocol_version: &config.protocol_version,
        provisioner_id: &config.provisioner_id,
        provider_id: &config.provider_id,
        provider_endpoint: &config.provider_endpoint,
        provider_endpoint_identity: &config.provider_endpoint_identity,
        provider_account_id: &config.provider_account_id,
        provider_region: &config.provider_region,
        provider_api_version: &config.provider_api_version,
        provider_grant_scope: &config.provider_grant_scope,
        provider_attestation_key_id: &config.provider_attestation_key_id,
        provider_attestation_key_sha256: &config.provider_attestation_key_sha256,
        agent: &config.agent,
        instance_identity: &config.instance_identity,
    })
}

fn open_database(path: &Path) -> Result<Connection, ProvisionerError> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_FULL_MUTEX,
    )
    .map_err(|_| ProvisionerError::StateUnavailable)?;
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(|_| ProvisionerError::StateUnavailable)?;
    connection
        .execute_batch(
            "PRAGMA journal_mode = DELETE;
             PRAGMA synchronous = FULL;
             PRAGMA foreign_keys = ON;
             PRAGMA trusted_schema = OFF;",
        )
        .map_err(|_| ProvisionerError::StateUnavailable)?;
    Ok(connection)
}

fn load_stored_request_connection(
    connection: &Connection,
    request_id: Uuid,
) -> Result<Option<StoredRequest>, ProvisionerError> {
    connection
        .query_row(
            "SELECT request_json, request_sha256, state, instance_json, latest_receipt_json,
                    updated_at_unix_ms
             FROM requests WHERE request_id = ?1",
            [request_id.to_string()],
            stored_request_from_row,
        )
        .optional()
        .map_err(|_| ProvisionerError::StateUnavailable)?
        .transpose()
}

fn load_stored_request_tx(
    transaction: &Transaction<'_>,
    request_id: Uuid,
) -> Result<Option<StoredRequest>, ProvisionerError> {
    transaction
        .query_row(
            "SELECT request_json, request_sha256, state, instance_json, latest_receipt_json,
                    updated_at_unix_ms
             FROM requests WHERE request_id = ?1",
            [request_id.to_string()],
            stored_request_from_row,
        )
        .optional()
        .map_err(|_| ProvisionerError::StateUnavailable)?
        .transpose()
}

fn stored_request_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<Result<StoredRequest, ProvisionerError>> {
    let request_json: Vec<u8> = row.get(0)?;
    let request_sha256: String = row.get(1)?;
    let state: String = row.get(2)?;
    let instance_json: Option<Vec<u8>> = row.get(3)?;
    let receipt_json: Option<Vec<u8>> = row.get(4)?;
    let updated_at_unix_ms: i64 = row.get(5)?;
    Ok((|| {
        let request = serde_json::from_slice(&request_json)
            .map_err(|_| ProvisionerError::StateUnavailable)?;
        if canonical_digest(&request)? != request_sha256 {
            return Err(ProvisionerError::StateUnavailable);
        }
        Ok(StoredRequest {
            request,
            request_sha256,
            state: StoredState::parse(&state)?,
            instance: instance_json
                .as_deref()
                .map(serde_json::from_slice)
                .transpose()
                .map_err(|_| ProvisionerError::StateUnavailable)?,
            latest_receipt: receipt_json
                .as_deref()
                .map(serde_json::from_slice)
                .transpose()
                .map_err(|_| ProvisionerError::StateUnavailable)?,
            updated_at_unix_ms,
        })
    })())
}

fn validate_config(
    config: &ProvisionerConfig,
    implementation_sha256: &str,
    provider_token: &str,
    provider_public_key: &[u8],
    receipt_signing_key: &[u8],
) -> Result<(), ProvisionerError> {
    let text = [
        &config.provisioner_id,
        &config.implementation_id,
        &config.deployment_identity,
        &config.operator_identity,
        &config.provider_id,
        &config.provider_endpoint_identity,
        &config.provider_account_id,
        &config.provider_region,
        &config.provider_api_version,
        &config.provider_grant_id,
        &config.provider_grant_scope,
        &config.provider_attestation_key_id,
        &config.receipt_signing_key_id,
        &config.instance_identity.issuer,
        &config.instance_identity.audience,
        &config.instance_identity.role,
    ];
    if config.protocol_version != PROTOCOL_VERSION
        || config.generation == 0
        || text
            .iter()
            .any(|value| !valid_text(value, MAX_BINDING_BYTES))
        || !valid_digest(implementation_sha256)
        || !valid_digest(&config.provider_token_sha256)
        || !valid_digest(&config.provider_attestation_key_sha256)
        || !valid_digest(&config.receipt_signing_key_sha256)
        || !valid_digest(&config.instance_identity.iam_policy_sha256)
        || content_sha256(provider_token.as_bytes()) != config.provider_token_sha256
        || content_sha256(provider_public_key) != config.provider_attestation_key_sha256
        || content_sha256(receipt_signing_key) != config.receipt_signing_key_sha256
        || provider_token.is_empty()
        || provider_token.len() > 4_096
        || provider_public_key.len() != 32
        || receipt_signing_key.len() < 32
        || receipt_signing_key.len() > 4_096
        || config.provider_timeout_ms == 0
        || config.provider_timeout_ms > MAX_PROVIDER_TIMEOUT_MS
        || config.startup_timeout_ms == 0
        || config.startup_timeout_ms > MAX_STARTUP_TIMEOUT_MS
        || config.startup_poll_interval_ms == 0
        || config.startup_poll_interval_ms > config.startup_timeout_ms
        || config.max_instance_lifetime_ms == 0
        || config.max_instance_lifetime_ms
            > u64::try_from(MAX_INSTANCE_LIFETIME_MS)
                .map_err(|_| ProvisionerError::InvalidConfig)?
        || config.instance_identity.max_ttl_ms == 0
        || config.instance_identity.max_ttl_ms > config.max_instance_lifetime_ms
        || config.quotas.max_active_global == 0
        || config.quotas.max_active_global > 1_000
        || config.quotas.max_active_per_tenant == 0
        || config.quotas.max_active_per_tenant > config.quotas.max_active_global
        || config.quotas.max_active_per_project == 0
        || config.quotas.max_active_per_project > config.quotas.max_active_per_tenant
        || !config.state_dir.is_absolute()
    {
        return Err(ProvisionerError::InvalidConfig);
    }
    validate_agent_specification(&config.agent)?;
    match (&config.ca_bundle_path, &config.ca_bundle_sha256) {
        (Some(path), Some(digest)) if path.is_absolute() && valid_digest(digest) => {}
        (None, None) if config.test_allow_http_loopback => {}
        _ => return Err(ProvisionerError::InvalidConfig),
    }
    let now = now_unix_ms()?;
    if config.provider_grant_expires_unix_ms <= now {
        return Err(ProvisionerError::ExpiredGrant);
    }
    Ok(())
}

fn validate_agent_specification(agent: &AgentSpecification) -> Result<(), ProvisionerError> {
    let text = [
        &agent.agent_class_id,
        &agent.template_id,
        &agent.image_id,
        &agent.platform,
        &agent.trust_pool,
        &agent.network.policy_id,
        &agent.volumes.policy_id,
        &agent.workspace.policy_id,
        &agent.cache.policy_id,
        &agent.cache.trust_class,
    ];
    let digests = [
        &agent.template_sha256,
        &agent.image_sha256,
        &agent.bootstrap_sha256,
        &agent.toolchain_sha256,
        &agent.network.policy_sha256,
        &agent.volumes.policy_sha256,
        &agent.workspace.policy_sha256,
        &agent.cache.policy_sha256,
    ];
    if text
        .iter()
        .any(|value| !valid_text(value, MAX_BINDING_BYTES))
        || digests.iter().any(|value| !valid_digest(value))
        || agent.capabilities.is_empty()
        || agent.capabilities.len() > 64
        || agent
            .capabilities
            .iter()
            .any(|value| !valid_text(value, MAX_BINDING_BYTES))
        || agent.network.allow_ingress
        || agent.network.allow_instance_metadata
        || agent.network.egress_allowlist.is_empty()
        || agent.network.egress_allowlist.len() > 64
        || agent
            .network
            .egress_allowlist
            .iter()
            .any(|value| !valid_text(value, MAX_BINDING_BYTES))
        || agent.volumes.allow_host_mounts
        || agent.volumes.grants.len() > 16
        || agent.workspace.max_bytes == 0
        || !agent.workspace.encrypted
        || !agent.workspace.ephemeral
        || !agent.workspace.destroy_on_release
    {
        return Err(ProvisionerError::InvalidConfig);
    }
    let mut mount_paths = BTreeSet::new();
    for grant in &agent.volumes.grants {
        if !valid_text(&grant.volume_class, MAX_BINDING_BYTES)
            || !valid_text(&grant.mount_path, MAX_BINDING_BYTES)
            || !grant.mount_path.starts_with('/')
            || grant.mount_path.contains("..")
            || grant.max_bytes == 0
            || !grant.destroy_on_release
            || !mount_paths.insert(&grant.mount_path)
        {
            return Err(ProvisionerError::InvalidConfig);
        }
    }
    match agent.cache.mode {
        CacheMode::Disabled => {
            if agent.cache.namespace.is_some() || agent.cache.max_bytes != 0 {
                return Err(ProvisionerError::InvalidConfig);
            }
        }
        CacheMode::ReadOnly | CacheMode::IsolatedReadWrite => {
            if agent.cache.max_bytes == 0
                || agent
                    .cache
                    .namespace
                    .as_deref()
                    .is_none_or(|value| !valid_text(value, MAX_BINDING_BYTES))
            {
                return Err(ProvisionerError::InvalidConfig);
            }
        }
    }
    Ok(())
}

fn validate_endpoint(config: &ProvisionerConfig) -> Result<Url, ProvisionerError> {
    let endpoint =
        Url::parse(&config.provider_endpoint).map_err(|_| ProvisionerError::InvalidConfig)?;
    if !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || !matches!(endpoint.path(), "" | "/")
        || endpoint.host_str().is_none()
    {
        return Err(ProvisionerError::InvalidConfig);
    }
    match endpoint.scheme() {
        "https" if config.ca_bundle_path.is_some() => {}
        "http" if config.test_allow_http_loopback && endpoint_is_loopback(&endpoint) => {}
        _ => return Err(ProvisionerError::InvalidConfig),
    }
    Ok(endpoint)
}

fn endpoint_is_loopback(endpoint: &Url) -> bool {
    endpoint
        .host_str()
        .and_then(|host| host.parse::<std::net::IpAddr>().ok())
        .is_some_and(|address| address.is_loopback())
}

fn validate_command_window(
    requested_at_unix_ms: i64,
    expires_at_unix_ms: i64,
    now: i64,
) -> Result<(), ProvisionerError> {
    let latest_requested = now
        .checked_add(MAX_CLOCK_SKEW_MS)
        .ok_or(ProvisionerError::ExpiredRequest)?;
    let window = expires_at_unix_ms
        .checked_sub(requested_at_unix_ms)
        .ok_or(ProvisionerError::ExpiredRequest)?;
    if requested_at_unix_ms > latest_requested
        || expires_at_unix_ms <= now
        || window <= 0
        || window > MAX_COMMAND_WINDOW_MS
    {
        return Err(ProvisionerError::ExpiredRequest);
    }
    Ok(())
}

fn bearer(token: &str) -> Result<HeaderValue, ProvisionerError> {
    let value = format!("Bearer {token}");
    HeaderValue::from_str(&value).map_err(|_| ProvisionerError::InvalidConfig)
}

fn request_header(value: &str) -> Result<HeaderValue, ProvisionerError> {
    HeaderValue::from_str(value).map_err(|_| ProvisionerError::InvalidConfig)
}

fn validate_provider_observation(
    observed_at_unix_ms: i64,
    request_started_at_unix_ms: i64,
) -> Result<(), ProvisionerError> {
    let now = now_unix_ms()?;
    let earliest = request_started_at_unix_ms
        .checked_sub(MAX_CLOCK_SKEW_MS)
        .ok_or(ProvisionerError::InvalidProviderResponse)?;
    let latest = now
        .checked_add(MAX_CLOCK_SKEW_MS)
        .ok_or(ProvisionerError::InvalidProviderResponse)?;
    if !(earliest..=latest).contains(&observed_at_unix_ms) {
        return Err(ProvisionerError::InvalidProviderResponse);
    }
    Ok(())
}

fn valid_text(value: &str, maximum: usize) -> bool {
    !value.trim().is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, ProvisionerError> {
    serde_json::to_vec(value).map_err(|_| ProvisionerError::StateUnavailable)
}

pub fn parse_json_no_duplicates<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ProvisionerError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    DuplicateRejectingSeed
        .deserialize(&mut deserializer)
        .map_err(|_| ProvisionerError::InvalidProviderResponse)?;
    deserializer
        .end()
        .map_err(|_| ProvisionerError::InvalidProviderResponse)?;
    serde_json::from_slice(bytes).map_err(|_| ProvisionerError::InvalidProviderResponse)
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, ProvisionerError> {
    Ok(content_sha256(&canonical_json(value)?))
}

#[must_use]
pub fn content_sha256(bytes: &[u8]) -> String {
    encode_digest(&Sha256::digest(bytes))
}

fn encode_digest(digest: &[u8]) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

fn now_unix_ms() -> Result<i64, ProvisionerError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ProvisionerError::StateUnavailable)?;
    i64::try_from(duration.as_millis()).map_err(|_| ProvisionerError::StateUnavailable)
}

pub async fn read_bounded_regular_file(
    path: &Path,
    maximum: usize,
) -> Result<Vec<u8>, ProvisionerError> {
    let metadata = tokio::fs::symlink_metadata(path)
        .await
        .map_err(|_| ProvisionerError::InvalidConfig)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.len() > maximum as u64
    {
        return Err(ProvisionerError::InvalidConfig);
    }
    let bytes = tokio::fs::read(path)
        .await
        .map_err(|_| ProvisionerError::InvalidConfig)?;
    if bytes.len() > maximum {
        return Err(ProvisionerError::InvalidConfig);
    }
    Ok(bytes)
}

#[cfg(unix)]
pub async fn read_private_bounded_regular_file(
    path: &Path,
    maximum: usize,
) -> Result<Vec<u8>, ProvisionerError> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    use tokio::io::AsyncReadExt as _;

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| ProvisionerError::InvalidConfig)?;
    let metadata = file
        .metadata()
        .map_err(|_| ProvisionerError::InvalidConfig)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || metadata.len() > maximum as u64
    {
        return Err(ProvisionerError::InvalidConfig);
    }
    let mut bytes = Vec::new();
    tokio::fs::File::from_std(file)
        .take((maximum as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| ProvisionerError::InvalidConfig)?;
    if bytes.len() > maximum {
        return Err(ProvisionerError::InvalidConfig);
    }
    Ok(bytes)
}

#[cfg(not(unix))]
pub async fn read_private_bounded_regular_file(
    _path: &Path,
    _maximum: usize,
) -> Result<Vec<u8>, ProvisionerError> {
    Err(ProvisionerError::InvalidConfig)
}

pub async fn sha256_file(path: &Path) -> Result<String, ProvisionerError> {
    use tokio::io::AsyncReadExt as _;

    let metadata = tokio::fs::symlink_metadata(path)
        .await
        .map_err(|_| ProvisionerError::InvalidConfig)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(ProvisionerError::InvalidConfig);
    }
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|_| ProvisionerError::InvalidConfig)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1_024];
    loop {
        let read = file
            .read(&mut buffer)
            .await
            .map_err(|_| ProvisionerError::InvalidConfig)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(encode_digest(&digest.finalize()))
}

#[cfg(unix)]
fn prepare_private_state_dir(path: &Path) -> Result<(), ProvisionerError> {
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};

    if !path.is_absolute() {
        return Err(ProvisionerError::InvalidConfig);
    }
    if !path.exists() {
        let parent = path.parent().ok_or(ProvisionerError::InvalidConfig)?;
        let canonical_parent = parent
            .canonicalize()
            .map_err(|_| ProvisionerError::InvalidConfig)?;
        if canonical_parent != parent {
            return Err(ProvisionerError::InvalidConfig);
        }
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(path) {
            Ok(()) => File::open(parent)
                .and_then(|file| file.sync_all())
                .map_err(|_| ProvisionerError::StateUnavailable)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(ProvisionerError::StateUnavailable),
        }
    }
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| ProvisionerError::StateUnavailable)?;
    let canonical = path
        .canonicalize()
        .map_err(|_| ProvisionerError::StateUnavailable)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o7777 != 0o700
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || canonical != path
    {
        return Err(ProvisionerError::InvalidConfig);
    }
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| ProvisionerError::StateUnavailable)
}

#[cfg(not(unix))]
fn prepare_private_state_dir(_path: &Path) -> Result<(), ProvisionerError> {
    Err(ProvisionerError::InvalidConfig)
}

#[cfg(unix)]
fn prepare_private_database_file(path: &Path) -> Result<(), ProvisionerError> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .mode(0o600)
        .open(path)
        .map_err(|_| ProvisionerError::StateUnavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| ProvisionerError::StateUnavailable)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o600
    {
        return Err(ProvisionerError::InvalidConfig);
    }
    file.sync_all()
        .map_err(|_| ProvisionerError::StateUnavailable)?;
    sync_database_parent(path)
}

#[cfg(not(unix))]
fn prepare_private_database_file(_path: &Path) -> Result<(), ProvisionerError> {
    Err(ProvisionerError::InvalidConfig)
}

fn sync_database_parent(path: &Path) -> Result<(), ProvisionerError> {
    let parent = path.parent().ok_or(ProvisionerError::StateUnavailable)?;
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|_| ProvisionerError::StateUnavailable)
}
