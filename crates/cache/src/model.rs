use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheKind {
    Dependency,
    Build,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CachePolicy {
    pub policy_id: String,
    pub tenant_id: String,
    pub project_id: String,
    pub pipeline_id: String,
    pub trust_class: String,
    pub allowed_kinds: Vec<CacheKind>,
    pub read_principals: Vec<String>,
    pub write_principals: Vec<String>,
    pub max_entry_bytes: u64,
    pub max_total_bytes: u64,
    pub max_entries: u64,
    pub ttl_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheConfig {
    pub protocol_version: String,
    pub service_id: String,
    pub implementation_sha256: String,
    pub deployment_identity: String,
    pub operator_identity: String,
    pub cache_generation: u64,
    pub restore_epoch: u64,
    pub database_path: String,
    pub receipt_key_id: String,
    pub receipt_key_sha256: String,
    pub max_frame_bytes: u64,
    pub max_database_bytes: u64,
    pub max_cleanup_rows: u64,
    pub policies: Vec<CachePolicy>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheKeyRequest {
    pub policy_id: String,
    pub tenant_id: String,
    pub project_id: String,
    pub pipeline_id: String,
    pub trust_class: String,
    pub cache_kind: CacheKind,
    pub restore_epoch: u64,
    pub logical_key_sha256: String,
    pub input_sha256: String,
    pub toolchain_sha256: String,
    pub platform_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CanonicalCacheKey {
    pub schema_version: String,
    pub service_id: String,
    pub policy_id: String,
    pub policy_sha256: String,
    pub tenant_id: String,
    pub project_id: String,
    pub pipeline_id: String,
    pub trust_class: String,
    pub cache_kind: CacheKind,
    pub cache_generation: u64,
    pub generation_sha256: String,
    pub restore_epoch: u64,
    pub logical_key_sha256: String,
    pub input_sha256: String,
    pub toolchain_sha256: String,
    pub platform_sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheOperation {
    Read,
    Publish,
    Evict,
    Cleanup,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheOutcome {
    Miss,
    Hit,
    Published,
    PublicationReplay,
    PublicationConflict,
    Evicted,
    Expired,
    StaleGeneration,
    StaleRestoreEpoch,
    CorruptRejected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEvent {
    pub schema_version: String,
    pub service_id: String,
    pub implementation_sha256: String,
    pub configuration_sha256: String,
    pub operation: CacheOperation,
    pub outcome: CacheOutcome,
    pub caller_id: String,
    pub policy_id: String,
    pub policy_sha256: String,
    pub generation_sha256: String,
    pub restore_epoch: u64,
    pub namespace_sha256: String,
    pub key_sha256: String,
    pub content_sha256: Option<String>,
    pub content_bytes: Option<u64>,
    pub observed_at_unix_ms: i64,
    pub previous_event_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheReceipt {
    pub sequence: u64,
    pub event: AuditEvent,
    pub event_sha256: String,
    pub signature: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadStatus {
    Miss,
    Hit,
    CorruptRejected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadResult {
    pub status: ReadStatus,
    pub content: Option<Vec<u8>>,
    pub receipts: Vec<CacheReceipt>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublishStatus {
    Published,
    Replay,
    Conflict,
    CorruptRejected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishResult {
    pub status: PublishStatus,
    pub receipts: Vec<CacheReceipt>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CleanupResult {
    pub removed: u64,
    pub receipts: Vec<CacheReceipt>,
}
