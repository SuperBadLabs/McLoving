use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use hmac::{Hmac, Mac as _};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension as _, Transaction, TransactionBehavior, params,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::model::{
    AuditEvent, CacheConfig, CacheKeyRequest, CacheOperation, CacheOutcome, CachePolicy,
    CacheReceipt, CanonicalCacheKey, CleanupResult, PublishResult, PublishStatus, ReadResult,
    ReadStatus,
};
use crate::{EVENT_SCHEMA_VERSION, KEY_SCHEMA_VERSION, PROTOCOL_VERSION};

type HmacSha256 = Hmac<Sha256>;
const MAX_IDENTITY_BYTES: usize = 256;
const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub trait Clock: Send + Sync {
    fn now_unix_ms(&self) -> Result<i64, CacheError>;
}

#[derive(Debug)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_ms(&self) -> Result<i64, CacheError> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CacheError::ClockUnavailable)?;
        i64::try_from(duration.as_millis()).map_err(|_| CacheError::ClockUnavailable)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("cache configuration is invalid")]
    InvalidConfig,
    #[error("cache request is invalid")]
    InvalidRequest,
    #[error("cache request is not authorized")]
    Unauthorized,
    #[error("cache entry exceeds its policy quota")]
    EntryQuotaExceeded,
    #[error("cache policy quota cannot admit the entry")]
    PolicyQuotaExceeded,
    #[error("cache state is unavailable")]
    StateUnavailable,
    #[error("cache clock is unavailable")]
    ClockUnavailable,
    #[error("cache protocol frame is malformed")]
    MalformedProtocol,
    #[error("cache audit chain is invalid")]
    InvalidAuditChain,
}

impl CacheError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidConfig => "CACHE_CONFIG_INVALID",
            Self::InvalidRequest => "CACHE_REQUEST_INVALID",
            Self::Unauthorized => "CACHE_REQUEST_UNAUTHORIZED",
            Self::EntryQuotaExceeded => "CACHE_ENTRY_QUOTA_EXCEEDED",
            Self::PolicyQuotaExceeded => "CACHE_POLICY_QUOTA_EXCEEDED",
            Self::StateUnavailable => "CACHE_STATE_UNAVAILABLE",
            Self::ClockUnavailable => "CACHE_CLOCK_UNAVAILABLE",
            Self::MalformedProtocol => "CACHE_PROTOCOL_MALFORMED",
            Self::InvalidAuditChain => "CACHE_AUDIT_INVALID",
        }
    }
}

#[derive(Clone)]
pub struct CacheStore {
    database_path: PathBuf,
    config: CacheConfig,
    configuration_sha256: String,
    generation_sha256: String,
    receipt_key: Arc<Vec<u8>>,
    clock: Arc<dyn Clock>,
}

#[derive(Serialize)]
struct GenerationBinding<'a> {
    protocol_version: &'a str,
    service_id: &'a str,
    configuration_sha256: &'a str,
    cache_generation: u64,
    restore_epoch: u64,
}

#[derive(Serialize)]
struct NamespaceBinding<'a> {
    service_id: &'a str,
    policy_id: &'a str,
    tenant_id: &'a str,
    project_id: &'a str,
    pipeline_id: &'a str,
    trust_class: &'a str,
}

struct AdmittedKey<'a> {
    policy: &'a CachePolicy,
    policy_sha256: String,
    canonical: CanonicalCacheKey,
    canonical_bytes: Vec<u8>,
    namespace_sha256: String,
    key_sha256: String,
}

struct StoredEntry {
    canonical_key: Vec<u8>,
    namespace_sha256: String,
    policy_id: String,
    policy_sha256: String,
    generation_sha256: String,
    restore_epoch: u64,
    content_sha256: String,
    content_bytes: u64,
    content: Vec<u8>,
    publication_event_sha256: String,
    created_at_unix_ms: i64,
    expires_at_unix_ms: i64,
}

struct ReceiptDetails<'a> {
    operation: CacheOperation,
    outcome: CacheOutcome,
    content_sha256: Option<&'a str>,
    content_bytes: Option<u64>,
    observed_at_unix_ms: i64,
}

impl CacheStore {
    pub fn open(config: CacheConfig, receipt_key: Vec<u8>) -> Result<Self, CacheError> {
        Self::open_with_clock(config, receipt_key, Arc::new(SystemClock))
    }

    pub fn open_with_clock(
        config: CacheConfig,
        receipt_key: Vec<u8>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, CacheError> {
        validate_config(&config)?;
        if receipt_key.len() < 32 || sha256(&receipt_key) != config.receipt_key_sha256 {
            return Err(CacheError::InvalidConfig);
        }
        let configuration_sha256 = canonical_digest(&config)?;
        let generation_sha256 = canonical_digest(&GenerationBinding {
            protocol_version: &config.protocol_version,
            service_id: &config.service_id,
            configuration_sha256: &configuration_sha256,
            cache_generation: config.cache_generation,
            restore_epoch: config.restore_epoch,
        })?;
        let database_path = PathBuf::from(&config.database_path);
        initialize_database(
            &database_path,
            &config,
            &configuration_sha256,
            &generation_sha256,
        )?;
        Ok(Self {
            database_path,
            config,
            configuration_sha256,
            generation_sha256,
            receipt_key: Arc::new(receipt_key),
            clock,
        })
    }

    pub fn configuration_sha256(&self) -> &str {
        &self.configuration_sha256
    }

    pub fn generation_sha256(&self) -> &str {
        &self.generation_sha256
    }

    pub fn publish(
        &self,
        caller_id: &str,
        caller_trust_class: &str,
        request: &CacheKeyRequest,
        content: &[u8],
    ) -> Result<PublishResult, CacheError> {
        let admitted = self.admit(caller_id, caller_trust_class, request, true)?;
        let content_bytes =
            u64::try_from(content.len()).map_err(|_| CacheError::EntryQuotaExceeded)?;
        if content_bytes > admitted.policy.max_entry_bytes {
            return Err(CacheError::EntryQuotaExceeded);
        }
        let content_sha256 = sha256(content);
        let now = self.clock.now_unix_ms()?;
        let expires_at = now
            .checked_add(
                i64::try_from(admitted.policy.ttl_ms).map_err(|_| CacheError::InvalidConfig)?,
            )
            .ok_or(CacheError::ClockUnavailable)?;
        let mut connection = self.open_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| CacheError::StateUnavailable)?;
        let mut receipts = Vec::new();
        if let Some(stored) = load_entry(&transaction, &admitted.key_sha256)? {
            if !self.entry_matches(&transaction, &stored, &admitted)?
                || !stored_content_matches(&stored)
            {
                delete_entry(&transaction, &admitted.key_sha256)?;
                receipts.push(self.append_receipt(
                    &transaction,
                    caller_id,
                    &admitted,
                    ReceiptDetails {
                        operation: CacheOperation::Publish,
                        outcome: CacheOutcome::CorruptRejected,
                        content_sha256: Some(&stored.content_sha256),
                        content_bytes: Some(stored.content_bytes),
                        observed_at_unix_ms: now,
                    },
                )?);
                transaction
                    .commit()
                    .map_err(|_| CacheError::StateUnavailable)?;
                return Ok(PublishResult {
                    status: PublishStatus::CorruptRejected,
                    receipts,
                });
            }
            if stored.expires_at_unix_ms <= now {
                delete_entry(&transaction, &admitted.key_sha256)?;
                receipts.push(self.append_receipt(
                    &transaction,
                    caller_id,
                    &admitted,
                    ReceiptDetails {
                        operation: CacheOperation::Evict,
                        outcome: CacheOutcome::Expired,
                        content_sha256: Some(&stored.content_sha256),
                        content_bytes: Some(stored.content_bytes),
                        observed_at_unix_ms: now,
                    },
                )?);
            } else {
                let (status, outcome) = if stored.content_sha256 == content_sha256
                    && stored.content_bytes == content_bytes
                    && stored.content == content
                {
                    (PublishStatus::Replay, CacheOutcome::PublicationReplay)
                } else {
                    (PublishStatus::Conflict, CacheOutcome::PublicationConflict)
                };
                receipts.push(self.append_receipt(
                    &transaction,
                    caller_id,
                    &admitted,
                    ReceiptDetails {
                        operation: CacheOperation::Publish,
                        outcome,
                        content_sha256: Some(&content_sha256),
                        content_bytes: Some(content_bytes),
                        observed_at_unix_ms: now,
                    },
                )?);
                transaction
                    .commit()
                    .map_err(|_| CacheError::StateUnavailable)?;
                return Ok(PublishResult { status, receipts });
            }
        }

        self.remove_stale_for_policy(&transaction, caller_id, &admitted, now, &mut receipts)?;
        self.evict_to_fit(
            &transaction,
            caller_id,
            &admitted,
            content_bytes,
            now,
            &mut receipts,
        )?;
        transaction
            .execute(
                "INSERT INTO entries(
                    namespace_sha256, key_sha256, canonical_key, policy_id, policy_sha256,
                    generation_sha256, restore_epoch, content_sha256, content_bytes, content,
                    publication_event_sha256, created_at_unix_ms, expires_at_unix_ms,
                    last_access_sequence
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, '', ?11, ?12, 0)",
                params![
                    admitted.namespace_sha256,
                    admitted.key_sha256,
                    admitted.canonical_bytes,
                    admitted.policy.policy_id,
                    admitted.policy_sha256,
                    self.generation_sha256,
                    to_i64(self.config.restore_epoch)?,
                    content_sha256,
                    to_i64(content_bytes)?,
                    content,
                    now,
                    expires_at,
                ],
            )
            .map_err(|_| CacheError::StateUnavailable)?;
        let receipt = self.append_receipt(
            &transaction,
            caller_id,
            &admitted,
            ReceiptDetails {
                operation: CacheOperation::Publish,
                outcome: CacheOutcome::Published,
                content_sha256: Some(&content_sha256),
                content_bytes: Some(content_bytes),
                observed_at_unix_ms: now,
            },
        )?;
        transaction
            .execute(
                "UPDATE entries
                 SET last_access_sequence = ?1, publication_event_sha256 = ?2
                 WHERE key_sha256 = ?3",
                params![
                    to_i64(receipt.sequence)?,
                    receipt.event_sha256,
                    admitted.key_sha256
                ],
            )
            .map_err(|_| CacheError::StateUnavailable)?;
        receipts.push(receipt);
        transaction
            .commit()
            .map_err(|_| CacheError::StateUnavailable)?;
        Ok(PublishResult {
            status: PublishStatus::Published,
            receipts,
        })
    }

    pub fn read(
        &self,
        caller_id: &str,
        caller_trust_class: &str,
        request: &CacheKeyRequest,
    ) -> Result<ReadResult, CacheError> {
        let admitted = self.admit(caller_id, caller_trust_class, request, false)?;
        let now = self.clock.now_unix_ms()?;
        let mut connection = self.open_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| CacheError::StateUnavailable)?;
        let Some(stored) = load_entry(&transaction, &admitted.key_sha256)? else {
            let receipt = self.append_receipt(
                &transaction,
                caller_id,
                &admitted,
                ReceiptDetails {
                    operation: CacheOperation::Read,
                    outcome: CacheOutcome::Miss,
                    content_sha256: None,
                    content_bytes: None,
                    observed_at_unix_ms: now,
                },
            )?;
            transaction
                .commit()
                .map_err(|_| CacheError::StateUnavailable)?;
            return Ok(ReadResult {
                status: ReadStatus::Miss,
                content: None,
                receipts: vec![receipt],
            });
        };
        if !self.entry_matches(&transaction, &stored, &admitted)?
            || !stored_content_matches(&stored)
        {
            delete_entry(&transaction, &admitted.key_sha256)?;
            let receipt = self.append_receipt(
                &transaction,
                caller_id,
                &admitted,
                ReceiptDetails {
                    operation: CacheOperation::Read,
                    outcome: CacheOutcome::CorruptRejected,
                    content_sha256: Some(&stored.content_sha256),
                    content_bytes: Some(stored.content_bytes),
                    observed_at_unix_ms: now,
                },
            )?;
            transaction
                .commit()
                .map_err(|_| CacheError::StateUnavailable)?;
            return Ok(ReadResult {
                status: ReadStatus::CorruptRejected,
                content: None,
                receipts: vec![receipt],
            });
        }
        if stored.expires_at_unix_ms <= now {
            delete_entry(&transaction, &admitted.key_sha256)?;
            let expired = self.append_receipt(
                &transaction,
                caller_id,
                &admitted,
                ReceiptDetails {
                    operation: CacheOperation::Evict,
                    outcome: CacheOutcome::Expired,
                    content_sha256: Some(&stored.content_sha256),
                    content_bytes: Some(stored.content_bytes),
                    observed_at_unix_ms: now,
                },
            )?;
            let miss = self.append_receipt(
                &transaction,
                caller_id,
                &admitted,
                ReceiptDetails {
                    operation: CacheOperation::Read,
                    outcome: CacheOutcome::Miss,
                    content_sha256: None,
                    content_bytes: None,
                    observed_at_unix_ms: now,
                },
            )?;
            transaction
                .commit()
                .map_err(|_| CacheError::StateUnavailable)?;
            return Ok(ReadResult {
                status: ReadStatus::Miss,
                content: None,
                receipts: vec![expired, miss],
            });
        }
        let receipt = self.append_receipt(
            &transaction,
            caller_id,
            &admitted,
            ReceiptDetails {
                operation: CacheOperation::Read,
                outcome: CacheOutcome::Hit,
                content_sha256: Some(&stored.content_sha256),
                content_bytes: Some(stored.content_bytes),
                observed_at_unix_ms: now,
            },
        )?;
        transaction
            .execute(
                "UPDATE entries SET last_access_sequence = ?1 WHERE key_sha256 = ?2",
                params![to_i64(receipt.sequence)?, admitted.key_sha256],
            )
            .map_err(|_| CacheError::StateUnavailable)?;
        transaction
            .commit()
            .map_err(|_| CacheError::StateUnavailable)?;
        Ok(ReadResult {
            status: ReadStatus::Hit,
            content: Some(stored.content),
            receipts: vec![receipt],
        })
    }

    pub fn cleanup(&self, caller_id: &str) -> Result<CleanupResult, CacheError> {
        if caller_id != self.config.operator_identity {
            return Err(CacheError::Unauthorized);
        }
        let now = self.clock.now_unix_ms()?;
        let mut connection = self.open_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| CacheError::StateUnavailable)?;
        let limit = to_i64(self.config.max_cleanup_rows)?;
        let candidates = {
            let mut statement = transaction
                .prepare(
                    "SELECT key_sha256, canonical_key, namespace_sha256, policy_id,
                            policy_sha256, generation_sha256, restore_epoch, content_sha256,
                            content_bytes, content, publication_event_sha256,
                            created_at_unix_ms, expires_at_unix_ms
                     FROM entries
                     WHERE expires_at_unix_ms <= ?1
                        OR generation_sha256 <> ?2
                        OR restore_epoch <> ?3
                     ORDER BY key_sha256
                     LIMIT ?4",
                )
                .map_err(|_| CacheError::StateUnavailable)?;
            let rows = statement
                .query_map(
                    params![
                        now,
                        self.generation_sha256,
                        to_i64(self.config.restore_epoch)?,
                        limit
                    ],
                    stored_entry_from_cleanup_row,
                )
                .map_err(|_| CacheError::StateUnavailable)?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|_| CacheError::StateUnavailable)?
        };
        let mut receipts = Vec::with_capacity(candidates.len());
        for (key_sha256, policy_id, stored) in candidates {
            let admitted = self.admitted_from_stored(&policy_id, &key_sha256, &stored)?;
            let outcome = stale_outcome(
                &stored,
                &self.generation_sha256,
                self.config.restore_epoch,
                now,
            );
            delete_entry(&transaction, &key_sha256)?;
            receipts.push(self.append_receipt(
                &transaction,
                caller_id,
                &admitted,
                ReceiptDetails {
                    operation: CacheOperation::Cleanup,
                    outcome,
                    content_sha256: Some(&stored.content_sha256),
                    content_bytes: Some(stored.content_bytes),
                    observed_at_unix_ms: now,
                },
            )?);
        }
        let removed = u64::try_from(receipts.len()).map_err(|_| CacheError::StateUnavailable)?;
        transaction
            .commit()
            .map_err(|_| CacheError::StateUnavailable)?;
        Ok(CleanupResult { removed, receipts })
    }

    pub fn verify_audit_chain(&self) -> Result<u64, CacheError> {
        self.audit_state().map(|state| state.0)
    }

    pub fn verify_audit_chain_against(
        &self,
        expected_events: u64,
        expected_head_sha256: &str,
    ) -> Result<(), CacheError> {
        if !valid_digest(expected_head_sha256) {
            return Err(CacheError::InvalidAuditChain);
        }
        let observed = self.audit_state()?;
        if observed.0 != expected_events || observed.1 != expected_head_sha256 {
            return Err(CacheError::InvalidAuditChain);
        }
        Ok(())
    }

    fn audit_state(&self) -> Result<(u64, String), CacheError> {
        let connection = self.open_connection()?;
        let mut statement = connection
            .prepare(
                "SELECT sequence, event_json, event_sha256, signature
                 FROM audit_events ORDER BY sequence",
            )
            .map_err(|_| CacheError::StateUnavailable)?;
        let mut rows = statement
            .query([])
            .map_err(|_| CacheError::StateUnavailable)?;
        let mut expected_sequence = 1_u64;
        let mut previous = ZERO_DIGEST.to_owned();
        while let Some(row) = rows.next().map_err(|_| CacheError::StateUnavailable)? {
            let sequence = u64::try_from(
                row.get::<_, i64>(0)
                    .map_err(|_| CacheError::InvalidAuditChain)?,
            )
            .map_err(|_| CacheError::InvalidAuditChain)?;
            let event_json: Vec<u8> = row.get(1).map_err(|_| CacheError::InvalidAuditChain)?;
            let event_sha256: String = row.get(2).map_err(|_| CacheError::InvalidAuditChain)?;
            let signature: String = row.get(3).map_err(|_| CacheError::InvalidAuditChain)?;
            let event: AuditEvent =
                serde_json::from_slice(&event_json).map_err(|_| CacheError::InvalidAuditChain)?;
            if sequence != expected_sequence
                || event.previous_event_sha256 != previous
                || canonical_bytes(&event)? != event_json
                || event_digest(&event_json) != event_sha256
                || !self.verify_signature(&event_sha256, &signature)
            {
                return Err(CacheError::InvalidAuditChain);
            }
            previous = event_sha256;
            expected_sequence = expected_sequence
                .checked_add(1)
                .ok_or(CacheError::InvalidAuditChain)?;
        }
        Ok((expected_sequence - 1, previous))
    }

    fn admit<'a>(
        &'a self,
        caller_id: &str,
        caller_trust_class: &str,
        request: &CacheKeyRequest,
        write: bool,
    ) -> Result<AdmittedKey<'a>, CacheError> {
        if !valid_identity(caller_id) || !valid_identity(caller_trust_class) {
            return Err(CacheError::InvalidRequest);
        }
        if request.restore_epoch != self.config.restore_epoch
            || !valid_digest(&request.logical_key_sha256)
            || !valid_digest(&request.input_sha256)
            || !valid_digest(&request.toolchain_sha256)
            || !valid_digest(&request.platform_sha256)
        {
            return Err(CacheError::InvalidRequest);
        }
        let policy = self
            .config
            .policies
            .binary_search_by(|candidate| candidate.policy_id.as_str().cmp(&request.policy_id))
            .ok()
            .map(|index| &self.config.policies[index])
            .ok_or(CacheError::Unauthorized)?;
        let principals = if write {
            &policy.write_principals
        } else {
            &policy.read_principals
        };
        if policy.tenant_id != request.tenant_id
            || policy.project_id != request.project_id
            || policy.pipeline_id != request.pipeline_id
            || policy.trust_class != request.trust_class
            || policy.trust_class != caller_trust_class
            || policy
                .allowed_kinds
                .binary_search(&request.cache_kind)
                .is_err()
            || principals
                .binary_search_by(|principal| principal.as_str().cmp(caller_id))
                .is_err()
        {
            return Err(CacheError::Unauthorized);
        }
        let policy_sha256 = canonical_digest(policy)?;
        let canonical = CanonicalCacheKey {
            schema_version: KEY_SCHEMA_VERSION.to_owned(),
            service_id: self.config.service_id.clone(),
            policy_id: policy.policy_id.clone(),
            policy_sha256: policy_sha256.clone(),
            tenant_id: request.tenant_id.clone(),
            project_id: request.project_id.clone(),
            pipeline_id: request.pipeline_id.clone(),
            trust_class: request.trust_class.clone(),
            cache_kind: request.cache_kind,
            cache_generation: self.config.cache_generation,
            generation_sha256: self.generation_sha256.clone(),
            restore_epoch: request.restore_epoch,
            logical_key_sha256: request.logical_key_sha256.clone(),
            input_sha256: request.input_sha256.clone(),
            toolchain_sha256: request.toolchain_sha256.clone(),
            platform_sha256: request.platform_sha256.clone(),
        };
        let canonical_bytes = canonical_bytes(&canonical)?;
        let namespace_sha256 = canonical_digest(&NamespaceBinding {
            service_id: &self.config.service_id,
            policy_id: &policy.policy_id,
            tenant_id: &policy.tenant_id,
            project_id: &policy.project_id,
            pipeline_id: &policy.pipeline_id,
            trust_class: &policy.trust_class,
        })?;
        let key_sha256 = domain_digest(b"mcloving.cache-key/v1\0", &canonical_bytes);
        Ok(AdmittedKey {
            policy,
            policy_sha256,
            canonical,
            canonical_bytes,
            namespace_sha256,
            key_sha256,
        })
    }

    fn admitted_from_stored<'a>(
        &'a self,
        policy_id: &str,
        key_sha256: &str,
        stored: &StoredEntry,
    ) -> Result<AdmittedKey<'a>, CacheError> {
        let policy = self
            .config
            .policies
            .binary_search_by(|candidate| candidate.policy_id.as_str().cmp(policy_id))
            .ok()
            .map(|index| &self.config.policies[index])
            .ok_or(CacheError::StateUnavailable)?;
        let canonical: CanonicalCacheKey = serde_json::from_slice(&stored.canonical_key)
            .map_err(|_| CacheError::StateUnavailable)?;
        Ok(AdmittedKey {
            policy,
            policy_sha256: stored.policy_sha256.clone(),
            canonical,
            canonical_bytes: stored.canonical_key.clone(),
            namespace_sha256: stored.namespace_sha256.clone(),
            key_sha256: key_sha256.to_owned(),
        })
    }

    fn open_connection(&self) -> Result<Connection, CacheError> {
        open_database(&self.database_path, false)
    }

    fn append_receipt(
        &self,
        transaction: &Transaction<'_>,
        caller_id: &str,
        admitted: &AdmittedKey<'_>,
        details: ReceiptDetails<'_>,
    ) -> Result<CacheReceipt, CacheError> {
        let previous = transaction
            .query_row(
                "SELECT event_sha256 FROM audit_events ORDER BY sequence DESC LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| CacheError::StateUnavailable)?
            .unwrap_or_else(|| ZERO_DIGEST.to_owned());
        let event = AuditEvent {
            schema_version: EVENT_SCHEMA_VERSION.to_owned(),
            service_id: self.config.service_id.clone(),
            implementation_sha256: self.config.implementation_sha256.clone(),
            configuration_sha256: self.configuration_sha256.clone(),
            operation: details.operation,
            outcome: details.outcome,
            caller_id: caller_id.to_owned(),
            policy_id: admitted.policy.policy_id.clone(),
            policy_sha256: admitted.policy_sha256.clone(),
            generation_sha256: admitted.canonical.generation_sha256.clone(),
            restore_epoch: admitted.canonical.restore_epoch,
            namespace_sha256: admitted.namespace_sha256.clone(),
            key_sha256: admitted.key_sha256.clone(),
            content_sha256: details.content_sha256.map(str::to_owned),
            content_bytes: details.content_bytes,
            observed_at_unix_ms: details.observed_at_unix_ms,
            previous_event_sha256: previous,
        };
        let event_json = canonical_bytes(&event)?;
        let event_sha256 = event_digest(&event_json);
        let signature = self.sign(&event_sha256)?;
        transaction
            .execute(
                "INSERT INTO audit_events(event_json, event_sha256, signature) VALUES (?1, ?2, ?3)",
                params![event_json, event_sha256, signature],
            )
            .map_err(|_| CacheError::StateUnavailable)?;
        let sequence = u64::try_from(transaction.last_insert_rowid())
            .map_err(|_| CacheError::StateUnavailable)?;
        Ok(CacheReceipt {
            sequence,
            event,
            event_sha256,
            signature,
        })
    }

    fn entry_matches(
        &self,
        transaction: &Transaction<'_>,
        stored: &StoredEntry,
        admitted: &AdmittedKey<'_>,
    ) -> Result<bool, CacheError> {
        let expected_expiry = stored
            .created_at_unix_ms
            .checked_add(
                i64::try_from(admitted.policy.ttl_ms).map_err(|_| CacheError::InvalidConfig)?,
            )
            .ok_or(CacheError::StateUnavailable)?;
        if stored.canonical_key != admitted.canonical_bytes
            || stored.namespace_sha256 != admitted.namespace_sha256
            || stored.policy_id != admitted.policy.policy_id
            || stored.policy_sha256 != admitted.policy_sha256
            || stored.generation_sha256 != admitted.canonical.generation_sha256
            || stored.restore_epoch != admitted.canonical.restore_epoch
            || stored.expires_at_unix_ms != expected_expiry
            || !valid_digest(&stored.publication_event_sha256)
        {
            return Ok(false);
        }
        let publication = transaction
            .query_row(
                "SELECT event_json, event_sha256, signature
                 FROM audit_events WHERE event_sha256 = ?1",
                [&stored.publication_event_sha256],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| CacheError::StateUnavailable)?;
        let Some((event_json, event_sha256, signature)) = publication else {
            return Ok(false);
        };
        let event: AuditEvent = match serde_json::from_slice(&event_json) {
            Ok(event) => event,
            Err(_) => return Ok(false),
        };
        Ok(canonical_bytes(&event)? == event_json
            && event_digest(&event_json) == event_sha256
            && event_sha256 == stored.publication_event_sha256
            && self.verify_signature(&event_sha256, &signature)
            && event.schema_version == EVENT_SCHEMA_VERSION
            && event.service_id == self.config.service_id
            && event.implementation_sha256 == self.config.implementation_sha256
            && event.configuration_sha256 == self.configuration_sha256
            && event.operation == CacheOperation::Publish
            && event.outcome == CacheOutcome::Published
            && admitted
                .policy
                .write_principals
                .binary_search(&event.caller_id)
                .is_ok()
            && event.policy_id == admitted.policy.policy_id
            && event.policy_sha256 == admitted.policy_sha256
            && event.generation_sha256 == admitted.canonical.generation_sha256
            && event.restore_epoch == admitted.canonical.restore_epoch
            && event.namespace_sha256 == admitted.namespace_sha256
            && event.key_sha256 == admitted.key_sha256
            && event.content_sha256.as_deref() == Some(stored.content_sha256.as_str())
            && event.content_bytes == Some(stored.content_bytes)
            && event.observed_at_unix_ms == stored.created_at_unix_ms)
    }

    fn sign(&self, digest: &str) -> Result<String, CacheError> {
        let mut mac =
            HmacSha256::new_from_slice(&self.receipt_key).map_err(|_| CacheError::InvalidConfig)?;
        mac.update(digest.as_bytes());
        Ok(BASE64.encode(mac.finalize().into_bytes()))
    }

    fn verify_signature(&self, digest: &str, signature: &str) -> bool {
        let Ok(signature) = BASE64.decode(signature) else {
            return false;
        };
        let Ok(mut mac) = HmacSha256::new_from_slice(&self.receipt_key) else {
            return false;
        };
        mac.update(digest.as_bytes());
        mac.verify_slice(&signature).is_ok()
    }

    fn remove_stale_for_policy(
        &self,
        transaction: &Transaction<'_>,
        caller_id: &str,
        admitted: &AdmittedKey<'_>,
        now: i64,
        receipts: &mut Vec<CacheReceipt>,
    ) -> Result<(), CacheError> {
        let limit = to_i64(self.config.max_cleanup_rows)?;
        let candidates = select_policy_candidates(
            transaction,
            &admitted.policy.policy_id,
            now,
            &self.generation_sha256,
            self.config.restore_epoch,
            limit,
        )?;
        for (key_sha256, stored) in candidates {
            let candidate =
                self.admitted_from_stored(&admitted.policy.policy_id, &key_sha256, &stored)?;
            let outcome = stale_outcome(
                &stored,
                &self.generation_sha256,
                self.config.restore_epoch,
                now,
            );
            delete_entry(transaction, &key_sha256)?;
            receipts.push(self.append_receipt(
                transaction,
                caller_id,
                &candidate,
                ReceiptDetails {
                    operation: CacheOperation::Evict,
                    outcome,
                    content_sha256: Some(&stored.content_sha256),
                    content_bytes: Some(stored.content_bytes),
                    observed_at_unix_ms: now,
                },
            )?);
        }
        Ok(())
    }

    fn evict_to_fit(
        &self,
        transaction: &Transaction<'_>,
        caller_id: &str,
        admitted: &AdmittedKey<'_>,
        incoming_bytes: u64,
        now: i64,
        receipts: &mut Vec<CacheReceipt>,
    ) -> Result<(), CacheError> {
        loop {
            let (entry_count, total_bytes): (i64, i64) = transaction
                .query_row(
                    "SELECT count(*), COALESCE(sum(content_bytes), 0)
                     FROM entries WHERE policy_id = ?1",
                    [&admitted.policy.policy_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(|_| CacheError::StateUnavailable)?;
            let entry_count =
                u64::try_from(entry_count).map_err(|_| CacheError::StateUnavailable)?;
            let total_bytes =
                u64::try_from(total_bytes).map_err(|_| CacheError::StateUnavailable)?;
            let count_fits = entry_count < admitted.policy.max_entries;
            let bytes_fit = total_bytes
                .checked_add(incoming_bytes)
                .is_some_and(|value| value <= admitted.policy.max_total_bytes);
            if count_fits && bytes_fit {
                return Ok(());
            }
            let candidate = transaction
                .query_row(
                    "SELECT key_sha256, canonical_key, namespace_sha256, policy_id,
                            policy_sha256, generation_sha256, restore_epoch, content_sha256,
                            content_bytes, content, publication_event_sha256,
                            created_at_unix_ms, expires_at_unix_ms
                     FROM entries WHERE policy_id = ?1
                     ORDER BY last_access_sequence, created_at_unix_ms, key_sha256 LIMIT 1",
                    [&admitted.policy.policy_id],
                    stored_entry_from_policy_row,
                )
                .optional()
                .map_err(|_| CacheError::StateUnavailable)?
                .ok_or(CacheError::PolicyQuotaExceeded)?;
            let (key_sha256, stored) = candidate;
            let candidate =
                self.admitted_from_stored(&admitted.policy.policy_id, &key_sha256, &stored)?;
            delete_entry(transaction, &key_sha256)?;
            receipts.push(self.append_receipt(
                transaction,
                caller_id,
                &candidate,
                ReceiptDetails {
                    operation: CacheOperation::Evict,
                    outcome: CacheOutcome::Evicted,
                    content_sha256: Some(&stored.content_sha256),
                    content_bytes: Some(stored.content_bytes),
                    observed_at_unix_ms: now,
                },
            )?);
        }
    }
}

fn validate_config(config: &CacheConfig) -> Result<(), CacheError> {
    if config.protocol_version != PROTOCOL_VERSION
        || !valid_identity(&config.service_id)
        || !valid_digest(&config.implementation_sha256)
        || !valid_identity(&config.deployment_identity)
        || !valid_identity(&config.operator_identity)
        || config.cache_generation == 0
        || !Path::new(&config.database_path).is_absolute()
        || !valid_identity(&config.receipt_key_id)
        || !valid_digest(&config.receipt_key_sha256)
        || config.max_frame_bytes < 1_024
        || config.max_database_bytes == 0
        || config.max_cleanup_rows == 0
        || config.max_cleanup_rows > 10_000
        || config.policies.is_empty()
        || !strictly_sorted_by(&config.policies, |policy| policy.policy_id.as_str())
    {
        return Err(CacheError::InvalidConfig);
    }
    let mut total_policy_bytes = 0_u64;
    for policy in &config.policies {
        if !valid_identity(&policy.policy_id)
            || !valid_identity(&policy.tenant_id)
            || !valid_identity(&policy.project_id)
            || !valid_identity(&policy.pipeline_id)
            || !valid_identity(&policy.trust_class)
            || policy.allowed_kinds.is_empty()
            || !strictly_sorted(&policy.allowed_kinds)
            || policy.read_principals.is_empty()
            || policy.write_principals.is_empty()
            || !strictly_sorted_by(&policy.read_principals, String::as_str)
            || !strictly_sorted_by(&policy.write_principals, String::as_str)
            || policy
                .read_principals
                .iter()
                .any(|value| !valid_identity(value))
            || policy
                .write_principals
                .iter()
                .any(|value| !valid_identity(value))
            || policy.max_entry_bytes == 0
            || policy.max_entry_bytes > policy.max_total_bytes
            || policy.max_entries == 0
            || policy.ttl_ms == 0
            || policy.ttl_ms > i64::MAX as u64
        {
            return Err(CacheError::InvalidConfig);
        }
        total_policy_bytes = total_policy_bytes
            .checked_add(policy.max_total_bytes)
            .ok_or(CacheError::InvalidConfig)?;
    }
    if total_policy_bytes > config.max_database_bytes {
        return Err(CacheError::InvalidConfig);
    }
    Ok(())
}

fn initialize_database(
    path: &Path,
    config: &CacheConfig,
    configuration_sha256: &str,
    generation_sha256: &str,
) -> Result<(), CacheError> {
    prepare_private_database(path)?;
    let connection = open_database(path, true)?;
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS metadata (
                 singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                 schema_version INTEGER NOT NULL CHECK (schema_version = 1),
                 service_id TEXT NOT NULL,
                 receipt_key_id TEXT NOT NULL
             ) STRICT;
             CREATE TABLE IF NOT EXISTS runtime_generations (
                 configuration_sha256 TEXT PRIMARY KEY,
                 implementation_sha256 TEXT NOT NULL,
                 cache_generation INTEGER NOT NULL CHECK (cache_generation > 0),
                 restore_epoch INTEGER NOT NULL CHECK (restore_epoch >= 0),
                 generation_sha256 TEXT NOT NULL UNIQUE
             ) STRICT;
             CREATE TABLE IF NOT EXISTS entries (
                 namespace_sha256 TEXT NOT NULL,
                 key_sha256 TEXT PRIMARY KEY,
                 canonical_key BLOB NOT NULL,
                 policy_id TEXT NOT NULL,
                 policy_sha256 TEXT NOT NULL,
                 generation_sha256 TEXT NOT NULL,
                 restore_epoch INTEGER NOT NULL CHECK (restore_epoch >= 0),
                 content_sha256 TEXT NOT NULL,
                 content_bytes INTEGER NOT NULL CHECK (content_bytes >= 0),
                 content BLOB NOT NULL,
                 publication_event_sha256 TEXT NOT NULL,
                 created_at_unix_ms INTEGER NOT NULL,
                 expires_at_unix_ms INTEGER NOT NULL,
                 last_access_sequence INTEGER NOT NULL CHECK (last_access_sequence >= 0)
             ) STRICT;
             CREATE INDEX IF NOT EXISTS entries_policy_lru
                 ON entries(policy_id, last_access_sequence, created_at_unix_ms, key_sha256);
             CREATE TABLE IF NOT EXISTS audit_events (
                 sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                 event_json BLOB NOT NULL,
                 event_sha256 TEXT NOT NULL UNIQUE,
                 signature TEXT NOT NULL
             ) STRICT;",
        )
        .map_err(|_| CacheError::StateUnavailable)?;
    connection
        .execute(
            "INSERT INTO metadata(singleton, schema_version, service_id, receipt_key_id)
             VALUES (1, 1, ?1, ?2) ON CONFLICT(singleton) DO NOTHING",
            params![config.service_id, config.receipt_key_id],
        )
        .map_err(|_| CacheError::StateUnavailable)?;
    let stored: (String, String) = connection
        .query_row(
            "SELECT service_id, receipt_key_id FROM metadata WHERE singleton = 1 AND schema_version = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| CacheError::StateUnavailable)?;
    if stored.0 != config.service_id || stored.1 != config.receipt_key_id {
        return Err(CacheError::StateUnavailable);
    }
    connection
        .execute(
            "INSERT INTO runtime_generations(
                 configuration_sha256, implementation_sha256, cache_generation,
                 restore_epoch, generation_sha256
             ) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(configuration_sha256) DO NOTHING",
            params![
                configuration_sha256,
                config.implementation_sha256,
                to_i64(config.cache_generation)?,
                to_i64(config.restore_epoch)?,
                generation_sha256,
            ],
        )
        .map_err(|_| CacheError::StateUnavailable)?;
    let stored_generation: (String, i64, i64, String) = connection
        .query_row(
            "SELECT implementation_sha256, cache_generation, restore_epoch, generation_sha256
             FROM runtime_generations WHERE configuration_sha256 = ?1",
            [configuration_sha256],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|_| CacheError::StateUnavailable)?;
    if stored_generation.0 != config.implementation_sha256
        || stored_generation.1 != to_i64(config.cache_generation)?
        || stored_generation.2 != to_i64(config.restore_epoch)?
        || stored_generation.3 != generation_sha256
    {
        return Err(CacheError::StateUnavailable);
    }
    let integrity: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(|_| CacheError::StateUnavailable)?;
    if integrity != "ok" {
        return Err(CacheError::StateUnavailable);
    }
    Ok(())
}

#[cfg(unix)]
fn prepare_private_database(path: &Path) -> Result<(), CacheError> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    let parent = path.parent().ok_or(CacheError::InvalidConfig)?;
    let canonical_parent = parent
        .canonicalize()
        .map_err(|_| CacheError::InvalidConfig)?;
    let parent_metadata =
        std::fs::symlink_metadata(parent).map_err(|_| CacheError::InvalidConfig)?;
    if canonical_parent != parent
        || !parent_metadata.file_type().is_dir()
        || parent_metadata.file_type().is_symlink()
        || parent_metadata.uid() != nix::unistd::geteuid().as_raw()
        || parent_metadata.mode() & 0o077 != 0
    {
        return Err(CacheError::InvalidConfig);
    }
    if !path.exists() {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|_| CacheError::StateUnavailable)?;
        file.sync_all().map_err(|_| CacheError::StateUnavailable)?;
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| CacheError::StateUnavailable)?;
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|_| CacheError::StateUnavailable)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(CacheError::InvalidConfig);
    }
    Ok(())
}

#[cfg(not(unix))]
fn prepare_private_database(path: &Path) -> Result<(), CacheError> {
    let parent = path.parent().ok_or(CacheError::InvalidConfig)?;
    if !parent.is_dir() {
        return Err(CacheError::InvalidConfig);
    }
    if path.exists() {
        let metadata = std::fs::symlink_metadata(path).map_err(|_| CacheError::StateUnavailable)?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(CacheError::InvalidConfig);
        }
    }
    Ok(())
}

fn open_database(path: &Path, create: bool) -> Result<Connection, CacheError> {
    let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_FULL_MUTEX;
    if create {
        flags |= OpenFlags::SQLITE_OPEN_CREATE;
    }
    let connection =
        Connection::open_with_flags(path, flags).map_err(|_| CacheError::StateUnavailable)?;
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(|_| CacheError::StateUnavailable)?;
    connection
        .execute_batch(
            "PRAGMA journal_mode = DELETE;
             PRAGMA synchronous = FULL;
             PRAGMA foreign_keys = ON;
             PRAGMA trusted_schema = OFF;",
        )
        .map_err(|_| CacheError::StateUnavailable)?;
    Ok(connection)
}

fn load_entry(
    transaction: &Transaction<'_>,
    key_sha256: &str,
) -> Result<Option<StoredEntry>, CacheError> {
    transaction
        .query_row(
            "SELECT canonical_key, namespace_sha256, policy_id, policy_sha256,
                    generation_sha256, restore_epoch, content_sha256, content_bytes, content,
                    publication_event_sha256, created_at_unix_ms, expires_at_unix_ms
             FROM entries WHERE key_sha256 = ?1",
            [key_sha256],
            stored_entry_from_row,
        )
        .optional()
        .map_err(|_| CacheError::StateUnavailable)
}

fn stored_entry_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredEntry> {
    Ok(StoredEntry {
        canonical_key: row.get(0)?,
        namespace_sha256: row.get(1)?,
        policy_id: row.get(2)?,
        policy_sha256: row.get(3)?,
        generation_sha256: row.get(4)?,
        restore_epoch: u64::try_from(row.get::<_, i64>(5)?).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                5,
                rusqlite::types::Type::Integer,
                Box::new(error),
            )
        })?,
        content_sha256: row.get(6)?,
        content_bytes: u64::try_from(row.get::<_, i64>(7)?).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                7,
                rusqlite::types::Type::Integer,
                Box::new(error),
            )
        })?,
        content: row.get(8)?,
        publication_event_sha256: row.get(9)?,
        created_at_unix_ms: row.get(10)?,
        expires_at_unix_ms: row.get(11)?,
    })
}

fn stored_entry_from_policy_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<(String, StoredEntry)> {
    let key_sha256 = row.get(0)?;
    let stored = StoredEntry {
        canonical_key: row.get(1)?,
        namespace_sha256: row.get(2)?,
        policy_id: row.get(3)?,
        policy_sha256: row.get(4)?,
        generation_sha256: row.get(5)?,
        restore_epoch: u64::try_from(row.get::<_, i64>(6)?).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                6,
                rusqlite::types::Type::Integer,
                Box::new(error),
            )
        })?,
        content_sha256: row.get(7)?,
        content_bytes: u64::try_from(row.get::<_, i64>(8)?).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                8,
                rusqlite::types::Type::Integer,
                Box::new(error),
            )
        })?,
        content: row.get(9)?,
        publication_event_sha256: row.get(10)?,
        created_at_unix_ms: row.get(11)?,
        expires_at_unix_ms: row.get(12)?,
    };
    Ok((key_sha256, stored))
}

fn stored_entry_from_cleanup_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<(String, String, StoredEntry)> {
    let key_sha256 = row.get(0)?;
    let policy_id = row.get(3)?;
    let stored = StoredEntry {
        canonical_key: row.get(1)?,
        namespace_sha256: row.get(2)?,
        policy_id: row.get(3)?,
        policy_sha256: row.get(4)?,
        generation_sha256: row.get(5)?,
        restore_epoch: u64::try_from(row.get::<_, i64>(6)?).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                6,
                rusqlite::types::Type::Integer,
                Box::new(error),
            )
        })?,
        content_sha256: row.get(7)?,
        content_bytes: u64::try_from(row.get::<_, i64>(8)?).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                8,
                rusqlite::types::Type::Integer,
                Box::new(error),
            )
        })?,
        content: row.get(9)?,
        publication_event_sha256: row.get(10)?,
        created_at_unix_ms: row.get(11)?,
        expires_at_unix_ms: row.get(12)?,
    };
    Ok((key_sha256, policy_id, stored))
}

fn select_policy_candidates(
    transaction: &Transaction<'_>,
    policy_id: &str,
    now: i64,
    generation_sha256: &str,
    restore_epoch: u64,
    limit: i64,
) -> Result<Vec<(String, StoredEntry)>, CacheError> {
    let mut statement = transaction
        .prepare(
            "SELECT key_sha256, canonical_key, namespace_sha256, policy_id,
                    policy_sha256, generation_sha256, restore_epoch, content_sha256,
                    content_bytes, content, publication_event_sha256,
                    created_at_unix_ms, expires_at_unix_ms
             FROM entries
             WHERE policy_id = ?1 AND (
                 expires_at_unix_ms <= ?2 OR generation_sha256 <> ?3 OR restore_epoch <> ?4
             )
             ORDER BY key_sha256 LIMIT ?5",
        )
        .map_err(|_| CacheError::StateUnavailable)?;
    let rows = statement
        .query_map(
            params![
                policy_id,
                now,
                generation_sha256,
                to_i64(restore_epoch)?,
                limit
            ],
            stored_entry_from_policy_row,
        )
        .map_err(|_| CacheError::StateUnavailable)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|_| CacheError::StateUnavailable)
}

fn stored_content_matches(stored: &StoredEntry) -> bool {
    u64::try_from(stored.content.len()).ok() == Some(stored.content_bytes)
        && sha256(&stored.content) == stored.content_sha256
}

fn stale_outcome(
    stored: &StoredEntry,
    generation_sha256: &str,
    restore_epoch: u64,
    now: i64,
) -> CacheOutcome {
    if stored.expires_at_unix_ms <= now {
        CacheOutcome::Expired
    } else if stored.restore_epoch != restore_epoch {
        CacheOutcome::StaleRestoreEpoch
    } else if stored.generation_sha256 != generation_sha256 {
        CacheOutcome::StaleGeneration
    } else {
        CacheOutcome::Evicted
    }
}

fn delete_entry(transaction: &Transaction<'_>, key_sha256: &str) -> Result<(), CacheError> {
    transaction
        .execute("DELETE FROM entries WHERE key_sha256 = ?1", [key_sha256])
        .map_err(|_| CacheError::StateUnavailable)?;
    Ok(())
}

fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, CacheError> {
    serde_json::to_vec(value).map_err(|_| CacheError::StateUnavailable)
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, CacheError> {
    Ok(sha256(&canonical_bytes(value)?))
}

fn event_digest(event_json: &[u8]) -> String {
    domain_digest(b"mcloving.cache-event/v1\0", event_json)
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(bytes);
    encode_digest(&digest.finalize())
}

fn sha256(bytes: &[u8]) -> String {
    encode_digest(&Sha256::digest(bytes))
}

fn encode_digest(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_identity(value: &str) -> bool {
    !value.is_empty()
        && !matches!(value, "." | "..")
        && value.len() <= MAX_IDENTITY_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'/' | b'\\'))
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn strictly_sorted_by<T, K: Ord + ?Sized>(values: &[T], key: impl Fn(&T) -> &K) -> bool {
    values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}

fn to_i64(value: u64) -> Result<i64, CacheError> {
    i64::try_from(value).map_err(|_| CacheError::InvalidConfig)
}
