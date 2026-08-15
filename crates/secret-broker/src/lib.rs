//! Provider-neutral Jenkins credential mapping and short-lived grant broker.
//!
//! Provider-resolved secret bytes exist only in [`SecretMaterial`] during
//! redemption by an exact out-of-process consumer. Owner-private startup markers
//! are deny-only inputs; mapping, grant, receipt, and audit types deliberately
//! have no field capable of carrying secret bytes.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::OpenOptions;
use std::path::Path;
use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

pub const SCHEMA_VERSION: &str = "mcloving.secret-mapping/v1";
pub const GRANT_PROTOCOL_VERSION: &str = "mcloving.secret-grant/v1";

const MAX_TEXT_BYTES: usize = 1_024;
const MAX_REFERENCE_BYTES: usize = 4_096;
const MAX_TAINT_PATH: usize = 32;
const MAX_SECRET_BYTES: usize = 65_536;
const MAX_DENIED_PUBLIC_MARKERS: usize = 256;
const MAX_DENIED_PUBLIC_MARKER_BYTES: usize = 1024 * 1024;
const MAX_GRANT_TTL_MS: i64 = 15 * 60 * 1_000;
const MAX_APPROVAL_TTL_MS: i64 = 30 * 24 * 60 * 60 * 1_000;
const ZERO_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaintClass {
    ConnectorOnly,
    SourceAcquisitionOnly,
    ControllerOnly,
    WorkloadVisible,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadChannel {
    Argument,
    EnvironmentVariable,
    File,
    StandardInput,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConsumerBinding {
    ExternalConnector {
        connector_id: String,
        implementation_sha256: String,
        configuration_sha256: String,
    },
    SourceAcquirer {
        acquirer_id: String,
        implementation_sha256: String,
        configuration_sha256: String,
    },
    Controller {
        operation: String,
    },
    Workload {
        channel: WorkloadChannel,
        target: String,
    },
}

impl ConsumerBinding {
    pub fn taint_class(&self) -> TaintClass {
        match self {
            Self::ExternalConnector { .. } => TaintClass::ConnectorOnly,
            Self::SourceAcquirer { .. } => TaintClass::SourceAcquisitionOnly,
            Self::Controller { .. } => TaintClass::ControllerOnly,
            Self::Workload { .. } => TaintClass::WorkloadVisible,
        }
    }

    fn grant_eligible(&self) -> bool {
        matches!(
            self,
            Self::ExternalConnector { .. } | Self::SourceAcquirer { .. }
        )
    }

    fn identity(&self) -> &str {
        match self {
            Self::ExternalConnector { connector_id, .. } => connector_id,
            Self::SourceAcquirer { acquirer_id, .. } => acquirer_id,
            Self::Controller { operation } => operation,
            Self::Workload { target, .. } => target,
        }
    }

    fn implementation_sha256(&self) -> Option<&str> {
        match self {
            Self::ExternalConnector {
                implementation_sha256,
                ..
            }
            | Self::SourceAcquirer {
                implementation_sha256,
                ..
            } => Some(implementation_sha256),
            Self::Controller { .. } | Self::Workload { .. } => None,
        }
    }

    fn configuration_sha256(&self) -> Option<&str> {
        match self {
            Self::ExternalConnector {
                configuration_sha256,
                ..
            }
            | Self::SourceAcquirer {
                configuration_sha256,
                ..
            } => Some(configuration_sha256),
            Self::Controller { .. } | Self::Workload { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MappingDisposition {
    GrantEligible,
    IneligibleControllerVisible,
    IneligibleWorkloadVisible,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialMapping {
    pub schema_version: String,
    pub mapping_id: Uuid,
    pub inventory_epoch_sha256: String,
    pub inventory_job_id: String,
    pub inventory_dependency_id: String,
    pub jenkins_credential_reference: String,
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub environment: String,
    pub action: String,
    pub owner_identity: String,
    pub owner_approval_signer_key_id: String,
    pub owner_approval_public_key_sha256: String,
    pub owner_approved_at_unix_ms: i64,
    pub owner_approval_expires_unix_ms: i64,
    pub owner_approval_sha256: String,
    pub owner_approval_signature: String,
    pub provider_identity: String,
    pub provider_version: String,
    pub provider_implementation_sha256: String,
    pub provider_configuration_sha256: String,
    pub provider_reference: String,
    pub secret_version: String,
    pub rotation_generation: u64,
    pub declared_taint: TaintClass,
    pub taint_path: Vec<String>,
    pub classification_evidence_sha256: String,
    pub consumer: ConsumerBinding,
    pub disposition: MappingDisposition,
}

impl CredentialMapping {
    pub fn owner_approval_payload(&self) -> Result<Vec<u8>, BrokerError> {
        let mut unsigned = self.clone();
        unsigned.owner_approval_sha256 = ZERO_SHA256.to_owned();
        unsigned.owner_approval_signature.clear();
        serde_json::to_vec(&unsigned).map_err(BrokerError::from)
    }

    pub fn owner_approval_message(&self) -> Result<Vec<u8>, BrokerError> {
        Ok([
            b"mcloving-secret-owner-approval-v1\0".as_slice(),
            self.owner_approval_payload()?.as_slice(),
        ]
        .concat())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryCredential {
    pub inventory_epoch_sha256: String,
    pub job_id: String,
    pub dependency_id: String,
    pub jenkins_credential_reference: String,
    pub owner_identity: String,
    pub declared_taint: TaintClass,
    pub taint_path: Vec<String>,
    pub classification_evidence_sha256: String,
    pub consumer: ConsumerBinding,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRequest {
    pub protocol_version: String,
    pub grant_id: Uuid,
    pub mapping_id: Uuid,
    pub expected_rotation_generation: u64,
    pub expected_provider_version: String,
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub build_id: Uuid,
    pub attempt_id: Uuid,
    pub environment: String,
    pub action: String,
    pub fence: u64,
    pub consumer: ConsumerBinding,
    pub requested_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub audit_provenance: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GrantReceipt {
    pub protocol_version: String,
    pub grant_id: Uuid,
    pub mapping_id: Uuid,
    pub rotation_generation: u64,
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub build_id: Uuid,
    pub attempt_id: Uuid,
    pub environment: String,
    pub action: String,
    pub fence: u64,
    pub consumer: ConsumerBinding,
    pub provider_identity: String,
    pub provider_version: String,
    pub provider_implementation_sha256: String,
    pub provider_configuration_sha256: String,
    pub secret_version: String,
    pub issued_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub audit_provenance: String,
    pub receipt_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConsumerGrantBinding {
    ExternalConnector {
        grant_id: String,
        grant_version: String,
        grant_scope: String,
        grant_expires_unix_ms: i64,
        connector_id: String,
        implementation_sha256: String,
        configuration_sha256: String,
    },
    SourceAcquirer {
        grant_id: String,
        grant_version: String,
        grant_scope: String,
        grant_expires_unix_ms: i64,
        acquirer_id: String,
        implementation_sha256: String,
        configuration_sha256: String,
    },
}

impl GrantReceipt {
    pub fn consumer_binding(&self) -> Result<ConsumerGrantBinding, BrokerError> {
        let grant_id = self.grant_id.to_string();
        let grant_scope = format!(
            "organization/{}/project/{}/build/{}/attempt/{}/environment/{}/action/{}/fence/{}",
            self.organization_id,
            self.project_id,
            self.build_id,
            self.attempt_id,
            self.environment,
            self.action,
            self.fence
        );
        match &self.consumer {
            ConsumerBinding::ExternalConnector {
                connector_id,
                implementation_sha256,
                configuration_sha256,
            } => Ok(ConsumerGrantBinding::ExternalConnector {
                grant_id,
                grant_version: GRANT_PROTOCOL_VERSION.to_owned(),
                grant_scope,
                grant_expires_unix_ms: self.expires_at_unix_ms,
                connector_id: connector_id.clone(),
                implementation_sha256: implementation_sha256.clone(),
                configuration_sha256: configuration_sha256.clone(),
            }),
            ConsumerBinding::SourceAcquirer {
                acquirer_id,
                implementation_sha256,
                configuration_sha256,
            } => Ok(ConsumerGrantBinding::SourceAcquirer {
                grant_id,
                grant_version: GRANT_PROTOCOL_VERSION.to_owned(),
                grant_scope,
                grant_expires_unix_ms: self.expires_at_unix_ms,
                acquirer_id: acquirer_id.clone(),
                implementation_sha256: implementation_sha256.clone(),
                configuration_sha256: configuration_sha256.clone(),
            }),
            ConsumerBinding::Controller { .. } | ConsumerBinding::Workload { .. } => {
                Err(BrokerError::MappingDenied)
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RedemptionRequest {
    pub grant_id: Uuid,
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub build_id: Uuid,
    pub attempt_id: Uuid,
    pub fence: u64,
    pub consumer: ConsumerBinding,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RedemptionReceipt {
    pub protocol_version: String,
    pub grant_id: Uuid,
    pub mapping_id: Uuid,
    pub rotation_generation: u64,
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub build_id: Uuid,
    pub attempt_id: Uuid,
    pub fence: u64,
    pub consumer: ConsumerBinding,
    pub provider_identity: String,
    pub provider_version: String,
    pub provider_implementation_sha256: String,
    pub provider_configuration_sha256: String,
    pub secret_version: String,
    pub redeemed_at_unix_ms: i64,
    pub grant_receipt_sha256: String,
    pub receipt_sha256: String,
}

pub struct SecretMaterial(Vec<u8>);

impl SecretMaterial {
    pub fn new(bytes: Vec<u8>) -> Result<Self, BrokerError> {
        if bytes.len() < 16 || bytes.len() > MAX_SECRET_BYTES {
            return Err(BrokerError::ProviderDenied);
        }
        Ok(Self(bytes))
    }

    /// Exposes bytes only to the exact out-of-process consumer integration.
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretMaterial([REDACTED])")
    }
}

impl Drop for SecretMaterial {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub struct ProviderSecret {
    pub secret_version: String,
    pub material: SecretMaterial,
}

impl fmt::Debug for ProviderSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderSecret")
            .field("secret_version", &self.secret_version)
            .field("material", &self.material)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderRequest {
    pub provider_identity: String,
    pub provider_version: String,
    pub provider_implementation_sha256: String,
    pub provider_configuration_sha256: String,
    pub provider_reference: String,
    pub secret_version: String,
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub build_id: Uuid,
    pub attempt_id: Uuid,
    pub environment: String,
    pub action: String,
    pub fence: u64,
    pub consumer: ConsumerBinding,
    pub expires_at_unix_ms: i64,
}

pub trait SecretProvider {
    fn resolve(&self, request: &ProviderRequest) -> Result<ProviderSecret, BrokerError>;
}

pub struct SecretRedemption {
    pub receipt: RedemptionReceipt,
    pub material: SecretMaterial,
}

impl fmt::Debug for SecretRedemption {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretRedemption")
            .field("receipt", &self.receipt)
            .field("material", &self.material)
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum BrokerError {
    #[error("secret mapping is outside its bounds")]
    InvalidMapping,
    #[error("credential inventory does not reconcile exactly")]
    InventoryMismatch,
    #[error("secret grant request is outside its bounds")]
    InvalidGrant,
    #[error("secret mapping or grant conflicts with existing truth")]
    Conflict,
    #[error("secret mapping owner approval is missing, stale, or invalid")]
    OwnerApprovalDenied,
    #[error("secret mapping is missing, stale, revoked, or ineligible")]
    MappingDenied,
    #[error("secret grant is missing, stale, replayed, or outside its scope")]
    GrantDenied,
    #[error("secret provider denied or substituted the requested version")]
    ProviderDenied,
    #[error("secret material appeared in broker public evidence")]
    ConfidentialityDenied,
    #[error("secret broker audit chain is invalid")]
    AuditInvalid,
    #[error("secret broker state is unavailable")]
    StateUnavailable(#[from] rusqlite::Error),
    #[error("secret broker state path is not an owner-private regular file")]
    InvalidStatePath,
    #[error("secret broker state filesystem is unavailable")]
    StateIo(#[from] std::io::Error),
    #[error("secret broker canonical encoding failed")]
    Encoding(#[from] serde_json::Error),
}

pub struct SecretBroker {
    connection: Connection,
    trusted_owner_keys: BTreeMap<String, Vec<u8>>,
    denied_public_markers: Zeroizing<Vec<Vec<u8>>>,
}

impl SecretBroker {
    pub fn open(
        path: &Path,
        trusted_owner_keys: BTreeMap<String, Vec<u8>>,
        denied_public_markers: Vec<Vec<u8>>,
    ) -> Result<Self, BrokerError> {
        let denied_public_markers = Zeroizing::new(denied_public_markers);
        validate_trusted_owner_keys(&trusted_owner_keys)?;
        validate_denied_public_markers(&denied_public_markers)?;
        let canonical_path = prepare_state_path(path)?;
        validate_state_sidecars(&canonical_path)?;
        let connection = Connection::open(&canonical_path)?;
        connection.execute_batch(
            "PRAGMA trusted_schema = OFF;
             PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             CREATE TABLE IF NOT EXISTS mapping_versions (
                 mapping_id TEXT NOT NULL,
                 rotation_generation INTEGER NOT NULL CHECK(rotation_generation > 0),
                 canonical_json BLOB NOT NULL,
                 status TEXT NOT NULL CHECK(status IN ('active', 'revoked')),
                 revocation_generation INTEGER NOT NULL DEFAULT 0 CHECK(revocation_generation >= 0),
                 revoked_at_unix_ms INTEGER,
                 revocation_reason TEXT,
                 PRIMARY KEY(mapping_id, rotation_generation)
             );
             CREATE TABLE IF NOT EXISTS mapping_heads (
                 mapping_id TEXT PRIMARY KEY,
                 rotation_generation INTEGER NOT NULL CHECK(rotation_generation > 0)
             );
             CREATE TABLE IF NOT EXISTS grants (
                 grant_id TEXT PRIMARY KEY,
                 mapping_id TEXT NOT NULL,
                 rotation_generation INTEGER NOT NULL,
                 canonical_request BLOB NOT NULL,
                 canonical_receipt BLOB NOT NULL,
                 receipt_sha256 TEXT NOT NULL,
                 scope_sha256 TEXT NOT NULL,
                 status TEXT NOT NULL CHECK(status IN ('issued', 'redeemed', 'revoked')),
                 issued_at_unix_ms INTEGER NOT NULL,
                 expires_at_unix_ms INTEGER NOT NULL,
                 redeemed_at_unix_ms INTEGER,
                 FOREIGN KEY(mapping_id, rotation_generation)
                    REFERENCES mapping_versions(mapping_id, rotation_generation)
             );
             CREATE UNIQUE INDEX IF NOT EXISTS one_grant_per_scope
             ON grants(mapping_id, rotation_generation, scope_sha256);
             CREATE TABLE IF NOT EXISTS audit_events (
                 sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                 event_type TEXT NOT NULL,
                 canonical_payload BLOB NOT NULL,
                 previous_sha256 TEXT NOT NULL,
                 event_sha256 TEXT NOT NULL UNIQUE
             );",
        )?;
        validate_state_file(&canonical_path)?;
        validate_state_sidecars(&canonical_path)?;
        Ok(Self {
            connection,
            trusted_owner_keys,
            denied_public_markers,
        })
    }

    pub fn install_mapping(
        &mut self,
        mapping: &CredentialMapping,
        installed_at_unix_ms: i64,
    ) -> Result<(), BrokerError> {
        validate_mapping(mapping)?;
        let canonical = serde_json::to_vec(mapping)?;
        ensure_markers_absent(mapping, &canonical, &self.denied_public_markers)?;
        let owner_approval_public_key = self
            .trusted_owner_keys
            .get(&mapping.owner_approval_signer_key_id)
            .ok_or(BrokerError::OwnerApprovalDenied)?;
        verify_owner_approval(mapping, owner_approval_public_key, installed_at_unix_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let head = transaction
            .query_row(
                "SELECT rotation_generation FROM mapping_heads WHERE mapping_id = ?1",
                [mapping.mapping_id.to_string()],
                |row| row.get::<_, u64>(0),
            )
            .optional()?;
        match head {
            None if mapping.rotation_generation != 1 => {
                return Err(BrokerError::Conflict);
            }
            Some(current) if mapping.rotation_generation != current + 1 => {
                return Err(BrokerError::Conflict);
            }
            Some(current) => {
                let prior: Vec<u8> = transaction.query_row(
                    "SELECT canonical_json FROM mapping_versions
                     WHERE mapping_id = ?1 AND rotation_generation = ?2 AND status = 'active'",
                    params![mapping.mapping_id.to_string(), current],
                    |row| row.get(0),
                )?;
                let prior: CredentialMapping = serde_json::from_slice(&prior)?;
                validate_rotation(&prior, mapping)?;
                transaction.execute(
                    "UPDATE grants SET status = 'revoked'
                     WHERE mapping_id = ?1 AND rotation_generation = ?2 AND status = 'issued'",
                    params![mapping.mapping_id.to_string(), current],
                )?;
            }
            None => {}
        }
        transaction.execute(
            "INSERT INTO mapping_versions(
                 mapping_id, rotation_generation, canonical_json, status
             ) VALUES (?1, ?2, ?3, 'active')",
            params![
                mapping.mapping_id.to_string(),
                mapping.rotation_generation,
                canonical
            ],
        )?;
        transaction.execute(
            "INSERT INTO mapping_heads(mapping_id, rotation_generation)
             VALUES (?1, ?2)
             ON CONFLICT(mapping_id) DO UPDATE SET rotation_generation = excluded.rotation_generation",
            params![mapping.mapping_id.to_string(), mapping.rotation_generation],
        )?;
        append_audit(
            &transaction,
            if head.is_some() {
                "secret.mapping_rotated"
            } else {
                "secret.mapping_installed"
            },
            &serde_json::json!({
                "mapping_id": mapping.mapping_id,
                "rotation_generation": mapping.rotation_generation,
                "provider_identity": mapping.provider_identity,
                "provider_version": mapping.provider_version,
                "provider_implementation_sha256": mapping.provider_implementation_sha256,
                "provider_configuration_sha256": mapping.provider_configuration_sha256,
                "owner_identity": mapping.owner_identity,
                "owner_approval_signer_key_id": mapping.owner_approval_signer_key_id,
                "owner_approval_sha256": mapping.owner_approval_sha256,
                "consumer": mapping.consumer,
                "disposition": mapping.disposition,
                "installed_at_unix_ms": installed_at_unix_ms,
            }),
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn revoke_mapping(
        &mut self,
        mapping_id: Uuid,
        expected_rotation_generation: u64,
        revocation_generation: u64,
        revoked_at_unix_ms: i64,
        reason: &str,
    ) -> Result<(), BrokerError> {
        if expected_rotation_generation == 0
            || revocation_generation == 0
            || revoked_at_unix_ms < 0
            || !valid_text(reason, MAX_TEXT_BYTES)
        {
            return Err(BrokerError::InvalidMapping);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE mapping_versions
             SET status = 'revoked', revocation_generation = ?3,
                 revoked_at_unix_ms = ?4, revocation_reason = ?5
             WHERE mapping_id = ?1 AND rotation_generation = ?2
               AND status = 'active' AND revocation_generation < ?3
               AND (SELECT rotation_generation FROM mapping_heads WHERE mapping_id = ?1) = ?2",
            params![
                mapping_id.to_string(),
                expected_rotation_generation,
                revocation_generation,
                revoked_at_unix_ms,
                reason
            ],
        )?;
        if changed != 1 {
            return Err(BrokerError::MappingDenied);
        }
        transaction.execute(
            "UPDATE grants SET status = 'revoked'
             WHERE mapping_id = ?1 AND rotation_generation = ?2 AND status = 'issued'",
            params![mapping_id.to_string(), expected_rotation_generation],
        )?;
        append_audit(
            &transaction,
            "secret.mapping_revoked",
            &serde_json::json!({
                "mapping_id": mapping_id,
                "rotation_generation": expected_rotation_generation,
                "revocation_generation": revocation_generation,
                "revoked_at_unix_ms": revoked_at_unix_ms,
                "reason": reason,
            }),
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn issue_grant(
        &mut self,
        request: &GrantRequest,
        trusted_now_unix_ms: i64,
    ) -> Result<GrantReceipt, BrokerError> {
        validate_grant_request(request)?;
        if trusted_now_unix_ms < request.requested_at_unix_ms
            || trusted_now_unix_ms >= request.expires_at_unix_ms
        {
            return Err(BrokerError::InvalidGrant);
        }
        let canonical_request = serde_json::to_vec(request)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((existing_request, existing_receipt, status)) = transaction
            .query_row(
                "SELECT canonical_request, canonical_receipt, status
                 FROM grants WHERE grant_id = ?1",
                [request.grant_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?
        {
            if existing_request != canonical_request {
                return Err(BrokerError::Conflict);
            }
            if status != "issued" || trusted_now_unix_ms >= request.expires_at_unix_ms {
                return Err(BrokerError::GrantDenied);
            }
            let receipt = serde_json::from_slice(&existing_receipt)?;
            transaction.commit()?;
            return Ok(receipt);
        }
        let canonical_mapping: Vec<u8> = transaction
            .query_row(
                "SELECT v.canonical_json
                 FROM mapping_versions AS v
                 JOIN mapping_heads AS h ON h.mapping_id = v.mapping_id
                    AND h.rotation_generation = v.rotation_generation
                 WHERE v.mapping_id = ?1 AND v.rotation_generation = ?2
                   AND v.status = 'active'",
                params![
                    request.mapping_id.to_string(),
                    request.expected_rotation_generation
                ],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(BrokerError::MappingDenied)?;
        let mapping: CredentialMapping = serde_json::from_slice(&canonical_mapping)?;
        if !grant_matches_mapping(request, &mapping) {
            return Err(BrokerError::MappingDenied);
        }
        let scope_sha256 = grant_scope_sha256(request)?;
        if transaction
            .query_row(
                "SELECT 1 FROM grants
                 WHERE mapping_id = ?1 AND rotation_generation = ?2 AND scope_sha256 = ?3",
                params![
                    request.mapping_id.to_string(),
                    request.expected_rotation_generation,
                    scope_sha256
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some()
        {
            return Err(BrokerError::GrantDenied);
        }
        let mut receipt = GrantReceipt {
            protocol_version: GRANT_PROTOCOL_VERSION.to_owned(),
            grant_id: request.grant_id,
            mapping_id: mapping.mapping_id,
            rotation_generation: mapping.rotation_generation,
            organization_id: request.organization_id,
            project_id: request.project_id,
            build_id: request.build_id,
            attempt_id: request.attempt_id,
            environment: request.environment.clone(),
            action: request.action.clone(),
            fence: request.fence,
            consumer: request.consumer.clone(),
            provider_identity: mapping.provider_identity,
            provider_version: mapping.provider_version,
            provider_implementation_sha256: mapping.provider_implementation_sha256,
            provider_configuration_sha256: mapping.provider_configuration_sha256,
            secret_version: mapping.secret_version,
            issued_at_unix_ms: trusted_now_unix_ms,
            expires_at_unix_ms: request.expires_at_unix_ms,
            audit_provenance: request.audit_provenance.clone(),
            receipt_sha256: ZERO_SHA256.to_owned(),
        };
        receipt.receipt_sha256 = canonical_sha256(&receipt)?;
        let canonical_receipt = serde_json::to_vec(&receipt)?;
        transaction.execute(
            "INSERT INTO grants(
                 grant_id, mapping_id, rotation_generation, canonical_request,
                 canonical_receipt, receipt_sha256, scope_sha256, status, issued_at_unix_ms,
                 expires_at_unix_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'issued', ?8, ?9)",
            params![
                request.grant_id.to_string(),
                request.mapping_id.to_string(),
                request.expected_rotation_generation,
                canonical_request,
                canonical_receipt,
                receipt.receipt_sha256,
                scope_sha256,
                trusted_now_unix_ms,
                request.expires_at_unix_ms,
            ],
        )?;
        append_audit(
            &transaction,
            "secret.grant_issued",
            &serde_json::json!({
                "grant_id": request.grant_id,
                "mapping_id": request.mapping_id,
                "rotation_generation": request.expected_rotation_generation,
                "organization_id": request.organization_id,
                "project_id": request.project_id,
                "build_id": request.build_id,
                "attempt_id": request.attempt_id,
                "fence": request.fence,
                "consumer": request.consumer,
                "expires_at_unix_ms": request.expires_at_unix_ms,
                "receipt_sha256": receipt.receipt_sha256,
            }),
        )?;
        transaction.commit()?;
        Ok(receipt)
    }

    pub fn redeem_grant<P: SecretProvider>(
        &mut self,
        request: &RedemptionRequest,
        provider: &P,
        trusted_now_unix_ms: i64,
    ) -> Result<SecretRedemption, BrokerError> {
        if trusted_now_unix_ms < 0 || request.fence > i64::MAX as u64 {
            return Err(BrokerError::GrantDenied);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row = transaction
            .query_row(
                "SELECT g.canonical_request, g.canonical_receipt, g.status,
                        v.canonical_json, h.rotation_generation, v.status
                 FROM grants AS g
                 JOIN mapping_versions AS v ON v.mapping_id = g.mapping_id
                    AND v.rotation_generation = g.rotation_generation
                 JOIN mapping_heads AS h ON h.mapping_id = g.mapping_id
                 WHERE g.grant_id = ?1",
                [request.grant_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, u64>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )
            .optional()?
            .ok_or(BrokerError::GrantDenied)?;
        let grant_request: GrantRequest = serde_json::from_slice(&row.0)?;
        let grant_receipt: GrantReceipt = serde_json::from_slice(&row.1)?;
        let mapping: CredentialMapping = serde_json::from_slice(&row.3)?;
        if row.2 != "issued"
            || row.5 != "active"
            || row.4 != mapping.rotation_generation
            || trusted_now_unix_ms < grant_receipt.issued_at_unix_ms
            || trusted_now_unix_ms >= grant_receipt.expires_at_unix_ms
            || request.organization_id != grant_request.organization_id
            || request.project_id != grant_request.project_id
            || request.build_id != grant_request.build_id
            || request.attempt_id != grant_request.attempt_id
            || request.fence != grant_request.fence
            || request.consumer != grant_request.consumer
        {
            return Err(BrokerError::GrantDenied);
        }
        let provider_request = ProviderRequest {
            provider_identity: mapping.provider_identity.clone(),
            provider_version: mapping.provider_version.clone(),
            provider_implementation_sha256: mapping.provider_implementation_sha256.clone(),
            provider_configuration_sha256: mapping.provider_configuration_sha256.clone(),
            provider_reference: mapping.provider_reference.clone(),
            secret_version: mapping.secret_version.clone(),
            organization_id: request.organization_id,
            project_id: request.project_id,
            build_id: request.build_id,
            attempt_id: request.attempt_id,
            environment: mapping.environment.clone(),
            action: mapping.action.clone(),
            fence: request.fence,
            consumer: request.consumer.clone(),
            expires_at_unix_ms: grant_receipt.expires_at_unix_ms,
        };
        let provider_secret = provider.resolve(&provider_request)?;
        if provider_secret.secret_version != mapping.secret_version {
            return Err(BrokerError::ProviderDenied);
        }
        ensure_non_disclosure(
            provider_secret.material.expose_secret(),
            &mapping,
            &grant_request,
            &grant_receipt,
            &audit_events_json_tx(&transaction)?,
        )?;
        let mut receipt = RedemptionReceipt {
            protocol_version: GRANT_PROTOCOL_VERSION.to_owned(),
            grant_id: request.grant_id,
            mapping_id: mapping.mapping_id,
            rotation_generation: mapping.rotation_generation,
            organization_id: request.organization_id,
            project_id: request.project_id,
            build_id: request.build_id,
            attempt_id: request.attempt_id,
            fence: request.fence,
            consumer: request.consumer.clone(),
            provider_identity: mapping.provider_identity,
            provider_version: mapping.provider_version,
            provider_implementation_sha256: mapping.provider_implementation_sha256,
            provider_configuration_sha256: mapping.provider_configuration_sha256,
            secret_version: mapping.secret_version,
            redeemed_at_unix_ms: trusted_now_unix_ms,
            grant_receipt_sha256: grant_receipt.receipt_sha256,
            receipt_sha256: ZERO_SHA256.to_owned(),
        };
        receipt.receipt_sha256 = canonical_sha256(&receipt)?;
        let changed = transaction.execute(
            "UPDATE grants SET status = 'redeemed', redeemed_at_unix_ms = ?2
             WHERE grant_id = ?1 AND status = 'issued'",
            params![request.grant_id.to_string(), trusted_now_unix_ms],
        )?;
        if changed != 1 {
            return Err(BrokerError::GrantDenied);
        }
        append_audit(
            &transaction,
            "secret.grant_redeemed",
            &serde_json::json!({
                "grant_id": request.grant_id,
                "mapping_id": mapping.mapping_id,
                "rotation_generation": mapping.rotation_generation,
                "organization_id": request.organization_id,
                "project_id": request.project_id,
                "build_id": request.build_id,
                "attempt_id": request.attempt_id,
                "fence": request.fence,
                "consumer": request.consumer,
                "redemption_receipt_sha256": receipt.receipt_sha256,
            }),
        )?;
        transaction.commit()?;
        Ok(SecretRedemption {
            receipt,
            material: provider_secret.material,
        })
    }

    pub fn audit_events_json(&self) -> Result<Vec<Vec<u8>>, BrokerError> {
        let mut statement = self
            .connection
            .prepare("SELECT canonical_payload FROM audit_events ORDER BY sequence")?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(BrokerError::from)
    }

    pub fn verify_audit_chain(&self) -> Result<usize, BrokerError> {
        let mut statement = self.connection.prepare(
            "SELECT sequence, event_type, canonical_payload, previous_sha256, event_sha256
             FROM audit_events ORDER BY sequence",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        let mut expected_sequence = 1_i64;
        let mut previous = ZERO_SHA256.to_owned();
        for row in rows {
            let (sequence, event_type, payload, recorded_previous, recorded_digest) = row?;
            let expected_digest = audit_event_sha256(&previous, &event_type, &payload);
            if sequence != expected_sequence
                || recorded_previous != previous
                || recorded_digest != expected_digest
            {
                return Err(BrokerError::AuditInvalid);
            }
            expected_sequence += 1;
            previous = recorded_digest;
        }
        usize::try_from(expected_sequence - 1).map_err(|_| BrokerError::AuditInvalid)
    }
}

pub fn reconcile_inventory(
    inventory: &[InventoryCredential],
    mappings: &[CredentialMapping],
) -> Result<(), BrokerError> {
    let mut inventory_index = BTreeMap::new();
    for credential in inventory {
        validate_inventory_credential(credential)?;
        let key = (
            credential.inventory_epoch_sha256.clone(),
            credential.job_id.clone(),
            credential.dependency_id.clone(),
        );
        if inventory_index.insert(key, credential).is_some() {
            return Err(BrokerError::InventoryMismatch);
        }
    }
    let mut mapped = BTreeSet::new();
    for mapping in mappings {
        validate_mapping(mapping)?;
        let key = (
            mapping.inventory_epoch_sha256.clone(),
            mapping.inventory_job_id.clone(),
            mapping.inventory_dependency_id.clone(),
        );
        let credential = inventory_index
            .get(&key)
            .ok_or(BrokerError::InventoryMismatch)?;
        if !mapped.insert(key)
            || mapping.jenkins_credential_reference != credential.jenkins_credential_reference
            || mapping.owner_identity != credential.owner_identity
            || mapping.declared_taint != credential.declared_taint
            || mapping.taint_path != credential.taint_path
            || mapping.classification_evidence_sha256 != credential.classification_evidence_sha256
            || mapping.consumer != credential.consumer
        {
            return Err(BrokerError::InventoryMismatch);
        }
    }
    if mapped.len() != inventory_index.len() {
        return Err(BrokerError::InventoryMismatch);
    }
    Ok(())
}

fn prepare_state_path(path: &Path) -> Result<PathBuf, BrokerError> {
    if !path.is_absolute() {
        return Err(BrokerError::InvalidStatePath);
    }
    let filename = path.file_name().ok_or(BrokerError::InvalidStatePath)?;
    let parent = path.parent().ok_or(BrokerError::InvalidStatePath)?;
    let canonical_parent = parent.canonicalize()?;
    validate_state_parent(&canonical_parent)?;
    let canonical_path = canonical_parent.join(filename);
    match std::fs::symlink_metadata(&canonical_path) {
        Ok(_) => validate_state_file(&canonical_path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            drop(options.open(&canonical_path)?);
            validate_state_file(&canonical_path)?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(canonical_path)
}

fn validate_state_parent(path: &Path) -> Result<(), BrokerError> {
    let metadata = std::fs::metadata(path)?;
    if !metadata.is_dir() {
        return Err(BrokerError::InvalidStatePath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.uid() != nix::unistd::Uid::effective().as_raw() || metadata.mode() & 0o077 != 0
        {
            return Err(BrokerError::InvalidStatePath);
        }
    }
    Ok(())
}

fn validate_state_file(path: &Path) -> Result<(), BrokerError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(BrokerError::InvalidStatePath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
        {
            return Err(BrokerError::InvalidStatePath);
        }
    }
    Ok(())
}

fn validate_state_sidecars(path: &Path) -> Result<(), BrokerError> {
    let filename = path.file_name().ok_or(BrokerError::InvalidStatePath)?;
    let parent = path.parent().ok_or(BrokerError::InvalidStatePath)?;
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut sidecar_name = filename.to_os_string();
        sidecar_name.push(suffix);
        let sidecar = parent.join(sidecar_name);
        match std::fs::symlink_metadata(&sidecar) {
            Ok(_) => validate_state_file(&sidecar)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn grant_scope_sha256(request: &GrantRequest) -> Result<String, BrokerError> {
    canonical_sha256(&serde_json::json!({
        "mapping_id": request.mapping_id,
        "rotation_generation": request.expected_rotation_generation,
        "organization_id": request.organization_id,
        "project_id": request.project_id,
        "build_id": request.build_id,
        "attempt_id": request.attempt_id,
        "environment": request.environment,
        "action": request.action,
        "fence": request.fence,
        "consumer": request.consumer,
    }))
}

fn ensure_non_disclosure(
    secret: &[u8],
    mapping: &CredentialMapping,
    request: &GrantRequest,
    receipt: &GrantReceipt,
    audit_events: &[Vec<u8>],
) -> Result<(), BrokerError> {
    let mut public = serde_json::to_vec(mapping)?;
    public.extend(serde_json::to_vec(request)?);
    public.extend(serde_json::to_vec(receipt)?);
    for event in audit_events {
        public.extend_from_slice(event);
    }
    if secret_representations(secret)
        .iter()
        .any(|marker| public.windows(marker.len()).any(|window| window == marker))
    {
        return Err(BrokerError::ConfidentialityDenied);
    }
    Ok(())
}

fn secret_representations(secret: &[u8]) -> BTreeSet<Vec<u8>> {
    let mut values = BTreeSet::from([secret.to_vec()]);
    for encoded in [
        STANDARD.encode(secret),
        STANDARD_NO_PAD.encode(secret),
        URL_SAFE.encode(secret),
        URL_SAFE_NO_PAD.encode(secret),
    ] {
        values.insert(encoded.into_bytes());
    }
    let mut lower_hex = String::with_capacity(secret.len() * 2);
    let mut upper_hex = String::with_capacity(secret.len() * 2);
    let mut lower_percent = String::with_capacity(secret.len() * 3);
    let mut upper_percent = String::with_capacity(secret.len() * 3);
    for byte in secret {
        use fmt::Write as _;
        let _ = write!(&mut lower_hex, "{byte:02x}");
        let _ = write!(&mut upper_hex, "{byte:02X}");
        let _ = write!(&mut lower_percent, "%{byte:02x}");
        let _ = write!(&mut upper_percent, "%{byte:02X}");
    }
    values.extend([
        lower_hex.into_bytes(),
        upper_hex.into_bytes(),
        lower_percent.into_bytes(),
        upper_percent.into_bytes(),
    ]);
    values
}

fn audit_events_json_tx(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<Vec<Vec<u8>>, BrokerError> {
    let mut statement =
        transaction.prepare("SELECT canonical_payload FROM audit_events ORDER BY sequence")?;
    let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(BrokerError::from)
}

fn validate_inventory_credential(credential: &InventoryCredential) -> Result<(), BrokerError> {
    if !is_sha256(&credential.inventory_epoch_sha256)
        || !valid_text(&credential.job_id, MAX_TEXT_BYTES)
        || !valid_text(&credential.dependency_id, MAX_TEXT_BYTES)
        || !valid_text(
            &credential.jenkins_credential_reference,
            MAX_REFERENCE_BYTES,
        )
        || !valid_text(&credential.owner_identity, MAX_TEXT_BYTES)
        || credential.declared_taint != credential.consumer.taint_class()
        || !valid_taint_path(&credential.taint_path)
        || !is_sha256(&credential.classification_evidence_sha256)
        || !valid_consumer(&credential.consumer)
    {
        return Err(BrokerError::InventoryMismatch);
    }
    Ok(())
}

fn validate_trusted_owner_keys(
    trusted_owner_keys: &BTreeMap<String, Vec<u8>>,
) -> Result<(), BrokerError> {
    let mut public_key_digests = BTreeSet::new();
    if trusted_owner_keys.is_empty()
        || trusted_owner_keys.iter().any(|(key_id, public_key)| {
            !valid_text(key_id, MAX_TEXT_BYTES)
                || public_key.len() != 32
                || !public_key_digests.insert(sha256_hex(public_key))
        })
    {
        return Err(BrokerError::OwnerApprovalDenied);
    }
    Ok(())
}

fn validate_denied_public_markers(markers: &[Vec<u8>]) -> Result<(), BrokerError> {
    let mut unique_representations = BTreeSet::new();
    if markers.is_empty()
        || markers.len() > MAX_DENIED_PUBLIC_MARKERS
        || markers
            .iter()
            .try_fold(0_usize, |total, marker| total.checked_add(marker.len()))
            .is_none_or(|total| total > MAX_DENIED_PUBLIC_MARKER_BYTES)
        || markers.iter().any(|marker| {
            marker.len() < 16
                || marker.len() > MAX_SECRET_BYTES
                || secret_representations(marker)
                    .into_iter()
                    .any(|representation| !unique_representations.insert(representation))
        })
    {
        return Err(BrokerError::InvalidMapping);
    }
    Ok(())
}

fn ensure_markers_absent<T: Serialize>(
    value: &T,
    canonical: &[u8],
    markers: &[Vec<u8>],
) -> Result<(), BrokerError> {
    let representations = markers
        .iter()
        .flat_map(|marker| secret_representations(marker))
        .collect::<Vec<_>>();
    let semantic = serde_json::to_value(value)?;
    if contains_marker(canonical, &representations)
        || json_contains_marker(&semantic, &representations)
    {
        return Err(BrokerError::ConfidentialityDenied);
    }
    Ok(())
}

fn contains_marker(value: &[u8], markers: &[Vec<u8>]) -> bool {
    markers.iter().any(|marker| {
        value
            .windows(marker.len())
            .any(|window| window == marker.as_slice())
    })
}

fn json_contains_marker(value: &serde_json::Value, markers: &[Vec<u8>]) -> bool {
    match value {
        serde_json::Value::String(value) => contains_marker(value.as_bytes(), markers),
        serde_json::Value::Array(values) => values
            .iter()
            .any(|value| json_contains_marker(value, markers)),
        serde_json::Value::Object(values) => values.iter().any(|(key, value)| {
            contains_marker(key.as_bytes(), markers) || json_contains_marker(value, markers)
        }),
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
            false
        }
    }
}

fn verify_owner_approval(
    mapping: &CredentialMapping,
    owner_approval_public_key: &[u8],
    installed_at_unix_ms: i64,
) -> Result<(), BrokerError> {
    let approval_ttl = mapping
        .owner_approval_expires_unix_ms
        .checked_sub(mapping.owner_approved_at_unix_ms);
    if installed_at_unix_ms < mapping.owner_approved_at_unix_ms
        || installed_at_unix_ms >= mapping.owner_approval_expires_unix_ms
        || approval_ttl.is_none_or(|ttl| !(1..=MAX_APPROVAL_TTL_MS).contains(&ttl))
        || sha256_hex(owner_approval_public_key) != mapping.owner_approval_public_key_sha256
    {
        return Err(BrokerError::OwnerApprovalDenied);
    }
    let payload = mapping.owner_approval_payload()?;
    if sha256_hex(&payload) != mapping.owner_approval_sha256 {
        return Err(BrokerError::OwnerApprovalDenied);
    }
    let signature = STANDARD
        .decode(&mapping.owner_approval_signature)
        .map_err(|_| BrokerError::OwnerApprovalDenied)?;
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, owner_approval_public_key)
        .verify(&mapping.owner_approval_message()?, &signature)
        .map_err(|_| BrokerError::OwnerApprovalDenied)
}

fn validate_mapping(mapping: &CredentialMapping) -> Result<(), BrokerError> {
    let expected_disposition = match mapping.consumer {
        ConsumerBinding::ExternalConnector { .. } | ConsumerBinding::SourceAcquirer { .. } => {
            MappingDisposition::GrantEligible
        }
        ConsumerBinding::Controller { .. } => MappingDisposition::IneligibleControllerVisible,
        ConsumerBinding::Workload { .. } => MappingDisposition::IneligibleWorkloadVisible,
    };
    if mapping.schema_version != SCHEMA_VERSION
        || mapping.mapping_id.is_nil()
        || !is_sha256(&mapping.inventory_epoch_sha256)
        || !valid_text(&mapping.inventory_job_id, MAX_TEXT_BYTES)
        || !valid_text(&mapping.inventory_dependency_id, MAX_TEXT_BYTES)
        || !valid_text(&mapping.jenkins_credential_reference, MAX_REFERENCE_BYTES)
        || !valid_text(&mapping.environment, MAX_TEXT_BYTES)
        || !valid_text(&mapping.action, MAX_TEXT_BYTES)
        || !valid_text(&mapping.owner_identity, MAX_TEXT_BYTES)
        || !valid_text(&mapping.owner_approval_signer_key_id, MAX_TEXT_BYTES)
        || !is_sha256(&mapping.owner_approval_public_key_sha256)
        || mapping.owner_approved_at_unix_ms < 0
        || mapping.owner_approval_expires_unix_ms <= mapping.owner_approved_at_unix_ms
        || !is_sha256(&mapping.owner_approval_sha256)
        || !valid_text(&mapping.owner_approval_signature, MAX_REFERENCE_BYTES)
        || !valid_text(&mapping.provider_identity, MAX_TEXT_BYTES)
        || !valid_text(&mapping.provider_version, MAX_TEXT_BYTES)
        || !is_sha256(&mapping.provider_implementation_sha256)
        || !is_sha256(&mapping.provider_configuration_sha256)
        || !valid_text(&mapping.provider_reference, MAX_REFERENCE_BYTES)
        || !valid_text(&mapping.secret_version, MAX_TEXT_BYTES)
        || mapping.rotation_generation == 0
        || mapping.declared_taint != mapping.consumer.taint_class()
        || !valid_taint_path(&mapping.taint_path)
        || !is_sha256(&mapping.classification_evidence_sha256)
        || !valid_consumer(&mapping.consumer)
        || mapping.disposition != expected_disposition
    {
        return Err(BrokerError::InvalidMapping);
    }
    Ok(())
}

fn validate_rotation(
    prior: &CredentialMapping,
    replacement: &CredentialMapping,
) -> Result<(), BrokerError> {
    if prior.mapping_id != replacement.mapping_id
        || prior.inventory_epoch_sha256 != replacement.inventory_epoch_sha256
        || prior.inventory_job_id != replacement.inventory_job_id
        || prior.inventory_dependency_id != replacement.inventory_dependency_id
        || prior.jenkins_credential_reference != replacement.jenkins_credential_reference
        || prior.organization_id != replacement.organization_id
        || prior.project_id != replacement.project_id
        || prior.environment != replacement.environment
        || prior.action != replacement.action
        || prior.owner_identity != replacement.owner_identity
        || prior.consumer != replacement.consumer
        || prior.declared_taint != replacement.declared_taint
        || prior.taint_path != replacement.taint_path
        || prior.classification_evidence_sha256 != replacement.classification_evidence_sha256
        || prior.disposition != replacement.disposition
        || prior.provider_identity != replacement.provider_identity
    {
        return Err(BrokerError::Conflict);
    }
    Ok(())
}

fn validate_grant_request(request: &GrantRequest) -> Result<(), BrokerError> {
    let ttl = request
        .expires_at_unix_ms
        .checked_sub(request.requested_at_unix_ms);
    if request.protocol_version != GRANT_PROTOCOL_VERSION
        || request.grant_id.is_nil()
        || request.mapping_id.is_nil()
        || request.expected_rotation_generation == 0
        || !valid_text(&request.expected_provider_version, MAX_TEXT_BYTES)
        || !valid_text(&request.environment, MAX_TEXT_BYTES)
        || !valid_text(&request.action, MAX_TEXT_BYTES)
        || request.fence > i64::MAX as u64
        || !request.consumer.grant_eligible()
        || !valid_consumer(&request.consumer)
        || request.requested_at_unix_ms < 0
        || ttl.is_none_or(|ttl| !(1..=MAX_GRANT_TTL_MS).contains(&ttl))
        || !valid_text(&request.audit_provenance, MAX_REFERENCE_BYTES)
    {
        return Err(BrokerError::InvalidGrant);
    }
    Ok(())
}

fn grant_matches_mapping(request: &GrantRequest, mapping: &CredentialMapping) -> bool {
    mapping.disposition == MappingDisposition::GrantEligible
        && mapping.consumer.grant_eligible()
        && request.expected_provider_version == mapping.provider_version
        && request.organization_id == mapping.organization_id
        && request.project_id == mapping.project_id
        && request.environment == mapping.environment
        && request.action == mapping.action
        && request.consumer == mapping.consumer
}

fn valid_consumer(consumer: &ConsumerBinding) -> bool {
    if !valid_text(consumer.identity(), MAX_TEXT_BYTES) {
        return false;
    }
    match (
        consumer.implementation_sha256(),
        consumer.configuration_sha256(),
    ) {
        (Some(implementation), Some(configuration)) => {
            is_sha256(implementation) && is_sha256(configuration)
        }
        (None, None) => true,
        _ => false,
    }
}

fn valid_taint_path(path: &[String]) -> bool {
    !path.is_empty()
        && path.len() <= MAX_TAINT_PATH
        && path
            .iter()
            .all(|element| valid_text(element, MAX_TEXT_BYTES))
}

fn valid_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value == value.trim()
        && !value.chars().any(char::is_control)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, BrokerError> {
    let bytes = serde_json::to_vec(value)?;
    Ok(sha256_hex(&bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        use fmt::Write as _;
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

fn append_audit<T: Serialize>(
    transaction: &rusqlite::Transaction<'_>,
    event_type: &str,
    payload: &T,
) -> Result<(), BrokerError> {
    let canonical_payload = serde_json::to_vec(payload)?;
    let previous = transaction
        .query_row(
            "SELECT event_sha256 FROM audit_events ORDER BY sequence DESC LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .unwrap_or_else(|| ZERO_SHA256.to_owned());
    let event_sha256 = audit_event_sha256(&previous, event_type, &canonical_payload);
    transaction.execute(
        "INSERT INTO audit_events(event_type, canonical_payload, previous_sha256, event_sha256)
         VALUES (?1, ?2, ?3, ?4)",
        params![event_type, canonical_payload, previous, event_sha256],
    )?;
    Ok(())
}

fn audit_event_sha256(previous: &str, event_type: &str, canonical_payload: &[u8]) -> String {
    sha256_hex(
        [
            b"mcloving-secret-audit-v1\0".as_slice(),
            previous.as_bytes(),
            b"\0",
            event_type.as_bytes(),
            b"\0",
            canonical_payload,
        ]
        .concat()
        .as_slice(),
    )
}
