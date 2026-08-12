//! PostgreSQL-backed controller truth and transaction boundaries.

use aho_corasick::{AhoCorasickBuilder, MatchKind};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Acquire, PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

mod admin_migration;
mod audit;
mod authorization_mapping;
pub mod authz;
mod consumer_migration;
mod dag;
mod identity;
mod product;
mod scheduler;
mod security;
mod state_transfer;
mod test_results;
mod trigger_ingress;

pub use admin_migration::{
    ExternalAdminAuthority, ExternalAdminClientReceipt, ExternalAdminClientWrite,
    ExternalAdminDisposition, ExternalAdminOperation, ExternalAdminOperationContract,
    compute_external_admin_client_binding_digest, compute_external_admin_client_digest,
};
pub use audit::{
    AuditEvent, AuditExport, AuditPage, AuditRetentionPolicy, MAX_AUDIT_PAGE, NewAuditEvent,
    compute_audit_event_hash, verify_audit_export, verify_audit_page,
};
pub use authorization_mapping::{
    AuthorizationPolicyReceipt, AuthorizationPolicyWrite, AuthorizationPrincipalMappingWrite,
    compute_authorization_policy_digest,
};
pub use consumer_migration::{
    ExternalReadAuthority, ExternalReadConsumerReceipt, ExternalReadConsumerWrite,
    ExternalReadEndpointContract, ExternalReadResource,
    compute_external_read_consumer_binding_digest, compute_external_read_consumer_digest,
};
pub use dag::{
    DagAdmission, DagContractError, DagContractErrorCode, DagDependency, DagNodeAdmission,
    DagNodeKind, DagReplayBinding, DependencyCondition, MatrixCell, NewDagBuild, NewDagNode,
    compile_matrix, validate_dag_contract,
};
pub use identity::{
    AuthenticatedIdentity, IdentityLifecycle, IdentityProviderConfig, IdentityProviderWrite,
    LoginAttempt, NewHumanIdentity, NewServiceCredential, NewServiceIdentity, OidcIdentityClaims,
    ServiceCredential, SessionIssue, SessionView,
};
pub use product::{
    ApprovalView, AttemptView, BuildCursor, BuildGraph, BuildListItem, BuildPage, ComponentCursor,
    ComponentPage, ComponentPutOutcome, ComponentRecord, ComponentWrite, CredentialGrantView,
    DependencyView, MAX_PRODUCT_PAGE, NodeView, PipelineOperationalState,
    PipelineOperationalStateRecord, PipelineOperationalStateTransition,
    PipelineOperationalStateTransitionOutcome, PipelinePage, PipelinePutOutcome, PipelineRecord,
    PipelineWrite, TestReportView,
};
pub use scheduler::{ClaimRequest, ClaimedAttempt, WaitReason};
pub use security::{CredentialDelivery, NewCredentialGrant, NewEnvironmentApproval};
pub use state_transfer::{ScmCheckoutEvidenceRef, StateTransferReceipt};
pub use test_results::{
    DEFAULT_MAX_JUNIT_BYTES, DEFAULT_MAX_JUNIT_CASES, DEFAULT_MAX_JUNIT_SUITES, JunitLimits,
    NormalizedTestCase, NormalizedTestReport, NormalizedTestSuite,
    TEST_RESULT_RAW_RETENTION_SECONDS, TEST_RESULT_SCHEMA_VERSION, TestAggregate, TestCaseHistory,
    TestCaseObservation, TestOutcome, TestReportSource, TestResultError, parse_junit,
};
pub use trigger_ingress::{
    NewTriggerDelivery, PipelineTrigger, PipelineTriggerState, PipelineTriggerWrite,
    TriggerDelivery, TriggerDeliveryAdmission, TriggerDeliveryClaimOutcome,
    TriggerDeliveryClaimRequest, TriggerDeliveryCompletionRequest, TriggerDeliveryFailure,
    TriggerDeliveryFailureRequest, TriggerDeliveryRedrive, TriggerDeliveryStatus, TriggerKind,
    TriggerPutOutcome, TriggerScheduleSlot, TriggerScheduleWatermark, TriggerTransferSnapshot,
    compute_trigger_transfer_snapshot_digest, compute_trigger_transfer_snapshot_ledger_digest,
    verify_trigger_transfer_snapshot,
};

pub(crate) const RESTORE_FENCE_LOCK_KEY: i64 = 0x4d_63_4c_6f_76_72_65_63;
const MAX_ATTEMPT_LOG_BYTES: i64 = 64 * 1_048_576;
const MAX_ATTEMPT_LOG_CHUNKS: i64 = 66;
/// Largest caller-selected object-retention interval accepted by the controller.
///
/// This keeps PostgreSQL interval arithmetic comfortably inside its timestamp
/// range before any staged object is claimed for publication.
pub const MAX_OBJECT_RETENTION_SECONDS: i64 = 100 * 365 * 24 * 60 * 60;

/// Schema installed by [`Store::migrate`].
pub const CONTROLLER_SCHEMA_V1: &str = include_str!("../migrations/0001_controller_truth.sql");
/// Tenant identity and row-level-security migration.
pub const TENANT_SECURITY_V2: &str = include_str!("../migrations/0002_tenant_security.sql");
/// Public API and committed log migration.
pub const PUBLIC_API_V3: &str = include_str!("../migrations/0003_public_api.sql");
/// Immutable retry history and uncertain-effect reconciliation migration.
pub const DURABLE_RETRY_V4: &str = include_str!("../migrations/0004_durable_retry.sql");
/// Controller references to immutable object-store content.
pub const OBJECT_REFERENCES_V5: &str = include_str!("../migrations/0005_object_references.sql");
/// Backup checkpoints, restore fencing, retention, and legal-hold migration.
pub const RECOVERY_OPERATIONS_V6: &str = include_str!("../migrations/0006_recovery_operations.sql");
/// Durable, active-active-safe agent session authority.
pub const AGENT_SESSIONS_V7: &str = include_str!("../migrations/0007_agent_sessions.sql");
/// Trust-pool routing for executable nodes.
pub const NODE_TRUST_POOL_V8: &str = include_str!("../migrations/0008_node_trust_pool.sql");
/// Durable bounded pipeline-DAG scheduling truth.
pub const PIPELINE_DAG_V9: &str = include_str!("../migrations/0009_pipeline_dag.sql");
/// Attempt-scoped credentials and protected-environment approvals.
pub const ATTEMPT_CREDENTIALS_V10: &str =
    include_str!("../migrations/0010_attempt_credentials.sql");
/// Tenant-scoped, hash-chained append-only audit truth.
pub const TENANT_AUDIT_V11: &str = include_str!("../migrations/0011_tenant_audit.sql");
/// Product-facing immutable artifact metadata.
pub const ARTIFACT_METADATA_V12: &str = include_str!("../migrations/0012_artifact_metadata.sql");
/// Immutable, bounded, normalized test-result evidence.
pub const NORMALIZED_TEST_RESULTS_V13: &str = include_str!("../migrations/0013_test_results.sql");
/// Least-privilege deletion-claim probe for fenced artifact publication.
pub const OBJECT_PUBLICATION_FENCE_V14: &str =
    include_str!("../migrations/0014_object_publication_fence.sql");
/// Versioned pipeline and immutable component catalog product surface.
pub const PRODUCT_SURFACE_V15: &str = include_str!("../migrations/0015_product_surface.sql");
/// Monotonic cross-node ordering for resumable build-log pages.
pub const GLOBAL_LOG_ORDER_V16: &str = include_str!("../migrations/0016_global_log_order.sql");
/// Immutable, replay-safe Jenkins/McLoving persistent-state transfer records.
pub const STATE_TRANSFER_V17: &str = include_str!("../migrations/0017_state_transfer.sql");
/// Durable per-attempt dependency-generation readiness.
pub const ATTEMPT_READINESS_V18: &str = include_str!("../migrations/0018_attempt_readiness.sql");
/// Durable OIDC, principal-lifecycle, session, and service-credential truth.
pub const IDENTITY_LIFECYCLE_V19: &str = include_str!("../migrations/0019_identity_lifecycle.sql");
/// One-time rotating refresh credentials for durable human sessions.
pub const IDENTITY_SESSION_REFRESH_V20: &str =
    include_str!("../migrations/0020_identity_session_refresh.sql");
/// Explicit session lineages for targeted refresh-reuse and logout revocation.
pub const IDENTITY_SESSION_LINEAGE_V21: &str =
    include_str!("../migrations/0021_identity_session_lineage.sql");
/// Durable reservation of non-API secrets in the global credential namespace.
pub const CREDENTIAL_NAMESPACE_V22: &str =
    include_str!("../migrations/0022_credential_namespace.sql");
/// Fail-closed PostgreSQL function execution boundary for runtime sessions.
pub const RUNTIME_FUNCTION_BOUNDARY_V23: &str =
    include_str!("../migrations/0023_runtime_function_boundary.sql");
/// Immutable, provenance-bound Jenkins authorization policy generations.
pub const AUTHORIZATION_MAPPING_V24: &str =
    include_str!("../migrations/0024_authorization_mapping.sql");
/// Immutable external-reader contract and authority generations.
pub const EXTERNAL_READ_CONSUMERS_V25: &str =
    include_str!("../migrations/0025_external_read_consumers.sql");
/// Immutable administrative-writer contract and authority generations.
pub const EXTERNAL_ADMIN_CLIENTS_V26: &str =
    include_str!("../migrations/0026_external_admin_clients.sql");
/// Monotonic per-pipeline enabled/disabled truth and build-generation fences.
pub const PIPELINE_OPERATIONAL_STATE_V27: &str =
    include_str!("../migrations/0027_pipeline_operational_state.sql");
/// Typed authenticated trigger configurations and durable delivery truth.
pub const TRIGGER_INGRESS_V28: &str = include_str!("../migrations/0028_trigger_ingress.sql");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentReconciliationDisposition {
    Retain,
    Cancel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconciliationTrustPoolAuthorization {
    Matching,
    Missing,
    Mismatched,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentCancellationDisposition {
    Completed,
    RetireStale,
    ReconciliationRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentCancellationOutcome {
    Terminated,
    AlreadyExited,
    IdentityMismatch,
    ReconciliationRequired,
}

/// Fenced controller authority and the observed result of one cancellation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentCancellationCompletion<'a> {
    pub organization_id: Uuid,
    pub attempt_id: Uuid,
    pub fence: i64,
    pub restore_epoch: i64,
    pub agent_id: &'a str,
    pub session_epoch: u64,
    pub outcome: AgentCancellationOutcome,
}

/// A build and its first executable node, admitted as one durable unit.
#[derive(Clone, Debug)]
pub struct NewBuild {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub pipeline_id: Uuid,
    pub pipeline_revision: i64,
    pub pipeline_operational_generation: i64,
    pub idempotency_key: String,
    pub pipeline_digest: [u8; 32],
    pub node_key: String,
    pub required_capabilities: Vec<String>,
    pub required_trust_pool: String,
    pub priority: i32,
    pub execution_spec: Value,
}

/// Stable identifiers returned after admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAdmission {
    pub build_id: Uuid,
    pub node_id: Uuid,
    pub attempt_id: Uuid,
    pub created: bool,
}

/// Public read model for one build and its initial attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildSnapshot {
    pub build_id: Uuid,
    pub node_id: Uuid,
    pub attempt_id: Uuid,
    pub build_status: String,
    pub attempt_status: String,
    pub fence: i64,
    pub lease_owner: Option<String>,
    pub cancellation_requested: bool,
    pub terminal_summary: Option<Value>,
    pub execution_spec: Value,
}

/// One checksummed, controller-committed log chunk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedLog {
    pub attempt_id: Uuid,
    pub fence: i64,
    pub sequence: i64,
    pub stream: String,
    pub content: Vec<u8>,
    pub digest: [u8; 32],
}

/// Fenced log publication from one agent attempt.
pub struct NewLogChunk<'a> {
    pub organization_id: Uuid,
    pub attempt_id: Uuid,
    pub fence: i64,
    pub restore_epoch: i64,
    pub agent_id: &'a str,
    pub sequence: i64,
    pub stream: &'a str,
    pub content: &'a [u8],
}

/// Exact execution payload authorized by a live fenced offer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptExecution {
    pub build_id: Uuid,
    pub project_id: Uuid,
    pub execution_spec: Value,
    pub cancellation_requested: bool,
}

/// One transactionally published outbox record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedOutbox {
    pub id: i64,
    pub topic: String,
    pub aggregate_id: Uuid,
    pub payload: Value,
}

/// Idempotency classification for a durable external effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectClass {
    Idempotent,
    ExternallyIdempotent,
    NonIdempotent,
}

impl EffectClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::Idempotent => "idempotent",
            Self::ExternallyIdempotent => "externally_idempotent",
            Self::NonIdempotent => "non_idempotent",
        }
    }
}

/// Durable reconciliation state for one effect key and fencing epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectStatus {
    Prepared,
    Applied,
    Confirmed,
    Uncertain,
}

impl EffectStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Applied => "applied",
            Self::Confirmed => "confirmed",
            Self::Uncertain => "uncertain",
        }
    }
}

/// One immutable-payload effect checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectCheckpoint {
    pub attempt_id: Uuid,
    pub fence: i64,
    pub effect_key: String,
    pub effect_class: EffectClass,
    pub status: EffectStatus,
    pub payload: Value,
    pub payload_digest: [u8; 32],
}

/// Result of a durable retry decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryDecision {
    Scheduled {
        attempt_id: Uuid,
        ordinal: i32,
        created: bool,
    },
    DeadLettered,
    Ineligible,
}

/// Durable object category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectKind {
    Log,
    Artifact,
    Result,
}

impl ObjectKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Log => "log",
            Self::Artifact => "artifact",
            Self::Result => "result",
        }
    }
}

/// Explicit controller view of object-store availability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectStatus {
    Pending,
    Available,
    Missing,
    Corrupt,
}

impl ObjectStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Available => "available",
            Self::Missing => "missing",
            Self::Corrupt => "corrupt",
        }
    }
}

/// One controller-owned reference to immutable object content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredObject {
    pub attempt_id: Uuid,
    pub fence: i64,
    pub kind: ObjectKind,
    pub name: String,
    pub digest: [u8; 32],
    pub bytes: i64,
    pub status: ObjectStatus,
}

/// Product-facing artifact identity joined to its execution hierarchy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactMetadata {
    pub build_id: Uuid,
    pub node_id: Uuid,
    pub attempt_id: Uuid,
    pub fence: i64,
    pub name: String,
    pub digest: [u8; 32],
    pub bytes: i64,
    pub media_type: String,
    pub status: ObjectStatus,
}

/// Exclusive, durable authority to remove one globally unprotected CAS object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectDeletionClaim {
    pub digest: [u8; 32],
    pub token: Uuid,
}

/// A sealed database checkpoint that can anchor backup and PITR operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryPoint {
    pub backup_id: String,
    pub restore_epoch: i64,
    /// LSN persisted inside the sealed database row.
    pub sealed_lsn: String,
    /// Later WAL boundary that includes the transaction persisting `sealed_lsn`.
    pub recovery_lsn: String,
}

/// Result of activating restored controller truth.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreActivation {
    pub restore_epoch: i64,
    pub backup_id: String,
    pub sealed_lsn: String,
    pub affected_attempts: u64,
}

/// Terminal result accepted from a fenced attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalOutcome {
    Succeeded,
    Failed,
    Aborted,
}

impl TerminalOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Aborted => "aborted",
        }
    }
}

/// Transactional controller-store failure.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database operation failed: {0}")]
    Database(#[from] sqlx::Error),
    #[error("idempotent build exists without its initial node or attempt")]
    IncompleteAdmission,
    #[error("attempt {attempt_id} log sequence {sequence} has a corrupt digest")]
    CorruptLogDigest { attempt_id: Uuid, sequence: i64 },
    #[error("invalid durable effect payload: {0}")]
    InvalidEffectPayload(String),
    #[error("invalid durable object record: {0}")]
    InvalidObjectRecord(String),
    #[error("invalid recovery operation: {0}")]
    InvalidRecoveryOperation(String),
    #[error("invalid agent session authority")]
    InvalidAgentSession,
    #[error("required agent trust pool must be non-empty")]
    InvalidTrustPool,
    #[error("invalid pipeline DAG: {0}")]
    InvalidDag(String),
    #[error("idempotency key conflict: {0}")]
    IdempotencyConflict(String),
    #[error("invalid security operation: {0}")]
    InvalidSecurityOperation(String),
    #[error("security operation conflict: {0}")]
    SecurityConflict(String),
    #[error("invalid audit operation: {0}")]
    InvalidAuditOperation(String),
    #[error("invalid normalized test result: {0}")]
    InvalidTestResult(String),
    #[error("invalid product operation: {0}")]
    InvalidProductOperation(String),
    #[error("product catalog conflict: {0}")]
    ProductConflict(String),
    #[error("invalid pipeline operational-state operation: {0}")]
    InvalidPipelineState(String),
    #[error("pipeline operational-state conflict: {0}")]
    PipelineStateConflict(String),
    #[error("pipeline {pipeline_id} is disabled at operational generation {generation}")]
    PipelineDisabled { pipeline_id: Uuid, generation: i64 },
    #[error("invalid trigger ingress operation: {0}")]
    InvalidTriggerIngress(String),
    #[error("trigger ingress conflict: {0}")]
    TriggerIngressConflict(String),
    #[error("trigger {trigger_id} is paused at generation {generation}")]
    TriggerPaused { trigger_id: Uuid, generation: i64 },
    #[error("invalid state transfer: {0}")]
    InvalidStateTransfer(String),
    #[error("state-transfer conflict: {0}")]
    StateTransferConflict(String),
    #[error("invalid identity operation: {0}")]
    InvalidIdentityOperation(String),
    #[error("invalid runtime database configuration: {0}")]
    InvalidRuntimeConfiguration(String),
    #[error("identity operation conflict: {0}")]
    IdentityConflict(String),
    #[error("invalid authorization operation: {0}")]
    InvalidAuthorizationOperation(String),
    #[error("authorization operation conflict: {0}")]
    AuthorizationConflict(String),
    #[error("invalid external read consumer migration: {0}")]
    InvalidConsumerMigration(String),
    #[error("external read consumer migration conflict: {0}")]
    ConsumerMigrationConflict(String),
    #[error("invalid external admin client migration: {0}")]
    InvalidAdminMigration(String),
    #[error("external admin client migration conflict: {0}")]
    AdminMigrationConflict(String),
    #[error("audit chain for tenant {organization_id} is corrupt at sequence {sequence}")]
    CorruptAuditChain {
        organization_id: Uuid,
        sequence: i64,
    },
}

/// PostgreSQL source-of-truth facade.
#[derive(Clone, Debug)]
pub struct Store {
    pool: PgPool,
}

impl Store {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Proves that migration and runtime pools target the same live database,
    /// then verifies the exact RLS-constrained runtime role and its required
    /// privilege envelope before bootstrap rotates credentials.
    pub async fn preflight_tenant_runtime(
        &self,
        migration_store: &Self,
        organization_id: Uuid,
    ) -> Result<(), StoreError> {
        let lock_key = {
            let mut bytes = [0_u8; 8];
            bytes.copy_from_slice(&Uuid::new_v4().as_bytes()[..8]);
            i64::from_be_bytes(bytes)
        };
        let mut migration_tx = migration_store.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(lock_key)
            .execute(&mut *migration_tx)
            .await?;
        let migration_database = sqlx::query_as::<_, (String, i64)>(
            "SELECT current_database(), oid::bigint
               FROM pg_database
              WHERE datname = current_database()",
        )
        .fetch_one(&mut *migration_tx)
        .await?;

        let mut tx = self.tenant_transaction(organization_id).await?;
        let runtime_claimed_lock =
            sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_xact_lock($1)")
                .bind(lock_key)
                .fetch_one(&mut *tx)
                .await?;
        if runtime_claimed_lock {
            tx.rollback().await?;
            migration_tx.rollback().await?;
            return Err(StoreError::InvalidRuntimeConfiguration(
                "migration and runtime pools do not share one live PostgreSQL cluster".to_owned(),
            ));
        }
        let runtime_database = sqlx::query_as::<_, (String, i64)>(
            "SELECT current_database(), oid::bigint
               FROM pg_database
              WHERE datname = current_database()",
        )
        .fetch_one(&mut *tx)
        .await?;
        if runtime_database != migration_database {
            tx.rollback().await?;
            migration_tx.rollback().await?;
            return Err(StoreError::InvalidRuntimeConfiguration(
                "migration and runtime pools do not target the same PostgreSQL database".to_owned(),
            ));
        }

        let constrained_runtime_role = sqlx::query_scalar::<_, bool>(
            "SELECT session_user = current_user
                    AND rolname = 'mcloving_tenant'
                    AND rolcanlogin
                    AND NOT rolsuper
                    AND NOT rolbypassrls
                    AND NOT rolcreaterole
                    AND NOT rolcreatedb
                    AND NOT rolreplication
                    AND NOT EXISTS (
                        SELECT 1
                          FROM pg_auth_members
                         WHERE member = pg_roles.oid
                    )
               FROM pg_roles
              WHERE rolname = session_user",
        )
        .fetch_one(&mut *tx)
        .await?;
        if !constrained_runtime_role {
            tx.rollback().await?;
            migration_tx.rollback().await?;
            return Err(StoreError::InvalidRuntimeConfiguration(
                "runtime login must be the constrained mcloving_tenant role".to_owned(),
            ));
        }

        let required_privileges = sqlx::query_scalar::<_, bool>(
            "WITH expected_schema(privilege, is_grantable) AS (
                 VALUES ('USAGE', false)
             ),
             expected_tables(table_name, privilege) AS (
                 VALUES
                   ('organizations', 'SELECT'),
                   ('projects', 'SELECT'),
                   ('identities', 'SELECT'),
                   ('project_memberships', 'SELECT'),
                   ('service_scopes', 'SELECT'),
                   ('builds', 'SELECT'), ('builds', 'INSERT'),
                   ('builds', 'UPDATE'), ('builds', 'DELETE'),
                   ('nodes', 'SELECT'), ('nodes', 'INSERT'),
                   ('nodes', 'UPDATE'), ('nodes', 'DELETE'),
                   ('attempts', 'SELECT'), ('attempts', 'INSERT'),
                   ('attempts', 'UPDATE'), ('attempts', 'DELETE'),
                   ('build_events', 'SELECT'), ('build_events', 'INSERT'),
                   ('build_events', 'UPDATE'), ('build_events', 'DELETE'),
                   ('outbox', 'SELECT'), ('outbox', 'INSERT'),
                   ('outbox', 'UPDATE'), ('outbox', 'DELETE'),
                   ('attempt_log_chunks', 'SELECT'), ('attempt_log_chunks', 'INSERT'),
                   ('attempt_log_chunks', 'UPDATE'), ('attempt_log_chunks', 'DELETE'),
                   ('attempt_effects', 'SELECT'), ('attempt_effects', 'INSERT'),
                   ('attempt_effects', 'UPDATE'),
                   ('dead_letters', 'SELECT'), ('dead_letters', 'INSERT'),
                   ('attempt_objects', 'SELECT'), ('attempt_objects', 'INSERT'),
                   ('attempt_objects', 'UPDATE'),
                   ('controller_metadata', 'SELECT'),
                   ('object_retention', 'SELECT'), ('object_retention', 'INSERT'),
                   ('object_retention', 'UPDATE'),
                   ('legal_holds', 'SELECT'), ('legal_holds', 'INSERT'),
                   ('legal_holds', 'UPDATE'),
                   ('agent_sessions', 'SELECT'), ('agent_sessions', 'INSERT'),
                   ('agent_sessions', 'UPDATE'),
                   ('node_dependencies', 'SELECT'), ('node_dependencies', 'INSERT'),
                   ('node_dependencies', 'UPDATE'), ('node_dependencies', 'DELETE'),
                   ('protected_environments', 'SELECT'),
                   ('protected_environments', 'INSERT'),
                   ('protected_environments', 'UPDATE'),
                   ('environment_approvals', 'SELECT'),
                   ('environment_approvals', 'INSERT'),
                   ('environment_approvals', 'UPDATE'),
                   ('credential_grants', 'SELECT'), ('credential_grants', 'INSERT'),
                   ('credential_grants', 'UPDATE'),
                   ('audit_events', 'SELECT'), ('audit_events', 'INSERT'),
                   ('audit_chain_heads', 'SELECT'), ('audit_chain_heads', 'INSERT'),
                   ('audit_chain_heads', 'UPDATE'),
                   ('audit_retention_policies', 'SELECT'),
                   ('audit_retention_policies', 'INSERT'),
                   ('audit_retention_policies', 'UPDATE'),
                   ('normalized_test_reports', 'SELECT'),
                   ('normalized_test_reports', 'INSERT'),
                   ('normalized_test_suites', 'SELECT'),
                   ('normalized_test_suites', 'INSERT'),
                   ('normalized_test_cases', 'SELECT'),
                   ('normalized_test_cases', 'INSERT'),
                   ('pipeline_definitions', 'SELECT'),
                   ('pipeline_definitions', 'INSERT'),
                   ('pipeline_definitions', 'UPDATE'),
                   ('pipeline_revisions', 'SELECT'), ('pipeline_revisions', 'INSERT'),
                   ('pipeline_operational_state_history', 'SELECT'),
                   ('pipeline_operational_state_history', 'INSERT'),
                   ('pipeline_trigger_definitions', 'SELECT'),
                   ('pipeline_trigger_definitions', 'INSERT'),
                   ('pipeline_trigger_definitions', 'UPDATE'),
                   ('pipeline_trigger_versions', 'SELECT'),
                   ('pipeline_trigger_versions', 'INSERT'),
                   ('trigger_deliveries', 'SELECT'),
                   ('trigger_deliveries', 'INSERT'),
                   ('trigger_deliveries', 'UPDATE'),
                   ('trigger_schedule_watermarks', 'SELECT'),
                   ('trigger_schedule_watermarks', 'INSERT'),
                   ('trigger_schedule_watermarks', 'UPDATE'),
                   ('component_packages', 'SELECT'), ('component_packages', 'INSERT'),
                   ('state_transfer_receipts', 'SELECT'),
                   ('state_transfer_records', 'SELECT'),
                   ('state_transfer_protections', 'SELECT'),
                   ('state_transfer_scm_evidence', 'SELECT'),
                   ('identity_providers', 'SELECT'),
                   ('identity_group_snapshots', 'SELECT'),
                   ('identity_group_snapshots', 'INSERT'),
                   ('identity_group_snapshots', 'DELETE'),
                   ('oidc_token_replays', 'SELECT'), ('oidc_token_replays', 'INSERT'),
                   ('oidc_token_replays', 'DELETE'),
                   ('identity_sessions', 'SELECT'), ('identity_sessions', 'INSERT'),
                   ('identity_sessions', 'UPDATE'), ('identity_sessions', 'DELETE'),
                   ('service_credentials', 'SELECT'),
                   ('authorization_policy_versions', 'SELECT'),
                   ('authorization_principal_mappings', 'SELECT'),
                   ('authorization_action_grants', 'SELECT'),
                   ('authorization_project_policies', 'SELECT'),
                   ('external_read_consumer_versions', 'SELECT'),
                   ('external_read_consumer_current', 'SELECT'),
                   ('external_admin_client_versions', 'SELECT'),
                   ('external_admin_client_current', 'SELECT'),
                   ('oidc_login_attempts', 'SELECT'), ('oidc_login_attempts', 'INSERT'),
                   ('oidc_login_attempts', 'UPDATE'), ('oidc_login_attempts', 'DELETE'),
                   ('credential_namespace_reservations', 'SELECT'),
                   ('credential_namespace_reservations', 'INSERT')
             ),
             expected_columns(table_name, column_name, privilege, is_grantable) AS (
                 VALUES
                   ('identities', 'group_generation', 'UPDATE', false),
                   ('identities', 'group_digest', 'UPDATE', false),
                   ('identities', 'updated_at', 'UPDATE', false)
             ),
             expected_functions(function_oid, privilege, is_grantable) AS (
                 VALUES
                   ('public.mcloving_owned_object_publication_allowed(uuid,uuid,bigint,text,text,bytea)'::regprocedure, 'EXECUTE', false),
                   ('public.mcloving_state_transfer_holds_valid(jsonb)'::regprocedure, 'EXECUTE', false),
                   ('public.mcloving_state_transfer_digest_json(bytea)'::regprocedure, 'EXECUTE', false),
                   ('public.mcloving_state_transfer_normalize_holds(jsonb)'::regprocedure, 'EXECUTE', false),
                   ('public.mcloving_state_transfer_protection_digest(text,text,bytea,bigint,jsonb)'::regprocedure, 'EXECUTE', false),
                   ('public.mcloving_state_transfer_receipt_has_protection(uuid,uuid,uuid,bytea,text,text,bytea,bigint,jsonb)'::regprocedure, 'EXECUTE', false)
             ),
             actual_schema(privilege, is_grantable) AS (
                 SELECT acl.privilege_type, acl.is_grantable
                   FROM pg_namespace AS namespace
                  CROSS JOIN LATERAL aclexplode(
                      array_append(
                          COALESCE(namespace.nspacl, '{}'::aclitem[]),
                          makeaclitem(
                              namespace.nspowner,
                              namespace.nspowner,
                              'USAGE',
                              false
                          )
                      )
                  ) AS acl
                   JOIN pg_roles AS grantee ON grantee.oid = acl.grantee
                  WHERE namespace.nspname = 'public'
                    AND grantee.rolname = current_user
             ),
             public_schema_privileges AS (
                 SELECT acl.privilege_type
                   FROM pg_namespace AS namespace
                  CROSS JOIN LATERAL aclexplode(
                      array_append(
                          COALESCE(namespace.nspacl, '{}'::aclitem[]),
                          makeaclitem(
                              namespace.nspowner,
                              namespace.nspowner,
                              'USAGE',
                              false
                          )
                      )
                  ) AS acl
                  WHERE namespace.nspname = 'public'
                    AND acl.grantee = 0
             ),
             unexpected_named_schema_privileges AS (
                 SELECT acl.privilege_type
                   FROM pg_namespace AS namespace
                  CROSS JOIN LATERAL aclexplode(
                      array_append(
                          COALESCE(namespace.nspacl, '{}'::aclitem[]),
                          makeaclitem(
                              namespace.nspowner,
                              namespace.nspowner,
                              'USAGE',
                              false
                          )
                      )
                  ) AS acl
                   JOIN pg_roles AS grantee ON grantee.oid = acl.grantee
                  WHERE namespace.nspname = 'public'
                    AND acl.grantee <> namespace.nspowner
                    AND NOT (
                        grantee.rolname = current_user
                        AND acl.privilege_type = 'USAGE'
                        AND NOT acl.is_grantable
                    )
             ),
             actual_tables(table_name, privilege) AS (
                 SELECT table_name, privilege_type
                   FROM information_schema.table_privileges
                  WHERE table_schema = 'public'
                    AND grantee = current_user
             ),
             actual_columns(table_name, column_name, privilege, is_grantable) AS (
                 SELECT column_name.table_name,
                        column_name.column_name,
                        column_name.privilege_type,
                        column_name.is_grantable = 'YES'
                   FROM information_schema.column_privileges AS column_name
                  WHERE column_name.table_schema = 'public'
                    AND column_name.grantee = current_user
                    AND NOT EXISTS (
                        SELECT 1
                          FROM expected_tables AS table_grant
                         WHERE table_grant.table_name = column_name.table_name
                           AND table_grant.privilege = column_name.privilege_type
                    )
             ),
             expected_sequences(sequence_oid, privilege, is_grantable) AS (
                 SELECT sequence.oid, grant_name.privilege, false
                   FROM pg_class AS sequence
                   JOIN pg_namespace AS namespace
                     ON namespace.oid = sequence.relnamespace
                  CROSS JOIN (VALUES ('USAGE'), ('SELECT')) AS grant_name(privilege)
                  WHERE namespace.nspname = 'public'
                    AND sequence.relkind = 'S'
             ),
             actual_sequences(sequence_oid, privilege, is_grantable) AS (
                 SELECT sequence.oid, acl.privilege_type, acl.is_grantable
                   FROM pg_class AS sequence
                   JOIN pg_namespace AS namespace
                     ON namespace.oid = sequence.relnamespace
                  CROSS JOIN LATERAL aclexplode(
                      array_append(
                          COALESCE(sequence.relacl, '{}'::aclitem[]),
                          makeaclitem(
                              sequence.relowner,
                              sequence.relowner,
                              'SELECT',
                              false
                          )
                      )
                  ) AS acl
                   JOIN pg_roles AS grantee ON grantee.oid = acl.grantee
                  WHERE namespace.nspname = 'public'
                    AND sequence.relkind = 'S'
                    AND grantee.rolname = current_user
             ),
             actual_functions(function_oid, privilege, is_grantable) AS (
                 SELECT function.oid, acl.privilege_type, acl.is_grantable
                   FROM pg_proc AS function
                  JOIN pg_namespace AS namespace
                     ON namespace.oid = function.pronamespace
                  CROSS JOIN LATERAL aclexplode(
                      array_append(
                          COALESCE(
                              function.proacl,
                              acldefault('f', function.proowner)
                          ),
                          makeaclitem(
                              function.proowner,
                              function.proowner,
                              'EXECUTE',
                              false
                          )
                      )
                  ) AS acl
                   JOIN pg_roles AS grantee ON grantee.oid = acl.grantee
                  WHERE namespace.nspname = 'public'
                    AND grantee.rolname = current_user
             ),
             public_function_execution AS (
                 SELECT function.oid
                   FROM pg_proc AS function
                  JOIN pg_namespace AS namespace
                     ON namespace.oid = function.pronamespace
                  CROSS JOIN LATERAL aclexplode(
                      array_append(
                          COALESCE(
                              function.proacl,
                              acldefault('f', function.proowner)
                          ),
                          makeaclitem(
                              function.proowner,
                              function.proowner,
                              'EXECUTE',
                              false
                          )
                      )
                  ) AS acl
                  WHERE namespace.nspname = 'public'
                    AND acl.grantee = 0
                    AND acl.privilege_type = 'EXECUTE'
             ),
             runtime_owned_functions AS (
                 SELECT function.oid
                   FROM pg_proc AS function
                   JOIN pg_namespace AS namespace
                     ON namespace.oid = function.pronamespace
                   JOIN pg_roles AS owner ON owner.oid = function.proowner
                  WHERE namespace.nspname = 'public'
                    AND owner.rolname = session_user
             )
             SELECT has_schema_privilege(current_user, 'public', 'USAGE')
                    AND NOT has_schema_privilege(current_user, 'public', 'CREATE')
                    AND NOT EXISTS (
                        (SELECT * FROM expected_schema
                         EXCEPT
                         SELECT * FROM actual_schema)
                        UNION ALL
                        (SELECT * FROM actual_schema
                         EXCEPT
                         SELECT * FROM expected_schema)
                    )
                    AND NOT EXISTS (SELECT 1 FROM public_schema_privileges)
                    AND NOT EXISTS (
                        SELECT 1 FROM unexpected_named_schema_privileges
                    )
                    AND NOT EXISTS (
                        (SELECT * FROM expected_tables
                         EXCEPT
                         SELECT * FROM actual_tables)
                        UNION ALL
                        (SELECT * FROM actual_tables
                         EXCEPT
                         SELECT * FROM expected_tables)
                    )
                    AND NOT EXISTS (
                        (SELECT * FROM expected_columns
                         EXCEPT
                         SELECT * FROM actual_columns)
                        UNION ALL
                        (SELECT * FROM actual_columns
                         EXCEPT
                         SELECT * FROM expected_columns)
                    )
                    AND NOT EXISTS (
                        (SELECT * FROM expected_functions
                         EXCEPT
                         SELECT * FROM actual_functions)
                        UNION ALL
                        (SELECT * FROM actual_functions
                         EXCEPT
                         SELECT * FROM expected_functions)
                    )
                    AND NOT EXISTS (
                        (SELECT * FROM expected_sequences
                         EXCEPT
                         SELECT * FROM actual_sequences)
                        UNION ALL
                        (SELECT * FROM actual_sequences
                         EXCEPT
                         SELECT * FROM expected_sequences)
                    )
                    AND NOT EXISTS (SELECT 1 FROM public_function_execution)
                    AND NOT EXISTS (SELECT 1 FROM runtime_owned_functions)
                    AND NOT EXISTS (
                        SELECT 1
                          FROM information_schema.table_privileges
                         WHERE table_schema = 'public'
                           AND grantee IN ('PUBLIC', current_user)
                           AND is_grantable = 'YES'
                    )
                    AND NOT EXISTS (
                        SELECT 1
                          FROM information_schema.column_privileges
                         WHERE table_schema = 'public'
                           AND grantee = 'PUBLIC'
                    )
                    AND NOT EXISTS (
                        SELECT 1
                          FROM pg_class AS object
                         JOIN pg_namespace AS namespace
                            ON namespace.oid = object.relnamespace
                         CROSS JOIN LATERAL aclexplode(
                             array_append(
                                 COALESCE(object.relacl, '{}'::aclitem[]),
                                 makeaclitem(
                                     object.relowner,
                                     object.relowner,
                                     'SELECT',
                                     false
                                 )
                             )
                         ) AS acl
                         WHERE namespace.nspname = 'public'
                           AND object.relkind IN ('r', 'p', 'v', 'm', 'S')
                           AND acl.grantee = 0
                    )",
        )
        .fetch_one(&mut *tx)
        .await?;
        if !required_privileges {
            tx.rollback().await?;
            migration_tx.rollback().await?;
            return Err(StoreError::InvalidRuntimeConfiguration(
                "runtime role does not match the required least-privilege grant matrix".to_owned(),
            ));
        }

        let forced_rls = sqlx::query_scalar::<_, bool>(
            "WITH expected(table_name) AS (
                 VALUES
                   ('organizations'), ('projects'), ('identities'),
                   ('project_memberships'), ('service_scopes'), ('builds'),
                   ('nodes'), ('attempts'), ('build_events'), ('outbox'),
                   ('pipeline_definitions'), ('pipeline_revisions'),
                   ('pipeline_operational_state_history'),
                   ('pipeline_trigger_definitions'),
                   ('pipeline_trigger_versions'), ('trigger_deliveries'),
                   ('trigger_schedule_watermarks'),
                   ('component_packages'), ('attempt_log_chunks'),
                   ('attempt_effects'), ('dead_letters'), ('attempt_objects'),
                   ('state_transfer_receipts'), ('state_transfer_records'),
                   ('state_transfer_scm_evidence'), ('state_transfer_protections'),
                   ('object_retention'), ('legal_holds'), ('node_dependencies'),
                   ('identity_providers'), ('identity_group_snapshots'),
                   ('authorization_policy_versions'),
                   ('authorization_principal_mappings'),
                   ('authorization_action_grants'),
                   ('authorization_project_policies'),
                   ('external_read_consumer_versions'),
                   ('external_read_consumer_current'),
                   ('external_admin_client_versions'),
                   ('external_admin_client_current'),
                   ('oidc_login_attempts'), ('identity_sessions'),
                   ('oidc_token_replays'), ('service_credentials'),
                   ('protected_environments'), ('environment_approvals'),
                   ('credential_grants'), ('credential_namespace_reservations'),
                   ('audit_events'), ('audit_chain_heads'),
                   ('audit_retention_policies'), ('normalized_test_reports'),
                   ('normalized_test_suites'), ('normalized_test_cases')
             ),
             relations AS (
                 SELECT expected.table_name, class.oid, class.relowner,
                        class.relrowsecurity, class.relforcerowsecurity,
                        CASE
                            WHEN expected.table_name = 'organizations' THEN 'id'
                            ELSE 'organization_id'
                        END AS tenant_column
                   FROM expected
                   LEFT JOIN pg_class AS class
                     ON class.oid = format('public.%I', expected.table_name)::regclass
             ),
             policies AS (
                 SELECT relation.table_name, relation.tenant_column,
                        policy.polname, policy.polcmd, policy.polpermissive,
                        policy.polroles,
                        pg_get_expr(policy.polqual, policy.polrelid) AS using_expression,
                        pg_get_expr(policy.polwithcheck, policy.polrelid) AS check_expression
                   FROM relations AS relation
                   JOIN pg_policy AS policy ON policy.polrelid = relation.oid
             )
             SELECT COUNT(*) = 53
                    AND BOOL_AND(
                        relrowsecurity
                        AND relforcerowsecurity
                        AND relowner <> (
                            SELECT oid FROM pg_roles WHERE rolname = session_user
                        )
                    )
                    AND NOT EXISTS (
                        SELECT 1
                          FROM relations AS relation
                          LEFT JOIN policies AS policy
                            ON policy.table_name = relation.table_name
                         WHERE policy.polname IS NULL
                            OR policy.polname <> format(
                                '%s_tenant_policy', relation.table_name
                            )
                            OR policy.polcmd <> '*'
                            OR NOT policy.polpermissive
                            OR policy.polroles <> ARRAY[0]::oid[]
                            OR policy.using_expression <> format(
                                '(%I = (NULLIF(current_setting(''mcloving.organization_id''::text, true), ''''::text))::uuid)',
                                relation.tenant_column
                            )
                            OR policy.check_expression <> format(
                                '(%I = (NULLIF(current_setting(''mcloving.organization_id''::text, true), ''''::text))::uuid)',
                                relation.tenant_column
                            )
                    )
                    AND (SELECT COUNT(*) FROM policies) = 53
               FROM relations",
        )
        .fetch_one(&mut *tx)
        .await?;
        if !forced_rls {
            tx.rollback().await?;
            migration_tx.rollback().await?;
            return Err(StoreError::InvalidRuntimeConfiguration(
                "required tenant tables must enforce row-level security".to_owned(),
            ));
        }

        let (organization_visible, _, _, _) = sqlx::query_as::<_, (bool, i64, i64, i64)>(
            "SELECT
                 EXISTS (
                     SELECT 1
                     FROM organizations
                     WHERE id = $1
                 ),
                 (SELECT COUNT(*) FROM projects WHERE organization_id = $1),
                 (SELECT COUNT(*) FROM service_credentials WHERE organization_id = $1),
                 (SELECT COUNT(*)
                    FROM credential_namespace_reservations
                   WHERE organization_id = $1)",
        )
        .bind(organization_id)
        .fetch_one(&mut *tx)
        .await?;
        if !organization_visible {
            tx.rollback().await?;
            migration_tx.rollback().await?;
            return Err(StoreError::InvalidRuntimeConfiguration(format!(
                "organization {organization_id} is not visible to the runtime role"
            )));
        }
        let mut other_organization_id = Uuid::new_v4();
        while other_organization_id == organization_id {
            other_organization_id = Uuid::new_v4();
        }
        sqlx::query("SELECT set_config('mcloving.organization_id', $1, true)")
            .bind(other_organization_id.to_string())
            .execute(&mut *tx)
            .await?;
        let cross_tenant_visible = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (
                 SELECT 1 FROM organizations WHERE id = $1
             ) OR EXISTS (
                 SELECT 1 FROM projects WHERE organization_id = $1
             )",
        )
        .bind(organization_id)
        .fetch_one(&mut *tx)
        .await?;
        if cross_tenant_visible {
            tx.rollback().await?;
            migration_tx.rollback().await?;
            return Err(StoreError::InvalidRuntimeConfiguration(
                "tenant row-level-security policies permit cross-tenant visibility".to_owned(),
            ));
        }
        tx.rollback().await?;
        migration_tx.rollback().await?;
        Ok(())
    }

    /// Installs the version-one controller schema.
    pub async fn migrate(&self) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(0x4d_63_4c_6f_76_69_6e_67_i64)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS mcloving_schema_migrations (
                 version integer PRIMARY KEY,
                 installed_at timestamptz NOT NULL DEFAULT clock_timestamp()
             )",
        )
        .execute(&mut *tx)
        .await?;
        apply_migration(&mut tx, 1, CONTROLLER_SCHEMA_V1).await?;
        apply_migration(&mut tx, 2, TENANT_SECURITY_V2).await?;
        apply_migration(&mut tx, 3, PUBLIC_API_V3).await?;
        apply_migration(&mut tx, 4, DURABLE_RETRY_V4).await?;
        apply_migration(&mut tx, 5, OBJECT_REFERENCES_V5).await?;
        apply_migration(&mut tx, 6, RECOVERY_OPERATIONS_V6).await?;
        apply_migration(&mut tx, 7, AGENT_SESSIONS_V7).await?;
        apply_migration(&mut tx, 8, NODE_TRUST_POOL_V8).await?;
        apply_migration(&mut tx, 9, PIPELINE_DAG_V9).await?;
        apply_migration(&mut tx, 10, ATTEMPT_CREDENTIALS_V10).await?;
        apply_migration(&mut tx, 11, TENANT_AUDIT_V11).await?;
        apply_migration(&mut tx, 12, ARTIFACT_METADATA_V12).await?;
        apply_migration(&mut tx, 13, NORMALIZED_TEST_RESULTS_V13).await?;
        apply_migration(&mut tx, 14, OBJECT_PUBLICATION_FENCE_V14).await?;
        apply_migration(&mut tx, 15, PRODUCT_SURFACE_V15).await?;
        apply_migration(&mut tx, 16, GLOBAL_LOG_ORDER_V16).await?;
        apply_migration(&mut tx, 17, STATE_TRANSFER_V17).await?;
        apply_migration(&mut tx, 18, ATTEMPT_READINESS_V18).await?;
        apply_migration(&mut tx, 19, IDENTITY_LIFECYCLE_V19).await?;
        apply_migration(&mut tx, 20, IDENTITY_SESSION_REFRESH_V20).await?;
        apply_migration(&mut tx, 21, IDENTITY_SESSION_LINEAGE_V21).await?;
        apply_migration(&mut tx, 22, CREDENTIAL_NAMESPACE_V22).await?;
        apply_migration(&mut tx, 23, RUNTIME_FUNCTION_BOUNDARY_V23).await?;
        apply_migration(&mut tx, 24, AUTHORIZATION_MAPPING_V24).await?;
        apply_migration(&mut tx, 25, EXTERNAL_READ_CONSUMERS_V25).await?;
        apply_migration(&mut tx, 26, EXTERNAL_ADMIN_CLIENTS_V26).await?;
        apply_migration(&mut tx, 27, PIPELINE_OPERATIONAL_STATE_V27).await?;
        apply_migration(&mut tx, 28, TRIGGER_INGRESS_V28).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Atomically advances one agent session epoch across controller replicas.
    pub async fn open_agent_session(
        &self,
        agent_id: &str,
        trust_pool: &str,
        session_epoch: u64,
        protocol_minor: u16,
        features: &[String],
        capabilities: &[String],
    ) -> Result<bool, StoreError> {
        let session_epoch =
            i64::try_from(session_epoch).map_err(|_| StoreError::InvalidAgentSession)?;
        let row = sqlx::query_scalar::<_, i64>(
            "INSERT INTO agent_sessions(
                 agent_id, trust_pool, session_epoch, protocol_minor,
                 features, capabilities
             )
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (agent_id) DO UPDATE
             SET trust_pool = EXCLUDED.trust_pool,
                 session_epoch = EXCLUDED.session_epoch,
                 protocol_minor = EXCLUDED.protocol_minor,
                 features = EXCLUDED.features,
                 capabilities = EXCLUDED.capabilities,
                 updated_at = clock_timestamp()
             WHERE agent_sessions.session_epoch < EXCLUDED.session_epoch
             RETURNING session_epoch",
        )
        .bind(agent_id)
        .bind(trust_pool)
        .bind(session_epoch)
        .bind(i32::from(protocol_minor))
        .bind(features)
        .bind(capabilities)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.is_some())
    }

    pub async fn authorize_agent_session(
        &self,
        agent_id: &str,
        session_epoch: u64,
    ) -> Result<bool, StoreError> {
        let session_epoch =
            i64::try_from(session_epoch).map_err(|_| StoreError::InvalidAgentSession)?;
        Ok(sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(
                 SELECT 1 FROM agent_sessions
                 WHERE agent_id = $1 AND session_epoch = $2
             )",
        )
        .bind(agent_id)
        .bind(session_epoch)
        .fetch_one(&self.pool)
        .await?)
    }

    /// Binds a fenced attempt authority to the trust pool durably required by
    /// its node. Re-enrollment may advance an agent session, but it must never
    /// let a certificate in a different pool inherit prior fenced authority.
    #[allow(clippy::too_many_arguments)]
    pub async fn authorize_attempt_trust_pool(
        &self,
        organization_id: Uuid,
        attempt_id: Uuid,
        fence: i64,
        restore_epoch: i64,
        agent_id: &str,
        trust_pool: &str,
    ) -> Result<bool, StoreError> {
        let mut tx = self.tenant_transaction(organization_id).await?;
        acquire_restore_fence_shared(&mut tx).await?;
        let authorized = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(
                 SELECT 1
                 FROM attempts AS a
                 JOIN nodes AS n
                   ON n.id = a.node_id
                  AND n.organization_id = a.organization_id
                 CROSS JOIN controller_metadata AS m
                 WHERE a.organization_id = $1
                   AND a.id = $2
                   AND a.fence = $3
                   AND a.restore_epoch = $4
                   AND a.lease_owner = $5
                   AND n.required_trust_pool = $6
                   AND m.singleton
                   AND a.restore_epoch = m.restore_epoch
             )",
        )
        .bind(organization_id)
        .bind(attempt_id)
        .bind(fence)
        .bind(restore_epoch)
        .bind(agent_id)
        .bind(trust_pool)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(authorized)
    }

    /// Authorizes a journaled attempt to enter reconciliation using only its
    /// immutable node trust pool. Live fence, restore epoch, and lease-owner
    /// checks belong to the subsequent disposition/recovery transaction:
    /// stale authority must be able to receive `Cancel`, but can never be
    /// retained or recovered.
    pub async fn authorize_reconciliation_trust_pool(
        &self,
        organization_id: Uuid,
        attempt_id: Uuid,
        trust_pool: &str,
    ) -> Result<ReconciliationTrustPoolAuthorization, StoreError> {
        let mut tx = self.tenant_transaction(organization_id).await?;
        let required_trust_pool = sqlx::query_scalar::<_, String>(
            "SELECT n.required_trust_pool
             FROM attempts AS a
             JOIN nodes AS n
               ON n.id = a.node_id
              AND n.organization_id = a.organization_id
             WHERE a.organization_id = $1
               AND a.id = $2",
        )
        .bind(organization_id)
        .bind(attempt_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(match required_trust_pool {
            Some(required) if required == trust_pool => {
                ReconciliationTrustPoolAuthorization::Matching
            }
            Some(_) => ReconciliationTrustPoolAuthorization::Mismatched,
            None => ReconciliationTrustPoolAuthorization::Missing,
        })
    }

    /// Returns only the capabilities durably bound to the exact current session.
    pub async fn agent_session_capabilities(
        &self,
        agent_id: &str,
        session_epoch: u64,
    ) -> Result<Option<Vec<String>>, StoreError> {
        let session_epoch =
            i64::try_from(session_epoch).map_err(|_| StoreError::InvalidAgentSession)?;
        Ok(sqlx::query_scalar::<_, Vec<String>>(
            "SELECT capabilities
             FROM agent_sessions
             WHERE agent_id = $1 AND session_epoch = $2",
        )
        .bind(agent_id)
        .bind(session_epoch)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Resolves a recovered attempt against current durable controller truth.
    pub async fn agent_reconciliation_disposition(
        &self,
        organization_id: Uuid,
        attempt_id: Uuid,
        fence: i64,
        restore_epoch: i64,
        agent_id: &str,
    ) -> Result<AgentReconciliationDisposition, StoreError> {
        self.agent_reconciliation_disposition_with_session(
            organization_id,
            attempt_id,
            fence,
            restore_epoch,
            agent_id,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn agent_reconciliation_disposition_in_session(
        &self,
        organization_id: Uuid,
        attempt_id: Uuid,
        fence: i64,
        restore_epoch: i64,
        agent_id: &str,
        session_epoch: u64,
    ) -> Result<AgentReconciliationDisposition, StoreError> {
        self.agent_reconciliation_disposition_with_session(
            organization_id,
            attempt_id,
            fence,
            restore_epoch,
            agent_id,
            Some(session_epoch),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn agent_reconciliation_disposition_with_session(
        &self,
        organization_id: Uuid,
        attempt_id: Uuid,
        fence: i64,
        restore_epoch: i64,
        agent_id: &str,
        session_epoch: Option<u64>,
    ) -> Result<AgentReconciliationDisposition, StoreError> {
        let mut tx = self.tenant_transaction(organization_id).await?;
        if let Some(session_epoch) = session_epoch
            && !Self::lock_agent_session(&mut tx, agent_id, session_epoch).await?
        {
            tx.rollback().await?;
            return Ok(AgentReconciliationDisposition::Cancel);
        }
        let row = sqlx::query_as::<_, (bool, bool)>(
            "SELECT
                 a.fence = $3
                 AND a.restore_epoch = $4
                 AND a.lease_owner = $5
                 AND a.restore_epoch = (
                     SELECT restore_epoch FROM controller_metadata WHERE singleton
                 )
                 AND a.status IN (
                     'offered', 'accepted', 'running', 'finalizing', 'cancelling',
                     'reconciliation_required'
                 ) AS current_authority,
                 a.status <> 'reconciliation_required'
                 AND (
                     b.cancellation_requested_at IS NOT NULL
                     OR a.status = 'cancelling'
                 )
             FROM attempts AS a
             JOIN nodes AS n
               ON n.id = a.node_id AND n.organization_id = a.organization_id
             JOIN builds AS b
               ON b.id = n.build_id AND b.organization_id = n.organization_id
             WHERE a.organization_id = $1 AND a.id = $2",
        )
        .bind(organization_id)
        .bind(attempt_id)
        .bind(fence)
        .bind(restore_epoch)
        .bind(agent_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(match row {
            Some((true, false)) => AgentReconciliationDisposition::Retain,
            _ => AgentReconciliationDisposition::Cancel,
        })
    }

    /// Re-establishes bounded upload authority for an exact locally-finalizing
    /// attempt after an agent reconnect.
    ///
    /// The scheduler lock prevents an expired lease from being requeued while
    /// immutable spool evidence is replayed. Already-terminal exact authority
    /// is retained so response-loss replay can converge without another
    /// terminal event.
    #[allow(clippy::too_many_arguments)]
    pub async fn recover_agent_finalization(
        &self,
        organization_id: Uuid,
        attempt_id: Uuid,
        fence: i64,
        restore_epoch: i64,
        agent_id: &str,
        local_phase: &str,
        lease_seconds: i32,
    ) -> Result<bool, StoreError> {
        self.recover_agent_finalization_with_session(
            organization_id,
            attempt_id,
            fence,
            restore_epoch,
            agent_id,
            None,
            local_phase,
            lease_seconds,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn recover_agent_finalization_in_session(
        &self,
        organization_id: Uuid,
        attempt_id: Uuid,
        fence: i64,
        restore_epoch: i64,
        agent_id: &str,
        session_epoch: u64,
        local_phase: &str,
        lease_seconds: i32,
    ) -> Result<bool, StoreError> {
        self.recover_agent_finalization_with_session(
            organization_id,
            attempt_id,
            fence,
            restore_epoch,
            agent_id,
            Some(session_epoch),
            local_phase,
            lease_seconds,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn recover_agent_finalization_with_session(
        &self,
        organization_id: Uuid,
        attempt_id: Uuid,
        fence: i64,
        restore_epoch: i64,
        agent_id: &str,
        session_epoch: Option<u64>,
        local_phase: &str,
        lease_seconds: i32,
    ) -> Result<bool, StoreError> {
        if !matches!(local_phase, "finalizing" | "cancelling") || lease_seconds <= 0 {
            return Ok(false);
        }
        let mut tx = self.tenant_transaction(organization_id).await?;
        if let Some(session_epoch) = session_epoch
            && !Self::lock_agent_session(&mut tx, agent_id, session_epoch).await?
        {
            tx.rollback().await?;
            return Ok(false);
        }
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!("mcloving.scheduler.{organization_id}"))
            .execute(&mut *tx)
            .await?;
        acquire_restore_fence_shared(&mut tx).await?;
        let status = sqlx::query_scalar::<_, String>(
            "SELECT a.status
             FROM attempts AS a
             CROSS JOIN controller_metadata AS m
             WHERE a.organization_id = $1
               AND a.id = $2
               AND a.fence = $3
               AND a.restore_epoch = $4
               AND a.lease_owner = $5
               AND m.singleton
               AND a.restore_epoch = m.restore_epoch
             FOR UPDATE OF a",
        )
        .bind(organization_id)
        .bind(attempt_id)
        .bind(fence)
        .bind(restore_epoch)
        .bind(agent_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(status) = status else {
            tx.rollback().await?;
            return Ok(false);
        };
        let terminal = matches!(status.as_str(), "succeeded" | "failed" | "aborted");
        // The local phase records how evidence must be replayed, not which
        // completion protocol won the race. Exact fenced authority may observe
        // cancellation while work is completing (or completion while the
        // controller is cancelling), so every nonterminal completion phase is
        // recoverable and converges through the durable result.
        let resumable = recoverable_finalization_status(&status);
        if !terminal && !resumable {
            tx.rollback().await?;
            return Ok(false);
        }
        if resumable {
            sqlx::query(
                "UPDATE attempts
                 SET status = $3,
                     lease_expires_at =
                         clock_timestamp() + make_interval(secs => $4)
                 WHERE organization_id = $1 AND id = $2",
            )
            .bind(organization_id)
            .bind(attempt_id)
            .bind(local_phase)
            .bind(f64::from(lease_seconds))
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(true)
    }

    /// Atomically acknowledges a fenced agent's cancellation or interrupted
    /// execution recovery outcome.
    ///
    /// A reconnect may arrive after its lease deadline, so cancellation
    /// completion is authorized by the current restore epoch, exact fence, and
    /// exact lease owner and current session trust pool rather than by an
    /// unexpired lease. Response-loss
    /// replay of an already-applied outcome succeeds without emitting a second
    /// event. Unverifiable process termination and uncertain external effects
    /// fail closed into explicit reconciliation instead of being mislabeled
    /// aborted.
    pub async fn complete_agent_cancellation(
        &self,
        completion: AgentCancellationCompletion<'_>,
    ) -> Result<AgentCancellationDisposition, StoreError> {
        let AgentCancellationCompletion {
            organization_id,
            attempt_id,
            fence,
            restore_epoch,
            agent_id,
            session_epoch,
            outcome,
        } = completion;
        let mut tx = self.tenant_transaction(organization_id).await?;
        acquire_restore_fence_shared(&mut tx).await?;
        if !Self::lock_agent_session(&mut tx, agent_id, session_epoch).await? {
            tx.rollback().await?;
            return Ok(AgentCancellationDisposition::RetireStale);
        }
        let authority = sqlx::query_as::<_, (Uuid, Uuid, String, Option<Value>, bool, bool)>(
            "SELECT n.id, n.build_id, a.status, a.terminal_summary,
                    b.cancellation_requested_at IS NOT NULL, b.dag_mode
             FROM attempts AS a
             JOIN nodes AS n
               ON n.id = a.node_id
              AND n.organization_id = a.organization_id
             JOIN builds AS b
               ON b.id = n.build_id
              AND b.organization_id = n.organization_id
             JOIN agent_sessions AS s
               ON s.agent_id = a.lease_owner
              AND s.session_epoch = $6
              AND s.trust_pool = n.required_trust_pool
             WHERE a.id = $1
               AND a.organization_id = $2
               AND a.fence = $3
               AND a.restore_epoch = $4
               AND a.lease_owner = $5
               AND a.restore_epoch = (
                   SELECT restore_epoch
                   FROM controller_metadata
                   WHERE singleton
               )
               AND a.status IN (
                   'accepted', 'running', 'cancelling', 'aborted',
                   'reconciliation_required'
               )
             FOR UPDATE OF a, n, b",
        )
        .bind(attempt_id)
        .bind(organization_id)
        .bind(fence)
        .bind(restore_epoch)
        .bind(agent_id)
        .bind(i64::try_from(session_epoch).map_err(|_| StoreError::InvalidAgentSession)?)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((node_id, build_id, status, terminal_summary, owner_cancelled, dag_mode)) =
            authority
        else {
            tx.rollback().await?;
            return Ok(AgentCancellationDisposition::RetireStale);
        };
        if status == "aborted" {
            tx.commit().await?;
            return Ok(
                if matches!(
                    terminal_summary
                        .as_ref()
                        .and_then(|value| value.get("reason"))
                        .and_then(Value::as_str),
                    Some("agent_process_identity_mismatch" | "agent_recovery_stale_process")
                ) {
                    AgentCancellationDisposition::RetireStale
                } else {
                    AgentCancellationDisposition::Completed
                },
            );
        }
        if status == "reconciliation_required" {
            tx.commit().await?;
            return Ok(AgentCancellationDisposition::ReconciliationRequired);
        }

        let uncertain_effects = sqlx::query_scalar::<_, i64>(
            "SELECT count(*)
             FROM attempt_effects
             WHERE organization_id = $1
               AND attempt_id = $2
               AND fence = $3
               AND status = 'uncertain'",
        )
        .bind(organization_id)
        .bind(attempt_id)
        .bind(fence)
        .fetch_one(&mut *tx)
        .await?;
        if outcome == AgentCancellationOutcome::ReconciliationRequired || uncertain_effects > 0 {
            sqlx::query(
                "UPDATE attempts
                 SET status = 'reconciliation_required',
                     lease_expires_at = NULL
                 WHERE id = $1 AND organization_id = $2",
            )
            .bind(attempt_id)
            .bind(organization_id)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE nodes
                 SET status = 'reconciliation_required'
                 WHERE id = $1 AND organization_id = $2",
            )
            .bind(node_id)
            .bind(organization_id)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE builds
                 SET status = 'reconciliation_required', completed_at = NULL
                 WHERE id = $1 AND organization_id = $2",
            )
            .bind(build_id)
            .bind(organization_id)
            .execute(&mut *tx)
            .await?;
            append_event_and_outbox(
                &mut tx,
                organization_id,
                build_id,
                "attempt.cancellation_reconciliation_required",
                json!({
                    "attempt_id": attempt_id,
                    "fence": fence,
                    "agent_id": agent_id,
                    "process_termination": match outcome {
                        AgentCancellationOutcome::Terminated => "terminated",
                        AgentCancellationOutcome::AlreadyExited => "already_exited",
                        AgentCancellationOutcome::IdentityMismatch => "identity_mismatch",
                        AgentCancellationOutcome::ReconciliationRequired => "unverifiable",
                    },
                    "uncertain_effects": uncertain_effects,
                }),
            )
            .await?;
            tx.commit().await?;
            return Ok(AgentCancellationDisposition::ReconciliationRequired);
        }

        // Reconciliation promotes a locally cancelling interrupted execution
        // from accepted/running to cancelling before its durable cancellation
        // result is replayed. With no owner cancellation request, that status
        // is still recovery-originated and must converge to a terminal result.
        let recovery =
            !owner_cancelled && matches!(status.as_str(), "accepted" | "running" | "cancelling");
        if !owner_cancelled && !recovery {
            tx.rollback().await?;
            return Ok(AgentCancellationDisposition::RetireStale);
        }
        let (terminal_reason, event_kind, disposition) = match outcome {
            AgentCancellationOutcome::Terminated => (
                if recovery {
                    "agent_recovery_terminated"
                } else {
                    "agent_confirmed_cancellation"
                },
                if recovery {
                    "attempt.recovery_terminated"
                } else {
                    "attempt.cancellation_completed"
                },
                AgentCancellationDisposition::Completed,
            ),
            AgentCancellationOutcome::AlreadyExited => (
                if recovery {
                    "agent_recovery_process_already_exited"
                } else {
                    "agent_process_already_exited"
                },
                if recovery {
                    "attempt.recovery_process_already_exited"
                } else {
                    "attempt.cancellation_completed"
                },
                AgentCancellationDisposition::Completed,
            ),
            AgentCancellationOutcome::IdentityMismatch => (
                if recovery {
                    "agent_recovery_stale_process"
                } else {
                    "agent_process_identity_mismatch"
                },
                if recovery {
                    "attempt.recovery_stale_process"
                } else {
                    "attempt.cancellation_stale_process"
                },
                AgentCancellationDisposition::RetireStale,
            ),
            AgentCancellationOutcome::ReconciliationRequired => {
                unreachable!("reconciliation-required outcome returned above")
            }
        };
        sqlx::query(
            "UPDATE attempts
             SET status = 'aborted',
                 terminal_summary = $3,
                 completed_at = clock_timestamp(),
                 lease_expires_at = NULL
             WHERE id = $1 AND organization_id = $2",
        )
        .bind(attempt_id)
        .bind(organization_id)
        .bind(json!({"reason": terminal_reason}))
        .execute(&mut *tx)
        .await?;
        if dag_mode {
            dag::advance_dag_after_attempt(
                &mut tx,
                organization_id,
                build_id,
                node_id,
                attempt_id,
                TerminalOutcome::Aborted,
            )
            .await?;
        } else {
            sqlx::query(
                "UPDATE nodes
                 SET status = 'aborted'
                 WHERE id = $1 AND organization_id = $2",
            )
            .bind(node_id)
            .bind(organization_id)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE builds
                 SET status = 'aborted', completed_at = clock_timestamp()
                 WHERE id = $1 AND organization_id = $2",
            )
            .bind(build_id)
            .bind(organization_id)
            .execute(&mut *tx)
            .await?;
        }
        append_event_and_outbox(
            &mut tx,
            organization_id,
            build_id,
            event_kind,
            json!({
                "attempt_id": attempt_id,
                "fence": fence,
                "agent_id": agent_id,
                "process_termination": match outcome {
                    AgentCancellationOutcome::Terminated => "terminated",
                    AgentCancellationOutcome::AlreadyExited => "already_exited",
                    AgentCancellationOutcome::IdentityMismatch => "identity_mismatch",
                    AgentCancellationOutcome::ReconciliationRequired => "unverifiable",
                },
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(disposition)
    }

    /// Creates an organization/project pair for bootstrap and tests.
    pub async fn create_project(
        &self,
        organization_id: Uuid,
        organization_slug: &str,
        project_id: Uuid,
        project_slug: &str,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO organizations (id, slug) VALUES ($1, $2)")
            .bind(organization_id)
            .bind(organization_slug)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO projects (id, organization_id, slug) VALUES ($1, $2, $3)")
            .bind(project_id)
            .bind(organization_id)
            .bind(project_slug)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Commits build, node, initial attempt, event, and outbox message together.
    ///
    /// Repeating the same project/idempotency-key returns the original durable
    /// identifiers without emitting a second event or outbox record.
    pub async fn admit_build(&self, input: &NewBuild) -> Result<BuildAdmission, StoreError> {
        if input.required_trust_pool.trim().is_empty()
            || input.required_trust_pool.trim() != input.required_trust_pool
        {
            return Err(StoreError::InvalidTrustPool);
        }
        let mut tx = self.tenant_transaction(input.organization_id).await?;
        lock_pipeline_transaction(&mut tx, input.organization_id, input.pipeline_id).await?;
        if let Some(existing) = existing_admission(&mut tx, input).await? {
            tx.commit().await?;
            return Ok(existing);
        }
        let pipeline_revision_digest = lock_enabled_pipeline_binding(
            &mut tx,
            input.organization_id,
            input.project_id,
            input.pipeline_id,
            input.pipeline_revision,
            input.pipeline_operational_generation,
        )
        .await?;
        let build_id = Uuid::new_v4();
        let inserted = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO builds (
                 id, organization_id, project_id,
                 pipeline_id, pipeline_revision, pipeline_operational_generation,
                 pipeline_revision_digest,
                 idempotency_key, pipeline_digest, status, priority
             )
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'queued', $10)
             ON CONFLICT (project_id, idempotency_key) DO NOTHING
             RETURNING id",
        )
        .bind(build_id)
        .bind(input.organization_id)
        .bind(input.project_id)
        .bind(input.pipeline_id)
        .bind(input.pipeline_revision)
        .bind(input.pipeline_operational_generation)
        .bind(pipeline_revision_digest.as_slice())
        .bind(&input.idempotency_key)
        .bind(input.pipeline_digest.as_slice())
        .bind(input.priority)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(build_id) = inserted else {
            let existing = existing_admission(&mut tx, input)
                .await?
                .ok_or(StoreError::IncompleteAdmission)?;
            tx.commit().await?;
            return Ok(existing);
        };

        let node_id = Uuid::new_v4();
        let attempt_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO nodes (
                 id, organization_id, build_id, node_key, status,
                 required_capabilities, required_trust_pool, priority, execution_spec
             )
             VALUES ($1, $2, $3, $4, 'queued', $5, $6, $7, $8)",
        )
        .bind(node_id)
        .bind(input.organization_id)
        .bind(build_id)
        .bind(&input.node_key)
        .bind(&input.required_capabilities)
        .bind(&input.required_trust_pool)
        .bind(input.priority)
        .bind(&input.execution_spec)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "WITH timing AS (SELECT clock_timestamp() AS admitted_at)
             INSERT INTO attempts (
                 id, organization_id, node_id, ordinal, status,
                 created_at, ready_at
             )
             SELECT $1, $2, $3, 1, 'queued', admitted_at, admitted_at
             FROM timing",
        )
        .bind(attempt_id)
        .bind(input.organization_id)
        .bind(node_id)
        .execute(&mut *tx)
        .await?;
        append_event_and_outbox(
            &mut tx,
            input.organization_id,
            build_id,
            "build.admitted",
            json!({
                "build_id": build_id,
                "node_id": node_id,
                "attempt_id": attempt_id,
            }),
        )
        .await?;
        tx.commit().await?;

        Ok(BuildAdmission {
            build_id,
            node_id,
            attempt_id,
            created: true,
        })
    }

    /// Returns the tenant-scoped public build view.
    pub async fn build_snapshot(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        build_id: Uuid,
    ) -> Result<Option<BuildSnapshot>, StoreError> {
        type SnapshotRow = (
            Uuid,
            Uuid,
            Uuid,
            String,
            String,
            i64,
            Option<String>,
            bool,
            Option<Value>,
            Value,
        );
        let mut tx = self.tenant_transaction(organization_id).await?;
        let row = sqlx::query_as::<_, SnapshotRow>(
            "SELECT b.id, n.id, a.id, b.status, a.status, a.fence,
                    a.lease_owner, b.cancellation_requested_at IS NOT NULL,
                    a.terminal_summary, n.execution_spec
             FROM builds AS b
             JOIN nodes AS n
               ON n.build_id = b.id AND n.organization_id = b.organization_id
             JOIN attempts AS a
               ON a.node_id = n.id AND a.organization_id = n.organization_id
             WHERE b.organization_id = $1
               AND b.project_id = $2
               AND b.id = $3
             ORDER BY a.ordinal DESC
             LIMIT 1",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(build_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.map(
            |(
                build_id,
                node_id,
                attempt_id,
                build_status,
                attempt_status,
                fence,
                lease_owner,
                cancellation_requested,
                terminal_summary,
                execution_spec,
            )| BuildSnapshot {
                build_id,
                node_id,
                attempt_id,
                build_status,
                attempt_status,
                fence,
                lease_owner,
                cancellation_requested,
                terminal_summary,
                execution_spec,
            },
        ))
    }

    /// Requests cancellation exactly once.
    ///
    /// Queued work is aborted atomically because no agent owns it. Active work
    /// moves to `cancelling` and remains non-terminal until the fenced agent
    /// publishes its result.
    pub async fn request_cancellation(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        build_id: Uuid,
    ) -> Result<bool, StoreError> {
        self.request_cancellation_as(organization_id, project_id, build_id, "system:controller")
            .await
    }

    pub async fn request_cancellation_as(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        build_id: Uuid,
        actor_subject: &str,
    ) -> Result<bool, StoreError> {
        validate_audit_actor(actor_subject)?;
        let mut tx = self.tenant_transaction(organization_id).await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!("mcloving.scheduler.{organization_id}"))
            .execute(&mut *tx)
            .await?;
        let dag_mode = sqlx::query_scalar::<_, bool>(
            "SELECT dag_mode
             FROM builds
             WHERE organization_id = $1
               AND project_id = $2
               AND id = $3
               AND status IN ('queued', 'running')
             FOR UPDATE",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(build_id)
        .fetch_optional(&mut *tx)
        .await?;
        if dag_mode == Some(true) {
            if !dag::cancel_dag_build(&mut tx, organization_id, build_id).await? {
                tx.rollback().await?;
                return Ok(false);
            }
            append_event_and_outbox_as(
                &mut tx,
                organization_id,
                build_id,
                actor_subject,
                "build.cancellation_requested",
                json!({
                    "dag": true,
                }),
            )
            .await?;
            tx.commit().await?;
            return Ok(true);
        }
        let attempt = sqlx::query_as::<_, (Uuid, Uuid, String, bool)>(
            "SELECT a.id, n.id, b.status,
                    b.cancellation_requested_at IS NOT NULL
             FROM builds AS b
             JOIN nodes AS n
               ON n.build_id = b.id
              AND n.organization_id = b.organization_id
             JOIN attempts AS a
               ON a.node_id = n.id
              AND a.organization_id = n.organization_id
             WHERE b.organization_id = $1
               AND b.project_id = $2
               AND b.id = $3
               AND b.status IN ('queued', 'running')
             ORDER BY a.ordinal DESC
             LIMIT 1
             FOR UPDATE OF b, n, a",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(build_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((attempt_id, node_id, build_status, already_requested)) = attempt else {
            tx.rollback().await?;
            return Ok(false);
        };
        if already_requested {
            tx.rollback().await?;
            return Ok(false);
        }

        if build_status == "queued" {
            sqlx::query(
                "UPDATE attempts
                 SET status = 'aborted',
                     terminal_summary = $3,
                     completed_at = clock_timestamp()
                 WHERE organization_id = $1
                   AND id = $2
                   AND status = 'queued'",
            )
            .bind(organization_id)
            .bind(attempt_id)
            .bind(json!({"reason": "cancelled_before_execution"}))
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE nodes
                 SET status = 'aborted'
                 WHERE organization_id = $1
                   AND id = $2
                   AND status = 'queued'",
            )
            .bind(organization_id)
            .bind(node_id)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE builds
                 SET status = 'aborted',
                     cancellation_requested_at = clock_timestamp(),
                     completed_at = clock_timestamp()
                 WHERE organization_id = $1
                   AND id = $2
                   AND status = 'queued'",
            )
            .bind(organization_id)
            .bind(build_id)
            .execute(&mut *tx)
            .await?;
        } else {
            sqlx::query(
                "UPDATE builds
                 SET cancellation_requested_at = clock_timestamp()
                 WHERE organization_id = $1 AND id = $2",
            )
            .bind(organization_id)
            .bind(build_id)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE attempts
                 SET status = 'cancelling'
                 WHERE organization_id = $1
                   AND id = $2
                   AND status IN ('offered', 'accepted', 'running', 'finalizing')",
            )
            .bind(organization_id)
            .bind(attempt_id)
            .execute(&mut *tx)
            .await?;
        }
        append_event_and_outbox_as(
            &mut tx,
            organization_id,
            build_id,
            actor_subject,
            "build.cancellation_requested",
            json!({
                "attempt_id": attempt_id,
                "node_id": node_id,
                "terminal": build_status == "queued",
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Reads current-fence committed log chunks in global commit order.
    pub async fn build_logs(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        build_id: Uuid,
    ) -> Result<Vec<CommittedLog>, StoreError> {
        type LogRow = (Uuid, i64, i64, String, Vec<u8>, Vec<u8>);
        let mut tx = self.tenant_transaction(organization_id).await?;
        let rows = sqlx::query_as::<_, LogRow>(
            "SELECT l.attempt_id, l.fence, l.sequence, l.stream, l.content, l.digest
             FROM attempt_log_chunks AS l
             JOIN attempts AS a
               ON a.id = l.attempt_id AND a.organization_id = l.organization_id
             JOIN nodes AS n
               ON n.id = a.node_id AND n.organization_id = a.organization_id
             JOIN builds AS b
               ON b.id = n.build_id AND b.organization_id = n.organization_id
             WHERE l.organization_id = $1
               AND b.project_id = $2
               AND b.id = $3
               AND l.fence = a.fence
             ORDER BY l.cursor_id",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(build_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.into_iter()
            .map(|(attempt_id, fence, sequence, stream, content, digest)| {
                let digest: [u8; 32] =
                    digest
                        .try_into()
                        .map_err(|_| StoreError::CorruptLogDigest {
                            attempt_id,
                            sequence,
                        })?;
                Ok(CommittedLog {
                    attempt_id,
                    fence,
                    sequence,
                    stream,
                    content,
                    digest,
                })
            })
            .collect()
    }

    /// Returns the exact immutable checkout evidence committed by one fenced
    /// attempt in a project build. The stored canonical bytes, rather than a
    /// caller-supplied checkout, are the export authority.
    pub async fn state_transfer_scm_checkout(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        build_id: Uuid,
        attempt_id: Uuid,
        fence: i64,
        evidence_key: &str,
    ) -> Result<Option<mcloving_state_transfer::ScmState>, StoreError> {
        let mut tx = self.tenant_transaction(organization_id).await?;
        let evidence = sqlx::query_as::<_, (Vec<u8>, Vec<u8>)>(
            "SELECT e.canonical_evidence, e.evidence_digest
             FROM state_transfer_scm_evidence AS e
             JOIN attempts AS a
               ON a.organization_id = e.organization_id
              AND a.id = e.attempt_id
              AND a.fence = e.fence
             JOIN nodes AS n
               ON n.organization_id = a.organization_id
              AND n.id = a.node_id
             JOIN builds AS b
               ON b.organization_id = n.organization_id
              AND b.id = n.build_id
             WHERE e.organization_id = $1
               AND e.project_id = $2
               AND b.id = $3
               AND e.attempt_id = $4
               AND e.fence = $5
               AND e.evidence_key = $6",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(build_id)
        .bind(attempt_id)
        .bind(fence)
        .bind(evidence_key)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        evidence
            .map(|(bytes, digest)| {
                let actual_digest: [u8; 32] = Sha256::digest(&bytes).into();
                if actual_digest.as_slice() != digest.as_slice() {
                    return Err(StoreError::InvalidStateTransfer(
                        "stored SCM checkout evidence digest is invalid".to_owned(),
                    ));
                }
                let evidence: Value = serde_json::from_slice(&bytes).map_err(|error| {
                    StoreError::InvalidStateTransfer(format!(
                        "stored SCM checkout evidence is not canonical JSON: {error}"
                    ))
                })?;
                if evidence.get("schema").and_then(Value::as_str)
                    != Some("mcloving.scm-checkout-evidence/v1")
                {
                    return Err(StoreError::InvalidStateTransfer(
                        "stored SCM checkout evidence schema is unsupported".to_owned(),
                    ));
                }
                serde_json::from_value(evidence.get("checkout").cloned().ok_or_else(|| {
                    StoreError::InvalidStateTransfer(
                        "stored SCM checkout evidence has no checkout".to_owned(),
                    )
                })?)
                .map_err(|error| {
                    StoreError::InvalidStateTransfer(format!(
                        "stored SCM checkout is invalid: {error}"
                    ))
                })
            })
            .transpose()
    }

    /// Returns one immutable, stable page of current-fence build logs.
    ///
    /// The cursor is the exact last `(attempt, fence, sequence, stream)` tuple
    /// from a prior page. It resolves independently of the attempt's current
    /// fence, while returned rows remain restricted to current-fence evidence.
    #[allow(clippy::too_many_arguments)]
    pub async fn build_logs_page(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        build_id: Uuid,
        after_attempt_id: Option<Uuid>,
        after_fence: Option<i64>,
        after_sequence: Option<i64>,
        after_stream: Option<&str>,
        limit: u32,
    ) -> Result<Vec<CommittedLog>, StoreError> {
        let cursor_is_complete = after_attempt_id.is_some()
            && after_fence.is_some()
            && after_sequence.is_some()
            && after_stream.is_some();
        if limit == 0
            || limit > 1_001
            || after_fence.is_some_and(|fence| fence < 0)
            || after_sequence.is_some_and(|sequence| sequence < 0)
            || (after_attempt_id.is_some()
                || after_fence.is_some()
                || after_sequence.is_some()
                || after_stream.is_some())
                != cursor_is_complete
        {
            return Err(StoreError::InvalidProductOperation(
                "log page requires a complete non-negative cursor and limit between 1 and 1001"
                    .to_owned(),
            ));
        }
        type LogRow = (Uuid, i64, i64, String, Vec<u8>, Vec<u8>);
        let mut tx = self.tenant_transaction(organization_id).await?;
        let rows = sqlx::query_as::<_, LogRow>(
            "WITH cursor AS (
                 SELECT l.cursor_id
                 FROM attempt_log_chunks AS l
                 JOIN attempts AS a
                   ON a.id = l.attempt_id
                  AND a.organization_id = l.organization_id
                 JOIN nodes AS n
                   ON n.id = a.node_id
                  AND n.organization_id = a.organization_id
                 JOIN builds AS b
                   ON b.id = n.build_id
                  AND b.organization_id = n.organization_id
                 WHERE l.organization_id = $1
                   AND b.project_id = $2
                   AND b.id = $3
                   AND l.attempt_id = $4
                   AND l.fence = $5
                   AND l.sequence = $6
                   AND l.stream = $7
             )
             SELECT l.attempt_id, l.fence, l.sequence, l.stream, l.content, l.digest
             FROM attempt_log_chunks AS l
             JOIN attempts AS a
               ON a.id = l.attempt_id AND a.organization_id = l.organization_id
             JOIN nodes AS n
               ON n.id = a.node_id AND n.organization_id = a.organization_id
             JOIN builds AS b
               ON b.id = n.build_id AND b.organization_id = n.organization_id
             WHERE l.organization_id = $1
               AND b.project_id = $2
               AND b.id = $3
               AND l.fence = a.fence
               AND (
                   $4::uuid IS NULL
                   OR (
                       EXISTS (SELECT 1 FROM cursor)
                       AND l.cursor_id > (SELECT cursor_id FROM cursor)
                   )
               )
             ORDER BY l.cursor_id
             LIMIT $8",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(build_id)
        .bind(after_attempt_id)
        .bind(after_fence)
        .bind(after_sequence)
        .bind(after_stream)
        .bind(i64::from(limit))
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.into_iter()
            .map(|(attempt_id, fence, sequence, stream, content, digest)| {
                let digest: [u8; 32] =
                    digest
                        .try_into()
                        .map_err(|_| StoreError::CorruptLogDigest {
                            attempt_id,
                            sequence,
                        })?;
                Ok(CommittedLog {
                    attempt_id,
                    fence,
                    sequence,
                    stream,
                    content,
                    digest,
                })
            })
            .collect()
    }

    /// Commits a log chunk only for the exact live fenced attempt.
    pub async fn append_log(&self, chunk: &NewLogChunk<'_>) -> Result<bool, StoreError> {
        self.append_log_with_session(chunk, None).await
    }

    pub async fn append_log_in_session(
        &self,
        chunk: &NewLogChunk<'_>,
        session_epoch: u64,
    ) -> Result<bool, StoreError> {
        self.append_log_with_session(chunk, Some(session_epoch))
            .await
    }

    async fn append_log_with_session(
        &self,
        chunk: &NewLogChunk<'_>,
        session_epoch: Option<u64>,
    ) -> Result<bool, StoreError> {
        if !log_sequence_is_bounded(chunk.sequence) {
            return Ok(false);
        }
        let mut tx = self.tenant_transaction(chunk.organization_id).await?;
        acquire_restore_fence_shared(&mut tx).await?;
        if let Some(session_epoch) = session_epoch
            && !Self::lock_agent_session(&mut tx, chunk.agent_id, session_epoch).await?
        {
            tx.rollback().await?;
            return Ok(false);
        }
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!(
                "mcloving.log.{}.{}.{}",
                chunk.organization_id, chunk.attempt_id, chunk.fence
            ))
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "SELECT pg_advisory_xact_lock(
                 hashtextextended(
                     'mcloving.log.build.' || n.organization_id::text || '.' || n.build_id::text,
                     0
                 )
             )
             FROM attempts AS a
             JOIN nodes AS n
               ON n.organization_id = a.organization_id
              AND n.id = a.node_id
             WHERE a.organization_id = $1
               AND a.id = $2",
        )
        .bind(chunk.organization_id)
        .bind(chunk.attempt_id)
        .execute(&mut *tx)
        .await?;
        let redactions = sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT secret_value
             FROM credential_grants
             WHERE organization_id = $1
               AND attempt_id = $2
               AND fence = $3
             ORDER BY id",
        )
        .bind(chunk.organization_id)
        .bind(chunk.attempt_id)
        .bind(chunk.fence)
        .fetch_all(&mut *tx)
        .await?;
        let content = redact_to_fixed_point(chunk.content, &redactions)?;
        let digest: [u8; 32] = Sha256::digest(&content).into();
        let existing = sqlx::query_as::<_, (String, Vec<u8>)>(
            "SELECT l.stream, l.digest
             FROM attempt_log_chunks AS l
             JOIN attempts AS a
               ON a.organization_id = l.organization_id
              AND a.id = l.attempt_id
             CROSS JOIN controller_metadata AS m
             WHERE l.organization_id = $1
               AND l.attempt_id = $2
               AND l.fence = $3
               AND l.sequence = $4
               AND a.restore_epoch = $5
               AND a.lease_owner = $6
               AND m.singleton
               AND a.restore_epoch = m.restore_epoch
             FOR UPDATE OF l",
        )
        .bind(chunk.organization_id)
        .bind(chunk.attempt_id)
        .bind(chunk.fence)
        .bind(chunk.sequence)
        .bind(chunk.restore_epoch)
        .bind(chunk.agent_id)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some((stream, existing_digest)) = existing {
            let identical = stream == chunk.stream && existing_digest == digest;
            if identical {
                tx.commit().await?;
            } else {
                tx.rollback().await?;
            }
            return Ok(identical);
        }
        let committed = sqlx::query_scalar::<_, i64>(
            "SELECT COALESCE(sum(octet_length(content)), 0)::bigint
             FROM attempt_log_chunks
             WHERE organization_id = $1
               AND attempt_id = $2
               AND fence = $3",
        )
        .bind(chunk.organization_id)
        .bind(chunk.attempt_id)
        .bind(chunk.fence)
        .fetch_one(&mut *tx)
        .await?;
        let incoming = i64::try_from(content.len()).unwrap_or(i64::MAX);
        if !log_quota_allows(committed, incoming) {
            tx.rollback().await?;
            return Ok(false);
        }
        let inserted = sqlx::query_scalar::<_, i64>(
            "INSERT INTO attempt_log_chunks (
                 organization_id, attempt_id, fence, sequence,
                 stream, content, digest
             )
             SELECT $1, a.id, $3, $6, $7, $8, $9
             FROM attempts AS a
             WHERE a.organization_id = $1
               AND a.id = $2
               AND a.fence = $3
               AND a.restore_epoch = $4
               AND a.restore_epoch = (
                   SELECT restore_epoch FROM controller_metadata WHERE singleton
               )
               AND a.lease_owner = $5
               AND a.lease_expires_at > clock_timestamp()
               AND a.status IN ('accepted', 'running', 'finalizing', 'cancelling')
             ON CONFLICT (organization_id, attempt_id, fence, sequence)
             DO UPDATE SET content = EXCLUDED.content
             WHERE attempt_log_chunks.stream = EXCLUDED.stream
               AND attempt_log_chunks.digest = EXCLUDED.digest
             RETURNING sequence",
        )
        .bind(chunk.organization_id)
        .bind(chunk.attempt_id)
        .bind(chunk.fence)
        .bind(chunk.restore_epoch)
        .bind(chunk.agent_id)
        .bind(chunk.sequence)
        .bind(chunk.stream)
        .bind(&content)
        .bind(digest.as_slice())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(inserted.is_some())
    }

    /// Loads execution only for the exact current fenced lease owner.
    pub async fn attempt_execution(
        &self,
        organization_id: Uuid,
        attempt_id: Uuid,
        fence: i64,
        restore_epoch: i64,
        agent_id: &str,
    ) -> Result<Option<AttemptExecution>, StoreError> {
        self.attempt_execution_with_session(
            organization_id,
            attempt_id,
            fence,
            restore_epoch,
            agent_id,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn attempt_execution_in_session(
        &self,
        organization_id: Uuid,
        attempt_id: Uuid,
        fence: i64,
        restore_epoch: i64,
        agent_id: &str,
        session_epoch: u64,
    ) -> Result<Option<AttemptExecution>, StoreError> {
        self.attempt_execution_with_session(
            organization_id,
            attempt_id,
            fence,
            restore_epoch,
            agent_id,
            Some(session_epoch),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn attempt_execution_with_session(
        &self,
        organization_id: Uuid,
        attempt_id: Uuid,
        fence: i64,
        restore_epoch: i64,
        agent_id: &str,
        session_epoch: Option<u64>,
    ) -> Result<Option<AttemptExecution>, StoreError> {
        let mut tx = self.tenant_transaction(organization_id).await?;
        acquire_restore_fence_shared(&mut tx).await?;
        if let Some(session_epoch) = session_epoch
            && !Self::lock_agent_session(&mut tx, agent_id, session_epoch).await?
        {
            tx.rollback().await?;
            return Ok(None);
        }
        let row = sqlx::query_as::<_, (Uuid, Uuid, Value, bool)>(
            "SELECT b.id, b.project_id, n.execution_spec,
                    b.cancellation_requested_at IS NOT NULL
             FROM attempts AS a
             JOIN nodes AS n
               ON n.id = a.node_id AND n.organization_id = a.organization_id
             JOIN builds AS b
               ON b.id = n.build_id AND b.organization_id = n.organization_id
             WHERE a.organization_id = $1
               AND a.id = $2
               AND a.fence = $3
               AND a.restore_epoch = $4
               AND a.restore_epoch = (
                   SELECT restore_epoch FROM controller_metadata WHERE singleton
               )
               AND a.lease_owner = $5
               AND a.lease_expires_at > clock_timestamp()
               AND a.status IN ('offered', 'accepted', 'running', 'finalizing', 'cancelling')",
        )
        .bind(organization_id)
        .bind(attempt_id)
        .bind(fence)
        .bind(restore_epoch)
        .bind(agent_id)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some((build_id, _, _, _)) = row.as_ref()
            && let Err(error) =
                lock_enabled_build_pipeline(&mut tx, organization_id, *build_id).await
        {
            tx.rollback().await?;
            return match error {
                StoreError::PipelineDisabled { .. } | StoreError::PipelineStateConflict(_) => {
                    Ok(None)
                }
                other => Err(other),
            };
        }
        tx.commit().await?;
        Ok(row.map(
            |(build_id, project_id, execution_spec, cancellation_requested)| AttemptExecution {
                build_id,
                project_id,
                execution_spec,
                cancellation_requested,
            },
        ))
    }

    /// Idempotently records that an accepted attempt began running.
    pub async fn mark_attempt_running(
        &self,
        organization_id: Uuid,
        attempt_id: Uuid,
        fence: i64,
        restore_epoch: i64,
        agent_id: &str,
    ) -> Result<bool, StoreError> {
        self.mark_attempt_running_with_session(
            organization_id,
            attempt_id,
            fence,
            restore_epoch,
            agent_id,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn mark_attempt_running_in_session(
        &self,
        organization_id: Uuid,
        attempt_id: Uuid,
        fence: i64,
        restore_epoch: i64,
        agent_id: &str,
        session_epoch: u64,
    ) -> Result<bool, StoreError> {
        self.mark_attempt_running_with_session(
            organization_id,
            attempt_id,
            fence,
            restore_epoch,
            agent_id,
            Some(session_epoch),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn mark_attempt_running_with_session(
        &self,
        organization_id: Uuid,
        attempt_id: Uuid,
        fence: i64,
        restore_epoch: i64,
        agent_id: &str,
        session_epoch: Option<u64>,
    ) -> Result<bool, StoreError> {
        let mut tx = self.tenant_transaction(organization_id).await?;
        acquire_restore_fence_shared(&mut tx).await?;
        if let Some(session_epoch) = session_epoch
            && !Self::lock_agent_session(&mut tx, agent_id, session_epoch).await?
        {
            tx.rollback().await?;
            return Ok(false);
        }
        let row = sqlx::query_as::<_, (Uuid, Uuid, String)>(
            "SELECT n.id, n.build_id, a.status
             FROM attempts AS a
             JOIN nodes AS n
               ON n.id = a.node_id AND n.organization_id = a.organization_id
             WHERE a.organization_id = $1
               AND a.id = $2
               AND a.fence = $3
               AND a.restore_epoch = $4
               AND a.restore_epoch = (
                   SELECT restore_epoch FROM controller_metadata WHERE singleton
               )
               AND a.lease_owner = $5
               AND a.lease_expires_at > clock_timestamp()
               AND a.status IN ('accepted', 'running')
             FOR UPDATE OF a, n",
        )
        .bind(organization_id)
        .bind(attempt_id)
        .bind(fence)
        .bind(restore_epoch)
        .bind(agent_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((node_id, build_id, status)) = row else {
            tx.rollback().await?;
            return Ok(false);
        };
        if let Err(error) = lock_enabled_build_pipeline(&mut tx, organization_id, build_id).await {
            tx.rollback().await?;
            return match error {
                StoreError::PipelineDisabled { .. } | StoreError::PipelineStateConflict(_) => {
                    Ok(false)
                }
                other => Err(other),
            };
        }
        if status == "running" {
            tx.commit().await?;
            return Ok(true);
        }
        sqlx::query(
            "UPDATE attempts SET status = 'running'
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(organization_id)
        .bind(attempt_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE nodes SET status = 'running'
             WHERE organization_id = $1 AND id = $2 AND status IN ('offered', 'running')",
        )
        .bind(organization_id)
        .bind(node_id)
        .execute(&mut *tx)
        .await?;
        append_event_and_outbox(
            &mut tx,
            organization_id,
            build_id,
            "attempt.running",
            json!({
                "attempt_id": attempt_id,
                "node_id": node_id,
                "fence": fence,
                "restore_epoch": restore_epoch,
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Publishes a bounded outbox batch exactly once.
    pub async fn publish_outbox(
        &self,
        organization_id: Uuid,
        limit: i64,
    ) -> Result<Vec<PublishedOutbox>, StoreError> {
        if !(1..=1_000).contains(&limit) {
            return Ok(Vec::new());
        }
        let mut tx = self.tenant_transaction(organization_id).await?;
        let rows = sqlx::query_as::<_, (i64, String, Uuid, Value)>(
            "WITH selected AS (
                 SELECT id
                 FROM outbox
                 WHERE organization_id = $1 AND published_at IS NULL
                 ORDER BY id
                 LIMIT $2
                 FOR UPDATE SKIP LOCKED
             )
             UPDATE outbox AS o
             SET published_at = clock_timestamp()
             FROM selected
             WHERE o.id = selected.id
             RETURNING o.id, o.topic, o.aggregate_id, o.payload",
        )
        .bind(organization_id)
        .bind(limit)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows
            .into_iter()
            .map(|(id, topic, aggregate_id, payload)| PublishedOutbox {
                id,
                topic,
                aggregate_id,
                payload,
            })
            .collect())
    }

    /// Records a monotonic effect checkpoint for an exact fenced attempt.
    ///
    /// The payload and idempotency class are immutable. Repeating a checkpoint
    /// is idempotent, while regressions or conflicting payloads are rejected.
    #[allow(clippy::too_many_arguments)]
    pub async fn checkpoint_effect(
        &self,
        organization_id: Uuid,
        attempt_id: Uuid,
        fence: i64,
        restore_epoch: i64,
        agent_id: &str,
        effect_key: &str,
        effect_class: EffectClass,
        status: EffectStatus,
        payload: &Value,
    ) -> Result<bool, StoreError> {
        if effect_key.is_empty() || effect_key.len() > 256 {
            return Ok(false);
        }
        let payload_bytes = serde_json::to_vec(payload)
            .map_err(|error| StoreError::InvalidEffectPayload(error.to_string()))?;
        let payload_digest: [u8; 32] = Sha256::digest(payload_bytes).into();
        let mut tx = self.tenant_transaction(organization_id).await?;
        acquire_restore_fence_shared(&mut tx).await?;
        let attempt_authority = sqlx::query_as::<_, (i64, Uuid)>(
            "SELECT a.restore_epoch, n.build_id
             FROM attempts AS a
             JOIN nodes AS n
               ON n.id = a.node_id AND n.organization_id = a.organization_id
             CROSS JOIN controller_metadata AS m
             WHERE a.organization_id = $1
               AND a.id = $2
               AND a.fence = $3
               AND a.restore_epoch = $4
               AND a.lease_owner = $5
               AND a.lease_expires_at > clock_timestamp()
               AND a.status IN ('accepted', 'running', 'finalizing', 'cancelling')
               AND m.singleton
               AND a.restore_epoch = m.restore_epoch
             FOR UPDATE OF a",
        )
        .bind(organization_id)
        .bind(attempt_id)
        .bind(fence)
        .bind(restore_epoch)
        .bind(agent_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((_, build_id)) = attempt_authority else {
            tx.rollback().await?;
            return Ok(false);
        };
        let existing = sqlx::query_as::<_, (String, String, Vec<u8>)>(
            "SELECT effect_class, status, payload_digest
             FROM attempt_effects
             WHERE organization_id = $1
               AND attempt_id = $2
               AND fence = $3
               AND effect_key = $4
             FOR UPDATE",
        )
        .bind(organization_id)
        .bind(attempt_id)
        .bind(fence)
        .bind(effect_key)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some((existing_class, existing_status, existing_digest)) = existing {
            let valid = existing_class == effect_class.as_str()
                && existing_digest == payload_digest
                && valid_effect_transition(&existing_status, status);
            if !valid {
                tx.rollback().await?;
                return Ok(false);
            }
            if existing_status == status.as_str() {
                tx.commit().await?;
                return Ok(true);
            }
            if let Err(error) =
                lock_enabled_build_pipeline(&mut tx, organization_id, build_id).await
            {
                tx.rollback().await?;
                return match error {
                    StoreError::PipelineDisabled { .. } | StoreError::PipelineStateConflict(_) => {
                        Ok(false)
                    }
                    other => Err(other),
                };
            }
            sqlx::query(
                "UPDATE attempt_effects
                 SET status = $5, updated_at = clock_timestamp()
                 WHERE organization_id = $1
                   AND attempt_id = $2
                   AND fence = $3
                   AND effect_key = $4",
            )
            .bind(organization_id)
            .bind(attempt_id)
            .bind(fence)
            .bind(effect_key)
            .bind(status.as_str())
            .execute(&mut *tx)
            .await?;
        } else {
            if status != EffectStatus::Prepared {
                tx.rollback().await?;
                return Ok(false);
            }
            if let Err(error) =
                lock_enabled_build_pipeline(&mut tx, organization_id, build_id).await
            {
                tx.rollback().await?;
                return match error {
                    StoreError::PipelineDisabled { .. } | StoreError::PipelineStateConflict(_) => {
                        Ok(false)
                    }
                    other => Err(other),
                };
            }
            sqlx::query(
                "INSERT INTO attempt_effects (
                     organization_id, attempt_id, fence, effect_key,
                     effect_class, status, payload, payload_digest
                 )
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(organization_id)
            .bind(attempt_id)
            .bind(fence)
            .bind(effect_key)
            .bind(effect_class.as_str())
            .bind(status.as_str())
            .bind(payload)
            .bind(payload_digest.as_slice())
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(true)
    }

    /// Confirms one fenced uncertain effect without restoring execution authority.
    ///
    /// Restore activation and lease expiry leave the attempt fenced and move
    /// unresolved effect checkpoints to `uncertain`. Reconciliation may only
    /// confirm an existing, payload-identical uncertain row after executable
    /// lease authority has been cleared. `lease_owner` may remain as durable
    /// attribution for agent reconciliation; the null expiry and
    /// `reconciliation_required` status prevent lease renewal or execution.
    /// Same-epoch lease expiry is restricted to the attempt's current fence;
    /// restore reconciliation may also confirm an historical fence that was
    /// made uncertain by the restore sweep.
    #[allow(clippy::too_many_arguments)]
    pub async fn confirm_uncertain_effect(
        &self,
        organization_id: Uuid,
        attempt_id: Uuid,
        fence: i64,
        effect_key: &str,
        effect_class: EffectClass,
        payload: &Value,
    ) -> Result<bool, StoreError> {
        if effect_key.is_empty() || effect_key.len() > 256 {
            return Ok(false);
        }
        let payload_bytes = serde_json::to_vec(payload)
            .map_err(|error| StoreError::InvalidEffectPayload(error.to_string()))?;
        let payload_digest: [u8; 32] = Sha256::digest(payload_bytes).into();
        let mut tx = self.tenant_transaction(organization_id).await?;
        acquire_restore_fence_shared(&mut tx).await?;
        let reconciled = sqlx::query_scalar::<_, Uuid>(
            "UPDATE attempt_effects AS e
             SET status = 'confirmed',
                 updated_at = CASE
                     WHEN e.status = 'uncertain' THEN clock_timestamp()
                     ELSE e.updated_at
                 END
             FROM attempts AS a, controller_metadata AS m
             WHERE e.organization_id = $1
               AND e.attempt_id = $2
               AND e.fence = $3
               AND e.effect_key = $4
               AND e.effect_class = $5
               AND e.payload_digest = $6
               AND e.status IN ('uncertain', 'confirmed')
               AND a.organization_id = e.organization_id
               AND a.id = e.attempt_id
               AND a.status = 'reconciliation_required'
               AND a.lease_expires_at IS NULL
               AND m.singleton
               AND a.restore_epoch <= m.restore_epoch
               AND (
                   (a.restore_epoch = m.restore_epoch AND e.fence = a.fence)
                   OR (
                       a.restore_epoch < m.restore_epoch
                       AND e.fence <= a.fence
                   )
               )
             RETURNING e.attempt_id",
        )
        .bind(organization_id)
        .bind(attempt_id)
        .bind(fence)
        .bind(effect_key)
        .bind(effect_class.as_str())
        .bind(payload_digest.as_slice())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(reconciled.is_some())
    }

    /// Terminates one fully resolved reconciliation without granting a lease.
    ///
    /// An explicit operator decision may close the attempt only after every
    /// uncertain effect across every historical fence has been confirmed. The
    /// attempt, node, build, event, and outbox update share the retry decision
    /// lock.
    #[allow(clippy::too_many_arguments)]
    pub async fn finalize_reconciled_attempt(
        &self,
        organization_id: Uuid,
        attempt_id: Uuid,
        fence: i64,
        actor: &str,
        outcome: TerminalOutcome,
        summary: Value,
    ) -> Result<bool, StoreError> {
        if actor.is_empty() || actor.len() > 256 {
            return Ok(false);
        }
        let mut tx = self.tenant_transaction(organization_id).await?;
        acquire_restore_fence_shared(&mut tx).await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!("mcloving.retry.{attempt_id}"))
            .execute(&mut *tx)
            .await?;
        let exact_replay = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (
                 SELECT 1
                 FROM build_events
                 WHERE organization_id = $1
                   AND kind = 'attempt.reconciliation_terminal'
                   AND payload ->> 'attempt_id' = $2::text
                   AND (payload ->> 'fence')::bigint = $3
                   AND payload ->> 'actor' = $4
                   AND payload ->> 'outcome' = $5
                   AND payload -> 'summary' = $6::jsonb
             )",
        )
        .bind(organization_id)
        .bind(attempt_id)
        .bind(fence)
        .bind(actor)
        .bind(outcome.as_str())
        .bind(&summary)
        .fetch_one(&mut *tx)
        .await?;
        if exact_replay {
            tx.commit().await?;
            return Ok(true);
        }
        let reconciled = sqlx::query_as::<_, (Uuid, Uuid, i64)>(
            "UPDATE attempts AS a
             SET status = $4,
                 terminal_summary = $5,
                 completed_at = clock_timestamp()
             FROM nodes AS n
             WHERE a.organization_id = $1
               AND a.id = $2
               AND a.fence = $3
               AND a.status = 'reconciliation_required'
               AND a.lease_expires_at IS NULL
               AND NOT EXISTS (
                   SELECT 1
                   FROM attempts AS child
                   WHERE child.organization_id = a.organization_id
                     AND child.retry_of = a.id
               )
               AND NOT EXISTS (
                   SELECT 1
                   FROM dead_letters AS dead
                   WHERE dead.organization_id = a.organization_id
                     AND dead.attempt_id = a.id
               )
               AND n.organization_id = a.organization_id
               AND n.id = a.node_id
               AND NOT EXISTS (
                   SELECT 1
                   FROM attempt_effects AS e
                   WHERE e.organization_id = a.organization_id
                     AND e.attempt_id = a.id
                     AND e.status = 'uncertain'
               )
             RETURNING n.id, n.build_id, a.restore_epoch",
        )
        .bind(organization_id)
        .bind(attempt_id)
        .bind(fence)
        .bind(outcome.as_str())
        .bind(&summary)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((node_id, build_id, restore_epoch)) = reconciled else {
            tx.rollback().await?;
            return Ok(false);
        };
        if !dag::advance_dag_after_attempt(
            &mut tx,
            organization_id,
            build_id,
            node_id,
            attempt_id,
            outcome,
        )
        .await?
        {
            sqlx::query(
                "UPDATE nodes
                 SET status = $3
                 WHERE organization_id = $1 AND id = $2",
            )
            .bind(organization_id)
            .bind(node_id)
            .bind(outcome.as_str())
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE builds
                 SET status = $3, completed_at = clock_timestamp()
                 WHERE organization_id = $1 AND id = $2",
            )
            .bind(organization_id)
            .bind(build_id)
            .bind(outcome.as_str())
            .execute(&mut *tx)
            .await?;
        }
        append_event_and_outbox(
            &mut tx,
            organization_id,
            build_id,
            "attempt.reconciliation_terminal",
            json!({
                "attempt_id": attempt_id,
                "fence": fence,
                "restore_epoch": restore_epoch,
                "actor": actor,
                "outcome": outcome.as_str(),
                "summary": summary,
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Returns every effect that requires explicit operator reconciliation.
    pub async fn uncertain_effects(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<EffectCheckpoint>, StoreError> {
        let mut tx = self.tenant_transaction(organization_id).await?;
        type EffectRow = (Uuid, i64, String, String, String, Value, Vec<u8>);
        let rows = sqlx::query_as::<_, EffectRow>(
            "SELECT attempt_id, fence, effect_key, effect_class, status,
                    payload, payload_digest
             FROM attempt_effects
             WHERE organization_id = $1 AND status = 'uncertain'
             ORDER BY updated_at, attempt_id, effect_key",
        )
        .bind(organization_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.into_iter()
            .map(
                |(attempt_id, fence, effect_key, effect_class, status, payload, digest)| {
                    Ok(EffectCheckpoint {
                        attempt_id,
                        fence,
                        effect_key,
                        effect_class: parse_effect_class(&effect_class)?,
                        status: parse_effect_status(&status)?,
                        payload,
                        payload_digest: digest.try_into().map_err(|_| {
                            StoreError::InvalidEffectPayload(
                                "stored effect digest is not 32 bytes".to_owned(),
                            )
                        })?,
                    })
                },
            )
            .collect()
    }

    /// Creates one new immutable attempt or dead-letters an exhausted node.
    ///
    /// Only failed or reconciliation-required attempts are eligible. Repeating
    /// the same decision returns the existing child attempt.
    pub async fn schedule_retry(
        &self,
        organization_id: Uuid,
        attempt_id: Uuid,
        max_attempts: i32,
        reason: &str,
    ) -> Result<RetryDecision, StoreError> {
        self.schedule_retry_as(
            organization_id,
            attempt_id,
            max_attempts,
            reason,
            "system:controller",
        )
        .await
    }

    pub async fn schedule_retry_as(
        &self,
        organization_id: Uuid,
        attempt_id: Uuid,
        max_attempts: i32,
        reason: &str,
        actor_subject: &str,
    ) -> Result<RetryDecision, StoreError> {
        if !(1..=16).contains(&max_attempts) || reason.is_empty() || reason.len() > 1024 {
            return Ok(RetryDecision::Ineligible);
        }
        validate_audit_actor(actor_subject)?;
        let mut tx = self.tenant_transaction(organization_id).await?;
        acquire_restore_fence_shared(&mut tx).await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!("mcloving.retry.{attempt_id}"))
            .execute(&mut *tx)
            .await?;
        let current = sqlx::query_as::<_, (Uuid, Uuid, i32, String, bool, bool, bool)>(
            "SELECT n.id, n.build_id, a.ordinal, a.status,
                    b.cancellation_requested_at IS NOT NULL,
                    b.dag_mode,
                    EXISTS (
                        SELECT 1
                        FROM build_events AS e
                        WHERE e.organization_id = a.organization_id
                          AND e.build_id = b.id
                          AND e.kind = 'attempt.reconciliation_terminal'
                          AND e.payload ->> 'attempt_id' = a.id::text
                    )
             FROM attempts AS a
             JOIN nodes AS n
               ON n.id = a.node_id AND n.organization_id = a.organization_id
             JOIN builds AS b
               ON b.id = n.build_id AND b.organization_id = n.organization_id
             WHERE a.organization_id = $1 AND a.id = $2
             FOR UPDATE OF a, n, b",
        )
        .bind(organization_id)
        .bind(attempt_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((
            node_id,
            build_id,
            ordinal,
            status,
            cancelled,
            dag_mode,
            reconciliation_terminalized,
        )) = current
        else {
            tx.rollback().await?;
            return Ok(RetryDecision::Ineligible);
        };
        if cancelled
            || reconciliation_terminalized
            || !matches!(status.as_str(), "failed" | "reconciliation_required")
        {
            tx.rollback().await?;
            return Ok(RetryDecision::Ineligible);
        }
        if let Some((child_id, child_ordinal)) = sqlx::query_as::<_, (Uuid, i32)>(
            "SELECT id, ordinal
             FROM attempts
             WHERE organization_id = $1 AND retry_of = $2",
        )
        .bind(organization_id)
        .bind(attempt_id)
        .fetch_optional(&mut *tx)
        .await?
        {
            tx.commit().await?;
            return Ok(RetryDecision::Scheduled {
                attempt_id: child_id,
                ordinal: child_ordinal,
                created: false,
            });
        }
        if let Err(error) = lock_enabled_build_pipeline(&mut tx, organization_id, build_id).await {
            tx.rollback().await?;
            return match error {
                StoreError::PipelineDisabled { .. } | StoreError::PipelineStateConflict(_) => {
                    Ok(RetryDecision::Ineligible)
                }
                other => Err(other),
            };
        }
        let has_non_idempotent_effect = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (
                 SELECT 1
                 FROM attempt_effects
                 WHERE organization_id = $1
                   AND attempt_id = $2
                   AND effect_class = 'non_idempotent'
             )",
        )
        .bind(organization_id)
        .bind(attempt_id)
        .fetch_one(&mut *tx)
        .await?;
        if has_non_idempotent_effect {
            tx.rollback().await?;
            return Ok(RetryDecision::Ineligible);
        }
        let has_dead_letter = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (
                 SELECT 1
                 FROM dead_letters
                 WHERE organization_id = $1 AND attempt_id = $2
             )",
        )
        .bind(organization_id)
        .bind(attempt_id)
        .fetch_one(&mut *tx)
        .await?;
        if has_dead_letter {
            terminalize_dead_lettered_reconciliation(
                &mut tx,
                organization_id,
                attempt_id,
                node_id,
                build_id,
                reason,
            )
            .await?;
            tx.commit().await?;
            return Ok(RetryDecision::DeadLettered);
        }
        if ordinal >= max_attempts {
            let payload = json!({
                "attempt_id": attempt_id,
                "ordinal": ordinal,
                "max_attempts": max_attempts,
                "reason": reason,
            });
            let digest: [u8; 32] = Sha256::digest(
                serde_json::to_vec(&payload)
                    .map_err(|error| StoreError::InvalidEffectPayload(error.to_string()))?,
            )
            .into();
            let inserted = sqlx::query(
                "INSERT INTO dead_letters (
                     organization_id, attempt_id, reason, payload, payload_digest
                 )
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (organization_id, attempt_id) DO NOTHING",
            )
            .bind(organization_id)
            .bind(attempt_id)
            .bind(reason)
            .bind(&payload)
            .bind(digest.as_slice())
            .execute(&mut *tx)
            .await?;
            if inserted.rows_affected() == 1 {
                append_event_and_outbox_as(
                    &mut tx,
                    organization_id,
                    build_id,
                    actor_subject,
                    "attempt.dead_lettered",
                    payload,
                )
                .await?;
            }
            terminalize_dead_lettered_reconciliation(
                &mut tx,
                organization_id,
                attempt_id,
                node_id,
                build_id,
                reason,
            )
            .await?;
            tx.commit().await?;
            return Ok(RetryDecision::DeadLettered);
        }
        let child_id = Uuid::new_v4();
        let child_ordinal = ordinal + 1;
        if dag_mode {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind(format!("mcloving.dag.retry.{build_id}"))
                .execute(&mut *tx)
                .await?;
            sqlx::query(
                "WITH timing AS (
                     SELECT clock_timestamp() AS admitted_at
                 ), eligibility AS (
                     SELECT NOT EXISTS (
                         SELECT 1
                         FROM node_dependencies AS dependency
                         JOIN nodes AS parent
                           ON parent.id = dependency.parent_node_id
                          AND parent.organization_id = dependency.organization_id
                         WHERE dependency.organization_id = $2
                           AND dependency.child_node_id = $3
                           AND (
                               (
                                   dependency.condition = 'succeeded'
                                   AND parent.status <> 'succeeded'
                               )
                               OR (
                                   dependency.condition = 'completed'
                                   AND parent.status NOT IN (
                                       'succeeded', 'failed', 'aborted', 'skipped'
                                   )
                               )
                           )
                     ) AS ready
                 ), inserted AS (
                     INSERT INTO attempts (
                         id, organization_id, node_id, ordinal, status, retry_of,
                         restore_epoch, created_at, ready_at
                     )
                     SELECT $1, $2, $3, $4, 'queued', $5, restore_epoch,
                            admitted_at,
                            CASE WHEN eligibility.ready THEN admitted_at ELSE NULL END
                     FROM controller_metadata, timing, eligibility
                     WHERE singleton
                     RETURNING ready_at
                 )
                 UPDATE nodes AS node
                 SET status = CASE
                         WHEN inserted.ready_at IS NULL THEN 'blocked'
                         ELSE 'queued'
                     END,
                     logical_outcome = NULL,
                     cancellation_requested_at = NULL,
                     max_attempts = GREATEST(node.max_attempts, $6),
                     queued_at = COALESCE(inserted.ready_at, node.queued_at)
                 FROM inserted
                 WHERE node.organization_id = $2
                   AND node.id = $3",
            )
            .bind(child_id)
            .bind(organization_id)
            .bind(node_id)
            .bind(child_ordinal)
            .bind(attempt_id)
            .bind(max_attempts)
            .execute(&mut *tx)
            .await?;
            let skipped_nodes = sqlx::query_as::<_, (Uuid, Uuid, i32)>(
                "WITH RECURSIVE descendants(id) AS (
                     SELECT child_node_id
                     FROM node_dependencies
                     WHERE organization_id = $1
                       AND parent_node_id = $2
                     UNION
                     SELECT dependency.child_node_id
                     FROM node_dependencies AS dependency
                     JOIN descendants
                       ON descendants.id = dependency.parent_node_id
                     WHERE dependency.organization_id = $1
                 )
                 SELECT n.id, latest.id, latest.ordinal
                 FROM nodes AS n
                 JOIN LATERAL (
                     SELECT a.id, a.ordinal, a.status, a.terminal_summary
                     FROM attempts AS a
                     WHERE a.organization_id = n.organization_id
                       AND a.node_id = n.id
                     ORDER BY a.ordinal DESC
                     LIMIT 1
                 ) AS latest ON true
                 WHERE n.organization_id = $1
                   AND n.build_id = $3
                   AND n.status = 'skipped'
                   AND n.logical_outcome = 'skipped'
                   AND (
                       n.id IN (SELECT id FROM descendants)
                       OR (
                           latest.status = 'aborted'
                           AND latest.terminal_summary ->> 'reason' = 'fail_fast_skipped'
                       )
                   )
                 ORDER BY n.id
                 FOR UPDATE OF n",
            )
            .bind(organization_id)
            .bind(node_id)
            .bind(build_id)
            .fetch_all(&mut *tx)
            .await?;
            for (skipped_node_id, previous_attempt_id, previous_ordinal) in &skipped_nodes {
                sqlx::query(
                    "WITH timing AS (SELECT clock_timestamp() AS admitted_at)
                     INSERT INTO attempts (
                         id, organization_id, node_id, ordinal, status, retry_of,
                         restore_epoch, created_at, ready_at
                     )
                     SELECT $1, $2, $3, $4, 'queued', $5, restore_epoch,
                            admitted_at,
                            CASE WHEN EXISTS (
                                SELECT 1
                                FROM node_dependencies AS dependency
                                WHERE dependency.organization_id = $2
                                  AND dependency.child_node_id = $3
                            ) THEN NULL ELSE admitted_at END
                     FROM controller_metadata, timing
                     WHERE singleton",
                )
                .bind(Uuid::new_v4())
                .bind(organization_id)
                .bind(skipped_node_id)
                .bind(previous_ordinal + 1)
                .bind(previous_attempt_id)
                .execute(&mut *tx)
                .await?;
                sqlx::query(
                    "UPDATE nodes AS n
                     SET status = CASE
                         WHEN EXISTS (
                             SELECT 1
                             FROM node_dependencies AS dependency
                             WHERE dependency.organization_id = n.organization_id
                               AND dependency.child_node_id = n.id
                         )
                         THEN 'blocked'
                         ELSE 'queued'
                     END,
                         logical_outcome = NULL,
                         cancellation_requested_at = NULL,
                         queued_at = clock_timestamp()
                     WHERE n.organization_id = $1
                       AND n.id = $2
                       AND n.status = 'skipped'
                       AND n.logical_outcome = 'skipped'",
                )
                .bind(organization_id)
                .bind(skipped_node_id)
                .execute(&mut *tx)
                .await?;
            }
        } else {
            sqlx::query(
                "WITH timing AS (SELECT clock_timestamp() AS admitted_at)
                 INSERT INTO attempts (
                     id, organization_id, node_id, ordinal, status, retry_of,
                     restore_epoch, created_at, ready_at
                 )
                 SELECT $1, $2, $3, $4, 'queued', $5, restore_epoch,
                        admitted_at, admitted_at
                 FROM controller_metadata, timing
                 WHERE singleton",
            )
            .bind(child_id)
            .bind(organization_id)
            .bind(node_id)
            .bind(child_ordinal)
            .bind(attempt_id)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE nodes
                 SET status = 'queued', queued_at = clock_timestamp()
                 WHERE organization_id = $1 AND id = $2",
            )
            .bind(organization_id)
            .bind(node_id)
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query(
            "UPDATE builds
             SET status = 'queued',
                 completed_at = NULL,
                 cancellation_requested_at = NULL
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(organization_id)
        .bind(build_id)
        .execute(&mut *tx)
        .await?;
        append_event_and_outbox_as(
            &mut tx,
            organization_id,
            build_id,
            actor_subject,
            "attempt.retry_scheduled",
            json!({
                "attempt_id": child_id,
                "retry_of": attempt_id,
                "ordinal": child_ordinal,
                "reason": reason,
                "dag": dag_mode,
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(RetryDecision::Scheduled {
            attempt_id: child_id,
            ordinal: child_ordinal,
            created: true,
        })
    }

    /// Registers one immutable object only for the exact live fenced owner.
    #[allow(clippy::too_many_arguments)]
    pub async fn register_object(
        &self,
        organization_id: Uuid,
        attempt_id: Uuid,
        fence: i64,
        restore_epoch: i64,
        agent_id: &str,
        kind: ObjectKind,
        name: &str,
        digest: [u8; 32],
        bytes: i64,
    ) -> Result<bool, StoreError> {
        if name.is_empty() || name.len() > 512 || bytes < 0 {
            return Ok(false);
        }
        let mut tx = self.tenant_transaction(organization_id).await?;
        acquire_restore_fence_shared(&mut tx).await?;
        acquire_object_deletion_fence(&mut tx, &digest).await?;
        let inserted = match sqlx::query_scalar::<_, String>(
            "INSERT INTO attempt_objects (
                 organization_id, attempt_id, fence, kind, name,
                 object_digest, bytes
             )
             SELECT $1, a.id, $3, $6, $7, $8, $9
             FROM attempts AS a
             WHERE a.organization_id = $1
               AND a.id = $2
               AND a.fence = $3
               AND a.restore_epoch = $4
               AND a.restore_epoch = (
                   SELECT restore_epoch FROM controller_metadata WHERE singleton
               )
               AND a.lease_owner = $5
               AND a.lease_expires_at > clock_timestamp()
               AND a.status IN ('accepted', 'running', 'finalizing', 'cancelling')
             ON CONFLICT (organization_id, attempt_id, fence, kind, name)
             DO UPDATE SET checked_at = clock_timestamp()
             WHERE attempt_objects.object_digest = EXCLUDED.object_digest
               AND attempt_objects.bytes = EXCLUDED.bytes
             RETURNING name",
        )
        .bind(organization_id)
        .bind(attempt_id)
        .bind(fence)
        .bind(restore_epoch)
        .bind(agent_id)
        .bind(kind.as_str())
        .bind(name)
        .bind(digest.as_slice())
        .bind(bytes)
        .fetch_optional(&mut *tx)
        .await
        {
            Ok(inserted) => inserted,
            Err(error) if is_object_deletion_fence_violation(&error) => {
                tx.rollback().await?;
                return Ok(false);
            }
            Err(error) => return Err(error.into()),
        };
        tx.commit().await?;
        Ok(inserted.is_some())
    }

    /// Reserves one immutable artifact identity before object publication.
    #[allow(clippy::too_many_arguments)]
    pub async fn register_artifact(
        &self,
        organization_id: Uuid,
        build_id: Uuid,
        node_id: Uuid,
        attempt_id: Uuid,
        fence: i64,
        restore_epoch: i64,
        agent_id: &str,
        name: &str,
        digest: [u8; 32],
        bytes: i64,
        media_type: &str,
        retention_seconds: i64,
    ) -> Result<bool, StoreError> {
        if name.is_empty()
            || name.len() > 512
            || name.chars().any(char::is_control)
            || bytes < 0
            || media_type.is_empty()
            || media_type.len() > 255
            || media_type.trim() != media_type
            || media_type.chars().any(char::is_control)
            || !(0..=MAX_OBJECT_RETENTION_SECONDS).contains(&retention_seconds)
        {
            return Ok(false);
        }
        let mut tx = self.tenant_transaction(organization_id).await?;
        acquire_restore_fence_shared(&mut tx).await?;
        acquire_object_deletion_fence(&mut tx, &digest).await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!(
                "mcloving.artifact.{organization_id}.{attempt_id}.{fence}.{name}"
            ))
            .execute(&mut *tx)
            .await?;
        let existing = sqlx::query_scalar::<_, String>(
            "SELECT o.name
             FROM attempt_objects AS o
             JOIN attempts AS a
               ON a.organization_id = o.organization_id
              AND a.id = o.attempt_id
             JOIN nodes AS n
               ON n.organization_id = a.organization_id
              AND n.id = a.node_id
             WHERE o.organization_id = $1
               AND n.build_id = $2
               AND n.id = $3
               AND o.attempt_id = $4
               AND o.fence = $5
               AND a.restore_epoch = $6
               AND a.restore_epoch = (
                   SELECT restore_epoch FROM controller_metadata WHERE singleton
               )
               AND a.lease_owner = $7
               AND o.kind = 'artifact'
               AND o.name = $8
               AND o.object_digest = $9
               AND o.bytes = $10
               AND o.media_type = $11
               AND o.status IN ('pending', 'available')",
        )
        .bind(organization_id)
        .bind(build_id)
        .bind(node_id)
        .bind(attempt_id)
        .bind(fence)
        .bind(restore_epoch)
        .bind(agent_id)
        .bind(name)
        .bind(digest.as_slice())
        .bind(bytes)
        .bind(media_type)
        .fetch_optional(&mut *tx)
        .await?;
        if existing.is_some() {
            sqlx::query(
                "INSERT INTO object_retention (
                     organization_id, object_digest, retain_until
                 )
                 VALUES (
                     $1, $2,
                     clock_timestamp() + ($3::double precision * interval '1 second')
                 )
                 ON CONFLICT (organization_id, object_digest) DO UPDATE
                 SET retain_until = GREATEST(
                         object_retention.retain_until,
                         EXCLUDED.retain_until
                     ),
                     updated_at = clock_timestamp()",
            )
            .bind(organization_id)
            .bind(digest.as_slice())
            .bind(retention_seconds as f64)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Ok(true);
        }
        let inserted = match sqlx::query_scalar::<_, String>(
            "INSERT INTO attempt_objects (
                 organization_id, attempt_id, fence, kind, name,
                 object_digest, bytes, media_type, status
             )
             SELECT $1, a.id, $5, 'artifact', $8, $9, $10, $11, 'pending'
             FROM attempts AS a
             JOIN nodes AS n
               ON n.organization_id = a.organization_id
              AND n.id = a.node_id
             JOIN builds AS b
               ON b.organization_id = n.organization_id
              AND b.id = n.build_id
             WHERE a.organization_id = $1
               AND b.id = $2
               AND n.id = $3
               AND a.id = $4
               AND a.fence = $5
               AND a.restore_epoch = $6
               AND a.restore_epoch = (
                   SELECT restore_epoch FROM controller_metadata WHERE singleton
               )
               AND a.lease_owner = $7
               AND a.lease_expires_at > clock_timestamp()
               AND a.status IN ('accepted', 'running', 'finalizing', 'cancelling')
             ON CONFLICT (organization_id, attempt_id, fence, kind, name)
             DO UPDATE SET checked_at = clock_timestamp()
             WHERE attempt_objects.object_digest = EXCLUDED.object_digest
               AND attempt_objects.bytes = EXCLUDED.bytes
               AND attempt_objects.media_type = EXCLUDED.media_type
               AND attempt_objects.status IN ('pending', 'available')
             RETURNING name",
        )
        .bind(organization_id)
        .bind(build_id)
        .bind(node_id)
        .bind(attempt_id)
        .bind(fence)
        .bind(restore_epoch)
        .bind(agent_id)
        .bind(name)
        .bind(digest.as_slice())
        .bind(bytes)
        .bind(media_type)
        .fetch_optional(&mut *tx)
        .await
        {
            Ok(inserted) => inserted,
            Err(error) if is_object_deletion_fence_violation(&error) => {
                tx.rollback().await?;
                return Ok(false);
            }
            Err(error) => return Err(error.into()),
        };
        if inserted.is_none() {
            tx.rollback().await?;
            return Ok(false);
        }
        sqlx::query(
            "INSERT INTO object_retention (
                 organization_id, object_digest, retain_until
             )
             VALUES (
                 $1, $2,
                 clock_timestamp() + ($3::double precision * interval '1 second')
             )
             ON CONFLICT (organization_id, object_digest) DO UPDATE
             SET retain_until = GREATEST(
                     object_retention.retain_until,
                     EXCLUDED.retain_until
                 ),
                 updated_at = clock_timestamp()",
        )
        .bind(organization_id)
        .bind(digest.as_slice())
        .bind(retention_seconds as f64)
        .execute(&mut *tx)
        .await?;
        append_event_and_outbox(
            &mut tx,
            organization_id,
            build_id,
            "artifact.reserved",
            json!({
                "node_id": node_id,
                "attempt_id": attempt_id,
                "fence": fence,
                "name": name,
                "sha256": hex_digest(&digest),
                "bytes": bytes,
                "media_type": media_type,
                "retention_seconds": retention_seconds,
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Reports whether an old filesystem publication claim still belongs to a
    /// recoverable, current-restore artifact reservation.
    pub async fn artifact_publication_claim_active(
        &self,
        organization_id: Uuid,
        digest: [u8; 32],
        bytes: i64,
    ) -> Result<bool, StoreError> {
        if bytes < 0 {
            return Ok(false);
        }
        let mut tx = self.tenant_transaction(organization_id).await?;
        let active = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (
                 SELECT 1
                 FROM attempt_objects AS o
                 JOIN attempts AS a
                   ON a.organization_id = o.organization_id
                  AND a.id = o.attempt_id
                 WHERE o.organization_id = $1
                   AND o.kind = 'artifact'
                   AND o.object_digest = $2
                   AND o.bytes = $3
                   AND o.status = 'pending'
                   AND a.restore_epoch = (
                       SELECT restore_epoch FROM controller_metadata WHERE singleton
                   )
                   AND a.status IN ('accepted', 'running', 'finalizing', 'cancelling')
                   AND a.lease_owner IS NOT NULL
             )",
        )
        .bind(organization_id)
        .bind(digest.as_slice())
        .bind(bytes)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(active)
    }

    /// Marks an exact reserved artifact available only after bytes are published.
    #[allow(clippy::too_many_arguments)]
    pub async fn mark_artifact_available(
        &self,
        organization_id: Uuid,
        build_id: Uuid,
        node_id: Uuid,
        attempt_id: Uuid,
        fence: i64,
        name: &str,
        digest: [u8; 32],
        bytes: i64,
        media_type: &str,
        retention_seconds: i64,
    ) -> Result<bool, StoreError> {
        if !(0..=MAX_OBJECT_RETENTION_SECONDS).contains(&retention_seconds) {
            return Ok(false);
        }
        let mut tx = self.tenant_transaction(organization_id).await?;
        acquire_object_deletion_fence(&mut tx, &digest).await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!(
                "mcloving.artifact.{organization_id}.{attempt_id}.{fence}.{name}"
            ))
            .execute(&mut *tx)
            .await?;
        let status = sqlx::query_scalar::<_, String>(
            "SELECT o.status
             FROM attempt_objects AS o
             JOIN attempts AS a
               ON a.organization_id = o.organization_id
              AND a.id = o.attempt_id
             JOIN nodes AS n
               ON n.organization_id = a.organization_id
              AND n.id = a.node_id
             WHERE o.organization_id = $1
               AND n.build_id = $2
               AND n.id = $3
               AND o.attempt_id = $4
               AND o.fence = $5
               AND o.kind = 'artifact'
               AND o.name = $6
               AND o.object_digest = $7
               AND o.bytes = $8
               AND o.media_type = $9
               AND mcloving_owned_object_publication_allowed(
                     o.organization_id,
                     o.attempt_id,
                     o.fence,
                     o.kind,
                     o.name,
                     o.object_digest
                   )
             FOR UPDATE OF o",
        )
        .bind(organization_id)
        .bind(build_id)
        .bind(node_id)
        .bind(attempt_id)
        .bind(fence)
        .bind(name)
        .bind(digest.as_slice())
        .bind(bytes)
        .bind(media_type)
        .fetch_optional(&mut *tx)
        .await?;
        match status.as_deref() {
            Some("available") => {
                tx.commit().await?;
                return Ok(true);
            }
            Some("pending") => {}
            _ => {
                tx.rollback().await?;
                return Ok(false);
            }
        }
        sqlx::query(
            "UPDATE attempt_objects
             SET status = 'available', checked_at = clock_timestamp()
             WHERE organization_id = $1
               AND attempt_id = $2
               AND fence = $3
               AND kind = 'artifact'
               AND name = $4
               AND object_digest = $5
               AND status = 'pending'",
        )
        .bind(organization_id)
        .bind(attempt_id)
        .bind(fence)
        .bind(name)
        .bind(digest.as_slice())
        .execute(&mut *tx)
        .await?;
        append_event_and_outbox(
            &mut tx,
            organization_id,
            build_id,
            "artifact.committed",
            json!({
                "node_id": node_id,
                "attempt_id": attempt_id,
                "fence": fence,
                "name": name,
                "sha256": hex_digest(&digest),
                "bytes": bytes,
                "media_type": media_type,
                "retention_seconds": retention_seconds,
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Lists product-facing artifact metadata in stable execution/name order.
    pub async fn build_artifacts(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        build_id: Uuid,
    ) -> Result<Vec<ArtifactMetadata>, StoreError> {
        type ArtifactRow = (Uuid, Uuid, Uuid, i64, String, Vec<u8>, i64, String, String);
        let mut tx = self.tenant_transaction(organization_id).await?;
        let rows = sqlx::query_as::<_, ArtifactRow>(
            "SELECT b.id, n.id, a.id, o.fence, o.name, o.object_digest,
                    o.bytes, o.media_type, o.status
             FROM attempt_objects AS o
             JOIN attempts AS a
               ON a.organization_id = o.organization_id
              AND a.id = o.attempt_id
             JOIN nodes AS n
               ON n.organization_id = a.organization_id
              AND n.id = a.node_id
             JOIN builds AS b
               ON b.organization_id = n.organization_id
              AND b.id = n.build_id
             WHERE o.organization_id = $1
               AND b.project_id = $2
               AND b.id = $3
               AND o.kind = 'artifact'
             ORDER BY n.node_key, a.ordinal, o.name",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(build_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.into_iter()
            .map(
                |(
                    build_id,
                    node_id,
                    attempt_id,
                    fence,
                    name,
                    digest,
                    bytes,
                    media_type,
                    status,
                )| {
                    Ok(ArtifactMetadata {
                        build_id,
                        node_id,
                        attempt_id,
                        fence,
                        name,
                        digest: digest.try_into().map_err(|_| {
                            StoreError::InvalidObjectRecord(
                                "artifact digest is not 32 bytes".to_owned(),
                            )
                        })?,
                        bytes,
                        media_type,
                        status: parse_object_status(&status)?,
                    })
                },
            )
            .collect()
    }

    /// Records a verified availability result without changing object identity.
    #[allow(clippy::too_many_arguments)]
    pub async fn set_object_status(
        &self,
        organization_id: Uuid,
        attempt_id: Uuid,
        fence: i64,
        kind: ObjectKind,
        name: &str,
        digest: [u8; 32],
        status: ObjectStatus,
    ) -> Result<bool, StoreError> {
        let mut tx = self.tenant_transaction(organization_id).await?;
        if status == ObjectStatus::Available {
            acquire_object_deletion_fence(&mut tx, &digest).await?;
        }
        let updated = sqlx::query_scalar::<_, String>(
            "UPDATE attempt_objects
             SET status = $7, checked_at = clock_timestamp()
             WHERE organization_id = $1
               AND attempt_id = $2
               AND fence = $3
               AND kind = $4
               AND name = $5
               AND object_digest = $6
               AND (
                 $7 <> 'available'
                 OR mcloving_owned_object_publication_allowed(
                      organization_id,
                      attempt_id,
                      fence,
                      kind,
                      name,
                      object_digest
                    )
               )
             RETURNING name",
        )
        .bind(organization_id)
        .bind(attempt_id)
        .bind(fence)
        .bind(kind.as_str())
        .bind(name)
        .bind(digest.as_slice())
        .bind(status.as_str())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(updated.is_some())
    }

    /// Lists all object references for a build, including explicit gaps.
    pub async fn build_objects(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        build_id: Uuid,
    ) -> Result<Vec<StoredObject>, StoreError> {
        type ObjectRow = (Uuid, i64, String, String, Vec<u8>, i64, String);
        let mut tx = self.tenant_transaction(organization_id).await?;
        let rows = sqlx::query_as::<_, ObjectRow>(
            "SELECT o.attempt_id, o.fence, o.kind, o.name,
                    o.object_digest, o.bytes, o.status
             FROM attempt_objects AS o
             JOIN attempts AS a
               ON a.id = o.attempt_id AND a.organization_id = o.organization_id
             JOIN nodes AS n
               ON n.id = a.node_id AND n.organization_id = a.organization_id
             JOIN builds AS b
               ON b.id = n.build_id AND b.organization_id = n.organization_id
             WHERE o.organization_id = $1
               AND b.project_id = $2
               AND b.id = $3
             ORDER BY a.ordinal, o.kind, o.name",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(build_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.into_iter()
            .map(|(attempt_id, fence, kind, name, digest, bytes, status)| {
                Ok(StoredObject {
                    attempt_id,
                    fence,
                    kind: parse_object_kind(&kind)?,
                    name,
                    digest: digest.try_into().map_err(|_| {
                        StoreError::InvalidObjectRecord(
                            "stored object digest is not 32 bytes".to_owned(),
                        )
                    })?,
                    bytes,
                    status: parse_object_status(&status)?,
                })
            })
            .collect()
    }

    /// Returns the global restore epoch used to fence pre-restore authority.
    pub async fn current_restore_epoch(&self) -> Result<i64, StoreError> {
        Ok(sqlx::query_scalar::<_, i64>(
            "SELECT restore_epoch
             FROM controller_metadata
             WHERE singleton",
        )
        .fetch_one(&self.pool)
        .await?)
    }

    /// Seals a stable backup identifier to the current PostgreSQL WAL position.
    ///
    /// Repeating an existing identifier returns a safe checkpoint at or after
    /// the original. The row is committed before its seal LSN is sampled and
    /// persisted; a later advertised recovery LSN is sampled only after that
    /// finalizing transaction commits. Backup tooling must persist this record
    /// with the database snapshot and, for HA PITR, retain WAL through the
    /// returned `recovery_lsn`.
    pub async fn seal_recovery_point(&self, backup_id: &str) -> Result<RecoveryPoint, StoreError> {
        if backup_id.is_empty() || backup_id.len() > 256 {
            return Err(StoreError::InvalidRecoveryOperation(
                "backup id must contain between 1 and 256 bytes".to_owned(),
            ));
        }
        let mut connection = self.pool.acquire().await?;
        connection.close_on_drop();
        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(RESTORE_FENCE_LOCK_KEY)
            .execute(&mut *connection)
            .await?;
        let mut tx = (&mut connection).begin().await?;
        sqlx::query(
            "INSERT INTO recovery_points (
                 backup_id, restore_epoch, recovery_lsn
             )
             SELECT $1, restore_epoch, NULL
             FROM controller_metadata
             WHERE singleton
             ON CONFLICT (backup_id) DO NOTHING",
        )
        .bind(backup_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        let durable_lsn =
            sqlx::query_scalar::<_, String>("SELECT pg_current_wal_flush_lsn()::text")
                .fetch_one(&mut *connection)
                .await?;
        let mut tx = (&mut connection).begin().await?;
        let (restore_epoch, sealed_lsn) = sqlx::query_as::<_, (i64, String)>(
            "UPDATE recovery_points
             SET recovery_lsn = COALESCE(recovery_lsn, $2::pg_lsn)
             WHERE backup_id = $1
             RETURNING restore_epoch, recovery_lsn::text",
        )
        .bind(backup_id)
        .bind(durable_lsn)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        let recovery_lsn =
            sqlx::query_scalar::<_, String>("SELECT pg_current_wal_flush_lsn()::text")
                .fetch_one(&mut *connection)
                .await?;
        Ok(RecoveryPoint {
            backup_id: backup_id.to_owned(),
            restore_epoch,
            sealed_lsn,
            recovery_lsn,
        })
    }

    /// Activates restored truth and atomically invalidates every old lease.
    ///
    /// This is a privileged, controller-wide recovery operation. Schedulers
    /// share-lock the epoch row while claiming, so no offer can straddle the
    /// activation transaction. Active attempts become explicit reconciliation
    /// work; their previous fence, owner, and epoch remain immutable history.
    pub async fn activate_restore_epoch(
        &self,
        backup_id: &str,
        reason: &str,
    ) -> Result<Option<RestoreActivation>, StoreError> {
        if backup_id.is_empty() || backup_id.len() > 256 || reason.is_empty() || reason.len() > 1024
        {
            return Err(StoreError::InvalidRecoveryOperation(
                "backup id and restore reason must be non-empty and bounded".to_owned(),
            ));
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(RESTORE_FENCE_LOCK_KEY)
            .execute(&mut *tx)
            .await?;
        let current_epoch = sqlx::query_scalar::<_, i64>(
            "SELECT restore_epoch
             FROM controller_metadata
             WHERE singleton
             FOR UPDATE",
        )
        .fetch_one(&mut *tx)
        .await?;
        let existing = sqlx::query_as::<_, (i64, String, i64)>(
            "SELECT restore_epoch, recovery_lsn::text, affected_attempts
             FROM restore_epochs
             WHERE backup_id = $1",
        )
        .bind(backup_id)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some((restore_epoch, recovery_lsn, affected_attempts)) = existing {
            tx.commit().await?;
            return Ok(Some(RestoreActivation {
                restore_epoch,
                backup_id: backup_id.to_owned(),
                sealed_lsn: recovery_lsn,
                affected_attempts: u64::try_from(affected_attempts).map_err(|_| {
                    StoreError::InvalidRecoveryOperation(
                        "stored affected-attempt count is invalid".to_owned(),
                    )
                })?,
            }));
        }
        let recovery_point = sqlx::query_as::<_, (i64, String)>(
            "SELECT restore_epoch, recovery_lsn::text
             FROM recovery_points
             WHERE backup_id = $1
               AND recovery_lsn IS NOT NULL",
        )
        .bind(backup_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((point_epoch, recovery_lsn)) = recovery_point else {
            tx.rollback().await?;
            return Ok(None);
        };
        if point_epoch != current_epoch {
            tx.rollback().await?;
            return Err(StoreError::InvalidRecoveryOperation(format!(
                "recovery point belongs to restore epoch {point_epoch}, current epoch is {current_epoch}"
            )));
        }
        let restore_epoch = current_epoch.checked_add(1).ok_or_else(|| {
            StoreError::InvalidRecoveryOperation("restore epoch overflow".to_owned())
        })?;
        let affected = sqlx::query_as::<_, (Uuid, Uuid, Uuid, Uuid, i64)>(
            "SELECT a.id, a.organization_id, n.id, n.build_id, a.restore_epoch
             FROM attempts AS a
             JOIN nodes AS n
               ON n.id = a.node_id AND n.organization_id = a.organization_id
             WHERE a.status IN (
                 'offered', 'accepted', 'running', 'finalizing', 'cancelling'
             )
             ORDER BY a.organization_id, a.id
             FOR UPDATE OF a, n",
        )
        .fetch_all(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE controller_metadata
             SET restore_epoch = $1, updated_at = clock_timestamp()
             WHERE singleton",
        )
        .bind(restore_epoch)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO restore_epochs (
                 restore_epoch, backup_id, recovery_lsn, reason, affected_attempts
             )
             VALUES ($1, $2, $3::pg_lsn, $4, $5)",
        )
        .bind(restore_epoch)
        .bind(backup_id)
        .bind(&recovery_lsn)
        .bind(reason)
        .bind(i64::try_from(affected.len()).map_err(|_| {
            StoreError::InvalidRecoveryOperation("affected-attempt count overflow".to_owned())
        })?)
        .execute(&mut *tx)
        .await?;
        for (attempt_id, organization_id, node_id, build_id, attempt_epoch) in &affected {
            sqlx::query(
                "UPDATE attempts
                 SET status = 'reconciliation_required',
                     lease_owner = NULL,
                     lease_expires_at = NULL
                 WHERE id = $1 AND organization_id = $2",
            )
            .bind(attempt_id)
            .bind(organization_id)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE nodes
                 SET status = 'reconciliation_required'
                 WHERE id = $1 AND organization_id = $2",
            )
            .bind(node_id)
            .bind(organization_id)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE builds
                 SET status = 'reconciliation_required', completed_at = NULL
                 WHERE id = $1 AND organization_id = $2",
            )
            .bind(build_id)
            .bind(organization_id)
            .execute(&mut *tx)
            .await?;
            let uncertain_effects = sqlx::query(
                "UPDATE attempt_effects
                 SET status = 'uncertain', updated_at = clock_timestamp()
                 WHERE organization_id = $1
                   AND attempt_id = $2
                   AND status IN ('prepared', 'applied')",
            )
            .bind(organization_id)
            .bind(attempt_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            append_event_and_outbox(
                &mut tx,
                *organization_id,
                *build_id,
                "attempt.restore_reconciliation_required",
                json!({
                    "attempt_id": attempt_id,
                    "attempt_restore_epoch": attempt_epoch,
                    "restore_epoch": restore_epoch,
                    "backup_id": backup_id,
                    "recovery_lsn": recovery_lsn,
                    "uncertain_effects": uncertain_effects,
                }),
            )
            .await?;
        }
        tx.commit().await?;
        Ok(Some(RestoreActivation {
            restore_epoch,
            backup_id: backup_id.to_owned(),
            sealed_lsn: recovery_lsn,
            affected_attempts: affected.len() as u64,
        }))
    }

    /// Extends an object's deletion deadline without permitting shortening.
    pub async fn retain_object_for(
        &self,
        organization_id: Uuid,
        digest: [u8; 32],
        retention_seconds: i64,
    ) -> Result<bool, StoreError> {
        if !(0..=MAX_OBJECT_RETENTION_SECONDS).contains(&retention_seconds) {
            return Ok(false);
        }
        let mut tx = self.tenant_transaction(organization_id).await?;
        acquire_object_deletion_fence(&mut tx, &digest).await?;
        let retained = match sqlx::query_scalar::<_, Vec<u8>>(
            "INSERT INTO object_retention (
                 organization_id, object_digest, retain_until
             )
             SELECT $1, $2,
                    clock_timestamp() + make_interval(secs => $3::double precision)
             WHERE EXISTS (
                 SELECT 1
                 FROM attempt_objects
                 WHERE organization_id = $1 AND object_digest = $2
             )
             ON CONFLICT (organization_id, object_digest)
             DO UPDATE SET
                 retain_until = GREATEST(
                     object_retention.retain_until,
                     EXCLUDED.retain_until
                 ),
                 updated_at = clock_timestamp()
             RETURNING object_digest",
        )
        .bind(organization_id)
        .bind(digest.as_slice())
        .bind(retention_seconds as f64)
        .fetch_optional(&mut *tx)
        .await
        {
            Ok(retained) => retained,
            Err(error) if is_object_deletion_fence_violation(&error) => {
                tx.rollback().await?;
                return Ok(false);
            }
            Err(error) => return Err(error.into()),
        };
        tx.commit().await?;
        Ok(retained.is_some())
    }

    /// Applies an immutable, named legal hold to committed object content.
    pub async fn acquire_legal_hold(
        &self,
        organization_id: Uuid,
        digest: [u8; 32],
        hold_key: &str,
        reason: &str,
    ) -> Result<bool, StoreError> {
        if hold_key.is_empty() || hold_key.len() > 256 || reason.is_empty() || reason.len() > 1024 {
            return Ok(false);
        }
        let mut tx = self.tenant_transaction(organization_id).await?;
        acquire_object_deletion_fence(&mut tx, &digest).await?;
        let held = match sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO legal_holds (
                 id, organization_id, object_digest, hold_key, reason
             )
             SELECT $1, $2, $3, $4, $5
             WHERE EXISTS (
                 SELECT 1
                 FROM attempt_objects
                 WHERE organization_id = $2 AND object_digest = $3
             )
             ON CONFLICT (organization_id, object_digest, hold_key)
             DO UPDATE SET reason = EXCLUDED.reason
             WHERE legal_holds.reason = EXCLUDED.reason
               AND legal_holds.released_at IS NULL
             RETURNING id",
        )
        .bind(Uuid::new_v4())
        .bind(organization_id)
        .bind(digest.as_slice())
        .bind(hold_key)
        .bind(reason)
        .fetch_optional(&mut *tx)
        .await
        {
            Ok(held) => held,
            Err(error) if is_object_deletion_fence_violation(&error) => {
                tx.rollback().await?;
                return Ok(false);
            }
            Err(error) => return Err(error.into()),
        };
        tx.commit().await?;
        Ok(held.is_some())
    }

    /// Releases one exact legal hold while preserving its audit record.
    pub async fn release_legal_hold(
        &self,
        organization_id: Uuid,
        digest: [u8; 32],
        hold_key: &str,
    ) -> Result<bool, StoreError> {
        let mut tx = self.tenant_transaction(organization_id).await?;
        let released = sqlx::query_scalar::<_, Uuid>(
            "UPDATE legal_holds
             SET released_at = clock_timestamp()
             WHERE organization_id = $1
               AND object_digest = $2
               AND hold_key = $3
               AND released_at IS NULL
             RETURNING id",
        )
        .bind(organization_id)
        .bind(digest.as_slice())
        .bind(hold_key)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(released.is_some())
    }

    /// Inspects globally unprotected content without granting deletion authority.
    ///
    /// This privileged cross-tenant operation is deliberately not exposed
    /// through a tenant transaction. Every organization referencing a digest
    /// must have expired retention and no organization may have an active hold.
    /// Absence of any retention record is fail-closed. Callers must use
    /// [`Self::claim_objects_globally_for_deletion`] before physical deletion;
    /// this point-in-time inspection result is never deletion authority.
    pub async fn objects_globally_eligible_for_deletion(
        &self,
        limit: i64,
    ) -> Result<Vec<[u8; 32]>, StoreError> {
        if !(1..=10_000).contains(&limit) {
            return Ok(Vec::new());
        }
        let rows = sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT DISTINCT candidate.object_digest
             FROM attempt_objects AS candidate
             WHERE NOT EXISTS (
                   SELECT 1
                   FROM attempt_objects AS pending
                   WHERE pending.object_digest = candidate.object_digest
                     AND pending.status = 'pending'
               )
               AND NOT EXISTS (
                   SELECT 1
                   FROM attempt_objects AS referenced
                   LEFT JOIN object_retention AS r
                     ON r.organization_id = referenced.organization_id
                    AND r.object_digest = referenced.object_digest
                   WHERE referenced.object_digest = candidate.object_digest
                     AND (
                         r.object_digest IS NULL
                         OR r.retain_until > clock_timestamp()
                     )
               )
               AND NOT EXISTS (
                   SELECT 1
                   FROM legal_holds AS h
                   WHERE h.object_digest = candidate.object_digest
                     AND h.released_at IS NULL
               )
             ORDER BY candidate.object_digest
             LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|digest| {
                digest.try_into().map_err(|_| {
                    StoreError::InvalidObjectRecord(
                        "retained object digest is not 32 bytes".to_owned(),
                    )
                })
            })
            .collect()
    }

    /// Claims globally unprotected content for serialized physical deletion.
    ///
    /// Each durable claim fences new references, retention extensions, and
    /// legal holds for its digest. Before touching physical storage, a worker
    /// must successfully call [`Self::begin_object_deletion`]. Claimed work can
    /// be abandoned; deleting work must instead be recovered and completed.
    /// Completed claims remain as tombstones and permanently block stale
    /// references to deleted content.
    pub async fn claim_objects_globally_for_deletion(
        &self,
        limit: i64,
    ) -> Result<Vec<ObjectDeletionClaim>, StoreError> {
        if !(1..=10_000).contains(&limit) {
            return Ok(Vec::new());
        }
        let mut tx = self.pool.begin().await?;
        let candidates = sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT DISTINCT candidate.object_digest
             FROM attempt_objects AS candidate
             WHERE NOT EXISTS (
                   SELECT 1
                   FROM object_deletion_claims AS claim
                   WHERE claim.object_digest = candidate.object_digest
               )
               AND NOT EXISTS (
                   SELECT 1
                   FROM attempt_objects AS pending
                   WHERE pending.object_digest = candidate.object_digest
                     AND pending.status = 'pending'
               )
               AND NOT EXISTS (
                   SELECT 1
                   FROM attempt_objects AS referenced
                   LEFT JOIN object_retention AS r
                     ON r.organization_id = referenced.organization_id
                    AND r.object_digest = referenced.object_digest
                   WHERE referenced.object_digest = candidate.object_digest
                     AND (
                         r.object_digest IS NULL
                         OR r.retain_until > clock_timestamp()
                     )
               )
               AND NOT EXISTS (
                   SELECT 1
                   FROM legal_holds AS h
                   WHERE h.object_digest = candidate.object_digest
                     AND h.released_at IS NULL
               )
             ORDER BY candidate.object_digest
             LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&mut *tx)
        .await?;
        let mut claims = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            let digest: [u8; 32] = candidate.try_into().map_err(|_| {
                StoreError::InvalidObjectRecord(
                    "deletion candidate digest is not 32 bytes".to_owned(),
                )
            })?;
            acquire_object_deletion_fence(&mut tx, &digest).await?;
            let token = Uuid::new_v4();
            let inserted = sqlx::query_scalar::<_, Uuid>(
                "INSERT INTO object_deletion_claims (
                     object_digest, claim_token, status
                 )
                 SELECT $1, $2, 'claimed'
                 WHERE EXISTS (
                       SELECT 1
                       FROM attempt_objects
                       WHERE object_digest = $1
                   )
                   AND NOT EXISTS (
                       SELECT 1
                       FROM attempt_objects AS pending
                       WHERE pending.object_digest = $1
                         AND pending.status = 'pending'
                   )
                   AND NOT EXISTS (
                       SELECT 1
                       FROM attempt_objects AS referenced
                       LEFT JOIN object_retention AS r
                         ON r.organization_id = referenced.organization_id
                        AND r.object_digest = referenced.object_digest
                       WHERE referenced.object_digest = $1
                         AND (
                             r.object_digest IS NULL
                             OR r.retain_until > clock_timestamp()
                         )
                   )
                   AND NOT EXISTS (
                       SELECT 1
                       FROM legal_holds AS h
                       WHERE h.object_digest = $1
                         AND h.released_at IS NULL
                   )
                   AND NOT EXISTS (
                       SELECT 1
                       FROM object_deletion_claims
                       WHERE object_digest = $1
                   )
                 RETURNING claim_token",
            )
            .bind(digest.as_slice())
            .bind(token)
            .fetch_optional(&mut *tx)
            .await?;
            if inserted.is_some() {
                claims.push(ObjectDeletionClaim { digest, token });
            }
        }
        tx.commit().await?;
        Ok(claims)
    }

    /// Lists durable active claims so a restarted deleter can recover work.
    pub async fn pending_object_deletion_claims(
        &self,
        limit: i64,
    ) -> Result<Vec<ObjectDeletionClaim>, StoreError> {
        if !(1..=10_000).contains(&limit) {
            return Ok(Vec::new());
        }
        let rows = sqlx::query_as::<_, (Vec<u8>, Uuid)>(
            "SELECT object_digest, claim_token
             FROM object_deletion_claims
             WHERE status IN ('claimed', 'deleting')
             ORDER BY claimed_at, object_digest
             LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|(digest, token)| {
                Ok(ObjectDeletionClaim {
                    digest: digest.try_into().map_err(|_| {
                        StoreError::InvalidObjectRecord(
                            "deletion claim digest is not 32 bytes".to_owned(),
                        )
                    })?,
                    token,
                })
            })
            .collect()
    }

    /// Irrevocably authorizes one exact claim to touch physical storage.
    ///
    /// This transition must commit before any CAS delete. It is idempotent for
    /// the same token. Once it succeeds, the claim cannot be abandoned; a
    /// crashed worker is recovered through [`Self::pending_object_deletion_claims`].
    pub async fn begin_object_deletion(
        &self,
        claim: ObjectDeletionClaim,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        acquire_object_deletion_fence(&mut tx, &claim.digest).await?;
        let started = sqlx::query_scalar::<_, Uuid>(
            "UPDATE object_deletion_claims
             SET status = 'deleting',
                 deletion_started_at = COALESCE(
                     deletion_started_at,
                     clock_timestamp()
                 )
             WHERE object_digest = $1
               AND claim_token = $2
               AND status IN ('claimed', 'deleting')
             RETURNING claim_token",
        )
        .bind(claim.digest.as_slice())
        .bind(claim.token)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(started.is_some())
    }

    /// Completes an exact deletion claim after the CAS object is gone.
    pub async fn complete_object_deletion(
        &self,
        claim: ObjectDeletionClaim,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        acquire_object_deletion_fence(&mut tx, &claim.digest).await?;
        let completed = sqlx::query_scalar::<_, Uuid>(
            "WITH transitioned AS (
                 UPDATE object_deletion_claims
                 SET status = 'deleted', completed_at = clock_timestamp()
                 WHERE object_digest = $1
                   AND claim_token = $2
                   AND status = 'deleting'
                 RETURNING claim_token
             )
             SELECT claim_token FROM transitioned
             UNION ALL
             SELECT claim_token
             FROM object_deletion_claims
             WHERE object_digest = $1
               AND claim_token = $2
               AND status = 'deleted'
             LIMIT 1",
        )
        .bind(claim.digest.as_slice())
        .bind(claim.token)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(completed.is_some())
    }

    /// Revokes an exact claim before physical deletion has been authorized.
    ///
    /// A worker must treat `false` as a hard prohibition on touching storage.
    /// Deleting claims cannot be abandoned because the physical outcome may be
    /// ambiguous; they remain fenced and recoverable until completion.
    pub async fn abandon_object_deletion(
        &self,
        claim: ObjectDeletionClaim,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        acquire_object_deletion_fence(&mut tx, &claim.digest).await?;
        let abandoned = sqlx::query_scalar::<_, Uuid>(
            "DELETE FROM object_deletion_claims
             WHERE object_digest = $1
               AND claim_token = $2
               AND status = 'claimed'
             RETURNING claim_token",
        )
        .bind(claim.digest.as_slice())
        .bind(claim.token)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(abandoned.is_some())
    }

    /// Accepts exactly one terminal publication for the current attempt fence.
    ///
    /// The attempt, node, build, event, and outbox mutation share a transaction.
    /// A stale or losing concurrent publisher observes `false`. If the current
    /// fence has an uncertain effect, normal terminal publication is rejected
    /// and the attempt is atomically routed to explicit reconciliation.
    #[allow(clippy::too_many_arguments)]
    pub async fn finalize_attempt(
        &self,
        organization_id: Uuid,
        attempt_id: Uuid,
        fence: i64,
        restore_epoch: i64,
        agent_id: &str,
        outcome: TerminalOutcome,
        summary: Value,
    ) -> Result<bool, StoreError> {
        self.finalize_attempt_with_session(
            organization_id,
            attempt_id,
            fence,
            restore_epoch,
            agent_id,
            None,
            outcome,
            summary,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn finalize_attempt_in_session(
        &self,
        organization_id: Uuid,
        attempt_id: Uuid,
        fence: i64,
        restore_epoch: i64,
        agent_id: &str,
        session_epoch: u64,
        outcome: TerminalOutcome,
        summary: Value,
    ) -> Result<bool, StoreError> {
        self.finalize_attempt_with_session(
            organization_id,
            attempt_id,
            fence,
            restore_epoch,
            agent_id,
            Some(session_epoch),
            outcome,
            summary,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn finalize_attempt_with_session(
        &self,
        organization_id: Uuid,
        attempt_id: Uuid,
        fence: i64,
        restore_epoch: i64,
        agent_id: &str,
        session_epoch: Option<u64>,
        outcome: TerminalOutcome,
        summary: Value,
    ) -> Result<bool, StoreError> {
        let mut tx = self.tenant_transaction(organization_id).await?;
        acquire_restore_fence_shared(&mut tx).await?;
        if let Some(session_epoch) = session_epoch
            && !Self::lock_agent_session(&mut tx, agent_id, session_epoch).await?
        {
            tx.rollback().await?;
            return Ok(false);
        }
        let existing = sqlx::query_as::<_, (String, Option<Value>)>(
            "SELECT a.status, a.terminal_summary
             FROM attempts AS a
             CROSS JOIN controller_metadata AS m
             WHERE a.id = $1
               AND a.organization_id = $2
               AND a.fence = $3
               AND a.restore_epoch = $4
               AND a.lease_owner = $5
               AND m.singleton
               AND a.restore_epoch = m.restore_epoch
             FOR UPDATE OF a",
        )
        .bind(attempt_id)
        .bind(organization_id)
        .bind(fence)
        .bind(restore_epoch)
        .bind(agent_id)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some((status, terminal_summary)) = existing
            && matches!(status.as_str(), "succeeded" | "failed" | "aborted")
        {
            let identical =
                status == outcome.as_str() && terminal_summary.as_ref() == Some(&summary);
            if identical {
                tx.commit().await?;
            } else {
                tx.rollback().await?;
            }
            return Ok(identical);
        }
        let authority = sqlx::query_as::<_, (Uuid, Uuid)>(
            "SELECT n.id, n.build_id
             FROM attempts AS a
             JOIN nodes AS n
               ON n.id = a.node_id
              AND n.organization_id = a.organization_id
             WHERE a.id = $1
               AND a.organization_id = $2
               AND a.fence = $3
               AND a.restore_epoch = $4
               AND a.lease_owner = $5
               AND a.lease_expires_at > clock_timestamp()
               AND a.status IN ('accepted', 'running', 'finalizing', 'cancelling')
               AND a.restore_epoch = (
                   SELECT restore_epoch
                   FROM controller_metadata
                   WHERE singleton
               )
             FOR UPDATE OF a, n",
        )
        .bind(attempt_id)
        .bind(organization_id)
        .bind(fence)
        .bind(restore_epoch)
        .bind(agent_id)
        .fetch_optional(&mut *tx)
        .await?;

        let Some((node_id, build_id)) = authority else {
            tx.rollback().await?;
            return Ok(false);
        };

        let uncertain_effects = sqlx::query_scalar::<_, i64>(
            "SELECT count(*)
             FROM attempt_effects
             WHERE organization_id = $1
               AND attempt_id = $2
               AND fence = $3
               AND status = 'uncertain'",
        )
        .bind(organization_id)
        .bind(attempt_id)
        .bind(fence)
        .fetch_one(&mut *tx)
        .await?;
        if uncertain_effects > 0 {
            sqlx::query(
                "UPDATE attempts
                 SET status = 'reconciliation_required',
                     lease_owner = NULL,
                     lease_expires_at = NULL
                 WHERE id = $1 AND organization_id = $2",
            )
            .bind(attempt_id)
            .bind(organization_id)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE nodes
                 SET status = 'reconciliation_required'
                 WHERE id = $1 AND organization_id = $2",
            )
            .bind(node_id)
            .bind(organization_id)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE builds
                 SET status = 'reconciliation_required', completed_at = NULL
                 WHERE id = $1 AND organization_id = $2",
            )
            .bind(build_id)
            .bind(organization_id)
            .execute(&mut *tx)
            .await?;
            append_event_and_outbox(
                &mut tx,
                organization_id,
                build_id,
                "attempt.terminal_reconciliation_required",
                json!({
                    "attempt_id": attempt_id,
                    "node_id": node_id,
                    "fence": fence,
                    "restore_epoch": restore_epoch,
                    "agent_id": agent_id,
                    "attempted_outcome": outcome.as_str(),
                    "uncertain_effects": uncertain_effects,
                }),
            )
            .await?;
            tx.commit().await?;
            return Ok(false);
        }

        sqlx::query(
            "UPDATE attempts
             SET status = $3,
                 terminal_summary = $4,
                 completed_at = clock_timestamp(),
                 lease_expires_at = NULL
             WHERE id = $1 AND organization_id = $2",
        )
        .bind(attempt_id)
        .bind(organization_id)
        .bind(outcome.as_str())
        .bind(&summary)
        .execute(&mut *tx)
        .await?;
        if !dag::advance_dag_after_attempt(
            &mut tx,
            organization_id,
            build_id,
            node_id,
            attempt_id,
            outcome,
        )
        .await?
        {
            sqlx::query(
                "UPDATE nodes
                 SET status = $3
                 WHERE id = $1 AND organization_id = $2",
            )
            .bind(node_id)
            .bind(organization_id)
            .bind(outcome.as_str())
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE builds
                 SET status = $3, completed_at = clock_timestamp()
                 WHERE id = $1 AND organization_id = $2",
            )
            .bind(build_id)
            .bind(organization_id)
            .bind(outcome.as_str())
            .execute(&mut *tx)
            .await?;
        }
        append_event_and_outbox(
            &mut tx,
            organization_id,
            build_id,
            "attempt.terminal",
            json!({
                "attempt_id": attempt_id,
                "fence": fence,
                "restore_epoch": restore_epoch,
                "outcome": outcome.as_str(),
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    pub(crate) async fn tenant_transaction(
        &self,
        organization_id: Uuid,
    ) -> Result<Transaction<'_, Postgres>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT set_config('mcloving.organization_id', $1, true)")
            .bind(organization_id.to_string())
            .execute(&mut *tx)
            .await?;
        Ok(tx)
    }

    pub(crate) async fn lock_agent_session(
        tx: &mut Transaction<'_, Postgres>,
        agent_id: &str,
        session_epoch: u64,
    ) -> Result<bool, StoreError> {
        let session_epoch =
            i64::try_from(session_epoch).map_err(|_| StoreError::InvalidAgentSession)?;
        let current = sqlx::query_scalar::<_, i64>(
            "SELECT session_epoch
             FROM agent_sessions
             WHERE agent_id = $1
             FOR SHARE",
        )
        .bind(agent_id)
        .fetch_optional(&mut **tx)
        .await?;
        Ok(current == Some(session_epoch))
    }
}

async fn apply_migration(
    tx: &mut Transaction<'_, Postgres>,
    version: i32,
    sql: &str,
) -> Result<(), sqlx::Error> {
    let installed = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (
             SELECT 1 FROM mcloving_schema_migrations WHERE version = $1
         )",
    )
    .bind(version)
    .fetch_one(&mut **tx)
    .await?;
    if !installed {
        sqlx::raw_sql(sql).execute(&mut **tx).await?;
        sqlx::query("INSERT INTO mcloving_schema_migrations (version) VALUES ($1)")
            .bind(version)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

async fn existing_admission(
    tx: &mut Transaction<'_, Postgres>,
    input: &NewBuild,
) -> Result<Option<BuildAdmission>, StoreError> {
    let row = sqlx::query(
        "SELECT b.id AS build_id, n.id AS node_id, a.id AS attempt_id,
                b.organization_id, b.pipeline_id, b.pipeline_revision,
                b.pipeline_operational_generation, b.pipeline_digest,
                b.priority AS build_priority, b.dag_mode,
                n.node_key, n.required_capabilities, n.required_trust_pool,
                n.priority AS node_priority, n.execution_spec
         FROM builds AS b
         JOIN nodes AS n ON n.build_id = b.id AND n.organization_id = b.organization_id
         JOIN attempts AS a ON a.node_id = n.id AND a.organization_id = n.organization_id
         WHERE b.project_id = $1
           AND b.idempotency_key = $2
           AND a.ordinal = 1
         ORDER BY n.id
         LIMIT 2",
    )
    .bind(input.project_id)
    .bind(&input.idempotency_key)
    .fetch_all(&mut **tx)
    .await?;
    if row.is_empty() {
        return Ok(None);
    }
    if row.len() != 1 {
        return Err(StoreError::IdempotencyConflict(
            "idempotent single-node build has a different node contract".to_owned(),
        ));
    }
    let row = &row[0];
    let exact = row.try_get::<Uuid, _>("organization_id")? == input.organization_id
        && row.try_get::<Option<Uuid>, _>("pipeline_id")? == Some(input.pipeline_id)
        && row.try_get::<Option<i64>, _>("pipeline_revision")? == Some(input.pipeline_revision)
        && row.try_get::<Option<i64>, _>("pipeline_operational_generation")?
            == Some(input.pipeline_operational_generation)
        && row.try_get::<Vec<u8>, _>("pipeline_digest")? == input.pipeline_digest
        && row.try_get::<i32, _>("build_priority")? == input.priority
        && !row.try_get::<bool, _>("dag_mode")?
        && row.try_get::<String, _>("node_key")? == input.node_key
        && row.try_get::<Vec<String>, _>("required_capabilities")? == input.required_capabilities
        && row.try_get::<String, _>("required_trust_pool")? == input.required_trust_pool
        && row.try_get::<i32, _>("node_priority")? == input.priority
        && row.try_get::<Value, _>("execution_spec")? == input.execution_spec;
    if !exact {
        return Err(StoreError::IdempotencyConflict(
            "idempotency key already belongs to a different build contract".to_owned(),
        ));
    }
    Ok(Some(BuildAdmission {
        build_id: row.try_get("build_id")?,
        node_id: row.try_get("node_id")?,
        attempt_id: row.try_get("attempt_id")?,
        created: false,
    }))
}

pub(crate) async fn lock_pipeline_transaction(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    pipeline_id: Uuid,
) -> Result<(), StoreError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("mcloving.pipeline.{organization_id}.{pipeline_id}"))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub(crate) async fn lock_enabled_pipeline_binding(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    project_id: Uuid,
    pipeline_id: Uuid,
    pipeline_revision: i64,
    operational_generation: i64,
) -> Result<[u8; 32], StoreError> {
    if pipeline_revision <= 0 || operational_generation <= 0 {
        return Err(StoreError::InvalidPipelineState(
            "pipeline admission binding must use positive revision and generation".to_owned(),
        ));
    }
    let current = sqlx::query_as::<_, (i64, i64, String, Vec<u8>)>(
        "SELECT d.current_revision, d.operational_generation, h.state, r.semantic_digest
         FROM pipeline_definitions AS d
         JOIN pipeline_operational_state_history AS h
           ON h.organization_id = d.organization_id
          AND h.pipeline_id = d.pipeline_id
          AND h.generation = d.operational_generation
         JOIN pipeline_revisions AS r
           ON r.organization_id = d.organization_id
          AND r.pipeline_id = d.pipeline_id
          AND r.revision = d.current_revision
         WHERE d.organization_id = $1
           AND d.project_id = $2
           AND d.pipeline_id = $3
         FOR UPDATE OF d",
    )
    .bind(organization_id)
    .bind(project_id)
    .bind(pipeline_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((current_revision, current_generation, state, current_digest)) = current else {
        return Err(StoreError::PipelineStateConflict(
            "pipeline admission binding does not identify a saved pipeline".to_owned(),
        ));
    };
    if state == "disabled" {
        return Err(StoreError::PipelineDisabled {
            pipeline_id,
            generation: current_generation,
        });
    }
    if state != "enabled" {
        return Err(StoreError::InvalidPipelineState(format!(
            "stored pipeline operational state '{state}' is invalid"
        )));
    }
    if current_revision != pipeline_revision || current_generation != operational_generation {
        return Err(StoreError::PipelineStateConflict(format!(
            "pipeline admission binding is stale: current revision/generation is \
             {current_revision}/{current_generation}"
        )));
    }
    current_digest.try_into().map_err(|_| {
        StoreError::PipelineStateConflict(
            "saved pipeline revision digest is not SHA-256 sized".to_owned(),
        )
    })
}

pub(crate) async fn lock_enabled_build_pipeline(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    build_id: Uuid,
) -> Result<(Uuid, i64), StoreError> {
    let binding = sqlx::query_as::<_, (Option<Uuid>, Option<i64>)>(
        "SELECT pipeline_id, pipeline_operational_generation
         FROM builds
         WHERE organization_id = $1 AND id = $2",
    )
    .bind(organization_id)
    .bind(build_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((Some(pipeline_id), Some(admitted_generation))) = binding else {
        return Err(StoreError::PipelineStateConflict(
            "build is missing its pipeline operational-state binding".to_owned(),
        ));
    };
    let current = sqlx::query_as::<_, (i64, String)>(
        "SELECT d.operational_generation, h.state
         FROM pipeline_definitions AS d
         JOIN pipeline_operational_state_history AS h
           ON h.organization_id = d.organization_id
          AND h.pipeline_id = d.pipeline_id
          AND h.generation = d.operational_generation
         WHERE d.organization_id = $1 AND d.pipeline_id = $2
         FOR UPDATE OF d",
    )
    .bind(organization_id)
    .bind(pipeline_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((current_generation, state)) = current else {
        return Err(StoreError::PipelineStateConflict(
            "build pipeline operational-state truth is missing".to_owned(),
        ));
    };
    if state == "disabled" {
        return Err(StoreError::PipelineDisabled {
            pipeline_id,
            generation: current_generation,
        });
    }
    if state != "enabled" {
        return Err(StoreError::InvalidPipelineState(format!(
            "stored pipeline operational state '{state}' is invalid"
        )));
    }
    if current_generation != admitted_generation {
        return Err(StoreError::PipelineStateConflict(format!(
            "build pipeline generation {admitted_generation} is stale; current generation is \
             {current_generation}"
        )));
    }
    Ok((pipeline_id, current_generation))
}

async fn append_event_and_outbox(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    build_id: Uuid,
    kind: &str,
    payload: Value,
) -> Result<(), StoreError> {
    append_event_and_outbox_as(
        tx,
        organization_id,
        build_id,
        "system:controller",
        kind,
        payload,
    )
    .await
}

async fn append_event_and_outbox_as(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    build_id: Uuid,
    actor_subject: &str,
    kind: &str,
    payload: Value,
) -> Result<(), StoreError> {
    validate_audit_actor(actor_subject)?;
    sqlx::query(
        "INSERT INTO build_events (organization_id, build_id, kind, payload)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(organization_id)
    .bind(build_id)
    .bind(kind)
    .bind(&payload)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "INSERT INTO outbox (organization_id, topic, aggregate_id, payload)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(organization_id)
    .bind(kind)
    .bind(build_id)
    .bind(&payload)
    .execute(&mut **tx)
    .await?;
    audit::append_audit_record(
        tx,
        organization_id,
        audit_category_for_event(kind),
        actor_subject,
        kind,
        &format!("build:{build_id}"),
        payload,
    )
    .await?;
    Ok(())
}

pub(crate) fn validate_audit_actor(actor_subject: &str) -> Result<(), StoreError> {
    if actor_subject.is_empty()
        || actor_subject.len() > 512
        || actor_subject.trim() != actor_subject
        || actor_subject.chars().any(char::is_control)
    {
        return Err(StoreError::InvalidAuditOperation(
            "audit actor subject must be non-empty, canonical, and bounded".to_owned(),
        ));
    }
    Ok(())
}

fn audit_category_for_event(kind: &str) -> &'static str {
    if kind.contains("credential") {
        "credential_grant"
    } else if kind.contains("approval") || kind.contains("approved") {
        "approval"
    } else if kind.contains("artifact") || kind.contains("object") {
        "artifact"
    } else {
        "scheduling"
    }
}

async fn terminalize_dead_lettered_reconciliation(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    attempt_id: Uuid,
    node_id: Uuid,
    build_id: Uuid,
    reason: &str,
) -> Result<(), sqlx::Error> {
    let terminalized = sqlx::query_scalar::<_, Uuid>(
        "UPDATE attempts
         SET status = 'failed',
             terminal_summary = $3,
             completed_at = clock_timestamp()
         WHERE organization_id = $1
           AND id = $2
           AND status = 'reconciliation_required'
         RETURNING id",
    )
    .bind(organization_id)
    .bind(attempt_id)
    .bind(json!({"dead_lettered": true, "reason": reason}))
    .fetch_optional(&mut **tx)
    .await?;
    if terminalized.is_none() {
        return Ok(());
    }
    sqlx::query(
        "UPDATE nodes
         SET status = 'failed'
         WHERE organization_id = $1 AND id = $2",
    )
    .bind(organization_id)
    .bind(node_id)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "UPDATE builds
         SET status = 'failed', completed_at = clock_timestamp()
         WHERE organization_id = $1 AND id = $2",
    )
    .bind(organization_id)
    .bind(build_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn acquire_restore_fence_shared(
    tx: &mut Transaction<'_, Postgres>,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock_shared($1)")
        .bind(RESTORE_FENCE_LOCK_KEY)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn acquire_object_deletion_fence(
    tx: &mut Transaction<'_, Postgres>,
    digest: &[u8; 32],
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "SELECT pg_advisory_xact_lock(
             hashtextextended('mcloving.object.delete.' || encode($1, 'hex'), 0)
         )",
    )
    .bind(digest.as_slice())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn is_object_deletion_fence_violation(error: &sqlx::Error) -> bool {
    error.as_database_error().is_some_and(|database_error| {
        database_error.code().as_deref() == Some("P0001")
            && database_error.message() == "mcloving object protection write is unavailable"
    })
}

fn valid_effect_transition(current: &str, requested: EffectStatus) -> bool {
    matches!(
        (current, requested),
        (
            "prepared",
            EffectStatus::Prepared | EffectStatus::Applied | EffectStatus::Uncertain
        ) | (
            "applied",
            EffectStatus::Applied | EffectStatus::Confirmed | EffectStatus::Uncertain
        ) | ("confirmed", EffectStatus::Confirmed)
            | (
                "uncertain",
                EffectStatus::Uncertain | EffectStatus::Confirmed
            )
    )
}

fn recoverable_finalization_status(status: &str) -> bool {
    matches!(status, "running" | "finalizing" | "cancelling")
}

fn log_quota_allows(committed: i64, incoming: i64) -> bool {
    committed >= 0 && incoming >= 0 && committed.saturating_add(incoming) <= MAX_ATTEMPT_LOG_BYTES
}

fn log_sequence_is_bounded(sequence: i64) -> bool {
    (0..MAX_ATTEMPT_LOG_CHUNKS).contains(&sequence)
}

fn parse_effect_class(value: &str) -> Result<EffectClass, StoreError> {
    match value {
        "idempotent" => Ok(EffectClass::Idempotent),
        "externally_idempotent" => Ok(EffectClass::ExternallyIdempotent),
        "non_idempotent" => Ok(EffectClass::NonIdempotent),
        other => Err(StoreError::InvalidEffectPayload(format!(
            "unknown effect class {other}"
        ))),
    }
}

fn parse_effect_status(value: &str) -> Result<EffectStatus, StoreError> {
    match value {
        "prepared" => Ok(EffectStatus::Prepared),
        "applied" => Ok(EffectStatus::Applied),
        "confirmed" => Ok(EffectStatus::Confirmed),
        "uncertain" => Ok(EffectStatus::Uncertain),
        other => Err(StoreError::InvalidEffectPayload(format!(
            "unknown effect status {other}"
        ))),
    }
}

fn parse_object_kind(value: &str) -> Result<ObjectKind, StoreError> {
    match value {
        "log" => Ok(ObjectKind::Log),
        "artifact" => Ok(ObjectKind::Artifact),
        "result" => Ok(ObjectKind::Result),
        other => Err(StoreError::InvalidObjectRecord(format!(
            "unknown object kind {other}"
        ))),
    }
}

fn hex_digest(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn redact_to_fixed_point(content: &[u8], redactions: &[Vec<u8>]) -> Result<Vec<u8>, StoreError> {
    if !redactions.is_empty() {
        AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostLongest)
            .build(redactions)
            .map_err(|error| {
                StoreError::InvalidSecurityOperation(format!(
                    "credential redaction set is invalid: {error}"
                ))
            })?;
    }
    let mut secrets = redactions
        .iter()
        .map(Vec::as_slice)
        .filter(|secret| !secret.is_empty())
        .collect::<Vec<_>>();
    secrets.sort_unstable_by_key(|secret| std::cmp::Reverse(secret.len()));
    let mut output = Vec::with_capacity(content.len());
    for byte in content {
        output.push(*byte);
        while let Some(secret) = secrets.iter().find(|secret| output.ends_with(secret)) {
            output.truncate(output.len() - secret.len());
        }
    }
    Ok(output)
}

fn parse_object_status(value: &str) -> Result<ObjectStatus, StoreError> {
    match value {
        "pending" => Ok(ObjectStatus::Pending),
        "available" => Ok(ObjectStatus::Available),
        "missing" => Ok(ObjectStatus::Missing),
        "corrupt" => Ok(ObjectStatus::Corrupt),
        other => Err(StoreError::InvalidObjectRecord(format!(
            "unknown object status {other}"
        ))),
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn credential_redaction_reaches_a_fixed_point() {
        assert_eq!(
            redact_to_fixed_point(b"abc", &[b"b".to_vec(), b"ac".to_vec()]).unwrap(),
            b""
        );
    }

    #[test]
    fn finalization_recovery_accepts_all_nonterminal_completion_races() {
        for status in ["running", "finalizing", "cancelling"] {
            assert!(recoverable_finalization_status(status));
        }
        for status in [
            "queued",
            "offered",
            "accepted",
            "reconciliation_required",
            "succeeded",
            "failed",
            "aborted",
        ] {
            assert!(!recoverable_finalization_status(status));
        }
    }

    #[test]
    fn log_quota_is_closed_at_the_boundary() {
        assert!(log_quota_allows(MAX_ATTEMPT_LOG_BYTES - 1, 1));
        assert!(!log_quota_allows(MAX_ATTEMPT_LOG_BYTES, 1));
        assert!(!log_quota_allows(i64::MAX, i64::MAX));
        assert!(!log_quota_allows(-1, 1));
        assert!(log_sequence_is_bounded(0));
        assert!(log_sequence_is_bounded(MAX_ATTEMPT_LOG_CHUNKS - 1));
        assert!(!log_sequence_is_bounded(MAX_ATTEMPT_LOG_CHUNKS));
        assert!(!log_sequence_is_bounded(-1));
    }

    #[test]
    fn protected_environment_approval_events_use_the_approval_category() {
        assert_eq!(audit_category_for_event("environment.approved"), "approval");
        assert_eq!(audit_category_for_event("approval.requested"), "approval");
    }
}
