//! PostgreSQL-backed controller truth and transaction boundaries.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Acquire, PgPool, Postgres, Transaction};
use uuid::Uuid;

pub mod authz;
mod scheduler;

pub use scheduler::{ClaimRequest, ClaimedAttempt, WaitReason};

pub(crate) const RESTORE_FENCE_LOCK_KEY: i64 = 0x4d_63_4c_6f_76_72_65_63;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentReconciliationDisposition {
    Retain,
    Cancel,
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
    pub idempotency_key: String,
    pub pipeline_digest: [u8; 32],
    pub node_key: String,
    pub required_capabilities: Vec<String>,
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
    Available,
    Missing,
    Corrupt,
}

impl ObjectStatus {
    fn as_str(self) -> &'static str {
        match self {
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
        let mut tx = self.tenant_transaction(organization_id).await?;
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
        if !matches!(local_phase, "finalizing" | "cancelling") || lease_seconds <= 0 {
            return Ok(false);
        }
        let mut tx = self.tenant_transaction(organization_id).await?;
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
        let resumable = match local_phase {
            "finalizing" => matches!(status.as_str(), "running" | "finalizing"),
            "cancelling" => status == "cancelling",
            _ => false,
        };
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

    /// Atomically acknowledges a fenced agent's cancellation outcome.
    ///
    /// A reconnect may arrive after its lease deadline, so cancellation
    /// completion is authorized by the current restore epoch, exact fence, and
    /// exact lease owner rather than by an unexpired lease. Response-loss
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
        let session_epoch =
            i64::try_from(session_epoch).map_err(|_| StoreError::InvalidAgentSession)?;
        let current_session = sqlx::query_scalar::<_, i64>(
            "SELECT session_epoch
             FROM agent_sessions
             WHERE agent_id = $1
             FOR UPDATE",
        )
        .bind(agent_id)
        .fetch_optional(&mut *tx)
        .await?;
        if current_session != Some(session_epoch) {
            tx.rollback().await?;
            return Ok(AgentCancellationDisposition::RetireStale);
        }
        let authority = sqlx::query_as::<_, (Uuid, Uuid, String)>(
            "SELECT n.id, n.build_id, a.status
             FROM attempts AS a
             JOIN nodes AS n
               ON n.id = a.node_id
              AND n.organization_id = a.organization_id
             JOIN builds AS b
               ON b.id = n.build_id
              AND b.organization_id = n.organization_id
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
               AND a.status IN ('cancelling', 'aborted', 'reconciliation_required')
               AND b.cancellation_requested_at IS NOT NULL
             FOR UPDATE OF a, n, b",
        )
        .bind(attempt_id)
        .bind(organization_id)
        .bind(fence)
        .bind(restore_epoch)
        .bind(agent_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((node_id, build_id, status)) = authority else {
            tx.rollback().await?;
            return Ok(AgentCancellationDisposition::RetireStale);
        };
        if status == "aborted" {
            tx.commit().await?;
            return Ok(AgentCancellationDisposition::Completed);
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
                        AgentCancellationOutcome::ReconciliationRequired => "unverifiable",
                    },
                    "uncertain_effects": uncertain_effects,
                }),
            )
            .await?;
            tx.commit().await?;
            return Ok(AgentCancellationDisposition::ReconciliationRequired);
        }

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
        .bind(json!({"reason": "agent_confirmed_cancellation"}))
        .execute(&mut *tx)
        .await?;
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
        append_event_and_outbox(
            &mut tx,
            organization_id,
            build_id,
            "attempt.cancellation_completed",
            json!({
                "attempt_id": attempt_id,
                "fence": fence,
                "agent_id": agent_id,
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(AgentCancellationDisposition::Completed)
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
        let mut tx = self.tenant_transaction(input.organization_id).await?;
        let build_id = Uuid::new_v4();
        let inserted = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO builds (
                 id, organization_id, project_id, idempotency_key,
                 pipeline_digest, status, priority
             )
             VALUES ($1, $2, $3, $4, $5, 'queued', $6)
             ON CONFLICT (project_id, idempotency_key) DO NOTHING
             RETURNING id",
        )
        .bind(build_id)
        .bind(input.organization_id)
        .bind(input.project_id)
        .bind(&input.idempotency_key)
        .bind(input.pipeline_digest.as_slice())
        .bind(input.priority)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(build_id) = inserted else {
            let existing = existing_admission(&mut tx, input.project_id, &input.idempotency_key)
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
                 required_capabilities, priority, execution_spec
             )
             VALUES ($1, $2, $3, $4, 'queued', $5, $6, $7)",
        )
        .bind(node_id)
        .bind(input.organization_id)
        .bind(build_id)
        .bind(&input.node_key)
        .bind(&input.required_capabilities)
        .bind(input.priority)
        .bind(&input.execution_spec)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO attempts (
                 id, organization_id, node_id, ordinal, status
             )
             VALUES ($1, $2, $3, 1, 'queued')",
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
        let mut tx = self.tenant_transaction(organization_id).await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!("mcloving.scheduler.{organization_id}"))
            .execute(&mut *tx)
            .await?;
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
        append_event_and_outbox(
            &mut tx,
            organization_id,
            build_id,
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

    /// Reads committed log chunks in deterministic sequence order.
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
             ORDER BY a.ordinal, l.sequence, l.stream, l.attempt_id",
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

    /// Commits a log chunk only for the exact live fenced attempt.
    pub async fn append_log(&self, chunk: &NewLogChunk<'_>) -> Result<bool, StoreError> {
        let digest: [u8; 32] = Sha256::digest(chunk.content).into();
        let mut tx = self.tenant_transaction(chunk.organization_id).await?;
        acquire_restore_fence_shared(&mut tx).await?;
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
        .bind(chunk.content)
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
        let mut tx = self.tenant_transaction(organization_id).await?;
        acquire_restore_fence_shared(&mut tx).await?;
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
        let mut tx = self.tenant_transaction(organization_id).await?;
        acquire_restore_fence_shared(&mut tx).await?;
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
        let attempt_exists = sqlx::query_scalar::<_, i64>(
            "SELECT a.restore_epoch
             FROM attempts AS a
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
        if attempt_exists.is_none() {
            tx.rollback().await?;
            return Ok(false);
        }
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
            if existing_status != status.as_str() {
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
            }
        } else {
            if status != EffectStatus::Prepared {
                tx.rollback().await?;
                return Ok(false);
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
        if max_attempts < 1 || reason.is_empty() || reason.len() > 1024 {
            return Ok(RetryDecision::Ineligible);
        }
        let mut tx = self.tenant_transaction(organization_id).await?;
        acquire_restore_fence_shared(&mut tx).await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!("mcloving.retry.{attempt_id}"))
            .execute(&mut *tx)
            .await?;
        let current = sqlx::query_as::<_, (Uuid, Uuid, i32, String, bool, bool)>(
            "SELECT n.id, n.build_id, a.ordinal, a.status,
                    b.cancellation_requested_at IS NOT NULL,
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
        let Some((node_id, build_id, ordinal, status, cancelled, reconciliation_terminalized)) =
            current
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
                append_event_and_outbox(
                    &mut tx,
                    organization_id,
                    build_id,
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
        sqlx::query(
            "INSERT INTO attempts (
                 id, organization_id, node_id, ordinal, status, retry_of,
                 restore_epoch
             )
             SELECT $1, $2, $3, $4, 'queued', $5, restore_epoch
             FROM controller_metadata
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
        sqlx::query(
            "UPDATE builds
             SET status = 'queued', completed_at = NULL
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(organization_id)
        .bind(build_id)
        .execute(&mut *tx)
        .await?;
        append_event_and_outbox(
            &mut tx,
            organization_id,
            build_id,
            "attempt.retry_scheduled",
            json!({
                "attempt_id": child_id,
                "retry_of": attempt_id,
                "ordinal": child_ordinal,
                "reason": reason,
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
        let updated = sqlx::query_scalar::<_, String>(
            "UPDATE attempt_objects
             SET status = $7, checked_at = clock_timestamp()
             WHERE organization_id = $1
               AND attempt_id = $2
               AND fence = $3
               AND kind = $4
               AND name = $5
               AND object_digest = $6
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
        if retention_seconds < 0 {
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
        let mut tx = self.tenant_transaction(organization_id).await?;
        acquire_restore_fence_shared(&mut tx).await?;
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
    project_id: Uuid,
    idempotency_key: &str,
) -> Result<Option<BuildAdmission>, sqlx::Error> {
    sqlx::query_as::<_, (Uuid, Uuid, Uuid)>(
        "SELECT b.id, n.id, a.id
         FROM builds AS b
         JOIN nodes AS n ON n.build_id = b.id AND n.organization_id = b.organization_id
         JOIN attempts AS a ON a.node_id = n.id AND a.organization_id = n.organization_id
         WHERE b.project_id = $1
           AND b.idempotency_key = $2
           AND a.ordinal = 1",
    )
    .bind(project_id)
    .bind(idempotency_key)
    .fetch_optional(&mut **tx)
    .await
    .map(|row| {
        row.map(|(build_id, node_id, attempt_id)| BuildAdmission {
            build_id,
            node_id,
            attempt_id,
            created: false,
        })
    })
}

async fn append_event_and_outbox(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    build_id: Uuid,
    kind: &str,
    payload: Value,
) -> Result<(), sqlx::Error> {
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
    .bind(payload)
    .execute(&mut **tx)
    .await?;
    Ok(())
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

fn parse_object_status(value: &str) -> Result<ObjectStatus, StoreError> {
    match value {
        "available" => Ok(ObjectStatus::Available),
        "missing" => Ok(ObjectStatus::Missing),
        "corrupt" => Ok(ObjectStatus::Corrupt),
        other => Err(StoreError::InvalidObjectRecord(format!(
            "unknown object status {other}"
        ))),
    }
}
