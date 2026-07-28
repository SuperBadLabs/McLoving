//! PostgreSQL-backed controller truth and transaction boundaries.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

pub mod authz;
mod scheduler;

pub use scheduler::{ClaimRequest, ClaimedAttempt, WaitReason};

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
    pub effect_key: String,
    pub effect_class: EffectClass,
    pub status: EffectStatus,
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
        tx.commit().await?;
        Ok(())
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
              AND a.ordinal = 1
             WHERE b.organization_id = $1
               AND b.project_id = $2
               AND b.id = $3
               AND b.status IN ('queued', 'running')
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
             ORDER BY l.sequence, l.stream",
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
        let inserted = sqlx::query_scalar::<_, i64>(
            "INSERT INTO attempt_log_chunks (
                 organization_id, attempt_id, fence, sequence,
                 stream, content, digest
             )
             SELECT $1, a.id, $3, $5, $6, $7, $8
             FROM attempts AS a
             WHERE a.organization_id = $1
               AND a.id = $2
               AND a.fence = $3
               AND a.lease_owner = $4
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
        agent_id: &str,
    ) -> Result<Option<AttemptExecution>, StoreError> {
        let mut tx = self.tenant_transaction(organization_id).await?;
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
               AND a.lease_owner = $4
               AND a.lease_expires_at > clock_timestamp()
               AND a.status IN ('offered', 'accepted', 'running', 'finalizing', 'cancelling')",
        )
        .bind(organization_id)
        .bind(attempt_id)
        .bind(fence)
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
        agent_id: &str,
    ) -> Result<bool, StoreError> {
        let mut tx = self.tenant_transaction(organization_id).await?;
        let row = sqlx::query_as::<_, (Uuid, Uuid, String)>(
            "SELECT n.id, n.build_id, a.status
             FROM attempts AS a
             JOIN nodes AS n
               ON n.id = a.node_id AND n.organization_id = a.organization_id
             WHERE a.organization_id = $1
               AND a.id = $2
               AND a.fence = $3
               AND a.lease_owner = $4
               AND a.lease_expires_at > clock_timestamp()
               AND a.status IN ('accepted', 'running')
             FOR UPDATE OF a, n",
        )
        .bind(organization_id)
        .bind(attempt_id)
        .bind(fence)
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
            json!({"attempt_id": attempt_id, "node_id": node_id, "fence": fence}),
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
        let attempt_exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (
                 SELECT 1 FROM attempts
                 WHERE organization_id = $1 AND id = $2 AND fence = $3
             )",
        )
        .bind(organization_id)
        .bind(attempt_id)
        .bind(fence)
        .fetch_one(&mut *tx)
        .await?;
        if !attempt_exists {
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

    /// Returns every effect that requires explicit operator reconciliation.
    pub async fn uncertain_effects(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<EffectCheckpoint>, StoreError> {
        let mut tx = self.tenant_transaction(organization_id).await?;
        let rows = sqlx::query_as::<_, (String, String, String, Vec<u8>)>(
            "SELECT effect_key, effect_class, status, payload_digest
             FROM attempt_effects
             WHERE organization_id = $1 AND status = 'uncertain'
             ORDER BY updated_at, attempt_id, effect_key",
        )
        .bind(organization_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.into_iter()
            .map(|(effect_key, effect_class, status, digest)| {
                Ok(EffectCheckpoint {
                    effect_key,
                    effect_class: parse_effect_class(&effect_class)?,
                    status: parse_effect_status(&status)?,
                    payload_digest: digest.try_into().map_err(|_| {
                        StoreError::InvalidEffectPayload(
                            "stored effect digest is not 32 bytes".to_owned(),
                        )
                    })?,
                })
            })
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
        if max_attempts < 1 || reason.is_empty() {
            return Ok(RetryDecision::Ineligible);
        }
        let mut tx = self.tenant_transaction(organization_id).await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!("mcloving.retry.{attempt_id}"))
            .execute(&mut *tx)
            .await?;
        let current = sqlx::query_as::<_, (Uuid, Uuid, i32, String, bool)>(
            "SELECT n.id, n.build_id, a.ordinal, a.status,
                    b.cancellation_requested_at IS NOT NULL
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
        let Some((node_id, build_id, ordinal, status, cancelled)) = current else {
            tx.rollback().await?;
            return Ok(RetryDecision::Ineligible);
        };
        if cancelled || !matches!(status.as_str(), "failed" | "reconciliation_required") {
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
            sqlx::query(
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
            append_event_and_outbox(
                &mut tx,
                organization_id,
                build_id,
                "attempt.dead_lettered",
                payload,
            )
            .await?;
            tx.commit().await?;
            return Ok(RetryDecision::DeadLettered);
        }
        let child_id = Uuid::new_v4();
        let child_ordinal = ordinal + 1;
        sqlx::query(
            "INSERT INTO attempts (
                 id, organization_id, node_id, ordinal, status, retry_of
             )
             VALUES ($1, $2, $3, $4, 'queued', $5)",
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
        let inserted = sqlx::query_scalar::<_, String>(
            "INSERT INTO attempt_objects (
                 organization_id, attempt_id, fence, kind, name,
                 object_digest, bytes
             )
             SELECT $1, a.id, $3, $5, $6, $7, $8
             FROM attempts AS a
             WHERE a.organization_id = $1
               AND a.id = $2
               AND a.fence = $3
               AND a.lease_owner = $4
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
        .bind(agent_id)
        .bind(kind.as_str())
        .bind(name)
        .bind(digest.as_slice())
        .bind(bytes)
        .fetch_optional(&mut *tx)
        .await?;
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

    /// Accepts exactly one terminal publication for the current attempt fence.
    ///
    /// The attempt, node, build, event, and outbox mutation share a transaction.
    /// A stale or losing concurrent publisher observes `false`.
    pub async fn finalize_attempt(
        &self,
        organization_id: Uuid,
        attempt_id: Uuid,
        fence: i64,
        agent_id: &str,
        outcome: TerminalOutcome,
        summary: Value,
    ) -> Result<bool, StoreError> {
        let mut tx = self.tenant_transaction(organization_id).await?;
        let row = sqlx::query_as::<_, (Uuid, Uuid)>(
            "UPDATE attempts AS a
             SET status = $5,
                 terminal_summary = $6,
                 completed_at = clock_timestamp(),
                 lease_expires_at = NULL
             FROM nodes AS n
             WHERE a.id = $1
               AND a.organization_id = $2
               AND a.fence = $3
               AND a.lease_owner = $4
               AND a.lease_expires_at > clock_timestamp()
               AND a.status IN ('accepted', 'running', 'finalizing', 'cancelling')
               AND n.id = a.node_id
               AND n.organization_id = a.organization_id
             RETURNING n.id, n.build_id",
        )
        .bind(attempt_id)
        .bind(organization_id)
        .bind(fence)
        .bind(agent_id)
        .bind(outcome.as_str())
        .bind(&summary)
        .fetch_optional(&mut *tx)
        .await?;

        let Some((node_id, build_id)) = row else {
            tx.rollback().await?;
            return Ok(false);
        };

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
