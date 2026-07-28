//! PostgreSQL-backed controller truth and transaction boundaries.

use serde_json::{Value, json};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

pub mod authz;
mod scheduler;

pub use scheduler::{ClaimRequest, ClaimedAttempt, WaitReason};

/// Schema installed by [`Store::migrate`].
pub const CONTROLLER_SCHEMA_V1: &str = include_str!("../migrations/0001_controller_truth.sql");
/// Tenant identity and row-level-security migration.
pub const TENANT_SECURITY_V2: &str = include_str!("../migrations/0002_tenant_security.sql");

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
}

/// Stable identifiers returned after admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAdmission {
    pub build_id: Uuid,
    pub node_id: Uuid,
    pub attempt_id: Uuid,
    pub created: bool,
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
                 required_capabilities, priority
             )
             VALUES ($1, $2, $3, $4, 'queued', $5, $6)",
        )
        .bind(node_id)
        .bind(input.organization_id)
        .bind(build_id)
        .bind(&input.node_key)
        .bind(&input.required_capabilities)
        .bind(input.priority)
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
               AND a.status IN ('accepted', 'running', 'finalizing')
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
