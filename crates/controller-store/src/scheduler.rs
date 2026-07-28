use std::collections::BTreeSet;

use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

use crate::{Store, StoreError, append_event_and_outbox};

/// Inputs to one deterministic scheduler claim.
#[derive(Clone, Debug)]
pub struct ClaimRequest {
    pub organization_id: Uuid,
    pub scheduler_id: String,
    pub agent_id: String,
    pub capabilities: Vec<String>,
    pub lease_seconds: i32,
    /// Changes the deterministic tie-break among otherwise equal candidates.
    pub fairness_seed: i64,
}

/// A fenced offer created by the scheduler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimedAttempt {
    pub build_id: Uuid,
    pub node_id: Uuid,
    pub attempt_id: Uuid,
    pub fence: i64,
    pub agent_id: String,
}

/// Stable explanation when the scheduler cannot claim work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WaitReason {
    Ready,
    NoQueuedWork,
    CapabilityMismatch {
        required: BTreeSet<String>,
        missing: BTreeSet<String>,
    },
}

impl Store {
    /// Claims at most one compatible node and creates a new fencing epoch.
    ///
    /// The transaction-scoped advisory lock deliberately implements the Wave 1
    /// single-node scheduler. Row locking remains `SKIP LOCKED` so this query
    /// can evolve into active-active claims without changing candidate state.
    pub async fn claim_next(
        &self,
        request: &ClaimRequest,
    ) -> Result<Option<ClaimedAttempt>, StoreError> {
        if request.lease_seconds <= 0 {
            return Ok(None);
        }
        let mut tx = self.pool().begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)")
            .bind(format!("mcloving.scheduler.{}", request.organization_id))
            .execute(&mut *tx)
            .await?;

        let candidate = sqlx::query(
            "SELECT n.id AS node_id, n.build_id, a.id AS attempt_id
             FROM nodes AS n
             JOIN attempts AS a
               ON a.node_id = n.id
              AND a.organization_id = n.organization_id
              AND a.status = 'queued'
             WHERE n.organization_id = $1
               AND n.status = 'queued'
               AND n.required_capabilities <@ $2::text[]
             ORDER BY
               n.priority DESC,
               n.queued_at ASC,
               hashtextextended(n.id::text, $3) ASC,
               n.id ASC
             LIMIT 1
             FOR UPDATE OF n, a SKIP LOCKED",
        )
        .bind(request.organization_id)
        .bind(&request.capabilities)
        .bind(request.fairness_seed)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(candidate) = candidate else {
            tx.rollback().await?;
            return Ok(None);
        };
        let node_id: Uuid = candidate.try_get("node_id")?;
        let build_id: Uuid = candidate.try_get("build_id")?;
        let attempt_id: Uuid = candidate.try_get("attempt_id")?;

        let fence = sqlx::query_scalar::<_, i64>(
            "UPDATE attempts
             SET status = 'offered',
                 fence = fence + 1,
                 lease_owner = $3,
                 lease_expires_at =
                   clock_timestamp() + make_interval(secs => $4)
             WHERE id = $1 AND organization_id = $2
             RETURNING fence",
        )
        .bind(attempt_id)
        .bind(request.organization_id)
        .bind(&request.agent_id)
        .bind(f64::from(request.lease_seconds))
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE nodes SET status = 'offered'
             WHERE id = $1 AND organization_id = $2",
        )
        .bind(node_id)
        .bind(request.organization_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE builds SET status = 'running'
             WHERE id = $1 AND organization_id = $2 AND status = 'queued'",
        )
        .bind(build_id)
        .bind(request.organization_id)
        .execute(&mut *tx)
        .await?;
        append_event_and_outbox(
            &mut tx,
            request.organization_id,
            build_id,
            "attempt.offered",
            json!({
                "attempt_id": attempt_id,
                "node_id": node_id,
                "agent_id": request.agent_id,
                "scheduler_id": request.scheduler_id,
                "fence": fence,
            }),
        )
        .await?;
        tx.commit().await?;

        Ok(Some(ClaimedAttempt {
            build_id,
            node_id,
            attempt_id,
            fence,
            agent_id: request.agent_id.clone(),
        }))
    }

    /// Requeues one expired offer without changing its fence.
    ///
    /// The following claim increments the fence, making the previous agent
    /// publication stale before new work is offered.
    pub async fn requeue_one_expired(&self, organization_id: Uuid) -> Result<bool, StoreError> {
        let mut tx = self.pool().begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)")
            .bind(format!("mcloving.scheduler.{organization_id}"))
            .execute(&mut *tx)
            .await?;
        let expired = sqlx::query(
            "SELECT a.id AS attempt_id, n.id AS node_id, n.build_id
             FROM attempts AS a
             JOIN nodes AS n
               ON n.id = a.node_id
              AND n.organization_id = a.organization_id
             WHERE a.organization_id = $1
               AND a.status = 'offered'
               AND a.lease_expires_at <= clock_timestamp()
             ORDER BY a.lease_expires_at, a.id
             LIMIT 1
             FOR UPDATE OF a, n SKIP LOCKED",
        )
        .bind(organization_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(expired) = expired else {
            tx.rollback().await?;
            return Ok(false);
        };
        let attempt_id: Uuid = expired.try_get("attempt_id")?;
        let node_id: Uuid = expired.try_get("node_id")?;
        let build_id: Uuid = expired.try_get("build_id")?;
        sqlx::query(
            "UPDATE attempts
             SET status = 'queued', lease_owner = NULL, lease_expires_at = NULL
             WHERE id = $1 AND organization_id = $2",
        )
        .bind(attempt_id)
        .bind(organization_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE nodes SET status = 'queued'
             WHERE id = $1 AND organization_id = $2",
        )
        .bind(node_id)
        .bind(organization_id)
        .execute(&mut *tx)
        .await?;
        append_event_and_outbox(
            &mut tx,
            organization_id,
            build_id,
            "attempt.lease_expired",
            json!({"attempt_id": attempt_id, "node_id": node_id}),
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Explains the first scheduling boundary without mutating queue state.
    pub async fn explain_wait(
        &self,
        organization_id: Uuid,
        capabilities: &[String],
    ) -> Result<WaitReason, StoreError> {
        let compatible = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (
                 SELECT 1 FROM nodes
                 WHERE organization_id = $1
                   AND status = 'queued'
                   AND required_capabilities <@ $2::text[]
             )",
        )
        .bind(organization_id)
        .bind(capabilities)
        .fetch_one(self.pool())
        .await?;
        if compatible {
            return Ok(WaitReason::Ready);
        }

        let required = sqlx::query_scalar::<_, Vec<String>>(
            "SELECT required_capabilities
             FROM nodes
             WHERE organization_id = $1 AND status = 'queued'
             ORDER BY priority DESC, queued_at, id
             LIMIT 1",
        )
        .bind(organization_id)
        .fetch_optional(self.pool())
        .await?;
        let Some(required) = required else {
            return Ok(WaitReason::NoQueuedWork);
        };
        let required = required.into_iter().collect::<BTreeSet<_>>();
        let offered = capabilities.iter().cloned().collect::<BTreeSet<_>>();
        let missing = required.difference(&offered).cloned().collect();
        Ok(WaitReason::CapabilityMismatch { required, missing })
    }
}
