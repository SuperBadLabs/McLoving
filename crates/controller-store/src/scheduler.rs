use std::collections::BTreeSet;

use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

use crate::{
    Store, StoreError, acquire_org_scheduler_lock, acquire_restore_fence_shared,
    append_event_and_outbox,
};

/// Inputs to one deterministic scheduler claim.
#[derive(Clone, Debug)]
pub struct ClaimRequest {
    pub organization_id: Uuid,
    pub scheduler_id: String,
    pub agent_id: String,
    pub capabilities: Vec<String>,
    /// Authenticated trust pool from the agent's certificate binding.
    pub trust_pool: String,
    pub lease_seconds: i32,
    /// Changes the deterministic tie-break among otherwise equal candidates.
    pub fairness_seed: i64,
}

/// A fenced offer created by the scheduler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimedAttempt {
    pub organization_id: Uuid,
    pub build_id: Uuid,
    pub node_id: Uuid,
    pub attempt_id: Uuid,
    pub fence: i64,
    pub restore_epoch: i64,
    pub agent_id: String,
}

/// Lease state observed under the accepting transaction's row lock, so the
/// accept receipt can answer what the immediate post-accept renewal used to:
/// whether a cancellation had already committed for this attempt's build or
/// node when acceptance was recorded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptedOffer {
    pub cancellation_requested: bool,
}

/// Outcome of one fenced lease-renewal request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseRenewalDisposition {
    /// The lease was extended under current authority.
    Renewed { cancellation_requested: bool },
    /// The attempt is already terminal; an exact replay's renewal is an
    /// acknowledged no-op that extends nothing.
    TerminalNoOp,
    /// The renewal was refused; the cause matches the recorded
    /// `attempt.lease_renewal_rejected` event.
    Rejected { cause: &'static str },
}

/// Stable explanation when the scheduler cannot claim work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WaitReason {
    Ready,
    NoQueuedWork,
    TrustPoolMismatch {
        required: String,
        offered: String,
    },
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
        self.claim_next_with_session(request, None).await
    }

    /// Production claim path: the authenticated epoch is locked through the
    /// same transaction that creates fenced lease authority.
    pub async fn claim_next_in_session(
        &self,
        request: &ClaimRequest,
        session_epoch: u64,
    ) -> Result<Option<ClaimedAttempt>, StoreError> {
        self.claim_next_with_session(request, Some(session_epoch))
            .await
    }

    async fn claim_next_with_session(
        &self,
        request: &ClaimRequest,
        session_epoch: Option<u64>,
    ) -> Result<Option<ClaimedAttempt>, StoreError> {
        if request.lease_seconds <= 0 || request.trust_pool.trim().is_empty() {
            return Ok(None);
        }
        let mut tx = self.tenant_transaction(request.organization_id).await?;
        if let Some(session_epoch) = session_epoch
            && !Self::lock_agent_session(&mut tx, &request.agent_id, session_epoch).await?
        {
            tx.rollback().await?;
            return Ok(None);
        }
        acquire_org_scheduler_lock(&mut tx, request.organization_id).await?;
        acquire_restore_fence_shared(&mut tx).await?;
        let restore_epoch = sqlx::query_scalar::<_, i64>(
            "SELECT restore_epoch
             FROM controller_metadata
             WHERE singleton",
        )
        .fetch_one(&mut *tx)
        .await?;

        let candidate = sqlx::query(
            "SELECT n.id AS node_id, n.build_id, a.id AS attempt_id
             FROM nodes AS n
             JOIN builds AS b
               ON b.id = n.build_id
              AND b.organization_id = n.organization_id
             JOIN attempts AS a
               ON a.node_id = n.id
              AND a.organization_id = n.organization_id
              AND a.status = 'queued'
             JOIN pipeline_definitions AS d
               ON d.organization_id = b.organization_id
              AND d.project_id = b.project_id
              AND d.pipeline_id = b.pipeline_id
              AND d.operational_generation = b.pipeline_operational_generation
             JOIN pipeline_operational_state_history AS h
               ON h.organization_id = d.organization_id
              AND h.pipeline_id = d.pipeline_id
              AND h.generation = d.operational_generation
              AND h.state = 'enabled'
             WHERE n.organization_id = $1
               AND n.status = 'queued'
               AND (
                   b.status = 'queued'
                   OR (b.dag_mode AND b.status = 'running')
               )
               AND b.cancellation_requested_at IS NULL
               AND n.cancellation_requested_at IS NULL
               AND n.required_capabilities <@ $2::text[]
               AND n.required_trust_pool = $4
               AND NOT EXISTS (
                   SELECT 1
                   FROM node_dependencies AS dependency
                   JOIN nodes AS parent
                     ON parent.id = dependency.parent_node_id
                    AND parent.organization_id = dependency.organization_id
                    AND parent.build_id = dependency.build_id
                   WHERE dependency.organization_id = n.organization_id
                     AND dependency.build_id = n.build_id
                     AND dependency.child_node_id = n.id
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
               )
             ORDER BY
               n.priority DESC,
               n.queued_at ASC,
               hashtextextended(n.id::text, $3) ASC,
               n.id ASC
             LIMIT 1
             FOR UPDATE OF b, n, a SKIP LOCKED",
        )
        .bind(request.organization_id)
        .bind(&request.capabilities)
        .bind(request.fairness_seed)
        .bind(&request.trust_pool)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(candidate) = candidate else {
            tx.rollback().await?;
            return Ok(None);
        };
        let node_id: Uuid = candidate.try_get("node_id")?;
        let build_id: Uuid = candidate.try_get("build_id")?;
        let attempt_id: Uuid = candidate.try_get("attempt_id")?;
        if let Err(error) =
            crate::lock_enabled_build_pipeline(&mut tx, request.organization_id, build_id).await
        {
            tx.rollback().await?;
            return match error {
                StoreError::PipelineDisabled { .. } | StoreError::PipelineStateConflict(_) => {
                    Ok(None)
                }
                other => Err(other),
            };
        }

        let fence = sqlx::query_scalar::<_, i64>(
            "UPDATE attempts
             SET status = 'offered',
                 fence = fence + 1,
                 lease_owner = $3,
                 lease_expires_at =
                   clock_timestamp() + make_interval(secs => $4),
                 restore_epoch = $5
             WHERE id = $1 AND organization_id = $2
             RETURNING fence",
        )
        .bind(attempt_id)
        .bind(request.organization_id)
        .bind(&request.agent_id)
        .bind(f64::from(request.lease_seconds))
        .bind(restore_epoch)
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
                "trust_pool": request.trust_pool,
                "scheduler_id": request.scheduler_id,
                "fence": fence,
                "restore_epoch": restore_epoch,
            }),
        )
        .await?;
        tx.commit().await?;

        Ok(Some(ClaimedAttempt {
            organization_id: request.organization_id,
            build_id,
            node_id,
            attempt_id,
            fence,
            restore_epoch,
            agent_id: request.agent_id.clone(),
        }))
    }

    /// Accepts a live offer only from its fenced lease owner.
    pub async fn accept_offer(
        &self,
        organization_id: Uuid,
        attempt_id: Uuid,
        fence: i64,
        restore_epoch: i64,
        agent_id: &str,
    ) -> Result<bool, StoreError> {
        Ok(self
            .accept_offer_with_session(
                organization_id,
                attempt_id,
                fence,
                restore_epoch,
                agent_id,
                None,
            )
            .await?
            .is_some())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn accept_offer_in_session(
        &self,
        organization_id: Uuid,
        attempt_id: Uuid,
        fence: i64,
        restore_epoch: i64,
        agent_id: &str,
        session_epoch: u64,
    ) -> Result<Option<AcceptedOffer>, StoreError> {
        self.accept_offer_with_session(
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
    async fn accept_offer_with_session(
        &self,
        organization_id: Uuid,
        attempt_id: Uuid,
        fence: i64,
        restore_epoch: i64,
        agent_id: &str,
        session_epoch: Option<u64>,
    ) -> Result<Option<AcceptedOffer>, StoreError> {
        let mut tx = self.tenant_transaction(organization_id).await?;
        if let Some(session_epoch) = session_epoch
            && !Self::lock_agent_session(&mut tx, agent_id, session_epoch).await?
        {
            tx.rollback().await?;
            return Ok(None);
        }
        acquire_org_scheduler_lock(&mut tx, organization_id).await?;
        acquire_restore_fence_shared(&mut tx).await?;
        let accepted = sqlx::query_as::<_, (Uuid, Uuid, String, bool)>(
            "SELECT n.id, n.build_id, a.status,
                    b.cancellation_requested_at IS NOT NULL
                    OR n.cancellation_requested_at IS NOT NULL
             FROM attempts AS a
             JOIN nodes AS n
               ON n.id = a.node_id AND n.organization_id = a.organization_id
             JOIN builds AS b
               ON b.id = n.build_id AND b.organization_id = n.organization_id
             WHERE a.id = $1
               AND a.organization_id = $2
               AND a.fence = $3
               AND a.restore_epoch = $4
               AND a.restore_epoch = (
                   SELECT restore_epoch FROM controller_metadata WHERE singleton
               )
               AND a.lease_owner = $5
               AND a.lease_expires_at > clock_timestamp()
               AND a.status IN ('offered', 'accepted', 'running', 'cancelling')
             FOR UPDATE OF a, n",
        )
        .bind(attempt_id)
        .bind(organization_id)
        .bind(fence)
        .bind(restore_epoch)
        .bind(agent_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((node_id, build_id, status, cancellation_requested)) = accepted else {
            tx.rollback().await?;
            return Ok(None);
        };
        // An attempt already routed into cancellation is a requested
        // cancellation even before the build or node stamp is visible here.
        let accepted_offer = AcceptedOffer {
            cancellation_requested: cancellation_requested || status == "cancelling",
        };
        if let Err(error) =
            crate::lock_enabled_build_pipeline(&mut tx, organization_id, build_id).await
        {
            tx.rollback().await?;
            return match error {
                StoreError::PipelineDisabled { .. } | StoreError::PipelineStateConflict(_) => {
                    Ok(None)
                }
                other => Err(other),
            };
        }
        if status != "offered" {
            tx.commit().await?;
            return Ok(Some(accepted_offer));
        }
        sqlx::query(
            "UPDATE attempts SET status = 'accepted'
             WHERE id = $1 AND organization_id = $2",
        )
        .bind(attempt_id)
        .bind(organization_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE nodes SET status = 'running'
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
            "attempt.accepted",
            json!({
                "attempt_id": attempt_id,
                "node_id": node_id,
                "agent_id": agent_id,
                "fence": fence,
                "restore_epoch": restore_epoch,
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(Some(accepted_offer))
    }

    /// Renews one exact live lease and returns its cancellation state.
    pub async fn renew_attempt_lease(
        &self,
        organization_id: Uuid,
        attempt_id: Uuid,
        fence: i64,
        restore_epoch: i64,
        agent_id: &str,
        lease_seconds: i32,
    ) -> Result<Option<bool>, StoreError> {
        Ok(
            match self
                .renew_attempt_lease_with_session(
                    organization_id,
                    attempt_id,
                    fence,
                    restore_epoch,
                    agent_id,
                    None,
                    lease_seconds,
                )
                .await?
            {
                LeaseRenewalDisposition::Renewed {
                    cancellation_requested,
                } => Some(cancellation_requested),
                LeaseRenewalDisposition::TerminalNoOp => Some(false),
                LeaseRenewalDisposition::Rejected { .. } => None,
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn renew_attempt_lease_in_session(
        &self,
        organization_id: Uuid,
        attempt_id: Uuid,
        fence: i64,
        restore_epoch: i64,
        agent_id: &str,
        session_epoch: u64,
        lease_seconds: i32,
    ) -> Result<LeaseRenewalDisposition, StoreError> {
        self.renew_attempt_lease_with_session(
            organization_id,
            attempt_id,
            fence,
            restore_epoch,
            agent_id,
            Some(session_epoch),
            lease_seconds,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn renew_attempt_lease_with_session(
        &self,
        organization_id: Uuid,
        attempt_id: Uuid,
        fence: i64,
        restore_epoch: i64,
        agent_id: &str,
        session_epoch: Option<u64>,
        lease_seconds: i32,
    ) -> Result<LeaseRenewalDisposition, StoreError> {
        if lease_seconds <= 0 {
            return Ok(LeaseRenewalDisposition::Rejected {
                cause: "invalid_lease_window",
            });
        }
        let mut tx = self.tenant_transaction(organization_id).await?;
        if let Some(session_epoch) = session_epoch
            && !Self::lock_agent_session(&mut tx, agent_id, session_epoch).await?
        {
            // Naming the refusal appends to build_events and the outbox, so
            // this branch is a multi-table writer like the renewal below it and
            // takes the same canonical order. The shared restore fence
            // additionally makes the event serialize against restore
            // activation, which holds it exclusively while rewriting authority.
            acquire_org_scheduler_lock(&mut tx, organization_id).await?;
            acquire_restore_fence_shared(&mut tx).await?;
            record_lease_renewal_rejection(
                &mut tx,
                organization_id,
                attempt_id,
                fence,
                agent_id,
                "agent_session_stale",
            )
            .await?;
            tx.commit().await?;
            return Ok(LeaseRenewalDisposition::Rejected {
                cause: "agent_session_stale",
            });
        }
        // Renewal stopped being a single-table writer when the operational
        // fence arrived: it locks the pipeline operational-state row before
        // updating the attempt, so it must follow the canonical order like
        // every other multi-table path or it deadlocks against DAG advance
        // and cancellation, which lock builds/nodes/attempts under this lock.
        acquire_org_scheduler_lock(&mut tx, organization_id).await?;
        acquire_restore_fence_shared(&mut tx).await?;
        let active_build = sqlx::query_scalar::<_, Uuid>(
            "SELECT n.build_id
             FROM attempts AS a
             JOIN nodes AS n
               ON n.id = a.node_id AND n.organization_id = a.organization_id
             WHERE a.organization_id = $1
               AND a.id = $2
               AND a.fence = $3
               AND a.restore_epoch = $4
               AND a.lease_owner = $5
               AND a.status IN ('accepted', 'running', 'finalizing', 'cancelling')",
        )
        .bind(organization_id)
        .bind(attempt_id)
        .bind(fence)
        .bind(restore_epoch)
        .bind(agent_id)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(build_id) = active_build
            && let Err(error) =
                crate::lock_enabled_build_pipeline(&mut tx, organization_id, build_id).await
        {
            tx.rollback().await?;
            return match error {
                StoreError::PipelineDisabled { .. } | StoreError::PipelineStateConflict(_) => {
                    Ok(LeaseRenewalDisposition::Renewed {
                        cancellation_requested: true,
                    })
                }
                other => Err(other),
            };
        }
        let cancellation_requested = sqlx::query_scalar::<_, bool>(
            "UPDATE attempts AS a
             SET lease_expires_at =
                   clock_timestamp() + make_interval(secs => $6)
             FROM nodes AS n, builds AS b
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
               AND n.id = a.node_id
               AND n.organization_id = a.organization_id
               AND b.id = n.build_id
               AND b.organization_id = n.organization_id
             RETURNING
                 b.cancellation_requested_at IS NOT NULL
                 OR n.cancellation_requested_at IS NOT NULL",
        )
        .bind(organization_id)
        .bind(attempt_id)
        .bind(fence)
        .bind(restore_epoch)
        .bind(agent_id)
        .bind(f64::from(lease_seconds))
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(cancellation_requested) = cancellation_requested {
            tx.commit().await?;
            return Ok(LeaseRenewalDisposition::Renewed {
                cancellation_requested,
            });
        }
        // A response-loss replay can observe an already-terminal attempt.
        // Its exact terminal publication is idempotent and needs no renewed
        // lease, so acknowledge the renewal as a no-op instead of revoking the
        // replay's authority-loss token.
        let terminal = sqlx::query_scalar::<_, bool>(
            "SELECT true
             FROM attempts AS a
             WHERE a.organization_id = $1
               AND a.id = $2
               AND a.fence = $3
               AND a.restore_epoch = $4
               AND a.lease_owner = $5
               AND a.status IN ('succeeded', 'failed', 'aborted')
               AND a.restore_epoch = (
                   SELECT restore_epoch FROM controller_metadata WHERE singleton
               )",
        )
        .bind(organization_id)
        .bind(attempt_id)
        .bind(fence)
        .bind(restore_epoch)
        .bind(agent_id)
        .fetch_optional(&mut *tx)
        .await?;
        if terminal.is_some() {
            tx.commit().await?;
            return Ok(LeaseRenewalDisposition::TerminalNoOp);
        }
        record_lease_renewal_rejection(
            &mut tx,
            organization_id,
            attempt_id,
            fence,
            agent_id,
            "lease_not_current",
        )
        .await?;
        tx.commit().await?;
        Ok(LeaseRenewalDisposition::Rejected {
            cause: "lease_not_current",
        })
    }

    /// Resolves one expired active lease without changing its fence.
    ///
    /// Safe work returns to the queue so the following claim increments the
    /// fence. An unresolved non-idempotent effect is instead made uncertain
    /// and routes the attempt through explicit reconciliation.
    pub async fn requeue_one_expired(&self, organization_id: Uuid) -> Result<bool, StoreError> {
        let mut tx = self.tenant_transaction(organization_id).await?;
        // Every work poll runs this pass, and in a healthy build nothing is
        // ever expired — yet the pass used to take the exclusive org
        // scheduler lock just to find that out, contending with the very
        // lifecycle transactions it polls on behalf of. Probe first with a
        // plain snapshot read (no row or advisory locks, so the canonical
        // lock order is untouched); only a possible candidate pays for the
        // locked pass. A candidate appearing after the probe is caught by
        // the next poll's pass, exactly as one appearing after the locked
        // scan would have been.
        let candidate_may_exist = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(
                 SELECT 1
                 FROM attempts
                 WHERE organization_id = $1
                   AND status IN (
                       'offered', 'accepted', 'running', 'finalizing', 'cancelling'
                   )
                   AND lease_expires_at <= clock_timestamp()
             )",
        )
        .bind(organization_id)
        .fetch_one(&mut *tx)
        .await?;
        if !candidate_may_exist {
            tx.rollback().await?;
            return Ok(false);
        }
        acquire_org_scheduler_lock(&mut tx, organization_id).await?;
        acquire_restore_fence_shared(&mut tx).await?;
        let expired = sqlx::query(
            "SELECT a.id AS attempt_id, a.fence, n.id AS node_id, n.build_id,
                    (
                        n.cancellation_requested_at IS NOT NULL
                        OR b.cancellation_requested_at IS NOT NULL
                    ) AS cancellation_requested
             FROM attempts AS a
             JOIN nodes AS n
               ON n.id = a.node_id
              AND n.organization_id = a.organization_id
             JOIN builds AS b
               ON b.id = n.build_id
              AND b.organization_id = n.organization_id
             WHERE a.organization_id = $1
               AND a.status IN (
                   'offered', 'accepted', 'running', 'finalizing', 'cancelling'
               )
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
        let fence: i64 = expired.try_get("fence")?;
        let node_id: Uuid = expired.try_get("node_id")?;
        let build_id: Uuid = expired.try_get("build_id")?;
        let cancellation_requested: bool = expired.try_get("cancellation_requested")?;
        let pipeline_enabled =
            match crate::lock_enabled_build_pipeline(&mut tx, organization_id, build_id).await {
                Ok(_) => true,
                Err(StoreError::PipelineDisabled { .. } | StoreError::PipelineStateConflict(_)) => {
                    false
                }
                Err(error) => return Err(error),
            };
        let protected_effects = sqlx::query_as::<_, (String, String)>(
            "SELECT effect_key, status
             FROM attempt_effects
             WHERE organization_id = $1
               AND attempt_id = $2
               AND fence = $3
               AND (
                   effect_class = 'non_idempotent'
                   OR payload ->> 'schema_version' =
                      'mcloving.controller-effect-prepared/v1'
               )
               AND status IN (
                   'prepared', 'applied', 'confirmed', 'uncertain', 'release_pending'
               )
             ORDER BY effect_key
             FOR UPDATE",
        )
        .bind(organization_id)
        .bind(attempt_id)
        .bind(fence)
        .fetch_all(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE attempt_effects
             SET status = 'uncertain', updated_at = clock_timestamp()
             WHERE organization_id = $1
               AND attempt_id = $2
               AND fence = $3
               AND (
                   effect_class = 'non_idempotent'
                   OR payload ->> 'schema_version' =
                      'mcloving.controller-effect-prepared/v1'
               )
               AND status IN ('prepared', 'applied')",
        )
        .bind(organization_id)
        .bind(attempt_id)
        .bind(fence)
        .execute(&mut *tx)
        .await?;
        let requires_reconciliation = !protected_effects.is_empty();
        let uncertain_effects = protected_effects
            .iter()
            .filter(|(_, status)| status != "confirmed")
            .count();
        let confirmed_effects = protected_effects.len() - uncertain_effects;
        if (cancellation_requested || !pipeline_enabled) && !requires_reconciliation {
            let terminal_reason = if pipeline_enabled {
                "cancellation_lease_expired"
            } else {
                "pipeline_operational_generation_fenced"
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
            if !crate::dag::advance_dag_after_attempt(
                &mut tx,
                organization_id,
                build_id,
                node_id,
                attempt_id,
                crate::TerminalOutcome::Aborted,
            )
            .await?
            {
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
                if pipeline_enabled {
                    "attempt.cancellation_lease_expired"
                } else {
                    "attempt.pipeline_generation_fenced"
                },
                json!({
                    "attempt_id": attempt_id,
                    "node_id": node_id,
                    "fence": fence,
                }),
            )
            .await?;
            tx.commit().await?;
            return Ok(true);
        }
        let next_status = if requires_reconciliation {
            "reconciliation_required"
        } else {
            "queued"
        };
        sqlx::query(
            "UPDATE attempts
             SET status = $3, lease_owner = NULL, lease_expires_at = NULL
             WHERE id = $1 AND organization_id = $2",
        )
        .bind(attempt_id)
        .bind(organization_id)
        .bind(next_status)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE nodes SET status = $3
             WHERE id = $1 AND organization_id = $2",
        )
        .bind(node_id)
        .bind(organization_id)
        .bind(next_status)
        .execute(&mut *tx)
        .await?;
        if requires_reconciliation {
            sqlx::query(
                "UPDATE builds
                 SET status = 'reconciliation_required', completed_at = NULL
                 WHERE id = $1 AND organization_id = $2",
            )
            .bind(build_id)
            .bind(organization_id)
            .execute(&mut *tx)
            .await?;
        } else {
            sqlx::query(
                "UPDATE builds SET status = 'queued'
                 WHERE id = $1
                   AND organization_id = $2
                   AND status = 'running'
                   AND cancellation_requested_at IS NULL",
            )
            .bind(build_id)
            .bind(organization_id)
            .execute(&mut *tx)
            .await?;
        }
        let event_kind = if requires_reconciliation {
            "attempt.lease_expired_reconciliation_required"
        } else {
            "attempt.lease_expired"
        };
        append_event_and_outbox(
            &mut tx,
            organization_id,
            build_id,
            event_kind,
            json!({
                "attempt_id": attempt_id,
                "node_id": node_id,
                "fence": fence,
                "uncertain_effects": uncertain_effects,
                "confirmed_effects": confirmed_effects,
            }),
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
        trust_pool: &str,
    ) -> Result<WaitReason, StoreError> {
        if trust_pool.trim().is_empty() || trust_pool.trim() != trust_pool {
            return Err(StoreError::InvalidTrustPool);
        }
        let mut tx = self.tenant_transaction(organization_id).await?;
        let compatible = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (
                 SELECT 1
                 FROM nodes AS n
                 JOIN builds AS b
                   ON b.id = n.build_id
                  AND b.organization_id = n.organization_id
                 JOIN pipeline_definitions AS d
                   ON d.organization_id = b.organization_id
                  AND d.project_id = b.project_id
                  AND d.pipeline_id = b.pipeline_id
                  AND d.operational_generation = b.pipeline_operational_generation
                 JOIN pipeline_operational_state_history AS h
                   ON h.organization_id = d.organization_id
                  AND h.pipeline_id = d.pipeline_id
                  AND h.generation = d.operational_generation
                  AND h.state = 'enabled'
                 WHERE n.organization_id = $1
                   AND n.status = 'queued'
                   AND (
                       b.status = 'queued'
                       OR (b.dag_mode AND b.status = 'running')
                   )
                   AND n.required_capabilities <@ $2::text[]
                   AND n.required_trust_pool = $3
                   AND n.cancellation_requested_at IS NULL
                   AND b.cancellation_requested_at IS NULL
                   AND NOT EXISTS (
                       SELECT 1
                       FROM node_dependencies AS dependency
                       JOIN nodes AS parent
                         ON parent.id = dependency.parent_node_id
                        AND parent.organization_id = dependency.organization_id
                        AND parent.build_id = dependency.build_id
                       WHERE dependency.organization_id = n.organization_id
                         AND dependency.build_id = n.build_id
                         AND dependency.child_node_id = n.id
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
                   )
             )",
        )
        .bind(organization_id)
        .bind(capabilities)
        .bind(trust_pool)
        .fetch_one(&mut *tx)
        .await?;
        if compatible {
            tx.commit().await?;
            return Ok(WaitReason::Ready);
        }

        let required = sqlx::query_as::<_, (Vec<String>, String)>(
            "SELECT n.required_capabilities, n.required_trust_pool
             FROM nodes AS n
             JOIN builds AS b
               ON b.id = n.build_id
              AND b.organization_id = n.organization_id
             JOIN pipeline_definitions AS d
               ON d.organization_id = b.organization_id
              AND d.project_id = b.project_id
              AND d.pipeline_id = b.pipeline_id
              AND d.operational_generation = b.pipeline_operational_generation
             JOIN pipeline_operational_state_history AS h
               ON h.organization_id = d.organization_id
              AND h.pipeline_id = d.pipeline_id
              AND h.generation = d.operational_generation
              AND h.state = 'enabled'
             WHERE n.organization_id = $1
               AND n.status = 'queued'
               AND (
                   b.status = 'queued'
                   OR (b.dag_mode AND b.status = 'running')
               )
               AND n.cancellation_requested_at IS NULL
               AND b.cancellation_requested_at IS NULL
               AND NOT EXISTS (
                   SELECT 1
                   FROM node_dependencies AS dependency
                   JOIN nodes AS parent
                     ON parent.id = dependency.parent_node_id
                    AND parent.organization_id = dependency.organization_id
                    AND parent.build_id = dependency.build_id
                   WHERE dependency.organization_id = n.organization_id
                     AND dependency.build_id = n.build_id
                     AND dependency.child_node_id = n.id
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
               )
             ORDER BY (n.required_trust_pool = $2) DESC,
                      n.priority DESC,
                      n.queued_at,
                      n.id
             LIMIT 1",
        )
        .bind(organization_id)
        .bind(trust_pool)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((required, required_trust_pool)) = required else {
            tx.commit().await?;
            return Ok(WaitReason::NoQueuedWork);
        };
        if required_trust_pool != trust_pool {
            tx.commit().await?;
            return Ok(WaitReason::TrustPoolMismatch {
                required: required_trust_pool,
                offered: trust_pool.to_owned(),
            });
        }
        let required = required.into_iter().collect::<BTreeSet<_>>();
        let offered = capabilities.iter().cloned().collect::<BTreeSet<_>>();
        let missing = required.difference(&offered).cloned().collect();
        tx.commit().await?;
        Ok(WaitReason::CapabilityMismatch { required, missing })
    }
}

impl Store {
    /// Records a named renewal rejection outside the renewal transaction, for
    /// callers that refuse authority before the store's renewal path runs
    /// (the session-epoch gate in the agent-control handler). The event binds
    /// only to durable truth: it is appended solely when the named attempt at
    /// this exact fence is currently leased by the reporting agent, so a
    /// stale-session caller cannot inject a false event against another
    /// agent's attempt or an arbitrary fence. Best effort otherwise.
    pub async fn record_lease_renewal_rejection(
        &self,
        organization_id: Uuid,
        attempt_id: Uuid,
        fence: i64,
        agent_id: &str,
        cause: &str,
    ) -> Result<(), StoreError> {
        let mut tx = self.tenant_transaction(organization_id).await?;
        // Appending the event touches attempts, nodes, build_events, and the
        // outbox, so this is a multi-table write and takes the canonical order.
        // The shared restore fence additionally keeps the event from landing
        // after restore activation invalidates the lease it describes.
        acquire_org_scheduler_lock(&mut tx, organization_id).await?;
        acquire_restore_fence_shared(&mut tx).await?;
        let build = sqlx::query_scalar::<_, Uuid>(
            "SELECT n.build_id
             FROM attempts AS a
             JOIN nodes AS n
               ON n.id = a.node_id AND n.organization_id = a.organization_id
             WHERE a.organization_id = $1
               AND a.id = $2
               AND a.fence = $3
               AND a.lease_owner = $4
               AND a.lease_expires_at > clock_timestamp()
               AND a.status IN ('accepted', 'running', 'finalizing', 'cancelling')
               AND a.restore_epoch = (
                   SELECT restore_epoch FROM controller_metadata WHERE singleton
               )",
        )
        .bind(organization_id)
        .bind(attempt_id)
        .bind(fence)
        .bind(agent_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(build_id) = build else {
            tx.rollback().await?;
            return Ok(());
        };
        append_event_and_outbox(
            &mut tx,
            organization_id,
            build_id,
            "attempt.lease_renewal_rejected",
            json!({
                "attempt_id": attempt_id,
                "fence": fence,
                "agent_id": agent_id,
                "cause": cause,
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
}

/// Names a refused lease renewal in the build's event stream so authority
/// loss under a running step is controller-visible truth, never only a later
/// silent expiry or an agent-side surprise.
///
/// Callers reach this after a non-locking authority check at the request
/// boundary, so the described authority can have lapsed before this
/// transaction serialized. The lookup therefore re-derives the build under the
/// caller's already-held shared restore fence and appends only while the named
/// attempt still sits at this exact fence, owned by this agent, non-terminal,
/// and under the live restore epoch. A terminalized attempt is deliberately
/// silent here: the renewal path treats that same attempt as a terminal no-op,
/// and one refusal must not be published as two contradicting facts. Lease
/// expiry is not part of the predicate, because an expired lease is precisely
/// the refusal this event exists to name.
async fn record_lease_renewal_rejection(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: Uuid,
    attempt_id: Uuid,
    fence: i64,
    agent_id: &str,
    cause: &str,
) -> Result<(), StoreError> {
    let build = sqlx::query_scalar::<_, Uuid>(
        "SELECT n.build_id
         FROM attempts AS a
         JOIN nodes AS n
           ON n.id = a.node_id AND n.organization_id = a.organization_id
         WHERE a.organization_id = $1
           AND a.id = $2
           AND a.fence = $3
           AND a.lease_owner = $4
           AND a.status IN ('accepted', 'running', 'finalizing', 'cancelling')
           AND a.restore_epoch = (
               SELECT restore_epoch FROM controller_metadata WHERE singleton
           )",
    )
    .bind(organization_id)
    .bind(attempt_id)
    .bind(fence)
    .bind(agent_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(build_id) = build else {
        return Ok(());
    };
    append_event_and_outbox(
        tx,
        organization_id,
        build_id,
        "attempt.lease_renewal_rejected",
        json!({
            "attempt_id": attempt_id,
            "fence": fence,
            "agent_id": agent_id,
            "cause": cause,
        }),
    )
    .await
}
