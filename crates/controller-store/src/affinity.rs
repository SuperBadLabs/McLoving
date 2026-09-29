//! Build workspace affinity (PAR-015): later stages stick to the first stage's agent.
use crate::StoreError;
use mcloving_domain::workspace::{WorkspaceAffinityGrant, WorkspaceAffinityMode};
use serde_json::json;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

/// Pin the build to `agent_id` on first-stage success, or verify the pin matches.
pub(crate) async fn record_successful_agent(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    build_id: Uuid,
    agent_id: &str,
    node_id: Uuid,
) -> Result<(), StoreError> {
    let affinity_work: bool = sqlx::query_scalar(
        "SELECT node_kind = 'work' AND $4 = ANY(required_capabilities)
         FROM nodes
         WHERE organization_id = $1 AND build_id = $2 AND id = $3",
    )
    .bind(organization_id)
    .bind(build_id)
    .bind(node_id)
    .bind(mcloving_domain::workspace::WORKSPACE_AFFINITY_CAPABILITY)
    .fetch_optional(&mut **tx)
    .await?
    .unwrap_or(false);
    if !affinity_work {
        return Ok(());
    }
    let updated = sqlx::query_scalar::<_, Uuid>(
        "UPDATE builds
         SET workspace_affinity_agent_id = COALESCE(workspace_affinity_agent_id, $3)
         WHERE organization_id = $1
           AND id = $2
           AND dag_mode
           AND workspace_namespace IS NULL
           AND (
               workspace_affinity_agent_id IS NULL
               OR workspace_affinity_agent_id = $3
           )
           AND (
               SELECT count(*)::int FROM nodes
               WHERE organization_id = $1 AND build_id = $2 AND node_kind = 'work'
           ) > 1
           AND EXISTS (
               SELECT 1 FROM nodes
               WHERE organization_id = $1
                 AND build_id = $2
                 AND node_kind = 'work'
           )
           AND NOT EXISTS (
               SELECT 1 FROM nodes
               WHERE organization_id = $1
                 AND build_id = $2
                 AND node_kind = 'work'
                 AND NOT ($4 = ANY(required_capabilities))
           )
         RETURNING id",
    )
    .bind(organization_id)
    .bind(build_id)
    .bind(agent_id)
    .bind(mcloving_domain::workspace::WORKSPACE_AFFINITY_CAPABILITY)
    .fetch_optional(&mut **tx)
    .await?;
    if updated.is_none() {
        // Not an affinity build, or agent mismatch on an already-pinned build.
        let pinned: Option<String> = sqlx::query_scalar(
            "SELECT workspace_affinity_agent_id FROM builds
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(organization_id)
        .bind(build_id)
        .fetch_optional(&mut **tx)
        .await?
        .flatten();
        if let Some(existing) = pinned
            && existing != agent_id
        {
            return Err(StoreError::SequentialIntegrity(format!(
                "workspace affinity agent mismatch: pinned {existing}, got {agent_id}"
            )));
        }
    }
    Ok(())
}

/// Fail ready affinity successors whose pinned agent has no live session
/// that can still run the queued node (feature, trust pool, and full
/// required_capabilities). A pinned agent missing a later stage capability
/// must not leave the build queued forever.
pub(crate) async fn fail_orphaned_affinity_builds(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
) -> Result<usize, StoreError> {
    let rows = sqlx::query(
        "SELECT DISTINCT b.id AS build_id, b.workspace_affinity_agent_id AS agent_id
         FROM builds AS b
         JOIN nodes AS n
           ON n.build_id = b.id AND n.organization_id = b.organization_id
         JOIN attempts AS a
           ON a.node_id = n.id AND a.organization_id = n.organization_id
          AND a.status = 'queued'
         WHERE b.organization_id = $1
           AND b.dag_mode
           AND b.status IN ('queued', 'running')
           AND b.workspace_affinity_agent_id IS NOT NULL
           AND b.workspace_namespace IS NULL
           AND n.status = 'queued'
           AND n.node_kind = 'work'
           AND $2 = ANY(n.required_capabilities)
           AND n.cancellation_requested_at IS NULL
           AND b.cancellation_requested_at IS NULL
           AND EXISTS (
               SELECT 1 FROM nodes AS qn
               WHERE qn.build_id = b.id
                 AND qn.organization_id = b.organization_id
                 AND qn.status = 'queued'
                 AND qn.node_kind = 'work'
                 AND $2 = ANY(qn.required_capabilities)
                 AND NOT EXISTS (
                     SELECT 1 FROM agent_sessions AS s
                     WHERE s.agent_id = b.workspace_affinity_agent_id
                       AND $2 = ANY(s.capabilities)
                       AND $3 = ANY(s.features)
                       AND qn.required_trust_pool = s.trust_pool
                       AND qn.required_capabilities <@ s.capabilities
                       AND s.updated_at > clock_timestamp() - interval '5 minutes'
                 )
           )",
    )
    .bind(organization_id)
    .bind(mcloving_domain::workspace::WORKSPACE_AFFINITY_CAPABILITY)
    .bind(mcloving_domain::workspace::WORKSPACE_AFFINITY_FEATURE)
    .fetch_all(&mut **tx)
    .await?;
    let mut failed = 0usize;
    for row in rows {
        let build_id: Uuid = row.try_get("build_id")?;
        let agent_id: String = row.try_get("agent_id")?;
        let summary = json!({
            "reason": "workspace_affinity_agent_gone",
            "agent_id": agent_id,
        });
        sqlx::query(
            "UPDATE attempts AS a
             SET status = 'aborted',
                 terminal_summary = $3,
                 completed_at = clock_timestamp(),
                 lease_expires_at = NULL
             FROM nodes AS n
             WHERE a.organization_id = $1
               AND n.organization_id = a.organization_id
               AND n.build_id = $2
               AND n.id = a.node_id
               AND a.status IN ('queued', 'offered')
               AND n.status IN ('blocked', 'queued', 'offered')",
        )
        .bind(organization_id)
        .bind(build_id)
        .bind(&summary)
        .execute(&mut **tx)
        .await?;
        sqlx::query(
            "UPDATE nodes
             SET status = 'aborted',
                 logical_outcome = 'aborted'
             WHERE organization_id = $1
               AND build_id = $2
               AND status IN ('blocked', 'queued', 'offered')
               AND logical_outcome IS NULL",
        )
        .bind(organization_id)
        .bind(build_id)
        .execute(&mut **tx)
        .await?;
        sqlx::query(
            "UPDATE builds
             SET status = 'failed',
                 completed_at = clock_timestamp()
             WHERE organization_id = $1
               AND id = $2
               AND status IN ('queued', 'running')",
        )
        .bind(organization_id)
        .bind(build_id)
        .execute(&mut **tx)
        .await?;
        crate::append_event_and_outbox(
            tx,
            organization_id,
            build_id,
            "build.workspace_affinity_agent_gone",
            summary,
        )
        .await?;
        crate::dag::record_terminal_notifications(tx, organization_id, build_id, "failed").await?;
        failed += 1;
    }
    Ok(failed)
}

/// Build the wire grant for one claimed attempt, if this build uses affinity.
pub(crate) async fn grant_for_attempt(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    build_id: Uuid,
    node_id: Uuid,
) -> Result<Option<WorkspaceAffinityGrant>, StoreError> {
    let row = sqlx::query(
        "SELECT b.workspace_affinity_agent_id,
                b.workspace_namespace IS NOT NULL AS transfer,
                (
                    SELECT count(*)::int FROM nodes
                    WHERE organization_id = b.organization_id
                      AND build_id = b.id
                      AND node_kind = 'work'
                ) AS work_nodes,
                (
                    -- Count siblings that still need the shared tree: active
                    -- stages and failed ones that remain schedule_retry-able.
                    SELECT count(*)::int FROM nodes
                    WHERE organization_id = b.organization_id
                      AND build_id = b.id
                      AND node_kind = 'work'
                      AND id <> $3
                      AND status NOT IN ('succeeded', 'aborted', 'skipped')
                ) AS remaining_after,
                n.node_kind = 'work' AND $4 = ANY(n.required_capabilities) AS affinity_work
         FROM builds AS b
         JOIN nodes AS n
           ON n.organization_id = b.organization_id
          AND n.build_id = b.id
          AND n.id = $3
         WHERE b.organization_id = $1 AND b.id = $2 AND b.dag_mode
           AND EXISTS (
               SELECT 1 FROM nodes
               WHERE organization_id = b.organization_id
                 AND build_id = b.id
                 AND node_kind = 'work'
           )
           AND NOT EXISTS (
               SELECT 1 FROM nodes
               WHERE organization_id = b.organization_id
                 AND build_id = b.id
                 AND node_kind = 'work'
                 AND NOT ($4 = ANY(required_capabilities))
           )",
    )
    .bind(organization_id)
    .bind(build_id)
    .bind(node_id)
    .bind(mcloving_domain::workspace::WORKSPACE_AFFINITY_CAPABILITY)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let affinity_work: bool = row.try_get("affinity_work")?;
    if !affinity_work {
        return Ok(None);
    }
    let transfer: bool = row.try_get("transfer")?;
    let work_nodes: i32 = row.try_get("work_nodes")?;
    if transfer || work_nodes <= 1 {
        return Ok(None);
    }
    let affinity_agent: Option<String> = row.try_get("workspace_affinity_agent_id")?;
    let remaining_after: i32 = row.try_get("remaining_after")?;
    let mode = if affinity_agent.is_some() {
        WorkspaceAffinityMode::Reuse
    } else {
        WorkspaceAffinityMode::Create
    };
    let grant = WorkspaceAffinityGrant {
        version: 1,
        mode,
        retain_on_success: remaining_after > 0,
    };
    grant
        .validate()
        .map_err(|error| StoreError::SequentialIntegrity(error.to_string()))?;
    Ok(Some(grant))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcloving_domain::workspace::WorkspaceAffinityMode;

    #[test]
    fn affinity_grant_create_then_reuse_shape() {
        let create = WorkspaceAffinityGrant {
            version: 1,
            mode: WorkspaceAffinityMode::Create,
            retain_on_success: true,
        };
        create.validate().unwrap();
        let reuse = WorkspaceAffinityGrant {
            version: 1,
            mode: WorkspaceAffinityMode::Reuse,
            retain_on_success: false,
        };
        reuse.validate().unwrap();
        assert_ne!(create.mode, reuse.mode);
    }
}
