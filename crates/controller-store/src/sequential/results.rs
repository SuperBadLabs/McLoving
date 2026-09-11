use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::Row;
use uuid::Uuid;

use super::{SequentialDagBuild, SequentialStepLayout};
use crate::{
    AttemptView, DagDependency, DagNodeKind, DependencyCondition, NewDagBuild, NewDagNode, Store,
    StoreError,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SequentialBuildResult {
    pub workspace_namespace: Option<Uuid>,
    pub workspace_generation: i64,
    pub workspace_closed: bool,
    pub workspace_receipt: Option<Value>,
    pub build_id: Uuid,
    pub pipeline_id: Uuid,
    pub pipeline_revision: i64,
    pub pipeline_operational_generation: i64,
    pub pipeline_digest: [u8; 32],
    pub layout_version: u32,
    /// Existing durable build policy, not a second aggregate computed by this reader.
    pub status: String,
    pub stages: Vec<SequentialStageResult>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SequentialStageResult {
    pub stage_id: String,
    pub stage_name: String,
    pub stage_ordinal: usize,
    pub status: String,
    pub steps: Vec<SequentialStepResult>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SequentialStepResult {
    pub layout: SequentialStepLayout,
    pub node_id: Uuid,
    pub status: String,
    pub logical_outcome: Option<String>,
    pub cancellation_requested: bool,
    pub max_attempts: i32,
    pub attempts: Vec<SequentialAttemptResult>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SequentialAttemptResult {
    /// `started_at_unix_ms` is durable StartWork accounting, not process birth.
    /// `completed_at_unix_ms` is terminal accounting, not observed process exit.
    pub accounting: AttemptView,
    pub logs: Vec<SequentialLogReference>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SequentialLogReference {
    pub attempt_id: Uuid,
    pub fence: i64,
    pub stream: String,
    pub first_sequence: i64,
    pub last_sequence: i64,
    pub chunk_count: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Contract {
    version: u32,
    priority: i32,
    nodes: Vec<ContractNode>,
    sequential_layout: Layout,
    #[serde(default)]
    workspace_transfer: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Layout {
    version: u32,
    steps: Vec<SequentialStepLayout>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContractNode {
    node_key: String,
    kind: String,
    dependencies: Vec<ContractDependency>,
    required_capabilities: Vec<String>,
    required_platform: String,
    required_trust_pool: String,
    priority: i32,
    execution_spec: Value,
    fail_fast: bool,
    max_attempts: i32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContractDependency {
    node_key: String,
    condition: String,
}

fn integrity(message: &str) -> StoreError {
    StoreError::SequentialIntegrity(message.to_owned())
}

fn restore_contract(mut dag: NewDagBuild, value: Value) -> Result<SequentialDagBuild, StoreError> {
    let contract: Contract = serde_json::from_value(value.clone())
        .map_err(|_| integrity("malformed sequential contract"))?;
    if contract.version != 1
        || contract.sequential_layout.version != 1
        || contract.priority != dag.priority
    {
        return Err(integrity(
            "unknown contract version or changed build priority",
        ));
    }
    let workspace = match contract.workspace_transfer {
        None => false,
        Some(value) if value == serde_json::json!({"version": 1}) => true,
        _ => return Err(integrity("unknown workspace contract")),
    };
    let expected_capabilities = if workspace {
        vec![
            "platform:linux",
            mcloving_domain::workspace::WORKSPACE_TRANSFER_CAPABILITY,
        ]
    } else {
        vec!["platform:linux"]
    };
    dag.nodes = contract
        .nodes
        .into_iter()
        .map(|node| {
            if node.kind != "work" || node.required_capabilities != expected_capabilities {
                return Err(integrity("unsupported immutable node kind or capability"));
            }
            let dependencies = node
                .dependencies
                .into_iter()
                .map(|dependency| {
                    if dependency.condition != "succeeded" {
                        return Err(integrity("unsupported dependency condition"));
                    }
                    Ok(DagDependency {
                        node_key: dependency.node_key,
                        condition: DependencyCondition::Succeeded,
                    })
                })
                .collect::<Result<Vec<_>, StoreError>>()?;
            Ok(NewDagNode {
                node_key: node.node_key,
                kind: DagNodeKind::Work,
                dependencies,
                required_capabilities: Vec::new(),
                required_platform: node.required_platform,
                required_trust_pool: node.required_trust_pool,
                priority: node.priority,
                execution_spec: node.execution_spec,
                fail_fast: node.fail_fast,
                max_attempts: node.max_attempts,
            })
        })
        .collect::<Result<Vec<_>, StoreError>>()?;
    let input = SequentialDagBuild::new(dag, contract.sequential_layout.steps)
        .map_err(|_| integrity("invalid immutable sequential layout or process contract"))?;
    let input = if workspace {
        input.with_workspace_transfer()?
    } else {
        input
    };
    if input.contract() != value {
        return Err(integrity("noncanonical immutable contract"));
    }
    Ok(input)
}

impl Store {
    /// Read a complete ordered projection from one repeatable-read snapshot.
    /// Legacy or absent builds return None; malformed sequential metadata is an error.
    /// The caller's attempt limit is operational and never a claim that history is corrupt.
    #[doc(hidden)]
    pub async fn sequential_build_result(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        build_id: Uuid,
        attempt_limit: usize,
    ) -> Result<Option<SequentialBuildResult>, StoreError> {
        if !(1..=100_000).contains(&attempt_limit) {
            return Err(StoreError::SequentialReadIncomplete);
        }
        let mut tx = self.tenant_transaction(organization_id).await?;
        // tenant_transaction executes only BEGIN/SET LOCAL, so no data snapshot precedes this.
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *tx)
            .await?;
        let build = sqlx::query("SELECT pipeline_id, pipeline_revision, pipeline_operational_generation,
                pipeline_digest, pipeline_revision_digest, idempotency_key, priority, status, dag_mode, dag_contract, workspace_namespace, workspace_generation, workspace_closed, workspace_receipt, workspace_snapshot
            FROM builds WHERE organization_id = $1 AND project_id = $2 AND id = $3")
            .bind(organization_id).bind(project_id).bind(build_id).fetch_optional(&mut *tx).await?;
        let Some(build) = build else {
            tx.commit().await?;
            return Ok(None);
        };
        let contract: Option<Value> = build.try_get("dag_contract")?;
        let Some(contract) = contract.filter(|value| value.get("sequential_layout").is_some())
        else {
            tx.commit().await?;
            return Ok(None);
        };
        let digest: Vec<u8> = build.try_get("pipeline_digest")?;
        let saved_digest: Option<Vec<u8>> = build.try_get("pipeline_revision_digest")?;
        if !build.try_get::<bool, _>("dag_mode")? || saved_digest.as_ref() != Some(&digest) {
            return Err(integrity("sequential mode or frozen digests differ"));
        }
        let dag = NewDagBuild {
            organization_id,
            project_id,
            pipeline_id: build
                .try_get::<Option<Uuid>, _>("pipeline_id")?
                .ok_or_else(|| integrity("missing pipeline identity"))?,
            pipeline_revision: build
                .try_get::<Option<i64>, _>("pipeline_revision")?
                .ok_or_else(|| integrity("missing revision"))?,
            pipeline_operational_generation: build
                .try_get::<Option<i64>, _>("pipeline_operational_generation")?
                .ok_or_else(|| integrity("missing generation"))?,
            pipeline_digest: digest
                .try_into()
                .map_err(|_| integrity("invalid semantic digest length"))?,
            idempotency_key: build.try_get("idempotency_key")?,
            priority: build.try_get("priority")?,
            notify_targets: serde_json::json!([]),
            nodes: Vec::new(),
        };
        let input = restore_contract(dag, contract)?;
        let namespace: Option<Uuid> = build.try_get("workspace_namespace")?;
        let closed: bool = build.try_get("workspace_closed")?;
        let snapshot: Option<Value> = build.try_get("workspace_snapshot")?;
        if input.workspace_transfer_enabled() != namespace.is_some()
            || (closed && snapshot.is_some())
        {
            return Err(integrity(
                "workspace contract and durable lifecycle disagree",
            ));
        }
        if namespace.is_some()
            && closed
                != matches!(
                    build.try_get::<String, _>("status")?.as_str(),
                    "succeeded" | "failed" | "aborted"
                )
        {
            return Err(integrity(
                "workspace closure differs from build terminal status",
            ));
        }
        if namespace.is_some() {
            let snapshot: Option<mcloving_domain::workspace::WorkspaceSnapshot> = snapshot
                .map(serde_json::from_value)
                .transpose()
                .map_err(|_| integrity("invalid workspace snapshot"))?;
            crate::workspace::validate_checkpoint(
                build.try_get("workspace_generation")?,
                snapshot.as_ref(),
                build
                    .try_get::<Option<Value>, _>("workspace_receipt")?
                    .as_ref(),
                closed,
                input.layout.len() as i32,
            )?;
        }

        let node_rows = sqlx::query("SELECT id, node_key, node_kind, status, logical_outcome,
                required_capabilities, required_trust_pool, priority, execution_spec, fail_fast, max_attempts,
                cancellation_requested_at IS NOT NULL AS cancelled
            FROM nodes WHERE organization_id = $1 AND build_id = $2 ORDER BY node_key LIMIT 65")
            .bind(organization_id).bind(build_id).fetch_all(&mut *tx).await?;
        if node_rows.len() != input.dag.nodes.len() {
            return Err(integrity("node/layout cardinality differs"));
        }
        let mut by_key = BTreeMap::new();
        let mut by_id = BTreeMap::new();
        for row in &node_rows {
            let key: String = row.try_get("node_key")?;
            let id: Uuid = row.try_get("id")?;
            let expected = input
                .dag
                .nodes
                .iter()
                .find(|node| node.node_key == key)
                .ok_or_else(|| integrity("node absent from immutable contract"))?;
            if row.try_get::<String, _>("node_kind")? != "work"
                || row.try_get::<Vec<String>, _>("required_capabilities")?
                    != if input.workspace_transfer_enabled() {
                        vec![
                            "platform:linux",
                            mcloving_domain::workspace::WORKSPACE_TRANSFER_CAPABILITY,
                        ]
                    } else {
                        vec!["platform:linux"]
                    }
                || row.try_get::<String, _>("required_trust_pool")? != expected.required_trust_pool
                || row.try_get::<i32, _>("priority")? != expected.priority
                || row.try_get::<Value, _>("execution_spec")? != expected.execution_spec
                || row.try_get::<bool, _>("fail_fast")? != expected.fail_fast
                || by_key.insert(key.clone(), row).is_some()
                || by_id.insert(id, key).is_some()
            {
                return Err(integrity("stored node differs from immutable contract"));
            }
        }
        let edges = sqlx::query_as::<_, (Uuid, Uuid, String)>(
            "SELECT parent_node_id, child_node_id, condition
            FROM node_dependencies WHERE organization_id = $1 AND build_id = $2 LIMIT 65",
        )
        .bind(organization_id)
        .bind(build_id)
        .fetch_all(&mut *tx)
        .await?;
        let expected_edges = input
            .layout
            .windows(2)
            .map(|pair| {
                Ok((
                    by_key[&pair[0].node_key].try_get::<Uuid, _>("id")?,
                    by_key[&pair[1].node_key].try_get::<Uuid, _>("id")?,
                    "succeeded".to_owned(),
                ))
            })
            .collect::<Result<BTreeSet<_>, sqlx::Error>>()?;
        if edges.len() != expected_edges.len()
            || edges.into_iter().collect::<BTreeSet<_>>() != expected_edges
        {
            return Err(integrity(
                "stored dependencies differ from immutable contract",
            ));
        }
        let rows = sqlx::query("SELECT a.id, a.node_id, a.ordinal, a.retry_of, a.status, a.fence,
                a.lease_owner, a.terminal_summary,
                (EXTRACT(EPOCH FROM a.created_at) * 1000)::bigint AS created_ms,
                (EXTRACT(EPOCH FROM a.ready_at) * 1000)::bigint AS ready_ms,
                (EXTRACT(EPOCH FROM a.completed_at) * 1000)::bigint AS completed_ms,
                (SELECT (EXTRACT(EPOCH FROM e.created_at) * 1000)::bigint FROM build_events AS e
                    WHERE e.organization_id = a.organization_id AND e.build_id = n.build_id
                    AND e.kind = 'attempt.running' AND e.payload @> jsonb_build_object('attempt_id', a.id, 'fence', a.fence)
                    ORDER BY e.id LIMIT 1) AS started_ms
            FROM attempts AS a JOIN nodes AS n ON n.organization_id = a.organization_id AND n.id = a.node_id
            WHERE a.organization_id = $1 AND n.build_id = $2 ORDER BY a.node_id, a.ordinal LIMIT $3")
            .bind(organization_id).bind(build_id).bind((attempt_limit + 1) as i64).fetch_all(&mut *tx).await?;
        if rows.len() > attempt_limit {
            return Err(StoreError::SequentialReadIncomplete);
        }
        let mut attempts: BTreeMap<Uuid, Vec<SequentialAttemptResult>> = BTreeMap::new();
        let mut attempt_ids = BTreeSet::new();
        for row in &rows {
            let attempt = AttemptView {
                attempt_id: row.try_get("id")?,
                node_id: row.try_get("node_id")?,
                ordinal: row.try_get("ordinal")?,
                retry_of: row.try_get("retry_of")?,
                status: row.try_get("status")?,
                fence: row.try_get("fence")?,
                lease_owner: row.try_get("lease_owner")?,
                terminal_summary: row.try_get("terminal_summary")?,
                created_at_unix_ms: row.try_get("created_ms")?,
                ready_at_unix_ms: row.try_get("ready_ms")?,
                started_at_unix_ms: row.try_get("started_ms")?,
                completed_at_unix_ms: row.try_get("completed_ms")?,
            };
            let lineage = attempts.entry(attempt.node_id).or_default();
            if !by_id.contains_key(&attempt.node_id)
                || !attempt_ids.insert(attempt.attempt_id)
                || attempt.ordinal as usize != lineage.len() + 1
                || attempt.retry_of
                    != lineage
                        .last()
                        .map(|previous| previous.accounting.attempt_id)
            {
                return Err(integrity("incomplete or mismatched attempt lineage"));
            }
            lineage.push(SequentialAttemptResult {
                accounting: attempt,
                logs: Vec::new(),
            });
        }
        let logs = sqlx::query("SELECT l.attempt_id, l.fence, l.stream,
                min(l.sequence) AS first_sequence, max(l.sequence) AS last_sequence, count(*) AS chunk_count
            FROM attempt_log_chunks AS l JOIN attempts AS a ON a.organization_id = l.organization_id AND a.id = l.attempt_id
            JOIN nodes AS n ON n.organization_id = a.organization_id AND n.id = a.node_id
            WHERE l.organization_id = $1 AND n.build_id = $2 GROUP BY l.attempt_id, l.fence, l.stream
            ORDER BY l.attempt_id, l.fence, l.stream LIMIT 100001")
            .bind(organization_id).bind(build_id).fetch_all(&mut *tx).await?;
        if logs.len() > 100_000 {
            return Err(StoreError::SequentialReadIncomplete);
        }
        let mut log_refs: BTreeMap<Uuid, Vec<SequentialLogReference>> = BTreeMap::new();
        for row in logs {
            let reference = SequentialLogReference {
                attempt_id: row.try_get("attempt_id")?,
                fence: row.try_get("fence")?,
                stream: row.try_get("stream")?,
                first_sequence: row.try_get("first_sequence")?,
                last_sequence: row.try_get("last_sequence")?,
                chunk_count: row.try_get("chunk_count")?,
            };
            if !attempt_ids.contains(&reference.attempt_id) {
                return Err(integrity("log refers to missing attempt"));
            }
            log_refs
                .entry(reference.attempt_id)
                .or_default()
                .push(reference);
        }
        let mut stages: Vec<SequentialStageResult> = Vec::new();
        for layout in &input.layout {
            let row = by_key[&layout.node_key];
            let id: Uuid = row.try_get("id")?;
            let mut lineage = attempts
                .remove(&id)
                .ok_or_else(|| integrity("node has no initial attempt"))?;
            for attempt in &mut lineage {
                attempt.logs = log_refs
                    .remove(&attempt.accounting.attempt_id)
                    .unwrap_or_default();
            }
            let status: String = row.try_get("status")?;
            let outcome: Option<String> = row.try_get("logical_outcome")?;
            if terminal(&status) != outcome.is_some()
                || outcome.as_ref().is_some_and(|value| value != &status)
            {
                return Err(integrity("logical outcome and node state differ"));
            }
            if stages
                .last()
                .is_none_or(|stage| stage.stage_ordinal != layout.stage_ordinal)
            {
                stages.push(SequentialStageResult {
                    stage_id: layout.stage_id.clone(),
                    stage_name: layout.stage_name.clone(),
                    stage_ordinal: layout.stage_ordinal,
                    status: String::new(),
                    steps: Vec::new(),
                });
            }
            stages
                .last_mut()
                .expect("stage inserted")
                .steps
                .push(SequentialStepResult {
                    layout: layout.clone(),
                    node_id: id,
                    status,
                    logical_outcome: outcome,
                    cancellation_requested: row.try_get("cancelled")?,
                    max_attempts: row.try_get("max_attempts")?,
                    attempts: lineage,
                });
        }
        for stage in &mut stages {
            stage.status = aggregate(
                &stage
                    .steps
                    .iter()
                    .map(|step| step.status.as_str())
                    .collect::<Vec<_>>(),
            )?;
        }
        aggregate(
            &stages
                .iter()
                .flat_map(|stage| stage.steps.iter().map(|step| step.status.as_str()))
                .collect::<Vec<_>>(),
        )?;
        let result = SequentialBuildResult {
            workspace_namespace: build.try_get("workspace_namespace")?,
            workspace_generation: build.try_get("workspace_generation")?,
            workspace_closed: build.try_get("workspace_closed")?,
            workspace_receipt: build.try_get("workspace_receipt")?,
            build_id,
            pipeline_id: input.dag.pipeline_id,
            pipeline_revision: input.dag.pipeline_revision,
            pipeline_operational_generation: input.dag.pipeline_operational_generation,
            pipeline_digest: input.dag.pipeline_digest,
            layout_version: 1,
            status: build.try_get("status")?,
            stages,
        };
        crate::workspace::validate_history(organization_id, &result)?;
        tx.commit().await?;
        Ok(Some(result))
    }
}

fn terminal(status: &str) -> bool {
    matches!(status, "succeeded" | "failed" | "aborted" | "skipped")
}

fn aggregate(states: &[&str]) -> Result<String, StoreError> {
    if states.is_empty()
        || states.iter().any(|state| {
            !terminal(state)
                && !matches!(
                    *state,
                    "queued"
                        | "blocked"
                        | "offered"
                        | "running"
                        | "cancelling"
                        | "reconciliation_required"
                )
        })
    {
        return Err(integrity("unknown or empty logical stage state"));
    }
    let has = |state| states.contains(&state);
    let result = if states.iter().all(|state| terminal(state)) {
        if has("failed") {
            "failed"
        } else if has("aborted") {
            "aborted"
        } else if states.iter().all(|state| *state == "succeeded") {
            "succeeded"
        } else if states.iter().all(|state| *state == "skipped") {
            "skipped"
        } else {
            return Err(integrity(
                "terminal linear stage mixes succeeded and skipped without failure or abort",
            ));
        }
    } else if has("reconciliation_required") {
        "reconciliation_required"
    } else if has("running")
        || has("offered")
        || has("cancelling")
        || states.iter().any(|state| terminal(state))
    {
        "running"
    } else if has("queued") {
        "queued"
    } else {
        "blocked"
    };
    Ok(result.to_owned())
}

#[cfg(test)]
mod tests {
    use super::aggregate;
    #[test]
    fn stage_aggregation_uses_current_logical_outcomes() {
        for (states, expected) in [
            (vec!["queued", "blocked"], "queued"),
            (vec!["blocked", "blocked"], "blocked"),
            (vec!["succeeded", "queued"], "running"),
            (
                vec!["failed", "reconciliation_required"],
                "reconciliation_required",
            ),
            (vec!["succeeded", "succeeded"], "succeeded"),
            (vec!["succeeded", "failed", "skipped"], "failed"),
            (vec!["succeeded", "aborted"], "aborted"),
            (vec!["skipped", "skipped"], "skipped"),
            (vec!["failed", "aborted"], "failed"),
            (vec!["cancelling", "blocked"], "running"),
        ] {
            assert_eq!(aggregate(&states).unwrap(), expected);
        }
        assert!(aggregate(&["succeeded", "skipped"]).is_err());
        assert!(aggregate(&[]).is_err());
        assert!(aggregate(&["unknown"]).is_err());
    }
}
