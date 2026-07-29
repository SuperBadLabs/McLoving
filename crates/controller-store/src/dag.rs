use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde_json::{Value, json};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use crate::{Store, StoreError, TerminalOutcome, append_event_and_outbox};

const MAX_DAG_NODES: usize = 256;
const MAX_DAG_EDGES: usize = 4_096;
const MAX_MATRIX_AXES: usize = 8;
const MAX_MATRIX_VALUES_PER_AXIS: usize = 32;
const MAX_MATRIX_CELLS: usize = 256;
const MAX_DAG_TEXT_BYTES: usize = 256;
const MAX_EXECUTION_SPEC_BYTES: usize = 256 * 1024;
const MAX_DAG_CAPABILITIES: usize = 64;

/// Condition under which one dependency is satisfied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DependencyCondition {
    Succeeded,
    Completed,
}

impl DependencyCondition {
    fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Completed => "completed",
        }
    }
}

/// Scheduling role of a logical DAG node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DagNodeKind {
    Work,
    Join,
    Post,
}

impl DagNodeKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Work => "work",
            Self::Join => "join",
            Self::Post => "post",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DagDependency {
    pub node_key: String,
    pub condition: DependencyCondition,
}

/// One logical node admitted into durable PostgreSQL truth.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewDagNode {
    pub node_key: String,
    pub kind: DagNodeKind,
    pub dependencies: Vec<DagDependency>,
    pub required_capabilities: Vec<String>,
    pub required_platform: String,
    pub required_trust_pool: String,
    pub priority: i32,
    pub execution_spec: Value,
    pub fail_fast: bool,
    pub max_attempts: i32,
}

/// One complete DAG build admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewDagBuild {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub idempotency_key: String,
    pub pipeline_digest: [u8; 32],
    pub priority: i32,
    pub nodes: Vec<NewDagNode>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DagNodeAdmission {
    pub node_id: Uuid,
    pub attempt_id: Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DagAdmission {
    pub build_id: Uuid,
    pub nodes: BTreeMap<String, DagNodeAdmission>,
    pub created: bool,
}

/// One deterministic Cartesian-product cell.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MatrixCell {
    pub node_key: String,
    pub values: BTreeMap<String, String>,
}

/// Compile sorted axes and sorted unique values into a bounded stable product.
pub fn compile_matrix(
    node_prefix: &str,
    axes: &BTreeMap<String, Vec<String>>,
) -> Result<Vec<MatrixCell>, DagContractError> {
    validate_text("$.node_prefix", node_prefix)?;
    if axes.is_empty() || axes.len() > MAX_MATRIX_AXES {
        return Err(DagContractError::new(
            DagContractErrorCode::MatrixAxisLimit,
            "$.axes",
            format!("matrix axis count must be between 1 and {MAX_MATRIX_AXES}"),
        ));
    }
    let mut normalized = Vec::with_capacity(axes.len());
    let mut cells = 1_usize;
    for (axis, values) in axes {
        validate_text(&format!("$.axes.{axis}"), axis)?;
        if values.is_empty() || values.len() > MAX_MATRIX_VALUES_PER_AXIS {
            return Err(DagContractError::new(
                DagContractErrorCode::MatrixValueLimit,
                format!("$.axes.{axis}"),
                format!(
                    "matrix values per axis must be between 1 and {MAX_MATRIX_VALUES_PER_AXIS}"
                ),
            ));
        }
        let mut values = values.clone();
        for value in &values {
            validate_text(&format!("$.axes.{axis}"), value)?;
        }
        values.sort();
        if values.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(DagContractError::new(
                DagContractErrorCode::DuplicateMatrixValue,
                format!("$.axes.{axis}"),
                "matrix values must be unique",
            ));
        }
        cells = cells.checked_mul(values.len()).ok_or_else(|| {
            DagContractError::new(
                DagContractErrorCode::MatrixCellLimit,
                "$.axes",
                "matrix product overflows",
            )
        })?;
        if cells > MAX_MATRIX_CELLS {
            return Err(DagContractError::new(
                DagContractErrorCode::MatrixCellLimit,
                "$.axes",
                format!("matrix product exceeds {MAX_MATRIX_CELLS} cells"),
            ));
        }
        normalized.push((axis.clone(), values));
    }

    let mut products = vec![BTreeMap::new()];
    for (axis, values) in normalized {
        let mut next = Vec::with_capacity(products.len() * values.len());
        for product in products {
            for value in &values {
                let mut cell = product.clone();
                cell.insert(axis.clone(), value.clone());
                next.push(cell);
            }
        }
        products = next;
    }
    products
        .into_iter()
        .map(|values| {
            let dimensions = values
                .iter()
                .map(|(axis, value)| format!("{axis}={value}"))
                .collect::<Vec<_>>()
                .join(",");
            let node_key = format!("{node_prefix}[{dimensions}]");
            validate_node_key("$.node_key", &node_key)?;
            Ok(MatrixCell { node_key, values })
        })
        .collect::<Result<Vec<_>, DagContractError>>()
}

impl Store {
    /// Atomically admits an entire validated DAG, all first attempts,
    /// dependency edges, one event, and one outbox record.
    pub async fn admit_dag(&self, input: &NewDagBuild) -> Result<DagAdmission, StoreError> {
        validate_dag_contract(input).map_err(|error| StoreError::InvalidDag(error.to_string()))?;
        let mut tx = self.tenant_transaction(input.organization_id).await?;
        let build_id = Uuid::new_v4();
        let contract = normalized_dag_contract(input);
        let inserted = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO builds (
                 id, organization_id, project_id, idempotency_key,
                 pipeline_digest, status, priority, dag_mode, dag_contract
             )
             VALUES ($1, $2, $3, $4, $5, 'queued', $6, true, $7)
             ON CONFLICT (project_id, idempotency_key) DO NOTHING
             RETURNING id",
        )
        .bind(build_id)
        .bind(input.organization_id)
        .bind(input.project_id)
        .bind(&input.idempotency_key)
        .bind(input.pipeline_digest.as_slice())
        .bind(input.priority)
        .bind(&contract)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(build_id) = inserted else {
            let admission = existing_dag_admission(&mut tx, input, &contract).await?;
            tx.commit().await?;
            return Ok(admission);
        };

        let mut nodes = BTreeMap::new();
        for node in &input.nodes {
            let node_id = Uuid::new_v4();
            let attempt_id = Uuid::new_v4();
            let status = if node.dependencies.is_empty() {
                "queued"
            } else {
                "blocked"
            };
            let mut capabilities = node.required_capabilities.clone();
            capabilities.push(format!("platform:{}", node.required_platform));
            capabilities.sort();
            capabilities.dedup();
            sqlx::query(
                "INSERT INTO nodes (
                     id, organization_id, build_id, node_key, status,
                     required_capabilities, required_trust_pool, priority,
                     execution_spec, node_kind, fail_fast, max_attempts
                 )
                 VALUES (
                     $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
                 )",
            )
            .bind(node_id)
            .bind(input.organization_id)
            .bind(build_id)
            .bind(&node.node_key)
            .bind(status)
            .bind(&capabilities)
            .bind(&node.required_trust_pool)
            .bind(node.priority)
            .bind(&node.execution_spec)
            .bind(node.kind.as_str())
            .bind(node.fail_fast)
            .bind(node.max_attempts)
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
            nodes.insert(
                node.node_key.clone(),
                DagNodeAdmission {
                    node_id,
                    attempt_id,
                },
            );
        }
        for node in &input.nodes {
            let child = nodes[&node.node_key].node_id;
            for dependency in &node.dependencies {
                let parent = nodes[&dependency.node_key].node_id;
                sqlx::query(
                    "INSERT INTO node_dependencies (
                         organization_id, build_id, parent_node_id,
                         child_node_id, condition
                     )
                     VALUES ($1, $2, $3, $4, $5)",
                )
                .bind(input.organization_id)
                .bind(build_id)
                .bind(parent)
                .bind(child)
                .bind(dependency.condition.as_str())
                .execute(&mut *tx)
                .await?;
            }
        }
        append_event_and_outbox(
            &mut tx,
            input.organization_id,
            build_id,
            "dag.admitted",
            json!({
                "build_id": build_id,
                "nodes": nodes.len(),
                "edges": input.nodes.iter().map(|node| node.dependencies.len()).sum::<usize>(),
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(DagAdmission {
            build_id,
            nodes,
            created: true,
        })
    }
}

pub(crate) async fn advance_dag_after_attempt(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    build_id: Uuid,
    node_id: Uuid,
    attempt_id: Uuid,
    outcome: TerminalOutcome,
) -> Result<bool, StoreError> {
    let row = sqlx::query(
        "SELECT b.dag_mode,
                (
                    b.cancellation_requested_at IS NOT NULL
                    OR n.cancellation_requested_at IS NOT NULL
                ) AS cancelled,
                n.node_key, n.fail_fast, n.max_attempts, a.ordinal
         FROM builds AS b
         JOIN nodes AS n
           ON n.build_id = b.id AND n.organization_id = b.organization_id
         JOIN attempts AS a
           ON a.node_id = n.id AND a.organization_id = n.organization_id
         WHERE b.organization_id = $1
           AND b.id = $2
           AND n.id = $3
           AND a.id = $4
         FOR UPDATE OF b, n, a",
    )
    .bind(organization_id)
    .bind(build_id)
    .bind(node_id)
    .bind(attempt_id)
    .fetch_one(&mut **tx)
    .await?;
    let dag_mode: bool = row.try_get("dag_mode")?;
    if !dag_mode {
        return Ok(false);
    }
    let cancelled: bool = row.try_get("cancelled")?;
    let node_key: String = row.try_get("node_key")?;
    let fail_fast: bool = row.try_get("fail_fast")?;
    let max_attempts: i32 = row.try_get("max_attempts")?;
    let ordinal: i32 = row.try_get("ordinal")?;

    if outcome == TerminalOutcome::Failed && ordinal < max_attempts && !cancelled {
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
        .fetch_one(&mut **tx)
        .await?;
        if !has_non_idempotent_effect {
            let retry_id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO attempts (
                     id, organization_id, node_id, ordinal, status, retry_of
                 )
                 VALUES ($1, $2, $3, $4, 'queued', $5)",
            )
            .bind(retry_id)
            .bind(organization_id)
            .bind(node_id)
            .bind(ordinal + 1)
            .bind(attempt_id)
            .execute(&mut **tx)
            .await?;
            sqlx::query(
                "UPDATE nodes
                 SET status = 'queued',
                     cancellation_requested_at = NULL
                 WHERE organization_id = $1
                   AND id = $2
                   AND logical_outcome IS NULL",
            )
            .bind(organization_id)
            .bind(node_id)
            .execute(&mut **tx)
            .await?;
            append_event_and_outbox(
                tx,
                organization_id,
                build_id,
                "dag.node_retry_scheduled",
                json!({
                    "node_id": node_id,
                    "node_key": node_key,
                    "attempt_id": retry_id,
                    "ordinal": ordinal + 1,
                    "max_attempts": max_attempts,
                }),
            )
            .await?;
            return Ok(true);
        }
    }

    let node_outcome = outcome.as_str();
    let won = sqlx::query_scalar::<_, Uuid>(
        "UPDATE nodes
         SET status = $3,
             logical_outcome = $3,
             cancellation_requested_at = NULL
         WHERE organization_id = $1
           AND id = $2
           AND logical_outcome IS NULL
         RETURNING id",
    )
    .bind(organization_id)
    .bind(node_id)
    .bind(node_outcome)
    .fetch_optional(&mut **tx)
    .await?;
    if won.is_none() {
        return Ok(true);
    }

    if outcome == TerminalOutcome::Failed && fail_fast {
        sqlx::query(
            "UPDATE nodes
             SET cancellation_requested_at = clock_timestamp()
             WHERE organization_id = $1
               AND build_id = $2
               AND id <> $3
               AND status IN ('offered', 'running')",
        )
        .bind(organization_id)
        .bind(build_id)
        .bind(node_id)
        .execute(&mut **tx)
        .await?;
        sqlx::query(
            "UPDATE attempts AS a
             SET status = 'cancelling'
             FROM nodes AS n
             WHERE a.organization_id = $1
               AND n.organization_id = a.organization_id
               AND n.build_id = $2
               AND n.id = a.node_id
               AND n.id <> $3
               AND n.status IN ('offered', 'running')
               AND a.status IN ('offered', 'accepted', 'running', 'finalizing')",
        )
        .bind(organization_id)
        .bind(build_id)
        .bind(node_id)
        .execute(&mut **tx)
        .await?;
        mark_unstarted_skipped(tx, organization_id, build_id, true).await?;
    }

    advance_blocked_nodes(tx, organization_id, build_id).await?;
    derive_build_outcome(tx, organization_id, build_id).await?;
    append_event_and_outbox(
        tx,
        organization_id,
        build_id,
        "dag.node_terminal",
        json!({
            "node_id": node_id,
            "node_key": node_key,
            "attempt_id": attempt_id,
            "outcome": node_outcome,
            "fail_fast": fail_fast,
        }),
    )
    .await?;
    Ok(true)
}

pub(crate) async fn cancel_dag_build(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    build_id: Uuid,
) -> Result<bool, StoreError> {
    let requested = sqlx::query_scalar::<_, Uuid>(
        "UPDATE builds
         SET cancellation_requested_at = clock_timestamp()
         WHERE organization_id = $1
           AND id = $2
           AND dag_mode
           AND status IN ('queued', 'running')
           AND cancellation_requested_at IS NULL
         RETURNING id",
    )
    .bind(organization_id)
    .bind(build_id)
    .fetch_optional(&mut **tx)
    .await?;
    if requested.is_none() {
        return Ok(false);
    }
    sqlx::query(
        "UPDATE attempts AS a
         SET status = 'aborted',
             terminal_summary = $3,
             completed_at = clock_timestamp()
         FROM nodes AS n
         WHERE a.organization_id = $1
           AND n.organization_id = a.organization_id
           AND n.build_id = $2
           AND n.id = a.node_id
           AND n.status IN ('blocked', 'queued')
           AND a.status = 'queued'",
    )
    .bind(organization_id)
    .bind(build_id)
    .bind(json!({"reason": "dag_cancelled_before_execution"}))
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "UPDATE nodes
         SET status = 'aborted',
             logical_outcome = 'aborted'
         WHERE organization_id = $1
           AND build_id = $2
           AND status IN ('blocked', 'queued')
           AND logical_outcome IS NULL",
    )
    .bind(organization_id)
    .bind(build_id)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "UPDATE nodes
         SET cancellation_requested_at = clock_timestamp()
         WHERE organization_id = $1
           AND build_id = $2
           AND status IN ('offered', 'running')",
    )
    .bind(organization_id)
    .bind(build_id)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "UPDATE attempts AS a
         SET status = 'cancelling'
         FROM nodes AS n
         WHERE a.organization_id = $1
           AND n.organization_id = a.organization_id
           AND n.build_id = $2
           AND n.id = a.node_id
           AND n.status IN ('offered', 'running')
           AND a.status IN ('offered', 'accepted', 'running', 'finalizing')",
    )
    .bind(organization_id)
    .bind(build_id)
    .execute(&mut **tx)
    .await?;
    derive_build_outcome(tx, organization_id, build_id).await?;
    Ok(true)
}

async fn mark_unstarted_skipped(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    build_id: Uuid,
    exclude_post: bool,
) -> Result<(), StoreError> {
    sqlx::query(
        "UPDATE attempts AS a
         SET status = 'aborted',
             terminal_summary = $4,
             completed_at = clock_timestamp()
         FROM nodes AS n
         WHERE a.organization_id = $1
           AND n.organization_id = a.organization_id
           AND n.build_id = $2
           AND n.id = a.node_id
           AND n.status IN ('blocked', 'queued')
           AND ($3 = false OR n.node_kind <> 'post')
           AND a.status = 'queued'",
    )
    .bind(organization_id)
    .bind(build_id)
    .bind(exclude_post)
    .bind(json!({"reason": "fail_fast_skipped"}))
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "UPDATE nodes
         SET status = 'skipped',
             logical_outcome = 'skipped'
         WHERE organization_id = $1
           AND build_id = $2
           AND status IN ('blocked', 'queued')
           AND ($3 = false OR node_kind <> 'post')
           AND logical_outcome IS NULL",
    )
    .bind(organization_id)
    .bind(build_id)
    .bind(exclude_post)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn advance_blocked_nodes(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    build_id: Uuid,
) -> Result<(), StoreError> {
    loop {
        let skipped = sqlx::query(
            "UPDATE nodes AS child
             SET status = 'skipped',
                 logical_outcome = 'skipped'
             WHERE child.organization_id = $1
               AND child.build_id = $2
               AND child.status = 'blocked'
               AND child.node_kind <> 'post'
               AND EXISTS (
                   SELECT 1
                   FROM node_dependencies AS dependency
                   JOIN nodes AS parent
                     ON parent.id = dependency.parent_node_id
                    AND parent.organization_id = dependency.organization_id
                   WHERE dependency.organization_id = child.organization_id
                     AND dependency.child_node_id = child.id
                     AND dependency.condition = 'succeeded'
                     AND parent.status IN ('failed', 'aborted', 'skipped')
               )",
        )
        .bind(organization_id)
        .bind(build_id)
        .execute(&mut **tx)
        .await?
        .rows_affected();
        if skipped > 0 {
            sqlx::query(
                "UPDATE attempts AS a
                 SET status = 'aborted',
                     terminal_summary = $3,
                     completed_at = clock_timestamp()
                 FROM nodes AS n
                 WHERE a.organization_id = $1
                   AND n.organization_id = a.organization_id
                   AND n.build_id = $2
                   AND n.id = a.node_id
                   AND n.status = 'skipped'
                   AND a.status = 'queued'",
            )
            .bind(organization_id)
            .bind(build_id)
            .bind(json!({"reason": "dependency_not_succeeded"}))
            .execute(&mut **tx)
            .await?;
        }
        let readied = sqlx::query(
            "UPDATE nodes AS child
             SET status = 'queued',
                 queued_at = clock_timestamp()
             WHERE child.organization_id = $1
               AND child.build_id = $2
               AND child.status = 'blocked'
               AND NOT EXISTS (
                   SELECT 1
                   FROM node_dependencies AS dependency
                   JOIN nodes AS parent
                     ON parent.id = dependency.parent_node_id
                    AND parent.organization_id = dependency.organization_id
                   WHERE dependency.organization_id = child.organization_id
                     AND dependency.child_node_id = child.id
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
               )",
        )
        .bind(organization_id)
        .bind(build_id)
        .execute(&mut **tx)
        .await?
        .rows_affected();
        if skipped == 0 && readied == 0 {
            break;
        }
    }
    Ok(())
}

async fn derive_build_outcome(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    build_id: Uuid,
) -> Result<(), StoreError> {
    let counts = sqlx::query(
        "SELECT
             count(*) FILTER (
                 WHERE status NOT IN ('succeeded', 'failed', 'aborted', 'skipped')
             ) AS pending,
             count(*) FILTER (WHERE logical_outcome = 'failed') AS failed,
             count(*) FILTER (WHERE logical_outcome = 'aborted') AS aborted,
             count(*) FILTER (WHERE status IN ('offered', 'running')) AS active,
             count(*) FILTER (
                 WHERE status = 'reconciliation_required'
             ) AS reconciliation_required,
             bool_or(cancellation_requested_at IS NOT NULL) AS node_cancelled
         FROM nodes
         WHERE organization_id = $1 AND build_id = $2",
    )
    .bind(organization_id)
    .bind(build_id)
    .fetch_one(&mut **tx)
    .await?;
    let pending: i64 = counts.try_get("pending")?;
    let failed: i64 = counts.try_get("failed")?;
    let aborted: i64 = counts.try_get("aborted")?;
    let active: i64 = counts.try_get("active")?;
    let reconciliation_required: i64 = counts.try_get("reconciliation_required")?;
    let node_cancelled: Option<bool> = counts.try_get("node_cancelled")?;
    if pending == 0 {
        let owner_cancelled = sqlx::query_scalar::<_, bool>(
            "SELECT cancellation_requested_at IS NOT NULL
             FROM builds
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(organization_id)
        .bind(build_id)
        .fetch_one(&mut **tx)
        .await?;
        let status = if failed > 0 {
            "failed"
        } else if owner_cancelled || aborted > 0 {
            "aborted"
        } else {
            "succeeded"
        };
        sqlx::query(
            "UPDATE builds
             SET status = $3, completed_at = clock_timestamp()
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(organization_id)
        .bind(build_id)
        .bind(status)
        .execute(&mut **tx)
        .await?;
    } else {
        let status = if reconciliation_required > 0 {
            "reconciliation_required"
        } else if active > 0 || node_cancelled.unwrap_or(false) {
            "running"
        } else {
            "queued"
        };
        sqlx::query(
            "UPDATE builds
             SET status = $3, completed_at = NULL
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(organization_id)
        .bind(build_id)
        .bind(status)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

async fn existing_dag_admission(
    tx: &mut Transaction<'_, Postgres>,
    input: &NewDagBuild,
    contract: &Value,
) -> Result<DagAdmission, StoreError> {
    let row = sqlx::query_as::<_, (Uuid, Vec<u8>, bool, bool)>(
        "SELECT id, pipeline_digest, dag_mode,
                dag_contract IS NOT DISTINCT FROM $3 AS contract_matches
         FROM builds
         WHERE project_id = $1 AND idempotency_key = $2",
    )
    .bind(input.project_id)
    .bind(&input.idempotency_key)
    .bind(contract)
    .fetch_one(&mut **tx)
    .await?;
    let (build_id, digest, dag_mode, contract_matches) = row;
    if !dag_mode || digest != input.pipeline_digest || !contract_matches {
        return Err(StoreError::InvalidDag(
            "idempotency key already belongs to a different build contract".to_owned(),
        ));
    }
    let rows = sqlx::query_as::<_, (String, Uuid, Uuid)>(
        "SELECT n.node_key, n.id, a.id
         FROM nodes AS n
         JOIN attempts AS a
           ON a.node_id = n.id
          AND a.organization_id = n.organization_id
          AND a.ordinal = 1
         WHERE n.organization_id = $1 AND n.build_id = $2
         ORDER BY n.node_key",
    )
    .bind(input.organization_id)
    .bind(build_id)
    .fetch_all(&mut **tx)
    .await?;
    let nodes = rows
        .into_iter()
        .map(|(key, node_id, attempt_id)| {
            (
                key,
                DagNodeAdmission {
                    node_id,
                    attempt_id,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    if nodes.len() != input.nodes.len()
        || input
            .nodes
            .iter()
            .any(|node| !nodes.contains_key(&node.node_key))
    {
        return Err(StoreError::InvalidDag(
            "idempotent DAG exists with a different node contract".to_owned(),
        ));
    }
    Ok(DagAdmission {
        build_id,
        nodes,
        created: false,
    })
}

fn normalized_dag_contract(input: &NewDagBuild) -> Value {
    let mut nodes = input.nodes.iter().collect::<Vec<_>>();
    nodes.sort_by(|left, right| left.node_key.cmp(&right.node_key));
    let nodes = nodes
        .into_iter()
        .map(|node| {
            let mut dependencies = node.dependencies.iter().collect::<Vec<_>>();
            dependencies.sort_by(|left, right| {
                left.node_key
                    .cmp(&right.node_key)
                    .then_with(|| left.condition.as_str().cmp(right.condition.as_str()))
            });
            let dependencies = dependencies
                .into_iter()
                .map(|dependency| {
                    json!({
                        "node_key": dependency.node_key,
                        "condition": dependency.condition.as_str(),
                    })
                })
                .collect::<Vec<_>>();
            let mut capabilities = node.required_capabilities.clone();
            capabilities.push(format!("platform:{}", node.required_platform));
            capabilities.sort();
            capabilities.dedup();
            json!({
                "node_key": node.node_key,
                "kind": node.kind.as_str(),
                "dependencies": dependencies,
                "required_capabilities": capabilities,
                "required_platform": node.required_platform,
                "required_trust_pool": node.required_trust_pool,
                "priority": node.priority,
                "execution_spec": node.execution_spec,
                "fail_fast": node.fail_fast,
                "max_attempts": node.max_attempts,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "version": 1,
        "priority": input.priority,
        "nodes": nodes,
    })
}

/// Validates the complete bounded DAG contract without requiring a database.
pub fn validate_dag_contract(input: &NewDagBuild) -> Result<(), DagContractError> {
    validate_text("$.idempotency_key", &input.idempotency_key)?;
    if input.nodes.is_empty() || input.nodes.len() > MAX_DAG_NODES {
        return Err(DagContractError::new(
            DagContractErrorCode::NodeLimit,
            "$.nodes",
            format!("DAG node count must be between 1 and {MAX_DAG_NODES}"),
        ));
    }
    let mut keys = BTreeSet::new();
    for node in &input.nodes {
        validate_node_key("$.nodes.node_key", &node.node_key)?;
        if !keys.insert(node.node_key.clone()) {
            return Err(DagContractError::new(
                DagContractErrorCode::DuplicateNode,
                format!("$.nodes.{}", node.node_key),
                "DAG node keys must be unique",
            ));
        }
    }
    let mut edges = 0_usize;
    let mut indegree = BTreeMap::new();
    let mut children: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for node in &input.nodes {
        validate_text(
            &format!("$.nodes.{}.required_platform", node.node_key),
            &node.required_platform,
        )?;
        validate_text(
            &format!("$.nodes.{}.required_trust_pool", node.node_key),
            &node.required_trust_pool,
        )?;
        if node.required_capabilities.len() > MAX_DAG_CAPABILITIES {
            return Err(DagContractError::new(
                DagContractErrorCode::CapabilityLimit,
                format!("$.nodes.{}.required_capabilities", node.node_key),
                format!("capability count exceeds {MAX_DAG_CAPABILITIES}"),
            ));
        }
        let mut capabilities = BTreeSet::new();
        for capability in &node.required_capabilities {
            validate_text(
                &format!("$.nodes.{}.required_capabilities", node.node_key),
                capability,
            )?;
            if !capabilities.insert(capability) {
                return Err(DagContractError::new(
                    DagContractErrorCode::DuplicateCapability,
                    format!("$.nodes.{}.required_capabilities", node.node_key),
                    "capabilities must be unique",
                ));
            }
        }
        if !(1..=16).contains(&node.max_attempts) {
            return Err(DagContractError::new(
                DagContractErrorCode::RetryLimit,
                format!("$.nodes.{}.max_attempts", node.node_key),
                "max_attempts must be between 1 and 16",
            ));
        }
        if serde_json::to_vec(&node.execution_spec)
            .map_err(|error| {
                DagContractError::new(
                    DagContractErrorCode::ExecutionSpecLimit,
                    format!("$.nodes.{}.execution_spec", node.node_key),
                    error.to_string(),
                )
            })?
            .len()
            > MAX_EXECUTION_SPEC_BYTES
        {
            return Err(DagContractError::new(
                DagContractErrorCode::ExecutionSpecLimit,
                format!("$.nodes.{}.execution_spec", node.node_key),
                format!("execution specification exceeds {MAX_EXECUTION_SPEC_BYTES} bytes"),
            ));
        }
        let platform_capability = format!("platform:{}", node.required_platform);
        if node.required_capabilities.iter().any(|capability| {
            capability.starts_with("platform:") && capability != &platform_capability
        }) {
            return Err(DagContractError::new(
                DagContractErrorCode::PlatformMismatch,
                format!("$.nodes.{}.required_capabilities", node.node_key),
                "platform capability conflicts with required_platform",
            ));
        }
        if node.kind == DagNodeKind::Join && node.dependencies.len() < 2 {
            return Err(DagContractError::new(
                DagContractErrorCode::InvalidNodeKind,
                format!("$.nodes.{}.dependencies", node.node_key),
                "join nodes require at least two dependencies",
            ));
        }
        if node.kind == DagNodeKind::Post
            && (node.dependencies.is_empty()
                || node
                    .dependencies
                    .iter()
                    .any(|dependency| dependency.condition != DependencyCondition::Completed))
        {
            return Err(DagContractError::new(
                DagContractErrorCode::InvalidNodeKind,
                format!("$.nodes.{}.dependencies", node.node_key),
                "post nodes require one or more completion dependencies",
            ));
        }
        let mut parents = BTreeSet::new();
        for dependency in &node.dependencies {
            edges += 1;
            if edges > MAX_DAG_EDGES {
                return Err(DagContractError::new(
                    DagContractErrorCode::EdgeLimit,
                    "$.nodes",
                    format!("DAG edge count exceeds {MAX_DAG_EDGES}"),
                ));
            }
            if !keys.contains(&dependency.node_key) {
                return Err(DagContractError::new(
                    DagContractErrorCode::MissingDependency,
                    format!("$.nodes.{}.dependencies", node.node_key),
                    format!("dependency {:?} does not exist", dependency.node_key),
                ));
            }
            if dependency.node_key == node.node_key || !parents.insert(&dependency.node_key) {
                return Err(DagContractError::new(
                    DagContractErrorCode::DuplicateDependency,
                    format!("$.nodes.{}.dependencies", node.node_key),
                    "dependencies must be distinct and cannot reference the node itself",
                ));
            }
            children
                .entry(dependency.node_key.clone())
                .or_default()
                .push(node.node_key.clone());
        }
        indegree.insert(node.node_key.clone(), node.dependencies.len());
    }
    let mut ready = indegree
        .iter()
        .filter_map(|(key, degree)| (*degree == 0).then_some(key.clone()))
        .collect::<BTreeSet<_>>();
    let mut visited = 0_usize;
    while let Some(key) = ready.pop_first() {
        visited += 1;
        for child in children.get(&key).into_iter().flatten() {
            let degree = indegree.get_mut(child).expect("validated child");
            *degree -= 1;
            if *degree == 0 {
                ready.insert(child.clone());
            }
        }
    }
    if visited != input.nodes.len() {
        return Err(DagContractError::new(
            DagContractErrorCode::Cycle,
            "$.nodes",
            "DAG contains a dependency cycle",
        ));
    }
    Ok(())
}

fn validate_text(path: &str, value: &str) -> Result<(), DagContractError> {
    if value.is_empty()
        || value.len() > MAX_DAG_TEXT_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(DagContractError::new(
            DagContractErrorCode::InvalidText,
            path,
            "must be bounded ASCII letters, digits, dot, underscore, or hyphen",
        ));
    }
    Ok(())
}

fn validate_node_key(path: &str, value: &str) -> Result<(), DagContractError> {
    if value.is_empty()
        || value.len() > MAX_DAG_TEXT_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'-' | b'[' | b']' | b'=' | b',')
        })
    {
        return Err(DagContractError::new(
            DagContractErrorCode::InvalidText,
            path,
            "must be a bounded canonical DAG node key",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DagContractErrorCode {
    InvalidText,
    MatrixAxisLimit,
    MatrixValueLimit,
    MatrixCellLimit,
    DuplicateMatrixValue,
    NodeLimit,
    EdgeLimit,
    DuplicateNode,
    MissingDependency,
    DuplicateDependency,
    Cycle,
    RetryLimit,
    InvalidNodeKind,
    PlatformMismatch,
    CapabilityLimit,
    DuplicateCapability,
    ExecutionSpecLimit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DagContractError {
    pub code: DagContractErrorCode,
    pub path: String,
    pub message: String,
}

impl DagContractError {
    fn new(
        code: DagContractErrorCode,
        path: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            path: path.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for DagContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.path, self.message)
    }
}

impl std::error::Error for DagContractError {}
