use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::Row;
use uuid::Uuid;

use crate::{Store, StoreError};

pub const MAX_PRODUCT_PAGE: u32 = 200;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PipelineWrite {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub pipeline_id: Uuid,
    pub slug: String,
    pub source: String,
    pub source_sha256: [u8; 32],
    pub semantic_digest: [u8; 32],
    pub schema_major: i32,
    pub schema_minor: i32,
    pub parameter_schema: Value,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PipelineRecord {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub pipeline_id: Uuid,
    pub slug: String,
    pub revision: i64,
    pub source: String,
    pub source_sha256: [u8; 32],
    pub semantic_digest: [u8; 32],
    pub schema_major: i32,
    pub schema_minor: i32,
    pub parameter_schema: Value,
    pub created_at_unix_ms: i64,
    pub updated_at_unix_ms: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum PipelinePutOutcome {
    Created(PipelineRecord),
    Updated(PipelineRecord),
    Unchanged(PipelineRecord),
    PreconditionFailed { current_revision: i64 },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PipelinePage {
    pub items: Vec<PipelineRecord>,
    pub next_after: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComponentWrite {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub digest: [u8; 32],
    pub name: String,
    pub version_major: i32,
    pub version_minor: i32,
    pub canonical_bytes: Vec<u8>,
    pub source_sha256: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComponentRecord {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub digest: [u8; 32],
    pub name: String,
    pub version_major: i32,
    pub version_minor: i32,
    pub canonical_bytes: Vec<u8>,
    pub source_sha256: [u8; 32],
    pub created_at_unix_ms: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComponentPage {
    pub items: Vec<ComponentRecord>,
    pub next_after: Option<ComponentCursor>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComponentCursor {
    pub name: String,
    pub digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ComponentPutOutcome {
    Created,
    Unchanged,
    Conflict,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BuildListItem {
    pub build_id: Uuid,
    pub pipeline_digest: [u8; 32],
    pub status: String,
    pub priority: i32,
    pub dag_mode: bool,
    pub created_at_unix_ms: i64,
    pub created_at_unix_micros: i64,
    pub completed_at_unix_ms: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BuildPage {
    pub items: Vec<BuildListItem>,
    pub next_after: Option<BuildCursor>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BuildCursor {
    pub created_at_unix_micros: i64,
    pub build_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodeView {
    pub node_id: Uuid,
    pub node_key: String,
    pub kind: String,
    pub status: String,
    pub logical_outcome: Option<String>,
    pub fail_fast: bool,
    pub max_attempts: i32,
    pub required_platform: String,
    pub required_trust_pool: String,
    pub cancellation_requested: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttemptView {
    pub attempt_id: Uuid,
    pub node_id: Uuid,
    pub ordinal: i32,
    pub status: String,
    pub fence: i64,
    pub lease_owner: Option<String>,
    pub terminal_summary: Option<Value>,
    pub created_at_unix_ms: i64,
    pub started_at_unix_ms: Option<i64>,
    pub completed_at_unix_ms: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DependencyView {
    pub parent_node_id: Uuid,
    pub child_node_id: Uuid,
    pub condition: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BuildGraph {
    pub build: BuildListItem,
    pub nodes: Vec<NodeView>,
    pub attempts: Vec<AttemptView>,
    pub dependencies: Vec<DependencyView>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ApprovalView {
    pub approval_id: Uuid,
    pub build_id: Uuid,
    pub environment: String,
    pub action: String,
    pub approver_subject: String,
    pub expires_at_unix_ms: i64,
    pub consumed_by_attempt: Option<Uuid>,
    pub consumed_fence: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CredentialGrantView {
    pub grant_id: Uuid,
    pub build_id: Uuid,
    pub attempt_id: Uuid,
    pub fence: i64,
    pub environment: String,
    pub action: String,
    pub target_name: String,
    pub expires_at_unix_ms: i64,
    pub delivered: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TestReportView {
    pub report_id: Uuid,
    pub build_id: Uuid,
    pub node_id: Uuid,
    pub attempt_id: Uuid,
    pub fence: i64,
    pub schema_version: i32,
    pub raw_artifact_name: String,
    pub raw_object_digest: [u8; 32],
    pub aggregate: Value,
    pub created_at_unix_ms: i64,
}

impl Store {
    pub async fn put_pipeline(
        &self,
        input: &PipelineWrite,
        expected_revision: Option<i64>,
    ) -> Result<PipelinePutOutcome, StoreError> {
        self.put_pipeline_as(input, expected_revision, "system:controller")
            .await
    }

    pub async fn put_pipeline_as(
        &self,
        input: &PipelineWrite,
        expected_revision: Option<i64>,
        actor_subject: &str,
    ) -> Result<PipelinePutOutcome, StoreError> {
        validate_pipeline_write(input)?;
        if actor_subject.is_empty() || actor_subject.trim() != actor_subject {
            return Err(StoreError::InvalidProductOperation(
                "pipeline audit actor must be non-empty and canonical".to_owned(),
            ));
        }
        if expected_revision.is_some_and(|revision| revision < 0) {
            return Err(StoreError::InvalidProductOperation(
                "pipeline revision precondition must be non-negative".to_owned(),
            ));
        }
        let mut tx = self.tenant_transaction(input.organization_id).await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!(
                "mcloving.pipeline.{}.{}",
                input.organization_id, input.pipeline_id
            ))
            .execute(&mut *tx)
            .await?;
        let existing_project = sqlx::query_scalar::<_, Uuid>(
            "SELECT project_id
             FROM pipeline_definitions
             WHERE organization_id = $1
               AND pipeline_id = $2",
        )
        .bind(input.organization_id)
        .bind(input.pipeline_id)
        .fetch_optional(&mut *tx)
        .await?;
        if existing_project.is_some_and(|project_id| project_id != input.project_id) {
            tx.rollback().await?;
            return Err(StoreError::ProductConflict(format!(
                "pipeline id '{}' is already in use in another project",
                input.pipeline_id
            )));
        }
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!(
                "mcloving.pipeline.slug.{}.{}.{}",
                input.organization_id, input.project_id, input.slug
            ))
            .execute(&mut *tx)
            .await?;
        let conflicting_pipeline = sqlx::query_scalar::<_, Uuid>(
            "SELECT pipeline_id
             FROM pipeline_definitions
             WHERE organization_id = $1
               AND project_id = $2
               AND slug = $3
               AND pipeline_id <> $4",
        )
        .bind(input.organization_id)
        .bind(input.project_id)
        .bind(&input.slug)
        .bind(input.pipeline_id)
        .fetch_optional(&mut *tx)
        .await?;
        if conflicting_pipeline.is_some() {
            tx.rollback().await?;
            return Err(StoreError::ProductConflict(format!(
                "pipeline slug '{}' is already in use in this project",
                input.slug
            )));
        }
        let current = sqlx::query(
            "SELECT current_revision
             FROM pipeline_definitions
             WHERE organization_id = $1
               AND project_id = $2
               AND pipeline_id = $3
             FOR UPDATE",
        )
        .bind(input.organization_id)
        .bind(input.project_id)
        .bind(input.pipeline_id)
        .fetch_optional(&mut *tx)
        .await?;

        let (revision, outcome_kind) = if let Some(row) = current {
            let current_revision: i64 = row.try_get("current_revision")?;
            if expected_revision != Some(current_revision) {
                tx.rollback().await?;
                return Ok(PipelinePutOutcome::PreconditionFailed { current_revision });
            }
            let same = sqlx::query_scalar::<_, bool>(
                "SELECT d.slug = $4
                        AND r.source = $5
                        AND r.source_sha256 = $6
                        AND r.semantic_digest = $7
                        AND r.schema_major = $8
                        AND r.schema_minor = $9
                        AND r.parameter_schema = $10
                 FROM pipeline_revisions AS r
                 JOIN pipeline_definitions AS d
                   ON d.organization_id = r.organization_id
                  AND d.pipeline_id = r.pipeline_id
                 WHERE r.organization_id = $1
                   AND r.pipeline_id = $2
                   AND r.revision = $3",
            )
            .bind(input.organization_id)
            .bind(input.pipeline_id)
            .bind(current_revision)
            .bind(&input.slug)
            .bind(&input.source)
            .bind(input.source_sha256.as_slice())
            .bind(input.semantic_digest.as_slice())
            .bind(input.schema_major)
            .bind(input.schema_minor)
            .bind(&input.parameter_schema)
            .fetch_one(&mut *tx)
            .await?;
            if same {
                let record = pipeline_record_in_transaction(
                    &mut tx,
                    input.organization_id,
                    input.pipeline_id,
                )
                .await?
                .ok_or(StoreError::IncompleteAdmission)?;
                tx.commit().await?;
                return Ok(PipelinePutOutcome::Unchanged(record));
            }
            (current_revision + 1, 1_u8)
        } else {
            if expected_revision.is_some_and(|revision| revision != 0) {
                tx.rollback().await?;
                return Ok(PipelinePutOutcome::PreconditionFailed {
                    current_revision: 0,
                });
            }
            sqlx::query(
                "INSERT INTO pipeline_definitions (
                     organization_id, project_id, pipeline_id, slug
                 )
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(input.organization_id)
            .bind(input.project_id)
            .bind(input.pipeline_id)
            .bind(&input.slug)
            .execute(&mut *tx)
            .await?;
            (1_i64, 0_u8)
        };

        sqlx::query(
            "INSERT INTO pipeline_revisions (
                 organization_id, project_id, pipeline_id, revision,
                 source, source_sha256, semantic_digest,
                 schema_major, schema_minor, parameter_schema
             )
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(input.organization_id)
        .bind(input.project_id)
        .bind(input.pipeline_id)
        .bind(revision)
        .bind(&input.source)
        .bind(input.source_sha256.as_slice())
        .bind(input.semantic_digest.as_slice())
        .bind(input.schema_major)
        .bind(input.schema_minor)
        .bind(&input.parameter_schema)
        .execute(&mut *tx)
        .await?;
        if revision > 1 {
            sqlx::query(
                "UPDATE pipeline_definitions
                 SET current_revision = $4,
                     slug = $5,
                     updated_at = clock_timestamp()
                 WHERE organization_id = $1
                   AND project_id = $2
                   AND pipeline_id = $3",
            )
            .bind(input.organization_id)
            .bind(input.project_id)
            .bind(input.pipeline_id)
            .bind(revision)
            .bind(&input.slug)
            .execute(&mut *tx)
            .await?;
        }
        crate::audit::append_audit_record(
            &mut tx,
            input.organization_id,
            "pipeline",
            actor_subject,
            if outcome_kind == 0 {
                "pipeline.created"
            } else {
                "pipeline.revised"
            },
            &format!(
                "project:{}:pipeline:{}",
                input.project_id, input.pipeline_id
            ),
            json!({
                "project_id": input.project_id,
                "pipeline_id": input.pipeline_id,
                "revision": revision,
                "semantic_digest": hex::encode(input.semantic_digest),
            }),
        )
        .await?;
        let record =
            pipeline_record_in_transaction(&mut tx, input.organization_id, input.pipeline_id)
                .await?
                .ok_or(StoreError::IncompleteAdmission)?;
        tx.commit().await?;
        Ok(if outcome_kind == 0 {
            PipelinePutOutcome::Created(record)
        } else {
            PipelinePutOutcome::Updated(record)
        })
    }

    pub async fn pipeline(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        pipeline_id: Uuid,
    ) -> Result<Option<PipelineRecord>, StoreError> {
        let mut tx = self.tenant_transaction(organization_id).await?;
        let record = pipeline_record_in_transaction(&mut tx, organization_id, pipeline_id).await?;
        if record
            .as_ref()
            .is_some_and(|record| record.project_id != project_id)
        {
            tx.rollback().await?;
            return Ok(None);
        }
        tx.commit().await?;
        Ok(record)
    }

    pub async fn pipelines(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        after_slug: Option<&str>,
        limit: u32,
    ) -> Result<PipelinePage, StoreError> {
        validate_page(limit)?;
        let mut tx = self.tenant_transaction(organization_id).await?;
        let rows = sqlx::query(
            "SELECT d.organization_id, d.project_id, d.pipeline_id, d.slug,
                    d.current_revision AS revision, r.source,
                    r.source_sha256, r.semantic_digest,
                    r.schema_major, r.schema_minor, r.parameter_schema,
                    (EXTRACT(EPOCH FROM d.created_at) * 1000)::bigint AS created_ms,
                    (EXTRACT(EPOCH FROM d.updated_at) * 1000)::bigint AS updated_ms
             FROM pipeline_definitions AS d
             JOIN pipeline_revisions AS r
               ON r.organization_id = d.organization_id
              AND r.pipeline_id = d.pipeline_id
              AND r.revision = d.current_revision
             WHERE d.organization_id = $1
               AND d.project_id = $2
               AND ($3::text IS NULL OR d.slug > $3)
             ORDER BY d.slug, d.pipeline_id
             LIMIT $4",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(after_slug)
        .bind(i64::from(limit) + 1)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        let mut items = rows
            .iter()
            .map(pipeline_record_from_row)
            .collect::<Result<Vec<_>, StoreError>>()?;
        let next_after = (items.len() > limit as usize).then(|| {
            items
                .get(limit as usize - 1)
                .expect("positive bounded page has a cursor")
                .slug
                .clone()
        });
        items.truncate(limit as usize);
        Ok(PipelinePage { items, next_after })
    }

    pub async fn register_component(
        &self,
        input: &ComponentWrite,
    ) -> Result<ComponentPutOutcome, StoreError> {
        self.register_component_as(input, "system:controller").await
    }

    pub async fn register_component_as(
        &self,
        input: &ComponentWrite,
        actor_subject: &str,
    ) -> Result<ComponentPutOutcome, StoreError> {
        validate_component_write(input)?;
        crate::validate_audit_actor(actor_subject)?;
        let mut tx = self.tenant_transaction(input.organization_id).await?;
        let inserted = sqlx::query_scalar::<_, Vec<u8>>(
            "INSERT INTO component_packages (
                 organization_id, project_id, digest, name,
                 version_major, version_minor, canonical_bytes, source_sha256
             )
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (organization_id, digest) DO NOTHING
             RETURNING digest",
        )
        .bind(input.organization_id)
        .bind(input.project_id)
        .bind(input.digest.as_slice())
        .bind(&input.name)
        .bind(input.version_major)
        .bind(input.version_minor)
        .bind(&input.canonical_bytes)
        .bind(input.source_sha256.as_slice())
        .fetch_optional(&mut *tx)
        .await?;
        if inserted.is_none() {
            let exact = sqlx::query_scalar::<_, bool>(
                "SELECT project_id = $3
                        AND name = $4
                        AND version_major = $5
                        AND version_minor = $6
                        AND canonical_bytes = $7
                        AND source_sha256 = $8
                 FROM component_packages
                 WHERE organization_id = $1 AND digest = $2",
            )
            .bind(input.organization_id)
            .bind(input.digest.as_slice())
            .bind(input.project_id)
            .bind(&input.name)
            .bind(input.version_major)
            .bind(input.version_minor)
            .bind(&input.canonical_bytes)
            .bind(input.source_sha256.as_slice())
            .fetch_one(&mut *tx)
            .await?;
            tx.commit().await?;
            return Ok(if exact {
                ComponentPutOutcome::Unchanged
            } else {
                ComponentPutOutcome::Conflict
            });
        }
        crate::audit::append_audit_record(
            &mut tx,
            input.organization_id,
            "component",
            actor_subject,
            "component.registered",
            &format!(
                "project:{}:component:{}",
                input.project_id,
                hex::encode(input.digest)
            ),
            json!({
                "project_id": input.project_id,
                "digest": hex::encode(input.digest),
                "name": &input.name,
                "version_major": input.version_major,
                "version_minor": input.version_minor,
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(ComponentPutOutcome::Created)
    }

    pub async fn component(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        digest: [u8; 32],
    ) -> Result<Option<ComponentRecord>, StoreError> {
        let mut tx = self.tenant_transaction(organization_id).await?;
        let row = sqlx::query(
            "SELECT organization_id, project_id, digest, name,
                    version_major, version_minor, canonical_bytes, source_sha256,
                    (EXTRACT(EPOCH FROM created_at) * 1000)::bigint AS created_ms
             FROM component_packages
             WHERE organization_id = $1 AND project_id = $2 AND digest = $3",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(digest.as_slice())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        row.as_ref().map(component_record_from_row).transpose()
    }

    pub async fn components(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        after: Option<&ComponentCursor>,
        limit: u32,
    ) -> Result<ComponentPage, StoreError> {
        validate_page(limit)?;
        let after_name = after.map(|cursor| cursor.name.as_str());
        let after_digest = after.map(|cursor| cursor.digest.as_slice());
        let mut tx = self.tenant_transaction(organization_id).await?;
        let rows = sqlx::query(
            "SELECT organization_id, project_id, digest, name,
                    version_major, version_minor, canonical_bytes, source_sha256,
                    (EXTRACT(EPOCH FROM created_at) * 1000)::bigint AS created_ms
             FROM component_packages
             WHERE organization_id = $1
               AND project_id = $2
               AND (
                   $3::text IS NULL
                   OR (name, digest) > ($3, $4::bytea)
               )
             ORDER BY name, digest
             LIMIT $5",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(after_name)
        .bind(after_digest)
        .bind(i64::from(limit) + 1)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        let mut items = rows
            .iter()
            .map(component_record_from_row)
            .collect::<Result<Vec<_>, StoreError>>()?;
        let next_after = (items.len() > limit as usize).then(|| {
            let item = items
                .get(limit as usize - 1)
                .expect("positive bounded page has a cursor");
            ComponentCursor {
                name: item.name.clone(),
                digest: item.digest,
            }
        });
        items.truncate(limit as usize);
        Ok(ComponentPage { items, next_after })
    }

    pub async fn builds_page(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        after: Option<BuildCursor>,
        status: Option<&str>,
        limit: u32,
    ) -> Result<BuildPage, StoreError> {
        validate_page(limit)?;
        if status.is_some_and(|status| {
            !matches!(
                status,
                "queued" | "running" | "succeeded" | "failed" | "aborted"
            )
        }) {
            return Err(StoreError::InvalidProductOperation(
                "build status filter is invalid".to_owned(),
            ));
        }
        let after_created = after.map(|cursor| cursor.created_at_unix_micros);
        let after_id = after.map(|cursor| cursor.build_id);
        let mut tx = self.tenant_transaction(organization_id).await?;
        let rows = sqlx::query(
            "SELECT id, pipeline_digest, status, priority, dag_mode,
                    (EXTRACT(EPOCH FROM created_at) * 1000)::bigint AS created_ms,
                    (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint AS created_micros,
                    CASE WHEN completed_at IS NULL THEN NULL
                         ELSE (EXTRACT(EPOCH FROM completed_at) * 1000)::bigint
                    END AS completed_ms
             FROM builds
             WHERE organization_id = $1
               AND project_id = $2
               AND (
                   $3::bigint IS NULL
                   OR (created_at, id) < (
                       TIMESTAMPTZ 'epoch' + $3 * INTERVAL '1 microsecond',
                       $4::uuid
                   )
               )
               AND ($5::text IS NULL OR status = $5)
             ORDER BY created_at DESC, id DESC
             LIMIT $6",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(after_created)
        .bind(after_id)
        .bind(status)
        .bind(i64::from(limit) + 1)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        let mut items = rows
            .iter()
            .map(build_item_from_row)
            .collect::<Result<Vec<_>, StoreError>>()?;
        let next_after = (items.len() > limit as usize).then(|| {
            let item = items
                .get(limit as usize - 1)
                .expect("positive bounded page has a cursor");
            BuildCursor {
                created_at_unix_micros: item.created_at_unix_micros,
                build_id: item.build_id,
            }
        });
        items.truncate(limit as usize);
        Ok(BuildPage { items, next_after })
    }

    pub async fn build_graph(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        build_id: Uuid,
    ) -> Result<Option<BuildGraph>, StoreError> {
        let mut tx = self.tenant_transaction(organization_id).await?;
        let build = sqlx::query(
            "SELECT id, pipeline_digest, status, priority, dag_mode,
                    (EXTRACT(EPOCH FROM created_at) * 1000)::bigint AS created_ms,
                    (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint AS created_micros,
                    CASE WHEN completed_at IS NULL THEN NULL
                         ELSE (EXTRACT(EPOCH FROM completed_at) * 1000)::bigint
                    END AS completed_ms
             FROM builds
             WHERE organization_id = $1 AND project_id = $2 AND id = $3",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(build_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(build) = build else {
            tx.rollback().await?;
            return Ok(None);
        };
        let nodes = sqlx::query(
            "SELECT id, node_key, node_kind, status, logical_outcome,
                    fail_fast, max_attempts,
                    COALESCE(
                        (
                            SELECT substring(capability FROM 10)
                            FROM unnest(required_capabilities) AS capability
                            WHERE capability LIKE 'platform:%'
                            ORDER BY capability
                            LIMIT 1
                        ),
                        'linux'
                    ) AS required_platform,
                    required_trust_pool, cancellation_requested_at IS NOT NULL AS cancelled
             FROM nodes
             WHERE organization_id = $1 AND build_id = $2
             ORDER BY node_key, id",
        )
        .bind(organization_id)
        .bind(build_id)
        .fetch_all(&mut *tx)
        .await?;
        let attempts = sqlx::query(
            "SELECT a.id, a.node_id, a.ordinal, a.status, a.fence,
                    a.lease_owner, a.terminal_summary,
                    (EXTRACT(EPOCH FROM a.created_at) * 1000)::bigint AS created_ms,
                    (
                        SELECT (EXTRACT(EPOCH FROM e.created_at) * 1000)::bigint
                        FROM build_events AS e
                        WHERE e.organization_id = a.organization_id
                          AND e.build_id = n.build_id
                          AND e.kind = 'attempt.running'
                          AND e.payload @> jsonb_build_object(
                              'attempt_id', a.id,
                              'fence', a.fence
                          )
                        ORDER BY e.id
                        LIMIT 1
                    ) AS started_ms,
                    CASE WHEN a.completed_at IS NULL THEN NULL
                         ELSE (EXTRACT(EPOCH FROM a.completed_at) * 1000)::bigint
                    END AS completed_ms
             FROM attempts AS a
             JOIN nodes AS n
               ON n.organization_id = a.organization_id
              AND n.id = a.node_id
             WHERE a.organization_id = $1 AND n.build_id = $2
             ORDER BY n.node_key, a.ordinal",
        )
        .bind(organization_id)
        .bind(build_id)
        .fetch_all(&mut *tx)
        .await?;
        let dependencies = sqlx::query(
            "SELECT parent_node_id, child_node_id, condition
             FROM node_dependencies
             WHERE organization_id = $1 AND build_id = $2
             ORDER BY child_node_id, parent_node_id",
        )
        .bind(organization_id)
        .bind(build_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Some(BuildGraph {
            build: build_item_from_row(&build)?,
            nodes: nodes
                .iter()
                .map(|row| {
                    Ok(NodeView {
                        node_id: row.try_get("id")?,
                        node_key: row.try_get("node_key")?,
                        kind: row.try_get("node_kind")?,
                        status: row.try_get("status")?,
                        logical_outcome: row.try_get("logical_outcome")?,
                        fail_fast: row.try_get("fail_fast")?,
                        max_attempts: row.try_get("max_attempts")?,
                        required_platform: row.try_get("required_platform")?,
                        required_trust_pool: row.try_get("required_trust_pool")?,
                        cancellation_requested: row.try_get("cancelled")?,
                    })
                })
                .collect::<Result<Vec<_>, StoreError>>()?,
            attempts: attempts
                .iter()
                .map(|row| {
                    Ok(AttemptView {
                        attempt_id: row.try_get("id")?,
                        node_id: row.try_get("node_id")?,
                        ordinal: row.try_get("ordinal")?,
                        status: row.try_get("status")?,
                        fence: row.try_get("fence")?,
                        lease_owner: row.try_get("lease_owner")?,
                        terminal_summary: row.try_get("terminal_summary")?,
                        created_at_unix_ms: row.try_get("created_ms")?,
                        started_at_unix_ms: row.try_get("started_ms")?,
                        completed_at_unix_ms: row.try_get("completed_ms")?,
                    })
                })
                .collect::<Result<Vec<_>, StoreError>>()?,
            dependencies: dependencies
                .iter()
                .map(|row| {
                    Ok(DependencyView {
                        parent_node_id: row.try_get("parent_node_id")?,
                        child_node_id: row.try_get("child_node_id")?,
                        condition: row.try_get("condition")?,
                    })
                })
                .collect::<Result<Vec<_>, StoreError>>()?,
        }))
    }

    pub async fn approvals(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        build_id: Uuid,
    ) -> Result<Vec<ApprovalView>, StoreError> {
        let mut tx = self.tenant_transaction(organization_id).await?;
        let rows = sqlx::query(
            "SELECT id, build_id, environment, action, approver_subject,
                    (EXTRACT(EPOCH FROM expires_at) * 1000)::bigint AS expires_ms,
                    consumed_by_attempt, consumed_fence
             FROM environment_approvals
             WHERE organization_id = $1 AND project_id = $2 AND build_id = $3
             ORDER BY created_at, id",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(build_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.iter()
            .map(|row| {
                Ok(ApprovalView {
                    approval_id: row.try_get("id")?,
                    build_id: row.try_get("build_id")?,
                    environment: row.try_get("environment")?,
                    action: row.try_get("action")?,
                    approver_subject: row.try_get("approver_subject")?,
                    expires_at_unix_ms: row.try_get("expires_ms")?,
                    consumed_by_attempt: row.try_get("consumed_by_attempt")?,
                    consumed_fence: row.try_get("consumed_fence")?,
                })
            })
            .collect()
    }

    pub async fn credential_grants(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        build_id: Uuid,
    ) -> Result<Vec<CredentialGrantView>, StoreError> {
        let mut tx = self.tenant_transaction(organization_id).await?;
        let rows = sqlx::query(
            "SELECT id, build_id, attempt_id, fence, environment, action,
                    target_name,
                    (EXTRACT(EPOCH FROM expires_at) * 1000)::bigint AS expires_ms,
                    delivered_at IS NOT NULL AS delivered
             FROM credential_grants
             WHERE organization_id = $1 AND project_id = $2 AND build_id = $3
             ORDER BY created_at, id",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(build_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.iter()
            .map(|row| {
                Ok(CredentialGrantView {
                    grant_id: row.try_get("id")?,
                    build_id: row.try_get("build_id")?,
                    attempt_id: row.try_get("attempt_id")?,
                    fence: row.try_get("fence")?,
                    environment: row.try_get("environment")?,
                    action: row.try_get("action")?,
                    target_name: row.try_get("target_name")?,
                    expires_at_unix_ms: row.try_get("expires_ms")?,
                    delivered: row.try_get("delivered")?,
                })
            })
            .collect()
    }

    pub async fn test_reports(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        build_id: Uuid,
    ) -> Result<Vec<TestReportView>, StoreError> {
        let mut tx = self.tenant_transaction(organization_id).await?;
        let rows = sqlx::query(
            "SELECT report_id, build_id, node_id, attempt_id, fence,
                    schema_version, raw_artifact_name, raw_object_digest,
                    aggregate,
                    (EXTRACT(EPOCH FROM created_at) * 1000)::bigint AS created_ms
             FROM normalized_test_reports
             WHERE organization_id = $1 AND project_id = $2 AND build_id = $3
             ORDER BY created_at, report_id",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(build_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.iter()
            .map(|row| {
                Ok(TestReportView {
                    report_id: row.try_get("report_id")?,
                    build_id: row.try_get("build_id")?,
                    node_id: row.try_get("node_id")?,
                    attempt_id: row.try_get("attempt_id")?,
                    fence: row.try_get("fence")?,
                    schema_version: row.try_get("schema_version")?,
                    raw_artifact_name: row.try_get("raw_artifact_name")?,
                    raw_object_digest: digest(row.try_get("raw_object_digest")?)?,
                    aggregate: row.try_get("aggregate")?,
                    created_at_unix_ms: row.try_get("created_ms")?,
                })
            })
            .collect()
    }
}

async fn pipeline_record_in_transaction(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: Uuid,
    pipeline_id: Uuid,
) -> Result<Option<PipelineRecord>, StoreError> {
    let row = sqlx::query(
        "SELECT d.organization_id, d.project_id, d.pipeline_id, d.slug,
                d.current_revision AS revision, r.source,
                r.source_sha256, r.semantic_digest,
                r.schema_major, r.schema_minor, r.parameter_schema,
                (EXTRACT(EPOCH FROM d.created_at) * 1000)::bigint AS created_ms,
                (EXTRACT(EPOCH FROM d.updated_at) * 1000)::bigint AS updated_ms
         FROM pipeline_definitions AS d
         JOIN pipeline_revisions AS r
           ON r.organization_id = d.organization_id
          AND r.pipeline_id = d.pipeline_id
          AND r.revision = d.current_revision
         WHERE d.organization_id = $1 AND d.pipeline_id = $2",
    )
    .bind(organization_id)
    .bind(pipeline_id)
    .fetch_optional(&mut **tx)
    .await?;
    row.as_ref().map(pipeline_record_from_row).transpose()
}

fn pipeline_record_from_row(row: &sqlx::postgres::PgRow) -> Result<PipelineRecord, StoreError> {
    Ok(PipelineRecord {
        organization_id: row.try_get("organization_id")?,
        project_id: row.try_get("project_id")?,
        pipeline_id: row.try_get("pipeline_id")?,
        slug: row.try_get("slug")?,
        revision: row.try_get("revision")?,
        source: row.try_get("source")?,
        source_sha256: digest(row.try_get("source_sha256")?)?,
        semantic_digest: digest(row.try_get("semantic_digest")?)?,
        schema_major: row.try_get("schema_major")?,
        schema_minor: row.try_get("schema_minor")?,
        parameter_schema: row.try_get("parameter_schema")?,
        created_at_unix_ms: row.try_get("created_ms")?,
        updated_at_unix_ms: row.try_get("updated_ms")?,
    })
}

fn component_record_from_row(row: &sqlx::postgres::PgRow) -> Result<ComponentRecord, StoreError> {
    Ok(ComponentRecord {
        organization_id: row.try_get("organization_id")?,
        project_id: row.try_get("project_id")?,
        digest: digest(row.try_get("digest")?)?,
        name: row.try_get("name")?,
        version_major: row.try_get("version_major")?,
        version_minor: row.try_get("version_minor")?,
        canonical_bytes: row.try_get("canonical_bytes")?,
        source_sha256: digest(row.try_get("source_sha256")?)?,
        created_at_unix_ms: row.try_get("created_ms")?,
    })
}

fn build_item_from_row(row: &sqlx::postgres::PgRow) -> Result<BuildListItem, StoreError> {
    Ok(BuildListItem {
        build_id: row.try_get("id")?,
        pipeline_digest: digest(row.try_get("pipeline_digest")?)?,
        status: row.try_get("status")?,
        priority: row.try_get("priority")?,
        dag_mode: row.try_get("dag_mode")?,
        created_at_unix_ms: row.try_get("created_ms")?,
        created_at_unix_micros: row.try_get("created_micros")?,
        completed_at_unix_ms: row.try_get("completed_ms")?,
    })
}

fn digest(bytes: Vec<u8>) -> Result<[u8; 32], StoreError> {
    bytes.try_into().map_err(|_| {
        StoreError::InvalidProductOperation("stored product digest is malformed".to_owned())
    })
}

fn validate_pipeline_write(input: &PipelineWrite) -> Result<(), StoreError> {
    if input.slug.is_empty()
        || input.slug.len() > 128
        || input.slug.trim() != input.slug
        || input.slug.chars().any(char::is_control)
        || input.source.is_empty()
        || input.source.len() > 1_048_576
        || input.schema_major <= 0
        || input.schema_minor < 0
        || !input.parameter_schema.is_object()
    {
        return Err(StoreError::InvalidProductOperation(
            "pipeline catalog input is outside its bounds".to_owned(),
        ));
    }
    Ok(())
}

fn validate_component_write(input: &ComponentWrite) -> Result<(), StoreError> {
    if input.name.is_empty()
        || input.name.len() > 128
        || input.name.trim() != input.name
        || input.name.chars().any(char::is_control)
        || input.version_major <= 0
        || input.version_minor < 0
        || input.canonical_bytes.is_empty()
        || input.canonical_bytes.len() > 1_048_576
    {
        return Err(StoreError::InvalidProductOperation(
            "component catalog input is outside its bounds".to_owned(),
        ));
    }
    Ok(())
}

fn validate_page(limit: u32) -> Result<(), StoreError> {
    if limit == 0 || limit > MAX_PRODUCT_PAGE {
        return Err(StoreError::InvalidProductOperation(format!(
            "page limit must be between 1 and {MAX_PRODUCT_PAGE}"
        )));
    }
    Ok(())
}
