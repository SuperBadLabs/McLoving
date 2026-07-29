use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

use super::{Store, StoreError, append_event_and_outbox};

const MAX_SECURITY_LABEL_BYTES: usize = 128;
const MAX_APPROVER_SUBJECT_BYTES: usize = 256;
const MAX_SECRET_BYTES: usize = 65_536;
const MAX_TOTAL_SECRET_BYTES: usize = 65_536;
const MAX_APPROVALS: usize = 8;
const MAX_TTL_SECONDS: i32 = 24 * 60 * 60;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewEnvironmentApproval<'a> {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub build_id: Uuid,
    pub pipeline_digest: [u8; 32],
    pub environment: &'a str,
    pub action: &'a str,
    pub approver_subject: &'a str,
    pub ttl_seconds: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewCredentialGrant<'a> {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub build_id: Uuid,
    pub attempt_id: Uuid,
    pub fence: i64,
    pub pipeline_digest: [u8; 32],
    pub environment: &'a str,
    pub action: &'a str,
    pub target_name: &'a str,
    pub secret_value: &'a [u8],
    pub approval_ids: &'a [Uuid],
    pub ttl_seconds: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialDelivery {
    pub grant_id: Uuid,
    pub target_name: String,
    pub secret_value: Vec<u8>,
}

impl Store {
    pub async fn configure_protected_environment(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        environment: &str,
        action: &str,
        required_approvals: i16,
    ) -> Result<bool, StoreError> {
        if !valid_label(environment)
            || !valid_label(action)
            || !(0..=i16::try_from(MAX_APPROVALS).expect("bound fits i16"))
                .contains(&required_approvals)
        {
            return Err(StoreError::InvalidSecurityOperation(
                "protected environment policy is outside its bounds".to_owned(),
            ));
        }
        let mut tx = self.tenant_transaction(organization_id).await?;
        let configured = sqlx::query_scalar::<_, String>(
            "INSERT INTO protected_environments (
                 organization_id, project_id, environment, action,
                 required_approvals
             )
             SELECT $1, p.id, $3, $4, $5
             FROM projects AS p
             WHERE p.organization_id = $1 AND p.id = $2
             ON CONFLICT (organization_id, project_id, environment, action)
             DO UPDATE SET
                 required_approvals = EXCLUDED.required_approvals,
                 updated_at = CASE
                     WHEN protected_environments.required_approvals
                          IS DISTINCT FROM EXCLUDED.required_approvals
                     THEN clock_timestamp()
                     ELSE protected_environments.updated_at
                 END
             RETURNING environment",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(environment)
        .bind(action)
        .bind(required_approvals)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(configured.is_some())
    }

    pub async fn approve_environment(
        &self,
        approval: &NewEnvironmentApproval<'_>,
    ) -> Result<bool, StoreError> {
        validate_approval(approval)?;
        let mut tx = self.tenant_transaction(approval.organization_id).await?;
        let inserted = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO environment_approvals (
                 id, organization_id, project_id, build_id, pipeline_digest,
                 environment, action, approver_subject, expires_at
             )
             SELECT $1, b.organization_id, b.project_id, b.id,
                    b.pipeline_digest, $6, $7, $8,
                    clock_timestamp() + make_interval(secs => $9)
             FROM builds AS b
             JOIN protected_environments AS e
               ON e.organization_id = b.organization_id
              AND e.project_id = b.project_id
              AND e.environment = $6
              AND e.action = $7
             WHERE b.organization_id = $2
               AND b.project_id = $3
               AND b.id = $4
               AND b.pipeline_digest = $5
             ON CONFLICT DO NOTHING
             RETURNING id",
        )
        .bind(approval.id)
        .bind(approval.organization_id)
        .bind(approval.project_id)
        .bind(approval.build_id)
        .bind(approval.pipeline_digest.as_slice())
        .bind(approval.environment)
        .bind(approval.action)
        .bind(approval.approver_subject)
        .bind(approval.ttl_seconds)
        .fetch_optional(&mut *tx)
        .await?;
        if inserted.is_some() {
            append_event_and_outbox(
                &mut tx,
                approval.organization_id,
                approval.build_id,
                "environment.approved",
                json!({
                    "approval_id": approval.id,
                    "project_id": approval.project_id,
                    "environment": approval.environment,
                    "action": approval.action,
                    "approver_subject": approval.approver_subject,
                }),
            )
            .await?;
        }
        tx.commit().await?;
        Ok(inserted.is_some())
    }

    pub async fn issue_credential_grant(
        &self,
        grant: &NewCredentialGrant<'_>,
    ) -> Result<bool, StoreError> {
        validate_grant(grant)?;
        let mut tx = self.tenant_transaction(grant.organization_id).await?;
        let policy = sqlx::query(
            "SELECT e.required_approvals
             FROM attempts AS a
             JOIN nodes AS n
               ON n.organization_id = a.organization_id AND n.id = a.node_id
             JOIN builds AS b
               ON b.organization_id = n.organization_id AND b.id = n.build_id
             JOIN protected_environments AS e
               ON e.organization_id = b.organization_id
              AND e.project_id = b.project_id
              AND e.environment = $7
              AND e.action = $8
             WHERE a.organization_id = $1
               AND b.project_id = $2
               AND b.id = $3
               AND a.id = $4
               AND a.fence = $5
               AND b.pipeline_digest = $6
               AND a.status IN ('offered', 'accepted', 'running')
             FOR UPDATE OF a, b, e",
        )
        .bind(grant.organization_id)
        .bind(grant.project_id)
        .bind(grant.build_id)
        .bind(grant.attempt_id)
        .bind(grant.fence)
        .bind(grant.pipeline_digest.as_slice())
        .bind(grant.environment)
        .bind(grant.action)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(policy) = policy else {
            tx.rollback().await?;
            return Ok(false);
        };
        let required_approvals: i16 = policy.try_get("required_approvals")?;
        let required_approvals =
            usize::try_from(required_approvals).expect("database constraint is non-negative");
        let (existing_grants, existing_secret_bytes) = sqlx::query_as::<_, (i64, i64)>(
            "SELECT COUNT(*), COALESCE(SUM(octet_length(secret_value)), 0)
             FROM credential_grants
             WHERE organization_id = $1
               AND attempt_id = $2
               AND fence = $3",
        )
        .bind(grant.organization_id)
        .bind(grant.attempt_id)
        .bind(grant.fence)
        .fetch_one(&mut *tx)
        .await?;
        let proposed_secret_bytes = existing_secret_bytes.checked_add(
            i64::try_from(grant.secret_value.len()).expect("validated bound fits i64"),
        );
        if existing_grants >= i64::try_from(MAX_APPROVALS).expect("bound fits i64")
            || proposed_secret_bytes.is_none_or(|bytes| {
                bytes > i64::try_from(MAX_TOTAL_SECRET_BYTES).expect("bound fits i64")
            })
        {
            tx.rollback().await?;
            return Ok(false);
        }

        let locked_approvals = if grant.approval_ids.is_empty() {
            Vec::new()
        } else {
            sqlx::query_as::<_, (Uuid, String)>(
                "SELECT id, approver_subject
                 FROM environment_approvals
                 WHERE organization_id = $1
                   AND id = ANY($2)
                   AND project_id = $3
                   AND build_id = $4
                   AND pipeline_digest = $5
                   AND environment = $6
                   AND action = $7
                   AND expires_at > clock_timestamp()
                   AND (
                       consumed_at IS NULL
                       OR (
                           consumed_by_attempt = $8
                           AND consumed_fence = $9
                       )
                   )
                 FOR UPDATE",
            )
            .bind(grant.organization_id)
            .bind(grant.approval_ids)
            .bind(grant.project_id)
            .bind(grant.build_id)
            .bind(grant.pipeline_digest.as_slice())
            .bind(grant.environment)
            .bind(grant.action)
            .bind(grant.attempt_id)
            .bind(grant.fence)
            .fetch_all(&mut *tx)
            .await?
        };
        let distinct_approvers = locked_approvals
            .iter()
            .map(|(_, subject)| subject)
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        if locked_approvals.len() != grant.approval_ids.len()
            || distinct_approvers < required_approvals
        {
            tx.rollback().await?;
            return Ok(false);
        }
        let inserted = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO credential_grants (
                 id, organization_id, project_id, build_id, attempt_id, fence,
                 pipeline_digest, environment, action, target_name,
                 secret_value, expires_at
             )
             VALUES (
                 $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                 clock_timestamp() + make_interval(secs => $12)
             )
             ON CONFLICT DO NOTHING
             RETURNING id",
        )
        .bind(grant.id)
        .bind(grant.organization_id)
        .bind(grant.project_id)
        .bind(grant.build_id)
        .bind(grant.attempt_id)
        .bind(grant.fence)
        .bind(grant.pipeline_digest.as_slice())
        .bind(grant.environment)
        .bind(grant.action)
        .bind(grant.target_name)
        .bind(grant.secret_value)
        .bind(grant.ttl_seconds)
        .fetch_optional(&mut *tx)
        .await?;
        if inserted.is_none() {
            tx.rollback().await?;
            return Ok(false);
        }
        if !locked_approvals.is_empty() {
            sqlx::query(
                "UPDATE environment_approvals
                 SET consumed_by_attempt = $3,
                     consumed_fence = $4,
                     consumed_at = clock_timestamp()
                 WHERE organization_id = $1
                   AND id = ANY($2)
                   AND consumed_at IS NULL",
            )
            .bind(grant.organization_id)
            .bind(grant.approval_ids)
            .bind(grant.attempt_id)
            .bind(grant.fence)
            .execute(&mut *tx)
            .await?;
        }
        append_event_and_outbox(
            &mut tx,
            grant.organization_id,
            grant.build_id,
            "credential.grant_issued",
            json!({
                "grant_id": grant.id,
                "project_id": grant.project_id,
                "attempt_id": grant.attempt_id,
                "fence": grant.fence,
                "environment": grant.environment,
                "action": grant.action,
                "target_name": grant.target_name,
                "approval_ids": grant.approval_ids,
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn redeem_credential_grants(
        &self,
        organization_id: Uuid,
        attempt_id: Uuid,
        fence: i64,
        restore_epoch: i64,
        agent_id: &str,
        session_epoch: u64,
        target_names: &[String],
    ) -> Result<Option<Vec<CredentialDelivery>>, StoreError> {
        if target_names.is_empty()
            || target_names.len() > MAX_APPROVALS
            || target_names
                .iter()
                .any(|name| !valid_environment_name(name))
            || target_names
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != target_names.len()
        {
            return Err(StoreError::InvalidSecurityOperation(
                "credential request targets are outside their bounds".to_owned(),
            ));
        }
        let session_epoch =
            i64::try_from(session_epoch).map_err(|_| StoreError::InvalidAgentSession)?;
        let mut tx = self.tenant_transaction(organization_id).await?;
        let rows = sqlx::query_as::<_, (Uuid, String, Vec<u8>, Uuid, bool)>(
            "SELECT g.id, g.target_name, g.secret_value, g.build_id,
                    g.delivered_at IS NOT NULL AS already_delivered
             FROM credential_grants AS g
             JOIN attempts AS a
               ON a.organization_id = g.organization_id
              AND a.id = g.attempt_id
             JOIN nodes AS n
               ON n.organization_id = a.organization_id AND n.id = a.node_id
             JOIN builds AS b
               ON b.organization_id = n.organization_id AND b.id = n.build_id,
             agent_sessions AS s
             WHERE g.organization_id = $1
               AND g.attempt_id = $2
               AND g.fence = $3
               AND (
                   g.delivered_at IS NOT NULL
                   OR g.expires_at > clock_timestamp()
               )
               AND a.organization_id = g.organization_id
               AND a.id = g.attempt_id
               AND a.fence = g.fence
               AND a.restore_epoch = $4
               AND a.restore_epoch = (
                   SELECT restore_epoch
                   FROM controller_metadata
                   WHERE singleton
               )
               AND a.lease_owner = $5
               AND a.lease_expires_at > clock_timestamp()
               AND a.status = 'accepted'
               AND b.id = g.build_id
               AND b.project_id = g.project_id
               AND b.pipeline_digest = g.pipeline_digest
               AND s.agent_id = $5
               AND s.session_epoch = $6
               AND s.features @> ARRAY['attempt-credentials-v1']::text[]
             ORDER BY g.target_name
             FOR UPDATE OF g",
        )
        .bind(organization_id)
        .bind(attempt_id)
        .bind(fence)
        .bind(restore_epoch)
        .bind(agent_id)
        .bind(session_epoch)
        .fetch_all(&mut *tx)
        .await?;
        let requested = target_names
            .iter()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        let available = rows
            .iter()
            .map(|row| row.1.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        if !available.is_subset(&requested) {
            return Err(StoreError::InvalidSecurityOperation(
                "credential grants do not match the execution contract".to_owned(),
            ));
        }
        if available != requested {
            tx.commit().await?;
            return Ok(None);
        }
        let delivered_count = rows.iter().filter(|row| row.4).count();
        if delivered_count != 0 && delivered_count != rows.len() {
            return Err(StoreError::InvalidSecurityOperation(
                "credential delivery has a partial atomic grant set".to_owned(),
            ));
        }
        if delivered_count == 0 {
            let grant_ids = rows.iter().map(|row| row.0).collect::<Vec<_>>();
            let delivered = sqlx::query_scalar::<_, Uuid>(
                "UPDATE credential_grants
                 SET delivered_at = clock_timestamp()
                 WHERE organization_id = $1
                   AND id = ANY($2::uuid[])
                   AND delivered_at IS NULL
                 RETURNING id",
            )
            .bind(organization_id)
            .bind(&grant_ids)
            .fetch_all(&mut *tx)
            .await?;
            if delivered.len() != rows.len() {
                return Err(StoreError::InvalidSecurityOperation(
                    "credential delivery lost its atomic grant set".to_owned(),
                ));
            }
        }
        if delivered_count == 0 {
            let (_, _, _, build_id, _) = rows
                .first()
                .expect("an exact non-empty target set has at least one grant");
            append_event_and_outbox(
                &mut tx,
                organization_id,
                *build_id,
                "credential.grants_delivered",
                json!({
                    "attempt_id": attempt_id,
                    "fence": fence,
                    "grant_ids": rows.iter().map(|row| row.0).collect::<Vec<_>>(),
                    "target_names": rows.iter().map(|row| &row.1).collect::<Vec<_>>(),
                }),
            )
            .await?;
        }
        tx.commit().await?;
        Ok(Some(
            rows.into_iter()
                .map(
                    |(grant_id, target_name, secret_value, _, _)| CredentialDelivery {
                        grant_id,
                        target_name,
                        secret_value,
                    },
                )
                .collect(),
        ))
    }
}

fn validate_approval(approval: &NewEnvironmentApproval<'_>) -> Result<(), StoreError> {
    if !valid_label(approval.environment)
        || !valid_label(approval.action)
        || approval.approver_subject.trim().is_empty()
        || approval.approver_subject.len() > MAX_APPROVER_SUBJECT_BYTES
        || !(1..=MAX_TTL_SECONDS).contains(&approval.ttl_seconds)
    {
        return Err(StoreError::InvalidSecurityOperation(
            "environment approval is outside its bounds".to_owned(),
        ));
    }
    Ok(())
}

fn validate_grant(grant: &NewCredentialGrant<'_>) -> Result<(), StoreError> {
    if grant.fence < 0
        || !valid_label(grant.environment)
        || !valid_label(grant.action)
        || !valid_environment_name(grant.target_name)
        || grant.secret_value.is_empty()
        || grant.secret_value.len() > MAX_SECRET_BYTES
        || grant.secret_value.contains(&0)
        || std::str::from_utf8(grant.secret_value).is_err()
        || grant.approval_ids.len() > MAX_APPROVALS
        || grant
            .approval_ids
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != grant.approval_ids.len()
        || !(1..=MAX_TTL_SECONDS).contains(&grant.ttl_seconds)
    {
        return Err(StoreError::InvalidSecurityOperation(
            "credential grant is outside its bounds".to_owned(),
        ));
    }
    Ok(())
}

fn valid_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SECURITY_LABEL_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_environment_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(byte) if byte.is_ascii_alphabetic() || byte == b'_')
        && value.len() <= MAX_SECURITY_LABEL_BYTES
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}
