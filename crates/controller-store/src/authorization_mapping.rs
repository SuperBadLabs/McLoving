use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::audit::append_audit_record;
use super::authz::{Action, GrantDecision};
use super::{Store, StoreError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationPrincipalMappingWrite {
    pub mapping_id: Uuid,
    pub target_identity_id: Uuid,
    pub source_identity_id: String,
    pub source_alias_history: Value,
    pub source_membership_generation: i64,
    pub source_lifecycle_state: String,
    pub source_acl_entry_id: String,
    pub source_acl_scope: String,
    pub source_acl_generation: String,
    pub source_permissions: BTreeSet<String>,
    pub target_provider_id: Option<Uuid>,
    pub target_external_subject: Option<String>,
    pub target_lifecycle_generation: i64,
    pub target_group_generation: i64,
    pub target_provenance_digest: [u8; 32],
    pub resulting_role: String,
    pub decisions: BTreeMap<Action, GrantDecision>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationPolicyWrite {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub generation: i64,
    pub expected_current_generation: Option<i64>,
    pub source_realm_implementation: String,
    pub source_realm_digest: [u8; 32],
    pub source_inventory_digest: [u8; 32],
    pub reviewer: String,
    pub actor_subject: String,
    pub restored_from_generation: Option<i64>,
    pub mappings: Vec<AuthorizationPrincipalMappingWrite>,
    pub expected_policy_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationPolicyReceipt {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub generation: i64,
    pub policy_digest: [u8; 32],
    pub mapping_count: usize,
    pub grant_count: usize,
}

impl Store {
    /// Installs one complete, immutable authorization generation and atomically
    /// advances the project's active pointer. This is a privileged migration
    /// operation; the constrained runtime role has read-only access.
    pub async fn install_authorization_policy(
        &self,
        input: &AuthorizationPolicyWrite,
    ) -> Result<AuthorizationPolicyReceipt, StoreError> {
        validate_policy(input)?;
        let policy_digest = compute_authorization_policy_digest(input)?;
        if policy_digest != input.expected_policy_digest {
            return invalid("authorization policy digest does not match its canonical content");
        }

        let mut tx = self.tenant_transaction(input.organization_id).await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!(
                "mcloving.authorization-policy.{}.{}",
                input.organization_id, input.project_id
            ))
            .execute(&mut *tx)
            .await?;
        let project_exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (
                 SELECT 1 FROM projects WHERE organization_id = $1 AND id = $2
             )",
        )
        .bind(input.organization_id)
        .bind(input.project_id)
        .fetch_one(&mut *tx)
        .await?;
        if !project_exists {
            return invalid("authorization target project does not exist in the tenant");
        }

        let current_generation = sqlx::query_scalar::<_, i64>(
            "SELECT current_generation
             FROM authorization_project_policies
             WHERE organization_id = $1 AND project_id = $2
             FOR UPDATE",
        )
        .bind(input.organization_id)
        .bind(input.project_id)
        .fetch_optional(&mut *tx)
        .await?;
        if current_generation != input.expected_current_generation {
            return Err(StoreError::AuthorizationConflict(
                "authorization policy current generation changed".to_owned(),
            ));
        }
        let required_generation =
            current_generation
                .unwrap_or(0)
                .checked_add(1)
                .ok_or_else(|| {
                    StoreError::InvalidAuthorizationOperation(
                        "authorization policy generation overflow".to_owned(),
                    )
                })?;
        if input.generation != required_generation {
            return invalid("authorization policy generation must advance by exactly one");
        }
        if let Some(restored) = input.restored_from_generation
            && (restored >= input.generation
                || !sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS (
                         SELECT 1 FROM authorization_policy_versions
                         WHERE organization_id = $1 AND project_id = $2
                           AND generation = $3
                     )",
                )
                .bind(input.organization_id)
                .bind(input.project_id)
                .bind(restored)
                .fetch_one(&mut *tx)
                .await?)
        {
            return invalid("authorization rollback source generation is not retained");
        }

        for mapping in &input.mappings {
            validate_target_identity(&mut tx, input, mapping).await?;
        }

        sqlx::query(
            "INSERT INTO authorization_policy_versions (
                 organization_id, project_id, generation, policy_digest,
                 source_realm_implementation, source_realm_digest,
                 source_inventory_digest, reviewer, restored_from_generation
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(input.organization_id)
        .bind(input.project_id)
        .bind(input.generation)
        .bind(policy_digest.as_slice())
        .bind(&input.source_realm_implementation)
        .bind(input.source_realm_digest.as_slice())
        .bind(input.source_inventory_digest.as_slice())
        .bind(&input.reviewer)
        .bind(input.restored_from_generation)
        .execute(&mut *tx)
        .await?;

        let mut grant_count = 0_usize;
        for mapping in &input.mappings {
            let mapping_digest = compute_mapping_digest(mapping)?;
            let source_permissions = mapping
                .source_permissions
                .iter()
                .cloned()
                .collect::<Vec<_>>();
            sqlx::query(
                "INSERT INTO authorization_principal_mappings (
                     organization_id, project_id, policy_generation, mapping_id,
                     target_identity_id, source_identity_id, source_alias_history,
                     source_membership_generation, source_lifecycle_state,
                     source_acl_entry_id, source_acl_scope, source_acl_generation,
                     source_permissions, target_provider_id, target_external_subject,
                     target_lifecycle_generation, target_group_generation,
                     target_provenance_digest, resulting_role, mapping_digest
                 ) VALUES (
                     $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                     $11, $12, $13, $14, $15, $16, $17, $18, $19, $20
                 )",
            )
            .bind(input.organization_id)
            .bind(input.project_id)
            .bind(input.generation)
            .bind(mapping.mapping_id)
            .bind(mapping.target_identity_id)
            .bind(&mapping.source_identity_id)
            .bind(&mapping.source_alias_history)
            .bind(mapping.source_membership_generation)
            .bind(&mapping.source_lifecycle_state)
            .bind(&mapping.source_acl_entry_id)
            .bind(&mapping.source_acl_scope)
            .bind(&mapping.source_acl_generation)
            .bind(json!(source_permissions))
            .bind(mapping.target_provider_id)
            .bind(&mapping.target_external_subject)
            .bind(mapping.target_lifecycle_generation)
            .bind(mapping.target_group_generation)
            .bind(mapping.target_provenance_digest.as_slice())
            .bind(&mapping.resulting_role)
            .bind(mapping_digest.as_slice())
            .execute(&mut *tx)
            .await?;

            for (action, decision) in &mapping.decisions {
                sqlx::query(
                    "INSERT INTO authorization_action_grants (
                         organization_id, project_id, policy_generation,
                         mapping_id, action, decision
                     ) VALUES ($1, $2, $3, $4, $5, $6)",
                )
                .bind(input.organization_id)
                .bind(input.project_id)
                .bind(input.generation)
                .bind(mapping.mapping_id)
                .bind(action.as_str())
                .bind(decision.as_str())
                .execute(&mut *tx)
                .await?;
                grant_count += 1;
            }
        }

        sqlx::query(
            "INSERT INTO authorization_project_policies (
                 organization_id, project_id, current_generation
             ) VALUES ($1, $2, $3)
             ON CONFLICT (organization_id, project_id) DO UPDATE
             SET current_generation = EXCLUDED.current_generation,
                 updated_at = clock_timestamp()",
        )
        .bind(input.organization_id)
        .bind(input.project_id)
        .bind(input.generation)
        .execute(&mut *tx)
        .await?;

        append_audit_record(
            &mut tx,
            input.organization_id,
            "authorization",
            &input.actor_subject,
            if input.restored_from_generation.is_some() {
                "policy_rolled_back"
            } else {
                "policy_installed"
            },
            &format!("project:{}", input.project_id),
            json!({
                "project_id": input.project_id,
                "generation": input.generation,
                "policy_digest": hex::encode(policy_digest),
                "source_realm_digest": hex::encode(input.source_realm_digest),
                "source_inventory_digest": hex::encode(input.source_inventory_digest),
                "reviewer": input.reviewer,
                "restored_from_generation": input.restored_from_generation,
                "mapping_count": input.mappings.len(),
                "grant_count": grant_count,
            }),
        )
        .await?;
        tx.commit().await?;

        Ok(AuthorizationPolicyReceipt {
            organization_id: input.organization_id,
            project_id: input.project_id,
            generation: input.generation,
            policy_digest,
            mapping_count: input.mappings.len(),
            grant_count,
        })
    }
}

pub fn compute_authorization_policy_digest(
    input: &AuthorizationPolicyWrite,
) -> Result<[u8; 32], StoreError> {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, b"mcloving-authorization-policy-v1");
    hash_field(&mut hasher, input.organization_id.as_bytes());
    hash_field(&mut hasher, input.project_id.as_bytes());
    hash_field(&mut hasher, &input.generation.to_be_bytes());
    hash_field(&mut hasher, input.source_realm_implementation.as_bytes());
    hash_field(&mut hasher, &input.source_realm_digest);
    hash_field(&mut hasher, &input.source_inventory_digest);
    hash_field(&mut hasher, input.reviewer.as_bytes());
    hash_field(
        &mut hasher,
        &input.restored_from_generation.unwrap_or(0).to_be_bytes(),
    );
    let mut mappings = input.mappings.iter().collect::<Vec<_>>();
    mappings.sort_by_key(|mapping| mapping.mapping_id);
    for mapping in mappings {
        hash_field(&mut hasher, &compute_mapping_digest(mapping)?);
    }
    Ok(hasher.finalize().into())
}

fn compute_mapping_digest(
    mapping: &AuthorizationPrincipalMappingWrite,
) -> Result<[u8; 32], StoreError> {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, b"mcloving-authorization-mapping-v1");
    hash_field(&mut hasher, mapping.mapping_id.as_bytes());
    hash_field(&mut hasher, mapping.target_identity_id.as_bytes());
    hash_field(&mut hasher, mapping.source_identity_id.as_bytes());
    hash_field(
        &mut hasher,
        &serde_json::to_vec(&mapping.source_alias_history).map_err(|error| {
            StoreError::InvalidAuthorizationOperation(format!(
                "source alias history is not canonical JSON: {error}"
            ))
        })?,
    );
    hash_field(
        &mut hasher,
        &mapping.source_membership_generation.to_be_bytes(),
    );
    hash_field(&mut hasher, mapping.source_lifecycle_state.as_bytes());
    hash_field(&mut hasher, mapping.source_acl_entry_id.as_bytes());
    hash_field(&mut hasher, mapping.source_acl_scope.as_bytes());
    hash_field(&mut hasher, mapping.source_acl_generation.as_bytes());
    for permission in &mapping.source_permissions {
        hash_field(&mut hasher, permission.as_bytes());
    }
    hash_field(
        &mut hasher,
        mapping.target_provider_id.unwrap_or(Uuid::nil()).as_bytes(),
    );
    hash_field(
        &mut hasher,
        mapping
            .target_external_subject
            .as_deref()
            .unwrap_or("")
            .as_bytes(),
    );
    hash_field(
        &mut hasher,
        &mapping.target_lifecycle_generation.to_be_bytes(),
    );
    hash_field(&mut hasher, &mapping.target_group_generation.to_be_bytes());
    hash_field(&mut hasher, &mapping.target_provenance_digest);
    hash_field(&mut hasher, mapping.resulting_role.as_bytes());
    for (action, decision) in &mapping.decisions {
        hash_field(&mut hasher, action.as_str().as_bytes());
        hash_field(&mut hasher, decision.as_str().as_bytes());
    }
    Ok(hasher.finalize().into())
}

fn validate_policy(input: &AuthorizationPolicyWrite) -> Result<(), StoreError> {
    if input.generation <= 0 {
        return invalid("authorization policy generation must be positive");
    }
    validate_text(
        "source realm implementation",
        &input.source_realm_implementation,
        512,
    )?;
    validate_text("reviewer", &input.reviewer, 512)?;
    validate_text("actor subject", &input.actor_subject, 512)?;
    let mut mapping_ids = BTreeSet::new();
    for mapping in &input.mappings {
        if !mapping_ids.insert(mapping.mapping_id) {
            return invalid("authorization mapping identifiers must be unique");
        }
        validate_mapping(mapping)?;
    }
    Ok(())
}

fn validate_mapping(mapping: &AuthorizationPrincipalMappingWrite) -> Result<(), StoreError> {
    validate_text(
        "source identity identifier",
        &mapping.source_identity_id,
        512,
    )?;
    if !mapping.source_alias_history.is_array() {
        return invalid("source alias history must be a JSON array");
    }
    if mapping.source_membership_generation <= 0
        || mapping.target_lifecycle_generation <= 0
        || mapping.target_group_generation <= 0
    {
        return invalid("authorization identity generations must be positive");
    }
    if !matches!(
        mapping.source_lifecycle_state.as_str(),
        "active" | "disabled" | "deleted"
    ) {
        return invalid("source lifecycle state is unknown");
    }
    validate_text(
        "source ACL entry identifier",
        &mapping.source_acl_entry_id,
        1024,
    )?;
    validate_text("source ACL scope", &mapping.source_acl_scope, 1024)?;
    validate_text("source ACL generation", &mapping.source_acl_generation, 512)?;
    validate_text("resulting role", &mapping.resulting_role, 128)?;
    if mapping.source_permissions.is_empty() || mapping.decisions.is_empty() {
        return invalid("authorization mappings require source permissions and decisions");
    }
    if mapping.target_provider_id.is_some() != mapping.target_external_subject.is_some() {
        return invalid("target provider and external subject must be supplied together");
    }
    if let Some(subject) = &mapping.target_external_subject {
        validate_text("target external subject", subject, 512)?;
    }
    let source_actions = source_actions(&mapping.source_permissions);
    let source_is_admin = mapping
        .source_permissions
        .iter()
        .any(|permission| normalized_permission(permission) == "overall.administer");
    for (action, decision) in &mapping.decisions {
        if *decision == GrantDecision::Allow && mapping.source_lifecycle_state != "active" {
            return invalid("inactive source principals cannot produce target allow decisions");
        }
        if *action == Action::SchedulerControl {
            return invalid("Jenkins ACL mappings cannot grant scheduler control");
        }
        if *decision == GrantDecision::Allow && !source_is_admin && !source_actions.contains(action)
        {
            return invalid("target allow decision broadens the source Jenkins ACL");
        }
    }
    Ok(())
}

async fn validate_target_identity(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    policy: &AuthorizationPolicyWrite,
    mapping: &AuthorizationPrincipalMappingWrite,
) -> Result<(), StoreError> {
    type IdentityRow = (
        String,
        String,
        i64,
        Option<Uuid>,
        Option<String>,
        i64,
        Option<Vec<u8>>,
        Option<String>,
        Option<i64>,
        Value,
        Option<Vec<u8>>,
    );
    let row = sqlx::query_as::<_, IdentityRow>(
        "SELECT kind, lifecycle_state, lifecycle_generation, provider_id,
                external_subject, group_generation, source_realm_digest,
                source_identity_id, source_membership_generation, alias_history,
                provenance_digest
         FROM identities
         WHERE organization_id = $1 AND id = $2
         FOR SHARE",
    )
    .bind(policy.organization_id)
    .bind(mapping.target_identity_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| {
        StoreError::InvalidAuthorizationOperation(
            "authorization target identity does not exist in the tenant".to_owned(),
        )
    })?;
    if row.1 != "active"
        || row.2 != mapping.target_lifecycle_generation
        || row.5 != mapping.target_group_generation
        || row.3 != mapping.target_provider_id
        || row.4 != mapping.target_external_subject
    {
        return invalid("authorization target identity lifecycle binding is stale");
    }
    if row.0 == "human" {
        if row.6.as_deref() != Some(policy.source_realm_digest.as_slice())
            || row.7.as_deref() != Some(mapping.source_identity_id.as_str())
            || row.8 != Some(mapping.source_membership_generation)
            || row.9 != mapping.source_alias_history
            || row.10.as_deref() != Some(mapping.target_provenance_digest.as_slice())
        {
            return invalid("authorization human identity provenance does not match IDP truth");
        }
    } else if row.0 != "service" {
        return invalid("authorization target identity kind is unknown");
    }
    Ok(())
}

fn source_actions(permissions: &BTreeSet<String>) -> BTreeSet<Action> {
    permissions
        .iter()
        .filter_map(
            |permission| match normalized_permission(permission).as_str() {
                "job.read" | "item.read" => Some(Action::ProjectView),
                "job.build" | "item.build" => Some(Action::BuildTrigger),
                "job.cancel" | "run.cancel" => Some(Action::BuildCancel),
                "job.configure" | "item.configure" => Some(Action::ProjectConfigure),
                "job.approve" | "input.approve" => Some(Action::ApprovalAct),
                "job.retry" | "run.replay" | "run.retry" => Some(Action::BuildRetry),
                "artifact.read" | "run.artifacts" => Some(Action::ArtifactRead),
                "artifact.write" => Some(Action::ArtifactWrite),
                "test.read" | "run.tests" => Some(Action::TestRead),
                "log.read" | "run.logs" => Some(Action::LogRead),
                "credential.use" | "credentials.use" => Some(Action::SecretUse),
                "audit.read" => Some(Action::AuditRead),
                _ => None,
            },
        )
        .collect()
}

fn normalized_permission(permission: &str) -> String {
    permission.trim().to_ascii_lowercase().replace('/', ".")
}

fn validate_text(label: &str, value: &str, maximum: usize) -> Result<(), StoreError> {
    if value.is_empty() || value.trim() != value || value.len() > maximum {
        return Err(StoreError::InvalidAuthorizationOperation(format!(
            "{label} is empty, padded, or too long"
        )));
    }
    Ok(())
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn invalid<T>(message: &str) -> Result<T, StoreError> {
    Err(StoreError::InvalidAuthorizationOperation(
        message.to_owned(),
    ))
}
