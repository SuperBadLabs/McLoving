use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::audit::append_audit_record;
use super::authorization_mapping::authorization_policy_lock_key;
use super::authz::{Action, authorize};
use super::identity::load_principal;
use super::{Store, StoreError};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalAdminAuthority {
    JenkinsSource,
    McLovingTarget,
}

impl ExternalAdminAuthority {
    fn as_str(self) -> &'static str {
        match self {
            Self::JenkinsSource => "jenkins_source",
            Self::McLovingTarget => "mcloving_target",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalAdminOperation {
    ApprovalCreate,
    BuildCancel,
    BuildPauseResume,
    BuildRetry,
    BuildSubmit,
    BuildTerminate,
    ControllerGlobalMutate,
    CredentialReferenceMutate,
    FolderMutate,
    InputSubmit,
    NodeMutate,
    PipelineDelete,
    PipelineDisable,
    PipelinePut,
    QueueReorder,
}

impl ExternalAdminOperation {
    pub const ALL: [Self; 15] = [
        Self::ApprovalCreate,
        Self::BuildCancel,
        Self::BuildPauseResume,
        Self::BuildRetry,
        Self::BuildSubmit,
        Self::BuildTerminate,
        Self::ControllerGlobalMutate,
        Self::CredentialReferenceMutate,
        Self::FolderMutate,
        Self::InputSubmit,
        Self::NodeMutate,
        Self::PipelineDelete,
        Self::PipelineDisable,
        Self::PipelinePut,
        Self::QueueReorder,
    ];

    fn as_str(self) -> &'static str {
        match self {
            Self::ApprovalCreate => "approval_create",
            Self::BuildCancel => "build_cancel",
            Self::BuildPauseResume => "build_pause_resume",
            Self::BuildRetry => "build_retry",
            Self::BuildSubmit => "build_submit",
            Self::BuildTerminate => "build_terminate",
            Self::ControllerGlobalMutate => "controller_global_mutate",
            Self::CredentialReferenceMutate => "credential_reference_mutate",
            Self::FolderMutate => "folder_mutate",
            Self::InputSubmit => "input_submit",
            Self::NodeMutate => "node_mutate",
            Self::PipelineDelete => "pipeline_delete",
            Self::PipelineDisable => "pipeline_disable",
            Self::PipelinePut => "pipeline_put",
            Self::QueueReorder => "queue_reorder",
        }
    }

    fn admitted_contract(
        self,
    ) -> Option<(
        &'static str,
        &'static str,
        &'static str,
        &'static str,
        Action,
    )> {
        match self {
            Self::PipelinePut => Some((
                "PUT",
                "/api/v1/organizations/{organization}/projects/{project}/pipelines/{pipeline}",
                "if_match_revision",
                "desired_state_digest+revision",
                Action::ProjectConfigure,
            )),
            Self::BuildSubmit => Some((
                "POST",
                "/api/v1/organizations/{organization}/projects/{project}/builds",
                "pipeline_digest",
                "idempotency_key",
                Action::BuildTrigger,
            )),
            Self::BuildCancel => Some((
                "POST",
                "/api/v1/organizations/{organization}/projects/{project}/builds/{build}/cancel",
                "build_state_fence",
                "build_id+cancel_state",
                Action::BuildCancel,
            )),
            Self::BuildRetry => Some((
                "POST",
                "/api/v1/organizations/{organization}/projects/{project}/builds/{build}/attempts/{attempt}/retry",
                "attempt_fence",
                "attempt_id+request_digest",
                Action::BuildRetry,
            )),
            Self::ApprovalCreate => Some((
                "POST",
                "/api/v1/organizations/{organization}/projects/{project}/builds/{build}/approvals",
                "environment+action+expiry",
                "approval_id",
                Action::ApprovalAct,
            )),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalAdminDisposition {
    McLovingV1,
    OwnerRetired,
    Pending,
}

impl ExternalAdminDisposition {
    fn as_str(self) -> &'static str {
        match self {
            Self::McLovingV1 => "mcloving_v1",
            Self::OwnerRetired => "owner_retired",
            Self::Pending => "pending",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalAdminOperationContract {
    pub operation: ExternalAdminOperation,
    pub disposition: ExternalAdminDisposition,
    pub method: Option<String>,
    pub endpoint: Option<String>,
    pub precondition: Option<String>,
    pub idempotency: Option<String>,
    pub desired_state_schema: Option<String>,
    pub retirement_evidence_digest: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalAdminClientWrite {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub client_id: String,
    pub generation: i64,
    pub expected_current_generation: Option<i64>,
    pub authority: ExternalAdminAuthority,
    pub source_inventory_digest: [u8; 32],
    pub source_inventory_generation: String,
    pub source_endpoint: String,
    pub source_caller: String,
    pub source_authentication: String,
    pub source_scope: String,
    pub target_identity_id: Uuid,
    pub target_subject: String,
    pub target_api_base: String,
    pub target_api_version: String,
    pub operation_contracts: Vec<ExternalAdminOperationContract>,
    pub observation_started_unix_ms: i64,
    pub observation_ended_unix_ms: i64,
    pub source_writes_observed: u64,
    pub positive_authorization_digest: [u8; 32],
    pub negative_authorization_digest: [u8; 32],
    pub convergence_digest: [u8; 32],
    pub ordering_idempotency_digest: [u8; 32],
    pub partial_failure_retry_digest: [u8; 32],
    pub conflict_digest: [u8; 32],
    pub rollback_from_generation: Option<i64>,
    pub rollback_evidence_digest: Option<[u8; 32]>,
    pub reviewer: String,
    pub actor_subject: String,
    pub expected_contract_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalAdminClientReceipt {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub client_id: String,
    pub generation: i64,
    pub authority: ExternalAdminAuthority,
    pub binding_digest: [u8; 32],
    pub contract_digest: [u8; 32],
}

impl Store {
    pub async fn install_external_admin_client(
        &self,
        input: &ExternalAdminClientWrite,
    ) -> Result<ExternalAdminClientReceipt, StoreError> {
        validate_input(input)?;
        let binding_digest = compute_external_admin_client_binding_digest(input)?;
        let contract_digest = compute_external_admin_client_digest(input)?;
        if contract_digest != input.expected_contract_digest {
            return invalid("external admin client digest does not match canonical content");
        }
        let source_writes_observed = i64::try_from(input.source_writes_observed)
            .map_err(|_| StoreError::InvalidAdminMigration("source write count overflow".into()))?;
        let mut tx = self.tenant_transaction(input.organization_id).await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!(
                "mcloving.external-admin-client.{}.{}.{}",
                input.organization_id, input.project_id, input.client_id
            ))
            .execute(&mut *tx)
            .await?;
        let project_exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM projects WHERE organization_id = $1 AND id = $2)",
        )
        .bind(input.organization_id)
        .bind(input.project_id)
        .fetch_one(&mut *tx)
        .await?;
        if !project_exists {
            return invalid("external admin client target project does not exist in the tenant");
        }
        if input.authority == ExternalAdminAuthority::McLovingTarget {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind(authorization_policy_lock_key(
                    input.organization_id,
                    input.project_id,
                ))
                .execute(&mut *tx)
                .await?;
        }
        let identity = sqlx::query_as::<_, (String, String)>(
            "SELECT lifecycle_state, kind FROM identities
             WHERE organization_id = $1 AND id = $2 AND subject = $3 FOR UPDATE",
        )
        .bind(input.organization_id)
        .bind(input.target_identity_id)
        .bind(&input.target_subject)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((lifecycle, kind)) = identity else {
            return invalid("external admin client target identity is absent or substituted");
        };
        if input.authority == ExternalAdminAuthority::McLovingTarget {
            if lifecycle != "active" {
                return invalid("external admin client target identity is inactive");
            }
            let principal = load_principal(
                &mut tx,
                input.organization_id,
                input.target_identity_id,
                &input.target_subject,
                &kind,
            )
            .await?;
            let required = input
                .operation_contracts
                .iter()
                .filter(|contract| contract.disposition == ExternalAdminDisposition::McLovingV1)
                .filter_map(|contract| contract.operation.admitted_contract().map(|value| value.4))
                .collect::<BTreeSet<_>>();
            for action in required {
                if authorize(
                    &principal,
                    input.organization_id,
                    Some(input.project_id),
                    action,
                )
                .is_err()
                {
                    return invalid(format!(
                        "external admin client target identity lacks required {} authority",
                        action.as_str()
                    ));
                }
            }
        }
        let current = sqlx::query_as::<_, (i64, String, bool)>(
            "SELECT current.current_generation, version.authority,
                    version.binding_digest = $4
             FROM external_admin_client_current AS current
             JOIN external_admin_client_versions AS version
               ON version.organization_id = current.organization_id
              AND version.project_id = current.project_id
              AND version.client_id = current.client_id
              AND version.generation = current.current_generation
             WHERE current.organization_id = $1 AND current.project_id = $2
               AND current.client_id = $3 FOR UPDATE OF current",
        )
        .bind(input.organization_id)
        .bind(input.project_id)
        .bind(&input.client_id)
        .bind(binding_digest.as_slice())
        .fetch_optional(&mut *tx)
        .await?;
        if current.as_ref().map(|row| row.0) != input.expected_current_generation {
            return Err(StoreError::AdminMigrationConflict(
                "external admin client current generation changed".to_owned(),
            ));
        }
        if current.as_ref().is_some_and(|row| !row.2) {
            return invalid("external admin client binding changed across an authority transition");
        }
        let required_generation = match current.as_ref() {
            Some(row) => row.0.checked_add(1).ok_or_else(|| {
                StoreError::InvalidAdminMigration(
                    "external admin client generation overflow".into(),
                )
            })?,
            None => 1,
        };
        if input.generation != required_generation {
            return invalid("external admin client generation must advance by exactly one");
        }
        validate_transition(input, current.as_ref())?;
        let operation_contracts =
            serde_json::to_value(&input.operation_contracts).map_err(|error| {
                StoreError::InvalidAdminMigration(format!(
                    "external admin operation contracts cannot be encoded: {error}"
                ))
            })?;
        sqlx::query(
            "INSERT INTO external_admin_client_versions (
                 organization_id, project_id, client_id, generation, authority,
                 binding_digest, contract_digest, source_inventory_digest,
                 source_inventory_generation, source_endpoint, source_caller,
                 source_authentication, source_scope, target_identity_id, target_subject,
                 target_api_base, target_api_version, operation_contracts,
                 observation_started_unix_ms, observation_ended_unix_ms,
                 source_writes_observed, positive_authorization_digest,
                 negative_authorization_digest, convergence_digest,
                 ordering_idempotency_digest, partial_failure_retry_digest,
                 conflict_digest, rollback_from_generation, rollback_evidence_digest, reviewer
             ) VALUES (
                 $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,
                 $16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30
             )",
        )
        .bind(input.organization_id)
        .bind(input.project_id)
        .bind(&input.client_id)
        .bind(input.generation)
        .bind(input.authority.as_str())
        .bind(binding_digest.as_slice())
        .bind(contract_digest.as_slice())
        .bind(input.source_inventory_digest.as_slice())
        .bind(&input.source_inventory_generation)
        .bind(&input.source_endpoint)
        .bind(&input.source_caller)
        .bind(&input.source_authentication)
        .bind(&input.source_scope)
        .bind(input.target_identity_id)
        .bind(&input.target_subject)
        .bind(&input.target_api_base)
        .bind(&input.target_api_version)
        .bind(operation_contracts)
        .bind(input.observation_started_unix_ms)
        .bind(input.observation_ended_unix_ms)
        .bind(source_writes_observed)
        .bind(input.positive_authorization_digest.as_slice())
        .bind(input.negative_authorization_digest.as_slice())
        .bind(input.convergence_digest.as_slice())
        .bind(input.ordering_idempotency_digest.as_slice())
        .bind(input.partial_failure_retry_digest.as_slice())
        .bind(input.conflict_digest.as_slice())
        .bind(input.rollback_from_generation)
        .bind(
            input
                .rollback_evidence_digest
                .as_ref()
                .map(|digest| digest.as_slice()),
        )
        .bind(&input.reviewer)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO external_admin_client_current (
                 organization_id, project_id, client_id, current_generation
             ) VALUES ($1,$2,$3,$4)
             ON CONFLICT (organization_id, project_id, client_id) DO UPDATE
             SET current_generation = EXCLUDED.current_generation,
                 updated_at = clock_timestamp()",
        )
        .bind(input.organization_id)
        .bind(input.project_id)
        .bind(&input.client_id)
        .bind(input.generation)
        .execute(&mut *tx)
        .await?;
        append_audit_record(
            &mut tx,
            input.organization_id,
            "migration",
            &input.actor_subject,
            match input.authority {
                ExternalAdminAuthority::JenkinsSource if input.generation == 1 => {
                    "external_admin_client.registered"
                }
                ExternalAdminAuthority::JenkinsSource => "external_admin_client.rolled_back",
                ExternalAdminAuthority::McLovingTarget => "external_admin_client.cut_over",
            },
            &format!(
                "project:{}:external-admin-client:{}",
                input.project_id, input.client_id
            ),
            json!({
                "project_id": input.project_id,
                "client_id": input.client_id,
                "generation": input.generation,
                "authority": input.authority.as_str(),
                "binding_digest": hex::encode(binding_digest),
                "contract_digest": hex::encode(contract_digest),
                "source_inventory_digest": hex::encode(input.source_inventory_digest),
                "source_writes_observed": input.source_writes_observed,
                "observation_started_unix_ms": input.observation_started_unix_ms,
                "observation_ended_unix_ms": input.observation_ended_unix_ms,
                "rollback_from_generation": input.rollback_from_generation,
                "reviewer": input.reviewer,
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(ExternalAdminClientReceipt {
            organization_id: input.organization_id,
            project_id: input.project_id,
            client_id: input.client_id.clone(),
            generation: input.generation,
            authority: input.authority,
            binding_digest,
            contract_digest,
        })
    }
}

pub fn compute_external_admin_client_digest(
    input: &ExternalAdminClientWrite,
) -> Result<[u8; 32], StoreError> {
    validate_input(input)?;
    let mut hasher = Sha256::new();
    hash(&mut hasher, b"mcloving-external-admin-client-v1");
    hash(
        &mut hasher,
        &compute_external_admin_client_binding_digest(input)?,
    );
    hash(&mut hasher, &input.generation.to_be_bytes());
    hash(&mut hasher, input.authority.as_str().as_bytes());
    let mut contracts = input.operation_contracts.iter().collect::<Vec<_>>();
    contracts.sort_by_key(|contract| contract.operation);
    for contract in contracts {
        hash_contract(&mut hasher, contract);
    }
    hash(
        &mut hasher,
        &input.observation_started_unix_ms.to_be_bytes(),
    );
    hash(&mut hasher, &input.observation_ended_unix_ms.to_be_bytes());
    hash(&mut hasher, &input.source_writes_observed.to_be_bytes());
    for digest in [
        input.positive_authorization_digest,
        input.negative_authorization_digest,
        input.convergence_digest,
        input.ordering_idempotency_digest,
        input.partial_failure_retry_digest,
        input.conflict_digest,
    ] {
        hash(&mut hasher, &digest);
    }
    hash(
        &mut hasher,
        &input.rollback_from_generation.unwrap_or(0).to_be_bytes(),
    );
    hash(
        &mut hasher,
        &input.rollback_evidence_digest.unwrap_or([0; 32]),
    );
    hash(&mut hasher, input.reviewer.as_bytes());
    Ok(hasher.finalize().into())
}

pub fn compute_external_admin_client_binding_digest(
    input: &ExternalAdminClientWrite,
) -> Result<[u8; 32], StoreError> {
    validate_input(input)?;
    let mut hasher = Sha256::new();
    hash(&mut hasher, b"mcloving-external-admin-client-binding-v1");
    hash(&mut hasher, input.organization_id.as_bytes());
    hash(&mut hasher, input.project_id.as_bytes());
    hash(&mut hasher, input.client_id.as_bytes());
    hash(&mut hasher, &input.source_inventory_digest);
    hash(&mut hasher, input.source_inventory_generation.as_bytes());
    hash(&mut hasher, input.source_endpoint.as_bytes());
    hash(&mut hasher, input.source_caller.as_bytes());
    hash(&mut hasher, input.source_authentication.as_bytes());
    hash(&mut hasher, input.source_scope.as_bytes());
    hash(&mut hasher, input.target_identity_id.as_bytes());
    hash(&mut hasher, input.target_subject.as_bytes());
    hash(&mut hasher, input.target_api_base.as_bytes());
    hash(&mut hasher, input.target_api_version.as_bytes());
    let mut contracts = input.operation_contracts.iter().collect::<Vec<_>>();
    contracts.sort_by_key(|contract| contract.operation);
    for contract in contracts {
        hash(&mut hasher, contract.operation.as_str().as_bytes());
    }
    Ok(hasher.finalize().into())
}

fn hash_contract(hasher: &mut Sha256, contract: &ExternalAdminOperationContract) {
    hash(hasher, contract.operation.as_str().as_bytes());
    hash(hasher, contract.disposition.as_str().as_bytes());
    for value in [
        contract.method.as_deref(),
        contract.endpoint.as_deref(),
        contract.precondition.as_deref(),
        contract.idempotency.as_deref(),
        contract.desired_state_schema.as_deref(),
    ] {
        hash(hasher, value.unwrap_or("").as_bytes());
    }
    hash(
        hasher,
        &contract.retirement_evidence_digest.unwrap_or([0; 32]),
    );
}

fn validate_transition(
    input: &ExternalAdminClientWrite,
    current: Option<&(i64, String, bool)>,
) -> Result<(), StoreError> {
    match (current, input.authority) {
        (None, ExternalAdminAuthority::JenkinsSource) => {
            if input.rollback_from_generation.is_some() || input.rollback_evidence_digest.is_some()
            {
                return invalid("initial Jenkins admin authority cannot be a rollback");
            }
        }
        (None, ExternalAdminAuthority::McLovingTarget) => {
            return invalid(
                "McLoving admin authority requires a retained Jenkins source generation",
            );
        }
        (Some((_, authority, _)), ExternalAdminAuthority::McLovingTarget)
            if authority == ExternalAdminAuthority::JenkinsSource.as_str() =>
        {
            if input.source_writes_observed != 0 {
                return invalid("McLoving admin authority requires zero residual Jenkins writes");
            }
            if input
                .operation_contracts
                .iter()
                .any(|contract| contract.disposition == ExternalAdminDisposition::Pending)
            {
                return invalid(
                    "McLoving admin authority requires every operation migrated or owner-retired",
                );
            }
            if input.rollback_from_generation.is_some() || input.rollback_evidence_digest.is_some()
            {
                return invalid("McLoving admin cutover cannot carry rollback fields");
            }
        }
        (Some((generation, authority, _)), ExternalAdminAuthority::JenkinsSource)
            if authority == ExternalAdminAuthority::McLovingTarget.as_str() =>
        {
            if input.rollback_from_generation != Some(*generation)
                || input.rollback_evidence_digest.is_none()
            {
                return invalid(
                    "Jenkins admin restoration must bind the immediately preceding target generation",
                );
            }
        }
        (Some(_), _) => return invalid("external admin client authority must alternate"),
    }
    Ok(())
}

fn validate_input(input: &ExternalAdminClientWrite) -> Result<(), StoreError> {
    if input.generation <= 0 {
        return invalid("external admin client generation must be positive");
    }
    for (name, value, max) in [
        ("client id", input.client_id.as_str(), 256),
        (
            "source inventory generation",
            input.source_inventory_generation.as_str(),
            512,
        ),
        ("source endpoint", input.source_endpoint.as_str(), 2048),
        ("source caller", input.source_caller.as_str(), 512),
        (
            "source authentication",
            input.source_authentication.as_str(),
            512,
        ),
        ("source scope", input.source_scope.as_str(), 512),
        ("target subject", input.target_subject.as_str(), 512),
        ("target API base", input.target_api_base.as_str(), 2048),
        ("reviewer", input.reviewer.as_str(), 512),
        ("actor subject", input.actor_subject.as_str(), 512),
    ] {
        validate_text(name, value, max)?;
    }
    if !http_endpoint(&input.source_endpoint) || !http_endpoint(&input.target_api_base) {
        return invalid("source and target endpoints must be explicit HTTP(S) URLs");
    }
    if input.target_api_version != "v1" {
        return invalid("external admin client target API version must be v1");
    }
    if input.observation_started_unix_ms <= 0
        || input.observation_ended_unix_ms <= input.observation_started_unix_ms
    {
        return invalid("external admin client observation window is invalid");
    }
    let expected = ExternalAdminOperation::ALL
        .into_iter()
        .collect::<BTreeSet<_>>();
    let actual = input
        .operation_contracts
        .iter()
        .map(|contract| contract.operation)
        .collect::<BTreeSet<_>>();
    if actual != expected || input.operation_contracts.len() != expected.len() {
        return invalid(
            "external admin client must classify every canonical write operation exactly once",
        );
    }
    for contract in &input.operation_contracts {
        match contract.disposition {
            ExternalAdminDisposition::McLovingV1 => {
                let Some((method, endpoint, precondition, idempotency, _)) =
                    contract.operation.admitted_contract()
                else {
                    return invalid(
                        "unsupported admin operation cannot claim a McLoving v1 mapping",
                    );
                };
                if contract.method.as_deref() != Some(method)
                    || contract.endpoint.as_deref() != Some(endpoint)
                    || contract.precondition.as_deref() != Some(precondition)
                    || contract.idempotency.as_deref() != Some(idempotency)
                    || contract.desired_state_schema.as_deref() != Some("mcloving.public-api/v1")
                    || contract.retirement_evidence_digest.is_some()
                {
                    return invalid(
                        "external admin operation does not match its canonical v1 contract",
                    );
                }
            }
            ExternalAdminDisposition::OwnerRetired => {
                if contract.method.is_some()
                    || contract.endpoint.is_some()
                    || contract.precondition.is_some()
                    || contract.idempotency.is_some()
                    || contract.desired_state_schema.is_some()
                    || contract.retirement_evidence_digest.is_none()
                    || contract.retirement_evidence_digest == Some([0; 32])
                {
                    return invalid(
                        "owner-retired admin operation requires only non-zero retirement evidence",
                    );
                }
            }
            ExternalAdminDisposition::Pending => {
                if contract.method.is_some()
                    || contract.endpoint.is_some()
                    || contract.precondition.is_some()
                    || contract.idempotency.is_some()
                    || contract.desired_state_schema.is_some()
                    || contract.retirement_evidence_digest.is_some()
                {
                    return invalid(
                        "pending admin operation cannot carry a target or retirement contract",
                    );
                }
            }
        }
    }
    for digest in [
        input.source_inventory_digest,
        input.positive_authorization_digest,
        input.negative_authorization_digest,
        input.convergence_digest,
        input.ordering_idempotency_digest,
        input.partial_failure_retry_digest,
        input.conflict_digest,
    ] {
        if digest == [0; 32] {
            return invalid("external admin client evidence digests must be non-zero");
        }
    }
    if input.rollback_evidence_digest == Some([0; 32]) {
        return invalid("external admin client rollback evidence digest must be non-zero");
    }
    if input.rollback_from_generation.is_some() != input.rollback_evidence_digest.is_some() {
        return invalid("external admin client rollback fields must be supplied together");
    }
    Ok(())
}

fn validate_text(name: &str, value: &str, max: usize) -> Result<(), StoreError> {
    if value.is_empty() || value.trim() != value || value.len() > max || value.contains('\0') {
        return invalid(format!("external admin client {name} is invalid"));
    }
    Ok(())
}

fn http_endpoint(value: &str) -> bool {
    (value.starts_with("https://") || value.starts_with("http://"))
        && !value.chars().any(char::is_whitespace)
}

fn hash(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn invalid<T>(message: impl Into<String>) -> Result<T, StoreError> {
    Err(StoreError::InvalidAdminMigration(message.into()))
}
