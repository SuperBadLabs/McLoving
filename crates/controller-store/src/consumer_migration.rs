use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::audit::append_audit_record;
use super::authz::{Action, authorize};
use super::identity::load_principal;
use super::{Store, StoreError};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalReadAuthority {
    JenkinsSource,
    McLovingTarget,
}

impl ExternalReadAuthority {
    fn as_str(self) -> &'static str {
        match self {
            Self::JenkinsSource => "jenkins_source",
            Self::McLovingTarget => "mcloving_target",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalReadResource {
    Artifact,
    ArtifactContent,
    BuildGraph,
    BuildStatus,
    JobMetadata,
    Log,
    Queue,
    TestResult,
}

impl ExternalReadResource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Artifact => "artifact",
            Self::ArtifactContent => "artifact_content",
            Self::BuildGraph => "build_graph",
            Self::BuildStatus => "build_status",
            Self::JobMetadata => "job_metadata",
            Self::Log => "log",
            Self::Queue => "queue",
            Self::TestResult => "test_result",
        }
    }

    fn required_action(self) -> Action {
        match self {
            Self::Artifact | Self::ArtifactContent => Action::ArtifactRead,
            Self::Log => Action::LogRead,
            Self::TestResult => Action::TestRead,
            Self::BuildGraph | Self::BuildStatus | Self::JobMetadata | Self::Queue => {
                Action::ProjectView
            }
        }
    }

    fn endpoint(self) -> &'static str {
        match self {
            Self::Artifact => {
                "/api/v1/organizations/{organization}/projects/{project}/builds/{build}/artifacts"
            }
            Self::ArtifactContent => {
                "/api/v1/organizations/{organization}/projects/{project}/builds/{build}/artifacts/content"
            }
            Self::BuildGraph => {
                "/api/v1/organizations/{organization}/projects/{project}/builds/{build}/graph"
            }
            Self::BuildStatus => {
                "/api/v1/organizations/{organization}/projects/{project}/builds/{build}"
            }
            Self::JobMetadata => {
                "/api/v1/organizations/{organization}/projects/{project}/pipelines"
            }
            Self::Log => {
                "/api/v1/organizations/{organization}/projects/{project}/builds/{build}/logs"
            }
            Self::Queue => "/api/v1/organizations/{organization}/projects/{project}/builds",
            Self::TestResult => {
                "/api/v1/organizations/{organization}/projects/{project}/builds/{build}/tests"
            }
        }
    }

    fn query_names(self) -> &'static [&'static str] {
        match self {
            Self::Log => &[
                "after_attempt_id",
                "after_fence",
                "after_sequence",
                "after_stream",
                "limit",
            ],
            Self::Queue => &["after_created_micros", "after_id", "limit", "status"],
            Self::JobMetadata => &["after", "limit"],
            Self::ArtifactContent => &["attempt_id", "name"],
            Self::Artifact | Self::BuildGraph | Self::BuildStatus | Self::TestResult => &[],
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalReadEndpointContract {
    pub resource: ExternalReadResource,
    pub endpoint: String,
    pub query: BTreeMap<String, String>,
    pub pagination: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalReadConsumerWrite {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub consumer_id: String,
    pub generation: i64,
    pub expected_current_generation: Option<i64>,
    pub authority: ExternalReadAuthority,
    pub source_inventory_digest: [u8; 32],
    pub source_inventory_generation: String,
    pub source_endpoint: String,
    pub source_caller: String,
    pub target_identity_id: Uuid,
    pub target_subject: String,
    pub target_api_base: String,
    pub target_api_version: String,
    pub endpoint_contracts: Vec<ExternalReadEndpointContract>,
    pub retention_semantics: String,
    pub url_semantics: String,
    pub rate_limit_per_minute: u32,
    pub observation_started_unix_ms: i64,
    pub observation_ended_unix_ms: i64,
    pub source_reads_observed: u64,
    pub positive_authorization_digest: [u8; 32],
    pub negative_authorization_digest: [u8; 32],
    pub equivalence_digest: [u8; 32],
    pub artifact_retrieval_digest: [u8; 32],
    pub pagination_resume_digest: [u8; 32],
    pub outage_behavior_digest: [u8; 32],
    pub rollback_from_generation: Option<i64>,
    pub rollback_evidence_digest: Option<[u8; 32]>,
    pub reviewer: String,
    pub actor_subject: String,
    pub expected_contract_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalReadConsumerReceipt {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub consumer_id: String,
    pub generation: i64,
    pub authority: ExternalReadAuthority,
    pub binding_digest: [u8; 32],
    pub contract_digest: [u8; 32],
}

impl Store {
    /// Appends one externally reviewed consumer-authority generation.
    ///
    /// Generation one records Jenkins as the source authority. A target
    /// transition is accepted only after an observation window reports zero
    /// residual Jenkins reads. Restoring Jenkins must point to the immediately
    /// preceding target generation and carry separate rollback evidence.
    pub async fn install_external_read_consumer(
        &self,
        input: &ExternalReadConsumerWrite,
    ) -> Result<ExternalReadConsumerReceipt, StoreError> {
        validate_input(input)?;
        let binding_digest = compute_external_read_consumer_binding_digest(input)?;
        let contract_digest = compute_external_read_consumer_digest(input)?;
        if contract_digest != input.expected_contract_digest {
            return invalid("external read consumer digest does not match canonical content");
        }
        let source_reads_observed = i64::try_from(input.source_reads_observed).map_err(|_| {
            StoreError::InvalidConsumerMigration("source read count overflow".into())
        })?;

        let mut tx = self.tenant_transaction(input.organization_id).await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!(
                "mcloving.external-read-consumer.{}.{}.{}",
                input.organization_id, input.project_id, input.consumer_id
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
            return invalid("external read consumer target project does not exist in the tenant");
        }
        let target_identity = sqlx::query_as::<_, (String, String)>(
            "SELECT lifecycle_state, kind FROM identities
             WHERE organization_id = $1 AND id = $2 AND subject = $3
             FOR UPDATE",
        )
        .bind(input.organization_id)
        .bind(input.target_identity_id)
        .bind(&input.target_subject)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((target_lifecycle, target_kind)) = target_identity else {
            return invalid("external read consumer target identity is absent or substituted");
        };
        if input.authority == ExternalReadAuthority::McLovingTarget && target_lifecycle != "active"
        {
            return invalid("external read consumer target identity is inactive");
        }
        if input.authority == ExternalReadAuthority::McLovingTarget {
            let principal = load_principal(
                &mut tx,
                input.organization_id,
                input.target_identity_id,
                &input.target_subject,
                &target_kind,
            )
            .await?;
            let required_actions = input
                .endpoint_contracts
                .iter()
                .map(|contract| contract.resource.required_action())
                .collect::<BTreeSet<_>>();
            for action in required_actions {
                if authorize(
                    &principal,
                    input.organization_id,
                    Some(input.project_id),
                    action,
                )
                .is_err()
                {
                    return invalid(format!(
                        "external read consumer target identity lacks required {} authority",
                        action.as_str()
                    ));
                }
            }
        }

        let current = sqlx::query_as::<_, (i64, String, bool)>(
            "SELECT current.current_generation, version.authority,
                    version.binding_digest = $4
             FROM external_read_consumer_current AS current
             JOIN external_read_consumer_versions AS version
               ON version.organization_id = current.organization_id
              AND version.project_id = current.project_id
              AND version.consumer_id = current.consumer_id
              AND version.generation = current.current_generation
             WHERE current.organization_id = $1 AND current.project_id = $2
               AND current.consumer_id = $3
             FOR UPDATE OF current",
        )
        .bind(input.organization_id)
        .bind(input.project_id)
        .bind(&input.consumer_id)
        .bind(binding_digest.as_slice())
        .fetch_optional(&mut *tx)
        .await?;
        if current.as_ref().map(|row| row.0) != input.expected_current_generation {
            return Err(StoreError::ConsumerMigrationConflict(
                "external read consumer current generation changed".to_owned(),
            ));
        }
        if current.as_ref().is_some_and(|row| !row.2) {
            return invalid(
                "external read consumer binding changed across an authority transition",
            );
        }
        let required_generation = match current.as_ref() {
            Some(row) => row.0.checked_add(1).ok_or_else(|| {
                StoreError::InvalidConsumerMigration(
                    "external read consumer generation overflow".to_owned(),
                )
            })?,
            None => 1,
        };
        if input.generation != required_generation {
            return invalid("external read consumer generation must advance by exactly one");
        }
        validate_transition(input, current.as_ref())?;

        let endpoint_contracts =
            serde_json::to_value(&input.endpoint_contracts).map_err(|error| {
                StoreError::InvalidConsumerMigration(format!(
                    "external read endpoint contracts cannot be encoded: {error}"
                ))
            })?;
        sqlx::query(
            "INSERT INTO external_read_consumer_versions (
                 organization_id, project_id, consumer_id, generation, authority,
                 binding_digest, contract_digest, source_inventory_digest, source_inventory_generation,
                 source_endpoint, source_caller, target_identity_id, target_subject,
                 target_api_base, target_api_version, endpoint_contracts,
                 retention_semantics, url_semantics, rate_limit_per_minute,
                 observation_started_unix_ms, observation_ended_unix_ms,
                 source_reads_observed, positive_authorization_digest,
                 negative_authorization_digest, equivalence_digest,
                 artifact_retrieval_digest, pagination_resume_digest,
                 outage_behavior_digest, rollback_from_generation,
                 rollback_evidence_digest, reviewer
             ) VALUES (
                 $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                 $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
                 $21, $22, $23, $24, $25, $26, $27, $28, $29, $30,
                 $31
             )",
        )
        .bind(input.organization_id)
        .bind(input.project_id)
        .bind(&input.consumer_id)
        .bind(input.generation)
        .bind(input.authority.as_str())
        .bind(binding_digest.as_slice())
        .bind(contract_digest.as_slice())
        .bind(input.source_inventory_digest.as_slice())
        .bind(&input.source_inventory_generation)
        .bind(&input.source_endpoint)
        .bind(&input.source_caller)
        .bind(input.target_identity_id)
        .bind(&input.target_subject)
        .bind(&input.target_api_base)
        .bind(&input.target_api_version)
        .bind(endpoint_contracts)
        .bind(&input.retention_semantics)
        .bind(&input.url_semantics)
        .bind(i64::from(input.rate_limit_per_minute))
        .bind(input.observation_started_unix_ms)
        .bind(input.observation_ended_unix_ms)
        .bind(source_reads_observed)
        .bind(input.positive_authorization_digest.as_slice())
        .bind(input.negative_authorization_digest.as_slice())
        .bind(input.equivalence_digest.as_slice())
        .bind(input.artifact_retrieval_digest.as_slice())
        .bind(input.pagination_resume_digest.as_slice())
        .bind(input.outage_behavior_digest.as_slice())
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
            "INSERT INTO external_read_consumer_current (
                 organization_id, project_id, consumer_id, current_generation
             ) VALUES ($1, $2, $3, $4)
             ON CONFLICT (organization_id, project_id, consumer_id) DO UPDATE
             SET current_generation = EXCLUDED.current_generation,
                 updated_at = clock_timestamp()",
        )
        .bind(input.organization_id)
        .bind(input.project_id)
        .bind(&input.consumer_id)
        .bind(input.generation)
        .execute(&mut *tx)
        .await?;

        append_audit_record(
            &mut tx,
            input.organization_id,
            "migration",
            &input.actor_subject,
            match input.authority {
                ExternalReadAuthority::JenkinsSource if input.generation == 1 => {
                    "external_read_consumer.registered"
                }
                ExternalReadAuthority::JenkinsSource => "external_read_consumer.rolled_back",
                ExternalReadAuthority::McLovingTarget => "external_read_consumer.cut_over",
            },
            &format!(
                "project:{}:external-read-consumer:{}",
                input.project_id, input.consumer_id
            ),
            json!({
                "project_id": input.project_id,
                "consumer_id": input.consumer_id,
                "generation": input.generation,
                "authority": input.authority.as_str(),
                "binding_digest": hex::encode(binding_digest),
                "contract_digest": hex::encode(contract_digest),
                "source_inventory_digest": hex::encode(input.source_inventory_digest),
                "source_reads_observed": input.source_reads_observed,
                "observation_started_unix_ms": input.observation_started_unix_ms,
                "observation_ended_unix_ms": input.observation_ended_unix_ms,
                "rollback_from_generation": input.rollback_from_generation,
                "reviewer": input.reviewer,
            }),
        )
        .await?;
        tx.commit().await?;

        Ok(ExternalReadConsumerReceipt {
            organization_id: input.organization_id,
            project_id: input.project_id,
            consumer_id: input.consumer_id.clone(),
            generation: input.generation,
            authority: input.authority,
            binding_digest,
            contract_digest,
        })
    }
}

pub fn compute_external_read_consumer_digest(
    input: &ExternalReadConsumerWrite,
) -> Result<[u8; 32], StoreError> {
    validate_input(input)?;
    let mut hasher = Sha256::new();
    hash(&mut hasher, b"mcloving-external-read-consumer-v1");
    hash(
        &mut hasher,
        &compute_external_read_consumer_binding_digest(input)?,
    );
    hash(&mut hasher, &input.generation.to_be_bytes());
    hash(&mut hasher, input.authority.as_str().as_bytes());
    hash(
        &mut hasher,
        &input.observation_started_unix_ms.to_be_bytes(),
    );
    hash(&mut hasher, &input.observation_ended_unix_ms.to_be_bytes());
    hash(&mut hasher, &input.source_reads_observed.to_be_bytes());
    for digest in [
        input.positive_authorization_digest,
        input.negative_authorization_digest,
        input.equivalence_digest,
        input.artifact_retrieval_digest,
        input.pagination_resume_digest,
        input.outage_behavior_digest,
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

pub fn compute_external_read_consumer_binding_digest(
    input: &ExternalReadConsumerWrite,
) -> Result<[u8; 32], StoreError> {
    validate_input(input)?;
    let mut hasher = Sha256::new();
    hash(&mut hasher, b"mcloving-external-read-consumer-binding-v1");
    hash(&mut hasher, input.organization_id.as_bytes());
    hash(&mut hasher, input.project_id.as_bytes());
    hash(&mut hasher, input.consumer_id.as_bytes());
    hash(&mut hasher, &input.source_inventory_digest);
    hash(&mut hasher, input.source_inventory_generation.as_bytes());
    hash(&mut hasher, input.source_endpoint.as_bytes());
    hash(&mut hasher, input.source_caller.as_bytes());
    hash(&mut hasher, input.target_identity_id.as_bytes());
    hash(&mut hasher, input.target_subject.as_bytes());
    hash(&mut hasher, input.target_api_base.as_bytes());
    hash(&mut hasher, input.target_api_version.as_bytes());
    let mut contracts = input.endpoint_contracts.iter().collect::<Vec<_>>();
    contracts.sort_by_key(|contract| contract.resource);
    for contract in contracts {
        hash(&mut hasher, contract.resource.as_str().as_bytes());
        hash(&mut hasher, contract.endpoint.as_bytes());
        for (name, value) in &contract.query {
            hash(&mut hasher, name.as_bytes());
            hash(&mut hasher, value.as_bytes());
        }
        hash(&mut hasher, contract.pagination.as_bytes());
    }
    hash(&mut hasher, input.retention_semantics.as_bytes());
    hash(&mut hasher, input.url_semantics.as_bytes());
    hash(&mut hasher, &input.rate_limit_per_minute.to_be_bytes());
    Ok(hasher.finalize().into())
}

fn validate_transition(
    input: &ExternalReadConsumerWrite,
    current: Option<&(i64, String, bool)>,
) -> Result<(), StoreError> {
    match (current, input.authority) {
        (None, ExternalReadAuthority::JenkinsSource) => {
            if input.rollback_from_generation.is_some() || input.rollback_evidence_digest.is_some()
            {
                return invalid("initial Jenkins authority cannot be a rollback");
            }
        }
        (None, ExternalReadAuthority::McLovingTarget) => {
            return invalid("McLoving authority requires a retained Jenkins source generation");
        }
        (Some((_, authority, _)), ExternalReadAuthority::McLovingTarget)
            if authority == ExternalReadAuthority::JenkinsSource.as_str() =>
        {
            if input.source_reads_observed != 0 {
                return invalid("McLoving authority requires zero residual Jenkins reads");
            }
            if input.rollback_from_generation.is_some() || input.rollback_evidence_digest.is_some()
            {
                return invalid("McLoving cutover cannot carry rollback fields");
            }
        }
        (Some((generation, authority, _)), ExternalReadAuthority::JenkinsSource)
            if authority == ExternalReadAuthority::McLovingTarget.as_str() =>
        {
            if input.rollback_from_generation != Some(*generation)
                || input.rollback_evidence_digest.is_none()
            {
                return invalid(
                    "Jenkins restoration must bind the immediately preceding target generation",
                );
            }
        }
        (Some(_), _) => return invalid("external read consumer authority must alternate"),
    }
    Ok(())
}

fn validate_input(input: &ExternalReadConsumerWrite) -> Result<(), StoreError> {
    if input.generation <= 0 {
        return invalid("external read consumer generation must be positive");
    }
    for (name, value, max) in [
        ("consumer id", input.consumer_id.as_str(), 256),
        (
            "source inventory generation",
            input.source_inventory_generation.as_str(),
            512,
        ),
        ("source endpoint", input.source_endpoint.as_str(), 2048),
        ("source caller", input.source_caller.as_str(), 512),
        ("target subject", input.target_subject.as_str(), 512),
        ("target API base", input.target_api_base.as_str(), 2048),
        (
            "retention semantics",
            input.retention_semantics.as_str(),
            2048,
        ),
        ("URL semantics", input.url_semantics.as_str(), 2048),
        ("reviewer", input.reviewer.as_str(), 512),
        ("actor subject", input.actor_subject.as_str(), 512),
    ] {
        validate_text(name, value, max)?;
    }
    if !http_endpoint(&input.source_endpoint) || !http_endpoint(&input.target_api_base) {
        return invalid("source and target endpoints must be explicit HTTP(S) URLs");
    }
    if input.target_api_version != "v1" {
        return invalid("external read consumer target API version must be v1");
    }
    if input.rate_limit_per_minute == 0 || input.rate_limit_per_minute > 1_000_000 {
        return invalid("external read consumer rate limit is outside its bounded range");
    }
    if input.observation_started_unix_ms <= 0
        || input.observation_ended_unix_ms <= input.observation_started_unix_ms
    {
        return invalid("external read consumer observation window is invalid");
    }
    if input.endpoint_contracts.is_empty() || input.endpoint_contracts.len() > 8 {
        return invalid("external read consumer must bind one to eight read resources");
    }
    let mut resources = BTreeSet::new();
    for contract in &input.endpoint_contracts {
        if !resources.insert(contract.resource) {
            return invalid("external read consumer resources must be unique");
        }
        validate_text("endpoint", &contract.endpoint, 2048)?;
        validate_text("pagination semantics", &contract.pagination, 2048)?;
        if !contract.endpoint.starts_with("/api/v1/")
            || contract.endpoint.contains('?')
            || contract.endpoint.contains('#')
        {
            return invalid("external read endpoint must be a query-free /api/v1 path");
        }
        if contract.endpoint != contract.resource.endpoint() {
            return invalid("external read endpoint does not match its resource");
        }
        if contract.query.len() > 32 {
            return invalid("external read endpoint query contract is too large");
        }
        for (name, value) in &contract.query {
            validate_text("query name", name, 128)?;
            validate_text("query semantics", value, 1024)?;
        }
        let query_names = contract
            .query
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let expected_query_names = contract
            .resource
            .query_names()
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if query_names != expected_query_names {
            return invalid("external read query contract does not match its resource");
        }
    }
    for digest in [
        input.source_inventory_digest,
        input.positive_authorization_digest,
        input.negative_authorization_digest,
        input.equivalence_digest,
        input.artifact_retrieval_digest,
        input.pagination_resume_digest,
        input.outage_behavior_digest,
    ] {
        if digest == [0; 32] {
            return invalid("external read consumer evidence digests must be non-zero");
        }
    }
    if input.rollback_evidence_digest == Some([0; 32]) {
        return invalid("external read consumer rollback evidence digest must be non-zero");
    }
    if input.rollback_from_generation.is_some() != input.rollback_evidence_digest.is_some() {
        return invalid("external read consumer rollback fields must be supplied together");
    }
    Ok(())
}

fn validate_text(name: &str, value: &str, max: usize) -> Result<(), StoreError> {
    if value.is_empty() || value.trim() != value || value.len() > max || value.contains('\0') {
        return invalid(format!("external read consumer {name} is invalid"));
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
    Err(StoreError::InvalidConsumerMigration(message.into()))
}
