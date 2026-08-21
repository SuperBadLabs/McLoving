#![recursion_limit = "256"]
//! Versioned public HTTP API and its Rust client.

mod oidc;

pub use mcloving_controller_store::{BuildCursor, PipelineOperationalState};
pub use oidc::{
    MAX_OIDC_CLOCK_SKEW_SECONDS, MAX_OIDC_JWKS_BYTES, MAX_OIDC_REFRESH_TTL_SECONDS,
    MAX_OIDC_REQUEST_TIMEOUT_SECONDS, MAX_OIDC_SESSION_TTL_SECONDS, OidcClientConfig,
};

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::DefaultBodyLimit;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use mcloving_controller_store::{
    ApprovalView, ArtifactMetadata, AuditPage, BuildGraph, BuildPage, CancellationDecision,
    ComponentCursor, ComponentPage, ComponentPutOutcome, ComponentRecord, ComponentWrite,
    CredentialGrantView, DagDependency, DagNodeKind, DependencyCondition, DiscoveredRefKind,
    DiscoveryChild, DiscoveryChildState, DiscoveryObservationWrite, DiscoveryParent,
    DiscoveryParentKind, DiscoveryParentPutOutcome, DiscoveryParentState, DiscoveryParentWrite,
    DiscoveryScanOutcome, DiscoveryScanReceipt, DiscoveryScanSource, DiscoveryScanWrite,
    ForkTrustStrategy, MAX_OBJECT_RETENTION_SECONDS, NewDagBuild, NewDagNode,
    NewEnvironmentApproval, NewTriggerDelivery, ObjectKind, ObjectStatus, OrphanPolicy,
    PipelineOperationalStateRecord, PipelineOperationalStateTransition,
    PipelineOperationalStateTransitionOutcome, PipelinePage, PipelinePutOutcome, PipelineRecord,
    PipelineTrigger, PipelineTriggerState, PipelineTriggerWrite, PipelineWrite,
    PullRequestDiscoveryStrategy, RetryDecision, Store, StoreError, TRIGGER_DAG_IDEMPOTENCY_PREFIX,
    TestReportView, TriggerDelivery, TriggerDeliveryAdmission, TriggerDeliveryClaimOutcome,
    TriggerDeliveryClaimRequest, TriggerDeliveryDagAdmission, TriggerDeliveryDagAdmissionRequest,
    TriggerDeliveryFailure, TriggerDeliveryFailureRequest, TriggerDeliveryRedrive, TriggerKind,
    TriggerPutOutcome, TriggerScheduleSlot, WaitReason,
    authz::{Action, Principal, authorize as authorize_principal},
};
use mcloving_object_store::{
    FilesystemObjectStore, ObjectGap, ObjectRef, ObjectStoreError, PendingObject,
};
use mcloving_pipeline_ir::{
    ParameterType, ParameterValue, ParseLimits, PipelineIr, ProcessMode, Step,
    compile_strict_yaml_with_parameters,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const IDEMPOTENCY_HEADER: &str = "idempotency-key";
pub const TRUST_POOL_HEADER: &str = "mcloving-trust-pool";
pub const PLATFORM_HEADER: &str = "mcloving-platform";
pub const ARTIFACT_NAME_HEADER: &str = "mcloving-artifact-name";
pub const ARTIFACT_AGENT_AUTHORIZATION_HEADER: &str = "mcloving-agent-authorization";
pub const MAX_DISCOVERY_SCAN_BODY_BYTES: usize = 128 * 1024 * 1024;
pub const CONNECTOR_MAPPING_CATALOG_V1: &str = "mcloving.connector-mapping-catalog/v1";
const DEFAULT_TRUST_POOL: &str = "trusted-linux";
const DEFAULT_PLATFORM: &str = "linux";
const MAX_PUBLICATION_CLAIM_RECONCILIATION: usize = 128;
const MAX_DISCOVERY_SCAN_OBSERVATIONS: usize = 4096;

#[derive(Clone)]
pub struct ApiState {
    store: Store,
    authentication: Authentication,
    artifact_agents: Vec<ArtifactAgentCredential>,
    object_store: Option<FilesystemObjectStore>,
    artifact_body_limit: usize,
    staged_upload_ttl: Duration,
    publication_claim_cursor: Arc<Mutex<Option<String>>>,
    oidc_clients: BTreeMap<(Uuid, Uuid), oidc::OidcClient>,
    connector_mapping_catalog: ConnectorMappingCatalog,
}

/// Deployment-owned admission catalog for one exact execution profile.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorMappingCatalog {
    pub schema_version: String,
    pub profile: String,
    pub generation: u64,
    pub mappings: Vec<ConnectorMappingRecord>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorMappingRecord {
    pub mapping_id: String,
    pub mapping_digest: String,
}

impl ConnectorMappingCatalog {
    fn deny_all() -> Self {
        Self {
            schema_version: CONNECTOR_MAPPING_CATALOG_V1.to_owned(),
            profile: "unconfigured".to_owned(),
            generation: 0,
            mappings: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<(), ApiError> {
        if self.schema_version != CONNECTOR_MAPPING_CATALOG_V1
            || self.generation == 0
            || !canonical_mapping_name(&self.profile)
            || self.mappings.is_empty()
            || self.mappings.len() > 1_024
        {
            return Err(ApiError::configuration(
                "connector mapping catalog schema, profile, generation, or size is invalid",
            ));
        }
        let mut identifiers = BTreeSet::new();
        for mapping in &self.mappings {
            if !canonical_mapping_name(&mapping.mapping_id)
                || !canonical_sha256_reference(&mapping.mapping_digest)
                || !identifiers.insert(&mapping.mapping_id)
            {
                return Err(ApiError::configuration(
                    "connector mapping catalog contains an invalid or duplicate mapping",
                ));
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn contains_exact(&self, mapping_id: &str, mapping_digest: &str) -> bool {
        self.mappings.iter().any(|mapping| {
            mapping.mapping_id == mapping_id && mapping.mapping_digest == mapping_digest
        })
    }
}

#[derive(Clone)]
struct ApiCredential {
    token_digest: [u8; 32],
    principal: Principal,
}

#[derive(Clone)]
enum Authentication {
    /// Test and compatibility construction only. The shipped controller uses
    /// the durable identity/session tables instead.
    Static(Vec<ApiCredential>),
    Durable,
}

#[derive(Clone)]
struct ArtifactAgentCredential {
    token_digest: [u8; 32],
    agent_id: String,
}

impl ApiState {
    pub fn new(store: Store, bearer_token: &str, principal: Principal) -> Result<Self, ApiError> {
        if bearer_token.len() < 32 {
            return Err(ApiError::configuration(
                "bearer token must contain at least 32 bytes",
            ));
        }
        Ok(Self {
            store,
            authentication: Authentication::Static(vec![ApiCredential {
                token_digest: Sha256::digest(bearer_token.as_bytes()).into(),
                principal,
            }]),
            artifact_agents: Vec::new(),
            object_store: None,
            artifact_body_limit: 2 * 1024 * 1024,
            staged_upload_ttl: Duration::from_secs(24 * 60 * 60),
            publication_claim_cursor: Arc::new(Mutex::new(None)),
            oidc_clients: BTreeMap::new(),
            connector_mapping_catalog: ConnectorMappingCatalog::deny_all(),
        })
    }

    /// Constructs the production API authentication path.
    ///
    /// Human sessions and service credentials are resolved from PostgreSQL on
    /// every request, so revocation and lifecycle-generation fences apply
    /// across every active controller without process-local token state.
    pub fn new_durable(store: Store) -> Self {
        Self {
            store,
            authentication: Authentication::Durable,
            artifact_agents: Vec::new(),
            object_store: None,
            artifact_body_limit: 2 * 1024 * 1024,
            staged_upload_ttl: Duration::from_secs(24 * 60 * 60),
            publication_claim_cursor: Arc::new(Mutex::new(None)),
            oidc_clients: BTreeMap::new(),
            connector_mapping_catalog: ConnectorMappingCatalog::deny_all(),
        }
    }

    pub async fn process_due_trigger_deliveries(
        &self,
        organization_id: Uuid,
        limit: i64,
    ) -> Result<usize, ApiError> {
        let scan_unix_ms = unix_time_ms();
        let deliveries = self
            .store
            .due_trigger_deliveries(organization_id, scan_unix_ms, limit)
            .await
            .map_err(trigger_error)?;
        let mut processed = 0;
        for delivery in deliveries {
            process_trigger_delivery(self, delivery, unix_time_ms()).await?;
            processed += 1;
        }
        Ok(processed)
    }

    /// Adds another independently authenticated API principal.
    ///
    /// Distinct human approvers must use distinct tokens and subjects so
    /// multi-party policy cannot collapse them into the controller service
    /// identity.
    pub fn with_bearer_principal(
        mut self,
        bearer_token: &str,
        principal: Principal,
    ) -> Result<Self, ApiError> {
        validate_bearer_secret(bearer_token)?;
        let token_digest: [u8; 32] = Sha256::digest(bearer_token.as_bytes()).into();
        let Authentication::Static(credentials) = &mut self.authentication else {
            return Err(ApiError::configuration(
                "process-local bearer principals are forbidden in durable authentication mode",
            ));
        };
        if credentials
            .iter()
            .any(|credential| constant_time_eq(&credential.token_digest, &token_digest))
            || self
                .artifact_agents
                .iter()
                .any(|credential| constant_time_eq(&credential.token_digest, &token_digest))
        {
            return Err(ApiError::configuration(
                "API and artifact-agent bearer tokens must be globally unique",
            ));
        }
        credentials.push(ApiCredential {
            token_digest,
            principal,
        });
        Ok(self)
    }

    /// Binds an independent bearer secret to one artifact-publishing agent.
    ///
    /// The public API bearer token is deliberately insufficient for immutable
    /// artifact publication.
    pub fn with_artifact_agent_token(
        mut self,
        bearer_token: &str,
        agent_id: &str,
    ) -> Result<Self, ApiError> {
        validate_bearer_secret(bearer_token)?;
        if agent_id.trim().is_empty() || agent_id.trim() != agent_id {
            return Err(ApiError::configuration(
                "artifact agent ID must be non-empty and canonical",
            ));
        }
        let token_digest: [u8; 32] = Sha256::digest(bearer_token.as_bytes()).into();
        let Authentication::Static(credentials) = &self.authentication else {
            return Err(ApiError::configuration(
                "durable authentication requires a database-backed artifact-agent token check",
            ));
        };
        if credentials
            .iter()
            .any(|credential| constant_time_eq(&credential.token_digest, &token_digest))
            || self.artifact_agents.iter().any(|credential| {
                credential.agent_id == agent_id
                    || constant_time_eq(&credential.token_digest, &token_digest)
            })
        {
            return Err(ApiError::configuration(
                "artifact agent IDs must be unique and bearer tokens must be globally unique",
            ));
        }
        self.artifact_agents.push(ArtifactAgentCredential {
            token_digest,
            agent_id: agent_id.to_owned(),
        });
        Ok(self)
    }

    /// Binds an artifact-publishing agent after atomically reserving its bearer
    /// digest outside every durable API credential namespace for this tenant.
    pub async fn with_durable_artifact_agent_token(
        mut self,
        bearer_token: &str,
        agent_id: &str,
        organization_id: Uuid,
    ) -> Result<Self, ApiError> {
        validate_bearer_secret(bearer_token)?;
        if agent_id.trim().is_empty() || agent_id.trim() != agent_id {
            return Err(ApiError::configuration(
                "artifact agent ID must be non-empty and canonical",
            ));
        }
        if !matches!(self.authentication, Authentication::Durable) {
            return Err(ApiError::configuration(
                "database-backed artifact-agent token checks require durable authentication",
            ));
        }
        let token_digest: [u8; 32] = Sha256::digest(bearer_token.as_bytes()).into();
        if self.artifact_agents.iter().any(|credential| {
            credential.agent_id == agent_id
                || constant_time_eq(&credential.token_digest, &token_digest)
        }) {
            return Err(ApiError::configuration(
                "artifact agent IDs must be unique and bearer tokens must be globally unique",
            ));
        }
        self.store
            .reserve_artifact_agent_credential(organization_id, agent_id, token_digest)
            .await
            .map_err(|error| {
                ApiError::configuration(format!(
                    "reserve artifact-agent bearer in the durable credential namespace: {error}"
                ))
            })?;
        self.artifact_agents.push(ArtifactAgentCredential {
            token_digest,
            agent_id: agent_id.to_owned(),
        });
        Ok(self)
    }

    pub fn with_object_store(mut self, object_store: FilesystemObjectStore) -> Self {
        self.artifact_body_limit =
            usize::try_from(object_store.quota().max_object_bytes).unwrap_or(usize::MAX);
        self.object_store = Some(object_store);
        self
    }

    pub fn with_connector_mapping_catalog(
        mut self,
        catalog: ConnectorMappingCatalog,
    ) -> Result<Self, ApiError> {
        catalog.validate()?;
        self.connector_mapping_catalog = catalog;
        Ok(self)
    }

    /// Sets the maximum age of a durable but unpublished artifact upload.
    ///
    /// Reclamation runs before each new upload, so abandoned reservations
    /// cannot permanently consume the tenant's object-store quota.
    pub fn with_staged_upload_ttl(mut self, staged_upload_ttl: Duration) -> Self {
        self.staged_upload_ttl = staged_upload_ttl;
        self
    }

    pub fn with_oidc_client(mut self, config: OidcClientConfig) -> Result<Self, ApiError> {
        if !matches!(self.authentication, Authentication::Durable) {
            return Err(ApiError::configuration(
                "OIDC requires durable database-backed authentication",
            ));
        }
        let key = (config.organization_id, config.provider_id);
        if self.oidc_clients.contains_key(&key) {
            return Err(ApiError::configuration(
                "OIDC provider is configured more than once",
            ));
        }
        self.oidc_clients
            .insert(key, oidc::OidcClient::new(config)?);
        Ok(self)
    }
}

pub fn router(state: ApiState) -> Router {
    let artifact_upload = Router::new()
        .route(
            "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/artifact-uploads",
            post(stage_artifact),
        )
        .route_layer(DefaultBodyLimit::max(state.artifact_body_limit));
    let discovery_scan = Router::new()
        .route(
            "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}/discovery/{parent_id}/scans",
            post(reconcile_discovery_scan),
        )
        // A maximally populated accepted observation contains fewer than 30 KiB
        // even with six-byte JSON escaping for every bounded string byte and
        // escaped field names. 4,096 observations plus the bounded envelope
        // therefore fit below this conservative 128 MiB transport ceiling.
        .route_layer(DefaultBodyLimit::max(MAX_DISCOVERY_SCAN_BODY_BYTES));
    static_ui_router()
        .route("/openapi.json", get(openapi))
        .route(
            "/api/v1/organizations/{organization_id}/auth/oidc/{provider_id}/start",
            get(oidc::start),
        )
        .route(
            "/api/v1/organizations/{organization_id}/auth/oidc/{provider_id}/callback",
            get(oidc::callback),
        )
        .route(
            "/api/v1/organizations/{organization_id}/auth/session/refresh",
            post(oidc::refresh),
        )
        .route(
            "/api/v1/organizations/{organization_id}/auth/session/logout",
            post(oidc::logout),
        )
        .route(
            "/api/v1/organizations/{organization_id}/audit",
            get(list_audit),
        )
        .route(
            "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/validate",
            post(validate_pipeline),
        )
        .route(
            "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/plan",
            post(plan_pipeline),
        )
        .route(
            "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines",
            get(list_pipelines),
        )
        .route(
            "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}",
            get(get_pipeline).put(put_pipeline),
        )
        .route(
            "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}/state",
            get(get_pipeline_state).put(put_pipeline_state),
        )
        .route(
            "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}/builds",
            post(submit_pipeline_build),
        )
        .route(
            "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}/triggers/{trigger_id}",
            get(get_pipeline_trigger).put(put_pipeline_trigger),
        )
        .route(
            "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}/triggers/{trigger_id}/events",
            post(submit_trigger_event),
        )
        .route(
            "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}/triggers/{trigger_id}/deliveries/{delivery_id}/redrive",
            post(redrive_trigger_event),
        )
        .route(
            "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}/discovery/{parent_id}",
            get(get_discovery_parent).put(put_discovery_parent),
        )
        .merge(discovery_scan)
        .route(
            "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}/discovery/{parent_id}/children",
            get(list_discovery_children),
        )
        .route(
            "/api/v1/organizations/{organization_id}/projects/{project_id}/components",
            get(list_components),
        )
        .route(
            "/api/v1/organizations/{organization_id}/projects/{project_id}/components/{digest}",
            get(get_component).put(put_component),
        )
        .route(
            "/api/v1/organizations/{organization_id}/projects/{project_id}/builds",
            get(list_builds),
        )
        .route(
            "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}",
            get(status),
        )
        .route(
            "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/logs",
            get(logs),
        )
        .route(
            "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/graph",
            get(build_graph),
        )
        .route(
            "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/approvals",
            get(list_approvals).post(create_approval),
        )
        .route(
            "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/credential-grants",
            get(list_credential_grants),
        )
        .route(
            "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/tests",
            get(list_test_reports),
        )
        .route(
            "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/cancel",
            post(cancel),
        )
        .route(
            "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/attempts/{attempt_id}/retry",
            post(retry_attempt),
        )
        .merge(artifact_upload)
        .route(
            "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/artifact-uploads/{upload_token}/commit",
            post(commit_artifact),
        )
        .route(
            "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/artifacts",
            get(list_artifacts),
        )
        .route(
            "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/artifacts/metadata",
            get(artifact_metadata),
        )
        .route(
            "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/artifacts/content",
            get(download_artifact),
        )
        .route(
            "/api/v1/organizations/{organization_id}/scheduler/explain",
            get(explain),
        )
        .with_state(Arc::new(state))
}

pub fn static_ui_router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/", get(ui_index))
        .route("/app.js", get(ui_javascript))
        .route("/app.css", get(ui_stylesheet))
}

const UI_INDEX: &str = include_str!("../ui/index.html");
const UI_JAVASCRIPT: &str = include_str!("../ui/app.js");
const UI_STYLESHEET: &str = include_str!("../ui/app.css");
const UI_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

async fn ui_index() -> Response {
    static_ui_response("text/html; charset=utf-8", UI_INDEX)
}

async fn ui_javascript() -> Response {
    static_ui_response("text/javascript; charset=utf-8", UI_JAVASCRIPT)
}

async fn ui_stylesheet() -> Response {
    static_ui_response("text/css; charset=utf-8", UI_STYLESHEET)
}

fn static_ui_response(content_type: &'static str, body: &'static str) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(UI_CSP),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    (headers, body).into_response()
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SubmissionRequest {
    pub source: String,
    #[serde(default)]
    pub parameters: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PipelineBuildRequest {
    #[serde(default)]
    pub parameters: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PipelineOperationalStateRequest {
    pub state: PipelineOperationalState,
    pub reason: String,
    pub source_identity: String,
    pub source_generation: String,
    pub source_effective_at_unix_ms: i64,
    pub source_provenance_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PipelineTriggerRequest {
    pub kind: TriggerKind,
    pub state: PipelineTriggerState,
    pub implementation_sha256: String,
    pub configuration_sha256: String,
    pub filter_sha256: String,
    pub event_source_identity: String,
    pub source_generation: String,
    pub configuration: Value,
    pub deduplication_window_seconds: i64,
    pub max_delivery_attempts: i32,
    pub delivery_ttl_seconds: i64,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PipelineTriggerResponse {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub pipeline_id: Uuid,
    pub trigger_id: Uuid,
    pub generation: i64,
    pub kind: TriggerKind,
    pub state: PipelineTriggerState,
    pub implementation_sha256: String,
    pub configuration_sha256: String,
    pub filter_sha256: String,
    pub event_source_identity: String,
    pub source_generation: String,
    pub configuration: Value,
    pub deduplication_window_seconds: i64,
    pub max_delivery_attempts: i32,
    pub delivery_ttl_seconds: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TriggerEventRequest {
    pub trigger_generation: i64,
    pub delivery_id: String,
    pub event_id: String,
    pub event_kind: String,
    pub event_time_unix_ms: i64,
    pub payload: Value,
    #[serde(default)]
    pub parameters: BTreeMap<String, Value>,
    #[serde(default = "default_platform")]
    pub platform: String,
    #[serde(default = "default_trust_pool")]
    pub trust_pool: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct TriggerEventResponse {
    pub delivery: TriggerDelivery,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admission: Option<AdmissionResponse>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TriggerRedriveRequest {
    pub delivery_id: String,
    pub event_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryParentRequest {
    pub kind: DiscoveryParentKind,
    pub state: DiscoveryParentState,
    pub implementation_sha256: String,
    pub protocol_version: String,
    pub configuration_sha256: String,
    pub provider: String,
    pub provider_identity: String,
    pub organization_identity: Option<String>,
    pub repositories: Vec<String>,
    #[serde(default)]
    pub branch_includes: Vec<String>,
    #[serde(default)]
    pub branch_excludes: Vec<String>,
    pub pull_request_strategy: PullRequestDiscoveryStrategy,
    pub fork_trust_strategy: ForkTrustStrategy,
    #[serde(default)]
    pub trusted_fork_repositories: Vec<String>,
    pub jenkinsfile_path: String,
    pub child_configuration_policy_sha256: String,
    pub orphan_policy: OrphanPolicy,
    pub authorization_generation: i64,
    pub authorization_policy_sha256: String,
    pub trigger_id: Uuid,
    pub trigger_generation: i64,
    pub trigger_configuration_sha256: String,
    pub source_implementation_sha256: String,
    pub source_protocol_version: String,
    pub source_configuration_sha256: String,
    pub restored_from_generation: Option<i64>,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DiscoveryParentResponse {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub pipeline_id: Uuid,
    pub parent_id: Uuid,
    pub generation: i64,
    pub kind: DiscoveryParentKind,
    pub state: DiscoveryParentState,
    pub implementation_sha256: String,
    pub protocol_version: String,
    pub configuration_sha256: String,
    pub provider: String,
    pub provider_identity: String,
    pub organization_identity: Option<String>,
    pub repositories: Vec<String>,
    pub branch_includes: Vec<String>,
    pub branch_excludes: Vec<String>,
    pub pull_request_strategy: PullRequestDiscoveryStrategy,
    pub fork_trust_strategy: ForkTrustStrategy,
    pub trusted_fork_repositories: Vec<String>,
    pub jenkinsfile_path: String,
    pub child_configuration_policy_sha256: String,
    pub orphan_policy: OrphanPolicy,
    pub authorization_generation: i64,
    pub authorization_policy_sha256: String,
    pub trigger_id: Uuid,
    pub trigger_generation: i64,
    pub trigger_configuration_sha256: String,
    pub source_implementation_sha256: String,
    pub source_protocol_version: String,
    pub source_configuration_sha256: String,
    pub restored_from_generation: Option<i64>,
    pub audit_sequence: i64,
    pub audit_event_hash: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryObservationRequest {
    pub child_key: String,
    pub child_pipeline_id: Uuid,
    pub repository_identity: String,
    pub ref_kind: DiscoveredRefKind,
    pub ref_name: String,
    pub pull_request_number: Option<i64>,
    pub head_repository_identity: String,
    pub present: bool,
    pub revision: String,
    pub provenance_sha256: String,
    pub jenkinsfile_path: String,
    pub jenkinsfile_sha256: String,
    pub child_configuration_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryScanRequest {
    pub parent_generation: i64,
    pub scan_id: String,
    pub source: DiscoveryScanSource,
    pub source_event_id: Option<String>,
    pub source_cursor: i64,
    pub complete_snapshot: bool,
    pub provider_snapshot_sha256: String,
    pub request_sha256: String,
    pub observations: Vec<DiscoveryObservationRequest>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DiscoveryScanResponse {
    pub receipt: DiscoveryScanReceiptResponse,
    pub replayed: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct DiscoveryScanReceiptResponse {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub pipeline_id: Uuid,
    pub parent_id: Uuid,
    pub parent_generation: i64,
    pub scan_id: String,
    pub source: DiscoveryScanSource,
    pub source_event_id: Option<String>,
    pub source_cursor: i64,
    pub complete_snapshot: bool,
    pub provider_snapshot_sha256: String,
    pub request_sha256: String,
    pub observation_count: usize,
    pub selected_count: usize,
    pub active_count: usize,
    pub quarantined_count: usize,
    pub retired_count: usize,
    pub audit_sequence: i64,
    pub audit_event_hash: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct DiscoveryChildResponse {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub pipeline_id: Uuid,
    pub parent_id: Uuid,
    pub child_key: String,
    pub child_pipeline_id: Uuid,
    pub repository_identity: String,
    pub ref_kind: DiscoveredRefKind,
    pub ref_name: String,
    pub pull_request_number: Option<i64>,
    pub head_repository_identity: String,
    pub is_fork: bool,
    pub state: DiscoveryChildState,
    pub state_generation: i64,
    pub revision: String,
    pub provenance_sha256: String,
    pub jenkinsfile_path: String,
    pub jenkinsfile_sha256: String,
    pub child_configuration_sha256: String,
    pub parent_generation: i64,
    pub source_cursor: i64,
    pub last_scan_id: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct DiscoveryChildPageResponse {
    pub items: Vec<DiscoveryChildResponse>,
    pub next_after: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PipelineUpsertRequest {
    pub slug: String,
    pub source: String,
    #[serde(default)]
    pub parameters: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PipelinePlanResponse {
    pub schema_major: u16,
    pub schema_minor: u16,
    pub semantic_digest: String,
    pub parameters: Value,
    pub stages: Vec<PipelineStagePlan>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PipelineStagePlan {
    pub id: String,
    pub name: String,
    pub process_steps: usize,
    pub connector_intent_steps: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ValidationResponse {
    pub valid: bool,
    pub semantic_digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ComponentUpsertRequest {
    pub name: String,
    pub version_major: i32,
    pub version_minor: i32,
    pub canonical_hex: String,
    pub source_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ApprovalRequest {
    pub approval_id: Uuid,
    pub environment: String,
    pub action: String,
    pub ttl_seconds: i32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RetryRequest {
    pub max_attempts: i32,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum RetryResponse {
    Scheduled {
        attempt_id: Uuid,
        ordinal: i32,
        created: bool,
    },
    DeadLettered,
    Ineligible,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct PageQuery {
    pub limit: Option<u32>,
    pub after: Option<String>,
    pub after_digest: Option<String>,
    pub after_created_micros: Option<i64>,
    pub after_id: Option<Uuid>,
    pub status: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct AuditQuery {
    pub after_sequence: Option<i64>,
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct LogQuery {
    pub after_attempt_id: Option<Uuid>,
    pub after_fence: Option<i64>,
    pub after_sequence: Option<i64>,
    pub after_stream: Option<String>,
    pub limit: Option<u32>,
}

async fn openapi() -> Json<Value> {
    Json(openapi_document())
}

fn openapi_document() -> Value {
    let organization = path_parameter("organization_id", "uuid");
    let provider = path_parameter("provider_id", "uuid");
    let project = path_parameter("project_id", "uuid");
    let pipeline = path_parameter("pipeline_id", "uuid");
    let trigger = path_parameter("trigger_id", "uuid");
    let discovery_parent = path_parameter("parent_id", "uuid");
    let delivery = path_parameter("delivery_id", "string");
    let digest = path_parameter("digest", "sha256");
    let build = path_parameter("build_id", "uuid");
    let attempt = path_parameter("attempt_id", "uuid");
    let upload = path_parameter("upload_token", "string");
    let page = vec![
        query_parameter("limit", "integer"),
        query_parameter("after", "string"),
    ];
    let build_page = vec![
        query_parameter("limit", "integer"),
        query_parameter("after_created_micros", "integer"),
        query_parameter("after_id", "uuid"),
        query_parameter("status", "string"),
    ];
    let component_page = vec![
        query_parameter("limit", "integer"),
        query_parameter("after", "string"),
        query_parameter("after_digest", "sha256"),
    ];
    let trigger_event_payload = trigger_event_payload_schema();
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "McLoving public API",
            "version": "v1",
            "description": "Tenant-scoped, API-first controller contract. All mutating retries require an explicit idempotency or revision precondition."
        },
        "servers": [{"url": "/"}],
        "tags": [
            {"name": "authentication"},
            {"name": "pipelines"},
            {"name": "triggers"},
            {"name": "discovery"},
            {"name": "components"},
            {"name": "builds"},
            {"name": "evidence"},
            {"name": "security"},
            {"name": "audit"},
            {"name": "scheduler"}
        ],
        "security": [{"bearer": []}],
        "paths": {
            "/api/v1/organizations/{organization_id}/auth/oidc/{provider_id}/start": {
                "parameters": [organization.clone(), provider.clone()],
                "get": unauthenticated_api_operation(
                    "startOidcLogin", "authentication", "Start OIDC authorization code with PKCE", "200",
                    vec![required_query_parameter("redirect_uri", "string")], None
                )
            },
            "/api/v1/organizations/{organization_id}/auth/oidc/{provider_id}/callback": {
                "parameters": [organization.clone(), provider],
                "get": unauthenticated_api_operation(
                    "completeOidcLogin", "authentication", "Complete one-time OIDC callback", "200",
                    vec![
                        required_query_parameter("code", "string"),
                        required_query_parameter("state", "string")
                    ], None
                )
            },
            "/api/v1/organizations/{organization_id}/auth/session/refresh": {
                "parameters": [organization.clone()],
                "post": unauthenticated_api_operation(
                    "refreshOidcSession", "authentication", "Rotate an OIDC refresh credential", "200",
                    Vec::new(), Some("RefreshRequest")
                )
            },
            "/api/v1/organizations/{organization_id}/auth/session/logout": {
                "parameters": [organization.clone()],
                "post": api_operation(
                    "logoutOidcSession", "authentication", "Revoke the current OIDC session", "200",
                    Vec::new(), None
                )
            },
            "/api/v1/organizations/{organization_id}/audit": {
                "parameters": [organization.clone()],
                "get": api_operation(
                    "listAudit", "audit", "Export a verified audit-chain page", "200",
                    vec![
                        query_parameter("after_sequence", "integer"),
                        query_parameter("limit", "integer")
                    ],
                    None
                )
            },
            "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/validate": {
                "parameters": [organization.clone(), project.clone()],
                "post": api_operation(
                    "validatePipeline", "pipelines", "Validate strict YAML and parameters", "200",
                    Vec::new(), Some("SubmissionRequest")
                )
            },
            "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/plan": {
                "parameters": [organization.clone(), project.clone()],
                "post": api_operation(
                    "planPipeline", "pipelines", "Compile a deterministic execution plan", "200",
                    Vec::new(), Some("SubmissionRequest")
                )
            },
            "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines": {
                "parameters": [organization.clone(), project.clone()],
                "get": api_operation(
                    "listPipelines", "pipelines", "List versioned pipelines", "200",
                    page, None
                )
            },
            "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}": {
                "parameters": [organization.clone(), project.clone(), pipeline.clone()],
                "get": api_operation(
                    "getPipeline", "pipelines", "Read one pipeline revision", "200",
                    Vec::new(), None
                ),
                "put": put_pipeline_operation()
            },
            "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}/state": {
                "parameters": [organization.clone(), project.clone(), pipeline.clone()],
                "get": api_operation(
                    "getPipelineState", "pipelines", "Read current pipeline operational state", "200",
                    Vec::new(), None
                ),
                "put": put_pipeline_state_operation()
            },
            "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}/triggers/{trigger_id}": {
                "parameters": [organization.clone(), project.clone(), pipeline.clone(), trigger.clone()],
                "get": api_operation(
                    "getPipelineTrigger", "triggers", "Read the current typed trigger generation", "200",
                    Vec::new(), None
                ),
                "put": put_pipeline_trigger_operation()
            },
            "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}/triggers/{trigger_id}/events": {
                "parameters": [organization.clone(), project.clone(), pipeline.clone(), trigger.clone()],
                "post": trigger_event_operation(
                    "submitTriggerEvent", "Authenticate, durably capture, and process a typed trigger event", "TriggerEventRequest"
                )
            },
            "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}/triggers/{trigger_id}/deliveries/{delivery_id}/redrive": {
                "parameters": [organization.clone(), project.clone(), pipeline.clone(), trigger, delivery],
                "post": trigger_event_operation(
                    "redriveTriggerDelivery", "Explicitly redrive one dead-lettered trigger delivery", "TriggerRedriveRequest"
                )
            },
            "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}/discovery/{parent_id}": {
                "parameters": [organization.clone(), project.clone(), pipeline.clone(), discovery_parent.clone()],
                "get": api_operation(
                    "getDiscoveryParent", "discovery", "Read the current immutable discovery-parent generation", "200",
                    Vec::new(), None
                ),
                "put": put_discovery_parent_operation()
            },
            "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}/discovery/{parent_id}/scans": {
                "parameters": [organization.clone(), project.clone(), pipeline.clone(), discovery_parent.clone()],
                "post": discovery_scan_operation()
            },
            "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}/discovery/{parent_id}/children": {
                "parameters": [organization.clone(), project.clone(), pipeline.clone(), discovery_parent],
                "get": discovery_children_operation()
            },
            "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}/builds": {
                "parameters": [organization.clone(), project.clone(), pipeline],
                "post": submit_build_operation()
            },
            "/api/v1/organizations/{organization_id}/projects/{project_id}/components": {
                "parameters": [organization.clone(), project.clone()],
                "get": api_operation(
                    "listComponents", "components", "List immutable components", "200",
                    component_page, None
                )
            },
            "/api/v1/organizations/{organization_id}/projects/{project_id}/components/{digest}": {
                "parameters": [organization.clone(), project.clone(), digest],
                "get": api_operation(
                    "getComponent", "components", "Read one immutable component", "200",
                    Vec::new(), None
                ),
                "put": put_component_operation()
            },
            "/api/v1/organizations/{organization_id}/projects/{project_id}/builds": {
                "parameters": [organization.clone(), project.clone()],
                "get": api_operation(
                    "listBuilds", "builds", "List builds with a stable cursor", "200",
                    build_page, None
                )
            },
            "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}": {
                "parameters": [organization.clone(), project.clone(), build.clone()],
                "get": api_operation(
                    "getBuild", "builds", "Read current build and attempt state", "200",
                    Vec::new(), None
                )
            },
            "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/graph": {
                "parameters": [organization.clone(), project.clone(), build.clone()],
                "get": api_operation(
                    "getBuildGraph", "builds", "Read nodes, dependencies, and attempt history", "200",
                    Vec::new(), None
                )
            },
            "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/logs": {
                "parameters": [organization.clone(), project.clone(), build.clone()],
                "get": api_operation(
                    "listBuildLogs", "evidence", "Read fenced log chunks", "200",
                    vec![
                        query_parameter("after_attempt_id", "uuid"),
                        query_parameter("after_fence", "integer"),
                        query_parameter("after_sequence", "integer"),
                        query_parameter("after_stream", "string"),
                        query_parameter("limit", "integer")
                    ],
                    None
                )
            },
            "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/approvals": {
                "parameters": [organization.clone(), project.clone(), build.clone()],
                "get": array_api_operation(
                    "listApprovals", "security", "List build approvals", "200",
                    Vec::new(), None
                ),
                "post": create_approval_operation()
            },
            "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/credential-grants": {
                "parameters": [organization.clone(), project.clone(), build.clone()],
                "get": array_api_operation(
                    "listCredentialGrants", "security", "List credential-grant metadata", "200",
                    Vec::new(), None
                )
            },
            "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/tests": {
                "parameters": [organization.clone(), project.clone(), build.clone()],
                "get": array_api_operation(
                    "listTestReports", "evidence", "List normalized test evidence", "200",
                    Vec::new(), None
                )
            },
            "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/cancel": {
                "parameters": [organization.clone(), project.clone(), build.clone()],
                "post": api_operation(
                    "cancelBuild", "builds", "Request durable cancellation", "200",
                    Vec::new(), None
                )
            },
            "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/attempts/{attempt_id}/retry": {
                "parameters": [
                    organization.clone(),
                    project.clone(),
                    build.clone(),
                    attempt
                ],
                "post": api_operation(
                    "retryAttempt", "builds", "Schedule a safe bounded attempt retry", "200",
                    Vec::new(), Some("RetryRequest")
                )
            },
            "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/artifact-uploads": {
                "parameters": [organization.clone(), project.clone(), build.clone()],
                "post": binary_request_api_operation(
                    "stageArtifact", "evidence", "Stage bounded artifact bytes", "201",
                    vec![header_parameter(ARTIFACT_NAME_HEADER, true)]
                )
            },
            "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/artifact-uploads/{upload_token}/commit": {
                "parameters": [organization.clone(), project.clone(), build.clone(), upload],
                "post": api_operation(
                    "commitArtifact", "evidence", "Commit an exact fenced artifact upload", "201",
                    vec![header_parameter(ARTIFACT_AGENT_AUTHORIZATION_HEADER, true)],
                    Some("ArtifactCommitRequest")
                )
            },
            "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/artifacts": {
                "parameters": [organization.clone(), project.clone(), build.clone()],
                "get": array_api_operation(
                    "listArtifacts", "evidence", "List immutable artifact metadata", "200",
                    Vec::new(), None
                )
            },
            "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/artifacts/metadata": {
                "parameters": [organization.clone(), project.clone(), build.clone()],
                "get": api_operation(
                    "getArtifactMetadata", "evidence", "Read exact artifact metadata", "200",
                    vec![
                        required_query_parameter("attempt_id", "uuid"),
                        required_query_parameter("name", "string")
                    ],
                    None
                )
            },
            "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/artifacts/content": {
                "parameters": [organization.clone(), project.clone(), build],
                "get": binary_api_operation(
                    "downloadArtifact", "evidence", "Download verified artifact bytes", "200",
                    vec![
                        required_query_parameter("attempt_id", "uuid"),
                        required_query_parameter("name", "string")
                    ],
                    None
                )
            },
            "/api/v1/organizations/{organization_id}/scheduler/explain": {
                "parameters": [organization],
                "get": api_operation(
                    "explainScheduling", "scheduler", "Explain scheduler eligibility", "200",
                    vec![
                        query_parameter("capability", "string"),
                        query_parameter("trust_pool", "string")
                    ],
                    None
                )
            }
        },
        "components": {
            "securitySchemes": {
                "bearer": {"type": "http", "scheme": "bearer", "bearerFormat": "opaque"}
            },
            "responses": {
                "Error": {
                    "description": "Stable error envelope",
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}
                }
            },
            "schemas": {
                "Error": {
                    "type": "object",
                    "required": ["code", "message"],
                    "properties": {
                        "code": {"type": "string"},
                        "message": {"type": "string"}
                    },
                    "additionalProperties": false
                },
                "SubmissionRequest": {
                    "type": "object",
                    "required": ["source"],
                    "properties": {
                        "source": {"type": "string"},
                        "parameters": parameter_values_schema()
                    },
                    "additionalProperties": false
                },
                "PipelineBuildRequest": {
                    "type": "object",
                    "properties": {
                        "parameters": parameter_values_schema()
                    },
                    "additionalProperties": false
                },
                "PipelineOperationalStateRequest": {
                    "type": "object",
                    "required": [
                        "state", "reason", "source_identity", "source_generation",
                        "source_effective_at_unix_ms", "source_provenance_sha256"
                    ],
                    "properties": {
                        "state": {"type": "string", "enum": ["enabled", "disabled"]},
                        "reason": {"type": "string", "minLength": 1, "maxLength": 2048},
                        "source_identity": {"type": "string", "minLength": 1, "maxLength": 512},
                        "source_generation": {"type": "string", "minLength": 1, "maxLength": 512},
                        "source_effective_at_unix_ms": {"type": "integer", "minimum": 0},
                        "source_provenance_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
                    },
                    "additionalProperties": false
                },
                "PipelineTriggerRequest": pipeline_trigger_request_schema(),
                "ScmPipelineTriggerRequest": pipeline_trigger_request_variant_schema(
                    "scm_webhook", "ScmTriggerConfiguration"
                ),
                "SchedulePipelineTriggerRequest": pipeline_trigger_request_variant_schema(
                    "schedule", "ScheduleTriggerConfiguration"
                ),
                "UpstreamPipelineTriggerRequest": pipeline_trigger_request_variant_schema(
                    "upstream", "UpstreamTriggerConfiguration"
                ),
                "RemoteApiPipelineTriggerRequest": pipeline_trigger_request_variant_schema(
                    "remote_api", "RemoteApiTriggerConfiguration"
                ),
                "TriggerEventRequest": {
                    "type": "object",
                    "required": ["trigger_generation", "delivery_id", "event_id", "event_kind", "event_time_unix_ms", "payload"],
                    "properties": {
                        "trigger_generation": {
                            "type": "integer", "format": "int64",
                            "minimum": 1, "maximum": i64::MAX
                        },
                        "delivery_id": {"type": "string", "minLength": 1, "maxLength": 512},
                        "event_id": {"type": "string", "minLength": 1, "maxLength": 512},
                        "event_kind": {"type": "string", "minLength": 1, "maxLength": 256},
                        "event_time_unix_ms": {
                            "type": "integer", "format": "int64",
                            "minimum": 0, "maximum": i64::MAX
                        },
                        "payload": {"$ref": "#/components/schemas/TriggerEventPayload"},
                        "parameters": parameter_values_schema(),
                        "platform": {"type": "string", "enum": ["linux", "windows"]},
                        "trust_pool": {"type": "string", "minLength": 1, "maxLength": 128}
                    },
                    "additionalProperties": false
                },
                "TriggerEventResponse": trigger_event_response_schema(),
                "TriggerDelivery": trigger_delivery_schema(),
                "AdmissionResponse": admission_response_schema(),
                "ScmTriggerConfiguration": scm_trigger_configuration_schema(),
                "ScheduleTriggerConfiguration": schedule_trigger_configuration_schema(),
                "UpstreamTriggerConfiguration": upstream_trigger_configuration_schema(),
                "RemoteApiTriggerConfiguration": remote_api_trigger_configuration_schema(),
                "TriggerEventPayload": trigger_event_payload,
                "ScmTriggerEventPayload": scm_trigger_event_payload_schema(),
                "ScheduleTriggerEventPayload": schedule_trigger_event_payload_schema(),
                "UpstreamTriggerEventPayload": upstream_trigger_event_payload_schema(),
                "RemoteApiTriggerEventPayload": remote_api_trigger_event_payload_schema(),
                "TriggerRedriveRequest": {
                    "type": "object",
                    "required": ["delivery_id", "event_id"],
                    "properties": {
                        "delivery_id": {"type": "string", "minLength": 1, "maxLength": 512},
                        "event_id": {"type": "string", "minLength": 1, "maxLength": 512}
                    },
                    "additionalProperties": false
                },
                "DiscoveryParentRequest": discovery_parent_request_schema(),
                "DiscoveryScanRequest": discovery_scan_request_schema(),
                "DiscoveryObservationRequest": discovery_observation_request_schema(),
                "DiscoveryChild": discovery_child_schema(),
                "DiscoveryChildPage": discovery_child_page_schema(),
                "RefreshRequest": {
                    "type": "object",
                    "required": ["refresh_token"],
                    "properties": {
                        "refresh_token": {"type": "string", "minLength": 32, "maxLength": 512}
                    },
                    "additionalProperties": false
                },
                "PipelineUpsertRequest": {
                    "type": "object",
                    "required": ["slug", "source"],
                    "properties": {
                        "slug": {"type": "string"},
                        "source": {"type": "string"},
                        "parameters": parameter_values_schema()
                    },
                    "additionalProperties": false
                },
                "ComponentUpsertRequest": {
                    "type": "object",
                    "required": ["name", "version_major", "version_minor", "canonical_hex", "source_sha256"],
                    "properties": {
                        "name": {"type": "string"},
                        "version_major": {"type": "integer"},
                        "version_minor": {"type": "integer"},
                        "canonical_hex": {"type": "string"},
                        "source_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
                    },
                    "additionalProperties": false
                },
                "ApprovalRequest": {
                    "type": "object",
                    "required": ["approval_id", "environment", "action", "ttl_seconds"],
                    "properties": {
                        "approval_id": {"type": "string", "format": "uuid"},
                        "environment": {"type": "string"},
                        "action": {"type": "string"},
                        "ttl_seconds": {"type": "integer", "minimum": 1}
                    },
                    "additionalProperties": false
                },
                "RetryRequest": {
                    "type": "object",
                    "required": ["max_attempts", "reason"],
                    "properties": {
                        "max_attempts": {"type": "integer", "minimum": 1, "maximum": 16},
                        "reason": {"type": "string", "minLength": 1, "maxLength": 1024}
                    },
                    "additionalProperties": false
                },
                "ArtifactCommitRequest": {
                    "type": "object",
                    "required": ["attempt_id", "fence", "restore_epoch", "node_id", "agent_id", "name", "sha256", "bytes", "media_type", "retention_seconds"],
                    "properties": {
                        "attempt_id": {"type": "string", "format": "uuid"},
                        "fence": {"type": "integer", "format": "int64", "minimum": 1},
                        "restore_epoch": {"type": "integer", "format": "int64", "minimum": 0},
                        "node_id": {"type": "string", "format": "uuid"},
                        "agent_id": {"type": "string", "minLength": 1, "maxLength": 512},
                        "name": {"type": "string", "minLength": 1, "maxLength": 512},
                        "sha256": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"},
                        "bytes": {"type": "integer", "format": "int64", "minimum": 0, "maximum": 9223372036854775807_i64},
                        "media_type": {"type": "string", "minLength": 1, "maxLength": 255},
                        "retention_seconds": {"type": "integer", "format": "int64", "minimum": 0, "maximum": MAX_OBJECT_RETENTION_SECONDS}
                    },
                    "additionalProperties": false
                },
                "BinaryArtifact": {"type": "string", "format": "binary"}
            }
        }
    })
}

fn pipeline_trigger_request_schema() -> Value {
    json!({
        "oneOf": [
            {"$ref": "#/components/schemas/ScmPipelineTriggerRequest"},
            {"$ref": "#/components/schemas/SchedulePipelineTriggerRequest"},
            {"$ref": "#/components/schemas/UpstreamPipelineTriggerRequest"},
            {"$ref": "#/components/schemas/RemoteApiPipelineTriggerRequest"}
        ],
        "discriminator": {
            "propertyName": "kind",
            "mapping": {
                "scm_webhook": "#/components/schemas/ScmPipelineTriggerRequest",
                "schedule": "#/components/schemas/SchedulePipelineTriggerRequest",
                "upstream": "#/components/schemas/UpstreamPipelineTriggerRequest",
                "remote_api": "#/components/schemas/RemoteApiPipelineTriggerRequest"
            }
        }
    })
}

fn discovery_parent_request_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    let strings = json!({
        "type": "array", "maxItems": 4096, "uniqueItems": true,
        "items": {"type": "string", "minLength": 1, "maxLength": 512}
    });
    json!({
        "type": "object",
        "required": [
            "kind", "state", "implementation_sha256", "protocol_version",
            "configuration_sha256", "provider", "provider_identity", "repositories",
            "pull_request_strategy", "fork_trust_strategy", "jenkinsfile_path",
            "child_configuration_policy_sha256", "orphan_policy",
            "authorization_generation", "authorization_policy_sha256", "trigger_id",
            "trigger_generation", "trigger_configuration_sha256",
            "source_implementation_sha256", "source_protocol_version",
            "source_configuration_sha256", "reason"
        ],
        "properties": {
            "kind": {"type": "string", "enum": ["multibranch_pipeline", "organization_folder"]},
            "state": {"type": "string", "enum": ["enabled", "quiesced"]},
            "implementation_sha256": digest.clone(),
            "protocol_version": {"type": "string", "minLength": 1, "maxLength": 128},
            "configuration_sha256": digest.clone(),
            "provider": {"type": "string", "enum": ["github", "gitlab", "bitbucket", "gitea"]},
            "provider_identity": {"type": "string", "minLength": 1, "maxLength": 512},
            "organization_identity": {"type": ["string", "null"], "minLength": 1, "maxLength": 512},
            "repositories": strings.clone(),
            "branch_includes": strings.clone(),
            "branch_excludes": strings.clone(),
            "pull_request_strategy": {"type": "string", "enum": ["none", "origin_only", "origin_and_forks"]},
            "fork_trust_strategy": {"type": "string", "enum": ["none", "named_repositories", "all"]},
            "trusted_fork_repositories": strings,
            "jenkinsfile_path": {"type": "string", "minLength": 1, "maxLength": 1024},
            "child_configuration_policy_sha256": digest.clone(),
            "orphan_policy": {"type": "string", "enum": ["retain", "retire"]},
            "authorization_generation": {"type": "integer", "format": "int64", "minimum": 1, "maximum": i64::MAX},
            "authorization_policy_sha256": digest.clone(),
            "trigger_id": {"type": "string", "format": "uuid"},
            "trigger_generation": {"type": "integer", "format": "int64", "minimum": 1, "maximum": i64::MAX},
            "trigger_configuration_sha256": digest.clone(),
            "source_implementation_sha256": digest.clone(),
            "source_protocol_version": {"type": "string", "minLength": 1, "maxLength": 128},
            "source_configuration_sha256": digest,
            "restored_from_generation": {"type": ["integer", "null"], "format": "int64", "minimum": 1, "maximum": i64::MAX},
            "reason": {"type": "string", "minLength": 1, "maxLength": 2048}
        },
        "additionalProperties": false
    })
}

fn discovery_observation_request_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    json!({
        "type": "object",
        "required": [
            "child_key", "child_pipeline_id", "repository_identity", "ref_kind",
            "ref_name", "head_repository_identity", "present", "revision",
            "provenance_sha256", "jenkinsfile_path", "jenkinsfile_sha256",
            "child_configuration_sha256"
        ],
        "properties": {
            "child_key": {"type": "string", "minLength": 1, "maxLength": 1024},
            "child_pipeline_id": {"type": "string", "format": "uuid"},
            "repository_identity": {"type": "string", "minLength": 1, "maxLength": 512},
            "ref_kind": {"type": "string", "enum": ["branch", "pull_request"]},
            "ref_name": {"type": "string", "minLength": 1, "maxLength": 512},
            "pull_request_number": {"type": ["integer", "null"], "format": "int64", "minimum": 1, "maximum": i64::MAX},
            "head_repository_identity": {"type": "string", "minLength": 1, "maxLength": 512},
            "present": {"type": "boolean"},
            "revision": {"type": "string", "pattern": "^[0-9A-Fa-f]{7,128}$"},
            "provenance_sha256": digest.clone(),
            "jenkinsfile_path": {"type": "string", "minLength": 1, "maxLength": 1024},
            "jenkinsfile_sha256": digest.clone(),
            "child_configuration_sha256": digest
        },
        "additionalProperties": false
    })
}

fn discovery_scan_request_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "parent_generation", "scan_id", "source", "source_cursor",
            "complete_snapshot", "provider_snapshot_sha256", "request_sha256",
            "observations"
        ],
        "properties": {
            "parent_generation": {"type": "integer", "format": "int64", "minimum": 1, "maximum": i64::MAX},
            "scan_id": {"type": "string", "minLength": 1, "maxLength": 512},
            "source": {"type": "string", "enum": ["webhook", "periodic", "recovery"]},
            "source_event_id": {"type": ["string", "null"], "minLength": 1, "maxLength": 512},
            "source_cursor": {"type": "integer", "format": "int64", "minimum": 1, "maximum": i64::MAX},
            "complete_snapshot": {"type": "boolean"},
            "provider_snapshot_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "request_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "observations": {
                "type": "array", "maxItems": MAX_DISCOVERY_SCAN_OBSERVATIONS,
                "items": {"$ref": "#/components/schemas/DiscoveryObservationRequest"}
            }
        },
        "additionalProperties": false
    })
}

fn discovery_child_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    json!({
        "type": "object",
        "required": [
            "organization_id", "project_id", "pipeline_id", "parent_id", "child_key",
            "child_pipeline_id", "repository_identity", "ref_kind", "ref_name",
            "pull_request_number", "head_repository_identity", "is_fork", "state",
            "state_generation", "revision", "provenance_sha256", "jenkinsfile_path",
            "jenkinsfile_sha256", "child_configuration_sha256", "parent_generation",
            "source_cursor", "last_scan_id"
        ],
        "properties": {
            "organization_id": {"type": "string", "format": "uuid"},
            "project_id": {"type": "string", "format": "uuid"},
            "pipeline_id": {"type": "string", "format": "uuid"},
            "parent_id": {"type": "string", "format": "uuid"},
            "child_key": {"type": "string", "minLength": 1, "maxLength": 1024},
            "child_pipeline_id": {"type": "string", "format": "uuid"},
            "repository_identity": {"type": "string", "minLength": 1, "maxLength": 512},
            "ref_kind": {"type": "string", "enum": ["branch", "pull_request"]},
            "ref_name": {"type": "string", "minLength": 1, "maxLength": 512},
            "pull_request_number": {"type": ["integer", "null"], "format": "int64", "minimum": 1, "maximum": i64::MAX},
            "head_repository_identity": {"type": "string", "minLength": 1, "maxLength": 512},
            "is_fork": {"type": "boolean"},
            "state": {"type": "string", "enum": ["active", "quarantined", "retired"]},
            "state_generation": {"type": "integer", "format": "int64", "minimum": 1, "maximum": i64::MAX},
            "revision": {"type": "string", "pattern": "^[0-9A-Fa-f]{7,128}$"},
            "provenance_sha256": digest.clone(),
            "jenkinsfile_path": {"type": "string", "minLength": 1, "maxLength": 1024},
            "jenkinsfile_sha256": digest.clone(),
            "child_configuration_sha256": digest,
            "parent_generation": {"type": "integer", "format": "int64", "minimum": 1, "maximum": i64::MAX},
            "source_cursor": {"type": "integer", "format": "int64", "minimum": 1, "maximum": i64::MAX},
            "last_scan_id": {"type": "string", "minLength": 1, "maxLength": 512}
        },
        "additionalProperties": false
    })
}

fn discovery_child_page_schema() -> Value {
    json!({
        "type": "object",
        "required": ["items", "next_after"],
        "properties": {
            "items": {
                "type": "array",
                "maxItems": mcloving_controller_store::MAX_DISCOVERY_CHILD_PAGE,
                "items": {"$ref": "#/components/schemas/DiscoveryChild"}
            },
            "next_after": {"type": ["string", "null"], "maxLength": 1024}
        },
        "additionalProperties": false
    })
}

fn parameter_values_schema() -> Value {
    json!({
        "type": "object",
        "maxProperties": 128,
        "propertyNames": {
            "pattern": "^[A-Za-z0-9_-]{1,256}$"
        },
        "additionalProperties": {
            "oneOf": [
                {"type": "boolean"},
                {
                    "type": "integer",
                    "format": "int64",
                    "minimum": i64::MIN,
                    "maximum": i64::MAX
                },
                {"type": "string", "maxLength": 4096}
            ]
        }
    })
}

fn trigger_event_response_schema() -> Value {
    json!({
        "type": "object",
        "required": ["delivery"],
        "properties": {
            "delivery": {"$ref": "#/components/schemas/TriggerDelivery"},
            "admission": {"$ref": "#/components/schemas/AdmissionResponse"}
        },
        "additionalProperties": false
    })
}

fn trigger_delivery_schema() -> Value {
    let digest = json!({
        "type": "array",
        "minItems": 32,
        "maxItems": 32,
        "items": {"type": "integer", "minimum": 0, "maximum": 255}
    });
    json!({
        "type": "object",
        "required": [
            "organization_id", "project_id", "pipeline_id", "trigger_id",
            "trigger_generation", "delivery_id", "event_id", "event_kind",
            "caller_identity", "payload_sha256", "canonical_payload", "parameters",
            "requested_platform", "requested_trust_pool", "event_time_unix_ms",
            "accepted_at_unix_ms", "expires_at_unix_ms", "status", "attempt_count",
            "next_attempt_at_unix_ms", "claim_owner", "claim_fence",
            "claim_expires_at_unix_ms", "redrive_of_delivery_id", "redrive_ordinal",
            "build_id", "terminal_reason", "audit_sequence", "audit_event_hash"
        ],
        "properties": {
            "organization_id": {"type": "string", "format": "uuid"},
            "project_id": {"type": "string", "format": "uuid"},
            "pipeline_id": {"type": "string", "format": "uuid"},
            "trigger_id": {"type": "string", "format": "uuid"},
            "trigger_generation": {"type": "integer", "format": "int64", "minimum": 1, "maximum": i64::MAX},
            "delivery_id": {"type": "string", "minLength": 1, "maxLength": 512},
            "event_id": {"type": "string", "minLength": 1, "maxLength": 512},
            "event_kind": {"type": "string", "minLength": 1, "maxLength": 256},
            "caller_identity": {"type": "string", "minLength": 1, "maxLength": 512},
            "payload_sha256": digest.clone(),
            "canonical_payload": {"type": "object"},
            "parameters": {"type": "object"},
            "requested_platform": {"type": "string", "enum": ["linux", "windows"]},
            "requested_trust_pool": {"type": "string", "minLength": 1, "maxLength": 128},
            "event_time_unix_ms": {"type": "integer", "format": "int64", "minimum": 0, "maximum": i64::MAX},
            "accepted_at_unix_ms": {"type": "integer", "format": "int64", "minimum": 0, "maximum": i64::MAX},
            "expires_at_unix_ms": {"type": "integer", "format": "int64", "minimum": 0, "maximum": i64::MAX},
            "status": {"type": "string", "enum": ["pending", "retry_wait", "admitted", "dead_lettered"]},
            "attempt_count": {"type": "integer", "format": "int32", "minimum": 0, "maximum": i32::MAX},
            "next_attempt_at_unix_ms": {"type": "integer", "format": "int64", "minimum": 0, "maximum": i64::MAX},
            "claim_owner": {"type": ["string", "null"]},
            "claim_fence": {"type": "integer", "format": "int64", "minimum": 0, "maximum": i64::MAX},
            "claim_expires_at_unix_ms": {"type": ["integer", "null"], "format": "int64", "minimum": 0, "maximum": i64::MAX},
            "redrive_of_delivery_id": {"type": ["string", "null"]},
            "redrive_ordinal": {"type": ["integer", "null"], "format": "int32", "minimum": 1, "maximum": i32::MAX},
            "build_id": {"type": ["string", "null"], "format": "uuid"},
            "terminal_reason": {"type": ["string", "null"], "maxLength": 2048},
            "audit_sequence": {"type": "integer", "format": "int64", "minimum": 1, "maximum": i64::MAX},
            "audit_event_hash": digest
        },
        "additionalProperties": false
    })
}

fn admission_response_schema() -> Value {
    json!({
        "type": "object",
        "required": ["build_id", "node_id", "attempt_id", "created", "pipeline_digest"],
        "properties": {
            "build_id": {"type": "string", "format": "uuid"},
            "node_id": {"type": "string", "format": "uuid"},
            "attempt_id": {"type": "string", "format": "uuid"},
            "created": {"type": "boolean"},
            "pipeline_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
        },
        "additionalProperties": false
    })
}

fn pipeline_trigger_request_variant_schema(kind: &str, configuration_schema: &str) -> Value {
    json!({
        "type": "object",
        "required": [
            "kind", "state", "implementation_sha256", "configuration_sha256",
            "filter_sha256", "event_source_identity", "source_generation",
            "configuration", "deduplication_window_seconds",
            "max_delivery_attempts", "delivery_ttl_seconds", "reason"
        ],
        "properties": {
            "kind": {"type": "string", "const": kind},
            "state": {"type": "string", "enum": ["enabled", "paused"]},
            "implementation_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "configuration_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "filter_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "event_source_identity": {"type": "string", "minLength": 1, "maxLength": 512},
            "source_generation": {"type": "string", "minLength": 1, "maxLength": 512},
            "configuration": {"$ref": format!("#/components/schemas/{configuration_schema}")},
            "deduplication_window_seconds": {"type": "integer", "format": "int64", "minimum": 1, "maximum": 2592000},
            "max_delivery_attempts": {"type": "integer", "format": "int32", "minimum": 1, "maximum": 100},
            "delivery_ttl_seconds": {"type": "integer", "format": "int64", "minimum": 1, "maximum": 2592000},
            "reason": {"type": "string", "minLength": 1, "maxLength": 2048}
        },
        "additionalProperties": false
    })
}

fn scm_trigger_configuration_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "provider": {"type": "string", "minLength": 1, "maxLength": 512},
            "repository_identity": {"type": "string", "minLength": 1, "maxLength": 512},
            "filter": trigger_filter_schema(&["event_kinds", "branches", "path_prefixes"])
        },
        "required": ["provider", "repository_identity", "filter"],
        "additionalProperties": false
    })
}

fn schedule_trigger_configuration_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "timezone": {"type": "string", "minLength": 1, "maxLength": 128},
            "calendar": {"type": "string", "minLength": 1, "maxLength": 128},
            "expression": {"type": "string", "minLength": 1, "maxLength": 512},
            "schedule_identity_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "resolver_implementation_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "resolved_slots_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "resolved_slots_unix_ms": {
                "type": "array", "minItems": 1, "maxItems": 4096, "uniqueItems": true,
                "description": "Resolved Unix-millisecond slots in strictly increasing order; the digest binds this exact ordered array.",
                "x-mcloving-ordering": "strictly_increasing",
                "items": {
                    "type": "integer", "format": "int64",
                    "minimum": 0, "maximum": i64::MAX
                }
            },
            "jenkins_hash_algorithm_version": {"type": "string", "minLength": 1, "maxLength": 512},
            "jenkins_full_item_name": {"type": "string", "minLength": 1, "maxLength": 512},
            "jenkins_hash_inputs_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "filter": trigger_filter_schema(&["event_kinds"])
        },
        "required": [
            "timezone", "calendar", "expression", "schedule_identity_sha256",
            "resolver_implementation_sha256", "resolved_slots_sha256",
            "resolved_slots_unix_ms", "filter"
        ],
        "dependentRequired": {
            "jenkins_hash_algorithm_version": ["jenkins_full_item_name", "jenkins_hash_inputs_sha256"],
            "jenkins_full_item_name": ["jenkins_hash_algorithm_version", "jenkins_hash_inputs_sha256"],
            "jenkins_hash_inputs_sha256": ["jenkins_hash_algorithm_version", "jenkins_full_item_name"]
        },
        "additionalProperties": false
    })
}

fn upstream_trigger_configuration_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "upstream_pipeline_id": {"type": "string", "format": "uuid"},
            "filter": trigger_filter_schema(&["event_kinds", "statuses"])
        },
        "required": ["upstream_pipeline_id", "filter"],
        "additionalProperties": false
    })
}

fn remote_api_trigger_configuration_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "audience": {"type": "string", "minLength": 1, "maxLength": 512},
            "filter": trigger_filter_schema(&["event_kinds", "request_methods"])
        },
        "required": ["audience", "filter"],
        "additionalProperties": false
    })
}

fn trigger_filter_schema(fields: &[&str]) -> Value {
    let mut properties = serde_json::Map::new();
    for field in fields {
        properties.insert(
            (*field).to_owned(),
            json!({
                "type": "array",
                "maxItems": 128,
                "uniqueItems": true,
                "items": {"type": "string", "minLength": 1, "maxLength": 512}
            }),
        );
    }
    json!({
        "type": "object",
        "properties": properties,
        "additionalProperties": false
    })
}

fn trigger_event_payload_schema() -> Value {
    json!({
        "oneOf": [
            {"$ref": "#/components/schemas/ScmTriggerEventPayload"},
            {"$ref": "#/components/schemas/ScheduleTriggerEventPayload"},
            {"$ref": "#/components/schemas/UpstreamTriggerEventPayload"},
            {"$ref": "#/components/schemas/RemoteApiTriggerEventPayload"}
        ]
    })
}

fn scm_trigger_event_payload_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "repository_identity": {"type": "string", "minLength": 1, "maxLength": 512},
            "revision": {"type": "string", "minLength": 1, "maxLength": 512},
            "branch": {"type": "string", "minLength": 1, "maxLength": 512},
            "paths": {
                "type": "array",
                "maxItems": 128,
                "items": {"type": "string", "minLength": 1, "maxLength": 512}
            }
        },
        "required": ["repository_identity", "revision", "branch"],
        "additionalProperties": false
    })
}

fn schedule_trigger_event_payload_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "timezone": {"type": "string", "minLength": 1, "maxLength": 128},
            "calendar": {"type": "string", "minLength": 1, "maxLength": 128},
            "expression": {"type": "string", "minLength": 1, "maxLength": 512},
            "schedule_identity_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "expected_last_resolved_slot_unix_ms": {
                "type": "integer", "format": "int64",
                "minimum": 0, "maximum": i64::MAX
            },
            "resolved_slot_unix_ms": {
                "type": "integer", "format": "int64",
                "minimum": 0, "maximum": i64::MAX
            }
        },
        "required": [
            "timezone", "calendar", "expression", "schedule_identity_sha256",
            "resolved_slot_unix_ms"
        ],
        "additionalProperties": false
    })
}

fn upstream_trigger_event_payload_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "upstream_pipeline_id": {"type": "string", "format": "uuid"},
            "upstream_build_id": {"type": "string", "format": "uuid"},
            "status": {"type": "string", "minLength": 1, "maxLength": 512}
        },
        "required": ["upstream_pipeline_id", "upstream_build_id", "status"],
        "additionalProperties": false
    })
}

fn remote_api_trigger_event_payload_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "audience": {"type": "string", "minLength": 1, "maxLength": 512},
            "request_id": {"type": "string", "minLength": 1, "maxLength": 512},
            "request_method": {"type": "string", "minLength": 1, "maxLength": 512}
        },
        "required": ["audience", "request_id", "request_method"],
        "additionalProperties": false
    })
}

fn api_operation(
    operation_id: &str,
    tag: &str,
    summary: &str,
    success_status: &str,
    parameters: Vec<Value>,
    request_schema: Option<&str>,
) -> Value {
    let mut operation = json!({
        "operationId": operation_id,
        "tags": [tag],
        "summary": summary,
        "parameters": parameters,
        "responses": {
            "default": {"$ref": "#/components/responses/Error"}
        }
    });
    operation["responses"][success_status] = json!({
        "description": "Successful response",
        "content": {"application/json": {"schema": {"type": "object"}}}
    });
    if let Some(schema) = request_schema {
        operation["requestBody"] = json!({
            "required": true,
            "content": {
                "application/json": {
                    "schema": {"$ref": format!("#/components/schemas/{schema}")}
                }
            }
        });
    }
    operation
}

fn unauthenticated_api_operation(
    operation_id: &str,
    tag: &str,
    summary: &str,
    success_status: &str,
    parameters: Vec<Value>,
    request_schema: Option<&str>,
) -> Value {
    let mut operation = api_operation(
        operation_id,
        tag,
        summary,
        success_status,
        parameters,
        request_schema,
    );
    operation["security"] = json!([]);
    operation
}

fn array_api_operation(
    operation_id: &str,
    tag: &str,
    summary: &str,
    success_status: &str,
    parameters: Vec<Value>,
    request_schema: Option<&str>,
) -> Value {
    let mut operation = api_operation(
        operation_id,
        tag,
        summary,
        success_status,
        parameters,
        request_schema,
    );
    operation["responses"][success_status]["content"]["application/json"]["schema"] =
        json!({"type": "array", "items": {"type": "object"}});
    operation
}

fn put_pipeline_operation() -> Value {
    let mut operation = api_operation(
        "putPipeline",
        "pipelines",
        "Create or revise a pipeline",
        "201",
        vec![header_parameter("if-match", true)],
        Some("PipelineUpsertRequest"),
    );
    operation["responses"]["200"] = json!({
        "description": "Updated pipeline revision or idempotent replay",
        "content": {"application/json": {"schema": {"type": "object"}}}
    });
    operation
}

fn create_approval_operation() -> Value {
    let mut operation = api_operation(
        "createApproval",
        "security",
        "Create an expiring approval",
        "201",
        Vec::new(),
        Some("ApprovalRequest"),
    );
    operation["responses"]["200"] = json!({
        "description": "Idempotent replay of an active approval",
        "content": {"application/json": {"schema": {"type": "object"}}}
    });
    operation
}

fn put_component_operation() -> Value {
    let mut operation = api_operation(
        "putComponent",
        "components",
        "Publish an immutable component",
        "201",
        Vec::new(),
        Some("ComponentUpsertRequest"),
    );
    operation["responses"]["200"] = json!({
        "description": "Idempotent replay of an existing component",
        "content": {"application/json": {"schema": {"type": "object"}}}
    });
    operation
}

fn submit_build_operation() -> Value {
    let mut operation = api_operation(
        "submitBuild",
        "builds",
        "Submit parameters to an enabled saved pipeline",
        "201",
        vec![
            header_parameter(IDEMPOTENCY_HEADER, true),
            header_parameter(PLATFORM_HEADER, false),
            header_parameter(TRUST_POOL_HEADER, false),
        ],
        Some("PipelineBuildRequest"),
    );
    operation["responses"]["200"] = json!({
        "description": "Idempotent replay of an existing build",
        "content": {"application/json": {"schema": {"type": "object"}}}
    });
    operation
}

fn put_pipeline_state_operation() -> Value {
    let mut operation = api_operation(
        "putPipelineState",
        "pipelines",
        "Advance enabled or disabled operational state",
        "200",
        vec![
            header_parameter("If-Match", true),
            header_parameter(IDEMPOTENCY_HEADER, true),
        ],
        Some("PipelineOperationalStateRequest"),
    );
    operation["responses"]["412"] = json!({
        "description": "Operational-state generation precondition failed",
        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}
    });
    operation
}

fn put_pipeline_trigger_operation() -> Value {
    let mut operation = api_operation(
        "putPipelineTrigger",
        "triggers",
        "Create, pause, resume, rotate, or revise a typed trigger",
        "201",
        vec![
            header_parameter("If-Match", true),
            header_parameter(IDEMPOTENCY_HEADER, true),
        ],
        Some("PipelineTriggerRequest"),
    );
    operation["responses"]["200"] = json!({
        "description": "Updated trigger generation or idempotent replay",
        "content": {"application/json": {"schema": {"type": "object"}}}
    });
    operation["responses"]["412"] = json!({
        "description": "Trigger generation precondition failed",
        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}
    });
    operation
}

fn put_discovery_parent_operation() -> Value {
    let mut operation = api_operation(
        "putDiscoveryParent",
        "discovery",
        "Create, quiesce, restore, or revise an immutable discovery-parent generation",
        "201",
        vec![
            header_parameter("If-Match", true),
            header_parameter(IDEMPOTENCY_HEADER, true),
        ],
        Some("DiscoveryParentRequest"),
    );
    operation["responses"]["200"] = json!({
        "description": "Updated discovery generation or exact idempotent replay",
        "content": {"application/json": {"schema": {"type": "object"}}}
    });
    operation["responses"]["412"] = json!({
        "description": "Discovery generation precondition failed",
        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}
    });
    operation
}

fn discovery_scan_operation() -> Value {
    let mut operation = api_operation(
        "reconcileDiscoveryScan",
        "discovery",
        "Atomically reconcile one digest-bound webhook, periodic, or recovery scan",
        "201",
        Vec::new(),
        Some("DiscoveryScanRequest"),
    );
    operation["requestBody"]["x-mcloving-max-body-bytes"] = json!(MAX_DISCOVERY_SCAN_BODY_BYTES);
    operation["responses"]["200"] = json!({
        "description": "Exact scan replay",
        "content": {"application/json": {"schema": {"type": "object"}}}
    });
    operation
}

fn discovery_children_operation() -> Value {
    let mut after = query_parameter("after", "string");
    after["schema"]["maxLength"] = json!(1024);
    let mut limit = query_parameter("limit", "integer");
    limit["schema"]["minimum"] = json!(1);
    limit["schema"]["maximum"] = json!(mcloving_controller_store::MAX_DISCOVERY_CHILD_PAGE);
    let mut operation = api_operation(
        "listDiscoveryChildren",
        "discovery",
        "List one bounded child-key page of retained discovery truth",
        "200",
        vec![after, limit],
        None,
    );
    operation["responses"]["200"]["content"]["application/json"]["schema"] =
        json!({"$ref": "#/components/schemas/DiscoveryChildPage"});
    operation
}

fn trigger_event_operation(operation_id: &str, summary: &str, body_schema: &str) -> Value {
    let mut operation = api_operation(
        operation_id,
        "triggers",
        summary,
        "201",
        Vec::new(),
        Some(body_schema),
    );
    let response = |description: &str| {
        json!({
            "description": description,
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/TriggerEventResponse"}}}
        })
    };
    operation["responses"]["200"] = response("Exact replay of an admitted trigger delivery");
    operation["responses"]["201"] = response("New trigger delivery admitted or durably captured");
    operation["responses"]["202"] =
        response("Delivery is durably leased or waiting for its bounded retry");
    operation["responses"]["422"] =
        response("Delivery is durably dead-lettered and carries its terminal state");
    operation
}

fn binary_api_operation(
    operation_id: &str,
    tag: &str,
    summary: &str,
    success_status: &str,
    parameters: Vec<Value>,
    request_schema: Option<&str>,
) -> Value {
    let mut operation = api_operation(
        operation_id,
        tag,
        summary,
        success_status,
        parameters,
        request_schema,
    );
    operation["responses"][success_status] = json!({
        "description": "Verified artifact bytes under the stored media type",
        "content": {
            "application/octet-stream": {
                "schema": {"type": "string", "format": "binary"}
            }
        }
    });
    operation
}

fn binary_request_api_operation(
    operation_id: &str,
    tag: &str,
    summary: &str,
    success_status: &str,
    parameters: Vec<Value>,
) -> Value {
    let mut operation = api_operation(operation_id, tag, summary, success_status, parameters, None);
    operation["requestBody"] = json!({
        "required": true,
        "content": {
            "application/octet-stream": {
                "schema": {"type": "string", "format": "binary"}
            }
        }
    });
    operation
}

fn path_parameter(name: &str, format: &str) -> Value {
    parameter(name, "path", true, format)
}

fn query_parameter(name: &str, format: &str) -> Value {
    parameter(name, "query", false, format)
}

fn required_query_parameter(name: &str, format: &str) -> Value {
    parameter(name, "query", true, format)
}

fn header_parameter(name: &str, required: bool) -> Value {
    parameter(name, "header", required, "string")
}

fn parameter(name: &str, location: &str, required: bool, format: &str) -> Value {
    let schema = match format {
        "integer" => json!({"type": "integer", "format": "int64"}),
        "uuid" => json!({"type": "string", "format": "uuid"}),
        "sha256" => json!({"type": "string", "pattern": "^[0-9a-f]{64}$"}),
        _ => json!({"type": "string"}),
    };
    json!({
        "name": name,
        "in": location,
        "required": required,
        "schema": schema
    })
}

async fn list_audit(
    State(state): State<Arc<ApiState>>,
    Path(organization_id): Path<Uuid>,
    Query(query): Query<AuditQuery>,
    headers: HeaderMap,
) -> Result<Json<AuditPage>, ApiError> {
    authorize(&state, &headers, organization_id, None, Action::AuditRead).await?;
    let after_sequence = query.after_sequence.unwrap_or(0);
    let limit = query.limit.unwrap_or(100);
    if after_sequence < 0 || limit == 0 || limit > mcloving_controller_store::MAX_AUDIT_PAGE {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_audit_page",
            format!(
                "audit cursor must be non-negative and limit between 1 and {}",
                mcloving_controller_store::MAX_AUDIT_PAGE
            ),
        ));
    }
    state
        .store
        .export_audit_page(organization_id, after_sequence, limit)
        .await
        .map(Json)
        .map_err(product_error)
}

async fn validate_pipeline(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id)): Path<ProjectPath>,
    headers: HeaderMap,
    Json(request): Json<SubmissionRequest>,
) -> Result<Json<ValidationResponse>, ApiError> {
    authorize(
        &state,
        &headers,
        organization_id,
        Some(project_id),
        Action::ProjectConfigure,
    )
    .await?;
    let pipeline =
        compile_source_with_parameters(&request.source, parameter_values(request.parameters)?)?;
    validate_connector_mappings(&pipeline, &state.connector_mapping_catalog)?;
    let digest = pipeline.semantic_digest().map_err(pipeline_rejected)?;
    Ok(Json(ValidationResponse {
        valid: true,
        semantic_digest: hex(&digest),
    }))
}

async fn plan_pipeline(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id)): Path<ProjectPath>,
    headers: HeaderMap,
    Json(request): Json<SubmissionRequest>,
) -> Result<Json<PipelinePlanResponse>, ApiError> {
    authorize(
        &state,
        &headers,
        organization_id,
        Some(project_id),
        Action::ProjectConfigure,
    )
    .await?;
    let pipeline =
        compile_source_with_parameters(&request.source, parameter_values(request.parameters)?)?;
    validate_connector_mappings(&pipeline, &state.connector_mapping_catalog)?;
    Ok(Json(pipeline_plan(&pipeline)?))
}

async fn put_pipeline(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id, pipeline_id)): Path<(Uuid, Uuid, Uuid)>,
    headers: HeaderMap,
    Json(request): Json<PipelineUpsertRequest>,
) -> Result<Response, ApiError> {
    let principal = authorize(
        &state,
        &headers,
        organization_id,
        Some(project_id),
        Action::ProjectConfigure,
    )
    .await?;
    let expected_revision = expected_revision(&headers)?;
    let pipeline =
        compile_source_with_parameters(&request.source, parameter_values(request.parameters)?)?;
    validate_connector_mappings(&pipeline, &state.connector_mapping_catalog)?;
    let semantic_digest = pipeline.semantic_digest().map_err(pipeline_rejected)?;
    let source_sha256 = Sha256::digest(request.source.as_bytes()).into();
    let parameter_schema = parameter_schema(&pipeline);
    let outcome = state
        .store
        .put_pipeline_as(
            &PipelineWrite {
                organization_id,
                project_id,
                pipeline_id,
                slug: request.slug,
                source: request.source,
                source_sha256,
                semantic_digest,
                schema_major: i32::from(pipeline.schema.major),
                schema_minor: i32::from(pipeline.schema.minor),
                parameter_schema,
            },
            Some(expected_revision),
            &principal.subject,
        )
        .await
        .map_err(product_error)?;
    let (status, record) = match outcome {
        PipelinePutOutcome::Created(record) => (StatusCode::CREATED, record),
        PipelinePutOutcome::Updated(record) | PipelinePutOutcome::Unchanged(record) => {
            (StatusCode::OK, record)
        }
        PipelinePutOutcome::PreconditionFailed { current_revision } => {
            return Err(ApiError::new(
                StatusCode::PRECONDITION_FAILED,
                "revision_precondition_failed",
                format!("current pipeline revision is {current_revision}"),
            ));
        }
    };
    let revision = record.revision;
    let mut response = (status, Json(record)).into_response();
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(&format!("\"{revision}\"")).map_err(internal)?,
    );
    Ok(response)
}

async fn get_pipeline(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id, pipeline_id)): Path<(Uuid, Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    authorize(
        &state,
        &headers,
        organization_id,
        Some(project_id),
        Action::ProjectView,
    )
    .await?;
    let record = state
        .store
        .pipeline(organization_id, project_id, pipeline_id)
        .await
        .map_err(product_error)?
        .ok_or_else(resource_not_found)?;
    let mut response = Json(record.clone()).into_response();
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(&format!("\"{}\"", record.revision)).map_err(internal)?,
    );
    Ok(response)
}

async fn get_pipeline_state(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id, pipeline_id)): Path<(Uuid, Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    authorize(
        &state,
        &headers,
        organization_id,
        Some(project_id),
        Action::ProjectView,
    )
    .await?;
    let record = state
        .store
        .pipeline_operational_state(organization_id, project_id, pipeline_id)
        .await
        .map_err(pipeline_state_error)?
        .ok_or_else(resource_not_found)?;
    pipeline_state_response(StatusCode::OK, record)
}

async fn put_pipeline_state(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id, pipeline_id)): Path<(Uuid, Uuid, Uuid)>,
    headers: HeaderMap,
    Json(request): Json<PipelineOperationalStateRequest>,
) -> Result<Response, ApiError> {
    let principal = authorize(
        &state,
        &headers,
        organization_id,
        Some(project_id),
        Action::ProjectConfigure,
    )
    .await?;
    let expected_generation = expected_revision(&headers)?;
    if expected_generation == 0 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_state_precondition",
            "pipeline operational-state If-Match generation must be positive",
        ));
    }
    let idempotency_key = required_idempotency_key(&headers)?;
    let source_provenance_sha256 = parse_hex_digest_named(
        &request.source_provenance_sha256,
        "pipeline state provenance",
    )?;
    let outcome = state
        .store
        .transition_pipeline_operational_state(&PipelineOperationalStateTransition {
            organization_id,
            project_id,
            pipeline_id,
            expected_generation,
            state: request.state,
            reason: request.reason,
            actor_subject: principal.subject,
            source_identity: request.source_identity,
            source_generation: request.source_generation,
            source_effective_at_unix_ms: request.source_effective_at_unix_ms,
            source_provenance_sha256,
            idempotency_key: idempotency_key.to_owned(),
        })
        .await
        .map_err(pipeline_state_error)?;
    match outcome {
        PipelineOperationalStateTransitionOutcome::Applied(record) => {
            pipeline_state_response(StatusCode::OK, record)
        }
        PipelineOperationalStateTransitionOutcome::Idempotent(record) => {
            pipeline_state_response(StatusCode::OK, record)
        }
        PipelineOperationalStateTransitionOutcome::NotFound => Err(resource_not_found()),
        PipelineOperationalStateTransitionOutcome::PreconditionFailed { current_generation } => {
            Err(ApiError::new(
                StatusCode::PRECONDITION_FAILED,
                "state_generation_precondition_failed",
                format!("current pipeline operational-state generation is {current_generation}"),
            ))
        }
    }
}

fn pipeline_state_response(
    status: StatusCode,
    record: PipelineOperationalStateRecord,
) -> Result<Response, ApiError> {
    let generation = record.generation;
    let mut response = (status, Json(record)).into_response();
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(&format!("\"{generation}\"")).map_err(internal)?,
    );
    Ok(response)
}

async fn list_pipelines(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id)): Path<ProjectPath>,
    Query(query): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Json<PipelinePage>, ApiError> {
    authorize(
        &state,
        &headers,
        organization_id,
        Some(project_id),
        Action::ProjectView,
    )
    .await?;
    state
        .store
        .pipelines(
            organization_id,
            project_id,
            query.after.as_deref(),
            page_limit(query.limit)?,
        )
        .await
        .map(Json)
        .map_err(product_error)
}

async fn put_component(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id, digest_hex)): Path<(Uuid, Uuid, String)>,
    headers: HeaderMap,
    Json(request): Json<ComponentUpsertRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let principal = authorize(
        &state,
        &headers,
        organization_id,
        Some(project_id),
        Action::ProjectConfigure,
    )
    .await?;
    let digest = parse_hex_digest_named(&digest_hex, "component")?;
    let canonical_bytes = parse_hex_bytes(&request.canonical_hex, "component canonical bytes")?;
    if Sha256::digest(&canonical_bytes).as_slice() != digest {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "component_digest_mismatch",
            "component path digest does not match canonical bytes",
        ));
    }
    let source_sha256 = parse_hex_digest_named(&request.source_sha256, "component source")?;
    let outcome = state
        .store
        .register_component_as(
            &ComponentWrite {
                organization_id,
                project_id,
                digest,
                name: request.name,
                version_major: request.version_major,
                version_minor: request.version_minor,
                canonical_bytes,
                source_sha256,
            },
            &principal.subject,
        )
        .await
        .map_err(product_error)?;
    let status = match outcome {
        ComponentPutOutcome::Created => StatusCode::CREATED,
        ComponentPutOutcome::Unchanged => StatusCode::OK,
        ComponentPutOutcome::Conflict => {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "component_digest_conflict",
                "component digest already identifies different immutable content",
            ));
        }
    };
    Ok((
        status,
        Json(json!({"digest": digest_hex.to_ascii_lowercase()})),
    ))
}

async fn get_component(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id, digest_hex)): Path<(Uuid, Uuid, String)>,
    headers: HeaderMap,
) -> Result<Json<mcloving_controller_store::ComponentRecord>, ApiError> {
    authorize(
        &state,
        &headers,
        organization_id,
        Some(project_id),
        Action::ProjectView,
    )
    .await?;
    let digest = parse_hex_digest_named(&digest_hex, "component")?;
    state
        .store
        .component(organization_id, project_id, digest)
        .await
        .map_err(product_error)?
        .map(Json)
        .ok_or_else(resource_not_found)
}

async fn list_components(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id)): Path<ProjectPath>,
    Query(query): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Json<ComponentPage>, ApiError> {
    authorize(
        &state,
        &headers,
        organization_id,
        Some(project_id),
        Action::ProjectView,
    )
    .await?;
    let after = match (&query.after, &query.after_digest) {
        (None, None) => None,
        (Some(name), Some(digest)) => Some(ComponentCursor {
            name: name.clone(),
            digest: parse_hex_digest_named(digest, "component cursor")?,
        }),
        _ => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "invalid_cursor",
                "component cursor requires both after and after_digest",
            ));
        }
    };
    state
        .store
        .components(
            organization_id,
            project_id,
            after.as_ref(),
            page_limit(query.limit)?,
        )
        .await
        .map(Json)
        .map_err(product_error)
}

async fn list_builds(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id)): Path<ProjectPath>,
    Query(query): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Json<BuildPage>, ApiError> {
    authorize(
        &state,
        &headers,
        organization_id,
        Some(project_id),
        Action::ProjectView,
    )
    .await?;
    let after = match (query.after_created_micros, query.after_id) {
        (None, None) => None,
        (Some(created_at_unix_micros), Some(build_id)) => Some(BuildCursor {
            created_at_unix_micros,
            build_id,
        }),
        _ => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "invalid_cursor",
                "build cursor requires after_created_micros and after_id",
            ));
        }
    };
    state
        .store
        .builds_page(
            organization_id,
            project_id,
            after,
            query.status.as_deref(),
            page_limit(query.limit)?,
        )
        .await
        .map(Json)
        .map_err(product_error)
}

async fn build_graph(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id, build_id)): Path<BuildPath>,
    headers: HeaderMap,
) -> Result<Json<BuildGraph>, ApiError> {
    authorize(
        &state,
        &headers,
        organization_id,
        Some(project_id),
        Action::ProjectView,
    )
    .await?;
    state
        .store
        .build_graph(organization_id, project_id, build_id)
        .await
        .map_err(product_error)?
        .map(Json)
        .ok_or_else(resource_not_found)
}

async fn list_approvals(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id, build_id)): Path<BuildPath>,
    headers: HeaderMap,
) -> Result<Json<Vec<ApprovalView>>, ApiError> {
    authorize(
        &state,
        &headers,
        organization_id,
        Some(project_id),
        Action::ProjectView,
    )
    .await?;
    state
        .store
        .approvals(organization_id, project_id, build_id)
        .await
        .map(Json)
        .map_err(product_error)
}

async fn create_approval(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id, build_id)): Path<BuildPath>,
    headers: HeaderMap,
    Json(request): Json<ApprovalRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let approver = authorize(
        &state,
        &headers,
        organization_id,
        Some(project_id),
        Action::ApprovalAct,
    )
    .await?;
    let graph = state
        .store
        .build_graph(organization_id, project_id, build_id)
        .await
        .map_err(product_error)?
        .ok_or_else(resource_not_found)?;
    let created = state
        .store
        .approve_environment(&NewEnvironmentApproval {
            id: request.approval_id,
            organization_id,
            project_id,
            build_id,
            pipeline_digest: graph.build.pipeline_digest,
            environment: &request.environment,
            action: &request.action,
            approver_subject: &approver.subject,
            ttl_seconds: request.ttl_seconds,
        })
        .await
        .map_err(security_error)?;
    Ok((
        if created {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        Json(json!({
            "approval_id": request.approval_id,
            "created": created,
        })),
    ))
}

async fn list_credential_grants(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id, build_id)): Path<BuildPath>,
    headers: HeaderMap,
) -> Result<Json<Vec<CredentialGrantView>>, ApiError> {
    authorize(
        &state,
        &headers,
        organization_id,
        Some(project_id),
        Action::SecretUse,
    )
    .await?;
    state
        .store
        .credential_grants(organization_id, project_id, build_id)
        .await
        .map(Json)
        .map_err(product_error)
}

async fn list_test_reports(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id, build_id)): Path<BuildPath>,
    headers: HeaderMap,
) -> Result<Json<Vec<TestReportView>>, ApiError> {
    authorize(
        &state,
        &headers,
        organization_id,
        Some(project_id),
        Action::TestRead,
    )
    .await?;
    state
        .store
        .test_reports(organization_id, project_id, build_id)
        .await
        .map(Json)
        .map_err(product_error)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AdmissionResponse {
    pub build_id: Uuid,
    pub node_id: Uuid,
    pub attempt_id: Uuid,
    pub created: bool,
    pub pipeline_digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BuildResponse {
    pub build_id: Uuid,
    pub node_id: Uuid,
    pub attempt_id: Uuid,
    pub status: String,
    pub attempt_status: String,
    pub fence: i64,
    pub lease_owner: Option<String>,
    pub cancellation_requested: bool,
    pub terminal_summary: Option<Value>,
    pub effects: Vec<RuntimeEffectEvidenceResponse>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeEffectEvidenceResponse {
    pub fence: i64,
    pub effect_key: String,
    pub effect_class: String,
    pub status: String,
    pub payload_sha256: String,
    pub outcome_receipt_sha256: Option<String>,
    pub reconciliation_receipt_sha256: Option<String>,
    pub observation_receipt_sha256: Option<String>,
    pub shadow_replay_receipt_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LogResponse {
    pub attempt_id: Uuid,
    pub fence: i64,
    pub sequence: i64,
    pub stream: String,
    pub text: Option<String>,
    pub content_hex: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LogCursor {
    pub attempt_id: Uuid,
    pub fence: i64,
    pub sequence: i64,
    pub stream: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LogPage {
    pub items: Vec<LogResponse>,
    pub next_after: Option<LogCursor>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CancellationResponse {
    pub accepted: bool,
    /// Names why a refusal happened; absent when the request was accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StagedArtifactResponse {
    pub upload_token: String,
    pub name: String,
    pub media_type: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ArtifactCommitRequest {
    pub node_id: Uuid,
    pub attempt_id: Uuid,
    pub fence: i64,
    pub restore_epoch: i64,
    pub agent_id: String,
    pub name: String,
    pub media_type: String,
    pub sha256: String,
    pub bytes: u64,
    pub retention_seconds: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArtifactResponse {
    pub build_id: Uuid,
    pub node_id: Uuid,
    pub attempt_id: Uuid,
    pub fence: i64,
    pub name: String,
    pub sha256: String,
    pub bytes: u64,
    pub media_type: String,
    pub status: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ArtifactQuery {
    pub attempt_id: Uuid,
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum ExplainResponse {
    Ready,
    NoQueuedWork,
    TrustPoolMismatch {
        required: String,
        offered: String,
    },
    CapabilityMismatch {
        required: Vec<String>,
        missing: Vec<String>,
    },
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
}

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    fn configuration(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "configuration", message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                code: self.code,
                message: self.message,
            }),
        )
            .into_response()
    }
}

type ProjectPath = (Uuid, Uuid);
type BuildPath = (Uuid, Uuid, Uuid);

async fn get_pipeline_trigger(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id, pipeline_id, trigger_id)): Path<(Uuid, Uuid, Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    authorize(
        &state,
        &headers,
        organization_id,
        Some(project_id),
        Action::ProjectView,
    )
    .await?;
    let trigger = state
        .store
        .pipeline_trigger(organization_id, project_id, pipeline_id, trigger_id)
        .await
        .map_err(trigger_error)?
        .ok_or_else(resource_not_found)?;
    trigger_response(StatusCode::OK, trigger)
}

async fn put_pipeline_trigger(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id, pipeline_id, trigger_id)): Path<(Uuid, Uuid, Uuid, Uuid)>,
    headers: HeaderMap,
    Json(request): Json<PipelineTriggerRequest>,
) -> Result<Response, ApiError> {
    let principal = authorize(
        &state,
        &headers,
        organization_id,
        Some(project_id),
        Action::ProjectConfigure,
    )
    .await?;
    let expected_generation = expected_revision(&headers)?;
    let idempotency_key = required_idempotency_key(&headers)?;
    let outcome = state
        .store
        .put_pipeline_trigger(&PipelineTriggerWrite {
            organization_id,
            project_id,
            pipeline_id,
            trigger_id,
            expected_generation,
            kind: request.kind,
            state: request.state,
            implementation_sha256: parse_hex_digest_named(
                &request.implementation_sha256,
                "trigger implementation",
            )?,
            configuration_sha256: parse_hex_digest_named(
                &request.configuration_sha256,
                "trigger configuration",
            )?,
            filter_sha256: parse_hex_digest_named(&request.filter_sha256, "trigger filter")?,
            event_source_identity: request.event_source_identity,
            source_generation: request.source_generation,
            configuration: request.configuration,
            deduplication_window_seconds: request.deduplication_window_seconds,
            max_delivery_attempts: request.max_delivery_attempts,
            delivery_ttl_seconds: request.delivery_ttl_seconds,
            actor_subject: principal.subject,
            reason: request.reason,
            idempotency_key: idempotency_key.to_owned(),
        })
        .await
        .map_err(trigger_error)?;
    match outcome {
        TriggerPutOutcome::Created(trigger) => trigger_response(StatusCode::CREATED, trigger),
        TriggerPutOutcome::Revised(trigger) | TriggerPutOutcome::Replayed(trigger) => {
            trigger_response(StatusCode::OK, trigger)
        }
        TriggerPutOutcome::PreconditionFailed { current_generation } => Err(ApiError::new(
            StatusCode::PRECONDITION_FAILED,
            "trigger_generation_precondition_failed",
            format!("current trigger generation is {current_generation}"),
        )),
    }
}

fn trigger_response(status: StatusCode, trigger: PipelineTrigger) -> Result<Response, ApiError> {
    let generation = trigger.generation;
    let mut response = (
        status,
        Json(PipelineTriggerResponse {
            organization_id: trigger.organization_id,
            project_id: trigger.project_id,
            pipeline_id: trigger.pipeline_id,
            trigger_id: trigger.trigger_id,
            generation,
            kind: trigger.kind,
            state: trigger.state,
            implementation_sha256: hex(&trigger.implementation_sha256),
            configuration_sha256: hex(&trigger.configuration_sha256),
            filter_sha256: hex(&trigger.filter_sha256),
            event_source_identity: trigger.event_source_identity,
            source_generation: trigger.source_generation,
            configuration: trigger.configuration,
            deduplication_window_seconds: trigger.deduplication_window_seconds,
            max_delivery_attempts: trigger.max_delivery_attempts,
            delivery_ttl_seconds: trigger.delivery_ttl_seconds,
        }),
    )
        .into_response();
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(&format!("\"{generation}\"")).map_err(internal)?,
    );
    Ok(response)
}

async fn get_discovery_parent(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id, pipeline_id, parent_id)): Path<(Uuid, Uuid, Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    authorize(
        &state,
        &headers,
        organization_id,
        Some(project_id),
        Action::ProjectView,
    )
    .await?;
    let parent = state
        .store
        .discovery_parent(organization_id, project_id, pipeline_id, parent_id)
        .await
        .map_err(discovery_error)?
        .ok_or_else(resource_not_found)?;
    discovery_parent_response(StatusCode::OK, parent)
}

async fn put_discovery_parent(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id, pipeline_id, parent_id)): Path<(Uuid, Uuid, Uuid, Uuid)>,
    headers: HeaderMap,
    Json(request): Json<DiscoveryParentRequest>,
) -> Result<Response, ApiError> {
    let principal = authorize(
        &state,
        &headers,
        organization_id,
        Some(project_id),
        Action::ProjectConfigure,
    )
    .await?;
    let expected_generation = expected_revision(&headers)?;
    let idempotency_key = required_idempotency_key(&headers)?;
    let outcome = state
        .store
        .put_discovery_parent(&DiscoveryParentWrite {
            organization_id,
            project_id,
            pipeline_id,
            parent_id,
            expected_generation,
            kind: request.kind,
            state: request.state,
            implementation_sha256: parse_lowercase_hex_digest_named(
                &request.implementation_sha256,
                "discovery implementation",
            )?,
            protocol_version: request.protocol_version,
            expected_configuration_sha256: parse_lowercase_hex_digest_named(
                &request.configuration_sha256,
                "discovery configuration",
            )?,
            provider: request.provider,
            provider_identity: request.provider_identity,
            organization_identity: request.organization_identity,
            repositories: request.repositories,
            branch_includes: request.branch_includes,
            branch_excludes: request.branch_excludes,
            pull_request_strategy: request.pull_request_strategy,
            fork_trust_strategy: request.fork_trust_strategy,
            trusted_fork_repositories: request.trusted_fork_repositories,
            jenkinsfile_path: request.jenkinsfile_path,
            child_configuration_policy_sha256: parse_lowercase_hex_digest_named(
                &request.child_configuration_policy_sha256,
                "discovery child configuration policy",
            )?,
            orphan_policy: request.orphan_policy,
            authorization_generation: request.authorization_generation,
            authorization_policy_sha256: parse_lowercase_hex_digest_named(
                &request.authorization_policy_sha256,
                "discovery authorization policy",
            )?,
            trigger_id: request.trigger_id,
            trigger_generation: request.trigger_generation,
            trigger_configuration_sha256: parse_lowercase_hex_digest_named(
                &request.trigger_configuration_sha256,
                "discovery trigger configuration",
            )?,
            source_implementation_sha256: parse_lowercase_hex_digest_named(
                &request.source_implementation_sha256,
                "discovery source implementation",
            )?,
            source_protocol_version: request.source_protocol_version,
            source_configuration_sha256: parse_lowercase_hex_digest_named(
                &request.source_configuration_sha256,
                "discovery source configuration",
            )?,
            restored_from_generation: request.restored_from_generation,
            actor_subject: principal.subject,
            reason: request.reason,
            idempotency_key: idempotency_key.to_owned(),
        })
        .await
        .map_err(discovery_error)?;
    match outcome {
        DiscoveryParentPutOutcome::Created(parent) => {
            discovery_parent_response(StatusCode::CREATED, parent)
        }
        DiscoveryParentPutOutcome::Revised(parent)
        | DiscoveryParentPutOutcome::Replayed(parent) => {
            discovery_parent_response(StatusCode::OK, parent)
        }
        DiscoveryParentPutOutcome::PreconditionFailed { current_generation } => Err(ApiError::new(
            StatusCode::PRECONDITION_FAILED,
            "discovery_generation_precondition_failed",
            format!("current discovery generation is {current_generation}"),
        )),
    }
}

async fn reconcile_discovery_scan(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id, pipeline_id, parent_id)): Path<(Uuid, Uuid, Uuid, Uuid)>,
    headers: HeaderMap,
    Json(request): Json<DiscoveryScanRequest>,
) -> Result<Response, ApiError> {
    let principal = authorize(
        &state,
        &headers,
        organization_id,
        Some(project_id),
        Action::ProjectConfigure,
    )
    .await?;
    let observations = request
        .observations
        .into_iter()
        .map(|observation| {
            Ok(DiscoveryObservationWrite {
                child_key: observation.child_key,
                child_pipeline_id: observation.child_pipeline_id,
                repository_identity: observation.repository_identity,
                ref_kind: observation.ref_kind,
                ref_name: observation.ref_name,
                pull_request_number: observation.pull_request_number,
                head_repository_identity: observation.head_repository_identity,
                present: observation.present,
                revision: observation.revision,
                provenance_sha256: parse_lowercase_hex_digest_named(
                    &observation.provenance_sha256,
                    "discovery observation provenance",
                )?,
                jenkinsfile_path: observation.jenkinsfile_path,
                jenkinsfile_sha256: parse_lowercase_hex_digest_named(
                    &observation.jenkinsfile_sha256,
                    "discovery Jenkinsfile",
                )?,
                child_configuration_sha256: parse_lowercase_hex_digest_named(
                    &observation.child_configuration_sha256,
                    "discovery child configuration",
                )?,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    let outcome = state
        .store
        .reconcile_discovery_scan(&DiscoveryScanWrite {
            organization_id,
            project_id,
            pipeline_id,
            parent_id,
            expected_parent_generation: request.parent_generation,
            scan_id: request.scan_id,
            source: request.source,
            source_event_id: request.source_event_id,
            source_cursor: request.source_cursor,
            complete_snapshot: request.complete_snapshot,
            provider_snapshot_sha256: parse_lowercase_hex_digest_named(
                &request.provider_snapshot_sha256,
                "discovery provider snapshot",
            )?,
            observations,
            expected_request_sha256: parse_lowercase_hex_digest_named(
                &request.request_sha256,
                "discovery scan request",
            )?,
            actor_subject: principal.subject,
        })
        .await
        .map_err(discovery_error)?;
    let (status, receipt, replayed) = match outcome {
        DiscoveryScanOutcome::Reconciled(receipt) => (StatusCode::CREATED, receipt, false),
        DiscoveryScanOutcome::Replayed(receipt) => (StatusCode::OK, receipt, true),
    };
    Ok((
        status,
        Json(DiscoveryScanResponse {
            receipt: receipt.into(),
            replayed,
        }),
    )
        .into_response())
}

async fn list_discovery_children(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id, pipeline_id, parent_id)): Path<(Uuid, Uuid, Uuid, Uuid)>,
    Query(query): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    authorize(
        &state,
        &headers,
        organization_id,
        Some(project_id),
        Action::ProjectView,
    )
    .await?;
    let page = state
        .store
        .discovery_children(
            organization_id,
            project_id,
            pipeline_id,
            parent_id,
            query.after.as_deref(),
            discovery_child_page_limit(query.limit)?,
        )
        .await
        .map_err(discovery_error)?;
    Ok(Json(DiscoveryChildPageResponse {
        items: page
            .items
            .into_iter()
            .map(DiscoveryChildResponse::from)
            .collect::<Vec<_>>(),
        next_after: page.next_after,
    })
    .into_response())
}

impl From<DiscoveryScanReceipt> for DiscoveryScanReceiptResponse {
    fn from(receipt: DiscoveryScanReceipt) -> Self {
        Self {
            organization_id: receipt.organization_id,
            project_id: receipt.project_id,
            pipeline_id: receipt.pipeline_id,
            parent_id: receipt.parent_id,
            parent_generation: receipt.parent_generation,
            scan_id: receipt.scan_id,
            source: receipt.source,
            source_event_id: receipt.source_event_id,
            source_cursor: receipt.source_cursor,
            complete_snapshot: receipt.complete_snapshot,
            provider_snapshot_sha256: hex(&receipt.provider_snapshot_sha256),
            request_sha256: hex(&receipt.request_sha256),
            observation_count: receipt.observation_count,
            selected_count: receipt.selected_count,
            active_count: receipt.active_count,
            quarantined_count: receipt.quarantined_count,
            retired_count: receipt.retired_count,
            audit_sequence: receipt.audit_sequence,
            audit_event_hash: hex(&receipt.audit_event_hash),
        }
    }
}

impl From<DiscoveryChild> for DiscoveryChildResponse {
    fn from(child: DiscoveryChild) -> Self {
        Self {
            organization_id: child.organization_id,
            project_id: child.project_id,
            pipeline_id: child.pipeline_id,
            parent_id: child.parent_id,
            child_key: child.child_key,
            child_pipeline_id: child.child_pipeline_id,
            repository_identity: child.repository_identity,
            ref_kind: child.ref_kind,
            ref_name: child.ref_name,
            pull_request_number: child.pull_request_number,
            head_repository_identity: child.head_repository_identity,
            is_fork: child.is_fork,
            state: child.state,
            state_generation: child.state_generation,
            revision: child.revision,
            provenance_sha256: hex(&child.provenance_sha256),
            jenkinsfile_path: child.jenkinsfile_path,
            jenkinsfile_sha256: hex(&child.jenkinsfile_sha256),
            child_configuration_sha256: hex(&child.child_configuration_sha256),
            parent_generation: child.parent_generation,
            source_cursor: child.source_cursor,
            last_scan_id: child.last_scan_id,
        }
    }
}

fn discovery_parent_response(
    status: StatusCode,
    parent: DiscoveryParent,
) -> Result<Response, ApiError> {
    let generation = parent.generation;
    let mut response = (
        status,
        Json(DiscoveryParentResponse {
            organization_id: parent.organization_id,
            project_id: parent.project_id,
            pipeline_id: parent.pipeline_id,
            parent_id: parent.parent_id,
            generation,
            kind: parent.kind,
            state: parent.state,
            implementation_sha256: hex(&parent.implementation_sha256),
            protocol_version: parent.protocol_version,
            configuration_sha256: hex(&parent.configuration_sha256),
            provider: parent.provider,
            provider_identity: parent.provider_identity,
            organization_identity: parent.organization_identity,
            repositories: parent.repositories,
            branch_includes: parent.branch_includes,
            branch_excludes: parent.branch_excludes,
            pull_request_strategy: parent.pull_request_strategy,
            fork_trust_strategy: parent.fork_trust_strategy,
            trusted_fork_repositories: parent.trusted_fork_repositories,
            jenkinsfile_path: parent.jenkinsfile_path,
            child_configuration_policy_sha256: hex(&parent.child_configuration_policy_sha256),
            orphan_policy: parent.orphan_policy,
            authorization_generation: parent.authorization_generation,
            authorization_policy_sha256: hex(&parent.authorization_policy_sha256),
            trigger_id: parent.trigger_id,
            trigger_generation: parent.trigger_generation,
            trigger_configuration_sha256: hex(&parent.trigger_configuration_sha256),
            source_implementation_sha256: hex(&parent.source_implementation_sha256),
            source_protocol_version: parent.source_protocol_version,
            source_configuration_sha256: hex(&parent.source_configuration_sha256),
            restored_from_generation: parent.restored_from_generation,
            audit_sequence: parent.audit_sequence,
            audit_event_hash: hex(&parent.audit_event_hash),
        }),
    )
        .into_response();
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(&format!("\"{generation}\""))
            .map_err(|_| ApiError::configuration("invalid discovery generation ETag"))?,
    );
    Ok(response)
}

async fn submit_trigger_event(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id, pipeline_id, trigger_id)): Path<(Uuid, Uuid, Uuid, Uuid)>,
    headers: HeaderMap,
    Json(request): Json<TriggerEventRequest>,
) -> Result<Response, ApiError> {
    let principal = authorize(
        &state,
        &headers,
        organization_id,
        Some(project_id),
        Action::BuildTrigger,
    )
    .await?;
    let trigger = state
        .store
        .pipeline_trigger_generation(
            organization_id,
            project_id,
            pipeline_id,
            trigger_id,
            request.trigger_generation,
        )
        .await
        .map_err(trigger_error)?
        .ok_or_else(resource_not_found)?;
    validate_trigger_event_filter(&trigger, &request)?;
    // Reject parameter shapes before durable capture. The processing path
    // repeats this validation for crash/restart and legacy-corruption safety.
    parameter_values(request.parameters.clone())?;
    let accepted_at_unix_ms = unix_time_ms();
    let canonical_payload = canonical_trigger_payload(&request)?;
    let payload_bytes = serde_json::to_vec(&canonical_payload).map_err(internal)?;
    let payload_sha256: [u8; 32] = Sha256::digest(&payload_bytes).into();
    let parameters = Value::Object(request.parameters.clone().into_iter().collect());
    let schedule_slot = trigger_schedule_slot(&trigger, &request)?;
    let delivery = state
        .store
        .accept_trigger_delivery(&NewTriggerDelivery {
            organization_id,
            project_id,
            pipeline_id,
            trigger_id,
            expected_trigger_generation: request.trigger_generation,
            delivery_id: request.delivery_id.clone(),
            event_id: request.event_id.clone(),
            event_kind: request.event_kind.clone(),
            caller_identity: principal.subject.clone(),
            payload_sha256,
            canonical_payload,
            parameters,
            requested_platform: request.platform.clone(),
            requested_trust_pool: request.trust_pool.clone(),
            event_time_unix_ms: request.event_time_unix_ms,
            accepted_at_unix_ms,
            schedule_slot,
        })
        .await
        .map_err(trigger_error)?;
    let delivery = match delivery {
        TriggerDeliveryAdmission::Created(delivery)
        | TriggerDeliveryAdmission::Replayed(delivery) => delivery,
    };
    process_trigger_delivery(&state, delivery, accepted_at_unix_ms).await
}

async fn redrive_trigger_event(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id, pipeline_id, trigger_id, dead_letter_delivery_id)): Path<(
        Uuid,
        Uuid,
        Uuid,
        Uuid,
        String,
    )>,
    headers: HeaderMap,
    Json(request): Json<TriggerRedriveRequest>,
) -> Result<Response, ApiError> {
    let principal = authorize(
        &state,
        &headers,
        organization_id,
        Some(project_id),
        Action::ProjectConfigure,
    )
    .await?;
    let accepted_at_unix_ms = unix_time_ms();
    let delivery = state
        .store
        .redrive_trigger_delivery(&TriggerDeliveryRedrive {
            organization_id,
            project_id,
            pipeline_id,
            trigger_id,
            dead_letter_delivery_id,
            new_delivery_id: request.delivery_id,
            new_event_id: request.event_id,
            actor_subject: principal.subject,
            accepted_at_unix_ms,
        })
        .await
        .map_err(trigger_error)?;
    let delivery = match delivery {
        TriggerDeliveryAdmission::Created(delivery)
        | TriggerDeliveryAdmission::Replayed(delivery) => delivery,
    };
    process_trigger_delivery(&state, delivery, accepted_at_unix_ms).await
}

async fn process_trigger_delivery(
    state: &ApiState,
    delivery: TriggerDelivery,
    now_unix_ms: i64,
) -> Result<Response, ApiError> {
    if delivery.status == mcloving_controller_store::TriggerDeliveryStatus::Admitted {
        return admitted_trigger_response(state, delivery).await;
    }
    if delivery.status == mcloving_controller_store::TriggerDeliveryStatus::DeadLettered {
        return Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(TriggerEventResponse {
                delivery,
                admission: None,
            }),
        )
            .into_response());
    }
    let worker_identity = format!("trigger-api:{}", Uuid::new_v4());
    let claim = state
        .store
        .claim_trigger_delivery(&TriggerDeliveryClaimRequest {
            organization_id: delivery.organization_id,
            trigger_id: delivery.trigger_id,
            delivery_id: delivery.delivery_id.clone(),
            worker_identity: worker_identity.clone(),
            now_unix_ms,
            lease_expires_at_unix_ms: now_unix_ms.saturating_add(60_000),
        })
        .await
        .map_err(trigger_error)?;
    let claimed = match claim {
        TriggerDeliveryClaimOutcome::Claimed(delivery) => delivery,
        TriggerDeliveryClaimOutcome::NotDue(delivery)
        | TriggerDeliveryClaimOutcome::Leased(delivery) => {
            return Ok((
                StatusCode::ACCEPTED,
                Json(TriggerEventResponse {
                    delivery,
                    admission: None,
                }),
            )
                .into_response());
        }
        TriggerDeliveryClaimOutcome::Terminal(delivery) => {
            if delivery.status == mcloving_controller_store::TriggerDeliveryStatus::Admitted {
                return admitted_trigger_response(state, delivery).await;
            }
            return Ok((
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(TriggerEventResponse {
                    delivery,
                    admission: None,
                }),
            )
                .into_response());
        }
    };
    let build_idempotency = trigger_build_idempotency(claimed.trigger_id, &claimed.delivery_id);
    let parameters = match parameter_values_from_delivery(&claimed) {
        Ok(parameters) => parameters,
        Err(error) => {
            return fail_claimed_trigger_delivery(state, claimed, worker_identity, error).await;
        }
    };
    match admit_pipeline_parameters(
        state,
        PipelineAdmissionInput {
            organization_id: claimed.organization_id,
            project_id: claimed.project_id,
            pipeline_id: claimed.pipeline_id,
            idempotency_key: build_idempotency,
            parameters,
            required_platform: claimed.requested_platform.clone(),
            required_trust_pool: claimed.requested_trust_pool.clone(),
            trigger_claim: Some(TriggerDeliveryDagAdmissionRequest {
                organization_id: claimed.organization_id,
                trigger_id: claimed.trigger_id,
                delivery_id: claimed.delivery_id.clone(),
                worker_identity: worker_identity.clone(),
                claim_fence: claimed.claim_fence,
            }),
            trigger_replay: false,
        },
    )
    .await
    {
        Ok(result) => {
            let delivery = result
                .trigger_delivery
                .ok_or_else(|| internal("trigger admission omitted its atomic delivery result"))?;
            Ok((
                result.status,
                Json(TriggerEventResponse {
                    delivery,
                    admission: result.admission,
                }),
            )
                .into_response())
        }
        Err(error) => fail_claimed_trigger_delivery(state, claimed, worker_identity, error).await,
    }
}

async fn fail_claimed_trigger_delivery(
    state: &ApiState,
    claimed: TriggerDelivery,
    worker_identity: String,
    error: ApiError,
) -> Result<Response, ApiError> {
    let retryable = error.status.is_server_error();
    let failure_unix_ms = unix_time_ms();
    let failed = state
        .store
        .fail_trigger_delivery(&TriggerDeliveryFailureRequest {
            organization_id: claimed.organization_id,
            trigger_id: claimed.trigger_id,
            delivery_id: claimed.delivery_id,
            worker_identity,
            claim_fence: claimed.claim_fence,
            now_unix_ms: failure_unix_ms,
            retry_at_unix_ms: failure_unix_ms.saturating_add(60_000),
            retryable,
            reason: bounded_trigger_failure_reason(&error),
        })
        .await
        .map_err(trigger_error)?;
    let (status, delivery) = match failed {
        TriggerDeliveryFailure::RetryScheduled(delivery) => (StatusCode::ACCEPTED, delivery),
        TriggerDeliveryFailure::DeadLettered(delivery) => {
            (StatusCode::UNPROCESSABLE_ENTITY, delivery)
        }
        TriggerDeliveryFailure::LeaseLost(delivery) => (StatusCode::ACCEPTED, delivery),
    };
    Ok((
        status,
        Json(TriggerEventResponse {
            delivery,
            admission: None,
        }),
    )
        .into_response())
}

async fn admitted_trigger_response(
    state: &ApiState,
    delivery: TriggerDelivery,
) -> Result<Response, ApiError> {
    let build_id = delivery
        .build_id
        .ok_or_else(|| internal("admitted trigger delivery is missing its bound build identity"))?;
    let result = admit_pipeline_parameters(
        state,
        PipelineAdmissionInput {
            organization_id: delivery.organization_id,
            project_id: delivery.project_id,
            pipeline_id: delivery.pipeline_id,
            idempotency_key: trigger_build_idempotency(delivery.trigger_id, &delivery.delivery_id),
            parameters: parameter_values_from_delivery(&delivery)?,
            required_platform: delivery.requested_platform.clone(),
            required_trust_pool: delivery.requested_trust_pool.clone(),
            trigger_claim: None,
            trigger_replay: true,
        },
    )
    .await?;
    let admission = result
        .admission
        .ok_or_else(|| internal("admitted trigger replay omitted its build admission"))?;
    if admission.build_id != build_id {
        return Err(internal(
            "trigger delivery replay resolved to a different build identity",
        ));
    }
    Ok((
        result.status,
        Json(TriggerEventResponse {
            delivery,
            admission: Some(admission),
        }),
    )
        .into_response())
}

fn parameter_values_from_delivery(
    delivery: &TriggerDelivery,
) -> Result<BTreeMap<String, ParameterValue>, ApiError> {
    let parameters: BTreeMap<String, Value> = serde_json::from_value(delivery.parameters.clone())
        .map_err(|_| {
        internal("stored trigger delivery parameters are not a canonical object")
    })?;
    parameter_values(parameters)
}

fn canonical_trigger_payload(request: &TriggerEventRequest) -> Result<Value, ApiError> {
    if !request.payload.is_object() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_trigger_payload",
            "trigger payload must be an object",
        ));
    }
    Ok(json!({
        "trigger_generation": request.trigger_generation,
        "event_kind": request.event_kind.clone(),
        "event_time_unix_ms": request.event_time_unix_ms,
        "payload": request.payload.clone(),
    }))
}

fn validate_trigger_event_filter(
    trigger: &PipelineTrigger,
    request: &TriggerEventRequest,
) -> Result<(), ApiError> {
    if trigger.state == PipelineTriggerState::Paused {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "trigger_paused",
            format!("trigger is paused at generation {}", trigger.generation),
        ));
    }
    let filter = trigger
        .configuration
        .get("filter")
        .and_then(Value::as_object)
        .ok_or_else(|| internal("stored trigger filter is not an object"))?;
    if let Some(events) = filter.get("event_kinds") {
        let events = canonical_string_array(events, "event_kinds")?;
        if !events.is_empty() && !events.iter().any(|event| event == &request.event_kind) {
            return Err(trigger_filtered("event kind"));
        }
    }
    match trigger.kind {
        TriggerKind::ScmWebhook => {
            let configured = trigger
                .configuration
                .get("repository_identity")
                .and_then(Value::as_str)
                .ok_or_else(|| internal("stored SCM repository identity is missing"))?;
            if trigger_payload_text(request, "repository_identity")? != configured {
                return Err(trigger_filtered("SCM repository identity"));
            }
            trigger_payload_text(request, "revision")?;
            if let Some(branches) = filter.get("branches") {
                let branches = canonical_string_array(branches, "branches")?;
                let branch = request
                    .payload
                    .get("branch")
                    .and_then(Value::as_str)
                    .ok_or_else(|| trigger_filtered("missing branch"))?;
                if !branches.is_empty() && !branches.iter().any(|allowed| allowed == branch) {
                    return Err(trigger_filtered("branch"));
                }
            }
            let supplied_paths = request
                .payload
                .get("paths")
                .map(|paths| {
                    let paths = paths
                        .as_array()
                        .ok_or_else(|| trigger_filtered("invalid paths"))?;
                    if paths.len() > 128 {
                        return Err(trigger_filtered("invalid paths"));
                    }
                    paths
                        .iter()
                        .map(|path| {
                            path.as_str()
                                .filter(|path| {
                                    !path.is_empty()
                                        && path.trim() == *path
                                        && path.len() <= 512
                                        && !path.chars().any(char::is_control)
                                })
                                .ok_or_else(|| trigger_filtered("invalid path"))
                        })
                        .collect::<Result<Vec<_>, ApiError>>()
                })
                .transpose()?;
            if let Some(prefixes) = filter.get("path_prefixes") {
                let prefixes = canonical_string_array(prefixes, "path_prefixes")?;
                let matched = prefixes.is_empty()
                    || supplied_paths
                        .as_ref()
                        .ok_or_else(|| trigger_filtered("missing paths"))?
                        .iter()
                        .any(|path| prefixes.iter().any(|prefix| path.starts_with(prefix)));
                if !matched {
                    return Err(trigger_filtered("path"));
                }
            }
        }
        TriggerKind::Upstream => {
            let configured = trigger
                .configuration
                .get("upstream_pipeline_id")
                .and_then(Value::as_str)
                .ok_or_else(|| internal("stored upstream pipeline identity is missing"))?;
            let supplied = request
                .payload
                .get("upstream_pipeline_id")
                .and_then(Value::as_str)
                .ok_or_else(|| trigger_filtered("missing upstream pipeline identity"))?;
            if supplied != configured {
                return Err(trigger_filtered("upstream pipeline identity"));
            }
            let upstream_build = trigger_payload_text(request, "upstream_build_id")?;
            Uuid::parse_str(upstream_build)
                .map_err(|_| trigger_filtered("invalid upstream build identity"))?;
            if let Some(statuses) = filter.get("statuses") {
                let statuses = canonical_string_array(statuses, "statuses")?;
                let status = request
                    .payload
                    .get("status")
                    .and_then(Value::as_str)
                    .ok_or_else(|| trigger_filtered("missing upstream status"))?;
                if !statuses.is_empty() && !statuses.iter().any(|allowed| allowed == status) {
                    return Err(trigger_filtered("upstream status"));
                }
            }
        }
        TriggerKind::Schedule => {
            if request.event_kind != "schedule" {
                return Err(trigger_filtered("schedule event kind"));
            }
        }
        TriggerKind::RemoteApi => {
            let configured = trigger
                .configuration
                .get("audience")
                .and_then(Value::as_str)
                .ok_or_else(|| internal("stored remote-build audience is missing"))?;
            if trigger_payload_text(request, "audience")? != configured {
                return Err(trigger_filtered("remote-build audience"));
            }
            if trigger_payload_text(request, "request_id")? != request.event_id {
                return Err(trigger_filtered("remote-build request identity"));
            }
            let method = trigger_payload_text(request, "request_method")?;
            if let Some(methods) = filter.get("request_methods") {
                let methods = canonical_string_array(methods, "request_methods")?;
                if !methods.is_empty() && !methods.iter().any(|allowed| allowed == method) {
                    return Err(trigger_filtered("request method"));
                }
            }
        }
        TriggerKind::Plugin => {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "trigger_class_ineligible",
                "plugin trigger class has no installed admitted implementation",
            ));
        }
    }
    Ok(())
}

fn trigger_payload_text<'a>(
    request: &'a TriggerEventRequest,
    field: &str,
) -> Result<&'a str, ApiError> {
    request
        .payload
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.trim() == *value && value.len() <= 512)
        .ok_or_else(|| trigger_filtered(&format!("missing or invalid {field}")))
}

fn trigger_schedule_slot(
    trigger: &PipelineTrigger,
    request: &TriggerEventRequest,
) -> Result<Option<TriggerScheduleSlot>, ApiError> {
    if trigger.kind != TriggerKind::Schedule {
        return Ok(None);
    }
    let required_text = |field: &str| {
        request
            .payload
            .get(field)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| trigger_filtered(&format!("missing schedule {field}")))
    };
    let resolved_slot_unix_ms = request
        .payload
        .get("resolved_slot_unix_ms")
        .and_then(Value::as_i64)
        .ok_or_else(|| trigger_filtered("missing resolved schedule slot"))?;
    let expected_last_resolved_slot_unix_ms = request
        .payload
        .get("expected_last_resolved_slot_unix_ms")
        .map(|value| {
            value.as_i64().ok_or_else(|| {
                ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "invalid_schedule_watermark",
                    "expected schedule watermark must be an integer",
                )
            })
        })
        .transpose()?;
    Ok(Some(TriggerScheduleSlot {
        timezone: required_text("timezone")?,
        calendar: required_text("calendar")?,
        expression: required_text("expression")?,
        schedule_identity_sha256: parse_hex_digest_named(
            &required_text("schedule_identity_sha256")?,
            "schedule identity",
        )?,
        expected_last_resolved_slot_unix_ms,
        resolved_slot_unix_ms,
    }))
}

fn canonical_string_array(value: &Value, field: &str) -> Result<Vec<String>, ApiError> {
    let values = value.as_array().ok_or_else(|| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid_trigger_configuration",
            format!("stored trigger filter '{field}' must be an array"),
        )
    })?;
    let strings = values
        .iter()
        .map(|value| {
            value.as_str().map(str::to_owned).ok_or_else(|| {
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "invalid_trigger_configuration",
                    format!("stored trigger filter '{field}' contains a non-string"),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(strings)
}

fn trigger_filtered(field: &str) -> ApiError {
    ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "trigger_filtered",
        format!("trigger event did not pass the configured {field} filter"),
    )
}

fn trigger_build_idempotency(trigger_id: Uuid, delivery_id: &str) -> String {
    let digest: [u8; 32] = Sha256::digest(delivery_id.as_bytes()).into();
    format!(
        "{TRIGGER_DAG_IDEMPOTENCY_PREFIX}{trigger_id}-{}",
        hex(&digest)
    )
}

fn default_platform() -> String {
    DEFAULT_PLATFORM.to_owned()
}

async fn submit_pipeline_build(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id, pipeline_id)): Path<(Uuid, Uuid, Uuid)>,
    headers: HeaderMap,
    Json(request): Json<PipelineBuildRequest>,
) -> Result<(StatusCode, Json<AdmissionResponse>), ApiError> {
    authorize(
        &state,
        &headers,
        organization_id,
        Some(project_id),
        Action::BuildTrigger,
    )
    .await?;
    let required_trust_pool = submission_trust_pool(&headers)?;
    let required_platform = submission_platform(&headers)?;
    let idempotency_key = ordinary_build_idempotency_key(&headers)?;
    let parameters = parameter_values(request.parameters)?;
    let result = admit_pipeline_parameters(
        &state,
        PipelineAdmissionInput {
            organization_id,
            project_id,
            pipeline_id,
            idempotency_key: idempotency_key.to_owned(),
            parameters,
            required_platform,
            required_trust_pool,
            trigger_claim: None,
            trigger_replay: false,
        },
    )
    .await?;
    let response = result
        .admission
        .ok_or_else(|| internal("pipeline admission omitted its build response"))?;
    Ok((result.status, Json(response)))
}

struct PipelineAdmissionInput {
    organization_id: Uuid,
    project_id: Uuid,
    pipeline_id: Uuid,
    idempotency_key: String,
    parameters: BTreeMap<String, ParameterValue>,
    required_platform: String,
    required_trust_pool: String,
    trigger_claim: Option<TriggerDeliveryDagAdmissionRequest>,
    trigger_replay: bool,
}

struct PipelineAdmissionResult {
    status: StatusCode,
    admission: Option<AdmissionResponse>,
    trigger_delivery: Option<TriggerDelivery>,
}

async fn admit_pipeline_parameters(
    state: &ApiState,
    input: PipelineAdmissionInput,
) -> Result<PipelineAdmissionResult, ApiError> {
    let PipelineAdmissionInput {
        organization_id,
        project_id,
        pipeline_id,
        idempotency_key,
        parameters,
        required_platform,
        required_trust_pool,
        trigger_claim,
        trigger_replay,
    } = input;
    let replay = state
        .store
        .dag_replay_binding(organization_id, project_id, &idempotency_key)
        .await
        .map_err(admission_error)?;
    let (source, pipeline_revision, pipeline_operational_generation) = match replay {
        Some(binding) => {
            if binding.pipeline_id != pipeline_id {
                return Err(admission_error(StoreError::IdempotencyConflict(
                    "idempotency key already belongs to a different pipeline".to_owned(),
                )));
            }
            (
                binding.source,
                binding.pipeline_revision,
                binding.pipeline_operational_generation,
            )
        }
        None => {
            let saved = state
                .store
                .pipeline(organization_id, project_id, pipeline_id)
                .await
                .map_err(product_error)?
                .ok_or_else(resource_not_found)?;
            (saved.source, saved.revision, saved.operational_generation)
        }
    };
    let pipeline = compile_source_with_parameters(&source, parameters)?;
    validate_connector_mappings(&pipeline, &state.connector_mapping_catalog)?;
    validate_execution_platform(&pipeline, &required_platform)?;
    let digest = pipeline.semantic_digest().map_err(|error| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "pipeline_rejected",
            error.to_string(),
        )
    })?;
    let nodes = pipeline
        .stages
        .iter()
        .enumerate()
        .map(|(index, stage)| NewDagNode {
            node_key: stage.id.clone(),
            kind: DagNodeKind::Work,
            dependencies: index
                .checked_sub(1)
                .map(|previous| {
                    vec![DagDependency {
                        node_key: pipeline.stages[previous].id.clone(),
                        condition: DependencyCondition::Succeeded,
                    }]
                })
                .unwrap_or_default(),
            required_capabilities: Vec::new(),
            required_platform: required_platform.clone(),
            required_trust_pool: required_trust_pool.clone(),
            priority: 0,
            execution_spec: execution_spec(&stage.steps),
            fail_fast: true,
            max_attempts: 1,
        })
        .collect();
    let dag = NewDagBuild {
        organization_id,
        project_id,
        pipeline_id,
        pipeline_revision,
        pipeline_operational_generation,
        idempotency_key: idempotency_key.to_owned(),
        pipeline_digest: digest,
        priority: 0,
        nodes,
    };
    let (admission, trigger_delivery) = match trigger_claim {
        Some(claim) => match state
            .store
            .admit_trigger_delivery_dag(&claim, &dag)
            .await
            .map_err(admission_error)?
        {
            TriggerDeliveryDagAdmission::Admitted {
                delivery,
                admission,
            } => (admission, Some(delivery)),
            TriggerDeliveryDagAdmission::DeadLettered(delivery) => {
                return Ok(PipelineAdmissionResult {
                    status: StatusCode::UNPROCESSABLE_ENTITY,
                    admission: None,
                    trigger_delivery: Some(delivery),
                });
            }
            TriggerDeliveryDagAdmission::LeaseLost(delivery) => {
                return Ok(PipelineAdmissionResult {
                    status: StatusCode::ACCEPTED,
                    admission: None,
                    trigger_delivery: Some(delivery),
                });
            }
        },
        None if trigger_replay => (
            state
                .store
                .replay_trigger_dag(&dag)
                .await
                .map_err(admission_error)?,
            None,
        ),
        None => (
            state.store.admit_dag(&dag).await.map_err(admission_error)?,
            None,
        ),
    };
    let first = pipeline
        .stages
        .first()
        .and_then(|stage| admission.nodes.get(&stage.id))
        .ok_or_else(|| internal("DAG admission omitted its first node"))?;
    let status = if admission.created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok(PipelineAdmissionResult {
        status,
        admission: Some(AdmissionResponse {
            build_id: admission.build_id,
            node_id: first.node_id,
            attempt_id: first.attempt_id,
            created: admission.created,
            pipeline_digest: hex(&digest),
        }),
        trigger_delivery,
    })
}

fn required_idempotency_key(headers: &HeaderMap) -> Result<&str, ApiError> {
    headers
        .get(IDEMPOTENCY_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 256
                && value.trim() == *value
                && !value.chars().any(char::is_control)
        })
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "idempotency_key_required",
                "a canonical non-empty Idempotency-Key header of at most 256 bytes is required",
            )
        })
}

fn ordinary_build_idempotency_key(headers: &HeaderMap) -> Result<&str, ApiError> {
    let value = required_idempotency_key(headers)?;
    if value.starts_with(TRIGGER_DAG_IDEMPOTENCY_PREFIX) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "reserved_idempotency_key",
            "the trigger DAG idempotency namespace is reserved",
        ));
    }
    Ok(value)
}

fn submission_trust_pool(headers: &HeaderMap) -> Result<String, ApiError> {
    let value = match headers.get(TRUST_POOL_HEADER) {
        Some(value) => value.to_str().map_err(|_| invalid_trust_pool())?,
        None => DEFAULT_TRUST_POOL,
    };
    if value.is_empty() || value.trim() != value {
        return Err(invalid_trust_pool());
    }
    Ok(value.to_owned())
}

fn invalid_trust_pool() -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        "invalid_trust_pool",
        "trust pool must be non-empty and contain no surrounding whitespace",
    )
}

fn submission_platform(headers: &HeaderMap) -> Result<String, ApiError> {
    let value = match headers.get(PLATFORM_HEADER) {
        Some(value) => value.to_str().map_err(|_| invalid_platform())?,
        None => DEFAULT_PLATFORM,
    };
    if !matches!(value, "linux" | "windows") {
        return Err(invalid_platform());
    }
    Ok(value.to_owned())
}

fn invalid_platform() -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        "invalid_platform",
        "platform must be exactly linux or windows",
    )
}

fn execution_spec(steps: &[Step]) -> Value {
    let contains_connector_intent = steps
        .iter()
        .any(|step| matches!(step, Step::ConnectorIntent(_)));
    let steps = steps
        .iter()
        .map(|step| match step {
            Step::Process(process) => json!({
                "kind": "process",
                "mode": execution_mode_wire_name(process.mode),
                "program": process.program,
                "args": process.args,
                "env": process.env,
                "timeout_seconds": process.timeout_seconds,
            }),
            Step::ConnectorIntent(intent) => json!({
                "kind": "connector_intent",
                "mapping_id": intent.mapping_id,
                "mapping_digest": intent.mapping_digest,
                "effect_class": match intent.effect_class {
                    mcloving_pipeline_ir::ConnectorEffectClass::Idempotent => "idempotent",
                    mcloving_pipeline_ir::ConnectorEffectClass::ExternallyIdempotent => "externally_idempotent",
                    mcloving_pipeline_ir::ConnectorEffectClass::NonIdempotent => "non_idempotent",
                },
                "effect_key_template": intent.effect_key_template,
                "public_input_schema": intent.public_input_schema.iter().map(|(name, kind)| (name, json_field_type_name(*kind))).collect::<BTreeMap<_, _>>(),
                "protected_secret_ref_schema": intent.protected_secret_ref_schema.iter().map(|(name, kind)| (name, json_field_type_name(*kind))).collect::<BTreeMap<_, _>>(),
                "expected_public_result_schema": intent.expected_public_result_schema.iter().map(|(name, kind)| (name, json_field_type_name(*kind))).collect::<BTreeMap<_, _>>(),
                "timeout_seconds": intent.timeout_seconds,
                "ambiguity_policy": "observe_then_reconcile",
                "downstream_control_digest": intent.downstream_control_digest,
            }),
        })
        .collect::<Vec<_>>();
    json!({"version": if contains_connector_intent { 2 } else { 1 }, "steps": steps})
}

fn json_field_type_name(kind: mcloving_pipeline_ir::JsonFieldType) -> &'static str {
    match kind {
        mcloving_pipeline_ir::JsonFieldType::Array => "array",
        mcloving_pipeline_ir::JsonFieldType::Boolean => "boolean",
        mcloving_pipeline_ir::JsonFieldType::Null => "null",
        mcloving_pipeline_ir::JsonFieldType::Number => "number",
        mcloving_pipeline_ir::JsonFieldType::Object => "object",
        mcloving_pipeline_ir::JsonFieldType::String => "string",
    }
}

fn execution_mode_wire_name(mode: ProcessMode) -> &'static str {
    match mode {
        // Protocol 1.0 agents derived this spelling from the Rust variant name.
        // Keep emitting it until a negotiated feature can version the wire value.
        ProcessMode::PowerShell => "power_shell",
        _ => mode.as_str(),
    }
}

fn validate_execution_platform(pipeline: &PipelineIr, platform: &str) -> Result<(), ApiError> {
    if platform == "windows" {
        return Ok(());
    }
    let windows_mode = pipeline
        .stages
        .iter()
        .flat_map(|stage| &stage.steps)
        .find_map(|step| match step {
            Step::Process(process)
                if matches!(
                    process.mode,
                    ProcessMode::WindowsCmd | ProcessMode::PowerShell
                ) =>
            {
                Some(process.mode.as_str())
            }
            _ => None,
        });
    match windows_mode {
        Some(mode) => Err(pipeline_rejected(format!(
            "execution mode {mode} requires platform windows"
        ))),
        None => Ok(()),
    }
}

fn compile_source_with_parameters(
    source: &str,
    parameters: BTreeMap<String, ParameterValue>,
) -> Result<PipelineIr, ApiError> {
    if source.len() > ParseLimits::default().max_source_bytes {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "pipeline_too_large",
            "pipeline source exceeds the configured parser byte limit",
        ));
    }
    compile_strict_yaml_with_parameters("public-api", source, ParseLimits::default(), parameters)
        .map_err(pipeline_rejected)
}

fn validate_connector_mappings(
    pipeline: &PipelineIr,
    catalog: &ConnectorMappingCatalog,
) -> Result<(), ApiError> {
    for intent in pipeline
        .stages
        .iter()
        .flat_map(|stage| &stage.steps)
        .filter_map(|step| match step {
            Step::ConnectorIntent(intent) => Some(intent),
            Step::Process(_) => None,
        })
    {
        let Some(mapping) = catalog
            .mappings
            .iter()
            .find(|mapping| mapping.mapping_id == intent.mapping_id)
        else {
            return Err(pipeline_rejected(format!(
                "connector mapping {} is not admitted by deployment profile {}",
                intent.mapping_id, catalog.profile
            )));
        };
        if mapping.mapping_digest != intent.mapping_digest {
            return Err(pipeline_rejected(format!(
                "connector mapping {} digest is floating, stale, or substituted for deployment profile {}",
                intent.mapping_id, catalog.profile
            )));
        }
    }
    Ok(())
}

fn canonical_mapping_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
        })
}

fn canonical_sha256_reference(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn parameter_values(
    parameters: BTreeMap<String, Value>,
) -> Result<BTreeMap<String, ParameterValue>, ApiError> {
    if parameters.len() > 128 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_parameters",
            "at most 128 parameter values may be submitted",
        ));
    }
    parameters
        .into_iter()
        .map(|(name, value)| {
            if name.is_empty()
                || name.len() > 256
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            {
                return Err(invalid_parameter_name());
            }
            let value = match value {
                Value::Bool(value) => ParameterValue::Bool(value),
                Value::Number(value) => value
                    .as_i64()
                    .map(ParameterValue::Integer)
                    .ok_or_else(invalid_parameter_value)?,
                Value::String(value) if value.len() <= 4 * 1024 => ParameterValue::String(value),
                _ => return Err(invalid_parameter_value()),
            };
            Ok((name, value))
        })
        .collect()
}

fn invalid_parameter_name() -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        "invalid_parameters",
        "parameter names must be 1-256 ASCII letters, digits, underscores, or hyphens",
    )
}

fn bounded_trigger_failure_reason(error: &ApiError) -> String {
    const MAX_FAILURE_REASON_BYTES: usize = 2048;

    let mut reason = format!("{}: {}", error.code, error.message)
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>();
    reason = reason.trim().to_owned();
    if reason.is_empty() {
        reason = "trigger admission failed".to_owned();
    }
    while reason.len() > MAX_FAILURE_REASON_BYTES {
        reason.pop();
    }
    reason
}

fn invalid_parameter_value() -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        "invalid_parameters",
        "parameter values must be bounded booleans, signed integers, or strings",
    )
}

fn pipeline_rejected(error: impl std::fmt::Display) -> ApiError {
    ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "pipeline_rejected",
        error.to_string(),
    )
}

fn pipeline_plan(pipeline: &PipelineIr) -> Result<PipelinePlanResponse, ApiError> {
    Ok(PipelinePlanResponse {
        schema_major: pipeline.schema.major,
        schema_minor: pipeline.schema.minor,
        semantic_digest: hex(&pipeline.semantic_digest().map_err(pipeline_rejected)?),
        parameters: parameter_schema(pipeline),
        stages: pipeline
            .stages
            .iter()
            .map(|stage| PipelineStagePlan {
                id: stage.id.clone(),
                name: stage.name.clone(),
                process_steps: stage
                    .steps
                    .iter()
                    .filter(|step| matches!(step, Step::Process(_)))
                    .count(),
                connector_intent_steps: stage
                    .steps
                    .iter()
                    .filter(|step| matches!(step, Step::ConnectorIntent(_)))
                    .count(),
            })
            .collect(),
    })
}

fn parameter_schema(pipeline: &PipelineIr) -> Value {
    Value::Object(
        pipeline
            .parameters
            .iter()
            .map(|(name, definition)| {
                let parameter_type = match definition.parameter_type {
                    ParameterType::Bool => "boolean",
                    ParameterType::Integer => "integer",
                    ParameterType::String => "string",
                };
                (
                    name.clone(),
                    json!({
                        "type": parameter_type,
                        "secret": definition.secret,
                        "has_default": definition.default.is_some(),
                    }),
                )
            })
            .collect(),
    )
}

fn expected_revision(headers: &HeaderMap) -> Result<i64, ApiError> {
    let Some(value) = headers.get(header::IF_MATCH) else {
        return Err(invalid_revision_precondition());
    };
    let value = value
        .to_str()
        .map_err(|_| invalid_revision_precondition())?;
    let value = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(invalid_revision_precondition)?;
    value
        .parse::<i64>()
        .ok()
        .filter(|revision| *revision >= 0)
        .ok_or_else(invalid_revision_precondition)
}

fn invalid_revision_precondition() -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        "invalid_revision_precondition",
        "If-Match is required and must be a quoted non-negative pipeline revision",
    )
}

fn page_limit(limit: Option<u32>) -> Result<u32, ApiError> {
    let limit = limit.unwrap_or(50);
    if limit == 0 || limit > mcloving_controller_store::MAX_PRODUCT_PAGE {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_page_limit",
            format!(
                "page limit must be between 1 and {}",
                mcloving_controller_store::MAX_PRODUCT_PAGE
            ),
        ));
    }
    Ok(limit)
}

fn discovery_child_page_limit(limit: Option<u32>) -> Result<u32, ApiError> {
    let limit = limit.unwrap_or(50);
    if limit == 0 || limit > mcloving_controller_store::MAX_DISCOVERY_CHILD_PAGE {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_discovery_page_limit",
            format!(
                "discovery child page limit must be between 1 and {}",
                mcloving_controller_store::MAX_DISCOVERY_CHILD_PAGE
            ),
        ));
    }
    Ok(limit)
}

fn parse_hex_digest_named(value: &str, kind: &'static str) -> Result<[u8; 32], ApiError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_digest",
            format!("{kind} SHA-256 must contain exactly 64 hexadecimal characters"),
        ));
    }
    let bytes = parse_hex_bytes(value, kind)?;
    bytes
        .try_into()
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid_digest", "invalid SHA-256"))
}

fn parse_lowercase_hex_digest_named(value: &str, kind: &'static str) -> Result<[u8; 32], ApiError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_digest",
            format!("{kind} SHA-256 must contain exactly 64 lowercase hexadecimal characters"),
        ));
    }
    parse_hex_digest_named(value, kind)
}

fn parse_hex_bytes(value: &str, kind: &'static str) -> Result<Vec<u8>, ApiError> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_hex",
            format!("{kind} must contain an even number of hexadecimal characters"),
        ));
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16).map_err(|_| {
                ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "invalid_hex",
                    format!("{kind} contains invalid hexadecimal data"),
                )
            })
        })
        .collect()
}

fn product_error(error: StoreError) -> ApiError {
    match error {
        StoreError::InvalidProductOperation(message) => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_product_operation",
            message,
        ),
        StoreError::InvalidAuditOperation(message) => {
            ApiError::new(StatusCode::BAD_REQUEST, "invalid_audit_operation", message)
        }
        StoreError::ProductConflict(message) => {
            ApiError::new(StatusCode::CONFLICT, "product_conflict", message)
        }
        other => internal(other),
    }
}

fn pipeline_state_error(error: StoreError) -> ApiError {
    match error {
        StoreError::InvalidPipelineState(message) => {
            ApiError::new(StatusCode::BAD_REQUEST, "invalid_pipeline_state", message)
        }
        StoreError::PipelineStateConflict(message) => {
            ApiError::new(StatusCode::CONFLICT, "pipeline_state_conflict", message)
        }
        other => internal(other),
    }
}

fn trigger_error(error: StoreError) -> ApiError {
    match error {
        StoreError::InvalidTriggerIngress(message) => {
            ApiError::new(StatusCode::BAD_REQUEST, "invalid_trigger_ingress", message)
        }
        StoreError::TriggerIngressConflict(message) => {
            ApiError::new(StatusCode::CONFLICT, "trigger_ingress_conflict", message)
        }
        StoreError::TriggerPaused {
            trigger_id,
            generation,
        } => ApiError::new(
            StatusCode::CONFLICT,
            "trigger_paused",
            format!("trigger {trigger_id} is paused at generation {generation}"),
        ),
        StoreError::PipelineDisabled {
            pipeline_id,
            generation,
        } => ApiError::new(
            StatusCode::CONFLICT,
            "pipeline_disabled",
            format!("pipeline {pipeline_id} is disabled at operational generation {generation}"),
        ),
        StoreError::PipelineStateConflict(message) => {
            ApiError::new(StatusCode::CONFLICT, "pipeline_state_conflict", message)
        }
        other => internal(other),
    }
}

fn discovery_error(error: StoreError) -> ApiError {
    match error {
        StoreError::InvalidDiscovery(message) => {
            ApiError::new(StatusCode::BAD_REQUEST, "invalid_discovery", message)
        }
        StoreError::DiscoveryConflict(message) => {
            ApiError::new(StatusCode::CONFLICT, "discovery_conflict", message)
        }
        StoreError::DiscoveryQuiesced {
            parent_id,
            generation,
        } => ApiError::new(
            StatusCode::CONFLICT,
            "discovery_quiesced",
            format!("discovery parent {parent_id} is quiesced at generation {generation}"),
        ),
        other => internal(other),
    }
}

fn admission_error(error: StoreError) -> ApiError {
    match error {
        StoreError::IdempotencyConflict(message) => {
            ApiError::new(StatusCode::CONFLICT, "idempotency_conflict", message)
        }
        StoreError::InvalidDag(message) => ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "pipeline_rejected",
            message,
        ),
        StoreError::PipelineDisabled {
            pipeline_id,
            generation,
        } => ApiError::new(
            StatusCode::CONFLICT,
            "pipeline_disabled",
            format!("pipeline {pipeline_id} is disabled at operational generation {generation}"),
        ),
        StoreError::PipelineStateConflict(message) => {
            ApiError::new(StatusCode::CONFLICT, "pipeline_state_conflict", message)
        }
        StoreError::InvalidPipelineState(message) => {
            ApiError::new(StatusCode::BAD_REQUEST, "invalid_pipeline_state", message)
        }
        other => internal(other),
    }
}

fn security_error(error: StoreError) -> ApiError {
    match error {
        StoreError::SecurityConflict(message) => {
            ApiError::new(StatusCode::CONFLICT, "security_conflict", message)
        }
        StoreError::InvalidSecurityOperation(message) => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_security_operation",
            message,
        ),
        other => internal(other),
    }
}

fn resource_not_found() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        "not_found",
        "the requested resource was not found",
    )
}

async fn status(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id, build_id)): Path<BuildPath>,
    headers: HeaderMap,
) -> Result<Json<BuildResponse>, ApiError> {
    authorize(
        &state,
        &headers,
        organization_id,
        Some(project_id),
        Action::ProjectView,
    )
    .await?;
    let snapshot = state
        .store
        .build_snapshot(organization_id, project_id, build_id)
        .await
        .map_err(internal)?
        .ok_or_else(not_found)?;
    let effects = state
        .store
        .effect_evidence_summaries(organization_id, snapshot.attempt_id)
        .await
        .map_err(internal)?
        .into_iter()
        .map(|effect| RuntimeEffectEvidenceResponse {
            fence: effect.fence,
            effect_key: effect.effect_key,
            effect_class: effect.effect_class,
            status: effect.status,
            payload_sha256: hex(&effect.payload_digest),
            outcome_receipt_sha256: effect.outcome_receipt_digest.map(|digest| hex(&digest)),
            reconciliation_receipt_sha256: effect
                .reconciliation_receipt_digest
                .map(|digest| hex(&digest)),
            observation_receipt_sha256: effect
                .observation_receipt_digest
                .map(|digest| hex(&digest)),
            shadow_replay_receipt_sha256: effect
                .shadow_replay_receipt_digest
                .map(|digest| hex(&digest)),
        })
        .collect();
    Ok(Json(BuildResponse {
        build_id: snapshot.build_id,
        node_id: snapshot.node_id,
        attempt_id: snapshot.attempt_id,
        status: snapshot.build_status,
        attempt_status: snapshot.attempt_status,
        fence: snapshot.fence,
        lease_owner: snapshot.lease_owner,
        cancellation_requested: snapshot.cancellation_requested,
        terminal_summary: snapshot.terminal_summary,
        effects,
    }))
}

async fn stage_artifact(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id, build_id)): Path<BuildPath>,
    headers: HeaderMap,
    content: Bytes,
) -> Result<(StatusCode, Json<StagedArtifactResponse>), ApiError> {
    authorize(
        &state,
        &headers,
        organization_id,
        Some(project_id),
        Action::ArtifactWrite,
    )
    .await?;
    require_build(&state, organization_id, project_id, build_id).await?;
    let name = bounded_header(
        &headers,
        ARTIFACT_NAME_HEADER,
        512,
        "artifact_name_required",
    )?;
    let media_type = bounded_header(
        &headers,
        header::CONTENT_TYPE.as_str(),
        255,
        "media_type_required",
    )?;
    if let Some(length) = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        && length != content.len() as u64
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "partial_upload",
            "received artifact bytes do not match Content-Length",
        ));
    }
    let object_store = object_store(&state)?;
    reap_abandoned_artifact_uploads(&state).await?;
    let staged = object_store
        .stage_artifact(&organization_id.to_string(), &content)
        .map_err(object_store_error)?
        .persist()
        .map_err(object_store_error)?;
    Ok((
        StatusCode::CREATED,
        Json(StagedArtifactResponse {
            upload_token: staged.token().to_owned(),
            name,
            media_type,
            sha256: hex(&staged.object_ref().sha256),
            bytes: staged.object_ref().bytes,
        }),
    ))
}

async fn reap_abandoned_artifact_uploads(state: &ApiState) -> Result<(), ApiError> {
    let object_store = object_store(state)?;
    let claims = {
        let mut cursor = state
            .publication_claim_cursor
            .lock()
            .map_err(|_| internal("publication-claim cursor lock is poisoned"))?;
        let claims = object_store
            .publication_claims_older_than(
                state.staged_upload_ttl,
                MAX_PUBLICATION_CLAIM_RECONCILIATION,
                cursor.as_deref(),
            )
            .map_err(object_store_error)?;
        if let Some(last) = claims.last() {
            *cursor = Some(last.token().to_owned());
        }
        claims
    };
    for claim in claims {
        let Some(organization_id) = publication_claim_organization_id(claim.token()) else {
            object_store
                .release_publication_claim(&claim, state.staged_upload_ttl)
                .map_err(object_store_error)?;
            continue;
        };
        let bytes = i64::try_from(claim.object_ref().bytes).map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "artifact_reconciliation_failed",
                "publication claim exceeds controller metadata bounds",
            )
        })?;
        if state
            .store
            .artifact_publication_claim_active(organization_id, claim.object_ref().sha256, bytes)
            .await
            .map_err(internal)?
        {
            continue;
        }
        object_store
            .release_publication_claim(&claim, state.staged_upload_ttl)
            .map_err(object_store_error)?;
    }
    object_store
        .reap_staged_older_than(state.staged_upload_ttl)
        .map_err(object_store_error)?;
    Ok(())
}

fn publication_claim_organization_id(token: &str) -> Option<Uuid> {
    let prefix = token.get(..36)?;
    if token.as_bytes().get(36) != Some(&b'-') {
        return None;
    }
    Uuid::parse_str(prefix).ok()
}

async fn commit_artifact(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id, build_id, upload_token)): Path<(Uuid, Uuid, Uuid, String)>,
    headers: HeaderMap,
    Json(request): Json<ArtifactCommitRequest>,
) -> Result<(StatusCode, Json<ArtifactResponse>), ApiError> {
    authorize(
        &state,
        &headers,
        organization_id,
        Some(project_id),
        Action::ArtifactWrite,
    )
    .await?;
    authorize_artifact_agent(&state, &headers, &request.agent_id)?;
    require_build(&state, organization_id, project_id, build_id).await?;
    if !upload_token.starts_with(&format!("{organization_id}-")) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "upload_tenant_mismatch",
            "artifact upload token does not belong to this tenant",
        ));
    }
    validate_artifact_retention(request.retention_seconds)?;
    let digest = parse_hex_digest(&request.sha256)?;
    let pending = PendingObject::from_parts(
        upload_token,
        ObjectRef {
            sha256: digest,
            bytes: request.bytes,
        },
    )
    .map_err(object_store_error)?;
    let pending = object_store(&state)?
        .claim_pending(&pending)
        .map_err(object_store_error)?;
    object_store(&state)?
        .verify_pending(&pending)
        .map_err(object_store_error)?;
    let bytes = i64::try_from(request.bytes).map_err(|_| {
        ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "artifact_too_large",
            "artifact byte count exceeds controller metadata bounds",
        )
    })?;
    let registered = state
        .store
        .register_artifact(
            organization_id,
            build_id,
            request.node_id,
            request.attempt_id,
            request.fence,
            request.restore_epoch,
            &request.agent_id,
            &request.name,
            digest,
            bytes,
            &request.media_type,
            request.retention_seconds,
        )
        .await
        .map_err(internal)?;
    if !registered {
        object_store(&state)?
            .abort_pending(&pending)
            .map_err(object_store_error)?;
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "artifact_authority_rejected",
            "artifact metadata did not match live fenced execution authority",
        ));
    }
    let committed = object_store(&state)?
        .commit_pending(pending)
        .map_err(object_store_error)?;
    if committed.sha256 != digest || committed.bytes != request.bytes {
        return Err(ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "artifact_publication_mismatch",
            "published artifact identity differs from its verified reservation",
        ));
    }
    let available = state
        .store
        .mark_artifact_available(
            organization_id,
            build_id,
            request.node_id,
            request.attempt_id,
            request.fence,
            &request.name,
            digest,
            bytes,
            &request.media_type,
            request.retention_seconds,
        )
        .await
        .map_err(internal)?;
    if !available {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "artifact_publication_rejected",
            "published artifact does not match its reserved metadata",
        ));
    }
    let artifact = find_artifact(
        &state,
        organization_id,
        project_id,
        build_id,
        request.attempt_id,
        &request.name,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(artifact_response(artifact)?)))
}

async fn list_artifacts(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id, build_id)): Path<BuildPath>,
    headers: HeaderMap,
) -> Result<Json<Vec<ArtifactResponse>>, ApiError> {
    authorize(
        &state,
        &headers,
        organization_id,
        Some(project_id),
        Action::ArtifactRead,
    )
    .await?;
    require_build(&state, organization_id, project_id, build_id).await?;
    let artifacts = state
        .store
        .build_artifacts(organization_id, project_id, build_id)
        .await
        .map_err(internal)?
        .into_iter()
        .map(artifact_response)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(artifacts))
}

async fn artifact_metadata(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id, build_id)): Path<BuildPath>,
    Query(query): Query<ArtifactQuery>,
    headers: HeaderMap,
) -> Result<Json<ArtifactResponse>, ApiError> {
    authorize(
        &state,
        &headers,
        organization_id,
        Some(project_id),
        Action::ArtifactRead,
    )
    .await?;
    require_build(&state, organization_id, project_id, build_id).await?;
    let artifact = find_artifact(
        &state,
        organization_id,
        project_id,
        build_id,
        query.attempt_id,
        &query.name,
    )
    .await?;
    Ok(Json(artifact_response(artifact)?))
}

async fn download_artifact(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id, build_id)): Path<BuildPath>,
    Query(query): Query<ArtifactQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    authorize(
        &state,
        &headers,
        organization_id,
        Some(project_id),
        Action::ArtifactRead,
    )
    .await?;
    require_build(&state, organization_id, project_id, build_id).await?;
    let artifact = find_artifact(
        &state,
        organization_id,
        project_id,
        build_id,
        query.attempt_id,
        &query.name,
    )
    .await?;
    if artifact.status == ObjectStatus::Pending {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "artifact_not_available",
            "artifact publication has not completed",
        ));
    }
    let reference = ObjectRef {
        sha256: artifact.digest,
        bytes: u64::try_from(artifact.bytes).map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid_artifact_metadata",
                "stored artifact byte count is invalid",
            )
        })?,
    };
    let content = match object_store(&state)?.read_verified(&reference) {
        Ok(content) => content,
        Err(gap) => {
            let status = match gap {
                ObjectGap::Missing { .. } => ObjectStatus::Missing,
                ObjectGap::Corrupt { .. } => ObjectStatus::Corrupt,
            };
            state
                .store
                .set_object_status(
                    organization_id,
                    artifact.attempt_id,
                    artifact.fence,
                    ObjectKind::Artifact,
                    &artifact.name,
                    artifact.digest,
                    status,
                )
                .await
                .map_err(internal)?;
            return Err(ApiError::new(
                StatusCode::GONE,
                "artifact_gap",
                "artifact bytes are missing or corrupt",
            ));
        }
    };
    if artifact.status != ObjectStatus::Available {
        let restored = state
            .store
            .set_object_status(
                organization_id,
                artifact.attempt_id,
                artifact.fence,
                ObjectKind::Artifact,
                &artifact.name,
                artifact.digest,
                ObjectStatus::Available,
            )
            .await
            .map_err(internal)?;
        if !restored {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "artifact_restore_raced",
                "restored artifact metadata changed during verification",
            ));
        }
    }
    let mut response = Response::new(content.into());
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&artifact.media_type).map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid_artifact_metadata",
                "stored media type is not a valid HTTP header",
            )
        })?,
    );
    response.headers_mut().insert(
        "mcloving-artifact-sha256",
        HeaderValue::from_str(&hex(&artifact.digest)).expect("hex digest is a valid header"),
    );
    Ok(response)
}

async fn logs(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id, build_id)): Path<BuildPath>,
    Query(query): Query<LogQuery>,
    headers: HeaderMap,
) -> Result<Json<LogPage>, ApiError> {
    authorize(
        &state,
        &headers,
        organization_id,
        Some(project_id),
        Action::LogRead,
    )
    .await?;
    if state
        .store
        .build_snapshot(organization_id, project_id, build_id)
        .await
        .map_err(internal)?
        .is_none()
    {
        return Err(not_found());
    }
    let limit = query.limit.unwrap_or(200);
    if limit == 0 || limit > 1_000 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_log_page",
            "log page limit must be between 1 and 1000",
        ));
    }
    let fetch_limit = limit.checked_add(1).unwrap_or(limit);
    let mut logs = state
        .store
        .build_logs_page(
            organization_id,
            project_id,
            build_id,
            query.after_attempt_id,
            query.after_fence,
            query.after_sequence,
            query.after_stream.as_deref(),
            fetch_limit,
        )
        .await
        .map_err(product_error)?;
    let next_after = if logs.len() > limit as usize {
        logs.truncate(limit as usize);
        logs.last().map(|entry| LogCursor {
            attempt_id: entry.attempt_id,
            fence: entry.fence,
            sequence: entry.sequence,
            stream: entry.stream.clone(),
        })
    } else {
        None
    };
    let items = logs
        .into_iter()
        .map(|entry| {
            let (text, content_hex) = encode_log_content(&entry.content);
            LogResponse {
                attempt_id: entry.attempt_id,
                fence: entry.fence,
                sequence: entry.sequence,
                stream: entry.stream,
                text,
                content_hex,
                sha256: hex(&entry.digest),
            }
        })
        .collect();
    Ok(Json(LogPage { items, next_after }))
}

async fn cancel(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id, build_id)): Path<BuildPath>,
    headers: HeaderMap,
) -> Result<Json<CancellationResponse>, ApiError> {
    let principal = authorize(
        &state,
        &headers,
        organization_id,
        Some(project_id),
        Action::BuildCancel,
    )
    .await?;
    let decision = state
        .store
        .request_cancellation_decision_as(organization_id, project_id, build_id, &principal.subject)
        .await
        .map_err(internal)?;
    match decision {
        CancellationDecision::Accepted => Ok(Json(CancellationResponse {
            accepted: true,
            reason: None,
        })),
        CancellationDecision::AlreadyRequested => Ok(Json(CancellationResponse {
            accepted: false,
            reason: Some("cancellation was already requested for this build".to_owned()),
        })),
        CancellationDecision::NotCancellable { build_status } => {
            Err(cancellation_refusal(build_id, build_status))
        }
    }
}

/// Names the exact reason a build cannot be cancelled. A build parked in
/// `reconciliation_required` in particular is refused with its state and the
/// operator resolution path rather than a bare conflict.
fn cancellation_refusal(build_id: Uuid, build_status: Option<String>) -> ApiError {
    match build_status.as_deref() {
        Some("reconciliation_required") => ApiError::new(
            StatusCode::CONFLICT,
            "build_reconciliation_required",
            format!(
                "build {build_id} is parked in reconciliation_required: a recovered agent \
                 attempt is awaiting operator reconciliation, and cancellation cannot \
                 discharge it; confirm the attempt's uncertain effects and then retry the \
                 attempt or finalize the reconciliation, after which the owning agent \
                 discharges its recovered journal record and resumes polling (see \
                 docs/architecture/AGENT_RUNTIME.md, \"Recovered-attempt discharge\")"
            ),
        ),
        Some(status) => ApiError::new(
            StatusCode::CONFLICT,
            "build_not_cancellable",
            format!("build {build_id} is {status} and can no longer be cancelled"),
        ),
        None => ApiError::new(
            StatusCode::NOT_FOUND,
            "build_not_found",
            format!("build {build_id} was not found in this project"),
        ),
    }
}

async fn retry_attempt(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id, build_id, attempt_id)): Path<(Uuid, Uuid, Uuid, Uuid)>,
    headers: HeaderMap,
    Json(request): Json<RetryRequest>,
) -> Result<Json<RetryResponse>, ApiError> {
    let principal = authorize(
        &state,
        &headers,
        organization_id,
        Some(project_id),
        Action::BuildRetry,
    )
    .await?;
    let graph = state
        .store
        .build_graph(organization_id, project_id, build_id)
        .await
        .map_err(product_error)?
        .ok_or_else(resource_not_found)?;
    if !graph
        .attempts
        .iter()
        .any(|attempt| attempt.attempt_id == attempt_id)
    {
        return Err(resource_not_found());
    }
    let response = match state
        .store
        .schedule_retry_as(
            organization_id,
            attempt_id,
            request.max_attempts,
            &request.reason,
            &principal.subject,
        )
        .await
        .map_err(product_error)?
    {
        RetryDecision::Scheduled {
            attempt_id,
            ordinal,
            created,
        } => RetryResponse::Scheduled {
            attempt_id,
            ordinal,
            created,
        },
        RetryDecision::DeadLettered => RetryResponse::DeadLettered,
        RetryDecision::Ineligible => RetryResponse::Ineligible,
    };
    Ok(Json(response))
}

#[derive(Deserialize)]
struct ExplainQuery {
    #[serde(default)]
    capability: Option<String>,
    #[serde(default = "default_trust_pool")]
    trust_pool: String,
}

fn default_trust_pool() -> String {
    DEFAULT_TRUST_POOL.to_owned()
}

async fn explain(
    State(state): State<Arc<ApiState>>,
    Path(organization_id): Path<Uuid>,
    Query(query): Query<ExplainQuery>,
    headers: HeaderMap,
) -> Result<Json<ExplainResponse>, ApiError> {
    authorize(
        &state,
        &headers,
        organization_id,
        None,
        Action::SchedulerControl,
    )
    .await?;
    let response = match state
        .store
        .explain_wait(
            organization_id,
            &query
                .capability
                .as_deref()
                .unwrap_or_default()
                .split(',')
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>(),
            &query.trust_pool,
        )
        .await
        .map_err(explain_error)?
    {
        WaitReason::Ready => ExplainResponse::Ready,
        WaitReason::NoQueuedWork => ExplainResponse::NoQueuedWork,
        WaitReason::TrustPoolMismatch { required, offered } => {
            ExplainResponse::TrustPoolMismatch { required, offered }
        }
        WaitReason::CapabilityMismatch { required, missing } => {
            ExplainResponse::CapabilityMismatch {
                required: required.into_iter().collect(),
                missing: missing.into_iter().collect(),
            }
        }
    };
    Ok(Json(response))
}

async fn require_build(
    state: &ApiState,
    organization_id: Uuid,
    project_id: Uuid,
    build_id: Uuid,
) -> Result<(), ApiError> {
    if state
        .store
        .build_snapshot(organization_id, project_id, build_id)
        .await
        .map_err(internal)?
        .is_none()
    {
        return Err(not_found());
    }
    Ok(())
}

fn object_store(state: &ApiState) -> Result<&FilesystemObjectStore, ApiError> {
    state.object_store.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "artifact_store_unavailable",
            "artifact storage is not configured",
        )
    })
}

fn bounded_header(
    headers: &HeaderMap,
    name: &str,
    max_bytes: usize,
    code: &'static str,
) -> Result<String, ApiError> {
    let value = headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            !value.is_empty()
                && value.len() <= max_bytes
                && value.trim() == *value
                && !value.chars().any(char::is_control)
        })
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                code,
                format!("{name} must be non-empty, canonical, and bounded"),
            )
        })?;
    Ok(value.to_owned())
}

async fn find_artifact(
    state: &ApiState,
    organization_id: Uuid,
    project_id: Uuid,
    build_id: Uuid,
    attempt_id: Uuid,
    name: &str,
) -> Result<ArtifactMetadata, ApiError> {
    state
        .store
        .build_artifacts(organization_id, project_id, build_id)
        .await
        .map_err(internal)?
        .into_iter()
        .find(|artifact| artifact.attempt_id == attempt_id && artifact.name == name)
        .ok_or_else(not_found)
}

fn artifact_response(artifact: ArtifactMetadata) -> Result<ArtifactResponse, ApiError> {
    Ok(ArtifactResponse {
        build_id: artifact.build_id,
        node_id: artifact.node_id,
        attempt_id: artifact.attempt_id,
        fence: artifact.fence,
        name: artifact.name,
        sha256: hex(&artifact.digest),
        bytes: u64::try_from(artifact.bytes).map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid_artifact_metadata",
                "stored artifact byte count is invalid",
            )
        })?,
        media_type: artifact.media_type,
        status: match artifact.status {
            ObjectStatus::Pending => "pending",
            ObjectStatus::Available => "available",
            ObjectStatus::Missing => "missing",
            ObjectStatus::Corrupt => "corrupt",
        }
        .to_owned(),
    })
}

fn parse_hex_digest(value: &str) -> Result<[u8; 32], ApiError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_artifact_digest",
            "artifact SHA-256 must contain exactly 64 hexadecimal characters",
        ));
    }
    let mut digest = [0_u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|_| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "invalid_artifact_digest",
                "artifact SHA-256 is invalid",
            )
        })?;
    }
    Ok(digest)
}

fn validate_artifact_retention(retention_seconds: i64) -> Result<(), ApiError> {
    if !(0..=MAX_OBJECT_RETENTION_SECONDS).contains(&retention_seconds) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "artifact_retention_out_of_range",
            format!(
                "artifact retention must be between zero and \
                 {MAX_OBJECT_RETENTION_SECONDS} seconds"
            ),
        ));
    }
    Ok(())
}

fn object_store_error(error: ObjectStoreError) -> ApiError {
    match error {
        ObjectStoreError::ObjectQuotaExceeded => ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "artifact_object_quota",
            error.to_string(),
        ),
        ObjectStoreError::TotalQuotaExceeded => ApiError::new(
            StatusCode::INSUFFICIENT_STORAGE,
            "artifact_total_quota",
            error.to_string(),
        ),
        ObjectStoreError::StagedObjectQuotaExceeded => ApiError::new(
            StatusCode::INSUFFICIENT_STORAGE,
            "artifact_staged_object_quota",
            error.to_string(),
        ),
        ObjectStoreError::ForeignStagingPath
        | ObjectStoreError::CorruptStagedObject
        | ObjectStoreError::ImmutableObjectConflict => ApiError::new(
            StatusCode::CONFLICT,
            "artifact_integrity",
            error.to_string(),
        ),
        _ => internal(error),
    }
}

async fn authorize(
    state: &ApiState,
    headers: &HeaderMap,
    organization_id: Uuid,
    project_id: Option<Uuid>,
    action: Action,
) -> Result<Principal, ApiError> {
    let principal = authenticate_principal(state, headers, organization_id).await?;
    authorize_principal(&principal, organization_id, project_id, action)
        .map_err(|error| ApiError::new(StatusCode::FORBIDDEN, "forbidden", error.to_string()))?;
    Ok(principal)
}

async fn authenticate_principal(
    state: &ApiState,
    headers: &HeaderMap,
    organization_id: Uuid,
) -> Result<Principal, ApiError> {
    let supplied: [u8; 32] = bearer_token(headers)
        .map(|token| Sha256::digest(token.as_bytes()).into())
        .ok_or_else(unauthorized)?;
    match &state.authentication {
        Authentication::Static(credentials) => credentials
            .iter()
            .find(|credential| constant_time_eq(&supplied, &credential.token_digest))
            .map(|credential| credential.principal.clone())
            .ok_or_else(unauthorized),
        Authentication::Durable => state
            .store
            .authenticate_api_token(organization_id, supplied, unix_time_ms())
            .await
            .map(|authenticated| authenticated.principal)
            .map_err(|_| unauthorized()),
    }
}

fn authorize_artifact_agent(
    state: &ApiState,
    headers: &HeaderMap,
    requested_agent_id: &str,
) -> Result<(), ApiError> {
    let supplied = header_bearer_token(headers, ARTIFACT_AGENT_AUTHORIZATION_HEADER)
        .map(|token| Sha256::digest(token.as_bytes()))
        .ok_or_else(unauthorized)?;
    let credential = state
        .artifact_agents
        .iter()
        .find(|credential| constant_time_eq(supplied.as_slice(), &credential.token_digest))
        .ok_or_else(unauthorized)?;
    if credential.agent_id != requested_agent_id {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "agent_identity_mismatch",
            "artifact agent identity does not match its authenticated bearer",
        ));
    }
    Ok(())
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    header_bearer_token(headers, "authorization")
}

fn unix_time_ms() -> i64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    i64::try_from(millis).unwrap_or(i64::MAX)
}

fn header_bearer_token<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let value = headers.get(name)?.to_str().ok()?;
    let mut fields = value.split_ascii_whitespace();
    let scheme = fields.next()?;
    let token = fields.next()?;
    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() || fields.next().is_some() {
        return None;
    }
    Some(token)
}

fn validate_bearer_secret(bearer_token: &str) -> Result<(), ApiError> {
    if bearer_token.len() < 32 {
        return Err(ApiError::configuration(
            "bearer token must contain at least 32 bytes",
        ));
    }
    Ok(())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn unauthorized() -> ApiError {
    ApiError::new(
        StatusCode::UNAUTHORIZED,
        "unauthorized",
        "a valid bearer token is required",
    )
}

fn not_found() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "not_found", "build was not found")
}

fn explain_error(error: StoreError) -> ApiError {
    if matches!(error, StoreError::InvalidTrustPool) {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_trust_pool",
            "trust_pool must be non-empty and contain no surrounding whitespace",
        )
    } else {
        internal(error)
    }
}

fn internal(error: impl std::fmt::Display) -> ApiError {
    eprintln!("public API request failed internally: {error}");
    ApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal",
        "internal server error",
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn encode_log_content(content: &[u8]) -> (Option<String>, String) {
    (
        std::str::from_utf8(content).ok().map(str::to_owned),
        hex(content),
    )
}

#[derive(Clone)]
pub struct Client {
    base_url: String,
    bearer_token: String,
    artifact_agent_token: Option<String>,
    inner: reqwest::Client,
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("controller returned HTTP {status}: {body}")]
    Response { status: StatusCode, body: String },
}

impl Client {
    pub fn new(base_url: &str, bearer_token: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            bearer_token: bearer_token.to_owned(),
            artifact_agent_token: None,
            inner: reqwest::Client::new(),
        }
    }

    pub fn with_artifact_agent_token(mut self, bearer_token: &str) -> Self {
        self.artifact_agent_token = Some(bearer_token.to_owned());
        self
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn submit_pipeline_on_platform_in_pool(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        pipeline_id: Uuid,
        idempotency_key: &str,
        platform: &str,
        trust_pool: &str,
        request: &PipelineBuildRequest,
    ) -> Result<AdmissionResponse, ClientError> {
        self.send(
            self.inner
                .post(format!(
                    "{}/pipelines/{pipeline_id}/builds",
                    self.project_url(organization_id, project_id)
                ))
                .header(IDEMPOTENCY_HEADER, idempotency_key)
                .header(PLATFORM_HEADER, platform)
                .header(TRUST_POOL_HEADER, trust_pool)
                .json(request),
        )
        .await
    }

    pub async fn pipeline_operational_state(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        pipeline_id: Uuid,
    ) -> Result<PipelineOperationalStateRecord, ClientError> {
        self.send(self.inner.get(format!(
            "{}/pipelines/{pipeline_id}/state",
            self.project_url(organization_id, project_id)
        )))
        .await
    }

    pub async fn transition_pipeline_operational_state(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        pipeline_id: Uuid,
        expected_generation: i64,
        idempotency_key: &str,
        request: &PipelineOperationalStateRequest,
    ) -> Result<PipelineOperationalStateRecord, ClientError> {
        self.send(
            self.inner
                .put(format!(
                    "{}/pipelines/{pipeline_id}/state",
                    self.project_url(organization_id, project_id)
                ))
                .header(header::IF_MATCH, format!("\"{expected_generation}\""))
                .header(IDEMPOTENCY_HEADER, idempotency_key)
                .json(request),
        )
        .await
    }

    pub async fn validate_pipeline(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        request: &SubmissionRequest,
    ) -> Result<ValidationResponse, ClientError> {
        self.send(
            self.inner
                .post(format!(
                    "{}/pipelines/validate",
                    self.project_url(organization_id, project_id)
                ))
                .json(request),
        )
        .await
    }

    pub async fn plan_pipeline(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        request: &SubmissionRequest,
    ) -> Result<PipelinePlanResponse, ClientError> {
        self.send(
            self.inner
                .post(format!(
                    "{}/pipelines/plan",
                    self.project_url(organization_id, project_id)
                ))
                .json(request),
        )
        .await
    }

    pub async fn put_pipeline(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        pipeline_id: Uuid,
        expected_revision: i64,
        request: &PipelineUpsertRequest,
    ) -> Result<PipelineRecord, ClientError> {
        self.send(
            self.inner
                .put(format!(
                    "{}/pipelines/{pipeline_id}",
                    self.project_url(organization_id, project_id)
                ))
                .header(header::IF_MATCH, format!("\"{expected_revision}\""))
                .json(request),
        )
        .await
    }

    pub async fn pipeline(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        pipeline_id: Uuid,
    ) -> Result<PipelineRecord, ClientError> {
        self.send(self.inner.get(format!(
            "{}/pipelines/{pipeline_id}",
            self.project_url(organization_id, project_id)
        )))
        .await
    }

    pub async fn pipelines(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        after: Option<&str>,
        limit: Option<u32>,
    ) -> Result<PipelinePage, ClientError> {
        let mut request = self.inner.get(format!(
            "{}/pipelines",
            self.project_url(organization_id, project_id)
        ));
        if let Some(after) = after {
            request = request.query(&[("after", after)]);
        }
        if let Some(limit) = limit {
            request = request.query(&[("limit", limit)]);
        }
        self.send(request).await
    }

    pub async fn put_component(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        digest: &str,
        request: &ComponentUpsertRequest,
    ) -> Result<Value, ClientError> {
        self.send(
            self.inner
                .put(format!(
                    "{}/components/{digest}",
                    self.project_url(organization_id, project_id)
                ))
                .json(request),
        )
        .await
    }

    pub async fn component(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        digest: &str,
    ) -> Result<ComponentRecord, ClientError> {
        self.send(self.inner.get(format!(
            "{}/components/{digest}",
            self.project_url(organization_id, project_id)
        )))
        .await
    }

    pub async fn components(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        after: Option<&ComponentCursor>,
        limit: Option<u32>,
    ) -> Result<ComponentPage, ClientError> {
        let mut request = self.inner.get(format!(
            "{}/components",
            self.project_url(organization_id, project_id)
        ));
        if let Some(after) = after {
            request = request.query(&[
                ("after", after.name.clone()),
                ("after_digest", hex(&after.digest)),
            ]);
        }
        if let Some(limit) = limit {
            request = request.query(&[("limit", limit)]);
        }
        self.send(request).await
    }

    pub async fn builds(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        after: Option<BuildCursor>,
        status: Option<&str>,
        limit: Option<u32>,
    ) -> Result<BuildPage, ClientError> {
        let mut request = self.inner.get(self.builds_url(organization_id, project_id));
        if let Some(after) = after {
            request = request.query(&[
                (
                    "after_created_micros",
                    after.created_at_unix_micros.to_string(),
                ),
                ("after_id", after.build_id.to_string()),
            ]);
        }
        if let Some(status) = status {
            request = request.query(&[("status", status)]);
        }
        if let Some(limit) = limit {
            request = request.query(&[("limit", limit)]);
        }
        self.send(request).await
    }

    pub async fn status(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        build_id: Uuid,
    ) -> Result<BuildResponse, ClientError> {
        self.send(
            self.inner
                .get(self.build_url(organization_id, project_id, build_id)),
        )
        .await
    }

    pub async fn build_graph(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        build_id: Uuid,
    ) -> Result<BuildGraph, ClientError> {
        self.send(self.inner.get(format!(
            "{}/graph",
            self.build_url(organization_id, project_id, build_id)
        )))
        .await
    }

    pub async fn approvals(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        build_id: Uuid,
    ) -> Result<Vec<ApprovalView>, ClientError> {
        self.send(self.inner.get(format!(
            "{}/approvals",
            self.build_url(organization_id, project_id, build_id)
        )))
        .await
    }

    pub async fn approve(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        build_id: Uuid,
        request: &ApprovalRequest,
    ) -> Result<Value, ClientError> {
        self.send(
            self.inner
                .post(format!(
                    "{}/approvals",
                    self.build_url(organization_id, project_id, build_id)
                ))
                .json(request),
        )
        .await
    }

    pub async fn credential_grants(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        build_id: Uuid,
    ) -> Result<Vec<CredentialGrantView>, ClientError> {
        self.send(self.inner.get(format!(
            "{}/credential-grants",
            self.build_url(organization_id, project_id, build_id)
        )))
        .await
    }

    pub async fn test_reports(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        build_id: Uuid,
    ) -> Result<Vec<TestReportView>, ClientError> {
        self.send(self.inner.get(format!(
            "{}/tests",
            self.build_url(organization_id, project_id, build_id)
        )))
        .await
    }

    pub async fn audit(
        &self,
        organization_id: Uuid,
        after_sequence: Option<i64>,
        limit: Option<u32>,
    ) -> Result<AuditPage, ClientError> {
        let mut request = self.inner.get(format!(
            "{}/api/v1/organizations/{organization_id}/audit",
            self.base_url
        ));
        if let Some(after_sequence) = after_sequence {
            request = request.query(&[("after_sequence", after_sequence)]);
        }
        if let Some(limit) = limit {
            request = request.query(&[("limit", limit)]);
        }
        self.send(request).await
    }

    pub async fn logs(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        build_id: Uuid,
    ) -> Result<Vec<LogResponse>, ClientError> {
        let mut items = Vec::new();
        let mut after = None;
        loop {
            let page = self
                .logs_page(
                    organization_id,
                    project_id,
                    build_id,
                    after.as_ref(),
                    Some(1_000),
                )
                .await?;
            items.extend(page.items);
            let Some(next_after) = page.next_after else {
                return Ok(items);
            };
            after = Some(next_after);
        }
    }

    pub async fn logs_page(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        build_id: Uuid,
        after: Option<&LogCursor>,
        limit: Option<u32>,
    ) -> Result<LogPage, ClientError> {
        let mut request = self.inner.get(format!(
            "{}/logs",
            self.build_url(organization_id, project_id, build_id)
        ));
        if let Some(after) = after {
            request = request.query(&[
                ("after_attempt_id", after.attempt_id.to_string()),
                ("after_fence", after.fence.to_string()),
                ("after_sequence", after.sequence.to_string()),
                ("after_stream", after.stream.clone()),
            ]);
        }
        if let Some(limit) = limit {
            request = request.query(&[("limit", limit)]);
        }
        self.send(request).await
    }

    pub async fn cancel(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        build_id: Uuid,
    ) -> Result<CancellationResponse, ClientError> {
        self.send(self.inner.post(format!(
            "{}/cancel",
            self.build_url(organization_id, project_id, build_id)
        )))
        .await
    }

    pub async fn retry(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        build_id: Uuid,
        attempt_id: Uuid,
        request: &RetryRequest,
    ) -> Result<RetryResponse, ClientError> {
        self.send(
            self.inner
                .post(format!(
                    "{}/attempts/{attempt_id}/retry",
                    self.build_url(organization_id, project_id, build_id)
                ))
                .json(request),
        )
        .await
    }

    pub async fn stage_artifact(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        build_id: Uuid,
        name: &str,
        media_type: &str,
        content: Vec<u8>,
    ) -> Result<StagedArtifactResponse, ClientError> {
        self.send(
            self.inner
                .post(format!(
                    "{}/artifact-uploads",
                    self.build_url(organization_id, project_id, build_id)
                ))
                .header(ARTIFACT_NAME_HEADER, name)
                .header(header::CONTENT_TYPE, media_type)
                .body(content),
        )
        .await
    }

    pub async fn commit_artifact(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        build_id: Uuid,
        upload_token: &str,
        request: &ArtifactCommitRequest,
    ) -> Result<ArtifactResponse, ClientError> {
        let mut http_request = self
            .inner
            .post(format!(
                "{}/artifact-uploads/{upload_token}/commit",
                self.build_url(organization_id, project_id, build_id)
            ))
            .json(request);
        if let Some(token) = &self.artifact_agent_token {
            http_request = http_request.header(
                ARTIFACT_AGENT_AUTHORIZATION_HEADER,
                format!("Bearer {token}"),
            );
        }
        self.send(http_request).await
    }

    pub async fn artifacts(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        build_id: Uuid,
    ) -> Result<Vec<ArtifactResponse>, ClientError> {
        self.send(self.inner.get(format!(
            "{}/artifacts",
            self.build_url(organization_id, project_id, build_id)
        )))
        .await
    }

    pub async fn artifact_metadata(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        build_id: Uuid,
        attempt_id: Uuid,
        name: &str,
    ) -> Result<ArtifactResponse, ClientError> {
        self.send(
            self.inner
                .get(format!(
                    "{}/artifacts/metadata",
                    self.build_url(organization_id, project_id, build_id)
                ))
                .query(&[
                    ("attempt_id", attempt_id.to_string()),
                    ("name", name.to_owned()),
                ]),
        )
        .await
    }

    pub async fn download_artifact(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        build_id: Uuid,
        attempt_id: Uuid,
        name: &str,
    ) -> Result<Vec<u8>, ClientError> {
        let response = self
            .inner
            .get(format!(
                "{}/artifacts/content",
                self.build_url(organization_id, project_id, build_id)
            ))
            .query(&[
                ("attempt_id", attempt_id.to_string()),
                ("name", name.to_owned()),
            ])
            .bearer_auth(&self.bearer_token)
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            return Err(ClientError::Response {
                status,
                body: response.text().await?,
            });
        }
        Ok(response.bytes().await?.to_vec())
    }

    pub async fn explain(
        &self,
        organization_id: Uuid,
        capabilities: &[String],
    ) -> Result<ExplainResponse, ClientError> {
        self.explain_in_pool(organization_id, capabilities, DEFAULT_TRUST_POOL)
            .await
    }

    pub async fn explain_in_pool(
        &self,
        organization_id: Uuid,
        capabilities: &[String],
        trust_pool: &str,
    ) -> Result<ExplainResponse, ClientError> {
        let request = self.inner.get(format!(
            "{}/api/v1/organizations/{organization_id}/scheduler/explain",
            self.base_url
        ));
        let joined = capabilities.join(",");
        let request = request.query(&[
            ("capability", joined),
            ("trust_pool", trust_pool.to_owned()),
        ]);
        self.send(request).await
    }

    async fn send<T: for<'de> Deserialize<'de>>(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<T, ClientError> {
        let response = request.bearer_auth(&self.bearer_token).send().await?;
        let status = response.status();
        if !status.is_success() {
            return Err(ClientError::Response {
                status,
                body: response.text().await?,
            });
        }
        Ok(response.json().await?)
    }

    fn build_url(&self, organization_id: Uuid, project_id: Uuid, build_id: Uuid) -> String {
        format!(
            "{}/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}",
            self.base_url
        )
    }

    fn project_url(&self, organization_id: Uuid, project_id: Uuid) -> String {
        format!(
            "{}/api/v1/organizations/{organization_id}/projects/{project_id}",
            self.base_url
        )
    }

    fn builds_url(&self, organization_id: Uuid, project_id: Uuid) -> String {
        format!("{}/builds", self.project_url(organization_id, project_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn token_comparison_is_exact() {
        assert!(constant_time_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2, 4]));
        assert!(!constant_time_eq(&[1, 2], &[1, 2, 0]));
    }

    #[test]
    fn cancellation_refusals_name_their_exact_reason() {
        let build_id = Uuid::from_u128(0x1234);

        let parked = cancellation_refusal(build_id, Some("reconciliation_required".to_owned()));
        assert_eq!(parked.status, StatusCode::CONFLICT);
        assert_eq!(parked.code, "build_reconciliation_required");
        assert!(parked.message.contains("reconciliation_required"));
        assert!(
            parked
                .message
                .contains("recovered agent attempt is awaiting operator reconciliation")
        );
        assert!(parked.message.contains("AGENT_RUNTIME.md"));

        let terminal = cancellation_refusal(build_id, Some("succeeded".to_owned()));
        assert_eq!(terminal.status, StatusCode::CONFLICT);
        assert_eq!(terminal.code, "build_not_cancellable");
        assert!(terminal.message.contains("succeeded"));

        let missing = cancellation_refusal(build_id, None);
        assert_eq!(missing.status, StatusCode::NOT_FOUND);
        assert_eq!(missing.code, "build_not_found");
    }

    #[tokio::test]
    async fn bearer_tokens_resolve_distinct_approval_subjects() {
        let organization_id = Uuid::new_v4();
        let project_id = Uuid::new_v4();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
            .expect("construct lazy pool");
        let service = Principal {
            subject: "service:api".to_owned(),
            kind: mcloving_controller_store::authz::PrincipalKind::Service,
            organization_id,
            project_roles: BTreeMap::new(),
            service_scopes: [mcloving_controller_store::authz::ServiceScope::ProjectAdmin].into(),
            mapped_projects: BTreeSet::new(),
            action_grants: BTreeMap::new(),
        };
        let human = Principal {
            subject: "oidc:alice".to_owned(),
            kind: mcloving_controller_store::authz::PrincipalKind::Human,
            organization_id,
            project_roles: [(
                project_id,
                mcloving_controller_store::authz::ProjectRole::Admin,
            )]
            .into(),
            service_scopes: BTreeSet::new(),
            mapped_projects: BTreeSet::new(),
            action_grants: BTreeMap::new(),
        };
        let state = ApiState::new(
            Store::new(pool),
            "service-api-principal-token-32-bytes",
            service,
        )
        .unwrap()
        .with_bearer_principal("alice-human-principal-token-32-bytes", human)
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer alice-human-principal-token-32-bytes"
                .parse()
                .unwrap(),
        );
        let resolved = authorize(
            &state,
            &headers,
            organization_id,
            Some(project_id),
            Action::ProjectConfigure,
        )
        .await
        .expect("human principal is independently authenticated");
        assert_eq!(resolved.subject, "oidc:alice");
    }

    #[tokio::test]
    async fn artifact_commit_requires_agent_bound_bearer() {
        let organization_id = Uuid::new_v4();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
            .expect("construct lazy pool");
        let principal = Principal {
            subject: "service:api".to_owned(),
            kind: mcloving_controller_store::authz::PrincipalKind::Service,
            organization_id,
            project_roles: BTreeMap::new(),
            service_scopes: BTreeSet::new(),
            mapped_projects: BTreeSet::new(),
            action_grants: BTreeMap::new(),
        };
        let state = ApiState::new(
            Store::new(pool),
            "public-api-principal-token-32-bytes",
            principal,
        )
        .unwrap()
        .with_artifact_agent_token("agent-publication-secret-token-32-bytes", "agent-1")
        .unwrap();
        let mut headers = HeaderMap::new();
        assert_eq!(
            authorize_artifact_agent(&state, &headers, "agent-1")
                .unwrap_err()
                .status,
            StatusCode::UNAUTHORIZED
        );
        headers.insert(
            ARTIFACT_AGENT_AUTHORIZATION_HEADER,
            "Bearer agent-publication-secret-token-32-bytes"
                .parse()
                .unwrap(),
        );
        authorize_artifact_agent(&state, &headers, "agent-1")
            .expect("exact agent binding is accepted");
        assert_eq!(
            authorize_artifact_agent(&state, &headers, "agent-2")
                .unwrap_err()
                .status,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn credential_namespaces_reject_token_reuse_in_either_order() {
        let organization_id = Uuid::new_v4();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
            .expect("construct lazy pool");
        let principal = Principal {
            subject: "service:api".to_owned(),
            kind: mcloving_controller_store::authz::PrincipalKind::Service,
            organization_id,
            project_roles: BTreeMap::new(),
            service_scopes: BTreeSet::new(),
            mapped_projects: BTreeSet::new(),
            action_grants: BTreeMap::new(),
        };
        let shared = "shared-cross-namespace-secret-token-32-bytes";
        let api_first = ApiState::new(Store::new(pool.clone()), shared, principal.clone()).unwrap();
        assert!(
            api_first
                .with_artifact_agent_token(shared, "agent-1")
                .is_err(),
            "an API bearer cannot also authenticate an artifact agent"
        );

        let agent_first = ApiState::new(
            Store::new(pool),
            "independent-service-principal-token-32-bytes",
            principal.clone(),
        )
        .unwrap()
        .with_artifact_agent_token(shared, "agent-1")
        .unwrap();
        assert!(
            agent_first
                .with_bearer_principal(shared, principal)
                .is_err(),
            "an artifact-agent bearer cannot also authenticate an API principal"
        );

        let durable_pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
            .expect("construct lazy pool");
        assert!(
            ApiState::new_durable(Store::new(durable_pool))
                .with_artifact_agent_token(shared, "agent-1")
                .is_err(),
            "durable mode must fail closed unless the database namespace is checked"
        );
    }

    #[test]
    fn log_transport_preserves_exact_non_utf8_bytes() {
        let content = [0xf0, 0x9f, 0x92];
        let (text, content_hex) = encode_log_content(&content);
        assert_eq!(text, None);
        assert_eq!(content_hex, "f09f92");
        let (text, content_hex) = encode_log_content("McLoving".as_bytes());
        assert_eq!(text.as_deref(), Some("McLoving"));
        assert_eq!(content_hex, "4d634c6f76696e67");
    }

    #[test]
    fn idempotency_reuse_is_a_client_visible_conflict() {
        let error = admission_error(StoreError::IdempotencyConflict(
            "key belongs to another contract".to_owned(),
        ));
        assert_eq!(error.status, StatusCode::CONFLICT);
        assert_eq!(error.code, "idempotency_conflict");
    }

    #[test]
    fn ordinary_builds_cannot_claim_the_trigger_idempotency_namespace() {
        let mut headers = HeaderMap::new();
        headers.insert(
            IDEMPOTENCY_HEADER,
            HeaderValue::from_static("mcloving-trigger-v1-forged"),
        );
        let error = ordinary_build_idempotency_key(&headers).unwrap_err();
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.code, "reserved_idempotency_key");
        assert!(required_idempotency_key(&headers).is_ok());
    }

    #[test]
    fn artifact_retention_is_bounded_before_publication_claim() {
        for seconds in [0, MAX_OBJECT_RETENTION_SECONDS] {
            validate_artifact_retention(seconds).expect("retention boundary accepted");
        }
        for seconds in [-1, MAX_OBJECT_RETENTION_SECONDS + 1, i64::MAX] {
            let error = validate_artifact_retention(seconds).expect_err("retention rejected");
            assert_eq!(error.status, StatusCode::BAD_REQUEST);
            assert_eq!(error.code, "artifact_retention_out_of_range");
        }
    }

    #[test]
    fn discovery_child_pages_have_closed_bounds() {
        assert_eq!(discovery_child_page_limit(None).unwrap(), 50);
        assert_eq!(
            discovery_child_page_limit(Some(mcloving_controller_store::MAX_DISCOVERY_CHILD_PAGE))
                .unwrap(),
            mcloving_controller_store::MAX_DISCOVERY_CHILD_PAGE
        );
        for limit in [0, mcloving_controller_store::MAX_DISCOVERY_CHILD_PAGE + 1] {
            let error = discovery_child_page_limit(Some(limit)).unwrap_err();
            assert_eq!(error.status, StatusCode::BAD_REQUEST);
            assert_eq!(error.code, "invalid_discovery_page_limit");
        }
    }

    #[test]
    fn publication_claim_owner_is_extracted_only_from_controller_tokens() {
        let organization_id = Uuid::from_u128(7);
        let token = format!("{organization_id}-123-9.staged");
        assert_eq!(
            publication_claim_organization_id(&token),
            Some(organization_id)
        );
        assert_eq!(
            publication_claim_organization_id("tenant-a-123-9.staged"),
            None
        );
        assert_eq!(
            publication_claim_organization_id(&format!("{organization_id}.123-9.staged")),
            None
        );
    }

    #[test]
    fn bearer_scheme_is_case_insensitive_but_grammar_is_strict() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "bearer exact-token".parse().unwrap());
        assert_eq!(bearer_token(&headers), Some("exact-token"));
        headers.insert(
            "authorization",
            "BEARER exact-token trailing".parse().unwrap(),
        );
        assert_eq!(bearer_token(&headers), None);
        headers.insert("authorization", "Basic exact-token".parse().unwrap());
        assert_eq!(bearer_token(&headers), None);
    }

    #[test]
    fn client_paths_are_versioned_and_tenant_scoped() {
        let client = Client::new("https://controller.example/", "token");
        let organization_id = Uuid::nil();
        let project_id = Uuid::from_u128(1);
        let build_id = Uuid::from_u128(2);
        assert_eq!(
            client.build_url(organization_id, project_id, build_id),
            format!(
                "https://controller.example/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}"
            )
        );
    }

    #[test]
    fn discovery_responses_encode_digests_as_hex() {
        assert!(parse_lowercase_hex_digest_named(&"ab".repeat(32), "discovery").is_ok());
        let uppercase = parse_lowercase_hex_digest_named(&"AB".repeat(32), "discovery")
            .expect_err("uppercase discovery digest must fail closed");
        assert_eq!(uppercase.status, StatusCode::BAD_REQUEST);
        assert_eq!(uppercase.code, "invalid_digest");

        let receipt = DiscoveryScanReceiptResponse::from(DiscoveryScanReceipt {
            organization_id: Uuid::from_u128(1),
            project_id: Uuid::from_u128(2),
            pipeline_id: Uuid::from_u128(3),
            parent_id: Uuid::from_u128(4),
            parent_generation: 1,
            scan_id: "scan-1".to_owned(),
            source: DiscoveryScanSource::Periodic,
            source_event_id: None,
            source_cursor: 1,
            complete_snapshot: true,
            provider_snapshot_sha256: [7; 32],
            request_sha256: [8; 32],
            observation_count: 1,
            selected_count: 1,
            active_count: 1,
            quarantined_count: 0,
            retired_count: 0,
            audit_sequence: 1,
            audit_event_hash: [9; 32],
        });
        assert_eq!(receipt.provider_snapshot_sha256, "07".repeat(32));
        assert_eq!(receipt.request_sha256, "08".repeat(32));
        assert_eq!(receipt.audit_event_hash, "09".repeat(32));

        let child = DiscoveryChildResponse::from(DiscoveryChild {
            organization_id: Uuid::from_u128(1),
            project_id: Uuid::from_u128(2),
            pipeline_id: Uuid::from_u128(3),
            parent_id: Uuid::from_u128(4),
            child_key: "repo:branch:main".to_owned(),
            child_pipeline_id: Uuid::from_u128(5),
            repository_identity: "github:example/repo".to_owned(),
            ref_kind: DiscoveredRefKind::Branch,
            ref_name: "main".to_owned(),
            pull_request_number: None,
            head_repository_identity: "github:example/repo".to_owned(),
            is_fork: false,
            state: DiscoveryChildState::Active,
            state_generation: 1,
            revision: "1111111".to_owned(),
            provenance_sha256: [10; 32],
            jenkinsfile_path: "Jenkinsfile".to_owned(),
            jenkinsfile_sha256: [11; 32],
            child_configuration_sha256: [12; 32],
            parent_generation: 1,
            source_cursor: 1,
            last_scan_id: "scan-1".to_owned(),
        });
        assert_eq!(child.provenance_sha256, "0a".repeat(32));
        assert_eq!(child.jenkinsfile_sha256, "0b".repeat(32));
        assert_eq!(child.child_configuration_sha256, "0c".repeat(32));
        let page = serde_json::to_value(DiscoveryChildPageResponse {
            items: vec![child],
            next_after: Some("repo:branch:main".to_owned()),
        })
        .unwrap();
        assert!(page.is_object());
        assert!(page["items"].is_array());
        assert_eq!(page["next_after"], "repo:branch:main");
    }

    #[test]
    fn openapi_covers_every_public_route_with_unique_operations_and_errors() {
        let document = openapi_document();
        let paths = document["paths"].as_object().expect("paths object");
        let expected = [
            (
                "/api/v1/organizations/{organization_id}/auth/oidc/{provider_id}/start",
                "get",
            ),
            (
                "/api/v1/organizations/{organization_id}/auth/oidc/{provider_id}/callback",
                "get",
            ),
            (
                "/api/v1/organizations/{organization_id}/auth/session/refresh",
                "post",
            ),
            (
                "/api/v1/organizations/{organization_id}/auth/session/logout",
                "post",
            ),
            ("/api/v1/organizations/{organization_id}/audit", "get"),
            (
                "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/validate",
                "post",
            ),
            (
                "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/plan",
                "post",
            ),
            (
                "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines",
                "get",
            ),
            (
                "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}",
                "get",
            ),
            (
                "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}",
                "put",
            ),
            (
                "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}/state",
                "get",
            ),
            (
                "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}/state",
                "put",
            ),
            (
                "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}/triggers/{trigger_id}",
                "get",
            ),
            (
                "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}/triggers/{trigger_id}",
                "put",
            ),
            (
                "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}/triggers/{trigger_id}/events",
                "post",
            ),
            (
                "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}/triggers/{trigger_id}/deliveries/{delivery_id}/redrive",
                "post",
            ),
            (
                "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}/discovery/{parent_id}",
                "get",
            ),
            (
                "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}/discovery/{parent_id}",
                "put",
            ),
            (
                "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}/discovery/{parent_id}/scans",
                "post",
            ),
            (
                "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}/discovery/{parent_id}/children",
                "get",
            ),
            (
                "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}/builds",
                "post",
            ),
            (
                "/api/v1/organizations/{organization_id}/projects/{project_id}/components",
                "get",
            ),
            (
                "/api/v1/organizations/{organization_id}/projects/{project_id}/components/{digest}",
                "get",
            ),
            (
                "/api/v1/organizations/{organization_id}/projects/{project_id}/components/{digest}",
                "put",
            ),
            (
                "/api/v1/organizations/{organization_id}/projects/{project_id}/builds",
                "get",
            ),
            (
                "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}",
                "get",
            ),
            (
                "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/graph",
                "get",
            ),
            (
                "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/logs",
                "get",
            ),
            (
                "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/approvals",
                "get",
            ),
            (
                "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/approvals",
                "post",
            ),
            (
                "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/credential-grants",
                "get",
            ),
            (
                "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/tests",
                "get",
            ),
            (
                "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/cancel",
                "post",
            ),
            (
                "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/attempts/{attempt_id}/retry",
                "post",
            ),
            (
                "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/artifact-uploads",
                "post",
            ),
            (
                "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/artifact-uploads/{upload_token}/commit",
                "post",
            ),
            (
                "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/artifacts",
                "get",
            ),
            (
                "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/artifacts/metadata",
                "get",
            ),
            (
                "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/artifacts/content",
                "get",
            ),
            (
                "/api/v1/organizations/{organization_id}/scheduler/explain",
                "get",
            ),
        ];
        let mut operation_ids = BTreeSet::new();
        for (path, method) in expected {
            let operation = &paths[path][method];
            let operation_id = operation["operationId"]
                .as_str()
                .unwrap_or_else(|| panic!("{method} {path} has no operationId"));
            assert!(
                operation_ids.insert(operation_id),
                "duplicate operationId {operation_id}"
            );
            assert_eq!(
                operation["responses"]["default"]["$ref"], "#/components/responses/Error",
                "{method} {path} omits the stable error envelope"
            );
        }
        let documented_methods = paths
            .values()
            .map(|path| {
                path.as_object()
                    .expect("path item")
                    .keys()
                    .filter(|key| matches!(key.as_str(), "get" | "put" | "post" | "delete"))
                    .count()
            })
            .sum::<usize>();
        assert_eq!(documented_methods, expected.len());

        let component_parameters = paths
            ["/api/v1/organizations/{organization_id}/projects/{project_id}/components"]["get"]
            ["parameters"]
            .as_array()
            .expect("component-list query parameters");
        let component_parameter_names = component_parameters
            .iter()
            .filter_map(|parameter| parameter["name"].as_str())
            .collect::<BTreeSet<_>>();
        assert!(component_parameter_names.contains("after"));
        assert!(component_parameter_names.contains("after_digest"));
        let component = &paths["/api/v1/organizations/{organization_id}/projects/{project_id}/components/{digest}"]
            ["put"];
        assert!(component["responses"]["200"].is_object());
        assert!(component["responses"]["201"].is_object());

        let discovery_children = &paths["/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}/discovery/{parent_id}/children"]
            ["get"];
        let discovery_parameters = discovery_children["parameters"]
            .as_array()
            .expect("discovery child page parameters");
        let discovery_limit = discovery_parameters
            .iter()
            .find(|parameter| parameter["name"] == "limit")
            .expect("bounded discovery child page limit");
        assert_eq!(discovery_limit["schema"]["minimum"], 1);
        assert_eq!(
            discovery_limit["schema"]["maximum"],
            mcloving_controller_store::MAX_DISCOVERY_CHILD_PAGE
        );
        assert_eq!(
            discovery_children["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/DiscoveryChildPage"
        );
        let discovery_page = &document["components"]["schemas"]["DiscoveryChildPage"];
        assert_eq!(
            discovery_page["properties"]["items"]["maxItems"],
            mcloving_controller_store::MAX_DISCOVERY_CHILD_PAGE
        );
        assert_eq!(
            discovery_page["properties"]["items"]["items"]["$ref"],
            "#/components/schemas/DiscoveryChild"
        );
        let discovery_scan = &paths["/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}/discovery/{parent_id}/scans"]
            ["post"];
        assert_eq!(
            discovery_scan["requestBody"]["x-mcloving-max-body-bytes"],
            MAX_DISCOVERY_SCAN_BODY_BYTES
        );

        let submission = &paths["/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}/builds"]
            ["post"];
        assert!(submission["responses"]["200"].is_object());
        assert!(submission["responses"]["201"].is_object());
        assert!(submission["responses"]["202"].is_null());

        let pipeline = &paths["/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}"]
            ["put"];
        assert!(pipeline["responses"]["200"].is_object());
        assert!(pipeline["responses"]["201"].is_object());

        let state = &paths["/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}/state"];
        assert!(state["get"]["responses"]["200"].is_object());
        assert!(state["put"]["responses"]["200"].is_object());
        assert!(state["put"]["responses"]["201"].is_null());

        for operation in [
            &paths["/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}/triggers/{trigger_id}/events"]
                ["post"],
            &paths["/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}/triggers/{trigger_id}/deliveries/{delivery_id}/redrive"]
                ["post"],
        ] {
            for status in ["200", "201", "202", "422"] {
                assert_eq!(
                    operation["responses"][status]["content"]["application/json"]["schema"]["$ref"],
                    "#/components/schemas/TriggerEventResponse"
                );
            }
        }

        let schemas = &document["components"]["schemas"];
        assert_eq!(
            schemas["TriggerEventResponse"]["properties"]["delivery"]["$ref"],
            "#/components/schemas/TriggerDelivery"
        );
        assert!(
            schemas["TriggerEventResponse"]["required"]
                .as_array()
                .expect("trigger-event response requirements")
                .contains(&Value::from("delivery"))
        );
        assert_eq!(
            schemas["TriggerDelivery"]["properties"]["status"]["enum"],
            json!(["pending", "retry_wait", "admitted", "dead_lettered"])
        );
        let trigger_request = &schemas["PipelineTriggerRequest"];
        assert_eq!(trigger_request["discriminator"]["propertyName"], "kind");
        assert_eq!(
            trigger_request["oneOf"]
                .as_array()
                .expect("typed trigger request variants")
                .len(),
            4
        );
        assert!(
            trigger_request["discriminator"]["mapping"]["plugin"].is_null(),
            "unimplemented plugin triggers must not be advertised as accepted"
        );
        let scm_request = &schemas["ScmPipelineTriggerRequest"];
        assert_eq!(scm_request["properties"]["kind"]["const"], "scm_webhook");
        assert_eq!(
            scm_request["properties"]["configuration"]["$ref"],
            "#/components/schemas/ScmTriggerConfiguration"
        );
        assert_eq!(
            scm_request["properties"]["deduplication_window_seconds"]["format"],
            "int64"
        );
        assert_eq!(
            scm_request["properties"]["max_delivery_attempts"]["format"],
            "int32"
        );
        assert_eq!(
            scm_request["properties"]["delivery_ttl_seconds"]["format"],
            "int64"
        );
        let scm_configuration = &schemas["ScmTriggerConfiguration"];
        assert!(
            scm_configuration["required"]
                .as_array()
                .expect("SCM configuration requirements")
                .contains(&Value::from("repository_identity"))
        );
        assert!(scm_configuration["properties"]["expression"].is_null());
        assert!(scm_configuration["properties"]["filter"]["properties"]["statuses"].is_null());
        assert_eq!(
            scm_configuration["properties"]["filter"]["properties"]["event_kinds"]["uniqueItems"],
            true
        );
        let schedule_configuration = &schemas["ScheduleTriggerConfiguration"];
        assert!(
            schedule_configuration["required"]
                .as_array()
                .expect("schedule configuration requirements")
                .contains(&Value::from("resolved_slots_unix_ms"))
        );
        assert!(
            schedule_configuration["properties"]["repository_identity"].is_null(),
            "kind-specific configuration fields must fail closed"
        );
        let resolved_slots =
            &schedule_configuration["properties"]["resolved_slots_unix_ms"]["items"];
        assert_eq!(resolved_slots["format"], "int64");
        assert_eq!(resolved_slots["maximum"], i64::MAX);
        assert_eq!(
            schedule_configuration["properties"]["resolved_slots_unix_ms"]["x-mcloving-ordering"],
            "strictly_increasing"
        );
        assert!(
            schedule_configuration["properties"]["resolved_slots_unix_ms"]["description"]
                .as_str()
                .expect("resolved-slot ordering description")
                .contains("strictly increasing")
        );
        let trigger_event = &schemas["TriggerEventRequest"];
        assert_eq!(
            trigger_event["properties"]["trigger_generation"]["format"],
            "int64"
        );
        assert_eq!(
            trigger_event["properties"]["trigger_generation"]["maximum"],
            i64::MAX
        );
        assert_eq!(
            trigger_event["properties"]["event_time_unix_ms"]["format"],
            "int64"
        );
        assert_eq!(
            trigger_event["properties"]["event_time_unix_ms"]["maximum"],
            i64::MAX
        );
        let event_payload = &schemas["TriggerEventPayload"];
        assert_eq!(
            event_payload["oneOf"]
                .as_array()
                .expect("typed trigger event payload variants")
                .len(),
            4
        );
        let scm_event = &schemas["ScmTriggerEventPayload"];
        assert!(
            scm_event["required"]
                .as_array()
                .expect("SCM event payload requirements")
                .contains(&Value::from("revision"))
        );
        assert!(scm_event["properties"]["resolved_slot_unix_ms"].is_null());
        let schedule_event = &schemas["ScheduleTriggerEventPayload"];
        assert!(
            schedule_event["required"]
                .as_array()
                .expect("schedule event payload requirements")
                .contains(&Value::from("resolved_slot_unix_ms"))
        );
        for field in [
            "expected_last_resolved_slot_unix_ms",
            "resolved_slot_unix_ms",
        ] {
            assert_eq!(schedule_event["properties"][field]["format"], "int64");
            assert_eq!(schedule_event["properties"][field]["maximum"], i64::MAX);
        }
        assert!(schedule_event["properties"]["repository_identity"].is_null());
        let remote_event = &schemas["RemoteApiTriggerEventPayload"];
        assert!(
            remote_event["required"]
                .as_array()
                .expect("remote API event payload requirements")
                .contains(&Value::from("request_id"))
        );
        let trigger_parameters = &schemas["TriggerEventRequest"]["properties"]["parameters"];
        assert_eq!(trigger_parameters["maxProperties"], 128);
        assert_eq!(
            trigger_parameters["propertyNames"]["pattern"],
            "^[A-Za-z0-9_-]{1,256}$"
        );
        assert_eq!(
            schemas["ScmTriggerEventPayload"]["properties"]["paths"]["maxItems"],
            128
        );
        let parameter_variants = trigger_parameters["additionalProperties"]["oneOf"]
            .as_array()
            .expect("closed trigger parameter value variants");
        assert_eq!(parameter_variants.len(), 3);
        assert!(
            parameter_variants
                .iter()
                .any(|variant| variant["type"] == "boolean")
        );
        assert!(parameter_variants.iter().any(|variant| {
            variant["type"] == "integer"
                && variant["format"] == "int64"
                && variant["minimum"] == i64::MIN
                && variant["maximum"] == i64::MAX
        }));
        assert!(
            parameter_variants
                .iter()
                .any(|variant| { variant["type"] == "string" && variant["maxLength"] == 4096 })
        );

        let approvals = &paths["/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/approvals"];
        assert!(approvals["post"]["responses"]["200"].is_object());
        assert!(approvals["post"]["responses"]["201"].is_object());
        for operation in [
            &approvals["get"],
            &paths["/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/credential-grants"]
                ["get"],
            &paths["/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/tests"]
                ["get"],
            &paths["/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/artifacts"]
                ["get"],
        ] {
            assert_eq!(
                operation["responses"]["200"]["content"]["application/json"]["schema"]["type"],
                "array"
            );
            assert_eq!(
                operation["responses"]["200"]["content"]["application/json"]["schema"]["items"]["type"],
                "object"
            );
        }

        let download = &paths["/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/artifacts/content"]
            ["get"];
        assert_eq!(
            download["responses"]["200"]["content"]["application/octet-stream"]["schema"]["format"],
            "binary"
        );
        assert!(
            download["responses"]["200"]["content"]["application/json"].is_null(),
            "artifact downloads must not advertise JSON"
        );
        let stage = &paths["/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/artifact-uploads"]
            ["post"];
        assert_eq!(
            stage["requestBody"]["content"]["application/octet-stream"]["schema"]["format"],
            "binary"
        );
        assert!(
            stage["requestBody"]["content"]["application/json"].is_null(),
            "artifact staging must not advertise JSON"
        );
        let commit = &paths["/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/artifact-uploads/{upload_token}/commit"]
            ["post"];
        assert!(commit["responses"]["201"].is_object());
        assert!(commit["responses"]["200"].is_null());
        let artifact_commit = &document["components"]["schemas"]["ArtifactCommitRequest"];
        assert_eq!(artifact_commit["additionalProperties"], false);
        for property in [
            "attempt_id",
            "fence",
            "restore_epoch",
            "node_id",
            "agent_id",
            "name",
            "sha256",
            "bytes",
            "media_type",
            "retention_seconds",
        ] {
            assert!(
                artifact_commit["properties"][property].is_object(),
                "artifact commit property {property} must be typed"
            );
        }
        assert_eq!(
            artifact_commit["properties"]["attempt_id"]["format"],
            "uuid"
        );
        assert_eq!(artifact_commit["properties"]["fence"]["type"], "integer");
        assert_eq!(artifact_commit["properties"]["bytes"]["maximum"], i64::MAX);
        assert_eq!(
            artifact_commit["properties"]["retention_seconds"]["maximum"],
            MAX_OBJECT_RETENTION_SECONDS
        );
        let log_parameters = paths["/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/logs"]
            ["get"]["parameters"]
            .as_array()
            .expect("log query parameters");
        assert!(
            log_parameters
                .iter()
                .any(|parameter| { parameter["name"] == "after_fence" })
        );
    }

    #[test]
    fn parameter_names_and_trigger_failure_reasons_are_bounded() {
        for invalid_name in ["", "bad.name", "bad\nname"] {
            let parameters = BTreeMap::from([(invalid_name.to_owned(), json!(true))]);
            let error = parameter_values(parameters).expect_err("reject invalid parameter name");
            assert_eq!(error.status, StatusCode::BAD_REQUEST);
            assert_eq!(error.code, "invalid_parameters");
        }
        let oversized_name = "x".repeat(257);
        assert!(
            parameter_values(BTreeMap::from([(oversized_name, json!(true))])).is_err(),
            "reject names that exceed the OpenAPI/runtime limit"
        );

        let failure = ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "pipeline_rejected",
            format!("{}\npoison", "x".repeat(3_000)),
        );
        let reason = bounded_trigger_failure_reason(&failure);
        assert!(!reason.is_empty());
        assert!(reason.len() <= 2_048);
        assert!(!reason.chars().any(char::is_control));
        assert_eq!(reason.trim(), reason);
    }

    #[test]
    fn pipeline_catalog_request_defaults_parameter_values() {
        let request: PipelineUpsertRequest = serde_json::from_value(
            json!({"slug": "release", "source": "version: 1\nname: release\nstages: []"}),
        )
        .expect("deserialize request");
        assert!(request.parameters.is_empty());
    }

    #[test]
    fn invalid_trust_pool_is_a_client_error() {
        let response = explain_error(StoreError::InvalidTrustPool);
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(response.code, "invalid_trust_pool");
    }

    #[test]
    fn duplicate_pipeline_slug_is_a_stable_conflict() {
        let response = product_error(StoreError::ProductConflict(
            "pipeline slug 'release' is already in use in this project".to_owned(),
        ));
        assert_eq!(response.status, StatusCode::CONFLICT);
        assert_eq!(response.code, "product_conflict");
    }

    #[test]
    fn mismatched_approval_replay_is_a_stable_conflict() {
        let response = security_error(StoreError::SecurityConflict(
            "approval id already belongs to a different approval contract".to_owned(),
        ));
        assert_eq!(response.status, StatusCode::CONFLICT);
        assert_eq!(response.code, "security_conflict");
    }

    #[test]
    fn pipeline_revision_precondition_is_explicit_and_strict() {
        let headers = HeaderMap::new();
        let missing = expected_revision(&headers).expect_err("missing If-Match must fail");
        assert_eq!(missing.status, StatusCode::BAD_REQUEST);
        assert_eq!(missing.code, "invalid_revision_precondition");

        let mut headers = HeaderMap::new();
        headers.insert(header::IF_MATCH, HeaderValue::from_static("\"0\""));
        assert_eq!(expected_revision(&headers).expect("parse revision zero"), 0);
    }

    #[test]
    fn submission_trust_pool_is_explicit_and_canonical() {
        let mut headers = HeaderMap::new();
        assert_eq!(
            submission_trust_pool(&headers).expect("default trust pool"),
            DEFAULT_TRUST_POOL
        );
        headers.insert(TRUST_POOL_HEADER, "trusted-build".parse().unwrap());
        assert_eq!(
            submission_trust_pool(&headers).expect("explicit trust pool"),
            "trusted-build"
        );
        headers.insert(TRUST_POOL_HEADER, " trusted-build ".parse().unwrap());
        let error = submission_trust_pool(&headers).expect_err("reject padded trust pool");
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.code, "invalid_trust_pool");
    }

    #[test]
    fn submission_platform_is_explicit_and_closed() {
        let mut headers = HeaderMap::new();
        assert_eq!(
            submission_platform(&headers).expect("default platform"),
            DEFAULT_PLATFORM
        );
        headers.insert(PLATFORM_HEADER, "windows".parse().unwrap());
        assert_eq!(
            submission_platform(&headers).expect("explicit platform"),
            "windows"
        );
        headers.insert(PLATFORM_HEADER, "macos".parse().unwrap());
        let error = submission_platform(&headers).expect_err("reject unsupported platform");
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.code, "invalid_platform");
    }

    #[test]
    fn connector_mapping_catalog_denies_unknown_floating_and_duplicate_entries() {
        let pipeline = compile_source_with_parameters(
            r#"
version: 1
name: notify
stages:
  - id: notify
    name: Notify
    steps:
      - connector_intent:
          mapping_id: notification.v1
          mapping_digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          effect_class: externally_idempotent
          effect_key_template: build.notification
          public_input_schema:
            message: string
          protected_secret_ref_schema:
            token: string
          expected_public_result_schema:
            delivery_id: string
          timeout_seconds: 30
          ambiguity_policy: observe_then_reconcile
          downstream_control_digest: sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
"#,
            BTreeMap::new(),
        )
        .expect("compile connector intent");
        let mapping = ConnectorMappingRecord {
            mapping_id: "notification.v1".into(),
            mapping_digest: format!("sha256:{}", "a".repeat(64)),
        };
        let catalog = ConnectorMappingCatalog {
            schema_version: CONNECTOR_MAPPING_CATALOG_V1.into(),
            profile: "private-linux-x86_64".into(),
            generation: 1,
            mappings: vec![mapping.clone()],
        };
        catalog.validate().expect("validate exact catalog");
        validate_connector_mappings(&pipeline, &catalog).expect("admit exact mapping");

        let unknown = ConnectorMappingCatalog {
            mappings: vec![ConnectorMappingRecord {
                mapping_id: "different.v1".into(),
                ..mapping.clone()
            }],
            ..catalog.clone()
        };
        let error = validate_connector_mappings(&pipeline, &unknown)
            .expect_err("unknown mapping must fail closed");
        assert_eq!(error.code, "pipeline_rejected");
        assert!(error.message.contains("not admitted"));

        let floating = ConnectorMappingCatalog {
            mappings: vec![ConnectorMappingRecord {
                mapping_digest: format!("sha256:{}", "c".repeat(64)),
                ..mapping.clone()
            }],
            ..catalog.clone()
        };
        let error = validate_connector_mappings(&pipeline, &floating)
            .expect_err("floating mapping must fail closed");
        assert!(error.message.contains("floating, stale, or substituted"));

        let duplicate = ConnectorMappingCatalog {
            mappings: vec![mapping.clone(), mapping],
            ..catalog
        };
        assert!(duplicate.validate().is_err());
    }

    #[test]
    fn execution_spec_preserves_explicit_process_mode() {
        let pipeline = compile_source_with_parameters(
            r#"
version: 1
name: windows-mode
stages:
  - id: execute
    name: Execute
    steps:
      - process:
          mode: powershell
          program: build.ps1
"#,
            BTreeMap::new(),
        )
        .expect("compile explicit Windows process mode");
        let spec = execution_spec(&pipeline.stages[0].steps);
        assert_eq!(spec["steps"][0]["mode"], "power_shell");
        assert_eq!(spec["steps"][0]["program"], "build.ps1");
    }

    #[test]
    fn windows_only_execution_modes_require_windows_admission() {
        for mode in ["windows_cmd", "powershell"] {
            let pipeline = compile_source_with_parameters(
                &format!(
                    r#"
version: 1
name: windows-mode
stages:
  - id: execute
    name: Execute
    steps:
      - process:
          mode: {mode}
          program: build.cmd
"#
                ),
                BTreeMap::new(),
            )
            .expect("compile explicit Windows mode");

            let error = validate_execution_platform(&pipeline, "linux")
                .expect_err("Linux admission must reject Windows-only execution modes");
            assert_eq!(error.status, StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(error.code, "pipeline_rejected");
            assert_eq!(
                error.message,
                format!("execution mode {mode} requires platform windows")
            );
            validate_execution_platform(&pipeline, "windows")
                .expect("Windows admission accepts Windows execution modes");
        }
    }

    #[test]
    fn direct_execution_mode_is_cross_platform() {
        let pipeline = compile_source_with_parameters(
            r#"
version: 1
name: direct-mode
stages:
  - id: execute
    name: Execute
    steps:
      - process:
          mode: direct
          program: tool
"#,
            BTreeMap::new(),
        )
        .expect("compile direct process mode");
        validate_execution_platform(&pipeline, "linux").expect("Linux accepts direct mode");
        validate_execution_platform(&pipeline, "windows").expect("Windows accepts direct mode");
    }
}
