//! Versioned public HTTP API and its Rust client.

mod oidc;

pub use oidc::OidcClientConfig;

use std::collections::BTreeMap;
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
    ApprovalView, ArtifactMetadata, AuditPage, BuildCursor, BuildGraph, BuildPage, ComponentCursor,
    ComponentPage, ComponentPutOutcome, ComponentRecord, ComponentWrite, CredentialGrantView,
    DagDependency, DagNodeKind, DependencyCondition, MAX_OBJECT_RETENTION_SECONDS, NewDagBuild,
    NewDagNode, NewEnvironmentApproval, ObjectKind, ObjectStatus, PipelinePage, PipelinePutOutcome,
    PipelineRecord, PipelineWrite, RetryDecision, Store, StoreError, TestReportView, WaitReason,
    authz::{Action, Principal, authorize as authorize_principal},
};
use mcloving_object_store::{
    FilesystemObjectStore, ObjectGap, ObjectRef, ObjectStoreError, PendingObject,
};
use mcloving_pipeline_ir::{
    ParameterType, ParameterValue, ParseLimits, PipelineIr, Step,
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
const DEFAULT_TRUST_POOL: &str = "trusted-linux";
const DEFAULT_PLATFORM: &str = "linux";
const MAX_PUBLICATION_CLAIM_RECONCILIATION: usize = 128;

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
        }
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
        let collides_with_api = match &self.authentication {
            Authentication::Static(credentials) => credentials
                .iter()
                .any(|credential| constant_time_eq(&credential.token_digest, &token_digest)),
            Authentication::Durable => false,
        };
        if collides_with_api
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

    pub fn with_object_store(mut self, object_store: FilesystemObjectStore) -> Self {
        self.artifact_body_limit =
            usize::try_from(object_store.quota().max_object_bytes).unwrap_or(usize::MAX);
        self.object_store = Some(object_store);
        self
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
            "/api/v1/organizations/{organization_id}/projects/{project_id}/components",
            get(list_components),
        )
        .route(
            "/api/v1/organizations/{organization_id}/projects/{project_id}/components/{digest}",
            get(get_component).put(put_component),
        )
        .route(
            "/api/v1/organizations/{organization_id}/projects/{project_id}/builds",
            post(submit).get(list_builds),
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
                "parameters": [organization.clone(), project.clone(), pipeline],
                "get": api_operation(
                    "getPipeline", "pipelines", "Read one pipeline revision", "200",
                    Vec::new(), None
                ),
                "put": put_pipeline_operation()
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
                ),
                "post": submit_build_operation()
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
                        "parameters": {"type": "object", "additionalProperties": true}
                    },
                    "additionalProperties": false
                },
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
                        "parameters": {"type": "object", "additionalProperties": true}
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
        "Submit strict YAML for idempotent admission",
        "201",
        vec![
            header_parameter(IDEMPOTENCY_HEADER, true),
            header_parameter(PLATFORM_HEADER, false),
            header_parameter(TRUST_POOL_HEADER, false),
        ],
        Some("SubmissionRequest"),
    );
    operation["responses"]["200"] = json!({
        "description": "Idempotent replay of an existing build",
        "content": {"application/json": {"schema": {"type": "object"}}}
    });
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
        Action::ProjectRead,
    )
    .await?;
    let pipeline =
        compile_source_with_parameters(&request.source, parameter_values(request.parameters)?)?;
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
        Action::ProjectRead,
    )
    .await?;
    let pipeline =
        compile_source_with_parameters(&request.source, parameter_values(request.parameters)?)?;
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
        Action::ProjectAdmin,
    )
    .await?;
    let expected_revision = expected_revision(&headers)?;
    let pipeline =
        compile_source_with_parameters(&request.source, parameter_values(request.parameters)?)?;
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
        Action::ProjectRead,
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
        Action::ProjectRead,
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
        Action::ProjectAdmin,
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
        Action::ProjectRead,
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
        Action::ProjectRead,
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
        Action::ProjectRead,
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
        Action::ProjectRead,
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
        Action::ProjectRead,
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
        Action::ProjectAdmin,
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
        Action::ProjectRead,
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

async fn submit(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id)): Path<ProjectPath>,
    headers: HeaderMap,
    source: Bytes,
) -> Result<(StatusCode, Json<AdmissionResponse>), ApiError> {
    authorize(
        &state,
        &headers,
        organization_id,
        Some(project_id),
        Action::BuildSubmit,
    )
    .await?;
    let required_trust_pool = submission_trust_pool(&headers)?;
    let required_platform = submission_platform(&headers)?;
    let idempotency_key = headers
        .get(IDEMPOTENCY_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "idempotency_key_required",
                "a non-empty Idempotency-Key header of at most 256 bytes is required",
            )
        })?;
    let (source, parameters) = submission_payload(&headers, &source)?;
    let pipeline = compile_source_with_parameters(&source, parameters)?;
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
    let admission = state
        .store
        .admit_dag(&NewDagBuild {
            organization_id,
            project_id,
            idempotency_key: idempotency_key.to_owned(),
            pipeline_digest: digest,
            priority: 0,
            nodes,
        })
        .await
        .map_err(admission_error)?;
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
    Ok((
        status,
        Json(AdmissionResponse {
            build_id: admission.build_id,
            node_id: first.node_id,
            attempt_id: first.attempt_id,
            created: admission.created,
            pipeline_digest: hex(&digest),
        }),
    ))
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
    let steps = steps
        .iter()
        .map(|step| match step {
            Step::Process(process) => json!({
                "kind": "process",
                "program": process.program,
                "args": process.args,
                "env": process.env,
                "timeout_seconds": process.timeout_seconds,
            }),
        })
        .collect::<Vec<_>>();
    json!({"version": 1, "steps": steps})
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

fn submission_payload(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(String, BTreeMap<String, ParameterValue>), ApiError> {
    let is_json = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.split(';').next() == Some("application/json"));
    if !is_json {
        let source = std::str::from_utf8(body).map_err(|_| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "invalid_utf8",
                "pipeline source must be UTF-8",
            )
        })?;
        return Ok((source.to_owned(), BTreeMap::new()));
    }
    let request: SubmissionRequest = serde_json::from_slice(body).map_err(|error| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_submission",
            format!("submission JSON is invalid: {error}"),
        )
    })?;
    let parameters = parameter_values(request.parameters)?;
    Ok((request.source, parameters))
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
                process_steps: stage.steps.len(),
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
        Action::ProjectRead,
    )
    .await?;
    let snapshot = state
        .store
        .build_snapshot(organization_id, project_id, build_id)
        .await
        .map_err(internal)?
        .ok_or_else(not_found)?;
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
        Action::BuildSubmit,
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
        Action::BuildSubmit,
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
        Action::ProjectRead,
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
        Action::ProjectRead,
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
        Action::ProjectRead,
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
        Action::ProjectRead,
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
    let accepted = state
        .store
        .request_cancellation_as(organization_id, project_id, build_id, &principal.subject)
        .await
        .map_err(internal)?;
    Ok(Json(CancellationResponse { accepted }))
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
        Action::BuildSubmit,
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

    pub async fn submit(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        idempotency_key: &str,
        source: String,
    ) -> Result<AdmissionResponse, ClientError> {
        self.submit_in_pool(
            organization_id,
            project_id,
            idempotency_key,
            DEFAULT_TRUST_POOL,
            source,
        )
        .await
    }

    pub async fn submit_in_pool(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        idempotency_key: &str,
        trust_pool: &str,
        source: String,
    ) -> Result<AdmissionResponse, ClientError> {
        self.submit_on_platform_in_pool(
            organization_id,
            project_id,
            idempotency_key,
            DEFAULT_PLATFORM,
            trust_pool,
            source,
        )
        .await
    }

    pub async fn submit_on_platform_in_pool(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        idempotency_key: &str,
        platform: &str,
        trust_pool: &str,
        source: String,
    ) -> Result<AdmissionResponse, ClientError> {
        self.send(
            self.inner
                .post(format!(
                    "{}/api/v1/organizations/{organization_id}/projects/{project_id}/builds",
                    self.base_url
                ))
                .header(IDEMPOTENCY_HEADER, idempotency_key)
                .header(PLATFORM_HEADER, platform)
                .header(TRUST_POOL_HEADER, trust_pool)
                .header("content-type", "application/yaml")
                .body(source),
        )
        .await
    }

    pub async fn submit_request_on_platform_in_pool(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        idempotency_key: &str,
        platform: &str,
        trust_pool: &str,
        request: &SubmissionRequest,
    ) -> Result<AdmissionResponse, ClientError> {
        self.send(
            self.inner
                .post(self.builds_url(organization_id, project_id))
                .header(IDEMPOTENCY_HEADER, idempotency_key)
                .header(PLATFORM_HEADER, platform)
                .header(TRUST_POOL_HEADER, trust_pool)
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
            Action::ProjectAdmin,
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
                "/api/v1/organizations/{organization_id}/projects/{project_id}/builds",
                "post",
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

        let submission =
            &paths["/api/v1/organizations/{organization_id}/projects/{project_id}/builds"]["post"];
        assert!(submission["responses"]["200"].is_object());
        assert!(submission["responses"]["201"].is_object());
        assert!(submission["responses"]["202"].is_null());

        let pipeline = &paths["/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}"]
            ["put"];
        assert!(pipeline["responses"]["200"].is_object());
        assert!(pipeline["responses"]["201"].is_object());

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
}
