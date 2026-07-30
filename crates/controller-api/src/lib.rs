//! Versioned public HTTP API and its Rust client.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::DefaultBodyLimit;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use mcloving_controller_store::{
    ArtifactMetadata, NewBuild, ObjectKind, ObjectStatus, Store, StoreError, WaitReason,
};
use mcloving_object_store::{
    FilesystemObjectStore, ObjectGap, ObjectRef, ObjectStoreError, PendingObject,
};
use mcloving_pipeline_ir::{ParseLimits, Step, compile_strict_yaml};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const IDEMPOTENCY_HEADER: &str = "idempotency-key";
pub const TRUST_POOL_HEADER: &str = "mcloving-trust-pool";
pub const PLATFORM_HEADER: &str = "mcloving-platform";
pub const ARTIFACT_NAME_HEADER: &str = "mcloving-artifact-name";
const DEFAULT_TRUST_POOL: &str = "trusted-linux";
const DEFAULT_PLATFORM: &str = "linux";

#[derive(Clone)]
pub struct ApiState {
    store: Store,
    token_digest: [u8; 32],
    object_store: Option<FilesystemObjectStore>,
    artifact_body_limit: usize,
    staged_upload_ttl: Duration,
}

impl ApiState {
    pub fn new(store: Store, bearer_token: &str) -> Result<Self, ApiError> {
        if bearer_token.len() < 32 {
            return Err(ApiError::configuration(
                "bearer token must contain at least 32 bytes",
            ));
        }
        Ok(Self {
            store,
            token_digest: Sha256::digest(bearer_token.as_bytes()).into(),
            object_store: None,
            artifact_body_limit: 2 * 1024 * 1024,
            staged_upload_ttl: Duration::from_secs(24 * 60 * 60),
        })
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
}

pub fn router(state: ApiState) -> Router {
    let artifact_upload = Router::new()
        .route(
            "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/artifact-uploads",
            post(stage_artifact),
        )
        .route_layer(DefaultBodyLimit::max(state.artifact_body_limit));
    Router::new()
        .route(
            "/api/v1/organizations/{organization_id}/projects/{project_id}/builds",
            post(submit),
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
            "/api/v1/organizations/{organization_id}/projects/{project_id}/builds/{build_id}/cancel",
            post(cancel),
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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LogResponse {
    pub attempt_id: Uuid,
    pub fence: i64,
    pub sequence: i64,
    pub stream: String,
    pub text: String,
    pub sha256: String,
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
    authorize(&state, &headers)?;
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
    let source = std::str::from_utf8(&source).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_utf8",
            "pipeline source must be UTF-8",
        )
    })?;
    let pipeline =
        compile_strict_yaml("public-api", source, ParseLimits::default()).map_err(|error| {
            ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "pipeline_rejected",
                error.to_string(),
            )
        })?;
    if pipeline.stages.len() != 1 {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "wave1_stage_count",
            "Wave 1 accepts exactly one stage",
        ));
    }
    let stage = &pipeline.stages[0];
    if stage.steps.len() != 1 {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "wave1_step_count",
            "Wave 1 accepts exactly one process step",
        ));
    }
    let execution_spec = execution_spec(&stage.steps);
    let digest = pipeline.semantic_digest().map_err(|error| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "pipeline_rejected",
            error.to_string(),
        )
    })?;
    let admission = state
        .store
        .admit_build(&NewBuild {
            organization_id,
            project_id,
            idempotency_key: idempotency_key.to_owned(),
            pipeline_digest: digest,
            node_key: stage.id.clone(),
            required_capabilities: vec![required_platform],
            required_trust_pool,
            priority: 0,
            execution_spec,
        })
        .await
        .map_err(internal)?;
    let status = if admission.created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((
        status,
        Json(AdmissionResponse {
            build_id: admission.build_id,
            node_id: admission.node_id,
            attempt_id: admission.attempt_id,
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

async fn status(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id, build_id)): Path<BuildPath>,
    headers: HeaderMap,
) -> Result<Json<BuildResponse>, ApiError> {
    authorize(&state, &headers)?;
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
    authorize(&state, &headers)?;
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
    object_store
        .reap_staged_older_than(state.staged_upload_ttl)
        .map_err(object_store_error)?;
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

async fn commit_artifact(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id, build_id, upload_token)): Path<(Uuid, Uuid, Uuid, String)>,
    headers: HeaderMap,
    Json(request): Json<ArtifactCommitRequest>,
) -> Result<(StatusCode, Json<ArtifactResponse>), ApiError> {
    authorize(&state, &headers)?;
    require_build(&state, organization_id, project_id, build_id).await?;
    if !upload_token.starts_with(&format!("{organization_id}-")) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "upload_tenant_mismatch",
            "artifact upload token does not belong to this tenant",
        ));
    }
    let digest = parse_hex_digest(&request.sha256)?;
    let pending = PendingObject::from_parts(
        upload_token,
        ObjectRef {
            sha256: digest,
            bytes: request.bytes,
        },
    )
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
    authorize(&state, &headers)?;
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
    authorize(&state, &headers)?;
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
    authorize(&state, &headers)?;
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
    headers: HeaderMap,
) -> Result<Json<Vec<LogResponse>>, ApiError> {
    authorize(&state, &headers)?;
    if state
        .store
        .build_snapshot(organization_id, project_id, build_id)
        .await
        .map_err(internal)?
        .is_none()
    {
        return Err(not_found());
    }
    let logs = state
        .store
        .build_logs(organization_id, project_id, build_id)
        .await
        .map_err(internal)?
        .into_iter()
        .map(|entry| LogResponse {
            attempt_id: entry.attempt_id,
            fence: entry.fence,
            sequence: entry.sequence,
            stream: entry.stream,
            text: String::from_utf8_lossy(&entry.content).into_owned(),
            sha256: hex(&entry.digest),
        })
        .collect();
    Ok(Json(logs))
}

async fn cancel(
    State(state): State<Arc<ApiState>>,
    Path((organization_id, project_id, build_id)): Path<BuildPath>,
    headers: HeaderMap,
) -> Result<Json<CancellationResponse>, ApiError> {
    authorize(&state, &headers)?;
    let accepted = state
        .store
        .request_cancellation(organization_id, project_id, build_id)
        .await
        .map_err(internal)?;
    Ok(Json(CancellationResponse { accepted }))
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
    authorize(&state, &headers)?;
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

fn authorize(state: &ApiState, headers: &HeaderMap) -> Result<(), ApiError> {
    let supplied = bearer_token(headers)
        .map(|token| Sha256::digest(token.as_bytes()))
        .ok_or_else(unauthorized)?;
    if !constant_time_eq(supplied.as_slice(), &state.token_digest) {
        return Err(unauthorized());
    }
    Ok(())
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get("authorization")?.to_str().ok()?;
    let mut fields = value.split_ascii_whitespace();
    let scheme = fields.next()?;
    let token = fields.next()?;
    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() || fields.next().is_some() {
        return None;
    }
    Some(token)
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

#[derive(Clone)]
pub struct Client {
    base_url: String,
    bearer_token: String,
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
            inner: reqwest::Client::new(),
        }
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

    pub async fn logs(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        build_id: Uuid,
    ) -> Result<Vec<LogResponse>, ClientError> {
        self.send(self.inner.get(format!(
            "{}/logs",
            self.build_url(organization_id, project_id, build_id)
        )))
        .await
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
        self.send(
            self.inner
                .post(format!(
                    "{}/artifact-uploads/{upload_token}/commit",
                    self.build_url(organization_id, project_id, build_id)
                ))
                .json(request),
        )
        .await
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_comparison_is_exact() {
        assert!(constant_time_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2, 4]));
        assert!(!constant_time_eq(&[1, 2], &[1, 2, 0]));
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
    fn invalid_trust_pool_is_a_client_error() {
        let response = explain_error(StoreError::InvalidTrustPool);
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(response.code, "invalid_trust_pool");
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
