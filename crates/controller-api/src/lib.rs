//! Versioned public HTTP API and its Rust client.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use mcloving_controller_store::{NewBuild, Store, WaitReason};
use mcloving_pipeline_ir::{ParseLimits, Step, compile_strict_yaml};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const IDEMPOTENCY_HEADER: &str = "idempotency-key";

#[derive(Clone)]
pub struct ApiState {
    store: Store,
    token_digest: [u8; 32],
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
        })
    }
}

pub fn router(state: ApiState) -> Router {
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
            required_capabilities: vec!["linux".to_owned()],
            required_trust_pool: "trusted-linux".to_owned(),
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
    "trusted-linux".to_owned()
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
        .map_err(internal)?
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
        self.send(
            self.inner
                .post(format!(
                    "{}/api/v1/organizations/{organization_id}/projects/{project_id}/builds",
                    self.base_url
                ))
                .header(IDEMPOTENCY_HEADER, idempotency_key)
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

    pub async fn explain(
        &self,
        organization_id: Uuid,
        capabilities: &[String],
    ) -> Result<ExplainResponse, ClientError> {
        self.explain_in_pool(organization_id, capabilities, "trusted-linux")
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
}
