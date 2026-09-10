use axum::Json;
use axum::extract::{Json as JsonBody, Query};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use mcloving_controller_api::static_ui_router;
use mcloving_pipeline_ir::{ParseLimits, compile_strict_yaml_with_parameters};
use serde_json::{Value, json};
use std::collections::BTreeMap;

const ORGANIZATION: &str = "11111111-1111-4111-8111-111111111111";
const PROJECT: &str = "22222222-2222-4222-8222-222222222222";
const BUILD: &str = "33333333-3333-4333-8333-333333333333";
const ATTEMPT: &str = "44444444-4444-4444-8444-444444444444";
const TOKEN: &str = "browser-token";

#[tokio::main]
async fn main() {
    let project = format!("/api/v1/organizations/{ORGANIZATION}/projects/{PROJECT}");
    let build = format!("{project}/builds/{BUILD}");
    let pipeline = format!("{project}/pipelines/{{pipeline_id}}");
    let app = static_ui_router::<()>()
        .route(&format!("{project}/builds"), get(builds))
        .route(&format!("{project}/pipelines/validate"), post(validate))
        .route(&format!("{project}/pipelines/plan"), post(plan))
        .route(&pipeline, put(save_pipeline))
        .route(
            &format!("{pipeline}/state"),
            get(pipeline_state).put(set_pipeline_state),
        )
        .route(&format!("{pipeline}/builds"), post(submit))
        .route(&build, get(status))
        .route(&format!("{build}/graph"), get(graph))
        .route(&format!("{build}/logs"), get(logs))
        .route(&format!("{build}/tests"), get(tests))
        .route(&format!("{build}/artifacts"), get(artifacts))
        .route(&format!("{build}/artifacts/content"), get(artifact_content))
        .route(&format!("{build}/approvals"), get(approvals).post(approve))
        .route(&format!("{build}/cancel"), post(cancel))
        .route(
            &format!("/api/v1/organizations/{ORGANIZATION}/audit"),
            get(audit),
        )
        .route(
            &format!("/api/v1/organizations/{ORGANIZATION}/scheduler/explain"),
            get(explain),
        );
    let address =
        std::env::var("UI_FIXTURE_ADDRESS").unwrap_or_else(|_| "127.0.0.1:19090".to_owned());
    let listener = tokio::net::TcpListener::bind(&address)
        .await
        .expect("bind UI fixture");
    eprintln!("UI fixture listening on {address}");
    axum::serve(listener, app).await.expect("serve UI fixture");
}

async fn builds(headers: HeaderMap) -> impl IntoResponse {
    authorized(
        &headers,
        json!({
            "items": [{
                "build_id": BUILD,
                "status": "running",
                "created_at_unix_micros": 1_786_000_000_000_000_i64
            }],
            "next_after": null
        }),
    )
}

async fn submit(headers: HeaderMap) -> impl IntoResponse {
    authorized(
        &headers,
        json!({
            "build_id": BUILD,
            "node_id": "55555555-5555-4555-8555-555555555555",
            "attempt_id": ATTEMPT,
            "created": true,
            "pipeline_digest": "ab".repeat(32)
        }),
    )
}

async fn save_pipeline(headers: HeaderMap) -> impl IntoResponse {
    authorized(
        &headers,
        json!({
            "organization_id": ORGANIZATION,
            "project_id": PROJECT,
            "pipeline_id": "66666666-6666-4666-8666-666666666666",
            "slug": "browser-pipeline",
            "revision": 1,
            "source": "version: 1",
            "source_sha256": vec![0_u8; 32],
            "semantic_digest": vec![1_u8; 32],
            "schema_major": 1,
            "schema_minor": 0,
            "parameter_schema": {},
            "operational_generation": 1,
            "operational_state": "enabled",
            "created_at_unix_ms": 1,
            "updated_at_unix_ms": 1
        }),
    )
}

async fn pipeline_state(headers: HeaderMap) -> impl IntoResponse {
    authorized(&headers, state_record("enabled", 1))
}

async fn set_pipeline_state(headers: HeaderMap) -> impl IntoResponse {
    authorized(&headers, state_record("disabled", 2))
}

fn state_record(state: &str, generation: i64) -> Value {
    json!({
        "organization_id": ORGANIZATION,
        "project_id": PROJECT,
        "pipeline_id": "66666666-6666-4666-8666-666666666666",
        "generation": generation,
        "state": state,
        "reason": "browser state",
        "actor_subject": "service:browser",
        "source_identity": "browser:fixture",
        "source_generation": format!("fixture:{generation}"),
        "source_effective_at_unix_ms": 1_800_000_000_000_i64,
        "source_provenance_sha256": vec![0x42_u8; 32],
        "idempotency_key": format!("fixture:{generation}"),
        "effective_at_unix_ms": 1_800_000_000_001_i64,
        "audit_sequence": generation,
        "audit_event_hash": vec![0x24_u8; 32]
    })
}

// The browser gate has to prove that a strict-YAML refusal reaches the user, so
// this route cannot answer `valid: true` unconditionally the way the rest of the
// fixture stubs its responses. It compiles the submitted source through the same
// `compile_strict_yaml_with_parameters` entry point the shipped
// `validate_pipeline` handler uses, and reproduces that handler's rejection
// envelope -- 422 with `pipeline_rejected` and the compiler's own message -- so
// what the client renders is the production parser's verdict and wording rather
// than an error this fixture invented.
async fn validate(headers: HeaderMap, body: Option<JsonBody<Value>>) -> Response {
    if let Some(denial) = unauthorized(&headers) {
        return denial;
    }
    match compile_submitted_source(body) {
        Ok(pipeline) => match pipeline.semantic_digest_hex() {
            Ok(digest) => Json(json!({"valid": true, "semantic_digest": digest})).into_response(),
            Err(error) => pipeline_rejected(&error.to_string()),
        },
        Err(message) => pipeline_rejected(&message),
    }
}

fn compile_submitted_source(
    body: Option<JsonBody<Value>>,
) -> Result<mcloving_pipeline_ir::PipelineIr, String> {
    let source = body
        .as_ref()
        .and_then(|JsonBody(value)| value.get("source"))
        .and_then(Value::as_str)
        .ok_or_else(|| "request body must carry a pipeline source string".to_owned())?;
    compile_strict_yaml_with_parameters(
        "public-api",
        source,
        ParseLimits::default(),
        BTreeMap::new(),
    )
    .map_err(|error| error.to_string())
}

fn pipeline_rejected(message: &str) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({"code": "pipeline_rejected", "message": message})),
    )
        .into_response()
}

fn unauthorized(headers: &HeaderMap) -> Option<Response> {
    let expected = format!("Bearer {TOKEN}");
    let presented = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok());
    if presented == Some(expected.as_str()) {
        return None;
    }
    Some(
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"code": "unauthorized", "message": "token required"})),
        )
            .into_response(),
    )
}

async fn plan(headers: HeaderMap) -> impl IntoResponse {
    authorized(
        &headers,
        json!({
            "schema_major": 1,
            "schema_minor": 1,
            "semantic_digest": "ab".repeat(32),
            "parameters": {},
            "stages": [{"id": "build", "name": "Build", "process_steps": 1}]
        }),
    )
}

async fn status(headers: HeaderMap) -> impl IntoResponse {
    authorized(
        &headers,
        json!({
            "build_id": BUILD,
            "node_id": "55555555-5555-4555-8555-555555555555",
            "attempt_id": ATTEMPT,
            "status": "running",
            "attempt_status": "running",
            "fence": 1,
            "lease_owner": "browser-agent",
            "cancellation_requested": false,
            "terminal_summary": null
        }),
    )
}

async fn graph(headers: HeaderMap) -> impl IntoResponse {
    authorized(
        &headers,
        json!({"build_id": BUILD, "nodes": [{"id": "build", "status": "running"}]}),
    )
}

async fn logs(headers: HeaderMap) -> impl IntoResponse {
    authorized(
        &headers,
        json!({
            "items": [{
                "attempt_id": ATTEMPT,
                "fence": 1,
                "sequence": 1,
                "stream": "stdout",
                "text": "browser journey log",
                "sha256": "00".repeat(32)
            }],
            "next_after": null
        }),
    )
}

async fn tests(headers: HeaderMap) -> impl IntoResponse {
    authorized(
        &headers,
        json!([{"schema_version": 1, "outcome": "passed", "total": 3}]),
    )
}

// The listing and the content route are driven from ONE table, and the content
// route resolves it the way production does.
//
// `ArtifactQuery` carries only `attempt_id` and `name`, and `find_artifact`
// takes the FIRST match with no fence in the predicate or the ordering. A
// fixture that answered a fence-specific record for that query would manufacture
// behaviour the shipped controller does not have, and the gate would stay green
// on it.
//
// `report.txt` appears twice, sharing an attempt and a name and differing only
// by fence, because that pair is what makes the client's focus key -- which does
// carry the fence -- load-bearing. It is deliberately ambiguous to the download
// query, and the shipped client cannot disambiguate it; that is a real client
// limitation, filed separately rather than papered over here. `build.log` is
// uniquely named, so it is the row the delivery journey uses.
fn artifact_table() -> Vec<(&'static str, i64, &'static str)> {
    vec![
        ("report.txt", 1, "twelve bytes"),
        ("build.log", 1, "browser fixture build log\n"),
        ("report.txt", 2, "browser fixture artifact bytes\n123"),
    ]
}

async fn artifacts(headers: HeaderMap) -> impl IntoResponse {
    let items: Vec<Value> = artifact_table()
        .into_iter()
        .map(|(name, fence, body)| {
            json!({
                "build_id": BUILD,
                "node_id": "55555555-5555-4555-8555-555555555555",
                "attempt_id": ATTEMPT,
                "fence": fence,
                "name": name,
                "sha256": "11".repeat(32),
                "bytes": body.len(),
                "media_type": "text/plain",
                "status": "available"
            })
        })
        .collect();
    authorized(&headers, Value::Array(items))
}

// Resolved exactly as `find_artifact` resolves it: first record matching the
// attempt and name, fence ignored. For `report.txt` that is the fence-1 record,
// not the fence-2 one the user may have clicked -- which is the production
// behaviour, faithfully reproduced rather than corrected here.
async fn artifact_content(
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response {
    if let Some(denial) = unauthorized(&headers) {
        return denial;
    }
    if query.get("attempt_id").map(String::as_str) != Some(ATTEMPT) {
        return artifact_not_found(&query);
    }
    let requested = query.get("name").map(String::as_str).unwrap_or_default();
    match artifact_table()
        .into_iter()
        .find(|(name, _, _)| *name == requested)
    {
        Some((_, _, body)) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/octet-stream")],
            body,
        )
            .into_response(),
        None => artifact_not_found(&query),
    }
}

fn artifact_not_found(query: &BTreeMap<String, String>) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "code": "artifact_not_found",
            "message": format!("no artifact for {query:?}")
        })),
    )
        .into_response()
}

async fn approvals(headers: HeaderMap) -> impl IntoResponse {
    authorized(&headers, json!([]))
}

async fn approve(headers: HeaderMap) -> impl IntoResponse {
    authorized(&headers, json!({"accepted": true}))
}

async fn cancel(headers: HeaderMap) -> impl IntoResponse {
    authorized(&headers, json!({"accepted": true}))
}

async fn audit(headers: HeaderMap) -> impl IntoResponse {
    authorized(
        &headers,
        json!({"events": [{"sequence": 1, "kind": "build.submitted"}], "next_after": null}),
    )
}

async fn explain(headers: HeaderMap) -> impl IntoResponse {
    authorized(&headers, json!({"reason": "ready"}))
}

fn authorized(headers: &HeaderMap, value: Value) -> (StatusCode, Json<Value>) {
    let expected = format!("Bearer {TOKEN}");
    if headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        == Some(expected.as_str())
    {
        (StatusCode::OK, Json(value))
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"code": "unauthorized", "message": "token required"})),
        )
    }
}
