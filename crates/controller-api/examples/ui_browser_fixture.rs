use axum::Json;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use mcloving_controller_api::static_ui_router;
use serde_json::{Value, json};

const ORGANIZATION: &str = "11111111-1111-4111-8111-111111111111";
const PROJECT: &str = "22222222-2222-4222-8222-222222222222";
const BUILD: &str = "33333333-3333-4333-8333-333333333333";
const ATTEMPT: &str = "44444444-4444-4444-8444-444444444444";
const TOKEN: &str = "browser-token";

#[tokio::main]
async fn main() {
    let project = format!("/api/v1/organizations/{ORGANIZATION}/projects/{PROJECT}");
    let build = format!("{project}/builds/{BUILD}");
    let app = static_ui_router::<()>()
        .route(&format!("{project}/builds"), get(builds).post(submit))
        .route(&format!("{project}/pipelines/validate"), post(validate))
        .route(&format!("{project}/pipelines/plan"), post(plan))
        .route(&build, get(status))
        .route(&format!("{build}/graph"), get(graph))
        .route(&format!("{build}/logs"), get(logs))
        .route(&format!("{build}/tests"), get(tests))
        .route(&format!("{build}/artifacts"), get(artifacts))
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

async fn validate(headers: HeaderMap) -> impl IntoResponse {
    authorized(
        &headers,
        json!({"valid": true, "semantic_digest": "ab".repeat(32)}),
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

async fn artifacts(headers: HeaderMap) -> impl IntoResponse {
    authorized(&headers, json!([]))
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
