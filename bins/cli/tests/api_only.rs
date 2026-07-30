use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Json;
use axum::Router;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use mcloving_cli::{Arguments, Command, CommandOutput, OutputMode, execute};
use serde_json::{Value, json};
use uuid::Uuid;

const TOKEN: &str = "cli-api-only-token";

#[tokio::test]
async fn validate_and_resumable_watch_use_only_the_public_api() {
    let organization = Uuid::new_v4();
    let project = Uuid::new_v4();
    let build = Uuid::new_v4();
    let attempt = Uuid::new_v4();
    let polls = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route(
            &format!("/api/v1/organizations/{organization}/projects/{project}/pipelines/validate"),
            post(validate),
        )
        .route(
            &format!("/api/v1/organizations/{organization}/projects/{project}/builds/{build}"),
            get(status),
        )
        .route(
            &format!("/api/v1/organizations/{organization}/projects/{project}/builds/{build}/logs"),
            get(logs),
        )
        .with_state(MockState {
            polls: polls.clone(),
            build,
            attempt,
        });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let pipeline = std::env::temp_dir().join(format!("mcloving-cli-{}.yaml", Uuid::new_v4()));
    tokio::fs::write(&pipeline, "version: 1\nname: api-only\nstages: []\n")
        .await
        .unwrap();
    let common = || (format!("http://{address}"), organization, Some(project));

    let (server_url, organization, project) = common();
    let validated = execute(&Arguments {
        server: server_url,
        token: TOKEN.to_owned(),
        organization,
        project,
        output: OutputMode::Json,
        command: Command::Validate {
            pipeline: pipeline.clone(),
            parameters: vec!["count=3".to_owned()],
        },
    })
    .await
    .unwrap();
    assert_eq!(
        structured(validated),
        json!({"valid": true, "semantic_digest": "ab".repeat(32)})
    );

    let (server_url, organization, project) = common();
    let watched = execute(&Arguments {
        server: server_url,
        token: TOKEN.to_owned(),
        organization,
        project,
        output: OutputMode::Json,
        command: Command::Watch {
            build,
            interval_ms: 0,
            max_polls: Some(3),
            after_attempt: Some(attempt),
            after_sequence: Some(0),
            after_stream: Some("stdout".to_owned()),
        },
    })
    .await
    .unwrap();
    let watched = structured(watched);
    assert_eq!(watched["state"], "terminal");
    assert_eq!(watched["polls"], 2);
    assert_eq!(watched["logs"].as_array().unwrap().len(), 3);
    assert_eq!(watched["resume_after"]["attempt_id"], attempt.to_string());
    assert_eq!(watched["resume_after"]["sequence"], 3);
    assert_eq!(watched["resume_after"]["stream"], "stdout");
    assert_eq!(polls.load(Ordering::SeqCst), 2);

    tokio::fs::remove_file(pipeline).await.unwrap();
    server.abort();
}

#[derive(Clone)]
struct MockState {
    polls: Arc<AtomicUsize>,
    build: Uuid,
    attempt: Uuid,
}

async fn validate(headers: HeaderMap) -> Json<Value> {
    require_token(&headers);
    Json(json!({"valid": true, "semantic_digest": "ab".repeat(32)}))
}

async fn status(State(state): State<MockState>, headers: HeaderMap) -> Json<Value> {
    require_token(&headers);
    let poll = state.polls.fetch_add(1, Ordering::SeqCst);
    let terminal = poll > 0;
    Json(json!({
        "build_id": state.build,
        "node_id": Uuid::nil(),
        "attempt_id": state.attempt,
        "status": if terminal { "succeeded" } else { "running" },
        "attempt_status": "succeeded",
        "fence": 1,
        "lease_owner": null,
        "cancellation_requested": false,
        "terminal_summary": if terminal { Some(json!({"exit_code": 0})) } else { None },
    }))
}

async fn logs(
    State(state): State<MockState>,
    Query(query): Query<BTreeMap<String, String>>,
    headers: HeaderMap,
) -> Json<Value> {
    require_token(&headers);
    let status_polls = state.polls.load(Ordering::SeqCst);
    let after_sequence = query
        .get("after_sequence")
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(-1);
    let sequence = if status_polls == 2 && after_sequence == 2 {
        3
    } else {
        status_polls as i64
    };
    let next_after = (status_polls == 2 && after_sequence < 2).then(|| {
        json!({
            "attempt_id": state.attempt,
            "sequence": sequence,
            "stream": "stdout",
        })
    });
    let text = format!("line-{sequence}");
    let content_hex = text
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Json(json!({
        "items": [{
            "attempt_id": state.attempt,
            "fence": 1,
            "sequence": sequence,
            "stream": "stdout",
            "text": text,
            "content_hex": content_hex,
            "sha256": "00".repeat(32),
        }],
        "next_after": next_after,
    }))
}

fn require_token(headers: &HeaderMap) {
    assert_eq!(
        headers
            .get("authorization")
            .and_then(|value| value.to_str().ok()),
        Some("Bearer cli-api-only-token")
    );
}

fn structured(output: CommandOutput) -> Value {
    match output {
        CommandOutput::Structured(value) => value,
        CommandOutput::Text(_) => panic!("expected structured output"),
    }
}
