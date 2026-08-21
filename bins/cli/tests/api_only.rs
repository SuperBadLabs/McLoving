use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Json;
use axum::Router;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::routing::{get, post, put};
use mcloving_cli::{Arguments, Command, CommandOutput, OutputMode, PipelineStateArg, execute};
use serde_json::{Value, json};
use uuid::Uuid;

const TOKEN: &str = "cli-api-only-token";

#[tokio::test]
async fn validate_and_resumable_watch_use_only_the_public_api() {
    let organization = Uuid::new_v4();
    let project = Uuid::new_v4();
    let build = Uuid::new_v4();
    let pipeline_id = Uuid::new_v4();
    let attempt = Uuid::new_v4();
    let polls = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route(
            &format!("/api/v1/organizations/{organization}/projects/{project}/pipelines"),
            get(pipelines),
        )
        .route(
            &format!(
                "/api/v1/organizations/{organization}/projects/{project}/pipelines/{pipeline_id}"
            ),
            put(apply_pipeline),
        )
        .route(
            &format!(
                "/api/v1/organizations/{organization}/projects/{project}/pipelines/{pipeline_id}/state"
            ),
            get(pipeline_state).put(set_pipeline_state),
        )
        .route(
            &format!(
                "/api/v1/organizations/{organization}/projects/{project}/pipelines/{pipeline_id}/builds"
            ),
            post(submit_pipeline),
        )
        .route(
            &format!("/api/v1/organizations/{organization}/projects/{project}/builds"),
            get(builds),
        )
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
            pipeline_id,
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
    let pipeline_page = execute(&Arguments {
        server: server_url,
        token: TOKEN.to_owned(),
        organization,
        project,
        output: OutputMode::Json,
        command: Command::Pipelines {
            after: Some("legacy-job".to_owned()),
            limit: 17,
        },
    })
    .await
    .unwrap();
    let pipeline_page = structured(pipeline_page);
    assert_eq!(pipeline_page["items"][0]["slug"], "replacement-job");
    assert_eq!(pipeline_page["next_after"], "replacement-job");

    let (server_url, organization, project) = common();
    let applied = execute(&Arguments {
        server: server_url,
        token: TOKEN.to_owned(),
        organization,
        project,
        output: OutputMode::Json,
        command: Command::Apply {
            pipeline_id,
            slug: "replacement-job".to_owned(),
            expected_revision: 7,
            pipeline: pipeline.clone(),
            parameters: vec!["count=3".to_owned()],
        },
    })
    .await
    .unwrap();
    let applied = structured(applied);
    assert_eq!(applied["pipeline_id"], pipeline_id.to_string());
    assert_eq!(applied["revision"], 8);

    let (server_url, organization, project) = common();
    let state = structured(
        execute(&Arguments {
            server: server_url,
            token: TOKEN.to_owned(),
            organization,
            project,
            output: OutputMode::Json,
            command: Command::PipelineState { pipeline_id },
        })
        .await
        .unwrap(),
    );
    assert_eq!(state["state"], "enabled");
    assert_eq!(state["generation"], 1);

    let provenance = "42".repeat(32);
    let (server_url, organization, project) = common();
    let state = structured(
        execute(&Arguments {
            server: server_url,
            token: TOKEN.to_owned(),
            organization,
            project,
            output: OutputMode::Json,
            command: Command::SetPipelineState {
                pipeline_id,
                state: PipelineStateArg::Disabled,
                expected_generation: 1,
                idempotency_key: "cli-state-disable".to_owned(),
                reason: "reviewed freeze".to_owned(),
                source_identity: "jenkins:jobstate-import".to_owned(),
                source_generation: "jenkins:42".to_owned(),
                source_effective_at_unix_ms: 1_800_000_000_000,
                source_provenance_sha256: provenance,
            },
        })
        .await
        .unwrap(),
    );
    assert_eq!(state["state"], "disabled");
    assert_eq!(state["generation"], 2);

    let (server_url, organization, project) = common();
    let admission = structured(
        execute(&Arguments {
            server: server_url,
            token: TOKEN.to_owned(),
            organization,
            project,
            output: OutputMode::Json,
            command: Command::Submit {
                pipeline_id,
                idempotency_key: "cli-saved-pipeline".to_owned(),
                parameters: vec!["count=3".to_owned()],
                trust_pool: "trusted-linux".to_owned(),
                platform: "linux".to_owned(),
            },
        })
        .await
        .unwrap(),
    );
    assert_eq!(admission["build_id"], build.to_string());

    let (server_url, organization, project) = common();
    let build_page = execute(&Arguments {
        server: server_url,
        token: TOKEN.to_owned(),
        organization,
        project,
        output: OutputMode::Json,
        command: Command::Builds {
            after_created_micros: Some(1_234_567),
            after_id: Some(build),
            status: Some("queued".to_owned()),
            limit: 23,
        },
    })
    .await
    .unwrap();
    let build_page = structured(build_page);
    assert_eq!(build_page["items"][0]["status"], "queued");
    assert_eq!(build_page["next_after"]["build_id"], build.to_string());

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
            after_fence: Some(1),
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
    assert_eq!(watched["resume_after"]["fence"], 1);
    assert_eq!(watched["resume_after"]["sequence"], 3);
    assert_eq!(watched["resume_after"]["stream"], "stdout");
    assert_eq!(polls.load(Ordering::SeqCst), 2);

    let (server_url, organization, project) = common();
    let unavailable = execute(&Arguments {
        server: server_url,
        token: TOKEN.to_owned(),
        organization,
        project,
        output: OutputMode::Json,
        command: Command::Watch {
            build: Uuid::new_v4(),
            interval_ms: 0,
            max_polls: Some(1),
            after_attempt: None,
            after_fence: None,
            after_sequence: None,
            after_stream: None,
        },
    })
    .await
    .expect("an unavailable status endpoint produces an uncertain receipt");
    let unavailable = structured(unavailable);
    assert_eq!(unavailable["state"], "uncertain");
    assert_eq!(unavailable["reason"], "status_request_failed");

    tokio::fs::remove_file(pipeline).await.unwrap();
    server.abort();
}

async fn pipelines(
    Query(query): Query<BTreeMap<String, String>>,
    headers: HeaderMap,
) -> Json<Value> {
    require_token(&headers);
    assert_eq!(query.get("after").map(String::as_str), Some("legacy-job"));
    assert_eq!(query.get("limit").map(String::as_str), Some("17"));
    Json(json!({
        "items": [{
            "organization_id": Uuid::nil(),
            "project_id": Uuid::nil(),
            "pipeline_id": Uuid::nil(),
            "slug": "replacement-job",
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
        }],
        "next_after": "replacement-job"
    }))
}

async fn apply_pipeline(
    State(state): State<MockState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    require_token(&headers);
    assert_eq!(
        headers
            .get("if-match")
            .and_then(|value| value.to_str().ok()),
        Some("\"7\"")
    );
    assert_eq!(body["slug"], "replacement-job");
    assert_eq!(body["parameters"]["count"], 3);
    Json(json!({
        "organization_id": Uuid::nil(),
        "project_id": Uuid::nil(),
        "pipeline_id": state.pipeline_id,
        "slug": "replacement-job",
        "revision": 8,
        "source": body["source"],
        "source_sha256": vec![0_u8; 32],
        "semantic_digest": vec![1_u8; 32],
        "schema_major": 1,
        "schema_minor": 0,
        "parameter_schema": {},
        "operational_generation": 1,
        "operational_state": "enabled",
        "created_at_unix_ms": 1,
        "updated_at_unix_ms": 2
    }))
}

async fn pipeline_state(headers: HeaderMap) -> Json<Value> {
    require_token(&headers);
    Json(state_record("enabled", 1, "created"))
}

async fn set_pipeline_state(headers: HeaderMap, Json(body): Json<Value>) -> Json<Value> {
    require_token(&headers);
    assert_eq!(
        headers
            .get("if-match")
            .and_then(|value| value.to_str().ok()),
        Some("\"1\"")
    );
    assert_eq!(
        headers
            .get("idempotency-key")
            .and_then(|value| value.to_str().ok()),
        Some("cli-state-disable")
    );
    assert_eq!(body["state"], "disabled");
    assert_eq!(body["reason"], "reviewed freeze");
    assert_eq!(body["source_identity"], "jenkins:jobstate-import");
    Json(state_record("disabled", 2, "cli-state-disable"))
}

async fn submit_pipeline(
    State(mock): State<MockState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    require_token(&headers);
    assert_eq!(
        headers
            .get("idempotency-key")
            .and_then(|value| value.to_str().ok()),
        Some("cli-saved-pipeline")
    );
    assert_eq!(body, json!({"parameters": {"count": 3}}));
    Json(json!({
        "build_id": mock.build,
        "node_id": Uuid::new_v4(),
        "attempt_id": Uuid::new_v4(),
        "created": true,
        "pipeline_digest": "ab".repeat(32),
    }))
}

fn state_record(state: &str, generation: i64, idempotency_key: &str) -> Value {
    json!({
        "organization_id": Uuid::nil(),
        "project_id": Uuid::nil(),
        "pipeline_id": Uuid::nil(),
        "generation": generation,
        "state": state,
        "reason": "reviewed state",
        "actor_subject": "service:cli",
        "source_identity": "test:cli",
        "source_generation": format!("generation:{generation}"),
        "source_effective_at_unix_ms": 1_800_000_000_000_i64,
        "source_provenance_sha256": vec![0x42_u8; 32],
        "idempotency_key": idempotency_key,
        "effective_at_unix_ms": 1_800_000_000_001_i64,
        "audit_sequence": 1,
        "audit_event_hash": vec![0x24_u8; 32],
    })
}

async fn builds(
    State(state): State<MockState>,
    Query(query): Query<BTreeMap<String, String>>,
    headers: HeaderMap,
) -> Json<Value> {
    require_token(&headers);
    assert_eq!(
        query.get("after_created_micros").map(String::as_str),
        Some("1234567")
    );
    let expected_build_id = state.build.to_string();
    assert_eq!(
        query.get("after_id").map(String::as_str),
        Some(expected_build_id.as_str())
    );
    assert_eq!(query.get("status").map(String::as_str), Some("queued"));
    assert_eq!(query.get("limit").map(String::as_str), Some("23"));
    Json(json!({
        "items": [{
            "build_id": state.build,
            "pipeline_digest": vec![2_u8; 32],
            "status": "queued",
            "priority": 0,
            "dag_mode": false,
            "created_at_unix_ms": 1_234,
            "created_at_unix_micros": 1_234_567,
            "completed_at_unix_ms": null
        }],
        "next_after": {
            "created_at_unix_micros": 1_234_567,
            "build_id": state.build
        }
    }))
}

#[derive(Clone)]
struct MockState {
    polls: Arc<AtomicUsize>,
    build: Uuid,
    attempt: Uuid,
    pipeline_id: Uuid,
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
        "effects": [],
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
            "fence": 1,
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
