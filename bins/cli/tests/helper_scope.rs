use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::{post, put};
use axum::{Json, Router};
use clap::Parser;
use mcloving_cli::{Arguments, CommandOutput, execute};
use serde_json::{Value, json};
use uuid::Uuid;

type Observations = Arc<Mutex<Vec<(Value, HeaderMap)>>>;

#[tokio::test]
async fn configuration_commands_preserve_scope_and_admission_headers_over_the_api() {
    let organization = Uuid::new_v4();
    let project = Uuid::new_v4();
    let pipeline_id = Uuid::new_v4();
    let observed = Observations::default();
    let prefix = format!("/api/v1/organizations/{organization}/projects/{project}/pipelines");
    let app = Router::new()
        .route(&format!("{prefix}/validate"), post(observe))
        .route(&format!("{prefix}/plan"), post(observe))
        .route(&format!("{prefix}/{pipeline_id}"), put(observe))
        .with_state(observed.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let path = std::env::temp_dir().join(format!("mcloving-cli-scope-{}.yaml", Uuid::new_v4()));
    let source = "version: 1\nname: scope\nstages: []\n";
    tokio::fs::write(&path, source).await.unwrap();
    for command in ["validate", "plan", "apply"] {
        for (custom, platform) in [(false, "linux"), (true, "linux"), (true, "windows")] {
            for scoped in [false, true] {
                if command == "apply" && !scoped {
                    continue; // Apply always gets its pipeline scope from the path.
                }
                let mut argv = vec![
                    "mcloving".to_owned(),
                    "--server".to_owned(),
                    format!("http://{address}"),
                    "--token".to_owned(),
                    "scope-fixture-token".to_owned(),
                    "--organization".to_owned(),
                    organization.to_string(),
                    "--project".to_owned(),
                    project.to_string(),
                    command.to_owned(),
                ];
                if command == "apply" {
                    argv.extend([
                        pipeline_id.to_string(),
                        "--slug".to_owned(),
                        "scoped-pipeline".to_owned(),
                        "--expected-revision".to_owned(),
                        "7".to_owned(),
                    ]);
                } else if scoped {
                    argv.extend(["--pipeline-id".to_owned(), pipeline_id.to_string()]);
                }
                argv.extend([
                    path.to_str().unwrap().to_owned(),
                    "--parameter".to_owned(),
                    "count=3".to_owned(),
                ]);
                if custom {
                    argv.extend([
                        "--trust-pool".to_owned(),
                        "cache-special".to_owned(),
                        "--platform".to_owned(),
                        platform.to_owned(),
                    ]);
                }
                let output = execute(&Arguments::try_parse_from(&argv).unwrap())
                    .await
                    .unwrap();
                if command == "plan" {
                    let CommandOutput::Structured(plan) = output else {
                        panic!("plan must return structured output");
                    };
                    assert_eq!(plan["stages"].as_array().unwrap().len(), 1);
                    assert_eq!(plan["stages"][0]["id"], "build");
                    assert_eq!(
                        plan["stages"][0]["process_steps"],
                        if custom { 0 } else { 2 }
                    );
                    assert_eq!(plan["stages"][0]["connector_intent_steps"], 0);
                    assert_eq!(
                        plan["stages"][0]["cache_intent_steps"],
                        if custom { 1 } else { 0 }
                    );
                }
                let (body, headers) = observed.lock().unwrap().pop().unwrap();
                assert_eq!(
                    headers["mcloving-trust-pool"],
                    if custom {
                        "cache-special"
                    } else {
                        "trusted-linux"
                    }
                );
                assert_eq!(headers["mcloving-platform"], platform);
                if command == "apply" {
                    assert_eq!(headers["if-match"], "\"7\"");
                    assert_eq!(
                        body,
                        json!({"slug":"scoped-pipeline","source":source,"parameters":{"count":3}})
                    );
                } else {
                    assert!(!headers.contains_key("if-match"));
                    assert_eq!(
                        body,
                        json!({"source":source,"pipeline_id":scoped.then_some(pipeline_id),"parameters":{"count":3}})
                    );
                }
                if !custom {
                    let mut invalid = argv.clone();
                    invalid.extend(["--platform".to_owned(), "unsupported-platform".to_owned()]);
                    assert!(Arguments::try_parse_from(invalid).is_err());
                }
                if command != "apply" && !scoped {
                    argv.extend(["--pipeline-id".to_owned(), "invalid-uuid".to_owned()]);
                    assert!(Arguments::try_parse_from(argv).is_err());
                }
            }
        }
    }
    assert!(observed.lock().unwrap().is_empty());
    tokio::fs::remove_file(path).await.unwrap();
    server.abort();
}

async fn observe(
    State(observed): State<Observations>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    assert_eq!(headers["authorization"], "Bearer scope-fixture-token");
    let custom = headers["mcloving-trust-pool"] == "cache-special";
    let mut stage =
        json!({"id":"build","name":"Build","process_steps":2,"connector_intent_steps":0});
    if custom {
        stage["process_steps"] = json!(0);
        stage["cache_intent_steps"] = json!(1);
    }
    // Default responses model an older controller with a nonempty process
    // stage and no cache counter. Current responses preserve a nonzero count.
    observed.lock().unwrap().push((body.clone(), headers));
    // This transport fixture does not grant Windows cache admission: it only
    // verifies that the CLI sends the platform for the real server to assess.
    Json(json!({
        "valid":true,"semantic_digest":if body.get("slug").is_some() { json!(vec![1u8;32]) } else { json!("ab".repeat(32)) },
        "schema_major":1,"schema_minor":if custom { 4 } else { 3 },"parameters":{},"stages":[stage],
        "organization_id":Uuid::nil(),"project_id":Uuid::nil(),"pipeline_id":Uuid::nil(),
        "slug":"scoped-pipeline","revision":8,"source":body["source"],
        "source_sha256":vec![0u8;32],"parameter_schema":{},
        "operational_generation":1,"operational_state":"enabled",
        "created_at_unix_ms":1,"updated_at_unix_ms":2
    }))
}
