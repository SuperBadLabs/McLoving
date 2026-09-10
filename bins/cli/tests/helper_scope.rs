use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use clap::Parser;
use mcloving_cli::{Arguments, execute};
use serde_json::{Value, json};
use uuid::Uuid;

#[tokio::test]
async fn validate_and_plan_propagate_optional_pipeline_scope_over_the_api() {
    let organization = Uuid::new_v4();
    let project = Uuid::new_v4();
    let pipeline_id = Uuid::new_v4();
    let observed = Arc::new(Mutex::new(Vec::<Value>::new()));
    let prefix = format!("/api/v1/organizations/{organization}/projects/{project}/pipelines");
    let app = Router::new()
        .route(&format!("{prefix}/validate"), post(observe))
        .route(&format!("{prefix}/plan"), post(observe))
        .with_state(observed.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let path = std::env::temp_dir().join(format!("mcloving-cli-scope-{}.yaml", Uuid::new_v4()));
    let source = "version: 1\nname: scope\nstages: []\n";
    tokio::fs::write(&path, source).await.unwrap();
    for command in ["validate", "plan"] {
        for scope in [None, Some(pipeline_id)] {
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
                path.to_str().unwrap().to_owned(),
                "--parameter".to_owned(),
                "count=3".to_owned(),
            ];
            if let Some(scope) = scope {
                argv.extend(["--pipeline-id".to_owned(), scope.to_string()]);
            }
            let arguments = Arguments::try_parse_from(&argv).unwrap();
            execute(&arguments).await.unwrap();
            assert_eq!(
                observed.lock().unwrap().pop().unwrap(),
                json!({"source":source,"pipeline_id":scope,"parameters":{"count":3}}),
                "{command} must preserve the exact optional authority and existing parameters"
            );
            if scope.is_none() {
                argv.extend(["--pipeline-id".to_owned(), "invalid-uuid".to_owned()]);
                assert!(Arguments::try_parse_from(argv).is_err());
            }
        }
    }
    assert!(observed.lock().unwrap().is_empty());
    tokio::fs::remove_file(path).await.unwrap();
    server.abort();
}

async fn observe(
    State(observed): State<Arc<Mutex<Vec<Value>>>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    assert_eq!(headers["authorization"], "Bearer scope-fixture-token");
    observed.lock().unwrap().push(body);
    Json(json!({
        "valid":true,"semantic_digest":"ab".repeat(32),
        "schema_major":1,"schema_minor":4,"parameters":{},"stages":[]
    }))
}
