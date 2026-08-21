//! EXEC-001 regression gate: a strict-YAML pipeline the execution machinery
//! cannot run (100 process steps in one stage) must be rejected by validate
//! and by admission with the same named diagnostic, so "validate accepted"
//! implies "runnable". The measured defect let this exact shape through both
//! gates and then looped forever at agent claim time.

use std::collections::{BTreeMap, BTreeSet};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use mcloving_controller_api::{ApiState, IDEMPOTENCY_HEADER, router};
use mcloving_controller_store::{
    PipelinePutOutcome, PipelineWrite, Store,
    authz::{Principal, PrincipalKind, ServiceScope},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;
use uuid::Uuid;

const TOKEN: &str = "unsupported-spec-gate-token-32-bytes";

fn hundred_step_single_stage_source() -> String {
    let mut source = String::from(
        "version: 1\nname: dense\nstages:\n  - id: build\n    name: Build\n    steps:\n",
    );
    for index in 0..100 {
        source.push_str(&format!(
            "      - process:\n          program: /bin/sh\n          args: [-c, \"echo step-{index}\"]\n          timeout_seconds: 10\n"
        ));
    }
    source
}

async fn error_body(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), 1_048_576)
        .await
        .expect("read error body");
    serde_json::from_slice(&bytes).expect("error body is JSON")
}

#[tokio::test]
async fn validate_and_admission_reject_the_hundred_step_stage_with_one_named_diagnostic() {
    let Ok(url) = std::env::var("MCLOVING_TEST_DATABASE_URL") else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("connect to configured PostgreSQL");
    let store = Store::new(pool);
    store.migrate().await.expect("install controller schema");
    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    store
        .create_project(
            organization_id,
            &format!("org-{organization_id}"),
            project_id,
            "unsupported-spec-gate",
        )
        .await
        .expect("create gate project");
    let principal = Principal {
        subject: "service:unsupported-spec-gate".to_owned(),
        kind: PrincipalKind::Service,
        organization_id,
        project_roles: BTreeMap::new(),
        service_scopes: [
            ServiceScope::ProjectRead,
            ServiceScope::BuildSubmit,
            ServiceScope::ProjectAdmin,
        ]
        .into_iter()
        .collect::<BTreeSet<_>>(),
        mapped_projects: BTreeSet::new(),
        action_grants: BTreeMap::new(),
    };
    let app =
        router(ApiState::new(store.clone(), TOKEN, principal).expect("construct gate API state"));
    let source = hundred_step_single_stage_source();
    let project_url = format!("/api/v1/organizations/{organization_id}/projects/{project_id}");

    // 1. The validate route must refuse the unrunnable pipeline by name.
    let validated = app
        .clone()
        .oneshot(
            Request::post(format!("{project_url}/pipelines/validate"))
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"source": source}).to_string()))
                .unwrap(),
        )
        .await
        .expect("run validate route");
    assert_eq!(validated.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = error_body(validated).await;
    assert_eq!(body["code"], "unsupported_execution_spec");
    assert_eq!(
        body["message"],
        "stage build declares 100 steps; the execution machinery runs exactly one step per stage"
    );

    // 2. Storage through the API must refuse it identically.
    let pipeline_id = Uuid::new_v4();
    let stored = app
        .clone()
        .oneshot(
            Request::put(format!("{project_url}/pipelines/{pipeline_id}"))
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::IF_MATCH, "\"0\"")
                .body(Body::from(
                    json!({"slug": "dense", "source": source}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("run pipeline upsert route");
    assert_eq!(stored.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        error_body(stored).await["code"],
        "unsupported_execution_spec"
    );

    // 3. Admission must agree even for a pipeline stored behind the API's
    //    back: a submission of the unrunnable source dies named instead of
    //    scheduling work no agent will ever execute.
    let smuggled_id = Uuid::new_v4();
    let outcome = store
        .put_pipeline(
            &PipelineWrite {
                organization_id,
                project_id,
                pipeline_id: smuggled_id,
                slug: "smuggled-dense".to_owned(),
                source_sha256: Sha256::digest(source.as_bytes()).into(),
                source: source.clone(),
                semantic_digest: Sha256::digest(b"smuggled-dense-semantic").into(),
                schema_major: 1,
                schema_minor: 0,
                parameter_schema: json!({}),
            },
            Some(0),
        )
        .await
        .expect("store the unrunnable pipeline directly");
    assert!(matches!(outcome, PipelinePutOutcome::Created(_)));
    let admitted = app
        .clone()
        .oneshot(
            Request::post(format!("{project_url}/pipelines/{smuggled_id}/builds"))
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(IDEMPOTENCY_HEADER, "unsupported-spec-gate-submission")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .expect("run build submission route");
    assert_eq!(admitted.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = error_body(admitted).await;
    assert_eq!(body["code"], "unsupported_execution_spec");
    assert_eq!(
        body["message"],
        "stage build declares 100 steps; the execution machinery runs exactly one step per stage"
    );

    // 4. The single-step shape of the same pipeline remains admissible, so the
    //    gate rejects exactly the unrunnable class and nothing else.
    let single = "version: 1\nname: dense\nstages:\n  - id: build\n    name: Build\n    steps:\n      - process:\n          program: /bin/sh\n          args: [-c, \"echo one\"]\n          timeout_seconds: 10\n";
    let accepted = app
        .oneshot(
            Request::post(format!("{project_url}/pipelines/validate"))
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"source": single}).to_string()))
                .unwrap(),
        )
        .await
        .expect("validate the single-step shape");
    assert_eq!(accepted.status(), StatusCode::OK);
}
