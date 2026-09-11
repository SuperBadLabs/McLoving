//! GitHub webhook receiver gate (PAR-001): a recorded push delivery, signed
//! under the trigger's derived secret, is admitted through the durable trigger
//! path with no bearer; a redelivery is acknowledged with the same build and
//! no second build; a reused delivery id with a different body is refused as
//! a conflict; a tampered body leaves no receipt; unadmitted deliveries are
//! acknowledged so GitHub reports the hook healthy.
use std::collections::{BTreeMap, BTreeSet};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use hmac::{Hmac, Mac as _};
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

const TOKEN: &str = "scm-webhook-contract-token-32-bytes!";
const KEY: &[u8] = b"scm-webhook-fixture-key-at-least-32-bytes";
const COMMIT: &str = "507956c8dfab2d04959825c277a5205b2aac01d0";

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn sign(secret: &str, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(body);
    format!(
        "sha256={}",
        mac.finalize()
            .into_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

/// A push delivery in the shape GitHub sends, reduced to the fields that
/// matter plus the usual noise around them.
fn push_delivery(reference: &str, after: &str) -> Value {
    json!({
        "ref": reference,
        "before": "0eb949baaf86fde35003fc985d101d8e46a10168",
        "after": after,
        "created": false,
        "deleted": after == "0000000000000000000000000000000000000000",
        "forced": false,
        "compare": "https://github.com/SuperBadLabs/cljest/compare/0eb949baaf86...507956c8dfab",
        "commits": [{
            "id": after,
            "message": "seed",
            "timestamp": "2026-09-11T10:00:00Z",
            "added": ["src/cljest/core.clj"],
            "removed": [],
            "modified": ["README.md"]
        }],
        "head_commit": {"id": after, "timestamp": "2026-09-11T10:00:00Z"},
        "repository": {
            "id": 1,
            "name": "cljest",
            "full_name": "SuperBadLabs/cljest",
            "private": false,
            "html_url": "https://github.com/SuperBadLabs/cljest",
            "default_branch": "main"
        },
        "pusher": {"name": "srikanth"},
        "sender": {"login": "srikanth"}
    })
}

async fn post(
    app: axum::Router,
    hook_route: &str,
    delivery: &str,
    event: &str,
    body: Vec<u8>,
    signature: String,
) -> axum::response::Response {
    app.oneshot(
        Request::post(hook_route)
            .header(header::CONTENT_TYPE, "application/json")
            .header("X-GitHub-Delivery", delivery)
            .header("X-GitHub-Event", event)
            .header("X-Hub-Signature-256", signature)
            .body(Body::from(body))
            .unwrap(),
    )
    .await
    .unwrap()
}

async fn json_body(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

#[tokio::test]
async fn a_signed_github_push_is_admitted_once_and_replayed_without_a_second_build() {
    let Ok(url) = std::env::var("MCLOVING_TEST_DATABASE_URL") else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let pool = PgPoolOptions::new()
        .connect(&url)
        .await
        .expect("connect PostgreSQL webhook test");
    let store = Store::new(pool.clone());
    store.migrate().await.expect("install controller schema");
    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    let pipeline_id = Uuid::new_v4();
    let trigger_id = Uuid::new_v4();
    store
        .create_project(
            organization_id,
            &format!("org-{organization_id}"),
            project_id,
            "scm-webhook",
        )
        .await
        .expect("create webhook project");
    // The pipeline declares `revision`, so the delivery's commit reaches it
    // as a parameter, the way a checkout step takes its commit (PAR-012).
    let source = r#"version: 1
name: scm-webhook
parameters:
  revision:
    type: string
stages:
  - id: run
    name: Run
    steps:
      - process:
          program: echo
          args:
            - expression: parameters.revision
"#;
    assert!(matches!(
        store
            .put_pipeline(
                &PipelineWrite {
                    organization_id,
                    project_id,
                    pipeline_id,
                    slug: "scm-webhook".to_owned(),
                    source: source.to_owned(),
                    source_sha256: Sha256::digest(source.as_bytes()).into(),
                    semantic_digest: Sha256::digest(b"scm-webhook-semantic").into(),
                    schema_major: 1,
                    schema_minor: 1,
                    parameter_schema: json!({
                        "revision": {"type": "string", "secret": false, "has_default": false}
                    }),
                },
                Some(0),
            )
            .await
            .expect("create webhook pipeline"),
        PipelinePutOutcome::Created(_)
    ));
    let principal = Principal {
        subject: "service:webhook-operator".to_owned(),
        kind: PrincipalKind::Service,
        organization_id,
        project_roles: BTreeMap::new(),
        service_scopes: [
            ServiceScope::ProjectAdmin,
            ServiceScope::ProjectRead,
            ServiceScope::BuildSubmit,
        ]
        .into_iter()
        .collect(),
        mapped_projects: BTreeSet::new(),
        action_grants: BTreeMap::new(),
    };
    let unkeyed = router(
        ApiState::new(store.clone(), TOKEN, principal.clone()).expect("construct unkeyed API"),
    );
    let app = router(
        ApiState::new(store.clone(), TOKEN, principal)
            .expect("construct webhook API")
            .with_webhook_key(KEY.to_vec())
            .expect("install webhook key"),
    );
    let trigger_path = format!(
        "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}/triggers/{trigger_id}"
    );
    let filter =
        json!({"event_kinds": ["push", "pull_request"], "branches": ["main"], "path_prefixes": []});
    let configuration = json!({
        "provider": "github",
        "repository_identity": "SuperBadLabs/cljest",
        "filter": filter.clone()
    });
    let configured = app
        .clone()
        .oneshot(
            Request::put(&trigger_path)
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::IF_MATCH, "\"0\"")
                .header(IDEMPOTENCY_HEADER, "scm-webhook-create")
                .body(Body::from(
                    json!({
                        "kind": "scm_webhook",
                        "state": "enabled",
                        "implementation_sha256": sha256_hex(b"scm-webhook-v1"),
                        "configuration_sha256": sha256_hex(&serde_json::to_vec(&configuration).unwrap()),
                        "filter_sha256": sha256_hex(&serde_json::to_vec(&filter).unwrap()),
                        "event_source_identity": "scm:github:webhook:cljest",
                        "source_generation": "hook-generation-1",
                        "configuration": configuration,
                        "deduplication_window_seconds": 3600,
                        "max_delivery_attempts": 3,
                        "delivery_ttl_seconds": 7200,
                        "reason": "reviewed GitHub hook",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("configure hook trigger");
    assert_eq!(configured.status(), StatusCode::CREATED);

    // The operator reads the hook path and derived secret with configuration
    // authority; a controller without a key has nothing to give.
    let webhook_path = format!("{trigger_path}/webhook");
    let no_key = unkeyed
        .clone()
        .oneshot(
            Request::get(&webhook_path)
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(no_key.status(), StatusCode::NOT_FOUND);
    let unauthenticated = app
        .clone()
        .oneshot(Request::get(&webhook_path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
    let hook = app
        .clone()
        .oneshot(
            Request::get(&webhook_path)
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(hook.status(), StatusCode::OK);
    let hook = json_body(hook).await;
    let secret = hook["secret"].as_str().expect("derived secret").to_owned();
    assert_eq!(secret.len(), 64);
    let hook_route = hook["path"].as_str().expect("hook path").to_owned();
    assert_eq!(
        hook_route,
        format!(
            "/api/v1/webhooks/github/{organization_id}/{project_id}/{pipeline_id}/{trigger_id}"
        )
    );

    let body = serde_json::to_vec(&push_delivery("refs/heads/main", COMMIT)).unwrap();
    let delivery_id = "72d3162e-cc78-11e3-81ab-4c9367dc0958";

    // A tampered body is refused without any receipt.
    let forged = post(
        app.clone(),
        &hook_route,
        delivery_id,
        "push",
        body.clone(),
        sign("not-the-secret", &body),
    )
    .await;
    assert_eq!(forged.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(forged).await["code"], "webhook_signature_invalid");
    let deliveries: i64 =
        sqlx::query_scalar("SELECT count(*) FROM trigger_deliveries WHERE organization_id = $1")
            .bind(organization_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(deliveries, 0, "a forged delivery leaves no receipt");
    let missing_header = app
        .clone()
        .oneshot(
            Request::post(&hook_route)
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-GitHub-Event", "push")
                .header("X-Hub-Signature-256", sign(&secret, &body))
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_header.status(), StatusCode::BAD_REQUEST);
    let unkeyed_post = post(
        unkeyed.clone(),
        &hook_route,
        delivery_id,
        "push",
        body.clone(),
        sign(&secret, &body),
    )
    .await;
    assert_eq!(unkeyed_post.status(), StatusCode::NOT_FOUND);

    // The real delivery admits a build; the delivery's commit is the build's
    // `revision` parameter.
    let admitted = post(
        app.clone(),
        &hook_route,
        delivery_id,
        "push",
        body.clone(),
        sign(&secret, &body),
    )
    .await;
    let admitted_status = admitted.status();
    let admitted = json_body(admitted).await;
    assert_eq!(admitted_status, StatusCode::CREATED, "{admitted}");
    let build_id = admitted["admission"]["build_id"]
        .as_str()
        .expect("admitted build id")
        .to_owned();
    assert_eq!(admitted["delivery"]["delivery_id"], delivery_id);
    assert_eq!(
        admitted["delivery"]["caller_identity"],
        "scm:github:webhook:cljest"
    );
    assert_eq!(admitted["delivery"]["parameters"]["revision"], COMMIT);
    assert_eq!(
        admitted["delivery"]["canonical_payload"]["payload"]["branch"],
        "main"
    );
    assert_eq!(
        admitted["delivery"]["canonical_payload"]["payload"]["paths"],
        json!(["README.md", "src/cljest/core.clj"])
    );

    // GitHub redelivers: same delivery id, same body, same build, no second.
    let replayed = post(
        app.clone(),
        &hook_route,
        delivery_id,
        "push",
        body.clone(),
        sign(&secret, &body),
    )
    .await;
    assert_eq!(replayed.status(), StatusCode::OK);
    let replayed = json_body(replayed).await;
    assert_eq!(replayed["admission"]["build_id"], build_id);
    let builds: i64 = sqlx::query_scalar("SELECT count(*) FROM builds WHERE organization_id = $1")
        .bind(organization_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(builds, 1, "a redelivery mints no second build");

    // The same delivery id with a different signed body is a conflict.
    let altered = serde_json::to_vec(&push_delivery(
        "refs/heads/main",
        "0eb949baaf86fde35003fc985d101d8e46a10168",
    ))
    .unwrap();
    let conflict = post(
        app.clone(),
        &hook_route,
        delivery_id,
        "push",
        altered.clone(),
        sign(&secret, &altered),
    )
    .await;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_eq!(
        json_body(conflict).await["code"],
        "trigger_ingress_conflict"
    );

    // Authenticated but not admitted: filtered branch, tag push, ping. Each is
    // acknowledged with 202 so GitHub reports success, and each leaves an
    // audit record of the decision rather than a delivery row.
    let dev = serde_json::to_vec(&push_delivery("refs/heads/dev", COMMIT)).unwrap();
    let filtered = post(
        app.clone(),
        &hook_route,
        "dev-1",
        "push",
        dev.clone(),
        sign(&secret, &dev),
    )
    .await;
    assert_eq!(filtered.status(), StatusCode::ACCEPTED);
    let filtered = json_body(filtered).await;
    assert_eq!(filtered["status"], "filtered");
    let tag = serde_json::to_vec(&push_delivery("refs/tags/v1", COMMIT)).unwrap();
    let ignored = post(
        app.clone(),
        &hook_route,
        "tag-1",
        "push",
        tag.clone(),
        sign(&secret, &tag),
    )
    .await;
    assert_eq!(ignored.status(), StatusCode::ACCEPTED);
    assert_eq!(json_body(ignored).await["status"], "ignored");
    let ping = br#"{"zen":"Keep it logically awesome.","hook_id":1,"repository":{"full_name":"SuperBadLabs/cljest"}}"#.to_vec();
    let ping_response = post(
        app.clone(),
        &hook_route,
        "ping-1",
        "ping",
        ping.clone(),
        sign(&secret, &ping),
    )
    .await;
    assert_eq!(ping_response.status(), StatusCode::ACCEPTED);
    let deliveries: i64 =
        sqlx::query_scalar("SELECT count(*) FROM trigger_deliveries WHERE organization_id = $1")
            .bind(organization_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(deliveries, 1, "unadmitted deliveries hold no ledger row");
    let unadmitted: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE organization_id = $1 AND action = 'trigger.delivery_unadmitted'",
    )
    .bind(organization_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(unadmitted, 3, "every unadmitted delivery is recorded");

    // A pull request synchronize on the filtered branch set: head ref must
    // pass the branch filter like a push.
    let pull = serde_json::to_vec(&json!({
        "action": "synchronize",
        "number": 7,
        "pull_request": {
            "head": {"sha": COMMIT, "ref": "main"},
            "base": {"ref": "main"},
            "updated_at": "2026-09-11T10:05:00Z"
        },
        "repository": {"full_name": "SuperBadLabs/cljest"}
    }))
    .unwrap();
    let pull_response = post(
        app.clone(),
        &hook_route,
        "pr-1",
        "pull_request",
        pull.clone(),
        sign(&secret, &pull),
    )
    .await;
    assert_eq!(pull_response.status(), StatusCode::CREATED);
    let pull_response = json_body(pull_response).await;
    assert_eq!(pull_response["delivery"]["event_kind"], "pull_request");
    assert_ne!(pull_response["admission"]["build_id"], build_id);
}
