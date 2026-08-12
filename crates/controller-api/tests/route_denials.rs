use std::collections::{BTreeMap, BTreeSet};

use axum::body::Body;
use axum::body::to_bytes;
use axum::http::{Method, Request, StatusCode, header};
use mcloving_controller_api::{
    ARTIFACT_NAME_HEADER, ApiState, IDEMPOTENCY_HEADER, PLATFORM_HEADER, TRUST_POOL_HEADER, router,
};
use mcloving_controller_store::{
    NewTriggerDelivery, PipelinePutOutcome, PipelineWrite, Store, TriggerDeliveryAdmission,
    TriggerDeliveryClaimOutcome, TriggerDeliveryClaimRequest, TriggerDeliveryFailureRequest,
    TriggerDeliveryStatus,
    authz::{Principal, PrincipalKind, ServiceScope},
};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;
use uuid::Uuid;

const TOKEN: &str = "route-denial-contract-token-32-bytes";

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Clone)]
struct RouteCase {
    method: Method,
    path: String,
    body: String,
    content_type: Option<&'static str>,
    headers: Vec<(&'static str, &'static str)>,
}

#[tokio::test]
async fn every_tenant_route_denies_missing_and_cross_tenant_authority() {
    let principal_organization = Uuid::new_v4();
    let requested_organization = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    let build_id = Uuid::new_v4();
    let pipeline_id = Uuid::new_v4();
    let attempt_id = Uuid::new_v4();
    let approval_id = Uuid::new_v4();
    let node_id = Uuid::new_v4();
    let digest = "11".repeat(32);
    let principal = Principal {
        subject: "service:route-contract".to_owned(),
        kind: PrincipalKind::Service,
        organization_id: principal_organization,
        project_roles: BTreeMap::new(),
        service_scopes: [
            ServiceScope::ProjectRead,
            ServiceScope::BuildSubmit,
            ServiceScope::BuildCancel,
            ServiceScope::SecretUse,
            ServiceScope::ProjectAdmin,
            ServiceScope::AuditRead,
            ServiceScope::SchedulerControl,
        ]
        .into_iter()
        .collect::<BTreeSet<_>>(),
        mapped_projects: BTreeSet::new(),
        action_grants: BTreeMap::new(),
    };
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
        .expect("construct lazy pool");
    let app = router(
        ApiState::new(Store::new(pool), TOKEN, principal).expect("construct contract API state"),
    );

    let cases = route_cases(
        requested_organization,
        project_id,
        build_id,
        pipeline_id,
        attempt_id,
        approval_id,
        node_id,
        &digest,
    );
    assert_eq!(cases.len(), 32, "route matrix must track the public API");
    for case in cases {
        let unauthenticated = app
            .clone()
            .oneshot(request(&case, None))
            .await
            .expect("route missing-authority request");
        assert_eq!(
            unauthenticated.status(),
            StatusCode::UNAUTHORIZED,
            "{} {} must reject missing authority",
            case.method,
            case.path
        );

        let cross_tenant = app
            .clone()
            .oneshot(request(&case, Some(TOKEN)))
            .await
            .expect("route cross-tenant request");
        assert_eq!(
            cross_tenant.status(),
            StatusCode::FORBIDDEN,
            "{} {} must reject cross-tenant substitution",
            case.method,
            case.path
        );
    }
}

#[tokio::test]
async fn static_ui_is_csp_locked_external_only_and_accessibility_structured() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
        .expect("construct lazy pool");
    let principal = Principal {
        subject: "service:ui-contract".to_owned(),
        kind: PrincipalKind::Service,
        organization_id: Uuid::new_v4(),
        project_roles: BTreeMap::new(),
        service_scopes: BTreeSet::new(),
        mapped_projects: BTreeSet::new(),
        action_grants: BTreeMap::new(),
    };
    let app = router(ApiState::new(Store::new(pool), TOKEN, principal).expect("UI API state"));

    let response = app
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .expect("UI response");
    assert_eq!(response.status(), StatusCode::OK);
    let csp = response
        .headers()
        .get(header::CONTENT_SECURITY_POLICY)
        .and_then(|value| value.to_str().ok())
        .expect("CSP header");
    assert!(csp.contains("default-src 'none'"));
    assert!(csp.contains("script-src 'self'"));
    assert!(csp.contains("style-src 'self'"));
    assert!(!csp.contains("'unsafe-inline'"));
    let html = String::from_utf8(
        to_bytes(response.into_body(), 256 * 1024)
            .await
            .expect("bounded HTML")
            .to_vec(),
    )
    .expect("HTML UTF-8");
    assert!(html.contains("<main>"));
    assert!(html.contains("<nav aria-label=\"Product journeys\">"));
    assert!(html.contains("role=\"status\""));
    assert!(html.contains("<script src=\"/app.js\" defer></script>"));
    assert!(html.contains("<option value=\"aborted\">cancelled</option>"));
    assert!(html.contains("<input id=\"approval-id\" required"));
    assert!(html.contains("<input id=\"idempotency-key\" required>"));
    assert!(html.contains(
        "id=\"pipeline-id\" required autocomplete=\"off\" inputmode=\"text\" pattern=\"[0-9a-fA-F]{8}-"
    ));
    assert!(html.contains("Submit saved pipeline"));
    assert!(html.contains("Advance state"));
    assert!(html.contains("stages:\n  - id: hello"));
    assert!(!html.contains("stages: []"));
    assert!(!html.contains("browser-submit"));
    assert!(!html.contains("<style"));
    assert_eq!(html.matches("<script").count(), 1);
    let app_js = include_str!("../ui/app.js");
    assert!(app_js.contains("byId(\"approval-id\").value = newUuid()"));
    assert!(app_js.contains("byId(\"idempotency-key\").value = newUuid()"));
    assert!(app_js.contains("const idempotencyKey = byId(\"idempotency-key\").value.trim()"));
    assert!(app_js.contains("\"idempotency-key\": idempotencyKey"));
    assert!(app_js.contains("const approvalId = byId(\"approval-id\").value.trim()"));
    assert!(app_js.contains("approval_id: approvalId"));
    assert_eq!(
        app_js.matches("crypto.randomUUID()").count(),
        1,
        "one logical approval ID must survive uncertain retries"
    );
    assert!(
        app_js.contains("if (result.created === true) byId(\"approval-id\").value = newUuid()")
    );
    assert!(app_js.contains("crypto.getRandomValues(new Uint8Array(16))"));
    assert!(app_js.contains("async function loadAllBuilds(status)"));
    assert!(app_js.contains("after_created_micros"));
    assert!(app_js.contains("build pagination cursor did not advance"));
    assert!(app_js.contains("async function loadAllLogs(base)"));
    assert!(app_js.contains("const liveLogState = { base: \"\", cursor: null, items: [] }"));
    assert!(app_js.contains("let cursor = liveLogState.cursor"));
    assert!(app_js.contains("liveLogState.cursor = cursorFromLog"));
    assert!(app_js.contains("let loadBuildQueue = Promise.resolve()"));
    assert!(app_js.contains("const pendingBuildLoads = new Map()"));
    assert!(app_js.contains("const pending = pendingBuildLoads.get(base)"));
    assert!(app_js.contains(".then(() => loadBuildOnce(base))"));
    assert!(app_js.contains("if (base !== buildPath())"));
    assert!(app_js.contains("if (!page.next_after) return"));
    assert!(app_js.contains("after_fence"));
    assert!(app_js.contains("entry.content_hex"));
    assert!(app_js.contains("async function loadAllAudit()"));
    assert!(app_js.contains("page.next_after_sequence"));
    assert!(app_js.contains("`${pipelinePath()}/builds`"));
    assert!(app_js.contains("`${pipelinePath()}/state`"));
    assert!(app_js.contains("const pipelineStateRetry ="));
    assert!(
        app_js.contains("source_effective_at_unix_ms: pipelineStateRetry.sourceEffectiveAtUnixMs")
    );
}

#[tokio::test]
async fn pipeline_state_transition_requires_project_configure_authority() {
    let Ok(url) = std::env::var("MCLOVING_TEST_DATABASE_URL") else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let pool = PgPoolOptions::new()
        .connect(&url)
        .await
        .expect("connect PostgreSQL state authorization test");
    let store = Store::new(pool);
    store.migrate().await.expect("install controller schema");
    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    let pipeline_id = Uuid::new_v4();
    store
        .create_project(
            organization_id,
            &format!("org-{organization_id}"),
            project_id,
            "state-authz",
        )
        .await
        .expect("create state authorization project");
    let source = "version: 1\nname: state-authz\nstages: []\n";
    assert!(matches!(
        store
            .put_pipeline(
                &PipelineWrite {
                    organization_id,
                    project_id,
                    pipeline_id,
                    slug: "state-authz".to_owned(),
                    source: source.to_owned(),
                    source_sha256: Sha256::digest(source.as_bytes()).into(),
                    semantic_digest: Sha256::digest(b"state-authz-semantic").into(),
                    schema_major: 1,
                    schema_minor: 0,
                    parameter_schema: json!({}),
                },
                Some(0),
            )
            .await
            .expect("create state authorization pipeline"),
        PipelinePutOutcome::Created(_)
    ));
    let principal = Principal {
        subject: "service:state-reader".to_owned(),
        kind: PrincipalKind::Service,
        organization_id,
        project_roles: BTreeMap::new(),
        service_scopes: [ServiceScope::ProjectRead].into_iter().collect(),
        mapped_projects: BTreeSet::new(),
        action_grants: BTreeMap::new(),
    };
    let app =
        router(ApiState::new(store, TOKEN, principal).expect("construct state authorization API"));
    let path = format!(
        "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}/state"
    );
    let read = app
        .clone()
        .oneshot(
            Request::get(&path)
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("read current state");
    assert_eq!(read.status(), StatusCode::OK);
    let transition = app
        .oneshot(
            Request::put(&path)
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::IF_MATCH, "\"1\"")
                .header(IDEMPOTENCY_HEADER, "state-reader-denied")
                .body(Body::from(
                    json!({
                        "state": "disabled",
                        "reason": "must be denied",
                        "source_identity": "test:reader",
                        "source_generation": "test:1",
                        "source_effective_at_unix_ms": 1_800_000_000_000_i64,
                        "source_provenance_sha256": "42".repeat(32),
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("deny state transition");
    assert_eq!(transition.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn authenticated_trigger_configuration_filters_and_replay_share_durable_admission() {
    let Ok(url) = std::env::var("MCLOVING_TEST_DATABASE_URL") else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let pool = PgPoolOptions::new()
        .connect(&url)
        .await
        .expect("connect PostgreSQL trigger API test");
    let store = Store::new(pool);
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
            "trigger-api",
        )
        .await
        .expect("create trigger API project");
    let source = r#"version: 1
name: trigger-api
stages:
  - id: run
    name: Run
    steps:
      - process:
          program: echo
          args: [ok]
"#;
    assert!(matches!(
        store
            .put_pipeline(
                &PipelineWrite {
                    organization_id,
                    project_id,
                    pipeline_id,
                    slug: "trigger-api".to_owned(),
                    source: source.to_owned(),
                    source_sha256: Sha256::digest(source.as_bytes()).into(),
                    semantic_digest: Sha256::digest(b"trigger-api-semantic").into(),
                    schema_major: 1,
                    schema_minor: 0,
                    parameter_schema: json!({}),
                },
                Some(0),
            )
            .await
            .expect("create trigger API pipeline"),
        PipelinePutOutcome::Created(_)
    ));
    let principal = Principal {
        subject: "scm:github:installation:42".to_owned(),
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
    let state = ApiState::new(store.clone(), TOKEN, principal).expect("construct trigger API");
    let retry_state = state.clone();
    let app = router(state);
    let path = format!(
        "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}/triggers/{trigger_id}"
    );
    let filter = json!({"event_kinds": ["push"], "branches": ["main"], "path_prefixes": ["src/"]});
    let configuration = json!({
        "provider": "github",
        "repository_identity": "github:superbadlabs/mcloving",
        "filter": filter.clone()
    });
    let configuration_sha256 = sha256_hex(&serde_json::to_vec(&configuration).unwrap());
    let filter_sha256 = sha256_hex(&serde_json::to_vec(&filter).unwrap());
    let configured = app
        .clone()
        .oneshot(
            Request::put(&path)
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::IF_MATCH, "\"0\"")
                .header(IDEMPOTENCY_HEADER, "trigger-api-create")
                .body(Body::from(
                    json!({
                        "kind": "scm_webhook",
                        "state": "enabled",
                        "implementation_sha256": sha256_hex(b"trigger-api-v1"),
                        "configuration_sha256": configuration_sha256,
                        "filter_sha256": filter_sha256,
                        "event_source_identity": "scm:github:installation:42",
                        "source_generation": "github-installation-generation-1",
                        "configuration": configuration,
                        "deduplication_window_seconds": 3600,
                        "max_delivery_attempts": 3,
                        "delivery_ttl_seconds": 7200,
                        "reason": "reviewed GitHub trigger",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("configure typed trigger");
    assert_eq!(configured.status(), StatusCode::CREATED);

    let event_path = format!("{path}/events");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let retry_payload = json!({
        "trigger_generation": 1,
        "event_kind": "push",
        "event_time_unix_ms": now,
        "payload": {
            "repository_identity": "github:superbadlabs/mcloving",
            "revision": "retry-worker-revision",
            "branch": "main",
            "paths": ["src/retry.rs"]
        }
    });
    let retry_delivery = NewTriggerDelivery {
        organization_id,
        project_id,
        pipeline_id,
        trigger_id,
        expected_trigger_generation: 1,
        delivery_id: "durable-retry-delivery".to_owned(),
        event_id: "durable-retry-event".to_owned(),
        event_kind: "push".to_owned(),
        caller_identity: "scm:github:installation:42".to_owned(),
        payload_sha256: Sha256::digest(serde_json::to_vec(&retry_payload).unwrap()).into(),
        canonical_payload: retry_payload,
        parameters: json!({}),
        requested_platform: "linux".to_owned(),
        requested_trust_pool: "trusted-linux".to_owned(),
        event_time_unix_ms: now,
        accepted_at_unix_ms: now,
        schedule_slot: None,
    };
    store
        .accept_trigger_delivery(&retry_delivery)
        .await
        .expect("capture delivery before contained outage");
    let claimed = match store
        .claim_trigger_delivery(&TriggerDeliveryClaimRequest {
            organization_id,
            trigger_id,
            delivery_id: retry_delivery.delivery_id.clone(),
            worker_identity: "contained-outage-worker".to_owned(),
            now_unix_ms: now,
            lease_expires_at_unix_ms: now + 60_000,
        })
        .await
        .unwrap()
    {
        TriggerDeliveryClaimOutcome::Claimed(delivery) => delivery,
        other => panic!("unexpected contained-outage claim: {other:?}"),
    };
    store
        .fail_trigger_delivery(&TriggerDeliveryFailureRequest {
            organization_id,
            trigger_id,
            delivery_id: retry_delivery.delivery_id.clone(),
            worker_identity: "contained-outage-worker".to_owned(),
            claim_fence: claimed.claim_fence,
            now_unix_ms: now,
            retry_at_unix_ms: now + 1,
            retryable: true,
            reason: "contained admission outage".to_owned(),
        })
        .await
        .expect("persist bounded retry");
    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    assert_eq!(
        retry_state
            .process_due_trigger_deliveries(organization_id, 128)
            .await
            .expect("shipped retry worker processes durable due delivery"),
        1
    );
    let replayed = store
        .accept_trigger_delivery(&retry_delivery)
        .await
        .expect("read durable retry terminal state");
    let TriggerDeliveryAdmission::Replayed(replayed) = replayed else {
        panic!("durable retry must replay its original delivery")
    };
    assert_eq!(replayed.status, TriggerDeliveryStatus::Admitted);
    assert!(replayed.build_id.is_some());

    let mut corrupt_parameters_delivery = retry_delivery.clone();
    corrupt_parameters_delivery.delivery_id = "corrupt-parameters-delivery".to_owned();
    corrupt_parameters_delivery.event_id = "corrupt-parameters-event".to_owned();
    corrupt_parameters_delivery.parameters = json!({"invalid": ["array"]});
    store
        .accept_trigger_delivery(&corrupt_parameters_delivery)
        .await
        .expect("capture stored invalid-parameter recovery fixture");
    assert_eq!(
        retry_state
            .process_due_trigger_deliveries(organization_id, 128)
            .await
            .expect("invalid stored parameters consume one terminal attempt"),
        1
    );
    let corrupt_replay = store
        .accept_trigger_delivery(&corrupt_parameters_delivery)
        .await
        .expect("read invalid-parameter terminal state");
    let TriggerDeliveryAdmission::Replayed(corrupt_replay) = corrupt_replay else {
        panic!("invalid-parameter delivery must replay its terminal state")
    };
    assert_eq!(corrupt_replay.status, TriggerDeliveryStatus::DeadLettered);
    assert_eq!(corrupt_replay.attempt_count, 1);
    assert!(corrupt_replay.claim_owner.is_none());

    let filtered = app
        .clone()
        .oneshot(
            Request::post(&event_path)
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "trigger_generation": 1,
                        "delivery_id": "filtered-delivery",
                        "event_id": "filtered-event",
                        "event_kind": "push",
                        "event_time_unix_ms": now,
                        "payload": {
                            "repository_identity": "github:superbadlabs/mcloving",
                            "revision": "0123456789abcdef",
                            "branch": "release",
                            "paths": ["src/lib.rs"]
                        },
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("filter disallowed branch");
    assert_eq!(filtered.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let substituted_repository = app
        .clone()
        .oneshot(
            Request::post(&event_path)
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "trigger_generation": 1,
                        "delivery_id": "substituted-repository-delivery",
                        "event_id": "substituted-repository-event",
                        "event_kind": "push",
                        "event_time_unix_ms": now,
                        "payload": {
                            "repository_identity": "github:superbadlabs/another-repository",
                            "revision": "0123456789abcdef",
                            "branch": "main",
                            "paths": ["src/lib.rs"]
                        },
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("deny substituted SCM repository");
    assert_eq!(
        substituted_repository.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );

    let unknown_request_field = app
        .clone()
        .oneshot(
            Request::post(&event_path)
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "trigger_generation": 1,
                        "delivery_id": "unknown-field-delivery",
                        "event_id": "unknown-field-event",
                        "event_kind": "push",
                        "event_time_unix_ms": now,
                        "payload": {
                            "repository_identity": "github:superbadlabs/mcloving",
                            "revision": "0123456789abcdef",
                            "branch": "main",
                            "paths": ["src/lib.rs"]
                        },
                        "unreviewed_extension": true,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("deny unknown trigger request field");
    assert_eq!(
        unknown_request_field.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );

    let invalid_parameters = app
        .clone()
        .oneshot(
            Request::post(&event_path)
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "trigger_generation": 1,
                        "delivery_id": "invalid-parameters-delivery",
                        "event_id": "invalid-parameters-event",
                        "event_kind": "push",
                        "event_time_unix_ms": now,
                        "payload": {
                            "repository_identity": "github:superbadlabs/mcloving",
                            "revision": "0123456789abcdef",
                            "branch": "main",
                            "paths": ["src/lib.rs"]
                        },
                        "parameters": {"invalid": ["array"]},
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("reject invalid parameters before durable capture");
    assert_eq!(invalid_parameters.status(), StatusCode::BAD_REQUEST);
    assert!(
        store
            .due_trigger_deliveries(organization_id, now + 1, 128)
            .await
            .unwrap()
            .iter()
            .all(|delivery| delivery.delivery_id != "invalid-parameters-delivery")
    );

    let accepted_body = json!({
        "trigger_generation": 1,
        "delivery_id": "accepted-delivery",
        "event_id": "accepted-event",
        "event_kind": "push",
        "event_time_unix_ms": now,
        "payload": {
            "repository_identity": "github:superbadlabs/mcloving",
            "revision": "0123456789abcdef",
            "branch": "main",
            "paths": ["src/lib.rs"]
        },
    })
    .to_string();
    let accepted = app
        .clone()
        .oneshot(
            Request::post(&event_path)
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(accepted_body.clone()))
                .unwrap(),
        )
        .await
        .expect("accept authenticated trigger event");
    assert_eq!(accepted.status(), StatusCode::CREATED);
    let replay = app
        .clone()
        .oneshot(
            Request::post(&event_path)
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(accepted_body.clone()))
                .unwrap(),
        )
        .await
        .expect("replay authenticated trigger event");
    assert_eq!(replay.status(), StatusCode::OK);

    let rotated_filter =
        json!({"event_kinds": ["push"], "branches": ["release"], "path_prefixes": ["src/"]});
    let rotated_configuration = json!({
        "provider": "github",
        "repository_identity": "github:superbadlabs/mcloving",
        "filter": rotated_filter.clone()
    });
    let rotated = app
        .clone()
        .oneshot(
            Request::put(&path)
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::IF_MATCH, "\"1\"")
                .header(IDEMPOTENCY_HEADER, "trigger-api-rotate")
                .body(Body::from(
                    json!({
                        "kind": "scm_webhook",
                        "state": "enabled",
                        "implementation_sha256": sha256_hex(b"trigger-api-v2"),
                        "configuration_sha256": sha256_hex(&serde_json::to_vec(&rotated_configuration).unwrap()),
                        "filter_sha256": sha256_hex(&serde_json::to_vec(&rotated_filter).unwrap()),
                        "event_source_identity": "scm:github:installation:42",
                        "source_generation": "github-installation-generation-2",
                        "configuration": rotated_configuration,
                        "deduplication_window_seconds": 3600,
                        "max_delivery_attempts": 3,
                        "delivery_ttl_seconds": 7200,
                        "reason": "reviewed GitHub trigger rotation",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("rotate trigger configuration");
    assert_eq!(rotated.status(), StatusCode::OK);
    let replay_after_rotation = app
        .clone()
        .oneshot(
            Request::post(&event_path)
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(accepted_body.clone()))
                .unwrap(),
        )
        .await
        .expect("replay accepted event after trigger rotation");
    assert_eq!(replay_after_rotation.status(), StatusCode::OK);
    let stale_new_event = app
        .oneshot(
            Request::post(&event_path)
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    accepted_body
                        .replace("accepted-delivery", "stale-delivery")
                        .replace("accepted-event", "stale-event"),
                ))
                .unwrap(),
        )
        .await
        .expect("reject new event against stale trigger generation");
    assert_eq!(stale_new_event.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn saved_pipeline_submission_keeps_revision_and_instantiated_digests_distinct() {
    let Ok(url) = std::env::var("MCLOVING_TEST_DATABASE_URL") else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let pool = PgPoolOptions::new()
        .connect(&url)
        .await
        .expect("connect PostgreSQL parameterized admission test");
    let store = Store::new(pool);
    store.migrate().await.expect("install controller schema");
    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    let pipeline_id = Uuid::new_v4();
    store
        .create_project(
            organization_id,
            &format!("org-{organization_id}"),
            project_id,
            "parameterized-admission",
        )
        .await
        .expect("create parameterized admission project");
    let principal = Principal {
        subject: "service:parameterized-admission".to_owned(),
        kind: PrincipalKind::Service,
        organization_id,
        project_roles: BTreeMap::new(),
        service_scopes: [
            ServiceScope::ProjectAdmin,
            ServiceScope::BuildSubmit,
            ServiceScope::ProjectRead,
        ]
        .into_iter()
        .collect(),
        mapped_projects: BTreeSet::new(),
        action_grants: BTreeMap::new(),
    };
    let app = router(
        ApiState::new(store.clone(), TOKEN, principal)
            .expect("construct parameterized admission API"),
    );
    let source = r#"version: 1
name: parameterized-admission
parameters:
  message:
    type: string
    default: saved
stages:
  - id: run
    name: Run
    steps:
      - process:
          program: echo
          args:
            - expression: parameters.message
"#;
    let pipeline_path = format!(
        "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines/{pipeline_id}"
    );
    let saved = app
        .clone()
        .oneshot(
            Request::put(&pipeline_path)
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::IF_MATCH, "\"0\"")
                .body(Body::from(
                    json!({
                        "slug": "parameterized-admission",
                        "source": source,
                        "parameters": {},
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("save parameterized pipeline");
    assert_eq!(saved.status(), StatusCode::CREATED);
    let admitted = app
        .clone()
        .oneshot(
            Request::post(format!("{pipeline_path}/builds"))
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(IDEMPOTENCY_HEADER, "parameterized-admission")
                .header(PLATFORM_HEADER, "linux")
                .header(TRUST_POOL_HEADER, "trusted-linux")
                .body(Body::from(
                    json!({"parameters": {"message": "instantiated"}}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("submit parameterized saved pipeline");
    assert_eq!(admitted.status(), StatusCode::CREATED);

    let revised_source = source.replace("name: Run", "name: Run revised");
    let revised = app
        .clone()
        .oneshot(
            Request::put(&pipeline_path)
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::IF_MATCH, "\"1\"")
                .body(Body::from(
                    json!({
                        "slug": "parameterized-admission",
                        "source": revised_source,
                        "parameters": {},
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("revise parameterized pipeline after admission");
    assert_eq!(revised.status(), StatusCode::OK);

    let disabled = app
        .clone()
        .oneshot(
            Request::put(format!("{pipeline_path}/state"))
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::IF_MATCH, "\"1\"")
                .header(IDEMPOTENCY_HEADER, "disable-after-admission")
                .body(Body::from(
                    json!({
                        "state": "disabled",
                        "reason": "exercise admission replay fence",
                        "source_identity": "test:idempotent-replay",
                        "source_generation": "test:disable:1",
                        "source_effective_at_unix_ms": 1_700_000_000_000_i64,
                        "source_provenance_sha256": "44".repeat(32),
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("disable pipeline after admission");
    assert_eq!(disabled.status(), StatusCode::OK);
    let reenabled = app
        .clone()
        .oneshot(
            Request::put(format!("{pipeline_path}/state"))
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::IF_MATCH, "\"2\"")
                .header(IDEMPOTENCY_HEADER, "reenable-after-admission")
                .body(Body::from(
                    json!({
                        "state": "enabled",
                        "reason": "exercise admission replay generation",
                        "source_identity": "test:idempotent-replay",
                        "source_generation": "test:enable:2",
                        "source_effective_at_unix_ms": 1_700_000_000_001_i64,
                        "source_provenance_sha256": "45".repeat(32),
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("re-enable pipeline after admission");
    assert_eq!(reenabled.status(), StatusCode::OK);

    let replayed = app
        .clone()
        .oneshot(
            Request::post(format!("{pipeline_path}/builds"))
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(IDEMPOTENCY_HEADER, "parameterized-admission")
                .header(PLATFORM_HEADER, "linux")
                .header(TRUST_POOL_HEADER, "trusted-linux")
                .body(Body::from(
                    json!({"parameters": {"message": "instantiated"}}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("replay original admission after pipeline revision");
    assert_eq!(replayed.status(), StatusCode::OK);

    let divergent_parameters = app
        .clone()
        .oneshot(
            Request::post(format!("{pipeline_path}/builds"))
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(IDEMPOTENCY_HEADER, "parameterized-admission")
                .header(PLATFORM_HEADER, "linux")
                .header(TRUST_POOL_HEADER, "trusted-linux")
                .body(Body::from(
                    json!({"parameters": {"message": "different"}}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("reject divergent parameter replay");
    assert_eq!(divergent_parameters.status(), StatusCode::CONFLICT);

    let divergent_pool = app
        .oneshot(
            Request::post(format!("{pipeline_path}/builds"))
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(IDEMPOTENCY_HEADER, "parameterized-admission")
                .header(PLATFORM_HEADER, "linux")
                .header(TRUST_POOL_HEADER, "different-pool")
                .body(Body::from(
                    json!({"parameters": {"message": "instantiated"}}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("reject divergent trust-pool replay");
    assert_eq!(divergent_pool.status(), StatusCode::CONFLICT);

    let (revision, revision_digest, instantiated_digest) =
        sqlx::query_as::<_, (i64, Vec<u8>, Vec<u8>)>(
            "SELECT pipeline_revision, pipeline_revision_digest, pipeline_digest
         FROM builds
         WHERE organization_id = $1
           AND project_id = $2
           AND idempotency_key = 'parameterized-admission'",
        )
        .bind(organization_id)
        .bind(project_id)
        .fetch_one(store.pool())
        .await
        .expect("read parameterized build digests");
    let build_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)
         FROM builds
         WHERE organization_id = $1
           AND project_id = $2
           AND idempotency_key = 'parameterized-admission'",
    )
    .bind(organization_id)
    .bind(project_id)
    .fetch_one(store.pool())
    .await
    .expect("count idempotent build admissions");
    assert_eq!(revision, 1);
    assert_eq!(build_count, 1);
    assert_ne!(revision_digest, instantiated_digest);
}

fn request(case: &RouteCase, token: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(case.method.clone())
        .uri(&case.path);
    if let Some(content_type) = case.content_type {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    for (name, value) in &case.headers {
        builder = builder.header(*name, *value);
    }
    builder
        .body(Body::from(case.body.clone()))
        .expect("construct route request")
}

#[allow(clippy::too_many_arguments)]
fn route_cases(
    organization_id: Uuid,
    project_id: Uuid,
    build_id: Uuid,
    pipeline_id: Uuid,
    attempt_id: Uuid,
    approval_id: Uuid,
    node_id: Uuid,
    digest: &str,
) -> Vec<RouteCase> {
    let project = format!("/api/v1/organizations/{organization_id}/projects/{project_id}");
    let trigger_id = Uuid::new_v4();
    let build = format!("{project}/builds/{build_id}");
    let source = r#"{"source":"version: 1\nname: route-contract\nstages: []"}"#;
    let pipeline =
        r#"{"slug":"route-contract","source":"version: 1\nname: route-contract\nstages: []"}"#;
    let component = format!(
        r#"{{"name":"component","version_major":1,"version_minor":0,"canonical_hex":"","source_sha256":"{}"}}"#,
        "00".repeat(32)
    );
    let approval = format!(
        r#"{{"approval_id":"{approval_id}","environment":"production","action":"deploy","ttl_seconds":60}}"#
    );
    let retry = r#"{"max_attempts":3,"reason":"operator retry"}"#;
    let state = format!(
        r#"{{"state":"disabled","reason":"reviewed freeze","source_identity":"jenkins:jobstate-import","source_generation":"jenkins:42","source_effective_at_unix_ms":1800000000000,"source_provenance_sha256":"{}"}}"#,
        "42".repeat(32)
    );
    let trigger = format!(
        r#"{{"kind":"remote_api","state":"enabled","implementation_sha256":"{digest}","configuration_sha256":"{digest}","filter_sha256":"{digest}","event_source_identity":"service:trigger","source_generation":"source-1","configuration":{{"filter":{{}}}},"deduplication_window_seconds":60,"max_delivery_attempts":3,"delivery_ttl_seconds":300,"reason":"reviewed trigger"}}"#
    );
    let event = r#"{"trigger_generation":1,"delivery_id":"delivery-1","event_id":"event-1","event_kind":"remote","event_time_unix_ms":1800000000000,"payload":{}}"#;
    let commit = format!(
        r#"{{"node_id":"{node_id}","attempt_id":"{attempt_id}","fence":1,"restore_epoch":1,"agent_id":"agent","name":"artifact.bin","media_type":"application/octet-stream","sha256":"{digest}","bytes":1,"retention_seconds":60}}"#
    );
    let json = Some("application/json");
    vec![
        case(
            Method::GET,
            format!("/api/v1/organizations/{organization_id}/audit"),
        ),
        body_case(
            Method::POST,
            format!("{project}/pipelines/validate"),
            source,
            json,
        ),
        body_case(
            Method::POST,
            format!("{project}/pipelines/plan"),
            source,
            json,
        ),
        case(Method::GET, format!("{project}/pipelines")),
        case(Method::GET, format!("{project}/pipelines/{pipeline_id}")),
        body_case(
            Method::PUT,
            format!("{project}/pipelines/{pipeline_id}"),
            pipeline,
            json,
        )
        .with_header(header::IF_MATCH.as_str(), "\"0\""),
        case(
            Method::GET,
            format!("{project}/pipelines/{pipeline_id}/state"),
        ),
        body_case(
            Method::PUT,
            format!("{project}/pipelines/{pipeline_id}/state"),
            state,
            json,
        )
        .with_header(header::IF_MATCH.as_str(), "\"1\"")
        .with_header(IDEMPOTENCY_HEADER, "route-state-disable"),
        case(
            Method::GET,
            format!("{project}/pipelines/{pipeline_id}/triggers/{trigger_id}"),
        ),
        body_case(
            Method::PUT,
            format!("{project}/pipelines/{pipeline_id}/triggers/{trigger_id}"),
            &trigger,
            json,
        )
        .with_header(header::IF_MATCH.as_str(), "\"0\"")
        .with_header(IDEMPOTENCY_HEADER, "route-trigger-create"),
        body_case(
            Method::POST,
            format!("{project}/pipelines/{pipeline_id}/triggers/{trigger_id}/events"),
            event,
            json,
        ),
        body_case(
            Method::POST,
            format!(
                "{project}/pipelines/{pipeline_id}/triggers/{trigger_id}/deliveries/dead-1/redrive"
            ),
            r#"{"delivery_id":"redrive-1","event_id":"redrive-event-1"}"#,
            json,
        ),
        case(Method::GET, format!("{project}/components")),
        case(Method::GET, format!("{project}/components/{digest}")),
        body_case(
            Method::PUT,
            format!("{project}/components/{digest}"),
            component,
            json,
        ),
        case(Method::GET, format!("{project}/builds")),
        body_case(
            Method::POST,
            format!("{project}/pipelines/{pipeline_id}/builds"),
            r#"{"parameters":{}}"#,
            json,
        )
        .with_header(IDEMPOTENCY_HEADER, "route-contract")
        .with_header(PLATFORM_HEADER, "linux")
        .with_header(TRUST_POOL_HEADER, "trusted-linux"),
        case(Method::GET, build.clone()),
        case(Method::GET, format!("{build}/logs")),
        case(Method::GET, format!("{build}/graph")),
        case(Method::GET, format!("{build}/approvals")),
        body_case(Method::POST, format!("{build}/approvals"), approval, json),
        case(Method::GET, format!("{build}/credential-grants")),
        case(Method::GET, format!("{build}/tests")),
        body_case(Method::POST, format!("{build}/cancel"), "", None),
        body_case(
            Method::POST,
            format!("{build}/attempts/{attempt_id}/retry"),
            retry,
            json,
        ),
        body_case(
            Method::POST,
            format!("{build}/artifact-uploads"),
            "x",
            Some("application/octet-stream"),
        )
        .with_header(ARTIFACT_NAME_HEADER, "artifact.bin"),
        body_case(
            Method::POST,
            format!("{build}/artifact-uploads/upload.staged/commit"),
            commit,
            json,
        ),
        case(Method::GET, format!("{build}/artifacts")),
        case(
            Method::GET,
            format!("{build}/artifacts/metadata?attempt_id={attempt_id}&name=artifact.bin"),
        ),
        case(
            Method::GET,
            format!("{build}/artifacts/content?attempt_id={attempt_id}&name=artifact.bin"),
        ),
        case(
            Method::GET,
            format!(
                "/api/v1/organizations/{organization_id}/scheduler/explain?capability=linux&trust_pool=trusted-linux"
            ),
        ),
    ]
}

fn case(method: Method, path: String) -> RouteCase {
    body_case(method, path, "", None)
}

fn body_case(
    method: Method,
    path: String,
    body: impl Into<String>,
    content_type: Option<&'static str>,
) -> RouteCase {
    RouteCase {
        method,
        path,
        body: body.into(),
        content_type,
        headers: Vec::new(),
    }
}

impl RouteCase {
    fn with_header(mut self, name: &'static str, value: &'static str) -> Self {
        self.headers.push((name, value));
        self
    }
}
