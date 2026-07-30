use std::collections::{BTreeMap, BTreeSet};

use axum::body::Body;
use axum::body::to_bytes;
use axum::http::{Method, Request, StatusCode, header};
use mcloving_controller_api::{
    ARTIFACT_NAME_HEADER, ApiState, IDEMPOTENCY_HEADER, PLATFORM_HEADER, TRUST_POOL_HEADER, router,
};
use mcloving_controller_store::{
    Store,
    authz::{Principal, PrincipalKind, ServiceScope},
};
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;
use uuid::Uuid;

const TOKEN: &str = "route-denial-contract-token-32-bytes";

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
    assert_eq!(cases.len(), 26, "route matrix must track the public API");
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
    assert!(!html.contains("<style"));
    assert_eq!(html.matches("<script").count(), 1);
    let app_js = include_str!("../ui/app.js");
    assert!(app_js.contains("byId(\"approval-id\").value = newUuid()"));
    assert!(app_js.contains("approval_id: byId(\"approval-id\").value.trim()"));
    assert_eq!(
        app_js.matches("crypto.randomUUID()").count(),
        1,
        "one logical approval ID must survive uncertain retries"
    );
    assert!(app_js.contains("crypto.getRandomValues(new Uint8Array(16))"));
    assert!(app_js.contains("async function loadAllLogs(base)"));
    assert!(app_js.contains("if (!page.next_after) return"));
    assert!(app_js.contains("after_fence"));
    assert!(app_js.contains("entry.content_hex"));
    assert!(app_js.contains("async function loadAllAudit()"));
    assert!(app_js.contains("page.next_after_sequence"));
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
            format!("{project}/builds"),
            "version: 1\nname: route-contract\nstages: []",
            Some("application/yaml"),
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
