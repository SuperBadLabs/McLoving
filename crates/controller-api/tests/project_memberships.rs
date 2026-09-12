//! PAR-003 through the public API: an Owner bootstrapped offline grants a
//! Viewer through the memberships route, revokes it, and the Viewer's
//! bearer is refused afterwards. The API runs as the controller's runtime
//! role against PostgreSQL; the bearers are real human sessions.

use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use axum::{Router, response::Response};
use mcloving_controller_api::{ApiState, router};
use mcloving_controller_store::authz::ProjectRole;
use mcloving_controller_store::{
    IdentityProviderWrite, MembershipAuthority, NewHumanIdentity, OidcIdentityClaims,
    ProjectRoleGrant, SessionIssue, Store,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tower::ServiceExt;
use uuid::Uuid;

async fn test_store() -> Option<Store> {
    let url = std::env::var("MCLOVING_TEST_DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .expect("connect to the configured PostgreSQL test database");
    let store = Store::new(pool);
    store.migrate().await.expect("install controller schema");
    Some(store)
}

async fn runtime_store(admin: &Store) -> Store {
    let mut setup = admin.pool().begin().await.expect("begin runtime setup");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind("mcloving.test.authorization-role-login")
        .execute(&mut *setup)
        .await
        .expect("serialize runtime setup");
    let can_login: bool =
        sqlx::query_scalar("SELECT rolcanlogin FROM pg_roles WHERE rolname = 'mcloving_tenant'")
            .fetch_one(&mut *setup)
            .await
            .expect("inspect runtime role");
    if !can_login {
        sqlx::query("ALTER ROLE mcloving_tenant LOGIN")
            .execute(&mut *setup)
            .await
            .expect("enable test runtime login");
    }
    setup.commit().await.expect("commit runtime setup");
    let options = std::env::var("MCLOVING_TEST_DATABASE_URL")
        .expect("database URL remains configured")
        .parse::<PgConnectOptions>()
        .expect("parse test database URL")
        .username("mcloving_tenant");
    Store::new(
        PgPoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await
            .expect("connect as runtime role"),
    )
}

fn digest(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

struct Tenant {
    organization_id: Uuid,
    project_id: Uuid,
    provider: IdentityProviderWrite,
}

async fn tenant(admin: &Store) -> Tenant {
    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    admin
        .create_project(
            organization_id,
            &format!("org-{organization_id}"),
            project_id,
            &format!("project-{project_id}"),
        )
        .await
        .expect("create project");
    let provider = IdentityProviderWrite {
        organization_id,
        provider_id: Uuid::new_v4(),
        issuer: "https://idp.par003-api.test".to_owned(),
        audience: "mcloving-par003".to_owned(),
        authorization_endpoint: "https://idp.par003-api.test/authorize".to_owned(),
        token_endpoint: "https://idp.par003-api.test/token".to_owned(),
        jwks_uri: "https://idp.par003-api.test/jwks".to_owned(),
        client_id: "mcloving-par003".to_owned(),
        group_claim: "groups".to_owned(),
        configuration_generation: 1,
        configuration_digest: digest("par003-api-provider"),
        jwks_generation: 1,
        jwks_digest: digest("par003-api-jwks"),
        enabled: true,
        actor_subject: "reviewer:par003".to_owned(),
    };
    admin
        .provision_identity_provider(&provider)
        .await
        .expect("provision provider");
    Tenant {
        organization_id,
        project_id,
        provider,
    }
}

async fn human(admin: &Store, tenant: &Tenant, name: &str) -> Uuid {
    let identity_id = Uuid::new_v4();
    admin
        .provision_human_identity(&NewHumanIdentity {
            organization_id: tenant.organization_id,
            identity_id,
            subject: format!("human:{name}"),
            provider_id: tenant.provider.provider_id,
            external_subject: format!("par003-api-{identity_id}"),
            source_realm_digest: digest("par003-source-realm"),
            source_identity_id: format!("jenkins-user-{name}"),
            source_membership_generation: 1,
            alias_history: Vec::new(),
            provenance_digest: digest("par003-provenance"),
            actor_subject: "reviewer:par003".to_owned(),
        })
        .await
        .expect("provision human identity");
    identity_id
}

/// A human session issued the way the OIDC callback issues one; answers the
/// raw bearer the API authenticates by digest.
async fn bearer(runtime: &Store, tenant: &Tenant, identity_id: Uuid, label: &str) -> String {
    let token = format!("par003-bearer-{label}-{identity_id}");
    runtime
        .issue_human_session(
            &OidcIdentityClaims {
                organization_id: tenant.organization_id,
                provider_id: tenant.provider.provider_id,
                issuer: tenant.provider.issuer.clone(),
                external_subject: format!("par003-api-{identity_id}"),
                groups: Vec::new(),
                provider_configuration_generation: tenant.provider.configuration_generation,
                provider_jwks_generation: tenant.provider.jwks_generation,
                id_token_digest: digest(&format!("{token}-id-token")),
            },
            &SessionIssue {
                session_id: Uuid::new_v4(),
                token_digest: Sha256::digest(token.as_bytes()).into(),
                refresh_token_digest: Some(digest(&format!("{token}-refresh"))),
                issued_at_unix_ms: 0,
                expires_at_unix_ms: i64::MAX / 2,
                refresh_expires_at_unix_ms: Some(i64::MAX / 2 + 1),
            },
        )
        .await
        .expect("issue human session");
    token
}

async fn call(
    app: &Router,
    method: Method,
    path: &str,
    bearer: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"));
    let body = match body {
        Some(body) => {
            request = request.header(header::CONTENT_TYPE, "application/json");
            Body::from(body.to_string())
        }
        None => Body::empty(),
    };
    let response: Response = app
        .clone()
        .oneshot(request.body(body).expect("request"))
        .await
        .expect("response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body");
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value)
}

#[tokio::test]
async fn owner_grants_and_revokes_a_viewer_whose_bearer_is_then_refused() {
    let Some(admin) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let tenant = tenant(&admin).await;
    let runtime = runtime_store(&admin).await;
    let app = router(ApiState::new_durable(runtime_store(&admin).await));
    let owner = human(&admin, &tenant, "owner").await;
    let admin_user = human(&admin, &tenant, "admin").await;
    let viewer = human(&admin, &tenant, "viewer").await;
    let organization_id = tenant.organization_id;
    let project_id = tenant.project_id;
    let memberships =
        format!("/api/v1/organizations/{organization_id}/projects/{project_id}/memberships");
    let pipelines =
        format!("/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines");

    // Nobody holds a role: the first Owner comes from the admin tool's path.
    admin
        .grant_project_role(&ProjectRoleGrant {
            organization_id,
            project_id,
            identity_id: owner,
            role: ProjectRole::Owner,
            authority: MembershipAuthority::Bootstrap,
            actor_subject: "operator:par003",
            reason: "bootstrap the project owner",
        })
        .await
        .expect("bootstrap owner");
    let owner_bearer = bearer(&runtime, &tenant, owner, "owner").await;

    // The Owner grants a Viewer through the memberships route.
    let (status, body) = call(
        &app,
        Method::PUT,
        &format!("{memberships}/{viewer}"),
        &owner_bearer,
        Some(json!({"role": "viewer", "reason": "PAR-003 proof"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["role"], "viewer");
    assert_eq!(body["outcome"], "granted");
    assert_eq!(body["granted_by"], "human:owner");
    let viewer_bearer = bearer(&runtime, &tenant, viewer, "viewer").await;
    let (status, _) = call(&app, Method::GET, &pipelines, &viewer_bearer, None).await;
    assert_eq!(status, StatusCode::OK, "the Viewer reads the project");
    let (status, _) = call(&app, Method::GET, &memberships, &viewer_bearer, None).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a Viewer does not read memberships"
    );

    // An Admin manages roles below Owner and nothing at Owner.
    let (status, _) = call(
        &app,
        Method::PUT,
        &format!("{memberships}/{admin_user}"),
        &owner_bearer,
        Some(json!({"role": "admin", "reason": "PAR-003 proof"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let admin_bearer = bearer(&runtime, &tenant, admin_user, "admin").await;
    let (status, body) = call(
        &app,
        Method::PUT,
        &format!("{memberships}/{viewer}"),
        &admin_bearer,
        Some(json!({"role": "owner", "reason": "PAR-003 proof"})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "project_role_denied");
    let (status, body) = call(
        &app,
        Method::DELETE,
        &format!("{memberships}/{owner}"),
        &admin_bearer,
        Some(json!({"reason": "PAR-003 proof"})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = call(
        &app,
        Method::DELETE,
        &format!("{memberships}/{owner}"),
        &owner_bearer,
        Some(json!({"reason": "PAR-003 proof"})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the last Owner stays: {body}"
    );

    // The memberships listing names the three.
    let (status, body) = call(&app, Method::GET, &memberships, &owner_bearer, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["memberships"]
            .as_array()
            .expect("memberships")
            .iter()
            .map(|membership| (
                membership["subject"].as_str().unwrap().to_owned(),
                membership["role"].as_str().unwrap().to_owned()
            ))
            .collect::<Vec<_>>(),
        vec![
            ("human:admin".to_owned(), "admin".to_owned()),
            ("human:owner".to_owned(), "owner".to_owned()),
            ("human:viewer".to_owned(), "viewer".to_owned()),
        ]
    );

    // The Owner revokes the Viewer; the Viewer's bearer is refused at once.
    let (status, body) = call(
        &app,
        Method::DELETE,
        &format!("{memberships}/{viewer}"),
        &owner_bearer,
        Some(json!({"reason": "PAR-003 proof"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["outcome"], "revoked");
    assert_eq!(body["previous_role"], "viewer");
    assert_eq!(body["fenced_generation"], 2);
    let (status, _) = call(&app, Method::GET, &pipelines, &viewer_bearer, None).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the revoked Viewer's bearer answers 401 on a build listing"
    );
    // A session issued afterwards authenticates but holds no role.
    let viewer_bearer = bearer(&runtime, &tenant, viewer, "viewer-after").await;
    let (status, _) = call(&app, Method::GET, &pipelines, &viewer_bearer, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
