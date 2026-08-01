use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::{Body, to_bytes};
use axum::extract::{ConnectInfo, Form, State};
use axum::http::{Request, StatusCode, header};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use mcloving_controller_api::{ApiState, OidcClientConfig, router};
use mcloving_controller_store::{IdentityProviderWrite, NewHumanIdentity, Store};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tokio::net::TcpListener;
use tower::ServiceExt;
use uuid::Uuid;

#[derive(Clone)]
struct FakeIdp {
    issuer: String,
    expected: Arc<Mutex<Option<ExpectedExchange>>>,
    jwks: Arc<Vec<u8>>,
    private_key_pem: Arc<Vec<u8>>,
}

struct ExpectedExchange {
    nonce: String,
    challenge: String,
    redirect_uri: String,
    groups: Vec<String>,
}

#[derive(Serialize)]
struct TestClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: u64,
    iat: u64,
    nonce: String,
    groups: Vec<String>,
}

async fn token(
    State(state): State<FakeIdp>,
    Form(form): Form<BTreeMap<String, String>>,
) -> Result<Json<Value>, StatusCode> {
    let expected = state
        .expected
        .lock()
        .expect("fake IdP exchange lock")
        .take()
        .ok_or(StatusCode::BAD_REQUEST)?;
    if form.get("grant_type").map(String::as_str) != Some("authorization_code")
        || form.get("code").map(String::as_str) != Some("valid-code")
        || form.get("redirect_uri") != Some(&expected.redirect_uri)
        || form.get("client_id").map(String::as_str) != Some("mcloving-test")
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let verifier = form.get("code_verifier").ok_or(StatusCode::BAD_REQUEST)?;
    let actual_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    if actual_challenge != expected.challenge {
        return Err(StatusCode::BAD_REQUEST);
    }
    let now = unix_seconds();
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key".to_owned());
    let id_token = encode(
        &header,
        &TestClaims {
            iss: state.issuer,
            sub: "immutable-source-user-42".to_owned(),
            aud: "mcloving-test".to_owned(),
            exp: now + 300,
            iat: now,
            nonce: expected.nonce,
            groups: expected.groups,
        },
        &EncodingKey::from_rsa_pem(state.private_key_pem.as_ref())
            .expect("parse generated test RSA key"),
    )
    .expect("sign contained test ID token");
    Ok(Json(json!({"id_token": id_token})))
}

async fn jwks(State(state): State<FakeIdp>) -> Vec<u8> {
    state.jwks.as_ref().clone()
}

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
        .bind("mcloving.test.oidc-role-login")
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

async fn oidc_app(
    admin: &Store,
    organization_id: Uuid,
    provider_id: Uuid,
    configuration_generation: i64,
    configuration_digest: [u8; 32],
    redirect_uri: &str,
) -> Router {
    router(
        ApiState::new_durable(runtime_store(admin).await)
            .with_oidc_client(OidcClientConfig {
                organization_id,
                provider_id,
                configuration_generation,
                configuration_digest,
                client_secret: Some("contained-client-secret".to_owned()),
                allowed_redirect_uris: BTreeSet::from([redirect_uri.to_owned()]),
                session_ttl: Duration::from_secs(300),
                refresh_ttl: Duration::from_secs(900),
                request_timeout: Duration::from_secs(2),
                clock_skew: Duration::from_secs(5),
                max_jwks_bytes: 64 * 1024,
                allow_insecure_loopback_for_tests: true,
            })
            .expect("configure contained OIDC client"),
    )
}

#[tokio::test]
async fn oidc_pkce_refresh_group_fencing_and_logout_are_end_to_end() {
    let Some(admin) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let (private_key_pem, jwk_n) = generated_rsa_key();
    let jwk_e = "AQAB";
    let jwks_bytes = serde_json::to_vec(&json!({
        "keys": [{
            "kty": "RSA",
            "kid": "test-key",
            "use": "sig",
            "alg": "RS256",
            "n": jwk_n,
            "e": jwk_e
        }]
    }))
    .expect("serialize contained JWKS");
    let expected = Arc::new(Mutex::new(None));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind contained IdP");
    let base = format!("http://{}", listener.local_addr().expect("IdP address"));
    let idp = FakeIdp {
        issuer: base.clone(),
        expected: expected.clone(),
        jwks: Arc::new(jwks_bytes.clone()),
        private_key_pem: Arc::new(private_key_pem),
    };
    let idp_server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/token", post(token))
                .route("/jwks", get(jwks))
                .with_state(idp),
        )
        .await
        .expect("serve contained IdP");
    });

    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    admin
        .create_project(
            organization_id,
            &format!("oidc-{organization_id}"),
            project_id,
            "oidc-project",
        )
        .await
        .expect("create OIDC tenant");
    let provider_id = Uuid::new_v4();
    let configuration_digest = Sha256::digest(b"test-provider-v1").into();
    let provider = IdentityProviderWrite {
        organization_id,
        provider_id,
        issuer: base.clone(),
        audience: "mcloving-test".to_owned(),
        authorization_endpoint: format!("{base}/authorize"),
        token_endpoint: format!("{base}/token"),
        jwks_uri: format!("{base}/jwks"),
        client_id: "mcloving-test".to_owned(),
        group_claim: "groups".to_owned(),
        configuration_generation: 1,
        configuration_digest,
        jwks_generation: 1,
        jwks_digest: Sha256::digest(&jwks_bytes).into(),
        enabled: true,
        actor_subject: "test:operator".to_owned(),
    };
    admin
        .provision_identity_provider(&provider)
        .await
        .expect("provision contained OIDC provider");
    let identity_id = Uuid::new_v4();
    admin
        .provision_human_identity(&NewHumanIdentity {
            organization_id,
            identity_id,
            subject: format!("oidc:{identity_id}"),
            provider_id,
            external_subject: "immutable-source-user-42".to_owned(),
            source_realm_digest: Sha256::digest(b"jenkins-security-realm").into(),
            source_identity_id: "jenkins-user-id-42".to_owned(),
            source_membership_generation: 8,
            alias_history: vec!["old-login".to_owned()],
            provenance_digest: Sha256::digest(b"mig-000-identity-edge").into(),
            actor_subject: "test:operator".to_owned(),
        })
        .await
        .expect("provision immutable source-to-target identity edge");
    sqlx::query(
        "INSERT INTO project_memberships(identity_id, organization_id, project_id, role)
         VALUES ($1,$2,$3,'viewer')",
    )
    .bind(identity_id)
    .bind(organization_id)
    .bind(project_id)
    .execute(admin.pool())
    .await
    .expect("provision reviewed project role");

    let redirect_uri = "http://127.0.0.1/callback";
    let app = oidc_app(
        &admin,
        organization_id,
        provider_id,
        1,
        configuration_digest,
        redirect_uri,
    )
    .await;

    let first = login(
        app.clone(),
        organization_id,
        provider_id,
        redirect_uri,
        &expected,
        vec!["developers".to_owned()],
    )
    .await;
    assert_eq!(first["identity_id"], identity_id.to_string());
    let first_access = first["access_token"].as_str().expect("first access token");
    assert_eq!(
        project_read(app.clone(), organization_id, project_id, first_access).await,
        StatusCode::OK
    );
    assert_eq!(
        project_read(app.clone(), Uuid::new_v4(), project_id, first_access).await,
        StatusCode::UNAUTHORIZED,
        "a session must never cross tenants"
    );

    let second = login(
        app.clone(),
        organization_id,
        provider_id,
        redirect_uri,
        &expected,
        vec!["operators".to_owned()],
    )
    .await;
    assert_eq!(
        project_read(app.clone(), organization_id, project_id, first_access).await,
        StatusCode::UNAUTHORIZED,
        "a group-generation change immediately fences old sessions"
    );
    let second_access = second["access_token"]
        .as_str()
        .expect("second access token");
    let second_refresh = second["refresh_token"].as_str().expect("refresh token");
    let refresh_response = app
        .clone()
        .oneshot(
            Request::post(format!(
                "/api/v1/organizations/{organization_id}/auth/session/refresh"
            ))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({"refresh_token": second_refresh}).to_string(),
            ))
            .expect("refresh request"),
        )
        .await
        .expect("refresh response");
    assert_eq!(refresh_response.status(), StatusCode::OK);
    assert_no_store(&refresh_response);
    let refreshed: Value = serde_json::from_slice(
        &to_bytes(refresh_response.into_body(), 64 * 1024)
            .await
            .expect("refresh response body"),
    )
    .expect("parse refresh response");
    assert_eq!(
        project_read(app.clone(), organization_id, project_id, second_access).await,
        StatusCode::UNAUTHORIZED,
        "refresh rotation revokes the replaced access token"
    );
    let refreshed_access = refreshed["access_token"]
        .as_str()
        .expect("refreshed access token");
    let logout_response = app
        .clone()
        .oneshot(
            Request::post(format!(
                "/api/v1/organizations/{organization_id}/auth/session/logout"
            ))
            .header(header::AUTHORIZATION, format!("Bearer {refreshed_access}"))
            .body(Body::empty())
            .expect("logout request"),
        )
        .await
        .expect("logout response");
    assert_eq!(logout_response.status(), StatusCode::OK);
    assert_no_store(&logout_response);
    assert_eq!(
        project_read(app.clone(), organization_id, project_id, refreshed_access).await,
        StatusCode::UNAUTHORIZED,
        "logout revokes the durable session across controllers"
    );
    let next_configuration_digest = Sha256::digest(b"test-provider-v2").into();
    admin
        .provision_identity_provider(&IdentityProviderWrite {
            configuration_generation: 2,
            configuration_digest: next_configuration_digest,
            ..provider.clone()
        })
        .await
        .expect("advance the durable provider configuration");
    assert_eq!(
        start_status(app.clone(), organization_id, provider_id, redirect_uri).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "a replica with stale local OIDC configuration must fail closed"
    );
    let fresh_app = oidc_app(
        &admin,
        organization_id,
        provider_id,
        2,
        next_configuration_digest,
        redirect_uri,
    )
    .await;
    let callback_state = begin_login(
        fresh_app.clone(),
        organization_id,
        provider_id,
        redirect_uri,
        &expected,
        vec!["operators".to_owned()],
    )
    .await;
    assert_eq!(
        callback_status(app, organization_id, provider_id, &callback_state).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "a stale replica must reject before consuming fresh callback state"
    );
    assert_eq!(
        callback_status(fresh_app, organization_id, provider_id, &callback_state).await,
        StatusCode::OK,
        "the fresh replica must be able to retry the unconsumed callback"
    );
    idp_server.abort();
}

async fn start_status(
    app: Router,
    organization_id: Uuid,
    provider_id: Uuid,
    redirect_uri: &str,
) -> StatusCode {
    let mut start_url = reqwest::Url::parse("http://mcloving.invalid").expect("base URL");
    start_url.set_path(&format!(
        "/api/v1/organizations/{organization_id}/auth/oidc/{provider_id}/start"
    ));
    start_url
        .query_pairs_mut()
        .append_pair("redirect_uri", redirect_uri);
    app.oneshot(
        Request::get(format!(
            "{}?{}",
            start_url.path(),
            start_url.query().expect("start query")
        ))
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 43_123))))
        .body(Body::empty())
        .expect("start request"),
    )
    .await
    .expect("start response")
    .status()
}

async fn login(
    app: Router,
    organization_id: Uuid,
    provider_id: Uuid,
    redirect_uri: &str,
    expected: &Arc<Mutex<Option<ExpectedExchange>>>,
    groups: Vec<String>,
) -> Value {
    let state = begin_login(
        app.clone(),
        organization_id,
        provider_id,
        redirect_uri,
        expected,
        groups,
    )
    .await;
    let callback = callback_response(app, organization_id, provider_id, &state).await;
    assert_eq!(callback.status(), StatusCode::OK);
    assert_no_store(&callback);
    serde_json::from_slice(
        &to_bytes(callback.into_body(), 64 * 1024)
            .await
            .expect("callback body"),
    )
    .expect("parse callback response")
}

async fn begin_login(
    app: Router,
    organization_id: Uuid,
    provider_id: Uuid,
    redirect_uri: &str,
    expected: &Arc<Mutex<Option<ExpectedExchange>>>,
    groups: Vec<String>,
) -> String {
    let mut start_url = reqwest::Url::parse("http://mcloving.invalid").expect("base URL");
    start_url.set_path(&format!(
        "/api/v1/organizations/{organization_id}/auth/oidc/{provider_id}/start"
    ));
    start_url
        .query_pairs_mut()
        .append_pair("redirect_uri", redirect_uri);
    let start = app
        .clone()
        .oneshot(
            Request::get(format!(
                "{}?{}",
                start_url.path(),
                start_url.query().expect("start query")
            ))
            .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 43_123))))
            .body(Body::empty())
            .expect("start request"),
        )
        .await
        .expect("start response");
    assert_eq!(start.status(), StatusCode::OK);
    assert_no_store(&start);
    let start: Value = serde_json::from_slice(
        &to_bytes(start.into_body(), 64 * 1024)
            .await
            .expect("start response body"),
    )
    .expect("parse start response");
    let authorization = reqwest::Url::parse(
        start["authorization_url"]
            .as_str()
            .expect("authorization URL"),
    )
    .expect("parse authorization URL");
    let query = authorization
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<BTreeMap<_, _>>();
    *expected.lock().expect("fake IdP exchange lock") = Some(ExpectedExchange {
        nonce: query["nonce"].clone(),
        challenge: query["code_challenge"].clone(),
        redirect_uri: redirect_uri.to_owned(),
        groups,
    });
    query["state"].clone()
}

async fn callback_response(
    app: Router,
    organization_id: Uuid,
    provider_id: Uuid,
    state: &str,
) -> axum::response::Response {
    app
        .oneshot(
            Request::get(format!(
                "/api/v1/organizations/{organization_id}/auth/oidc/{provider_id}/callback?code=valid-code&state={}",
                state
            ))
            .body(Body::empty())
            .expect("callback request"),
        )
        .await
        .expect("callback response")
}

async fn callback_status(
    app: Router,
    organization_id: Uuid,
    provider_id: Uuid,
    state: &str,
) -> StatusCode {
    callback_response(app, organization_id, provider_id, state)
        .await
        .status()
}

async fn project_read(
    app: Router,
    organization_id: Uuid,
    project_id: Uuid,
    token: &str,
) -> StatusCode {
    app.oneshot(
        Request::get(format!(
            "/api/v1/organizations/{organization_id}/projects/{project_id}/pipelines"
        ))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("project read request"),
    )
    .await
    .expect("project read response")
    .status()
}

fn assert_no_store(response: &axum::response::Response) {
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL),
        Some(&header::HeaderValue::from_static("no-store"))
    );
    assert_eq!(
        response.headers().get(header::PRAGMA),
        Some(&header::HeaderValue::from_static("no-cache"))
    );
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn generated_rsa_key() -> (Vec<u8>, String) {
    let generated = Command::new("openssl")
        .args([
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-pkeyopt",
            "rsa_keygen_pubexp:65537",
        ])
        .output()
        .expect("run OpenSSL test-key generator");
    assert!(
        generated.status.success(),
        "OpenSSL test-key generation failed: {}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let private_key_pem = openssl_with_input(&["rsa", "-traditional"], &generated.stdout);
    let modulus = openssl_with_input(&["rsa", "-noout", "-modulus"], &private_key_pem);
    let modulus = std::str::from_utf8(&modulus)
        .expect("OpenSSL modulus is UTF-8")
        .trim()
        .strip_prefix("Modulus=")
        .expect("OpenSSL modulus prefix");
    assert_eq!(modulus.len() % 2, 0, "OpenSSL modulus has complete bytes");
    let modulus = (0..modulus.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&modulus[index..index + 2], 16)
                .expect("OpenSSL modulus is hexadecimal")
        })
        .collect::<Vec<_>>();
    (
        private_key_pem,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(modulus),
    )
}

fn openssl_with_input(arguments: &[&str], input: &[u8]) -> Vec<u8> {
    let mut child = Command::new("openssl")
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start OpenSSL test-key command");
    child
        .stdin
        .take()
        .expect("OpenSSL stdin")
        .write_all(input)
        .expect("write generated key to OpenSSL");
    let output = child.wait_with_output().expect("wait for OpenSSL");
    assert!(
        output.status.success(),
        "OpenSSL test-key command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}
