use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::header::{CACHE_CONTROL, PRAGMA};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use mcloving_controller_store::{
    IdentityProviderConfig, LoginAttempt, OidcIdentityClaims, SessionIssue, StoreError,
};
use rand::RngCore;
use rand::rngs::OsRng;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{ApiError, ApiState, bearer_token, unix_time_ms};

const MAX_TOKEN_RESPONSE_BYTES: usize = 128 * 1024;
pub const MAX_OIDC_SESSION_TTL_SECONDS: u64 = 60 * 60;
pub const MAX_OIDC_REFRESH_TTL_SECONDS: u64 = 24 * 60 * 60;
pub const MAX_OIDC_REQUEST_TIMEOUT_SECONDS: u64 = 60;
pub const MAX_OIDC_CLOCK_SKEW_SECONDS: u64 = 5 * 60;
pub const MAX_OIDC_JWKS_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone)]
pub struct OidcClientConfig {
    pub organization_id: Uuid,
    pub provider_id: Uuid,
    pub configuration_generation: i64,
    pub configuration_digest: [u8; 32],
    pub client_secret: Option<String>,
    pub allowed_redirect_uris: BTreeSet<String>,
    pub session_ttl: Duration,
    pub refresh_ttl: Duration,
    pub request_timeout: Duration,
    pub clock_skew: Duration,
    pub max_jwks_bytes: usize,
    pub allow_insecure_loopback_for_tests: bool,
}

#[derive(Clone)]
pub(crate) struct OidcClient {
    config: OidcClientConfig,
    http: Client,
    start_attempts: Arc<Mutex<BTreeMap<IpAddr, VecDeque<Instant>>>>,
}

impl OidcClient {
    pub(crate) fn new(config: OidcClientConfig) -> Result<Self, ApiError> {
        if config.allowed_redirect_uris.is_empty()
            || config.configuration_generation <= 0
            || config.session_ttl.is_zero()
            || config.refresh_ttl <= config.session_ttl
            || config.request_timeout.is_zero()
            || config.max_jwks_bytes == 0
            || config.session_ttl.as_secs() > MAX_OIDC_SESSION_TTL_SECONDS
            || config.refresh_ttl.as_secs() > MAX_OIDC_REFRESH_TTL_SECONDS
            || config.request_timeout.as_secs() > MAX_OIDC_REQUEST_TIMEOUT_SECONDS
            || config.clock_skew.as_secs() > MAX_OIDC_CLOCK_SKEW_SECONDS
            || config.max_jwks_bytes > MAX_OIDC_JWKS_BYTES
        {
            return Err(ApiError::configuration(
                "OIDC client bounds or redirect allowlist are invalid",
            ));
        }
        if config
            .client_secret
            .as_ref()
            .is_some_and(|secret| secret.is_empty() || secret.len() > 8 * 1024)
        {
            return Err(ApiError::configuration(
                "OIDC client secret must be non-empty and at most 8192 bytes",
            ));
        }
        for redirect in &config.allowed_redirect_uris {
            secure_url(
                redirect,
                "OIDC redirect URI",
                config.allow_insecure_loopback_for_tests,
            )?;
        }
        let http = Client::builder()
            .timeout(config.request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| ApiError::configuration(error.to_string()))?;
        Ok(Self {
            config,
            http,
            start_attempts: Arc::new(Mutex::new(BTreeMap::new())),
        })
    }

    fn admit_start(&self, client: IpAddr) -> Result<(), ApiError> {
        const WINDOW: Duration = Duration::from_secs(60);
        const MAX_PER_WINDOW: usize = 60;
        const MAX_TRACKED_CLIENTS: usize = 4096;
        let now = Instant::now();
        let mut attempts = self
            .start_attempts
            .lock()
            .map_err(|_| ApiError::configuration("OIDC rate limiter is unavailable"))?;
        attempts.retain(|_, timestamps| {
            timestamps.retain(|timestamp| now.duration_since(*timestamp) < WINDOW);
            !timestamps.is_empty()
        });
        if !attempts.contains_key(&client) && attempts.len() >= MAX_TRACKED_CLIENTS {
            return Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "oidc_start_rate_limited",
                "OIDC login start rate limit exceeded",
            ));
        }
        let client_attempts = attempts.entry(client).or_default();
        if client_attempts.len() >= MAX_PER_WINDOW {
            return Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "oidc_start_rate_limited",
                "OIDC login start rate limit exceeded",
            ));
        }
        client_attempts.push_back(now);
        Ok(())
    }
}

#[derive(Deserialize)]
pub(crate) struct StartQuery {
    redirect_uri: String,
}

#[derive(Serialize)]
pub(crate) struct StartResponse {
    authorization_url: String,
    expires_in_seconds: u64,
}

#[derive(Deserialize)]
pub(crate) struct CallbackQuery {
    code: String,
    state: String,
}

#[derive(Serialize)]
pub(crate) struct SessionResponse {
    access_token: String,
    token_type: &'static str,
    expires_in_seconds: u64,
    refresh_token: String,
    refresh_expires_in_seconds: u64,
    identity_id: Uuid,
    session_id: Uuid,
}

#[derive(Deserialize)]
pub(crate) struct RefreshRequest {
    refresh_token: String,
}

#[derive(Serialize)]
pub(crate) struct LogoutResponse {
    revoked: bool,
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
}

#[derive(Deserialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    aud: Value,
    exp: u64,
    iat: u64,
    nonce: String,
    #[serde(default)]
    nbf: Option<u64>,
    #[serde(default)]
    azp: Option<String>,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

pub(crate) async fn start(
    State(state): State<std::sync::Arc<ApiState>>,
    ConnectInfo(client_address): ConnectInfo<SocketAddr>,
    Path((organization_id, provider_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<StartQuery>,
) -> Result<(HeaderMap, Json<StartResponse>), ApiError> {
    let client = runtime_client(&state, organization_id, provider_id)?;
    client.admit_start(client_address.ip())?;
    let provider = current_provider(&state, organization_id, provider_id, client).await?;
    if !client
        .config
        .allowed_redirect_uris
        .contains(&query.redirect_uri)
    {
        return Err(oidc_bad_request(
            "oidc_redirect_denied",
            "redirect URI is not in the exact OIDC allowlist",
        ));
    }
    validate_provider_urls(&provider, client.config.allow_insecure_loopback_for_tests)?;
    let state_token = random_token();
    let nonce = random_token();
    let verifier = random_token();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let expires_in = 10 * 60;
    let now = unix_time_ms();
    state
        .store
        .record_oidc_login_attempt(&LoginAttempt {
            organization_id,
            attempt_id: Uuid::new_v4(),
            provider_id,
            state_digest: digest(&state_token),
            nonce_digest: digest(&nonce),
            pkce_verifier: verifier,
            redirect_uri: query.redirect_uri.clone(),
            provider_configuration_generation: provider.configuration_generation,
            expires_at_unix_ms: now.saturating_add(expires_in * 1_000),
        })
        .await
        .map_err(identity_error)?;
    let mut authorization_url = Url::parse(&provider.authorization_endpoint)
        .map_err(|_| oidc_bad_request("oidc_provider_invalid", "authorization URL is invalid"))?;
    authorization_url.query_pairs_mut().extend_pairs([
        ("response_type", "code"),
        ("client_id", provider.client_id.as_str()),
        ("redirect_uri", query.redirect_uri.as_str()),
        ("scope", "openid profile groups"),
        ("state", state_token.as_str()),
        ("nonce", nonce.as_str()),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ]);
    Ok((
        no_store_headers(),
        Json(StartResponse {
            authorization_url: authorization_url.into(),
            expires_in_seconds: expires_in as u64,
        }),
    ))
}

pub(crate) async fn callback(
    State(state): State<std::sync::Arc<ApiState>>,
    Path((organization_id, provider_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<CallbackQuery>,
) -> Result<(HeaderMap, Json<SessionResponse>), ApiError> {
    if query.code.is_empty()
        || query.code.len() > 4 * 1024
        || query.state.len() < 32
        || query.state.len() > 512
    {
        return Err(oidc_bad_request(
            "oidc_callback_invalid",
            "OIDC code and state are required",
        ));
    }
    let client = runtime_client(&state, organization_id, provider_id)?;
    let now = unix_time_ms();
    let login = state
        .store
        .consume_oidc_login_attempt(organization_id, digest(&query.state), now)
        .await
        .map_err(identity_error)?;
    if login.provider_id != provider_id {
        return Err(oidc_bad_request(
            "oidc_provider_mismatch",
            "OIDC state is bound to another provider",
        ));
    }
    let provider = current_provider(&state, organization_id, provider_id, client).await?;
    validate_provider_urls(&provider, client.config.allow_insecure_loopback_for_tests)?;
    let mut token_request = client.http.post(&provider.token_endpoint).form(&[
        ("grant_type", "authorization_code"),
        ("code", query.code.as_str()),
        ("redirect_uri", login.redirect_uri.as_str()),
        ("client_id", provider.client_id.as_str()),
        ("code_verifier", login.pkce_verifier.as_str()),
    ]);
    if let Some(secret) = &client.config.client_secret {
        token_request = token_request.basic_auth(&provider.client_id, Some(secret));
    }
    let token_bytes = bounded_response(
        token_request.send().await,
        MAX_TOKEN_RESPONSE_BYTES,
        "OIDC token endpoint",
    )
    .await?;
    let token: TokenResponse = serde_json::from_slice(&token_bytes).map_err(|_| {
        oidc_bad_request(
            "oidc_token_invalid",
            "OIDC token response is malformed or lacks an ID token",
        )
    })?;
    let jwks_bytes = bounded_response(
        client.http.get(&provider.jwks_uri).send().await,
        client.config.max_jwks_bytes,
        "OIDC JWKS endpoint",
    )
    .await?;
    if digest_bytes(&jwks_bytes) != provider.jwks_digest {
        return Err(oidc_bad_request(
            "oidc_jwks_generation_mismatch",
            "OIDC JWKS bytes do not match the provisioned generation digest",
        ));
    }
    let claims = validate_id_token(
        &token.id_token,
        &jwks_bytes,
        &provider,
        login.nonce_digest,
        now,
        client.config.clock_skew,
    )?;
    let access_token = random_token();
    let refresh_token = random_token();
    let issue = session_issue(&client.config, &access_token, &refresh_token, now)?;
    let session = state
        .store
        .issue_human_session(
            &OidcIdentityClaims {
                organization_id,
                provider_id,
                issuer: claims.iss,
                external_subject: claims.sub,
                groups: claim_groups(&claims.extra, &provider.group_claim)?,
                provider_configuration_generation: provider.configuration_generation,
                provider_jwks_generation: provider.jwks_generation,
                id_token_digest: digest(&token.id_token),
            },
            &issue,
        )
        .await
        .map_err(identity_error)?;
    Ok((
        no_store_headers(),
        Json(session_response(
            &client.config,
            access_token,
            refresh_token,
            session.identity_id,
            session.session_id,
            session.refresh_expires_at_unix_ms,
            now,
        )),
    ))
}

pub(crate) async fn refresh(
    State(state): State<std::sync::Arc<ApiState>>,
    Path(organization_id): Path<Uuid>,
    Json(request): Json<RefreshRequest>,
) -> Result<(HeaderMap, Json<SessionResponse>), ApiError> {
    if request.refresh_token.len() < 32 || request.refresh_token.len() > 512 {
        return Err(oidc_bad_request(
            "oidc_refresh_invalid",
            "refresh credential is invalid",
        ));
    }
    let now = unix_time_ms();
    let access_token = random_token();
    let refresh_token = random_token();
    let current_refresh_digest = digest(&request.refresh_token);
    let provider_id = state
        .store
        .refresh_session_provider(organization_id, current_refresh_digest, now)
        .await
        .map_err(identity_error)?;
    let client = runtime_client(&state, organization_id, provider_id)?;
    current_provider(&state, organization_id, provider_id, client).await?;
    let config = client.config.clone();
    let issue = session_issue(&config, &access_token, &refresh_token, now)?;
    let session = state
        .store
        .rotate_human_session(organization_id, current_refresh_digest, &issue)
        .await
        .map_err(identity_error)?;
    Ok((
        no_store_headers(),
        Json(session_response(
            &config,
            access_token,
            refresh_token,
            session.identity_id,
            session.session_id,
            session.refresh_expires_at_unix_ms,
            now,
        )),
    ))
}

pub(crate) async fn logout(
    State(state): State<std::sync::Arc<ApiState>>,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Json<LogoutResponse>), ApiError> {
    let raw_token = bearer_token(&headers).ok_or_else(super::unauthorized)?;
    let authenticated = state
        .store
        .authenticate_api_token(organization_id, digest(raw_token), unix_time_ms())
        .await
        .map_err(|_| super::unauthorized())?;
    let Some(session_id) = authenticated.session_id else {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "oidc_session_required",
            "logout requires a human OIDC session",
        ));
    };
    let revoked = state
        .store
        .revoke_session(
            organization_id,
            session_id,
            unix_time_ms(),
            "logout",
            &authenticated.principal.subject,
        )
        .await
        .map_err(identity_error)?;
    Ok((no_store_headers(), Json(LogoutResponse { revoked })))
}

fn no_store_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
    headers
}

fn runtime_client(
    state: &ApiState,
    organization_id: Uuid,
    provider_id: Uuid,
) -> Result<&OidcClient, ApiError> {
    state
        .oidc_clients
        .get(&(organization_id, provider_id))
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "oidc_provider_unavailable",
                "OIDC provider is not configured on this controller",
            )
        })
}

async fn current_provider(
    state: &ApiState,
    organization_id: Uuid,
    provider_id: Uuid,
    client: &OidcClient,
) -> Result<IdentityProviderConfig, ApiError> {
    let provider = state
        .store
        .identity_provider_config(organization_id, provider_id)
        .await
        .map_err(identity_error)?;
    if !provider.enabled {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "oidc_provider_disabled",
            "OIDC provider is disabled",
        ));
    }
    if provider.configuration_generation != client.config.configuration_generation
        || provider.configuration_digest != client.config.configuration_digest
    {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "oidc_configuration_stale",
            "OIDC client configuration is stale on this controller",
        ));
    }
    Ok(provider)
}

fn validate_provider_urls(
    provider: &IdentityProviderConfig,
    allow_insecure_loopback: bool,
) -> Result<(), ApiError> {
    secure_url(&provider.issuer, "OIDC issuer", allow_insecure_loopback)?;
    secure_url(
        &provider.authorization_endpoint,
        "OIDC authorization endpoint",
        allow_insecure_loopback,
    )?;
    secure_url(
        &provider.token_endpoint,
        "OIDC token endpoint",
        allow_insecure_loopback,
    )?;
    secure_url(&provider.jwks_uri, "OIDC JWKS URI", allow_insecure_loopback)?;
    Ok(())
}

fn secure_url(raw: &str, label: &str, allow_insecure_loopback: bool) -> Result<Url, ApiError> {
    let url = Url::parse(raw)
        .map_err(|_| ApiError::configuration(format!("{label} is not an absolute URL")))?;
    let loopback_http = url.scheme() == "http"
        && url.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
    if url.scheme() != "https" && !(allow_insecure_loopback && loopback_http) {
        return Err(ApiError::configuration(format!(
            "{label} must use HTTPS (loopback HTTP is test-only)"
        )));
    }
    if url.username() != "" || url.password().is_some() || url.fragment().is_some() {
        return Err(ApiError::configuration(format!(
            "{label} must not contain userinfo or a fragment"
        )));
    }
    Ok(url)
}

async fn bounded_response(
    response: Result<reqwest::Response, reqwest::Error>,
    limit: usize,
    label: &str,
) -> Result<Vec<u8>, ApiError> {
    let mut response = response.map_err(|_| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "oidc_provider_unavailable",
            format!("{label} is unavailable"),
        )
    })?;
    if !response.status().is_success() {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "oidc_provider_rejected",
            format!("{label} rejected the request"),
        ));
    }
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(oidc_bad_request(
            "oidc_response_oversized",
            "OIDC provider response exceeds the configured bound",
        ));
    }
    let mut bytes = Vec::new();
    loop {
        let chunk = response.chunk().await.map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "oidc_provider_unavailable",
                format!("{label} response could not be read"),
            )
        })?;
        let Some(chunk) = chunk else {
            break;
        };
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err(oidc_bad_request(
                "oidc_response_oversized",
                "OIDC provider response exceeds the configured bound",
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn validate_id_token(
    raw: &str,
    jwks_bytes: &[u8],
    provider: &IdentityProviderConfig,
    expected_nonce_digest: [u8; 32],
    now_unix_ms: i64,
    clock_skew: Duration,
) -> Result<IdTokenClaims, ApiError> {
    let header = decode_header(raw).map_err(|_| invalid_id_token())?;
    if !matches!(
        header.alg,
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512
    ) {
        return Err(invalid_id_token());
    }
    let kid = header.kid.as_deref().ok_or_else(invalid_id_token)?;
    let set: JwkSet = serde_json::from_slice(jwks_bytes).map_err(|_| invalid_id_token())?;
    let matching_keys = set
        .keys
        .iter()
        .filter(|key| key.common.key_id.as_deref() == Some(kid))
        .collect::<Vec<_>>();
    if matching_keys.len() != 1 {
        return Err(invalid_id_token());
    }
    let jwk = matching_keys[0];
    let key = DecodingKey::from_jwk(jwk).map_err(|_| invalid_id_token())?;
    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[provider.issuer.as_str()]);
    validation.set_audience(&[provider.audience.as_str()]);
    validation.leeway = clock_skew.as_secs();
    validation.validate_exp = true;
    validation.validate_nbf = true;
    let claims = decode::<IdTokenClaims>(raw, &key, &validation)
        .map_err(|_| invalid_id_token())?
        .claims;
    let now_seconds = u64::try_from(now_unix_ms.max(0) / 1_000).unwrap_or(u64::MAX);
    if claims.iss != provider.issuer
        || claims.sub.is_empty()
        || claims.sub.trim() != claims.sub
        || claims.sub.len() > 512
        || claims.iat > now_seconds.saturating_add(clock_skew.as_secs())
        || claims.exp.saturating_add(clock_skew.as_secs()) < now_seconds
        || claims
            .nbf
            .is_some_and(|nbf| nbf > now_seconds.saturating_add(clock_skew.as_secs()))
        || digest(&claims.nonce) != expected_nonce_digest
    {
        return Err(invalid_id_token());
    }
    // Retain and inspect the claim so serde cannot silently accept an absent or
    // structurally invalid audience. OIDC requires the authorized party for a
    // multi-audience token, and any supplied value must name this client.
    if !authorized_party_matches(&claims.aud, claims.azp.as_deref(), &provider.client_id) {
        return Err(invalid_id_token());
    }
    Ok(claims)
}

fn authorized_party_matches(
    audience: &Value,
    authorized_party: Option<&str>,
    client_id: &str,
) -> bool {
    let audience_count = match audience {
        Value::String(value) if !value.is_empty() => 1,
        Value::Array(values)
            if !values.is_empty()
                && values
                    .iter()
                    .all(|value| value.as_str().is_some_and(|value| !value.is_empty())) =>
        {
            values.len()
        }
        _ => return false,
    };
    match authorized_party {
        Some(value) => value == client_id,
        None => audience_count == 1,
    }
}

fn claim_groups(
    claims: &BTreeMap<String, Value>,
    group_claim: &str,
) -> Result<Vec<String>, ApiError> {
    let Some(value) = claims.get(group_claim) else {
        return Err(invalid_id_token());
    };
    let groups = value.as_array().ok_or_else(invalid_id_token)?;
    if groups.len() > 4096 {
        return Err(invalid_id_token());
    }
    groups
        .iter()
        .map(|group| {
            group
                .as_str()
                .filter(|group| {
                    !group.is_empty()
                        && group.trim() == *group
                        && group.len() <= 512
                        && !group.contains('\0')
                })
                .map(str::to_owned)
                .ok_or_else(invalid_id_token)
        })
        .collect()
}

fn session_issue(
    config: &OidcClientConfig,
    access_token: &str,
    refresh_token: &str,
    now: i64,
) -> Result<SessionIssue, ApiError> {
    let session_ms = i64::try_from(config.session_ttl.as_millis())
        .map_err(|_| ApiError::configuration("OIDC session TTL is too large"))?;
    let refresh_ms = i64::try_from(config.refresh_ttl.as_millis())
        .map_err(|_| ApiError::configuration("OIDC refresh TTL is too large"))?;
    Ok(SessionIssue {
        session_id: Uuid::new_v4(),
        token_digest: digest(access_token),
        refresh_token_digest: Some(digest(refresh_token)),
        issued_at_unix_ms: now,
        expires_at_unix_ms: now.saturating_add(session_ms),
        refresh_expires_at_unix_ms: Some(now.saturating_add(refresh_ms)),
    })
}

fn session_response(
    config: &OidcClientConfig,
    access_token: String,
    refresh_token: String,
    identity_id: Uuid,
    session_id: Uuid,
    refresh_expires_at_unix_ms: Option<i64>,
    now_unix_ms: i64,
) -> SessionResponse {
    SessionResponse {
        access_token,
        token_type: "Bearer",
        expires_in_seconds: config.session_ttl.as_secs(),
        refresh_token,
        refresh_expires_in_seconds: refresh_expires_at_unix_ms
            .map(|expiry| u64::try_from(expiry.saturating_sub(now_unix_ms) / 1_000).unwrap_or(0))
            .unwrap_or(0),
        identity_id,
        session_id,
    }
}

fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn digest(value: &str) -> [u8; 32] {
    digest_bytes(value.as_bytes())
}

fn digest_bytes(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

fn invalid_id_token() -> ApiError {
    ApiError::new(
        StatusCode::UNAUTHORIZED,
        "oidc_id_token_invalid",
        "OIDC ID token validation failed",
    )
}

fn identity_error(error: StoreError) -> ApiError {
    match error {
        StoreError::InvalidIdentityOperation(message) => {
            oidc_bad_request("identity_invalid", message)
        }
        StoreError::IdentityConflict(message) => {
            ApiError::new(StatusCode::UNAUTHORIZED, "identity_conflict", message)
        }
        other => super::internal(other),
    }
}

fn oidc_bad_request(code: &'static str, message: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, code, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorized_party_is_required_for_multiple_audiences_and_exact_when_present() {
        let one = serde_json::json!("mcloving");
        assert!(authorized_party_matches(&one, None, "mcloving"));
        assert!(authorized_party_matches(&one, Some("mcloving"), "mcloving"));
        assert!(!authorized_party_matches(&one, Some("other"), "mcloving"));

        let many = serde_json::json!(["mcloving", "other"]);
        assert!(!authorized_party_matches(&many, None, "mcloving"));
        assert!(authorized_party_matches(
            &many,
            Some("mcloving"),
            "mcloving"
        ));
        assert!(!authorized_party_matches(&many, Some("other"), "mcloving"));
    }
}
