use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
#[cfg(debug_assertions)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use mcloving_agent_protocol::wire::agent_control_server::{AgentControl, AgentControlServer};
use mcloving_agent_protocol::wire::{
    AttemptAuthority, CancellationCompletion, CancellationDisposition, CancellationOutcome,
    CancellationReceipt, CredentialBinding, CredentialEnvelope, CredentialRequest,
    OpenSessionRequest, OpenSessionResponse, ReconciliationDirective, ReconciliationReport,
    RotateCertificateRequest, RotateCertificateResponse, WorkAssignment, WorkAuthority,
    WorkCompletion, WorkLeaseReceipt, WorkLeaseRenewal, WorkLogChunk, WorkOffer, WorkOutcome,
    WorkPoll, WorkReceipt,
};
use mcloving_agent_protocol::{
    ATTEMPT_CREDENTIALS_FEATURE, CURRENT_SESSION_EPOCH_METADATA, ProtocolRange,
    RECOVERED_FINALIZATION_LEASE_SECONDS, WORK_DELIVERY_FEATURE, negotiate,
};
use mcloving_controller_api::{
    ApiState, ConnectorMappingCatalog, MAX_OIDC_CLOCK_SKEW_SECONDS, MAX_OIDC_JWKS_BYTES,
    MAX_OIDC_REFRESH_TTL_SECONDS, MAX_OIDC_REQUEST_TIMEOUT_SECONDS, MAX_OIDC_SESSION_TTL_SECONDS,
    OidcClientConfig, router,
};
use mcloving_controller_store::{
    AgentCancellationCompletion, AgentCancellationDisposition, AgentCancellationOutcome,
    AgentReconciliationDisposition, ClaimRequest, IdentityProviderWrite, LeaseRenewalDisposition,
    NewLogChunk, NewServiceCredential, NewServiceIdentity, ReconciliationTrustPoolAuthorization,
    Store, StoreError, TerminalOutcome, authz::ServiceScope,
};
use mcloving_execution_spine::{EffectExecutionPlan, WorkerConfig, preflight_worker, run_claim};
use mcloving_object_store::{FilesystemObjectStore, Quota};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};
use uuid::Uuid;

fn validate_artifact_agent_token(api_token: &str, artifact_agent_token: &str) -> Result<()> {
    if artifact_agent_token.len() < 32 {
        bail!("MCLOVING_ARTIFACT_AGENT_TOKEN must contain at least 32 bytes");
    }
    if api_token == artifact_agent_token {
        bail!("MCLOVING_API_TOKEN and MCLOVING_ARTIFACT_AGENT_TOKEN must be distinct");
    }
    Ok(())
}

fn validate_effect_mapping_configuration(
    executable_mapping: Option<(&str, &str)>,
    catalog: Option<&ConnectorMappingCatalog>,
) -> Result<()> {
    match (executable_mapping, catalog) {
        (Some((mapping_id, mapping_digest)), Some(catalog))
            if catalog.mappings.len() == 1
                && catalog.contains_exact(mapping_id, mapping_digest) =>
        {
            Ok(())
        }
        (Some(_), Some(_)) => {
            bail!("effect mapping catalog must contain exactly the executable runtime mapping")
        }
        (Some(_), None) => {
            bail!("MCLOVING_EFFECT_MAPPING_CATALOG is required with an effect runtime plan")
        }
        (None, Some(_)) => {
            bail!("effect mapping catalog cannot advertise a mapping without an executable plan")
        }
        (None, None) => Ok(()),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let migration_database_url = std::env::var("MCLOVING_MIGRATION_DATABASE_URL")
        .context("MCLOVING_MIGRATION_DATABASE_URL is required")?;
    let runtime_database_url =
        std::env::var("MCLOVING_DATABASE_URL").context("MCLOVING_DATABASE_URL is required")?;
    if migration_database_url == runtime_database_url {
        bail!("migration and runtime database credentials must be distinct");
    }
    if std::env::var_os("MCLOVING_API_PRINCIPALS_PATH").is_some() {
        bail!(
            "MCLOVING_API_PRINCIPALS_PATH is retired; provision immutable OIDC identities instead"
        );
    }
    let bearer_token =
        std::env::var("MCLOVING_API_TOKEN").context("MCLOVING_API_TOKEN is required")?;
    if bearer_token.len() < 32 {
        bail!("MCLOVING_API_TOKEN must contain at least 32 bytes");
    }
    let bearer_generation = std::env::var("MCLOVING_API_TOKEN_GENERATION")
        .unwrap_or_else(|_| "1".to_owned())
        .parse::<i64>()
        .context("MCLOVING_API_TOKEN_GENERATION must be a positive integer")?;
    if bearer_generation <= 0 {
        bail!("MCLOVING_API_TOKEN_GENERATION must be positive");
    }
    let artifact_agent_token = std::env::var("MCLOVING_ARTIFACT_AGENT_TOKEN")
        .context("MCLOVING_ARTIFACT_AGENT_TOKEN is required")?;
    validate_artifact_agent_token(&bearer_token, &artifact_agent_token)?;
    let artifact_agent_digest: [u8; 32] = Sha256::digest(artifact_agent_token.as_bytes()).into();
    let listen = std::env::var("MCLOVING_LISTEN").unwrap_or_else(|_| "127.0.0.1:8080".to_owned());
    let worker = EmbeddedWorker::from_environment()?;
    let connector_mapping_catalog = connector_mapping_catalog_from_environment()?;
    validate_effect_mapping_configuration(
        worker.config.effect_plan.as_ref().map(|plan| {
            (
                plan.freeze.mapping_id.as_str(),
                plan.freeze.mapping_digest.as_str(),
            )
        }),
        connector_mapping_catalog.as_ref(),
    )?;
    let oidc = oidc_environment(worker.organization_id)?;
    let object_root = PathBuf::from(
        std::env::var("MCLOVING_OBJECT_ROOT").unwrap_or_else(|_| "./data/objects".to_owned()),
    );
    let max_object_bytes = bounded_u64_environment("MCLOVING_MAX_OBJECT_BYTES", 64 * 1024 * 1024)?;
    let max_total_bytes =
        bounded_u64_environment("MCLOVING_MAX_TOTAL_OBJECT_BYTES", 10 * 1024 * 1024 * 1024)?;
    let max_staged_objects = bounded_u64_environment("MCLOVING_MAX_STAGED_OBJECTS", 4_096)?;
    let staged_upload_ttl = Duration::from_secs(bounded_u64_environment(
        "MCLOVING_STAGED_UPLOAD_TTL_SECONDS",
        24 * 60 * 60,
    )?);
    let outbox_retention_hours = u32::try_from(bounded_u64_environment_at_most(
        "MCLOVING_OUTBOX_RETENTION_HOURS",
        DEFAULT_OUTBOX_RETENTION_HOURS,
        MAX_OUTBOX_RETENTION_HOURS,
    )?)
    .context("MCLOVING_OUTBOX_RETENTION_HOURS must fit in 32 bits")?;
    if max_total_bytes < max_object_bytes {
        bail!("MCLOVING_MAX_TOTAL_OBJECT_BYTES must be at least MCLOVING_MAX_OBJECT_BYTES");
    }
    let object_store = FilesystemObjectStore::open(
        &object_root,
        Quota {
            max_object_bytes,
            max_total_bytes,
            max_staged_objects,
        },
    )
    .with_context(|| format!("open artifact object store at {}", object_root.display()))?;
    preflight_worker(&worker.config)
        .await
        .context("preflight embedded worker runtime")?;
    let listener = TcpListener::bind(&listen)
        .await
        .with_context(|| format!("bind controller to {listen}"))?;
    let agent_control = agent_control_environment().await?;
    let migration_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&migration_database_url)
        .await
        .context("connect to PostgreSQL migration role")?;
    let migration_store = Store::new(migration_pool.clone());
    migration_store
        .migrate()
        .await
        .context("migrate controller store")?;
    let runtime_pool = PgPoolOptions::new()
        .max_connections(16)
        .connect(&runtime_database_url)
        .await
        .context("connect to PostgreSQL runtime role")?;
    let store = Store::new(runtime_pool);
    store
        .preflight_tenant_runtime(&migration_store, worker.organization_id)
        .await
        .context("preflight PostgreSQL runtime tenant access")?;
    let mut state = ApiState::new_durable(store.clone());
    if let Some(catalog) = connector_mapping_catalog {
        state = state
            .with_connector_mapping_catalog(catalog)
            .context("configure connector mapping admission catalog")?;
    }
    if let Some(oidc) = &oidc {
        state = state
            .with_oidc_client(oidc.client.clone())
            .context("configure OIDC authorization-code client")?;
    }
    let api_identity_id = deterministic_uuid(&format!(
        "mcloving:service:public-api:{}",
        worker.organization_id
    ));
    let api_subject = format!("service:public-api:{api_identity_id}");
    migration_store
        .provision_service_identity(&NewServiceIdentity {
            organization_id: worker.organization_id,
            identity_id: api_identity_id,
            subject: api_subject,
            scopes: [
                ServiceScope::ProjectRead,
                ServiceScope::BuildSubmit,
                ServiceScope::BuildCancel,
                ServiceScope::SecretUse,
                ServiceScope::ProjectAdmin,
                ServiceScope::AuditRead,
                ServiceScope::SchedulerControl,
            ]
            .into(),
            actor_subject: "bootstrap:controller".to_owned(),
        })
        .await
        .context("provision durable public API service identity")?;
    let credential_id = deterministic_uuid(&format!(
        "mcloving:service-credential:{api_identity_id}:{bearer_generation}"
    ));
    let api_credential = NewServiceCredential {
        organization_id: worker.organization_id,
        credential_id,
        identity_id: api_identity_id,
        generation: bearer_generation,
        token_digest: Sha256::digest(bearer_token.as_bytes()).into(),
        issued_at_unix_ms: unix_time_ms(),
        expires_at_unix_ms: None,
        actor_subject: "bootstrap:controller".to_owned(),
    };
    if let Some(oidc) = &oidc {
        migration_store
            .provision_controller_authentication(
                &api_credential,
                &oidc.provider,
                &worker.config.agent_id,
                artifact_agent_digest,
            )
            .await
            .context(
                "atomically provision public API credential, OIDC provider, and artifact-agent reservation",
            )?;
    } else {
        migration_store
            .provision_controller_credential(
                &api_credential,
                &worker.config.agent_id,
                artifact_agent_digest,
            )
            .await
            .context("atomically provision public API credential and artifact-agent reservation")?;
    }
    migration_pool.close().await;
    let state = state
        .with_durable_artifact_agent_token(
            &artifact_agent_token,
            &worker.config.agent_id,
            worker.organization_id,
        )
        .await
        .context("configure artifact-agent authentication")?
        .with_object_store(object_store)
        .with_staged_upload_ttl(staged_upload_ttl);
    let trigger_retry_state = state.clone();
    let trigger_retry_organization = worker.organization_id;
    let server = async {
        axum::serve(
            listener,
            router(state).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .context("serve public API")
    };
    let agent_server = run_agent_control_server(store.clone(), agent_control);
    tokio::pin!(server);
    tokio::pin!(agent_server);
    let outbox_reaper_loop = run_outbox_reaper(
        store.clone(),
        worker.organization_id,
        outbox_retention_hours,
    );
    tokio::pin!(outbox_reaper_loop);
    let worker_loop = run_embedded_worker(store, worker);
    tokio::pin!(worker_loop);
    let trigger_retry_loop =
        run_trigger_retry_worker(trigger_retry_state, trigger_retry_organization);
    tokio::pin!(trigger_retry_loop);
    tokio::select! {
        result = &mut server => result,
        result = &mut agent_server => result,
        result = &mut worker_loop => result,
        result = &mut trigger_retry_loop => result,
        result = &mut outbox_reaper_loop => result,
    }
}

fn bounded_u64_environment(name: &str, default: u64) -> Result<u64> {
    match std::env::var(name) {
        Ok(value) => {
            let parsed = value
                .parse::<u64>()
                .with_context(|| format!("{name} must be an unsigned integer"))?;
            if parsed == 0 {
                bail!("{name} must be greater than zero");
            }
            Ok(parsed)
        }
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(error).with_context(|| format!("read {name}")),
    }
}

fn bounded_u64_environment_at_most(name: &str, default: u64, maximum: u64) -> Result<u64> {
    let value = bounded_u64_environment(name, default)?;
    bounded_u64_at_most(name, value, maximum)
}

fn bounded_u64_at_most(name: &str, value: u64, maximum: u64) -> Result<u64> {
    if value > maximum {
        bail!("{name} must be at most {maximum}");
    }
    Ok(value)
}

struct OidcEnvironment {
    provider: IdentityProviderWrite,
    client: OidcClientConfig,
}

fn oidc_environment(organization_id: Uuid) -> Result<Option<OidcEnvironment>> {
    let provider_id = match std::env::var("MCLOVING_OIDC_PROVIDER_ID") {
        Ok(value) => value
            .parse::<Uuid>()
            .context("MCLOVING_OIDC_PROVIDER_ID must be a UUID")?,
        Err(std::env::VarError::NotPresent) => {
            const OIDC_ENVIRONMENT: &[&str] = &[
                "MCLOVING_OIDC_ISSUER",
                "MCLOVING_OIDC_AUDIENCE",
                "MCLOVING_OIDC_AUTHORIZATION_ENDPOINT",
                "MCLOVING_OIDC_TOKEN_ENDPOINT",
                "MCLOVING_OIDC_JWKS_URI",
                "MCLOVING_OIDC_CLIENT_ID",
                "MCLOVING_OIDC_CLIENT_SECRET",
                "MCLOVING_OIDC_GROUP_CLAIM",
                "MCLOVING_OIDC_CONFIGURATION_GENERATION",
                "MCLOVING_OIDC_JWKS_GENERATION",
                "MCLOVING_OIDC_JWKS_SHA256",
                "MCLOVING_OIDC_ALLOWED_REDIRECT_URIS",
                "MCLOVING_OIDC_SESSION_TTL_SECONDS",
                "MCLOVING_OIDC_REFRESH_TTL_SECONDS",
                "MCLOVING_OIDC_REQUEST_TIMEOUT_SECONDS",
                "MCLOVING_OIDC_CLOCK_SKEW_SECONDS",
                "MCLOVING_OIDC_MAX_JWKS_BYTES",
            ];
            if let Some(name) = OIDC_ENVIRONMENT
                .iter()
                .find(|name| std::env::var_os(name).is_some())
            {
                bail!("{name} requires MCLOVING_OIDC_PROVIDER_ID");
            }
            return Ok(None);
        }
        Err(error) => return Err(error).context("read MCLOVING_OIDC_PROVIDER_ID"),
    };
    let issuer = required("MCLOVING_OIDC_ISSUER")?;
    let audience = required("MCLOVING_OIDC_AUDIENCE")?;
    let authorization_endpoint = required("MCLOVING_OIDC_AUTHORIZATION_ENDPOINT")?;
    let token_endpoint = required("MCLOVING_OIDC_TOKEN_ENDPOINT")?;
    let jwks_uri = required("MCLOVING_OIDC_JWKS_URI")?;
    let client_id = required("MCLOVING_OIDC_CLIENT_ID")?;
    let client_secret = match std::env::var("MCLOVING_OIDC_CLIENT_SECRET") {
        Ok(secret) => Some(secret),
        Err(std::env::VarError::NotPresent) => None,
        Err(error) => return Err(error).context("read MCLOVING_OIDC_CLIENT_SECRET"),
    };
    let group_claim = required("MCLOVING_OIDC_GROUP_CLAIM")?;
    let configuration_generation =
        bounded_u64_environment("MCLOVING_OIDC_CONFIGURATION_GENERATION", 1)?;
    let jwks_generation = bounded_u64_environment("MCLOVING_OIDC_JWKS_GENERATION", 1)?;
    let jwks_digest = parse_sha256_environment("MCLOVING_OIDC_JWKS_SHA256")?;
    let allowed_redirect_uris = required("MCLOVING_OIDC_ALLOWED_REDIRECT_URIS")?
        .split(',')
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if allowed_redirect_uris.iter().any(|uri| uri.trim() != uri) {
        bail!("MCLOVING_OIDC_ALLOWED_REDIRECT_URIS entries must be canonical");
    }
    let session_ttl_seconds = bounded_u64_environment_at_most(
        "MCLOVING_OIDC_SESSION_TTL_SECONDS",
        15 * 60,
        MAX_OIDC_SESSION_TTL_SECONDS,
    )?;
    let refresh_ttl_seconds = bounded_u64_environment_at_most(
        "MCLOVING_OIDC_REFRESH_TTL_SECONDS",
        8 * 60 * 60,
        MAX_OIDC_REFRESH_TTL_SECONDS,
    )?;
    let request_timeout_seconds = bounded_u64_environment_at_most(
        "MCLOVING_OIDC_REQUEST_TIMEOUT_SECONDS",
        10,
        MAX_OIDC_REQUEST_TIMEOUT_SECONDS,
    )?;
    let clock_skew_seconds = bounded_u64_environment_at_most(
        "MCLOVING_OIDC_CLOCK_SKEW_SECONDS",
        60,
        MAX_OIDC_CLOCK_SKEW_SECONDS,
    )?;
    let max_jwks_bytes = usize::try_from(bounded_u64_environment_at_most(
        "MCLOVING_OIDC_MAX_JWKS_BYTES",
        256 * 1024,
        MAX_OIDC_JWKS_BYTES as u64,
    )?)
    .context("MCLOVING_OIDC_MAX_JWKS_BYTES is too large")?;
    let configuration_digest = oidc_configuration_digest(
        &[
            &issuer,
            &audience,
            &authorization_endpoint,
            &token_endpoint,
            &jwks_uri,
            &client_id,
            &group_claim,
        ],
        client_secret.as_deref(),
        &allowed_redirect_uris,
        session_ttl_seconds,
        refresh_ttl_seconds,
        request_timeout_seconds,
        clock_skew_seconds,
        max_jwks_bytes,
        false,
    );
    let configuration_generation = i64::try_from(configuration_generation)
        .context("MCLOVING_OIDC_CONFIGURATION_GENERATION is too large")?;
    let jwks_generation =
        i64::try_from(jwks_generation).context("MCLOVING_OIDC_JWKS_GENERATION is too large")?;
    let provider = IdentityProviderWrite {
        organization_id,
        provider_id,
        issuer,
        audience,
        authorization_endpoint,
        token_endpoint,
        jwks_uri,
        client_id,
        group_claim,
        configuration_generation,
        configuration_digest,
        jwks_generation,
        jwks_digest,
        enabled: true,
        actor_subject: "bootstrap:controller".to_owned(),
    };
    let client = OidcClientConfig {
        organization_id,
        provider_id,
        configuration_generation,
        configuration_digest,
        client_secret,
        allowed_redirect_uris,
        session_ttl: Duration::from_secs(session_ttl_seconds),
        refresh_ttl: Duration::from_secs(refresh_ttl_seconds),
        request_timeout: Duration::from_secs(request_timeout_seconds),
        clock_skew: Duration::from_secs(clock_skew_seconds),
        max_jwks_bytes,
        allow_insecure_loopback_for_tests: false,
    };
    client
        .validate_with_provider(&provider)
        .context("validate complete OIDC runtime client before persistence")?;
    Ok(Some(OidcEnvironment { provider, client }))
}

#[allow(clippy::too_many_arguments)]
fn oidc_configuration_digest(
    fields: &[&str],
    client_secret: Option<&str>,
    allowed_redirect_uris: &BTreeSet<String>,
    session_ttl_seconds: u64,
    refresh_ttl_seconds: u64,
    request_timeout_seconds: u64,
    clock_skew_seconds: u64,
    max_jwks_bytes: usize,
    allow_insecure_loopback_for_tests: bool,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"mcloving.oidc.configuration.v2\0");
    for field in fields {
        hash_oidc_configuration_field(&mut hash, field.as_bytes());
    }
    match client_secret {
        Some(secret) => {
            hash.update([1]);
            hash.update(Sha256::digest(secret.as_bytes()));
        }
        None => hash.update([0]),
    }
    hash.update((allowed_redirect_uris.len() as u64).to_be_bytes());
    for redirect_uri in allowed_redirect_uris {
        hash_oidc_configuration_field(&mut hash, redirect_uri.as_bytes());
    }
    hash.update(session_ttl_seconds.to_be_bytes());
    hash.update(refresh_ttl_seconds.to_be_bytes());
    hash.update(request_timeout_seconds.to_be_bytes());
    hash.update(clock_skew_seconds.to_be_bytes());
    hash.update((max_jwks_bytes as u64).to_be_bytes());
    hash.update([u8::from(allow_insecure_loopback_for_tests)]);
    hash.finalize().into()
}

fn hash_oidc_configuration_field(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
}

fn parse_sha256_environment(name: &str) -> Result<[u8; 32]> {
    let value = required(name)?;
    if value.len() != 64 {
        bail!("{name} must contain exactly 64 lowercase hexadecimal characters");
    }
    let mut digest = [0_u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        let pair = &value[index * 2..index * 2 + 2];
        if !pair
            .bytes()
            .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
        {
            bail!("{name} must contain exactly 64 lowercase hexadecimal characters");
        }
        *byte = u8::from_str_radix(pair, 16).context("parse OIDC JWKS SHA-256")?;
    }
    Ok(digest)
}

fn deterministic_uuid(label: &str) -> Uuid {
    let digest = Sha256::digest(label.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn unix_time_ms() -> i64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    i64::try_from(millis).unwrap_or(i64::MAX)
}

/// Sliding-window record of committed session-epoch advances per agent
/// identity.
///
/// One healthy executor advances its epoch once per service session. Two
/// executors misconfigured with a single agent identity fight a session-epoch
/// war: each reconnect fences the other, so the stored epoch advances every
/// few seconds. Rejections issued while that churn is high name the suspected
/// identity collision instead of only reporting a bare stale epoch.
#[derive(Debug, Default)]
struct SessionEpochChurn {
    advances_by_agent: Mutex<BTreeMap<String, VecDeque<Instant>>>,
}

const SESSION_CHURN_WINDOW: Duration = Duration::from_secs(60);
const SESSION_CHURN_COLLISION_THRESHOLD: usize = 3;
const MAX_TRACKED_SESSION_ADVANCES: usize = 32;

impl SessionEpochChurn {
    fn record_advance(&self, agent_id: &str) {
        let mut advances_by_agent = self
            .advances_by_agent
            .lock()
            .expect("session churn lock is never poisoned");
        let advances = advances_by_agent.entry(agent_id.to_owned()).or_default();
        let now = Instant::now();
        advances.push_back(now);
        while advances.len() > MAX_TRACKED_SESSION_ADVANCES
            || advances
                .front()
                .is_some_and(|advance| now.duration_since(*advance) > SESSION_CHURN_WINDOW)
        {
            advances.pop_front();
        }
    }

    /// Names the suspected collision when this identity's stored epoch has
    /// advanced repeatedly within the sliding window.
    fn suspected_collision(&self, agent_id: &str) -> Option<String> {
        let advances_by_agent = self
            .advances_by_agent
            .lock()
            .expect("session churn lock is never poisoned");
        let now = Instant::now();
        let advances = advances_by_agent
            .get(agent_id)?
            .iter()
            .filter(|advance| now.duration_since(**advance) <= SESSION_CHURN_WINDOW)
            .count();
        if advances < SESSION_CHURN_COLLISION_THRESHOLD {
            return None;
        }
        Some(format!(
            "agent identity collision suspected for {agent_id}: session epoch advanced \
             {advances} times in {} seconds; a second executor may be sharing this \
             agent identity",
            SESSION_CHURN_WINDOW.as_secs()
        ))
    }
}

/// Builds the fail-closed stale-epoch rejection, naming the suspected
/// identity collision when the stored epoch is churning.
fn stale_session_status(churn: &SessionEpochChurn, agent_id: &str) -> Status {
    if let Some(collision) = churn.suspected_collision(agent_id) {
        eprintln!("agent-control: {collision}");
        return Status::failed_precondition(format!("stale agent session epoch; {collision}"));
    }
    Status::failed_precondition("stale agent session epoch")
}

#[derive(Clone)]
struct ControllerAgentService {
    store: Store,
    identities: Arc<AgentIdentityBindings>,
    session_churn: Arc<SessionEpochChurn>,
    #[cfg(debug_assertions)]
    drop_start_response_once: Arc<AtomicBool>,
    #[cfg(debug_assertions)]
    reject_renewal_window: Arc<RenewalRejectionWindow>,
}

/// Test-only fault injection: refuse the renewals numbered `after + 1` through
/// `after + count` (1-indexed across the process) so a gate can prove that a
/// running step loses its lease deliberately rather than by outrunning it.
#[cfg(debug_assertions)]
#[derive(Default)]
struct RenewalRejectionWindow {
    counter: std::sync::atomic::AtomicU32,
    after: u32,
    count: u32,
}

#[cfg(debug_assertions)]
impl RenewalRejectionWindow {
    fn from_environment() -> Self {
        let Some(value) = std::env::var_os("MCLOVING_TEST_REJECT_RENEWALS") else {
            return Self::default();
        };
        let value = value.to_string_lossy();
        let (after, count) = value
            .split_once(',')
            .and_then(|(after, count)| {
                Some((after.trim().parse().ok()?, count.trim().parse().ok()?))
            })
            .expect("MCLOVING_TEST_REJECT_RENEWALS must be 'after,count'");
        Self {
            counter: std::sync::atomic::AtomicU32::new(0),
            after,
            count,
        }
    }

    fn rejects_this_renewal(&self) -> bool {
        if self.count == 0 {
            return false;
        }
        // Saturating arithmetic keeps a misconfigured window from panicking a
        // debug controller; a saturated window simply rejects to the end.
        let ordinal = self
            .counter
            .fetch_add(1, Ordering::SeqCst)
            .saturating_add(1);
        ordinal > self.after && ordinal <= self.after.saturating_add(self.count)
    }
}

#[tonic::async_trait]
impl AgentControl for ControllerAgentService {
    async fn open_session(
        &self,
        request: Request<OpenSessionRequest>,
    ) -> Result<Response<OpenSessionResponse>, Status> {
        let identity = self.identities.authenticate(&request)?;
        let request = request.into_inner();
        if request.agent_id.trim().is_empty() || request.trust_pool.trim().is_empty() {
            return Err(Status::invalid_argument(
                "agent_id and trust_pool are required",
            ));
        }
        if request.agent_id != identity.agent_id || request.trust_pool != identity.trust_pool {
            return Err(Status::permission_denied(
                "agent identity or trust pool does not match the authenticated certificate",
            ));
        }
        let offer = request
            .protocol
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("protocol offer is required"))?;
        let remote = ProtocolRange::try_from(offer)
            .map_err(|error| Status::failed_precondition(error.to_string()))?;
        let local = ProtocolRange::current([
            "journal-v1".to_owned(),
            "unix-process-group-v1".to_owned(),
            "windows-job-object-v1".to_owned(),
            WORK_DELIVERY_FEATURE.to_owned(),
            ATTEMPT_CREDENTIALS_FEATURE.to_owned(),
        ]);
        let negotiated = negotiate(&local, &remote)
            .map_err(|error| Status::failed_precondition(error.to_string()))?;
        if !self
            .store
            .open_agent_session(
                &request.agent_id,
                &request.trust_pool,
                request.session_epoch,
                negotiated.minor,
                &negotiated.features.iter().cloned().collect::<Vec<_>>(),
                &request.capabilities,
            )
            .await
            .map_err(internal_store_error)?
        {
            let mut status = stale_session_status(&self.session_churn, &request.agent_id);
            // The rejection itself carries the stored epoch so a lagging
            // journal (for example after a documented journal replacement)
            // can reserve past this floor in one step instead of brute
            // forcing the epoch space one retry at a time. The fence itself
            // is not weakened: this offer stays rejected.
            if let Some(stored_epoch) = self
                .store
                .agent_session_epoch(&request.agent_id)
                .await
                .map_err(internal_store_error)?
                && let Ok(value) = stored_epoch.to_string().parse()
            {
                status
                    .metadata_mut()
                    .insert(CURRENT_SESSION_EPOCH_METADATA, value);
            }
            return Err(status);
        }
        self.session_churn.record_advance(&request.agent_id);
        Ok(Response::new(OpenSessionResponse {
            session_epoch: request.session_epoch,
            protocol_minor: u32::from(negotiated.minor),
            features: negotiated.features.into_iter().collect(),
            certificate_not_after_unix_ms: 0,
        }))
    }

    async fn rotate_certificate(
        &self,
        _request: Request<RotateCertificateRequest>,
    ) -> Result<Response<RotateCertificateResponse>, Status> {
        Err(Status::unimplemented(
            "certificate issuance is owned by the enrollment service",
        ))
    }

    async fn reconcile(
        &self,
        request: Request<ReconciliationReport>,
    ) -> Result<Response<ReconciliationDirective>, Status> {
        let identity = self.identities.authenticate(&request)?;
        let request = request.into_inner();
        if request.agent_id != identity.agent_id {
            return Err(Status::permission_denied(
                "agent identity does not match the authenticated certificate",
            ));
        }
        if !self
            .store
            .authorize_agent_session(&request.agent_id, request.session_epoch)
            .await
            .map_err(internal_store_error)?
        {
            return Err(stale_session_status(&self.session_churn, &request.agent_id));
        }
        let mut retained = BTreeSet::new();
        let mut cancelled = BTreeSet::new();
        for attempt in request.attempts {
            let organization_id = authenticated_organization(identity, &attempt.organization_id)?;
            let attempt_id = attempt
                .attempt_id
                .parse()
                .map_err(|_| Status::invalid_argument("attempt_id must be a UUID"))?;
            let (restore_epoch, fence) = decode_authority_token(attempt.fence_token);
            if attempt.attempt_id.trim().is_empty()
                || attempt.organization_id.trim().is_empty()
                || attempt.payload_digest.len() != 32
                || attempt.workspace.trim().is_empty()
                || attempt
                    .logs
                    .iter()
                    .any(|entry| entry.relative_path.trim().is_empty() || entry.digest.len() != 32)
                || attempt.result.as_ref().is_some_and(|entry| {
                    entry.relative_path.trim().is_empty() || entry.digest.len() != 32
                })
            {
                return Err(Status::invalid_argument(
                    "reconciliation attempt metadata is invalid",
                ));
            }
            require_reconciliation_trust_pool(&self.store, identity, organization_id, attempt_id)
                .await?;
            if matches!(attempt.phase.as_str(), "finalizing" | "cancelling")
                && self
                    .store
                    .recover_agent_finalization_in_session(
                        organization_id,
                        attempt_id,
                        fence,
                        restore_epoch,
                        &request.agent_id,
                        request.session_epoch,
                        &attempt.phase,
                        i32::try_from(RECOVERED_FINALIZATION_LEASE_SECONDS)
                            .expect("recovery lease fits the store wire type"),
                    )
                    .await
                    .map_err(internal_store_error)?
            {
                retained.insert((
                    attempt.organization_id,
                    attempt.attempt_id,
                    attempt.fence_token,
                ));
                continue;
            }
            match self
                .store
                .agent_reconciliation_disposition_in_session(
                    organization_id,
                    attempt_id,
                    fence,
                    restore_epoch,
                    &request.agent_id,
                    request.session_epoch,
                )
                .await
                .map_err(internal_store_error)?
            {
                AgentReconciliationDisposition::Retain => {
                    retained.insert((
                        attempt.organization_id,
                        attempt.attempt_id,
                        attempt.fence_token,
                    ));
                }
                AgentReconciliationDisposition::Cancel => {
                    cancelled.insert((
                        attempt.organization_id,
                        attempt.attempt_id,
                        attempt.fence_token,
                    ));
                }
            }
        }
        Ok(Response::new(ReconciliationDirective {
            session_epoch: request.session_epoch,
            retain_attempts: retained
                .into_iter()
                .map(
                    |(organization_id, attempt_id, fence_token)| AttemptAuthority {
                        organization_id,
                        attempt_id,
                        fence_token,
                    },
                )
                .collect(),
            cancel_attempts: cancelled
                .into_iter()
                .map(
                    |(organization_id, attempt_id, fence_token)| AttemptAuthority {
                        organization_id,
                        attempt_id,
                        fence_token,
                    },
                )
                .collect(),
        }))
    }

    async fn complete_cancellation(
        &self,
        request: Request<CancellationCompletion>,
    ) -> Result<Response<CancellationReceipt>, Status> {
        let identity = self.identities.authenticate(&request)?;
        let request = request.into_inner();
        if request.agent_id != identity.agent_id {
            return Err(Status::permission_denied(
                "agent identity does not match the authenticated certificate",
            ));
        }
        if !self
            .store
            .authorize_agent_session(&request.agent_id, request.session_epoch)
            .await
            .map_err(internal_store_error)?
        {
            return Err(stale_session_status(&self.session_churn, &request.agent_id));
        }
        let organization_id = authenticated_organization(identity, &request.organization_id)?;
        let attempt_id = request
            .attempt_id
            .parse()
            .map_err(|_| Status::invalid_argument("attempt_id must be a UUID"))?;
        let outcome = match CancellationOutcome::try_from(request.outcome) {
            Ok(CancellationOutcome::Terminated) => AgentCancellationOutcome::Terminated,
            Ok(CancellationOutcome::AlreadyExited) => AgentCancellationOutcome::AlreadyExited,
            Ok(CancellationOutcome::IdentityMismatch) => AgentCancellationOutcome::IdentityMismatch,
            Ok(CancellationOutcome::ReconciliationRequired) => {
                AgentCancellationOutcome::ReconciliationRequired
            }
            Ok(CancellationOutcome::Unspecified) | Err(_) => {
                return Err(Status::invalid_argument(
                    "cancellation outcome must be explicit",
                ));
            }
        };
        let (restore_epoch, fence) = decode_authority_token(request.fence_token);
        let disposition = self
            .store
            .complete_agent_cancellation(AgentCancellationCompletion {
                organization_id,
                attempt_id,
                fence,
                restore_epoch,
                agent_id: &request.agent_id,
                session_epoch: request.session_epoch,
                outcome,
            })
            .await
            .map_err(internal_store_error)?;
        Ok(Response::new(CancellationReceipt {
            session_epoch: request.session_epoch,
            disposition: match disposition {
                AgentCancellationDisposition::Completed => {
                    CancellationDisposition::Completed as i32
                }
                AgentCancellationDisposition::RetireStale => {
                    CancellationDisposition::RetireStale as i32
                }
                AgentCancellationDisposition::ReconciliationRequired => {
                    CancellationDisposition::ReconciliationRequired as i32
                }
                AgentCancellationDisposition::DischargeRecovered => {
                    eprintln!(
                        "agent-control: authorized discharge of recovered attempt {}/{} \
                         fence {} reported by agent {}: fenced authority is disowned",
                        request.organization_id,
                        request.attempt_id,
                        request.fence_token,
                        request.agent_id,
                    );
                    CancellationDisposition::DischargeRecovered as i32
                }
            },
        }))
    }

    async fn poll_work(&self, request: Request<WorkPoll>) -> Result<Response<WorkOffer>, Status> {
        let identity = self.identities.authenticate(&request)?.clone();
        let request = request.into_inner();
        authorize_work_session(
            &self.store,
            &self.session_churn,
            &identity,
            &request.agent_id,
            request.session_epoch,
            &request.organization_id,
        )
        .await?;
        let lease_seconds = i32::try_from(request.lease_seconds)
            .map_err(|_| Status::invalid_argument("lease_seconds is out of range"))?;
        if !(5..=300).contains(&lease_seconds) {
            return Err(Status::invalid_argument(
                "lease_seconds must be between 5 and 300",
            ));
        }
        let capabilities = self
            .store
            .agent_session_capabilities(&request.agent_id, request.session_epoch)
            .await
            .map_err(internal_store_error)?
            .ok_or_else(|| stale_session_status(&self.session_churn, &request.agent_id))?;
        self.store
            .requeue_one_expired(identity.organization_id)
            .await
            .map_err(internal_store_error)?;
        let assignment = if let Some(claim) = self
            .store
            .claim_next_in_session(
                &ClaimRequest {
                    organization_id: identity.organization_id,
                    scheduler_id: format!("agent:{}:{}", request.agent_id, request.session_epoch),
                    agent_id: request.agent_id.clone(),
                    capabilities,
                    trust_pool: identity.trust_pool.clone(),
                    lease_seconds,
                    fairness_seed: 0,
                },
                request.session_epoch,
            )
            .await
            .map_err(internal_store_error)?
        {
            let execution = self
                .store
                .attempt_execution_in_session(
                    claim.organization_id,
                    claim.attempt_id,
                    claim.fence,
                    claim.restore_epoch,
                    &claim.agent_id,
                    request.session_epoch,
                )
                .await
                .map_err(internal_store_error)?
                .ok_or_else(|| Status::aborted("claimed work lost fenced authority"))?;
            let execution_spec_json = serde_json::to_vec(&execution.execution_spec)
                .map_err(|error| Status::internal(format!("serialize execution spec: {error}")))?;
            Some(WorkAssignment {
                organization_id: claim.organization_id.to_string(),
                build_id: claim.build_id.to_string(),
                node_id: claim.node_id.to_string(),
                attempt_id: claim.attempt_id.to_string(),
                fence_token: encode_authority_token(claim.restore_epoch, claim.fence)?,
                payload_digest: Sha256::digest(&execution_spec_json).to_vec(),
                execution_spec_json,
            })
        } else {
            None
        };
        Ok(Response::new(WorkOffer {
            session_epoch: request.session_epoch,
            assignment,
        }))
    }

    async fn accept_work(
        &self,
        request: Request<WorkAuthority>,
    ) -> Result<Response<WorkReceipt>, Status> {
        let identity = self.identities.authenticate(&request)?.clone();
        let authority = request.into_inner();
        let context =
            authorize_work_authority(&self.store, &self.session_churn, &identity, &authority)
                .await?;
        let accepted = self
            .store
            .accept_offer_in_session(
                context.organization_id,
                context.attempt_id,
                context.fence,
                context.restore_epoch,
                &authority.agent_id,
                authority.session_epoch,
            )
            .await
            .map_err(internal_store_error)?;
        Ok(Response::new(WorkReceipt {
            session_epoch: authority.session_epoch,
            accepted,
        }))
    }

    async fn start_work(
        &self,
        request: Request<WorkAuthority>,
    ) -> Result<Response<WorkReceipt>, Status> {
        let identity = self.identities.authenticate(&request)?.clone();
        let authority = request.into_inner();
        let context =
            authorize_work_authority(&self.store, &self.session_churn, &identity, &authority)
                .await?;
        let accepted = self
            .store
            .mark_attempt_running_in_session(
                context.organization_id,
                context.attempt_id,
                context.fence,
                context.restore_epoch,
                &authority.agent_id,
                authority.session_epoch,
            )
            .await
            .map_err(internal_store_error)?;
        #[cfg(debug_assertions)]
        if accepted && self.drop_start_response_once.swap(false, Ordering::SeqCst) {
            return Err(Status::unavailable(
                "test-only injected start acknowledgement loss",
            ));
        }
        Ok(Response::new(WorkReceipt {
            session_epoch: authority.session_epoch,
            accepted,
        }))
    }

    async fn fetch_credentials(
        &self,
        request: Request<CredentialRequest>,
    ) -> Result<Response<CredentialEnvelope>, Status> {
        let identity = self.identities.authenticate(&request)?.clone();
        let request = request.into_inner();
        let authority = request
            .authority
            .ok_or_else(|| Status::invalid_argument("work authority is required"))?;
        let context =
            authorize_work_authority(&self.store, &self.session_churn, &identity, &authority)
                .await?;
        let deliveries = self
            .store
            .redeem_credential_grants(
                context.organization_id,
                context.attempt_id,
                context.fence,
                context.restore_epoch,
                &authority.agent_id,
                authority.session_epoch,
                &request.target_names,
            )
            .await
            .map_err(credential_store_error)?;
        let ready = deliveries.is_some();
        let credentials = deliveries
            .unwrap_or_default()
            .into_iter()
            .map(|credential| CredentialBinding {
                grant_id: credential.grant_id.to_string(),
                target_name: credential.target_name,
                secret_value: credential.secret_value,
            })
            .collect();
        Ok(Response::new(CredentialEnvelope {
            session_epoch: authority.session_epoch,
            credentials,
            ready,
        }))
    }

    async fn renew_work_lease(
        &self,
        request: Request<WorkLeaseRenewal>,
    ) -> Result<Response<WorkLeaseReceipt>, Status> {
        let identity = self.identities.authenticate(&request)?.clone();
        let request = request.into_inner();
        let authority = request
            .authority
            .ok_or_else(|| Status::invalid_argument("work authority is required"))?;
        let context =
            match authorize_work_authority(&self.store, &self.session_churn, &identity, &authority)
                .await
            {
                Ok(context) => context,
                Err(status) => {
                    // A session-epoch conflict rejects the renewal here, before the
                    // store's renewal path runs, so the named controller-side event
                    // must be recorded at this boundary or the motivating collision
                    // stays invisible. Best effort under the authenticated tenant;
                    // the original rejection is returned unchanged.
                    if status.code() == tonic::Code::FailedPrecondition
                        && status.message().contains("stale agent session epoch")
                        && let Ok(organization_id) =
                            authenticated_organization(&identity, &authority.organization_id)
                        && let Ok(attempt_id) = authority.attempt_id.parse()
                    {
                        let (_, fence) = decode_authority_token(authority.fence_token);
                        let _ = self
                            .store
                            .record_lease_renewal_rejection(
                                organization_id,
                                attempt_id,
                                fence,
                                &authority.agent_id,
                                "agent_session_stale",
                            )
                            .await;
                    }
                    return Err(status);
                }
            };
        let lease_seconds = i32::try_from(request.lease_seconds)
            .map_err(|_| Status::invalid_argument("lease_seconds is out of range"))?;
        if !(5..=300).contains(&lease_seconds) {
            return Err(Status::invalid_argument(
                "lease_seconds must be between 5 and 300",
            ));
        }
        #[cfg(debug_assertions)]
        if self.reject_renewal_window.rejects_this_renewal() {
            return Ok(Response::new(WorkLeaseReceipt {
                session_epoch: authority.session_epoch,
                accepted: false,
                cancellation_requested: false,
                rejection_cause: String::new(),
            }));
        }
        let disposition = self
            .store
            .renew_attempt_lease_in_session(
                context.organization_id,
                context.attempt_id,
                context.fence,
                context.restore_epoch,
                &authority.agent_id,
                authority.session_epoch,
                lease_seconds,
            )
            .await
            .map_err(internal_store_error)?;
        let receipt = match disposition {
            LeaseRenewalDisposition::Renewed {
                cancellation_requested,
            } => WorkLeaseReceipt {
                session_epoch: authority.session_epoch,
                accepted: true,
                cancellation_requested,
                rejection_cause: String::new(),
            },
            LeaseRenewalDisposition::TerminalNoOp => WorkLeaseReceipt {
                session_epoch: authority.session_epoch,
                accepted: true,
                cancellation_requested: false,
                rejection_cause: String::new(),
            },
            LeaseRenewalDisposition::Rejected { cause } => WorkLeaseReceipt {
                session_epoch: authority.session_epoch,
                accepted: false,
                cancellation_requested: false,
                rejection_cause: cause.to_owned(),
            },
        };
        Ok(Response::new(receipt))
    }

    async fn publish_log(
        &self,
        request: Request<WorkLogChunk>,
    ) -> Result<Response<WorkReceipt>, Status> {
        let identity = self.identities.authenticate(&request)?.clone();
        let request = request.into_inner();
        let authority = request
            .authority
            .ok_or_else(|| Status::invalid_argument("work authority is required"))?;
        let context =
            authorize_work_authority(&self.store, &self.session_churn, &identity, &authority)
                .await?;
        if !matches!(request.stream.as_str(), "stdout" | "stderr")
            || request.content.len() > 1_048_576
        {
            return Err(Status::invalid_argument(
                "log stream or one-MiB chunk bound is invalid",
            ));
        }
        let sequence = i64::try_from(request.sequence)
            .map_err(|_| Status::invalid_argument("log sequence is out of range"))?;
        let accepted = self
            .store
            .append_log_in_session(
                &NewLogChunk {
                    organization_id: context.organization_id,
                    attempt_id: context.attempt_id,
                    fence: context.fence,
                    restore_epoch: context.restore_epoch,
                    agent_id: &authority.agent_id,
                    sequence,
                    stream: &request.stream,
                    content: &request.content,
                },
                authority.session_epoch,
            )
            .await
            .map_err(internal_store_error)?;
        Ok(Response::new(WorkReceipt {
            session_epoch: authority.session_epoch,
            accepted,
        }))
    }

    async fn complete_work(
        &self,
        request: Request<WorkCompletion>,
    ) -> Result<Response<WorkReceipt>, Status> {
        let identity = self.identities.authenticate(&request)?.clone();
        let request = request.into_inner();
        let authority = request
            .authority
            .ok_or_else(|| Status::invalid_argument("work authority is required"))?;
        let context =
            authorize_work_authority(&self.store, &self.session_churn, &identity, &authority)
                .await?;
        if request.summary_json.len() > 65_536 {
            return Err(Status::invalid_argument("terminal summary exceeds 64 KiB"));
        }
        let summary: serde_json::Value = serde_json::from_slice(&request.summary_json)
            .map_err(|_| Status::invalid_argument("terminal summary must be valid JSON"))?;
        let outcome = match WorkOutcome::try_from(request.outcome) {
            Ok(WorkOutcome::Succeeded) => TerminalOutcome::Succeeded,
            Ok(WorkOutcome::Failed) => TerminalOutcome::Failed,
            Ok(WorkOutcome::Aborted) => TerminalOutcome::Aborted,
            Ok(WorkOutcome::Unspecified) | Err(_) => {
                return Err(Status::invalid_argument("work outcome must be explicit"));
            }
        };
        let accepted = self
            .store
            .finalize_attempt_in_session(
                context.organization_id,
                context.attempt_id,
                context.fence,
                context.restore_epoch,
                &authority.agent_id,
                authority.session_epoch,
                outcome,
                summary,
            )
            .await
            .map_err(internal_store_error)?;
        Ok(Response::new(WorkReceipt {
            session_epoch: authority.session_epoch,
            accepted,
        }))
    }
}

#[derive(Clone, Copy)]
struct WorkContext {
    organization_id: Uuid,
    attempt_id: Uuid,
    restore_epoch: i64,
    fence: i64,
}

async fn authorize_work_session(
    store: &Store,
    session_churn: &SessionEpochChurn,
    identity: &AgentIdentity,
    agent_id: &str,
    session_epoch: u64,
    organization_id: &str,
) -> Result<(), Status> {
    if agent_id != identity.agent_id
        || organization_id.parse::<Uuid>().ok() != Some(identity.organization_id)
    {
        return Err(Status::permission_denied(
            "work identity or organization does not match the authenticated certificate",
        ));
    }
    if !store
        .authorize_agent_session(agent_id, session_epoch)
        .await
        .map_err(internal_store_error)?
    {
        return Err(stale_session_status(session_churn, agent_id));
    }
    Ok(())
}

async fn authorize_work_authority(
    store: &Store,
    session_churn: &SessionEpochChurn,
    identity: &AgentIdentity,
    authority: &WorkAuthority,
) -> Result<WorkContext, Status> {
    authorize_work_session(
        store,
        session_churn,
        identity,
        &authority.agent_id,
        authority.session_epoch,
        &authority.organization_id,
    )
    .await?;
    let organization_id = authority
        .organization_id
        .parse()
        .map_err(|_| Status::invalid_argument("organization_id must be a UUID"))?;
    let attempt_id = authority
        .attempt_id
        .parse()
        .map_err(|_| Status::invalid_argument("attempt_id must be a UUID"))?;
    let (restore_epoch, fence) = decode_authority_token(authority.fence_token);
    require_attempt_trust_pool(
        store,
        identity,
        organization_id,
        attempt_id,
        restore_epoch,
        fence,
        &authority.agent_id,
    )
    .await?;
    Ok(WorkContext {
        organization_id,
        attempt_id,
        restore_epoch,
        fence,
    })
}

#[allow(clippy::too_many_arguments)]
async fn require_attempt_trust_pool(
    store: &Store,
    identity: &AgentIdentity,
    organization_id: Uuid,
    attempt_id: Uuid,
    restore_epoch: i64,
    fence: i64,
    agent_id: &str,
) -> Result<(), Status> {
    if store
        .authorize_attempt_trust_pool(
            organization_id,
            attempt_id,
            fence,
            restore_epoch,
            agent_id,
            &identity.trust_pool,
        )
        .await
        .map_err(internal_store_error)?
    {
        Ok(())
    } else {
        Err(Status::permission_denied(
            "fenced work authority does not match the certificate trust pool",
        ))
    }
}

async fn require_reconciliation_trust_pool(
    store: &Store,
    identity: &AgentIdentity,
    organization_id: Uuid,
    attempt_id: Uuid,
) -> Result<(), Status> {
    match store
        .authorize_reconciliation_trust_pool(organization_id, attempt_id, &identity.trust_pool)
        .await
        .map_err(internal_store_error)?
    {
        ReconciliationTrustPoolAuthorization::Matching
        | ReconciliationTrustPoolAuthorization::Missing => Ok(()),
        ReconciliationTrustPoolAuthorization::Mismatched => Err(Status::permission_denied(
            "reconciliation attempt does not match the certificate trust pool",
        )),
    }
}

fn encode_authority_token(restore_epoch: i64, fence: i64) -> Result<u64, Status> {
    let restore_epoch = u32::try_from(restore_epoch)
        .map_err(|_| Status::failed_precondition("restore epoch exceeds wire bounds"))?;
    let fence = u32::try_from(fence)
        .map_err(|_| Status::failed_precondition("fence exceeds wire bounds"))?;
    Ok((u64::from(restore_epoch) << 32) | u64::from(fence))
}

fn decode_authority_token(token: u64) -> (i64, i64) {
    (
        i64::from((token >> 32) as u32),
        i64::from((token & u64::from(u32::MAX)) as u32),
    )
}

fn internal_store_error(error: mcloving_controller_store::StoreError) -> Status {
    Status::internal(format!("controller store failed: {error}"))
}

fn credential_store_error(error: StoreError) -> Status {
    match error {
        StoreError::InvalidSecurityOperation(_) | StoreError::InvalidAgentSession => {
            Status::failed_precondition(format!("credential delivery rejected: {error}"))
        }
        other => internal_store_error(other),
    }
}

struct AgentControlEnvironment {
    address: SocketAddr,
    listener: TcpListener,
    certificate: Vec<u8>,
    private_key: Vec<u8>,
    client_ca: Vec<u8>,
    identities: AgentIdentityBindings,
    #[cfg(debug_assertions)]
    drop_start_response_once: bool,
}

impl AgentControlEnvironment {
    fn tls_config(&self) -> ServerTlsConfig {
        ServerTlsConfig::new()
            .identity(Identity::from_pem(
                self.certificate.clone(),
                self.private_key.clone(),
            ))
            .client_ca_root(Certificate::from_pem(self.client_ca.clone()))
    }
}

async fn agent_control_environment() -> Result<Option<AgentControlEnvironment>> {
    let listen = match std::env::var("MCLOVING_AGENT_LISTEN") {
        Ok(listen) => listen,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(error) => return Err(error).context("read MCLOVING_AGENT_LISTEN"),
    };
    let address = listen
        .parse()
        .with_context(|| format!("MCLOVING_AGENT_LISTEN is invalid: {listen}"))?;
    let listener = TcpListener::bind(address)
        .await
        .with_context(|| format!("bind agent control to {address}"))?;
    let environment = AgentControlEnvironment {
        address,
        listener,
        certificate: std::fs::read(required("MCLOVING_AGENT_SERVER_CERT_PATH")?)
            .context("read agent-control server certificate")?,
        private_key: std::fs::read(required("MCLOVING_AGENT_SERVER_KEY_PATH")?)
            .context("read agent-control server private key")?,
        client_ca: std::fs::read(required("MCLOVING_AGENT_CLIENT_CA_PATH")?)
            .context("read agent-control client CA")?,
        identities: AgentIdentityBindings::read(PathBuf::from(required(
            "MCLOVING_AGENT_IDENTITY_BINDINGS_PATH",
        )?))
        .context("read agent certificate identity bindings")?,
        #[cfg(debug_assertions)]
        drop_start_response_once: std::env::var_os("MCLOVING_TEST_DROP_START_RESPONSE_ONCE")
            .is_some(),
    };
    Server::builder()
        .tls_config(environment.tls_config())
        .context("configure agent-control mTLS")?;
    Ok(Some(environment))
}

async fn run_agent_control_server(
    store: Store,
    environment: Option<AgentControlEnvironment>,
) -> Result<()> {
    let Some(environment) = environment else {
        std::future::pending::<()>().await;
        unreachable!("pending agent server future returned")
    };
    let address = environment.address;
    let tls = environment.tls_config();
    let listener = environment.listener;
    #[cfg(debug_assertions)]
    let drop_start_response_once = environment.drop_start_response_once;
    let service = ControllerAgentService {
        store,
        identities: Arc::new(environment.identities),
        session_churn: Arc::new(SessionEpochChurn::default()),
        #[cfg(debug_assertions)]
        drop_start_response_once: Arc::new(AtomicBool::new(drop_start_response_once)),
        #[cfg(debug_assertions)]
        reject_renewal_window: Arc::new(RenewalRejectionWindow::from_environment()),
    };
    Server::builder()
        .tls_config(tls)
        .context("configure agent-control mTLS")?
        .add_service(AgentControlServer::new(service))
        .serve_with_incoming(TcpListenerStream::new(listener))
        .await
        .with_context(|| format!("serve agent control on {address}"))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AgentIdentity {
    agent_id: String,
    trust_pool: String,
    organization_id: Uuid,
}

#[derive(Debug)]
struct AgentIdentityBindings {
    by_certificate_sha256: BTreeMap<[u8; 32], AgentIdentity>,
}

impl AgentIdentityBindings {
    fn read(path: PathBuf) -> Result<Self> {
        let source = std::fs::read_to_string(&path)
            .with_context(|| format!("read identity bindings from {}", path.display()))?;
        Self::parse(&source)
    }

    fn parse(source: &str) -> Result<Self> {
        let mut by_certificate_sha256 = BTreeMap::new();
        let mut claims_by_agent = BTreeMap::new();
        for (index, raw_line) in source.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
            if fields.len() == 3 {
                bail!(
                    "identity binding line {} uses the legacy three-column format; append the exact organization UUID as column four before starting this controller",
                    index + 1
                );
            }
            if fields.len() != 4 {
                bail!(
                    "identity binding line {} must contain SHA-256, agent ID, trust pool, and organization UUID",
                    index + 1
                );
            }
            let digest = parse_sha256(fields[0]).with_context(|| {
                format!("identity binding line {} has invalid SHA-256", index + 1)
            })?;
            let identity = AgentIdentity {
                agent_id: fields[1].to_owned(),
                trust_pool: fields[2].to_owned(),
                organization_id: fields[3].parse().with_context(|| {
                    format!(
                        "identity binding line {} has an invalid organization UUID",
                        index + 1
                    )
                })?,
            };
            if identity.agent_id.trim().is_empty() || identity.trust_pool.trim().is_empty() {
                bail!(
                    "identity binding line {} contains an empty claim",
                    index + 1
                );
            }
            if by_certificate_sha256.contains_key(&digest) {
                bail!(
                    "identity binding line {} repeats a certificate digest",
                    index + 1
                );
            }
            let claims = (identity.trust_pool.clone(), identity.organization_id);
            if let Some(existing_claims) = claims_by_agent.get(&identity.agent_id) {
                if existing_claims != &claims {
                    bail!(
                        "identity binding line {} assigns agent {} conflicting trust or organization claims",
                        index + 1,
                        identity.agent_id
                    );
                }
            } else {
                claims_by_agent.insert(identity.agent_id.clone(), claims);
            }
            by_certificate_sha256.insert(digest, identity);
        }
        if by_certificate_sha256.is_empty() {
            bail!("at least one agent certificate identity binding is required");
        }
        Ok(Self {
            by_certificate_sha256,
        })
    }

    fn authenticate<T>(&self, request: &Request<T>) -> Result<&AgentIdentity, Status> {
        let tls = request
            .extensions()
            .get::<TlsConnectInfo<TcpConnectInfo>>()
            .ok_or_else(|| Status::unauthenticated("mutual TLS connection identity is missing"))?;
        let certificates = tls
            .peer_certs()
            .ok_or_else(|| Status::unauthenticated("client certificate is missing"))?;
        let leaf = certificates
            .first()
            .ok_or_else(|| Status::unauthenticated("client certificate chain is empty"))?;
        let digest: [u8; 32] = Sha256::digest(leaf.as_ref()).into();
        self.by_certificate_sha256
            .get(&digest)
            .ok_or_else(|| Status::permission_denied("client certificate is not enrolled"))
    }
}

fn parse_sha256(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 {
        bail!("SHA-256 must contain 64 hexadecimal characters");
    }
    let mut digest = [0_u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .context("SHA-256 contains a non-hexadecimal character")?;
    }
    Ok(digest)
}

fn authenticated_organization(
    identity: &AgentIdentity,
    organization_id: &str,
) -> Result<Uuid, Status> {
    let organization_id = organization_id
        .parse()
        .map_err(|_| Status::invalid_argument("organization_id must be a UUID"))?;
    if organization_id != identity.organization_id {
        return Err(Status::permission_denied(
            "organization does not match the authenticated certificate",
        ));
    }
    Ok(organization_id)
}

struct EmbeddedWorker {
    organization_id: Uuid,
    scheduler_id: String,
    capabilities: Vec<String>,
    trust_pool: String,
    lease_seconds: i32,
    poll_interval: Duration,
    config: WorkerConfig,
}

impl EmbeddedWorker {
    fn from_environment() -> Result<Self> {
        let organization_id = required("MCLOVING_ORGANIZATION_ID")?
            .parse()
            .context("MCLOVING_ORGANIZATION_ID must be a UUID")?;
        let agent_id = required("MCLOVING_AGENT_ID")?;
        let capabilities = required("MCLOVING_AGENT_CAPABILITIES")?
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if capabilities.is_empty() {
            bail!("MCLOVING_AGENT_CAPABILITIES must not be empty");
        }
        let trust_pool = required("MCLOVING_AGENT_TRUST_POOL")?;
        let lease_seconds = parse_positive::<i32>("MCLOVING_LEASE_SECONDS")?;
        let poll_milliseconds = parse_positive::<u64>("MCLOVING_POLL_MILLISECONDS")?;
        let cancellation_milliseconds =
            parse_positive::<u64>("MCLOVING_CANCELLATION_POLL_MILLISECONDS")?;
        let termination_grace_milliseconds =
            parse_positive::<u64>("MCLOVING_TERMINATION_GRACE_MILLISECONDS")?;
        Ok(Self {
            organization_id,
            scheduler_id: format!("embedded:{agent_id}"),
            capabilities,
            trust_pool,
            lease_seconds,
            poll_interval: Duration::from_millis(poll_milliseconds),
            config: WorkerConfig {
                agent_id,
                session_epoch: parse_positive("MCLOVING_SESSION_EPOCH")?,
                workspace_root: PathBuf::from(required("MCLOVING_WORKSPACE_ROOT")?),
                journal_path: PathBuf::from(required("MCLOVING_AGENT_JOURNAL")?),
                cancellation_poll: Duration::from_millis(cancellation_milliseconds),
                lease_seconds,
                termination_grace: Duration::from_millis(termination_grace_milliseconds),
                effect_plan: effect_plan_from_environment()?,
            },
        })
    }
}

async fn run_embedded_worker(store: Store, worker: EmbeddedWorker) -> Result<()> {
    loop {
        if let Err(error) = store.requeue_one_expired(worker.organization_id).await {
            eprintln!("expired-lease reconciliation failed: {error}");
        }
        match store
            .claim_next(&ClaimRequest {
                organization_id: worker.organization_id,
                scheduler_id: worker.scheduler_id.clone(),
                agent_id: worker.config.agent_id.clone(),
                capabilities: worker.capabilities.clone(),
                trust_pool: worker.trust_pool.clone(),
                lease_seconds: worker.lease_seconds,
                fairness_seed: 0,
            })
            .await
        {
            Ok(Some(claim)) => {
                if let Err(error) = run_claim(&store, &claim, &worker.config).await {
                    eprintln!(
                        "attempt {} failed before terminal publication: {error}",
                        claim.attempt_id
                    );
                }
            }
            Ok(None) => tokio::time::sleep(worker.poll_interval).await,
            Err(error) => {
                eprintln!("scheduler claim failed: {error}");
                tokio::time::sleep(worker.poll_interval).await;
            }
        }
    }
}

async fn run_trigger_retry_worker(state: ApiState, organization_id: Uuid) -> Result<()> {
    const RETRY_SCAN_LIMIT: i64 = 128;
    const RETRY_POLL_INTERVAL: Duration = Duration::from_secs(1);
    loop {
        match state
            .process_due_trigger_deliveries(organization_id, RETRY_SCAN_LIMIT)
            .await
        {
            Ok(0) => tokio::time::sleep(RETRY_POLL_INTERVAL).await,
            Ok(_) => {}
            Err(error) => {
                eprintln!("trigger retry scan failed: {error}");
                tokio::time::sleep(RETRY_POLL_INTERVAL).await;
            }
        }
    }
}

/// Default outbox retention horizon: seven days.
const DEFAULT_OUTBOX_RETENTION_HOURS: u64 = 168;
/// Upper retention bound: ten years, which also keeps the horizon within the
/// 32-bit range the store accepts.
const MAX_OUTBOX_RETENTION_HOURS: u64 = 10 * 365 * 24;

/// Bounds outbox accumulation. No outbox consumer is currently shipped, so
/// rows are delivery staging that would otherwise grow forever; the durable
/// records are `build_events` and `audit_events`. Each pass deletes one
/// bounded batch past the retention horizon and reports any remaining
/// unpublished backlog.
async fn run_outbox_reaper(
    store: Store,
    organization_id: Uuid,
    retention_hours: u32,
) -> Result<()> {
    const REAP_BATCH_LIMIT: u32 = 512;
    const REAP_POLL_INTERVAL: Duration = Duration::from_secs(15 * 60);
    loop {
        match store
            .reap_outbox(organization_id, retention_hours, REAP_BATCH_LIMIT)
            .await
        {
            Ok(0) => {}
            Ok(reaped) => {
                eprintln!(
                    "outbox reaper deleted {reaped} rows past the {retention_hours}h retention \
                     horizon"
                );
                if reaped == u64::from(REAP_BATCH_LIMIT) {
                    continue;
                }
            }
            Err(error) => {
                eprintln!("outbox reap failed: {error}");
                tokio::time::sleep(REAP_POLL_INTERVAL).await;
                continue;
            }
        }
        match store.outbox_backlog(organization_id).await {
            Ok(backlog) if backlog.unpublished_count > 0 => {
                eprintln!(
                    "outbox backlog: {} unpublished reapable rows of {} total ({} protected \
                     proof rows are never reaped; no consumer is shipped; reapable rows \
                     expire after {retention_hours}h)",
                    backlog.unpublished_count, backlog.total_count, backlog.protected_count
                );
            }
            Ok(_) => {}
            Err(error) => eprintln!("outbox backlog scan failed: {error}"),
        }
        tokio::time::sleep(REAP_POLL_INTERVAL).await;
    }
}

fn required(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} is required"))
}

fn effect_plan_from_environment() -> Result<Option<EffectExecutionPlan>> {
    let path = match std::env::var("MCLOVING_EFFECT_RUNTIME_PLAN") {
        Ok(path) if !path.is_empty() => PathBuf::from(path),
        Ok(_) => bail!("MCLOVING_EFFECT_RUNTIME_PLAN must not be empty"),
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(error) => return Err(error).context("read MCLOVING_EFFECT_RUNTIME_PLAN"),
    };
    if !path.is_absolute() {
        bail!("MCLOVING_EFFECT_RUNTIME_PLAN must be an absolute path");
    }
    let metadata = std::fs::symlink_metadata(&path)
        .with_context(|| format!("inspect effect runtime plan {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 1024 * 1024 {
        bail!("effect runtime plan must be a bounded regular non-symlink file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("effect runtime plan must not be accessible by group or other users");
        }
    }
    let bytes = std::fs::read(&path)
        .with_context(|| format!("read effect runtime plan {}", path.display()))?;
    mcloving_external_connector::parse_json_no_duplicates(&bytes)
        .context("parse strict effect runtime plan")
        .map(Some)
}

fn connector_mapping_catalog_from_environment() -> Result<Option<ConnectorMappingCatalog>> {
    let path = match std::env::var("MCLOVING_EFFECT_MAPPING_CATALOG") {
        Ok(path) if !path.is_empty() => PathBuf::from(path),
        Ok(_) => bail!("MCLOVING_EFFECT_MAPPING_CATALOG must not be empty"),
        Err(std::env::VarError::NotPresent) => {
            if std::env::var_os("MCLOVING_EFFECT_MAPPING_CATALOG_SHA256").is_some() {
                bail!(
                    "MCLOVING_EFFECT_MAPPING_CATALOG_SHA256 requires MCLOVING_EFFECT_MAPPING_CATALOG"
                );
            }
            return Ok(None);
        }
        Err(error) => return Err(error).context("read MCLOVING_EFFECT_MAPPING_CATALOG"),
    };
    if !path.is_absolute() {
        bail!("MCLOVING_EFFECT_MAPPING_CATALOG must be an absolute path");
    }
    let expected_digest = required("MCLOVING_EFFECT_MAPPING_CATALOG_SHA256")?;
    if expected_digest.len() != 64
        || !expected_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("MCLOVING_EFFECT_MAPPING_CATALOG_SHA256 must be lowercase SHA-256 hex");
    }
    let metadata = std::fs::symlink_metadata(&path)
        .with_context(|| format!("inspect connector mapping catalog {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 1024 * 1024 {
        bail!("connector mapping catalog must be a bounded regular non-symlink file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o022 != 0 {
            bail!("connector mapping catalog must not be writable by group or other users");
        }
    }
    let bytes = std::fs::read(&path)
        .with_context(|| format!("read connector mapping catalog {}", path.display()))?;
    let actual_digest = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if actual_digest != expected_digest {
        bail!("connector mapping catalog digest does not match deployment configuration");
    }
    let catalog: ConnectorMappingCatalog =
        mcloving_external_connector::parse_json_no_duplicates(&bytes)
            .context("parse strict connector mapping catalog")?;
    catalog
        .validate()
        .context("validate connector mapping catalog")?;
    Ok(Some(catalog))
}

fn parse_positive<T>(name: &str) -> Result<T>
where
    T: std::str::FromStr + PartialOrd + Default,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    let value = required(name)?
        .parse::<T>()
        .with_context(|| format!("{name} must be an integer"))?;
    if value <= T::default() {
        bail!("{name} must be positive");
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn effect_catalog(mappings: Vec<(&str, &str)>) -> ConnectorMappingCatalog {
        ConnectorMappingCatalog {
            schema_version: mcloving_controller_api::CONNECTOR_MAPPING_CATALOG_V1.to_owned(),
            profile: "private-linux-x86_64".to_owned(),
            generation: 1,
            mappings: mappings
                .into_iter()
                .map(|(mapping_id, mapping_digest)| {
                    mcloving_controller_api::ConnectorMappingRecord {
                        mapping_id: mapping_id.to_owned(),
                        mapping_digest: mapping_digest.to_owned(),
                    }
                })
                .collect(),
        }
    }

    #[test]
    fn artifact_agent_token_is_validated_before_bootstrap() {
        let api_token = "a".repeat(32);
        let short_artifact_token = "b".repeat(31);
        assert_eq!(
            validate_artifact_agent_token(&api_token, &short_artifact_token)
                .unwrap_err()
                .to_string(),
            "MCLOVING_ARTIFACT_AGENT_TOKEN must contain at least 32 bytes"
        );
        assert!(validate_artifact_agent_token(&api_token, &api_token).is_err());
        assert!(validate_artifact_agent_token(&api_token, &"b".repeat(32)).is_ok());
    }

    #[test]
    fn repeated_session_epoch_churn_names_a_suspected_identity_collision() {
        let churn = SessionEpochChurn::default();
        churn.record_advance("windows-1");
        churn.record_advance("windows-1");
        assert_eq!(churn.suspected_collision("windows-1"), None);
        assert_eq!(churn.suspected_collision("other-agent"), None);
        let quiet = stale_session_status(&churn, "windows-1");
        assert_eq!(quiet.code(), tonic::Code::FailedPrecondition);
        assert_eq!(quiet.message(), "stale agent session epoch");

        churn.record_advance("windows-1");
        let collision = churn
            .suspected_collision("windows-1")
            .expect("threshold advances within the window name the collision");
        assert_eq!(
            collision,
            "agent identity collision suspected for windows-1: session epoch advanced \
             3 times in 60 seconds; a second executor may be sharing this agent identity"
        );
        let named = stale_session_status(&churn, "windows-1");
        assert_eq!(named.code(), tonic::Code::FailedPrecondition);
        assert!(named.message().contains("stale agent session epoch"));
        assert!(
            named
                .message()
                .contains("agent identity collision suspected for windows-1")
        );
        assert_eq!(churn.suspected_collision("other-agent"), None);
    }

    #[test]
    fn tracked_session_advances_are_bounded() {
        let churn = SessionEpochChurn::default();
        for _ in 0..(MAX_TRACKED_SESSION_ADVANCES + 10) {
            churn.record_advance("windows-1");
        }
        let advances = churn
            .advances_by_agent
            .lock()
            .expect("session churn lock is never poisoned");
        assert!(advances.get("windows-1").unwrap().len() <= MAX_TRACKED_SESSION_ADVANCES);
    }

    #[test]
    fn advertised_effect_mappings_exactly_match_the_embedded_worker() {
        let first_digest = format!("sha256:{}", "a".repeat(64));
        let second_digest = format!("sha256:{}", "b".repeat(64));
        let exact = effect_catalog(vec![("notification.v1", &first_digest)]);
        assert!(
            validate_effect_mapping_configuration(
                Some(("notification.v1", &first_digest)),
                Some(&exact),
            )
            .is_ok()
        );

        let extra = effect_catalog(vec![
            ("notification.v1", &first_digest),
            ("deployment.v1", &second_digest),
        ]);
        assert!(
            validate_effect_mapping_configuration(
                Some(("notification.v1", &first_digest)),
                Some(&extra),
            )
            .is_err()
        );
        assert!(validate_effect_mapping_configuration(None, Some(&exact)).is_err());
        assert!(
            validate_effect_mapping_configuration(Some(("notification.v1", &first_digest)), None,)
                .is_err()
        );
        assert!(validate_effect_mapping_configuration(None, None).is_ok());
    }

    #[test]
    fn composite_authority_token_preserves_restore_epoch_and_fence() {
        let token = (u64::from(17_u32) << 32) | u64::from(23_u32);
        assert_eq!(decode_authority_token(token), (17, 23));
    }

    #[test]
    fn permanent_credential_contract_errors_are_not_retried_as_internal_failures() {
        let invalid_grants =
            StoreError::InvalidSecurityOperation("unrequested credential target".to_owned());
        assert_eq!(
            credential_store_error(invalid_grants).code(),
            tonic::Code::FailedPrecondition
        );
        assert_eq!(
            credential_store_error(StoreError::InvalidAgentSession).code(),
            tonic::Code::FailedPrecondition
        );
    }

    #[test]
    fn certificate_bindings_are_exact_and_fail_closed() {
        let digest = "11".repeat(32);
        let bindings = AgentIdentityBindings::parse(&format!(
            "# sha256 agent trust-pool organization\n{digest} windows-1 trusted-windows 00000000-0000-0000-0000-000000000123\n"
        ))
        .unwrap();
        assert_eq!(
            bindings.by_certificate_sha256.get(&[0x11; 32]).unwrap(),
            &AgentIdentity {
                agent_id: "windows-1".to_owned(),
                trust_pool: "trusted-windows".to_owned(),
                organization_id: Uuid::from_u128(0x123),
            }
        );
        assert!(AgentIdentityBindings::parse("").is_err());
        assert!(
            AgentIdentityBindings::parse(&format!(
                "{digest} agent pool\n{digest} other other-pool\n"
            ))
            .is_err()
        );
        let rotated_digest = "22".repeat(32);
        assert!(
            AgentIdentityBindings::parse(&format!(
                "{digest} agent pool 00000000-0000-0000-0000-000000000123\n{rotated_digest} agent pool 00000000-0000-0000-0000-000000000123\n"
            ))
            .is_ok()
        );
        assert!(
            AgentIdentityBindings::parse(&format!(
                "{digest} agent trusted 00000000-0000-0000-0000-000000000123\n{rotated_digest} agent untrusted 00000000-0000-0000-0000-000000000123\n"
            ))
            .is_err()
        );
        assert!(
            AgentIdentityBindings::parse(
                "not-a-digest agent pool 00000000-0000-0000-0000-000000000123\n"
            )
            .is_err()
        );
        let legacy_error =
            AgentIdentityBindings::parse(&format!("{digest} agent pool\n")).unwrap_err();
        assert!(
            legacy_error
                .to_string()
                .contains("legacy three-column format")
        );
        assert!(legacy_error.to_string().contains("organization UUID"));
    }

    #[test]
    fn reconciliation_organization_is_certificate_bound() {
        let identity = AgentIdentity {
            agent_id: "agent-1".to_owned(),
            trust_pool: "trusted".to_owned(),
            organization_id: Uuid::from_u128(0x123),
        };
        assert_eq!(
            authenticated_organization(&identity, "00000000-0000-0000-0000-000000000123").unwrap(),
            identity.organization_id
        );
        assert_eq!(
            authenticated_organization(&identity, "00000000-0000-0000-0000-000000000999")
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        assert_eq!(
            authenticated_organization(&identity, "not-a-uuid")
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
    }

    #[test]
    fn oidc_clock_skew_has_a_security_ceiling() {
        assert_eq!(
            bounded_u64_at_most("MCLOVING_OIDC_CLOCK_SKEW_SECONDS", 300, 300).unwrap(),
            300
        );
        assert!(
            bounded_u64_at_most("MCLOVING_OIDC_CLOCK_SKEW_SECONDS", 301, 300)
                .unwrap_err()
                .to_string()
                .contains("must be at most 300")
        );
    }

    #[test]
    fn oidc_configuration_digest_binds_local_security_controls() {
        let first_redirects = BTreeSet::from(["https://app.example.test/callback".to_owned()]);
        let second_redirects = BTreeSet::from(["https://new.example.test/callback".to_owned()]);
        let fields = [
            "https://id.example.test",
            "audience",
            "https://id.example.test/authorize",
            "https://id.example.test/token",
            "https://id.example.test/jwks",
            "client",
            "groups",
        ];
        let baseline = oidc_configuration_digest(
            &fields,
            Some("secret"),
            &first_redirects,
            900,
            28_800,
            10,
            60,
            256 * 1024,
            false,
        );
        assert_ne!(
            baseline,
            oidc_configuration_digest(
                &fields,
                Some("secret"),
                &second_redirects,
                900,
                28_800,
                10,
                60,
                256 * 1024,
                false,
            )
        );
        assert_ne!(
            baseline,
            oidc_configuration_digest(
                &fields,
                Some("secret"),
                &first_redirects,
                901,
                28_800,
                10,
                60,
                256 * 1024,
                false,
            )
        );
    }
}
