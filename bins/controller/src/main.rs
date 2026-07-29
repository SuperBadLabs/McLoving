use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use mcloving_agent_protocol::wire::agent_control_server::{AgentControl, AgentControlServer};
use mcloving_agent_protocol::wire::{
    OpenSessionRequest, OpenSessionResponse, ReconciliationDirective, ReconciliationReport,
    RotateCertificateRequest, RotateCertificateResponse,
};
use mcloving_agent_protocol::{ProtocolRange, negotiate};
use mcloving_controller_api::{ApiState, router};
use mcloving_controller_store::{AgentReconciliationDisposition, ClaimRequest, Store};
use mcloving_execution_spine::{WorkerConfig, run_claim};
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<()> {
    let migration_database_url = std::env::var("MCLOVING_MIGRATION_DATABASE_URL")
        .context("MCLOVING_MIGRATION_DATABASE_URL is required")?;
    let runtime_database_url =
        std::env::var("MCLOVING_DATABASE_URL").context("MCLOVING_DATABASE_URL is required")?;
    if migration_database_url == runtime_database_url {
        bail!("migration and runtime database credentials must be distinct");
    }
    let bearer_token =
        std::env::var("MCLOVING_API_TOKEN").context("MCLOVING_API_TOKEN is required")?;
    let listen = std::env::var("MCLOVING_LISTEN").unwrap_or_else(|_| "127.0.0.1:8080".to_owned());
    let migration_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&migration_database_url)
        .await
        .context("connect to PostgreSQL migration role")?;
    Store::new(migration_pool.clone())
        .migrate()
        .await
        .context("migrate controller store")?;
    migration_pool.close().await;

    let runtime_pool = PgPoolOptions::new()
        .max_connections(16)
        .connect(&runtime_database_url)
        .await
        .context("connect to PostgreSQL runtime role")?;
    let store = Store::new(runtime_pool);
    let state = ApiState::new(store.clone(), &bearer_token).context("configure public API")?;
    let worker = EmbeddedWorker::from_environment()?;
    tokio::fs::create_dir_all(&worker.config.workspace_root)
        .await
        .context("create embedded worker workspace root")?;
    if let Some(parent) = worker.config.journal_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .context("create embedded worker journal directory")?;
    }
    let listener = TcpListener::bind(&listen)
        .await
        .with_context(|| format!("bind controller to {listen}"))?;
    let server = async {
        axum::serve(listener, router(state))
            .await
            .context("serve public API")
    };
    let agent_server = run_agent_control_server(ControllerAgentService {
        store: store.clone(),
    });
    tokio::pin!(server);
    tokio::pin!(agent_server);
    let worker_loop = run_embedded_worker(store, worker);
    tokio::pin!(worker_loop);
    tokio::select! {
        result = &mut server => result,
        result = &mut agent_server => result,
        result = &mut worker_loop => result,
    }
}

#[derive(Clone)]
struct ControllerAgentService {
    store: Store,
}

#[tonic::async_trait]
impl AgentControl for ControllerAgentService {
    async fn open_session(
        &self,
        request: Request<OpenSessionRequest>,
    ) -> Result<Response<OpenSessionResponse>, Status> {
        let request = request.into_inner();
        if request.agent_id.trim().is_empty() || request.trust_pool.trim().is_empty() {
            return Err(Status::invalid_argument(
                "agent_id and trust_pool are required",
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
            "linux-process-group-v1".to_owned(),
            "windows-job-object-v1".to_owned(),
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
            return Err(Status::failed_precondition("stale agent session epoch"));
        }
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
        let request = request.into_inner();
        if !self
            .store
            .authorize_agent_session(&request.agent_id, request.session_epoch)
            .await
            .map_err(internal_store_error)?
        {
            return Err(Status::failed_precondition("stale agent session epoch"));
        }
        let mut retained = BTreeSet::new();
        let mut cancelled = BTreeSet::new();
        for attempt in request.attempts {
            let organization_id = attempt
                .organization_id
                .parse()
                .map_err(|_| Status::invalid_argument("organization_id must be a UUID"))?;
            let attempt_id = attempt
                .attempt_id
                .parse()
                .map_err(|_| Status::invalid_argument("attempt_id must be a UUID"))?;
            let fence = i64::try_from(attempt.fence_token)
                .map_err(|_| Status::invalid_argument("fence_token is out of range"))?;
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
            match self
                .store
                .agent_reconciliation_disposition(
                    organization_id,
                    attempt_id,
                    fence,
                    &request.agent_id,
                )
                .await
                .map_err(internal_store_error)?
            {
                AgentReconciliationDisposition::Retain => {
                    retained.insert(attempt.attempt_id);
                }
                AgentReconciliationDisposition::Cancel => {
                    cancelled.insert(attempt.attempt_id);
                }
            }
        }
        Ok(Response::new(ReconciliationDirective {
            session_epoch: request.session_epoch,
            retain_attempt_ids: retained.into_iter().collect(),
            cancel_attempt_ids: cancelled.into_iter().collect(),
        }))
    }
}

fn internal_store_error(error: mcloving_controller_store::StoreError) -> Status {
    Status::internal(format!("controller store failed: {error}"))
}

async fn run_agent_control_server(service: ControllerAgentService) -> Result<()> {
    let Some(listen) = std::env::var("MCLOVING_AGENT_LISTEN").ok() else {
        std::future::pending::<()>().await;
        unreachable!("pending agent server future returned")
    };
    let address: SocketAddr = listen
        .parse()
        .with_context(|| format!("MCLOVING_AGENT_LISTEN is invalid: {listen}"))?;
    let certificate = std::fs::read(required("MCLOVING_AGENT_SERVER_CERT_PATH")?)
        .context("read agent-control server certificate")?;
    let private_key = std::fs::read(required("MCLOVING_AGENT_SERVER_KEY_PATH")?)
        .context("read agent-control server private key")?;
    let client_ca = std::fs::read(required("MCLOVING_AGENT_CLIENT_CA_PATH")?)
        .context("read agent-control client CA")?;
    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(certificate, private_key))
        .client_ca_root(Certificate::from_pem(client_ca));
    Server::builder()
        .tls_config(tls)
        .context("configure agent-control mTLS")?
        .add_service(AgentControlServer::new(service))
        .serve(address)
        .await
        .with_context(|| format!("serve agent control on {address}"))
}

struct EmbeddedWorker {
    organization_id: Uuid,
    scheduler_id: String,
    capabilities: Vec<String>,
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

fn required(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} is required"))
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
