use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use mcloving_agent_protocol::wire::agent_control_server::{AgentControl, AgentControlServer};
use mcloving_agent_protocol::wire::{
    AttemptAuthority, CancellationCompletion, CancellationDisposition, CancellationOutcome,
    CancellationReceipt, OpenSessionRequest, OpenSessionResponse, ReconciliationDirective,
    ReconciliationReport, RotateCertificateRequest, RotateCertificateResponse,
};
use mcloving_agent_protocol::{ProtocolRange, negotiate};
use mcloving_controller_api::{ApiState, router};
use mcloving_controller_store::{
    AgentCancellationCompletion, AgentCancellationDisposition, AgentCancellationOutcome,
    AgentReconciliationDisposition, ClaimRequest, Store,
};
use mcloving_execution_spine::{WorkerConfig, run_claim};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;
use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};
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
    let agent_server = run_agent_control_server(store.clone());
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
    identities: Arc<AgentIdentityBindings>,
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
            match self
                .store
                .agent_reconciliation_disposition(
                    organization_id,
                    attempt_id,
                    fence,
                    restore_epoch,
                    &request.agent_id,
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
            return Err(Status::failed_precondition("stale agent session epoch"));
        }
        let organization_id = request
            .organization_id
            .parse()
            .map_err(|_| Status::invalid_argument("organization_id must be a UUID"))?;
        let attempt_id = request
            .attempt_id
            .parse()
            .map_err(|_| Status::invalid_argument("attempt_id must be a UUID"))?;
        let outcome = match CancellationOutcome::try_from(request.outcome) {
            Ok(CancellationOutcome::Terminated) => AgentCancellationOutcome::Terminated,
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
            },
        }))
    }
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

async fn run_agent_control_server(store: Store) -> Result<()> {
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
    let identities = AgentIdentityBindings::read(PathBuf::from(required(
        "MCLOVING_AGENT_IDENTITY_BINDINGS_PATH",
    )?))
    .context("read agent certificate identity bindings")?;
    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(certificate, private_key))
        .client_ca_root(Certificate::from_pem(client_ca));
    let service = ControllerAgentService {
        store,
        identities: Arc::new(identities),
    };
    Server::builder()
        .tls_config(tls)
        .context("configure agent-control mTLS")?
        .add_service(AgentControlServer::new(service))
        .serve(address)
        .await
        .with_context(|| format!("serve agent control on {address}"))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AgentIdentity {
    agent_id: String,
    trust_pool: String,
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
        let mut trust_pool_by_agent = BTreeMap::new();
        for (index, raw_line) in source.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
            if fields.len() != 3 {
                bail!(
                    "identity binding line {} must contain SHA-256, agent ID, and trust pool",
                    index + 1
                );
            }
            let digest = parse_sha256(fields[0]).with_context(|| {
                format!("identity binding line {} has invalid SHA-256", index + 1)
            })?;
            let identity = AgentIdentity {
                agent_id: fields[1].to_owned(),
                trust_pool: fields[2].to_owned(),
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
            if let Some(existing_trust_pool) = trust_pool_by_agent.get(&identity.agent_id) {
                if existing_trust_pool != &identity.trust_pool {
                    bail!(
                        "identity binding line {} assigns agent {} to conflicting trust pools",
                        index + 1,
                        identity.agent_id
                    );
                }
            } else {
                trust_pool_by_agent.insert(identity.agent_id.clone(), identity.trust_pool.clone());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composite_authority_token_preserves_restore_epoch_and_fence() {
        let token = (u64::from(17_u32) << 32) | u64::from(23_u32);
        assert_eq!(decode_authority_token(token), (17, 23));
    }

    #[test]
    fn certificate_bindings_are_exact_and_fail_closed() {
        let digest = "11".repeat(32);
        let bindings = AgentIdentityBindings::parse(&format!(
            "# sha256 agent trust-pool\n{digest} windows-1 trusted-windows\n"
        ))
        .unwrap();
        assert_eq!(
            bindings.by_certificate_sha256.get(&[0x11; 32]).unwrap(),
            &AgentIdentity {
                agent_id: "windows-1".to_owned(),
                trust_pool: "trusted-windows".to_owned(),
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
                "{digest} agent pool\n{rotated_digest} agent pool\n"
            ))
            .is_ok()
        );
        assert!(
            AgentIdentityBindings::parse(&format!(
                "{digest} agent trusted\n{rotated_digest} agent untrusted\n"
            ))
            .is_err()
        );
        assert!(AgentIdentityBindings::parse("not-a-digest agent pool\n").is_err());
        assert!(AgentIdentityBindings::parse(&format!("{digest} agent\n")).is_err());
    }
}
