use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use mcloving_controller_api::{ApiState, router};
use mcloving_controller_store::{ClaimRequest, Store};
use mcloving_execution_spine::{WorkerConfig, run_claim};
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;
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
    tokio::pin!(server);
    let worker_loop = run_embedded_worker(store, worker);
    tokio::pin!(worker_loop);
    tokio::select! {
        result = &mut server => result,
        result = &mut worker_loop => result,
    }
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
