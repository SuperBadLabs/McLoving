//! Native McLoving agent service runtime.

use std::collections::BTreeMap;
use std::env;
use std::fs::{File, OpenOptions};
use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

mod worker;

use mcloving_agent_protocol::wire;
use mcloving_agent_protocol::wire::agent_control_client::AgentControlClient;
use mcloving_agent_protocol::wire::{
    AttemptState, CancellationCompletion, CancellationDisposition, CancellationOutcome,
    OpenSessionRequest, ProtocolOffer, ReconciliationReport as WireReport,
};
use mcloving_agent_protocol::{
    ATTEMPT_CREDENTIALS_FEATURE, CURRENT_SESSION_EPOCH_METADATA, OutboundMtlsConfig,
    PROTOCOL_MAJOR, PROTOCOL_MINOR, RECOVERED_DISCHARGE_FEATURE, TransportError,
    WORK_COMPLETION_SUBSTITUTION_FEATURE, WORK_DELIVERY_FEATURE,
};
#[cfg(windows)]
use mcloving_agent_runtime::Acceptance;
use mcloving_agent_runtime::executor::ExecutionError;
#[cfg(windows)]
use mcloving_agent_runtime::executor::{ExecutionMode, ExecutionRequest, execute_with_spawn_hook};
use mcloving_agent_runtime::{AttemptPhase, Journal, JournalError, ReconciliationReport};
#[cfg(windows)]
use std::ffi::OsString;
use thiserror::Error;
use tokio::time::{MissedTickBehavior, interval, sleep, timeout};
use tokio_util::sync::CancellationToken;

const RECONCILIATION_INTERVAL: Duration = Duration::from_secs(30);
const RECONNECT_DELAY: Duration = Duration::from_secs(2);
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);
const OPEN_SESSION_TIMEOUT: Duration = Duration::from_secs(15);
/// Consecutive stale-session-epoch session failures before the retry log
/// names a suspected identity collision. A single healthy agent catches up a
/// lagging journal inside one enrollment, so repeated stale rejections mean
/// another executor keeps advancing this identity's epoch.
const STALE_SESSION_COLLISION_THRESHOLD: u32 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentConfig {
    pub agent_id: String,
    pub trust_pool: String,
    pub organization_id: String,
    pub controller_uri: String,
    pub controller_dns_name: String,
    pub controller_ca_path: PathBuf,
    pub agent_certificate_path: PathBuf,
    pub agent_private_key_path: PathBuf,
    pub journal_path: PathBuf,
    pub workspace_root: PathBuf,
    pub session_receipt_path: Option<PathBuf>,
    pub minimum_session_epoch: u64,
    pub lease_seconds: u32,
    pub poll_interval: Duration,
    pub lease_renewal_interval: Duration,
    pub termination_grace: Duration,
}

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("required configuration {0} is missing or empty")]
    MissingConfig(&'static str),
    #[error("configuration MCLOVING_AGENT_MINIMUM_SESSION_EPOCH is invalid")]
    InvalidMinimumSessionEpoch,
    #[error("configuration {0} is invalid")]
    InvalidConfig(&'static str),
    #[error("agent journal failed: {0}")]
    Journal(#[from] JournalError),
    #[error("agent configuration or identity file I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("outbound mTLS configuration failed: {0}")]
    Transport(#[from] TransportError),
    #[error("controller connection failed: {0}")]
    Connect(#[from] tonic::transport::Error),
    #[error("controller RPC failed: {0}")]
    Rpc(#[from] tonic::Status),
    #[error("controller returned a stale session epoch")]
    StaleSession,
    #[error("controller rejected the current fenced work authority")]
    StaleAuthority,
    #[error("agent has an unresolved recovered attempt and will not poll for more work")]
    UnresolvedReconciliation,
    #[error(
        "attempt {organization}/{attempt} was parked for reconciliation by its own execution: {cause}"
    )]
    ExecutionReconciliationRequired {
        organization: String,
        attempt: String,
        cause: String,
    },
    #[error("controller returned an invalid work assignment: {0}")]
    InvalidAssignment(String),
    #[error("execution specification is invalid: {0}")]
    InvalidSpec(#[from] serde_json::Error),
    #[error("agent execution failed: {0}")]
    Execution(#[from] ExecutionError),
    #[error("controller selected an unsupported protocol minor")]
    UnsupportedProtocol,
    #[error("agent identity and journal are already active in another process")]
    AlreadyRunning,
    #[error("agent probe exceeded its bounded deadline")]
    ProbeTimeout,
    #[error("open-session RPC exceeded its bounded deadline")]
    OpenSessionTimeout,
    #[error("lease renewal RPC exceeded its safe deadline")]
    LeaseRenewalTimeout,
    #[error("authority RPC exceeded its bounded lease deadline")]
    AuthorityRpcTimeout,
    #[error("work poll RPC exceeded its bounded deadline")]
    PollTimeout,
    #[error("agent service was stopped")]
    Stopped,
    #[error("journal path cannot be represented in the wire protocol")]
    NonUtf8Path,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoveredCancellation {
    Terminated,
    AlreadyExited,
    #[cfg(unix)]
    RetireStale,
    ReconciliationRequired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionReceipt {
    pub session_epoch: u64,
    pub active_attempts: usize,
}

struct AgentInstanceGuard {
    _lock: File,
}

impl Drop for AgentInstanceGuard {
    fn drop(&mut self) {
        let _ = self._lock.unlock();
    }
}

impl AgentConfig {
    pub fn from_environment() -> Result<Self, AgentError> {
        Self::from_values(&env::vars().collect())
    }

    pub fn from_values(values: &BTreeMap<String, String>) -> Result<Self, AgentError> {
        let required = |name: &'static str| {
            values
                .get(name)
                .filter(|value| !value.trim().is_empty())
                .cloned()
                .ok_or(AgentError::MissingConfig(name))
        };
        let minimum_session_epoch =
            values
                .get("MCLOVING_AGENT_MINIMUM_SESSION_EPOCH")
                .map_or(Ok(0), |value| {
                    value
                        .parse()
                        .map_err(|_| AgentError::InvalidMinimumSessionEpoch)
                })?;
        let lease_seconds = parse_config::<u32>(values, "MCLOVING_AGENT_LEASE_SECONDS", 30)?;
        if !(5..=300).contains(&lease_seconds) {
            return Err(AgentError::InvalidConfig("MCLOVING_AGENT_LEASE_SECONDS"));
        }
        let poll_milliseconds =
            parse_config::<u64>(values, "MCLOVING_AGENT_POLL_MILLISECONDS", 500)?;
        let renewal_milliseconds =
            parse_config::<u64>(values, "MCLOVING_AGENT_RENEW_MILLISECONDS", 5_000)?;
        let termination_grace_milliseconds = parse_config::<u64>(
            values,
            "MCLOVING_AGENT_TERMINATION_GRACE_MILLISECONDS",
            2_000,
        )?;
        if poll_milliseconds == 0
            || renewal_milliseconds == 0
            || termination_grace_milliseconds == 0
            || renewal_milliseconds >= u64::from(lease_seconds.saturating_sub(1)) * 1_000
        {
            return Err(AgentError::InvalidConfig(
                "agent polling, renewal, or termination timing",
            ));
        }
        Ok(Self {
            agent_id: required("MCLOVING_AGENT_ID")?,
            trust_pool: required("MCLOVING_AGENT_TRUST_POOL")?,
            organization_id: required("MCLOVING_AGENT_ORGANIZATION_ID")?,
            controller_uri: required("MCLOVING_CONTROLLER_URI")?,
            controller_dns_name: required("MCLOVING_CONTROLLER_DNS_NAME")?,
            controller_ca_path: PathBuf::from(required("MCLOVING_CONTROLLER_CA_PATH")?),
            agent_certificate_path: PathBuf::from(required("MCLOVING_AGENT_CERTIFICATE_PATH")?),
            agent_private_key_path: PathBuf::from(required("MCLOVING_AGENT_PRIVATE_KEY_PATH")?),
            journal_path: PathBuf::from(required("MCLOVING_AGENT_JOURNAL_PATH")?),
            workspace_root: PathBuf::from(required("MCLOVING_AGENT_WORKSPACE_ROOT")?),
            session_receipt_path: values
                .get("MCLOVING_AGENT_SESSION_RECEIPT_PATH")
                .filter(|value| !value.trim().is_empty())
                .map(PathBuf::from),
            minimum_session_epoch,
            lease_seconds,
            poll_interval: Duration::from_millis(poll_milliseconds),
            lease_renewal_interval: Duration::from_millis(renewal_milliseconds),
            termination_grace: Duration::from_millis(termination_grace_milliseconds),
        })
    }
}

fn parse_config<T>(
    values: &BTreeMap<String, String>,
    name: &'static str,
    default: T,
) -> Result<T, AgentError>
where
    T: std::str::FromStr,
{
    values.get(name).map_or(Ok(default), |value| {
        value.parse().map_err(|_| AgentError::InvalidConfig(name))
    })
}

pub async fn run_until_stopped(
    config: &AgentConfig,
    stop: CancellationToken,
) -> Result<(), AgentError> {
    let _instance = acquire_instance_guard(config)?;
    let mut consecutive_stale_sessions: u32 = 0;
    let mut last_session_error = String::new();
    let mut repeated_session_errors: u64 = 0;
    loop {
        if stop.is_cancelled() {
            return Ok(());
        }
        match run_session(config, stop.clone()).await {
            Ok(()) => return Ok(()),
            Err(error) if !stop.is_cancelled() => {
                consecutive_stale_sessions = if names_stale_session_epoch(&error) {
                    consecutive_stale_sessions.saturating_add(1)
                } else {
                    0
                };
                // A parked or partitioned agent hits the same failure every
                // reconnect; repeating it at full cadence floods the log and
                // rotates away the one line naming the failure that started
                // the streak. Duplicates are logged at powers of two.
                let message = error.to_string();
                if message == last_session_error {
                    repeated_session_errors = repeated_session_errors.saturating_add(1);
                    if repeated_session_errors.is_power_of_two() {
                        eprintln!(
                            "agent session ended; retrying: {message} (unchanged for \
                             {repeated_session_errors} consecutive sessions)"
                        );
                    }
                } else {
                    last_session_error = message;
                    repeated_session_errors = 0;
                    eprintln!("agent session ended; retrying: {error}");
                }
                if consecutive_stale_sessions >= STALE_SESSION_COLLISION_THRESHOLD {
                    eprintln!(
                        "agent identity collision suspected: {consecutive_stale_sessions} \
                         consecutive stale session epoch rejections for agent {}; a second \
                         executor may be sharing this agent identity (verify \
                         MCLOVING_AGENT_ID and its certificate binding are unique)",
                        config.agent_id
                    );
                }
                tokio::select! {
                    () = stop.cancelled() => return Ok(()),
                    () = sleep(RECONNECT_DELAY) => {}
                }
            }
            Err(_) => return Ok(()),
        }
    }
}

/// Whether a session failure was a controller stale-session-epoch rejection —
/// the signature of a competing executor advancing this identity's epoch.
fn names_stale_session_epoch(error: &AgentError) -> bool {
    match error {
        AgentError::StaleSession => true,
        AgentError::Rpc(status) => status.message().contains("stale agent session epoch"),
        _ => false,
    }
}

pub async fn probe_once(config: &AgentConfig) -> Result<SessionReceipt, AgentError> {
    let _instance = acquire_instance_guard(config)?;
    with_probe_timeout(PROBE_TIMEOUT, async {
        let stop = CancellationToken::new();
        let (mut client, mut receipt) = open_session(config, stop.clone()).await?;
        send_reconciliation(config, &mut client, receipt.session_epoch, stop.clone()).await?;
        worker::recover_finalizations(config, &mut client, receipt.session_epoch, &stop).await?;
        receipt.active_attempts = Journal::open(&config.journal_path)?
            .reconcile()?
            .attempts
            .len();
        Ok(receipt)
    })
    .await
}

async fn with_probe_timeout<T>(
    deadline: Duration,
    operation: impl Future<Output = Result<T, AgentError>>,
) -> Result<T, AgentError> {
    timeout(deadline, operation)
        .await
        .map_err(|_| AgentError::ProbeTimeout)?
}

fn acquire_instance_guard(config: &AgentConfig) -> Result<AgentInstanceGuard, AgentError> {
    let lock_path = instance_lock_path(&config.journal_path);
    let lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(lock_path)?;
    match lock.try_lock() {
        Ok(()) => Ok(AgentInstanceGuard { _lock: lock }),
        Err(std::fs::TryLockError::WouldBlock) => Err(AgentError::AlreadyRunning),
        Err(std::fs::TryLockError::Error(error)) => Err(error.into()),
    }
}

fn instance_lock_path(journal_path: &Path) -> PathBuf {
    let mut path = journal_path.as_os_str().to_os_string();
    path.push(".agent.lock");
    path.into()
}

async fn run_session(config: &AgentConfig, stop: CancellationToken) -> Result<(), AgentError> {
    let (mut client, receipt) = open_session(config, stop.clone()).await?;
    publish_recovery_ready_session_receipt(
        config.session_receipt_path.as_deref(),
        receipt.session_epoch,
        async {
            send_reconciliation(config, &mut client, receipt.session_epoch, stop.clone()).await?;
            worker::recover_finalizations(config, &mut client, receipt.session_epoch, &stop).await
        },
    )
    .await?;
    let mut reconciliation_tick = interval(RECONCILIATION_INTERVAL);
    reconciliation_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    reconciliation_tick.tick().await;
    let mut work_tick = interval(config.poll_interval);
    work_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    work_tick.tick().await;
    // The poll interval paces how often an idle agent ASKS for work. It must
    // not also pace how fast work is DONE: with one assignment handled per
    // tick, a queue of ready units drains at one unit per interval, so every
    // unit after the first waits a full period for no reason. `drain` carries
    // "the last pass moved the queue" into the next iteration, which skips the
    // wait. Measured on mario at the shipped 500 ms default: 496 ms per stage
    // before, bounded by the executing work after.
    //
    // Starting true keeps the session's first poll immediate: the tick
    // consumed above is the interval's zero-delay first fire, and waiting out
    // a full period before ever asking would delay a session's first
    // assignment by one interval.
    let mut drain = true;
    loop {
        // Ready immediately while draining; otherwise the ordinary poll tick.
        let work_ready = async {
            if !drain {
                work_tick.tick().await;
            }
        };
        tokio::select! {
            () = stop.cancelled() => return Ok(()),
            _ = reconciliation_tick.tick() => {
                send_reconciliation(
                    config,
                    &mut client,
                    receipt.session_epoch,
                    stop.clone(),
                ).await?;
                worker::reclaim_terminal_spools(config).await?;
            }
            () = work_ready => {
                // Only executed or terminally refused work justifies asking
                // again at once. A declined assignment stays offered until its
                // lease lapses, so draining on it would spin on one offer.
                drain = worker::poll_and_run_one(
                    config,
                    &mut client,
                    receipt.session_epoch,
                    stop.clone(),
                ).await? == worker::PollOutcome::Progressed;
            }
        }
    }
}

async fn publish_recovery_ready_session_receipt<F>(
    path: Option<&Path>,
    session_epoch: u64,
    recovery_initialization: F,
) -> Result<(), AgentError>
where
    F: Future<Output = Result<(), AgentError>>,
{
    recovery_initialization.await?;
    publish_authenticated_session_receipt(path, session_epoch)
}

async fn open_session(
    config: &AgentConfig,
    stop: CancellationToken,
) -> Result<
    (
        AgentControlClient<tonic::transport::Channel>,
        SessionReceipt,
    ),
    AgentError,
> {
    let mut journal = Journal::open(&config.journal_path)?;
    let mut session_epoch = journal.reserve_session_epoch(config.minimum_session_epoch)?;
    let active_attempts = journal.reconcile()?.attempts.len();
    let endpoint = outbound_config(config).await?.endpoint()?;
    let channel = tokio::select! {
        () = stop.cancelled() => return Err(AgentError::Stopped),
        result = endpoint.connect() => result?,
    };
    let mut client = AgentControlClient::new(channel);
    let mut caught_up = false;
    loop {
        let request = OpenSessionRequest {
            agent_id: config.agent_id.clone(),
            session_epoch,
            protocol: Some(ProtocolOffer {
                major: u32::from(PROTOCOL_MAJOR),
                minimum_minor: u32::from(PROTOCOL_MINOR),
                maximum_minor: u32::from(PROTOCOL_MINOR),
                features: vec![
                    "journal-v1".to_owned(),
                    platform_feature().to_owned(),
                    WORK_DELIVERY_FEATURE.to_owned(),
                    ATTEMPT_CREDENTIALS_FEATURE.to_owned(),
                    WORK_COMPLETION_SUBSTITUTION_FEATURE.to_owned(),
                    RECOVERED_DISCHARGE_FEATURE.to_owned(),
                ],
            }),
            trust_pool: config.trust_pool.clone(),
            capabilities: session_capabilities(),
        };
        let response = tokio::select! {
            () = stop.cancelled() => return Err(AgentError::Stopped),
            response = bounded_open_session_rpc(OPEN_SESSION_TIMEOUT, client.open_session(request)) => response,
        };
        let response = match response {
            Ok(response) => response.into_inner(),
            Err(AgentError::Rpc(status)) => {
                if !caught_up && let Some(floor) = stale_epoch_floor(&status) {
                    // The controller durably remembers a newer session epoch
                    // than this journal has reserved (for example after a
                    // documented journal replacement). Reserve past the
                    // returned floor in one durable step and re-offer once;
                    // the controller's fence itself is unchanged and a second
                    // rejection — the identity-collision signature — is
                    // surfaced unmodified.
                    caught_up = true;
                    session_epoch = journal.reserve_session_epoch(
                        floor.checked_add(1).ok_or(AgentError::StaleSession)?,
                    )?;
                    eprintln!(
                        "advancing agent session epoch to {session_epoch} to satisfy the \
                         controller's durable session floor"
                    );
                    continue;
                }
                return Err(AgentError::Rpc(status));
            }
            Err(error) => return Err(error),
        };
        if response.session_epoch != session_epoch {
            return Err(AgentError::StaleSession);
        }
        if response.protocol_minor != u32::from(PROTOCOL_MINOR) {
            return Err(AgentError::UnsupportedProtocol);
        }
        require_work_delivery_feature(&response.features)?;
        require_attempt_credentials_feature(&response.features)?;
        return Ok((
            client,
            SessionReceipt {
                session_epoch,
                active_attempts,
            },
        ));
    }
}

/// Extracts the controller's stored session epoch from a stale-epoch
/// open-session rejection, when the controller provided one.
fn stale_epoch_floor(status: &tonic::Status) -> Option<u64> {
    if status.code() != tonic::Code::FailedPrecondition
        || !status.message().contains("stale agent session epoch")
    {
        return None;
    }
    status
        .metadata()
        .get(CURRENT_SESSION_EPOCH_METADATA)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
}

async fn bounded_open_session_rpc<T>(
    deadline: Duration,
    operation: impl Future<Output = Result<tonic::Response<T>, tonic::Status>>,
) -> Result<tonic::Response<T>, AgentError> {
    timeout(deadline, operation)
        .await
        .map_err(|_| AgentError::OpenSessionTimeout)?
        .map_err(AgentError::from)
}

fn publish_authenticated_session_receipt(
    path: Option<&Path>,
    session_epoch: u64,
) -> Result<(), AgentError> {
    let Some(path) = path else {
        return Ok(());
    };
    if path.exists() {
        let receipt = std::fs::read_to_string(path)?;
        let existing_epoch = receipt
            .strip_prefix("session_epoch=")
            .and_then(|value| value.strip_suffix('\n'))
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "authenticated session receipt is malformed",
                )
            })?;
        match existing_epoch.cmp(&session_epoch) {
            std::cmp::Ordering::Equal => return Ok(()),
            std::cmp::Ordering::Greater => {
                return Err(AgentError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "authenticated session receipt epoch {existing_epoch} is newer than session epoch {session_epoch}"
                    ),
                )));
            }
            std::cmp::Ordering::Less => {}
        }
    }
    let mut pending = path.as_os_str().to_os_string();
    pending.push(format!(".pending.{}.{}", std::process::id(), session_epoch));
    let pending = PathBuf::from(pending);
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&pending)?;
        writeln!(file, "session_epoch={session_epoch}")?;
        file.sync_all()?;
        std::fs::rename(&pending, path)?;
        Ok::<(), std::io::Error>(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&pending);
    }
    result.map_err(AgentError::Io)
}

fn require_work_delivery_feature(features: &[String]) -> Result<(), AgentError> {
    if features
        .iter()
        .any(|feature| feature == WORK_DELIVERY_FEATURE)
    {
        Ok(())
    } else {
        Err(AgentError::UnsupportedProtocol)
    }
}

fn require_attempt_credentials_feature(features: &[String]) -> Result<(), AgentError> {
    if features
        .iter()
        .any(|feature| feature == ATTEMPT_CREDENTIALS_FEATURE)
    {
        Ok(())
    } else {
        Err(AgentError::UnsupportedProtocol)
    }
}

async fn send_reconciliation(
    config: &AgentConfig,
    client: &mut AgentControlClient<tonic::transport::Channel>,
    session_epoch: u64,
    stop: CancellationToken,
) -> Result<(), AgentError> {
    quiesce_recovered_executions(config).await?;
    let report = Journal::open(&config.journal_path)?.reconcile()?;
    let request = wire_report(config, session_epoch, &report)?;
    let directive = tokio::select! {
        () = stop.cancelled() => return Err(AgentError::Stopped),
        response = tokio::time::timeout(
            worker::lease_rpc_budget(Duration::from_secs(u64::from(config.lease_seconds))),
            client.reconcile(request),
        ) => response.map_err(|_| AgentError::LeaseRenewalTimeout)??,
    }
    .into_inner();
    if directive.session_epoch != session_epoch {
        return Err(AgentError::StaleSession);
    }
    let cancelled = directive
        .cancel_attempts
        .into_iter()
        .map(|authority| {
            (
                authority.organization_id,
                authority.attempt_id,
                authority.fence_token,
            )
        })
        .collect::<std::collections::BTreeSet<_>>();
    let retained = directive
        .retain_attempts
        .into_iter()
        .map(|authority| {
            (
                authority.organization_id,
                authority.attempt_id,
                authority.fence_token,
            )
        })
        .collect::<std::collections::BTreeSet<_>>();
    // Reconciliation-required attempts covered by the directive are settled
    // below and may be discharged by an explicit controller confirmation;
    // only an attempt the directive did not address keeps the session
    // fail-closed unconditionally.
    let mut unresolved = report.attempts.iter().any(|attempt| {
        attempt.phase == AttemptPhase::ReconciliationRequired
            && !cancellation_targets(&cancelled, attempt)
            && !cancellation_targets(&retained, attempt)
    });
    if !cancelled.is_empty() || !retained.is_empty() {
        let mut journal = Journal::open(&config.journal_path)?;
        for attempt in &report.attempts {
            if recovered_attempt_requires_cancellation_report(&cancelled, &retained, attempt) {
                let outcome =
                    if worker::recovered_attempt_has_durable_containment_proof(config, attempt)
                        .await?
                    {
                        journal.transition(
                            &attempt.organization_id,
                            &attempt.attempt_id,
                            attempt.fence_token,
                            attempt.session_epoch,
                            AttemptPhase::Cancelling,
                            attempt.process_id,
                        )?;
                        RecoveredCancellation::AlreadyExited
                    } else {
                        cancel_recovered_attempt(&mut journal, attempt, config.termination_grace)
                            .await?
                    };
                let cancellation_outcome = match outcome {
                    RecoveredCancellation::Terminated => CancellationOutcome::Terminated as i32,
                    RecoveredCancellation::AlreadyExited => {
                        CancellationOutcome::AlreadyExited as i32
                    }
                    #[cfg(unix)]
                    RecoveredCancellation::RetireStale => {
                        CancellationOutcome::IdentityMismatch as i32
                    }
                    RecoveredCancellation::ReconciliationRequired => {
                        CancellationOutcome::ReconciliationRequired as i32
                    }
                };
                if outcome != RecoveredCancellation::ReconciliationRequired
                    && worker::recovered_cancellation_requires_persistence(config, attempt).await?
                {
                    worker::persist_recovered_cancellation(
                        config,
                        &mut journal,
                        attempt,
                        cancellation_outcome,
                    )
                    .await?;
                }
                let request = CancellationCompletion {
                    agent_id: config.agent_id.clone(),
                    session_epoch,
                    organization_id: attempt.organization_id.clone(),
                    attempt_id: attempt.attempt_id.clone(),
                    fence_token: attempt.fence_token,
                    outcome: cancellation_outcome,
                };
                let receipt = tokio::select! {
                    () = stop.cancelled() => return Err(AgentError::Stopped),
                    response = tokio::time::timeout(
                        worker::lease_rpc_budget(Duration::from_secs(
                            u64::from(config.lease_seconds),
                        )),
                        client.complete_cancellation(request),
                    ) => response.map_err(|_| AgentError::LeaseRenewalTimeout)??,
                }
                .into_inner();
                if receipt.session_epoch != session_epoch {
                    return Err(AgentError::StaleSession);
                }
                let phase = recovered_cancellation_phase(outcome, receipt.disposition)?;
                journal.transition(
                    &attempt.organization_id,
                    &attempt.attempt_id,
                    attempt.fence_token,
                    attempt.session_epoch,
                    phase,
                    attempt.process_id,
                )?;
                if outcome == RecoveredCancellation::ReconciliationRequired
                    && phase == AttemptPhase::Aborted
                {
                    eprintln!(
                        "discharged recovered attempt {}/{} fence {}: the controller \
                         confirmed its fenced authority is disowned; terminal evidence \
                         is preserved in the journal and its spools are reclaimed under \
                         the terminal spool rules",
                        attempt.organization_id, attempt.attempt_id, attempt.fence_token
                    );
                }
                unresolved |= phase == AttemptPhase::ReconciliationRequired;
            }
        }
    }
    if unresolved {
        Err(AgentError::UnresolvedReconciliation)
    } else {
        Ok(())
    }
}

async fn quiesce_recovered_executions(config: &AgentConfig) -> Result<(), AgentError> {
    let report = Journal::open(&config.journal_path)?.reconcile()?;
    let mut journal = Journal::open(&config.journal_path)?;
    for attempt in &report.attempts {
        if !matches!(
            attempt.phase,
            AttemptPhase::Accepted | AttemptPhase::Running
        ) {
            continue;
        }
        let outcome =
            cancel_recovered_attempt(&mut journal, attempt, config.termination_grace).await?;
        if outcome != RecoveredCancellation::ReconciliationRequired
            && worker::recovered_cancellation_requires_persistence(config, attempt).await?
        {
            let cancellation_outcome = match outcome {
                RecoveredCancellation::Terminated => CancellationOutcome::Terminated as i32,
                RecoveredCancellation::AlreadyExited => CancellationOutcome::AlreadyExited as i32,
                #[cfg(unix)]
                RecoveredCancellation::RetireStale => CancellationOutcome::IdentityMismatch as i32,
                RecoveredCancellation::ReconciliationRequired => unreachable!("checked above"),
            };
            worker::persist_recovered_cancellation(
                config,
                &mut journal,
                attempt,
                cancellation_outcome,
            )
            .await?;
        }
    }
    Ok(())
}

fn recovered_cancellation_phase(
    outcome: RecoveredCancellation,
    disposition: i32,
) -> Result<AttemptPhase, AgentError> {
    let disposition = CancellationDisposition::try_from(disposition)
        .map_err(|_| AgentError::UnsupportedProtocol)?;
    if disposition == CancellationDisposition::Unspecified {
        return Err(AgentError::UnsupportedProtocol);
    }
    // An explicit fenced discharge is the one controller confirmation that
    // may retire a locally unverifiable recovered attempt: the controller
    // determined under the exact current session that this fence is disowned
    // (requeued, terminal, superseded by an operator retry, or unknown) and
    // can never act again. The agent never self-discharges on suspicion.
    if disposition == CancellationDisposition::DischargeRecovered {
        return Ok(AttemptPhase::Aborted);
    }
    // Local containment knowledge wins over a stale controller receipt. A
    // retired fence does not prove an unverifiable process group is gone.
    if outcome == RecoveredCancellation::ReconciliationRequired {
        return Ok(AttemptPhase::ReconciliationRequired);
    }
    Ok(match disposition {
        CancellationDisposition::Completed | CancellationDisposition::RetireStale => {
            AttemptPhase::Aborted
        }
        CancellationDisposition::ReconciliationRequired => AttemptPhase::ReconciliationRequired,
        CancellationDisposition::Unspecified | CancellationDisposition::DischargeRecovered => {
            unreachable!("validated above")
        }
    })
}

async fn cancel_recovered_attempt(
    journal: &mut Journal,
    attempt: &mcloving_agent_runtime::ReconciliationAttempt,
    termination_grace: Duration,
) -> Result<RecoveredCancellation, AgentError> {
    if attempt.phase == AttemptPhase::ReconciliationRequired {
        return Ok(RecoveredCancellation::ReconciliationRequired);
    }
    journal.transition(
        &attempt.organization_id,
        &attempt.attempt_id,
        attempt.fence_token,
        attempt.session_epoch,
        AttemptPhase::Cancelling,
        attempt.process_id,
    )?;
    match terminate_recovered_process(
        attempt.process_id,
        attempt.process_birth_identity.as_deref(),
        termination_grace,
    )
    .await?
    {
        RecoveredCancellation::ReconciliationRequired => {
            journal.transition(
                &attempt.organization_id,
                &attempt.attempt_id,
                attempt.fence_token,
                attempt.session_epoch,
                AttemptPhase::ReconciliationRequired,
                attempt.process_id,
            )?;
            Ok(RecoveredCancellation::ReconciliationRequired)
        }
        outcome => Ok(outcome),
    }
}

fn cancellation_targets(
    cancelled: &std::collections::BTreeSet<(String, String, u64)>,
    attempt: &mcloving_agent_runtime::ReconciliationAttempt,
) -> bool {
    cancelled.contains(&(
        attempt.organization_id.clone(),
        attempt.attempt_id.clone(),
        attempt.fence_token,
    ))
}

fn recovered_attempt_requires_cancellation_report(
    cancelled: &std::collections::BTreeSet<(String, String, u64)>,
    retained: &std::collections::BTreeSet<(String, String, u64)>,
    attempt: &mcloving_agent_runtime::ReconciliationAttempt,
) -> bool {
    cancellation_targets(cancelled, attempt)
        || (cancellation_targets(retained, attempt)
            && matches!(
                attempt.phase,
                AttemptPhase::Accepted
                    | AttemptPhase::Running
                    | AttemptPhase::ReconciliationRequired
            ))
}

#[cfg(unix)]
async fn terminate_recovered_process(
    process_id: Option<u32>,
    process_birth_identity: Option<&str>,
    termination_grace: Duration,
) -> Result<RecoveredCancellation, AgentError> {
    let Some(process_id) = process_id else {
        return Ok(RecoveredCancellation::AlreadyExited);
    };
    let Some(expected_identity) = process_birth_identity else {
        return Ok(RecoveredCancellation::ReconciliationRequired);
    };
    match process_birth_identity_for(process_id)? {
        // A dead process-group leader does not prove that its descendants are
        // gone. Without the leader's birth identity we cannot safely
        // distinguish the original group from a recycled PGID.
        None => return Ok(RecoveredCancellation::ReconciliationRequired),
        Some(current) if current != expected_identity => {
            return Ok(RecoveredCancellation::RetireStale);
        }
        Some(_) => {}
    }

    use nix::errno::Errno;
    use nix::sys::signal::{Signal, killpg};
    use nix::unistd::Pid;
    let process_group =
        Pid::from_raw(i32::try_from(process_id).map_err(|_| {
            AgentError::Io(std::io::Error::other("process ID exceeds Unix PID range"))
        })?);
    match killpg(process_group, Signal::SIGTERM) {
        Ok(()) => {}
        Err(Errno::ESRCH) => return Ok(RecoveredCancellation::AlreadyExited),
        Err(error) => return Err(AgentError::Io(std::io::Error::other(error))),
    }

    let deadline = std::time::Instant::now() + termination_grace;
    while std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(25)).await;
        match process_birth_identity_for(process_id)? {
            None if !unix_process_group_exists(process_group)? => {
                return Ok(RecoveredCancellation::Terminated);
            }
            None => {}
            Some(current) if current != expected_identity => {
                return Ok(RecoveredCancellation::RetireStale);
            }
            Some(_) => {}
        }
    }

    // Re-read the non-reusable identity immediately before escalation. This is
    // the decisive recycled-PID guard: a mismatched process group is never
    // signalled, even if the original group disappeared during the grace
    // window.
    match process_birth_identity_for(process_id)? {
        None if !unix_process_group_exists(process_group)? => {
            return Ok(RecoveredCancellation::Terminated);
        }
        None => {}
        Some(current) if current != expected_identity => {
            return Ok(RecoveredCancellation::RetireStale);
        }
        Some(_) => {}
    }
    match killpg(process_group, Signal::SIGKILL) {
        Ok(()) => {}
        Err(Errno::ESRCH) => return Ok(RecoveredCancellation::Terminated),
        Err(error) => return Err(AgentError::Io(std::io::Error::other(error))),
    }
    let deadline = std::time::Instant::now() + termination_grace;
    while std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(25)).await;
        match process_birth_identity_for(process_id)? {
            None if !unix_process_group_exists(process_group)? => {
                return Ok(RecoveredCancellation::Terminated);
            }
            None => {}
            Some(current) if current != expected_identity => {
                return Ok(RecoveredCancellation::RetireStale);
            }
            Some(_) => {}
        }
    }
    Ok(RecoveredCancellation::ReconciliationRequired)
}

#[cfg(unix)]
fn unix_process_group_exists(process_group: nix::unistd::Pid) -> Result<bool, AgentError> {
    use nix::errno::Errno;
    use nix::sys::signal::killpg;

    match killpg(process_group, None) {
        Ok(()) | Err(Errno::EPERM) => Ok(true),
        Err(Errno::ESRCH) => Ok(false),
        Err(error) => Err(AgentError::Io(std::io::Error::other(error))),
    }
}

#[cfg(windows)]
async fn terminate_recovered_process(
    process_id: Option<u32>,
    _process_birth_identity: Option<&str>,
    _termination_grace: Duration,
) -> Result<RecoveredCancellation, AgentError> {
    // The previous service process owned the kill-on-close Job Object. SCM
    // restart cannot occur until that process and its complete Job have died.
    Ok(if process_id.is_some() {
        RecoveredCancellation::Terminated
    } else {
        RecoveredCancellation::AlreadyExited
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn process_birth_identity_for(process_id: u32) -> Result<Option<String>, AgentError> {
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let stat = match std::fs::read_to_string(format!("/proc/{process_id}/stat")) {
        Ok(stat) => stat,
        // A task that exits between open and read fails with raw ESRCH, which
        // std does not map to NotFound; both mean the process is gone.
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                || error.raw_os_error() == Some(nix::errno::Errno::ESRCH as i32) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    let (_, fields) = stat.rsplit_once(") ").ok_or_else(|| {
        AgentError::Io(std::io::Error::other(
            "Linux process stat has no command terminator",
        ))
    })?;
    let start_ticks = fields.split_whitespace().nth(19).ok_or_else(|| {
        AgentError::Io(std::io::Error::other(
            "Linux process stat has no birth tick",
        ))
    })?;
    Ok(Some(format!(
        "linux-proc-v1:{}:{start_ticks}",
        boot_id.trim()
    )))
}

#[cfg(all(unix, not(target_os = "linux")))]
pub(crate) fn process_birth_identity_for(_process_id: u32) -> Result<Option<String>, AgentError> {
    Ok(None)
}

#[cfg(windows)]
pub(crate) fn process_birth_identity_for(_process_id: u32) -> Result<Option<String>, AgentError> {
    Ok(None)
}

fn wire_report(
    config: &AgentConfig,
    session_epoch: u64,
    report: &ReconciliationReport,
) -> Result<WireReport, AgentError> {
    Ok(WireReport {
        agent_id: config.agent_id.clone(),
        session_epoch,
        attempts: report
            .attempts
            .iter()
            .map(|attempt| {
                Ok(AttemptState {
                    organization_id: attempt.organization_id.clone(),
                    attempt_id: attempt.attempt_id.clone(),
                    fence_token: attempt.fence_token,
                    phase: attempt.phase.wire_name().to_owned(),
                    payload_digest: attempt.payload_digest.to_vec(),
                    process_id: attempt.process_id,
                    process_birth_identity: attempt.process_birth_identity.clone(),
                    workspace: wire_path(&attempt.workspace)?,
                    logs: attempt
                        .logs
                        .iter()
                        .map(wire_spool)
                        .collect::<Result<_, AgentError>>()?,
                    result: attempt.result.as_ref().map(wire_spool).transpose()?,
                })
            })
            .collect::<Result<_, AgentError>>()?,
    })
}

fn wire_spool(entry: &mcloving_agent_runtime::SpoolEntry) -> Result<wire::SpoolEntry, AgentError> {
    Ok(wire::SpoolEntry {
        relative_path: wire_path(&entry.relative_path)?,
        digest: entry.digest.to_vec(),
        bytes: entry.bytes,
        sequence: entry.sequence,
    })
}

fn wire_path(path: &Path) -> Result<String, AgentError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or(AgentError::NonUtf8Path)
}

async fn outbound_config(config: &AgentConfig) -> Result<OutboundMtlsConfig, AgentError> {
    Ok(OutboundMtlsConfig {
        controller_uri: config.controller_uri.clone(),
        controller_dns_name: config.controller_dns_name.clone(),
        controller_ca_pem: tokio::fs::read(&config.controller_ca_path).await?,
        agent_certificate_pem: tokio::fs::read(&config.agent_certificate_path).await?,
        agent_private_key_pem: tokio::fs::read(&config.agent_private_key_path).await?,
    })
}

/// Validates every local production identity input without opening a network
/// connection or creating journal/workspace state.
pub async fn validate_outbound_configuration(config: &AgentConfig) -> Result<(), AgentError> {
    outbound_config(config).await?.endpoint()?;
    Ok(())
}

#[cfg(windows)]
const fn platform_feature() -> &'static str {
    "windows-job-object-v1"
}

#[cfg(not(windows))]
const fn platform_feature() -> &'static str {
    "unix-process-group-v1"
}

fn session_capabilities() -> Vec<String> {
    vec![
        std::env::consts::OS.to_owned(),
        mcloving_domain::capability::platform_capability(std::env::consts::OS),
        std::env::consts::ARCH.to_owned(),
    ]
}

pub async fn run_service_smoke(
    journal_path: &Path,
    stop: CancellationToken,
) -> Result<(), AgentError> {
    let mut journal = Journal::open(journal_path)?;
    journal.reserve_session_epoch(0)?;
    let _ = journal.reconcile()?;
    stop.cancelled().await;
    Ok(())
}

/// Destructive Windows service-crash fixture.
///
/// First start records an accepted/running attempt and launches this exact
/// agent binary as a native process-tree fixture in a Job Object. Keeping the
/// WIN-004 crash gate independent of any shell startup policy makes it prove
/// containment and recovery directly; shell parity remains a separate WIN-002
/// gate. After the service process is force-killed, a second start observes
/// the durable running attempt and waits for operator reconciliation instead
/// of duplicating execution.
#[cfg(windows)]
pub async fn run_execution_service_smoke(
    journal_path: &Path,
    workspace_root: &Path,
    marker_root: &Path,
    stop: CancellationToken,
) -> Result<(), AgentError> {
    let mut journal = Journal::open(journal_path)?;
    let session_epoch = journal.reserve_session_epoch(0)?;
    if !journal.reconcile()?.attempts.is_empty() {
        stop.cancelled().await;
        return Ok(());
    }

    let acceptance = Acceptance {
        organization_id: "service-smoke".to_owned(),
        attempt_id: "crash-recovery".to_owned(),
        fence_token: 1,
        session_epoch,
        payload_digest: [0x57; 32],
        workspace: PathBuf::from("service-smoke/crash-recovery"),
    };
    journal.accept(&acceptance)?;
    let request = ExecutionRequest {
        workspace_root: workspace_root.to_owned(),
        workspace: acceptance.workspace.clone(),
        mode: ExecutionMode::Direct,
        program: std::env::current_exe()?,
        arguments: vec![
            OsString::from("workload-tree-smoke"),
            marker_root.as_os_str().to_owned(),
        ],
        environment: BTreeMap::new(),
        output_limit_bytes: None,
        timeout: Duration::from_secs(300),
        termination_grace: Duration::from_millis(100),
    };
    execute_with_spawn_hook(&request, stop, |process_id| {
        journal
            .transition(
                &acceptance.organization_id,
                &acceptance.attempt_id,
                acceptance.fence_token,
                session_epoch,
                AttemptPhase::Running,
                Some(process_id),
            )
            .map_err(|error| ExecutionError::SpawnHook(error.to_string()))
    })
    .await
    .map(|_| ())
    .map_err(|error| AgentError::Io(std::io::Error::other(error)))
}

/// Holds a newly created Windows workload at a named pre-resume boundary.
///
/// The hosted war gate force-kills the service while this callback is blocked.
/// Because `CreateProcessW` atomically applied Job-list membership, closing the
/// service's Job handle must remove the suspended workload at both the
/// contained-before-record and recorded-before-resume boundaries.
#[cfg(windows)]
pub async fn run_creation_boundary_service_smoke(
    journal_path: &Path,
    workspace_root: &Path,
    script: &Path,
    marker: &Path,
    record_before_pause: bool,
    stop: CancellationToken,
) -> Result<(), AgentError> {
    let mut journal = Journal::open(journal_path)?;
    let session_epoch = journal.reserve_session_epoch(0)?;
    let boundary = if record_before_pause {
        "recorded-before-resume"
    } else {
        "contained-before-record"
    };
    let acceptance = Acceptance {
        organization_id: "service-boundary".to_owned(),
        attempt_id: boundary.to_owned(),
        fence_token: 1,
        session_epoch,
        payload_digest: [0x58; 32],
        workspace: PathBuf::from(format!("service-boundary/{boundary}")),
    };
    journal.accept(&acceptance)?;
    let request = ExecutionRequest {
        workspace_root: workspace_root.to_owned(),
        workspace: acceptance.workspace.clone(),
        mode: ExecutionMode::PowerShell,
        program: script.to_owned(),
        arguments: Vec::<OsString>::new(),
        environment: BTreeMap::new(),
        output_limit_bytes: None,
        timeout: Duration::from_secs(300),
        termination_grace: Duration::from_millis(100),
    };
    execute_with_spawn_hook(&request, stop, |process_id| {
        if record_before_pause {
            journal
                .transition(
                    &acceptance.organization_id,
                    &acceptance.attempt_id,
                    acceptance.fence_token,
                    session_epoch,
                    AttemptPhase::Running,
                    Some(process_id),
                )
                .map_err(|error| ExecutionError::SpawnHook(error.to_string()))?;
        }
        let mut marker_file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(marker)
            .map_err(ExecutionError::Io)?;
        use std::io::Write;
        writeln!(marker_file, "{process_id}").map_err(ExecutionError::Io)?;
        marker_file.sync_all().map_err(ExecutionError::Io)?;
        loop {
            std::thread::park_timeout(Duration::from_secs(60));
        }
    })
    .await
    .map(|_| ())
    .map_err(|error| AgentError::Io(std::io::Error::other(error)))
}

pub fn journal_health(path: &Path) -> Result<(String, String, usize), AgentError> {
    let journal = Journal::open(path)?;
    Ok((
        journal.journal_mode()?,
        journal.integrity_check()?,
        journal.reconcile()?.attempts.len(),
    ))
}

pub fn journal_session_epoch(path: &Path) -> Result<u64, AgentError> {
    let journal = Journal::open(path)?;
    Ok(journal.last_session_epoch()?)
}

pub fn observe_journal(
    path: &Path,
) -> Result<mcloving_agent_runtime::JournalObservation, AgentError> {
    Ok(Journal::observe(path)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values() -> BTreeMap<String, String> {
        [
            ("MCLOVING_AGENT_ID", "windows-1"),
            ("MCLOVING_AGENT_TRUST_POOL", "trusted-build"),
            (
                "MCLOVING_AGENT_ORGANIZATION_ID",
                "00000000-0000-0000-0000-000000000123",
            ),
            ("MCLOVING_CONTROLLER_URI", "https://controller.internal"),
            ("MCLOVING_CONTROLLER_DNS_NAME", "controller.internal"),
            ("MCLOVING_CONTROLLER_CA_PATH", "ca.pem"),
            ("MCLOVING_AGENT_CERTIFICATE_PATH", "agent.pem"),
            ("MCLOVING_AGENT_PRIVATE_KEY_PATH", "agent-key.pem"),
            ("MCLOVING_AGENT_JOURNAL_PATH", "agent.db"),
            ("MCLOVING_AGENT_WORKSPACE_ROOT", "workspace"),
            ("MCLOVING_AGENT_SESSION_RECEIPT_PATH", "session.receipt"),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
    }

    #[test]
    fn session_advertises_canonical_platform_and_legacy_os_capabilities() {
        let capabilities = session_capabilities();
        assert!(capabilities.contains(&std::env::consts::OS.to_owned()));
        assert!(capabilities.contains(&format!("platform:{}", std::env::consts::OS)));
        assert!(capabilities.contains(&std::env::consts::ARCH.to_owned()));
    }

    #[test]
    fn configuration_is_strict_and_does_not_embed_tls_material() {
        let config = AgentConfig::from_values(&values()).unwrap();
        assert_eq!(config.agent_id, "windows-1");
        assert_eq!(config.minimum_session_epoch, 0);
        assert_eq!(
            config.session_receipt_path,
            Some(PathBuf::from("session.receipt"))
        );

        let mut missing = values();
        missing.remove("MCLOVING_AGENT_PRIVATE_KEY_PATH");
        assert!(matches!(
            AgentConfig::from_values(&missing),
            Err(AgentError::MissingConfig("MCLOVING_AGENT_PRIVATE_KEY_PATH"))
        ));

        let mut unsafe_renewal = values();
        unsafe_renewal.insert("MCLOVING_AGENT_LEASE_SECONDS".to_owned(), "5".to_owned());
        unsafe_renewal.insert(
            "MCLOVING_AGENT_RENEW_MILLISECONDS".to_owned(),
            "4500".to_owned(),
        );
        assert!(matches!(
            AgentConfig::from_values(&unsafe_renewal),
            Err(AgentError::InvalidConfig(
                "agent polling, renewal, or termination timing"
            ))
        ));
    }

    #[test]
    fn probe_cannot_reserve_a_session_while_the_agent_is_active() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = AgentConfig::from_values(&values()).unwrap();
        config.journal_path = directory.path().join("agent.db");

        let running_agent = acquire_instance_guard(&config).unwrap();
        assert!(matches!(
            acquire_instance_guard(&config),
            Err(AgentError::AlreadyRunning)
        ));
        drop(running_agent);
        acquire_instance_guard(&config).unwrap();
    }

    #[tokio::test]
    async fn stalled_probe_is_bounded() {
        let result = with_probe_timeout::<()>(
            Duration::from_millis(1),
            std::future::pending::<Result<(), AgentError>>(),
        )
        .await;
        assert!(matches!(result, Err(AgentError::ProbeTimeout)));
    }

    #[tokio::test]
    async fn stalled_open_session_rpc_is_bounded() {
        let result = bounded_open_session_rpc::<()>(
            Duration::from_millis(1),
            std::future::pending::<Result<tonic::Response<()>, tonic::Status>>(),
        )
        .await;
        assert!(matches!(result, Err(AgentError::OpenSessionTimeout)));
    }

    #[test]
    fn authenticated_session_receipt_is_atomic_and_monotonic() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("session.receipt");
        publish_authenticated_session_receipt(Some(&path), 41).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "session_epoch=41\n"
        );

        publish_authenticated_session_receipt(Some(&path), 42).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "session_epoch=42\n"
        );
        assert!(publish_authenticated_session_receipt(Some(&path), 41).is_err());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "session_epoch=42\n"
        );
        assert!(std::fs::read_dir(directory.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("pending")
        }));
    }

    #[tokio::test]
    async fn failed_recovery_initialization_does_not_publish_health() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("session.receipt");
        publish_authenticated_session_receipt(Some(&path), 40).unwrap();

        let result = publish_recovery_ready_session_receipt(Some(&path), 41, async {
            Err(AgentError::UnsupportedProtocol)
        })
        .await;

        assert!(matches!(result, Err(AgentError::UnsupportedProtocol)));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "session_epoch=40\n"
        );
    }

    #[test]
    fn work_delivery_must_be_negotiated_before_polling() {
        assert!(matches!(
            require_work_delivery_feature(&["journal-v1".to_owned()]),
            Err(AgentError::UnsupportedProtocol)
        ));
        require_work_delivery_feature(&[WORK_DELIVERY_FEATURE.to_owned()]).unwrap();
    }

    #[test]
    fn stale_receipt_cannot_retire_unverifiable_local_containment() {
        assert_eq!(
            recovered_cancellation_phase(
                RecoveredCancellation::ReconciliationRequired,
                CancellationDisposition::RetireStale as i32,
            )
            .unwrap(),
            AttemptPhase::ReconciliationRequired
        );
        assert_eq!(
            recovered_cancellation_phase(
                RecoveredCancellation::AlreadyExited,
                CancellationDisposition::RetireStale as i32,
            )
            .unwrap(),
            AttemptPhase::Aborted
        );
    }

    #[test]
    fn explicit_discharge_confirmation_retires_an_unverifiable_recovered_attempt() {
        assert_eq!(
            recovered_cancellation_phase(
                RecoveredCancellation::ReconciliationRequired,
                CancellationDisposition::DischargeRecovered as i32,
            )
            .unwrap(),
            AttemptPhase::Aborted
        );
        assert_eq!(
            recovered_cancellation_phase(
                RecoveredCancellation::AlreadyExited,
                CancellationDisposition::DischargeRecovered as i32,
            )
            .unwrap(),
            AttemptPhase::Aborted
        );
    }

    #[test]
    fn stale_session_epoch_failures_are_recognized_for_collision_naming() {
        assert!(names_stale_session_epoch(&AgentError::StaleSession));
        assert!(names_stale_session_epoch(&AgentError::Rpc(
            tonic::Status::failed_precondition(
                "stale agent session epoch; agent identity collision suspected for windows-1"
            )
        )));
        assert!(!names_stale_session_epoch(&AgentError::Rpc(
            tonic::Status::unavailable("controller restarting")
        )));
        assert!(!names_stale_session_epoch(&AgentError::StaleAuthority));
    }

    #[test]
    fn stale_epoch_floor_requires_the_exact_rejection_and_metadata() {
        let mut status = tonic::Status::failed_precondition("stale agent session epoch");
        assert_eq!(stale_epoch_floor(&status), None);
        status
            .metadata_mut()
            .insert(CURRENT_SESSION_EPOCH_METADATA, "41".parse().unwrap());
        assert_eq!(stale_epoch_floor(&status), Some(41));

        let mut wrong_code = tonic::Status::unavailable("stale agent session epoch");
        wrong_code
            .metadata_mut()
            .insert(CURRENT_SESSION_EPOCH_METADATA, "41".parse().unwrap());
        assert_eq!(stale_epoch_floor(&wrong_code), None);

        let mut wrong_message = tonic::Status::failed_precondition("another precondition");
        wrong_message
            .metadata_mut()
            .insert(CURRENT_SESSION_EPOCH_METADATA, "41".parse().unwrap());
        assert_eq!(stale_epoch_floor(&wrong_message), None);

        let mut invalid_value = tonic::Status::failed_precondition("stale agent session epoch");
        invalid_value.metadata_mut().insert(
            CURRENT_SESSION_EPOCH_METADATA,
            "not-a-number".parse().unwrap(),
        );
        assert_eq!(stale_epoch_floor(&invalid_value), None);
    }

    #[test]
    fn retained_reconciliation_required_attempt_is_reported_to_the_controller() {
        let attempt = mcloving_agent_runtime::ReconciliationAttempt {
            organization_id: "org".to_owned(),
            attempt_id: "attempt".to_owned(),
            fence_token: 7,
            session_epoch: 3,
            payload_digest: [0x42; 32],
            phase: AttemptPhase::ReconciliationRequired,
            workspace: PathBuf::from("org/attempt/7"),
            process_id: Some(42),
            process_birth_identity: None,
            logs: Vec::new(),
            result: None,
        };
        let retained = [("org".to_owned(), "attempt".to_owned(), 7)]
            .into_iter()
            .collect();

        assert!(recovered_attempt_requires_cancellation_report(
            &std::collections::BTreeSet::new(),
            &retained,
            &attempt
        ));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn recovered_windows_attempt_without_process_is_already_exited() {
        assert_eq!(
            terminate_recovered_process(None, None, Duration::from_millis(25))
                .await
                .unwrap(),
            RecoveredCancellation::AlreadyExited
        );
    }

    #[tokio::test]
    async fn smoke_runtime_reserves_epoch_and_stops_cleanly() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("agent.db");
        let stop = CancellationToken::new();
        let cancellation = stop.clone();
        let task_path = path.clone();
        let task = tokio::spawn(async move { run_service_smoke(&task_path, cancellation).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        stop.cancel();
        task.await.unwrap().unwrap();

        let health = journal_health(&path).unwrap();
        assert_eq!(health.0, "wal");
        assert_eq!(health.1, "ok");
        assert_eq!(health.2, 0);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn recovered_unix_process_group_without_birth_identity_is_not_signalled() {
        let mut command = tokio::process::Command::new("/bin/sh");
        command.args(["-c", "exec sleep 30"]).process_group(0);
        let mut child = command.spawn().unwrap();
        let process_id = child.id().unwrap();

        assert_eq!(
            terminate_recovered_process(Some(process_id), None, Duration::from_millis(25))
                .await
                .unwrap(),
            RecoveredCancellation::ReconciliationRequired
        );
        assert!(child.try_wait().unwrap().is_none());
        child.kill().await.unwrap();
        child.wait().await.unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn missing_unix_group_leader_requires_reconciliation() {
        use nix::sys::signal::{Signal, killpg};
        use nix::unistd::Pid;

        let mut command = tokio::process::Command::new("/bin/sh");
        command
            .args(["-c", "sleep 30 &"])
            .process_group(0)
            .kill_on_drop(false);
        let mut leader = command.spawn().unwrap();
        let process_id = leader.id().unwrap();
        leader.wait().await.unwrap();

        assert_eq!(
            terminate_recovered_process(
                Some(process_id),
                Some("linux-proc-v1:gone:1"),
                Duration::from_millis(25),
            )
            .await
            .unwrap(),
            RecoveredCancellation::ReconciliationRequired
        );
        let group = Pid::from_raw(i32::try_from(process_id).unwrap());
        assert!(unix_process_group_exists(group).unwrap());
        let _ = killpg(group, Signal::SIGKILL);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn recovered_unix_process_group_with_mismatched_birth_identity_is_retired_not_signalled()
    {
        let mut command = tokio::process::Command::new("/bin/sh");
        command.args(["-c", "exec sleep 30"]).process_group(0);
        let mut child = command.spawn().unwrap();
        let process_id = child.id().unwrap();
        let identity = process_birth_identity_for(process_id).unwrap().unwrap();

        assert_eq!(
            terminate_recovered_process(
                Some(process_id),
                Some(&format!("{identity}-recycled")),
                Duration::from_millis(25),
            )
            .await
            .unwrap(),
            RecoveredCancellation::RetireStale
        );
        assert!(child.try_wait().unwrap().is_none());
        child.kill().await.unwrap();
        child.wait().await.unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn recovered_unix_process_group_with_matching_birth_identity_is_terminated() {
        let mut command = tokio::process::Command::new("/bin/sh");
        command.args(["-c", "exec sleep 30"]).process_group(0);
        let mut child = command.spawn().unwrap();
        let process_id = child.id().unwrap();
        let identity = process_birth_identity_for(process_id).unwrap().unwrap();
        let waiter = tokio::spawn(async move { child.wait().await.unwrap() });

        assert_eq!(
            terminate_recovered_process(Some(process_id), Some(&identity), Duration::from_secs(1),)
                .await
                .unwrap(),
            RecoveredCancellation::Terminated
        );
        waiter.await.unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn unverifiable_recovered_cancellation_is_retained_without_session_failure() {
        use mcloving_agent_runtime::Acceptance;

        let mut command = tokio::process::Command::new("/bin/sh");
        command.args(["-c", "exec sleep 30"]).process_group(0);
        let mut child = command.spawn().unwrap();
        let process_id = child.id().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let mut journal = Journal::open(directory.path().join("agent.db")).unwrap();
        let session_epoch = journal.reserve_session_epoch(0).unwrap();
        let acceptance = Acceptance {
            organization_id: "org".to_owned(),
            attempt_id: "unverifiable".to_owned(),
            fence_token: 7,
            session_epoch,
            payload_digest: [0x55; 32],
            workspace: PathBuf::from("org/unverifiable"),
        };
        journal.accept(&acceptance).unwrap();
        journal
            .transition(
                &acceptance.organization_id,
                &acceptance.attempt_id,
                acceptance.fence_token,
                session_epoch,
                AttemptPhase::Running,
                Some(process_id),
            )
            .unwrap();
        let attempt = journal.reconcile().unwrap().attempts.remove(0);

        assert_eq!(
            cancel_recovered_attempt(&mut journal, &attempt, Duration::from_millis(25))
                .await
                .unwrap(),
            RecoveredCancellation::ReconciliationRequired
        );
        assert_eq!(
            journal.reconcile().unwrap().attempts[0].phase,
            AttemptPhase::ReconciliationRequired
        );
        assert!(child.try_wait().unwrap().is_none());

        child.kill().await.unwrap();
        child.wait().await.unwrap();
    }

    #[test]
    fn reconciliation_wire_preserves_process_and_spool_metadata() {
        let config = AgentConfig::from_values(&values()).unwrap();
        let report = ReconciliationReport {
            attempts: vec![mcloving_agent_runtime::ReconciliationAttempt {
                organization_id: "org".to_owned(),
                attempt_id: "attempt".to_owned(),
                fence_token: 3,
                session_epoch: 4,
                payload_digest: [5; 32],
                phase: AttemptPhase::Running,
                workspace: PathBuf::from("org/attempt"),
                process_id: Some(42),
                process_birth_identity: Some("linux-proc-v1:boot:42".to_owned()),
                logs: vec![mcloving_agent_runtime::SpoolEntry {
                    sequence: 7,
                    relative_path: PathBuf::from("spool/stdout.log"),
                    digest: [8; 32],
                    bytes: 9,
                }],
                result: Some(mcloving_agent_runtime::SpoolEntry {
                    sequence: 0,
                    relative_path: PathBuf::from("spool/result.pb"),
                    digest: [10; 32],
                    bytes: 11,
                }),
            }],
        };
        let wire = wire_report(&config, 4, &report).unwrap();
        let attempt = &wire.attempts[0];
        assert_eq!(attempt.process_id, Some(42));
        assert_eq!(
            attempt.process_birth_identity.as_deref(),
            Some("linux-proc-v1:boot:42")
        );
        assert_eq!(attempt.workspace, "org/attempt");
        assert_eq!(attempt.logs[0].sequence, 7);
        assert_eq!(attempt.logs[0].digest, vec![8; 32]);
        assert_eq!(attempt.result.as_ref().unwrap().bytes, 11);
    }

    #[test]
    fn cancellation_authority_does_not_match_another_fence_of_the_same_attempt() {
        let cancelled =
            std::collections::BTreeSet::from([("org".to_owned(), "attempt".to_owned(), 7)]);
        let attempt = mcloving_agent_runtime::ReconciliationAttempt {
            organization_id: "org".to_owned(),
            attempt_id: "attempt".to_owned(),
            fence_token: 8,
            session_epoch: 1,
            payload_digest: [0; 32],
            phase: AttemptPhase::Running,
            workspace: PathBuf::from("org/attempt"),
            process_id: None,
            process_birth_identity: None,
            logs: Vec::new(),
            result: None,
        };
        assert!(!cancellation_targets(&cancelled, &attempt));
    }
}
