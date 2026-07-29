//! Native McLoving agent service runtime.

use std::collections::BTreeMap;
use std::env;
use std::fs::{File, OpenOptions};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::Duration;

mod worker;

use mcloving_agent_protocol::wire;
use mcloving_agent_protocol::wire::agent_control_client::AgentControlClient;
use mcloving_agent_protocol::wire::{
    AttemptState, CancellationCompletion, CancellationDisposition, CancellationOutcome,
    OpenSessionRequest, ProtocolOffer, ReconciliationReport as WireReport,
};
use mcloving_agent_protocol::{OutboundMtlsConfig, PROTOCOL_MAJOR, PROTOCOL_MINOR, TransportError};
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
    #[error("controller returned an invalid work assignment: {0}")]
    InvalidAssignment(String),
    #[error("execution specification is invalid: {0}")]
    InvalidSpec(#[from] serde_json::Error),
    #[error("execution specification is unsupported")]
    UnsupportedSpec,
    #[error("agent execution failed: {0}")]
    Execution(#[from] ExecutionError),
    #[error("controller selected an unsupported protocol minor")]
    UnsupportedProtocol,
    #[error("agent identity and journal are already active in another process")]
    AlreadyRunning,
    #[error("agent probe exceeded its bounded deadline")]
    ProbeTimeout,
    #[error("agent service was stopped")]
    Stopped,
    #[error("journal path cannot be represented in the wire protocol")]
    NonUtf8Path,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoveredCancellation {
    Terminated,
    #[cfg(unix)]
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
            || renewal_milliseconds >= u64::from(lease_seconds) * 1_000
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
    loop {
        if stop.is_cancelled() {
            return Ok(());
        }
        match run_session(config, stop.clone()).await {
            Ok(()) => return Ok(()),
            Err(error) if !stop.is_cancelled() => {
                eprintln!("agent session ended; retrying: {error}");
                tokio::select! {
                    () = stop.cancelled() => return Ok(()),
                    () = sleep(RECONNECT_DELAY) => {}
                }
            }
            Err(_) => return Ok(()),
        }
    }
}

pub async fn probe_once(config: &AgentConfig) -> Result<SessionReceipt, AgentError> {
    let _instance = acquire_instance_guard(config)?;
    with_probe_timeout(PROBE_TIMEOUT, async {
        let stop = CancellationToken::new();
        let (mut client, receipt) = open_session(config, stop.clone()).await?;
        send_reconciliation(config, &mut client, receipt.session_epoch, stop).await?;
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
    send_reconciliation(config, &mut client, receipt.session_epoch, stop.clone()).await?;
    worker::recover_finalizations(config, &mut client, receipt.session_epoch).await?;
    let mut reconciliation_tick = interval(RECONCILIATION_INTERVAL);
    reconciliation_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    reconciliation_tick.tick().await;
    let mut work_tick = interval(config.poll_interval);
    work_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    work_tick.tick().await;
    loop {
        tokio::select! {
            () = stop.cancelled() => return Ok(()),
            _ = reconciliation_tick.tick() => {
                send_reconciliation(
                    config,
                    &mut client,
                    receipt.session_epoch,
                    stop.clone(),
                ).await?;
            }
            _ = work_tick.tick() => {
                worker::poll_and_run_one(
                    config,
                    &mut client,
                    receipt.session_epoch,
                    stop.clone(),
                ).await?;
            }
        }
    }
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
    let session_epoch = journal.reserve_session_epoch(config.minimum_session_epoch)?;
    let active_attempts = journal.reconcile()?.attempts.len();
    let endpoint = outbound_config(config).await?.endpoint()?;
    let channel = tokio::select! {
        () = stop.cancelled() => return Err(AgentError::Stopped),
        result = endpoint.connect() => result?,
    };
    let mut client = AgentControlClient::new(channel);
    let request = OpenSessionRequest {
        agent_id: config.agent_id.clone(),
        session_epoch,
        protocol: Some(ProtocolOffer {
            major: u32::from(PROTOCOL_MAJOR),
            minimum_minor: u32::from(PROTOCOL_MINOR),
            maximum_minor: u32::from(PROTOCOL_MINOR),
            features: vec!["journal-v1".to_owned(), platform_feature().to_owned()],
        }),
        trust_pool: config.trust_pool.clone(),
        capabilities: vec![
            std::env::consts::OS.to_owned(),
            std::env::consts::ARCH.to_owned(),
        ],
    };
    let response = tokio::select! {
        () = stop.cancelled() => return Err(AgentError::Stopped),
        response = client.open_session(request) => response?,
    }
    .into_inner();
    if response.session_epoch != session_epoch {
        return Err(AgentError::StaleSession);
    }
    if response.protocol_minor != u32::from(PROTOCOL_MINOR) {
        return Err(AgentError::UnsupportedProtocol);
    }
    Ok((
        client,
        SessionReceipt {
            session_epoch,
            active_attempts,
        },
    ))
}

async fn send_reconciliation(
    config: &AgentConfig,
    client: &mut AgentControlClient<tonic::transport::Channel>,
    session_epoch: u64,
    stop: CancellationToken,
) -> Result<(), AgentError> {
    let report = Journal::open(&config.journal_path)?.reconcile()?;
    let request = wire_report(config, session_epoch, &report)?;
    let directive = tokio::select! {
        () = stop.cancelled() => return Err(AgentError::Stopped),
        response = client.reconcile(request) => response?,
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
    if !cancelled.is_empty() {
        let mut journal = Journal::open(&config.journal_path)?;
        for attempt in &report.attempts {
            if cancellation_targets(&cancelled, attempt) {
                let outcome =
                    cancel_recovered_attempt(&mut journal, attempt, config.termination_grace)
                        .await?;
                let request = CancellationCompletion {
                    agent_id: config.agent_id.clone(),
                    session_epoch,
                    organization_id: attempt.organization_id.clone(),
                    attempt_id: attempt.attempt_id.clone(),
                    fence_token: attempt.fence_token,
                    outcome: match outcome {
                        RecoveredCancellation::Terminated => CancellationOutcome::Terminated as i32,
                        #[cfg(unix)]
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
                    },
                };
                let receipt = tokio::select! {
                    () = stop.cancelled() => return Err(AgentError::Stopped),
                    response = client.complete_cancellation(request) => response?,
                }
                .into_inner();
                if receipt.session_epoch != session_epoch {
                    return Err(AgentError::StaleSession);
                }
                let phase = match CancellationDisposition::try_from(receipt.disposition) {
                    Ok(
                        CancellationDisposition::Completed | CancellationDisposition::RetireStale,
                    ) => AttemptPhase::Aborted,
                    Ok(CancellationDisposition::ReconciliationRequired) => {
                        AttemptPhase::ReconciliationRequired
                    }
                    Ok(CancellationDisposition::Unspecified) | Err(_) => {
                        return Err(AgentError::UnsupportedProtocol);
                    }
                };
                journal.transition(
                    &attempt.organization_id,
                    &attempt.attempt_id,
                    attempt.fence_token,
                    attempt.session_epoch,
                    phase,
                    attempt.process_id,
                )?;
            }
        }
    }
    Ok(())
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
        None => return Ok(RecoveredCancellation::AlreadyExited),
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
            None => return Ok(RecoveredCancellation::Terminated),
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
        None => return Ok(RecoveredCancellation::Terminated),
        Some(current) if current != expected_identity => {
            return Ok(RecoveredCancellation::RetireStale);
        }
        Some(_) => {}
    }
    match killpg(process_group, Signal::SIGKILL) {
        Ok(()) | Err(Errno::ESRCH) => Ok(RecoveredCancellation::Terminated),
        Err(error) => Err(AgentError::Io(std::io::Error::other(error))),
    }
}

#[cfg(windows)]
async fn terminate_recovered_process(
    _process_id: Option<u32>,
    _process_birth_identity: Option<&str>,
    _termination_grace: Duration,
) -> Result<RecoveredCancellation, AgentError> {
    // The previous service process owned the kill-on-close Job Object. SCM
    // restart cannot occur until that process and its complete Job have died.
    Ok(RecoveredCancellation::Terminated)
}

#[cfg(target_os = "linux")]
pub(crate) fn process_birth_identity_for(process_id: u32) -> Result<Option<String>, AgentError> {
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let stat = match std::fs::read_to_string(format!("/proc/{process_id}/stat")) {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
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

#[cfg(windows)]
const fn platform_feature() -> &'static str {
    "windows-job-object-v1"
}

#[cfg(not(windows))]
const fn platform_feature() -> &'static str {
    "unix-process-group-v1"
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
/// First start records an accepted/running attempt and launches the supplied
/// PowerShell file in a Job Object. After the service process is force-killed,
/// a second start observes the durable running attempt and waits for operator
/// reconciliation instead of duplicating execution.
#[cfg(windows)]
pub async fn run_execution_service_smoke(
    journal_path: &Path,
    workspace_root: &Path,
    script: &Path,
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
        mode: ExecutionMode::PowerShell,
        program: script.to_owned(),
        arguments: Vec::<OsString>::new(),
        environment: BTreeMap::new(),
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
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
    }

    #[test]
    fn configuration_is_strict_and_does_not_embed_tls_material() {
        let config = AgentConfig::from_values(&values()).unwrap();
        assert_eq!(config.agent_id, "windows-1");
        assert_eq!(config.minimum_session_epoch, 0);

        let mut missing = values();
        missing.remove("MCLOVING_AGENT_PRIVATE_KEY_PATH");
        assert!(matches!(
            AgentConfig::from_values(&missing),
            Err(AgentError::MissingConfig("MCLOVING_AGENT_PRIVATE_KEY_PATH"))
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

        assert_eq!(
            terminate_recovered_process(
                Some(process_id),
                Some(&identity),
                Duration::from_millis(25),
            )
            .await
            .unwrap(),
            RecoveredCancellation::Terminated
        );
        child.wait().await.unwrap();
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
