//! Fenced controller-to-agent work execution.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::future::Future;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use crate::private_helper::PreparedHelper;
use mcloving_agent_protocol::RECOVERED_FINALIZATION_LEASE_SECONDS;
use mcloving_agent_protocol::wire::agent_control_client::AgentControlClient;
use mcloving_agent_protocol::wire::{
    CancellationCompletion, CancellationDisposition, CancellationOutcome, CredentialBinding,
    CredentialRequest, InlineLogChunk, WorkAssignment, WorkAuthority, WorkCompletion,
    WorkLeaseRenewal, WorkLogChunk, WorkOutcome, WorkPoll, WorkReceipt,
};
use mcloving_agent_runtime::executor::{
    ExecutionError, ExecutionMode, ExecutionRequest, Termination,
    execute_with_spawn_hook_and_redactions, is_link_or_reparse_point, sync_boundaries,
};
use mcloving_agent_runtime::executor::{
    flush_terminal_cleanup, remove_terminal_relative_path as remove_runtime_terminal_path,
};
use mcloving_agent_runtime::{
    Acceptance, AttemptPhase, Finalization, Journal, MAX_ATTEMPT_OUTPUT_BYTES, ProcessIdentity,
    SpoolEntry,
};
use mcloving_domain::ConnectorIntentSpec;
use mcloving_domain::cache_intent::{CacheIntentSpec, CacheWorkContext, cache_assignment_digest};
use mcloving_domain::input_intent::{InputIntentSpec, InputWorkContext, input_assignment_digest};
use mcloving_domain::workspace::{WorkspaceGrant, WorkspaceTransferResult};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use tonic::transport::Channel;
use uuid::Uuid;

use crate::{AgentConfig, AgentError, SessionFeatures, process_birth_identity_for};

const MAX_LOG_CHUNK_BYTES: usize = 1_048_576;
// 64 full chunks of the 64 MiB quota plus one partial chunk per stream of a
// sixteen-step attempt (PAR-010); the controller enforces the same count.
const MAX_LOG_CHUNKS_PER_ATTEMPT: u64 = 96;
const MAX_RESULT_SPOOL_BYTES: u64 = 65_536;
const MAX_EXECUTION_TIMEOUT_SECONDS: u64 = 7 * 24 * 60 * 60;
const WORK_POLL_RPC_WINDOW: Duration = Duration::from_secs(25);
const AGENT_RESULT_DIRECTORY: &str = ".agent-results";
const WORK_COMPLETION_PROTOCOL: &str = "work";
const CANCELLATION_COMPLETION_PROTOCOL: &str = "cancellation";

#[derive(Deserialize)]
struct ExecutionSpec {
    version: u16,
    steps: Vec<ProcessSpec>,
    /// Version-5 only: the digest-pinned image every step runs in (PAR-011).
    #[serde(default)]
    image: Option<String>,
}

#[derive(Deserialize)]
struct ProcessSpec {
    kind: String,
    #[serde(default)]
    mode: ProcessMode,
    program: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    credentials: Vec<String>,
    timeout_seconds: Option<u64>,
}

struct ExecutionEnvironment {
    values: BTreeMap<String, String>,
    redactions: Vec<Vec<u8>>,
}

#[derive(Deserialize)]
struct PersistedResult {
    #[serde(default)]
    workspace_transfer: Option<WorkspaceTransferResult>,
    outcome: String,
    exit_code: Option<i32>,
    termination: String,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default = "default_completion_protocol")]
    completion_protocol: String,
    cancellation_outcome: Option<i32>,
    #[serde(default)]
    steps: Vec<StepRecord>,
}

/// Build the wire summary from the digest-verified durable result. Workspace
/// publications must carry the identical checkpoint and failure evidence on
/// initial upload and replay; the controller normalizes its bytes to a receipt.
fn work_completion_summary(
    result: &PersistedResult,
    digest: &[u8; 32],
    legacy_replay: bool,
) -> Result<Vec<u8>, AgentError> {
    // The legacy reason-only replay shape predates step records; a multi-step
    // result keeps the modern shape on replay so a crash before terminal
    // publication never changes the fields a client sees.
    let mut summary = if result.workspace_transfer.is_none()
        && legacy_replay
        && result.reason.is_some()
        && result.steps.is_empty()
    {
        json!({"reason": result.reason, "result_sha256": hex(digest)})
    } else {
        json!({"exit_code": result.exit_code, "termination": result.termination, "result_sha256": hex(digest)})
    };
    if let Some(transfer) = &result.workspace_transfer {
        transfer
            .validate()
            .map_err(|error| AgentError::InvalidAssignment(error.to_string()))?;
        summary["workspace_transfer"] = serde_json::to_value(transfer)?;
        if let Some(reason) = &result.reason {
            summary["reason"] = json!(reason);
        }
    }
    if !result.steps.is_empty() {
        summary["steps"] = serde_json::to_value(&result.steps)?;
        if let Some(reason) = &result.reason {
            summary["reason"] = json!(reason);
        }
    }
    let encoded = serde_json::to_vec(&summary)?;
    if encoded.len() > MAX_RESULT_SPOOL_BYTES as usize {
        return Err(AgentError::InvalidAssignment(
            "completion summary exceeds its quota".to_owned(),
        ));
    }
    Ok(encoded)
}

fn default_completion_protocol() -> String {
    WORK_COMPLETION_PROTOCOL.to_owned()
}

#[derive(Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ProcessMode {
    #[default]
    Direct,
    WindowsCmd,
    #[serde(rename = "powershell", alias = "power_shell")]
    PowerShell,
}

enum HelperIntent {
    Cache(CacheIntentSpec, CacheWorkContext),
    Input(InputIntentSpec, InputWorkContext),
}
impl HelperIntent {
    fn binding_failure(&self) -> &'static str {
        match self {
            Self::Cache(..) => "cache_binding_rejected",
            Self::Input(..) => "input_binding_rejected",
        }
    }
}
struct ValidatedAssignment {
    helper: Option<HelperIntent>,
    workspace_grant: Option<WorkspaceGrant>,
    authority: WorkAuthority,
    workspace: PathBuf,
    payload_digest: [u8; 32],
    /// Ordered steps of one attempt; exactly one unless `multi_step`.
    steps: Vec<ProcessSpec>,
    /// The payload arrived as the version-5 envelope (PAR-010): steps run
    /// under per-step spools and step ordinals, and the journal records
    /// each step start before its spawn.
    multi_step: bool,
    /// Digest-pinned image every step runs in under podman (PAR-011).
    image: Option<String>,
}

/// One step's durable outcome inside a multi-step attempt, written into the
/// result spool and carried on the terminal summary.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct StepRecord {
    ordinal: u32,
    outcome: String,
    exit_code: Option<i32>,
    termination: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

/// The digest-verified payload permanently determines whether an assignment is
/// runnable. An unsupported specification is therefore never an error to retry:
/// it must be accepted and finalized as a named terminal failure, or the
/// controller reschedules it forever while the build reports progress.
enum AssignmentDisposition {
    Runnable(Box<ValidatedAssignment>),
    /// A well-formed payload this agent cannot execute, which another agent
    /// can. Never terminal: the claim is declined so the lease lapses and the
    /// work returns to the queue for a runtime that matches it.
    ForAnotherRuntime(&'static str),
    Unsupported(UnsupportedAssignment),
}

struct UnsupportedAssignment {
    authority: WorkAuthority,
    workspace: PathBuf,
    payload_digest: [u8; 32],
    detail: String,
}

struct ProcesslessCompletion<'a> {
    authority: &'a WorkAuthority,
    workspace: &'a Path,
    session_epoch: u64,
    outcome: WorkOutcome,
    reason: String,
    /// Per-step records of a multi-step attempt whose first step never
    /// spawned; empty for every single-step processless completion.
    steps: Vec<StepRecord>,
}

struct DurableResult<'a> {
    workspace_transfer: Option<&'a WorkspaceTransferResult>,
    outcome: WorkOutcome,
    exit_code: Option<i32>,
    termination: &'a str,
    reason: Option<&'a str>,
    completion_protocol: &'a str,
    cancellation_outcome: Option<i32>,
    /// Per-step outcomes of a multi-step attempt; empty for single-step work
    /// so the single-step result bytes are unchanged.
    steps: &'a [StepRecord],
}

struct LeaseRenewalControl {
    lease_seconds: u32,
    renewal_interval: Duration,
    /// The last instant the agent KNOWS preceded the controller stamping this
    /// term's `lease_expires_at` -- the moment the request that opened the term
    /// left, never the moment its answer came back. The controller stamps the
    /// expiry while the request is in flight, so an anchor taken on receipt is
    /// later than the controller's own by the round trip, and a round trip
    /// longer than the one-second margin would put the agent's deadline AFTER
    /// the instant the attempt becomes reclaimable.
    lease_started_at: tokio::time::Instant,
    lease_window: Duration,
    termination_grace: Duration,
    execution_cancellation: CancellationToken,
    authority_lost: CancellationToken,
    stop: CancellationToken,
    loss_reason: Arc<OnceLock<&'static str>>,
}

/// Marker for an execution cancelled by the controller's own request; it is
/// never reported as lease loss.
const CONTROLLER_CANCELLATION_TRIGGER: &str = "controller_cancellation";

/// Names the exact renewal failure before it cancels a running execution, so
/// authority loss during a step is never a silent cancellation. First trigger
/// wins: a cancellation already in progress keeps its cause.
fn record_lease_loss(loss_reason: &OnceLock<&'static str>, cause: &'static str) {
    if loss_reason.set(cause).is_ok() {
        eprintln!("lease_lost_during_execution: {cause}; cancelling the running step");
    }
}

/// Maps the controller's named refusal cause onto the agent's fixed cause
/// vocabulary so the durable result agrees with the recorded controller
/// event; an empty or unknown cause stays the generic rejection.
fn renewal_rejection_cause(cause: &str) -> &'static str {
    match cause {
        "agent_session_stale" => "renewal_session_stale",
        _ => "renewal_rejected",
    }
}

/// Classifies a renewal status the controller actually ANSWERED with: a
/// stale-session fencing rejection is named as such, and every other answered
/// refusal is the generic rejection. A status the agent merely failed to get an
/// answer to never reaches this function -- see [`renewal_went_unanswered`].
fn renewal_status_cause(status: &tonic::Status) -> &'static str {
    if status.code() == tonic::Code::FailedPrecondition
        && status.message().contains("stale agent session epoch")
    {
        "renewal_session_stale"
    } else {
        "renewal_refused"
    }
}

/// Did this renewal fail to produce a usable answer, rather than carry one?
///
/// Only an answer can withdraw authority. Unreachability cannot: the lease the
/// agent already holds stands until it expires, and the controller cannot
/// requeue the attempt before then -- `requeue_one_expired` reclaims only a
/// lease whose `lease_expires_at` has passed, and the renewal statement itself
/// requires an unexpired one. Treating the two alike killed a running step on
/// the first failed renewal RPC while 296 seconds of a 300-second lease
/// remained, which is `AGENT-007`.
///
/// The predicate is deliberately the SAME one every other authority-bearing RPC
/// in this file already uses, so the renewal task cannot disagree with the log
/// publication and start-work paths about which statuses are worth another ask.
/// Those paths are bounded by `authority_lost`, which this task owns; this one
/// is bounded by the lease itself.
fn renewal_went_unanswered(status: &tonic::Status) -> bool {
    retryable_authority_transition(status)
}

/// How often an unanswered renewal is retried: at least once a second, so a
/// controller that comes back from a short restart is noticed promptly, and
/// ordinarily no more often than the agent's own renewal cadence, which the
/// configuration already forbids from being zero. The renewal loop can shorten
/// this interval to leave room for a second ask near the held deadline.
fn renewal_retry_interval(renewal_interval: Duration) -> Duration {
    renewal_interval.min(Duration::from_secs(1))
}

/// When to ask again after an unanswered renewal, or `None` at the execution
/// cancellation deadline. Its request-start anchor reserves the complete
/// termination grace plus one second before controller expiry. Cancellation
/// begins at this deadline; observed process quiescence is a separate gate.
fn next_renewal_retry(
    now: tokio::time::Instant,
    lease_deadline: tokio::time::Instant,
    retry_interval: Duration,
) -> Option<tokio::time::Instant> {
    if now >= lease_deadline {
        None
    } else {
        Some((now + retry_interval).min(lease_deadline))
    }
}

struct PublicationContext<'a> {
    client: &'a mut AgentControlClient<Channel>,
    authority: &'a WorkAuthority,
    session_epoch: u64,
    control: AuthorityRpcControl<'a>,
}

#[derive(Clone, Copy)]
struct AuthorityRpcControl<'a> {
    authority_lost: &'a CancellationToken,
    stop: &'a CancellationToken,
    lease_window: Duration,
}

/// What one work poll did, so the caller can tell an idle pass from one that
/// moved the queue. The poll interval paces *asking* for work; it must not
/// also pace *doing* it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PollOutcome {
    /// The controller offered nothing.
    Idle,
    /// An assignment was executed, or terminally refused. Either way the queue
    /// moved and the next unit may already be claimable.
    Progressed,
    /// The assignment was declined without terminalizing it. The controller
    /// re-offers it until the lease lapses, so asking again immediately would
    /// spin on the same offer.
    Declined,
}

pub(super) async fn poll_and_run_one(
    config: &AgentConfig,
    client: &mut AgentControlClient<Channel>,
    session_epoch: u64,
    features: SessionFeatures,
    stop: CancellationToken,
) -> Result<PollOutcome, AgentError> {
    // Taken before the poll is sent: the controller stamps the claim lease
    // inside the poll transaction, so the true expiry is never earlier than
    // this instant plus the lease window. The folded accept path uses it to
    // bound the first background renewal.
    let claimed_no_later_than = tokio::time::Instant::now();
    let offer = tokio::select! {
        () = stop.cancelled() => return Ok(PollOutcome::Idle),
        response = poll_rpc(
            WORK_POLL_RPC_WINDOW,
            client.poll_work(WorkPoll {
                agent_id: config.agent_id.clone(),
                session_epoch,
                organization_id: config.organization_id.clone(),
                lease_seconds: config.lease_seconds,
            }),
        ) => response?,
    };
    ensure_session(offer.session_epoch, session_epoch)?;
    let Some(assignment) = offer.assignment else {
        return Ok(PollOutcome::Idle);
    };
    if !assignment.workspace_transfer_json.is_empty() && !features.workspace_transfer {
        return Err(AgentError::InvalidAssignment(
            "workspace transfer was not negotiated".to_owned(),
        ));
    }
    match validate_assignment_with_features(config, session_epoch, assignment, features)? {
        AssignmentDisposition::Runnable(assignment) => {
            run_assignment(
                config,
                client,
                session_epoch,
                features,
                claimed_no_later_than,
                *assignment,
                stop,
            )
            .await?;
            Ok(PollOutcome::Progressed)
        }
        AssignmentDisposition::ForAnotherRuntime(reason) => {
            // Decline without terminalizing. The lease lapses, the controller
            // requeues, and an agent with the matching runtime claims it.
            eprintln!("declining_assignment: {reason}");
            Ok(PollOutcome::Declined)
        }
        AssignmentDisposition::Unsupported(refusal) => {
            refuse_unsupported_assignment(
                config,
                client,
                session_epoch,
                features,
                claimed_no_later_than,
                refusal,
                stop,
            )
            .await?;
            Ok(PollOutcome::Progressed)
        }
    }
}

pub(super) async fn recover_finalizations(
    config: &AgentConfig,
    client: &mut AgentControlClient<Channel>,
    session_epoch: u64,
    stop: &CancellationToken,
) -> Result<(), AgentError> {
    reclaim_terminal_spools(config).await?;
    let report = Journal::open(&config.journal_path)?.reconcile()?;
    for attempt in report.attempts {
        if !matches!(
            attempt.phase,
            AttemptPhase::Finalizing | AttemptPhase::Cancelling
        ) {
            continue;
        }
        let authority = WorkAuthority {
            agent_id: config.agent_id.clone(),
            session_epoch,
            organization_id: attempt.organization_id.clone(),
            attempt_id: attempt.attempt_id.clone(),
            fence_token: attempt.fence_token,
        };
        let lease_started_at = tokio::time::Instant::now();
        let lease_window = Duration::from_secs(RECOVERED_FINALIZATION_LEASE_SECONDS);
        let lease = lease_deadline_rpc(
            lease_started_at + lease_rpc_budget(lease_window),
            client.renew_work_lease(WorkLeaseRenewal {
                authority: Some(authority.clone()),
                lease_seconds: u32::try_from(RECOVERED_FINALIZATION_LEASE_SECONDS)
                    .expect("recovery lease fits the wire type"),
            }),
        )
        .await?;
        ensure_session(lease.session_epoch, session_epoch)?;
        if !lease.accepted {
            return Err(AgentError::StaleAuthority);
        }
        let lease_stop = CancellationToken::new();
        // A probe timeout drops this recovery future. Keep cancellation tied
        // to that lifetime so the spawned renewal task cannot outlive replay.
        let _lease_stop_guard = lease_stop.clone().drop_guard();
        let authority_lost = CancellationToken::new();
        let execution_cancellation = CancellationToken::new();
        let lease_task = tokio::spawn(renew_lease(
            client.clone(),
            authority.clone(),
            LeaseRenewalControl {
                lease_seconds: config.lease_seconds,
                renewal_interval: recovery_renewal_interval(config.lease_renewal_interval),
                lease_started_at,
                lease_window,
                termination_grace: Duration::ZERO,
                execution_cancellation,
                authority_lost: authority_lost.clone(),
                stop: lease_stop.clone(),
                loss_reason: Arc::new(OnceLock::new()),
            },
        ));
        let replay_result = replay_finalization(
            config,
            client,
            session_epoch,
            &attempt,
            authority,
            AuthorityRpcControl {
                authority_lost: &authority_lost,
                stop,
                lease_window,
            },
        )
        .await;
        lease_stop.cancel();
        let lease_result = lease_task.await;
        let terminal = replay_result?;
        commit_replayed_phase(config, &attempt, terminal).await?;
        // The controller's terminal acknowledgement is authoritative even
        // when a concurrent renewal observes that the terminal lease is no
        // longer renewable. Never strand an acknowledged replay locally.
        lease_result.map_err(|error| {
            AgentError::InvalidAssignment(format!("lease task failed: {error}"))
        })??;
    }
    Ok(())
}

async fn commit_replayed_phase(
    config: &AgentConfig,
    attempt: &mcloving_agent_runtime::ReconciliationAttempt,
    phase: AttemptPhase,
) -> Result<(), AgentError> {
    let mut journal = Journal::open(&config.journal_path)?;
    // Replay can learn that a cancellation overrode the terminal this attempt
    // was finalizing, and the journal reaches Aborted only through Cancelling.
    // Without that step recovery cannot clear the finalization at all, and the
    // agent stops polling for work entirely.
    if phase == AttemptPhase::Aborted {
        journal.transition(
            &attempt.organization_id,
            &attempt.attempt_id,
            attempt.fence_token,
            attempt.session_epoch,
            AttemptPhase::Cancelling,
            attempt.process_id,
        )?;
    }
    journal.transition(
        &attempt.organization_id,
        &attempt.attempt_id,
        attempt.fence_token,
        attempt.session_epoch,
        phase,
        attempt.process_id,
    )?;
    if phase.is_terminal() {
        reclaim_attempt_spools(config, attempt).await?;
    }
    Ok(())
}

fn recovery_renewal_interval(configured: Duration) -> Duration {
    configured.min(Duration::from_secs(
        RECOVERED_FINALIZATION_LEASE_SECONDS / 2,
    ))
}

async fn replay_finalization(
    config: &AgentConfig,
    client: &mut AgentControlClient<Channel>,
    session_epoch: u64,
    attempt: &mcloving_agent_runtime::ReconciliationAttempt,
    authority: WorkAuthority,
    control: AuthorityRpcControl<'_>,
) -> Result<AttemptPhase, AgentError> {
    validate_log_spool_quota(&attempt.logs)?;
    let mut sequence = 0;
    let mut publication = PublicationContext {
        client,
        authority: &authority,
        session_epoch,
        control,
    };
    for entry in &attempt.logs {
        let (stream, step_ordinal) = spool_stream(entry)?;
        sequence = publish_spool(
            &mut publication,
            stream,
            step_ordinal,
            &config.workspace_root,
            entry,
            sequence,
        )
        .await?;
    }
    let result_entry = attempt.result.as_ref().ok_or_else(|| {
        AgentError::InvalidAssignment(
            "finalizing journal attempt has no durable result spool".to_owned(),
        )
    })?;
    let result_content =
        verified_spool_content(&config.workspace_root, result_entry, "result").await?;
    let result: PersistedResult = serde_json::from_slice(&result_content)?;
    let outcome = persisted_outcome(&result.outcome)?;
    if (attempt.phase == AttemptPhase::Finalizing && outcome == WorkOutcome::Aborted)
        || (attempt.phase == AttemptPhase::Cancelling && outcome != WorkOutcome::Aborted)
    {
        return Err(AgentError::InvalidAssignment(
            "journal phase conflicts with durable result outcome".to_owned(),
        ));
    }
    match result.completion_protocol.as_str() {
        WORK_COMPLETION_PROTOCOL => {
            let summary = work_completion_summary(&result, &result_entry.digest, true)?;
            let published = published_work_outcome(
                authority_rpc(
                    control,
                    publication.client.complete_work(WorkCompletion {
                        authority: Some(authority.clone()),
                        outcome: outcome as i32,
                        summary_json: summary,
                        // Replay re-publishes through PublishLog: the chunks
                        // may exceed one apiece, and the streamed path is the
                        // recovery invariant being replayed.
                        inline_log_chunks: Vec::new(),
                    }),
                )
                .await?,
                session_epoch,
            )?;
            terminal_phase(published.unwrap_or(outcome))
        }
        CANCELLATION_COMPLETION_PROTOCOL => {
            if attempt.phase != AttemptPhase::Cancelling || outcome != WorkOutcome::Aborted {
                return Err(AgentError::InvalidAssignment(
                    "cancellation replay conflicts with durable journal state".to_owned(),
                ));
            }
            let cancellation_outcome = result.cancellation_outcome.ok_or_else(|| {
                AgentError::InvalidAssignment(
                    "cancellation replay has no durable outcome".to_owned(),
                )
            })?;
            match CancellationOutcome::try_from(cancellation_outcome) {
                Ok(
                    CancellationOutcome::Terminated
                    | CancellationOutcome::AlreadyExited
                    | CancellationOutcome::IdentityMismatch,
                ) => {}
                Ok(
                    CancellationOutcome::Unspecified | CancellationOutcome::ReconciliationRequired,
                )
                | Err(_) => {
                    return Err(AgentError::InvalidAssignment(
                        "cancellation replay has an invalid durable outcome".to_owned(),
                    ));
                }
            }
            let receipt = authority_rpc(
                control,
                publication
                    .client
                    .complete_cancellation(CancellationCompletion {
                        agent_id: config.agent_id.clone(),
                        session_epoch,
                        organization_id: attempt.organization_id.clone(),
                        attempt_id: attempt.attempt_id.clone(),
                        fence_token: attempt.fence_token,
                        outcome: cancellation_outcome,
                    }),
            )
            .await?;
            ensure_session(receipt.session_epoch, session_epoch)?;
            match CancellationDisposition::try_from(receipt.disposition) {
                Ok(
                    CancellationDisposition::Completed
                    | CancellationDisposition::RetireStale
                    | CancellationDisposition::DischargeRecovered,
                ) => Ok(AttemptPhase::Aborted),
                Ok(CancellationDisposition::ReconciliationRequired) => {
                    Ok(AttemptPhase::ReconciliationRequired)
                }
                Ok(CancellationDisposition::Unspecified) | Err(_) => {
                    Err(AgentError::UnsupportedProtocol)
                }
            }
        }
        _ => Err(AgentError::InvalidAssignment(
            "durable result has an unknown completion protocol".to_owned(),
        )),
    }
}

#[cfg(test)]
fn validate_assignment(
    config: &AgentConfig,
    session_epoch: u64,
    assignment: WorkAssignment,
) -> Result<AssignmentDisposition, AgentError> {
    validate_assignment_with_features(
        config,
        session_epoch,
        assignment,
        SessionFeatures::default(),
    )
}

fn validate_assignment_with_features(
    config: &AgentConfig,
    session_epoch: u64,
    assignment: WorkAssignment,
    features: SessionFeatures,
) -> Result<AssignmentDisposition, AgentError> {
    let organization = parse_uuid("organization_id", &assignment.organization_id)?;
    let configured_organization =
        parse_uuid("configured organization_id", &config.organization_id)?;
    if organization != configured_organization {
        return Err(AgentError::InvalidAssignment(
            "organization does not match the configured tenant".to_owned(),
        ));
    }
    parse_uuid("build_id", &assignment.build_id)?;
    parse_uuid("node_id", &assignment.node_id)?;
    parse_uuid("attempt_id", &assignment.attempt_id)?;
    let payload_digest: [u8; 32] = assignment
        .payload_digest
        .as_slice()
        .try_into()
        .map_err(|_| AgentError::InvalidAssignment("payload digest is not SHA-256".to_owned()))?;
    let cache_context = CacheWorkContext {
        organization_id: assignment.organization_id.clone(),
        project_id: assignment.project_id.clone(),
        pipeline_id: assignment.pipeline_id.clone(),
        build_id: assignment.build_id.clone(),
        node_id: assignment.node_id.clone(),
        attempt_id: assignment.attempt_id.clone(),
        fence_token: assignment.fence_token,
    };
    let helper_version =
        serde_json::from_slice::<serde_json::Value>(&assignment.execution_spec_json)
            .ok()
            .and_then(|value| value.get("version").and_then(serde_json::Value::as_u64));
    let calculated: [u8; 32] = if matches!(helper_version, Some(3 | 4)) {
        cache_context.validate().map_err(|_| {
            AgentError::InvalidAssignment("helper work context is invalid".to_owned())
        })?;
        if helper_version == Some(4) {
            input_assignment_digest(&assignment.execution_spec_json, &cache_context)
        } else {
            cache_assignment_digest(&assignment.execution_spec_json, &cache_context)
        }
    } else {
        Sha256::digest(&assignment.execution_spec_json).into()
    };
    if payload_digest != calculated {
        return Err(AgentError::InvalidAssignment(
            "execution payload digest does not match".to_owned(),
        ));
    }
    let workspace_grant = if assignment.workspace_transfer_json.is_empty() {
        None
    } else {
        if !cfg!(target_os = "linux") || assignment.workspace_transfer_json.len() > 65_536 {
            return Err(AgentError::InvalidAssignment(
                "unsupported workspace transfer".to_owned(),
            ));
        }
        let grant: WorkspaceGrant = serde_json::from_slice(&assignment.workspace_transfer_json)?;
        grant
            .validate()
            .map_err(|error| AgentError::InvalidAssignment(error.to_string()))?;
        if grant.organization_id != assignment.organization_id
            || grant.build_id != assignment.build_id
        {
            return Err(AgentError::InvalidAssignment(
                "workspace grant scope mismatch".to_owned(),
            ));
        }
        Some(grant)
    };
    let workspace = PathBuf::from(format!(
        "{}/{}/{}",
        assignment.organization_id, assignment.attempt_id, assignment.fence_token
    ));
    let authority = WorkAuthority {
        agent_id: config.agent_id.clone(),
        session_epoch,
        organization_id: assignment.organization_id,
        attempt_id: assignment.attempt_id,
        fence_token: assignment.fence_token,
    };
    Ok(
        match classify_assignment_spec(&assignment.execution_spec_json) {
            SpecClassification::Process(process) => {
                if workspace_grant.is_some()
                    && (!process.env.is_empty() || !process.credentials.is_empty())
                {
                    return Ok(AssignmentDisposition::Unsupported(UnsupportedAssignment {
                        authority,
                        workspace,
                        payload_digest,
                        detail: "workspace transfer forbids environment overrides and credentials"
                            .to_owned(),
                    }));
                }
                AssignmentDisposition::Runnable(Box::new(ValidatedAssignment {
                    helper: None,
                    workspace_grant,
                    authority,
                    workspace,
                    payload_digest,
                    steps: vec![process],
                    multi_step: false,
                    image: None,
                }))
            }
            SpecClassification::Steps { steps, image } => {
                if image.is_some() && (!cfg!(unix) || config.podman_path.is_none()) {
                    // Routing keeps image work away from agents without a
                    // runtime; if it arrives anyway, another agent can run it.
                    return Ok(AssignmentDisposition::ForAnotherRuntime(
                        "container work requires an agent with a configured podman runtime",
                    ));
                }
                if !features.multi_step {
                    // The capability is advertised at session open, before
                    // negotiation can tell this agent whether the controller
                    // it reached understands step ordinals. A previous-release
                    // replica in a mixed rollout may therefore claim a
                    // version-5 node for this session. That work is valid for
                    // any session that did negotiate the feature, so decline
                    // it back to the queue rather than fail it for good.
                    return Ok(AssignmentDisposition::ForAnotherRuntime(
                        "multi-step work requires a session that negotiated multi-step-execution-v1",
                    ));
                }
                if workspace_grant.is_some() {
                    return Ok(AssignmentDisposition::Unsupported(UnsupportedAssignment {
                        authority,
                        workspace,
                        payload_digest,
                        detail: "workspace transfer is not supported for multi-step stages"
                            .to_owned(),
                    }));
                }
                AssignmentDisposition::Runnable(Box::new(ValidatedAssignment {
                    helper: None,
                    workspace_grant: None,
                    authority,
                    workspace,
                    payload_digest,
                    steps,
                    multi_step: true,
                    image,
                }))
            }
            SpecClassification::Cache(intent) => {
                if !cfg!(target_os = "linux")
                    || config.cache_bindings.is_none()
                    || workspace_grant.is_some()
                {
                    AssignmentDisposition::Unsupported(UnsupportedAssignment {
                        authority,
                        workspace,
                        payload_digest,
                        detail:
                            "cache runtime binding unavailable or workspace transfer unsupported"
                                .to_owned(),
                    })
                } else {
                    let process = ProcessSpec {
                        kind: "cache_intent".to_owned(),
                        mode: ProcessMode::Direct,
                        program: String::new(),
                        args: Vec::new(),
                        env: BTreeMap::new(),
                        credentials: Vec::new(),
                        timeout_seconds: Some(intent.timeout_seconds),
                    };
                    AssignmentDisposition::Runnable(Box::new(ValidatedAssignment {
                        helper: Some(HelperIntent::Cache(intent, cache_context)),
                        workspace_grant,
                        authority,
                        workspace,
                        payload_digest,
                        steps: vec![process],
                        multi_step: false,
                        image: None,
                    }))
                }
            }
            SpecClassification::Input(intent) => {
                if !cfg!(target_os = "linux")
                    || config.input_bindings.is_none()
                    || workspace_grant.is_some()
                {
                    AssignmentDisposition::Unsupported(UnsupportedAssignment {
                        authority,
                        workspace,
                        payload_digest,
                        detail:
                            "input runtime binding unavailable or workspace transfer unsupported"
                                .to_owned(),
                    })
                } else {
                    let process = ProcessSpec {
                        kind: "input_intent".to_owned(),
                        mode: ProcessMode::Direct,
                        program: String::new(),
                        args: Vec::new(),
                        env: BTreeMap::new(),
                        credentials: Vec::new(),
                        timeout_seconds: Some(intent.timeout_seconds),
                    };
                    AssignmentDisposition::Runnable(Box::new(ValidatedAssignment {
                        helper: Some(HelperIntent::Input(intent, cache_context)),
                        workspace_grant,
                        authority,
                        workspace,
                        payload_digest,
                        steps: vec![process],
                        multi_step: false,
                        image: None,
                    }))
                }
            }
            SpecClassification::ForAnotherRuntime(reason) => {
                AssignmentDisposition::ForAnotherRuntime(reason)
            }
            SpecClassification::Unsupported(detail) => {
                AssignmentDisposition::Unsupported(UnsupportedAssignment {
                    authority,
                    workspace,
                    payload_digest,
                    detail,
                })
            }
        },
    )
}

/// What this agent can make of a digest-verified execution payload.
enum SpecClassification {
    Input(InputIntentSpec),
    Cache(CacheIntentSpec),
    Process(ProcessSpec),
    /// The version-5 multi-step envelope: ordered process steps of one stage,
    /// optionally all inside one digest-pinned image.
    Steps {
        steps: Vec<ProcessSpec>,
        image: Option<String>,
    },
    ForAnotherRuntime(&'static str),
    Unsupported(String),
}

/// Separates a payload that is unrunnable anywhere from one that merely needs a
/// different runtime, before the strict process decode that cannot tell them
/// apart.
///
/// A connector-intent step carries no `program`, so decoding it as a process
/// spec fails exactly like malformed input. Terminalizing on that would
/// permanently fail work an effect-runtime worker could have run, and those
/// nodes are admitted with no required capability, so they do reach
/// process-only agents until capability routing prevents it.
fn connector_intent_payload(execution_spec_json: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(execution_spec_json) else {
        return false;
    };
    // Decline only a payload some other runtime can actually execute. Anything
    // this agent can prove unrunnable it must terminalize itself rather than
    // return to the queue, because declining only re-offers the work and this
    // agent may win the claim again — connector nodes carry no runtime
    // capability constraint until EXEC-002 adds one, so nothing guarantees an
    // effect worker ever sees it.
    //
    // Version is part of that judgement: a connector-intent step under any
    // version but 2 is runnable by nothing. So is a version-2 intent whose
    // fields the effect runtime would reject, which is why this decodes the
    // whole intent through the shared schema rather than checking its shape.
    if value.get("version").and_then(serde_json::Value::as_u64) != Some(2) {
        return false;
    }
    let Some(steps) = value.get("steps").and_then(serde_json::Value::as_array) else {
        return false;
    };
    let [step] = steps.as_slice() else {
        return false;
    };
    if step.get("kind").and_then(serde_json::Value::as_str) != Some("connector_intent") {
        return false;
    }
    let mut intent = step.clone();
    let Some(fields) = intent.as_object_mut() else {
        return false;
    };
    fields.remove("kind");
    serde_json::from_value::<ConnectorIntentSpec>(intent).is_ok()
}

fn classify_assignment_spec(execution_spec_json: &[u8]) -> SpecClassification {
    if serde_json::from_slice::<serde_json::Value>(execution_spec_json)
        .ok()
        .is_some_and(|value| value.get("version").and_then(serde_json::Value::as_u64) == Some(3))
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Envelope {
            version: u16,
            steps: Vec<CacheStep>,
        }
        #[derive(Deserialize)]
        #[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
        enum CacheStep {
            CacheIntent(CacheIntentSpec),
        }
        let decoded = mcloving_cache::parse_json_no_duplicates::<Envelope>(execution_spec_json);
        return match decoded {
            Ok(mut envelope) if envelope.version == 3 && envelope.steps.len() == 1 => {
                let Some(CacheStep::CacheIntent(intent)) = envelope.steps.pop() else {
                    unreachable!()
                };
                if intent.validate().is_ok() {
                    SpecClassification::Cache(intent)
                } else {
                    SpecClassification::Unsupported("invalid cache intent".to_owned())
                }
            }
            _ => SpecClassification::Unsupported("invalid cache execution envelope".to_owned()),
        };
    }
    if serde_json::from_slice::<serde_json::Value>(execution_spec_json)
        .ok()
        .is_some_and(|value| value.get("version").and_then(serde_json::Value::as_u64) == Some(4))
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Envelope {
            version: u16,
            steps: Vec<InputStep>,
        }
        #[derive(Deserialize)]
        #[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
        enum InputStep {
            InputIntent(InputIntentSpec),
        }
        let decoded =
            mcloving_input_adapter::parse_json_no_duplicates::<Envelope>(execution_spec_json);
        return match decoded {
            Ok(mut envelope) if envelope.version == 4 && envelope.steps.len() == 1 => {
                let Some(InputStep::InputIntent(intent)) = envelope.steps.pop() else {
                    unreachable!()
                };
                if intent.validate().is_ok() {
                    SpecClassification::Input(intent)
                } else {
                    SpecClassification::Unsupported("invalid input intent".to_owned())
                }
            }
            _ => SpecClassification::Unsupported("invalid input execution envelope".to_owned()),
        };
    }
    if connector_intent_payload(execution_spec_json) {
        return SpecClassification::ForAnotherRuntime(
            "connector-intent work requires a controller-owned effect runtime",
        );
    }
    if serde_json::from_slice::<serde_json::Value>(execution_spec_json)
        .ok()
        .is_some_and(|value| value.get("version").and_then(serde_json::Value::as_u64) == Some(5))
    {
        return match supported_multi_step_spec(execution_spec_json) {
            Ok((steps, image)) => SpecClassification::Steps { steps, image },
            Err(detail) => SpecClassification::Unsupported(bounded_refusal_detail(detail)),
        };
    }
    match supported_process_spec(execution_spec_json) {
        Ok(process) => SpecClassification::Process(process),
        Err(detail) => SpecClassification::Unsupported(bounded_refusal_detail(detail)),
    }
}

/// Classifies the version-5 envelope (PAR-010): one to sixteen bounded
/// process steps, each held to exactly the per-step rules of the single-step
/// contract. Every refusal is permanent for this payload.
fn supported_multi_step_spec(
    execution_spec_json: &[u8],
) -> Result<(Vec<ProcessSpec>, Option<String>), String> {
    use mcloving_domain::multi_step::MAX_STEPS_PER_STAGE;
    let spec: ExecutionSpec = serde_json::from_slice(execution_spec_json).map_err(|error| {
        format!("execution spec does not deserialize as a version-5 multi-step spec: {error}")
    })?;
    if spec.version != 5 {
        return Err(format!(
            "execution spec version {} is not supported (expected 5)",
            spec.version
        ));
    }
    if spec.steps.is_empty() || spec.steps.len() > MAX_STEPS_PER_STAGE {
        return Err(format!(
            "execution spec declares {} steps (expected 1..={MAX_STEPS_PER_STAGE} process steps)",
            spec.steps.len()
        ));
    }
    for (index, process) in spec.steps.iter().enumerate() {
        if process.kind != "process" {
            return Err(format!(
                "execution spec step {index} kind {:?} is not supported (expected \"process\")",
                process.kind
            ));
        }
        if !matches!(
            process.timeout_seconds,
            None | Some(1..=MAX_EXECUTION_TIMEOUT_SECONDS)
        ) {
            return Err(format!(
                "step {index} timeout must be between 1 and {MAX_EXECUTION_TIMEOUT_SECONDS} seconds"
            ));
        }
        if process.credentials.len() > 8
            || !credential_targets_are_valid(&process.env, &process.credentials)
        {
            return Err(format!(
                "step {index} credential targets must be unique bounded environment names and must not collide with pipeline environment"
            ));
        }
    }
    // Credentials are redeemed once per attempt as the union of every step's
    // targets, and the controller bounds that request at eight, so the union
    // is checked here rather than discovered as a refused redemption later.
    let union = spec
        .steps
        .iter()
        .flat_map(|process| process.credentials.iter())
        .collect::<std::collections::BTreeSet<_>>();
    if union.len() > 8 {
        return Err(format!(
            "credential targets across all steps ({}) exceed the per-attempt bound of 8",
            union.len()
        ));
    }
    if let Some(image) = &spec.image
        && !mcloving_domain::container::is_digest_pinned_image(image)
    {
        return Err("stage image is not a digest-pinned reference".to_owned());
    }
    Ok((spec.steps, spec.image))
}

/// The refusal reason is written twice into the durable result and sent as the
/// completion summary, which the controller caps at 64 KiB, while an execution
/// spec may approach the store's far larger limit. An unbounded reason built
/// from an attacker-controlled field would fail that check, leave the attempt
/// unfinalized, and wedge the journal on an oversized spool — turning the
/// terminal refusal this ticket introduces back into the loop it removes.
const MAX_REFUSAL_DETAIL_BYTES: usize = 512;

fn bounded_refusal_detail(detail: String) -> String {
    if detail.len() <= MAX_REFUSAL_DETAIL_BYTES {
        return detail;
    }
    let mut cut = MAX_REFUSAL_DETAIL_BYTES;
    while !detail.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{} (truncated)", &detail[..cut])
}

/// Classifies the digest-verified execution payload against the only contract
/// this agent can execute: version 1 with exactly one bounded process step.
/// Every refusal returned here is permanent for this payload.
fn supported_process_spec(execution_spec_json: &[u8]) -> Result<ProcessSpec, String> {
    let spec: ExecutionSpec = match serde_json::from_slice(execution_spec_json) {
        Ok(spec) => spec,
        Err(error) => {
            return Err(format!(
                "execution spec does not deserialize as a version-1 process spec: {error}"
            ));
        }
    };
    if spec.version != 1 {
        return Err(format!(
            "execution spec version {} is not supported (expected 1)",
            spec.version
        ));
    }
    let mut steps = spec.steps;
    if steps.len() != 1 {
        return Err(format!(
            "execution spec declares {} steps (expected exactly 1 process step)",
            steps.len()
        ));
    }
    let Some(process) = steps.pop() else {
        return Err("execution spec declares 0 steps (expected exactly 1 process step)".to_owned());
    };
    if process.kind != "process" {
        return Err(format!(
            "execution spec step kind {:?} is not supported (expected \"process\")",
            process.kind
        ));
    }
    if !matches!(
        process.timeout_seconds,
        None | Some(1..=MAX_EXECUTION_TIMEOUT_SECONDS)
    ) {
        return Err(format!(
            "process timeout must be between 1 and {MAX_EXECUTION_TIMEOUT_SECONDS} seconds"
        ));
    }
    if process.credentials.len() > 8
        || !credential_targets_are_valid(&process.env, &process.credentials)
    {
        return Err(
            "credential targets must be unique bounded environment names and must not collide with pipeline environment".to_owned(),
        );
    }
    Ok(process)
}

/// Terminal fail-closed path for a permanently unsupported assignment: accept
/// the fenced work so the controller stops offering it, then finalize the
/// attempt as failed with a named reason. Without this, a validate-escaping
/// spec is refused, rescheduled, and refused again while the build reports
/// `running` forever.
#[allow(clippy::too_many_arguments)]
async fn refuse_unsupported_assignment(
    config: &AgentConfig,
    client: &mut AgentControlClient<Channel>,
    session_epoch: u64,
    features: SessionFeatures,
    claimed_no_later_than: tokio::time::Instant,
    refusal: UnsupportedAssignment,
    stop: CancellationToken,
) -> Result<(), AgentError> {
    let mut journal = Journal::open(&config.journal_path)?;
    journal.accept(&Acceptance {
        organization_id: refusal.authority.organization_id.clone(),
        attempt_id: refusal.authority.attempt_id.clone(),
        fence_token: refusal.authority.fence_token,
        session_epoch,
        payload_digest: refusal.payload_digest,
        workspace: refusal.workspace.clone(),
    })?;
    let lease_window = Duration::from_secs(u64::from(config.lease_seconds));
    let receipt =
        lease_window_rpc(lease_window, client.accept_work(refusal.authority.clone())).await?;
    let accept_cancellation = receipt.cancellation_requested;
    require_work_receipt(receipt, session_epoch)?;
    let accepted_at = tokio::time::Instant::now();
    // Folded exactly like the runnable path, and anchored the same way: the
    // accept receipt answers the serialized renewal's questions when
    // accept-carries-lease-state-v1 was negotiated, the periodic renewal task
    // covers the lease from here, and the arm that did not renew is still on
    // the claim's own term because accepting does not extend it.
    let (cancellation_requested, lease_started_at) = if features.accept_lease_state
        && !accept_consumed_claim_lease(
            claimed_no_later_than,
            lease_window,
            accepted_at,
            config.lease_renewal_interval,
        ) {
        (accept_cancellation, claimed_no_later_than)
    } else {
        let lease = lease_deadline_rpc(
            accepted_at + lease_rpc_budget(lease_window),
            client.renew_work_lease(WorkLeaseRenewal {
                authority: Some(refusal.authority.clone()),
                lease_seconds: config.lease_seconds,
            }),
        )
        .await?;
        ensure_session(lease.session_epoch, session_epoch)?;
        if !lease.accepted {
            return Err(AgentError::StaleAuthority);
        }
        (lease.cancellation_requested, accepted_at)
    };
    let lease_stop = CancellationToken::new();
    // No process will ever spawn for this refusal, so execution cancellation
    // starts already-cancelled exactly like the pre-spawn cancellation path.
    let execution_cancellation = CancellationToken::new();
    execution_cancellation.cancel();
    let authority_lost = CancellationToken::new();
    let lease_task = tokio::spawn(renew_lease(
        client.clone(),
        refusal.authority.clone(),
        LeaseRenewalControl {
            lease_seconds: config.lease_seconds,
            renewal_interval: config.lease_renewal_interval,
            lease_started_at,
            lease_window,
            termination_grace: Duration::ZERO,
            execution_cancellation,
            authority_lost: authority_lost.clone(),
            stop: lease_stop.clone(),
            // A refusal spawns no process, so lease loss can cancel no step
            // and nothing reads this back. Its own cell, like every other
            // processless path.
            loss_reason: Arc::new(OnceLock::new()),
        },
    ));
    // Cancellation can already have committed before acceptance was recorded.
    // The normal assignment path publishes that as aborted, and a cancelled
    // build must not be reported as an execution-spec failure instead, so the
    // refusal yields to it.
    let (outcome, reason) = if cancellation_requested {
        (
            WorkOutcome::Aborted,
            "cancelled_before_process_spawn".to_owned(),
        )
    } else {
        (
            WorkOutcome::Failed,
            format!("unsupported_execution_spec: {}", refusal.detail),
        )
    };
    let completion_result = finalize_without_process(
        config,
        client,
        &mut journal,
        ProcesslessCompletion {
            authority: &refusal.authority,
            workspace: &refusal.workspace,
            session_epoch,
            outcome,
            reason,
            steps: Vec::new(),
        },
        AuthorityRpcControl {
            authority_lost: &authority_lost,
            stop: &stop,
            lease_window,
        },
    )
    .await;
    lease_stop.cancel();
    let lease_result = lease_task
        .await
        .map_err(|error| AgentError::InvalidAssignment(format!("lease task failed: {error}")))?;
    completion_result?;
    lease_result
}

fn parse_uuid(name: &str, value: &str) -> Result<Uuid, AgentError> {
    value
        .parse()
        .map_err(|_| AgentError::InvalidAssignment(format!("{name} is not a UUID")))
}

#[allow(clippy::too_many_arguments)]
async fn run_assignment(
    config: &AgentConfig,
    client: &mut AgentControlClient<Channel>,
    session_epoch: u64,
    features: SessionFeatures,
    _claimed_no_later_than: tokio::time::Instant,
    assignment: ValidatedAssignment,
    stop: CancellationToken,
) -> Result<(), AgentError> {
    let organization = assignment.authority.organization_id.clone();
    let attempt = assignment.authority.attempt_id.clone();
    let fence = assignment.authority.fence_token;
    let mut journal = Journal::open(&config.journal_path)?;
    let durable_acceptance = journal.accept(&Acceptance {
        organization_id: organization.clone(),
        attempt_id: attempt.clone(),
        fence_token: fence,
        session_epoch,
        payload_digest: assignment.payload_digest,
        workspace: assignment.workspace.clone(),
    })?;

    let lease_window = Duration::from_secs(u64::from(config.lease_seconds));
    let receipt = lease_window_rpc(
        lease_window,
        client.accept_work(assignment.authority.clone()),
    )
    .await?;
    let accept_cancellation = receipt.cancellation_requested;
    require_work_receipt(receipt, session_epoch)?;
    let accepted_at = tokio::time::Instant::now();
    // Acceptance does not renew the controller's claim term or report its
    // duration. Before spawning, obtain a term with the explicitly requested
    // duration; agent/controller defaults need not match. This deliberately
    // retains one serialized RPC even when folded acceptance is negotiated.
    // Request-start anchoring and the shortened timeout ensure a delayed
    // response cannot leave a process starting without termination reserve.
    let lease_started_at = accepted_at;
    let lease = lease_deadline_rpc(
        lease_cancellation_deadline(lease_started_at, lease_window, config.termination_grace),
        client.renew_work_lease(WorkLeaseRenewal {
            authority: Some(assignment.authority.clone()),
            lease_seconds: config.lease_seconds,
        }),
    )
    .await?;
    ensure_session(lease.session_epoch, session_epoch)?;
    if !lease.accepted {
        return Err(AgentError::StaleAuthority);
    }
    if tokio::time::Instant::now()
        >= lease_cancellation_deadline(lease_started_at, lease_window, config.termination_grace)
    {
        return Err(AgentError::LeaseRenewalTimeout);
    }
    let cancellation_requested = accept_cancellation || lease.cancellation_requested;
    if cancellation_requested {
        let lease_stop = CancellationToken::new();
        let execution_cancellation = CancellationToken::new();
        execution_cancellation.cancel();
        let authority_lost = CancellationToken::new();
        let lease_task = tokio::spawn(renew_lease(
            client.clone(),
            assignment.authority.clone(),
            LeaseRenewalControl {
                lease_seconds: config.lease_seconds,
                renewal_interval: config.lease_renewal_interval,
                lease_started_at,
                lease_window,
                termination_grace: Duration::ZERO,
                execution_cancellation,
                authority_lost: authority_lost.clone(),
                stop: lease_stop.clone(),
                loss_reason: Arc::new(OnceLock::new()),
            },
        ));
        let completion_result = finalize_without_process(
            config,
            client,
            &mut journal,
            ProcesslessCompletion {
                authority: &assignment.authority,
                workspace: &assignment.workspace,
                session_epoch,
                outcome: WorkOutcome::Aborted,
                reason: "cancelled_before_process_spawn".to_owned(),
                steps: Vec::new(),
            },
            AuthorityRpcControl {
                authority_lost: &authority_lost,
                stop: &stop,
                lease_window,
            },
        )
        .await;
        lease_stop.cancel();
        let lease_result = lease_task.await.map_err(|error| {
            AgentError::InvalidAssignment(format!("lease task failed: {error}"))
        })?;
        completion_result?;
        return lease_result;
    }
    let execution_cancellation = stop.child_token();
    let authority_lost = CancellationToken::new();
    let lease_stop = CancellationToken::new();
    let lease_loss_reason = Arc::new(OnceLock::new());
    let lease_task = tokio::spawn(renew_lease(
        client.clone(),
        assignment.authority.clone(),
        LeaseRenewalControl {
            lease_seconds: config.lease_seconds,
            renewal_interval: config.lease_renewal_interval,
            lease_started_at,
            lease_window,
            termination_grace: config.termination_grace,
            execution_cancellation: execution_cancellation.clone(),
            authority_lost: authority_lost.clone(),
            stop: lease_stop.clone(),
            loss_reason: lease_loss_reason.clone(),
        },
    ));
    let prepared_helper = match assignment
        .helper
        .as_ref()
        .map(|helper| match helper {
            HelperIntent::Cache(intent, context) => {
                crate::cache::prepare(config, intent, context, &assignment.payload_digest)
                    .map(Box::new)
                    .map(PreparedHelper::Cache)
            }
            HelperIntent::Input(intent, context) => crate::input::prepare(
                config,
                intent,
                context,
                &assignment.payload_digest,
                durable_acceptance.accepted_at_unix_ms,
            )
            .map(Box::new)
            .map(PreparedHelper::Input),
        })
        .transpose()
    {
        Ok(prepared) => prepared,
        Err(_) => {
            let result = finalize_without_process(
                config,
                client,
                &mut journal,
                ProcesslessCompletion {
                    authority: &assignment.authority,
                    workspace: &assignment.workspace,
                    session_epoch,
                    outcome: WorkOutcome::Failed,
                    reason: assignment
                        .helper
                        .as_ref()
                        .map_or("helper_binding_rejected", HelperIntent::binding_failure)
                        .to_owned(),
                    steps: Vec::new(),
                },
                AuthorityRpcControl {
                    authority_lost: &authority_lost,
                    stop: &stop,
                    lease_window,
                },
            )
            .await;
            lease_stop.cancel();
            let renewal = lease_task.await.map_err(|error| {
                AgentError::InvalidAssignment(format!("lease task failed: {error}"))
            })?;
            result?;
            return renewal;
        }
    };
    let mut assignment = assignment;
    let mut steps = std::mem::take(&mut assignment.steps);
    let multi_step = assignment.multi_step;
    // Validation admitted an image only with a configured runtime.
    let container_runtime = assignment
        .image
        .as_ref()
        .map(|image| {
            config
                .podman_path
                .clone()
                .map(|runtime| (runtime, image.clone()))
                .ok_or_else(|| {
                    AgentError::InvalidAssignment(
                        "container stage reached an agent without a runtime".to_owned(),
                    )
                })
        })
        .transpose()?;
    if let Some(prepared) = &prepared_helper {
        let first = steps
            .first_mut()
            .expect("a validated assignment carries at least one step");
        first.program = prepared.program().to_string_lossy().into_owned();
        first.args = prepared
            .arguments()
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect();
        first.env = prepared.environment();
    }
    // Credentials are granted per attempt. Every step's targets are fetched
    // once, and each step below binds only the targets it declared.
    let mut credential_targets: Vec<String> = Vec::new();
    for step in &steps {
        for target in &step.credentials {
            if !credential_targets.contains(target) {
                credential_targets.push(target.clone());
            }
        }
    }
    let credentials = if credential_targets.is_empty() {
        Vec::new()
    } else {
        match wait_for_credentials(
            client,
            &assignment.authority,
            &credential_targets,
            session_epoch,
            lease_window,
            &execution_cancellation,
            &authority_lost,
        )
        .await
        {
            Ok(Some(credentials)) => credentials,
            Ok(None) => {
                let completion_result = finalize_without_process(
                    config,
                    client,
                    &mut journal,
                    ProcesslessCompletion {
                        authority: &assignment.authority,
                        workspace: &assignment.workspace,
                        session_epoch,
                        outcome: WorkOutcome::Aborted,
                        reason: "cancelled_while_waiting_for_credentials".to_owned(),
                        steps: Vec::new(),
                    },
                    AuthorityRpcControl {
                        authority_lost: &authority_lost,
                        stop: &stop,
                        lease_window,
                    },
                )
                .await;
                lease_stop.cancel();
                let lease_result = lease_task.await.map_err(|error| {
                    AgentError::InvalidAssignment(format!("lease task failed: {error}"))
                })?;
                completion_result?;
                return lease_result;
            }
            Err(error) => {
                lease_stop.cancel();
                let _ = lease_task.await;
                return Err(error);
            }
        }
    };
    let start_receipt = match start_work_with_retry(
        client,
        &assignment.authority,
        session_epoch,
        lease_window,
        &execution_cancellation,
        &authority_lost,
        &stop,
    )
    .await
    {
        Ok(Some(receipt)) => receipt,
        Ok(None) => {
            let completion_result = finalize_without_process(
                config,
                client,
                &mut journal,
                ProcesslessCompletion {
                    authority: &assignment.authority,
                    workspace: &assignment.workspace,
                    session_epoch,
                    outcome: WorkOutcome::Aborted,
                    reason: "cancelled_while_starting_work".to_owned(),
                    steps: Vec::new(),
                },
                AuthorityRpcControl {
                    authority_lost: &authority_lost,
                    stop: &stop,
                    lease_window,
                },
            )
            .await;
            lease_stop.cancel();
            let lease_result = lease_task.await.map_err(|error| {
                AgentError::InvalidAssignment(format!("lease task failed: {error}"))
            })?;
            completion_result?;
            return lease_result;
        }
        Err(error) => {
            lease_stop.cancel();
            let _ = lease_task.await;
            return Err(error);
        }
    };
    require_work_receipt(start_receipt, session_epoch)?;
    // Every step's output is redacted against every credential the attempt
    // redeemed, not only the ones that step declared: an earlier step may
    // write its secret into the shared workspace and a later step may print
    // it, and the durable local spool must never hold it either way. Only the
    // declared bindings are injected into a step's environment.
    let attempt_redactions =
        execution_environment(BTreeMap::new(), credentials.clone())?.redactions;
    let completion_result: Result<(), AgentError> = async {
        // One attempt, several ordered steps (PAR-010). Every step's spool is
        // journaled before the first publication, every step's outcome is
        // recorded in the durable result, and execution stops at the first
        // step that does not succeed. The single-step envelope is the
        // one-iteration case of the same loop.
        let mut step_records: Vec<StepRecord> = Vec::with_capacity(steps.len());
        let mut logs: Vec<SpoolEntry> = Vec::with_capacity(steps.len() * 2);
        let mut output_budget = MAX_ATTEMPT_OUTPUT_BYTES;
        let mut last_outcome: Option<mcloving_agent_runtime::executor::ExecutionOutcome> = None;
        for (index, process) in steps.into_iter().enumerate() {
            let ordinal = u32::try_from(index).expect("step count is bounded");
            let step_credentials = credentials
                .iter()
                .filter(|credential| process.credentials.contains(&credential.target_name))
                .cloned()
                .collect::<Vec<_>>();
            let execution_environment = execution_environment(process.env, step_credentials)?;
            if multi_step {
                // Durable before the spawn: a crash anywhere after this point
                // names this step as interrupted, because the journal cannot
                // tell an exited process from one that was cut off.
                journal.record_step_start(
                    &organization,
                    &attempt,
                    fence,
                    session_epoch,
                    ordinal,
                )?;
            }
            let request = ExecutionRequest {
                workspace_seed: if index == 0 {
                    assignment
                        .workspace_grant
                        .as_ref()
                        .map(|grant| grant.snapshot.clone())
                } else {
                    None
                },
                step_ordinal: multi_step.then_some(ordinal),
                container: container_runtime.as_ref().map(|(runtime, image)| {
                    mcloving_agent_runtime::executor::ContainerSpec {
                        runtime: runtime.clone(),
                        image: image.clone(),
                        name: crate::container::container_name(&attempt, ordinal),
                    }
                }),
                workspace_root: config.workspace_root.clone(),
                workspace: assignment.workspace.clone(),
                mode: match process.mode {
                    ProcessMode::Direct => ExecutionMode::Direct,
                    ProcessMode::WindowsCmd => ExecutionMode::WindowsCmd,
                    ProcessMode::PowerShell => ExecutionMode::PowerShell,
                },
                program: PathBuf::from(process.program),
                arguments: process.args.into_iter().map(OsString::from).collect(),
                environment: execution_environment
                    .values
                    .into_iter()
                    .map(|(key, value)| (OsString::from(key), OsString::from(value)))
                    .collect(),
                // The per-attempt output quota is shared by every step, so a
                // later step may only spend what earlier steps left.
                output_limit_bytes: Some(
                    prepared_helper
                        .as_ref()
                        .map_or(output_budget, |helper| helper.output_limit()),
                ),
                timeout: Duration::from_secs(process.timeout_seconds.unwrap_or(3_600)),
                termination_grace: config.termination_grace,
            };
            let on_spawn = |process_id| {
                let process_birth_identity = process_birth_identity_for(process_id)
                    .map_err(|error| ExecutionError::SpawnHook(error.to_string()))?;
                match process_birth_identity {
                    Some(identity) => journal.transition_with_process_identity(
                        &organization,
                        &attempt,
                        fence,
                        session_epoch,
                        AttemptPhase::Running,
                        ProcessIdentity {
                            process_id,
                            birth_identity: &identity,
                        },
                    ),
                    None => journal.transition(
                        &organization,
                        &attempt,
                        fence,
                        session_epoch,
                        AttemptPhase::Running,
                        Some(process_id),
                    ),
                }
                .map_err(|error| ExecutionError::SpawnHook(error.to_string()))
            };
            let helper = if index == 0 {
                prepared_helper.as_ref()
            } else {
                None
            };
            let execution = execute_prepared(
                &request,
                execution_cancellation.clone(),
                &attempt_redactions,
                helper,
                on_spawn,
            )
            .await;
            let mut outcome = match execution {
                Ok(outcome) => outcome,
                Err(error) => {
                    if let Some(process_id) = unverified_containment_process_id(&error) {
                        journal.transition(
                            &organization,
                            &attempt,
                            fence,
                            session_epoch,
                            AttemptPhase::ReconciliationRequired,
                            Some(process_id),
                        )?;
                        return Err(AgentError::ExecutionReconciliationRequired {
                            organization: organization.clone(),
                            attempt: attempt.clone(),
                            cause: error.to_string(),
                        });
                    }
                    if requires_processless_reconciliation(&error) {
                        // Containment is proven empty, but the configured root has
                        // lost its pinned identity. Never write result evidence
                        // through an attacker-controlled replacement pathname.
                        journal.transition(
                            &organization,
                            &attempt,
                            fence,
                            session_epoch,
                            AttemptPhase::ReconciliationRequired,
                            None,
                        )?;
                        return Err(AgentError::ExecutionReconciliationRequired {
                            organization: organization.clone(),
                            attempt: attempt.clone(),
                            cause: error.to_string(),
                        });
                    }
                    // One refusal shape for every step that never spawned: a
                    // lease loss keeps its cause, a seed failure its own name,
                    // anything else the spawn error.
                    let spawn_outcome = if matches!(&error, ExecutionError::CancelledBeforeSpawn) {
                        WorkOutcome::Aborted
                    } else {
                        WorkOutcome::Failed
                    };
                    let spawn_reason = match &error {
                        // A controller-requested cancellation is not a lease
                        // loss; only an actual authority loss keeps its cause.
                        ExecutionError::CancelledBeforeSpawn => lease_loss_reason
                            .get()
                            .filter(|cause| **cause != CONTROLLER_CANCELLATION_TRIGGER)
                            .map(|cause| format!("lease_lost_during_execution:{cause}"))
                            .unwrap_or_else(|| "cancelled_before_process_spawn".to_owned()),
                        ExecutionError::WorkspaceTransfer(_) => {
                            format!("workspace_seed_failed:{error}")
                        }
                        _ => bounded_refusal_detail(format!("process_spawn_failed: {error}")),
                    };
                    let spawn_record = StepRecord {
                        ordinal,
                        outcome: outcome_name(spawn_outcome).to_owned(),
                        exit_code: None,
                        termination: "spawn_failed".to_owned(),
                        reason: Some(spawn_reason.clone()),
                    };
                    if index == 0 {
                        // No process ever ran, so this is the processless
                        // completion; a multi-step attempt still records its
                        // ordinal-0 failure so the summary keeps the contract.
                        return finalize_without_process(
                            config,
                            client,
                            &mut journal,
                            ProcesslessCompletion {
                                authority: &assignment.authority,
                                workspace: &assignment.workspace,
                                session_epoch,
                                outcome: spawn_outcome,
                                reason: spawn_reason,
                                steps: if multi_step {
                                    vec![spawn_record]
                                } else {
                                    Vec::new()
                                },
                            },
                            AuthorityRpcControl {
                                authority_lost: &authority_lost,
                                stop: &stop,
                                lease_window,
                            },
                        )
                        .await;
                    }
                    // A later step could not start. The earlier steps ran and
                    // their evidence is journaled below, so this is a failed
                    // step inside a real attempt, not a processless one.
                    step_records.push(spawn_record);
                    break;
                }
            };
            #[cfg(debug_assertions)]
            {
                if helper.is_some()
                    && outcome.private_response_accepted == Some(true)
                    && std::env::var("MCLOVING_TEST_CRASH_AFTER_HELPER_RECEIPT").as_deref()
                        == Ok("1")
                {
                    std::process::exit(87);
                }
                // The exact ambiguity window: the step's process has exited,
                // nothing about that exit is durable yet. A restart from here
                // must report the step interrupted, never re-run it.
                if std::env::var("MCLOVING_TEST_CRASH_AFTER_STEP_EXIT").as_deref()
                    == Ok(ordinal.to_string().as_str())
                {
                    std::process::exit(88);
                }
            }
            if multi_step {
                relocate_step_spool(
                    &config.workspace_root,
                    &assignment.workspace,
                    ordinal,
                    &mut outcome,
                )
                .await?;
            }
            // Journal spool sequences are per attempt, and the executor
            // numbers each execution's streams 0 and 1; give every step its
            // own pair so no step's evidence collides with another's.
            outcome.stdout.sequence = u64::from(ordinal) * 2;
            outcome.stderr.sequence = u64::from(ordinal) * 2 + 1;
            if multi_step {
                // Durable before the next step spawns: a crash while a later
                // step runs must still let recovery publish and reclaim this
                // step's evidence rather than leave it referenced by nothing.
                journal.record_logs(
                    &organization,
                    &attempt,
                    fence,
                    session_epoch,
                    &[outcome.stdout.clone(), outcome.stderr.clone()],
                )?;
            }
            output_budget = output_budget
                .saturating_sub(outcome.stdout.bytes)
                .saturating_sub(outcome.stderr.bytes);
            let step_terminal = match outcome.termination {
                Termination::Cancelled => WorkOutcome::Aborted,
                Termination::TimedOut | Termination::OutputLimitExceeded => WorkOutcome::Failed,
                Termination::Exited if outcome.exit_code == Some(0) => WorkOutcome::Succeeded,
                Termination::Exited => WorkOutcome::Failed,
            };
            logs.push(outcome.stdout.clone());
            logs.push(outcome.stderr.clone());
            step_records.push(StepRecord {
                ordinal,
                outcome: outcome_name(step_terminal).to_owned(),
                exit_code: outcome.exit_code,
                termination: termination_name(outcome.termination).to_owned(),
                reason: None,
            });
            let stop_here = step_terminal != WorkOutcome::Succeeded;
            last_outcome = Some(outcome);
            if stop_here {
                break;
            }
        }
        let outcome = last_outcome.expect("the first step either ran or returned above");
        let last_record = step_records
            .last()
            .expect("every executed step leaves a record");
        validate_log_spool_quota(&logs)?;
        // The attempt's terminal is the last step's, whether that step ran
        // and exited or never spawned; `outcome` is only the last process that
        // ran and must not outrank a later step's refusal to start.
        let mut terminal = match last_record.outcome.as_str() {
            "succeeded" => WorkOutcome::Succeeded,
            "aborted" => WorkOutcome::Aborted,
            _ => WorkOutcome::Failed,
        };
        let helper_failure = (outcome.private_response_accepted == Some(false)).then(|| {
            prepared_helper
                .as_ref()
                .map_or("helper_response_rejected", PreparedHelper::response_failure)
        });
        if helper_failure.is_some() && terminal == WorkOutcome::Succeeded {
            terminal = WorkOutcome::Failed;
        }
        let workspace_transfer = assignment.workspace_grant.as_ref().map(|grant| {
            let (snapshot, error) = match outcome.workspace_snapshot.clone() {
                Some(Ok(snapshot)) => (Some(snapshot), None),
                Some(Err(error)) => (None, Some(error)),
                None => (None, Some("workspace_capture_missing".to_owned())),
            };
            WorkspaceTransferResult {
                version: 1,
                organization_id: grant.organization_id.clone(),
                build_id: grant.build_id.clone(),
                namespace_id: grant.namespace_id.clone(),
                generation: grant.generation,
                input_digest: grant.digest,
                snapshot,
                error,
            }
        });
        let workspace_failure = workspace_transfer
            .as_ref()
            .and_then(|transfer| transfer.error.as_ref())
            .map(|error| format!("workspace_capture_failed:{error}"));
        if workspace_failure.is_some() && terminal == WorkOutcome::Succeeded {
            terminal = WorkOutcome::Failed;
        }
        // A cancellation forced by lease loss is named in the durable result so
        // the replayed terminal summary records why the step was cut short.
        let lease_loss = (outcome.termination == Termination::Cancelled)
            .then(|| lease_loss_reason.get())
            .flatten()
            .filter(|cause| **cause != CONTROLLER_CANCELLATION_TRIGGER)
            .map(|cause| format!("lease_lost_during_execution:{cause}"));
        let step_failure = last_record.reason.clone();
        let result = write_result(
            &config.workspace_root,
            &assignment.workspace,
            DurableResult {
                workspace_transfer: workspace_transfer.as_ref(),
                outcome: terminal,
                exit_code: last_record.exit_code,
                termination: if last_record.termination == "spawn_failed" {
                    "spawn_failed"
                } else {
                    termination_name(outcome.termination)
                },
                // Keep the authority-loss cause primary; capture refusal remains
                // independently recorded in workspace_transfer.error.
                reason: lease_loss
                    .as_deref()
                    .or(workspace_failure.as_deref())
                    .or(helper_failure)
                    .or(step_failure.as_deref()),
                completion_protocol: WORK_COMPLETION_PROTOCOL,
                cancellation_outcome: None,
                steps: if multi_step { &step_records } else { &[] },
            },
        )
        .await?;
        journal.begin_finalization(&Finalization {
            organization_id: &organization,
            attempt_id: &attempt,
            fence_token: fence,
            session_epoch,
            phase: if terminal == WorkOutcome::Aborted {
                AttemptPhase::Cancelling
            } else {
                AttemptPhase::Finalizing
            },
            process_id: Some(outcome.process_id),
            logs: &logs,
            result: &result,
        })?;

        // Terminal truth and every replay input are durable before the first
        // replayable upload. A committed log whose response is lost can therefore
        // be resumed without executing the workload again.
        let mut publication = PublicationContext {
            client,
            authority: &assignment.authority,
            session_epoch,
            control: AuthorityRpcControl {
                authority_lost: &authority_lost,
                stop: &stop,
                lease_window,
            },
        };
        // Inline delivery carries at most one chunk per stream name, which a
        // multi-step attempt has several of; those always stream.
        let mut inline_chunks = (features.inline_terminal_logs && !multi_step).then(Vec::new);
        let mut next_sequence = 0;
        for entry in &logs {
            let (stream, step_ordinal) = spool_stream(entry)?;
            next_sequence = publish_or_inline_spool(
                &mut publication,
                stream,
                step_ordinal,
                &config.workspace_root,
                entry,
                next_sequence,
                inline_chunks.as_mut(),
            )
            .await?;
        }
        let result_content =
            verified_spool_content(&config.workspace_root, &result, "result").await?;
        let persisted: PersistedResult = serde_json::from_slice(&result_content)?;
        let summary = work_completion_summary(&persisted, &result.digest, false)?;
        let completion = authority_rpc(
            publication.control,
            publication.client.complete_work(WorkCompletion {
                authority: Some(assignment.authority.clone()),
                outcome: terminal as i32,
                summary_json: summary,
                inline_log_chunks: inline_chunks.unwrap_or_default(),
            }),
        )
        .await?;
        let published = published_work_outcome(completion, session_epoch)?.unwrap_or(terminal);
        crash_after_terminal_commit_for_test();
        journal_published_terminal(
            &mut journal,
            &organization,
            &attempt,
            fence,
            session_epoch,
            published,
            Some(outcome.process_id),
        )?;
        reclaim_spool_entries(
            config,
            &organization,
            &attempt,
            fence,
            session_epoch,
            &logs,
            Some(&result),
            &assignment.workspace,
        )
        .await?;
        Ok(())
    }
    .await;
    lease_stop.cancel();
    let lease_result = lease_task
        .await
        .map_err(|error| AgentError::InvalidAssignment(format!("lease task failed: {error}")))?;
    completion_result?;
    lease_result
}

fn execution_environment(
    mut environment: BTreeMap<String, String>,
    credentials: Vec<CredentialBinding>,
) -> Result<ExecutionEnvironment, AgentError> {
    if credentials.len() > 8 {
        return Err(AgentError::InvalidAssignment(
            "credential count exceeds the per-attempt bound".to_owned(),
        ));
    }
    let target_names = credentials
        .iter()
        .map(|credential| credential.target_name.clone())
        .collect::<Vec<_>>();
    if !credential_targets_are_valid(&environment, &target_names) {
        return Err(AgentError::InvalidAssignment(
            "credential targets must be unique bounded environment names and must not collide with pipeline environment".to_owned(),
        ));
    }
    let mut grant_ids = std::collections::BTreeSet::new();
    let mut redactions = Vec::with_capacity(credentials.len());
    let mut total_secret_bytes = 0_usize;
    for credential in credentials {
        let grant_id = Uuid::parse_str(&credential.grant_id).map_err(|_| {
            AgentError::InvalidAssignment("credential grant ID is invalid".to_owned())
        })?;
        if !grant_ids.insert(grant_id) {
            return Err(AgentError::InvalidAssignment(
                "credential grant IDs must be unique".to_owned(),
            ));
        }
        if !valid_environment_name(&credential.target_name)
            || credential.secret_value.is_empty()
            || credential.secret_value.len() > 65_536
            || credential.secret_value.contains(&0)
        {
            return Err(AgentError::InvalidAssignment(
                "credential binding is outside its bounds".to_owned(),
            ));
        }
        total_secret_bytes = total_secret_bytes
            .checked_add(credential.secret_value.len())
            .ok_or_else(|| {
                AgentError::InvalidAssignment("credential redaction set is too large".to_owned())
            })?;
        if total_secret_bytes > 65_536 {
            return Err(AgentError::InvalidAssignment(
                "credential redaction set is too large".to_owned(),
            ));
        }
        let secret = String::from_utf8(credential.secret_value.clone()).map_err(|_| {
            AgentError::InvalidAssignment("credential value must be valid UTF-8".to_owned())
        })?;
        if environment.insert(credential.target_name, secret).is_some() {
            return Err(AgentError::InvalidAssignment(
                "credential target collides with the pipeline environment".to_owned(),
            ));
        }
        redactions.push(credential.secret_value);
    }
    Ok(ExecutionEnvironment {
        values: environment,
        redactions,
    })
}

fn valid_environment_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(byte) if byte.is_ascii_alphabetic() || byte == b'_')
        && value.len() <= 128
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn credential_targets_are_valid(
    environment: &BTreeMap<String, String>,
    target_names: &[String],
) -> bool {
    let environment_names = environment
        .keys()
        .map(|name| environment_name_key(name))
        .collect::<std::collections::BTreeSet<_>>();
    let mut targets = std::collections::BTreeSet::new();
    target_names.iter().all(|name| {
        valid_environment_name(name)
            && !reserved_credential_environment_name(name)
            && !environment_names.contains(&environment_name_key(name))
            && targets.insert(environment_name_key(name))
    })
}

#[cfg(windows)]
fn environment_name_key(value: &str) -> String {
    value.to_ascii_uppercase()
}

#[cfg(not(windows))]
fn environment_name_key(value: &str) -> String {
    value.to_owned()
}

#[cfg(windows)]
fn reserved_credential_environment_name(value: &str) -> bool {
    matches!(value.to_ascii_uppercase().as_str(), "TEMP" | "TMP")
}

#[cfg(not(windows))]
fn reserved_credential_environment_name(_value: &str) -> bool {
    false
}

async fn wait_for_credentials(
    client: &mut AgentControlClient<Channel>,
    authority: &WorkAuthority,
    target_names: &[String],
    session_epoch: u64,
    lease_window: Duration,
    execution_cancellation: &CancellationToken,
    authority_lost: &CancellationToken,
) -> Result<Option<Vec<CredentialBinding>>, AgentError> {
    loop {
        let response = tokio::select! {
            () = execution_cancellation.cancelled() => return Ok(None),
            () = authority_lost.cancelled() => return Err(AgentError::StaleAuthority),
            response = tokio::time::timeout(
                lease_rpc_budget(lease_window),
                client.fetch_credentials(CredentialRequest {
                    authority: Some(authority.clone()),
                    target_names: target_names.to_vec(),
                }),
            ) => match response {
                Ok(Ok(response)) => response.into_inner(),
                Err(_) => {
                    if !wait_for_authority_retry(execution_cancellation, authority_lost).await? {
                        return Ok(None);
                    }
                    continue;
                }
                Ok(Err(status)) if retryable_authority_transition(&status) => {
                    if !wait_for_authority_retry(execution_cancellation, authority_lost).await? {
                        return Ok(None);
                    }
                    continue;
                }
                Ok(Err(status)) => return Err(AgentError::Rpc(status)),
            },
        };
        ensure_session(response.session_epoch, session_epoch)?;
        if response.ready {
            return Ok(Some(response.credentials));
        }
        if !wait_for_authority_retry(execution_cancellation, authority_lost).await? {
            return Ok(None);
        }
    }
}

async fn start_work_with_retry(
    client: &mut AgentControlClient<Channel>,
    authority: &WorkAuthority,
    session_epoch: u64,
    lease_window: Duration,
    execution_cancellation: &CancellationToken,
    authority_lost: &CancellationToken,
    stop: &CancellationToken,
) -> Result<Option<WorkReceipt>, AgentError> {
    loop {
        let response = tokio::select! {
            biased;
            () = execution_cancellation.cancelled() => return Ok(None),
            () = authority_lost.cancelled() => return Err(AgentError::StaleAuthority),
            () = stop.cancelled() => return Err(AgentError::Stopped),
            response = tokio::time::timeout(
                lease_rpc_budget(lease_window),
                client.start_work(authority.clone()),
            ) => match response {
                Ok(Ok(response)) => response.into_inner(),
                Err(_) => {
                    if !wait_for_authority_retry(execution_cancellation, authority_lost).await? {
                        return Ok(None);
                    }
                    continue;
                }
                Ok(Err(status)) if retryable_authority_transition(&status) => {
                    if !wait_for_authority_retry(execution_cancellation, authority_lost).await? {
                        return Ok(None);
                    }
                    continue;
                }
                Ok(Err(status)) => return Err(AgentError::Rpc(status)),
            },
        };
        require_work_receipt(response, session_epoch)?;
        return Ok(Some(response));
    }
}

async fn wait_for_authority_retry(
    execution_cancellation: &CancellationToken,
    authority_lost: &CancellationToken,
) -> Result<bool, AgentError> {
    tokio::select! {
        () = execution_cancellation.cancelled() => Ok(false),
        () = authority_lost.cancelled() => Err(AgentError::StaleAuthority),
        () = tokio::time::sleep(Duration::from_millis(250)) => Ok(true),
    }
}

fn retryable_authority_transition(status: &tonic::Status) -> bool {
    matches!(
        status.code(),
        tonic::Code::Cancelled
            | tonic::Code::Unknown
            | tonic::Code::DeadlineExceeded
            | tonic::Code::ResourceExhausted
            | tonic::Code::Aborted
            | tonic::Code::Internal
            | tonic::Code::Unavailable
    )
}

fn unverified_containment_process_id(error: &ExecutionError) -> Option<u32> {
    match error {
        ExecutionError::ContainmentUnverified { process_id, .. } => Some(*process_id),
        _ => None,
    }
}

fn requires_processless_reconciliation(error: &ExecutionError) -> bool {
    matches!(error, ExecutionError::ReplacedWorkspaceRoot)
}

async fn renew_lease(
    mut client: AgentControlClient<Channel>,
    authority: WorkAuthority,
    control: LeaseRenewalControl,
) -> Result<(), AgentError> {
    let LeaseRenewalControl {
        lease_seconds,
        renewal_interval,
        lease_started_at,
        lease_window,
        termination_grace,
        execution_cancellation,
        authority_lost,
        stop,
        loss_reason,
    } = control;
    let mut lease_started_at = lease_started_at;
    let mut lease_window = lease_window;
    let retry_interval = renewal_retry_interval(renewal_interval);
    loop {
        // Start cancellation early enough to finish graceful termination and
        // send SIGKILL before reclamation. The wake itself must obey this bound:
        // a long cadence must not sleep through the reserved termination time.
        let lease_deadline =
            lease_cancellation_deadline(lease_started_at, lease_window, termination_grace);
        tokio::select! {
            () = stop.cancelled() => return Ok(()),
            () = tokio::time::sleep_until(
                (lease_started_at + renewal_interval).min(lease_deadline)
            ) => {}
        }
        if tokio::time::Instant::now() >= lease_deadline {
            if stop.is_cancelled() {
                return Ok(());
            }
            record_lease_loss(&loss_reason, "renewal_unanswered_until_expiry");
            execution_cancellation.cancel();
            authority_lost.cancel();
            return Err(AgentError::LeaseRenewalTimeout);
        }
        // Fix this allowance for the whole retry cycle: one pending response
        // may use at most half the initially remaining execution budget. Reuse
        // that duration rather than halving on every retry near the deadline.
        let response_budget = Duration::from_secs(1)
            .min(lease_deadline.saturating_duration_since(tokio::time::Instant::now()) / 2);
        // A long configured cadence must not sleep through the time reserved
        // for a second ask. Ordinary held terms keep their configured cadence.
        let retry_interval = retry_interval.min(response_budget);
        let mut unanswered: u64 = 0;
        // Carried out of the loop with the receipt: the term a successful
        // renewal opens is measured from the moment THAT request left, so the
        // agent's deadline stays before the controller's stamp however slow the
        // round trip is.
        let (receipt, request_sent_at) = loop {
            let request_sent_at = tokio::time::Instant::now();
            if request_sent_at >= lease_deadline {
                if stop.is_cancelled() {
                    return Ok(());
                }
                record_lease_loss(&loss_reason, "renewal_unanswered_until_expiry");
                execution_cancellation.cancel();
                authority_lost.cancel();
                return Err(AgentError::LeaseRenewalTimeout);
            }
            // A connected peer may keep one RPC pending through its outage.
            // Bound each ask independently so it cannot consume the entire
            // held term and prevent a later request from observing recovery.
            // Keep the allowance independent of a fast renewal cadence while
            // leaving room for another ask even in a short usable term.
            let rpc_deadline = (request_sent_at + response_budget).min(lease_deadline);
            let renewal = tokio::select! {
                () = stop.cancelled() => return Ok(()),
                result = tokio::time::timeout_at(
                    rpc_deadline,
                    client.renew_work_lease(WorkLeaseRenewal {
                        authority: Some(authority.clone()),
                        lease_seconds,
                    }),
                ) => result,
            };
            // A stop request makes any concurrent renewal failure moot: the
            // attempt is already finalized and the session must not be torn
            // down over a lease this task was told to release. The failure arms
            // below re-check because the select above is unbiased and the RPC
            // may have failed in the same poll that observed the stop.
            match renewal {
                Ok(Ok(response)) => {
                    if unanswered > 0 {
                        eprintln!(
                            "renewal_answered_again: the controller answered after \
                             {unanswered} unanswered attempt(s); the step kept running \
                             on the lease it already held"
                        );
                    }
                    break (response.into_inner(), request_sent_at);
                }
                Ok(Err(error)) => {
                    if stop.is_cancelled() {
                        return Ok(());
                    }
                    if !renewal_went_unanswered(&error) {
                        record_lease_loss(&loss_reason, renewal_status_cause(&error));
                        execution_cancellation.cancel();
                        authority_lost.cancel();
                        return Err(error.into());
                    }
                    if unanswered == 0 {
                        eprintln!(
                            "renewal_unanswered: {}: {}; authority is not withdrawn by \
                             an answer that never arrived, so the step keeps running \
                             and the renewal is retried every {retry_interval:?} until \
                             the held lease lapses",
                            error.code(),
                            error.message(),
                        );
                    }
                    unanswered = unanswered.saturating_add(1);
                }
                // Only this ask expired; the unchanged term deadline below
                // decides whether any authority remains for another request.
                Err(_) => {
                    if stop.is_cancelled() {
                        return Ok(());
                    }
                    if unanswered == 0 {
                        eprintln!(
                            "renewal_unanswered: RPC timed out; retrying within the held lease"
                        );
                    }
                    unanswered = unanswered.saturating_add(1);
                }
            }
            let now = tokio::time::Instant::now();
            // Count time spent awaiting the RPC toward the cadence. A timed-out
            // ask must not incur another whole interval before the next ask.
            let retry_delay = (request_sent_at + retry_interval).saturating_duration_since(now);
            let Some(retry_at) = next_renewal_retry(now, lease_deadline, retry_delay) else {
                if stop.is_cancelled() {
                    return Ok(());
                }
                record_lease_loss(&loss_reason, "renewal_unanswered_until_expiry");
                execution_cancellation.cancel();
                authority_lost.cancel();
                return Err(AgentError::LeaseRenewalTimeout);
            };
            tokio::select! {
                () = stop.cancelled() => return Ok(()),
                () = tokio::time::sleep_until(retry_at) => {}
            }
        };
        match ensure_session(receipt.session_epoch, authority.session_epoch) {
            Ok(()) => {}
            Err(error) => {
                if stop.is_cancelled() {
                    return Ok(());
                }
                record_lease_loss(&loss_reason, "renewal_session_stale");
                execution_cancellation.cancel();
                authority_lost.cancel();
                return Err(error);
            }
        }
        if !receipt.accepted {
            if stop.is_cancelled() {
                return Ok(());
            }
            record_lease_loss(
                &loss_reason,
                renewal_rejection_cause(&receipt.rejection_cause),
            );
            execution_cancellation.cancel();
            authority_lost.cancel();
            return Err(AgentError::StaleAuthority);
        }
        if receipt.cancellation_requested {
            // The controller's cancellation is the terminating trigger; claim
            // the slot so a renewal failure observed while the process is
            // already being terminated cannot relabel the cause as lease loss.
            let _ = loss_reason.set(CONTROLLER_CANCELLATION_TRIGGER);
            execution_cancellation.cancel();
        }
        lease_started_at = request_sent_at;
        lease_window = Duration::from_secs(u64::from(lease_seconds));
    }
}

/// Whether the accepting handshake consumed enough of the claim lease that
/// the periodic renewal cadence can no longer be trusted to re-arm it before
/// the worst-case expiry: the claim instant — taken before the poll RPC was
/// sent, so the estimate errs early — plus the lease window, minus the
/// codebase's one-second safety margin. In that near-expiry case the folded
/// accept path falls back to the serialized pre-feature renewal so a
/// workload never spawns on a lease the reaper may already be fencing; a
/// background renewal scheduled early instead would still race the reaper
/// while the process runs.
fn accept_consumed_claim_lease(
    claimed_no_later_than: tokio::time::Instant,
    lease_window: Duration,
    accepted_at: tokio::time::Instant,
    renewal_interval: Duration,
) -> bool {
    claimed_no_later_than + lease_window.saturating_sub(Duration::from_secs(1))
        < accepted_at + renewal_interval
}

pub(super) fn execution_lease_budget(
    lease_window: Duration,
    termination_grace: Duration,
) -> Duration {
    lease_rpc_budget(lease_window).saturating_sub(termination_grace)
}

/// Cancellation must begin with the complete termination grace still inside
/// the term. This is the cancellation deadline, not proof of process death;
/// the shipped-runtime gate independently observes quiescence before expiry.
fn lease_cancellation_deadline(
    lease_started_at: tokio::time::Instant,
    lease_window: Duration,
    termination_grace: Duration,
) -> tokio::time::Instant {
    lease_started_at + execution_lease_budget(lease_window, termination_grace)
}

pub(super) fn lease_rpc_budget(lease_window: Duration) -> Duration {
    lease_window.saturating_sub(Duration::from_secs(1))
}

async fn lease_window_rpc<T>(
    lease_window: Duration,
    operation: impl Future<Output = Result<tonic::Response<T>, tonic::Status>>,
) -> Result<T, AgentError> {
    lease_deadline_rpc(
        tokio::time::Instant::now() + lease_rpc_budget(lease_window),
        operation,
    )
    .await
}

async fn lease_deadline_rpc<T>(
    deadline: tokio::time::Instant,
    operation: impl Future<Output = Result<tonic::Response<T>, tonic::Status>>,
) -> Result<T, AgentError> {
    tokio::time::timeout_at(deadline, operation)
        .await
        .map_err(|_| AgentError::LeaseRenewalTimeout)?
        .map(tonic::Response::into_inner)
        .map_err(AgentError::from)
}

async fn poll_rpc<T>(
    lease_window: Duration,
    operation: impl Future<Output = Result<tonic::Response<T>, tonic::Status>>,
) -> Result<T, AgentError> {
    tokio::time::timeout(lease_rpc_budget(lease_window), operation)
        .await
        .map_err(|_| AgentError::PollTimeout)?
        .map(tonic::Response::into_inner)
        .map_err(AgentError::from)
}

async fn authority_rpc<T>(
    control: AuthorityRpcControl<'_>,
    operation: impl Future<Output = Result<tonic::Response<T>, tonic::Status>>,
) -> Result<T, AgentError> {
    tokio::select! {
        biased;
        () = control.authority_lost.cancelled() => Err(AgentError::StaleAuthority),
        () = control.stop.cancelled() => Err(AgentError::Stopped),
        result = tokio::time::timeout(lease_rpc_budget(control.lease_window), operation) => {
            result
                .map_err(|_| AgentError::AuthorityRpcTimeout)?
                .map(tonic::Response::into_inner)
                .map_err(AgentError::from)
        },
    }
}

/// Publishes one spooled log stream, riding the terminal publication when it
/// can: a stream that fits a single chunk is verified exactly like the
/// streamed form and then carried in `WorkCompletion.inline_log_chunks`
/// (`inline` is `Some` only when inline-terminal-logs-v1 was negotiated),
/// sparing its `PublishLog` round trip. Anything larger — or any stream when
/// the peer never negotiated the feature — goes through `publish_spool`
/// unchanged. Returns the next unused sequence either way, so mixed streams
/// number identically to the fully streamed form.
async fn publish_or_inline_spool(
    publication: &mut PublicationContext<'_>,
    stream: &str,
    step_ordinal: u32,
    workspace_root: &Path,
    entry: &SpoolEntry,
    first_sequence: u64,
    inline: Option<&mut Vec<InlineLogChunk>>,
) -> Result<u64, AgentError> {
    let single_chunk = entry.bytes <= MAX_LOG_CHUNK_BYTES as u64;
    let Some(chunks) = inline.filter(|_| single_chunk) else {
        return publish_spool(
            publication,
            stream,
            step_ordinal,
            workspace_root,
            entry,
            first_sequence,
        )
        .await;
    };
    if entry.bytes > MAX_ATTEMPT_OUTPUT_BYTES {
        return Err(AgentError::InvalidAssignment(
            "durable log spool exceeds the per-attempt quota".to_owned(),
        ));
    }
    // One pass reads, sizes, and digests the stream: the bytes that ride the
    // completion are exactly the bytes that were hashed against the journaled
    // descriptor, so a separate verification read would re-check the same
    // buffer.
    let path = workspace_root.join(&entry.relative_path);
    let mut file = fs::File::open(path).await?;
    let expected = usize::try_from(entry.bytes).map_err(|_| {
        AgentError::InvalidAssignment("log length exceeds platform bounds".to_owned())
    })?;
    let mut content = Vec::with_capacity(expected.saturating_add(1));
    // Bounded to one byte past the journaled size: enough to detect growth,
    // never enough to let an oversized on-disk file dictate the allocation.
    (&mut file)
        .take(entry.bytes.saturating_add(1))
        .read_to_end(&mut content)
        .await?;
    if content.len() != expected || <[u8; 32]>::from(Sha256::digest(&content)) != entry.digest {
        return Err(AgentError::InvalidAssignment(
            "durable log spool metadata does not match its content".to_owned(),
        ));
    }
    // An empty stream carries no evidence and must consume neither a log row
    // nor a sequence number. It is still authenticated by the bounded read
    // above before the terminal publication references its descriptor.
    if content.is_empty() {
        return Ok(first_sequence);
    }
    if first_sequence >= MAX_LOG_CHUNKS_PER_ATTEMPT {
        return Err(AgentError::InvalidAssignment(
            "log chunk count exceeds the per-attempt quota".to_owned(),
        ));
    }
    chunks.push(InlineLogChunk {
        sequence: first_sequence,
        stream: stream.to_owned(),
        content,
        step_ordinal,
    });
    first_sequence
        .checked_add(1)
        .ok_or_else(|| AgentError::InvalidAssignment("log sequence exceeds wire bounds".to_owned()))
}

async fn publish_spool(
    publication: &mut PublicationContext<'_>,
    stream: &str,
    step_ordinal: u32,
    workspace_root: &Path,
    entry: &SpoolEntry,
    first_sequence: u64,
) -> Result<u64, AgentError> {
    if entry.bytes > MAX_ATTEMPT_OUTPUT_BYTES {
        return Err(AgentError::InvalidAssignment(
            "durable log spool exceeds the per-attempt quota".to_owned(),
        ));
    }
    let path = workspace_root.join(&entry.relative_path);
    verify_spool_file(&path, entry, "log").await?;
    let mut file = fs::File::open(path).await?;
    let mut buffer = vec![0_u8; MAX_LOG_CHUNK_BYTES];
    let mut sequence = first_sequence;
    let mut remaining = entry.bytes;
    while remaining > 0 {
        let read_limit =
            usize::try_from(remaining.min(MAX_LOG_CHUNK_BYTES as u64)).map_err(|_| {
                AgentError::InvalidAssignment("log length exceeds platform bounds".to_owned())
            })?;
        let bytes = file.read(&mut buffer[..read_limit]).await?;
        if bytes == 0 {
            return Err(AgentError::InvalidAssignment(
                "durable log spool became shorter after verification".to_owned(),
            ));
        }
        if sequence >= MAX_LOG_CHUNKS_PER_ATTEMPT {
            return Err(AgentError::InvalidAssignment(
                "log chunk count exceeds the per-attempt quota".to_owned(),
            ));
        }
        require_work_receipt(
            authority_rpc(
                publication.control,
                publication.client.publish_log(WorkLogChunk {
                    authority: Some(publication.authority.clone()),
                    sequence,
                    stream: stream.to_owned(),
                    content: buffer[..bytes].to_vec(),
                    step_ordinal,
                }),
            )
            .await?,
            publication.session_epoch,
        )?;
        remaining = remaining
            .checked_sub(u64::try_from(bytes).map_err(|_| {
                AgentError::InvalidAssignment("log length exceeds wire bounds".to_owned())
            })?)
            .ok_or_else(|| {
                AgentError::InvalidAssignment("log length exceeds wire bounds".to_owned())
            })?;
        sequence = sequence.checked_add(1).ok_or_else(|| {
            AgentError::InvalidAssignment("log sequence exceeds wire bounds".to_owned())
        })?;
    }
    let mut growth_probe = [0_u8; 1];
    if file.read(&mut growth_probe).await? != 0 {
        return Err(AgentError::InvalidAssignment(
            "durable log spool grew after verification".to_owned(),
        ));
    }
    Ok(sequence)
}

async fn verified_spool_content(
    workspace_root: &Path,
    entry: &SpoolEntry,
    kind: &str,
) -> Result<Vec<u8>, AgentError> {
    if entry.bytes > MAX_RESULT_SPOOL_BYTES {
        return Err(AgentError::InvalidAssignment(format!(
            "durable {kind} spool exceeds its quota"
        )));
    }
    let path = workspace_root.join(&entry.relative_path);
    verify_spool_file(&path, entry, kind).await?;
    let content = fs::read(path).await?;
    Ok(content)
}

pub(super) async fn reclaim_terminal_spools(config: &AgentConfig) -> Result<(), AgentError> {
    let attempts = Journal::open(&config.journal_path)?
        .terminal_spools()?
        .attempts;
    for attempt in &attempts {
        reclaim_attempt_spools(config, attempt).await?;
    }
    Ok(())
}

async fn reclaim_attempt_spools(
    config: &AgentConfig,
    attempt: &mcloving_agent_runtime::ReconciliationAttempt,
) -> Result<(), AgentError> {
    reclaim_spool_entries(
        config,
        &attempt.organization_id,
        &attempt.attempt_id,
        attempt.fence_token,
        attempt.session_epoch,
        &attempt.logs,
        attempt.result.as_ref(),
        &attempt.workspace,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn reclaim_spool_entries(
    config: &AgentConfig,
    organization_id: &str,
    attempt_id: &str,
    fence_token: u64,
    session_epoch: u64,
    logs: &[SpoolEntry],
    result: Option<&SpoolEntry>,
    workspace: &Path,
) -> Result<(), AgentError> {
    // Remove the attempt root first. Log entries live below it, and a workload
    // may have replaced that root after containment. Cleanup must never follow
    // such a replacement while trying to reach an individual log.
    let mut changed = remove_attempt_workspace(&config.workspace_root, workspace).await?;
    for entry in logs.iter().chain(result) {
        changed.extend(remove_spool_file(&config.workspace_root, entry).await?);
    }
    // The relocated step spools of a multi-step attempt sit in one fixed
    // directory. Every journaled entry below it was acknowledged before this
    // point, and anything the journal never learned about is exactly the
    // crash-window orphan this removal exists for.
    changed.extend(
        remove_terminal_relative_path(&config.workspace_root, &step_spool_area(workspace)).await?,
    );
    flush_terminal_cleanup(&config.workspace_root, workspace, changed).await?;
    Journal::open(&config.journal_path)?.retire_terminal_spools(
        organization_id,
        attempt_id,
        fence_token,
        session_epoch,
    )?;
    Ok(())
}

async fn remove_attempt_workspace(
    workspace_root: &Path,
    workspace: &Path,
) -> Result<Vec<PathBuf>, AgentError> {
    if workspace.as_os_str().is_empty()
        || workspace.is_absolute()
        || workspace
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(AgentError::InvalidAssignment(
            "terminal workspace must be normalized and relative".to_owned(),
        ));
    }
    remove_terminal_relative_path(workspace_root, workspace).await
}

async fn remove_spool_file(
    workspace_root: &Path,
    entry: &SpoolEntry,
) -> Result<Vec<PathBuf>, AgentError> {
    if entry.relative_path.is_absolute()
        || entry
            .relative_path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(AgentError::InvalidAssignment(
            "terminal spool path must be normalized and relative".to_owned(),
        ));
    }
    remove_terminal_relative_path(workspace_root, &entry.relative_path).await
}

/// Removes one terminal path, returning the directories whose entry lists
/// changed and that still exist — the durability boundaries its caller
/// flushes once, before retiring the descriptors that referenced the path.
async fn remove_terminal_relative_path(
    workspace_root: &Path,
    relative_path: &Path,
) -> Result<Vec<PathBuf>, AgentError> {
    remove_runtime_terminal_path(workspace_root, relative_path)
        .await
        .map_err(Into::into)
}

async fn restore_directory_access(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        let mut permissions = metadata.permissions();
        permissions.set_mode(permissions.mode() | 0o700);
        fs::set_permissions(path, permissions).await
    }
    #[cfg(not(unix))]
    {
        let _ = (path, metadata);
        Ok(())
    }
}

async fn verify_spool_file(path: &Path, entry: &SpoolEntry, kind: &str) -> Result<(), AgentError> {
    let mut file = fs::File::open(path).await?;
    // A read buffer, not a chunk: 64 KiB digests just as fast without a
    // megabyte of zeroed allocation per verification.
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut digest = Sha256::new();
    let mut bytes = 0_u64;
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        bytes = bytes
            .checked_add(u64::try_from(read).map_err(|_| {
                AgentError::InvalidAssignment("spool size exceeds wire bounds".to_owned())
            })?)
            .ok_or_else(|| {
                AgentError::InvalidAssignment("spool size exceeds wire bounds".to_owned())
            })?;
        digest.update(&buffer[..read]);
    }
    let calculated: [u8; 32] = digest.finalize().into();
    if calculated != entry.digest || bytes != entry.bytes {
        return Err(AgentError::InvalidAssignment(format!(
            "durable {kind} spool metadata does not match its content"
        )));
    }
    Ok(())
}

fn validate_log_spool_quota(entries: &[SpoolEntry]) -> Result<(), AgentError> {
    let total = entries.iter().try_fold(0_u64, |total, entry| {
        total.checked_add(entry.bytes).ok_or_else(|| {
            AgentError::InvalidAssignment("durable log spool exceeds its quota".to_owned())
        })
    })?;
    if total > MAX_ATTEMPT_OUTPUT_BYTES {
        return Err(AgentError::InvalidAssignment(
            "durable log spool exceeds its per-attempt quota".to_owned(),
        ));
    }
    Ok(())
}

/// Reads a journaled spool's stream name and step ordinal back from its path:
/// `spool/{stdout,stderr}.log` is the single-step layout (ordinal zero), and
/// `spool/step-N/{stdout,stderr}.log` is step N of a multi-step attempt.
fn spool_stream(entry: &SpoolEntry) -> Result<(&'static str, u32), AgentError> {
    let stream = match entry
        .relative_path
        .file_name()
        .and_then(|name| name.to_str())
    {
        Some("stdout.log") => "stdout",
        Some("stderr.log") => "stderr",
        _ => {
            return Err(AgentError::InvalidAssignment(
                "journal log spool has an unknown stream path".to_owned(),
            ));
        }
    };
    let parent = entry
        .relative_path
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str());
    let ordinal = match parent {
        Some("spool") => 0,
        Some(step) => step
            .strip_prefix("step-")
            .and_then(|digits| digits.parse::<u32>().ok())
            .filter(|ordinal| *ordinal < mcloving_domain::multi_step::MAX_STEP_ORDINAL_EXCLUSIVE)
            .ok_or_else(|| {
                AgentError::InvalidAssignment(
                    "journal log spool has an unknown step directory".to_owned(),
                )
            })?,
        None => {
            return Err(AgentError::InvalidAssignment(
                "journal log spool has no spool directory".to_owned(),
            ));
        }
    };
    Ok((stream, ordinal))
}

async fn write_result(
    workspace_root: &Path,
    workspace: &Path,
    result: DurableResult<'_>,
) -> Result<SpoolEntry, AgentError> {
    let DurableResult {
        workspace_transfer,
        outcome,
        exit_code,
        termination,
        reason,
        completion_protocol,
        cancellation_outcome,
        steps,
    } = result;
    let relative_parent = PathBuf::from(AGENT_RESULT_DIRECTORY)
        .join(workspace)
        .join(Uuid::new_v4().simple().to_string());
    let (parent, changed_parents) =
        create_result_directory(workspace_root, &relative_parent).await?;
    let relative_path = relative_parent.join("result.json");
    let path = parent.join("result.json");
    let mut value = json!({
        "outcome": outcome_name(outcome),
        "exit_code": exit_code,
        "termination": termination,
        "reason": reason,
        "completion_protocol": completion_protocol,
        "cancellation_outcome": cancellation_outcome,
    });
    if !steps.is_empty() {
        value["steps"] = serde_json::to_value(steps)?;
    }
    if let Some(transfer) = workspace_transfer {
        transfer
            .validate()
            .map_err(|error| AgentError::InvalidAssignment(error.to_string()))?;
        value["workspace_transfer"] = serde_json::to_value(transfer)?;
    }
    let content = serde_json::to_vec(&value)?;
    if content.len() > MAX_RESULT_SPOOL_BYTES as usize {
        return Err(AgentError::InvalidAssignment(
            "result spool exceeds its quota".to_owned(),
        ));
    }
    match fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .await
    {
        Ok(mut file) => {
            file.write_all(&content).await?;
            // The barrier the finalization journal record depends on: the
            // result payload, the directory entry that names it, and each
            // newly created ancestor's parent entry, durable before this
            // returns. Pre-existing ancestors were made durable by the
            // attempt that created them and their entry lists did not
            // change, so only the parents that gained an entry flush — as
            // one batch, since the entries are independent of one another.
            let file = file.into_std().await;
            let mut boundaries = changed_parents;
            boundaries.push(parent.clone());
            tokio::task::spawn_blocking(move || sync_boundaries(&[&file], &boundaries))
                .await
                .map_err(|error| {
                    AgentError::InvalidAssignment(format!("durability flush failed: {error}"))
                })??;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if fs::read(&path).await? != content {
                return Err(AgentError::InvalidAssignment(
                    "durable result spool conflicts with replay evidence".to_owned(),
                ));
            }
        }
        Err(error) => return Err(error.into()),
    }
    Ok(SpoolEntry {
        sequence: 0,
        relative_path,
        digest: Sha256::digest(&content).into(),
        bytes: u64::try_from(content.len()).map_err(|_| {
            AgentError::InvalidAssignment("result length exceeds wire bounds".to_owned())
        })?,
    })
}

/// Moves a finished step's spool directory out of the workload-visible
/// workspace into the agent-owned result area (PAR-010). Every later step runs
/// with the same workspace as its working directory, so a cleanup such as
/// `rm -rf spool` in step N would otherwise destroy step N-1's already-hashed
/// evidence and leave finalization unable to publish. The move is a rename
/// within the workspace root, so the hashed bytes are untouched, and both
/// directory entries are flushed before the journal may reference the new
/// path. A hostile same-UID workload can still reach the result area by
/// absolute path; that remains SEC-005.
async fn relocate_step_spool(
    workspace_root: &Path,
    workspace: &Path,
    ordinal: u32,
    outcome: &mut mcloving_agent_runtime::executor::ExecutionOutcome,
) -> Result<(), AgentError> {
    // Deterministic, not random: terminal reclaim removes this whole
    // directory whether or not the journal references what is inside, so a
    // crash between the rename below and the journal write that follows it
    // orphans nothing.
    let relative_parent = step_spool_area(workspace);
    let (parent, changed_parents) =
        create_result_directory(workspace_root, &relative_parent).await?;
    let step_directory = format!("step-{ordinal}");
    let attempt_spool = workspace_root.join(workspace).join("spool");
    let source = attempt_spool.join(&step_directory);
    let destination = parent.join(&step_directory);
    let source_metadata = fs::symlink_metadata(&source).await?;
    if !source_metadata.is_dir() || is_link_or_reparse_point(&source_metadata) {
        return Err(AgentError::InvalidAssignment(
            "step spool directory was replaced before relocation".to_owned(),
        ));
    }
    fs::rename(&source, &destination).await?;
    let mut boundaries = changed_parents;
    boundaries.push(parent);
    boundaries.push(attempt_spool);
    tokio::task::spawn_blocking(move || {
        mcloving_agent_runtime::executor::sync_directories(&boundaries)
    })
    .await
    .map_err(|error| {
        AgentError::InvalidAssignment(format!("durability flush failed: {error}"))
    })??;
    let relative_step = relative_parent.join(&step_directory);
    outcome.stdout.relative_path = relative_step.join("stdout.log");
    outcome.stderr.relative_path = relative_step.join("stderr.log");
    Ok(())
}

/// Where a multi-step attempt's finished step spools live once relocated:
/// one fixed directory per attempt workspace, so cleanup can find it without
/// the journal.
fn step_spool_area(workspace: &Path) -> PathBuf {
    PathBuf::from(AGENT_RESULT_DIRECTORY)
        .join(workspace)
        .join("steps")
}

async fn create_result_directory(
    workspace_root: &Path,
    relative_parent: &Path,
) -> Result<(PathBuf, Vec<PathBuf>), AgentError> {
    if relative_parent.is_absolute()
        || relative_parent
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(AgentError::InvalidAssignment(
            "result spool parent must be normalized and relative".to_owned(),
        ));
    }
    fs::create_dir_all(workspace_root).await?;
    let root_metadata = fs::symlink_metadata(workspace_root).await?;
    if !root_metadata.is_dir() || is_link_or_reparse_point(&root_metadata) {
        return Err(AgentError::InvalidAssignment(
            "workspace root is a non-directory, symlink, or reparse point".to_owned(),
        ));
    }
    restore_directory_access(workspace_root, &root_metadata).await?;

    let mut directory = workspace_root.to_owned();
    let mut changed_parents = Vec::new();
    for component in relative_parent.components() {
        let Component::Normal(component) = component else {
            unreachable!("relative result parent was validated above");
        };
        let parent = directory.clone();
        directory.push(component);
        match fs::create_dir(&directory).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        // The parent is flushed whether this walk created the component or
        // found it: a component left by a predecessor that failed before its
        // own barrier has no durable entry, and treating existence as
        // durability would let this attempt's final barrier skip it.
        changed_parents.push(parent);
        let metadata = fs::symlink_metadata(&directory).await?;
        if !metadata.is_dir() || is_link_or_reparse_point(&metadata) {
            return Err(AgentError::InvalidAssignment(
                "result spool parent contains a non-directory, symlink, or reparse point"
                    .to_owned(),
            ));
        }
        restore_directory_access(&directory, &metadata).await?;
    }
    let canonical_root = fs::canonicalize(workspace_root).await?;
    let canonical_parent = fs::canonicalize(&directory).await?;
    if !canonical_parent.starts_with(&canonical_root) {
        return Err(AgentError::InvalidAssignment(
            "result spool parent escapes the workspace root".to_owned(),
        ));
    }
    Ok((canonical_parent, changed_parents))
}

pub(super) async fn persist_recovered_cancellation(
    config: &AgentConfig,
    journal: &mut Journal,
    attempt: &mcloving_agent_runtime::ReconciliationAttempt,
    cancellation_outcome: i32,
) -> Result<(), AgentError> {
    // A multi-step attempt names the step it was cut off in. The journal
    // recorded that step's start before its spawn and nothing about its exit,
    // so recovery can only report it interrupted: never re-run, never skipped.
    let interrupted_step = attempt
        .current_step
        .map(|ordinal| format!("interrupted_at_step:{ordinal}"));
    let result = write_result(
        &config.workspace_root,
        &attempt.workspace,
        DurableResult {
            workspace_transfer: None,
            outcome: WorkOutcome::Aborted,
            exit_code: None,
            termination: "recovered_cancellation",
            reason: interrupted_step.as_deref(),
            completion_protocol: CANCELLATION_COMPLETION_PROTOCOL,
            cancellation_outcome: Some(cancellation_outcome),
            steps: &[],
        },
    )
    .await?;
    journal.begin_finalization(&Finalization {
        organization_id: &attempt.organization_id,
        attempt_id: &attempt.attempt_id,
        fence_token: attempt.fence_token,
        session_epoch: attempt.session_epoch,
        phase: AttemptPhase::Cancelling,
        process_id: attempt.process_id,
        logs: &attempt.logs,
        result: &result,
    })?;
    Ok(())
}

pub(super) async fn recovered_cancellation_requires_persistence(
    config: &AgentConfig,
    attempt: &mcloving_agent_runtime::ReconciliationAttempt,
) -> Result<bool, AgentError> {
    let Some(result) = recovered_persisted_result(config, attempt).await? else {
        return Ok(true);
    };
    match result.completion_protocol.as_str() {
        // A stale-fence cancellation retires this local authority; it must not
        // replace the immutable evidence of the work that already completed.
        WORK_COMPLETION_PROTOCOL => Ok(false),
        // Cancellation evidence was already committed atomically with this
        // journal phase and is equally immutable.
        CANCELLATION_COMPLETION_PROTOCOL => Ok(false),
        _ => Err(AgentError::InvalidAssignment(
            "durable result has an unknown completion protocol".to_owned(),
        )),
    }
}

pub(super) async fn recovered_attempt_has_durable_containment_proof(
    config: &AgentConfig,
    attempt: &mcloving_agent_runtime::ReconciliationAttempt,
) -> Result<bool, AgentError> {
    if !matches!(
        attempt.phase,
        AttemptPhase::Finalizing | AttemptPhase::Cancelling
    ) {
        return Ok(false);
    }
    let Some(result) = recovered_persisted_result(config, attempt).await? else {
        return Ok(false);
    };
    match result.completion_protocol.as_str() {
        WORK_COMPLETION_PROTOCOL | CANCELLATION_COMPLETION_PROTOCOL => Ok(true),
        _ => Err(AgentError::InvalidAssignment(
            "durable result has an unknown completion protocol".to_owned(),
        )),
    }
}

async fn recovered_persisted_result(
    config: &AgentConfig,
    attempt: &mcloving_agent_runtime::ReconciliationAttempt,
) -> Result<Option<PersistedResult>, AgentError> {
    let Some(result_entry) = &attempt.result else {
        return Ok(None);
    };
    let content = verified_spool_content(&config.workspace_root, result_entry, "result").await?;
    Ok(Some(serde_json::from_slice(&content)?))
}

async fn finalize_without_process(
    config: &AgentConfig,
    client: &mut AgentControlClient<Channel>,
    journal: &mut Journal,
    completion: ProcesslessCompletion<'_>,
    control: AuthorityRpcControl<'_>,
) -> Result<(), AgentError> {
    let ProcesslessCompletion {
        authority,
        workspace,
        session_epoch,
        outcome,
        reason,
        steps,
    } = completion;
    let result = write_result(
        &config.workspace_root,
        workspace,
        DurableResult {
            workspace_transfer: None,
            outcome,
            exit_code: None,
            termination: &reason,
            reason: Some(&reason),
            completion_protocol: WORK_COMPLETION_PROTOCOL,
            cancellation_outcome: None,
            steps: &steps,
        },
    )
    .await?;
    journal.begin_finalization(&Finalization {
        organization_id: &authority.organization_id,
        attempt_id: &authority.attempt_id,
        fence_token: authority.fence_token,
        session_epoch,
        phase: if outcome == WorkOutcome::Aborted {
            AttemptPhase::Cancelling
        } else {
            AttemptPhase::Finalizing
        },
        process_id: None,
        logs: &[],
        result: &result,
    })?;
    // The immediate summary is built from the persisted result exactly as a
    // replay builds it, so a client sees the same bytes (reason, digest and,
    // for a multi-step attempt whose first step never spawned, its step
    // record) whether or not publication was replayed.
    let result_content = verified_spool_content(&config.workspace_root, &result, "result").await?;
    let persisted: PersistedResult = serde_json::from_slice(&result_content)?;
    let summary = work_completion_summary(&persisted, &result.digest, true)?;
    let published = published_work_outcome(
        authority_rpc(
            control,
            client.complete_work(WorkCompletion {
                authority: Some(authority.clone()),
                outcome: outcome as i32,
                summary_json: summary,
                // A processless completion journals no log spools.
                inline_log_chunks: Vec::new(),
            }),
        )
        .await?,
        session_epoch,
    )?
    .unwrap_or(outcome);
    journal_published_terminal(
        journal,
        &authority.organization_id,
        &authority.attempt_id,
        authority.fence_token,
        session_epoch,
        published,
        None,
    )?;
    reclaim_spool_entries(
        config,
        &authority.organization_id,
        &authority.attempt_id,
        authority.fence_token,
        session_epoch,
        &[],
        Some(&result),
        workspace,
    )
    .await?;
    Ok(())
}

fn require_work_receipt(
    receipt: mcloving_agent_protocol::wire::WorkReceipt,
    session_epoch: u64,
) -> Result<(), AgentError> {
    published_work_outcome(receipt, session_epoch).map(|_| ())
}

/// Returns the terminal the controller actually published, which is not always
/// the one that was requested: a cancellation committing before the publishing
/// row lock overrides a non-succeeded terminal. The journal must record what
/// landed, or durable agent truth disagrees with the controller.
fn published_work_outcome(
    receipt: mcloving_agent_protocol::wire::WorkReceipt,
    session_epoch: u64,
) -> Result<Option<WorkOutcome>, AgentError> {
    ensure_session(receipt.session_epoch, session_epoch)?;
    if !receipt.accepted {
        return Err(AgentError::StaleAuthority);
    }
    Ok(match WorkOutcome::try_from(receipt.published_outcome) {
        Ok(WorkOutcome::Unspecified) | Err(_) => None,
        Ok(outcome) => Some(outcome),
    })
}

fn ensure_session(received: u64, expected: u64) -> Result<(), AgentError> {
    if received == expected {
        Ok(())
    } else {
        Err(AgentError::StaleSession)
    }
}

/// Journals the terminal the controller actually published.
///
/// A cancellation committing at the publishing row lock can override a
/// non-succeeded terminal, and the journal only reaches `Aborted` through
/// `Cancelling`. An abort published against a `Finalizing` attempt therefore
/// takes that step first, or durable agent truth would refuse the very outcome
/// the controller committed. Re-entering `Cancelling` is a no-op.
fn journal_published_terminal(
    journal: &mut Journal,
    organization: &str,
    attempt: &str,
    fence: u64,
    session_epoch: u64,
    published: WorkOutcome,
    process_id: Option<u32>,
) -> Result<(), AgentError> {
    if published == WorkOutcome::Aborted {
        journal.transition(
            organization,
            attempt,
            fence,
            session_epoch,
            AttemptPhase::Cancelling,
            process_id,
        )?;
    }
    journal.transition(
        organization,
        attempt,
        fence,
        session_epoch,
        terminal_phase(published)?,
        process_id,
    )?;
    Ok(())
}

fn terminal_phase(outcome: WorkOutcome) -> Result<AttemptPhase, AgentError> {
    match outcome {
        WorkOutcome::Succeeded => Ok(AttemptPhase::Succeeded),
        WorkOutcome::Failed => Ok(AttemptPhase::Failed),
        WorkOutcome::Aborted => Ok(AttemptPhase::Aborted),
        WorkOutcome::Unspecified => Err(AgentError::UnsupportedProtocol),
    }
}

fn persisted_outcome(outcome: &str) -> Result<WorkOutcome, AgentError> {
    match outcome {
        "succeeded" => Ok(WorkOutcome::Succeeded),
        "failed" => Ok(WorkOutcome::Failed),
        "aborted" => Ok(WorkOutcome::Aborted),
        _ => Err(AgentError::InvalidAssignment(
            "durable result has an unknown terminal outcome".to_owned(),
        )),
    }
}

#[cfg(debug_assertions)]
fn crash_after_terminal_commit_for_test() {
    if std::env::var_os("MCLOVING_TEST_CRASH_AFTER_TERMINAL_COMMIT").is_some() {
        std::process::exit(86);
    }
}

#[cfg(not(debug_assertions))]
fn crash_after_terminal_commit_for_test() {}

fn outcome_name(outcome: WorkOutcome) -> &'static str {
    match outcome {
        WorkOutcome::Succeeded => "succeeded",
        WorkOutcome::Failed => "failed",
        WorkOutcome::Aborted => "aborted",
        WorkOutcome::Unspecified => "unspecified",
    }
}

fn termination_name(termination: Termination) -> &'static str {
    match termination {
        Termination::Exited => "exited",
        Termination::TimedOut => "timed_out",
        Termination::Cancelled => "cancelled",
        Termination::OutputLimitExceeded => "output_limit_exceeded",
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn prompt_acceptance_keeps_the_folded_accept_renewal_free() {
        let claimed = tokio::time::Instant::now();
        let accepted = claimed + Duration::from_millis(70);
        assert!(!accept_consumed_claim_lease(
            claimed,
            Duration::from_secs(30),
            accepted,
            Duration::from_secs(5),
        ));
    }

    #[tokio::test]
    async fn near_expiry_acceptance_falls_back_to_the_serialized_renewal() {
        // The reviewed hazard: accept_work succeeded 29 s into a 30 s claim
        // lease. The periodic cadence cannot re-arm before the worst-case
        // expiry, so the fold must not spawn on the residual lease.
        let claimed = tokio::time::Instant::now();
        let accepted = claimed + Duration::from_secs(29);
        assert!(accept_consumed_claim_lease(
            claimed,
            Duration::from_secs(30),
            accepted,
            Duration::from_secs(5),
        ));
        // Exactly at the boundary the cadence still makes it: renewal at
        // accepted+5s meets a worst-case expiry of claimed+29s only when it
        // is strictly later, so a 24s-old acceptance is still foldable.
        assert!(!accept_consumed_claim_lease(
            claimed,
            Duration::from_secs(30),
            claimed + Duration::from_secs(24),
            Duration::from_secs(5),
        ));
        // A window inside the one-second margin never folds; saturation
        // instead of underflow.
        assert!(accept_consumed_claim_lease(
            claimed,
            Duration::from_millis(500),
            claimed,
            Duration::from_secs(5),
        ));
    }

    fn config() -> AgentConfig {
        AgentConfig {
            input_bindings: None,
            cache_bindings: None,
            podman_path: None,
            agent_id: "agent-1".to_owned(),
            trust_pool: "trusted".to_owned(),
            organization_id: "00000000-0000-0000-0000-000000000123".to_owned(),
            controller_uri: "https://controller.internal".to_owned(),
            controller_dns_name: "controller.internal".to_owned(),
            controller_ca_path: PathBuf::from("ca.pem"),
            agent_certificate_path: PathBuf::from("agent.pem"),
            agent_private_key_path: PathBuf::from("agent-key.pem"),
            journal_path: PathBuf::from("agent.db"),
            workspace_root: PathBuf::from("workspace"),
            session_receipt_path: None,
            minimum_session_epoch: 0,
            lease_seconds: 30,
            poll_interval: Duration::from_millis(500),
            lease_renewal_interval: Duration::from_secs(5),
            termination_grace: Duration::from_secs(2),
        }
    }

    fn assignment(spec: &[u8]) -> WorkAssignment {
        WorkAssignment {
            project_id: String::new(),
            pipeline_id: String::new(),
            workspace_transfer_json: Vec::new(),
            organization_id: "00000000-0000-0000-0000-000000000123".to_owned(),
            build_id: "00000000-0000-0000-0000-000000000124".to_owned(),
            node_id: "00000000-0000-0000-0000-000000000125".to_owned(),
            attempt_id: "00000000-0000-0000-0000-000000000126".to_owned(),
            fence_token: (7_u64 << 32) | 9,
            execution_spec_json: spec.to_vec(),
            payload_digest: Sha256::digest(spec).to_vec(),
        }
    }

    fn multi_step_spec(count: usize) -> Vec<u8> {
        let steps = (0..count)
            .map(|index| {
                json!({
                    "kind": "process",
                    "program": "/bin/sh",
                    "args": ["-c", format!("echo step-{index}")],
                    "timeout_seconds": 10
                })
            })
            .collect::<Vec<_>>();
        serde_json::to_vec(&json!({"version": 5, "steps": steps})).unwrap()
    }

    /// PAR-010: the version-5 envelope is runnable only once the controller
    /// confirmed it understands step ordinals on the wire; without that the
    /// work is declined back to the queue for a session that did, never run
    /// as a silent single step and never failed for good.
    #[test]
    fn multi_step_envelope_runs_only_when_the_feature_was_negotiated() {
        let spec = multi_step_spec(3);
        assert!(matches!(
            validate_assignment(&config(), 4, assignment(&spec)).unwrap(),
            AssignmentDisposition::ForAnotherRuntime(reason)
                if reason.contains("multi-step-execution-v1")
        ));

        let features = SessionFeatures {
            multi_step: true,
            ..SessionFeatures::default()
        };
        let validated = runnable(
            validate_assignment_with_features(&config(), 4, assignment(&spec), features).unwrap(),
        );
        assert!(validated.multi_step);
        assert_eq!(validated.steps.len(), 3);
        assert_eq!(validated.steps[2].args, vec!["-c", "echo step-2"]);
        assert!(validated.helper.is_none());
    }

    #[test]
    fn multi_step_envelope_refuses_shapes_outside_its_contract() {
        let features = SessionFeatures {
            multi_step: true,
            ..SessionFeatures::default()
        };
        let too_many = multi_step_spec(17);
        let refusal = unsupported(
            validate_assignment_with_features(&config(), 4, assignment(&too_many), features)
                .unwrap(),
        );
        assert!(refusal.detail.contains("17 steps"), "{}", refusal.detail);

        let empty = serde_json::to_vec(&json!({"version": 5, "steps": []})).unwrap();
        let refusal = unsupported(
            validate_assignment_with_features(&config(), 4, assignment(&empty), features).unwrap(),
        );
        assert!(refusal.detail.contains("0 steps"), "{}", refusal.detail);

        let foreign_kind = serde_json::to_vec(&json!({"version": 5, "steps": [
            {"kind": "process", "program": "/bin/true"},
            {"kind": "checkout", "program": ""}
        ]}))
        .unwrap();
        let refusal = unsupported(
            validate_assignment_with_features(&config(), 4, assignment(&foreign_kind), features)
                .unwrap(),
        );
        assert!(refusal.detail.contains("step 1 kind"), "{}", refusal.detail);

        let unbounded = serde_json::to_vec(&json!({"version": 5, "steps": [
            {"kind": "process", "program": "/bin/true"},
            {"kind": "process", "program": "/bin/true", "timeout_seconds": 0}
        ]}))
        .unwrap();
        let refusal = unsupported(
            validate_assignment_with_features(&config(), 4, assignment(&unbounded), features)
                .unwrap(),
        );
        assert!(
            refusal.detail.contains("step 1 timeout"),
            "{}",
            refusal.detail
        );

        // Eight per step is fine; nine distinct targets across the attempt is
        // the controller's redemption bound and must be refused up front.
        let step = |names: &[&str]| json!({"kind": "process", "program": "/bin/true", "credentials": names});
        let split = serde_json::to_vec(&json!({"version": 5, "steps": [
            step(&["A1", "A2", "A3", "A4", "A5"]),
            step(&["B1", "B2", "B3", "B4"])
        ]}))
        .unwrap();
        let refusal = unsupported(
            validate_assignment_with_features(&config(), 4, assignment(&split), features).unwrap(),
        );
        assert!(
            refusal.detail.contains("across all steps (9)"),
            "{}",
            refusal.detail
        );
        let shared = serde_json::to_vec(&json!({"version": 5, "steps": [
            step(&["A1", "A2", "A3", "A4", "A5"]),
            step(&["A1", "A2", "A3", "B4"])
        ]}))
        .unwrap();
        runnable(
            validate_assignment_with_features(&config(), 4, assignment(&shared), features).unwrap(),
        );
    }

    /// A single process step keeps the version-1 shape and the single-step
    /// path exactly as before; version 5 never changes what an old spec means.
    #[test]
    fn single_step_envelope_is_unchanged_by_multi_step_support() {
        let spec = serde_json::to_vec(&json!({"version": 1, "steps": [
            {"kind": "process", "program": "/bin/true"}
        ]}))
        .unwrap();
        let validated = runnable(validate_assignment(&config(), 4, assignment(&spec)).unwrap());
        assert!(!validated.multi_step);
        assert_eq!(validated.steps.len(), 1);
    }

    #[test]
    fn spool_paths_encode_their_stream_and_step_ordinal() {
        let entry = |path: &str| SpoolEntry {
            sequence: 0,
            relative_path: PathBuf::from(path),
            digest: [0; 32],
            bytes: 0,
        };
        assert_eq!(
            spool_stream(&entry("org/a/spool/stdout.log")).unwrap(),
            ("stdout", 0)
        );
        assert_eq!(
            spool_stream(&entry("org/a/spool/stderr.log")).unwrap(),
            ("stderr", 0)
        );
        assert_eq!(
            spool_stream(&entry("org/a/spool/step-0/stdout.log")).unwrap(),
            ("stdout", 0)
        );
        assert_eq!(
            spool_stream(&entry("org/a/spool/step-15/stderr.log")).unwrap(),
            ("stderr", 15)
        );
        assert!(spool_stream(&entry("org/a/spool/step-x/stdout.log")).is_err());
        assert!(spool_stream(&entry("org/a/other/stdout.log")).is_err());
        assert!(spool_stream(&entry("org/a/spool/step-1/result.json")).is_err());
    }

    #[test]
    fn completion_summary_carries_per_step_records_and_the_failing_reason() {
        let persisted = PersistedResult {
            workspace_transfer: None,
            outcome: "failed".to_owned(),
            exit_code: Some(3),
            termination: "exited".to_owned(),
            reason: None,
            completion_protocol: WORK_COMPLETION_PROTOCOL.to_owned(),
            cancellation_outcome: None,
            steps: vec![
                StepRecord {
                    ordinal: 0,
                    outcome: "succeeded".to_owned(),
                    exit_code: Some(0),
                    termination: "exited".to_owned(),
                    reason: None,
                },
                StepRecord {
                    ordinal: 1,
                    outcome: "failed".to_owned(),
                    exit_code: Some(3),
                    termination: "exited".to_owned(),
                    reason: None,
                },
            ],
        };
        let summary: serde_json::Value =
            serde_json::from_slice(&work_completion_summary(&persisted, &[7; 32], false).unwrap())
                .unwrap();
        assert_eq!(summary["exit_code"], 3);
        assert_eq!(summary["steps"].as_array().unwrap().len(), 2);
        assert_eq!(summary["steps"][1]["outcome"], "failed");
        assert_eq!(summary["steps"][1]["exit_code"], 3);
        assert!(summary["steps"][0].get("reason").is_none());

        let single = PersistedResult {
            steps: Vec::new(),
            ..persisted
        };
        let summary: serde_json::Value =
            serde_json::from_slice(&work_completion_summary(&single, &[7; 32], false).unwrap())
                .unwrap();
        assert!(
            summary.get("steps").is_none(),
            "single-step summaries are byte-compatible"
        );
    }

    #[test]
    fn cache_context_substitution_is_rejected_before_runnable_assignment() {
        let spec=serde_json::to_vec(&json!({"version":3,"steps":[{"kind":"cache_intent","mapping_id":"fixture","mapping_digest":format!("sha256:{}","a".repeat(64)),"operation":"read","logical_key_sha256":"b".repeat(64),"input_sha256":"c".repeat(64),"timeout_seconds":10}]})).unwrap();
        let mut offer = assignment(&spec);
        offer.project_id = "00000000-0000-0000-0000-000000000127".to_owned();
        offer.pipeline_id = "00000000-0000-0000-0000-000000000128".to_owned();
        let context = CacheWorkContext {
            organization_id: offer.organization_id.clone(),
            project_id: offer.project_id.clone(),
            pipeline_id: offer.pipeline_id.clone(),
            build_id: offer.build_id.clone(),
            node_id: offer.node_id.clone(),
            attempt_id: offer.attempt_id.clone(),
            fence_token: offer.fence_token,
        };
        offer.payload_digest = cache_assignment_digest(&spec, &context).to_vec();
        let mut configured = config();
        configured.cache_bindings = Some(crate::cache::CacheBindings {
            schema_version: "mcloving.agent-cache-bindings/v1".into(),
            mappings: Vec::new(),
        });
        #[cfg(target_os = "linux")]
        assert!(matches!(
            validate_assignment(&configured, 4, offer.clone()).unwrap(),
            AssignmentDisposition::Runnable(_)
        ));
        for index in 0..8 {
            let mut changed = offer.clone();
            let replacement = "00000000-0000-0000-0000-000000000129".to_owned();
            match index {
                0 => changed.organization_id = replacement,
                1 => changed.project_id = replacement,
                2 => changed.pipeline_id = replacement,
                3 => changed.build_id = replacement,
                4 => changed.node_id = replacement,
                5 => changed.attempt_id = replacement,
                6 => changed.fence_token += 1,
                _ => changed.execution_spec_json.push(b' '),
            }
            assert!(
                validate_assignment(&configured, 4, changed).is_err(),
                "context field {index}"
            );
        }
    }

    #[test]
    fn input_context_substitution_is_rejected_before_runnable_assignment() {
        let spec=serde_json::to_vec(&json!({"version":4,"steps":[{"kind":"input_intent","mapping_id":"fixture","mapping_digest":format!("sha256:{}","a".repeat(64)),"timeout_seconds":10}]})).unwrap();
        let mut offer = assignment(&spec);
        offer.project_id = "00000000-0000-0000-0000-000000000127".to_owned();
        offer.pipeline_id = "00000000-0000-0000-0000-000000000128".to_owned();
        let context = InputWorkContext {
            organization_id: offer.organization_id.clone(),
            project_id: offer.project_id.clone(),
            pipeline_id: offer.pipeline_id.clone(),
            build_id: offer.build_id.clone(),
            node_id: offer.node_id.clone(),
            attempt_id: offer.attempt_id.clone(),
            fence_token: offer.fence_token,
        };
        offer.payload_digest = input_assignment_digest(&spec, &context).to_vec();
        let mut configured = config();
        configured.input_bindings = Some(crate::input::InputBindings {
            schema_version: "mcloving.agent-input-bindings/v1".into(),
            mappings: Vec::new(),
        });
        #[cfg(target_os = "linux")]
        assert!(matches!(
            validate_assignment(&configured, 4, offer.clone()).unwrap(),
            AssignmentDisposition::Runnable(_)
        ));
        for index in 0..8 {
            let mut changed = offer.clone();
            let replacement = "00000000-0000-0000-0000-000000000129".to_owned();
            match index {
                0 => changed.organization_id = replacement,
                1 => changed.project_id = replacement,
                2 => changed.pipeline_id = replacement,
                3 => changed.build_id = replacement,
                4 => changed.node_id = replacement,
                5 => changed.attempt_id = replacement,
                6 => changed.fence_token += 1,
                _ => changed.execution_spec_json.push(b' '),
            }
            assert!(
                validate_assignment(&configured, 4, changed).is_err(),
                "context field {index}"
            );
        }
        let mut invalid = offer;
        invalid.project_id.clear();
        assert!(matches!(
            validate_assignment(&configured, 4, invalid),
            Err(AgentError::InvalidAssignment(message)) if message == "helper work context is invalid"
        ));
    }

    #[test]
    fn workspace_publication_and_replay_preserve_checkpoint_reason_and_result_digest() {
        use mcloving_domain::workspace::WorkspaceSnapshot;
        let snapshot = WorkspaceSnapshot {
            version: 1,
            entries: Vec::new(),
        };
        for (capture_failure, lease_loss) in [(false, false), (true, false), (true, true)] {
            let transfer = WorkspaceTransferResult {
                version: 1,
                organization_id: "00000000-0000-0000-0000-000000000123".to_owned(),
                build_id: "00000000-0000-0000-0000-000000000124".to_owned(),
                namespace_id: "00000000-0000-0000-0000-000000000127".to_owned(),
                generation: 0,
                input_digest: snapshot.digest().unwrap(),
                snapshot: (!capture_failure).then_some(snapshot.clone()),
                error: capture_failure.then_some(
                    if lease_loss {
                        "execution_not_completed"
                    } else {
                        "workspace_unsupported_entry"
                    }
                    .to_owned(),
                ),
            };
            let durable = json!({
                "outcome": if lease_loss { "aborted" } else if capture_failure { "failed" } else { "succeeded" },
                "exit_code": 0, "termination": if lease_loss { "cancelled" } else { "exited" },
                "reason": if lease_loss { Some("lease_lost_during_execution:renewal_timeout") } else { capture_failure.then_some("workspace_capture_failed:workspace_unsupported_entry") },
                "completion_protocol": "work", "cancellation_outcome": null,
                "workspace_transfer": transfer,
            });
            let bytes = serde_json::to_vec(&durable).unwrap();
            let digest: [u8; 32] = Sha256::digest(&bytes).into();
            let persisted: PersistedResult = serde_json::from_slice(&bytes).unwrap();
            let initial = work_completion_summary(&persisted, &digest, false).unwrap();
            let replay = work_completion_summary(&persisted, &digest, true).unwrap();
            assert_eq!(initial, replay);
            let summary: serde_json::Value = serde_json::from_slice(&initial).unwrap();
            assert_eq!(summary["workspace_transfer"], durable["workspace_transfer"]);
            assert_eq!(summary["exit_code"], 0);
            assert_eq!(summary["termination"], durable["termination"]);
            assert_eq!(summary["result_sha256"], hex(&digest));
            if capture_failure {
                assert_eq!(summary["reason"], durable["reason"]);
            }
            assert!(initial.len() <= MAX_RESULT_SPOOL_BYTES as usize);
        }
        let legacy: PersistedResult = serde_json::from_value(json!({
            "outcome":"succeeded", "exit_code":0, "termination":"exited", "reason":null,
            "completion_protocol":"work", "cancellation_outcome":null,
        }))
        .unwrap();
        let expected = serde_json::to_vec(
            &json!({"exit_code":0,"termination":"exited","result_sha256":hex(&[7;32])}),
        )
        .unwrap();
        assert_eq!(
            work_completion_summary(&legacy, &[7; 32], false).unwrap(),
            expected
        );
        assert_eq!(
            work_completion_summary(&legacy, &[7; 32], true).unwrap(),
            expected
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn workspace_grants_bind_scope_digest_and_refuse_environment() {
        use mcloving_domain::workspace::WorkspaceSnapshot;
        let snapshot = WorkspaceSnapshot {
            version: 1,
            entries: Vec::new(),
        };
        let mut grant = WorkspaceGrant {
            version: 1,
            organization_id: config().organization_id,
            build_id: "00000000-0000-0000-0000-000000000124".to_owned(),
            namespace_id: "00000000-0000-0000-0000-000000000127".to_owned(),
            generation: 0,
            digest: snapshot.digest().unwrap(),
            snapshot,
        };
        let spec = br#"{"version":1,"steps":[{"kind":"process","program":"/bin/sh","args":["-c","true"]}]}"#;
        let mut offer = assignment(spec);
        offer.workspace_transfer_json = serde_json::to_vec(&grant).unwrap();
        assert!(
            runnable(validate_assignment(&config(), 1, offer.clone()).unwrap())
                .workspace_grant
                .is_some()
        );
        grant.build_id = "00000000-0000-0000-0000-000000000999".to_owned();
        offer.workspace_transfer_json = serde_json::to_vec(&grant).unwrap();
        assert!(validate_assignment(&config(), 1, offer.clone()).is_err());
        grant.build_id = offer.build_id.clone();
        grant.digest = [0; 32];
        offer.workspace_transfer_json = serde_json::to_vec(&grant).unwrap();
        assert!(validate_assignment(&config(), 1, offer).is_err());
        grant.digest = grant.snapshot.digest().unwrap();
        for extras in [
            json!({"env":{"SAFE":"value"}}),
            json!({"credentials":["TOKEN"]}),
        ] {
            let mut process = json!({"kind":"process","program":"/bin/sh","args":["-c","true"]});
            process
                .as_object_mut()
                .unwrap()
                .extend(extras.as_object().unwrap().clone());
            let mut offer =
                assignment(&serde_json::to_vec(&json!({"version":1,"steps":[process]})).unwrap());
            offer.workspace_transfer_json = serde_json::to_vec(&grant).unwrap();
            assert!(
                unsupported(validate_assignment(&config(), 1, offer).unwrap())
                    .detail
                    .contains("forbids")
            );
        }
    }

    #[test]
    fn credential_bindings_are_bounded_unique_and_collision_free() {
        let grant_id = Uuid::new_v4();
        let execution = execution_environment(
            BTreeMap::from([("SAFE".to_owned(), "value".to_owned())]),
            vec![CredentialBinding {
                grant_id: grant_id.to_string(),
                target_name: "DEPLOY_TOKEN".to_owned(),
                secret_value: b"marker-secret".to_vec(),
            }],
        )
        .unwrap();
        assert_eq!(execution.values["SAFE"], "value");
        assert_eq!(execution.values["DEPLOY_TOKEN"], "marker-secret");
        assert_eq!(execution.redactions, vec![b"marker-secret".to_vec()]);

        assert!(
            execution_environment(
                BTreeMap::from([("DEPLOY_TOKEN".to_owned(), "pipeline".to_owned())]),
                vec![CredentialBinding {
                    grant_id: grant_id.to_string(),
                    target_name: "DEPLOY_TOKEN".to_owned(),
                    secret_value: b"marker-secret".to_vec(),
                }],
            )
            .is_err()
        );
        assert!(
            execution_environment(
                BTreeMap::new(),
                vec![CredentialBinding {
                    grant_id: grant_id.to_string(),
                    target_name: "invalid-name".to_owned(),
                    secret_value: b"marker-secret".to_vec(),
                }],
            )
            .is_err()
        );
    }

    #[test]
    fn ambiguous_authority_transition_statuses_are_retryable() {
        for code in [
            tonic::Code::Cancelled,
            tonic::Code::Unknown,
            tonic::Code::DeadlineExceeded,
            tonic::Code::ResourceExhausted,
            tonic::Code::Aborted,
            tonic::Code::Internal,
            tonic::Code::Unavailable,
        ] {
            assert!(
                retryable_authority_transition(&tonic::Status::new(code, "ambiguous")),
                "{code:?} must be safe to replay"
            );
        }
        for code in [
            tonic::Code::InvalidArgument,
            tonic::Code::NotFound,
            tonic::Code::AlreadyExists,
            tonic::Code::PermissionDenied,
            tonic::Code::FailedPrecondition,
            tonic::Code::OutOfRange,
            tonic::Code::Unimplemented,
            tonic::Code::Unauthenticated,
            tonic::Code::DataLoss,
        ] {
            assert!(
                !retryable_authority_transition(&tonic::Status::new(code, "definitive")),
                "{code:?} must fail closed"
            );
        }
    }

    #[tokio::test]
    async fn authority_retry_wait_preserves_cancellation_and_authority_loss() {
        let cancellation = CancellationToken::new();
        let authority_lost = CancellationToken::new();
        cancellation.cancel();
        assert!(
            !wait_for_authority_retry(&cancellation, &authority_lost)
                .await
                .unwrap()
        );

        let cancellation = CancellationToken::new();
        let authority_lost = CancellationToken::new();
        authority_lost.cancel();
        assert!(matches!(
            wait_for_authority_retry(&cancellation, &authority_lost).await,
            Err(AgentError::StaleAuthority)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_credential_targets_are_case_insensitive_and_reserve_temp() {
        let environment = BTreeMap::from([("deploy_token".to_owned(), "pipeline".to_owned())]);
        assert!(!credential_targets_are_valid(
            &environment,
            &["DEPLOY_TOKEN".to_owned()]
        ));
        assert!(!credential_targets_are_valid(
            &BTreeMap::new(),
            &["TOKEN".to_owned(), "token".to_owned()]
        ));
        for reserved in ["TEMP", "temp", "TMP", "tmp"] {
            assert!(!credential_targets_are_valid(
                &BTreeMap::new(),
                &[reserved.to_owned()]
            ));
        }
    }

    #[test]
    fn only_unverified_containment_retains_reconciliation_identity() {
        assert_eq!(
            unverified_containment_process_id(&ExecutionError::WindowsJob(
                "job drain failed".to_owned()
            )),
            None
        );
        assert_eq!(
            unverified_containment_process_id(&ExecutionError::ContainmentUnverified {
                process_id: 43,
                reason: "group still exists".to_owned(),
            }),
            Some(43)
        );
        assert_eq!(
            unverified_containment_process_id(&ExecutionError::WindowsJob(
                "pre-spawn failure".to_owned()
            )),
            None
        );
    }

    #[test]
    fn replaced_workspace_root_requires_processless_reconciliation() {
        assert!(requires_processless_reconciliation(
            &ExecutionError::ReplacedWorkspaceRoot
        ));
        assert!(!requires_processless_reconciliation(
            &ExecutionError::ReplacedSpoolPath
        ));
    }

    fn runnable(disposition: AssignmentDisposition) -> ValidatedAssignment {
        match disposition {
            AssignmentDisposition::Runnable(assignment) => *assignment,
            AssignmentDisposition::Unsupported(refusal) => {
                panic!("assignment must be runnable, refused: {}", refusal.detail)
            }
            AssignmentDisposition::ForAnotherRuntime(reason) => {
                panic!("assignment must be runnable, declined: {reason}")
            }
        }
    }

    fn unsupported(disposition: AssignmentDisposition) -> UnsupportedAssignment {
        match disposition {
            AssignmentDisposition::Unsupported(refusal) => refusal,
            AssignmentDisposition::Runnable(_) => {
                panic!("assignment must be refused as unsupported")
            }
            AssignmentDisposition::ForAnotherRuntime(reason) => {
                panic!("assignment must be refused as unsupported, declined: {reason}")
            }
        }
    }

    /// A connector intent is runnable by an effect-runtime worker, so a
    /// process-only agent must decline it rather than permanently fail work
    /// another agent could complete.
    #[test]
    fn connector_intent_work_is_declined_not_terminally_refused() {
        let spec = br#"{"version":2,"steps":[{"kind":"connector_intent","mapping_id":"notification.v1","mapping_digest":"sha256:aa","effect_class":"idempotent","effect_key_template":"k","public_input_schema":{},"protected_secret_ref_schema":{},"expected_public_result_schema":{},"timeout_seconds":30,"ambiguity_policy":"observe_then_reconcile","downstream_control_digest":"sha256:bb"}]}"#;
        assert!(matches!(
            validate_assignment(&config(), 4, assignment(spec)).unwrap(),
            AssignmentDisposition::ForAnotherRuntime(_)
        ));
    }

    /// An unknown step kind is attacker-controlled and can be far larger than
    /// the controller's 64 KiB summary limit. The refusal reason must stay
    /// publishable, or the attempt never terminalizes at all.
    #[test]
    fn an_oversized_refusal_reason_stays_publishable() {
        let kind = "k".repeat(200_000);
        let spec = format!(r#"{{"version":1,"steps":[{{"kind":"{kind}","program":"true"}}]}}"#);
        let refusal =
            unsupported(validate_assignment(&config(), 4, assignment(spec.as_bytes())).unwrap());
        assert!(
            refusal.detail.len() < 1_024,
            "detail: {}",
            refusal.detail.len()
        );
        assert!(refusal.detail.ends_with("(truncated)"));
    }

    /// A connector-intent payload runnable by nothing — wrong version, or
    /// fields the effect runtime would reject — must be terminalized here.
    /// Declining it only re-offers work no runtime can complete.
    #[test]
    fn connector_intent_payloads_no_runtime_accepts_are_terminally_refused() {
        for spec in [
            br#"{"version":1,"steps":[{"kind":"connector_intent"}]}"#.to_vec(),
            br#"{"version":2,"steps":[{"kind":"connector_intent"}]}"#.to_vec(),
            br#"{"version":2,"steps":[{"kind":"connector_intent","mapping_digest":"sha256:aa","effect_class":"idempotent","effect_key_template":"k","public_input_schema":{},"protected_secret_ref_schema":{},"expected_public_result_schema":{},"timeout_seconds":30,"ambiguity_policy":"observe_then_reconcile","downstream_control_digest":"sha256:bb"}]}"#.to_vec(),
        ] {
            let refusal =
                unsupported(validate_assignment(&config(), 4, assignment(&spec)).unwrap());
            assert!(!refusal.detail.is_empty());
        }
    }

    #[test]
    fn assignment_is_tenant_bound_and_digest_checked() {
        let spec = br#"{"version":1,"steps":[{"kind":"process","program":"true"}]}"#;
        let validated = runnable(validate_assignment(&config(), 4, assignment(spec)).unwrap());
        assert_eq!(validated.authority.session_epoch, 4);
        assert_eq!(
            validated.workspace,
            PathBuf::from(
                "00000000-0000-0000-0000-000000000123/00000000-0000-0000-0000-000000000126/30064771081"
            )
        );

        let mut wrong_tenant = assignment(spec);
        wrong_tenant.organization_id = "00000000-0000-0000-0000-000000000999".to_owned();
        assert!(validate_assignment(&config(), 4, wrong_tenant).is_err());

        let mut wrong_digest = assignment(spec);
        wrong_digest.payload_digest = vec![0; 32];
        assert!(validate_assignment(&config(), 4, wrong_digest).is_err());

        let unbounded_timeout = br#"{"version":1,"steps":[{"kind":"process","program":"true","timeout_seconds":18446744073709551615}]}"#;
        let refusal =
            unsupported(validate_assignment(&config(), 4, assignment(unbounded_timeout)).unwrap());
        assert!(refusal.detail.contains("process timeout"));
        let zero_timeout =
            br#"{"version":1,"steps":[{"kind":"process","program":"true","timeout_seconds":0}]}"#;
        let refusal =
            unsupported(validate_assignment(&config(), 4, assignment(zero_timeout)).unwrap());
        assert!(refusal.detail.contains("process timeout"));
    }

    #[test]
    fn execution_budget_reserves_entire_grace_and_rejects_exhausted_windows() {
        assert_eq!(
            execution_lease_budget(Duration::from_secs(30), Duration::from_secs(2)),
            Duration::from_secs(27)
        );
        assert_eq!(
            execution_lease_budget(Duration::from_secs(10), Duration::from_secs(4)),
            Duration::from_secs(5)
        );
        assert_eq!(
            execution_lease_budget(Duration::from_secs(5), Duration::from_secs(4)),
            Duration::ZERO
        );
        assert_eq!(
            execution_lease_budget(Duration::from_secs(5), Duration::MAX),
            Duration::ZERO
        );
    }

    #[test]
    fn lease_rpc_budget_expires_before_the_controller_lease() {
        assert_eq!(
            lease_rpc_budget(Duration::from_secs(30)),
            Duration::from_secs(29)
        );
        assert_eq!(lease_rpc_budget(Duration::from_millis(500)), Duration::ZERO);
    }

    /// AGENT-007. Only an ANSWER can withdraw authority. Every status the
    /// controller's own renewal handler can return is treated as an answer and
    /// cancels the step; a status that means the ask never landed is retried.
    #[test]
    fn only_an_answered_renewal_withdraws_authority() {
        for answered in [
            tonic::Status::failed_precondition("stale agent session epoch for agent x"),
            tonic::Status::failed_precondition("attempt is not leased"),
            tonic::Status::permission_denied("agent is not in the trust pool"),
            tonic::Status::unauthenticated("client certificate is unknown"),
            tonic::Status::not_found("attempt does not exist"),
            tonic::Status::invalid_argument("lease_seconds must be between 5 and 300"),
        ] {
            assert!(
                !renewal_went_unanswered(&answered),
                "{answered:?} is an answer from the controller and must cancel the step"
            );
        }
        for unanswered in [
            tonic::Status::unavailable("tcp connect error: Connection refused"),
            tonic::Status::deadline_exceeded("no reply"),
            tonic::Status::cancelled("connection closed mid-call"),
            tonic::Status::unknown("h2 protocol error"),
            tonic::Status::internal("controller store is unavailable"),
        ] {
            assert!(
                renewal_went_unanswered(&unanswered),
                "{unanswered:?} withdraws no authority and must be retried"
            );
        }
    }

    /// AGENT-007. The stale-session fencing rejection keeps its own name, and
    /// every other answered refusal is named as a refusal rather than -- as it
    /// was before this ticket -- as a transport failure it is not.
    #[test]
    fn an_answered_refusal_is_named_as_one() {
        assert_eq!(
            renewal_status_cause(&tonic::Status::failed_precondition(
                "stale agent session epoch for agent x"
            )),
            "renewal_session_stale"
        );
        assert_eq!(
            renewal_status_cause(&tonic::Status::permission_denied("not in trust pool")),
            "renewal_refused"
        );
    }

    /// AGENT-007, from review. Cancelling an execution is not stopping it: the
    /// executor signals the group and waits the termination grace before
    /// `SIGKILL`, so the grace has to come out of the lease. Reserving only the
    /// one-second RPC margin left a workload that ignores `SIGTERM` running past
    /// the instant another runtime may claim the same attempt.
    #[test]
    fn the_termination_grace_is_reserved_inside_the_lease() {
        let start = tokio::time::Instant::now();
        let window = Duration::from_secs(30);
        let grace = Duration::from_secs(2);
        assert_eq!(
            lease_cancellation_deadline(start, window, grace),
            start + Duration::from_secs(27),
            "the deadline reserves the RPC margin AND the grace"
        );
        assert!(
            lease_cancellation_deadline(start, window, grace) + grace <= start + window,
            "the configured termination reserve fits before lease expiry"
        );
        // A grace wider than the whole window cannot go negative; the renewal
        // then has no room at all, which the agent configuration refuses.
        assert_eq!(
            lease_cancellation_deadline(start, Duration::from_secs(5), Duration::from_secs(30)),
            start
        );
    }

    /// AGENT-007, from review. A lease term must be anchored at the instant its
    /// request LEFT, never at the instant its answer arrived. The controller
    /// stamps `lease_expires_at` while the request is in flight, so a round trip
    /// longer than the one-second margin makes a receipt-time anchor put the
    /// agent's deadline AFTER the attempt becomes reclaimable -- and the retry
    /// this ticket adds would then run the step into that window.
    ///
    /// This test is the arithmetic, not a mutation gate on the call sites: the
    /// anchor is a call-site choice, and no test here can fail if a call site
    /// picks the wrong instant. That limit is stated in the closure receipt
    /// rather than papered over.
    #[test]
    fn a_lease_term_anchored_on_receipt_can_outlive_the_controller() {
        let window = Duration::from_secs(30);
        let sent = tokio::time::Instant::now();
        // The controller stamps its expiry somewhere inside the round trip.
        let processed = sent + Duration::from_millis(400);
        let answered = sent + Duration::from_millis(2_400);
        let controller_expiry = processed + window;

        assert!(
            sent + lease_rpc_budget(window) <= controller_expiry,
            "anchoring at the send instant must never reach the controller's expiry"
        );
        assert!(
            answered + lease_rpc_budget(window) > controller_expiry,
            "anchoring on receipt overruns it as soon as the round trip exceeds \
             the one-second margin, which is why the anchor is the send instant"
        );
    }

    /// AGENT-007. The retry cadence is bounded on both sides: never slower than
    /// one second, so a controller back from a short restart is found promptly,
    /// and never faster than the agent's own renewal interval.
    #[test]
    fn the_renewal_retry_cadence_is_bounded_on_both_sides() {
        assert_eq!(
            renewal_retry_interval(Duration::from_secs(5)),
            Duration::from_secs(1)
        );
        assert_eq!(
            renewal_retry_interval(Duration::from_millis(200)),
            Duration::from_millis(200)
        );
    }

    /// AGENT-007. The lease the agent already holds is the whole bound on the
    /// retry: no wait reaches past it, and at it the retry stops so the step is
    /// cancelled rather than outliving the authority that covered it.
    #[test]
    fn a_renewal_retry_never_outlives_the_held_lease() {
        let now = tokio::time::Instant::now();
        let deadline = now + Duration::from_secs(10);
        assert_eq!(
            next_renewal_retry(now, deadline, Duration::from_secs(1)),
            Some(now + Duration::from_secs(1)),
            "an ordinary retry waits the cadence"
        );
        assert_eq!(
            next_renewal_retry(
                now + Duration::from_millis(9_500),
                deadline,
                Duration::from_secs(1)
            ),
            Some(deadline),
            "a retry that would wait past the lease is pulled back to it"
        );
        assert_eq!(
            next_renewal_retry(deadline, deadline, Duration::from_secs(1)),
            None,
            "at the lease deadline the step is cancelled, not retried"
        );
        assert_eq!(
            next_renewal_retry(
                deadline + Duration::from_secs(1),
                deadline,
                Duration::from_secs(1)
            ),
            None,
            "past the lease deadline the step is cancelled, not retried"
        );
    }

    #[tokio::test]
    async fn authority_loss_interrupts_a_stalled_terminal_rpc() {
        let authority_lost = CancellationToken::new();
        authority_lost.cancel();
        let stop = CancellationToken::new();
        let result = authority_rpc::<()>(
            AuthorityRpcControl {
                authority_lost: &authority_lost,
                stop: &stop,
                lease_window: Duration::from_secs(30),
            },
            std::future::pending::<Result<tonic::Response<()>, tonic::Status>>(),
        )
        .await;
        assert!(matches!(result, Err(AgentError::StaleAuthority)));
    }

    #[tokio::test]
    async fn service_stop_interrupts_a_stalled_terminal_rpc() {
        let authority_lost = CancellationToken::new();
        let stop = CancellationToken::new();
        stop.cancel();
        let result = authority_rpc::<()>(
            AuthorityRpcControl {
                authority_lost: &authority_lost,
                stop: &stop,
                lease_window: Duration::from_secs(30),
            },
            std::future::pending::<Result<tonic::Response<()>, tonic::Status>>(),
        )
        .await;
        assert!(matches!(result, Err(AgentError::Stopped)));
    }

    #[tokio::test]
    async fn stalled_authority_rpc_is_lease_bounded() {
        let authority_lost = CancellationToken::new();
        let stop = CancellationToken::new();
        let result = authority_rpc::<()>(
            AuthorityRpcControl {
                authority_lost: &authority_lost,
                stop: &stop,
                lease_window: Duration::from_millis(1_001),
            },
            std::future::pending::<Result<tonic::Response<()>, tonic::Status>>(),
        )
        .await;
        assert!(matches!(result, Err(AgentError::AuthorityRpcTimeout)));
    }

    #[tokio::test]
    async fn startup_rpc_deadline_is_fail_closed() {
        let result = lease_deadline_rpc::<()>(
            tokio::time::Instant::now() + Duration::from_millis(1),
            std::future::pending::<Result<tonic::Response<()>, tonic::Status>>(),
        )
        .await;
        assert!(matches!(result, Err(AgentError::LeaseRenewalTimeout)));
    }

    #[tokio::test]
    async fn idle_work_poll_is_bounded() {
        let result = poll_rpc::<()>(
            Duration::from_millis(1),
            std::future::pending::<Result<tonic::Response<()>, tonic::Status>>(),
        )
        .await;
        assert!(matches!(result, Err(AgentError::PollTimeout)));
    }

    #[test]
    fn execution_spec_is_fail_closed() {
        let multiple =
            br#"{"version":1,"steps":[{"kind":"process","program":"one"},{"kind":"process","program":"two"}]}"#;
        let refusal = unsupported(validate_assignment(&config(), 1, assignment(multiple)).unwrap());
        assert_eq!(
            refusal.detail,
            "execution spec declares 2 steps (expected exactly 1 process step)"
        );
        let wrong_kind = br#"{"version":1,"steps":[{"kind":"shell","program":"no"}]}"#;
        let refusal =
            unsupported(validate_assignment(&config(), 1, assignment(wrong_kind)).unwrap());
        assert_eq!(
            refusal.detail,
            "execution spec step kind \"shell\" is not supported (expected \"process\")"
        );
        let wrong_version = br#"{"version":2,"steps":[{"kind":"process","program":"no"}]}"#;
        let refusal =
            unsupported(validate_assignment(&config(), 1, assignment(wrong_version)).unwrap());
        assert_eq!(
            refusal.detail,
            "execution spec version 2 is not supported (expected 1)"
        );

        let windows_cmd = br#"{"version":1,"steps":[{"kind":"process","mode":"windows_cmd","program":"build.cmd"}]}"#;
        assert!(matches!(
            runnable(
                validate_assignment(&config(), 1, assignment(windows_cmd))
                    .expect("accept explicit cmd mode")
            )
            .steps[0]
                .mode,
            ProcessMode::WindowsCmd
        ));
        let powershell = br#"{"version":1,"steps":[{"kind":"process","mode":"powershell","program":"build.ps1"}]}"#;
        assert!(matches!(
            runnable(
                validate_assignment(&config(), 1, assignment(powershell))
                    .expect("accept explicit PowerShell mode")
            )
            .steps[0]
                .mode,
            ProcessMode::PowerShell
        ));
        let legacy_powershell = br#"{"version":1,"steps":[{"kind":"process","mode":"power_shell","program":"build.ps1"}]}"#;
        assert!(matches!(
            runnable(
                validate_assignment(&config(), 1, assignment(legacy_powershell))
                    .expect("accept the protocol v1.0 PowerShell spelling")
            )
            .steps[0]
                .mode,
            ProcessMode::PowerShell
        ));
        let unknown_mode =
            br#"{"version":1,"steps":[{"kind":"process","mode":"shell","program":"build.ps1"}]}"#;
        let refusal =
            unsupported(validate_assignment(&config(), 1, assignment(unknown_mode)).unwrap());
        assert!(
            refusal
                .detail
                .starts_with("execution spec does not deserialize"),
            "unknown execution modes must remain fail-closed: {}",
            refusal.detail
        );
    }

    #[test]
    fn log_spool_quota_is_enforced_before_upload() {
        let entry = |sequence, bytes| SpoolEntry {
            sequence,
            relative_path: PathBuf::from(format!("spool/{sequence}.log")),
            digest: [0; 32],
            bytes,
        };
        validate_log_spool_quota(&[
            entry(0, MAX_ATTEMPT_OUTPUT_BYTES / 2),
            entry(1, MAX_ATTEMPT_OUTPUT_BYTES / 2),
        ])
        .unwrap();
        assert!(matches!(
            validate_log_spool_quota(&[entry(0, MAX_ATTEMPT_OUTPUT_BYTES), entry(1, 1)]),
            Err(AgentError::InvalidAssignment(_))
        ));
    }

    #[test]
    fn recovered_finalization_renews_before_its_fixed_deadline() {
        assert_eq!(
            recovery_renewal_interval(Duration::from_secs(60)),
            Duration::from_secs(15)
        );
        assert_eq!(
            recovery_renewal_interval(Duration::from_secs(5)),
            Duration::from_secs(5)
        );
    }

    #[tokio::test]
    async fn dropped_recovery_scope_cancels_lease_renewal() {
        let lease_stop = CancellationToken::new();
        let renewal_observer = lease_stop.clone();
        let recovery = tokio::spawn(async move {
            let _lease_stop_guard = lease_stop.drop_guard();
            std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;

        recovery.abort();
        assert!(recovery.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(1), renewal_observer.cancelled())
            .await
            .expect("dropping recovery must stop the detached lease renewal");
    }

    #[tokio::test]
    async fn result_spool_uses_post_containment_nonce_and_binds_completion_protocol() {
        let directory = tempfile::tempdir().unwrap();
        let workspace = PathBuf::from("org/attempt");
        let workload_result = directory.path().join(&workspace).join("spool/result.json");
        let predictable_agent_result = directory
            .path()
            .join(AGENT_RESULT_DIRECTORY)
            .join(&workspace)
            .join("result.json");
        fs::create_dir_all(workload_result.parent().unwrap())
            .await
            .unwrap();
        fs::write(&workload_result, b"workload-controlled")
            .await
            .unwrap();
        fs::create_dir_all(predictable_agent_result.parent().unwrap())
            .await
            .unwrap();
        fs::write(&predictable_agent_result, b"workload-controlled")
            .await
            .unwrap();

        let first = write_result(
            directory.path(),
            &workspace,
            DurableResult {
                workspace_transfer: None,
                outcome: WorkOutcome::Failed,
                exit_code: None,
                termination: "process_spawn_failed",
                reason: Some("process_spawn_failed: refused"),
                completion_protocol: WORK_COMPLETION_PROTOCOL,
                cancellation_outcome: None,
                steps: &[],
            },
        )
        .await
        .unwrap();
        let replay = write_result(
            directory.path(),
            &workspace,
            DurableResult {
                workspace_transfer: None,
                outcome: WorkOutcome::Failed,
                exit_code: None,
                termination: "process_spawn_failed",
                reason: Some("process_spawn_failed: refused"),
                completion_protocol: WORK_COMPLETION_PROTOCOL,
                cancellation_outcome: None,
                steps: &[],
            },
        )
        .await
        .unwrap();
        assert_ne!(first.relative_path, replay.relative_path);
        assert_eq!(first.digest, replay.digest);
        assert_eq!(first.bytes, replay.bytes);
        assert!(
            first
                .relative_path
                .starts_with(Path::new(AGENT_RESULT_DIRECTORY))
        );
        assert_eq!(
            fs::read(workload_result).await.unwrap(),
            b"workload-controlled"
        );
        assert_eq!(
            fs::read(predictable_agent_result).await.unwrap(),
            b"workload-controlled"
        );

        let result: PersistedResult = serde_json::from_slice(
            &fs::read(directory.path().join(&first.relative_path))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(result.completion_protocol, WORK_COMPLETION_PROTOCOL);
        assert_eq!(
            result.reason.as_deref(),
            Some("process_spawn_failed: refused")
        );
        assert!(result.cancellation_outcome.is_none());

        let cancellation = write_result(
            directory.path(),
            &workspace,
            DurableResult {
                workspace_transfer: None,
                outcome: WorkOutcome::Aborted,
                exit_code: None,
                termination: "recovered_cancellation",
                reason: None,
                completion_protocol: CANCELLATION_COMPLETION_PROTOCOL,
                cancellation_outcome: Some(CancellationOutcome::Terminated as i32),
                steps: &[],
            },
        )
        .await
        .unwrap();
        assert_ne!(first.relative_path, cancellation.relative_path);
        let cancellation_result: PersistedResult = serde_json::from_slice(
            &fs::read(directory.path().join(cancellation.relative_path))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            cancellation_result.completion_protocol,
            CANCELLATION_COMPLETION_PROTOCOL
        );
        assert_eq!(
            cancellation_result.cancellation_outcome,
            Some(CancellationOutcome::Terminated as i32)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn result_spool_rejects_a_symlinked_agent_parent() {
        let directory = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(
            outside.path(),
            directory.path().join(AGENT_RESULT_DIRECTORY),
        )
        .unwrap();

        assert!(matches!(
            write_result(
                directory.path(),
                Path::new("org/attempt"),
                DurableResult {
                    workspace_transfer: None,
                    outcome: WorkOutcome::Failed,
                    exit_code: None,
                    termination: "process_spawn_failed",
                    reason: Some("refused"),
                    completion_protocol: WORK_COMPLETION_PROTOCOL,
                    cancellation_outcome: None,
                    steps: &[],
                },
            )
            .await,
            Err(AgentError::InvalidAssignment(_))
        ));
        assert!(std::fs::read_dir(outside.path()).unwrap().next().is_none());
    }

    #[cfg(windows)]
    fn create_windows_junction(junction: &Path, target: &Path) {
        let status = std::process::Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(junction)
            .arg(target)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "failed to create junction {} -> {}",
            junction.display(),
            target.display()
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn result_spool_rejects_a_windows_junction_ancestor() {
        let directory = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let result_root = directory.path().join(AGENT_RESULT_DIRECTORY);
        let junction = result_root.join("org");
        std::fs::create_dir(&result_root).unwrap();
        create_windows_junction(&junction, outside.path());

        assert!(matches!(
            write_result(
                directory.path(),
                Path::new("org/attempt"),
                DurableResult {
                    workspace_transfer: None,
                    outcome: WorkOutcome::Failed,
                    exit_code: None,
                    termination: "process_spawn_failed",
                    reason: Some("refused"),
                    completion_protocol: WORK_COMPLETION_PROTOCOL,
                    cancellation_outcome: None,
                    steps: &[],
                },
            )
            .await,
            Err(AgentError::InvalidAssignment(_))
        ));
        assert!(std::fs::read_dir(outside.path()).unwrap().next().is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn result_spool_restores_agent_owned_traversal_after_containment() {
        let directory = tempfile::tempdir().unwrap();
        let result_root = directory.path().join(AGENT_RESULT_DIRECTORY);
        let organization = result_root.join("org");
        fs::create_dir_all(&organization).await.unwrap();
        fs::set_permissions(&organization, std::fs::Permissions::from_mode(0o000))
            .await
            .unwrap();
        fs::set_permissions(&result_root, std::fs::Permissions::from_mode(0o000))
            .await
            .unwrap();

        let result = write_result(
            directory.path(),
            Path::new("org/attempt"),
            DurableResult {
                workspace_transfer: None,
                outcome: WorkOutcome::Failed,
                exit_code: None,
                termination: "exited",
                reason: Some("restored"),
                completion_protocol: WORK_COMPLETION_PROTOCOL,
                cancellation_outcome: None,
                steps: &[],
            },
        )
        .await
        .unwrap();

        assert!(directory.path().join(result.relative_path).is_file());
        assert_eq!(
            fs::metadata(&result_root)
                .await
                .unwrap()
                .permissions()
                .mode()
                & 0o700,
            0o700
        );
    }

    #[tokio::test]
    async fn recovered_cancellation_preserves_an_existing_work_result() {
        let directory = tempfile::tempdir().unwrap();
        let workspace = PathBuf::from("org/stale-finalization");
        let result = write_result(
            directory.path(),
            &workspace,
            DurableResult {
                workspace_transfer: None,
                outcome: WorkOutcome::Succeeded,
                exit_code: Some(0),
                termination: "exited",
                reason: None,
                completion_protocol: WORK_COMPLETION_PROTOCOL,
                cancellation_outcome: None,
                steps: &[],
            },
        )
        .await
        .unwrap();
        let mut config = config();
        config.workspace_root = directory.path().to_owned();
        let attempt = mcloving_agent_runtime::ReconciliationAttempt {
            organization_id: "org".to_owned(),
            attempt_id: "stale-finalization".to_owned(),
            fence_token: 7,
            session_epoch: 3,
            payload_digest: [0x5a; 32],
            phase: AttemptPhase::Finalizing,
            workspace,
            process_id: None,
            process_birth_identity: None,
            current_step: None,
            logs: Vec::new(),
            result: Some(result),
        };

        assert!(
            !recovered_cancellation_requires_persistence(&config, &attempt)
                .await
                .unwrap()
        );
        assert!(
            recovered_attempt_has_durable_containment_proof(&config, &attempt)
                .await
                .unwrap()
        );

        let cancellation_result = write_result(
            directory.path(),
            &attempt.workspace,
            DurableResult {
                workspace_transfer: None,
                outcome: WorkOutcome::Aborted,
                exit_code: None,
                termination: "recovered_cancellation",
                reason: None,
                completion_protocol: CANCELLATION_COMPLETION_PROTOCOL,
                cancellation_outcome: Some(CancellationOutcome::Terminated as i32),
                steps: &[],
            },
        )
        .await
        .unwrap();
        let cancellation_attempt = mcloving_agent_runtime::ReconciliationAttempt {
            phase: AttemptPhase::Cancelling,
            result: Some(cancellation_result),
            ..attempt
        };
        assert!(
            recovered_attempt_has_durable_containment_proof(&config, &cancellation_attempt)
                .await
                .unwrap()
        );
        assert!(
            !recovered_cancellation_requires_persistence(&config, &cancellation_attempt)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn replayed_spools_are_preserved_until_terminal_and_then_reclaimed() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = config();
        config.workspace_root = directory.path().join("workspace");
        config.journal_path = directory.path().join("agent.db");
        let workspace = PathBuf::from(
            "00000000-0000-0000-0000-000000000123/\
             00000000-0000-0000-0000-000000000126/7",
        );
        let stdout_path = config
            .workspace_root
            .join(&workspace)
            .join("spool/stdout.log");
        let stderr_path = config
            .workspace_root
            .join(&workspace)
            .join("spool/stderr.log");
        fs::create_dir_all(stdout_path.parent().unwrap())
            .await
            .unwrap();
        fs::write(&stdout_path, b"stdout").await.unwrap();
        fs::write(&stderr_path, b"stderr").await.unwrap();
        let build_output = config
            .workspace_root
            .join(&workspace)
            .join("build/output.bin");
        fs::create_dir_all(build_output.parent().unwrap())
            .await
            .unwrap();
        fs::write(&build_output, b"ordinary-workspace-output")
            .await
            .unwrap();
        let logs = [
            SpoolEntry {
                sequence: 0,
                relative_path: workspace.join("spool/stdout.log"),
                digest: Sha256::digest(b"stdout").into(),
                bytes: 6,
            },
            SpoolEntry {
                sequence: 1,
                relative_path: workspace.join("spool/stderr.log"),
                digest: Sha256::digest(b"stderr").into(),
                bytes: 6,
            },
        ];
        let result = write_result(
            &config.workspace_root,
            &workspace,
            DurableResult {
                workspace_transfer: None,
                outcome: WorkOutcome::Succeeded,
                exit_code: Some(0),
                termination: "exited",
                reason: None,
                completion_protocol: WORK_COMPLETION_PROTOCOL,
                cancellation_outcome: None,
                steps: &[],
            },
        )
        .await
        .unwrap();
        let result_path = config.workspace_root.join(&result.relative_path);
        let acceptance = Acceptance {
            organization_id: "00000000-0000-0000-0000-000000000123".to_owned(),
            attempt_id: "00000000-0000-0000-0000-000000000126".to_owned(),
            fence_token: 7,
            session_epoch: 3,
            payload_digest: [0x42; 32],
            workspace: workspace.clone(),
        };
        let mut journal = Journal::open(&config.journal_path).unwrap();
        journal.accept(&acceptance).unwrap();
        journal
            .begin_finalization(&Finalization {
                organization_id: &acceptance.organization_id,
                attempt_id: &acceptance.attempt_id,
                fence_token: acceptance.fence_token,
                session_epoch: acceptance.session_epoch,
                phase: AttemptPhase::Finalizing,
                process_id: Some(42),
                logs: &logs,
                result: &result,
            })
            .unwrap();
        drop(journal);

        let attempt = Journal::open(&config.journal_path)
            .unwrap()
            .reconcile()
            .unwrap()
            .attempts
            .into_iter()
            .next()
            .unwrap();
        commit_replayed_phase(&config, &attempt, AttemptPhase::ReconciliationRequired)
            .await
            .unwrap();

        assert!(stdout_path.exists());
        assert!(stderr_path.exists());
        assert!(result_path.exists());
        assert!(config.workspace_root.join(&workspace).exists());
        let reconciled = Journal::open(&config.journal_path)
            .unwrap()
            .reconcile()
            .unwrap()
            .attempts;
        assert_eq!(reconciled.len(), 1);
        assert_eq!(reconciled[0].phase, AttemptPhase::ReconciliationRequired);

        commit_replayed_phase(&config, &attempt, AttemptPhase::Aborted)
            .await
            .unwrap();

        assert!(!stdout_path.exists());
        assert!(!stderr_path.exists());
        assert!(!result_path.exists());
        assert!(!config.workspace_root.join(&workspace).exists());
        assert!(
            Journal::open(&config.journal_path)
                .unwrap()
                .terminal_spools()
                .unwrap()
                .attempts
                .is_empty()
        );
        // The terminal journal row remains durable history.
        assert!(
            Journal::open(&config.journal_path)
                .unwrap()
                .reconcile()
                .unwrap()
                .attempts
                .is_empty()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn replaced_terminal_workspace_root_is_rejected_without_following() {
        let directory = tempfile::tempdir().unwrap();
        let workspace_root = directory.path().join("workspace");
        let workspace = PathBuf::from("organization/attempt/7");
        let displaced_root = directory.path().join("displaced-workspace");
        let outside = directory.path().join("outside");
        fs::create_dir_all(workspace_root.join(&workspace))
            .await
            .unwrap();
        fs::create_dir_all(outside.join(&workspace)).await.unwrap();
        fs::write(outside.join(&workspace).join("sentinel"), b"must-survive")
            .await
            .unwrap();
        fs::rename(&workspace_root, &displaced_root).await.unwrap();
        std::os::unix::fs::symlink(&outside, &workspace_root).unwrap();

        let error = remove_attempt_workspace(&workspace_root, &workspace)
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            AgentError::Execution(ExecutionError::ReplacedWorkspaceRoot)
        ));
        assert_eq!(
            fs::read(outside.join(&workspace).join("sentinel"))
                .await
                .unwrap(),
            b"must-survive"
        );
        assert!(displaced_root.join(&workspace).exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn replaced_terminal_workspace_leaf_is_removed_without_following() {
        let directory = tempfile::tempdir().unwrap();
        let workspace_root = directory.path().join("workspace");
        let workspace = PathBuf::from("organization/attempt/7");
        let workspace_path = workspace_root.join(&workspace);
        let displaced_path = workspace_root.join("displaced-attempt");
        let outside = directory.path().join("outside");
        fs::create_dir_all(&workspace_path).await.unwrap();
        fs::create_dir_all(&outside).await.unwrap();
        fs::write(outside.join("sentinel"), b"must-survive")
            .await
            .unwrap();
        fs::rename(&workspace_path, &displaced_path).await.unwrap();
        std::os::unix::fs::symlink(&outside, &workspace_path).unwrap();

        remove_attempt_workspace(&workspace_root, &workspace)
            .await
            .unwrap();

        assert!(fs::symlink_metadata(&workspace_path).await.is_err());
        assert_eq!(
            fs::read(outside.join("sentinel")).await.unwrap(),
            b"must-survive"
        );
        assert!(displaced_path.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn replaced_terminal_workspace_ancestor_is_removed_without_following() {
        let directory = tempfile::tempdir().unwrap();
        let workspace_root = directory.path().join("workspace");
        let workspace = PathBuf::from("organization/attempt/7");
        let workspace_path = workspace_root.join(&workspace);
        let organization_path = workspace_root.join("organization");
        let displaced_path = workspace_root.join("displaced-organization");
        let outside = directory.path().join("outside");
        fs::create_dir_all(&workspace_path).await.unwrap();
        fs::create_dir_all(&outside).await.unwrap();
        fs::write(outside.join("sentinel"), b"must-survive")
            .await
            .unwrap();
        fs::rename(&organization_path, &displaced_path)
            .await
            .unwrap();
        std::os::unix::fs::symlink(&outside, &organization_path).unwrap();

        remove_attempt_workspace(&workspace_root, &workspace)
            .await
            .unwrap();

        assert!(fs::symlink_metadata(&organization_path).await.is_err());
        assert_eq!(
            fs::read(outside.join("sentinel")).await.unwrap(),
            b"must-survive"
        );
        assert!(displaced_path.join("attempt/7").exists());

        // The organization namespace is reusable after the obstructing
        // symlink is removed, and a regular-file replacement is retired by the
        // same no-follow path.
        fs::create_dir_all(&workspace_path).await.unwrap();
        fs::remove_dir_all(&organization_path).await.unwrap();
        fs::write(&organization_path, b"replacement").await.unwrap();
        remove_attempt_workspace(&workspace_root, &workspace)
            .await
            .unwrap();
        assert!(fs::symlink_metadata(&organization_path).await.is_err());
        fs::create_dir_all(&workspace_path).await.unwrap();
        assert!(workspace_path.is_dir());
        assert_eq!(
            fs::read(outside.join("sentinel")).await.unwrap(),
            b"must-survive"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn permission_restricted_workspace_descendants_are_reclaimed() {
        let directory = tempfile::tempdir().unwrap();
        let workspace_root = directory.path().join("workspace");
        let workspace = PathBuf::from("organization/attempt/7");
        let workspace_path = workspace_root.join(&workspace);
        let locked = workspace_path.join("nested/locked");
        let outside = directory.path().join("outside");
        fs::create_dir_all(locked.join("deeper")).await.unwrap();
        fs::write(locked.join("deeper/output"), b"remove-me")
            .await
            .unwrap();
        fs::create_dir_all(&outside).await.unwrap();
        fs::write(outside.join("sentinel"), b"must-survive")
            .await
            .unwrap();
        std::os::unix::fs::symlink(&outside, locked.join("outside-link")).unwrap();
        fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000))
            .await
            .unwrap();

        remove_attempt_workspace(&workspace_root, &workspace)
            .await
            .unwrap();

        assert!(fs::symlink_metadata(&workspace_path).await.is_err());
        assert_eq!(
            fs::read(outside.join("sentinel")).await.unwrap(),
            b"must-survive"
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn replaced_terminal_workspace_root_junction_is_rejected_without_following() {
        let directory = tempfile::tempdir().unwrap();
        let workspace_root = directory.path().join("workspace");
        let workspace = PathBuf::from("organization/attempt/7");
        let displaced_root = directory.path().join("displaced-workspace");
        let outside = directory.path().join("outside");
        fs::create_dir_all(workspace_root.join(&workspace))
            .await
            .unwrap();
        fs::create_dir_all(outside.join(&workspace)).await.unwrap();
        fs::write(outside.join(&workspace).join("sentinel"), b"must-survive")
            .await
            .unwrap();
        fs::rename(&workspace_root, &displaced_root).await.unwrap();
        create_windows_junction(&workspace_root, &outside);

        let error = remove_attempt_workspace(&workspace_root, &workspace)
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            AgentError::Execution(ExecutionError::ReplacedWorkspaceRoot)
        ));
        assert_eq!(
            fs::read(outside.join(&workspace).join("sentinel"))
                .await
                .unwrap(),
            b"must-survive"
        );
        assert!(displaced_root.join(&workspace).exists());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn replaced_terminal_workspace_junction_is_removed_without_following() {
        let directory = tempfile::tempdir().unwrap();
        let workspace_root = directory.path().join("workspace");
        let workspace = PathBuf::from("organization/attempt/7");
        let workspace_path = workspace_root.join(&workspace);
        let organization_path = workspace_root.join("organization");
        let displaced_path = workspace_root.join("displaced-organization");
        let outside = directory.path().join("outside");
        fs::create_dir_all(&workspace_path).await.unwrap();
        fs::create_dir_all(&outside).await.unwrap();
        fs::write(outside.join("sentinel"), b"must-survive")
            .await
            .unwrap();
        fs::rename(&organization_path, &displaced_path)
            .await
            .unwrap();
        create_windows_junction(&organization_path, &outside);
        let junction_metadata = fs::symlink_metadata(&organization_path).await.unwrap();
        assert!(is_link_or_reparse_point(&junction_metadata));

        remove_attempt_workspace(&workspace_root, &workspace)
            .await
            .unwrap();

        assert!(fs::symlink_metadata(&organization_path).await.is_err());
        assert_eq!(
            fs::read(outside.join("sentinel")).await.unwrap(),
            b"must-survive"
        );
        assert!(displaced_path.join("attempt/7").exists());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn read_only_windows_workspace_artifacts_are_reclaimed() {
        let directory = tempfile::tempdir().unwrap();
        let workspace_root = directory.path().join("workspace");
        let workspace = PathBuf::from("organization/attempt/7");
        let workspace_path = workspace_root.join(&workspace);
        let artifact = workspace_path.join("artifact.txt");
        fs::create_dir_all(&workspace_path).await.unwrap();
        fs::write(&artifact, b"terminal-artifact").await.unwrap();
        let mut permissions = fs::metadata(&artifact).await.unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&artifact, permissions).await.unwrap();

        remove_attempt_workspace(&workspace_root, &workspace)
            .await
            .unwrap();

        assert!(fs::symlink_metadata(&workspace_path).await.is_err());
    }

    #[tokio::test]
    async fn spool_verification_streams_and_rejects_digest_mismatch() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("large.log");
        let content = vec![0x5a; MAX_LOG_CHUNK_BYTES + 17];
        fs::write(&path, &content).await.unwrap();
        let mut entry = SpoolEntry {
            sequence: 0,
            relative_path: PathBuf::from("large.log"),
            digest: Sha256::digest(&content).into(),
            bytes: u64::try_from(content.len()).unwrap(),
        };
        verify_spool_file(&path, &entry, "log").await.unwrap();
        entry.digest[0] ^= 0xff;
        assert!(matches!(
            verify_spool_file(&path, &entry, "log").await,
            Err(AgentError::InvalidAssignment(_))
        ));
    }
}

#[cfg(test)]
mod renewal_tests;

async fn execute_prepared<F>(
    request: &ExecutionRequest,
    cancellation: CancellationToken,
    redactions: &[Vec<u8>],
    helper: Option<&PreparedHelper>,
    on_spawn: F,
) -> Result<mcloving_agent_runtime::executor::ExecutionOutcome, ExecutionError>
where
    F: FnOnce(u32) -> Result<(), ExecutionError>,
{
    #[cfg(target_os = "linux")]
    if let Some(helper) = helper {
        let transform = |stdout: &[u8], stderr: &[u8]| helper.transform(stdout, stderr);
        return mcloving_agent_runtime::executor::execute_with_spawn_hook_and_private_io(
            request,
            cancellation,
            mcloving_agent_runtime::executor::PrivateExecutionIo {
                request: helper.request(),
                transform: &transform,
            },
            on_spawn,
        )
        .await;
    }
    #[cfg(not(target_os = "linux"))]
    if helper.is_some() {
        return Err(ExecutionError::InvalidPrivateIo);
    }
    execute_with_spawn_hook_and_redactions(request, cancellation, redactions, on_spawn).await
}
