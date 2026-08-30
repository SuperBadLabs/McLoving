//! Fenced controller-to-agent work execution.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::future::Future;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use mcloving_agent_protocol::RECOVERED_FINALIZATION_LEASE_SECONDS;
use mcloving_agent_protocol::wire::agent_control_client::AgentControlClient;
use mcloving_agent_protocol::wire::{
    CancellationCompletion, CancellationDisposition, CancellationOutcome, CredentialBinding,
    CredentialRequest, WorkAssignment, WorkAuthority, WorkCompletion, WorkLeaseRenewal,
    WorkLogChunk, WorkOutcome, WorkPoll, WorkReceipt,
};
use mcloving_agent_runtime::executor::{
    ExecutionError, ExecutionMode, ExecutionRequest, Termination, WorkspaceRootGuard,
    execute_with_spawn_hook_and_redactions, is_link_or_reparse_point, sync_directory,
};
use mcloving_agent_runtime::{
    Acceptance, AttemptPhase, Finalization, Journal, MAX_ATTEMPT_OUTPUT_BYTES, ProcessIdentity,
    SpoolEntry,
};
use mcloving_domain::ConnectorIntentSpec;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use tonic::transport::Channel;
use uuid::Uuid;

use crate::{AgentConfig, AgentError, process_birth_identity_for};

const MAX_LOG_CHUNK_BYTES: usize = 1_048_576;
const MAX_LOG_CHUNKS_PER_ATTEMPT: u64 = 66;
const MAX_RESULT_SPOOL_BYTES: u64 = 65_536;
const MAX_EXECUTION_TIMEOUT_SECONDS: u64 = 7 * 24 * 60 * 60;
const AGENT_RESULT_DIRECTORY: &str = ".agent-results";
const WORK_COMPLETION_PROTOCOL: &str = "work";
const CANCELLATION_COMPLETION_PROTOCOL: &str = "cancellation";

#[derive(Deserialize)]
struct ExecutionSpec {
    version: u16,
    steps: Vec<ProcessSpec>,
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
    outcome: String,
    exit_code: Option<i32>,
    termination: String,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default = "default_completion_protocol")]
    completion_protocol: String,
    cancellation_outcome: Option<i32>,
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

struct ValidatedAssignment {
    authority: WorkAuthority,
    workspace: PathBuf,
    payload_digest: [u8; 32],
    process: ProcessSpec,
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
}

struct DurableResult<'a> {
    outcome: WorkOutcome,
    exit_code: Option<i32>,
    termination: &'a str,
    reason: Option<&'a str>,
    completion_protocol: &'a str,
    cancellation_outcome: Option<i32>,
}

struct LeaseRenewalControl {
    lease_seconds: u32,
    renewal_interval: Duration,
    lease_started_at: tokio::time::Instant,
    lease_window: Duration,
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

/// Classifies a renewal RPC rejection status: a stale-session fencing
/// rejection is named as such rather than as a transport failure.
fn renewal_status_cause(status: &tonic::Status) -> &'static str {
    if status.code() == tonic::Code::FailedPrecondition
        && status.message().contains("stale agent session epoch")
    {
        "renewal_session_stale"
    } else {
        "renewal_transport_failure"
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
    stop: CancellationToken,
) -> Result<PollOutcome, AgentError> {
    let offer = tokio::select! {
        () = stop.cancelled() => return Ok(PollOutcome::Idle),
        response = poll_rpc(
            Duration::from_secs(u64::from(config.lease_seconds)),
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
    match validate_assignment(config, session_epoch, assignment)? {
        AssignmentDisposition::Runnable(assignment) => {
            run_assignment(config, client, session_epoch, *assignment, stop).await?;
            Ok(PollOutcome::Progressed)
        }
        AssignmentDisposition::ForAnotherRuntime(reason) => {
            // Decline without terminalizing. The lease lapses, the controller
            // requeues, and an agent with the matching runtime claims it.
            eprintln!("declining_assignment: {reason}");
            Ok(PollOutcome::Declined)
        }
        AssignmentDisposition::Unsupported(refusal) => {
            refuse_unsupported_assignment(config, client, session_epoch, refusal, stop).await?;
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
        let stream = spool_stream(entry)?;
        sequence = publish_spool(
            &mut publication,
            stream,
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
            let summary = if let Some(reason) = result.reason {
                serde_json::to_vec(&json!({
                    "reason": reason,
                    "result_sha256": hex(&result_entry.digest),
                }))?
            } else {
                serde_json::to_vec(&json!({
                    "exit_code": result.exit_code,
                    "termination": result.termination,
                    "result_sha256": hex(&result_entry.digest),
                }))?
            };
            let published = published_work_outcome(
                authority_rpc(
                    control,
                    publication.client.complete_work(WorkCompletion {
                        authority: Some(authority.clone()),
                        outcome: outcome as i32,
                        summary_json: summary,
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

fn validate_assignment(
    config: &AgentConfig,
    session_epoch: u64,
    assignment: WorkAssignment,
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
    let calculated: [u8; 32] = Sha256::digest(&assignment.execution_spec_json).into();
    if payload_digest != calculated {
        return Err(AgentError::InvalidAssignment(
            "execution payload digest does not match".to_owned(),
        ));
    }
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
                AssignmentDisposition::Runnable(Box::new(ValidatedAssignment {
                    authority,
                    workspace,
                    payload_digest,
                    process,
                }))
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
    Process(ProcessSpec),
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
    if connector_intent_payload(execution_spec_json) {
        return SpecClassification::ForAnotherRuntime(
            "connector-intent work requires a controller-owned effect runtime",
        );
    }
    match supported_process_spec(execution_spec_json) {
        Ok(process) => SpecClassification::Process(process),
        Err(detail) => SpecClassification::Unsupported(bounded_refusal_detail(detail)),
    }
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
async fn refuse_unsupported_assignment(
    config: &AgentConfig,
    client: &mut AgentControlClient<Channel>,
    session_epoch: u64,
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
    require_work_receipt(
        lease_window_rpc(lease_window, client.accept_work(refusal.authority.clone())).await?,
        session_epoch,
    )?;
    let lease_started_at = tokio::time::Instant::now();
    let lease = lease_deadline_rpc(
        lease_started_at + lease_rpc_budget(lease_window),
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
            execution_cancellation,
            authority_lost: authority_lost.clone(),
            stop: lease_stop.clone(),
            // A refusal spawns no process, so lease loss can cancel no step
            // and nothing reads this back. Its own cell, like every other
            // processless path.
            loss_reason: Arc::new(OnceLock::new()),
        },
    ));
    // Cancellation can already have committed before this immediate renewal
    // answered. The normal assignment path publishes that as aborted, and a
    // cancelled build must not be reported as an execution-spec failure
    // instead, so the refusal yields to it.
    let (outcome, reason) = if lease.cancellation_requested {
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

async fn run_assignment(
    config: &AgentConfig,
    client: &mut AgentControlClient<Channel>,
    session_epoch: u64,
    assignment: ValidatedAssignment,
    stop: CancellationToken,
) -> Result<(), AgentError> {
    let organization = assignment.authority.organization_id.clone();
    let attempt = assignment.authority.attempt_id.clone();
    let fence = assignment.authority.fence_token;
    let mut journal = Journal::open(&config.journal_path)?;
    journal.accept(&Acceptance {
        organization_id: organization.clone(),
        attempt_id: attempt.clone(),
        fence_token: fence,
        session_epoch,
        payload_digest: assignment.payload_digest,
        workspace: assignment.workspace.clone(),
    })?;

    let lease_window = Duration::from_secs(u64::from(config.lease_seconds));
    require_work_receipt(
        lease_window_rpc(
            lease_window,
            client.accept_work(assignment.authority.clone()),
        )
        .await?,
        session_epoch,
    )?;
    let lease_started_at = tokio::time::Instant::now();
    let lease = lease_deadline_rpc(
        lease_started_at + lease_rpc_budget(lease_window),
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
    if lease.cancellation_requested {
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
            execution_cancellation: execution_cancellation.clone(),
            authority_lost: authority_lost.clone(),
            stop: lease_stop.clone(),
            loss_reason: lease_loss_reason.clone(),
        },
    ));
    let process = assignment.process;
    let credentials = if process.credentials.is_empty() {
        Vec::new()
    } else {
        match wait_for_credentials(
            client,
            &assignment.authority,
            &process.credentials,
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
    let execution_environment = match execution_environment(process.env, credentials) {
        Ok(environment) => environment,
        Err(error) => {
            lease_stop.cancel();
            let _ = lease_task.await;
            return Err(error);
        }
    };
    let request = ExecutionRequest {
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
        output_limit_bytes: Some(MAX_ATTEMPT_OUTPUT_BYTES),
        timeout: Duration::from_secs(process.timeout_seconds.unwrap_or(3_600)),
        termination_grace: config.termination_grace,
    };
    let execution = execute_with_spawn_hook_and_redactions(
        &request,
        execution_cancellation.clone(),
        &execution_environment.redactions,
        |process_id| {
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
        },
    )
    .await;
    let completion_result: Result<(), AgentError> = async {
        let outcome = match execution {
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
                return finalize_without_process(
                    config,
                    client,
                    &mut journal,
                    ProcesslessCompletion {
                        authority: &assignment.authority,
                        workspace: &assignment.workspace,
                        session_epoch,
                        outcome: WorkOutcome::Failed,
                        reason: format!("process_spawn_failed: {error}"),
                    },
                    AuthorityRpcControl {
                        authority_lost: &authority_lost,
                        stop: &stop,
                        lease_window,
                    },
                )
                .await;
            }
        };
        validate_log_spool_quota(&[outcome.stdout.clone(), outcome.stderr.clone()])?;
        let terminal = match outcome.termination {
            Termination::Cancelled => WorkOutcome::Aborted,
            Termination::TimedOut | Termination::OutputLimitExceeded => WorkOutcome::Failed,
            Termination::Exited if outcome.exit_code == Some(0) => WorkOutcome::Succeeded,
            Termination::Exited => WorkOutcome::Failed,
        };
        // A cancellation forced by lease loss is named in the durable result so
        // the replayed terminal summary records why the step was cut short.
        let lease_loss = (outcome.termination == Termination::Cancelled)
            .then(|| lease_loss_reason.get())
            .flatten()
            .filter(|cause| **cause != CONTROLLER_CANCELLATION_TRIGGER)
            .map(|cause| format!("lease_lost_during_execution:{cause}"));
        let result = write_result(
            &config.workspace_root,
            &assignment.workspace,
            DurableResult {
                outcome: terminal,
                exit_code: outcome.exit_code,
                termination: termination_name(outcome.termination),
                reason: lease_loss.as_deref(),
                completion_protocol: WORK_COMPLETION_PROTOCOL,
                cancellation_outcome: None,
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
            logs: &[outcome.stdout.clone(), outcome.stderr.clone()],
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
        let next_sequence = publish_spool(
            &mut publication,
            "stdout",
            &config.workspace_root,
            &outcome.stdout,
            0,
        )
        .await?;
        publish_spool(
            &mut publication,
            "stderr",
            &config.workspace_root,
            &outcome.stderr,
            next_sequence,
        )
        .await?;
        let summary = serde_json::to_vec(&json!({
            "exit_code": outcome.exit_code,
            "termination": termination_name(outcome.termination),
            "result_sha256": hex(&result.digest),
        }))?;
        let completion = authority_rpc(
            publication.control,
            publication.client.complete_work(WorkCompletion {
                authority: Some(assignment.authority.clone()),
                outcome: terminal as i32,
                summary_json: summary,
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
            &[outcome.stdout.clone(), outcome.stderr.clone()],
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
        execution_cancellation,
        authority_lost,
        stop,
        loss_reason,
    } = control;
    let mut lease_started_at = lease_started_at;
    let mut lease_window = lease_window;
    loop {
        tokio::select! {
            () = stop.cancelled() => return Ok(()),
            () = tokio::time::sleep_until(lease_started_at + renewal_interval) => {}
        }
        let deadline = lease_started_at + lease_rpc_budget(lease_window);
        let renewal = tokio::select! {
            () = stop.cancelled() => return Ok(()),
            result = tokio::time::timeout_at(
                deadline,
                client.renew_work_lease(WorkLeaseRenewal {
                    authority: Some(authority.clone()),
                    lease_seconds,
                }),
            ) => result,
        };
        // A stop request makes any concurrent renewal failure moot: the
        // attempt is already finalized and the session must not be torn down
        // over a lease this task was told to release. The failure arms below
        // re-check because the select above is unbiased and the RPC may have
        // failed in the same poll that observed the stop.
        let receipt = match renewal {
            Err(_) => {
                if stop.is_cancelled() {
                    return Ok(());
                }
                record_lease_loss(&loss_reason, "renewal_timeout");
                execution_cancellation.cancel();
                authority_lost.cancel();
                return Err(AgentError::LeaseRenewalTimeout);
            }
            Ok(Ok(response)) => response.into_inner(),
            Ok(Err(error)) => {
                if stop.is_cancelled() {
                    return Ok(());
                }
                record_lease_loss(&loss_reason, renewal_status_cause(&error));
                execution_cancellation.cancel();
                authority_lost.cancel();
                return Err(error.into());
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
        lease_started_at = tokio::time::Instant::now();
        lease_window = Duration::from_secs(u64::from(lease_seconds));
    }
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

async fn publish_spool(
    publication: &mut PublicationContext<'_>,
    stream: &str,
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
    let mut published = false;
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
                }),
            )
            .await?,
            publication.session_epoch,
        )?;
        published = true;
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
    if !published {
        if first_sequence >= MAX_LOG_CHUNKS_PER_ATTEMPT {
            return Err(AgentError::InvalidAssignment(
                "log chunk count exceeds the per-attempt quota".to_owned(),
            ));
        }
        require_work_receipt(
            authority_rpc(
                publication.control,
                publication.client.publish_log(WorkLogChunk {
                    authority: Some(publication.authority.clone()),
                    sequence: first_sequence,
                    stream: stream.to_owned(),
                    content: Vec::new(),
                }),
            )
            .await?,
            publication.session_epoch,
        )?;
        sequence = sequence.checked_add(1).ok_or_else(|| {
            AgentError::InvalidAssignment("log sequence exceeds wire bounds".to_owned())
        })?;
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
    remove_attempt_workspace(&config.workspace_root, workspace).await?;
    for entry in logs.iter().chain(result) {
        remove_spool_file(&config.workspace_root, entry).await?;
    }
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
) -> Result<(), AgentError> {
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

async fn remove_spool_file(workspace_root: &Path, entry: &SpoolEntry) -> Result<(), AgentError> {
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

async fn remove_terminal_relative_path(
    workspace_root: &Path,
    relative_path: &Path,
) -> Result<(), AgentError> {
    let root_metadata = match fs::symlink_metadata(workspace_root).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !root_metadata.is_dir() || is_link_or_reparse_point(&root_metadata) {
        return Err(ExecutionError::ReplacedWorkspaceRoot.into());
    }
    restore_directory_access(workspace_root, &root_metadata).await?;
    let workspace_root_guard = WorkspaceRootGuard::open(workspace_root)?;
    workspace_root_guard.ensure_original(workspace_root)?;

    let path = workspace_root.join(relative_path);
    let mut current = workspace_root.to_owned();
    let mut components = relative_path.components().peekable();
    while let Some(component) = components.next() {
        workspace_root_guard.ensure_original(workspace_root)?;
        let Component::Normal(component) = component else {
            unreachable!("terminal path was validated by its caller");
        };
        current.push(component);
        let is_leaf = components.peek().is_none();
        match fs::symlink_metadata(&current).await {
            Ok(metadata)
                if !is_leaf && metadata.is_dir() && !is_link_or_reparse_point(&metadata) =>
            {
                restore_directory_access(&current, &metadata).await?;
            }
            Ok(metadata) if !is_leaf => {
                // An ancestor was replaced. Remove only the replacement entry;
                // platform-specific unlinking never follows its target.
                remove_terminal_replacement_entry(&current, &metadata).await?;
                sync_directory(
                    current
                        .parent()
                        .expect("a normalized relative path has a parent"),
                )?;
                break;
            }
            Ok(metadata) if metadata.is_dir() && !is_link_or_reparse_point(&metadata) => {
                remove_directory_tree_no_follow(&current).await?;
                sync_directory(
                    current
                        .parent()
                        .expect("a normalized relative path has a parent"),
                )?;
                break;
            }
            Ok(metadata) => {
                // Remove the replacement entry itself, never its target.
                remove_terminal_replacement_entry(&current, &metadata).await?;
                sync_directory(
                    current
                        .parent()
                        .expect("a normalized relative path has a parent"),
                )?;
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(error.into()),
        }
    }
    workspace_root_guard.ensure_original(workspace_root)?;
    prune_empty_spool_directories(workspace_root, &workspace_root_guard, path.parent()).await
}

async fn remove_terminal_replacement_entry(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), std::io::Error> {
    #[cfg(windows)]
    {
        if windows_entry_is_directory(metadata) {
            // Windows removes directory junctions and directory symlinks with
            // RemoveDirectory; this deletes the reparse point, not its target.
            fs::remove_dir(path).await
        } else {
            if !is_link_or_reparse_point(metadata) {
                restore_file_deletion_access(path, metadata).await?;
            }
            fs::remove_file(path).await
        }
    }
    #[cfg(not(windows))]
    {
        let _ = metadata;
        fs::remove_file(path).await
    }
}

#[cfg(windows)]
// Windows `readonly` is a single file attribute; clearing it does not broaden
// Unix mode bits because this implementation is not compiled on Unix.
#[allow(clippy::permissions_set_readonly_false)]
async fn restore_file_deletion_access(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), std::io::Error> {
    if metadata.permissions().readonly() {
        let mut permissions = metadata.permissions();
        permissions.set_readonly(false);
        fs::set_permissions(path, permissions).await?;
    }
    Ok(())
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

async fn remove_directory_tree_no_follow(path: &Path) -> Result<(), std::io::Error> {
    let root = path.to_owned();
    tokio::task::spawn_blocking(move || remove_directory_tree_no_follow_sync(&root))
        .await
        .map_err(|error| std::io::Error::other(format!("workspace cleanup task failed: {error}")))?
}

fn remove_directory_tree_no_follow_sync(root: &Path) -> Result<(), std::io::Error> {
    let mut stack = vec![(root.to_owned(), false)];
    while let Some((path, expanded)) = stack.pop() {
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if is_link_or_reparse_point(&metadata) {
            remove_terminal_replacement_entry_sync(&path, &metadata)?;
            continue;
        }
        if !metadata.is_dir() {
            restore_file_deletion_access_sync(&path, &metadata)?;
            std::fs::remove_file(&path)?;
            continue;
        }
        if expanded {
            std::fs::remove_dir(&path)?;
            continue;
        }

        restore_directory_access_sync(&path, &metadata)?;
        stack.push((path.clone(), true));
        for entry in std::fs::read_dir(&path)? {
            stack.push((entry?.path(), false));
        }
    }
    Ok(())
}

#[cfg(windows)]
// See the async counterpart: this is Windows attribute recovery, not Unix
// permission widening.
#[allow(clippy::permissions_set_readonly_false)]
fn restore_file_deletion_access_sync(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), std::io::Error> {
    if metadata.permissions().readonly() {
        let mut permissions = metadata.permissions();
        permissions.set_readonly(false);
        std::fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

#[cfg(not(windows))]
fn restore_file_deletion_access_sync(
    _path: &Path,
    _metadata: &std::fs::Metadata,
) -> Result<(), std::io::Error> {
    Ok(())
}

fn restore_directory_access_sync(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        let mut permissions = metadata.permissions();
        permissions.set_mode(permissions.mode() | 0o700);
        std::fs::set_permissions(path, permissions)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, metadata);
        Ok(())
    }
}

fn remove_terminal_replacement_entry_sync(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), std::io::Error> {
    #[cfg(windows)]
    {
        if windows_entry_is_directory(metadata) {
            std::fs::remove_dir(path)
        } else {
            std::fs::remove_file(path)
        }
    }
    #[cfg(not(windows))]
    {
        let _ = metadata;
        std::fs::remove_file(path)
    }
}

#[cfg(windows)]
fn windows_entry_is_directory(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    metadata.file_attributes() & FILE_ATTRIBUTE_DIRECTORY != 0
}

async fn prune_empty_spool_directories(
    workspace_root: &Path,
    workspace_root_guard: &WorkspaceRootGuard,
    start: Option<&Path>,
) -> Result<(), AgentError> {
    let mut current = start.map(Path::to_owned);
    while let Some(directory) = current {
        workspace_root_guard.ensure_original(workspace_root)?;
        if directory == workspace_root {
            break;
        }
        if !directory.starts_with(workspace_root) {
            return Err(AgentError::InvalidAssignment(
                "terminal spool parent escapes the workspace root".to_owned(),
            ));
        }
        let parent = directory.parent().map(Path::to_owned);
        match fs::remove_dir(&directory).await {
            Ok(()) => {
                if let Some(parent) = &parent {
                    sync_directory(parent)?;
                }
                current = parent;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                current = parent;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::DirectoryNotEmpty | std::io::ErrorKind::PermissionDenied
                ) =>
            {
                break;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

async fn verify_spool_file(path: &Path, entry: &SpoolEntry, kind: &str) -> Result<(), AgentError> {
    let mut file = fs::File::open(path).await?;
    let mut buffer = vec![0_u8; MAX_LOG_CHUNK_BYTES];
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

fn spool_stream(entry: &SpoolEntry) -> Result<&'static str, AgentError> {
    match entry
        .relative_path
        .file_name()
        .and_then(|name| name.to_str())
    {
        Some("stdout.log") => Ok("stdout"),
        Some("stderr.log") => Ok("stderr"),
        _ => Err(AgentError::InvalidAssignment(
            "journal log spool has an unknown stream path".to_owned(),
        )),
    }
}

async fn write_result(
    workspace_root: &Path,
    workspace: &Path,
    result: DurableResult<'_>,
) -> Result<SpoolEntry, AgentError> {
    let DurableResult {
        outcome,
        exit_code,
        termination,
        reason,
        completion_protocol,
        cancellation_outcome,
    } = result;
    let relative_parent = PathBuf::from(AGENT_RESULT_DIRECTORY)
        .join(workspace)
        .join(Uuid::new_v4().simple().to_string());
    let parent = create_result_directory(workspace_root, &relative_parent).await?;
    let relative_path = relative_parent.join("result.json");
    let path = parent.join("result.json");
    let content = serde_json::to_vec(&json!({
        "outcome": outcome_name(outcome),
        "exit_code": exit_code,
        "termination": termination,
        "reason": reason,
        "completion_protocol": completion_protocol,
        "cancellation_outcome": cancellation_outcome,
    }))?;
    match fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .await
    {
        Ok(mut file) => {
            file.write_all(&content).await?;
            file.sync_all().await?;
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
    sync_result_directory_chain(workspace_root, &parent)?;
    Ok(SpoolEntry {
        sequence: 0,
        relative_path,
        digest: Sha256::digest(&content).into(),
        bytes: u64::try_from(content.len()).map_err(|_| {
            AgentError::InvalidAssignment("result length exceeds wire bounds".to_owned())
        })?,
    })
}

async fn create_result_directory(
    workspace_root: &Path,
    relative_parent: &Path,
) -> Result<PathBuf, AgentError> {
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
    for component in relative_parent.components() {
        let Component::Normal(component) = component else {
            unreachable!("relative result parent was validated above");
        };
        directory.push(component);
        match fs::create_dir(&directory).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
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
    Ok(canonical_parent)
}

fn sync_result_directory_chain(workspace_root: &Path, parent: &Path) -> Result<(), AgentError> {
    let canonical_root = std::fs::canonicalize(workspace_root)?;
    if !parent.starts_with(&canonical_root) {
        return Err(AgentError::InvalidAssignment(
            "result spool escapes the workspace root".to_owned(),
        ));
    }
    for directory in parent.ancestors() {
        sync_directory(directory)?;
        if directory == canonical_root {
            return Ok(());
        }
    }
    Err(AgentError::InvalidAssignment(
        "result spool has no durable workspace-root ancestor".to_owned(),
    ))
}

pub(super) async fn persist_recovered_cancellation(
    config: &AgentConfig,
    journal: &mut Journal,
    attempt: &mcloving_agent_runtime::ReconciliationAttempt,
    cancellation_outcome: i32,
) -> Result<(), AgentError> {
    let result = write_result(
        &config.workspace_root,
        &attempt.workspace,
        DurableResult {
            outcome: WorkOutcome::Aborted,
            exit_code: None,
            termination: "recovered_cancellation",
            reason: None,
            completion_protocol: CANCELLATION_COMPLETION_PROTOCOL,
            cancellation_outcome: Some(cancellation_outcome),
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
    } = completion;
    let result = write_result(
        &config.workspace_root,
        workspace,
        DurableResult {
            outcome,
            exit_code: None,
            termination: &reason,
            reason: Some(&reason),
            completion_protocol: WORK_COMPLETION_PROTOCOL,
            cancellation_outcome: None,
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
    let published = published_work_outcome(
        authority_rpc(
            control,
            client.complete_work(WorkCompletion {
                authority: Some(authority.clone()),
                outcome: outcome as i32,
                summary_json: serde_json::to_vec(&json!({
                    "reason": reason,
                    "result_sha256": hex(&result.digest),
                }))?,
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

    fn config() -> AgentConfig {
        AgentConfig {
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
            organization_id: "00000000-0000-0000-0000-000000000123".to_owned(),
            build_id: "00000000-0000-0000-0000-000000000124".to_owned(),
            node_id: "00000000-0000-0000-0000-000000000125".to_owned(),
            attempt_id: "00000000-0000-0000-0000-000000000126".to_owned(),
            fence_token: (7_u64 << 32) | 9,
            execution_spec_json: spec.to_vec(),
            payload_digest: Sha256::digest(spec).to_vec(),
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
    fn lease_rpc_budget_expires_before_the_controller_lease() {
        assert_eq!(
            lease_rpc_budget(Duration::from_secs(30)),
            Duration::from_secs(29)
        );
        assert_eq!(lease_rpc_budget(Duration::from_millis(500)), Duration::ZERO);
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
            .process
            .mode,
            ProcessMode::WindowsCmd
        ));
        let powershell = br#"{"version":1,"steps":[{"kind":"process","mode":"powershell","program":"build.ps1"}]}"#;
        assert!(matches!(
            runnable(
                validate_assignment(&config(), 1, assignment(powershell))
                    .expect("accept explicit PowerShell mode")
            )
            .process
            .mode,
            ProcessMode::PowerShell
        ));
        let legacy_powershell = br#"{"version":1,"steps":[{"kind":"process","mode":"power_shell","program":"build.ps1"}]}"#;
        assert!(matches!(
            runnable(
                validate_assignment(&config(), 1, assignment(legacy_powershell))
                    .expect("accept the protocol v1.0 PowerShell spelling")
            )
            .process
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
                outcome: WorkOutcome::Failed,
                exit_code: None,
                termination: "process_spawn_failed",
                reason: Some("process_spawn_failed: refused"),
                completion_protocol: WORK_COMPLETION_PROTOCOL,
                cancellation_outcome: None,
            },
        )
        .await
        .unwrap();
        let replay = write_result(
            directory.path(),
            &workspace,
            DurableResult {
                outcome: WorkOutcome::Failed,
                exit_code: None,
                termination: "process_spawn_failed",
                reason: Some("process_spawn_failed: refused"),
                completion_protocol: WORK_COMPLETION_PROTOCOL,
                cancellation_outcome: None,
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
                outcome: WorkOutcome::Aborted,
                exit_code: None,
                termination: "recovered_cancellation",
                reason: None,
                completion_protocol: CANCELLATION_COMPLETION_PROTOCOL,
                cancellation_outcome: Some(CancellationOutcome::Terminated as i32),
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
                    outcome: WorkOutcome::Failed,
                    exit_code: None,
                    termination: "process_spawn_failed",
                    reason: Some("refused"),
                    completion_protocol: WORK_COMPLETION_PROTOCOL,
                    cancellation_outcome: None,
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
                    outcome: WorkOutcome::Failed,
                    exit_code: None,
                    termination: "process_spawn_failed",
                    reason: Some("refused"),
                    completion_protocol: WORK_COMPLETION_PROTOCOL,
                    cancellation_outcome: None,
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
                outcome: WorkOutcome::Failed,
                exit_code: None,
                termination: "exited",
                reason: Some("restored"),
                completion_protocol: WORK_COMPLETION_PROTOCOL,
                cancellation_outcome: None,
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
                outcome: WorkOutcome::Succeeded,
                exit_code: Some(0),
                termination: "exited",
                reason: None,
                completion_protocol: WORK_COMPLETION_PROTOCOL,
                cancellation_outcome: None,
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
                outcome: WorkOutcome::Aborted,
                exit_code: None,
                termination: "recovered_cancellation",
                reason: None,
                completion_protocol: CANCELLATION_COMPLETION_PROTOCOL,
                cancellation_outcome: Some(CancellationOutcome::Terminated as i32),
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
                outcome: WorkOutcome::Succeeded,
                exit_code: Some(0),
                termination: "exited",
                reason: None,
                completion_protocol: WORK_COMPLETION_PROTOCOL,
                cancellation_outcome: None,
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
        assert!(windows_entry_is_directory(&junction_metadata));

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
