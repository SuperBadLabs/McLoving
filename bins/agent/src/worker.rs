//! Fenced controller-to-agent work execution.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::future::Future;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use mcloving_agent_protocol::RECOVERED_FINALIZATION_LEASE_SECONDS;
use mcloving_agent_protocol::wire::agent_control_client::AgentControlClient;
use mcloving_agent_protocol::wire::{
    CancellationCompletion, CancellationDisposition, CancellationOutcome, WorkAssignment,
    WorkAuthority, WorkCompletion, WorkLeaseRenewal, WorkLogChunk, WorkOutcome, WorkPoll,
};
use mcloving_agent_runtime::executor::{
    ExecutionError, ExecutionMode, ExecutionRequest, Termination, execute_with_spawn_hook,
    sync_directory,
};
use mcloving_agent_runtime::{
    Acceptance, AttemptPhase, Finalization, Journal, ProcessIdentity, SpoolEntry,
};
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
const MAX_TOTAL_LOG_SPOOL_BYTES: u64 = 64 * 1_048_576;
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
    timeout_seconds: Option<u64>,
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
    PowerShell,
}

struct ValidatedAssignment {
    authority: WorkAuthority,
    workspace: PathBuf,
    payload_digest: [u8; 32],
    process: ProcessSpec,
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
}

struct PublicationContext<'a> {
    client: &'a mut AgentControlClient<Channel>,
    authority: &'a WorkAuthority,
    session_epoch: u64,
    authority_lost: &'a CancellationToken,
}

pub(super) async fn poll_and_run_one(
    config: &AgentConfig,
    client: &mut AgentControlClient<Channel>,
    session_epoch: u64,
    stop: CancellationToken,
) -> Result<(), AgentError> {
    let offer = tokio::select! {
        () = stop.cancelled() => return Ok(()),
        response = client.poll_work(WorkPoll {
            agent_id: config.agent_id.clone(),
            session_epoch,
            organization_id: config.organization_id.clone(),
            lease_seconds: config.lease_seconds,
        }) => response?,
    }
    .into_inner();
    ensure_session(offer.session_epoch, session_epoch)?;
    let Some(assignment) = offer.assignment else {
        return Ok(());
    };
    let assignment = validate_assignment(config, session_epoch, assignment)?;
    run_assignment(config, client, session_epoch, assignment, stop).await
}

pub(super) async fn recover_finalizations(
    config: &AgentConfig,
    client: &mut AgentControlClient<Channel>,
    session_epoch: u64,
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
            },
        ));
        let replay_result = replay_finalization(
            config,
            client,
            session_epoch,
            &attempt,
            authority,
            &authority_lost,
        )
        .await;
        lease_stop.cancel();
        let lease_result = lease_task.await;
        let terminal = replay_result?;
        Journal::open(&config.journal_path)?.transition(
            &attempt.organization_id,
            &attempt.attempt_id,
            attempt.fence_token,
            attempt.session_epoch,
            terminal,
            attempt.process_id,
        )?;
        reclaim_attempt_spools(config, &attempt).await?;
        // The controller's terminal acknowledgement is authoritative even
        // when a concurrent renewal observes that the terminal lease is no
        // longer renewable. Never strand an acknowledged replay locally.
        lease_result.map_err(|error| {
            AgentError::InvalidAssignment(format!("lease task failed: {error}"))
        })??;
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
    authority_lost: &CancellationToken,
) -> Result<AttemptPhase, AgentError> {
    validate_log_spool_quota(&attempt.logs)?;
    let mut sequence = 0;
    let mut publication = PublicationContext {
        client,
        authority: &authority,
        session_epoch,
        authority_lost,
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
            require_work_receipt(
                authority_rpc(
                    authority_lost,
                    publication.client.complete_work(WorkCompletion {
                        authority: Some(authority.clone()),
                        outcome: outcome as i32,
                        summary_json: summary,
                    }),
                )
                .await?,
                session_epoch,
            )?;
            terminal_phase(outcome)
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
                authority_lost,
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
                Ok(CancellationDisposition::Completed | CancellationDisposition::RetireStale) => {
                    Ok(AttemptPhase::Aborted)
                }
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
) -> Result<ValidatedAssignment, AgentError> {
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
    let spec: ExecutionSpec = serde_json::from_slice(&assignment.execution_spec_json)?;
    if spec.version != 1 || spec.steps.len() != 1 || spec.steps[0].kind != "process" {
        return Err(AgentError::UnsupportedSpec);
    }
    if !matches!(
        spec.steps[0].timeout_seconds,
        None | Some(1..=MAX_EXECUTION_TIMEOUT_SECONDS)
    ) {
        return Err(AgentError::InvalidAssignment(format!(
            "process timeout must be between 1 and {MAX_EXECUTION_TIMEOUT_SECONDS} seconds"
        )));
    }
    let workspace = PathBuf::from(format!(
        "{}/{}/{}",
        assignment.organization_id, assignment.attempt_id, assignment.fence_token
    ));
    Ok(ValidatedAssignment {
        authority: WorkAuthority {
            agent_id: config.agent_id.clone(),
            session_epoch,
            organization_id: assignment.organization_id,
            attempt_id: assignment.attempt_id,
            fence_token: assignment.fence_token,
        },
        workspace,
        payload_digest,
        process: spec
            .steps
            .into_iter()
            .next()
            .ok_or(AgentError::UnsupportedSpec)?,
    })
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
            &authority_lost,
        )
        .await;
        lease_stop.cancel();
        let lease_result = lease_task.await.map_err(|error| {
            AgentError::InvalidAssignment(format!("lease task failed: {error}"))
        })?;
        completion_result?;
        return lease_result;
    }
    require_work_receipt(
        lease_deadline_rpc(
            lease_started_at + lease_rpc_budget(lease_window),
            client.start_work(assignment.authority.clone()),
        )
        .await?,
        session_epoch,
    )?;

    let execution_cancellation = stop.child_token();
    let authority_lost = CancellationToken::new();
    let lease_stop = CancellationToken::new();
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
        },
    ));
    let process = assignment.process;
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
        environment: process
            .env
            .into_iter()
            .map(|(key, value)| (OsString::from(key), OsString::from(value)))
            .collect(),
        output_limit_bytes: Some(MAX_TOTAL_LOG_SPOOL_BYTES),
        timeout: Duration::from_secs(process.timeout_seconds.unwrap_or(3_600)),
        termination_grace: config.termination_grace,
    };
    let execution =
        execute_with_spawn_hook(&request, execution_cancellation.clone(), |process_id| {
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
        })
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
                    return Err(AgentError::UnresolvedReconciliation);
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
                    &authority_lost,
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
        let result = write_result(
            &config.workspace_root,
            &assignment.workspace,
            DurableResult {
                outcome: terminal,
                exit_code: outcome.exit_code,
                termination: termination_name(outcome.termination),
                reason: None,
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
            authority_lost: &authority_lost,
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
            &authority_lost,
            publication.client.complete_work(WorkCompletion {
                authority: Some(assignment.authority.clone()),
                outcome: terminal as i32,
                summary_json: summary,
            }),
        )
        .await?;
        require_work_receipt(completion, session_epoch)?;
        crash_after_terminal_commit_for_test();
        journal.transition(
            &organization,
            &attempt,
            fence,
            session_epoch,
            terminal_phase(terminal)?,
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

fn unverified_containment_process_id(error: &ExecutionError) -> Option<u32> {
    match error {
        ExecutionError::ContainmentUnverified { process_id, .. } => Some(*process_id),
        _ => None,
    }
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
        let receipt = match renewal {
            Err(_) => {
                execution_cancellation.cancel();
                authority_lost.cancel();
                return Err(AgentError::LeaseRenewalTimeout);
            }
            Ok(Ok(response)) => response.into_inner(),
            Ok(Err(error)) => {
                execution_cancellation.cancel();
                authority_lost.cancel();
                return Err(error.into());
            }
        };
        match ensure_session(receipt.session_epoch, authority.session_epoch) {
            Ok(()) => {}
            Err(error) => {
                execution_cancellation.cancel();
                authority_lost.cancel();
                return Err(error);
            }
        }
        if !receipt.accepted {
            execution_cancellation.cancel();
            authority_lost.cancel();
            return Err(AgentError::StaleAuthority);
        }
        if receipt.cancellation_requested {
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

async fn authority_rpc<T>(
    authority_lost: &CancellationToken,
    operation: impl Future<Output = Result<tonic::Response<T>, tonic::Status>>,
) -> Result<T, AgentError> {
    tokio::select! {
        biased;
        () = authority_lost.cancelled() => Err(AgentError::StaleAuthority),
        result = operation => Ok(result?.into_inner()),
    }
}

async fn publish_spool(
    publication: &mut PublicationContext<'_>,
    stream: &str,
    workspace_root: &Path,
    entry: &SpoolEntry,
    first_sequence: u64,
) -> Result<u64, AgentError> {
    if entry.bytes > MAX_TOTAL_LOG_SPOOL_BYTES {
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
                publication.authority_lost,
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
                publication.authority_lost,
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
    for entry in logs.iter().chain(result) {
        remove_spool_file(&config.workspace_root, entry).await?;
    }
    remove_attempt_workspace(&config.workspace_root, workspace).await?;
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
    let path = workspace_root.join(workspace);
    let mut current = workspace_root.to_owned();
    for component in workspace.components() {
        let Component::Normal(component) = component else {
            unreachable!("terminal workspace was validated above");
        };
        current.push(component);
        match fs::symlink_metadata(&current).await {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => {
                return Err(AgentError::InvalidAssignment(
                    "terminal workspace contains a non-directory or symlink".to_owned(),
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(error.into()),
        }
    }
    match fs::remove_dir_all(&path).await {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                sync_directory(parent)?;
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    prune_empty_spool_directories(workspace_root, path.parent()).await
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
    let path = workspace_root.join(&entry.relative_path);
    let mut removed = false;
    match fs::remove_file(&path).await {
        Ok(()) => removed = true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    if removed && let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    prune_empty_spool_directories(workspace_root, path.parent()).await
}

async fn prune_empty_spool_directories(
    workspace_root: &Path,
    start: Option<&Path>,
) -> Result<(), AgentError> {
    let mut current = start.map(Path::to_owned);
    while let Some(directory) = current {
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
    if total > MAX_TOTAL_LOG_SPOOL_BYTES {
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
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(AgentError::InvalidAssignment(
                "result spool parent contains a non-directory or symlink".to_owned(),
            ));
        }
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
    authority_lost: &CancellationToken,
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
    require_work_receipt(
        authority_rpc(
            authority_lost,
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
    )?;
    journal.transition(
        &authority.organization_id,
        &authority.attempt_id,
        authority.fence_token,
        session_epoch,
        terminal_phase(outcome)?,
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
    ensure_session(receipt.session_epoch, session_epoch)?;
    if receipt.accepted {
        Ok(())
    } else {
        Err(AgentError::StaleAuthority)
    }
}

fn ensure_session(received: u64, expected: u64) -> Result<(), AgentError> {
    if received == expected {
        Ok(())
    } else {
        Err(AgentError::StaleSession)
    }
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
    fn assignment_is_tenant_bound_and_digest_checked() {
        let spec = br#"{"version":1,"steps":[{"kind":"process","program":"true"}]}"#;
        let validated = validate_assignment(&config(), 4, assignment(spec)).unwrap();
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
        assert!(matches!(
            validate_assignment(&config(), 4, assignment(unbounded_timeout)),
            Err(AgentError::InvalidAssignment(_))
        ));
        let zero_timeout =
            br#"{"version":1,"steps":[{"kind":"process","program":"true","timeout_seconds":0}]}"#;
        assert!(matches!(
            validate_assignment(&config(), 4, assignment(zero_timeout)),
            Err(AgentError::InvalidAssignment(_))
        ));
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
        let result = authority_rpc::<()>(
            &authority_lost,
            std::future::pending::<Result<tonic::Response<()>, tonic::Status>>(),
        )
        .await;
        assert!(matches!(result, Err(AgentError::StaleAuthority)));
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

    #[test]
    fn execution_spec_is_fail_closed() {
        let multiple =
            br#"{"version":1,"steps":[{"kind":"process","program":"one"},{"kind":"process","program":"two"}]}"#;
        assert!(matches!(
            validate_assignment(&config(), 1, assignment(multiple)),
            Err(AgentError::UnsupportedSpec)
        ));
        let wrong_kind = br#"{"version":1,"steps":[{"kind":"shell","program":"no"}]}"#;
        assert!(matches!(
            validate_assignment(&config(), 1, assignment(wrong_kind)),
            Err(AgentError::UnsupportedSpec)
        ));
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
            entry(0, MAX_TOTAL_LOG_SPOOL_BYTES / 2),
            entry(1, MAX_TOTAL_LOG_SPOOL_BYTES / 2),
        ])
        .unwrap();
        assert!(matches!(
            validate_log_spool_quota(&[entry(0, MAX_TOTAL_LOG_SPOOL_BYTES), entry(1, 1)]),
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
    async fn acknowledged_terminal_spools_are_reclaimed_and_metadata_is_retired() {
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
        journal
            .transition(
                &acceptance.organization_id,
                &acceptance.attempt_id,
                acceptance.fence_token,
                acceptance.session_epoch,
                AttemptPhase::Succeeded,
                Some(42),
            )
            .unwrap();
        drop(journal);

        reclaim_terminal_spools(&config).await.unwrap();

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
