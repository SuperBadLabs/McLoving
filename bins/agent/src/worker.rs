//! Fenced controller-to-agent work execution.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use mcloving_agent_protocol::wire::agent_control_client::AgentControlClient;
use mcloving_agent_protocol::wire::{
    CancellationCompletion, CancellationDisposition, CancellationOutcome, WorkAssignment,
    WorkAuthority, WorkCompletion, WorkLeaseRenewal, WorkLogChunk, WorkOutcome, WorkPoll,
};
use mcloving_agent_runtime::executor::{
    ExecutionError, ExecutionMode, ExecutionRequest, Termination, execute_with_spawn_hook,
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
const MAX_RESULT_SPOOL_BYTES: u64 = 65_536;
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
        let lease_stop = CancellationToken::new();
        let authority_lost = CancellationToken::new();
        let lease_task = tokio::spawn(renew_lease(
            client.clone(),
            authority.clone(),
            config.lease_seconds,
            config.lease_renewal_interval,
            authority_lost,
            lease_stop.clone(),
        ));
        let replay_result =
            replay_finalization(config, client, session_epoch, &attempt, authority).await;
        lease_stop.cancel();
        let lease_result = lease_task.await.map_err(|error| {
            AgentError::InvalidAssignment(format!("lease task failed: {error}"))
        })?;
        let terminal = replay_result?;
        lease_result?;
        Journal::open(&config.journal_path)?.transition(
            &attempt.organization_id,
            &attempt.attempt_id,
            attempt.fence_token,
            attempt.session_epoch,
            terminal,
            attempt.process_id,
        )?;
    }
    Ok(())
}

async fn replay_finalization(
    config: &AgentConfig,
    client: &mut AgentControlClient<Channel>,
    session_epoch: u64,
    attempt: &mcloving_agent_runtime::ReconciliationAttempt,
    authority: WorkAuthority,
) -> Result<AttemptPhase, AgentError> {
    validate_log_spool_quota(&attempt.logs)?;
    let mut sequence = 0;
    for entry in &attempt.logs {
        let stream = spool_stream(entry)?;
        sequence = publish_spool(
            client,
            &authority,
            session_epoch,
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
                client
                    .complete_work(WorkCompletion {
                        authority: Some(authority),
                        outcome: outcome as i32,
                        summary_json: summary,
                    })
                    .await?
                    .into_inner(),
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
            let receipt = client
                .complete_cancellation(CancellationCompletion {
                    agent_id: config.agent_id.clone(),
                    session_epoch,
                    organization_id: attempt.organization_id.clone(),
                    attempt_id: attempt.attempt_id.clone(),
                    fence_token: attempt.fence_token,
                    outcome: cancellation_outcome,
                })
                .await?
                .into_inner();
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

    require_work_receipt(
        client
            .accept_work(assignment.authority.clone())
            .await?
            .into_inner(),
        session_epoch,
    )?;
    let lease = client
        .renew_work_lease(WorkLeaseRenewal {
            authority: Some(assignment.authority.clone()),
            lease_seconds: config.lease_seconds,
        })
        .await?
        .into_inner();
    ensure_session(lease.session_epoch, session_epoch)?;
    if !lease.accepted {
        return Err(AgentError::StaleAuthority);
    }
    if lease.cancellation_requested {
        let lease_stop = CancellationToken::new();
        let execution_cancellation = CancellationToken::new();
        execution_cancellation.cancel();
        let lease_task = tokio::spawn(renew_lease(
            client.clone(),
            assignment.authority.clone(),
            config.lease_seconds,
            config.lease_renewal_interval,
            execution_cancellation,
            lease_stop.clone(),
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
        client
            .start_work(assignment.authority.clone())
            .await?
            .into_inner(),
        session_epoch,
    )?;

    let execution_cancellation = stop.child_token();
    let lease_stop = CancellationToken::new();
    let lease_task = tokio::spawn(renew_lease(
        client.clone(),
        assignment.authority.clone(),
        config.lease_seconds,
        config.lease_renewal_interval,
        execution_cancellation.clone(),
        lease_stop.clone(),
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
                )
                .await;
            }
        };
        validate_log_spool_quota(&[outcome.stdout.clone(), outcome.stderr.clone()])?;
        let terminal = match outcome.termination {
            Termination::Cancelled => WorkOutcome::Aborted,
            Termination::TimedOut => WorkOutcome::Failed,
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
        let next_sequence = publish_spool(
            client,
            &assignment.authority,
            session_epoch,
            "stdout",
            &config.workspace_root,
            &outcome.stdout,
            0,
        )
        .await?;
        publish_spool(
            client,
            &assignment.authority,
            session_epoch,
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
        let completion = client
            .complete_work(WorkCompletion {
                authority: Some(assignment.authority),
                outcome: terminal as i32,
                summary_json: summary,
            })
            .await?
            .into_inner();
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

async fn renew_lease(
    mut client: AgentControlClient<Channel>,
    authority: WorkAuthority,
    lease_seconds: u32,
    renewal_interval: Duration,
    execution_cancellation: CancellationToken,
    lease_stop: CancellationToken,
) -> Result<(), AgentError> {
    loop {
        tokio::select! {
            () = lease_stop.cancelled() => return Ok(()),
            () = tokio::time::sleep(renewal_interval) => {}
        }
        let receipt = match client
            .renew_work_lease(WorkLeaseRenewal {
                authority: Some(authority.clone()),
                lease_seconds,
            })
            .await
        {
            Ok(response) => response.into_inner(),
            Err(error) => {
                execution_cancellation.cancel();
                return Err(error.into());
            }
        };
        if let Err(error) = ensure_session(receipt.session_epoch, authority.session_epoch) {
            execution_cancellation.cancel();
            return Err(error);
        }
        if !receipt.accepted {
            execution_cancellation.cancel();
            return Err(AgentError::StaleAuthority);
        }
        if receipt.cancellation_requested {
            execution_cancellation.cancel();
        }
    }
}

async fn publish_spool(
    client: &mut AgentControlClient<Channel>,
    authority: &WorkAuthority,
    session_epoch: u64,
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
    loop {
        let bytes = file.read(&mut buffer).await?;
        if bytes == 0 {
            break;
        }
        require_work_receipt(
            client
                .publish_log(WorkLogChunk {
                    authority: Some(authority.clone()),
                    sequence,
                    stream: stream.to_owned(),
                    content: buffer[..bytes].to_vec(),
                })
                .await?
                .into_inner(),
            session_epoch,
        )?;
        published = true;
        sequence = sequence.checked_add(1).ok_or_else(|| {
            AgentError::InvalidAssignment("log sequence exceeds wire bounds".to_owned())
        })?;
    }
    if !published {
        require_work_receipt(
            client
                .publish_log(WorkLogChunk {
                    authority: Some(authority.clone()),
                    sequence: first_sequence,
                    stream: stream.to_owned(),
                    content: Vec::new(),
                })
                .await?
                .into_inner(),
            session_epoch,
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
    let relative_path = workspace.join("spool/result.json");
    let path = workspace_root.join(&relative_path);
    let parent = path.parent().ok_or_else(|| {
        AgentError::InvalidAssignment("result spool has no parent directory".to_owned())
    })?;
    fs::create_dir_all(parent).await?;
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
    Ok(SpoolEntry {
        sequence: 0,
        relative_path,
        digest: Sha256::digest(&content).into(),
        bytes: u64::try_from(content.len()).map_err(|_| {
            AgentError::InvalidAssignment("result length exceeds wire bounds".to_owned())
        })?,
    })
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

async fn finalize_without_process(
    config: &AgentConfig,
    client: &mut AgentControlClient<Channel>,
    journal: &mut Journal,
    completion: ProcesslessCompletion<'_>,
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
        client
            .complete_work(WorkCompletion {
                authority: Some(authority.clone()),
                outcome: outcome as i32,
                summary_json: serde_json::to_vec(&json!({
                    "reason": reason,
                    "result_sha256": hex(&result.digest),
                }))?,
            })
            .await?
            .into_inner(),
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

    #[tokio::test]
    async fn result_spool_is_idempotent_and_completion_protocol_bound() {
        let directory = tempfile::tempdir().unwrap();
        let workspace = PathBuf::from("org/attempt");

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
        assert_eq!(first, replay);

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

        assert!(matches!(
            write_result(
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
            .await,
            Err(AgentError::InvalidAssignment(_))
        ));
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
