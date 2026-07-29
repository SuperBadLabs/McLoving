//! Fenced controller-to-agent work execution.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use mcloving_agent_protocol::wire::agent_control_client::AgentControlClient;
use mcloving_agent_protocol::wire::{
    WorkAssignment, WorkAuthority, WorkCompletion, WorkLeaseRenewal, WorkLogChunk, WorkOutcome,
    WorkPoll,
};
use mcloving_agent_runtime::executor::{
    ExecutionError, ExecutionMode, ExecutionRequest, Termination, execute_with_spawn_hook,
};
use mcloving_agent_runtime::{Acceptance, AttemptPhase, Journal, ProcessIdentity, SpoolEntry};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;
use tonic::transport::Channel;
use uuid::Uuid;

use crate::{AgentConfig, AgentError, process_birth_identity_for};

const MAX_LOG_CHUNK_BYTES: usize = 1_048_576;

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
        let summary = serde_json::to_vec(&json!({
            "exit_code": result.exit_code,
            "termination": result.termination,
            "result_sha256": hex(&result_entry.digest),
        }))?;
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
        Journal::open(&config.journal_path)?.transition(
            &attempt.organization_id,
            &attempt.attempt_id,
            attempt.fence_token,
            attempt.session_epoch,
            terminal_phase(outcome)?,
            attempt.process_id,
        )?;
    }
    Ok(())
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
        return finalize_without_process(
            client,
            &mut journal,
            &assignment.authority,
            session_epoch,
            WorkOutcome::Aborted,
            "cancelled_before_process_spawn",
        )
        .await;
    }
    require_work_receipt(
        client
            .start_work(assignment.authority.clone())
            .await?
            .into_inner(),
        session_epoch,
    )?;

    let execution_cancellation = stop.child_token();
    let lease_task = tokio::spawn(renew_lease(
        client.clone(),
        assignment.authority.clone(),
        config.lease_seconds,
        config.lease_renewal_interval,
        execution_cancellation.clone(),
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
    execution_cancellation.cancel();
    lease_task
        .await
        .map_err(|error| AgentError::InvalidAssignment(format!("lease task failed: {error}")))??;

    let outcome = match execution {
        Ok(outcome) => outcome,
        Err(error) => {
            return finalize_without_process(
                client,
                &mut journal,
                &assignment.authority,
                session_epoch,
                WorkOutcome::Failed,
                &format!("process_spawn_failed: {error}"),
            )
            .await;
        }
    };
    journal.record_log(
        &organization,
        &attempt,
        fence,
        session_epoch,
        &outcome.stdout,
    )?;
    journal.record_log(
        &organization,
        &attempt,
        fence,
        session_epoch,
        &outcome.stderr,
    )?;
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

    let terminal = match outcome.termination {
        Termination::Cancelled => WorkOutcome::Aborted,
        Termination::TimedOut => WorkOutcome::Failed,
        Termination::Exited if outcome.exit_code == Some(0) => WorkOutcome::Succeeded,
        Termination::Exited => WorkOutcome::Failed,
    };
    journal.transition(
        &organization,
        &attempt,
        fence,
        session_epoch,
        if terminal == WorkOutcome::Aborted {
            AttemptPhase::Cancelling
        } else {
            AttemptPhase::Finalizing
        },
        Some(outcome.process_id),
    )?;
    let result = write_result(
        &config.workspace_root,
        &assignment.workspace,
        terminal,
        outcome.exit_code,
        outcome.termination,
    )
    .await?;
    journal.record_result(&organization, &attempt, fence, session_epoch, &result)?;
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

async fn renew_lease(
    mut client: AgentControlClient<Channel>,
    authority: WorkAuthority,
    lease_seconds: u32,
    renewal_interval: Duration,
    cancellation: CancellationToken,
) -> Result<(), AgentError> {
    loop {
        tokio::select! {
            () = cancellation.cancelled() => return Ok(()),
            () = tokio::time::sleep(renewal_interval) => {}
        }
        let receipt = client
            .renew_work_lease(WorkLeaseRenewal {
                authority: Some(authority.clone()),
                lease_seconds,
            })
            .await?
            .into_inner();
        ensure_session(receipt.session_epoch, authority.session_epoch)?;
        if !receipt.accepted {
            cancellation.cancel();
            return Err(AgentError::StaleAuthority);
        }
        if receipt.cancellation_requested {
            cancellation.cancel();
            return Ok(());
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
    let content = verified_spool_content(workspace_root, entry, "log").await?;
    let chunks = content.len().max(1).div_ceil(MAX_LOG_CHUNK_BYTES);
    for (offset, chunk) in content.chunks(MAX_LOG_CHUNK_BYTES).enumerate() {
        let sequence = first_sequence
            .checked_add(u64::try_from(offset).map_err(|_| {
                AgentError::InvalidAssignment("log sequence exceeds wire bounds".to_owned())
            })?)
            .ok_or_else(|| {
                AgentError::InvalidAssignment("log sequence exceeds wire bounds".to_owned())
            })?;
        require_work_receipt(
            client
                .publish_log(WorkLogChunk {
                    authority: Some(authority.clone()),
                    sequence,
                    stream: stream.to_owned(),
                    content: chunk.to_vec(),
                })
                .await?
                .into_inner(),
            session_epoch,
        )?;
    }
    if content.is_empty() {
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
    }
    first_sequence
        .checked_add(u64::try_from(chunks).map_err(|_| {
            AgentError::InvalidAssignment("log sequence exceeds wire bounds".to_owned())
        })?)
        .ok_or_else(|| AgentError::InvalidAssignment("log sequence exceeds wire bounds".to_owned()))
}

async fn verified_spool_content(
    workspace_root: &Path,
    entry: &SpoolEntry,
    kind: &str,
) -> Result<Vec<u8>, AgentError> {
    let content = fs::read(workspace_root.join(&entry.relative_path)).await?;
    let calculated: [u8; 32] = Sha256::digest(&content).into();
    if calculated != entry.digest || u64::try_from(content.len()).ok() != Some(entry.bytes) {
        return Err(AgentError::InvalidAssignment(format!(
            "durable {kind} spool metadata does not match its content"
        )));
    }
    Ok(content)
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
    outcome: WorkOutcome,
    exit_code: Option<i32>,
    termination: Termination,
) -> Result<SpoolEntry, AgentError> {
    let relative_path = workspace.join("spool/result.json");
    let path = workspace_root.join(&relative_path);
    let content = serde_json::to_vec(&json!({
        "outcome": outcome_name(outcome),
        "exit_code": exit_code,
        "termination": termination_name(termination),
    }))?;
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .await?;
    file.write_all(&content).await?;
    file.sync_all().await?;
    Ok(SpoolEntry {
        sequence: 0,
        relative_path,
        digest: Sha256::digest(&content).into(),
        bytes: u64::try_from(content.len()).map_err(|_| {
            AgentError::InvalidAssignment("result length exceeds wire bounds".to_owned())
        })?,
    })
}

async fn finalize_without_process(
    client: &mut AgentControlClient<Channel>,
    journal: &mut Journal,
    authority: &WorkAuthority,
    session_epoch: u64,
    outcome: WorkOutcome,
    reason: &str,
) -> Result<(), AgentError> {
    journal.transition(
        &authority.organization_id,
        &authority.attempt_id,
        authority.fence_token,
        session_epoch,
        if outcome == WorkOutcome::Aborted {
            AttemptPhase::Cancelling
        } else {
            AttemptPhase::Finalizing
        },
        None,
    )?;
    require_work_receipt(
        client
            .complete_work(WorkCompletion {
                authority: Some(authority.clone()),
                outcome: outcome as i32,
                summary_json: serde_json::to_vec(&json!({"reason": reason}))?,
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
}
