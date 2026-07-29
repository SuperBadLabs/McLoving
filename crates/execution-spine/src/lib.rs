//! The smallest truthful controller-to-agent execution spine.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use mcloving_agent_runtime::executor::{
    ExecutionError, ExecutionMode, ExecutionRequest, Termination, execute_with_spawn_hook,
};
use mcloving_agent_runtime::{Acceptance, AttemptPhase, Journal, JournalError, SpoolEntry};
use mcloving_controller_store::{ClaimedAttempt, NewLogChunk, Store, StoreError, TerminalOutcome};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::fs;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct WorkerConfig {
    pub agent_id: String,
    pub session_epoch: u64,
    pub workspace_root: PathBuf,
    pub journal_path: PathBuf,
    pub cancellation_poll: Duration,
    pub lease_seconds: i32,
    pub termination_grace: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunReceipt {
    pub build_id: Uuid,
    pub attempt_id: Uuid,
    pub fence: i64,
    pub outcome: TerminalOutcome,
    pub exit_code: Option<i32>,
    pub stdout_sha256: [u8; 32],
    pub stderr_sha256: [u8; 32],
}

#[derive(Debug, thiserror::Error)]
pub enum SpineError {
    #[error("controller store failed: {0}")]
    Store(#[from] StoreError),
    #[error("agent journal failed: {0}")]
    Journal(#[from] JournalError),
    #[error("execution failed: {0}")]
    Execution(#[from] ExecutionError),
    #[error("execution specification is invalid: {0}")]
    InvalidSpec(#[from] serde_json::Error),
    #[error("controller rejected the current fenced authority")]
    StaleAuthority,
    #[error("execution specification must contain exactly one process step")]
    UnsupportedSpec,
    #[error("numeric value cannot be represented by the durable protocol")]
    FenceOverflow,
    #[error("lease duration must be positive and exceed the cancellation poll interval")]
    InvalidLeaseConfiguration,
    #[error("result I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

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
    env: std::collections::BTreeMap<String, String>,
    timeout_seconds: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ProcessMode {
    #[default]
    Direct,
    WindowsCmd,
    PowerShell,
}

fn journal_authority_token(restore_epoch: i64, fence: i64) -> Result<u64, SpineError> {
    let restore_epoch = u32::try_from(restore_epoch).map_err(|_| SpineError::FenceOverflow)?;
    let fence = u32::try_from(fence).map_err(|_| SpineError::FenceOverflow)?;
    let token = (u64::from(restore_epoch) << 32) | u64::from(fence);
    i64::try_from(token).map_err(|_| SpineError::FenceOverflow)?;
    Ok(token)
}

pub async fn run_claim(
    store: &Store,
    claim: &ClaimedAttempt,
    config: &WorkerConfig,
) -> Result<RunReceipt, SpineError> {
    let lease_seconds =
        u64::try_from(config.lease_seconds).map_err(|_| SpineError::InvalidLeaseConfiguration)?;
    if lease_seconds == 0 || config.cancellation_poll >= Duration::from_secs(lease_seconds) {
        return Err(SpineError::InvalidLeaseConfiguration);
    }
    let execution = store
        .attempt_execution(
            claim.organization_id,
            claim.attempt_id,
            claim.fence,
            claim.restore_epoch,
            &config.agent_id,
        )
        .await?
        .ok_or(SpineError::StaleAuthority)?;
    let payload_digest: [u8; 32] =
        Sha256::digest(serde_json::to_vec(&execution.execution_spec)?).into();
    let spec: ExecutionSpec = serde_json::from_value(execution.execution_spec)?;
    if spec.version != 1 || spec.steps.len() != 1 || spec.steps[0].kind != "process" {
        return Err(SpineError::UnsupportedSpec);
    }
    let process = &spec.steps[0];
    let database_fence = u64::try_from(claim.fence).map_err(|_| SpineError::FenceOverflow)?;
    let journal_fence = journal_authority_token(claim.restore_epoch, claim.fence)?;
    let organization = claim.organization_id.to_string();
    let attempt = claim.attempt_id.to_string();
    let workspace = PathBuf::from(format!(
        "{organization}/{attempt}/{}-{fence}",
        claim.restore_epoch,
        fence = database_fence,
    ));
    let mut journal = Journal::open(&config.journal_path)?;
    journal.accept(&Acceptance {
        organization_id: organization.clone(),
        attempt_id: attempt.clone(),
        fence_token: journal_fence,
        session_epoch: config.session_epoch,
        payload_digest,
        workspace: workspace.clone(),
    })?;
    if !store
        .accept_offer(
            claim.organization_id,
            claim.attempt_id,
            claim.fence,
            claim.restore_epoch,
            &config.agent_id,
        )
        .await?
    {
        return Err(SpineError::StaleAuthority);
    }
    let accepted_execution = store
        .attempt_execution(
            claim.organization_id,
            claim.attempt_id,
            claim.fence,
            claim.restore_epoch,
            &config.agent_id,
        )
        .await?
        .ok_or(SpineError::StaleAuthority)?;
    if accepted_execution.cancellation_requested {
        return finalize_without_process(
            store,
            claim,
            config,
            &mut journal,
            &organization,
            &attempt,
            journal_fence,
            TerminalOutcome::Aborted,
            "cancelled_before_process_spawn",
        )
        .await;
    }
    if !store
        .mark_attempt_running(
            claim.organization_id,
            claim.attempt_id,
            claim.fence,
            claim.restore_epoch,
            &config.agent_id,
        )
        .await?
    {
        if store
            .attempt_execution(
                claim.organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                &config.agent_id,
            )
            .await?
            .is_some_and(|current| current.cancellation_requested)
        {
            return finalize_without_process(
                store,
                claim,
                config,
                &mut journal,
                &organization,
                &attempt,
                journal_fence,
                TerminalOutcome::Aborted,
                "cancelled_before_process_spawn",
            )
            .await;
        }
        return Err(SpineError::StaleAuthority);
    }

    let cancellation = CancellationToken::new();
    if execution.cancellation_requested {
        cancellation.cancel();
    }
    let poll = tokio::spawn(cancellation_poller(
        store.clone(),
        claim.clone(),
        config.agent_id.clone(),
        config.cancellation_poll,
        config.lease_seconds,
        cancellation.clone(),
    ));
    let request = ExecutionRequest {
        workspace_root: config.workspace_root.clone(),
        workspace: workspace.clone(),
        mode: match process.mode {
            ProcessMode::Direct => ExecutionMode::Direct,
            ProcessMode::WindowsCmd => ExecutionMode::WindowsCmd,
            ProcessMode::PowerShell => ExecutionMode::PowerShell,
        },
        program: PathBuf::from(&process.program),
        arguments: process.args.iter().map(OsString::from).collect(),
        environment: process
            .env
            .iter()
            .map(|(key, value)| (OsString::from(key), OsString::from(value)))
            .collect(),
        output_limit_bytes: None,
        timeout: Duration::from_secs(process.timeout_seconds.unwrap_or(3_600)),
        termination_grace: config.termination_grace,
    };
    let outcome = execute_with_spawn_hook(&request, cancellation.clone(), |process_id| {
        journal
            .transition(
                &organization,
                &attempt,
                journal_fence,
                config.session_epoch,
                AttemptPhase::Running,
                Some(process_id),
            )
            .map_err(|error| ExecutionError::SpawnHook(error.to_string()))
    })
    .await;
    cancellation.cancel();
    poll.await.ok();
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            return finalize_without_process(
                store,
                claim,
                config,
                &mut journal,
                &organization,
                &attempt,
                journal_fence,
                TerminalOutcome::Failed,
                &format!("process_spawn_failed: {error}"),
            )
            .await;
        }
    };

    journal.record_log(
        &organization,
        &attempt,
        journal_fence,
        config.session_epoch,
        &outcome.stdout,
    )?;
    journal.record_log(
        &organization,
        &attempt,
        journal_fence,
        config.session_epoch,
        &outcome.stderr,
    )?;
    commit_log(store, claim, config, "stdout", &outcome.stdout).await?;
    commit_log(store, claim, config, "stderr", &outcome.stderr).await?;

    let terminal = match outcome.termination {
        Termination::Cancelled => TerminalOutcome::Aborted,
        Termination::TimedOut | Termination::OutputLimitExceeded => TerminalOutcome::Failed,
        Termination::Exited if outcome.exit_code == Some(0) => TerminalOutcome::Succeeded,
        Termination::Exited => TerminalOutcome::Failed,
    };
    let transition = if terminal == TerminalOutcome::Aborted {
        AttemptPhase::Cancelling
    } else {
        AttemptPhase::Finalizing
    };
    journal.transition(
        &organization,
        &attempt,
        journal_fence,
        config.session_epoch,
        transition,
        Some(outcome.process_id),
    )?;
    let result = write_result(
        &config.workspace_root,
        &workspace,
        terminal,
        outcome.exit_code,
    )
    .await?;
    journal.record_result(
        &organization,
        &attempt,
        journal_fence,
        config.session_epoch,
        &result,
    )?;
    if !store
        .finalize_attempt(
            claim.organization_id,
            claim.attempt_id,
            claim.fence,
            claim.restore_epoch,
            &config.agent_id,
            terminal,
            json!({
                "exit_code": outcome.exit_code,
                "termination": format!("{:?}", outcome.termination).to_lowercase(),
                "result_sha256": hex(&result.digest),
            }),
        )
        .await?
    {
        return Err(SpineError::StaleAuthority);
    }
    journal.transition(
        &organization,
        &attempt,
        journal_fence,
        config.session_epoch,
        match terminal {
            TerminalOutcome::Succeeded => AttemptPhase::Succeeded,
            TerminalOutcome::Failed => AttemptPhase::Failed,
            TerminalOutcome::Aborted => AttemptPhase::Aborted,
        },
        Some(outcome.process_id),
    )?;
    Ok(RunReceipt {
        build_id: claim.build_id,
        attempt_id: claim.attempt_id,
        fence: claim.fence,
        outcome: terminal,
        exit_code: outcome.exit_code,
        stdout_sha256: outcome.stdout.digest,
        stderr_sha256: outcome.stderr.digest,
    })
}

async fn cancellation_poller(
    store: Store,
    claim: ClaimedAttempt,
    agent_id: String,
    interval: Duration,
    lease_seconds: i32,
    cancellation: CancellationToken,
) {
    while !cancellation.is_cancelled() {
        tokio::time::sleep(interval).await;
        match store
            .renew_attempt_lease(
                claim.organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                &agent_id,
                lease_seconds,
            )
            .await
        {
            Ok(Some(true)) => cancellation.cancel(),
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => cancellation.cancel(),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn finalize_without_process(
    store: &Store,
    claim: &ClaimedAttempt,
    config: &WorkerConfig,
    journal: &mut Journal,
    organization: &str,
    attempt: &str,
    fence: u64,
    terminal: TerminalOutcome,
    reason: &str,
) -> Result<RunReceipt, SpineError> {
    let preparing = if terminal == TerminalOutcome::Aborted {
        AttemptPhase::Cancelling
    } else {
        AttemptPhase::Finalizing
    };
    journal.transition(
        organization,
        attempt,
        fence,
        config.session_epoch,
        preparing,
        None,
    )?;
    if !store
        .finalize_attempt(
            claim.organization_id,
            claim.attempt_id,
            claim.fence,
            claim.restore_epoch,
            &config.agent_id,
            terminal,
            json!({"reason": reason}),
        )
        .await?
    {
        return Err(SpineError::StaleAuthority);
    }
    journal.transition(
        organization,
        attempt,
        fence,
        config.session_epoch,
        match terminal {
            TerminalOutcome::Succeeded => AttemptPhase::Succeeded,
            TerminalOutcome::Failed => AttemptPhase::Failed,
            TerminalOutcome::Aborted => AttemptPhase::Aborted,
        },
        None,
    )?;
    Ok(RunReceipt {
        build_id: claim.build_id,
        attempt_id: claim.attempt_id,
        fence: claim.fence,
        outcome: terminal,
        exit_code: None,
        stdout_sha256: [0; 32],
        stderr_sha256: [0; 32],
    })
}

async fn commit_log(
    store: &Store,
    claim: &ClaimedAttempt,
    config: &WorkerConfig,
    stream: &str,
    entry: &SpoolEntry,
) -> Result<(), SpineError> {
    let content = fs::read(config.workspace_root.join(&entry.relative_path)).await?;
    if !store
        .append_log(&NewLogChunk {
            organization_id: claim.organization_id,
            attempt_id: claim.attempt_id,
            fence: claim.fence,
            restore_epoch: claim.restore_epoch,
            agent_id: &config.agent_id,
            sequence: i64::try_from(entry.sequence).map_err(|_| SpineError::FenceOverflow)?,
            stream,
            content: &content,
        })
        .await?
    {
        return Err(SpineError::StaleAuthority);
    }
    Ok(())
}

async fn write_result(
    workspace_root: &Path,
    workspace: &Path,
    outcome: TerminalOutcome,
    exit_code: Option<i32>,
) -> Result<SpoolEntry, SpineError> {
    let relative_path = workspace.join("spool/result.json");
    let path = workspace_root.join(&relative_path);
    let content = serde_json::to_vec(&json!({
        "outcome": format!("{outcome:?}").to_lowercase(),
        "exit_code": exit_code,
    }))?;
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .await?;
    use tokio::io::AsyncWriteExt;
    file.write_all(&content).await?;
    file.sync_all().await?;
    Ok(SpoolEntry {
        sequence: 0,
        relative_path,
        digest: Sha256::digest(&content).into(),
        bytes: u64::try_from(content.len()).map_err(|_| SpineError::FenceOverflow)?,
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
