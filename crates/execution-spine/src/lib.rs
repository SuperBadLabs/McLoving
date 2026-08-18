//! The smallest truthful controller-to-agent execution spine.

mod effect_runtime;
mod effect_transport;

pub use effect_runtime::{
    EffectRuntimeError, EffectRuntimeFreeze, FreshOneActionGrant, PreparedEffect,
    abandon_prepared_effect, confirm_effect_observation, finalize_effect_shadow_join,
    finalize_effect_shadow_join_as, mark_effect_uncertain, prepare_effect, record_effect_outcome,
    record_reconciled_effect_outcome,
};
pub use effect_transport::{
    EffectServiceError, PinnedServiceCommand, invoke_connector, invoke_observer, invoke_shadow,
};

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mcloving_agent_runtime::executor::{
    ExecutionError, ExecutionMode, ExecutionRequest, Termination, WorkspaceRootGuard,
    execute_with_spawn_hook,
};
use mcloving_agent_runtime::{
    Acceptance, AttemptPhase, Journal, JournalError, MAX_ATTEMPT_OUTPUT_BYTES, SpoolEntry,
};
use mcloving_controller_store::{ClaimedAttempt, NewLogChunk, Store, StoreError, TerminalOutcome};
use mcloving_destination_observer::{ObservationPhase, ObservationRequest};
use mcloving_external_connector::{
    ConnectorCommand, OutcomeStatus, RECONCILE_REQUEST_SCHEMA_VERSION, ReconcileRequest,
    SHADOW_REPLAY_SCHEMA_VERSION, ShadowReplayRequest, outcome_receipt_digest,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
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
    pub effect_plan: Option<EffectExecutionPlan>,
}

/// One exact, deployment-owned, one-action runtime plan. It contains signed
/// public requests and public keys, never a destination credential or token.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectExecutionPlan {
    pub schema_version: String,
    pub freeze: EffectRuntimeFreeze,
    pub connector_service: PinnedServiceCommand,
    pub observer_service: PinnedServiceCommand,
    pub shadow_service: PinnedServiceCommand,
    pub observation_request: ObservationRequest,
    pub audit_provenance: String,
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

/// Proves that the embedded worker can use its durable local resources before
/// the controller rotates any externally visible credentials.
pub async fn preflight_worker(config: &WorkerConfig) -> Result<(), SpineError> {
    fs::create_dir_all(&config.workspace_root).await?;
    let workspace_guard = WorkspaceRootGuard::open(&config.workspace_root)?;
    workspace_guard.ensure_original(&config.workspace_root)?;

    let probe = config
        .workspace_root
        .join(format!(".mcloving-preflight-{}", Uuid::new_v4()));
    fs::create_dir(&probe).await?;
    if let Err(error) = workspace_guard.ensure_original(&config.workspace_root) {
        let _ = fs::remove_dir(&probe).await;
        return Err(error.into());
    }
    fs::remove_dir(&probe).await?;

    if let Some(parent) = config.journal_path.parent() {
        fs::create_dir_all(parent).await?;
    }
    Journal::open(&config.journal_path)?;
    Ok(())
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
    #[error("connector intent requires a configured controller-owned effect runtime")]
    EffectRuntimeUnavailable,
    #[error("effect runtime failed: {0}")]
    EffectRuntime(#[from] EffectRuntimeError),
    #[error("effect service failed: {0}")]
    EffectService(#[from] EffectServiceError),
    #[error("effect is durably frozen pending reconciliation")]
    EffectReconciliationRequired,
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
    steps: Vec<ExecutionStep>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ExecutionStep {
    Process(ProcessSpec),
    ConnectorIntent(ConnectorIntentSpec),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessSpec {
    #[serde(default)]
    mode: ProcessMode,
    program: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: std::collections::BTreeMap<String, String>,
    timeout_seconds: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorIntentSpec {
    pub mapping_id: String,
    pub mapping_digest: String,
    pub effect_class: ConnectorEffectClass,
    pub effect_key_template: String,
    pub public_input_schema: std::collections::BTreeMap<String, JsonFieldType>,
    pub protected_secret_ref_schema: std::collections::BTreeMap<String, JsonFieldType>,
    pub expected_public_result_schema: std::collections::BTreeMap<String, JsonFieldType>,
    pub timeout_seconds: u64,
    pub ambiguity_policy: AmbiguityPolicy,
    pub downstream_control_digest: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorEffectClass {
    Idempotent,
    ExternallyIdempotent,
    NonIdempotent,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JsonFieldType {
    Array,
    Boolean,
    Null,
    Number,
    Object,
    String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AmbiguityPolicy {
    ObserveThenReconcile,
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ProcessMode {
    #[default]
    Direct,
    WindowsCmd,
    #[serde(rename = "powershell", alias = "power_shell")]
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
    let process = match (spec.version, spec.steps.as_slice()) {
        (1, [ExecutionStep::Process(process)]) => process,
        (2, [ExecutionStep::ConnectorIntent(intent)]) => match &config.effect_plan {
            Some(plan) => return run_effect_claim(store, claim, config, intent, plan).await,
            None => return Err(SpineError::EffectRuntimeUnavailable),
        },
        _ => return Err(SpineError::UnsupportedSpec),
    };
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
        output_limit_bytes: Some(MAX_ATTEMPT_OUTPUT_BYTES),
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

async fn run_effect_claim(
    store: &Store,
    claim: &ClaimedAttempt,
    config: &WorkerConfig,
    intent: &ConnectorIntentSpec,
    plan: &EffectExecutionPlan,
) -> Result<RunReceipt, SpineError> {
    if plan.schema_version != "mcloving.controller-effect-plan/v1"
        || plan.audit_provenance.is_empty()
    {
        return Err(SpineError::EffectRuntimeUnavailable);
    }
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
    let accepted = store
        .attempt_execution(
            claim.organization_id,
            claim.attempt_id,
            claim.fence,
            claim.restore_epoch,
            &config.agent_id,
        )
        .await?
        .ok_or(SpineError::StaleAuthority)?;
    if accepted.cancellation_requested {
        return finalize_effect_attempt(
            store,
            claim,
            config,
            TerminalOutcome::Aborted,
            json!({"reason": "cancelled_before_effect_prepare"}),
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
        return Err(SpineError::StaleAuthority);
    }

    let prepared = prepare_effect(
        store,
        claim,
        &config.agent_id,
        intent,
        &plan.freeze,
        unix_time_millis()?,
    )
    .await?;
    let frozen = store
        .attempt_execution(
            claim.organization_id,
            claim.attempt_id,
            claim.fence,
            claim.restore_epoch,
            &config.agent_id,
        )
        .await?
        .ok_or(SpineError::StaleAuthority)?;
    if frozen.cancellation_requested {
        abandon_prepared_effect(store, claim, &config.agent_id, &prepared).await?;
        return finalize_effect_attempt(
            store,
            claim,
            config,
            TerminalOutcome::Aborted,
            json!({"reason": "cancelled_before_effect_dispatch"}),
        )
        .await;
    }
    validate_observation_request(claim, plan)?;

    let outcome = match invoke_connector(
        &plan.connector_service,
        ConnectorCommand::Execute {
            request: Box::new(plan.freeze.action_request.clone()),
        },
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error) if service_may_have_dispatched(&error) => {
            route_effect_reconciliation(store, claim, config, &prepared, "connector_dispatch")
                .await?;
            return Err(SpineError::EffectReconciliationRequired);
        }
        Err(error) => {
            abandon_prepared_effect(store, claim, &config.agent_id, &prepared).await?;
            return finalize_effect_attempt(
                store,
                claim,
                config,
                TerminalOutcome::Failed,
                json!({"reason": "effect_service_preflight_failed", "code": error.to_string()}),
            )
            .await;
        }
    };
    record_effect_outcome(
        store,
        claim,
        &config.agent_id,
        intent,
        &plan.freeze,
        &prepared,
        &outcome,
    )
    .await?;

    let observation =
        match invoke_observer(&plan.observer_service, plan.observation_request.clone()).await {
            Ok(observation) => observation,
            Err(_) => {
                route_effect_reconciliation(store, claim, config, &prepared, "observer_join")
                    .await?;
                return Err(SpineError::EffectReconciliationRequired);
            }
        };
    confirm_effect_observation(
        store,
        claim,
        &config.agent_id,
        &plan.freeze,
        &prepared,
        &outcome,
        &observation,
    )
    .await?;

    let effective_outcome =
        if outcome.status == OutcomeStatus::Ambiguous || outcome.ambiguous_requires_observation {
            let observed_effect = observation
                .state
                .get("effect_observed")
                .and_then(Value::as_bool)
                .ok_or(SpineError::EffectReconciliationRequired)?;
            let reconciled = match invoke_connector(
                &plan.connector_service,
                ConnectorCommand::Reconcile {
                    request: Box::new(ReconcileRequest {
                        schema_version: RECONCILE_REQUEST_SCHEMA_VERSION.to_owned(),
                        request_id: outcome.request_id,
                        expected_request_sha256: outcome.request_sha256.clone(),
                        expected_ambiguous_receipt_sha256: outcome_receipt_digest(&outcome)
                            .map_err(|_| SpineError::EffectReconciliationRequired)?,
                        observed_effect,
                        observation_receipt: observation.clone(),
                        audit_provenance: plan.audit_provenance.clone(),
                    }),
                },
            )
            .await
            {
                Ok(reconciled) => reconciled,
                Err(_) => {
                    route_effect_reconciliation(
                        store,
                        claim,
                        config,
                        &prepared,
                        "connector_reconciliation",
                    )
                    .await?;
                    return Err(SpineError::EffectReconciliationRequired);
                }
            };
            record_reconciled_effect_outcome(
                store,
                claim,
                &config.agent_id,
                intent,
                &plan.freeze,
                &prepared,
                &outcome,
                &observation,
                &reconciled,
            )
            .await?;
            reconciled
        } else {
            outcome
        };

    let outcome_sha256 = outcome_receipt_digest(&effective_outcome)
        .map_err(|_| SpineError::EffectReconciliationRequired)?;
    let shadow = match invoke_shadow(
        &plan.shadow_service,
        ShadowReplayRequest {
            schema_version: SHADOW_REPLAY_SCHEMA_VERSION.to_owned(),
            replay_id: Uuid::new_v4(),
            expected_outcome_receipt_sha256: outcome_sha256,
            expected_shadow_identity: plan.freeze.expected_shadow_identity.clone(),
            outcome_receipt: effective_outcome.clone(),
            replayed_at_unix_ms: unix_time_millis()?,
            audit_provenance: plan.audit_provenance.clone(),
        },
    )
    .await
    {
        Ok(shadow) => shadow,
        Err(_) => {
            route_effect_reconciliation(store, claim, config, &prepared, "shadow_replay").await?;
            return Err(SpineError::EffectReconciliationRequired);
        }
    };
    let cancellation_requested = store
        .attempt_execution(
            claim.organization_id,
            claim.attempt_id,
            claim.fence,
            claim.restore_epoch,
            &config.agent_id,
        )
        .await?
        .ok_or(SpineError::StaleAuthority)?
        .cancellation_requested;
    let terminal = finalize_effect_shadow_join_as(
        store,
        claim,
        &config.agent_id,
        &plan.freeze,
        &prepared,
        &effective_outcome,
        &shadow,
        cancellation_requested.then_some(TerminalOutcome::Aborted),
    )
    .await?;
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

fn validate_observation_request(
    claim: &ClaimedAttempt,
    plan: &EffectExecutionPlan,
) -> Result<(), SpineError> {
    let fence = u64::try_from(claim.fence).map_err(|_| SpineError::FenceOverflow)?;
    if plan.observation_request.tenant_id != claim.organization_id
        || plan.observation_request.build_id != claim.build_id
        || plan.observation_request.attempt_id != claim.attempt_id
        || plan.observation_request.effect_fence != fence
        || plan.observation_request.observer_id != plan.freeze.expected_observer_id
        || !matches!(
            plan.observation_request.phase,
            ObservationPhase::PostAction | ObservationPhase::Reconciliation
        )
    {
        return Err(SpineError::EffectRuntimeUnavailable);
    }
    Ok(())
}

fn service_may_have_dispatched(error: &EffectServiceError) -> bool {
    matches!(
        error,
        EffectServiceError::AmbiguousTimeout
            | EffectServiceError::ResponseTooLarge
            | EffectServiceError::ServiceFailed
            | EffectServiceError::InvalidResponse
            | EffectServiceError::Io(_)
    )
}

async fn route_effect_reconciliation(
    store: &Store,
    claim: &ClaimedAttempt,
    config: &WorkerConfig,
    prepared: &PreparedEffect,
    phase: &str,
) -> Result<(), SpineError> {
    mark_effect_uncertain(store, claim, &config.agent_id, prepared).await?;
    let published = store
        .finalize_attempt(
            claim.organization_id,
            claim.attempt_id,
            claim.fence,
            claim.restore_epoch,
            &config.agent_id,
            TerminalOutcome::Failed,
            json!({"reason": "effect_reconciliation_required", "phase": phase}),
        )
        .await?;
    if published {
        return Err(SpineError::EffectRuntimeUnavailable);
    }
    Ok(())
}

async fn finalize_effect_attempt(
    store: &Store,
    claim: &ClaimedAttempt,
    config: &WorkerConfig,
    outcome: TerminalOutcome,
    summary: Value,
) -> Result<RunReceipt, SpineError> {
    if !store
        .finalize_attempt(
            claim.organization_id,
            claim.attempt_id,
            claim.fence,
            claim.restore_epoch,
            &config.agent_id,
            outcome,
            summary,
        )
        .await?
    {
        return Err(SpineError::StaleAuthority);
    }
    Ok(RunReceipt {
        build_id: claim.build_id,
        attempt_id: claim.attempt_id,
        fence: claim.fence,
        outcome,
        exit_code: None,
        stdout_sha256: [0; 32],
        stderr_sha256: [0; 32],
    })
}

fn unix_time_millis() -> Result<i64, SpineError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SpineError::FenceOverflow)?
        .as_millis();
    i64::try_from(millis).map_err(|_| SpineError::FenceOverflow)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn powershell_mode_accepts_current_and_protocol_v1_wire_spellings() {
        for mode in ["powershell", "power_shell"] {
            let spec: ExecutionSpec = serde_json::from_value(json!({
                "version": 1,
                "steps": [{
                    "kind": "process",
                    "mode": mode,
                    "program": "build.ps1"
                }]
            }))
            .expect("accept supported PowerShell wire spelling");
            assert!(matches!(
                spec.steps[0],
                ExecutionStep::Process(ProcessSpec {
                    mode: ProcessMode::PowerShell,
                    ..
                })
            ));
        }

        assert!(
            serde_json::from_value::<ExecutionSpec>(json!({
                "version": 1,
                "steps": [{
                    "kind": "process",
                    "mode": "shell",
                    "program": "build.ps1"
                }]
            }))
            .is_err(),
            "unknown execution modes must remain fail-closed"
        );
    }

    #[test]
    fn connector_intent_protocol_is_closed_and_never_accepts_authority_overrides() {
        let spec = json!({
            "version": 2,
            "steps": [{
                "kind": "connector_intent",
                "mapping_id": "notification.v1",
                "mapping_digest": format!("sha256:{}", "a".repeat(64)),
                "effect_class": "externally_idempotent",
                "effect_key_template": "build.notification",
                "public_input_schema": {"message": "string"},
                "protected_secret_ref_schema": {"token": "string"},
                "expected_public_result_schema": {"delivery_id": "string"},
                "timeout_seconds": 30,
                "ambiguity_policy": "observe_then_reconcile",
                "downstream_control_digest": format!("sha256:{}", "b".repeat(64)),
            }]
        });
        let parsed: ExecutionSpec = serde_json::from_value(spec.clone()).expect("typed intent");
        assert!(matches!(parsed.steps[0], ExecutionStep::ConnectorIntent(_)));
        for forbidden in ["endpoint_url", "credential", "program"] {
            let mut mutated = spec.clone();
            mutated["steps"][0][forbidden] = json!("forbidden");
            assert!(serde_json::from_value::<ExecutionSpec>(mutated).is_err());
        }
    }
}
