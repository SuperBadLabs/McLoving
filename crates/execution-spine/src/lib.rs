//! The smallest truthful controller-to-agent execution spine.

mod effect_runtime;
mod effect_transport;

pub use effect_runtime::{
    EffectRuntimeError, EffectRuntimeFreeze, FreshOneActionGrant, PreparedEffect,
    abandon_prepared_effect, commit_effect_dispatch, confirm_effect_observation,
    finalize_effect_shadow_join, finalize_effect_shadow_join_as, mark_effect_release_pending,
    mark_effect_uncertain, prepare_effect, record_effect_outcome, record_reconciled_effect_outcome,
};
pub use effect_transport::{
    EffectServiceError, PinnedServiceCommand, invoke_connector, invoke_observer, invoke_shadow,
};
use effect_transport::{ValidatedEffectServices, preflight_effect_services};

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
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
    ActionRequest, ConnectorCommand, OutcomeStatus, RECONCILE_REQUEST_SCHEMA_VERSION,
    ReconcileRequest, SHADOW_REPLAY_SCHEMA_VERSION, ShadowReplayRequest, outcome_receipt_digest,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::fs;
use tokio::sync::Mutex;
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
    #[error("controller effect invariant violated: {0}")]
    EffectInvariantViolated(&'static str),
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
    renew_effect_lease(store, claim, config).await?;
    let renewal_interval = effect_renewal_interval(config);
    let dispatch_state = Arc::new(AtomicU8::new(EFFECT_PREDISPATCH));
    let renewal_gate = Arc::new(Mutex::new(()));
    let effect = run_effect_claim_under_lease(
        store,
        claim,
        config,
        intent,
        plan,
        Arc::clone(&dispatch_state),
        Arc::clone(&renewal_gate),
    );
    let renewal = maintain_effect_lease(
        store,
        claim,
        config,
        renewal_interval,
        Arc::clone(&renewal_gate),
    );
    tokio::pin!(effect, renewal);
    tokio::select! {
        result = &mut effect => result,
        result = &mut renewal => {
            let renewal_error = match result {
                Ok(()) => SpineError::StaleAuthority,
                Err(error) => error,
            };
            let _ = dispatch_state.compare_exchange(
                EFFECT_PREDISPATCH,
                EFFECT_RENEWAL_LOST,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            match (&mut effect).await {
                Ok(receipt) => Ok(receipt),
                Err(SpineError::StaleAuthority) => Err(renewal_error),
                Err(error) => Err(error),
            }
        }
    }
}

const EFFECT_PREDISPATCH: u8 = 0;
const EFFECT_DISPATCH_COMMITTED: u8 = 1;
const EFFECT_RENEWAL_LOST: u8 = 2;
const EFFECT_DISPATCH_COMMITTING: u8 = 3;

async fn run_effect_claim_under_lease(
    store: &Store,
    claim: &ClaimedAttempt,
    config: &WorkerConfig,
    intent: &ConnectorIntentSpec,
    plan: &EffectExecutionPlan,
    dispatch_state: Arc<AtomicU8>,
    renewal_gate: Arc<Mutex<()>>,
) -> Result<RunReceipt, SpineError> {
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
    let pipeline_id = accepted
        .pipeline_id
        .ok_or(SpineError::EffectRuntimeUnavailable)?;
    // Compare the complete frozen one-action binding, not just the execution
    // scope. A plan bound to another build, attempt, fence, or effect key
    // would only be rejected later by `validate_freeze`, whose error
    // propagates without a terminal publication; the checkpoint-free attempt
    // would then requeue on lease expiry and the mismatch could win the queue
    // repeatedly. Terminalize the mismatch here instead.
    let claim_fence = u64::try_from(claim.fence).map_err(|_| SpineError::FenceOverflow)?;
    if plan.freeze.action_request.tenant_id != claim.organization_id
        || plan.freeze.action_request.project_id != accepted.project_id
        || plan.freeze.action_request.pipeline_id != pipeline_id
        || plan.freeze.action_request.build_id != claim.build_id
        || plan.freeze.action_request.attempt_id != claim.attempt_id
        || plan.freeze.action_request.effect_fence != claim_fence
        || plan.freeze.action_request.effect_key != intent.effect_key_template
    {
        return finalize_effect_attempt(
            store,
            claim,
            config,
            TerminalOutcome::Failed,
            json!({"reason": "effect_plan_scope_mismatch"}),
        )
        .await;
    }
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

    let prepare_now = unix_time_millis()?;
    let remaining_action_authority_ms = plan
        .freeze
        .action_request
        .expires_at_unix_ms
        .checked_sub(prepare_now)
        .and_then(|remaining| u64::try_from(remaining).ok());
    let Some(remaining_action_authority_ms) = remaining_action_authority_ms
        .filter(|remaining| *remaining > plan.observer_service.timeout_millis)
    else {
        return finalize_effect_attempt(
            store,
            claim,
            config,
            TerminalOutcome::Failed,
            json!({"reason": "effect_action_request_preflight_failed"}),
        )
        .await;
    };
    let connector_service = match bounded_connector_service(
        &plan.connector_service,
        intent,
        plan.observer_service.timeout_millis,
        remaining_action_authority_ms,
    ) {
        Ok(service) => service,
        Err(_) => {
            return finalize_effect_attempt(
                store,
                claim,
                config,
                TerminalOutcome::Failed,
                json!({"reason": "effect_timeout_budget_exhausted"}),
            )
            .await;
        }
    };
    let preflight_validity_ms = connector_service
        .timeout_millis
        .checked_add(plan.observer_service.timeout_millis)
        .ok_or(SpineError::EffectRuntimeUnavailable)?;
    if !action_request_covers_execution_window(
        &plan.freeze.action_request,
        prepare_now,
        preflight_validity_ms,
    ) {
        return finalize_effect_attempt(
            store,
            claim,
            config,
            TerminalOutcome::Failed,
            json!({"reason": "effect_action_request_preflight_failed"}),
        )
        .await;
    }

    let prepared = prepare_effect(
        store,
        claim,
        &config.agent_id,
        intent,
        &plan.freeze,
        plan.observation_request.expires_at_unix_ms,
        prepare_now,
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
    if validate_observation_request(
        claim,
        accepted.project_id,
        pipeline_id,
        plan,
        &prepared.request_sha256,
    )
    .is_err()
    {
        abandon_prepared_effect(store, claim, &config.agent_id, &prepared).await?;
        return finalize_effect_attempt(
            store,
            claim,
            config,
            TerminalOutcome::Failed,
            json!({"reason": "effect_observation_request_preflight_failed"}),
        )
        .await;
    }
    let services = match preflight_effect_services(
        &connector_service,
        &plan.observer_service,
        &plan.shadow_service,
    )
    .await
    {
        Ok(services) => services,
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

    if let Err(error) = services
        .verify_observer_request(plan.observation_request.clone())
        .await
    {
        if matches!(&error, EffectServiceError::ObserverRejected(_)) {
            abandon_prepared_effect(store, claim, &config.agent_id, &prepared).await?;
            return finalize_effect_attempt(
                store,
                claim,
                config,
                TerminalOutcome::Failed,
                json!({
                    "reason": "effect_observation_request_rejected",
                    "code": error.to_string()
                }),
            )
            .await;
        }
        return finalize_reserved_pre_dispatch_exit(
            store,
            claim,
            config,
            &prepared,
            &services,
            &plan.observation_request,
            (
                TerminalOutcome::Failed,
                json!({
                    "reason": "effect_observation_request_preflight_failed",
                    "code": error.to_string()
                }),
            ),
        )
        .await;
    }

    // Exclude an in-flight renewal query from the final durable authority
    // check and local dispatch commit. The fresh renewal gives the connector
    // call a full lease window; attempt_execution then revalidates the exact
    // fence after its pipeline lock before the local commit is published.
    let dispatch_renewal_guard = renewal_gate.lock().await;
    if let Err(error) = renew_effect_lease(store, claim, config).await {
        let released = services
            .release_observer_request(plan.observation_request.clone())
            .await
            .is_ok();
        persist_undispatched_release_disposition(
            store,
            claim,
            &config.agent_id,
            &prepared,
            released,
        )
        .await?;
        return Err(error);
    }
    let pre_dispatch = match store
        .attempt_execution(
            claim.organization_id,
            claim.attempt_id,
            claim.fence,
            claim.restore_epoch,
            &config.agent_id,
        )
        .await
    {
        Ok(Some(execution)) => execution,
        Ok(None) => {
            let released = services
                .release_observer_request(plan.observation_request.clone())
                .await
                .is_ok();
            persist_undispatched_release_disposition(
                store,
                claim,
                &config.agent_id,
                &prepared,
                released,
            )
            .await?;
            return Err(SpineError::StaleAuthority);
        }
        Err(error) => {
            let released = services
                .release_observer_request(plan.observation_request.clone())
                .await
                .is_ok();
            persist_undispatched_release_disposition(
                store,
                claim,
                &config.agent_id,
                &prepared,
                released,
            )
            .await?;
            return Err(error.into());
        }
    };
    if pre_dispatch.cancellation_requested {
        return finalize_reserved_pre_dispatch_exit(
            store,
            claim,
            config,
            &prepared,
            &services,
            &plan.observation_request,
            (
                TerminalOutcome::Aborted,
                json!({"reason": "cancelled_during_effect_preflight"}),
            ),
        )
        .await;
    }
    let dispatch_now = match unix_time_millis() {
        Ok(now) => now,
        Err(_) => {
            return finalize_reserved_pre_dispatch_exit(
                store,
                claim,
                config,
                &prepared,
                &services,
                &plan.observation_request,
                (
                    TerminalOutcome::Failed,
                    json!({"reason": "effect_dispatch_clock_unavailable"}),
                ),
            )
            .await;
        }
    };
    if !action_request_covers_execution_window(
        &plan.freeze.action_request,
        dispatch_now,
        connector_service.timeout_millis,
    ) {
        return finalize_reserved_pre_dispatch_exit(
            store,
            claim,
            config,
            &prepared,
            &services,
            &plan.observation_request,
            (
                TerminalOutcome::Failed,
                json!({"reason": "effect_action_request_preflight_failed"}),
            ),
        )
        .await;
    }
    // The observer approved `Verify` for the full connector-plus-observer
    // window as of that call; waiting on the renewal gate or the authority
    // query can outlive that approval. Revalidate the observation request for
    // the complete remaining connector and observer window at the final
    // dispatch decision so a non-idempotent action can never be dispatched
    // once the post-action observation is no longer coverable.
    if !observation_request_covers_execution_window(
        &plan.observation_request,
        dispatch_now,
        preflight_validity_ms,
    ) {
        return finalize_reserved_pre_dispatch_exit(
            store,
            claim,
            config,
            &prepared,
            &services,
            &plan.observation_request,
            (
                TerminalOutcome::Failed,
                json!({"reason": "effect_observation_request_preflight_failed"}),
            ),
        )
        .await;
    }

    // Reserve the local commit state before the durable checkpoint. Holding the
    // renewal gate prevents a renewal failure from racing this transition.
    if dispatch_state
        .compare_exchange(
            EFFECT_PREDISPATCH,
            EFFECT_DISPATCH_COMMITTING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        let released = services
            .release_observer_request(plan.observation_request.clone())
            .await
            .is_ok();
        persist_undispatched_release_disposition(
            store,
            claim,
            &config.agent_id,
            &prepared,
            released,
        )
        .await?;
        return Err(SpineError::StaleAuthority);
    }

    // This is the durable dispatch commit. Once it succeeds, lease-expiry
    // recovery must treat the connector as possibly dispatched even if this
    // process is paused before the invocation below. The exact fenced lease
    // and immutable prepared payload are checked in the same store transaction.
    if let Err(error) = commit_effect_dispatch(store, claim, &config.agent_id, &prepared).await {
        // The durable commit refuses a fresh dispatch once cancellation has
        // committed. Distinguish that acknowledged refusal from genuine
        // authority loss so the cancelled attempt is published as aborted
        // instead of stranding in `cancelling`.
        if matches!(error, EffectRuntimeError::StaleAuthority)
            && let Ok(Some(execution)) = store
                .attempt_execution(
                    claim.organization_id,
                    claim.attempt_id,
                    claim.fence,
                    claim.restore_epoch,
                    &config.agent_id,
                )
                .await
            && execution.cancellation_requested
        {
            return finalize_reserved_pre_dispatch_exit(
                store,
                claim,
                config,
                &prepared,
                &services,
                &plan.observation_request,
                (
                    TerminalOutcome::Aborted,
                    json!({"reason": "cancelled_before_effect_dispatch"}),
                ),
            )
            .await;
        }
        let released = services
            .release_observer_request(plan.observation_request.clone())
            .await
            .is_ok();
        persist_undispatched_release_disposition(
            store,
            claim,
            &config.agent_id,
            &prepared,
            released,
        )
        .await?;
        return Err(error.into());
    }
    dispatch_state.store(EFFECT_DISPATCH_COMMITTED, Ordering::Release);
    drop(dispatch_renewal_guard);

    let outcome = match services
        .invoke_connector(ConnectorCommand::Execute {
            request: Box::new(plan.freeze.action_request.clone()),
        })
        .await
    {
        Ok(outcome) => outcome,
        Err(_) => {
            route_effect_reconciliation(store, claim, config, &prepared, "connector_dispatch")
                .await?;
            return Err(SpineError::EffectReconciliationRequired);
        }
    };
    if record_effect_outcome(
        store,
        claim,
        &config.agent_id,
        intent,
        &plan.freeze,
        &prepared,
        &outcome,
    )
    .await
    .is_err()
    {
        route_effect_reconciliation(store, claim, config, &prepared, "connector_outcome").await?;
        return Err(SpineError::EffectReconciliationRequired);
    }

    let observation = match services
        .invoke_observer(plan.observation_request.clone())
        .await
    {
        Ok(observation) => observation,
        Err(_) => {
            route_effect_reconciliation(store, claim, config, &prepared, "observer_join").await?;
            return Err(SpineError::EffectReconciliationRequired);
        }
    };
    if confirm_effect_observation(
        store,
        claim,
        &config.agent_id,
        &plan.freeze,
        &prepared,
        &outcome,
        &plan.observation_request,
        &observation,
    )
    .await
    .is_err()
    {
        route_effect_reconciliation(store, claim, config, &prepared, "observer_outcome").await?;
        return Err(SpineError::EffectReconciliationRequired);
    }

    let effective_outcome = if outcome.status == OutcomeStatus::Ambiguous
        || outcome.ambiguous_requires_observation
    {
        let Some(observed_effect) = observation
            .state
            .get("effect_observed")
            .and_then(Value::as_bool)
        else {
            route_effect_reconciliation(store, claim, config, &prepared, "observer_state").await?;
            return Err(SpineError::EffectReconciliationRequired);
        };
        let reconciled = match services
            .invoke_connector(ConnectorCommand::Reconcile {
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
            })
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
        if record_reconciled_effect_outcome(
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
        .await
        .is_err()
        {
            route_effect_reconciliation(
                store,
                claim,
                config,
                &prepared,
                "connector_reconciliation_outcome",
            )
            .await?;
            return Err(SpineError::EffectReconciliationRequired);
        }
        reconciled
    } else {
        outcome
    };

    let outcome_sha256 = match outcome_receipt_digest(&effective_outcome) {
        Ok(digest) => digest,
        Err(_) => {
            route_effect_reconciliation(store, claim, config, &prepared, "shadow_request").await?;
            return Err(SpineError::EffectReconciliationRequired);
        }
    };
    let shadow = match services
        .invoke_shadow(ShadowReplayRequest {
            schema_version: SHADOW_REPLAY_SCHEMA_VERSION.to_owned(),
            replay_id: Uuid::new_v4(),
            expected_outcome_receipt_sha256: outcome_sha256,
            expected_shadow_identity: plan.freeze.expected_shadow_identity.clone(),
            outcome_receipt: effective_outcome.clone(),
            replayed_at_unix_ms: unix_time_millis()?,
            audit_provenance: plan.audit_provenance.clone(),
        })
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
    let terminal = match finalize_effect_shadow_join_as(
        store,
        claim,
        &config.agent_id,
        &plan.freeze,
        &prepared,
        &effective_outcome,
        &shadow,
        cancellation_requested.then_some(TerminalOutcome::Aborted),
    )
    .await
    {
        Ok(terminal) => terminal,
        Err(_) => {
            route_effect_reconciliation(store, claim, config, &prepared, "shadow_outcome").await?;
            return Err(SpineError::EffectReconciliationRequired);
        }
    };
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
    project_id: Uuid,
    pipeline_id: Uuid,
    plan: &EffectExecutionPlan,
    request_sha256: &str,
) -> Result<(), SpineError> {
    let fence = u64::try_from(claim.fence).map_err(|_| SpineError::FenceOverflow)?;
    // Bind the observation request to the frozen action before verification
    // and dispatch: a request aimed at another destination, effect class, or
    // connector request digest would pass observer Verify (the observer only
    // checks its own deployment binding), reserve the mismatched observation,
    // and fail the cross-binding join only after a potentially non-idempotent
    // dispatch. Refusing here keeps the exit on the reserved pre-dispatch
    // path instead of reconciliation.
    if plan.observation_request.tenant_id != claim.organization_id
        || plan.observation_request.project_id != project_id
        || plan.observation_request.pipeline_id != pipeline_id
        || plan.observation_request.build_id != claim.build_id
        || plan.observation_request.attempt_id != claim.attempt_id
        || plan.observation_request.effect_fence != fence
        || plan.observation_request.observer_id != plan.freeze.expected_observer_id
        || plan.observation_request.endpoint_identity
            != plan.freeze.action_request.endpoint_identity
        || plan.observation_request.account_identity != plan.freeze.action_request.account_identity
        || plan.observation_request.resource_identity
            != plan.freeze.action_request.resource_identity
        || plan.observation_request.effect_class != plan.freeze.action_request.effect_class
        || plan
            .observation_request
            .query
            .get("connector_request_sha256")
            .map(String::as_str)
            != Some(request_sha256)
        || plan
            .observation_request
            .predecessor_receipt_sha256
            .as_deref()
            != Some(plan.freeze.pre_action_observation_sha256.as_str())
        || !matches!(
            plan.observation_request.phase,
            ObservationPhase::PostAction | ObservationPhase::Reconciliation
        )
    {
        return Err(SpineError::EffectRuntimeUnavailable);
    }
    Ok(())
}

/// Persist cleanup through the current lease when it is still authoritative,
/// falling back to the lease-less transition only after authority is stale.
async fn persist_undispatched_release_disposition(
    store: &Store,
    claim: &ClaimedAttempt,
    agent_id: &str,
    prepared: &PreparedEffect,
    released: bool,
) -> Result<(), SpineError> {
    let live_checkpoint = if released {
        abandon_prepared_effect(store, claim, agent_id, prepared).await
    } else {
        mark_effect_release_pending(store, claim, agent_id, prepared).await
    };
    match live_checkpoint {
        Ok(()) => Ok(()),
        Err(EffectRuntimeError::StaleAuthority) => {
            if store
                .record_undispatched_release_after_authority_loss(
                    claim.organization_id,
                    claim.attempt_id,
                    claim.fence,
                    claim.restore_epoch,
                    agent_id,
                    &prepared.effect_key,
                    prepared.effect_class,
                    &prepared.payload,
                    released,
                )
                .await?
            {
                Ok(())
            } else {
                Err(SpineError::EffectRuntimeUnavailable)
            }
        }
        Err(error) => Err(error.into()),
    }
}

async fn finalize_reserved_pre_dispatch_exit(
    store: &Store,
    claim: &ClaimedAttempt,
    config: &WorkerConfig,
    prepared: &PreparedEffect,
    services: &ValidatedEffectServices,
    observation_request: &ObservationRequest,
    outcome: (TerminalOutcome, Value),
) -> Result<RunReceipt, SpineError> {
    let (terminal, mut summary) = outcome;
    let mut released = false;
    for attempt in 1..=3 {
        if services
            .release_observer_request(observation_request.clone())
            .await
            .is_ok()
        {
            released = true;
            break;
        }
        if attempt < 3 {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
    // Most callers reach here holding the dispatch renewal gate, so no lease
    // maintenance can run while the observer release is retried above. A slow
    // release can therefore outlive the lease and leave this checkpoint with
    // no live authority. Take the stale-authority fallback for both release
    // outcomes: the live checkpoint alone would leave the effect `prepared`,
    // and once expiry rewrites it to ordinary `uncertain` the release-expiry
    // abandonment transition can no longer claim it.
    if !released {
        persist_undispatched_release_disposition(store, claim, &config.agent_id, prepared, false)
            .await?;
        let published = store
            .finalize_attempt(
                claim.organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                &config.agent_id,
                TerminalOutcome::Failed,
                json!({
                    "reason": "effect_reconciliation_required",
                    "phase": "observer_reservation_release"
                }),
            )
            .await?;
        if published {
            // Not an inversion: this effect was just durably marked
            // release_pending, so the store must refuse terminal publication
            // and route the attempt to reconciliation instead. A published
            // terminal here means the controller store broke that guarantee.
            return Err(SpineError::EffectInvariantViolated(
                "the store published a terminal outcome for an attempt holding a release_pending effect",
            ));
        }
        return Err(SpineError::EffectReconciliationRequired);
    }
    persist_undispatched_release_disposition(store, claim, &config.agent_id, prepared, true)
        .await?;
    if let Some(summary) = summary.as_object_mut() {
        summary.insert(
            "observer_reservation_release".to_owned(),
            json!({"status": "released"}),
        );
    }
    finalize_effect_attempt(store, claim, config, terminal, summary).await
}

fn bounded_connector_service(
    service: &PinnedServiceCommand,
    intent: &ConnectorIntentSpec,
    observer_preflight_timeout_millis: u64,
    remaining_action_authority_millis: u64,
) -> Result<PinnedServiceCommand, SpineError> {
    let intent_timeout_millis = intent
        .timeout_seconds
        .checked_mul(1_000)
        .ok_or(SpineError::EffectRuntimeUnavailable)?;
    let total_budget_millis = intent_timeout_millis.min(remaining_action_authority_millis);
    let connector_budget_millis = total_budget_millis
        .checked_sub(observer_preflight_timeout_millis)
        .filter(|budget| *budget > 0)
        .ok_or(SpineError::EffectRuntimeUnavailable)?;
    let mut bounded = service.clone();
    bounded.timeout_millis = bounded.timeout_millis.min(connector_budget_millis);
    if bounded.timeout_millis == 0 {
        return Err(SpineError::EffectRuntimeUnavailable);
    }
    Ok(bounded)
}

fn action_request_covers_execution_window(
    request: &ActionRequest,
    now_unix_ms: i64,
    required_validity_ms: u64,
) -> bool {
    validity_window_covers(
        request.expires_at_unix_ms,
        now_unix_ms,
        required_validity_ms,
    )
}

fn observation_request_covers_execution_window(
    request: &ObservationRequest,
    now_unix_ms: i64,
    required_validity_ms: u64,
) -> bool {
    validity_window_covers(
        request.expires_at_unix_ms,
        now_unix_ms,
        required_validity_ms,
    )
}

fn validity_window_covers(
    expires_at_unix_ms: i64,
    now_unix_ms: i64,
    required_validity_ms: u64,
) -> bool {
    i64::try_from(required_validity_ms)
        .ok()
        .and_then(|required| now_unix_ms.checked_add(required))
        .is_some_and(|deadline| deadline <= expires_at_unix_ms)
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
        // Not an inversion: this effect was just durably marked uncertain, so
        // the store must refuse terminal publication and route the attempt to
        // reconciliation instead. A published terminal here means the
        // controller store broke that guarantee.
        return Err(SpineError::EffectInvariantViolated(
            "the store published a terminal outcome for an attempt holding an uncertain effect",
        ));
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

fn effect_renewal_interval(config: &WorkerConfig) -> Duration {
    Duration::from_millis(
        u64::try_from(config.lease_seconds)
            .unwrap_or(1)
            .saturating_mul(1_000)
            .checked_div(3)
            .unwrap_or(1)
            .max(1),
    )
}

async fn maintain_effect_lease(
    store: &Store,
    claim: &ClaimedAttempt,
    config: &WorkerConfig,
    interval: Duration,
    renewal_gate: Arc<Mutex<()>>,
) -> Result<(), SpineError> {
    loop {
        tokio::time::sleep(interval).await;
        let _renewal_guard = renewal_gate.lock().await;
        renew_effect_lease(store, claim, config).await?;
    }
}

async fn renew_effect_lease(
    store: &Store,
    claim: &ClaimedAttempt,
    config: &WorkerConfig,
) -> Result<(), SpineError> {
    if store
        .renew_attempt_lease(
            claim.organization_id,
            claim.attempt_id,
            claim.fence,
            claim.restore_epoch,
            &config.agent_id,
            config.lease_seconds,
        )
        .await?
        .is_none()
    {
        return Err(SpineError::StaleAuthority);
    }
    // A cancellation request is joined after dispatch; renewal retains the
    // fence until the independent outcome, observation, and shadow are durable.
    Ok(())
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

    #[test]
    fn connector_service_timeout_is_bounded_by_the_pipeline_intent() {
        let intent = ConnectorIntentSpec {
            mapping_id: "notification.v1".into(),
            mapping_digest: format!("sha256:{}", "a".repeat(64)),
            effect_class: ConnectorEffectClass::ExternallyIdempotent,
            effect_key_template: "build.notification".into(),
            public_input_schema: Default::default(),
            protected_secret_ref_schema: Default::default(),
            expected_public_result_schema: Default::default(),
            timeout_seconds: 2,
            ambiguity_policy: AmbiguityPolicy::ObserveThenReconcile,
            downstream_control_digest: format!("sha256:{}", "b".repeat(64)),
        };
        let service = PinnedServiceCommand {
            executable: PathBuf::from("/fixture/connector"),
            executable_sha256: "c".repeat(64),
            arguments: Vec::new(),
            timeout_millis: 30_000,
        };
        assert_eq!(
            bounded_connector_service(&service, &intent, 500, 1_900)
                .expect("bound service timeout")
                .timeout_millis,
            1_400
        );
        assert!(bounded_connector_service(&service, &intent, 500, 500).is_err());
    }

    #[test]
    fn effect_renewal_is_capped_well_before_lease_expiry() {
        let config = WorkerConfig {
            agent_id: "renewal-test".into(),
            session_epoch: 1,
            workspace_root: PathBuf::from("/unused/workspace"),
            journal_path: PathBuf::from("/unused/journal"),
            cancellation_poll: Duration::from_millis(4_900),
            lease_seconds: 5,
            termination_grace: Duration::from_secs(1),
            effect_plan: None,
        };
        assert_eq!(
            effect_renewal_interval(&config),
            Duration::from_millis(1_666)
        );
    }
}
