use std::path::PathBuf;
use std::process::{Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::AsyncWriteExt as _;
use tokio::process::Command;
use uuid::Uuid;

use crate::publication::{ConcurrentClaimState, SerializedOutputGuard};
use crate::{
    AdapterBindings, CanonicalPlan, CertifiedConfig, ClaimOutcome, Ecosystem, HttpTransport,
    LoadedAuthorities, RepositoryBinding, ResolutionReceipt, ResolutionRequest, ResolutionStore,
    StoreError, parse_maven_lock, parse_npm_package_lock, parse_pypi_requirements,
};

pub const MAX_PUBLICATION_WORKER_BYTES: usize = 16 * 1_048_576;
const DELIVERY_ACK_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionFrame {
    pub request: ResolutionRequest,
    pub lock_base64: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PublicationWorkerRequest {
    config: CertifiedConfig,
    claim: crate::ResolutionClaim,
    request: ResolutionRequest,
    admitted: crate::AdmittedRequest,
    plan: CanonicalPlan,
    fetched: Vec<crate::FetchedArtifact>,
    deadline_monotonic_ns: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum PublicationWorkerResponse {
    Ok { receipt: Box<ResolutionReceipt> },
    Error { code: String },
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("{code}: {message}")]
pub struct ResolverError {
    pub code: &'static str,
    pub message: &'static str,
}

impl ResolverError {
    pub(crate) fn denied(code: &'static str) -> Self {
        Self {
            code,
            message: "dependency resolution was denied",
        }
    }
}

pub struct DependencyResolver {
    config: CertifiedConfig,
    store: ResolutionStore,
    transport: HttpTransport,
    publication_worker: PathBuf,
    store_serial: tokio::sync::Mutex<()>,
    store_poisoned: AtomicBool,
    publication_serial: tokio::sync::Mutex<()>,
    publication_poisoned: AtomicBool,
}

impl DependencyResolver {
    pub fn new(config: CertifiedConfig) -> Result<Self, ResolverError> {
        #[cfg(target_os = "linux")]
        let publication_worker = PathBuf::from("/proc/self/exe");
        #[cfg(not(target_os = "linux"))]
        let publication_worker = std::env::current_exe()
            .map_err(|_| ResolverError::denied("DEP_EXECUTABLE_IDENTITY_INVALID"))?;
        Self::new_inner(config, publication_worker, false)
    }

    pub fn new_with_publication_worker(
        config: CertifiedConfig,
        publication_worker: PathBuf,
    ) -> Result<Self, ResolverError> {
        if !config.loopback_fixture
            || std::env::var_os("MCLOVING_DEPENDENCY_RESOLVER_TEST_MODE").as_deref()
                != Some(std::ffi::OsStr::new("1"))
        {
            return Err(ResolverError::denied("DEP_EXECUTABLE_IDENTITY_INVALID"));
        }
        Self::new_inner(config, publication_worker, true)
    }

    fn new_inner(
        config: CertifiedConfig,
        publication_worker: PathBuf,
        canonicalize_worker: bool,
    ) -> Result<Self, ResolverError> {
        crate::standalone::verify_executable_path(&config, &publication_worker)?;
        let publication_worker = if canonicalize_worker {
            std::fs::canonicalize(publication_worker)
                .map_err(|_| ResolverError::denied("DEP_EXECUTABLE_IDENTITY_INVALID"))?
        } else {
            publication_worker
        };
        let authorities =
            LoadedAuthorities::load(&config).map_err(|error| ResolverError::denied(error.code))?;
        let store = ResolutionStore::open(&config, &authorities)
            .map_err(|error| ResolverError::denied(error.code))?;
        let transport = HttpTransport::new(&config, &authorities)
            .map_err(|error| ResolverError::denied(error.code))?;
        Ok(Self {
            config,
            store,
            transport,
            publication_worker,
            store_serial: tokio::sync::Mutex::new(()),
            store_poisoned: AtomicBool::new(false),
            publication_serial: tokio::sync::Mutex::new(()),
            publication_poisoned: AtomicBool::new(false),
        })
    }

    pub async fn resolve_frame(
        &self,
        frame: ResolutionFrame,
    ) -> Result<ResolutionReceipt, ResolverError> {
        let receipt = self.resolve_frame_for_output(frame).await?;
        self.acknowledge_response_delivery(&receipt).await;
        Ok(receipt)
    }

    pub async fn resolve_frame_for_output(
        &self,
        frame: ResolutionFrame,
    ) -> Result<ResolutionReceipt, ResolverError> {
        if self.store_poisoned.load(Ordering::Acquire) {
            return Err(ResolverError::denied(
                "DEP_STORE_PARENT_IO_RESTART_REQUIRED",
            ));
        }
        if self.publication_poisoned.load(Ordering::Acquire) {
            return Err(ResolverError::denied(
                "DEP_STORE_PUBLICATION_RESTART_REQUIRED",
            ));
        }
        self.transport
            .ensure_available()
            .map_err(|error| ResolverError::denied(error.code))?;
        let started_at = Instant::now();
        let wall_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ResolverError::denied("DEP_REQUEST_TIME_INVALID"))?;
        let now_unix_ms = u64::try_from(wall_now.as_millis())
            .map_err(|_| ResolverError::denied("DEP_REQUEST_TIME_INVALID"))?;
        let remaining = duration_until_unix_deadline(frame.request.expires_at_unix_ms, wall_now)?;
        let deadline = started_at
            .checked_add(remaining)
            .ok_or_else(|| ResolverError::denied("DEP_REQUEST_TIME_INVALID"))?;
        let lock_bytes = BASE64
            .decode(&frame.lock_base64)
            .map_err(|_| ResolverError::denied("DEP_REQUEST_LOCK_ENCODING_INVALID"))?;
        if lock_bytes.len() as u64 > self.config.limits.max_lock_bytes {
            return Err(ResolverError::denied("DEP_LOCK_SIZE_INVALID"));
        }
        let bindings = self.adapter_bindings(&frame.request)?;
        let plan = parse_lock(&frame.request, &lock_bytes, &bindings)?;
        if Instant::now() >= deadline {
            return Err(ResolverError::denied("DEP_REQUEST_TIME_INVALID"));
        }
        let admitted = crate::admit_request(
            &self.config,
            &frame.request,
            &plan,
            &lock_bytes,
            now_unix_ms,
        )
        .map_err(|error| ResolverError::denied(error.code))?;
        let store = self.store.clone();
        let claim_request = frame.request.clone();
        let claim_admitted = admitted.clone();
        let claim_plan = plan.clone();
        let max_frame_bytes = self.config.limits.max_frame_bytes;
        let claim_outcome = self
            .run_store_operation(deadline, move || {
                store.ensure_receipt_response_capacity(
                    &claim_request,
                    &claim_admitted,
                    &claim_plan,
                    max_frame_bytes,
                )?;
                store.claim_or_replay(&claim_request, &claim_admitted, &claim_plan)
            })
            .await?;
        let claim = match claim_outcome {
            ClaimOutcome::Replay(receipt) => return Ok(*receipt),
            ClaimOutcome::Concurrent(claim) => {
                return self
                    .await_concurrent(claim.resolution_id, &admitted.request_sha256, deadline)
                    .await;
            }
            ClaimOutcome::New(claim) => claim,
        };
        let resolution_id = claim.resolution_id;
        let fetched = match self
            .transport
            .fetch_plan(resolution_id, &plan, deadline)
            .await
        {
            Ok(fetched) => fetched,
            Err(error) => {
                self.store.release_incomplete_claim(&claim);
                return Err(ResolverError::denied(error.code));
            }
        };
        if Instant::now() >= deadline {
            self.transport.preserve_cleanup_ambiguity();
            self.store.release_incomplete_claim(&claim);
            return Err(ResolverError::denied("DEP_TRANSPORT_DEADLINE"));
        }
        match self
            .publish_supervised(&claim, frame.request, &admitted, plan, fetched, deadline)
            .await
        {
            Ok(receipt) => Ok(receipt),
            Err(error) => {
                // A killed publication worker may still be leaving a blocked
                // kernel syscall. Preserve the durable claim and transient
                // allocation as explicit restart ambiguity instead of racing
                // cleanup against an incompletely terminated worker.
                self.preserve_publication_ambiguity();
                self.store.release_incomplete_claim(&claim);
                Err(error)
            }
        }
    }

    pub fn serialized_output_guard(&self) -> SerializedOutputGuard {
        self.store.serialized_output_guard()
    }

    async fn publish_supervised(
        &self,
        claim: &crate::ResolutionClaim,
        request: ResolutionRequest,
        admitted: &crate::AdmittedRequest,
        plan: CanonicalPlan,
        fetched: Vec<crate::FetchedArtifact>,
        deadline: Instant,
    ) -> Result<ResolutionReceipt, ResolverError> {
        let publication_guard = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            self.publication_serial.lock(),
        )
        .await
        .map_err(|_| {
            self.preserve_publication_ambiguity();
            ResolverError::denied("DEP_STORE_PUBLICATION_QUEUE_DEADLINE")
        })?;
        let _publication_guard = publication_guard;
        if self.publication_poisoned.load(Ordering::Acquire) {
            return Err(ResolverError::denied(
                "DEP_STORE_PUBLICATION_RESTART_REQUIRED",
            ));
        }
        let worker_request = PublicationWorkerRequest {
            config: self.config.clone(),
            claim: claim.clone(),
            request,
            admitted: admitted.clone(),
            plan,
            fetched,
            deadline_monotonic_ns: monotonic_deadline_ns(deadline)?,
        };
        let payload = serde_json::to_vec(&worker_request)
            .map_err(|_| ResolverError::denied("DEP_STORE_PUBLICATION_WORKER_FAILED"))?;
        if payload.len() > MAX_PUBLICATION_WORKER_BYTES {
            return Err(ResolverError::denied(
                "DEP_STORE_PUBLICATION_WORKER_FRAME_INVALID",
            ));
        }
        let inherited_lock = self
            .store
            .publication_lock_file()
            .map_err(|error| ResolverError::denied(error.code))?;
        let mut command = Command::new(&self.publication_worker);
        command
            .arg("--publication-worker")
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(inherited_lock));
        if self.config.loopback_fixture
            && std::env::var_os("MCLOVING_DEPENDENCY_RESOLVER_TEST_MODE").as_deref()
                == Some(std::ffi::OsStr::new("1"))
        {
            command.env("MCLOVING_DEPENDENCY_RESOLVER_TEST_MODE", "1");
        }
        let output = match supervise_publication_worker(
            command,
            payload,
            deadline,
            &self.publication_poisoned,
        )
        .await
        {
            Ok(output) => output,
            Err(error) => {
                self.preserve_publication_ambiguity();
                return Err(error);
            }
        };
        if !output.status.success()
            || output.stdout.len() as u64 > self.config.limits.max_frame_bytes
        {
            self.preserve_publication_ambiguity();
            return Err(ResolverError::denied("DEP_STORE_PUBLICATION_WORKER_FAILED"));
        }
        let response: PublicationWorkerResponse =
            match crate::strict_json::from_slice(&output.stdout) {
                Ok(response) => response,
                Err(_) => {
                    self.preserve_publication_ambiguity();
                    return Err(ResolverError::denied("DEP_STORE_PUBLICATION_WORKER_FAILED"));
                }
            };
        match response {
            PublicationWorkerResponse::Ok { receipt }
                if receipt.resolution_id == claim.resolution_id
                    && receipt.request_sha256 == admitted.request_sha256 =>
            {
                Ok(*receipt)
            }
            PublicationWorkerResponse::Ok { .. } => {
                self.preserve_publication_ambiguity();
                Err(ResolverError::denied("DEP_STORE_PUBLICATION_WORKER_FAILED"))
            }
            PublicationWorkerResponse::Error { code } => {
                self.preserve_publication_ambiguity();
                Err(ResolverError::denied(worker_error_code(&code)))
            }
        }
    }

    fn preserve_publication_ambiguity(&self) {
        self.publication_poisoned.store(true, Ordering::Release);
        self.transport.preserve_cleanup_ambiguity();
    }

    pub async fn acknowledge_response_delivery(&self, receipt: &ResolutionReceipt) {
        if !self.store.delivery_ack_pending(receipt.resolution_id) {
            return;
        }
        let resolution_id = receipt.resolution_id;
        let store = self.store.clone();
        let receipt = receipt.clone();
        let task =
            tokio::task::spawn_blocking(move || store.acknowledge_receipt_delivery(&receipt));
        let acknowledged = tokio::time::timeout(DELIVERY_ACK_TIMEOUT, task)
            .await
            .is_ok_and(|result| result.is_ok_and(|result| result.is_ok()));
        if !acknowledged {
            self.store_poisoned.store(true, Ordering::Release);
        }
        self.store.release_completed_delivery(resolution_id);
    }

    async fn run_store_operation<T, F>(
        &self,
        deadline: Instant,
        operation: F,
    ) -> Result<T, ResolverError>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T, StoreError> + Send + 'static,
    {
        supervise_parent_store_operation(
            &self.store_serial,
            &self.store_poisoned,
            deadline,
            operation,
        )
        .await
    }

    fn adapter_bindings(
        &self,
        request: &ResolutionRequest,
    ) -> Result<AdapterBindings, ResolverError> {
        let adapter = self
            .config
            .adapters
            .iter()
            .find(|adapter| adapter.ecosystem == request.ecosystem)
            .ok_or_else(|| ResolverError::denied("DEP_CONFIG_ADAPTER_SET_INVALID"))?;
        let repositories = request
            .repository_ids
            .iter()
            .map(|repository_id| {
                self.config
                    .repositories
                    .iter()
                    .find(|repository| &repository.repository_id == repository_id)
                    .map(|repository| RepositoryBinding {
                        repository_id: repository.repository_id.clone(),
                        credentialed: repository.credentialed(),
                        permits_untrusted_source: repository.permits_untrusted_source,
                    })
                    .ok_or_else(|| ResolverError::denied("DEP_REQUEST_REPOSITORY_UNCONFIGURED"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(AdapterBindings {
            adapter_id: adapter.adapter_id.clone(),
            adapter_sha256: adapter.implementation_sha256.clone(),
            source_tree_sha256: request.source_tree_sha256.clone(),
            resolver_toolchain_id: self.config.resolver_toolchain_id.clone(),
            resolver_toolchain_sha256: self.config.resolver_toolchain_sha256.clone(),
            source_trust_class: request.source_trust_class,
            repositories,
        })
    }

    async fn await_concurrent(
        &self,
        resolution_id: Uuid,
        expected_request_sha256: &str,
        deadline: Instant,
    ) -> Result<ResolutionReceipt, ResolverError> {
        loop {
            let store = self.store.clone();
            let request_sha256 = expected_request_sha256.to_owned();
            match self
                .run_store_operation(deadline, move || {
                    store.concurrent_claim_state(resolution_id, &request_sha256)
                })
                .await?
            {
                ConcurrentClaimState::Completed(receipt) => return Ok(*receipt),
                ConcurrentClaimState::InactiveIncomplete => {
                    return Err(ResolverError::denied("DEP_STORE_AMBIGUOUS_CLAIM"));
                }
                ConcurrentClaimState::Active => {}
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| ResolverError::denied("DEP_STORE_CONCURRENT_DEADLINE"))?;
            tokio::time::sleep(remaining.min(Duration::from_millis(10))).await;
        }
    }
}

async fn supervise_parent_store_operation<T, F>(
    store_serial: &tokio::sync::Mutex<()>,
    store_poisoned: &AtomicBool,
    deadline: Instant,
    operation: F,
) -> Result<T, ResolverError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, StoreError> + Send + 'static,
{
    let _guard = tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline),
        store_serial.lock(),
    )
    .await
    .map_err(|_| ResolverError::denied("DEP_STORE_PARENT_IO_QUEUE_DEADLINE"))?;
    if store_poisoned.load(Ordering::Acquire) {
        return Err(ResolverError::denied(
            "DEP_STORE_PARENT_IO_RESTART_REQUIRED",
        ));
    }
    let task = tokio::task::spawn_blocking(operation);
    match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), task).await {
        Ok(Ok(Ok(result))) if Instant::now() < deadline => Ok(result),
        Ok(Ok(Err(error))) if Instant::now() < deadline => Err(ResolverError::denied(error.code)),
        Ok(Err(_)) => {
            store_poisoned.store(true, Ordering::Release);
            Err(ResolverError::denied("DEP_STORE_PARENT_IO_FAILED"))
        }
        Ok(_) | Err(_) => {
            store_poisoned.store(true, Ordering::Release);
            Err(ResolverError::denied("DEP_STORE_PARENT_IO_DEADLINE"))
        }
    }
}

pub fn run_publication_worker(input: &[u8]) -> PublicationWorkerResponse {
    if input.len() > MAX_PUBLICATION_WORKER_BYTES {
        return PublicationWorkerResponse::Error {
            code: "DEP_STORE_PUBLICATION_WORKER_FRAME_INVALID".to_owned(),
        };
    }
    let request: PublicationWorkerRequest = match crate::strict_json::from_slice(input) {
        Ok(request) => request,
        Err(_) => {
            return PublicationWorkerResponse::Error {
                code: "DEP_STORE_PUBLICATION_WORKER_FRAME_INVALID".to_owned(),
            };
        }
    };
    let deadline = match instant_from_monotonic_deadline(request.deadline_monotonic_ns) {
        Ok(deadline) => deadline,
        Err(error) => {
            return PublicationWorkerResponse::Error {
                code: error.code.to_owned(),
            };
        }
    };
    if let Err(error) = crate::standalone::verify_running_executable(&request.config) {
        return PublicationWorkerResponse::Error {
            code: error.code.to_owned(),
        };
    }
    let authorities = match LoadedAuthorities::load(&request.config) {
        Ok(authorities) => authorities,
        Err(error) => {
            return PublicationWorkerResponse::Error {
                code: error.code.to_owned(),
            };
        }
    };
    let store = match ResolutionStore::open_worker(&request.config, &authorities) {
        Ok(store) => store,
        Err(error) => {
            return PublicationWorkerResponse::Error {
                code: error.code.to_owned(),
            };
        }
    };
    match store.publish_worker(
        &request.claim,
        request.request,
        &request.admitted,
        request.plan,
        &request.fetched,
        deadline,
    ) {
        Ok(receipt) => PublicationWorkerResponse::Ok {
            receipt: Box::new(receipt),
        },
        Err(error) => PublicationWorkerResponse::Error {
            code: error.code.to_owned(),
        },
    }
}

async fn supervise_publication_worker(
    mut command: Command,
    payload: Vec<u8>,
    deadline: Instant,
    publication_poisoned: &AtomicBool,
) -> Result<Output, ResolverError> {
    command.kill_on_drop(true);
    let mut child = command
        .spawn()
        .map_err(|_| ResolverError::denied("DEP_STORE_PUBLICATION_WORKER_FAILED"))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| ResolverError::denied("DEP_STORE_PUBLICATION_WORKER_FAILED"))?;
    let operation = async move {
        stdin.write_all(&payload).await?;
        stdin.shutdown().await?;
        drop(stdin);
        child.wait_with_output().await
    };
    match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), operation).await {
        Ok(result) => {
            result.map_err(|_| ResolverError::denied("DEP_STORE_PUBLICATION_WORKER_FAILED"))
        }
        Err(_) => {
            publication_poisoned.store(true, Ordering::Release);
            Err(ResolverError::denied("DEP_STORE_PUBLICATION_DEADLINE"))
        }
    }
}

fn monotonic_deadline_ns(deadline: Instant) -> Result<u64, ResolverError> {
    let clock_now = monotonic_ns()?;
    let instant_now = Instant::now();
    let remaining = deadline
        .checked_duration_since(instant_now)
        .ok_or_else(|| ResolverError::denied("DEP_STORE_PUBLICATION_DEADLINE"))?;
    let remaining_ns = u64::try_from(remaining.as_nanos())
        .map_err(|_| ResolverError::denied("DEP_STORE_PUBLICATION_DEADLINE"))?;
    clock_now
        .checked_add(remaining_ns)
        .ok_or_else(|| ResolverError::denied("DEP_STORE_PUBLICATION_DEADLINE"))
}

fn instant_from_monotonic_deadline(deadline_ns: u64) -> Result<Instant, ResolverError> {
    let instant_now = Instant::now();
    let clock_now = monotonic_ns()?;
    let remaining_ns = deadline_ns
        .checked_sub(clock_now)
        .filter(|remaining| *remaining > 0)
        .ok_or_else(|| ResolverError::denied("DEP_STORE_PUBLICATION_DEADLINE"))?;
    instant_now
        .checked_add(Duration::from_nanos(remaining_ns))
        .ok_or_else(|| ResolverError::denied("DEP_STORE_PUBLICATION_DEADLINE"))
}

#[cfg(unix)]
fn monotonic_ns() -> Result<u64, ResolverError> {
    use nix::sys::time::TimeValLike as _;

    let value = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC)
        .map_err(|_| ResolverError::denied("DEP_STORE_PUBLICATION_CLOCK_INVALID"))?
        .num_nanoseconds();
    u64::try_from(value).map_err(|_| ResolverError::denied("DEP_STORE_PUBLICATION_CLOCK_INVALID"))
}

#[cfg(not(unix))]
fn monotonic_ns() -> Result<u64, ResolverError> {
    Err(ResolverError::denied(
        "DEP_STORE_PUBLICATION_PLATFORM_UNSUPPORTED",
    ))
}

fn worker_error_code(code: &str) -> &'static str {
    match code {
        "DEP_EXECUTABLE_IDENTITY_INVALID" => "DEP_EXECUTABLE_IDENTITY_INVALID",
        "DEP_EXECUTABLE_IDENTITY_MISMATCH" => "DEP_EXECUTABLE_IDENTITY_MISMATCH",
        "DEP_STORE_ARTIFACT_BINDING_MISMATCH" => "DEP_STORE_ARTIFACT_BINDING_MISMATCH",
        "DEP_STORE_ARTIFACT_CONTENT_MISMATCH" => "DEP_STORE_ARTIFACT_CONTENT_MISMATCH",
        "DEP_STORE_ARTIFACT_SET_MISMATCH" => "DEP_STORE_ARTIFACT_SET_MISMATCH",
        "DEP_STORE_CLAIM_NOT_ACTIVE" => "DEP_STORE_CLAIM_NOT_ACTIVE",
        "DEP_STORE_DIRECTORY_POLICY_DENIED" => "DEP_STORE_DIRECTORY_POLICY_DENIED",
        "DEP_STORE_FILE_POLICY_DENIED" => "DEP_STORE_FILE_POLICY_DENIED",
        "DEP_STORE_PLATFORM_UNSUPPORTED" => "DEP_STORE_PLATFORM_UNSUPPORTED",
        "DEP_STORE_PUBLICATION_BINDING_INVALID" => "DEP_STORE_PUBLICATION_BINDING_INVALID",
        "DEP_STORE_PUBLICATION_CLOCK_INVALID" => "DEP_STORE_PUBLICATION_CLOCK_INVALID",
        "DEP_STORE_PUBLICATION_CONFLICT" => "DEP_STORE_PUBLICATION_CONFLICT",
        "DEP_STORE_PUBLICATION_DEADLINE" => "DEP_STORE_PUBLICATION_DEADLINE",
        "DEP_STORE_PUBLICATION_LATE" => "DEP_STORE_PUBLICATION_LATE",
        "DEP_STORE_PUBLICATION_PLATFORM_UNSUPPORTED" => {
            "DEP_STORE_PUBLICATION_PLATFORM_UNSUPPORTED"
        }
        "DEP_STORE_PUBLICATION_WORKER_FRAME_INVALID" => {
            "DEP_STORE_PUBLICATION_WORKER_FRAME_INVALID"
        }
        "DEP_STORE_RECEIPT_INVALID" => "DEP_STORE_RECEIPT_INVALID",
        "DEP_STORE_RECEIPT_KEY_INVALID" => "DEP_STORE_RECEIPT_KEY_INVALID",
        "DEP_STORE_RETAINED_TREE_MISMATCH" => "DEP_STORE_RETAINED_TREE_MISMATCH",
        "DEP_STORE_SECRET_MARKER_DETECTED" => "DEP_STORE_SECRET_MARKER_DETECTED",
        "DEP_STORE_STATE_INVALID" => "DEP_STORE_STATE_INVALID",
        "DEP_STORE_STATE_UNAVAILABLE" => "DEP_STORE_STATE_UNAVAILABLE",
        "DEP_STORE_TRANSIENT_PATH_MISMATCH" => "DEP_STORE_TRANSIENT_PATH_MISMATCH",
        "DEP_STORE_WORKER_PARENT_LOCK_INVALID" => "DEP_STORE_WORKER_PARENT_LOCK_INVALID",
        _ => "DEP_STORE_PUBLICATION_WORKER_FAILED",
    }
}

pub fn parse_resolution_frame(bytes: &[u8]) -> Result<ResolutionFrame, ResolverError> {
    crate::strict_json::from_slice(bytes)
        .map_err(|_| ResolverError::denied("DEP_REQUEST_FRAME_INVALID"))
}

fn parse_lock(
    request: &ResolutionRequest,
    lock_bytes: &[u8],
    bindings: &AdapterBindings,
) -> Result<CanonicalPlan, ResolverError> {
    match request.ecosystem {
        Ecosystem::Maven => parse_maven_lock(lock_bytes, bindings),
        Ecosystem::Npm => parse_npm_package_lock(lock_bytes, bindings),
        Ecosystem::Pypi => parse_pypi_requirements(lock_bytes, bindings),
    }
    .map_err(|error| ResolverError::denied(error.code))
}

fn duration_until_unix_deadline(
    deadline_unix_ms: u64,
    wall_now: Duration,
) -> Result<Duration, ResolverError> {
    Duration::from_millis(deadline_unix_ms)
        .checked_sub(wall_now)
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| ResolverError::denied("DEP_REQUEST_TIME_INVALID"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn publication_worker_is_killed_at_the_absolute_deadline() {
        let mut command = Command::new("/bin/sleep");
        command
            .arg("60")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let started = Instant::now();
        let poisoned = AtomicBool::new(false);
        let error = supervise_publication_worker(
            command,
            b"bounded worker input".to_vec(),
            started + Duration::from_millis(25),
            &poisoned,
        )
        .await
        .expect_err("stalled publication worker deadline");
        assert_eq!(error.code, "DEP_STORE_PUBLICATION_DEADLINE");
        assert!(poisoned.load(Ordering::Acquire));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn parent_store_operation_is_bounded_and_poisoned_at_deadline() {
        let serial = tokio::sync::Mutex::new(());
        let poisoned = AtomicBool::new(false);
        let started = Instant::now();
        let error = supervise_parent_store_operation(
            &serial,
            &poisoned,
            started + Duration::from_millis(5),
            || {
                std::thread::sleep(Duration::from_millis(100));
                Ok::<_, StoreError>(())
            },
        )
        .await
        .expect_err("stalled parent store operation");
        assert_eq!(error.code, "DEP_STORE_PARENT_IO_DEADLINE");
        assert!(poisoned.load(Ordering::Acquire));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn deadline_derivation_preserves_submillisecond_remainder() {
        assert_eq!(
            duration_until_unix_deadline(1_000, Duration::from_nanos(999_999_999)).unwrap(),
            Duration::from_nanos(1)
        );
        assert_eq!(
            duration_until_unix_deadline(1_000, Duration::from_millis(1_000))
                .expect_err("equal deadline"),
            ResolverError::denied("DEP_REQUEST_TIME_INVALID")
        );
    }
}
