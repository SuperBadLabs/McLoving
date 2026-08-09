use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    AdapterBindings, CanonicalPlan, CertifiedConfig, ClaimOutcome, Ecosystem, HttpTransport,
    LoadedAuthorities, RepositoryBinding, ResolutionReceipt, ResolutionRequest, ResolutionStore,
    parse_maven_lock, parse_npm_package_lock, parse_pypi_requirements,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionFrame {
    pub request: ResolutionRequest,
    pub lock_base64: String,
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
}

impl DependencyResolver {
    pub fn new(config: CertifiedConfig) -> Result<Self, ResolverError> {
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
        })
    }

    pub async fn resolve_frame(
        &self,
        frame: ResolutionFrame,
    ) -> Result<ResolutionReceipt, ResolverError> {
        let started_at = Instant::now();
        let now_unix_ms = now_unix_ms()?;
        let remaining_ms = frame
            .request
            .expires_at_unix_ms
            .checked_sub(now_unix_ms)
            .filter(|remaining| *remaining > 0)
            .ok_or_else(|| ResolverError::denied("DEP_REQUEST_TIME_INVALID"))?;
        let deadline = started_at
            .checked_add(Duration::from_millis(remaining_ms))
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
        let claim = match self
            .store
            .claim_or_replay(&frame.request, &admitted, &plan)
            .map_err(|error| ResolverError::denied(error.code))?
        {
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
            let cleanup = self.transport.cleanup_resolution(resolution_id).await;
            self.store.release_incomplete_claim(&claim);
            cleanup.map_err(|error| ResolverError::denied(error.code))?;
            return Err(ResolverError::denied("DEP_TRANSPORT_DEADLINE"));
        }
        let store = self.store.clone();
        let publish_claim = claim.clone();
        let publish_request = frame.request;
        let publish_admitted = admitted.clone();
        let publish_plan = plan;
        let receipt = match tokio::task::spawn_blocking(move || {
            store.publish(
                &publish_claim,
                publish_request,
                &publish_admitted,
                publish_plan,
                &fetched,
            )
        })
        .await
        {
            Ok(Ok(receipt)) => receipt,
            Ok(Err(error)) => {
                let cleanup = self.transport.cleanup_resolution(resolution_id).await;
                self.store.release_incomplete_claim(&claim);
                cleanup.map_err(|cleanup_error| ResolverError::denied(cleanup_error.code))?;
                return Err(ResolverError::denied(error.code));
            }
            Err(_) => {
                let cleanup = self.transport.cleanup_resolution(resolution_id).await;
                self.store.release_incomplete_claim(&claim);
                cleanup.map_err(|error| ResolverError::denied(error.code))?;
                return Err(ResolverError::denied("DEP_STORE_PUBLICATION_TASK_FAILED"));
            }
        };
        self.transport
            .cleanup_resolution(resolution_id)
            .await
            .map_err(|error| ResolverError::denied(error.code))?;
        Ok(receipt)
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
            if let Some(receipt) = self
                .store
                .load_completed(resolution_id, expected_request_sha256)
                .map_err(|error| ResolverError::denied(error.code))?
            {
                return Ok(receipt);
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| ResolverError::denied("DEP_STORE_CONCURRENT_DEADLINE"))?;
            tokio::time::sleep(remaining.min(Duration::from_millis(10))).await;
        }
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

fn now_unix_ms() -> Result<u64, ResolverError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ResolverError::denied("DEP_REQUEST_TIME_INVALID"))?
        .as_millis();
    u64::try_from(millis).map_err(|_| ResolverError::denied("DEP_REQUEST_TIME_INVALID"))
}
