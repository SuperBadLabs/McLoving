use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use hmac::{Hmac, Mac as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    AdmittedRequest, CanonicalPlan, CertifiedConfig, FetchedArtifact, LoadedAuthorities,
    ResolutionRequest,
};

type HmacSha256 = Hmac<Sha256>;
const CLAIM_SCHEMA: &str = "mcloving.dependency-claim/v1";
const COMPLETION_SCHEMA: &str = "mcloving.dependency-completion/v1";
const MANIFEST_SCHEMA: &str = "mcloving.dependency-manifest/v1";
const RECEIPT_SCHEMA: &str = "mcloving.dependency-receipt/v1";
const MAX_STATE_BYTES: u64 = 16 * 1_048_576;
const LOCK_FILE: &str = ".mcloving-dependency-output.lock";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionClaim {
    pub schema_version: String,
    pub resolution_id: Uuid,
    pub request_sha256: String,
    pub configuration_sha256: String,
    pub graph_sha256: String,
    pub generation: u64,
    pub publication_deadline_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ResolutionCompletion {
    schema_version: String,
    resolution_id: Uuid,
    request_sha256: String,
    receipt_hmac_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedArtifact {
    pub node_id: String,
    pub relative_path: String,
    pub size: u64,
    pub sha256: String,
    pub attestation_sha256: String,
    pub publication_generation: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ResolutionManifest {
    schema_version: String,
    resolution_id: Uuid,
    request_sha256: String,
    graph_sha256: String,
    artifacts: Vec<RetainedArtifact>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionReceipt {
    pub schema_version: String,
    pub protocol_version: String,
    pub resolution_id: Uuid,
    pub request_sha256: String,
    pub configuration_sha256: String,
    pub executable_sha256: String,
    pub secret_marker_set_sha256: String,
    pub request: ResolutionRequest,
    pub plan: CanonicalPlan,
    pub artifacts: Vec<RetainedArtifact>,
    pub retained_tree_sha256: String,
    pub generation: u64,
    pub rollback_from_generation: Option<u64>,
    pub publication_deadline_unix_ms: u64,
    pub published_at_unix_ms: u64,
    pub receipt_key_id: String,
    pub hmac_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaimOutcome {
    New(ResolutionClaim),
    Replay(Box<ResolutionReceipt>),
    Concurrent(ResolutionClaim),
}

pub(crate) enum ConcurrentClaimState {
    Active,
    Completed(Box<ResolutionReceipt>),
    InactiveIncomplete,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("{code}: {message}")]
pub struct StoreError {
    pub code: &'static str,
    pub message: String,
}

impl StoreError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[cfg(target_os = "linux")]
type OutputLock = nix::fcntl::Flock<File>;

#[cfg(not(target_os = "linux"))]
struct OutputLock;

struct StoreInner {
    root: PathBuf,
    transport_root: PathBuf,
    configuration_sha256: String,
    generation: u64,
    executable_sha256: String,
    secret_marker_set_sha256: String,
    receipt_key_id: String,
    receipt_key: Vec<u8>,
    marker_set: Vec<Vec<u8>>,
    max_artifact_bytes: u64,
    max_total_artifact_bytes: u64,
    active: Mutex<BTreeSet<Uuid>>,
    _lock: OutputLockGuard,
}

enum OutputLockGuard {
    Owner(OutputLock),
    Inherited { _file: File },
}

#[derive(Clone)]
pub struct ResolutionStore {
    inner: Arc<StoreInner>,
}

struct PublicationInput<'a> {
    claim: &'a ResolutionClaim,
    request: ResolutionRequest,
    admitted: &'a AdmittedRequest,
    plan: CanonicalPlan,
    fetched: &'a [FetchedArtifact],
    deadline: Instant,
}

impl ResolutionStore {
    pub fn open(
        config: &CertifiedConfig,
        authorities: &LoadedAuthorities,
    ) -> Result<Self, StoreError> {
        crate::validate_config(config)
            .map_err(|error| StoreError::new(error.code, error.message))?;
        Self::open_inner(
            config,
            authorities.receipt_key(),
            authorities
                .markers()
                .map(|marker| marker.to_vec())
                .collect(),
        )
    }

    fn open_inner(
        config: &CertifiedConfig,
        receipt_key: &[u8],
        marker_set: Vec<Vec<u8>>,
    ) -> Result<Self, StoreError> {
        let root = PathBuf::from(&config.output_root);
        let lock = acquire_output_lock(&root)?;
        Self::open_inner_with_lock(
            config,
            receipt_key,
            marker_set,
            OutputLockGuard::Owner(lock),
        )
    }

    pub(crate) fn open_worker(
        config: &CertifiedConfig,
        authorities: &LoadedAuthorities,
    ) -> Result<Self, StoreError> {
        crate::validate_config(config)
            .map_err(|error| StoreError::new(error.code, error.message))?;
        let inherited_lock = verify_inherited_output_lock(&PathBuf::from(&config.output_root))?;
        Self::open_inner_with_lock(
            config,
            authorities.receipt_key(),
            authorities
                .markers()
                .map(|marker| marker.to_vec())
                .collect(),
            OutputLockGuard::Inherited {
                _file: inherited_lock,
            },
        )
    }

    fn open_inner_with_lock(
        config: &CertifiedConfig,
        receipt_key: &[u8],
        marker_set: Vec<Vec<u8>>,
        lock: OutputLockGuard,
    ) -> Result<Self, StoreError> {
        if receipt_key.is_empty() {
            return Err(StoreError::new(
                "DEP_STORE_RECEIPT_KEY_INVALID",
                "receipt key cannot be empty",
            ));
        }
        let root = PathBuf::from(&config.output_root);
        prepare_layout(&root)?;
        let configuration_sha256 = crate::configuration_sha256(config)
            .map_err(|error| StoreError::new(error.code, error.message))?;
        Ok(Self {
            inner: Arc::new(StoreInner {
                root,
                transport_root: PathBuf::from(&config.transport_root),
                configuration_sha256,
                generation: config.generation,
                executable_sha256: config.executable_sha256.clone(),
                secret_marker_set_sha256: config.secret_marker_set_sha256.clone(),
                receipt_key_id: config.receipt_key_id.clone(),
                receipt_key: receipt_key.to_vec(),
                marker_set,
                max_artifact_bytes: config.limits.max_artifact_bytes,
                max_total_artifact_bytes: config.limits.max_total_artifact_bytes,
                active: Mutex::new(BTreeSet::new()),
                _lock: lock,
            }),
        })
    }

    pub fn claim_or_replay(
        &self,
        request: &ResolutionRequest,
        admitted: &AdmittedRequest,
        plan: &CanonicalPlan,
    ) -> Result<ClaimOutcome, StoreError> {
        if admitted.configuration_sha256 != self.inner.configuration_sha256
            || crate::request_sha256(request)
                .map_err(|error| StoreError::new(error.code, error.message))?
                != admitted.request_sha256
            || crate::validate_plan(plan).is_err()
            || request.expected_graph_sha256 != plan.graph_sha256
        {
            return Err(StoreError::new(
                "DEP_STORE_CLAIM_BINDING_INVALID",
                "claim request, configuration, or canonical plan is not exact",
            ));
        }
        self.deny_secret_markers(request, plan)?;
        let resolution_id = Uuid::parse_str(&request.resolution_id).map_err(|_| {
            StoreError::new(
                "DEP_STORE_RESOLUTION_ID_INVALID",
                "resolution identity is not a UUID",
            )
        })?;
        let expected = ResolutionClaim {
            schema_version: CLAIM_SCHEMA.to_owned(),
            resolution_id,
            request_sha256: admitted.request_sha256.clone(),
            configuration_sha256: admitted.configuration_sha256.clone(),
            graph_sha256: plan.graph_sha256.clone(),
            generation: self.inner.generation,
            publication_deadline_unix_ms: admitted.absolute_expiry_unix_ms,
        };
        let claim_path = self.claim_path(resolution_id);
        let active = self
            .inner
            .active
            .lock()
            .map_err(|_| state_error())?
            .contains(&resolution_id);
        if active {
            if path_exists(&claim_path)? {
                let existing: ResolutionClaim = read_json(&claim_path, 0o600)?;
                if existing != expected {
                    return Err(StoreError::new(
                        "DEP_STORE_REPLAY_SUBSTITUTION",
                        "resolution identity is already bound to different claim content",
                    ));
                }
            }
            return Ok(ClaimOutcome::Concurrent(expected));
        }
        if path_exists(&claim_path)? {
            let existing: ResolutionClaim = read_json(&claim_path, 0o600)?;
            if existing != expected {
                return Err(StoreError::new(
                    "DEP_STORE_REPLAY_SUBSTITUTION",
                    "resolution identity is already bound to different claim content",
                ));
            }
            return Err(StoreError::new(
                "DEP_STORE_AMBIGUOUS_CLAIM",
                "matching incomplete claim requires explicit reconciliation",
            ));
        }
        if let Some(receipt) = self.load_receipt(resolution_id)? {
            self.verify_replay(&receipt, &admitted.request_sha256)?;
            return Ok(ClaimOutcome::Replay(Box::new(receipt)));
        }
        {
            let mut active = self.inner.active.lock().map_err(|_| state_error())?;
            if !active.insert(resolution_id) {
                return Ok(ClaimOutcome::Concurrent(expected));
            }
        }
        if let Err(error) = write_new_json(&claim_path, &expected, 0o600) {
            self.deactivate(resolution_id);
            return Err(error);
        }
        self.finish_claim_directory_sync(
            resolution_id,
            sync_directory(&self.inner.root.join("claims")),
        )?;
        Ok(ClaimOutcome::New(expected))
    }

    pub(crate) fn ensure_receipt_response_capacity(
        &self,
        request: &ResolutionRequest,
        admitted: &AdmittedRequest,
        plan: &CanonicalPlan,
        max_frame_bytes: u64,
    ) -> Result<(), StoreError> {
        let resolution_id = Uuid::parse_str(&request.resolution_id).map_err(|_| {
            StoreError::new(
                "DEP_STORE_RESOLUTION_ID_INVALID",
                "resolution identity is not a UUID",
            )
        })?;
        let mut artifacts = plan
            .nodes
            .iter()
            .map(|node| RetainedArtifact {
                node_id: node.node_id.clone(),
                relative_path: format!("artifacts/{}", node.sha256),
                size: node.declared_size,
                sha256: node.sha256.clone(),
                attestation_sha256: "f".repeat(64),
                publication_generation: self.inner.generation,
            })
            .collect::<Vec<_>>();
        artifacts.sort_by(|left, right| left.node_id.cmp(&right.node_id));
        let receipt = ResolutionReceipt {
            schema_version: RECEIPT_SCHEMA.to_owned(),
            protocol_version: request.protocol_version.clone(),
            resolution_id,
            request_sha256: admitted.request_sha256.clone(),
            configuration_sha256: admitted.configuration_sha256.clone(),
            executable_sha256: self.inner.executable_sha256.clone(),
            secret_marker_set_sha256: self.inner.secret_marker_set_sha256.clone(),
            request: request.clone(),
            plan: plan.clone(),
            artifacts,
            retained_tree_sha256: "f".repeat(64),
            generation: self.inner.generation,
            rollback_from_generation: request.rollback_from_generation,
            publication_deadline_unix_ms: admitted.absolute_expiry_unix_ms,
            published_at_unix_ms: u64::MAX,
            receipt_key_id: self.inner.receipt_key_id.clone(),
            hmac_sha256: "f".repeat(64),
        };
        let response = crate::standalone::ResolverResponse::Ok {
            receipt: Box::new(receipt),
        };
        let response_bytes = serde_json::to_vec(&response).map_err(|_| state_error())?;
        if response_bytes.len() as u64 > max_frame_bytes {
            return Err(StoreError::new(
                "DEP_RESPONSE_FRAME_OVERSIZED",
                "successful dependency receipt exceeds the certified response frame",
            ));
        }
        Ok(())
    }

    pub(crate) fn concurrent_claim_state(
        &self,
        resolution_id: Uuid,
        expected_request_sha256: &str,
    ) -> Result<ConcurrentClaimState, StoreError> {
        if self
            .inner
            .active
            .lock()
            .map_err(|_| state_error())?
            .contains(&resolution_id)
        {
            return Ok(ConcurrentClaimState::Active);
        }
        if path_exists(&self.claim_path(resolution_id))?
            || path_exists(&self.ambiguity_path(resolution_id))?
        {
            return Ok(ConcurrentClaimState::InactiveIncomplete);
        }
        match self.load_receipt(resolution_id)? {
            Some(receipt) => {
                self.verify_replay(&receipt, expected_request_sha256)?;
                Ok(ConcurrentClaimState::Completed(Box::new(receipt)))
            }
            None => Ok(ConcurrentClaimState::InactiveIncomplete),
        }
    }

    pub fn load_completed(
        &self,
        resolution_id: Uuid,
        expected_request_sha256: &str,
    ) -> Result<Option<ResolutionReceipt>, StoreError> {
        if self
            .inner
            .active
            .lock()
            .map_err(|_| state_error())?
            .contains(&resolution_id)
        {
            return Ok(None);
        }
        let receipt = self.load_receipt(resolution_id)?;
        if let Some(receipt) = &receipt {
            self.verify_replay(receipt, expected_request_sha256)?;
        }
        Ok(receipt)
    }

    pub fn publish(
        &self,
        claim: &ResolutionClaim,
        request: ResolutionRequest,
        admitted: &AdmittedRequest,
        plan: CanonicalPlan,
        fetched: &[FetchedArtifact],
        deadline: Instant,
    ) -> Result<ResolutionReceipt, StoreError> {
        let receipt = self.publish_inner(
            PublicationInput {
                claim,
                request,
                admitted,
                plan,
                fetched,
                deadline,
            },
            true,
        )?;
        let _ = self.acknowledge_delivery(claim);
        Ok(receipt)
    }

    pub(crate) fn publish_worker(
        &self,
        claim: &ResolutionClaim,
        request: ResolutionRequest,
        admitted: &AdmittedRequest,
        plan: CanonicalPlan,
        fetched: &[FetchedArtifact],
        deadline: Instant,
    ) -> Result<ResolutionReceipt, StoreError> {
        self.publish_inner(
            PublicationInput {
                claim,
                request,
                admitted,
                plan,
                fetched,
                deadline,
            },
            false,
        )
    }

    fn publish_inner(
        &self,
        input: PublicationInput<'_>,
        require_in_process_claim: bool,
    ) -> Result<ResolutionReceipt, StoreError> {
        let PublicationInput {
            claim,
            request,
            admitted,
            plan,
            fetched,
            deadline,
        } = input;
        let now_unix_ms = current_unix_ms()?;
        if Instant::now() >= deadline || now_unix_ms >= claim.publication_deadline_unix_ms {
            return Err(StoreError::new(
                "DEP_STORE_PUBLICATION_LATE",
                "publication deadline expired before staging",
            ));
        }
        if claim.request_sha256 != admitted.request_sha256
            || claim.configuration_sha256 != admitted.configuration_sha256
            || claim.graph_sha256 != plan.graph_sha256
            || claim.generation != self.inner.generation
            || claim.publication_deadline_unix_ms != admitted.absolute_expiry_unix_ms
        {
            return Err(StoreError::new(
                "DEP_STORE_PUBLICATION_BINDING_INVALID",
                "claim, request, plan, generation, or deadline does not match publication",
            ));
        }
        let resolution_id = claim.resolution_id;
        if require_in_process_claim
            && !self
                .inner
                .active
                .lock()
                .map_err(|_| state_error())?
                .contains(&resolution_id)
        {
            return Err(StoreError::new(
                "DEP_STORE_CLAIM_NOT_ACTIVE",
                "publication requires the active in-process claim owner",
            ));
        }
        if !require_in_process_claim {
            let durable_claim: ResolutionClaim = read_json(&self.claim_path(resolution_id), 0o600)?;
            if durable_claim != *claim {
                return Err(StoreError::new(
                    "DEP_STORE_CLAIM_NOT_ACTIVE",
                    "publication worker requires the exact durable parent claim",
                ));
            }
        }
        let artifact_by_node = fetched
            .iter()
            .map(|artifact| (artifact.node_id.as_str(), artifact))
            .collect::<BTreeMap<_, _>>();
        if artifact_by_node.len() != plan.nodes.len()
            || plan
                .nodes
                .iter()
                .any(|node| !artifact_by_node.contains_key(node.node_id.as_str()))
        {
            return Err(StoreError::new(
                "DEP_STORE_ARTIFACT_SET_MISMATCH",
                "verified artifact set does not exactly match the canonical plan",
            ));
        }

        let stage = self
            .inner
            .root
            .join(format!(".{}.{}.stage", resolution_id, Uuid::new_v4()));
        create_directory(&stage, 0o700)?;
        let artifacts_root = stage.join("artifacts");
        create_directory(&artifacts_root, 0o700)?;
        let publication =
            self.stage_publication(&stage, &artifacts_root, claim, &plan, &artifact_by_node);
        let artifacts = match publication {
            Ok(value) => value,
            Err(error) => {
                remove_private_tree(&stage)?;
                return Err(error);
            }
        };
        let bundle_path = self.bundle_path(resolution_id);
        if path_exists(&bundle_path)? {
            remove_private_tree(&stage)?;
            return Err(StoreError::new(
                "DEP_STORE_PUBLICATION_CONFLICT",
                "resolution bundle already exists",
            ));
        }
        rename_no_replace(&stage, &bundle_path)?;
        set_mode_and_sync(&bundle_path, 0o500)?;
        sync_directory(&self.inner.root.join("bundles"))?;
        if Instant::now() >= deadline || current_unix_ms()? >= claim.publication_deadline_unix_ms {
            remove_private_tree(&bundle_path)?;
            sync_directory(&self.inner.root.join("bundles"))?;
            return Err(StoreError::new(
                "DEP_STORE_PUBLICATION_LATE",
                "late bundle publication was withdrawn",
            ));
        }
        let retained_tree_sha256 = retained_tree_sha256(
            &bundle_path,
            &self.inner.root,
            self.inner.max_artifact_bytes.max(MAX_STATE_BYTES),
            self.inner
                .max_total_artifact_bytes
                .checked_add(MAX_STATE_BYTES)
                .ok_or_else(state_error)?,
        )?;
        let published_at_unix_ms = current_unix_ms()?;
        if Instant::now() >= deadline || published_at_unix_ms >= claim.publication_deadline_unix_ms
        {
            remove_private_tree(&bundle_path)?;
            sync_directory(&self.inner.root.join("bundles"))?;
            return Err(StoreError::new(
                "DEP_STORE_PUBLICATION_LATE",
                "late verified bundle publication was withdrawn",
            ));
        }
        let rollback_from_generation = request.rollback_from_generation;
        let mut receipt = ResolutionReceipt {
            schema_version: RECEIPT_SCHEMA.to_owned(),
            protocol_version: request.protocol_version.clone(),
            resolution_id,
            request_sha256: admitted.request_sha256.clone(),
            configuration_sha256: admitted.configuration_sha256.clone(),
            executable_sha256: self.inner.executable_sha256.clone(),
            secret_marker_set_sha256: self.inner.secret_marker_set_sha256.clone(),
            request,
            plan,
            artifacts,
            retained_tree_sha256,
            generation: self.inner.generation,
            rollback_from_generation,
            publication_deadline_unix_ms: claim.publication_deadline_unix_ms,
            published_at_unix_ms,
            receipt_key_id: self.inner.receipt_key_id.clone(),
            hmac_sha256: String::new(),
        };
        receipt.hmac_sha256 = sign_receipt(&receipt, &self.inner.receipt_key)?;
        self.deny_secret_markers(&receipt, &())?;
        let receipt_path = self.receipt_path(resolution_id);
        if let Err(error) = write_new_json(&receipt_path, &receipt, 0o400) {
            self.withdraw_publication(&receipt_path, &bundle_path)?;
            return Err(error);
        }
        sync_directory(&self.inner.root.join("receipts"))?;
        if Instant::now() >= deadline || current_unix_ms()? >= claim.publication_deadline_unix_ms {
            self.withdraw_publication(&receipt_path, &bundle_path)?;
            return Err(StoreError::new(
                "DEP_STORE_PUBLICATION_LATE",
                "late receipt publication was withdrawn",
            ));
        }
        self.verify_replay(&receipt, &admitted.request_sha256)?;
        self.cleanup_transient_resolution(resolution_id)?;
        if Instant::now() >= deadline || current_unix_ms()? >= claim.publication_deadline_unix_ms {
            self.withdraw_publication(&receipt_path, &bundle_path)?;
            return Err(StoreError::new(
                "DEP_STORE_PUBLICATION_LATE",
                "late verified publication was withdrawn while its durable claim remained",
            ));
        }
        let completion = ResolutionCompletion {
            schema_version: COMPLETION_SCHEMA.to_owned(),
            resolution_id,
            request_sha256: receipt.request_sha256.clone(),
            receipt_hmac_sha256: receipt.hmac_sha256.clone(),
        };
        let completion_path = self.completion_path(resolution_id);
        write_new_json(&completion_path, &completion, 0o400)?;
        if Instant::now() >= deadline || current_unix_ms()? >= claim.publication_deadline_unix_ms {
            self.remove_completion(&completion_path)?;
            self.withdraw_publication(&receipt_path, &bundle_path)?;
            return Err(StoreError::new(
                "DEP_STORE_PUBLICATION_LATE",
                "late completion record was withdrawn while its durable claim remained",
            ));
        }
        self.record_ambiguity(claim)?;
        std::fs::remove_file(self.claim_path(resolution_id)).map_err(|_| state_error())?;
        if let Err(error) = sync_directory(&self.inner.root.join("claims")) {
            self.rollback_completion(claim, &completion_path)?;
            return Err(error);
        }
        if Instant::now() >= deadline || current_unix_ms()? >= claim.publication_deadline_unix_ms {
            self.rollback_completion(claim, &completion_path)?;
            let withdrawal = self.withdraw_publication(&receipt_path, &bundle_path);
            self.deactivate(resolution_id);
            withdrawal?;
            return Err(StoreError::new(
                "DEP_STORE_PUBLICATION_LATE",
                "late completion was withdrawn and its durable claim restored",
            ));
        }
        self.deactivate(resolution_id);
        Ok(receipt)
    }

    pub fn release_incomplete_claim(&self, claim: &ResolutionClaim) {
        self.deactivate(claim.resolution_id);
    }

    fn finish_claim_directory_sync(
        &self,
        resolution_id: Uuid,
        result: Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        if result.is_err() {
            self.deactivate(resolution_id);
        }
        result
    }

    fn rollback_completion(
        &self,
        claim: &ResolutionClaim,
        completion_path: &Path,
    ) -> Result<(), StoreError> {
        let ambiguity_result = self.record_ambiguity(claim);
        let claim_result = self.ensure_exact_claim(claim);
        let completion_result = self.remove_completion(completion_path);
        match (ambiguity_result, claim_result, completion_result) {
            (Ok(()), _, _) | (_, Ok(()), _) | (_, _, Ok(())) => Ok(()),
            (Err(error), Err(_), Err(_)) => Err(error),
        }
    }

    fn record_ambiguity(&self, claim: &ResolutionClaim) -> Result<(), StoreError> {
        let path = self.ambiguity_path(claim.resolution_id);
        if !path_exists(&path)? {
            write_new_json(&path, claim, 0o600)?;
        }
        let recorded: ResolutionClaim = read_json(&path, 0o600)?;
        if recorded != *claim {
            return Err(StoreError::new(
                "DEP_STORE_REPLAY_SUBSTITUTION",
                "durable ambiguity record does not match the publication claim",
            ));
        }
        sync_directory(&self.inner.root.join("ambiguities"))
    }

    pub(crate) fn acknowledge_delivery(&self, claim: &ResolutionClaim) -> Result<(), StoreError> {
        let path = self.ambiguity_path(claim.resolution_id);
        let recorded: ResolutionClaim = read_json(&path, 0o600)?;
        if recorded != *claim {
            return Err(StoreError::new(
                "DEP_STORE_REPLAY_SUBSTITUTION",
                "delivery acknowledgement does not match the publication claim",
            ));
        }
        remove_private_file(&path)?;
        sync_directory(&self.inner.root.join("ambiguities"))
    }

    fn ensure_exact_claim(&self, claim: &ResolutionClaim) -> Result<(), StoreError> {
        let path = self.claim_path(claim.resolution_id);
        if !path_exists(&path)?
            && write_new_json(&path, claim, 0o600).is_err()
            && !path_exists(&path)?
        {
            return Err(state_error());
        }
        let restored: ResolutionClaim = read_json(&path, 0o600)?;
        if restored != *claim {
            return Err(StoreError::new(
                "DEP_STORE_REPLAY_SUBSTITUTION",
                "restored durable claim does not match the publication claim",
            ));
        }
        sync_directory(&self.inner.root.join("claims"))
    }

    fn remove_completion(&self, path: &Path) -> Result<(), StoreError> {
        if path_exists(path)? {
            remove_private_file(path)?;
            sync_directory(&self.inner.root.join("completions"))?;
        }
        Ok(())
    }

    fn withdraw_publication(
        &self,
        receipt_path: &Path,
        bundle_path: &Path,
    ) -> Result<(), StoreError> {
        if path_exists(receipt_path)? {
            remove_private_file(receipt_path)?;
            sync_directory(&self.inner.root.join("receipts"))?;
        }
        remove_private_tree(bundle_path)?;
        sync_directory(&self.inner.root.join("bundles"))
    }

    fn cleanup_transient_resolution(&self, resolution_id: Uuid) -> Result<(), StoreError> {
        let resolution_root = self.inner.transport_root.join(resolution_id.to_string());
        validate_directory(&resolution_root, 0o700)?;
        remove_private_tree(&resolution_root)?;
        sync_directory(&self.inner.transport_root)
    }

    pub(crate) fn publication_lock_file(&self) -> Result<File, StoreError> {
        match &self.inner._lock {
            OutputLockGuard::Owner(lock) => lock.try_clone().map_err(|_| state_error()),
            OutputLockGuard::Inherited { .. } => Err(StoreError::new(
                "DEP_STORE_WORKER_PARENT_LOCK_INVALID",
                "only the resolver parent may delegate its output lock",
            )),
        }
    }

    fn stage_publication(
        &self,
        stage: &Path,
        artifacts_root: &Path,
        claim: &ResolutionClaim,
        plan: &CanonicalPlan,
        artifact_by_node: &BTreeMap<&str, &FetchedArtifact>,
    ) -> Result<Vec<RetainedArtifact>, StoreError> {
        let mut retained = Vec::with_capacity(plan.nodes.len());
        let mut content_paths = BTreeMap::new();
        for node in &plan.nodes {
            let fetched = artifact_by_node
                .get(node.node_id.as_str())
                .expect("artifact set was checked above");
            if fetched.sha256 != node.sha256
                || fetched.declared_size != node.declared_size
                || fetched.publication_generation != claim.generation
            {
                return Err(StoreError::new(
                    "DEP_STORE_ARTIFACT_BINDING_MISMATCH",
                    "verified artifact metadata changed before publication",
                ));
            }
            let expected_transient = self
                .inner
                .transport_root
                .join(claim.resolution_id.to_string())
                .join(format!("{}.part", node.node_id));
            if fetched.transient_path != expected_transient {
                return Err(StoreError::new(
                    "DEP_STORE_TRANSIENT_PATH_MISMATCH",
                    "verified artifact is not bound to its dedicated transport path",
                ));
            }
            verify_file(
                &fetched.transient_path,
                0o600,
                node.declared_size,
                &node.sha256,
            )?;
            let relative_path = format!("artifacts/{}", node.sha256);
            let destination = stage.join(&relative_path);
            if let Some(existing) = content_paths.get(&node.sha256) {
                if existing != &relative_path {
                    return Err(state_error());
                }
            } else {
                copy_new_file(&fetched.transient_path, &destination, node.declared_size)?;
                set_mode_and_sync(&destination, 0o400)?;
                content_paths.insert(node.sha256.clone(), relative_path.clone());
            }
            retained.push(RetainedArtifact {
                node_id: node.node_id.clone(),
                relative_path,
                size: node.declared_size,
                sha256: node.sha256.clone(),
                attestation_sha256: fetched.attestation_sha256.clone(),
                publication_generation: fetched.publication_generation,
            });
        }
        retained.sort_by(|left, right| left.node_id.cmp(&right.node_id));
        let manifest = ResolutionManifest {
            schema_version: MANIFEST_SCHEMA.to_owned(),
            resolution_id: claim.resolution_id,
            request_sha256: claim.request_sha256.clone(),
            graph_sha256: claim.graph_sha256.clone(),
            artifacts: retained.clone(),
        };
        write_new_json(&stage.join("manifest.json"), &manifest, 0o400)?;
        set_mode_and_sync(artifacts_root, 0o500)?;
        sync_directory(artifacts_root)?;
        sync_directory(stage)?;
        Ok(retained)
    }

    fn verify_replay(
        &self,
        receipt: &ResolutionReceipt,
        expected_request_sha256: &str,
    ) -> Result<(), StoreError> {
        let hmac_valid = verify_receipt_hmac(receipt, &self.inner.receipt_key).is_ok();
        if receipt.schema_version != RECEIPT_SCHEMA
            || receipt.request_sha256 != expected_request_sha256
            || receipt.generation != self.inner.generation
            || receipt.configuration_sha256 != self.inner.configuration_sha256
            || receipt.executable_sha256 != self.inner.executable_sha256
            || receipt.secret_marker_set_sha256 != self.inner.secret_marker_set_sha256
            || receipt.receipt_key_id != self.inner.receipt_key_id
            || !hmac_valid
        {
            return Err(StoreError::new(
                "DEP_STORE_RECEIPT_INVALID",
                "stored receipt signature or exact runtime binding is invalid",
            ));
        }
        if crate::request_sha256(&receipt.request)
            .map_err(|error| StoreError::new(error.code, error.message))?
            != receipt.request_sha256
            || crate::validate_plan(&receipt.plan).is_err()
            || receipt.request.expected_graph_sha256 != receipt.plan.graph_sha256
            || receipt.request.expected_configuration_sha256 != receipt.configuration_sha256
            || receipt.request.expected_generation != receipt.generation
            || receipt.request.rollback_from_generation != receipt.rollback_from_generation
            || receipt.published_at_unix_ms >= receipt.publication_deadline_unix_ms
        {
            return Err(StoreError::new(
                "DEP_STORE_RECEIPT_INVALID",
                "stored receipt request, plan, generation, rollback, or deadline binding is invalid",
            ));
        }
        let bundle = self.bundle_path(receipt.resolution_id);
        if retained_tree_sha256(
            &bundle,
            &self.inner.root,
            self.inner.max_artifact_bytes.max(MAX_STATE_BYTES),
            self.inner
                .max_total_artifact_bytes
                .checked_add(MAX_STATE_BYTES)
                .ok_or_else(state_error)?,
        )? != receipt.retained_tree_sha256
        {
            return Err(StoreError::new(
                "DEP_STORE_RETAINED_TREE_MISMATCH",
                "retained dependency bundle has been substituted",
            ));
        }
        let manifest: ResolutionManifest = read_json(&bundle.join("manifest.json"), 0o400)?;
        if manifest.resolution_id != receipt.resolution_id
            || manifest.request_sha256 != receipt.request_sha256
            || manifest.graph_sha256 != receipt.plan.graph_sha256
            || manifest.artifacts != receipt.artifacts
        {
            return Err(StoreError::new(
                "DEP_STORE_MANIFEST_MISMATCH",
                "retained manifest does not match the signed receipt",
            ));
        }
        for artifact in &receipt.artifacts {
            verify_file(
                &bundle.join(&artifact.relative_path),
                0o400,
                artifact.size,
                &artifact.sha256,
            )?;
        }
        Ok(())
    }

    fn load_receipt(&self, resolution_id: Uuid) -> Result<Option<ResolutionReceipt>, StoreError> {
        if path_exists(&self.claim_path(resolution_id))?
            || path_exists(&self.ambiguity_path(resolution_id))?
        {
            return Err(StoreError::new(
                "DEP_STORE_AMBIGUOUS_CLAIM",
                "durable claim takes precedence over any apparent completion",
            ));
        }
        let receipt_path = self.receipt_path(resolution_id);
        let completion_path = self.completion_path(resolution_id);
        let receipt_exists = path_exists(&receipt_path)?;
        let completion_exists = path_exists(&completion_path)?;
        if !receipt_exists && !completion_exists {
            return Ok(None);
        }
        if !receipt_exists || !completion_exists {
            return Err(StoreError::new(
                "DEP_STORE_AMBIGUOUS_COMPLETION",
                "receipt and durable completion record must exist together",
            ));
        }
        let receipt: ResolutionReceipt = read_json(&receipt_path, 0o400)?;
        let completion: ResolutionCompletion = read_json(&completion_path, 0o400)?;
        if completion.schema_version != COMPLETION_SCHEMA
            || completion.resolution_id != resolution_id
            || completion.request_sha256 != receipt.request_sha256
            || completion.receipt_hmac_sha256 != receipt.hmac_sha256
        {
            return Err(StoreError::new(
                "DEP_STORE_RECEIPT_INVALID",
                "durable completion record does not bind the exact receipt",
            ));
        }
        Ok(Some(receipt))
    }

    fn claim_path(&self, resolution_id: Uuid) -> PathBuf {
        self.inner
            .root
            .join("claims")
            .join(format!("{resolution_id}.json"))
    }

    fn receipt_path(&self, resolution_id: Uuid) -> PathBuf {
        self.inner
            .root
            .join("receipts")
            .join(format!("{resolution_id}.json"))
    }

    fn completion_path(&self, resolution_id: Uuid) -> PathBuf {
        self.inner
            .root
            .join("completions")
            .join(format!("{resolution_id}.json"))
    }

    fn ambiguity_path(&self, resolution_id: Uuid) -> PathBuf {
        self.inner
            .root
            .join("ambiguities")
            .join(format!("{resolution_id}.json"))
    }

    fn bundle_path(&self, resolution_id: Uuid) -> PathBuf {
        self.inner
            .root
            .join("bundles")
            .join(resolution_id.to_string())
    }

    fn deactivate(&self, resolution_id: Uuid) {
        if let Ok(mut active) = self.inner.active.lock() {
            active.remove(&resolution_id);
        }
    }

    fn deny_secret_markers<T: Serialize, U: Serialize>(
        &self,
        first: &T,
        second: &U,
    ) -> Result<(), StoreError> {
        let first_semantic = serde_json::to_value(first).map_err(|_| state_error())?;
        let second_semantic = serde_json::to_value(second).map_err(|_| state_error())?;
        let first = serde_json::to_vec(&first_semantic).map_err(|_| state_error())?;
        let second = serde_json::to_vec(&second_semantic).map_err(|_| state_error())?;
        if self.inner.marker_set.iter().any(|marker| {
            contains_bytes(&first, marker)
                || contains_bytes(&second, marker)
                || semantic_value_contains_marker(&first_semantic, marker)
                || semantic_value_contains_marker(&second_semantic, marker)
        }) {
            return Err(StoreError::new(
                "DEP_STORE_SECRET_MARKER_DETECTED",
                "dependency resolution state contains a configured secret marker",
            ));
        }
        Ok(())
    }
}

fn semantic_value_contains_marker(value: &serde_json::Value, marker: &[u8]) -> bool {
    match value {
        serde_json::Value::String(value) => contains_bytes(value.as_bytes(), marker),
        serde_json::Value::Array(values) => values
            .iter()
            .any(|value| semantic_value_contains_marker(value, marker)),
        serde_json::Value::Object(values) => values.iter().any(|(key, value)| {
            contains_bytes(key.as_bytes(), marker) || semantic_value_contains_marker(value, marker)
        }),
        _ => false,
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && needle.len() <= haystack.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn sign_receipt(receipt: &ResolutionReceipt, key: &[u8]) -> Result<String, StoreError> {
    let mut unsigned = receipt.clone();
    unsigned.hmac_sha256.clear();
    let bytes = serde_json::to_vec(&unsigned).map_err(|_| state_error())?;
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| {
        StoreError::new(
            "DEP_STORE_RECEIPT_KEY_INVALID",
            "receipt HMAC key is invalid",
        )
    })?;
    mac.update(b"mcloving-dependency-receipt-hmac-v1");
    mac.update(&(bytes.len() as u64).to_be_bytes());
    mac.update(&bytes);
    Ok(format!("{:x}", mac.finalize().into_bytes()))
}

fn verify_receipt_hmac(receipt: &ResolutionReceipt, key: &[u8]) -> Result<(), StoreError> {
    let signature = decode_hmac(&receipt.hmac_sha256).ok_or_else(|| {
        StoreError::new(
            "DEP_STORE_RECEIPT_INVALID",
            "stored receipt HMAC is not canonical lowercase hex",
        )
    })?;
    let mut unsigned = receipt.clone();
    unsigned.hmac_sha256.clear();
    let bytes = serde_json::to_vec(&unsigned).map_err(|_| state_error())?;
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| {
        StoreError::new(
            "DEP_STORE_RECEIPT_KEY_INVALID",
            "receipt HMAC key is invalid",
        )
    })?;
    mac.update(b"mcloving-dependency-receipt-hmac-v1");
    mac.update(&(bytes.len() as u64).to_be_bytes());
    mac.update(&bytes);
    mac.verify_slice(&signature).map_err(|_| {
        StoreError::new(
            "DEP_STORE_RECEIPT_INVALID",
            "stored receipt HMAC does not verify",
        )
    })
}

fn decode_hmac(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut decoded = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        decoded[index] = high << 4 | low;
    }
    Some(decoded)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn acquire_output_lock(root: &Path) -> Result<OutputLock, StoreError> {
    use nix::fcntl::{Flock, FlockArg};
    use nix::unistd::Uid;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

    let canonical = std::fs::canonicalize(root).map_err(|_| state_error())?;
    let metadata = std::fs::symlink_metadata(root).map_err(|_| state_error())?;
    if canonical != root
        || !metadata.file_type().is_dir()
        || metadata.uid() != Uid::effective().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(StoreError::new(
            "DEP_STORE_ROOT_POLICY_DENIED",
            "output root must be canonical, private, resolver-owned, and non-symlink",
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(nix::fcntl::OFlag::O_CLOEXEC.bits() | nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(root.join(LOCK_FILE))
        .map_err(|_| state_error())?;
    file.sync_all().map_err(|_| state_error())?;
    sync_directory(root)?;
    Flock::lock(file, FlockArg::LockExclusiveNonblock).map_err(|_| {
        StoreError::new(
            "DEP_STORE_ROOT_LOCKED",
            "another resolver owns the output root",
        )
    })
}

#[cfg(target_os = "linux")]
fn verify_inherited_output_lock(root: &Path) -> Result<File, StoreError> {
    use nix::fcntl::{Flock, FlockArg};
    use nix::unistd::Uid;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let inherited = nix::unistd::dup(std::io::stderr())
        .map(File::from)
        .map_err(|_| state_error())?;
    let inherited_metadata = inherited.metadata().map_err(|_| state_error())?;
    let path_metadata =
        std::fs::symlink_metadata(root.join(LOCK_FILE)).map_err(|_| state_error())?;
    if !inherited_metadata.is_file()
        || !path_metadata.file_type().is_file()
        || inherited_metadata.uid() != Uid::effective().as_raw()
        || path_metadata.uid() != Uid::effective().as_raw()
        || inherited_metadata.permissions().mode() & 0o777 != 0o600
        || path_metadata.permissions().mode() & 0o777 != 0o600
        || inherited_metadata.dev() != path_metadata.dev()
        || inherited_metadata.ino() != path_metadata.ino()
    {
        return Err(StoreError::new(
            "DEP_STORE_WORKER_PARENT_LOCK_INVALID",
            "publication worker did not inherit the exact private parent output lock",
        ));
    }
    match Flock::lock(inherited, FlockArg::LockExclusiveNonblock) {
        Ok(lock) => {
            let retained = lock.try_clone().map_err(|_| state_error())?;
            std::mem::forget(lock);
            Ok(retained)
        }
        Err(_) => Err(StoreError::new(
            "DEP_STORE_WORKER_PARENT_LOCK_INVALID",
            "publication worker did not inherit the locked parent file description",
        )),
    }
}

#[cfg(not(target_os = "linux"))]
fn verify_inherited_output_lock(_root: &Path) -> Result<File, StoreError> {
    Err(StoreError::new(
        "DEP_STORE_PLATFORM_UNSUPPORTED",
        "publication worker parent-lock proof requires Linux flock semantics",
    ))
}

#[cfg(not(target_os = "linux"))]
fn acquire_output_lock(_root: &Path) -> Result<OutputLock, StoreError> {
    Err(StoreError::new(
        "DEP_STORE_PLATFORM_UNSUPPORTED",
        "durable dependency publication requires Linux file semantics",
    ))
}

fn prepare_layout(root: &Path) -> Result<(), StoreError> {
    let expected = BTreeSet::from([
        LOCK_FILE.to_owned(),
        "ambiguities".to_owned(),
        "bundles".to_owned(),
        "claims".to_owned(),
        "completions".to_owned(),
        "receipts".to_owned(),
    ]);
    for name in [
        "ambiguities",
        "bundles",
        "claims",
        "completions",
        "receipts",
    ] {
        let path = root.join(name);
        if path_exists(&path)? {
            validate_directory(&path, 0o700)?;
        } else {
            create_directory(&path, 0o700)?;
        }
    }
    for entry in std::fs::read_dir(root).map_err(|_| state_error())? {
        let entry = entry.map_err(|_| state_error())?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !expected.contains(&name) {
            return Err(StoreError::new(
                "DEP_STORE_ROOT_RESIDUAL",
                "output root contains an unexpected residual entry",
            ));
        }
    }
    sync_directory(root)
}

fn retained_tree_sha256(
    root: &Path,
    output_root: &Path,
    max_file_bytes: u64,
    max_total_bytes: u64,
) -> Result<String, StoreError> {
    validate_directory(root, 0o500)?;
    let mut files = Vec::new();
    let mut directories = vec![
        directory_record("@output-root", output_root, 0o700)?,
        directory_record("@bundles-root", &output_root.join("bundles"), 0o700)?,
    ];
    let mut total = 0_u64;
    collect_tree(
        root,
        root,
        max_file_bytes,
        max_total_bytes,
        &mut total,
        &mut directories,
        &mut files,
    )?;
    files.sort_by(|left, right| left.0.cmp(&right.0));
    let mut hasher = Sha256::new();
    update_segment(&mut hasher, b"mcloving-dependency-retained-tree-v1");
    directories.sort_by(|left, right| left.0.cmp(&right.0));
    for (relative, mode, uid, device, inode) in directories {
        update_segment(&mut hasher, b"directory");
        update_segment(&mut hasher, relative.as_bytes());
        update_segment(&mut hasher, &mode.to_be_bytes());
        update_segment(&mut hasher, &uid.to_be_bytes());
        update_segment(&mut hasher, &device.to_be_bytes());
        update_segment(&mut hasher, &inode.to_be_bytes());
    }
    for (relative, mode, size, digest) in files {
        update_segment(&mut hasher, b"file");
        update_segment(&mut hasher, relative.as_bytes());
        update_segment(&mut hasher, &mode.to_be_bytes());
        update_segment(&mut hasher, &size.to_be_bytes());
        update_segment(&mut hasher, digest.as_bytes());
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn collect_tree(
    root: &Path,
    directory: &Path,
    max_file_bytes: u64,
    max_total_bytes: u64,
    total: &mut u64,
    directories: &mut Vec<(String, u32, u32, u64, u64)>,
    files: &mut Vec<(String, u32, u64, String)>,
) -> Result<(), StoreError> {
    validate_directory(directory, 0o500)?;
    let relative_directory = if directory == root {
        ".".to_owned()
    } else {
        directory
            .strip_prefix(root)
            .map_err(|_| state_error())?
            .to_str()
            .ok_or_else(state_error)?
            .to_owned()
    };
    directories.push(directory_record(&relative_directory, directory, 0o500)?);
    for entry in std::fs::read_dir(directory).map_err(|_| state_error())? {
        let entry = entry.map_err(|_| state_error())?;
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path).map_err(|_| state_error())?;
        if metadata.file_type().is_symlink() {
            return Err(StoreError::new(
                "DEP_STORE_RETAINED_TREE_MISMATCH",
                "retained bundle contains a symlink",
            ));
        }
        if metadata.is_dir() {
            collect_tree(
                root,
                &path,
                max_file_bytes,
                max_total_bytes,
                total,
                directories,
                files,
            )?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| state_error())?
                .to_str()
                .ok_or_else(state_error)?
                .to_owned();
            let (size, digest) = hash_bounded_file(&path, max_file_bytes, 0o400)?;
            *total = total.checked_add(size).ok_or_else(state_error)?;
            if *total > max_total_bytes {
                return Err(StoreError::new(
                    "DEP_STORE_RETAINED_TREE_MISMATCH",
                    "retained dependency tree exceeds its signed total bound",
                ));
            }
            files.push((relative, 0o400, size, digest));
        } else {
            return Err(StoreError::new(
                "DEP_STORE_RETAINED_TREE_MISMATCH",
                "retained bundle contains an unsupported file type",
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn directory_record(
    label: &str,
    path: &Path,
    expected_mode: u32,
) -> Result<(String, u32, u32, u64, u64), StoreError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let metadata = std::fs::symlink_metadata(path).map_err(|_| state_error())?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.permissions().mode() & 0o777 != expected_mode
    {
        return Err(StoreError::new(
            "DEP_STORE_DIRECTORY_POLICY_DENIED",
            "retained ancestor owner, mode, or type violates policy",
        ));
    }
    Ok((
        label.to_owned(),
        expected_mode,
        metadata.uid(),
        metadata.dev(),
        metadata.ino(),
    ))
}

#[cfg(not(unix))]
fn directory_record(
    _label: &str,
    _path: &Path,
    _expected_mode: u32,
) -> Result<(String, u32, u32, u64, u64), StoreError> {
    Err(StoreError::new(
        "DEP_STORE_PLATFORM_UNSUPPORTED",
        "retained ancestor verification requires Unix inode semantics",
    ))
}

fn verify_file(path: &Path, mode: u32, size: u64, digest: &str) -> Result<(), StoreError> {
    let (actual_size, actual_digest) = hash_bounded_file(path, size, mode)?;
    if actual_size != size || actual_digest != digest {
        return Err(StoreError::new(
            "DEP_STORE_ARTIFACT_CONTENT_MISMATCH",
            "artifact content changed before or after publication",
        ));
    }
    Ok(())
}

fn hash_bounded_file(path: &Path, max_bytes: u64, mode: u32) -> Result<(u64, String), StoreError> {
    let mut file = open_verified_file(path, max_bytes, mode)?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 65_536];
    loop {
        let read = file.read(&mut buffer).map_err(|_| state_error())?;
        if read == 0 {
            break;
        }
        total = total.checked_add(read as u64).ok_or_else(state_error)?;
        if total > max_bytes {
            return Err(state_error());
        }
        hasher.update(&buffer[..read]);
    }
    Ok((total, format!("{:x}", hasher.finalize())))
}

#[cfg(unix)]
fn read_bounded_file(path: &Path, max_bytes: u64, mode: u32) -> Result<Vec<u8>, StoreError> {
    let file = open_verified_file(path, max_bytes, mode)?;
    let metadata = file.metadata().map_err(|_| state_error())?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| state_error())?;
    if bytes.len() as u64 > max_bytes {
        return Err(state_error());
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_verified_file(path: &Path, max_bytes: u64, mode: u32) -> Result<File, StoreError> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::fcntl::OFlag::O_CLOEXEC.bits() | nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(path)
        .map_err(|_| state_error())?;
    let metadata = file.metadata().map_err(|_| state_error())?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.permissions().mode() & 0o777 != mode
        || metadata.len() > max_bytes
    {
        return Err(StoreError::new(
            "DEP_STORE_FILE_POLICY_DENIED",
            "state file owner, mode, type, or size violates policy",
        ));
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_verified_file(_path: &Path, _max_bytes: u64, _mode: u32) -> Result<File, StoreError> {
    Err(StoreError::new(
        "DEP_STORE_PLATFORM_UNSUPPORTED",
        "durable dependency publication requires Unix file semantics",
    ))
}

#[cfg(not(unix))]
fn read_bounded_file(_path: &Path, _max_bytes: u64, _mode: u32) -> Result<Vec<u8>, StoreError> {
    Err(StoreError::new(
        "DEP_STORE_PLATFORM_UNSUPPORTED",
        "durable dependency publication requires Unix file semantics",
    ))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path, mode: u32) -> Result<T, StoreError> {
    let bytes = read_bounded_file(path, MAX_STATE_BYTES, mode)?;
    crate::strict_json::from_slice(&bytes).map_err(|_| {
        StoreError::new(
            "DEP_STORE_STATE_INVALID",
            "stored state is malformed or not closed JSON",
        )
    })
}

fn write_new_json<T: Serialize>(path: &Path, value: &T, final_mode: u32) -> Result<(), StoreError> {
    let bytes = serde_json::to_vec(value).map_err(|_| state_error())?;
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(state_error());
    }
    let parent = path.parent().ok_or_else(state_error)?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(state_error)?;
    let temporary = parent.join(format!(".{name}.{}.tmp", Uuid::new_v4()));
    write_new_file(&temporary, &bytes)?;
    if let Err(error) =
        set_mode_and_sync(&temporary, final_mode).and_then(|()| rename_no_replace(&temporary, path))
    {
        let _ = remove_private_file(&temporary);
        return Err(error);
    }
    sync_directory(parent)
}

#[cfg(unix)]
fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::fcntl::OFlag::O_CLOEXEC.bits() | nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(path)
        .map_err(|_| state_error())?;
    file.write_all(bytes).map_err(|_| state_error())?;
    file.sync_all().map_err(|_| state_error())
}

#[cfg(not(unix))]
fn write_new_file(_path: &Path, _bytes: &[u8]) -> Result<(), StoreError> {
    Err(StoreError::new(
        "DEP_STORE_PLATFORM_UNSUPPORTED",
        "durable dependency publication requires Unix file semantics",
    ))
}

#[cfg(unix)]
fn copy_new_file(source: &Path, destination: &Path, expected_size: u64) -> Result<(), StoreError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut source = open_verified_file(source, expected_size, 0o600)?;
    let mut destination = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::fcntl::OFlag::O_CLOEXEC.bits() | nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(destination)
        .map_err(|_| state_error())?;
    let copied = std::io::copy(&mut source, &mut destination).map_err(|_| state_error())?;
    if copied != expected_size {
        return Err(StoreError::new(
            "DEP_STORE_ARTIFACT_CONTENT_MISMATCH",
            "artifact size changed while it was copied for publication",
        ));
    }
    destination.sync_all().map_err(|_| state_error())
}

#[cfg(not(unix))]
fn copy_new_file(
    _source: &Path,
    _destination: &Path,
    _expected_size: u64,
) -> Result<(), StoreError> {
    Err(StoreError::new(
        "DEP_STORE_PLATFORM_UNSUPPORTED",
        "durable dependency publication requires Unix file semantics",
    ))
}

#[cfg(unix)]
fn set_mode_and_sync(path: &Path, mode: u32) -> Result<(), StoreError> {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|_| state_error())?;
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| state_error())
}

#[cfg(not(unix))]
fn set_mode_and_sync(_path: &Path, _mode: u32) -> Result<(), StoreError> {
    Err(StoreError::new(
        "DEP_STORE_PLATFORM_UNSUPPORTED",
        "durable dependency publication requires Unix file semantics",
    ))
}

#[cfg(unix)]
fn create_directory(path: &Path, mode: u32) -> Result<(), StoreError> {
    use std::os::unix::fs::DirBuilderExt as _;

    let mut builder = std::fs::DirBuilder::new();
    builder.mode(mode).create(path).map_err(|_| state_error())?;
    sync_directory(path.parent().ok_or_else(state_error)?)
}

#[cfg(not(unix))]
fn create_directory(_path: &Path, _mode: u32) -> Result<(), StoreError> {
    Err(StoreError::new(
        "DEP_STORE_PLATFORM_UNSUPPORTED",
        "durable dependency publication requires Unix file semantics",
    ))
}

#[cfg(unix)]
fn validate_directory(path: &Path, mode: u32) -> Result<(), StoreError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let metadata = std::fs::symlink_metadata(path).map_err(|_| state_error())?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.permissions().mode() & 0o777 != mode
    {
        return Err(StoreError::new(
            "DEP_STORE_DIRECTORY_POLICY_DENIED",
            "state directory owner, mode, or type violates policy",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_directory(_path: &Path, _mode: u32) -> Result<(), StoreError> {
    Err(StoreError::new(
        "DEP_STORE_PLATFORM_UNSUPPORTED",
        "durable dependency publication requires Unix file semantics",
    ))
}

fn sync_directory(path: &Path) -> Result<(), StoreError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| state_error())
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn rename_no_replace(source: &Path, destination: &Path) -> Result<(), StoreError> {
    use nix::fcntl::{RenameFlags, renameat2};

    let source_parent = source.parent().ok_or_else(state_error)?;
    let destination_parent = destination.parent().ok_or_else(state_error)?;
    let source_name = source.file_name().ok_or_else(state_error)?;
    let destination_name = destination.file_name().ok_or_else(state_error)?;
    let source_directory = File::open(source_parent).map_err(|_| state_error())?;
    let destination_directory = File::open(destination_parent).map_err(|_| state_error())?;
    renameat2(
        &source_directory,
        source_name,
        &destination_directory,
        destination_name,
        RenameFlags::RENAME_NOREPLACE,
    )
    .map_err(|_| {
        StoreError::new(
            "DEP_STORE_PUBLICATION_CONFLICT",
            "atomic no-overwrite bundle publication failed",
        )
    })
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn rename_no_replace(_source: &Path, _destination: &Path) -> Result<(), StoreError> {
    Err(StoreError::new(
        "DEP_STORE_PLATFORM_UNSUPPORTED",
        "atomic no-overwrite publication requires Linux renameat2",
    ))
}

fn remove_private_tree(path: &Path) -> Result<(), StoreError> {
    if !path_exists(path)? {
        return Ok(());
    }
    make_tree_writable(path)?;
    std::fs::remove_dir_all(path).map_err(|_| state_error())
}

fn path_exists(path: &Path) -> Result<bool, StoreError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(state_error()),
    }
}

#[cfg(unix)]
fn remove_private_file(path: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::PermissionsExt as _;

    let metadata = std::fs::symlink_metadata(path).map_err(|_| state_error())?;
    if !metadata.file_type().is_file() {
        return Err(state_error());
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|_| state_error())?;
    std::fs::remove_file(path).map_err(|_| state_error())
}

#[cfg(not(unix))]
fn remove_private_file(_path: &Path) -> Result<(), StoreError> {
    Err(StoreError::new(
        "DEP_STORE_PLATFORM_UNSUPPORTED",
        "durable dependency publication requires Unix file semantics",
    ))
}

#[cfg(unix)]
fn make_tree_writable(path: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::PermissionsExt as _;

    let metadata = std::fs::symlink_metadata(path).map_err(|_| state_error())?;
    if metadata.file_type().is_symlink() {
        return Err(state_error());
    }
    if metadata.is_dir() {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| state_error())?;
        for entry in std::fs::read_dir(path).map_err(|_| state_error())? {
            make_tree_writable(&entry.map_err(|_| state_error())?.path())?;
        }
    } else if metadata.is_file() {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| state_error())?;
    } else {
        return Err(state_error());
    }
    Ok(())
}

#[cfg(not(unix))]
fn make_tree_writable(_path: &Path) -> Result<(), StoreError> {
    Err(StoreError::new(
        "DEP_STORE_PLATFORM_UNSUPPORTED",
        "durable dependency publication requires Unix file semantics",
    ))
}

fn current_unix_ms() -> Result<u64, StoreError> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| state_error())?
        .as_millis();
    u64::try_from(millis).map_err(|_| state_error())
}

fn update_segment(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn state_error() -> StoreError {
    StoreError::new(
        "DEP_STORE_STATE_UNAVAILABLE",
        "durable dependency state could not be verified or updated",
    )
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use tempfile::TempDir;

    use super::*;
    use crate::{
        AdapterConfig, Ecosystem, PackageNode, RepositoryBinding, RepositoryConfig, ResolverLimits,
        SourceTrustClass, canonical_graph_sha256, canonical_node_id, configuration_sha256,
        request_sha256,
    };

    struct Fixture {
        _root: TempDir,
        config: CertifiedConfig,
        request: ResolutionRequest,
        admitted: AdmittedRequest,
        plan: CanonicalPlan,
        fetched: Vec<FetchedArtifact>,
        receipt_key: Vec<u8>,
    }

    impl Fixture {
        fn new() -> Self {
            let root = TempDir::new().expect("publication root");
            let output = root.path().join("output");
            std::fs::create_dir(&output).expect("output root");
            std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o700))
                .expect("private output root");
            let body = b"contained published artifact";
            let artifact_sha256 = format!("{:x}", Sha256::digest(body));
            let mut node = PackageNode {
                node_id: String::new(),
                coordinate: "com.example:app:jar".to_owned(),
                exact_version: "1.0.0".to_owned(),
                repository_id: "contained-maven".to_owned(),
                artifact_path: "com/example/app/1.0.0/app.jar".to_owned(),
                declared_size: body.len() as u64,
                sha256: artifact_sha256.clone(),
                attestation_key_id: Some("contained-key".to_owned()),
                dependencies: Vec::new(),
            };
            node.node_id = canonical_node_id(Ecosystem::Maven, &node).expect("node id");
            let resolution_id = Uuid::new_v4();
            let transport = root.path().join("transport");
            let resolution_transport = transport.join(resolution_id.to_string());
            std::fs::create_dir_all(&resolution_transport).expect("transport resolution root");
            std::fs::set_permissions(&transport, std::fs::Permissions::from_mode(0o700))
                .expect("private transport root");
            std::fs::set_permissions(
                &resolution_transport,
                std::fs::Permissions::from_mode(0o700),
            )
            .expect("private transport resolution root");
            let transient = resolution_transport.join(format!("{}.part", node.node_id));
            std::fs::write(&transient, body).expect("transient artifact");
            std::fs::set_permissions(&transient, std::fs::Permissions::from_mode(0o600))
                .expect("private transient artifact");
            let mut plan = CanonicalPlan {
                schema_version: "mcloving.dependency-plan/v1".to_owned(),
                ecosystem: Ecosystem::Maven,
                adapter_id: "maven-v1".to_owned(),
                adapter_sha256: "a".repeat(64),
                source_tree_sha256: "b".repeat(64),
                lock_sha256: "c".repeat(64),
                resolver_toolchain_id: "contained-toolchain".to_owned(),
                resolver_toolchain_sha256: "d".repeat(64),
                source_trust_class: SourceTrustClass::Trusted,
                repositories: vec![RepositoryBinding {
                    repository_id: "contained-maven".to_owned(),
                    credentialed: false,
                    permits_untrusted_source: true,
                }],
                nodes: vec![node.clone()],
                roots: vec![node.node_id.clone()],
                graph_sha256: String::new(),
            };
            plan.graph_sha256 = canonical_graph_sha256(&plan).expect("graph digest");
            let config = CertifiedConfig {
                schema_version: "mcloving.dependency-config/v1".to_owned(),
                protocol_version: "mcloving.dependency-resolver/v1".to_owned(),
                configuration_id: "publication-test".to_owned(),
                deployment_id: "contained".to_owned(),
                operator_id: "test-operator".to_owned(),
                generation: 7,
                executable_sha256: "e".repeat(64),
                resolver_toolchain_id: "contained-toolchain".to_owned(),
                resolver_toolchain_sha256: "d".repeat(64),
                adapters: vec![
                    AdapterConfig {
                        ecosystem: Ecosystem::Maven,
                        adapter_id: "maven-v1".to_owned(),
                        implementation_sha256: "a".repeat(64),
                    },
                    AdapterConfig {
                        ecosystem: Ecosystem::Npm,
                        adapter_id: "npm-v1".to_owned(),
                        implementation_sha256: "1".repeat(64),
                    },
                    AdapterConfig {
                        ecosystem: Ecosystem::Pypi,
                        adapter_id: "pypi-v1".to_owned(),
                        implementation_sha256: "2".repeat(64),
                    },
                ],
                repositories: vec![RepositoryConfig {
                    repository_id: "contained-maven".to_owned(),
                    ecosystem: Ecosystem::Maven,
                    base_url: "https://127.0.0.1/repository/".to_owned(),
                    coordinate_prefixes: vec!["com.example:".to_owned()],
                    credential_path: None,
                    credential_sha256: None,
                    permits_untrusted_source: true,
                    attestation_key_id: "contained-key".to_owned(),
                    attestation_key_path: "/authority/attestation.pub".to_owned(),
                    attestation_key_sha256: "3".repeat(64),
                    private_ca_path: Some("/authority/private-ca.pem".to_owned()),
                    private_ca_sha256: Some("4".repeat(64)),
                    grant: None,
                }],
                receipt_key_id: "receipt-key-v1".to_owned(),
                receipt_key_path: "/authority/receipt.key".to_owned(),
                receipt_key_sha256: "5".repeat(64),
                secret_marker_set_path: "/authority/markers.json".to_owned(),
                secret_marker_set_sha256: "6".repeat(64),
                output_root: output.to_str().expect("output path").to_owned(),
                transport_root: transport.to_str().expect("transport path").to_owned(),
                limits: ResolverLimits {
                    max_frame_bytes: 1_048_576,
                    max_lock_bytes: 262_144,
                    max_repositories: 4,
                    max_nodes: 100,
                    max_edges: 1_000,
                    max_artifacts: 100,
                    max_artifact_bytes: 4_096,
                    max_total_artifact_bytes: 16_384,
                    transport_capacity_bytes: 16_384,
                    max_path_bytes: 4_096,
                    max_header_bytes: 16_384,
                    max_request_lifetime_ms: 120_000,
                },
                loopback_fixture: false,
            };
            let now = current_unix_ms().expect("wall clock");
            let mut request = ResolutionRequest {
                schema_version: "mcloving.dependency-request/v1".to_owned(),
                protocol_version: config.protocol_version.clone(),
                resolution_id: resolution_id.to_string(),
                tenant_id: "tenant-a".to_owned(),
                project_id: "project-a".to_owned(),
                pipeline_id: "pipeline-a".to_owned(),
                build_id: Uuid::new_v4().to_string(),
                attempt_id: Uuid::new_v4().to_string(),
                audit_lineage: "audit/publication/1".to_owned(),
                source_trust_class: SourceTrustClass::Trusted,
                expected_executable_sha256: config.executable_sha256.clone(),
                expected_configuration_sha256: configuration_sha256(&config)
                    .expect("configuration digest"),
                expected_adapter_id: plan.adapter_id.clone(),
                expected_adapter_sha256: plan.adapter_sha256.clone(),
                expected_resolver_toolchain_id: plan.resolver_toolchain_id.clone(),
                expected_resolver_toolchain_sha256: plan.resolver_toolchain_sha256.clone(),
                expected_generation: config.generation,
                acquisition_receipt_sha256: "7".repeat(64),
                source_tree_sha256: plan.source_tree_sha256.clone(),
                logical_lock_path: "dependency-locks/maven.json".to_owned(),
                expected_lock_sha256: plan.lock_sha256.clone(),
                ecosystem: Ecosystem::Maven,
                expected_graph_sha256: plan.graph_sha256.clone(),
                repository_ids: vec!["contained-maven".to_owned()],
                grants: Vec::new(),
                requested_at_unix_ms: now.saturating_sub(1_000),
                expires_at_unix_ms: now + 60_000,
                rollback_from_generation: None,
            };
            let request_digest = request_sha256(&request).expect("request digest");
            let admitted = AdmittedRequest {
                configuration_sha256: request.expected_configuration_sha256.clone(),
                request_sha256: request_digest,
                absolute_expiry_unix_ms: request.expires_at_unix_ms,
                repository_ids: request.repository_ids.clone(),
            };
            let fetched = vec![FetchedArtifact {
                node_id: node.node_id,
                transient_path: transient,
                declared_size: body.len() as u64,
                sha256: artifact_sha256,
                attestation_sha256: "8".repeat(64),
                publication_generation: config.generation,
            }];
            request.expected_graph_sha256 = plan.graph_sha256.clone();
            Self {
                _root: root,
                config,
                request,
                admitted,
                plan,
                fetched,
                receipt_key: b"contained-receipt-key-material-v1".to_vec(),
            }
        }

        fn store(&self) -> ResolutionStore {
            self.store_with_markers(vec![self.receipt_key.clone()])
        }

        fn store_with_markers(&self, markers: Vec<Vec<u8>>) -> ResolutionStore {
            ResolutionStore::open_inner(&self.config, &self.receipt_key, markers)
                .expect("resolution store")
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn publication_parent_delegates_the_exact_locked_file() {
        use std::os::unix::fs::MetadataExt as _;

        let fixture = Fixture::new();
        let store = fixture.store();
        let delegated = store
            .publication_lock_file()
            .expect("delegated parent lock");
        let expected =
            std::fs::metadata(PathBuf::from(&fixture.config.output_root).join(LOCK_FILE))
                .expect("output lock metadata");
        let actual = delegated.metadata().expect("delegated lock metadata");
        assert_eq!(
            (actual.dev(), actual.ino()),
            (expected.dev(), expected.ino())
        );
    }

    #[test]
    fn durable_claim_precedes_immutable_bundle_and_exact_offline_replay() {
        let fixture = Fixture::new();
        let store = fixture.store();
        let claim = match store
            .claim_or_replay(&fixture.request, &fixture.admitted, &fixture.plan)
            .expect("new claim")
        {
            ClaimOutcome::New(claim) => claim,
            other => panic!("unexpected claim outcome: {other:?}"),
        };
        assert!(store.claim_path(claim.resolution_id).exists());
        let receipt = store
            .publish(
                &claim,
                fixture.request.clone(),
                &fixture.admitted,
                fixture.plan.clone(),
                &fixture.fetched,
                Instant::now() + std::time::Duration::from_secs(60),
            )
            .expect("published receipt");
        assert!(!store.claim_path(claim.resolution_id).exists());
        assert!(store.completion_path(claim.resolution_id).exists());
        assert!(
            !PathBuf::from(&fixture.config.transport_root)
                .join(claim.resolution_id.to_string())
                .exists(),
            "verified transient state must be gone before completion is replayable"
        );
        let replay = store
            .claim_or_replay(&fixture.request, &fixture.admitted, &fixture.plan)
            .expect("offline replay");
        assert_eq!(replay, ClaimOutcome::Replay(Box::new(receipt.clone())));
        assert_eq!(
            store
                .load_completed(claim.resolution_id, &fixture.admitted.request_sha256)
                .expect("stored receipt"),
            Some(receipt)
        );
    }

    #[test]
    fn concurrency_substitution_restart_ambiguity_and_tamper_are_explicit() {
        let mut fixture = Fixture::new();
        let store = fixture.store();
        let claim = match store
            .claim_or_replay(&fixture.request, &fixture.admitted, &fixture.plan)
            .expect("new claim")
        {
            ClaimOutcome::New(claim) => claim,
            other => panic!("unexpected claim outcome: {other:?}"),
        };
        assert_eq!(
            store
                .claim_or_replay(&fixture.request, &fixture.admitted, &fixture.plan)
                .expect("concurrent claim"),
            ClaimOutcome::Concurrent(claim.clone())
        );
        let original_request = fixture.request.clone();
        let original_admitted = fixture.admitted.clone();
        fixture.request.audit_lineage = "audit/substituted".to_owned();
        fixture.admitted.request_sha256 = request_sha256(&fixture.request).expect("new request");
        let error = store
            .claim_or_replay(&fixture.request, &fixture.admitted, &fixture.plan)
            .expect_err("claim substitution");
        assert_eq!(error.code, "DEP_STORE_REPLAY_SUBSTITUTION");

        fixture.request = original_request;
        fixture.admitted = original_admitted;
        store.release_incomplete_claim(&claim);
        assert!(matches!(
            store
                .concurrent_claim_state(claim.resolution_id, &fixture.admitted.request_sha256)
                .expect("released concurrent state"),
            ConcurrentClaimState::InactiveIncomplete
        ));
        drop(store);
        let reopened = fixture.store();
        let error = reopened
            .claim_or_replay(&fixture.request, &fixture.admitted, &fixture.plan)
            .expect_err("restart ambiguity");
        assert_eq!(error.code, "DEP_STORE_AMBIGUOUS_CLAIM");
    }

    #[test]
    fn request_secret_markers_are_denied_before_claim() {
        let mut fixture = Fixture::new();
        fixture.request.audit_lineage =
            String::from_utf8(fixture.receipt_key.clone()).expect("UTF-8 receipt-key fixture");
        fixture.admitted.request_sha256 =
            request_sha256(&fixture.request).expect("marked request digest");
        let store = fixture.store();
        let error = store
            .claim_or_replay(&fixture.request, &fixture.admitted, &fixture.plan)
            .expect_err("request secret marker");
        assert_eq!(error.code, "DEP_STORE_SECRET_MARKER_DETECTED");
        assert!(
            std::fs::read_dir(store.inner.root.join("claims"))
                .expect("claims directory")
                .next()
                .is_none(),
            "secret-bearing request must not create a durable claim"
        );
    }

    #[test]
    fn json_sensitive_secret_marker_is_denied_before_escaping() {
        let mut fixture = Fixture::new();
        let marker = b"contained-\"secret\\marker".to_vec();
        fixture.request.audit_lineage =
            String::from_utf8(marker.clone()).expect("UTF-8 semantic marker");
        fixture.admitted.request_sha256 =
            request_sha256(&fixture.request).expect("marked request digest");
        let store = fixture.store_with_markers(vec![fixture.receipt_key.clone(), marker]);
        let error = store
            .claim_or_replay(&fixture.request, &fixture.admitted, &fixture.plan)
            .expect_err("raw semantic secret marker");
        assert_eq!(error.code, "DEP_STORE_SECRET_MARKER_DETECTED");
    }

    #[test]
    fn claim_precedes_completion_and_completion_marker_is_required() {
        let fixture = Fixture::new();
        let store = fixture.store();
        let claim = match store
            .claim_or_replay(&fixture.request, &fixture.admitted, &fixture.plan)
            .expect("new claim")
        {
            ClaimOutcome::New(claim) => claim,
            other => panic!("unexpected claim outcome: {other:?}"),
        };
        store
            .publish(
                &claim,
                fixture.request.clone(),
                &fixture.admitted,
                fixture.plan.clone(),
                &fixture.fetched,
                Instant::now() + std::time::Duration::from_secs(60),
            )
            .expect("completed publication");

        write_new_json(&store.claim_path(claim.resolution_id), &claim, 0o600)
            .expect("restored durable claim");
        let error = store
            .claim_or_replay(&fixture.request, &fixture.admitted, &fixture.plan)
            .expect_err("claim must dominate completion");
        assert_eq!(error.code, "DEP_STORE_AMBIGUOUS_CLAIM");
        remove_private_file(&store.claim_path(claim.resolution_id)).expect("remove test claim");
        sync_directory(&store.inner.root.join("claims")).expect("sync test claim removal");

        remove_private_file(&store.completion_path(claim.resolution_id))
            .expect("remove completion record");
        sync_directory(&store.inner.root.join("completions")).expect("sync completion removal");
        let error = store
            .load_completed(claim.resolution_id, &fixture.admitted.request_sha256)
            .expect_err("receipt without completion");
        assert_eq!(error.code, "DEP_STORE_AMBIGUOUS_COMPLETION");
    }

    #[test]
    fn completion_write_failure_keeps_the_durable_claim() {
        let fixture = Fixture::new();
        let store = fixture.store();
        let claim = match store
            .claim_or_replay(&fixture.request, &fixture.admitted, &fixture.plan)
            .expect("new claim")
        {
            ClaimOutcome::New(claim) => claim,
            other => panic!("unexpected claim outcome: {other:?}"),
        };
        let conflicting_completion = ResolutionCompletion {
            schema_version: COMPLETION_SCHEMA.to_owned(),
            resolution_id: claim.resolution_id,
            request_sha256: claim.request_sha256.clone(),
            receipt_hmac_sha256: "0".repeat(64),
        };
        write_new_json(
            &store.completion_path(claim.resolution_id),
            &conflicting_completion,
            0o400,
        )
        .expect("conflicting completion fixture");

        let error = store
            .publish(
                &claim,
                fixture.request.clone(),
                &fixture.admitted,
                fixture.plan.clone(),
                &fixture.fetched,
                Instant::now() + std::time::Duration::from_secs(60),
            )
            .expect_err("completion write conflict");
        assert_eq!(error.code, "DEP_STORE_PUBLICATION_CONFLICT");
        assert!(store.claim_path(claim.resolution_id).exists());
        store.release_incomplete_claim(&claim);
        let error = store
            .claim_or_replay(&fixture.request, &fixture.admitted, &fixture.plan)
            .expect_err("durable claim after completion failure");
        assert_eq!(error.code, "DEP_STORE_AMBIGUOUS_CLAIM");
    }

    #[test]
    fn durable_ambiguity_record_blocks_an_apparent_completion() {
        let fixture = Fixture::new();
        let store = fixture.store();
        let claim = match store
            .claim_or_replay(&fixture.request, &fixture.admitted, &fixture.plan)
            .expect("new claim")
        {
            ClaimOutcome::New(claim) => claim,
            other => panic!("unexpected claim outcome: {other:?}"),
        };
        store
            .publish(
                &claim,
                fixture.request.clone(),
                &fixture.admitted,
                fixture.plan.clone(),
                &fixture.fetched,
                Instant::now() + std::time::Duration::from_secs(60),
            )
            .expect("completed publication");
        store.record_ambiguity(&claim).expect("durable ambiguity");

        let error = store
            .load_completed(claim.resolution_id, &fixture.admitted.request_sha256)
            .expect_err("ambiguity must dominate exact completion");
        assert_eq!(error.code, "DEP_STORE_AMBIGUOUS_CLAIM");
    }

    #[test]
    fn worker_completion_remains_blocked_until_receipt_delivery_is_acknowledged() {
        let fixture = Fixture::new();
        let store = fixture.store();
        let claim = match store
            .claim_or_replay(&fixture.request, &fixture.admitted, &fixture.plan)
            .expect("new claim")
        {
            ClaimOutcome::New(claim) => claim,
            other => panic!("unexpected claim outcome: {other:?}"),
        };
        let receipt = store
            .publish_worker(
                &claim,
                fixture.request.clone(),
                &fixture.admitted,
                fixture.plan.clone(),
                &fixture.fetched,
                Instant::now() + std::time::Duration::from_secs(60),
            )
            .expect("worker publication");
        let error = store
            .load_completed(claim.resolution_id, &fixture.admitted.request_sha256)
            .expect_err("unacknowledged delivery must remain ambiguous");
        assert_eq!(error.code, "DEP_STORE_AMBIGUOUS_CLAIM");

        store
            .acknowledge_delivery(&claim)
            .expect("receipt delivery acknowledgement");
        assert_eq!(
            store
                .load_completed(claim.resolution_id, &fixture.admitted.request_sha256)
                .expect("acknowledged completion"),
            Some(receipt)
        );
    }

    #[test]
    fn oversized_success_response_is_denied_before_claim() {
        let fixture = Fixture::new();
        let store = fixture.store();
        let error = store
            .ensure_receipt_response_capacity(
                &fixture.request,
                &fixture.admitted,
                &fixture.plan,
                128,
            )
            .expect_err("oversized success response");
        assert_eq!(error.code, "DEP_RESPONSE_FRAME_OVERSIZED");
        let resolution_id = Uuid::parse_str(&fixture.request.resolution_id).expect("resolution ID");
        assert!(!store.claim_path(resolution_id).exists());
    }

    #[test]
    fn final_claim_sync_error_deactivates_the_owner() {
        let fixture = Fixture::new();
        let store = fixture.store();
        let claim = match store
            .claim_or_replay(&fixture.request, &fixture.admitted, &fixture.plan)
            .expect("new claim")
        {
            ClaimOutcome::New(claim) => claim,
            other => panic!("unexpected claim outcome: {other:?}"),
        };
        let error = store
            .finish_claim_directory_sync(claim.resolution_id, Err(state_error()))
            .expect_err("final claim sync error");
        assert_eq!(error.code, "DEP_STORE_STATE_UNAVAILABLE");
        assert!(matches!(
            store
                .concurrent_claim_state(claim.resolution_id, &fixture.admitted.request_sha256)
                .expect("inactive incomplete claim"),
            ConcurrentClaimState::InactiveIncomplete
        ));
    }

    #[test]
    fn receipt_is_durably_removed_before_a_publication_bundle() {
        let fixture = Fixture::new();
        let store = fixture.store();
        let claim = match store
            .claim_or_replay(&fixture.request, &fixture.admitted, &fixture.plan)
            .expect("new claim")
        {
            ClaimOutcome::New(claim) => claim,
            other => panic!("unexpected claim outcome: {other:?}"),
        };
        store
            .publish(
                &claim,
                fixture.request.clone(),
                &fixture.admitted,
                fixture.plan.clone(),
                &fixture.fetched,
                Instant::now() + std::time::Duration::from_secs(60),
            )
            .expect("published receipt");
        let receipt_path = store.receipt_path(claim.resolution_id);
        let bundle_path = store.bundle_path(claim.resolution_id);
        store
            .withdraw_publication(&receipt_path, &bundle_path)
            .expect("paired withdrawal");
        assert!(!receipt_path.exists());
        assert!(!bundle_path.exists());
    }

    #[test]
    fn uncertain_receipt_lookup_retains_the_publication_bundle() {
        let fixture = Fixture::new();
        let store = fixture.store();
        let blocker = store.inner.root.join("receipt-lookup-blocker");
        std::fs::write(&blocker, b"not a directory").expect("lookup blocker");
        let receipt_path = blocker.join("receipt.json");
        let bundle_path = store.inner.root.join("bundles/uncertain");
        create_directory(&bundle_path, 0o700).expect("test bundle");

        let error = store
            .withdraw_publication(&receipt_path, &bundle_path)
            .expect_err("uncertain receipt lookup");
        assert_eq!(error.code, "DEP_STORE_STATE_UNAVAILABLE");
        assert!(bundle_path.exists(), "uncertainty must retain the bundle");
    }

    #[test]
    fn receipt_hmac_tampering_is_denied() {
        let fixture = Fixture::new();
        let store = fixture.store();
        let claim = match store
            .claim_or_replay(&fixture.request, &fixture.admitted, &fixture.plan)
            .expect("new claim")
        {
            ClaimOutcome::New(claim) => claim,
            other => panic!("unexpected claim outcome: {other:?}"),
        };
        let mut receipt = store
            .publish(
                &claim,
                fixture.request.clone(),
                &fixture.admitted,
                fixture.plan.clone(),
                &fixture.fetched,
                Instant::now() + std::time::Duration::from_secs(60),
            )
            .expect("publication");
        receipt.hmac_sha256 = "0".repeat(64);
        let receipt_path = store.receipt_path(claim.resolution_id);
        std::fs::set_permissions(&receipt_path, std::fs::Permissions::from_mode(0o600))
            .expect("make receipt mutable for adversarial fixture");
        std::fs::write(
            &receipt_path,
            serde_json::to_vec(&receipt).expect("tampered receipt bytes"),
        )
        .expect("tamper receipt");
        std::fs::set_permissions(&receipt_path, std::fs::Permissions::from_mode(0o400))
            .expect("restore sealed receipt mode");
        let error = store
            .load_completed(claim.resolution_id, &fixture.admitted.request_sha256)
            .expect_err("tampered receipt HMAC");
        assert_eq!(error.code, "DEP_STORE_RECEIPT_INVALID");
    }

    #[test]
    fn retained_content_substitution_and_late_publication_are_denied() {
        let fixture = Fixture::new();
        let store = fixture.store();
        let claim = match store
            .claim_or_replay(&fixture.request, &fixture.admitted, &fixture.plan)
            .expect("new claim")
        {
            ClaimOutcome::New(claim) => claim,
            other => panic!("unexpected claim outcome: {other:?}"),
        };
        let receipt = store
            .publish(
                &claim,
                fixture.request.clone(),
                &fixture.admitted,
                fixture.plan.clone(),
                &fixture.fetched,
                Instant::now() + std::time::Duration::from_secs(60),
            )
            .expect("publication");
        let artifact_path = store
            .bundle_path(claim.resolution_id)
            .join(&receipt.artifacts[0].relative_path);
        std::fs::set_permissions(&artifact_path, std::fs::Permissions::from_mode(0o600))
            .expect("make artifact mutable for adversarial fixture");
        std::fs::write(&artifact_path, b"substituted").expect("substitute artifact");
        std::fs::set_permissions(&artifact_path, std::fs::Permissions::from_mode(0o400))
            .expect("restore sealed mode");
        let error = store
            .load_completed(claim.resolution_id, &fixture.admitted.request_sha256)
            .expect_err("retained substitution");
        assert_eq!(error.code, "DEP_STORE_RETAINED_TREE_MISMATCH");

        let late = Fixture::new();
        let late_store = late.store();
        let mut late_admitted = late.admitted.clone();
        late_admitted.absolute_expiry_unix_ms = current_unix_ms().expect("clock") - 1;
        let late_claim = match late_store
            .claim_or_replay(&late.request, &late_admitted, &late.plan)
            .expect("late claim")
        {
            ClaimOutcome::New(claim) => claim,
            other => panic!("unexpected claim outcome: {other:?}"),
        };
        let error = late_store
            .publish(
                &late_claim,
                late.request.clone(),
                &late_admitted,
                late.plan.clone(),
                &late.fetched,
                Instant::now() + std::time::Duration::from_secs(60),
            )
            .expect_err("late publication");
        assert_eq!(error.code, "DEP_STORE_PUBLICATION_LATE");
        assert!(!late_store.bundle_path(late_claim.resolution_id).exists());
        late_store.release_incomplete_claim(&late_claim);

        let monotonic = Fixture::new();
        let monotonic_store = monotonic.store();
        let monotonic_claim = match monotonic_store
            .claim_or_replay(&monotonic.request, &monotonic.admitted, &monotonic.plan)
            .expect("monotonic claim")
        {
            ClaimOutcome::New(claim) => claim,
            other => panic!("unexpected claim outcome: {other:?}"),
        };
        let error = monotonic_store
            .publish(
                &monotonic_claim,
                monotonic.request.clone(),
                &monotonic.admitted,
                monotonic.plan.clone(),
                &monotonic.fetched,
                Instant::now(),
            )
            .expect_err("expired monotonic publication");
        assert_eq!(error.code, "DEP_STORE_PUBLICATION_LATE");
        assert!(
            !monotonic_store
                .bundle_path(monotonic_claim.resolution_id)
                .exists()
        );
        monotonic_store.release_incomplete_claim(&monotonic_claim);
    }

    #[test]
    fn publication_rejects_artifacts_outside_the_bound_transport_slot() {
        let mut fixture = Fixture::new();
        let store = fixture.store();
        let claim = match store
            .claim_or_replay(&fixture.request, &fixture.admitted, &fixture.plan)
            .expect("new claim")
        {
            ClaimOutcome::New(claim) => claim,
            other => panic!("unexpected claim outcome: {other:?}"),
        };
        fixture.fetched[0].transient_path = fixture._root.path().join("forged.part");
        std::fs::write(
            &fixture.fetched[0].transient_path,
            b"contained published artifact",
        )
        .expect("forged transient");
        std::fs::set_permissions(
            &fixture.fetched[0].transient_path,
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("forged transient mode");
        let error = store
            .publish(
                &claim,
                fixture.request.clone(),
                &fixture.admitted,
                fixture.plan.clone(),
                &fixture.fetched,
                Instant::now() + std::time::Duration::from_secs(60),
            )
            .expect_err("foreign transient path");
        assert_eq!(error.code, "DEP_STORE_TRANSIENT_PATH_MISMATCH");
        store.release_incomplete_claim(&claim);
    }

    #[test]
    fn generation_cutover_and_explicit_rollback_lineage_are_exact() {
        let mut fixture = Fixture::new();
        let generation_seven = publish_fixture(&fixture);
        assert_eq!(generation_seven.generation, 7);

        rotate_generation(&mut fixture, 8, None);
        let generation_eight = publish_fixture(&fixture);
        assert_eq!(generation_eight.generation, 8);
        assert_eq!(generation_eight.rollback_from_generation, None);
        assert_ne!(
            generation_seven.configuration_sha256,
            generation_eight.configuration_sha256
        );

        rotate_generation(&mut fixture, 9, Some(8));
        let rollback = publish_fixture(&fixture);
        assert_eq!(rollback.generation, 9);
        assert_eq!(rollback.rollback_from_generation, Some(8));
        assert_ne!(generation_eight.request_sha256, rollback.request_sha256);
    }

    fn publish_fixture(fixture: &Fixture) -> ResolutionReceipt {
        let store = fixture.store();
        let claim = match store
            .claim_or_replay(&fixture.request, &fixture.admitted, &fixture.plan)
            .expect("generation claim")
        {
            ClaimOutcome::New(claim) => claim,
            other => panic!("unexpected generation outcome: {other:?}"),
        };
        store
            .publish(
                &claim,
                fixture.request.clone(),
                &fixture.admitted,
                fixture.plan.clone(),
                &fixture.fetched,
                Instant::now() + std::time::Duration::from_secs(60),
            )
            .expect("generation publication")
    }

    fn rotate_generation(fixture: &mut Fixture, generation: u64, rollback_from: Option<u64>) {
        let previous_bundle_artifact = PathBuf::from(&fixture.config.output_root)
            .join("bundles")
            .join(&fixture.request.resolution_id)
            .join("artifacts")
            .join(&fixture.plan.nodes[0].sha256);
        fixture.config.generation = generation;
        fixture.request.resolution_id = Uuid::new_v4().to_string();
        fixture.request.build_id = Uuid::new_v4().to_string();
        fixture.request.attempt_id = Uuid::new_v4().to_string();
        fixture.request.expected_generation = generation;
        fixture.request.rollback_from_generation = rollback_from;
        fixture.request.expected_configuration_sha256 =
            configuration_sha256(&fixture.config).expect("rotated config digest");
        fixture.admitted.configuration_sha256 =
            fixture.request.expected_configuration_sha256.clone();
        fixture.admitted.request_sha256 =
            request_sha256(&fixture.request).expect("rotated request digest");
        fixture.admitted.absolute_expiry_unix_ms = fixture.request.expires_at_unix_ms;
        fixture.fetched[0].publication_generation = generation;
        let next_root =
            PathBuf::from(&fixture.config.transport_root).join(&fixture.request.resolution_id);
        std::fs::create_dir(&next_root).expect("rotated transport root");
        std::fs::set_permissions(&next_root, std::fs::Permissions::from_mode(0o700))
            .expect("private rotated transport root");
        let next_transient = next_root.join(format!("{}.part", fixture.fetched[0].node_id));
        std::fs::copy(previous_bundle_artifact, &next_transient)
            .expect("rotated transient artifact");
        std::fs::set_permissions(&next_transient, std::fs::Permissions::from_mode(0o600))
            .expect("rotated transient mode");
        fixture.fetched[0].transient_path = next_transient;
    }
}
