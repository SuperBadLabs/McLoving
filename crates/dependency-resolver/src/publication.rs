#[cfg(test)]
use std::collections::VecDeque;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use hmac::{Hmac, Mac as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    AdmittedRequest, CanonicalPlan, CertifiedConfig, FetchedArtifact, LoadedAuthorities,
    ResolutionRequest, serialized_response_fits_frame,
};

type HmacSha256 = Hmac<Sha256>;
const CLAIM_SCHEMA: &str = "mcloving.dependency-claim/v1";
const COMPLETION_SCHEMA: &str = "mcloving.dependency-completion/v1";
const PUBLICATION_COMMIT_SCHEMA: &str = "mcloving.dependency-publication-commit/v1";
const MANIFEST_SCHEMA: &str = "mcloving.dependency-manifest/v1";
const ARCHIVE_SCHEMA: &str = "mcloving.dependency-archive/v1";
const RECEIPT_SCHEMA: &str = "mcloving.dependency-receipt/v1";
const MAX_STATE_BYTES: u64 = 16 * 1_048_576;
#[cfg(test)]
const MAX_RETAINED_TREE_ENTRIES: usize = 1_000_000;
#[cfg(test)]
const MAX_CLEANUP_DEPTH: usize = 64;
const LOCK_FILE: &str = ".mcloving-dependency-output.lock";

#[cfg(test)]
#[derive(Clone, Copy)]
struct RetainedTreeLimits {
    max_entries: usize,
    max_depth: usize,
}

#[cfg(test)]
struct RetainedTreeRecords<'a> {
    total: &'a mut u64,
    directories: &'a mut Vec<(String, u32, u32, u64, u64)>,
    files: &'a mut Vec<(String, u32, u64, String)>,
}

#[cfg(test)]
#[allow(dead_code)]
#[derive(Debug)]
struct RetainedTreeEvidence {
    sha256: String,
    directories: BTreeSet<String>,
    files: BTreeMap<String, (u64, String)>,
    manifest_bytes: Vec<u8>,
}

#[cfg(test)]
struct PinnedPublicationDirectory {
    directory: File,
    path: PathBuf,
    device: u64,
    inode: u64,
}

#[cfg(all(target_os = "linux", test))]
struct PendingRetainedDirectory {
    directory: Arc<File>,
    relative: String,
    depth: usize,
    parent: Arc<File>,
    name: std::ffi::CString,
    identity: RetainedLinkIdentity,
}

#[cfg(all(target_os = "linux", test))]
struct RetainedTreeLink {
    parent: Arc<File>,
    name: std::ffi::CString,
    identity: RetainedLinkIdentity,
    directory: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RetainedLinkIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    links: u64,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

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
struct PublicationCommit {
    schema_version: String,
    claim: ResolutionClaim,
    receipt_identity: RetainedLinkIdentity,
    completion_identity: RetainedLinkIdentity,
    hmac_sha256: String,
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
struct ResolutionArchiveHeader {
    schema_version: String,
    manifest: ResolutionManifest,
    entries: Vec<ResolutionArchiveEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ResolutionArchiveEntry {
    relative_path: String,
    payload_offset: u64,
    size: u64,
    sha256: String,
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

pub struct SerializedOutputGuard {
    marker_set: Vec<Vec<u8>>,
    suffix: Vec<u8>,
    suffix_limit: usize,
}

impl SerializedOutputGuard {
    fn new(marker_set: &[Vec<u8>]) -> Self {
        Self {
            marker_set: marker_set.to_vec(),
            suffix: Vec::new(),
            suffix_limit: marker_set
                .iter()
                .map(Vec::len)
                .max()
                .unwrap_or_default()
                .saturating_sub(1),
        }
    }

    pub fn admit(&mut self, bytes: &[u8]) -> bool {
        let mut candidate = Vec::with_capacity(self.suffix.len() + bytes.len());
        candidate.extend_from_slice(&self.suffix);
        candidate.extend_from_slice(bytes);
        if self
            .marker_set
            .iter()
            .any(|marker| contains_bytes(&candidate, marker))
        {
            return false;
        }
        let retained = self.suffix_limit.min(candidate.len());
        self.suffix.clear();
        self.suffix
            .extend_from_slice(&candidate[candidate.len() - retained..]);
        true
    }
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

#[cfg(target_os = "linux")]
type ReceiptAdmissionLock = nix::fcntl::Flock<File>;

#[cfg(not(target_os = "linux"))]
struct ReceiptAdmissionLock;

#[cfg(not(target_os = "linux"))]
struct OutputLock;

struct StoreInner {
    root_directory: File,
    ambiguities_root: PathBuf,
    ambiguities_directory: File,
    bundles_root: PathBuf,
    bundles_directory: File,
    claims_root: PathBuf,
    claims_directory: File,
    commits_root: PathBuf,
    commits_directory: File,
    completions_root: PathBuf,
    completions_directory: File,
    receipts_root: PathBuf,
    receipts_directory: File,
    transport_root: PathBuf,
    transport_directory: File,
    configuration_sha256: String,
    generation: u64,
    executable_sha256: String,
    secret_marker_set_sha256: String,
    receipt_key_id: String,
    receipt_key: Vec<u8>,
    marker_set: Vec<Vec<u8>>,
    max_total_artifact_bytes: u64,
    active: Mutex<BTreeSet<Uuid>>,
    _lock: OutputLockGuard,
}

struct StoreDirectories {
    ambiguities_root: PathBuf,
    ambiguities_directory: File,
    bundles_root: PathBuf,
    bundles_directory: File,
    claims_root: PathBuf,
    claims_directory: File,
    commits_root: PathBuf,
    commits_directory: File,
    completions_root: PathBuf,
    completions_directory: File,
    receipts_root: PathBuf,
    receipts_directory: File,
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

struct LoadedReceipt {
    receipt: ResolutionReceipt,
    admission_lock: ReceiptAdmissionLock,
    receipt_identity: RetainedLinkIdentity,
    completion_file: File,
    completion_identity: RetainedLinkIdentity,
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
            None,
        )
    }

    fn open_inner(
        config: &CertifiedConfig,
        receipt_key: &[u8],
        marker_set: Vec<Vec<u8>>,
        transport_root_identity: Option<crate::transport::TransportRootIdentity>,
    ) -> Result<Self, StoreError> {
        let root_directory = open_pinned_cleanup_root(Path::new(&config.output_root))?;
        let root = pinned_directory_path(&root_directory);
        let lock = acquire_output_lock(&root_directory, &root)?;
        Self::open_inner_with_lock(
            config,
            receipt_key,
            marker_set,
            root,
            root_directory,
            transport_root_identity,
            OutputLockGuard::Owner(lock),
        )
    }

    pub(crate) fn open_worker(
        config: &CertifiedConfig,
        authorities: &LoadedAuthorities,
        output_root_identity: crate::transport::TransportRootIdentity,
        transport_root_identity: crate::transport::TransportRootIdentity,
    ) -> Result<Self, StoreError> {
        crate::validate_config(config)
            .map_err(|error| StoreError::new(error.code, error.message))?;
        let root_directory = open_pinned_cleanup_root(Path::new(&config.output_root))?;
        validate_private_directory(
            &root_directory,
            "DEP_STORE_ROOT_POLICY_DENIED",
            "output root must remain private and resolver-owned",
        )?;
        require_directory_identity(
            &root_directory,
            output_root_identity,
            "DEP_STORE_WORKER_PARENT_ROOT_INVALID",
            "publication worker output root does not match the pinned parent root",
        )?;
        let root = pinned_directory_path(&root_directory);
        let inherited_lock = verify_inherited_output_lock(&root_directory)?;
        Self::open_inner_with_lock(
            config,
            authorities.receipt_key(),
            authorities
                .markers()
                .map(|marker| marker.to_vec())
                .collect(),
            root,
            root_directory,
            Some(transport_root_identity),
            OutputLockGuard::Inherited {
                _file: inherited_lock,
            },
        )
    }

    fn open_inner_with_lock(
        config: &CertifiedConfig,
        receipt_key: &[u8],
        marker_set: Vec<Vec<u8>>,
        root: PathBuf,
        root_directory: File,
        expected_transport_root_identity: Option<crate::transport::TransportRootIdentity>,
        lock: OutputLockGuard,
    ) -> Result<Self, StoreError> {
        if receipt_key.is_empty() {
            return Err(StoreError::new(
                "DEP_STORE_RECEIPT_KEY_INVALID",
                "receipt key cannot be empty",
            ));
        }
        let directories = prepare_layout(&root_directory, &root)?;
        let transport_directory = open_pinned_cleanup_root(Path::new(&config.transport_root))?;
        validate_private_directory(
            &transport_directory,
            "DEP_STORE_TRANSIENT_PATH_MISMATCH",
            "publication transport root must remain private and resolver-owned",
        )?;
        let transport_root = pinned_directory_path(&transport_directory);
        if let Some(expected) = expected_transport_root_identity
            && directory_device_inode(&transport_directory)? != (expected.device, expected.inode)
        {
            return Err(StoreError::new(
                "DEP_STORE_TRANSIENT_PATH_MISMATCH",
                "publication transport root does not match the held transport lease",
            ));
        }
        let configuration_sha256 = crate::configuration_sha256(config)
            .map_err(|error| StoreError::new(error.code, error.message))?;
        Ok(Self {
            inner: Arc::new(StoreInner {
                root_directory,
                ambiguities_root: directories.ambiguities_root,
                ambiguities_directory: directories.ambiguities_directory,
                bundles_root: directories.bundles_root,
                bundles_directory: directories.bundles_directory,
                claims_root: directories.claims_root,
                claims_directory: directories.claims_directory,
                commits_root: directories.commits_root,
                commits_directory: directories.commits_directory,
                completions_root: directories.completions_root,
                completions_directory: directories.completions_directory,
                receipts_root: directories.receipts_root,
                receipts_directory: directories.receipts_directory,
                transport_root,
                transport_directory,
                configuration_sha256,
                generation: config.generation,
                executable_sha256: config.executable_sha256.clone(),
                secret_marker_set_sha256: config.secret_marker_set_sha256.clone(),
                receipt_key_id: config.receipt_key_id.clone(),
                receipt_key: receipt_key.to_vec(),
                marker_set,
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
        if let Some(loaded) = self.load_receipt(resolution_id)? {
            let receipt = self.admit_loaded_receipt(loaded, &admitted.request_sha256)?;
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
        self.finish_claim_directory_sync(resolution_id, sync_directory(&self.inner.claims_root))?;
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
        if !serialized_response_fits_frame(response_bytes.len(), max_frame_bytes) {
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
            Some(loaded) => {
                let receipt = self.admit_loaded_receipt(loaded, expected_request_sha256)?;
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
        self.load_receipt(resolution_id)?
            .map(|loaded| self.admit_loaded_receipt(loaded, expected_request_sha256))
            .transpose()
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

        let first_transient = fetched.first().ok_or_else(|| {
            StoreError::new(
                "DEP_STORE_ARTIFACT_SET_MISMATCH",
                "verified artifact set must identify its dedicated transport archive",
            )
        })?;
        let transient_identity = (
            first_transient.transient_root_device,
            first_transient.transient_root_inode,
        );
        let transient_name = format!(".{resolution_id}.transport");
        if fetched
            .iter()
            .any(|artifact| artifact.transient_path != Path::new(&transient_name))
        {
            return Err(StoreError::new(
                "DEP_STORE_TRANSIENT_PATH_MISMATCH",
                "verified artifact is not bound to its dedicated transport archive",
            ));
        }
        let transient_size = fetched.iter().try_fold(0_u64, |offset, artifact| {
            if (
                artifact.transient_root_device,
                artifact.transient_root_inode,
            ) != transient_identity
                || artifact.transient_offset != offset
            {
                return None;
            }
            offset.checked_add(artifact.declared_size)
        });
        if transient_identity.0 == 0 || transient_identity.1 == 0 || transient_size.is_none() {
            return Err(StoreError::new(
                "DEP_STORE_TRANSIENT_ROOT_MISMATCH",
                "verified artifacts do not share one exact contiguous transport archive",
            ));
        }
        let transient_archive = pin_private_regular_file_at(
            &self.inner.transport_directory,
            &transient_name,
            0o600,
            transient_size.expect("checked above"),
            transient_identity,
        )?;

        let stage_name = format!(".{}.{}.stage", resolution_id, Uuid::new_v4());
        let stage = self.inner.bundles_root.join(&stage_name);
        let (stage_file, artifacts) = self.stage_archive_publication(
            &stage,
            &transient_archive,
            claim,
            &plan,
            &artifact_by_node,
        )?;
        let archive_max_bytes = self
            .inner
            .max_total_artifact_bytes
            .checked_add(MAX_STATE_BYTES)
            .and_then(|value| value.checked_add(8))
            .ok_or_else(state_error)?;
        let staged_identity = verified_file_fingerprint(&stage_file, archive_max_bytes, 0o400)?;
        let bundle_path = self.bundle_path(resolution_id);
        if path_exists(&bundle_path)? {
            remove_private_file_exact(
                &self.inner.bundles_directory,
                &self.inner.bundles_root,
                &stage,
                staged_identity.device,
                staged_identity.inode,
            )?;
            return Err(StoreError::new(
                "DEP_STORE_PUBLICATION_CONFLICT",
                "resolution bundle already exists",
            ));
        }
        if let Err(error) = rename_no_replace(&stage, &bundle_path) {
            remove_private_file_exact(
                &self.inner.bundles_directory,
                &self.inner.bundles_root,
                &stage,
                staged_identity.device,
                staged_identity.inode,
            )?;
            return Err(error);
        }
        let stage_fingerprint = verified_file_fingerprint(&stage_file, archive_max_bytes, 0o400)?;
        if (stage_fingerprint.device, stage_fingerprint.inode)
            != (staged_identity.device, staged_identity.inode)
        {
            return Err(receipt_pair_changed());
        }
        if let Err(error) = revalidate_verified_file_link(
            &bundle_path,
            &stage_file,
            &stage_fingerprint,
            archive_max_bytes,
            0o400,
        ) {
            remove_private_file_exact(
                &self.inner.bundles_directory,
                &self.inner.bundles_root,
                &bundle_path,
                stage_fingerprint.device,
                stage_fingerprint.inode,
            )?;
            return Err(error);
        }
        sync_directory(&self.inner.bundles_root)?;
        if Instant::now() >= deadline || current_unix_ms()? >= claim.publication_deadline_unix_ms {
            remove_private_file_exact(
                &self.inner.bundles_directory,
                &self.inner.bundles_root,
                &bundle_path,
                stage_fingerprint.device,
                stage_fingerprint.inode,
            )?;
            sync_directory(&self.inner.bundles_root)?;
            return Err(StoreError::new(
                "DEP_STORE_PUBLICATION_LATE",
                "late bundle publication was withdrawn",
            ));
        }
        let expected_manifest = ResolutionManifest {
            schema_version: MANIFEST_SCHEMA.to_owned(),
            resolution_id,
            request_sha256: claim.request_sha256.clone(),
            graph_sha256: claim.graph_sha256.clone(),
            artifacts: artifacts.clone(),
        };
        let retained_tree_sha256 =
            match verify_resolution_archive(&bundle_path, &expected_manifest, archive_max_bytes) {
                Ok(sha256) => sha256,
                Err(error) => {
                    remove_private_file_exact(
                        &self.inner.bundles_directory,
                        &self.inner.bundles_root,
                        &bundle_path,
                        stage_fingerprint.device,
                        stage_fingerprint.inode,
                    )?;
                    sync_directory(&self.inner.bundles_root)?;
                    return Err(error);
                }
            };
        let published_at_unix_ms = current_unix_ms()?;
        if Instant::now() >= deadline || published_at_unix_ms >= claim.publication_deadline_unix_ms
        {
            remove_private_file_exact(
                &self.inner.bundles_directory,
                &self.inner.bundles_root,
                &bundle_path,
                stage_fingerprint.device,
                stage_fingerprint.inode,
            )?;
            sync_directory(&self.inner.bundles_root)?;
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
        let receipt_file = match write_new_json(&receipt_path, &receipt, 0o400) {
            Ok(file) => file,
            Err(error) => {
                self.withdraw_publication_exact(
                    &receipt_path,
                    &bundle_path,
                    None,
                    (stage_fingerprint.device, stage_fingerprint.inode),
                )?;
                return Err(error);
            }
        };
        let receipt_fingerprint = verified_file_fingerprint(&receipt_file, MAX_STATE_BYTES, 0o400)?;
        let receipt_identity = (receipt_fingerprint.device, receipt_fingerprint.inode);
        sync_directory(&self.inner.receipts_root)?;
        if Instant::now() >= deadline || current_unix_ms()? >= claim.publication_deadline_unix_ms {
            self.withdraw_publication_exact(
                &receipt_path,
                &bundle_path,
                Some(receipt_identity),
                (stage_fingerprint.device, stage_fingerprint.inode),
            )?;
            return Err(StoreError::new(
                "DEP_STORE_PUBLICATION_LATE",
                "late receipt publication was withdrawn",
            ));
        }
        self.verify_replay(&receipt, &admitted.request_sha256)?;
        self.cleanup_transient_archive(resolution_id, transient_identity)?;
        if Instant::now() >= deadline || current_unix_ms()? >= claim.publication_deadline_unix_ms {
            self.withdraw_publication_exact(
                &receipt_path,
                &bundle_path,
                Some(receipt_identity),
                (stage_fingerprint.device, stage_fingerprint.inode),
            )?;
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
        let completion_file = write_new_json(&completion_path, &completion, 0o400)?;
        let completion_fingerprint =
            verified_file_fingerprint(&completion_file, MAX_STATE_BYTES, 0o400)?;
        let completion_identity = (completion_fingerprint.device, completion_fingerprint.inode);
        if Instant::now() >= deadline || current_unix_ms()? >= claim.publication_deadline_unix_ms {
            self.remove_completion_exact(&completion_path, completion_identity)?;
            self.withdraw_publication_exact(
                &receipt_path,
                &bundle_path,
                Some(receipt_identity),
                (stage_fingerprint.device, stage_fingerprint.inode),
            )?;
            return Err(StoreError::new(
                "DEP_STORE_PUBLICATION_LATE",
                "late completion record was withdrawn while its durable claim remained",
            ));
        }
        self.record_ambiguity(claim)?;
        let mut publication_commit = PublicationCommit {
            schema_version: PUBLICATION_COMMIT_SCHEMA.to_owned(),
            claim: claim.clone(),
            receipt_identity: receipt_fingerprint,
            completion_identity: completion_fingerprint,
            hmac_sha256: String::new(),
        };
        publication_commit.hmac_sha256 =
            sign_publication_commit(&publication_commit, &self.inner.receipt_key)?;
        self.record_publication_commit(publication_commit)?;
        revalidate_publication_pair(
            &receipt_path,
            &receipt_file,
            &receipt_fingerprint,
            &completion_path,
            &completion_file,
            &completion_fingerprint,
        )?;
        remove_private_file(
            &self.inner.claims_directory,
            &self.inner.claims_root,
            &self.claim_path(resolution_id),
        )?;
        if let Err(error) = sync_directory(&self.inner.claims_root) {
            self.rollback_completion(claim, &completion_path, completion_identity)?;
            return Err(error);
        }
        if Instant::now() >= deadline || current_unix_ms()? >= claim.publication_deadline_unix_ms {
            self.rollback_completion(claim, &completion_path, completion_identity)?;
            let withdrawal = self.withdraw_publication_exact(
                &receipt_path,
                &bundle_path,
                Some(receipt_identity),
                (stage_fingerprint.device, stage_fingerprint.inode),
            );
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

    pub(crate) fn release_completed_delivery(&self, resolution_id: Uuid) {
        self.deactivate(resolution_id);
    }

    pub(crate) fn delivery_ack_pending(&self, resolution_id: Uuid) -> bool {
        self.inner
            .active
            .lock()
            .is_ok_and(|active| active.contains(&resolution_id))
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
        completion_identity: (u64, u64),
    ) -> Result<(), StoreError> {
        let ambiguity_result = self.record_ambiguity(claim);
        let claim_result = self.ensure_exact_claim(claim);
        let completion_result = self.remove_completion_exact(completion_path, completion_identity);
        match (ambiguity_result, claim_result, completion_result) {
            (Ok(()), _, _) | (_, Ok(()), _) | (_, _, Ok(())) => Ok(()),
            (Err(error), Err(_), Err(_)) => Err(error),
        }
    }

    fn record_ambiguity(&self, claim: &ResolutionClaim) -> Result<(), StoreError> {
        let _admission_lock = self.lock_existing_receipt(claim.resolution_id)?;
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
        sync_directory(&self.inner.ambiguities_root)
    }

    fn record_publication_commit(&self, commit: PublicationCommit) -> Result<(), StoreError> {
        verify_publication_commit_hmac(&commit, &self.inner.receipt_key)?;
        revalidate_store_directory_link(
            &self.inner.root_directory,
            "commits",
            &self.inner.commits_directory,
        )?;
        let path = self.commit_path(commit.claim.resolution_id);
        if !path_exists(&path)? {
            write_new_json(&path, &commit, 0o400)?;
        }
        let recorded: PublicationCommit = read_json(&path, 0o400)?;
        if recorded != commit
            || verify_publication_commit_hmac(&recorded, &self.inner.receipt_key).is_err()
        {
            return Err(StoreError::new(
                "DEP_STORE_PUBLICATION_AMBIGUOUS",
                "durable publication commit does not bind the exact retained pair",
            ));
        }
        sync_directory(&self.inner.commits_root)
    }

    fn read_publication_commit(
        &self,
        resolution_id: Uuid,
    ) -> Result<PublicationCommit, StoreError> {
        revalidate_store_directory_link(
            &self.inner.root_directory,
            "commits",
            &self.inner.commits_directory,
        )?;
        let commit: PublicationCommit = read_json(&self.commit_path(resolution_id), 0o400)?;
        verify_publication_commit_hmac(&commit, &self.inner.receipt_key)?;
        Ok(commit)
    }

    pub(crate) fn acknowledge_delivery(&self, claim: &ResolutionClaim) -> Result<(), StoreError> {
        let receipt_path = self.receipt_path(claim.resolution_id);
        let admission_lock = lock_receipt_admission(&receipt_path)?;
        let completion_path = self.completion_path(claim.resolution_id);
        let completion_file = open_verified_file(&completion_path, MAX_STATE_BYTES, 0o400)?;
        let commit = self.read_publication_commit(claim.resolution_id)?;
        if commit.schema_version != PUBLICATION_COMMIT_SCHEMA || commit.claim != *claim {
            return Err(StoreError::new(
                "DEP_STORE_PUBLICATION_AMBIGUOUS",
                "delivery acknowledgement does not match the exact publication commit",
            ));
        }
        revalidate_publication_pair(
            &receipt_path,
            &admission_lock,
            &commit.receipt_identity,
            &completion_path,
            &completion_file,
            &commit.completion_identity,
        )?;
        let path = self.ambiguity_path(claim.resolution_id);
        let recorded: ResolutionClaim = read_json(&path, 0o600)?;
        if recorded != *claim {
            return Err(StoreError::new(
                "DEP_STORE_REPLAY_SUBSTITUTION",
                "delivery acknowledgement does not match the publication claim",
            ));
        }
        remove_private_file(
            &self.inner.ambiguities_directory,
            &self.inner.ambiguities_root,
            &path,
        )?;
        sync_directory(&self.inner.ambiguities_root)
    }

    pub(crate) fn acknowledge_receipt_delivery(
        &self,
        receipt: &ResolutionReceipt,
    ) -> Result<(), StoreError> {
        self.acknowledge_delivery(&claim_from_receipt(receipt))
    }

    fn ensure_exact_claim(&self, claim: &ResolutionClaim) -> Result<(), StoreError> {
        let _admission_lock = self.lock_existing_receipt(claim.resolution_id)?;
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
        sync_directory(&self.inner.claims_root)?;
        trace_replay_namespace(claim.resolution_id, "blocker-created");
        Ok(())
    }

    fn remove_completion_exact(&self, path: &Path, identity: (u64, u64)) -> Result<(), StoreError> {
        if !path_exists(path)? {
            return Err(cleanup_exact_mismatch());
        }
        remove_private_file_exact(
            &self.inner.completions_directory,
            &self.inner.completions_root,
            path,
            identity.0,
            identity.1,
        )?;
        sync_directory(&self.inner.completions_root)
    }

    #[cfg(test)]
    fn withdraw_publication(
        &self,
        receipt_path: &Path,
        bundle_path: &Path,
    ) -> Result<(), StoreError> {
        if path_exists(receipt_path)? {
            remove_private_file(
                &self.inner.receipts_directory,
                &self.inner.receipts_root,
                receipt_path,
            )?;
            sync_directory(&self.inner.receipts_root)?;
        }
        remove_private_file(
            &self.inner.bundles_directory,
            &self.inner.bundles_root,
            bundle_path,
        )?;
        sync_directory(&self.inner.bundles_root)
    }

    fn withdraw_publication_exact(
        &self,
        receipt_path: &Path,
        bundle_path: &Path,
        receipt_identity: Option<(u64, u64)>,
        bundle_identity: (u64, u64),
    ) -> Result<(), StoreError> {
        match (path_exists(receipt_path)?, receipt_identity) {
            (true, Some(identity)) => {
                remove_private_file_exact(
                    &self.inner.receipts_directory,
                    &self.inner.receipts_root,
                    receipt_path,
                    identity.0,
                    identity.1,
                )?;
                sync_directory(&self.inner.receipts_root)?;
            }
            (true, None) => {
                return Err(StoreError::new(
                    "DEP_STORE_PUBLICATION_AMBIGUOUS",
                    "receipt publication became visible without a retained inode identity",
                ));
            }
            (false, Some(_)) => return Err(cleanup_exact_mismatch()),
            (false, None) => {}
        }
        remove_private_file_exact(
            &self.inner.bundles_directory,
            &self.inner.bundles_root,
            bundle_path,
            bundle_identity.0,
            bundle_identity.1,
        )?;
        sync_directory(&self.inner.bundles_root)
    }

    fn cleanup_transient_archive(
        &self,
        resolution_id: Uuid,
        identity: (u64, u64),
    ) -> Result<(), StoreError> {
        let archive_path = self
            .inner
            .transport_root
            .join(format!(".{resolution_id}.transport"));
        remove_private_file_exact(
            &self.inner.transport_directory,
            &self.inner.transport_root,
            &archive_path,
            identity.0,
            identity.1,
        )?;
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

    pub(crate) fn bound_root_identities(
        &self,
    ) -> Result<
        (
            crate::transport::TransportRootIdentity,
            crate::transport::TransportRootIdentity,
        ),
        StoreError,
    > {
        let (output_device, output_inode) = directory_device_inode(&self.inner.root_directory)?;
        let (device, inode) = directory_device_inode(&self.inner.transport_directory)?;
        Ok((
            crate::transport::TransportRootIdentity {
                device: output_device,
                inode: output_inode,
            },
            crate::transport::TransportRootIdentity { device, inode },
        ))
    }

    pub(crate) fn serialized_output_guard(&self) -> SerializedOutputGuard {
        SerializedOutputGuard::new(&self.inner.marker_set)
    }

    fn stage_archive_publication(
        &self,
        stage: &Path,
        transient_archive: &File,
        claim: &ResolutionClaim,
        plan: &CanonicalPlan,
        artifact_by_node: &BTreeMap<&str, &FetchedArtifact>,
    ) -> Result<(File, Vec<RetainedArtifact>), StoreError> {
        let mut retained = Vec::with_capacity(plan.nodes.len());
        let mut unique_payloads = BTreeMap::new();
        let archive_identity = directory_device_inode(transient_archive)?;
        let mut expected_offset = 0_u64;
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
            let expected_transient = PathBuf::from(format!(".{}.transport", claim.resolution_id));
            if fetched.transient_path != expected_transient {
                return Err(StoreError::new(
                    "DEP_STORE_TRANSIENT_PATH_MISMATCH",
                    "verified artifact is not bound to its dedicated transport path",
                ));
            }
            if (fetched.transient_root_device, fetched.transient_root_inode) != archive_identity
                || fetched.transient_offset != expected_offset
            {
                return Err(StoreError::new(
                    "DEP_STORE_TRANSIENT_ROOT_MISMATCH",
                    "verified artifact transport archive changed before publication",
                ));
            }
            verify_archive_slice(
                transient_archive,
                fetched.transient_offset,
                node.declared_size,
                &node.sha256,
            )?;
            let relative_path = format!("artifacts/{}", node.sha256);
            if let Some((_, existing_size)) = unique_payloads.get(&relative_path) {
                // Equal content may occur at different transport offsets. The first
                // verified occurrence is the sole durable payload.
                if *existing_size != node.declared_size {
                    return Err(state_error());
                }
            } else {
                unique_payloads.insert(
                    relative_path.clone(),
                    (fetched.transient_offset, node.declared_size),
                );
            }
            retained.push(RetainedArtifact {
                node_id: node.node_id.clone(),
                relative_path,
                size: node.declared_size,
                sha256: node.sha256.clone(),
                attestation_sha256: fetched.attestation_sha256.clone(),
                publication_generation: fetched.publication_generation,
            });
            expected_offset = expected_offset
                .checked_add(node.declared_size)
                .ok_or_else(state_error)?;
        }
        retained.sort_by(|left, right| left.node_id.cmp(&right.node_id));
        let manifest = ResolutionManifest {
            schema_version: MANIFEST_SCHEMA.to_owned(),
            resolution_id: claim.resolution_id,
            request_sha256: claim.request_sha256.clone(),
            graph_sha256: claim.graph_sha256.clone(),
            artifacts: retained.clone(),
        };
        let mut payload_offset = 0_u64;
        let mut payload_sources = Vec::with_capacity(unique_payloads.len());
        let mut entries = Vec::with_capacity(unique_payloads.len());
        for (relative_path, (source_offset, size)) in unique_payloads {
            let sha256 = relative_path
                .strip_prefix("artifacts/")
                .ok_or_else(state_error)?
                .to_owned();
            entries.push(ResolutionArchiveEntry {
                relative_path,
                payload_offset,
                size,
                sha256: sha256.clone(),
            });
            payload_sources.push((source_offset, size, sha256));
            payload_offset = payload_offset.checked_add(size).ok_or_else(state_error)?;
        }
        let header = ResolutionArchiveHeader {
            schema_version: ARCHIVE_SCHEMA.to_owned(),
            manifest,
            entries,
        };
        let header_bytes = serde_json::to_vec(&header).map_err(|_| state_error())?;
        if header_bytes.len() as u64 > MAX_STATE_BYTES {
            return Err(state_error());
        }
        let mut prefix = Vec::with_capacity(8 + header_bytes.len());
        prefix.extend_from_slice(&(header_bytes.len() as u64).to_be_bytes());
        prefix.extend_from_slice(&header_bytes);
        let mut stage_file = write_new_file(stage, &prefix)?;
        let stage_identity = directory_device_inode(&stage_file)?;
        let staging = (|| {
            for (source_offset, size, sha256) in payload_sources {
                append_archive_slice(
                    transient_archive,
                    source_offset,
                    &mut stage_file,
                    size,
                    &sha256,
                )?;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                stage_file
                    .set_permissions(std::fs::Permissions::from_mode(0o400))
                    .map_err(|_| state_error())?;
            }
            stage_file.sync_all().map_err(|_| state_error())
        })();
        if let Err(error) = staging {
            remove_private_file_exact(
                &self.inner.bundles_directory,
                &self.inner.bundles_root,
                stage,
                stage_identity.0,
                stage_identity.1,
            )?;
            return Err(error);
        }
        Ok((stage_file, retained))
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
        let expected_manifest = ResolutionManifest {
            schema_version: MANIFEST_SCHEMA.to_owned(),
            resolution_id: receipt.resolution_id,
            request_sha256: receipt.request_sha256.clone(),
            graph_sha256: receipt.plan.graph_sha256.clone(),
            artifacts: receipt.artifacts.clone(),
        };
        let archive_max_bytes = self
            .inner
            .max_total_artifact_bytes
            .checked_add(MAX_STATE_BYTES)
            .and_then(|value| value.checked_add(8))
            .ok_or_else(state_error)?;
        let retained_sha256 = verify_resolution_archive(
            &self.bundle_path(receipt.resolution_id),
            &expected_manifest,
            archive_max_bytes,
        )?;
        if retained_sha256 != receipt.retained_tree_sha256 {
            return Err(StoreError::new(
                "DEP_STORE_RETAINED_TREE_MISMATCH",
                "retained dependency archive has been substituted",
            ));
        }
        Ok(())
    }

    fn load_receipt(&self, resolution_id: Uuid) -> Result<Option<LoadedReceipt>, StoreError> {
        self.require_no_replay_blocker(resolution_id)?;
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

        // The immutable receipt inode is the per-resolution admission lock.
        // Every production path that can create or remove a durable blocker
        // takes this same lock. Holding it across receipt/tree verification and
        // the final blocker check gives replay admission one linearization
        // point instead of a check-then-verify race.
        let mut admission_lock = lock_receipt_admission(&receipt_path)?;
        self.require_no_replay_blocker(resolution_id)?;
        if !path_exists(&receipt_path)? || !path_exists(&completion_path)? {
            return Err(StoreError::new(
                "DEP_STORE_AMBIGUOUS_COMPLETION",
                "receipt and durable completion record must remain linked together",
            ));
        }
        let receipt_identity = verified_file_fingerprint(&admission_lock, MAX_STATE_BYTES, 0o400)?;
        let receipt: ResolutionReceipt = read_json_from_file(&mut admission_lock)?;
        if verified_file_fingerprint(&admission_lock, MAX_STATE_BYTES, 0o400)? != receipt_identity {
            return Err(receipt_pair_changed());
        }
        let mut completion_file = open_verified_file(&completion_path, MAX_STATE_BYTES, 0o400)?;
        let completion_identity =
            verified_file_fingerprint(&completion_file, MAX_STATE_BYTES, 0o400)?;
        let completion: ResolutionCompletion = read_json_from_file(&mut completion_file)?;
        if verified_file_fingerprint(&completion_file, MAX_STATE_BYTES, 0o400)?
            != completion_identity
        {
            return Err(receipt_pair_changed());
        }
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
        let commit = self.read_publication_commit(resolution_id)?;
        if commit.schema_version != PUBLICATION_COMMIT_SCHEMA
            || commit.claim != claim_from_receipt(&receipt)
            || commit.receipt_identity != receipt_identity
            || commit.completion_identity != completion_identity
        {
            return Err(StoreError::new(
                "DEP_STORE_AMBIGUOUS_COMPLETION",
                "permanent publication commit does not bind the exact durable pair",
            ));
        }
        Ok(Some(LoadedReceipt {
            receipt,
            admission_lock,
            receipt_identity,
            completion_file,
            completion_identity,
        }))
    }

    fn admit_loaded_receipt(
        &self,
        loaded: LoadedReceipt,
        expected_request_sha256: &str,
    ) -> Result<ResolutionReceipt, StoreError> {
        self.verify_replay(&loaded.receipt, expected_request_sha256)?;
        self.require_no_replay_blocker(loaded.receipt.resolution_id)?;
        revalidate_loaded_receipt_pair(
            &loaded,
            &self.receipt_path(loaded.receipt.resolution_id),
            &self.completion_path(loaded.receipt.resolution_id),
        )?;
        trace_replay_namespace(loaded.receipt.resolution_id, "replay-admitted");
        Ok(loaded.receipt)
    }

    fn require_no_replay_blocker(&self, resolution_id: Uuid) -> Result<(), StoreError> {
        if path_exists(&self.claim_path(resolution_id))?
            || path_exists(&self.ambiguity_path(resolution_id))?
        {
            return Err(StoreError::new(
                "DEP_STORE_AMBIGUOUS_CLAIM",
                "durable claim takes precedence over any apparent completion",
            ));
        }
        Ok(())
    }

    fn lock_existing_receipt(
        &self,
        resolution_id: Uuid,
    ) -> Result<Option<ReceiptAdmissionLock>, StoreError> {
        let path = self.receipt_path(resolution_id);
        if path_exists(&path)? {
            return lock_receipt_admission(&path).map(Some);
        }
        Ok(None)
    }

    fn claim_path(&self, resolution_id: Uuid) -> PathBuf {
        self.inner.claims_root.join(format!("{resolution_id}.json"))
    }

    fn receipt_path(&self, resolution_id: Uuid) -> PathBuf {
        self.inner
            .receipts_root
            .join(format!("{resolution_id}.json"))
    }

    fn completion_path(&self, resolution_id: Uuid) -> PathBuf {
        self.inner
            .completions_root
            .join(format!("{resolution_id}.json"))
    }

    fn commit_path(&self, resolution_id: Uuid) -> PathBuf {
        self.inner
            .commits_root
            .join(format!("{resolution_id}.json"))
    }

    fn ambiguity_path(&self, resolution_id: Uuid) -> PathBuf {
        self.inner
            .ambiguities_root
            .join(format!("{resolution_id}.json"))
    }

    fn bundle_path(&self, resolution_id: Uuid) -> PathBuf {
        self.inner
            .bundles_root
            .join(format!("{resolution_id}.bundle"))
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

fn sign_publication_commit(commit: &PublicationCommit, key: &[u8]) -> Result<String, StoreError> {
    let mut unsigned = commit.clone();
    unsigned.hmac_sha256.clear();
    let bytes = serde_json::to_vec(&unsigned).map_err(|_| state_error())?;
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| {
        StoreError::new(
            "DEP_STORE_RECEIPT_KEY_INVALID",
            "publication commit HMAC key is invalid",
        )
    })?;
    mac.update(b"mcloving-dependency-publication-commit-hmac-v1");
    mac.update(&(bytes.len() as u64).to_be_bytes());
    mac.update(&bytes);
    Ok(format!("{:x}", mac.finalize().into_bytes()))
}

fn verify_publication_commit_hmac(
    commit: &PublicationCommit,
    key: &[u8],
) -> Result<(), StoreError> {
    let signature = decode_hmac(&commit.hmac_sha256).ok_or_else(|| {
        StoreError::new(
            "DEP_STORE_PUBLICATION_AMBIGUOUS",
            "publication commit HMAC is not canonical lowercase hex",
        )
    })?;
    let mut unsigned = commit.clone();
    unsigned.hmac_sha256.clear();
    let bytes = serde_json::to_vec(&unsigned).map_err(|_| state_error())?;
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| {
        StoreError::new(
            "DEP_STORE_RECEIPT_KEY_INVALID",
            "publication commit HMAC key is invalid",
        )
    })?;
    mac.update(b"mcloving-dependency-publication-commit-hmac-v1");
    mac.update(&(bytes.len() as u64).to_be_bytes());
    mac.update(&bytes);
    mac.verify_slice(&signature).map_err(|_| {
        StoreError::new(
            "DEP_STORE_PUBLICATION_AMBIGUOUS",
            "publication commit HMAC does not verify",
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
fn acquire_output_lock(root_directory: &File, root: &Path) -> Result<OutputLock, StoreError> {
    use nix::fcntl::{Flock, FlockArg};
    use nix::unistd::Uid;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let metadata = root_directory.metadata().map_err(|_| state_error())?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != Uid::effective().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(StoreError::new(
            "DEP_STORE_ROOT_POLICY_DENIED",
            "output root must be canonical, private, resolver-owned, and non-symlink",
        ));
    }
    let sentinel = open_output_lock(&root.join(LOCK_FILE))?;
    sentinel.sync_all().map_err(|_| state_error())?;
    sync_directory(root)?;
    let lock_target = root_directory.try_clone().map_err(|_| state_error())?;
    Flock::lock(lock_target, FlockArg::LockExclusiveNonblock).map_err(|_| {
        StoreError::new(
            "DEP_STORE_ROOT_LOCKED",
            "another resolver owns the output root",
        )
    })
}

#[cfg(target_os = "linux")]
fn open_output_lock(path: &Path) -> Result<File, StoreError> {
    use nix::fcntl::OFlag;
    use std::io::ErrorKind;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    let file = match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags((OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits())
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            // Inspect the directory entry without invoking a FIFO or device
            // driver's potentially blocking read-write open operation.
            let inspection = OpenOptions::new()
                .read(true)
                .custom_flags((OFlag::O_PATH | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW).bits())
                .open(path)
                .map_err(|_| state_error())?;
            trace_output_lock_open("path-inspected");
            let inspected = inspection.metadata().map_err(|_| state_error())?;
            if !private_output_lock_metadata(&inspected) {
                return Err(state_error());
            }

            // Reopen the exact inspected inode, retaining O_NONBLOCK as a
            // second boundary, rather than reopening the mutable pathname.
            trace_output_lock_open("data-open");
            let pinned_path = format!("/proc/self/fd/{}", inspection.as_raw_fd());
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags((OFlag::O_CLOEXEC | OFlag::O_NONBLOCK).bits())
                .open(pinned_path)
                .map_err(|_| state_error())?;
            let opened = file.metadata().map_err(|_| state_error())?;
            if !private_output_lock_metadata(&opened)
                || opened.dev() != inspected.dev()
                || opened.ino() != inspected.ino()
            {
                return Err(state_error());
            }
            file
        }
        Err(_) => return Err(state_error()),
    };

    let opened = file.metadata().map_err(|_| state_error())?;
    let linked = std::fs::symlink_metadata(path).map_err(|_| state_error())?;
    if !private_output_lock_metadata(&opened)
        || !private_output_lock_metadata(&linked)
        || opened.dev() != linked.dev()
        || opened.ino() != linked.ino()
    {
        return Err(state_error());
    }
    Ok(file)
}

#[cfg(test)]
thread_local! {
    static OUTPUT_LOCK_OPEN_TRACE: std::cell::RefCell<Vec<&'static str>> = const {
        std::cell::RefCell::new(Vec::new())
    };
}

#[cfg(all(test, target_os = "linux"))]
thread_local! {
    static RETAINED_TREE_PRE_SCAN_INJECTION_TEST_HOOK: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
}

#[cfg(test)]
thread_local! {
    static VERIFIED_FILE_OPEN_TRACE: std::cell::RefCell<Vec<(PathBuf, &'static str)>> = const {
        std::cell::RefCell::new(Vec::new())
    };
}

#[cfg(test)]
static REPLAY_NAMESPACE_TRACE: std::sync::LazyLock<Mutex<Vec<(Uuid, &'static str)>>> =
    std::sync::LazyLock::new(|| Mutex::new(Vec::new()));

#[cfg(test)]
type ReceiptLockTestHook = Option<(PathBuf, std::sync::mpsc::Sender<&'static str>)>;

#[cfg(test)]
static RECEIPT_LOCK_TEST_HOOK: std::sync::LazyLock<Mutex<ReceiptLockTestHook>> =
    std::sync::LazyLock::new(|| Mutex::new(None));

#[cfg(test)]
thread_local! {
    static CLEANUP_SWAP_TEST_HOOK: std::cell::RefCell<Option<(PathBuf, PathBuf, PathBuf)>> = const {
        std::cell::RefCell::new(None)
    };
    static CLEANUP_PRE_INSPECTION_SWAP_TEST_HOOK: std::cell::RefCell<Option<(PathBuf, PathBuf, PathBuf)>> = const {
        std::cell::RefCell::new(None)
    };
    static CLEANUP_FINAL_SWAP_TEST_HOOK: std::cell::RefCell<Option<(PathBuf, PathBuf, PathBuf)>> = const {
        std::cell::RefCell::new(None)
    };
    static CLEANUP_PRE_UNLINK_SWAP_TEST_HOOK: std::cell::RefCell<Option<(PathBuf, PathBuf, PathBuf)>> = const {
        std::cell::RefCell::new(None)
    };
    static RETAINED_TREE_SWAP_TEST_HOOK: std::cell::RefCell<Option<(PathBuf, PathBuf)>> = const {
        std::cell::RefCell::new(None)
    };
}

#[cfg(test)]
fn trace_output_lock_open(event: &'static str) {
    OUTPUT_LOCK_OPEN_TRACE.with(|trace| trace.borrow_mut().push(event));
}

#[cfg(not(test))]
fn trace_output_lock_open(_event: &'static str) {}

#[cfg(test)]
fn trace_verified_file_open(path: &Path, event: &'static str) {
    VERIFIED_FILE_OPEN_TRACE.with(|trace| {
        trace.borrow_mut().push((path.to_path_buf(), event));
    });
}

#[cfg(not(test))]
fn trace_verified_file_open(_path: &Path, _event: &'static str) {}

#[cfg(test)]
fn trace_replay_namespace(resolution_id: Uuid, event: &'static str) {
    if let Ok(mut trace) = REPLAY_NAMESPACE_TRACE.lock() {
        trace.push((resolution_id, event));
    }
}

#[cfg(not(test))]
fn trace_replay_namespace(_resolution_id: Uuid, _event: &'static str) {}

#[cfg(test)]
fn trace_receipt_admission_lock(path: &Path, event: &'static str) {
    if let Ok(mut hook) = RECEIPT_LOCK_TEST_HOOK.lock()
        && let Some((target, sender)) = hook.as_ref()
        && target == path
    {
        let _ = sender.send(event);
        if event == "acquired" {
            *hook = None;
        }
    }
}

#[cfg(not(test))]
fn trace_receipt_admission_lock(_path: &Path, _event: &'static str) {}

#[cfg(test)]
fn run_cleanup_swap_hook(path: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::symlink;

    let swap = CLEANUP_SWAP_TEST_HOOK.with(|hook| {
        let mut hook = hook.borrow_mut();
        if hook.as_ref().is_some_and(|(target, _, _)| target == path) {
            return hook.take();
        }
        None
    });
    if let Some((target, replacement, backup)) = swap {
        std::fs::rename(&target, backup).map_err(|_| state_error())?;
        symlink(replacement, target).map_err(|_| state_error())?;
    }
    Ok(())
}

#[cfg(test)]
fn run_cleanup_pre_inspection_swap_hook(path: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::symlink;

    let swap = CLEANUP_PRE_INSPECTION_SWAP_TEST_HOOK.with(|hook| {
        let mut hook = hook.borrow_mut();
        if hook.as_ref().is_some_and(|(target, _, _)| target == path) {
            return hook.take();
        }
        None
    });
    if let Some((target, replacement, backup)) = swap {
        std::fs::rename(&target, backup).map_err(|_| state_error())?;
        symlink(replacement, target).map_err(|_| state_error())?;
    }
    Ok(())
}

#[cfg(test)]
fn run_cleanup_final_swap_hook(path: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::symlink;

    let swap = CLEANUP_FINAL_SWAP_TEST_HOOK.with(|hook| {
        let mut hook = hook.borrow_mut();
        if hook.as_ref().is_some_and(|(target, _, _)| target == path) {
            return hook.take();
        }
        None
    });
    if let Some((target, replacement, backup)) = swap {
        std::fs::rename(&target, backup).map_err(|_| state_error())?;
        symlink(replacement, target).map_err(|_| state_error())?;
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
fn run_cleanup_pre_unlink_swap_hook<Fd: std::os::fd::AsFd>(
    parent: &Fd,
    name: &std::ffi::CStr,
    display_path: &Path,
) -> Result<(), StoreError> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::symlink;

    let swap = CLEANUP_PRE_UNLINK_SWAP_TEST_HOOK.with(|hook| {
        let mut hook = hook.borrow_mut();
        if hook
            .as_ref()
            .is_some_and(|(target, _, _)| target == display_path)
        {
            return hook.take();
        }
        None
    });
    if let Some((_, replacement, backup)) = swap {
        let selected = PathBuf::from(format!("/proc/self/fd/{}", parent.as_fd().as_raw_fd()))
            .join(std::ffi::OsStr::from_bytes(name.to_bytes()));
        std::fs::rename(&selected, backup).map_err(|_| state_error())?;
        if replacement.is_file() {
            std::fs::hard_link(replacement, selected).map_err(|_| state_error())?;
        } else {
            symlink(replacement, selected).map_err(|_| state_error())?;
        }
    }
    Ok(())
}

#[cfg(not(test))]
fn run_cleanup_swap_hook(_path: &Path) -> Result<(), StoreError> {
    Ok(())
}

#[cfg(not(test))]
fn run_cleanup_pre_inspection_swap_hook(_path: &Path) -> Result<(), StoreError> {
    Ok(())
}

#[cfg(not(test))]
fn run_cleanup_final_swap_hook(_path: &Path) -> Result<(), StoreError> {
    Ok(())
}

#[cfg(any(not(test), not(target_os = "linux")))]
fn run_cleanup_pre_unlink_swap_hook<Fd: std::os::fd::AsFd>(
    _parent: &Fd,
    _name: &std::ffi::CStr,
    _display_path: &Path,
) -> Result<(), StoreError> {
    Ok(())
}

#[cfg(test)]
fn run_retained_tree_swap_hook() -> Result<(), StoreError> {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let swap = RETAINED_TREE_SWAP_TEST_HOOK.with(|hook| hook.borrow_mut().take());
    if let Some((target, backup)) = swap {
        let parent = target.parent().expect("retained swap parent");
        let original_mode = std::fs::metadata(parent)
            .expect("retained swap parent metadata")
            .permissions()
            .mode()
            & 0o777;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .expect("make retained swap parent writable");
        std::fs::rename(&target, &backup).expect("move traversed retained entry");
        symlink(&backup, &target).expect("relink traversed retained entry");
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(original_mode))
            .expect("reseal retained swap parent");
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
fn run_retained_tree_pre_scan_injection_hook(bundle: &File) -> Result<(), StoreError> {
    use nix::sys::stat::{Mode, fchmod};
    use std::os::fd::AsRawFd as _;

    if !RETAINED_TREE_PRE_SCAN_INJECTION_TEST_HOOK.with(|hook| hook.replace(false)) {
        return Ok(());
    }
    fchmod(bundle, Mode::from_bits_truncate(0o600)).map_err(|_| retained_tree_mismatch())?;
    let pinned_path = format!("/proc/self/fd/{}", bundle.as_raw_fd());
    let mut writable = OpenOptions::new()
        .append(true)
        .open(pinned_path)
        .map_err(|_| retained_tree_mismatch())?;
    writable
        .write_all(b"unmanifested archive bytes")
        .map_err(|_| retained_tree_mismatch())?;
    writable.sync_all().map_err(|_| retained_tree_mismatch())?;
    fchmod(bundle, Mode::from_bits_truncate(0o400)).map_err(|_| retained_tree_mismatch())
}

#[cfg(any(not(test), not(target_os = "linux")))]
fn run_retained_tree_pre_scan_injection_hook(_bundle: &File) -> Result<(), StoreError> {
    Ok(())
}

#[cfg(not(test))]
fn run_retained_tree_swap_hook() -> Result<(), StoreError> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn private_output_lock_metadata(metadata: &std::fs::Metadata) -> bool {
    use nix::unistd::Uid;
    use std::os::unix::fs::MetadataExt as _;

    metadata.is_file()
        && metadata.uid() == Uid::effective().as_raw()
        && metadata.nlink() == 1
        && metadata.mode() & 0o777 == 0o600
}

#[cfg(target_os = "linux")]
fn verify_inherited_output_lock(root_directory: &File) -> Result<File, StoreError> {
    use nix::fcntl::{Flock, FlockArg};
    use nix::unistd::Uid;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let inherited = nix::unistd::dup(std::io::stderr())
        .map(File::from)
        .map_err(|_| state_error())?;
    let inherited_metadata = inherited.metadata().map_err(|_| state_error())?;
    let root_metadata = root_directory.metadata().map_err(|_| state_error())?;
    if !inherited_metadata.is_dir()
        || !root_metadata.is_dir()
        || inherited_metadata.uid() != Uid::effective().as_raw()
        || root_metadata.uid() != Uid::effective().as_raw()
        || inherited_metadata.permissions().mode() & 0o777 != 0o700
        || root_metadata.permissions().mode() & 0o777 != 0o700
        || inherited_metadata.dev() != root_metadata.dev()
        || inherited_metadata.ino() != root_metadata.ino()
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
fn verify_inherited_output_lock(_root_directory: &File) -> Result<File, StoreError> {
    Err(StoreError::new(
        "DEP_STORE_PLATFORM_UNSUPPORTED",
        "publication worker parent-lock proof requires Linux flock semantics",
    ))
}

#[cfg(not(target_os = "linux"))]
fn acquire_output_lock(_root_directory: &File, _root: &Path) -> Result<OutputLock, StoreError> {
    Err(StoreError::new(
        "DEP_STORE_PLATFORM_UNSUPPORTED",
        "durable dependency publication requires Linux file semantics",
    ))
}

fn prepare_layout(root_directory: &File, root: &Path) -> Result<StoreDirectories, StoreError> {
    let expected = BTreeSet::from([
        LOCK_FILE.to_owned(),
        "ambiguities".to_owned(),
        "bundles".to_owned(),
        "claims".to_owned(),
        "commits".to_owned(),
        "completions".to_owned(),
        "receipts".to_owned(),
    ]);
    for name in [
        "ambiguities",
        "bundles",
        "claims",
        "commits",
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
    let ambiguities_directory = open_store_directory(root_directory, "ambiguities")?;
    let bundles_directory = open_store_directory(root_directory, "bundles")?;
    let claims_directory = open_store_directory(root_directory, "claims")?;
    let commits_directory = open_store_directory(root_directory, "commits")?;
    let completions_directory = open_store_directory(root_directory, "completions")?;
    let receipts_directory = open_store_directory(root_directory, "receipts")?;
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
    root_directory.sync_all().map_err(|_| state_error())?;
    for (name, directory) in [
        ("ambiguities", &ambiguities_directory),
        ("bundles", &bundles_directory),
        ("claims", &claims_directory),
        ("commits", &commits_directory),
        ("completions", &completions_directory),
        ("receipts", &receipts_directory),
    ] {
        revalidate_store_directory_link(root_directory, name, directory)?;
    }
    Ok(StoreDirectories {
        ambiguities_root: pinned_directory_path(&ambiguities_directory),
        ambiguities_directory,
        bundles_root: pinned_directory_path(&bundles_directory),
        bundles_directory,
        claims_root: pinned_directory_path(&claims_directory),
        claims_directory,
        commits_root: pinned_directory_path(&commits_directory),
        commits_directory,
        completions_root: pinned_directory_path(&completions_directory),
        completions_directory,
        receipts_root: pinned_directory_path(&receipts_directory),
        receipts_directory,
    })
}

#[cfg(target_os = "linux")]
fn open_store_directory(root_directory: &File, name: &str) -> Result<File, StoreError> {
    use nix::fcntl::{OFlag, openat};
    use nix::sys::stat::Mode;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let directory = File::from(
        openat(
            root_directory,
            name,
            OFlag::O_RDONLY
                | OFlag::O_DIRECTORY
                | OFlag::O_NOFOLLOW
                | OFlag::O_CLOEXEC
                | OFlag::O_NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| state_error())?,
    );
    let metadata = directory.metadata().map_err(|_| state_error())?;
    if !metadata.is_dir()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(state_error());
    }
    Ok(directory)
}

#[cfg(not(target_os = "linux"))]
fn open_store_directory(_root_directory: &File, _name: &str) -> Result<File, StoreError> {
    Err(StoreError::new(
        "DEP_STORE_PLATFORM_UNSUPPORTED",
        "pinned store directories require Linux file semantics",
    ))
}

#[cfg(target_os = "linux")]
fn revalidate_store_directory_link(
    root_directory: &File,
    name: &str,
    expected: &File,
) -> Result<(), StoreError> {
    use nix::fcntl::{OFlag, openat};
    use nix::sys::stat::Mode;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let linked = File::from(
        openat(
            root_directory,
            name,
            OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| state_error())?,
    );
    let linked = linked.metadata().map_err(|_| state_error())?;
    let expected = expected.metadata().map_err(|_| state_error())?;
    if !linked.is_dir()
        || linked.uid() != nix::unistd::Uid::effective().as_raw()
        || linked.permissions().mode() & 0o777 != 0o700
        || linked.dev() != expected.dev()
        || linked.ino() != expected.ino()
    {
        return Err(StoreError::new(
            "DEP_STORE_FIXED_DIRECTORY_AMBIGUOUS",
            "fixed output directory link changed after it was pinned",
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn revalidate_store_directory_link(
    _root_directory: &File,
    _name: &str,
    _expected: &File,
) -> Result<(), StoreError> {
    Err(state_error())
}

fn retained_archive_mismatch() -> StoreError {
    StoreError::new(
        "DEP_STORE_RETAINED_TREE_MISMATCH",
        "retained dependency archive is malformed, incomplete, or has been substituted",
    )
}

fn verify_resolution_archive(
    path: &Path,
    expected_manifest: &ResolutionManifest,
    max_bytes: u64,
) -> Result<String, StoreError> {
    let mut archive =
        open_verified_file(path, max_bytes, 0o400).map_err(|_| retained_archive_mismatch())?;
    let fingerprint = verified_file_fingerprint(&archive, max_bytes, 0o400)
        .map_err(|_| retained_archive_mismatch())?;
    let archive_size = fingerprint.size;
    run_retained_tree_pre_scan_injection_hook(&archive)?;
    let mut length_bytes = [0_u8; 8];
    archive
        .read_exact(&mut length_bytes)
        .map_err(|_| retained_archive_mismatch())?;
    let header_length = u64::from_be_bytes(length_bytes);
    if header_length == 0 || header_length > MAX_STATE_BYTES {
        return Err(retained_archive_mismatch());
    }
    let header_size = usize::try_from(header_length).map_err(|_| retained_archive_mismatch())?;
    let mut header_bytes = vec![0_u8; header_size];
    archive
        .read_exact(&mut header_bytes)
        .map_err(|_| retained_archive_mismatch())?;
    let header: ResolutionArchiveHeader =
        crate::strict_json::from_slice(&header_bytes).map_err(|_| retained_archive_mismatch())?;
    if header.schema_version != ARCHIVE_SCHEMA || header.manifest != *expected_manifest {
        return Err(StoreError::new(
            "DEP_STORE_MANIFEST_MISMATCH",
            "retained archive manifest does not match the exact publication receipt",
        ));
    }

    let mut unique_artifacts = BTreeMap::<String, (u64, String)>::new();
    for artifact in &expected_manifest.artifacts {
        let expected_path = format!("artifacts/{}", artifact.sha256);
        if artifact.relative_path != expected_path {
            return Err(retained_archive_mismatch());
        }
        if unique_artifacts
            .insert(
                artifact.relative_path.clone(),
                (artifact.size, artifact.sha256.clone()),
            )
            .is_some_and(|existing| existing != (artifact.size, artifact.sha256.clone()))
        {
            return Err(retained_archive_mismatch());
        }
    }
    let mut expected_offset = 0_u64;
    let mut expected_entries = Vec::with_capacity(unique_artifacts.len());
    for (relative_path, (size, sha256)) in unique_artifacts {
        expected_entries.push(ResolutionArchiveEntry {
            relative_path,
            payload_offset: expected_offset,
            size,
            sha256,
        });
        expected_offset = expected_offset
            .checked_add(size)
            .ok_or_else(retained_archive_mismatch)?;
    }
    if header.entries != expected_entries {
        return Err(retained_archive_mismatch());
    }
    let payload_start = 8_u64
        .checked_add(header_length)
        .ok_or_else(retained_archive_mismatch)?;
    let expected_size = payload_start
        .checked_add(expected_offset)
        .ok_or_else(retained_archive_mismatch)?;
    if archive_size != expected_size {
        return Err(retained_archive_mismatch());
    }
    for entry in &header.entries {
        let offset = payload_start
            .checked_add(entry.payload_offset)
            .ok_or_else(retained_archive_mismatch)?;
        verify_archive_slice(&archive, offset, entry.size, &entry.sha256)
            .map_err(|_| retained_archive_mismatch())?;
    }

    archive
        .seek(SeekFrom::Start(0))
        .map_err(|_| retained_archive_mismatch())?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 65_536];
    loop {
        let read = archive
            .read(&mut buffer)
            .map_err(|_| retained_archive_mismatch())?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(retained_archive_mismatch)?;
        if total > archive_size {
            return Err(retained_archive_mismatch());
        }
        hasher.update(&buffer[..read]);
    }
    run_retained_tree_swap_hook()?;
    if total != archive_size
        || verified_file_fingerprint(&archive, max_bytes, 0o400)
            .map_err(|_| retained_archive_mismatch())?
            != fingerprint
    {
        return Err(retained_archive_mismatch());
    }
    revalidate_verified_file_link(path, &archive, &fingerprint, max_bytes, 0o400)
        .map_err(|_| retained_archive_mismatch())?;
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(all(target_os = "linux", test))]
fn retained_tree_evidence_with_limits(
    output_directory: &File,
    bundles_directory: &File,
    resolution_id: &str,
    max_file_bytes: u64,
    max_total_bytes: u64,
    limits: RetainedTreeLimits,
) -> Result<RetainedTreeEvidence, StoreError> {
    use nix::fcntl::{OFlag, openat};
    use nix::sys::stat::Mode;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::MetadataExt as _;

    if Path::new(resolution_id).components().count() != 1
        || !matches!(
            Path::new(resolution_id).components().next(),
            Some(Component::Normal(_))
        )
    {
        return Err(state_error());
    }
    let bundles_metadata = bundles_directory
        .metadata()
        .map_err(|_| retained_tree_mismatch())?;
    validate_retained_directory_metadata(&bundles_metadata, 0o700)?;
    let mut links = vec![RetainedTreeLink {
        parent: Arc::new(output_directory.try_clone().map_err(|_| state_error())?),
        name: std::ffi::CString::new("bundles").expect("fixed store directory name"),
        identity: retained_link_identity(&bundles_metadata),
        directory: true,
    }];
    revalidate_retained_link(&links[0])?;
    let bundle_name =
        std::ffi::CString::new(resolution_id.as_bytes()).map_err(|_| state_error())?;
    let bundle_inspection = File::from(
        openat(
            bundles_directory,
            bundle_name.as_c_str(),
            OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| retained_tree_mismatch())?,
    );
    let bundle_inspected = bundle_inspection
        .metadata()
        .map_err(|_| retained_tree_mismatch())?;
    validate_retained_directory_metadata(&bundle_inspected, 0o500)?;
    let bundle_directory = Arc::new(File::from(
        openat(
            bundles_directory,
            bundle_name.as_c_str(),
            OFlag::O_RDONLY
                | OFlag::O_DIRECTORY
                | OFlag::O_NOFOLLOW
                | OFlag::O_CLOEXEC
                | OFlag::O_NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| retained_tree_mismatch())?,
    ));
    let bundle_opened = bundle_directory
        .metadata()
        .map_err(|_| retained_tree_mismatch())?;
    if bundle_opened.dev() != bundle_inspected.dev()
        || bundle_opened.ino() != bundle_inspected.ino()
    {
        return Err(retained_tree_mismatch());
    }
    run_retained_tree_pre_scan_injection_hook(&bundle_directory)?;
    let bundle_inspected = bundle_inspection
        .metadata()
        .map_err(|_| retained_tree_mismatch())?;
    validate_retained_directory_metadata(&bundle_inspected, 0o500)?;
    let bundle_opened = bundle_directory
        .metadata()
        .map_err(|_| retained_tree_mismatch())?;
    if bundle_opened.dev() != bundle_inspected.dev()
        || bundle_opened.ino() != bundle_inspected.ino()
    {
        return Err(retained_tree_mismatch());
    }

    let mut files = Vec::new();
    let mut directories = vec![
        directory_record_from_file("@output-root", output_directory, 0o700)?,
        directory_record_from_file("@bundles-root", bundles_directory, 0o700)?,
    ];
    let mut total = 0_u64;
    let records = RetainedTreeRecords {
        total: &mut total,
        directories: &mut directories,
        files: &mut files,
    };
    let bundles_parent = Arc::new(bundles_directory.try_clone().map_err(|_| state_error())?);
    let mut pending = VecDeque::from([PendingRetainedDirectory {
        directory: bundle_directory,
        relative: ".".to_owned(),
        depth: 0,
        parent: bundles_parent,
        name: bundle_name,
        identity: retained_link_identity(&bundle_inspected),
    }]);
    let mut entry_count = 0_usize;
    admit_retained_tree_entry(&mut entry_count, limits.max_entries)?;
    let mut manifest_bytes = None;
    let mut retained_directories = BTreeSet::new();

    while let Some(pending_directory) = pending.pop_front() {
        if !retained_directories.insert(pending_directory.relative.clone()) {
            return Err(retained_tree_mismatch());
        }
        records.directories.push(directory_record_from_file(
            &pending_directory.relative,
            &pending_directory.directory,
            0o500,
        )?);
        links.push(RetainedTreeLink {
            parent: Arc::clone(&pending_directory.parent),
            name: pending_directory.name,
            identity: pending_directory.identity,
            directory: true,
        });

        let directory_path = pinned_directory_path(&pending_directory.directory);
        for entry in std::fs::read_dir(&directory_path).map_err(|_| retained_tree_mismatch())? {
            let entry = entry.map_err(|_| retained_tree_mismatch())?;
            admit_retained_tree_entry(&mut entry_count, limits.max_entries)?;
            let child_depth = pending_directory
                .depth
                .checked_add(1)
                .ok_or_else(retained_tree_bound_error)?;
            if child_depth > limits.max_depth {
                return Err(retained_tree_bound_error());
            }
            let child_os_name = entry.file_name();
            let child_name = std::ffi::CString::new(child_os_name.as_bytes())
                .map_err(|_| retained_tree_mismatch())?;
            let child_text = child_os_name.to_str().ok_or_else(retained_tree_mismatch)?;
            let relative = if pending_directory.relative == "." {
                child_text.to_owned()
            } else {
                format!("{}/{}", pending_directory.relative, child_text)
            };
            let inspection = File::from(
                openat(
                    &*pending_directory.directory,
                    child_name.as_c_str(),
                    OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| retained_tree_mismatch())?,
            );
            let inspected = inspection
                .metadata()
                .map_err(|_| retained_tree_mismatch())?;
            if inspected.is_dir() {
                validate_retained_directory_metadata(&inspected, 0o500)?;
                let directory = Arc::new(File::from(
                    openat(
                        &*pending_directory.directory,
                        child_name.as_c_str(),
                        OFlag::O_RDONLY
                            | OFlag::O_DIRECTORY
                            | OFlag::O_NOFOLLOW
                            | OFlag::O_CLOEXEC
                            | OFlag::O_NONBLOCK,
                        Mode::empty(),
                    )
                    .map_err(|_| retained_tree_mismatch())?,
                ));
                let opened = directory.metadata().map_err(|_| retained_tree_mismatch())?;
                if opened.dev() != inspected.dev() || opened.ino() != inspected.ino() {
                    return Err(retained_tree_mismatch());
                }
                pending.push_back(PendingRetainedDirectory {
                    directory,
                    relative,
                    depth: child_depth,
                    parent: Arc::clone(&pending_directory.directory),
                    name: child_name,
                    identity: retained_link_identity(&inspected),
                });
            } else if inspected.is_file() {
                let mut file = open_verified_inspected_file(
                    &pending_directory.directory,
                    child_name.as_c_str(),
                    &inspection,
                    max_file_bytes,
                    0o400,
                )?;
                let mut bytes = Vec::new();
                let mut hasher = Sha256::new();
                let mut size = 0_u64;
                let mut buffer = [0_u8; 65_536];
                loop {
                    let read = file.read(&mut buffer).map_err(|_| state_error())?;
                    if read == 0 {
                        break;
                    }
                    size = size.checked_add(read as u64).ok_or_else(state_error)?;
                    if size > max_file_bytes {
                        return Err(retained_tree_mismatch());
                    }
                    hasher.update(&buffer[..read]);
                    if relative == "manifest.json" {
                        if size > MAX_STATE_BYTES {
                            return Err(retained_tree_mismatch());
                        }
                        bytes.extend_from_slice(&buffer[..read]);
                    }
                }
                *records.total = records.total.checked_add(size).ok_or_else(state_error)?;
                if *records.total > max_total_bytes {
                    return Err(StoreError::new(
                        "DEP_STORE_RETAINED_TREE_MISMATCH",
                        "retained dependency tree exceeds its signed total bound",
                    ));
                }
                let digest = format!("{:x}", hasher.finalize());
                records.files.push((relative.clone(), 0o400, size, digest));
                if relative == "manifest.json" {
                    manifest_bytes = Some(bytes);
                }
                links.push(RetainedTreeLink {
                    parent: Arc::clone(&pending_directory.directory),
                    name: child_name,
                    identity: retained_link_identity(&inspected),
                    directory: false,
                });
            } else {
                return Err(StoreError::new(
                    "DEP_STORE_RETAINED_TREE_MISMATCH",
                    "retained bundle contains a symlink or unsupported file type",
                ));
            }
        }
    }

    run_retained_tree_swap_hook()?;
    for link in links.iter().rev() {
        revalidate_retained_link(link)?;
    }
    let manifest_bytes = manifest_bytes.ok_or_else(|| {
        StoreError::new(
            "DEP_STORE_MANIFEST_MISMATCH",
            "retained dependency bundle has no manifest",
        )
    })?;
    files.sort_by(|left, right| left.0.cmp(&right.0));
    let file_evidence = files
        .iter()
        .map(|(relative, _, size, digest)| (relative.clone(), (*size, digest.clone())))
        .collect();
    directories.sort_by(|left, right| left.0.cmp(&right.0));
    let mut hasher = Sha256::new();
    update_segment(&mut hasher, b"mcloving-dependency-retained-tree-v1");
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
    Ok(RetainedTreeEvidence {
        sha256: format!("{:x}", hasher.finalize()),
        directories: retained_directories,
        files: file_evidence,
        manifest_bytes,
    })
}

#[cfg(all(target_os = "linux", test))]
fn revalidate_retained_link(link: &RetainedTreeLink) -> Result<(), StoreError> {
    use nix::fcntl::{OFlag, openat};
    use nix::sys::stat::Mode;

    let linked = File::from(
        openat(
            &*link.parent,
            link.name.as_c_str(),
            OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| retained_tree_mismatch())?,
    );
    let metadata = linked.metadata().map_err(|_| retained_tree_mismatch())?;
    if retained_link_identity(&metadata) != link.identity
        || metadata.is_dir() != link.directory
        || metadata.is_file() == link.directory
    {
        return Err(retained_tree_mismatch());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn retained_link_identity(metadata: &std::fs::Metadata) -> RetainedLinkIdentity {
    use std::os::unix::fs::MetadataExt as _;

    RetainedLinkIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
        uid: metadata.uid(),
        links: metadata.nlink(),
        size: metadata.size(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

#[cfg(all(target_os = "linux", test))]
fn validate_retained_directory_metadata(
    metadata: &std::fs::Metadata,
    expected_mode: u32,
) -> Result<(), StoreError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    if !metadata.is_dir()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.permissions().mode() & 0o777 != expected_mode
    {
        return Err(StoreError::new(
            "DEP_STORE_DIRECTORY_POLICY_DENIED",
            "retained ancestor owner, mode, or type violates policy",
        ));
    }
    Ok(())
}

#[cfg(all(target_os = "linux", test))]
fn directory_record_from_file(
    label: &str,
    directory: &File,
    expected_mode: u32,
) -> Result<(String, u32, u32, u64, u64), StoreError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = directory.metadata().map_err(|_| state_error())?;
    validate_retained_directory_metadata(&metadata, expected_mode)?;
    Ok((
        label.to_owned(),
        expected_mode,
        metadata.uid(),
        metadata.dev(),
        metadata.ino(),
    ))
}

#[cfg(test)]
fn retained_tree_mismatch() -> StoreError {
    StoreError::new(
        "DEP_STORE_RETAINED_TREE_MISMATCH",
        "retained dependency bundle changed during descriptor-backed verification",
    )
}

#[cfg(test)]
fn admit_retained_tree_entry(count: &mut usize, max_entries: usize) -> Result<(), StoreError> {
    *count = count.checked_add(1).ok_or_else(retained_tree_bound_error)?;
    if *count > max_entries {
        return Err(retained_tree_bound_error());
    }
    Ok(())
}

#[cfg(test)]
fn retained_tree_bound_error() -> StoreError {
    StoreError::new(
        "DEP_STORE_RETAINED_TREE_MISMATCH",
        "retained dependency tree exceeds its certified entry or depth bound",
    )
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

#[cfg(target_os = "linux")]
fn open_verified_file(path: &Path, max_bytes: u64, mode: u32) -> Result<File, StoreError> {
    use nix::fcntl::OFlag;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    let inspection = OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_PATH | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW).bits())
        .open(path)
        .map_err(|_| state_error())?;
    trace_verified_file_open(path, "path-inspected");
    let inspected = inspection.metadata().map_err(|_| state_error())?;
    if !verified_file_metadata(&inspected, max_bytes, mode) {
        return Err(file_policy_error());
    }

    let pinned_path = format!("/proc/self/fd/{}", inspection.as_raw_fd());
    trace_verified_file_open(path, "data-open");
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_CLOEXEC | OFlag::O_NONBLOCK).bits())
        .open(pinned_path)
        .map_err(|_| state_error())?;
    let opened = file.metadata().map_err(|_| state_error())?;
    let linked = std::fs::symlink_metadata(path).map_err(|_| state_error())?;
    if !verified_file_metadata(&opened, max_bytes, mode)
        || !verified_file_metadata(&linked, max_bytes, mode)
        || opened.dev() != inspected.dev()
        || opened.ino() != inspected.ino()
        || linked.dev() != inspected.dev()
        || linked.ino() != inspected.ino()
    {
        return Err(file_policy_error());
    }
    Ok(file)
}

#[cfg(all(target_os = "linux", test))]
fn open_verified_inspected_file(
    parent: &File,
    name: &std::ffi::CStr,
    inspection: &File,
    max_bytes: u64,
    mode: u32,
) -> Result<File, StoreError> {
    use nix::fcntl::{OFlag, openat};
    use nix::sys::stat::Mode;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    let inspected = inspection.metadata().map_err(|_| state_error())?;
    if !verified_file_metadata(&inspected, max_bytes, mode) {
        return Err(file_policy_error());
    }
    let pinned_path = format!("/proc/self/fd/{}", inspection.as_raw_fd());
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_CLOEXEC | OFlag::O_NONBLOCK).bits())
        .open(pinned_path)
        .map_err(|_| state_error())?;
    let opened = file.metadata().map_err(|_| state_error())?;
    let linked = File::from(
        openat(
            parent,
            name,
            OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| state_error())?,
    );
    let linked = linked.metadata().map_err(|_| state_error())?;
    if !verified_file_metadata(&opened, max_bytes, mode)
        || !verified_file_metadata(&linked, max_bytes, mode)
        || opened.dev() != inspected.dev()
        || opened.ino() != inspected.ino()
        || linked.dev() != inspected.dev()
        || linked.ino() != inspected.ino()
    {
        return Err(file_policy_error());
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
fn lock_receipt_admission(path: &Path) -> Result<ReceiptAdmissionLock, StoreError> {
    use nix::fcntl::{Flock, FlockArg};

    let file = open_verified_file(path, MAX_STATE_BYTES, 0o400)?;
    trace_receipt_admission_lock(path, "attempt");
    let lock = Flock::lock(file, FlockArg::LockExclusiveNonblock).map_err(|_| state_error())?;
    trace_receipt_admission_lock(path, "acquired");
    Ok(lock)
}

#[cfg(target_os = "linux")]
fn revalidate_loaded_receipt_pair(
    loaded: &LoadedReceipt,
    receipt_path: &Path,
    completion_path: &Path,
) -> Result<(), StoreError> {
    revalidate_publication_pair(
        receipt_path,
        &loaded.admission_lock,
        &loaded.receipt_identity,
        completion_path,
        &loaded.completion_file,
        &loaded.completion_identity,
    )
}

#[cfg(not(target_os = "linux"))]
fn revalidate_loaded_receipt_pair(
    _loaded: &LoadedReceipt,
    _receipt_path: &Path,
    _completion_path: &Path,
) -> Result<(), StoreError> {
    Err(StoreError::new(
        "DEP_STORE_PLATFORM_UNSUPPORTED",
        "receipt pair revalidation requires Linux descriptor semantics",
    ))
}

#[cfg(target_os = "linux")]
fn revalidate_publication_pair(
    receipt_path: &Path,
    receipt_file: &File,
    receipt_identity: &RetainedLinkIdentity,
    completion_path: &Path,
    completion_file: &File,
    completion_identity: &RetainedLinkIdentity,
) -> Result<(), StoreError> {
    revalidate_verified_file_link(
        receipt_path,
        receipt_file,
        receipt_identity,
        MAX_STATE_BYTES,
        0o400,
    )?;
    revalidate_verified_file_link(
        completion_path,
        completion_file,
        completion_identity,
        MAX_STATE_BYTES,
        0o400,
    )
}

#[cfg(not(target_os = "linux"))]
fn revalidate_publication_pair(
    _receipt_path: &Path,
    _receipt_file: &File,
    _receipt_identity: &RetainedLinkIdentity,
    _completion_path: &Path,
    _completion_file: &File,
    _completion_identity: &RetainedLinkIdentity,
) -> Result<(), StoreError> {
    Err(StoreError::new(
        "DEP_STORE_PLATFORM_UNSUPPORTED",
        "publication pair revalidation requires Linux descriptor semantics",
    ))
}

#[cfg(target_os = "linux")]
fn revalidate_verified_file_link(
    path: &Path,
    pinned: &File,
    expected: &RetainedLinkIdentity,
    max_bytes: u64,
    mode: u32,
) -> Result<(), StoreError> {
    use nix::fcntl::OFlag;
    use std::os::unix::fs::OpenOptionsExt as _;

    let linked = OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_PATH | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW).bits())
        .open(path)
        .map_err(|_| receipt_pair_changed())?;
    let pinned = pinned.metadata().map_err(|_| receipt_pair_changed())?;
    let linked = linked.metadata().map_err(|_| receipt_pair_changed())?;
    if !verified_file_metadata(&pinned, max_bytes, mode)
        || !verified_file_metadata(&linked, max_bytes, mode)
        || retained_link_identity(&pinned) != *expected
        || retained_link_identity(&linked) != *expected
    {
        return Err(receipt_pair_changed());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verified_file_fingerprint(
    file: &File,
    max_bytes: u64,
    mode: u32,
) -> Result<RetainedLinkIdentity, StoreError> {
    let metadata = file.metadata().map_err(|_| receipt_pair_changed())?;
    if !verified_file_metadata(&metadata, max_bytes, mode) {
        return Err(receipt_pair_changed());
    }
    Ok(retained_link_identity(&metadata))
}

#[cfg(not(target_os = "linux"))]
fn verified_file_fingerprint(
    _file: &File,
    _max_bytes: u64,
    _mode: u32,
) -> Result<RetainedLinkIdentity, StoreError> {
    Err(StoreError::new(
        "DEP_STORE_PLATFORM_UNSUPPORTED",
        "receipt fingerprinting requires Linux file semantics",
    ))
}

fn receipt_pair_changed() -> StoreError {
    StoreError::new(
        "DEP_STORE_AMBIGUOUS_COMPLETION",
        "receipt and completion links changed during replay verification",
    )
}

fn claim_from_receipt(receipt: &ResolutionReceipt) -> ResolutionClaim {
    ResolutionClaim {
        schema_version: CLAIM_SCHEMA.to_owned(),
        resolution_id: receipt.resolution_id,
        request_sha256: receipt.request_sha256.clone(),
        configuration_sha256: receipt.configuration_sha256.clone(),
        graph_sha256: receipt.plan.graph_sha256.clone(),
        generation: receipt.generation,
        publication_deadline_unix_ms: receipt.publication_deadline_unix_ms,
    }
}

#[cfg(not(target_os = "linux"))]
fn lock_receipt_admission(_path: &Path) -> Result<ReceiptAdmissionLock, StoreError> {
    Err(StoreError::new(
        "DEP_STORE_PLATFORM_UNSUPPORTED",
        "receipt replay admission locking requires Linux file semantics",
    ))
}

#[cfg(target_os = "linux")]
fn verified_file_metadata(metadata: &std::fs::Metadata, max_bytes: u64, mode: u32) -> bool {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    metadata.is_file()
        && metadata.uid() == nix::unistd::Uid::effective().as_raw()
        && metadata.nlink() == 1
        && metadata.permissions().mode() & 0o777 == mode
        && metadata.len() <= max_bytes
}

fn file_policy_error() -> StoreError {
    StoreError::new(
        "DEP_STORE_FILE_POLICY_DENIED",
        "state file owner, mode, type, link count, size, or identity violates policy",
    )
}

#[cfg(not(target_os = "linux"))]
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

fn read_json_from_file<T: for<'de> Deserialize<'de>>(file: &mut File) -> Result<T, StoreError> {
    file.seek(SeekFrom::Start(0)).map_err(|_| state_error())?;
    let metadata = file.metadata().map_err(|_| state_error())?;
    if metadata.len() > MAX_STATE_BYTES {
        return Err(state_error());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_STATE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| state_error())?;
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(state_error());
    }
    crate::strict_json::from_slice(&bytes).map_err(|_| {
        StoreError::new(
            "DEP_STORE_STATE_INVALID",
            "stored state is malformed or not closed JSON",
        )
    })
}

fn write_new_json<T: Serialize>(
    path: &Path,
    value: &T,
    final_mode: u32,
) -> Result<File, StoreError> {
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
    let file = write_new_file(&temporary, &bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(final_mode))
            .map_err(|_| state_error())?;
    }
    file.sync_all().map_err(|_| state_error())?;
    if let Err(error) = rename_no_replace(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    sync_directory(parent)?;
    let identity = verified_file_fingerprint(&file, MAX_STATE_BYTES, final_mode)?;
    revalidate_verified_file_link(path, &file, &identity, MAX_STATE_BYTES, final_mode)?;
    Ok(file)
}

#[cfg(unix)]
fn write_new_file(path: &Path, bytes: &[u8]) -> Result<File, StoreError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::fcntl::OFlag::O_CLOEXEC.bits() | nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(path)
        .map_err(|_| state_error())?;
    file.write_all(bytes).map_err(|_| state_error())?;
    file.sync_all().map_err(|_| state_error())?;
    Ok(file)
}

#[cfg(not(unix))]
fn write_new_file(_path: &Path, _bytes: &[u8]) -> Result<File, StoreError> {
    Err(StoreError::new(
        "DEP_STORE_PLATFORM_UNSUPPORTED",
        "durable dependency publication requires Unix file semantics",
    ))
}

#[cfg(all(unix, test))]
fn set_mode_and_sync(path: &Path, mode: u32) -> Result<(), StoreError> {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|_| state_error())?;
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| state_error())
}

#[cfg(all(not(unix), test))]
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

#[cfg(target_os = "linux")]
fn pin_private_regular_file_at(
    parent: &File,
    name: &str,
    expected_mode: u32,
    expected_size: u64,
    expected_identity: (u64, u64),
) -> Result<File, StoreError> {
    use nix::fcntl::{OFlag, openat};
    use nix::sys::stat::Mode;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let file = File::from(
        openat(
            parent,
            name,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| state_error())?,
    );
    let metadata = file.metadata().map_err(|_| state_error())?;
    let parent_metadata = parent.metadata().map_err(|_| state_error())?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.permissions().mode() & 0o777 != expected_mode
        || metadata.nlink() != 1
        || metadata.len() != expected_size
        || metadata.dev() != parent_metadata.dev()
        || (metadata.dev(), metadata.ino()) != expected_identity
    {
        return Err(StoreError::new(
            "DEP_STORE_TRANSIENT_ROOT_MISMATCH",
            "transport archive type, owner, mode, size, links, device, or inode changed",
        ));
    }
    let linked = File::from(
        openat(
            parent,
            name,
            OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| state_error())?,
    );
    let linked = linked.metadata().map_err(|_| state_error())?;
    if !linked.is_file() || linked.dev() != metadata.dev() || linked.ino() != metadata.ino() {
        return Err(StoreError::new(
            "DEP_STORE_TRANSIENT_ROOT_MISMATCH",
            "transport archive link changed while its descriptor was retained",
        ));
    }
    Ok(file)
}

#[cfg(not(target_os = "linux"))]
fn pin_private_regular_file_at(
    _parent: &File,
    _name: &str,
    _expected_mode: u32,
    _expected_size: u64,
    _expected_identity: (u64, u64),
) -> Result<File, StoreError> {
    Err(StoreError::new(
        "DEP_STORE_PLATFORM_UNSUPPORTED",
        "descriptor-pinned transport archives require Linux file semantics",
    ))
}

fn verify_archive_slice(
    archive: &File,
    offset: u64,
    size: u64,
    expected_sha256: &str,
) -> Result<(), StoreError> {
    let mut archive = archive.try_clone().map_err(|_| state_error())?;
    archive
        .seek(SeekFrom::Start(offset))
        .map_err(|_| state_error())?;
    let mut remaining = size;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 65_536];
    while remaining > 0 {
        let limit =
            usize::try_from(remaining.min(buffer.len() as u64)).map_err(|_| state_error())?;
        let read = archive
            .read(&mut buffer[..limit])
            .map_err(|_| state_error())?;
        if read == 0 {
            return Err(state_error());
        }
        remaining -= read as u64;
        hasher.update(&buffer[..read]);
    }
    if format!("{:x}", hasher.finalize()) != expected_sha256 {
        return Err(StoreError::new(
            "DEP_STORE_ARTIFACT_CONTENT_MISMATCH",
            "transport archive slice does not match the exact artifact digest",
        ));
    }
    Ok(())
}

fn append_archive_slice(
    source: &File,
    offset: u64,
    destination: &mut File,
    size: u64,
    expected_sha256: &str,
) -> Result<(), StoreError> {
    let mut source = source.try_clone().map_err(|_| state_error())?;
    source
        .seek(SeekFrom::Start(offset))
        .map_err(|_| state_error())?;
    let mut remaining = size;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 65_536];
    while remaining > 0 {
        let limit =
            usize::try_from(remaining.min(buffer.len() as u64)).map_err(|_| state_error())?;
        let read = source
            .read(&mut buffer[..limit])
            .map_err(|_| state_error())?;
        if read == 0 {
            return Err(state_error());
        }
        destination
            .write_all(&buffer[..read])
            .map_err(|_| state_error())?;
        remaining -= read as u64;
        hasher.update(&buffer[..read]);
    }
    if format!("{:x}", hasher.finalize()) != expected_sha256 {
        return Err(StoreError::new(
            "DEP_STORE_ARTIFACT_CONTENT_MISMATCH",
            "copied transport archive slice does not match the exact artifact digest",
        ));
    }
    Ok(())
}

#[cfg(all(target_os = "linux", test))]
fn create_and_pin_private_directory_at(
    parent: &File,
    name: &str,
    mode: u32,
) -> Result<PinnedPublicationDirectory, StoreError> {
    use nix::sys::stat::{Mode, mkdirat};

    // Linux does not expose a mkdir syscall that returns the new directory
    // descriptor. Keep creation and the first no-follow open in this one
    // pinned-parent boundary and never derive identity from an absolute path.
    mkdirat(parent, name, Mode::from_bits_truncate(mode)).map_err(|_| state_error())?;
    parent.sync_all().map_err(|_| state_error())?;
    pin_private_directory_at(parent, name, mode, None)
}

#[cfg(all(not(target_os = "linux"), test))]
fn create_and_pin_private_directory_at(
    _parent: &File,
    _name: &str,
    _mode: u32,
) -> Result<PinnedPublicationDirectory, StoreError> {
    Err(StoreError::new(
        "DEP_STORE_PLATFORM_UNSUPPORTED",
        "descriptor-pinned publication requires Linux file semantics",
    ))
}

#[cfg(all(target_os = "linux", test))]
fn pin_private_directory_at(
    parent: &File,
    name: &str,
    expected_mode: u32,
    expected_identity: Option<(u64, u64)>,
) -> Result<PinnedPublicationDirectory, StoreError> {
    use nix::fcntl::{OFlag, openat};
    use nix::sys::stat::Mode;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let directory = File::from(
        openat(
            parent,
            name,
            OFlag::O_RDONLY
                | OFlag::O_DIRECTORY
                | OFlag::O_NOFOLLOW
                | OFlag::O_CLOEXEC
                | OFlag::O_NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| state_error())?,
    );
    let metadata = directory.metadata().map_err(|_| state_error())?;
    let parent_metadata = parent.metadata().map_err(|_| state_error())?;
    if !metadata.is_dir()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.permissions().mode() & 0o777 != expected_mode
        || metadata.dev() != parent_metadata.dev()
        || expected_identity.is_some_and(|(device, inode)| {
            metadata.dev() != device || (inode != 0 && metadata.ino() != inode)
        })
    {
        return Err(StoreError::new(
            "DEP_STORE_DIRECTORY_POLICY_DENIED",
            "publication directory owner, mode, device, or identity violates policy",
        ));
    }
    let pinned = PinnedPublicationDirectory {
        path: pinned_directory_path(&directory),
        device: metadata.dev(),
        inode: metadata.ino(),
        directory,
    };
    revalidate_private_directory_link(parent, name, &pinned, expected_mode)?;
    Ok(pinned)
}

#[cfg(all(not(target_os = "linux"), test))]
fn pin_private_directory_at(
    _parent: &File,
    _name: &str,
    _expected_mode: u32,
    _expected_identity: Option<(u64, u64)>,
) -> Result<PinnedPublicationDirectory, StoreError> {
    Err(StoreError::new(
        "DEP_STORE_PLATFORM_UNSUPPORTED",
        "descriptor-pinned publication requires Linux file semantics",
    ))
}

#[cfg(all(target_os = "linux", test))]
fn revalidate_private_directory_link(
    parent: &File,
    name: &str,
    expected: &PinnedPublicationDirectory,
    expected_mode: u32,
) -> Result<(), StoreError> {
    use nix::fcntl::{OFlag, openat};
    use nix::sys::stat::Mode;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let linked = File::from(
        openat(
            parent,
            name,
            OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| state_error())?,
    );
    let metadata = linked.metadata().map_err(|_| state_error())?;
    if !metadata.is_dir()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.permissions().mode() & 0o777 != expected_mode
        || metadata.dev() != expected.device
        || metadata.ino() != expected.inode
    {
        return Err(StoreError::new(
            "DEP_STORE_PUBLICATION_AMBIGUOUS",
            "publication directory link changed while its descriptor was retained",
        ));
    }
    Ok(())
}

#[cfg(all(not(target_os = "linux"), test))]
fn revalidate_private_directory_link(
    _parent: &File,
    _name: &str,
    _expected: &PinnedPublicationDirectory,
    _expected_mode: u32,
) -> Result<(), StoreError> {
    Err(state_error())
}

#[cfg(all(unix, test))]
fn seal_directory(directory: &File, mode: u32) -> Result<(), StoreError> {
    use std::os::unix::fs::PermissionsExt as _;

    directory
        .set_permissions(std::fs::Permissions::from_mode(mode))
        .map_err(|_| state_error())?;
    directory.sync_all().map_err(|_| state_error())
}

#[cfg(all(not(unix), test))]
fn seal_directory(_directory: &File, _mode: u32) -> Result<(), StoreError> {
    Err(state_error())
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

#[cfg(all(target_os = "linux", test))]
fn remove_private_tree(
    root_directory: &File,
    root_path: &Path,
    path: &Path,
) -> Result<(), StoreError> {
    let (mut parent, name) = open_cleanup_parent(root_directory, root_path, path)?;
    let mut entries = 1_usize;
    remove_private_tree_at(&mut parent, &name, path, None, 0, &mut entries)
}

#[cfg(all(target_os = "linux", test))]
pub(crate) fn remove_private_tree_exact(
    root_directory: &File,
    root_path: &Path,
    path: &Path,
    expected_device: u64,
    expected_inode: u64,
) -> Result<(), StoreError> {
    let (mut parent, name) = open_cleanup_parent(root_directory, root_path, path)?;
    let mut entries = 1_usize;
    remove_private_tree_at(
        &mut parent,
        &name,
        path,
        Some((expected_device, expected_inode)),
        0,
        &mut entries,
    )
}

#[cfg(all(not(target_os = "linux"), test))]
pub(crate) fn remove_private_tree_exact(
    _root_directory: &File,
    _root_path: &Path,
    _path: &Path,
    _expected_device: u64,
    _expected_inode: u64,
) -> Result<(), StoreError> {
    Err(StoreError::new(
        "DEP_STORE_PLATFORM_UNSUPPORTED",
        "descriptor-pinned cleanup requires Linux file semantics",
    ))
}

#[cfg(all(not(target_os = "linux"), test))]
fn remove_private_tree(
    _root_directory: &File,
    _root_path: &Path,
    _path: &Path,
) -> Result<(), StoreError> {
    Err(StoreError::new(
        "DEP_STORE_PLATFORM_UNSUPPORTED",
        "descriptor-pinned cleanup requires Linux file semantics",
    ))
}

fn path_exists(path: &Path) -> Result<bool, StoreError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(state_error()),
    }
}

#[cfg(target_os = "linux")]
fn remove_private_file(
    root_directory: &File,
    root_path: &Path,
    path: &Path,
) -> Result<(), StoreError> {
    let (parent, name) = open_cleanup_parent(root_directory, root_path, path)?;
    remove_private_file_at(&parent, &name, path, None)
}

#[cfg(target_os = "linux")]
pub(crate) fn remove_private_file_exact(
    root_directory: &File,
    root_path: &Path,
    path: &Path,
    expected_device: u64,
    expected_inode: u64,
) -> Result<(), StoreError> {
    let (parent, name) = open_cleanup_parent(root_directory, root_path, path)?;
    remove_private_file_at(
        &parent,
        &name,
        path,
        Some((expected_device, expected_inode)),
    )
}

#[cfg(not(target_os = "linux"))]
fn remove_private_file(
    _root_directory: &File,
    _root_path: &Path,
    _path: &Path,
) -> Result<(), StoreError> {
    Err(StoreError::new(
        "DEP_STORE_PLATFORM_UNSUPPORTED",
        "descriptor-pinned cleanup requires Linux file semantics",
    ))
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn remove_private_file_exact(
    _root_directory: &File,
    _root_path: &Path,
    _path: &Path,
    _expected_device: u64,
    _expected_inode: u64,
) -> Result<(), StoreError> {
    Err(StoreError::new(
        "DEP_STORE_PLATFORM_UNSUPPORTED",
        "exact private-file cleanup requires Linux file semantics",
    ))
}

#[cfg(target_os = "linux")]
pub(crate) fn open_pinned_cleanup_root(path: &Path) -> Result<File, StoreError> {
    use nix::fcntl::{OFlag, openat};
    use nix::sys::stat::Mode;

    if !path.is_absolute() {
        return Err(state_error());
    }
    let mut directory = File::open("/").map_err(|_| state_error())?;
    let mut opened_component = false;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                directory = File::from(
                    openat(
                        &directory,
                        name,
                        OFlag::O_RDONLY
                            | OFlag::O_DIRECTORY
                            | OFlag::O_NOFOLLOW
                            | OFlag::O_CLOEXEC
                            | OFlag::O_NONBLOCK,
                        Mode::empty(),
                    )
                    .map_err(|_| state_error())?,
                );
                opened_component = true;
            }
            _ => return Err(state_error()),
        }
    }
    let root_stat = nix::sys::stat::fstat(&directory).map_err(|_| state_error())?;
    if !opened_component || !owned_cleanup_directory(&root_stat) {
        return Err(state_error());
    }
    Ok(directory)
}

#[cfg(target_os = "linux")]
pub(crate) fn pinned_directory_path(directory: &File) -> PathBuf {
    use std::os::fd::AsRawFd as _;

    PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()))
}

#[cfg(unix)]
fn directory_device_inode(directory: &File) -> Result<(u64, u64), StoreError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = directory.metadata().map_err(|_| state_error())?;
    Ok((metadata.dev(), metadata.ino()))
}

fn require_directory_identity(
    directory: &File,
    expected: crate::transport::TransportRootIdentity,
    code: &'static str,
    message: &'static str,
) -> Result<(), StoreError> {
    if directory_device_inode(directory)? != (expected.device, expected.inode) {
        return Err(StoreError::new(code, message));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_private_directory(
    directory: &File,
    code: &'static str,
    message: &'static str,
) -> Result<(), StoreError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let metadata = directory.metadata().map_err(|_| state_error())?;
    if !metadata.is_dir()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(StoreError::new(code, message));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_directory(
    _directory: &File,
    _code: &'static str,
    _message: &'static str,
) -> Result<(), StoreError> {
    Err(state_error())
}

#[cfg(not(unix))]
fn directory_device_inode(_directory: &File) -> Result<(u64, u64), StoreError> {
    Err(state_error())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn open_pinned_cleanup_root(_path: &Path) -> Result<File, StoreError> {
    Err(StoreError::new(
        "DEP_STORE_PLATFORM_UNSUPPORTED",
        "descriptor-pinned cleanup requires Linux file semantics",
    ))
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn pinned_directory_path(_directory: &File) -> PathBuf {
    PathBuf::new()
}

#[cfg(target_os = "linux")]
fn open_cleanup_parent(
    root_directory: &File,
    root_path: &Path,
    path: &Path,
) -> Result<(nix::dir::Dir, std::ffi::CString), StoreError> {
    use nix::fcntl::{OFlag, openat};
    use nix::sys::stat::Mode;
    use std::os::fd::OwnedFd;
    use std::os::unix::ffi::OsStrExt as _;

    let relative = path.strip_prefix(root_path).map_err(|_| state_error())?;
    let components = relative
        .components()
        .map(|component| match component {
            Component::Normal(name) => Ok(name),
            _ => Err(state_error()),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (name, parents) = components.split_last().ok_or_else(state_error)?;
    let mut directory = root_directory.try_clone().map_err(|_| state_error())?;
    for component in parents {
        directory = File::from(
            openat(
                &directory,
                *component,
                OFlag::O_RDONLY
                    | OFlag::O_DIRECTORY
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_CLOEXEC
                    | OFlag::O_NONBLOCK,
                Mode::empty(),
            )
            .map_err(|_| state_error())?,
        );
        let stat = nix::sys::stat::fstat(&directory).map_err(|_| state_error())?;
        if !owned_cleanup_directory(&stat) {
            return Err(state_error());
        }
    }
    let parent = nix::dir::Dir::from_fd(OwnedFd::from(directory)).map_err(|_| state_error())?;
    let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| state_error())?;
    Ok((parent, name))
}

#[cfg(target_os = "linux")]
fn inspect_cleanup_entry<Fd: std::os::fd::AsFd>(
    parent: Fd,
    name: &std::ffi::CStr,
) -> Result<std::os::fd::OwnedFd, StoreError> {
    use nix::fcntl::{OFlag, openat};
    use nix::sys::stat::Mode;

    openat(
        parent,
        name,
        OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| state_error())
}

#[cfg(target_os = "linux")]
fn remove_private_file_at<Fd: std::os::fd::AsFd>(
    parent: Fd,
    name: &std::ffi::CStr,
    display_path: &Path,
    expected_identity: Option<(u64, u64)>,
) -> Result<(), StoreError> {
    use nix::fcntl::{OFlag, open};
    use nix::sys::stat::{Mode, SFlag, fchmod, fstat};
    use nix::unistd::{UnlinkatFlags, unlinkat};
    use std::os::fd::AsRawFd as _;

    run_cleanup_pre_inspection_swap_hook(display_path)?;
    let inspection = inspect_cleanup_entry(&parent, name)?;
    let inspected = fstat(&inspection).map_err(|_| state_error())?;
    if expected_identity.is_some_and(|identity| (inspected.st_dev, inspected.st_ino) != identity) {
        return Err(cleanup_exact_mismatch());
    }
    if !owned_cleanup_entry(&inspected, SFlag::S_IFREG) || inspected.st_nlink != 1 {
        return Err(state_error());
    }
    run_cleanup_swap_hook(display_path)?;
    let pinned_path = format!("/proc/self/fd/{}", inspection.as_raw_fd());
    let opened = open(
        pinned_path.as_str(),
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| state_error())?;
    let opened_stat = fstat(&opened).map_err(|_| state_error())?;
    if !same_cleanup_identity(&inspected, &opened_stat)
        || !owned_cleanup_entry(&opened_stat, SFlag::S_IFREG)
    {
        return Err(state_error());
    }
    require_cleanup_identity(&parent, name, &inspected)?;
    run_cleanup_final_swap_hook(display_path)?;
    let quarantine = quarantine_cleanup_entry(&parent, name)?;
    let quarantined = inspect_cleanup_entry(&parent, &quarantine)?;
    let quarantined_stat = fstat(&quarantined).map_err(|_| state_error())?;
    if !same_cleanup_identity(&inspected, &quarantined_stat) {
        return Err(cleanup_selection_changed(expected_identity));
    }
    fchmod(&opened, Mode::from_bits_truncate(0o600)).map_err(|_| state_error())?;
    require_cleanup_identity(&parent, &quarantine, &inspected)?;
    run_cleanup_pre_unlink_swap_hook(&parent, &quarantine, display_path)?;
    unlinkat(&parent, quarantine.as_c_str(), UnlinkatFlags::NoRemoveDir)
        .map_err(|_| cleanup_selection_changed(expected_identity))?;
    let removed = fstat(&opened).map_err(|_| cleanup_selection_changed(expected_identity))?;
    if removed.st_nlink != 0 {
        return Err(cleanup_selection_changed(expected_identity));
    }
    Ok(())
}

#[cfg(all(target_os = "linux", test))]
fn remove_private_tree_at(
    parent: &mut nix::dir::Dir,
    name: &std::ffi::CStr,
    display_path: &Path,
    expected_identity: Option<(u64, u64)>,
    depth: usize,
    entries: &mut usize,
) -> Result<(), StoreError> {
    use nix::fcntl::OFlag;
    use nix::sys::stat::{Mode, SFlag, fchmod, fstat};
    use nix::unistd::{UnlinkatFlags, unlinkat};
    use std::os::fd::AsRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;

    if depth > MAX_CLEANUP_DEPTH || *entries > MAX_RETAINED_TREE_ENTRIES {
        return Err(state_error());
    }
    run_cleanup_pre_inspection_swap_hook(display_path)?;
    let inspection = inspect_cleanup_entry(&*parent, name)?;
    let inspected = fstat(&inspection).map_err(|_| state_error())?;
    if expected_identity.is_some_and(|identity| (inspected.st_dev, inspected.st_ino) != identity) {
        return Err(cleanup_exact_mismatch());
    }
    if !owned_cleanup_entry(&inspected, SFlag::S_IFDIR) {
        return Err(state_error());
    }
    run_cleanup_swap_hook(display_path)?;
    let pinned_path = format!("/proc/self/fd/{}", inspection.as_raw_fd());
    let mut directory = nix::dir::Dir::open(
        pinned_path.as_str(),
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| state_error())?;
    let opened = fstat(&directory).map_err(|_| state_error())?;
    if !same_cleanup_identity(&inspected, &opened) || !owned_cleanup_entry(&opened, SFlag::S_IFDIR)
    {
        return Err(state_error());
    }
    require_cleanup_identity(&*parent, name, &inspected)?;
    run_cleanup_final_swap_hook(display_path)?;
    let quarantine = quarantine_cleanup_entry(&*parent, name)?;
    let quarantined = inspect_cleanup_entry(&*parent, &quarantine)?;
    let quarantined_stat = fstat(&quarantined).map_err(|_| state_error())?;
    if !same_cleanup_identity(&inspected, &quarantined_stat) {
        return Err(cleanup_selection_changed(expected_identity));
    }
    fchmod(&directory, Mode::from_bits_truncate(0o700)).map_err(|_| state_error())?;
    let names = collect_cleanup_names(&mut directory, entries, MAX_RETAINED_TREE_ENTRIES)?;
    for child_name in names {
        let child_path = display_path.join(std::ffi::OsStr::from_bytes(child_name.to_bytes()));
        let child = inspect_cleanup_entry(&directory, &child_name)?;
        let child_stat = fstat(&child).map_err(|_| state_error())?;
        let child_type = nix::sys::stat::SFlag::from_bits_truncate(child_stat.st_mode);
        if child_type.contains(SFlag::S_IFDIR) {
            remove_private_tree_at(
                &mut directory,
                &child_name,
                &child_path,
                None,
                depth + 1,
                entries,
            )?;
        } else if child_type.contains(SFlag::S_IFREG) {
            remove_private_file_at(&directory, &child_name, &child_path, None)?;
        } else {
            return Err(state_error());
        }
    }
    require_cleanup_identity(&*parent, &quarantine, &inspected)?;
    run_cleanup_pre_unlink_swap_hook(&*parent, &quarantine, display_path)?;
    unlinkat(&*parent, quarantine.as_c_str(), UnlinkatFlags::RemoveDir)
        .map_err(|_| cleanup_selection_changed(expected_identity))?;
    let removed = fstat(&directory).map_err(|_| cleanup_selection_changed(expected_identity))?;
    if removed.st_nlink != 0 {
        return Err(cleanup_selection_changed(expected_identity));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn quarantine_cleanup_entry<Fd: std::os::fd::AsFd>(
    parent: &Fd,
    name: &std::ffi::CStr,
) -> Result<std::ffi::CString, StoreError> {
    use nix::errno::Errno;
    use nix::fcntl::{RenameFlags, renameat2};

    for _ in 0..16 {
        let quarantine =
            std::ffi::CString::new(format!(".mcloving-cleanup-{}", Uuid::new_v4().simple()))
                .map_err(|_| state_error())?;
        match renameat2(
            parent,
            name,
            parent,
            quarantine.as_c_str(),
            RenameFlags::RENAME_NOREPLACE,
        ) {
            Ok(()) => return Ok(quarantine),
            Err(Errno::EEXIST) => continue,
            Err(_) => return Err(state_error()),
        }
    }
    Err(state_error())
}

fn cleanup_selection_changed(expected_identity: Option<(u64, u64)>) -> StoreError {
    if expected_identity.is_some() {
        cleanup_exact_mismatch()
    } else {
        state_error()
    }
}

fn cleanup_exact_mismatch() -> StoreError {
    StoreError::new(
        "DEP_STORE_PUBLICATION_AMBIGUOUS",
        "cleanup link no longer names the exact retained inode",
    )
}

#[cfg(all(target_os = "linux", test))]
fn collect_cleanup_names(
    directory: &mut nix::dir::Dir,
    entries: &mut usize,
    max_entries: usize,
) -> Result<Vec<std::ffi::CString>, StoreError> {
    let mut names = Vec::new();
    for entry in directory.iter() {
        let entry = entry.map_err(|_| state_error())?;
        if entry.file_name().to_bytes() == b"." || entry.file_name().to_bytes() == b".." {
            continue;
        }
        if *entries >= max_entries {
            return Err(state_error());
        }
        *entries += 1;
        names.push(entry.file_name().to_owned());
    }
    Ok(names)
}

#[cfg(target_os = "linux")]
fn require_cleanup_identity<Fd: std::os::fd::AsFd>(
    parent: Fd,
    name: &std::ffi::CStr,
    expected: &nix::libc::stat,
) -> Result<(), StoreError> {
    let linked = inspect_cleanup_entry(parent, name)?;
    let linked_stat = nix::sys::stat::fstat(&linked).map_err(|_| state_error())?;
    if !same_cleanup_identity(expected, &linked_stat) {
        return Err(state_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn owned_cleanup_entry(metadata: &nix::libc::stat, expected: nix::sys::stat::SFlag) -> bool {
    nix::sys::stat::SFlag::from_bits_truncate(metadata.st_mode).contains(expected)
        && metadata.st_uid == nix::unistd::Uid::effective().as_raw()
}

#[cfg(target_os = "linux")]
fn owned_cleanup_directory(metadata: &nix::libc::stat) -> bool {
    owned_cleanup_entry(metadata, nix::sys::stat::SFlag::S_IFDIR)
}

#[cfg(target_os = "linux")]
fn same_cleanup_identity(left: &nix::libc::stat, right: &nix::libc::stat) -> bool {
    left.st_dev == right.st_dev && left.st_ino == right.st_ino
}

fn current_unix_ms() -> Result<u64, StoreError> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| state_error())?
        .as_millis();
    u64::try_from(millis).map_err(|_| state_error())
}

#[cfg(test)]
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
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use tempfile::TempDir;

    use super::*;
    use crate::{
        AdapterConfig, Ecosystem, PackageNode, RepositoryBinding, RepositoryConfig, ResolverLimits,
        SourceProvenance, SourceTrustClass, canonical_graph_sha256, canonical_node_id,
        configuration_sha256, request_sha256,
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
            std::fs::create_dir_all(&transport).expect("transport root");
            std::fs::set_permissions(&transport, std::fs::Permissions::from_mode(0o700))
                .expect("private transport root");
            let transient = transport.join(format!(".{resolution_id}.transport"));
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
                source_attestation_key_id: "source-key-v1".to_owned(),
                source_attestation_key_path: "/authority/source-attestation.pub".to_owned(),
                source_attestation_key_sha256: "9".repeat(64),
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
                source_provenance: SourceProvenance {
                    schema_version: "mcloving.source-provenance/v1".to_owned(),
                    key_id: config.source_attestation_key_id.clone(),
                    issued_at_unix_ms: now.saturating_sub(1_000),
                    expires_at_unix_ms: now + 60_000,
                    signature_base64: "AA".repeat(43),
                },
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
                node_id: node.node_id.clone(),
                transient_path: PathBuf::from(format!(".{resolution_id}.transport")),
                declared_size: body.len() as u64,
                sha256: artifact_sha256,
                attestation_sha256: "8".repeat(64),
                publication_generation: config.generation,
                transient_offset: 0,
                transient_root_device: std::fs::metadata(&transient)
                    .expect("transport archive metadata")
                    .dev(),
                transient_root_inode: std::fs::metadata(&transient)
                    .expect("transport archive metadata")
                    .ino(),
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
            ResolutionStore::open_inner(&self.config, &self.receipt_key, markers, None)
                .expect("resolution store")
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn publication_artifacts_relink_cannot_redirect_writes_or_cleanup() {
        use std::os::unix::fs::symlink;

        let root = TempDir::new().expect("publication root");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private publication root");
        let bundles = root.path().join("bundles");
        std::fs::create_dir(&bundles).expect("bundles root");
        std::fs::set_permissions(&bundles, std::fs::Permissions::from_mode(0o700))
            .expect("private bundles root");
        let bundles_directory = open_pinned_cleanup_root(&bundles).expect("pinned bundles root");
        let stage_name = ".contained.stage";
        let stage_link = bundles.join(stage_name);
        let stage = create_and_pin_private_directory_at(&bundles_directory, stage_name, 0o700)
            .expect("created and pinned stage");
        let artifacts_link = stage.path.join("artifacts");
        let artifacts = create_and_pin_private_directory_at(&stage.directory, "artifacts", 0o700)
            .expect("created and pinned artifacts");

        let held = stage.path.join("held-artifacts");
        std::fs::rename(&artifacts_link, &held).expect("unlink pinned artifacts");
        let outside = TempDir::new().expect("outside directory");
        symlink(outside.path(), &artifacts_link).expect("replacement artifacts symlink");
        std::fs::write(artifacts.path.join("digest"), b"retained bytes")
            .expect("write through pinned artifacts descriptor");
        seal_directory(&artifacts.directory, 0o500).expect("seal pinned artifacts");

        assert_eq!(
            std::fs::read(held.join("digest")).expect("retained artifact"),
            b"retained bytes"
        );
        assert!(!outside.path().join("digest").exists());
        assert!(
            revalidate_private_directory_link(&stage.directory, "artifacts", &artifacts, 0o500)
                .is_err()
        );
        assert!(
            remove_private_tree_exact(
                &bundles_directory,
                &bundles,
                &stage_link,
                stage.device,
                stage.inode,
            )
            .is_err()
        );
        assert!(outside.path().exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn publication_parent_delegates_the_exact_locked_root() {
        use std::os::unix::fs::MetadataExt as _;

        let fixture = Fixture::new();
        let store = fixture.store();
        let delegated = store
            .publication_lock_file()
            .expect("delegated parent lock");
        let expected =
            std::fs::metadata(&fixture.config.output_root).expect("output root metadata");
        let actual = delegated.metadata().expect("delegated lock metadata");
        assert_eq!(
            (actual.dev(), actual.ino()),
            (expected.dev(), expected.ino())
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn replacing_the_lock_sentinel_cannot_split_root_serialization() {
        let fixture = Fixture::new();
        let _store = fixture.store();
        let root = PathBuf::from(&fixture.config.output_root);
        let sentinel = root.join(LOCK_FILE);
        std::fs::rename(&sentinel, root.join("detached-lock-sentinel"))
            .expect("detach lock sentinel");
        write_new_file(&sentinel, b"").expect("replacement lock sentinel");
        set_mode_and_sync(&sentinel, 0o600).expect("seal replacement sentinel");
        let root_directory = open_pinned_cleanup_root(&root).expect("pinned output root");

        let error = acquire_output_lock(&root_directory, &root)
            .expect_err("the output root inode remains locked");
        assert_eq!(error.code, "DEP_STORE_ROOT_LOCKED");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn worker_output_identity_rejects_a_private_replacement_root() {
        let root = TempDir::new().expect("worker root parent");
        let configured = root.path().join("output");
        std::fs::create_dir(&configured).expect("output root");
        std::fs::set_permissions(&configured, std::fs::Permissions::from_mode(0o700))
            .expect("private output root");
        let parent_root = open_pinned_cleanup_root(&configured).expect("parent pinned root");
        let (device, inode) = directory_device_inode(&parent_root).expect("parent identity");
        let expected = crate::transport::TransportRootIdentity { device, inode };

        let held = root.path().join("held-output");
        std::fs::rename(&configured, &held).expect("move parent output root");
        std::fs::create_dir(&configured).expect("replacement output root");
        std::fs::set_permissions(&configured, std::fs::Permissions::from_mode(0o700))
            .expect("private replacement root");
        let replacement = open_pinned_cleanup_root(&configured).expect("replacement pinned root");
        let error = require_directory_identity(
            &replacement,
            expected,
            "DEP_STORE_WORKER_PARENT_ROOT_INVALID",
            "publication worker output root does not match the pinned parent root",
        )
        .expect_err("replacement worker root");
        assert_eq!(error.code, "DEP_STORE_WORKER_PARENT_ROOT_INVALID");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fixed_store_directory_relink_is_rejected_after_pinning() {
        let root = TempDir::new().expect("store root");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private store root");
        let claims = root.path().join("claims");
        std::fs::create_dir(&claims).expect("claims directory");
        std::fs::set_permissions(&claims, std::fs::Permissions::from_mode(0o700))
            .expect("private claims directory");
        let root_directory = open_pinned_cleanup_root(root.path()).expect("pinned store root");
        let pinned = open_store_directory(&root_directory, "claims").expect("pinned claims");

        std::fs::rename(&claims, root.path().join("held-claims")).expect("move pinned claims");
        std::fs::create_dir(&claims).expect("replacement claims");
        std::fs::set_permissions(&claims, std::fs::Permissions::from_mode(0o700))
            .expect("private replacement claims");
        let error = revalidate_store_directory_link(&root_directory, "claims", &pinned)
            .expect_err("relinked claims directory");
        assert_eq!(error.code, "DEP_STORE_FIXED_DIRECTORY_AMBIGUOUS");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn output_store_remains_bound_to_the_root_that_holds_its_lock() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let fixture = Fixture::new();
        let store = fixture.store();
        let configured = PathBuf::from(&fixture.config.output_root);
        let pinned = fixture._root.path().join("output-pinned");
        std::fs::rename(&configured, &pinned).expect("move locked output root");
        std::fs::create_dir(&configured).expect("replacement output root");
        std::fs::set_permissions(&configured, std::fs::Permissions::from_mode(0o700))
            .expect("replacement output mode");

        let claim = match store
            .claim_or_replay(&fixture.request, &fixture.admitted, &fixture.plan)
            .expect("claim through pinned store")
        {
            ClaimOutcome::New(claim) => claim,
            other => panic!("unexpected claim outcome: {other:?}"),
        };
        assert!(
            pinned
                .join(format!(
                    "claims/{claim_id}.json",
                    claim_id = claim.resolution_id
                ))
                .exists()
        );
        assert!(
            !configured
                .join(format!(
                    "claims/{claim_id}.json",
                    claim_id = claim.resolution_id
                ))
                .exists(),
            "replacement pathname must not redirect locked store writes"
        );
        let delegated = store
            .publication_lock_file()
            .expect("delegated output lock");
        let locked = std::fs::metadata(&pinned).expect("locked root inode");
        let delegated = delegated.metadata().expect("delegated inode");
        assert_eq!(
            (delegated.dev(), delegated.ino()),
            (locked.dev(), locked.ino())
        );
        store.release_incomplete_claim(&claim);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn store_rejects_a_transport_root_replaced_after_lease_identity_capture() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let fixture = Fixture::new();
        let configured = PathBuf::from(&fixture.config.transport_root);
        let metadata = std::fs::metadata(&configured).expect("leased transport root");
        let expected = crate::transport::TransportRootIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        let leased = fixture._root.path().join("transport-leased");
        std::fs::rename(&configured, &leased).expect("move leased transport root");
        std::fs::create_dir(&configured).expect("replacement transport root");
        std::fs::set_permissions(&configured, std::fs::Permissions::from_mode(0o700))
            .expect("replacement transport mode");

        let error = match ResolutionStore::open_inner(
            &fixture.config,
            &fixture.receipt_key,
            vec![fixture.receipt_key.clone()],
            Some(expected),
        ) {
            Ok(_) => panic!("replacement transport root was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.code, "DEP_STORE_TRANSIENT_PATH_MISMATCH");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn store_construction_rechecks_private_output_and_transport_modes() {
        let output_fixture = Fixture::new();
        std::fs::set_permissions(
            &output_fixture.config.output_root,
            std::fs::Permissions::from_mode(0o750),
        )
        .expect("broaden output root mode");
        let output_error = match ResolutionStore::open_inner(
            &output_fixture.config,
            &output_fixture.receipt_key,
            vec![output_fixture.receipt_key.clone()],
            None,
        ) {
            Ok(_) => panic!("broadened output root was accepted"),
            Err(error) => error,
        };
        assert_eq!(output_error.code, "DEP_STORE_ROOT_POLICY_DENIED");

        let transport_fixture = Fixture::new();
        std::fs::set_permissions(
            &transport_fixture.config.transport_root,
            std::fs::Permissions::from_mode(0o750),
        )
        .expect("broaden transport root mode");
        let transport_error = match ResolutionStore::open_inner(
            &transport_fixture.config,
            &transport_fixture.receipt_key,
            vec![transport_fixture.receipt_key.clone()],
            None,
        ) {
            Ok(_) => panic!("broadened transport root was accepted"),
            Err(error) => error,
        };
        assert_eq!(transport_error.code, "DEP_STORE_TRANSIENT_PATH_MISMATCH");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fifo_output_lock_is_rejected_after_inspection_before_data_open() {
        use nix::sys::stat::Mode;
        use nix::unistd::mkfifo;
        use std::time::Duration;

        let fixture = Fixture::new();
        let lock_path = PathBuf::from(&fixture.config.output_root).join(LOCK_FILE);
        mkfifo(&lock_path, Mode::S_IRUSR | Mode::S_IWUSR).expect("output lock fifo");
        OUTPUT_LOCK_OPEN_TRACE.with(|trace| trace.borrow_mut().clear());
        let started = Instant::now();
        let error = match ResolutionStore::open_inner(
            &fixture.config,
            &fixture.receipt_key,
            vec![fixture.receipt_key.clone()],
            None,
        ) {
            Ok(_) => panic!("non-regular output lock was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.code, "DEP_STORE_STATE_UNAVAILABLE");
        OUTPUT_LOCK_OPEN_TRACE.with(|trace| {
            assert_eq!(
                trace.borrow().as_slice(),
                ["path-inspected"],
                "non-regular state must be rejected after path-only inspection and before data open"
            );
        });
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn retained_state_workflows_reject_special_files_before_target_data_open() {
        use nix::sys::stat::Mode;
        use nix::unistd::mkfifo;
        use std::time::Duration;

        fn clear_trace() {
            VERIFIED_FILE_OPEN_TRACE.with(|trace| trace.borrow_mut().clear());
        }

        fn target_events(path: &Path) -> Vec<&'static str> {
            VERIFIED_FILE_OPEN_TRACE.with(|trace| {
                trace
                    .borrow()
                    .iter()
                    .filter_map(|(opened, event)| (opened == path).then_some(*event))
                    .collect()
            })
        }

        fn published_fixture() -> (Fixture, ResolutionStore, ResolutionClaim) {
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
                    Instant::now() + Duration::from_secs(60),
                )
                .expect("published receipt");
            (fixture, store, claim)
        }

        let fixture = Fixture::new();
        let store = fixture.store();
        let claim_path = store
            .claim_path(Uuid::parse_str(&fixture.request.resolution_id).expect("resolution UUID"));
        mkfifo(&claim_path, Mode::S_IRUSR | Mode::S_IWUSR).expect("claim fifo");
        clear_trace();
        let error = store
            .claim_or_replay(&fixture.request, &fixture.admitted, &fixture.plan)
            .expect_err("claim workflow must reject FIFO state");
        assert_eq!(error.code, "DEP_STORE_FILE_POLICY_DENIED");
        assert_eq!(target_events(&claim_path), ["path-inspected"]);

        let (fixture, store, claim) = published_fixture();
        let receipt_path = store.receipt_path(claim.resolution_id);
        std::fs::remove_file(&receipt_path).expect("remove receipt fixture");
        mkfifo(&receipt_path, Mode::S_IRUSR).expect("receipt fifo");
        clear_trace();
        let error = store
            .load_completed(claim.resolution_id, &fixture.admitted.request_sha256)
            .expect_err("receipt workflow must reject FIFO state");
        assert_eq!(error.code, "DEP_STORE_FILE_POLICY_DENIED");
        assert_eq!(target_events(&receipt_path), ["path-inspected"]);

        let (fixture, store, claim) = published_fixture();
        let completion_path = store.completion_path(claim.resolution_id);
        std::fs::remove_file(&completion_path).expect("remove completion fixture");
        mkfifo(&completion_path, Mode::S_IRUSR).expect("completion fifo");
        clear_trace();
        let error = store
            .load_completed(claim.resolution_id, &fixture.admitted.request_sha256)
            .expect_err("completion workflow must reject FIFO state");
        assert_eq!(error.code, "DEP_STORE_FILE_POLICY_DENIED");
        assert_eq!(target_events(&completion_path), ["path-inspected"]);

        let (fixture, store, claim) = published_fixture();
        let ambiguity_path = store.ambiguity_path(claim.resolution_id);
        mkfifo(&ambiguity_path, Mode::S_IRUSR | Mode::S_IWUSR).expect("ambiguity fifo");
        clear_trace();
        let error = store
            .load_completed(claim.resolution_id, &fixture.admitted.request_sha256)
            .expect_err("ambiguity workflow must reject blocked replay");
        assert_eq!(error.code, "DEP_STORE_AMBIGUOUS_CLAIM");
        assert!(target_events(&ambiguity_path).is_empty());

        clear_trace();
        let started = Instant::now();
        let error = read_bounded_file(Path::new("/dev/null"), MAX_STATE_BYTES, 0o666)
            .expect_err("device state must fail closed");
        assert_eq!(error.code, "DEP_STORE_FILE_POLICY_DENIED");
        assert_eq!(target_events(Path::new("/dev/null")), ["path-inspected"]);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cleanup_chmods_and_traverses_only_pinned_entries_after_path_swaps() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = TempDir::new().expect("cleanup swap root");
        let private = root.path().join("private");
        std::fs::create_dir(&private).expect("private cleanup parent");
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700))
            .expect("private cleanup parent mode");
        let root_directory = open_pinned_cleanup_root(root.path()).expect("pinned cleanup root");

        let outside_file = root.path().join("outside-file");
        std::fs::write(&outside_file, b"outside").expect("outside file");
        std::fs::set_permissions(&outside_file, std::fs::Permissions::from_mode(0o400))
            .expect("outside file mode");
        let target_file = private.join("claim.json");
        std::fs::write(&target_file, b"claim").expect("cleanup target file");
        std::fs::set_permissions(&target_file, std::fs::Permissions::from_mode(0o400))
            .expect("cleanup target file mode");
        let file_backup = private.join("claim.backup");
        CLEANUP_SWAP_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some((
                target_file.clone(),
                outside_file.clone(),
                file_backup.clone(),
            ));
        });
        remove_private_file(&root_directory, root.path(), &target_file)
            .expect_err("swapped cleanup file identity");
        assert_eq!(
            std::fs::metadata(&outside_file)
                .expect("outside file metadata")
                .permissions()
                .mode()
                & 0o777,
            0o400,
            "cleanup must not chmod a symlink replacement target"
        );
        assert!(file_backup.exists());
        assert!(
            std::fs::symlink_metadata(&target_file)
                .expect("swapped file entry")
                .file_type()
                .is_symlink()
        );

        let outside_directory = root.path().join("outside-directory");
        std::fs::create_dir(&outside_directory).expect("outside directory");
        std::fs::write(outside_directory.join("sentinel"), b"outside").expect("outside sentinel");
        std::fs::set_permissions(&outside_directory, std::fs::Permissions::from_mode(0o500))
            .expect("outside directory mode");
        let target_tree = private.join("bundle");
        std::fs::create_dir(&target_tree).expect("cleanup target tree");
        std::fs::write(target_tree.join("artifact"), b"artifact").expect("cleanup target artifact");
        std::fs::set_permissions(
            target_tree.join("artifact"),
            std::fs::Permissions::from_mode(0o400),
        )
        .expect("cleanup target artifact mode");
        std::fs::set_permissions(&target_tree, std::fs::Permissions::from_mode(0o500))
            .expect("cleanup target tree mode");
        let tree_backup = private.join("bundle.backup");
        CLEANUP_SWAP_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some((
                target_tree.clone(),
                outside_directory.clone(),
                tree_backup.clone(),
            ));
        });
        remove_private_tree(&root_directory, root.path(), &target_tree)
            .expect_err("swapped cleanup tree identity");
        assert_eq!(
            std::fs::metadata(&outside_directory)
                .expect("outside directory metadata")
                .permissions()
                .mode()
                & 0o777,
            0o500,
            "cleanup must not chmod a symlink replacement directory"
        );
        assert!(outside_directory.join("sentinel").exists());
        assert!(tree_backup.exists());
        assert!(
            std::fs::symlink_metadata(&target_tree)
                .expect("swapped tree entry")
                .file_type()
                .is_symlink()
        );
        std::fs::set_permissions(&outside_directory, std::fs::Permissions::from_mode(0o700))
            .expect("restore outside directory mode for fixture cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn exact_cleanup_never_adopts_a_replacement_at_final_selection() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let root = TempDir::new().expect("exact cleanup root");
        let private = root.path().join("private");
        std::fs::create_dir(&private).expect("private cleanup parent");
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700))
            .expect("private cleanup parent mode");
        let root_directory = open_pinned_cleanup_root(root.path()).expect("pinned cleanup root");

        let target_file = private.join("receipt.json");
        std::fs::write(&target_file, b"receipt").expect("exact target file");
        std::fs::set_permissions(&target_file, std::fs::Permissions::from_mode(0o400))
            .expect("exact target file mode");
        let file_identity = std::fs::metadata(&target_file).expect("target file metadata");
        let outside_file = root.path().join("outside-file");
        std::fs::write(&outside_file, b"outside").expect("outside file");
        std::fs::set_permissions(&outside_file, std::fs::Permissions::from_mode(0o400))
            .expect("outside file mode");
        let file_backup = private.join("receipt.backup");
        CLEANUP_PRE_INSPECTION_SWAP_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some((
                target_file.clone(),
                outside_file.clone(),
                file_backup.clone(),
            ));
        });
        let error = remove_private_file_exact(
            &root_directory,
            root.path(),
            &target_file,
            file_identity.dev(),
            file_identity.ino(),
        )
        .expect_err("exact file replacement");
        assert_eq!(error.code, "DEP_STORE_PUBLICATION_AMBIGUOUS");
        assert_eq!(
            std::fs::read(&outside_file).expect("outside file"),
            b"outside"
        );
        assert!(file_backup.exists());

        let target_tree = private.join("bundle");
        std::fs::create_dir(&target_tree).expect("exact target tree");
        std::fs::set_permissions(&target_tree, std::fs::Permissions::from_mode(0o500))
            .expect("exact target tree mode");
        let tree_identity = std::fs::metadata(&target_tree).expect("target tree metadata");
        let outside_tree = root.path().join("outside-tree");
        std::fs::create_dir(&outside_tree).expect("outside tree");
        std::fs::write(outside_tree.join("sentinel"), b"outside").expect("outside sentinel");
        std::fs::set_permissions(&outside_tree, std::fs::Permissions::from_mode(0o500))
            .expect("outside tree mode");
        let tree_backup = private.join("bundle.backup");
        CLEANUP_PRE_INSPECTION_SWAP_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some((
                target_tree.clone(),
                outside_tree.clone(),
                tree_backup.clone(),
            ));
        });
        let error = remove_private_tree_exact(
            &root_directory,
            root.path(),
            &target_tree,
            tree_identity.dev(),
            tree_identity.ino(),
        )
        .expect_err("exact tree replacement");
        assert_eq!(error.code, "DEP_STORE_PUBLICATION_AMBIGUOUS");
        assert!(outside_tree.join("sentinel").exists());
        assert!(tree_backup.exists());
        std::fs::set_permissions(&outside_tree, std::fs::Permissions::from_mode(0o700))
            .expect("restore outside tree mode");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cleanup_quarantines_the_final_selected_name_before_deletion() {
        let root = TempDir::new().expect("quarantine cleanup root");
        let private = root.path().join("private");
        std::fs::create_dir(&private).expect("private cleanup parent");
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700))
            .expect("private cleanup parent mode");
        let root_directory = open_pinned_cleanup_root(root.path()).expect("pinned cleanup root");

        let target_file = private.join("receipt.json");
        std::fs::write(&target_file, b"receipt").expect("exact target file");
        std::fs::set_permissions(&target_file, std::fs::Permissions::from_mode(0o400))
            .expect("exact target file mode");
        let file_identity = std::fs::metadata(&target_file).expect("target file metadata");
        let outside_file = root.path().join("outside-file-final");
        std::fs::write(&outside_file, b"outside").expect("outside file");
        let file_backup = private.join("receipt.final-backup");
        CLEANUP_FINAL_SWAP_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some((
                target_file.clone(),
                outside_file.clone(),
                file_backup.clone(),
            ));
        });
        let error = remove_private_file_exact(
            &root_directory,
            root.path(),
            &target_file,
            file_identity.dev(),
            file_identity.ino(),
        )
        .expect_err("final file exchange");
        assert_eq!(error.code, "DEP_STORE_PUBLICATION_AMBIGUOUS");
        assert_eq!(
            std::fs::read(&outside_file).expect("outside file"),
            b"outside"
        );
        assert!(file_backup.exists());

        let target_tree = private.join("bundle");
        std::fs::create_dir(&target_tree).expect("exact target tree");
        std::fs::set_permissions(&target_tree, std::fs::Permissions::from_mode(0o500))
            .expect("exact target tree mode");
        let tree_identity = std::fs::metadata(&target_tree).expect("target tree metadata");
        let outside_tree = root.path().join("outside-tree-final");
        std::fs::create_dir(&outside_tree).expect("outside tree");
        std::fs::write(outside_tree.join("sentinel"), b"outside").expect("outside sentinel");
        let tree_backup = private.join("bundle.final-backup");
        CLEANUP_FINAL_SWAP_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some((
                target_tree.clone(),
                outside_tree.clone(),
                tree_backup.clone(),
            ));
        });
        let error = remove_private_tree_exact(
            &root_directory,
            root.path(),
            &target_tree,
            tree_identity.dev(),
            tree_identity.ino(),
        )
        .expect_err("final tree exchange");
        assert_eq!(error.code, "DEP_STORE_PUBLICATION_AMBIGUOUS");
        assert!(outside_tree.join("sentinel").exists());
        assert!(tree_backup.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cleanup_detects_quarantine_replacement_before_unlink() {
        let root = TempDir::new().expect("pre-unlink cleanup root");
        let private = root.path().join("private");
        std::fs::create_dir(&private).expect("private cleanup parent");
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700))
            .expect("private cleanup parent mode");
        let root_directory = open_pinned_cleanup_root(root.path()).expect("pinned cleanup root");

        let target_file = private.join("receipt.json");
        std::fs::write(&target_file, b"receipt").expect("exact target file");
        std::fs::set_permissions(&target_file, std::fs::Permissions::from_mode(0o400))
            .expect("exact target file mode");
        let file_identity = std::fs::metadata(&target_file).expect("target file metadata");
        let outside_file = root.path().join("outside-file-pre-unlink");
        std::fs::write(&outside_file, b"outside").expect("outside file");
        let file_backup = private.join("receipt.pre-unlink-backup");
        CLEANUP_PRE_UNLINK_SWAP_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some((
                target_file.clone(),
                outside_file.clone(),
                file_backup.clone(),
            ));
        });
        let error = remove_private_file_exact(
            &root_directory,
            root.path(),
            &target_file,
            file_identity.dev(),
            file_identity.ino(),
        )
        .expect_err("pre-unlink file exchange");
        assert_eq!(error.code, "DEP_STORE_PUBLICATION_AMBIGUOUS");
        assert_eq!(
            std::fs::read(&outside_file).expect("outside file survives"),
            b"outside"
        );
        assert_eq!(
            std::fs::read(&file_backup).expect("exact file survives"),
            b"receipt"
        );

        let target_tree = private.join("bundle");
        std::fs::create_dir(&target_tree).expect("exact target tree");
        std::fs::set_permissions(&target_tree, std::fs::Permissions::from_mode(0o500))
            .expect("exact target tree mode");
        let tree_identity = std::fs::metadata(&target_tree).expect("target tree metadata");
        let outside_tree = root.path().join("outside-tree-pre-unlink");
        std::fs::create_dir(&outside_tree).expect("outside tree");
        std::fs::write(outside_tree.join("sentinel"), b"outside").expect("outside sentinel");
        let tree_backup = private.join("bundle.pre-unlink-backup");
        CLEANUP_PRE_UNLINK_SWAP_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some((
                target_tree.clone(),
                outside_tree.clone(),
                tree_backup.clone(),
            ));
        });
        let error = remove_private_tree_exact(
            &root_directory,
            root.path(),
            &target_tree,
            tree_identity.dev(),
            tree_identity.ino(),
        )
        .expect_err("pre-unlink tree exchange");
        assert_eq!(error.code, "DEP_STORE_PUBLICATION_AMBIGUOUS");
        assert!(outside_tree.join("sentinel").exists());
        assert!(tree_backup.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cleanup_stays_beneath_the_pinned_root_after_root_path_replacement() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let outer = TempDir::new().expect("cleanup root replacement fixture");
        let store_root = outer.path().join("store");
        let claims = store_root.join("claims");
        std::fs::create_dir_all(&claims).expect("store claims");
        let trusted_claim = claims.join("claim.json");
        std::fs::write(&trusted_claim, b"trusted").expect("trusted claim");
        std::fs::set_permissions(&trusted_claim, std::fs::Permissions::from_mode(0o400))
            .expect("trusted claim mode");
        let root_directory =
            open_pinned_cleanup_root(&store_root).expect("pinned trusted store root");

        let outside_root = outer.path().join("outside");
        let outside_claims = outside_root.join("claims");
        std::fs::create_dir_all(&outside_claims).expect("outside claims");
        let outside_claim = outside_claims.join("claim.json");
        std::fs::write(&outside_claim, b"outside").expect("outside claim");
        std::fs::set_permissions(&outside_claim, std::fs::Permissions::from_mode(0o400))
            .expect("outside claim mode");

        let pinned_backup = outer.path().join("store-pinned");
        std::fs::rename(&store_root, &pinned_backup).expect("move trusted store root");
        symlink(&outside_root, &store_root).expect("replace store pathname");
        remove_private_file(&root_directory, &store_root, &trusted_claim)
            .expect("cleanup through pinned root");

        assert!(!pinned_backup.join("claims/claim.json").exists());
        assert_eq!(
            std::fs::read(&outside_claim).expect("outside claim"),
            b"outside"
        );
        assert_eq!(
            std::fs::metadata(&outside_claim)
                .expect("outside claim metadata")
                .permissions()
                .mode()
                & 0o777,
            0o400
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cleanup_name_collection_enforces_the_cap_during_iteration() {
        use nix::fcntl::OFlag;
        use nix::sys::stat::Mode;

        let root = TempDir::new().expect("cleanup entry cap fixture");
        for name in ["one", "two", "three"] {
            std::fs::write(root.path().join(name), name).expect("cleanup cap entry");
        }
        let mut directory = nix::dir::Dir::open(
            root.path(),
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .expect("cleanup cap directory");
        let mut entries = 1_usize;
        collect_cleanup_names(&mut directory, &mut entries, 3)
            .expect_err("fourth admitted entry must fail during iteration");
        assert_eq!(entries, 3);
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

    #[cfg(target_os = "linux")]
    #[test]
    fn replay_admission_bounds_lock_contention_and_serializes_blocker_retry() {
        use std::sync::mpsc;
        use std::time::Duration;

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
                Instant::now() + Duration::from_secs(60),
            )
            .expect("published receipt");

        let loaded = store
            .load_receipt(claim.resolution_id)
            .expect("load completed receipt")
            .expect("completed receipt");
        REPLAY_NAMESPACE_TRACE
            .lock()
            .expect("replay trace")
            .retain(|(resolution_id, _)| *resolution_id != claim.resolution_id);

        let receipt_path = store.receipt_path(claim.resolution_id);
        let (lock_tx, lock_rx) = mpsc::channel();
        *RECEIPT_LOCK_TEST_HOOK.lock().expect("receipt-lock hook") = Some((receipt_path, lock_tx));
        let writer_store = store.clone();
        let writer_claim = claim.clone();
        let started = Instant::now();
        let writer = std::thread::spawn(move || {
            writer_store
                .ensure_exact_claim(&writer_claim)
                .expect_err("contended blocker lock must fail closed")
        });
        assert_eq!(lock_rx.recv().expect("writer lock attempt"), "attempt");
        let contention = writer.join().expect("contended blocker writer");
        assert_eq!(contention.code, "DEP_STORE_STATE_UNAVAILABLE");
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(
            !store.claim_path(claim.resolution_id).exists(),
            "contended blocker writer must fail before linking state"
        );

        let replay = store
            .admit_loaded_receipt(loaded, &fixture.admitted.request_sha256)
            .expect("serialized replay admission");
        assert_eq!(replay.resolution_id, claim.resolution_id);
        store
            .ensure_exact_claim(&claim)
            .expect("blocker retry after replay admission");
        assert_eq!(lock_rx.recv().expect("retry lock attempt"), "attempt");
        assert_eq!(lock_rx.recv().expect("writer lock acquisition"), "acquired");
        assert!(store.claim_path(claim.resolution_id).exists());
        let events = REPLAY_NAMESPACE_TRACE
            .lock()
            .expect("replay trace")
            .iter()
            .filter_map(|(resolution_id, event)| {
                (*resolution_id == claim.resolution_id).then_some(*event)
            })
            .collect::<Vec<_>>();
        assert_eq!(events, ["replay-admitted", "blocker-created"]);
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
            std::fs::read_dir(&store.inner.claims_root)
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
    fn complete_serialized_error_envelope_is_marker_scanned() {
        let fixture = Fixture::new();
        let store =
            fixture.store_with_markers(vec![fixture.receipt_key.clone(), b"dependency".to_vec()]);
        let response = br#"{"status":"error","code":"DEP_REQUEST_INVALID","message":"dependency resolution was denied"}\n"#;
        let mut guard = store.serialized_output_guard();
        assert!(!guard.admit(response));
        let mut guard = store.serialized_output_guard();
        assert!(guard.admit(
            br#"{"status":"error","code":"DEP_REQUEST_INVALID","message":"request denied"}\n"#
        ));
    }

    #[test]
    fn serialized_output_guard_blocks_a_marker_spanning_frames() {
        let fixture = Fixture::new();
        let marker = b"tail\"}\n{\"status".to_vec();
        let store = fixture.store_with_markers(vec![fixture.receipt_key.clone(), marker]);
        let first = b"{\"message\":\"safe-tail\"}\n";
        let second = b"{\"status\":\"error\"}\n";
        assert!(!contains_bytes(first, b"tail\"}\n{\"status"));
        assert!(!contains_bytes(second, b"tail\"}\n{\"status"));

        let mut guard = store.serialized_output_guard();
        assert!(guard.admit(first));
        assert!(!guard.admit(second));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn replay_revalidates_exact_receipt_and_completion_links_after_tree_verification() {
        fn loaded_fixture() -> (Fixture, ResolutionStore, ResolutionClaim, LoadedReceipt) {
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
            let loaded = store
                .load_receipt(claim.resolution_id)
                .expect("load receipt pair")
                .expect("completed receipt pair");
            (fixture, store, claim, loaded)
        }

        let (fixture, store, claim, loaded) = loaded_fixture();
        let completion_path = store.completion_path(claim.resolution_id);
        let completion_bytes = std::fs::read(&completion_path).expect("completion bytes");
        std::fs::remove_file(&completion_path).expect("unlink completion");
        write_new_file(&completion_path, &completion_bytes).expect("replacement completion");
        set_mode_and_sync(&completion_path, 0o400).expect("seal replacement completion");
        let completion_error = store
            .admit_loaded_receipt(loaded, &fixture.admitted.request_sha256)
            .expect_err("replacement completion link must fail replay");
        assert_eq!(completion_error.code, "DEP_STORE_AMBIGUOUS_COMPLETION");

        let (fixture, store, claim, loaded) = loaded_fixture();
        let receipt_path = store.receipt_path(claim.resolution_id);
        let receipt_bytes = std::fs::read(&receipt_path).expect("receipt bytes");
        std::fs::remove_file(&receipt_path).expect("unlink locked receipt");
        write_new_file(&receipt_path, &receipt_bytes).expect("replacement receipt");
        set_mode_and_sync(&receipt_path, 0o400).expect("seal replacement receipt");
        let receipt_error = store
            .admit_loaded_receipt(loaded, &fixture.admitted.request_sha256)
            .expect_err("replacement receipt link must fail replay");
        assert_eq!(receipt_error.code, "DEP_STORE_AMBIGUOUS_COMPLETION");

        let (fixture, store, claim, loaded) = loaded_fixture();
        let completion_path = store.completion_path(claim.resolution_id);
        let mut completion_bytes = std::fs::read(&completion_path).expect("completion bytes");
        let digest_prefix = b"\"receipt_hmac_sha256\":\"";
        let digest_start = completion_bytes
            .windows(digest_prefix.len())
            .position(|window| window == digest_prefix)
            .map(|index| index + digest_prefix.len())
            .expect("completion digest field");
        completion_bytes[digest_start] = if completion_bytes[digest_start] == b'0' {
            b'1'
        } else {
            b'0'
        };
        std::fs::set_permissions(&completion_path, std::fs::Permissions::from_mode(0o600))
            .expect("make completion writable");
        std::fs::write(&completion_path, completion_bytes).expect("mutate completion in place");
        std::fs::set_permissions(&completion_path, std::fs::Permissions::from_mode(0o400))
            .expect("reseal mutated completion");
        let mutation_error = store
            .admit_loaded_receipt(loaded, &fixture.admitted.request_sha256)
            .expect_err("in-place completion mutation must fail replay");
        assert_eq!(mutation_error.code, "DEP_STORE_AMBIGUOUS_COMPLETION");
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
        remove_private_file(
            &store.inner.claims_directory,
            &store.inner.claims_root,
            &store.claim_path(claim.resolution_id),
        )
        .expect("remove test claim");
        sync_directory(&store.inner.claims_root).expect("sync test claim removal");

        remove_private_file(
            &store.inner.completions_directory,
            &store.inner.completions_root,
            &store.completion_path(claim.resolution_id),
        )
        .expect("remove completion record");
        sync_directory(&store.inner.completions_root).expect("sync completion removal");
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

    #[cfg(target_os = "linux")]
    #[test]
    fn permanent_commit_prevents_pair_swap_from_withdrawing_delivery_blocker() {
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
        let receipt_path = store.receipt_path(claim.resolution_id);
        let held_receipt = store.inner.receipts_root.join("held-commit-pair.json");
        std::fs::rename(&receipt_path, &held_receipt).expect("move committed receipt");
        write_new_json(&receipt_path, &receipt, 0o400).expect("identical replacement receipt");
        let replacement_receipt =
            open_verified_file(&receipt_path, MAX_STATE_BYTES, 0o400).expect("replacement receipt");
        let mut forged_commit = store
            .read_publication_commit(claim.resolution_id)
            .expect("original authenticated commit");
        forged_commit.receipt_identity =
            verified_file_fingerprint(&replacement_receipt, MAX_STATE_BYTES, 0o400)
                .expect("replacement receipt fingerprint");
        let commit_path = store.commit_path(claim.resolution_id);
        let held_commit = store
            .inner
            .commits_root
            .join("held-authenticated-commit.json");
        std::fs::rename(&commit_path, &held_commit).expect("move authenticated commit");
        write_new_json(&commit_path, &forged_commit, 0o400).expect("forged replacement commit");

        let error = store
            .acknowledge_delivery(&claim)
            .expect_err("replacement pair cannot withdraw the delivery blocker");
        assert_eq!(error.code, "DEP_STORE_PUBLICATION_AMBIGUOUS");
        assert!(
            store.ambiguity_path(claim.resolution_id).exists(),
            "delivery ambiguity remains durable"
        );
        assert!(
            store.commit_path(claim.resolution_id).exists(),
            "forged commit remains explicit for diagnosis"
        );
        let replay_error = store
            .load_completed(claim.resolution_id, &fixture.admitted.request_sha256)
            .expect_err("pair substitution remains explicitly blocked");
        assert_eq!(replay_error.code, "DEP_STORE_AMBIGUOUS_CLAIM");
        assert!(
            held_receipt.exists(),
            "the committed receipt remains explicit"
        );
        assert!(
            held_commit.exists(),
            "the authenticated commit remains explicit"
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

    #[cfg(target_os = "linux")]
    #[test]
    fn receipt_withdrawal_refuses_a_relinked_private_file() {
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
            .expect("published receipt");
        let receipt_path = store.receipt_path(receipt.resolution_id);
        let bundle_path = store.bundle_path(receipt.resolution_id);
        let receipt_identity = directory_device_inode(
            &open_verified_file(&receipt_path, MAX_STATE_BYTES, 0o400).expect("published receipt"),
        )
        .expect("receipt identity");
        let bundle_identity =
            directory_device_inode(&File::open(&bundle_path).expect("published bundle directory"))
                .expect("bundle identity");
        let held_receipt = store.inner.receipts_root.join("held-receipt.json");
        std::fs::rename(&receipt_path, &held_receipt).expect("move published receipt");
        write_new_file(&receipt_path, b"replacement")
            .expect("replacement receipt")
            .set_permissions(std::fs::Permissions::from_mode(0o400))
            .expect("seal replacement receipt");

        let error = store
            .withdraw_publication_exact(
                &receipt_path,
                &bundle_path,
                Some(receipt_identity),
                bundle_identity,
            )
            .expect_err("relinked receipt withdrawal");
        assert_eq!(error.code, "DEP_STORE_PUBLICATION_AMBIGUOUS");
        assert!(receipt_path.exists(), "replacement must not be deleted");
        assert!(
            held_receipt.exists(),
            "published inode must remain explicit"
        );
        assert!(
            bundle_path.exists(),
            "bundle must remain paired on ambiguity"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn claim_commit_revalidates_the_exact_durable_pair() {
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
            .expect("published receipt");
        let receipt_path = store.receipt_path(receipt.resolution_id);
        let completion_path = store.completion_path(receipt.resolution_id);
        let receipt_file =
            open_verified_file(&receipt_path, MAX_STATE_BYTES, 0o400).expect("pinned receipt");
        let receipt_identity = verified_file_fingerprint(&receipt_file, MAX_STATE_BYTES, 0o400)
            .expect("receipt fingerprint");
        let completion_file = open_verified_file(&completion_path, MAX_STATE_BYTES, 0o400)
            .expect("pinned completion");
        let completion_identity =
            verified_file_fingerprint(&completion_file, MAX_STATE_BYTES, 0o400)
                .expect("completion fingerprint");

        let held_receipt = store.inner.receipts_root.join("held-commit-receipt.json");
        std::fs::rename(&receipt_path, &held_receipt).expect("move exact receipt");
        write_new_json(&receipt_path, &receipt, 0o400).expect("replacement receipt");
        let receipt_error = revalidate_publication_pair(
            &receipt_path,
            &receipt_file,
            &receipt_identity,
            &completion_path,
            &completion_file,
            &completion_identity,
        )
        .expect_err("replacement receipt must prevent claim commit");
        assert_eq!(receipt_error.code, "DEP_STORE_AMBIGUOUS_COMPLETION");
        std::fs::remove_file(&receipt_path).expect("remove replacement receipt");
        std::fs::rename(&held_receipt, &receipt_path).expect("restore exact receipt");

        let held_completion = store
            .inner
            .completions_root
            .join("held-commit-completion.json");
        std::fs::rename(&completion_path, &held_completion).expect("move exact completion");
        let completion_error = revalidate_publication_pair(
            &receipt_path,
            &receipt_file,
            &receipt_identity,
            &completion_path,
            &completion_file,
            &completion_identity,
        )
        .expect_err("missing completion must prevent claim commit");
        assert_eq!(completion_error.code, "DEP_STORE_AMBIGUOUS_COMPLETION");
        assert!(
            held_completion.exists(),
            "the exact completion remains explicit"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn exact_withdrawal_refuses_missing_receipt_and_completion_links() {
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
            .expect("published receipt");
        let receipt_path = store.receipt_path(receipt.resolution_id);
        let completion_path = store.completion_path(receipt.resolution_id);
        let bundle_path = store.bundle_path(receipt.resolution_id);
        let receipt_identity = directory_device_inode(
            &open_verified_file(&receipt_path, MAX_STATE_BYTES, 0o400).expect("published receipt"),
        )
        .expect("receipt identity");
        let completion_identity = directory_device_inode(
            &open_verified_file(&completion_path, MAX_STATE_BYTES, 0o400)
                .expect("published completion"),
        )
        .expect("completion identity");
        let bundle_identity =
            directory_device_inode(&File::open(&bundle_path).expect("published bundle directory"))
                .expect("bundle identity");
        let held_receipt = store.inner.receipts_root.join("held-missing-receipt.json");
        std::fs::rename(&receipt_path, &held_receipt).expect("move published receipt");

        let receipt_error = store
            .withdraw_publication_exact(
                &receipt_path,
                &bundle_path,
                Some(receipt_identity),
                bundle_identity,
            )
            .expect_err("missing exact receipt link");
        assert_eq!(receipt_error.code, "DEP_STORE_PUBLICATION_AMBIGUOUS");
        assert!(held_receipt.exists());
        assert!(bundle_path.exists(), "bundle remains paired on ambiguity");

        let held_completion = store
            .inner
            .completions_root
            .join("held-missing-completion.json");
        std::fs::rename(&completion_path, &held_completion).expect("move published completion");
        let completion_error = store
            .remove_completion_exact(&completion_path, completion_identity)
            .expect_err("missing exact completion link");
        assert_eq!(completion_error.code, "DEP_STORE_PUBLICATION_AMBIGUOUS");
        assert!(held_completion.exists());
    }

    #[test]
    fn uncertain_receipt_lookup_retains_the_publication_bundle() {
        let fixture = Fixture::new();
        let store = fixture.store();
        let blocker =
            pinned_directory_path(&store.inner.root_directory).join("receipt-lookup-blocker");
        std::fs::write(&blocker, b"not a directory").expect("lookup blocker");
        let receipt_path = blocker.join("receipt.json");
        let bundle_path = store.inner.bundles_root.join("uncertain");
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
        let _receipt = store
            .publish(
                &claim,
                fixture.request.clone(),
                &fixture.admitted,
                fixture.plan.clone(),
                &fixture.fetched,
                Instant::now() + std::time::Duration::from_secs(60),
            )
            .expect("publication");
        let archive_path = store.bundle_path(claim.resolution_id);
        std::fs::set_permissions(&archive_path, std::fs::Permissions::from_mode(0o600))
            .expect("make archive mutable for adversarial fixture");
        let mut archive = OpenOptions::new()
            .append(true)
            .open(&archive_path)
            .expect("open archive for substitution");
        archive
            .write_all(b"substituted")
            .expect("substitute archive");
        archive.sync_all().expect("sync substituted archive");
        std::fs::set_permissions(&archive_path, std::fs::Permissions::from_mode(0o400))
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

    #[cfg(target_os = "linux")]
    #[test]
    fn publication_rejects_unmanifested_entries_before_signing_the_tree() {
        let fixture = Fixture::new();
        let store = fixture.store();
        let claim = match store
            .claim_or_replay(&fixture.request, &fixture.admitted, &fixture.plan)
            .expect("new claim")
        {
            ClaimOutcome::New(claim) => claim,
            other => panic!("unexpected claim outcome: {other:?}"),
        };
        RETAINED_TREE_PRE_SCAN_INJECTION_TEST_HOOK.with(|hook| hook.set(true));

        let error = store
            .publish(
                &claim,
                fixture.request.clone(),
                &fixture.admitted,
                fixture.plan.clone(),
                &fixture.fetched,
                Instant::now() + std::time::Duration::from_secs(60),
            )
            .expect_err("unmanifested retained entry");
        assert_eq!(error.code, "DEP_STORE_RETAINED_TREE_MISMATCH");
        assert_eq!(
            error.message,
            "retained dependency archive is malformed, incomplete, or has been substituted"
        );
        assert!(!store.bundle_path(claim.resolution_id).exists());
        assert!(!store.receipt_path(claim.resolution_id).exists());
        assert!(!store.completion_path(claim.resolution_id).exists());
    }

    #[test]
    fn retained_tree_scan_bounds_entries_and_depth_before_descending() {
        let root = TempDir::new().expect("retained tree root");
        let output = root.path().join("output");
        let bundles = output.join("bundles");
        let tree = bundles.join("tree");
        let first = tree.join("first");
        let nested = first.join("nested");
        let second = tree.join("second");
        std::fs::create_dir(&output).expect("output");
        std::fs::create_dir(&bundles).expect("bundles");
        std::fs::create_dir(&tree).expect("tree");
        std::fs::create_dir(&first).expect("first");
        std::fs::create_dir(&nested).expect("nested");
        std::fs::create_dir(&second).expect("second");
        for directory in [&output, &bundles] {
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
                .expect("private retained ancestor");
        }
        for directory in [&tree, &first, &nested, &second] {
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o500))
                .expect("seal retained directory");
        }
        let output_directory = open_pinned_cleanup_root(&output).expect("pinned output root");
        let bundles_directory =
            open_store_directory(&output_directory, "bundles").expect("pinned bundles root");

        let scan = |limits| {
            retained_tree_evidence_with_limits(
                &output_directory,
                &bundles_directory,
                "tree",
                1,
                1,
                limits,
            )
        };
        let entry_error = scan(RetainedTreeLimits {
            max_entries: 2,
            max_depth: 8,
        })
        .expect_err("entry cap");
        assert_eq!(entry_error.code, "DEP_STORE_RETAINED_TREE_MISMATCH");

        let depth_error = scan(RetainedTreeLimits {
            max_entries: 8,
            max_depth: 1,
        })
        .expect_err("depth cap");
        assert_eq!(depth_error.code, "DEP_STORE_RETAINED_TREE_MISMATCH");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn replay_rejects_a_retained_archive_relinked_after_descriptor_verification() {
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
            .expect("published receipt");
        let archive = PathBuf::from(&fixture.config.output_root)
            .join("bundles")
            .join(format!("{}.bundle", claim.resolution_id));
        let moved = archive
            .parent()
            .expect("retained bundle root")
            .join("moved-retained-archive.bundle");
        RETAINED_TREE_SWAP_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some((archive.clone(), moved.clone()));
        });

        let error = store
            .verify_replay(&receipt, &fixture.admitted.request_sha256)
            .expect_err("relinked retained archive must fail replay");
        assert!(
            moved.is_file(),
            "the originally inspected archive was moved"
        );
        assert!(
            std::fs::symlink_metadata(&archive)
                .expect("replacement retained entry")
                .file_type()
                .is_symlink(),
            "the mutable pathname was replaced only after descriptor verification"
        );
        assert_eq!(
            error.code, "DEP_STORE_RETAINED_TREE_MISMATCH",
            "unexpected relink denial: {error}"
        );
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
        let next_transient = PathBuf::from(&fixture.config.transport_root)
            .join(format!(".{}.transport", fixture.request.resolution_id));
        std::fs::write(&next_transient, b"contained published artifact")
            .expect("rotated transient artifact");
        std::fs::set_permissions(&next_transient, std::fs::Permissions::from_mode(0o600))
            .expect("rotated transient mode");
        fixture.fetched[0].transient_path =
            PathBuf::from(format!(".{}.transport", fixture.request.resolution_id));
        let next_metadata = std::fs::metadata(&next_transient).expect("rotated transport metadata");
        fixture.fetched[0].transient_root_device = next_metadata.dev();
        fixture.fetched[0].transient_root_inode = next_metadata.ino();
    }
}
