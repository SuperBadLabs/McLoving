use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use reqwest::header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, HeaderValue};
use reqwest::{Client, StatusCode, Url};
use ring::signature::{ED25519, UnparsedPublicKey};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::AsyncWriteExt as _;
use uuid::Uuid;

use crate::{CanonicalPlan, CertifiedConfig, LoadedAuthorities, PackageNode};

const REPOSITORY_HEADER: &str = "x-mcloving-repository-id";
const ATTESTATION_HEADER: &str = "x-mcloving-attestation";
const GENERATION_HEADER: &str = "x-mcloving-publication-generation";
const TRANSPORT_LOCK_CONTENT: &[u8] = b"mcloving-dependency-transport-lock/v1\n";

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct FetchedArtifact {
    pub node_id: String,
    pub transient_path: PathBuf,
    pub declared_size: u64,
    pub sha256: String,
    pub attestation_sha256: String,
    pub publication_generation: u64,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("{code}: {message}")]
pub struct TransportError {
    pub code: &'static str,
    pub message: String,
}

impl TransportError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

struct RepositoryRuntime {
    base_url: Url,
    client: Client,
    authorization: Option<HeaderValue>,
    attestation_key_id: String,
    attestation_key: Vec<u8>,
}

pub struct HttpTransport {
    generation: u64,
    max_header_bytes: u64,
    max_artifact_bytes: u64,
    max_total_artifact_bytes: u64,
    transport_root: PathBuf,
    markers: Vec<Vec<u8>>,
    repositories: BTreeMap<String, RepositoryRuntime>,
    cleanup_poisoned: AtomicBool,
    _lease: Option<TransportLease>,
}

impl HttpTransport {
    pub fn new(
        config: &CertifiedConfig,
        authorities: &LoadedAuthorities,
    ) -> Result<Self, TransportError> {
        crate::validate_config(config)
            .map_err(|error| TransportError::new(error.code, error.message))?;
        let lease = TransportLease::acquire(config)?;
        let markers = authorities
            .markers()
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        let mut repositories = BTreeMap::new();
        for repository in &config.repositories {
            let base_url = Url::parse(&repository.base_url).map_err(|_| {
                TransportError::new("DEP_TRANSPORT_CONFIG_INVALID", "repository URL is invalid")
            })?;
            let mut builder = Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .no_proxy()
                .no_gzip()
                .no_brotli()
                .no_deflate()
                .no_zstd()
                .pool_max_idle_per_host(0)
                .user_agent("mcloving-dependency-resolver/1");
            if let Some(ca) = authorities.repository_private_ca(&repository.repository_id) {
                let certificate = reqwest::Certificate::from_pem(ca).map_err(|_| {
                    TransportError::new(
                        "DEP_TRANSPORT_CA_INVALID",
                        "repository private CA is not a valid PEM certificate",
                    )
                })?;
                builder = builder
                    .add_root_certificate(certificate)
                    .tls_built_in_root_certs(false);
            }
            let client = builder.build().map_err(|_| {
                TransportError::new(
                    "DEP_TRANSPORT_CLIENT_INVALID",
                    "repository client could not be constructed",
                )
            })?;
            let authorization = authorities
                .repository_credential(&repository.repository_id)
                .map(|credential| {
                    let mut header = HeaderValue::from_bytes(credential).map_err(|_| {
                        TransportError::new(
                            "DEP_TRANSPORT_CREDENTIAL_INVALID",
                            "repository credential cannot be represented as one authorization value",
                        )
                    })?;
                    header.set_sensitive(true);
                    Ok::<_, TransportError>(header)
                })
                .transpose()?;
            let attestation_key = authorities
                .repository_attestation_key(&repository.repository_id)
                .ok_or_else(|| {
                    TransportError::new(
                        "DEP_TRANSPORT_ATTESTATION_KEY_MISSING",
                        "repository attestation key was not loaded",
                    )
                })?
                .to_vec();
            if attestation_key.len() != 32 {
                return Err(TransportError::new(
                    "DEP_TRANSPORT_ATTESTATION_KEY_INVALID",
                    "repository Ed25519 public key must be exactly 32 bytes",
                ));
            }
            repositories.insert(
                repository.repository_id.clone(),
                RepositoryRuntime {
                    base_url,
                    client,
                    authorization,
                    attestation_key_id: repository.attestation_key_id.clone(),
                    attestation_key,
                },
            );
        }
        Ok(Self {
            generation: config.generation,
            max_header_bytes: config.limits.max_header_bytes,
            max_artifact_bytes: config.limits.max_artifact_bytes,
            max_total_artifact_bytes: config.limits.max_total_artifact_bytes,
            transport_root: PathBuf::from(&config.transport_root),
            markers,
            repositories,
            cleanup_poisoned: AtomicBool::new(false),
            _lease: Some(lease),
        })
    }

    pub fn ensure_available(&self) -> Result<(), TransportError> {
        if self.cleanup_poisoned.load(Ordering::Acquire) {
            Err(TransportError::new(
                "DEP_TRANSPORT_CLEANUP_RESTART_REQUIRED",
                "transport cleanup is ambiguous and requires resolver restart",
            ))
        } else {
            Ok(())
        }
    }

    pub fn preserve_cleanup_ambiguity(&self) {
        self.cleanup_poisoned.store(true, Ordering::Release);
    }

    pub async fn fetch_plan(
        &self,
        resolution_id: Uuid,
        plan: &CanonicalPlan,
        deadline: Instant,
    ) -> Result<Vec<FetchedArtifact>, TransportError> {
        self.ensure_available()?;
        crate::validate_plan(plan)
            .map_err(|error| TransportError::new(error.code, error.message))?;
        let total = plan.nodes.iter().try_fold(0_u64, |total, node| {
            if node.declared_size > self.max_artifact_bytes {
                None
            } else {
                total.checked_add(node.declared_size)
            }
        });
        if total.is_none_or(|total| total > self.max_total_artifact_bytes) {
            return Err(TransportError::new(
                "DEP_TRANSPORT_AGGREGATE_LIMIT",
                "artifact plan exceeds a certified per-artifact or aggregate bound",
            ));
        }
        let resolution_root = self.transport_root.join(resolution_id.to_string());
        run_transport_before_deadline(deadline, create_private_resolution_root(&resolution_root))
            .await
            .map_err(|error| preserve_transport_setup_error(&self.cleanup_poisoned, error))?;
        match self.fetch_plan_into(plan, deadline, &resolution_root).await {
            Ok(fetched) => Ok(fetched),
            Err(error) => {
                if Instant::now() >= deadline {
                    self.preserve_cleanup_ambiguity();
                    return Err(error);
                }
                self.cleanup_resolution_before_deadline(resolution_id, deadline)
                    .await?;
                Err(error)
            }
        }
    }

    pub async fn cleanup_resolution_before_deadline(
        &self,
        resolution_id: Uuid,
        deadline: Instant,
    ) -> Result<(), TransportError> {
        self.ensure_available()?;
        supervise_cleanup(
            &self.cleanup_poisoned,
            deadline,
            self.cleanup_resolution(resolution_id),
        )
        .await
    }

    async fn cleanup_resolution(&self, resolution_id: Uuid) -> Result<(), TransportError> {
        let resolution_root = self.transport_root.join(resolution_id.to_string());
        tokio::fs::remove_dir_all(&resolution_root)
            .await
            .map_err(|_| {
                TransportError::new(
                    "DEP_TRANSPORT_CLEANUP_AMBIGUOUS",
                    "verified transient resolution could not be removed",
                )
            })?;
        let root = self.transport_root.clone();
        tokio::task::spawn_blocking(move || {
            std::fs::File::open(root)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| {
                    TransportError::new(
                        "DEP_TRANSPORT_CLEANUP_AMBIGUOUS",
                        "transient cleanup directory entry could not be synchronized",
                    )
                })
        })
        .await
        .map_err(|_| {
            TransportError::new(
                "DEP_TRANSPORT_CLEANUP_AMBIGUOUS",
                "transient cleanup task did not complete",
            )
        })??;
        Ok(())
    }

    async fn fetch_plan_into(
        &self,
        plan: &CanonicalPlan,
        deadline: Instant,
        resolution_root: &Path,
    ) -> Result<Vec<FetchedArtifact>, TransportError> {
        let mut total = 0_u64;
        let mut fetched = Vec::with_capacity(plan.nodes.len());
        for node in &plan.nodes {
            total = total.checked_add(node.declared_size).ok_or_else(|| {
                TransportError::new(
                    "DEP_TRANSPORT_AGGREGATE_LIMIT",
                    "artifact aggregate size overflowed",
                )
            })?;
            if total > self.max_total_artifact_bytes {
                return Err(TransportError::new(
                    "DEP_TRANSPORT_AGGREGATE_LIMIT",
                    "artifact aggregate exceeds the certified transport bound",
                ));
            }
            fetched.push(
                self.fetch_node(plan.ecosystem, node, deadline, resolution_root)
                    .await?,
            );
        }
        Ok(fetched)
    }

    async fn fetch_node(
        &self,
        ecosystem: crate::Ecosystem,
        node: &PackageNode,
        deadline: Instant,
        resolution_root: &Path,
    ) -> Result<FetchedArtifact, TransportError> {
        let repository = self.repositories.get(&node.repository_id).ok_or_else(|| {
            TransportError::new(
                "DEP_TRANSPORT_REPOSITORY_UNCONFIGURED",
                "artifact references an unconfigured repository",
            )
        })?;
        let url = repository.base_url.join(&node.artifact_path).map_err(|_| {
            TransportError::new(
                "DEP_TRANSPORT_URL_INVALID",
                "artifact path could not be joined to its configured repository",
            )
        })?;
        if url.origin() != repository.base_url.origin()
            || !url.path().starts_with(repository.base_url.path())
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(TransportError::new(
                "DEP_TRANSPORT_ORIGIN_SUBSTITUTION",
                "artifact URL escaped its configured repository origin or path prefix",
            ));
        }
        let mut request = repository.client.get(url);
        if let Some(authorization) = &repository.authorization {
            request = request.header(AUTHORIZATION, authorization.clone());
        }
        let response = run_before_deadline(deadline, request.send()).await?;
        if response.status() != StatusCode::OK {
            return Err(TransportError::new(
                "DEP_TRANSPORT_RESPONSE_DENIED",
                "repository response status is not the exact admitted success status",
            ));
        }
        validate_headers(
            response.headers(),
            node,
            self.generation,
            self.max_header_bytes,
            &self.markers,
        )?;
        let signature = response
            .headers()
            .get(ATTESTATION_HEADER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| BASE64.decode(value).ok())
            .ok_or_else(|| {
                TransportError::new(
                    "DEP_TRANSPORT_ATTESTATION_INVALID",
                    "repository attestation is missing or malformed",
                )
            })?;
        let message = canonical_attestation_message(
            node,
            &repository.attestation_key_id,
            self.generation,
            ecosystem.as_str().as_bytes(),
        );
        UnparsedPublicKey::new(&ED25519, &repository.attestation_key)
            .verify(&message, &signature)
            .map_err(|_| {
                TransportError::new(
                    "DEP_TRANSPORT_ATTESTATION_INVALID",
                    "repository attestation does not verify for the exact artifact binding",
                )
            })?;

        let transient_path = resolution_root.join(format!("{}.part", node.node_id));
        let mut file =
            run_transport_before_deadline(deadline, create_private_file(&transient_path)).await?;
        let mut response = response;
        let mut hasher = Sha256::new();
        let mut received = 0_u64;
        let mut scanner = MarkerScanner::new(&self.markers);
        while let Some(chunk) = run_before_deadline(deadline, response.chunk()).await? {
            received = received.checked_add(chunk.len() as u64).ok_or_else(|| {
                TransportError::new("DEP_TRANSPORT_SIZE_MISMATCH", "artifact size overflowed")
            })?;
            if received > node.declared_size {
                return Err(TransportError::new(
                    "DEP_TRANSPORT_SIZE_MISMATCH",
                    "artifact body exceeds its declared size",
                ));
            }
            scanner.scan(&chunk)?;
            hasher.update(&chunk);
            run_before_deadline(deadline, file.write_all(&chunk)).await?;
        }
        if received != node.declared_size || format!("{:x}", hasher.finalize()) != node.sha256 {
            return Err(TransportError::new(
                "DEP_TRANSPORT_CONTENT_MISMATCH",
                "artifact size or content digest does not match the canonical plan",
            ));
        }
        run_before_deadline(deadline, file.sync_all()).await?;
        drop(file);
        verify_transient_file(&transient_path, node.declared_size, &node.sha256, deadline).await?;
        Ok(FetchedArtifact {
            node_id: node.node_id.clone(),
            transient_path,
            declared_size: received,
            sha256: node.sha256.clone(),
            attestation_sha256: format!("{:x}", Sha256::digest(&signature)),
            publication_generation: self.generation,
        })
    }
}

async fn supervise_cleanup<F>(
    cleanup_poisoned: &AtomicBool,
    deadline: Instant,
    cleanup: F,
) -> Result<(), TransportError>
where
    F: std::future::Future<Output = Result<(), TransportError>>,
{
    match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), cleanup).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            cleanup_poisoned.store(true, Ordering::Release);
            Err(error)
        }
        Err(_) => {
            cleanup_poisoned.store(true, Ordering::Release);
            Err(TransportError::new(
                "DEP_TRANSPORT_CLEANUP_AMBIGUOUS",
                "transient cleanup exceeded the absolute deadline and requires resolver restart",
            ))
        }
    }
}

#[cfg(unix)]
async fn verify_transient_file(
    path: &Path,
    expected_size: u64,
    expected_sha256: &str,
    deadline: Instant,
) -> Result<(), TransportError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use tokio::io::AsyncReadExt as _;

    let mut options = tokio::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(nix::fcntl::OFlag::O_CLOEXEC.bits() | nix::fcntl::OFlag::O_NOFOLLOW.bits());
    let mut file = run_before_deadline(deadline, options.open(path)).await?;
    let metadata = run_before_deadline(deadline, file.metadata()).await?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.len() != expected_size
    {
        return Err(TransportError::new(
            "DEP_TRANSPORT_CONTENT_MISMATCH",
            "persisted transient artifact size, type, owner, or mode changed",
        ));
    }
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 65_536];
    loop {
        let read = run_before_deadline(deadline, file.read(&mut buffer)).await?;
        if read == 0 {
            break;
        }
        total = total.checked_add(read as u64).ok_or_else(|| {
            TransportError::new(
                "DEP_TRANSPORT_CONTENT_MISMATCH",
                "persisted artifact size overflowed",
            )
        })?;
        if total > expected_size {
            return Err(TransportError::new(
                "DEP_TRANSPORT_CONTENT_MISMATCH",
                "persisted artifact exceeds its admitted size",
            ));
        }
        hasher.update(&buffer[..read]);
    }
    if total != expected_size || format!("{:x}", hasher.finalize()) != expected_sha256 {
        return Err(TransportError::new(
            "DEP_TRANSPORT_CONTENT_MISMATCH",
            "persisted transient artifact bytes changed after synchronization",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
async fn verify_transient_file(
    _path: &Path,
    _expected_size: u64,
    _expected_sha256: &str,
    _deadline: Instant,
) -> Result<(), TransportError> {
    Err(TransportError::new(
        "DEP_TRANSPORT_PLATFORM_UNSUPPORTED",
        "transient verification requires Unix file semantics",
    ))
}

fn validate_headers(
    headers: &reqwest::header::HeaderMap,
    node: &PackageNode,
    generation: u64,
    max_header_bytes: u64,
    markers: &[Vec<u8>],
) -> Result<(), TransportError> {
    let total = headers.iter().try_fold(0_u64, |total, (name, value)| {
        total
            .checked_add(name.as_str().len() as u64)
            .and_then(|value_total| value_total.checked_add(value.as_bytes().len() as u64))
    });
    if total.is_none_or(|total| total > max_header_bytes)
        || headers.iter().any(|(name, value)| {
            contains_marker(name.as_str().as_bytes(), markers)
                || contains_marker(value.as_bytes(), markers)
        })
    {
        return Err(TransportError::new(
            "DEP_TRANSPORT_HEADER_DENIED",
            "repository headers are oversized or contain a secret marker",
        ));
    }
    let content_length = headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    let content_type = headers.get(CONTENT_TYPE).map(HeaderValue::as_bytes);
    let repository_id = headers.get(REPOSITORY_HEADER).map(HeaderValue::as_bytes);
    let response_generation = headers
        .get(GENERATION_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if content_length != Some(node.declared_size)
        || content_type != Some(b"application/octet-stream".as_slice())
        || repository_id != Some(node.repository_id.as_bytes())
        || response_generation != Some(generation)
        || headers.get_all(ATTESTATION_HEADER).iter().count() != 1
        || headers.get_all(REPOSITORY_HEADER).iter().count() != 1
        || headers.get_all(GENERATION_HEADER).iter().count() != 1
        || headers.get_all(CONTENT_TYPE).iter().count() != 1
        || headers.get_all(CONTENT_LENGTH).iter().count() != 1
    {
        return Err(TransportError::new(
            "DEP_TRANSPORT_HEADER_DENIED",
            "repository headers do not match the exact artifact binding",
        ));
    }
    Ok(())
}

pub fn canonical_attestation_message(
    node: &PackageNode,
    key_id: &str,
    generation: u64,
    ecosystem: &[u8],
) -> Vec<u8> {
    let mut message = Vec::new();
    let declared_size = node.declared_size.to_be_bytes();
    let publication_generation = generation.to_be_bytes();
    for segment in [
        b"mcloving-dependency-attestation-v1".as_slice(),
        node.repository_id.as_bytes(),
        key_id.as_bytes(),
        ecosystem,
        node.coordinate.as_bytes(),
        node.exact_version.as_bytes(),
        node.artifact_path.as_bytes(),
        &declared_size,
        node.sha256.as_bytes(),
        &publication_generation,
    ] {
        message.extend_from_slice(&(segment.len() as u64).to_be_bytes());
        message.extend_from_slice(segment);
    }
    message
}

struct MarkerScanner<'a> {
    markers: &'a [Vec<u8>],
    tail: Vec<u8>,
    max_marker_len: usize,
}

impl<'a> MarkerScanner<'a> {
    fn new(markers: &'a [Vec<u8>]) -> Self {
        Self {
            markers,
            tail: Vec::new(),
            max_marker_len: markers.iter().map(Vec::len).max().unwrap_or(0),
        }
    }

    fn scan(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        let mut window = std::mem::take(&mut self.tail);
        window.extend_from_slice(bytes);
        if contains_marker(&window, self.markers) {
            return Err(TransportError::new(
                "DEP_TRANSPORT_SECRET_MARKER",
                "artifact body contains a configured secret marker",
            ));
        }
        let retain = self.max_marker_len.saturating_sub(1).min(window.len());
        self.tail = window.split_off(window.len() - retain);
        Ok(())
    }
}

fn contains_marker(bytes: &[u8], markers: &[Vec<u8>]) -> bool {
    markers.iter().any(|marker| {
        marker.len() <= bytes.len() && bytes.windows(marker.len()).any(|window| window == marker)
    })
}

#[cfg(target_os = "linux")]
type TransportRootLock = nix::fcntl::Flock<std::fs::File>;

#[cfg(not(target_os = "linux"))]
struct TransportRootLock;

struct TransportLease {
    _lock: TransportRootLock,
}

impl TransportLease {
    #[cfg(target_os = "linux")]
    fn acquire(config: &CertifiedConfig) -> Result<Self, TransportError> {
        use nix::fcntl::{Flock, FlockArg};
        use nix::sys::statvfs::statvfs;
        use nix::unistd::Uid;
        use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

        let root = Path::new(&config.transport_root);
        let output = Path::new(&config.output_root);
        let canonical = std::fs::canonicalize(root).map_err(|_| root_policy_error())?;
        let parent = root.parent().ok_or_else(root_policy_error)?;
        let root_metadata = std::fs::symlink_metadata(root).map_err(|_| root_policy_error())?;
        let parent_metadata = std::fs::metadata(parent).map_err(|_| root_policy_error())?;
        let output_metadata = std::fs::metadata(output).map_err(|_| root_policy_error())?;
        let filesystem = statvfs(root).map_err(|_| root_policy_error())?;
        let capacity = filesystem
            .blocks()
            .checked_mul(filesystem.fragment_size())
            .ok_or_else(root_policy_error)?;
        if canonical != root
            || !root_metadata.file_type().is_dir()
            || root_metadata.uid() != Uid::effective().as_raw()
            || root_metadata.permissions().mode() & 0o777 != 0o700
            || root_metadata.dev() == parent_metadata.dev()
            || root_metadata.dev() == output_metadata.dev()
            || capacity != config.limits.transport_capacity_bytes
        {
            return Err(root_policy_error());
        }

        let lock_path = root.join(".mcloving-dependency-resolver.lock");
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(
                nix::fcntl::OFlag::O_CLOEXEC.bits() | nix::fcntl::OFlag::O_NOFOLLOW.bits(),
            )
            .open(lock_path)
            .map_err(|_| root_state_error())?;
        let mut existing = Vec::new();
        file.read_to_end(&mut existing)
            .map_err(|_| root_state_error())?;
        if existing.is_empty() {
            file.seek(SeekFrom::Start(0))
                .and_then(|_| file.write_all(TRANSPORT_LOCK_CONTENT))
                .map_err(|_| root_state_error())?;
        } else if existing != TRANSPORT_LOCK_CONTENT {
            return Err(root_state_error());
        }
        let metadata = file.metadata().map_err(|_| root_state_error())?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(root_state_error());
        }
        file.sync_all().map_err(|_| root_state_error())?;
        std::fs::File::open(root)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| root_state_error())?;
        let lock =
            Flock::lock(file, FlockArg::LockExclusiveNonblock).map_err(|_| root_state_error())?;
        let mut entries = std::fs::read_dir(root).map_err(|_| root_state_error())?;
        let mut lock_seen = false;
        for entry in &mut entries {
            let entry = entry.map_err(|_| root_state_error())?;
            if entry.file_name() != ".mcloving-dependency-resolver.lock" || lock_seen {
                return Err(root_state_error());
            }
            if !entry.file_type().map_err(|_| root_state_error())?.is_file() {
                return Err(root_state_error());
            }
            lock_seen = true;
        }
        if !lock_seen {
            return Err(root_state_error());
        }
        Ok(Self { _lock: lock })
    }

    #[cfg(not(target_os = "linux"))]
    fn acquire(_config: &CertifiedConfig) -> Result<Self, TransportError> {
        Err(TransportError::new(
            "DEP_TRANSPORT_PLATFORM_UNSUPPORTED",
            "dedicated transport filesystem enforcement requires Linux",
        ))
    }
}

fn root_policy_error() -> TransportError {
    TransportError::new(
        "DEP_TRANSPORT_ROOT_POLICY_DENIED",
        "transport root mount, owner, mode, device, or exact capacity violates policy",
    )
}

fn root_state_error() -> TransportError {
    TransportError::new(
        "DEP_TRANSPORT_ROOT_STATE_DENIED",
        "transport root is locked, residual, or cannot be inspected safely",
    )
}

async fn run_before_deadline<F, T, E>(deadline: Instant, future: F) -> Result<T, TransportError>
where
    F: std::future::Future<Output = Result<T, E>>,
{
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| {
            TransportError::new(
                "DEP_TRANSPORT_DEADLINE",
                "absolute transport deadline expired",
            )
        })?;
    tokio::time::timeout(remaining, future)
        .await
        .map_err(|_| {
            TransportError::new(
                "DEP_TRANSPORT_DEADLINE",
                "absolute transport deadline expired",
            )
        })?
        .map_err(|_| {
            TransportError::new(
                "DEP_TRANSPORT_IO_FAILED",
                "bounded transport operation failed",
            )
        })
}

async fn run_transport_before_deadline<F, T>(
    deadline: Instant,
    future: F,
) -> Result<T, TransportError>
where
    F: std::future::Future<Output = Result<T, TransportError>>,
{
    tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), future)
        .await
        .map_err(|_| {
            TransportError::new(
                "DEP_TRANSPORT_DEADLINE",
                "absolute transport deadline expired",
            )
        })?
}

fn preserve_transport_setup_error(
    cleanup_poisoned: &AtomicBool,
    error: TransportError,
) -> TransportError {
    if error.code == "DEP_TRANSPORT_DEADLINE" {
        cleanup_poisoned.store(true, Ordering::Release);
    }
    error
}

#[cfg(unix)]
async fn create_private_resolution_root(path: &Path) -> Result<(), TransportError> {
    let mut builder = tokio::fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(path).await.map_err(|_| {
        TransportError::new(
            "DEP_TRANSPORT_STATE_CONFLICT",
            "transient resolution root already exists or cannot be created",
        )
    })
}

#[cfg(not(unix))]
async fn create_private_resolution_root(_path: &Path) -> Result<(), TransportError> {
    Err(TransportError::new(
        "DEP_TRANSPORT_PLATFORM_UNSUPPORTED",
        "private transport roots require Unix file semantics",
    ))
}

#[cfg(unix)]
async fn create_private_file(path: &Path) -> Result<tokio::fs::File, TransportError> {
    let mut options = tokio::fs::OpenOptions::new();
    options
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(nix::fcntl::OFlag::O_CLOEXEC.bits() | nix::fcntl::OFlag::O_NOFOLLOW.bits());
    options.open(path).await.map_err(|_| {
        TransportError::new(
            "DEP_TRANSPORT_STATE_CONFLICT",
            "transient artifact path already exists or cannot be created",
        )
    })
}

#[cfg(not(unix))]
async fn create_private_file(_path: &Path) -> Result<tokio::fs::File, TransportError> {
    Err(TransportError::new(
        "DEP_TRANSPORT_PLATFORM_UNSUPPORTED",
        "private transport files require Unix file semantics",
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use axum::Router;
    use axum::body::Body;
    use axum::extract::State;
    use axum::http::{Request, Response};
    use axum::routing::get;
    use ring::signature::{Ed25519KeyPair, KeyPair as _};
    use tempfile::TempDir;

    use super::*;
    use crate::{
        CanonicalPlan, Ecosystem, PackageNode, RepositoryBinding, SourceTrustClass,
        canonical_graph_sha256, canonical_node_id,
    };

    #[derive(Clone)]
    struct RepositoryState {
        node: PackageNode,
        body: Vec<u8>,
        key: Arc<Ed25519KeyPair>,
        authorization: Vec<u8>,
        repository_header: String,
        generation: u64,
        corrupt_signature: bool,
        delay: Duration,
    }

    async fn artifact(
        State(state): State<RepositoryState>,
        request: Request<Body>,
    ) -> Response<Body> {
        tokio::time::sleep(state.delay).await;
        if request
            .headers()
            .get(AUTHORIZATION)
            .map(HeaderValue::as_bytes)
            != Some(state.authorization.as_slice())
        {
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::empty())
                .expect("unauthorized response");
        }
        let message = canonical_attestation_message(
            &state.node,
            "contained-key",
            state.generation,
            Ecosystem::Maven.as_str().as_bytes(),
        );
        let mut signature = state.key.sign(&message).as_ref().to_vec();
        if state.corrupt_signature {
            signature[0] ^= 1;
        }
        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/octet-stream")
            .header(CONTENT_LENGTH, state.body.len().to_string())
            .header(REPOSITORY_HEADER, state.repository_header)
            .header(GENERATION_HEADER, state.generation.to_string())
            .header(ATTESTATION_HEADER, BASE64.encode(signature))
            .body(Body::from(state.body))
            .expect("artifact response")
    }

    struct TransportFixture {
        _root: TempDir,
        transport: HttpTransport,
        plan: CanonicalPlan,
        server: tokio::task::JoinHandle<()>,
    }

    impl TransportFixture {
        async fn new(
            body: Vec<u8>,
            markers: Vec<Vec<u8>>,
            repository_header: &str,
            corrupt_signature: bool,
        ) -> Self {
            Self::with_response(
                body.clone(),
                body,
                markers,
                repository_header,
                corrupt_signature,
                Duration::ZERO,
                7,
            )
            .await
        }

        async fn with_response(
            expected_body: Vec<u8>,
            response_body: Vec<u8>,
            markers: Vec<Vec<u8>>,
            repository_header: &str,
            corrupt_signature: bool,
            delay: Duration,
            generation: u64,
        ) -> Self {
            let key = Arc::new(
                Ed25519KeyPair::from_seed_unchecked(&[9_u8; 32]).expect("contained Ed25519 key"),
            );
            let mut node = PackageNode {
                node_id: String::new(),
                coordinate: "com.example:app:jar".to_owned(),
                exact_version: "1.0.0".to_owned(),
                repository_id: "contained-maven".to_owned(),
                artifact_path: "com/example/app/1.0.0/app.jar".to_owned(),
                declared_size: expected_body.len() as u64,
                sha256: format!("{:x}", Sha256::digest(&expected_body)),
                attestation_key_id: Some("contained-key".to_owned()),
                dependencies: Vec::new(),
            };
            node.node_id = canonical_node_id(Ecosystem::Maven, &node).expect("node id");
            let state = RepositoryState {
                node: node.clone(),
                body: response_body,
                key: Arc::clone(&key),
                authorization: b"Bearer contained-credential".to_vec(),
                repository_header: repository_header.to_owned(),
                generation,
                corrupt_signature,
                delay,
            };
            let app = Router::new()
                .route("/repository/com/example/app/1.0.0/app.jar", get(artifact))
                .with_state(state);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("loopback listener");
            let address = listener.local_addr().expect("listener address");
            let server = tokio::spawn(async move {
                axum::serve(listener, app).await.expect("repository server");
            });
            let root = TempDir::new().expect("transport root");
            let mut authorization = HeaderValue::from_static("Bearer contained-credential");
            authorization.set_sensitive(true);
            let repository = RepositoryRuntime {
                base_url: Url::parse(&format!("http://{address}/repository/"))
                    .expect("repository URL"),
                client: Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .retry(reqwest::retry::never())
                    .no_proxy()
                    .build()
                    .expect("contained client"),
                authorization: Some(authorization),
                attestation_key_id: "contained-key".to_owned(),
                attestation_key: key.public_key().as_ref().to_vec(),
            };
            let transport = HttpTransport {
                generation: 7,
                max_header_bytes: 16_384,
                max_artifact_bytes: 1_048_576,
                max_total_artifact_bytes: 1_048_576,
                transport_root: root.path().to_path_buf(),
                markers,
                repositories: BTreeMap::from([("contained-maven".to_owned(), repository)]),
                cleanup_poisoned: AtomicBool::new(false),
                _lease: None,
            };
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
                    credentialed: true,
                    permits_untrusted_source: false,
                }],
                roots: vec![node.node_id.clone()],
                nodes: vec![node],
                graph_sha256: String::new(),
            };
            plan.graph_sha256 = canonical_graph_sha256(&plan).expect("graph digest");
            Self {
                _root: root,
                transport,
                plan,
                server,
            }
        }
    }

    impl Drop for TransportFixture {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    #[tokio::test]
    async fn exact_get_attestation_and_content_are_retained_without_execution() {
        let fixture = TransportFixture::new(
            b"contained artifact bytes".to_vec(),
            vec![b"credential-marker-not-present".to_vec()],
            "contained-maven",
            false,
        )
        .await;
        let fetched = fixture
            .transport
            .fetch_plan(
                Uuid::new_v4(),
                &fixture.plan,
                Instant::now() + Duration::from_secs(2),
            )
            .await
            .expect("verified artifact");
        assert_eq!(fetched.len(), 1);
        assert_eq!(
            tokio::fs::read(&fetched[0].transient_path)
                .await
                .expect("retained transient bytes"),
            b"contained artifact bytes"
        );
        assert_eq!(fetched[0].publication_generation, 7);
    }

    #[tokio::test]
    async fn mirror_signature_and_secret_substitution_fail_closed() {
        let mirror = TransportFixture::new(
            b"artifact".to_vec(),
            vec![b"unrelated-marker".to_vec()],
            "substituted-mirror",
            false,
        )
        .await;
        let error = mirror
            .transport
            .fetch_plan(
                Uuid::new_v4(),
                &mirror.plan,
                Instant::now() + Duration::from_secs(2),
            )
            .await
            .expect_err("mirror substitution");
        assert_eq!(error.code, "DEP_TRANSPORT_HEADER_DENIED");

        let signature = TransportFixture::new(
            b"artifact".to_vec(),
            vec![b"unrelated-marker".to_vec()],
            "contained-maven",
            true,
        )
        .await;
        let error = signature
            .transport
            .fetch_plan(
                Uuid::new_v4(),
                &signature.plan,
                Instant::now() + Duration::from_secs(2),
            )
            .await
            .expect_err("signature substitution");
        assert_eq!(error.code, "DEP_TRANSPORT_ATTESTATION_INVALID");

        let secret = b"prefix-contained-secret-marker-suffix".to_vec();
        let marker = TransportFixture::new(
            secret,
            vec![b"contained-secret-marker".to_vec()],
            "contained-maven",
            false,
        )
        .await;
        let error = marker
            .transport
            .fetch_plan(
                Uuid::new_v4(),
                &marker.plan,
                Instant::now() + Duration::from_secs(2),
            )
            .await
            .expect_err("secret marker");
        assert_eq!(error.code, "DEP_TRANSPORT_SECRET_MARKER");
    }

    #[tokio::test]
    async fn wrong_content_size_generation_key_missing_offline_and_timeout_fail_closed() {
        let wrong_content = TransportFixture::with_response(
            b"artifact".to_vec(),
            b"artifacx".to_vec(),
            vec![b"unrelated-marker".to_vec()],
            "contained-maven",
            false,
            Duration::ZERO,
            7,
        )
        .await;
        let error = wrong_content
            .transport
            .fetch_plan(
                Uuid::new_v4(),
                &wrong_content.plan,
                Instant::now() + Duration::from_secs(2),
            )
            .await
            .expect_err("content substitution");
        assert_eq!(error.code, "DEP_TRANSPORT_CONTENT_MISMATCH");

        let wrong_size = TransportFixture::with_response(
            b"artifact".to_vec(),
            b"artifact-extra".to_vec(),
            vec![b"unrelated-marker".to_vec()],
            "contained-maven",
            false,
            Duration::ZERO,
            7,
        )
        .await;
        let error = wrong_size
            .transport
            .fetch_plan(
                Uuid::new_v4(),
                &wrong_size.plan,
                Instant::now() + Duration::from_secs(2),
            )
            .await
            .expect_err("size substitution");
        assert_eq!(error.code, "DEP_TRANSPORT_HEADER_DENIED");

        let stale = TransportFixture::with_response(
            b"artifact".to_vec(),
            b"artifact".to_vec(),
            vec![b"unrelated-marker".to_vec()],
            "contained-maven",
            false,
            Duration::ZERO,
            6,
        )
        .await;
        let error = stale
            .transport
            .fetch_plan(
                Uuid::new_v4(),
                &stale.plan,
                Instant::now() + Duration::from_secs(2),
            )
            .await
            .expect_err("stale publication generation");
        assert_eq!(error.code, "DEP_TRANSPORT_HEADER_DENIED");

        let mut wrong_key = TransportFixture::new(
            b"artifact".to_vec(),
            vec![b"unrelated-marker".to_vec()],
            "contained-maven",
            false,
        )
        .await;
        wrong_key
            .transport
            .repositories
            .get_mut("contained-maven")
            .expect("repository runtime")
            .attestation_key = Ed25519KeyPair::from_seed_unchecked(&[12_u8; 32])
            .expect("wrong key")
            .public_key()
            .as_ref()
            .to_vec();
        let error = wrong_key
            .transport
            .fetch_plan(
                Uuid::new_v4(),
                &wrong_key.plan,
                Instant::now() + Duration::from_secs(2),
            )
            .await
            .expect_err("wrong attestation key");
        assert_eq!(error.code, "DEP_TRANSPORT_ATTESTATION_INVALID");

        let mut missing = TransportFixture::new(
            b"artifact".to_vec(),
            vec![b"unrelated-marker".to_vec()],
            "contained-maven",
            false,
        )
        .await;
        missing.plan.nodes[0].artifact_path = "missing/artifact.jar".to_owned();
        missing.plan.nodes[0].node_id =
            canonical_node_id(Ecosystem::Maven, &missing.plan.nodes[0]).expect("missing node id");
        missing.plan.roots = vec![missing.plan.nodes[0].node_id.clone()];
        missing.plan.graph_sha256 = canonical_graph_sha256(&missing.plan).expect("missing graph");
        let error = missing
            .transport
            .fetch_plan(
                Uuid::new_v4(),
                &missing.plan,
                Instant::now() + Duration::from_secs(2),
            )
            .await
            .expect_err("missing artifact");
        assert_eq!(error.code, "DEP_TRANSPORT_RESPONSE_DENIED");

        let offline = TransportFixture::new(
            b"artifact".to_vec(),
            vec![b"unrelated-marker".to_vec()],
            "contained-maven",
            false,
        )
        .await;
        offline.server.abort();
        let error = offline
            .transport
            .fetch_plan(
                Uuid::new_v4(),
                &offline.plan,
                Instant::now() + Duration::from_secs(2),
            )
            .await
            .expect_err("offline repository");
        assert_eq!(error.code, "DEP_TRANSPORT_IO_FAILED");

        let timeout = TransportFixture::with_response(
            b"artifact".to_vec(),
            b"artifact".to_vec(),
            vec![b"unrelated-marker".to_vec()],
            "contained-maven",
            false,
            Duration::from_millis(100),
            7,
        )
        .await;
        let error = timeout
            .transport
            .fetch_plan(
                Uuid::new_v4(),
                &timeout.plan,
                Instant::now() + Duration::from_millis(5),
            )
            .await
            .expect_err("absolute timeout");
        assert_eq!(error.code, "DEP_TRANSPORT_DEADLINE");
        let restart = timeout
            .transport
            .ensure_available()
            .expect_err("timed-out cleanup ambiguity");
        assert_eq!(restart.code, "DEP_TRANSPORT_CLEANUP_RESTART_REQUIRED");
    }

    #[test]
    fn configured_secret_marker_in_header_name_is_denied() {
        let node = PackageNode {
            node_id: "node".to_owned(),
            coordinate: "com.example:app:jar".to_owned(),
            exact_version: "1.0.0".to_owned(),
            repository_id: "contained-maven".to_owned(),
            artifact_path: "com/example/app/1.0.0/app.jar".to_owned(),
            declared_size: 8,
            sha256: "a".repeat(64),
            attestation_key_id: Some("contained-key".to_owned()),
            dependencies: Vec::new(),
        };
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("8"));
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        headers.insert(
            REPOSITORY_HEADER,
            HeaderValue::from_static("contained-maven"),
        );
        headers.insert(GENERATION_HEADER, HeaderValue::from_static("7"));
        headers.insert(ATTESTATION_HEADER, HeaderValue::from_static("AA=="));
        headers.insert(
            reqwest::header::HeaderName::from_static("x-contained-secret-marker"),
            HeaderValue::from_static("safe"),
        );
        let error = validate_headers(
            &headers,
            &node,
            7,
            16_384,
            &[b"contained-secret-marker".to_vec()],
        )
        .expect_err("secret marker in header name");
        assert_eq!(error.code, "DEP_TRANSPORT_HEADER_DENIED");
    }

    #[test]
    fn secret_marker_spanning_body_chunks_is_denied() {
        let markers = vec![b"cross-chunk-secret".to_vec()];
        let mut scanner = MarkerScanner::new(&markers);
        scanner
            .scan(b"prefix-cross-chunk-")
            .expect("partial marker");
        let error = scanner.scan(b"secret-suffix").expect_err("spanning marker");
        assert_eq!(error.code, "DEP_TRANSPORT_SECRET_MARKER");
    }

    #[tokio::test]
    async fn cleanup_timeout_returns_promptly_and_poisons_transport() {
        let poisoned = AtomicBool::new(false);
        let started = Instant::now();
        let error = supervise_cleanup(
            &poisoned,
            started + Duration::from_millis(5),
            std::future::pending::<Result<(), TransportError>>(),
        )
        .await
        .expect_err("stalled cleanup");
        assert_eq!(error.code, "DEP_TRANSPORT_CLEANUP_AMBIGUOUS");
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(poisoned.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn transient_creation_future_is_bounded_by_the_deadline() {
        let started = Instant::now();
        let poisoned = AtomicBool::new(false);
        let error = run_transport_before_deadline(
            started + Duration::from_millis(5),
            std::future::pending::<Result<(), TransportError>>(),
        )
        .await
        .map_err(|error| preserve_transport_setup_error(&poisoned, error))
        .expect_err("stalled transient creation");
        assert_eq!(error.code, "DEP_TRANSPORT_DEADLINE");
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(poisoned.load(Ordering::Acquire));
    }
}
