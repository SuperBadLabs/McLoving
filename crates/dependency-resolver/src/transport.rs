use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
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
    pub transient_offset: u64,
    pub transient_root_device: u64,
    pub transient_root_inode: u64,
}

#[derive(Clone, Copy, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransportRootIdentity {
    pub device: u64,
    pub inode: u64,
}

struct PendingTransportArchive {
    root_directory: Arc<std::fs::File>,
    linked_path: PathBuf,
    identity: TransportRootIdentity,
}

struct TransportArchiveWriter<'a> {
    file: &'a mut tokio::fs::File,
    name: &'a str,
    offset: u64,
    identity: TransportRootIdentity,
}

#[cfg(test)]
struct PinnedTransportResolution {
    _directory: std::fs::File,
    path: PathBuf,
    identity: TransportRootIdentity,
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
    fetch_slot: tokio::sync::Mutex<()>,
    cleanup_poisoned: AtomicBool,
    _lease: Option<TransportLease>,
}

impl HttpTransport {
    pub fn new(
        config: &CertifiedConfig,
        authorities: &LoadedAuthorities,
    ) -> Result<Self, TransportError> {
        Self::new_inner(config, authorities, None)
    }

    pub(crate) fn new_with_bound_roots(
        config: &CertifiedConfig,
        authorities: &LoadedAuthorities,
        output_device: u64,
        transport_identity: TransportRootIdentity,
    ) -> Result<Self, TransportError> {
        Self::new_inner(
            config,
            authorities,
            Some((output_device, transport_identity)),
        )
    }

    fn new_inner(
        config: &CertifiedConfig,
        authorities: &LoadedAuthorities,
        expected_roots: Option<(u64, TransportRootIdentity)>,
    ) -> Result<Self, TransportError> {
        crate::validate_config(config)
            .map_err(|error| TransportError::new(error.code, error.message))?;
        let lease = TransportLease::acquire(config, expected_roots)?;
        let transport_root = lease.root_path.clone();
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
            transport_root,
            markers,
            repositories,
            fetch_slot: tokio::sync::Mutex::new(()),
            cleanup_poisoned: AtomicBool::new(false),
            _lease: Some(lease),
        })
    }

    pub(crate) fn root_identity(&self) -> Result<TransportRootIdentity, TransportError> {
        self._lease
            .as_ref()
            .map(|lease| lease.root_identity)
            .ok_or_else(root_state_error)
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

    pub async fn preserve_cleanup_ambiguity(&self) {
        let _fetch_slot = self.fetch_slot.lock().await;
        self.poison_cleanup_while_fetch_slot_held();
    }

    fn poison_cleanup_while_fetch_slot_held(&self) {
        self.cleanup_poisoned.store(true, Ordering::Release);
    }

    fn resolution_root_directory(&self) -> Result<Arc<std::fs::File>, TransportError> {
        if let Some(lease) = &self._lease {
            return Ok(Arc::clone(&lease._root_directory));
        }
        #[cfg(test)]
        {
            crate::publication::open_pinned_cleanup_root(&self.transport_root)
                .map(Arc::new)
                .map_err(|_| root_state_error())
        }
        #[cfg(not(test))]
        Err(root_state_error())
    }

    pub async fn fetch_plan(
        &self,
        resolution_id: Uuid,
        plan: &CanonicalPlan,
        deadline: Instant,
    ) -> Result<Vec<FetchedArtifact>, TransportError> {
        let _fetch_slot = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            self.fetch_slot.lock(),
        )
        .await
        .map_err(|_| {
            TransportError::new(
                "DEP_TRANSPORT_DEADLINE",
                "absolute transport deadline expired while waiting for the serialized fetch slot",
            )
        })?;
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
        let root_directory = self.resolution_root_directory()?;
        let archive_name = format!(".{resolution_id}.transport");
        let archive_path =
            crate::publication::pinned_directory_path(&root_directory).join(&archive_name);
        let mut archive =
            run_transport_before_deadline(deadline, create_private_file(&archive_path))
                .await
                .map_err(|error| preserve_transport_setup_error(&self.cleanup_poisoned, error))?;
        let created = inspect_transport_archive_metadata(&archive, &archive_path)
            .await
            .inspect_err(|_| {
                self.poison_cleanup_while_fetch_slot_held();
            })?;
        let root_metadata = inspect_transport_root_metadata(&root_directory, &archive_path)
            .inspect_err(|_| {
                self.poison_cleanup_while_fetch_slot_held();
            })?;
        #[cfg(target_os = "linux")]
        let identity =
            establish_transport_archive_identity(&created, &root_metadata, &archive_path)
                .inspect_err(|_| {
                    self.poison_cleanup_while_fetch_slot_held();
                })?;
        #[cfg(not(target_os = "linux"))]
        let identity = {
            self.poison_cleanup_while_fetch_slot_held();
            return Err(root_state_error());
        };
        let pending = PendingTransportArchive {
            root_directory,
            linked_path: self.transport_root.join(&archive_name),
            identity,
        };
        match self
            .fetch_plan_into(plan, deadline, &mut archive, &archive_name, identity)
            .await
        {
            Ok(fetched) => {
                if let Err(error) =
                    sync_transport_archive_before_deadline(deadline, &archive, &archive_path).await
                {
                    drop(archive);
                    if Instant::now() >= deadline {
                        self.poison_cleanup_while_fetch_slot_held();
                        return Err(error);
                    }
                    self.cleanup_resolution_before_deadline(&pending, deadline)
                        .await?;
                    return Err(error);
                }
                drop(archive);
                substitute_transient_after_sync_for_test(&archive_path)?;
                match verify_transient_archive(&archive_path, &fetched, deadline).await {
                    Ok(()) => Ok(fetched),
                    Err(error) => {
                        if Instant::now() >= deadline {
                            self.poison_cleanup_while_fetch_slot_held();
                            return Err(error);
                        }
                        self.cleanup_resolution_before_deadline(&pending, deadline)
                            .await?;
                        Err(error)
                    }
                }
            }
            Err(error) => {
                drop(archive);
                if Instant::now() >= deadline {
                    self.poison_cleanup_while_fetch_slot_held();
                    return Err(error);
                }
                self.cleanup_resolution_before_deadline(&pending, deadline)
                    .await?;
                Err(error)
            }
        }
    }

    async fn cleanup_resolution_before_deadline(
        &self,
        resolution: &PendingTransportArchive,
        deadline: Instant,
    ) -> Result<(), TransportError> {
        self.ensure_available()?;
        supervise_cleanup(
            &self.cleanup_poisoned,
            deadline,
            self.cleanup_resolution(resolution),
        )
        .await
    }

    async fn cleanup_resolution(
        &self,
        resolution: &PendingTransportArchive,
    ) -> Result<(), TransportError> {
        let root_directory = resolution
            .root_directory
            .try_clone()
            .map_err(|_| root_state_error())?;
        let root = self.transport_root.clone();
        let linked_path = resolution.linked_path.clone();
        let identity = resolution.identity;
        tokio::task::spawn_blocking(move || {
            crate::publication::remove_private_file_exact(
                &root_directory,
                &root,
                &linked_path,
                identity.device,
                identity.inode,
            )
            .map_err(|_| cleanup_ambiguity_error())?;
            root_directory
                .sync_all()
                .map_err(|_| cleanup_ambiguity_error())
        })
        .await
        .map_err(|_| cleanup_ambiguity_error())??;
        Ok(())
    }

    async fn fetch_plan_into(
        &self,
        plan: &CanonicalPlan,
        deadline: Instant,
        archive: &mut tokio::fs::File,
        archive_name: &str,
        archive_identity: TransportRootIdentity,
    ) -> Result<Vec<FetchedArtifact>, TransportError> {
        let mut total = 0_u64;
        let mut fetched = Vec::with_capacity(plan.nodes.len());
        let mut scanner = MarkerScanner::new(&self.markers);
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
                self.fetch_node(
                    plan.ecosystem,
                    node,
                    deadline,
                    &mut scanner,
                    TransportArchiveWriter {
                        file: archive,
                        name: archive_name,
                        offset: total - node.declared_size,
                        identity: archive_identity,
                    },
                )
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
        scanner: &mut MarkerScanner<'_>,
        archive: TransportArchiveWriter<'_>,
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

        let mut response = response;
        let mut hasher = Sha256::new();
        let mut received = 0_u64;
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
            run_before_deadline(deadline, archive.file.write_all(&chunk)).await?;
        }
        if received != node.declared_size || format!("{:x}", hasher.finalize()) != node.sha256 {
            return Err(TransportError::new(
                "DEP_TRANSPORT_CONTENT_MISMATCH",
                "artifact size or content digest does not match the canonical plan",
            ));
        }
        Ok(FetchedArtifact {
            node_id: node.node_id.clone(),
            transient_path: PathBuf::from(archive.name),
            declared_size: received,
            sha256: node.sha256.clone(),
            attestation_sha256: format!("{:x}", Sha256::digest(&signature)),
            publication_generation: self.generation,
            transient_offset: archive.offset,
            transient_root_device: archive.identity.device,
            transient_root_inode: archive.identity.inode,
        })
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PostCreateInspectionFailure {
    ArchiveMetadata,
    RootMetadata,
    IdentityNotFile,
    IdentityDeviceMismatch,
    IdentityZeroInode,
}

#[cfg(test)]
thread_local! {
    static TRANSIENT_OPEN_TRACE: std::cell::RefCell<Vec<(PathBuf, &'static str)>> = const {
        std::cell::RefCell::new(Vec::new())
    };
    static TRANSIENT_FIFO_SUBSTITUTION: std::cell::RefCell<Option<PathBuf>> = const {
        std::cell::RefCell::new(None)
    };
    static TRANSIENT_SYNC_FAILURE: std::cell::RefCell<Option<PathBuf>> = const {
        std::cell::RefCell::new(None)
    };
    static TRANSIENT_METADATA_FAILURE: std::cell::RefCell<Option<(PathBuf, PostCreateInspectionFailure)>> = const {
        std::cell::RefCell::new(None)
    };
}

#[cfg(test)]
fn take_post_create_failure(path: &Path, expected: PostCreateInspectionFailure) -> bool {
    TRANSIENT_METADATA_FAILURE.with(|target| {
        let mut target = target.borrow_mut();
        if target.as_ref().is_some_and(|(configured, failure)| {
            configured.file_name() == path.file_name() && *failure == expected
        }) {
            target.take();
            true
        } else {
            false
        }
    })
}

#[cfg(test)]
async fn inspect_transport_archive_metadata(
    archive: &tokio::fs::File,
    path: &Path,
) -> Result<std::fs::Metadata, TransportError> {
    if take_post_create_failure(path, PostCreateInspectionFailure::ArchiveMetadata) {
        tokio::task::yield_now().await;
        return Err(root_state_error());
    }
    archive.metadata().await.map_err(|_| root_state_error())
}

#[cfg(test)]
fn inspect_transport_root_metadata(
    root: &std::fs::File,
    archive_path: &Path,
) -> Result<std::fs::Metadata, TransportError> {
    if take_post_create_failure(archive_path, PostCreateInspectionFailure::RootMetadata) {
        return Err(root_state_error());
    }
    root.metadata().map_err(|_| root_state_error())
}

#[cfg(not(test))]
fn inspect_transport_root_metadata(
    root: &std::fs::File,
    _archive_path: &Path,
) -> Result<std::fs::Metadata, TransportError> {
    root.metadata().map_err(|_| root_state_error())
}

#[cfg(all(target_os = "linux", test))]
fn establish_transport_archive_identity(
    created: &std::fs::Metadata,
    root: &std::fs::Metadata,
    archive_path: &Path,
) -> Result<TransportRootIdentity, TransportError> {
    use std::os::unix::fs::MetadataExt as _;

    let mut is_file = created.is_file();
    let device = created.dev();
    let inode = created.ino();
    let mut root_device = root.dev();
    let mut validated_inode = inode;
    if take_post_create_failure(archive_path, PostCreateInspectionFailure::IdentityNotFile) {
        is_file = false;
    } else if take_post_create_failure(
        archive_path,
        PostCreateInspectionFailure::IdentityDeviceMismatch,
    ) {
        root_device = device.wrapping_add(1);
    } else if take_post_create_failure(archive_path, PostCreateInspectionFailure::IdentityZeroInode)
    {
        validated_inode = 0;
    }
    validate_transport_archive_identity(is_file, device, validated_inode, root_device)
}

#[cfg(all(target_os = "linux", not(test)))]
fn establish_transport_archive_identity(
    created: &std::fs::Metadata,
    root: &std::fs::Metadata,
    _archive_path: &Path,
) -> Result<TransportRootIdentity, TransportError> {
    use std::os::unix::fs::MetadataExt as _;

    validate_transport_archive_identity(created.is_file(), created.dev(), created.ino(), root.dev())
}

#[cfg(target_os = "linux")]
fn validate_transport_archive_identity(
    is_file: bool,
    device: u64,
    inode: u64,
    root_device: u64,
) -> Result<TransportRootIdentity, TransportError> {
    if !is_file || device != root_device || inode == 0 {
        return Err(root_state_error());
    }
    Ok(TransportRootIdentity { device, inode })
}

#[cfg(not(test))]
async fn inspect_transport_archive_metadata(
    archive: &tokio::fs::File,
    _path: &Path,
) -> Result<std::fs::Metadata, TransportError> {
    archive.metadata().await.map_err(|_| root_state_error())
}

#[cfg(test)]
async fn sync_transport_archive_before_deadline(
    deadline: Instant,
    archive: &tokio::fs::File,
    path: &Path,
) -> Result<(), TransportError> {
    let fail = TRANSIENT_SYNC_FAILURE.with(|target| {
        target
            .borrow_mut()
            .take_if(|configured| configured.file_name() == path.file_name())
            .is_some()
    });
    if fail {
        return Err(TransportError::new(
            "DEP_TRANSPORT_IO_FAILED",
            "transport archive synchronization failed",
        ));
    }
    run_before_deadline(deadline, archive.sync_all()).await
}

#[cfg(not(test))]
async fn sync_transport_archive_before_deadline(
    deadline: Instant,
    archive: &tokio::fs::File,
    _path: &Path,
) -> Result<(), TransportError> {
    run_before_deadline(deadline, archive.sync_all()).await
}

#[cfg(test)]
fn substitute_transient_after_sync_for_test(path: &Path) -> Result<(), TransportError> {
    use nix::sys::stat::Mode;
    use nix::unistd::mkfifo;

    let substitute = TRANSIENT_FIFO_SUBSTITUTION.with(|target| {
        target
            .borrow_mut()
            .take_if(|configured| configured.file_name() == path.file_name())
            .is_some()
    });
    if substitute {
        std::fs::remove_file(path).map_err(|_| transient_content_error())?;
        mkfifo(path, Mode::S_IRUSR | Mode::S_IWUSR).map_err(|_| transient_content_error())?;
    }
    Ok(())
}

#[cfg(not(test))]
fn substitute_transient_after_sync_for_test(_path: &Path) -> Result<(), TransportError> {
    Ok(())
}

#[cfg(test)]
fn trace_transient_open(path: &Path, event: &'static str) {
    TRANSIENT_OPEN_TRACE.with(|trace| {
        trace.borrow_mut().push((path.to_path_buf(), event));
    });
}

#[cfg(not(test))]
fn trace_transient_open(_path: &Path, _event: &'static str) {}

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

#[cfg(all(target_os = "linux", test))]
fn pin_transport_resolution(
    root_directory: Arc<std::fs::File>,
    root_path: &Path,
    resolution_id: Uuid,
    created_identity: TransportRootIdentity,
) -> Result<PinnedTransportResolution, TransportError> {
    use nix::fcntl::{OFlag, openat};
    use nix::sys::stat::Mode;

    let name = resolution_id.to_string();
    let directory = std::fs::File::from(
        openat(
            &*root_directory,
            name.as_str(),
            OFlag::O_RDONLY
                | OFlag::O_DIRECTORY
                | OFlag::O_NOFOLLOW
                | OFlag::O_CLOEXEC
                | OFlag::O_NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| root_state_error())?,
    );
    finish_transport_resolution_pin(
        root_directory,
        root_path,
        resolution_id,
        directory,
        Some(created_identity),
    )
}

#[cfg(all(target_os = "linux", test))]
fn finish_transport_resolution_pin(
    root_directory: Arc<std::fs::File>,
    root_path: &Path,
    resolution_id: Uuid,
    directory: std::fs::File,
    created_identity: Option<TransportRootIdentity>,
) -> Result<PinnedTransportResolution, TransportError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let name = resolution_id.to_string();
    let metadata = directory.metadata().map_err(|_| root_state_error())?;
    let root_metadata = root_directory.metadata().map_err(|_| root_state_error())?;
    if !metadata.is_dir()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o700
        || metadata.dev() != root_metadata.dev()
        || created_identity.is_some_and(|identity| {
            metadata.dev() != identity.device || metadata.ino() != identity.inode
        })
    {
        return Err(root_state_error());
    }
    let path = crate::publication::pinned_directory_path(&directory);
    if std::fs::read_dir(&path)
        .map_err(|_| root_state_error())?
        .next()
        .is_some()
    {
        return Err(root_state_error());
    }
    let linked_path = root_path.join(&name);
    let linked = std::fs::symlink_metadata(&linked_path).map_err(|_| root_state_error())?;
    if !linked.file_type().is_dir()
        || linked.dev() != metadata.dev()
        || linked.ino() != metadata.ino()
    {
        return Err(root_state_error());
    }
    let pinned_root_path = crate::publication::pinned_directory_path(&root_directory);
    validate_transport_resolution_root(&pinned_root_path, &name, &metadata)?;
    let final_link =
        std::fs::symlink_metadata(pinned_root_path.join(&name)).map_err(|_| root_state_error())?;
    if !final_link.file_type().is_dir()
        || final_link.dev() != metadata.dev()
        || final_link.ino() != metadata.ino()
    {
        return Err(root_state_error());
    }
    Ok(PinnedTransportResolution {
        _directory: directory,
        path,
        identity: TransportRootIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
    })
}

#[cfg(all(target_os = "linux", test))]
fn validate_transport_resolution_root(
    root_path: &Path,
    resolution_name: &str,
    resolution_metadata: &std::fs::Metadata,
) -> Result<(), TransportError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let mut resolution_seen = false;
    let mut lock_seen = false;
    for entry in std::fs::read_dir(root_path).map_err(|_| root_state_error())? {
        let entry = entry.map_err(|_| root_state_error())?;
        if entry.file_name() == resolution_name {
            if resolution_seen {
                return Err(root_state_error());
            }
            let linked = entry.metadata().map_err(|_| root_state_error())?;
            if !entry.file_type().map_err(|_| root_state_error())?.is_dir()
                || linked.dev() != resolution_metadata.dev()
                || linked.ino() != resolution_metadata.ino()
            {
                return Err(root_state_error());
            }
            resolution_seen = true;
        } else if entry.file_name() == ".mcloving-dependency-resolver.lock" {
            if lock_seen {
                return Err(root_state_error());
            }
            let linked = entry.metadata().map_err(|_| root_state_error())?;
            if !entry.file_type().map_err(|_| root_state_error())?.is_file()
                || !linked.is_file()
                || linked.uid() != nix::unistd::Uid::effective().as_raw()
                || linked.nlink() != 1
                || linked.permissions().mode() & 0o777 != 0o600
                || linked.len() != TRANSPORT_LOCK_CONTENT.len() as u64
            {
                return Err(root_state_error());
            }
            lock_seen = true;
        } else {
            return Err(root_state_error());
        }
    }
    if !resolution_seen || (!cfg!(test) && !lock_seen) {
        return Err(root_state_error());
    }
    Ok(())
}

#[cfg(all(not(target_os = "linux"), test))]
fn pin_transport_resolution(
    _root_directory: Arc<std::fs::File>,
    _root_path: &Path,
    _resolution_id: Uuid,
    _created_identity: TransportRootIdentity,
) -> Result<PinnedTransportResolution, TransportError> {
    Err(TransportError::new(
        "DEP_TRANSPORT_PLATFORM_UNSUPPORTED",
        "transient resolution pinning requires Linux descriptor semantics",
    ))
}

#[cfg(target_os = "linux")]
async fn verify_transient_archive(
    path: &Path,
    artifacts: &[FetchedArtifact],
    deadline: Instant,
) -> Result<(), TransportError> {
    use nix::fcntl::OFlag;
    use std::io::SeekFrom;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};

    let first = artifacts.first().ok_or_else(transient_content_error)?;
    let expected_size = artifacts
        .iter()
        .try_fold(0_u64, |expected, artifact| {
            if artifact.transient_path != first.transient_path
                || artifact.transient_root_device != first.transient_root_device
                || artifact.transient_root_inode != first.transient_root_inode
                || artifact.transient_offset != expected
            {
                return None;
            }
            expected.checked_add(artifact.declared_size)
        })
        .ok_or_else(transient_content_error)?;
    if Instant::now() >= deadline {
        return Err(TransportError::new(
            "DEP_TRANSPORT_DEADLINE",
            "absolute transport deadline expired",
        ));
    }
    let inspection = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_PATH | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW).bits())
        .open(path)
        .map_err(|_| transient_content_error())?;
    trace_transient_open(path, "path-inspected");
    let inspected = inspection
        .metadata()
        .map_err(|_| transient_content_error())?;
    if !transient_metadata_matches(&inspected, expected_size)
        || inspected.dev() != first.transient_root_device
        || inspected.ino() != first.transient_root_inode
    {
        return Err(transient_content_error());
    }
    let pinned_path = format!("/proc/self/fd/{}", inspection.as_raw_fd());
    trace_transient_open(path, "data-open");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_CLOEXEC | OFlag::O_NONBLOCK).bits())
        .open(pinned_path)
        .map_err(|_| transient_content_error())?;
    let opened = file.metadata().map_err(|_| transient_content_error())?;
    if !transient_metadata_matches(&opened, expected_size)
        || opened.dev() != inspected.dev()
        || opened.ino() != inspected.ino()
    {
        return Err(transient_content_error());
    }
    let mut file = tokio::fs::File::from_std(file);
    let mut buffer = [0_u8; 65_536];
    for artifact in artifacts {
        run_before_deadline(
            deadline,
            file.seek(SeekFrom::Start(artifact.transient_offset)),
        )
        .await?;
        let mut remaining = artifact.declared_size;
        let mut hasher = Sha256::new();
        while remaining > 0 {
            let limit = usize::try_from(remaining.min(buffer.len() as u64))
                .map_err(|_| transient_content_error())?;
            let read = run_before_deadline(deadline, file.read(&mut buffer[..limit])).await?;
            if read == 0 {
                return Err(transient_content_error());
            }
            remaining -= read as u64;
            hasher.update(&buffer[..read]);
        }
        if format!("{:x}", hasher.finalize()) != artifact.sha256 {
            return Err(transient_content_error());
        }
    }
    let linked = std::fs::symlink_metadata(path).map_err(|_| transient_content_error())?;
    if !transient_metadata_matches(&linked, expected_size)
        || linked.dev() != inspected.dev()
        || linked.ino() != inspected.ino()
    {
        return Err(transient_content_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
async fn verify_transient_archive(
    _path: &Path,
    _artifacts: &[FetchedArtifact],
    _deadline: Instant,
) -> Result<(), TransportError> {
    Err(TransportError::new(
        "DEP_TRANSPORT_PLATFORM_UNSUPPORTED",
        "transient archive verification requires Linux descriptor semantics",
    ))
}

#[cfg(all(target_os = "linux", test))]
async fn verify_transient_file(
    path: &Path,
    expected_size: u64,
    expected_sha256: &str,
    deadline: Instant,
) -> Result<(), TransportError> {
    use nix::fcntl::OFlag;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    use tokio::io::AsyncReadExt as _;

    if Instant::now() >= deadline {
        return Err(TransportError::new(
            "DEP_TRANSPORT_DEADLINE",
            "absolute transport deadline expired",
        ));
    }
    let inspection = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_PATH | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW).bits())
        .open(path)
        .map_err(|_| transient_content_error())?;
    trace_transient_open(path, "path-inspected");
    let inspected = inspection
        .metadata()
        .map_err(|_| transient_content_error())?;
    if !transient_metadata_matches(&inspected, expected_size) {
        return Err(transient_content_error());
    }
    let pinned_path = format!("/proc/self/fd/{}", inspection.as_raw_fd());
    trace_transient_open(path, "data-open");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_CLOEXEC | OFlag::O_NONBLOCK).bits())
        .open(pinned_path)
        .map_err(|_| transient_content_error())?;
    let opened = file.metadata().map_err(|_| transient_content_error())?;
    let linked = std::fs::symlink_metadata(path).map_err(|_| transient_content_error())?;
    if !transient_metadata_matches(&opened, expected_size)
        || !transient_metadata_matches(&linked, expected_size)
        || opened.dev() != inspected.dev()
        || opened.ino() != inspected.ino()
        || linked.dev() != inspected.dev()
        || linked.ino() != inspected.ino()
    {
        return Err(transient_content_error());
    }
    let mut file = tokio::fs::File::from_std(file);
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

#[cfg(target_os = "linux")]
fn transient_metadata_matches(metadata: &std::fs::Metadata, expected_size: u64) -> bool {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    metadata.is_file()
        && metadata.uid() == nix::unistd::Uid::effective().as_raw()
        && metadata.nlink() == 1
        && metadata.permissions().mode() & 0o777 == 0o600
        && metadata.len() == expected_size
}

fn transient_content_error() -> TransportError {
    TransportError::new(
        "DEP_TRANSPORT_CONTENT_MISMATCH",
        "persisted transient artifact size, type, owner, mode, link count, or identity changed",
    )
}

fn cleanup_ambiguity_error() -> TransportError {
    TransportError::new(
        "DEP_TRANSPORT_CLEANUP_AMBIGUOUS",
        "verified transient resolution could not be removed exactly",
    )
}

#[cfg(all(not(target_os = "linux"), test))]
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
    _root_directory: Arc<std::fs::File>,
    root_path: PathBuf,
    root_identity: TransportRootIdentity,
}

impl TransportLease {
    #[cfg(target_os = "linux")]
    fn acquire(
        config: &CertifiedConfig,
        expected_roots: Option<(u64, TransportRootIdentity)>,
    ) -> Result<Self, TransportError> {
        use nix::sys::statvfs::statvfs;
        use nix::unistd::Uid;
        use std::io::{Seek as _, SeekFrom, Write as _};
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let configured_root = Path::new(&config.transport_root);
        let output = Path::new(&config.output_root);
        let root_directory = Arc::new(
            crate::publication::open_pinned_cleanup_root(configured_root)
                .map_err(|_| root_policy_error())?,
        );
        let root = crate::publication::pinned_directory_path(&root_directory);
        let parent = configured_root.parent().ok_or_else(root_policy_error)?;
        let root_metadata = root_directory.metadata().map_err(|_| root_policy_error())?;
        let linked_metadata =
            std::fs::symlink_metadata(configured_root).map_err(|_| root_policy_error())?;
        let parent_metadata = std::fs::metadata(parent).map_err(|_| root_policy_error())?;
        let output_device = match expected_roots {
            Some((output_device, _)) => output_device,
            None => std::fs::metadata(output)
                .map_err(|_| root_policy_error())?
                .dev(),
        };
        let filesystem = statvfs(&root).map_err(|_| root_policy_error())?;
        let capacity = filesystem
            .blocks()
            .checked_mul(filesystem.fragment_size())
            .ok_or_else(root_policy_error)?;
        if !root_metadata.file_type().is_dir()
            || !linked_metadata.file_type().is_dir()
            || root_metadata.uid() != Uid::effective().as_raw()
            || root_metadata.permissions().mode() & 0o777 != 0o700
            || root_metadata.dev() != linked_metadata.dev()
            || root_metadata.ino() != linked_metadata.ino()
            || root_metadata.dev() == parent_metadata.dev()
            || root_metadata.dev() == output_device
            || expected_roots.is_some_and(|(_, expected)| {
                (root_metadata.dev(), root_metadata.ino()) != (expected.device, expected.inode)
            })
            || capacity != config.limits.transport_capacity_bytes
        {
            return Err(root_policy_error());
        }

        let lock_path = root.join(".mcloving-dependency-resolver.lock");
        let mut file = open_transport_lock(&lock_path)?;
        let existing = read_transport_lock_bounded(&mut file)?;
        if existing.is_empty() {
            file.seek(SeekFrom::Start(0))
                .and_then(|_| file.write_all(TRANSPORT_LOCK_CONTENT))
                .map_err(|_| root_state_error())?;
        } else if existing != TRANSPORT_LOCK_CONTENT {
            return Err(root_state_error());
        }
        let metadata = file.metadata().map_err(|_| root_state_error())?;
        if !metadata.is_file()
            || metadata.uid() != Uid::effective().as_raw()
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.len() != TRANSPORT_LOCK_CONTENT.len() as u64
        {
            return Err(root_state_error());
        }
        file.sync_all().map_err(|_| root_state_error())?;
        root_directory.sync_all().map_err(|_| root_state_error())?;
        let lock = lock_transport_root(&root_directory)?;
        let mut entries = std::fs::read_dir(&root).map_err(|_| root_state_error())?;
        let mut lock_seen = false;
        for entry in &mut entries {
            let entry = entry.map_err(|_| root_state_error())?;
            if entry.file_name() != ".mcloving-dependency-resolver.lock" || lock_seen {
                return Err(root_state_error());
            }
            let entry_metadata = entry.metadata().map_err(|_| root_state_error())?;
            if !entry.file_type().map_err(|_| root_state_error())?.is_file()
                || !entry_metadata.is_file()
                || entry_metadata.dev() != metadata.dev()
                || entry_metadata.ino() != metadata.ino()
            {
                return Err(root_state_error());
            }
            lock_seen = true;
        }
        if !lock_seen {
            return Err(root_state_error());
        }
        Ok(Self {
            _lock: lock,
            _root_directory: root_directory,
            root_path: root,
            root_identity: TransportRootIdentity {
                device: root_metadata.dev(),
                inode: root_metadata.ino(),
            },
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn acquire(
        _config: &CertifiedConfig,
        _expected_roots: Option<(u64, TransportRootIdentity)>,
    ) -> Result<Self, TransportError> {
        Err(TransportError::new(
            "DEP_TRANSPORT_PLATFORM_UNSUPPORTED",
            "dedicated transport filesystem enforcement requires Linux",
        ))
    }
}

#[cfg(target_os = "linux")]
fn lock_transport_root(
    root_directory: &std::fs::File,
) -> Result<TransportRootLock, TransportError> {
    use nix::fcntl::{Flock, FlockArg};

    let lock_target = root_directory.try_clone().map_err(|_| root_state_error())?;
    Flock::lock(lock_target, FlockArg::LockExclusiveNonblock).map_err(|_| root_state_error())
}

#[cfg(target_os = "linux")]
fn open_transport_lock(path: &Path) -> Result<std::fs::File, TransportError> {
    use nix::fcntl::OFlag;
    use nix::unistd::Uid;
    use std::io::ErrorKind;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags((OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits())
        .open(path)
    {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            // O_PATH pins and stats the directory entry without invoking a
            // FIFO or device driver's potentially blocking open operation.
            let inspection = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags((OFlag::O_PATH | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW).bits())
                .open(path)
                .map_err(|_| root_state_error())?;
            let inspected = inspection.metadata().map_err(|_| root_state_error())?;
            if !inspected.is_file()
                || inspected.uid() != Uid::effective().as_raw()
                || inspected.nlink() != 1
                || inspected.mode() & 0o077 != 0
            {
                return Err(root_state_error());
            }

            // Reopen the exact pinned inode, not the attacker-controlled path.
            // O_NONBLOCK is retained as a second defensive boundary.
            let pinned_path = format!("/proc/self/fd/{}", inspection.as_raw_fd());
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags((OFlag::O_CLOEXEC | OFlag::O_NONBLOCK).bits())
                .open(pinned_path)
                .map_err(|_| root_state_error())?;
            let opened = file.metadata().map_err(|_| root_state_error())?;
            if !opened.is_file()
                || opened.dev() != inspected.dev()
                || opened.ino() != inspected.ino()
            {
                return Err(root_state_error());
            }
            Ok(file)
        }
        Err(_) => Err(root_state_error()),
    }
}

#[cfg(target_os = "linux")]
fn read_transport_lock_bounded(file: &mut std::fs::File) -> Result<Vec<u8>, TransportError> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    let expected_len = TRANSPORT_LOCK_CONTENT.len();
    let metadata = file.metadata().map_err(|_| root_state_error())?;
    if !metadata.is_file() || metadata.len() > expected_len as u64 {
        return Err(root_state_error());
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| root_state_error())?;
    let mut existing = Vec::with_capacity(expected_len + 1);
    file.take((expected_len + 1) as u64)
        .read_to_end(&mut existing)
        .map_err(|_| root_state_error())?;
    if existing.len() > expected_len {
        return Err(root_state_error());
    }
    Ok(existing)
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

    #[cfg(target_os = "linux")]
    #[test]
    fn sparse_transport_lock_is_rejected_before_unbounded_allocation() {
        use std::io::Write as _;

        let root = TempDir::new().expect("transport lock root");
        let lock_path = root.path().join("transport.lock");
        let mut lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(lock_path)
            .expect("transport lock");
        lock.write_all(TRANSPORT_LOCK_CONTENT)
            .expect("valid transport lock");
        lock.set_len(1_u64 << 40).expect("sparse transport lock");

        let error = read_transport_lock_bounded(&mut lock).expect_err("oversized sparse lock");
        assert_eq!(error.code, "DEP_TRANSPORT_ROOT_STATE_DENIED");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fifo_transport_lock_is_rejected_before_blocking_read() {
        use nix::sys::stat::Mode;
        use nix::unistd::mkfifo;

        let root = TempDir::new().expect("transport lock root");
        let lock_path = root.path().join("transport.lock");
        mkfifo(&lock_path, Mode::S_IRUSR | Mode::S_IWUSR).expect("transport lock fifo");
        let started = Instant::now();
        let error = open_transport_lock(&lock_path).expect_err("non-regular lock");
        assert_eq!(error.code, "DEP_TRANSPORT_ROOT_STATE_DENIED");
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn device_transport_lock_is_rejected_before_device_open() {
        let started = Instant::now();
        let error = open_transport_lock(Path::new("/dev/null")).expect_err("device lock");
        assert_eq!(error.code, "DEP_TRANSPORT_ROOT_STATE_DENIED");
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn replacing_the_transport_sentinel_cannot_split_root_serialization() {
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

        let root = TempDir::new().expect("transport lock root");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private transport root");
        let sentinel = root.path().join(".mcloving-dependency-resolver.lock");
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&sentinel)
            .expect("transport sentinel");
        file.write_all(TRANSPORT_LOCK_CONTENT)
            .expect("sentinel content");
        file.sync_all().expect("sentinel durability");
        let root_directory = crate::publication::open_pinned_cleanup_root(root.path())
            .expect("pinned transport root");
        let _lock = lock_transport_root(&root_directory).expect("first root lock");

        std::fs::rename(&sentinel, root.path().join("detached-transport-sentinel"))
            .expect("detach sentinel");
        let mut replacement = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&sentinel)
            .expect("replacement sentinel");
        replacement
            .write_all(TRANSPORT_LOCK_CONTENT)
            .expect("replacement content");
        replacement.sync_all().expect("replacement durability");

        let competing_root = crate::publication::open_pinned_cleanup_root(root.path())
            .expect("independently pinned competing root");
        let error = lock_transport_root(&competing_root)
            .expect_err("the stable transport root remains locked");
        assert_eq!(error.code, "DEP_TRANSPORT_ROOT_STATE_DENIED");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolution_directory_relink_cannot_redirect_writes_or_exact_cleanup() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

        let root = TempDir::new().expect("transport root");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private transport root");
        let resolution_id = Uuid::new_v4();
        let linked = root.path().join(resolution_id.to_string());
        std::fs::create_dir(&linked).expect("resolution directory");
        std::fs::set_permissions(&linked, std::fs::Permissions::from_mode(0o700))
            .expect("private resolution directory");
        let root_directory = Arc::new(
            crate::publication::open_pinned_cleanup_root(root.path())
                .expect("pinned transport root"),
        );
        let created = std::fs::symlink_metadata(&linked).expect("created resolution identity");
        let pinned = pin_transport_resolution(
            Arc::clone(&root_directory),
            root.path(),
            resolution_id,
            TransportRootIdentity {
                device: created.dev(),
                inode: created.ino(),
            },
        )
        .expect("pinned resolution directory");

        let held = root.path().join("held-resolution");
        std::fs::rename(&linked, &held).expect("unlink pinned resolution");
        let outside = TempDir::new().expect("outside directory");
        symlink(outside.path(), &linked).expect("replacement resolution symlink");
        std::fs::write(pinned.path.join("artifact.part"), b"pinned bytes")
            .expect("write through retained descriptor");

        assert_eq!(
            std::fs::read(held.join("artifact.part")).expect("pinned artifact"),
            b"pinned bytes"
        );
        assert!(!outside.path().join("artifact.part").exists());
        assert!(
            crate::publication::remove_private_tree_exact(
                &root_directory,
                root.path(),
                &linked,
                pinned.identity.device,
                pinned.identity.inode,
            )
            .is_err()
        );
        assert!(outside.path().exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolution_directory_replacement_between_creation_and_pin_is_rejected() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let root = TempDir::new().expect("transport root");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private transport root");
        let resolution_id = Uuid::new_v4();
        let linked = root.path().join(resolution_id.to_string());
        std::fs::create_dir(&linked).expect("created resolution directory");
        std::fs::set_permissions(&linked, std::fs::Permissions::from_mode(0o700))
            .expect("private created directory");
        let created = std::fs::symlink_metadata(&linked).expect("created identity");
        let created_identity = TransportRootIdentity {
            device: created.dev(),
            inode: created.ino(),
        };
        let held = root.path().join("held-created-resolution");
        std::fs::rename(&linked, &held).expect("move created directory");
        std::fs::create_dir(&linked).expect("replacement resolution directory");
        std::fs::set_permissions(&linked, std::fs::Permissions::from_mode(0o700))
            .expect("private replacement directory");
        let root_directory = Arc::new(
            crate::publication::open_pinned_cleanup_root(root.path())
                .expect("pinned transport root"),
        );

        let error =
            pin_transport_resolution(root_directory, root.path(), resolution_id, created_identity)
                .err()
                .expect("replacement must not satisfy the created identity");
        assert_eq!(error.code, "DEP_TRANSPORT_ROOT_STATE_DENIED");
        assert!(
            held.exists(),
            "the originally created inode remains explicit"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn fifo_and_device_transients_are_rejected_before_data_open() {
        use nix::sys::stat::Mode;
        use nix::unistd::mkfifo;

        let root = TempDir::new().expect("transient inspection root");
        let fifo = root.path().join("artifact.part");
        mkfifo(&fifo, Mode::S_IRUSR | Mode::S_IWUSR).expect("transient fifo");
        let deadline = Instant::now() + Duration::from_secs(1);
        let started = Instant::now();
        let error = verify_transient_file(&fifo, 0, &"0".repeat(64), deadline)
            .await
            .expect_err("non-regular transient");
        assert_eq!(error.code, "DEP_TRANSPORT_CONTENT_MISMATCH");
        assert!(started.elapsed() < Duration::from_secs(1));

        let deadline = Instant::now() + Duration::from_secs(1);
        let started = Instant::now();
        let error = verify_transient_file(Path::new("/dev/null"), 0, &"0".repeat(64), deadline)
            .await
            .expect_err("device transient");
        assert_eq!(error.code, "DEP_TRANSPORT_CONTENT_MISMATCH");
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn production_fetch_rejects_fifo_substitution_before_data_open() {
        let fixture = TransportFixture::new(
            b"contained artifact bytes".to_vec(),
            vec![b"credential-marker-not-present".to_vec()],
            "contained-maven",
            false,
        )
        .await;
        let resolution_id = Uuid::new_v4();
        let transient_path = fixture
            .transport
            .transport_root
            .join(format!(".{resolution_id}.transport"));
        TRANSIENT_OPEN_TRACE.with(|trace| trace.borrow_mut().clear());
        TRANSIENT_FIFO_SUBSTITUTION.with(|target| {
            *target.borrow_mut() = Some(transient_path.clone());
        });

        let error = fixture
            .transport
            .fetch_plan(
                resolution_id,
                &fixture.plan,
                Instant::now() + Duration::from_secs(2),
            )
            .await
            .expect_err("post-download FIFO substitution");
        assert_eq!(error.code, "DEP_TRANSPORT_CLEANUP_AMBIGUOUS");
        assert_eq!(
            fixture
                .transport
                .ensure_available()
                .expect_err("ambiguous cleanup poisons the transport")
                .code,
            "DEP_TRANSPORT_CLEANUP_RESTART_REQUIRED"
        );
        let events = TRANSIENT_OPEN_TRACE.with(|trace| {
            trace
                .borrow()
                .iter()
                .filter_map(|(opened, event)| {
                    (opened.file_name() == transient_path.file_name()).then_some(*event)
                })
                .collect::<Vec<_>>()
        });
        assert_eq!(
            events,
            ["path-inspected"],
            "the production fetch flow must reject substituted special state before data open"
        );
    }

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
                fetch_slot: tokio::sync::Mutex::new(()),
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

        async fn with_cross_artifact_marker() -> Self {
            let key = Arc::new(
                Ed25519KeyPair::from_seed_unchecked(&[9_u8; 32]).expect("contained Ed25519 key"),
            );
            let artifact_specs = [
                (
                    "com.example:first:jar",
                    "com/example/first/1.0.0/first.jar",
                    b"first-body-boundary-prefix".to_vec(),
                ),
                (
                    "com.example:second:jar",
                    "com/example/second/1.0.0/second.jar",
                    b"second-body-boundary-suffix".to_vec(),
                ),
            ];
            let mut bodies = BTreeMap::new();
            let mut nodes = artifact_specs
                .into_iter()
                .map(|(coordinate, artifact_path, body)| {
                    let mut node = PackageNode {
                        node_id: String::new(),
                        coordinate: coordinate.to_owned(),
                        exact_version: "1.0.0".to_owned(),
                        repository_id: "contained-maven".to_owned(),
                        artifact_path: artifact_path.to_owned(),
                        declared_size: body.len() as u64,
                        sha256: format!("{:x}", Sha256::digest(&body)),
                        attestation_key_id: Some("contained-key".to_owned()),
                        dependencies: Vec::new(),
                    };
                    node.node_id = canonical_node_id(Ecosystem::Maven, &node).expect("node id");
                    bodies.insert(node.artifact_path.clone(), body);
                    node
                })
                .collect::<Vec<_>>();
            nodes.sort_by(|left, right| left.node_id.cmp(&right.node_id));
            let first = bodies
                .get(&nodes[0].artifact_path)
                .expect("first sorted artifact body");
            let second = bodies
                .get(&nodes[1].artifact_path)
                .expect("second sorted artifact body");
            let mut marker = first[first.len() - 8..].to_vec();
            marker.extend_from_slice(&second[..8]);
            assert!(!contains_marker(first, std::slice::from_ref(&marker)));
            assert!(!contains_marker(second, std::slice::from_ref(&marker)));

            let mut app = Router::new();
            for node in &nodes {
                let state = RepositoryState {
                    node: node.clone(),
                    body: bodies
                        .get(&node.artifact_path)
                        .expect("artifact body")
                        .clone(),
                    key: Arc::clone(&key),
                    authorization: b"Bearer contained-credential".to_vec(),
                    repository_header: "contained-maven".to_owned(),
                    generation: 7,
                    corrupt_signature: false,
                    delay: Duration::ZERO,
                };
                app = app.merge(
                    Router::new()
                        .route(
                            &format!("/repository/{}", node.artifact_path),
                            get(artifact),
                        )
                        .with_state(state),
                );
            }
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
            let roots = nodes.iter().map(|node| node.node_id.clone()).collect();
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
                roots,
                nodes,
                graph_sha256: String::new(),
            };
            plan.graph_sha256 = canonical_graph_sha256(&plan).expect("graph digest");
            let transport = HttpTransport {
                generation: 7,
                max_header_bytes: 16_384,
                max_artifact_bytes: 1_048_576,
                max_total_artifact_bytes: 1_048_576,
                transport_root: root.path().to_path_buf(),
                markers: vec![marker],
                repositories: BTreeMap::from([("contained-maven".to_owned(), repository)]),
                fetch_slot: tokio::sync::Mutex::new(()),
                cleanup_poisoned: AtomicBool::new(false),
                _lease: None,
            };
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
            tokio::fs::read(
                fixture
                    .transport
                    .transport_root
                    .join(&fetched[0].transient_path),
            )
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

    #[tokio::test]
    async fn secret_marker_spanning_adjacent_artifacts_is_denied_by_the_real_plan_wiring() {
        let fixture = TransportFixture::with_cross_artifact_marker().await;
        let resolution_id = Uuid::new_v4();
        let transient = fixture
            ._root
            .path()
            .join(format!(".{resolution_id}.transport"));
        let error = fixture
            .transport
            .fetch_plan(
                resolution_id,
                &fixture.plan,
                Instant::now() + Duration::from_secs(2),
            )
            .await
            .expect_err("marker spanning adjacent artifacts");
        assert_eq!(error.code, "DEP_TRANSPORT_SECRET_MARKER");
        assert!(!transient.exists());
        fixture
            .transport
            .ensure_available()
            .expect("exact cleanup keeps transport available");
    }

    #[tokio::test]
    async fn final_archive_sync_failure_removes_the_exact_transport_file() {
        let fixture = TransportFixture::new(
            b"artifact".to_vec(),
            vec![b"unrelated-marker".to_vec()],
            "contained-maven",
            false,
        )
        .await;
        let resolution_id = Uuid::new_v4();
        let transient = fixture
            ._root
            .path()
            .join(format!(".{resolution_id}.transport"));
        TRANSIENT_SYNC_FAILURE.with(|target| {
            *target.borrow_mut() = Some(transient.clone());
        });
        let error = fixture
            .transport
            .fetch_plan(
                resolution_id,
                &fixture.plan,
                Instant::now() + Duration::from_secs(2),
            )
            .await
            .expect_err("final transport sync failure");
        assert_eq!(error.code, "DEP_TRANSPORT_IO_FAILED");
        assert!(!transient.exists());
        fixture
            .transport
            .ensure_available()
            .expect("exact cleanup keeps transport available");
    }

    #[tokio::test]
    async fn every_post_create_identity_failure_poisons_the_next_production_fetch() {
        for failure in [
            PostCreateInspectionFailure::ArchiveMetadata,
            PostCreateInspectionFailure::RootMetadata,
            PostCreateInspectionFailure::IdentityNotFile,
            PostCreateInspectionFailure::IdentityDeviceMismatch,
            PostCreateInspectionFailure::IdentityZeroInode,
        ] {
            let fixture = TransportFixture::new(
                b"artifact".to_vec(),
                vec![b"unrelated-marker".to_vec()],
                "contained-maven",
                false,
            )
            .await;
            let resolution_id = Uuid::new_v4();
            let transient = fixture
                ._root
                .path()
                .join(format!(".{resolution_id}.transport"));
            TRANSIENT_METADATA_FAILURE.with(|target| {
                *target.borrow_mut() = Some((transient.clone(), failure));
            });
            let error = fixture
                .transport
                .fetch_plan(
                    resolution_id,
                    &fixture.plan,
                    Instant::now() + Duration::from_secs(2),
                )
                .await
                .expect_err("post-create identity failure");
            assert_eq!(error.code, "DEP_TRANSPORT_ROOT_STATE_DENIED");
            assert!(
                transient.exists(),
                "unknown identity is preserved for restart"
            );
            let later_resolution = Uuid::new_v4();
            let later_path = fixture
                ._root
                .path()
                .join(format!(".{later_resolution}.transport"));
            let later = fixture
                .transport
                .fetch_plan(
                    later_resolution,
                    &fixture.plan,
                    Instant::now() + Duration::from_secs(2),
                )
                .await
                .expect_err("poisoned production fetch");
            assert_eq!(later.code, "DEP_TRANSPORT_CLEANUP_RESTART_REQUIRED");
            assert!(!later_path.exists());
        }
    }

    #[tokio::test]
    async fn overlapping_fetch_cannot_succeed_after_transport_is_poisoned() {
        let fixture = TransportFixture::with_response(
            b"artifact".to_vec(),
            b"artifact".to_vec(),
            vec![b"unrelated-marker".to_vec()],
            "contained-maven",
            false,
            Duration::from_millis(50),
            7,
        )
        .await;
        let failing_resolution = Uuid::new_v4();
        let failing_path = fixture
            ._root
            .path()
            .join(format!(".{failing_resolution}.transport"));
        let overlapping_resolution = Uuid::new_v4();
        let overlapping_path = fixture
            ._root
            .path()
            .join(format!(".{overlapping_resolution}.transport"));
        TRANSIENT_METADATA_FAILURE.with(|target| {
            *target.borrow_mut() = Some((
                failing_path.clone(),
                PostCreateInspectionFailure::ArchiveMetadata,
            ));
        });
        let (failing, overlapping) = tokio::join!(
            fixture.transport.fetch_plan(
                failing_resolution,
                &fixture.plan,
                Instant::now() + Duration::from_secs(2),
            ),
            fixture.transport.fetch_plan(
                overlapping_resolution,
                &fixture.plan,
                Instant::now() + Duration::from_secs(2),
            )
        );
        assert_eq!(
            failing.expect_err("post-create failure").code,
            "DEP_TRANSPORT_ROOT_STATE_DENIED"
        );
        assert_eq!(
            overlapping
                .expect_err("overlapping fetch after poison")
                .code,
            "DEP_TRANSPORT_CLEANUP_RESTART_REQUIRED"
        );
        assert!(failing_path.exists());
        assert!(!overlapping_path.exists());
    }

    #[tokio::test]
    async fn external_poison_transition_waits_for_the_active_fetch_slot() {
        let fixture = TransportFixture::with_response(
            b"artifact".to_vec(),
            b"artifact".to_vec(),
            vec![b"unrelated-marker".to_vec()],
            "contained-maven",
            false,
            Duration::from_millis(50),
            7,
        )
        .await;
        let active_resolution = Uuid::new_v4();
        let poison_completed = AtomicBool::new(false);
        let (active, ()) = tokio::join!(
            async {
                let result = fixture
                    .transport
                    .fetch_plan(
                        active_resolution,
                        &fixture.plan,
                        Instant::now() + Duration::from_secs(2),
                    )
                    .await;
                (result, poison_completed.load(Ordering::Acquire))
            },
            async {
                tokio::time::sleep(Duration::from_millis(5)).await;
                fixture.transport.preserve_cleanup_ambiguity().await;
                poison_completed.store(true, Ordering::Release);
            }
        );
        assert!(active.0.is_ok(), "active fetch finishes before poison");
        assert!(
            !active.1,
            "external poison cannot transition while a fetch holds the slot"
        );
        assert!(poison_completed.load(Ordering::Acquire));

        let later_resolution = Uuid::new_v4();
        let later = fixture
            .transport
            .fetch_plan(
                later_resolution,
                &fixture.plan,
                Instant::now() + Duration::from_secs(2),
            )
            .await
            .expect_err("later fetch after external poison");
        assert_eq!(later.code, "DEP_TRANSPORT_CLEANUP_RESTART_REQUIRED");
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
