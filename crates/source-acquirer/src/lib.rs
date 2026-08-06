use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::ffi::OsString;
use std::io::SeekFrom;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aho_corasick::AhoCorasick;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use caseless::Caseless as _;
use hmac::{Hmac, Mac as _};
use serde::de::{DeserializeOwned, DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};
use tokio::process::Command;
use tokio::sync::Mutex;
use unicode_normalization::UnicodeNormalization as _;
use url::Url;
use uuid::Uuid;

pub const PROTOCOL_VERSION: &str = "mcloving.source-acquirer/v1";

const MAX_BINDING_TEXT_BYTES: usize = 4 * 1_024;
const MAX_EXECUTABLE_BYTES: u64 = 512 * 1_024 * 1_024;
const MAX_GIT_METADATA_BYTES: usize = 64 * 1_024 * 1_024;
const MAX_GIT_STDERR_BYTES: usize = 2 * 1_024 * 1_024;
const MAX_CONFIGURED_FILES: usize = 1_000_000;
const MAX_CONFIGURED_BYTES: u64 = 512 * 1_024 * 1_024 * 1_024;
const MAX_CONFIGURED_FILE_BYTES: u64 = 32 * 1_024 * 1_024 * 1_024;
const MAX_CONFIGURED_PATH_BYTES: usize = 4 * 1_024;
const MAX_CONFIGURED_SUBMODULES: usize = 1_024;
const MAX_CONFIGURED_DEPTH: u32 = 1_000_000;
const MAX_CONFIGURED_TIMEOUT_MS: u64 = 15 * 60 * 1_000;
const MAX_LOCAL_PUBLICATION_MS: u64 = 2 * 60 * 1_000;
const TRANSPORT_QUOTA_POLL_INTERVAL: Duration = Duration::from_millis(1);
const MAX_TRANSPORT_QUOTA_SCAN_RESTARTS: usize = 3;
const MAX_AUTHORITY_BYTES: usize = 64 * 1_024;
const MAX_MARKERS: usize = 256;
const MAX_MARKER_BYTES: usize = 256 * 1_024;
const FILTER_IGNORED_WARNING: &[u8] = b"warning: filtering not recognized by server, ignoring";

type HmacSha256 = Hmac<Sha256>;

struct VerifiedFile {
    file: std::fs::File,
    invocation_path: PathBuf,
}

struct VerifiedRuntimeFile {
    binding: RuntimeBinding,
    file: std::fs::File,
    device: u64,
    inode: u64,
}

struct RuntimeDirectory {
    path: PathBuf,
    _directory: std::fs::File,
    invocation_path: PathBuf,
    links: Vec<(OsString, PathBuf)>,
}

impl RuntimeDirectory {
    fn verify(&self) -> Result<(), SourceError> {
        #[cfg(not(target_os = "linux"))]
        {
            Err(SourceError::InvalidConfig)
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

            let metadata = std::fs::metadata(&self.invocation_path)
                .map_err(|_| SourceError::BindingMismatch)?;
            if !metadata.file_type().is_dir()
                || metadata.permissions().mode() & 0o7777 != 0o500
                || metadata.uid() != nix::unistd::Uid::effective().as_raw()
            {
                return Err(SourceError::BindingMismatch);
            }
            let actual_names = std::fs::read_dir(&self.invocation_path)
                .map_err(|_| SourceError::BindingMismatch)?
                .map(|entry| {
                    entry
                        .map(|entry| entry.file_name())
                        .map_err(|_| SourceError::BindingMismatch)
                })
                .collect::<Result<BTreeSet<_>, _>>()?;
            let expected_names = self
                .links
                .iter()
                .map(|(name, _)| name.clone())
                .collect::<BTreeSet<_>>();
            if actual_names != expected_names {
                return Err(SourceError::BindingMismatch);
            }
            for (name, target) in &self.links {
                let link_path = self.invocation_path.join(name);
                let metadata = std::fs::symlink_metadata(&link_path)
                    .map_err(|_| SourceError::BindingMismatch)?;
                if !metadata.file_type().is_symlink()
                    || std::fs::read_link(link_path).map_err(|_| SourceError::BindingMismatch)?
                        != *target
                {
                    return Err(SourceError::BindingMismatch);
                }
            }
            Ok(())
        }
    }
}

impl Drop for RuntimeDirectory {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o700));
            for (name, _) in &self.links {
                let _ = std::fs::remove_file(self.path.join(name));
            }
            let _ = std::fs::remove_dir(&self.path);
        }
    }
}

struct GitExecDirectory {
    path: PathBuf,
    _directory: std::fs::File,
    invocation_path: PathBuf,
}

impl GitExecDirectory {
    fn verify(&self, git: &Path, remote_helper: &Path) -> Result<(), SourceError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (git, remote_helper);
            Err(SourceError::InvalidConfig)
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

            let metadata = std::fs::metadata(&self.invocation_path)
                .map_err(|_| SourceError::BindingMismatch)?;
            if !metadata.file_type().is_dir()
                || metadata.permissions().mode() & 0o7777 != 0o500
                || metadata.uid() != nix::unistd::Uid::effective().as_raw()
            {
                return Err(SourceError::BindingMismatch);
            }
            for (name, target) in [
                ("git", git),
                ("git-upload-pack", git),
                ("git-remote-http", remote_helper),
                ("git-remote-https", remote_helper),
            ] {
                if std::fs::read_link(self.invocation_path.join(name))
                    .map_err(|_| SourceError::BindingMismatch)?
                    != target
                {
                    return Err(SourceError::BindingMismatch);
                }
            }
            Ok(())
        }
    }
}

impl Drop for GitExecDirectory {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o700));
            for name in [
                "git",
                "git-upload-pack",
                "git-remote-http",
                "git-remote-https",
            ] {
                let _ = std::fs::remove_file(self.path.join(name));
            }
            let _ = std::fs::remove_dir(&self.path);
        }
    }
}

struct DuplicateRejectingSeed;

impl<'de> DeserializeSeed<'de> for DuplicateRejectingSeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateRejectingVisitor)
    }
}

struct DuplicateRejectingVisitor;

impl<'de> Visitor<'de> for DuplicateRejectingVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON without duplicate object members")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        DuplicateRejectingSeed.deserialize(deserializer)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        DuplicateRejectingSeed.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence
            .next_element_seed(DuplicateRejectingSeed)?
            .is_some()
        {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut members = HashSet::new();
        while let Some(member) = map.next_key::<String>()? {
            if !members.insert(member) {
                return Err(A::Error::custom("duplicate JSON object member"));
            }
            map.next_value_seed(DuplicateRejectingSeed)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustClass {
    Trusted,
    UntrustedFork,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryBinding {
    pub provider_identity: String,
    pub repository_identity: String,
    pub repository_url: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBinding {
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceConfig {
    pub protocol_version: String,
    pub schema_version: String,
    pub acquirer_id: String,
    pub deployment_identity: String,
    pub operator_identity: String,
    pub generation: u64,
    pub primary_repository: RepositoryBinding,
    pub allow_untrusted_forks: bool,
    pub allowed_fork_repositories: Vec<RepositoryBinding>,
    pub allowed_submodule_repositories: Vec<RepositoryBinding>,
    pub allowed_ref_prefixes: Vec<String>,
    pub allowed_sparse_roots: Vec<String>,
    pub git_executable_path: PathBuf,
    pub git_executable_sha256: String,
    pub git_remote_https_executable_path: PathBuf,
    pub git_remote_https_executable_sha256: String,
    pub runtime_closure: Vec<RuntimeBinding>,
    pub runtime_closure_sha256: String,
    pub git_version: String,
    pub grant_id: String,
    pub grant_version: String,
    pub grant_scope: String,
    pub grant_expires_unix_ms: i64,
    pub credential_username: String,
    pub credential_sha256: String,
    pub receipt_signing_key_id: String,
    pub receipt_signing_key_sha256: String,
    pub secret_marker_set_sha256: String,
    pub max_depth: u32,
    pub max_files: usize,
    pub max_total_bytes: u64,
    pub max_file_bytes: u64,
    pub max_transport_bytes: u64,
    pub max_path_bytes: usize,
    pub max_submodules: usize,
    pub command_timeout_ms: u64,
    pub output_root: PathBuf,
    #[serde(default)]
    pub ca_bundle_path: Option<PathBuf>,
    #[serde(default)]
    pub ca_bundle_sha256: Option<String>,
    #[serde(default)]
    pub test_allow_file_repositories: bool,
    #[serde(default)]
    pub test_allow_http_loopback: bool,
}

impl SourceConfig {
    pub fn canonical_digest(&self) -> Result<String, SourceError> {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubmoduleRequest {
    pub path: String,
    pub provider_identity: String,
    pub repository_identity: String,
    pub repository_url: String,
    pub authenticated_ref: String,
    pub exact_commit: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcquisitionRequest {
    pub acquisition_id: Uuid,
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub pipeline_id: Uuid,
    pub build_id: Uuid,
    pub attempt_id: Uuid,
    pub checkout_name: String,
    pub acquirer_id: String,
    pub expected_implementation_sha256: String,
    pub expected_git_sha256: String,
    pub expected_git_remote_https_sha256: String,
    pub expected_config_sha256: String,
    pub protocol_version: String,
    pub schema_version: String,
    pub expected_generation: u64,
    pub rollback_from_generation: Option<u64>,
    pub provider_identity: String,
    pub repository_identity: String,
    pub repository_url: String,
    pub authenticated_ref: String,
    pub exact_commit: String,
    pub source_identity: String,
    pub trust_class: TrustClass,
    pub depth: u32,
    pub sparse_roots: Vec<String>,
    pub submodules: Vec<SubmoduleRequest>,
    pub requested_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub audit_lineage: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestEntry {
    pub path: String,
    pub git_mode: String,
    pub git_object_id: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryTreeReceipt {
    pub path: String,
    pub provider_identity: String,
    pub repository_identity: String,
    pub repository_url: String,
    pub authenticated_ref: String,
    pub resolved_commit: String,
    pub resolved_tree: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcquisitionReceipt {
    pub protocol_version: String,
    pub schema_version: String,
    pub acquisition_id: Uuid,
    pub request_sha256: String,
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub pipeline_id: Uuid,
    pub build_id: Uuid,
    pub attempt_id: Uuid,
    pub checkout_name: String,
    pub acquirer_id: String,
    pub acquirer_implementation_sha256: String,
    pub git_implementation_sha256: String,
    pub git_remote_https_implementation_sha256: String,
    pub runtime_closure_sha256: String,
    pub git_version: String,
    pub acquirer_config_sha256: String,
    pub deployment_identity: String,
    pub operator_identity: String,
    pub generation: u64,
    pub rollback_from_generation: Option<u64>,
    pub source_identity: String,
    pub trust_class: TrustClass,
    pub grant_id: String,
    pub grant_version: String,
    pub grant_scope: String,
    pub depth: u32,
    pub sparse_roots: Vec<String>,
    pub repository_trees: Vec<RepositoryTreeReceipt>,
    pub manifest_sha256: String,
    pub content_sha256: String,
    pub materialized_files: usize,
    pub materialized_bytes: u64,
    pub transport_bytes: u64,
    pub output_relative_path: String,
    pub acquired_at_unix_ms: i64,
    pub publication_deadline_unix_ms: i64,
    pub audit_lineage: String,
    pub signing_key_id: String,
    pub secret_marker_set_sha256: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AcquisitionClaim {
    protocol_version: String,
    request_sha256: String,
    publication_deadline_unix_ms: i64,
}

#[derive(Clone, Debug)]
struct GitTreeEntry {
    mode: String,
    kind: String,
    object_id: String,
    path: String,
}

#[derive(Clone, Debug)]
struct RepositoryWork {
    prefix: String,
    binding: RepositoryBinding,
    authenticated_ref: String,
    exact_commit: String,
    ancestry: Vec<(String, String)>,
}

#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("source acquirer configuration is invalid")]
    InvalidConfig,
    #[error("source acquisition request does not match the certified configuration")]
    BindingMismatch,
    #[error("source acquisition request is expired or outside its bounded window")]
    ExpiredRequest,
    #[error("source credential grant is expired")]
    ExpiredGrant,
    #[error("repository or ref is not admitted")]
    RepositoryDenied,
    #[error("requested ref did not resolve to the exact commit")]
    RevisionMismatch,
    #[error("submodule graph is missing, substituted, cyclic, or excessive")]
    SubmoduleMismatch,
    #[error("repository tree contains an unsafe or unsupported path")]
    UnsafeTree,
    #[error("source acquisition exceeded a certified resource bound")]
    LimitExceeded,
    #[error("source credential was denied")]
    Unauthorized,
    #[error("source repository was unavailable")]
    SourceUnavailable,
    #[error("source acquisition identifier was replayed with different content")]
    ReplayMismatch,
    #[error("a prior acquisition claim is incomplete and requires reconciliation")]
    AmbiguousClaim,
    #[error("stored source receipt or manifest failed integrity verification")]
    InvalidStoredReceipt,
    #[error("source acquirer private state is unavailable")]
    StateUnavailable,
}

impl SourceError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidConfig => "invalid_config",
            Self::BindingMismatch => "binding_mismatch",
            Self::ExpiredRequest => "expired_request",
            Self::ExpiredGrant => "expired_grant",
            Self::RepositoryDenied => "repository_denied",
            Self::RevisionMismatch => "revision_mismatch",
            Self::SubmoduleMismatch => "submodule_mismatch",
            Self::UnsafeTree => "unsafe_tree",
            Self::LimitExceeded => "limit_exceeded",
            Self::Unauthorized => "unauthorized",
            Self::SourceUnavailable => "source_unavailable",
            Self::ReplayMismatch => "replay_mismatch",
            Self::AmbiguousClaim => "ambiguous_claim",
            Self::InvalidStoredReceipt => "invalid_stored_receipt",
            Self::StateUnavailable => "state_unavailable",
        }
    }
}

pub struct SourceAcquirer {
    config: SourceConfig,
    config_sha256: String,
    implementation_sha256: String,
    git_executable: VerifiedFile,
    git_remote_https_executable: VerifiedFile,
    askpass_executable: VerifiedFile,
    ca_bundle: Option<VerifiedFile>,
    runtime_closure: Vec<VerifiedRuntimeFile>,
    runtime_directory: RuntimeDirectory,
    git_exec_directory: GitExecDirectory,
    credential_path: PathBuf,
    signing_key: Vec<u8>,
    secret_marker_matcher: AhoCorasick,
    admission: Mutex<()>,
}

impl SourceAcquirer {
    pub async fn new(
        config: SourceConfig,
        implementation_sha256: String,
        credential_path: PathBuf,
        credential: &[u8],
        signing_key: Vec<u8>,
        secret_markers: Vec<Vec<u8>>,
    ) -> Result<Self, SourceError> {
        validate_config(
            &config,
            &implementation_sha256,
            credential,
            &signing_key,
            &secret_markers,
        )?;
        let credential_on_disk =
            read_private_bounded_regular_file(&credential_path, MAX_AUTHORITY_BYTES).await?;
        if credential_on_disk != credential {
            return Err(SourceError::InvalidConfig);
        }
        ensure_private_output_root(&config.output_root).await?;
        let git_executable = snapshot_verified_file(
            &config.git_executable_path,
            &config.git_executable_sha256,
            "mcloving-git",
            0o500,
        )
        .await?;
        let git_remote_https_executable = snapshot_verified_file(
            &config.git_remote_https_executable_path,
            &config.git_remote_https_executable_sha256,
            "mcloving-git-remote-https",
            0o500,
        )
        .await?;
        let askpass_executable_path =
            std::env::current_exe().map_err(|_| SourceError::InvalidConfig)?;
        let askpass_executable = snapshot_verified_file(
            &askpass_executable_path,
            &implementation_sha256,
            "mcloving-source-askpass",
            0o500,
        )
        .await?;
        let ca_bundle = match (&config.ca_bundle_path, &config.ca_bundle_sha256) {
            (Some(path), Some(expected)) => {
                Some(snapshot_verified_file(path, expected, "mcloving-source-ca", 0o400).await?)
            }
            (None, None) => None,
            _ => return Err(SourceError::InvalidConfig),
        };
        let runtime_closure = open_runtime_closure(&config.runtime_closure).await?;
        let runtime_directory =
            create_runtime_directory(&config.output_root, &config.runtime_closure)?;
        let observed_runtime = trace_runtime_closure(
            &[
                git_executable.invocation_path.clone(),
                git_remote_https_executable.invocation_path.clone(),
                askpass_executable.invocation_path.clone(),
            ],
            Some(&runtime_directory.invocation_path),
        )
        .await?;
        let configured_runtime = config
            .runtime_closure
            .iter()
            .map(|binding| binding.path.clone())
            .collect::<BTreeSet<_>>();
        if observed_runtime != configured_runtime {
            return Err(SourceError::InvalidConfig);
        }
        let git_exec_directory = create_git_exec_directory(
            &config.output_root,
            &git_executable.invocation_path,
            &git_remote_https_executable.invocation_path,
        )?;
        let config_sha256 = config.canonical_digest()?;
        let secret_marker_matcher =
            AhoCorasick::new(&secret_markers).map_err(|_| SourceError::InvalidConfig)?;
        let acquirer = Self {
            config,
            config_sha256,
            implementation_sha256,
            git_executable,
            git_remote_https_executable,
            askpass_executable,
            ca_bundle,
            runtime_closure,
            runtime_directory,
            git_exec_directory,
            credential_path,
            signing_key,
            secret_marker_matcher,
            admission: Mutex::new(()),
        };
        let version = acquirer
            .run_git(vec![OsString::from("--version")], MAX_BINDING_TEXT_BYTES)
            .await?;
        let version = String::from_utf8(version).map_err(|_| SourceError::InvalidConfig)?;
        if version.trim() != acquirer.config.git_version {
            return Err(SourceError::InvalidConfig);
        }
        Ok(acquirer)
    }

    pub fn config_sha256(&self) -> &str {
        &self.config_sha256
    }

    pub async fn acquire(
        &self,
        request: &AcquisitionRequest,
    ) -> Result<AcquisitionReceipt, SourceError> {
        let _process_guard = self.admission.lock().await;
        let _root_lock = lock_output_root(&self.config.output_root).await?;
        let now = now_unix_ms()?;
        let request_sha256 = self.validate_request(request, now)?;
        if claim_path(&self.config.output_root, request.acquisition_id).exists() {
            return Err(SourceError::AmbiguousClaim);
        }
        if let Some(receipt) = self.load_receipt(request.acquisition_id).await? {
            if receipt.request_sha256 != request_sha256 {
                return Err(SourceError::ReplayMismatch);
            }
            self.verify_receipt(&receipt).await?;
            return Ok(receipt);
        }
        self.verify_runtime_authority(true).await?;
        let publication_deadline_unix_ms = self.publication_deadline(request, now)?;
        self.store_claim(
            request.acquisition_id,
            &AcquisitionClaim {
                protocol_version: PROTOCOL_VERSION.to_owned(),
                request_sha256: request_sha256.clone(),
                publication_deadline_unix_ms,
            },
        )
        .await?;

        let stage = self.config.output_root.join(format!(
            ".stage-{}-{}",
            request.acquisition_id,
            Uuid::new_v4()
        ));
        create_private_directory(&stage).await?;
        let result = self
            .acquire_into_stage(
                request,
                &request_sha256,
                publication_deadline_unix_ms,
                &stage,
            )
            .await;
        if result.is_err() {
            let _ = make_tree_owner_writable(&stage).await;
            let _ = tokio::fs::remove_dir_all(&stage).await;
        }
        result
    }

    async fn acquire_into_stage(
        &self,
        request: &AcquisitionRequest,
        request_sha256: &str,
        publication_deadline_unix_ms: i64,
        stage: &Path,
    ) -> Result<AcquisitionReceipt, SourceError> {
        self.ensure_before_deadline(publication_deadline_unix_ms)?;
        let repositories_dir = stage.join("repositories");
        let tree_dir = stage.join("tree");
        create_private_directory(&repositories_dir).await?;
        create_private_directory(&tree_dir).await?;

        let expected_submodules = request
            .submodules
            .iter()
            .map(|submodule| (submodule.path.clone(), submodule))
            .collect::<BTreeMap<_, _>>();
        let mut observed_submodules = BTreeSet::new();
        let mut work = VecDeque::from([RepositoryWork {
            prefix: String::new(),
            binding: RepositoryBinding {
                provider_identity: request.provider_identity.clone(),
                repository_identity: request.repository_identity.clone(),
                repository_url: request.repository_url.clone(),
            },
            authenticated_ref: request.authenticated_ref.clone(),
            exact_commit: request.exact_commit.clone(),
            ancestry: vec![(
                request.repository_identity.clone(),
                request.exact_commit.clone(),
            )],
        }]);
        let mut repository_trees = Vec::new();
        let mut manifest = Vec::new();
        let mut exact_paths = HashSet::new();
        let mut folded_paths = HashMap::new();
        let mut materialized_bytes = 0_u64;

        while let Some(repository) = work.pop_front() {
            self.ensure_before_deadline(publication_deadline_unix_ms)?;
            let repository_index = repository_trees.len();
            let git_dir = repositories_dir.join(format!("{repository_index}.git"));
            self.fetch_repository(
                &repository,
                request.depth,
                &git_dir,
                publication_deadline_unix_ms,
                &repositories_dir,
            )
            .await?;
            let resolved_tree = self
                .git_text(
                    vec![
                        OsString::from("--git-dir"),
                        git_dir.as_os_str().to_owned(),
                        OsString::from("rev-parse"),
                        OsString::from("--verify"),
                        OsString::from(format!("{}^{{tree}}", repository.exact_commit)),
                    ],
                    256,
                )
                .await?;
            if !is_object_id(&resolved_tree) {
                return Err(SourceError::SourceUnavailable);
            }
            let entries = self.list_tree(&git_dir, &repository.exact_commit).await?;
            let module_declarations = self
                .read_gitmodules(
                    &git_dir,
                    &entries,
                    publication_deadline_unix_ms,
                    &repositories_dir,
                )
                .await?;
            let mut observed_local_gitlinks = BTreeSet::new();

            for entry in entries {
                let full_path = prefixed_path(&repository.prefix, &entry.path)?;
                if entry.mode == "160000" {
                    if entry.kind != "commit" || !is_object_id(&entry.object_id) {
                        return Err(SourceError::SubmoduleMismatch);
                    }
                    let declaration = module_declarations
                        .get(&entry.path)
                        .ok_or(SourceError::SubmoduleMismatch)?;
                    let expected = expected_submodules
                        .get(&full_path)
                        .ok_or(SourceError::SubmoduleMismatch)?;
                    if expected.exact_commit != entry.object_id
                        || expected.repository_url != *declaration
                        || expected.provider_identity.trim().is_empty()
                        || expected.repository_identity.trim().is_empty()
                        || !self
                            .config
                            .allowed_submodule_repositories
                            .iter()
                            .any(|allowed| {
                                allowed.provider_identity == expected.provider_identity
                                    && allowed.repository_identity == expected.repository_identity
                                    && allowed.repository_url == expected.repository_url
                            })
                        || !valid_ref(&expected.authenticated_ref)
                        || !self.ref_allowed(&expected.authenticated_ref)
                    {
                        return Err(SourceError::SubmoduleMismatch);
                    }
                    if repository.ancestry.iter().any(|(identity, commit)| {
                        identity == &expected.repository_identity
                            && commit == &expected.exact_commit
                    }) {
                        return Err(SourceError::SubmoduleMismatch);
                    }
                    observed_local_gitlinks.insert(entry.path.clone());
                    observed_submodules.insert(full_path.clone());
                    let mut ancestry = repository.ancestry.clone();
                    ancestry.push((
                        expected.repository_identity.clone(),
                        expected.exact_commit.clone(),
                    ));
                    work.push_back(RepositoryWork {
                        prefix: full_path.clone(),
                        binding: RepositoryBinding {
                            provider_identity: expected.provider_identity.clone(),
                            repository_identity: expected.repository_identity.clone(),
                            repository_url: expected.repository_url.clone(),
                        },
                        authenticated_ref: expected.authenticated_ref.clone(),
                        exact_commit: expected.exact_commit.clone(),
                        ancestry,
                    });
                    if self.path_selected(&full_path, &request.sparse_roots) {
                        self.reserve_manifest_path(
                            &full_path,
                            &mut exact_paths,
                            &mut folded_paths,
                        )?;
                        create_relative_directories(&tree_dir, Path::new(&full_path)).await?;
                        manifest.push(ManifestEntry {
                            path: full_path,
                            git_mode: entry.mode,
                            git_object_id: entry.object_id.clone(),
                            bytes: 0,
                            sha256: sha256_hex(entry.object_id.as_bytes()),
                        });
                        if manifest.len() > self.config.max_files {
                            return Err(SourceError::LimitExceeded);
                        }
                    }
                    continue;
                }
                if !matches!(entry.mode.as_str(), "100644" | "100755" | "120000")
                    || entry.kind != "blob"
                    || !is_object_id(&entry.object_id)
                {
                    return Err(SourceError::UnsafeTree);
                }
                if !self.path_selected(&full_path, &request.sparse_roots) {
                    continue;
                }
                self.reserve_manifest_path(&full_path, &mut exact_paths, &mut folded_paths)?;
                let blob_result = self
                    .run_credential_git_until(
                        vec![
                            OsString::from("--git-dir"),
                            git_dir.as_os_str().to_owned(),
                            OsString::from("cat-file"),
                            OsString::from("blob"),
                            OsString::from(&entry.object_id),
                        ],
                        usize::try_from(self.config.max_file_bytes)
                            .unwrap_or(usize::MAX)
                            .min(usize::MAX - 1),
                        publication_deadline_unix_ms,
                        &repositories_dir,
                    )
                    .await;
                self.ensure_transport_quota(&repositories_dir).await?;
                let blob = blob_result?;
                let blob_bytes =
                    u64::try_from(blob.len()).map_err(|_| SourceError::LimitExceeded)?;
                if blob_bytes > self.config.max_file_bytes {
                    return Err(SourceError::LimitExceeded);
                }
                materialized_bytes = materialized_bytes
                    .checked_add(blob_bytes)
                    .ok_or(SourceError::LimitExceeded)?;
                if materialized_bytes > self.config.max_total_bytes {
                    return Err(SourceError::LimitExceeded);
                }
                self.reject_secret_markers(&blob)?;
                self.materialize_entry(&tree_dir, &full_path, &entry.mode, &blob)
                    .await?;
                manifest.push(ManifestEntry {
                    path: full_path,
                    git_mode: entry.mode,
                    git_object_id: entry.object_id,
                    bytes: blob_bytes,
                    sha256: sha256_hex(&blob),
                });
                if manifest.len() > self.config.max_files {
                    return Err(SourceError::LimitExceeded);
                }
            }
            if module_declarations.len() != observed_local_gitlinks.len()
                || module_declarations
                    .keys()
                    .any(|path| !observed_local_gitlinks.contains(path))
            {
                return Err(SourceError::SubmoduleMismatch);
            }
            repository_trees.push(RepositoryTreeReceipt {
                path: repository.prefix,
                provider_identity: repository.binding.provider_identity,
                repository_identity: repository.binding.repository_identity,
                repository_url: repository.binding.repository_url,
                authenticated_ref: repository.authenticated_ref,
                resolved_commit: repository.exact_commit,
                resolved_tree,
            });
            if repository_trees.len().saturating_sub(1) > self.config.max_submodules {
                return Err(SourceError::LimitExceeded);
            }
        }

        if observed_submodules.len() != expected_submodules.len()
            || expected_submodules
                .keys()
                .any(|path| !observed_submodules.contains(path))
            || manifest.is_empty()
        {
            return Err(SourceError::SubmoduleMismatch);
        }
        manifest.sort_by(|left, right| left.path.cmp(&right.path));
        repository_trees.sort_by(|left, right| left.path.cmp(&right.path));
        let manifest_bytes =
            serde_json::to_vec(&manifest).map_err(|_| SourceError::StateUnavailable)?;
        let manifest_sha256 = sha256_hex(&manifest_bytes);
        let transport_bytes = self.ensure_transport_quota(&repositories_dir).await?;
        write_new_file(&stage.join("manifest.json"), &manifest_bytes, 0o600).await?;
        sync_tree(&tree_dir).await?;
        make_tree_read_only(&tree_dir).await?;

        let acquired_at_unix_ms = now_unix_ms()?;
        if acquired_at_unix_ms >= publication_deadline_unix_ms {
            return Err(SourceError::ExpiredRequest);
        }
        let mut receipt = AcquisitionReceipt {
            protocol_version: PROTOCOL_VERSION.to_owned(),
            schema_version: self.config.schema_version.clone(),
            acquisition_id: request.acquisition_id,
            request_sha256: request_sha256.to_owned(),
            organization_id: request.organization_id,
            project_id: request.project_id,
            pipeline_id: request.pipeline_id,
            build_id: request.build_id,
            attempt_id: request.attempt_id,
            checkout_name: request.checkout_name.clone(),
            acquirer_id: self.config.acquirer_id.clone(),
            acquirer_implementation_sha256: self.implementation_sha256.clone(),
            git_implementation_sha256: self.config.git_executable_sha256.clone(),
            git_remote_https_implementation_sha256: self
                .config
                .git_remote_https_executable_sha256
                .clone(),
            runtime_closure_sha256: self.config.runtime_closure_sha256.clone(),
            git_version: self.config.git_version.clone(),
            acquirer_config_sha256: self.config_sha256.clone(),
            deployment_identity: self.config.deployment_identity.clone(),
            operator_identity: self.config.operator_identity.clone(),
            generation: self.config.generation,
            rollback_from_generation: request.rollback_from_generation,
            source_identity: request.source_identity.clone(),
            trust_class: request.trust_class,
            grant_id: self.config.grant_id.clone(),
            grant_version: self.config.grant_version.clone(),
            grant_scope: self.config.grant_scope.clone(),
            depth: request.depth,
            sparse_roots: request.sparse_roots.clone(),
            repository_trees,
            manifest_sha256: manifest_sha256.clone(),
            content_sha256: manifest_sha256,
            materialized_files: manifest.len(),
            materialized_bytes,
            transport_bytes,
            output_relative_path: format!("{}/tree", request.acquisition_id),
            acquired_at_unix_ms,
            publication_deadline_unix_ms,
            audit_lineage: request.audit_lineage.clone(),
            signing_key_id: self.config.receipt_signing_key_id.clone(),
            secret_marker_set_sha256: self.config.secret_marker_set_sha256.clone(),
            signature: String::new(),
        };
        receipt.signature = self.sign_receipt(&receipt)?;
        let receipt_bytes =
            serde_json::to_vec(&receipt).map_err(|_| SourceError::StateUnavailable)?;
        write_new_file(&stage.join("receipt.json"), &receipt_bytes, 0o600).await?;
        tokio::fs::remove_dir_all(&repositories_dir)
            .await
            .map_err(|_| SourceError::StateUnavailable)?;
        set_file_mode_and_sync(&stage.join("manifest.json"), 0o400).await?;
        set_file_mode_and_sync(&stage.join("receipt.json"), 0o400).await?;
        sync_directory(stage).await?;

        self.ensure_before_deadline(publication_deadline_unix_ms)?;
        set_mode(stage, 0o500).await?;
        sync_directory(stage).await?;
        self.ensure_before_deadline(publication_deadline_unix_ms)?;
        publish_stage(
            &self.config.output_root,
            stage,
            request.acquisition_id,
            &AcquisitionClaim {
                protocol_version: PROTOCOL_VERSION.to_owned(),
                request_sha256: request_sha256.to_owned(),
                publication_deadline_unix_ms,
            },
        )
        .await?;
        Ok(receipt)
    }

    fn validate_request(
        &self,
        request: &AcquisitionRequest,
        now: i64,
    ) -> Result<String, SourceError> {
        let expected_binding = RepositoryBinding {
            provider_identity: request.provider_identity.clone(),
            repository_identity: request.repository_identity.clone(),
            repository_url: request.repository_url.clone(),
        };
        let repository_admitted = match request.trust_class {
            TrustClass::Trusted => expected_binding == self.config.primary_repository,
            TrustClass::UntrustedFork => {
                self.config.allow_untrusted_forks
                    && self
                        .config
                        .allowed_fork_repositories
                        .contains(&expected_binding)
            }
        };
        if request.acquisition_id.is_nil()
            || request.organization_id.is_nil()
            || request.project_id.is_nil()
            || request.pipeline_id.is_nil()
            || request.build_id.is_nil()
            || request.attempt_id.is_nil()
            || request.checkout_name.trim().is_empty()
            || request.source_identity.trim().is_empty()
            || request.audit_lineage.trim().is_empty()
            || request.acquirer_id != self.config.acquirer_id
            || request.expected_implementation_sha256 != self.implementation_sha256
            || request.expected_git_sha256 != self.config.git_executable_sha256
            || request.expected_git_remote_https_sha256
                != self.config.git_remote_https_executable_sha256
            || request.expected_config_sha256 != self.config_sha256
            || request.protocol_version != PROTOCOL_VERSION
            || request.schema_version != self.config.schema_version
            || request.expected_generation != self.config.generation
            || request
                .rollback_from_generation
                .is_some_and(|generation| generation >= self.config.generation)
            || request.requested_at_unix_ms > now
            || request.expires_at_unix_ms <= request.requested_at_unix_ms
            || request.depth == 0
            || request.depth > self.config.max_depth
            || request.submodules.len() > self.config.max_submodules
            || !repository_admitted
            || !valid_ref(&request.authenticated_ref)
            || !self.ref_allowed(&request.authenticated_ref)
            || !is_object_id(&request.exact_commit)
        {
            return Err(SourceError::BindingMismatch);
        }
        if request.expires_at_unix_ms <= now {
            return Err(SourceError::ExpiredRequest);
        }
        if self.config.grant_expires_unix_ms <= now {
            return Err(SourceError::ExpiredGrant);
        }
        if [
            &request.checkout_name,
            &request.source_identity,
            &request.audit_lineage,
            &request.repository_identity,
            &request.repository_url,
            &request.authenticated_ref,
        ]
        .iter()
        .any(|value| !valid_binding_text(value))
        {
            return Err(SourceError::BindingMismatch);
        }
        validate_sparse_roots(
            &request.sparse_roots,
            &self.config.allowed_sparse_roots,
            self.config.max_path_bytes,
        )
        .map_err(|_| SourceError::BindingMismatch)?;
        let mut submodule_paths = BTreeSet::new();
        for submodule in &request.submodules {
            validate_repository_url(
                &submodule.repository_url,
                self.config.test_allow_file_repositories,
                self.config.test_allow_http_loopback,
            )
            .map_err(|_| SourceError::SubmoduleMismatch)?;
            validate_relative_path(&submodule.path, self.config.max_path_bytes)
                .map_err(|_| SourceError::SubmoduleMismatch)?;
            if !submodule_paths.insert(submodule.path.clone())
                || !is_object_id(&submodule.exact_commit)
                || !valid_ref(&submodule.authenticated_ref)
                || !self.ref_allowed(&submodule.authenticated_ref)
            {
                return Err(SourceError::SubmoduleMismatch);
            }
        }
        canonical_digest(request)
    }

    fn ref_allowed(&self, reference: &str) -> bool {
        self.config
            .allowed_ref_prefixes
            .iter()
            .any(|prefix| reference.starts_with(prefix))
    }

    fn publication_deadline(
        &self,
        request: &AcquisitionRequest,
        now: i64,
    ) -> Result<i64, SourceError> {
        let lifetime = self
            .config
            .command_timeout_ms
            .checked_mul(
                u64::try_from(request.submodules.len())
                    .unwrap_or(u64::MAX)
                    .saturating_add(1)
                    .saturating_mul(8),
            )
            .and_then(|value| value.checked_add(MAX_LOCAL_PUBLICATION_MS))
            .and_then(|value| i64::try_from(value).ok())
            .ok_or(SourceError::InvalidConfig)?;
        let deadline = now
            .checked_add(lifetime)
            .ok_or(SourceError::InvalidConfig)?
            .min(request.expires_at_unix_ms)
            .min(self.config.grant_expires_unix_ms);
        if deadline <= now {
            Err(SourceError::ExpiredRequest)
        } else {
            Ok(deadline)
        }
    }

    fn ensure_before_deadline(&self, deadline: i64) -> Result<(), SourceError> {
        if now_unix_ms()? >= deadline {
            Err(SourceError::ExpiredRequest)
        } else {
            Ok(())
        }
    }

    async fn ensure_transport_quota(&self, root: &Path) -> Result<u64, SourceError> {
        let bytes = allocated_storage_bytes(root).await?;
        if bytes > self.config.max_transport_bytes {
            Err(SourceError::LimitExceeded)
        } else {
            Ok(bytes)
        }
    }

    async fn fetch_repository(
        &self,
        repository: &RepositoryWork,
        depth: u32,
        git_dir: &Path,
        deadline: i64,
        transport_root: &Path,
    ) -> Result<(), SourceError> {
        create_private_directory(git_dir).await?;
        let mut init_arguments = vec![OsString::from("init"), OsString::from("--bare")];
        if repository.exact_commit.len() == 64 {
            init_arguments.push(OsString::from("--object-format=sha256"));
        }
        init_arguments.push(git_dir.as_os_str().to_owned());
        self.run_git_until(init_arguments, MAX_GIT_METADATA_BYTES, deadline)
            .await?;
        self.ensure_transport_quota(transport_root).await?;
        for (key, value) in [
            (
                "remote.origin.url",
                repository.binding.repository_url.as_str(),
            ),
            ("remote.origin.promisor", "true"),
            ("remote.origin.partialclonefilter", "blob:none"),
            ("extensions.partialClone", "origin"),
        ] {
            self.run_git_until(
                vec![
                    OsString::from("--git-dir"),
                    git_dir.as_os_str().to_owned(),
                    OsString::from("config"),
                    OsString::from(key),
                    OsString::from(value),
                ],
                MAX_GIT_METADATA_BYTES,
                deadline,
            )
            .await?;
            self.ensure_transport_quota(transport_root).await?;
        }
        self.ensure_before_deadline(deadline)?;
        let mut arguments = vec![
            OsString::from("--git-dir"),
            git_dir.as_os_str().to_owned(),
            OsString::from("fetch"),
            OsString::from("--filter=blob:none"),
            OsString::from("--no-tags"),
            OsString::from("--force"),
        ];
        arguments.push(OsString::from(format!("--depth={depth}")));
        arguments.extend([
            OsString::from("--"),
            OsString::from("origin"),
            OsString::from(&repository.authenticated_ref),
        ]);
        let fetch = self
            .run_credential_git_until(arguments, MAX_GIT_METADATA_BYTES, deadline, transport_root)
            .await;
        self.ensure_transport_quota(transport_root).await?;
        fetch?;
        self.ensure_before_deadline(deadline)?;
        let resolved = self
            .git_text(
                vec![
                    OsString::from("--git-dir"),
                    git_dir.as_os_str().to_owned(),
                    OsString::from("rev-parse"),
                    OsString::from("--verify"),
                    OsString::from("FETCH_HEAD^{commit}"),
                ],
                256,
            )
            .await?;
        if resolved != repository.exact_commit {
            return Err(SourceError::RevisionMismatch);
        }
        Ok(())
    }

    async fn list_tree(
        &self,
        git_dir: &Path,
        commit: &str,
    ) -> Result<Vec<GitTreeEntry>, SourceError> {
        let bytes = self
            .run_git(
                vec![
                    OsString::from("--git-dir"),
                    git_dir.as_os_str().to_owned(),
                    OsString::from("ls-tree"),
                    OsString::from("-rz"),
                    OsString::from("--full-tree"),
                    OsString::from(commit),
                ],
                MAX_GIT_METADATA_BYTES,
            )
            .await?;
        parse_ls_tree(&bytes, self.config.max_path_bytes, self.config.max_files)
    }

    async fn read_gitmodules(
        &self,
        git_dir: &Path,
        entries: &[GitTreeEntry],
        deadline: i64,
        transport_root: &Path,
    ) -> Result<BTreeMap<String, String>, SourceError> {
        let Some(entry) = entries.iter().find(|entry| entry.path == ".gitmodules") else {
            return Ok(BTreeMap::new());
        };
        if entry.mode != "100644" || entry.kind != "blob" {
            return Err(SourceError::SubmoduleMismatch);
        }
        let bytes_result = self
            .run_credential_git_until(
                vec![
                    OsString::from("--git-dir"),
                    git_dir.as_os_str().to_owned(),
                    OsString::from("cat-file"),
                    OsString::from("blob"),
                    OsString::from(&entry.object_id),
                ],
                MAX_AUTHORITY_BYTES,
                deadline,
                transport_root,
            )
            .await;
        self.ensure_transport_quota(transport_root).await?;
        let bytes = bytes_result?;
        self.reject_secret_markers(&bytes)?;
        parse_gitmodules(&bytes, self.config.max_path_bytes)
    }

    async fn materialize_entry(
        &self,
        root: &Path,
        path: &str,
        mode: &str,
        bytes: &[u8],
    ) -> Result<(), SourceError> {
        let relative = Path::new(path);
        let parent = relative.parent().ok_or(SourceError::UnsafeTree)?;
        create_relative_directories(root, parent).await?;
        let destination = root.join(relative);
        match mode {
            "100644" => write_new_file(&destination, bytes, 0o600).await,
            "100755" => write_new_file(&destination, bytes, 0o700).await,
            "120000" => create_safe_symlink(root, relative, bytes).await,
            _ => Err(SourceError::UnsafeTree),
        }
    }

    fn reserve_manifest_path(
        &self,
        path: &str,
        exact_paths: &mut HashSet<String>,
        folded_paths: &mut HashMap<String, String>,
    ) -> Result<(), SourceError> {
        validate_relative_path(path, self.config.max_path_bytes)?;
        if exact_paths.contains(path)
            || exact_paths
                .iter()
                .any(|reserved| reserved.starts_with(&format!("{path}/")))
        {
            return Err(SourceError::UnsafeTree);
        }
        let mut prefix = String::new();
        let components = path.split('/').collect::<Vec<_>>();
        for (index, component) in components.iter().enumerate() {
            if index > 0 {
                prefix.push('/');
            }
            prefix.push_str(component);
            let folded = compatibility_case_key(&prefix);
            if folded_paths
                .get(&folded)
                .is_some_and(|reserved| reserved != &prefix)
            {
                return Err(SourceError::UnsafeTree);
            }
            folded_paths.entry(folded).or_insert_with(|| prefix.clone());
        }
        exact_paths.insert(path.to_owned());
        Ok(())
    }

    fn path_selected(&self, path: &str, sparse_roots: &[String]) -> bool {
        sparse_roots.is_empty()
            || sparse_roots.iter().any(|root| {
                path == root
                    || path
                        .strip_prefix(root)
                        .is_some_and(|suffix| suffix.starts_with('/'))
                    || root
                        .strip_prefix(path)
                        .is_some_and(|suffix| suffix.starts_with('/'))
            })
    }

    async fn git_text(
        &self,
        arguments: Vec<OsString>,
        max_stdout: usize,
    ) -> Result<String, SourceError> {
        let bytes = self.run_git(arguments, max_stdout).await?;
        let value = String::from_utf8(bytes).map_err(|_| SourceError::SourceUnavailable)?;
        Ok(value.trim().to_owned())
    }

    async fn run_git(
        &self,
        arguments: Vec<OsString>,
        max_stdout: usize,
    ) -> Result<Vec<u8>, SourceError> {
        self.run_git_with_deadline(arguments, max_stdout, None, false, None)
            .await
    }

    async fn run_git_until(
        &self,
        arguments: Vec<OsString>,
        max_stdout: usize,
        deadline_unix_ms: i64,
    ) -> Result<Vec<u8>, SourceError> {
        self.run_git_with_deadline(arguments, max_stdout, Some(deadline_unix_ms), false, None)
            .await
    }

    async fn run_credential_git_until(
        &self,
        arguments: Vec<OsString>,
        max_stdout: usize,
        deadline_unix_ms: i64,
        transport_root: &Path,
    ) -> Result<Vec<u8>, SourceError> {
        self.run_git_with_deadline(
            arguments,
            max_stdout,
            Some(deadline_unix_ms),
            true,
            Some(transport_root),
        )
        .await
    }

    async fn run_git_with_deadline(
        &self,
        arguments: Vec<OsString>,
        max_stdout: usize,
        deadline_unix_ms: Option<i64>,
        credential_bearing: bool,
        transport_root: Option<&Path>,
    ) -> Result<Vec<u8>, SourceError> {
        self.verify_runtime_authority(credential_bearing).await?;
        self.git_exec_directory.verify(
            &self.git_executable.invocation_path,
            &self.git_remote_https_executable.invocation_path,
        )?;
        let (timeout, deadline_limited) = if let Some(deadline) = deadline_unix_ms {
            let remaining = deadline
                .checked_sub(now_unix_ms()?)
                .ok_or(SourceError::ExpiredRequest)?;
            if remaining <= 0 {
                return Err(SourceError::ExpiredRequest);
            }
            let remaining = u64::try_from(remaining).map_err(|_| SourceError::ExpiredRequest)?;
            (
                Duration::from_millis(self.config.command_timeout_ms.min(remaining)),
                remaining <= self.config.command_timeout_ms,
            )
        } else {
            (Duration::from_millis(self.config.command_timeout_ms), false)
        };
        let mut command = Command::new(&self.git_executable.invocation_path);
        command
            .env_clear()
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("PATH", &self.git_exec_directory.invocation_path)
            .env("HOME", "/nonexistent")
            .env("LD_BIND_NOW", "1")
            .env("LD_LIBRARY_PATH", &self.runtime_directory.invocation_path)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_EXEC_PATH", &self.git_exec_directory.invocation_path)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("NO_PROXY", "*")
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "credential.helper=",
                "-c",
                "http.followRedirects=false",
                "-c",
                "protocol.version=2",
                "-c",
                "gc.auto=0",
                "-c",
                "maintenance.auto=false",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "transfer.fsckObjects=true",
                "-c",
                "fetch.fsckObjects=true",
                "-c",
                "fetch.unpackLimit=1",
                "-c",
                "transfer.unpackLimit=1",
                "-c",
                "protocol.allow=never",
                "-c",
                "protocol.https.allow=always",
            ]);
        if credential_bearing {
            command
                .env("GIT_ASKPASS", &self.askpass_executable.invocation_path)
                .env("MCLOVING_SOURCE_ACQUIRER_ASKPASS", "1")
                .env(
                    "MCLOVING_SOURCE_ACQUIRER_CREDENTIAL_FILE",
                    &self.credential_path,
                )
                .env(
                    "MCLOVING_SOURCE_ACQUIRER_CREDENTIAL_USERNAME",
                    &self.config.credential_username,
                )
                .env(
                    "MCLOVING_SOURCE_ACQUIRER_CREDENTIAL_SHA256",
                    &self.config.credential_sha256,
                );
        }
        if self.config.test_allow_http_loopback {
            command.args(["-c", "protocol.http.allow=always"]);
        }
        if self.config.test_allow_file_repositories {
            command.args(["-c", "protocol.file.allow=always"]);
        }
        if let Some(ca_bundle) = &self.ca_bundle {
            command.env("GIT_SSL_CAINFO", &ca_bundle.invocation_path);
        }
        command
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        #[cfg(unix)]
        command.process_group(0);
        let mut child = command
            .spawn()
            .map_err(|_| SourceError::SourceUnavailable)?;
        #[cfg(unix)]
        let process_group_id = i32::try_from(child.id().ok_or(SourceError::SourceUnavailable)?)
            .map_err(|_| SourceError::SourceUnavailable)?;
        #[cfg(unix)]
        let process_group_id = Some(process_group_id);
        #[cfg(not(unix))]
        let process_group_id = None;
        let stdout = child.stdout.take().ok_or(SourceError::StateUnavailable)?;
        let stderr = child.stderr.take().ok_or(SourceError::StateUnavailable)?;
        let stdout_task = tokio::spawn(read_bounded(stdout, max_stdout));
        let stderr_task = tokio::spawn(read_bounded(stderr, MAX_GIT_STDERR_BYTES));
        enum MonitorEvent {
            Exited(std::io::Result<std::process::ExitStatus>),
            Quota(Result<(), SourceError>),
            Poll,
            TimedOut,
        }
        let started = tokio::time::Instant::now();
        let status = loop {
            let remaining = timeout
                .checked_sub(started.elapsed())
                .unwrap_or(Duration::ZERO);
            if remaining.is_zero() {
                terminate_child(&mut child, process_group_id).await?;
                stdout_task.abort();
                stderr_task.abort();
                let _ = stdout_task.await;
                let _ = stderr_task.await;
                return Err(if deadline_limited {
                    SourceError::ExpiredRequest
                } else {
                    SourceError::SourceUnavailable
                });
            }
            let event = if let Some(root) = transport_root {
                tokio::select! {
                    status = child.wait() => MonitorEvent::Exited(status),
                    quota = self.ensure_transport_quota(root) => {
                        MonitorEvent::Quota(quota.map(|_| ()))
                    }
                    _ = tokio::time::sleep(remaining) => MonitorEvent::TimedOut,
                }
            } else {
                tokio::select! {
                    status = child.wait() => MonitorEvent::Exited(status),
                    _ = tokio::time::sleep(remaining) => MonitorEvent::TimedOut,
                }
            };
            match event {
                MonitorEvent::Exited(status) => {
                    break status.map_err(|_| SourceError::SourceUnavailable)?;
                }
                MonitorEvent::Quota(Err(error)) => {
                    terminate_child(&mut child, process_group_id).await?;
                    stdout_task.abort();
                    stderr_task.abort();
                    let _ = stdout_task.await;
                    let _ = stderr_task.await;
                    return Err(error);
                }
                MonitorEvent::Quota(Ok(())) => {
                    let remaining = timeout
                        .checked_sub(started.elapsed())
                        .unwrap_or(Duration::ZERO);
                    let event = if remaining.is_zero() {
                        MonitorEvent::TimedOut
                    } else {
                        tokio::select! {
                            status = child.wait() => MonitorEvent::Exited(status),
                            _ = tokio::time::sleep(TRANSPORT_QUOTA_POLL_INTERVAL) => {
                                MonitorEvent::Poll
                            }
                            _ = tokio::time::sleep(remaining) => MonitorEvent::TimedOut,
                        }
                    };
                    match event {
                        MonitorEvent::Exited(status) => {
                            break status.map_err(|_| SourceError::SourceUnavailable)?;
                        }
                        MonitorEvent::Poll => continue,
                        MonitorEvent::TimedOut => {}
                        MonitorEvent::Quota(_) => unreachable!(),
                    }
                }
                MonitorEvent::TimedOut => {}
                MonitorEvent::Poll => unreachable!(),
            }
            terminate_child(&mut child, process_group_id).await?;
            stdout_task.abort();
            stderr_task.abort();
            let _ = stdout_task.await;
            let _ = stderr_task.await;
            return Err(if deadline_limited {
                SourceError::ExpiredRequest
            } else {
                SourceError::SourceUnavailable
            });
        };
        let stdout = stdout_task
            .await
            .map_err(|_| SourceError::StateUnavailable)?
            .map_err(|_| SourceError::LimitExceeded)?;
        let stderr = stderr_task
            .await
            .map_err(|_| SourceError::StateUnavailable)?
            .map_err(|_| SourceError::LimitExceeded)?;
        self.reject_secret_markers(&stdout)?;
        self.reject_secret_markers(&stderr)?;
        if credential_bearing
            && stderr
                .windows(FILTER_IGNORED_WARNING.len())
                .any(|window| window == FILTER_IGNORED_WARNING)
        {
            return Err(SourceError::SourceUnavailable);
        }
        if !status.success() {
            return Err(SourceError::SourceUnavailable);
        }
        Ok(stdout)
    }

    async fn verify_runtime_authority(&self, verify_askpass: bool) -> Result<(), SourceError> {
        let credential =
            read_private_bounded_regular_file(&self.credential_path, MAX_AUTHORITY_BYTES).await?;
        if sha256_hex(&credential) != self.config.credential_sha256
            || sha256_open_file(&self.git_executable.file).await?
                != self.config.git_executable_sha256
            || sha256_open_file(&self.git_remote_https_executable.file).await?
                != self.config.git_remote_https_executable_sha256
            || verify_askpass
                && sha256_open_file(&self.askpass_executable.file).await?
                    != self.implementation_sha256
        {
            return Err(SourceError::BindingMismatch);
        }
        if let (Some(ca_bundle), Some(expected)) = (&self.ca_bundle, &self.config.ca_bundle_sha256)
            && sha256_open_file(&ca_bundle.file).await? != *expected
        {
            return Err(SourceError::BindingMismatch);
        }
        verify_runtime_closure_files(&self.runtime_closure).await?;
        self.runtime_directory.verify()?;
        Ok(())
    }

    fn reject_secret_markers(&self, bytes: &[u8]) -> Result<(), SourceError> {
        if self.secret_marker_matcher.is_match(bytes) {
            Err(SourceError::Unauthorized)
        } else {
            Ok(())
        }
    }

    fn sign_receipt(&self, receipt: &AcquisitionReceipt) -> Result<String, SourceError> {
        let mut unsigned = receipt.clone();
        unsigned.signature.clear();
        let bytes = serde_json::to_vec(&unsigned).map_err(|_| SourceError::StateUnavailable)?;
        let mut mac = HmacSha256::new_from_slice(&self.signing_key)
            .map_err(|_| SourceError::InvalidConfig)?;
        mac.update(&bytes);
        Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
    }

    pub async fn verify_receipt(&self, receipt: &AcquisitionReceipt) -> Result<(), SourceError> {
        if receipt.protocol_version != PROTOCOL_VERSION
            || receipt.schema_version != self.config.schema_version
            || receipt.acquirer_id != self.config.acquirer_id
            || receipt.acquirer_implementation_sha256 != self.implementation_sha256
            || receipt.git_implementation_sha256 != self.config.git_executable_sha256
            || receipt.git_remote_https_implementation_sha256
                != self.config.git_remote_https_executable_sha256
            || receipt.runtime_closure_sha256 != self.config.runtime_closure_sha256
            || receipt.git_version != self.config.git_version
            || receipt.acquirer_config_sha256 != self.config_sha256
            || receipt.deployment_identity != self.config.deployment_identity
            || receipt.operator_identity != self.config.operator_identity
            || receipt.generation != self.config.generation
            || receipt.signing_key_id != self.config.receipt_signing_key_id
            || receipt.secret_marker_set_sha256 != self.config.secret_marker_set_sha256
            || receipt.output_relative_path != format!("{}/tree", receipt.acquisition_id)
            || receipt.transport_bytes > self.config.max_transport_bytes
        {
            return Err(SourceError::InvalidStoredReceipt);
        }
        self.verify_receipt_signature(receipt)?;
        let manifest_path = acquisition_path(&self.config.output_root, receipt.acquisition_id)
            .join("manifest.json");
        let manifest = read_bounded_regular_file(&manifest_path, MAX_GIT_METADATA_BYTES).await?;
        if sha256_hex(&manifest) != receipt.manifest_sha256
            || receipt.content_sha256 != receipt.manifest_sha256
        {
            return Err(SourceError::InvalidStoredReceipt);
        }
        let entries: Vec<ManifestEntry> =
            parse_json_no_duplicates(&manifest).map_err(|_| SourceError::InvalidStoredReceipt)?;
        let bytes = entries
            .iter()
            .try_fold(0_u64, |total, entry| total.checked_add(entry.bytes));
        if entries.len() != receipt.materialized_files || bytes != Some(receipt.materialized_bytes)
        {
            return Err(SourceError::InvalidStoredReceipt);
        }
        self.verify_materialized_tree(receipt, &entries).await?;
        Ok(())
    }

    fn verify_receipt_signature(&self, receipt: &AcquisitionReceipt) -> Result<(), SourceError> {
        let signature = URL_SAFE_NO_PAD
            .decode(receipt.signature.as_bytes())
            .map_err(|_| SourceError::InvalidStoredReceipt)?;
        let mut unsigned = receipt.clone();
        unsigned.signature.clear();
        let bytes = serde_json::to_vec(&unsigned).map_err(|_| SourceError::InvalidStoredReceipt)?;
        let mut mac = HmacSha256::new_from_slice(&self.signing_key)
            .map_err(|_| SourceError::InvalidConfig)?;
        mac.update(&bytes);
        mac.verify_slice(&signature)
            .map_err(|_| SourceError::InvalidStoredReceipt)
    }

    async fn verify_materialized_tree(
        &self,
        receipt: &AcquisitionReceipt,
        entries: &[ManifestEntry],
    ) -> Result<(), SourceError> {
        if entries.windows(2).any(|pair| pair[0].path >= pair[1].path) {
            return Err(SourceError::InvalidStoredReceipt);
        }
        let acquisition_root = acquisition_path(&self.config.output_root, receipt.acquisition_id);
        let tree_root = acquisition_root.join("tree");
        validate_retained_directory(&acquisition_root, 0o500).await?;
        validate_retained_directory(&tree_root, 0o500).await?;
        validate_retained_file(&acquisition_root.join("manifest.json"), 0o400).await?;
        validate_retained_file(&acquisition_root.join("receipt.json"), 0o400).await?;

        let submodules = receipt
            .repository_trees
            .iter()
            .skip(1)
            .map(|repository| (repository.path.as_str(), repository))
            .collect::<BTreeMap<_, _>>();
        if receipt.repository_trees.is_empty()
            || !receipt.repository_trees[0].path.is_empty()
            || submodules.len() + 1 != receipt.repository_trees.len()
        {
            return Err(SourceError::InvalidStoredReceipt);
        }
        let mut expected_leaf_paths = BTreeSet::new();
        let mut expected_directories = BTreeSet::new();
        let mut total_bytes = 0_u64;
        for entry in entries {
            validate_relative_path(&entry.path, self.config.max_path_bytes)
                .map_err(|_| SourceError::InvalidStoredReceipt)?;
            if !is_object_id(&entry.git_object_id)
                || !is_sha256_hex(&entry.sha256)
                || !expected_leaf_paths.insert(entry.path.clone())
            {
                return Err(SourceError::InvalidStoredReceipt);
            }
            add_parent_directories(&entry.path, &mut expected_directories)?;
            let path = tree_root.join(&entry.path);
            let metadata = tokio::fs::symlink_metadata(&path)
                .await
                .map_err(|_| SourceError::InvalidStoredReceipt)?;
            match entry.git_mode.as_str() {
                "100644" | "100755" => {
                    let expected_mode = if entry.git_mode == "100755" {
                        0o500
                    } else {
                        0o400
                    };
                    validate_retained_metadata(&metadata, false, expected_mode)?;
                    let bytes = read_bounded_regular_file(
                        &path,
                        usize::try_from(self.config.max_file_bytes).unwrap_or(usize::MAX),
                    )
                    .await
                    .map_err(|_| SourceError::InvalidStoredReceipt)?;
                    if u64::try_from(bytes.len()).ok() != Some(entry.bytes)
                        || sha256_hex(&bytes) != entry.sha256
                    {
                        return Err(SourceError::InvalidStoredReceipt);
                    }
                    total_bytes = total_bytes
                        .checked_add(entry.bytes)
                        .ok_or(SourceError::InvalidStoredReceipt)?;
                }
                "120000" => {
                    if !metadata.file_type().is_symlink() {
                        return Err(SourceError::InvalidStoredReceipt);
                    }
                    let target = read_link_bytes(&path).await?;
                    validate_symlink_target(Path::new(&entry.path), &target)
                        .map_err(|_| SourceError::InvalidStoredReceipt)?;
                    if u64::try_from(target.len()).ok() != Some(entry.bytes)
                        || sha256_hex(&target) != entry.sha256
                    {
                        return Err(SourceError::InvalidStoredReceipt);
                    }
                    total_bytes = total_bytes
                        .checked_add(entry.bytes)
                        .ok_or(SourceError::InvalidStoredReceipt)?;
                }
                "160000" => {
                    validate_retained_metadata(&metadata, true, 0o500)?;
                    let repository = submodules
                        .get(entry.path.as_str())
                        .ok_or(SourceError::InvalidStoredReceipt)?;
                    if repository.resolved_commit != entry.git_object_id
                        || entry.bytes != 0
                        || entry.sha256 != sha256_hex(entry.git_object_id.as_bytes())
                    {
                        return Err(SourceError::InvalidStoredReceipt);
                    }
                    expected_directories.insert(entry.path.clone());
                }
                _ => return Err(SourceError::InvalidStoredReceipt),
            }
        }
        if total_bytes != receipt.materialized_bytes {
            return Err(SourceError::InvalidStoredReceipt);
        }
        let (actual_leaves, actual_directories) = inventory_materialized_tree(&tree_root).await?;
        let expected_non_directory_leaves = entries
            .iter()
            .filter(|entry| entry.git_mode != "160000")
            .map(|entry| entry.path.clone())
            .collect::<BTreeSet<_>>();
        if actual_leaves != expected_non_directory_leaves
            || actual_directories != expected_directories
        {
            return Err(SourceError::InvalidStoredReceipt);
        }
        Ok(())
    }

    async fn load_receipt(
        &self,
        acquisition_id: Uuid,
    ) -> Result<Option<AcquisitionReceipt>, SourceError> {
        let path = acquisition_path(&self.config.output_root, acquisition_id).join("receipt.json");
        match tokio::fs::symlink_metadata(&path).await {
            Ok(metadata) if metadata.file_type().is_file() => {
                let bytes = read_bounded_regular_file(&path, MAX_GIT_METADATA_BYTES).await?;
                let receipt = parse_json_no_duplicates(&bytes)
                    .map_err(|_| SourceError::InvalidStoredReceipt)?;
                Ok(Some(receipt))
            }
            Ok(_) => Err(SourceError::InvalidStoredReceipt),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(SourceError::StateUnavailable),
        }
    }

    async fn store_claim(
        &self,
        acquisition_id: Uuid,
        claim: &AcquisitionClaim,
    ) -> Result<(), SourceError> {
        let bytes = serde_json::to_vec(claim).map_err(|_| SourceError::StateUnavailable)?;
        write_new_file(
            &claim_path(&self.config.output_root, acquisition_id),
            &bytes,
            0o600,
        )
        .await?;
        sync_directory(&self.config.output_root).await
    }
}

fn validate_config(
    config: &SourceConfig,
    implementation_sha256: &str,
    credential: &[u8],
    signing_key: &[u8],
    markers: &[Vec<u8>],
) -> Result<(), SourceError> {
    let runtime_closure_digest_matches = runtime_closure_digest(&config.runtime_closure)
        .is_ok_and(|digest| digest == config.runtime_closure_sha256);
    if config.protocol_version != PROTOCOL_VERSION
        || [
            &config.schema_version,
            &config.acquirer_id,
            &config.deployment_identity,
            &config.operator_identity,
            &config.git_version,
            &config.grant_id,
            &config.grant_version,
            &config.grant_scope,
            &config.credential_username,
            &config.receipt_signing_key_id,
        ]
        .iter()
        .any(|value| !valid_binding_text(value))
        || config.generation == 0
        || !config.output_root.is_absolute()
        || !config.git_executable_path.is_absolute()
        || !config.git_remote_https_executable_path.is_absolute()
        || !is_sha256_hex(implementation_sha256)
        || !is_sha256_hex(&config.git_executable_sha256)
        || !is_sha256_hex(&config.git_remote_https_executable_sha256)
        || !is_sha256_hex(&config.runtime_closure_sha256)
        || !is_sha256_hex(&config.credential_sha256)
        || !is_sha256_hex(&config.receipt_signing_key_sha256)
        || !is_sha256_hex(&config.secret_marker_set_sha256)
        || credential.len() < 16
        || std::str::from_utf8(credential).is_err()
        || credential.contains(&b'\r')
        || credential.contains(&b'\n')
        || signing_key.len() < 32
        || sha256_hex(credential) != config.credential_sha256
        || sha256_hex(signing_key) != config.receipt_signing_key_sha256
        || marker_set_digest(markers) != config.secret_marker_set_sha256
        || markers.is_empty()
        || markers.len() > MAX_MARKERS
        || markers.iter().any(Vec::is_empty)
        || !markers.iter().any(|marker| marker.as_slice() == credential)
        || config.max_files == 0
        || config.max_files > MAX_CONFIGURED_FILES
        || config.max_total_bytes == 0
        || config.max_total_bytes > MAX_CONFIGURED_BYTES
        || config.max_file_bytes == 0
        || config.max_file_bytes > config.max_total_bytes
        || config.max_file_bytes > MAX_CONFIGURED_FILE_BYTES
        || config.max_transport_bytes == 0
        || config.max_transport_bytes > MAX_CONFIGURED_BYTES
        || config.max_path_bytes == 0
        || config.max_path_bytes > MAX_CONFIGURED_PATH_BYTES
        || config.max_submodules > MAX_CONFIGURED_SUBMODULES
        || config.max_depth > MAX_CONFIGURED_DEPTH
        || config.command_timeout_ms == 0
        || config.command_timeout_ms > MAX_CONFIGURED_TIMEOUT_MS
        || config.allowed_ref_prefixes.is_empty()
        || config.runtime_closure.is_empty()
        || config.runtime_closure.iter().any(|binding| {
            !binding.path.is_absolute()
                || !is_sha256_hex(&binding.sha256)
                || std::fs::canonicalize(&binding.path).ok().as_ref() != Some(&binding.path)
        })
        || config
            .runtime_closure
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || config
            .runtime_closure
            .iter()
            .filter_map(|binding| binding.path.file_name())
            .collect::<BTreeSet<_>>()
            .len()
            != config.runtime_closure.len()
        || !runtime_closure_digest_matches
    {
        return Err(SourceError::InvalidConfig);
    }
    let marker_bytes = markers
        .iter()
        .try_fold(0_usize, |total, marker| total.checked_add(marker.len()));
    if marker_bytes.is_none_or(|bytes| bytes > MAX_MARKER_BYTES) {
        return Err(SourceError::InvalidConfig);
    }
    let mut unique_markers = markers.to_vec();
    unique_markers.sort();
    unique_markers.dedup();
    if unique_markers.len() != markers.len() {
        return Err(SourceError::InvalidConfig);
    }
    validate_repository_binding(
        &config.primary_repository,
        config.test_allow_file_repositories,
        config.test_allow_http_loopback,
    )?;
    validate_repository_bindings(
        &config.allowed_fork_repositories,
        config.test_allow_file_repositories,
        config.test_allow_http_loopback,
    )?;
    validate_repository_bindings(
        &config.allowed_submodule_repositories,
        config.test_allow_file_repositories,
        config.test_allow_http_loopback,
    )?;
    let mut refs = config.allowed_ref_prefixes.clone();
    refs.sort();
    refs.dedup();
    if refs.len() != config.allowed_ref_prefixes.len()
        || refs.iter().any(|prefix| {
            !prefix.starts_with("refs/") || !valid_ref(&format!("{prefix}placeholder"))
        })
    {
        return Err(SourceError::InvalidConfig);
    }
    validate_sparse_roots(
        &config.allowed_sparse_roots,
        &config.allowed_sparse_roots,
        config.max_path_bytes,
    )
    .map_err(|_| SourceError::InvalidConfig)?;
    if config.ca_bundle_path.is_some() != config.ca_bundle_sha256.is_some()
        || config
            .ca_bundle_path
            .as_ref()
            .is_some_and(|path| !path.is_absolute())
        || config
            .ca_bundle_sha256
            .as_ref()
            .is_some_and(|digest| !is_sha256_hex(digest))
        || !config.test_allow_file_repositories
            && !config.test_allow_http_loopback
            && config.ca_bundle_path.is_none()
    {
        return Err(SourceError::InvalidConfig);
    }
    Ok(())
}

fn validate_repository_bindings(
    repositories: &[RepositoryBinding],
    allow_file: bool,
    allow_http_loopback: bool,
) -> Result<(), SourceError> {
    let mut identities = BTreeSet::new();
    for repository in repositories {
        validate_repository_binding(repository, allow_file, allow_http_loopback)?;
        if !identities.insert((
            repository.provider_identity.clone(),
            repository.repository_identity.clone(),
        )) {
            return Err(SourceError::InvalidConfig);
        }
    }
    Ok(())
}

fn validate_repository_binding(
    repository: &RepositoryBinding,
    allow_file: bool,
    allow_http_loopback: bool,
) -> Result<(), SourceError> {
    if !valid_binding_text(&repository.provider_identity)
        || !valid_binding_text(&repository.repository_identity)
    {
        return Err(SourceError::InvalidConfig);
    }
    validate_repository_url(&repository.repository_url, allow_file, allow_http_loopback)
}

fn validate_repository_url(
    repository_url: &str,
    allow_file: bool,
    allow_http_loopback: bool,
) -> Result<(), SourceError> {
    let url = Url::parse(repository_url).map_err(|_| SourceError::InvalidConfig)?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || repository_url.len() > MAX_BINDING_TEXT_BYTES
    {
        return Err(SourceError::InvalidConfig);
    }
    match url.scheme() {
        "https" if url.host_str().is_some() => Ok(()),
        "http"
            if allow_http_loopback
                && matches!(url.host_str(), Some("127.0.0.1" | "::1" | "localhost")) =>
        {
            Ok(())
        }
        "file" if allow_file && url.host_str().is_none_or(str::is_empty) => {
            let path = url.to_file_path().map_err(|_| SourceError::InvalidConfig)?;
            if path.is_absolute() {
                Ok(())
            } else {
                Err(SourceError::InvalidConfig)
            }
        }
        _ => Err(SourceError::InvalidConfig),
    }
}

fn validate_sparse_roots(
    roots: &[String],
    allowed: &[String],
    max_path_bytes: usize,
) -> Result<(), SourceError> {
    let mut seen = BTreeSet::new();
    for root in roots {
        validate_relative_path(root, max_path_bytes)?;
        if !seen.insert(root.clone())
            || !allowed.is_empty()
                && !allowed.iter().any(|admitted| {
                    root == admitted
                        || root
                            .strip_prefix(admitted)
                            .is_some_and(|suffix| suffix.starts_with('/'))
                })
        {
            return Err(SourceError::BindingMismatch);
        }
    }
    Ok(())
}

fn valid_ref(reference: &str) -> bool {
    reference.starts_with("refs/")
        && reference.len() <= MAX_BINDING_TEXT_BYTES
        && !reference.ends_with('/')
        && !reference.ends_with('.')
        && !reference.ends_with(".lock")
        && !reference.contains("..")
        && !reference.contains("@{")
        && !reference.contains("//")
        && !reference
            .bytes()
            .any(|byte| byte <= b' ' || byte == 0x7f || b"~^:?*[\\".contains(&byte))
}

fn valid_binding_text(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAX_BINDING_TEXT_BYTES
        && !value.chars().any(char::is_control)
}

fn is_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn prefixed_path(prefix: &str, path: &str) -> Result<String, SourceError> {
    if prefix.is_empty() {
        Ok(path.to_owned())
    } else {
        Ok(format!("{prefix}/{path}"))
    }
}

fn compatibility_case_key(path: &str) -> String {
    path.chars()
        .nfd()
        .default_case_fold()
        .nfkd()
        .default_case_fold()
        .nfkd()
        .collect()
}

fn validate_relative_path(path: &str, max_path_bytes: usize) -> Result<(), SourceError> {
    if path.is_empty() || path.len() > max_path_bytes || path.contains('\\') {
        return Err(SourceError::UnsafeTree);
    }
    let parsed = Path::new(path);
    if parsed.is_absolute()
        || parsed.components().any(|component| {
            !matches!(component, Component::Normal(_))
                || component
                    .as_os_str()
                    .to_str()
                    .is_none_or(|value| value.eq_ignore_ascii_case(".git"))
        })
    {
        return Err(SourceError::UnsafeTree);
    }
    Ok(())
}

fn parse_ls_tree(
    bytes: &[u8],
    max_path_bytes: usize,
    max_files: usize,
) -> Result<Vec<GitTreeEntry>, SourceError> {
    let mut entries = Vec::new();
    for record in bytes
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        let tab = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or(SourceError::SourceUnavailable)?;
        let header = std::str::from_utf8(&record[..tab]).map_err(|_| SourceError::UnsafeTree)?;
        let path = std::str::from_utf8(&record[tab + 1..])
            .map_err(|_| SourceError::UnsafeTree)?
            .to_owned();
        validate_relative_path(&path, max_path_bytes)?;
        let mut fields = header.split(' ');
        let mode = fields.next().ok_or(SourceError::SourceUnavailable)?;
        let kind = fields.next().ok_or(SourceError::SourceUnavailable)?;
        let object_id = fields.next().ok_or(SourceError::SourceUnavailable)?;
        if fields.next().is_some() {
            return Err(SourceError::SourceUnavailable);
        }
        entries.push(GitTreeEntry {
            mode: mode.to_owned(),
            kind: kind.to_owned(),
            object_id: object_id.to_owned(),
            path,
        });
        if entries.len() > max_files.saturating_add(MAX_CONFIGURED_SUBMODULES) {
            return Err(SourceError::LimitExceeded);
        }
    }
    Ok(entries)
}

fn parse_gitmodules(
    bytes: &[u8],
    max_path_bytes: usize,
) -> Result<BTreeMap<String, String>, SourceError> {
    let text = std::str::from_utf8(bytes).map_err(|_| SourceError::SubmoduleMismatch)?;
    let mut current = None::<String>;
    let mut sections = BTreeMap::<String, BTreeMap<String, String>>::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line
            .strip_prefix("[submodule \"")
            .and_then(|value| value.strip_suffix("\"]"))
        {
            if name.is_empty() || name.contains(['\\', '"']) {
                return Err(SourceError::SubmoduleMismatch);
            }
            if sections.contains_key(name) {
                return Err(SourceError::SubmoduleMismatch);
            }
            sections.insert(name.to_owned(), BTreeMap::new());
            current = Some(name.to_owned());
            continue;
        }
        let section = current.as_ref().ok_or(SourceError::SubmoduleMismatch)?;
        let (key, value) = line.split_once('=').ok_or(SourceError::SubmoduleMismatch)?;
        let key = key.trim();
        let value = value.trim();
        if !matches!(key, "path" | "url") || value.is_empty() {
            return Err(SourceError::SubmoduleMismatch);
        }
        if sections
            .get_mut(section)
            .ok_or(SourceError::SubmoduleMismatch)?
            .insert(key.to_owned(), value.to_owned())
            .is_some()
        {
            return Err(SourceError::SubmoduleMismatch);
        }
    }
    let mut paths = BTreeMap::new();
    for values in sections.into_values() {
        if values.len() != 2 {
            return Err(SourceError::SubmoduleMismatch);
        }
        let path = values.get("path").ok_or(SourceError::SubmoduleMismatch)?;
        let url = values.get("url").ok_or(SourceError::SubmoduleMismatch)?;
        validate_relative_path(path, max_path_bytes)?;
        if paths.insert(path.clone(), url.clone()).is_some() {
            return Err(SourceError::SubmoduleMismatch);
        }
    }
    Ok(paths)
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, SourceError> {
    let bytes = serde_json::to_vec(value).map_err(|_| SourceError::InvalidConfig)?;
    Ok(sha256_hex(&bytes))
}

pub fn parse_json_no_duplicates<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, SourceError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    DuplicateRejectingSeed
        .deserialize(&mut deserializer)
        .map_err(|_| SourceError::InvalidConfig)?;
    deserializer.end().map_err(|_| SourceError::InvalidConfig)?;
    serde_json::from_slice(bytes).map_err(|_| SourceError::InvalidConfig)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

pub fn content_sha256(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}

pub fn marker_set_digest(markers: &[Vec<u8>]) -> String {
    let mut sorted = markers.to_vec();
    sorted.sort();
    let mut hasher = Sha256::new();
    for marker in sorted {
        hasher.update(
            u64::try_from(marker.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        hasher.update(marker);
    }
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

fn now_unix_ms() -> Result<i64, SourceError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SourceError::StateUnavailable)?;
    i64::try_from(duration.as_millis()).map_err(|_| SourceError::StateUnavailable)
}

async fn terminate_child(
    child: &mut tokio::process::Child,
    process_group_id: Option<i32>,
) -> Result<(), SourceError> {
    #[cfg(unix)]
    match nix::sys::signal::killpg(
        nix::unistd::Pid::from_raw(process_group_id.ok_or(SourceError::StateUnavailable)?),
        nix::sys::signal::Signal::SIGKILL,
    ) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
        Err(_) => return Err(SourceError::StateUnavailable),
    }
    #[cfg(not(unix))]
    {
        let _ = process_group_id;
        child
            .start_kill()
            .map_err(|_| SourceError::StateUnavailable)?;
    }
    tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .map_err(|_| SourceError::StateUnavailable)?
        .map_err(|_| SourceError::StateUnavailable)?;
    Ok(())
}

async fn read_bounded<R>(reader: R, max_bytes: usize) -> Result<Vec<u8>, std::io::Error>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let limit = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::with_capacity(max_bytes.min(64 * 1_024));
    reader.take(limit).read_to_end(&mut bytes).await?;
    if bytes.len() > max_bytes {
        Err(std::io::Error::other("bounded Git output exceeded"))
    } else {
        Ok(bytes)
    }
}

pub async fn read_bounded_regular_file(
    path: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>, SourceError> {
    let metadata = tokio::fs::symlink_metadata(path)
        .await
        .map_err(|_| SourceError::StateUnavailable)?;
    if !metadata.file_type().is_file()
        || metadata.len() > u64::try_from(max_bytes).unwrap_or(u64::MAX)
    {
        return Err(SourceError::StateUnavailable);
    }
    let mut options = tokio::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        options.custom_flags(nix::libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .await
        .map_err(|_| SourceError::StateUnavailable)?;
    let opened = file
        .metadata()
        .await
        .map_err(|_| SourceError::StateUnavailable)?;
    if !opened.file_type().is_file() || opened.len() > u64::try_from(max_bytes).unwrap_or(u64::MAX)
    {
        return Err(SourceError::StateUnavailable);
    }
    read_bounded(file, max_bytes)
        .await
        .map_err(|_| SourceError::StateUnavailable)
}

pub async fn read_private_bounded_regular_file(
    path: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>, SourceError> {
    #[cfg(not(unix))]
    {
        let _ = (path, max_bytes);
        Err(SourceError::StateUnavailable)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let metadata = tokio::fs::symlink_metadata(path)
            .await
            .map_err(|_| SourceError::StateUnavailable)?;
        let valid = |metadata: &std::fs::Metadata| {
            metadata.file_type().is_file()
                && metadata.len() <= u64::try_from(max_bytes).unwrap_or(u64::MAX)
                && metadata.permissions().mode() & 0o077 == 0
                && metadata.uid() == nix::unistd::Uid::effective().as_raw()
        };
        if !valid(&metadata) {
            return Err(SourceError::StateUnavailable);
        }
        let mut options = tokio::fs::OpenOptions::new();
        options.read(true).custom_flags(nix::libc::O_NOFOLLOW);
        let file = options
            .open(path)
            .await
            .map_err(|_| SourceError::StateUnavailable)?;
        if !valid(
            &file
                .metadata()
                .await
                .map_err(|_| SourceError::StateUnavailable)?,
        ) {
            return Err(SourceError::StateUnavailable);
        }
        read_bounded(file, max_bytes)
            .await
            .map_err(|_| SourceError::StateUnavailable)
    }
}

pub async fn sha256_file(path: &Path) -> Result<String, SourceError> {
    let metadata = tokio::fs::symlink_metadata(path)
        .await
        .map_err(|_| SourceError::InvalidConfig)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_EXECUTABLE_BYTES {
        return Err(SourceError::InvalidConfig);
    }
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|_| SourceError::InvalidConfig)?;
    let bytes = read_bounded(
        file,
        usize::try_from(MAX_EXECUTABLE_BYTES).unwrap_or(usize::MAX),
    )
    .await
    .map_err(|_| SourceError::InvalidConfig)?;
    Ok(sha256_hex(&bytes))
}

pub fn runtime_closure_digest(bindings: &[RuntimeBinding]) -> Result<String, SourceError> {
    canonical_digest(&bindings)
}

pub async fn inspect_runtime_closure(
    executables: &[PathBuf],
) -> Result<Vec<RuntimeBinding>, SourceError> {
    let paths = trace_runtime_closure(executables, None).await?;
    let mut bindings = Vec::with_capacity(paths.len());
    for path in paths {
        bindings.push(RuntimeBinding {
            sha256: sha256_file(&path).await?,
            path,
        });
    }
    bindings.sort();
    Ok(bindings)
}

async fn open_runtime_closure(
    bindings: &[RuntimeBinding],
) -> Result<Vec<VerifiedRuntimeFile>, SourceError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = bindings;
        Err(SourceError::InvalidConfig)
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

        let mut verified = Vec::with_capacity(bindings.len());
        for binding in bindings {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
                .open(&binding.path)
                .map_err(|_| SourceError::InvalidConfig)?;
            let metadata = file.metadata().map_err(|_| SourceError::InvalidConfig)?;
            if !metadata.file_type().is_file()
                || metadata.len() > MAX_EXECUTABLE_BYTES
                || metadata.uid() != 0
                || metadata.permissions().mode() & 0o022 != 0
                || sha256_open_file(&file).await? != binding.sha256
            {
                return Err(SourceError::InvalidConfig);
            }
            verified.push(VerifiedRuntimeFile {
                binding: binding.clone(),
                device: metadata.dev(),
                inode: metadata.ino(),
                file,
            });
        }
        Ok(verified)
    }
}

async fn verify_runtime_closure_files(runtime: &[VerifiedRuntimeFile]) -> Result<(), SourceError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = runtime;
        Err(SourceError::BindingMismatch)
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        for entry in runtime {
            let metadata =
                std::fs::metadata(&entry.binding.path).map_err(|_| SourceError::BindingMismatch)?;
            if !metadata.file_type().is_file()
                || metadata.dev() != entry.device
                || metadata.ino() != entry.inode
                || metadata.uid() != 0
                || metadata.permissions().mode() & 0o022 != 0
                || sha256_open_file(&entry.file).await? != entry.binding.sha256
            {
                return Err(SourceError::BindingMismatch);
            }
        }
        Ok(())
    }
}

async fn trace_runtime_closure(
    executables: &[PathBuf],
    runtime_directory: Option<&Path>,
) -> Result<BTreeSet<PathBuf>, SourceError> {
    let mut closure = BTreeSet::new();
    for executable in executables {
        let mut command = Command::new(executable);
        command
            .env_clear()
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("LD_BIND_NOW", "1")
            .env("LD_TRACE_LOADED_OBJECTS", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if let Some(runtime_directory) = runtime_directory {
            command.env("LD_LIBRARY_PATH", runtime_directory);
        }
        let mut child = command.spawn().map_err(|_| SourceError::InvalidConfig)?;
        let stdout = child.stdout.take().ok_or(SourceError::InvalidConfig)?;
        let stderr = child.stderr.take().ok_or(SourceError::InvalidConfig)?;
        let stdout_task = tokio::spawn(read_bounded(stdout, MAX_BINDING_TEXT_BYTES * 16));
        let stderr_task = tokio::spawn(read_bounded(stderr, MAX_BINDING_TEXT_BYTES));
        let status = match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
            Ok(status) => status.map_err(|_| SourceError::InvalidConfig)?,
            Err(_) => {
                child.start_kill().map_err(|_| SourceError::InvalidConfig)?;
                let _ = child.wait().await;
                stdout_task.abort();
                stderr_task.abort();
                let _ = stdout_task.await;
                let _ = stderr_task.await;
                return Err(SourceError::InvalidConfig);
            }
        };
        let stdout = stdout_task
            .await
            .map_err(|_| SourceError::InvalidConfig)?
            .map_err(|_| SourceError::InvalidConfig)?;
        let stderr = stderr_task
            .await
            .map_err(|_| SourceError::InvalidConfig)?
            .map_err(|_| SourceError::InvalidConfig)?;
        if !status.success() || !stderr.is_empty() {
            return Err(SourceError::InvalidConfig);
        }
        let output = std::str::from_utf8(&stdout).map_err(|_| SourceError::InvalidConfig)?;
        for line in output
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            let candidate = if let Some((_, resolved)) = line.split_once("=>") {
                let path = resolved
                    .split_ascii_whitespace()
                    .next()
                    .ok_or(SourceError::InvalidConfig)?;
                if path == "not" {
                    return Err(SourceError::InvalidConfig);
                }
                Some(path)
            } else {
                line.split_ascii_whitespace()
                    .next()
                    .filter(|path| path.starts_with('/'))
            };
            if let Some(candidate) = candidate {
                let canonical =
                    std::fs::canonicalize(candidate).map_err(|_| SourceError::InvalidConfig)?;
                if !canonical.is_absolute() {
                    return Err(SourceError::InvalidConfig);
                }
                closure.insert(canonical);
            } else if !line.starts_with("linux-vdso") && line != "statically linked" {
                return Err(SourceError::InvalidConfig);
            }
        }
    }
    Ok(closure)
}

async fn snapshot_verified_file(
    path: &Path,
    expected_sha256: &str,
    snapshot_name: &str,
    mode: u32,
) -> Result<VerifiedFile, SourceError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, expected_sha256, snapshot_name, mode);
        Err(SourceError::InvalidConfig)
    }
    #[cfg(target_os = "linux")]
    {
        use nix::fcntl::{FcntlArg, SealFlag, fcntl};
        use nix::sys::memfd::{MFdFlags, memfd_create};
        use nix::sys::stat::{Mode, fchmod};
        use std::io::Write as _;
        use std::os::fd::AsRawFd as _;
        use std::os::fd::OwnedFd;
        use std::os::unix::fs::OpenOptionsExt as _;

        let source = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| SourceError::InvalidConfig)?;
        let metadata = source.metadata().map_err(|_| SourceError::InvalidConfig)?;
        if !metadata.file_type().is_file() || metadata.len() > MAX_EXECUTABLE_BYTES {
            return Err(SourceError::InvalidConfig);
        }
        let bytes = read_bounded(
            tokio::fs::File::from_std(source.try_clone().map_err(|_| SourceError::InvalidConfig)?),
            usize::try_from(MAX_EXECUTABLE_BYTES).unwrap_or(usize::MAX),
        )
        .await
        .map_err(|_| SourceError::InvalidConfig)?;
        if sha256_hex(&bytes) != expected_sha256 {
            return Err(SourceError::InvalidConfig);
        }
        let descriptor: OwnedFd = memfd_create(
            snapshot_name,
            MFdFlags::MFD_CLOEXEC | MFdFlags::MFD_ALLOW_SEALING,
        )
        .map_err(|_| SourceError::InvalidConfig)?;
        let mut file = std::fs::File::from(descriptor);
        file.write_all(&bytes)
            .map_err(|_| SourceError::InvalidConfig)?;
        file.sync_all().map_err(|_| SourceError::InvalidConfig)?;
        fchmod(&file, Mode::from_bits_truncate(mode)).map_err(|_| SourceError::InvalidConfig)?;
        let required_seals = SealFlag::F_SEAL_SEAL
            | SealFlag::F_SEAL_SHRINK
            | SealFlag::F_SEAL_GROW
            | SealFlag::F_SEAL_WRITE;
        fcntl(&file, FcntlArg::F_ADD_SEALS(required_seals))
            .map_err(|_| SourceError::InvalidConfig)?;
        let observed_seals =
            fcntl(&file, FcntlArg::F_GET_SEALS).map_err(|_| SourceError::InvalidConfig)?;
        if observed_seals & required_seals.bits() != required_seals.bits()
            || sha256_open_file(&file).await? != expected_sha256
        {
            return Err(SourceError::InvalidConfig);
        }
        let descriptor = file.as_raw_fd();
        let invocation_path =
            PathBuf::from(format!("/proc/{}/fd/{descriptor}", std::process::id()));
        Ok(VerifiedFile {
            file,
            invocation_path,
        })
    }
}

fn create_runtime_directory(
    output_root: &Path,
    bindings: &[RuntimeBinding],
) -> Result<RuntimeDirectory, SourceError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (output_root, bindings);
        Err(SourceError::InvalidConfig)
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _, symlink};

        let path = output_root.join(format!(".runtime-{}", Uuid::new_v4()));
        std::fs::create_dir(&path).map_err(|_| SourceError::StateUnavailable)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| SourceError::StateUnavailable)?;
        let mut links = Vec::with_capacity(bindings.len());
        for binding in bindings {
            let name = binding
                .path
                .file_name()
                .ok_or(SourceError::InvalidConfig)?
                .to_os_string();
            if links.iter().any(|(existing, _)| existing == &name) {
                return Err(SourceError::InvalidConfig);
            }
            symlink(&binding.path, path.join(&name)).map_err(|_| SourceError::StateUnavailable)?;
            links.push((name, binding.path.clone()));
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500))
            .map_err(|_| SourceError::StateUnavailable)?;
        let directory = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|_| SourceError::StateUnavailable)?;
        let invocation_path = PathBuf::from(format!(
            "/proc/{}/fd/{}",
            std::process::id(),
            directory.as_raw_fd()
        ));
        Ok(RuntimeDirectory {
            path,
            _directory: directory,
            invocation_path,
            links,
        })
    }
}

fn create_git_exec_directory(
    output_root: &Path,
    git: &Path,
    remote_helper: &Path,
) -> Result<GitExecDirectory, SourceError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (output_root, git, remote_helper);
        Err(SourceError::InvalidConfig)
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _, symlink};

        let path = output_root.join(format!(".git-exec-{}", Uuid::new_v4()));
        std::fs::create_dir(&path).map_err(|_| SourceError::StateUnavailable)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| SourceError::StateUnavailable)?;
        for (name, target) in [
            ("git", git),
            ("git-upload-pack", git),
            ("git-remote-http", remote_helper),
            ("git-remote-https", remote_helper),
        ] {
            symlink(target, path.join(name)).map_err(|_| SourceError::StateUnavailable)?;
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500))
            .map_err(|_| SourceError::StateUnavailable)?;
        let directory = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|_| SourceError::StateUnavailable)?;
        let invocation_path = PathBuf::from(format!(
            "/proc/{}/fd/{}",
            std::process::id(),
            directory.as_raw_fd()
        ));
        Ok(GitExecDirectory {
            path,
            _directory: directory,
            invocation_path,
        })
    }
}

async fn sha256_open_file(file: &std::fs::File) -> Result<String, SourceError> {
    let cloned = file.try_clone().map_err(|_| SourceError::InvalidConfig)?;
    let mut file = tokio::fs::File::from_std(cloned);
    file.seek(SeekFrom::Start(0))
        .await
        .map_err(|_| SourceError::InvalidConfig)?;
    let metadata = file
        .metadata()
        .await
        .map_err(|_| SourceError::InvalidConfig)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_EXECUTABLE_BYTES {
        return Err(SourceError::InvalidConfig);
    }
    let bytes = read_bounded(
        file,
        usize::try_from(MAX_EXECUTABLE_BYTES).unwrap_or(usize::MAX),
    )
    .await
    .map_err(|_| SourceError::InvalidConfig)?;
    Ok(sha256_hex(&bytes))
}

#[cfg(unix)]
type OutputRootLock = nix::fcntl::Flock<std::fs::File>;

#[cfg(not(unix))]
struct OutputRootLock;

async fn lock_output_root(root: &Path) -> Result<OutputRootLock, SourceError> {
    #[cfg(unix)]
    {
        use nix::fcntl::{Flock, FlockArg};
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

        let path = root.join(".coordination-v1.lock");
        tokio::task::spawn_blocking(move || {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .mode(0o600)
                .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
                .open(path)
                .map_err(|_| SourceError::StateUnavailable)?;
            let metadata = file.metadata().map_err(|_| SourceError::StateUnavailable)?;
            if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
                return Err(SourceError::StateUnavailable);
            }
            Flock::lock(file, FlockArg::LockExclusive).map_err(|_| SourceError::StateUnavailable)
        })
        .await
        .map_err(|_| SourceError::StateUnavailable)?
    }
    #[cfg(not(unix))]
    {
        let _ = root;
        Err(SourceError::InvalidConfig)
    }
}

async fn ensure_private_output_root(root: &Path) -> Result<(), SourceError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let parent = root.parent().ok_or(SourceError::InvalidConfig)?;
        if tokio::fs::canonicalize(parent)
            .await
            .map_err(|_| SourceError::InvalidConfig)?
            != parent
        {
            return Err(SourceError::InvalidConfig);
        }
        if tokio::fs::symlink_metadata(root).await.is_err() {
            create_private_directory(root).await?;
        }
        let metadata = tokio::fs::symlink_metadata(root)
            .await
            .map_err(|_| SourceError::StateUnavailable)?;
        if !metadata.file_type().is_dir()
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || tokio::fs::canonicalize(root)
                .await
                .map_err(|_| SourceError::InvalidConfig)?
                != root
        {
            return Err(SourceError::InvalidConfig);
        }
        sync_directory(parent).await
    }
    #[cfg(not(unix))]
    {
        let _ = root;
        Err(SourceError::InvalidConfig)
    }
}

async fn create_private_directory(path: &Path) -> Result<(), SourceError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;

        let path = path.to_owned();
        tokio::task::spawn_blocking(move || {
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            builder
                .create(&path)
                .map_err(|_| SourceError::StateUnavailable)
        })
        .await
        .map_err(|_| SourceError::StateUnavailable)??;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(SourceError::InvalidConfig)
    }
}

async fn create_relative_directories(root: &Path, relative: &Path) -> Result<(), SourceError> {
    let mut current = root.to_owned();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(SourceError::UnsafeTree);
        };
        current.push(component);
        match tokio::fs::symlink_metadata(&current).await {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => return Err(SourceError::UnsafeTree),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                create_private_directory(&current).await?;
            }
            Err(_) => return Err(SourceError::StateUnavailable),
        }
    }
    Ok(())
}

async fn write_new_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), SourceError> {
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(mode).custom_flags(nix::libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .await
        .map_err(|_| SourceError::StateUnavailable)?;
    file.write_all(bytes)
        .await
        .map_err(|_| SourceError::StateUnavailable)?;
    file.sync_all()
        .await
        .map_err(|_| SourceError::StateUnavailable)
}

async fn create_safe_symlink(
    root: &Path,
    relative: &Path,
    target_bytes: &[u8],
) -> Result<(), SourceError> {
    #[cfg(unix)]
    {
        validate_symlink_target(relative, target_bytes)?;
        let target = std::str::from_utf8(target_bytes).map_err(|_| SourceError::UnsafeTree)?;
        let target_path = Path::new(target);
        let destination = root.join(relative);
        let target = target_path.to_owned();
        tokio::task::spawn_blocking(move || {
            std::os::unix::fs::symlink(target, destination)
                .map_err(|_| SourceError::StateUnavailable)
        })
        .await
        .map_err(|_| SourceError::StateUnavailable)??;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (root, relative, target_bytes);
        Err(SourceError::UnsafeTree)
    }
}

fn validate_symlink_target(relative: &Path, target_bytes: &[u8]) -> Result<(), SourceError> {
    let target = std::str::from_utf8(target_bytes).map_err(|_| SourceError::UnsafeTree)?;
    let target_path = Path::new(target);
    if target_path.is_absolute() || target.is_empty() {
        return Err(SourceError::UnsafeTree);
    }
    let mut normalized = relative
        .parent()
        .ok_or(SourceError::UnsafeTree)?
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_os_string()),
            _ => None,
        })
        .collect::<Vec<_>>();
    for component in target_path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(value) if !value.eq_ignore_ascii_case(".git") => {
                normalized.push(value.to_os_string());
            }
            Component::ParentDir if normalized.pop().is_some() => {}
            _ => return Err(SourceError::UnsafeTree),
        }
    }
    Ok(())
}

async fn read_link_bytes(path: &Path) -> Result<Vec<u8>, SourceError> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;

        let target = tokio::fs::read_link(path)
            .await
            .map_err(|_| SourceError::InvalidStoredReceipt)?;
        Ok(target.as_os_str().as_bytes().to_vec())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(SourceError::InvalidStoredReceipt)
    }
}

fn add_parent_directories(
    path: &str,
    directories: &mut BTreeSet<String>,
) -> Result<(), SourceError> {
    let mut current = PathBuf::new();
    let parent = Path::new(path)
        .parent()
        .ok_or(SourceError::InvalidStoredReceipt)?;
    for component in parent.components() {
        let Component::Normal(value) = component else {
            return Err(SourceError::InvalidStoredReceipt);
        };
        current.push(value);
        directories.insert(
            current
                .to_str()
                .ok_or(SourceError::InvalidStoredReceipt)?
                .to_owned(),
        );
    }
    Ok(())
}

async fn validate_retained_directory(path: &Path, mode: u32) -> Result<(), SourceError> {
    let metadata = tokio::fs::symlink_metadata(path)
        .await
        .map_err(|_| SourceError::InvalidStoredReceipt)?;
    validate_retained_metadata(&metadata, true, mode)
}

async fn validate_retained_file(path: &Path, mode: u32) -> Result<(), SourceError> {
    let metadata = tokio::fs::symlink_metadata(path)
        .await
        .map_err(|_| SourceError::InvalidStoredReceipt)?;
    validate_retained_metadata(&metadata, false, mode)
}

fn validate_retained_metadata(
    metadata: &std::fs::Metadata,
    directory: bool,
    mode: u32,
) -> Result<(), SourceError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let kind_matches = if directory {
            metadata.file_type().is_dir()
        } else {
            metadata.file_type().is_file()
        };
        if !kind_matches
            || metadata.permissions().mode() & 0o7777 != mode
            || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        {
            return Err(SourceError::InvalidStoredReceipt);
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (metadata, directory, mode);
        Err(SourceError::InvalidStoredReceipt)
    }
}

async fn inventory_materialized_tree(
    root: &Path,
) -> Result<(BTreeSet<String>, BTreeSet<String>), SourceError> {
    let mut leaves = BTreeSet::new();
    let mut directory_paths = BTreeSet::new();
    let mut directories = vec![root.to_owned()];
    let mut index = 0;
    while index < directories.len() {
        let directory = directories[index].clone();
        index += 1;
        let mut entries = tokio::fs::read_dir(&directory)
            .await
            .map_err(|_| SourceError::InvalidStoredReceipt)?;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|_| SourceError::InvalidStoredReceipt)?
        {
            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .ok()
                .and_then(Path::to_str)
                .ok_or(SourceError::InvalidStoredReceipt)?
                .to_owned();
            let metadata = tokio::fs::symlink_metadata(&path)
                .await
                .map_err(|_| SourceError::InvalidStoredReceipt)?;
            if metadata.file_type().is_dir() {
                validate_retained_metadata(&metadata, true, 0o500)?;
                directory_paths.insert(relative);
                directories.push(path);
            } else if metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                leaves.insert(relative);
            } else {
                return Err(SourceError::InvalidStoredReceipt);
            }
            if leaves.len().saturating_add(directory_paths.len())
                > MAX_CONFIGURED_FILES.saturating_add(MAX_CONFIGURED_SUBMODULES)
            {
                return Err(SourceError::InvalidStoredReceipt);
            }
        }
    }
    Ok((leaves, directory_paths))
}

async fn sync_tree(root: &Path) -> Result<(), SourceError> {
    let mut directories = vec![root.to_owned()];
    let mut index = 0;
    while index < directories.len() {
        let directory = directories[index].clone();
        index += 1;
        let mut entries = tokio::fs::read_dir(&directory)
            .await
            .map_err(|_| SourceError::StateUnavailable)?;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|_| SourceError::StateUnavailable)?
        {
            let metadata = tokio::fs::symlink_metadata(entry.path())
                .await
                .map_err(|_| SourceError::StateUnavailable)?;
            if metadata.file_type().is_dir() {
                directories.push(entry.path());
            } else if metadata.file_type().is_file() {
                tokio::fs::File::open(entry.path())
                    .await
                    .map_err(|_| SourceError::StateUnavailable)?
                    .sync_all()
                    .await
                    .map_err(|_| SourceError::StateUnavailable)?;
            } else if !metadata.file_type().is_symlink() {
                return Err(SourceError::UnsafeTree);
            }
        }
    }
    for directory in directories.into_iter().rev() {
        sync_directory(&directory).await?;
    }
    Ok(())
}

async fn allocated_storage_bytes(root: &Path) -> Result<u64, SourceError> {
    for restart in 0..=MAX_TRANSPORT_QUOTA_SCAN_RESTARTS {
        if let Some(bytes) = allocated_storage_bytes_once(root).await? {
            return Ok(bytes);
        }
        if restart == MAX_TRANSPORT_QUOTA_SCAN_RESTARTS {
            return Err(SourceError::StateUnavailable);
        }
        tokio::task::yield_now().await;
    }
    Err(SourceError::StateUnavailable)
}

async fn allocated_storage_bytes_once(root: &Path) -> Result<Option<u64>, SourceError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        let root_metadata = tokio::fs::symlink_metadata(root)
            .await
            .map_err(|_| SourceError::StateUnavailable)?;
        if !root_metadata.file_type().is_dir() {
            return Err(SourceError::StateUnavailable);
        }
        let mut total = root_metadata
            .len()
            .max(root_metadata.blocks().saturating_mul(512));
        let mut entries_seen = 0_usize;
        let mut directories = vec![root.to_owned()];
        let mut index = 0;
        while index < directories.len() {
            let directory = directories[index].clone();
            index += 1;
            let mut entries = match tokio::fs::read_dir(&directory).await {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(_) => return Err(SourceError::StateUnavailable),
            };
            loop {
                let entry = match entries.next_entry().await {
                    Ok(Some(entry)) => entry,
                    Ok(None) => break,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        return Ok(None);
                    }
                    Err(_) => return Err(SourceError::StateUnavailable),
                };
                entries_seen = entries_seen.saturating_add(1);
                if entries_seen > MAX_CONFIGURED_FILES.saturating_mul(4) {
                    return Err(SourceError::LimitExceeded);
                }
                let metadata = match tokio::fs::symlink_metadata(entry.path()).await {
                    Ok(metadata) => metadata,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                    Err(_) => return Err(SourceError::StateUnavailable),
                };
                if metadata.file_type().is_dir() {
                    directories.push(entry.path());
                } else if !metadata.file_type().is_file() {
                    return Err(SourceError::StateUnavailable);
                }
                let allocated = metadata.len().max(metadata.blocks().saturating_mul(512));
                total = total
                    .checked_add(allocated)
                    .ok_or(SourceError::LimitExceeded)?;
            }
        }
        Ok(Some(total))
    }
    #[cfg(not(unix))]
    {
        let _ = root;
        Err(SourceError::InvalidConfig)
    }
}

async fn make_tree_read_only(root: &Path) -> Result<(), SourceError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let mut directories = vec![root.to_owned()];
        let mut index = 0;
        while index < directories.len() {
            let directory = directories[index].clone();
            index += 1;
            let mut entries = tokio::fs::read_dir(&directory)
                .await
                .map_err(|_| SourceError::StateUnavailable)?;
            while let Some(entry) = entries
                .next_entry()
                .await
                .map_err(|_| SourceError::StateUnavailable)?
            {
                let metadata = tokio::fs::symlink_metadata(entry.path())
                    .await
                    .map_err(|_| SourceError::StateUnavailable)?;
                if metadata.file_type().is_dir() {
                    directories.push(entry.path());
                } else if metadata.file_type().is_file() {
                    let executable = metadata.permissions().mode() & 0o100 != 0;
                    set_file_mode_and_sync(&entry.path(), if executable { 0o500 } else { 0o400 })
                        .await?;
                } else if !metadata.file_type().is_symlink() {
                    return Err(SourceError::UnsafeTree);
                }
            }
        }
        for directory in directories.into_iter().rev() {
            set_mode(&directory, 0o500).await?;
            sync_directory(&directory).await?;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = root;
        Err(SourceError::InvalidConfig)
    }
}

async fn make_tree_owner_writable(root: &Path) -> Result<(), SourceError> {
    let metadata = match tokio::fs::symlink_metadata(root).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(SourceError::StateUnavailable),
    };
    if !metadata.file_type().is_dir() {
        return Err(SourceError::StateUnavailable);
    }
    let mut directories = vec![root.to_owned()];
    let mut index = 0;
    while index < directories.len() {
        let directory = directories[index].clone();
        index += 1;
        set_mode(&directory, 0o700).await?;
        let mut entries = tokio::fs::read_dir(&directory)
            .await
            .map_err(|_| SourceError::StateUnavailable)?;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|_| SourceError::StateUnavailable)?
        {
            let metadata = tokio::fs::symlink_metadata(entry.path())
                .await
                .map_err(|_| SourceError::StateUnavailable)?;
            if metadata.file_type().is_dir() {
                directories.push(entry.path());
            } else if !metadata.file_type().is_file() && !metadata.file_type().is_symlink() {
                return Err(SourceError::StateUnavailable);
            }
        }
    }
    Ok(())
}

async fn set_file_mode_and_sync(path: &Path, mode: u32) -> Result<(), SourceError> {
    set_mode(path, mode).await?;
    tokio::fs::File::open(path)
        .await
        .map_err(|_| SourceError::StateUnavailable)?
        .sync_all()
        .await
        .map_err(|_| SourceError::StateUnavailable)
}

async fn set_mode(path: &Path, mode: u32) -> Result<(), SourceError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .await
            .map_err(|_| SourceError::StateUnavailable)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Err(SourceError::InvalidConfig)
    }
}

#[cfg(unix)]
async fn sync_directory(path: &Path) -> Result<(), SourceError> {
    let directory = tokio::fs::File::open(path)
        .await
        .map_err(|_| SourceError::StateUnavailable)?;
    if !directory
        .metadata()
        .await
        .map_err(|_| SourceError::StateUnavailable)?
        .is_dir()
    {
        return Err(SourceError::StateUnavailable);
    }
    directory
        .sync_all()
        .await
        .map_err(|_| SourceError::StateUnavailable)
}

#[cfg(not(unix))]
async fn sync_directory(_path: &Path) -> Result<(), SourceError> {
    Err(SourceError::InvalidConfig)
}

async fn publish_stage(
    root: &Path,
    stage: &Path,
    acquisition_id: Uuid,
    claim: &AcquisitionClaim,
) -> Result<(), SourceError> {
    let final_path = acquisition_path(root, acquisition_id);
    tokio::fs::rename(stage, &final_path)
        .await
        .map_err(|_| SourceError::StateUnavailable)?;
    if sync_directory(root).await.is_err() {
        withdraw_late_publication(root, acquisition_id, claim, &final_path).await?;
        return Err(SourceError::StateUnavailable);
    }
    if now_unix_ms()? >= claim.publication_deadline_unix_ms {
        withdraw_late_publication(root, acquisition_id, claim, &final_path).await?;
        return Err(SourceError::ExpiredRequest);
    }
    if tokio::fs::remove_file(claim_path(root, acquisition_id))
        .await
        .is_err()
    {
        withdraw_late_publication(root, acquisition_id, claim, &final_path).await?;
        return Err(SourceError::StateUnavailable);
    }
    if sync_directory(root).await.is_err() {
        withdraw_late_publication(root, acquisition_id, claim, &final_path).await?;
        return Err(SourceError::StateUnavailable);
    }
    if now_unix_ms()? >= claim.publication_deadline_unix_ms {
        withdraw_late_publication(root, acquisition_id, claim, &final_path).await?;
        return Err(SourceError::ExpiredRequest);
    }
    Ok(())
}

async fn withdraw_late_publication(
    root: &Path,
    acquisition_id: Uuid,
    claim: &AcquisitionClaim,
    final_path: &Path,
) -> Result<(), SourceError> {
    let claim_path = claim_path(root, acquisition_id);
    if !claim_path.exists() {
        let bytes = serde_json::to_vec(claim).map_err(|_| SourceError::StateUnavailable)?;
        write_new_file(&claim_path, &bytes, 0o600).await?;
    }
    let quarantine = root.join(format!(".expired-{acquisition_id}-{}", Uuid::new_v4()));
    tokio::fs::rename(final_path, &quarantine)
        .await
        .map_err(|_| SourceError::StateUnavailable)?;
    sync_directory(root).await?;
    make_tree_owner_writable(&quarantine).await?;
    tokio::fs::remove_dir_all(&quarantine)
        .await
        .map_err(|_| SourceError::StateUnavailable)?;
    sync_directory(root).await
}

fn acquisition_path(root: &Path, acquisition_id: Uuid) -> PathBuf {
    root.join(acquisition_id.to_string())
}

fn claim_path(root: &Path, acquisition_id: Uuid) -> PathBuf {
    root.join(format!("{acquisition_id}.claim.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn expired_final_publication_is_withdrawn_while_claim_remains() {
        let temporary = tempfile::tempdir().expect("publication tempdir");
        let root = temporary.path();
        let acquisition_id = Uuid::new_v4();
        let stage = root.join("stage");
        create_private_directory(&stage).await.unwrap();
        write_new_file(&stage.join("receipt.json"), b"{}", 0o400)
            .await
            .unwrap();
        let claim = AcquisitionClaim {
            protocol_version: PROTOCOL_VERSION.to_owned(),
            request_sha256: "a".repeat(64),
            publication_deadline_unix_ms: now_unix_ms().unwrap() - 1,
        };
        write_new_file(
            &claim_path(root, acquisition_id),
            &serde_json::to_vec(&claim).unwrap(),
            0o600,
        )
        .await
        .unwrap();

        assert!(matches!(
            publish_stage(root, &stage, acquisition_id, &claim).await,
            Err(SourceError::ExpiredRequest)
        ));
        assert!(!acquisition_path(root, acquisition_id).exists());
        assert!(claim_path(root, acquisition_id).exists());
        assert!(std::fs::read_dir(root).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".expired-")
        }));
    }
}
