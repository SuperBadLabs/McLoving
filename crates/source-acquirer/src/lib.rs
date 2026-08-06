use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac as _};
use serde::de::{DeserializeOwned, DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::process::Command;
use tokio::sync::Mutex;
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
const MAX_AUTHORITY_BYTES: usize = 64 * 1_024;
const MAX_MARKERS: usize = 256;
const MAX_MARKER_WORK: u128 = 512 * 1_024 * 1_024;

type HmacSha256 = Hmac<Sha256>;

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
    credential_path: PathBuf,
    signing_key: Vec<u8>,
    secret_markers: Vec<Vec<u8>>,
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
        if sha256_file(&config.git_executable_path).await? != config.git_executable_sha256 {
            return Err(SourceError::InvalidConfig);
        }
        if let (Some(path), Some(expected)) = (&config.ca_bundle_path, &config.ca_bundle_sha256)
            && sha256_file(path).await? != *expected
        {
            return Err(SourceError::InvalidConfig);
        }
        ensure_private_output_root(&config.output_root).await?;
        let config_sha256 = config.canonical_digest()?;
        let acquirer = Self {
            config,
            config_sha256,
            implementation_sha256,
            credential_path,
            signing_key,
            secret_markers,
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
        if let Some(receipt) = self.load_receipt(request.acquisition_id).await? {
            if receipt.request_sha256 != request_sha256 {
                return Err(SourceError::ReplayMismatch);
            }
            self.verify_receipt(&receipt).await?;
            return Ok(receipt);
        }
        if claim_path(&self.config.output_root, request.acquisition_id).exists() {
            return Err(SourceError::AmbiguousClaim);
        }
        self.verify_runtime_authority().await?;
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
        let mut folded_paths = HashSet::new();
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
            let module_declarations = self.read_gitmodules(&git_dir, &entries).await?;
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
                        manifest.push(ManifestEntry {
                            path: full_path,
                            git_mode: entry.mode,
                            git_object_id: entry.object_id.clone(),
                            bytes: 0,
                            sha256: sha256_hex(entry.object_id.as_bytes()),
                        });
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
                let blob = self
                    .run_git(
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
                    )
                    .await?;
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
        set_mode(&stage.join("manifest.json"), 0o400).await?;
        set_mode(&stage.join("receipt.json"), 0o400).await?;
        sync_directory(stage).await?;

        self.ensure_before_deadline(publication_deadline_unix_ms)?;
        let final_path = acquisition_path(&self.config.output_root, request.acquisition_id);
        tokio::fs::rename(stage, &final_path)
            .await
            .map_err(|_| SourceError::StateUnavailable)?;
        sync_directory(&self.config.output_root).await?;
        tokio::fs::remove_file(claim_path(&self.config.output_root, request.acquisition_id))
            .await
            .map_err(|_| SourceError::StateUnavailable)?;
        sync_directory(&self.config.output_root).await?;
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
            || request.expected_config_sha256 != self.config_sha256
            || request.protocol_version != PROTOCOL_VERSION
            || request.schema_version != self.config.schema_version
            || request.expected_generation != self.config.generation
            || request
                .rollback_from_generation
                .is_some_and(|generation| generation >= self.config.generation)
            || request.requested_at_unix_ms > now
            || request.expires_at_unix_ms <= now
            || request.expires_at_unix_ms <= request.requested_at_unix_ms
            || request.depth > self.config.max_depth
            || request.submodules.len() > self.config.max_submodules
            || !repository_admitted
            || !valid_ref(&request.authenticated_ref)
            || !self.ref_allowed(&request.authenticated_ref)
            || !is_object_id(&request.exact_commit)
        {
            return Err(SourceError::BindingMismatch);
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
        )?;
        let mut submodule_paths = BTreeSet::new();
        for submodule in &request.submodules {
            validate_repository_url(
                &submodule.repository_url,
                self.config.test_allow_file_repositories,
                self.config.test_allow_http_loopback,
            )?;
            validate_relative_path(&submodule.path, self.config.max_path_bytes)?;
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

    async fn fetch_repository(
        &self,
        repository: &RepositoryWork,
        depth: u32,
        git_dir: &Path,
        deadline: i64,
    ) -> Result<(), SourceError> {
        create_private_directory(git_dir).await?;
        let mut init_arguments = vec![OsString::from("init"), OsString::from("--bare")];
        if repository.exact_commit.len() == 64 {
            init_arguments.push(OsString::from("--object-format=sha256"));
        }
        init_arguments.push(git_dir.as_os_str().to_owned());
        self.run_git(init_arguments, MAX_GIT_METADATA_BYTES).await?;
        self.ensure_before_deadline(deadline)?;
        let mut arguments = vec![
            OsString::from("--git-dir"),
            git_dir.as_os_str().to_owned(),
            OsString::from("fetch"),
            OsString::from("--no-tags"),
            OsString::from("--force"),
        ];
        if depth > 0 {
            arguments.push(OsString::from(format!("--depth={depth}")));
        }
        arguments.extend([
            OsString::from("--"),
            OsString::from(&repository.binding.repository_url),
            OsString::from(&repository.authenticated_ref),
        ]);
        self.run_git(arguments, MAX_GIT_METADATA_BYTES).await?;
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
    ) -> Result<BTreeMap<String, String>, SourceError> {
        let Some(entry) = entries.iter().find(|entry| entry.path == ".gitmodules") else {
            return Ok(BTreeMap::new());
        };
        if entry.mode != "100644" || entry.kind != "blob" {
            return Err(SourceError::SubmoduleMismatch);
        }
        let bytes = self
            .run_git(
                vec![
                    OsString::from("--git-dir"),
                    git_dir.as_os_str().to_owned(),
                    OsString::from("cat-file"),
                    OsString::from("blob"),
                    OsString::from(&entry.object_id),
                ],
                MAX_AUTHORITY_BYTES,
            )
            .await?;
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
        folded_paths: &mut HashSet<String>,
    ) -> Result<(), SourceError> {
        validate_relative_path(path, self.config.max_path_bytes)?;
        let folded = path.to_lowercase();
        if !exact_paths.insert(path.to_owned()) || !folded_paths.insert(folded) {
            return Err(SourceError::UnsafeTree);
        }
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
        self.verify_runtime_authority().await?;
        let mut command = Command::new(&self.config.git_executable_path);
        command
            .env_clear()
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/nonexistent")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env(
                "GIT_ASKPASS",
                std::env::current_exe().map_err(|_| SourceError::InvalidConfig)?,
            )
            .env("MCLOVING_SOURCE_ACQUIRER_ASKPASS", "1")
            .env(
                "MCLOVING_SOURCE_ACQUIRER_CREDENTIAL_FILE",
                &self.credential_path,
            )
            .env(
                "MCLOVING_SOURCE_ACQUIRER_CREDENTIAL_USERNAME",
                &self.config.credential_username,
            )
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
                "protocol.allow=never",
                "-c",
                "protocol.https.allow=always",
            ]);
        if self.config.test_allow_http_loopback {
            command.args(["-c", "protocol.http.allow=always"]);
        }
        if self.config.test_allow_file_repositories {
            command.args(["-c", "protocol.file.allow=always"]);
        }
        if let Some(path) = &self.config.ca_bundle_path {
            command.env("GIT_SSL_CAINFO", path);
        }
        command
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = command
            .spawn()
            .map_err(|_| SourceError::SourceUnavailable)?;
        let stdout = child.stdout.take().ok_or(SourceError::StateUnavailable)?;
        let stderr = child.stderr.take().ok_or(SourceError::StateUnavailable)?;
        let timeout = Duration::from_millis(self.config.command_timeout_ms);
        let completed = tokio::time::timeout(timeout, async move {
            let status = child.wait();
            let stdout = read_bounded(stdout, max_stdout);
            let stderr = read_bounded(stderr, MAX_GIT_STDERR_BYTES);
            tokio::try_join!(status, stdout, stderr)
        })
        .await
        .map_err(|_| SourceError::SourceUnavailable)?
        .map_err(|_| SourceError::LimitExceeded)?;
        let (status, stdout, stderr) = completed;
        self.reject_secret_markers(&stdout)?;
        self.reject_secret_markers(&stderr)?;
        if !status.success() {
            return Err(SourceError::SourceUnavailable);
        }
        Ok(stdout)
    }

    async fn verify_runtime_authority(&self) -> Result<(), SourceError> {
        let credential =
            read_private_bounded_regular_file(&self.credential_path, MAX_AUTHORITY_BYTES).await?;
        if sha256_hex(&credential) != self.config.credential_sha256
            || sha256_file(&self.config.git_executable_path).await?
                != self.config.git_executable_sha256
        {
            return Err(SourceError::BindingMismatch);
        }
        if let (Some(path), Some(expected)) =
            (&self.config.ca_bundle_path, &self.config.ca_bundle_sha256)
            && sha256_file(path).await? != *expected
        {
            return Err(SourceError::BindingMismatch);
        }
        Ok(())
    }

    fn reject_secret_markers(&self, bytes: &[u8]) -> Result<(), SourceError> {
        if self
            .secret_markers
            .iter()
            .any(|marker| contains_bytes(bytes, marker))
        {
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
            || receipt.git_version != self.config.git_version
            || receipt.acquirer_config_sha256 != self.config_sha256
            || receipt.deployment_identity != self.config.deployment_identity
            || receipt.operator_identity != self.config.operator_identity
            || receipt.generation != self.config.generation
            || receipt.signing_key_id != self.config.receipt_signing_key_id
            || receipt.secret_marker_set_sha256 != self.config.secret_marker_set_sha256
            || receipt.output_relative_path != format!("{}/tree", receipt.acquisition_id)
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
        validate_retained_directory(&acquisition_root, 0o700).await?;
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
        || !is_sha256_hex(implementation_sha256)
        || !is_sha256_hex(&config.git_executable_sha256)
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
        || config.max_files == 0
        || config.max_files > MAX_CONFIGURED_FILES
        || config.max_total_bytes == 0
        || config.max_total_bytes > MAX_CONFIGURED_BYTES
        || config.max_file_bytes == 0
        || config.max_file_bytes > config.max_total_bytes
        || config.max_file_bytes > MAX_CONFIGURED_FILE_BYTES
        || config.max_path_bytes == 0
        || config.max_path_bytes > MAX_CONFIGURED_PATH_BYTES
        || config.max_submodules > MAX_CONFIGURED_SUBMODULES
        || config.max_depth > MAX_CONFIGURED_DEPTH
        || config.command_timeout_ms == 0
        || config.command_timeout_ms > MAX_CONFIGURED_TIMEOUT_MS
        || config.allowed_ref_prefixes.is_empty()
    {
        return Err(SourceError::InvalidConfig);
    }
    let marker_bytes = markers.iter().try_fold(0_u128, |total, marker| {
        total.checked_add(u128::try_from(marker.len()).unwrap_or(u128::MAX))
    });
    if marker_bytes
        .and_then(|bytes| bytes.checked_mul(u128::from(config.max_total_bytes)))
        .is_none_or(|work| work > MAX_MARKER_WORK)
    {
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
    )?;
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

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|candidate| candidate == needle)
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
                    set_mode(&entry.path(), if executable { 0o500 } else { 0o400 }).await?;
                } else if !metadata.file_type().is_symlink() {
                    return Err(SourceError::UnsafeTree);
                }
            }
        }
        for directory in directories.into_iter().rev() {
            set_mode(&directory, 0o500).await?;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = root;
        Err(SourceError::InvalidConfig)
    }
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

fn acquisition_path(root: &Path, acquisition_id: Uuid) -> PathBuf {
    root.join(acquisition_id.to_string())
}

fn claim_path(root: &Path, acquisition_id: Uuid) -> PathBuf {
    root.join(format!("{acquisition_id}.claim.json"))
}
