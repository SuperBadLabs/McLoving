//! Deployment-owned checkout mediation (PAR-012). A pipeline names a binding,
//! a ref, an exact commit and a workspace destination; the repository, the
//! credential, the sealed acquirer and its containment come from the binding.
//! The acquired tree is then published into the attempt workspace by a
//! descriptor-relative, no-replace rename whose destination identity is
//! checked before and after.
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use mcloving_domain::cache_intent::{canonical_mapping_id, canonical_sha256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::private_helper::read_private;
use crate::{AgentConfig, AgentError};

const MAX_BINDINGS_BYTES: usize = 262_144;
/// One NDJSON request line to the acquirer; its own bound is 64 KiB.
#[cfg(target_os = "linux")]
const MAX_REQUEST_BYTES: usize = 65_536;
/// One NDJSON receipt line back; the private-IO executor caps output here.
#[cfg(target_os = "linux")]
const MAX_RESPONSE_BYTES: u64 = 262_144;
/// Directory entries the publication walk will visit before refusing: the
/// receipt bounds files, and this bounds a tree whose directory count the
/// receipt does not carry.
#[cfg(target_os = "linux")]
const MAX_PUBLICATION_ENTRIES: usize = 262_144;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBindings {
    pub schema_version: String,
    pub mappings: Vec<SourceBinding>,
}

/// How the sealed acquirer is entered on a host that restricts unprivileged
/// user namespaces: `aa-exec -p <profile> -- /proc/self/fd/N`. The profile
/// grants only `userns create`; the image is still the sealed memory file.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceLauncher {
    pub aa_exec: PathBuf,
    pub profile: String,
}

/// Every operator authority choice is covered by the canonical mapping digest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBinding {
    pub mapping_id: String,
    pub organization_id: String,
    pub project_id: String,
    pub pipeline_id: String,
    pub trust_pool: String,
    pub executable: PathBuf,
    pub executable_sha256: String,
    pub config_path: PathBuf,
    pub config_sha256: String,
    pub credential_path: PathBuf,
    pub signing_key_path: PathBuf,
    pub secret_markers_path: PathBuf,
    #[serde(default)]
    pub launcher: Option<SourceLauncher>,
    /// Fixture-only operator opt-in, never supplied by a submitted job: the
    /// acquirer configuration may then name file or loopback repositories.
    #[serde(default)]
    pub test_mode: bool,
}
impl SourceBinding {
    pub fn mapping_digest(&self) -> Result<String, AgentError> {
        Ok(format!(
            "sha256:{}",
            hex(&Sha256::digest(serde_json::to_vec(self)?))
        ))
    }
}
fn denied() -> AgentError {
    AgentError::InvalidConfig("sealed source deployment binding")
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn load_bindings(path: &Path, expected_sha256: &str) -> Result<SourceBindings, AgentError> {
    let bytes = read_private(path, MAX_BINDINGS_BYTES, true)?;
    if !canonical_sha256(expected_sha256) || hex(&Sha256::digest(&bytes)) != expected_sha256 {
        return Err(denied());
    }
    let bindings: SourceBindings =
        mcloving_cache::parse_json_no_duplicates(&bytes).map_err(|_| denied())?;
    if bindings.schema_version != "mcloving.agent-source-bindings/v1"
        || bindings.mappings.is_empty()
        || bindings.mappings.len() > 128
    {
        return Err(denied());
    }
    let mut ids = BTreeSet::new();
    for b in &bindings.mappings {
        if !canonical_mapping_id(&b.mapping_id)
            || !ids.insert(&b.mapping_id)
            || [&b.organization_id, &b.project_id, &b.pipeline_id]
                .into_iter()
                .any(|id| {
                    uuid::Uuid::parse_str(id)
                        .map_or(true, |value| value.is_nil() || value.to_string() != *id)
                })
            || [&b.executable_sha256, &b.config_sha256]
                .into_iter()
                .any(|value| !canonical_sha256(value))
            || b.trust_pool.is_empty()
            || b.trust_pool.len() > 128
            || b.trust_pool.trim() != b.trust_pool
            || [
                &b.executable,
                &b.config_path,
                &b.credential_path,
                &b.signing_key_path,
                &b.secret_markers_path,
            ]
            .into_iter()
            .any(|path| !path.is_absolute())
            || b.launcher.as_ref().is_some_and(|launcher| {
                !launcher.aa_exec.is_absolute()
                    || launcher.profile.is_empty()
                    || launcher.profile.len() > 128
                    || !launcher.profile.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                    })
            })
        {
            return Err(denied());
        }
    }
    Ok(bindings)
}

/// `sealed-source-v1` plus one exact binding capability per mapping in this
/// agent's trust pool; Linux only, since the acquirer seals and contains
/// itself with Linux facilities.
pub(crate) fn scheduling_capabilities(config: &AgentConfig) -> Result<Vec<String>, AgentError> {
    let mut capabilities = BTreeSet::new();
    if cfg!(target_os = "linux")
        && let Some(bindings) = &config.source_bindings
    {
        capabilities.insert(mcloving_domain::source_intent::SOURCE_CAPABILITY.to_owned());
        for binding in &bindings.mappings {
            if binding.trust_pool == config.trust_pool {
                capabilities.insert(
                    mcloving_domain::source_intent::source_binding_capability(
                        &binding.mapping_id,
                        &binding.mapping_digest()?,
                    )
                    .map_err(|_| denied())?,
                );
            }
        }
    }
    Ok(capabilities.into_iter().collect())
}

#[cfg(target_os = "linux")]
pub(crate) use linux::{PreparedSource, prepare};

#[cfg(target_os = "linux")]
mod linux {
    use super::{
        MAX_PUBLICATION_ENTRIES, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, SourceBinding, denied, hex,
    };
    use crate::private_helper::{read_private, seal_executable};
    use crate::{AgentConfig, AgentError};
    use mcloving_agent_runtime::executor::PrivateExecutionOutput;
    use mcloving_domain::source_intent::{CheckoutStepSpec, SourceWorkContext};
    use mcloving_source_acquirer::{
        AcquisitionReceipt, AcquisitionRequest, SourceAcquirer, SourceConfig, TrustClass,
        content_sha256, marker_set_digest, parse_json_no_duplicates,
    };
    use std::collections::BTreeMap;
    use std::ffi::{CStr, OsString};
    use std::fs::File;
    use std::os::fd::{AsFd, OwnedFd};
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use uuid::Uuid;

    fn now_ms() -> Result<i64, AgentError> {
        i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| denied())?
                .as_millis(),
        )
        .map_err(|_| denied())
    }

    /// Everything the executor needs to run one sealed acquisition, plus what
    /// `transform` needs to authenticate the answer and `publish` needs to
    /// move the tree.
    pub(crate) struct PreparedSource {
        // Hold the immutable executable through process spawn and containment.
        _executable: File,
        pub program: PathBuf,
        pub arguments: Vec<OsString>,
        pub environment: BTreeMap<String, String>,
        pub output_limit: u64,
        config: SourceConfig,
        signing_key: Vec<u8>,
        /// The request without its time window; `begin` opens the window
        /// into `live` when the step is about to spawn.
        acquisition: AcquisitionRequest,
        timeout_seconds: u64,
        live: Mutex<Option<AcquisitionRequest>>,
        binding: SourceBinding,
        invocation_id: String,
        verified: Mutex<Option<AcquisitionReceipt>>,
        last_outcome: Mutex<Option<&'static str>>,
    }

    /// What `publish` moved, for the step's public record.
    #[derive(Clone, Debug)]
    pub(crate) struct PublishedCheckout {
        pub destination: String,
        pub resolved_commit: String,
        pub materialized_files: usize,
    }

    /// One deterministic acquisition id per attempt and step, so a retried
    /// spawn of the same step meets the acquirer's replay rules rather than
    /// minting a second tree.
    fn acquisition_id(context: &SourceWorkContext, ordinal: u32) -> Uuid {
        use sha2::{Digest as _, Sha256};
        let digest = Sha256::digest(
            format!(
                "mcloving.source-acquisition/v1:{}:{}:{ordinal}",
                context.attempt_id, context.fence_token
            )
            .as_bytes(),
        );
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        // Name-derived (version 8, RFC 9562 custom) with the RFC variant.
        bytes[6] = (bytes[6] & 0x0f) | 0x80;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Uuid::from_bytes(bytes)
    }

    pub(crate) fn prepare(
        config: &AgentConfig,
        spec: &CheckoutStepSpec,
        context: &SourceWorkContext,
        payload_digest: &[u8; 32],
        ordinal: u32,
    ) -> Result<PreparedSource, AgentError> {
        spec.validate().map_err(|_| denied())?;
        context.validate().map_err(|_| denied())?;
        let binding = config
            .source_bindings
            .as_ref()
            .and_then(|catalog| {
                catalog
                    .mappings
                    .iter()
                    .find(|entry| entry.mapping_id == spec.mapping_id)
            })
            .ok_or_else(denied)?;
        if binding.mapping_digest()? != spec.mapping_digest
            || binding.organization_id != context.organization_id
            || binding.project_id != context.project_id
            || binding.pipeline_id != context.pipeline_id
            || binding.trust_pool != config.trust_pool
        {
            return Err(denied());
        }
        let source_config: SourceConfig =
            parse_json_no_duplicates(&read_private(&binding.config_path, 262_144, false)?)
                .map_err(|_| denied())?;
        if source_config.canonical_digest().map_err(|_| denied())? != binding.config_sha256
            || ((source_config.test_allow_file_repositories
                || source_config.test_allow_http_loopback)
                && !binding.test_mode)
        {
            return Err(denied());
        }
        let signing_key = read_private(&binding.signing_key_path, 4096, false)?;
        if signing_key.len() < 32
            || content_sha256(&signing_key) != source_config.receipt_signing_key_sha256
        {
            return Err(denied());
        }
        let markers = read_private(&binding.secret_markers_path, 65_536, false)?
            .split(|byte| *byte == b'\n')
            .filter(|marker| !marker.is_empty())
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        if marker_set_digest(&markers) != source_config.secret_marker_set_sha256 {
            return Err(denied());
        }
        // The acquirer would refuse a ref outside its allow-list as a generic
        // binding mismatch; refusing here names the reason to the pipeline.
        if !source_config
            .allowed_ref_prefixes
            .iter()
            .any(|prefix| spec.reference.starts_with(prefix))
        {
            return Err(AgentError::InvalidConfig(
                "checkout ref is outside the binding's allowed prefixes",
            ));
        }
        let uuid = |value: &str| Uuid::parse_str(value).map_err(|_| denied());
        // The time window is opened by `begin`, immediately before the step's
        // spawn: a checkout prepared with the attempt but placed after long
        // steps must not reach the acquirer already expired.
        let acquisition = AcquisitionRequest {
            acquisition_id: acquisition_id(context, ordinal),
            organization_id: uuid(&context.organization_id)?,
            project_id: uuid(&context.project_id)?,
            pipeline_id: uuid(&context.pipeline_id)?,
            build_id: uuid(&context.build_id)?,
            attempt_id: uuid(&context.attempt_id)?,
            checkout_name: spec.destination.clone(),
            acquirer_id: source_config.acquirer_id.clone(),
            expected_implementation_sha256: binding.executable_sha256.clone(),
            expected_git_sha256: source_config.git_executable_sha256.clone(),
            expected_git_remote_https_sha256: source_config
                .git_remote_https_executable_sha256
                .clone(),
            expected_config_sha256: binding.config_sha256.clone(),
            protocol_version: source_config.protocol_version.clone(),
            schema_version: source_config.schema_version.clone(),
            expected_generation: source_config.generation,
            rollback_from_generation: None,
            provider_identity: source_config.primary_repository.provider_identity.clone(),
            repository_identity: source_config.primary_repository.repository_identity.clone(),
            repository_url: source_config.primary_repository.repository_url.clone(),
            authenticated_ref: spec.reference.clone(),
            exact_commit: spec.commit.clone(),
            source_identity: format!("mcloving.pipeline/{}", context.pipeline_id),
            trust_class: TrustClass::Trusted,
            depth: 1,
            sparse_roots: Vec::new(),
            submodules: Vec::new(),
            requested_at_unix_ms: 0,
            expires_at_unix_ms: 0,
            audit_lineage: format!(
                "mcloving.build/{}/attempt/{}/step/{ordinal}",
                context.build_id, context.attempt_id
            ),
        };
        // Bounded with the window's widest possible spelling in place of the
        // placeholders it carries until `begin`.
        if serde_json::to_vec(&acquisition)?.len() + 2 * i64::MAX.to_string().len() + 1
            > MAX_REQUEST_BYTES
        {
            return Err(denied());
        }
        let (executable, sealed) =
            seal_executable(&binding.executable, &binding.executable_sha256)?;
        let (program, arguments) = match &binding.launcher {
            Some(launcher) => (
                launcher.aa_exec.clone(),
                vec![
                    OsString::from("-p"),
                    OsString::from(&launcher.profile),
                    OsString::from("--"),
                    sealed.into_os_string(),
                ],
            ),
            None => (sealed, Vec::new()),
        };
        let mut environment = BTreeMap::new();
        for (name, path) in [
            ("MCLOVING_SOURCE_ACQUIRER_CONFIG", &binding.config_path),
            (
                "MCLOVING_SOURCE_ACQUIRER_CREDENTIAL_FILE",
                &binding.credential_path,
            ),
            (
                "MCLOVING_SOURCE_ACQUIRER_SIGNING_KEY_FILE",
                &binding.signing_key_path,
            ),
            (
                "MCLOVING_SOURCE_ACQUIRER_SECRET_MARKERS_FILE",
                &binding.secret_markers_path,
            ),
        ] {
            environment.insert(
                name.to_owned(),
                path.to_str().ok_or_else(denied)?.to_owned(),
            );
        }
        environment.insert(
            "MCLOVING_SOURCE_ACQUIRER_EXPECTED_CONFIG_SHA256".to_owned(),
            binding.config_sha256.clone(),
        );
        if binding.test_mode {
            environment.insert(
                "MCLOVING_SOURCE_ACQUIRER_TEST_MODE".to_owned(),
                "1".to_owned(),
            );
        }
        Ok(PreparedSource {
            _executable: executable,
            program,
            arguments,
            environment,
            output_limit: MAX_RESPONSE_BYTES,
            config: source_config,
            signing_key,
            acquisition,
            timeout_seconds: spec.timeout_seconds,
            live: Mutex::new(None),
            binding: binding.clone(),
            invocation_id: format!("sha256:{}", hex(payload_digest)),
            verified: Mutex::new(None),
            last_outcome: Mutex::new(None),
        })
    }

    /// The sealed acquirer's closed failure codes; anything else is reported
    /// as a generic acquisition failure rather than echoed.
    const HELPER_CODES: &[&str] = &[
        "invalid_config",
        "binding_mismatch",
        "expired_request",
        "expired_grant",
        "repository_denied",
        "revision_mismatch",
        "submodule_mismatch",
        "unsafe_tree",
        "limit_exceeded",
        "unauthorized",
        "source_unavailable",
        "replay_mismatch",
        "ambiguous_claim",
        "invalid_stored_receipt",
        "state_unavailable",
        "transport_namespace_unavailable",
        "oversized_request",
        "malformed_request",
    ];

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct HelperAnswer {
        ok: bool,
        #[serde(default)]
        receipt: Option<Box<AcquisitionReceipt>>,
        #[serde(default)]
        code: Option<String>,
        #[serde(default)]
        message: Option<String>,
    }

    impl PreparedSource {
        /// Opens the request's time window now, for exactly the step's
        /// timeout, and fixes the request the helper will read. Called right
        /// before the spawn, so waiting for credentials or earlier steps
        /// never spends the checkout's own time.
        pub fn begin(&self) -> Result<(), AgentError> {
            let requested_at = now_ms()?;
            let expires_at = requested_at
                .checked_add(i64::try_from(self.timeout_seconds * 1_000).map_err(|_| denied())?)
                .ok_or_else(denied)?;
            let mut live = self.acquisition.clone();
            live.requested_at_unix_ms = requested_at;
            live.expires_at_unix_ms = expires_at;
            *self.live.lock().map_err(|_| denied())? = Some(live);
            Ok(())
        }

        /// The NDJSON request line for the helper: the live request once
        /// `begin` opened its window, otherwise the windowless template, which
        /// the acquirer refuses as expired rather than running.
        pub fn request(&self) -> Vec<u8> {
            let request = self
                .live
                .lock()
                .ok()
                .and_then(|live| live.clone())
                .unwrap_or_else(|| self.acquisition.clone());
            let mut bytes = serde_json::to_vec(&request).unwrap_or_default();
            bytes.push(b'\n');
            bytes
        }

        fn live_request(&self) -> Option<AcquisitionRequest> {
            self.live.lock().ok().and_then(|live| live.clone())
        }

        /// Authenticates the acquirer's one-line answer against the request
        /// this agent wrote and the material it configured the helper with,
        /// and emits only a typed public summary. Nothing of the answer
        /// itself, its message included, reaches the public stream.
        pub fn transform(&self, stdout: &[u8], _stderr: &[u8]) -> PrivateExecutionOutput {
            let (outcome, receipt) = match self.authenticate(stdout) {
                Ok(receipt) => ("acquired", Some(receipt)),
                Err(outcome) => (outcome, None),
            };
            let accepted = receipt.is_some();
            if let Ok(mut last) = self.last_outcome.lock() {
                *last = Some(outcome);
            }
            let mut public = serde_json::to_vec(&serde_json::json!({
                "protocol": "mcloving.source-invocation/v1",
                "invocation_id": self.invocation_id,
                "mapping_id": self.binding.mapping_id,
                "acquisition_id": self.acquisition.acquisition_id,
                "destination": self.acquisition.checkout_name,
                "outcome": outcome,
                "resolved_commit": receipt.as_ref().and_then(|r| r.repository_trees.first()).map(|t| t.resolved_commit.clone()),
                "resolved_tree": receipt.as_ref().and_then(|r| r.repository_trees.first()).map(|t| t.resolved_tree.clone()),
                "materialized_files": receipt.as_ref().map(|r| r.materialized_files),
                "materialized_bytes": receipt.as_ref().map(|r| r.materialized_bytes),
                "transport_bytes": receipt.as_ref().map(|r| r.transport_bytes),
            }))
            .unwrap_or_default();
            public.push(b'\n');
            if let Some(receipt) = receipt
                && let Ok(mut verified) = self.verified.lock()
            {
                *verified = Some(receipt);
            }
            PrivateExecutionOutput {
                stdout: public,
                accepted,
            }
        }

        fn authenticate(&self, stdout: &[u8]) -> Result<AcquisitionReceipt, &'static str> {
            let line = stdout.strip_suffix(b"\n").unwrap_or(stdout);
            if line.is_empty() || line.contains(&b'\n') {
                return Err("response_rejected");
            }
            let answer: HelperAnswer =
                parse_json_no_duplicates(line).map_err(|_| "response_rejected")?;
            if !answer.ok {
                // The helper's failure code is a closed enum name and is the
                // only part of the answer carried forward; its message may
                // name paths or hosts and is dropped.
                drop(answer.message);
                return Err(match answer.code.as_deref() {
                    Some(code)
                        if !code.is_empty()
                            && code.len() <= 64
                            && code
                                .bytes()
                                .all(|byte| byte.is_ascii_lowercase() || byte == b'_') =>
                    {
                        HELPER_CODES
                            .iter()
                            .copied()
                            .find(|known| *known == code)
                            .unwrap_or("acquisition_failed")
                    }
                    _ => "acquisition_failed",
                });
            }
            let receipt = *answer.receipt.ok_or("response_rejected")?;
            SourceAcquirer::authenticate_receipt(
                &self.config,
                &self.binding.config_sha256,
                &self.binding.executable_sha256,
                &self.signing_key,
                &receipt,
            )
            .map_err(|_| "response_rejected")?;
            let request_sha256 =
                self.live_request()
                    .ok_or("response_rejected")
                    .and_then(|live| {
                        SourceAcquirer::request_sha256(&live).map_err(|_| "response_rejected")
                    })?;
            let primary = receipt
                .repository_trees
                .first()
                .ok_or("response_rejected")?;
            if receipt.acquisition_id != self.acquisition.acquisition_id
                || receipt.request_sha256 != request_sha256
                || receipt.attempt_id != self.acquisition.attempt_id
                || receipt.build_id != self.acquisition.build_id
                || receipt.checkout_name != self.acquisition.checkout_name
                || receipt.trust_class != TrustClass::Trusted
                || !primary.path.is_empty()
                || primary.resolved_commit != self.acquisition.exact_commit
                || primary.repository_url != self.acquisition.repository_url
            {
                return Err("response_rejected");
            }
            Ok(receipt)
        }

        /// The outcome the last `transform` reported, for the step reason.
        pub fn last_outcome(&self) -> Option<&'static str> {
            self.last_outcome.lock().ok().and_then(|last| *last)
        }

        /// Moves the verified tree into `<workspace>/<destination>`.
        ///
        /// The destination is checked absent by a no-follow stat, the move is
        /// a `renameat2(RENAME_NOREPLACE)` between two directory descriptors,
        /// and the moved entry is checked afterwards to be the very inode the
        /// acquirer built. A destination that an earlier step pre-created (a
        /// symlink, say) is refused by name with nothing written through it;
        /// one that appeared between the check and the rename makes the
        /// rename fail rather than replace, and is reported as substituted.
        /// Then the tree, which the acquirer left read-only, is made writable
        /// for its owner so build steps can work in it, walking by descriptor
        /// and never following a link.
        pub fn publish(&self, workspace: &Path) -> Result<PublishedCheckout, String> {
            let receipt = self
                .verified
                .lock()
                .ok()
                .and_then(|mut slot| slot.take())
                .ok_or_else(|| "checkout_unverified".to_owned())?;
            let destination = self.acquisition.checkout_name.as_str();
            let acquisition_dir = self
                .config
                .output_root
                .join(receipt.acquisition_id.to_string());
            let acquisition = open_directory(&acquisition_dir)
                .map_err(|error| format!("checkout_publication_failed:acquisition:{error}"))?;
            require_owned(&acquisition)?;
            // A refused publication must not leave the materialized tree
            // under the output root: every such build would otherwise keep a
            // whole checkout on the source volume. The receipt and manifest
            // the acquirer retained beside it stay.
            publish_tree(&acquisition, workspace, destination)?;
            Ok(PublishedCheckout {
                destination: destination.to_owned(),
                resolved_commit: receipt
                    .repository_trees
                    .first()
                    .map(|tree| tree.resolved_commit.clone())
                    .unwrap_or_default(),
                materialized_files: receipt.materialized_files,
            })
        }
    }

    /// Moves `tree` under `acquisition` into `<workspace>/<destination>`, and
    /// on any refusal or failure that leaves the tree behind discards it,
    /// keeping whatever else the acquirer retained beside it.
    fn publish_tree(
        acquisition: &OwnedFd,
        workspace: &Path,
        destination: &str,
    ) -> Result<(), String> {
        match move_verified_tree(acquisition, workspace, destination) {
            Ok(()) => Ok(()),
            Err(error) => {
                if let Err(discard) = discard_acquired_tree(acquisition) {
                    return Err(format!("{error};tree_not_discarded:{discard}"));
                }
                Err(error)
            }
        }
    }

    fn move_verified_tree(
        acquisition: &OwnedFd,
        workspace: &Path,
        destination: &str,
    ) -> Result<(), String> {
        use nix::fcntl::{OFlag, RenameFlags, openat, renameat2};
        use nix::sys::stat::{Mode, fchmod, fstatat};
        // The acquirer left its directory 0o500; renaming an entry out of it
        // needs the owner's write bit back.
        fchmod(acquisition, Mode::from_bits_truncate(0o700))
            .map_err(|error| format!("checkout_publication_failed:chmod:{error}"))?;
        // Moving a directory to a new parent rewrites its `..` entry, so the
        // tree itself needs its owner's write bit back as well; the descriptor
        // doubles as the identity the moved entry must match.
        let tree_fd = openat(
            acquisition,
            "tree",
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| format!("checkout_publication_failed:tree:{error}"))?;
        let tree = nix::sys::stat::fstat(&tree_fd)
            .map_err(|error| format!("checkout_publication_failed:tree:{error}"))?;
        fchmod(&tree_fd, Mode::from_bits_truncate(0o700))
            .map_err(|error| format!("checkout_publication_failed:chmod:{error}"))?;
        drop(tree_fd);
        let workspace_fd = open_directory(workspace)
            .map_err(|error| format!("checkout_publication_failed:workspace:{error}"))?;
        require_owned(&workspace_fd)?;
        match fstatat(
            &workspace_fd,
            destination,
            nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
        ) {
            Err(nix::errno::Errno::ENOENT) => {}
            Ok(_) => return Err(format!("checkout_destination_preexists:{destination}")),
            Err(error) => {
                return Err(format!("checkout_publication_failed:destination:{error}"));
            }
        }
        match renameat2(
            acquisition,
            "tree",
            &workspace_fd,
            destination,
            RenameFlags::RENAME_NOREPLACE,
        ) {
            Ok(()) => {}
            Err(nix::errno::Errno::EEXIST | nix::errno::Errno::ENOTEMPTY) => {
                return Err(format!("checkout_destination_substituted:{destination}"));
            }
            Err(nix::errno::Errno::EXDEV) => {
                return Err(
                    "checkout_publication_cross_device:the source output root and the workspace root must share a filesystem"
                        .to_owned(),
                );
            }
            Err(error) => return Err(format!("checkout_publication_failed:rename:{error}")),
        }
        let moved = fstatat(
            &workspace_fd,
            destination,
            nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .map_err(|error| format!("checkout_publication_failed:verify:{error}"))?;
        if moved.st_dev != tree.st_dev
            || moved.st_ino != tree.st_ino
            || moved.st_mode & nix::libc::S_IFMT != nix::libc::S_IFDIR
        {
            return Err(format!("checkout_destination_substituted:{destination}"));
        }
        let published = openat(
            &workspace_fd,
            destination,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| format!("checkout_publication_failed:open:{error}"))?;
        let mut budget = MAX_PUBLICATION_ENTRIES;
        make_owner_writable(published, &mut budget)
            .map_err(|error| format!("checkout_publication_failed:writable:{error}"))?;
        for directory in [&workspace_fd, acquisition] {
            File::from(
                nix::unistd::dup(directory)
                    .map_err(|error| format!("checkout_publication_failed:dup:{error}"))?,
            )
            .sync_all()
            .map_err(|error| format!("checkout_publication_failed:sync:{error}"))?;
        }
        Ok(())
    }

    /// Removes `tree` under `acquisition` if it is still there, by
    /// descriptor and never following a link, within the publication walk
    /// budget. Absent already means nothing to do.
    fn discard_acquired_tree(acquisition: &OwnedFd) -> Result<(), String> {
        use nix::fcntl::{OFlag, openat};
        use nix::sys::stat::{Mode, fchmod, fstatat};
        match fstatat(
            acquisition,
            "tree",
            nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
        ) {
            Err(nix::errno::Errno::ENOENT) => return Ok(()),
            Err(error) => return Err(error.to_string()),
            Ok(stat) if stat.st_mode & nix::libc::S_IFMT != nix::libc::S_IFDIR => {
                return nix::unistd::unlinkat(
                    acquisition,
                    "tree",
                    nix::unistd::UnlinkatFlags::NoRemoveDir,
                )
                .map_err(|error| error.to_string());
            }
            Ok(_) => {}
        }
        fchmod(acquisition, Mode::from_bits_truncate(0o700)).map_err(|error| error.to_string())?;
        let tree = openat(
            acquisition,
            "tree",
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| error.to_string())?;
        let mut budget = MAX_PUBLICATION_ENTRIES;
        remove_directory_contents(tree, &mut budget)?;
        nix::unistd::unlinkat(acquisition, "tree", nix::unistd::UnlinkatFlags::RemoveDir)
            .map_err(|error| error.to_string())?;
        File::from(nix::unistd::dup(acquisition).map_err(|error| error.to_string())?)
            .sync_all()
            .map_err(|error| error.to_string())
    }

    /// Empties `directory` by descriptor: subdirectories are recursed into
    /// and removed, everything else is unlinked, links included but never
    /// followed.
    fn remove_directory_contents(directory: OwnedFd, budget: &mut usize) -> Result<(), String> {
        use nix::dir::{Dir, Type};
        use nix::fcntl::{OFlag, openat};
        use nix::sys::stat::{Mode, fchmod, fstatat};
        use nix::unistd::{UnlinkatFlags, unlinkat};
        // The acquirer left directories 0o500; unlinking their entries needs
        // the owner's write bit.
        fchmod(&directory, Mode::from_bits_truncate(0o700)).map_err(|error| error.to_string())?;
        let listing = nix::unistd::dup(&directory).map_err(|error| error.to_string())?;
        let mut dir = Dir::from_fd(listing).map_err(|error| error.to_string())?;
        let mut children: Vec<(std::ffi::CString, Option<Type>)> = Vec::new();
        for entry in dir.iter() {
            let entry = entry.map_err(|error| error.to_string())?;
            let name = entry.file_name();
            if name == c"." || name == c".." {
                continue;
            }
            *budget = budget
                .checked_sub(1)
                .ok_or_else(|| "discard walk exceeded its entry budget".to_owned())?;
            children.push((name.to_owned(), entry.file_type()));
        }
        for (name, kind) in children {
            let name: &CStr = &name;
            let is_directory = match kind {
                Some(kind) => kind == Type::Directory,
                None => {
                    let stat = fstatat(&directory, name, nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW)
                        .map_err(|error| error.to_string())?;
                    stat.st_mode & nix::libc::S_IFMT == nix::libc::S_IFDIR
                }
            };
            if is_directory {
                let child = openat(
                    &directory,
                    name,
                    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|error| error.to_string())?;
                remove_directory_contents(child, budget)?;
                unlinkat(&directory, name, UnlinkatFlags::RemoveDir)
                    .map_err(|error| error.to_string())?;
            } else {
                unlinkat(&directory, name, UnlinkatFlags::NoRemoveDir)
                    .map_err(|error| error.to_string())?;
            }
        }
        let _ = directory.as_fd();
        Ok(())
    }

    fn open_directory(path: &Path) -> Result<OwnedFd, nix::errno::Errno> {
        use nix::fcntl::{OFlag, open};
        use nix::sys::stat::Mode;
        open(
            path,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
    }

    fn require_owned(fd: &OwnedFd) -> Result<(), String> {
        let stat = nix::sys::stat::fstat(fd)
            .map_err(|error| format!("checkout_publication_failed:stat:{error}"))?;
        if stat.st_uid != nix::unistd::geteuid().as_raw() {
            return Err(
                "checkout_publication_failed:directory is not owned by the agent".to_owned(),
            );
        }
        Ok(())
    }

    /// Adds the owner's write bit to every directory and regular file below
    /// `directory`, by descriptor, never following a link, within `budget`
    /// entries. Symlinks and special files are left untouched.
    fn make_owner_writable(directory: OwnedFd, budget: &mut usize) -> Result<(), String> {
        use nix::dir::{Dir, Type};
        use nix::fcntl::{OFlag, openat};
        use nix::sys::stat::{Mode, fchmod, fstat, fstatat};
        let stat = fstat(&directory).map_err(|error| error.to_string())?;
        fchmod(
            &directory,
            Mode::from_bits_truncate((stat.st_mode & 0o7777) | 0o700),
        )
        .map_err(|error| error.to_string())?;
        let listing = nix::unistd::dup(&directory).map_err(|error| error.to_string())?;
        let mut dir = Dir::from_fd(listing).map_err(|error| error.to_string())?;
        let mut children: Vec<(std::ffi::CString, Option<Type>)> = Vec::new();
        for entry in dir.iter() {
            let entry = entry.map_err(|error| error.to_string())?;
            let name = entry.file_name();
            if name == c"." || name == c".." {
                continue;
            }
            *budget = budget
                .checked_sub(1)
                .ok_or_else(|| "publication walk exceeded its entry budget".to_owned())?;
            children.push((name.to_owned(), entry.file_type()));
        }
        for (name, kind) in children {
            let name: &CStr = &name;
            let kind = match kind {
                Some(kind) => kind,
                None => {
                    let stat = fstatat(&directory, name, nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW)
                        .map_err(|error| error.to_string())?;
                    match stat.st_mode & nix::libc::S_IFMT {
                        nix::libc::S_IFDIR => Type::Directory,
                        nix::libc::S_IFREG => Type::File,
                        _ => continue,
                    }
                }
            };
            match kind {
                Type::Directory => {
                    let child = openat(
                        &directory,
                        name,
                        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(|error| error.to_string())?;
                    make_owner_writable(child, budget)?;
                }
                Type::File => {
                    let child = openat(
                        &directory,
                        name,
                        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
                        Mode::empty(),
                    )
                    .map_err(|error| error.to_string())?;
                    let stat = fstat(&child).map_err(|error| error.to_string())?;
                    if stat.st_mode & nix::libc::S_IFMT != nix::libc::S_IFREG {
                        continue;
                    }
                    fchmod(
                        &child,
                        Mode::from_bits_truncate((stat.st_mode & 0o7777) | 0o600),
                    )
                    .map_err(|error| error.to_string())?;
                }
                _ => {}
            }
        }
        let _ = directory.as_fd();
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::PermissionsExt as _;

        fn read_only_tree(root: &Path) -> PathBuf {
            let acquisition = root.join("acq");
            let tree = acquisition.join("tree");
            std::fs::create_dir_all(tree.join("src")).unwrap();
            std::fs::write(tree.join("README"), b"hello").unwrap();
            std::fs::write(tree.join("src/main.rs"), b"fn main() {}").unwrap();
            std::os::unix::fs::symlink("/etc/passwd", tree.join("link")).unwrap();
            for file in [tree.join("README"), tree.join("src/main.rs")] {
                std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o400)).unwrap();
            }
            for dir in [tree.join("src"), tree.clone(), acquisition.clone()] {
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
            }
            acquisition
        }

        /// The publication primitive with the receipt already verified: the
        /// same descriptor-relative moves and the same discard on refusal
        /// `publish` performs, so the refusals can be exercised without a
        /// sealed helper.
        fn move_tree(
            acquisition: &Path,
            workspace: &Path,
            destination: &str,
        ) -> Result<(), String> {
            let acquisition_fd = open_directory(acquisition).map_err(|e| e.to_string())?;
            publish_tree(&acquisition_fd, workspace, destination)
        }

        #[test]
        fn a_read_only_tree_lands_writable_and_links_are_never_followed() {
            let root = tempfile::tempdir().unwrap();
            let acquisition = read_only_tree(root.path());
            let workspace = root.path().join("ws");
            std::fs::create_dir(&workspace).unwrap();
            move_tree(&acquisition, &workspace, "source").unwrap();
            let published = workspace.join("source");
            assert!(!acquisition.join("tree").exists());
            assert_eq!(std::fs::read(published.join("README")).unwrap(), b"hello");
            for path in [published.join("README"), published.join("src/main.rs")] {
                let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode & 0o600, 0o600, "{}", path.display());
            }
            for path in [published.clone(), published.join("src")] {
                let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode & 0o700, 0o700, "{}", path.display());
            }
            // The link target's mode is untouched: the walk chmods by an
            // O_NOFOLLOW descriptor and skips links outright.
            let target = std::fs::metadata("/etc/passwd")
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(target & 0o777, 0o644);
            std::fs::write(published.join("src/new.rs"), b"writable").unwrap();
        }

        #[test]
        fn a_pre_created_destination_is_refused_by_name_with_nothing_written() {
            let root = tempfile::tempdir().unwrap();
            let acquisition = read_only_tree(root.path());
            let workspace = root.path().join("ws");
            std::fs::create_dir(&workspace).unwrap();
            let elsewhere = root.path().join("elsewhere");
            std::fs::create_dir(&elsewhere).unwrap();
            std::os::unix::fs::symlink(&elsewhere, workspace.join("source")).unwrap();
            std::fs::set_permissions(&acquisition, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::write(acquisition.join("receipt.json"), b"{}").unwrap();
            std::fs::set_permissions(&acquisition, std::fs::Permissions::from_mode(0o500)).unwrap();
            let error = move_tree(&acquisition, &workspace, "source").unwrap_err();
            assert_eq!(error, "checkout_destination_preexists:source");
            assert!(std::fs::read_dir(&elsewhere).unwrap().next().is_none());
            // The refused tree is discarded, links unlinked not followed, and
            // the retained receipt beside it is kept.
            assert!(!acquisition.join("tree").exists());
            assert!(acquisition.join("receipt.json").exists());
            assert!(Path::new("/etc/passwd").exists());
        }

        #[test]
        fn a_destination_that_appears_before_the_rename_is_detected_not_replaced() {
            use nix::fcntl::{RenameFlags, renameat2};
            let root = tempfile::tempdir().unwrap();
            let acquisition = read_only_tree(root.path());
            let workspace = root.path().join("ws");
            std::fs::create_dir(&workspace).unwrap();
            let acquisition_fd = open_directory(&acquisition).unwrap();
            nix::sys::stat::fchmod(
                &acquisition_fd,
                nix::sys::stat::Mode::from_bits_truncate(0o700),
            )
            .unwrap();
            std::fs::set_permissions(
                acquisition.join("tree"),
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
            let workspace_fd = open_directory(&workspace).unwrap();
            // The window between the absence check and the rename: a hostile
            // sibling drops a symlink into place.
            std::os::unix::fs::symlink("/etc", workspace.join("source")).unwrap();
            let result = renameat2(
                &acquisition_fd,
                "tree",
                &workspace_fd,
                "source",
                RenameFlags::RENAME_NOREPLACE,
            );
            assert_eq!(result, Err(nix::errno::Errno::EEXIST));
            assert!(
                std::fs::symlink_metadata(workspace.join("source"))
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
            assert!(acquisition.join("tree/README").exists());
        }
    }
}
