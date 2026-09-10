//! Deployment-owned cache mediation. No job supplies a path or a principal.
use std::collections::BTreeSet;
use std::fs::File;
#[cfg(unix)]
use std::io::Read;
#[cfg(target_os = "linux")]
use std::io::Write;
use std::path::{Path, PathBuf};

use mcloving_agent_runtime::executor::PrivateExecutionOutput;
use mcloving_cache::{CacheCommand, CacheConfig, CacheKeyRequest, CacheKind, Clock, SystemClock};
use mcloving_domain::cache_intent::{
    CacheIntentSpec, CacheOperation, CacheWorkContext, canonical_mapping_id, canonical_sha256,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{AgentConfig, AgentError};
const MAX_FRAME_BYTES: u64 = 262_144;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheBindings {
    pub schema_version: String,
    pub mappings: Vec<CacheBinding>,
}

/// Its canonical digest covers every authority/configuration choice below.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheBinding {
    pub mapping_id: String,
    pub organization_id: String,
    pub project_id: String,
    pub pipeline_id: String,
    pub trust_pool: String,
    pub allowed_operations: Vec<CacheOperation>,
    pub executable: PathBuf,
    pub executable_sha256: String,
    pub config_path: PathBuf,
    pub config_sha256: String,
    pub receipt_key_path: PathBuf,
    pub policy_id: String,
    pub caller_id: String,
    pub trust_class: String,
    pub cache_kind: CacheKind,
    pub toolchain_sha256: String,
    pub platform_sha256: String,
}

impl CacheBinding {
    pub fn mapping_digest(&self) -> Result<String, AgentError> {
        Ok(format!(
            "sha256:{}",
            hex(&Sha256::digest(serde_json::to_vec(self)?))
        ))
    }
}

fn denied() -> AgentError {
    AgentError::InvalidConfig("sealed cache deployment binding")
}

pub fn load_bindings(path: &Path, expected_sha256: &str) -> Result<CacheBindings, AgentError> {
    let bytes = read_private(path, MAX_FRAME_BYTES as usize, true)?;
    if !canonical_sha256(expected_sha256) || hex(&Sha256::digest(&bytes)) != expected_sha256 {
        return Err(denied());
    }
    let bindings: CacheBindings =
        mcloving_cache::parse_json_no_duplicates(&bytes).map_err(|_| denied())?;
    if bindings.schema_version != "mcloving.agent-cache-bindings/v1"
        || bindings.mappings.is_empty()
        || bindings.mappings.len() > 128
    {
        return Err(denied());
    }
    let mut ids = BTreeSet::new();
    for binding in &bindings.mappings {
        if !canonical_mapping_id(&binding.mapping_id)
            || !ids.insert(&binding.mapping_id)
            || binding.allowed_operations.is_empty()
            || binding.allowed_operations.len() > 2
            || binding
                .allowed_operations
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != binding.allowed_operations.len()
            || [
                &binding.organization_id,
                &binding.project_id,
                &binding.pipeline_id,
            ]
            .into_iter()
            .any(|id| {
                uuid::Uuid::parse_str(id)
                    .map_or(true, |value| value.is_nil() || value.to_string() != *id)
            })
            || [
                &binding.executable_sha256,
                &binding.config_sha256,
                &binding.toolchain_sha256,
                &binding.platform_sha256,
            ]
            .into_iter()
            .any(|value| !canonical_sha256(value))
            || [
                &binding.trust_pool,
                &binding.policy_id,
                &binding.caller_id,
                &binding.trust_class,
            ]
            .into_iter()
            .any(|value| value.is_empty() || value.len() > 256 || value.trim() != value.as_str())
            || [
                &binding.executable,
                &binding.config_path,
                &binding.receipt_key_path,
            ]
            .into_iter()
            .any(|path| !path.is_absolute())
        {
            return Err(denied());
        }
    }
    Ok(bindings)
}

#[cfg(unix)]
fn read_private(path: &Path, maximum: usize, immutable: bool) -> Result<Vec<u8>, AgentError> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    if !path.is_absolute() || path.canonicalize().map_err(|_| denied())? != path {
        return Err(denied());
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| denied())?;
    let metadata = file.metadata().map_err(|_| denied())?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || (immutable && metadata.mode() & 0o777 != 0o400)
        || metadata.len() > maximum as u64
    {
        return Err(denied());
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| denied())?;
    if bytes.len() > maximum {
        return Err(denied());
    }
    Ok(bytes)
}
#[cfg(not(unix))]
fn read_private(_: &Path, _: usize, _: bool) -> Result<Vec<u8>, AgentError> {
    Err(denied())
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct PreparedCache {
    // Hold the immutable executable through process spawn and containment.
    _executable: File,
    pub program: PathBuf,
    pub arguments: Vec<std::ffi::OsString>,
    pub request: Vec<u8>,
    pub output_limit: u64,
    config: CacheConfig,
    receipt_key: Vec<u8>,
    key: CacheKeyRequest,
    publication: Option<Vec<u8>>,
    binding: CacheBinding,
    invocation_id: String,
    started_at_ms: i64,
}

pub(crate) fn prepare(
    config: &AgentConfig,
    intent: &CacheIntentSpec,
    context: &CacheWorkContext,
    payload_digest: &[u8; 32],
) -> Result<PreparedCache, AgentError> {
    intent.validate().map_err(|_| denied())?;
    context.validate().map_err(|_| denied())?;
    let binding = config
        .cache_bindings
        .as_ref()
        .and_then(|catalog| {
            catalog
                .mappings
                .iter()
                .find(|entry| entry.mapping_id == intent.mapping_id)
        })
        .ok_or_else(denied)?;
    if binding.mapping_digest()? != intent.mapping_digest
        || binding.organization_id != context.organization_id
        || binding.project_id != context.project_id
        || binding.pipeline_id != context.pipeline_id
        || binding.trust_pool != config.trust_pool
        || !binding.allowed_operations.contains(&intent.operation)
    {
        return Err(denied());
    }
    let cache_config = mcloving_cache::load_config(&binding.config_path).map_err(|_| denied())?;
    if mcloving_cache::configuration_sha256(&cache_config).map_err(|_| denied())?
        != binding.config_sha256
        || cache_config.implementation_sha256 != binding.executable_sha256
        || cache_config.max_frame_bytes == 0
        || cache_config.max_frame_bytes > MAX_FRAME_BYTES
        || binding.caller_id == cache_config.operator_identity
    {
        return Err(denied());
    }
    let receipt_key = read_private(&binding.receipt_key_path, 4096, false)?;
    if receipt_key.len() < 32
        || hex(&Sha256::digest(&receipt_key)) != cache_config.receipt_key_sha256
    {
        return Err(denied());
    }
    let key = CacheKeyRequest {
        policy_id: binding.policy_id.clone(),
        tenant_id: context.organization_id.clone(),
        project_id: context.project_id.clone(),
        pipeline_id: context.pipeline_id.clone(),
        trust_class: binding.trust_class.clone(),
        cache_kind: binding.cache_kind,
        generation_sha256: mcloving_cache::derive_generation_sha256(&cache_config)
            .map_err(|_| denied())?,
        restore_epoch: cache_config.restore_epoch,
        logical_key_sha256: intent.logical_key_sha256.clone(),
        input_sha256: intent.input_sha256.clone(),
        toolchain_sha256: binding.toolchain_sha256.clone(),
        platform_sha256: binding.platform_sha256.clone(),
    };
    let publication = intent.decoded_content().map_err(|_| denied())?;
    mcloving_cache::validate_operation_request(
        &cache_config,
        &binding.caller_id,
        &binding.trust_class,
        &key,
        publication.is_some(),
    )
    .map_err(|_| denied())?;
    let command = match &intent.content_base64 {
        Some(content) => CacheCommand::Publish {
            caller_id: binding.caller_id.clone(),
            caller_trust_class: binding.trust_class.clone(),
            key: key.clone(),
            content_base64: content.clone(),
        },
        None => CacheCommand::Read {
            caller_id: binding.caller_id.clone(),
            caller_trust_class: binding.trust_class.clone(),
            key: key.clone(),
        },
    };
    let mut request = serde_json::to_vec(&command)?;
    request.push(b'\n');
    if request.len() as u64 > cache_config.max_frame_bytes {
        return Err(denied());
    }
    let (executable, program) = seal_executable(&binding.executable, &binding.executable_sha256)?;
    let arguments = vec![
        "--config".into(),
        binding.config_path.as_os_str().into(),
        "--receipt-key".into(),
        binding.receipt_key_path.as_os_str().into(),
        "--expected-config-sha256".into(),
        binding.config_sha256.clone().into(),
    ];
    Ok(PreparedCache {
        _executable: executable,
        program,
        arguments,
        request,
        output_limit: cache_config.max_frame_bytes,
        config: cache_config,
        receipt_key,
        key,
        publication,
        binding: binding.clone(),
        invocation_id: format!("sha256:{}", hex(payload_digest)),
        started_at_ms: SystemClock.now_unix_ms().map_err(|_| denied())?,
    })
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl PreparedCache {
    pub fn transform(&self, stdout: &[u8], stderr: &[u8]) -> PrivateExecutionOutput {
        let verified = if stderr.is_empty() {
            SystemClock.now_unix_ms().and_then(|now| {
                mcloving_cache::verify_operation_response(
                    &self.config,
                    &self.receipt_key,
                    &self.binding.caller_id,
                    &self.binding.trust_class,
                    &self.key,
                    self.publication.as_deref(),
                    stdout,
                    self.started_at_ms,
                    now,
                )
            })
        } else {
            Err(mcloving_cache::CacheError::MalformedProtocol)
        };
        let (outcome, event, accepted) = match verified {
            Ok(value) => (value.outcome, Some(value.event_sha256), value.succeeded),
            Err(_) => ("response_rejected", None, false),
        };
        let mut public = serde_json::to_vec(&serde_json::json!({
            "protocol": "mcloving.cache-invocation/v1", "invocation_id": self.invocation_id,
            "mapping_id": self.binding.mapping_id, "outcome": outcome, "event_sha256": event,
        }))
        .unwrap_or_default();
        public.push(b'\n');
        PrivateExecutionOutput {
            stdout: public,
            accepted,
        }
    }
}

#[cfg(target_os = "linux")]
fn seal_executable(path: &Path, expected: &str) -> Result<(File, PathBuf), AgentError> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    if !path.is_absolute() || path.canonicalize().map_err(|_| denied())? != path {
        return Err(denied());
    }
    let input = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| denied())?;
    let metadata = input.metadata().map_err(|_| denied())?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 512 * 1024 * 1024 {
        return Err(denied());
    }
    let fd = nix::sys::memfd::memfd_create(
        "mcloving-sealed-cache",
        nix::sys::memfd::MFdFlags::MFD_CLOEXEC | nix::sys::memfd::MFdFlags::MFD_ALLOW_SEALING,
    )
    .map_err(|_| denied())?;
    let mut file = File::from(fd);
    let mut digest = Sha256::new();
    let mut input = input.take(512 * 1024 * 1024 + 1);
    let mut copied = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let count = input.read(&mut buffer).map_err(|_| denied())?;
        if count == 0 {
            break;
        }
        copied += count as u64;
        if copied > metadata.len() {
            return Err(denied());
        }
        digest.update(&buffer[..count]);
        file.write_all(&buffer[..count]).map_err(|_| denied())?;
    }
    if copied != metadata.len() || hex(&digest.finalize()) != expected {
        return Err(denied());
    }
    nix::fcntl::fcntl(
        &file,
        nix::fcntl::FcntlArg::F_ADD_SEALS(
            nix::fcntl::SealFlag::F_SEAL_WRITE
                | nix::fcntl::SealFlag::F_SEAL_GROW
                | nix::fcntl::SealFlag::F_SEAL_SHRINK
                | nix::fcntl::SealFlag::F_SEAL_SEAL,
        ),
    )
    .map_err(|_| denied())?;
    nix::fcntl::fcntl(
        &file,
        nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
    )
    .map_err(|_| denied())?;
    let program = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
    Ok((file, program))
}
#[cfg(not(target_os = "linux"))]
fn seal_executable(_: &Path, _: &str) -> Result<(File, PathBuf), AgentError> {
    Err(denied())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::time::Duration;
    #[test]
    fn fifo_binding_config_and_executable_are_refused_without_waiting_for_a_writer() {
        let root = tempfile::tempdir().unwrap();
        let fifo = root.path().join("special");
        nix::unistd::mkfifo(
            &fifo,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let probe = fifo.clone();
        std::thread::spawn(move || {
            sender
                .send((
                    read_private(&probe, 1024, false).is_err(),
                    seal_executable(&probe, &"a".repeat(64)).is_err(),
                    mcloving_cache::load_config(&probe).is_err(),
                ))
                .unwrap();
        });
        assert_eq!(
            receiver.recv_timeout(Duration::from_secs(1)).unwrap(),
            (true, true, true)
        );
    }
    #[test]
    fn prepared_sealed_executable_survives_original_path_substitution() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("program");
        let bytes = std::fs::read("/bin/echo").unwrap();
        std::fs::write(&path, &bytes).unwrap();
        let (_sealed, program) = seal_executable(&path, &hex(&Sha256::digest(&bytes))).unwrap();
        std::fs::write(&path, b"substituted executable").unwrap();
        let output = std::process::Command::new(program)
            .arg("original-pinned-bytes")
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"original-pinned-bytes\n");
        assert!(seal_executable(&path, &hex(&Sha256::digest(&bytes))).is_err());
    }
}
