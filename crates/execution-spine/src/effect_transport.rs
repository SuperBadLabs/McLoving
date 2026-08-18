use std::path::PathBuf;
use std::process::Stdio;

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd as _;

use mcloving_destination_observer::{
    ObservationReceipt, ObservationRequest, ObserverCommand, observation_request_digest,
};
use mcloving_external_connector::{
    ConnectorCommand, ConnectorResponse, OutcomeReceipt, ShadowCommand, ShadowReplayReceipt,
    ShadowReplayRequest, ShadowResponse,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};
use tokio::process::Command;

const MAX_SERVICE_FRAME_BYTES: usize = 256 * 1024;
const MAX_SERVICE_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;

/// Deployment-selected executable identity for one independently confined
/// connector, observer, or shadow service.
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedServiceCommand {
    pub executable: PathBuf,
    pub executable_sha256: String,
    pub arguments: Vec<PathBuf>,
    pub timeout_millis: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum EffectServiceError {
    #[error("effect service deployment binding is invalid")]
    InvalidBinding,
    #[error("effect service executable cannot be read")]
    ExecutableUnavailable,
    #[error("effect service executable digest does not match the frozen deployment")]
    ExecutableSubstituted,
    #[error("effect service request exceeds the protocol limit")]
    RequestTooLarge,
    #[error("effect service response exceeds the protocol limit")]
    ResponseTooLarge,
    #[error("effect service timed out after possible dispatch")]
    AmbiguousTimeout,
    #[error("effect service process failed")]
    ServiceFailed,
    #[error("destination observer definitively rejected verification: {0}")]
    ObserverRejected(String),
    #[error("effect service could not be spawned before request dispatch")]
    SpawnFailed,
    #[error("effect service protocol response is invalid")]
    InvalidResponse,
    #[error("effect service I/O failed")]
    Io(#[from] std::io::Error),
}

pub async fn invoke_connector(
    service: &PinnedServiceCommand,
    command: ConnectorCommand,
) -> Result<OutcomeReceipt, EffectServiceError> {
    let service = validate_service_command(service).await?;
    invoke_validated_connector(&service, command).await
}

async fn invoke_validated_connector(
    service: &ValidatedServiceCommand,
    command: ConnectorCommand,
) -> Result<OutcomeReceipt, EffectServiceError> {
    match invoke_validated::<_, ConnectorResponse>(service, &command).await? {
        ConnectorResponse::Ok { receipt } => Ok(*receipt),
        ConnectorResponse::Error { .. } => Err(EffectServiceError::ServiceFailed),
    }
}

pub async fn invoke_shadow(
    service: &PinnedServiceCommand,
    request: ShadowReplayRequest,
) -> Result<ShadowReplayReceipt, EffectServiceError> {
    let service = validate_service_command(service).await?;
    invoke_validated_shadow(&service, request).await
}

async fn invoke_validated_shadow(
    service: &ValidatedServiceCommand,
    request: ShadowReplayRequest,
) -> Result<ShadowReplayReceipt, EffectServiceError> {
    let command = ShadowCommand::Replay {
        request: Box::new(request),
    };
    match invoke_validated::<_, ShadowResponse>(service, &command).await? {
        ShadowResponse::Ok { receipt } => Ok(*receipt),
        ShadowResponse::Error { .. } => Err(EffectServiceError::ServiceFailed),
    }
}

pub async fn invoke_observer(
    service: &PinnedServiceCommand,
    request: ObservationRequest,
) -> Result<ObservationReceipt, EffectServiceError> {
    let service = validate_service_command(service).await?;
    invoke_validated_observer(&service, request).await
}

async fn invoke_validated_observer(
    service: &ValidatedServiceCommand,
    request: ObservationRequest,
) -> Result<ObservationReceipt, EffectServiceError> {
    let command = ObserverCommand::Observe { request };
    let response: ObserverClientResponse = invoke_validated(service, &command).await?;
    match response {
        ObserverClientResponse::Observed { receipt } => Ok(*receipt),
        ObserverClientResponse::Verified { .. } => Err(EffectServiceError::InvalidResponse),
        ObserverClientResponse::Released { .. } => Err(EffectServiceError::InvalidResponse),
        ObserverClientResponse::Error { code, message } => {
            let _ = (code, message);
            Err(EffectServiceError::ServiceFailed)
        }
    }
}

pub(crate) struct ValidatedEffectServices {
    connector: ValidatedServiceCommand,
    observer: tokio::sync::Mutex<ValidatedObserverSession>,
    observer_timeout_millis: u64,
    shadow: ValidatedServiceCommand,
}

impl ValidatedEffectServices {
    pub(crate) async fn verify_observer_request(
        &self,
        request: ObservationRequest,
    ) -> Result<(), EffectServiceError> {
        let expected = observation_request_digest(&request)
            .map_err(|_| EffectServiceError::InvalidResponse)?;
        let required_validity_ms = self
            .connector
            .command
            .timeout_millis
            .checked_add(self.observer_timeout_millis)
            .ok_or(EffectServiceError::InvalidBinding)?;
        let command = ObserverCommand::Verify {
            request,
            required_validity_ms,
        };
        let mut observer = self.observer.lock().await;
        match observer
            .invoke::<_, ObserverClientResponse>(&command)
            .await?
        {
            ObserverClientResponse::Verified { request_sha256 } if request_sha256 == expected => {
                Ok(())
            }
            ObserverClientResponse::Verified { .. } => Err(EffectServiceError::InvalidResponse),
            ObserverClientResponse::Observed { .. } => Err(EffectServiceError::InvalidResponse),
            ObserverClientResponse::Released { .. } => Err(EffectServiceError::InvalidResponse),
            ObserverClientResponse::Error { code, message } => {
                let _ = message;
                if observer_verify_rejection_is_definitive(&code) {
                    Err(EffectServiceError::ObserverRejected(code))
                } else {
                    Err(EffectServiceError::ServiceFailed)
                }
            }
        }
    }

    pub(crate) async fn release_observer_request(
        &self,
        request: ObservationRequest,
    ) -> Result<(), EffectServiceError> {
        let expected = observation_request_digest(&request)
            .map_err(|_| EffectServiceError::InvalidResponse)?;
        let command = ObserverCommand::Release { request };
        let mut observer = self.observer.lock().await;
        match observer
            .invoke::<_, ObserverClientResponse>(&command)
            .await?
        {
            ObserverClientResponse::Released { request_sha256 } if request_sha256 == expected => {
                Ok(())
            }
            ObserverClientResponse::Released { .. }
            | ObserverClientResponse::Verified { .. }
            | ObserverClientResponse::Observed { .. } => Err(EffectServiceError::InvalidResponse),
            ObserverClientResponse::Error { code, message } => {
                let _ = (code, message);
                Err(EffectServiceError::ServiceFailed)
            }
        }
    }

    pub(crate) async fn invoke_connector(
        &self,
        command: ConnectorCommand,
    ) -> Result<OutcomeReceipt, EffectServiceError> {
        invoke_validated_connector(&self.connector, command).await
    }

    pub(crate) async fn invoke_observer(
        &self,
        request: ObservationRequest,
    ) -> Result<ObservationReceipt, EffectServiceError> {
        let command = ObserverCommand::Observe { request };
        let mut observer = self.observer.lock().await;
        match observer
            .invoke::<_, ObserverClientResponse>(&command)
            .await?
        {
            ObserverClientResponse::Observed { receipt } => Ok(*receipt),
            ObserverClientResponse::Verified { .. } | ObserverClientResponse::Released { .. } => {
                Err(EffectServiceError::InvalidResponse)
            }
            ObserverClientResponse::Error { code, message } => {
                let _ = (code, message);
                Err(EffectServiceError::ServiceFailed)
            }
        }
    }

    pub(crate) async fn invoke_shadow(
        &self,
        request: ShadowReplayRequest,
    ) -> Result<ShadowReplayReceipt, EffectServiceError> {
        invoke_validated_shadow(&self.shadow, request).await
    }
}

fn observer_verify_rejection_is_definitive(code: &str) -> bool {
    matches!(
        code,
        "invalid_config"
            | "malformed_request"
            | "oversized_request"
            | "unauthorized_request"
            | "binding_mismatch"
            | "expired_request"
            | "expired_grant"
            | "runtime_fenced"
            | "replay_mismatch"
            | "observation_pending"
            | "phase_mismatch"
            | "capacity_exceeded"
            | "invalid_receipt"
    )
}

pub(crate) async fn preflight_effect_services(
    connector: &PinnedServiceCommand,
    observer: &PinnedServiceCommand,
    shadow: &PinnedServiceCommand,
) -> Result<ValidatedEffectServices, EffectServiceError> {
    let observer = validate_service_command(observer).await?;
    let observer_timeout_millis = observer.command.timeout_millis;
    Ok(ValidatedEffectServices {
        connector: validate_service_command(connector).await?,
        observer: tokio::sync::Mutex::new(ValidatedObserverSession::spawn(observer)?),
        observer_timeout_millis,
        shadow: validate_service_command(shadow).await?,
    })
}

struct ValidatedObserverSession {
    _binding: ValidatedServiceCommand,
    _child: tokio::process::Child,
    stdin: tokio::process::ChildStdin,
    stdout: tokio::process::ChildStdout,
    timeout_millis: u64,
}

impl ValidatedObserverSession {
    fn spawn(binding: ValidatedServiceCommand) -> Result<Self, EffectServiceError> {
        let mut child = Command::new(binding.executable.program());
        child
            .args(&binding.command.arguments)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut child = child.spawn().map_err(|_| EffectServiceError::SpawnFailed)?;
        let stdin = child.stdin.take().ok_or(EffectServiceError::SpawnFailed)?;
        let stdout = child.stdout.take().ok_or(EffectServiceError::SpawnFailed)?;
        let timeout_millis = binding.command.timeout_millis;
        Ok(Self {
            _binding: binding,
            _child: child,
            stdin,
            stdout,
            timeout_millis,
        })
    }

    async fn invoke<T, R>(&mut self, request: &T) -> Result<R, EffectServiceError>
    where
        T: Serialize,
        R: DeserializeOwned,
    {
        let mut request_bytes =
            serde_json::to_vec(request).map_err(|_| EffectServiceError::InvalidResponse)?;
        if request_bytes.len() >= MAX_SERVICE_FRAME_BYTES {
            return Err(EffectServiceError::RequestTooLarge);
        }
        request_bytes.push(b'\n');
        let exchange = async {
            self.stdin.write_all(&request_bytes).await?;
            self.stdin.flush().await?;
            let mut response = Vec::new();
            loop {
                let mut byte = [0_u8; 1];
                let read = self.stdout.read(&mut byte).await?;
                if read == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "observer session closed before its response",
                    ));
                }
                response.push(byte[0]);
                if response.len() > MAX_SERVICE_FRAME_BYTES || byte[0] == b'\n' {
                    break;
                }
            }
            Ok::<_, std::io::Error>(response)
        };
        let response = tokio::time::timeout(
            std::time::Duration::from_millis(self.timeout_millis),
            exchange,
        )
        .await
        .map_err(|_| EffectServiceError::AmbiguousTimeout)??;
        if response.len() > MAX_SERVICE_FRAME_BYTES {
            return Err(EffectServiceError::ResponseTooLarge);
        }
        let response = one_json_line(&response)?;
        let value: Value = mcloving_external_connector::parse_json_no_duplicates(response)
            .map_err(|_| EffectServiceError::InvalidResponse)?;
        serde_json::from_value(value).map_err(|_| EffectServiceError::InvalidResponse)
    }
}

#[derive(serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum ObserverClientResponse {
    Verified { request_sha256: String },
    Observed { receipt: Box<ObservationReceipt> },
    Released { request_sha256: String },
    Error { code: String, message: String },
}

async fn invoke_validated<T, R>(
    service: &ValidatedServiceCommand,
    request: &T,
) -> Result<R, EffectServiceError>
where
    T: Serialize,
    R: DeserializeOwned,
{
    let mut request_bytes =
        serde_json::to_vec(request).map_err(|_| EffectServiceError::InvalidResponse)?;
    if request_bytes.len() >= MAX_SERVICE_FRAME_BYTES {
        return Err(EffectServiceError::RequestTooLarge);
    }
    request_bytes.push(b'\n');

    let mut child = Command::new(service.executable.program());
    child
        .args(&service.command.arguments)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = child.spawn().map_err(|_| EffectServiceError::SpawnFailed)?;
    let mut stdin = child.stdin.take().ok_or(EffectServiceError::SpawnFailed)?;
    let mut stdout = child.stdout.take().ok_or(EffectServiceError::SpawnFailed)?;
    let exchange = async {
        stdin.write_all(&request_bytes).await?;
        stdin.shutdown().await?;
        drop(stdin);
        let mut response = Vec::new();
        (&mut stdout)
            .take((MAX_SERVICE_FRAME_BYTES + 1) as u64)
            .read_to_end(&mut response)
            .await?;
        let status = child.wait().await?;
        Ok::<_, std::io::Error>((status, response))
    };
    let (status, response) = tokio::time::timeout(
        std::time::Duration::from_millis(service.command.timeout_millis),
        exchange,
    )
    .await
    .map_err(|_| EffectServiceError::AmbiguousTimeout)??;
    if !status.success() {
        return Err(EffectServiceError::ServiceFailed);
    }
    if response.len() > MAX_SERVICE_FRAME_BYTES {
        return Err(EffectServiceError::ResponseTooLarge);
    }
    let response = one_json_line(&response)?;
    let value: Value = mcloving_external_connector::parse_json_no_duplicates(response)
        .map_err(|_| EffectServiceError::InvalidResponse)?;
    serde_json::from_value(value).map_err(|_| EffectServiceError::InvalidResponse)
}

struct ValidatedServiceCommand {
    command: PinnedServiceCommand,
    executable: ValidatedServiceExecutable,
}

async fn validate_service_command(
    service: &PinnedServiceCommand,
) -> Result<ValidatedServiceCommand, EffectServiceError> {
    Ok(ValidatedServiceCommand {
        command: service.clone(),
        executable: validate_service(service).await?,
    })
}

#[cfg(target_os = "linux")]
struct ValidatedServiceExecutable {
    file: std::fs::File,
}

#[cfg(target_os = "linux")]
impl ValidatedServiceExecutable {
    fn program(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
    }
}

#[cfg(not(target_os = "linux"))]
struct ValidatedServiceExecutable;

#[cfg(not(target_os = "linux"))]
impl ValidatedServiceExecutable {
    fn program(&self) -> PathBuf {
        unreachable!("effect services fail closed outside the pinned Linux profile")
    }
}

async fn validate_service(
    service: &PinnedServiceCommand,
) -> Result<ValidatedServiceExecutable, EffectServiceError> {
    if service.timeout_millis == 0
        || !service.executable.is_absolute()
        || !is_sha256(&service.executable_sha256)
        || service.arguments.len() > 16
        || service.arguments.iter().any(|path| !path.is_absolute())
    {
        return Err(EffectServiceError::InvalidBinding);
    }

    #[cfg(not(target_os = "linux"))]
    return Err(EffectServiceError::InvalidBinding);

    #[cfg(target_os = "linux")]
    let descriptor = nix::fcntl::open(
        &service.executable,
        nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )
    .map_err(|_| EffectServiceError::ExecutableUnavailable)?;
    #[cfg(target_os = "linux")]
    let mut file = tokio::fs::File::from_std(std::fs::File::from(descriptor));
    #[cfg(target_os = "linux")]
    let metadata = file
        .metadata()
        .await
        .map_err(|_| EffectServiceError::ExecutableUnavailable)?;
    #[cfg(target_os = "linux")]
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_SERVICE_EXECUTABLE_BYTES
    {
        return Err(EffectServiceError::ExecutableUnavailable);
    }
    #[cfg(target_os = "linux")]
    let canonical = tokio::fs::canonicalize(&service.executable)
        .await
        .map_err(|_| EffectServiceError::ExecutableUnavailable)?;
    #[cfg(target_os = "linux")]
    if canonical != service.executable {
        return Err(EffectServiceError::InvalidBinding);
    }
    #[cfg(target_os = "linux")]
    let sealed_descriptor = nix::sys::memfd::memfd_create(
        "mcloving-effect-service",
        nix::sys::memfd::MFdFlags::MFD_CLOEXEC | nix::sys::memfd::MFdFlags::MFD_ALLOW_SEALING,
    )
    .map_err(|_| EffectServiceError::ExecutableUnavailable)?;
    #[cfg(target_os = "linux")]
    let mut sealed = tokio::fs::File::from_std(std::fs::File::from(sealed_descriptor));
    #[cfg(target_os = "linux")]
    let copied = tokio::io::copy(&mut file, &mut sealed)
        .await
        .map_err(|_| EffectServiceError::ExecutableUnavailable)?;
    #[cfg(target_os = "linux")]
    if copied != metadata.len() {
        return Err(EffectServiceError::ExecutableSubstituted);
    }
    #[cfg(target_os = "linux")]
    sealed
        .flush()
        .await
        .map_err(|_| EffectServiceError::ExecutableUnavailable)?;
    #[cfg(target_os = "linux")]
    let sealed = sealed.into_std().await;
    #[cfg(target_os = "linux")]
    nix::fcntl::fcntl(
        &sealed,
        nix::fcntl::FcntlArg::F_ADD_SEALS(
            nix::fcntl::SealFlag::F_SEAL_WRITE
                | nix::fcntl::SealFlag::F_SEAL_GROW
                | nix::fcntl::SealFlag::F_SEAL_SHRINK
                | nix::fcntl::SealFlag::F_SEAL_SEAL,
        ),
    )
    .map_err(|_| EffectServiceError::ExecutableUnavailable)?;
    #[cfg(target_os = "linux")]
    let mut sealed = tokio::fs::File::from_std(sealed);
    #[cfg(target_os = "linux")]
    sealed
        .seek(std::io::SeekFrom::Start(0))
        .await
        .map_err(|_| EffectServiceError::ExecutableUnavailable)?;
    #[cfg(target_os = "linux")]
    let digest = digest_file(&mut sealed).await?;
    #[cfg(target_os = "linux")]
    if digest != service.executable_sha256 {
        return Err(EffectServiceError::ExecutableSubstituted);
    }
    #[cfg(target_os = "linux")]
    let file = sealed.into_std().await;
    #[cfg(target_os = "linux")]
    nix::fcntl::fcntl(
        &file,
        nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
    )
    .map_err(|_| EffectServiceError::ExecutableUnavailable)?;
    #[cfg(target_os = "linux")]
    return Ok(ValidatedServiceExecutable { file });
}

async fn digest_file(file: &mut tokio::fs::File) -> Result<String, EffectServiceError> {
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .await
            .map_err(|_| EffectServiceError::ExecutableUnavailable)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn one_json_line(bytes: &[u8]) -> Result<&[u8], EffectServiceError> {
    let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    if bytes.is_empty() || bytes.contains(&b'\n') || bytes.contains(&b'\r') {
        return Err(EffectServiceError::InvalidResponse);
    }
    Ok(bytes)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observer_verify_rejections_distinguish_acknowledged_denials_from_ambiguity() {
        for code in [
            "malformed_request",
            "unauthorized_request",
            "binding_mismatch",
            "expired_request",
            "capacity_exceeded",
        ] {
            assert!(observer_verify_rejection_is_definitive(code), "{code}");
        }
        for code in ["state_unavailable", "destination_unavailable", "unknown"] {
            assert!(!observer_verify_rejection_is_definitive(code), "{code}");
        }
    }

    #[test]
    fn response_framing_is_exactly_one_bounded_json_line() {
        assert_eq!(one_json_line(b"{}\n").unwrap(), b"{}");
        for invalid in [b"".as_slice(), b"{}\n{}", b"{}\r\n"] {
            assert!(one_json_line(invalid).is_err());
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn sealed_executable_survives_same_inode_mutation_and_path_replacement() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().expect("temporary executable root");
        let service_path = root.path().join("service");
        let replacement_path = root.path().join("replacement");
        let printf = if std::path::Path::new("/usr/bin/printf").is_file() {
            "/usr/bin/printf"
        } else {
            "/bin/printf"
        };
        let false_program = if std::path::Path::new("/usr/bin/false").is_file() {
            "/usr/bin/false"
        } else {
            "/bin/false"
        };
        std::fs::copy(printf, &service_path).expect("copy original executable");
        std::fs::set_permissions(&service_path, std::fs::Permissions::from_mode(0o700))
            .expect("set executable mode");
        let executable_sha256 =
            Sha256::digest(std::fs::read(&service_path).expect("read original executable"))
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
        let service = PinnedServiceCommand {
            executable: service_path.clone(),
            executable_sha256,
            arguments: Vec::new(),
            timeout_millis: 1_000,
        };
        let verified = validate_service(&service)
            .await
            .expect("verify and seal executable bytes");

        std::fs::copy(false_program, &service_path).expect("mutate verified source inode");

        std::fs::copy(false_program, &replacement_path).expect("copy substituted executable");
        std::fs::set_permissions(&replacement_path, std::fs::Permissions::from_mode(0o700))
            .expect("set replacement mode");
        std::fs::rename(&replacement_path, &service_path).expect("replace executable path");

        let output = std::process::Command::new(verified.program())
            .arg("verified-inode")
            .output()
            .expect("execute retained inode");
        assert!(output.status.success());
        assert_eq!(output.stdout, b"verified-inode");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn invalid_executable_format_is_a_pre_dispatch_spawn_failure() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().expect("temporary executable root");
        let service_path = root.path().join("invalid-service");
        std::fs::write(&service_path, b"not-an-executable-format")
            .expect("write invalid executable");
        std::fs::set_permissions(&service_path, std::fs::Permissions::from_mode(0o700))
            .expect("set executable mode");
        let executable_sha256 =
            Sha256::digest(std::fs::read(&service_path).expect("read invalid executable"))
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
        let service = validate_service_command(&PinnedServiceCommand {
            executable: service_path,
            executable_sha256,
            arguments: Vec::new(),
            timeout_millis: 1_000,
        })
        .await
        .expect("seal invalid executable bytes");

        let result =
            invoke_validated::<_, Value>(&service, &serde_json::json!({"test": true})).await;
        assert!(matches!(result, Err(EffectServiceError::SpawnFailed)));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn persistent_observer_session_pins_loaded_inputs_across_requests() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().expect("temporary observer root");
        let service_path = root.path().join("observer-service");
        let input_path = root.path().join("observer-authority");
        let replacement_path = root.path().join("replacement-authority");
        std::fs::write(
            &service_path,
            b"#!/bin/sh\nIFS= read -r pinned < \"$1\" || exit 2\nwhile IFS= read -r request; do\n  printf '{\"pinned\":\"%s\"}\\n' \"$pinned\"\ndone\n",
        )
        .expect("write observer fixture");
        std::fs::set_permissions(&service_path, std::fs::Permissions::from_mode(0o700))
            .expect("make observer fixture executable");
        std::fs::write(&input_path, b"verified-input\n").expect("write verified authority");
        std::fs::set_permissions(&input_path, std::fs::Permissions::from_mode(0o600))
            .expect("protect verified authority");
        let executable_sha256 =
            Sha256::digest(std::fs::read(&service_path).expect("read observer fixture"))
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
        let binding = validate_service_command(&PinnedServiceCommand {
            executable: service_path,
            executable_sha256,
            arguments: vec![input_path.clone()],
            timeout_millis: 1_000,
        })
        .await
        .expect("seal observer fixture");
        let mut observer = ValidatedObserverSession::spawn(binding).expect("start observer once");
        let first: Value = observer
            .invoke(&serde_json::json!({"operation": "verify"}))
            .await
            .expect("first observer response");
        assert_eq!(first["pinned"], "verified-input");

        std::fs::write(&replacement_path, b"substituted-input\n")
            .expect("write substituted authority");
        std::fs::rename(&replacement_path, &input_path).expect("replace observer authority path");
        let second: Value = observer
            .invoke(&serde_json::json!({"operation": "observe"}))
            .await
            .expect("second observer response");
        assert_eq!(
            second["pinned"], "verified-input",
            "post-action observation must remain in the process that loaded verified inputs"
        );
    }
}
