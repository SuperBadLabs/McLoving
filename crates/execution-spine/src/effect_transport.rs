use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use mcloving_destination_observer::{ObservationReceipt, ObservationRequest, ObserverCommand};
use mcloving_external_connector::{
    ConnectorCommand, ConnectorResponse, OutcomeReceipt, ShadowCommand, ShadowReplayReceipt,
    ShadowReplayRequest, ShadowResponse,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::process::Command;

const MAX_SERVICE_FRAME_BYTES: usize = 256 * 1024;
const MAX_SERVICE_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;

/// Deployment-selected executable identity for one independently confined
/// connector, observer, or shadow service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedServiceCommand {
    pub executable: PathBuf,
    pub executable_sha256: String,
    pub timeout: Duration,
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
    #[error("effect service protocol response is invalid")]
    InvalidResponse,
    #[error("effect service I/O failed")]
    Io(#[from] std::io::Error),
}

pub async fn invoke_connector(
    service: &PinnedServiceCommand,
    command: ConnectorCommand,
) -> Result<OutcomeReceipt, EffectServiceError> {
    match invoke::<_, ConnectorResponse>(service, &command).await? {
        ConnectorResponse::Ok { receipt } => Ok(*receipt),
        ConnectorResponse::Error { .. } => Err(EffectServiceError::ServiceFailed),
    }
}

pub async fn invoke_shadow(
    service: &PinnedServiceCommand,
    request: ShadowReplayRequest,
) -> Result<ShadowReplayReceipt, EffectServiceError> {
    let command = ShadowCommand::Replay {
        request: Box::new(request),
    };
    match invoke::<_, ShadowResponse>(service, &command).await? {
        ShadowResponse::Ok { receipt } => Ok(*receipt),
        ShadowResponse::Error { .. } => Err(EffectServiceError::ServiceFailed),
    }
}

pub async fn invoke_observer(
    service: &PinnedServiceCommand,
    request: ObservationRequest,
) -> Result<ObservationReceipt, EffectServiceError> {
    let command = ObserverCommand::Observe { request };
    let response: ObserverClientResponse = invoke(service, &command).await?;
    match response {
        ObserverClientResponse::Observed { receipt } => Ok(*receipt),
        ObserverClientResponse::Error { code, message } => {
            let _ = (code, message);
            Err(EffectServiceError::ServiceFailed)
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum ObserverClientResponse {
    Observed { receipt: Box<ObservationReceipt> },
    Error { code: String, message: String },
}

async fn invoke<T, R>(service: &PinnedServiceCommand, request: &T) -> Result<R, EffectServiceError>
where
    T: Serialize,
    R: DeserializeOwned,
{
    validate_service(service).await?;
    let mut request_bytes =
        serde_json::to_vec(request).map_err(|_| EffectServiceError::InvalidResponse)?;
    if request_bytes.len() >= MAX_SERVICE_FRAME_BYTES {
        return Err(EffectServiceError::RequestTooLarge);
    }
    request_bytes.push(b'\n');

    let mut child = Command::new(&service.executable)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| EffectServiceError::ServiceFailed)?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or(EffectServiceError::ServiceFailed)?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or(EffectServiceError::ServiceFailed)?;
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
    let (status, response) = tokio::time::timeout(service.timeout, exchange)
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

async fn validate_service(service: &PinnedServiceCommand) -> Result<(), EffectServiceError> {
    if service.timeout.is_zero()
        || !service.executable.is_absolute()
        || !is_sha256(&service.executable_sha256)
    {
        return Err(EffectServiceError::InvalidBinding);
    }
    let metadata = tokio::fs::symlink_metadata(&service.executable)
        .await
        .map_err(|_| EffectServiceError::ExecutableUnavailable)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_SERVICE_EXECUTABLE_BYTES
    {
        return Err(EffectServiceError::ExecutableUnavailable);
    }
    let canonical = tokio::fs::canonicalize(&service.executable)
        .await
        .map_err(|_| EffectServiceError::ExecutableUnavailable)?;
    if canonical != service.executable {
        return Err(EffectServiceError::InvalidBinding);
    }
    let digest = digest_file(&service.executable).await?;
    if digest != service.executable_sha256 {
        return Err(EffectServiceError::ExecutableSubstituted);
    }
    Ok(())
}

async fn digest_file(path: &Path) -> Result<String, EffectServiceError> {
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|_| EffectServiceError::ExecutableUnavailable)?;
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
    fn response_framing_is_exactly_one_bounded_json_line() {
        assert_eq!(one_json_line(b"{}\n").unwrap(), b"{}");
        for invalid in [b"".as_slice(), b"{}\n{}", b"{}\r\n"] {
            assert!(one_json_line(invalid).is_err());
        }
    }
}
