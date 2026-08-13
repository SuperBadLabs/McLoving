use std::io::ErrorKind;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};

use crate::{
    ActionRequest, ConnectorConfig, ConnectorError, ExternalConnector, OutcomeReceipt,
    RUNTIME_IMAGE_ATTESTATION_SCHEMA_VERSION, ReconcileRequest, RuntimeImageAttestation,
    ShadowReplayConfig, ShadowReplayReceipt, ShadowReplayRequest, ShadowReplayer,
    parse_json_no_duplicates, read_private_bounded_regular_file,
    verify_runtime_image_attestation_signature,
};

pub const MAX_FRAME_BYTES: usize = 256 * 1024;
const MAX_CONFIG_BYTES: usize = 128 * 1024;
const MAX_KEY_BYTES: usize = 16 * 1024;
const MAX_TOKEN_BYTES: usize = 64 * 1024;
const MAX_MARKER_BYTES: usize = 256 * 1024;
const MAX_RUNTIME_ATTESTATION_BYTES: usize = 16 * 1024;
const MAX_RUNTIME_ATTESTATION_WINDOW_MS: i64 = 5 * 60 * 1_000;
#[cfg(any(target_os = "linux", test))]
const SHADOW_APPARMOR_LABEL: &str = "mcloving-external-shadow-replay (enforce)";

/// Refuse to load shadow replay authority unless the live process is confined by the exact
/// enforcing AppArmor profile certified for the no-network replay boundary.
pub fn require_shadow_apparmor_enforcement() -> Result<(), ConnectorError> {
    #[cfg(target_os = "linux")]
    {
        let label = std::fs::read_to_string("/proc/self/attr/current")
            .map_err(|_| ConnectorError::StateUnavailable)?;
        if !shadow_apparmor_label_is_enforcing(&label) {
            return Err(ConnectorError::StateUnavailable);
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(ConnectorError::StateUnavailable)
    }
}

#[cfg(any(target_os = "linux", test))]
fn shadow_apparmor_label_is_enforcing(label: &str) -> bool {
    label.trim_end_matches(['\r', '\n']) == SHADOW_APPARMOR_LABEL
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConnectorCommand {
    Execute { request: Box<ActionRequest> },
    Reconcile { request: Box<ReconcileRequest> },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConnectorResponse {
    Ok { receipt: Box<OutcomeReceipt> },
    Error { code: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum ShadowCommand {
    Replay { request: Box<ShadowReplayRequest> },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ShadowResponse {
    Ok { receipt: Box<ShadowReplayReceipt> },
    Error { code: String },
}

#[allow(clippy::too_many_arguments)]
pub fn load_connector(
    config_path: &Path,
    runtime_attestation_path: &Path,
    runtime_attestation_key_path: &Path,
    request_key_path: &Path,
    destination_key_path: &Path,
    outcome_seed_path: &Path,
    observer_key_path: &Path,
    token_path: &Path,
    marker_path: &Path,
) -> Result<ExternalConnector, ConnectorError> {
    let config: ConnectorConfig = parse_config(&read_private_bounded_regular_file(
        config_path,
        MAX_CONFIG_BYTES,
    )?)?;
    let config_sha256 = config.canonical_digest()?;
    verify_runtime_attestation(
        runtime_attestation_path,
        runtime_attestation_key_path,
        RuntimeAttestationExpectation {
            workload_kind: "external_connector",
            workload_identity: &config.service_identity,
            implementation_sha256: &config.implementation_sha256,
            image_sha256: &config.image_sha256,
            config_sha256: &config_sha256,
            deployment_identity: &config.deployment_identity,
            runtime_boundary_identity: &config.runtime_boundary_identity,
            authority_key_id: &config.runtime_attestation_authority_key_id,
            authority_key_sha256: &config.runtime_attestation_authority_key_sha256,
        },
    )?;
    let request_key = decode_single_key(request_key_path)?;
    let destination_key = decode_single_key(destination_key_path)?;
    let outcome_seed = decode_single_key(outcome_seed_path)?;
    let observer_key = decode_single_key(observer_key_path)?;
    let token = read_private_bounded_regular_file(token_path, MAX_TOKEN_BYTES)?;
    let markers = decode_markers(marker_path)?;
    ExternalConnector::new(
        config,
        request_key,
        destination_key,
        outcome_seed,
        observer_key,
        token,
        markers,
    )
}

pub fn load_shadow_replayer(
    config_path: &Path,
    runtime_attestation_path: &Path,
    runtime_attestation_key_path: &Path,
    connector_key_path: &Path,
    replay_seed_path: &Path,
    marker_path: &Path,
) -> Result<ShadowReplayer, ConnectorError> {
    let config: ShadowReplayConfig = parse_config(&read_private_bounded_regular_file(
        config_path,
        MAX_CONFIG_BYTES,
    )?)?;
    let config_sha256 = config.canonical_digest()?;
    verify_runtime_attestation(
        runtime_attestation_path,
        runtime_attestation_key_path,
        RuntimeAttestationExpectation {
            workload_kind: "external_shadow_replay",
            workload_identity: &config.shadow_identity,
            implementation_sha256: &config.implementation_sha256,
            image_sha256: &config.image_sha256,
            config_sha256: &config_sha256,
            deployment_identity: &config.deployment_identity,
            runtime_boundary_identity: &config.runtime_boundary_identity,
            authority_key_id: &config.runtime_attestation_authority_key_id,
            authority_key_sha256: &config.runtime_attestation_authority_key_sha256,
        },
    )?;
    ShadowReplayer::new(
        config,
        decode_single_key(connector_key_path)?,
        decode_single_key(replay_seed_path)?,
        decode_markers(marker_path)?,
    )
}

struct RuntimeAttestationExpectation<'a> {
    workload_kind: &'a str,
    workload_identity: &'a str,
    implementation_sha256: &'a str,
    image_sha256: &'a str,
    config_sha256: &'a str,
    deployment_identity: &'a str,
    runtime_boundary_identity: &'a str,
    authority_key_id: &'a str,
    authority_key_sha256: &'a str,
}

fn verify_runtime_attestation(
    attestation_path: &Path,
    authority_key_path: &Path,
    expected: RuntimeAttestationExpectation<'_>,
) -> Result<(), ConnectorError> {
    let authority_key = decode_single_key(authority_key_path)?;
    if crate::content_sha256(&authority_key) != expected.authority_key_sha256 {
        return Err(ConnectorError::InvalidConfig);
    }
    let attestation: RuntimeImageAttestation = parse_config(&read_private_bounded_regular_file(
        attestation_path,
        MAX_RUNTIME_ATTESTATION_BYTES,
    )?)?;
    let evidence = crate::authority::running_runtime_evidence()?;
    let now_unix_ms = current_unix_time_ms()?;
    validate_runtime_attestation(
        &attestation,
        &authority_key,
        &expected,
        &evidence,
        now_unix_ms,
    )
}

fn validate_runtime_attestation(
    attestation: &RuntimeImageAttestation,
    authority_key: &[u8],
    expected: &RuntimeAttestationExpectation<'_>,
    evidence: &crate::authority::RuntimeEvidence,
    now_unix_ms: i64,
) -> Result<(), ConnectorError> {
    verify_runtime_image_attestation_signature(attestation, authority_key)?;
    if attestation.schema_version != RUNTIME_IMAGE_ATTESTATION_SCHEMA_VERSION
        || attestation.workload_kind != expected.workload_kind
        || attestation.workload_identity != expected.workload_identity
        || attestation.implementation_sha256 != expected.implementation_sha256
        || attestation.implementation_sha256 != evidence.implementation_sha256
        || attestation.image_sha256 != expected.image_sha256
        || attestation.config_sha256 != expected.config_sha256
        || attestation.deployment_identity != expected.deployment_identity
        || attestation.runtime_boundary_identity != expected.runtime_boundary_identity
        || attestation.linux_boot_id != evidence.linux_boot_id
        || attestation.mount_namespace_inode != evidence.mount_namespace_inode
        || attestation.cgroup_sha256 != evidence.cgroup_sha256
        || attestation.authority_key_id != expected.authority_key_id
        || attestation.issued_at_unix_ms > now_unix_ms
        || attestation.expires_at_unix_ms < now_unix_ms
        || attestation.expires_at_unix_ms < attestation.issued_at_unix_ms
        || attestation
            .expires_at_unix_ms
            .saturating_sub(attestation.issued_at_unix_ms)
            > MAX_RUNTIME_ATTESTATION_WINDOW_MS
    {
        return Err(ConnectorError::InvalidConfig);
    }
    Ok(())
}

fn current_unix_time_ms() -> Result<i64, ConnectorError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ConnectorError::StateUnavailable)?;
    i64::try_from(duration.as_millis()).map_err(|_| ConnectorError::StateUnavailable)
}

pub async fn serve_connector_stdio(connector: &ExternalConnector) -> Result<(), ConnectorError> {
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut stdout = tokio::io::stdout();
    loop {
        let Some(frame) = read_frame(&mut reader).await? else {
            return Ok(());
        };
        let response = match parse_json_no_duplicates::<ConnectorCommand>(&frame) {
            Ok(ConnectorCommand::Execute { request }) => match connector.execute(*request).await {
                Ok(receipt) => ConnectorResponse::Ok {
                    receipt: Box::new(receipt),
                },
                Err(error) => ConnectorResponse::Error {
                    code: error.code().to_owned(),
                },
            },
            Ok(ConnectorCommand::Reconcile { request }) => match connector.reconcile(*request) {
                Ok(receipt) => ConnectorResponse::Ok {
                    receipt: Box::new(receipt),
                },
                Err(error) => ConnectorResponse::Error {
                    code: error.code().to_owned(),
                },
            },
            Err(error) => ConnectorResponse::Error {
                code: error.code().to_owned(),
            },
        };
        write_frame(&mut stdout, &response).await?;
    }
}

pub async fn serve_shadow_stdio(shadow: &ShadowReplayer) -> Result<(), ConnectorError> {
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut stdout = tokio::io::stdout();
    loop {
        let Some(frame) = read_frame(&mut reader).await? else {
            return Ok(());
        };
        let response = match parse_json_no_duplicates::<ShadowCommand>(&frame) {
            Ok(ShadowCommand::Replay { request }) => match shadow.replay(*request) {
                Ok(receipt) => ShadowResponse::Ok {
                    receipt: Box::new(receipt),
                },
                Err(error) => ShadowResponse::Error {
                    code: error.code().to_owned(),
                },
            },
            Err(error) => ShadowResponse::Error {
                code: error.code().to_owned(),
            },
        };
        write_frame(&mut stdout, &response).await?;
    }
}

async fn read_frame<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
) -> Result<Option<Vec<u8>>, ConnectorError> {
    let mut frame = Vec::new();
    let read = reader
        .take((MAX_FRAME_BYTES as u64).saturating_add(1))
        .read_until(b'\n', &mut frame)
        .await
        .map_err(|_| ConnectorError::MalformedRequest)?;
    if read == 0 {
        return Ok(None);
    }
    if frame.len() > MAX_FRAME_BYTES || frame.last() != Some(&b'\n') {
        return Err(ConnectorError::OversizedRequest);
    }
    frame.pop();
    if frame.last() == Some(&b'\r') {
        frame.pop();
    }
    if frame.is_empty() {
        return Err(ConnectorError::MalformedRequest);
    }
    Ok(Some(frame))
}

async fn write_frame<W: tokio::io::AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    response: &T,
) -> Result<(), ConnectorError> {
    let mut bytes = serde_json::to_vec(response).map_err(|_| ConnectorError::StateUnavailable)?;
    if bytes.len().saturating_add(1) > MAX_FRAME_BYTES {
        return Err(ConnectorError::CapacityExceeded);
    }
    bytes.push(b'\n');
    writer
        .write_all(&bytes)
        .await
        .map_err(|error| match error.kind() {
            ErrorKind::BrokenPipe => ConnectorError::StateUnavailable,
            _ => ConnectorError::StateUnavailable,
        })?;
    writer
        .flush()
        .await
        .map_err(|_| ConnectorError::StateUnavailable)
}

fn parse_config<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, ConnectorError> {
    parse_json_no_duplicates(bytes).map_err(|_| ConnectorError::InvalidConfig)
}

fn decode_single_key(path: &Path) -> Result<Vec<u8>, ConnectorError> {
    let bytes = read_private_bounded_regular_file(path, MAX_KEY_BYTES)?;
    let encoded = std::str::from_utf8(&bytes)
        .map_err(|_| ConnectorError::InvalidConfig)?
        .trim();
    BASE64
        .decode(encoded)
        .map_err(|_| ConnectorError::InvalidConfig)
}

fn decode_markers(path: &Path) -> Result<Vec<Vec<u8>>, ConnectorError> {
    let bytes = read_private_bounded_regular_file(path, MAX_MARKER_BYTES)?;
    let encoded: Vec<String> = parse_config(&bytes)?;
    encoded
        .into_iter()
        .map(|marker| {
            BASE64
                .decode(marker)
                .map_err(|_| ConnectorError::InvalidConfig)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shadow_replay_accepts_only_the_exact_enforcing_apparmor_label() {
        assert!(shadow_apparmor_label_is_enforcing(
            "mcloving-external-shadow-replay (enforce)\n"
        ));
        for rejected in [
            "unconfined\n",
            "mcloving-external-shadow-replay (complain)\n",
            "mcloving-external-shadow-replay (unconfined)\n",
            "mcloving-external-shadow-replay//child (enforce)\n",
            "mcloving-external-shadow-replay (enforce) trailing\n",
        ] {
            assert!(!shadow_apparmor_label_is_enforcing(rejected));
        }
    }

    #[test]
    fn runtime_attestation_is_signed_fresh_and_bound_to_live_evidence() {
        let seed = vec![11; 32];
        let public_key = crate::public_key_from_seed(&seed).unwrap();
        let image_sha256 = "c".repeat(64);
        let config_sha256 = "d".repeat(64);
        let authority_key_sha256 = crate::content_sha256(&public_key);
        let evidence = crate::authority::RuntimeEvidence {
            implementation_sha256: "a".repeat(64),
            linux_boot_id: "boot-1".to_owned(),
            mount_namespace_inode: 42,
            cgroup_sha256: "b".repeat(64),
        };
        let expectation = RuntimeAttestationExpectation {
            workload_kind: "external_connector",
            workload_identity: "service/connector",
            implementation_sha256: &evidence.implementation_sha256,
            image_sha256: &image_sha256,
            config_sha256: &config_sha256,
            deployment_identity: "deployment/connector",
            runtime_boundary_identity: "runtime/connector",
            authority_key_id: "key/runtime-attestation",
            authority_key_sha256: &authority_key_sha256,
        };
        let mut attestation = RuntimeImageAttestation {
            schema_version: RUNTIME_IMAGE_ATTESTATION_SCHEMA_VERSION.to_owned(),
            workload_kind: expectation.workload_kind.to_owned(),
            workload_identity: expectation.workload_identity.to_owned(),
            implementation_sha256: expectation.implementation_sha256.to_owned(),
            image_sha256: expectation.image_sha256.to_owned(),
            config_sha256: expectation.config_sha256.to_owned(),
            deployment_identity: expectation.deployment_identity.to_owned(),
            runtime_boundary_identity: expectation.runtime_boundary_identity.to_owned(),
            linux_boot_id: evidence.linux_boot_id.clone(),
            mount_namespace_inode: evidence.mount_namespace_inode,
            cgroup_sha256: evidence.cgroup_sha256.clone(),
            issued_at_unix_ms: 1_000,
            expires_at_unix_ms: 2_000,
            authority_key_id: expectation.authority_key_id.to_owned(),
            signature_base64: String::new(),
        };
        crate::sign_runtime_image_attestation(&mut attestation, &seed).unwrap();
        validate_runtime_attestation(&attestation, &public_key, &expectation, &evidence, 1_500)
            .unwrap();

        attestation.mount_namespace_inode += 1;
        crate::sign_runtime_image_attestation(&mut attestation, &seed).unwrap();
        assert_eq!(
            validate_runtime_attestation(&attestation, &public_key, &expectation, &evidence, 1_500,),
            Err(ConnectorError::InvalidConfig)
        );
    }
}
