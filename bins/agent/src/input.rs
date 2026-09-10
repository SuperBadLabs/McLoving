//! Deployment-owned public input capture. Provider credentials remain helper-owned.
use crate::private_helper::{read_private, seal_executable};
use crate::{AgentConfig, AgentError};
use mcloving_agent_runtime::executor::PrivateExecutionOutput;
use mcloving_domain::cache_intent::{canonical_mapping_id, canonical_sha256};
use mcloving_domain::input_intent::{InputIntentSpec, InputWorkContext, input_capture_id};
use mcloving_input_adapter::{AdapterConfig, CaptureRequest, Confidentiality};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::{Path, PathBuf};
const MAX_FRAME_BYTES: usize = 262_144;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InputBindings {
    pub schema_version: String,
    pub mappings: Vec<InputBinding>,
}

/// Every operator authority choice is covered by the canonical mapping digest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InputBinding {
    pub mapping_id: String,
    pub organization_id: String,
    pub project_id: String,
    pub pipeline_id: String,
    pub trust_pool: String,
    pub executable: PathBuf,
    pub executable_sha256: String,
    pub config_path: PathBuf,
    pub config_sha256: String,
    pub read_token_path: PathBuf,
    pub signing_key_path: PathBuf,
    pub secret_markers_path: PathBuf,
    pub input_name: String,
    pub query: BTreeMap<String, String>,
    pub expected_cursor: Option<String>,
    pub confidentiality_ceiling: Confidentiality,
    /// Fixture-only operator opt-in, never supplied by a submitted job.
    pub test_allow_http_loopback: bool,
}
impl InputBinding {
    pub fn mapping_digest(&self) -> Result<String, AgentError> {
        Ok(format!(
            "sha256:{}",
            mcloving_input_adapter::content_sha256(&serde_json::to_vec(self)?)
        ))
    }
}
fn denied() -> AgentError {
    AgentError::InvalidConfig("sealed input deployment binding")
}
fn now_ms() -> Result<i64, AgentError> {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| denied())?
            .as_millis(),
    )
    .map_err(|_| denied())
}
pub(crate) fn scheduling_capabilities(config: &AgentConfig) -> Result<Vec<String>, AgentError> {
    let mut capabilities = BTreeSet::new();
    if cfg!(target_os = "linux")
        && let Some(bindings) = &config.input_bindings
    {
        capabilities.insert(mcloving_domain::input_intent::INPUT_CAPABILITY.to_owned());
        for binding in &bindings.mappings {
            if binding.trust_pool == config.trust_pool {
                capabilities.insert(
                    mcloving_domain::input_intent::input_binding_capability(
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
pub fn load_bindings(path: &Path, expected_sha256: &str) -> Result<InputBindings, AgentError> {
    let bytes = read_private(path, MAX_FRAME_BYTES, true)?;
    if !canonical_sha256(expected_sha256)
        || mcloving_input_adapter::content_sha256(&bytes) != expected_sha256
    {
        return Err(denied());
    }
    let bindings: InputBindings =
        mcloving_input_adapter::parse_json_no_duplicates(&bytes).map_err(|_| denied())?;
    if bindings.schema_version != "mcloving.agent-input-bindings/v1"
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
                    uuid::Uuid::parse_str(id).map_or(true, |id_value| {
                        id_value.is_nil() || id_value.to_string() != *id
                    })
                })
            || [&b.executable_sha256, &b.config_sha256]
                .into_iter()
                .any(|v| !canonical_sha256(v))
            || [&b.trust_pool, &b.input_name]
                .into_iter()
                .any(|v| v.is_empty() || v.len() > 256 || v.trim() != v.as_str())
            || [
                &b.executable,
                &b.config_path,
                &b.read_token_path,
                &b.signing_key_path,
                &b.secret_markers_path,
            ]
            .into_iter()
            .any(|p| !p.is_absolute())
            || b.confidentiality_ceiling != Confidentiality::Public
            || b.query.len() > 64
            || b.query
                .iter()
                .any(|(k, v)| k.is_empty() || k.len() > 256 || v.len() > 4096)
            || b.expected_cursor.as_ref().is_some_and(|v| v.len() > 256)
        {
            return Err(denied());
        }
    }
    Ok(bindings)
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct PreparedInput {
    _executable: File,
    pub program: PathBuf,
    pub arguments: Vec<std::ffi::OsString>,
    pub environment: BTreeMap<String, String>,
    pub request: Vec<u8>,
    pub output_limit: u64,
    config: AdapterConfig,
    signing_key: Vec<u8>,
    secret_markers: Vec<Vec<u8>>,
    capture: CaptureRequest,
    binding: InputBinding,
    invocation_id: String,
    started_at_ms: i64,
}

/// Request identity and timestamps are derived solely from durable acceptance,
/// authoritative assignment digest/context and the frozen operator mapping.
#[allow(clippy::too_many_arguments)] // Durable acceptance is distinct from current observation.
pub fn derive_capture_request(
    binding: &InputBinding,
    config: &AdapterConfig,
    intent: &InputIntentSpec,
    context: &InputWorkContext,
    payload_digest: &[u8; 32],
    accepted_at_ms: i64,
    now: i64,
) -> Result<CaptureRequest, AgentError> {
    intent.validate().map_err(|_| denied())?;
    context.validate().map_err(|_| denied())?;
    if binding.mapping_digest()? != intent.mapping_digest
        || binding.mapping_id != intent.mapping_id
        || binding.organization_id != context.organization_id
        || binding.project_id != context.project_id
        || binding.pipeline_id != context.pipeline_id
        || binding.confidentiality_ceiling != Confidentiality::Public
        || config.max_confidentiality != Confidentiality::Public
        || config.max_response_bytes > 12 * 1024
        || config.test_allow_http_loopback != binding.test_allow_http_loopback
        || config.canonical_digest().map_err(|_| denied())? != binding.config_sha256
        || accepted_at_ms <= 0
        || accepted_at_ms > now
    {
        return Err(denied());
    }
    let expires = accepted_at_ms
        .checked_add(
            i64::try_from(intent.timeout_seconds)
                .map_err(|_| denied())?
                .checked_mul(1000)
                .ok_or_else(denied)?,
        )
        .ok_or_else(denied)?
        .min(config.grant_expires_unix_ms);
    if expires <= now {
        return Err(denied());
    }
    let parse = |value: &str| uuid::Uuid::parse_str(value).map_err(|_| denied());
    let request = CaptureRequest {
        capture_id: input_capture_id(payload_digest),
        organization_id: parse(&context.organization_id)?,
        project_id: parse(&context.project_id)?,
        pipeline_id: parse(&context.pipeline_id)?,
        build_id: parse(&context.build_id)?,
        attempt_id: parse(&context.attempt_id)?,
        input_name: binding.input_name.clone(),
        adapter_id: config.adapter_id.clone(),
        expected_implementation_sha256: binding.executable_sha256.clone(),
        expected_config_sha256: binding.config_sha256.clone(),
        protocol_version: config.protocol_version.clone(),
        schema_version: config.schema_version.clone(),
        expected_generation: config.generation,
        rollback_from_generation: None,
        endpoint_identity: config.endpoint_identity.clone(),
        data_source_identity: config.data_source_identity.clone(),
        grant_id: config.grant_id.clone(),
        grant_version: config.grant_version.clone(),
        grant_scope: config.grant_scope.clone(),
        query: binding.query.clone(),
        expected_cursor: binding.expected_cursor.clone(),
        requested_at_unix_ms: accepted_at_ms,
        expires_at_unix_ms: expires,
        confidentiality_ceiling: Confidentiality::Public,
        audit_lineage: format!(
            "sha256:{}",
            payload_digest
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ),
    };
    mcloving_input_adapter::validate_capture_request(
        config,
        &binding.executable_sha256,
        &request,
        now,
    )
    .map_err(|_| denied())?;
    Ok(request)
}

pub(crate) fn prepare(
    config: &AgentConfig,
    intent: &InputIntentSpec,
    context: &InputWorkContext,
    payload_digest: &[u8; 32],
    accepted_at_ms: i64,
) -> Result<PreparedInput, AgentError> {
    let binding = config
        .input_bindings
        .as_ref()
        .and_then(|catalog| {
            catalog
                .mappings
                .iter()
                .find(|b| b.mapping_id == intent.mapping_id)
        })
        .ok_or_else(denied)?;
    if binding.trust_pool != config.trust_pool {
        return Err(denied());
    }
    let adapter_config: AdapterConfig = mcloving_input_adapter::parse_json_no_duplicates(
        &read_private(&binding.config_path, 65536, false)?,
    )
    .map_err(|_| denied())?;
    let signing_key = read_private(&binding.signing_key_path, 4096, false)?;
    let secret_markers = read_private(&binding.secret_markers_path, 65536, false)?
        .split(|b| *b == b'\n')
        .filter(|m| !m.is_empty())
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    mcloving_input_adapter::validate_verifier_config(
        &adapter_config,
        &binding.executable_sha256,
        &signing_key,
        &secret_markers,
    )
    .map_err(|_| denied())?;
    let started_at_ms = now_ms()?;
    let capture = derive_capture_request(
        binding,
        &adapter_config,
        intent,
        context,
        payload_digest,
        accepted_at_ms,
        started_at_ms,
    )?;
    let mut request = serde_json::to_vec(&capture)?;
    request.push(b'\n');
    if request.len() > 65536 {
        return Err(denied());
    }
    let (executable, program) = seal_executable(&binding.executable, &binding.executable_sha256)?;
    let mut environment = BTreeMap::new();
    for (name, path) in [
        ("MCLOVING_INPUT_ADAPTER_CONFIG", &binding.config_path),
        (
            "MCLOVING_INPUT_ADAPTER_READ_TOKEN_FILE",
            &binding.read_token_path,
        ),
        (
            "MCLOVING_INPUT_ADAPTER_SIGNING_KEY_FILE",
            &binding.signing_key_path,
        ),
        (
            "MCLOVING_INPUT_ADAPTER_SECRET_MARKERS_FILE",
            &binding.secret_markers_path,
        ),
    ] {
        environment.insert(
            name.to_owned(),
            path.to_str().ok_or_else(denied)?.to_owned(),
        );
    }
    environment.insert(
        "MCLOVING_INPUT_ADAPTER_EXPECTED_CONFIG_SHA256".to_owned(),
        binding.config_sha256.clone(),
    );
    if binding.test_allow_http_loopback {
        environment.insert(
            "MCLOVING_INPUT_ADAPTER_TEST_MODE".to_owned(),
            "1".to_owned(),
        );
    }
    Ok(PreparedInput {
        _executable: executable,
        program,
        arguments: Vec::new(),
        environment,
        request,
        output_limit: MAX_FRAME_BYTES as u64,
        config: adapter_config,
        signing_key,
        secret_markers,
        capture,
        binding: binding.clone(),
        invocation_id: format!(
            "sha256:{}",
            payload_digest
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ),
        started_at_ms,
    })
}
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl PreparedInput {
    pub fn transform(&self, stdout: &[u8], stderr: &[u8]) -> PrivateExecutionOutput {
        let accepted = stderr.is_empty()
            && now_ms().is_ok_and(|now| {
                mcloving_input_adapter::verify_capture_response(
                    &self.config,
                    &self.binding.executable_sha256,
                    &self.signing_key,
                    &self.secret_markers,
                    &self.capture,
                    stdout,
                    self.started_at_ms,
                    now,
                )
                .is_ok()
            });
        let mut public=serde_json::to_vec(&serde_json::json!({
            "protocol":"mcloving.input-invocation/v1", "invocation_id":self.invocation_id,
            "mapping_id":self.binding.mapping_id,"capture_id":self.capture.capture_id,
            "request_sha256":mcloving_input_adapter::capture_request_sha256(&self.capture).unwrap_or_default(),
            "outcome":if accepted {"captured"} else {"response_rejected"},
        })).unwrap_or_default();
        public.push(b'\n');
        PrivateExecutionOutput {
            stdout: public,
            accepted,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (
        InputBinding,
        AdapterConfig,
        InputIntentSpec,
        InputWorkContext,
    ) {
        let id = uuid::Uuid::new_v4().to_string();
        let cfg:AdapterConfig=serde_json::from_value(serde_json::json!({
            "protocol_version":"mcloving.input-adapter/v1","schema_version":"flags/v1","adapter_id":"flags","deployment_identity":"deployment","operator_identity":"operator","generation":1,
            "endpoint_url":"http://127.0.0.1:9/input","endpoint_identity":"source","data_source_identity":"data","allowed_query_keys":["branch"],"response_schema":[],"grant_id":"grant","grant_version":"1","grant_scope":"read","grant_expires_unix_ms":200000,
            "read_token_sha256":"a".repeat(64),"signing_key_id":"key","signing_key_sha256":"b".repeat(64),"secret_marker_set_sha256":"c".repeat(64),"max_confidentiality":"public","max_response_bytes":1024,"max_requests_per_minute":10,"timeout_ms":1000,"max_age_ms":5000,"retry_attempts":0,"spool_dir":"/must-not-create","test_allow_http_loopback":true
        })).unwrap();
        let binding = InputBinding {
            mapping_id: "fixture".into(),
            organization_id: id.clone(),
            project_id: id.clone(),
            pipeline_id: id.clone(),
            trust_pool: "pool".into(),
            executable: "/helper".into(),
            executable_sha256: "d".repeat(64),
            config_path: "/config".into(),
            config_sha256: cfg.canonical_digest().unwrap(),
            read_token_path: "/token-must-not-read".into(),
            signing_key_path: "/key".into(),
            secret_markers_path: "/markers".into(),
            input_name: "enabled".into(),
            query: BTreeMap::from([("branch".into(), "main".into())]),
            expected_cursor: Some("cursor".into()),
            confidentiality_ceiling: Confidentiality::Public,
            test_allow_http_loopback: true,
        };
        let intent = InputIntentSpec {
            mapping_id: binding.mapping_id.clone(),
            mapping_digest: binding.mapping_digest().unwrap(),
            timeout_seconds: 60,
        };
        let context = InputWorkContext {
            organization_id: id.clone(),
            project_id: id.clone(),
            pipeline_id: id.clone(),
            build_id: id.clone(),
            node_id: id.clone(),
            attempt_id: id,
            fence_token: 1,
        };
        (binding, cfg, intent, context)
    }
    #[test]
    fn durable_request_recomputes_exactly_caps_grant_and_retains_complete_assignment_digest() {
        let (binding, cfg, intent, context) = fixture();
        let a = derive_capture_request(
            &binding,
            &cfg,
            &intent,
            &context,
            &[0xab; 32],
            150000,
            150001,
        )
        .unwrap();
        let b = derive_capture_request(
            &binding,
            &cfg,
            &intent,
            &context,
            &[0xab; 32],
            150000,
            160000,
        )
        .unwrap();
        assert_eq!(
            serde_json::to_vec(&a).unwrap(),
            serde_json::to_vec(&b).unwrap()
        );
        assert_eq!(a.requested_at_unix_ms, 150000);
        assert_eq!(a.expires_at_unix_ms, 200000);
        assert_eq!(a.audit_lineage, format!("sha256:{}", "ab".repeat(32)));
        assert_eq!(a.capture_id, input_capture_id(&[0xab; 32]));
        let mut digest = [0xab; 32];
        digest[31] ^= 1;
        let other =
            derive_capture_request(&binding, &cfg, &intent, &context, &digest, 150000, 150001)
                .unwrap();
        assert_ne!(a.capture_id, other.capture_id);
        assert_ne!(a.audit_lineage, other.audit_lineage);
        assert!(
            derive_capture_request(
                &binding,
                &cfg,
                &intent,
                &context,
                &[0xab; 32],
                150000,
                200000
            )
            .is_err()
        );
        assert!(
            derive_capture_request(
                &binding,
                &cfg,
                &intent,
                &context,
                &[0xab; 32],
                150000,
                149999
            )
            .is_err()
        );
        assert!(
            derive_capture_request(
                &binding,
                &cfg,
                &intent,
                &context,
                &[0xab; 32],
                i64::MAX - 1,
                i64::MAX - 1
            )
            .is_err()
        );
    }
    #[test]
    fn request_derivation_refuses_mapping_scope_config_and_private_confidentiality_substitution() {
        let (binding, cfg, intent, context) = fixture();
        let mut changed = binding.clone();
        changed.query.insert("branch".into(), "other".into());
        assert!(
            derive_capture_request(&changed, &cfg, &intent, &context, &[1; 32], 150000, 150001)
                .is_err()
        );
        let mut changed_context = context.clone();
        changed_context.project_id = uuid::Uuid::new_v4().to_string();
        assert!(
            derive_capture_request(
                &binding,
                &cfg,
                &intent,
                &changed_context,
                &[1; 32],
                150000,
                150001
            )
            .is_err()
        );
        let mut changed_cfg = cfg.clone();
        changed_cfg.max_confidentiality = Confidentiality::Internal;
        assert!(
            derive_capture_request(
                &binding,
                &changed_cfg,
                &intent,
                &context,
                &[1; 32],
                150000,
                150001
            )
            .is_err()
        );
        changed_cfg = cfg;
        changed_cfg.endpoint_url = "http://127.0.0.1:9/other".into();
        assert!(
            derive_capture_request(
                &binding,
                &changed_cfg,
                &intent,
                &context,
                &[1; 32],
                150000,
                150001
            )
            .is_err()
        );
    }
}
