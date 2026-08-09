use std::collections::BTreeSet;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::config::{
    CertifiedConfig, ConfigError, configuration_sha256, repositories_by_id, validate_binding,
    validate_config, validate_digest,
};
use crate::{CanonicalPlan, Ecosystem, REQUEST_SCHEMA_VERSION, SourceTrustClass};

pub const SOURCE_PROVENANCE_SCHEMA_VERSION: &str = "mcloving.source-provenance/v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceProvenance {
    pub schema_version: String,
    pub key_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub signature_base64: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GrantUse {
    pub repository_id: String,
    pub grant_id: String,
    pub version: u64,
    pub scope: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionRequest {
    pub schema_version: String,
    pub protocol_version: String,
    pub resolution_id: String,
    pub tenant_id: String,
    pub project_id: String,
    pub pipeline_id: String,
    pub build_id: String,
    pub attempt_id: String,
    pub audit_lineage: String,
    pub source_trust_class: SourceTrustClass,
    pub source_provenance: SourceProvenance,
    pub expected_executable_sha256: String,
    pub expected_configuration_sha256: String,
    pub expected_adapter_id: String,
    pub expected_adapter_sha256: String,
    pub expected_resolver_toolchain_id: String,
    pub expected_resolver_toolchain_sha256: String,
    pub expected_generation: u64,
    pub acquisition_receipt_sha256: String,
    pub source_tree_sha256: String,
    pub logical_lock_path: String,
    pub expected_lock_sha256: String,
    pub ecosystem: Ecosystem,
    pub expected_graph_sha256: String,
    pub repository_ids: Vec<String>,
    pub grants: Vec<GrantUse>,
    pub requested_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub rollback_from_generation: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmittedRequest {
    pub configuration_sha256: String,
    pub request_sha256: String,
    pub absolute_expiry_unix_ms: u64,
    pub repository_ids: Vec<String>,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("{code}: {message}")]
pub struct RequestError {
    pub code: &'static str,
    pub message: String,
}

impl RequestError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl From<ConfigError> for RequestError {
    fn from(error: ConfigError) -> Self {
        Self::new(error.code, error.message)
    }
}

pub fn admit_request(
    config: &CertifiedConfig,
    source_attestation_key: &[u8],
    request: &ResolutionRequest,
    plan: &CanonicalPlan,
    lock_bytes: &[u8],
    now_unix_ms: u64,
) -> Result<AdmittedRequest, RequestError> {
    validate_config(config)?;
    crate::validate_plan(plan).map_err(|error| RequestError::new(error.code, error.message))?;
    validate_request_shape(config, request, now_unix_ms)?;
    let config_digest = configuration_sha256(config)?;
    if request.expected_configuration_sha256 != config_digest
        || request.expected_executable_sha256 != config.executable_sha256
        || request.expected_resolver_toolchain_id != config.resolver_toolchain_id
        || request.expected_resolver_toolchain_sha256 != config.resolver_toolchain_sha256
        || request.expected_generation != config.generation
    {
        return Err(RequestError::new(
            "DEP_REQUEST_RUNTIME_BINDING_MISMATCH",
            "request does not bind the exact certified resolver runtime",
        ));
    }
    verify_source_provenance(config, source_attestation_key, request)?;
    if request
        .rollback_from_generation
        .is_some_and(|generation| generation >= request.expected_generation)
    {
        return Err(RequestError::new(
            "DEP_REQUEST_ROLLBACK_INVALID",
            "rollback source generation must be strictly older",
        ));
    }
    validate_plan_binding(config, request, plan, lock_bytes)?;
    validate_repository_binding(config, request, plan, now_unix_ms)?;
    Ok(AdmittedRequest {
        configuration_sha256: config_digest,
        request_sha256: request_sha256(request)?,
        absolute_expiry_unix_ms: request.expires_at_unix_ms,
        repository_ids: request.repository_ids.clone(),
    })
}

pub fn source_provenance_message(request: &ResolutionRequest) -> Result<Vec<u8>, RequestError> {
    let mut unsigned = request.clone();
    unsigned.source_provenance.signature_base64.clear();
    let bytes = serde_json::to_vec(&unsigned).map_err(|_| {
        RequestError::new(
            "DEP_REQUEST_SOURCE_PROVENANCE_INVALID",
            "source provenance could not be serialized canonically",
        )
    })?;
    let domain = b"mcloving-source-provenance-v1";
    let mut message = Vec::with_capacity(16 + domain.len() + bytes.len());
    message.extend_from_slice(&(domain.len() as u64).to_be_bytes());
    message.extend_from_slice(domain);
    message.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    message.extend_from_slice(&bytes);
    Ok(message)
}

fn verify_source_provenance(
    config: &CertifiedConfig,
    source_attestation_key: &[u8],
    request: &ResolutionRequest,
) -> Result<(), RequestError> {
    let provenance = &request.source_provenance;
    if provenance.schema_version != SOURCE_PROVENANCE_SCHEMA_VERSION
        || provenance.key_id != config.source_attestation_key_id
        || provenance.issued_at_unix_ms != request.requested_at_unix_ms
        || provenance.expires_at_unix_ms != request.expires_at_unix_ms
        || source_attestation_key.len() != 32
        || format!("{:x}", Sha256::digest(source_attestation_key))
            != config.source_attestation_key_sha256
    {
        return Err(RequestError::new(
            "DEP_REQUEST_SOURCE_PROVENANCE_INVALID",
            "source provenance schema, authority, lifetime, or key is invalid",
        ));
    }
    let signature = STANDARD_NO_PAD
        .decode(provenance.signature_base64.as_bytes())
        .map_err(|_| {
            RequestError::new(
                "DEP_REQUEST_SOURCE_PROVENANCE_INVALID",
                "source provenance signature encoding is invalid",
            )
        })?;
    if signature.len() != 64 || STANDARD_NO_PAD.encode(&signature) != provenance.signature_base64 {
        return Err(RequestError::new(
            "DEP_REQUEST_SOURCE_PROVENANCE_INVALID",
            "source provenance signature encoding is invalid",
        ));
    }
    let message = source_provenance_message(request)?;
    UnparsedPublicKey::new(&ED25519, source_attestation_key)
        .verify(&message, &signature)
        .map_err(|_| {
            RequestError::new(
                "DEP_REQUEST_SOURCE_PROVENANCE_INVALID",
                "source provenance signature does not bind the exact request",
            )
        })
}

pub fn request_sha256(request: &ResolutionRequest) -> Result<String, RequestError> {
    let bytes = serde_json::to_vec(request).map_err(|_| {
        RequestError::new(
            "DEP_REQUEST_CANONICALIZATION_FAILED",
            "request could not be serialized canonically",
        )
    })?;
    let mut hasher = Sha256::new();
    let domain = b"mcloving-dependency-request-v1";
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

fn validate_request_shape(
    config: &CertifiedConfig,
    request: &ResolutionRequest,
    now_unix_ms: u64,
) -> Result<(), RequestError> {
    if request.schema_version != REQUEST_SCHEMA_VERSION
        || request.protocol_version != config.protocol_version
    {
        return Err(RequestError::new(
            "DEP_REQUEST_SCHEMA_MISMATCH",
            "request schema or protocol is not supported",
        ));
    }
    for value in [
        &request.resolution_id,
        &request.build_id,
        &request.attempt_id,
    ] {
        let parsed = Uuid::parse_str(value).map_err(|_| {
            RequestError::new(
                "DEP_REQUEST_UUID_INVALID",
                "resolution, build, and attempt identities must be UUIDs",
            )
        })?;
        if parsed.to_string() != *value {
            return Err(RequestError::new(
                "DEP_REQUEST_UUID_INVALID",
                "resolution, build, and attempt identities must use canonical lowercase UUID text",
            ));
        }
    }
    for (name, value) in [
        ("tenant", request.tenant_id.as_str()),
        ("project", request.project_id.as_str()),
        ("pipeline", request.pipeline_id.as_str()),
        ("audit lineage", request.audit_lineage.as_str()),
        ("adapter", request.expected_adapter_id.as_str()),
        (
            "resolver toolchain",
            request.expected_resolver_toolchain_id.as_str(),
        ),
    ] {
        validate_binding(name, value)?;
    }
    for (name, value) in [
        ("executable", request.expected_executable_sha256.as_str()),
        (
            "configuration",
            request.expected_configuration_sha256.as_str(),
        ),
        ("adapter", request.expected_adapter_sha256.as_str()),
        (
            "resolver toolchain",
            request.expected_resolver_toolchain_sha256.as_str(),
        ),
        (
            "acquisition receipt",
            request.acquisition_receipt_sha256.as_str(),
        ),
        ("source tree", request.source_tree_sha256.as_str()),
        ("lock", request.expected_lock_sha256.as_str()),
        ("graph", request.expected_graph_sha256.as_str()),
    ] {
        validate_digest(name, value)?;
    }
    validate_logical_lock_path(&request.logical_lock_path, config.limits.max_path_bytes)?;
    let lifetime = request
        .expires_at_unix_ms
        .checked_sub(request.requested_at_unix_ms)
        .ok_or_else(|| {
            RequestError::new(
                "DEP_REQUEST_TIME_INVALID",
                "request expiry precedes request time",
            )
        })?;
    if request.requested_at_unix_ms > now_unix_ms
        || request.expires_at_unix_ms <= now_unix_ms
        || lifetime == 0
        || lifetime > config.limits.max_request_lifetime_ms
    {
        return Err(RequestError::new(
            "DEP_REQUEST_TIME_INVALID",
            "request is future-issued, expired, or exceeds the lifetime bound",
        ));
    }
    Ok(())
}

fn validate_plan_binding(
    config: &CertifiedConfig,
    request: &ResolutionRequest,
    plan: &CanonicalPlan,
    lock_bytes: &[u8],
) -> Result<(), RequestError> {
    if lock_bytes.len() as u64 > config.limits.max_lock_bytes
        || sha256_hex(lock_bytes) != request.expected_lock_sha256
    {
        return Err(RequestError::new(
            "DEP_REQUEST_LOCK_MISMATCH",
            "lock bytes exceed the limit or do not match the request digest",
        ));
    }
    let adapter = config
        .adapters
        .iter()
        .find(|adapter| adapter.ecosystem == request.ecosystem)
        .expect("validated config has one adapter per ecosystem");
    if plan.ecosystem != request.ecosystem
        || plan.adapter_id != request.expected_adapter_id
        || plan.adapter_sha256 != request.expected_adapter_sha256
        || adapter.adapter_id != request.expected_adapter_id
        || adapter.implementation_sha256 != request.expected_adapter_sha256
        || plan.source_tree_sha256 != request.source_tree_sha256
        || plan.lock_sha256 != request.expected_lock_sha256
        || plan.graph_sha256 != request.expected_graph_sha256
        || plan.resolver_toolchain_id != request.expected_resolver_toolchain_id
        || plan.resolver_toolchain_sha256 != request.expected_resolver_toolchain_sha256
        || plan.source_trust_class != request.source_trust_class
    {
        return Err(RequestError::new(
            "DEP_REQUEST_PLAN_BINDING_MISMATCH",
            "request, certified adapter, and canonical plan do not match exactly",
        ));
    }
    if plan.nodes.len() as u64 > config.limits.max_nodes
        || plan.nodes.len() as u64 > config.limits.max_artifacts
        || plan
            .nodes
            .iter()
            .map(|node| node.dependencies.len() as u64)
            .sum::<u64>()
            > config.limits.max_edges
        || plan
            .nodes
            .iter()
            .any(|node| node.artifact_path.len() as u64 > config.limits.max_path_bytes)
        || plan
            .nodes
            .iter()
            .any(|node| node.declared_size > config.limits.max_artifact_bytes)
        || plan
            .nodes
            .iter()
            .try_fold(0_u64, |total, node| total.checked_add(node.declared_size))
            .is_none_or(|total| total > config.limits.max_total_artifact_bytes)
    {
        return Err(RequestError::new(
            "DEP_REQUEST_RESOURCE_LIMIT_EXCEEDED",
            "canonical plan exceeds a certified graph or artifact limit",
        ));
    }
    Ok(())
}

fn validate_repository_binding(
    config: &CertifiedConfig,
    request: &ResolutionRequest,
    plan: &CanonicalPlan,
    now_unix_ms: u64,
) -> Result<(), RequestError> {
    validate_sorted_bindings(&request.repository_ids, "repository")?;
    let repositories = repositories_by_id(config);
    let plan_repositories = plan
        .repositories
        .iter()
        .map(|repository| repository.repository_id.clone())
        .collect::<Vec<_>>();
    if request.repository_ids != plan_repositories {
        return Err(RequestError::new(
            "DEP_REQUEST_REPOSITORY_SET_MISMATCH",
            "request repository set does not exactly match the canonical plan",
        ));
    }
    let graph_repositories = plan
        .nodes
        .iter()
        .map(|node| node.repository_id.as_str())
        .collect::<BTreeSet<_>>();
    if graph_repositories.len() != plan.repositories.len()
        || plan
            .repositories
            .iter()
            .any(|binding| !graph_repositories.contains(binding.repository_id.as_str()))
    {
        return Err(RequestError::new(
            "DEP_REQUEST_REPOSITORY_SET_MISMATCH",
            "canonical repository bindings do not exactly match repositories used by graph nodes",
        ));
    }
    for node in &plan.nodes {
        let repository = repositories
            .get(node.repository_id.as_str())
            .ok_or_else(|| {
                RequestError::new(
                    "DEP_REQUEST_REPOSITORY_UNCONFIGURED",
                    "plan references an unconfigured repository",
                )
            })?;
        if repository.ecosystem != plan.ecosystem
            || node.attestation_key_id.as_deref() != Some(repository.attestation_key_id.as_str())
            || plan
                .repositories
                .iter()
                .find(|binding| binding.repository_id == node.repository_id)
                .is_none_or(|binding| {
                    binding.credentialed != repository.credentialed()
                        || binding.permits_untrusted_source != repository.permits_untrusted_source
                })
            || !repository
                .coordinate_prefixes
                .iter()
                .any(|prefix| node.coordinate.starts_with(prefix))
            || repository.credentialed()
                && request.source_trust_class == SourceTrustClass::Untrusted
        {
            return Err(RequestError::new(
                "DEP_REQUEST_REPOSITORY_POLICY_DENIED",
                "repository does not admit the ecosystem, coordinate, or source trust class",
            ));
        }
    }
    validate_grants(request, &repositories, now_unix_ms)
}

fn validate_grants(
    request: &ResolutionRequest,
    repositories: &std::collections::BTreeMap<&str, &crate::RepositoryConfig>,
    now_unix_ms: u64,
) -> Result<(), RequestError> {
    let mut previous = None;
    let mut used = BTreeSet::new();
    for grant_use in &request.grants {
        if previous.is_some_and(|value: &str| value >= grant_use.repository_id.as_str()) {
            return Err(RequestError::new(
                "DEP_REQUEST_GRANTS_NONCANONICAL",
                "grant uses must be sorted and duplicate-free by repository",
            ));
        }
        previous = Some(grant_use.repository_id.as_str());
        let repository = repositories
            .get(grant_use.repository_id.as_str())
            .ok_or_else(|| {
                RequestError::new(
                    "DEP_REQUEST_GRANT_MISMATCH",
                    "grant use references an unconfigured repository",
                )
            })?;
        let grant = repository.grant.as_ref().ok_or_else(|| {
            RequestError::new(
                "DEP_REQUEST_GRANT_MISMATCH",
                "request supplies a grant for a repository without one",
            )
        })?;
        if grant.grant_id != grant_use.grant_id
            || grant.version != grant_use.version
            || grant.scope != grant_use.scope
            || grant.expires_at_unix_ms <= now_unix_ms
            || grant.expires_at_unix_ms < request.expires_at_unix_ms
        {
            return Err(RequestError::new(
                "DEP_REQUEST_GRANT_MISMATCH",
                "repository grant identity, scope, version, or expiry does not match",
            ));
        }
        used.insert(grant_use.repository_id.as_str());
    }
    for repository_id in &request.repository_ids {
        let repository = repositories
            .get(repository_id.as_str())
            .expect("request repositories were validated above");
        if repository.grant.is_some() != used.contains(repository_id.as_str()) {
            return Err(RequestError::new(
                "DEP_REQUEST_GRANT_MISMATCH",
                "request grant set does not exactly match repository policy",
            ));
        }
    }
    Ok(())
}

fn validate_sorted_bindings(values: &[String], name: &str) -> Result<(), RequestError> {
    if values.is_empty() {
        return Err(RequestError::new(
            "DEP_REQUEST_BINDING_SET_INVALID",
            format!("{name} set cannot be empty"),
        ));
    }
    let mut previous = None;
    for value in values {
        validate_binding(name, value)?;
        if previous.is_some_and(|prior: &str| prior >= value.as_str()) {
            return Err(RequestError::new(
                "DEP_REQUEST_BINDING_SET_INVALID",
                format!("{name} set must be strictly sorted and duplicate-free"),
            ));
        }
        previous = Some(value.as_str());
    }
    Ok(())
}

fn validate_logical_lock_path(value: &str, max_path_bytes: u64) -> Result<(), RequestError> {
    if value.is_empty()
        || value.len() as u64 > max_path_bytes
        || value.starts_with('/')
        || value.contains('\\')
        || value.contains('%')
        || value
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
        || value.chars().any(char::is_control)
    {
        return Err(RequestError::new(
            "DEP_REQUEST_LOCK_PATH_INVALID",
            "logical lock path is absolute, traversing, or noncanonical",
        ));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
