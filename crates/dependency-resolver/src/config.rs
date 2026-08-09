use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::{Host, Url};

use crate::{CONFIG_SCHEMA_VERSION, Ecosystem, PROTOCOL_VERSION};

const MAX_BINDING_BYTES: usize = 1_024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterConfig {
    pub ecosystem: Ecosystem,
    pub adapter_id: String,
    pub implementation_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryGrant {
    pub grant_id: String,
    pub version: u64,
    pub scope: String,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryConfig {
    pub repository_id: String,
    pub ecosystem: Ecosystem,
    pub base_url: String,
    pub coordinate_prefixes: Vec<String>,
    pub credential_path: Option<String>,
    pub credential_sha256: Option<String>,
    pub permits_untrusted_source: bool,
    pub attestation_key_id: String,
    pub attestation_key_path: String,
    pub attestation_key_sha256: String,
    pub private_ca_path: Option<String>,
    pub private_ca_sha256: Option<String>,
    pub grant: Option<RepositoryGrant>,
}

impl RepositoryConfig {
    pub fn credentialed(&self) -> bool {
        self.credential_sha256.is_some()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolverLimits {
    pub max_frame_bytes: u64,
    pub max_lock_bytes: u64,
    pub max_repositories: u64,
    pub max_nodes: u64,
    pub max_edges: u64,
    pub max_artifacts: u64,
    pub max_artifact_bytes: u64,
    pub max_total_artifact_bytes: u64,
    pub transport_capacity_bytes: u64,
    pub max_path_bytes: u64,
    pub max_header_bytes: u64,
    pub max_request_lifetime_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertifiedConfig {
    pub schema_version: String,
    pub protocol_version: String,
    pub configuration_id: String,
    pub deployment_id: String,
    pub operator_id: String,
    pub generation: u64,
    pub executable_sha256: String,
    pub resolver_toolchain_id: String,
    pub resolver_toolchain_sha256: String,
    pub adapters: Vec<AdapterConfig>,
    pub repositories: Vec<RepositoryConfig>,
    pub receipt_key_id: String,
    pub receipt_key_path: String,
    pub receipt_key_sha256: String,
    pub secret_marker_set_path: String,
    pub secret_marker_set_sha256: String,
    pub output_root: String,
    pub transport_root: String,
    pub limits: ResolverLimits,
    pub loopback_fixture: bool,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("{code}: {message}")]
pub struct ConfigError {
    pub code: &'static str,
    pub message: String,
}

impl ConfigError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

pub fn validate_config(config: &CertifiedConfig) -> Result<(), ConfigError> {
    if config.schema_version != CONFIG_SCHEMA_VERSION || config.protocol_version != PROTOCOL_VERSION
    {
        return Err(ConfigError::new(
            "DEP_CONFIG_SCHEMA_MISMATCH",
            "dependency configuration schema or protocol is not supported",
        ));
    }
    for (name, value) in [
        ("configuration", config.configuration_id.as_str()),
        ("deployment", config.deployment_id.as_str()),
        ("operator", config.operator_id.as_str()),
        ("resolver toolchain", config.resolver_toolchain_id.as_str()),
        ("receipt key", config.receipt_key_id.as_str()),
    ] {
        validate_binding(name, value)?;
    }
    if config.generation == 0 {
        return Err(ConfigError::new(
            "DEP_CONFIG_GENERATION_INVALID",
            "configuration generation must be positive",
        ));
    }
    for (name, value) in [
        ("executable", config.executable_sha256.as_str()),
        (
            "resolver toolchain",
            config.resolver_toolchain_sha256.as_str(),
        ),
        ("receipt key", config.receipt_key_sha256.as_str()),
        (
            "secret marker set",
            config.secret_marker_set_sha256.as_str(),
        ),
    ] {
        validate_digest(name, value)?;
    }
    validate_adapters(&config.adapters)?;
    validate_repositories(config)?;
    validate_authority_path("receipt key", &config.receipt_key_path)?;
    validate_authority_path("secret marker set", &config.secret_marker_set_path)?;
    validate_private_root("output", &config.output_root)?;
    validate_private_root("transport", &config.transport_root)?;
    if config.output_root == config.transport_root {
        return Err(ConfigError::new(
            "DEP_CONFIG_ROOT_ALIAS",
            "output and transport roots must be different",
        ));
    }
    validate_limits(&config.limits)?;
    Ok(())
}

pub fn configuration_sha256(config: &CertifiedConfig) -> Result<String, ConfigError> {
    validate_config(config)?;
    let bytes = serde_json::to_vec(config).map_err(|_| {
        ConfigError::new(
            "DEP_CONFIG_CANONICALIZATION_FAILED",
            "configuration could not be serialized canonically",
        )
    })?;
    Ok(domain_sha256(b"mcloving-dependency-config-v1", &bytes))
}

fn validate_adapters(adapters: &[AdapterConfig]) -> Result<(), ConfigError> {
    let expected = [Ecosystem::Maven, Ecosystem::Npm, Ecosystem::Pypi];
    if adapters.len() != expected.len() {
        return Err(ConfigError::new(
            "DEP_CONFIG_ADAPTER_SET_INVALID",
            "configuration must bind exactly one v1 adapter per ecosystem",
        ));
    }
    for (adapter, ecosystem) in adapters.iter().zip(expected) {
        if adapter.ecosystem != ecosystem {
            return Err(ConfigError::new(
                "DEP_CONFIG_ADAPTER_SET_INVALID",
                "adapters must be unique and sorted by ecosystem",
            ));
        }
        validate_binding("adapter", &adapter.adapter_id)?;
        validate_digest("adapter implementation", &adapter.implementation_sha256)?;
    }
    Ok(())
}

fn validate_repositories(config: &CertifiedConfig) -> Result<(), ConfigError> {
    if config.repositories.is_empty()
        || config.repositories.len() as u64 > config.limits.max_repositories
    {
        return Err(ConfigError::new(
            "DEP_CONFIG_REPOSITORY_COUNT_INVALID",
            "repository count is outside the configured bound",
        ));
    }
    let mut previous = None;
    let mut origins = BTreeSet::new();
    for repository in &config.repositories {
        validate_binding("repository", &repository.repository_id)?;
        if previous.is_some_and(|value: &str| value >= repository.repository_id.as_str()) {
            return Err(ConfigError::new(
                "DEP_CONFIG_REPOSITORIES_NONCANONICAL",
                "repositories must be strictly sorted and duplicate-free",
            ));
        }
        previous = Some(repository.repository_id.as_str());
        validate_repository_url(config, repository, &mut origins)?;
        validate_prefixes(&repository.coordinate_prefixes)?;
        validate_binding("attestation key", &repository.attestation_key_id)?;
        validate_authority_path("attestation key", &repository.attestation_key_path)?;
        validate_digest("attestation key", &repository.attestation_key_sha256)?;
        match (
            repository.credential_path.as_deref(),
            repository.credential_sha256.as_deref(),
        ) {
            (Some(path), Some(digest)) => {
                validate_authority_path("repository credential", path)?;
                validate_digest("repository credential", digest)?;
            }
            (None, None) => {}
            _ => {
                return Err(ConfigError::new(
                    "DEP_CONFIG_CREDENTIAL_BINDING_INVALID",
                    "repository credential path and digest must be configured together",
                ));
            }
        }
        if repository.credentialed() && repository.permits_untrusted_source {
            return Err(ConfigError::new(
                "DEP_CONFIG_REPOSITORY_TRUST_INVALID",
                "credentialed repository cannot permit untrusted source",
            ));
        }
        match (
            repository.private_ca_path.as_deref(),
            repository.private_ca_sha256.as_deref(),
        ) {
            (Some(path), Some(digest)) => {
                validate_authority_path("private CA", path)?;
                validate_digest("private CA", digest)?;
            }
            (None, None) => {}
            _ => {
                return Err(ConfigError::new(
                    "DEP_CONFIG_CA_BINDING_INVALID",
                    "private CA path and digest must be configured together",
                ));
            }
        }
        if let Some(grant) = &repository.grant {
            validate_binding("grant", &grant.grant_id)?;
            validate_binding("grant scope", &grant.scope)?;
            if grant.version == 0 || grant.expires_at_unix_ms == 0 {
                return Err(ConfigError::new(
                    "DEP_CONFIG_GRANT_INVALID",
                    "repository grant version and expiry must be positive",
                ));
            }
        }
    }
    Ok(())
}

fn validate_repository_url(
    config: &CertifiedConfig,
    repository: &RepositoryConfig,
    origins: &mut BTreeSet<String>,
) -> Result<(), ConfigError> {
    let url = Url::parse(&repository.base_url).map_err(|_| {
        ConfigError::new(
            "DEP_CONFIG_REPOSITORY_URL_INVALID",
            "repository base URL is invalid",
        )
    })?;
    if url.as_str() != repository.base_url
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.path().ends_with('/')
    {
        return Err(ConfigError::new(
            "DEP_CONFIG_REPOSITORY_URL_INVALID",
            "repository URL contains authority-bearing or noncanonical components",
        ));
    }
    let loopback = match url.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        _ => false,
    };
    match url.scheme() {
        "https" if repository.private_ca_sha256.is_some() => {}
        "http" if config.loopback_fixture && loopback && repository.private_ca_sha256.is_none() => {
        }
        _ => {
            return Err(ConfigError::new(
                "DEP_CONFIG_REPOSITORY_TLS_INVALID",
                "repository requires HTTPS with pinned CA or explicit cleartext loopback fixture",
            ));
        }
    }
    let origin = url.origin().ascii_serialization();
    if !origins.insert(origin) {
        return Err(ConfigError::new(
            "DEP_CONFIG_REPOSITORY_ORIGIN_DUPLICATE",
            "one origin cannot be assigned to multiple repositories",
        ));
    }
    Ok(())
}

fn validate_prefixes(prefixes: &[String]) -> Result<(), ConfigError> {
    if prefixes.is_empty() {
        return Err(ConfigError::new(
            "DEP_CONFIG_PREFIX_SET_INVALID",
            "repository coordinate prefix set cannot be empty",
        ));
    }
    let mut previous = None;
    for prefix in prefixes {
        validate_binding("coordinate prefix", prefix)?;
        if prefix.chars().any(char::is_whitespace)
            || previous.is_some_and(|value: &str| value >= prefix.as_str())
        {
            return Err(ConfigError::new(
                "DEP_CONFIG_PREFIX_SET_INVALID",
                "coordinate prefixes must be canonical, sorted, and duplicate-free",
            ));
        }
        previous = Some(prefix.as_str());
    }
    Ok(())
}

fn validate_private_root(name: &str, value: &str) -> Result<(), ConfigError> {
    let path = Path::new(value);
    let normalized = path.components().collect::<std::path::PathBuf>();
    if value.len() > 4_096
        || !path.is_absolute()
        || normalized.to_str() != Some(value)
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(ConfigError::new(
            "DEP_CONFIG_ROOT_INVALID",
            format!("{name} root is not an absolute canonical path"),
        ));
    }
    Ok(())
}

fn validate_authority_path(name: &str, value: &str) -> Result<(), ConfigError> {
    let path = Path::new(value);
    let normalized = path.components().collect::<std::path::PathBuf>();
    if value.len() > 4_096
        || !path.is_absolute()
        || normalized.to_str() != Some(value)
        || value.ends_with('/')
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(ConfigError::new(
            "DEP_CONFIG_AUTHORITY_PATH_INVALID",
            format!("{name} path is not an absolute canonical file path"),
        ));
    }
    Ok(())
}

fn validate_limits(limits: &ResolverLimits) -> Result<(), ConfigError> {
    let values = [
        limits.max_frame_bytes,
        limits.max_lock_bytes,
        limits.max_repositories,
        limits.max_nodes,
        limits.max_edges,
        limits.max_artifacts,
        limits.max_artifact_bytes,
        limits.max_total_artifact_bytes,
        limits.transport_capacity_bytes,
        limits.max_path_bytes,
        limits.max_header_bytes,
        limits.max_request_lifetime_ms,
    ];
    if values.contains(&0)
        || limits.max_frame_bytes > 1_048_576
        || limits.max_lock_bytes > limits.max_frame_bytes
        || limits.max_artifacts > limits.max_nodes
        || limits.max_artifact_bytes > limits.max_total_artifact_bytes
        || limits.max_total_artifact_bytes > limits.transport_capacity_bytes
    {
        return Err(ConfigError::new(
            "DEP_CONFIG_LIMITS_INVALID",
            "resolver limits are zero, internally inconsistent, or exceed the protocol frame cap",
        ));
    }
    Ok(())
}

pub(crate) fn repositories_by_id(config: &CertifiedConfig) -> BTreeMap<&str, &RepositoryConfig> {
    config
        .repositories
        .iter()
        .map(|repository| (repository.repository_id.as_str(), repository))
        .collect()
}

pub(crate) fn validate_binding(name: &str, value: &str) -> Result<(), ConfigError> {
    if value.is_empty() || value.len() > MAX_BINDING_BYTES || value.chars().any(char::is_control) {
        return Err(ConfigError::new(
            "DEP_CONFIG_BINDING_INVALID",
            format!("{name} binding is empty, oversized, or control-bearing"),
        ));
    }
    Ok(())
}

pub(crate) fn validate_digest(name: &str, value: &str) -> Result<(), ConfigError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ConfigError::new(
            "DEP_CONFIG_DIGEST_INVALID",
            format!("{name} digest is not canonical lowercase SHA-256"),
        ));
    }
    Ok(())
}

fn domain_sha256(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}
