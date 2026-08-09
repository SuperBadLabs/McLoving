use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::PLAN_SCHEMA_VERSION;
use crate::plan::{
    CanonicalPlan, Ecosystem, PackageNode, PlanError, RepositoryBinding, SourceTrustClass,
    canonical_graph_sha256, canonical_node_id, validate_plan,
};
use crate::strict_json;

const MAVEN_LOCK_SCHEMA_VERSION: &str = "mcloving.maven-lock/v1";
const MAX_LOCK_BYTES: usize = 1_048_576;
const MAX_LOCAL_KEY_BYTES: usize = 1_024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterBindings {
    pub adapter_id: String,
    pub adapter_sha256: String,
    pub source_tree_sha256: String,
    pub resolver_toolchain_id: String,
    pub resolver_toolchain_sha256: String,
    pub source_trust_class: SourceTrustClass,
    pub repositories: Vec<RepositoryBinding>,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("{code}: {message}")]
pub struct AdapterError {
    pub code: &'static str,
    pub message: String,
}

impl AdapterError {
    pub(crate) fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl From<PlanError> for AdapterError {
    fn from(error: PlanError) -> Self {
        Self::new(error.code, error.message)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MavenLock {
    schema_version: String,
    nodes: Vec<MavenLockNode>,
    roots: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MavenLockNode {
    key: String,
    group: String,
    artifact: String,
    artifact_type: String,
    classifier: Option<String>,
    version: String,
    repository_id: String,
    artifact_path: String,
    declared_size: u64,
    sha256: String,
    attestation_key_id: Option<String>,
    dependencies: Vec<String>,
}

pub fn parse_maven_lock(
    lock_bytes: &[u8],
    bindings: &AdapterBindings,
) -> Result<CanonicalPlan, AdapterError> {
    if lock_bytes.is_empty() || lock_bytes.len() > MAX_LOCK_BYTES {
        return Err(AdapterError::new(
            "DEP_LOCK_SIZE_INVALID",
            "Maven lock bytes are empty or exceed the adapter bound",
        ));
    }
    let lock: MavenLock = strict_json::from_slice(lock_bytes).map_err(|error| {
        AdapterError::new(
            "DEP_MAVEN_LOCK_INVALID",
            format!("Maven lock is not closed canonical JSON: {error}"),
        )
    })?;
    if lock.schema_version != MAVEN_LOCK_SCHEMA_VERSION {
        return Err(AdapterError::new(
            "DEP_MAVEN_SCHEMA_MISMATCH",
            "Maven lock schema is not supported",
        ));
    }
    if lock.nodes.is_empty() || lock.roots.is_empty() {
        return Err(AdapterError::new(
            "DEP_MAVEN_GRAPH_EMPTY",
            "Maven lock must contain nodes and roots",
        ));
    }

    let mut raw_by_key = BTreeMap::new();
    for node in &lock.nodes {
        validate_local_key(&node.key)?;
        if raw_by_key.insert(node.key.as_str(), node).is_some() {
            return Err(AdapterError::new(
                "DEP_MAVEN_KEY_DUPLICATE",
                "Maven lock node keys must be unique",
            ));
        }
        validate_sorted_unique_keys(&node.dependencies, "dependency")?;
    }
    validate_sorted_unique_keys(&lock.roots, "root")?;

    let mut key_to_id = BTreeMap::new();
    let mut nodes = Vec::with_capacity(lock.nodes.len());
    for raw in &lock.nodes {
        let coordinate = maven_coordinate(raw)?;
        let mut node = PackageNode {
            node_id: String::new(),
            coordinate,
            exact_version: raw.version.clone(),
            repository_id: raw.repository_id.clone(),
            artifact_path: raw.artifact_path.clone(),
            declared_size: raw.declared_size,
            sha256: raw.sha256.clone(),
            attestation_key_id: raw.attestation_key_id.clone(),
            dependencies: Vec::new(),
        };
        node.node_id = canonical_node_id(Ecosystem::Maven, &node)?;
        if key_to_id
            .insert(raw.key.as_str(), node.node_id.clone())
            .is_some()
        {
            return Err(AdapterError::new(
                "DEP_MAVEN_KEY_DUPLICATE",
                "Maven lock node keys must be unique",
            ));
        }
        nodes.push(node);
    }

    for (raw, node) in lock.nodes.iter().zip(&mut nodes) {
        node.dependencies = translate_keys(&raw.dependencies, &key_to_id, "dependency")?;
    }
    nodes.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    let roots = translate_keys(&lock.roots, &key_to_id, "root")?;

    let mut plan = CanonicalPlan {
        schema_version: PLAN_SCHEMA_VERSION.to_owned(),
        ecosystem: Ecosystem::Maven,
        adapter_id: bindings.adapter_id.clone(),
        adapter_sha256: bindings.adapter_sha256.clone(),
        source_tree_sha256: bindings.source_tree_sha256.clone(),
        lock_sha256: sha256_hex(lock_bytes),
        resolver_toolchain_id: bindings.resolver_toolchain_id.clone(),
        resolver_toolchain_sha256: bindings.resolver_toolchain_sha256.clone(),
        source_trust_class: bindings.source_trust_class,
        repositories: bindings.repositories.clone(),
        nodes,
        roots,
        graph_sha256: String::new(),
    };
    plan.graph_sha256 = canonical_graph_sha256(&plan)?;
    validate_plan(&plan)?;
    Ok(plan)
}

fn maven_coordinate(node: &MavenLockNode) -> Result<String, AdapterError> {
    for (name, value) in [
        ("group", node.group.as_str()),
        ("artifact", node.artifact.as_str()),
        ("artifact type", node.artifact_type.as_str()),
    ] {
        validate_maven_coordinate_part(name, value)?;
    }
    if let Some(classifier) = &node.classifier {
        validate_maven_coordinate_part("classifier", classifier)?;
        Ok(format!(
            "{}:{}:{}:{}",
            node.group, node.artifact, node.artifact_type, classifier
        ))
    } else {
        Ok(format!(
            "{}:{}:{}",
            node.group, node.artifact, node.artifact_type
        ))
    }
}

fn validate_maven_coordinate_part(name: &str, value: &str) -> Result<(), AdapterError> {
    if value.is_empty()
        || value.len() > MAX_LOCAL_KEY_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(AdapterError::new(
            "DEP_MAVEN_COORDINATE_INVALID",
            format!("Maven {name} is empty or noncanonical"),
        ));
    }
    Ok(())
}

pub(crate) fn validate_local_key(value: &str) -> Result<(), AdapterError> {
    if value.is_empty()
        || value.len() > MAX_LOCAL_KEY_BYTES
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(AdapterError::new(
            "DEP_MAVEN_KEY_INVALID",
            "Maven lock key is empty, oversized, or control-bearing",
        ));
    }
    Ok(())
}

fn validate_sorted_unique_keys(values: &[String], name: &str) -> Result<(), AdapterError> {
    let mut previous = None;
    for value in values {
        validate_local_key(value)?;
        if previous.is_some_and(|prior: &str| prior >= value.as_str()) {
            return Err(AdapterError::new(
                "DEP_MAVEN_GRAPH_NONCANONICAL",
                format!("Maven {name} keys must be strictly sorted and duplicate-free"),
            ));
        }
        previous = Some(value.as_str());
    }
    Ok(())
}

fn translate_keys(
    values: &[String],
    key_to_id: &BTreeMap<&str, String>,
    name: &str,
) -> Result<Vec<String>, AdapterError> {
    let mut translated = BTreeSet::new();
    for value in values {
        let node_id = key_to_id.get(value.as_str()).ok_or_else(|| {
            AdapterError::new(
                "DEP_MAVEN_GRAPH_NODE_MISSING",
                format!("Maven {name} references an unknown node key"),
            )
        })?;
        if !translated.insert(node_id.clone()) {
            return Err(AdapterError::new(
                "DEP_MAVEN_GRAPH_NONCANONICAL",
                format!("Maven {name} maps to a duplicate canonical node"),
            ));
        }
    }
    Ok(translated.into_iter().collect())
}

pub(crate) fn assemble_plan(
    ecosystem: Ecosystem,
    lock_bytes: &[u8],
    bindings: &AdapterBindings,
    mut nodes: Vec<PackageNode>,
    mut roots: Vec<String>,
) -> Result<CanonicalPlan, AdapterError> {
    nodes.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    roots.sort();
    let mut plan = CanonicalPlan {
        schema_version: PLAN_SCHEMA_VERSION.to_owned(),
        ecosystem,
        adapter_id: bindings.adapter_id.clone(),
        adapter_sha256: bindings.adapter_sha256.clone(),
        source_tree_sha256: bindings.source_tree_sha256.clone(),
        lock_sha256: sha256_hex(lock_bytes),
        resolver_toolchain_id: bindings.resolver_toolchain_id.clone(),
        resolver_toolchain_sha256: bindings.resolver_toolchain_sha256.clone(),
        source_trust_class: bindings.source_trust_class,
        repositories: bindings.repositories.clone(),
        nodes,
        roots,
        graph_sha256: String::new(),
    };
    plan.graph_sha256 = canonical_graph_sha256(&plan)?;
    validate_plan(&plan)?;
    Ok(plan)
}

pub(crate) fn validate_lock_size(lock_bytes: &[u8], ecosystem: &str) -> Result<(), AdapterError> {
    if lock_bytes.is_empty() || lock_bytes.len() > MAX_LOCK_BYTES {
        return Err(AdapterError::new(
            "DEP_LOCK_SIZE_INVALID",
            format!("{ecosystem} lock bytes are empty or exceed the adapter bound"),
        ));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
