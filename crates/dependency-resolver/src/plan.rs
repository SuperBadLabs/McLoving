use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::PLAN_SCHEMA_VERSION;

const MAX_BINDING_BYTES: usize = 1_024;
const MAX_COORDINATE_BYTES: usize = 1_024;
const MAX_VERSION_BYTES: usize = 256;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_REPOSITORIES: usize = 64;
const MAX_NODES: usize = 100_000;
const MAX_EDGES: usize = 1_000_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Ecosystem {
    Maven,
    Npm,
    Pypi,
}

impl Ecosystem {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Maven => "maven",
            Self::Npm => "npm",
            Self::Pypi => "pypi",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceTrustClass {
    Trusted,
    Untrusted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryBinding {
    pub repository_id: String,
    pub credentialed: bool,
    pub permits_untrusted_source: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageNode {
    pub node_id: String,
    pub coordinate: String,
    pub exact_version: String,
    pub repository_id: String,
    pub artifact_path: String,
    pub declared_size: u64,
    pub sha256: String,
    pub attestation_key_id: Option<String>,
    pub dependencies: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalPlan {
    pub schema_version: String,
    pub ecosystem: Ecosystem,
    pub adapter_id: String,
    pub adapter_sha256: String,
    pub source_tree_sha256: String,
    pub lock_sha256: String,
    pub resolver_toolchain_id: String,
    pub resolver_toolchain_sha256: String,
    pub source_trust_class: SourceTrustClass,
    pub repositories: Vec<RepositoryBinding>,
    pub nodes: Vec<PackageNode>,
    pub roots: Vec<String>,
    pub graph_sha256: String,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("{code}: {message}")]
pub struct PlanError {
    pub code: &'static str,
    pub message: String,
}

impl PlanError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

pub fn validate_plan(plan: &CanonicalPlan) -> Result<(), PlanError> {
    if plan.schema_version != PLAN_SCHEMA_VERSION {
        return Err(PlanError::new(
            "DEP_PLAN_SCHEMA_MISMATCH",
            "dependency plan schema is not supported",
        ));
    }
    validate_binding("adapter id", &plan.adapter_id)?;
    validate_binding("resolver toolchain id", &plan.resolver_toolchain_id)?;
    for (name, digest) in [
        ("adapter", &plan.adapter_sha256),
        ("source tree", &plan.source_tree_sha256),
        ("lock", &plan.lock_sha256),
        ("resolver toolchain", &plan.resolver_toolchain_sha256),
        ("graph", &plan.graph_sha256),
    ] {
        validate_digest(name, digest)?;
    }

    if plan.repositories.is_empty() || plan.repositories.len() > MAX_REPOSITORIES {
        return Err(PlanError::new(
            "DEP_REPOSITORY_COUNT_INVALID",
            "repository count is outside the supported bound",
        ));
    }
    if plan.nodes.is_empty() || plan.nodes.len() > MAX_NODES {
        return Err(PlanError::new(
            "DEP_NODE_COUNT_INVALID",
            "package-node count is outside the supported bound",
        ));
    }
    if plan.roots.is_empty() || plan.roots.len() > plan.nodes.len() {
        return Err(PlanError::new(
            "DEP_ROOT_COUNT_INVALID",
            "root count is outside the supported bound",
        ));
    }

    let repositories = validate_repositories(plan)?;
    let nodes = validate_nodes(plan, &repositories)?;
    validate_roots(plan, &nodes)?;
    validate_graph_reachability(plan, &nodes)?;

    let actual_graph = canonical_graph_sha256(plan)?;
    if actual_graph != plan.graph_sha256 {
        return Err(PlanError::new(
            "DEP_GRAPH_DIGEST_MISMATCH",
            "canonical graph digest does not match the declared digest",
        ));
    }
    Ok(())
}

fn validate_repositories(
    plan: &CanonicalPlan,
) -> Result<BTreeMap<&str, &RepositoryBinding>, PlanError> {
    let mut repositories = BTreeMap::new();
    let mut previous = None;
    for repository in &plan.repositories {
        validate_binding("repository id", &repository.repository_id)?;
        if previous.is_some_and(|value: &str| value >= repository.repository_id.as_str()) {
            return Err(PlanError::new(
                "DEP_REPOSITORIES_NONCANONICAL",
                "repositories must be strictly sorted and duplicate-free",
            ));
        }
        if repository.credentialed && repository.permits_untrusted_source {
            return Err(PlanError::new(
                "DEP_REPOSITORY_TRUST_INVALID",
                "a credentialed repository cannot admit untrusted source",
            ));
        }
        if plan.source_trust_class == SourceTrustClass::Untrusted
            && (!repository.permits_untrusted_source || repository.credentialed)
        {
            return Err(PlanError::new(
                "DEP_UNTRUSTED_REPOSITORY_DENIED",
                "untrusted source requested a private or credentialed repository",
            ));
        }
        previous = Some(repository.repository_id.as_str());
        repositories.insert(repository.repository_id.as_str(), repository);
    }
    Ok(repositories)
}

fn validate_nodes<'a>(
    plan: &'a CanonicalPlan,
    repositories: &BTreeMap<&str, &RepositoryBinding>,
) -> Result<BTreeMap<&'a str, &'a PackageNode>, PlanError> {
    let mut nodes = BTreeMap::new();
    let mut coordinates = BTreeSet::new();
    let mut previous = None;
    let mut edge_count = 0usize;

    for node in &plan.nodes {
        validate_digest("node", &node.node_id)?;
        validate_digest("artifact", &node.sha256)?;
        validate_coordinate(&node.coordinate)?;
        validate_exact_version(plan.ecosystem, &node.exact_version)?;
        validate_artifact_path(&node.artifact_path)?;
        validate_binding("repository id", &node.repository_id)?;
        if node.declared_size == 0 {
            return Err(PlanError::new(
                "DEP_ARTIFACT_SIZE_INVALID",
                "artifact size must be positive",
            ));
        }
        if let Some(key_id) = &node.attestation_key_id {
            validate_binding("attestation key id", key_id)?;
        }
        if !repositories.contains_key(node.repository_id.as_str()) {
            return Err(PlanError::new(
                "DEP_REPOSITORY_UNBOUND",
                "a package node references an undeclared repository",
            ));
        }
        if previous.is_some_and(|value: &str| value >= node.node_id.as_str()) {
            return Err(PlanError::new(
                "DEP_NODES_NONCANONICAL",
                "package nodes must be strictly sorted by node id",
            ));
        }
        if !coordinates.insert(node.coordinate.as_str()) {
            return Err(PlanError::new(
                "DEP_COORDINATE_CONFLICT",
                "a coordinate is bound to more than one package node",
            ));
        }
        if canonical_node_id(plan.ecosystem, node)? != node.node_id {
            return Err(PlanError::new(
                "DEP_NODE_ID_MISMATCH",
                "package node id does not match canonical node content",
            ));
        }
        validate_sorted_digests("dependency", &node.dependencies)?;
        edge_count = edge_count
            .checked_add(node.dependencies.len())
            .ok_or_else(|| {
                PlanError::new("DEP_EDGE_COUNT_INVALID", "dependency edge count overflowed")
            })?;
        if edge_count > MAX_EDGES {
            return Err(PlanError::new(
                "DEP_EDGE_COUNT_INVALID",
                "dependency edge count exceeds the supported bound",
            ));
        }
        previous = Some(node.node_id.as_str());
        nodes.insert(node.node_id.as_str(), node);
    }

    for node in &plan.nodes {
        for dependency in &node.dependencies {
            if dependency == &node.node_id {
                return Err(PlanError::new(
                    "DEP_GRAPH_SELF_EDGE",
                    "a package node cannot depend on itself",
                ));
            }
            if !nodes.contains_key(dependency.as_str()) {
                return Err(PlanError::new(
                    "DEP_GRAPH_NODE_MISSING",
                    "a dependency edge references a missing package node",
                ));
            }
        }
    }
    Ok(nodes)
}

fn validate_roots(
    plan: &CanonicalPlan,
    nodes: &BTreeMap<&str, &PackageNode>,
) -> Result<(), PlanError> {
    validate_sorted_digests("root", &plan.roots)?;
    if plan
        .roots
        .iter()
        .any(|root| !nodes.contains_key(root.as_str()))
    {
        return Err(PlanError::new(
            "DEP_GRAPH_ROOT_MISSING",
            "a graph root references a missing package node",
        ));
    }
    Ok(())
}

fn validate_graph_reachability(
    plan: &CanonicalPlan,
    nodes: &BTreeMap<&str, &PackageNode>,
) -> Result<(), PlanError> {
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for root in &plan.roots {
        visit_node(root, nodes, &mut visiting, &mut visited)?;
    }
    if visited.len() != nodes.len() {
        return Err(PlanError::new(
            "DEP_GRAPH_UNREACHABLE_NODE",
            "the dependency graph contains a node unreachable from every root",
        ));
    }
    Ok(())
}

fn visit_node<'a>(
    node_id: &'a str,
    nodes: &BTreeMap<&'a str, &'a PackageNode>,
    visiting: &mut BTreeSet<&'a str>,
    visited: &mut BTreeSet<&'a str>,
) -> Result<(), PlanError> {
    if visited.contains(node_id) {
        return Ok(());
    }
    if !visiting.insert(node_id) {
        return Err(PlanError::new(
            "DEP_GRAPH_CYCLE",
            "the dependency graph contains a cycle",
        ));
    }
    let node = nodes.get(node_id).ok_or_else(|| {
        PlanError::new(
            "DEP_GRAPH_NODE_MISSING",
            "a dependency edge references a missing package node",
        )
    })?;
    for dependency in &node.dependencies {
        visit_node(dependency, nodes, visiting, visited)?;
    }
    visiting.remove(node_id);
    visited.insert(node_id);
    Ok(())
}

pub fn canonical_node_id(ecosystem: Ecosystem, node: &PackageNode) -> Result<String, PlanError> {
    let attestation = node.attestation_key_id.as_deref().unwrap_or("");
    Ok(domain_sha256(
        b"mcloving-dependency-node-v1",
        &[
            ecosystem.as_str().as_bytes(),
            node.coordinate.as_bytes(),
            node.exact_version.as_bytes(),
            node.repository_id.as_bytes(),
            node.artifact_path.as_bytes(),
            &node.declared_size.to_be_bytes(),
            node.sha256.as_bytes(),
            attestation.as_bytes(),
        ],
    ))
}

pub fn canonical_graph_sha256(plan: &CanonicalPlan) -> Result<String, PlanError> {
    let mut hasher = Sha256::new();
    update_segment(&mut hasher, b"mcloving-dependency-graph-v1");
    update_segment(&mut hasher, plan.ecosystem.as_str().as_bytes());
    update_segment(&mut hasher, plan.adapter_id.as_bytes());
    update_segment(&mut hasher, plan.adapter_sha256.as_bytes());
    update_segment(&mut hasher, plan.source_tree_sha256.as_bytes());
    update_segment(&mut hasher, plan.lock_sha256.as_bytes());
    update_segment(&mut hasher, plan.resolver_toolchain_id.as_bytes());
    update_segment(&mut hasher, plan.resolver_toolchain_sha256.as_bytes());
    for repository in &plan.repositories {
        update_segment(&mut hasher, b"repository");
        update_segment(&mut hasher, repository.repository_id.as_bytes());
        update_segment(&mut hasher, &[u8::from(repository.credentialed)]);
        update_segment(
            &mut hasher,
            &[u8::from(repository.permits_untrusted_source)],
        );
    }
    for node in &plan.nodes {
        update_segment(&mut hasher, b"node");
        update_segment(&mut hasher, node.node_id.as_bytes());
        for dependency in &node.dependencies {
            update_segment(&mut hasher, b"edge");
            update_segment(&mut hasher, dependency.as_bytes());
        }
    }
    for root in &plan.roots {
        update_segment(&mut hasher, b"root");
        update_segment(&mut hasher, root.as_bytes());
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn domain_sha256(domain: &[u8], segments: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    update_segment(&mut hasher, domain);
    for segment in segments {
        update_segment(&mut hasher, segment);
    }
    format!("{:x}", hasher.finalize())
}

fn update_segment(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn validate_binding(name: &str, value: &str) -> Result<(), PlanError> {
    if value.is_empty()
        || value.len() > MAX_BINDING_BYTES
        || value.chars().any(|character| character.is_control())
    {
        return Err(PlanError::new(
            "DEP_BINDING_INVALID",
            format!("{name} is empty, oversized, or control-bearing"),
        ));
    }
    Ok(())
}

fn validate_digest(name: &str, value: &str) -> Result<(), PlanError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PlanError::new(
            "DEP_DIGEST_INVALID",
            format!("{name} digest is not canonical lowercase SHA-256"),
        ));
    }
    Ok(())
}

fn validate_coordinate(value: &str) -> Result<(), PlanError> {
    if value.is_empty()
        || value.len() > MAX_COORDINATE_BYTES
        || value.chars().any(|character| {
            character.is_control() || character.is_whitespace() || character == '\\'
        })
    {
        return Err(PlanError::new(
            "DEP_COORDINATE_INVALID",
            "package coordinate is empty, oversized, or noncanonical",
        ));
    }
    Ok(())
}

pub(crate) fn validate_exact_version(ecosystem: Ecosystem, value: &str) -> Result<(), PlanError> {
    let lower = value.to_ascii_lowercase();
    let invalid_common = value.is_empty()
        || value.len() > MAX_VERSION_BYTES
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        || value.contains('*')
        || value.contains('>')
        || value.contains('<')
        || value.contains('^')
        || value.contains('~')
        || lower == "latest";
    let invalid_ecosystem = match ecosystem {
        Ecosystem::Maven => {
            lower.contains("snapshot")
                || lower == "release"
                || value.contains('$')
                || value.contains('{')
                || value.contains('}')
                || value.contains('[')
                || value.contains(']')
                || value.contains('(')
                || value.contains(')')
                || value.contains(',')
        }
        Ecosystem::Npm => !is_canonical_npm_version(value),
        Ecosystem::Pypi => !is_canonical_pypi_version(value),
    };
    if invalid_common || invalid_ecosystem {
        return Err(PlanError::new(
            "DEP_VERSION_MUTABLE",
            "package version is mutable, ranged, or noncanonical",
        ));
    }
    Ok(())
}

fn is_canonical_npm_version(value: &str) -> bool {
    let (without_build, build) = value
        .split_once('+')
        .map_or((value, None), |(left, right)| (left, Some(right)));
    if build.is_some_and(|part| !valid_identifiers(part, false))
        || without_build.matches('+').count() != 0
    {
        return false;
    }
    let (core, prerelease) = without_build
        .split_once('-')
        .map_or((without_build, None), |(left, right)| (left, Some(right)));
    if prerelease.is_some_and(|part| !valid_identifiers(part, true)) {
        return false;
    }
    let mut parts = core.split('.');
    let valid = parts.by_ref().take(3).all(canonical_numeric);
    valid && parts.next().is_none() && core.matches('.').count() == 2
}

fn valid_identifiers(value: &str, reject_numeric_leading_zero: bool) -> bool {
    !value.is_empty()
        && value.split('.').all(|identifier| {
            !identifier.is_empty()
                && identifier
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && (!reject_numeric_leading_zero
                    || !identifier.bytes().all(|byte| byte.is_ascii_digit())
                    || canonical_numeric(identifier))
        })
}

fn canonical_numeric(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
}

fn is_canonical_pypi_version(value: &str) -> bool {
    if value != value.to_ascii_lowercase()
        || value.starts_with('v')
        || value.starts_with('=')
        || value.contains('_')
        || value.contains('-')
        || value.contains("..")
        || value.ends_with(['.', '!', '+'])
        || value.matches('!').count() > 1
        || value.matches('+').count() > 1
    {
        return false;
    }
    let (public, local) = value
        .split_once('+')
        .map_or((value, None), |(left, right)| (left, Some(right)));
    if local.is_some_and(|part| {
        part.is_empty()
            || !part.split('.').all(|identifier| {
                !identifier.is_empty()
                    && identifier.bytes().all(|byte| byte.is_ascii_alphanumeric())
                    && (!identifier.bytes().all(|byte| byte.is_ascii_digit())
                        || canonical_numeric(identifier))
            })
    }) {
        return false;
    }
    let release = match public.split_once('!') {
        Some((epoch, rest)) if canonical_numeric(epoch) => rest,
        Some(_) => return false,
        None => public,
    };
    let release_end = release
        .find(|character: char| !character.is_ascii_digit() && character != '.')
        .unwrap_or(release.len());
    let release_number = &release[..release_end];
    if release_number.is_empty()
        || release_number.ends_with('.')
        || !release_number.split('.').all(canonical_numeric)
    {
        return false;
    }
    let mut suffix = &release[release_end..];
    let prerelease = suffix
        .strip_prefix("rc")
        .or_else(|| suffix.strip_prefix('a'))
        .or_else(|| suffix.strip_prefix('b'));
    if let Some(rest) = prerelease {
        let Some(rest) = consume_numeric_suffix(rest) else {
            return false;
        };
        suffix = rest;
    }
    if let Some(rest) = suffix.strip_prefix(".post") {
        let Some(rest) = consume_numeric_suffix(rest) else {
            return false;
        };
        suffix = rest;
    }
    if let Some(rest) = suffix.strip_prefix(".dev") {
        let Some(rest) = consume_numeric_suffix(rest) else {
            return false;
        };
        suffix = rest;
    }
    suffix.is_empty()
}

fn consume_numeric_suffix(value: &str) -> Option<&str> {
    let end = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    canonical_numeric(&value[..end]).then_some(&value[end..])
}

fn validate_artifact_path(value: &str) -> Result<(), PlanError> {
    if value.is_empty()
        || value.len() > MAX_PATH_BYTES
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains("//")
        || value.contains('\\')
        || value.contains('?')
        || value.contains('#')
        || value.contains('%')
        || value.contains("://")
        || value.chars().any(|character| character.is_control())
        || value
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(PlanError::new(
            "DEP_ARTIFACT_PATH_INVALID",
            "artifact path is absolute, traversing, URL-bearing, or noncanonical",
        ));
    }
    Ok(())
}

fn validate_sorted_digests(name: &str, values: &[String]) -> Result<(), PlanError> {
    let mut previous = None;
    for value in values {
        validate_digest(name, value)?;
        if previous.is_some_and(|prior: &str| prior >= value.as_str()) {
            return Err(PlanError::new(
                "DEP_GRAPH_NONCANONICAL",
                format!("{name} identities must be strictly sorted and duplicate-free"),
            ));
        }
        previous = Some(value.as_str());
    }
    Ok(())
}
