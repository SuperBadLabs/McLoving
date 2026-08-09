use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use crate::adapter::{
    AdapterBindings, AdapterError, assemble_plan, validate_local_key, validate_lock_size,
};
use crate::plan::{Ecosystem, PackageNode, canonical_node_id, validate_exact_version};
use crate::strict_json;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct NpmPackageLock {
    name: String,
    version: String,
    lockfile_version: u8,
    requires: bool,
    packages: BTreeMap<String, NpmPackage>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NpmPackage {
    name: String,
    version: String,
    #[serde(default)]
    dependencies: BTreeMap<String, String>,
    integrity: Option<String>,
    mcloving: Option<NpmArtifactBinding>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NpmArtifactBinding {
    repository_id: String,
    artifact_path: String,
    declared_size: u64,
    sha256: String,
    attestation_key_id: Option<String>,
}

pub fn parse_npm_package_lock(
    lock_bytes: &[u8],
    bindings: &AdapterBindings,
) -> Result<crate::CanonicalPlan, AdapterError> {
    validate_lock_size(lock_bytes, "npm package")?;
    let lock: NpmPackageLock = strict_json::from_slice(lock_bytes).map_err(|error| {
        AdapterError::new(
            "DEP_NPM_LOCK_INVALID",
            format!("npm lock is not closed package-lock JSON: {error}"),
        )
    })?;
    if lock.lockfile_version != 3 || !lock.requires {
        return Err(AdapterError::new(
            "DEP_NPM_SCHEMA_MISMATCH",
            "npm lock must use package-lock v3 with requires=true",
        ));
    }
    validate_package_name(&lock.name)?;
    validate_exact_npm_version(&lock.version)?;
    let root = lock.packages.get("").ok_or_else(|| {
        AdapterError::new(
            "DEP_NPM_ROOT_MISSING",
            "npm lock does not contain the root package entry",
        )
    })?;
    if root.name != lock.name
        || root.version != lock.version
        || root.integrity.is_some()
        || root.mcloving.is_some()
    {
        return Err(AdapterError::new(
            "DEP_NPM_ROOT_INVALID",
            "npm root package does not exactly bind lock identity and dependencies",
        ));
    }

    let mut raw_by_name = BTreeMap::new();
    for (package_path, package) in lock.packages.iter().filter(|(path, _)| !path.is_empty()) {
        validate_package_name(&package.name)?;
        validate_exact_npm_version(&package.version)?;
        let expected_path = format!("node_modules/{}", package.name);
        if package_path != &expected_path {
            return Err(AdapterError::new(
                "DEP_NPM_LAYOUT_UNSUPPORTED",
                "npm v1 admits only an exact flat node_modules lock layout",
            ));
        }
        if raw_by_name.insert(package.name.as_str(), package).is_some() {
            return Err(AdapterError::new(
                "DEP_NPM_PACKAGE_DUPLICATE",
                "npm lock contains duplicate package identities",
            ));
        }
    }
    if raw_by_name.is_empty() || root.dependencies.is_empty() {
        return Err(AdapterError::new(
            "DEP_NPM_GRAPH_EMPTY",
            "npm lock must contain package nodes and root dependencies",
        ));
    }

    let mut name_to_id = BTreeMap::new();
    let mut nodes = Vec::with_capacity(raw_by_name.len());
    for (name, package) in &raw_by_name {
        let artifact = package.mcloving.as_ref().ok_or_else(|| {
            AdapterError::new(
                "DEP_NPM_ARTIFACT_BINDING_MISSING",
                "npm package omits its McLoving artifact binding",
            )
        })?;
        validate_integrity(package.integrity.as_deref(), &artifact.sha256)?;
        let mut node = PackageNode {
            node_id: String::new(),
            coordinate: (*name).to_owned(),
            exact_version: package.version.clone(),
            repository_id: artifact.repository_id.clone(),
            artifact_path: artifact.artifact_path.clone(),
            declared_size: artifact.declared_size,
            sha256: artifact.sha256.clone(),
            attestation_key_id: artifact.attestation_key_id.clone(),
            dependencies: Vec::new(),
        };
        node.node_id = canonical_node_id(Ecosystem::Npm, &node)?;
        name_to_id.insert(*name, node.node_id.clone());
        nodes.push(node);
    }

    for node in &mut nodes {
        let package = raw_by_name
            .get(node.coordinate.as_str())
            .expect("node was created from the package map");
        node.dependencies =
            translate_dependencies(&package.dependencies, &raw_by_name, &name_to_id)?;
    }
    let roots = translate_dependencies(&root.dependencies, &raw_by_name, &name_to_id)?;
    assemble_plan(Ecosystem::Npm, lock_bytes, bindings, nodes, roots)
}

fn translate_dependencies(
    dependencies: &BTreeMap<String, String>,
    packages: &BTreeMap<&str, &NpmPackage>,
    name_to_id: &BTreeMap<&str, String>,
) -> Result<Vec<String>, AdapterError> {
    let mut translated = BTreeSet::new();
    for (name, expected_version) in dependencies {
        validate_package_name(name)?;
        validate_exact_npm_version(expected_version)?;
        let package = packages.get(name.as_str()).ok_or_else(|| {
            AdapterError::new(
                "DEP_NPM_GRAPH_NODE_MISSING",
                "npm dependency references a missing package",
            )
        })?;
        if package.version != *expected_version {
            return Err(AdapterError::new(
                "DEP_NPM_VERSION_SUBSTITUTION",
                "npm dependency version does not match its package node",
            ));
        }
        let node_id = name_to_id
            .get(name.as_str())
            .expect("package and node maps are constructed together");
        translated.insert(node_id.clone());
    }
    Ok(translated.into_iter().collect())
}

fn validate_package_name(value: &str) -> Result<(), AdapterError> {
    validate_local_key(value)?;
    let valid_unscoped = |name: &str| {
        !name.is_empty()
            && name.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'-' | b'_')
            })
    };
    let valid = if let Some(scoped) = value.strip_prefix('@') {
        scoped
            .split_once('/')
            .is_some_and(|(scope, name)| valid_unscoped(scope) && valid_unscoped(name))
    } else {
        valid_unscoped(value)
    };
    if !valid {
        return Err(AdapterError::new(
            "DEP_NPM_PACKAGE_NAME_INVALID",
            "npm package name is not canonical lowercase registry syntax",
        ));
    }
    Ok(())
}

fn validate_exact_npm_version(value: &str) -> Result<(), AdapterError> {
    validate_exact_version(Ecosystem::Npm, value).map_err(Into::into)
}

fn validate_integrity(integrity: Option<&str>, sha256: &str) -> Result<(), AdapterError> {
    let expected = format!("sha256-{sha256}");
    if integrity != Some(expected.as_str()) {
        return Err(AdapterError::new(
            "DEP_NPM_INTEGRITY_INVALID",
            "npm integrity must contain the exact configured lowercase SHA-256 extension",
        ));
    }
    Ok(())
}
