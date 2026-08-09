use std::collections::{BTreeMap, BTreeSet};

use crate::adapter::{
    AdapterBindings, AdapterError, assemble_plan, validate_local_key, validate_lock_size,
};
use crate::plan::{Ecosystem, PackageNode, canonical_node_id};

#[derive(Debug)]
struct Requirement {
    name: String,
    version: String,
    repository_id: String,
    artifact_path: String,
    declared_size: u64,
    sha256: String,
    attestation_key_id: Option<String>,
    dependencies: Vec<String>,
    root: bool,
}

pub fn parse_pypi_requirements(
    lock_bytes: &[u8],
    bindings: &AdapterBindings,
) -> Result<crate::CanonicalPlan, AdapterError> {
    validate_lock_size(lock_bytes, "PyPI requirements")?;
    let text = std::str::from_utf8(lock_bytes).map_err(|_| {
        AdapterError::new(
            "DEP_PYPI_LOCK_INVALID",
            "PyPI requirements must be canonical UTF-8",
        )
    })?;
    if text.contains('\r') || !text.ends_with('\n') {
        return Err(AdapterError::new(
            "DEP_PYPI_LOCK_INVALID",
            "PyPI requirements must use LF lines and end with LF",
        ));
    }

    let mut requirements = BTreeMap::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let requirement = parse_requirement_line(line)?;
        let key = requirement_key(&requirement.name, &requirement.version);
        if requirements.insert(key, requirement).is_some() {
            return Err(AdapterError::new(
                "DEP_PYPI_REQUIREMENT_DUPLICATE",
                "PyPI requirements contain a duplicate name and version",
            ));
        }
    }
    if requirements.is_empty() || requirements.values().all(|requirement| !requirement.root) {
        return Err(AdapterError::new(
            "DEP_PYPI_GRAPH_EMPTY",
            "PyPI requirements must contain packages and at least one root",
        ));
    }

    let mut key_to_id = BTreeMap::new();
    let mut nodes = Vec::with_capacity(requirements.len());
    for (key, requirement) in &requirements {
        let mut node = PackageNode {
            node_id: String::new(),
            coordinate: requirement.name.clone(),
            exact_version: requirement.version.clone(),
            repository_id: requirement.repository_id.clone(),
            artifact_path: requirement.artifact_path.clone(),
            declared_size: requirement.declared_size,
            sha256: requirement.sha256.clone(),
            attestation_key_id: requirement.attestation_key_id.clone(),
            dependencies: Vec::new(),
        };
        node.node_id = canonical_node_id(Ecosystem::Pypi, &node)?;
        key_to_id.insert(key.as_str(), node.node_id.clone());
        nodes.push(node);
    }

    let mut roots = BTreeSet::new();
    for node in &mut nodes {
        let key = requirement_key(&node.coordinate, &node.exact_version);
        let requirement = requirements
            .get(&key)
            .expect("node was created from the requirement map");
        node.dependencies = translate_dependencies(&requirement.dependencies, &key_to_id)?;
        if requirement.root {
            roots.insert(node.node_id.clone());
        }
    }
    assemble_plan(
        Ecosystem::Pypi,
        lock_bytes,
        bindings,
        nodes,
        roots.into_iter().collect(),
    )
}

fn parse_requirement_line(line: &str) -> Result<Requirement, AdapterError> {
    if line.as_bytes().first().is_some_and(u8::is_ascii_whitespace)
        || line.as_bytes().last().is_some_and(u8::is_ascii_whitespace)
        || line
            .chars()
            .any(|character| matches!(character, ';' | '[' | ']' | '\\' | '#'))
        || line.chars().any(char::is_control)
    {
        return Err(unsupported("PyPI requirement contains unsupported syntax"));
    }
    let mut tokens = line.split_ascii_whitespace();
    let coordinate = tokens
        .next()
        .ok_or_else(|| unsupported("empty requirement"))?;
    let (name, version) = coordinate
        .split_once("==")
        .filter(|(name, version)| !name.contains('=') && !version.contains('='))
        .ok_or_else(|| unsupported("PyPI requirement must use one exact == version"))?;
    validate_normalized_name(name)?;
    validate_exact_pypi_version(version)?;

    let mut options = BTreeMap::new();
    let mut root = false;
    for token in tokens {
        if token == "--root" {
            if root {
                return Err(unsupported("duplicate PyPI --root option"));
            }
            root = true;
            continue;
        }
        let (option, value) = token
            .split_once('=')
            .filter(|(_, value)| !value.is_empty())
            .ok_or_else(|| unsupported("PyPI option must use --name=value syntax"))?;
        if options.insert(option, value).is_some() {
            return Err(unsupported("duplicate PyPI requirement option"));
        }
    }
    for option in options.keys() {
        if !matches!(
            *option,
            "--repository" | "--artifact" | "--size" | "--hash" | "--attestation" | "--depends"
        ) {
            return Err(unsupported("unknown PyPI requirement option"));
        }
    }
    let repository_id = required_option(&options, "--repository")?;
    validate_local_key(repository_id)?;
    let artifact_path = required_option(&options, "--artifact")?;
    let declared_size = required_option(&options, "--size")?
        .parse::<u64>()
        .ok()
        .filter(|size| *size > 0)
        .ok_or_else(|| unsupported("PyPI artifact size must be a positive integer"))?;
    let hash = required_option(&options, "--hash")?;
    let sha256 = hash
        .strip_prefix("sha256:")
        .ok_or_else(|| unsupported("PyPI hash must use the exact sha256:<lowercase-hex> form"))?;
    if sha256.len() != 64
        || !sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(unsupported("PyPI SHA-256 is not canonical lowercase hex"));
    }
    let attestation_key_id = options
        .get("--attestation")
        .map(|value| (*value).to_owned());
    if let Some(value) = &attestation_key_id {
        validate_local_key(value)?;
    }
    let dependencies = options
        .get("--depends")
        .map_or_else(|| Ok(Vec::new()), |value| parse_dependencies(value))?;
    Ok(Requirement {
        name: name.to_owned(),
        version: version.to_owned(),
        repository_id: repository_id.to_owned(),
        artifact_path: artifact_path.to_owned(),
        declared_size,
        sha256: sha256.to_owned(),
        attestation_key_id,
        dependencies,
        root,
    })
}

fn parse_dependencies(value: &str) -> Result<Vec<String>, AdapterError> {
    let mut dependencies = BTreeSet::new();
    for coordinate in value.split(',') {
        let (name, version) = coordinate
            .split_once("==")
            .filter(|(name, version)| !name.contains('=') && !version.contains('='))
            .ok_or_else(|| unsupported("PyPI dependency must use one exact == version"))?;
        validate_normalized_name(name)?;
        validate_exact_pypi_version(version)?;
        if !dependencies.insert(requirement_key(name, version)) {
            return Err(unsupported("duplicate PyPI dependency"));
        }
    }
    Ok(dependencies.into_iter().collect())
}

fn translate_dependencies(
    dependencies: &[String],
    key_to_id: &BTreeMap<&str, String>,
) -> Result<Vec<String>, AdapterError> {
    dependencies
        .iter()
        .map(|dependency| {
            key_to_id.get(dependency.as_str()).cloned().ok_or_else(|| {
                AdapterError::new(
                    "DEP_PYPI_GRAPH_NODE_MISSING",
                    "PyPI dependency references a missing requirement",
                )
            })
        })
        .collect()
}

fn required_option<'a>(
    options: &'a BTreeMap<&str, &str>,
    name: &str,
) -> Result<&'a str, AdapterError> {
    options
        .get(name)
        .copied()
        .ok_or_else(|| unsupported("PyPI requirement omits required provenance metadata"))
}

fn validate_normalized_name(value: &str) -> Result<(), AdapterError> {
    validate_local_key(value)?;
    if value.starts_with('-')
        || value.ends_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(unsupported(
            "PyPI package name is not normalized PEP 503 syntax",
        ));
    }
    Ok(())
}

fn validate_exact_pypi_version(value: &str) -> Result<(), AdapterError> {
    if value.is_empty()
        || value.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'!' | b'+' | b'-' | b'_'))
        })
    {
        return Err(AdapterError::new(
            "DEP_VERSION_MUTABLE",
            "PyPI version is not an exact canonical version",
        ));
    }
    Ok(())
}

fn requirement_key(name: &str, version: &str) -> String {
    format!("{name}=={version}")
}

fn unsupported(message: impl Into<String>) -> AdapterError {
    AdapterError::new("DEP_PYPI_SYNTAX_UNSUPPORTED", message)
}
