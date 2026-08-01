//! Deny-authority admission for prefetched Jenkins shared-library sources.
//!
//! The worker receives no SCM or credential authority and never evaluates
//! Groovy. It verifies a corpus-bound strict-YAML ledger and immutable,
//! normalized `vars`, `src`, and `resources` trees only.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

use mcloving_pipeline_ir::{ParseLimits, parse_strict};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SCHEMA: &str = "mcloving.jenkins.shared-library-ledger/v1";
pub const LOCK_SCHEMA: &str = "mcloving.jenkins.shared-library-lock/v1";
pub const LEDGER_ID: &str = "mario-jenkins-oracle-228-shared-libraries-v1";
pub const LEDGER_SHA256: &str = "fb6ff37c33aba6288e9632e5d0993adf634d840c5fe21f6345dea5350f28e35b";
pub const LEDGER_SEMANTIC_SHA256: &str =
    "f925714595d48efcf29ea9c64696a99cd361b6a4a9b847c2d96b807a63add309";
pub const INVENTORY_MANIFEST_SHA256: &str =
    "8cf682d06522b050c97c504c1a516f33463bd906e4ee10c3d6a1c38c03c6ec07";
pub const JOB_GRAPH_SHA256: &str =
    "76ae2e85d7d8a5a1410826b7b4556a36407bba726ac2baf6efe67062888b99ab";
pub const RUNTIME_DEPENDENCIES_SHA256: &str =
    "238ed4cc59ff67bbb1dc40bb1bd3ec28dce914c4dffd701f1a8505d760ba11a4";
pub const CORPUS_MANIFEST_SHA256: &str =
    "a28283de801854836887e9bc6cffd43c10bb078dbeff343fdf92d19b470a74c2";
pub const SOURCE_MANIFEST_SHA256: &str =
    "3f95c70e04ef72dc107e7bb6f031679cfc56e5cf44e12948b89c98baacd7db06";
const MAX_LEDGER_BYTES: usize = 262_144;
const MAX_LOCK_BYTES: usize = 16_384;
const MAX_README_BYTES: usize = 65_536;
const MAX_SOURCE_FILES: u64 = 20_000;
const MAX_SOURCE_DIRECTORIES: u64 = 20_000;
const MAX_SOURCE_DEPTH: usize = 64;
const MAX_SOURCE_BYTES: u64 = 128 * 1024 * 1024;
const BUNDLE_FILES: [&str; 3] = ["README.md", "ledger.lock.yaml", "ledger.yaml"];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerReceipt {
    pub observations: usize,
    pub live_observations: usize,
    pub resolutions: usize,
    pub executable: u64,
    pub ledger_sha256: String,
    pub semantic_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceReceipt {
    pub resolutions: usize,
    pub files: u64,
    pub bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorpusReceipt {
    pub observations: usize,
    pub files: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceTreeReceipt {
    pub tree_sha256: String,
    pub namespaces: Vec<NamespaceReceipt>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceReceipt {
    pub name: &'static str,
    pub present: bool,
    pub files: u64,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LibraryError {
    pub code: &'static str,
    pub message: String,
}

impl LibraryError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for LibraryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for LibraryError {}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    schema: String,
    ledger_id: String,
    ledger_version: u64,
    binding: Binding,
    policy: Policy,
    observations: Vec<Observation>,
    resolutions: Vec<Resolution>,
    coverage: Coverage,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    controller_id: String,
    inventory_manifest_sha256: String,
    job_graph_sha256: String,
    runtime_dependencies_sha256: String,
    corpus_manifest_sha256: String,
    source_manifest_sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    scm_network: Disposition,
    scm_credentials: Disposition,
    groovy_evaluation: Disposition,
    controller_execution: Disposition,
    unresolved_library: Disposition,
    source_input: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Disposition {
    Forbidden,
    Unsupported,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    observation_id: String,
    job_id: String,
    source_file: String,
    source_sha256: String,
    line: u64,
    syntax: Syntax,
    evidence: Evidence,
    reference: String,
    load_phase: LoadPhase,
    sandbox: Requirement,
    cps: Requirement,
    plugin_dependencies: Vec<String>,
    credential_dependency: CredentialDependency,
    resolution_id: Option<String>,
    disposition: ObservationDisposition,
    reason: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Syntax {
    StaticAnnotation,
    RuntimeCall,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Evidence {
    Live,
    CommentFalsePositive,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum LoadPhase {
    CompileTime,
    Runtime,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Requirement {
    Required,
    Unknown,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum CredentialDependency {
    PublicPrefetched,
    ControllerMappingRequired,
    DynamicUnresolved,
    ScmReferenceUnresolved,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ObservationDisposition {
    SourceVerifiedUnsupported,
    UnresolvedUnsupported,
    CommentOnly,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Resolution {
    resolution_id: String,
    reference: String,
    repository: String,
    requested_ref: String,
    commit_sha1: String,
    tree_sha256: String,
    namespaces: Vec<NamespaceDigest>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NamespaceDigest {
    name: Namespace,
    present: bool,
    files: u64,
    bytes: u64,
    sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
enum Namespace {
    Vars,
    Src,
    Resources,
}

impl Namespace {
    fn name(self) -> &'static str {
        match self {
            Self::Vars => "vars",
            Self::Src => "src",
            Self::Resources => "resources",
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Coverage {
    corpus_sources: u64,
    indexed_occurrences: u64,
    indexed_distinct_references: u64,
    corrected_live_occurrences: u64,
    comment_false_positives: u64,
    resolved_references: u64,
    resolved_live_occurrences: u64,
    executable_cases: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerLock {
    schema: String,
    ledger_id: String,
    ledger_version: u64,
    ledger_sha256: String,
    semantic_sha256: String,
    readme_sha256: String,
    inventory_manifest_sha256: String,
    corpus_manifest_sha256: String,
    source_manifest_sha256: String,
}

pub fn digest_ledger_file(path: &Path) -> Result<(String, String), LibraryError> {
    let bytes = read_regular(path.to_path_buf(), MAX_LEDGER_BYTES)?;
    let ledger = parse_and_validate(&bytes)?;
    Ok((sha256_hex(&bytes), semantic_digest(&ledger)?))
}

pub fn verify_bundle(root: &Path) -> Result<LedgerReceipt, LibraryError> {
    load_bundle(root).map(|(_, receipt)| receipt)
}

fn load_bundle(root: &Path) -> Result<(Ledger, LedgerReceipt), LibraryError> {
    validate_exact_entries(root, &BUNDLE_FILES)?;
    let readme = read_regular(root.join("README.md"), MAX_README_BYTES)?;
    let ledger_bytes = read_regular(root.join("ledger.yaml"), MAX_LEDGER_BYTES)?;
    let lock_bytes = read_regular(root.join("ledger.lock.yaml"), MAX_LOCK_BYTES)?;
    let ledger = parse_and_validate(&ledger_bytes)?;
    let ledger_sha256 = sha256_hex(&ledger_bytes);
    let semantic_sha256 = semantic_digest(&ledger)?;
    exact("ledger.sha256", &ledger_sha256, LEDGER_SHA256)?;
    exact(
        "ledger.semantic_sha256",
        &semantic_sha256,
        LEDGER_SEMANTIC_SHA256,
    )?;
    let lock: LedgerLock = parse_yaml(&lock_bytes, "E_LOCK_SCHEMA")?;
    validate_lock(
        &lock,
        &ledger_sha256,
        &semantic_sha256,
        &sha256_hex(&readme),
    )?;
    let receipt = LedgerReceipt {
        observations: ledger.observations.len(),
        live_observations: ledger
            .observations
            .iter()
            .filter(|item| item.evidence == Evidence::Live)
            .count(),
        resolutions: ledger.resolutions.len(),
        executable: ledger.coverage.executable_cases,
        ledger_sha256,
        semantic_sha256,
    };
    Ok((ledger, receipt))
}

pub fn verify_corpus(
    bundle_root: &Path,
    corpus_root: &Path,
) -> Result<CorpusReceipt, LibraryError> {
    let (ledger, _receipt) = load_bundle(bundle_root)?;
    ensure_real_directory(corpus_root, "E_CORPUS_ENTRY")?;
    verify_source_manifest(corpus_root)?;
    let mut source_files = BTreeSet::new();
    let mut locations = BTreeSet::new();
    let mut live_locations = BTreeSet::new();
    for observation in &ledger.observations {
        validate_relative(&observation.source_file)?;
        if !locations.insert((observation.source_file.as_str(), observation.line)) {
            return Err(LibraryError::new(
                "E_CORPUS_DUPLICATE",
                "duplicate source observation",
            ));
        }
        let path = corpus_root.join(&observation.source_file);
        let bytes = read_regular(path, MAX_LEDGER_BYTES)?;
        if sha256_hex(&bytes) != observation.source_sha256 {
            return Err(LibraryError::new(
                "E_CORPUS_DIGEST",
                format!(
                    "{} does not match its source digest",
                    observation.source_file
                ),
            ));
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| LibraryError::new("E_CORPUS_UTF8", "corpus source is not UTF-8"))?;
        let line_index = usize::try_from(observation.line - 1)
            .map_err(|_| LibraryError::new("E_CORPUS_LINE", "source line is out of range"))?;
        let line = text.lines().nth(line_index).ok_or_else(|| {
            LibraryError::new(
                "E_CORPUS_LINE",
                format!(
                    "{}:{} does not exist",
                    observation.source_file, observation.line
                ),
            )
        })?;
        if !line.contains(&observation.reference) {
            return Err(LibraryError::new(
                "E_CORPUS_LINE",
                format!(
                    "{}:{} does not contain the recorded reference",
                    observation.source_file, observation.line
                ),
            ));
        }
        if observation.evidence == Evidence::CommentFalsePositive
            && !line.trim_start().starts_with("//")
        {
            return Err(LibraryError::new(
                "E_CORPUS_CLASSIFICATION",
                "comment false positive is not on a comment line",
            ));
        }
        if observation.evidence == Evidence::Live && line.trim_start().starts_with("//") {
            return Err(LibraryError::new(
                "E_CORPUS_CLASSIFICATION",
                "live observation is on a comment line",
            ));
        }
        if observation.evidence == Evidence::Live {
            live_locations.insert((observation.source_file.clone(), observation.line));
        }
        source_files.insert(observation.source_file.as_str());
    }
    if live_locations != discover_live_library_locations(corpus_root)? {
        return Err(LibraryError::new(
            "E_CORPUS_COVERAGE",
            "live library locations do not match the independently discovered corpus calls",
        ));
    }
    Ok(CorpusReceipt {
        observations: ledger.observations.len(),
        files: source_files.len(),
    })
}

pub fn verify_sources(
    bundle_root: &Path,
    sources_root: &Path,
) -> Result<SourceReceipt, LibraryError> {
    let (ledger, _receipt) = load_bundle(bundle_root)?;
    ensure_read_only_directory(sources_root)?;
    let expected = ledger
        .resolutions
        .iter()
        .map(|item| item.resolution_id.as_str())
        .collect::<BTreeSet<_>>();
    validate_exact_entries(sources_root, &expected.iter().copied().collect::<Vec<_>>())?;
    let mut total_files = 0_u64;
    let mut total_bytes = 0_u64;
    for resolution in &ledger.resolutions {
        let root = sources_root.join(&resolution.resolution_id);
        ensure_read_only_directory(&root)?;
        let expected_namespaces = resolution
            .namespaces
            .iter()
            .filter(|item| item.present)
            .map(|item| item.name.name())
            .collect::<Vec<_>>();
        validate_exact_entries(&root, &expected_namespaces)?;
        let mut observed = Vec::new();
        for expected_namespace in &resolution.namespaces {
            let actual =
                digest_namespace(&root, expected_namespace.name, expected_namespace.present)?;
            if &actual != expected_namespace {
                return Err(LibraryError::new(
                    "E_SOURCE_DIGEST",
                    format!(
                        "{} {} source digest does not match",
                        resolution.resolution_id,
                        expected_namespace.name.name()
                    ),
                ));
            }
            total_files = total_files
                .checked_add(actual.files)
                .ok_or_else(|| LibraryError::new("E_SOURCE_LIMIT", "source file count overflow"))?;
            total_bytes = total_bytes
                .checked_add(actual.bytes)
                .ok_or_else(|| LibraryError::new("E_SOURCE_LIMIT", "source byte count overflow"))?;
            observed.push(actual);
        }
        if tree_digest(&observed) != resolution.tree_sha256 {
            return Err(LibraryError::new(
                "E_SOURCE_DIGEST",
                format!("{} tree digest does not match", resolution.resolution_id),
            ));
        }
    }
    if total_files > MAX_SOURCE_FILES || total_bytes > MAX_SOURCE_BYTES {
        return Err(LibraryError::new(
            "E_SOURCE_LIMIT",
            "shared-library source exceeds its aggregate limit",
        ));
    }
    Ok(SourceReceipt {
        resolutions: ledger.resolutions.len(),
        files: total_files,
        bytes: total_bytes,
    })
}

pub fn digest_source(root: &Path) -> Result<SourceTreeReceipt, LibraryError> {
    ensure_read_only_directory(root)?;
    let mut found = BTreeSet::new();
    for entry in
        fs::read_dir(root).map_err(|error| LibraryError::new("E_SOURCE_IO", error.to_string()))?
    {
        let entry = entry.map_err(|error| LibraryError::new("E_SOURCE_IO", error.to_string()))?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| LibraryError::new("E_SOURCE_ENTRY", "non-UTF-8 source namespace"))?;
        if !matches!(name, "vars" | "src" | "resources")
            || !entry
                .file_type()
                .map_err(|error| LibraryError::new("E_SOURCE_IO", error.to_string()))?
                .is_dir()
        {
            return Err(LibraryError::new(
                "E_SOURCE_ENTRY",
                format!("unexpected source entry {name}"),
            ));
        }
        found.insert(name.to_owned());
    }
    if found.is_empty() {
        return Err(LibraryError::new(
            "E_SOURCE_ENTRY",
            "shared-library source has no standard namespace",
        ));
    }
    let namespaces = [Namespace::Vars, Namespace::Src, Namespace::Resources]
        .into_iter()
        .map(|namespace| digest_namespace(root, namespace, found.contains(namespace.name())))
        .collect::<Result<Vec<_>, _>>()?;
    let tree_sha256 = tree_digest(&namespaces);
    Ok(SourceTreeReceipt {
        tree_sha256,
        namespaces: namespaces
            .into_iter()
            .map(|item| NamespaceReceipt {
                name: item.name.name(),
                present: item.present,
                files: item.files,
                bytes: item.bytes,
                sha256: item.sha256,
            })
            .collect(),
    })
}

fn parse_and_validate(bytes: &[u8]) -> Result<Ledger, LibraryError> {
    let ledger: Ledger = parse_yaml(bytes, "E_LEDGER_SCHEMA")?;
    validate_ledger(&ledger)?;
    Ok(ledger)
}

fn verify_source_manifest(corpus_root: &Path) -> Result<(), LibraryError> {
    let parent = corpus_root.parent().ok_or_else(|| {
        LibraryError::new("E_CORPUS_MANIFEST", "corpus source root has no parent")
    })?;
    let bytes = read_regular(parent.join("SOURCE_SHA256SUMS"), MAX_LEDGER_BYTES)?;
    if sha256_hex(&bytes) != SOURCE_MANIFEST_SHA256 {
        return Err(LibraryError::new(
            "E_CORPUS_MANIFEST",
            "source manifest does not match the sealed digest",
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| LibraryError::new("E_CORPUS_MANIFEST", "source manifest is not UTF-8"))?;
    let mut expected = BTreeMap::new();
    let mut previous = None;
    for line in text.lines() {
        let (digest, path) = line
            .split_once("  ")
            .ok_or_else(|| LibraryError::new("E_CORPUS_MANIFEST", "invalid manifest line"))?;
        validate_hex(digest, 64, "source manifest SHA-256")?;
        let relative = path.strip_prefix("sources/").ok_or_else(|| {
            LibraryError::new("E_CORPUS_MANIFEST", "manifest path is outside sources")
        })?;
        validate_relative(relative)?;
        if relative.contains('/') || !relative.ends_with(".Jenkinsfile") {
            return Err(LibraryError::new(
                "E_CORPUS_MANIFEST",
                "manifest source is not a flat Jenkinsfile",
            ));
        }
        if previous.is_some_and(|value: &str| value >= relative)
            || expected.insert(relative.to_owned(), digest).is_some()
        {
            return Err(LibraryError::new(
                "E_CORPUS_MANIFEST",
                "manifest paths are duplicate or not strictly sorted",
            ));
        }
        previous = Some(relative);
    }
    if expected.len() != 228 {
        return Err(LibraryError::new(
            "E_CORPUS_MANIFEST",
            "source manifest does not contain exactly 228 files",
        ));
    }
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(corpus_root)
        .map_err(|error| LibraryError::new("E_CORPUS_IO", error.to_string()))?
    {
        let entry = entry.map_err(|error| LibraryError::new("E_CORPUS_IO", error.to_string()))?;
        let kind = entry
            .file_type()
            .map_err(|error| LibraryError::new("E_CORPUS_IO", error.to_string()))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| LibraryError::new("E_CORPUS_ENTRY", "non-UTF-8 corpus filename"))?;
        if !kind.is_file() || kind.is_symlink() || !expected.contains_key(&name) {
            return Err(LibraryError::new(
                "E_CORPUS_ENTRY",
                "corpus contains an unexpected or non-regular entry",
            ));
        }
        actual.insert(name);
    }
    if actual != expected.keys().cloned().collect() {
        return Err(LibraryError::new(
            "E_CORPUS_ENTRY",
            "corpus source set does not match its sealed manifest",
        ));
    }
    for (name, digest) in expected {
        let source = read_regular(corpus_root.join(&name), MAX_LEDGER_BYTES)?;
        if sha256_hex(&source) != digest {
            return Err(LibraryError::new(
                "E_CORPUS_DIGEST",
                format!("{name} does not match the sealed source manifest"),
            ));
        }
    }
    Ok(())
}

fn discover_live_library_locations(
    corpus_root: &Path,
) -> Result<BTreeSet<(String, u64)>, LibraryError> {
    let mut locations = BTreeSet::new();
    for entry in fs::read_dir(corpus_root)
        .map_err(|error| LibraryError::new("E_CORPUS_IO", error.to_string()))?
    {
        let entry = entry.map_err(|error| LibraryError::new("E_CORPUS_IO", error.to_string()))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| LibraryError::new("E_CORPUS_ENTRY", "non-UTF-8 corpus filename"))?;
        let bytes = read_regular(entry.path(), MAX_LEDGER_BYTES)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| LibraryError::new("E_CORPUS_UTF8", "corpus source is not UTF-8"))?;
        for (index, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            let runtime_call = trimmed.strip_prefix("library").is_some_and(|rest| {
                rest.starts_with('(') || rest.chars().next().is_some_and(char::is_whitespace)
            });
            if trimmed.starts_with("@Library(") || runtime_call {
                let line = u64::try_from(index + 1).map_err(|_| {
                    LibraryError::new("E_CORPUS_LINE", "source line number overflow")
                })?;
                locations.insert((name.clone(), line));
            }
        }
    }
    Ok(locations)
}

fn parse_yaml<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    code: &'static str,
) -> Result<T, LibraryError> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| LibraryError::new(code, "input is not UTF-8"))?;
    parse_strict(text, ParseLimits::default())
        .map_err(|error| LibraryError::new(code, error.to_string()))?;
    serde_saphyr::from_str(text).map_err(|error| LibraryError::new(code, error.to_string()))
}

fn validate_ledger(ledger: &Ledger) -> Result<(), LibraryError> {
    exact("schema", &ledger.schema, SCHEMA)?;
    exact("ledger_id", &ledger.ledger_id, LEDGER_ID)?;
    exact_u64("ledger_version", ledger.ledger_version, 1)?;
    exact(
        "binding.controller_id",
        &ledger.binding.controller_id,
        "mario/jenkins-oracle-228",
    )?;
    exact(
        "binding.inventory_manifest_sha256",
        &ledger.binding.inventory_manifest_sha256,
        INVENTORY_MANIFEST_SHA256,
    )?;
    exact(
        "binding.job_graph_sha256",
        &ledger.binding.job_graph_sha256,
        JOB_GRAPH_SHA256,
    )?;
    exact(
        "binding.runtime_dependencies_sha256",
        &ledger.binding.runtime_dependencies_sha256,
        RUNTIME_DEPENDENCIES_SHA256,
    )?;
    exact(
        "binding.corpus_manifest_sha256",
        &ledger.binding.corpus_manifest_sha256,
        CORPUS_MANIFEST_SHA256,
    )?;
    exact(
        "binding.source_manifest_sha256",
        &ledger.binding.source_manifest_sha256,
        SOURCE_MANIFEST_SHA256,
    )?;
    if ledger.policy.scm_network != Disposition::Forbidden
        || ledger.policy.scm_credentials != Disposition::Forbidden
        || ledger.policy.groovy_evaluation != Disposition::Forbidden
        || ledger.policy.controller_execution != Disposition::Forbidden
        || ledger.policy.unresolved_library != Disposition::Unsupported
        || ledger.policy.source_input != "prefetched-digest-verified-read-only"
    {
        return Err(LibraryError::new(
            "E_POLICY",
            "shared-library policy grants authority",
        ));
    }
    let mut observation_ids = BTreeSet::new();
    let mut resolution_ids = BTreeSet::new();
    let mut resolution_refs = BTreeMap::new();
    let mut resolution_origins = BTreeSet::new();
    let mut references = BTreeSet::new();
    for resolution in &ledger.resolutions {
        validate_token(&resolution.resolution_id, "resolution ID")?;
        if !resolution_ids.insert(resolution.resolution_id.as_str()) {
            return Err(LibraryError::new("E_DUPLICATE", "duplicate resolution ID"));
        }
        validate_visible(&resolution.reference, "resolution reference", 512)?;
        validate_visible(&resolution.requested_ref, "requested ref", 256)?;
        validate_visible(&resolution.repository, "resolved repository", 512)?;
        validate_hex(&resolution.commit_sha1, 40, "commit SHA-1")?;
        validate_hex(&resolution.tree_sha256, 64, "tree SHA-256")?;
        if !resolution.repository.starts_with("https://github.com/")
            || !resolution.repository.ends_with(".git")
        {
            return Err(LibraryError::new(
                "E_RESOLUTION",
                "resolved repository is not an explicit GitHub HTTPS URL",
            ));
        }
        if resolution_refs
            .insert(
                resolution.resolution_id.as_str(),
                resolution.reference.as_str(),
            )
            .is_some()
            || !resolution_origins.insert((
                resolution.repository.as_str(),
                resolution.requested_ref.as_str(),
                resolution.commit_sha1.as_str(),
            ))
        {
            return Err(LibraryError::new(
                "E_DUPLICATE",
                "duplicate resolution provenance",
            ));
        }
        if resolution.namespaces.len() != 3
            || resolution
                .namespaces
                .iter()
                .map(|item| item.name)
                .collect::<Vec<_>>()
                != [Namespace::Vars, Namespace::Src, Namespace::Resources]
        {
            return Err(LibraryError::new(
                "E_RESOLUTION",
                "resolution must bind vars, src, and resources in order",
            ));
        }
        for namespace in &resolution.namespaces {
            validate_hex(&namespace.sha256, 64, "namespace SHA-256")?;
            if !namespace.present && (namespace.files != 0 || namespace.bytes != 0) {
                return Err(LibraryError::new(
                    "E_RESOLUTION",
                    "absent namespace has content",
                ));
            }
        }
    }
    let mut live = 0_u64;
    let mut comments = 0_u64;
    let mut resolved_live = 0_u64;
    let mut used_resolutions = BTreeSet::new();
    let mut observation_locations = BTreeSet::new();
    for observation in &ledger.observations {
        validate_token(&observation.observation_id, "observation ID")?;
        if !observation_ids.insert(observation.observation_id.as_str()) {
            return Err(LibraryError::new("E_DUPLICATE", "duplicate observation ID"));
        }
        validate_token(&observation.job_id, "job ID")?;
        validate_relative(&observation.source_file)?;
        if observation.source_file != format!("{}.Jenkinsfile", observation.job_id) {
            return Err(LibraryError::new(
                "E_OBSERVATION",
                "job ID does not bind its source filename",
            ));
        }
        validate_hex(&observation.source_sha256, 64, "source SHA-256")?;
        validate_visible(&observation.reference, "library reference", 512)?;
        if observation.line == 0 {
            return Err(LibraryError::new(
                "E_OBSERVATION",
                "invalid source observation",
            ));
        }
        if !observation_locations.insert((observation.source_file.as_str(), observation.line)) {
            return Err(LibraryError::new(
                "E_DUPLICATE",
                "duplicate source observation location",
            ));
        }
        if observation.reason.is_empty() || observation.reason.len() > 1024 {
            return Err(LibraryError::new(
                "E_OBSERVATION",
                "missing or oversized disposition reason",
            ));
        }
        if observation.plugin_dependencies.is_empty()
            || observation
                .plugin_dependencies
                .windows(2)
                .any(|items| items[0] >= items[1])
        {
            return Err(LibraryError::new(
                "E_OBSERVATION",
                "plugin dependencies must be non-empty and strictly sorted",
            ));
        }
        for plugin in &observation.plugin_dependencies {
            validate_token(plugin, "plugin dependency")?;
        }
        references.insert(observation.reference.as_str());
        match observation.evidence {
            Evidence::CommentFalsePositive => {
                comments += 1;
                if observation.disposition != ObservationDisposition::CommentOnly
                    || observation.resolution_id.is_some()
                    || observation.load_phase != LoadPhase::NotApplicable
                    || observation.sandbox != Requirement::NotApplicable
                    || observation.cps != Requirement::NotApplicable
                    || observation.credential_dependency != CredentialDependency::NotApplicable
                {
                    return Err(LibraryError::new(
                        "E_OBSERVATION",
                        "comment false positive carries runtime semantics",
                    ));
                }
            }
            Evidence::Live => {
                live += 1;
                if observation.load_phase == LoadPhase::NotApplicable
                    || observation.sandbox == Requirement::NotApplicable
                    || observation.cps == Requirement::NotApplicable
                    || observation.credential_dependency == CredentialDependency::NotApplicable
                {
                    return Err(LibraryError::new(
                        "E_OBSERVATION",
                        "live library lacks dependency classification",
                    ));
                }
                if let Some(resolution_id) = &observation.resolution_id {
                    if !resolution_ids.contains(resolution_id.as_str())
                        || resolution_refs.get(resolution_id.as_str())
                            != Some(&observation.reference.as_str())
                        || observation.disposition
                            != ObservationDisposition::SourceVerifiedUnsupported
                        || observation.credential_dependency
                            != CredentialDependency::PublicPrefetched
                    {
                        return Err(LibraryError::new(
                            "E_OBSERVATION",
                            "resolved observation is not deny-authority source verified",
                        ));
                    }
                    used_resolutions.insert(resolution_id.as_str());
                    resolved_live += 1;
                } else if observation.disposition != ObservationDisposition::UnresolvedUnsupported {
                    return Err(LibraryError::new(
                        "E_OBSERVATION",
                        "unresolved observation is not explicitly unsupported",
                    ));
                }
            }
        }
    }
    if used_resolutions != resolution_ids {
        return Err(LibraryError::new(
            "E_COVERAGE",
            "resolved source provenance is unused or missing",
        ));
    }
    let coverage = &ledger.coverage;
    if coverage.corpus_sources != 228
        || coverage.indexed_occurrences != 18
        || coverage.indexed_distinct_references != 17
        || coverage.corrected_live_occurrences != live
        || coverage.comment_false_positives != comments
        || coverage.resolved_references != ledger.resolutions.len() as u64
        || coverage.resolved_live_occurrences != resolved_live
        || coverage.executable_cases != 0
        || live != 23
        || comments != 2
        || references.len() != 24
    {
        return Err(LibraryError::new(
            "E_COVERAGE",
            "shared-library coverage denominator is not exact",
        ));
    }
    Ok(())
}

fn validate_lock(
    lock: &LedgerLock,
    raw: &str,
    semantic: &str,
    readme: &str,
) -> Result<(), LibraryError> {
    exact("lock.schema", &lock.schema, LOCK_SCHEMA)?;
    exact("lock.ledger_id", &lock.ledger_id, LEDGER_ID)?;
    exact_u64("lock.ledger_version", lock.ledger_version, 1)?;
    exact("lock.ledger_sha256", &lock.ledger_sha256, raw)?;
    exact("lock.semantic_sha256", &lock.semantic_sha256, semantic)?;
    exact("lock.readme_sha256", &lock.readme_sha256, readme)?;
    exact(
        "lock.inventory_manifest_sha256",
        &lock.inventory_manifest_sha256,
        INVENTORY_MANIFEST_SHA256,
    )?;
    exact(
        "lock.corpus_manifest_sha256",
        &lock.corpus_manifest_sha256,
        CORPUS_MANIFEST_SHA256,
    )?;
    exact(
        "lock.source_manifest_sha256",
        &lock.source_manifest_sha256,
        SOURCE_MANIFEST_SHA256,
    )
}

fn semantic_digest(ledger: &Ledger) -> Result<String, LibraryError> {
    serde_json::to_vec(ledger)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| LibraryError::new("E_SEMANTIC", error.to_string()))
}

fn digest_namespace(
    root: &Path,
    namespace: Namespace,
    present: bool,
) -> Result<NamespaceDigest, LibraryError> {
    let path = root.join(namespace.name());
    if !present {
        if path.exists() {
            return Err(LibraryError::new(
                "E_SOURCE_ENTRY",
                "absent namespace exists",
            ));
        }
        return Ok(NamespaceDigest {
            name: namespace,
            present: false,
            files: 0,
            bytes: 0,
            sha256: sha256_hex(
                format!(
                    "mcloving.shared-library.namespace/v1\0{}\0absent",
                    namespace.name()
                )
                .as_bytes(),
            ),
        });
    }
    ensure_read_only_directory(&path)?;
    let mut files = Vec::new();
    let mut bytes = 0_u64;
    let mut directories = 1_u64;
    collect_files(&path, &path, &mut files, &mut bytes, &mut directories, 0)?;
    files.sort_by(|left, right| left.0.cmp(&right.0));
    let mut hasher = Sha256::new();
    hasher.update(b"mcloving.shared-library.namespace/v1\0");
    hasher.update(namespace.name().as_bytes());
    hasher.update([0]);
    for (relative, file_bytes) in &files {
        hasher.update((relative.len() as u64).to_be_bytes());
        hasher.update(relative.as_bytes());
        hasher.update((file_bytes.len() as u64).to_be_bytes());
        hasher.update(file_bytes);
    }
    Ok(NamespaceDigest {
        name: namespace,
        present: true,
        files: files.len() as u64,
        bytes,
        sha256: format!("{:x}", hasher.finalize()),
    })
}

fn collect_files(
    root: &Path,
    current: &Path,
    output: &mut Vec<(String, Vec<u8>)>,
    total_bytes: &mut u64,
    total_directories: &mut u64,
    depth: usize,
) -> Result<bool, LibraryError> {
    if depth > MAX_SOURCE_DEPTH {
        return Err(LibraryError::new(
            "E_SOURCE_LIMIT",
            "source tree exceeds its directory depth limit",
        ));
    }
    let mut entries = Vec::new();
    for entry in fs::read_dir(current)
        .map_err(|error| LibraryError::new("E_SOURCE_IO", error.to_string()))?
    {
        if entries.len() as u64 >= MAX_SOURCE_FILES + MAX_SOURCE_DIRECTORIES {
            return Err(LibraryError::new(
                "E_SOURCE_LIMIT",
                "source directory contains too many entries",
            ));
        }
        entries.push(entry.map_err(|error| LibraryError::new("E_SOURCE_IO", error.to_string()))?);
    }
    entries.sort_by_key(|entry| entry.file_name());
    let mut contains_file = false;
    for entry in entries {
        let entry_path = entry.path();
        let relative = entry_path
            .strip_prefix(root)
            .map_err(|_| LibraryError::new("E_SOURCE_ENTRY", "source path escaped namespace"))?
            .to_str()
            .ok_or_else(|| LibraryError::new("E_SOURCE_ENTRY", "source path is not UTF-8"))?
            .replace('\\', "/");
        validate_relative(&relative)?;
        let metadata = entry
            .metadata()
            .map_err(|error| LibraryError::new("E_SOURCE_IO", error.to_string()))?;
        let file_type = entry
            .file_type()
            .map_err(|error| LibraryError::new("E_SOURCE_IO", error.to_string()))?;
        if file_type.is_symlink() || (!file_type.is_file() && !file_type.is_dir()) {
            return Err(LibraryError::new(
                "E_SOURCE_ENTRY",
                "source tree contains a symlink or special file",
            ));
        }
        ensure_read_only_metadata(&metadata)?;
        if file_type.is_dir() {
            *total_directories = total_directories.checked_add(1).ok_or_else(|| {
                LibraryError::new("E_SOURCE_LIMIT", "source directory count overflow")
            })?;
            if *total_directories > MAX_SOURCE_DIRECTORIES {
                return Err(LibraryError::new(
                    "E_SOURCE_LIMIT",
                    "too many source directories",
                ));
            }
            if !collect_files(
                root,
                &entry_path,
                output,
                total_bytes,
                total_directories,
                depth + 1,
            )? {
                return Err(LibraryError::new(
                    "E_SOURCE_ENTRY",
                    "source tree contains an empty directory",
                ));
            }
            contains_file = true;
        } else {
            if output.len() as u64 >= MAX_SOURCE_FILES {
                return Err(LibraryError::new("E_SOURCE_LIMIT", "too many source files"));
            }
            *total_bytes = total_bytes
                .checked_add(metadata.len())
                .ok_or_else(|| LibraryError::new("E_SOURCE_LIMIT", "source byte count overflow"))?;
            if *total_bytes > MAX_SOURCE_BYTES {
                return Err(LibraryError::new(
                    "E_SOURCE_LIMIT",
                    "source namespace exceeds its byte limit",
                ));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.nlink() != 1 {
                    return Err(LibraryError::new(
                        "E_SOURCE_ENTRY",
                        "source tree contains a hard-linked file",
                    ));
                }
            }
            output.push((
                relative,
                read_regular(entry_path, MAX_SOURCE_BYTES as usize)?,
            ));
            contains_file = true;
        }
    }
    Ok(contains_file)
}

fn tree_digest(namespaces: &[NamespaceDigest]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"mcloving.shared-library.tree/v1\0");
    for item in namespaces {
        hasher.update(item.name.name().as_bytes());
        hasher.update([0]);
        hasher.update([u8::from(item.present)]);
        hasher.update(item.files.to_be_bytes());
        hasher.update(item.bytes.to_be_bytes());
        hasher.update(item.sha256.as_bytes());
        hasher.update([0]);
    }
    format!("{:x}", hasher.finalize())
}

fn validate_exact_entries(root: &Path, expected: &[&str]) -> Result<(), LibraryError> {
    ensure_real_directory(root, "E_BUNDLE_ENTRY")?;
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    let mut found = BTreeSet::new();
    for entry in
        fs::read_dir(root).map_err(|error| LibraryError::new("E_BUNDLE_IO", error.to_string()))?
    {
        let entry = entry.map_err(|error| LibraryError::new("E_BUNDLE_IO", error.to_string()))?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| LibraryError::new("E_BUNDLE_ENTRY", "non-UTF-8 entry"))?;
        if !expected.contains(name) {
            return Err(LibraryError::new(
                "E_BUNDLE_ENTRY",
                format!("unexpected entry {name}"),
            ));
        }
        found.insert(name.to_owned());
    }
    if found != expected.iter().map(|item| (*item).to_owned()).collect() {
        return Err(LibraryError::new("E_BUNDLE_ENTRY", "bundle is incomplete"));
    }
    Ok(())
}

fn ensure_read_only_directory(path: &Path) -> Result<(), LibraryError> {
    let metadata = ensure_real_directory(path, "E_SOURCE_ENTRY")?;
    ensure_read_only_metadata(&metadata)
}

fn ensure_real_directory(path: &Path, code: &'static str) -> Result<fs::Metadata, LibraryError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| LibraryError::new(code, error.to_string()))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(LibraryError::new(code, "expected a real directory"));
    }
    Ok(metadata)
}

fn ensure_read_only_metadata(metadata: &fs::Metadata) -> Result<(), LibraryError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o222 != 0 {
            return Err(LibraryError::new(
                "E_SOURCE_WRITABLE",
                "source input is writable",
            ));
        }
    }
    if metadata.permissions().readonly() {
        Ok(())
    } else {
        #[cfg(not(unix))]
        return Err(LibraryError::new(
            "E_SOURCE_WRITABLE",
            "source input is writable",
        ));
        #[cfg(unix)]
        Ok(())
    }
}

fn read_regular(path: PathBuf, limit: usize) -> Result<Vec<u8>, LibraryError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = options.open(&path).map_err(|error| {
        LibraryError::new("E_FILE", format!("cannot open {}: {error}", path.display()))
    })?;
    let metadata = file
        .metadata()
        .map_err(|error| LibraryError::new("E_FILE", error.to_string()))?;
    if !metadata.file_type().is_file() || metadata.len() > limit as u64 {
        return Err(LibraryError::new(
            "E_FILE",
            "input is not a bounded regular file",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| LibraryError::new("E_FILE", error.to_string()))?;
    if bytes.len() > limit {
        return Err(LibraryError::new("E_FILE", "input grew beyond its limit"));
    }
    Ok(bytes)
}

fn validate_token(value: &str, field: &str) -> Result<(), LibraryError> {
    if value.is_empty()
        || value.len() > 512
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(LibraryError::new("E_TOKEN", format!("invalid {field}")));
    }
    Ok(())
}

fn validate_relative(value: &str) -> Result<(), LibraryError> {
    if value.is_empty()
        || value.starts_with('/')
        || value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(LibraryError::new(
            "E_SOURCE_ENTRY",
            "invalid relative source path",
        ));
    }
    Ok(())
}

fn validate_visible(value: &str, field: &str, limit: usize) -> Result<(), LibraryError> {
    if value.is_empty() || value.len() > limit || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(LibraryError::new("E_TOKEN", format!("invalid {field}")));
    }
    Ok(())
}

fn validate_hex(value: &str, length: usize, field: &str) -> Result<(), LibraryError> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(LibraryError::new("E_DIGEST", format!("invalid {field}")));
    }
    Ok(())
}

fn exact(field: &str, actual: &str, expected: &str) -> Result<(), LibraryError> {
    if actual == expected {
        Ok(())
    } else {
        Err(LibraryError::new(
            "E_BINDING",
            format!("{field} does not match sealed binding"),
        ))
    }
}

fn exact_u64(field: &str, actual: u64, expected: u64) -> Result<(), LibraryError> {
    if actual == expected {
        Ok(())
    } else {
        Err(LibraryError::new(
            "E_BINDING",
            format!("{field} does not match sealed binding"),
        ))
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;
    #[cfg(unix)]
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::*;
    use tempfile::TempDir;

    fn resolution(index: usize) -> Resolution {
        let namespaces = [Namespace::Vars, Namespace::Src, Namespace::Resources]
            .into_iter()
            .map(|name| NamespaceDigest {
                name,
                present: false,
                files: 0,
                bytes: 0,
                sha256: sha256_hex(
                    format!(
                        "mcloving.shared-library.namespace/v1\0{}\0absent",
                        name.name()
                    )
                    .as_bytes(),
                ),
            })
            .collect::<Vec<_>>();
        Resolution {
            resolution_id: format!("resolved-{index}"),
            reference: format!("resolved-lib-{index}@main"),
            repository: format!("https://github.com/example/library-{index}.git"),
            requested_ref: "main".to_owned(),
            commit_sha1: format!("{index:040x}"),
            tree_sha256: tree_digest(&namespaces),
            namespaces,
        }
    }

    fn observation(index: usize, source_sha256: String) -> Observation {
        let (evidence, reference, resolution_id, disposition, dependency, phase, requirement) =
            if index >= 23 {
                (
                    Evidence::CommentFalsePositive,
                    format!("comment-lib-{index}@main"),
                    None,
                    ObservationDisposition::CommentOnly,
                    CredentialDependency::NotApplicable,
                    LoadPhase::NotApplicable,
                    Requirement::NotApplicable,
                )
            } else if index < 8 {
                (
                    Evidence::Live,
                    if index == 7 {
                        "resolved-lib-6@main".to_owned()
                    } else {
                        format!("resolved-lib-{index}@main")
                    },
                    Some(format!("resolved-{}", index.min(6))),
                    ObservationDisposition::SourceVerifiedUnsupported,
                    CredentialDependency::PublicPrefetched,
                    LoadPhase::CompileTime,
                    Requirement::Required,
                )
            } else {
                (
                    Evidence::Live,
                    format!("unresolved-lib-{index}@main"),
                    None,
                    ObservationDisposition::UnresolvedUnsupported,
                    CredentialDependency::ControllerMappingRequired,
                    LoadPhase::CompileTime,
                    Requirement::Unknown,
                )
            };
        Observation {
            observation_id: format!("observation-{index}"),
            job_id: format!("job-{index}"),
            source_file: format!("job-{index}.Jenkinsfile"),
            source_sha256,
            line: 1,
            syntax: Syntax::StaticAnnotation,
            evidence,
            reference,
            load_phase: phase,
            sandbox: requirement,
            cps: requirement,
            plugin_dependencies: vec!["pipeline-groovy-lib".to_owned()],
            credential_dependency: dependency,
            resolution_id,
            disposition,
            reason: "explicit test disposition".to_owned(),
        }
    }

    fn ledger(source_digests: &[String]) -> Ledger {
        Ledger {
            schema: SCHEMA.to_owned(),
            ledger_id: LEDGER_ID.to_owned(),
            ledger_version: 1,
            binding: Binding {
                controller_id: "mario/jenkins-oracle-228".to_owned(),
                inventory_manifest_sha256: INVENTORY_MANIFEST_SHA256.to_owned(),
                job_graph_sha256: JOB_GRAPH_SHA256.to_owned(),
                runtime_dependencies_sha256: RUNTIME_DEPENDENCIES_SHA256.to_owned(),
                corpus_manifest_sha256: CORPUS_MANIFEST_SHA256.to_owned(),
                source_manifest_sha256: SOURCE_MANIFEST_SHA256.to_owned(),
            },
            policy: Policy {
                scm_network: Disposition::Forbidden,
                scm_credentials: Disposition::Forbidden,
                groovy_evaluation: Disposition::Forbidden,
                controller_execution: Disposition::Forbidden,
                unresolved_library: Disposition::Unsupported,
                source_input: "prefetched-digest-verified-read-only".to_owned(),
            },
            observations: (0..25)
                .map(|index| observation(index, source_digests[index].clone()))
                .collect(),
            resolutions: (0..7).map(resolution).collect(),
            coverage: Coverage {
                corpus_sources: 228,
                indexed_occurrences: 18,
                indexed_distinct_references: 17,
                corrected_live_occurrences: 23,
                comment_false_positives: 2,
                resolved_references: 7,
                resolved_live_occurrences: 8,
                executable_cases: 0,
            },
        }
    }

    #[test]
    fn exact_bundle_is_accepted_and_substitution_is_rejected() {
        let temp = TempDir::new().expect("tempdir");
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let bundle =
            workspace.join("migration/mario-jenkins-oracle-228/corpus-v1/shared-libraries-v1");
        for name in BUNDLE_FILES {
            fs::copy(bundle.join(name), temp.path().join(name)).expect("copy exact bundle");
        }
        let receipt = verify_bundle(temp.path()).expect("valid bundle");
        assert_eq!(
            (
                receipt.observations,
                receipt.live_observations,
                receipt.resolutions,
                receipt.executable
            ),
            (25, 23, 7, 0)
        );
        fs::write(temp.path().join("unexpected"), b"no").expect("extra entry");
        assert_eq!(
            verify_bundle(temp.path()).expect_err("extra entry").code,
            "E_BUNDLE_ENTRY"
        );
        fs::remove_file(temp.path().join("unexpected")).expect("remove extra entry");

        let ledger_path = temp.path().join("ledger.yaml");
        let original = fs::read_to_string(&ledger_path).expect("read ledger");
        let mutated = original.replacen(
            "runtime-computed parameter revision",
            "runtime-computed substituted revision",
            1,
        );
        let candidate = parse_and_validate(mutated.as_bytes()).expect("valid substituted ledger");
        let mutated_raw = sha256_hex(mutated.as_bytes());
        let mutated_semantic = semantic_digest(&candidate).expect("semantic digest");
        fs::write(&ledger_path, mutated).expect("write substituted ledger");
        let lock_path = temp.path().join("ledger.lock.yaml");
        let lock = fs::read_to_string(&lock_path)
            .expect("read lock")
            .replace(LEDGER_SHA256, &mutated_raw)
            .replace(LEDGER_SEMANTIC_SHA256, &mutated_semantic);
        fs::write(lock_path, lock).expect("write matching substituted lock");
        assert_eq!(
            verify_bundle(temp.path())
                .expect_err("joint ledger and lock substitution")
                .code,
            "E_BINDING"
        );
    }

    #[test]
    fn coverage_and_policy_fail_closed() {
        let digests = vec![sha256_hex(b"fixture"); 25];
        let mut candidate = ledger(&digests);
        candidate.coverage.executable_cases = 1;
        assert_eq!(
            validate_ledger(&candidate)
                .expect_err("executable case")
                .code,
            "E_COVERAGE"
        );
        candidate.coverage.executable_cases = 0;
        candidate.policy.scm_network = Disposition::Unsupported;
        assert_eq!(
            validate_ledger(&candidate)
                .expect_err("network authority")
                .code,
            "E_POLICY"
        );

        let mut candidate = ledger(&digests);
        candidate.resolutions[0].repository = "https://github.com/example/library\n.git".to_owned();
        assert_eq!(
            validate_ledger(&candidate)
                .expect_err("control character in repository")
                .code,
            "E_TOKEN"
        );
    }

    #[test]
    fn strict_yaml_errors_are_attributed_to_the_input_schema() {
        let error =
            parse_yaml::<LedgerLock>(b"schema: first\nschema: duplicate\n", "E_LOCK_SCHEMA")
                .expect_err("duplicate YAML key");
        assert_eq!(error.code, "E_LOCK_SCHEMA");
    }

    #[test]
    fn independent_discovery_covers_every_live_library_form() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let source_root = workspace.join("migration/mario-jenkins-oracle-228/corpus-v1/sources");
        let locations =
            discover_live_library_locations(&source_root).expect("discover live library calls");
        assert_eq!(locations.len(), 23);
        for expected in [
            ("Ableton_python-pipeline-utils.Jenkinsfile", 4),
            ("concur_jenkins-yml-workflowLibs.Jenkinsfile", 2),
            ("jenkins-zh_jenkins-cli.Jenkinsfile", 1),
        ] {
            assert!(locations.contains(&(expected.0.to_owned(), expected.1)));
        }
    }

    #[test]
    fn corpus_receipt_binds_lines_and_digests() {
        let temp = TempDir::new().expect("tempdir");
        let corpus = temp.path().join("corpus");
        fs::create_dir_all(&corpus).expect("corpus");
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let source_root = workspace.join("migration/mario-jenkins-oracle-228/corpus-v1");
        let bundle = source_root.join("shared-libraries-v1");
        for entry in fs::read_dir(source_root.join("sources")).expect("source corpus") {
            let entry = entry.expect("source entry");
            fs::copy(entry.path(), corpus.join(entry.file_name())).expect("copy source fixture");
        }
        fs::copy(
            source_root.join("SOURCE_SHA256SUMS"),
            temp.path().join("SOURCE_SHA256SUMS"),
        )
        .expect("copy source manifest");
        let receipt = verify_corpus(&bundle, &corpus).expect("valid corpus");
        assert_eq!((receipt.observations, receipt.files), (25, 21));
        fs::write(
            corpus.join("AmanPathak-DevOps_EKS-Terraform-GitHub-Actions.Jenkinsfile"),
            b"@Library('hidden-substitution@main') _\n",
        )
        .expect("mutate corpus");
        assert_eq!(
            verify_corpus(&bundle, &corpus)
                .expect_err("unobserved source substitution")
                .code,
            "E_CORPUS_DIGEST"
        );
    }

    #[cfg(unix)]
    #[test]
    fn source_input_must_be_read_only_and_symlink_free() {
        let temp = TempDir::new().expect("tempdir");
        let writable = temp.path().join("writable");
        fs::create_dir(&writable).expect("writable");
        assert_eq!(
            ensure_read_only_directory(&writable)
                .expect_err("writable input")
                .code,
            "E_SOURCE_WRITABLE"
        );
        fs::set_permissions(&writable, fs::Permissions::from_mode(0o555)).expect("seal directory");
        ensure_read_only_directory(&writable).expect("read-only directory");
        let target = temp.path().join("target");
        fs::create_dir(&target).expect("target");
        let link = temp.path().join("link");
        symlink(&target, &link).expect("symlink");
        assert_eq!(
            ensure_real_directory(&link, "E_SOURCE_ENTRY")
                .expect_err("symlink")
                .code,
            "E_SOURCE_ENTRY"
        );
    }

    #[cfg(unix)]
    #[test]
    fn source_traversal_rejects_empty_non_utf8_and_overdeep_directories() {
        let empty_fixture = TempDir::new().expect("empty fixture");
        let vars = empty_fixture.path().join("vars");
        let empty = vars.join("empty");
        fs::create_dir_all(&empty).expect("empty directory");
        fs::set_permissions(&empty, fs::Permissions::from_mode(0o555)).expect("seal empty");
        fs::set_permissions(&vars, fs::Permissions::from_mode(0o555)).expect("seal vars");
        assert_eq!(
            digest_namespace(empty_fixture.path(), Namespace::Vars, true)
                .expect_err("empty directory")
                .code,
            "E_SOURCE_ENTRY"
        );
        fs::set_permissions(&vars, fs::Permissions::from_mode(0o755)).expect("unseal vars");
        fs::set_permissions(&empty, fs::Permissions::from_mode(0o755)).expect("unseal empty");

        let non_utf8_fixture = TempDir::new().expect("non-UTF-8 fixture");
        let vars = non_utf8_fixture.path().join("vars");
        fs::create_dir(&vars).expect("vars directory");
        let invalid = vars.join(std::ffi::OsString::from_vec(vec![0xff]));
        fs::create_dir(&invalid).expect("non-UTF-8 directory");
        fs::set_permissions(&invalid, fs::Permissions::from_mode(0o555)).expect("seal invalid");
        fs::set_permissions(&vars, fs::Permissions::from_mode(0o555)).expect("seal vars");
        assert_eq!(
            digest_namespace(non_utf8_fixture.path(), Namespace::Vars, true)
                .expect_err("non-UTF-8 directory")
                .code,
            "E_SOURCE_ENTRY"
        );
        fs::set_permissions(&vars, fs::Permissions::from_mode(0o755)).expect("unseal vars");
        fs::set_permissions(&invalid, fs::Permissions::from_mode(0o755)).expect("unseal invalid");

        let deep_fixture = TempDir::new().expect("deep fixture");
        let vars = deep_fixture.path().join("vars");
        fs::create_dir(&vars).expect("vars directory");
        let mut directories = vec![vars.clone()];
        let mut current = vars;
        for index in 0..=MAX_SOURCE_DEPTH {
            current = current.join(format!("d{index}"));
            fs::create_dir(&current).expect("nested directory");
            directories.push(current.clone());
        }
        let source = current.join("value.groovy");
        fs::write(&source, b"def call() { true }\n").expect("source file");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o444)).expect("seal source");
        for directory in directories.iter().rev() {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o555))
                .expect("seal nested directory");
        }
        assert_eq!(
            digest_namespace(deep_fixture.path(), Namespace::Vars, true)
                .expect_err("overdeep tree")
                .code,
            "E_SOURCE_LIMIT"
        );
        for directory in &directories {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o755))
                .expect("unseal nested directory");
        }
    }
}
