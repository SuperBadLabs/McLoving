//! Fail-closed admission for versioned Jenkins-to-McLoving mapping catalogs.
//!
//! The first catalog is deliberately narrow and corpus-earned: one literal
//! Jenkins `sh` step from Mario's immutable 228-file oracle maps to one
//! contained McLoving native process. The catalog grants no execution or
//! external-effect authority.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

use mcloving_pipeline_ir::{ParseLimits, parse_strict};
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub const SCHEMA: &str = "mcloving.jenkins.mapping-catalog/v1";
pub const LOCK_SCHEMA: &str = "mcloving.jenkins.mapping-lock/v1";
pub const CATALOG_ID: &str = "mario-jenkins-oracle-228-v1";
pub const CATALOG_VERSION: u64 = 1;
pub const CONTROLLER_ID: &str = "mario/jenkins-oracle-228";
pub const COMPILER: &str = "mcloving-jenkins-compiler-worker/1";
pub const PROFILE_SHA256: &str = "feeeb44d32aa10181e572a0dbbf5b2e23895731b1913bd46aba9f38d56172271";
pub const INVENTORY_SHA256: &str =
    "b1c2f81c74ec0ffc36971f358f920b2d0775c6009f474bea924448cd2a1915c1";
pub const CORPUS_MANIFEST_SHA256: &str =
    "59faf74bb8ebfbd658f85b5224ec15ee7b0db841ad66b2da1326cd83adac4f2a";
pub const CATALOG_SHA256: &str = "d383ab8e15593ca5cc2847633a1410b53e676442f60dfcca93606610d1f761c8";
pub const CATALOG_SEMANTIC_SHA256: &str =
    "1349f2864edb360cf1a954eda0327fe6e2d42549296437690f24168e54f80907";
pub const SOURCE_SHA256: &str = "666ac2275ea75730e27cf7b565d757691b094c508355adc0199d745278a23100";
pub const SOURCE_JOB_ID: &str = "corpus-052-cinqict_jenkinsdev";
pub const PLUGIN_SHA256: &str = "a0f0f1464ce3592f76d0f0079ce9fc2d4272594f995bf3d1a7ede4cd5031452e";
pub const PLUGIN_VERSION: &str = "1479.v56e587f413a_7";
pub const MAPPING_ID: &str = "jenkins.workflow-durable-task-step.sh.literal.v1";
pub const TARGET_IR: &str = "mcloving.pipeline/1";
pub const TRUST_POOL: &str = "migration-deny-authority";
const MAX_CATALOG_BYTES: usize = 65_536;
const MAX_LOCK_BYTES: usize = 8_192;
const MAX_README_BYTES: usize = 65_536;
const BUNDLE_FILES: [&str; 3] = ["README.md", "catalog.lock.yaml", "catalog.yaml"];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogReceipt {
    pub schema: String,
    pub catalog_id: String,
    pub catalog_version: u64,
    pub mappings: usize,
    pub earned_cases: u64,
    pub catalog_sha256: String,
    pub semantic_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogError {
    pub code: &'static str,
    pub message: String,
}

impl CatalogError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for CatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for CatalogError {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    schema: String,
    catalog_id: String,
    catalog_version: u64,
    source: SourceBinding,
    target: TargetBinding,
    policy: CatalogPolicy,
    mappings: Vec<Mapping>,
    coverage: Coverage,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceBinding {
    controller_id: String,
    inventory_sha256: String,
    corpus_manifest_sha256: String,
    compiler: String,
    compiler_profile_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetBinding {
    pipeline_ir: String,
    platform: String,
    trust_pool: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogPolicy {
    unknown_step: Disposition,
    unknown_plugin: Disposition,
    floating_mapping: Disposition,
    silent_fallback: Disposition,
    undeclared_host_reads: Disposition,
    external_effects: Disposition,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum Disposition {
    Forbidden,
    Unsupported,
    ConnectorOnly,
    NotApplicable,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Mapping {
    mapping_id: String,
    mapping_version: u64,
    classification: Classification,
    source: StepSource,
    target: ProcessTarget,
    effects: Effects,
    trust: Trust,
    supported_target_profiles: Vec<String>,
    provenance: Provenance,
    local_input: Disposition,
    shared_resource: Disposition,
    cache: Disposition,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum Classification {
    NativeProcess,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StepSource {
    symbol: String,
    plugin: String,
    plugin_version: String,
    plugin_sha256: String,
    parameters: Vec<Parameter>,
    additional_parameters: Disposition,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Parameter {
    name: String,
    value_type: String,
    required: bool,
    literal_only: bool,
    confidentiality: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessTarget {
    kind: String,
    program: String,
    args_prefix: Vec<String>,
    source_parameter: String,
    target_position: u64,
    working_directory: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Effects {
    class: String,
    workspace_write: bool,
    network: Disposition,
    credentials: Disposition,
    host_filesystem: Disposition,
    production_external_effects: Disposition,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Trust {
    required_pool: String,
    required_platform: String,
    workload_execution: bool,
    scheduler: bool,
    agent_protocol: bool,
    credentials: bool,
    connector: bool,
    external_effects: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Provenance {
    source_job_id: String,
    source_sha256: String,
    evidence: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Coverage {
    corpus_sources: u64,
    compiler_admitted_cases: u64,
    mapping_earned_cases: u64,
    mapped_source_sha256: Vec<String>,
    certified_equivalence_cases: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogLock {
    schema: String,
    catalog_id: String,
    catalog_version: u64,
    catalog_sha256: String,
    semantic_sha256: String,
    compiler_profile_sha256: String,
    corpus_manifest_sha256: String,
}

pub fn verify_bundle(root: &Path) -> Result<CatalogReceipt, CatalogError> {
    validate_bundle_entries(root)?;
    let _readme_bytes = read_regular(root.join("README.md"), MAX_README_BYTES)?;
    let catalog_bytes = read_regular(root.join("catalog.yaml"), MAX_CATALOG_BYTES)?;
    let lock_bytes = read_regular(root.join("catalog.lock.yaml"), MAX_LOCK_BYTES)?;
    let catalog_sha256 = sha256_hex(&catalog_bytes);
    let catalog = parse_catalog(&catalog_bytes)?;
    let semantic_sha256 = semantic_digest(&catalog);
    let lock: CatalogLock = parse_yaml(&lock_bytes, "E_LOCK_SCHEMA")?;
    validate_lock(&lock, &catalog_sha256, &semantic_sha256)?;

    Ok(CatalogReceipt {
        schema: catalog.schema,
        catalog_id: catalog.catalog_id,
        catalog_version: catalog.catalog_version,
        mappings: catalog.mappings.len(),
        earned_cases: catalog.coverage.mapping_earned_cases,
        catalog_sha256,
        semantic_sha256,
    })
}

pub fn validate_catalog_bytes(source: &[u8]) -> Result<(String, String), CatalogError> {
    let catalog = parse_catalog(source)?;
    Ok((sha256_hex(source), semantic_digest(&catalog)))
}

fn parse_catalog(source: &[u8]) -> Result<Catalog, CatalogError> {
    if source.len() > MAX_CATALOG_BYTES {
        return Err(CatalogError::new(
            "E_CATALOG_SIZE",
            "catalog exceeds 65536 bytes",
        ));
    }
    let catalog: Catalog = parse_yaml(source, "E_CATALOG_SCHEMA")?;
    validate_catalog(&catalog)?;
    Ok(catalog)
}

fn parse_yaml<T: for<'de> Deserialize<'de>>(
    source: &[u8],
    schema_code: &'static str,
) -> Result<T, CatalogError> {
    let text = std::str::from_utf8(source)
        .map_err(|_| CatalogError::new("E_CATALOG_UTF8", "catalog is not UTF-8"))?;
    parse_strict(text, ParseLimits::default())
        .map_err(|error| CatalogError::new("E_CATALOG_YAML", error.to_string()))?;
    serde_saphyr::from_str(text).map_err(|error| CatalogError::new(schema_code, error.to_string()))
}

fn validate_catalog(catalog: &Catalog) -> Result<(), CatalogError> {
    exact("schema", &catalog.schema, SCHEMA)?;
    exact("catalog_id", &catalog.catalog_id, CATALOG_ID)?;
    exact_u64("catalog_version", catalog.catalog_version, CATALOG_VERSION)?;
    exact(
        "source.controller_id",
        &catalog.source.controller_id,
        CONTROLLER_ID,
    )?;
    exact(
        "source.inventory_sha256",
        &catalog.source.inventory_sha256,
        INVENTORY_SHA256,
    )?;
    exact(
        "source.corpus_manifest_sha256",
        &catalog.source.corpus_manifest_sha256,
        CORPUS_MANIFEST_SHA256,
    )?;
    exact("source.compiler", &catalog.source.compiler, COMPILER)?;
    exact(
        "source.compiler_profile_sha256",
        &catalog.source.compiler_profile_sha256,
        PROFILE_SHA256,
    )?;
    exact("target.pipeline_ir", &catalog.target.pipeline_ir, TARGET_IR)?;
    exact("target.platform", &catalog.target.platform, "any")?;
    exact("target.trust_pool", &catalog.target.trust_pool, TRUST_POOL)?;
    if catalog.policy.unknown_step != Disposition::Unsupported
        || catalog.policy.unknown_plugin != Disposition::Unsupported
        || catalog.policy.floating_mapping != Disposition::Forbidden
        || catalog.policy.silent_fallback != Disposition::Forbidden
        || catalog.policy.undeclared_host_reads != Disposition::Forbidden
        || catalog.policy.external_effects != Disposition::ConnectorOnly
    {
        return Err(CatalogError::new(
            "E_POLICY",
            "catalog policy is not fail-closed",
        ));
    }
    if catalog.mappings.len() != 1 {
        return Err(CatalogError::new(
            "E_MAPPING_COUNT",
            "v1 requires exactly one corpus-earned mapping",
        ));
    }
    validate_mapping(&catalog.mappings[0])?;
    if catalog.coverage.corpus_sources != 228
        || catalog.coverage.compiler_admitted_cases != 1
        || catalog.coverage.mapping_earned_cases != 1
        || catalog.coverage.certified_equivalence_cases != 0
        || catalog.coverage.mapped_source_sha256 != [SOURCE_SHA256]
    {
        return Err(CatalogError::new(
            "E_COVERAGE",
            "coverage must describe the exact earned case without certification inflation",
        ));
    }
    Ok(())
}

fn validate_mapping(mapping: &Mapping) -> Result<(), CatalogError> {
    exact("mapping_id", &mapping.mapping_id, MAPPING_ID)?;
    exact_u64("mapping_version", mapping.mapping_version, 1)?;
    if mapping.classification != Classification::NativeProcess {
        return Err(CatalogError::new(
            "E_CLASSIFICATION",
            "the admitted mapping must be a native process",
        ));
    }
    exact("source.symbol", &mapping.source.symbol, "sh")?;
    exact(
        "source.plugin",
        &mapping.source.plugin,
        "workflow-durable-task-step",
    )?;
    exact(
        "source.plugin_version",
        &mapping.source.plugin_version,
        PLUGIN_VERSION,
    )?;
    exact(
        "source.plugin_sha256",
        &mapping.source.plugin_sha256,
        PLUGIN_SHA256,
    )?;
    if mapping.source.parameters.len() != 1 {
        return Err(CatalogError::new(
            "E_PARAMETER_SCHEMA",
            "literal sh requires exactly one parameter",
        ));
    }
    let parameter = &mapping.source.parameters[0];
    exact("parameter.name", &parameter.name, "script")?;
    exact("parameter.value_type", &parameter.value_type, "string")?;
    exact(
        "parameter.confidentiality",
        &parameter.confidentiality,
        "public",
    )?;
    if !parameter.required
        || !parameter.literal_only
        || mapping.source.additional_parameters != Disposition::Forbidden
    {
        return Err(CatalogError::new(
            "E_PARAMETER_SCHEMA",
            "sh parameter schema is not exact and literal-only",
        ));
    }
    exact("target.kind", &mapping.target.kind, "process")?;
    exact("target.program", &mapping.target.program, "/bin/sh")?;
    if mapping.target.args_prefix != ["-xe", "-c"] {
        return Err(CatalogError::new(
            "E_TARGET",
            "target argument prefix must be exactly [-xe, -c]",
        ));
    }
    exact(
        "target.source_parameter",
        &mapping.target.source_parameter,
        "script",
    )?;
    exact_u64("target.target_position", mapping.target.target_position, 2)?;
    exact(
        "target.working_directory",
        &mapping.target.working_directory,
        "workspace-root",
    )?;
    exact("effects.class", &mapping.effects.class, "workspace-process")?;
    if !mapping.effects.workspace_write
        || mapping.effects.network != Disposition::Forbidden
        || mapping.effects.credentials != Disposition::Forbidden
        || mapping.effects.host_filesystem != Disposition::Forbidden
        || mapping.effects.production_external_effects != Disposition::ConnectorOnly
    {
        return Err(CatalogError::new(
            "E_EFFECTS",
            "mapping effect boundary is not exact and fail-closed",
        ));
    }
    exact(
        "trust.required_pool",
        &mapping.trust.required_pool,
        TRUST_POOL,
    )?;
    exact(
        "trust.required_platform",
        &mapping.trust.required_platform,
        "any",
    )?;
    if mapping.trust.workload_execution
        || mapping.trust.scheduler
        || mapping.trust.agent_protocol
        || mapping.trust.credentials
        || mapping.trust.connector
        || mapping.trust.external_effects
    {
        return Err(CatalogError::new(
            "E_AUTHORITY",
            "mapping catalog grants authority",
        ));
    }
    if mapping.supported_target_profiles != [PROFILE_SHA256] {
        return Err(CatalogError::new(
            "E_TARGET_PROFILE",
            "mapping target profile is floating or substituted",
        ));
    }
    exact(
        "provenance.source_job_id",
        &mapping.provenance.source_job_id,
        SOURCE_JOB_ID,
    )?;
    exact(
        "provenance.source_sha256",
        &mapping.provenance.source_sha256,
        SOURCE_SHA256,
    )?;
    exact(
        "provenance.evidence",
        &mapping.provenance.evidence,
        "compiler-v1/rust-admission.receipt",
    )?;
    if mapping.local_input != Disposition::NotApplicable
        || mapping.shared_resource != Disposition::NotApplicable
        || mapping.cache != Disposition::NotApplicable
    {
        return Err(CatalogError::new(
            "E_UNEARNED_MAPPING",
            "v1 cannot claim local-input, shared-resource, or cache semantics",
        ));
    }
    Ok(())
}

fn validate_lock(
    lock: &CatalogLock,
    catalog_sha256: &str,
    semantic_sha256: &str,
) -> Result<(), CatalogError> {
    exact("lock.schema", &lock.schema, LOCK_SCHEMA)?;
    exact("lock.catalog_id", &lock.catalog_id, CATALOG_ID)?;
    exact_u64(
        "lock.catalog_version",
        lock.catalog_version,
        CATALOG_VERSION,
    )?;
    exact("catalog.sha256", catalog_sha256, CATALOG_SHA256)?;
    exact(
        "catalog.semantic_sha256",
        semantic_sha256,
        CATALOG_SEMANTIC_SHA256,
    )?;
    exact("lock.catalog_sha256", &lock.catalog_sha256, catalog_sha256)?;
    exact(
        "lock.semantic_sha256",
        &lock.semantic_sha256,
        semantic_sha256,
    )?;
    exact(
        "lock.compiler_profile_sha256",
        &lock.compiler_profile_sha256,
        PROFILE_SHA256,
    )?;
    exact(
        "lock.corpus_manifest_sha256",
        &lock.corpus_manifest_sha256,
        CORPUS_MANIFEST_SHA256,
    )
}

fn semantic_digest(catalog: &Catalog) -> String {
    let mapping = &catalog.mappings[0];
    let lines = [
        catalog.schema.clone(),
        catalog.catalog_id.clone(),
        catalog.catalog_version.to_string(),
        catalog.source.controller_id.clone(),
        catalog.source.inventory_sha256.clone(),
        catalog.source.corpus_manifest_sha256.clone(),
        catalog.source.compiler.clone(),
        catalog.source.compiler_profile_sha256.clone(),
        catalog.target.pipeline_ir.clone(),
        catalog.target.platform.clone(),
        catalog.target.trust_pool.clone(),
        mapping.mapping_id.clone(),
        mapping.mapping_version.to_string(),
        mapping.source.symbol.clone(),
        mapping.source.plugin.clone(),
        mapping.source.plugin_version.clone(),
        mapping.source.plugin_sha256.clone(),
        mapping.target.program.clone(),
        mapping.target.args_prefix[0].clone(),
        mapping.target.args_prefix[1].clone(),
        mapping.target.source_parameter.clone(),
        mapping.target.target_position.to_string(),
        mapping.target.working_directory.clone(),
        mapping.provenance.source_job_id.clone(),
        mapping.provenance.source_sha256.clone(),
        mapping.provenance.evidence.clone(),
        catalog.coverage.corpus_sources.to_string(),
        catalog.coverage.compiler_admitted_cases.to_string(),
        catalog.coverage.mapping_earned_cases.to_string(),
        catalog.coverage.certified_equivalence_cases.to_string(),
    ];
    sha256_hex(lines.join("\n").as_bytes())
}

fn exact(field: &str, actual: &str, expected: &str) -> Result<(), CatalogError> {
    if actual != expected {
        return Err(CatalogError::new(
            "E_BINDING",
            format!("{field} does not match the sealed binding"),
        ));
    }
    Ok(())
}

fn exact_u64(field: &str, actual: u64, expected: u64) -> Result<(), CatalogError> {
    if actual != expected {
        return Err(CatalogError::new(
            "E_BINDING",
            format!("{field} does not match the sealed binding"),
        ));
    }
    Ok(())
}

fn validate_bundle_entries(root: &Path) -> Result<(), CatalogError> {
    let expected = BUNDLE_FILES.into_iter().collect::<BTreeSet<_>>();
    let entries = fs::read_dir(root).map_err(|error| {
        CatalogError::new("E_BUNDLE_IO", format!("cannot list bundle: {error}"))
    })?;
    let mut found = BTreeSet::new();
    for entry in entries {
        let entry = entry
            .map_err(|error| CatalogError::new("E_BUNDLE_IO", format!("bad entry: {error}")))?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| CatalogError::new("E_BUNDLE_ENTRY", "non-UTF-8 bundle entry"))?;
        if !expected.contains(name) {
            return Err(CatalogError::new(
                "E_BUNDLE_ENTRY",
                format!("unexpected bundle entry {name}"),
            ));
        }
        found.insert(name.to_owned());
    }
    if found != expected.into_iter().map(str::to_owned).collect() {
        return Err(CatalogError::new(
            "E_BUNDLE_ENTRY",
            "mapping bundle is incomplete",
        ));
    }
    Ok(())
}

fn read_regular(path: PathBuf, limit: usize) -> Result<Vec<u8>, CatalogError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(&path).map_err(|error| {
        CatalogError::new(
            "E_BUNDLE_ENTRY",
            format!("cannot open {} as a regular file: {error}", path.display()),
        )
    })?;
    let metadata = file.metadata().map_err(|error| {
        CatalogError::new(
            "E_BUNDLE_IO",
            format!("cannot inspect open {}: {error}", path.display()),
        )
    })?;
    if !metadata.file_type().is_file() {
        return Err(CatalogError::new(
            "E_BUNDLE_ENTRY",
            format!("{} is not a regular file", path.display()),
        ));
    }
    if metadata.len() > limit as u64 {
        return Err(CatalogError::new(
            "E_BUNDLE_SIZE",
            format!("{} exceeds its byte limit", path.display()),
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            CatalogError::new(
                "E_BUNDLE_IO",
                format!("cannot read open {}: {error}", path.display()),
            )
        })?;
    if bytes.len() > limit {
        return Err(CatalogError::new(
            "E_BUNDLE_SIZE",
            format!("{} grew beyond its byte limit", path.display()),
        ));
    }
    Ok(bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_yaml_rejects_aliases_before_schema_loading() {
        let source = b"schema: &schema mcloving.jenkins.mapping-catalog/v1\ncatalog_id: *schema\n";
        let error = validate_catalog_bytes(source).expect_err("alias must be rejected");
        assert_eq!(error.code, "E_CATALOG_YAML");
    }
}
