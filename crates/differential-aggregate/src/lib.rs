//! Fail-closed MIG-006 aggregation over the three immutable differential
//! evidence sets. This crate delegates their semantics to the canonical
//! DIFF-001/002/003 verifiers and only verifies identities, coverage joins,
//! and the zero-authority claim ledger.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::Read as _;
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SCHEMA: &str = "mcloving.jenkins.differential-aggregate/v1";
pub const CASE: &str = "mario-230-corpus-228-immutable-closure";
pub const EVIDENCE_FILE: &str = "differential-aggregate.json";
pub const EVIDENCE_SHA256: &str =
    "90ef410114812982f7dc98cabafea8215a1f87739023f0636853f77b1f9a77a9";

const MAX_EVIDENCE_BYTES: u64 = 32_768;
const MAX_BOUND_INPUT_BYTES: u64 = 2_097_152;
const DIFF001_ROOT: &str = "migration/mario-jenkins-oracle-228/corpus-v1/differential-v1";
const DIFF002_ROOT: &str = "migration/state-policy-differential-v1";
const DIFF003_ROOT: &str = "migration/boundary-differential-v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationReceipt {
    pub schema: &'static str,
    pub case: &'static str,
    pub aggregate_sha256: String,
    pub verified_inputs: usize,
    pub coverage: Vec<CoverageMetric>,
    pub production_authority: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageMetric {
    pub name: String,
    pub numerator: u64,
    pub denominator: u64,
    pub unit: String,
    pub evidence: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationError {
    pub code: &'static str,
    pub message: String,
}

impl VerificationError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for VerificationError {}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Aggregate {
    schema: String,
    case: String,
    inputs: Vec<BoundInput>,
    differential_receipts: DifferentialReceipts,
    identity_joins: IdentityJoins,
    coverage: Vec<CoverageMetric>,
    taxonomy: Taxonomy,
    authority: Authority,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BoundInput {
    name: String,
    path: String,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DifferentialReceipts {
    diff001: DifferentialReceipt,
    diff002: DifferentialReceipt,
    diff003: DifferentialReceipt,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DifferentialReceipt {
    root: String,
    schema: String,
    case: String,
    // DIFF-001 binds its canonical derived trace digest here; DIFF-002 and
    // DIFF-003 bind their canonical evidence JSON digests.
    evidence_sha256: String,
    verified_records: u64,
    mismatches: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct IdentityJoins {
    jenkins_image_sha256: String,
    jenkins_plugin_manifest_sha256: String,
    rust_image_sha256: String,
    postgres_image_sha256: String,
    source_sha256: String,
    pipeline_sha256: String,
    compiler_profile_sha256: String,
    mapping_catalog_sha256: String,
    corpus_manifest_sha256: String,
    runtime_dependency_manifest_sha256: String,
    identity_client_manifest_sha256: String,
    release_id: String,
    release_version: String,
    release_profile: String,
    release_envelope_sha256: String,
    release_evidence_manifest_sha256: String,
    release_verification_receipt_sha256: String,
    mig005a_forward_sha256: String,
    mig005a_reverse_sha256: String,
    mig005a_evidence_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Taxonomy {
    deterministic_rejection: Vec<String>,
    aggregate_mismatch: Vec<String>,
    regression: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Authority {
    certification_scope: String,
    production_authority: bool,
    production_credentials: bool,
    production_effects: bool,
    scheduler_authority: bool,
    cutover_authority: bool,
    migration_package_is_input: bool,
    historical_ranvil_native: HistoricalMetric,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HistoricalMetric {
    numerator: u64,
    denominator: u64,
    meaning: String,
    grants_runnable_or_equivalence_claim: bool,
}

pub fn verify_bundle(
    bundle_root: &Path,
    repository_root: &Path,
) -> Result<VerificationReceipt, VerificationError> {
    verify_bundle_tree(bundle_root)?;
    let evidence_path = bundle_root.join(EVIDENCE_FILE);
    let metadata = fs::symlink_metadata(&evidence_path)
        .map_err(|error| VerificationError::new("E_IO", error.to_string()))?;
    if metadata.len() > MAX_EVIDENCE_BYTES {
        return Err(VerificationError::new(
            "E_SIZE",
            "aggregate evidence exceeds byte ceiling",
        ));
    }
    let bytes = read_bounded(
        &evidence_path,
        MAX_EVIDENCE_BYTES,
        "E_SIZE",
        "aggregate evidence exceeds byte ceiling",
    )?;
    let evidence_sha256 = sha256(&bytes);
    if evidence_sha256 != EVIDENCE_SHA256 {
        return Err(VerificationError::new(
            "E_EVIDENCE_DIGEST",
            "aggregate evidence does not match the compiled detached digest",
        ));
    }
    let aggregate: Aggregate = serde_json::from_slice(&bytes)
        .map_err(|error| VerificationError::new("E_SCHEMA", error.to_string()))?;
    verify_aggregate(&aggregate, repository_root)?;
    Ok(VerificationReceipt {
        schema: SCHEMA,
        case: CASE,
        aggregate_sha256: evidence_sha256,
        verified_inputs: aggregate.inputs.len(),
        coverage: aggregate.coverage,
        production_authority: false,
    })
}

fn verify_bundle_tree(root: &Path) -> Result<(), VerificationError> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| VerificationError::new("E_IO", error.to_string()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(VerificationError::new(
            "E_TREE",
            "bundle root must be a directory",
        ));
    }
    let expected_names = BTreeSet::from(["SHA256SUMS".to_owned(), EVIDENCE_FILE.to_owned()]);
    let mut names = BTreeSet::new();
    for entry in
        fs::read_dir(root).map_err(|error| VerificationError::new("E_IO", error.to_string()))?
    {
        let entry = entry.map_err(|error| VerificationError::new("E_IO", error.to_string()))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| VerificationError::new("E_TREE", "non-UTF-8 bundle entry"))?;
        if names.len() == expected_names.len()
            || !expected_names.contains(name.as_str())
            || !names.insert(name.clone())
        {
            return Err(VerificationError::new(
                "E_TREE",
                "bundle contains an unexpected or duplicate entry",
            ));
        }
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| VerificationError::new("E_IO", error.to_string()))?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || has_multiple_hard_links(&entry.path(), &metadata)?
        {
            return Err(VerificationError::new(
                "E_TREE",
                format!("unsafe bundle entry {name}"),
            ));
        }
    }
    if names != expected_names {
        return Err(VerificationError::new(
            "E_TREE",
            "bundle must contain exactly SHA256SUMS and differential-aggregate.json",
        ));
    }
    let manifest_path = root.join("SHA256SUMS");
    let manifest_metadata = fs::symlink_metadata(&manifest_path)
        .map_err(|error| VerificationError::new("E_MANIFEST", error.to_string()))?;
    if manifest_metadata.len() > 256 {
        return Err(VerificationError::new(
            "E_MANIFEST",
            "detached manifest exceeds byte ceiling",
        ));
    }
    let manifest = String::from_utf8(read_bounded(
        &manifest_path,
        256,
        "E_MANIFEST",
        "detached manifest exceeds byte ceiling",
    )?)
    .map_err(|error| VerificationError::new("E_MANIFEST", error.to_string()))?;
    if manifest != format!("{}  {}\n", EVIDENCE_SHA256, EVIDENCE_FILE) {
        return Err(VerificationError::new(
            "E_MANIFEST",
            "detached manifest mismatch",
        ));
    }
    Ok(())
}

fn verify_aggregate(
    aggregate: &Aggregate,
    repository_root: &Path,
) -> Result<(), VerificationError> {
    if aggregate.schema != SCHEMA || aggregate.case != CASE {
        return Err(VerificationError::new(
            "E_IDENTITY_MISMATCH",
            "aggregate schema or case mismatch",
        ));
    }
    let verified_inputs = verify_bound_inputs(&aggregate.inputs, repository_root)?;
    let native = mcloving_jenkins_differential::verify_bundle(&repository_root.join(DIFF001_ROOT))
        .map_err(|error| VerificationError::new("E_DIFF001_REGRESSION", error.to_string()))?;
    let state =
        mcloving_state_policy_differential::verify_bundle(&repository_root.join(DIFF002_ROOT))
            .map_err(|error| VerificationError::new("E_DIFF002_REGRESSION", error.to_string()))?;
    let boundary =
        mcloving_boundary_differential::verify_bundle(&repository_root.join(DIFF003_ROOT))
            .map_err(|error| VerificationError::new("E_DIFF003_REGRESSION", error.to_string()))?;
    verify_receipts(&aggregate.differential_receipts, &native, &state, &boundary)?;
    verify_identity_joins(&aggregate.identity_joins)?;
    let corpus_sources =
        verify_corpus_index(verified_inputs.get("corpus_index").ok_or_else(|| {
            VerificationError::new("E_INPUT_DENOMINATOR", "missing corpus index")
        })?)?;
    verify_source_job_map(
        verified_inputs.get("source_job_map").ok_or_else(|| {
            VerificationError::new("E_INPUT_DENOMINATOR", "missing source/job map")
        })?,
        &corpus_sources,
    )?;
    verify_coverage(&aggregate.coverage)?;
    verify_taxonomy(&aggregate.taxonomy)?;
    verify_authority(&aggregate.authority)?;
    Ok(())
}

fn verify_bound_inputs(
    inputs: &[BoundInput],
    root: &Path,
) -> Result<BTreeMap<String, Vec<u8>>, VerificationError> {
    let expected: BTreeMap<&str, (&str, &str)> = [
        ("corpus_manifest", ("migration/mario-jenkins-oracle-228/corpus-v1/SHA256SUMS", "a28283de801854836887e9bc6cffd43c10bb078dbeff343fdf92d19b470a74c2")),
        ("source_manifest", ("migration/mario-jenkins-oracle-228/corpus-v1/SOURCE_SHA256SUMS", "3f95c70e04ef72dc107e7bb6f031679cfc56e5cf44e12948b89c98baacd7db06")),
        ("corpus_index", ("migration/mario-jenkins-oracle-228/corpus-v1/corpus-index.tsv", "5ecfefafc33b61d5c304a2dc6fbd60ca819882c3294605d92248f86215d51137")),
        ("source_job_map", ("migration/mario-jenkins-oracle-228/corpus-v1/source-job-map.tsv", "cc4f25bb2d487751255e124942e596320f8d5ab059b396421044f2085baf398b")),
        ("inventory", ("migration/mario-jenkins-oracle-228/inventory-20260731T064417Z-r2/eligibility-ledger.yaml", "436c76718f537ce199e4177e4db9998aad4b661176ff25d5daef17e082e4e636")),
        ("oracle_summary", ("migration/mario-jenkins-oracle-228/corpus-v1/oracle/summary.json", "c7045cc4fd280579d9427e4781ba2d672b04f38c359ce8a3e541ab8adeec5512")),
        ("compiler_receipt", ("migration/mario-jenkins-oracle-228/corpus-v1/compiler-v1/rust-admission.receipt", "3585f3e12525c42cd0b99abf61de371e64e03a20628dd1e5cbda87ae1933bb76")),
        ("mapping_catalog", ("migration/mario-jenkins-oracle-228/corpus-v1/mapping-v1/catalog.yaml", "d383ab8e15593ca5cc2847633a1410b53e676442f60dfcca93606610d1f761c8")),
        ("mapping_lock", ("migration/mario-jenkins-oracle-228/corpus-v1/mapping-v1/catalog.lock.yaml", "e8af0a08f60b7e179667e80ab19b2e8d0a119e185faa5faa4edb810e169ab203")),
        ("diff001_manifest", ("migration/mario-jenkins-oracle-228/corpus-v1/differential-v1/SHA256SUMS", "e783c38f9014b80a162328eba3abcf2565e38dfe54caa2a51660b886e3c3e73e")),
        ("diff002_evidence", ("migration/state-policy-differential-v1/state-policy.json", "70607ab0b64cb35c5b875dea7b1f94db14e6df7e931671e2f96828e1c7a52a78")),
        ("diff003_evidence", ("migration/boundary-differential-v1/boundary-differential.json", "45f4686f4a18940e72ebb4836dcc8b6136634761cb0cd01250e2ed48bdd3320b")),
    ].into_iter().collect();
    if inputs.len() != expected.len() {
        return Err(VerificationError::new(
            "E_INPUT_DENOMINATOR",
            "bound input set is incomplete",
        ));
    }
    let mut seen = BTreeSet::new();
    let mut verified = BTreeMap::new();
    for input in inputs {
        if !seen.insert(input.name.as_str()) {
            return Err(VerificationError::new(
                "E_INPUT_DENOMINATOR",
                "duplicate bound input",
            ));
        }
        let Some((path, digest)) = expected.get(input.name.as_str()) else {
            return Err(VerificationError::new(
                "E_INPUT_SUBSTITUTION",
                format!("unknown input {}", input.name),
            ));
        };
        if input.path != *path || input.sha256 != *digest || !safe_relative(&input.path) {
            return Err(VerificationError::new(
                "E_INPUT_SUBSTITUTION",
                format!("{} identity mismatch", input.name),
            ));
        }
        let bytes = read_regular_beneath(root, &input.path)?;
        if bytes.len() as u64 > MAX_BOUND_INPUT_BYTES || sha256(&bytes) != input.sha256 {
            return Err(VerificationError::new(
                "E_INPUT_SUBSTITUTION",
                format!("{} content mismatch", input.name),
            ));
        }
        verified.insert(input.name.clone(), bytes);
    }
    Ok(verified)
}

fn verify_receipts(
    receipts: &DifferentialReceipts,
    native: &mcloving_jenkins_differential::VerificationReceipt,
    state: &mcloving_state_policy_differential::VerificationReceipt,
    boundary: &mcloving_boundary_differential::VerificationReceipt,
) -> Result<(), VerificationError> {
    let expected = [
        (
            &receipts.diff001,
            DIFF001_ROOT,
            native.schema,
            native.case,
            &native.trace_sha256,
            228,
        ),
        (
            &receipts.diff002,
            DIFF002_ROOT,
            state.schema,
            state.case,
            &state.evidence_sha256,
            33,
        ),
        (
            &receipts.diff003,
            DIFF003_ROOT,
            boundary.schema,
            boundary.case,
            &boundary.evidence_sha256,
            72,
        ),
    ];
    for (receipt, root, schema, case, canonical_result_sha256, classified) in expected {
        if receipt.root != root
            || receipt.schema != schema
            || receipt.case != case
            || receipt.evidence_sha256 != *canonical_result_sha256
            || receipt.verified_records != classified
            || receipt.mismatches != 0
        {
            return Err(VerificationError::new(
                "E_RECEIPT_MISMATCH",
                format!("{} receipt mismatch", receipt.schema),
            ));
        }
    }
    if native.admitted_cases != 1
        || native.certified_cases != 1
        || native.non_admitted_cases != 227
        || state.principals != 2
        || state.decisions != 8
        || state.operational_cases != 3
        || state.adversarial_scenarios != 20
        || boundary.boundaries != 13
        || boundary.scenarios != 48
        || boundary.joins != 11
        || boundary.production_boundary_mappings != 0
        || boundary.duplicate_effects != 0
        || boundary.secret_marker_disclosures != 0
    {
        return Err(VerificationError::new(
            "E_RECEIPT_MISMATCH",
            "canonical receipt denominator or safety mismatch",
        ));
    }
    Ok(())
}

fn verify_identity_joins(joins: &IdentityJoins) -> Result<(), VerificationError> {
    let expected = IdentityJoins {
        jenkins_image_sha256: mcloving_jenkins_differential::JENKINS_IMAGE_SHA256.into(),
        jenkins_plugin_manifest_sha256:
            mcloving_jenkins_differential::JENKINS_PLUGIN_MANIFEST_SHA256.into(),
        rust_image_sha256: mcloving_jenkins_differential::MCLOVING_RUNNER_IMAGE_SHA256.into(),
        postgres_image_sha256: mcloving_jenkins_differential::MCLOVING_DATABASE_IMAGE_SHA256.into(),
        source_sha256: mcloving_jenkins_differential::SOURCE_SHA256.into(),
        pipeline_sha256: mcloving_jenkins_differential::PIPELINE_SHA256.into(),
        compiler_profile_sha256: "feeeb44d32aa10181e572a0dbbf5b2e23895731b1913bd46aba9f38d56172271"
            .into(),
        mapping_catalog_sha256: "d383ab8e15593ca5cc2847633a1410b53e676442f60dfcca93606610d1f761c8"
            .into(),
        corpus_manifest_sha256: "59faf74bb8ebfbd658f85b5224ec15ee7b0db841ad66b2da1326cd83adac4f2a"
            .into(),
        runtime_dependency_manifest_sha256:
            mcloving_boundary_differential::RUNTIME_DEPENDENCY_MANIFEST_SHA256.into(),
        identity_client_manifest_sha256:
            mcloving_boundary_differential::IDENTITY_CLIENT_MANIFEST_SHA256.into(),
        release_id: mcloving_boundary_differential::RELEASE_ID.into(),
        release_version: "v0.1.0".into(),
        release_profile: "private-linux-x86_64".into(),
        release_envelope_sha256: mcloving_boundary_differential::RELEASE_ENVELOPE_SHA256.into(),
        release_evidence_manifest_sha256:
            mcloving_boundary_differential::RELEASE_EVIDENCE_MANIFEST_SHA256.into(),
        release_verification_receipt_sha256:
            mcloving_boundary_differential::RELEASE_VERIFICATION_RECEIPT_SHA256.into(),
        mig005a_forward_sha256: mcloving_state_policy_differential::MIG005A_FORWARD_SHA256.into(),
        mig005a_reverse_sha256: mcloving_state_policy_differential::MIG005A_REVERSE_SHA256.into(),
        mig005a_evidence_sha256: mcloving_state_policy_differential::MIG005A_EVIDENCE_SHA256.into(),
    };
    if joins != &expected
        || joins.jenkins_image_sha256 != mcloving_state_policy_differential::JENKINS_IMAGE_SHA256
        || joins.jenkins_image_sha256 != mcloving_boundary_differential::JENKINS_IMAGE_SHA256
        || joins.rust_image_sha256 != mcloving_boundary_differential::RUST_IMAGE_SHA256
        || joins.postgres_image_sha256 != mcloving_state_policy_differential::POSTGRES_IMAGE_SHA256
        || joins.postgres_image_sha256 != mcloving_boundary_differential::POSTGRES_IMAGE_SHA256
    {
        return Err(VerificationError::new(
            "E_IDENTITY_MISMATCH",
            "cross-differential identity join mismatch",
        ));
    }
    Ok(())
}

fn verify_corpus_index(bytes: &[u8]) -> Result<BTreeSet<String>, VerificationError> {
    let text = String::from_utf8(bytes.to_vec())
        .map_err(|error| VerificationError::new("E_CASE_COVERAGE", error.to_string()))?;
    let mut lines = text.lines();
    let header = lines
        .next()
        .ok_or_else(|| VerificationError::new("E_CASE_COVERAGE", "missing corpus header"))?;
    let columns: Vec<&str> = header.split('\t').collect();
    let positions: BTreeMap<&str, usize> =
        columns.iter().enumerate().map(|(i, v)| (*v, i)).collect();
    for required in ["file", "source_sha256", "migration_class", "worker_v1"] {
        if !positions.contains_key(required) {
            return Err(VerificationError::new(
                "E_CASE_COVERAGE",
                format!("missing {required} column"),
            ));
        }
    }
    let mut files = BTreeSet::new();
    let mut admitted = 0_u64;
    let mut rejected = 0_u64;
    for line in lines {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() != columns.len() || !files.insert(fields[positions["file"]].to_owned()) {
            return Err(VerificationError::new(
                "E_CASE_COVERAGE",
                "malformed or duplicate corpus row",
            ));
        }
        match (
            fields[positions["migration_class"]],
            fields[positions["worker_v1"]],
        ) {
            ("admitted-compile-only", "compiled-disabled-import") => {
                admitted += 1;
                if fields[positions["source_sha256"]]
                    != mcloving_jenkins_differential::SOURCE_SHA256
                {
                    return Err(VerificationError::new(
                        "E_IDENTITY_MISMATCH",
                        "admitted source mismatch",
                    ));
                }
            }
            ("unsupported", "E_SOURCE_NOT_ADMITTED") => rejected += 1,
            _ => {
                return Err(VerificationError::new(
                    "E_UNCLASSIFIED_CASE",
                    "unstable or unclassified corpus disposition",
                ));
            }
        }
    }
    if files.len() != 228 || admitted != 1 || rejected != 227 {
        return Err(VerificationError::new(
            "E_CASE_COVERAGE",
            "corpus denominator mismatch",
        ));
    }
    Ok(files)
}

fn verify_source_job_map(
    bytes: &[u8],
    corpus_sources: &BTreeSet<String>,
) -> Result<(), VerificationError> {
    let text = String::from_utf8(bytes.to_vec())
        .map_err(|error| VerificationError::new("E_POPULATION_COVERAGE", error.to_string()))?;
    let mut lines = text.lines();
    if lines.next()
        != Some(
            "file\tjob_id\tinventory_inline_sha256\tconfig_sha256\tenabled\tstate_generation\tstate_reason\tnode_authority",
        )
    {
        return Err(VerificationError::new(
            "E_POPULATION_COVERAGE",
            "source/job header mismatch",
        ));
    }
    let mut jobs = BTreeSet::new();
    let mut sources = BTreeSet::new();
    for line in lines {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() != 8
            || !jobs.insert(fields[1])
            || fields[4] != "false"
            || fields[6] != "offline-frozen-source-state"
            || fields[7] != "parse-only-controller-no-executors-or-nodes"
        {
            return Err(VerificationError::new(
                "E_POPULATION_COVERAGE",
                "job mapping is duplicated, enabled, or authoritative",
            ));
        }
        sources.insert(fields[0].to_owned());
    }
    if jobs.len() != 230 || sources.len() != 228 || &sources != corpus_sources {
        return Err(VerificationError::new(
            "E_POPULATION_COVERAGE",
            "expected 230 jobs over 228 sources",
        ));
    }
    Ok(())
}

fn verify_coverage(coverage: &[CoverageMetric]) -> Result<(), VerificationError> {
    let expected = [
        (
            "production_population",
            230,
            230,
            "disabled_jobs",
            "source_job_map",
        ),
        (
            "parse_reach",
            140,
            228,
            "corpus_files",
            "oracle_summary.chengis_parsed",
        ),
        (
            "native_runnable",
            1,
            228,
            "corpus_files",
            "diff001.certified_cases",
        ),
        (
            "actionable_migration",
            1,
            228,
            "corpus_files",
            "compiler_and_mapping_admission",
        ),
        (
            "deterministic_rejection",
            227,
            227,
            "non_admitted_cases",
            "E_SOURCE_NOT_ADMITTED",
        ),
        (
            "certified_equivalence_admitted",
            1,
            1,
            "admitted_cases",
            "diff001.certified_cases",
        ),
        (
            "certified_equivalence_corpus",
            1,
            228,
            "corpus_files",
            "diff001.certified_cases",
        ),
    ];
    if coverage.len() != expected.len() {
        return Err(VerificationError::new(
            "E_DENOMINATOR_BORROWING",
            "coverage metric set mismatch",
        ));
    }
    for (metric, (name, numerator, denominator, unit, evidence)) in coverage.iter().zip(expected) {
        if metric.name != name
            || metric.numerator != numerator
            || metric.denominator != denominator
            || metric.unit != unit
            || metric.evidence != evidence
        {
            return Err(VerificationError::new(
                "E_DENOMINATOR_BORROWING",
                format!("{name} metric mismatch"),
            ));
        }
    }
    Ok(())
}

fn verify_taxonomy(taxonomy: &Taxonomy) -> Result<(), VerificationError> {
    if taxonomy.deterministic_rejection != ["E_SOURCE_NOT_ADMITTED"]
        || taxonomy.aggregate_mismatch
            != [
                "E_AUTHORITY",
                "E_CASE_COVERAGE",
                "E_DENOMINATOR_BORROWING",
                "E_EVIDENCE_DIGEST",
                "E_IDENTITY_MISMATCH",
                "E_INPUT_DENOMINATOR",
                "E_INPUT_SUBSTITUTION",
                "E_IO",
                "E_MANIFEST",
                "E_POPULATION_COVERAGE",
                "E_RECEIPT_MISMATCH",
                "E_SCHEMA",
                "E_SIZE",
                "E_TAXONOMY",
                "E_TREE",
                "E_UNCLASSIFIED_CASE",
            ]
        || taxonomy.regression
            != [
                "E_DIFF001_REGRESSION",
                "E_DIFF002_REGRESSION",
                "E_DIFF003_REGRESSION",
            ]
    {
        return Err(VerificationError::new(
            "E_TAXONOMY",
            "taxonomy is unstable or incomplete",
        ));
    }
    Ok(())
}

fn verify_authority(authority: &Authority) -> Result<(), VerificationError> {
    if authority.certification_scope != "immutable_contained_evidence_only"
        || authority.production_authority
        || authority.production_credentials
        || authority.production_effects
        || authority.scheduler_authority
        || authority.cutover_authority
        || authority.migration_package_is_input
        || authority.historical_ranvil_native.numerator != 18
        || authority.historical_ranvil_native.denominator != 228
        || authority.historical_ranvil_native.meaning != "legacy_parser_model_reach_only"
        || authority
            .historical_ranvil_native
            .grants_runnable_or_equivalence_claim
    {
        return Err(VerificationError::new(
            "E_AUTHORITY",
            "aggregate broadens authority or historical claim",
        ));
    }
    Ok(())
}

fn safe_relative(path: &str) -> bool {
    !path.is_empty()
        && Path::new(path)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

#[cfg(unix)]
fn has_multiple_hard_links(
    _path: &Path,
    metadata: &fs::Metadata,
) -> Result<bool, VerificationError> {
    use std::os::unix::fs::MetadataExt as _;

    Ok(metadata.nlink() != 1)
}

#[cfg(windows)]
fn has_multiple_hard_links(
    path: &Path,
    _metadata: &fs::Metadata,
) -> Result<bool, VerificationError> {
    let file =
        fs::File::open(path).map_err(|error| VerificationError::new("E_IO", error.to_string()))?;
    let count = mcloving_windows_job::file_link_count(&file)
        .map_err(|error| VerificationError::new("E_IO", error.to_string()))?;
    Ok(count != 1)
}

#[cfg(not(any(unix, windows)))]
fn has_multiple_hard_links(
    _path: &Path,
    _metadata: &fs::Metadata,
) -> Result<bool, VerificationError> {
    Ok(true)
}

fn read_bounded(
    path: &Path,
    max_bytes: u64,
    size_code: &'static str,
    size_message: &'static str,
) -> Result<Vec<u8>, VerificationError> {
    let file =
        fs::File::open(path).map_err(|error| VerificationError::new("E_IO", error.to_string()))?;
    let mut bytes = Vec::new();
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| VerificationError::new("E_IO", error.to_string()))?;
    if bytes.len() as u64 > max_bytes {
        return Err(VerificationError::new(size_code, size_message));
    }
    Ok(bytes)
}

fn read_regular_beneath(root: &Path, relative: &str) -> Result<Vec<u8>, VerificationError> {
    if !safe_relative(relative) {
        return Err(VerificationError::new(
            "E_INPUT_SUBSTITUTION",
            "input path is not a safe relative path",
        ));
    }
    let root_metadata = fs::symlink_metadata(root)
        .map_err(|error| VerificationError::new("E_IO", error.to_string()))?;
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Err(VerificationError::new(
            "E_INPUT_SUBSTITUTION",
            "repository root is not a direct directory",
        ));
    }
    let mut current = root.to_path_buf();
    for component in Path::new(relative).components() {
        let Component::Normal(part) = component else {
            return Err(VerificationError::new(
                "E_INPUT_SUBSTITUTION",
                "input path contains an unsafe component",
            ));
        };
        current.push(part);
        let metadata = fs::symlink_metadata(&current)
            .map_err(|error| VerificationError::new("E_IO", error.to_string()))?;
        if metadata.file_type().is_symlink() {
            return Err(VerificationError::new(
                "E_INPUT_SUBSTITUTION",
                format!("symlinked input component {}", current.display()),
            ));
        }
    }
    let metadata = fs::symlink_metadata(&current)
        .map_err(|error| VerificationError::new("E_IO", error.to_string()))?;
    if !metadata.is_file() || has_multiple_hard_links(&current, &metadata)? {
        return Err(VerificationError::new(
            "E_INPUT_SUBSTITUTION",
            "bound input is not an unaliased regular file",
        ));
    }
    if metadata.len() > MAX_BOUND_INPUT_BYTES {
        return Err(VerificationError::new(
            "E_INPUT_SUBSTITUTION",
            "bound input exceeds byte ceiling",
        ));
    }
    read_bounded(
        &current,
        MAX_BOUND_INPUT_BYTES,
        "E_INPUT_SUBSTITUTION",
        "bound input exceeds byte ceiling",
    )
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repository() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn fixture() -> Aggregate {
        serde_json::from_slice(include_bytes!(
            "../../../migration/differential-aggregate-v1/differential-aggregate.json"
        ))
        .expect("parse aggregate fixture")
    }

    #[test]
    fn exact_aggregate_verifies_all_three_canonical_receipts() {
        verify_aggregate(&fixture(), &repository()).expect("verify aggregate");
    }

    #[test]
    fn denominator_borrowing_fails_closed() {
        let mut aggregate = fixture();
        aggregate.coverage[2].denominator = 1;
        assert_eq!(
            verify_aggregate(&aggregate, &repository())
                .unwrap_err()
                .code,
            "E_DENOMINATOR_BORROWING"
        );
    }

    #[test]
    fn input_substitution_and_authority_broadening_fail_closed() {
        let mut substituted = fixture();
        substituted.inputs[0].path = "../substituted".into();
        assert_eq!(
            verify_aggregate(&substituted, &repository())
                .unwrap_err()
                .code,
            "E_INPUT_SUBSTITUTION"
        );

        let mut authority = fixture();
        authority.authority.production_authority = true;
        assert_eq!(
            verify_aggregate(&authority, &repository())
                .unwrap_err()
                .code,
            "E_AUTHORITY"
        );
    }

    #[test]
    fn identity_and_taxonomy_mutations_fail_closed() {
        let mut identity = fixture();
        identity.identity_joins.release_id = "substituted".into();
        assert_eq!(
            verify_aggregate(&identity, &repository()).unwrap_err().code,
            "E_IDENTITY_MISMATCH"
        );

        let mut taxonomy = fixture();
        taxonomy.taxonomy.deterministic_rejection[0] = "unsupported".into();
        assert_eq!(
            verify_aggregate(&taxonomy, &repository()).unwrap_err().code,
            "E_TAXONOMY"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn multiply_linked_bound_input_fails_closed() {
        let temporary = tempfile::tempdir().expect("temporary repository");
        let input = temporary.path().join("input.json");
        let alias_directory = tempfile::tempdir().expect("alias directory");
        fs::write(&input, b"{}\n").expect("write input");
        fs::hard_link(&input, alias_directory.path().join("input-alias")).expect("hardlink input");

        assert_eq!(
            read_regular_beneath(temporary.path(), "input.json")
                .unwrap_err()
                .code,
            "E_INPUT_SUBSTITUTION"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_repository_root_fails_closed() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().expect("parent directory");
        let repository = parent.path().join("repository");
        let alias = parent.path().join("repository-alias");
        fs::create_dir(&repository).expect("create repository");
        fs::write(repository.join("input.json"), b"{}\n").expect("write input");
        symlink(&repository, &alias).expect("symlink repository");

        assert_eq!(
            read_regular_beneath(&alias, "input.json").unwrap_err().code,
            "E_INPUT_SUBSTITUTION"
        );
    }

    #[test]
    fn oversized_bound_input_fails_before_reading() {
        let repository = tempfile::tempdir().expect("temporary repository");
        let input = fs::File::create(repository.path().join("input.json")).expect("create input");
        input
            .set_len(MAX_BOUND_INPUT_BYTES + 1)
            .expect("size oversized input");

        assert_eq!(
            read_regular_beneath(repository.path(), "input.json")
                .unwrap_err()
                .code,
            "E_INPUT_SUBSTITUTION"
        );
    }
}
