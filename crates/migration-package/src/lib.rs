//! Deterministic, deny-authority MIG-007 migration package.
//!
//! The package embeds the exact admitted compiler artifacts and the complete
//! corpus disposition ledger, then composes the existing canonical verifiers.
//! It does not implement an alternative compiler, mapping, differential, or
//! state-transform acceptance path.

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::Path;

use mcloving_jenkins_compiler_admission::{
    ADMITTED_JOB_GENERATION, ADMITTED_JOB_ID, ADMITTED_SOURCE_SHA256, COMPILER, CONTROLLER,
    ExpectedAdmission, INVENTORY_FINGERPRINT, PROFILE_SHA256, admit_response,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

mod private;

pub use private::{
    MAX_PRIVATE_PACKAGE_BYTES, PrivateGenerationInputs, PrivateVerificationInputs,
    PrivateVerificationReceipt, generate_private, verify_private,
};

pub const SCHEMA: &str = "mcloving.jenkins.migration-package/v1";
pub const PACKAGE_ID: &str = "mario-corpus-052-disabled-v1";
pub const PACKAGE_FILE: &str = "migration-package.json";
pub const MAX_PACKAGE_BYTES: usize = 1_048_576;
pub const PACKAGE_SHA256: &str = "304f75f7c85f11b4fb15ce11f5cf65e5dc69168e3ef85b03a9b3eabdbb3d4ed9";

const REQUEST_ID: &str = "mig003-golden";
const SOURCE_FILE: &str =
    "migration/mario-jenkins-oracle-228/corpus-v1/sources/cinqict_jenkinsdev.Jenkinsfile";
const COMPILER_ROOT: &str = "migration/mario-jenkins-oracle-228/corpus-v1/compiler-v1";
const MAPPING_ROOT: &str = "migration/mario-jenkins-oracle-228/corpus-v1/mapping-v1";
const CORPUS_INDEX: &str = "migration/mario-jenkins-oracle-228/corpus-v1/corpus-index.tsv";
const AGGREGATE_ROOT: &str = "migration/differential-aggregate-v1";
const AGGREGATE_FILE: &str = "migration/differential-aggregate-v1/differential-aggregate.json";
const STATE_POLICY_FILE: &str = "migration/state-policy-differential-v1/state-policy.json";
const ELIGIBILITY_LEDGER_FILE: &str =
    "migration/mario-jenkins-oracle-228/inventory-20260731T064417Z-r2/eligibility-ledger.yaml";
const PERSISTENT_STATE_FILE: &str =
    "migration/mario-jenkins-oracle-228/inventory-20260731T064417Z-r2/persistent-state.yaml";

const SOURCE_CONFIG_SHA256: &str =
    "e76362bbc8e899510b8498808ffd0d2f83bb64d3215cf2c5b31690895f251d97";
const WORKER_RESPONSE_SHA256: &str =
    "2eec55ccd153f7692b1cfd1b2d606a1a45af434a154bebdd62f9ab0bd89aef52";
const PIPELINE_SHA256: &str = "551d489ca13bf5d130bdc5c10ce35e5d3d988bdaa1c5488dd9bc79b30674acdc";
const JOBSTATE_SHA256: &str = "45f86c932d04a9d109afc0dd2b8a0ef30909311a59d4f453d77ed4b0e98c5be4";
const COMPILER_TRACE_SHA256: &str =
    "faa38c8829a38f43319765217e6f3e73ba10857eeec1efc76e7855dac7df7950";
const CANONICAL_IR_SHA256: &str =
    "2a9b8b7bcd076950c67de874bd1e2b693af511ad55a7de3495d5c0b4210349d3";
const CORPUS_MANIFEST_SHA256: &str =
    "59faf74bb8ebfbd658f85b5224ec15ee7b0db841ad66b2da1326cd83adac4f2a";
const CORPUS_INDEX_SHA256: &str =
    "5ecfefafc33b61d5c304a2dc6fbd60ca819882c3294605d92248f86215d51137";
const ORACLE_SUMMARY_SHA256: &str =
    "c7045cc4fd280579d9427e4781ba2d672b04f38c359ce8a3e541ab8adeec5512";
const MAPPING_LOCK_SHA256: &str =
    "e8af0a08f60b7e179667e80ab19b2e8d0a119e185faa5faa4edb810e169ab203";
const STATE_POLICY_SHA256: &str =
    "70607ab0b64cb35c5b875dea7b1f94db14e6df7e931671e2f96828e1c7a52a78";
const ELIGIBILITY_LEDGER_SHA256: &str =
    "436c76718f537ce199e4177e4db9998aad4b661176ff25d5daef17e082e4e636";
const PERSISTENT_STATE_SHA256: &str =
    "527700913d3f730a0f51c70ee40fb0be3a06c2385d92a69bf5a919d7536634b1";
const WORKER_IMAGE_SHA256: &str =
    "8459b3b080d4239daffa2d5ba632c707dfbd18657b0176fb0e6340ff5dd45548";

const RELEASE_ID: &str = "3d38cc2c-a88b-4fac-aae2-7d9459c36ee5";
const RELEASE_VERSION: &str = "v0.1.0";
const RELEASE_PROFILE: &str = "private-linux-x86_64";
const RELEASE_ENVELOPE_SHA256: &str =
    "09fea3d02f5bdb55fd4835a6bf92339eb47cfbba9f33b8b4a3bc4925596e293e";
const RELEASE_EVIDENCE_MANIFEST_SHA256: &str =
    "0ccc39a48217524efe681d984fea41f4f1afe1d3fa1be3177fa4598e6ddf8a41";
const RELEASE_VERIFICATION_RECEIPT_SHA256: &str =
    "6c11cc651b1f4daab6647b43947a433ae565b1a11dfa09cf5cf48e9f789f139f";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationReceipt {
    pub schema: &'static str,
    pub package_sha256: String,
    pub packaged_cases: usize,
    pub rejected_cases: usize,
    pub admitted_state_dependencies: usize,
    pub package_complete: bool,
    pub production_authority: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageError {
    pub code: &'static str,
    pub message: String,
}

impl PackageError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for PackageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for PackageError {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MigrationPackage {
    schema: String,
    package_id: String,
    identities: Identities,
    artifacts: Artifacts,
    state_transfer: StateTransferDisposition,
    dispositions: Vec<Disposition>,
    authority: Authority,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Identities {
    controller: String,
    inventory_fingerprint: String,
    corpus_manifest_sha256: String,
    corpus_index_sha256: String,
    oracle_summary_sha256: String,
    source_job_id: String,
    source_sha256: String,
    source_config_sha256: String,
    compiler: String,
    compiler_profile_sha256: String,
    compiler_worker_image_sha256: String,
    compiler_response_sha256: String,
    compiler_trace_sha256: String,
    pipeline_sha256: String,
    jobstate_sha256: String,
    canonical_ir_sha256: String,
    mapping_catalog_sha256: String,
    mapping_semantic_sha256: String,
    mapping_lock_sha256: String,
    differential_aggregate_sha256: String,
    state_policy_sha256: String,
    eligibility_ledger_sha256: String,
    persistent_state_inventory_sha256: String,
    release_id: String,
    release_version: String,
    release_profile: String,
    release_envelope_sha256: String,
    release_evidence_manifest_sha256: String,
    release_verification_receipt_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Artifacts {
    source_export: String,
    worker_response_edn: String,
    pipeline_yaml: String,
    jobstate_yaml: String,
    compiler_trace_yaml: String,
    mapping_catalog_yaml: String,
    mapping_lock_yaml: String,
    corpus_index_tsv: String,
    differential_aggregate_json: String,
    state_policy_json: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StateTransferDisposition {
    status: String,
    blocking_error: String,
    admitted_state_dependencies: Vec<StateDependency>,
    case_specific_rehearsal_receipts: Vec<String>,
    packaged_artifacts: Vec<String>,
    cutover_eligible: bool,
    rollback_eligible: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StateDependency {
    id: String,
    kind: String,
    record_count: usize,
    record_source_sha256: String,
    record_subject_sha256: String,
    restore_target: String,
    conflict_policy: String,
    retention_policy_id: String,
    retention_policy_sha256: String,
    retention_deadline: String,
    forward_mapping_id: String,
    forward_disposition: String,
    forward_evidence_sha256: String,
    rollback_mapping_id: String,
    rollback_disposition: String,
    rollback_evidence_sha256: String,
}

#[derive(Deserialize)]
struct EligibilityLedger {
    jobs: Vec<EligibilityJob>,
}

#[derive(Deserialize)]
struct EligibilityJob {
    job_id: String,
    persistent_state_ids: Vec<String>,
}

#[derive(Deserialize)]
struct PersistentStateLedger {
    jobs: Vec<PersistentStateJob>,
}

#[derive(Deserialize)]
struct PersistentStateJob {
    job_id: String,
    records: Vec<PersistentStateRecord>,
}

#[derive(Deserialize)]
struct PersistentStateRecord {
    id: String,
    kind: String,
    record_count: RecordCount,
    source_sha256: String,
    restore_target: String,
    conflict_policy: String,
    retention_policy_id: String,
    retention_policy_sha256: String,
    retention_deadline: String,
    forward_transform: StateTransform,
    rollback_transform: StateTransform,
}

#[derive(Deserialize)]
struct RecordCount {
    count: usize,
    subject_sha256: String,
}

#[derive(Deserialize)]
struct StateTransform {
    mapping_id: String,
    disposition: String,
    evidence_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct Disposition {
    file: String,
    source_sha256: String,
    migration_class: String,
    worker_disposition: String,
    package_status: String,
    source_certified_equivalence: bool,
    mig006_certified_equivalence: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Authority {
    source_state: String,
    production_authority: bool,
    production_credentials: bool,
    production_effects: bool,
    scheduler_authority: bool,
    trigger_authority: bool,
    canary_authority: bool,
    cutover_authority: bool,
    rollback_authority: bool,
    decommission_authority: bool,
    credential_material_present: bool,
}

pub fn generate(repository_root: &Path) -> Result<Vec<u8>, PackageError> {
    let artifacts = Artifacts {
        source_export: read_utf8(repository_root, SOURCE_FILE)?,
        worker_response_edn: read_utf8(
            repository_root,
            &format!("{COMPILER_ROOT}/worker-response.edn"),
        )?,
        pipeline_yaml: read_utf8(repository_root, &format!("{COMPILER_ROOT}/pipeline.yaml"))?,
        jobstate_yaml: read_utf8(repository_root, &format!("{COMPILER_ROOT}/jobstate.yaml"))?,
        compiler_trace_yaml: read_utf8(
            repository_root,
            &format!("{COMPILER_ROOT}/expected-trace.yaml"),
        )?,
        mapping_catalog_yaml: read_utf8(repository_root, &format!("{MAPPING_ROOT}/catalog.yaml"))?,
        mapping_lock_yaml: read_utf8(
            repository_root,
            &format!("{MAPPING_ROOT}/catalog.lock.yaml"),
        )?,
        corpus_index_tsv: read_utf8(repository_root, CORPUS_INDEX)?,
        differential_aggregate_json: read_utf8(repository_root, AGGREGATE_FILE)?,
        state_policy_json: read_utf8(repository_root, STATE_POLICY_FILE)?,
    };
    let dispositions = dispositions_from_index(&artifacts.corpus_index_tsv)?;
    let state_transfer = expected_state_transfer(repository_root)?;
    render(&MigrationPackage {
        schema: SCHEMA.into(),
        package_id: PACKAGE_ID.into(),
        identities: expected_identities(),
        artifacts,
        state_transfer,
        dispositions,
        authority: expected_authority(),
    })
}

pub fn verify(bytes: &[u8], repository_root: &Path) -> Result<VerificationReceipt, PackageError> {
    if bytes.len() > MAX_PACKAGE_BYTES {
        return Err(PackageError::new(
            "E_SIZE",
            "package exceeds the one MiB byte limit",
        ));
    }
    let package: MigrationPackage = serde_json::from_slice(bytes)
        .map_err(|error| PackageError::new("E_SCHEMA", error.to_string()))?;
    if render(&package)? != bytes {
        return Err(PackageError::new(
            "E_CANONICAL",
            "package bytes are not canonical pretty JSON",
        ));
    }
    let digest = sha256(bytes);
    if digest != PACKAGE_SHA256 {
        return Err(PackageError::new(
            "E_PACKAGE_DIGEST",
            "package digest mismatch",
        ));
    }
    if package.schema != SCHEMA || package.package_id != PACKAGE_ID {
        return Err(PackageError::new("E_SCHEMA", "package identity mismatch"));
    }
    if package.identities != expected_identities() {
        return Err(PackageError::new("E_IDENTITY", "identity binding mismatch"));
    }
    if package.state_transfer != expected_state_transfer(repository_root)? {
        return Err(PackageError::new(
            "E_STATE_TRANSFER",
            "state-transfer disposition or dependency denominator mismatch",
        ));
    }
    if package.authority != expected_authority() {
        return Err(PackageError::new(
            "E_AUTHORITY",
            "authority ledger mismatch",
        ));
    }

    verify_artifact_digests(&package.artifacts)?;
    let admission = admit_response(
        package.artifacts.worker_response_edn.as_bytes(),
        ExpectedAdmission {
            request_id: REQUEST_ID,
            job_id: ADMITTED_JOB_ID,
            job_generation: ADMITTED_JOB_GENERATION,
            source: package.artifacts.source_export.as_bytes(),
        },
    )
    .map_err(|error| PackageError::new("E_COMPILER", error.to_string()))?;
    if admission.pipeline_yaml_sha256 != PIPELINE_SHA256
        || admission.jobstate_yaml_sha256 != JOBSTATE_SHA256
        || admission.canonical_ir_sha256 != CANONICAL_IR_SHA256
        || admission.state != "disabled"
        || admission.stages != 1
        || admission.steps != 1
    {
        return Err(PackageError::new(
            "E_COMPILER",
            "compiler admission receipt mismatch",
        ));
    }

    let (catalog_sha256, semantic_sha256) =
        mcloving_jenkins_mapping_catalog::validate_catalog_bytes(
            package.artifacts.mapping_catalog_yaml.as_bytes(),
        )
        .map_err(|error| PackageError::new("E_MAPPING", error.to_string()))?;
    if catalog_sha256 != mcloving_jenkins_mapping_catalog::CATALOG_SHA256
        || semantic_sha256 != mcloving_jenkins_mapping_catalog::CATALOG_SEMANTIC_SHA256
    {
        return Err(PackageError::new("E_MAPPING", "mapping receipt mismatch"));
    }
    let bundle =
        mcloving_jenkins_mapping_catalog::verify_bundle(&repository_root.join(MAPPING_ROOT))
            .map_err(|error| PackageError::new("E_MAPPING", error.to_string()))?;
    if bundle.catalog_sha256 != catalog_sha256 || bundle.semantic_sha256 != semantic_sha256 {
        return Err(PackageError::new(
            "E_MAPPING",
            "mapping bundle and embedded catalog mismatch",
        ));
    }

    mcloving_state_policy_differential::verify_evidence_bytes(
        package.artifacts.state_policy_json.as_bytes(),
    )
    .map_err(|error| PackageError::new("E_STATE_POLICY", error.to_string()))?;
    let aggregate = mcloving_differential_aggregate::verify_bundle(
        &repository_root.join(AGGREGATE_ROOT),
        repository_root,
    )
    .map_err(|error| PackageError::new("E_AGGREGATE", error.to_string()))?;
    if aggregate.aggregate_sha256 != mcloving_differential_aggregate::EVIDENCE_SHA256
        || aggregate.production_authority
    {
        return Err(PackageError::new(
            "E_AGGREGATE",
            "aggregate receipt mismatch",
        ));
    }

    let expected_dispositions = dispositions_from_index(&package.artifacts.corpus_index_tsv)?;
    if package.dispositions != expected_dispositions {
        return Err(PackageError::new(
            "E_DISPOSITION",
            "case disposition ledger mismatch",
        ));
    }
    let packaged_cases = package
        .dispositions
        .iter()
        .filter(|entry| entry.package_status == "packaged_disabled_certified")
        .count();
    let rejected_cases = package
        .dispositions
        .iter()
        .filter(|entry| {
            entry
                .package_status
                .starts_with("deterministically_rejected")
        })
        .count();
    if packaged_cases != 0 || rejected_cases != 228 || package.dispositions.len() != 228 {
        return Err(PackageError::new(
            "E_DENOMINATOR",
            "incomplete package must reject all 228 cases",
        ));
    }

    Ok(VerificationReceipt {
        schema: SCHEMA,
        package_sha256: digest,
        packaged_cases,
        rejected_cases,
        admitted_state_dependencies: package.state_transfer.admitted_state_dependencies.len(),
        package_complete: false,
        production_authority: false,
    })
}

fn verify_artifact_digests(artifacts: &Artifacts) -> Result<(), PackageError> {
    let expected = [
        (
            "source export",
            &artifacts.source_export,
            ADMITTED_SOURCE_SHA256,
        ),
        (
            "compiler response",
            &artifacts.worker_response_edn,
            WORKER_RESPONSE_SHA256,
        ),
        ("pipeline YAML", &artifacts.pipeline_yaml, PIPELINE_SHA256),
        ("jobstate YAML", &artifacts.jobstate_yaml, JOBSTATE_SHA256),
        (
            "compiler trace",
            &artifacts.compiler_trace_yaml,
            COMPILER_TRACE_SHA256,
        ),
        (
            "mapping catalog",
            &artifacts.mapping_catalog_yaml,
            mcloving_jenkins_mapping_catalog::CATALOG_SHA256,
        ),
        (
            "mapping lock",
            &artifacts.mapping_lock_yaml,
            MAPPING_LOCK_SHA256,
        ),
        (
            "corpus index",
            &artifacts.corpus_index_tsv,
            CORPUS_INDEX_SHA256,
        ),
        (
            "differential aggregate",
            &artifacts.differential_aggregate_json,
            mcloving_differential_aggregate::EVIDENCE_SHA256,
        ),
        (
            "state policy",
            &artifacts.state_policy_json,
            STATE_POLICY_SHA256,
        ),
    ];
    for (name, value, expected_digest) in expected {
        if sha256(value.as_bytes()) != expected_digest {
            return Err(PackageError::new(
                "E_ARTIFACT",
                format!("{name} digest mismatch"),
            ));
        }
    }
    Ok(())
}

fn expected_identities() -> Identities {
    Identities {
        controller: CONTROLLER.into(),
        inventory_fingerprint: INVENTORY_FINGERPRINT.into(),
        corpus_manifest_sha256: CORPUS_MANIFEST_SHA256.into(),
        corpus_index_sha256: CORPUS_INDEX_SHA256.into(),
        oracle_summary_sha256: ORACLE_SUMMARY_SHA256.into(),
        source_job_id: ADMITTED_JOB_ID.into(),
        source_sha256: ADMITTED_SOURCE_SHA256.into(),
        source_config_sha256: SOURCE_CONFIG_SHA256.into(),
        compiler: COMPILER.into(),
        compiler_profile_sha256: PROFILE_SHA256.into(),
        compiler_worker_image_sha256: WORKER_IMAGE_SHA256.into(),
        compiler_response_sha256: WORKER_RESPONSE_SHA256.into(),
        compiler_trace_sha256: COMPILER_TRACE_SHA256.into(),
        pipeline_sha256: PIPELINE_SHA256.into(),
        jobstate_sha256: JOBSTATE_SHA256.into(),
        canonical_ir_sha256: CANONICAL_IR_SHA256.into(),
        mapping_catalog_sha256: mcloving_jenkins_mapping_catalog::CATALOG_SHA256.into(),
        mapping_semantic_sha256: mcloving_jenkins_mapping_catalog::CATALOG_SEMANTIC_SHA256.into(),
        mapping_lock_sha256: MAPPING_LOCK_SHA256.into(),
        differential_aggregate_sha256: mcloving_differential_aggregate::EVIDENCE_SHA256.into(),
        state_policy_sha256: STATE_POLICY_SHA256.into(),
        eligibility_ledger_sha256: ELIGIBILITY_LEDGER_SHA256.into(),
        persistent_state_inventory_sha256: PERSISTENT_STATE_SHA256.into(),
        release_id: RELEASE_ID.into(),
        release_version: RELEASE_VERSION.into(),
        release_profile: RELEASE_PROFILE.into(),
        release_envelope_sha256: RELEASE_ENVELOPE_SHA256.into(),
        release_evidence_manifest_sha256: RELEASE_EVIDENCE_MANIFEST_SHA256.into(),
        release_verification_receipt_sha256: RELEASE_VERIFICATION_RECEIPT_SHA256.into(),
    }
}

fn expected_state_transfer(
    repository_root: &Path,
) -> Result<StateTransferDisposition, PackageError> {
    let eligibility_bytes = read_utf8(repository_root, ELIGIBILITY_LEDGER_FILE)?;
    let persistent_state_bytes = read_utf8(repository_root, PERSISTENT_STATE_FILE)?;
    if sha256(eligibility_bytes.as_bytes()) != ELIGIBILITY_LEDGER_SHA256
        || sha256(persistent_state_bytes.as_bytes()) != PERSISTENT_STATE_SHA256
    {
        return Err(PackageError::new(
            "E_STATE_INVENTORY",
            "state-inventory digest mismatch",
        ));
    }
    let eligibility: EligibilityLedger = serde_saphyr::from_str(&eligibility_bytes)
        .map_err(|error| PackageError::new("E_STATE_INVENTORY", error.to_string()))?;
    let eligible_jobs = eligibility
        .jobs
        .iter()
        .filter(|job| job.job_id == ADMITTED_JOB_ID)
        .collect::<Vec<_>>();
    if eligible_jobs.len() != 1 || eligible_jobs[0].persistent_state_ids != ["build-history"] {
        return Err(PackageError::new(
            "E_STATE_INVENTORY",
            "admitted job state-dependency set mismatch",
        ));
    }
    let persistent_state: PersistentStateLedger =
        serde_saphyr::from_str(&persistent_state_bytes)
            .map_err(|error| PackageError::new("E_STATE_INVENTORY", error.to_string()))?;
    let state_jobs = persistent_state
        .jobs
        .iter()
        .filter(|job| job.job_id == ADMITTED_JOB_ID)
        .collect::<Vec<_>>();
    if state_jobs.len() != 1 || state_jobs[0].records.len() != 1 {
        return Err(PackageError::new(
            "E_STATE_INVENTORY",
            "admitted job state-record denominator mismatch",
        ));
    }
    let record = &state_jobs[0].records[0];
    if record.id != "build-history"
        || record.record_count.count != 1
        || record.forward_transform.disposition != "unsupported"
        || record.rollback_transform.disposition != "unsupported"
    {
        return Err(PackageError::new(
            "E_STATE_INVENTORY",
            "admitted build-history transfer classification mismatch",
        ));
    }
    let dependency = StateDependency {
        id: record.id.clone(),
        kind: record.kind.clone(),
        record_count: record.record_count.count,
        record_source_sha256: record.source_sha256.clone(),
        record_subject_sha256: record.record_count.subject_sha256.clone(),
        restore_target: record.restore_target.clone(),
        conflict_policy: record.conflict_policy.clone(),
        retention_policy_id: record.retention_policy_id.clone(),
        retention_policy_sha256: record.retention_policy_sha256.clone(),
        retention_deadline: record.retention_deadline.clone(),
        forward_mapping_id: record.forward_transform.mapping_id.clone(),
        forward_disposition: record.forward_transform.disposition.clone(),
        forward_evidence_sha256: record.forward_transform.evidence_sha256.clone(),
        rollback_mapping_id: record.rollback_transform.mapping_id.clone(),
        rollback_disposition: record.rollback_transform.disposition.clone(),
        rollback_evidence_sha256: record.rollback_transform.evidence_sha256.clone(),
    };
    Ok(StateTransferDisposition {
        status: "incomplete_state_transfer_unsupported".into(),
        blocking_error: "E_STATE_TRANSFER_EVIDENCE_UNAVAILABLE".into(),
        admitted_state_dependencies: vec![dependency],
        case_specific_rehearsal_receipts: Vec::new(),
        packaged_artifacts: Vec::new(),
        cutover_eligible: false,
        rollback_eligible: false,
    })
}

fn expected_authority() -> Authority {
    Authority {
        source_state: "disabled".into(),
        production_authority: false,
        production_credentials: false,
        production_effects: false,
        scheduler_authority: false,
        trigger_authority: false,
        canary_authority: false,
        cutover_authority: false,
        rollback_authority: false,
        decommission_authority: false,
        credential_material_present: false,
    }
}

fn dispositions_from_index(index: &str) -> Result<Vec<Disposition>, PackageError> {
    if index.contains('\r') {
        return Err(PackageError::new("E_DISPOSITION", "CR is not canonical"));
    }
    let mut lines = index.lines();
    let header = lines
        .next()
        .ok_or_else(|| PackageError::new("E_DISPOSITION", "missing corpus header"))?;
    let columns = header.split('\t').collect::<Vec<_>>();
    if columns.len() != 23
        || columns[0] != "file"
        || columns[2] != "source_sha256"
        || columns[20] != "migration_class"
        || columns[21] != "worker_v1"
        || columns[22] != "certified_equivalence"
    {
        return Err(PackageError::new(
            "E_DISPOSITION",
            "unexpected corpus-index schema",
        ));
    }
    let mut dispositions = Vec::new();
    let mut files = BTreeSet::new();
    for line in lines {
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 23 || !files.insert(fields[0]) {
            return Err(PackageError::new(
                "E_DISPOSITION",
                "malformed or duplicate corpus row",
            ));
        }
        let admitted = fields[2] == ADMITTED_SOURCE_SHA256;
        if admitted {
            if fields[20] != "admitted-compile-only"
                || fields[21] != "compiled-disabled-import"
                || fields[22] != "false"
            {
                return Err(PackageError::new(
                    "E_DISPOSITION",
                    "admitted corpus row mismatch",
                ));
            }
        } else if fields[20] != "unsupported"
            || fields[21] != "E_SOURCE_NOT_ADMITTED"
            || fields[22] != "false"
        {
            return Err(PackageError::new(
                "E_DISPOSITION",
                "non-admitted corpus row mismatch",
            ));
        }
        dispositions.push(Disposition {
            file: fields[0].into(),
            source_sha256: fields[2].into(),
            migration_class: fields[20].into(),
            worker_disposition: fields[21].into(),
            package_status: if admitted {
                "deterministically_rejected_state_transfer_incomplete"
            } else {
                "deterministically_rejected"
            }
            .into(),
            source_certified_equivalence: fields[22] == "true",
            mig006_certified_equivalence: admitted,
        });
    }
    dispositions.sort();
    if dispositions.len() != 228 {
        return Err(PackageError::new(
            "E_DENOMINATOR",
            "corpus disposition denominator is not 228",
        ));
    }
    Ok(dispositions)
}

fn render(package: &MigrationPackage) -> Result<Vec<u8>, PackageError> {
    let mut bytes = serde_json::to_vec_pretty(package)
        .map_err(|error| PackageError::new("E_SCHEMA", error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn read_utf8(root: &Path, relative: &str) -> Result<String, PackageError> {
    let bytes = fs::read(root.join(relative))
        .map_err(|error| PackageError::new("E_IO", format!("{relative}: {error}")))?;
    String::from_utf8(bytes)
        .map_err(|error| PackageError::new("E_IO", format!("{relative}: {error}")))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPOSITORY_ROOT: &str = env!("CARGO_MANIFEST_DIR");

    fn root() -> std::path::PathBuf {
        Path::new(REPOSITORY_ROOT).join("../..")
    }

    fn generated() -> Vec<u8> {
        generate(&root()).unwrap()
    }

    fn mutate(
        mut package: MigrationPackage,
        operation: impl FnOnce(&mut MigrationPackage),
    ) -> Vec<u8> {
        operation(&mut package);
        render(&package).unwrap()
    }

    #[test]
    fn deterministic_package_verifies_all_denominators() {
        let bytes = generated();
        assert_eq!(bytes, generate(&root()).unwrap());
        assert_eq!(
            bytes,
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../migration/migration-package-v1/migration-package.json"
            ))
        );
        let receipt = verify(&bytes, &root()).unwrap();
        assert_eq!(receipt.packaged_cases, 0);
        assert_eq!(receipt.rejected_cases, 228);
        assert_eq!(receipt.admitted_state_dependencies, 1);
        assert!(!receipt.package_complete);
        assert!(!receipt.production_authority);
    }

    #[test]
    fn artifact_substitution_fails_closed() {
        let package: MigrationPackage = serde_json::from_slice(&generated()).unwrap();
        let bytes = mutate(package, |value| value.artifacts.pipeline_yaml.push(' '));
        assert_eq!(
            verify(&bytes, &root()).unwrap_err().code,
            "E_PACKAGE_DIGEST"
        );
    }

    #[test]
    fn authority_promotion_fails_closed() {
        let package: MigrationPackage = serde_json::from_slice(&generated()).unwrap();
        let bytes = mutate(package, |value| value.authority.production_effects = true);
        assert_eq!(
            verify(&bytes, &root()).unwrap_err().code,
            "E_PACKAGE_DIGEST"
        );
    }

    #[test]
    fn disposition_omission_fails_closed() {
        let package: MigrationPackage = serde_json::from_slice(&generated()).unwrap();
        let bytes = mutate(package, |value| {
            value.dispositions.pop();
        });
        assert_eq!(
            verify(&bytes, &root()).unwrap_err().code,
            "E_PACKAGE_DIGEST"
        );
    }

    #[test]
    fn omitted_state_dependency_fails_closed() {
        let package: MigrationPackage = serde_json::from_slice(&generated()).unwrap();
        let bytes = mutate(package, |value| {
            value.state_transfer.admitted_state_dependencies.clear();
        });
        assert_eq!(
            verify(&bytes, &root()).unwrap_err().code,
            "E_PACKAGE_DIGEST"
        );
    }

    #[test]
    fn invented_state_artifact_or_eligibility_fails_closed() {
        let package: MigrationPackage = serde_json::from_slice(&generated()).unwrap();
        let bytes = mutate(package, |value| {
            value
                .state_transfer
                .packaged_artifacts
                .push("digest-only-artifact".into());
            value.state_transfer.cutover_eligible = true;
        });
        assert_eq!(
            verify(&bytes, &root()).unwrap_err().code,
            "E_PACKAGE_DIGEST"
        );
    }

    #[test]
    fn presentation_drift_is_rejected() {
        let mut bytes = generated();
        bytes.push(b'\n');
        assert_eq!(verify(&bytes, &root()).unwrap_err().code, "E_CANONICAL");
    }

    #[test]
    fn oversized_input_is_rejected_before_parsing() {
        let bytes = vec![b' '; MAX_PACKAGE_BYTES + 1];
        assert_eq!(verify(&bytes, &root()).unwrap_err().code, "E_SIZE");
    }
}
