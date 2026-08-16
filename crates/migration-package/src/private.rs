use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Read as _;
use std::path::{Component, Path};

use mcloving_jenkins_state_transfer::{
    admitted_forward_binding, admitted_reverse_binding, admitted_tree_digest,
    authenticate_forward_bundle, authenticate_reverse_bundle, load_admitted_history_owner_only,
    normalize_single_aborted_workflow, parse_retained_build_record,
};
use mcloving_state_transfer::{BuildResult, Digest, StateBundle, canonical_bytes, transform};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{PACKAGE_ID, PackageError, generate, sha256, verify};

const PRIVATE_SCHEMA: &str = "mcloving.jenkins.migration-package/private-v1";
const MIG005A_REVIEWED_HEAD: &str = "4d4e0027f8b103a39e1ed40d95c1a63385afa3e7";
const MIG005A_PROTECTED_MAIN: &str = "9932cf42d3337f7cfa092c094daf3498e26eface";
const MIG006_PROTECTED_MAIN: &str = "2a8f983838b4bd063bd029b3e164f7ac36c20439";
const MAX_EVIDENCE_FILES: usize = 96;
const MAX_EVIDENCE_FILE_BYTES: usize = 512 * 1024;
const ADMITTED_JENKINS_JOB_CONFIG: &[u8] =
    include_bytes!("../../../migration/state-transfer-v1/fixtures/corpus052-job-config.xml");

pub const MAX_PRIVATE_PACKAGE_BYTES: usize = 2 * 1024 * 1024;

const FORWARD_PATHS: &[&str] = &[
    "evidence/forward-normalization.txt",
    "evidence/postgres-container-inspect.json",
    "evidence/postgres-image-inspect.json",
    "evidence/private-network-inspect.json",
    "evidence/rust-client-container-inspect.json",
    "forward-bundle.json",
    "mcloving/forward-bundle.json",
    "mcloving/mcloving-build-2-log-0.txt",
    "mcloving/mcloving-build-2-log-1.txt",
    "mcloving/mcloving-build-2.log",
    "mcloving/rehearsal-summary.json",
    "mcloving/reverse-bundle.json",
];

const REVERSE_PATHS: &[&str] = &[
    "evidence/PLUGIN_SHA256SUMS",
    "evidence/authenticated-source-build-1.json",
    "evidence/authenticated-source-forward-bundle.json",
    "evidence/authenticated-source.txt",
    "evidence/authenticated-transform-binding.json",
    "evidence/continued-build-3-shell-log.json",
    "evidence/continued-build-3-stage.json",
    "evidence/continued-build-3-workflow.json",
    "evidence/continued-build-3.json",
    "evidence/continued-build-3.log",
    "evidence/imported-build-1.json",
    "evidence/imported-build-1.log",
    "evidence/imported-build-2-shell-log.json",
    "evidence/imported-build-2-shell-log.txt",
    "evidence/imported-build-2-stage.json",
    "evidence/imported-build-2-workflow.json",
    "evidence/imported-build-2.json",
    "evidence/imported-build-2.log",
    "evidence/jenkins-container-inspect.json",
    "evidence/jenkins-image-inspect.json",
    "evidence/jenkins-job-after/builds/1/build.xml",
    "evidence/jenkins-job-after/builds/1/log",
    "evidence/jenkins-job-after/builds/1/log-index",
    "evidence/jenkins-job-after/builds/1/workflow-completed/flowNodeStore.xml",
    "evidence/jenkins-job-after/builds/2/build.xml",
    "evidence/jenkins-job-after/builds/2/log",
    "evidence/jenkins-job-after/builds/2/log-index",
    "evidence/jenkins-job-after/builds/2/mcloving-native-provenance.json",
    "evidence/jenkins-job-after/builds/2/mcloving-state-transfer-build.json",
    "evidence/jenkins-job-after/builds/2/mcloving-state-transfer-receipt.json",
    "evidence/jenkins-job-after/builds/2/workflow-completed/flowNodeStore.xml",
    "evidence/jenkins-job-after/builds/3/build.xml",
    "evidence/jenkins-job-after/builds/3/log",
    "evidence/jenkins-job-after/builds/3/log-index",
    "evidence/jenkins-job-after/builds/3/workflow-completed/flowNodeStore.xml",
    "evidence/jenkins-job-after/builds/permalinks",
    "evidence/jenkins-job-after/config.xml",
    "evidence/jenkins-job-after/nextBuildNumber",
    "evidence/network-negative.txt",
    "evidence/private-network-inspect.json",
    "evidence/restarted-build-1.json",
    "evidence/restarted-build-1.log",
    "evidence/restarted-build-2-shell-log.json",
    "evidence/restarted-build-2-shell-log.txt",
    "evidence/restarted-build-2-stage.json",
    "evidence/restarted-build-2-workflow.json",
    "evidence/restarted-build-2.json",
    "evidence/restarted-build-2.log",
    "evidence/restored-source-forward-bundle.json",
    "evidence/restored-source.txt",
    "evidence/reverse-bundle.sha256",
    "evidence/reverse-source-build-1.json",
    "evidence/reverse-transform-binding.json",
    "evidence/template-boundary.txt",
    "evidence/template-build-2-shell-log.json",
    "evidence/template-build-2-stage.json",
    "evidence/template-build-2-workflow.json",
    "evidence/template-build-2.json",
    "evidence/template-build-2.log",
    "evidence/template-container-inspect.json",
    "evidence/verified-next-build-number.txt",
];

pub struct PrivateGenerationInputs<'a> {
    pub forward_evidence_root: &'a Path,
    pub reverse_evidence_root: &'a Path,
    pub verification: PrivateVerificationInputs<'a>,
}

pub struct PrivateVerificationInputs<'a> {
    pub sealed_history_root: &'a Path,
    pub expected_forward_manifest_sha256: &'a str,
    pub expected_reverse_manifest_sha256: &'a str,
    pub expected_forward_implementation_sha256: &'a str,
    pub expected_reverse_implementation_sha256: &'a str,
    pub expected_package_sha256: Option<&'a str>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateVerificationReceipt {
    pub schema: &'static str,
    pub packaged_cases: usize,
    pub rejected_cases: usize,
    pub admitted_state_dependencies: usize,
    pub package_complete: bool,
    pub shadow_eligible: bool,
    pub production_authority: bool,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PrivateMigrationPackage {
    schema: String,
    package_id: String,
    reviewed_heads: ReviewedHeads,
    public_baseline_json: String,
    state_transfer: PrivateStateTransfer,
    authority: PrivateAuthority,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReviewedHeads {
    mig005a_reviewed_head: String,
    mig005a_protected_main: String,
    mig006_protected_main: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PrivateStateTransfer {
    status: String,
    source_tree_sha256: String,
    forward_evidence: EvidenceArchive,
    reverse_evidence: EvidenceArchive,
    packaged_case: String,
    case_specific_receipts: Vec<String>,
    admitted_state_dependencies: Vec<String>,
    package_complete: bool,
    shadow_eligible: bool,
    canary_eligible: bool,
    cutover_eligible: bool,
    rollback_eligible: bool,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceArchive {
    role: String,
    manifest_sha256: String,
    manifest: String,
    files: Vec<EvidenceFile>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceFile {
    path: String,
    sha256: String,
    contents: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PrivateAuthority {
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

pub fn generate_private(
    repository_root: &Path,
    inputs: &PrivateGenerationInputs<'_>,
) -> Result<Vec<u8>, PackageError> {
    if !cfg!(unix) {
        return Err(PackageError::new(
            "E_PRIVATE_PLATFORM",
            "private package generation requires Unix no-follow input handling",
        ));
    }
    validate_digest(
        inputs.verification.expected_forward_manifest_sha256,
        "forward owner pin",
    )?;
    validate_digest(
        inputs.verification.expected_reverse_manifest_sha256,
        "reverse owner pin",
    )?;
    validate_digest(
        inputs.verification.expected_forward_implementation_sha256,
        "forward implementation owner pin",
    )?;
    validate_digest(
        inputs.verification.expected_reverse_implementation_sha256,
        "reverse implementation owner pin",
    )?;
    if inputs.verification.expected_package_sha256.is_some() {
        return Err(PackageError::new(
            "E_PRIVATE_INPUT",
            "generation must not accept a preselected private package digest",
        ));
    }
    let public_baseline = generate(repository_root)?;
    verify(&public_baseline, repository_root)?;
    let package = PrivateMigrationPackage {
        schema: PRIVATE_SCHEMA.into(),
        package_id: format!("{PACKAGE_ID}-private-state-v1"),
        reviewed_heads: expected_reviewed_heads(),
        public_baseline_json: String::from_utf8(public_baseline)
            .map_err(|error| PackageError::new("E_PRIVATE_BASELINE", error.to_string()))?,
        state_transfer: PrivateStateTransfer {
            status: "complete_private_state_transfer_verified".into(),
            source_tree_sha256: encode_digest(admitted_tree_digest()),
            forward_evidence: load_archive(
                "mig005a-forward",
                inputs.forward_evidence_root,
                inputs.verification.expected_forward_manifest_sha256,
                FORWARD_PATHS,
            )?,
            reverse_evidence: load_archive(
                "mig005a-jenkins-reverse",
                inputs.reverse_evidence_root,
                inputs.verification.expected_reverse_manifest_sha256,
                REVERSE_PATHS,
            )?,
            packaged_case: "corpus-052-cinqict_jenkinsdev".into(),
            case_specific_receipts: vec![
                "forward:mcloving/rehearsal-summary.json".into(),
                "reverse:evidence/imported-build-2-workflow.json".into(),
                "reverse:evidence/restarted-build-2-workflow.json".into(),
                "reverse:evidence/continued-build-3-workflow.json".into(),
            ],
            admitted_state_dependencies: vec!["build-history".into()],
            package_complete: true,
            shadow_eligible: true,
            canary_eligible: false,
            cutover_eligible: false,
            rollback_eligible: false,
        },
        authority: expected_private_authority(),
    };
    let bytes = render_private(&package)?;
    verify_private(&bytes, repository_root, &inputs.verification)?;
    Ok(bytes)
}

pub fn verify_private(
    bytes: &[u8],
    repository_root: &Path,
    inputs: &PrivateVerificationInputs<'_>,
) -> Result<PrivateVerificationReceipt, PackageError> {
    if !cfg!(unix) {
        return Err(PackageError::new(
            "E_PRIVATE_PLATFORM",
            "private package verification requires Unix no-follow input handling",
        ));
    }
    if bytes.len() > MAX_PRIVATE_PACKAGE_BYTES {
        return Err(PackageError::new(
            "E_PRIVATE_SIZE",
            "private package exceeds the two MiB byte limit",
        ));
    }
    validate_digest(inputs.expected_forward_manifest_sha256, "forward owner pin")?;
    validate_digest(inputs.expected_reverse_manifest_sha256, "reverse owner pin")?;
    validate_digest(
        inputs.expected_forward_implementation_sha256,
        "forward implementation owner pin",
    )?;
    validate_digest(
        inputs.expected_reverse_implementation_sha256,
        "reverse implementation owner pin",
    )?;
    if let Some(expected) = inputs.expected_package_sha256 {
        validate_digest(expected, "private package owner pin")?;
        if sha256(bytes) != expected {
            return Err(PackageError::new(
                "E_PRIVATE_PACKAGE_DIGEST",
                "private package digest mismatch",
            ));
        }
    }
    let package: PrivateMigrationPackage = serde_json::from_slice(bytes)
        .map_err(|error| PackageError::new("E_PRIVATE_SCHEMA", error.to_string()))?;
    if render_private(&package)? != bytes {
        return Err(PackageError::new(
            "E_PRIVATE_CANONICAL",
            "private package bytes are not canonical pretty JSON",
        ));
    }
    if package.schema != PRIVATE_SCHEMA
        || package.package_id != format!("{PACKAGE_ID}-private-state-v1")
        || package.reviewed_heads != expected_reviewed_heads()
    {
        return Err(PackageError::new(
            "E_PRIVATE_IDENTITY",
            "private package identity mismatch",
        ));
    }
    verify(package.public_baseline_json.as_bytes(), repository_root)?;
    if package.state_transfer.status != "complete_private_state_transfer_verified"
        || package.state_transfer.source_tree_sha256 != encode_digest(admitted_tree_digest())
        || package.state_transfer.packaged_case != "corpus-052-cinqict_jenkinsdev"
        || package.state_transfer.admitted_state_dependencies != ["build-history"]
        || package.state_transfer.case_specific_receipts
            != [
                "forward:mcloving/rehearsal-summary.json",
                "reverse:evidence/imported-build-2-workflow.json",
                "reverse:evidence/restarted-build-2-workflow.json",
                "reverse:evidence/continued-build-3-workflow.json",
            ]
        || !package.state_transfer.package_complete
        || !package.state_transfer.shadow_eligible
        || package.state_transfer.canary_eligible
        || package.state_transfer.cutover_eligible
        || package.state_transfer.rollback_eligible
    {
        return Err(PackageError::new(
            "E_PRIVATE_STATE_TRANSFER",
            "private state-transfer eligibility mismatch",
        ));
    }
    verify_archive(
        &package.state_transfer.forward_evidence,
        "mig005a-forward",
        inputs.expected_forward_manifest_sha256,
        FORWARD_PATHS,
    )?;
    verify_archive(
        &package.state_transfer.reverse_evidence,
        "mig005a-jenkins-reverse",
        inputs.expected_reverse_manifest_sha256,
        REVERSE_PATHS,
    )?;
    if package.authority != expected_private_authority() {
        return Err(PackageError::new(
            "E_PRIVATE_AUTHORITY",
            "private package authority ledger mismatch",
        ));
    }
    verify_exact_state(&package.state_transfer, inputs)?;
    Ok(PrivateVerificationReceipt {
        schema: PRIVATE_SCHEMA,
        packaged_cases: 1,
        rejected_cases: 227,
        admitted_state_dependencies: 1,
        package_complete: true,
        shadow_eligible: true,
        production_authority: false,
    })
}

fn verify_exact_state(
    state: &PrivateStateTransfer,
    inputs: &PrivateVerificationInputs<'_>,
) -> Result<(), PackageError> {
    let forward_bytes = archive_file(&state.forward_evidence, "mcloving/forward-bundle.json")?;
    let reverse_bytes = archive_file(&state.forward_evidence, "mcloving/reverse-bundle.json")?;
    if archive_file(&state.forward_evidence, "forward-bundle.json")? != forward_bytes {
        return Err(PackageError::new(
            "E_PRIVATE_CONTINUITY",
            "forward bundle copies are divergent",
        ));
    }
    let reverse_digest_receipt = std::str::from_utf8(archive_file(
        &state.reverse_evidence,
        "evidence/reverse-bundle.sha256",
    )?)
    .map_err(|error| PackageError::new("E_PRIVATE_CONTINUITY", error.to_string()))?;
    if reverse_digest_receipt.strip_suffix('\n') != Some(sha256(reverse_bytes).as_str()) {
        return Err(PackageError::new(
            "E_PRIVATE_CONTINUITY",
            "reverse bundle digest receipt is divergent",
        ));
    }
    let forward: StateBundle = serde_json::from_slice(forward_bytes)
        .map_err(|error| PackageError::new("E_PRIVATE_FORWARD", error.to_string()))?;
    let reverse: StateBundle = serde_json::from_slice(reverse_bytes)
        .map_err(|error| PackageError::new("E_PRIVATE_REVERSE", error.to_string()))?;
    require_canonical_bundle(&forward, forward_bytes, "forward")?;
    require_canonical_bundle(&reverse, reverse_bytes, "reverse")?;
    let opaque_evidence_id = forward
        .jobs
        .first()
        .and_then(|job| job.builds.first())
        .and_then(|build| build.logs.first())
        .map(|log| log.retrieval.logical_locator.as_str())
        .and_then(|locator| locator.strip_prefix("held-evidence:"))
        .and_then(|locator| locator.strip_suffix("/builds/1/log"))
        .filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
        .ok_or_else(|| {
            PackageError::new("E_PRIVATE_FORWARD", "opaque evidence locator is divergent")
        })?;
    require_private_parent_custody(inputs.sealed_history_root)?;
    let history =
        load_admitted_history_owner_only(inputs.sealed_history_root, opaque_evidence_id.to_owned())
            .map_err(|error| PackageError::new("E_PRIVATE_FORWARD", error.to_string()))?;
    let forward_implementation = parse_digest(inputs.expected_forward_implementation_sha256)?;
    if forward.binding.transform_implementation_digest != forward_implementation {
        return Err(PackageError::new(
            "E_PRIVATE_FORWARD",
            "forward transform does not match the independent owner pin",
        ));
    }
    let reconstructed = normalize_single_aborted_workflow(
        &history,
        &admitted_forward_binding(forward_implementation),
    )
    .map_err(|error| PackageError::new("E_PRIVATE_FORWARD", error.to_string()))?;
    if reconstructed.bundle() != &forward {
        let boundary = if reconstructed.bundle().binding != forward.binding {
            let expected = &reconstructed.bundle().binding;
            let actual = &forward.binding;
            let mut fields = Vec::new();
            if expected.source != actual.source {
                fields.push("source");
            }
            if expected.destination != actual.destination {
                fields.push("destination");
            }
            if expected.source_export_digest != actual.source_export_digest {
                fields.push("source-export");
            }
            if expected.transform_implementation_digest != actual.transform_implementation_digest {
                fields.push("transform-implementation");
            }
            if expected.transform_configuration_digest != actual.transform_configuration_digest {
                fields.push("transform-configuration");
            }
            if expected.conflict_policy != actual.conflict_policy {
                fields.push("conflict-policy");
            }
            if expected.provenance != actual.provenance {
                fields.push("provenance");
            }
            return Err(PackageError::new(
                "E_PRIVATE_FORWARD",
                format!(
                    "forward candidate differs at binding fields: {}",
                    fields.join(",")
                ),
            ));
        } else if reconstructed.bundle().jobs != forward.jobs {
            "jobs"
        } else {
            "expected-record denominator"
        };
        return Err(PackageError::new(
            "E_PRIVATE_FORWARD",
            format!("forward candidate differs at the {boundary} boundary"),
        ));
    }
    let authenticated_forward =
        authenticate_forward_bundle(&history, &forward, forward_implementation)
            .map_err(|error| PackageError::new("E_PRIVATE_FORWARD", error.to_string()))?;
    let reverse_implementation = parse_digest(inputs.expected_reverse_implementation_sha256)?;
    if reverse.binding.transform_implementation_digest != reverse_implementation {
        return Err(PackageError::new(
            "E_PRIVATE_REVERSE",
            "reverse transform does not match the independent owner pin",
        ));
    }
    let expected_reverse_binding = admitted_reverse_binding(reverse_implementation);
    let mut reverse_binding_fields = Vec::new();
    if reverse.binding.source != expected_reverse_binding.source {
        reverse_binding_fields.push("source");
    }
    if reverse.binding.destination != expected_reverse_binding.destination {
        reverse_binding_fields.push("destination");
    }
    if reverse.binding.transform_implementation_digest
        != expected_reverse_binding.transform_implementation_digest
    {
        reverse_binding_fields.push("transform-implementation");
    }
    if reverse.binding.transform_configuration_digest
        != expected_reverse_binding.transform_configuration_digest
    {
        reverse_binding_fields.push("transform-configuration");
    }
    if reverse.binding.provenance != expected_reverse_binding.provenance {
        reverse_binding_fields.push("provenance");
    }
    if !reverse_binding_fields.is_empty() {
        return Err(PackageError::new(
            "E_PRIVATE_REVERSE",
            format!(
                "reverse candidate differs at binding fields: {}",
                reverse_binding_fields.join(",")
            ),
        ));
    }
    let authenticated_reverse =
        authenticate_reverse_bundle(&authenticated_forward, &reverse, reverse_implementation)
            .map_err(|error| PackageError::new("E_PRIVATE_REVERSE", error.to_string()))?;
    transform(
        authenticated_reverse.bundle(),
        authenticated_reverse.expected(),
        &BTreeMap::new(),
    )
    .map_err(|error| PackageError::new("E_PRIVATE_REVERSE", error.to_string()))?;

    for path in [
        "evidence/authenticated-source-forward-bundle.json",
        "evidence/restored-source-forward-bundle.json",
    ] {
        if archive_file(&state.reverse_evidence, path)? != forward_bytes {
            return Err(PackageError::new(
                "E_PRIVATE_CONTINUITY",
                format!("{path} differs from the authenticated forward bundle"),
            ));
        }
    }
    if archive_file(&state.forward_evidence, "mcloving/mcloving-build-2.log")?
        != b"+ echo Hello World\nHello World\n"
        || archive_file(
            &state.reverse_evidence,
            "evidence/imported-build-2-shell-log.txt",
        )? != b"+ echo Hello World\nHello World\n"
        || archive_file(
            &state.reverse_evidence,
            "evidence/verified-next-build-number.txt",
        )? != b"4\n"
    {
        return Err(PackageError::new(
            "E_PRIVATE_CONTINUITY",
            "ordered logs or next-build continuation are divergent",
        ));
    }
    let summary: Value = serde_json::from_slice(archive_file(
        &state.forward_evidence,
        "mcloving/rehearsal-summary.json",
    )?)
    .map_err(|error| PackageError::new("E_PRIVATE_CONTINUITY", error.to_string()))?;
    if summary.get("production_authority") != Some(&Value::Bool(false))
        || summary.get("external_effects") != Some(&Value::from(0))
        || summary.get("actual_process_execution") != Some(&Value::Bool(true))
        || summary.get("forward_retrieval_verified") != Some(&Value::Bool(true))
        || summary.get("reverse_retrieval_verified") != Some(&Value::Bool(true))
        || summary.get("reverse_replay_verified") != Some(&Value::Bool(true))
        || summary.get("forward_bundle_digest") != Some(&Value::String(sha256(forward_bytes)))
        || summary.get("reverse_bundle_digest") != Some(&Value::String(sha256(reverse_bytes)))
        || summary.get("reverse_transform_implementation_sha256")
            != Some(&Value::String(encode_digest(reverse_implementation)))
        || summary.get("build_count") != Some(&Value::from(2))
        || summary.get("next_build_number") != Some(&Value::from(3))
        || summary.get("previous_result") != Some(&Value::from("succeeded"))
        || summary.get("imported_previous_build_number") != Some(&Value::from(1))
        || summary.get("imported_previous_result") != Some(&Value::from("aborted"))
        || summary.get("log_count") != Some(&Value::from(2))
    {
        return Err(PackageError::new(
            "E_PRIVATE_CONTINUITY",
            "durable rehearsal summary is divergent",
        ));
    }
    let authenticated_binding: Value = serde_json::from_slice(archive_file(
        &state.reverse_evidence,
        "evidence/authenticated-transform-binding.json",
    )?)
    .map_err(|error| PackageError::new("E_PRIVATE_CONTINUITY", error.to_string()))?;
    let reverse_binding: Value = serde_json::from_slice(archive_file(
        &state.reverse_evidence,
        "evidence/reverse-transform-binding.json",
    )?)
    .map_err(|error| PackageError::new("E_PRIVATE_CONTINUITY", error.to_string()))?;
    let expected_authenticated_binding = json!({
        "transform_implementation_digest": forward.binding.transform_implementation_digest,
        "transform_configuration_digest": forward.binding.transform_configuration_digest,
        "conflict_policy": forward.binding.conflict_policy,
    });
    let expected_reverse_binding = json!({
        "transform_implementation_digest": reverse.binding.transform_implementation_digest,
        "transform_configuration_digest": reverse.binding.transform_configuration_digest,
        "conflict_policy": reverse.binding.conflict_policy,
    });
    if authenticated_binding != expected_authenticated_binding
        || reverse_binding != expected_reverse_binding
        || forward.binding.transform_implementation_digest
            == reverse.binding.transform_implementation_digest
    {
        return Err(PackageError::new(
            "E_PRIVATE_CONTINUITY",
            "forward or reverse transform identity receipt is divergent",
        ));
    }
    let imported_attempt = reverse
        .jobs
        .first()
        .and_then(|job| job.builds.get(1))
        .and_then(|build| build.graph_nodes.first())
        .and_then(|node| node.attempts.first())
        .ok_or_else(|| {
            PackageError::new(
                "E_PRIVATE_CONTINUITY",
                "reverse bundle is missing the completed imported attempt",
            )
        })?;
    let imported_started = imported_attempt.started_at_unix_ms.ok_or_else(|| {
        PackageError::new(
            "E_PRIVATE_CONTINUITY",
            "imported attempt is missing its start time",
        )
    })?;
    let expected_log = b"+ echo Hello World\nHello World\n";
    let imported_build = reverse
        .jobs
        .first()
        .and_then(|job| job.builds.get(1))
        .ok_or_else(|| {
            PackageError::new(
                "E_PRIVATE_CONTINUITY",
                "reverse bundle is missing the completed imported build",
            )
        })?;
    validate_completed_build_logs(imported_build, &state.forward_evidence, expected_log)?;
    validate_state_transfer_sidecars(&state.reverse_evidence, reverse_bytes, imported_build)?;
    validate_workflow_receipts(
        &state.reverse_evidence,
        "imported",
        2,
        Some((imported_started, imported_attempt.ended_at_unix_ms)),
        Some(expected_log),
    )?;
    validate_workflow_receipts(
        &state.reverse_evidence,
        "restarted",
        2,
        Some((imported_started, imported_attempt.ended_at_unix_ms)),
        Some(expected_log),
    )?;
    validate_workflow_receipts(
        &state.reverse_evidence,
        "continued",
        3,
        None,
        Some(expected_log),
    )?;
    validate_workflow_receipts(&state.reverse_evidence, "template", 2, None, None)?;
    for (path, number, result) in [
        ("evidence/imported-build-1.json", 1, "ABORTED"),
        ("evidence/restarted-build-1.json", 1, "ABORTED"),
        ("evidence/imported-build-2.json", 2, "SUCCESS"),
        ("evidence/restarted-build-2.json", 2, "SUCCESS"),
        ("evidence/continued-build-3.json", 3, "SUCCESS"),
    ] {
        let value: Value = serde_json::from_slice(archive_file(&state.reverse_evidence, path)?)
            .map_err(|error| PackageError::new("E_PRIVATE_CONTINUITY", error.to_string()))?;
        if value.get("number") != Some(&Value::from(number))
            || value.get("result") != Some(&Value::from(result))
        {
            return Err(PackageError::new(
                "E_PRIVATE_CONTINUITY",
                format!("{path} is divergent"),
            ));
        }
        if number == 2
            && (value.get("queueId") != Some(&Value::from(-1))
                || value
                    .get("actions")
                    .and_then(Value::as_array)
                    .is_none_or(|actions| {
                        actions.iter().any(|action| {
                            matches!(
                                action.get("_class").and_then(Value::as_str),
                                Some("hudson.model.CauseAction")
                                    | Some("jenkins.metrics.impl.TimeInQueueAction")
                            )
                        })
                    }))
        {
            return Err(PackageError::new(
                "E_PRIVATE_CONTINUITY",
                format!("{path} has divergent imported execution provenance"),
            ));
        }
    }
    validate_retained_build_record(
        &state.reverse_evidence,
        "evidence/jenkins-job-after/builds/2/build.xml",
        &[
            "evidence/imported-build-2.json",
            "evidence/restarted-build-2.json",
        ],
        2,
    )?;
    validate_retained_build_record(
        &state.reverse_evidence,
        "evidence/jenkins-job-after/builds/3/build.xml",
        &["evidence/continued-build-3.json"],
        3,
    )?;
    validate_retained_job_configuration(&state.reverse_evidence)?;
    let source_build_1_log = history.files.get("1/log").ok_or_else(|| {
        PackageError::new(
            "E_PRIVATE_CONTINUITY",
            "authenticated source is missing build 1 log",
        )
    })?;
    validate_build_one_logs(&state.reverse_evidence, source_build_1_log)?;
    for path in [
        "evidence/imported-build-2.log",
        "evidence/restarted-build-2.log",
        "evidence/imported-build-2-shell-log.txt",
        "evidence/restarted-build-2-shell-log.txt",
    ] {
        if archive_file(&state.reverse_evidence, path)? != expected_log {
            return Err(PackageError::new(
                "E_PRIVATE_CONTINUITY",
                format!("{path} has divergent process output"),
            ));
        }
    }
    validate_retained_console_log(
        &state.reverse_evidence,
        "evidence/jenkins-job-after/builds/2/log",
        expected_log,
    )?;
    let continued_log = archive_file(&state.reverse_evidence, "evidence/continued-build-3.log")?;
    if !continued_log
        .windows(b"Hello World".len())
        .any(|window| window == b"Hello World")
    {
        return Err(PackageError::new(
            "E_PRIVATE_CONTINUITY",
            "continued build log omits the admitted process output",
        ));
    }
    validate_retained_console_log(
        &state.reverse_evidence,
        "evidence/jenkins-job-after/builds/3/log",
        continued_log,
    )?;
    let template_log = archive_file(&state.reverse_evidence, "evidence/template-build-2.log")?;
    if !template_log
        .windows(b"MIG005A_SERIALIZATION_TEMPLATE_ONLY".len())
        .any(|window| window == b"MIG005A_SERIALIZATION_TEMPLATE_ONLY")
        || template_log
            .windows(b"Hello World".len())
            .any(|window| window == b"Hello World")
        || archive_file(&state.reverse_evidence, "evidence/template-boundary.txt")?
            != b"schema=mcloving.jenkins-serialization-template/v1\ndestination_started=false\nadmitted_workload_process_executed=false\nexternal_effects=0\nproduction_authority=false\n"
    {
        return Err(PackageError::new(
            "E_PRIVATE_CONTINUITY",
            "serialization template execution boundary is divergent",
        ));
    }
    if archive_file(&state.reverse_evidence, "evidence/network-negative.txt")?
        != b"public-network-denied\n"
    {
        return Err(PackageError::new(
            "E_PRIVATE_CONTINUITY",
            "network-denial receipt is divergent",
        ));
    }
    if archive_file(
        &state.reverse_evidence,
        "evidence/jenkins-job-after/nextBuildNumber",
    )? != b"4\n"
    {
        return Err(PackageError::new(
            "E_PRIVATE_CONTINUITY",
            "retained Jenkins next-build cursor is divergent",
        ));
    }
    validate_retained_permalinks(&state.reverse_evidence)?;
    validate_private_network_topology(
        &state.forward_evidence,
        "evidence/private-network-inspect.json",
        &[
            "evidence/postgres-container-inspect.json",
            "evidence/rust-client-container-inspect.json",
        ],
    )?;
    validate_private_network_topology(
        &state.reverse_evidence,
        "evidence/private-network-inspect.json",
        &[
            "evidence/template-container-inspect.json",
            "evidence/jenkins-container-inspect.json",
        ],
    )?;
    Ok(())
}

fn validate_retained_job_configuration(archive: &EvidenceArchive) -> Result<(), PackageError> {
    let path = "evidence/jenkins-job-after/config.xml";
    if archive_file(archive, path)? != ADMITTED_JENKINS_JOB_CONFIG {
        return Err(PackageError::new(
            "E_PRIVATE_JOB_CONFIG",
            "retained Jenkins job configuration is divergent from the reviewed fixture",
        ));
    }
    Ok(())
}

fn validate_build_one_logs(
    archive: &EvidenceArchive,
    authenticated_source_log: &[u8],
) -> Result<(), PackageError> {
    for path in [
        "evidence/imported-build-1.log",
        "evidence/restarted-build-1.log",
        "evidence/jenkins-job-after/builds/1/log",
    ] {
        if archive_file(archive, path)? != authenticated_source_log {
            return Err(PackageError::new(
                "E_PRIVATE_CONTINUITY",
                format!("{path} is divergent from the authenticated source log"),
            ));
        }
    }
    Ok(())
}

fn validate_retained_console_log(
    archive: &EvidenceArchive,
    retained_path: &str,
    verified_capture: &[u8],
) -> Result<(), PackageError> {
    if archive_file(archive, retained_path)? != verified_capture {
        return Err(PackageError::new(
            "E_PRIVATE_CONTINUITY",
            format!("{retained_path} is divergent from its verified console capture"),
        ));
    }
    Ok(())
}

fn validate_retained_build_record(
    archive: &EvidenceArchive,
    retained_path: &str,
    api_paths: &[&str],
    expected_number: u64,
) -> Result<(), PackageError> {
    let retained = parse_retained_build_record(archive_file(archive, retained_path)?)
        .map_err(|error| PackageError::new("E_PRIVATE_RETAINED_BUILD", error.to_string()))?;
    if retained.result != BuildResult::Succeeded {
        return Err(PackageError::new(
            "E_PRIVATE_RETAINED_BUILD",
            format!("{retained_path} has divergent identity or result"),
        ));
    }
    for path in api_paths {
        let api: Value = serde_json::from_slice(archive_file(archive, path)?)
            .map_err(|error| PackageError::new("E_PRIVATE_RETAINED_BUILD", error.to_string()))?;
        if api.get("number") != Some(&Value::from(expected_number))
            || api.get("result") != Some(&Value::from("SUCCESS"))
            || api.get("timestamp") != Some(&Value::from(retained.started_at_unix_ms))
            || api.get("duration") != Some(&Value::from(retained.duration_ms))
        {
            return Err(PackageError::new(
                "E_PRIVATE_RETAINED_BUILD",
                format!("{retained_path} is divergent from {path}"),
            ));
        }
    }
    Ok(())
}

fn validate_completed_build_logs(
    imported_build: &mcloving_state_transfer::BuildState,
    archive: &EvidenceArchive,
    expected_aggregate: &[u8],
) -> Result<(), PackageError> {
    let paths = [
        "mcloving/mcloving-build-2-log-0.txt",
        "mcloving/mcloving-build-2-log-1.txt",
    ];
    if imported_build.logs.len() != paths.len() {
        return Err(PackageError::new(
            "E_PRIVATE_LOG",
            "completed build log denominator is divergent",
        ));
    }
    let mut aggregate = Vec::new();
    for (index, (log, path)) in imported_build.logs.iter().zip(paths).enumerate() {
        let contents = archive_file(archive, path)?;
        let digest = parse_digest(&sha256(contents))?;
        if log.sequence != index as u64
            || log.content_digest != digest
            || log.bytes != contents.len() as u64
            || log.retrieval.content_digest != digest
            || log.retrieval.media_type != "text/plain"
        {
            return Err(PackageError::new(
                "E_PRIVATE_LOG",
                format!("completed build log entry {index} is not bound to its captured chunk"),
            ));
        }
        aggregate.extend_from_slice(contents);
    }
    if aggregate != expected_aggregate {
        return Err(PackageError::new(
            "E_PRIVATE_LOG",
            "captured log chunks do not reconstruct the completed console output",
        ));
    }
    Ok(())
}

fn validate_retained_permalinks(archive: &EvidenceArchive) -> Result<(), PackageError> {
    let text = std::str::from_utf8(archive_file(
        archive,
        "evidence/jenkins-job-after/builds/permalinks",
    )?)
    .map_err(|error| PackageError::new("E_PRIVATE_CONTINUITY", error.to_string()))?;
    let mut actual = BTreeMap::new();
    for line in text.lines() {
        let (name, number) = line.split_once(' ').ok_or_else(|| {
            PackageError::new("E_PRIVATE_CONTINUITY", "retained permalink is malformed")
        })?;
        if name.is_empty()
            || number.parse::<i64>().is_err()
            || actual.insert(name, number).is_some()
        {
            return Err(PackageError::new(
                "E_PRIVATE_CONTINUITY",
                "retained permalink is duplicated or malformed",
            ));
        }
    }
    let expected = BTreeMap::from([
        ("lastCompletedBuild", "3"),
        ("lastStableBuild", "3"),
        ("lastSuccessfulBuild", "3"),
    ]);
    if actual != expected {
        return Err(PackageError::new(
            "E_PRIVATE_CONTINUITY",
            "retained Jenkins permalinks do not match continued build 3",
        ));
    }
    Ok(())
}

fn validate_private_network_topology(
    archive: &EvidenceArchive,
    network_path: &str,
    container_paths: &[&str],
) -> Result<(), PackageError> {
    let network: Value = serde_json::from_slice(archive_file(archive, network_path)?)
        .map_err(|error| PackageError::new("E_PRIVATE_NETWORK", error.to_string()))?;
    let networks = network
        .as_array()
        .filter(|values| values.len() == 1)
        .ok_or_else(|| {
            PackageError::new(
                "E_PRIVATE_NETWORK",
                "private network denominator is divergent",
            )
        })?;
    let network = &networks[0];
    let name = network
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty() && !name.chars().any(char::is_control))
        .ok_or_else(|| PackageError::new("E_PRIVATE_NETWORK", "private network has no identity"))?;
    if network.get("internal") != Some(&Value::Bool(true)) {
        return Err(PackageError::new(
            "E_PRIVATE_NETWORK",
            "captured network is not internal",
        ));
    }
    for path in container_paths {
        let inspect: Value = serde_json::from_slice(archive_file(archive, path)?)
            .map_err(|error| PackageError::new("E_PRIVATE_NETWORK", error.to_string()))?;
        let containers = inspect
            .as_array()
            .filter(|values| values.len() == 1)
            .ok_or_else(|| {
                PackageError::new(
                    "E_PRIVATE_NETWORK",
                    format!("{path} denominator is divergent"),
                )
            })?;
        let container = &containers[0];
        let network_mode = container
            .pointer("/HostConfig/NetworkMode")
            .and_then(Value::as_str);
        let attached = container
            .pointer("/NetworkSettings/Networks")
            .and_then(Value::as_object);
        if network_mode != Some("bridge")
            || attached.is_none_or(|attached| attached.len() != 1 || !attached.contains_key(name))
        {
            return Err(PackageError::new(
                "E_PRIVATE_NETWORK",
                format!("{path} is not exclusively attached to the captured internal network"),
            ));
        }
    }
    Ok(())
}

fn validate_state_transfer_sidecars(
    archive: &EvidenceArchive,
    reverse_bytes: &[u8],
    imported_build: &mcloving_state_transfer::BuildState,
) -> Result<(), PackageError> {
    let expected_build = serde_json::to_value(imported_build)
        .map_err(|error| PackageError::new("E_PRIVATE_SIDECAR", error.to_string()))?;
    let expected_receipt = json!({
        "schema": "mcloving.jenkins-reverse-import/v1",
        "source_build": 2,
        "destination_build": 2,
        "next_build_number": 3,
        "result": "SUCCESS",
        "reverse_bundle_digest": sha256(reverse_bytes),
        "external_effects": 0,
        "production_authority": false,
    });
    let expected_provenance = json!({
        "schema": "mcloving.jenkins-native-provenance/v1",
        "native_queue_id": -1,
        "native_cause_action": "removed-unrepresentable-contained-rehearsal",
        "native_time_in_queue_action": "removed-unrepresentable-contained-rehearsal",
        "source_queue_id": imported_build.source_queue_id,
        "queued_at_unix_ms": imported_build.queued_at_unix_ms,
        "trigger_kind": imported_build.trigger.trigger_kind,
        "trigger_external_id": imported_build.trigger.external_id,
        "trigger_actor_subject": imported_build.trigger.actor_subject,
    });
    for (path, expected) in [
        (
            "evidence/jenkins-job-after/builds/2/mcloving-state-transfer-build.json",
            &expected_build,
        ),
        (
            "evidence/jenkins-job-after/builds/2/mcloving-state-transfer-receipt.json",
            &expected_receipt,
        ),
        (
            "evidence/jenkins-job-after/builds/2/mcloving-native-provenance.json",
            &expected_provenance,
        ),
    ] {
        validate_exact_json_sidecar(archive, path, expected)?;
    }
    Ok(())
}

fn validate_exact_json_sidecar(
    archive: &EvidenceArchive,
    path: &str,
    expected: &Value,
) -> Result<(), PackageError> {
    let actual: Value = serde_json::from_slice(archive_file(archive, path)?)
        .map_err(|error| PackageError::new("E_PRIVATE_SIDECAR", error.to_string()))?;
    if actual != *expected {
        return Err(PackageError::new(
            "E_PRIVATE_SIDECAR",
            format!("{path} is divergent from authenticated reverse state"),
        ));
    }
    Ok(())
}

fn validate_workflow_receipts(
    archive: &EvidenceArchive,
    prefix: &str,
    number: u64,
    expected_shell_times: Option<(i64, i64)>,
    expected_shell_log: Option<&[u8]>,
) -> Result<(), PackageError> {
    let workflow_path = format!("evidence/{prefix}-build-{number}-workflow.json");
    let stage_path = format!("evidence/{prefix}-build-{number}-stage.json");
    let shell_path = format!("evidence/{prefix}-build-{number}-shell-log.json");
    let workflow: Value = serde_json::from_slice(archive_file(archive, &workflow_path)?)
        .map_err(|error| PackageError::new("E_PRIVATE_WORKFLOW", error.to_string()))?;
    let stages = workflow
        .get("stages")
        .and_then(Value::as_array)
        .filter(|stages| stages.len() == 1)
        .ok_or_else(|| {
            PackageError::new(
                "E_PRIVATE_WORKFLOW",
                format!("{workflow_path} has a divergent stage denominator"),
            )
        })?;
    let workflow_stage = &stages[0];
    if workflow.get("status") != Some(&Value::from("SUCCESS"))
        || workflow_stage.get("name") != Some(&Value::from("Build"))
        || workflow_stage.get("status") != Some(&Value::from("SUCCESS"))
    {
        return Err(PackageError::new(
            "E_PRIVATE_WORKFLOW",
            format!("{workflow_path} has a divergent workflow result"),
        ));
    }
    let stage_id = numeric_identifier(workflow_stage.get("id"), &workflow_path)?;

    let stage: Value = serde_json::from_slice(archive_file(archive, &stage_path)?)
        .map_err(|error| PackageError::new("E_PRIVATE_WORKFLOW", error.to_string()))?;
    let receipt_stage_id = numeric_identifier(stage.get("id"), &stage_path)?;
    if stage.get("name") != Some(&Value::from("Build"))
        || stage.get("status") != Some(&Value::from("SUCCESS"))
        || receipt_stage_id != stage_id
    {
        return Err(PackageError::new(
            "E_PRIVATE_WORKFLOW",
            format!("{stage_path} has a divergent Build stage"),
        ));
    }
    let shell_nodes = stage
        .get("stageFlowNodes")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            PackageError::new(
                "E_PRIVATE_WORKFLOW",
                format!("{stage_path} omits stage flow nodes"),
            )
        })?
        .iter()
        .filter(|node| {
            node.get("name") == Some(&Value::from("Shell Script"))
                && node.get("status") == Some(&Value::from("SUCCESS"))
        })
        .collect::<Vec<_>>();
    if shell_nodes.len() != 1 {
        return Err(PackageError::new(
            "E_PRIVATE_WORKFLOW",
            format!("{stage_path} has a divergent successful Shell Script denominator"),
        ));
    }
    let shell_node = shell_nodes[0];
    let shell_id = numeric_identifier(shell_node.get("id"), &stage_path)?;
    if let Some((started, ended)) = expected_shell_times {
        let duration = ended.checked_sub(started).ok_or_else(|| {
            PackageError::new("E_PRIVATE_WORKFLOW", "shell timing is not monotonic")
        })?;
        if shell_node.get("startTimeMillis") != Some(&Value::from(started))
            || shell_node.get("durationMillis") != Some(&Value::from(duration))
        {
            return Err(PackageError::new(
                "E_PRIVATE_WORKFLOW",
                format!("{stage_path} has divergent imported Shell Script timing"),
            ));
        }
    }

    let shell: Value = serde_json::from_slice(archive_file(archive, &shell_path)?)
        .map_err(|error| PackageError::new("E_PRIVATE_WORKFLOW", error.to_string()))?;
    let text = shell
        .get("text")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            PackageError::new(
                "E_PRIVATE_WORKFLOW",
                format!("{shell_path} omits shell text"),
            )
        })?
        .as_bytes();
    if numeric_identifier(shell.get("nodeId"), &shell_path)? != shell_id
        || shell.get("nodeStatus") != Some(&Value::from("SUCCESS"))
        || shell.get("hasMore") != Some(&Value::Bool(false))
        || shell.get("length") != Some(&Value::from(text.len()))
        || expected_shell_log.is_some_and(|expected| text != expected)
    {
        return Err(PackageError::new(
            "E_PRIVATE_WORKFLOW",
            format!("{shell_path} has divergent shell execution truth"),
        ));
    }
    Ok(())
}

fn numeric_identifier(value: Option<&Value>, role: &str) -> Result<String, PackageError> {
    let identifier = match value {
        Some(Value::String(value)) => value.clone(),
        Some(Value::Number(value)) if value.is_u64() => value.to_string(),
        _ => {
            return Err(PackageError::new(
                "E_PRIVATE_WORKFLOW",
                format!("{role} has a nonnumeric workflow identifier"),
            ));
        }
    };
    if identifier.is_empty() || !identifier.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(PackageError::new(
            "E_PRIVATE_WORKFLOW",
            format!("{role} has a noncanonical workflow identifier"),
        ));
    }
    Ok(identifier)
}

fn load_archive(
    role: &str,
    root: &Path,
    expected_manifest_sha256: &str,
    required_paths: &[&str],
) -> Result<EvidenceArchive, PackageError> {
    require_private_parent_custody(root)?;
    require_plain_directory(root)?;
    let manifest_bytes = read_plain_file(&root.join("SHA256SUMS"), MAX_EVIDENCE_FILE_BYTES)?;
    if sha256(&manifest_bytes) != expected_manifest_sha256 {
        return Err(PackageError::new(
            "E_PRIVATE_MANIFEST",
            format!("{role} manifest owner pin mismatch"),
        ));
    }
    let manifest = String::from_utf8(manifest_bytes)
        .map_err(|error| PackageError::new("E_PRIVATE_MANIFEST", error.to_string()))?;
    let entries = parse_manifest(&manifest)?;
    let expected = required_paths
        .iter()
        .map(|path| (*path).to_owned())
        .collect::<BTreeSet<_>>();
    if entries.keys().cloned().collect::<BTreeSet<_>>() != expected {
        return Err(PackageError::new(
            "E_PRIVATE_DENOMINATOR",
            format!("{role} evidence denominator mismatch"),
        ));
    }
    let mut actual = BTreeSet::new();
    collect_regular_files(root, root, &mut actual)?;
    let mut expected_actual = expected;
    expected_actual.insert("SHA256SUMS".to_owned());
    if actual != expected_actual {
        return Err(PackageError::new(
            "E_PRIVATE_DENOMINATOR",
            format!("{role} filesystem denominator mismatch"),
        ));
    }
    let mut total = manifest.len();
    let mut files = Vec::with_capacity(entries.len());
    for (path, expected_digest) in entries {
        let contents = read_plain_file(&root.join(&path), MAX_EVIDENCE_FILE_BYTES)?;
        total = total
            .checked_add(contents.len())
            .ok_or_else(|| PackageError::new("E_PRIVATE_SIZE", "evidence byte count overflow"))?;
        if total > MAX_PRIVATE_PACKAGE_BYTES || sha256(&contents) != expected_digest {
            return Err(PackageError::new(
                "E_PRIVATE_MANIFEST",
                format!("{role} evidence member mismatch"),
            ));
        }
        files.push(EvidenceFile {
            path,
            sha256: expected_digest,
            contents: String::from_utf8(contents)
                .map_err(|error| PackageError::new("E_PRIVATE_UTF8", error.to_string()))?,
        });
    }
    Ok(EvidenceArchive {
        role: role.into(),
        manifest_sha256: expected_manifest_sha256.into(),
        manifest,
        files,
    })
}

fn verify_archive(
    archive: &EvidenceArchive,
    expected_role: &str,
    expected_manifest_sha256: &str,
    required_paths: &[&str],
) -> Result<(), PackageError> {
    if archive.role != expected_role
        || archive.files.len() > MAX_EVIDENCE_FILES
        || archive.manifest_sha256 != expected_manifest_sha256
        || sha256(archive.manifest.as_bytes()) != expected_manifest_sha256
    {
        return Err(PackageError::new(
            "E_PRIVATE_MANIFEST",
            "embedded evidence manifest mismatch",
        ));
    }
    let entries = parse_manifest(&archive.manifest)?;
    let expected = required_paths
        .iter()
        .map(|path| (*path).to_owned())
        .collect::<BTreeSet<_>>();
    if entries.keys().cloned().collect::<BTreeSet<_>>() != expected {
        return Err(PackageError::new(
            "E_PRIVATE_DENOMINATOR",
            "embedded evidence denominator mismatch",
        ));
    }
    let mut seen = BTreeSet::new();
    for file in &archive.files {
        if !seen.insert(file.path.clone())
            || entries.get(&file.path) != Some(&file.sha256)
            || sha256(file.contents.as_bytes()) != file.sha256
        {
            return Err(PackageError::new(
                "E_PRIVATE_MANIFEST",
                "embedded evidence member mismatch",
            ));
        }
    }
    if seen != expected {
        return Err(PackageError::new(
            "E_PRIVATE_DENOMINATOR",
            "embedded evidence member set mismatch",
        ));
    }
    Ok(())
}

fn parse_manifest(manifest: &str) -> Result<BTreeMap<String, String>, PackageError> {
    if manifest.len() > MAX_EVIDENCE_FILE_BYTES || !manifest.ends_with('\n') {
        return Err(PackageError::new(
            "E_PRIVATE_MANIFEST",
            "evidence manifest is unbounded or not newline terminated",
        ));
    }
    let mut entries = BTreeMap::new();
    let mut previous: Option<&str> = None;
    for line in manifest.lines() {
        let (digest, path) = line.split_once("  ").ok_or_else(|| {
            PackageError::new("E_PRIVATE_MANIFEST", "malformed evidence manifest row")
        })?;
        validate_digest(digest, "evidence member")?;
        validate_relative_path(path)?;
        if previous.is_some_and(|value| value >= path)
            || entries.insert(path.to_owned(), digest.to_owned()).is_some()
        {
            return Err(PackageError::new(
                "E_PRIVATE_MANIFEST",
                "evidence manifest paths are not unique and sorted",
            ));
        }
        previous = Some(path);
    }
    if entries.is_empty() || entries.len() > MAX_EVIDENCE_FILES {
        return Err(PackageError::new(
            "E_PRIVATE_MANIFEST",
            "evidence manifest denominator is invalid",
        ));
    }
    Ok(entries)
}

fn collect_regular_files(
    root: &Path,
    directory: &Path,
    files: &mut BTreeSet<String>,
) -> Result<(), PackageError> {
    require_plain_directory(directory)?;
    for entry in fs::read_dir(directory)
        .map_err(|error| PackageError::new("E_PRIVATE_IO", error.to_string()))?
    {
        let entry = entry.map_err(|error| PackageError::new("E_PRIVATE_IO", error.to_string()))?;
        let file_type = entry
            .file_type()
            .map_err(|error| PackageError::new("E_PRIVATE_IO", error.to_string()))?;
        let path = entry.path();
        if file_type.is_symlink() {
            return Err(PackageError::new(
                "E_PRIVATE_FILE_TYPE",
                "private evidence contains a symbolic link",
            ));
        }
        if file_type.is_dir() {
            collect_regular_files(root, &path, files)?;
        } else if file_type.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|error| PackageError::new("E_PRIVATE_PATH", error.to_string()))?;
            let relative = relative
                .to_str()
                .ok_or_else(|| PackageError::new("E_PRIVATE_PATH", "evidence path is not UTF-8"))?;
            validate_relative_path(relative)?;
            if !files.insert(relative.to_owned()) || files.len() > MAX_EVIDENCE_FILES + 1 {
                return Err(PackageError::new(
                    "E_PRIVATE_DENOMINATOR",
                    "private evidence file denominator is invalid",
                ));
            }
        } else {
            return Err(PackageError::new(
                "E_PRIVATE_FILE_TYPE",
                "private evidence contains a non-regular entry",
            ));
        }
    }
    Ok(())
}

fn require_plain_directory(path: &Path) -> Result<(), PackageError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| PackageError::new("E_PRIVATE_IO", error.to_string()))?;
    if !metadata.file_type().is_dir() {
        return Err(PackageError::new(
            "E_PRIVATE_FILE_TYPE",
            "private evidence root is not a plain directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.uid() != nix::unistd::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
            return Err(PackageError::new(
                "E_PRIVATE_MODE",
                "private evidence directory has the wrong owner or grants group/other access",
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn require_private_parent_custody(path: &Path) -> Result<(), PackageError> {
    use std::os::unix::fs::MetadataExt as _;

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| PackageError::new("E_PRIVATE_IO", error.to_string()))?
            .join(path)
    };
    let mut current = absolute.parent();
    let mut immediate = true;
    while let Some(directory) = current {
        let metadata = fs::symlink_metadata(directory)
            .map_err(|error| PackageError::new("E_PRIVATE_IO", error.to_string()))?;
        let trusted_sticky_root = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || (metadata.mode() & 0o022 != 0
                && metadata.uid() != nix::unistd::geteuid().as_raw()
                && !trusted_sticky_root)
            || (immediate
                && (metadata.uid() != nix::unistd::geteuid().as_raw()
                    || metadata.mode() & 0o077 != 0))
        {
            return Err(PackageError::new(
                "E_PRIVATE_CUSTODY",
                "private evidence has a symlinked, writable, or non-owner parent",
            ));
        }
        immediate = false;
        current = directory.parent();
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_private_parent_custody(_path: &Path) -> Result<(), PackageError> {
    Err(PackageError::new(
        "E_PRIVATE_CUSTODY",
        "owner-private ancestor custody requires Unix",
    ))
}

fn read_plain_file(path: &Path, limit: usize) -> Result<Vec<u8>, PackageError> {
    read_regular_file(path, limit, true)
}

fn read_regular_file(
    path: &Path,
    limit: usize,
    require_owner_only: bool,
) -> Result<Vec<u8>, PackageError> {
    #[cfg(not(unix))]
    let _ = require_owner_only;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = options
        .open(path)
        .map_err(|error| PackageError::new("E_PRIVATE_IO", error.to_string()))?;
    let metadata = file
        .metadata()
        .map_err(|error| PackageError::new("E_PRIVATE_IO", error.to_string()))?;
    if !metadata.file_type().is_file() || metadata.len() > limit as u64 {
        return Err(PackageError::new(
            "E_PRIVATE_FILE_TYPE",
            "private input is not a bounded regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.nlink() != 1
            || (require_owner_only
                && (metadata.uid() != nix::unistd::geteuid().as_raw()
                    || metadata.mode() & 0o077 != 0))
        {
            return Err(PackageError::new(
                "E_PRIVATE_MODE",
                "private input has the wrong owner, is linked, or grants group/other access",
            ));
        }
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| PackageError::new("E_PRIVATE_IO", error.to_string()))?;
    if bytes.len() > limit {
        return Err(PackageError::new(
            "E_PRIVATE_SIZE",
            "private input exceeds its byte limit",
        ));
    }
    Ok(bytes)
}

fn parse_digest(value: &str) -> Result<Digest, PackageError> {
    validate_digest(value, "SHA-256")?;
    let mut digest = [0_u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|error| PackageError::new("E_PRIVATE_DIGEST", error.to_string()))?;
    }
    Ok(digest)
}

fn validate_digest(value: &str, role: &str) -> Result<(), PackageError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PackageError::new(
            "E_PRIVATE_DIGEST",
            format!("{role} digest is not canonical lowercase SHA-256"),
        ));
    }
    Ok(())
}

fn validate_relative_path(path: &str) -> Result<(), PackageError> {
    let value = Path::new(path);
    if path.is_empty()
        || path.contains('\\')
        || value.is_absolute()
        || value
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(PackageError::new(
            "E_PRIVATE_PATH",
            "evidence path is not a canonical relative path",
        ));
    }
    Ok(())
}

fn archive_file<'a>(archive: &'a EvidenceArchive, path: &str) -> Result<&'a [u8], PackageError> {
    archive
        .files
        .iter()
        .find(|file| file.path == path)
        .map(|file| file.contents.as_bytes())
        .ok_or_else(|| PackageError::new("E_PRIVATE_DENOMINATOR", "required evidence is absent"))
}

fn require_canonical_bundle(
    bundle: &StateBundle,
    bytes: &[u8],
    role: &str,
) -> Result<(), PackageError> {
    let canonical = canonical_bytes(bundle)
        .map_err(|error| PackageError::new("E_PRIVATE_STATE", error.to_string()))?;
    if canonical != bytes {
        return Err(PackageError::new(
            "E_PRIVATE_STATE",
            format!("{role} state bundle is not canonical"),
        ));
    }
    Ok(())
}

fn expected_reviewed_heads() -> ReviewedHeads {
    ReviewedHeads {
        mig005a_reviewed_head: MIG005A_REVIEWED_HEAD.into(),
        mig005a_protected_main: MIG005A_PROTECTED_MAIN.into(),
        mig006_protected_main: MIG006_PROTECTED_MAIN.into(),
    }
}

fn expected_private_authority() -> PrivateAuthority {
    PrivateAuthority {
        source_state: "disabled_held_evidence".into(),
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

fn render_private(package: &PrivateMigrationPackage) -> Result<Vec<u8>, PackageError> {
    let mut bytes = serde_json::to_vec_pretty(package)
        .map_err(|error| PackageError::new("E_PRIVATE_SCHEMA", error.to_string()))?;
    bytes.push(b'\n');
    if bytes.len() > MAX_PRIVATE_PACKAGE_BYTES {
        return Err(PackageError::new(
            "E_PRIVATE_SIZE",
            "private package exceeds the two MiB byte limit",
        ));
    }
    Ok(bytes)
}

fn encode_digest(digest: Digest) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_archive(files: &[(&str, &str)]) -> EvidenceArchive {
        EvidenceArchive {
            role: "test".into(),
            manifest_sha256: "0".repeat(64),
            manifest: String::new(),
            files: files
                .iter()
                .map(|(path, contents)| EvidenceFile {
                    path: (*path).into(),
                    sha256: sha256(contents.as_bytes()),
                    contents: (*contents).into(),
                })
                .collect(),
        }
    }

    fn workflow_archive(shell_status: &str) -> EvidenceArchive {
        let shell_text = "+ echo Hello World\nHello World\n";
        let files = [
            (
                "evidence/imported-build-2-workflow.json",
                serde_json::json!({
                    "status": "SUCCESS",
                    "stages": [{"id": "10", "name": "Build", "status": "SUCCESS"}]
                })
                .to_string(),
            ),
            (
                "evidence/imported-build-2-stage.json",
                serde_json::json!({
                    "id": "10",
                    "name": "Build",
                    "status": "SUCCESS",
                    "stageFlowNodes": [{
                        "id": "11",
                        "name": "Shell Script",
                        "status": "SUCCESS",
                        "startTimeMillis": 1000,
                        "durationMillis": 250
                    }]
                })
                .to_string(),
            ),
            (
                "evidence/imported-build-2-shell-log.json",
                serde_json::json!({
                    "nodeId": "11",
                    "nodeStatus": shell_status,
                    "hasMore": false,
                    "length": shell_text.len(),
                    "text": shell_text
                })
                .to_string(),
            ),
        ];
        EvidenceArchive {
            role: "test".into(),
            manifest_sha256: "0".repeat(64),
            manifest: String::new(),
            files: files
                .into_iter()
                .map(|(path, contents)| EvidenceFile {
                    path: path.into(),
                    sha256: sha256(contents.as_bytes()),
                    contents,
                })
                .collect(),
        }
    }

    #[test]
    fn manifest_parser_rejects_traversal_duplicates_and_bad_digests() {
        let digest = "0".repeat(64);
        assert!(parse_manifest(&format!("{digest}  ../escape\n")).is_err());
        assert!(parse_manifest(&format!("{digest}  a\n{digest}  a\n")).is_err());
        assert!(parse_manifest("not-a-digest  a\n").is_err());
    }

    #[test]
    fn archive_verifier_rejects_content_substitution() {
        let contents = "receipt\n";
        let digest = sha256(contents.as_bytes());
        let manifest = format!("{digest}  receipt.txt\n");
        let manifest_digest = sha256(manifest.as_bytes());
        let mut archive = EvidenceArchive {
            role: "test".into(),
            manifest_sha256: manifest_digest.clone(),
            manifest,
            files: vec![EvidenceFile {
                path: "receipt.txt".into(),
                sha256: digest,
                contents: contents.into(),
            }],
        };
        verify_archive(&archive, "test", &manifest_digest, &["receipt.txt"]).unwrap();
        archive.files[0].contents.push_str("changed");
        assert!(verify_archive(&archive, "test", &manifest_digest, &["receipt.txt"]).is_err());
    }

    #[test]
    fn workflow_receipts_require_semantic_joins_and_success() {
        let archive = workflow_archive("SUCCESS");
        validate_workflow_receipts(
            &archive,
            "imported",
            2,
            Some((1000, 1250)),
            Some(b"+ echo Hello World\nHello World\n"),
        )
        .unwrap();

        let divergent = workflow_archive("FAILED");
        assert!(
            validate_workflow_receipts(
                &divergent,
                "imported",
                2,
                Some((1000, 1250)),
                Some(b"+ echo Hello World\nHello World\n"),
            )
            .is_err()
        );

        let mut missing_stage_id = workflow_archive("SUCCESS");
        let stage = missing_stage_id
            .files
            .iter_mut()
            .find(|file| file.path.ends_with("-stage.json"))
            .unwrap();
        let mut value: Value = serde_json::from_str(&stage.contents).unwrap();
        value.as_object_mut().unwrap().remove("id");
        stage.contents = value.to_string();
        assert!(
            validate_workflow_receipts(
                &missing_stage_id,
                "imported",
                2,
                Some((1000, 1250)),
                Some(b"+ echo Hello World\nHello World\n"),
            )
            .is_err()
        );
    }

    #[test]
    fn digest_parser_requires_canonical_lowercase_sha256() {
        assert_eq!(parse_digest(&"0".repeat(64)).unwrap(), [0; 32]);
        assert!(parse_digest(&"A".repeat(64)).is_err());
        assert!(parse_digest(&"0".repeat(63)).is_err());
    }

    #[test]
    fn state_transfer_sidecar_rejects_authority_or_identity_drift() {
        let path = "evidence/jenkins-job-after/builds/2/mcloving-state-transfer-receipt.json";
        let expected = json!({
            "schema": "mcloving.jenkins-reverse-import/v1",
            "production_authority": false,
            "reverse_bundle_digest": "0".repeat(64),
        });
        let contents = expected.to_string();
        let archive = EvidenceArchive {
            role: "test".into(),
            manifest_sha256: "0".repeat(64),
            manifest: String::new(),
            files: vec![EvidenceFile {
                path: path.into(),
                sha256: sha256(contents.as_bytes()),
                contents,
            }],
        };
        validate_exact_json_sidecar(&archive, path, &expected).unwrap();

        let mut divergent = expected;
        divergent["production_authority"] = Value::Bool(true);
        assert!(validate_exact_json_sidecar(&archive, path, &divergent).is_err());
    }

    #[test]
    fn retained_job_configuration_is_bound_to_the_reviewed_fixture() {
        let path = "evidence/jenkins-job-after/config.xml";
        let reviewed = std::str::from_utf8(ADMITTED_JENKINS_JOB_CONFIG).unwrap();
        validate_retained_job_configuration(&test_archive(&[(path, reviewed)])).unwrap();

        let divergent = reviewed.replace("<disabled>false</disabled>", "<disabled>true</disabled>");
        assert!(validate_retained_job_configuration(&test_archive(&[(path, &divergent)])).is_err());
    }

    #[test]
    fn every_build_one_log_is_bound_to_the_authenticated_source() {
        let source = "authenticated source log\n";
        let paths = [
            "evidence/imported-build-1.log",
            "evidence/restarted-build-1.log",
            "evidence/jenkins-job-after/builds/1/log",
        ];
        let exact = test_archive(&[(paths[0], source), (paths[1], source), (paths[2], source)]);
        validate_build_one_logs(&exact, source.as_bytes()).unwrap();

        let identically_corrupted_captures = test_archive(&[
            (paths[0], "corrupted\n"),
            (paths[1], "corrupted\n"),
            (paths[2], source),
        ]);
        assert!(
            validate_build_one_logs(&identically_corrupted_captures, source.as_bytes()).is_err()
        );
    }

    #[test]
    fn retained_console_log_is_bound_to_its_verified_capture() {
        let path = "evidence/jenkins-job-after/builds/2/log";
        let archive = test_archive(&[(path, "verified output\n")]);
        validate_retained_console_log(&archive, path, b"verified output\n").unwrap();
        assert!(validate_retained_console_log(&archive, path, b"different output\n").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn sealed_source_requires_owner_only_directories_and_files() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o750)).unwrap();
        let error =
            load_admitted_history_owner_only(root.path(), "opaque-private-id".into()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("wrong owner or grants group/other access")
        );

        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(root.path().join("1")).unwrap();
        fs::create_dir(root.path().join("1/workflow-completed")).unwrap();
        for directory in [
            root.path().join("1"),
            root.path().join("1/workflow-completed"),
        ] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        for relative in [
            "1/build.xml",
            "1/log",
            "1/log-index",
            "1/workflow-completed/flowNodeStore.xml",
            "permalinks",
        ] {
            let path = root.path().join(relative);
            fs::write(&path, b"private").unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        fs::set_permissions(
            root.path().join("1/build.xml"),
            fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        let error =
            load_admitted_history_owner_only(root.path(), "opaque-private-id".into()).unwrap_err();
        assert!(error.to_string().contains("group/other access"));
    }
}
