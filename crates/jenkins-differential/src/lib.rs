//! Independent, fail-closed verification for the first Jenkins/McLoving
//! native execution differential.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const SCHEMA: &str = "mcloving.jenkins.native-differential/v1";
pub const TRACE_SCHEMA: &str = "mcloving.jenkins.differential-trace/v1";
pub const CASE: &str = "corpus-052-cinqict_jenkinsdev";
pub const SOURCE_SHA256: &str = "666ac2275ea75730e27cf7b565d757691b094c508355adc0199d745278a23100";
pub const PIPELINE_SHA256: &str =
    "551d489ca13bf5d130bdc5c10ce35e5d3d988bdaa1c5488dd9bc79b30674acdc";
pub const JENKINS_IMAGE_SHA256: &str =
    "f4f65e6cd1405cd889b7f5ac33f9d5cdc2a099de6b87fe8a3933b9c5d53d1d02";
pub const JENKINS_PLUGIN_MANIFEST_SHA256: &str =
    "e33fa87646e6e360e7614373cc0057ba2e92ff18b9a9ea9419dea796dcb950b0";
pub const JENKINS_INIT_SHA256: &str =
    "59e1e8ee88116c0645e7e2e4ea5af0184ce85d75b94df39b02c76d66347fdc0a";
const JENKINS_CONTAINER_ID: &str =
    "b64bb5ef3f6ec2e148d61d9593f5d1ab0a407fd632b5f51c36b559e4e85ab9a3";
const JENKINS_CONTAINER_NAME: &str = "mcloving-diff001-jenkins";
const JENKINS_CONTAINER_CREATED: &str = "2026-08-01T12:15:43.236541506Z";
const JENKINS_CONTAINER_STARTED: &str = "2026-08-01T12:15:43.401795528Z";
pub const MCLOVING_RUNNER_IMAGE_SHA256: &str =
    "77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa";
pub const MCLOVING_DATABASE_IMAGE_SHA256: &str =
    "ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94";

const MCLOVING_NETWORK: &str = "mcloving-diff001-net-v16";
const MCLOVING_PIPELINE_DIGEST: &str =
    "2a9b8b7bcd076950c67de874bd1e2b693af511ad55a7de3495d5c0b4210349d3";
const MCLOVING_PIPELINE_DIGEST_BYTES: [u64; 32] = [
    42, 155, 139, 123, 205, 7, 105, 80, 198, 125, 232, 116, 189, 30, 43, 105, 58, 245, 17, 173, 85,
    167, 222, 52, 149, 213, 192, 180, 33, 3, 73, 211,
];
const MCLOVING_BUILD_ID: &str = "37c442ef-f740-4662-9aa9-3577ebcbec8c";
const MCLOVING_NODE_ID: &str = "6ef240c4-dfe2-4532-8166-947de237c467";
const MCLOVING_ATTEMPT_ID: &str = "76b55bd3-7040-40b9-8dcf-243b2b5f6f45";
const MCLOVING_TEST_BINARY_SHA256: &str =
    "e843ecfa3c8acc71cc931634082a7098adf746e893c4493c617b96b5e2ffff1b";
const MCLOVING_CONTROLLER_BINARY_SHA256: &str =
    "c93970047f7f2ce169752448f3c0b96cd0b56038b2c8de4316ff14b8d11f8d0d";
const MCLOVING_RUNNER_ID: &str = "6c58b760d4f6030af9115d37f3d0137cc9ced22bfc9ebfefe3d68c0b91a66614";
const MCLOVING_RUNNER_NAME: &str = "mcloving-diff001-runner-v16";
const MCLOVING_RUNNER_CREATED: &str = "2026-08-01T08:11:05.433588704-05:00";
const MCLOVING_RUNNER_COMMAND: &str = "set -euo pipefail; { id; uname -a; locale; sha256sum 'target/debug/deps/diff_001-3b7075192798a581' target/debug/mcloving-controller; } > /evidence/runtime.txt; exec 'target/debug/deps/diff_001-3b7075192798a581' --nocapture";

const MAX_FILES: usize = 32;
const MAX_FILE_BYTES: u64 = 262_144;
const MAX_BUNDLE_BYTES: u64 = 1_048_576;
const BUNDLE_FILES: [&str; 30] = [
    "README.md",
    "coverage.yaml",
    "pipeline.yaml",
    "jenkins/Jenkinsfile",
    "jenkins/build.json",
    "jenkins/console.txt",
    "jenkins/container-inspect.json",
    "jenkins/controller.log",
    "jenkins/external-network.txt",
    "jenkins/file-sha256.txt",
    "jenkins/image-inspect.json",
    "jenkins/init.groovy",
    "jenkins/PLUGIN_SHA256SUMS",
    "jenkins/plugin-verification.txt",
    "jenkins/queue.json",
    "jenkins/runtime.txt",
    "jenkins/stage-build.json",
    "jenkins/wfapi.json",
    "jenkins/workspace-tmp.tsv",
    "jenkins/workspace.tsv",
    "mcloving/database-integrity.txt",
    "mcloving/mcloving-raw.json",
    "mcloving/mcloving-trace.json",
    "mcloving/network-inspect.json",
    "mcloving/postgres-inspect.json",
    "mcloving/postgres.log",
    "mcloving/runner-inspect-post.json",
    "mcloving/runner-inspect-pre.json",
    "mcloving/runtime.txt",
    "mcloving/test-output.txt",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationReceipt {
    pub schema: &'static str,
    pub case: &'static str,
    pub files: usize,
    pub admitted_cases: u64,
    pub certified_cases: u64,
    pub non_admitted_cases: u64,
    pub trace_sha256: String,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalTrace {
    schema: String,
    case: String,
    source_sha256: String,
    pipeline_sha256: String,
    stage_order: Vec<String>,
    process: CanonicalProcess,
    terminal_outcome: String,
    semantic_stdout_hex: String,
    attempt_ordinals: Vec<u64>,
    workspace_entries: u64,
    artifacts: u64,
    tests: u64,
    approvals: u64,
    credential_grants: u64,
    external_effects: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalProcess {
    program: String,
    args: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Coverage {
    version: u64,
    schema: String,
    corpus_cases: u64,
    admitted_cases: u64,
    certified_cases: u64,
    non_admitted_cases: u64,
    jenkins_executions: u64,
    mcloving_executions: u64,
    admitted_case: CoverageCase,
    non_admitted_families: Vec<String>,
    authority: CoverageAuthority,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CoverageCase {
    id: String,
    source_sha256: String,
    pipeline_sha256: String,
    platform: String,
    trust_pool: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CoverageAuthority {
    jenkins_network: String,
    mcloving_network: String,
    production_effects: bool,
    credentials: bool,
}

pub fn verify_bundle(root: &Path) -> Result<VerificationReceipt, VerificationError> {
    verify_manifest(root)?;
    verify_source_and_pipeline(root)?;
    verify_jenkins_job_definition(root)?;
    verify_jenkins_plugin_profile(root)?;
    let coverage = verify_coverage(root)?;
    let jenkins = derive_jenkins_trace(root)?;
    let mcloving = derive_mcloving_trace(root)?;
    if jenkins != mcloving {
        return Err(VerificationError::new(
            "E_TRACE_MISMATCH",
            format!("Jenkins trace {jenkins:?} differs from McLoving trace {mcloving:?}"),
        ));
    }
    let trace_sha256 = sha256(
        &serde_json::to_vec(&jenkins)
            .map_err(|error| VerificationError::new("E_TRACE", error.to_string()))?,
    );
    Ok(VerificationReceipt {
        schema: SCHEMA,
        case: CASE,
        files: BUNDLE_FILES.len(),
        admitted_cases: coverage.admitted_cases,
        certified_cases: coverage.certified_cases,
        non_admitted_cases: coverage.non_admitted_cases,
        trace_sha256,
    })
}

fn verify_manifest(root: &Path) -> Result<(), VerificationError> {
    verify_exact_tree(root)?;
    let manifest = read(root, "SHA256SUMS")?;
    let text = std::str::from_utf8(&manifest)
        .map_err(|error| VerificationError::new("E_MANIFEST", error.to_string()))?;
    let mut entries = BTreeMap::new();
    for line in text.lines() {
        let (digest, name) = line.split_once("  ").ok_or_else(|| {
            VerificationError::new("E_MANIFEST", format!("invalid manifest line {line:?}"))
        })?;
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(VerificationError::new("E_MANIFEST", "invalid digest"));
        }
        validate_relative_path(name)?;
        if entries.insert(name.to_owned(), digest.to_owned()).is_some() {
            return Err(VerificationError::new("E_MANIFEST", "duplicate path"));
        }
    }
    let expected = BUNDLE_FILES
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<BTreeSet<_>>();
    let actual = entries.keys().cloned().collect::<BTreeSet<_>>();
    if actual != expected || entries.len() > MAX_FILES {
        return Err(VerificationError::new(
            "E_MANIFEST_SET",
            "manifest file set is not exact",
        ));
    }
    let mut total = 0_u64;
    for (name, expected_digest) in entries {
        let bytes = read(root, &name)?;
        total = total.saturating_add(bytes.len() as u64);
        if sha256(&bytes) != expected_digest {
            return Err(VerificationError::new(
                "E_DIGEST",
                format!("digest mismatch for {name}"),
            ));
        }
    }
    if total > MAX_BUNDLE_BYTES {
        return Err(VerificationError::new("E_BOUNDS", "bundle is oversized"));
    }
    Ok(())
}

fn verify_exact_tree(root: &Path) -> Result<(), VerificationError> {
    let root_metadata = fs::symlink_metadata(root)
        .map_err(|error| VerificationError::new("E_TREE", error.to_string()))?;
    if !root_metadata.file_type().is_dir() {
        return Err(VerificationError::new(
            "E_TREE",
            "bundle root is not a real directory",
        ));
    }
    let mut expected_files = BUNDLE_FILES
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<BTreeSet<_>>();
    expected_files.insert("SHA256SUMS".to_owned());
    let expected_directories = ["jenkins".to_owned(), "mcloving".to_owned()]
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut actual_files = BTreeSet::new();
    let mut actual_directories = BTreeSet::new();
    collect_tree(
        root,
        Path::new(""),
        &mut actual_files,
        &mut actual_directories,
    )?;
    if actual_files != expected_files || actual_directories != expected_directories {
        return Err(VerificationError::new(
            "E_TREE",
            "filesystem tree is not exact",
        ));
    }
    Ok(())
}

fn collect_tree(
    root: &Path,
    relative: &Path,
    files: &mut BTreeSet<String>,
    directories: &mut BTreeSet<String>,
) -> Result<(), VerificationError> {
    let directory = root.join(relative);
    for entry in fs::read_dir(&directory)
        .map_err(|error| VerificationError::new("E_TREE", error.to_string()))?
    {
        let entry = entry.map_err(|error| VerificationError::new("E_TREE", error.to_string()))?;
        let child = relative.join(entry.file_name());
        let child_name = child.to_string_lossy().into_owned();
        validate_relative_path(&child_name)?;
        let file_type = entry
            .file_type()
            .map_err(|error| VerificationError::new("E_TREE", error.to_string()))?;
        if file_type.is_file() {
            files.insert(child_name);
        } else if file_type.is_dir() {
            directories.insert(child_name);
            collect_tree(root, &child, files, directories)?;
        } else {
            return Err(VerificationError::new(
                "E_TREE",
                "bundle contains a symlink or special file",
            ));
        }
    }
    Ok(())
}

fn verify_source_and_pipeline(root: &Path) -> Result<(), VerificationError> {
    if sha256(&read(root, "jenkins/Jenkinsfile")?) != SOURCE_SHA256 {
        return Err(VerificationError::new(
            "E_SOURCE",
            "source digest is not the admitted source",
        ));
    }
    if sha256(&read(root, "pipeline.yaml")?) != PIPELINE_SHA256 {
        return Err(VerificationError::new(
            "E_PIPELINE",
            "pipeline digest is not the admitted compilation",
        ));
    }
    Ok(())
}

fn verify_jenkins_job_definition(root: &Path) -> Result<(), VerificationError> {
    let init = read(root, "jenkins/init.groovy")?;
    if sha256(&init) != JENKINS_INIT_SHA256 {
        return Err(VerificationError::new(
            "E_JENKINS_SOURCE",
            "Jenkins initializer does not install the admitted source exactly",
        ));
    }

    let controller_log = text(root, "jenkins/controller.log")?;
    let init_position = controller_log
        .find("Executing /var/jenkins_home/init.groovy.d/99-diff001.groovy")
        .ok_or_else(|| {
            VerificationError::new("E_JENKINS_SOURCE", "initializer execution is absent")
        })?;
    let ready_position = controller_log
        .find("Jenkins is fully up and running")
        .ok_or_else(|| VerificationError::new("E_JENKINS_SOURCE", "ready event is absent"))?;
    let build_position = controller_log
        .find("diff-001-admitted #1")
        .ok_or_else(|| VerificationError::new("E_JENKINS_SOURCE", "build event is absent"))?;
    if !(init_position < ready_position && ready_position < build_position) {
        return Err(VerificationError::new(
            "E_JENKINS_SOURCE",
            "initializer, readiness, and build chronology differs",
        ));
    }
    Ok(())
}

fn verify_coverage(root: &Path) -> Result<Coverage, VerificationError> {
    let bytes = read(root, "coverage.yaml")?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| VerificationError::new("E_COVERAGE", error.to_string()))?;
    let coverage: Coverage = serde_saphyr::from_str(text)
        .map_err(|error| VerificationError::new("E_COVERAGE", error.to_string()))?;
    let expected_families = [
        "parameters",
        "conditions",
        "matrix",
        "timeouts",
        "retries",
        "caught-errors",
        "unstable-results",
        "cancellation",
        "post",
        "parallel",
        "join",
        "fail-fast",
        "multi-build",
        "shared-resources",
        "alternate-agent-selection",
        "approvals",
        "dependencies",
        "caches",
        "artifacts",
        "tests",
        "failure-outcomes",
        "scripted-pipeline",
        "shared-library-runtime",
        "external-effects",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    if coverage.version != 1
        || coverage.schema != SCHEMA
        || coverage.corpus_cases != 228
        || coverage.admitted_cases != 1
        || coverage.certified_cases != 1
        || coverage.non_admitted_cases != 227
        || coverage.jenkins_executions != 1
        || coverage.mcloving_executions != 1
        || coverage.admitted_case.id != CASE
        || coverage.admitted_case.source_sha256 != SOURCE_SHA256
        || coverage.admitted_case.pipeline_sha256 != PIPELINE_SHA256
        || coverage.admitted_case.platform != "linux"
        || coverage.admitted_case.trust_pool != "migration-deny-authority"
        || coverage.non_admitted_families != expected_families
        || coverage.authority.jenkins_network != "none"
        || coverage.authority.mcloving_network != "internal-postgresql-only"
        || coverage.authority.production_effects
        || coverage.authority.credentials
    {
        return Err(VerificationError::new(
            "E_COVERAGE",
            "coverage or authority contract is not exact",
        ));
    }
    Ok(coverage)
}

fn derive_jenkins_trace(root: &Path) -> Result<CanonicalTrace, VerificationError> {
    let build = json(root, "jenkins/build.json")?;
    exact_string(
        &build,
        &["fullDisplayName"],
        "diff-001-admitted #1",
        "E_JENKINS_BUILD",
    )?;
    exact_string(
        &build,
        &["url"],
        "http://127.0.0.1:8080/job/diff-001-admitted/1/",
        "E_JENKINS_BUILD",
    )?;
    exact_string(&build, &["result"], "SUCCESS", "E_JENKINS_BUILD")?;
    exact_u64(&build, &["number"], 1, "E_JENKINS_BUILD")?;
    exact_empty_array(&build, &["artifacts"], "E_JENKINS_BUILD")?;

    let workflow = json(root, "jenkins/wfapi.json")?;
    exact_string(&workflow, &["status"], "SUCCESS", "E_JENKINS_WORKFLOW")?;
    let stages = array(&workflow, &["stages"], "E_JENKINS_WORKFLOW")?;
    if stages.len() != 1 {
        return Err(VerificationError::new(
            "E_JENKINS_WORKFLOW",
            "expected one stage",
        ));
    }
    exact_string(&stages[0], &["name"], "Build", "E_JENKINS_WORKFLOW")?;
    exact_string(&stages[0], &["status"], "SUCCESS", "E_JENKINS_WORKFLOW")?;

    let stage = json(root, "jenkins/stage-build.json")?;
    exact_string(&stage, &["name"], "Build", "E_JENKINS_STAGE")?;
    exact_string(&stage, &["status"], "SUCCESS", "E_JENKINS_STAGE")?;
    let steps = array(&stage, &["stageFlowNodes"], "E_JENKINS_STAGE")?;
    if steps.len() != 1 {
        return Err(VerificationError::new(
            "E_JENKINS_STAGE",
            "expected one step",
        ));
    }
    exact_string(&steps[0], &["name"], "Shell Script", "E_JENKINS_STAGE")?;
    exact_string(&steps[0], &["status"], "SUCCESS", "E_JENKINS_STAGE")?;
    exact_string(
        &steps[0],
        &["parameterDescription"],
        "echo \"Hello World\"",
        "E_JENKINS_STAGE",
    )?;

    const EXPECTED_CONSOLE: &str = "Started by user unknown or anonymous\n\
[Pipeline] Start of Pipeline\n\
[Pipeline] node\n\
Running on Jenkins in /var/jenkins_home/workspace/diff-001-admitted\n\
[Pipeline] {\n\
[Pipeline] stage\n\
[Pipeline] { (Build)\n\
[Pipeline] sh\n\
+ echo Hello World\n\
Hello World\n\
[Pipeline] }\n\
[Pipeline] // stage\n\
[Pipeline] }\n\
[Pipeline] // node\n\
[Pipeline] End of Pipeline\n\
Finished: SUCCESS\n";
    if text(root, "jenkins/console.txt")? != EXPECTED_CONSOLE {
        return Err(VerificationError::new(
            "E_JENKINS_LOG",
            "Jenkins console transcript is not exact",
        ));
    }
    if !read(root, "jenkins/workspace.tsv")?.is_empty()
        || !read(root, "jenkins/workspace-tmp.tsv")?.is_empty()
    {
        return Err(VerificationError::new(
            "E_JENKINS_WORKSPACE",
            "Jenkins workspace is not empty",
        ));
    }
    verify_jenkins_containment(root)?;
    Ok(expected_trace())
}

fn verify_jenkins_containment(root: &Path) -> Result<(), VerificationError> {
    let inspect = json(root, "jenkins/container-inspect.json")?;
    let container = inspect
        .as_array()
        .and_then(|values| values.first())
        .ok_or_else(|| VerificationError::new("E_JENKINS_CONTAINMENT", "missing container"))?;
    exact_string(
        container,
        &["Id"],
        JENKINS_CONTAINER_ID,
        "E_JENKINS_CONTAINMENT",
    )?;
    exact_string(
        container,
        &["Name"],
        JENKINS_CONTAINER_NAME,
        "E_JENKINS_CONTAINMENT",
    )?;
    exact_string(
        container,
        &["Created"],
        JENKINS_CONTAINER_CREATED,
        "E_JENKINS_CONTAINMENT",
    )?;
    exact_string(
        container,
        &["State", "StartedAt"],
        JENKINS_CONTAINER_STARTED,
        "E_JENKINS_CONTAINMENT",
    )?;
    exact_string(
        container,
        &["State", "Status"],
        "running",
        "E_JENKINS_CONTAINMENT",
    )?;
    exact_bool(
        container,
        &["State", "Running"],
        true,
        "E_JENKINS_CONTAINMENT",
    )?;
    exact_bool(
        container,
        &["State", "OOMKilled"],
        false,
        "E_JENKINS_CONTAINMENT",
    )?;
    exact_string(
        container,
        &["Path"],
        "/usr/bin/tini",
        "E_JENKINS_CONTAINMENT",
    )?;
    exact_string_array(
        container,
        &["Args"],
        &["--", "/usr/local/bin/jenkins.sh"],
        "E_JENKINS_CONTAINMENT",
    )?;
    exact_string(
        container,
        &["Config", "Entrypoint"],
        "/usr/bin/tini -- /usr/local/bin/jenkins.sh",
        "E_JENKINS_CONTAINMENT",
    )?;
    exact_null(container, &["Config", "Cmd"], "E_JENKINS_CONTAINMENT")?;
    exact_string(
        container,
        &["Config", "User"],
        "jenkins",
        "E_JENKINS_CONTAINMENT",
    )?;
    exact_string(
        container,
        &["Config", "Image"],
        &format!("docker.io/jenkins/jenkins@sha256:{JENKINS_IMAGE_SHA256}"),
        "E_JENKINS_CONTAINMENT",
    )?;
    exact_string_array(
        container,
        &["Config", "Env"],
        &[
            "container=podman",
            "COPY_REFERENCE_FILE_LOG=/var/jenkins_home/copy_reference_file.log",
            "JAVA_HOME=/opt/java/openjdk",
            "JENKINS_SLAVE_AGENT_PORT=50000",
            "PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "JENKINS_UC=https://updates.jenkins.io",
            "JENKINS_HOME=/var/jenkins_home",
            "JENKINS_UC_EXPERIMENTAL=https://updates.jenkins.io/experimental",
            "JENKINS_VERSION=2.568.1",
            "LANG=C.UTF-8",
            "REF=/usr/share/jenkins/ref",
            "JENKINS_INCREMENTALS_REPO_MIRROR=https://repo.jenkins-ci.org/incrementals",
            "JAVA_OPTS=-Djenkins.install.runSetupWizard=false -Djava.awt.headless=true -Xms512m -Xmx2g",
            "TZ=UTC",
            "HOME=/var/jenkins_home",
            "HOSTNAME=b64bb5ef3f6e",
        ],
        "E_JENKINS_CONTAINMENT",
    )?;
    exact_string(
        container,
        &["ImageDigest"],
        &format!("sha256:{JENKINS_IMAGE_SHA256}"),
        "E_JENKINS_CONTAINMENT",
    )?;
    exact_string(
        container,
        &["HostConfig", "NetworkMode"],
        "none",
        "E_JENKINS_CONTAINMENT",
    )?;
    exact_bool(
        container,
        &["HostConfig", "ReadonlyRootfs"],
        true,
        "E_JENKINS_CONTAINMENT",
    )?;
    exact_bool(
        container,
        &["HostConfig", "Privileged"],
        false,
        "E_JENKINS_CONTAINMENT",
    )?;
    exact_empty_array(
        container,
        &["HostConfig", "CapAdd"],
        "E_JENKINS_CONTAINMENT",
    )?;
    exact_empty_array(
        container,
        &["HostConfig", "GroupAdd"],
        "E_JENKINS_CONTAINMENT",
    )?;
    exact_string_array(
        container,
        &["HostConfig", "SecurityOpt"],
        &["no-new-privileges"],
        "E_JENKINS_CONTAINMENT",
    )?;
    exact_string_array(
        container,
        &["HostConfig", "CapDrop"],
        &[
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_FOWNER",
            "CAP_FSETID",
            "CAP_KILL",
            "CAP_NET_BIND_SERVICE",
            "CAP_SETFCAP",
            "CAP_SETGID",
            "CAP_SETPCAP",
            "CAP_SETUID",
            "CAP_SYS_CHROOT",
        ],
        "E_JENKINS_CONTAINMENT",
    )?;
    exact_string(
        container,
        &["HostConfig", "Tmpfs", "/tmp"],
        "rw,noexec,nosuid,nodev,size=2g,rprivate,tmpcopyup",
        "E_JENKINS_CONTAINMENT",
    )?;
    exact_empty_object(
        container,
        &["HostConfig", "PortBindings"],
        "E_JENKINS_CONTAINMENT",
    )?;
    exact_null(container, &["EffectiveCaps"], "E_JENKINS_CONTAINMENT")?;
    exact_null(container, &["BoundingCaps"], "E_JENKINS_CONTAINMENT")?;
    exact_object_keys(
        container,
        &["NetworkSettings", "Networks"],
        &["none"],
        "E_JENKINS_CONTAINMENT",
    )?;
    exact_u64(
        container,
        &["HostConfig", "Memory"],
        4_294_967_296,
        "E_JENKINS_CONTAINMENT",
    )?;
    exact_u64(
        container,
        &["HostConfig", "MemorySwap"],
        4_294_967_296,
        "E_JENKINS_CONTAINMENT",
    )?;
    exact_u64(
        container,
        &["HostConfig", "NanoCpus"],
        2_000_000_000,
        "E_JENKINS_CONTAINMENT",
    )?;
    exact_u64(
        container,
        &["HostConfig", "PidsLimit"],
        512,
        "E_JENKINS_CONTAINMENT",
    )?;
    let ulimits = array(
        container,
        &["HostConfig", "Ulimits"],
        "E_JENKINS_CONTAINMENT",
    )?;
    if ulimits.len() != 2 {
        return Err(VerificationError::new(
            "E_JENKINS_CONTAINMENT",
            "Jenkins ulimit set is not exact",
        ));
    }
    for (name, bound) in [("RLIMIT_NOFILE", 1_024), ("RLIMIT_NPROC", 127_781)] {
        let limit = ulimits
            .iter()
            .find(|limit| value(limit, &["Name"]) == Some(&Value::String(name.into())))
            .ok_or_else(|| {
                VerificationError::new(
                    "E_JENKINS_CONTAINMENT",
                    format!("missing Jenkins ulimit {name}"),
                )
            })?;
        exact_u64(limit, &["Soft"], bound, "E_JENKINS_CONTAINMENT")?;
        exact_u64(limit, &["Hard"], bound, "E_JENKINS_CONTAINMENT")?;
    }
    let mounts = array(container, &["Mounts"], "E_JENKINS_CONTAINMENT")?;
    if mounts.len() != 4 {
        return Err(VerificationError::new(
            "E_JENKINS_CONTAINMENT",
            "Jenkins mount set is not exact",
        ));
    }
    for (source, destination, writable) in [
        (
            "/home/srikanth/jenkins-oracle-228/plugins",
            "/usr/share/jenkins/ref/plugins",
            false,
        ),
        (
            "/home/srikanth/mcloving-diff001-20260801T121500Z-v2/jenkins/home",
            "/var/jenkins_home",
            true,
        ),
        (
            "/home/srikanth/mcloving-diff001-20260801T121500Z-v2/jenkins/fixture/Jenkinsfile",
            "/fixture/Jenkinsfile",
            false,
        ),
        (
            "/home/srikanth/mcloving-diff001-20260801T121500Z-v2/jenkins/fixture/99-diff001.groovy",
            "/usr/share/jenkins/ref/init.groovy.d/99-diff001.groovy",
            false,
        ),
    ] {
        let mount = mounts
            .iter()
            .find(|mount| {
                value(mount, &["Destination"]) == Some(&Value::String(destination.into()))
            })
            .ok_or_else(|| {
                VerificationError::new(
                    "E_JENKINS_CONTAINMENT",
                    format!("missing Jenkins mount {destination}"),
                )
            })?;
        exact_string(mount, &["Type"], "bind", "E_JENKINS_CONTAINMENT")?;
        exact_bool(mount, &["RW"], writable, "E_JENKINS_CONTAINMENT")?;
        exact_string(mount, &["Source"], source, "E_JENKINS_CONTAINMENT")?;
    }
    let external = text(root, "jenkins/external-network.txt")?;
    const EXPECTED_RUNTIME: &str = "uid=1000(jenkins) gid=1000(jenkins) groups=1000(jenkins)\n\
Linux b64bb5ef3f6e 6.8.0-124-generic #124-Ubuntu SMP PREEMPT_DYNAMIC Tue May 26 13:00:45 UTC 2026 x86_64 GNU/Linux\n\
LANG=C.UTF-8\n\
LANGUAGE=\n\
LC_CTYPE=\"C.UTF-8\"\n\
LC_NUMERIC=\"C.UTF-8\"\n\
LC_TIME=\"C.UTF-8\"\n\
LC_COLLATE=\"C.UTF-8\"\n\
LC_MONETARY=\"C.UTF-8\"\n\
LC_MESSAGES=\"C.UTF-8\"\n\
LC_PAPER=\"C.UTF-8\"\n\
LC_NAME=\"C.UTF-8\"\n\
LC_ADDRESS=\"C.UTF-8\"\n\
LC_TELEPHONE=\"C.UTF-8\"\n\
LC_MEASUREMENT=\"C.UTF-8\"\n\
LC_IDENTIFICATION=\"C.UTF-8\"\n\
LC_ALL=\n\
openjdk version \"21.0.11\" 2026-04-21 LTS\n\
OpenJDK Runtime Environment Temurin-21.0.11+10 (build 21.0.11+10-LTS)\n\
OpenJDK 64-Bit Server VM Temurin-21.0.11+10 (build 21.0.11+10-LTS, mixed mode)\n\
2.568.1\n";
    if !external.ends_with("exit_code=7\n")
        || text(root, "jenkins/runtime.txt")? != EXPECTED_RUNTIME
    {
        return Err(VerificationError::new(
            "E_JENKINS_CONTAINMENT",
            "runtime or negative-network receipt differs",
        ));
    }
    Ok(())
}

fn verify_jenkins_plugin_profile(root: &Path) -> Result<(), VerificationError> {
    let manifest = read(root, "jenkins/PLUGIN_SHA256SUMS")?;
    if sha256(&manifest) != JENKINS_PLUGIN_MANIFEST_SHA256 {
        return Err(VerificationError::new(
            "E_JENKINS_PLUGINS",
            "Jenkins plugin manifest digest differs",
        ));
    }
    let manifest_text = std::str::from_utf8(&manifest)
        .map_err(|error| VerificationError::new("E_JENKINS_PLUGINS", error.to_string()))?;
    let mut plugins = BTreeSet::new();
    for line in manifest_text.lines() {
        let (digest, path) = line.split_once("  ").ok_or_else(|| {
            VerificationError::new("E_JENKINS_PLUGINS", "invalid plugin manifest line")
        })?;
        let valid_digest = digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
        let valid_path = path.strip_prefix("plugins/").is_some_and(|leaf| {
            !leaf.is_empty()
                && leaf.ends_with(".jpi")
                && !leaf.contains('/')
                && !leaf.contains('\\')
                && leaf != ".jpi"
        });
        if !valid_digest || !valid_path || !plugins.insert(path) {
            return Err(VerificationError::new(
                "E_JENKINS_PLUGINS",
                "plugin manifest entry is not canonical and unique",
            ));
        }
    }
    if plugins.len() != 90 {
        return Err(VerificationError::new(
            "E_JENKINS_PLUGINS",
            "Jenkins plugin manifest does not contain exactly 90 plugins",
        ));
    }
    const EXPECTED_RECEIPT: &str = "schema=mcloving.jenkins.plugin-verification/v1\n\
host=mario\n\
plugin_root=/home/srikanth/jenkins-oracle-228/plugins\n\
plugin_manifest_sha256=e33fa87646e6e360e7614373cc0057ba2e92ff18b9a9ea9419dea796dcb950b0\n\
plugin_count=90\n\
latest_plugin_mtime=2026-07-26T05:55:08.950484000Z\n\
jenkins_execution_started_at=2026-08-01T12:15:43.236541506Z\n\
verified_at=2026-08-01T13:28:36Z\n\
verification=sha256sum-strict-all-ok\n";
    if text(root, "jenkins/plugin-verification.txt")? != EXPECTED_RECEIPT {
        return Err(VerificationError::new(
            "E_JENKINS_PLUGINS",
            "Jenkins plugin verification receipt differs",
        ));
    }
    Ok(())
}

fn derive_mcloving_trace(root: &Path) -> Result<CanonicalTrace, VerificationError> {
    verify_mcloving_containment(root)?;
    let raw = json(root, "mcloving/mcloving-raw.json")?;
    for (path, expected) in [
        (
            &["admission", "pipeline_digest"][..],
            MCLOVING_PIPELINE_DIGEST,
        ),
        (&["admission", "build_id"][..], MCLOVING_BUILD_ID),
        (&["admission", "node_id"][..], MCLOVING_NODE_ID),
        (&["admission", "attempt_id"][..], MCLOVING_ATTEMPT_ID),
        (&["status", "build_id"][..], MCLOVING_BUILD_ID),
        (&["status", "node_id"][..], MCLOVING_NODE_ID),
        (&["status", "attempt_id"][..], MCLOVING_ATTEMPT_ID),
        (&["graph", "build", "build_id"][..], MCLOVING_BUILD_ID),
    ] {
        exact_string(&raw, path, expected, "E_MCLOVING")?;
    }
    exact_u64_array(
        &raw,
        &["graph", "build", "pipeline_digest"],
        &MCLOVING_PIPELINE_DIGEST_BYTES,
        "E_MCLOVING",
    )?;
    exact_u64(&raw, &["status", "fence"], 1, "E_MCLOVING")?;
    exact_string(&raw, &["status", "status"], "succeeded", "E_MCLOVING")?;
    exact_string(
        &raw,
        &["status", "attempt_status"],
        "succeeded",
        "E_MCLOVING",
    )?;
    let nodes = array(&raw, &["graph", "nodes"], "E_MCLOVING")?;
    let attempts = array(&raw, &["graph", "attempts"], "E_MCLOVING")?;
    let dependencies = array(&raw, &["graph", "dependencies"], "E_MCLOVING")?;
    if nodes.len() != 1 || attempts.len() != 1 || !dependencies.is_empty() {
        return Err(VerificationError::new("E_MCLOVING", "graph is not exact"));
    }
    exact_string(&nodes[0], &["node_key"], "build", "E_MCLOVING")?;
    exact_string(&nodes[0], &["node_id"], MCLOVING_NODE_ID, "E_MCLOVING")?;
    exact_string(&nodes[0], &["status"], "succeeded", "E_MCLOVING")?;
    exact_string(&nodes[0], &["required_platform"], "linux", "E_MCLOVING")?;
    exact_string(
        &nodes[0],
        &["required_trust_pool"],
        "migration-deny-authority",
        "E_MCLOVING",
    )?;
    exact_u64(&attempts[0], &["ordinal"], 1, "E_MCLOVING")?;
    exact_string(
        &attempts[0],
        &["attempt_id"],
        MCLOVING_ATTEMPT_ID,
        "E_MCLOVING",
    )?;
    exact_string(&attempts[0], &["node_id"], MCLOVING_NODE_ID, "E_MCLOVING")?;
    exact_u64(&attempts[0], &["fence"], 1, "E_MCLOVING")?;
    exact_string(&attempts[0], &["status"], "succeeded", "E_MCLOVING")?;
    exact_u64(
        &attempts[0],
        &["terminal_summary", "exit_code"],
        0,
        "E_MCLOVING",
    )?;
    exact_string(
        &attempts[0],
        &["terminal_summary", "termination"],
        "exited",
        "E_MCLOVING",
    )?;
    let logs = array(&raw, &["logs"], "E_MCLOVING")?;
    if logs.len() != 2 {
        return Err(VerificationError::new("E_MCLOVING", "logs are not exact"));
    }
    let stdout = &logs[0];
    let stderr = &logs[1];
    for (log, sequence, stream) in [(stdout, 0, "stdout"), (stderr, 1, "stderr")] {
        exact_string(log, &["attempt_id"], MCLOVING_ATTEMPT_ID, "E_MCLOVING")?;
        exact_u64(log, &["fence"], 1, "E_MCLOVING")?;
        exact_u64(log, &["sequence"], sequence, "E_MCLOVING")?;
        exact_string(log, &["stream"], stream, "E_MCLOVING")?;
    }
    exact_string(
        stdout,
        &["content_hex"],
        "48656c6c6f20576f726c640a",
        "E_MCLOVING",
    )?;
    exact_string(stdout, &["text"], "Hello World\n", "E_MCLOVING")?;
    exact_string(
        stdout,
        &["sha256"],
        "d2a84f4b8b650937ec8f73cd8be2c74add5a911ba64df27458ed8229da804a26",
        "E_MCLOVING",
    )?;
    exact_string(
        stderr,
        &["content_hex"],
        "2b206563686f2048656c6c6f20576f726c640a",
        "E_MCLOVING",
    )?;
    exact_string(stderr, &["text"], "+ echo Hello World\n", "E_MCLOVING")?;
    exact_string(
        stderr,
        &["sha256"],
        "dd0b88f8948e42d79e88c9fee0a6825c96a07800d0d6cff497d60bf092d4609c",
        "E_MCLOVING",
    )?;
    for field in ["artifacts", "tests", "approvals", "credential_grants"] {
        exact_empty_array(&raw, &[field], "E_MCLOVING")?;
    }
    let checked: CanonicalTrace =
        serde_json::from_slice(&read(root, "mcloving/mcloving-trace.json")?)
            .map_err(|error| VerificationError::new("E_MCLOVING_TRACE", error.to_string()))?;
    let expected = expected_trace();
    if checked != expected {
        return Err(VerificationError::new(
            "E_MCLOVING_TRACE",
            "checked trace does not match independently derived values",
        ));
    }
    Ok(expected)
}

fn verify_mcloving_containment(root: &Path) -> Result<(), VerificationError> {
    let network_inspect = json(root, "mcloving/network-inspect.json")?;
    let network = first_object(&network_inspect, "E_MCLOVING_CONTAINMENT")?;
    exact_string(
        network,
        &["name"],
        MCLOVING_NETWORK,
        "E_MCLOVING_CONTAINMENT",
    )?;
    exact_string(network, &["driver"], "bridge", "E_MCLOVING_CONTAINMENT")?;
    exact_bool(network, &["internal"], true, "E_MCLOVING_CONTAINMENT")?;

    let pre = json(root, "mcloving/runner-inspect-pre.json")?;
    let pre = first_object(&pre, "E_MCLOVING_CONTAINMENT")?;
    verify_runner_contract(pre, false)?;
    exact_string(
        pre,
        &["State", "Status"],
        "created",
        "E_MCLOVING_CONTAINMENT",
    )?;

    let post = json(root, "mcloving/runner-inspect-post.json")?;
    let post = first_object(&post, "E_MCLOVING_CONTAINMENT")?;
    verify_runner_contract(post, true)?;
    exact_string(
        post,
        &["State", "Status"],
        "exited",
        "E_MCLOVING_CONTAINMENT",
    )?;
    exact_u64(post, &["State", "ExitCode"], 0, "E_MCLOVING_CONTAINMENT")?;
    exact_bool(
        post,
        &["State", "OOMKilled"],
        false,
        "E_MCLOVING_CONTAINMENT",
    )?;

    let database = json(root, "mcloving/postgres-inspect.json")?;
    let database = first_object(&database, "E_MCLOVING_CONTAINMENT")?;
    verify_common_container(
        database,
        MCLOVING_DATABASE_IMAGE_SHA256,
        2_147_483_648,
        2_000_000_000,
        256,
    )?;
    exact_string(
        database,
        &["Id"],
        "80e472c559984c0dc1d2bccee1d0d753c7688eca39221ddcf45a0104bdbae57f",
        "E_MCLOVING_CONTAINMENT",
    )?;
    exact_string(
        database,
        &["Name"],
        "mcloving-diff001-db-v16",
        "E_MCLOVING_CONTAINMENT",
    )?;
    exact_string(
        database,
        &["Created"],
        "2026-08-01T08:11:04.203450178-05:00",
        "E_MCLOVING_CONTAINMENT",
    )?;
    exact_string(
        database,
        &["Path"],
        "docker-entrypoint.sh",
        "E_MCLOVING_CONTAINMENT",
    )?;
    exact_string_array(database, &["Args"], &["postgres"], "E_MCLOVING_CONTAINMENT")?;
    exact_string(
        database,
        &["Config", "Image"],
        &format!("docker.io/library/postgres@sha256:{MCLOVING_DATABASE_IMAGE_SHA256}"),
        "E_MCLOVING_CONTAINMENT",
    )?;
    exact_string(database, &["Config", "User"], "", "E_MCLOVING_CONTAINMENT")?;
    exact_string_array(
        database,
        &["Config", "Cmd"],
        &["postgres"],
        "E_MCLOVING_CONTAINMENT",
    )?;
    exact_string(
        database,
        &["Config", "Entrypoint"],
        "docker-entrypoint.sh",
        "E_MCLOVING_CONTAINMENT",
    )?;
    exact_string(
        database,
        &["State", "Status"],
        "running",
        "E_MCLOVING_CONTAINMENT",
    )?;
    exact_bool(
        database,
        &["State", "Running"],
        true,
        "E_MCLOVING_CONTAINMENT",
    )?;
    exact_bool(
        database,
        &["State", "OOMKilled"],
        false,
        "E_MCLOVING_CONTAINMENT",
    )?;
    exact_string_array(
        database,
        &["Config", "Env"],
        &[
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "container=podman",
            "PGDATA=/var/lib/postgresql/data/pgdata",
            "LANG=en_US.utf8",
            "PG_MAJOR=17",
            "PG_VERSION=17.6",
            "POSTGRES_HOST_AUTH_METHOD=trust",
            "GOSU_VERSION=1.19",
            "PG_SHA256=e0630a3600aea27511715563259ec2111cd5f4353a4b040e0be827f94cd7a8b0",
            "DOCKER_PG_LLVM_DEPS=llvm19-dev \t\tclang19",
            "POSTGRES_DB=mcloving",
            "POSTGRES_USER=mcloving",
            "HOME=/root",
            "HOSTNAME=80e472c55998",
        ],
        "E_MCLOVING_CONTAINMENT",
    )?;
    exact_empty_array(
        database,
        &["HostConfig", "CapAdd"],
        "E_MCLOVING_CONTAINMENT",
    )?;
    exact_string_array(
        database,
        &["HostConfig", "CapDrop"],
        &[
            "CAP_FSETID",
            "CAP_KILL",
            "CAP_NET_BIND_SERVICE",
            "CAP_SETFCAP",
            "CAP_SETPCAP",
            "CAP_SYS_CHROOT",
        ],
        "E_MCLOVING_CONTAINMENT",
    )?;
    exact_empty_array(
        database,
        &["HostConfig", "GroupAdd"],
        "E_MCLOVING_CONTAINMENT",
    )?;
    exact_empty_array(database, &["Mounts"], "E_MCLOVING_CONTAINMENT")?;
    exact_string_array(
        database,
        &["EffectiveCaps"],
        &[
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_FOWNER",
            "CAP_SETGID",
            "CAP_SETUID",
        ],
        "E_MCLOVING_CONTAINMENT",
    )?;
    exact_string_array(
        database,
        &["BoundingCaps"],
        &[
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_FOWNER",
            "CAP_SETGID",
            "CAP_SETUID",
        ],
        "E_MCLOVING_CONTAINMENT",
    )?;

    let runtime = text(root, "mcloving/runtime.txt")?;
    let expected_runtime = format!(
        "uid=1000(srikanth) gid=1000(srikanth) groups=1000(srikanth)\n\
Linux 6c58b760d4f6 7.0.0-28-generic #28~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC Wed Jul  1 15:50:57 UTC 2 x86_64 GNU/Linux\n\
LANG=C.UTF-8\n\
LANGUAGE=\n\
LC_CTYPE=\"C.UTF-8\"\n\
LC_NUMERIC=\"C.UTF-8\"\n\
LC_TIME=\"C.UTF-8\"\n\
LC_COLLATE=\"C.UTF-8\"\n\
LC_MONETARY=\"C.UTF-8\"\n\
LC_MESSAGES=\"C.UTF-8\"\n\
LC_PAPER=\"C.UTF-8\"\n\
LC_NAME=\"C.UTF-8\"\n\
LC_ADDRESS=\"C.UTF-8\"\n\
LC_TELEPHONE=\"C.UTF-8\"\n\
LC_MEASUREMENT=\"C.UTF-8\"\n\
LC_IDENTIFICATION=\"C.UTF-8\"\n\
LC_ALL=C.UTF-8\n\
{MCLOVING_TEST_BINARY_SHA256}  target/debug/deps/diff_001-3b7075192798a581\n\
{MCLOVING_CONTROLLER_BINARY_SHA256}  target/debug/mcloving-controller\n"
    );
    if runtime != expected_runtime {
        return Err(VerificationError::new(
            "E_MCLOVING_CONTAINMENT",
            "runner runtime receipt differs",
        ));
    }
    if text(root, "mcloving/database-integrity.txt")? != "mcloving|1\n"
        || !text(root, "mcloving/test-output.txt")?.contains("test result: ok. 1 passed; 0 failed")
    {
        return Err(VerificationError::new(
            "E_MCLOVING_CONTAINMENT",
            "database or test receipt differs",
        ));
    }
    Ok(())
}

fn verify_runner_contract(
    container: &Value,
    started_environment: bool,
) -> Result<(), VerificationError> {
    verify_common_container(
        container,
        MCLOVING_RUNNER_IMAGE_SHA256,
        4_294_967_296,
        4_000_000_000,
        512,
    )?;
    exact_string(
        container,
        &["Config", "User"],
        "1000:1000",
        "E_MCLOVING_CONTAINMENT",
    )?;
    exact_string(
        container,
        &["Id"],
        MCLOVING_RUNNER_ID,
        "E_MCLOVING_CONTAINMENT",
    )?;
    exact_string(
        container,
        &["Name"],
        MCLOVING_RUNNER_NAME,
        "E_MCLOVING_CONTAINMENT",
    )?;
    exact_string(
        container,
        &["Created"],
        MCLOVING_RUNNER_CREATED,
        "E_MCLOVING_CONTAINMENT",
    )?;
    exact_string_array(
        container,
        &["Config", "Cmd"],
        &["bash", "-c", MCLOVING_RUNNER_COMMAND],
        "E_MCLOVING_CONTAINMENT",
    )?;
    let mut environment = vec![
        "LANG=C.UTF-8",
        "PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "CARGO_HOME=/usr/local/cargo",
        "RUST_VERSION=1.97.1",
        "MCLOVING_TEST_DATABASE_URL=postgres://mcloving@mcloving-diff001-db-v16:5432/mcloving",
        "container=podman",
        "RUSTUP_HOME=/usr/local/rustup",
        "MCLOVING_DIFF001_EVIDENCE_DIR=/evidence",
        "LC_ALL=C.UTF-8",
    ];
    if started_environment {
        environment.extend(["HOME=/work", "HOSTNAME=6c58b760d4f6"]);
    }
    exact_string_array(
        container,
        &["Config", "Env"],
        &environment,
        "E_MCLOVING_CONTAINMENT",
    )?;
    exact_string(
        container,
        &["Config", "Entrypoint"],
        "",
        "E_MCLOVING_CONTAINMENT",
    )?;
    exact_empty_array(
        container,
        &["HostConfig", "CapAdd"],
        "E_MCLOVING_CONTAINMENT",
    )?;
    exact_empty_array(
        container,
        &["HostConfig", "GroupAdd"],
        "E_MCLOVING_CONTAINMENT",
    )?;
    exact_string_array(
        container,
        &["HostConfig", "CapDrop"],
        &[
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_FOWNER",
            "CAP_FSETID",
            "CAP_KILL",
            "CAP_NET_BIND_SERVICE",
            "CAP_SETFCAP",
            "CAP_SETGID",
            "CAP_SETPCAP",
            "CAP_SETUID",
            "CAP_SYS_CHROOT",
        ],
        "E_MCLOVING_CONTAINMENT",
    )?;
    exact_null(container, &["EffectiveCaps"], "E_MCLOVING_CONTAINMENT")?;
    exact_null(container, &["BoundingCaps"], "E_MCLOVING_CONTAINMENT")?;
    let mounts = array(container, &["Mounts"], "E_MCLOVING_CONTAINMENT")?;
    if mounts.len() != 2 {
        return Err(VerificationError::new(
            "E_MCLOVING_CONTAINMENT",
            "runner mounts are not exact",
        ));
    }
    for (source, destination, writable) in [
        ("/sn8100/work/forge/McLoving-diff001", "/work", false),
        (
            "/sn8100/runs/mcloving/diff001-native-20260801T131300Z-v16/capture/mcloving",
            "/evidence",
            true,
        ),
    ] {
        let mount = mounts
            .iter()
            .find(|mount| {
                value(mount, &["Destination"]) == Some(&Value::String(destination.into()))
            })
            .ok_or_else(|| {
                VerificationError::new(
                    "E_MCLOVING_CONTAINMENT",
                    format!("missing runner mount {destination}"),
                )
            })?;
        exact_string(mount, &["Type"], "bind", "E_MCLOVING_CONTAINMENT")?;
        exact_string(mount, &["Source"], source, "E_MCLOVING_CONTAINMENT")?;
        exact_bool(mount, &["RW"], writable, "E_MCLOVING_CONTAINMENT")?;
    }
    Ok(())
}

fn verify_common_container(
    container: &Value,
    image_sha256: &str,
    memory: u64,
    nano_cpus: u64,
    pids: u64,
) -> Result<(), VerificationError> {
    exact_string(
        container,
        &["ImageDigest"],
        &format!("sha256:{image_sha256}"),
        "E_MCLOVING_CONTAINMENT",
    )?;
    exact_bool(
        container,
        &["HostConfig", "ReadonlyRootfs"],
        true,
        "E_MCLOVING_CONTAINMENT",
    )?;
    exact_bool(
        container,
        &["HostConfig", "Privileged"],
        false,
        "E_MCLOVING_CONTAINMENT",
    )?;
    exact_string_array(
        container,
        &["HostConfig", "SecurityOpt"],
        &["no-new-privileges"],
        "E_MCLOVING_CONTAINMENT",
    )?;
    exact_empty_object(
        container,
        &["HostConfig", "PortBindings"],
        "E_MCLOVING_CONTAINMENT",
    )?;
    exact_u64(
        container,
        &["HostConfig", "Memory"],
        memory,
        "E_MCLOVING_CONTAINMENT",
    )?;
    exact_u64(
        container,
        &["HostConfig", "MemorySwap"],
        memory,
        "E_MCLOVING_CONTAINMENT",
    )?;
    exact_u64(
        container,
        &["HostConfig", "NanoCpus"],
        nano_cpus,
        "E_MCLOVING_CONTAINMENT",
    )?;
    exact_u64(
        container,
        &["HostConfig", "PidsLimit"],
        pids,
        "E_MCLOVING_CONTAINMENT",
    )?;
    exact_string(
        container,
        &["HostConfig", "NetworkMode"],
        "bridge",
        "E_MCLOVING_CONTAINMENT",
    )?;
    exact_object_keys(
        container,
        &["NetworkSettings", "Networks"],
        &[MCLOVING_NETWORK],
        "E_MCLOVING_CONTAINMENT",
    )?;
    Ok(())
}

fn expected_trace() -> CanonicalTrace {
    CanonicalTrace {
        schema: TRACE_SCHEMA.to_owned(),
        case: CASE.to_owned(),
        source_sha256: SOURCE_SHA256.to_owned(),
        pipeline_sha256: PIPELINE_SHA256.to_owned(),
        stage_order: vec!["Build".to_owned()],
        process: CanonicalProcess {
            program: "/bin/sh".to_owned(),
            args: vec![
                "-xe".to_owned(),
                "-c".to_owned(),
                "echo \"Hello World\"".to_owned(),
            ],
        },
        terminal_outcome: "success".to_owned(),
        semantic_stdout_hex: "48656c6c6f20576f726c640a".to_owned(),
        attempt_ordinals: vec![1],
        workspace_entries: 0,
        artifacts: 0,
        tests: 0,
        approvals: 0,
        credential_grants: 0,
        external_effects: 0,
    }
}

fn read(root: &Path, name: &str) -> Result<Vec<u8>, VerificationError> {
    validate_relative_path(name)?;
    let path = root.join(name);
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| VerificationError::new("E_READ", format!("{name}: {error}")))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_FILE_BYTES {
        return Err(VerificationError::new(
            "E_BOUNDS",
            format!("{name} is not a bounded regular file"),
        ));
    }
    fs::read(&path).map_err(|error| VerificationError::new("E_READ", format!("{name}: {error}")))
}

fn text(root: &Path, name: &str) -> Result<String, VerificationError> {
    String::from_utf8(read(root, name)?)
        .map_err(|error| VerificationError::new("E_TEXT", format!("{name}: {error}")))
}

fn json(root: &Path, name: &str) -> Result<Value, VerificationError> {
    serde_json::from_slice(&read(root, name)?)
        .map_err(|error| VerificationError::new("E_JSON", format!("{name}: {error}")))
}

fn validate_relative_path(name: &str) -> Result<(), VerificationError> {
    let path = Path::new(name);
    if name.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(VerificationError::new(
            "E_PATH",
            format!("unsafe evidence path {name:?}"),
        ));
    }
    Ok(())
}

fn value<'a>(root: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter().try_fold(root, |current, key| current.get(key))
}

fn array<'a>(
    root: &'a Value,
    path: &[&str],
    code: &'static str,
) -> Result<&'a Vec<Value>, VerificationError> {
    value(root, path)
        .and_then(Value::as_array)
        .ok_or_else(|| VerificationError::new(code, format!("missing array {}", path.join("."))))
}

fn first_object<'a>(root: &'a Value, code: &'static str) -> Result<&'a Value, VerificationError> {
    root.as_array()
        .and_then(|values| values.first())
        .ok_or_else(|| VerificationError::new(code, "missing inspect object"))
}

fn exact_string(
    root: &Value,
    path: &[&str],
    expected: &str,
    code: &'static str,
) -> Result<(), VerificationError> {
    if value(root, path).and_then(Value::as_str) != Some(expected) {
        return Err(VerificationError::new(
            code,
            format!("{} is not {expected:?}", path.join(".")),
        ));
    }
    Ok(())
}

fn exact_u64(
    root: &Value,
    path: &[&str],
    expected: u64,
    code: &'static str,
) -> Result<(), VerificationError> {
    if value(root, path).and_then(Value::as_u64) != Some(expected) {
        return Err(VerificationError::new(
            code,
            format!("{} is not {expected}", path.join(".")),
        ));
    }
    Ok(())
}

fn exact_u64_array(
    root: &Value,
    path: &[&str],
    expected: &[u64],
    code: &'static str,
) -> Result<(), VerificationError> {
    let actual = array(root, path, code)?
        .iter()
        .map(Value::as_u64)
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| VerificationError::new(code, "array contains a non-u64"))?;
    if actual != expected {
        return Err(VerificationError::new(
            code,
            format!("{} u64 array differs", path.join(".")),
        ));
    }
    Ok(())
}

fn exact_bool(
    root: &Value,
    path: &[&str],
    expected: bool,
    code: &'static str,
) -> Result<(), VerificationError> {
    if value(root, path).and_then(Value::as_bool) != Some(expected) {
        return Err(VerificationError::new(
            code,
            format!("{} is not {expected}", path.join(".")),
        ));
    }
    Ok(())
}

fn exact_null(root: &Value, path: &[&str], code: &'static str) -> Result<(), VerificationError> {
    if value(root, path) != Some(&Value::Null) {
        return Err(VerificationError::new(
            code,
            format!("{} is not null", path.join(".")),
        ));
    }
    Ok(())
}

fn exact_string_array(
    root: &Value,
    path: &[&str],
    expected: &[&str],
    code: &'static str,
) -> Result<(), VerificationError> {
    let actual = array(root, path, code)?;
    let actual = actual
        .iter()
        .map(Value::as_str)
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| VerificationError::new(code, "array contains a non-string"))?;
    if actual != expected {
        return Err(VerificationError::new(
            code,
            format!("{} string array differs", path.join(".")),
        ));
    }
    Ok(())
}

fn exact_empty_object(
    root: &Value,
    path: &[&str],
    code: &'static str,
) -> Result<(), VerificationError> {
    if !value(root, path)
        .and_then(Value::as_object)
        .is_some_and(serde_json::Map::is_empty)
    {
        return Err(VerificationError::new(
            code,
            format!("{} is not an empty object", path.join(".")),
        ));
    }
    Ok(())
}

fn exact_object_keys(
    root: &Value,
    path: &[&str],
    expected: &[&str],
    code: &'static str,
) -> Result<(), VerificationError> {
    let actual = value(root, path)
        .and_then(Value::as_object)
        .ok_or_else(|| VerificationError::new(code, "missing object"))?
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    if actual != expected {
        return Err(VerificationError::new(
            code,
            format!("{} object keys differ", path.join(".")),
        ));
    }
    Ok(())
}

fn exact_empty_array(
    root: &Value,
    path: &[&str],
    code: &'static str,
) -> Result<(), VerificationError> {
    if !array(root, path, code)?.is_empty() {
        return Err(VerificationError::new(
            code,
            format!("{} is not empty", path.join(".")),
        ));
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
