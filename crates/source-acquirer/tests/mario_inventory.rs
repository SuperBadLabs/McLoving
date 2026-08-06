use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

const EXPECTED_JOB_GRAPH_SHA256: &str =
    "76ae2e85d7d8a5a1410826b7b4556a36407bba726ac2baf6efe67062888b99ab";
const EXPECTED_RUNTIME_DEPENDENCIES_SHA256: &str =
    "238ed4cc59ff67bbb1dc40bb1bd3ec28dce914c4dffd701f1a8505d760ba11a4";
const EXPECTED_SOURCE_PROVENANCE_SHA256: &str =
    "43a1beac3acce97b7479f9b006a42d14208f9e5fd9ab7af9dcbd4c7061fcbc90";
const EXPECTED_SOURCE_GENERATION: &str =
    "2e350d0089c94379eb01124929ccc0f931c8e10f93860bef30be9d300572e556";

#[derive(Deserialize)]
struct JobGraph {
    binding: Binding,
    jobs: Vec<Job>,
}

#[derive(Deserialize)]
struct RuntimeInventory {
    binding: Binding,
    jobs: Vec<RuntimeJob>,
}

#[derive(Deserialize)]
struct Binding {
    controller_id: String,
    epoch_id: String,
    source_generation: String,
}

#[derive(Deserialize)]
struct Job {
    id: String,
    canonical_source: String,
    definition_kind: String,
}

#[derive(Deserialize)]
struct RuntimeJob {
    job_id: String,
    dependencies: Vec<Dependency>,
}

#[derive(Deserialize)]
struct Dependency {
    id: String,
    kind: String,
    credential_reference: Option<String>,
}

#[test]
fn sealed_mario_inventory_grants_no_live_scm_or_credential_authority() {
    let inventory = inventory_root();
    let job_graph_bytes = read_hashed(&inventory.join("job-graph.yaml"), EXPECTED_JOB_GRAPH_SHA256);
    let runtime_bytes = read_hashed(
        &inventory.join("runtime-dependencies.yaml"),
        EXPECTED_RUNTIME_DEPENDENCIES_SHA256,
    );
    let graph: JobGraph = serde_saphyr::from_slice(&job_graph_bytes).expect("parse job graph");
    let runtime: RuntimeInventory =
        serde_saphyr::from_slice(&runtime_bytes).expect("parse runtime inventory");

    assert_binding(&graph.binding);
    assert_binding(&runtime.binding);
    assert_eq!(graph.jobs.len(), 230);
    assert_eq!(runtime.jobs.len(), 230);

    for job in graph.jobs {
        assert_eq!(
            job.definition_kind, "org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition",
            "job {} must remain a frozen inline definition",
            job.id
        );
        assert!(
            job.canonical_source.starts_with(&format!(
                "jenkins://mario/jenkins-oracle-228/job/{}/inline/",
                job.id
            )),
            "job {} must not acquire live SCM authority",
            job.id
        );
    }

    for job in runtime.jobs {
        assert_eq!(job.dependencies.len(), 1, "job {}", job.job_id);
        let dependency = &job.dependencies[0];
        assert_eq!(dependency.id, "opaque-cps-runtime", "job {}", job.job_id);
        assert_eq!(dependency.kind, "controller-global", "job {}", job.job_id);
        assert!(
            dependency.credential_reference.is_none(),
            "job {} must not grant an SCM credential",
            job.job_id
        );
    }
}

#[test]
fn historical_corpus_provenance_remains_a_separate_non_authoritative_denominator() {
    let path = corpus_root().join("source-provenance.tsv");
    let bytes = read_hashed(&path, EXPECTED_SOURCE_PROVENANCE_SHA256);
    let text = std::str::from_utf8(&bytes).expect("source provenance is UTF-8");
    let mut lines = text.lines();
    let header = lines.next().expect("source provenance header");
    let columns: Vec<_> = header.split('\t').collect();
    let repo = column(&columns, "repo");
    let commit = column(&columns, "commit_sha1");
    let status = column(&columns, "provenance_status");
    let rows: Vec<Vec<&str>> = lines.map(|line| line.split('\t').collect()).collect();

    assert_eq!(rows.len(), 228);
    for row in rows {
        assert_eq!(row.len(), columns.len());
        assert!(!row[repo].is_empty());
        assert_eq!(row[commit].len(), 40);
        assert!(row[commit].bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(row[status], "exact-commit");
    }
}

fn inventory_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../migration/mario-jenkins-oracle-228/inventory-20260731T064417Z-r2")
}

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../migration/mario-jenkins-oracle-228/corpus-v1")
}

fn assert_binding(binding: &Binding) {
    assert_eq!(binding.controller_id, "mario/jenkins-oracle-228");
    assert_eq!(binding.epoch_id, "mario-oracle-20260731T064417Z-r2");
    assert_eq!(binding.source_generation, EXPECTED_SOURCE_GENERATION);
}

fn read_hashed(path: &Path, expected_sha256: &str) -> Vec<u8> {
    let bytes = std::fs::read(path).expect("read sealed inventory file");
    assert_eq!(sha256_hex(&bytes), expected_sha256, "{}", path.display());
    bytes
}

fn column(columns: &[&str], name: &str) -> usize {
    columns
        .iter()
        .position(|column| *column == name)
        .unwrap_or_else(|| panic!("missing {name} column"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}
