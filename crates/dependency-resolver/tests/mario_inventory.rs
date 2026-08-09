use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

const EXPECTED_RUNTIME_DEPENDENCIES_SHA256: &str =
    "238ed4cc59ff67bbb1dc40bb1bd3ec28dce914c4dffd701f1a8505d760ba11a4";
const EXPECTED_SOURCE_GENERATION: &str =
    "2e350d0089c94379eb01124929ccc0f931c8e10f93860bef30be9d300572e556";

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
struct RuntimeJob {
    job_id: String,
    dependencies: Vec<Dependency>,
}

#[derive(Deserialize)]
struct Dependency {
    id: String,
    kind: String,
    disposition: String,
    credential_reference: Option<String>,
}

#[test]
fn sealed_mario_inventory_grants_no_workload_dependency_authority() {
    let path = inventory_root().join("runtime-dependencies.yaml");
    let bytes = read_hashed(&path, EXPECTED_RUNTIME_DEPENDENCIES_SHA256);
    let inventory: RuntimeInventory =
        serde_saphyr::from_slice(&bytes).expect("parse runtime dependency inventory");

    assert_eq!(inventory.binding.controller_id, "mario/jenkins-oracle-228");
    assert_eq!(
        inventory.binding.epoch_id,
        "mario-oracle-20260731T064417Z-r2"
    );
    assert_eq!(
        inventory.binding.source_generation,
        EXPECTED_SOURCE_GENERATION
    );
    assert_eq!(inventory.jobs.len(), 230);

    let mut workload_dependencies = 0usize;
    for job in inventory.jobs {
        assert_eq!(job.dependencies.len(), 1, "job {}", job.job_id);
        for dependency in job.dependencies {
            workload_dependencies += usize::from(dependency.kind == "workload-dependency");
            assert_eq!(dependency.id, "opaque-cps-runtime", "job {}", job.job_id);
            assert_eq!(dependency.kind, "controller-global", "job {}", job.job_id);
            assert_eq!(dependency.disposition, "scripted", "job {}", job.job_id);
            assert!(
                dependency.credential_reference.is_none(),
                "job {} must not grant a dependency-repository credential",
                job.job_id
            );
        }
    }
    assert_eq!(workload_dependencies, 0);
}

fn inventory_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../migration/mario-jenkins-oracle-228/inventory-20260731T064417Z-r2")
}

fn read_hashed(path: &Path, expected_sha256: &str) -> Vec<u8> {
    let bytes = std::fs::read(path).expect("read sealed inventory file");
    assert_eq!(sha256_hex(&bytes), expected_sha256, "{}", path.display());
    bytes
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
