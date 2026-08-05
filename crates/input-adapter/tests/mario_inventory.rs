use std::path::PathBuf;

use serde::Deserialize;
use sha2::{Digest, Sha256};

const EXPECTED_RUNTIME_DEPENDENCIES_SHA256: &str =
    "238ed4cc59ff67bbb1dc40bb1bd3ec28dce914c4dffd701f1a8505d760ba11a4";
const EXPECTED_SOURCE_GENERATION: &str =
    "2e350d0089c94379eb01124929ccc0f931c8e10f93860bef30be9d300572e556";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    binding: Binding,
    jobs: Vec<Job>,
}

#[derive(Deserialize)]
struct Binding {
    controller_id: String,
    epoch_id: String,
    source_generation: String,
}

#[derive(Deserialize)]
struct Job {
    job_id: String,
    dependencies: Vec<Dependency>,
}

#[derive(Deserialize)]
struct Dependency {
    id: String,
    kind: String,
    disposition: String,
}

#[test]
fn sealed_mario_inventory_has_zero_admitted_live_external_inputs() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "../../migration/mario-jenkins-oracle-228/inventory-20260731T064417Z-r2/runtime-dependencies.yaml",
    );
    let bytes = std::fs::read(path).expect("read sealed runtime dependency inventory");
    assert_eq!(sha256_hex(&bytes), EXPECTED_RUNTIME_DEPENDENCIES_SHA256);
    let inventory: Inventory =
        serde_saphyr::from_slice(&bytes).expect("parse sealed runtime dependency inventory");
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

    for job in inventory.jobs {
        assert_eq!(job.dependencies.len(), 1, "job {}", job.job_id);
        let dependency = &job.dependencies[0];
        assert_eq!(dependency.id, "opaque-cps-runtime", "job {}", job.job_id);
        assert_eq!(dependency.kind, "controller-global", "job {}", job.job_id);
        assert_eq!(dependency.disposition, "scripted", "job {}", job.job_id);
    }
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
