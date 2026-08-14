use std::path::PathBuf;

use serde::Deserialize;
use sha2::{Digest, Sha256};

const EXPECTED_RUNTIME_DEPENDENCIES_SHA256: &str =
    "238ed4cc59ff67bbb1dc40bb1bd3ec28dce914c4dffd701f1a8505d760ba11a4";

#[derive(Deserialize)]
struct Inventory {
    jobs: Vec<Job>,
}

#[derive(Deserialize)]
struct Job {
    job_id: String,
    dependencies: Vec<Dependency>,
}

#[derive(Deserialize)]
struct Dependency {
    credential_reference: Option<String>,
    redaction_reference: Option<String>,
    secret_consumer: Option<serde_json::Value>,
}

#[test]
fn sealed_mario_inventory_has_zero_secret_mapping_or_grant_authority() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "../../migration/mario-jenkins-oracle-228/inventory-20260731T064417Z-r2/runtime-dependencies.yaml",
    );
    let bytes = std::fs::read(path).expect("read sealed runtime inventory");
    assert_eq!(sha256_hex(&bytes), EXPECTED_RUNTIME_DEPENDENCIES_SHA256);
    let inventory: Inventory =
        serde_saphyr::from_slice(&bytes).expect("parse sealed runtime inventory");
    assert_eq!(inventory.jobs.len(), 230);
    for job in inventory.jobs {
        for dependency in job.dependencies {
            assert!(
                dependency.credential_reference.is_none(),
                "job {} unexpectedly grants a credential mapping",
                job.job_id
            );
            assert!(
                dependency.redaction_reference.is_none(),
                "job {}",
                job.job_id
            );
            assert!(dependency.secret_consumer.is_none(), "job {}", job.job_id);
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        use std::fmt::Write as _;
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}
