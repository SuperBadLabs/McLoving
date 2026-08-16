use std::path::PathBuf;

use serde::Deserialize;
use sha2::{Digest as _, Sha256};

const EXPECTED_SCENARIO_CONTRACT_SHA256: &str =
    "e30c1d357bd97620fdb80616a03d049945a2bece6d31d88ae894b5020e3c7801";
const EXPECTED_ELIGIBILITY_SHA256: &str =
    "436c76718f537ce199e4177e4db9998aad4b661176ff25d5daef17e082e4e636";

#[derive(Deserialize)]
struct ScenarioContract {
    claims: ScenarioClaims,
}

#[derive(Deserialize)]
struct ScenarioClaims {
    effect_authority: bool,
    canary_eligible: bool,
}

#[derive(Deserialize)]
struct Eligibility {
    population: Population,
    jobs: Vec<Job>,
}

#[derive(Deserialize)]
struct Population {
    jobs_in_scope: usize,
}

#[derive(Deserialize)]
struct Job {
    disposition: String,
}

#[test]
fn sealed_mario_population_has_no_candidate_for_a_production_canary() {
    let root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../migration/mario-jenkins-oracle-228");
    let scenario_bytes = std::fs::read(root.join("corpus-v1/SCENARIO_CONTRACT.yaml"))
        .expect("read sealed Mario scenario contract");
    assert_eq!(
        sha256_hex(&scenario_bytes),
        EXPECTED_SCENARIO_CONTRACT_SHA256
    );
    let scenarios: ScenarioContract =
        serde_saphyr::from_slice(&scenario_bytes).expect("parse sealed Mario scenario contract");
    assert!(!scenarios.claims.effect_authority);
    assert!(!scenarios.claims.canary_eligible);

    let eligibility_bytes =
        std::fs::read(root.join("inventory-20260731T064417Z-r2/eligibility-ledger.yaml"))
            .expect("read sealed Mario eligibility ledger");
    assert_eq!(sha256_hex(&eligibility_bytes), EXPECTED_ELIGIBILITY_SHA256);
    let eligibility: Eligibility = serde_saphyr::from_slice(&eligibility_bytes)
        .expect("parse sealed Mario eligibility ledger");
    assert_eq!(eligibility.population.jobs_in_scope, 230);
    assert_eq!(eligibility.jobs.len(), 230);
    assert!(
        eligibility
            .jobs
            .iter()
            .all(|job| job.disposition == "unsupported")
    );
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}
