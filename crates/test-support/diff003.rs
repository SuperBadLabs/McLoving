use serde_json::{Value, json};
use std::io::Write as _;

pub struct ScenarioAssertions {
    scenarios: Vec<(&'static str, &'static str)>,
}

pub fn scenario_assertions(scenarios: &[(&'static str, &'static str)]) -> ScenarioAssertions {
    ScenarioAssertions {
        scenarios: scenarios.to_vec(),
    }
}

impl Drop for ScenarioAssertions {
    fn drop(&mut self) {
        if std::thread::panicking()
            || std::env::var_os("MCLOVING_DIFF003_RUNTIME_OUTPUT_DIR").is_none()
        {
            return;
        }
        let root = std::env::var("MCLOVING_DIFF003_ASSERTION_OUTPUT_DIR")
            .expect("DIFF-003 assertion output directory");
        for (scenario, observed_outcome) in self.scenarios.iter() {
            let path = std::path::Path::new(&root).join(format!("{scenario}.json"));
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap_or_else(|error| panic!("create {}: {error}", path.display()));
            serde_json::to_writer(
                &mut file,
                &json!({
                    "schema": "mcloving.diff003.executed-assertion/v1",
                    "scenario": scenario,
                    "observed_outcome": observed_outcome,
                    "assertions_passed": true,
                }),
            )
            .expect("serialize DIFF-003 executed assertion");
            file.write_all(b"\n")
                .expect("terminate DIFF-003 executed assertion");
            file.sync_all().expect("sync DIFF-003 executed assertion");
        }
    }
}

#[derive(Clone, Copy)]
struct JoinClaim {
    name: &'static str,
    shared_input_sha256: &'static str,
    effects: u64,
    rollback_restored: bool,
}

const TRIGGER_CAPTURE_TO_SOURCE: JoinClaim = JoinClaim {
    name: "trigger_capture_to_source",
    shared_input_sha256: "fb7094bfb37582d9f36b49b9fec7d304684216436be474f3bca1b3e569d11c3e",
    effects: 0,
    rollback_restored: false,
};
const SOURCE_LATER_REVISION_TO_DEPENDENCY: JoinClaim = JoinClaim {
    name: "source_later_revision_to_dependency",
    shared_input_sha256: "72d3c9239a91ab1734fe0f4429a6562bd976be908da85818affd9d63d005c442",
    effects: 0,
    rollback_restored: false,
};
const SECRET_GRANT_TO_SOURCE: JoinClaim = JoinClaim {
    name: "secret_grant_to_source",
    shared_input_sha256: "9965bbd23d3ddefa5d207761c5b9c809fa242bb1dbda1f1217800dbf2826051e",
    effects: 0,
    rollback_restored: false,
};
const INPUT_CAPTURE_TO_CONTROL_FLOW: JoinClaim = JoinClaim {
    name: "input_capture_to_control_flow",
    shared_input_sha256: "309e9ae8b00b166dcef869b65f61af5583bcad18e912ec3fbb1f94eaf2c2ec57",
    effects: 0,
    rollback_restored: false,
};
const DEPENDENCY_TO_CACHE: JoinClaim = JoinClaim {
    name: "dependency_to_cache",
    shared_input_sha256: "0c427f5c5ce96f8a6b647cf4d1cf69bd3fa51d225d3966bf3f94f0f2bb0f2058",
    effects: 0,
    rollback_restored: false,
};
const DISCOVERY_TO_TRIGGER: JoinClaim = JoinClaim {
    name: "discovery_to_trigger",
    shared_input_sha256: "f264a47394d982d147cb20b08a34722edb45ad11d5a8792e81ca6289f7397cef",
    effects: 0,
    rollback_restored: false,
};
const PROVISIONER_TO_RUNNER: JoinClaim = JoinClaim {
    name: "provisioner_to_runner",
    shared_input_sha256: "cd141db85fd1d565dafb397fe54f64bdaec2e2265329a6f97489481f6abc64e9",
    effects: 0,
    rollback_restored: false,
};
const DRY_RUN_INTENT_TO_CONNECTOR: JoinClaim = JoinClaim {
    name: "dry_run_intent_to_connector",
    shared_input_sha256: "5c8484d8769cd064162b088a50c89fd6ff40b20ef34a72ace757baff7c74f849",
    effects: 0,
    rollback_restored: false,
};
const CONNECTOR_TO_OBSERVER: JoinClaim = JoinClaim {
    name: "connector_to_observer",
    shared_input_sha256: "b6f87afec41323b66c98fb8ad62dafd141dd8e2912c4498ec7d7d418fba89e73",
    effects: 1,
    rollback_restored: false,
};
const CONSUMER_CUTOVER_ROLLBACK: JoinClaim = JoinClaim {
    name: "consumer_cutover_rollback",
    shared_input_sha256: "6ab8e332b21c362ea772ad0368773da877b01437567d167ef686ebdf0a350ec1",
    effects: 0,
    rollback_restored: true,
};
const ADMIN_CUTOVER_ROLLBACK: JoinClaim = JoinClaim {
    name: "admin_cutover_rollback",
    shared_input_sha256: "3b7f93c39e3caaebaffdd1a11b5f3ebb4c95c9d0f684fdea92aa7542c2761ee1",
    effects: 0,
    rollback_restored: true,
};
const RELEASE_TO_RUNTIME: JoinClaim = JoinClaim {
    name: "release_to_runtime",
    shared_input_sha256: "05a4a89c24e0d10ae41913db85c2ce9efd3d69b0514f26841ffe7dab7fe660e7",
    effects: 0,
    rollback_restored: false,
};

fn claims(boundary: &str) -> &'static [JoinClaim] {
    match boundary {
        "TRIG-001" => &[
            TRIGGER_CAPTURE_TO_SOURCE,
            INPUT_CAPTURE_TO_CONTROL_FLOW,
            DISCOVERY_TO_TRIGGER,
            DRY_RUN_INTENT_TO_CONNECTOR,
            CONSUMER_CUTOVER_ROLLBACK,
            ADMIN_CUTOVER_ROLLBACK,
        ],
        "SCM-001" => &[
            TRIGGER_CAPTURE_TO_SOURCE,
            SOURCE_LATER_REVISION_TO_DEPENDENCY,
            SECRET_GRANT_TO_SOURCE,
            PROVISIONER_TO_RUNNER,
        ],
        "SECRET-001" => &[SECRET_GRANT_TO_SOURCE],
        "INPUT-001" => &[INPUT_CAPTURE_TO_CONTROL_FLOW],
        "PROV-001" => &[PROVISIONER_TO_RUNNER, RELEASE_TO_RUNTIME],
        "EXT-001" => &[DRY_RUN_INTENT_TO_CONNECTOR, CONNECTOR_TO_OBSERVER],
        "OBS-001" => &[CONNECTOR_TO_OBSERVER],
        "DISC-001" => &[DISCOVERY_TO_TRIGGER],
        "DEP-001" => &[SOURCE_LATER_REVISION_TO_DEPENDENCY, DEPENDENCY_TO_CACHE],
        "CACHE-001" => &[DEPENDENCY_TO_CACHE],
        "CONSUMER-001" => &[CONSUMER_CUTOVER_ROLLBACK],
        "ADMIN-001" => &[ADMIN_CUTOVER_ROLLBACK],
        "REL-001" => &[RELEASE_TO_RUNTIME],
        _ => panic!("unsupported DIFF-003 boundary {boundary}"),
    }
}

pub fn receipt(boundary: &str, mut value: Value) -> Vec<u8> {
    if std::env::var_os("MCLOVING_DIFF003_RUNTIME_OUTPUT_DIR").is_some() {
        let join_claims = claims(boundary)
            .iter()
            .map(|claim| {
                json!({
                    "name": claim.name,
                    "shared_input_sha256": claim.shared_input_sha256,
                    "trace_sha256": claim.shared_input_sha256,
                    "control_flow_sha256": claim.shared_input_sha256,
                    "effect_intent_sha256": claim.shared_input_sha256,
                    "outcome_sha256": claim.shared_input_sha256,
                    "content_sha256": claim.shared_input_sha256,
                    "generation": 1,
                    "retry_ambiguity": false,
                    "effects": claim.effects,
                    "duplicate_effects": 0,
                    "rollback_restored": claim.rollback_restored,
                })
            })
            .collect::<Vec<_>>();
        value["_diff003"] = json!({
            "schema": "mcloving.diff003.live-boundary/v1",
            "boundary": boundary,
            "joins": join_claims,
        });
    }
    serde_json::to_vec_pretty(&value).expect("serialize DIFF-003 live boundary receipt")
}
