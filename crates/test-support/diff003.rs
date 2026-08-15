use serde_json::{Value, json};
use std::io::Write as _;

pub fn record_assertion(
    scenario: &'static str,
    observed_outcome: &'static str,
    observation: Value,
    assertion_passed: bool,
) {
    assert!(
        assertion_passed,
        "DIFF-003 scenario-specific assertion failed: {scenario}"
    );
    if std::env::var_os("MCLOVING_DIFF003_RUNTIME_OUTPUT_DIR").is_none() {
        return;
    }
    assert!(
        observation
            .as_object()
            .is_some_and(|value| !value.is_empty()),
        "DIFF-003 scenario observation must be a nonempty object"
    );
    let root = std::env::var("MCLOVING_DIFF003_ASSERTION_OUTPUT_DIR")
        .expect("DIFF-003 assertion output directory");
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
            "observation": observation,
            "assertions_passed": assertion_passed,
        }),
    )
    .expect("serialize DIFF-003 executed assertion");
    file.write_all(b"\n")
        .expect("terminate DIFF-003 executed assertion");
    file.sync_all().expect("sync DIFF-003 executed assertion");
}

fn join_names(boundary: &str) -> &'static [&'static str] {
    match boundary {
        "TRIG-001" => &[
            "trigger_capture_to_source",
            "input_capture_to_control_flow",
            "discovery_to_trigger",
            "consumer_cutover_rollback",
            "admin_cutover_rollback",
        ],
        "SCM-001" => &[
            "trigger_capture_to_source",
            "source_later_revision_to_dependency",
            "provisioner_to_source_transport",
        ],
        "SECRET-001" => &["secret_grant_to_connector"],
        "INPUT-001" => &["input_capture_to_control_flow"],
        "PROV-001" => &["provisioner_to_source_transport"],
        "EXT-001" => &[
            "secret_grant_to_connector",
            "connector_to_observer",
            "release_to_connector",
        ],
        "OBS-001" => &["connector_to_observer"],
        "DISC-001" => &["discovery_to_trigger"],
        "DEP-001" => &["source_later_revision_to_dependency", "dependency_to_cache"],
        "CACHE-001" => &["dependency_to_cache"],
        "CONSUMER-001" => &["consumer_cutover_rollback"],
        "ADMIN-001" => &["admin_cutover_rollback"],
        "REL-001" => &["release_to_connector"],
        _ => panic!("unsupported DIFF-003 boundary {boundary}"),
    }
}

pub fn receipt(boundary: &str, mut value: Value) -> Vec<u8> {
    if std::env::var_os("MCLOVING_DIFF003_RUNTIME_OUTPUT_DIR").is_some() {
        // Each projection is derived from this boundary's independently produced
        // live receipt. The runtime verifier compares it back to the signed
        // receipt and applies a pair-specific compatibility rule; no shared
        // constant is accepted as evidence that two boundaries agree.
        let observation = value.clone();
        let join_claims = join_names(boundary)
            .iter()
            .map(|name| {
                json!({
                    "schema": "mcloving.diff003.live-join-projection/v2",
                    "name": name,
                    "boundary": boundary,
                    "observation": observation,
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
