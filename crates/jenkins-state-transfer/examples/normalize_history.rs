use std::collections::BTreeMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::Path;

use mcloving_jenkins_state_transfer::{
    ImportBinding, admitted_destination_identity, admitted_source_identity, admitted_tree_digest,
    load_admitted_history, normalize_single_aborted_workflow,
};
use mcloving_state_transfer::{BuildResult, Digest, sha256, transform};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !cfg!(unix) {
        return Err(
            "exact Jenkins history normalization requires Unix no-follow file access".into(),
        );
    }
    let arguments = env::args().collect::<Vec<_>>();
    if !matches!(arguments.len(), 4 | 5) {
        return Err(
            "usage: normalize_history SEALED_BUILDS EXPECTED_TREE_SHA256 OPAQUE_EVIDENCE_ID [OUTPUT_BUNDLE]"
                .into(),
        );
    }
    let root = Path::new(&arguments[1]);
    let expected_tree_digest = parse_digest(&arguments[2])?;
    if expected_tree_digest != admitted_tree_digest() {
        return Err("expected tree digest is not the exact admitted digest".into());
    }
    let history = load_admitted_history(root, arguments[3].clone())?;
    let executable = fs::read(env::current_exe()?)?;
    let parsed = normalize_single_aborted_workflow(
        &history,
        &ImportBinding {
            source: admitted_source_identity(),
            destination: admitted_destination_identity(),
            transform_implementation_digest: sha256(&executable),
            transform_configuration_digest: sha256(b"corpus052-single-aborted-workflow-v1"),
            provenance: "MIG-005A owner-held exact admitted-case source".to_owned(),
            source_job_id: "corpus-052-cinqict_jenkinsdev".to_owned(),
            target_pipeline_id: "corpus-052-cinqict_jenkinsdev".to_owned(),
        },
    )?;
    let plan = transform(parsed.bundle(), parsed.expected(), &BTreeMap::new())?;
    let job = &plan.bundle.jobs[0];
    if job.previous_result != Some(BuildResult::Aborted) {
        return Err("normalized previous result is divergent".into());
    }
    println!("schema={}", plan.bundle.binding.schema);
    println!("source_tree_sha256={}", encode_digest(expected_tree_digest));
    println!("bundle_sha256={}", encode_digest(plan.bundle_digest));
    println!("record_count={}", plan.bundle.expected_record_ids.len());
    println!("build_count={}", job.builds.len());
    println!("next_build_number={}", job.next_build_number);
    println!("previous_result=aborted");
    println!("persistent_dependency=build-history");
    println!("production_authority=false");
    if let Some(output) = arguments.get(4) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)?;
        file.write_all(&plan.canonical_bytes)?;
        file.sync_all()?;
    }
    Ok(())
}

fn parse_digest(value: &str) -> Result<Digest, Box<dyn std::error::Error>> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("expected digest is not canonical lowercase SHA-256".into());
    }
    let mut digest = [0_u8; 32];
    for (index, output) in digest.iter_mut().enumerate() {
        *output = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
    }
    Ok(digest)
}

fn encode_digest(digest: Digest) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
