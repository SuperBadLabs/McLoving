use mcloving_jenkins_compiler_admission::{
    ADMITTED_JOB_GENERATION, ADMITTED_JOB_ID, ADMITTED_SOURCE_SHA256, ExpectedAdmission,
    ValidatedResponse, admit_response, validate_response,
};
use sha2::{Digest, Sha256};

const RESPONSE: &[u8] = include_bytes!("fixtures/mig003-golden.edn");
const UNSUPPORTED: &[u8] = include_bytes!("fixtures/mig003-unsupported.edn");
const REJECTED: &[u8] = include_bytes!("fixtures/rejected.edn");
const SOURCE: &[u8] = include_bytes!(
    "../../../migration/mario-jenkins-oracle-228/corpus-v1/sources/cinqict_jenkinsdev.Jenkinsfile"
);

fn expected() -> ExpectedAdmission<'static> {
    ExpectedAdmission {
        request_id: "mig003-golden",
        job_id: ADMITTED_JOB_ID,
        job_generation: ADMITTED_JOB_GENERATION,
        source: SOURCE,
    }
}

#[test]
fn exact_worker_fixture_is_independently_admitted() {
    let receipt = admit_response(RESPONSE, expected()).unwrap();
    assert_eq!(receipt.source_sha256, ADMITTED_SOURCE_SHA256);
    assert_eq!(receipt.state, "disabled");
    assert_eq!(receipt.stages, 1);
    assert_eq!(receipt.steps, 1);
    assert_eq!(
        receipt.pipeline_yaml_sha256,
        "551d489ca13bf5d130bdc5c10ce35e5d3d988bdaa1c5488dd9bc79b30674acdc"
    );
    assert_eq!(
        receipt.jobstate_yaml_sha256,
        "45f86c932d04a9d109afc0dd2b8a0ef30909311a59d4f453d77ed4b0e98c5be4"
    );
    assert_eq!(
        receipt.semantic_ir_sha256,
        "2a9b8b7bcd076950c67de874bd1e2b693af511ad55a7de3495d5c0b4210349d3"
    );
}

#[test]
fn every_compile_status_is_independently_validated() {
    assert!(matches!(
        validate_response(RESPONSE, expected()).unwrap(),
        ValidatedResponse::Admitted(_)
    ));
    let downgrade = validate_response(UNSUPPORTED, expected()).unwrap_err();
    assert_eq!(downgrade.code, "E_STATUS_DOWNGRADE");
    assert_eq!(
        validate_response(REJECTED, expected()).unwrap(),
        ValidatedResponse::Rejected {
            code: "E_ENV_AUTHORITY".to_owned()
        }
    );
}

#[test]
fn exact_admitted_case_cannot_be_downgraded_to_unsupported() {
    let error = validate_response(UNSUPPORTED, expected()).unwrap_err();
    assert_eq!(error.code, "E_STATUS_DOWNGRADE");
}

#[test]
fn alternate_edn_whitespace_cannot_bypass_compiled_admission() {
    let mutation = String::from_utf8(RESPONSE.to_vec())
        .unwrap()
        .replace(":status :compiled", ":status,:compiled");
    assert!(mutation.contains(":status,:compiled"));
    assert!(validate_response(mutation.as_bytes(), expected()).is_err());
}

#[test]
fn undeclared_worker_diagnostics_fail_closed() {
    let mutation = String::from_utf8(REJECTED.to_vec())
        .unwrap()
        .replace("E_ENV_AUTHORITY", "E_UNDECLARED_DIAGNOSTIC");
    assert!(validate_response(mutation.as_bytes(), expected()).is_err());
}

#[test]
fn authority_profile_state_and_canonical_substitution_fail_closed() {
    for mutation in [
        String::from_utf8(RESPONSE.to_vec())
            .unwrap()
            .replace(":effect-authority false", ":effect-authority true"),
        String::from_utf8(RESPONSE.to_vec())
            .unwrap()
            .replace("state: disabled", "state: enabled"),
        String::from_utf8(RESPONSE.to_vec()).unwrap().replace(
            "feeeb44d32aa10181e572a0dbbf5b2e23895731b1913bd46aba9f38d56172271",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        format!(" {}", String::from_utf8(RESPONSE.to_vec()).unwrap()),
    ] {
        assert!(admit_response(mutation.as_bytes(), expected()).is_err());
    }
}

#[test]
fn caller_source_and_job_generation_are_not_worker_controlled() {
    let wrong_source = b"pipeline { agent any }";
    assert!(
        admit_response(
            RESPONSE,
            ExpectedAdmission {
                source: wrong_source,
                ..expected()
            }
        )
        .is_err()
    );
    assert!(
        admit_response(
            RESPONSE,
            ExpectedAdmission {
                job_generation: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ..expected()
            }
        )
        .is_err()
    );
}

#[test]
fn self_consistent_malicious_yaml_is_still_reparsed_and_rejected() {
    let original_pipeline = concat!(
        "version: 1\n",
        "name: \"corpus-052-cinqict_jenkinsdev\"\n",
        "stages:\n",
        "  - id: \"build\"\n",
        "    name: \"Build\"\n",
        "    steps:\n",
        "      - process:\n",
        "          program: \"/bin/sh\"\n",
        "          args: [\"-xe\", \"-c\", \"echo \\\"Hello World\\\"\"]\n"
    );
    let malicious_pipeline = original_pipeline.replace(
        "stages:\n",
        "parameters:\n  token:\n    type: string\n    secret: true\nstages:\n",
    );
    let mut mutation = String::from_utf8(RESPONSE.to_vec()).unwrap().replace(
        "stages:\\n",
        "parameters:\\n  token:\\n    type: string\\n    secret: true\\nstages:\\n",
    );
    mutation = mutation.replace(
        "551d489ca13bf5d130bdc5c10ce35e5d3d988bdaa1c5488dd9bc79b30674acdc",
        &sha256_hex(malicious_pipeline.as_bytes()),
    );
    assert!(admit_response(mutation.as_bytes(), expected()).is_err());

    let original_jobstate = concat!(
        "version: 1\n",
        "schema: mcloving.jenkins.jobstate-import\n",
        "job_id: \"corpus-052-cinqict_jenkinsdev\"\n",
        "state: disabled\n",
        "generation: \"e76362bbc8e899510b8498808ffd0d2f83bb64d3215cf2c5b31690895f251d97\"\n",
        "reason: \"offline-frozen-source-state\"\n",
        "actor: \"jenkins/system\"\n",
        "effective_time: \"2026-07-31T06:44:17Z\"\n",
        "provenance:\n",
        "  controller: \"mario/jenkins-oracle-228\"\n",
        "  inventory_fingerprint: \"b1c2f81c74ec0ffc36971f358f920b2d0775c6009f474bea924448cd2a1915c1\"\n",
        "  source_sha256: \"666ac2275ea75730e27cf7b565d757691b094c508355adc0199d745278a23100\"\n",
        "  compiler: \"mcloving-jenkins-compiler-worker/1\"\n",
        "  compiler_profile_sha256: \"feeeb44d32aa10181e572a0dbbf5b2e23895731b1913bd46aba9f38d56172271\"\n"
    );
    let malicious_jobstate = original_jobstate.replace(
        "state: disabled\n",
        "state: disabled\nhost_path: \"/var/jenkins_home\"\n",
    );
    let mut mutation = String::from_utf8(RESPONSE.to_vec()).unwrap().replace(
        "state: disabled\\n",
        "state: disabled\\nhost_path: \\\"/var/jenkins_home\\\"\\n",
    );
    mutation = mutation.replace(
        "45f86c932d04a9d109afc0dd2b8a0ef30909311a59d4f453d77ed4b0e98c5be4",
        &sha256_hex(malicious_jobstate.as_bytes()),
    );
    assert!(admit_response(mutation.as_bytes(), expected()).is_err());
}

fn sha256_hex(value: &[u8]) -> String {
    Sha256::digest(value)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
