use std::fs;
use std::path::PathBuf;

use mcloving_jenkins_mapping_catalog::{
    CATALOG_ID, CATALOG_VERSION, CORPUS_MANIFEST_SHA256, PROFILE_SHA256, SCHEMA,
    validate_catalog_bytes, verify_bundle,
};

fn bundle_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../migration/mario-jenkins-oracle-228/corpus-v1/mapping-v1")
}

fn catalog() -> Vec<u8> {
    fs::read(bundle_root().join("catalog.yaml")).expect("read catalog")
}

#[test]
fn exact_corpus_earned_bundle_is_admitted() {
    let receipt = verify_bundle(&bundle_root()).expect("admit exact bundle");
    assert_eq!(receipt.schema, SCHEMA);
    assert_eq!(receipt.catalog_id, CATALOG_ID);
    assert_eq!(receipt.catalog_version, CATALOG_VERSION);
    assert_eq!(receipt.mappings, 1);
    assert_eq!(receipt.earned_cases, 1);
}

#[test]
fn plugin_profile_and_corpus_substitution_fail_closed() {
    for needle in [
        PROFILE_SHA256,
        CORPUS_MANIFEST_SHA256,
        "a0f0f1464ce3592f76d0f0079ce9fc2d4272594f995bf3d1a7ede4cd5031452e",
        "1479.v56e587f413a_7",
    ] {
        let mutated = String::from_utf8(catalog())
            .expect("UTF-8")
            .replace(needle, &"0".repeat(needle.len()));
        let error = validate_catalog_bytes(mutated.as_bytes()).expect_err("substitution must fail");
        assert!(
            matches!(error.code, "E_BINDING" | "E_TARGET_PROFILE"),
            "{}",
            error
        );
    }
}

#[test]
fn authority_host_reads_and_silent_fallback_fail_closed() {
    for (from, to) in [
        ("workload_execution: false", "workload_execution: true"),
        (
            "undeclared_host_reads: forbidden",
            "undeclared_host_reads: unsupported",
        ),
        ("silent_fallback: forbidden", "silent_fallback: unsupported"),
        ("host_filesystem: forbidden", "host_filesystem: unsupported"),
        ("network: forbidden", "network: unsupported"),
    ] {
        let mutated = String::from_utf8(catalog())
            .expect("UTF-8")
            .replace(from, to);
        let error = validate_catalog_bytes(mutated.as_bytes()).expect_err("policy must fail");
        assert!(matches!(
            error.code,
            "E_POLICY" | "E_EFFECTS" | "E_AUTHORITY"
        ));
    }
}

#[test]
fn floating_and_unearned_mappings_fail_closed() {
    for (from, to) in [
        ("mapping_version: 1", "mapping_version: 2"),
        ("literal_only: true", "literal_only: false"),
        ("mapping_earned_cases: 1", "mapping_earned_cases: 2"),
        ("local_input: not-applicable", "local_input: unsupported"),
        (
            "certified_equivalence_cases: 0",
            "certified_equivalence_cases: 1",
        ),
    ] {
        let mutated = String::from_utf8(catalog())
            .expect("UTF-8")
            .replace(from, to);
        assert!(
            validate_catalog_bytes(mutated.as_bytes()).is_err(),
            "{from}"
        );
    }
}

#[test]
fn unknown_fields_are_rejected() {
    let mutated = String::from_utf8(catalog())
        .expect("UTF-8")
        .replace("catalog_version: 1", "catalog_version: 1\nfallback: true");
    let error = validate_catalog_bytes(mutated.as_bytes()).expect_err("unknown field must fail");
    assert_eq!(error.code, "E_CATALOG_SCHEMA");
}
