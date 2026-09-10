use mcloving_pipeline_ir::{
    IR_V1_4, IR_V1_5, ParseLimits, Step, compile_strict_yaml, validate_canonical_bytes,
};
fn source() -> String {
    format!(
        "version: 1\nname: input-fixture\nstages:\n  - id: input\n    name: Input\n    steps:\n      - input_intent:\n          mapping_id: fixture\n          mapping_digest: sha256:{}\n          timeout_seconds: 30\n",
        "a".repeat(64)
    )
}
#[test]
fn input_schema_and_canonical_encoding_are_bounded_and_versioned() {
    let p = compile_strict_yaml("test", &source(), ParseLimits::default()).unwrap();
    assert_eq!(p.schema, IR_V1_5);
    let bytes = p.canonical_bytes().unwrap();
    assert_eq!(validate_canonical_bytes(&bytes).unwrap().schema, IR_V1_5);
    let mut old = p.clone();
    old.schema = IR_V1_4;
    assert!(old.canonical_bytes().is_err());
    let mut down = bytes.clone();
    down[14] = 0;
    down[15] = 4;
    assert!(validate_canonical_bytes(&down).is_err());
    for end in 0..bytes.len() {
        assert!(validate_canonical_bytes(&bytes[..end]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(validate_canonical_bytes(&trailing).is_err());
    let mut invalid_timeout = bytes;
    let n = invalid_timeout.len();
    invalid_timeout[n - 8..].fill(0);
    assert!(validate_canonical_bytes(&invalid_timeout).is_err());
    let mut malformed = p;
    let Step::InputIntent(input) = &mut malformed.stages[0].steps[0] else {
        unreachable!()
    };
    input.intent.timeout_seconds = 61;
    assert!(malformed.canonical_bytes().is_err());
}
#[test]
fn input_compiler_rejects_authority_unknown_duplicate_missing_and_mixed_forms() {
    let input = source();
    for bad in [
        input.replace("timeout_seconds: 30", "timeout_seconds: 0"),
        input.replace("timeout_seconds: 30", "timeout_seconds: 61"),
        input.replace(
            "timeout_seconds: 30",
            "timeout_seconds: '${{ parameters.timeout }}'",
        ),
        input.replace("          timeout_seconds: 30\n", ""),
        input.replace(
            "mapping_id: fixture",
            "mapping_id: fixture\n          mapping_id: duplicate",
        ),
        input.replace(
            "timeout_seconds: 30",
            "timeout_seconds: 30\n      - process:\n          program: /bin/true",
        ),
        input.clone()
            + &format!(
                "      - input_intent:{}",
                input.split_once("      - input_intent:").unwrap().1
            ),
    ] {
        assert!(
            compile_strict_yaml("bad", &bad, ParseLimits::default()).is_err(),
            "accepted {bad}"
        );
    }
    for field in [
        "query",
        "cursor",
        "endpoint",
        "principal",
        "schema",
        "confidentiality",
        "credential",
        "operation",
        "requested_at",
    ] {
        let bad = input.replace(
            "timeout_seconds: 30",
            &format!("timeout_seconds: 30\n          {field}: override"),
        );
        assert!(compile_strict_yaml("bad", &bad, ParseLimits::default()).is_err());
    }
}
#[test]
fn separate_input_cache_process_stages_retain_minimum_required_schema() {
    let source = source()
        + &format!(
            "  - id: cache\n    name: Cache\n    steps:\n      - cache_intent:\n          mapping_id: fixture\n          mapping_digest: sha256:{}\n          operation: read\n          logical_key_sha256: {}\n          input_sha256: {}\n          timeout_seconds: 30\n  - id: process\n    name: Process\n    steps:\n      - process:\n          program: /bin/true\n",
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64)
        );
    let p = compile_strict_yaml("mixed", &source, ParseLimits::default()).unwrap();
    assert_eq!(p.schema, IR_V1_5);
    assert_eq!(
        validate_canonical_bytes(&p.canonical_bytes().unwrap())
            .unwrap()
            .schema,
        IR_V1_5
    );
}
