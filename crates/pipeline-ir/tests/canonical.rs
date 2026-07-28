use mcloving_pipeline_ir::{
    IR_V1, ParseLimits, SchemaCompatibility, SchemaVersion, compile_strict_yaml,
    validate_canonical_bytes,
};

const PIPELINE_A: &str = r#"
version: 1
name: canonical
stages:
  - id: test
    name: Test
    steps:
      - process:
          program: cargo
          args: [test, --locked]
          env:
            ZED: last
            ALPHA: first
          timeout_seconds: 30
"#;

const PIPELINE_B: &str = r#"
# comments and source ordering do not change semantic bytes
name: canonical
version: 1
stages:
- name: Test
  id: test
  steps:
  - process:
      timeout_seconds: 30
      env: {ALPHA: first, ZED: last}
      args:
      - test
      - --locked
      program: cargo
"#;

#[test]
fn canonical_bytes_ignore_yaml_presentation_and_mapping_order() {
    let first = compile_strict_yaml("fixture://a", PIPELINE_A, ParseLimits::default()).unwrap();
    let second = compile_strict_yaml("fixture://b", PIPELINE_B, ParseLimits::default()).unwrap();
    assert_eq!(
        first.canonical_bytes().unwrap(),
        second.canonical_bytes().unwrap()
    );
    assert_eq!(
        first.semantic_digest().unwrap(),
        second.semantic_digest().unwrap()
    );
    assert_ne!(
        first.provenance.source_sha256,
        second.provenance.source_sha256
    );

    let summary = validate_canonical_bytes(&first.canonical_bytes().unwrap()).unwrap();
    assert_eq!(summary.schema, IR_V1);
    assert_eq!(summary.pipeline_name, "canonical");
    assert_eq!(summary.stages, 1);
    assert_eq!(summary.steps, 1);
    assert_eq!(summary.sha256, first.semantic_digest().unwrap());
    assert_eq!(
        first.semantic_digest_hex().unwrap(),
        "31a4b2d6a0d288d374de0ea57575c2ee3a07c6b443285685cebe06b1a2ef0f9c"
    );
}

#[test]
fn independent_validator_rejects_mutation_truncation_and_trailing_data() {
    let pipeline = compile_strict_yaml("fixture://a", PIPELINE_A, ParseLimits::default()).unwrap();
    let bytes = pipeline.canonical_bytes().unwrap();

    let mut bad_magic = bytes.clone();
    bad_magic[0] ^= 0xff;
    assert!(validate_canonical_bytes(&bad_magic).is_err());

    assert!(validate_canonical_bytes(&bytes[..bytes.len() - 1]).is_err());

    let mut trailing = bytes;
    trailing.push(0);
    assert!(validate_canonical_bytes(&trailing).is_err());
}

#[test]
fn programmatic_ir_must_validate_before_canonicalization() {
    let mut pipeline =
        compile_strict_yaml("fixture://a", PIPELINE_A, ParseLimits::default()).unwrap();
    pipeline.name = "x".repeat(16 * 1024 + 1);
    assert!(pipeline.canonical_bytes().is_err());
    assert!(pipeline.semantic_digest().is_err());
}

#[test]
fn schema_compatibility_is_explicit() {
    assert_eq!(
        IR_V1.compatibility_with(SchemaVersion { major: 1, minor: 0 }),
        SchemaCompatibility::Compatible
    );
    assert_eq!(
        IR_V1.compatibility_with(SchemaVersion { major: 1, minor: 1 }),
        SchemaCompatibility::ReaderTooOld
    );
    assert_eq!(
        IR_V1.compatibility_with(SchemaVersion { major: 2, minor: 0 }),
        SchemaCompatibility::MajorMismatch
    );
}
