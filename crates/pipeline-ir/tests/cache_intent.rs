use mcloving_pipeline_ir::{
    IR_V1_3, IR_V1_4, ParseLimits, Step, compile_strict_yaml, validate_canonical_bytes,
};
fn source(operation: &str, content: &str) -> String {
    format!(
        "version: 1\nname: cache-fixture\nstages:\n  - id: cache\n    name: Cache\n    steps:\n      - cache_intent:\n          mapping_id: fixture\n          mapping_digest: sha256:{}\n          operation: {operation}\n          logical_key_sha256: {}\n          input_sha256: {}\n{content}          timeout_seconds: 30\n",
        "a".repeat(64),
        "b".repeat(64),
        "c".repeat(64)
    )
}
#[test]
fn cache_schema_and_canonical_encoding_are_bounded_and_versioned() {
    for (op, content) in [
        ("read", ""),
        ("publish", "          content_base64: cHVibGlj\n"),
    ] {
        let p = compile_strict_yaml("test", &source(op, content), ParseLimits::default()).unwrap();
        assert_eq!(p.schema, IR_V1_4);
        assert!(matches!(p.stages[0].steps[0], Step::CacheIntent(_)));
        let bytes = p.canonical_bytes().unwrap();
        assert_eq!(validate_canonical_bytes(&bytes).unwrap().schema, IR_V1_4);
        let mut old = p.clone();
        old.schema = IR_V1_3;
        assert!(old.canonical_bytes().is_err());
        let mut down = bytes.clone();
        down[14] = 0;
        down[15] = 3;
        assert!(validate_canonical_bytes(&down).is_err());
        let mut malformed = p;
        let Step::CacheIntent(cache) = &mut malformed.stages[0].steps[0] else {
            unreachable!()
        };
        cache.intent.timeout_seconds = 61;
        assert!(malformed.canonical_bytes().is_err());
    }
}
#[test]
fn cache_compiler_rejects_extra_authority_and_mixed_or_unbounded_forms() {
    let read = source("read", "");
    for bad in [
        read.replace("timeout_seconds: 30", "timeout_seconds: 0"),
        read.replace("operation: read", "operation: delete"),
        read.replace(
            "timeout_seconds: 30",
            "timeout_seconds: 30\n          program: /bin/cache",
        ),
        source("read", "          content_base64: cHVibGlj\n"),
        source("publish", ""),
        source(
            "publish",
            "          content_base64: '${{ parameters.content }}'\n",
        ),
        read.replace(
            "          mapping_id: fixture",
            "          mapping_id: fixture\n          mapping_id: duplicate",
        ),
        read.replace(
            "timeout_seconds: 30",
            "timeout_seconds: 30\n      - process:\n          program: true",
        ),
    ] {
        assert!(
            compile_strict_yaml("bad", &bad, ParseLimits::default()).is_err(),
            "accepted {bad}"
        );
    }
}
