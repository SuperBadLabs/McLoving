use mcloving_pipeline_ir::{
    IR_V1_6, IR_V1_7, ParseLimits, Step, compile_strict_yaml, validate_canonical_bytes,
};
fn source() -> String {
    format!(
        "version: 1\nname: checkout-fixture\nstages:\n  - id: build\n    name: Build\n    steps:\n      - checkout:\n          mapping_id: fixture\n          mapping_digest: sha256:{}\n          ref: refs/heads/main\n          commit: {}\n          destination: source\n          timeout_seconds: 120\n      - process:\n          program: /bin/true\n",
        "a".repeat(64),
        "b".repeat(40)
    )
}
#[test]
fn checkout_schema_and_canonical_encoding_are_bounded_and_versioned() {
    let p = compile_strict_yaml("test", &source(), ParseLimits::default()).unwrap();
    assert_eq!(p.schema, IR_V1_7);
    let Step::Checkout(checkout) = &p.stages[0].steps[0] else {
        panic!("first step is the checkout")
    };
    assert_eq!(checkout.spec.destination, "source");
    assert_eq!(checkout.spec.timeout_seconds, 120);
    let bytes = p.canonical_bytes().unwrap();
    assert_eq!(validate_canonical_bytes(&bytes).unwrap().schema, IR_V1_7);
    // An older schema cannot carry the step, in either direction.
    let mut old = p.clone();
    old.schema = IR_V1_6;
    assert!(old.canonical_bytes().is_err());
    let mut down = bytes.clone();
    down[14] = 0;
    down[15] = 6;
    assert!(validate_canonical_bytes(&down).is_err());
    for end in 0..bytes.len() {
        assert!(validate_canonical_bytes(&bytes[..end]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(validate_canonical_bytes(&trailing).is_err());
    let mut malformed = p;
    let Step::Checkout(checkout) = &mut malformed.stages[0].steps[0] else {
        unreachable!()
    };
    checkout.spec.timeout_seconds = 3_601;
    assert!(malformed.canonical_bytes().is_err());
}
#[test]
fn checkout_defaults_destination_and_timeout_and_accepts_a_parameterized_commit() {
    let minimal = source()
        .replace("          destination: source\n", "")
        .replace("          timeout_seconds: 120\n", "");
    let p = compile_strict_yaml("test", &minimal, ParseLimits::default()).unwrap();
    let Step::Checkout(checkout) = &p.stages[0].steps[0] else {
        panic!("first step is the checkout")
    };
    assert_eq!(checkout.spec.destination, "source");
    assert_eq!(checkout.spec.timeout_seconds, 600);

    let parameterized = format!(
        "version: 1\nname: checkout-parameter\nparameters:\n  revision:\n    type: string\n    default: \"{}\"\nstages:\n  - id: build\n    name: Build\n    steps:\n      - checkout:\n          mapping_id: fixture\n          mapping_digest: sha256:{}\n          ref: refs/heads/main\n          commit:\n            expression: parameters.revision\n",
        "c".repeat(40),
        "a".repeat(64)
    );
    let p = compile_strict_yaml("test", &parameterized, ParseLimits::default()).unwrap();
    assert_eq!(p.schema, IR_V1_7);
    let Step::Checkout(checkout) = &p.stages[0].steps[0] else {
        panic!("first step is the checkout")
    };
    assert_eq!(checkout.spec.commit, "c".repeat(40));
}
#[test]
fn checkout_compiler_rejects_authority_shape_and_duplicate_forms() {
    let input = source();
    for bad in [
        input.replace("ref: refs/heads/main", "ref: main"),
        input.replace(&"b".repeat(40), "main"),
        input.replace(&"b".repeat(40), &"B".repeat(40)),
        input.replace("destination: source", "destination: ../escape"),
        input.replace("destination: source", "destination: spool"),
        input.replace("destination: source", "destination: .git"),
        input.replace("timeout_seconds: 120", "timeout_seconds: 0"),
        input.replace("timeout_seconds: 120", "timeout_seconds: 3601"),
        input.replace(
            "mapping_id: fixture",
            "mapping_id: fixture\n          mapping_id: duplicate",
        ),
        // Two checkouts in one stage.
        input.replace(
            "      - process:\n          program: /bin/true\n",
            &format!("      - checkout:{}", input.split_once("      - checkout:").unwrap().1),
        ),
        // A checkout mixed with an intent stage.
        input.replace(
            "      - process:\n          program: /bin/true\n",
            &format!(
                "      - cache_intent:\n          mapping_id: fixture\n          mapping_digest: sha256:{}\n          operation: read\n          logical_key_sha256: {}\n          input_sha256: {}\n          timeout_seconds: 30\n",
                "a".repeat(64),
                "b".repeat(64),
                "c".repeat(64)
            ),
        ),
    ] {
        assert!(
            compile_strict_yaml("bad", &bad, ParseLimits::default()).is_err(),
            "accepted {bad}"
        );
    }
    for field in [
        "repository_url",
        "credential",
        "depth",
        "sparse_roots",
        "submodules",
        "executable",
        "program",
    ] {
        let bad = input.replace(
            "timeout_seconds: 120",
            &format!("timeout_seconds: 120\n          {field}: override"),
        );
        assert!(
            compile_strict_yaml("bad", &bad, ParseLimits::default()).is_err(),
            "accepted field {field}"
        );
    }
}
#[test]
fn a_container_stage_may_hold_a_checkout_beside_its_process_steps() {
    let contained = source().replace(
        "    name: Build\n",
        &format!(
            "    name: Build\n    image: docker.io/library/alpine@sha256:{}\n",
            "d".repeat(64)
        ),
    );
    let p = compile_strict_yaml("test", &contained, ParseLimits::default()).unwrap();
    assert_eq!(p.schema, IR_V1_7);
    assert!(p.stages[0].image.is_some());
    let bytes = p.canonical_bytes().unwrap();
    assert_eq!(validate_canonical_bytes(&bytes).unwrap().schema, IR_V1_7);
}
