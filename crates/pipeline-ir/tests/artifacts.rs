use mcloving_pipeline_ir::{
    IR_V1, IR_V1_7, IR_V1_8, ParseLimits, compile_strict_yaml, validate_canonical_bytes,
};

const SOURCE: &str = "version: 1\nname: artifacts-fixture\nstages:\n  - id: build\n    name: Build\n    steps:\n      - process:\n          program: /bin/true\n    artifacts:\n      - name: target-logs\n        paths: [\"target/**/*.log\", \"report-?.xml\"]\n      - name: binaries\n        paths: [\"out/*\"]\n";

#[test]
fn declared_artifacts_are_typed_versioned_and_canonically_encoded() {
    let p = compile_strict_yaml("test", SOURCE, ParseLimits::default()).unwrap();
    assert_eq!(p.schema, IR_V1_8);
    let artifacts = &p.stages[0].artifacts;
    assert_eq!(artifacts.len(), 2);
    assert_eq!(artifacts[0].name, "target-logs");
    assert_eq!(artifacts[0].paths, ["target/**/*.log", "report-?.xml"]);
    assert!(artifacts[0].matches("target/debug/build.log"));
    assert!(!artifacts[0].matches("target/debug/build.txt"));
    let bytes = p.canonical_bytes().unwrap();
    assert_eq!(validate_canonical_bytes(&bytes).unwrap().schema, IR_V1_8);
    // An older schema cannot carry the declaration, in either direction.
    let mut old = p.clone();
    old.schema = IR_V1_7;
    assert!(old.canonical_bytes().is_err());
    let mut down = bytes.clone();
    down[14] = 0;
    down[15] = 7;
    assert!(validate_canonical_bytes(&down).is_err());
    for end in 0..bytes.len() {
        assert!(validate_canonical_bytes(&bytes[..end]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(validate_canonical_bytes(&trailing).is_err());
    // A tampered canonical form with a duplicate name or an escaping pattern
    // is refused by the reader, not only by the compiler.
    let mut duplicate = p.clone();
    duplicate.stages[0].artifacts[1].name = "target-logs".to_owned();
    assert!(duplicate.canonical_bytes().is_err());
    let mut escaping = p.clone();
    escaping.stages[0].artifacts[0].paths[0] = "../outside/*".to_owned();
    assert!(escaping.canonical_bytes().is_err());
    // A pipeline that declares nothing keeps its older schema: no version
    // drift for existing pipelines.
    let plain = SOURCE.split("    artifacts:").next().unwrap();
    let p = compile_strict_yaml("test", plain, ParseLimits::default()).unwrap();
    assert_eq!(p.schema, IR_V1);
    assert!(p.stages[0].artifacts.is_empty());
}

#[test]
fn artifact_declarations_are_refused_by_field() {
    for (bad, field) in [
        (
            SOURCE.replace("name: target-logs", "name: .hidden"),
            "artifacts[0]",
        ),
        (
            SOURCE.replace("target/**/*.log", "/abs/*.log"),
            "artifacts[0]",
        ),
        (
            SOURCE.replace("target/**/*.log", "../escape/*"),
            "artifacts[0]",
        ),
        (SOURCE.replace("target/**/*.log", "a\\\\b"), "artifacts[0]"),
        (
            SOURCE.replace("name: binaries", "name: target-logs"),
            "artifacts",
        ),
        (
            SOURCE.replace("paths: [\"out/*\"]", "paths: []"),
            "artifacts[1]",
        ),
        (
            SOURCE.replace("paths: [\"out/*\"]", "paths: out/*"),
            "artifacts[1].paths",
        ),
        (
            SOURCE.replace(
                "      - name: binaries\n",
                "      - name: binaries\n        extra: 1\n",
            ),
            "artifacts[1]",
        ),
    ] {
        let error = compile_strict_yaml("test", &bad, ParseLimits::default())
            .err()
            .unwrap_or_else(|| panic!("accepted: {bad}"));
        let text = error.to_string();
        assert!(text.contains(field), "{field}: {text}");
    }
}
