use std::collections::BTreeMap;

use mcloving_domain::notifications::NotifyTarget;
use mcloving_pipeline_ir::{
    IR_V1_1, IR_V1_8, IR_V1_9, ParameterValue, ParseLimits, compile_strict_yaml,
    compile_strict_yaml_with_parameters, instantiate_pipeline, validate_canonical_bytes,
};

const SOURCE: &str = "version: 1\nname: notify-fixture\nparameters:\n  revision:\n    type: string\n    default: \"0123456789abcdef0123456789abcdef01234567\"\nstages:\n  - id: build\n    name: Build\n    steps:\n      - process:\n          program: /bin/true\nnotify:\n  - github_status:\n      mapping_id: github.mcloving\n      commit:\n        expression: parameters.revision\n      context: mcloving/foundation\n      repository: SuperBadLabs/McLoving\n  - webhook:\n      mapping_id: hooks.team\n";

#[test]
fn notification_targets_are_typed_versioned_and_canonically_encoded() {
    let p = compile_strict_yaml("test", SOURCE, ParseLimits::default()).unwrap();
    assert_eq!(p.schema, IR_V1_9);
    assert_eq!(p.notify.len(), 2);
    let NotifyTarget::GithubStatus {
        mapping_id,
        commit,
        context,
        repository,
    } = &p.notify[0]
    else {
        panic!("first target is the commit status")
    };
    assert_eq!(mapping_id, "github.mcloving");
    assert_eq!(commit, "0123456789abcdef0123456789abcdef01234567");
    assert_eq!(context, "mcloving/foundation");
    assert_eq!(repository.as_deref(), Some("SuperBadLabs/McLoving"));
    assert_eq!(
        p.notify[1],
        NotifyTarget::Webhook {
            mapping_id: "hooks.team".to_owned()
        }
    );
    // The commit rides an expression binding on its own path and is
    // re-materialized on instantiation.
    assert!(
        p.expressions
            .iter()
            .any(|binding| binding.path == "$.notify[0].github_status.commit")
    );
    let instantiated = instantiate_pipeline(
        &p,
        BTreeMap::from([(
            "revision".to_owned(),
            ParameterValue::String("fedcba9876543210fedcba9876543210fedcba98".to_owned()),
        )]),
    )
    .unwrap();
    let NotifyTarget::GithubStatus { commit, .. } = &instantiated.notify[0] else {
        unreachable!()
    };
    assert_eq!(commit, "fedcba9876543210fedcba9876543210fedcba98");
    let bytes = p.canonical_bytes().unwrap();
    assert_eq!(validate_canonical_bytes(&bytes).unwrap().schema, IR_V1_9);
    // An older schema cannot carry the targets, in either direction.
    let mut old = p.clone();
    old.schema = IR_V1_8;
    assert!(old.canonical_bytes().is_err());
    let mut down = bytes.clone();
    down[14] = 0;
    down[15] = 8;
    assert!(validate_canonical_bytes(&down).is_err());
    for end in 0..bytes.len() {
        assert!(validate_canonical_bytes(&bytes[..end]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(validate_canonical_bytes(&trailing).is_err());
    // A tampered canonical form with a bad target is refused by the reader.
    let mut bad = p.clone();
    bad.notify[0] = NotifyTarget::GithubStatus {
        mapping_id: "github.mcloving".to_owned(),
        commit: "not-hex".to_owned(),
        context: "ctx".to_owned(),
        repository: None,
    };
    assert!(bad.canonical_bytes().is_err());
    // A pipeline that names no target keeps its older schema.
    let plain = SOURCE.split("notify:").next().unwrap();
    let p = compile_strict_yaml("test", plain, ParseLimits::default()).unwrap();
    assert_eq!(p.schema, IR_V1_1);
    assert!(p.notify.is_empty());
}

#[test]
fn a_parameter_supplied_commit_is_validated_after_evaluation() {
    let refused = compile_strict_yaml_with_parameters(
        "test",
        SOURCE,
        ParseLimits::default(),
        BTreeMap::from([(
            "revision".to_owned(),
            ParameterValue::String("Not A Commit".to_owned()),
        )]),
    )
    .expect_err("a non-hex commit is refused");
    assert!(
        refused.to_string().contains("notify[0].github_status"),
        "{refused}"
    );
}

#[test]
fn notification_targets_are_refused_by_field() {
    for (bad, field) in [
        (SOURCE.replace("mapping_id: hooks.team", "mapping_id: \"not canonical\""), "notify[1].webhook"),
        (SOURCE.replace("context: mcloving/foundation", "context: \"\""), "notify[0].github_status"),
        (SOURCE.replace("repository: SuperBadLabs/McLoving", "repository: nope"), "notify[0].github_status"),
        (SOURCE.replace("  - webhook:\n      mapping_id: hooks.team\n", "  - webhook:\n      mapping_id: hooks.team\n      extra: 1\n"), "notify[1].webhook"),
        (SOURCE.replace("  - webhook:\n      mapping_id: hooks.team\n", "  - slack:\n      mapping_id: hooks.team\n"), "notify[1].slack"),
        (SOURCE.replace("  - webhook:\n      mapping_id: hooks.team\n", "  - webhook:\n      mapping_id: hooks.team\n    github_status:\n      mapping_id: x\n      commit: \"0123456\"\n"), "notify[1]"),
    ] {
        let error = compile_strict_yaml("test", &bad, ParseLimits::default())
            .err()
            .unwrap_or_else(|| panic!("accepted: {bad}"));
        assert!(error.to_string().contains(field), "{field}: {error}");
    }
}
