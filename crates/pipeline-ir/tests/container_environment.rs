use mcloving_pipeline_ir::{ParseLimits, compile_strict_yaml};
fn source(name: &str, value: &str, container: bool) -> String {
    let image = if container {
        format!(
            "    image: example.invalid/image@sha256:{}\n",
            "a".repeat(64)
        )
    } else {
        String::new()
    };
    format!(
        "version: 1\nname: env\nstages:\n  - id: build\n    name: Build\n{image}    steps:\n      - process:\n          program: /bin/true\n          env:\n            {name:?}: {value:?}\n"
    )
}
#[test]
fn container_environment_names_cannot_be_env_file_comments() {
    for name in ["#", "#NAME", "BAD=NAME", "BAD\nNAME", "BAD\0NAME"] {
        let err = compile_strict_yaml(
            "container-env",
            &source(name, "value", true),
            ParseLimits::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("environment"), "{name:?}: {err}");
    }
    for value in ["two\nlines", "nul\0value"] {
        assert!(
            compile_strict_yaml(
                "container-env",
                &source("NAME", value, true),
                ParseLimits::default()
            )
            .is_err()
        );
    }
    assert!(
        compile_strict_yaml(
            "container-env",
            &source("NAME", "#literal=value", true),
            ParseLimits::default()
        )
        .is_ok()
    );
    assert!(
        compile_strict_yaml(
            "host-env",
            &source("#NAME", "literal", false),
            ParseLimits::default()
        )
        .is_ok()
    );
}
