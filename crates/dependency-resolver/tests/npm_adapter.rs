use mcloving_dependency_resolver::{
    AdapterBindings, RepositoryBinding, SourceTrustClass, parse_npm_package_lock,
};

fn bindings() -> AdapterBindings {
    AdapterBindings {
        adapter_id: "npm-package-lock-v3".to_owned(),
        adapter_sha256: "a".repeat(64),
        source_tree_sha256: "b".repeat(64),
        resolver_toolchain_id: "npm-11".to_owned(),
        resolver_toolchain_sha256: "c".repeat(64),
        source_trust_class: SourceTrustClass::Trusted,
        repositories: vec![RepositoryBinding {
            repository_id: "contained-npm".to_owned(),
            credentialed: false,
            permits_untrusted_source: true,
        }],
    }
}

fn valid_lock() -> String {
    format!(
        r#"{{
          "name":"sample-app",
          "version":"1.0.0",
          "lockfileVersion":3,
          "requires":true,
          "packages":{{
            "":{{
              "name":"sample-app",
              "version":"1.0.0",
              "dependencies":{{"tiny-lib":"2.1.0"}},
              "integrity":null,
              "mcloving":null
            }},
            "node_modules/tiny-lib":{{
              "name":"tiny-lib",
              "version":"2.1.0",
              "dependencies":{{}},
              "integrity":"sha256-{}",
              "mcloving":{{
                "repository_id":"contained-npm",
                "artifact_path":"tiny-lib/-/tiny-lib-2.1.0.tgz",
                "declared_size":19,
                "sha256":"{}",
                "attestation_key_id":"contained-npm-key"
              }}
            }}
          }}
        }}"#,
        "d".repeat(64),
        "d".repeat(64)
    )
}

#[test]
fn package_lock_v3_produces_a_canonical_plan() {
    let lock = valid_lock();
    let plan = parse_npm_package_lock(lock.as_bytes(), &bindings()).expect("valid npm lock");
    assert_eq!(plan.nodes.len(), 1);
    assert_eq!(plan.roots, vec![plan.nodes[0].node_id.clone()]);
    assert_eq!(plan.nodes[0].coordinate, "tiny-lib");
}

#[test]
fn npm_unknown_duplicate_and_unsafe_install_metadata_are_denied() {
    let duplicate = valid_lock().replacen(
        r#""lockfileVersion":3"#,
        r#""lockfileVersion":3,"lockfileVersion":3"#,
        1,
    );
    let error = parse_npm_package_lock(duplicate.as_bytes(), &bindings()).expect_err("duplicate");
    assert_eq!(error.code, "DEP_NPM_LOCK_INVALID");

    let install_script = valid_lock().replacen(
        r#""integrity":null"#,
        r#""hasInstallScript":true,"integrity":null"#,
        1,
    );
    let error = parse_npm_package_lock(install_script.as_bytes(), &bindings()).expect_err("script");
    assert_eq!(error.code, "DEP_NPM_LOCK_INVALID");
}

#[test]
fn npm_integrity_layout_and_version_substitution_are_denied() {
    let wrong_integrity = valid_lock().replacen(&"d".repeat(64), &"e".repeat(64), 1);
    let error =
        parse_npm_package_lock(wrong_integrity.as_bytes(), &bindings()).expect_err("integrity");
    assert_eq!(error.code, "DEP_NPM_INTEGRITY_INVALID");

    let nested = valid_lock().replacen(
        "node_modules/tiny-lib",
        "node_modules/parent/node_modules/tiny-lib",
        1,
    );
    let error = parse_npm_package_lock(nested.as_bytes(), &bindings()).expect_err("nested layout");
    assert_eq!(error.code, "DEP_NPM_LAYOUT_UNSUPPORTED");

    let substitution = valid_lock().replacen(
        r#""dependencies":{"tiny-lib":"2.1.0"}"#,
        r#""dependencies":{"tiny-lib":"2.2.0"}"#,
        1,
    );
    let error =
        parse_npm_package_lock(substitution.as_bytes(), &bindings()).expect_err("substitution");
    assert_eq!(error.code, "DEP_NPM_VERSION_SUBSTITUTION");
}
