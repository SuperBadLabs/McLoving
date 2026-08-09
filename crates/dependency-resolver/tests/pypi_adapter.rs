use mcloving_dependency_resolver::{
    AdapterBindings, RepositoryBinding, SourceTrustClass, parse_pypi_requirements,
};

fn bindings() -> AdapterBindings {
    AdapterBindings {
        adapter_id: "pypi-requirements-v1".to_owned(),
        adapter_sha256: "a".repeat(64),
        source_tree_sha256: "b".repeat(64),
        resolver_toolchain_id: "pip-exporter-1".to_owned(),
        resolver_toolchain_sha256: "c".repeat(64),
        source_trust_class: SourceTrustClass::Trusted,
        repositories: vec![RepositoryBinding {
            repository_id: "contained-pypi".to_owned(),
            credentialed: false,
            permits_untrusted_source: true,
        }],
    }
}

fn valid_requirements() -> String {
    format!(
        "sample-app==1.0.0 --repository=contained-pypi --artifact=packages/sample_app-1.0.0-py3-none-any.whl --size=23 --hash=sha256:{} --attestation=contained-pypi-key --depends=tiny-lib==2.1.0 --root\n\
         tiny-lib==2.1.0 --repository=contained-pypi --artifact=packages/tiny_lib-2.1.0-py3-none-any.whl --size=17 --hash=sha256:{} --attestation=contained-pypi-key\n",
        "d".repeat(64),
        "e".repeat(64)
    )
}

#[test]
fn exact_hashed_requirements_produce_a_complete_plan() {
    let requirements = valid_requirements();
    let plan =
        parse_pypi_requirements(requirements.as_bytes(), &bindings()).expect("valid PyPI lock");
    assert_eq!(plan.nodes.len(), 2);
    assert_eq!(plan.roots.len(), 1);
    assert_eq!(
        plan.nodes
            .iter()
            .map(|node| node.dependencies.len())
            .sum::<usize>(),
        1
    );
}

#[test]
fn floating_marker_url_and_include_syntax_are_typed_unsupported() {
    for unsupported in [
        "sample-app>=1.0.0 --root\n",
        "sample-app==1.0.0;python_version>'3.11' --root\n",
        "sample-app[extra]==1.0.0 --root\n",
        "-r other.txt\n",
        "sample-app @ https://example.invalid/app.whl\n",
    ] {
        let error = parse_pypi_requirements(unsupported.as_bytes(), &bindings())
            .expect_err("unsupported requirements syntax");
        assert_eq!(error.code, "DEP_PYPI_SYNTAX_UNSUPPORTED");
    }
}

#[test]
fn pypi_hash_metadata_edges_and_line_encoding_fail_closed() {
    let missing_hash =
        valid_requirements().replace(&format!(" --hash=sha256:{}", "d".repeat(64)), "");
    let error =
        parse_pypi_requirements(missing_hash.as_bytes(), &bindings()).expect_err("missing hash");
    assert_eq!(error.code, "DEP_PYPI_SYNTAX_UNSUPPORTED");

    let missing_node =
        valid_requirements().replace("tiny-lib==2.1.0 --root", "missing==2.1.0 --root");
    let error = parse_pypi_requirements(missing_node.as_bytes(), &bindings()).expect_err("edge");
    assert_eq!(error.code, "DEP_PYPI_GRAPH_NODE_MISSING");

    let crlf = valid_requirements().replace('\n', "\r\n");
    let error = parse_pypi_requirements(crlf.as_bytes(), &bindings()).expect_err("CRLF");
    assert_eq!(error.code, "DEP_PYPI_LOCK_INVALID");
}

#[test]
fn pypi_versions_must_be_canonical_pep440_text() {
    for invalid in [
        "01.0.0",
        "1_0_0",
        "V1.0.0",
        "1..0",
        "1.0.0garbage",
        "1.0.0-rc1",
    ] {
        let requirements = valid_requirements().replace("1.0.0", invalid);
        let error = parse_pypi_requirements(requirements.as_bytes(), &bindings())
            .expect_err("noncanonical PyPI version");
        assert_eq!(error.code, "DEP_VERSION_MUTABLE", "version {invalid}");
    }

    let canonical = valid_requirements().replace("1.0.0", "1!1.0.0rc1.post2.dev3+linux.1");
    parse_pypi_requirements(canonical.as_bytes(), &bindings()).expect("canonical PEP 440 version");
}
