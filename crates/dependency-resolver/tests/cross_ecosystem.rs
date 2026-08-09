use mcloving_dependency_resolver::{
    AdapterBindings, CanonicalPlan, Ecosystem, RepositoryBinding, SourceTrustClass,
    parse_maven_lock, parse_npm_package_lock, parse_pypi_requirements,
};

fn bindings(ecosystem: Ecosystem, repository_id: &str) -> AdapterBindings {
    AdapterBindings {
        adapter_id: format!("{ecosystem:?}-adapter-v1").to_ascii_lowercase(),
        adapter_sha256: "a".repeat(64),
        source_tree_sha256: "b".repeat(64),
        resolver_toolchain_id: "contained-toolchain".to_owned(),
        resolver_toolchain_sha256: "c".repeat(64),
        source_trust_class: SourceTrustClass::Trusted,
        repositories: vec![RepositoryBinding {
            repository_id: repository_id.to_owned(),
            credentialed: false,
            permits_untrusted_source: true,
        }],
    }
}

#[test]
fn all_v1_ecosystems_export_the_same_closed_two_node_topology() {
    let app_digest = "d".repeat(64);
    let library_digest = "e".repeat(64);
    let maven = format!(
        r#"{{"schema_version":"mcloving.maven-lock/v1","nodes":[{{"key":"app","group":"com.example","artifact":"app","artifact_type":"jar","classifier":null,"version":"1.0.0","repository_id":"maven","artifact_path":"com/example/app/1.0.0/app.jar","declared_size":11,"sha256":"{app_digest}","attestation_key_id":"maven-key","dependencies":["library"]}},{{"key":"library","group":"com.example","artifact":"library","artifact_type":"jar","classifier":null,"version":"2.0.0","repository_id":"maven","artifact_path":"com/example/library/2.0.0/library.jar","declared_size":7,"sha256":"{library_digest}","attestation_key_id":"maven-key","dependencies":[]}}],"roots":["app"]}}"#
    );
    let npm = format!(
        r#"{{"name":"root","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{{"":{{"name":"root","version":"1.0.0","dependencies":{{"app":"1.0.0"}},"integrity":null,"mcloving":null}},"node_modules/app":{{"name":"app","version":"1.0.0","dependencies":{{"library":"2.0.0"}},"integrity":"sha256-{app_digest}","mcloving":{{"repository_id":"npm","artifact_path":"app/-/app-1.0.0.tgz","declared_size":11,"sha256":"{app_digest}","attestation_key_id":"npm-key"}}}},"node_modules/library":{{"name":"library","version":"2.0.0","dependencies":{{}},"integrity":"sha256-{library_digest}","mcloving":{{"repository_id":"npm","artifact_path":"library/-/library-2.0.0.tgz","declared_size":7,"sha256":"{library_digest}","attestation_key_id":"npm-key"}}}}}}}}"#
    );
    let pypi = format!(
        "app==1.0.0 --repository=pypi --artifact=packages/app-1.0.0.whl --size=11 --hash=sha256:{app_digest} --attestation=pypi-key --depends=library==2.0.0 --root\n\
         library==2.0.0 --repository=pypi --artifact=packages/library-2.0.0.whl --size=7 --hash=sha256:{library_digest} --attestation=pypi-key\n"
    );
    let plans = [
        parse_maven_lock(maven.as_bytes(), &bindings(Ecosystem::Maven, "maven"))
            .expect("Maven plan"),
        parse_npm_package_lock(npm.as_bytes(), &bindings(Ecosystem::Npm, "npm")).expect("npm plan"),
        parse_pypi_requirements(pypi.as_bytes(), &bindings(Ecosystem::Pypi, "pypi"))
            .expect("PyPI plan"),
    ];
    for plan in &plans {
        assert_closed_two_node_topology(plan);
        assert_eq!(
            plan.nodes
                .iter()
                .map(|node| node.declared_size)
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from([7, 11])
        );
        assert_eq!(
            plan.nodes
                .iter()
                .map(|node| node.sha256.as_str())
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from([app_digest.as_str(), library_digest.as_str()])
        );
    }
    assert_ne!(plans[0].graph_sha256, plans[1].graph_sha256);
    assert_ne!(plans[1].graph_sha256, plans[2].graph_sha256);
}

#[test]
fn a_later_exact_version_requires_a_new_lock_node_and_graph() {
    let original = format!(
        r#"{{"schema_version":"mcloving.maven-lock/v1","nodes":[{{"key":"app","group":"com.example","artifact":"app","artifact_type":"jar","classifier":null,"version":"1.0.0","repository_id":"maven","artifact_path":"com/example/app/1.0.0/app.jar","declared_size":11,"sha256":"{}","attestation_key_id":"maven-key","dependencies":[]}}],"roots":["app"]}}"#,
        "d".repeat(64)
    );
    let later = original.replace("1.0.0", "1.1.0");
    let bindings = bindings(Ecosystem::Maven, "maven");
    let original = parse_maven_lock(original.as_bytes(), &bindings).expect("original exact lock");
    let later = parse_maven_lock(later.as_bytes(), &bindings).expect("later exact lock");
    assert_ne!(original.lock_sha256, later.lock_sha256);
    assert_ne!(original.nodes[0].node_id, later.nodes[0].node_id);
    assert_ne!(original.graph_sha256, later.graph_sha256);
    assert_eq!(later.nodes[0].exact_version, "1.1.0");
}

fn assert_closed_two_node_topology(plan: &CanonicalPlan) {
    assert_eq!(plan.nodes.len(), 2);
    assert_eq!(plan.roots.len(), 1);
    let root = plan
        .nodes
        .iter()
        .find(|node| node.node_id == plan.roots[0])
        .expect("root node");
    assert_eq!(root.dependencies.len(), 1);
    let leaf = plan
        .nodes
        .iter()
        .find(|node| node.node_id == root.dependencies[0])
        .expect("leaf node");
    assert!(leaf.dependencies.is_empty());
    assert!(root.coordinate.contains("app"));
    assert!(leaf.coordinate.contains("library"));
}
