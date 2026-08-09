use mcloving_dependency_resolver::{
    CanonicalPlan, Ecosystem, PackageNode, RepositoryBinding, SourceTrustClass,
    canonical_graph_sha256, canonical_node_id, validate_plan,
};

fn digest(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

fn node(coordinate: &str, version: &str, path: &str, dependencies: Vec<String>) -> PackageNode {
    let mut node = PackageNode {
        node_id: digest('0'),
        coordinate: coordinate.to_owned(),
        exact_version: version.to_owned(),
        repository_id: "central".to_owned(),
        artifact_path: path.to_owned(),
        declared_size: 128,
        sha256: digest('a'),
        attestation_key_id: Some("central-ed25519-v1".to_owned()),
        dependencies,
    };
    node.node_id = canonical_node_id(Ecosystem::Maven, &node).expect("node id");
    node
}

fn valid_plan() -> CanonicalPlan {
    let leaf = node(
        "org.example:leaf",
        "1.2.3",
        "org/example/leaf/1.2.3/leaf.jar",
        vec![],
    );
    let root = node(
        "org.example:root",
        "2.0.0",
        "org/example/root/2.0.0/root.jar",
        vec![leaf.node_id.clone()],
    );
    let mut nodes = vec![root, leaf];
    nodes.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    let roots = vec![
        nodes
            .iter()
            .find(|entry| entry.coordinate.ends_with(":root"))
            .expect("root")
            .node_id
            .clone(),
    ];
    let mut plan = CanonicalPlan {
        schema_version: "mcloving.dependency-plan/v1".to_owned(),
        ecosystem: Ecosystem::Maven,
        adapter_id: "mcloving.maven-lock/v1".to_owned(),
        adapter_sha256: digest('1'),
        source_tree_sha256: digest('2'),
        lock_sha256: digest('3'),
        resolver_toolchain_id: "mcloving-resolver-rust-1.97.1".to_owned(),
        resolver_toolchain_sha256: digest('4'),
        source_trust_class: SourceTrustClass::Trusted,
        repositories: vec![RepositoryBinding {
            repository_id: "central".to_owned(),
            credentialed: false,
            permits_untrusted_source: true,
        }],
        nodes,
        roots,
        graph_sha256: digest('0'),
    };
    plan.graph_sha256 = canonical_graph_sha256(&plan).expect("graph digest");
    plan
}

#[test]
fn exact_sorted_complete_graph_is_admitted() {
    validate_plan(&valid_plan()).expect("valid canonical plan");
}

#[test]
fn graph_digest_binds_edges_and_roots() {
    let mut plan = valid_plan();
    let alternate_root = plan
        .nodes
        .iter()
        .find(|node| node.dependencies.is_empty())
        .expect("leaf")
        .node_id
        .clone();
    plan.roots = vec![alternate_root];
    assert_eq!(
        validate_plan(&plan)
            .expect_err("stale digest must fail")
            .code,
        "DEP_GRAPH_UNREACHABLE_NODE"
    );

    let mut plan = valid_plan();
    plan.graph_sha256 = digest('f');
    assert_eq!(
        validate_plan(&plan)
            .expect_err("wrong graph digest must fail")
            .code,
        "DEP_GRAPH_DIGEST_MISMATCH"
    );
}

#[test]
fn mutable_or_traversing_nodes_are_denied() {
    let mut plan = valid_plan();
    plan.nodes[0].exact_version = "[1.0,2.0)".to_owned();
    assert_eq!(
        validate_plan(&plan).expect_err("range must fail").code,
        "DEP_VERSION_MUTABLE"
    );

    let mut plan = valid_plan();
    plan.nodes[0].artifact_path = "../outside.jar".to_owned();
    assert_eq!(
        validate_plan(&plan).expect_err("traversal must fail").code,
        "DEP_ARTIFACT_PATH_INVALID"
    );
}

#[test]
fn node_identity_detects_package_substitution() {
    let mut plan = valid_plan();
    plan.nodes[0].coordinate.push_str("-substituted");
    assert_eq!(
        validate_plan(&plan)
            .expect_err("coordinate substitution must fail")
            .code,
        "DEP_NODE_ID_MISMATCH"
    );
}

#[test]
fn cycles_and_unreachable_nodes_are_denied() {
    let mut plan = valid_plan();
    let first = plan.nodes[0].node_id.clone();
    let second = plan.nodes[1].node_id.clone();
    plan.nodes[0].dependencies = vec![second.clone()];
    plan.nodes[1].dependencies = vec![first];
    assert_eq!(
        validate_plan(&plan).expect_err("cycle must fail").code,
        "DEP_GRAPH_CYCLE"
    );

    let mut plan = valid_plan();
    let leaf = plan
        .nodes
        .iter_mut()
        .find(|node| node.dependencies.is_empty())
        .expect("leaf");
    leaf.coordinate = "org.example:orphan".to_owned();
    leaf.node_id = canonical_node_id(Ecosystem::Maven, leaf).expect("orphan id");
    plan.nodes
        .sort_by(|left, right| left.node_id.cmp(&right.node_id));
    assert_eq!(
        validate_plan(&plan).expect_err("orphan must fail").code,
        "DEP_GRAPH_NODE_MISSING"
    );
}

#[test]
fn untrusted_source_cannot_use_credentials() {
    let mut plan = valid_plan();
    plan.source_trust_class = SourceTrustClass::Untrusted;
    plan.repositories[0].credentialed = true;
    plan.repositories[0].permits_untrusted_source = false;
    assert_eq!(
        validate_plan(&plan)
            .expect_err("untrusted private repository must fail")
            .code,
        "DEP_UNTRUSTED_REPOSITORY_DENIED"
    );
}

#[test]
fn canonical_order_is_enforced() {
    let mut plan = valid_plan();
    plan.nodes.reverse();
    assert_eq!(
        validate_plan(&plan).expect_err("node order must fail").code,
        "DEP_NODES_NONCANONICAL"
    );

    let mut plan = valid_plan();
    let duplicate = plan.roots[0].clone();
    plan.roots.push(duplicate);
    assert_eq!(
        validate_plan(&plan)
            .expect_err("duplicate root must fail")
            .code,
        "DEP_GRAPH_NONCANONICAL"
    );
}

#[test]
fn one_coordinate_cannot_select_multiple_versions_or_repositories() {
    let mut plan = valid_plan();
    let mut conflict = node(
        "org.example:leaf",
        "9.9.9",
        "org/example/leaf/9.9.9/leaf.jar",
        vec![],
    );
    conflict.sha256 = digest('b');
    conflict.node_id = canonical_node_id(Ecosystem::Maven, &conflict).expect("conflict id");
    plan.nodes.push(conflict);
    plan.nodes
        .sort_by(|left, right| left.node_id.cmp(&right.node_id));

    assert_eq!(
        validate_plan(&plan)
            .expect_err("coordinate conflict must fail")
            .code,
        "DEP_COORDINATE_CONFLICT"
    );
}
