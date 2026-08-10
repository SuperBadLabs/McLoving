use mcloving_dependency_resolver::{
    AdapterBindings, RepositoryBinding, SourceTrustClass, parse_maven_lock, validate_plan,
};

fn bindings() -> AdapterBindings {
    AdapterBindings {
        adapter_id: "maven-lock-v1".to_owned(),
        adapter_sha256: "a".repeat(64),
        source_tree_sha256: "b".repeat(64),
        resolver_toolchain_id: "maven-exporter-1".to_owned(),
        resolver_toolchain_sha256: "c".repeat(64),
        source_trust_class: SourceTrustClass::Trusted,
        repositories: vec![RepositoryBinding {
            repository_id: "contained-maven".to_owned(),
            credentialed: true,
            permits_untrusted_source: false,
        }],
    }
}

fn valid_lock() -> String {
    format!(
        r#"{{
          "schema_version":"mcloving.maven-lock/v1",
          "nodes":[
            {{
              "key":"app",
              "group":"com.example",
              "artifact":"app",
              "artifact_type":"jar",
              "classifier":null,
              "version":"1.0.0",
              "repository_id":"contained-maven",
              "artifact_path":"com/example/app/1.0.0/app-1.0.0.jar",
              "declared_size":12,
              "sha256":"{}",
              "attestation_key_id":"contained-key-1",
              "dependencies":["library"]
            }},
            {{
              "key":"library",
              "group":"org.example",
              "artifact":"library",
              "artifact_type":"jar",
              "classifier":null,
              "version":"2.4.1",
              "repository_id":"contained-maven",
              "artifact_path":"org/example/library/2.4.1/library-2.4.1.jar",
              "declared_size":9,
              "sha256":"{}",
              "attestation_key_id":"contained-key-1",
              "dependencies":[]
            }}
          ],
          "roots":["app"]
        }}"#,
        "d".repeat(64),
        "e".repeat(64)
    )
}

#[test]
fn strict_maven_lock_becomes_a_complete_canonical_plan() {
    let bytes = valid_lock();
    let plan = parse_maven_lock(bytes.as_bytes(), &bindings()).expect("valid Maven lock");

    assert_eq!(plan.nodes.len(), 2);
    assert_eq!(plan.roots.len(), 1);
    assert_eq!(
        plan.nodes
            .iter()
            .map(|node| node.dependencies.len())
            .sum::<usize>(),
        1
    );
    assert!(plan.nodes[0].node_id < plan.nodes[1].node_id);
    validate_plan(&plan).expect("adapter output remains canonical");
}

#[test]
fn duplicate_and_unknown_json_members_are_denied() {
    let duplicate = valid_lock().replacen(
        r#""schema_version":"mcloving.maven-lock/v1""#,
        r#""schema_version":"mcloving.maven-lock/v1","schema_version":"mcloving.maven-lock/v1""#,
        1,
    );
    let error = parse_maven_lock(duplicate.as_bytes(), &bindings()).expect_err("duplicate field");
    assert_eq!(error.code, "DEP_MAVEN_LOCK_INVALID");

    let unknown = valid_lock().replacen(r#""key":"app""#, r#""key":"app","surprise":true"#, 1);
    let error = parse_maven_lock(unknown.as_bytes(), &bindings()).expect_err("unknown field");
    assert_eq!(error.code, "DEP_MAVEN_LOCK_INVALID");
}

#[test]
fn snapshots_missing_edges_and_traversal_fail_closed() {
    let snapshot = valid_lock().replacen(r#""version":"1.0.0""#, r#""version":"1.0-SNAPSHOT""#, 1);
    let error = parse_maven_lock(snapshot.as_bytes(), &bindings()).expect_err("snapshot");
    assert_eq!(error.code, "DEP_VERSION_MUTABLE");

    let missing = valid_lock().replacen(
        r#""dependencies":["library"]"#,
        r#""dependencies":["missing"]"#,
        1,
    );
    let error = parse_maven_lock(missing.as_bytes(), &bindings()).expect_err("missing node");
    assert_eq!(error.code, "DEP_MAVEN_GRAPH_NODE_MISSING");

    let traversal =
        valid_lock().replacen("com/example/app/1.0.0/app-1.0.0.jar", "../app-1.0.0.jar", 1);
    let error = parse_maven_lock(traversal.as_bytes(), &bindings()).expect_err("traversal");
    assert_eq!(error.code, "DEP_ARTIFACT_PATH_INVALID");

    let placeholder =
        valid_lock().replacen(r#""version":"1.0.0""#, r#""version":"${revision}""#, 1);
    let error = parse_maven_lock(placeholder.as_bytes(), &bindings()).expect_err("placeholder");
    assert_eq!(error.code, "DEP_VERSION_MUTABLE");
}

#[test]
fn mutable_graph_order_and_untrusted_private_access_are_denied() {
    let noncanonical = valid_lock().replacen(
        r#""dependencies":["library"]"#,
        r#""dependencies":["library","library"]"#,
        1,
    );
    let error = parse_maven_lock(noncanonical.as_bytes(), &bindings()).expect_err("duplicate edge");
    assert_eq!(error.code, "DEP_MAVEN_GRAPH_NONCANONICAL");

    let mut untrusted = bindings();
    untrusted.source_trust_class = SourceTrustClass::Untrusted;
    let error = parse_maven_lock(valid_lock().as_bytes(), &untrusted).expect_err("private repo");
    assert_eq!(error.code, "DEP_UNTRUSTED_REPOSITORY_DENIED");
}
