use std::collections::BTreeMap;

use mcloving_controller_store::{
    DagContractErrorCode, DagDependency, DagNodeKind, DependencyCondition, NewDagBuild, NewDagNode,
    compile_matrix, validate_dag_contract,
};
use serde_json::json;
use uuid::Uuid;

#[test]
fn matrix_order_is_presentation_independent_and_bounded() {
    let first = compile_matrix(
        "test",
        &BTreeMap::from([
            (
                "os".to_owned(),
                vec!["windows".to_owned(), "linux".to_owned()],
            ),
            (
                "arch".to_owned(),
                vec!["x64".to_owned(), "arm64".to_owned()],
            ),
        ]),
    )
    .unwrap();
    let second = compile_matrix(
        "test",
        &BTreeMap::from([
            (
                "arch".to_owned(),
                vec!["arm64".to_owned(), "x64".to_owned()],
            ),
            (
                "os".to_owned(),
                vec!["linux".to_owned(), "windows".to_owned()],
            ),
        ]),
    )
    .unwrap();
    assert_eq!(first, second);
    assert_eq!(
        first
            .iter()
            .map(|cell| cell.node_key.as_str())
            .collect::<Vec<_>>(),
        [
            "test[arch=arm64,os=linux]",
            "test[arch=arm64,os=windows]",
            "test[arch=x64,os=linux]",
            "test[arch=x64,os=windows]",
        ]
    );

    let matrix_node = NewDagNode {
        node_key: first[0].node_key.clone(),
        kind: DagNodeKind::Work,
        dependencies: Vec::new(),
        required_capabilities: vec!["shell".to_owned()],
        required_platform: "linux".to_owned(),
        required_trust_pool: "trusted".to_owned(),
        priority: 0,
        execution_spec: json!({"program": "true"}),
        fail_fast: false,
        max_attempts: 1,
    };
    assert!(
        validate_dag_contract(&NewDagBuild {
            organization_id: Uuid::nil(),
            project_id: Uuid::nil(),
            idempotency_key: "matrix-contract".to_owned(),
            pipeline_digest: [1; 32],
            priority: 1,
            nodes: vec![matrix_node],
        })
        .is_ok()
    );

    let oversized_value = "x".repeat(250);
    let oversized = compile_matrix(
        "test",
        &BTreeMap::from([("axis".to_owned(), vec![oversized_value])]),
    )
    .unwrap_err();
    assert_eq!(oversized.code, DagContractErrorCode::InvalidText);

    let too_large = compile_matrix(
        "test",
        &BTreeMap::from([
            (
                "a".to_owned(),
                (0..17).map(|value| format!("a{value}")).collect(),
            ),
            (
                "b".to_owned(),
                (0..17).map(|value| format!("b{value}")).collect(),
            ),
        ]),
    )
    .unwrap_err();
    assert_eq!(too_large.code, DagContractErrorCode::MatrixCellLimit);
}

#[test]
fn invalid_matrix_values_fail_closed() {
    let duplicate = compile_matrix(
        "test",
        &BTreeMap::from([(
            "os".to_owned(),
            vec!["linux".to_owned(), "linux".to_owned()],
        )]),
    )
    .unwrap_err();
    assert_eq!(duplicate.code, DagContractErrorCode::DuplicateMatrixValue);
    let empty = compile_matrix("test", &BTreeMap::new()).unwrap_err();
    assert_eq!(empty.code, DagContractErrorCode::MatrixAxisLimit);
}

#[test]
fn dag_public_types_preserve_explicit_semantics() {
    let build = NewDagBuild {
        organization_id: Uuid::nil(),
        project_id: Uuid::nil(),
        idempotency_key: "contract".to_owned(),
        pipeline_digest: [1; 32],
        priority: 1,
        nodes: vec![NewDagNode {
            node_key: "post".to_owned(),
            kind: DagNodeKind::Post,
            dependencies: vec![DagDependency {
                node_key: "work".to_owned(),
                condition: DependencyCondition::Completed,
            }],
            required_capabilities: vec!["shell".to_owned()],
            required_platform: "linux".to_owned(),
            required_trust_pool: "trusted".to_owned(),
            priority: 0,
            execution_spec: json!({"program": "true"}),
            fail_fast: false,
            max_attempts: 1,
        }],
    };
    assert_eq!(build.nodes[0].kind, DagNodeKind::Post);
    assert_eq!(
        build.nodes[0].dependencies[0].condition,
        DependencyCondition::Completed
    );
}

#[test]
fn capabilities_are_canonical_and_bounded() {
    let node = |required_capabilities: Vec<String>| NewDagNode {
        node_key: "work".to_owned(),
        kind: DagNodeKind::Work,
        dependencies: Vec::new(),
        required_capabilities,
        required_platform: "linux".to_owned(),
        required_trust_pool: "trusted".to_owned(),
        priority: 0,
        execution_spec: json!({"program": "true"}),
        fail_fast: false,
        max_attempts: 1,
    };
    let build = |node| NewDagBuild {
        organization_id: Uuid::nil(),
        project_id: Uuid::nil(),
        idempotency_key: "capability-contract".to_owned(),
        pipeline_digest: [1; 32],
        priority: 1,
        nodes: vec![node],
    };

    let duplicate =
        validate_dag_contract(&build(node(vec!["shell".to_owned(), "shell".to_owned()])))
            .unwrap_err();
    assert_eq!(duplicate.code, DagContractErrorCode::DuplicateCapability);

    let too_many = validate_dag_contract(&build(node(
        (0..65).map(|value| format!("capability-{value}")).collect(),
    )))
    .unwrap_err();
    assert_eq!(too_many.code, DagContractErrorCode::CapabilityLimit);

    let invalid =
        validate_dag_contract(&build(node(vec!["bad capability".to_owned()]))).unwrap_err();
    assert_eq!(invalid.code, DagContractErrorCode::InvalidText);
}
