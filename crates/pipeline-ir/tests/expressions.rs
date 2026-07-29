use std::collections::BTreeMap;

use mcloving_pipeline_ir::{
    EvaluatedValue, ExpressionErrorCode, ExpressionLimits, IR_V1_1, ParameterValue, ParseLimits,
    compile_strict_yaml, compile_strict_yaml_with_parameters, evaluate_expression,
    parse_expression, validate_canonical_bytes,
};
use proptest::prelude::*;

const PARAMETER_PIPELINE: &str = r#"
version: 1
name: parameterized
parameters:
  tool:
    type: string
    default: cargo
  target:
    type: string
    default: linux
  retries:
    type: integer
    default: 2
  enabled:
    type: boolean
    default: true
stages:
  - id: test
    name: Test
    steps:
      - process:
          program:
            expression: parameters.tool
          args:
            - test
            - expression: parameters.target + "-release"
          env:
            TARGET:
              expression: parameters.target
"#;

#[test]
fn expression_precedence_and_types_are_deterministic() {
    let expression =
        parse_expression("1 + 2 == 3 && !false || false", ExpressionLimits::default()).unwrap();
    let result =
        evaluate_expression(&expression, &BTreeMap::new(), ExpressionLimits::default()).unwrap();
    assert_eq!(result.value, ParameterValue::Bool(true));
    assert!(!result.secret);

    let string = parse_expression(r#""mc" + "loving""#, ExpressionLimits::default()).unwrap();
    assert_eq!(
        evaluate_expression(&string, &BTreeMap::new(), ExpressionLimits::default())
            .unwrap()
            .value,
        ParameterValue::String("mcloving".to_owned())
    );
}

#[test]
fn only_explicit_contexts_and_matching_types_are_accepted() {
    let error = parse_expression("github.ref", ExpressionLimits::default()).unwrap_err();
    assert_eq!(error.code, ExpressionErrorCode::UnknownContext);

    let expression = parse_expression("true + 1", ExpressionLimits::default()).unwrap();
    let error = evaluate_expression(&expression, &BTreeMap::new(), ExpressionLimits::default())
        .unwrap_err();
    assert_eq!(error.code, ExpressionErrorCode::TypeMismatch);

    let expression =
        parse_expression("9223372036854775807 + 1", ExpressionLimits::default()).unwrap();
    let error = evaluate_expression(&expression, &BTreeMap::new(), ExpressionLimits::default())
        .unwrap_err();
    assert_eq!(error.code, ExpressionErrorCode::IntegerOverflow);
}

#[test]
fn secret_taint_propagates_without_materializing_the_value() {
    let expression = parse_expression(
        r#"parameters.token == "expected""#,
        ExpressionLimits::default(),
    )
    .unwrap();
    let context = BTreeMap::from([(
        "token".to_owned(),
        EvaluatedValue {
            value: ParameterValue::String("expected".to_owned()),
            secret: true,
        },
    )]);
    let result = evaluate_expression(&expression, &context, ExpressionLimits::default()).unwrap();
    assert_eq!(result.value, ParameterValue::Bool(true));
    assert!(result.secret);
}

#[test]
fn parser_and_evaluator_enforce_independent_resource_limits() {
    let error = parse_expression(
        r#""12345""#,
        ExpressionLimits {
            max_string_bytes: 4,
            ..ExpressionLimits::default()
        },
    )
    .unwrap_err();
    assert_eq!(error.code, ExpressionErrorCode::StringLimit);

    let expression = parse_expression("true && true", ExpressionLimits::default()).unwrap();
    let error = evaluate_expression(
        &expression,
        &BTreeMap::new(),
        ExpressionLimits {
            max_operations: 0,
            ..ExpressionLimits::default()
        },
    )
    .unwrap_err();
    assert_eq!(error.code, ExpressionErrorCode::OperationLimit);

    let deeply_nested = format!("{}true", "!".repeat(64));
    let error = parse_expression(
        &deeply_nested,
        ExpressionLimits {
            max_depth: 8,
            ..ExpressionLimits::default()
        },
    )
    .unwrap_err();
    assert_eq!(error.code, ExpressionErrorCode::DepthLimit);
}

#[test]
fn typed_parameters_resolve_into_canonical_pipeline_ir_v1_1() {
    let pipeline = compile_strict_yaml(
        "fixture://parameters",
        PARAMETER_PIPELINE,
        ParseLimits::default(),
    )
    .unwrap();
    assert_eq!(pipeline.schema, IR_V1_1);
    assert_eq!(pipeline.parameters.len(), 4);
    assert_eq!(pipeline.parameter_values.len(), 4);
    assert_eq!(pipeline.expressions.len(), 3);

    let process = pipeline.stages[0].steps[0].clone().into_process();
    assert_eq!(process.program, "cargo");
    assert_eq!(process.args, ["test", "linux-release"]);
    assert_eq!(process.env["TARGET"], "linux");

    let summary = validate_canonical_bytes(&pipeline.canonical_bytes().unwrap()).unwrap();
    assert_eq!(summary.schema, IR_V1_1);
    assert_eq!(summary.parameters, 4);
    assert_eq!(summary.expressions, 3);
}

#[test]
fn explicit_inputs_are_typed_and_change_the_semantic_digest() {
    let defaults = compile_strict_yaml(
        "fixture://defaults",
        PARAMETER_PIPELINE,
        ParseLimits::default(),
    )
    .unwrap();
    let overridden = compile_strict_yaml_with_parameters(
        "fixture://override",
        PARAMETER_PIPELINE,
        ParseLimits::default(),
        BTreeMap::from([(
            "target".to_owned(),
            ParameterValue::String("windows".to_owned()),
        )]),
    )
    .unwrap();
    assert_ne!(
        defaults.semantic_digest().unwrap(),
        overridden.semantic_digest().unwrap()
    );

    let error = compile_strict_yaml_with_parameters(
        "fixture://wrong-type",
        PARAMETER_PIPELINE,
        ParseLimits::default(),
        BTreeMap::from([("target".to_owned(), ParameterValue::Bool(true))]),
    )
    .unwrap_err();
    assert!(error.message.contains("expected a string value"));
}

#[test]
fn secret_inputs_are_never_persisted_or_materialized() {
    let source = r#"
version: 1
name: secret
parameters:
  token:
    type: string
    secret: true
stages:
  - id: test
    name: Test
    steps:
      - process:
          program:
            expression: parameters.token
"#;
    let error = compile_strict_yaml_with_parameters(
        "fixture://secret",
        source,
        ParseLimits::default(),
        BTreeMap::from([(
            "token".to_owned(),
            ParameterValue::String("marker-secret".to_owned()),
        )]),
    )
    .unwrap_err();
    assert!(error.message.contains("secret-tainted"));
    assert!(!format!("{error:?}").contains("marker-secret"));

    let unused_source = source.replace(
        "          program:\n            expression: parameters.token",
        "          program: echo",
    );
    let pipeline = compile_strict_yaml_with_parameters(
        "fixture://unused-secret",
        &unused_source,
        ParseLimits::default(),
        BTreeMap::from([(
            "token".to_owned(),
            ParameterValue::String("marker-secret".to_owned()),
        )]),
    )
    .unwrap();
    let canonical = pipeline.canonical_bytes().unwrap();
    assert!(
        !canonical
            .windows(b"marker-secret".len())
            .any(|window| window == b"marker-secret")
    );
}

proptest! {
    #[test]
    fn arbitrary_expression_text_never_panics(source in ".{0,512}") {
        let _ = parse_expression(&source, ExpressionLimits::default());
    }
}

trait ProcessStepExt {
    fn into_process(self) -> mcloving_pipeline_ir::ProcessStep;
}

impl ProcessStepExt for mcloving_pipeline_ir::Step {
    fn into_process(self) -> mcloving_pipeline_ir::ProcessStep {
        match self {
            Self::Process(process) => process,
        }
    }
}
