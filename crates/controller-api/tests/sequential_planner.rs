use mcloving_controller_api::sequential::{SequentialBuildBinding, plan_sequential_build};
use mcloving_controller_store::SequentialDagBuild;
use mcloving_pipeline_ir::{
    IR_V1_8, ParseLimits, PipelineIr, ProcessMode, Step, compile_strict_yaml, validate_pipeline,
};
use serde_json::json;
use uuid::Uuid;

fn binding() -> SequentialBuildBinding {
    SequentialBuildBinding {
        organization_id: Uuid::new_v4(),
        project_id: Uuid::new_v4(),
        pipeline_id: Uuid::new_v4(),
        pipeline_revision: 1,
        pipeline_operational_generation: 1,
        idempotency_key: "sequential-planner".to_owned(),
    }
}

fn pipeline(stages: usize, steps: usize, script: &str) -> PipelineIr {
    let source =
        json!({"version": 1, "name": "sequential", "stages": (0..stages).map(|index| json!({
        "id": format!("s{index}"), "name": format!("S{index}"), "steps": (0..steps).map(|_| json!({
            "process": {"program": "/bin/sh", "args": ["-xe", "-c", script]}
        })).collect::<Vec<_>>()
    })).collect::<Vec<_>>()})
        .to_string();
    compile_strict_yaml("test:saved-sequential", &source, ParseLimits::default()).unwrap()
}

#[test]
fn steps_preserve_literals_order_frozen_digest_and_utf8_labels() {
    let mut ir = pipeline(
        2,
        2,
        "printf '%s\\n' 'quoted $literal'\nprintf 'second line\\n'",
    );
    ir.stages[0].name = "Büild 🚀".to_owned();
    ir.stages[0].id = "b-ild".to_owned();
    let plan = plan_sequential_build(&ir, binding()).unwrap();
    assert_eq!(plan.dag().pipeline_digest, ir.semantic_digest().unwrap());
    assert_eq!(plan.layout().len(), 4);
    assert_eq!(plan.layout()[0].stage_name, "Büild 🚀");
    assert_eq!(plan.layout()[1].step_ordinal, 2);
    assert_eq!(plan.layout()[2].stage_ordinal, 2);
    assert_eq!(
        plan.dag().nodes[2].dependencies[0].node_key,
        "b-ild[step=02]"
    );
    for (index, node) in plan.dag().nodes.iter().enumerate() {
        assert_eq!(node.execution_spec["steps"].as_array().unwrap().len(), 1);
        assert_eq!(
            node.execution_spec["steps"][0]["args"][2],
            "printf '%s\\n' 'quoted $literal'\nprintf 'second line\\n'"
        );
        assert_eq!(plan.layout()[index].execution_ordinal, index + 1);
        assert!(!node.fail_fast);
        assert_eq!(node.max_attempts, 1);
    }
}

/// PAR-011, from review. The sequential planner lowers steps to version-1
/// host processes; a stage that requested an image would otherwise run
/// uncontained under the agent account.
#[test]
fn container_stages_are_refused_rather_than_lowered_to_host_processes() {
    let mut ir = pipeline(1, 1, ":");
    ir.stages[0].image = Some(
        "docker.io/library/alpine@sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e"
            .to_owned(),
    );
    let error = plan_sequential_build(&ir, binding()).unwrap_err();
    assert!(
        error.to_string().contains("container stages"),
        "unexpected refusal: {error}"
    );
}

fn artifact_pipeline(artifact_stage: Option<usize>, container_stage: Option<usize>) -> PipelineIr {
    let mut source = json!({"version": 1, "name": "sequential-artifacts", "stages": [
        {"id": "prepare", "name": "Prepare", "steps": [
            {"process": {"program": "/bin/sh", "args": ["-xe", "-c", "printf prepare"]}}
        ]},
        {"id": "publish", "name": "Publish", "steps": [
            {"process": {"program": "/bin/sh", "args": ["-xe", "-c", "printf publish"]}},
            {"process": {"program": "/bin/sh", "args": ["-xe", "-c", "printf done"]}}
        ]}
    ]});
    if let Some(index) = artifact_stage {
        source["stages"][index]["artifacts"] = json!([
            {"name": "reports", "paths": ["out/**/*.xml"]}
        ]);
    }
    if let Some(index) = container_stage {
        source["stages"][index]["image"] = json!(
            "docker.io/library/alpine@sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e"
        );
    }
    let ir = compile_strict_yaml(
        "test:saved-sequential-artifacts",
        &source.to_string(),
        ParseLimits::default(),
    )
    .unwrap();
    validate_pipeline(&ir).unwrap();
    if artifact_stage.is_some() {
        assert_eq!(ir.schema, IR_V1_8);
    }
    ir
}

fn assert_artifact_stage_refused(stage_index: usize, stage_id: &str) {
    // The same valid pipeline without declarations still preserves every step
    // and its saved semantic digest. A blanket sequential refusal fails here.
    let plain = artifact_pipeline(None, None);
    let plan = plan_sequential_build(&plain, binding()).unwrap();
    assert_eq!(plan.dag().pipeline_digest, plain.semantic_digest().unwrap());
    assert_eq!(plan.layout().len(), 3);
    assert_eq!(plan.layout()[0].stage_id, "prepare");
    assert_eq!(plan.layout()[1].stage_id, "publish");
    assert_eq!(plan.layout()[2].step_ordinal, 2);

    // Compilation and validation above establish that refusal belongs to the
    // shipped planner, rather than an invalid artifact declaration or old IR.
    let ir = artifact_pipeline(Some(stage_index), None);
    assert_artifact_refusal(&ir, stage_id);
}

fn assert_artifact_refusal(ir: &PipelineIr, stage_id: &str) {
    let error = plan_sequential_build(ir, binding()).unwrap_err();
    assert!(
        matches!(error, mcloving_controller_store::StoreError::InvalidDag(_)),
        "unexpected refusal kind: {error}"
    );
    let diagnostic = error.to_string();
    assert!(diagnostic.contains("artifact"), "{diagnostic}");
    assert!(diagnostic.contains(stage_id), "{diagnostic}");
}

#[test]
fn first_artifact_stage_is_refused_by_name() {
    assert_artifact_stage_refused(0, "prepare");
}

#[test]
fn later_artifact_stage_is_refused_without_returning_a_partial_plan() {
    assert_artifact_stage_refused(1, "publish");
}

#[test]
fn container_and_artifact_stage_is_refused_with_the_artifact_stage_name() {
    let ir = artifact_pipeline(Some(1), Some(1));
    assert_artifact_refusal(&ir, "publish");
}

#[test]
fn stage_step_and_script_bounds_are_exact() {
    assert!(plan_sequential_build(&pipeline(32, 2, ":"), binding()).is_ok());
    assert!(plan_sequential_build(&pipeline(33, 1, ":"), binding()).is_err());
    assert!(plan_sequential_build(&pipeline(1, 65, ":"), binding()).is_err());
    assert!(plan_sequential_build(&pipeline(1, 1, &"x".repeat(4096)), binding()).is_ok());
    assert!(plan_sequential_build(&pipeline(1, 1, &"x".repeat(4097)), binding()).is_err());
    assert!(plan_sequential_build(&pipeline(2, 1, &"x".repeat(2048)), binding()).is_ok());
    assert!(plan_sequential_build(&pipeline(2, 1, &"x".repeat(2049)), binding()).is_err());
    let mut ir = pipeline(1, 1, ":");
    ir.stages[0].name = "x".repeat(96);
    ir.stages[0].id = "x".repeat(96);
    assert!(plan_sequential_build(&ir, binding()).is_ok());
    ir.stages[0].name.push('x');
    ir.stages[0].id.push('x');
    assert!(plan_sequential_build(&ir, binding()).is_err());
}

#[test]
fn unsupported_process_and_parameter_shapes_are_refused() {
    let original = pipeline(1, 1, ":");
    for mutation in 0..9 {
        let mut ir = original.clone();
        let Step::Process(process) = &mut ir.stages[0].steps[0] else {
            unreachable!()
        };
        match mutation {
            0 => process.program = "/bin/bash".to_owned(),
            1 => process.mode = ProcessMode::WindowsCmd,
            2 => {
                process.args.remove(0);
            }
            3 => {
                process.env.insert("EXTRA".to_owned(), "value".to_owned());
            }
            4 => {
                process.timeout_seconds = Some(1);
            }
            5 => {
                process.args[2] = "#! /bin/sh\ntrue".to_owned();
            }
            6 => {
                process.args[2].push('\0');
            }
            7 => {
                process.args[2].clear();
            }
            _ => {
                ir.parameter_values.insert(
                    "x".to_owned(),
                    mcloving_pipeline_ir::ParameterValue::String("value".to_owned()),
                );
            }
        };
        assert!(
            plan_sequential_build(&ir, binding()).is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn independent_store_constructor_rejects_forged_layout_and_policy() {
    let original = plan_sequential_build(&pipeline(2, 2, ":"), binding()).unwrap();
    for mutation in 0..17 {
        let mut dag = original.dag().clone();
        let mut layout = original.layout().to_vec();
        match mutation {
            0 => layout[0].execution_ordinal = 2,
            1 => layout[1].stage_ordinal = 2,
            2 => layout[1].step_ordinal = 3,
            3 => layout[1].stage_name = "changed".to_owned(),
            4 => layout[1].node_key = layout[0].node_key.clone(),
            5 => layout[0].stage_id = "substituted".to_owned(),
            6 => dag.nodes[1].dependencies.clear(),
            7 => {
                dag.nodes[1].dependencies[0].condition =
                    mcloving_controller_store::DependencyCondition::Completed
            }
            8 => dag.nodes[0].fail_fast = true,
            9 => dag.nodes[0].max_attempts = 2,
            10 => dag.nodes[0].required_trust_pool = "production".to_owned(),
            11 => dag.nodes[0]
                .required_capabilities
                .push("credential".to_owned()),
            12 => dag.nodes[0].execution_spec["steps"][0]["extra"] = json!(true),
            13 => dag.priority = 1,
            14 => dag.pipeline_operational_generation = 0,
            15 => {
                dag.notify_targets = json!([{
                    "kind": "webhook",
                    "mapping_id": "hooks.team",
                    "destination_url": "https://hooks.example.test/x"
                }])
            }
            _ => {
                layout.pop();
            }
        }
        assert!(
            SequentialDagBuild::new(dag, layout).is_err(),
            "mutation {mutation}"
        );
    }
    let mut dag = original.dag().clone();
    dag.nodes.reverse();
    let mut layout = original.layout().to_vec();
    layout.reverse();
    let canonical = SequentialDagBuild::new(dag, layout).unwrap();
    assert_eq!(canonical.layout(), original.layout());
}

#[test]
fn normalized_stage_collisions_and_empty_stages_are_refused() {
    let mut ir = pipeline(2, 1, ":");
    ir.stages[1].name = ir.stages[0].name.clone();
    assert!(plan_sequential_build(&ir, binding()).is_err());
    ir.stages[1].steps.clear();
    assert!(plan_sequential_build(&ir, binding()).is_err());
}

#[test]
fn input_capture_does_not_claim_literal_process_migration_semantics() {
    let source = format!(
        "version: 1\nname: input\nstages:\n  - id: input\n    name: Input\n    steps:\n      - input_intent:\n          mapping_id: fixture\n          mapping_digest: sha256:{}\n          timeout_seconds: 30\n",
        "a".repeat(64)
    );
    let ir = mcloving_pipeline_ir::compile_strict_yaml(
        "fixture",
        &source,
        mcloving_pipeline_ir::ParseLimits::default(),
    )
    .unwrap();
    assert!(plan_sequential_build(&ir, binding()).is_err());
}
