//! Authority-free contained planner. Public pipeline admission keeps its existing guard.

use mcloving_controller_store::{
    DagDependency, DagNodeKind, DependencyCondition, NewDagBuild, NewDagNode, SequentialDagBuild,
    SequentialStepLayout, StoreError,
};
use mcloving_pipeline_ir::{PipelineIr, ProcessMode, Step, validate_pipeline};
use uuid::Uuid;

/// Frozen saved-revision identity. The store checks its enabled generation and semantic digest.
#[derive(Clone, Debug)]
pub struct SequentialBuildBinding {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub pipeline_id: Uuid,
    pub pipeline_revision: i64,
    pub pipeline_operational_generation: i64,
    pub idempotency_key: String,
}

/// Lower each literal shell step to its own existing version-1 process node.
/// This function does not enable, save, or submit a pipeline and grants no authority.
pub fn plan_sequential_build(
    pipeline: &PipelineIr,
    binding: SequentialBuildBinding,
) -> Result<SequentialDagBuild, StoreError> {
    validate_pipeline(pipeline).map_err(|error| StoreError::InvalidDag(error.to_string()))?;
    if !pipeline.parameters.is_empty()
        || !pipeline.parameter_values.is_empty()
        || !pipeline.expressions.is_empty()
        || pipeline.stages.is_empty()
        || pipeline.stages.len() > 32
    {
        return Err(StoreError::InvalidDag(
            "sequential planning requires a bounded parameter-free pipeline".to_owned(),
        ));
    }
    let digest = pipeline
        .semantic_digest()
        .map_err(|error| StoreError::InvalidDag(error.to_string()))?;
    let mut nodes: Vec<NewDagNode> = Vec::new();
    let mut layout = Vec::new();
    for (stage_index, stage) in pipeline.stages.iter().enumerate() {
        if stage.steps.is_empty() {
            return Err(StoreError::InvalidDag(
                "sequential stage must contain a shell step".to_owned(),
            ));
        }
        // Sequential planning lowers every step to a version-1 host process
        // with no capability requirement. A stage that asked for containment
        // (PAR-011) must not silently run on the agent account instead.
        if stage.image.is_some() {
            return Err(StoreError::InvalidDag(
                "sequential planning does not admit container stages".to_owned(),
            ));
        }
        for (step_index, step) in stage.steps.iter().enumerate() {
            let Step::Process(process) = step else {
                return Err(StoreError::InvalidDag(
                    "sequential planning admits literal process steps only".to_owned(),
                ));
            };
            if process.mode != ProcessMode::Direct
                || process.program != "/bin/sh"
                || process.args.len() != 3
                || process.args[0] != "-xe"
                || process.args[1] != "-c"
                || !process.env.is_empty()
                || process.timeout_seconds.is_some()
                || nodes.len() >= 64
            {
                return Err(StoreError::InvalidDag(
                    "sequential shell shape or step bound is unsupported".to_owned(),
                ));
            }
            let node_key = format!("{}[step={:02}]", stage.id, step_index + 1);
            let dependencies = nodes
                .last()
                .map(|previous| {
                    vec![DagDependency {
                        node_key: previous.node_key.clone(),
                        condition: DependencyCondition::Succeeded,
                    }]
                })
                .unwrap_or_default();
            layout.push(SequentialStepLayout {
                node_key: node_key.clone(),
                stage_id: stage.id.clone(),
                stage_name: stage.name.clone(),
                stage_ordinal: stage_index + 1,
                step_ordinal: step_index + 1,
                execution_ordinal: nodes.len() + 1,
            });
            nodes.push(NewDagNode {
                node_key,
                kind: DagNodeKind::Work,
                dependencies,
                required_capabilities: Vec::new(),
                required_platform: "linux".to_owned(),
                required_trust_pool: "migration-deny-authority".to_owned(),
                priority: 0,
                execution_spec: super::execution_spec_parts(std::slice::from_ref(step), None, &[]),
                fail_fast: false,
                max_attempts: 1,
            });
        }
    }
    SequentialDagBuild::new(
        NewDagBuild {
            organization_id: binding.organization_id,
            project_id: binding.project_id,
            pipeline_id: binding.pipeline_id,
            pipeline_revision: binding.pipeline_revision,
            pipeline_operational_generation: binding.pipeline_operational_generation,
            idempotency_key: binding.idempotency_key,
            pipeline_digest: digest,
            priority: 0,
            nodes,
        },
        layout,
    )
}
