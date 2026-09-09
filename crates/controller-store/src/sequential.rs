//! Contained sequential execution contracts. No public submission route uses this mode.

pub(crate) mod results;

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    DagAdmission, DagDependency, DagNodeKind, DependencyCondition, NewDagBuild, Store, StoreError,
    TRIGGER_DAG_IDEMPOTENCY_PREFIX, validate_dag_contract,
};

/// Explicit immutable identity; consumers must never parse node keys for labels or order.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SequentialStepLayout {
    pub node_key: String,
    pub stage_id: String,
    pub stage_name: String,
    pub stage_ordinal: usize,
    pub step_ordinal: usize,
    pub execution_ordinal: usize,
}

/// Owned, validated, parameter-free admission. Deliberately not deserializable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SequentialDagBuild {
    dag: NewDagBuild,
    layout: Vec<SequentialStepLayout>,
}

impl SequentialDagBuild {
    pub fn new(
        dag: NewDagBuild,
        mut layout: Vec<SequentialStepLayout>,
    ) -> Result<Self, StoreError> {
        validate_dag_contract(&dag).map_err(|error| invalid(error.to_string()))?;
        if dag
            .idempotency_key
            .starts_with(TRIGGER_DAG_IDEMPOTENCY_PREFIX)
            || dag.priority != 0
            || dag.pipeline_revision <= 0
            || dag.pipeline_operational_generation <= 0
            || layout.is_empty()
            || layout.len() > 64
            || layout.len() != dag.nodes.len()
        {
            return Err(invalid("invalid sequential admission bounds or binding"));
        }
        layout.sort_by_key(|row| row.execution_ordinal);
        let nodes = dag
            .nodes
            .iter()
            .map(|node| (node.node_key.as_str(), node))
            .collect::<BTreeMap<_, _>>();
        let mut keys = BTreeSet::new();
        let mut stages = BTreeSet::new();
        let mut script_bytes = 0;
        for (index, row) in layout.iter().enumerate() {
            if row.execution_ordinal != index + 1
                || !keys.insert(&row.node_key)
                || row.stage_name.is_empty()
                || row.stage_name.len() > 96
                || row.stage_id.is_empty()
                || row.stage_id != normalized_stage_id(&row.stage_name)
            {
                return Err(invalid("invalid sequential layout identity"));
            }
            match index.checked_sub(1).map(|previous| &layout[previous]) {
                None if row.stage_ordinal == 1 && row.step_ordinal == 1 => {
                    stages.insert(&row.stage_id);
                }
                Some(previous)
                    if row.stage_ordinal == previous.stage_ordinal
                        && row.stage_id == previous.stage_id
                        && row.stage_name == previous.stage_name
                        && row.step_ordinal == previous.step_ordinal + 1 => {}
                Some(previous)
                    if row.stage_ordinal == previous.stage_ordinal + 1
                        && row.step_ordinal == 1
                        && stages.insert(&row.stage_id) => {}
                _ => {
                    return Err(invalid(
                        "sequential stage and step ordinals must be contiguous",
                    ));
                }
            }
            if row.stage_ordinal > 32 {
                return Err(invalid("sequential stage bound exceeded"));
            }
            let node = nodes
                .get(row.node_key.as_str())
                .ok_or_else(|| invalid("layout has no matching node"))?;
            let expected_dependencies = index
                .checked_sub(1)
                .map(|previous| {
                    vec![DagDependency {
                        node_key: layout[previous].node_key.clone(),
                        condition: DependencyCondition::Succeeded,
                    }]
                })
                .unwrap_or_default();
            if node.kind != DagNodeKind::Work
                || node.dependencies != expected_dependencies
                || !node.required_capabilities.is_empty()
                || node.required_platform != "linux"
                || node.required_trust_pool != "migration-deny-authority"
                || node.priority != 0
                || node.fail_fast
                || node.max_attempts != 1
            {
                return Err(invalid("sequential node policy or dependency mismatch"));
            }
            let script = node
                .execution_spec
                .pointer("/steps/0/args/2")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("sequential process must contain a literal shell script"))?;
            if script.is_empty()
                || script.len() > 4096
                || script.contains('\0')
                || script.starts_with("#!")
            {
                return Err(invalid("invalid sequential shell literal"));
            }
            script_bytes += script.len();
            if script_bytes > 4096
                || node.execution_spec
                    != json!({
                        "version": 1, "steps": [{"kind": "process", "mode": "direct", "program": "/bin/sh",
                            "args": ["-xe", "-c", script], "env": {}, "timeout_seconds": null}]
                    })
            {
                return Err(invalid(
                    "sequential process shape or aggregate literal bound mismatch",
                ));
            }
        }
        Ok(Self { dag, layout })
    }

    pub fn dag(&self) -> &NewDagBuild {
        &self.dag
    }
    pub fn layout(&self) -> &[SequentialStepLayout] {
        &self.layout
    }

    pub(crate) fn contract(&self) -> Value {
        let mut value = crate::dag::normalized_dag_contract(&self.dag);
        value["sequential_layout"] = json!({"version": 1, "steps": self.layout});
        value
    }
}

impl Store {
    /// Atomically admits this contained mode using the existing fenced DAG machinery.
    #[doc(hidden)]
    pub async fn admit_sequential_dag(
        &self,
        input: &SequentialDagBuild,
    ) -> Result<DagAdmission, StoreError> {
        let mut tx = self.tenant_transaction(input.dag.organization_id).await?;
        let admission =
            crate::dag::admit_dag_contract_transaction(&mut tx, &input.dag, input.contract(), true)
                .await?;
        tx.commit().await?;
        Ok(admission)
    }
}

fn invalid(message: impl Into<String>) -> StoreError {
    StoreError::InvalidDag(message.into())
}

// The protected compiler normalization is ASCII-only even when labels contain Unicode.
pub(crate) fn normalized_stage_id(name: &str) -> String {
    let mut result = String::new();
    let mut invalid_run = false;
    for character in name.chars().map(|character| character.to_ascii_lowercase()) {
        if character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || matches!(character, '.' | '_' | '-')
        {
            result.push(character);
            invalid_run = false;
        } else if !invalid_run {
            result.push('-');
            invalid_run = true;
        }
    }
    result.trim_matches('-').to_owned()
}
