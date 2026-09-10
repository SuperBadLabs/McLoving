use super::{ApiError, PipelineIr, StatusCode, Step};
use mcloving_domain::cache_intent::{canonical_mapping_id, canonical_sha256};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

pub const INPUT_MAPPING_CATALOG_V1: &str = "mcloving.input-mapping-catalog/v1";
/// Startup-frozen operator catalog. Changes take effect on controller restart;
/// queued work is additionally subject to the agent's own pinned catalog.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InputMappingCatalog {
    pub schema_version: String,
    pub profile: String,
    pub generation: u64,
    pub mappings: Vec<InputMappingRecord>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InputMappingRecord {
    pub mapping_id: String,
    pub mapping_digest: String,
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub pipeline_id: Uuid,
    pub trust_pool: String,
}
impl InputMappingCatalog {
    pub(super) fn deny_all() -> Self {
        Self {
            schema_version: INPUT_MAPPING_CATALOG_V1.into(),
            profile: "unconfigured".into(),
            generation: 0,
            mappings: Vec::new(),
        }
    }
    pub fn validate(&self) -> Result<(), ApiError> {
        if self.schema_version != INPUT_MAPPING_CATALOG_V1
            || !canonical_mapping_id(&self.profile)
            || self.generation == 0
            || self.mappings.is_empty()
            || self.mappings.len() > 1024
        {
            return Err(ApiError::configuration("invalid input mapping catalog"));
        }
        let mut ids = BTreeSet::new();
        for row in &self.mappings {
            if !canonical_mapping_id(&row.mapping_id)
                || !row
                    .mapping_digest
                    .strip_prefix("sha256:")
                    .is_some_and(canonical_sha256)
                || !ids.insert(&row.mapping_id)
                || row.organization_id.is_nil()
                || row.project_id.is_nil()
                || row.pipeline_id.is_nil()
                || row.trust_pool.is_empty()
                || row.trust_pool.len() > 128
                || row.trust_pool.trim() != row.trust_pool
            {
                return Err(ApiError::configuration(
                    "invalid or duplicate input mapping record",
                ));
            }
        }
        Ok(())
    }
}
pub(super) fn validate_input_mappings(
    pipeline: &PipelineIr,
    catalog: &InputMappingCatalog,
    organization_id: Uuid,
    project_id: Uuid,
    pipeline_id: Option<Uuid>,
    platform: &str,
    trust_pool: &str,
) -> Result<(), ApiError> {
    for input in pipeline
        .stages
        .iter()
        .flat_map(|s| &s.steps)
        .filter_map(|s| match s {
            Step::InputIntent(input) => Some(input),
            _ => None,
        })
    {
        let refuse = || {
            ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "input_mapping_denied",
                "input intent is not authorized for this pipeline, platform, trust pool",
            )
        };
        if platform != "linux" || pipeline_id.is_none_or(|id| id.is_nil()) {
            return Err(refuse());
        }
        let i = &input.intent;
        let row = catalog
            .mappings
            .iter()
            .find(|row| row.mapping_id == i.mapping_id)
            .ok_or_else(refuse)?;
        if row.mapping_digest != i.mapping_digest
            || row.organization_id != organization_id
            || row.project_id != project_id
            || Some(row.pipeline_id) != pipeline_id
            || row.trust_pool != trust_pool
        {
            return Err(refuse());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcloving_domain::input_intent::{
        INPUT_CAPABILITY, InputIntentSpec, input_binding_capability,
    };
    fn catalog() -> InputMappingCatalog {
        InputMappingCatalog {
            schema_version: INPUT_MAPPING_CATALOG_V1.into(),
            profile: "contained".into(),
            generation: 1,
            mappings: vec![InputMappingRecord {
                mapping_id: "fixture".into(),
                mapping_digest: format!("sha256:{}", "a".repeat(64)),
                organization_id: Uuid::from_u128(1),
                project_id: Uuid::from_u128(2),
                pipeline_id: Uuid::from_u128(3),
                trust_pool: "contained".into(),
            }],
        }
    }
    fn pipeline() -> PipelineIr {
        let source = format!(
            "version: 1\nname: input\nstages:\n  - id: input\n    name: Input\n    steps:\n      - input_intent:\n          mapping_id: fixture\n          mapping_digest: sha256:{}\n          timeout_seconds: 30\n",
            "a".repeat(64)
        );
        super::super::compile_source_with_parameters(&source, Default::default()).unwrap()
    }
    #[test]
    fn native_input_admission_checks_exact_scope_platform_trust_and_digest() {
        let p = pipeline();
        let c = catalog();
        c.validate().unwrap();
        validate_input_mappings(
            &p,
            &c,
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            Some(Uuid::from_u128(3)),
            "linux",
            "contained",
        )
        .unwrap();
        for (o, j, i, os, pool) in [
            (4, 2, Some(3), "linux", "contained"),
            (1, 4, Some(3), "linux", "contained"),
            (1, 2, Some(4), "linux", "contained"),
            (1, 2, None, "linux", "contained"),
            (1, 2, Some(3), "windows", "contained"),
            (1, 2, Some(3), "linux", "other"),
        ] {
            assert!(
                validate_input_mappings(
                    &p,
                    &c,
                    Uuid::from_u128(o),
                    Uuid::from_u128(j),
                    i.map(Uuid::from_u128),
                    os,
                    pool
                )
                .is_err()
            );
        }
        for changed in [InputMappingCatalog::deny_all(), {
            let mut v = c.clone();
            v.mappings[0].mapping_digest = format!("sha256:{}", "d".repeat(64));
            v
        }] {
            assert!(
                validate_input_mappings(
                    &p,
                    &changed,
                    Uuid::from_u128(1),
                    Uuid::from_u128(2),
                    Some(Uuid::from_u128(3)),
                    "linux",
                    "contained"
                )
                .is_err()
            );
        }
        let spec = super::super::execution_spec(&p.stages[0].steps);
        assert_eq!(spec["version"], 4);
        assert_eq!(spec["steps"][0]["kind"], "input_intent");
        let mut step = spec["steps"][0].as_object().unwrap().clone();
        step.remove("kind");
        serde_json::from_value::<InputIntentSpec>(serde_json::Value::Object(step))
            .unwrap()
            .validate()
            .unwrap();
        assert_eq!(
            super::super::stage_required_capabilities(&p.stages[0]),
            vec![
                INPUT_CAPABILITY.to_owned(),
                input_binding_capability("fixture", &format!("sha256:{}", "a".repeat(64))).unwrap(),
            ]
        );
    }
    #[test]
    fn input_scheduling_requires_exact_mapping_and_digest() {
        let p = pipeline();
        let required = super::super::stage_required_capabilities(&p.stages[0]);
        for advertised in [
            vec![INPUT_CAPABILITY.to_owned()],
            vec![
                INPUT_CAPABILITY.to_owned(),
                input_binding_capability("other", &format!("sha256:{}", "a".repeat(64))).unwrap(),
            ],
            vec![
                INPUT_CAPABILITY.to_owned(),
                input_binding_capability("fixture", &format!("sha256:{}", "b".repeat(64))).unwrap(),
            ],
        ] {
            assert!(
                !required
                    .iter()
                    .all(|capability| advertised.contains(capability))
            );
        }
        let plan = super::super::pipeline_plan(&p).unwrap();
        let value = serde_json::to_value(plan).unwrap();
        assert_eq!(value["stages"][0]["input_intent_steps"], 1);
    }

    #[test]
    fn noninput_validation_preserves_legacy_header_behavior() {
        let p=super::super::compile_source_with_parameters("version: 1\nname: process\nstages:\n  - id: run\n    name: Run\n    steps:\n      - process:\n          program: /bin/true\n",Default::default()).unwrap();
        let mut headers = super::super::HeaderMap::new();
        headers.insert(
            super::super::PLATFORM_HEADER,
            "not-a-platform".parse().unwrap(),
        );
        headers.insert(
            super::super::TRUST_POOL_HEADER,
            " bad-pool ".parse().unwrap(),
        );
        super::super::validate_input_scope_headers(
            &p,
            &InputMappingCatalog::deny_all(),
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            None,
            &headers,
        )
        .unwrap();
        assert!(super::super::stage_required_capabilities(&p.stages[0]).is_empty());
        assert!(
            super::super::validate_input_scope_headers(
                &pipeline(),
                &catalog(),
                Uuid::from_u128(1),
                Uuid::from_u128(2),
                Some(Uuid::from_u128(3)),
                &headers
            )
            .is_err()
        );
    }
    #[test]
    fn malformed_deployment_catalog_never_becomes_admission_authority() {
        let c = catalog();
        for v in [
            {
                let mut v = c.clone();
                v.mappings.push(v.mappings[0].clone());
                v
            },
            {
                let mut v = c.clone();
                v.mappings[0].pipeline_id = Uuid::nil();
                v
            },
            {
                let mut v = c.clone();
                v.generation = 0;
                v
            },
        ] {
            assert!(v.validate().is_err());
        }
        let mut value = serde_json::to_value(c).unwrap();
        value["mappings"][0]["executable"] = "/bin/untrusted".into();
        assert!(serde_json::from_value::<InputMappingCatalog>(value).is_err());
    }
    #[test]
    fn mixed_stage_envelopes_and_older_plan_responses_remain_compatible() {
        let input = pipeline();
        let cache_source = format!(
            "version: 1\nname: cache\nstages:\n  - id: cache\n    name: Cache\n    steps:\n      - cache_intent:\n          mapping_id: fixture\n          mapping_digest: sha256:{}\n          operation: read\n          logical_key_sha256: {}\n          input_sha256: {}\n          timeout_seconds: 30\n",
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64)
        );
        let cache = super::super::compile_source_with_parameters(&cache_source, Default::default())
            .unwrap();
        let process=super::super::compile_source_with_parameters("version: 1\nname: process\nstages:\n  - id: process\n    name: Process\n    steps:\n      - process:\n          program: /bin/true\n",Default::default()).unwrap();
        let mut mixed = input;
        mixed.stages.extend(cache.stages);
        mixed.stages.extend(process.stages);
        mixed.canonical_bytes().unwrap();
        for (stage, version) in mixed.stages.iter().zip([4, 3, 1]) {
            assert_eq!(
                super::super::execution_spec(&stage.steps)["version"],
                version
            );
        }
        let plan = super::super::pipeline_plan(&mixed).unwrap();
        let mut old = serde_json::to_value(plan).unwrap();
        for stage in old["stages"].as_array_mut().unwrap() {
            stage.as_object_mut().unwrap().remove("input_intent_steps");
        }
        let decoded: super::super::PipelinePlanResponse = serde_json::from_value(old).unwrap();
        assert!(
            decoded
                .stages
                .iter()
                .all(|stage| stage.input_intent_steps == 0)
        );
    }
}
