use super::{ApiError, PipelineIr, StatusCode, Step};
use mcloving_domain::cache_intent::{canonical_mapping_id, canonical_sha256};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

pub const SOURCE_MAPPING_CATALOG_V1: &str = "mcloving.source-mapping-catalog/v1";
/// Startup-frozen operator catalog of source bindings (PAR-012). Changes take
/// effect on controller restart; queued work is additionally subject to the
/// agent's own pinned bindings, which carry the repository and credential.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceMappingCatalog {
    pub schema_version: String,
    pub profile: String,
    pub generation: u64,
    pub mappings: Vec<SourceMappingRecord>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceMappingRecord {
    pub mapping_id: String,
    pub mapping_digest: String,
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub pipeline_id: Uuid,
    pub trust_pool: String,
}
impl SourceMappingCatalog {
    pub(super) fn deny_all() -> Self {
        Self {
            schema_version: SOURCE_MAPPING_CATALOG_V1.into(),
            profile: "unconfigured".into(),
            generation: 0,
            mappings: Vec::new(),
        }
    }
    pub fn validate(&self) -> Result<(), ApiError> {
        if self.schema_version != SOURCE_MAPPING_CATALOG_V1
            || !canonical_mapping_id(&self.profile)
            || self.generation == 0
            || self.mappings.is_empty()
            || self.mappings.len() > 1024
        {
            return Err(ApiError::configuration("invalid source mapping catalog"));
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
                    "invalid or duplicate source mapping record",
                ));
            }
        }
        Ok(())
    }
}
pub(super) fn validate_source_mappings(
    pipeline: &PipelineIr,
    catalog: &SourceMappingCatalog,
    organization_id: Uuid,
    project_id: Uuid,
    pipeline_id: Option<Uuid>,
    platform: &str,
    trust_pool: &str,
) -> Result<(), ApiError> {
    for checkout in pipeline
        .stages
        .iter()
        .flat_map(|s| &s.steps)
        .filter_map(|s| match s {
            Step::Checkout(checkout) => Some(checkout),
            _ => None,
        })
    {
        let refuse = || {
            ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "source_mapping_denied",
                "checkout step is not authorized for this pipeline, platform or trust pool",
            )
        };
        if platform != "linux" || pipeline_id.is_none_or(|id| id.is_nil()) {
            return Err(refuse());
        }
        let spec = &checkout.spec;
        let row = catalog
            .mappings
            .iter()
            .find(|row| row.mapping_id == spec.mapping_id)
            .ok_or_else(refuse)?;
        if row.mapping_digest != spec.mapping_digest
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
    use mcloving_domain::multi_step::MULTI_STEP_CAPABILITY;
    use mcloving_domain::source_intent::{
        CheckoutStepSpec, SOURCE_CAPABILITY, source_binding_capability,
    };
    fn catalog() -> SourceMappingCatalog {
        SourceMappingCatalog {
            schema_version: SOURCE_MAPPING_CATALOG_V1.into(),
            profile: "contained".into(),
            generation: 1,
            mappings: vec![SourceMappingRecord {
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
            "version: 1\nname: checkout\nstages:\n  - id: build\n    name: Build\n    steps:\n      - checkout:\n          mapping_id: fixture\n          mapping_digest: sha256:{}\n          ref: refs/heads/main\n          commit: {}\n          destination: source\n          timeout_seconds: 120\n      - process:\n          program: /bin/true\n",
            "a".repeat(64),
            "b".repeat(40)
        );
        super::super::compile_source_with_parameters(&source, Default::default()).unwrap()
    }
    #[test]
    fn checkout_admission_checks_exact_scope_platform_and_trust() {
        let p = pipeline();
        let c = catalog();
        c.validate().unwrap();
        validate_source_mappings(
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
                validate_source_mappings(
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
        let mut changed = c.clone();
        changed.mappings[0].mapping_digest = format!("sha256:{}", "d".repeat(64));
        for catalog in [SourceMappingCatalog::deny_all(), changed] {
            assert!(
                validate_source_mappings(
                    &p,
                    &catalog,
                    Uuid::from_u128(1),
                    Uuid::from_u128(2),
                    Some(Uuid::from_u128(3)),
                    "linux",
                    "contained"
                )
                .is_err()
            );
        }
        // A checkout stage rides the version-5 envelope even alongside one
        // process step, and its checkout step carries the whole typed spec.
        let spec = super::super::execution_spec(&p.stages[0]);
        assert_eq!(spec["version"], 5);
        assert_eq!(spec["steps"][0]["kind"], "checkout");
        assert_eq!(spec["steps"][1]["kind"], "process");
        let mut step = spec["steps"][0].as_object().unwrap().clone();
        step.remove("kind");
        serde_json::from_value::<CheckoutStepSpec>(serde_json::Value::Object(step))
            .unwrap()
            .validate()
            .unwrap();
        assert_eq!(
            super::super::stage_required_capabilities(&p.stages[0]),
            vec![
                MULTI_STEP_CAPABILITY.to_owned(),
                SOURCE_CAPABILITY.to_owned(),
                source_binding_capability("fixture", &format!("sha256:{}", "a".repeat(64)))
                    .unwrap(),
            ]
        );
        // Windows never runs the sealed acquirer.
        assert!(super::super::validate_execution_platform(&p, "windows").is_err());
        super::super::validate_execution_platform(&p, "linux").unwrap();
    }
    #[test]
    fn malformed_source_catalog_never_becomes_admission_authority() {
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
        value["mappings"][0]["repository_url"] = "https://example.invalid/repo".into();
        assert!(serde_json::from_value::<SourceMappingCatalog>(value).is_err());
    }
}
