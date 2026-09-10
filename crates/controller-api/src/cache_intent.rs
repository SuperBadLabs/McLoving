use super::{ApiError, PipelineIr, StatusCode, Step};
use mcloving_domain::cache_intent::{CacheOperation, canonical_mapping_id, canonical_sha256};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

pub const CACHE_MAPPING_CATALOG_V1: &str = "mcloving.cache-mapping-catalog/v1";
/// Startup-frozen operator catalog. Changes take effect on controller restart;
/// queued work is additionally subject to the agent's own pinned catalog.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheMappingCatalog {
    pub schema_version: String,
    pub profile: String,
    pub generation: u64,
    pub mappings: Vec<CacheMappingRecord>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheMappingRecord {
    pub mapping_id: String,
    pub mapping_digest: String,
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub pipeline_id: Uuid,
    pub trust_pool: String,
    pub allowed_operations: Vec<CacheOperation>,
}
impl CacheMappingCatalog {
    pub(super) fn deny_all() -> Self {
        Self {
            schema_version: CACHE_MAPPING_CATALOG_V1.into(),
            profile: "unconfigured".into(),
            generation: 0,
            mappings: Vec::new(),
        }
    }
    pub fn validate(&self) -> Result<(), ApiError> {
        if self.schema_version != CACHE_MAPPING_CATALOG_V1
            || !canonical_mapping_id(&self.profile)
            || self.generation == 0
            || self.mappings.is_empty()
            || self.mappings.len() > 1024
        {
            return Err(ApiError::configuration("invalid cache mapping catalog"));
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
                || row.allowed_operations.is_empty()
                || row.allowed_operations.len() > 2
                || row.allowed_operations.iter().collect::<BTreeSet<_>>().len()
                    != row.allowed_operations.len()
            {
                return Err(ApiError::configuration(
                    "invalid or duplicate cache mapping record",
                ));
            }
        }
        Ok(())
    }
}
pub(super) fn validate_cache_mappings(
    pipeline: &PipelineIr,
    catalog: &CacheMappingCatalog,
    organization_id: Uuid,
    project_id: Uuid,
    pipeline_id: Option<Uuid>,
    platform: &str,
    trust_pool: &str,
) -> Result<(), ApiError> {
    for cache in pipeline
        .stages
        .iter()
        .flat_map(|s| &s.steps)
        .filter_map(|s| match s {
            Step::CacheIntent(cache) => Some(cache),
            _ => None,
        })
    {
        let refuse = || {
            ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "cache_mapping_denied",
                "cache intent is not authorized for this pipeline, platform, trust pool or operation",
            )
        };
        if platform != "linux" || pipeline_id.is_none_or(|id| id.is_nil()) {
            return Err(refuse());
        }
        let i = &cache.intent;
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
            || !row.allowed_operations.contains(&i.operation)
        {
            return Err(refuse());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcloving_domain::cache_intent::{
        CACHE_CAPABILITY, CacheIntentSpec, cache_binding_capability,
    };
    fn catalog() -> CacheMappingCatalog {
        CacheMappingCatalog {
            schema_version: CACHE_MAPPING_CATALOG_V1.into(),
            profile: "contained".into(),
            generation: 1,
            mappings: vec![CacheMappingRecord {
                mapping_id: "fixture".into(),
                mapping_digest: format!("sha256:{}", "a".repeat(64)),
                organization_id: Uuid::from_u128(1),
                project_id: Uuid::from_u128(2),
                pipeline_id: Uuid::from_u128(3),
                trust_pool: "contained".into(),
                allowed_operations: vec![CacheOperation::Read, CacheOperation::Publish],
            }],
        }
    }
    fn pipeline() -> PipelineIr {
        let source = format!(
            "version: 1\nname: cache\nstages:\n  - id: cache\n    name: Cache\n    steps:\n      - cache_intent:\n          mapping_id: fixture\n          mapping_digest: sha256:{}\n          operation: read\n          logical_key_sha256: {}\n          input_sha256: {}\n          timeout_seconds: 30\n",
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64)
        );
        super::super::compile_source_with_parameters(&source, Default::default()).unwrap()
    }
    #[test]
    fn native_cache_admission_checks_exact_scope_platform_trust_and_operations() {
        let p = pipeline();
        let c = catalog();
        c.validate().unwrap();
        validate_cache_mappings(
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
                validate_cache_mappings(
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
        for changed in [
            CacheMappingCatalog::deny_all(),
            {
                let mut v = c.clone();
                v.mappings[0].mapping_digest = format!("sha256:{}", "d".repeat(64));
                v
            },
            {
                let mut v = c.clone();
                v.mappings[0].allowed_operations = vec![CacheOperation::Publish];
                v
            },
        ] {
            assert!(
                validate_cache_mappings(
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
        assert_eq!(spec["version"], 3);
        assert_eq!(spec["steps"][0]["kind"], "cache_intent");
        let mut step = spec["steps"][0].as_object().unwrap().clone();
        step.remove("kind");
        serde_json::from_value::<CacheIntentSpec>(serde_json::Value::Object(step))
            .unwrap()
            .validate()
            .unwrap();
        assert_eq!(
            super::super::stage_required_capabilities(&p.stages[0]),
            vec![
                CACHE_CAPABILITY.to_owned(),
                cache_binding_capability(
                    "fixture",
                    &format!("sha256:{}", "a".repeat(64)),
                    CacheOperation::Read
                )
                .unwrap(),
            ]
        );
    }
    #[test]
    fn cache_scheduling_requires_exact_mapping_digest_and_operation_support() {
        let p = pipeline();
        let required = super::super::stage_required_capabilities(&p.stages[0]);
        let digest = format!("sha256:{}", "a".repeat(64));
        let token = |mapping: &str, digest: &str, operation| {
            cache_binding_capability(mapping, digest, operation).unwrap()
        };
        // These agents share platform, trust pool and generic cache support.
        // Only the exact mapping/digest/operation may satisfy the DAG's
        // existing all-required-capabilities scheduling predicate.
        for advertised in [
            vec![CACHE_CAPABILITY.to_owned()],
            vec![
                CACHE_CAPABILITY.to_owned(),
                token("other", &digest, CacheOperation::Read),
            ],
            vec![
                CACHE_CAPABILITY.to_owned(),
                token(
                    "fixture",
                    &format!("sha256:{}", "b".repeat(64)),
                    CacheOperation::Read,
                ),
            ],
            vec![
                CACHE_CAPABILITY.to_owned(),
                token("fixture", &digest, CacheOperation::Publish),
            ],
        ] {
            assert!(
                !required
                    .iter()
                    .all(|capability| advertised.contains(capability))
            );
        }
        let capable = [
            CACHE_CAPABILITY.to_owned(),
            token("fixture", &digest, CacheOperation::Read),
        ];
        assert!(
            required
                .iter()
                .all(|capability| capable.contains(capability))
        );
        let mut publishing = p.stages[0].clone();
        let Step::CacheIntent(cache) = &mut publishing.steps[0] else {
            panic!("cache fixture")
        };
        cache.intent.operation = CacheOperation::Publish;
        cache.intent.content_base64 = Some(String::new());
        cache.intent.validate().unwrap();
        let publish_required = super::super::stage_required_capabilities(&publishing);
        assert_eq!(publish_required[0], CACHE_CAPABILITY);
        assert_eq!(
            publish_required[1],
            token("fixture", &digest, CacheOperation::Publish)
        );
        assert!(
            !publish_required
                .iter()
                .all(|capability| capable.contains(capability))
        );
    }

    #[test]
    fn noncache_validation_preserves_legacy_header_behavior() {
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
        super::super::validate_cache_scope_headers(
            &p,
            &CacheMappingCatalog::deny_all(),
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            None,
            &headers,
        )
        .unwrap();
        assert!(super::super::stage_required_capabilities(&p.stages[0]).is_empty());
        assert!(
            super::super::validate_cache_scope_headers(
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
                v.mappings[0].allowed_operations = vec![CacheOperation::Read, CacheOperation::Read];
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
        assert!(serde_json::from_value::<CacheMappingCatalog>(value).is_err());
    }
}
