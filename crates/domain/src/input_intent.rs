//! Bounded, operator-mapped input capture and authoritative assignment commitments.
pub use crate::cache_intent::CacheWorkContext as InputWorkContext;
use crate::cache_intent::{canonical_mapping_id, canonical_sha256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
pub const INPUT_CAPABILITY: &str = "sealed-input-v1";
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InputIntentSpec {
    pub mapping_id: String,
    pub mapping_digest: String,
    pub timeout_seconds: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid bounded input intent or authority: {0}")]
pub struct InputIntentError(pub &'static str);
impl InputIntentSpec {
    pub fn validate(&self) -> Result<(), InputIntentError> {
        if !canonical_mapping_id(&self.mapping_id) {
            return Err(InputIntentError("mapping identifier"));
        }
        if !self
            .mapping_digest
            .strip_prefix("sha256:")
            .is_some_and(canonical_sha256)
        {
            return Err(InputIntentError("digest"));
        }
        if !(1..=60).contains(&self.timeout_seconds) {
            return Err(InputIntentError("timeout"));
        }
        Ok(())
    }
}
/// Exact scheduling eligibility for a startup-frozen operator mapping.
pub fn input_binding_capability(
    mapping_id: &str,
    mapping_digest: &str,
) -> Result<String, InputIntentError> {
    if !canonical_mapping_id(mapping_id)
        || !mapping_digest
            .strip_prefix("sha256:")
            .is_some_and(canonical_sha256)
    {
        return Err(InputIntentError("mapping capability identity"));
    }
    let mut hash = Sha256::new();
    hash.update(b"mcloving.input-binding-capability/v1\0");
    for field in [mapping_id.as_bytes(), mapping_digest.as_bytes()] {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field);
    }
    Ok(format!("sealed-input-binding-v1-{:x}", hash.finalize()))
}
/// Callers validate canonical nonnil context and typed version-4 payload first.
pub fn input_assignment_digest(execution_spec_json: &[u8], context: &InputWorkContext) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"mcloving.input-assignment/v1\0");
    for value in [
        context.organization_id.as_bytes(),
        context.project_id.as_bytes(),
        context.pipeline_id.as_bytes(),
        context.build_id.as_bytes(),
        context.node_id.as_bytes(),
        context.attempt_id.as_bytes(),
        execution_spec_json,
    ] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value);
    }
    hash.update(context.fence_token.to_be_bytes());
    hash.finalize().into()
}

/// Deterministic RFC 9562 custom UUIDv8; the full digest remains authoritative.
pub fn input_capture_id(assignment_digest: &[u8; 32]) -> Uuid {
    let mut hash = Sha256::new();
    hash.update(b"mcloving.input-capture-id/v1\0");
    hash.update(assignment_digest);
    let digest = hash.finalize();
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn intent() -> InputIntentSpec {
        InputIntentSpec {
            mapping_id: "fixture".into(),
            mapping_digest: format!("sha256:{}", "a".repeat(64)),
            timeout_seconds: 30,
        }
    }
    #[test]
    fn intent_refuses_unbounded_or_job_supplied_authority() {
        for timeout in [1, 60] {
            let mut i = intent();
            i.timeout_seconds = timeout;
            i.validate().unwrap();
        }
        for timeout in [0, 61, u64::MAX] {
            let mut i = intent();
            i.timeout_seconds = timeout;
            assert!(i.validate().is_err());
        }
        for field in [
            "query",
            "cursor",
            "endpoint",
            "principal",
            "schema",
            "confidentiality",
            "credential",
            "operation",
            "requested_at",
        ] {
            let mut v = serde_json::to_value(intent()).unwrap();
            v[field] = "override".into();
            assert!(serde_json::from_value::<InputIntentSpec>(v).is_err());
        }
        for field in ["mapping_id", "mapping_digest", "timeout_seconds"] {
            let mut v = serde_json::to_value(intent()).unwrap();
            v.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<InputIntentSpec>(v).is_err());
        }
        for digest in [
            "a".repeat(64),
            format!("sha256:{}", "A".repeat(64)),
            format!("sha256:{}", "a".repeat(63)),
        ] {
            let mut i = intent();
            i.mapping_digest = digest;
            assert!(i.validate().is_err());
        }
        for id in ["".into(), "x".repeat(129), "a/b".into()] {
            let mut i = intent();
            i.mapping_id = id;
            assert!(i.validate().is_err());
        }
    }
    #[test]
    fn assignment_binds_every_authority_and_capture_id_is_custom_uuid_v8() {
        let c = InputWorkContext {
            organization_id: Uuid::from_u128(1).to_string(),
            project_id: Uuid::from_u128(2).to_string(),
            pipeline_id: Uuid::from_u128(3).to_string(),
            build_id: Uuid::from_u128(4).to_string(),
            node_id: Uuid::from_u128(5).to_string(),
            attempt_id: Uuid::from_u128(6).to_string(),
            fence_token: 1,
        };
        c.validate().unwrap();
        let digest = input_assignment_digest(b"spec", &c);
        let id = input_capture_id(&digest);
        assert_eq!(id, input_capture_id(&digest));
        assert!(!id.is_nil());
        assert_eq!(id.get_version_num(), 8);
        assert_eq!(id.get_variant(), uuid::Variant::RFC4122);
        assert_ne!(
            digest,
            crate::cache_intent::cache_assignment_digest(b"spec", &c)
        );
        for field in 0..7 {
            let mut changed = c.clone();
            match field {
                0 => changed.organization_id = Uuid::from_u128(7).to_string(),
                1 => changed.project_id = Uuid::from_u128(7).to_string(),
                2 => changed.pipeline_id = Uuid::from_u128(7).to_string(),
                3 => changed.build_id = Uuid::from_u128(7).to_string(),
                4 => changed.node_id = Uuid::from_u128(7).to_string(),
                5 => changed.attempt_id = Uuid::from_u128(7).to_string(),
                _ => changed.fence_token += 1,
            };
            let d = input_assignment_digest(b"spec", &changed);
            assert_ne!(digest, d);
            assert_ne!(id, input_capture_id(&d));
        }
        assert_ne!(digest, input_assignment_digest(b"other", &c));
        for invalid in [
            Uuid::nil().to_string(),
            "not-uuid".into(),
            "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA".into(),
        ] {
            let mut c = c.clone();
            c.pipeline_id = invalid;
            assert!(c.validate().is_err());
        }
        let mut invalid = c;
        invalid.fence_token = 0;
        assert!(invalid.validate().is_err());
    }
    #[test]
    fn scheduling_requires_exact_mapping_and_digest() {
        let i = intent();
        let cap = input_binding_capability(&i.mapping_id, &i.mapping_digest).unwrap();
        assert_ne!(cap, INPUT_CAPABILITY);
        assert_eq!(cap.len(), "sealed-input-binding-v1-".len() + 64);
        assert_ne!(
            cap,
            input_binding_capability("other", &i.mapping_digest).unwrap()
        );
        assert_ne!(
            cap,
            input_binding_capability(&i.mapping_id, &format!("sha256:{}", "b".repeat(64))).unwrap()
        );
        assert!(input_binding_capability("", &i.mapping_digest).is_err());
        assert!(input_binding_capability("fixture", "bad").is_err());
    }
}
