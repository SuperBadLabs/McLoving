//! Bounded native cache intents and controller-authorized work identity.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const MAX_CACHE_CONTENT_BYTES: usize = 12 * 1024;
pub const CACHE_CAPABILITY: &str = "sealed-cache-v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheOperation {
    Read,
    Publish,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheIntentSpec {
    pub mapping_id: String,
    pub mapping_digest: String,
    pub operation: CacheOperation,
    pub logical_key_sha256: String,
    pub input_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_base64: Option<String>,
    pub timeout_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid bounded cache intent or authority: {0}")]
pub struct CacheIntentError(pub &'static str);

pub fn canonical_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}

pub fn canonical_mapping_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

impl CacheIntentSpec {
    pub fn validate(&self) -> Result<(), CacheIntentError> {
        if !canonical_mapping_id(&self.mapping_id) {
            return Err(CacheIntentError("mapping identifier"));
        }
        if !self
            .mapping_digest
            .strip_prefix("sha256:")
            .is_some_and(canonical_sha256)
            || !canonical_sha256(&self.logical_key_sha256)
            || !canonical_sha256(&self.input_sha256)
        {
            return Err(CacheIntentError("digest"));
        }
        if !(1..=60).contains(&self.timeout_seconds) {
            return Err(CacheIntentError("timeout"));
        }
        self.decoded_content()?;
        Ok(())
    }
    pub fn decoded_content(&self) -> Result<Option<Vec<u8>>, CacheIntentError> {
        match (self.operation, self.content_base64.as_deref()) {
            (CacheOperation::Read, None) => Ok(None),
            (CacheOperation::Publish, Some(encoded)) => {
                if encoded.len() > 16 * 1024 {
                    return Err(CacheIntentError("content bound"));
                }
                let bytes = STANDARD
                    .decode(encoded)
                    .map_err(|_| CacheIntentError("base64"))?;
                if bytes.len() > MAX_CACHE_CONTENT_BYTES || STANDARD.encode(&bytes) != encoded {
                    return Err(CacheIntentError("noncanonical or oversized content"));
                }
                Ok(Some(bytes))
            }
            _ => Err(CacheIntentError(
                "content presence does not match operation",
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheWorkContext {
    pub organization_id: String,
    pub project_id: String,
    pub pipeline_id: String,
    pub build_id: String,
    pub node_id: String,
    pub attempt_id: String,
    pub fence_token: u64,
}
impl CacheWorkContext {
    pub fn validate(&self) -> Result<(), CacheIntentError> {
        for value in [
            &self.organization_id,
            &self.project_id,
            &self.pipeline_id,
            &self.build_id,
            &self.node_id,
            &self.attempt_id,
        ] {
            let id = Uuid::parse_str(value).map_err(|_| CacheIntentError("work identity"))?;
            if id.is_nil() || id.to_string() != *value {
                return Err(CacheIntentError("noncanonical work identity"));
            }
        }
        if self.fence_token == 0 {
            return Err(CacheIntentError("fence"));
        }
        Ok(())
    }
}
/// Callers validate context and the typed version-3 payload before accepting work.
pub fn cache_assignment_digest(execution_spec_json: &[u8], context: &CacheWorkContext) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"mcloving.cache-assignment/v1\0");
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

#[cfg(test)]
mod tests {
    use super::*;
    fn intent() -> CacheIntentSpec {
        CacheIntentSpec {
            mapping_id: "fixture".into(),
            mapping_digest: format!("sha256:{}", "a".repeat(64)),
            operation: CacheOperation::Publish,
            logical_key_sha256: "b".repeat(64),
            input_sha256: "c".repeat(64),
            content_base64: Some(STANDARD.encode(b"public fixture")),
            timeout_seconds: 30,
        }
    }
    #[test]
    fn bounded_literal_contract_refuses_ambiguity_and_authority_fields() {
        let original = intent();
        original.validate().unwrap();
        let mut value = serde_json::to_value(&original).unwrap();
        value["principal"] = serde_json::json!("operator");
        assert!(serde_json::from_value::<CacheIntentSpec>(value).is_err());
        for count in [0, 61] {
            let mut v = original.clone();
            v.timeout_seconds = count;
            assert!(v.validate().is_err());
        }
        let mut v = original.clone();
        v.operation = CacheOperation::Read;
        assert!(v.validate().is_err());
        v.content_base64 = None;
        v.validate().unwrap();
        v.operation = CacheOperation::Publish;
        assert!(v.validate().is_err());
        for content in [
            "***".to_owned(),
            STANDARD.encode(vec![0; MAX_CACHE_CONTENT_BYTES + 1]),
        ] {
            v.content_base64 = Some(content);
            assert!(v.validate().is_err());
        }
        v.content_base64 = Some(STANDARD.encode(vec![0; MAX_CACHE_CONTENT_BYTES]));
        v.validate().unwrap();
        v.content_base64 = Some(String::new());
        v.validate().unwrap();
        v.input_sha256 = "C".repeat(64);
        assert!(v.validate().is_err());
    }
    #[test]
    fn assignment_identity_and_every_authority_dimension_are_bound() {
        let c = CacheWorkContext {
            organization_id: "11111111-1111-1111-1111-111111111111".into(),
            project_id: "22222222-2222-2222-2222-222222222222".into(),
            pipeline_id: "33333333-3333-3333-3333-333333333333".into(),
            build_id: "44444444-4444-4444-4444-444444444444".into(),
            node_id: "55555555-5555-5555-5555-555555555555".into(),
            attempt_id: "66666666-6666-6666-6666-666666666666".into(),
            fence_token: 1,
        };
        c.validate().unwrap();
        let digest = cache_assignment_digest(b"spec", &c);
        for index in 0..7 {
            let mut m = c.clone();
            match index {
                0 => m.organization_id = "77777777-7777-7777-7777-777777777777".into(),
                1 => m.project_id = "77777777-7777-7777-7777-777777777777".into(),
                2 => m.pipeline_id = "77777777-7777-7777-7777-777777777777".into(),
                3 => m.build_id = "77777777-7777-7777-7777-777777777777".into(),
                4 => m.node_id = "77777777-7777-7777-7777-777777777777".into(),
                5 => m.attempt_id = "77777777-7777-7777-7777-777777777777".into(),
                _ => m.fence_token += 1,
            };
            assert_ne!(digest, cache_assignment_digest(b"spec", &m));
        }
        assert_ne!(digest, cache_assignment_digest(b"other", &c));
        let mut invalid = c;
        invalid.pipeline_id = Uuid::nil().to_string();
        assert!(invalid.validate().is_err());
    }
}
