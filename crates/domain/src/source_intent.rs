//! Bounded checkout steps (PAR-012): a pipeline names a deployment-owned
//! source binding, a ref, an exact commit and a workspace destination; every
//! repository, credential and executable choice stays with the deployment.
pub use crate::cache_intent::CacheWorkContext as SourceWorkContext;
use crate::cache_intent::{canonical_mapping_id, canonical_sha256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Scheduler capability an agent advertises when it carries any source
/// binding; a stage with a checkout step requires it.
pub const SOURCE_CAPABILITY: &str = "sealed-source-v1";
/// Longest accepted ref text; the sealed acquirer bounds its own at the same
/// figure.
pub const MAX_REFERENCE_BYTES: usize = 256;
/// Longest accepted destination name: one workspace path component.
pub const MAX_DESTINATION_BYTES: usize = 64;
/// Longest accepted checkout wait, including transport, in seconds.
pub const MAX_CHECKOUT_TIMEOUT_SECONDS: u64 = 3_600;
/// Workspace names the agent itself owns; a checkout may not land on them.
pub const RESERVED_DESTINATIONS: &[&str] = &["spool"];

/// The literal checkout step as compiled from the pipeline. `commit` may have
/// come from a typed parameter; by the time it is here it is a literal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CheckoutStepSpec {
    pub mapping_id: String,
    pub mapping_digest: String,
    /// Fully qualified ref the commit must be reachable from, `refs/...`.
    pub reference: String,
    /// Exact commit object id: 40 hex (SHA-1) or 64 hex (SHA-256).
    pub commit: String,
    /// Workspace-relative destination, a single path component.
    pub destination: String,
    pub timeout_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid bounded checkout step or authority: {0}")]
pub struct SourceIntentError(pub &'static str);

/// Exact scheduling eligibility for one startup-frozen source binding.
pub fn source_binding_capability(
    mapping_id: &str,
    mapping_digest: &str,
) -> Result<String, SourceIntentError> {
    if !canonical_mapping_id(mapping_id)
        || !mapping_digest
            .strip_prefix("sha256:")
            .is_some_and(canonical_sha256)
    {
        return Err(SourceIntentError("mapping capability identity"));
    }
    let mut hash = Sha256::new();
    hash.update(b"mcloving.source-binding-capability/v1\0");
    for field in [mapping_id.as_bytes(), mapping_digest.as_bytes()] {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field);
    }
    Ok(format!("sealed-source-binding-v1-{:x}", hash.finalize()))
}

/// `refs/...` with the same shape rule the sealed acquirer applies, so a ref
/// admitted here is never refused later for its spelling alone.
#[must_use]
pub fn is_valid_reference(reference: &str) -> bool {
    reference.starts_with("refs/")
        && reference.len() <= MAX_REFERENCE_BYTES
        && !reference.ends_with('/')
        && !reference.ends_with('.')
        && !reference.ends_with(".lock")
        && !reference.contains("..")
        && !reference.contains("@{")
        && !reference.contains("//")
        && !reference
            .bytes()
            .any(|byte| byte <= b' ' || byte == 0x7f || b"~^:?*[\\".contains(&byte))
}

/// A lowercase hex object id of either supported hash width.
#[must_use]
pub fn is_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

/// One plain path component the agent may create inside the workspace:
/// no separators, no `.`/`..`, no leading dot, no agent-owned name.
#[must_use]
pub fn is_valid_destination(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_DESTINATION_BYTES
        && !value.starts_with('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && !RESERVED_DESTINATIONS.contains(&value)
}

impl CheckoutStepSpec {
    pub fn validate(&self) -> Result<(), SourceIntentError> {
        if !canonical_mapping_id(&self.mapping_id) {
            return Err(SourceIntentError("mapping identifier"));
        }
        if !self
            .mapping_digest
            .strip_prefix("sha256:")
            .is_some_and(canonical_sha256)
        {
            return Err(SourceIntentError("digest"));
        }
        if !is_valid_reference(&self.reference) {
            return Err(SourceIntentError("reference"));
        }
        if !is_object_id(&self.commit) {
            return Err(SourceIntentError("commit"));
        }
        if !is_valid_destination(&self.destination) {
            return Err(SourceIntentError("destination"));
        }
        if !(1..=MAX_CHECKOUT_TIMEOUT_SECONDS).contains(&self.timeout_seconds) {
            return Err(SourceIntentError("timeout"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn spec() -> CheckoutStepSpec {
        CheckoutStepSpec {
            mapping_id: "fixture".into(),
            mapping_digest: format!("sha256:{}", "a".repeat(64)),
            reference: "refs/heads/main".into(),
            commit: "b".repeat(40),
            destination: "source".into(),
            timeout_seconds: 600,
        }
    }
    #[test]
    fn a_well_formed_checkout_validates_and_each_field_is_bounded() {
        spec().validate().unwrap();
        type Mutation = Box<dyn Fn(&mut CheckoutStepSpec)>;
        let cases: Vec<(&str, Mutation)> = vec![
            ("mapping id", Box::new(|s| s.mapping_id = "bad id".into())),
            ("digest", Box::new(|s| s.mapping_digest = "a".repeat(64))),
            ("ref prefix", Box::new(|s| s.reference = "main".into())),
            (
                "ref dotdot",
                Box::new(|s| s.reference = "refs/heads/a..b".into()),
            ),
            (
                "ref space",
                Box::new(|s| s.reference = "refs/heads/a b".into()),
            ),
            ("commit short", Box::new(|s| s.commit = "b".repeat(39))),
            ("commit upper", Box::new(|s| s.commit = "B".repeat(40))),
            (
                "destination slash",
                Box::new(|s| s.destination = "a/b".into()),
            ),
            ("destination dot", Box::new(|s| s.destination = "..".into())),
            (
                "destination hidden",
                Box::new(|s| s.destination = ".git".into()),
            ),
            (
                "destination reserved",
                Box::new(|s| s.destination = "spool".into()),
            ),
            (
                "destination empty",
                Box::new(|s| s.destination = String::new()),
            ),
            ("timeout zero", Box::new(|s| s.timeout_seconds = 0)),
            ("timeout long", Box::new(|s| s.timeout_seconds = 3_601)),
        ];
        for (name, mutate) in cases {
            let mut s = spec();
            mutate(&mut s);
            assert!(s.validate().is_err(), "{name} accepted");
        }
        let mut sha256 = spec();
        sha256.commit = "c".repeat(64);
        sha256.validate().unwrap();
    }
    #[test]
    fn scheduling_capability_binds_mapping_and_digest() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let original = source_binding_capability("fixture", &digest).unwrap();
        assert_eq!(original.len(), "sealed-source-binding-v1-".len() + 64);
        assert_ne!(original, SOURCE_CAPABILITY);
        assert_ne!(
            original,
            source_binding_capability("other", &digest).unwrap()
        );
        assert_ne!(
            original,
            source_binding_capability("fixture", &format!("sha256:{}", "b".repeat(64))).unwrap()
        );
        assert!(source_binding_capability("fixture", "sha256:short").is_err());
    }
}
