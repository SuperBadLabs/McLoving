//! Shared domain vocabulary. Runtime behavior begins in later tickets.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Stable product name used by foundation binaries.
pub const PRODUCT_NAME: &str = "McLoving";

/// One deployment-resolved external-effect intent, exactly as it appears in a
/// version-2 execution specification.
///
/// This lives in the shared vocabulary because two independent workers must
/// agree on it: the embedded spine decodes it to execute the effect, and the
/// process-only agent decodes it to decide whether the payload is runnable by
/// some other runtime or by none at all. A second copy of this schema would
/// drift, and a drifted copy makes one worker decline work the other would
/// terminalize.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorIntentSpec {
    pub mapping_id: String,
    pub mapping_digest: String,
    pub effect_class: ConnectorEffectClass,
    pub effect_key_template: String,
    pub public_input_schema: BTreeMap<String, JsonFieldType>,
    pub protected_secret_ref_schema: BTreeMap<String, JsonFieldType>,
    pub expected_public_result_schema: BTreeMap<String, JsonFieldType>,
    pub timeout_seconds: u64,
    pub ambiguity_policy: AmbiguityPolicy,
    pub downstream_control_digest: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorEffectClass {
    Idempotent,
    ExternallyIdempotent,
    NonIdempotent,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JsonFieldType {
    Array,
    Boolean,
    Null,
    Number,
    Object,
    String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AmbiguityPolicy {
    ObserveThenReconcile,
}

#[cfg(test)]
mod tests {
    use super::PRODUCT_NAME;

    #[test]
    fn product_name_is_stable() {
        assert_eq!(PRODUCT_NAME, "McLoving");
    }
}
