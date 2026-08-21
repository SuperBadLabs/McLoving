//! Shared domain vocabulary. Runtime behavior begins in later tickets.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Stable product name used by foundation binaries.
pub const PRODUCT_NAME: &str = "McLoving";

/// The scheduling capability vocabulary.
///
/// This module is the single code definition of the vocabulary documented in
/// `docs/architecture/CAPABILITY_VOCABULARY_V1.md`. Submissions, stored DAG
/// nodes, agent sessions, and the controller-embedded worker must all spell
/// capabilities through these constants so a configured worker can never
/// silently declare a token that no submission can ever require.
pub mod capability {
    use std::fmt;

    /// Prefix of every platform capability (`platform:linux`,
    /// `platform:windows`).
    pub const PLATFORM_CAPABILITY_PREFIX: &str = "platform:";

    /// The closed set of platforms a submission may require. The public API
    /// rejects any other platform value, so a capability outside
    /// `platform:<supported>` can never match a default submission.
    pub const SUPPORTED_PLATFORMS: [&str; 2] = ["linux", "windows"];

    /// Platform applied when a submission does not name one.
    pub const DEFAULT_PLATFORM: &str = "linux";

    /// The exact sentinel that disables the controller-embedded worker.
    ///
    /// It must be the only declared capability. A disabled embedded worker
    /// still performs expired-lease reconciliation but never claims work.
    pub const EMBEDDED_WORKER_DISABLED_SENTINEL: &str = "disabled";

    /// Spells the platform capability for one platform.
    #[must_use]
    pub fn platform_capability(platform: &str) -> String {
        format!("{PLATFORM_CAPABILITY_PREFIX}{platform}")
    }

    /// Reports whether a platform is inside the closed supported set.
    #[must_use]
    pub fn is_supported_platform(platform: &str) -> bool {
        SUPPORTED_PLATFORMS.contains(&platform)
    }

    /// Validated embedded-worker capability declaration.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum EmbeddedWorkerCapabilities {
        /// The exact disable sentinel was declared alone.
        Disabled,
        /// The declaration can satisfy at least one schedulable platform
        /// requirement.
        Schedulable(Vec<String>),
    }

    /// Named fail-closed rejection of an embedded-worker capability
    /// declaration.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum EmbeddedWorkerCapabilityError {
        /// No capabilities were declared.
        EmptyDeclaration,
        /// The disable sentinel was mixed with other capabilities.
        DisableSentinelNotAlone { declared: Vec<String> },
        /// No declared capability spells `platform:<supported>`, so no
        /// submission (including the default) could ever be claimed.
        NoSchedulablePlatform { declared: Vec<String> },
    }

    impl fmt::Display for EmbeddedWorkerCapabilityError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::EmptyDeclaration => write!(
                    formatter,
                    "EmbeddedWorkerCapabilityError::EmptyDeclaration: \
                     the embedded worker must declare at least one capability"
                ),
                Self::DisableSentinelNotAlone { declared } => write!(
                    formatter,
                    "EmbeddedWorkerCapabilityError::DisableSentinelNotAlone: \
                     the disable sentinel {EMBEDDED_WORKER_DISABLED_SENTINEL:?} \
                     must be the only declared capability, got {declared:?}"
                ),
                Self::NoSchedulablePlatform { declared } => write!(
                    formatter,
                    "EmbeddedWorkerCapabilityError::NoSchedulablePlatform: \
                     declared capabilities {declared:?} cannot satisfy any \
                     schedulable platform requirement; declare \
                     platform:linux or platform:windows, or exactly \
                     {EMBEDDED_WORKER_DISABLED_SENTINEL:?} to disable the \
                     embedded worker"
                ),
            }
        }
    }

    impl std::error::Error for EmbeddedWorkerCapabilityError {}

    /// Classifies an embedded-worker capability declaration against the
    /// vocabulary, failing closed on any set that could never claim work.
    pub fn classify_embedded_worker_capabilities(
        declared: &[String],
    ) -> Result<EmbeddedWorkerCapabilities, EmbeddedWorkerCapabilityError> {
        if declared.is_empty() {
            return Err(EmbeddedWorkerCapabilityError::EmptyDeclaration);
        }
        if declared
            .iter()
            .any(|capability| capability == EMBEDDED_WORKER_DISABLED_SENTINEL)
        {
            return if declared.len() == 1 {
                Ok(EmbeddedWorkerCapabilities::Disabled)
            } else {
                Err(EmbeddedWorkerCapabilityError::DisableSentinelNotAlone {
                    declared: declared.to_vec(),
                })
            };
        }
        let schedulable = SUPPORTED_PLATFORMS
            .iter()
            .any(|platform| declared.iter().any(|c| c == &platform_capability(platform)));
        if schedulable {
            Ok(EmbeddedWorkerCapabilities::Schedulable(declared.to_vec()))
        } else {
            Err(EmbeddedWorkerCapabilityError::NoSchedulablePlatform {
                declared: declared.to_vec(),
            })
        }
    }
}

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
    use super::capability::{
        DEFAULT_PLATFORM, EMBEDDED_WORKER_DISABLED_SENTINEL, EmbeddedWorkerCapabilities,
        EmbeddedWorkerCapabilityError, classify_embedded_worker_capabilities,
        is_supported_platform, platform_capability,
    };

    #[test]
    fn product_name_is_stable() {
        assert_eq!(PRODUCT_NAME, "McLoving");
    }

    #[test]
    fn default_platform_is_supported_and_spells_the_default_capability() {
        assert!(is_supported_platform(DEFAULT_PLATFORM));
        assert_eq!(platform_capability(DEFAULT_PLATFORM), "platform:linux");
        assert!(!is_supported_platform("macos"));
    }

    fn declared(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn every_deployed_declaration_stays_valid() {
        for accepted in [
            &["platform:linux"][..],
            &["platform:windows"][..],
            &["platform:linux", "gpu:cuda"][..],
        ] {
            let declared = declared(accepted);
            assert_eq!(
                classify_embedded_worker_capabilities(&declared),
                Ok(EmbeddedWorkerCapabilities::Schedulable(declared.clone())),
                "expected {declared:?} to stay schedulable"
            );
        }
        assert_eq!(
            classify_embedded_worker_capabilities(&declared(&[EMBEDDED_WORKER_DISABLED_SENTINEL])),
            Ok(EmbeddedWorkerCapabilities::Disabled)
        );
    }

    #[test]
    fn the_measured_misconfiguration_is_named() {
        let bare_linux = declared(&["linux"]);
        let error = classify_embedded_worker_capabilities(&bare_linux)
            .expect_err("bare linux must fail closed");
        assert_eq!(
            error,
            EmbeddedWorkerCapabilityError::NoSchedulablePlatform {
                declared: bare_linux
            }
        );
        assert!(
            error
                .to_string()
                .contains("EmbeddedWorkerCapabilityError::NoSchedulablePlatform"),
            "error must carry its stable name: {error}"
        );
    }

    #[test]
    fn unsupported_platform_prefix_fails_closed() {
        let macos = declared(&["platform:macos"]);
        assert_eq!(
            classify_embedded_worker_capabilities(&macos),
            Err(EmbeddedWorkerCapabilityError::NoSchedulablePlatform { declared: macos })
        );
    }

    #[test]
    fn the_disable_sentinel_must_stand_alone() {
        let mixed = declared(&["disabled", "platform:linux"]);
        assert_eq!(
            classify_embedded_worker_capabilities(&mixed),
            Err(EmbeddedWorkerCapabilityError::DisableSentinelNotAlone { declared: mixed })
        );
        assert_eq!(
            classify_embedded_worker_capabilities(&[]),
            Err(EmbeddedWorkerCapabilityError::EmptyDeclaration)
        );
    }
}
