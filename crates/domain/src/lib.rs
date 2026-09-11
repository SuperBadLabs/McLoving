//! Shared domain vocabulary. Runtime behavior begins in later tickets.

pub mod cache_intent;
pub mod input_intent;
pub mod source_intent;
pub mod workspace;

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
        /// A capability claims the reserved `platform:` namespace but names a
        /// platform outside the closed set.
        UnsupportedPlatform {
            capability: String,
            platform: String,
        },
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
                Self::UnsupportedPlatform {
                    capability,
                    platform,
                } => write!(
                    formatter,
                    "EmbeddedWorkerCapabilityError::UnsupportedPlatform: \
                     capability {capability:?} names platform {platform:?}, \
                     which is outside the supported set \
                     {SUPPORTED_PLATFORMS:?}; the {PLATFORM_CAPABILITY_PREFIX:?} \
                     namespace is closed, so no submission can ever require it"
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
        // The `platform:` namespace is closed, so a token inside it that names
        // an unsupported platform is refused rather than ignored. Accepting it
        // because some *other* declared platform is schedulable would leave the
        // configuration surface silently lying about a capability no submission
        // can ever require — the failure this ticket removes.
        for capability in declared {
            if let Some(platform) = capability.strip_prefix(PLATFORM_CAPABILITY_PREFIX)
                && !is_supported_platform(platform)
            {
                return Err(EmbeddedWorkerCapabilityError::UnsupportedPlatform {
                    capability: capability.clone(),
                    platform: platform.to_owned(),
                });
            }
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
        // Named for what is actually wrong: the token claims the closed
        // namespace, rather than merely failing to schedule.
        assert_eq!(
            classify_embedded_worker_capabilities(&macos),
            Err(EmbeddedWorkerCapabilityError::UnsupportedPlatform {
                capability: platform_capability("macos"),
                platform: "macos".to_owned(),
            })
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

    /// The `platform:` namespace is closed. A token inside it naming an
    /// unsupported platform must be refused even when another declared
    /// platform would schedule, or the configuration surface still accepts a
    /// capability no submission can ever require.
    #[test]
    fn an_unsupported_platform_capability_is_refused_even_alongside_a_supported_one() {
        for declared in [
            vec![platform_capability("linux"), platform_capability("macos")],
            vec![platform_capability("macos"), platform_capability("linux")],
        ] {
            assert_eq!(
                classify_embedded_worker_capabilities(&declared),
                Err(EmbeddedWorkerCapabilityError::UnsupportedPlatform {
                    capability: platform_capability("macos"),
                    platform: "macos".to_owned(),
                }),
                "declared {declared:?}"
            );
        }
        // A capability outside the reserved namespace is not the classifier's
        // business, so it still schedules alongside a supported platform.
        assert!(matches!(
            classify_embedded_worker_capabilities(&[
                platform_capability("linux"),
                "gpu".to_owned(),
            ]),
            Ok(EmbeddedWorkerCapabilities::Schedulable(_))
        ));
    }
}

/// Live log streaming (PAR-013): an agent publishes a step's output while
/// the step runs, each chunk's sequence reserved in its journal before it is
/// sent, and the controller lets a reader follow a build's log by one global
/// cursor with a bounded wait.
pub mod live_logs {
    /// Wire feature: the peer streams log chunks while a step runs and
    /// accepts the raised per-attempt chunk bound.
    pub const LIVE_LOG_STREAM_FEATURE: &str = "live-log-stream-v1";
    /// Exclusive upper bound on a log chunk sequence for a session that
    /// negotiated the feature; the 96-chunk terminal bound stays for every
    /// other session. Chunks may be as small as one poll interval's output,
    /// so an attempt at the 64 MiB byte quota needs room for many more of
    /// them than the terminal pass ever produced.
    pub const MAX_LIVE_ATTEMPT_LOG_CHUNKS: i64 = 8_192;
    /// Longest a follower may wait on one request for new chunks.
    pub const MAX_FOLLOW_WAIT_MS: u64 = 30_000;
}

/// Multi-step stages: one node and one attempt per stage, several ordered
/// process steps inside the attempt, distinguished in durable truth by a step
/// ordinal rather than by a second attempt.
pub mod multi_step {
    /// Scheduler capability a node requires when its stage carries more than
    /// one step. Only an agent that can run the version-5 envelope advertises
    /// it, so an older agent is never offered such a node and never has to
    /// refuse it.
    pub const MULTI_STEP_CAPABILITY: &str = "multi-step-v1";
    /// Wire feature: the peer understands the version-5 execution envelope
    /// and the `step_ordinal` field on log chunks.
    pub const MULTI_STEP_EXECUTION_FEATURE: &str = "multi-step-execution-v1";
    /// Upper bound on steps in one stage. Sixteen keeps the terminal summary
    /// far below its 64 KiB cap and bounds the spool count per attempt.
    pub const MAX_STEPS_PER_STAGE: usize = 16;
    /// Exclusive upper bound on a step ordinal carried on the wire and stored
    /// in PostgreSQL; the schema check mirrors it.
    pub const MAX_STEP_ORDINAL_EXCLUSIVE: u32 = 65_536;
}

/// Container stages (PAR-011): a stage that names a digest-pinned image runs
/// every step under rootless podman with the attempt workspace bind-mounted
/// and nothing else of the host.
pub mod container {
    /// Scheduler capability an agent advertises only when its configured
    /// podman answers; a stage with an image requires it.
    pub const CONTAINER_CAPABILITY: &str = "container-podman-v1";
    /// Longest accepted image reference.
    pub const MAX_IMAGE_REFERENCE_BYTES: usize = 512;

    /// Accepts only `[registry[:port]/]path@sha256:<64 hex>`: a tag can move,
    /// a digest cannot, so a tagged reference is refused rather than pulled.
    #[must_use]
    pub fn is_digest_pinned_image(reference: &str) -> bool {
        if reference.is_empty() || reference.len() > MAX_IMAGE_REFERENCE_BYTES {
            return false;
        }
        let Some((name, digest)) = reference.split_once('@') else {
            return false;
        };
        let Some(hex) = digest.strip_prefix("sha256:") else {
            return false;
        };
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return false;
        }
        let mut components = name.split('/');
        let Some(first) = components.next() else {
            return false;
        };
        let rest: Vec<&str> = components.collect();
        // The first component may be a registry host with a port; every other
        // component is a plain repository path element without a tag colon.
        // Reference parsing treats a first component that contains a dot or
        // is `localhost` as a registry domain, and a domain needs a `/repo`
        // path after it; `docker.io@sha256:...` names no repository at all.
        let looks_like_registry = first.contains('.') || first == "localhost";
        let host_ok = if let Some((host, port)) = first.split_once(':') {
            !rest.is_empty()
                && host_like(host)
                && !port.is_empty()
                && port.bytes().all(|byte| byte.is_ascii_digit())
        } else if looks_like_registry {
            !rest.is_empty() && host_like(first)
        } else {
            path_like(first)
        };
        host_ok && !name.ends_with('/') && rest.iter().all(|component| path_like(component))
    }

    fn host_like(component: &str) -> bool {
        !component.is_empty()
            && component.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.' || byte == b'-'
            })
    }

    fn path_like(component: &str) -> bool {
        !component.is_empty()
            && component.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'-' | b'_')
            })
    }

    #[cfg(test)]
    mod tests {
        use super::is_digest_pinned_image;

        #[test]
        fn digest_pinned_references_are_accepted_and_tags_refused() {
            let digest = "c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e";
            assert!(is_digest_pinned_image(&format!(
                "docker.io/library/alpine@sha256:{digest}"
            )));
            assert!(is_digest_pinned_image(&format!("alpine@sha256:{digest}")));
            assert!(is_digest_pinned_image(&format!(
                "registry.local:5000/team/tool@sha256:{digest}"
            )));
            assert!(!is_digest_pinned_image("docker.io/library/alpine:3.20"));
            assert!(!is_digest_pinned_image(&format!(
                "docker.io/library/alpine:3.20@sha256:{digest}"
            )));
            assert!(!is_digest_pinned_image("alpine@sha256:abc"));
            assert!(!is_digest_pinned_image(&format!("Alpine@sha256:{digest}")));
            assert!(!is_digest_pinned_image(&format!("@sha256:{digest}")));
            assert!(!is_digest_pinned_image(&format!(
                "registry:5000@sha256:{digest}"
            )));
            // A lone registry-looking component names no repository.
            assert!(!is_digest_pinned_image(&format!(
                "docker.io@sha256:{digest}"
            )));
            assert!(!is_digest_pinned_image(&format!(
                "localhost@sha256:{digest}"
            )));
            assert!(is_digest_pinned_image(&format!(
                "localhost/tool@sha256:{digest}"
            )));
            assert!(is_digest_pinned_image(&format!(
                "my.registry.example/team/tool@sha256:{digest}"
            )));
        }
    }
}
