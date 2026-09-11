//! Build notifications (PAR-004): a pipeline names the targets a build's
//! terminal outcome is delivered to, each only by the mapping id of a
//! deployment-owned notification mapping. The mapping, not the pipeline,
//! binds the credential to what it may act on: the exact repository a GitHub
//! commit status may be written to, or the exact destination of a signed
//! HTTPS webhook.

use serde::{Deserialize, Serialize};

/// Upper bound on targets one pipeline names.
pub const MAX_NOTIFY_TARGETS: usize = 8;
/// Longest commit-status context.
pub const MAX_STATUS_CONTEXT_BYTES: usize = 255;
/// Context a GitHub commit status is written under when the pipeline names
/// none.
pub const DEFAULT_STATUS_CONTEXT: &str = "mcloving";
/// Attempts before a delivery is abandoned.
pub const MAX_DELIVERY_ATTEMPTS: i32 = 12;
/// Longest wait between two attempts, in seconds.
pub const MAX_DELIVERY_BACKOFF_SECONDS: u64 = 3600;
/// Bound on one delivery attempt end to end, in seconds.
pub const DELIVERY_DEADLINE_SECONDS: u64 = 30;
/// How long a claim keeps its row off every other worker's scan: longer than
/// the deadline, so an attempt still in flight is never claimed twice.
pub const CLAIM_LEASE_SECONDS: u64 = 3 * DELIVERY_DEADLINE_SECONDS;
const _: () = assert!(CLAIM_LEASE_SECONDS > DELIVERY_DEADLINE_SECONDS);
/// Longest body a notification target may answer with before the answer is
/// discarded unread.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// One notification target as a pipeline declares it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NotifyTarget {
    /// A GitHub commit status on `commit` under `context`, written to the
    /// repository the mapping names; a pipeline may name the repository too,
    /// and then it must be the mapping's.
    GithubStatus {
        mapping_id: String,
        commit: String,
        context: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        repository: Option<String>,
    },
    /// A signed HTTPS POST of the build's terminal record to the destination
    /// the mapping names.
    Webhook { mapping_id: String },
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid notification target: {0}")]
pub struct NotifyTargetError(pub &'static str);

impl NotifyTarget {
    #[must_use]
    pub fn mapping_id(&self) -> &str {
        match self {
            Self::GithubStatus { mapping_id, .. } | Self::Webhook { mapping_id } => mapping_id,
        }
    }

    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::GithubStatus { .. } => "github_status",
            Self::Webhook { .. } => "webhook",
        }
    }

    pub fn validate(&self) -> Result<(), NotifyTargetError> {
        if !crate::cache_intent::canonical_mapping_id(self.mapping_id()) {
            return Err(NotifyTargetError("mapping identifier"));
        }
        if let Self::GithubStatus {
            commit,
            context,
            repository,
            ..
        } = self
        {
            if !is_commit_id(commit) {
                return Err(NotifyTargetError(
                    "commit must be 7 to 128 lowercase hexadecimal digits",
                ));
            }
            if !is_status_context(context) {
                return Err(NotifyTargetError(
                    "context must be 1 to 255 printable ASCII characters without leading or trailing whitespace",
                ));
            }
            if let Some(repository) = repository
                && !is_repository_identity(repository)
            {
                return Err(NotifyTargetError("repository must be owner/name"));
            }
        }
        Ok(())
    }
}

/// Validates a pipeline's whole target list: bounded, every target valid.
pub fn validate_targets(targets: &[NotifyTarget]) -> Result<(), NotifyTargetError> {
    if targets.len() > MAX_NOTIFY_TARGETS {
        return Err(NotifyTargetError("too many notification targets"));
    }
    for target in targets {
        target.validate()?;
    }
    Ok(())
}

/// A commit object id: 7 to 128 lowercase hexadecimal digits (a parameter
/// supplied by a webhook delivery is already lowercase).
#[must_use]
pub fn is_commit_id(value: &str) -> bool {
    (7..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[must_use]
pub fn is_status_context(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_STATUS_CONTEXT_BYTES
        && value.trim() == value
        && value.bytes().all(|byte| (0x20..0x7f).contains(&byte))
}

/// `owner/name`, each part 1 to 100 ASCII letters, digits, dots, underscores
/// or hyphens, exactly one slash.
#[must_use]
pub fn is_repository_identity(value: &str) -> bool {
    let Some((owner, name)) = value.split_once('/') else {
        return false;
    };
    [owner, name].iter().all(|part| {
        (1..=100).contains(&part.len())
            && !part.starts_with('.')
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_are_bounded_and_shaped() {
        let status = NotifyTarget::GithubStatus {
            mapping_id: "github.mcloving".to_owned(),
            commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            context: "mcloving/foundation".to_owned(),
            repository: Some("SuperBadLabs/McLoving".to_owned()),
        };
        assert!(status.validate().is_ok());
        let webhook = NotifyTarget::Webhook {
            mapping_id: "hooks.team".to_owned(),
        };
        assert!(webhook.validate().is_ok());
        assert!(validate_targets(&vec![webhook.clone(); MAX_NOTIFY_TARGETS + 1]).is_err());
        for (commit, context, repository) in [
            ("ABCDEF1", "ctx", None),
            ("012345", "ctx", None),
            ("0123456", "", None),
            ("0123456", " padded", None),
            ("0123456", "tab\there", None),
            ("0123456", "ctx", Some("no-slash")),
            ("0123456", "ctx", Some("owner/")),
            ("0123456", "ctx", Some("owner/.dot")),
        ] {
            let bad = NotifyTarget::GithubStatus {
                mapping_id: "github.mcloving".to_owned(),
                commit: commit.to_owned(),
                context: context.to_owned(),
                repository: repository.map(str::to_owned),
            };
            assert!(
                bad.validate().is_err(),
                "{commit} {context:?} {repository:?}"
            );
        }
        assert!(
            NotifyTarget::Webhook {
                mapping_id: "Not Canonical".to_owned()
            }
            .validate()
            .is_err()
        );
    }
}
