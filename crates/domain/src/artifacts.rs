//! Declared build artifacts (PAR-014): a stage names sets of workspace files
//! by bounded glob patterns; after its steps the agent uploads every matching
//! regular file to the controller over its own mTLS channel, each object named
//! `<artifact name>/<workspace-relative path>`.

use serde::{Deserialize, Serialize};

/// Scheduler capability an agent advertises when it can collect and upload
/// declared artifacts; a stage that declares any requires it, so an older
/// agent is never offered such a node.
pub const ARTIFACT_UPLOAD_CAPABILITY: &str = "artifact-upload-v1";
/// Wire feature: the peer accepts the `UploadArtifact` client stream.
pub const ARTIFACT_UPLOAD_FEATURE: &str = "artifact-upload-v1";
/// Upper bound on artifact declarations in one stage.
pub const MAX_ARTIFACTS_PER_STAGE: usize = 16;
/// Upper bound on path patterns in one declaration.
pub const MAX_ARTIFACT_PATTERNS: usize = 32;
/// Longest declared artifact name.
pub const MAX_ARTIFACT_NAME_BYTES: usize = 128;
/// Longest path pattern.
pub const MAX_ARTIFACT_PATTERN_BYTES: usize = 512;
/// Longest object name (`<artifact name>/<workspace path>`), the store's own
/// bound on an artifact name.
pub const MAX_ARTIFACT_OBJECT_NAME_BYTES: usize = 512;
/// Upper bound on files one attempt uploads across all its declarations.
pub const MAX_ARTIFACT_FILES_PER_ATTEMPT: usize = 1_024;
/// Upper bound on bytes one attempt uploads across all its declarations,
/// enforced by the agent before the first upload and by the store at every
/// registration.
pub const MAX_ATTEMPT_ARTIFACT_BYTES: u64 = 256 * 1_048_576;
/// Largest data frame on the upload stream.
pub const MAX_ARTIFACT_FRAME_BYTES: usize = 1_048_576;
/// Deepest directory the collector descends into below the workspace.
pub const MAX_ARTIFACT_WALK_DEPTH: usize = 32;
/// Most directory entries the collector visits before refusing the set.
pub const MAX_ARTIFACT_WALK_ENTRIES: usize = 65_536;
/// The controller's refusal of an upload whose bytes do not hash to the
/// declared digest; the agent reads it back as the step's own doing.
pub const ARTIFACT_DIGEST_MISMATCH: &str = "artifact bytes do not match the declared digest";
/// Media type every collected artifact is registered under.
pub const ARTIFACT_MEDIA_TYPE: &str = "application/octet-stream";
/// Retention the agent requests for a collected artifact.
pub const ARTIFACT_RETENTION_SECONDS: i64 = 30 * 24 * 60 * 60;
/// Seconds the controller allows an upload stream per MiB declared, and the
/// agent adds to its lease-sized RPC budget per MiB sent.
pub const ARTIFACT_UPLOAD_SECONDS_PER_MIB: u64 = 1;
/// Seconds the controller allows an upload stream before its first MiB.
pub const ARTIFACT_UPLOAD_BASE_SECONDS: u64 = 30;
/// Longest any one upload may take, on either side.
pub const MAX_ARTIFACT_UPLOAD_SECONDS: u64 = 15 * 60;

/// The receive or send budget for an upload of `bytes`: the base plus one
/// second per MiB, bounded.
#[must_use]
pub fn artifact_upload_seconds(bytes: u64) -> u64 {
    ARTIFACT_UPLOAD_BASE_SECONDS
        .saturating_add(
            bytes
                .div_ceil(1_048_576)
                .saturating_mul(ARTIFACT_UPLOAD_SECONDS_PER_MIB),
        )
        .min(MAX_ARTIFACT_UPLOAD_SECONDS)
}

/// One declared artifact: a name and the workspace-relative patterns whose
/// matching regular files it collects.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSpec {
    pub name: String,
    pub paths: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid artifact declaration: {0}")]
pub struct ArtifactSpecError(pub &'static str);

impl ArtifactSpec {
    pub fn validate(&self) -> Result<(), ArtifactSpecError> {
        validate_name(&self.name)?;
        if self.paths.is_empty() {
            return Err(ArtifactSpecError("at least one path pattern is required"));
        }
        if self.paths.len() > MAX_ARTIFACT_PATTERNS {
            return Err(ArtifactSpecError("too many path patterns"));
        }
        for pattern in &self.paths {
            validate_pattern(pattern)?;
        }
        Ok(())
    }

    /// Whether a workspace-relative path in `/` form matches any pattern.
    #[must_use]
    pub fn matches(&self, path: &str) -> bool {
        self.paths
            .iter()
            .any(|pattern| pattern_matches(pattern, path))
    }
}

/// Validates a stage's whole declaration list: bounded, every entry valid,
/// names unique.
pub fn validate_declarations(specs: &[ArtifactSpec]) -> Result<(), ArtifactSpecError> {
    if specs.len() > MAX_ARTIFACTS_PER_STAGE {
        return Err(ArtifactSpecError("too many artifact declarations"));
    }
    for (index, spec) in specs.iter().enumerate() {
        spec.validate()?;
        if specs[..index].iter().any(|other| other.name == spec.name) {
            return Err(ArtifactSpecError(
                "artifact names must be unique within a stage",
            ));
        }
    }
    Ok(())
}

/// A name is one to 128 ASCII letters, digits, dots, underscores or hyphens,
/// not starting with a dot: it heads every object name and must survive as
/// a path component and a URL query value unchanged.
pub fn validate_name(name: &str) -> Result<(), ArtifactSpecError> {
    if name.is_empty() || name.len() > MAX_ARTIFACT_NAME_BYTES {
        return Err(ArtifactSpecError("artifact name must be 1 to 128 bytes"));
    }
    if name.starts_with('.') {
        return Err(ArtifactSpecError("artifact name must not start with a dot"));
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ArtifactSpecError(
            "artifact name must contain only ASCII letters, digits, dot, underscore, or hyphen",
        ));
    }
    Ok(())
}

/// The pattern dialect: `/`-separated segments; a segment `**` matches zero
/// or more whole segments; within a segment `*` matches any run of
/// characters and `?` exactly one; everything else is literal. Relative to
/// the workspace, never absolute, never `.` or `..`, no backslashes and no
/// control characters.
pub fn validate_pattern(pattern: &str) -> Result<(), ArtifactSpecError> {
    if pattern.is_empty() || pattern.len() > MAX_ARTIFACT_PATTERN_BYTES {
        return Err(ArtifactSpecError("path pattern must be 1 to 512 bytes"));
    }
    if pattern.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(ArtifactSpecError(
            "path pattern contains a control character",
        ));
    }
    if pattern.contains('\\') {
        return Err(ArtifactSpecError("path pattern must use forward slashes"));
    }
    if pattern.starts_with('/') {
        return Err(ArtifactSpecError("path pattern must be workspace-relative"));
    }
    for segment in pattern.split('/') {
        if segment.is_empty() {
            return Err(ArtifactSpecError("path pattern has an empty segment"));
        }
        if segment == "." || segment == ".." {
            return Err(ArtifactSpecError("path pattern must not name . or .."));
        }
        if segment.contains("**") && segment != "**" {
            return Err(ArtifactSpecError(
                "** must stand alone as a whole path segment",
            ));
        }
    }
    Ok(())
}

/// The pattern's segments with consecutive `**` collapsed to one: the two
/// forms match the same paths, and the matcher's table is sized by the
/// collapsed length.
fn normalized_segments(pattern: &str) -> Vec<&str> {
    let mut segments: Vec<&str> = Vec::new();
    for segment in pattern.split('/') {
        if segment == "**" && segments.last() == Some(&"**") {
            continue;
        }
        segments.push(segment);
    }
    segments
}

/// Whether the pattern could match something strictly below the directory
/// at `dir` (workspace-relative, `/` form): the walk descends only into
/// such directories and refuses a link in their place before looking below.
/// A table over (pattern segment, path segment), so the work is the product
/// of the two lengths whatever the pattern's shape.
#[must_use]
pub fn pattern_may_descend(pattern: &str, dir: &str) -> bool {
    let pattern = normalized_segments(pattern);
    let dir: Vec<&str> = dir.split('/').collect();
    let (m, n) = (pattern.len(), dir.len());
    // table[i][j]: pattern[i..] can match something strictly below dir[j..].
    let mut table = vec![vec![false; n + 1]; m + 1];
    for i in (0..m).rev() {
        for j in (0..=n).rev() {
            table[i][j] = if j == n {
                // The directory is fully matched and pattern remains: a
                // deeper entry can still match.
                true
            } else if pattern[i] == "**" {
                table[i + 1][j] || table[i][j + 1]
            } else {
                segment_matches(pattern[i], dir[j]) && table[i + 1][j + 1]
            };
        }
    }
    table[0][0]
}

/// Whether a workspace-relative path in `/` form matches the pattern. A
/// table over (pattern segment, path segment), so a pattern of many `**`
/// segments costs their product, never a combinatorial search.
#[must_use]
pub fn pattern_matches(pattern: &str, path: &str) -> bool {
    let pattern = normalized_segments(pattern);
    let path: Vec<&str> = path.split('/').collect();
    let (m, n) = (pattern.len(), path.len());
    // table[i][j]: pattern[i..] matches path[j..] exactly.
    let mut table = vec![vec![false; n + 1]; m + 1];
    table[m][n] = true;
    for i in (0..m).rev() {
        for j in (0..=n).rev() {
            table[i][j] = if pattern[i] == "**" {
                table[i + 1][j] || (j < n && table[i][j + 1])
            } else {
                j < n && segment_matches(pattern[i], path[j]) && table[i + 1][j + 1]
            };
        }
    }
    table[0][0]
}

fn segment_matches(pattern: &str, name: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let name: Vec<char> = name.chars().collect();
    let (mut p, mut n) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while n < name.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == name[n]) {
            p += 1;
            n += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some((p, n));
            p += 1;
        } else if let Some((star_p, star_n)) = star {
            p = star_p + 1;
            n = star_n + 1;
            star = Some((star_p, star_n + 1));
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns_match_segments_and_recursive_globs() {
        assert!(pattern_matches(
            "target/**/*.log",
            "target/debug/build/x.log"
        ));
        assert!(pattern_matches("target/**/*.log", "target/x.log"));
        assert!(!pattern_matches("target/**/*.log", "other/x.log"));
        assert!(!pattern_matches("target/*.log", "target/debug/x.log"));
        assert!(pattern_matches("**/*.txt", "a.txt"));
        assert!(pattern_matches("**", "any/depth/at/all"));
        assert!(pattern_matches("report-?.xml", "report-1.xml"));
        assert!(!pattern_matches("report-?.xml", "report-10.xml"));
        assert!(pattern_matches("a*b*c", "aXXbYYc"));
        assert!(!pattern_matches("a*b*c", "aXXbYY"));
        // A wildcard never crosses a separator.
        assert!(!pattern_matches("*.log", "dir/x.log"));
    }

    #[test]
    fn matching_is_bounded_for_patterns_of_many_globstars() {
        // Roughly 170 `**` segments fit the pattern bound; against a
        // depth-32 non-matching path a recursive matcher would search
        // combinatorially many splits. The table finishes at once.
        let many = format!("{}absent", "**/".repeat(170));
        let path = (0..32).map(|_| "d").collect::<Vec<_>>().join("/");
        let started = std::time::Instant::now();
        assert!(!pattern_matches(&many, &path));
        assert!(pattern_may_descend(&many, &path));
        let alternating = (0..80).map(|_| "**/x").collect::<Vec<_>>().join("/");
        let path = (0..32).map(|_| "x").collect::<Vec<_>>().join("/");
        assert!(!pattern_matches(&alternating, &path));
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        assert!(pattern_matches("a/**/**/b", "a/b"));
        assert!(pattern_matches("a/**/**/b", "a/x/y/b"));
        assert_eq!(normalized_segments("a/**/**/**/b"), ["a", "**", "b"]);
    }

    #[test]
    fn descent_is_pruned_to_directories_a_pattern_can_enter() {
        assert!(pattern_may_descend("target/**/*.log", "target"));
        assert!(pattern_may_descend("target/**/*.log", "target/debug/deep"));
        assert!(!pattern_may_descend("target/**/*.log", "other"));
        assert!(pattern_may_descend("**/*.log", "anything/at/all"));
        assert!(pattern_may_descend("a/*/c", "a/b"));
        assert!(!pattern_may_descend("a/*/c", "a/b/c"));
        assert!(!pattern_may_descend("a/b", "a/b"));
        assert!(pattern_may_descend("out*/*", "outward"));
    }

    #[test]
    fn declarations_are_bounded_and_relative() {
        let ok = ArtifactSpec {
            name: "target-logs".to_owned(),
            paths: vec!["target/**/*.log".to_owned()],
        };
        assert!(ok.validate().is_ok());
        for pattern in [
            "",
            "/abs/*.log",
            "../escape/*",
            "a/./b",
            "a//b",
            "a\\b",
            "a**/b",
            "a/b/",
            "bad\u{7}",
        ] {
            assert!(validate_pattern(pattern).is_err(), "{pattern:?}");
        }
        for name in ["", ".hidden", "with space", "a/b", &"x".repeat(129)] {
            assert!(validate_name(name).is_err(), "{name:?}");
        }
        let duplicate = vec![ok.clone(), ok.clone()];
        assert!(validate_declarations(&duplicate).is_err());
        let too_many = vec![ok.clone(); MAX_ARTIFACTS_PER_STAGE + 1];
        assert!(validate_declarations(&too_many).is_err());
        let empty = ArtifactSpec {
            name: "empty".to_owned(),
            paths: Vec::new(),
        };
        assert!(empty.validate().is_err());
    }
}
