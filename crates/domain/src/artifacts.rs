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
/// Whole-set publication; v1 peers must not execute declared artifact work.
pub const ARTIFACT_SET_FEATURE: &str = "artifact-set-v2";
pub const MAX_ARTIFACT_MATCHING_CELLS: u64 = 8_388_608;
pub const ARTIFACT_COMMIT_HEADROOM_SECONDS: u64 = 60;
pub const ARTIFACT_RESPONSE_MARGIN_SECONDS: u64 = 5;
pub const ARTIFACT_READER_JOIN_SECONDS: u64 = 2;
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

/// One stage compilation, shared by collection and descent.
#[derive(Debug)]
pub struct CompiledArtifacts {
    declarations: Vec<(String, Vec<CompiledPattern>)>,
}
#[derive(Debug)]
pub struct CompiledPattern {
    segments: Vec<Segment>,
}
#[derive(Debug)]
enum Segment {
    Recursive,
    Literal(Vec<char>),
}
#[derive(Clone, Debug)]
pub struct MatchingBudget {
    remaining: u64,
    spent: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatchingBudgetSpent;
impl MatchingBudget {
    pub fn new(cells: u64) -> Self {
        Self {
            remaining: cells,
            spent: 0,
        }
    }
    pub fn spent(&self) -> u64 {
        self.spent
    }
    fn charge(&mut self) -> Result<(), MatchingBudgetSpent> {
        if self.remaining == 0 {
            return Err(MatchingBudgetSpent);
        }
        self.remaining -= 1;
        self.spent += 1;
        Ok(())
    }
}
impl CompiledArtifacts {
    pub fn new(specs: &[ArtifactSpec]) -> Self {
        Self {
            declarations: specs
                .iter()
                .map(|s| {
                    (
                        s.name.clone(),
                        s.paths.iter().map(|p| CompiledPattern::new(p)).collect(),
                    )
                })
                .collect(),
        }
    }
    /// Returns matched declaration names and whether any pattern permits descent.
    /// Every evaluation, including descent, uses this attempt's same budget.
    pub fn classify<'a>(
        &'a self,
        path: &str,
        budget: &mut MatchingBudget,
    ) -> Result<(Vec<&'a str>, bool), MatchingBudgetSpent> {
        let segments: Vec<&str> = path.split('/').collect();
        let mut names = Vec::new();
        let mut descends = false;
        for (name, patterns) in &self.declarations {
            let mut matched = false;
            for pattern in patterns {
                if !matched {
                    matched = pattern.evaluate(&segments, false, budget)?;
                }
                if !descends {
                    descends = pattern.evaluate(&segments, true, budget)?;
                }
            }
            if matched {
                names.push(name.as_str());
            }
        }
        Ok((names, descends))
    }
}
#[cfg(test)]
thread_local! { static COMPILED_PATTERN_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }
impl CompiledPattern {
    pub fn new(pattern: &str) -> Self {
        #[cfg(test)]
        COMPILED_PATTERN_COUNT.with(|n| n.set(n.get() + 1));
        let mut segments = Vec::new();
        for s in pattern.split('/') {
            if s == "**" {
                if !matches!(segments.last(), Some(Segment::Recursive)) {
                    segments.push(Segment::Recursive);
                }
            } else {
                segments.push(Segment::Literal(s.chars().collect()));
            }
        }
        Self { segments }
    }
    pub fn evaluate(
        &self,
        path: &[&str],
        descent: bool,
        budget: &mut MatchingBudget,
    ) -> Result<bool, MatchingBudgetSpent> {
        let n = path.len();
        let mut next = Vec::with_capacity(n + 1);
        for j in 0..=n {
            budget.charge()?;
            next.push(!descent && j == n);
        }
        for segment in self.segments.iter().rev() {
            let mut row = vec![false; n + 1];
            for j in (0..=n).rev() {
                budget.charge()?;
                row[j] = if descent && j == n {
                    true
                } else {
                    match segment {
                        Segment::Recursive => next[j] || (j < n && row[j + 1]),
                        Segment::Literal(p) => {
                            j < n && next[j + 1] && segment_matches_compiled(p, path[j], budget)?
                        }
                    }
                };
            }
            next = row;
        }
        Ok(next[0])
    }
}
fn segment_matches_compiled(
    pattern: &[char],
    name: &str,
    budget: &mut MatchingBudget,
) -> Result<bool, MatchingBudgetSpent> {
    // Wildcard backtracking/token comparisons share the same aggregate limit:
    // counting DP cells alone must not hide long literal-segment work.
    let mut chars = Vec::new();
    for c in name.chars() {
        budget.charge()?;
        chars.push(c);
    }
    let name = chars;
    let (mut p, mut n) = (0, 0);
    let mut star = None;
    while n < name.len() {
        budget.charge()?;
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == name[n]) {
            p += 1;
            n += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some((p, n));
            p += 1;
        } else if let Some((sp, sn)) = star {
            p = sp + 1;
            n = sn + 1;
            star = Some((sp, sn + 1));
        } else {
            return Ok(false);
        }
    }
    while p < pattern.len() && pattern[p] == '*' {
        budget.charge()?;
        p += 1;
    }
    Ok(p == pattern.len())
}
#[must_use]
pub fn pattern_matches(pattern: &str, path: &str) -> bool {
    CompiledPattern::new(pattern)
        .evaluate(
            &path.split('/').collect::<Vec<_>>(),
            false,
            &mut MatchingBudget::new(u64::MAX),
        )
        .unwrap_or(false)
}
#[must_use]
pub fn pattern_may_descend(pattern: &str, path: &str) -> bool {
    CompiledPattern::new(pattern)
        .evaluate(
            &path.split('/').collect::<Vec<_>>(),
            true,
            &mut MatchingBudget::new(u64::MAX),
        )
        .unwrap_or(false)
}
/// Bounded immutable set manifest. Digests are bound when each member is staged.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArtifactManifestMember {
    pub name: String,
    pub bytes: u64,
    pub media_type: String,
}
pub fn validate_manifest(members: &[ArtifactManifestMember]) -> Result<u64, ArtifactSpecError> {
    if members.len() > MAX_ARTIFACT_FILES_PER_ATTEMPT {
        return Err(ArtifactSpecError("too many artifact members"));
    }
    let mut total = 0_u64;
    let mut names = std::collections::BTreeSet::new();
    for member in members {
        if member.name.is_empty()
            || member.name.len() > MAX_ARTIFACT_OBJECT_NAME_BYTES
            || member.name.chars().any(char::is_control)
            || member.media_type != ARTIFACT_MEDIA_TYPE
            || !names.insert(&member.name)
        {
            return Err(ArtifactSpecError("invalid or duplicate artifact member"));
        }
        total = total
            .checked_add(member.bytes)
            .ok_or(ArtifactSpecError("artifact bytes overflow"))?;
        if total > MAX_ATTEMPT_ARTIFACT_BYTES {
            return Err(ArtifactSpecError("artifact byte quota"));
        }
    }
    Ok(total)
}
pub fn artifact_manifest_digest(members: &[ArtifactManifestMember]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut sorted = members.to_vec();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let mut digest = Sha256::new();
    digest.update(b"mcloving.artifact-set.v2\0");
    for m in sorted {
        for value in [m.name.as_bytes(), m.media_type.as_bytes()] {
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value);
        }
        digest.update(m.bytes.to_be_bytes());
    }
    digest.finalize().into()
}
pub fn artifact_server_seconds(bytes: u64) -> u64 {
    artifact_upload_seconds(bytes) + ARTIFACT_UPLOAD_BASE_SECONDS + ARTIFACT_COMMIT_HEADROOM_SECONDS
}
pub fn artifact_client_seconds(bytes: u64) -> u64 {
    artifact_server_seconds(bytes) + ARTIFACT_RESPONSE_MARGIN_SECONDS
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
        assert_eq!(CompiledPattern::new("a/**/**/**/b").segments.len(), 3);
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

#[cfg(test)]
mod agent012_tests {
    use super::*;
    #[test]
    fn shared_patterns_charge_matching_and_descent_without_recompilation() {
        let specs = vec![
            ArtifactSpec {
                name: "logs".into(),
                paths: vec!["a/**/x?.log".into(), "**/*.txt".into()],
            },
            ArtifactSpec {
                name: "all".into(),
                paths: vec!["**".into()],
            },
        ];
        let before_compile = COMPILED_PATTERN_COUNT.with(|n| n.get());
        let compiled = CompiledArtifacts::new(&specs);
        let after_compile = COMPILED_PATTERN_COUNT.with(|n| n.get());
        assert_eq!(after_compile - before_compile, 3);
        let address = compiled.declarations[0].1.as_ptr();
        let mut budget = MatchingBudget::new(10_000);
        assert_eq!(
            compiled.classify("a/b/x1.log", &mut budget).unwrap(),
            (vec!["logs", "all"], true)
        );
        let before = budget.spent();
        assert_eq!(
            compiled.classify("a/b/readme.txt", &mut budget).unwrap(),
            (vec!["logs", "all"], true)
        );
        assert!(budget.spent() > before);
        assert_eq!(address, compiled.declarations[0].1.as_ptr());
        assert_eq!(
            COMPILED_PATTERN_COUNT.with(|n| n.get()),
            after_compile,
            "matching/descent recompiled a pattern"
        );
        let mut tiny = MatchingBudget::new(1);
        assert_eq!(
            compiled.classify("a/b/x1.log", &mut tiny),
            Err(MatchingBudgetSpent)
        );
        assert_eq!(tiny.spent(), 1);
    }
    #[test]
    fn literal_token_backtracking_cannot_bypass_aggregate_budget() {
        let mut budget = MatchingBudget::new(64);
        assert_eq!(
            segment_matches_compiled(
                &"*aaaaaaaaab".chars().collect::<Vec<_>>(),
                &"a".repeat(64),
                &mut budget
            ),
            Err(MatchingBudgetSpent),
            "literal token matcher failed to refuse exhausted aggregate budget"
        );
        assert_eq!(budget.spent(), 64);
    }
    #[test]
    fn manifest_identity_is_order_independent_and_binds_exact_members() {
        let a = ArtifactManifestMember {
            name: "a/x".into(),
            bytes: 1,
            media_type: ARTIFACT_MEDIA_TYPE.into(),
        };
        let b = ArtifactManifestMember {
            name: "a/y".into(),
            bytes: 2,
            media_type: ARTIFACT_MEDIA_TYPE.into(),
        };
        assert_eq!(
            artifact_manifest_digest(&[a.clone(), b.clone()]),
            artifact_manifest_digest(&[b.clone(), a.clone()])
        );
        let mut changed = b.clone();
        changed.bytes += 1;
        assert_ne!(
            artifact_manifest_digest(&[a.clone(), b.clone()]),
            artifact_manifest_digest(&[a.clone(), changed])
        );
        assert!(validate_manifest(&[a.clone(), a]).is_err());
        let mut oversized = b;
        oversized.bytes = MAX_ATTEMPT_ARTIFACT_BYTES + 1;
        assert!(validate_manifest(&[oversized]).is_err());
    }
    #[test]
    fn client_budget_covers_receive_header_commit_and_response_margin() {
        for bytes in [0, 1, 128 * 1_048_576, MAX_ATTEMPT_ARTIFACT_BYTES] {
            assert!(
                artifact_server_seconds(bytes)
                    >= ARTIFACT_UPLOAD_BASE_SECONDS
                        + artifact_upload_seconds(bytes)
                        + ARTIFACT_COMMIT_HEADROOM_SECONDS
            );
            assert!(artifact_client_seconds(bytes) > artifact_server_seconds(bytes));
        }
    }
}
