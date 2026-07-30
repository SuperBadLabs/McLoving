use std::collections::HashMap;
use std::io::Cursor;

use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

use crate::{Store, StoreError, append_event_and_outbox};

pub const TEST_RESULT_SCHEMA_VERSION: u16 = 1;
pub const DEFAULT_MAX_JUNIT_BYTES: usize = 8 * 1_048_576;
pub const DEFAULT_MAX_JUNIT_SUITES: usize = 10_000;
pub const DEFAULT_MAX_JUNIT_CASES: usize = 100_000;
pub const TEST_RESULT_RAW_RETENTION_SECONDS: i64 = 30 * 24 * 60 * 60;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JunitLimits {
    pub max_bytes: usize,
    pub max_suites: usize,
    pub max_cases: usize,
    pub max_depth: usize,
    pub max_field_bytes: usize,
}

impl Default for JunitLimits {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_JUNIT_BYTES,
            max_suites: DEFAULT_MAX_JUNIT_SUITES,
            max_cases: DEFAULT_MAX_JUNIT_CASES,
            max_depth: 64,
            max_field_bytes: 16_384,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestReportSource {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub build_id: Uuid,
    pub node_id: Uuid,
    pub attempt_id: Uuid,
    pub fence: i64,
    pub artifact_name: String,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TestAggregate {
    pub total: u64,
    pub passed: u64,
    pub failed: u64,
    pub errors: u64,
    pub skipped: u64,
    pub duration_ms: u64,
}

impl TestAggregate {
    fn add(&mut self, outcome: TestOutcome, duration_ms: u64) -> Result<(), TestResultError> {
        self.total = self
            .total
            .checked_add(1)
            .ok_or(TestResultError::LimitExceeded("test aggregate overflow"))?;
        self.duration_ms =
            self.duration_ms
                .checked_add(duration_ms)
                .ok_or(TestResultError::LimitExceeded(
                    "duration aggregate overflow",
                ))?;
        match outcome {
            TestOutcome::Passed => self.passed += 1,
            TestOutcome::Failed => self.failed += 1,
            TestOutcome::Error => self.errors += 1,
            TestOutcome::Skipped => self.skipped += 1,
        }
        Ok(())
    }

    fn as_json(self) -> serde_json::Value {
        json!({
            "duration_ms": self.duration_ms,
            "errors": self.errors,
            "failed": self.failed,
            "passed": self.passed,
            "skipped": self.skipped,
            "total": self.total,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TestOutcome {
    Passed,
    Failed,
    Error,
    Skipped,
}

impl TestOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Error => "error",
            Self::Skipped => "skipped",
        }
    }

    fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "passed" => Ok(Self::Passed),
            "failed" => Ok(Self::Failed),
            "error" => Ok(Self::Error),
            "skipped" => Ok(Self::Skipped),
            other => Err(StoreError::InvalidTestResult(format!(
                "unknown persisted test outcome {other}"
            ))),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedTestCase {
    pub case_ordinal: u32,
    pub duplicate_ordinal: u32,
    pub name: String,
    pub classname: String,
    pub outcome: TestOutcome,
    pub duration_ms: u64,
    pub message: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedTestSuite {
    pub suite_ordinal: u32,
    pub name: String,
    pub aggregate: TestAggregate,
    pub cases: Vec<NormalizedTestCase>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedTestReport {
    pub schema_version: u16,
    pub source: TestReportSource,
    pub raw_sha256: [u8; 32],
    pub raw_bytes: u64,
    pub aggregate: TestAggregate,
    pub suites: Vec<NormalizedTestSuite>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestCaseObservation {
    pub report_id: Uuid,
    pub build_id: Uuid,
    pub attempt_id: Uuid,
    pub fence: i64,
    pub suite_ordinal: u32,
    pub case_ordinal: u32,
    pub duplicate_ordinal: u32,
    pub outcome: TestOutcome,
    pub duration_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestCaseHistory {
    pub suite_name: String,
    pub classname: String,
    pub case_name: String,
    pub flaky: bool,
    pub observations: Vec<TestCaseObservation>,
}

#[derive(Debug, thiserror::Error)]
pub enum TestResultError {
    #[error("JUnit input exceeds the configured {0}")]
    LimitExceeded(&'static str),
    #[error("JUnit entity declarations and doctypes are forbidden")]
    EntityDeclaration,
    #[error("malformed JUnit input: {0}")]
    Malformed(String),
}

struct PendingCase {
    name: String,
    classname: String,
    outcome: TestOutcome,
    duration_ms: u64,
    message: Option<String>,
}

struct PendingSuite {
    name: String,
    cases: Vec<NormalizedTestCase>,
    duplicates: HashMap<(String, String), u32>,
    aggregate: TestAggregate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JunitRoot {
    Suite,
    Suites,
}

pub fn parse_junit(
    bytes: &[u8],
    source: TestReportSource,
    limits: JunitLimits,
) -> Result<NormalizedTestReport, TestResultError> {
    validate_limits(bytes, limits)?;
    let raw_sha256: [u8; 32] = Sha256::digest(bytes).into();
    let mut reader = Reader::from_reader(Cursor::new(bytes));
    // Keep document-level whitespace events so a declaration that is not at
    // byte zero cannot be normalized into looking like the first event.
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut depth = 0_usize;
    let mut root = None;
    let mut suites = Vec::new();
    let mut current_suite: Option<PendingSuite> = None;
    let mut current_case: Option<PendingCase> = None;
    let mut case_count = 0_usize;
    let mut declaration_seen = false;
    let mut document_content_seen = false;

    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|error| TestResultError::Malformed(error.to_string()))?;
        match &event {
            Event::Decl(_) => {
                if declaration_seen || document_content_seen {
                    return Err(TestResultError::Malformed(
                        "XML declaration must appear exactly once at document start".to_owned(),
                    ));
                }
                declaration_seen = true;
            }
            Event::Eof => {}
            _ => document_content_seen = true,
        }
        match event {
            Event::Start(start) => {
                depth = depth
                    .checked_add(1)
                    .ok_or(TestResultError::LimitExceeded("XML depth"))?;
                if depth > limits.max_depth {
                    return Err(TestResultError::LimitExceeded("XML depth"));
                }
                on_start(
                    &reader,
                    &start,
                    limits,
                    depth,
                    &mut root,
                    &mut current_suite,
                    &mut current_case,
                )?;
            }
            Event::Empty(start) => {
                let event_depth = depth
                    .checked_add(1)
                    .ok_or(TestResultError::LimitExceeded("XML depth"))?;
                if event_depth > limits.max_depth {
                    return Err(TestResultError::LimitExceeded("XML depth"));
                }
                on_empty(
                    &reader,
                    &start,
                    limits,
                    event_depth,
                    &mut root,
                    &mut suites,
                    &mut current_suite,
                    &mut current_case,
                    &mut case_count,
                )?;
            }
            Event::End(end) => {
                match end.name().as_ref() {
                    b"testcase" => finish_case(
                        &mut current_suite,
                        &mut current_case,
                        &mut case_count,
                        limits,
                    )?,
                    b"testsuite" => {
                        if current_case.is_some() {
                            return Err(TestResultError::Malformed(
                                "testsuite ended inside testcase".to_owned(),
                            ));
                        }
                        finish_suite(&mut suites, &mut current_suite, limits)?;
                    }
                    _ => {}
                }
                depth = depth.checked_sub(1).ok_or_else(|| {
                    TestResultError::Malformed("unexpected closing element".to_owned())
                })?;
            }
            Event::DocType(_) => return Err(TestResultError::EntityDeclaration),
            Event::PI(_) => {
                return Err(TestResultError::Malformed(
                    "processing instructions are forbidden".to_owned(),
                ));
            }
            Event::Eof => break,
            Event::Decl(_) | Event::Comment(_) => {}
            Event::Text(text) if depth == 0 => {
                if text.as_ref().iter().any(|byte| !byte.is_ascii_whitespace()) {
                    return Err(TestResultError::Malformed(
                        "character data outside the document element".to_owned(),
                    ));
                }
            }
            Event::CData(_) if depth == 0 => {
                return Err(TestResultError::Malformed(
                    "CDATA outside the document element".to_owned(),
                ));
            }
            Event::GeneralRef(_) if depth == 0 => {
                return Err(TestResultError::Malformed(
                    "character reference outside the document element".to_owned(),
                ));
            }
            Event::Text(_) | Event::CData(_) => {}
            Event::GeneralRef(reference) => {
                let predefined = matches!(
                    reference.as_ref(),
                    b"amp" | b"lt" | b"gt" | b"apos" | b"quot"
                );
                let numeric = reference
                    .resolve_char_ref()
                    .map_err(|error| TestResultError::Malformed(error.to_string()))?;
                if !predefined
                    && !numeric
                        .is_some_and(|character| is_legal_xml_1_0_character(character as u32))
                {
                    return Err(TestResultError::Malformed(
                        "undefined or illegal XML reference".to_owned(),
                    ));
                }
            }
        }
        buffer.clear();
    }

    if root.is_none() {
        return Err(TestResultError::Malformed(
            "missing testsuite or testsuites root".to_owned(),
        ));
    }
    if depth != 0 || current_case.is_some() || current_suite.is_some() {
        return Err(TestResultError::Malformed(
            "unterminated JUnit element".to_owned(),
        ));
    }
    if suites.is_empty() {
        return Err(TestResultError::Malformed(
            "JUnit report contains no test suites".to_owned(),
        ));
    }
    let mut aggregate = TestAggregate::default();
    for suite in &suites {
        merge_aggregate(&mut aggregate, suite.aggregate)?;
    }
    Ok(NormalizedTestReport {
        schema_version: TEST_RESULT_SCHEMA_VERSION,
        source,
        raw_sha256,
        raw_bytes: u64::try_from(bytes.len())
            .map_err(|_| TestResultError::LimitExceeded("input byte count"))?,
        aggregate,
        suites,
    })
}

fn is_legal_xml_1_0_character(codepoint: u32) -> bool {
    matches!(
        codepoint,
        0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF
    )
}

fn validate_limits(bytes: &[u8], limits: JunitLimits) -> Result<(), TestResultError> {
    if limits.max_bytes == 0
        || limits.max_suites == 0
        || limits.max_cases == 0
        || limits.max_depth == 0
        || limits.max_field_bytes == 0
    {
        return Err(TestResultError::Malformed(
            "all parser limits must be positive".to_owned(),
        ));
    }
    if bytes.len() > limits.max_bytes {
        return Err(TestResultError::LimitExceeded("input byte limit"));
    }
    Ok(())
}

fn on_start(
    reader: &Reader<Cursor<&[u8]>>,
    start: &BytesStart<'_>,
    limits: JunitLimits,
    depth: usize,
    root: &mut Option<JunitRoot>,
    suite: &mut Option<PendingSuite>,
    case: &mut Option<PendingCase>,
) -> Result<(), TestResultError> {
    match start.name().as_ref() {
        b"testsuites" => {
            if depth != 1 || root.is_some() {
                return Err(TestResultError::Malformed(
                    "testsuites must be the single document root".to_owned(),
                ));
            }
            *root = Some(JunitRoot::Suites);
        }
        b"testsuite" => {
            let valid_position = match (*root, depth) {
                (None, 1) => {
                    *root = Some(JunitRoot::Suite);
                    true
                }
                (Some(JunitRoot::Suites), 2) => true,
                _ => false,
            };
            if !valid_position {
                return Err(TestResultError::Malformed(
                    "testsuite must be the root or a direct child of testsuites".to_owned(),
                ));
            }
            if suite.is_some() || case.is_some() {
                return Err(TestResultError::Malformed(
                    "nested test suites are not supported".to_owned(),
                ));
            }
            *suite = Some(PendingSuite {
                name: attribute(reader, start, b"name", limits)?.unwrap_or_default(),
                cases: Vec::new(),
                duplicates: HashMap::new(),
                aggregate: TestAggregate::default(),
            });
        }
        b"testcase" => {
            let valid_position = matches!(
                (*root, depth),
                (Some(JunitRoot::Suite), 2) | (Some(JunitRoot::Suites), 3)
            );
            if !valid_position {
                return Err(TestResultError::Malformed(
                    "testcase must be a direct child of testsuite".to_owned(),
                ));
            }
            if case.is_some() {
                return Err(TestResultError::Malformed(
                    "nested test cases are not supported".to_owned(),
                ));
            }
            if suite.is_none() {
                return Err(TestResultError::Malformed(
                    "testcase exists outside testsuite".to_owned(),
                ));
            }
            *case = Some(parse_case(reader, start, limits)?);
        }
        b"failure" => mark_case_at_depth(
            *root,
            depth,
            reader,
            start,
            limits,
            case,
            TestOutcome::Failed,
        )?,
        b"error" => mark_case_at_depth(
            *root,
            depth,
            reader,
            start,
            limits,
            case,
            TestOutcome::Error,
        )?,
        b"skipped" => mark_case_at_depth(
            *root,
            depth,
            reader,
            start,
            limits,
            case,
            TestOutcome::Skipped,
        )?,
        _ if depth == 1 => {
            return Err(TestResultError::Malformed(
                "unsupported JUnit document root".to_owned(),
            ));
        }
        _ => {}
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn on_empty(
    reader: &Reader<Cursor<&[u8]>>,
    start: &BytesStart<'_>,
    limits: JunitLimits,
    depth: usize,
    root: &mut Option<JunitRoot>,
    suites: &mut Vec<NormalizedTestSuite>,
    suite: &mut Option<PendingSuite>,
    case: &mut Option<PendingCase>,
    case_count: &mut usize,
) -> Result<(), TestResultError> {
    match start.name().as_ref() {
        b"testcase" => {
            on_start(reader, start, limits, depth, root, suite, case)?;
            finish_case(suite, case, case_count, limits)?;
        }
        b"failure" => mark_case_at_depth(
            *root,
            depth,
            reader,
            start,
            limits,
            case,
            TestOutcome::Failed,
        )?,
        b"error" => mark_case_at_depth(
            *root,
            depth,
            reader,
            start,
            limits,
            case,
            TestOutcome::Error,
        )?,
        b"skipped" => mark_case_at_depth(
            *root,
            depth,
            reader,
            start,
            limits,
            case,
            TestOutcome::Skipped,
        )?,
        b"testsuite" => {
            on_start(reader, start, limits, depth, root, suite, case)?;
            finish_suite(suites, suite, limits)?;
        }
        b"testsuites" => {
            on_start(reader, start, limits, depth, root, suite, case)?;
        }
        _ if depth == 1 => {
            return Err(TestResultError::Malformed(
                "unsupported JUnit document root".to_owned(),
            ));
        }
        _ => {}
    }
    Ok(())
}

fn parse_case(
    reader: &Reader<Cursor<&[u8]>>,
    start: &BytesStart<'_>,
    limits: JunitLimits,
) -> Result<PendingCase, TestResultError> {
    let name = attribute(reader, start, b"name", limits)?.ok_or_else(|| {
        TestResultError::Malformed("testcase is missing required name".to_owned())
    })?;
    let classname = attribute(reader, start, b"classname", limits)?.unwrap_or_default();
    let duration_ms = attribute(reader, start, b"time", limits)?
        .as_deref()
        .map(parse_duration_ms)
        .transpose()?
        .unwrap_or(0);
    Ok(PendingCase {
        name,
        classname,
        outcome: TestOutcome::Passed,
        duration_ms,
        message: None,
    })
}

fn mark_case(
    reader: &Reader<Cursor<&[u8]>>,
    start: &BytesStart<'_>,
    limits: JunitLimits,
    case: &mut Option<PendingCase>,
    outcome: TestOutcome,
) -> Result<(), TestResultError> {
    let current = case.as_mut().ok_or_else(|| {
        TestResultError::Malformed("test outcome exists outside testcase".to_owned())
    })?;
    if current.outcome != TestOutcome::Passed {
        return Err(TestResultError::Malformed(
            "testcase has multiple terminal outcomes".to_owned(),
        ));
    }
    current.outcome = outcome;
    current.message = attribute(reader, start, b"message", limits)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn mark_case_at_depth(
    root: Option<JunitRoot>,
    depth: usize,
    reader: &Reader<Cursor<&[u8]>>,
    start: &BytesStart<'_>,
    limits: JunitLimits,
    case: &mut Option<PendingCase>,
    outcome: TestOutcome,
) -> Result<(), TestResultError> {
    let direct_child = matches!(
        (root, depth),
        (Some(JunitRoot::Suite), 3) | (Some(JunitRoot::Suites), 4)
    );
    if !direct_child {
        return Err(TestResultError::Malformed(
            "test outcome must be a direct child of testcase".to_owned(),
        ));
    }
    mark_case(reader, start, limits, case, outcome)
}

fn finish_case(
    suite: &mut Option<PendingSuite>,
    case: &mut Option<PendingCase>,
    case_count: &mut usize,
    limits: JunitLimits,
) -> Result<(), TestResultError> {
    let pending = case
        .take()
        .ok_or_else(|| TestResultError::Malformed("testcase end without start".to_owned()))?;
    let suite = suite
        .as_mut()
        .ok_or_else(|| TestResultError::Malformed("testcase has no suite".to_owned()))?;
    if *case_count >= limits.max_cases {
        return Err(TestResultError::LimitExceeded("test case limit"));
    }
    *case_count += 1;
    let key = (pending.classname.clone(), pending.name.clone());
    let duplicate_ordinal = *suite.duplicates.entry(key).or_insert(0);
    suite
        .duplicates
        .entry((pending.classname.clone(), pending.name.clone()))
        .and_modify(|value| *value += 1);
    suite.aggregate.add(pending.outcome, pending.duration_ms)?;
    suite.cases.push(NormalizedTestCase {
        case_ordinal: u32::try_from(suite.cases.len())
            .map_err(|_| TestResultError::LimitExceeded("test case ordinal"))?,
        duplicate_ordinal,
        name: pending.name,
        classname: pending.classname,
        outcome: pending.outcome,
        duration_ms: pending.duration_ms,
        message: pending.message,
    });
    Ok(())
}

fn finish_suite(
    suites: &mut Vec<NormalizedTestSuite>,
    suite: &mut Option<PendingSuite>,
    limits: JunitLimits,
) -> Result<(), TestResultError> {
    if suites.len() >= limits.max_suites {
        return Err(TestResultError::LimitExceeded("test suite limit"));
    }
    let pending = suite
        .take()
        .ok_or_else(|| TestResultError::Malformed("testsuite end without start".to_owned()))?;
    suites.push(NormalizedTestSuite {
        suite_ordinal: u32::try_from(suites.len())
            .map_err(|_| TestResultError::LimitExceeded("test suite ordinal"))?,
        name: pending.name,
        aggregate: pending.aggregate,
        cases: pending.cases,
    });
    Ok(())
}

fn attribute(
    reader: &Reader<Cursor<&[u8]>>,
    start: &BytesStart<'_>,
    key: &[u8],
    limits: JunitLimits,
) -> Result<Option<String>, TestResultError> {
    let mut found = None;
    for attribute in start.attributes().with_checks(true) {
        let attribute = attribute.map_err(|error| TestResultError::Malformed(error.to_string()))?;
        if attribute.key.as_ref() == key {
            if found.is_some() {
                return Err(TestResultError::Malformed(format!(
                    "duplicate {} attribute",
                    String::from_utf8_lossy(key)
                )));
            }
            let value = attribute
                .decoded_and_normalized_value(XmlVersion::Implicit1_0, reader.decoder())
                .map_err(|error| TestResultError::Malformed(error.to_string()))?
                .into_owned();
            if value.len() > limits.max_field_bytes {
                return Err(TestResultError::LimitExceeded("field byte limit"));
            }
            found = Some(value);
        }
    }
    Ok(found)
}

fn parse_duration_ms(value: &str) -> Result<u64, TestResultError> {
    let seconds = value
        .parse::<f64>()
        .map_err(|_| TestResultError::Malformed("invalid testcase duration".to_owned()))?;
    if !seconds.is_finite() || seconds < 0.0 {
        return Err(TestResultError::Malformed(
            "invalid testcase duration".to_owned(),
        ));
    }
    let milliseconds = seconds * 1_000.0;
    if milliseconds > u64::MAX as f64 {
        return Err(TestResultError::LimitExceeded("testcase duration"));
    }
    Ok(milliseconds.round() as u64)
}

fn merge_aggregate(
    destination: &mut TestAggregate,
    source: TestAggregate,
) -> Result<(), TestResultError> {
    destination.total = destination
        .total
        .checked_add(source.total)
        .ok_or(TestResultError::LimitExceeded("test aggregate overflow"))?;
    destination.passed = destination
        .passed
        .checked_add(source.passed)
        .ok_or(TestResultError::LimitExceeded("test aggregate overflow"))?;
    destination.failed = destination
        .failed
        .checked_add(source.failed)
        .ok_or(TestResultError::LimitExceeded("test aggregate overflow"))?;
    destination.errors = destination
        .errors
        .checked_add(source.errors)
        .ok_or(TestResultError::LimitExceeded("test aggregate overflow"))?;
    destination.skipped = destination
        .skipped
        .checked_add(source.skipped)
        .ok_or(TestResultError::LimitExceeded("test aggregate overflow"))?;
    destination.duration_ms = destination
        .duration_ms
        .checked_add(source.duration_ms)
        .ok_or(TestResultError::LimitExceeded(
            "duration aggregate overflow",
        ))?;
    Ok(())
}

impl Store {
    pub async fn ingest_test_report(
        &self,
        report: &NormalizedTestReport,
    ) -> Result<bool, StoreError> {
        validate_report(report)?;
        let source = &report.source;
        let mut tx = self.tenant_transaction(source.organization_id).await?;
        let artifact_matches = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (
                 SELECT 1
                 FROM attempt_objects AS o
                 JOIN attempts AS a
                   ON a.organization_id = o.organization_id
                  AND a.id = o.attempt_id
                 JOIN nodes AS n
                   ON n.organization_id = a.organization_id
                  AND n.id = a.node_id
                 JOIN builds AS b
                   ON b.organization_id = n.organization_id
                  AND b.id = n.build_id
                 WHERE o.organization_id = $1
                   AND b.project_id = $2
                   AND b.id = $3
                   AND n.id = $4
                   AND a.id = $5
                   AND o.fence = $6
                   AND o.kind = 'artifact'
                   AND o.name = $7
                   AND o.object_digest = $8
                   AND o.bytes = $9
                   AND o.status = 'available'
             )",
        )
        .bind(source.organization_id)
        .bind(source.project_id)
        .bind(source.build_id)
        .bind(source.node_id)
        .bind(source.attempt_id)
        .bind(source.fence)
        .bind(&source.artifact_name)
        .bind(report.raw_sha256.as_slice())
        .bind(i64::try_from(report.raw_bytes).map_err(|_| {
            StoreError::InvalidTestResult(
                "raw report byte count exceeds PostgreSQL bigint".to_owned(),
            )
        })?)
        .fetch_one(&mut *tx)
        .await?;
        if !artifact_matches {
            tx.rollback().await?;
            return Ok(false);
        }

        let report_id = Uuid::new_v4();
        let inserted = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO normalized_test_reports (
                 organization_id, report_id, project_id, build_id, node_id,
                 attempt_id, fence, schema_version, raw_artifact_name,
                 raw_object_digest, raw_bytes, aggregate
             )
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
             ON CONFLICT (
                 organization_id, attempt_id, fence,
                 raw_artifact_name, raw_object_digest
             ) DO NOTHING
             RETURNING report_id",
        )
        .bind(source.organization_id)
        .bind(report_id)
        .bind(source.project_id)
        .bind(source.build_id)
        .bind(source.node_id)
        .bind(source.attempt_id)
        .bind(source.fence)
        .bind(i32::from(report.schema_version))
        .bind(&source.artifact_name)
        .bind(report.raw_sha256.as_slice())
        .bind(i64::try_from(report.raw_bytes).map_err(|_| {
            StoreError::InvalidTestResult(
                "raw report byte count exceeds PostgreSQL bigint".to_owned(),
            )
        })?)
        .bind(report.aggregate.as_json())
        .fetch_optional(&mut *tx)
        .await?;
        let Some(report_id) = inserted else {
            tx.rollback().await?;
            return Ok(false);
        };
        sqlx::query(
            "INSERT INTO object_retention (
                 organization_id, object_digest, retain_until
             )
             VALUES (
                 $1, $2,
                 clock_timestamp() + ($3::double precision * interval '1 second')
             )
             ON CONFLICT (organization_id, object_digest) DO UPDATE
             SET retain_until = GREATEST(
                     object_retention.retain_until,
                     EXCLUDED.retain_until
                 ),
                 updated_at = clock_timestamp()",
        )
        .bind(source.organization_id)
        .bind(report.raw_sha256.as_slice())
        .bind(TEST_RESULT_RAW_RETENTION_SECONDS as f64)
        .execute(&mut *tx)
        .await?;

        for suite in &report.suites {
            sqlx::query(
                "INSERT INTO normalized_test_suites (
                     organization_id, report_id, suite_ordinal, name, aggregate
                 )
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(source.organization_id)
            .bind(report_id)
            .bind(i32::try_from(suite.suite_ordinal).map_err(|_| {
                StoreError::InvalidTestResult("suite ordinal exceeds PostgreSQL integer".to_owned())
            })?)
            .bind(&suite.name)
            .bind(suite.aggregate.as_json())
            .execute(&mut *tx)
            .await?;
            for case in &suite.cases {
                sqlx::query(
                    "INSERT INTO normalized_test_cases (
                         organization_id, report_id, suite_ordinal, case_ordinal,
                         duplicate_ordinal, name, classname, outcome,
                         duration_ms, message
                     )
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
                )
                .bind(source.organization_id)
                .bind(report_id)
                .bind(i32::try_from(suite.suite_ordinal).map_err(|_| {
                    StoreError::InvalidTestResult(
                        "suite ordinal exceeds PostgreSQL integer".to_owned(),
                    )
                })?)
                .bind(i32::try_from(case.case_ordinal).map_err(|_| {
                    StoreError::InvalidTestResult(
                        "case ordinal exceeds PostgreSQL integer".to_owned(),
                    )
                })?)
                .bind(i32::try_from(case.duplicate_ordinal).map_err(|_| {
                    StoreError::InvalidTestResult(
                        "duplicate ordinal exceeds PostgreSQL integer".to_owned(),
                    )
                })?)
                .bind(&case.name)
                .bind(&case.classname)
                .bind(case.outcome.as_str())
                .bind(i64::try_from(case.duration_ms).map_err(|_| {
                    StoreError::InvalidTestResult(
                        "testcase duration exceeds PostgreSQL bigint".to_owned(),
                    )
                })?)
                .bind(&case.message)
                .execute(&mut *tx)
                .await?;
            }
        }
        append_event_and_outbox(
            &mut tx,
            source.organization_id,
            source.build_id,
            "test_report.ingested",
            json!({
                "attempt_id": source.attempt_id,
                "fence": source.fence,
                "raw_artifact_name": source.artifact_name,
                "raw_sha256": hex::encode(report.raw_sha256),
                "report_id": report_id,
                "schema_version": report.schema_version,
                "aggregate": report.aggregate.as_json(),
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    pub async fn test_case_history(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        suite_name: &str,
        classname: &str,
        case_name: &str,
        limit: u32,
    ) -> Result<TestCaseHistory, StoreError> {
        if suite_name.len() > 16_384
            || classname.len() > 16_384
            || case_name.is_empty()
            || case_name.len() > 16_384
            || limit == 0
            || limit > 10_000
        {
            return Err(StoreError::InvalidTestResult(
                "invalid test history query".to_owned(),
            ));
        }
        let mut tx = self.tenant_transaction(organization_id).await?;
        let rows = sqlx::query(
            "SELECT r.report_id, r.build_id, r.attempt_id, r.fence,
                    c.suite_ordinal, c.case_ordinal, c.duplicate_ordinal,
                    c.outcome, c.duration_ms
             FROM normalized_test_cases AS c
             JOIN normalized_test_suites AS s
               ON s.organization_id = c.organization_id
              AND s.report_id = c.report_id
              AND s.suite_ordinal = c.suite_ordinal
             JOIN normalized_test_reports AS r
               ON r.organization_id = c.organization_id
              AND r.report_id = c.report_id
             WHERE c.organization_id = $1
               AND r.project_id = $2
               AND s.name = $3
               AND c.classname = $4
               AND c.name = $5
             ORDER BY r.created_at DESC, r.report_id DESC,
                      c.suite_ordinal DESC, c.case_ordinal DESC
             LIMIT $6",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(suite_name)
        .bind(classname)
        .bind(case_name)
        .bind(i64::from(limit))
        .fetch_all(&mut *tx)
        .await?;
        let distinct_outcomes = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(DISTINCT c.outcome)
             FROM normalized_test_cases AS c
             JOIN normalized_test_suites AS s
               ON s.organization_id = c.organization_id
              AND s.report_id = c.report_id
              AND s.suite_ordinal = c.suite_ordinal
             JOIN normalized_test_reports AS r
               ON r.organization_id = c.organization_id
              AND r.report_id = c.report_id
             WHERE c.organization_id = $1
               AND r.project_id = $2
               AND s.name = $3
               AND c.classname = $4
               AND c.name = $5",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(suite_name)
        .bind(classname)
        .bind(case_name)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        let mut observations = rows
            .into_iter()
            .map(|row| {
                let outcome = TestOutcome::parse(row.get("outcome"))?;
                Ok(TestCaseObservation {
                    report_id: row.get("report_id"),
                    build_id: row.get("build_id"),
                    attempt_id: row.get("attempt_id"),
                    fence: row.get("fence"),
                    suite_ordinal: u32::try_from(row.get::<i32, _>("suite_ordinal")).map_err(
                        |_| StoreError::InvalidTestResult("negative suite ordinal".to_owned()),
                    )?,
                    case_ordinal: u32::try_from(row.get::<i32, _>("case_ordinal")).map_err(
                        |_| StoreError::InvalidTestResult("negative case ordinal".to_owned()),
                    )?,
                    duplicate_ordinal: u32::try_from(row.get::<i32, _>("duplicate_ordinal"))
                        .map_err(|_| {
                            StoreError::InvalidTestResult("negative duplicate ordinal".to_owned())
                        })?,
                    outcome,
                    duration_ms: u64::try_from(row.get::<i64, _>("duration_ms")).map_err(|_| {
                        StoreError::InvalidTestResult("negative testcase duration".to_owned())
                    })?,
                })
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        observations.reverse();
        Ok(TestCaseHistory {
            suite_name: suite_name.to_owned(),
            classname: classname.to_owned(),
            case_name: case_name.to_owned(),
            flaky: distinct_outcomes > 1,
            observations,
        })
    }
}

fn validate_report(report: &NormalizedTestReport) -> Result<(), StoreError> {
    if report.schema_version != TEST_RESULT_SCHEMA_VERSION
        || report.source.artifact_name.is_empty()
        || report.source.artifact_name.len() > 512
        || report.raw_bytes == 0
        || report.suites.is_empty()
        || report.suites.len() > DEFAULT_MAX_JUNIT_SUITES
        || report.aggregate.total > DEFAULT_MAX_JUNIT_CASES as u64
    {
        return Err(StoreError::InvalidTestResult(
            "normalized test report violates schema bounds".to_owned(),
        ));
    }
    let mut aggregate = TestAggregate::default();
    for (suite_index, suite) in report.suites.iter().enumerate() {
        if usize::try_from(suite.suite_ordinal).ok() != Some(suite_index)
            || suite.name.len() > 16_384
        {
            return Err(StoreError::InvalidTestResult(
                "normalized suite identity is invalid".to_owned(),
            ));
        }
        let mut suite_aggregate = TestAggregate::default();
        let mut duplicates = HashMap::new();
        for (case_index, case) in suite.cases.iter().enumerate() {
            let expected_duplicate = duplicates
                .entry((case.classname.clone(), case.name.clone()))
                .or_insert(0_u32);
            if usize::try_from(case.case_ordinal).ok() != Some(case_index)
                || case.duplicate_ordinal != *expected_duplicate
                || case.name.is_empty()
                || case.name.len() > 16_384
                || case.classname.len() > 16_384
                || case
                    .message
                    .as_ref()
                    .is_some_and(|value| value.len() > 16_384)
            {
                return Err(StoreError::InvalidTestResult(
                    "normalized testcase identity is invalid".to_owned(),
                ));
            }
            *expected_duplicate += 1;
            suite_aggregate
                .add(case.outcome, case.duration_ms)
                .map_err(|error| StoreError::InvalidTestResult(error.to_string()))?;
        }
        if suite_aggregate != suite.aggregate {
            return Err(StoreError::InvalidTestResult(
                "normalized suite aggregate does not match cases".to_owned(),
            ));
        }
        merge_aggregate(&mut aggregate, suite.aggregate)
            .map_err(|error| StoreError::InvalidTestResult(error.to_string()))?;
    }
    if aggregate != report.aggregate {
        return Err(StoreError::InvalidTestResult(
            "normalized report aggregate does not match suites".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> TestReportSource {
        TestReportSource {
            organization_id: Uuid::nil(),
            project_id: Uuid::nil(),
            build_id: Uuid::nil(),
            node_id: Uuid::nil(),
            attempt_id: Uuid::nil(),
            fence: 1,
            artifact_name: "reports/junit.xml".to_owned(),
        }
    }

    #[test]
    fn normalizes_duplicates_outcomes_and_deterministic_aggregates() {
        let xml = br#"
          <testsuites>
            <testsuite name="unit">
              <testcase classname="core" name="same" time="0.001"/>
              <testcase classname="core" name="same" time="0.002">
                <failure message="assertion"/>
              </testcase>
              <testcase classname="core" name="skipped"><skipped/></testcase>
              <testcase classname="core" name="error"><error message="boom"/></testcase>
            </testsuite>
          </testsuites>
        "#;
        let report = parse_junit(xml, source(), JunitLimits::default()).expect("normalize");
        assert_eq!(report.schema_version, 1);
        assert_eq!(
            report.aggregate,
            TestAggregate {
                total: 4,
                passed: 1,
                failed: 1,
                errors: 1,
                skipped: 1,
                duration_ms: 3,
            }
        );
        assert_eq!(report.suites[0].cases[0].duplicate_ordinal, 0);
        assert_eq!(report.suites[0].cases[1].duplicate_ordinal, 1);
        assert_eq!(report.raw_sha256, Sha256::digest(xml).as_slice());
        validate_report(&report).expect("self-consistent normalized report");
    }

    #[test]
    fn outcomes_must_be_direct_testcase_children() {
        for xml in [
            br#"<testsuite name="unit"><testcase name="nested"><system-out><failure/></system-out></testcase></testsuite>"#.as_slice(),
            br#"<testsuites><testsuite name="unit"><testcase name="nested"><wrapper><skipped/></wrapper></testcase></testsuite></testsuites>"#.as_slice(),
        ] {
            assert!(matches!(
                parse_junit(xml, source(), JunitLimits::default()),
                Err(TestResultError::Malformed(message))
                    if message == "test outcome must be a direct child of testcase"
            ));
        }
    }

    #[test]
    fn xml_declaration_is_optional_but_only_valid_once_at_document_start() {
        for (case, xml) in [
            br#"<testsuite/><?xml version="1.0"?>"#.as_slice(),
            br#" <?xml version="1.0"?><testsuite/>"#.as_slice(),
            br#"<?xml version="1.0"?><?xml version="1.0"?><testsuite/>"#.as_slice(),
            br#"<!--before--><?xml version="1.0"?><testsuite/>"#.as_slice(),
        ]
        .into_iter()
        .enumerate()
        {
            let result = parse_junit(xml, source(), JunitLimits::default());
            assert!(
                matches!(result, Err(TestResultError::Malformed(_))),
                "misplaced declaration case {case} was accepted"
            );
        }
        parse_junit(
            br#"<?xml version="1.0"?><testsuite/>"#,
            source(),
            JunitLimits::default(),
        )
        .expect("one declaration at byte zero is accepted");
        parse_junit(br#"<testsuite/>"#, source(), JunitLimits::default())
            .expect("the XML declaration remains optional");
    }

    #[test]
    fn rejects_entities_malformed_and_oversized_reports() {
        let entity = br#"<!DOCTYPE x [<!ENTITY boom "boom">]><testsuite name="x"/>"#;
        assert!(matches!(
            parse_junit(entity, source(), JunitLimits::default()),
            Err(TestResultError::EntityDeclaration)
        ));
        assert!(matches!(
            parse_junit(
                b"<testsuite><testcase name=\"x\"></testsuite>",
                source(),
                JunitLimits::default()
            ),
            Err(TestResultError::Malformed(_))
        ));
        let limits = JunitLimits {
            max_bytes: 8,
            ..JunitLimits::default()
        };
        assert!(matches!(
            parse_junit(b"<testsuite/>", source(), limits),
            Err(TestResultError::LimitExceeded("input byte limit"))
        ));
        let limits = JunitLimits {
            max_cases: 1,
            ..JunitLimits::default()
        };
        assert!(matches!(
            parse_junit(
                b"<testsuites><testsuite><testcase name=\"one\"/></testsuite><testsuite><testcase name=\"two\"/></testsuite></testsuites>",
                source(),
                limits
            ),
            Err(TestResultError::LimitExceeded("test case limit"))
        ));
        assert!(matches!(
            parse_junit(
                b"<wrapper><testsuite><testcase name=\"hidden\"/></testsuite></wrapper>",
                source(),
                JunitLimits::default()
            ),
            Err(TestResultError::Malformed(_))
        ));
        assert!(matches!(
            parse_junit(
                b"<testsuite name=\"one\"/><testsuite name=\"two\"/>",
                source(),
                JunitLimits::default()
            ),
            Err(TestResultError::Malformed(_))
        ));
        assert!(matches!(
            parse_junit(
                b"<testsuite><testcase name=\"x\">&undefined;</testcase></testsuite>",
                source(),
                JunitLimits::default()
            ),
            Err(TestResultError::Malformed(_))
        ));
        parse_junit(
            b"<testsuite><testcase name=\"amp\">&amp;</testcase></testsuite>",
            source(),
            JunitLimits::default(),
        )
        .expect("predefined XML references remain valid");
        parse_junit(
            b"<testsuite><testcase name=\"newline\">&#10;&#xA;</testcase></testsuite>",
            source(),
            JunitLimits::default(),
        )
        .expect("legal decimal and hexadecimal character references remain valid");
        for illegal in [
            b"<testsuite><testcase name=\"case\">&#1;</testcase></testsuite>".as_slice(),
            b"<testsuite><testcase name=\"case\">&#xB;</testcase></testsuite>".as_slice(),
            b"<testsuite><testcase name=\"case\">&undeclared;</testcase></testsuite>".as_slice(),
        ] {
            assert!(matches!(
                parse_junit(illegal, source(), JunitLimits::default()),
                Err(TestResultError::Malformed(_))
            ));
        }
        for malformed in [
            b"garbage<testsuite/>".as_slice(),
            b"<testsuite/>garbage".as_slice(),
            b"<![CDATA[garbage]]><testsuite/>".as_slice(),
            b"<![CDATA[ ]]><testsuite/>".as_slice(),
            b"<testsuite/><![CDATA[\n]]>".as_slice(),
            b"<testsuite/>&amp;".as_slice(),
        ] {
            assert!(matches!(
                parse_junit(malformed, source(), JunitLimits::default()),
                Err(TestResultError::Malformed(_))
            ));
        }
    }

    #[test]
    fn declaration_text_inside_comments_and_cdata_is_not_a_doctype() {
        let xml = br#"<testsuite name="suite">
          <!-- captured text: <!ENTITY harmless "text"> -->
          <testcase name="case">
            <system-out><![CDATA[<!DOCTYPE html><p>captured output</p>]]></system-out>
          </testcase>
        </testsuite>"#;
        let report =
            parse_junit(xml, source(), JunitLimits::default()).expect("parse literal text");
        assert_eq!(report.suites.len(), 1);
        assert_eq!(report.suites[0].cases.len(), 1);
    }
}
