//! Independent admission of the deny-authority Jenkins compiler response.
//!
//! The Clojure/Groovy worker is intentionally untrusted. This crate reparses
//! its canonical EDN envelope, reparses strict YAML, recompiles and validates
//! Pipeline IR, and validates the separate disabled operational-state record.

use std::collections::BTreeMap;
use std::fmt;

use mcloving_pipeline_ir::{
    ParseLimits, PipelineIr, Step, YamlValue, compile_strict_yaml, parse_strict,
    validate_canonical_bytes,
};
use sha2::{Digest, Sha256};

pub const PROTOCOL: &str = "mcloving.jenkins.compiler/1";
pub const COMPILER: &str = "mcloving-jenkins-compiler-worker/1";
pub const PROFILE_SHA256: &str = "feeeb44d32aa10181e572a0dbbf5b2e23895731b1913bd46aba9f38d56172271";
pub const INVENTORY_FINGERPRINT: &str =
    "b1c2f81c74ec0ffc36971f358f920b2d0775c6009f474bea924448cd2a1915c1";
pub const CONTROLLER: &str = "mario/jenkins-oracle-228";
pub const ADMITTED_JOB_ID: &str = "corpus-052-cinqict_jenkinsdev";
pub const ADMITTED_SOURCE_SHA256: &str =
    "666ac2275ea75730e27cf7b565d757691b094c508355adc0199d745278a23100";
pub const ADMITTED_JOB_GENERATION: &str =
    "e76362bbc8e899510b8498808ffd0d2f83bb64d3215cf2c5b31690895f251d97";
pub const JOB_REASON: &str = "offline-frozen-source-state";
pub const JOB_ACTOR: &str = "jenkins/system";
pub const JOB_EFFECTIVE_TIME: &str = "2026-07-31T06:44:17Z";
const MAX_RESPONSE_BYTES: usize = 65_536;

/// Caller-owned expectations that cannot be trusted to the worker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedAdmission<'a> {
    pub request_id: &'a str,
    pub job_id: &'a str,
    pub job_generation: &'a str,
    pub source: &'a [u8],
}

/// Rust-produced receipt after all worker output has been revalidated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionReceipt {
    pub request_id: String,
    pub job_id: String,
    pub source_sha256: String,
    pub pipeline_yaml_sha256: String,
    pub jobstate_yaml_sha256: String,
    pub semantic_ir_sha256: String,
    pub canonical_ir_sha256: String,
    pub stages: usize,
    pub steps: usize,
    pub state: String,
}

/// Stable independent-admission failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionError {
    pub code: &'static str,
    pub message: String,
}

impl AdmissionError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for AdmissionError {}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Edn {
    Map(BTreeMap<String, Edn>),
    Vector(Vec<Edn>),
    String(String),
    Keyword(String),
    Bool(bool),
    Integer(i64),
}

/// Reparse and independently validate one worker response.
pub fn admit_response(
    response: &[u8],
    expected: ExpectedAdmission<'_>,
) -> Result<AdmissionReceipt, AdmissionError> {
    if response.len() > MAX_RESPONSE_BYTES {
        return Err(AdmissionError::new(
            "E_RESPONSE_TOO_LARGE",
            "worker response exceeds 65536 bytes",
        ));
    }
    let text = std::str::from_utf8(response)
        .map_err(|_| AdmissionError::new("E_RESPONSE_UTF8", "response is not UTF-8"))?;
    let canonical = text.strip_suffix('\n').unwrap_or(text);
    if canonical.contains('\n') && text.ends_with("\n\n") {
        return Err(AdmissionError::new(
            "E_RESPONSE_CANONICAL",
            "response has more than one terminal newline",
        ));
    }
    let parsed = EdnParser::new(canonical).parse()?;
    if render_edn(&parsed) != canonical {
        return Err(AdmissionError::new(
            "E_RESPONSE_CANONICAL",
            "response is not canonical EDN",
        ));
    }

    let root = exact_map(
        &parsed,
        &[
            "authority",
            "compiler",
            "profile",
            "protocol",
            "request-id",
            "result",
            "source",
            "status",
        ],
        "E_RESPONSE_FIELDS",
    )?;
    expect_string(root, "protocol", PROTOCOL)?;
    expect_string(root, "compiler", COMPILER)?;
    expect_string(root, "request-id", expected.request_id)?;
    expect_keyword(root, "status", "compiled")?;
    validate_authority(field(root, "authority")?)?;
    validate_profile(field(root, "profile")?)?;

    let source_sha256 = sha256_hex(expected.source);
    if source_sha256 != ADMITTED_SOURCE_SHA256
        || expected.job_id != ADMITTED_JOB_ID
        || expected.job_generation != ADMITTED_JOB_GENERATION
    {
        return Err(AdmissionError::new(
            "E_EXPECTED_NOT_ADMITTED",
            "caller expectations do not identify the admitted Mario oracle case",
        ));
    }
    let source = exact_map(
        field(root, "source")?,
        &["bytes", "sha256"],
        "E_SOURCE_RECEIPT",
    )?;
    expect_integer(source, "bytes", expected.source.len() as i64)?;
    expect_string(source, "sha256", &source_sha256)?;

    let result = exact_map(
        field(root, "result")?,
        &[
            "agent-mapping",
            "jobstate-yaml",
            "jobstate-yaml-sha256",
            "pipeline-yaml",
            "pipeline-yaml-sha256",
            "semantic",
        ],
        "E_RESULT_FIELDS",
    )?;
    validate_agent_mapping(field(result, "agent-mapping")?)?;

    let pipeline_yaml = string_field(result, "pipeline-yaml")?;
    let pipeline_yaml_sha256 = sha256_hex(pipeline_yaml.as_bytes());
    expect_string(result, "pipeline-yaml-sha256", &pipeline_yaml_sha256)?;
    let source_id = format!(
        "jenkins://{CONTROLLER}/job/{}/inline/Jenkinsfile",
        expected.job_id
    );
    let pipeline = compile_strict_yaml(&source_id, pipeline_yaml, ParseLimits::default())
        .map_err(|error| AdmissionError::new("E_PIPELINE_YAML", error.to_string()))?;
    validate_pipeline_result(&pipeline, pipeline_yaml, expected.job_id)?;
    let canonical_ir = pipeline
        .canonical_bytes()
        .map_err(|error| AdmissionError::new("E_PIPELINE_IR", error.to_string()))?;
    let summary = validate_canonical_bytes(&canonical_ir)
        .map_err(|error| AdmissionError::new("E_PIPELINE_IR", error.to_string()))?;

    let jobstate_yaml = string_field(result, "jobstate-yaml")?;
    let jobstate_yaml_sha256 = sha256_hex(jobstate_yaml.as_bytes());
    expect_string(result, "jobstate-yaml-sha256", &jobstate_yaml_sha256)?;
    validate_jobstate(jobstate_yaml, &expected, &source_sha256)?;

    let semantic = exact_map(
        field(result, "semantic")?,
        &["stages", "steps"],
        "E_SEMANTIC_FIELDS",
    )?;
    expect_integer(semantic, "stages", summary.stages as i64)?;
    expect_integer(semantic, "steps", summary.steps as i64)?;

    Ok(AdmissionReceipt {
        request_id: expected.request_id.to_owned(),
        job_id: expected.job_id.to_owned(),
        source_sha256,
        pipeline_yaml_sha256,
        jobstate_yaml_sha256,
        semantic_ir_sha256: pipeline
            .semantic_digest_hex()
            .map_err(|error| AdmissionError::new("E_PIPELINE_IR", error.to_string()))?,
        canonical_ir_sha256: sha256_hex(&canonical_ir),
        stages: summary.stages,
        steps: summary.steps,
        state: "disabled".to_owned(),
    })
}

fn validate_authority(value: &Edn) -> Result<(), AdmissionError> {
    let map = exact_map(
        value,
        &[
            "agent-protocol",
            "controller-filesystem",
            "controller-store",
            "credentials",
            "effects",
            "network",
            "scheduler",
            "workload-execution",
        ],
        "E_AUTHORITY",
    )?;
    if map.values().any(|value| !matches!(value, Edn::Bool(false))) {
        return Err(AdmissionError::new(
            "E_AUTHORITY",
            "worker response claims authority",
        ));
    }
    Ok(())
}

fn validate_profile(value: &Edn) -> Result<(), AdmissionError> {
    let map = exact_map(
        value,
        &[
            "controller",
            "groovy-version",
            "java-runtime",
            "jenkins-core-version",
            "plugin-count",
            "profile-id",
            "profile-sha256",
            "snapshot-fingerprint",
        ],
        "E_PROFILE",
    )?;
    expect_string(map, "controller", CONTROLLER)?;
    expect_string(map, "groovy-version", "2.4.21")?;
    expect_string(map, "jenkins-core-version", "2.568.1")?;
    expect_integer(map, "plugin-count", 90)?;
    expect_string(map, "profile-id", "mario-jenkins-oracle-228")?;
    expect_string(map, "profile-sha256", PROFILE_SHA256)?;
    expect_string(map, "snapshot-fingerprint", INVENTORY_FINGERPRINT)?;
    let runtime = string_field(map, "java-runtime")?;
    if runtime != "21.0.11+10-LTS" {
        return Err(AdmissionError::new(
            "E_PROFILE",
            "unexpected Java runtime identity",
        ));
    }
    Ok(())
}

fn validate_agent_mapping(value: &Edn) -> Result<(), AdmissionError> {
    let map = exact_map(
        value,
        &[
            "effect-authority",
            "jenkins-selector",
            "mcloving-platform",
            "trust-pool",
        ],
        "E_AGENT_MAPPING",
    )?;
    expect_bool(map, "effect-authority", false)?;
    expect_string(map, "jenkins-selector", "any")?;
    expect_string(map, "mcloving-platform", "any")?;
    expect_string(map, "trust-pool", "migration-deny-authority")
}

fn validate_pipeline_result(
    pipeline: &PipelineIr,
    source: &str,
    job_id: &str,
) -> Result<(), AdmissionError> {
    if pipeline.name != job_id
        || !pipeline.parameters.is_empty()
        || !pipeline.parameter_values.is_empty()
        || !pipeline.expressions.is_empty()
        || pipeline.stages.len() != 1
    {
        return Err(AdmissionError::new(
            "E_PIPELINE_SEMANTICS",
            "pipeline identity, inputs, expressions, or stage count changed",
        ));
    }
    let stage = &pipeline.stages[0];
    if stage.id != "build" || stage.name != "Build" || stage.steps.len() != 1 {
        return Err(AdmissionError::new(
            "E_PIPELINE_SEMANTICS",
            "admitted stage semantics changed",
        ));
    }
    let Step::Process(process) = &stage.steps[0];
    if process.program != "/bin/sh"
        || process.args != ["-xe", "-c", "echo \"Hello World\""]
        || !process.env.is_empty()
        || process.timeout_seconds.is_some()
    {
        return Err(AdmissionError::new(
            "E_PIPELINE_SEMANTICS",
            "admitted shell semantics changed",
        ));
    }
    if render_pipeline_yaml(pipeline) != source {
        return Err(AdmissionError::new(
            "E_PIPELINE_CANONICAL",
            "strict YAML is semantically valid but not canonical compiler output",
        ));
    }
    Ok(())
}

fn render_pipeline_yaml(pipeline: &PipelineIr) -> String {
    let mut output = format!(
        "version: 1\nname: {}\nstages:\n",
        yaml_string(&pipeline.name)
    );
    for stage in &pipeline.stages {
        output.push_str(&format!(
            "  - id: {}\n    name: {}\n    steps:\n",
            yaml_string(&stage.id),
            yaml_string(&stage.name)
        ));
        for step in &stage.steps {
            let Step::Process(process) = step;
            let arguments = process
                .args
                .iter()
                .map(|argument| yaml_string(argument))
                .collect::<Vec<_>>()
                .join(", ");
            output.push_str(&format!(
                "      - process:\n          program: {}\n          args: [{arguments}]\n",
                yaml_string(&process.program)
            ));
        }
    }
    output
}

fn validate_jobstate(
    source: &str,
    expected: &ExpectedAdmission<'_>,
    source_sha256: &str,
) -> Result<(), AdmissionError> {
    let parsed = parse_strict(source, ParseLimits::default())
        .map_err(|error| AdmissionError::new("E_JOBSTATE_YAML", error.to_string()))?;
    let root = yaml_map(
        parsed.value,
        &[
            "actor",
            "effective_time",
            "generation",
            "job_id",
            "provenance",
            "reason",
            "schema",
            "state",
            "version",
        ],
    )?;
    yaml_integer(&root, "version", 1)?;
    yaml_text(&root, "schema", "mcloving.jenkins.jobstate-import")?;
    yaml_text(&root, "job_id", expected.job_id)?;
    yaml_text(&root, "state", "disabled")?;
    yaml_text(&root, "generation", expected.job_generation)?;
    yaml_text(&root, "reason", JOB_REASON)?;
    yaml_text(&root, "actor", JOB_ACTOR)?;
    yaml_text(&root, "effective_time", JOB_EFFECTIVE_TIME)?;
    let provenance = yaml_map(
        yaml_field(&root, "provenance")?.clone().value,
        &[
            "compiler",
            "compiler_profile_sha256",
            "controller",
            "inventory_fingerprint",
            "source_sha256",
        ],
    )?;
    yaml_text(&provenance, "controller", CONTROLLER)?;
    yaml_text(&provenance, "inventory_fingerprint", INVENTORY_FINGERPRINT)?;
    yaml_text(&provenance, "source_sha256", source_sha256)?;
    yaml_text(&provenance, "compiler", COMPILER)?;
    yaml_text(&provenance, "compiler_profile_sha256", PROFILE_SHA256)?;
    if render_jobstate(expected, source_sha256) != source {
        return Err(AdmissionError::new(
            "E_JOBSTATE_CANONICAL",
            "operational state is valid but not canonical compiler output",
        ));
    }
    Ok(())
}

fn render_jobstate(expected: &ExpectedAdmission<'_>, source_sha256: &str) -> String {
    format!(
        concat!(
            "version: 1\n",
            "schema: mcloving.jenkins.jobstate-import\n",
            "job_id: {}\n",
            "state: disabled\n",
            "generation: {}\n",
            "reason: {}\n",
            "actor: {}\n",
            "effective_time: {}\n",
            "provenance:\n",
            "  controller: {}\n",
            "  inventory_fingerprint: {}\n",
            "  source_sha256: {}\n",
            "  compiler: {}\n",
            "  compiler_profile_sha256: {}\n"
        ),
        yaml_string(expected.job_id),
        yaml_string(expected.job_generation),
        yaml_string(JOB_REASON),
        yaml_string(JOB_ACTOR),
        yaml_string(JOB_EFFECTIVE_TIME),
        yaml_string(CONTROLLER),
        yaml_string(INVENTORY_FINGERPRINT),
        yaml_string(source_sha256),
        yaml_string(COMPILER),
        yaml_string(PROFILE_SHA256)
    )
}

fn yaml_string(value: &str) -> String {
    quote_string(value)
}

fn yaml_map(
    value: YamlValue,
    expected: &[&str],
) -> Result<BTreeMap<String, mcloving_pipeline_ir::SpannedValue>, AdmissionError> {
    let YamlValue::Mapping(entries) = value else {
        return Err(AdmissionError::new("E_JOBSTATE_SCHEMA", "expected mapping"));
    };
    let map = entries
        .into_iter()
        .map(|entry| (entry.key, entry.value))
        .collect::<BTreeMap<_, _>>();
    let actual = map.keys().map(String::as_str).collect::<Vec<_>>();
    if actual != expected {
        return Err(AdmissionError::new(
            "E_JOBSTATE_SCHEMA",
            format!("unexpected fields: {actual:?}"),
        ));
    }
    Ok(map)
}

fn yaml_field<'a>(
    map: &'a BTreeMap<String, mcloving_pipeline_ir::SpannedValue>,
    key: &str,
) -> Result<&'a mcloving_pipeline_ir::SpannedValue, AdmissionError> {
    map.get(key)
        .ok_or_else(|| AdmissionError::new("E_JOBSTATE_SCHEMA", format!("missing {key}")))
}

fn yaml_text(
    map: &BTreeMap<String, mcloving_pipeline_ir::SpannedValue>,
    key: &str,
    expected: &str,
) -> Result<(), AdmissionError> {
    let YamlValue::String(actual) = &yaml_field(map, key)?.value else {
        return Err(AdmissionError::new(
            "E_JOBSTATE_SCHEMA",
            format!("{key} must be text"),
        ));
    };
    if actual != expected {
        return Err(AdmissionError::new(
            "E_JOBSTATE_SUBSTITUTION",
            format!("{key} changed"),
        ));
    }
    Ok(())
}

fn yaml_integer(
    map: &BTreeMap<String, mcloving_pipeline_ir::SpannedValue>,
    key: &str,
    expected: i64,
) -> Result<(), AdmissionError> {
    if !matches!(
        &yaml_field(map, key)?.value,
        YamlValue::Integer(actual) if *actual == expected
    ) {
        return Err(AdmissionError::new(
            "E_JOBSTATE_SCHEMA",
            format!("{key} changed"),
        ));
    }
    Ok(())
}

fn exact_map<'a>(
    value: &'a Edn,
    expected: &[&str],
    code: &'static str,
) -> Result<&'a BTreeMap<String, Edn>, AdmissionError> {
    let Edn::Map(map) = value else {
        return Err(AdmissionError::new(code, "expected map"));
    };
    let actual = map.keys().map(String::as_str).collect::<Vec<_>>();
    if actual != expected {
        return Err(AdmissionError::new(
            code,
            format!("unexpected fields: {actual:?}"),
        ));
    }
    Ok(map)
}

fn field<'a>(map: &'a BTreeMap<String, Edn>, key: &str) -> Result<&'a Edn, AdmissionError> {
    map.get(key)
        .ok_or_else(|| AdmissionError::new("E_RESPONSE_FIELDS", format!("missing {key}")))
}

fn string_field<'a>(map: &'a BTreeMap<String, Edn>, key: &str) -> Result<&'a str, AdmissionError> {
    let Edn::String(value) = field(map, key)? else {
        return Err(AdmissionError::new(
            "E_RESPONSE_TYPE",
            format!("{key} must be a string"),
        ));
    };
    Ok(value)
}

fn expect_string(
    map: &BTreeMap<String, Edn>,
    key: &str,
    expected: &str,
) -> Result<(), AdmissionError> {
    if string_field(map, key)? != expected {
        return Err(AdmissionError::new(
            "E_RESPONSE_SUBSTITUTION",
            format!("{key} changed"),
        ));
    }
    Ok(())
}

fn expect_keyword(
    map: &BTreeMap<String, Edn>,
    key: &str,
    expected: &str,
) -> Result<(), AdmissionError> {
    if !matches!(field(map, key)?, Edn::Keyword(value) if value == expected) {
        return Err(AdmissionError::new(
            "E_RESPONSE_SUBSTITUTION",
            format!("{key} changed"),
        ));
    }
    Ok(())
}

fn expect_bool(
    map: &BTreeMap<String, Edn>,
    key: &str,
    expected: bool,
) -> Result<(), AdmissionError> {
    if !matches!(field(map, key)?, Edn::Bool(value) if *value == expected) {
        return Err(AdmissionError::new(
            "E_RESPONSE_SUBSTITUTION",
            format!("{key} changed"),
        ));
    }
    Ok(())
}

fn expect_integer(
    map: &BTreeMap<String, Edn>,
    key: &str,
    expected: i64,
) -> Result<(), AdmissionError> {
    if !matches!(field(map, key)?, Edn::Integer(value) if *value == expected) {
        return Err(AdmissionError::new(
            "E_RESPONSE_SUBSTITUTION",
            format!("{key} changed"),
        ));
    }
    Ok(())
}

fn sha256_hex(value: &[u8]) -> String {
    Sha256::digest(value)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn quote_string(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{0008}' => output.push_str("\\b"),
            '\u{000c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character => output.push(character),
        }
    }
    output.push('"');
    output
}

fn render_edn(value: &Edn) -> String {
    match value {
        Edn::Map(map) => {
            let entries = map
                .iter()
                .map(|(key, value)| format!(":{key} {}", render_edn(value)))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{{{entries}}}")
        }
        Edn::Vector(values) => format!(
            "[{}]",
            values.iter().map(render_edn).collect::<Vec<_>>().join(" ")
        ),
        Edn::String(value) => quote_string(value),
        Edn::Keyword(value) => format!(":{value}"),
        Edn::Bool(value) => value.to_string(),
        Edn::Integer(value) => value.to_string(),
    }
}

struct EdnParser<'a> {
    source: &'a str,
    cursor: usize,
    nodes: usize,
}

impl<'a> EdnParser<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            cursor: 0,
            nodes: 0,
        }
    }

    fn parse(mut self) -> Result<Edn, AdmissionError> {
        let value = self.value(0)?;
        self.whitespace();
        if self.cursor != self.source.len() {
            return Err(AdmissionError::new("E_RESPONSE_EDN", "trailing EDN data"));
        }
        Ok(value)
    }

    fn value(&mut self, depth: usize) -> Result<Edn, AdmissionError> {
        self.whitespace();
        self.nodes += 1;
        if depth > 32 || self.nodes > 4096 {
            return Err(AdmissionError::new(
                "E_RESPONSE_EDN_LIMIT",
                "EDN structure limit exceeded",
            ));
        }
        match self.peek() {
            Some('{') => self.map(depth + 1),
            Some('[') => self.vector(depth + 1),
            Some('"') => self.string().map(Edn::String),
            Some(':') => self.keyword().map(Edn::Keyword),
            Some('t') if self.take_word("true") => Ok(Edn::Bool(true)),
            Some('f') if self.take_word("false") => Ok(Edn::Bool(false)),
            Some('-' | '0'..='9') => self.integer(),
            _ => Err(AdmissionError::new(
                "E_RESPONSE_EDN",
                "unsupported EDN value",
            )),
        }
    }

    fn map(&mut self, depth: usize) -> Result<Edn, AdmissionError> {
        self.expect('{')?;
        let mut map = BTreeMap::new();
        loop {
            self.whitespace();
            if self.take('}') {
                return Ok(Edn::Map(map));
            }
            let key = self.keyword()?;
            if map.contains_key(&key) {
                return Err(AdmissionError::new("E_RESPONSE_EDN", "duplicate map key"));
            }
            let value = self.value(depth)?;
            map.insert(key, value);
            self.whitespace();
        }
    }

    fn vector(&mut self, depth: usize) -> Result<Edn, AdmissionError> {
        self.expect('[')?;
        let mut values = Vec::new();
        loop {
            self.whitespace();
            if self.take(']') {
                return Ok(Edn::Vector(values));
            }
            if values.len() >= 4096 {
                return Err(AdmissionError::new(
                    "E_RESPONSE_EDN_LIMIT",
                    "EDN vector limit exceeded",
                ));
            }
            values.push(self.value(depth)?);
        }
    }

    fn string(&mut self) -> Result<String, AdmissionError> {
        self.expect('"')?;
        let mut output = String::new();
        loop {
            let Some(character) = self.next() else {
                return Err(AdmissionError::new("E_RESPONSE_EDN", "unterminated string"));
            };
            match character {
                '"' => return Ok(output),
                '\\' => {
                    let Some(escaped) = self.next() else {
                        return Err(AdmissionError::new("E_RESPONSE_EDN", "unterminated escape"));
                    };
                    output.push(match escaped {
                        '"' => '"',
                        '\\' => '\\',
                        'b' => '\u{0008}',
                        'f' => '\u{000c}',
                        'n' => '\n',
                        'r' => '\r',
                        't' => '\t',
                        _ => {
                            return Err(AdmissionError::new(
                                "E_RESPONSE_EDN",
                                "unsupported string escape",
                            ));
                        }
                    });
                }
                character if character.is_control() => {
                    return Err(AdmissionError::new(
                        "E_RESPONSE_EDN",
                        "unescaped control character",
                    ));
                }
                character => output.push(character),
            }
        }
    }

    fn keyword(&mut self) -> Result<String, AdmissionError> {
        self.expect(':')?;
        let start = self.cursor;
        while self
            .peek()
            .is_some_and(|value| value.is_ascii_alphanumeric() || "._:/-".contains(value))
        {
            self.next();
        }
        if start == self.cursor {
            return Err(AdmissionError::new("E_RESPONSE_EDN", "empty keyword"));
        }
        Ok(self.source[start..self.cursor].to_owned())
    }

    fn integer(&mut self) -> Result<Edn, AdmissionError> {
        let start = self.cursor;
        self.take('-');
        while self.peek().is_some_and(|value| value.is_ascii_digit()) {
            self.next();
        }
        self.source[start..self.cursor]
            .parse::<i64>()
            .map(Edn::Integer)
            .map_err(|_| AdmissionError::new("E_RESPONSE_EDN", "invalid integer"))
    }

    fn whitespace(&mut self) {
        while self
            .peek()
            .is_some_and(|value| value.is_ascii_whitespace() || value == ',')
        {
            self.next();
        }
    }

    fn take_word(&mut self, word: &str) -> bool {
        if self.source[self.cursor..].starts_with(word) {
            self.cursor += word.len();
            true
        } else {
            false
        }
    }

    fn expect(&mut self, expected: char) -> Result<(), AdmissionError> {
        if self.take(expected) {
            Ok(())
        } else {
            Err(AdmissionError::new(
                "E_RESPONSE_EDN",
                format!("expected {expected:?}"),
            ))
        }
    }

    fn take(&mut self, expected: char) -> bool {
        if self.peek() == Some(expected) {
            self.next();
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<char> {
        self.source[self.cursor..].chars().next()
    }

    fn next(&mut self) -> Option<char> {
        let value = self.peek()?;
        self.cursor += value.len_utf8();
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_edn_round_trips_and_rejects_presentation_drift() {
        let source = "{:a false, :b [1 \"two\"], :c :done}";
        let parsed = EdnParser::new(source).parse().unwrap();
        assert_eq!(render_edn(&parsed), source);
        assert_ne!(render_edn(&parsed), "{ :a false :b [1 \"two\"] :c :done }");
    }

    #[test]
    fn edn_parser_rejects_duplicates_tags_lists_and_trailing_data() {
        for source in [
            "{:a 1, :a 2}",
            "#foo {:a 1}",
            "(:a 1)",
            "{:a 1} {:b 2}",
            "{:a \"unterminated}",
        ] {
            assert!(EdnParser::new(source).parse().is_err(), "{source}");
        }
    }
}
