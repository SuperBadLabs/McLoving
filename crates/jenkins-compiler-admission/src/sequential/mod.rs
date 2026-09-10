//! Version-two compile-only admission. Caller attribution and exact source
//! semantics are verified independently; this module grants no execution authority.
use super::{
    AdmissionError, BTreeMap, Edn, EdnParser, MAX_RESPONSE_BYTES, PROFILE_SHA256, ParseLimits,
    Step, compile_strict_yaml, exact_map, expect_bool, expect_integer, expect_string, field,
    parse_strict, render_edn, sha256_hex, string_field, validate_authority,
    validate_canonical_bytes, validate_diagnostic, validate_profile,
};
use mcloving_pipeline_ir::ProcessMode;
mod source;
use source::{Classification, Stage};

pub const PROTOCOL: &str = "mcloving.jenkins.compiler/2";
pub const COMPILER: &str = "mcloving-jenkins-compiler-worker/2";
pub const CONTRACT_SHA256: &str =
    "264436c57b3aa82810f7041515c924b38a5a5e4be1f60fb6987151d1e8336a41";
pub const MAX_SOURCE_BYTES: usize = 16_384;
pub const MAX_CONTEXT_BYTES: usize = 2_048;
const TRANSPORT_SOURCE_BYTES: usize = 262_144;

/// Immutable validated caller-owned attribution, not proof of origin ownership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DocumentContext {
    document_id: String,
    origin: String,
    origin_kind: String,
    source_sha256: String,
    canonical: Vec<u8>,
    value: Edn,
}
impl DocumentContext {
    pub fn document_id(&self) -> &str {
        &self.document_id
    }
    pub fn context_sha256(&self) -> String {
        sha256_hex(&self.canonical)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SequentialExpectedAdmission<'a> {
    pub request_id: &'a str,
    pub source: &'a [u8],
    pub context: &'a DocumentContext,
}
// The frozen v2 API returns one bounded receipt by value; avoid introducing
// an allocation solely to equalize the two small denial variants.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SequentialValidatedResponse {
    Admitted(SequentialAdmissionReceipt),
    Unsupported { code: String },
    Rejected { code: String },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SequentialAdmissionReceipt {
    pub protocol: String,
    pub compiler: String,
    pub target_profile_sha256: String,
    pub request_id: String,
    pub document_id: String,
    pub source_sha256: String,
    pub context_sha256: String,
    pub contract_sha256: String,
    pub pipeline_yaml_sha256: String,
    pub definition_yaml_sha256: String,
    pub semantic_ir_sha256: String,
    pub canonical_ir_sha256: String,
    pub stages: usize,
    pub steps: usize,
    pub state: String,
    pub execution_authority: bool,
}

fn canonical(bytes: &[u8], limit: usize, code: &'static str) -> Result<Edn, AdmissionError> {
    if bytes.len() > limit {
        return Err(AdmissionError::new(
            code,
            "bounded canonical EDN size exceeded",
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| AdmissionError::new(code, "canonical EDN must be UTF-8"))?;
    let body = text
        .strip_suffix('\n')
        .ok_or_else(|| AdmissionError::new(code, "canonical EDN requires one final LF"))?;
    let parsed = EdnParser::new(body)
        .parse()
        .map_err(|_| AdmissionError::new(code, "invalid canonical EDN"))?;
    if render_edn(&parsed) != body {
        return Err(AdmissionError::new(code, "noncanonical EDN"));
    }
    Ok(parsed)
}
fn identifier(value: &str, max: usize, colon: bool) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b) || (colon && b == b':'))
}
pub fn parse_document_context(
    bytes: &[u8],
    source: &[u8],
) -> Result<DocumentContext, AdmissionError> {
    parse_document_context_inner(bytes, source)
        .map_err(|error| AdmissionError::new(error.code, "document context validation failed"))
}

fn parse_document_context_inner(
    bytes: &[u8],
    source: &[u8],
) -> Result<DocumentContext, AdmissionError> {
    let parsed = canonical(bytes, MAX_CONTEXT_BYTES, "E_DOCUMENT_CONTEXT")?;
    let context = exact_map(
        &parsed,
        &[
            "document-id",
            "origin",
            "origin-kind",
            "schema",
            "source-sha256",
        ],
        "E_DOCUMENT_CONTEXT",
    )?;
    expect_string(context, "schema", "mcloving.jenkins.source-document/1")?;
    let document_id = string_field(context, "document-id")?;
    let origin = string_field(context, "origin")?;
    if !identifier(document_id, 128, false)
        || origin.is_empty()
        || origin.len() > 512
        || !origin.bytes().all(|b| (0x20..=0x7e).contains(&b))
    {
        return Err(AdmissionError::new(
            "E_DOCUMENT_CONTEXT",
            "invalid document identifier or origin",
        ));
    }
    let Edn::Keyword(origin_kind) = field(context, "origin-kind")? else {
        return Err(AdmissionError::new(
            "E_DOCUMENT_CONTEXT",
            "origin kind must be a keyword",
        ));
    };
    if !["authored-document", "corpus-reference"].contains(&origin_kind.as_str()) {
        return Err(AdmissionError::new(
            "E_DOCUMENT_CONTEXT",
            "unknown origin kind",
        ));
    }
    let source_sha256 = string_field(context, "source-sha256")?;
    if source_sha256 != sha256_hex(source) {
        return Err(AdmissionError::new(
            "E_SOURCE_DIGEST",
            "document source digest does not match snapshot",
        ));
    }
    Ok(DocumentContext {
        document_id: document_id.to_owned(),
        origin: origin.to_owned(),
        origin_kind: origin_kind.clone(),
        source_sha256: source_sha256.to_owned(),
        canonical: bytes.to_vec(),
        value: parsed,
    })
}
fn expectations(expected: SequentialExpectedAdmission<'_>) -> Result<(), AdmissionError> {
    if !identifier(expected.request_id, 96, true) {
        return Err(AdmissionError::new(
            "E_REQUEST_ID",
            "invalid request identifier",
        ));
    }
    if expected.source.len() > TRANSPORT_SOURCE_BYTES {
        return Err(AdmissionError::new(
            "E_SOURCE_TOO_LARGE",
            "source transport ceiling exceeded",
        ));
    }
    if sha256_hex(expected.source) != expected.context.source_sha256 {
        return Err(AdmissionError::new(
            "E_SOURCE_DIGEST",
            "context does not bind this source snapshot",
        ));
    }
    Ok(())
}
fn map(entries: Vec<(&str, Edn)>) -> Edn {
    Edn::Map(
        entries
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect(),
    )
}
fn text(value: &str) -> Edn {
    Edn::String(value.to_owned())
}
fn keyword(value: &str) -> Edn {
    Edn::Keyword(value.to_owned())
}
fn encoded(value: &Edn) -> Vec<u8> {
    format!("{}\n", render_edn(value)).into_bytes()
}
pub fn sequential_request(
    expected: SequentialExpectedAdmission<'_>,
) -> Result<Vec<u8>, AdmissionError> {
    expectations(expected)?;
    Ok(encoded(&map(vec![
        ("operation", keyword("compile-sequential")),
        ("protocol", text(PROTOCOL)),
        ("request-id", text(expected.request_id)),
        ("source-context", expected.context.value.clone()),
        ("source-path", text("/input/Jenkinsfile")),
        ("target-contract-sha256", text(CONTRACT_SHA256)),
        ("target-profile-sha256", text(PROFILE_SHA256)),
    ])))
}
fn common(root: &BTreeMap<String, Edn>) -> Result<(), AdmissionError> {
    expect_string(root, "protocol", PROTOCOL)?;
    expect_string(root, "compiler", COMPILER)?;
    validate_authority(field(root, "authority")?)
}
fn attributed(
    root: &BTreeMap<String, Edn>,
    expected: SequentialExpectedAdmission<'_>,
) -> Result<(), AdmissionError> {
    common(root)?;
    expect_string(root, "request-id", expected.request_id)?;
    expect_string(root, "contract-sha256", CONTRACT_SHA256)?;
    validate_profile(field(root, "target-profile")?)?;
    if field(root, "source-context")? != &expected.context.value {
        return Err(AdmissionError::new(
            "E_DOCUMENT_CONTEXT",
            "returned context differs from caller snapshot",
        ));
    }
    let source = exact_map(
        field(root, "source")?,
        &["bytes", "context-sha256", "sha256"],
        "E_SOURCE_RECEIPT",
    )?;
    expect_integer(source, "bytes", expected.source.len() as i64)?;
    expect_string(source, "context-sha256", &expected.context.context_sha256())?;
    expect_string(source, "sha256", &expected.context.source_sha256)
}

pub fn validate_sequential_response(
    response: &[u8],
    expected: SequentialExpectedAdmission<'_>,
) -> Result<SequentialValidatedResponse, AdmissionError> {
    // Shared legacy validators may describe attacker-controlled map keys. V2
    // exposes only the stable code and a fixed message, never worker payload.
    validate_sequential_response_inner(response, expected)
        .map_err(|error| AdmissionError::new(error.code, "sequential response validation failed"))
}

fn validate_sequential_response_inner(
    response: &[u8],
    expected: SequentialExpectedAdmission<'_>,
) -> Result<SequentialValidatedResponse, AdmissionError> {
    expectations(expected)?;
    if response.len() > MAX_RESPONSE_BYTES {
        return Err(AdmissionError::new(
            "E_RESPONSE_TOO_LARGE",
            "worker response exceeds 65536 bytes",
        ));
    }
    let parsed = canonical(response, MAX_RESPONSE_BYTES, "E_RESPONSE_CANONICAL")?;
    let Edn::Map(root) = &parsed else {
        return Err(AdmissionError::new(
            "E_RESPONSE_FIELDS",
            "expected response map",
        ));
    };
    let Edn::Keyword(status) = field(root, "status")? else {
        return Err(AdmissionError::new(
            "E_RESPONSE_STATUS",
            "expected status keyword",
        ));
    };
    let classification = source::classify(expected.source);
    match status.as_str() {
        "compiled" => {
            let root = exact_map(
                &parsed,
                &[
                    "authority",
                    "compiler",
                    "contract-sha256",
                    "protocol",
                    "request-id",
                    "result",
                    "source",
                    "source-context",
                    "status",
                    "target-profile",
                ],
                "E_RESPONSE_FIELDS",
            )?;
            attributed(root, expected)?;
            let Classification::Supported(stages) = classification else {
                return Err(AdmissionError::new(
                    "E_SOURCE_SEMANTICS",
                    "source is not independently recognized as supported",
                ));
            };
            admit(root, expected, &stages).map(SequentialValidatedResponse::Admitted)
        }
        "unsupported" => {
            let root = exact_map(
                &parsed,
                &[
                    "authority",
                    "compiler",
                    "contract-sha256",
                    "diagnostic",
                    "protocol",
                    "request-id",
                    "source",
                    "source-context",
                    "status",
                    "target-profile",
                ],
                "E_RESPONSE_FIELDS",
            )?;
            attributed(root, expected)?;
            let Classification::Unsupported(code) = classification else {
                return Err(AdmissionError::new(
                    "E_SOURCE_CLASSIFICATION",
                    "unsupported status disagrees with independent recognition",
                ));
            };
            let code = validate_diagnostic(
                field(root, "diagnostic")?,
                &[code],
                "source is outside the currently admitted compiler subset",
            )?;
            Ok(SequentialValidatedResponse::Unsupported { code })
        }
        "rejected" => {
            let root = exact_map(
                &parsed,
                &["authority", "compiler", "diagnostic", "protocol", "status"],
                "E_RESPONSE_FIELDS",
            )?;
            common(root)?;
            let Classification::Rejected(code) = classification else {
                return Err(AdmissionError::new(
                    "E_SOURCE_CLASSIFICATION",
                    "rejection is not an independently confirmed source failure",
                ));
            };
            let code = validate_diagnostic(
                field(root, "diagnostic")?,
                &[code],
                "request rejected without execution authority",
            )?;
            Ok(SequentialValidatedResponse::Rejected { code })
        }
        _ => Err(AdmissionError::new(
            "E_RESPONSE_STATUS",
            "unknown sequential response status",
        )),
    }
}

fn admit(
    root: &BTreeMap<String, Edn>,
    expected: SequentialExpectedAdmission<'_>,
    stages: &[Stage],
) -> Result<SequentialAdmissionReceipt, AdmissionError> {
    let result = exact_map(
        field(root, "result")?,
        &[
            "agent-mapping",
            "definition-yaml",
            "definition-yaml-sha256",
            "pipeline-yaml",
            "pipeline-yaml-sha256",
            "semantic",
        ],
        "E_RESULT_FIELDS",
    )?;
    let mapping = exact_map(
        field(result, "agent-mapping")?,
        &[
            "effect-authority",
            "jenkins-selector",
            "mcloving-platform",
            "trust-pool",
        ],
        "E_AGENT_MAPPING",
    )?;
    expect_bool(mapping, "effect-authority", false)?;
    expect_string(mapping, "jenkins-selector", "any")?;
    expect_string(mapping, "mcloving-platform", "linux")?;
    expect_string(mapping, "trust-pool", "migration-deny-authority")?;
    let yaml = string_field(result, "pipeline-yaml")?;
    if yaml != pipeline_yaml(expected.context.document_id(), stages) {
        return Err(AdmissionError::new(
            "E_PIPELINE_SEMANTICS",
            "pipeline differs from independent source lowering",
        ));
    }
    let yaml_sha = sha256_hex(yaml.as_bytes());
    expect_string(result, "pipeline-yaml-sha256", &yaml_sha)?;
    let pipeline = compile_strict_yaml(
        &format!("jenkins-document://{}", expected.context.document_id()),
        yaml,
        ParseLimits::default(),
    )
    .map_err(|_| AdmissionError::new("E_PIPELINE_YAML", "strict pipeline compilation failed"))?;
    if pipeline.name != expected.context.document_id()
        || !pipeline.parameters.is_empty()
        || !pipeline.parameter_values.is_empty()
        || !pipeline.expressions.is_empty()
        || pipeline.stages.len() != stages.len()
    {
        return Err(AdmissionError::new(
            "E_PIPELINE_SEMANTICS",
            "unexpected pipeline identity or inputs",
        ));
    }
    for (actual, wanted) in pipeline.stages.iter().zip(stages) {
        if actual.name != wanted.name
            || actual.id != wanted.id
            || actual.steps.len() != wanted.scripts.len()
        {
            return Err(AdmissionError::new(
                "E_PIPELINE_SEMANTICS",
                "unexpected stage lowering",
            ));
        }
        for (step, script) in actual.steps.iter().zip(&wanted.scripts) {
            let Step::Process(process) = step else {
                return Err(AdmissionError::new(
                    "E_PIPELINE_SEMANTICS",
                    "non-process step",
                ));
            };
            if process.mode != ProcessMode::Direct
                || process.program != "/bin/sh"
                || process.args != ["-xe", "-c", script]
                || !process.env.is_empty()
                || process.timeout_seconds.is_some()
            {
                return Err(AdmissionError::new(
                    "E_PIPELINE_SEMANTICS",
                    "unexpected process lowering",
                ));
            }
        }
    }
    let canonical_ir = pipeline
        .canonical_bytes()
        .map_err(|_| AdmissionError::new("E_PIPELINE_IR", "invalid pipeline IR"))?;
    let summary = validate_canonical_bytes(&canonical_ir)
        .map_err(|_| AdmissionError::new("E_PIPELINE_IR", "invalid canonical IR"))?;
    let definition = string_field(result, "definition-yaml")?;
    if definition != definition_yaml(expected.context, &yaml_sha) {
        return Err(AdmissionError::new(
            "E_DEFINITION_CANONICAL",
            "disabled definition differs from caller provenance",
        ));
    }
    // Independently exercise strict YAML's duplicate/alias/type constraints even
    // though exact rendering has already bound every field and scalar.
    parse_strict(definition, ParseLimits::default()).map_err(|_| {
        AdmissionError::new("E_DEFINITION_YAML", "invalid strict disabled definition")
    })?;
    let definition_sha = sha256_hex(definition.as_bytes());
    expect_string(result, "definition-yaml-sha256", &definition_sha)?;
    let semantic = exact_map(
        field(result, "semantic")?,
        &["stages", "steps"],
        "E_SEMANTIC_FIELDS",
    )?;
    expect_integer(semantic, "stages", summary.stages as i64)?;
    expect_integer(semantic, "steps", summary.steps as i64)?;
    Ok(SequentialAdmissionReceipt {
        protocol: PROTOCOL.to_owned(),
        compiler: COMPILER.to_owned(),
        target_profile_sha256: PROFILE_SHA256.to_owned(),
        request_id: expected.request_id.to_owned(),
        document_id: expected.context.document_id.clone(),
        source_sha256: expected.context.source_sha256.clone(),
        context_sha256: expected.context.context_sha256(),
        contract_sha256: CONTRACT_SHA256.to_owned(),
        pipeline_yaml_sha256: yaml_sha,
        definition_yaml_sha256: definition_sha,
        semantic_ir_sha256: pipeline
            .semantic_digest_hex()
            .map_err(|_| AdmissionError::new("E_PIPELINE_IR", "semantic IR digest failed"))?,
        canonical_ir_sha256: sha256_hex(&canonical_ir),
        stages: summary.stages,
        steps: summary.steps,
        state: "disabled".to_owned(),
        execution_authority: false,
    })
}

fn yaml_string(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if (' '..='~').contains(&ch) => out.push(ch),
            ch if u32::from(ch) <= 0xffff => out.push_str(&format!("\\u{:04x}", u32::from(ch))),
            ch => out.push_str(&format!("\\U{:08x}", u32::from(ch))),
        }
    }
    out.push('"');
    out
}
fn pipeline_yaml(document_id: &str, stages: &[Stage]) -> String {
    let mut out = format!("version: 1\nname: {}\nstages:\n", yaml_string(document_id));
    for stage in stages {
        out.push_str(&format!(
            "  - id: {}\n    name: {}\n    steps:\n",
            yaml_string(&stage.id),
            yaml_string(&stage.name)
        ));
        for script in &stage.scripts {
            out.push_str(&format!("      - process:\n          program: \"/bin/sh\"\n          args: [\"-xe\", \"-c\", {}]\n", yaml_string(script)));
        }
    }
    out
}
fn definition_yaml(context: &DocumentContext, pipeline_sha: &str) -> String {
    format!(
        "version: 1\nschema: mcloving.jenkins.disabled-document\ndefinition_id: {}\nstate: disabled\nsource:\n  context_sha256: {}\n  origin_kind: {}\n  origin: {}\n  sha256: {}\ncompilation:\n  compiler: {}\n  contract_sha256: {}\n  target_profile_sha256: {}\n  pipeline_yaml_sha256: {}\n",
        yaml_string(&context.document_id),
        yaml_string(&context.context_sha256()),
        yaml_string(&context.origin_kind),
        yaml_string(&context.origin),
        yaml_string(&context.source_sha256),
        yaml_string(COMPILER),
        yaml_string(CONTRACT_SHA256),
        yaml_string(PROFILE_SHA256),
        yaml_string(pipeline_sha)
    )
}

#[cfg(test)]
mod tests;
