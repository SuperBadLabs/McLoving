use std::collections::{BTreeMap, HashSet};
use std::fmt;

use sha2::{Digest, Sha256};

use crate::canonical::encode_pipeline;
use crate::expression::{
    EvaluatedValue, Expression, ExpressionError, ExpressionLimits, ParameterValue,
    evaluate_expression, parse_expression, validate_expression,
};
use crate::strict_yaml::{
    AdmissionError, MappingEntry, ParseLimits, SourceSpan, SpannedValue, YamlValue, parse_strict,
};
use crate::{IR_V1, IR_V1_1};

pub(crate) const MAX_IR_STRING_BYTES: usize = 16 * 1024;
pub(crate) const MAX_STAGES: usize = 128;
pub(crate) const MAX_STEPS: usize = 4_096;
pub(crate) const MAX_PARAMETERS: usize = 128;
pub(crate) const MAX_EXPRESSION_BINDINGS: usize = 8_192;

/// Pipeline IR compatibility identity.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SchemaVersion {
    pub major: u16,
    pub minor: u16,
}

/// Compatibility result for a reader and a produced IR version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaCompatibility {
    Compatible,
    ReaderTooOld,
    MajorMismatch,
}

impl SchemaVersion {
    /// Decide whether this reader can consume a produced version.
    pub fn compatibility_with(self, produced: Self) -> SchemaCompatibility {
        if self.major != produced.major {
            SchemaCompatibility::MajorMismatch
        } else if self.minor < produced.minor {
            SchemaCompatibility::ReaderTooOld
        } else {
            SchemaCompatibility::Compatible
        }
    }
}

/// Identity of the compiler that admitted source into the IR.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompilerIdentity {
    pub name: String,
    pub version: String,
}

/// Exact input provenance. It is deliberately separate from semantic bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Provenance {
    pub source_id: String,
    pub source_sha256: [u8; 32],
    pub compiler: CompilerIdentity,
}

/// Canonical pipeline admitted by the strict YAML compiler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PipelineIr {
    pub schema: SchemaVersion,
    pub name: String,
    pub parameters: BTreeMap<String, ParameterDefinition>,
    pub parameter_values: BTreeMap<String, ParameterValue>,
    pub expressions: Vec<ExpressionBinding>,
    pub stages: Vec<Stage>,
    pub provenance: Provenance,
    pub source_span: SourceSpan,
}

/// The exact type of a native pipeline parameter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParameterType {
    Bool,
    Integer,
    String,
}

impl ParameterType {
    fn name(self) -> &'static str {
        match self {
            Self::Bool => "boolean",
            Self::Integer => "integer",
            Self::String => "string",
        }
    }

    fn accepts(self, value: &ParameterValue) -> bool {
        matches!(
            (self, value),
            (Self::Bool, ParameterValue::Bool(_))
                | (Self::Integer, ParameterValue::Integer(_))
                | (Self::String, ParameterValue::String(_))
        )
    }
}

/// A typed parameter declaration. Secret parameters may not have defaults and
/// are never persisted in `parameter_values`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParameterDefinition {
    pub parameter_type: ParameterType,
    pub default: Option<ParameterValue>,
    pub secret: bool,
}

/// The canonical expression that produced one concrete IR field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpressionBinding {
    pub path: String,
    pub expression: Expression,
}

/// A sequential stage in Pipeline IR v1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Stage {
    pub id: String,
    pub name: String,
    pub steps: Vec<Step>,
    pub source_span: SourceSpan,
}

/// A Pipeline IR v1 step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Step {
    Process(ProcessStep),
}

/// A native direct-process step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessStep {
    pub program: String,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub timeout_seconds: Option<u64>,
    pub source_span: SourceSpan,
}

impl PipelineIr {
    /// Deterministic semantic bytes. Provenance and source spans are excluded.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, IrValidationError> {
        validate_pipeline(self)?;
        Ok(encode_pipeline(self))
    }

    /// SHA-256 of the deterministic semantic bytes.
    pub fn semantic_digest(&self) -> Result<[u8; 32], IrValidationError> {
        Ok(Sha256::digest(self.canonical_bytes()?).into())
    }

    /// Lowercase hexadecimal semantic digest.
    pub fn semantic_digest_hex(&self) -> Result<String, IrValidationError> {
        Ok(self
            .semantic_digest()?
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect())
    }
}

/// Structural validation error independent of YAML parsing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrValidationError {
    pub path: String,
    pub message: String,
}

impl IrValidationError {
    fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for IrValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.path, self.message)
    }
}

impl std::error::Error for IrValidationError {}

/// Compile strict YAML into Pipeline IR v1.
pub fn compile_strict_yaml(
    source_id: &str,
    source: &str,
    limits: ParseLimits,
) -> Result<PipelineIr, CompileError> {
    compile_strict_yaml_with_parameters(source_id, source, limits, BTreeMap::new())
}

/// Compile strict YAML with explicit typed parameter inputs.
pub fn compile_strict_yaml_with_parameters(
    source_id: &str,
    source: &str,
    limits: ParseLimits,
    inputs: BTreeMap<String, ParameterValue>,
) -> Result<PipelineIr, CompileError> {
    let root = parse_strict(source, limits)?;
    let root_span = root.span;
    let mut root = MappingView::new(root, "$")?;
    let version = root.required_integer("version")?;
    if version != i64::from(IR_V1.major) {
        return Err(CompileError::schema(
            "$.version",
            format!("expected version {}, found {version}", IR_V1.major),
        ));
    }
    let name = root.required_string("name")?;
    let parameters_node = root.take("parameters");
    let stages_node = root.required("stages")?;
    root.finish()?;

    let parameters = compile_parameter_definitions(parameters_node)?;
    let (parameter_values, evaluation_context) = bind_parameter_values(&parameters, inputs)?;
    let mut expressions = Vec::new();
    let stages = compile_stages(stages_node, &evaluation_context, &mut expressions)?;
    expressions.sort_by(|left, right| left.path.cmp(&right.path));
    let schema = if parameters.is_empty() && expressions.is_empty() {
        IR_V1
    } else {
        IR_V1_1
    };
    let pipeline = PipelineIr {
        schema,
        name,
        parameters,
        parameter_values,
        expressions,
        stages,
        provenance: Provenance {
            source_id: source_id.to_owned(),
            source_sha256: Sha256::digest(source.as_bytes()).into(),
            compiler: CompilerIdentity {
                name: "mcloving-strict-yaml".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
            },
        },
        source_span: root_span,
    };
    validate_pipeline(&pipeline)?;
    Ok(pipeline)
}

fn compile_parameter_definitions(
    node: Option<SpannedValue>,
) -> Result<BTreeMap<String, ParameterDefinition>, CompileError> {
    let Some(node) = node else {
        return Ok(BTreeMap::new());
    };
    let span = node.span;
    let YamlValue::Mapping(entries) = node.value else {
        return Err(CompileError::schema("$.parameters", "expected a mapping").with_span(span));
    };
    if entries.len() > MAX_PARAMETERS {
        return Err(CompileError::schema(
            "$.parameters",
            format!("at most {MAX_PARAMETERS} parameters are accepted"),
        )
        .with_span(span));
    }
    entries
        .into_iter()
        .map(|entry| {
            let name = entry.key;
            validate_identifier(&format!("$.parameters.{name}"), &name)?;
            let path = format!("$.parameters.{name}");
            let mut definition = MappingView::new(entry.value, &path)?;
            let parameter_type = match definition.required_string("type")?.as_str() {
                "boolean" => ParameterType::Bool,
                "integer" => ParameterType::Integer,
                "string" => ParameterType::String,
                _ => {
                    return Err(CompileError::schema(
                        format!("{path}.type"),
                        "expected exactly boolean, integer, or string",
                    ));
                }
            };
            let secret = definition.optional_bool("secret")?.unwrap_or(false);
            let default = definition
                .take("default")
                .map(|value| compile_parameter_value(value, &format!("{path}.default")))
                .transpose()?;
            definition.finish()?;
            if secret && default.is_some() {
                return Err(CompileError::schema(
                    format!("{path}.default"),
                    "secret parameters must not declare persisted defaults",
                ));
            }
            if default
                .as_ref()
                .is_some_and(|value| !parameter_type.accepts(value))
            {
                return Err(CompileError::schema(
                    format!("{path}.default"),
                    format!("expected a {} default", parameter_type.name()),
                ));
            }
            Ok((
                name,
                ParameterDefinition {
                    parameter_type,
                    default,
                    secret,
                },
            ))
        })
        .collect()
}

fn compile_parameter_value(node: SpannedValue, path: &str) -> Result<ParameterValue, CompileError> {
    match node.value {
        YamlValue::Bool(value) => Ok(ParameterValue::Bool(value)),
        YamlValue::Integer(value) => Ok(ParameterValue::Integer(value)),
        YamlValue::String(value) => Ok(ParameterValue::String(value)),
        _ => Err(
            CompileError::schema(path, "expected a scalar parameter value").with_span(node.span),
        ),
    }
}

type BoundParameterValues = (
    BTreeMap<String, ParameterValue>,
    BTreeMap<String, EvaluatedValue>,
);

fn bind_parameter_values(
    definitions: &BTreeMap<String, ParameterDefinition>,
    mut inputs: BTreeMap<String, ParameterValue>,
) -> Result<BoundParameterValues, CompileError> {
    if let Some(name) = inputs.keys().find(|name| !definitions.contains_key(*name)) {
        return Err(CompileError::schema(
            format!("$.parameter_values.{name}"),
            "input does not have a parameter definition",
        ));
    }
    let mut public_values = BTreeMap::new();
    let mut context = BTreeMap::new();
    for (name, definition) in definitions {
        let value = inputs
            .remove(name)
            .or_else(|| definition.default.clone())
            .ok_or_else(|| {
                CompileError::schema(
                    format!("$.parameter_values.{name}"),
                    "required parameter input is missing",
                )
            })?;
        if !definition.parameter_type.accepts(&value) {
            return Err(CompileError::schema(
                format!("$.parameter_values.{name}"),
                format!("expected a {} value", definition.parameter_type.name()),
            ));
        }
        if !definition.secret {
            public_values.insert(name.clone(), value.clone());
        }
        context.insert(
            name.clone(),
            EvaluatedValue {
                value,
                secret: definition.secret,
            },
        );
    }
    Ok((public_values, context))
}

fn compile_stages(
    node: SpannedValue,
    parameters: &BTreeMap<String, EvaluatedValue>,
    expressions: &mut Vec<ExpressionBinding>,
) -> Result<Vec<Stage>, CompileError> {
    let span = node.span;
    let YamlValue::Sequence(nodes) = node.value else {
        return Err(CompileError::schema("$.stages", "expected a sequence").with_span(span));
    };
    if nodes.is_empty() {
        return Err(CompileError::schema(
            "$.stages",
            "at least one stage is required",
        ));
    }
    if nodes.len() > MAX_STAGES {
        return Err(CompileError::schema(
            "$.stages",
            format!("at most {MAX_STAGES} stages are accepted"),
        ));
    }

    nodes
        .into_iter()
        .enumerate()
        .map(|(index, node)| -> Result<Stage, CompileError> {
            let path = format!("$.stages[{index}]");
            let node_span = node.span;
            let mut stage = MappingView::new(node, &path)?;
            let id = stage.required_string("id")?;
            let name = stage.required_string("name")?;
            let steps_node = stage.required("steps")?;
            stage.finish()?;
            let steps = compile_steps(steps_node, &path, parameters, expressions)?;
            Ok(Stage {
                id,
                name,
                steps,
                source_span: node_span,
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.with_span_if_missing(span))
}

fn compile_steps(
    node: SpannedValue,
    stage_path: &str,
    parameters: &BTreeMap<String, EvaluatedValue>,
    expressions: &mut Vec<ExpressionBinding>,
) -> Result<Vec<Step>, CompileError> {
    let span = node.span;
    let YamlValue::Sequence(nodes) = node.value else {
        return Err(
            CompileError::schema(format!("{stage_path}.steps"), "expected a sequence")
                .with_span(span),
        );
    };
    if nodes.is_empty() {
        return Err(CompileError::schema(
            format!("{stage_path}.steps"),
            "at least one step is required",
        ));
    }
    nodes
        .into_iter()
        .enumerate()
        .map(|(index, node)| {
            let path = format!("{stage_path}.steps[{index}]");
            let step_span = node.span;
            let mut step = MappingView::new(node, &path)?;
            let process = step.required("process")?;
            step.finish()?;
            compile_process(process, &path, step_span, parameters, expressions).map(Step::Process)
        })
        .collect()
}

fn compile_process(
    node: SpannedValue,
    step_path: &str,
    source_span: SourceSpan,
    parameters: &BTreeMap<String, EvaluatedValue>,
    expressions: &mut Vec<ExpressionBinding>,
) -> Result<ProcessStep, CompileError> {
    let path = format!("{step_path}.process");
    let mut process = MappingView::new(node, &path)?;
    let program_node = process.required("program")?;
    let program = compile_resolved_string(
        program_node,
        &format!("{path}.program"),
        parameters,
        expressions,
    )?;
    let args = process
        .optional_resolved_string_sequence("args", parameters, expressions)?
        .unwrap_or_default();
    let env = process
        .optional_resolved_string_mapping("env", parameters, expressions)?
        .unwrap_or_default();
    let timeout_seconds = process.optional_u64("timeout_seconds")?;
    process.finish()?;
    Ok(ProcessStep {
        program,
        args,
        env,
        timeout_seconds,
        source_span,
    })
}

fn compile_resolved_string(
    node: SpannedValue,
    path: &str,
    parameters: &BTreeMap<String, EvaluatedValue>,
    expressions: &mut Vec<ExpressionBinding>,
) -> Result<String, CompileError> {
    let span = node.span;
    if let YamlValue::String(value) = node.value {
        return Ok(value);
    }
    let mut expression_view = MappingView::new(node, path)?;
    let source = expression_view.required_string("expression")?;
    expression_view.finish()?;
    let expression = parse_expression(&source, ExpressionLimits::default())
        .map_err(|error| CompileError::expression(path, error).with_span(span))?;
    let result = evaluate_expression(&expression, parameters, ExpressionLimits::default())
        .map_err(|error| CompileError::expression(path, error).with_span(span))?;
    if result.secret {
        return Err(CompileError::schema(
            path,
            "secret-tainted expression values cannot be materialized into Pipeline IR",
        )
        .with_span(span));
    }
    let ParameterValue::String(value) = result.value else {
        return Err(CompileError::schema(
            path,
            "process fields require an expression that evaluates to string",
        )
        .with_span(span));
    };
    if expressions.len() >= MAX_EXPRESSION_BINDINGS {
        return Err(CompileError::schema(
            path,
            format!("at most {MAX_EXPRESSION_BINDINGS} expression bindings are accepted"),
        )
        .with_span(span));
    }
    expressions.push(ExpressionBinding {
        path: path.to_owned(),
        expression,
    });
    Ok(value)
}

/// Validate a Pipeline IR object without consulting its YAML source.
pub fn validate_pipeline(pipeline: &PipelineIr) -> Result<(), IrValidationError> {
    if !matches!(pipeline.schema, IR_V1 | IR_V1_1) {
        return Err(IrValidationError::new(
            "$.schema",
            "only Pipeline IR v1.0 and v1.1 are accepted",
        ));
    }
    if pipeline.schema == IR_V1
        && (!pipeline.parameters.is_empty()
            || !pipeline.parameter_values.is_empty()
            || !pipeline.expressions.is_empty())
    {
        return Err(IrValidationError::new(
            "$.schema",
            "Pipeline IR v1.0 cannot contain parameter or expression fields",
        ));
    }
    validate_identifier("$.name", &pipeline.name)?;
    validate_string_length("$.name", &pipeline.name)?;
    validate_parameters_and_expressions(pipeline)?;
    if pipeline.stages.is_empty() || pipeline.stages.len() > MAX_STAGES {
        return Err(IrValidationError::new(
            "$.stages",
            format!("stage count must be between 1 and {MAX_STAGES}"),
        ));
    }

    let mut stage_ids = HashSet::new();
    let mut total_steps = 0_usize;
    for (stage_index, stage) in pipeline.stages.iter().enumerate() {
        let path = format!("$.stages[{stage_index}]");
        validate_identifier(&format!("{path}.id"), &stage.id)?;
        validate_string_length(&format!("{path}.id"), &stage.id)?;
        if !stage_ids.insert(&stage.id) {
            return Err(IrValidationError::new(
                format!("{path}.id"),
                "stage IDs must be unique",
            ));
        }
        if stage.name.trim().is_empty() {
            return Err(IrValidationError::new(
                format!("{path}.name"),
                "stage name must not be empty",
            ));
        }
        validate_string_length(&format!("{path}.name"), &stage.name)?;
        if stage.steps.is_empty() {
            return Err(IrValidationError::new(
                format!("{path}.steps"),
                "stage must contain at least one step",
            ));
        }
        total_steps = total_steps.saturating_add(stage.steps.len());
        if total_steps > MAX_STEPS {
            return Err(IrValidationError::new(
                "$.stages",
                format!("total step count exceeds {MAX_STEPS}"),
            ));
        }
        for (step_index, step) in stage.steps.iter().enumerate() {
            let Step::Process(process) = step;
            if process.program.trim().is_empty() {
                return Err(IrValidationError::new(
                    format!("{path}.steps[{step_index}].process.program"),
                    "program must not be empty",
                ));
            }
            validate_string_length(
                &format!("{path}.steps[{step_index}].process.program"),
                &process.program,
            )?;
            if process.args.len() > MAX_STEPS || process.env.len() > MAX_STEPS {
                return Err(IrValidationError::new(
                    format!("{path}.steps[{step_index}].process"),
                    format!("argument and environment counts must not exceed {MAX_STEPS}"),
                ));
            }
            for (argument_index, argument) in process.args.iter().enumerate() {
                validate_string_length(
                    &format!("{path}.steps[{step_index}].process.args[{argument_index}]"),
                    argument,
                )?;
            }
            if process.env.keys().any(|key| key.is_empty()) {
                return Err(IrValidationError::new(
                    format!("{path}.steps[{step_index}].process.env"),
                    "environment keys must not be empty",
                ));
            }
            for (key, value) in &process.env {
                if key.len() > MAX_IR_STRING_BYTES {
                    return Err(IrValidationError::new(
                        format!("{path}.steps[{step_index}].process.env"),
                        format!("environment key {key:?} exceeds {MAX_IR_STRING_BYTES} bytes"),
                    ));
                }
                validate_string_length(&format!("{path}.steps[{step_index}].process.env"), value)?;
            }
        }
    }
    Ok(())
}

fn validate_parameters_and_expressions(pipeline: &PipelineIr) -> Result<(), IrValidationError> {
    if pipeline.parameters.len() > MAX_PARAMETERS {
        return Err(IrValidationError::new(
            "$.parameters",
            format!("parameter count exceeds {MAX_PARAMETERS}"),
        ));
    }
    for (name, definition) in &pipeline.parameters {
        let path = format!("$.parameters.{name}");
        validate_identifier(&path, name)?;
        if definition.secret && definition.default.is_some() {
            return Err(IrValidationError::new(
                format!("{path}.default"),
                "secret parameters must not declare persisted defaults",
            ));
        }
        if definition
            .default
            .as_ref()
            .is_some_and(|value| !definition.parameter_type.accepts(value))
        {
            return Err(IrValidationError::new(
                format!("{path}.default"),
                format!("expected a {} default", definition.parameter_type.name()),
            ));
        }
        if let Some(value) = &definition.default {
            validate_parameter_value_length(&format!("{path}.default"), value)?;
        }
        if definition.secret {
            if pipeline.parameter_values.contains_key(name) {
                return Err(IrValidationError::new(
                    format!("$.parameter_values.{name}"),
                    "secret parameter values must not be persisted in Pipeline IR",
                ));
            }
        } else {
            let value = pipeline.parameter_values.get(name).ok_or_else(|| {
                IrValidationError::new(
                    format!("$.parameter_values.{name}"),
                    "public parameter value is missing",
                )
            })?;
            if !definition.parameter_type.accepts(value) {
                return Err(IrValidationError::new(
                    format!("$.parameter_values.{name}"),
                    format!("expected a {} value", definition.parameter_type.name()),
                ));
            }
            validate_parameter_value_length(&format!("$.parameter_values.{name}"), value)?;
        }
    }
    if let Some(name) = pipeline
        .parameter_values
        .keys()
        .find(|name| !pipeline.parameters.contains_key(*name))
    {
        return Err(IrValidationError::new(
            format!("$.parameter_values.{name}"),
            "value does not have a parameter definition",
        ));
    }
    if pipeline.expressions.len() > MAX_EXPRESSION_BINDINGS {
        return Err(IrValidationError::new(
            "$.expressions",
            format!("expression binding count exceeds {MAX_EXPRESSION_BINDINGS}"),
        ));
    }
    let mut previous_path: Option<&str> = None;
    for (index, binding) in pipeline.expressions.iter().enumerate() {
        let path = format!("$.expressions[{index}]");
        validate_string_length(&format!("{path}.path"), &binding.path)?;
        if binding.path.is_empty() {
            return Err(IrValidationError::new(
                format!("{path}.path"),
                "expression binding path must not be empty",
            ));
        }
        if previous_path.is_some_and(|previous| previous >= binding.path.as_str()) {
            return Err(IrValidationError::new(
                format!("{path}.path"),
                "expression binding paths must be unique and sorted",
            ));
        }
        previous_path = Some(&binding.path);
        validate_expression(&binding.expression, ExpressionLimits::default()).map_err(|error| {
            IrValidationError::new(format!("{path}.expression"), error.to_string())
        })?;
        validate_expression_parameters(&binding.expression, &pipeline.parameters, &path)?;
    }
    Ok(())
}

fn validate_expression_parameters(
    expression: &Expression,
    parameters: &BTreeMap<String, ParameterDefinition>,
    path: &str,
) -> Result<(), IrValidationError> {
    match expression {
        Expression::Parameter(name) => {
            let Some(definition) = parameters.get(name) else {
                return Err(IrValidationError::new(
                    path,
                    format!("expression references undefined parameter {name:?}"),
                ));
            };
            if definition.secret {
                return Err(IrValidationError::new(
                    path,
                    format!(
                        "expression binding cannot materialize secret-tainted parameter {name:?}"
                    ),
                ));
            }
        }
        Expression::Literal(_) => {}
        Expression::Not(value) => validate_expression_parameters(value, parameters, path)?,
        Expression::Equal(left, right)
        | Expression::NotEqual(left, right)
        | Expression::And(left, right)
        | Expression::Or(left, right)
        | Expression::Add(left, right) => {
            validate_expression_parameters(left, parameters, path)?;
            validate_expression_parameters(right, parameters, path)?;
        }
    }
    Ok(())
}

fn validate_parameter_value_length(
    path: &str,
    value: &ParameterValue,
) -> Result<(), IrValidationError> {
    if let ParameterValue::String(value) = value
        && value.len() > ExpressionLimits::default().max_string_bytes
    {
        return Err(IrValidationError::new(
            path,
            format!(
                "parameter string exceeds {} bytes",
                ExpressionLimits::default().max_string_bytes
            ),
        ));
    }
    Ok(())
}

fn validate_string_length(path: &str, value: &str) -> Result<(), IrValidationError> {
    if value.len() > MAX_IR_STRING_BYTES {
        return Err(IrValidationError::new(
            path,
            format!("string exceeds {MAX_IR_STRING_BYTES} bytes"),
        ));
    }
    Ok(())
}

fn validate_identifier(path: &str, value: &str) -> Result<(), IrValidationError> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(IrValidationError::new(
            path,
            "must contain only ASCII letters, digits, dot, underscore, or hyphen",
        ));
    }
    Ok(())
}

struct MappingView {
    entries: Vec<MappingEntry>,
    path: String,
}

impl MappingView {
    fn new(node: SpannedValue, path: &str) -> Result<Self, CompileError> {
        let YamlValue::Mapping(entries) = node.value else {
            return Err(CompileError::schema(path, "expected a mapping").with_span(node.span));
        };
        Ok(Self {
            entries,
            path: path.to_owned(),
        })
    }

    fn required(&mut self, key: &str) -> Result<SpannedValue, CompileError> {
        self.take(key).ok_or_else(|| {
            CompileError::schema(
                format!("{}.{}", self.path, key),
                "required field is missing",
            )
        })
    }

    fn required_string(&mut self, key: &str) -> Result<String, CompileError> {
        let node = self.required(key)?;
        let span = node.span;
        let YamlValue::String(value) = node.value else {
            return Err(CompileError::schema(
                format!("{}.{}", self.path, key),
                "expected a string",
            )
            .with_span(span));
        };
        Ok(value)
    }

    fn required_integer(&mut self, key: &str) -> Result<i64, CompileError> {
        let node = self.required(key)?;
        let span = node.span;
        let YamlValue::Integer(value) = node.value else {
            return Err(CompileError::schema(
                format!("{}.{}", self.path, key),
                "expected an integer",
            )
            .with_span(span));
        };
        Ok(value)
    }

    fn optional_u64(&mut self, key: &str) -> Result<Option<u64>, CompileError> {
        let Some(node) = self.take(key) else {
            return Ok(None);
        };
        let span = node.span;
        let YamlValue::Integer(value) = node.value else {
            return Err(CompileError::schema(
                format!("{}.{}", self.path, key),
                "expected an integer",
            )
            .with_span(span));
        };
        u64::try_from(value).map(Some).map_err(|_| {
            CompileError::schema(
                format!("{}.{}", self.path, key),
                "expected a non-negative integer",
            )
            .with_span(span)
        })
    }

    fn optional_bool(&mut self, key: &str) -> Result<Option<bool>, CompileError> {
        let Some(node) = self.take(key) else {
            return Ok(None);
        };
        let span = node.span;
        let YamlValue::Bool(value) = node.value else {
            return Err(CompileError::schema(
                format!("{}.{}", self.path, key),
                "expected a boolean",
            )
            .with_span(span));
        };
        Ok(Some(value))
    }

    fn optional_resolved_string_sequence(
        &mut self,
        key: &str,
        parameters: &BTreeMap<String, EvaluatedValue>,
        expressions: &mut Vec<ExpressionBinding>,
    ) -> Result<Option<Vec<String>>, CompileError> {
        let Some(node) = self.take(key) else {
            return Ok(None);
        };
        let span = node.span;
        let YamlValue::Sequence(values) = node.value else {
            return Err(CompileError::schema(
                format!("{}.{}", self.path, key),
                "expected a sequence",
            )
            .with_span(span));
        };
        values
            .into_iter()
            .enumerate()
            .map(|(index, value)| {
                compile_resolved_string(
                    value,
                    &format!("{}.{}[{index}]", self.path, key),
                    parameters,
                    expressions,
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some)
    }

    fn optional_resolved_string_mapping(
        &mut self,
        key: &str,
        parameters: &BTreeMap<String, EvaluatedValue>,
        expressions: &mut Vec<ExpressionBinding>,
    ) -> Result<Option<BTreeMap<String, String>>, CompileError> {
        let Some(node) = self.take(key) else {
            return Ok(None);
        };
        let span = node.span;
        let YamlValue::Mapping(entries) = node.value else {
            return Err(CompileError::schema(
                format!("{}.{}", self.path, key),
                "expected a mapping",
            )
            .with_span(span));
        };
        entries
            .into_iter()
            .map(|entry| {
                let value = compile_resolved_string(
                    entry.value,
                    &format!("{}.{}.{}", self.path, key, entry.key),
                    parameters,
                    expressions,
                )?;
                Ok((entry.key, value))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()
            .map(Some)
    }

    fn take(&mut self, key: &str) -> Option<SpannedValue> {
        self.entries
            .iter()
            .position(|entry| entry.key == key)
            .map(|index| self.entries.remove(index).value)
    }

    fn finish(self) -> Result<(), CompileError> {
        if let Some(entry) = self.entries.first() {
            return Err(CompileError::schema(
                format!("{}.{}", self.path, entry.key),
                format!("unknown field {:?}", entry.key),
            )
            .with_span(entry.key_span));
        }
        Ok(())
    }
}

/// A strict-source or schema compilation error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompileError {
    pub category: CompileErrorCategory,
    pub path: Option<String>,
    pub message: String,
    pub span: Option<SourceSpan>,
}

/// Stable compile error classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompileErrorCategory {
    Admission,
    Schema,
    Expression,
    IrValidation,
}

impl CompileError {
    fn schema(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            category: CompileErrorCategory::Schema,
            path: Some(path.into()),
            message: message.into(),
            span: None,
        }
    }

    fn expression(path: impl Into<String>, error: ExpressionError) -> Self {
        Self {
            category: CompileErrorCategory::Expression,
            path: Some(path.into()),
            message: error.to_string(),
            span: None,
        }
    }

    fn with_span(mut self, span: SourceSpan) -> Self {
        self.span = Some(span);
        self
    }

    fn with_span_if_missing(mut self, span: SourceSpan) -> Self {
        if self.span.is_none() {
            self.span = Some(span);
        }
        self
    }
}

impl fmt::Display for CompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(path) = &self.path {
            write!(formatter, "{path}: ")?;
        }
        write!(formatter, "{}", self.message)
    }
}

impl std::error::Error for CompileError {}

impl From<AdmissionError> for CompileError {
    fn from(error: AdmissionError) -> Self {
        Self {
            category: CompileErrorCategory::Admission,
            path: None,
            message: error.to_string(),
            span: Some(error.span),
        }
    }
}

impl From<IrValidationError> for CompileError {
    fn from(error: IrValidationError) -> Self {
        Self {
            category: CompileErrorCategory::IrValidation,
            path: Some(error.path),
            message: error.message,
            span: None,
        }
    }
}
