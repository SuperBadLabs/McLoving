use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use sha2::{Digest, Sha256};

use crate::expression::{
    EvaluatedValue, Expression, ExpressionLimits, ParameterValue, evaluate_expression,
};
use crate::model::{
    AmbiguityPolicy, ConnectorEffectClass, JsonFieldType, MAX_EXPRESSION_BINDINGS,
    MAX_IR_STRING_BYTES, MAX_PARAMETERS, MAX_STAGES, MAX_STEPS, ParameterType, PipelineIr,
    ProcessMode, SchemaVersion, Step,
};

const MAGIC: &[u8] = b"MCLOVING-IR\0";

pub(crate) fn encode_pipeline(pipeline: &PipelineIr) -> Vec<u8> {
    let mut writer = Writer::default();
    writer.bytes.extend_from_slice(MAGIC);
    writer.u16(pipeline.schema.major);
    writer.u16(pipeline.schema.minor);
    writer.string(&pipeline.name);
    if pipeline.schema.minor >= 1 {
        writer.u32(pipeline.parameters.len());
        for (name, definition) in &pipeline.parameters {
            writer.string(name);
            writer.parameter_type(definition.parameter_type);
            writer.u8(u8::from(definition.secret));
            match &definition.default {
                Some(value) => {
                    writer.u8(1);
                    writer.parameter_value(value);
                }
                None => writer.u8(0),
            }
        }
        writer.u32(pipeline.parameter_values.len());
        for (name, value) in &pipeline.parameter_values {
            writer.string(name);
            writer.parameter_value(value);
        }
        writer.u32(pipeline.expressions.len());
        for binding in &pipeline.expressions {
            writer.string(&binding.path);
            writer.expression(&binding.expression);
        }
    }
    writer.u32(pipeline.stages.len());
    for stage in &pipeline.stages {
        writer.string(&stage.id);
        writer.string(&stage.name);
        writer.u32(stage.steps.len());
        for step in &stage.steps {
            match step {
                Step::Process(process) => {
                    writer.u8(1);
                    if pipeline.schema.minor >= 2 {
                        writer.process_mode(process.mode);
                    }
                    writer.string(&process.program);
                    writer.u32(process.args.len());
                    for argument in &process.args {
                        writer.string(argument);
                    }
                    writer.u32(process.env.len());
                    for (key, value) in &process.env {
                        writer.string(key);
                        writer.string(value);
                    }
                    match process.timeout_seconds {
                        Some(timeout) => {
                            writer.u8(1);
                            writer.u64(timeout);
                        }
                        None => writer.u8(0),
                    }
                }
                Step::ConnectorIntent(intent) => {
                    writer.u8(2);
                    writer.string(&intent.mapping_id);
                    writer.string(&intent.mapping_digest);
                    writer.connector_effect_class(intent.effect_class);
                    writer.string(&intent.effect_key_template);
                    writer.json_field_schema(&intent.public_input_schema);
                    writer.json_field_schema(&intent.protected_secret_ref_schema);
                    writer.json_field_schema(&intent.expected_public_result_schema);
                    writer.u64(intent.timeout_seconds);
                    writer.ambiguity_policy(intent.ambiguity_policy);
                    writer.string(&intent.downstream_control_digest);
                }
            }
        }
    }
    writer.bytes
}

#[derive(Default)]
struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: usize) {
        debug_assert!(u32::try_from(value).is_ok());
        let value = value as u32;
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn string(&mut self, value: &str) {
        self.u32(value.len());
        self.bytes.extend_from_slice(value.as_bytes());
    }

    fn parameter_type(&mut self, parameter_type: ParameterType) {
        self.u8(match parameter_type {
            ParameterType::Bool => 1,
            ParameterType::Integer => 2,
            ParameterType::String => 3,
        });
    }

    fn process_mode(&mut self, mode: ProcessMode) {
        self.u8(match mode {
            ProcessMode::Direct => 0,
            ProcessMode::WindowsCmd => 1,
            ProcessMode::PowerShell => 2,
        });
    }

    fn connector_effect_class(&mut self, effect_class: ConnectorEffectClass) {
        self.u8(match effect_class {
            ConnectorEffectClass::Idempotent => 1,
            ConnectorEffectClass::ExternallyIdempotent => 2,
            ConnectorEffectClass::NonIdempotent => 3,
        });
    }

    fn json_field_schema(&mut self, schema: &BTreeMap<String, JsonFieldType>) {
        self.u32(schema.len());
        for (name, field_type) in schema {
            self.string(name);
            self.u8(match field_type {
                JsonFieldType::Array => 1,
                JsonFieldType::Boolean => 2,
                JsonFieldType::Null => 3,
                JsonFieldType::Number => 4,
                JsonFieldType::Object => 5,
                JsonFieldType::String => 6,
            });
        }
    }

    fn ambiguity_policy(&mut self, policy: AmbiguityPolicy) {
        self.u8(match policy {
            AmbiguityPolicy::ObserveThenReconcile => 1,
        });
    }

    fn parameter_value(&mut self, value: &ParameterValue) {
        match value {
            ParameterValue::Bool(value) => {
                self.u8(1);
                self.u8(u8::from(*value));
            }
            ParameterValue::Integer(value) => {
                self.u8(2);
                self.bytes.extend_from_slice(&value.to_be_bytes());
            }
            ParameterValue::String(value) => {
                self.u8(3);
                self.string(value);
            }
        }
    }

    fn expression(&mut self, expression: &Expression) {
        match expression {
            Expression::Literal(value) => {
                self.u8(1);
                self.parameter_value(value);
            }
            Expression::Parameter(name) => {
                self.u8(2);
                self.string(name);
            }
            Expression::Not(value) => {
                self.u8(3);
                self.expression(value);
            }
            Expression::Equal(left, right) => self.binary_expression(4, left, right),
            Expression::NotEqual(left, right) => self.binary_expression(5, left, right),
            Expression::And(left, right) => self.binary_expression(6, left, right),
            Expression::Or(left, right) => self.binary_expression(7, left, right),
            Expression::Add(left, right) => self.binary_expression(8, left, right),
        }
    }

    fn binary_expression(&mut self, opcode: u8, left: &Expression, right: &Expression) {
        self.u8(opcode);
        self.expression(left);
        self.expression(right);
    }
}

/// Result of independently validating canonical Pipeline IR bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalSummary {
    pub schema: SchemaVersion,
    pub pipeline_name: String,
    pub parameters: usize,
    pub expressions: usize,
    pub stages: usize,
    pub steps: usize,
    pub sha256: [u8; 32],
}

/// Canonical-byte validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalError {
    pub offset: usize,
    pub message: String,
}

impl CanonicalError {
    fn new(offset: usize, message: impl Into<String>) -> Self {
        Self {
            offset,
            message: message.into(),
        }
    }
}

impl fmt::Display for CanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "canonical IR byte {}: {}",
            self.offset, self.message
        )
    }
}

impl std::error::Error for CanonicalError {}

/// Validate framing, bounds, opcodes, ordering, UTF-8, and complete consumption.
pub fn validate_canonical_bytes(bytes: &[u8]) -> Result<CanonicalSummary, CanonicalError> {
    let mut reader = Reader { bytes, offset: 0 };
    if reader.take(MAGIC.len())? != MAGIC {
        return Err(CanonicalError::new(0, "invalid magic"));
    }
    let schema = SchemaVersion {
        major: reader.u16()?,
        minor: reader.u16()?,
    };
    if schema.major != 1 || schema.minor > 3 {
        return Err(CanonicalError::new(
            reader.offset.saturating_sub(4),
            "unsupported Pipeline IR schema",
        ));
    }
    let pipeline_name = reader.string()?;
    let mut parameters = 0;
    let mut expressions = 0;
    let mut expression_context = BTreeMap::new();
    let mut expression_bindings = Vec::new();
    if schema.minor >= 1 {
        parameters = reader.count(MAX_PARAMETERS, "parameter")?;
        let mut definitions = BTreeMap::new();
        let mut previous_name: Option<String> = None;
        for _ in 0..parameters {
            let name = reader.canonical_string_after(&mut previous_name, "parameter")?;
            if !is_parameter_identifier(&name) {
                return Err(CanonicalError::new(
                    reader.offset.saturating_sub(name.len()),
                    "invalid parameter identifier",
                ));
            }
            let parameter_type = reader.parameter_type()?;
            let secret = reader.bool_marker("secret")?;
            let default = match reader.u8()? {
                0 => None,
                1 => Some(reader.parameter_value()?),
                _ => {
                    return Err(CanonicalError::new(
                        reader.offset.saturating_sub(1),
                        "invalid parameter default marker",
                    ));
                }
            };
            if secret && default.is_some() {
                return Err(CanonicalError::new(
                    reader.offset,
                    "secret parameter contains a persisted default",
                ));
            }
            if default
                .as_ref()
                .is_some_and(|value| value.parameter_type() != parameter_type)
            {
                return Err(CanonicalError::new(
                    reader.offset,
                    "parameter default type does not match its definition",
                ));
            }
            definitions.insert(name, (parameter_type, secret));
        }
        let value_count = reader.count(MAX_PARAMETERS, "parameter value")?;
        let mut previous_value: Option<String> = None;
        for _ in 0..value_count {
            let name = reader.canonical_string_after(&mut previous_value, "parameter value")?;
            let value = reader.parameter_value()?;
            let Some((parameter_type, secret)) = definitions.get(&name) else {
                return Err(CanonicalError::new(
                    reader.offset,
                    "parameter value has no definition",
                ));
            };
            if *secret {
                return Err(CanonicalError::new(
                    reader.offset,
                    "secret parameter value is persisted in canonical IR",
                ));
            }
            if value.parameter_type() != *parameter_type {
                return Err(CanonicalError::new(
                    reader.offset,
                    "parameter value type does not match its definition",
                ));
            }
            expression_context.insert(
                name,
                EvaluatedValue {
                    value,
                    secret: false,
                },
            );
        }
        for (name, (_, secret)) in &definitions {
            if !secret && !expression_context.contains_key(name) {
                return Err(CanonicalError::new(
                    reader.offset,
                    "public parameter definition has no bound value",
                ));
            }
        }
        expressions = reader.count(MAX_EXPRESSION_BINDINGS, "expression binding")?;
        let mut previous_path: Option<String> = None;
        for _ in 0..expressions {
            let path = reader.canonical_string_after(&mut previous_path, "expression path")?;
            let mut expression_nodes = 0;
            let mut expression_operations = 0;
            let mut references = BTreeSet::new();
            let expression = reader.expression(
                0,
                &mut expression_nodes,
                &mut expression_operations,
                &mut references,
            )?;
            if references
                .iter()
                .any(|reference| !definitions.contains_key(reference))
            {
                return Err(CanonicalError::new(
                    reader.offset,
                    "expression references an undefined parameter",
                ));
            }
            if references.iter().any(|reference| {
                definitions
                    .get(reference)
                    .is_some_and(|(_, secret)| *secret)
            }) {
                return Err(CanonicalError::new(
                    reader.offset,
                    "expression materializes a secret-tainted parameter",
                ));
            }
            expression_bindings.push((path, expression));
        }
    }
    let stages = reader.count(MAX_STAGES, "stage")?;
    let mut steps = 0_usize;
    let mut materialized_fields = BTreeMap::new();
    for stage_index in 0..stages {
        reader.string()?;
        reader.string()?;
        let stage_steps = reader.count(MAX_STEPS, "step")?;
        steps = steps
            .checked_add(stage_steps)
            .filter(|count| *count <= MAX_STEPS)
            .ok_or_else(|| CanonicalError::new(reader.offset, "total step count exceeds limit"))?;
        for step_index in 0..stage_steps {
            match reader.u8()? {
                1 => {
                    let base = format!("$.stages[{stage_index}].steps[{step_index}].process");
                    if schema.minor >= 2 {
                        match reader.u8()? {
                            0..=2 => {}
                            _ => {
                                return Err(CanonicalError::new(
                                    reader.offset.saturating_sub(1),
                                    "invalid process mode",
                                ));
                            }
                        }
                    }
                    materialized_fields.insert(format!("{base}.program"), reader.string()?);
                    let arguments = reader.count(MAX_STEPS, "argument")?;
                    for argument_index in 0..arguments {
                        materialized_fields
                            .insert(format!("{base}.args[{argument_index}]"), reader.string()?);
                    }
                    let environment = reader.count(MAX_STEPS, "environment entry")?;
                    let mut previous_key: Option<String> = None;
                    for _ in 0..environment {
                        let key =
                            reader.canonical_string_after(&mut previous_key, "environment")?;
                        let value = reader.string()?;
                        materialized_fields.insert(format!("{base}.env.{key}"), value);
                    }
                    match reader.u8()? {
                        0 => {}
                        1 => {
                            reader.u64()?;
                        }
                        _ => {
                            return Err(CanonicalError::new(
                                reader.offset.saturating_sub(1),
                                "invalid timeout presence marker",
                            ));
                        }
                    }
                }
                2 if schema.minor >= 3 => {
                    if stage_steps != 1 {
                        return Err(CanonicalError::new(
                            reader.offset.saturating_sub(1),
                            "connector intent stage must contain exactly one step",
                        ));
                    }
                    let mapping_id = reader.string()?;
                    if !is_mapping_identifier(&mapping_id) {
                        return Err(CanonicalError::new(
                            reader.offset.saturating_sub(mapping_id.len()),
                            "invalid connector mapping identifier",
                        ));
                    }
                    validate_sha256_reference(&reader.string()?, reader.offset)?;
                    if !matches!(reader.u8()?, 1..=3) {
                        return Err(CanonicalError::new(
                            reader.offset.saturating_sub(1),
                            "invalid connector effect class",
                        ));
                    }
                    if reader.string()?.trim().is_empty() {
                        return Err(CanonicalError::new(
                            reader.offset,
                            "empty connector effect key template",
                        ));
                    }
                    for description in [
                        "public input",
                        "protected secret reference",
                        "public result",
                    ] {
                        let fields = reader.count(MAX_PARAMETERS, description)?;
                        let mut previous = None;
                        for _ in 0..fields {
                            let name = reader.canonical_string_after(&mut previous, description)?;
                            if !is_mapping_identifier(&name) {
                                return Err(CanonicalError::new(
                                    reader.offset,
                                    format!("invalid {description} field name"),
                                ));
                            }
                            if !matches!(reader.u8()?, 1..=6) {
                                return Err(CanonicalError::new(
                                    reader.offset.saturating_sub(1),
                                    format!("invalid {description} field type"),
                                ));
                            }
                        }
                    }
                    let timeout = reader.u64()?;
                    if timeout == 0 || timeout > 86_400 {
                        return Err(CanonicalError::new(
                            reader.offset.saturating_sub(8),
                            "invalid connector timeout",
                        ));
                    }
                    if reader.u8()? != 1 {
                        return Err(CanonicalError::new(
                            reader.offset.saturating_sub(1),
                            "invalid ambiguity policy",
                        ));
                    }
                    validate_sha256_reference(&reader.string()?, reader.offset)?;
                }
                _ => {
                    return Err(CanonicalError::new(
                        reader.offset.saturating_sub(1),
                        "unknown step opcode",
                    ));
                }
            }
        }
    }
    for (path, expression) in expression_bindings {
        let Some(materialized) = materialized_fields.get(&path) else {
            return Err(CanonicalError::new(
                reader.offset,
                "expression path does not identify a materializable process field",
            ));
        };
        let evaluated = evaluate_expression(
            &expression,
            &expression_context,
            ExpressionLimits::default(),
        )
        .map_err(|error| CanonicalError::new(reader.offset, error.to_string()))?;
        let ParameterValue::String(evaluated) = evaluated.value else {
            return Err(CanonicalError::new(
                reader.offset,
                "expression binding must evaluate to a string",
            ));
        };
        if &evaluated != materialized {
            return Err(CanonicalError::new(
                reader.offset,
                "expression result does not match the materialized process field",
            ));
        }
    }
    if reader.offset != bytes.len() {
        return Err(CanonicalError::new(
            reader.offset,
            "trailing bytes after canonical document",
        ));
    }
    Ok(CanonicalSummary {
        schema,
        pipeline_name,
        parameters,
        expressions,
        stages,
        steps,
        sha256: Sha256::digest(bytes).into(),
    })
}

fn is_parameter_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn is_mapping_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn validate_sha256_reference(value: &str, offset: usize) -> Result<(), CanonicalError> {
    let valid = value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    });
    if valid {
        Ok(())
    } else {
        Err(CanonicalError::new(
            offset.saturating_sub(value.len()),
            "invalid sha256 reference",
        ))
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], CanonicalError> {
        let end = self
            .offset
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| CanonicalError::new(self.offset, "truncated input"))?;
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, CanonicalError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, CanonicalError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32, CanonicalError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64(&mut self) -> Result<u64, CanonicalError> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn i64(&mut self) -> Result<i64, CanonicalError> {
        let bytes = self.take(8)?;
        Ok(i64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn count(&mut self, maximum: usize, description: &str) -> Result<usize, CanonicalError> {
        let count = self.u32()? as usize;
        if count > maximum {
            return Err(CanonicalError::new(
                self.offset.saturating_sub(4),
                format!("{description} count exceeds limit"),
            ));
        }
        Ok(count)
    }

    fn string(&mut self) -> Result<String, CanonicalError> {
        let length = self.count(MAX_IR_STRING_BYTES, "string byte")?;
        let offset = self.offset;
        std::str::from_utf8(self.take(length)?)
            .map(str::to_owned)
            .map_err(|_| CanonicalError::new(offset, "string is not UTF-8"))
    }

    fn canonical_string_after(
        &mut self,
        previous: &mut Option<String>,
        description: &str,
    ) -> Result<String, CanonicalError> {
        let value = self.string()?;
        if previous.as_ref().is_some_and(|previous| previous >= &value) {
            return Err(CanonicalError::new(
                self.offset,
                format!("{description} names are not in canonical order"),
            ));
        }
        *previous = Some(value.clone());
        Ok(value)
    }

    fn bool_marker(&mut self, description: &str) -> Result<bool, CanonicalError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(CanonicalError::new(
                self.offset.saturating_sub(1),
                format!("invalid {description} boolean marker"),
            )),
        }
    }

    fn parameter_type(&mut self) -> Result<ParameterType, CanonicalError> {
        match self.u8()? {
            1 => Ok(ParameterType::Bool),
            2 => Ok(ParameterType::Integer),
            3 => Ok(ParameterType::String),
            _ => Err(CanonicalError::new(
                self.offset.saturating_sub(1),
                "unknown parameter type opcode",
            )),
        }
    }

    fn parameter_value(&mut self) -> Result<ParameterValue, CanonicalError> {
        match self.u8()? {
            1 => Ok(ParameterValue::Bool(self.bool_marker("parameter")?)),
            2 => Ok(ParameterValue::Integer(self.i64()?)),
            3 => {
                let value = self.string()?;
                if value.len() > ExpressionLimits::default().max_string_bytes {
                    return Err(CanonicalError::new(
                        self.offset,
                        "parameter string exceeds expression limit",
                    ));
                }
                Ok(ParameterValue::String(value))
            }
            _ => Err(CanonicalError::new(
                self.offset.saturating_sub(1),
                "unknown parameter value opcode",
            )),
        }
    }

    fn expression(
        &mut self,
        depth: usize,
        nodes: &mut usize,
        operations: &mut usize,
        references: &mut BTreeSet<String>,
    ) -> Result<Expression, CanonicalError> {
        let limits = ExpressionLimits::default();
        if depth > limits.max_depth {
            return Err(CanonicalError::new(
                self.offset,
                "expression depth exceeds limit",
            ));
        }
        *nodes = nodes.saturating_add(1);
        if *nodes > limits.max_nodes {
            return Err(CanonicalError::new(
                self.offset,
                "expression node count exceeds limit",
            ));
        }
        let expression = match self.u8()? {
            1 => Expression::Literal(self.parameter_value()?),
            2 => {
                let name = self.string()?;
                references.insert(name.clone());
                Expression::Parameter(name)
            }
            3 => {
                *operations = operations.saturating_add(1);
                Expression::Not(Box::new(self.expression(
                    depth + 1,
                    nodes,
                    operations,
                    references,
                )?))
            }
            opcode @ 4..=8 => {
                *operations = operations.saturating_add(1);
                let left = Box::new(self.expression(depth + 1, nodes, operations, references)?);
                let right = Box::new(self.expression(depth + 1, nodes, operations, references)?);
                match opcode {
                    4 => Expression::Equal(left, right),
                    5 => Expression::NotEqual(left, right),
                    6 => Expression::And(left, right),
                    7 => Expression::Or(left, right),
                    8 => Expression::Add(left, right),
                    _ => unreachable!("matched canonical binary expression opcode"),
                }
            }
            _ => {
                return Err(CanonicalError::new(
                    self.offset.saturating_sub(1),
                    "unknown expression opcode",
                ));
            }
        };
        if *operations > limits.max_operations {
            return Err(CanonicalError::new(
                self.offset,
                "expression operation count exceeds limit",
            ));
        }
        Ok(expression)
    }
}

impl ParameterValue {
    fn parameter_type(&self) -> ParameterType {
        match self {
            Self::Bool(_) => ParameterType::Bool,
            Self::Integer(_) => ParameterType::Integer,
            Self::String(_) => ParameterType::String,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ParseLimits, compile_strict_yaml};

    #[test]
    fn independent_validator_rejects_a_connector_in_a_multi_step_stage() {
        let mut pipeline = compile_strict_yaml(
            "fixture://canonical-connector",
            r#"
version: 1
name: canonical-connector
stages:
  - id: notify
    name: Notify
    steps:
      - connector_intent:
          mapping_id: notification.v1
          mapping_digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          effect_class: externally_idempotent
          effect_key_template: build.notification
          public_input_schema: {message: string}
          protected_secret_ref_schema: {token: string}
          expected_public_result_schema: {delivery_id: string}
          timeout_seconds: 30
          ambiguity_policy: observe_then_reconcile
          downstream_control_digest: sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
"#,
            ParseLimits::default(),
        )
        .expect("compile singleton connector stage");
        let duplicate = pipeline.stages[0].steps[0].clone();
        pipeline.stages[0].steps.push(duplicate);
        let bytes = encode_pipeline(&pipeline);

        let error = validate_canonical_bytes(&bytes)
            .expect_err("canonical multi-step connector stage must fail");
        assert!(error.message.contains("exactly one step"));
    }
}
