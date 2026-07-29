//! Strict YAML admission and the canonical McLoving Pipeline IR.

mod canonical;
mod expression;
mod model;
mod strict_yaml;

pub use canonical::{CanonicalError, CanonicalSummary, validate_canonical_bytes};
pub use expression::{
    EvaluatedValue, Expression, ExpressionError, ExpressionErrorCode, ExpressionLimits,
    ParameterValue, evaluate_expression, parse_expression,
};
pub use model::{
    CompileError, CompileErrorCategory, CompilerIdentity, ExpressionBinding, IrValidationError,
    ParameterDefinition, ParameterType, PipelineIr, ProcessStep, Provenance, SchemaCompatibility,
    SchemaVersion, Stage, Step, compile_strict_yaml, compile_strict_yaml_with_parameters,
    validate_pipeline,
};
pub use strict_yaml::{
    AdmissionError, ErrorCode, MappingEntry, ParseLimits, SourceLocation, SourceSpan, SpannedValue,
    YamlValue, parse_strict,
};

/// The first stable Pipeline IR generation.
pub const IR_V1: SchemaVersion = SchemaVersion { major: 1, minor: 0 };

/// Typed parameters and bounded expressions.
pub const IR_V1_1: SchemaVersion = SchemaVersion { major: 1, minor: 1 };
