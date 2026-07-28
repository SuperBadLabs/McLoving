//! Strict YAML admission and the canonical McLoving Pipeline IR.

mod canonical;
mod model;
mod strict_yaml;

pub use canonical::{CanonicalError, CanonicalSummary, validate_canonical_bytes};
pub use model::{
    CompileError, CompileErrorCategory, CompilerIdentity, IrValidationError, PipelineIr,
    ProcessStep, Provenance, SchemaCompatibility, SchemaVersion, Stage, Step, compile_strict_yaml,
    validate_pipeline,
};
pub use strict_yaml::{
    AdmissionError, ErrorCode, MappingEntry, ParseLimits, SourceLocation, SourceSpan, SpannedValue,
    YamlValue, parse_strict,
};

/// The first stable Pipeline IR generation.
pub const IR_V1: SchemaVersion = SchemaVersion { major: 1, minor: 0 };
