//! Strict YAML admission and the canonical McLoving Pipeline IR.

mod canonical;
mod components;
mod expression;
mod model;
mod strict_yaml;

pub use canonical::{CanonicalError, CanonicalSummary, validate_canonical_bytes};
pub use components::{
    COMPONENT_V1, ComponentCatalog, ComponentDigest, ComponentError, ComponentErrorCode,
    ComponentInvocation, ComponentReceipt, ComponentVersion, ExpandedPipeline, ExpansionLimits,
    VersionedComponent, expand_component,
};
pub use expression::{
    EvaluatedValue, Expression, ExpressionError, ExpressionErrorCode, ExpressionLimits,
    ParameterValue, evaluate_expression, parse_expression,
};
pub use model::{
    AmbiguityPolicy, CacheIntentStep, CheckoutStep, CompileError, CompileErrorCategory,
    CompilerIdentity, ConnectorEffectClass, ConnectorIntentStep, ExpressionBinding,
    InputIntentStep, IrValidationError, JsonFieldType, ParameterDefinition, ParameterType,
    PipelineIr, ProcessMode, ProcessStep, Provenance, SchemaCompatibility, SchemaVersion, Stage,
    Step, compile_strict_yaml, compile_strict_yaml_with_parameters, instantiate_pipeline,
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

/// Explicit process execution modes.
pub const IR_V1_2: SchemaVersion = SchemaVersion { major: 1, minor: 2 };

/// Typed controller-owned external-effect intents.
pub const IR_V1_3: SchemaVersion = SchemaVersion { major: 1, minor: 3 };

/// Bounded deployment-resolved cache helper intents.
pub const IR_V1_4: SchemaVersion = SchemaVersion { major: 1, minor: 4 };

pub const IR_V1_5: SchemaVersion = SchemaVersion { major: 1, minor: 5 };

/// Container stages: a stage may name a digest-pinned image (PAR-011).
pub const IR_V1_6: SchemaVersion = SchemaVersion { major: 1, minor: 6 };

/// Checkout steps through the sealed source acquirer (PAR-012).
pub const IR_V1_7: SchemaVersion = SchemaVersion { major: 1, minor: 7 };
