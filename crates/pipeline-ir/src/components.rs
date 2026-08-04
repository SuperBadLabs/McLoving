use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

use sha2::{Digest, Sha256};

use crate::expression::ParameterValue;
use crate::model::{
    CompilerIdentity, MAX_IR_STRING_BYTES, MAX_PARAMETERS, ParameterType, PipelineIr, ProcessMode,
    Provenance, Stage, Step, instantiate_pipeline, validate_pipeline,
};
use crate::strict_yaml::SourceSpan;
use crate::{IR_V1, IR_V1_2};

const COMPONENT_MAGIC: &[u8] = b"MCLOVING-COMPONENT\0";
const EXPANSION_MAGIC: &[u8] = b"MCLOVING-EXPANSION\0";
const MAX_COMPONENT_OUTPUTS: usize = 128;
const MAX_COMPONENT_DEPENDENCIES: usize = 128;
const MAX_EXPANDED_COMPONENTS: usize = 128;
const EXPANDED_NAME_PREFIX: &str = "expanded.";
const EXPANDED_STAGE_ID_PREFIX_MAX_BYTES: usize = "c127.".len();

/// The first reusable-component contract.
pub const COMPONENT_V1: ComponentVersion = ComponentVersion { major: 1, minor: 0 };

/// Version of a reusable component package.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ComponentVersion {
    pub major: u16,
    pub minor: u16,
}

/// Immutable SHA-256 identity of a complete component package.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ComponentDigest([u8; 32]);

impl ComponentDigest {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    pub fn to_reference(self) -> String {
        format!("sha256:{self}")
    }
}

impl fmt::Display for ComponentDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for ComponentDigest {
    type Err = ComponentError;

    fn from_str(reference: &str) -> Result<Self, Self::Err> {
        let Some(hex) = reference.strip_prefix("sha256:") else {
            return Err(ComponentError::new(
                ComponentErrorCode::FloatingReference,
                "$.component",
                "component references must use exact sha256:<64 lowercase hex> form",
            ));
        };
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(ComponentError::new(
                ComponentErrorCode::InvalidReference,
                "$.component",
                "component digest must contain exactly 64 lowercase hexadecimal characters",
            ));
        }
        let mut bytes = [0_u8; 32];
        for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
            let pair = std::str::from_utf8(chunk).expect("validated ASCII");
            bytes[index] = u8::from_str_radix(pair, 16).expect("validated hexadecimal");
        }
        Ok(Self(bytes))
    }
}

/// One exact component invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComponentInvocation {
    pub digest: ComponentDigest,
    pub inputs: BTreeMap<String, ParameterValue>,
}

/// A complete immutable reusable component package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionedComponent {
    pub version: ComponentVersion,
    pub name: String,
    pub pipeline: PipelineIr,
    pub outputs: BTreeMap<String, ParameterType>,
    pub dependencies: Vec<ComponentInvocation>,
    pub provenance: Provenance,
}

impl VersionedComponent {
    pub fn new(
        name: impl Into<String>,
        pipeline: PipelineIr,
        outputs: BTreeMap<String, ParameterType>,
        dependencies: Vec<ComponentInvocation>,
        provenance: Provenance,
    ) -> Result<Self, ComponentError> {
        let component = Self {
            version: COMPONENT_V1,
            name: name.into(),
            pipeline,
            outputs,
            dependencies,
            provenance,
        };
        component.validate()?;
        Ok(component)
    }

    pub fn validate(&self) -> Result<(), ComponentError> {
        if self.version != COMPONENT_V1 {
            return Err(ComponentError::new(
                ComponentErrorCode::UnsupportedVersion,
                "$.version",
                "only reusable component v1.0 is accepted",
            ));
        }
        validate_identifier("$.name", &self.name)?;
        if self.name.len() > MAX_IR_STRING_BYTES - EXPANDED_NAME_PREFIX.len() {
            return Err(ComponentError::new(
                ComponentErrorCode::InvalidDefinition,
                "$.name",
                "component name leaves no room for the generated expansion prefix",
            ));
        }
        validate_pipeline(&self.pipeline).map_err(|error| {
            ComponentError::new(
                ComponentErrorCode::InvalidDefinition,
                format!("$.pipeline{}", error.path.trim_start_matches('$')),
                error.message,
            )
        })?;
        if self
            .pipeline
            .stages
            .iter()
            .any(|stage| stage.id.len() > MAX_IR_STRING_BYTES - EXPANDED_STAGE_ID_PREFIX_MAX_BYTES)
        {
            return Err(ComponentError::new(
                ComponentErrorCode::InvalidDefinition,
                "$.pipeline.stages.id",
                "component stage ID leaves no room for the generated expansion prefix",
            ));
        }
        if self
            .pipeline
            .parameters
            .values()
            .any(|definition| definition.secret)
        {
            return Err(ComponentError::new(
                ComponentErrorCode::SecretInput,
                "$.pipeline.parameters",
                "reusable component inputs cannot be secret; use attempt-scoped credential grants",
            ));
        }
        if self.outputs.len() > MAX_COMPONENT_OUTPUTS {
            return Err(ComponentError::new(
                ComponentErrorCode::OutputLimit,
                "$.outputs",
                format!("component output count exceeds {MAX_COMPONENT_OUTPUTS}"),
            ));
        }
        for name in self.outputs.keys() {
            validate_identifier(&format!("$.outputs.{name}"), name)?;
        }
        if self.dependencies.len() > MAX_COMPONENT_DEPENDENCIES {
            return Err(ComponentError::new(
                ComponentErrorCode::ComponentLimit,
                "$.dependencies",
                format!("component dependency count exceeds {MAX_COMPONENT_DEPENDENCIES}"),
            ));
        }
        Ok(())
    }

    /// Presentation-independent component package bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ComponentError> {
        self.validate()?;
        let pipeline = self.pipeline.canonical_bytes().map_err(|error| {
            ComponentError::new(
                ComponentErrorCode::InvalidDefinition,
                error.path,
                error.message,
            )
        })?;
        let mut writer = ComponentWriter::default();
        writer.raw(COMPONENT_MAGIC);
        writer.u16(self.version.major);
        writer.u16(self.version.minor);
        writer.string(&self.name);
        writer.bytes(&pipeline);
        writer.u32(self.outputs.len());
        for (name, output_type) in &self.outputs {
            writer.string(name);
            writer.parameter_type(*output_type);
        }
        writer.u32(self.dependencies.len());
        for dependency in &self.dependencies {
            writer.raw(&dependency.digest.0);
            writer.parameter_values(&dependency.inputs);
        }
        Ok(writer.finish())
    }

    pub fn semantic_digest(&self) -> Result<ComponentDigest, ComponentError> {
        Ok(ComponentDigest(
            Sha256::digest(self.canonical_bytes()?).into(),
        ))
    }
}

/// In-memory immutable component registry. Fetching and trust policy are
/// intentionally outside this pre-scheduling expansion boundary.
#[derive(Clone, Debug, Default)]
pub struct ComponentCatalog {
    components: BTreeMap<ComponentDigest, VersionedComponent>,
}

impl ComponentCatalog {
    pub fn register(
        &mut self,
        component: VersionedComponent,
    ) -> Result<ComponentDigest, ComponentError> {
        let digest = component.semantic_digest()?;
        self.insert_exact(digest, component)?;
        Ok(digest)
    }

    pub fn insert_exact(
        &mut self,
        expected: ComponentDigest,
        component: VersionedComponent,
    ) -> Result<(), ComponentError> {
        let actual = component.semantic_digest()?;
        if actual != expected {
            return Err(ComponentError::new(
                ComponentErrorCode::DigestMismatch,
                "$.component",
                format!("component package digest is {actual}, not declared digest {expected}"),
            ));
        }
        if let Some(existing) = self.components.get(&expected) {
            if existing.canonical_bytes()? != component.canonical_bytes()? {
                return Err(ComponentError::new(
                    ComponentErrorCode::Substitution,
                    "$.component",
                    "a different component package already occupies this immutable digest",
                ));
            }
            return Ok(());
        }
        self.components.insert(expected, component);
        Ok(())
    }

    pub fn get(&self, digest: ComponentDigest) -> Option<&VersionedComponent> {
        self.components.get(&digest)
    }
}

/// Independent limits enforced before expanded work reaches scheduling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpansionLimits {
    pub max_depth: usize,
    pub max_components: usize,
    pub max_stages: usize,
    pub max_steps: usize,
    pub max_canonical_bytes: usize,
}

impl Default for ExpansionLimits {
    fn default() -> Self {
        Self {
            max_depth: 8,
            max_components: 128,
            max_stages: 128,
            max_steps: 4_096,
            max_canonical_bytes: 256 * 1024,
        }
    }
}

/// Provenance and type contract for one exact invocation in an expansion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComponentReceipt {
    pub path: String,
    pub digest: ComponentDigest,
    pub version: ComponentVersion,
    pub inputs: BTreeMap<String, ParameterValue>,
    pub outputs: BTreeMap<String, ParameterType>,
    pub source_sha256: [u8; 32],
}

/// Concrete scheduling input plus a digest-bound component ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpandedPipeline {
    root: ComponentDigest,
    pipeline: PipelineIr,
    components: Vec<ComponentReceipt>,
}

impl ExpandedPipeline {
    #[must_use]
    pub fn root(&self) -> ComponentDigest {
        self.root
    }

    #[must_use]
    pub fn pipeline(&self) -> &PipelineIr {
        &self.pipeline
    }

    #[must_use]
    pub fn components(&self) -> &[ComponentReceipt] {
        &self.components
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ComponentError> {
        validate_pipeline(&self.pipeline).map_err(|error| {
            ComponentError::new(
                ComponentErrorCode::InvalidDefinition,
                error.path,
                error.message,
            )
        })?;
        self.validate_receipts()?;
        let pipeline = self.pipeline.canonical_bytes().map_err(|error| {
            ComponentError::new(
                ComponentErrorCode::InvalidDefinition,
                error.path,
                error.message,
            )
        })?;
        let mut writer = ComponentWriter::default();
        writer.raw(EXPANSION_MAGIC);
        writer.raw(&self.root.0);
        writer.u32(self.components.len());
        for receipt in &self.components {
            writer.string(&receipt.path);
            writer.raw(&receipt.digest.0);
            writer.u16(receipt.version.major);
            writer.u16(receipt.version.minor);
            writer.parameter_values(&receipt.inputs);
            writer.u32(receipt.outputs.len());
            for (name, output_type) in &receipt.outputs {
                writer.string(name);
                writer.parameter_type(*output_type);
            }
        }
        writer.bytes(&pipeline);
        Ok(writer.finish())
    }

    fn validate_receipts(&self) -> Result<(), ComponentError> {
        if self.components.is_empty() {
            return Err(ComponentError::new(
                ComponentErrorCode::InvalidDefinition,
                "$.components",
                "expanded component ledger must contain its root receipt",
            ));
        }
        if self.components.len() > MAX_EXPANDED_COMPONENTS {
            return Err(ComponentError::new(
                ComponentErrorCode::ComponentLimit,
                "$.components",
                format!("expanded component receipt count exceeds {MAX_EXPANDED_COMPONENTS}"),
            ));
        }

        let root = &self.components[0];
        if root.path != "$" {
            return Err(ComponentError::new(
                ComponentErrorCode::InvalidDefinition,
                "$.components[0].path",
                "the first expanded component receipt must be the root path $",
            ));
        }
        if root.digest != self.root {
            return Err(ComponentError::new(
                ComponentErrorCode::DigestMismatch,
                "$.components[0].digest",
                "the root receipt digest must match the expanded pipeline root digest",
            ));
        }

        let mut seen_paths = BTreeSet::new();
        for (index, receipt) in self.components.iter().enumerate() {
            let path = format!("$.components[{index}]");
            validate_receipt_path(&format!("{path}.path"), &receipt.path)?;
            if !seen_paths.insert(receipt.path.as_str()) {
                return Err(ComponentError::new(
                    ComponentErrorCode::InvalidDefinition,
                    format!("{path}.path"),
                    "expanded component receipt paths must be unique",
                ));
            }
            if index > 0 {
                let parent = receipt_parent(&receipt.path).expect("validated non-root path");
                if !seen_paths.contains(parent) {
                    return Err(ComponentError::new(
                        ComponentErrorCode::InvalidDefinition,
                        format!("{path}.path"),
                        "a component receipt must follow its parent receipt",
                    ));
                }
            }
            if receipt.version != COMPONENT_V1 {
                return Err(ComponentError::new(
                    ComponentErrorCode::UnsupportedVersion,
                    format!("{path}.version"),
                    "expanded component receipts must use component v1.0",
                ));
            }
            if receipt.inputs.len() > MAX_PARAMETERS {
                return Err(ComponentError::new(
                    ComponentErrorCode::InvalidDefinition,
                    format!("{path}.inputs"),
                    format!("component input count exceeds {MAX_PARAMETERS}"),
                ));
            }
            for (name, value) in &receipt.inputs {
                validate_identifier(&format!("{path}.inputs.{name}"), name)?;
                if name.contains('.') {
                    return Err(ComponentError::new(
                        ComponentErrorCode::InvalidDefinition,
                        format!("{path}.inputs.{name}"),
                        "component input names must not contain dot",
                    ));
                }
                if let ParameterValue::String(value) = value
                    && value.len() > MAX_IR_STRING_BYTES
                {
                    return Err(ComponentError::new(
                        ComponentErrorCode::InvalidDefinition,
                        format!("{path}.inputs.{name}"),
                        format!("component input string exceeds {MAX_IR_STRING_BYTES} bytes"),
                    ));
                }
            }
            if receipt.outputs.len() > MAX_COMPONENT_OUTPUTS {
                return Err(ComponentError::new(
                    ComponentErrorCode::OutputLimit,
                    format!("{path}.outputs"),
                    format!("component output count exceeds {MAX_COMPONENT_OUTPUTS}"),
                ));
            }
            for name in receipt.outputs.keys() {
                validate_identifier(&format!("{path}.outputs.{name}"), name)?;
            }
        }
        Ok(())
    }

    pub fn semantic_digest(&self) -> Result<[u8; 32], ComponentError> {
        Ok(Sha256::digest(self.canonical_bytes()?).into())
    }
}

fn validate_receipt_path(path: &str, value: &str) -> Result<(), ComponentError> {
    if value.len() > MAX_IR_STRING_BYTES {
        return Err(ComponentError::new(
            ComponentErrorCode::InvalidDefinition,
            path,
            format!("component receipt path exceeds {MAX_IR_STRING_BYTES} bytes"),
        ));
    }
    if value == "$" {
        return Ok(());
    }
    if receipt_parent(value).is_none() {
        return Err(ComponentError::new(
            ComponentErrorCode::InvalidDefinition,
            path,
            "component receipt path must use canonical $.dependencies[N] segments",
        ));
    }
    Ok(())
}

fn receipt_parent(path: &str) -> Option<&str> {
    let without_close = path.strip_suffix(']')?;
    let (parent, index) = without_close.rsplit_once(".dependencies[")?;
    if parent.is_empty()
        || index.is_empty()
        || !index.bytes().all(|byte| byte.is_ascii_digit())
        || (index.len() > 1 && index.starts_with('0'))
    {
        return None;
    }
    if parent != "$" && receipt_parent(parent).is_none() {
        return None;
    }
    Some(parent)
}

/// Resolve and fully expand an exact component graph before scheduling.
pub fn expand_component(
    root: ComponentInvocation,
    catalog: &ComponentCatalog,
    limits: ExpansionLimits,
) -> Result<ExpandedPipeline, ComponentError> {
    validate_limits(limits)?;
    let mut state = ExpansionState {
        catalog,
        limits,
        active: BTreeSet::new(),
        receipts: Vec::new(),
        stages: Vec::new(),
        step_count: 0,
    };
    state.expand(&root, "$", 1)?;
    let root_component = catalog.get(root.digest).ok_or_else(|| {
        ComponentError::new(
            ComponentErrorCode::MissingComponent,
            "$.component",
            format!(
                "component {} is not present in the immutable catalog",
                root.digest
            ),
        )
    })?;
    let schema = if state.stages.iter().any(|stage| {
        stage.steps.iter().any(|step| {
            let Step::Process(process) = step;
            process.mode != ProcessMode::Direct
        })
    }) {
        IR_V1_2
    } else {
        IR_V1
    };
    let pipeline = PipelineIr {
        schema,
        name: format!("{EXPANDED_NAME_PREFIX}{}", root_component.name),
        parameters: BTreeMap::new(),
        parameter_values: BTreeMap::new(),
        expressions: Vec::new(),
        stages: state.stages,
        provenance: Provenance {
            source_id: root_component.provenance.source_id.clone(),
            source_sha256: root_component.provenance.source_sha256,
            compiler: CompilerIdentity {
                name: "mcloving-component-expander".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
            },
        },
        source_span: SourceSpan {
            start: root_component.pipeline.source_span.start,
            end: root_component.pipeline.source_span.end,
        },
    };
    validate_pipeline(&pipeline).map_err(|error| {
        ComponentError::new(
            ComponentErrorCode::InvalidDefinition,
            error.path,
            error.message,
        )
    })?;
    let expanded = ExpandedPipeline {
        root: root.digest,
        pipeline,
        components: state.receipts,
    };
    let bytes = expanded.canonical_bytes()?;
    if bytes.len() > limits.max_canonical_bytes {
        return Err(ComponentError::new(
            ComponentErrorCode::ByteLimit,
            "$",
            format!(
                "expanded canonical bytes {} exceed limit {}",
                bytes.len(),
                limits.max_canonical_bytes
            ),
        ));
    }
    Ok(expanded)
}

struct ExpansionState<'a> {
    catalog: &'a ComponentCatalog,
    limits: ExpansionLimits,
    active: BTreeSet<ComponentDigest>,
    receipts: Vec<ComponentReceipt>,
    stages: Vec<Stage>,
    step_count: usize,
}

impl ExpansionState<'_> {
    fn expand(
        &mut self,
        invocation: &ComponentInvocation,
        path: &str,
        depth: usize,
    ) -> Result<(), ComponentError> {
        if depth > self.limits.max_depth {
            return Err(ComponentError::new(
                ComponentErrorCode::DepthLimit,
                path,
                format!(
                    "component expansion depth exceeds {}",
                    self.limits.max_depth
                ),
            ));
        }
        if self.receipts.len() >= self.limits.max_components {
            return Err(ComponentError::new(
                ComponentErrorCode::ComponentLimit,
                path,
                format!(
                    "component invocation count exceeds {}",
                    self.limits.max_components
                ),
            ));
        }
        let component = self.catalog.get(invocation.digest).ok_or_else(|| {
            ComponentError::new(
                ComponentErrorCode::MissingComponent,
                path,
                format!(
                    "component {} is not present in the immutable catalog",
                    invocation.digest
                ),
            )
        })?;
        if !self.active.insert(invocation.digest) {
            return Err(ComponentError::new(
                ComponentErrorCode::Cycle,
                path,
                format!("component cycle re-enters {}", invocation.digest),
            ));
        }

        let instance = instantiate_pipeline(&component.pipeline, invocation.inputs.clone())
            .map_err(|error| {
                ComponentError::new(
                    ComponentErrorCode::InputType,
                    format!("{path}.inputs"),
                    error.to_string(),
                )
            })?;
        let receipt_index = self.receipts.len();
        self.receipts.push(ComponentReceipt {
            path: path.to_owned(),
            digest: invocation.digest,
            version: component.version,
            inputs: instance.parameter_values.clone(),
            outputs: component.outputs.clone(),
            source_sha256: component.provenance.source_sha256,
        });

        for (index, dependency) in component.dependencies.iter().enumerate() {
            self.expand(
                dependency,
                &format!("{path}.dependencies[{index}]"),
                depth + 1,
            )?;
        }

        let actual = component.semantic_digest()?;
        if actual != invocation.digest {
            self.active.remove(&invocation.digest);
            return Err(ComponentError::new(
                ComponentErrorCode::DigestMismatch,
                path,
                format!(
                    "catalog package digest changed from {} to {actual}",
                    invocation.digest
                ),
            ));
        }

        for mut stage in instance.stages {
            if self.stages.len() >= self.limits.max_stages {
                self.active.remove(&invocation.digest);
                return Err(ComponentError::new(
                    ComponentErrorCode::StageLimit,
                    path,
                    format!("expanded stage count exceeds {}", self.limits.max_stages),
                ));
            }
            self.step_count = self.step_count.saturating_add(stage.steps.len());
            if self.step_count > self.limits.max_steps {
                self.active.remove(&invocation.digest);
                return Err(ComponentError::new(
                    ComponentErrorCode::StepLimit,
                    path,
                    format!("expanded step count exceeds {}", self.limits.max_steps),
                ));
            }
            stage.id = format!("c{receipt_index}.{}", stage.id);
            self.stages.push(stage);
        }
        self.active.remove(&invocation.digest);
        Ok(())
    }
}

fn validate_limits(limits: ExpansionLimits) -> Result<(), ComponentError> {
    if limits.max_depth == 0
        || limits.max_components == 0
        || limits.max_stages == 0
        || limits.max_steps == 0
        || limits.max_canonical_bytes == 0
    {
        return Err(ComponentError::new(
            ComponentErrorCode::InvalidLimits,
            "$.limits",
            "all expansion limits must be positive",
        ));
    }
    Ok(())
}

fn validate_identifier(path: &str, value: &str) -> Result<(), ComponentError> {
    if value.is_empty()
        || value.len() > 16 * 1024
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ComponentError::new(
            ComponentErrorCode::InvalidDefinition,
            path,
            "must contain only bounded ASCII letters, digits, dot, underscore, or hyphen",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentErrorCode {
    FloatingReference,
    InvalidReference,
    UnsupportedVersion,
    InvalidDefinition,
    DigestMismatch,
    Substitution,
    MissingComponent,
    InputType,
    SecretInput,
    Cycle,
    InvalidLimits,
    DepthLimit,
    ComponentLimit,
    OutputLimit,
    StageLimit,
    StepLimit,
    ByteLimit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComponentError {
    pub code: ComponentErrorCode,
    pub path: String,
    pub message: String,
}

impl ComponentError {
    fn new(code: ComponentErrorCode, path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code,
            path: path.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for ComponentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.path, self.message)
    }
}

impl std::error::Error for ComponentError {}

#[derive(Default)]
struct ComponentWriter {
    bytes: Vec<u8>,
}

impl ComponentWriter {
    fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn raw(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: usize) {
        debug_assert!(u32::try_from(value).is_ok());
        self.bytes.extend_from_slice(&(value as u32).to_be_bytes());
    }

    fn string(&mut self, value: &str) {
        self.u32(value.len());
        self.raw(value.as_bytes());
    }

    fn bytes(&mut self, value: &[u8]) {
        self.u32(value.len());
        self.raw(value);
    }

    fn parameter_type(&mut self, value: ParameterType) {
        self.u8(match value {
            ParameterType::Bool => 1,
            ParameterType::Integer => 2,
            ParameterType::String => 3,
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
                self.raw(&value.to_be_bytes());
            }
            ParameterValue::String(value) => {
                self.u8(3);
                self.string(value);
            }
        }
    }

    fn parameter_values(&mut self, values: &BTreeMap<String, ParameterValue>) {
        self.u32(values.len());
        for (name, value) in values {
            self.string(name);
            self.parameter_value(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ParseLimits, compile_strict_yaml};

    fn component(name: &str) -> VersionedComponent {
        let pipeline = compile_strict_yaml(
            "unit://component",
            &format!(
                "version: 1\nname: {name}\nstages:\n  - id: run\n    name: Run\n    steps:\n      - process:\n          program: \"true\"\n"
            ),
            ParseLimits::default(),
        )
        .unwrap();
        VersionedComponent::new(
            name,
            pipeline,
            BTreeMap::new(),
            Vec::new(),
            Provenance {
                source_id: "unit://component".to_owned(),
                source_sha256: [7; 32],
                compiler: CompilerIdentity {
                    name: "unit".to_owned(),
                    version: "1".to_owned(),
                },
            },
        )
        .unwrap()
    }

    #[test]
    fn active_path_cycle_is_rejected_even_if_a_catalog_is_corrupted() {
        let mut component = component("cycle");
        let digest = component.semantic_digest().unwrap();
        component.dependencies.push(ComponentInvocation {
            digest,
            inputs: BTreeMap::new(),
        });
        let mut catalog = ComponentCatalog::default();
        // Defense-in-depth test: a valid catalog cannot reach this state
        // because insert_exact verifies the complete package digest.
        catalog.components.insert(digest, component);
        let error = expand_component(
            ComponentInvocation {
                digest,
                inputs: BTreeMap::new(),
            },
            &catalog,
            ExpansionLimits::default(),
        )
        .unwrap_err();
        assert_eq!(error.code, ComponentErrorCode::Cycle);
    }

    #[test]
    fn mutated_expansion_receipts_fail_closed_inside_the_constructor_boundary() {
        let item = component("root");
        let digest = item.semantic_digest().unwrap();
        let mut catalog = ComponentCatalog::default();
        catalog.insert_exact(digest, item).unwrap();
        let expanded = expand_component(
            ComponentInvocation {
                digest,
                inputs: BTreeMap::new(),
            },
            &catalog,
            ExpansionLimits::default(),
        )
        .unwrap();

        let mut missing = expanded.clone();
        missing.components.clear();
        assert_eq!(
            missing.canonical_bytes().unwrap_err().code,
            ComponentErrorCode::InvalidDefinition
        );

        let mut wrong_digest = expanded.clone();
        wrong_digest.components[0].digest = ComponentDigest::from_bytes([9; 32]);
        assert_eq!(
            wrong_digest.canonical_bytes().unwrap_err().code,
            ComponentErrorCode::DigestMismatch
        );

        let mut duplicate = expanded;
        duplicate.components.push(duplicate.components[0].clone());
        assert_eq!(
            duplicate.canonical_bytes().unwrap_err().code,
            ComponentErrorCode::InvalidDefinition
        );
    }
}
