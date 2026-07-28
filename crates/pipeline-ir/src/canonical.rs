use std::fmt;

use sha2::{Digest, Sha256};

use crate::model::{MAX_IR_STRING_BYTES, MAX_STAGES, MAX_STEPS, PipelineIr, SchemaVersion, Step};

const MAGIC: &[u8] = b"MCLOVING-IR\0";

pub(crate) fn encode_pipeline(pipeline: &PipelineIr) -> Vec<u8> {
    let mut writer = Writer::default();
    writer.bytes.extend_from_slice(MAGIC);
    writer.u16(pipeline.schema.major);
    writer.u16(pipeline.schema.minor);
    writer.string(&pipeline.name);
    writer.u32(pipeline.stages.len());
    for stage in &pipeline.stages {
        writer.string(&stage.id);
        writer.string(&stage.name);
        writer.u32(stage.steps.len());
        for step in &stage.steps {
            match step {
                Step::Process(process) => {
                    writer.u8(1);
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
}

/// Result of independently validating canonical Pipeline IR bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalSummary {
    pub schema: SchemaVersion,
    pub pipeline_name: String,
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
    let pipeline_name = reader.string()?;
    let stages = reader.count(MAX_STAGES, "stage")?;
    let mut steps = 0_usize;
    for _ in 0..stages {
        reader.string()?;
        reader.string()?;
        let stage_steps = reader.count(MAX_STEPS, "step")?;
        steps = steps
            .checked_add(stage_steps)
            .filter(|count| *count <= MAX_STEPS)
            .ok_or_else(|| CanonicalError::new(reader.offset, "total step count exceeds limit"))?;
        for _ in 0..stage_steps {
            if reader.u8()? != 1 {
                return Err(CanonicalError::new(
                    reader.offset.saturating_sub(1),
                    "unknown step opcode",
                ));
            }
            reader.string()?;
            let arguments = reader.count(MAX_STEPS, "argument")?;
            for _ in 0..arguments {
                reader.string()?;
            }
            let environment = reader.count(MAX_STEPS, "environment entry")?;
            let mut previous_key: Option<String> = None;
            for _ in 0..environment {
                let key = reader.string()?;
                if previous_key
                    .as_ref()
                    .is_some_and(|previous| previous >= &key)
                {
                    return Err(CanonicalError::new(
                        reader.offset,
                        "environment keys are not in canonical order",
                    ));
                }
                previous_key = Some(key);
                reader.string()?;
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
        stages,
        steps,
        sha256: Sha256::digest(bytes).into(),
    })
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
}
