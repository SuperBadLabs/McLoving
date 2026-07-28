//! Version identity for the future canonical Pipeline IR.

/// Pipeline IR version. Semantics will be introduced by IR tickets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchemaVersion {
    pub major: u16,
    pub minor: u16,
}

/// Foundation placeholder for the first IR generation.
pub const IR_V1: SchemaVersion = SchemaVersion { major: 1, minor: 0 };
