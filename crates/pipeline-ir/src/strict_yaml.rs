use std::collections::HashSet;
use std::fmt;

use saphyr_parser::{Event, Parser, ScalarStyle, Span as ParserSpan};

/// Hard limits applied before a YAML document can enter the compiler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseLimits {
    pub max_source_bytes: usize,
    pub max_nodes: usize,
    pub max_depth: usize,
    pub max_scalar_bytes: usize,
    pub max_mapping_entries: usize,
    pub max_sequence_items: usize,
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self {
            max_source_bytes: 256 * 1024,
            max_nodes: 4_096,
            max_depth: 32,
            max_scalar_bytes: 16 * 1024,
            max_mapping_entries: 256,
            max_sequence_items: 1_024,
        }
    }
}

/// A source coordinate reported by the YAML scanner.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SourceLocation {
    pub offset: usize,
    pub line: usize,
    pub column: usize,
}

/// An exact half-open source range.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SourceSpan {
    pub start: SourceLocation,
    pub end: SourceLocation,
}

impl SourceSpan {
    fn from_parser(span: ParserSpan, character_byte_offsets: &[usize]) -> Self {
        Self {
            start: SourceLocation {
                offset: byte_offset(character_byte_offsets, span.start.index()),
                line: span.start.line(),
                column: span.start.col(),
            },
            end: SourceLocation {
                offset: byte_offset(character_byte_offsets, span.end.index()),
                line: span.end.line(),
                column: span.end.col(),
            },
        }
    }

    fn at(location: SourceLocation) -> Self {
        Self {
            start: location,
            end: location,
        }
    }
}

/// A strict YAML admission error category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCode {
    SourceTooLarge,
    Syntax,
    Directive,
    MultipleDocuments,
    Alias,
    Anchor,
    Tag,
    EmptyScalar,
    ComplexKey,
    DuplicateKey,
    DepthLimit,
    NodeLimit,
    ScalarLimit,
    MappingLimit,
    SequenceLimit,
    UnexpectedEvent,
}

/// A fail-closed YAML error with a stable code and source span.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionError {
    pub code: ErrorCode,
    pub message: String,
    pub span: SourceSpan,
}

impl AdmissionError {
    fn new(code: ErrorCode, message: impl Into<String>, span: SourceSpan) -> Self {
        Self {
            code,
            message: message.into(),
            span,
        }
    }
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{:?} at {}:{}: {}",
            self.code, self.span.start.line, self.span.start.column, self.message
        )
    }
}

impl std::error::Error for AdmissionError {}

/// A parsed value paired with its original source range.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpannedValue {
    pub value: YamlValue,
    pub span: SourceSpan,
}

/// A mapping entry that preserves the key location for precise diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MappingEntry {
    pub key: String,
    pub key_span: SourceSpan,
    pub value: SpannedValue,
}

/// Values accepted by the McLoving strict YAML subset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum YamlValue {
    Null,
    Bool(bool),
    Integer(i64),
    String(String),
    Sequence(Vec<SpannedValue>),
    Mapping(Vec<MappingEntry>),
}

#[derive(Clone, Debug)]
enum OwnedEvent {
    Scalar(String, ScalarStyle),
    SequenceStart,
    SequenceEnd,
    MappingStart,
    MappingEnd,
}

#[derive(Clone, Debug)]
struct SpannedEvent {
    event: OwnedEvent,
    span: SourceSpan,
}

struct Cursor<'a> {
    events: &'a [SpannedEvent],
    index: usize,
    limits: ParseLimits,
    nodes: usize,
}

impl<'a> Cursor<'a> {
    fn parse_node(&mut self, depth: usize) -> Result<SpannedValue, AdmissionError> {
        if depth > self.limits.max_depth {
            return Err(self.error_here(
                ErrorCode::DepthLimit,
                format!("nesting depth exceeds {}", self.limits.max_depth),
            ));
        }
        self.nodes += 1;
        if self.nodes > self.limits.max_nodes {
            return Err(self.error_here(
                ErrorCode::NodeLimit,
                format!("node count exceeds {}", self.limits.max_nodes),
            ));
        }

        let Some(event) = self.events.get(self.index).cloned() else {
            return Err(self.error_here(ErrorCode::UnexpectedEvent, "expected a YAML value"));
        };
        self.index += 1;

        match event.event {
            OwnedEvent::Scalar(value, style) => {
                if value.len() > self.limits.max_scalar_bytes {
                    return Err(AdmissionError::new(
                        ErrorCode::ScalarLimit,
                        format!(
                            "scalar length exceeds {} bytes",
                            self.limits.max_scalar_bytes
                        ),
                        event.span,
                    ));
                }
                let value = resolve_scalar(&value, style, event.span)?;
                Ok(SpannedValue {
                    value,
                    span: event.span,
                })
            }
            OwnedEvent::SequenceStart => {
                let mut values = Vec::new();
                loop {
                    let Some(next) = self.events.get(self.index) else {
                        return Err(AdmissionError::new(
                            ErrorCode::UnexpectedEvent,
                            "unterminated sequence",
                            event.span,
                        ));
                    };
                    if matches!(next.event, OwnedEvent::SequenceEnd) {
                        let end = next.span.end;
                        self.index += 1;
                        return Ok(SpannedValue {
                            value: YamlValue::Sequence(values),
                            span: SourceSpan {
                                start: event.span.start,
                                end,
                            },
                        });
                    }
                    if values.len() >= self.limits.max_sequence_items {
                        return Err(AdmissionError::new(
                            ErrorCode::SequenceLimit,
                            format!("sequence length exceeds {}", self.limits.max_sequence_items),
                            next.span,
                        ));
                    }
                    values.push(self.parse_node(depth + 1)?);
                }
            }
            OwnedEvent::MappingStart => {
                let mut entries = Vec::new();
                let mut keys = HashSet::new();
                loop {
                    let Some(next) = self.events.get(self.index) else {
                        return Err(AdmissionError::new(
                            ErrorCode::UnexpectedEvent,
                            "unterminated mapping",
                            event.span,
                        ));
                    };
                    if matches!(next.event, OwnedEvent::MappingEnd) {
                        let end = next.span.end;
                        self.index += 1;
                        return Ok(SpannedValue {
                            value: YamlValue::Mapping(entries),
                            span: SourceSpan {
                                start: event.span.start,
                                end,
                            },
                        });
                    }
                    if entries.len() >= self.limits.max_mapping_entries {
                        return Err(AdmissionError::new(
                            ErrorCode::MappingLimit,
                            format!("mapping length exceeds {}", self.limits.max_mapping_entries),
                            next.span,
                        ));
                    }

                    let key = self.parse_node(depth + 1)?;
                    let YamlValue::String(key_text) = key.value else {
                        return Err(AdmissionError::new(
                            ErrorCode::ComplexKey,
                            "mapping keys must be non-empty strings",
                            key.span,
                        ));
                    };
                    if !keys.insert(key_text.clone()) {
                        return Err(AdmissionError::new(
                            ErrorCode::DuplicateKey,
                            format!("duplicate mapping key {key_text:?}"),
                            key.span,
                        ));
                    }
                    let value = self.parse_node(depth + 1)?;
                    entries.push(MappingEntry {
                        key: key_text,
                        key_span: key.span,
                        value,
                    });
                }
            }
            OwnedEvent::SequenceEnd | OwnedEvent::MappingEnd => Err(AdmissionError::new(
                ErrorCode::UnexpectedEvent,
                "unexpected collection terminator",
                event.span,
            )),
        }
    }

    fn error_here(&self, code: ErrorCode, message: impl Into<String>) -> AdmissionError {
        let span = self
            .events
            .get(self.index)
            .map_or_else(SourceSpan::default, |event| event.span);
        AdmissionError::new(code, message, span)
    }
}

/// Parse exactly one restricted YAML 1.2 document.
pub fn parse_strict(source: &str, limits: ParseLimits) -> Result<SpannedValue, AdmissionError> {
    if source.len() > limits.max_source_bytes {
        return Err(AdmissionError::new(
            ErrorCode::SourceTooLarge,
            format!("source exceeds {} bytes", limits.max_source_bytes),
            SourceSpan::default(),
        ));
    }

    let character_byte_offsets = source
        .char_indices()
        .map(|(offset, _)| offset)
        .chain(std::iter::once(source.len()))
        .collect::<Vec<_>>();

    for (line_index, line) in source.lines().enumerate() {
        if line.starts_with('%') {
            let offset = source
                .lines()
                .take(line_index)
                .map(|previous| previous.len() + 1)
                .sum();
            let location = SourceLocation {
                offset,
                line: line_index + 1,
                column: 1,
            };
            return Err(AdmissionError::new(
                ErrorCode::Directive,
                "YAML directives are not supported",
                SourceSpan::at(location),
            ));
        }
    }

    let mut events = Vec::new();
    let mut documents = 0_usize;
    for parsed in Parser::new_from_str(source) {
        let (event, parser_span) = parsed.map_err(|error| {
            let marker = error.marker();
            let location = SourceLocation {
                offset: byte_offset(&character_byte_offsets, marker.index()),
                line: marker.line(),
                column: marker.col(),
            };
            let code = if error.info().contains("unknown anchor") {
                ErrorCode::Alias
            } else {
                ErrorCode::Syntax
            };
            AdmissionError::new(code, error.info(), SourceSpan::at(location))
        })?;
        let span = SourceSpan::from_parser(parser_span, &character_byte_offsets);
        match event {
            Event::Nothing | Event::StreamStart | Event::StreamEnd | Event::DocumentEnd => {}
            Event::DocumentStart(_) => {
                documents += 1;
                if documents > 1 {
                    return Err(AdmissionError::new(
                        ErrorCode::MultipleDocuments,
                        "exactly one YAML document is accepted",
                        span,
                    ));
                }
            }
            Event::Alias(_) => {
                return Err(AdmissionError::new(
                    ErrorCode::Alias,
                    "aliases are not supported",
                    span,
                ));
            }
            Event::Scalar(value, style, anchor, tag) => {
                reject_anchor_or_tag(anchor, tag.as_deref(), span)?;
                events.push(SpannedEvent {
                    event: OwnedEvent::Scalar(value.into_owned(), style),
                    span,
                });
            }
            Event::SequenceStart(anchor, tag) => {
                reject_anchor_or_tag(anchor, tag.as_deref(), span)?;
                events.push(SpannedEvent {
                    event: OwnedEvent::SequenceStart,
                    span,
                });
            }
            Event::SequenceEnd => events.push(SpannedEvent {
                event: OwnedEvent::SequenceEnd,
                span,
            }),
            Event::MappingStart(anchor, tag) => {
                reject_anchor_or_tag(anchor, tag.as_deref(), span)?;
                events.push(SpannedEvent {
                    event: OwnedEvent::MappingStart,
                    span,
                });
            }
            Event::MappingEnd => events.push(SpannedEvent {
                event: OwnedEvent::MappingEnd,
                span,
            }),
        }
    }

    if documents != 1 || events.is_empty() {
        return Err(AdmissionError::new(
            ErrorCode::UnexpectedEvent,
            "exactly one non-empty YAML document is required",
            SourceSpan::default(),
        ));
    }

    let mut cursor = Cursor {
        events: &events,
        index: 0,
        limits,
        nodes: 0,
    };
    let root = cursor.parse_node(1)?;
    if cursor.index != events.len() {
        return Err(cursor.error_here(
            ErrorCode::UnexpectedEvent,
            "unexpected content after the root value",
        ));
    }
    Ok(root)
}

fn byte_offset(character_byte_offsets: &[usize], character_index: usize) -> usize {
    character_byte_offsets
        .get(character_index)
        .copied()
        .unwrap_or_else(|| character_byte_offsets.last().copied().unwrap_or_default())
}

fn reject_anchor_or_tag(
    anchor: usize,
    tag: Option<&saphyr_parser::Tag>,
    span: SourceSpan,
) -> Result<(), AdmissionError> {
    if anchor != 0 {
        return Err(AdmissionError::new(
            ErrorCode::Anchor,
            "anchors are not supported",
            span,
        ));
    }
    if let Some(tag) = tag {
        return Err(AdmissionError::new(
            ErrorCode::Tag,
            format!("tag {tag} is not supported"),
            span,
        ));
    }
    Ok(())
}

fn resolve_scalar(
    value: &str,
    style: ScalarStyle,
    span: SourceSpan,
) -> Result<YamlValue, AdmissionError> {
    if style == ScalarStyle::Plain && span.start == span.end {
        return Err(AdmissionError::new(
            ErrorCode::EmptyScalar,
            "implicit empty scalars are not supported",
            span,
        ));
    }
    if style != ScalarStyle::Plain {
        return Ok(YamlValue::String(value.to_owned()));
    }
    if value.is_empty() {
        return Err(AdmissionError::new(
            ErrorCode::EmptyScalar,
            "implicit empty scalars are not supported",
            span,
        ));
    }
    match value {
        "null" => Ok(YamlValue::Null),
        "true" => Ok(YamlValue::Bool(true)),
        "false" => Ok(YamlValue::Bool(false)),
        _ if is_decimal_integer(value) => {
            value.parse::<i64>().map(YamlValue::Integer).map_err(|_| {
                AdmissionError::new(
                    ErrorCode::Syntax,
                    "integer is outside the signed 64-bit range",
                    span,
                )
            })
        }
        _ => Ok(YamlValue::String(value.to_owned())),
    }
}

fn is_decimal_integer(value: &str) -> bool {
    let digits = value.strip_prefix('-').unwrap_or(value);
    if digits.is_empty() {
        return false;
    }
    if digits.len() > 1 && digits.starts_with('0') {
        return false;
    }
    digits.bytes().all(|byte| byte.is_ascii_digit())
}
