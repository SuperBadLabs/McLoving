use std::collections::BTreeMap;
use std::fmt;

/// A typed value admitted by the native parameter and expression contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParameterValue {
    Bool(bool),
    Integer(i64),
    String(String),
}

impl ParameterValue {
    pub(crate) fn type_name(&self) -> &'static str {
        match self {
            Self::Bool(_) => "boolean",
            Self::Integer(_) => "integer",
            Self::String(_) => "string",
        }
    }
}

/// A deliberately small, non-Turing-complete expression tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Expression {
    Literal(ParameterValue),
    Parameter(String),
    Not(Box<Self>),
    Equal(Box<Self>, Box<Self>),
    NotEqual(Box<Self>, Box<Self>),
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
    Add(Box<Self>, Box<Self>),
}

/// Independent resource limits for expression parsing and evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpressionLimits {
    pub max_source_bytes: usize,
    pub max_nodes: usize,
    pub max_depth: usize,
    pub max_string_bytes: usize,
    pub max_operations: usize,
}

impl Default for ExpressionLimits {
    fn default() -> Self {
        Self {
            max_source_bytes: 16 * 1024,
            max_nodes: 128,
            max_depth: 16,
            max_string_bytes: 4 * 1024,
            max_operations: 128,
        }
    }
}

/// Stable expression failure classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpressionErrorCode {
    SourceLimit,
    Syntax,
    UnknownContext,
    NodeLimit,
    DepthLimit,
    StringLimit,
    OperationLimit,
    MissingParameter,
    TypeMismatch,
    IntegerOverflow,
}

/// A stable, byte-addressed expression error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpressionError {
    pub code: ExpressionErrorCode,
    pub offset: usize,
    pub message: String,
}

impl ExpressionError {
    fn new(code: ExpressionErrorCode, offset: usize, message: impl Into<String>) -> Self {
        Self {
            code,
            offset,
            message: message.into(),
        }
    }
}

impl fmt::Display for ExpressionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{:?} at byte {}: {}",
            self.code, self.offset, self.message
        )
    }
}

impl std::error::Error for ExpressionError {}

/// A value paired with its propagated secret taint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluatedValue {
    pub value: ParameterValue,
    pub secret: bool,
}

/// Parse an expression using only literals, `parameters.<name>`, parentheses,
/// unary `!`, equality, boolean operators, and checked string/integer `+`.
pub fn parse_expression(
    source: &str,
    limits: ExpressionLimits,
) -> Result<Expression, ExpressionError> {
    if source.len() > limits.max_source_bytes {
        return Err(ExpressionError::new(
            ExpressionErrorCode::SourceLimit,
            limits.max_source_bytes,
            format!(
                "expression source exceeds {} bytes",
                limits.max_source_bytes
            ),
        ));
    }
    let tokens = Lexer::new(source, limits).tokenize()?;
    Parser::new(tokens, limits).parse()
}

/// Evaluate an expression against the explicit parameter context.
pub fn evaluate_expression(
    expression: &Expression,
    parameters: &BTreeMap<String, EvaluatedValue>,
    limits: ExpressionLimits,
) -> Result<EvaluatedValue, ExpressionError> {
    validate_expression(expression, limits)?;
    let mut evaluator = Evaluator {
        parameters,
        limits,
        operations: 0,
    };
    evaluator.evaluate(expression, 0)
}

pub(crate) fn validate_expression(
    expression: &Expression,
    limits: ExpressionLimits,
) -> Result<(), ExpressionError> {
    fn walk(
        expression: &Expression,
        limits: ExpressionLimits,
        depth: usize,
        nodes: &mut usize,
        operations: &mut usize,
    ) -> Result<(), ExpressionError> {
        if depth > limits.max_depth {
            return Err(ExpressionError::new(
                ExpressionErrorCode::DepthLimit,
                0,
                format!("expression depth exceeds {}", limits.max_depth),
            ));
        }
        *nodes = nodes.saturating_add(1);
        if *nodes > limits.max_nodes {
            return Err(ExpressionError::new(
                ExpressionErrorCode::NodeLimit,
                0,
                format!("expression node count exceeds {}", limits.max_nodes),
            ));
        }
        match expression {
            Expression::Literal(ParameterValue::String(value)) => {
                if value.len() > limits.max_string_bytes {
                    return Err(ExpressionError::new(
                        ExpressionErrorCode::StringLimit,
                        0,
                        format!(
                            "expression string exceeds {} bytes",
                            limits.max_string_bytes
                        ),
                    ));
                }
            }
            Expression::Literal(_) => {}
            Expression::Parameter(name) => validate_parameter_name(name)?,
            Expression::Not(value) => {
                *operations = operations.saturating_add(1);
                walk(value, limits, depth + 1, nodes, operations)?;
            }
            Expression::Equal(left, right)
            | Expression::NotEqual(left, right)
            | Expression::And(left, right)
            | Expression::Or(left, right)
            | Expression::Add(left, right) => {
                *operations = operations.saturating_add(1);
                walk(left, limits, depth + 1, nodes, operations)?;
                walk(right, limits, depth + 1, nodes, operations)?;
            }
        }
        if *operations > limits.max_operations {
            return Err(ExpressionError::new(
                ExpressionErrorCode::OperationLimit,
                0,
                format!(
                    "expression operation count exceeds {}",
                    limits.max_operations
                ),
            ));
        }
        Ok(())
    }

    let mut nodes = 0;
    let mut operations = 0;
    walk(expression, limits, 0, &mut nodes, &mut operations)
}

fn validate_parameter_name(name: &str) -> Result<(), ExpressionError> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(ExpressionError::new(
            ExpressionErrorCode::Syntax,
            0,
            "parameter name must contain only ASCII letters, digits, underscore, or hyphen",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum TokenKind {
    Bool(bool),
    Integer(i64),
    String(String),
    Parameter(String),
    Not,
    Equal,
    NotEqual,
    And,
    Or,
    Add,
    LeftParen,
    RightParen,
    End,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Token {
    kind: TokenKind,
    offset: usize,
}

struct Lexer<'a> {
    source: &'a str,
    offset: usize,
    limits: ExpressionLimits,
}

impl<'a> Lexer<'a> {
    fn new(source: &'a str, limits: ExpressionLimits) -> Self {
        Self {
            source,
            offset: 0,
            limits,
        }
    }

    fn tokenize(mut self) -> Result<Vec<Token>, ExpressionError> {
        let mut tokens = Vec::new();
        loop {
            self.skip_whitespace();
            let offset = self.offset;
            let Some(byte) = self.peek() else {
                tokens.push(Token {
                    kind: TokenKind::End,
                    offset,
                });
                return Ok(tokens);
            };
            let kind = match byte {
                b'(' => {
                    self.offset += 1;
                    TokenKind::LeftParen
                }
                b')' => {
                    self.offset += 1;
                    TokenKind::RightParen
                }
                b'+' => {
                    self.offset += 1;
                    TokenKind::Add
                }
                b'!' if self.remaining().starts_with("!=") => {
                    self.offset += 2;
                    TokenKind::NotEqual
                }
                b'!' => {
                    self.offset += 1;
                    TokenKind::Not
                }
                b'=' if self.remaining().starts_with("==") => {
                    self.offset += 2;
                    TokenKind::Equal
                }
                b'&' if self.remaining().starts_with("&&") => {
                    self.offset += 2;
                    TokenKind::And
                }
                b'|' if self.remaining().starts_with("||") => {
                    self.offset += 2;
                    TokenKind::Or
                }
                b'"' => TokenKind::String(self.string()?),
                b'-' | b'0'..=b'9' => TokenKind::Integer(self.integer()?),
                b'a'..=b'z' | b'A'..=b'Z' | b'_' => self.identifier()?,
                _ => {
                    return Err(ExpressionError::new(
                        ExpressionErrorCode::Syntax,
                        offset,
                        "unexpected expression token",
                    ));
                }
            };
            tokens.push(Token { kind, offset });
            if tokens.len() > self.limits.max_nodes.saturating_mul(3).saturating_add(1) {
                return Err(ExpressionError::new(
                    ExpressionErrorCode::NodeLimit,
                    offset,
                    "expression token count exceeds bounded parser capacity",
                ));
            }
        }
    }

    fn remaining(&self) -> &'a str {
        &self.source[self.offset..]
    }

    fn peek(&self) -> Option<u8> {
        self.source.as_bytes().get(self.offset).copied()
    }

    fn skip_whitespace(&mut self) {
        while self.peek().is_some_and(|byte| byte.is_ascii_whitespace()) {
            self.offset += 1;
        }
    }

    fn integer(&mut self) -> Result<i64, ExpressionError> {
        let start = self.offset;
        if self.peek() == Some(b'-') {
            self.offset += 1;
        }
        let digits = self.offset;
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.offset += 1;
        }
        if self.offset == digits {
            return Err(ExpressionError::new(
                ExpressionErrorCode::Syntax,
                start,
                "minus must be followed by an integer",
            ));
        }
        self.source[start..self.offset].parse().map_err(|_| {
            ExpressionError::new(
                ExpressionErrorCode::IntegerOverflow,
                start,
                "integer literal is outside signed 64-bit range",
            )
        })
    }

    fn string(&mut self) -> Result<String, ExpressionError> {
        let start = self.offset;
        self.offset += 1;
        let mut value = String::new();
        loop {
            let Some(character) = self.remaining().chars().next() else {
                return Err(ExpressionError::new(
                    ExpressionErrorCode::Syntax,
                    start,
                    "unterminated string literal",
                ));
            };
            self.offset += character.len_utf8();
            match character {
                '"' => break,
                '\\' => {
                    let Some(escaped) = self.remaining().chars().next() else {
                        return Err(ExpressionError::new(
                            ExpressionErrorCode::Syntax,
                            self.offset,
                            "unterminated string escape",
                        ));
                    };
                    self.offset += escaped.len_utf8();
                    value.push(match escaped {
                        '"' => '"',
                        '\\' => '\\',
                        'n' => '\n',
                        'r' => '\r',
                        't' => '\t',
                        _ => {
                            return Err(ExpressionError::new(
                                ExpressionErrorCode::Syntax,
                                self.offset - escaped.len_utf8(),
                                "unsupported string escape",
                            ));
                        }
                    });
                }
                '\n' | '\r' => {
                    return Err(ExpressionError::new(
                        ExpressionErrorCode::Syntax,
                        self.offset - character.len_utf8(),
                        "literal newline is not allowed in expression strings",
                    ));
                }
                other => value.push(other),
            }
            if value.len() > self.limits.max_string_bytes {
                return Err(ExpressionError::new(
                    ExpressionErrorCode::StringLimit,
                    start,
                    format!(
                        "expression string exceeds {} bytes",
                        self.limits.max_string_bytes
                    ),
                ));
            }
        }
        Ok(value)
    }

    fn identifier(&mut self) -> Result<TokenKind, ExpressionError> {
        let start = self.offset;
        while self
            .peek()
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        {
            self.offset += 1;
        }
        let identifier = &self.source[start..self.offset];
        match identifier {
            "true" => Ok(TokenKind::Bool(true)),
            "false" => Ok(TokenKind::Bool(false)),
            _ => {
                let Some(name) = identifier.strip_prefix("parameters.") else {
                    return Err(ExpressionError::new(
                        ExpressionErrorCode::UnknownContext,
                        start,
                        "only the parameters.<name> context is available",
                    ));
                };
                validate_parameter_name(name).map_err(|mut error| {
                    error.offset = start;
                    error
                })?;
                Ok(TokenKind::Parameter(name.to_owned()))
            }
        }
    }
}

struct Parser {
    tokens: Vec<Token>,
    index: usize,
    limits: ExpressionLimits,
    nodes: usize,
    operations: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>, limits: ExpressionLimits) -> Self {
        Self {
            tokens,
            index: 0,
            limits,
            nodes: 0,
            operations: 0,
        }
    }

    fn parse(mut self) -> Result<Expression, ExpressionError> {
        let expression = self.parse_or(0)?;
        if !matches!(self.current().kind, TokenKind::End) {
            return Err(self.error("unexpected trailing expression token"));
        }
        Ok(expression)
    }

    fn current(&self) -> &Token {
        &self.tokens[self.index]
    }

    fn advance(&mut self) -> Token {
        let token = self.tokens[self.index].clone();
        self.index += 1;
        token
    }

    fn error(&self, message: impl Into<String>) -> ExpressionError {
        ExpressionError::new(ExpressionErrorCode::Syntax, self.current().offset, message)
    }

    fn node(
        &mut self,
        expression: Expression,
        depth: usize,
    ) -> Result<Expression, ExpressionError> {
        if depth > self.limits.max_depth {
            return Err(ExpressionError::new(
                ExpressionErrorCode::DepthLimit,
                self.current().offset,
                format!("expression depth exceeds {}", self.limits.max_depth),
            ));
        }
        self.nodes = self.nodes.saturating_add(1);
        if self.nodes > self.limits.max_nodes {
            return Err(ExpressionError::new(
                ExpressionErrorCode::NodeLimit,
                self.current().offset,
                format!("expression node count exceeds {}", self.limits.max_nodes),
            ));
        }
        Ok(expression)
    }

    fn operation(&mut self) -> Result<(), ExpressionError> {
        self.operations = self.operations.saturating_add(1);
        if self.operations > self.limits.max_operations {
            return Err(ExpressionError::new(
                ExpressionErrorCode::OperationLimit,
                self.current().offset,
                format!(
                    "expression operation count exceeds {}",
                    self.limits.max_operations
                ),
            ));
        }
        Ok(())
    }

    fn ensure_depth(&self, depth: usize) -> Result<(), ExpressionError> {
        if depth > self.limits.max_depth {
            return Err(ExpressionError::new(
                ExpressionErrorCode::DepthLimit,
                self.current().offset,
                format!("expression depth exceeds {}", self.limits.max_depth),
            ));
        }
        Ok(())
    }

    fn parse_or(&mut self, depth: usize) -> Result<Expression, ExpressionError> {
        let mut expression = self.parse_and(depth + 1)?;
        while matches!(self.current().kind, TokenKind::Or) {
            self.advance();
            self.operation()?;
            let right = self.parse_and(depth + 1)?;
            expression = self.node(Expression::Or(Box::new(expression), Box::new(right)), depth)?;
        }
        Ok(expression)
    }

    fn parse_and(&mut self, depth: usize) -> Result<Expression, ExpressionError> {
        let mut expression = self.parse_equality(depth + 1)?;
        while matches!(self.current().kind, TokenKind::And) {
            self.advance();
            self.operation()?;
            let right = self.parse_equality(depth + 1)?;
            expression = self.node(
                Expression::And(Box::new(expression), Box::new(right)),
                depth,
            )?;
        }
        Ok(expression)
    }

    fn parse_equality(&mut self, depth: usize) -> Result<Expression, ExpressionError> {
        let mut expression = self.parse_add(depth + 1)?;
        loop {
            let constructor = match self.current().kind {
                TokenKind::Equal => Expression::Equal,
                TokenKind::NotEqual => Expression::NotEqual,
                _ => return Ok(expression),
            };
            self.advance();
            self.operation()?;
            let right = self.parse_add(depth + 1)?;
            expression = self.node(constructor(Box::new(expression), Box::new(right)), depth)?;
        }
    }

    fn parse_add(&mut self, depth: usize) -> Result<Expression, ExpressionError> {
        let mut expression = self.parse_unary(depth + 1)?;
        while matches!(self.current().kind, TokenKind::Add) {
            self.advance();
            self.operation()?;
            let right = self.parse_unary(depth + 1)?;
            expression = self.node(
                Expression::Add(Box::new(expression), Box::new(right)),
                depth,
            )?;
        }
        Ok(expression)
    }

    fn parse_unary(&mut self, depth: usize) -> Result<Expression, ExpressionError> {
        self.ensure_depth(depth)?;
        if matches!(self.current().kind, TokenKind::Not) {
            self.advance();
            self.operation()?;
            let value = self.parse_unary(depth + 1)?;
            return self.node(Expression::Not(Box::new(value)), depth);
        }
        self.parse_primary(depth + 1)
    }

    fn parse_primary(&mut self, depth: usize) -> Result<Expression, ExpressionError> {
        self.ensure_depth(depth)?;
        let token = self.advance();
        let expression = match token.kind {
            TokenKind::Bool(value) => Expression::Literal(ParameterValue::Bool(value)),
            TokenKind::Integer(value) => Expression::Literal(ParameterValue::Integer(value)),
            TokenKind::String(value) => Expression::Literal(ParameterValue::String(value)),
            TokenKind::Parameter(name) => Expression::Parameter(name),
            TokenKind::LeftParen => {
                let value = self.parse_or(depth + 1)?;
                if !matches!(self.current().kind, TokenKind::RightParen) {
                    return Err(self.error("expected closing parenthesis"));
                }
                self.advance();
                return Ok(value);
            }
            _ => {
                return Err(ExpressionError::new(
                    ExpressionErrorCode::Syntax,
                    token.offset,
                    "expected expression value",
                ));
            }
        };
        self.node(expression, depth)
    }
}

struct Evaluator<'a> {
    parameters: &'a BTreeMap<String, EvaluatedValue>,
    limits: ExpressionLimits,
    operations: usize,
}

impl Evaluator<'_> {
    fn evaluate(
        &mut self,
        expression: &Expression,
        depth: usize,
    ) -> Result<EvaluatedValue, ExpressionError> {
        if depth > self.limits.max_depth {
            return Err(ExpressionError::new(
                ExpressionErrorCode::DepthLimit,
                0,
                format!("expression depth exceeds {}", self.limits.max_depth),
            ));
        }
        match expression {
            Expression::Literal(value) => Ok(EvaluatedValue {
                value: value.clone(),
                secret: false,
            }),
            Expression::Parameter(name) => self.parameters.get(name).cloned().ok_or_else(|| {
                ExpressionError::new(
                    ExpressionErrorCode::MissingParameter,
                    0,
                    format!("parameter {name:?} is not defined"),
                )
            }),
            Expression::Not(value) => {
                self.operation()?;
                let value = self.evaluate(value, depth + 1)?;
                let ParameterValue::Bool(value_bool) = value.value else {
                    return Err(type_mismatch("!", "boolean", value.value.type_name()));
                };
                Ok(EvaluatedValue {
                    value: ParameterValue::Bool(!value_bool),
                    secret: value.secret,
                })
            }
            Expression::Equal(left, right) | Expression::NotEqual(left, right) => {
                self.operation()?;
                let left = self.evaluate(left, depth + 1)?;
                let right = self.evaluate(right, depth + 1)?;
                if left.value.type_name() != right.value.type_name() {
                    return Err(type_mismatch(
                        "equality",
                        left.value.type_name(),
                        right.value.type_name(),
                    ));
                }
                let equal = left.value == right.value;
                Ok(EvaluatedValue {
                    value: ParameterValue::Bool(if matches!(expression, Expression::Equal(_, _)) {
                        equal
                    } else {
                        !equal
                    }),
                    secret: left.secret || right.secret,
                })
            }
            Expression::And(left, right) | Expression::Or(left, right) => {
                self.operation()?;
                let left = self.evaluate(left, depth + 1)?;
                let right = self.evaluate(right, depth + 1)?;
                let (ParameterValue::Bool(left_bool), ParameterValue::Bool(right_bool)) =
                    (&left.value, &right.value)
                else {
                    return Err(type_mismatch(
                        "boolean operator",
                        "boolean",
                        if !matches!(left.value, ParameterValue::Bool(_)) {
                            left.value.type_name()
                        } else {
                            right.value.type_name()
                        },
                    ));
                };
                let value = if matches!(expression, Expression::And(_, _)) {
                    *left_bool && *right_bool
                } else {
                    *left_bool || *right_bool
                };
                Ok(EvaluatedValue {
                    value: ParameterValue::Bool(value),
                    secret: left.secret || right.secret,
                })
            }
            Expression::Add(left, right) => {
                self.operation()?;
                let left = self.evaluate(left, depth + 1)?;
                let right = self.evaluate(right, depth + 1)?;
                let value = match (left.value, right.value) {
                    (ParameterValue::Integer(left), ParameterValue::Integer(right)) => {
                        ParameterValue::Integer(left.checked_add(right).ok_or_else(|| {
                            ExpressionError::new(
                                ExpressionErrorCode::IntegerOverflow,
                                0,
                                "integer addition overflowed signed 64-bit range",
                            )
                        })?)
                    }
                    (ParameterValue::String(left), ParameterValue::String(right)) => {
                        let length = left.len().checked_add(right.len()).ok_or_else(|| {
                            ExpressionError::new(
                                ExpressionErrorCode::StringLimit,
                                0,
                                "expression string length overflow",
                            )
                        })?;
                        if length > self.limits.max_string_bytes {
                            return Err(ExpressionError::new(
                                ExpressionErrorCode::StringLimit,
                                0,
                                format!(
                                    "expression string exceeds {} bytes",
                                    self.limits.max_string_bytes
                                ),
                            ));
                        }
                        ParameterValue::String(left + &right)
                    }
                    (left, right) => {
                        return Err(type_mismatch("+", left.type_name(), right.type_name()));
                    }
                };
                Ok(EvaluatedValue {
                    value,
                    secret: left.secret || right.secret,
                })
            }
        }
    }

    fn operation(&mut self) -> Result<(), ExpressionError> {
        self.operations = self.operations.saturating_add(1);
        if self.operations > self.limits.max_operations {
            return Err(ExpressionError::new(
                ExpressionErrorCode::OperationLimit,
                0,
                format!(
                    "expression operation count exceeds {}",
                    self.limits.max_operations
                ),
            ));
        }
        Ok(())
    }
}

fn type_mismatch(operator: &str, expected: &str, actual: &str) -> ExpressionError {
    ExpressionError::new(
        ExpressionErrorCode::TypeMismatch,
        0,
        format!("{operator} expected {expected}, found {actual}"),
    )
}
