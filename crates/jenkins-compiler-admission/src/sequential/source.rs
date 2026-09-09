//! Bounded, non-evaluating recognizer for the protected sequential language.
use std::collections::BTreeSet;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Stage {
    pub name: String,
    pub id: String,
    pub scripts: Vec<String>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Classification {
    Supported(Vec<Stage>),
    Unsupported(&'static str),
    Rejected(&'static str),
    Unclassified,
}
use Classification::{Rejected, Unclassified, Unsupported};
type Result<T> = std::result::Result<T, Classification>;

#[derive(Clone, Debug, Eq, PartialEq)]
enum Token {
    Word(String),
    Literal { text: String, dynamic: bool },
    Punct(char),
    Lf,
}

pub(super) fn classify(bytes: &[u8]) -> Classification {
    if bytes.len() > super::MAX_SOURCE_BYTES {
        return Rejected("E_SOURCE_TOO_LARGE");
    }
    let Ok(source) = std::str::from_utf8(bytes) else {
        return Rejected("E_SOURCE_TEXT");
    };
    if source.starts_with('\u{feff}') || source.contains(['\0', '\r']) {
        return Rejected("E_SOURCE_TEXT");
    }
    let tokens = match lex(source) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match (Parser {
        tokens,
        cursor: 0,
        steps: 0,
        script_bytes: 0,
    })
    .pipeline()
    {
        Ok(stages) => Classification::Supported(stages),
        Err(e) => e,
    }
}

fn lex(source: &str) -> Result<Vec<Token>> {
    // Groovy's Unicode preprocessing runs before comment removal.
    let chars: Vec<char> = source.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' {
            let start = i;
            while chars.get(i) == Some(&'\\') {
                i += 1;
            }
            if (i - start) % 2 == 1 && chars.get(i) == Some(&'u') {
                return Err(Unsupported("E_SOURCE_LEXICAL"));
            }
        } else {
            i += 1;
        }
    }
    let mut tokens = Vec::new();
    i = 0;
    if source.starts_with("#!") {
        while i < chars.len() && chars[i] != '\n' {
            i += 1;
        }
    }
    while i < chars.len() {
        match chars[i] {
            ' ' | '\t' | '\u{c}' => i += 1,
            '\n' => {
                tokens.push(Token::Lf);
                i += 1;
            }
            '/' if chars.get(i + 1) == Some(&'/') => {
                i += 2;
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '/' if chars.get(i + 1) == Some(&'*') => {
                i += 2;
                while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                    i += 1;
                }
                if i + 1 >= chars.len() {
                    return Err(Rejected("E_SOURCE_PARSE"));
                }
                i += 2;
            }
            '\'' | '"' => {
                let quote = chars[i];
                let triple = chars.get(i + 1) == Some(&quote) && chars.get(i + 2) == Some(&quote);
                i += if triple { 3 } else { 1 };
                let mut text = String::new();
                let mut dynamic = false;
                loop {
                    let Some(&ch) = chars.get(i) else {
                        return Err(Rejected("E_SOURCE_PARSE"));
                    };
                    if ch == '\\' {
                        let Some(&escaped) = chars.get(i + 1) else {
                            return Err(Rejected("E_SOURCE_PARSE"));
                        };
                        text.push(match escaped {
                            '\\' | '\'' | '"' | '$' => escaped,
                            'n' => '\n',
                            'r' => '\r',
                            't' => '\t',
                            'b' => '\u{8}',
                            'f' => '\u{c}',
                            _ => return Err(Unsupported("E_SOURCE_LEXICAL")),
                        });
                        i += 2;
                    } else if ch == quote
                        && (!triple
                            || (chars.get(i + 1) == Some(&quote)
                                && chars.get(i + 2) == Some(&quote)))
                    {
                        i += if triple { 3 } else { 1 };
                        break;
                    } else {
                        if ch == '\n' && !triple {
                            return Err(Rejected("E_SOURCE_PARSE"));
                        }
                        if ch == '$' && quote == '"' {
                            dynamic = true;
                        }
                        text.push(ch);
                        i += 1;
                    }
                }
                tokens.push(Token::Literal { text, dynamic });
            }
            ch if ch.is_ascii_alphabetic() || ch == '_' => {
                let start = i;
                while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                tokens.push(Token::Word(chars[start..i].iter().collect()));
            }
            ch if ch.is_ascii_graphic() && ch != '\\' && ch != '$' => {
                tokens.push(Token::Punct(ch));
                i += 1;
            }
            _ => return Err(Unsupported("E_SOURCE_LEXICAL")),
        }
    }
    Ok(tokens)
}

pub(super) fn stage_id(name: &str) -> String {
    let mut result = String::new();
    let mut invalid_run = false;
    for c in name.chars().map(|c| c.to_ascii_lowercase()) {
        if c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-') {
            result.push(c);
            invalid_run = false;
        } else if !invalid_run {
            result.push('-');
            invalid_run = true;
        }
    }
    result.trim_matches('-').to_owned()
}

struct Parser {
    tokens: Vec<Token>,
    cursor: usize,
    steps: usize,
    script_bytes: usize,
}
impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.cursor)
    }
    fn take(&mut self, token: &Token) -> bool {
        if self.peek() == Some(token) {
            self.cursor += 1;
            true
        } else {
            false
        }
    }
    fn punct(&mut self, ch: char) -> bool {
        self.take(&Token::Punct(ch))
    }
    fn word(&mut self, word: &str) -> bool {
        self.take(&Token::Word(word.to_owned()))
    }
    fn lf(&mut self) {
        while self.take(&Token::Lf) {}
    }
    fn separators(&mut self) -> bool {
        let start = self.cursor;
        while self.take(&Token::Lf) || self.punct(';') {}
        self.cursor > start
    }
    fn need_punct(&mut self, ch: char, code: &'static str) -> Result<()> {
        if self.punct(ch) {
            Ok(())
        } else {
            Err(Unsupported(code))
        }
    }
    fn need_word(&mut self, word: &str, code: &'static str) -> Result<()> {
        if self.word(word) {
            Ok(())
        } else {
            Err(Unsupported(code))
        }
    }
    fn open(&mut self, code: &'static str) -> Result<()> {
        self.lf();
        self.need_punct('{', code)?;
        self.separators();
        Ok(())
    }
    fn literal(&mut self, argument: &'static str, dynamic_code: &'static str) -> Result<String> {
        match self.peek().cloned() {
            Some(Token::Literal {
                text,
                dynamic: false,
            }) => {
                self.cursor += 1;
                Ok(text)
            }
            Some(Token::Literal { dynamic: true, .. }) => Err(Unsupported(dynamic_code)),
            _ => Err(Unsupported(argument)),
        }
    }
    fn pipeline(&mut self) -> Result<Vec<Stage>> {
        self.separators();
        self.need_word("pipeline", "E_DECLARATIVE_ROOT")?;
        self.open("E_DECLARATIVE_ROOT")?;
        self.need_word("agent", "E_DIRECTIVE_UNSUPPORTED")?;
        self.need_word("any", "E_AGENT_UNSUPPORTED")?;
        if !self.separators() {
            return Err(Unsupported("E_DIRECTIVE_UNSUPPORTED"));
        }
        self.need_word("stages", "E_DIRECTIVE_UNSUPPORTED")?;
        self.open("E_STAGES_BODY")?;
        // The protected oversized-stage fixture uses adjacent calls. Count the
        // bounded top-level calls before peer-separator diagnostics, without
        // treating quoted payload or nested stage bodies as declarations.
        let mut depth = 0usize;
        let mut stage_calls = 0usize;
        for (index, token) in self.tokens[self.cursor..].iter().enumerate() {
            match token {
                Token::Punct('}') if depth == 0 => break,
                Token::Punct('}') => depth -= 1,
                Token::Punct('{') => depth += 1,
                Token::Word(word)
                    if depth == 0
                        && word == "stage"
                        && self.tokens.get(self.cursor + index + 1) == Some(&Token::Punct('(')) =>
                {
                    stage_calls += 1
                }
                _ => {}
            }
        }
        if stage_calls > 32 {
            return Err(Unsupported("E_STAGES_BODY"));
        }
        let mut stages = Vec::new();
        let mut ids = BTreeSet::new();
        while !self.punct('}') {
            if self.peek().is_none() {
                return Err(Unclassified);
            }
            self.need_word("stage", "E_STAGE_UNSUPPORTED")?;
            self.need_punct('(', "E_STAGE_ARGUMENT")?;
            self.lf();
            let name = self.literal("E_STAGE_ARGUMENT", "E_STAGE_DYNAMIC")?;
            self.lf();
            self.need_punct(')', "E_STAGE_ARGUMENT")?;
            let id = stage_id(&name);
            if name.is_empty() || name.len() > 96 || id.is_empty() || id.len() > 96 {
                return Err(Unsupported("E_STAGE_NAME"));
            }
            if !ids.insert(id.clone()) {
                return Err(Unsupported("E_STAGE_DUPLICATE"));
            }
            self.open("E_STAGE_BODY")?;
            self.need_word("steps", "E_STAGE_BODY")?;
            self.open("E_STAGE_BODY")?;
            let mut scripts = Vec::new();
            while !self.punct('}') {
                if self.peek().is_none() {
                    return Err(Unclassified);
                }
                self.need_word("sh", "E_STEP_UNSUPPORTED")?;
                let parenthesized = self.punct('(');
                if parenthesized {
                    self.lf();
                }
                let script = self.literal("E_STEP_ARGUMENT", "E_STEP_DYNAMIC")?;
                if parenthesized {
                    self.lf();
                    self.need_punct(')', "E_STEP_ARGUMENT")?;
                }
                if script.is_empty() || script.len() > 4096 || script.contains('\0') {
                    return Err(Unsupported("E_STEP_ARGUMENT"));
                }
                if script.starts_with("#!") {
                    return Err(Unsupported("E_SHELL_SHEBANG_UNSUPPORTED"));
                }
                self.steps += 1;
                if self.steps > 64 {
                    return Err(Unsupported("E_STEP_LIMIT"));
                }
                self.script_bytes += script.len();
                if self.script_bytes > 4096 {
                    return Err(Unsupported("E_STEP_ARGUMENT"));
                }
                scripts.push(script);
                if !self.separators() && self.peek() != Some(&Token::Punct('}')) {
                    return Err(Unsupported("E_STEP_UNSUPPORTED"));
                }
            }
            if scripts.is_empty() {
                return Err(Unsupported("E_STAGE_BODY"));
            }
            self.separators();
            self.need_punct('}', "E_STAGE_BODY")?;
            stages.push(Stage { name, id, scripts });
            if stages.len() > 32 {
                return Err(Unsupported("E_STAGES_BODY"));
            }
            if !self.separators() && self.peek() != Some(&Token::Punct('}')) {
                return Err(Unsupported("E_STAGE_UNSUPPORTED"));
            }
        }
        if stages.is_empty() {
            return Err(Unsupported("E_STAGES_BODY"));
        }
        self.separators();
        self.need_punct('}', "E_DIRECTIVE_UNSUPPORTED")?;
        self.separators();
        if self.peek().is_some() {
            return Err(Unsupported("E_DECLARATIVE_ROOT"));
        }
        Ok(stages)
    }
}
