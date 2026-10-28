//! Lexer for template text, a port of Go's `text/template/parse/lex.go`.

use super::Pos;
use crate::strconv;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ItemType {
    Error,
    Bool,
    Char,
    CharConstant,
    Comment,
    Complex,
    Assign,
    Declare,
    Eof,
    Field,
    Identifier,
    LeftDelim,
    LeftParen,
    Number,
    Pipe,
    RawString,
    RightDelim,
    RightParen,
    Space,
    String,
    Text,
    Variable,
    // Keywords appear after all the rest.
    Keyword,
    Block,
    Break,
    Continue,
    Dot,
    Define,
    Else,
    End,
    If,
    Nil,
    Range,
    Template,
    With,
}

fn keyword(word: &str) -> Option<ItemType> {
    Some(match word {
        "." => ItemType::Dot,
        "block" => ItemType::Block,
        "break" => ItemType::Break,
        "continue" => ItemType::Continue,
        "define" => ItemType::Define,
        "else" => ItemType::Else,
        "end" => ItemType::End,
        "if" => ItemType::If,
        "range" => ItemType::Range,
        "nil" => ItemType::Nil,
        "template" => ItemType::Template,
        "with" => ItemType::With,
        _ => return None,
    })
}

#[derive(Clone, Debug)]
pub(crate) struct Item {
    pub typ: ItemType,
    pub pos: Pos,
    pub val: String,
    pub line: usize,
}

impl Item {
    fn empty() -> Item {
        Item {
            typ: ItemType::Eof,
            pos: Pos(0),
            val: String::new(),
            line: 0,
        }
    }
}

impl std::fmt::Display for Item {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.typ == ItemType::Eof {
            f.write_str("EOF")
        } else if self.typ == ItemType::Error {
            f.write_str(&self.val)
        } else if self.typ > ItemType::Keyword {
            write!(f, "<{}>", self.val)
        } else if self.val.chars().count() > 10 {
            let head: String = self.val.chars().take(10).collect();
            write!(f, "{}...", strconv::quote(head))
        } else {
            f.write_str(&strconv::quote(&self.val))
        }
    }
}

pub(crate) const DEFAULT_LEFT_DELIM: &str = "{{";
pub(crate) const DEFAULT_RIGHT_DELIM: &str = "}}";
const LEFT_COMMENT: &str = "/*";
const RIGHT_COMMENT: &str = "*/";
const SPACE_CHARS: &[char] = &[' ', '\t', '\r', '\n'];
const TRIM_MARKER: u8 = b'-';
const TRIM_MARKER_LEN: usize = 2;

#[derive(Clone, Copy, Default)]
pub(crate) struct LexOptions {
    pub emit_comment: bool,
    pub break_ok: bool,
    pub continue_ok: bool,
}

#[derive(Clone, Copy)]
enum State {
    Text,
    LeftDelim,
    Comment,
    RightDelim,
    InsideAction,
    Space,
    Identifier,
    Field,
    Variable,
    Char,
    Number,
    Quote,
    RawQuote,
}

pub(crate) struct Lexer {
    input: String,
    left_delim: String,
    right_delim: String,
    pos: usize,
    start: usize,
    at_eof: bool,
    paren_depth: i32,
    line: usize,
    start_line: usize,
    item: Item,
    inside_action: bool,
    pub options: LexOptions,
}

fn is_space(r: Option<char>) -> bool {
    matches!(r, Some(' ' | '\t' | '\r' | '\n'))
}

fn is_alpha_numeric(r: Option<char>) -> bool {
    match r {
        Some(c) => {
            c == '_' || crate::unicode::is_letter(c as i32) || crate::unicode::is_digit(c as i32)
        }
        None => false,
    }
}

fn has_left_trim_marker(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 2 && b[0] == TRIM_MARKER && is_space(Some(b[1] as char))
}

fn has_right_trim_marker(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 2 && is_space(Some(b[0] as char)) && b[1] == TRIM_MARKER
}

fn count_newlines(s: &str) -> usize {
    s.bytes().filter(|&b| b == b'\n').count()
}

/// Go's `%#U` formatting of a rune.
pub(crate) fn sharp_u(r: char) -> String {
    let mut s = format!("U+{:04X}", r as u32);
    if strconv::is_print(r as i32) {
        s.push_str(&format!(" '{r}'"));
    }
    s
}

/// `%#U` of a possibly absent rune; Go formats the EOF sentinel (-1) as
/// `U+FFFFFFFFFFFFFFFF`.
fn sharp_u_opt(r: Option<char>) -> String {
    match r {
        Some(c) => sharp_u(c),
        None => "U+FFFFFFFFFFFFFFFF".to_owned(),
    }
}

impl Lexer {
    pub fn new(input: &str, left: &str, right: &str) -> Lexer {
        let left = if left.is_empty() {
            DEFAULT_LEFT_DELIM
        } else {
            left
        };
        let right = if right.is_empty() {
            DEFAULT_RIGHT_DELIM
        } else {
            right
        };
        Lexer {
            input: input.to_owned(),
            left_delim: left.to_owned(),
            right_delim: right.to_owned(),
            pos: 0,
            start: 0,
            at_eof: false,
            paren_depth: 0,
            line: 1,
            start_line: 1,
            item: Item::empty(),
            inside_action: false,
            options: LexOptions::default(),
        }
    }

    fn rest(&self) -> &str {
        &self.input[self.pos..]
    }

    fn next(&mut self) -> Option<char> {
        if self.pos >= self.input.len() {
            self.at_eof = true;
            return None;
        }
        let r = self.input[self.pos..].chars().next().expect("in range");
        self.pos += r.len_utf8();
        if r == '\n' {
            self.line += 1;
        }
        Some(r)
    }

    fn peek(&mut self) -> Option<char> {
        let r = self.next();
        self.backup();
        r
    }

    fn backup(&mut self) {
        if !self.at_eof && self.pos > 0 {
            let r = self.input[..self.pos]
                .chars()
                .next_back()
                .expect("non-empty");
            self.pos -= r.len_utf8();
            if r == '\n' {
                self.line -= 1;
            }
        }
    }

    fn this_item(&mut self, t: ItemType) -> Item {
        let i = Item {
            typ: t,
            pos: Pos(self.start),
            val: self.input[self.start..self.pos].to_owned(),
            line: self.start_line,
        };
        self.start = self.pos;
        self.start_line = self.line;
        i
    }

    fn emit(&mut self, t: ItemType) -> Option<State> {
        let i = self.this_item(t);
        self.emit_item(i)
    }

    fn emit_item(&mut self, i: Item) -> Option<State> {
        self.item = i;
        None
    }

    fn ignore(&mut self) {
        self.line += count_newlines(&self.input[self.start..self.pos]);
        self.start = self.pos;
        self.start_line = self.line;
    }

    fn accept(&mut self, valid: &str) -> bool {
        if let Some(c) = self.next() {
            if valid.contains(c) {
                return true;
            }
        }
        self.backup();
        false
    }

    fn accept_run(&mut self, valid: &str) {
        while let Some(c) = self.next() {
            if !valid.contains(c) {
                break;
            }
        }
        self.backup();
    }

    fn errorf(&mut self, msg: String) -> Option<State> {
        self.item = Item {
            typ: ItemType::Error,
            pos: Pos(self.start),
            val: msg,
            line: self.start_line,
        };
        self.start = 0;
        self.pos = 0;
        self.input.clear();
        None
    }

    pub fn next_item(&mut self) -> Item {
        self.item = Item {
            typ: ItemType::Eof,
            pos: Pos(self.pos),
            val: "EOF".to_owned(),
            line: self.start_line,
        };
        let mut state = if self.inside_action {
            State::InsideAction
        } else {
            State::Text
        };
        loop {
            let next = match state {
                State::Text => self.lex_text(),
                State::LeftDelim => self.lex_left_delim(),
                State::Comment => self.lex_comment(),
                State::RightDelim => self.lex_right_delim(),
                State::InsideAction => self.lex_inside_action(),
                State::Space => self.lex_space(),
                State::Identifier => self.lex_identifier(),
                State::Field => self.lex_field_or_variable(ItemType::Field),
                State::Variable => self.lex_variable(),
                State::Char => self.lex_char(),
                State::Number => self.lex_number(),
                State::Quote => self.lex_quote(),
                State::RawQuote => self.lex_raw_quote(),
            };
            match next {
                Some(s) => state = s,
                None => return self.item.clone(),
            }
        }
    }

    fn lex_text(&mut self) -> Option<State> {
        if let Some(x) = self.rest().find(self.left_delim.as_str()) {
            if x > 0 {
                self.pos += x;
                // Determine how much preceding space to trim if necessary.
                let mut trim_length = 0;
                let delim_end = self.pos + self.left_delim.len();
                if has_left_trim_marker(&self.input[delim_end..]) {
                    let s = &self.input[self.start..self.pos];
                    trim_length = s.len() - s.trim_end_matches(SPACE_CHARS).len();
                }
                self.pos -= trim_length;
                self.line += count_newlines(&self.input[self.start..self.pos]);
                let i = self.this_item(ItemType::Text);
                self.pos += trim_length;
                self.ignore();
                if !i.val.is_empty() {
                    return self.emit_item(i);
                }
            }
            return Some(State::LeftDelim);
        }
        self.pos = self.input.len();
        // Correctly reached EOF.
        if self.pos > self.start {
            self.line += count_newlines(&self.input[self.start..self.pos]);
            return self.emit(ItemType::Text);
        }
        self.emit(ItemType::Eof)
    }

    /// Returns (at a right delimiter, with trim marker).
    fn at_right_delim(&self) -> (bool, bool) {
        let rest = self.rest();
        if has_right_trim_marker(rest)
            && rest[TRIM_MARKER_LEN..].starts_with(self.right_delim.as_str())
        {
            return (true, true);
        }
        if rest.starts_with(self.right_delim.as_str()) {
            return (true, false);
        }
        (false, false)
    }

    fn lex_left_delim(&mut self) -> Option<State> {
        self.pos += self.left_delim.len();
        let trim_space = has_left_trim_marker(self.rest());
        let after_marker = if trim_space { TRIM_MARKER_LEN } else { 0 };
        if self.input[self.pos + after_marker..].starts_with(LEFT_COMMENT) {
            self.pos += after_marker;
            self.ignore();
            return Some(State::Comment);
        }
        let i = self.this_item(ItemType::LeftDelim);
        self.inside_action = true;
        self.pos += after_marker;
        self.ignore();
        self.paren_depth = 0;
        self.emit_item(i)
    }

    fn lex_comment(&mut self) -> Option<State> {
        self.pos += LEFT_COMMENT.len();
        let Some(x) = self.rest().find(RIGHT_COMMENT) else {
            return self.errorf("unclosed comment".to_owned());
        };
        self.pos += x + RIGHT_COMMENT.len();
        let (delim, trim_space) = self.at_right_delim();
        if !delim {
            return self.errorf("comment ends before closing delimiter".to_owned());
        }
        self.line += count_newlines(&self.input[self.start..self.pos]);
        let i = self.this_item(ItemType::Comment);
        if trim_space {
            self.pos += TRIM_MARKER_LEN;
        }
        self.pos += self.right_delim.len();
        if trim_space {
            let rest = self.rest();
            self.pos += rest.len() - rest.trim_start_matches(SPACE_CHARS).len();
        }
        self.ignore();
        if self.options.emit_comment {
            return self.emit_item(i);
        }
        Some(State::Text)
    }

    fn lex_right_delim(&mut self) -> Option<State> {
        let (_, trim_space) = self.at_right_delim();
        if trim_space {
            self.pos += TRIM_MARKER_LEN;
            self.ignore();
        }
        self.pos += self.right_delim.len();
        let i = self.this_item(ItemType::RightDelim);
        if trim_space {
            let rest = self.rest();
            self.pos += rest.len() - rest.trim_start_matches(SPACE_CHARS).len();
            self.ignore();
        }
        self.inside_action = false;
        self.emit_item(i)
    }

    fn lex_inside_action(&mut self) -> Option<State> {
        let (delim, _) = self.at_right_delim();
        if delim {
            if self.paren_depth == 0 {
                return Some(State::RightDelim);
            }
            return self.errorf("unclosed left paren".to_owned());
        }
        let r = self.next();
        match r {
            None => self.errorf("unclosed action".to_owned()),
            Some(' ' | '\t' | '\r' | '\n') => {
                // Put space back in case we have " -}}".
                self.backup();
                Some(State::Space)
            }
            Some('=') => self.emit(ItemType::Assign),
            Some(':') => {
                if self.next() != Some('=') {
                    return self.errorf("expected :=".to_owned());
                }
                self.emit(ItemType::Declare)
            }
            Some('|') => self.emit(ItemType::Pipe),
            Some('"') => Some(State::Quote),
            Some('`') => Some(State::RawQuote),
            Some('$') => Some(State::Variable),
            Some('\'') => Some(State::Char),
            Some(c @ ('.' | '+' | '-' | '0'..='9')) => {
                // special look-ahead for ".field" so we don't break l.backup().
                if c == '.' && self.pos < self.input.len() {
                    let b = self.input.as_bytes()[self.pos];
                    if !b.is_ascii_digit() {
                        return Some(State::Field);
                    }
                }
                self.backup();
                Some(State::Number)
            }
            Some(_) if is_alpha_numeric(r) => {
                self.backup();
                Some(State::Identifier)
            }
            Some('(') => {
                self.paren_depth += 1;
                self.emit(ItemType::LeftParen)
            }
            Some(')') => {
                self.paren_depth -= 1;
                if self.paren_depth < 0 {
                    return self.errorf("unexpected right paren".to_owned());
                }
                self.emit(ItemType::RightParen)
            }
            Some(c) if c.is_ascii() && strconv::is_print(c as i32) => self.emit(ItemType::Char),
            Some(c) => self.errorf(format!("unrecognized character in action: {}", sharp_u(c))),
        }
    }

    fn lex_space(&mut self) -> Option<State> {
        let mut num_spaces = 0;
        while is_space(self.peek()) {
            self.next();
            num_spaces += 1;
        }
        // Be careful about a trim-marked closing delimiter, which has a minus
        // after a space. We know there is a space, so check for the '-' that
        // might follow.
        if has_right_trim_marker(&self.input[self.pos - 1..])
            && self.input[self.pos - 1 + TRIM_MARKER_LEN..].starts_with(self.right_delim.as_str())
        {
            self.backup(); // Before the space.
            if num_spaces == 1 {
                return Some(State::RightDelim); // On the delim, so go right to that.
            }
        }
        self.emit(ItemType::Space)
    }

    fn lex_identifier(&mut self) -> Option<State> {
        loop {
            let r = self.next();
            if is_alpha_numeric(r) {
                continue;
            }
            self.backup();
            let word = self.input[self.start..self.pos].to_owned();
            if !self.at_terminator() {
                return self.errorf(format!("bad character {}", sharp_u_opt(r)));
            }
            if let Some(item) = keyword(&word) {
                if (item == ItemType::Break && !self.options.break_ok)
                    || (item == ItemType::Continue && !self.options.continue_ok)
                {
                    return self.emit(ItemType::Identifier);
                }
                return self.emit(item);
            }
            if word.as_bytes()[0] == b'.' {
                return self.emit(ItemType::Field);
            }
            if word == "true" || word == "false" {
                return self.emit(ItemType::Bool);
            }
            return self.emit(ItemType::Identifier);
        }
    }

    fn lex_variable(&mut self) -> Option<State> {
        if self.at_terminator() {
            // Nothing interesting follows -> "$".
            return self.emit(ItemType::Variable);
        }
        self.lex_field_or_variable(ItemType::Variable)
    }

    fn lex_field_or_variable(&mut self, typ: ItemType) -> Option<State> {
        if self.at_terminator() {
            // Nothing interesting follows -> "." or "$".
            if typ == ItemType::Variable {
                return self.emit(ItemType::Variable);
            }
            return self.emit(ItemType::Dot);
        }
        let mut r;
        loop {
            r = self.next();
            if !is_alpha_numeric(r) {
                self.backup();
                break;
            }
        }
        if !self.at_terminator() {
            return self.errorf(format!("bad character {}", sharp_u_opt(r)));
        }
        self.emit(typ)
    }

    fn at_terminator(&mut self) -> bool {
        let r = self.peek();
        if is_space(r) {
            return true;
        }
        if matches!(r, None | Some('.' | ',' | '|' | ':' | ')' | '(')) {
            return true;
        }
        self.rest().starts_with(self.right_delim.as_str())
    }

    fn lex_char(&mut self) -> Option<State> {
        loop {
            match self.next() {
                Some('\\') => {
                    let r = self.next();
                    if r.is_some() && r != Some('\n') {
                        continue;
                    }
                    return self.errorf("unterminated character constant".to_owned());
                }
                None | Some('\n') => {
                    return self.errorf("unterminated character constant".to_owned());
                }
                Some('\'') => break,
                _ => {}
            }
        }
        self.emit(ItemType::CharConstant)
    }

    fn lex_number(&mut self) -> Option<State> {
        if !self.scan_number() {
            return self.errorf(format!(
                "bad number syntax: {}",
                strconv::quote(&self.input[self.start..self.pos])
            ));
        }
        let sign = self.peek();
        if sign == Some('+') || sign == Some('-') {
            // Complex: 1+2i. No spaces, must end in 'i'.
            if !self.scan_number() || self.input.as_bytes()[self.pos - 1] != b'i' {
                return self.errorf(format!(
                    "bad number syntax: {}",
                    strconv::quote(&self.input[self.start..self.pos])
                ));
            }
            return self.emit(ItemType::Complex);
        }
        self.emit(ItemType::Number)
    }

    fn scan_number(&mut self) -> bool {
        // Optional leading sign.
        self.accept("+-");
        // Is it hex?
        let mut digits = "0123456789_";
        if self.accept("0") {
            // Note: Leading 0 does not mean octal in floats.
            if self.accept("xX") {
                digits = "0123456789abcdefABCDEF_";
            } else if self.accept("oO") {
                digits = "01234567_";
            } else if self.accept("bB") {
                digits = "01_";
            }
        }
        self.accept_run(digits);
        if self.accept(".") {
            self.accept_run(digits);
        }
        if digits.len() == 10 + 1 && self.accept("eE") {
            self.accept("+-");
            self.accept_run("0123456789_");
        }
        if digits.len() == 16 + 6 + 1 && self.accept("pP") {
            self.accept("+-");
            self.accept_run("0123456789_");
        }
        // Is it imaginary?
        self.accept("i");
        // Next thing mustn't be alphanumeric.
        let p = self.peek();
        if is_alpha_numeric(p) {
            self.next();
            return false;
        }
        true
    }

    fn lex_quote(&mut self) -> Option<State> {
        loop {
            match self.next() {
                Some('\\') => {
                    let r = self.next();
                    if r.is_some() && r != Some('\n') {
                        continue;
                    }
                    return self.errorf("unterminated quoted string".to_owned());
                }
                None | Some('\n') => return self.errorf("unterminated quoted string".to_owned()),
                Some('"') => break,
                _ => {}
            }
        }
        self.emit(ItemType::String)
    }

    fn lex_raw_quote(&mut self) -> Option<State> {
        loop {
            match self.next() {
                None => return self.errorf("unterminated raw quoted string".to_owned()),
                Some('`') => break,
                _ => {}
            }
        }
        self.emit(ItemType::RawString)
    }
}
