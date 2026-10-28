//! The tokenizer: Go's `xml.Decoder` byte loop, namespace stack and helpers.
//!
//! Go's behaviour is reproduced byte for byte, including `getc`/`ungetc` line
//! and offset accounting, because error text and positions are observable.
use super::{
    conv::{lossy, quote},
    error::SyntaxError,
    is_in_character_range, is_name, Attr, CharData, Comment, Directive, EndElement, Error, Name,
    ProcInst, StartElement, Token, TokenReader,
};
use crate::{text::BytesExt, unicode::rune};
use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Read},
};

/// Go's `CharsetReader` hook: `(charset, input) -> reader of UTF-8`.
pub type CharsetReader<'a> = Box<
    dyn FnMut(
            &str,
            Box<dyn Read + 'a>,
        ) -> Result<Box<dyn Read + 'a>, Box<dyn std::error::Error + Send + Sync>>
        + 'a,
>;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum StackKind {
    Start,
    Ns,
    Eof,
}

#[derive(Clone, Debug)]
pub(super) struct StackEntry {
    pub kind: StackKind,
    pub name: Name,
    pub ok: bool,
}

const XML_URL: &str = "http://www.w3.org/XML/1998/namespace";
const XMLNS_PREFIX: &str = "xmlns";
const XML_PREFIX: &str = "xml";

/// An XML parser reading a particular input stream (Go `xml.Decoder`).
///
/// The parser assumes that its input is encoded in UTF-8.
pub struct Decoder<'a> {
    /// Go's `Strict` (default `true`): enforce the XML specification. When
    /// `false`, missing end tags are invented and unknown or malformed
    /// character entities are left alone.
    pub strict: bool,
    /// Go's `AutoClose`: when not strict, elements considered closed
    /// immediately after they are opened.
    pub auto_close: Vec<String>,
    /// Go's `Entity`: replacements for non-standard entity names. `lt`, `gt`,
    /// `amp`, `apos` and `quot` always work.
    pub entity: HashMap<String, String>,
    /// Go's `CharsetReader`: converts a declared non-UTF-8 charset to UTF-8.
    pub charset_reader: Option<CharsetReader<'a>>,
    /// Go's `DefaultSpace`: the name space of unadorned tags, as if the stream
    /// were wrapped in an element with `xmlns="DefaultSpace"`.
    pub default_space: String,
    /// Maximum bytes buffered for one token (text, comment, directive,
    /// processing instruction or name). Go has no limit; the default is far above
    /// any realistic token and does not change results on Go's own inputs.
    pub max_token_bytes: usize,
    /// Maximum element nesting accepted by `token`. Go has no limit.
    pub max_depth: usize,
    /// Maximum nesting `decode` will recurse into (Go's `maxUnmarshalDepth`).
    pub max_unmarshal_depth: usize,
    /// Stack bytes `decode` may use for recursion before it fails with the
    /// `exceeded max depth` error. Go's goroutine stacks grow on demand; a Rust
    /// thread's does not, so this keeps hostile nesting from overflowing it. The
    /// default suits a 2 MiB thread stack; raise it (with a larger stack) to
    /// decode the full `max_unmarshal_depth`.
    pub max_unmarshal_stack: usize,

    r: Option<BufReader<Box<dyn Read + 'a>>>,
    t: Option<Box<dyn TokenReader + 'a>>,
    pub(super) buf: Vec<u8>,
    pub(super) saved: Option<Vec<u8>>,
    pub(super) stk: Vec<StackEntry>,
    pub(super) stk_depth: usize,
    need_close: bool,
    to_close: Name,
    next_token: Option<Token>,
    next_byte: i32,
    ns: HashMap<String, String>,
    err: Option<Error>,
    line: usize,
    linestart: i64,
    offset: i64,
    pub(super) in_unmarshal_xml: bool,
    pub(super) stack_base: Option<usize>,
}

impl<'a> Decoder<'a> {
    /// Creates a new XML parser reading from `r` (Go `NewDecoder`).
    pub fn new(r: impl Read + 'a) -> Self {
        let mut d = Self::blank();
        d.r = Some(BufReader::new(Box::new(r)));
        d
    }

    /// Creates a new XML parser using an underlying token stream (Go
    /// `NewTokenDecoder`).
    ///
    /// Go returns `t` itself when it already is a `*Decoder`; a boxed trait
    /// object cannot be inspected that way, so a `Decoder` is simply wrapped.
    pub fn from_token_reader(t: impl TokenReader + 'a) -> Self {
        let mut d = Self::blank();
        d.t = Some(Box::new(t));
        d
    }

    fn blank() -> Self {
        Decoder {
            strict: true,
            auto_close: Vec::new(),
            entity: HashMap::new(),
            charset_reader: None,
            default_space: String::new(),
            max_token_bytes: 256 * 1024 * 1024,
            max_depth: 1_000_000,
            max_unmarshal_depth: 10_000,
            max_unmarshal_stack: 1 << 20,
            r: None,
            t: None,
            buf: Vec::new(),
            saved: None,
            stk: Vec::new(),
            stk_depth: 0,
            need_close: false,
            to_close: Name::default(),
            next_token: None,
            next_byte: -1,
            ns: HashMap::new(),
            err: None,
            line: 1,
            linestart: 0,
            offset: 0,
            in_unmarshal_xml: false,
            stack_base: None,
        }
    }

    /// Returns the next XML token in the input stream; `Err(Error::Eof)` at the
    /// end (Go `Token`).
    ///
    /// Self-closing elements are expanded into a start and an end element, and
    /// start and end elements are guaranteed to be properly nested and matched.
    /// Name spaces are translated to URLs; unknown prefixes are kept as the space.
    pub fn token(&mut self) -> Result<Token, Error> {
        if self.stk.last().is_some_and(|s| s.kind == StackKind::Eof) {
            return Err(Error::Eof);
        }
        let mut t = if let Some(t) = self.next_token.take() {
            t
        } else {
            match self.raw_token_inner() {
                Err(e) => {
                    if e.is_eof() && !self.stk.is_empty() {
                        return Err(self.syntax_error("unexpected EOF"));
                    }
                    return Err(e);
                }
                Ok(t) => t,
            }
        };
        if !self.strict {
            if let Some(t1) = self.auto_close(&t) {
                self.next_token = Some(t);
                t = t1;
            }
        }
        match t {
            Token::StartElement(mut t1) => {
                // The translations listed in the attributes apply to the element
                // name and to the other attribute names, so process them first.
                for a in &t1.attr {
                    if a.name.space == XMLNS_PREFIX {
                        let old = self.ns.get(&a.name.local).cloned();
                        self.push_ns(&a.name.local, old.clone());
                        self.ns.insert(a.name.local.clone(), a.value.clone());
                    }
                    if a.name.space.is_empty() && a.name.local == XMLNS_PREFIX {
                        let old = self.ns.get("").cloned();
                        self.push_ns("", old);
                        self.ns.insert(String::new(), a.value.clone());
                    }
                }
                self.push_element(t1.name.clone());
                let mut name = std::mem::take(&mut t1.name);
                self.translate(&mut name, true);
                t1.name = name;
                for i in 0..t1.attr.len() {
                    let mut n = std::mem::take(&mut t1.attr[i].name);
                    self.translate(&mut n, false);
                    t1.attr[i].name = n;
                }
                if self.stk_depth > self.max_depth {
                    self.err = Some(self.syntax_error("exceeded maximum element depth"));
                    return Err(self.err.clone().expect("just set"));
                }
                Ok(Token::StartElement(t1))
            }
            Token::EndElement(mut t1) => {
                if !self.pop_element(&mut t1) {
                    return Err(self.err.clone().unwrap_or(Error::Eof));
                }
                Ok(Token::EndElement(t1))
            }
            other => Ok(other),
        }
    }

    /// Like `token` but does not verify that start and end elements match and
    /// does not translate name space prefixes (Go `RawToken`).
    pub fn raw_token(&mut self) -> Result<Token, Error> {
        if self.in_unmarshal_xml {
            return Err(Error::msg(
                "xml: cannot use RawToken from UnmarshalXML method",
            ));
        }
        self.raw_token_inner()
    }

    /// Reads tokens until it has consumed the end element matching the most
    /// recent start element already consumed (Go `Skip`).
    pub fn skip(&mut self) -> Result<(), Error> {
        let mut depth: i64 = 0;
        loop {
            match self.token()? {
                Token::StartElement(_) => depth += 1,
                Token::EndElement(_) => {
                    if depth == 0 {
                        return Ok(());
                    }
                    depth -= 1;
                }
                _ => {}
            }
        }
    }

    /// The input stream byte offset of the current decoder position: the end of
    /// the most recently returned token (Go `InputOffset`).
    pub fn input_offset(&self) -> i64 {
        self.offset
    }

    /// The line and 1-based column of the current decoder position (Go `InputPos`).
    pub fn input_pos(&self) -> (usize, usize) {
        (self.line, (self.offset - self.linestart + 1) as usize)
    }

    fn translate(&self, n: &mut Name, is_element_name: bool) {
        if n.space == XMLNS_PREFIX {
            return;
        }
        if n.space.is_empty() && !is_element_name {
            return;
        }
        if n.space == XML_PREFIX {
            n.space = XML_URL.to_string();
        } else if n.space.is_empty() && n.local == XMLNS_PREFIX {
            return;
        }
        if let Some(v) = self.ns.get(&n.space) {
            n.space = v.clone();
        } else if n.space.is_empty() {
            n.space = self.default_space.clone();
        }
    }

    fn push(&mut self, kind: StackKind) -> &mut StackEntry {
        if kind == StackKind::Start {
            self.stk_depth += 1;
        }
        self.stk.push(StackEntry {
            kind,
            name: Name::default(),
            ok: false,
        });
        self.stk.last_mut().expect("just pushed")
    }

    fn pop(&mut self) -> Option<StackEntry> {
        let s = self.stk.pop();
        if let Some(s) = &s {
            if s.kind == StackKind::Start {
                self.stk_depth -= 1;
            }
        }
        s
    }

    /// Records that after the current element is finished `token` returns EOF
    /// until `pop_eof` is called.
    pub(super) fn push_eof(&mut self) -> Result<(), Error> {
        // Find the Start entry, then step below the Ns entries that belong to it.
        let Some(mut i) = self.stk.iter().rposition(|s| s.kind == StackKind::Start) else {
            return Err(Error::msg(
                "xml: Unmarshaler used without an open start element",
            ));
        };
        while i > 0 && self.stk[i - 1].kind == StackKind::Ns {
            i -= 1;
        }
        self.stk.insert(
            i,
            StackEntry {
                kind: StackKind::Eof,
                name: Name::default(),
                ok: false,
            },
        );
        Ok(())
    }

    /// Undoes a `push_eof`; the element must have been finished.
    pub(super) fn pop_eof(&mut self) -> bool {
        if self.stk.last().is_none_or(|s| s.kind != StackKind::Eof) {
            return false;
        }
        self.pop();
        true
    }

    fn push_element(&mut self, name: Name) {
        self.push(StackKind::Start).name = name;
    }

    fn push_ns(&mut self, local: &str, url: Option<String>) {
        let s = self.push(StackKind::Ns);
        s.name.local = local.to_string();
        s.ok = url.is_some();
        s.name.space = url.unwrap_or_default();
    }

    pub(super) fn syntax_error(&self, msg: &str) -> Error {
        Error::Syntax(SyntaxError {
            msg: msg.to_string(),
            line: self.line,
        })
    }

    fn pop_element(&mut self, t: &mut EndElement) -> bool {
        let s = self.pop();
        let name = t.name.clone();
        match s {
            None
            | Some(StackEntry {
                kind: StackKind::Ns | StackKind::Eof,
                ..
            }) => {
                self.err =
                    Some(self.syntax_error(&format!("unexpected end element </{}>", name.local)));
                return false;
            }
            Some(s) => {
                if s.name.local != name.local {
                    if !self.strict {
                        self.need_close = true;
                        self.to_close = t.name.clone();
                        t.name = s.name;
                        return true;
                    }
                    self.err = Some(self.syntax_error(&format!(
                        "element <{}> closed by </{}>",
                        s.name.local, name.local
                    )));
                    return false;
                }
                if s.name.space != name.space {
                    let ns = if name.space.is_empty() {
                        "\"\"".to_string()
                    } else {
                        name.space.clone()
                    };
                    self.err = Some(self.syntax_error(&format!(
                        "element <{}> in space {} closed by </{}> in space {}",
                        s.name.local, s.name.space, name.local, ns
                    )));
                    return false;
                }
            }
        }
        let mut n = std::mem::take(&mut t.name);
        self.translate(&mut n, true);
        t.name = n;
        // Pop until a Start or EOF is on top, undoing this element's translations.
        while self
            .stk
            .last()
            .is_some_and(|s| s.kind != StackKind::Start && s.kind != StackKind::Eof)
        {
            let s = self.pop().expect("checked non-empty");
            if s.ok {
                self.ns.insert(s.name.local, s.name.space);
            } else {
                self.ns.remove(&s.name.local);
            }
        }
        true
    }

    /// If the top element is autoclosing and `t` is not its end tag, invents it.
    fn auto_close(&self, t: &Token) -> Option<Token> {
        let top = self.stk.last()?;
        if top.kind != StackKind::Start {
            return None;
        }
        for s in &self.auto_close {
            if s.as_bytes().equal_fold(top.name.local.as_bytes()) {
                // This one should be auto closed if t doesn't close it.
                let closes = matches!(t, Token::EndElement(et)
                    if et.name.local.as_bytes().equal_fold(top.name.local.as_bytes()));
                if !closes {
                    return Some(Token::EndElement(EndElement {
                        name: top.name.clone(),
                    }));
                }
                break;
            }
        }
        None
    }

    fn fail(&self) -> Error {
        self.err.clone().unwrap_or(Error::Eof)
    }

    fn raw_token_inner(&mut self) -> Result<Token, Error> {
        if let Some(t) = self.t.as_mut() {
            return t.token();
        }
        if let Some(e) = &self.err {
            return Err(e.clone());
        }
        if self.need_close {
            // The last element we read was self-closing and we returned just
            // the StartElement half. Return the EndElement half now.
            self.need_close = false;
            return Ok(Token::EndElement(EndElement {
                name: self.to_close.clone(),
            }));
        }

        let Some(b) = self.getc() else {
            return Err(self.fail());
        };

        if b != b'<' {
            // Text section.
            self.ungetc(b);
            return match self.text(-1, false) {
                Some(data) => Ok(Token::CharData(CharData(data))),
                None => Err(self.fail()),
            };
        }

        let Some(mut b) = self.mustgetc() else {
            return Err(self.fail());
        };
        match b {
            b'/' => {
                // </: End element
                let Some(name) = self.nsname() else {
                    if self.err.is_none() {
                        self.err = Some(self.syntax_error("expected element name after </"));
                    }
                    return Err(self.fail());
                };
                self.space();
                let Some(b) = self.mustgetc() else {
                    return Err(self.fail());
                };
                if b != b'>' {
                    self.err = Some(self.syntax_error(&format!(
                        "invalid characters between </{} and >",
                        name.local
                    )));
                    return Err(self.fail());
                }
                return Ok(Token::EndElement(EndElement { name }));
            }
            b'?' => {
                // <?: Processing instruction.
                let Some(target) = self.name() else {
                    if self.err.is_none() {
                        self.err = Some(self.syntax_error("expected target name after <?"));
                    }
                    return Err(self.fail());
                };
                self.space();
                self.buf.clear();
                let mut b0 = 0u8;
                loop {
                    let Some(b) = self.mustgetc() else {
                        return Err(self.fail());
                    };
                    self.buf.push(b);
                    if b0 == b'?' && b == b'>' {
                        break;
                    }
                    b0 = b;
                    if !self.check_buf() {
                        return Err(self.fail());
                    }
                }
                let n = self.buf.len() - 2; // chop ?>
                let data = self.buf[..n].to_vec();

                if target == "xml" {
                    let ver = proc_inst(b"version", &data);
                    if !ver.is_empty() && ver != b"1.0" {
                        self.err = Some(Error::msg(format!(
                            "xml: unsupported version {}; only version 1.0 is supported",
                            quote(&ver)
                        )));
                        return Err(self.fail());
                    }
                    let enc = proc_inst(b"encoding", &data);
                    if !enc.is_empty()
                        && enc != b"utf-8"
                        && enc != b"UTF-8"
                        && !enc.eq_ignore_ascii_case(b"utf-8")
                    {
                        if self.charset_reader.is_none() {
                            self.err = Some(Error::msg(format!(
                                "xml: encoding {} declared but Decoder.CharsetReader is nil",
                                quote(&enc)
                            )));
                            return Err(self.fail());
                        }
                        let enc_name = lossy(&enc);
                        let current = self.r.take().expect("byte reader present");
                        let reader = self.charset_reader.as_mut().expect("checked above");
                        match reader(&enc_name, Box::new(current)) {
                            Err(e) => {
                                self.err = Some(Error::msg(format!(
                                    "xml: opening charset {}: {}",
                                    quote(&enc),
                                    e
                                )));
                                return Err(self.fail());
                            }
                            Ok(newr) => self.r = Some(BufReader::new(newr)),
                        }
                    }
                }
                return Ok(Token::ProcInst(ProcInst { target, inst: data }));
            }
            b'!' => {
                // <!: Maybe comment, maybe CDATA.
                let Some(c) = self.mustgetc() else {
                    return Err(self.fail());
                };
                b = c;
                match b {
                    b'-' => {
                        // <!- Probably <!-- for a comment.
                        let Some(c) = self.mustgetc() else {
                            return Err(self.fail());
                        };
                        if c != b'-' {
                            self.err =
                                Some(self.syntax_error("invalid sequence <!- not part of <!--"));
                            return Err(self.fail());
                        }
                        // Look for terminator.
                        self.buf.clear();
                        let (mut b0, mut b1) = (0u8, 0u8);
                        loop {
                            let Some(c) = self.mustgetc() else {
                                return Err(self.fail());
                            };
                            self.buf.push(c);
                            if b0 == b'-' && b1 == b'-' {
                                if c != b'>' {
                                    self.err = Some(self.syntax_error(
                                        "invalid sequence \"--\" not allowed in comments",
                                    ));
                                    return Err(self.fail());
                                }
                                break;
                            }
                            b0 = b1;
                            b1 = c;
                            if !self.check_buf() {
                                return Err(self.fail());
                            }
                        }
                        let n = self.buf.len() - 3; // chop -->
                        return Ok(Token::Comment(Comment(self.buf[..n].to_vec())));
                    }
                    b'[' => {
                        // <![ Probably <![CDATA[.
                        for want in b"CDATA[" {
                            let Some(c) = self.mustgetc() else {
                                return Err(self.fail());
                            };
                            if c != *want {
                                self.err = Some(self.syntax_error("invalid <![ sequence"));
                                return Err(self.fail());
                            }
                        }
                        // Have <![CDATA[. Read text until ]]>.
                        return match self.text(-1, true) {
                            Some(data) => Ok(Token::CharData(CharData(data))),
                            None => Err(self.fail()),
                        };
                    }
                    _ => {}
                }

                // Probably a directive: <!DOCTYPE ...>, <!ENTITY ...>, etc. We
                // accumulate it for the caller. Quoted angle brackets do not count
                // for nesting.
                self.buf.clear();
                self.buf.push(b);
                let mut inquote = 0u8;
                let mut depth = 0i32;
                loop {
                    let Some(c) = self.mustgetc() else {
                        return Err(self.fail());
                    };
                    b = c;
                    if inquote == 0 && b == b'>' && depth == 0 {
                        break;
                    }
                    // HandleB:
                    'handle: loop {
                        self.buf.push(b);
                        if b == inquote {
                            inquote = 0;
                        } else if inquote != 0 {
                            // in quotes, no special action
                        } else if b == b'\'' || b == b'"' {
                            inquote = b;
                        } else if b == b'>' && inquote == 0 {
                            depth -= 1;
                        } else if b == b'<' && inquote == 0 {
                            // Look for <!-- to begin comment.
                            let s = b"!--";
                            for i in 0..s.len() {
                                let Some(c) = self.mustgetc() else {
                                    return Err(self.fail());
                                };
                                b = c;
                                if b != s[i] {
                                    for ch in &s[..i] {
                                        self.buf.push(*ch);
                                    }
                                    depth += 1;
                                    continue 'handle;
                                }
                            }
                            // Remove < that was written above.
                            self.buf.pop();
                            // Look for terminator.
                            let (mut b0, mut b1) = (0u8, 0u8);
                            loop {
                                let Some(c) = self.mustgetc() else {
                                    return Err(self.fail());
                                };
                                b = c;
                                if b0 == b'-' && b1 == b'-' && b == b'>' {
                                    break;
                                }
                                b0 = b1;
                                b1 = b;
                            }
                            // Replace the comment with a space in the returned
                            // Directive body so that markup parts separated by the
                            // comment do not get joined when re-encoding.
                            self.buf.push(b' ');
                        }
                        break;
                    }
                    if !self.check_buf() {
                        return Err(self.fail());
                    }
                }
                return Ok(Token::Directive(Directive(self.buf.clone())));
            }
            _ => {}
        }

        // Must be an open element like <a href="foo">
        self.ungetc(b);

        let mut empty = false;
        let Some(name) = self.nsname() else {
            if self.err.is_none() {
                self.err = Some(self.syntax_error("expected element name after <"));
            }
            return Err(self.fail());
        };

        let mut attr: Vec<Attr> = Vec::new();
        loop {
            self.space();
            let Some(b) = self.mustgetc() else {
                return Err(self.fail());
            };
            if b == b'/' {
                empty = true;
                let Some(b) = self.mustgetc() else {
                    return Err(self.fail());
                };
                if b != b'>' {
                    self.err = Some(self.syntax_error("expected /> in element"));
                    return Err(self.fail());
                }
                break;
            }
            if b == b'>' {
                break;
            }
            self.ungetc(b);

            let Some(aname) = self.nsname() else {
                if self.err.is_none() {
                    self.err = Some(self.syntax_error("expected attribute name in element"));
                }
                return Err(self.fail());
            };
            let mut a = Attr {
                name: aname,
                value: String::new(),
            };
            self.space();
            let Some(b) = self.mustgetc() else {
                return Err(self.fail());
            };
            if b != b'=' {
                if self.strict {
                    self.err = Some(self.syntax_error("attribute name without = in element"));
                    return Err(self.fail());
                }
                self.ungetc(b);
                a.value = a.name.local.clone();
            } else {
                self.space();
                let Some(data) = self.attrval() else {
                    return Err(self.fail());
                };
                a.value = String::from_utf8_lossy(&data).into_owned();
            }
            attr.push(a);
        }
        if empty {
            self.need_close = true;
            self.to_close = name.clone();
        }
        Ok(Token::StartElement(StartElement { name, attr }))
    }

    fn attrval(&mut self) -> Option<Vec<u8>> {
        let b = self.mustgetc()?;
        // Handle quoted attribute values
        if b == b'"' || b == b'\'' {
            return self.text(i32::from(b), false);
        }
        // Handle unquoted attribute values for strict parsers
        if self.strict {
            self.err = Some(self.syntax_error("unquoted or missing attribute value in element"));
            return None;
        }
        // Handle unquoted attribute values for unstrict parsers
        self.ungetc(b);
        self.buf.clear();
        loop {
            let b = self.mustgetc()?;
            // https://www.w3.org/TR/REC-html40/intro/sgmltut.html#h-3.2.2
            if b.is_ascii_alphanumeric() || b == b'_' || b == b':' || b == b'-' {
                self.buf.push(b);
            } else {
                self.ungetc(b);
                break;
            }
        }
        Some(self.buf.clone())
    }

    /// Skips spaces if any.
    fn space(&mut self) {
        loop {
            let Some(b) = self.getc() else { return };
            match b {
                b' ' | b'\r' | b'\n' | b'\t' => {}
                _ => {
                    self.ungetc(b);
                    return;
                }
            }
        }
    }

    fn read_byte(&mut self) -> Result<u8, Error> {
        let r = self.r.as_mut().expect("byte reader present");
        loop {
            match r.fill_buf() {
                Ok([]) => return Err(Error::Eof),
                Ok(buf) => {
                    let b = buf[0];
                    r.consume(1);
                    return Ok(b);
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Reads a single byte, maintaining the line number. When there is none,
    /// returns `None` and leaves the error in `self.err`.
    fn getc(&mut self) -> Option<u8> {
        if self.err.is_some() {
            return None;
        }
        let b;
        if self.next_byte >= 0 {
            b = self.next_byte as u8;
            self.next_byte = -1;
        } else {
            match self.read_byte() {
                Ok(c) => b = c,
                Err(e) => {
                    self.err = Some(e);
                    return None;
                }
            }
            if let Some(saved) = &mut self.saved {
                saved.push(b);
            }
        }
        if b == b'\n' {
            self.line += 1;
            self.linestart = self.offset + 1;
        }
        self.offset += 1;
        Some(b)
    }

    /// Saved offset; if we did `ungetc` (a pending byte), back up one.
    pub(super) fn saved_offset(&self) -> usize {
        let mut n = self.saved.as_ref().map_or(0, Vec::len);
        if self.next_byte >= 0 {
            // A byte pushed back before saving began is not in the buffer.
            n = n.saturating_sub(1);
        }
        n
    }

    /// Must read a single byte; at EOF sets a "unexpected EOF" syntax error.
    fn mustgetc(&mut self) -> Option<u8> {
        let b = self.getc();
        if b.is_none() && matches!(self.err, Some(Error::Eof)) {
            self.err = Some(self.syntax_error("unexpected EOF"));
        }
        b
    }

    /// Unreads a single byte.
    fn ungetc(&mut self, b: u8) {
        if b == b'\n' {
            self.line -= 1;
        }
        self.next_byte = i32::from(b);
        self.offset -= 1;
    }

    fn check_buf(&mut self) -> bool {
        if self.buf.len() > self.max_token_bytes {
            self.err = Some(Error::msg("xml: token exceeds Decoder.max_token_bytes"));
            return false;
        }
        true
    }

    /// Reads a plain text section. If `quote >= 0` we are in a quoted string and
    /// need to find the matching quote. If `cdata` we are in `<![CDATA[` and need
    /// `]]>`. On failure returns `None` with the error in `self.err`.
    fn text(&mut self, quote: i32, cdata: bool) -> Option<Vec<u8>> {
        let (mut b0, mut b1) = (0u8, 0u8);
        let mut trunc = 0usize;
        self.buf.clear();
        'input: loop {
            let Some(mut b) = self.getc() else {
                if cdata {
                    if matches!(self.err, Some(Error::Eof)) {
                        self.err = Some(self.syntax_error("unexpected EOF in CDATA section"));
                    }
                    return None;
                }
                break 'input;
            };

            // <![CDATA[ section ends with ]]>. It is an error for ]]> to appear in
            // ordinary text, but it is allowed in quoted strings.
            if quote < 0 && b0 == b']' && b1 == b']' && b == b'>' {
                if cdata {
                    trunc = 2;
                    break 'input;
                }
                self.err = Some(self.syntax_error("unescaped ]]> not in CDATA section"));
                return None;
            }

            // Stop reading text if we see a <.
            if b == b'<' && !cdata {
                if quote >= 0 {
                    self.err = Some(self.syntax_error("unescaped < inside quoted string"));
                    return None;
                }
                self.ungetc(b'<');
                break 'input;
            }
            if quote >= 0 && i32::from(b) == quote {
                break 'input;
            }
            if b == b'&' && !cdata {
                // Read escaped character expression up to semicolon.
                let before = self.buf.len();
                self.buf.push(b'&');
                let mut text = String::new();
                let mut have_text = false;
                b = self.mustgetc()?;
                if b == b'#' {
                    self.buf.push(b);
                    b = self.mustgetc()?;
                    let mut base = 10;
                    if b == b'x' {
                        base = 16;
                        self.buf.push(b);
                        b = self.mustgetc()?;
                    }
                    let start = self.buf.len();
                    while b.is_ascii_digit()
                        || (base == 16 && matches!(b, b'a'..=b'f'))
                        || (base == 16 && matches!(b, b'A'..=b'F'))
                    {
                        self.buf.push(b);
                        b = self.mustgetc()?;
                    }
                    if b != b';' {
                        self.ungetc(b);
                    } else {
                        let s = String::from_utf8_lossy(&self.buf[start..]).into_owned();
                        self.buf.push(b';');
                        if let Ok(n) = u64::from_str_radix(&s, base) {
                            if n <= 0x10FFFF {
                                text = char::from_u32(n as u32).unwrap_or('\u{fffd}').to_string();
                                have_text = true;
                            }
                        }
                    }
                } else {
                    self.ungetc(b);
                    if !self.read_name() && self.err.is_some() {
                        return None;
                    }
                    b = self.mustgetc()?;
                    if b != b';' {
                        self.ungetc(b);
                    } else {
                        let name = self.buf[before + 1..].to_vec();
                        self.buf.push(b';');
                        if is_name(&name) {
                            let s = String::from_utf8_lossy(&name).into_owned();
                            match s.as_str() {
                                "lt" => (text, have_text) = ("<".into(), true),
                                "gt" => (text, have_text) = (">".into(), true),
                                "amp" => (text, have_text) = ("&".into(), true),
                                "apos" => (text, have_text) = ("'".into(), true),
                                "quot" => (text, have_text) = ("\"".into(), true),
                                _ => {
                                    if let Some(v) = self.entity.get(&s) {
                                        (text, have_text) = (v.clone(), true);
                                    }
                                }
                            }
                        }
                    }
                }

                if have_text {
                    self.buf.truncate(before);
                    self.buf.extend_from_slice(text.as_bytes());
                    b0 = 0;
                    b1 = 0;
                    if !self.check_buf() {
                        return None;
                    }
                    continue 'input;
                }
                if !self.strict {
                    b0 = 0;
                    b1 = 0;
                    continue 'input;
                }
                let mut ent = lossy(&self.buf[before..]);
                if !ent.ends_with(';') {
                    ent.push_str(" (no semicolon)");
                }
                self.err = Some(self.syntax_error(&format!("invalid character entity {ent}")));
                return None;
            }

            // We must rewrite unescaped \r and \r\n into \n.
            if b == b'\r' {
                self.buf.push(b'\n');
            } else if b1 == b'\r' && b == b'\n' {
                // Skip \r\n--we already wrote \n.
            } else {
                self.buf.push(b);
            }

            b0 = b1;
            b1 = b;
            if !self.check_buf() {
                return None;
            }
        }
        let n = self.buf.len() - trunc;
        let data = self.buf[..n].to_vec();

        // Inspect each rune for being a disallowed character.
        let mut rest = &data[..];
        while !rest.is_empty() {
            let (r, size) = rune::decode_rune(rest);
            if r == 0xFFFD && size == 1 {
                self.err = Some(self.syntax_error("invalid UTF-8"));
                return None;
            }
            rest = &rest[size..];
            if !is_in_character_range(r) {
                self.err = Some(self.syntax_error(&format!("illegal character code U+{r:04X}")));
                return None;
            }
        }
        Some(data)
    }

    /// Gets a name space name: a name with a `:` stuck in the middle.
    fn nsname(&mut self) -> Option<Name> {
        let s = self.name()?;
        if s.matches(':').count() > 1 {
            return None;
        }
        Some(match s.split_once(':') {
            Some((space, local)) if !space.is_empty() && !local.is_empty() => Name {
                space: space.to_string(),
                local: local.to_string(),
            },
            _ => Name {
                space: String::new(),
                local: s,
            },
        })
    }

    /// Gets a name. Does not set `err` if the name is missing (unless unexpected
    /// EOF is received): the caller provides better context.
    fn name(&mut self) -> Option<String> {
        self.buf.clear();
        if !self.read_name() {
            return None;
        }
        // Now we check the characters.
        if !is_name(&self.buf) {
            // Go prints the raw bytes; invalid ones appear as U+FFFD here.
            let text = lossy(&self.buf);
            self.err = Some(self.syntax_error(&format!("invalid XML name: {text}")));
            return None;
        }
        Some(String::from_utf8_lossy(&self.buf).into_owned())
    }

    /// Reads a name and appends its bytes to `buf`. The name is delimited by any
    /// single-byte character not valid in names; multi-byte characters are
    /// accepted here and validated by the caller.
    fn read_name(&mut self) -> bool {
        let Some(b) = self.mustgetc() else {
            return false;
        };
        if b < 0x80 && !is_name_byte(b) {
            self.ungetc(b);
            return false;
        }
        self.buf.push(b);
        loop {
            let Some(b) = self.mustgetc() else {
                return false;
            };
            if b < 0x80 && !is_name_byte(b) {
                self.ungetc(b);
                break;
            }
            self.buf.push(b);
            if !self.check_buf() {
                return false;
            }
        }
        true
    }
}

impl TokenReader for Decoder<'_> {
    fn token(&mut self) -> Result<Token, Error> {
        Decoder::token(self)
    }
}

fn is_name_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b':' || c == b'.' || c == b'-'
}

/// Parses the `param="..."` or `param='...'` value out of `s`, returning empty
/// if not found (Go `procInst`, including its quirks).
fn proc_inst(param: &[u8], s: &[u8]) -> Vec<u8> {
    let mut p = param.to_vec();
    p.push(b'=');
    let lenp = p.len();
    let mut i = 0;
    let mut sep = 0u8;
    while i < s.len() {
        let sub = &s[i..];
        let Some(k) = find(sub, &p) else {
            return Vec::new();
        };
        if lenp + k >= sub.len() {
            return Vec::new();
        }
        i += lenp + k + 1;
        let c = sub[lenp + k];
        if c == b'\'' || c == b'"' {
            sep = c;
            break;
        }
    }
    if sep == 0 {
        return Vec::new();
    }
    match s[i..].iter().position(|c| *c == sep) {
        Some(j) => s[i..i + j].to_vec(),
        None => Vec::new(),
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}
