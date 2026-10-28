//! Go's `text/scanner`: a scanner and tokenizer for UTF-8-encoded text.
//!
//! A [`Scanner`] reads from any [`std::io::Read`] and tokenizes it through
//! repeated calls to [`Scanner::scan`]. As in Go, the NUL character is not
//! allowed, and a leading byte order mark is discarded. By default a scanner
//! skips white space and Go comments and recognizes all literals of the Go
//! specification; [`Scanner::mode`] selects a subset.
//!
//! Token text is returned as bytes ([`Scanner::token_text`]) because Go
//! strings may hold invalid UTF-8, which the scanner reports as an error but
//! still includes in the token.
//!
//! ```
//! use rust_stdlib::text::scanner::{self, Scanner};
//!
//! let mut s = Scanner::default();
//! s.init("x := 0x1f // hex".as_bytes());
//! assert_eq!(s.scan(), scanner::IDENT);
//! assert_eq!(s.token_text(), b"x");
//! assert_eq!(s.scan(), ':' as i32);
//! assert_eq!(s.scan(), '=' as i32);
//! assert_eq!(s.scan(), scanner::INT);
//! assert_eq!(s.token_text(), b"0x1f");
//! assert_eq!(s.scan(), scanner::EOF);
//! ```

use crate::strconv::{quote, quote_rune};
use crate::unicode::is_digit;
use crate::unicode::is_letter;
use crate::unicode::rune::{append_rune, decode_rune, full_rune, RUNE_ERROR, RUNE_SELF, UTF_MAX};
use std::fmt;
use std::io::{self, ErrorKind, Read};
use std::rc::Rc;

/// Go's `Position`: a source position. A position is valid if `line > 0`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Position {
    /// Filename, if any. The scanner never changes it.
    pub filename: String,
    /// Byte offset, starting at 0.
    pub offset: usize,
    /// Line number, starting at 1.
    pub line: usize,
    /// Column number, starting at 1 (character count per line).
    pub column: usize,
}

impl Position {
    /// Reports whether the position is valid.
    pub fn is_valid(&self) -> bool {
        self.line > 0
    }
}

impl fmt::Display for Position {
    /// Formats as `filename:line:column`, using `<input>` when the filename
    /// is empty and omitting the line and column for an invalid position.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = if self.filename.is_empty() {
            "<input>"
        } else {
            self.filename.as_str()
        };
        f.write_str(name)?;
        if self.is_valid() {
            write!(f, ":{}:{}", self.line, self.column)?;
        }
        Ok(())
    }
}

/// Token for an identifier.
pub const IDENT: i32 = -2;
/// Token for an integer literal.
pub const INT: i32 = -3;
/// Token for a floating-point literal.
pub const FLOAT: i32 = -4;
/// Token for a character literal.
pub const CHAR: i32 = -5;
/// Token for an interpreted string literal.
pub const STRING: i32 = -6;
/// Token for a raw string literal.
pub const RAW_STRING: i32 = -7;
/// Token for a comment.
pub const COMMENT: i32 = -8;
/// Returned by [`Scanner::scan`] and [`Scanner::next`] at the end of the source.
pub const EOF: i32 = -1;

// Internal use only: a comment that is skipped as white space.
const SKIP_COMMENT: i32 = -9;

/// Mode bit: recognize identifiers.
pub const SCAN_IDENTS: usize = 1 << -IDENT;
/// Mode bit: recognize integers.
pub const SCAN_INTS: usize = 1 << -INT;
/// Mode bit: recognize floats, including integers and hexadecimal floats.
pub const SCAN_FLOATS: usize = 1 << -FLOAT;
/// Mode bit: recognize character literals.
pub const SCAN_CHARS: usize = 1 << -CHAR;
/// Mode bit: recognize interpreted string literals.
pub const SCAN_STRINGS: usize = 1 << -STRING;
/// Mode bit: recognize raw string literals.
pub const SCAN_RAW_STRINGS: usize = 1 << -RAW_STRING;
/// Mode bit: recognize comments.
pub const SCAN_COMMENTS: usize = 1 << -COMMENT;
/// Mode bit: with [`SCAN_COMMENTS`], comments become white space.
pub const SKIP_COMMENTS: usize = 1 << -SKIP_COMMENT;
/// Mode bits that accept all Go literal tokens, including identifiers.
/// Comments are skipped.
pub const DEFAULT_TOKENS: usize = SCAN_IDENTS
    | SCAN_FLOATS
    | SCAN_CHARS
    | SCAN_STRINGS
    | SCAN_RAW_STRINGS
    | SCAN_COMMENTS
    | SKIP_COMMENTS;

/// The default value of [`Scanner::whitespace`]: Go's white space characters.
pub const DEFAULT_WHITESPACE: u64 = (1 << b'\t') | (1 << b'\n') | (1 << b'\r') | (1 << b' ');

const BUF_LEN: usize = 1024; // at least UTF_MAX

/// Returns a printable string for a token or Unicode character.
pub fn token_string(tok: i32) -> String {
    match tok {
        EOF => "EOF".to_string(),
        IDENT => "Ident".to_string(),
        INT => "Int".to_string(),
        FLOAT => "Float".to_string(),
        CHAR => "Char".to_string(),
        STRING => "String".to_string(),
        RAW_STRING => "RawString".to_string(),
        COMMENT => "Comment".to_string(),
        _ => {
            let mut text = Vec::new();
            append_rune(&mut text, tok);
            quote(text)
        }
    }
}

/// Error callback type: receives the scanner and the error message. It is
/// shared, so a callback may replace or clear [`Scanner::error`] while it runs.
pub type ErrorFn<'a> = Rc<dyn Fn(&mut Scanner<'a>, &str) + 'a>;

/// Identifier predicate type: receives a character and its index in the identifier.
pub type IdentFn<'a> = Box<dyn Fn(i32, usize) -> bool + 'a>;

/// Reads Unicode characters and tokens from a [`Read`] source.
///
/// Create one with [`Scanner::default`] (Go's zero value) and call
/// [`Scanner::init`]. A scanner that was never initialized reads an empty
/// source.
pub struct Scanner<'a> {
    // Input
    src: Box<dyn Read + 'a>,

    // Source buffer (one extra byte is the sentinel for the common case of next).
    src_buf: Vec<u8>,
    src_pos: usize, // reading position (src_buf index)
    src_end: usize, // source end (src_buf index)

    // Source position
    src_buf_offset: usize, // byte offset of src_buf[0] in source
    line: usize,           // line count
    column: usize,         // character count
    last_line_len: usize,  // length of last line in characters
    last_char_len: usize,  // length of last character in bytes

    // Token text buffer: the head of the token text when it is no longer
    // in src_buf, and the tail positions in src_buf.
    tok_buf: Vec<u8>,
    tok_pos: isize, // token text tail position (src_buf index); -1 if none
    tok_end: isize, // token text tail end (src_buf index)

    // One character look-ahead
    ch: i32, // character before the current src_pos; -2 before the first read

    /// Called for each error encountered. If it is `None`, errors are
    /// written to standard error.
    pub error: Option<ErrorFn<'a>>,

    /// Incremented by one for each error encountered.
    pub error_count: usize,

    /// Controls which tokens are recognized. The field may be changed at any time.
    pub mode: usize,

    /// Controls which characters are white space: bit `ch` (for `ch <= ' '`)
    /// selects character `ch`. The field may be changed at any time.
    pub whitespace: u64,

    /// Predicate for the characters accepted as the `i`th rune of an
    /// identifier. If it is `None`, Go's identifier rules apply.
    pub is_ident_rune: Option<IdentFn<'a>>,

    /// Start position of the most recently scanned token, set by
    /// [`Scanner::scan`]. Calling [`Scanner::init`] or [`Scanner::next`]
    /// invalidates it (`line == 0`). The filename is never changed.
    pub position: Position,
}

impl Default for Scanner<'_> {
    /// Go's zero value: no source (reads as empty), mode 0 and no white space.
    fn default() -> Self {
        Scanner {
            src: Box::new(io::empty()),
            src_buf: vec![0; BUF_LEN + 1],
            src_pos: 0,
            src_end: 0,
            src_buf_offset: 0,
            line: 0,
            column: 0,
            last_line_len: 0,
            last_char_len: 0,
            tok_buf: Vec::new(),
            tok_pos: -1,
            tok_end: -1,
            ch: -2,
            error: None,
            error_count: 0,
            mode: 0,
            whitespace: 0,
            is_ident_rune: None,
            position: Position::default(),
        }
    }
}

fn lower(ch: i32) -> i32 {
    ('a' as i32 - 'A' as i32) | ch // returns lower-case ch iff ch is ASCII letter
}

fn is_decimal(ch: i32) -> bool {
    ('0' as i32..='9' as i32).contains(&ch)
}

fn is_hex(ch: i32) -> bool {
    is_decimal(ch) || ('a' as i32..='f' as i32).contains(&lower(ch))
}

fn digit_val(ch: i32) -> i32 {
    if is_decimal(ch) {
        ch - '0' as i32
    } else if ('a' as i32..='f' as i32).contains(&lower(ch)) {
        lower(ch) - 'a' as i32 + 10
    } else {
        16 // larger than any legal digit val
    }
}

fn lit_name(prefix: i32) -> &'static str {
    match char::from_u32(prefix as u32) {
        Some('x') => "hexadecimal literal",
        Some('o') | Some('0') => "octal literal",
        Some('b') => "binary literal",
        _ => "decimal literal",
    }
}

/// Returns the index of the first invalid separator in `x`, or -1.
fn invalid_sep(x: &[u8]) -> isize {
    let mut x1 = ' ' as i32; // prefix char, we only care if it's 'x'
    let mut d = '.' as i32; // digit: '_', '0' (a digit), or '.' (anything else)
    let mut i = 0;

    // a prefix counts as a digit
    if x.len() >= 2 && x[0] == b'0' {
        x1 = lower(x[1] as i32);
        if x1 == 'x' as i32 || x1 == 'o' as i32 || x1 == 'b' as i32 {
            d = '0' as i32;
            i = 2;
        }
    }

    // mantissa and exponent
    while i < x.len() {
        let p = d; // previous digit
        d = x[i] as i32;
        if d == '_' as i32 {
            if p != '0' as i32 {
                return i as isize;
            }
        } else if is_decimal(d) || (x1 == 'x' as i32 && is_hex(d)) {
            d = '0' as i32;
        } else {
            if p == '_' as i32 {
                return i as isize - 1;
            }
            d = '.' as i32;
        }
        i += 1;
    }
    if d == '_' as i32 {
        return x.len() as isize - 1;
    }

    -1
}

impl<'a> Scanner<'a> {
    /// Initializes the scanner with a new source and returns it.
    ///
    /// The error callback is cleared, [`Scanner::error_count`] is set to 0,
    /// [`Scanner::mode`] is set to [`DEFAULT_TOKENS`] and [`Scanner::whitespace`]
    /// to [`DEFAULT_WHITESPACE`].
    pub fn init<R: Read + 'a>(&mut self, src: R) -> &mut Self {
        self.src = Box::new(src);

        // initialize source buffer
        // (the first read happens on the first character)
        self.src_buf[0] = RUNE_SELF as u8; // sentinel
        self.src_pos = 0;
        self.src_end = 0;

        // initialize source position
        self.src_buf_offset = 0;
        self.line = 1;
        self.column = 0;
        self.last_line_len = 0;
        self.last_char_len = 0;

        // initialize token text buffer
        self.tok_pos = -1;

        // initialize one character look-ahead
        self.ch = -2; // no char read yet, not EOF

        // initialize public fields
        self.error = None;
        self.error_count = 0;
        self.mode = DEFAULT_TOKENS;
        self.whitespace = DEFAULT_WHITESPACE;
        self.position.line = 0; // invalidate token position

        self
    }

    /// Reads one chunk into `src_buf[from..]`. `Err(None)` is end of source
    /// and `Err(Some(message))` is a read error. A read that returns no bytes
    /// is the end of the source, as with [`Read`] implementations in general.
    fn fill(&mut self, from: usize) -> Result<usize, Option<String>> {
        loop {
            match self.src.read(&mut self.src_buf[from..BUF_LEN]) {
                Ok(0) => return Err(None),
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(Some(e.to_string())),
            }
        }
    }

    /// Reads and returns the next Unicode character (Go's `next`).
    fn advance(&mut self) -> i32 {
        let mut ch = self.src_buf[self.src_pos] as i32;
        let mut width = 1;

        if ch >= RUNE_SELF {
            // uncommon case: not ASCII or not enough bytes
            while self.src_pos + UTF_MAX > self.src_end
                && !full_rune(&self.src_buf[self.src_pos..self.src_end])
            {
                // not enough bytes: read some more, but first save away token text if any
                if self.tok_pos >= 0 {
                    let (from, to) = (self.tok_pos as usize, self.src_pos);
                    self.tok_buf.extend_from_slice(&self.src_buf[from..to]);
                    self.tok_pos = 0;
                    // tok_end is set by scan
                }
                // move unread bytes to the beginning of the buffer
                self.src_buf.copy_within(self.src_pos..self.src_end, 0);
                self.src_buf_offset += self.src_pos;
                // read more bytes
                let i = self.src_end - self.src_pos;
                let fill = self.fill(i);
                self.src_pos = 0;
                match fill {
                    Ok(n) => {
                        self.src_end = i + n;
                        self.src_buf[self.src_end] = RUNE_SELF as u8; // sentinel
                    }
                    Err(err) => {
                        self.src_end = i;
                        self.src_buf[self.src_end] = RUNE_SELF as u8; // sentinel
                        if let Some(message) = err {
                            self.report(&message);
                        }
                        if self.src_end == 0 {
                            if self.last_char_len > 0 {
                                // previous character was not EOF
                                self.column += 1;
                            }
                            self.last_char_len = 0;
                            return EOF;
                        }
                        // The source has no more bytes now (end of source or a
                        // read error); decode what is buffered.
                        break;
                    }
                }
            }
            // at least one byte
            ch = self.src_buf[self.src_pos] as i32;
            if ch >= RUNE_SELF {
                // uncommon case: not ASCII
                let (r, w) = decode_rune(&self.src_buf[self.src_pos..self.src_end]);
                ch = r;
                width = w;
                if ch == RUNE_ERROR && width == 1 {
                    // advance for correct error position
                    self.src_pos += width;
                    self.last_char_len = width;
                    self.column += 1;
                    self.report("invalid UTF-8 encoding");
                    return ch;
                }
            }
        }

        // advance
        self.src_pos += width;
        self.last_char_len = width;
        self.column += 1;

        // special situations
        match ch {
            0 => {
                // for compatibility with other tools
                self.report("invalid character NUL");
            }
            10 => {
                self.line += 1;
                self.last_line_len = self.column;
                self.column = 0;
            }
            _ => {}
        }

        ch
    }

    /// Reads and returns the next character, or [`EOF`]. Read errors and
    /// invalid characters are reported to [`Scanner::error`], and
    /// [`Scanner::position`] is invalidated.
    ///
    /// Use [`Scanner::pos`] for the current position.
    #[allow(clippy::should_implement_trait)] // Go's name; Scanner is not an Iterator.
    pub fn next(&mut self) -> i32 {
        self.tok_pos = -1; // don't collect token text
        self.position.line = 0; // invalidate token position
        let ch = self.peek();
        if ch != EOF {
            self.ch = self.advance();
        }
        ch
    }

    /// Returns the next character in the source without advancing the
    /// scanner, or [`EOF`] at the end of the source.
    pub fn peek(&mut self) -> i32 {
        if self.ch == -2 {
            // this code is only run for the very first character
            self.ch = self.advance();
            if self.ch == 0xFEFF {
                self.ch = self.advance(); // ignore BOM
            }
        }
        self.ch
    }

    /// Reports an error: counts it, then calls [`Scanner::error`] or writes
    /// the message to standard error.
    fn report(&mut self, msg: &str) {
        self.tok_end = self.cur_end(); // make sure token text is terminated
        self.error_count += 1;
        if let Some(handler) = self.error.clone() {
            handler(self, msg);
            return;
        }
        let mut pos = self.position.clone();
        if !pos.is_valid() {
            pos = self.pos();
        }
        eprintln!("{pos}: {msg}");
    }

    fn cur_end(&self) -> isize {
        self.src_pos as isize - self.last_char_len as isize
    }

    fn is_ident(&self, ch: i32, i: usize) -> bool {
        match &self.is_ident_rune {
            Some(f) => ch != EOF && f(ch, i),
            None => ch == '_' as i32 || is_letter(ch) || (is_digit(ch) && i > 0),
        }
    }

    fn is_space(&self, ch: i32) -> bool {
        (0..64).contains(&ch) && (self.whitespace >> ch) & 1 != 0
    }

    fn scan_identifier(&mut self) -> i32 {
        // we know the zeroth rune is OK; start scanning at the next one
        let mut ch = self.advance();
        let mut i = 1;
        while self.is_ident(ch, i) {
            ch = self.advance();
            i += 1;
        }
        ch
    }

    /// Accepts `{ digit | '_' }` starting with `ch0`. For `base <= 10` it
    /// records the first digit >= base in `invalid` if `invalid == 0`.
    /// Returns the first character after the sequence and a bit set: bit 0
    /// is set if digits were present, bit 1 if `_` separators were present.
    fn digits(&mut self, ch0: i32, base: i32, invalid: &mut i32) -> (i32, i32) {
        let mut ch = ch0;
        let mut digsep = 0;
        if base <= 10 {
            let max = '0' as i32 + base;
            while is_decimal(ch) || ch == '_' as i32 {
                let ds = if ch == '_' as i32 {
                    2
                } else {
                    if ch >= max && *invalid == 0 {
                        *invalid = ch;
                    }
                    1
                };
                digsep |= ds;
                ch = self.advance();
            }
        } else {
            while is_hex(ch) || ch == '_' as i32 {
                let ds = if ch == '_' as i32 { 2 } else { 1 };
                digsep |= ds;
                ch = self.advance();
            }
        }
        (ch, digsep)
    }

    fn scan_number(&mut self, mut ch: i32, mut seen_dot: bool) -> (i32, i32) {
        let mut base = 10;
        let mut prefix = 0; // one of 0 (decimal), '0' (0-octal), 'x', 'o', or 'b'
        let mut digsep = 0; // bit 0: digit present, bit 1: '_' present
        let mut invalid = 0; // invalid digit in literal, or 0
        let mut tok = 0;
        let mut ds;

        // integer part
        if !seen_dot {
            tok = INT;
            if ch == '0' as i32 {
                ch = self.advance();
                match lower(ch) {
                    c if c == 'x' as i32 => {
                        ch = self.advance();
                        base = 16;
                        prefix = 'x' as i32;
                    }
                    c if c == 'o' as i32 => {
                        ch = self.advance();
                        base = 8;
                        prefix = 'o' as i32;
                    }
                    c if c == 'b' as i32 => {
                        ch = self.advance();
                        base = 2;
                        prefix = 'b' as i32;
                    }
                    _ => {
                        base = 8;
                        prefix = '0' as i32;
                        digsep = 1; // leading 0
                    }
                }
            }
            (ch, ds) = self.digits(ch, base, &mut invalid);
            digsep |= ds;
            if ch == '.' as i32 && self.mode & SCAN_FLOATS != 0 {
                ch = self.advance();
                seen_dot = true;
            }
        }

        // fractional part
        if seen_dot {
            tok = FLOAT;
            if prefix == 'o' as i32 || prefix == 'b' as i32 {
                self.report(&format!("invalid radix point in {}", lit_name(prefix)));
            }
            (ch, ds) = self.digits(ch, base, &mut invalid);
            digsep |= ds;
        }

        if digsep & 1 == 0 {
            self.report(&format!("{} has no digits", lit_name(prefix)));
        }

        // exponent
        let e = lower(ch);
        if (e == 'e' as i32 || e == 'p' as i32) && self.mode & SCAN_FLOATS != 0 {
            if e == 'e' as i32 && prefix != 0 && prefix != '0' as i32 {
                self.report(&format!(
                    "{} exponent requires decimal mantissa",
                    quote_rune(ch)
                ));
            } else if e == 'p' as i32 && prefix != 'x' as i32 {
                self.report(&format!(
                    "{} exponent requires hexadecimal mantissa",
                    quote_rune(ch)
                ));
            }
            ch = self.advance();
            tok = FLOAT;
            if ch == '+' as i32 || ch == '-' as i32 {
                ch = self.advance();
            }
            let mut unused = 0;
            (ch, ds) = self.digits(ch, 10, &mut unused);
            digsep |= ds;
            if ds & 1 == 0 {
                self.report("exponent has no digits");
            }
        } else if prefix == 'x' as i32 && tok == FLOAT {
            self.report("hexadecimal mantissa requires a 'p' exponent");
        }

        if tok == INT && invalid != 0 {
            self.report(&format!(
                "invalid digit {} in {}",
                quote_rune(invalid),
                lit_name(prefix)
            ));
        }

        if digsep & 2 != 0 {
            self.tok_end = self.cur_end(); // make sure token text is terminated
            if invalid_sep(&self.token_text()) >= 0 {
                self.report("'_' must separate successive digits");
            }
        }

        (tok, ch)
    }

    fn scan_digits(&mut self, mut ch: i32, base: i32, mut n: i32) -> i32 {
        while n > 0 && digit_val(ch) < base {
            ch = self.advance();
            n -= 1;
        }
        if n > 0 {
            self.report("invalid char escape");
        }
        ch
    }

    fn scan_escape(&mut self, quote: i32) -> i32 {
        let mut ch = self.advance(); // read character after '/'
        if ch == quote || matches!(ch, 0x61 | 0x62 | 0x66 | 0x6E | 0x72 | 0x74 | 0x76 | 0x5C) {
            // a b f n r t v \ and the quote: nothing to do
            ch = self.advance();
        } else if ('0' as i32..='7' as i32).contains(&ch) {
            ch = self.scan_digits(ch, 8, 3);
        } else if ch == 'x' as i32 {
            let next = self.advance();
            ch = self.scan_digits(next, 16, 2);
        } else if ch == 'u' as i32 {
            let next = self.advance();
            ch = self.scan_digits(next, 16, 4);
        } else if ch == 'U' as i32 {
            let next = self.advance();
            ch = self.scan_digits(next, 16, 8);
        } else {
            self.report("invalid char escape");
        }
        ch
    }

    /// Scans a string literal body and returns the number of characters in it.
    fn scan_string(&mut self, quote: i32) -> usize {
        let mut ch = self.advance(); // read character after quote
        let mut n = 0;
        while ch != quote {
            if ch == '\n' as i32 || ch < 0 {
                self.report("literal not terminated");
                return n;
            }
            ch = if ch == '\\' as i32 {
                self.scan_escape(quote)
            } else {
                self.advance()
            };
            n += 1;
        }
        n
    }

    fn scan_raw_string(&mut self) {
        let mut ch = self.advance(); // read character after '`'
        while ch != '`' as i32 {
            if ch < 0 {
                self.report("literal not terminated");
                return;
            }
            ch = self.advance();
        }
    }

    fn scan_char(&mut self) {
        if self.scan_string('\'' as i32) != 1 {
            self.report("invalid char literal");
        }
    }

    fn scan_comment(&mut self, ch: i32) -> i32 {
        // ch == '/' || ch == '*'
        if ch == '/' as i32 {
            // line comment
            let mut ch = self.advance(); // read character after "//"
            while ch != '\n' as i32 && ch >= 0 {
                ch = self.advance();
            }
            return ch;
        }

        // general comment
        let mut ch = self.advance(); // read character after "/*"
        loop {
            if ch < 0 {
                self.report("comment not terminated");
                break;
            }
            let ch0 = ch;
            ch = self.advance();
            if ch0 == '*' as i32 && ch == '/' as i32 {
                ch = self.advance();
                break;
            }
        }
        ch
    }

    /// Reads the next token or Unicode character from the source and returns
    /// it. It only recognizes the tokens whose [`Scanner::mode`] bit
    /// (`1 << -t`) is set. It returns [`EOF`] at the end of the source.
    pub fn scan(&mut self) -> i32 {
        let mut ch = self.peek();

        // reset token text position
        self.tok_pos = -1;
        self.position.line = 0;

        let tok = 'redo: loop {
            // skip white space
            while self.is_space(ch) {
                ch = self.advance();
            }

            // start collecting token text
            self.tok_buf.clear();
            self.tok_pos = self.cur_end();

            // set token position
            self.position.offset = self.src_buf_offset + self.tok_pos as usize;
            if self.column > 0 {
                // common case: last character was not a '\n'
                self.position.line = self.line;
                self.position.column = self.column;
            } else {
                // last character was a '\n'
                self.position.line = self.line - 1;
                self.position.column = self.last_line_len;
            }

            // determine token value
            let mut tok = ch;
            if self.is_ident(ch, 0) {
                if self.mode & SCAN_IDENTS != 0 {
                    tok = IDENT;
                    ch = self.scan_identifier();
                } else {
                    ch = self.advance();
                }
            } else if is_decimal(ch) {
                if self.mode & (SCAN_INTS | SCAN_FLOATS) != 0 {
                    (tok, ch) = self.scan_number(ch, false);
                } else {
                    ch = self.advance();
                }
            } else {
                match char::from_u32(ch as u32) {
                    _ if ch == EOF => {}
                    Some('"') => {
                        if self.mode & SCAN_STRINGS != 0 {
                            self.scan_string('"' as i32);
                            tok = STRING;
                        }
                        ch = self.advance();
                    }
                    Some('\'') => {
                        if self.mode & SCAN_CHARS != 0 {
                            self.scan_char();
                            tok = CHAR;
                        }
                        ch = self.advance();
                    }
                    Some('.') => {
                        ch = self.advance();
                        if is_decimal(ch) && self.mode & SCAN_FLOATS != 0 {
                            (tok, ch) = self.scan_number(ch, true);
                        }
                    }
                    Some('/') => {
                        ch = self.advance();
                        if (ch == '/' as i32 || ch == '*' as i32) && self.mode & SCAN_COMMENTS != 0
                        {
                            if self.mode & SKIP_COMMENTS != 0 {
                                self.tok_pos = -1; // don't collect token text
                                ch = self.scan_comment(ch);
                                continue 'redo;
                            }
                            ch = self.scan_comment(ch);
                            tok = COMMENT;
                        }
                    }
                    Some('`') => {
                        if self.mode & SCAN_RAW_STRINGS != 0 {
                            self.scan_raw_string();
                            tok = RAW_STRING;
                        }
                        ch = self.advance();
                    }
                    _ => {
                        ch = self.advance();
                    }
                }
            }
            break tok;
        };

        // end of token text
        self.tok_end = self.cur_end();

        self.ch = ch;
        tok
    }

    /// Returns the position of the character immediately after the character
    /// or token returned by the last call to [`Scanner::next`] or
    /// [`Scanner::scan`]. Use [`Scanner::position`] for the start position of
    /// the most recently scanned token.
    pub fn pos(&self) -> Position {
        let mut pos = Position {
            filename: self.position.filename.clone(),
            offset: self.src_buf_offset + self.src_pos - self.last_char_len,
            ..Position::default()
        };
        if self.column > 0 {
            // common case: last character was not a '\n'
            pos.line = self.line;
            pos.column = self.column;
        } else if self.last_line_len > 0 {
            // last character was a '\n'
            pos.line = self.line - 1;
            pos.column = self.last_line_len;
        } else {
            // at the beginning of the source
            pos.line = 1;
            pos.column = 1;
        }
        pos
    }

    /// Returns the bytes of the most recently scanned token. It is valid
    /// after calling [`Scanner::scan`] and in calls of the error callback.
    pub fn token_text(&mut self) -> Vec<u8> {
        if self.tok_pos < 0 {
            // no token text
            return Vec::new();
        }

        if self.tok_end < self.tok_pos {
            // if EOF was reached, tok_end may precede tok_pos
            self.tok_end = self.tok_pos;
        }
        // tok_end >= tok_pos
        let (from, to) = (self.tok_pos as usize, self.tok_end as usize);

        if self.tok_buf.is_empty() {
            // common case: the entire token text is still in src_buf
            return self.src_buf[from..to].to_vec();
        }

        // part of the token text was saved in tok_buf: save the rest there
        // as well and return its content
        self.tok_buf.extend_from_slice(&self.src_buf[from..to]);
        self.tok_pos = self.tok_end; // ensure idempotency of token_text
        self.tok_buf.clone()
    }
}
