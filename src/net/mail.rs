//! RFC 5322 mail messages, addresses and dates in the style of Go's `net/mail`.
//!
//! The parsers port Go's grammar and its documented divergences from RFC 5322:
//! obsolete route addresses and folded CFWS inside addresses are not parsed,
//! no Unicode normalization is applied, and a leading mbox `From ` line is
//! accepted as an ordinary field (its key keeps its spaces). Encoded words in
//! display names are decoded with [`mime::WordDecoder`](crate::mime::WordDecoder).
//!
//! Differences from Go, all explicit errors rather than silent changes:
//! - Names, header keys and values must be valid UTF-8. Go keeps raw bytes,
//!   including the result of an encoded word that decodes to invalid UTF-8.
//! - Dates are parsed by [`Time::parse`](crate::time::Time::parse) with Go's layouts
//!   and returned as [`Time`], so the whole range Go accepts (year 0, offsets
//!   up to `+2460`, ...) is held.
//! - Header blocks, address lists and dates have byte and count budgets.
//!
//! Zone abbreviations other than `UTC`, `UT` and `GMT±h` parse with a zero
//! offset, as Go does when its local zone does not define the abbreviation.
//!
//! ```
//! use rust_stdlib::net::mail;
//! let message = mail::read_message(&b"From: =?utf-8?q?J=C3=B6rg?= <j@example.com>\r\nDate: Mon, 02 Jan 2006 15:04:05 -0700\r\n\r\nHello"[..])?;
//! let from = message.header.address_list("From")?;
//! assert_eq!(from[0].name, "Jörg");
//! assert_eq!(from[0].to_string(), "=?utf-8?q?J=C3=B6rg?= <j@example.com>");
//! assert_eq!(message.header.date()?.unix(), 1136239445);
//! let mut body = String::new();
//! std::io::Read::read_to_string(&mut { message.body }, &mut body)?;
//! assert_eq!(body, "Hello");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
use crate::mime::{WordDecoder, WordEncoder, WordError};
use crate::net::textproto::{self, canonical_mime_header_key_bytes, Limits, MIMEHeader, Reader};
use crate::time::{self, Time};
use std::io::BufRead;
use std::{error, fmt};

/// Errors from mail parsing.
#[derive(Debug)]
pub enum Error {
    /// The requested header is absent or empty (Go `ErrHeaderNotPresent`).
    HeaderNotPresent,
    /// Malformed address, date or header syntax.
    Parse(String),
    /// A budget was exceeded.
    TooLarge(&'static str),
    /// The header block could not be read.
    Read(textproto::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeaderNotPresent => f.write_str("mail: header not in message"),
            Self::Parse(message) => f.write_str(message),
            Self::TooLarge(what) => write!(f, "mail: {what} exceeds its budget"),
            Self::Read(error) => error.fmt(f),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Read(error) => Some(error),
            _ => None,
        }
    }
}

impl From<textproto::Error> for Error {
    fn from(error: textproto::Error) -> Self {
        Self::Read(error)
    }
}

fn parse_error(message: impl Into<String>) -> Error {
    Error::Parse(message.into())
}

fn quote(bytes: &[u8]) -> String {
    format!("{:?}", String::from_utf8_lossy(bytes))
}

/// Mail header fields keyed by canonical name.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Header(MIMEHeader);

impl Header {
    pub fn new() -> Self {
        Self::default()
    }
    /// First value of the canonical form of `key`.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key)
    }
    /// All values of the canonical form of `key`.
    pub fn values(&self, key: &str) -> &[String] {
        self.0.values(key)
    }
    pub fn iter(&self) -> impl Iterator<Item = (&str, &[String])> {
        self.0.iter()
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn as_mime_header(&self) -> &MIMEHeader {
        &self.0
    }
    fn present(&self, key: &str) -> Result<&str, Error> {
        match self.get(key) {
            None | Some("") => Err(Error::HeaderNotPresent),
            Some(value) => Ok(value),
        }
    }
    /// Parse the `Date` field with [`parse_date`].
    pub fn date(&self) -> Result<Time, Error> {
        parse_date(self.present("Date")?)
    }
    /// Parse the named field with [`parse_address_list`].
    pub fn address_list(&self, key: &str) -> Result<Vec<Address>, Error> {
        parse_address_list(self.present(key)?)
    }
}

impl From<MIMEHeader> for Header {
    fn from(header: MIMEHeader) -> Self {
        Self(header)
    }
}

/// A parsed message: its header and a reader positioned at the body.
#[derive(Debug)]
pub struct Message<R> {
    pub header: Header,
    pub body: R,
}

/// Read a message header with default [`Limits`]; the body is the rest of `r`.
pub fn read_message<R: BufRead>(r: R) -> Result<Message<R>, Error> {
    read_message_with_limits(r, Limits::default())
}

/// Read a message header within `limits`. Lines use
/// [`Limits::max_line_bytes`]; [`Limits::max_headers`] bounds the field count
/// and [`Limits::max_header_bytes`] the summed key and value bytes. Unlike
/// [`textproto::Reader::read_mime_header`], field names are not validated (an
/// empty name is skipped), and input that ends before the blank line is
/// accepted when at least one field was read.
pub fn read_message_with_limits<R: BufRead>(r: R, limits: Limits) -> Result<Message<R>, Error> {
    let mut reader = Reader::with_limits(r, limits);
    let mut header = MIMEHeader::new();
    match read_header(&mut reader, &mut header, limits) {
        Ok(()) => {}
        Err(Error::Read(textproto::Error::Eof)) if !header.is_empty() => {}
        Err(error) => return Err(error),
    }
    Ok(Message {
        header: Header(header),
        body: reader.into_inner(),
    })
}

/// Port of Go's lenient RFC 5322 `readHeader`.
fn read_header<R: BufRead>(
    reader: &mut Reader<R>,
    header: &mut MIMEHeader,
    limits: Limits,
) -> Result<(), Error> {
    if matches!(reader.peek_byte()?, Some(b' ' | b'\t')) {
        let line = reader.read_line_bytes()?;
        return Err(parse_error(format!(
            "mail: malformed initial line: {}",
            quote(&line)
        )));
    }
    let (mut fields, mut bytes) = (0usize, 0usize);
    loop {
        let kv = reader.read_continued_line_bytes()?;
        if kv.is_empty() {
            return Ok(());
        }
        let colon = kv
            .iter()
            .position(|&b| b == b':')
            .ok_or_else(|| parse_error(format!("mail: malformed header line: {}", quote(&kv))))?;
        let key = canonical_mime_header_key_bytes(&kv[..colon]);
        if key.is_empty() {
            continue;
        }
        let value = &kv[colon + 1..];
        let value = &value[value
            .iter()
            .position(|&b| b != b' ' && b != b'\t')
            .unwrap_or(value.len())..];
        fields += 1;
        bytes = bytes.saturating_add(key.len() + value.len());
        if fields > limits.max_headers || bytes > limits.max_header_bytes {
            return Err(Error::Read(textproto::Error::MessageTooLarge));
        }
        let key = String::from_utf8(key).map_err(|_| textproto::Error::InvalidUtf8)?;
        let value = String::from_utf8(value.to_vec()).map_err(|_| textproto::Error::InvalidUtf8)?;
        header.push_raw(key, value);
    }
}

/// A mail address: an optional display name and an `addr-spec`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Address {
    /// Display name; may be empty.
    pub name: String,
    /// `local@domain`.
    pub address: String,
}

/// Formats the address as RFC 5322 text, as Go's `Address.String` does: the
/// local part is quoted when it is not a dot-atom, a printable ASCII name is
/// quoted, and other names become RFC 2047 encoded words (B encoding when
/// the name contains RFC 2047 specials, Q otherwise).
impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (local, domain) = match self.address.rfind('@') {
            Some(at) => (&self.address[..at], &self.address[at + 1..]),
            None => (self.address.as_str(), ""),
        };
        let bytes = local.as_bytes();
        let quote_local = local.char_indices().any(|(i, c)| {
            !(is_atext(c, false)
                || c == '.' && i > 0 && bytes[i - 1] != b'.' && i < local.len() - 1)
        });
        let address = if quote_local {
            format!("<{}@{domain}>", quote_string(local))
        } else {
            format!("<{local}@{domain}>")
        };
        if self.name.is_empty() {
            return f.write_str(&address);
        }
        let printable = self
            .name
            .chars()
            .all(|c| (is_vchar(c) || is_wsp(c)) && c.is_ascii());
        let name = if printable {
            quote_string(&self.name)
        } else if self
            .name
            .contains(|c| "\"#$%&'(),.:;<>@[]^`{|}~".contains(c))
        {
            WordEncoder::B.encode("utf-8", &self.name)
        } else {
            WordEncoder::Q.encode("utf-8", &self.name)
        };
        write!(f, "{name} {address}")
    }
}

/// Parse one address such as `Barry Gibbs <bg@example.com>`.
pub fn parse_address(address: &str) -> Result<Address, Error> {
    AddressParser::default().parse(address)
}

/// Parse a comma-separated address list, including groups.
pub fn parse_address_list(list: &str) -> Result<Vec<Address>, Error> {
    AddressParser::default().parse_list(list)
}

/// Address parser with a configurable encoded-word decoder and budgets
/// (Go `mail.AddressParser`).
#[derive(Debug)]
pub struct AddressParser {
    /// Decoder for RFC 2047 encoded words in display names. Charsets it does
    /// not support make the parse fail, as in Go.
    pub word_decoder: WordDecoder,
    /// Largest accepted input.
    pub max_bytes: usize,
    /// Most addresses returned by one list.
    pub max_addresses: usize,
}

impl Default for AddressParser {
    fn default() -> Self {
        Self {
            word_decoder: WordDecoder::new(),
            max_bytes: 1 << 20,
            max_addresses: 10_000,
        }
    }
}

impl AddressParser {
    fn parser<'a>(&'a self, input: &'a str) -> Result<Parser<'a>, Error> {
        if input.len() > self.max_bytes {
            return Err(Error::TooLarge("address input"));
        }
        Ok(Parser {
            s: input.as_bytes(),
            decoder: &self.word_decoder,
            remaining: self.max_addresses,
        })
    }
    /// Parse a single address.
    pub fn parse(&self, address: &str) -> Result<Address, Error> {
        self.parser(address)?.parse_single_address()
    }
    /// Parse a comma-separated list of addresses and groups.
    pub fn parse_list(&self, list: &str) -> Result<Vec<Address>, Error> {
        self.parser(list)?.parse_address_list()
    }
}

/// One step of Go's `utf8.DecodeRune`.
enum Rune {
    End,
    Invalid,
    Char(char, usize),
}

fn decode_rune(s: &[u8]) -> Rune {
    let width = match s.first() {
        None => return Rune::End,
        Some(0..=0x7f) => 1,
        Some(0xc2..=0xdf) => 2,
        Some(0xe0..=0xef) => 3,
        Some(0xf0..=0xf4) => 4,
        Some(_) => return Rune::Invalid,
    };
    match s.get(..width).map(std::str::from_utf8) {
        Some(Ok(text)) => text
            .chars()
            .next()
            .map_or(Rune::Invalid, |c| Rune::Char(c, width)),
        _ => Rune::Invalid,
    }
}

/// Go's `for _, r := range s`: invalid bytes become U+FFFD one at a time.
fn runes(mut s: &[u8]) -> impl Iterator<Item = char> + '_ {
    std::iter::from_fn(move || match decode_rune(s) {
        Rune::End => None,
        Rune::Invalid => {
            s = &s[1..];
            Some(char::REPLACEMENT_CHARACTER)
        }
        Rune::Char(c, width) => {
            s = &s[width..];
            Some(c)
        }
    })
}

fn is_vchar(c: char) -> bool {
    ('!'..='~').contains(&c) || !c.is_ascii()
}

fn is_wsp(c: char) -> bool {
    c == ' ' || c == '\t'
}

fn is_atext(c: char, dot: bool) -> bool {
    match c {
        '.' => dot,
        '(' | ')' | '<' | '>' | '[' | ']' | ':' | ';' | '@' | '\\' | ',' | '"' => false,
        _ => is_vchar(c),
    }
}

fn is_qtext(c: char) -> bool {
    c != '\\' && c != '"' && is_vchar(c)
}

fn is_dtext(c: char) -> bool {
    !matches!(c, '[' | ']' | '\\') && is_vchar(c)
}

/// Render `s` as an RFC 5322 quoted-string; characters that cannot appear
/// even escaped (controls) are dropped, as in Go.
fn quote_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        if is_qtext(c) || is_wsp(c) {
            out.push(c);
        } else if is_vchar(c) {
            out.push('\\');
            out.push(c);
        }
    }
    out.push('"');
    out
}

fn text(bytes: Vec<u8>, what: &str) -> Result<String, Error> {
    String::from_utf8(bytes).map_err(|_| parse_error(format!("mail: {what} is not valid UTF-8")))
}

/// Byte-oriented port of Go's `addrParser`.
struct Parser<'a> {
    s: &'a [u8],
    decoder: &'a WordDecoder,
    remaining: usize,
}

impl Parser<'_> {
    fn empty(&self) -> bool {
        self.s.is_empty()
    }
    fn peek(&self) -> Option<u8> {
        self.s.first().copied()
    }
    fn consume(&mut self, c: u8) -> bool {
        if self.peek() == Some(c) {
            self.s = &self.s[1..];
            true
        } else {
            false
        }
    }
    fn skip_space(&mut self) {
        let n = self
            .s
            .iter()
            .take_while(|&&b| b == b' ' || b == b'\t')
            .count();
        self.s = &self.s[n..];
    }
    /// Skip spaces and comments; false on an unterminated comment.
    fn skip_cfws(&mut self) -> bool {
        self.skip_space();
        while self.consume(b'(') {
            if self.consume_comment().is_none() {
                return false;
            }
            self.skip_space();
        }
        true
    }
    /// Consume a comment whose `(` was already consumed, returning its text.
    fn consume_comment(&mut self) -> Option<Vec<u8>> {
        let mut depth = 1usize;
        let mut comment = Vec::new();
        while !self.empty() && depth > 0 {
            match self.s[0] {
                b'\\' if self.s.len() > 1 => self.s = &self.s[1..],
                b'(' => depth += 1,
                b')' => depth -= 1,
                _ => {}
            }
            if depth > 0 {
                comment.push(self.s[0]);
            }
            self.s = &self.s[1..];
        }
        (depth == 0).then_some(comment)
    }

    fn take(&mut self, addresses: &mut Vec<Address>, more: Vec<Address>) -> Result<(), Error> {
        self.remaining = self
            .remaining
            .checked_sub(more.len())
            .ok_or(Error::TooLarge("address count"))?;
        addresses.extend(more);
        Ok(())
    }

    fn parse_address_list(&mut self) -> Result<Vec<Address>, Error> {
        let mut list = Vec::new();
        loop {
            self.skip_space();
            // Empty entries are allowed (RFC 5322 obs-addr-list).
            if self.consume(b',') {
                continue;
            }
            let addresses = self.parse_address(true)?;
            self.take(&mut list, addresses)?;
            if !self.skip_cfws() {
                return Err(parse_error("mail: misformatted parenthetical comment"));
            }
            if self.empty() {
                break;
            }
            if self.peek() != Some(b',') {
                return Err(parse_error("mail: expected comma"));
            }
            while self.consume(b',') {
                self.skip_space();
            }
            if self.empty() {
                break;
            }
        }
        Ok(list)
    }

    fn parse_single_address(&mut self) -> Result<Address, Error> {
        let mut addresses = self.parse_address(true)?;
        if !self.skip_cfws() {
            return Err(parse_error("mail: misformatted parenthetical comment"));
        }
        if !self.empty() {
            return Err(parse_error(format!(
                "mail: expected single address, got {}",
                quote(self.s)
            )));
        }
        match addresses.len() {
            0 => Err(parse_error("mail: empty group")),
            1 => Ok(addresses.remove(0)),
            _ => Err(parse_error("mail: group with multiple addresses")),
        }
    }

    fn parse_address(&mut self, handle_group: bool) -> Result<Vec<Address>, Error> {
        self.skip_space();
        if self.empty() {
            return Err(parse_error("mail: no address"));
        }
        // An addr-spec has a narrower grammar than name-addr; try it first.
        if let Ok(address) = self.consume_addr_spec() {
            self.skip_space();
            let mut name = String::new();
            if self.peek() == Some(b'(') {
                name = self.consume_display_name_comment()?;
            }
            return Ok(vec![Address { name, address }]);
        }
        let mut name = Vec::new();
        if self.peek() != Some(b'<') {
            name = self.consume_phrase()?;
        }
        self.skip_space();
        if handle_group && self.consume(b':') {
            return self.consume_group_list();
        }
        if !self.consume(b'<') {
            return Err(if runes(&name).all(|c| is_atext(c, true)) {
                // Like "foo.bar": perhaps meant "foo.bar@domain".
                parse_error("mail: missing '@' or angle-addr")
            } else {
                parse_error("mail: no angle-addr")
            });
        }
        let address = self.consume_addr_spec()?;
        if !self.consume(b'>') {
            return Err(parse_error("mail: unclosed angle-addr"));
        }
        Ok(vec![Address {
            name: text(name, "display name")?,
            address,
        }])
    }

    fn consume_group_list(&mut self) -> Result<Vec<Address>, Error> {
        let mut group = Vec::new();
        self.skip_space();
        if self.consume(b';') {
            if !self.skip_cfws() {
                return Err(parse_error("mail: misformatted parenthetical comment"));
            }
            return Ok(group);
        }
        loop {
            self.skip_space();
            // Groups do not nest.
            let addresses = self.parse_address(false)?;
            self.take(&mut group, addresses)?;
            if !self.skip_cfws() {
                return Err(parse_error("mail: misformatted parenthetical comment"));
            }
            if self.consume(b';') {
                if !self.skip_cfws() {
                    return Err(parse_error("mail: misformatted parenthetical comment"));
                }
                return Ok(group);
            }
            if !self.consume(b',') {
                return Err(parse_error("mail: expected comma"));
            }
        }
    }

    /// Parse an addr-spec, restoring the position on failure.
    fn consume_addr_spec(&mut self) -> Result<String, Error> {
        let saved = self.s;
        let result = self.consume_addr_spec_inner();
        if result.is_err() {
            self.s = saved;
        }
        result
    }

    fn consume_addr_spec_inner(&mut self) -> Result<String, Error> {
        self.skip_space();
        if self.empty() {
            return Err(parse_error("mail: no addr-spec"));
        }
        let local = if self.peek() == Some(b'"') {
            match self.consume_quoted_string() {
                Ok(local) if !local.is_empty() => local,
                _ => return Err(parse_error("mail: empty quoted string in addr-spec")),
            }
        } else {
            self.consume_atom(true, false)?
        };
        if !self.consume(b'@') {
            return Err(parse_error("mail: missing @ in addr-spec"));
        }
        self.skip_space();
        if self.empty() {
            return Err(parse_error("mail: no domain in addr-spec"));
        }
        let domain = if self.peek() == Some(b'[') {
            self.consume_domain_literal()?
        } else {
            self.consume_atom(true, false)?
        };
        Ok(format!("{local}@{domain}"))
    }

    /// Parse a phrase (display name) to bytes; encoded words are decoded and
    /// adjacent ones joined before the caller validates UTF-8.
    fn consume_phrase(&mut self) -> Result<Vec<u8>, Error> {
        let mut words: Vec<Vec<u8>> = Vec::new();
        let mut encoded: Vec<u8> = Vec::new();
        let mut failure = None;
        loop {
            // obs-phrase allows CFWS after the first word.
            if !words.is_empty() && !self.skip_cfws() {
                return Err(parse_error("mail: misformatted parenthetical comment"));
            }
            self.skip_space();
            if self.empty() {
                break;
            }
            let (word, is_encoded) = if self.peek() == Some(b'"') {
                match self.consume_quoted_string() {
                    Ok(word) => (word.into_bytes(), false),
                    Err(error) => {
                        failure = Some(error);
                        break;
                    }
                }
            } else {
                // Dot-atoms are accepted here, beyond RFC 5322's atom.
                let atom = match self.consume_atom(true, true) {
                    Ok(atom) => atom,
                    Err(error) => {
                        failure = Some(error);
                        break;
                    }
                };
                match self.decode_rfc2047_word(&atom) {
                    Ok(decoded) => decoded,
                    Err(error) => {
                        failure = Some(error);
                        break;
                    }
                }
            };
            if is_encoded {
                encoded.extend_from_slice(&word);
            } else {
                if !encoded.is_empty() {
                    words.push(std::mem::take(&mut encoded));
                }
                words.push(word);
            }
        }
        if !encoded.is_empty() {
            words.push(encoded);
        }
        // Errors are ignored once at least one word was read.
        if let (Some(error), true) = (failure, words.is_empty()) {
            return Err(parse_error(format!(
                "mail: missing word in phrase: {error}"
            )));
        }
        Ok(words.join(&b' '))
    }

    fn consume_quoted_string(&mut self) -> Result<String, Error> {
        // The opening quote is at s[0].
        let mut i = 1;
        let mut out = String::new();
        let mut escaped = false;
        loop {
            let (c, width) = match decode_rune(&self.s[i..]) {
                Rune::End => return Err(parse_error("mail: unclosed quoted-string")),
                Rune::Invalid => {
                    return Err(parse_error(format!(
                        "mail: invalid utf-8 in quoted-string: {}",
                        quote(self.s)
                    )))
                }
                Rune::Char(c, width) => (c, width),
            };
            if escaped {
                // quoted-pair = "\" (VCHAR / WSP)
                if !is_vchar(c) && !is_wsp(c) {
                    return Err(parse_error(format!(
                        "mail: bad character in quoted-string: {c:?}"
                    )));
                }
                out.push(c);
                escaped = false;
            } else if is_qtext(c) || is_wsp(c) {
                out.push(c);
            } else if c == '"' {
                break;
            } else if c == '\\' {
                escaped = true;
            } else {
                return Err(parse_error(format!(
                    "mail: bad character in quoted-string: {c:?}"
                )));
            }
            i += width;
        }
        self.s = &self.s[i + 1..];
        Ok(out)
    }

    /// Parse an atom, or a dot-atom when `dot` is set. `permissive` accepts
    /// leading, trailing and doubled dots.
    fn consume_atom(&mut self, dot: bool, permissive: bool) -> Result<String, Error> {
        let mut i = 0;
        loop {
            match decode_rune(&self.s[i..]) {
                Rune::Invalid => {
                    return Err(parse_error(format!(
                        "mail: invalid utf-8 in address: {}",
                        quote(self.s)
                    )))
                }
                Rune::Char(c, width) if is_atext(c, dot) => i += width,
                _ => break,
            }
        }
        if i == 0 {
            return Err(parse_error("mail: invalid string"));
        }
        let atom = text(self.s[..i].to_vec(), "atom")?;
        self.s = &self.s[i..];
        if !permissive {
            if atom.starts_with('.') {
                return Err(parse_error("mail: leading dot in atom"));
            }
            if atom.contains("..") {
                return Err(parse_error("mail: double dot in atom"));
            }
            if atom.ends_with('.') {
                return Err(parse_error("mail: trailing dot in atom"));
            }
        }
        Ok(atom)
    }

    fn consume_domain_literal(&mut self) -> Result<String, Error> {
        if !self.consume(b'[') {
            return Err(parse_error("mail: missing \"[\" in domain-literal"));
        }
        let start = self.s;
        let mut len = 0;
        loop {
            match decode_rune(self.s) {
                Rune::End => return Err(parse_error("mail: unclosed domain-literal")),
                Rune::Char(']', _) => break,
                Rune::Invalid => {
                    return Err(parse_error(format!(
                        "mail: invalid utf-8 in domain-literal: {}",
                        quote(self.s)
                    )))
                }
                Rune::Char(c, width) => {
                    if !is_dtext(c) {
                        return Err(parse_error(format!(
                            "mail: bad character in domain-literal: {c:?}"
                        )));
                    }
                    len += width;
                    self.s = &self.s[width..];
                }
            }
        }
        let dtext = text(start[..len].to_vec(), "domain-literal")?;
        self.consume(b']');
        let valid = match dtext.strip_prefix("IPv6:") {
            // Go's net.ParseIP yields 16 bytes for IPv4 too.
            Some(ip) => go_parse_ip(ip).is_some(),
            None => go_parse_ip(&dtext).is_some_and(|ip| ip.to_ipv4_mapped().is_some()),
        };
        if !valid {
            return Err(parse_error(format!(
                "mail: invalid IP address in domain-literal: {dtext:?}"
            )));
        }
        Ok(format!("[{dtext}]"))
    }

    fn consume_display_name_comment(&mut self) -> Result<String, Error> {
        if !self.consume(b'(') {
            return Err(parse_error("mail: comment does not start with ("));
        }
        let comment = self
            .consume_comment()
            .ok_or_else(|| parse_error("mail: misformatted parenthetical comment"))?;
        let mut words = Vec::new();
        for word in comment
            .split(|&b| b == b' ' || b == b'\t')
            .filter(|w| !w.is_empty())
        {
            let word = match std::str::from_utf8(word) {
                Ok(word) => self.decode_rfc2047_word(word)?.0,
                Err(_) => word.to_vec(),
            };
            words.push(word);
        }
        text(words.join(&b' '), "display name")
    }

    /// Decode `word` if it is an encoded word. Malformed encoded words stay
    /// as written; an unsupported charset is an error, as in Go.
    fn decode_rfc2047_word(&self, word: &str) -> Result<(Vec<u8>, bool), Error> {
        match self.decoder.decode_word(word) {
            Ok(decoded) => Ok((decoded, true)),
            Err(WordError::Invalid) => Ok((word.as_bytes().to_vec(), false)),
            Err(WordError::Charset(error)) => Err(parse_error(format!("mail: {error}"))),
        }
    }
}

/// Go's `net.ParseIP` in 16-byte form: IPv4 or IPv6 text without a zone.
fn go_parse_ip(text: &str) -> Option<std::net::Ipv6Addr> {
    if let Ok(v4) = text.parse::<std::net::Ipv4Addr>() {
        return Some(v4.to_ipv6_mapped());
    }
    text.parse().ok()
}

/// Largest date string accepted by [`parse_date`].
const MAX_DATE_BYTES: usize = 64 << 10;

/// Parse an RFC 5322 date as Go's `mail.ParseDate` does.
///
/// Accepted forms are `[Mon, ]D Jan YYYY hh:mm[:ss[.frac]] zone` with one- or
/// two-digit days and two- or four-digit years (two-digit years from 69 are
/// 19xx). The zone is `±hhmm`, an abbreviation (`UTC`, `UT`, `GMT`, `GMT±h`
/// or obsolete names such as `EST`, which get a zero offset), and may be
/// followed by spaces and comments. CRLF pairs are removed first; a lone CR
/// is an error.
pub fn parse_date(date: &str) -> Result<Time, Error> {
    if date.len() > MAX_DATE_BYTES {
        return Err(Error::TooLarge("date"));
    }
    let date = date.replace("\r\n", "");
    if date.contains('\r') {
        return Err(parse_error("mail: header has a CR without LF"));
    }
    let bytes = date.as_bytes();
    let trimmed = &bytes[bytes
        .iter()
        .position(|&b| b != b' ' && b != b'\t')
        .unwrap_or(bytes.len())..];
    // RFC 5322 zones are five characters ("+hhmm") unless obsolete; cut the
    // value after the zone and leave the rest for CFWS.
    let (mut value, mut rest) = (bytes, trimmed);
    match trimmed.iter().position(|&b| b == b'+' || b == b'-') {
        Some(ind) if trimmed.len() >= ind + 5 => {
            (value, rest) = trimmed.split_at(ind + 5);
        }
        _ => {
            // Obsolete zones end in T (EST, GMT, UT); skip a weekday T.
            let mut ind = trimmed.iter().position(|&b| b == b'T');
            if ind == Some(0) {
                ind = trimmed[1..].iter().position(|&b| b == b'T').map(|i| i + 1);
            }
            if let Some(ind) = ind.filter(|&ind| trimmed.len() >= ind + 5) {
                (value, rest) = trimmed.split_at(ind + 1);
            }
        }
    }
    let mut cfws = Parser {
        s: rest,
        decoder: &WordDecoder::new(),
        remaining: 0,
    };
    if !cfws.skip_cfws() {
        return Err(parse_error("mail: misformatted parenthetical comment"));
    }
    // `value` is ASCII or arbitrary bytes; time::parse takes text, and any
    // non-UTF-8 byte cannot match a layout element anyway.
    let value =
        std::str::from_utf8(value).map_err(|_| parse_error("mail: header could not be parsed"))?;
    date_layouts()
        .find_map(|layout| time::Time::parse(&layout, value).ok())
        .ok_or_else(|| parse_error("mail: header could not be parsed"))
}

/// Go's date layouts, in Go's order: weekday, day, year, seconds, then zone,
/// outermost first (`buildDateLayouts`).
fn date_layouts() -> impl Iterator<Item = String> {
    ["", "Mon, "].into_iter().flat_map(|dow| {
        ["2", "02"].into_iter().flat_map(move |day| {
            ["2006", "06"].into_iter().flat_map(move |year| {
                [":05", ""].into_iter().flat_map(move |seconds| {
                    ["-0700", "MST", "UT"]
                        .into_iter()
                        .map(move |zone| format!("{dow}{day} Jan {year} 15:04{seconds} {zone}"))
                })
            })
        })
    })
}
