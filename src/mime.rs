//! Bounded media type and disposition parameter codecs and RFC 2047 encoded words.
//!
//! [`MediaType`] implements RFC 2045 token/quoted-string syntax with explicit
//! budgets. Parameter names are case-insensitive, duplicates are rejected, and
//! quoted values accept printable UTF-8. Go's `ParseMediaType` and
//! `FormatMediaType`, which also handle RFC 2231 values, are
//! [`parse_media_type`] and [`format_media_type`]. The extension registry is
//! [`type_by_extension`], [`extensions_by_type`] and [`add_extension_type`].
//!
//! [`WordEncoder`] and [`WordDecoder`] follow Go's `mime.WordEncoder` and
//! `mime.WordDecoder`. Decoded text must be valid UTF-8: where Go returns raw
//! bytes for an encoded word that decodes to invalid UTF-8, this module
//! returns an error.
//!
//! ```
//! use rust_stdlib::mime::{WordDecoder, WordEncoder};
//! assert_eq!(WordEncoder::Q.encode("utf-8", "¡Hola, señor!"), "=?utf-8?q?=C2=A1Hola,_se=C3=B1or!?=");
//! let decoded = WordDecoder::new().decode_header("=?ISO-8859-1?Q?Andr=E9?= Pirard")?;
//! assert_eq!(decoded, "André Pirard");
//! # Ok::<(), rust_stdlib::mime::Error>(())
//! ```
mod mediatype;
mod types;

pub use mediatype::{format_media_type, parse_media_type};
pub use types::{add_extension_type, extensions_by_type, type_by_extension};

use crate::encoding::base64;
use std::{borrow::Cow, collections::BTreeMap, error, fmt};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error(pub Cow<'static, str>);

impl Error {
    /// An error with a fixed message.
    pub const fn new(message: &'static str) -> Error {
        Error(Cow::Borrowed(message))
    }
}

/// Go's `ErrInvalidMediaParameter`: the media type parsed, but a parameter did not.
pub const ERR_INVALID_MEDIA_PARAMETER: Error = Error::new("mime: invalid media parameter");
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl error::Error for Error {}
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_bytes: usize,
    pub max_parameters: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bytes: 8192,
            max_parameters: 64,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaType {
    pub essence: String,
    pub parameters: BTreeMap<String, String>,
}

pub(crate) fn token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_graphic() && !b"()<>@,;:\\\"/[]?=".contains(&b))
}
fn valid_primary(value: &str) -> bool {
    token(value)
        || value
            .split_once('/')
            .is_some_and(|(kind, subtype)| token(kind) && token(subtype))
}
/// Parse a token (or media type) followed by semicolon parameters.
pub fn parse_parameters(
    input: &str,
    limits: Limits,
) -> Result<(String, BTreeMap<String, String>), Error> {
    if input.len() > limits.max_bytes {
        return Err(Error::new("MIME byte limit exceeded"));
    }
    if input.chars().any(|c| c.is_control() && c != '\t') {
        return Err(Error::new("control character in MIME value"));
    }
    let bytes = input.as_bytes();
    let mut cursor = input.find(';').unwrap_or(input.len());
    let value = input[..cursor].trim_matches([' ', '\t']);
    if !valid_primary(value) {
        return Err(Error::new("invalid MIME value"));
    }
    let mut params = BTreeMap::new();
    while cursor < bytes.len() {
        cursor += 1;
        while bytes.get(cursor).is_some_and(|b| *b == b' ' || *b == b'\t') {
            cursor += 1;
        }
        let start = cursor;
        while bytes
            .get(cursor)
            .is_some_and(|b| *b != b'=' && *b != b';' && *b != b' ' && *b != b'\t')
        {
            cursor += 1;
        }
        let name = &input[start..cursor];
        if !token(name) || name.contains('*') {
            return Err(Error::new("invalid or unsupported extended MIME parameter"));
        }
        while bytes.get(cursor).is_some_and(|b| *b == b' ' || *b == b'\t') {
            cursor += 1;
        }
        if bytes.get(cursor) != Some(&b'=') {
            return Err(Error::new("missing MIME parameter equals"));
        }
        cursor += 1;
        while bytes.get(cursor).is_some_and(|b| *b == b' ' || *b == b'\t') {
            cursor += 1;
        }
        let parsed;
        if bytes.get(cursor) == Some(&b'"') {
            cursor += 1;
            let mut out = Vec::new();
            loop {
                let b = *bytes
                    .get(cursor)
                    .ok_or(Error::new("unterminated MIME quoted string"))?;
                cursor += 1;
                match b {
                    b'"' => break,
                    b'\\' => {
                        let escaped = *bytes
                            .get(cursor)
                            .ok_or(Error::new("truncated MIME quoted pair"))?;
                        cursor += 1;
                        if !escaped.is_ascii() {
                            return Err(Error::new("invalid MIME quoted pair"));
                        }
                        out.push(escaped);
                    }
                    _ => out.push(b),
                }
            }
            parsed = String::from_utf8(out).map_err(|_| Error::new("invalid MIME UTF-8"))?;
            if parsed.chars().any(|c| c.is_control()) {
                return Err(Error::new("control character in MIME parameter"));
            }
        } else {
            let start = cursor;
            while bytes
                .get(cursor)
                .is_some_and(|b| *b != b';' && *b != b' ' && *b != b'\t')
            {
                cursor += 1;
            }
            parsed = input[start..cursor].to_owned();
            if !token(&parsed) {
                return Err(Error::new("invalid MIME parameter token"));
            }
        }
        while bytes.get(cursor).is_some_and(|b| *b == b' ' || *b == b'\t') {
            cursor += 1;
        }
        if cursor < bytes.len() && bytes[cursor] != b';' {
            return Err(Error::new("trailing MIME parameter data"));
        }
        if params.len() >= limits.max_parameters {
            return Err(Error::new("MIME parameter count limit exceeded"));
        }
        if params.insert(name.to_ascii_lowercase(), parsed).is_some() {
            return Err(Error::new("duplicate MIME parameter"));
        }
    }
    Ok((value.to_ascii_lowercase(), params))
}
/// Serialize parameters canonically, rejecting header injection.
pub fn format_parameters(
    value: &str,
    parameters: &BTreeMap<String, String>,
) -> Result<String, Error> {
    if !valid_primary(value) {
        return Err(Error::new("invalid MIME value"));
    }
    let mut out = value.to_ascii_lowercase();
    let mut seen = BTreeMap::new();
    for (name, value) in parameters {
        if !token(name)
            || name.contains('*')
            || seen.insert(name.to_ascii_lowercase(), ()).is_some()
        {
            return Err(Error::new("invalid or duplicate MIME parameter name"));
        }
        if value.chars().any(|c| c.is_control()) {
            return Err(Error::new("control character in MIME parameter"));
        }
        out.push_str("; ");
        out.push_str(&name.to_ascii_lowercase());
        out.push('=');
        if token(value) {
            out.push_str(value);
        } else {
            out.push('"');
            for c in value.chars() {
                if c == '\\' || c == '"' {
                    out.push('\\');
                }
                out.push(c);
            }
            out.push('"');
        }
    }
    Ok(out)
}
impl MediaType {
    pub fn parse(input: &str) -> Result<Self, Error> {
        Self::parse_with_limits(input, Limits::default())
    }
    pub fn parse_with_limits(input: &str, limits: Limits) -> Result<Self, Error> {
        let (essence, parameters) = parse_parameters(input, limits)?;
        let (kind, subtype) = essence
            .split_once('/')
            .ok_or(Error::new("media type requires type/subtype"))?;
        if !token(kind) || !token(subtype) {
            return Err(Error::new("invalid media type"));
        }
        Ok(Self {
            essence,
            parameters,
        })
    }
    pub fn encode(&self) -> Result<String, Error> {
        let encoded = format_parameters(&self.essence, &self.parameters)?;
        Self::parse_with_limits(
            &encoded,
            Limits {
                max_bytes: encoded.len(),
                max_parameters: self.parameters.len(),
            },
        )?;
        Ok(encoded)
    }
}
/// RFC 2047 encoded-word encoding scheme (Go `mime.BEncoding`/`mime.QEncoding`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WordEncoder {
    /// Base64 (`b`) encoding.
    B,
    /// Quoted-printable-like (`q`) encoding.
    Q,
}

/// Longest encoded word RFC 2047 allows, including delimiters.
const MAX_ENCODED_WORD_LEN: usize = 75;
/// Content budget of one word, measured against `=?UTF-8?q?` as Go does.
const MAX_CONTENT_LEN: usize = MAX_ENCODED_WORD_LEN - "=?UTF-8?q?".len() - "?=".len();
/// Input bytes whose padded base64 encoding fits in [`MAX_CONTENT_LEN`].
const MAX_BASE64_LEN: usize = MAX_CONTENT_LEN / 4 * 3;

impl WordEncoder {
    fn letter(self) -> char {
        match self {
            Self::B => 'b',
            Self::Q => 'q',
        }
    }

    /// Encode `s` as encoded words when it contains characters outside
    /// printable ASCII and tab; otherwise return it unchanged. With a UTF-8
    /// charset, long text is split into space-separated words of at most 75
    /// bytes without splitting a character, exactly as Go does.
    pub fn encode(self, charset: &str, s: &str) -> String {
        if !s.chars().any(|c| !(' '..='~').contains(&c) && c != '\t') {
            return s.to_owned();
        }
        let mut out = String::with_capacity(48);
        self.open_word(&mut out, charset);
        match self {
            Self::B => self.b_encode(&mut out, charset, s),
            Self::Q => self.q_encode(&mut out, charset, s),
        }
        out.push_str("?=");
        out
    }

    fn open_word(self, out: &mut String, charset: &str) {
        out.push_str("=?");
        out.push_str(charset);
        out.push('?');
        out.push(self.letter());
        out.push('?');
    }

    fn split_word(self, out: &mut String, charset: &str) {
        out.push_str("?= ");
        self.open_word(out, charset);
    }

    fn b_encode(self, out: &mut String, charset: &str, s: &str) {
        if !is_utf8_charset(charset) || base64::STANDARD.encoded_len(s.len()) <= MAX_CONTENT_LEN {
            out.push_str(&base64::STANDARD.encode(s.as_bytes()));
            return;
        }
        let (mut current, mut last) = (0, 0);
        for (i, c) in s.char_indices() {
            let len = c.len_utf8();
            if current + len <= MAX_BASE64_LEN {
                current += len;
            } else {
                out.push_str(&base64::STANDARD.encode(&s.as_bytes()[last..i]));
                self.split_word(out, charset);
                last = i;
                current = len;
            }
        }
        out.push_str(&base64::STANDARD.encode(&s.as_bytes()[last..]));
    }

    fn q_encode(self, out: &mut String, charset: &str, s: &str) {
        if !is_utf8_charset(charset) {
            write_q_string(out, s.as_bytes());
            return;
        }
        let mut current = 0;
        for c in s.chars() {
            let encoded_len = if (' '..='~').contains(&c) && !matches!(c, '=' | '?' | '_') {
                1
            } else {
                3 * c.len_utf8()
            };
            if current + encoded_len > MAX_CONTENT_LEN {
                self.split_word(out, charset);
                current = 0;
            }
            let mut buf = [0; 4];
            write_q_string(out, c.encode_utf8(&mut buf).as_bytes());
            current += encoded_len;
        }
    }
}

fn write_q_string(out: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &b in bytes {
        match b {
            b' ' => out.push('_'),
            b'!'..=b'~' if !matches!(b, b'=' | b'?' | b'_') => out.push(char::from(b)),
            _ => {
                out.push('=');
                out.push(char::from(HEX[usize::from(b >> 4)]));
                out.push(char::from(HEX[usize::from(b & 15)]));
            }
        }
    }
}

/// Compare a charset label with a lowercase ASCII name using Go's
/// `strings.EqualFold`. Besides ASCII case, Unicode simple folding maps
/// U+017F (long s) to `s` and U+212A (Kelvin sign) to `k`.
fn charset_is(label: &str, name: &str) -> bool {
    let mut expected = name.chars();
    for c in label.chars() {
        let folded = match c {
            '\u{17f}' => 's',
            '\u{212a}' => 'k',
            other => other.to_ascii_lowercase(),
        };
        if expected.next() != Some(folded) {
            return false;
        }
    }
    expected.next().is_none()
}

fn is_utf8_charset(charset: &str) -> bool {
    charset_is(charset, "utf-8")
}

/// Converts decoded bytes in a charset other than UTF-8, ISO-8859-1 and
/// US-ASCII to text. It receives the lowercased charset label.
pub type CharsetReader = dyn Fn(&str, &[u8]) -> Result<String, Error> + Send + Sync;

/// RFC 2047 encoded-word decoder (Go `mime.WordDecoder`).
///
/// UTF-8, ISO-8859-1 and US-ASCII are built in; other charsets go to the
/// optional [`CharsetReader`] hook and are an error without one.
pub struct WordDecoder {
    charset_reader: Option<Box<CharsetReader>>,
    max_bytes: usize,
}

impl Default for WordDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for WordDecoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WordDecoder")
            .field("charset_reader", &self.charset_reader.is_some())
            .field("max_bytes", &self.max_bytes)
            .finish()
    }
}

/// Why a single encoded word failed to decode.
pub(crate) enum WordError {
    /// Not a well-formed encoded word, or bad B/Q content.
    Invalid,
    /// The charset is unsupported or its reader failed.
    Charset(Error),
}

const INVALID_WORD: Error = Error::new("mime: invalid RFC 2047 encoded-word");

impl WordDecoder {
    /// A decoder with built-in charsets only and a 1 MiB input budget.
    pub fn new() -> Self {
        Self {
            charset_reader: None,
            max_bytes: 1 << 20,
        }
    }

    /// Install a converter for charsets other than UTF-8, ISO-8859-1 and US-ASCII.
    pub fn with_charset_reader(
        mut self,
        reader: impl Fn(&str, &[u8]) -> Result<String, Error> + Send + Sync + 'static,
    ) -> Self {
        self.charset_reader = Some(Box::new(reader));
        self
    }

    /// Set the largest word or header accepted by [`decode`](Self::decode)
    /// and [`decode_header`](Self::decode_header).
    pub fn with_max_bytes(mut self, max_bytes: usize) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    /// Decode one encoded word such as `=?utf-8?q?caf=C3=A9?=`.
    pub fn decode(&self, word: &str) -> Result<String, Error> {
        if word.len() > self.max_bytes {
            return Err(Error::new("mime: encoded-word byte limit exceeded"));
        }
        let bytes = self.decode_word(word).map_err(|error| match error {
            WordError::Invalid => INVALID_WORD,
            WordError::Charset(error) => error,
        })?;
        String::from_utf8(bytes).map_err(|_| Error::new("mime: encoded-word is not valid UTF-8"))
    }

    /// Decode one word to bytes. UTF-8 content is not validated here so that
    /// callers concatenating adjacent words can validate the joined text.
    pub(crate) fn decode_word(&self, word: &str) -> Result<Vec<u8>, WordError> {
        if word.len() < 8
            || !word.starts_with("=?")
            || !word.ends_with("?=")
            || word.bytes().filter(|&b| b == b'?').count() != 4
        {
            return Err(WordError::Invalid);
        }
        let inner = &word[2..word.len() - 2];
        let (charset, text) = inner.split_once('?').unwrap_or((inner, ""));
        if charset.is_empty() {
            return Err(WordError::Invalid);
        }
        let (encoding, text) = text.split_once('?').unwrap_or((text, ""));
        if encoding.len() != 1 {
            return Err(WordError::Invalid);
        }
        let content =
            decode_content(encoding.as_bytes()[0], text.as_bytes()).ok_or(WordError::Invalid)?;
        let mut out = Vec::with_capacity(content.len());
        self.convert(&mut out, charset, &content)
            .map_err(WordError::Charset)?;
        Ok(out)
    }

    /// Decode every encoded word in a header value, dropping whitespace
    /// between adjacent encoded words and keeping malformed words verbatim.
    pub fn decode_header(&self, header: &str) -> Result<String, Error> {
        if header.len() > self.max_bytes {
            return Err(Error::new("mime: header byte limit exceeded"));
        }
        let Some(first) = header.find("=?") else {
            return Ok(header.to_owned());
        };
        let mut out = header.as_bytes()[..first].to_vec();
        let mut rest = &header.as_bytes()[first..];
        let mut between_words = false;
        while let Some(start) = find(rest, b"=?") {
            let mut cur = start + 2;
            let Some(i) = rest[cur..].iter().position(|&b| b == b'?') else {
                break;
            };
            let charset = &rest[cur..cur + i];
            cur += i + 1;
            if rest.len() < cur + "Q??=".len() {
                break;
            }
            let encoding = rest[cur];
            cur += 1;
            if rest[cur] != b'?' {
                break;
            }
            cur += 1;
            let Some(j) = find(&rest[cur..], b"?=") else {
                break;
            };
            let end = cur + j + 2;
            let Some(content) = decode_content(encoding, &rest[cur..cur + j]) else {
                between_words = false;
                out.extend_from_slice(&rest[..end]);
                rest = &rest[end..];
                continue;
            };
            if start > 0
                && (!between_words
                    || rest[..start]
                        .iter()
                        .any(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r')))
            {
                out.extend_from_slice(&rest[..start]);
            }
            // The charset lies between ASCII delimiters of a &str, so it is
            // valid UTF-8; the lossy view never substitutes anything.
            self.convert(&mut out, &String::from_utf8_lossy(charset), &content)?;
            rest = &rest[end..];
            between_words = true;
        }
        out.extend_from_slice(rest);
        String::from_utf8(out).map_err(|_| Error::new("mime: decoded header is not valid UTF-8"))
    }

    fn convert(&self, out: &mut Vec<u8>, charset: &str, content: &[u8]) -> Result<(), Error> {
        if charset_is(charset, "utf-8") {
            out.extend_from_slice(content);
        } else if charset_is(charset, "iso-8859-1") {
            for &b in content {
                let mut buf = [0; 4];
                out.extend_from_slice(char::from(b).encode_utf8(&mut buf).as_bytes());
            }
        } else if charset_is(charset, "us-ascii") {
            for &b in content {
                if b.is_ascii() {
                    out.push(b);
                } else {
                    out.extend_from_slice("\u{fffd}".as_bytes());
                }
            }
        } else {
            let reader = self
                .charset_reader
                .as_ref()
                .ok_or(Error::new("mime: unhandled charset"))?;
            let lower: String = charset.chars().flat_map(char::to_lowercase).collect();
            out.extend_from_slice(reader(&lower, content)?.as_bytes());
        }
        Ok(())
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn decode_content(encoding: u8, text: &[u8]) -> Option<Vec<u8>> {
    match encoding {
        b'B' | b'b' => base64::STANDARD.decode(text).ok(),
        b'Q' | b'q' => q_decode(text),
        _ => None,
    }
}

fn q_decode(text: &[u8]) -> Option<Vec<u8>> {
    fn hex(b: u8) -> Option<u8> {
        char::from(b).to_digit(16).map(|d| d as u8)
    }
    let mut out = Vec::with_capacity(text.len());
    let mut i = 0;
    while i < text.len() {
        match text[i] {
            b'_' => out.push(b' '),
            b'=' => {
                if i + 2 >= text.len() {
                    return None;
                }
                out.push(hex(text[i + 1])? << 4 | hex(text[i + 2])?);
                i += 2;
            }
            c @ (b' '..=b'~' | b'\n' | b'\r' | b'\t') => out.push(c),
            _ => return None,
        }
        i += 1;
    }
    Some(out)
}
