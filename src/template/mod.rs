//! Bounded text and context-aware HTML interpolation.
//!
//! Grammar: `{{name}}`, where a name contains ASCII letters, digits, `_`, or
//! `.` and starts with a letter or `_`. Values are explicit string map entries;
//! missing values are errors. Template source is trusted application code.
//! HTML interpolation supports text, RCDATA, quoted ordinary attributes, and
//! quoted URL attributes. Substitutions into tag names, comments, unquoted
//! attributes, event handlers, CSS/JavaScript code, srcdoc, srcset and foreign
//! contexts are rejected. Static unquoted attributes remain valid. No value
//! can opt out of escaping. This deliberately bounded
//! basic interpolation grammar uses no functions. [`TextTemplate`] and
//! [`HtmlTemplate`] add conditionals, ranges, nested JSON value contexts,
//! typed first-party functions and explicitly registered trusted functions.
//! Script interpolation is permitted inside ordinary quoted JavaScript strings
//! when the source has no regex/division/template-literal ambiguity. CSS
//! interpolation is supported inside quoted `content:` property values.
//! URL/function strings, code positions, comments and incomplete escapes fail.
//!
//! URL values allow HTTP(S), mailto, tel, and relative references. Composed
//! values are checked before escaping, including static template fragments.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Write};

pub mod expression;
pub mod text;
pub use expression::{Function, Functions};
pub use text::{HtmlTemplate, TextTemplate};

pub type Values = BTreeMap<String, String>;

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub source_bytes: usize,
    pub fields: usize,
    pub output_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            source_bytes: 1 << 20,
            fields: 4096,
            output_bytes: 8 << 20,
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Syntax(String),
    Missing(String),
    UnsupportedContext(String),
    UnsafeUrl,
    Limit(&'static str),
    Io(io::Error),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(s) => write!(f, "template syntax: {s}"),
            Self::Missing(s) => write!(f, "missing template value: {s}"),
            Self::UnsupportedContext(s) => write!(f, "unsupported template context: {s}"),
            Self::UnsafeUrl => f.write_str("unsafe template URL"),
            Self::Limit(s) => write!(f, "template limit exceeded: {s}"),
            Self::Io(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
enum Segment {
    Literal(String),
    Field(String),
}
#[derive(Debug, Clone)]
enum Node {
    Plain(String),
    Text(Vec<Segment>, bool),
    Attribute(Vec<Segment>, bool),
    Language(Vec<Segment>, bool),
}

#[derive(Debug, Clone)]
pub struct Template {
    nodes: Vec<Node>,
    limits: Limits,
}

impl Template {
    pub fn text(source: &str) -> Result<Self, Error> {
        Self::text_with_limits(source, Limits::default())
    }
    pub fn text_with_limits(source: &str, limits: Limits) -> Result<Self, Error> {
        check_source(source, limits)?;
        let mut count = 0;
        let segments = segments(source, &mut count, limits)?;
        Ok(Self {
            nodes: vec![Node::Text(segments, false)],
            limits,
        })
    }
    pub fn html(source: &str) -> Result<Self, Error> {
        Self::html_with_limits(source, Limits::default())
    }
    pub fn html_with_limits(source: &str, limits: Limits) -> Result<Self, Error> {
        check_source(source, limits)?;
        let mut parser = HtmlParser {
            source,
            position: 0,
            count: 0,
            limits,
            nodes: Vec::new(),
        };
        parser.parse()?;
        Ok(Self {
            nodes: parser.nodes,
            limits,
        })
    }
    /// Rendering completes validation before writing anything to the writer.
    pub fn render_to(&self, values: &Values, writer: &mut impl Write) -> Result<(), Error> {
        let result = self.render(values)?;
        writer.write_all(result.as_bytes()).map_err(Error::Io)
    }
    pub fn render(&self, values: &Values) -> Result<String, Error> {
        let mut output = String::new();
        for node in &self.nodes {
            match node {
                Node::Plain(s) => append(&mut output, s, self.limits.output_bytes)?,
                Node::Text(parts, escaped) => {
                    for part in parts {
                        match part {
                            Segment::Literal(s) => {
                                append(&mut output, s, self.limits.output_bytes)?
                            }
                            Segment::Field(name) => {
                                let value = values
                                    .get(name)
                                    .ok_or_else(|| Error::Missing(name.clone()))?;
                                if *escaped {
                                    append_html(&mut output, value, self.limits.output_bytes)?;
                                } else {
                                    append(&mut output, value, self.limits.output_bytes)?;
                                }
                            }
                        }
                    }
                }
                Node::Attribute(parts, url) => {
                    if *url {
                        let mut raw = String::new();
                        for part in parts {
                            let value = match part {
                                Segment::Literal(s) => s,
                                Segment::Field(name) => values
                                    .get(name)
                                    .ok_or_else(|| Error::Missing(name.clone()))?,
                            };
                            append(&mut raw, value, self.limits.output_bytes)?;
                        }
                        validate_url(&raw)?;
                    }
                    for part in parts {
                        match part {
                            Segment::Literal(s) => {
                                append(&mut output, s, self.limits.output_bytes)?
                            }
                            Segment::Field(name) => append_html(
                                &mut output,
                                values
                                    .get(name)
                                    .ok_or_else(|| Error::Missing(name.clone()))?,
                                self.limits.output_bytes,
                            )?,
                        }
                    }
                }
                Node::Language(parts, css) => {
                    for part in parts {
                        match part {
                            Segment::Literal(s) => {
                                append(&mut output, s, self.limits.output_bytes)?
                            }
                            Segment::Field(name) => {
                                let value = values
                                    .get(name)
                                    .ok_or_else(|| Error::Missing(name.clone()))?;
                                if value.len()
                                    > self.limits.output_bytes.saturating_sub(output.len())
                                {
                                    return Err(Error::Limit("output bytes"));
                                }
                                let quoted = if *css {
                                    css_string(value)
                                } else {
                                    javascript_string(value).replace('\'', "\\u0027")
                                };
                                append(
                                    &mut output,
                                    &quoted[1..quoted.len() - 1],
                                    self.limits.output_bytes,
                                )?;
                            }
                        }
                    }
                }
            }
        }
        Ok(output)
    }
}

fn check_source(source: &str, limits: Limits) -> Result<(), Error> {
    if source.len() > limits.source_bytes {
        Err(Error::Limit("source bytes"))
    } else {
        Ok(())
    }
}
fn append(output: &mut String, value: &str, limit: usize) -> Result<(), Error> {
    if value.len() > limit.saturating_sub(output.len()) {
        return Err(Error::Limit("output bytes"));
    }
    output.push_str(value);
    Ok(())
}
fn append_html(output: &mut String, value: &str, limit: usize) -> Result<(), Error> {
    for c in value.chars() {
        match c {
            '&' => append(output, "&amp;", limit)?,
            '<' => append(output, "&lt;", limit)?,
            '>' => append(output, "&gt;", limit)?,
            '"' => append(output, "&#34;", limit)?,
            '\'' => append(output, "&#39;", limit)?,
            _ => {
                let mut buf = [0; 4];
                append(output, c.encode_utf8(&mut buf), limit)?;
            }
        }
    }
    Ok(())
}
fn segments(source: &str, count: &mut usize, limits: Limits) -> Result<Vec<Segment>, Error> {
    let mut result = Vec::new();
    let mut remaining = source;
    while let Some(start) = remaining.find("{{") {
        if start > 0 {
            result.push(Segment::Literal(remaining[..start].to_string()));
        }
        let end = remaining[start + 2..]
            .find("}}")
            .ok_or_else(|| Error::Syntax("unterminated field".into()))?
            + start
            + 2;
        let name = remaining[start + 2..end].trim();
        if !valid_name(name) {
            return Err(Error::Syntax("invalid field name".into()));
        }
        *count += 1;
        if *count > limits.fields {
            return Err(Error::Limit("fields"));
        }
        result.push(Segment::Field(name.to_string()));
        remaining = &remaining[end + 2..];
    }
    if !remaining.is_empty() {
        result.push(Segment::Literal(remaining.to_string()));
    }
    Ok(result)
}
fn valid_name(name: &str) -> bool {
    name.bytes()
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
}
fn has_field(s: &str) -> bool {
    s.contains("{{")
}
fn forbidden(s: &str, context: &str) -> Result<(), Error> {
    if has_field(s) {
        Err(Error::UnsupportedContext(context.to_string()))
    } else {
        Ok(())
    }
}
fn validate_url(value: &str) -> Result<(), Error> {
    if value.chars().any(|c| c.is_control() || c == '\\') {
        return Err(Error::UnsafeUrl);
    }
    let value = value.trim();
    let boundary = value.find(['/', '?', '#']).unwrap_or(value.len());
    let prefix = &value[..boundary];
    // Static entities could decode into a scheme separator inside the browser.
    if prefix.contains('&') {
        return Err(Error::UnsafeUrl);
    }
    if let Some(colon) = prefix.find(':') {
        let scheme = prefix[..colon].to_ascii_lowercase();
        if !matches!(scheme.as_str(), "http" | "https" | "mailto" | "tel") {
            return Err(Error::UnsafeUrl);
        }
    }
    Ok(())
}

struct HtmlParser<'a> {
    source: &'a str,
    position: usize,
    count: usize,
    limits: Limits,
    nodes: Vec<Node>,
}
impl HtmlParser<'_> {
    fn parse(&mut self) -> Result<(), Error> {
        while self.position < self.source.len() {
            let remaining = &self.source[self.position..];
            if remaining.starts_with("<!--") {
                let end = remaining
                    .find("-->")
                    .ok_or_else(|| Error::Syntax("unterminated comment".into()))?
                    + 3;
                forbidden(&remaining[..end], "comment")?;
                self.nodes.push(Node::Plain(remaining[..end].to_string()));
                self.position += end;
            } else if remaining.starts_with('<') {
                self.tag()?;
            } else {
                let length = remaining.find('<').unwrap_or(remaining.len());
                self.nodes.push(Node::Text(
                    segments(&remaining[..length], &mut self.count, self.limits)?,
                    true,
                ));
                self.position += length;
            }
        }
        Ok(())
    }
    fn tag(&mut self) -> Result<(), Error> {
        let start = self.position;
        let mut p = start + 1;
        let bytes = self.source.as_bytes();
        if bytes.get(p) == Some(&b'!') {
            let end = self.source[p..]
                .find('>')
                .ok_or_else(|| Error::Syntax("unterminated declaration".into()))?
                + p
                + 1;
            let declaration = &self.source[start..end];
            if !declaration.eq_ignore_ascii_case("<!doctype html>") {
                return Err(Error::UnsupportedContext("declaration".into()));
            }
            self.nodes.push(Node::Plain(declaration.to_string()));
            self.position = end;
            return Ok(());
        }
        let closing = bytes.get(p) == Some(&b'/');
        if closing {
            p += 1;
        }
        let name_start = p;
        while bytes
            .get(p)
            .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'-')
        {
            p += 1;
        }
        if name_start == p || !bytes[name_start].is_ascii_alphabetic() {
            return Err(Error::Syntax("invalid tag name".into()));
        }
        let name = self.source[name_start..p].to_ascii_lowercase();
        if matches!(
            name.as_str(),
            "svg" | "math" | "plaintext" | "xmp" | "iframe" | "noembed" | "noframes" | "noscript"
        ) {
            return Err(Error::UnsupportedContext(name));
        }
        let mut literal_start = start;
        let self_closing;
        loop {
            let before_space = p;
            while bytes.get(p).is_some_and(u8::is_ascii_whitespace) {
                p += 1;
            }
            if bytes.get(p) == Some(&b'>') {
                p += 1;
                self_closing = false;
                break;
            }
            if bytes.get(p) == Some(&b'/') && bytes.get(p + 1) == Some(&b'>') {
                p += 2;
                self_closing = true;
                break;
            }
            if closing || p == before_space {
                return Err(Error::Syntax("invalid tag boundary".into()));
            }
            let attr_start = p;
            while bytes
                .get(p)
                .is_some_and(|b| b.is_ascii_alphanumeric() || matches!(*b, b'-' | b'_' | b':'))
            {
                p += 1;
            }
            if attr_start == p {
                return Err(Error::Syntax("invalid attribute name".into()));
            }
            let attribute = self.source[attr_start..p].to_ascii_lowercase();
            let name_end = p;
            while bytes.get(p).is_some_and(u8::is_ascii_whitespace) {
                p += 1;
            }
            if bytes.get(p) != Some(&b'=') {
                p = name_end;
                continue;
            }
            p += 1;
            while bytes.get(p).is_some_and(u8::is_ascii_whitespace) {
                p += 1;
            }
            let quote = *bytes
                .get(p)
                .ok_or_else(|| Error::Syntax("missing attribute value".into()))?;
            if !matches!(quote, b'\'' | b'"') {
                let value_start = p;
                while bytes
                    .get(p)
                    .is_some_and(|b| !b.is_ascii_whitespace() && *b != b'>')
                {
                    p += 1;
                }
                forbidden(&self.source[value_start..p], "unquoted attribute")?;
                if self.source[value_start..p]
                    .bytes()
                    .any(|b| matches!(b, b'\'' | b'"' | b'<' | b'=' | b'`'))
                {
                    return Err(Error::Syntax("invalid unquoted value".into()));
                }
                if p == value_start {
                    return Err(Error::Syntax("missing attribute value".into()));
                }
                continue;
            }
            p += 1;
            let value_start = p;
            while bytes.get(p).is_some_and(|b| *b != quote) {
                p += 1;
            }
            if p == bytes.len() {
                return Err(Error::Syntax("unterminated attribute".into()));
            }
            let value = &self.source[value_start..p];
            if has_field(value) {
                if attribute.starts_with("on")
                    || (matches!(name.as_str(), "script" | "style")
                        && matches!(attribute.as_str(), "type" | "language"))
                    || matches!(
                        attribute.as_str(),
                        "style" | "srcdoc" | "srcset" | "imagesrcset" | "http-equiv" | "content"
                    )
                {
                    return Err(Error::UnsupportedContext(format!("attribute {attribute}")));
                }
                self.nodes.push(Node::Plain(
                    self.source[literal_start..value_start].to_string(),
                ));
                let url = matches!(
                    attribute.as_str(),
                    "href"
                        | "src"
                        | "action"
                        | "formaction"
                        | "poster"
                        | "cite"
                        | "background"
                        | "longdesc"
                        | "usemap"
                        | "manifest"
                        | "data"
                        | "codebase"
                        | "archive"
                        | "profile"
                        | "xlink:href"
                );
                self.nodes.push(Node::Attribute(
                    segments(value, &mut self.count, self.limits)?,
                    url,
                ));
                literal_start = p;
            }
            p += 1;
        }
        forbidden(&self.source[literal_start..p], "tag syntax")?;
        self.nodes
            .push(Node::Plain(self.source[literal_start..p].to_string()));
        self.position = p;
        if !closing && matches!(name.as_str(), "script" | "style" | "textarea" | "title") {
            // HTML ignores self-closing syntax for these elements.
            let _ = self_closing;
            let remaining = &self.source[p..];
            let lower = remaining.to_ascii_lowercase();
            let marker = format!("</{name}");
            let mut search = 0;
            let end = loop {
                let relative = lower[search..]
                    .find(&marker)
                    .ok_or_else(|| Error::Syntax(format!("unclosed {name}")))?;
                let candidate = search + relative;
                let boundary = lower.as_bytes().get(candidate + marker.len());
                if boundary.is_some_and(|b| b.is_ascii_whitespace() || matches!(*b, b'>' | b'/')) {
                    break candidate;
                }
                search = candidate + marker.len();
            };
            let content = &remaining[..end];
            if name == "script" {
                let lower = content.to_ascii_lowercase();
                if lower.contains("<!--") || lower.contains("<script") {
                    return Err(Error::UnsupportedContext("HTML script escape state".into()));
                }
            }
            if matches!(name.as_str(), "script" | "style") {
                self.nodes.extend(language_nodes(
                    content,
                    name == "style",
                    &mut self.count,
                    self.limits,
                )?);
            } else {
                self.nodes.push(Node::Text(
                    segments(content, &mut self.count, self.limits)?,
                    true,
                ));
            }
            self.position += end;
        }
        Ok(())
    }
}

// Dynamic language content is supported only inside ordinary quoted strings.
// Regex/division ambiguity, template literals, CSS functions and escapes in
// code are deliberately rejected for templates containing dynamic content.
fn language_nodes(
    source: &str,
    css: bool,
    count: &mut usize,
    limits: Limits,
) -> Result<Vec<Node>, Error> {
    if !has_field(source) {
        return Ok(vec![Node::Plain(source.to_string())]);
    }
    let bytes = source.as_bytes();
    let mut nodes = Vec::new();
    let mut p = 0;
    let mut literal = 0;
    let mut parentheses = 0usize;
    while p < bytes.len() {
        if source[p..].starts_with("{{") {
            return Err(Error::UnsupportedContext("language code".into()));
        }
        if bytes[p] == b'/' && bytes.get(p + 1) == Some(&b'*') {
            let end = source[p + 2..]
                .find("*/")
                .ok_or_else(|| Error::Syntax("unclosed language comment".into()))?
                + p
                + 4;
            forbidden(&source[p..end], "language comment")?;
            p = end;
            continue;
        }
        if !css && bytes[p] == b'/' && bytes.get(p + 1) == Some(&b'/') {
            let end = source[p..].find(['\n', '\r']).unwrap_or(source.len() - p) + p;
            forbidden(&source[p..end], "language comment")?;
            p = end;
            continue;
        }
        if matches!(bytes[p], b'/' | b'`' | b'\\') {
            return Err(Error::UnsupportedContext(
                "ambiguous language syntax".into(),
            ));
        }
        if css && bytes[p] == b'(' {
            parentheses += 1;
        }
        if css && bytes[p] == b')' {
            parentheses = parentheses
                .checked_sub(1)
                .ok_or_else(|| Error::Syntax("unbalanced CSS function".into()))?;
        }
        if matches!(bytes[p], b'\'' | b'"') {
            let quote = bytes[p];
            p += 1;
            let start = p;
            while p < bytes.len() && bytes[p] != quote {
                if bytes[p] == b'\\' {
                    if source[p + 1..].starts_with("{{") {
                        return Err(Error::UnsupportedContext(
                            "field after language escape".into(),
                        ));
                    }
                    p += 1;
                    if p >= bytes.len() {
                        return Err(Error::Syntax("unclosed language string".into()));
                    }
                }
                p += 1;
            }
            if p == bytes.len() {
                return Err(Error::Syntax("unclosed language string".into()));
            }
            if has_field(&source[start..p]) {
                if source[start..p].contains('\\') {
                    return Err(Error::UnsupportedContext(
                        "dynamic language string with static escape".into(),
                    ));
                }
                if css && parentheses != 0 {
                    return Err(Error::UnsupportedContext("CSS function string".into()));
                }
                if css {
                    let statement_start = source[..start - 1]
                        .rfind(['{', ';', '}'])
                        .map_or(0, |i| i + 1);
                    if !source[statement_start..start - 1]
                        .trim()
                        .eq_ignore_ascii_case("content:")
                    {
                        return Err(Error::UnsupportedContext(
                            "CSS string outside content property".into(),
                        ));
                    }
                }
                nodes.push(Node::Plain(source[literal..start].to_string()));
                nodes.push(Node::Language(
                    segments(&source[start..p], count, limits)?,
                    css,
                ));
                literal = p;
            }
        }
        p += 1;
        // Advance through a Unicode scalar before taking another string slice.
        while p < bytes.len() && !source.is_char_boundary(p) {
            p += 1;
        }
    }
    nodes.push(Node::Plain(source[literal..].to_string()));
    Ok(nodes)
}

/// A complete double-quoted JavaScript string literal; safe inside script text.
/// This does not turn arbitrary input into JavaScript source or expressions.
pub fn javascript_string(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if c.is_control() => {
                use fmt::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}
/// A complete quoted CSS string literal, including escapes for HTML delimiters.
/// Only suitable where a CSS string is required, never as a URL or stylesheet.
pub fn css_string(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        if c.is_control() || matches!(c, '"' | '\'' | '\\' | '<' | '>' | '&') {
            use fmt::Write;
            let _ = write!(out, "\\{:x} ", if c == '\0' { 0xfffd } else { c as u32 });
        } else {
            out.push(c);
        }
    }
    out.push('"');
    out
}
