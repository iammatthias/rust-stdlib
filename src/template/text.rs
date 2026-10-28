//! Structured text templates over the library's JSON value model.
//!
//! Actions: `{{path}}`, `{{if path}}...{{else}}...{{end}}`,
//! `{{range path}}...{{else}}...{{end}}`, and `{{with path}}...{{end}}`.
//! `.` is the current context; `$.name` refers to the root context. A range
//! visits array elements or object values in sorted key order. Conditions use
//! JSON truth: null, false, numeric zero, and empty collections/strings are
//! false. Missing paths and interpolated collections are errors. Nesting is
//! capped at 64 and each render at one million node visits/iterations.
//! Expressions support JSON scalar literals and pipelines, for example
//! `{{name | upper}}` or `{{if eq .name "Alice"}}...{{end}}`. Built-ins are
//! `len`, `upper`, `lower`, `eq`, `not`, `and`, `or`, `join`, and `index`.
//! Pipelines supply the preceding value as the last argument. `and`/`or` are
//! lazy and return the selected operand. Equality uses the JSON value model,
//! including exact numeric spelling. Register trusted Rust functions through
//! `functions_mut()`; a zero-argument call uses `{{name()}}`. Returned strings
//! always receive contextual escaping in HTML templates. Function definitions,
//! variables, parentheses and arbitrary Rust evaluation are unsupported.
//!
//! This is a text engine: outputs are unescaped and must not be used as HTML.

use super::expression::{self, Expression, Functions};
use super::{append, check_source, Error, Limits, Template, Values};
use crate::encoding::json::Value;
use std::io::Write;

#[derive(Debug, Clone)]
enum Node {
    Literal(String),
    Field(Expression),
    Block(Kind, Expression, Vec<Node>, Vec<Node>),
}
#[derive(Debug, Clone, Copy)]
enum Kind {
    If,
    Range,
    With,
}

#[derive(Debug, Clone)]
pub struct TextTemplate {
    nodes: Vec<Node>,
    limits: Limits,
    functions: Functions,
}

/// Structured HTML templates. Control-flow actions are permitted only between
/// complete HTML lexical contexts. Each fragment/branch must start and end in
/// ordinary HTML text, so branches cannot create tags, attributes or raw-text
/// contexts across an action boundary.
#[derive(Debug, Clone)]
pub struct HtmlTemplate {
    nodes: Vec<HtmlNode>,
    limits: Limits,
    functions: Functions,
}
#[derive(Debug, Clone)]
enum HtmlNode {
    Fragment(Template, Vec<(String, Expression)>),
    Block(Kind, Expression, Vec<HtmlNode>, Vec<HtmlNode>),
}
impl HtmlTemplate {
    pub fn parse(source: &str) -> Result<Self, Error> {
        Self::parse_with_limits(source, Limits::default())
    }
    pub fn parse_with_limits(source: &str, limits: Limits) -> Result<Self, Error> {
        let text = TextTemplate::parse_with_limits(source, limits)?;
        Ok(Self {
            nodes: compile_html(&text.nodes, limits)?,
            limits,
            functions: Functions::new(),
        })
    }
    pub fn functions_mut(&mut self) -> &mut Functions {
        &mut self.functions
    }
    pub fn render(&self, data: &Value) -> Result<String, Error> {
        let mut output = String::new();
        let mut remaining = 1_000_000;
        render_html(
            &self.nodes,
            data,
            data,
            &mut output,
            self.limits.output_bytes,
            &mut remaining,
            &self.functions,
        )?;
        Ok(output)
    }
    pub fn render_to(&self, data: &Value, writer: &mut impl Write) -> Result<(), Error> {
        writer
            .write_all(self.render(data)?.as_bytes())
            .map_err(Error::Io)
    }
}
fn compile_html(nodes: &[Node], limits: Limits) -> Result<Vec<HtmlNode>, Error> {
    let mut output = Vec::new();
    let mut source = String::new();
    let mut bindings = Vec::new();
    fn flush(
        output: &mut Vec<HtmlNode>,
        source: &mut String,
        bindings: &mut Vec<(String, Expression)>,
        limits: Limits,
    ) -> Result<(), Error> {
        if !source.is_empty() {
            output.push(HtmlNode::Fragment(
                Template::html_with_limits(source, limits)?,
                std::mem::take(bindings),
            ));
            source.clear();
        }
        Ok(())
    }
    for node in nodes {
        match node {
            Node::Literal(s) => source.push_str(s),
            Node::Field(path) => {
                let name = format!("field_{}", bindings.len());
                source.push_str(&format!("{{{{{name}}}}}"));
                bindings.push((name, path.clone()));
            }
            Node::Block(kind, path, body, fallback) => {
                flush(&mut output, &mut source, &mut bindings, limits)?;
                output.push(HtmlNode::Block(
                    *kind,
                    path.clone(),
                    compile_html(body, limits)?,
                    compile_html(fallback, limits)?,
                ));
            }
        }
    }
    flush(&mut output, &mut source, &mut bindings, limits)?;
    Ok(output)
}
fn scalar(value: &Value) -> Result<String, Error> {
    match value {
        Value::Null => Ok(String::new()),
        Value::Bool(b) => Ok(b.to_string()),
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) => Ok(n.as_str().to_string()),
        _ => Err(Error::Syntax("collections require range or with".into())),
    }
}
fn render_html(
    nodes: &[HtmlNode],
    current: &Value,
    root: &Value,
    output: &mut String,
    limit: usize,
    remaining: &mut usize,
    functions: &Functions,
) -> Result<(), Error> {
    for node in nodes {
        spend(remaining)?;
        match node {
            HtmlNode::Fragment(template, bindings) => {
                let mut values = Values::new();
                let mut staged = 0usize;
                for (name, path) in bindings {
                    spend(remaining)?;
                    let value = expression::eval(path, current, root, functions, limit, remaining)?;
                    let value = value.as_ref();
                    let size = match value {
                        Value::String(s) => s.len(),
                        Value::Number(n) => n.as_str().len(),
                        Value::Bool(true) => 4,
                        Value::Bool(false) => 5,
                        Value::Null => 0,
                        _ => return Err(Error::Syntax("collections require range or with".into())),
                    };
                    staged = staged
                        .checked_add(size)
                        .ok_or(Error::Limit("output bytes"))?;
                    if staged > limit.saturating_sub(output.len()) {
                        return Err(Error::Limit("output bytes"));
                    }
                    values.insert(name.clone(), scalar(value)?);
                }
                let rendered = template.render(&values)?;
                append(output, &rendered, limit)?;
            }
            HtmlNode::Block(kind, path, body, fallback) => {
                let value = expression::eval(path, current, root, functions, limit, remaining)?;
                let value = value.as_ref();
                match kind {
                    Kind::If => render_html(
                        if truth(value) { body } else { fallback },
                        current,
                        root,
                        output,
                        limit,
                        remaining,
                        functions,
                    )?,
                    Kind::With => {
                        if truth(value) {
                            render_html(body, value, root, output, limit, remaining, functions)?;
                        } else {
                            render_html(
                                fallback, current, root, output, limit, remaining, functions,
                            )?;
                        }
                    }
                    Kind::Range => match value {
                        Value::Array(values) => {
                            if values.is_empty() {
                                render_html(
                                    fallback, current, root, output, limit, remaining, functions,
                                )?;
                            }
                            for value in values {
                                spend(remaining)?;
                                render_html(
                                    body, value, root, output, limit, remaining, functions,
                                )?;
                            }
                        }
                        Value::Object(values) => {
                            if values.is_empty() {
                                render_html(
                                    fallback, current, root, output, limit, remaining, functions,
                                )?;
                            }
                            for value in values.values() {
                                spend(remaining)?;
                                render_html(
                                    body, value, root, output, limit, remaining, functions,
                                )?;
                            }
                        }
                        Value::Null => render_html(
                            fallback, current, root, output, limit, remaining, functions,
                        )?,
                        _ => return Err(Error::Syntax("range requires collection".into())),
                    },
                }
            }
        }
    }
    Ok(())
}

impl TextTemplate {
    pub fn parse(source: &str) -> Result<Self, Error> {
        Self::parse_with_limits(source, Limits::default())
    }
    pub fn parse_with_limits(source: &str, limits: Limits) -> Result<Self, Error> {
        check_source(source, limits)?;
        let mut parser = Parser {
            source,
            position: 0,
            actions: 0,
            limits,
        };
        let (nodes, ending) = parser.nodes(0)?;
        if ending != Terminator::Eof {
            return Err(Error::Syntax("unexpected block terminator".into()));
        }
        Ok(Self {
            nodes,
            limits,
            functions: Functions::new(),
        })
    }
    pub fn functions_mut(&mut self) -> &mut Functions {
        &mut self.functions
    }
    pub fn render(&self, data: &Value) -> Result<String, Error> {
        let mut out = String::new();
        let mut remaining = 1_000_000;
        render_nodes(
            &self.nodes,
            data,
            data,
            &mut out,
            self.limits.output_bytes,
            &mut remaining,
            &self.functions,
        )?;
        Ok(out)
    }
    pub fn render_to(&self, data: &Value, writer: &mut impl Write) -> Result<(), Error> {
        writer
            .write_all(self.render(data)?.as_bytes())
            .map_err(Error::Io)
    }
}

#[derive(PartialEq, Eq)]
enum Terminator {
    Eof,
    Else,
    End,
}
struct Parser<'a> {
    source: &'a str,
    position: usize,
    actions: usize,
    limits: Limits,
}
impl Parser<'_> {
    fn nodes(&mut self, depth: usize) -> Result<(Vec<Node>, Terminator), Error> {
        if depth > 64 {
            return Err(Error::Limit("template nesting"));
        }
        let mut nodes = Vec::new();
        while self.position < self.source.len() {
            let rest = &self.source[self.position..];
            let Some(relative) = rest.find("{{") else {
                nodes.push(Node::Literal(rest.to_string()));
                self.position = self.source.len();
                break;
            };
            if relative > 0 {
                nodes.push(Node::Literal(rest[..relative].to_string()));
            }
            let start = self.position + relative + 2;
            let end = action_end(self.source, start)?;
            let action = self.source[start..end].trim().to_string();
            self.position = end + 2;
            self.actions += 1;
            if self.actions > self.limits.fields {
                return Err(Error::Limit("fields"));
            }
            match action.as_str() {
                "else" => return Ok((nodes, Terminator::Else)),
                "end" => return Ok((nodes, Terminator::End)),
                _ => {}
            }
            let block = action
                .strip_prefix("if ")
                .map(|s| (Kind::If, s))
                .or_else(|| action.strip_prefix("range ").map(|s| (Kind::Range, s)))
                .or_else(|| action.strip_prefix("with ").map(|s| (Kind::With, s)));
            if let Some((kind, path)) = block {
                let path = path.trim();
                let expr = expression::parse(path)?;
                let (body, ending) = self.nodes(depth + 1)?;
                let fallback = if ending == Terminator::Else {
                    let (fallback, final_end) = self.nodes(depth + 1)?;
                    if final_end != Terminator::End {
                        return Err(Error::Syntax("missing block end".into()));
                    }
                    fallback
                } else if ending == Terminator::End {
                    Vec::new()
                } else {
                    return Err(Error::Syntax("missing block end".into()));
                };
                nodes.push(Node::Block(kind, expr, body, fallback));
            } else {
                nodes.push(Node::Field(expression::parse(&action)?));
            }
        }
        Ok((nodes, Terminator::Eof))
    }
}
fn action_end(source: &str, start: usize) -> Result<usize, Error> {
    let bytes = source.as_bytes();
    let mut cursor = start;
    let mut quoted = false;
    while cursor < bytes.len() {
        if quoted && bytes[cursor] == b'\\' {
            cursor += 2;
            continue;
        }
        if bytes[cursor] == b'"' {
            quoted = !quoted;
        }
        if !quoted && bytes[cursor] == b'}' && bytes.get(cursor + 1) == Some(&b'}') {
            return Ok(cursor);
        }
        cursor += 1;
    }
    Err(Error::Syntax(
        "unterminated action or string literal".into(),
    ))
}
pub(super) fn validate_path(path: &str) -> Result<(), Error> {
    if matches!(path, "." | "$") {
        return Ok(());
    }
    let path = path
        .strip_prefix("$.")
        .or_else(|| path.strip_prefix('.'))
        .unwrap_or(path);
    if path.is_empty()
        || !path
            .split('.')
            .all(|s| super::valid_name(s) && !s.contains('.'))
    {
        return Err(Error::Syntax("invalid value path".into()));
    }
    Ok(())
}
pub(super) fn resolve<'a>(
    path: &str,
    current: &'a Value,
    root: &'a Value,
) -> Result<&'a Value, Error> {
    if path == "." {
        return Ok(current);
    }
    if path == "$" {
        return Ok(root);
    }
    let (mut value, path) = if let Some(path) = path.strip_prefix("$.") {
        (root, path)
    } else {
        (current, path.strip_prefix('.').unwrap_or(path))
    };
    for component in path.split('.') {
        value = value
            .get(component)
            .ok_or_else(|| Error::Missing(path.to_string()))?;
    }
    Ok(value)
}
pub(super) fn truth(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::String(s) => !s.is_empty(),
        Value::Array(v) => !v.is_empty(),
        Value::Object(m) => !m.is_empty(),
        Value::Number(n) => n
            .as_str()
            .split(['e', 'E'])
            .next()
            .unwrap_or("")
            .bytes()
            .any(|b| matches!(b, b'1'..=b'9')),
    }
}
pub(super) fn spend(remaining: &mut usize) -> Result<(), Error> {
    *remaining = remaining
        .checked_sub(1)
        .ok_or(Error::Limit("render operations"))?;
    Ok(())
}
fn render_nodes(
    nodes: &[Node],
    current: &Value,
    root: &Value,
    out: &mut String,
    limit: usize,
    remaining: &mut usize,
    functions: &Functions,
) -> Result<(), Error> {
    for node in nodes {
        spend(remaining)?;
        match node {
            Node::Literal(s) => append(out, s, limit)?,
            Node::Field(path) => {
                match expression::eval(path, current, root, functions, limit, remaining)?.as_ref() {
                    Value::Null => {}
                    Value::Bool(b) => append(out, if *b { "true" } else { "false" }, limit)?,
                    Value::Number(n) => append(out, n.as_str(), limit)?,
                    Value::String(s) => append(out, s, limit)?,
                    _ => return Err(Error::Syntax("collections require range or with".into())),
                }
            }
            Node::Block(kind, path, body, fallback) => {
                let value = expression::eval(path, current, root, functions, limit, remaining)?;
                let value = value.as_ref();
                match kind {
                    Kind::If => render_nodes(
                        if truth(value) { body } else { fallback },
                        current,
                        root,
                        out,
                        limit,
                        remaining,
                        functions,
                    )?,
                    Kind::With => {
                        if truth(value) {
                            render_nodes(body, value, root, out, limit, remaining, functions)?;
                        } else {
                            render_nodes(
                                fallback, current, root, out, limit, remaining, functions,
                            )?;
                        }
                    }
                    Kind::Range => match value {
                        Value::Array(values) => {
                            if values.is_empty() {
                                render_nodes(
                                    fallback, current, root, out, limit, remaining, functions,
                                )?;
                            }
                            for value in values {
                                spend(remaining)?;
                                render_nodes(body, value, root, out, limit, remaining, functions)?;
                            }
                        }
                        Value::Object(values) => {
                            if values.is_empty() {
                                render_nodes(
                                    fallback, current, root, out, limit, remaining, functions,
                                )?;
                            }
                            for value in values.values() {
                                spend(remaining)?;
                                render_nodes(body, value, root, out, limit, remaining, functions)?;
                            }
                        }
                        Value::Null => {
                            render_nodes(fallback, current, root, out, limit, remaining, functions)?
                        }
                        _ => return Err(Error::Syntax("range requires collection".into())),
                    },
                }
            }
        }
    }
    Ok(())
}
