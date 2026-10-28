//! Typed, bounded template pipelines and explicitly registered trusted functions.
use super::{
    text::{resolve, spend, truth},
    Error,
};
use crate::encoding::json::Value;
use std::{borrow::Cow, collections::BTreeMap};

/// Functions are trusted Rust code, receive typed borrowed values, and must
/// bound their own allocation/work. Their returned values are checked against
/// the renderer's byte/depth/operation budgets and still contextually escaped.
pub type Function = fn(&[&Value]) -> Result<Value, String>;
#[derive(Debug, Clone, Default)]
pub struct Functions {
    registered: BTreeMap<String, Function>,
}
impl Functions {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn register(&mut self, name: &str, function: Function) -> Result<(), Error> {
        if !super::valid_name(name) || name.contains('.') || builtin(name) {
            return Err(Error::Syntax("invalid or reserved function name".into()));
        }
        if self.registered.contains_key(name) {
            return Err(Error::Syntax("duplicate function name".into()));
        }
        self.registered.insert(name.to_string(), function);
        Ok(())
    }
}
#[derive(Debug, Clone)]
pub(super) enum Expression {
    Path(String, usize),
    Literal(Value),
    Call(String, Vec<Expression>),
}
fn builtin(name: &str) -> bool {
    matches!(
        name,
        "len" | "upper" | "lower" | "eq" | "not" | "and" | "or" | "join" | "index"
    )
}

pub(super) fn parse(source: &str) -> Result<Expression, Error> {
    let tokens = tokenize(source)?;
    let mut pipes = tokens.split(|s| s == "|");
    let first = pipes
        .next()
        .ok_or_else(|| Error::Syntax("empty expression".into()))?;
    let mut expr = command(first, None)?;
    for pipe in pipes {
        expr = command(pipe, Some(expr))?;
    }
    Ok(expr)
}
fn command(tokens: &[String], previous: Option<Expression>) -> Result<Expression, Error> {
    if tokens.is_empty() {
        return Err(Error::Syntax("empty pipeline command".into()));
    }
    if previous.is_none() && tokens.len() == 1 && !builtin(&tokens[0]) && !tokens[0].ends_with("()")
    {
        return atom(&tokens[0]);
    }
    let name = tokens[0].strip_suffix("()").unwrap_or(&tokens[0]);
    if !super::valid_name(name) || name.contains('.') {
        return Err(Error::Syntax("invalid function name".into()));
    }
    let mut args = tokens[1..]
        .iter()
        .map(|s| atom(s))
        .collect::<Result<Vec<_>, _>>()?;
    if let Some(previous) = previous {
        args.push(previous);
    }
    if args.len() > 64 {
        return Err(Error::Limit("function arguments"));
    }
    Ok(Expression::Call(name.to_string(), args))
}
fn atom(token: &str) -> Result<Expression, Error> {
    if token.starts_with('"')
        || matches!(token, "true" | "false" | "null")
        || token.starts_with('-')
        || token.bytes().next().is_some_and(|b| b.is_ascii_digit())
    {
        let value = token
            .parse::<Value>()
            .map_err(|_| Error::Syntax("invalid expression literal".into()))?;
        if matches!(value, Value::Array(_) | Value::Object(_)) {
            return Err(Error::Syntax("collection literal unsupported".into()));
        }
        return Ok(Expression::Literal(value));
    }
    super::text::validate_path(token)?;
    Ok(Expression::Path(
        token.to_string(),
        token.bytes().filter(|b| *b == b'.').count() + 1,
    ))
}
fn tokenize(source: &str) -> Result<Vec<String>, Error> {
    let mut result = Vec::new();
    let mut cursor = 0;
    let bytes = source.as_bytes();
    while cursor < bytes.len() {
        if bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
            continue;
        }
        let start = cursor;
        if bytes[cursor] == b'|' {
            result.push("|".into());
            cursor += 1;
            continue;
        }
        if bytes[cursor] == b'"' {
            cursor += 1;
            while cursor < bytes.len() && bytes[cursor] != b'"' {
                if bytes[cursor] == b'\\' {
                    cursor += 1;
                }
                cursor += 1;
            }
            if cursor >= bytes.len() {
                return Err(Error::Syntax("unterminated expression string".into()));
            }
            cursor += 1;
            if bytes
                .get(cursor)
                .is_some_and(|b| !b.is_ascii_whitespace() && *b != b'|')
            {
                return Err(Error::Syntax("missing expression token separator".into()));
            }
        } else {
            while bytes
                .get(cursor)
                .is_some_and(|b| !b.is_ascii_whitespace() && *b != b'|')
            {
                cursor += 1;
            }
        }
        result.push(source[start..cursor].to_string());
        if result.len() > 256 {
            return Err(Error::Limit("expression tokens"));
        }
    }
    Ok(result)
}
pub(super) fn eval<'a>(
    expr: &'a Expression,
    current: &'a Value,
    root: &'a Value,
    functions: &Functions,
    limit: usize,
    remaining: &mut usize,
) -> Result<Cow<'a, Value>, Error> {
    spend(remaining)?;
    match expr {
        Expression::Path(path, steps) => {
            *remaining = remaining
                .checked_sub(*steps)
                .ok_or(Error::Limit("render operations"))?;
            Ok(Cow::Borrowed(resolve(path, current, root)?))
        }
        Expression::Literal(value) => Ok(Cow::Borrowed(value)),
        Expression::Call(name, arguments) => {
            if !builtin(name) && !functions.registered.contains_key(name) {
                return Err(function_error(name, "unknown function"));
            }
            if matches!(name.as_str(), "and" | "or") {
                if arguments.is_empty() {
                    return Err(function_error(name, "requires arguments"));
                }
                let mut result = Cow::Borrowed(&Value::Null);
                for argument in arguments {
                    result = eval(argument, current, root, functions, limit, remaining)?;
                    if truth(result.as_ref()) == (name == "or") {
                        break;
                    }
                }
                return Ok(result);
            }
            let arguments = arguments
                .iter()
                .map(|arg| eval(arg, current, root, functions, limit, remaining))
                .collect::<Result<Vec<_>, _>>()?;
            let refs = arguments.iter().map(|arg| arg.as_ref()).collect::<Vec<_>>();
            if name == "eq" {
                for value in &refs {
                    checked_value(value, limit, remaining)?;
                }
            }
            if name == "index" {
                if refs.len() != 2 {
                    return Err(function_error(name, "requires two arguments"));
                }
                let value = match (refs[0], refs[1]) {
                    (Value::Object(map), Value::String(key)) => map.get(key),
                    (Value::Array(values), Value::Number(n)) => n
                        .as_u64()
                        .and_then(|n| usize::try_from(n).ok())
                        .and_then(|n| values.get(n)),
                    _ => return Err(function_error(name, "requires object/key or array/index")),
                }
                .ok_or_else(|| function_error(name, "missing index"))?;
                checked_value(value, limit, remaining)?;
                return Ok(Cow::Owned(value.clone()));
            }
            let result = if builtin(name) {
                call_builtin(name, &refs, limit, remaining)
            } else {
                functions
                    .registered
                    .get(name)
                    .ok_or_else(|| function_error(name, "unknown function"))?(&refs)
            };
            let result = result.map_err(|message| function_error(name, &message))?;
            checked_value(&result, limit, remaining)?;
            Ok(Cow::Owned(result))
        }
    }
}
fn function_error(name: &str, message: &str) -> Error {
    Error::Syntax(format!("function {name}: {message}"))
}
fn checked_value(value: &Value, limit: usize, remaining: &mut usize) -> Result<(), Error> {
    fn walk(
        value: &Value,
        bytes: &mut usize,
        depth: usize,
        remaining: &mut usize,
    ) -> Result<(), Error> {
        spend(remaining)?;
        if depth > 64 {
            return Err(Error::Limit("function result nesting"));
        }
        let size = match value {
            Value::String(s) => s.len(),
            Value::Number(n) => n.as_str().len(),
            _ => 1,
        };
        *bytes = bytes
            .checked_sub(size)
            .ok_or(Error::Limit("function result bytes"))?;
        match value {
            Value::Array(values) => {
                for value in values {
                    walk(value, bytes, depth + 1, remaining)?;
                }
            }
            Value::Object(values) => {
                for (key, value) in values {
                    *bytes = bytes
                        .checked_sub(key.len())
                        .ok_or(Error::Limit("function result bytes"))?;
                    walk(value, bytes, depth + 1, remaining)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    let mut bytes = limit;
    walk(value, &mut bytes, 0, remaining)
}
fn call_builtin(
    name: &str,
    args: &[&Value],
    limit: usize,
    remaining: &mut usize,
) -> Result<Value, String> {
    let fail = || format!("invalid arguments to {name}");
    match name {
        "len" if args.len() == 1 => {
            let length = match args[0] {
                Value::String(s) => s.len(),
                Value::Array(a) => a.len(),
                Value::Object(o) => o.len(),
                _ => return Err(fail()),
            };
            Ok(Value::from(length as u64))
        }
        "upper" | "lower" if args.len() == 1 => {
            let Value::String(s) = args[0] else {
                return Err(fail());
            };
            if s.len() > limit {
                return Err("input byte limit exceeded".into());
            }
            let value = if name == "upper" {
                s.to_uppercase()
            } else {
                s.to_lowercase()
            };
            if value.len() > limit {
                return Err("output byte limit exceeded".into());
            }
            Ok(Value::String(value))
        }
        "eq" if args.len() == 2 => Ok(Value::Bool(args[0] == args[1])),
        "not" if args.len() == 1 => Ok(Value::Bool(!truth(args[0]))),
        "join" if args.len() == 2 => {
            let (items, separator) = match (args[0], args[1]) {
                (Value::Array(items), Value::String(separator))
                | (Value::String(separator), Value::Array(items)) => (items, separator),
                _ => return Err(fail()),
            };
            let mut out = String::new();
            for (i, item) in items.iter().enumerate() {
                spend(remaining).map_err(|e| e.to_string())?;
                let Value::String(value) = item else {
                    return Err(fail());
                };
                if i > 0 {
                    super::append(&mut out, separator, limit).map_err(|e| e.to_string())?;
                }
                super::append(&mut out, value, limit).map_err(|e| e.to_string())?;
            }
            Ok(Value::String(out))
        }
        _ => Err(fail()),
    }
}
