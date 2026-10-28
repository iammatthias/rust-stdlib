//! JavaScript escaping (Go `html/template` `js.go`).

use super::content::{indirect_to_stringer_or_error, stringify, ContentType};
use super::context::JsCtx;
use super::jsonenc;
use crate::text::template::value::{CallError, FuncSig, Kind, Type, Value};
use crate::text::template::verbs;
use crate::unicode::rune::{decode_last_rune, decode_rune};

/// The JS whitespace and line terminator code points.
const JS_WHITESPACE: &[char] = &[
    '\x0c', '\n', '\r', '\t', '\x0b', ' ', '\u{a0}', '\u{1680}', '\u{2000}', '\u{2001}',
    '\u{2002}', '\u{2003}', '\u{2004}', '\u{2005}', '\u{2006}', '\u{2007}', '\u{2008}', '\u{2009}',
    '\u{200a}', '\u{2028}', '\u{2029}', '\u{202f}', '\u{205f}', '\u{3000}', '\u{feff}',
];

/// Returns the JS context after the tokens in `s`, given the context
/// `preceding`: whether a following slash is a division or a regexp.
pub(crate) fn next_js_ctx(s: &[u8], preceding: JsCtx) -> JsCtx {
    // Trim all JS whitespace characters.
    let mut end = s.len();
    while end > 0 {
        let (r, w) = decode_last_rune(&s[..end]);
        match char::from_u32(r as u32) {
            Some(c) if JS_WHITESPACE.contains(&c) && w > 0 => end -= w,
            _ => break,
        }
    }
    let s = &s[..end];
    if s.is_empty() {
        return preceding;
    }

    // All cases below are in the single-byte UTF-8 group.
    let n = s.len();
    let c = s[n - 1];
    match c {
        b'+' | b'-' => {
            // ++ and -- are not regexp preceders, but + and - are
            // within regexp-preceders.
            let mut start = n - 1;
            while start > 0 && s[start - 1] == c {
                start -= 1;
            }
            // Count the number of adjacent dashes or pluses.
            if (n - start) & 1 == 1 {
                // Dash or plus immediately preceded by an odd number of
                // dashes or pluses is a regexp preceder.
                JsCtx::Regexp
            } else {
                JsCtx::DivOp
            }
        }
        b'.' => {
            // Handle "42."
            if n != 1 && s[n - 2].is_ascii_digit() {
                JsCtx::DivOp
            } else {
                JsCtx::Regexp
            }
        }
        // Suffixes for all punctuators from section 7.7 of the language
        // spec that only end binary operators not handled above.
        b',' | b'<' | b'>' | b'=' | b'*' | b'%' | b'&' | b'|' | b'^' | b'?' => JsCtx::Regexp,
        // Suffixes for all punctuators from section 7.7 of the language
        // spec that are prefix operators not handled above.
        b'!' | b'~' => JsCtx::Regexp,
        // Matches all the punctuators from section 7.7 of the language spec
        // that are open parentheses.
        b'(' | b'[' => JsCtx::Regexp,
        // Matches all the punctuators from section 7.7 of the language spec
        // that precede expression starts.
        b':' | b';' | b'{' => JsCtx::Regexp,
        // CAVEAT: the close punctuators ')', ']', '}' precede div ops and
        // are handled in the default except for '}' which can precede a
        // regexp as in a block statement.
        b'}' => JsCtx::Regexp,
        _ => {
            // Look for an IdentifierName and see if it is a keyword that
            // can precede a regexp.
            let mut j = n;
            while j > 0 && is_js_ident_part(i32::from(s[j - 1])) {
                j -= 1;
            }
            if let Ok(word) = std::str::from_utf8(&s[j..]) {
                if REGEXP_PRECEDER_KEYWORDS.contains(&word) {
                    return JsCtx::Regexp;
                }
            }
            // Otherwise is a punctuator not listed above, or a string which
            // precedes a div op, or an identifier which precedes a div op.
            JsCtx::DivOp
        }
    }
}

/// Keywords that precede a regular expression in JavaScript.
const REGEXP_PRECEDER_KEYWORDS: &[&str] = &[
    "break",
    "case",
    "continue",
    "delete",
    "do",
    "else",
    "finally",
    "in",
    "instanceof",
    "return",
    "throw",
    "try",
    "typeof",
    "void",
];

/// The `json.Marshaler` shape: `MarshalJSON() ([]byte, error)`.
fn marshaler_sig() -> FuncSig {
    FuncSig::new(
        vec![],
        vec![Type::slice_of(Type::uint8()), Type::error()],
        false,
    )
}

pub(crate) fn implements_marshaler(t: &Type) -> bool {
    t.method_set()
        .iter()
        .any(|(n, s)| n == "MarshalJSON" && *s == marshaler_sig())
}

/// Like `indirect`, but stops at a pointer that implements `json.Marshaler`.
fn indirect_to_json_marshaler(a: &Value) -> Value {
    let mut v = a.interface();
    if !v.is_valid() {
        return v;
    }
    while v.kind() == Kind::Pointer
        && !v.is_nil()
        && !implements_marshaler(v.type_().expect("valid"))
    {
        v = v.elem();
    }
    v.interface()
}

/// Case-insensitively replaces `<script` and `</script` with `\x3Cscript`,
/// `\x3C/script`.
fn replace_script_tags(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    let mut last = 0;
    while i < b.len() {
        if b[i] == b'<' {
            let rest = &b[i + 1..];
            let slash = usize::from(rest.first() == Some(&b'/'));
            if rest.len() >= slash + 6 && rest[slash..slash + 6].eq_ignore_ascii_case(b"script") {
                out.push_str(&s[last..i]);
                out.push_str("\\x3C");
                out.push_str(if slash == 1 { "/script" } else { "script" });
                i += 1 + slash + 6;
                last = i;
                continue;
            }
        }
        i += 1;
    }
    out.push_str(&s[last..]);
    out
}

/// Converts the arguments to a JSON string that can be embedded in a script
/// element or an event handler attribute.
pub(crate) fn js_val_escaper(args: &[Value]) -> Result<String, CallError> {
    let a: Value = if args.len() == 1 {
        let mut v = indirect_to_json_marshaler(&args[0]);
        if let Some(t) = v.type_() {
            if *t == super::content::js_type() {
                return Ok(v.as_string());
            }
            if *t == super::content::js_str_type() {
                return Ok(format!("\"{}\"", v.as_string()));
            }
            if !implements_marshaler(t) && t.implements(&Type::stringer()) {
                if let Ok(s) = v.method_by_name("String").call(&[]) {
                    v = s;
                }
            }
        }
        v
    } else {
        // This is a no-op for non-pointer types
        let vals: Vec<Value> = args.iter().map(indirect_to_json_marshaler).collect();
        Value::string(verbs::sprint(&vals))
    };
    let b = match jsonenc::marshal(&a) {
        Ok(b) => b,
        Err(jsonenc::EncErr::Panic(p)) => return Err(CallError::Panic(p)),
        Err(jsonenc::EncErr::Json(e)) => {
            // While the standard JSON marshaler does not include user
            // controlled information in the error message, structs can
            // implement the Marshaler interface and return arbitrary
            // content. Since we're embedding the error in the JS code, we
            // need to be careful.
            let mut err_str = replace_script_tags(&e);
            err_str = err_str.replace("*/", "* /");
            err_str = err_str.replace("<!--", "\\x3C!--");
            return Ok(format!(" /* {err_str} */null "));
        }
    };
    // TODO: maybe post-process output to prevent it from containing
    // "<!--", "-->", "<![CDATA[", "]]>", or "</script"
    // in case custom marshalers produce output containing those.
    // Note: Do not use \x escaping to save bytes because it is not JSON
    // compatible and this escaper supports ld+json content-type.
    if b.is_empty() {
        // In, `x=y/{{.}}*z` a json.Marshaler that produces "" should
        // not cause the output `x=y/*z`.
        return Ok(" null ".to_owned());
    }
    let (first, _) = decode_rune(&b);
    let (last, _) = decode_last_rune(&b);
    let mut buf = String::new();
    let pad = is_js_ident_part(first) || is_js_ident_part(last);
    if pad {
        buf.push(' ');
    }
    let mut written = 0;
    let mut i = 0;
    while i < b.len() {
        let (r, n) = decode_rune(&b[i..]);
        let repl = match r {
            0x2028 => "\\u2028",
            0x2029 => "\\u2029",
            _ => "",
        };
        if !repl.is_empty() {
            buf.push_str(&String::from_utf8_lossy(&b[written..i]));
            buf.push_str(repl);
            written = i + n;
        }
        i += n.max(1);
    }
    if !buf.is_empty() {
        buf.push_str(&String::from_utf8_lossy(&b[written..]));
        if pad {
            buf.push(' ');
        }
        return Ok(buf);
    }
    Ok(String::from_utf8_lossy(&b).into_owned())
}

/// Escapes a string for embedding in a JS string literal.
pub(crate) fn js_str_escaper(args: &[Value]) -> String {
    let (s, t) = stringify(args);
    if t == ContentType::JsStr {
        return replace(&s, JsTable::StrNorm);
    }
    replace(&s, JsTable::Str)
}

/// Escapes a string for embedding in a JS template literal.
pub(crate) fn js_tmpl_lit_escaper(args: &[Value]) -> String {
    let (s, _) = stringify(args);
    replace(&s, JsTable::Bq)
}

/// Escapes a string for embedding in a JS regexp literal.
pub(crate) fn js_regexp_escaper(args: &[Value]) -> String {
    let (s, _) = stringify(args);
    let s = replace(&s, JsTable::Regexp);
    if s.is_empty() {
        // /{{.X}}/ should not produce a line comment when .X == "".
        return "(?:)".to_owned();
    }
    s
}

#[derive(Clone, Copy)]
enum JsTable {
    Str,
    Bq,
    StrNorm,
    Regexp,
}

fn low_unicode(r: i32) -> Option<&'static str> {
    Some(match r {
        0 => "\\u0000",
        1 => "\\u0001",
        2 => "\\u0002",
        3 => "\\u0003",
        4 => "\\u0004",
        5 => "\\u0005",
        6 => "\\u0006",
        7 => "\\u0007",
        8 => "\\u0008",
        9 => "\\t",
        10 => "\\n",
        11 => "\\u000b", // "\v" == "v" on IE 6.
        12 => "\\f",
        13 => "\\r",
        0xe => "\\u000e",
        0xf => "\\u000f",
        0x10 => "\\u0010",
        0x11 => "\\u0011",
        0x12 => "\\u0012",
        0x13 => "\\u0013",
        0x14 => "\\u0014",
        0x15 => "\\u0015",
        0x16 => "\\u0016",
        0x17 => "\\u0017",
        0x18 => "\\u0018",
        0x19 => "\\u0019",
        0x1a => "\\u001a",
        0x1b => "\\u001b",
        0x1c => "\\u001c",
        0x1d => "\\u001d",
        0x1e => "\\u001e",
        0x1f => "\\u001f",
        _ => return None,
    })
}

fn table_repl(table: JsTable, r: i32) -> Option<&'static str> {
    let c = char::from_u32(r as u32)?;
    // Entries common to the string tables.
    let common = |c: char| -> Option<&'static str> {
        Some(match c {
            '"' => "\\u0022",
            '&' => "\\u0026",
            '\'' => "\\u0027",
            '+' => "\\u002b",
            '/' => "\\/",
            '<' => "\\u003c",
            '>' => "\\u003e",
            _ => return None,
        })
    };
    match table {
        JsTable::Str => match c {
            '`' => Some("\\u0060"),
            '\\' => Some("\\\\"),
            _ => common(c),
        },
        JsTable::Bq => match c {
            '`' => Some("\\u0060"),
            '\\' => Some("\\\\"),
            '$' => Some("\\u0024"),
            '{' => Some("\\u007b"),
            '}' => Some("\\u007d"),
            _ => common(c),
        },
        JsTable::StrNorm => match c {
            '`' => Some("\\u0060"),
            _ => common(c),
        },
        JsTable::Regexp => match c {
            '"' => Some("\\u0022"),
            '$' => Some("\\$"),
            '&' => Some("\\u0026"),
            '\'' => Some("\\u0027"),
            '(' => Some("\\("),
            ')' => Some("\\)"),
            '*' => Some("\\*"),
            '+' => Some("\\u002b"),
            '-' => Some("\\-"),
            '.' => Some("\\."),
            '/' => Some("\\/"),
            '<' => Some("\\u003c"),
            '>' => Some("\\u003e"),
            '?' => Some("\\?"),
            '[' => Some("\\["),
            '\\' => Some("\\\\"),
            ']' => Some("\\]"),
            '^' => Some("\\^"),
            '{' => Some("\\{"),
            '|' => Some("\\|"),
            '}' => Some("\\}"),
            _ => None,
        },
    }
}

/// Replaces the characters of `s` per the table, plus the low Unicode and
/// line separator characters.
fn replace(s: &str, table: JsTable) -> String {
    let sb = s.as_bytes();
    let mut b = String::new();
    let mut written = 0;
    let mut i = 0;
    while i < sb.len() {
        let (r, w) = decode_rune(&sb[i..]);
        let repl = if let Some(l) = low_unicode(r) {
            Some(l)
        } else if let Some(t) = table_repl(table, r) {
            Some(t)
        } else if r == 0x2028 {
            Some("\\u2028")
        } else if r == 0x2029 {
            Some("\\u2029")
        } else {
            None
        };
        if let Some(repl) = repl {
            b.push_str(&s[written..i]);
            b.push_str(repl);
            written = i + w;
        }
        i += w.max(1);
    }
    if written == 0 {
        return s.to_owned();
    }
    b.push_str(&s[written..]);
    b
}

/// Reports whether the rune is a JavaScript identifier part. The Unicode
/// rules are not implemented; this is the ASCII subset.
pub(crate) fn is_js_ident_part(r: i32) -> bool {
    matches!(r, 0x24 | 0x5f)
        || (i32::from(b'0')..=i32::from(b'9')).contains(&r)
        || (i32::from(b'A')..=i32::from(b'Z')).contains(&r)
        || (i32::from(b'a')..=i32::from(b'z')).contains(&r)
}

/// Reports whether the type is a JavaScript MIME type.
pub(crate) fn is_js_type(mime_type: &str) -> bool {
    // per
    //   https://www.w3.org/TR/html5/scripting-1.html#attr-script-type
    //   https://tools.ietf.org/html/rfc7231#section-3.1.1
    //   https://tools.ietf.org/html/rfc4329#section-3
    //   https://www.ietf.org/rfc/rfc4627.txt

    // discard parameters
    let mime = mime_type.split(';').next().unwrap_or("");
    let mime = mime.to_lowercase();
    let mime = mime.trim_matches(|c: char| c.is_whitespace());
    matches!(
        mime,
        "" | "application/ecmascript"
            | "application/javascript"
            | "application/json"
            | "application/ld+json"
            | "application/x-ecmascript"
            | "application/x-javascript"
            | "module"
            | "text/ecmascript"
            | "text/javascript"
            | "text/javascript1.0"
            | "text/javascript1.1"
            | "text/javascript1.2"
            | "text/javascript1.3"
            | "text/javascript1.4"
            | "text/javascript1.5"
            | "text/jscript"
            | "text/livescript"
            | "text/x-ecmascript"
            | "text/x-javascript"
    )
}

#[allow(dead_code)]
fn unused(v: &Value) -> Value {
    indirect_to_stringer_or_error(v)
}
