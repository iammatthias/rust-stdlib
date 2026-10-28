//! HTML escapers and the escaper function table (Go `html/template`
//! `html.go` and the `funcMap` of `escape.go`).

use super::content::{indirect_to_stringer_or_error, stringify, ContentType};
use super::context::{is_in_tag, Context, Delim, Element, State};
use super::css;
use super::js;
use super::transition::transition;
use super::url;
use super::util::index_any;
use crate::text::template::value::{CallError, FuncSig, Type, Value};
use crate::text::template::verbs;
use crate::text::template::FuncMap;
use crate::unicode::rune::decode_rune;
use std::sync::OnceLock;

/// The value substituted for unsafe content (Go `filterFailsafe`).
pub(crate) const FILTER_FAILSAFE: &str = "ZgotmplZ";

/// The strings the HTML escapers substitute, indexed by code point; the
/// table covers the code points below its length.
struct Table(&'static [(u32, &'static str)], u32);

const HTML_REPLACEMENT_TABLE: Table = Table(
    &[
        (0, "\u{FFFD}"),
        (b'"' as u32, "&#34;"),
        (b'&' as u32, "&amp;"),
        (b'\'' as u32, "&#39;"),
        (b'+' as u32, "&#43;"),
        (b'<' as u32, "&lt;"),
        (b'>' as u32, "&gt;"),
    ],
    b'>' as u32 + 1,
);

const HTML_NORM_REPLACEMENT_TABLE: Table = Table(
    &[
        (0, "\u{FFFD}"),
        (b'"' as u32, "&#34;"),
        (b'\'' as u32, "&#39;"),
        (b'+' as u32, "&#43;"),
        (b'<' as u32, "&lt;"),
        (b'>' as u32, "&gt;"),
    ],
    b'>' as u32 + 1,
);

const HTML_NOSPACE_REPLACEMENT_TABLE: Table = Table(
    &[
        (0, "&#xfffd;"),
        (b'\t' as u32, "&#9;"),
        (b'\n' as u32, "&#10;"),
        (0x0b, "&#11;"),
        (0x0c, "&#12;"),
        (b'\r' as u32, "&#13;"),
        (b' ' as u32, "&#32;"),
        (b'"' as u32, "&#34;"),
        (b'&' as u32, "&amp;"),
        (b'\'' as u32, "&#39;"),
        (b'+' as u32, "&#43;"),
        (b'<' as u32, "&lt;"),
        (b'=' as u32, "&#61;"),
        (b'>' as u32, "&gt;"),
        // A parse error in the attribute value (unquoted) and
        // before attribute value states.
        // Treated as a quoting character by IE.
        (b'`' as u32, "&#96;"),
    ],
    b'`' as u32 + 1,
);

const HTML_NOSPACE_NORM_REPLACEMENT_TABLE: Table = Table(
    &[
        (0, "&#xfffd;"),
        (b'\t' as u32, "&#9;"),
        (b'\n' as u32, "&#10;"),
        (0x0b, "&#11;"),
        (0x0c, "&#12;"),
        (b'\r' as u32, "&#13;"),
        (b' ' as u32, "&#32;"),
        (b'"' as u32, "&#34;"),
        (b'\'' as u32, "&#39;"),
        (b'+' as u32, "&#43;"),
        (b'<' as u32, "&lt;"),
        (b'=' as u32, "&#61;"),
        (b'>' as u32, "&gt;"),
        (b'`' as u32, "&#96;"),
    ],
    b'`' as u32 + 1,
);

impl Table {
    fn get(&self, r: u32) -> Option<&'static str> {
        self.0.iter().find(|(k, _)| *k == r).map(|(_, v)| *v)
    }
}

/// Escapes for an unquoted attribute value.
pub(crate) fn html_nospace_escaper(args: &[Value]) -> String {
    let (s, t) = stringify(args);
    if s.is_empty() {
        return FILTER_FAILSAFE.to_owned();
    }
    if t == ContentType::Html {
        return html_replacer(&strip_tags(&s), &HTML_NOSPACE_NORM_REPLACEMENT_TABLE, false);
    }
    html_replacer(&s, &HTML_NOSPACE_REPLACEMENT_TABLE, false)
}

/// Escapes for a quoted attribute value.
pub(crate) fn attr_escaper(args: &[Value]) -> String {
    let (s, t) = stringify(args);
    if t == ContentType::Html {
        return html_replacer(&strip_tags(&s), &HTML_NORM_REPLACEMENT_TABLE, true);
    }
    html_replacer(&s, &HTML_REPLACEMENT_TABLE, true)
}

/// Escapes for RCDATA elements such as `<textarea>`.
pub(crate) fn rcdata_escaper(args: &[Value]) -> String {
    let (s, t) = stringify(args);
    if t == ContentType::Html {
        return html_replacer(&s, &HTML_NORM_REPLACEMENT_TABLE, true);
    }
    html_replacer(&s, &HTML_REPLACEMENT_TABLE, true)
}

/// Escapes for HTML text.
pub(crate) fn html_escaper(args: &[Value]) -> String {
    let (s, t) = stringify(args);
    if t == ContentType::Html {
        return s;
    }
    html_replacer(&s, &HTML_REPLACEMENT_TABLE, true)
}

/// Replaces the characters in `s` that the table maps.
fn html_replacer(s: &str, table: &Table, bad_runes: bool) -> String {
    let sb = s.as_bytes();
    let mut written = 0;
    let mut b = String::new();
    let mut i = 0;
    while i < sb.len() {
        let (r, w) = decode_rune(&sb[i..]);
        let r = r as u32;
        if r < table.1 {
            if let Some(repl) = table.get(r) {
                if !repl.is_empty() {
                    b.push_str(&s[written..i]);
                    b.push_str(repl);
                    written = i + w;
                }
            }
        } else if bad_runes {
            // No-op.
            // IE does not allow these ranges in unquoted attrs.
        } else if (0xfdd0..=0xfdef).contains(&r) || (0xfff0..=0xffff).contains(&r) {
            b.push_str(&s[written..i]);
            b.push_str(&format!("&#x{r:x};"));
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

const DELIM_ENDS_DOUBLE: &[u8] = b"\"";
const DELIM_ENDS_SINGLE: &[u8] = b"'";
const DELIM_ENDS_SPACE: &[u8] = b" \t\n\x0c\r>";

/// The bytes that end an attribute value with the given delimiter.
pub(crate) fn delim_ends(d: Delim) -> &'static [u8] {
    match d {
        Delim::DoubleQuote => DELIM_ENDS_DOUBLE,
        Delim::SingleQuote => DELIM_ENDS_SINGLE,
        Delim::SpaceOrTagEnd => DELIM_ENDS_SPACE,
        Delim::None => b"",
    }
}

/// Strips tags and comments from the HTML, keeping the text, and returns the
/// result. If `html` has no tags it is returned as is.
pub(crate) fn strip_tags(html: &str) -> String {
    let s = html.as_bytes();
    let mut b: Vec<u8> = Vec::new();
    let mut c = Context::default();
    let mut i = 0;
    let mut all_text = true;
    while i != s.len() {
        // Using the transition funcs helps us avoid mangling
        // `<div title="1>2">` or `I <3 Ponies!`.
        if c.delim == Delim::None {
            let mut st = c.state;
            // Use RCDATA instead of parsing into JS or CSS styles.
            if c.element != Element::None && !is_in_tag(st) {
                st = State::Rcdata;
            }
            let (d, nread) = transition(st, c.clone(), &s[i..]);
            let i1 = i + nread;
            if c.state == State::Text || c.state == State::Rcdata {
                // Emit text up to the start of the tag or comment.
                let mut j = i1;
                if d.state != c.state {
                    for j1 in (i..j).rev() {
                        if s[j1] == b'<' {
                            j = j1;
                            break;
                        }
                    }
                }
                b.extend_from_slice(&s[i..j]);
            } else {
                all_text = false;
            }
            c = d;
            i = i1;
            continue;
        }
        let Some(p) = index_any(&s[i..], delim_ends(c.delim)) else {
            break;
        };
        let mut i1 = i + p;
        if c.delim != Delim::SpaceOrTagEnd {
            // Consume any quote.
            i1 += 1;
        }
        c = Context {
            state: State::Tag,
            element: c.element,
            ..Context::default()
        };
        i = i1;
    }
    if all_text {
        return html.to_owned();
    } else if c.state == State::Text || c.state == State::Rcdata {
        b.extend_from_slice(&s[i..]);
    }
    String::from_utf8_lossy(&b).into_owned()
}

/// Filters disallowed attribute names: those that are unknown, would cause
/// execution, or are not a valid name.
pub(crate) fn html_name_filter(args: &[Value]) -> String {
    let (s, t) = stringify(args);
    if t == ContentType::HtmlAttr {
        return s;
    }
    if s.is_empty() {
        // Avoid violation of structure preservation.
        // <input checked {{.K}}={{.V}}>.
        // Without this, if .K is empty then .V is the value of
        // checked, but otherwise .V is the value of the attribute
        // named .K.
        return FILTER_FAILSAFE.to_owned();
    }
    let s = s.to_lowercase();
    if super::attr::attr_type(&s) != ContentType::Plain {
        // Disallow dynamic attribute names whose content type is not plain.
        return FILTER_FAILSAFE.to_owned();
    }
    for r in s.chars() {
        if !r.is_ascii_digit() && !r.is_ascii_lowercase() {
            // Allow only ASCII alphanumerics, which are always safe.
            return FILTER_FAILSAFE.to_owned();
        }
    }
    s
}

/// Elides the value of an action in an HTML comment.
pub(crate) fn comment_escaper(_args: &[Value]) -> String {
    String::new()
}

/// The text of the arguments for `_eval_args_`.
fn eval_args(args: &[Value]) -> String {
    // Optimization for simple common case of a single string argument.
    if args.len() == 1 {
        let a = args[0].interface();
        if a.is_valid() && a.type_() == Some(&Type::string()) {
            return a.as_string();
        }
    }
    let converted: Vec<Value> = args.iter().map(indirect_to_stringer_or_error).collect();
    verbs::sprint(&converted)
}

/// The names of the escaper functions in the escaper function map.
pub(crate) const FUNC_NAMES: &[&str] = &[
    "_html_template_attrescaper",
    "_html_template_commentescaper",
    "_html_template_cssescaper",
    "_html_template_cssvaluefilter",
    "_html_template_htmlnamefilter",
    "_html_template_htmlescaper",
    "_html_template_jsregexpescaper",
    "_html_template_jsstrescaper",
    "_html_template_jstmpllitescaper",
    "_html_template_jsvalescaper",
    "_html_template_nospaceescaper",
    "_html_template_rcdataescaper",
    "_html_template_srcsetescaper",
    "_html_template_urlescaper",
    "_html_template_urlfilter",
    "_html_template_urlnormalizer",
    "_eval_args_",
];

/// The function map the escaper adds to every template.
pub(crate) fn func_map() -> &'static FuncMap {
    static M: OnceLock<FuncMap> = OnceLock::new();
    M.get_or_init(|| {
        let sig = FuncSig::new(
            vec![Type::slice_of(Type::any())],
            vec![Type::string()],
            true,
        );
        let mut m = FuncMap::new();
        let mut add = |name: &str, f: fn(&[Value]) -> String| {
            m.insert(
                name.to_owned(),
                Value::func_of(sig.clone(), move |a| Ok(Value::string(f(a)))),
            );
        };
        add("_html_template_attrescaper", attr_escaper);
        add("_html_template_commentescaper", comment_escaper);
        add("_html_template_cssescaper", css::css_escaper);
        add("_html_template_cssvaluefilter", css::css_value_filter);
        add("_html_template_htmlnamefilter", html_name_filter);
        add("_html_template_htmlescaper", html_escaper);
        add("_html_template_jsregexpescaper", js::js_regexp_escaper);
        add("_html_template_jsstrescaper", js::js_str_escaper);
        add("_html_template_jstmpllitescaper", js::js_tmpl_lit_escaper);
        add("_html_template_nospaceescaper", html_nospace_escaper);
        add("_html_template_rcdataescaper", rcdata_escaper);
        add(
            "_html_template_srcsetescaper",
            url::srcset_filter_and_escaper,
        );
        add("_html_template_urlescaper", url::url_escaper);
        add("_html_template_urlfilter", url::url_filter);
        add("_html_template_urlnormalizer", url::url_normalizer);
        add("_eval_args_", eval_args);
        m.insert(
            "_html_template_jsvalescaper".to_owned(),
            Value::func_of(sig.clone(), |a| js::js_val_escaper(a).map(Value::string)),
        );
        m
    })
}

#[allow(dead_code)]
fn unused(_: CallError) {}
