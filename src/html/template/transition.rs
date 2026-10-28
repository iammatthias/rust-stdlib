//! Context transitions (Go `html/template` `transition.go`).
//!
//! Each transition function maps a context and a byte string to the context
//! after the longest prefix of the string that changes the context, together
//! with the length of that prefix.

use super::attr::attr_type;
use super::content::ContentType;
use super::context::{
    is_comment, is_in_script_literal, Attr, Context, Delim, Element, JsCtx, State, UrlPart,
};
use super::css::{decode_css, ends_with_css_keyword};
use super::error::{errorf, ErrorCode};
use super::js::next_js_ctx;
use super::util::{
    equal_fold, has_prefix, index_any, index_any_runes, index_byte, index_sub, to_lower_string,
    trim_left, trim_right,
};
use crate::strconv;

/// Calls the transition function for the context's state.
pub(crate) fn transition(state: State, c: Context, s: &[u8]) -> (Context, usize) {
    match state {
        State::Text => t_text(c, s),
        State::Tag => t_tag(c, s),
        State::AttrName => t_attr_name(c, s),
        State::AfterName => t_after_name(c, s),
        State::BeforeValue => t_before_value(c, s),
        State::HtmlCmt => t_html_cmt(c, s),
        State::Rcdata => t_special_tag_end(c, s),
        State::Attr => t_attr(c, s),
        State::Url | State::Srcset => t_url(c, s),
        State::MetaContent => t_meta_content(c, s),
        State::MetaContentUrl => t_meta_content_url(c, s),
        State::Js => t_js(c, s),
        State::JsDqStr | State::JsSqStr | State::JsRegexp => t_js_delimited(c, s),
        State::JsTmplLit => t_js_tmpl(c, s),
        State::JsBlockCmt | State::CssBlockCmt => t_block_cmt(c, s),
        State::JsLineCmt | State::JsHtmlOpenCmt | State::JsHtmlCloseCmt | State::CssLineCmt => {
            t_line_cmt(c, s)
        }
        State::Css => t_css(c, s),
        State::CssDqStr | State::CssSqStr | State::CssDqUrl | State::CssSqUrl | State::CssUrl => {
            t_css_str(c, s)
        }
        State::Error => t_error(c, s),
        State::Dead => panic!("no transition function for stateDead"),
    }
}

const COMMENT_START: &[u8] = b"<!--";
const COMMENT_END: &[u8] = b"-->";

/// The context transition function for the text state.
fn t_text(c: Context, s: &[u8]) -> (Context, usize) {
    let mut k = 0;
    loop {
        let i = match index_byte(&s[k..], b'<') {
            Some(p) => k + p,
            None => return (c, s.len()),
        };
        if i + 1 == s.len() {
            // Remain in the text state.
            return (c, s.len());
        } else if i + 4 <= s.len() && &s[i..i + 4] == COMMENT_START {
            return (Context::new(State::HtmlCmt), i + 4);
        }
        let mut i = i + 1;
        let mut end = false;
        if s[i] == b'/' {
            if i + 1 == s.len() {
                // Remain in the text state.
                return (c, s.len());
            }
            end = true;
            i += 1;
        }
        let (j, e) = eat_tag_name(s, i);
        if j != i {
            let e = if end { Element::None } else { e };
            // We've found an HTML tag.
            return (
                Context {
                    state: State::Tag,
                    element: e,
                    ..Context::default()
                },
                j,
            );
        }
        k = j;
    }
}

fn element_content_type(e: Element) -> State {
    match e {
        Element::None => State::Text,
        Element::Script => State::Js,
        Element::Style => State::Css,
        Element::Textarea => State::Rcdata,
        Element::Title => State::Rcdata,
        Element::Meta => State::Text,
    }
}

/// The context transition function for the tag state.
fn t_tag(c: Context, s: &[u8]) -> (Context, usize) {
    // Find the attribute name.
    let i = eat_white_space(s, 0);
    if i == s.len() {
        return (c, s.len());
    }
    if s[i] == b'>' {
        // Treat <meta> specially, because it doesn't have an end tag, and we
        // want transitions in and out of the content to be wrapped in a text
        // state.
        if c.element == Element::Meta {
            return (
                Context {
                    state: State::Text,
                    element: Element::None,
                    ..Context::default()
                },
                i + 1,
            );
        }
        return (
            Context {
                state: element_content_type(c.element),
                element: c.element,
                ..Context::default()
            },
            i + 1,
        );
    }
    let j = match eat_attr_name(s, i) {
        Ok(j) => j,
        Err(err) => {
            return (Context::error(err), s.len());
        }
    };
    let mut attr = Attr::None;
    if i == j {
        return (
            Context::error(errorf(
                ErrorCode::BadHtml,
                None,
                0,
                format!(
                    "expected space, attr name, or end of tag, but got {}",
                    quote_bytes(&s[i..], None)
                ),
            )),
            s.len(),
        );
    }

    let attr_name = to_lower_string(&s[i..j]);
    if c.element == Element::Script && attr_name == "type" {
        attr = Attr::ScriptType;
    } else if c.element == Element::Meta && attr_name == "content" {
        attr = Attr::MetaContent;
    } else {
        match attr_type(&attr_name) {
            ContentType::Url => attr = Attr::Url,
            ContentType::Css => attr = Attr::Style,
            ContentType::Js => attr = Attr::Script,
            ContentType::Srcset => attr = Attr::Srcset,
            _ => {}
        }
    }

    let state = if j == s.len() {
        State::AttrName // Attribute name continues.
    } else {
        State::AfterName // Attribute name ends.
    };
    (
        Context {
            state,
            element: c.element,
            attr,
            ..Context::default()
        },
        j,
    )
}

/// The context transition function for the attribute name state.
fn t_attr_name(mut c: Context, s: &[u8]) -> (Context, usize) {
    match eat_attr_name(s, 0) {
        Err(err) => (Context::error(err), s.len()),
        Ok(i) => {
            if i != s.len() {
                c.state = State::AfterName;
            }
            (c, i)
        }
    }
}

/// The context transition function for the "after attribute name" state.
fn t_after_name(mut c: Context, s: &[u8]) -> (Context, usize) {
    // Look for the start of the value.
    let i = eat_white_space(s, 0);
    if i == s.len() {
        return (c, s.len());
    } else if s[i] != b'=' {
        // Occurs due to tag ending '>', and valueless attribute.
        c.state = State::Tag;
        return (c, i);
    }
    c.state = State::BeforeValue;
    // Consume the "=".
    (c, i + 1)
}

fn attr_start_state(a: Attr) -> State {
    match a {
        Attr::None => State::Attr,
        Attr::Script => State::Js,
        Attr::ScriptType => State::Attr,
        Attr::Style => State::Css,
        Attr::Url => State::Url,
        Attr::Srcset => State::Srcset,
        Attr::MetaContent => State::MetaContent,
    }
}

/// The context transition function for the "before attribute value" state.
fn t_before_value(mut c: Context, s: &[u8]) -> (Context, usize) {
    let mut i = eat_white_space(s, 0);
    if i == s.len() {
        return (c, s.len());
    }
    // Find the attribute delimiter.
    let mut delim = Delim::SpaceOrTagEnd;
    match s[i] {
        b'\'' => {
            delim = Delim::SingleQuote;
            i += 1;
        }
        b'"' => {
            delim = Delim::DoubleQuote;
            i += 1;
        }
        _ => {}
    }
    c.state = attr_start_state(c.attr);
    c.delim = delim;
    (c, i)
}

/// The context transition function for stateHTMLCmt.
fn t_html_cmt(c: Context, s: &[u8]) -> (Context, usize) {
    if let Some(i) = index_sub(s, COMMENT_END) {
        return (Context::default(), i + 3);
    }
    (c, s.len())
}

fn special_tag_end_marker(e: Element) -> &'static [u8] {
    match e {
        Element::Script => b"script",
        Element::Style => b"style",
        Element::Textarea => b"textarea",
        Element::Title => b"title",
        Element::Meta => b"",
        Element::None => b"",
    }
}

const SPECIAL_TAG_END_PREFIX: &[u8] = b"</";
const TAG_END_SEPARATORS: &[u8] = b"> \t\n\x0c/";

/// The context transition function for RCDATA elements. It matches the HTML
/// spec for how to find the end of the element's content.
pub(crate) fn t_special_tag_end(c: Context, s: &[u8]) -> (Context, usize) {
    if c.element != Element::None {
        // script end tags ("</script") within script literals are ignored, so
        // that script end tags in a JS string literal or comment do not end
        // the script.
        if c.element == Element::Script && (is_in_script_literal(c.state) || is_comment(c.state)) {
            return (c, s.len());
        }
        if let Some(i) = index_tag_end(s, special_tag_end_marker(c.element)) {
            return (Context::default(), i);
        }
    }
    (c, s.len())
}

/// The index of the first tag end of the given type (e.g. `</script`
/// followed by a separator), or `None`.
pub(crate) fn index_tag_end(s: &[u8], tag: &[u8]) -> Option<usize> {
    let mut res = 0;
    let plen = SPECIAL_TAG_END_PREFIX.len();
    let mut s = s;
    while !s.is_empty() {
        // Try to find the tag end prefix first.
        let i = index_sub(s, SPECIAL_TAG_END_PREFIX)?;
        s = &s[i + plen..];
        // Try to match the actual tag if there is still space for it.
        if tag.len() <= s.len() && equal_fold(tag, &s[..tag.len()]) {
            s = &s[tag.len()..];
            // Check the tag is followed by a proper separator.
            if !s.is_empty() && TAG_END_SEPARATORS.contains(&s[0]) {
                return Some(res + i);
            }
            res += tag.len();
        }
        res += i + plen;
    }
    None
}

/// The context transition function for the attribute state.
fn t_attr(c: Context, s: &[u8]) -> (Context, usize) {
    (c, s.len())
}

/// The context transition function for the URL state.
fn t_url(mut c: Context, s: &[u8]) -> (Context, usize) {
    if index_any(s, b"#?").is_some() {
        c.url_part = UrlPart::QueryOrFrag;
    } else if s.len() != eat_white_space(s, 0) && c.url_part == UrlPart::None {
        // HTML5 uses "Valid URL potentially surrounded by spaces" for
        // attrs: https://www.w3.org/TR/html5/index.html#attributes-1
        c.url_part = UrlPart::PreQuery;
    }
    (c, s.len())
}

/// The context transition function for the JS state.
fn t_js(mut c: Context, s: &[u8]) -> (Context, usize) {
    let Some(mut i) = index_any(s, b"\"`'/{}<-#") else {
        // Entire input is non string, comment, regexp tokens.
        c.js_ctx = next_js_ctx(s, c.js_ctx);
        return (c, s.len());
    };
    c.js_ctx = next_js_ctx(&s[..i], c.js_ctx);
    match s[i] {
        b'"' => {
            c.state = State::JsDqStr;
            c.js_ctx = JsCtx::Regexp;
        }
        b'\'' => {
            c.state = State::JsSqStr;
            c.js_ctx = JsCtx::Regexp;
        }
        b'`' => {
            c.state = State::JsTmplLit;
            c.js_ctx = JsCtx::Regexp;
        }
        b'/' => {
            if i + 1 < s.len() && s[i + 1] == b'/' {
                c.state = State::JsLineCmt;
                i += 1;
            } else if i + 1 < s.len() && s[i + 1] == b'*' {
                c.state = State::JsBlockCmt;
                i += 1;
            } else if c.js_ctx == JsCtx::Regexp {
                c.state = State::JsRegexp;
            } else if c.js_ctx == JsCtx::DivOp {
                c.js_ctx = JsCtx::Regexp;
            } else {
                return (
                    Context::error(errorf(
                        ErrorCode::SlashAmbig,
                        None,
                        0,
                        format!(
                            "'/' could start a division or regexp: {}",
                            quote_bytes(&s[i..], Some(32))
                        ),
                    )),
                    s.len(),
                );
            }
        }
        // ECMAScript supports HTML style comments for legacy reasons, see
        // Appendix B.1.1 "HTML-like Comments". The handling of these
        // comments is somewhat confusing. Multi-line comments are not
        // supported, i.e. anything on the same line as the comment opener is
        // part of the comment.
        b'<' => {
            // "<!--" is the start of an HTML-like single-line comment.
            if i + 3 < s.len() && &s[i..i + 4] == COMMENT_START {
                c.state = State::JsHtmlOpenCmt;
                i += 3;
            }
        }
        b'-' => {
            // "-->" is the start of an HTML-like single-line comment.
            if i + 2 < s.len() && &s[i..i + 3] == COMMENT_END {
                c.state = State::JsHtmlCloseCmt;
                i += 2;
            }
        }
        b'#' => {
            // If "#!" appears anywhere in the JS, it's a single-line comment
            // (hashbang).
            if i + 1 < s.len() && s[i + 1] == b'!' {
                c.state = State::JsLineCmt;
                i += 1;
            }
        }
        b'{' => {
            // We only care about tracking brace depth if we are inside a
            // template literal.
            let Some(depth) = c.js_brace_depth.as_mut().filter(|d| !d.is_empty()) else {
                c.js_ctx = next_js_ctx(&s[i..i + 1], c.js_ctx);
                return (c, i + 1);
            };
            *depth.last_mut().expect("non-empty") += 1;
            c.js_ctx = next_js_ctx(&s[i..i + 1], c.js_ctx);
        }
        b'}' => {
            let Some(depth) = c.js_brace_depth.as_mut().filter(|d| !d.is_empty()) else {
                // Either not in a template literal, or the brace depth
                // tracking is not applicable.
                c.js_ctx = next_js_ctx(&s[i..i + 1], c.js_ctx);
                return (c, i + 1);
            };
            // This cannot be hit from a template literal's JS interpolation
            // unless the opening brace was seen.
            *depth.last_mut().expect("non-empty") -= 1;
            if *depth.last().expect("non-empty") >= 0 {
                c.js_ctx = next_js_ctx(&s[i..i + 1], c.js_ctx);
                return (c, i + 1);
            }
            // The closing brace of a `${` interpolation: back to the template
            // literal.
            depth.pop();
            c.state = State::JsTmplLit;
        }
        _ => panic!("unreachable"),
    }
    (c, i + 1)
}

/// The context transition function for the JS template literal state.
fn t_js_tmpl(mut c: Context, s: &[u8]) -> (Context, usize) {
    let mut k = 0;
    while let Some(p) = index_any(&s[k..], b"`\\$") {
        let mut i = k + p;
        match s[i] {
            b'\\' => {
                i += 1;
                if i == s.len() {
                    return (
                        Context::error(errorf(
                            ErrorCode::PartialEscape,
                            None,
                            0,
                            format!(
                                "unfinished escape sequence in JS string: {}",
                                quote_bytes(s, None)
                            ),
                        )),
                        s.len(),
                    );
                }
            }
            b'$' => {
                if s.len() >= i + 2 && s[i + 1] == b'{' {
                    c.js_brace_depth.get_or_insert_with(Vec::new).push(0);
                    c.state = State::Js;
                    return (c, i + 2);
                }
            }
            b'`' => {
                // end
                c.state = State::Js;
                return (c, i + 1);
            }
            _ => {}
        }
        k = i + 1;
    }
    (c, s.len())
}

/// The context transition function for the JS string and regexp states.
fn t_js_delimited(mut c: Context, s: &[u8]) -> (Context, usize) {
    let specials: &[u8] = match c.state {
        State::JsSqStr => b"\\'",
        State::JsRegexp => b"\\/[]",
        _ => b"\\\"",
    };
    let mut k = 0;
    let mut in_charset = false;
    while let Some(p) = index_any(&s[k..], specials) {
        let mut i = k + p;
        match s[i] {
            b'\\' => {
                i += 1;
                if i == s.len() {
                    return (
                        Context::error(errorf(
                            ErrorCode::PartialEscape,
                            None,
                            0,
                            format!(
                                "unfinished escape sequence in JS string: {}",
                                quote_bytes(s, None)
                            ),
                        )),
                        s.len(),
                    );
                }
            }
            b'[' => in_charset = true,
            b']' => in_charset = false,
            b'/' => {
                // If "</script" appears in a regex literal, the '/' should not
                // close the regex literal, and it will end up appearing
                // unescaped in the output of the template. If we don't escape
                // this we would be open to injection, so we step over it.
                if i > 0 && i + 7 <= s.len() && equal_fold(&s[i - 1..i + 7], b"</script") {
                    i += 1;
                } else if !in_charset {
                    c.state = State::Js;
                    c.js_ctx = JsCtx::DivOp;
                    return (c, i + 1);
                }
            }
            _ => {
                // end delimiter
                if !in_charset {
                    c.state = State::Js;
                    c.js_ctx = JsCtx::DivOp;
                    return (c, i + 1);
                }
            }
        }
        k = i + 1;
    }

    if in_charset {
        // This can be fixed by making context richer if interpolation into
        // charsets is desired.
        return (
            Context::error(errorf(
                ErrorCode::PartialCharset,
                None,
                0,
                format!("unfinished JS regexp charset: {}", quote_bytes(s, None)),
            )),
            s.len(),
        );
    }

    (c, s.len())
}

/// The context transition function for the JS and CSS block comment states.
fn t_block_cmt(mut c: Context, s: &[u8]) -> (Context, usize) {
    let Some(i) = index_sub(s, b"*/") else {
        return (c, s.len());
    };
    match c.state {
        State::JsBlockCmt => c.state = State::Js,
        State::CssBlockCmt => c.state = State::Css,
        other => panic!("{}", other.name()),
    }
    (c, i + 2)
}

/// The context transition function for the JS and CSS line comment states.
fn t_line_cmt(mut c: Context, s: &[u8]) -> (Context, usize) {
    let (line_terminators, end_state) = match c.state {
        State::JsLineCmt | State::JsHtmlOpenCmt | State::JsHtmlCloseCmt => {
            ("\n\r\u{2028}\u{2029}", State::Js)
        }
        State::CssLineCmt => ("\n\x0c\r", State::Css),
        other => panic!("{}", other.name()),
    };
    let Some(i) = index_any_runes(s, line_terminators) else {
        return (c, s.len());
    };
    c.state = end_state;
    // Per section 7.4 of EcmaScript 5 : https://es5.github.io/#x7.4
    // "However, the LineTerminator at the end of the line is not considered to
    // be part of the single-line comment; it is recognized separately by the
    // lexical grammar and becomes part of the stream of input elements for the
    // syntactic grammar."
    (c, i)
}

/// The context transition function for the CSS state.
fn t_css(mut c: Context, s: &[u8]) -> (Context, usize) {
    // CSS quoted strings are almost never used except for:
    // (1) URLs as in background: "/foo.png"
    // (2) Multiword font-names as in font-family: "Times New Roman"
    // (3) List separators in content values as in inline-lists:
    //    <style>
    //    ul.inlineList { list-style: none; padding:0 }
    //    ul.inlineList > li { display: inline }
    //    ul.inlineList > li:before { content: ", " }
    //    ul.inlineList > li:first-child:before { content: "" }
    //    </style>
    // (4) Attribute value selectors as in a[href="http://example.com/"]
    //
    // We conservatively treat all strings as URLs, but make some
    // allowances to avoid confusion.
    //
    // In (1), our conservative assumption is justified.
    // In (2), valid font names do not contain ':', '?', or '#', so our
    // conservative assumption is fine since we will never transition past
    // urlPartPreQuery.
    // In (3), our protocol heuristic should not be tripped, and there
    // should not be non-space content after a '?' or '#', so as long as
    // we only %-encode RFC 3986 reserved characters we are ok.
    // In (4), we should URL escape for URL attributes, and for others we
    // have the attribute name available if our conservative assumption
    // proves problematic for real code.
    let mut k = 0;
    loop {
        let Some(p) = index_any(&s[k..], b"(\"'/") else {
            return (c, s.len());
        };
        let i = k + p;
        match s[i] {
            b'(' => {
                // Look for url to the left.
                let p = trim_right(&s[..i], b"\t\n\x0c\r ");
                if ends_with_css_keyword(p, "url") {
                    let mut j = s.len() - trim_left(&s[i + 1..], b"\t\n\x0c\r ").len();
                    if j != s.len() && s[j] == b'"' {
                        c.state = State::CssDqUrl;
                        j += 1;
                    } else if j != s.len() && s[j] == b'\'' {
                        c.state = State::CssSqUrl;
                        j += 1;
                    } else {
                        c.state = State::CssUrl;
                    }
                    return (c, j);
                }
            }
            b'/' => {
                if i + 1 < s.len() {
                    match s[i + 1] {
                        b'/' => {
                            c.state = State::CssLineCmt;
                            return (c, i + 2);
                        }
                        b'*' => {
                            c.state = State::CssBlockCmt;
                            return (c, i + 2);
                        }
                        _ => {}
                    }
                }
            }
            b'"' => {
                c.state = State::CssDqStr;
                return (c, i + 1);
            }
            b'\'' => {
                c.state = State::CssSqStr;
                return (c, i + 1);
            }
            _ => {}
        }
        k = i + 1;
    }
}

/// The context transition function for the CSS string and URL states.
fn t_css_str(mut c: Context, s: &[u8]) -> (Context, usize) {
    // CSS quoted string, URL, or non-URL state.
    let end_and_esc: &[u8] = match c.state {
        State::CssDqStr | State::CssDqUrl => b"\\\"",
        State::CssSqStr | State::CssSqUrl => b"\\'",
        State::CssUrl => b"\\\t\n\x0c\r )",
        other => panic!("{}", other.name()),
    };

    let mut k = 0;
    loop {
        let Some(p) = index_any(&s[k..], end_and_esc) else {
            let (c2, nread) = t_url(c, &decode_css(&s[k..]));
            return (c2, k + nread);
        };
        let mut i = k + p;
        if s[i] == b'\\' {
            i += 1;
            if i == s.len() {
                return (
                    Context::error(errorf(
                        ErrorCode::PartialEscape,
                        None,
                        0,
                        format!(
                            "unfinished escape sequence in CSS string: {}",
                            quote_bytes(s, None)
                        ),
                    )),
                    s.len(),
                );
            }
        } else {
            c.state = State::Css;
            return (c, i + 1);
        }
        let (c2, _) = t_url(c, &decode_css(&s[..i + 1]));
        c = c2;
        k = i + 1;
    }
}

/// The context transition function for the error state.
fn t_error(c: Context, s: &[u8]) -> (Context, usize) {
    (c, s.len())
}

/// The context transition function for the meta content attribute state.
fn t_meta_content(mut c: Context, s: &[u8]) -> (Context, usize) {
    for i in 0..s.len() {
        if i + 3 < s.len() && equal_fold(&s[i..i + 3], b"url") {
            let j = eat_white_space(s, i + 3);
            if j < s.len() && s[j] == b'=' {
                c.state = State::MetaContentUrl;
                return (c, j + 1);
            }
        }
    }
    (c, s.len())
}

/// The context transition function for the meta content URL state.
fn t_meta_content_url(mut c: Context, s: &[u8]) -> (Context, usize) {
    for (i, &b) in s.iter().enumerate() {
        if b == b';' {
            c.state = State::MetaContent;
            return (c, i + 1);
        }
    }
    (c, s.len())
}

/// Returns the index of the end of the attribute name starting at `i`, or an
/// error for bad names.
#[allow(clippy::result_large_err)]
fn eat_attr_name(s: &[u8], i: usize) -> Result<usize, super::error::Error> {
    for j in i..s.len() {
        match s[j] {
            b' ' | b'\t' | b'\n' | 0x0c | b'\r' | b'=' | b'>' => return Ok(j),
            // These are invalid characters in attribute names, but the HTML
            // parser accepts them, so we report an error.
            b'\'' | b'"' | b'<' => {
                return Err(errorf(
                    ErrorCode::BadHtml,
                    None,
                    0,
                    format!(
                        "{} in attribute name: {}",
                        quote_bytes(&s[j..j + 1], None),
                        quote_bytes(s, Some(32))
                    ),
                ));
            }
            _ => {}
        }
    }
    Ok(s.len())
}

fn element_name(name: &str) -> Element {
    match name {
        "script" => Element::Script,
        "style" => Element::Style,
        "textarea" => Element::Textarea,
        "title" => Element::Title,
        "meta" => Element::Meta,
        _ => Element::None,
    }
}

pub(crate) fn ascii_alpha(c: u8) -> bool {
    c.is_ascii_alphabetic()
}

pub(crate) fn ascii_alpha_num(c: u8) -> bool {
    c.is_ascii_alphanumeric()
}

/// Returns the end of the tag name starting at `i` (or `i` if there is none)
/// and the element type of the tag.
fn eat_tag_name(s: &[u8], i: usize) -> (usize, Element) {
    if i == s.len() || !ascii_alpha(s[i]) {
        return (i, Element::None);
    }
    let mut j = i + 1;
    while j < s.len() {
        let x = s[j];
        if ascii_alpha_num(x) {
            j += 1;
            continue;
        }
        // Allow "x-y" or "x:y" but not "x-", "-y", or "x--y".
        if (x == b':' || x == b'-') && j + 1 < s.len() && ascii_alpha_num(s[j + 1]) {
            j += 2;
            continue;
        }
        break;
    }
    (j, element_name(&to_lower_string(&s[i..j])))
}

/// Returns the index of the first non-white-space byte at or after `i`.
pub(crate) fn eat_white_space(s: &[u8], i: usize) -> usize {
    for (j, &c) in s.iter().enumerate().skip(i) {
        match c {
            b' ' | b'\t' | b'\n' | 0x0c | b'\r' => {}
            _ => return j,
        }
    }
    s.len()
}

/// Go's `%q` (with an optional precision in runes) of a byte string.
pub(crate) fn quote_bytes(s: &[u8], prec: Option<usize>) -> String {
    let text = String::from_utf8_lossy(s);
    match prec {
        Some(n) => {
            let t: String = text.chars().take(n).collect();
            strconv::quote(t)
        }
        None => strconv::quote(text.as_ref()),
    }
}

#[allow(dead_code)]
fn unused(_: &[u8]) -> bool {
    has_prefix(&[], &[])
}
