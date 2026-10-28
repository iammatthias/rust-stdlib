//! Escaping contexts (Go `html/template` `context.go`).
//!
//! A context describes the state of the HTML parser immediately before or
//! after a point in a template's output.

use super::error::Error;
use crate::text::template::parse::Node;
use std::fmt;
use std::sync::{Arc, Mutex};

macro_rules! string_enum {
    ($(#[$m:meta])* $name:ident, $go:literal, { $($v:ident = $s:literal),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
        #[repr(u8)]
        pub(crate) enum $name {
            #[default]
            $($v),+
        }
        impl $name {
            /// Go's `String` form, such as `stateText`.
            pub(crate) fn name(self) -> &'static str {
                match self { $($name::$v => $s),+ }
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.name())
            }
        }
    };
}

// The first state is the default (Go's zero value).
string_enum!(
    /// A context's parser state.
    State, "state", {
    Text = "stateText",
    Tag = "stateTag",
    AttrName = "stateAttrName",
    AfterName = "stateAfterName",
    BeforeValue = "stateBeforeValue",
    HtmlCmt = "stateHTMLCmt",
    Rcdata = "stateRCDATA",
    Attr = "stateAttr",
    Url = "stateURL",
    Srcset = "stateSrcset",
    Js = "stateJS",
    JsDqStr = "stateJSDqStr",
    JsSqStr = "stateJSSqStr",
    JsTmplLit = "stateJSTmplLit",
    JsRegexp = "stateJSRegexp",
    JsBlockCmt = "stateJSBlockCmt",
    JsLineCmt = "stateJSLineCmt",
    JsHtmlOpenCmt = "stateJSHTMLOpenCmt",
    JsHtmlCloseCmt = "stateJSHTMLCloseCmt",
    Css = "stateCSS",
    CssDqStr = "stateCSSDqStr",
    CssSqStr = "stateCSSSqStr",
    CssDqUrl = "stateCSSDqURL",
    CssSqUrl = "stateCSSSqURL",
    CssUrl = "stateCSSURL",
    CssBlockCmt = "stateCSSBlockCmt",
    CssLineCmt = "stateCSSLineCmt",
    Error = "stateError",
    MetaContent = "stateMetaContent",
    MetaContentUrl = "stateMetaContentURL",
    Dead = "stateDead",
});

string_enum!(
    /// What ends an attribute value.
    Delim, "delim", {
    None = "delimNone",
    DoubleQuote = "delimDoubleQuote",
    SingleQuote = "delimSingleQuote",
    SpaceOrTagEnd = "delimSpaceOrTagEnd",
});

string_enum!(
    /// Which part of a URL the output is in.
    UrlPart, "urlPart", {
    None = "urlPartNone",
    PreQuery = "urlPartPreQuery",
    QueryOrFrag = "urlPartQueryOrFrag",
    Unknown = "urlPartUnknown",
});

string_enum!(
    /// What the next JavaScript slash means.
    JsCtx, "jsCtx", {
    Regexp = "jsCtxRegexp",
    DivOp = "jsCtxDivOp",
    Unknown = "jsCtxUnknown",
});

string_enum!(
    /// The special element the parser is in.
    Element, "element", {
    None = "elementNone",
    Script = "elementScript",
    Style = "elementStyle",
    Textarea = "elementTextarea",
    Title = "elementTitle",
    Meta = "elementMeta",
});

string_enum!(
    /// The kind of attribute the parser is in.
    Attr, "attr", {
    None = "attrNone",
    Script = "attrScript",
    ScriptType = "attrScriptType",
    Style = "attrStyle",
    Url = "attrURL",
    Srcset = "attrSrcset",
    MetaContent = "attrMetaContent",
});

/// A shared, mutable escaping error: contexts compare errors by identity, and
/// the escaper fills in names and lines after the fact.
pub(crate) type SharedError = Arc<Mutex<Error>>;

/// Describes the state of the HTML parser immediately before or after a point
/// in the parse tree.
#[derive(Clone, Debug, Default)]
pub(crate) struct Context {
    pub state: State,
    pub delim: Delim,
    pub url_part: UrlPart,
    pub js_ctx: JsCtx,
    /// Tracks the brace depth of `${}` interpolations in nested JS template
    /// literals. `None` is Go's nil slice.
    pub js_brace_depth: Option<Vec<i32>>,
    pub attr: Attr,
    pub element: Element,
    /// The break or continue node, for range loops.
    pub n: Option<Node>,
    pub err: Option<SharedError>,
}

impl Context {
    pub fn new(state: State) -> Context {
        Context {
            state,
            ..Context::default()
        }
    }

    pub fn error(err: Error) -> Context {
        Context {
            state: State::Error,
            err: Some(Arc::new(Mutex::new(err))),
            ..Context::default()
        }
    }

    fn depth(&self) -> &[i32] {
        self.js_brace_depth.as_deref().unwrap_or(&[])
    }

    /// Reports whether two contexts are equal (Go `context.eq`).
    pub fn eq(&self, d: &Context) -> bool {
        self.state == d.state
            && self.delim == d.delim
            && self.url_part == d.url_part
            && self.js_ctx == d.js_ctx
            && self.depth() == d.depth()
            && self.attr == d.attr
            && self.element == d.element
            && match (&self.err, &d.err) {
                (None, None) => true,
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                _ => false,
            }
    }

    /// Returns a string that encodes the context, for naming derived
    /// templates (Go `context.mangle`).
    pub fn mangle(&self, template_name: &str) -> String {
        // The mangled name for the default context is the input template name.
        if self.state == State::Text {
            return template_name.to_owned();
        }
        let mut s = format!("{template_name}$htmltemplate_{}", self.state);
        if self.delim != Delim::None {
            s.push('_');
            s.push_str(self.delim.name());
        }
        if self.url_part != UrlPart::None {
            s.push('_');
            s.push_str(self.url_part.name());
        }
        if self.js_ctx != JsCtx::Regexp {
            s.push('_');
            s.push_str(self.js_ctx.name());
        }
        if let Some(d) = &self.js_brace_depth {
            s.push_str(&format!("_jsBraceDepth({})", fmt_ints(d)));
        }
        if self.attr != Attr::None {
            s.push('_');
            s.push_str(self.attr.name());
        }
        if self.element != Element::None {
            s.push('_');
            s.push_str(self.element.name());
        }
        s
    }
}

/// Formats a slice of ints as `%v` does: `[1 2 3]`.
fn fmt_ints(d: &[i32]) -> String {
    let parts: Vec<String> = d.iter().map(i32::to_string).collect();
    format!("[{}]", parts.join(" "))
}

impl fmt::Display for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let err = match &self.err {
            Some(e) => e.lock().expect("error lock").to_string(),
            None => "<nil>".to_owned(),
        };
        write!(
            f,
            "{{{} {} {} {} {} {} {} {}}}",
            self.state,
            self.delim,
            self.url_part,
            self.js_ctx,
            fmt_ints(self.depth()),
            self.attr,
            self.element,
            err
        )
    }
}

/// Reports whether the state is a comment state.
pub(crate) fn is_comment(s: State) -> bool {
    matches!(
        s,
        State::HtmlCmt
            | State::JsBlockCmt
            | State::JsLineCmt
            | State::JsHtmlOpenCmt
            | State::JsHtmlCloseCmt
            | State::CssBlockCmt
            | State::CssLineCmt
    )
}

/// Reports whether the state occurs solely inside an HTML tag.
pub(crate) fn is_in_tag(s: State) -> bool {
    matches!(
        s,
        State::Tag | State::AttrName | State::AfterName | State::BeforeValue | State::Attr
    )
}

/// Reports whether the given state is a JS literal.
pub(crate) fn is_in_script_literal(s: State) -> bool {
    matches!(
        s,
        State::JsDqStr | State::JsSqStr | State::JsTmplLit | State::JsRegexp
    )
}
