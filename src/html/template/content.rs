//! Typed content (Go `html/template` `content.go`).
//!
//! The typed strings [`Css`], [`Html`], [`HtmlAttr`], [`Js`], [`JsStr`],
//! [`Url`] and [`Srcset`] encapsulate known safe content that need not be
//! escaped. Go's types are defined string types; here each is a newtype that
//! converts into a template [`Value`] of the corresponding named type.
//!
//! Using these types is a security obligation: the content must satisfy the
//! contract documented for each type, because the template engine will not
//! escape it.

use crate::text::template::value::{Kind, ToValue, Type, Value};
use crate::text::template::verbs;
use std::sync::OnceLock;

macro_rules! content_types {
    ($($(#[$doc:meta])* $t:ident, $f:ident, $name:literal;)+) => { $(
        $(#[$doc])*
        #[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
        pub struct $t(pub String);

        impl From<&str> for $t {
            fn from(s: &str) -> $t {
                $t(s.to_owned())
            }
        }
        impl From<String> for $t {
            fn from(s: String) -> $t {
                $t(s)
            }
        }
        impl ToValue for $t {
            fn go_type() -> Type {
                $f()
            }
            fn to_value(&self) -> Value {
                Value::string_of(&$f(), &self.0)
            }
        }
        /// The template value type of the content type.
        pub fn $f() -> Type {
            static T: OnceLock<Type> = OnceLock::new();
            T.get_or_init(|| Type::named("template", $name, Type::string(), Vec::new()))
                .clone()
        }
    )+ };
}

content_types! {
    /// Encapsulates known safe content that matches any of:
    ///  1. The CSS3 stylesheet production, such as `p { color: purple }`.
    ///  2. The CSS3 rule production, such as `a[href=~"https:"].foo#bar`.
    ///  3. CSS3 declaration productions, such as `color: red; margin: 2px`.
    ///  4. The CSS3 value production, such as `rgba(0, 0, 255, 127)`.
    ///
    /// See <https://www.w3.org/TR/css-syntax-3/#parsing> and
    /// <https://web.archive.org/web/20090211114933/http://w3.org/TR/css3-syntax#style>.
    Css, css_type, "CSS";
    /// Encapsulates a known safe HTML document fragment. It should not be used
    /// for HTML from a third-party, or HTML with unclosed tags or comments.
    /// The outputs of a sound HTML sanitizer and a template escaped by this
    /// package are fine for use with `Html`.
    Html, html_type, "HTML";
    /// Encapsulates an HTML attribute from a trusted source, for example
    /// ` dir="ltr"`.
    HtmlAttr, html_attr_type, "HTMLAttr";
    /// Encapsulates a known safe EcmaScript5 Expression, for example
    /// `(x + y * z())`. Template authors are responsible for ensuring that
    /// typed expressions do not break the intended precedence and that there
    /// is no statement/expression ambiguity as when passing an expression like
    /// `{ foo: bar() }\n['foo']()`, which is both a valid Expression and a
    /// valid Program with a very different meaning.
    Js, js_type, "JS";
    /// Encapsulates a sequence of characters meant to be embedded between
    /// quotes in a JavaScript expression. The string must match a series of
    /// StringCharacters: StringCharacter :: SourceCharacter but not `\` or
    /// LineTerminator | EscapeSequence. Note that LineContinuations are not
    /// allowed. `JsStr("foo\\nbar")` is fine, but `JsStr("foo\\\nbar")` is
    /// not.
    JsStr, js_str_type, "JSStr";
    /// Encapsulates a known safe URL or URL substring (see RFC 3986). A URL
    /// like `javascript:checkThatFormNotEditedBeforeLeavingPage()` from a
    /// trusted source should go in the page, but by default dynamic
    /// `javascript:` URLs are filtered out since they are a frequently
    /// exploited injection vector.
    Url, url_type, "URL";
    /// Encapsulates a known safe srcset attribute (see
    /// <https://w3c.github.io/html/semantics-embedded-content.html#element-attrdef-img-srcset>).
    Srcset, srcset_type, "Srcset";
}

/// The kind of content a string holds (Go `contentType`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ContentType {
    Plain,
    Css,
    Html,
    HtmlAttr,
    Js,
    JsStr,
    Url,
    Srcset,
    /// Unsafe is used in attr.go for values that affect how embedded content
    /// and network messages are formed, vetted, or interpreted; or which
    /// credentials network messages carry.
    Unsafe,
}

/// Dereferences all pointers: the pointee of a pointer to a typed string is
/// typed content. Returns the dynamic value.
pub(crate) fn indirect(a: &Value) -> Value {
    let mut v = a.interface();
    if !v.is_valid() || v.kind() != Kind::Pointer {
        return v;
    }
    while v.kind() == Kind::Pointer && !v.is_nil() {
        v = v.elem();
    }
    v.interface()
}

/// Like [`indirect`] but stops at a pointer that implements `fmt.Stringer` or
/// `error`.
pub(crate) fn indirect_to_stringer_or_error(a: &Value) -> Value {
    let mut v = a.interface();
    if !v.is_valid() {
        return v;
    }
    while v.kind() == Kind::Pointer
        && !v.is_nil()
        && !v.type_().expect("valid").implements(&Type::stringer())
        && !v.type_().expect("valid").implements(&Type::error())
    {
        v = v.elem();
    }
    v.interface()
}

/// Converts the arguments to a string and reports the content type of the
/// result (Go `stringify`).
pub(crate) fn stringify(args: &[Value]) -> (String, ContentType) {
    if args.len() == 1 {
        let s = indirect(&args[0]);
        if let Some(t) = s.type_() {
            let content = if *t == Type::string() {
                Some(ContentType::Plain)
            } else if *t == css_type() {
                Some(ContentType::Css)
            } else if *t == html_type() {
                Some(ContentType::Html)
            } else if *t == html_attr_type() {
                Some(ContentType::HtmlAttr)
            } else if *t == js_type() {
                Some(ContentType::Js)
            } else if *t == js_str_type() {
                Some(ContentType::JsStr)
            } else if *t == url_type() {
                Some(ContentType::Url)
            } else if *t == srcset_type() {
                Some(ContentType::Srcset)
            } else {
                None
            };
            if let Some(c) = content {
                return (s.as_string(), c);
            }
        }
    }
    let mut converted = Vec::with_capacity(args.len());
    for arg in args {
        let a = arg.interface();
        if !a.is_valid() {
            continue;
        }
        converted.push(indirect_to_stringer_or_error(&a));
    }
    (verbs::sprint(&converted), ContentType::Plain)
}
