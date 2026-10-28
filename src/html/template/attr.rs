//! Attribute content types (Go `html/template` `attr.go`).

use super::content::ContentType;

/// The content type of the named attribute, from the HTML specification's
/// attribute index; unknown names fall back on name patterns.
fn attr_type_map(name: &str) -> Option<ContentType> {
    use ContentType::{Css, Html, Plain, Srcset, Unsafe, Url};
    Some(match name {
        "accept" => Plain,
        "accept-charset" => Unsafe,
        "action" => Url,
        "alt" => Plain,
        "archive" => Url,
        "async" => Unsafe,
        "autocomplete" => Plain,
        "autofocus" => Plain,
        "autoplay" => Plain,
        "background" => Url,
        "border" => Plain,
        "checked" => Plain,
        "cite" => Url,
        "challenge" => Unsafe,
        "charset" => Unsafe,
        "class" => Plain,
        "classid" => Url,
        "codebase" => Url,
        "cols" => Plain,
        "colspan" => Plain,
        "content" => Unsafe,
        "contenteditable" => Plain,
        "contextmenu" => Plain,
        "controls" => Plain,
        "coords" => Plain,
        "crossorigin" => Unsafe,
        "data" => Url,
        "datetime" => Plain,
        "default" => Plain,
        "defer" => Unsafe,
        "dir" => Plain,
        "dirname" => Plain,
        "disabled" => Plain,
        "draggable" => Plain,
        "dropzone" => Plain,
        "enctype" => Unsafe,
        "for" => Plain,
        "form" => Unsafe,
        "formaction" => Url,
        "formenctype" => Unsafe,
        "formmethod" => Unsafe,
        "formnovalidate" => Unsafe,
        "formtarget" => Plain,
        "headers" => Plain,
        "height" => Plain,
        "hidden" => Plain,
        "high" => Plain,
        "href" => Url,
        "hreflang" => Plain,
        "http-equiv" => Unsafe,
        "icon" => Url,
        "id" => Plain,
        "ismap" => Plain,
        "keytype" => Unsafe,
        "kind" => Plain,
        "label" => Plain,
        "lang" => Plain,
        "language" => Unsafe,
        "list" => Plain,
        "longdesc" => Url,
        "loop" => Plain,
        "low" => Plain,
        "manifest" => Url,
        "max" => Plain,
        "maxlength" => Plain,
        "media" => Plain,
        "mediagroup" => Plain,
        "method" => Unsafe,
        "min" => Plain,
        "multiple" => Plain,
        "name" => Plain,
        "novalidate" => Unsafe,
        // Skip handler names from
        // https://www.w3.org/TR/html5/webappapis.html#event-handlers-on-elements,-document-objects,-and-window-objects
        // since we have special handling in attrType.
        "open" => Plain,
        "optimum" => Plain,
        "pattern" => Unsafe,
        "placeholder" => Plain,
        "poster" => Url,
        "profile" => Url,
        "preload" => Plain,
        "pubdate" => Plain,
        "radiogroup" => Plain,
        "readonly" => Plain,
        "rel" => Unsafe,
        "required" => Plain,
        "reversed" => Plain,
        "rows" => Plain,
        "rowspan" => Plain,
        "sandbox" => Unsafe,
        "spellcheck" => Plain,
        "scope" => Plain,
        "scoped" => Plain,
        "seamless" => Plain,
        "selected" => Plain,
        "shape" => Plain,
        "size" => Plain,
        "sizes" => Plain,
        "span" => Plain,
        "src" => Url,
        "srcdoc" => Html,
        "srclang" => Plain,
        "srcset" => Srcset,
        "start" => Plain,
        "step" => Plain,
        "style" => Css,
        "tabindex" => Plain,
        "target" => Plain,
        "title" => Plain,
        "type" => Unsafe,
        "usemap" => Url,
        "value" => Unsafe,
        "width" => Plain,
        "wrap" => Plain,
        "xmlns" => Url,
        _ => return None,
    })
}

/// Returns the content type of the attribute with the given (lower case)
/// name.
pub(crate) fn attr_type(name: &str) -> ContentType {
    let mut name = name;
    if let Some(rest) = name.strip_prefix("data-") {
        // Strip data- so that custom attribute heuristics below are
        // widely applied.
        // Treat data-action as URL below.
        name = rest;
    } else if let Some((prefix, short)) = name.split_once(':') {
        if prefix == "xmlns" {
            return ContentType::Url;
        }
        // Treat svg:href and xlink:href as href below.
        name = short;
    }
    if let Some(t) = attr_type_map(name) {
        return t;
    }
    if name.starts_with("on") {
        return ContentType::Js;
    }
    // Heuristics to prevent "javascript:..." injection in custom data
    // attributes and custom attributes like g:tweetUrl.
    if name.contains("src") || name.contains("uri") || name.contains("url") {
        return ContentType::Url;
    }
    ContentType::Plain
}
