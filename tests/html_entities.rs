use rust_stdlib::html;

#[test]
fn decodes_named_entities_and_two_scalar_values() {
    assert_eq!(html::unescape("&amp;&lt;&gt;&quot;&apos;"), "&<>\"'");
    assert_eq!(html::unescape("&NotEqualTilde; &acE;"), "≂̸ ∾̳");
    assert_eq!(html::unescape("&AMP; &amp;"), "& &");
}

#[test]
fn accepts_only_go_compatible_legacy_prefixes() {
    assert_eq!(html::unescape("&amp &copy! &notit;"), "& ©! ¬it;");
    assert_eq!(html::unescape("&notin; &notin &notit="), "∉ ¬in ¬it=");
    assert_eq!(
        html::unescape("&unknown; &&; &; &#x; &#;"),
        "&unknown; &&; &; � &#;"
    );
}

#[test]
fn applies_html_numeric_reference_replacements() {
    assert_eq!(
        html::unescape("&#0; &#xD800; &#x110000; &#128; &#x80; &#13;"),
        "� � � € € \r"
    );
    assert_eq!(html::unescape("&#65 &#x41! &#X1f642;"), "A A! 🙂");
    assert_eq!(html::unescape("&#x; &#xyz; &#;"), "� &#xyz; &#;");
}

#[test]
fn preserves_non_references_and_escape_is_unchanged() {
    assert_eq!(html::unescape("plain & lone & 100%"), "plain & lone & 100%");
    assert_eq!(html::escape("<&>\"'"), "&lt;&amp;&gt;&#34;&#39;");
}
