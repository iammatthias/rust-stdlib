use rust_stdlib::mime::{
    add_extension_type, extensions_by_type, format_media_type, parse_media_type, type_by_extension,
    WordEncoder, ERR_INVALID_MEDIA_PARAMETER,
};
use std::collections::BTreeMap;

fn params(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

#[test]
fn parse_media_type_lowercases_and_unquotes() {
    let (media_type, parsed) = parse_media_type("TEXT/PLAIN;  Charset=\"UTF-8\"");
    assert_eq!(media_type, "text/plain");
    assert_eq!(parsed, Ok(params(&[("charset", "UTF-8")])));
}

#[test]
fn parse_media_type_joins_rfc_2231_continuations() {
    let (_, parsed) = parse_media_type("x/y; a*0=foo; a*1=bar");
    assert_eq!(parsed, Ok(params(&[("a", "foobar")])));
    let (_, parsed) = parse_media_type("x/y; t*=utf-8''%E2%82%AC");
    assert_eq!(parsed, Ok(params(&[("t", "€")])));
    let (_, parsed) = parse_media_type("x/y; t*=us-ascii'en'a%20b");
    assert_eq!(parsed, Ok(params(&[("t", "a b")])));
}

#[test]
fn parse_media_type_reports_bad_parameters_with_the_type() {
    let (media_type, parsed) = parse_media_type("text/plain; a");
    assert_eq!(media_type, "text/plain");
    assert_eq!(parsed, Err(ERR_INVALID_MEDIA_PARAMETER));

    let (media_type, parsed) = parse_media_type("x/y; a=b; a=c");
    assert_eq!(media_type, "");
    assert!(parsed.is_err());

    let (media_type, parsed) = parse_media_type("/x");
    assert_eq!(media_type, "");
    assert!(parsed.is_err());

    let (media_type, parsed) = parse_media_type("bogus");
    assert_eq!(media_type, "bogus");
    assert_eq!(parsed, Ok(BTreeMap::new()));
}

#[test]
fn parse_media_type_stops_at_a_trailing_semicolon() {
    let (media_type, parsed) = parse_media_type("x/y;");
    assert_eq!(media_type, "x/y");
    assert_eq!(parsed, Ok(BTreeMap::new()));
}

#[test]
fn format_media_type_quotes_and_encodes_values() {
    assert_eq!(
        format_media_type(
            "Text/Plain",
            &params(&[("Charset", "UTF-8"), ("title", "a b")])
        )
        .as_deref(),
        Some("text/plain; charset=UTF-8; title=\"a b\"")
    );
    assert_eq!(
        format_media_type("x/y", &params(&[("t", "€")])).as_deref(),
        Some("x/y; t*=utf-8''%E2%82%AC")
    );
    assert_eq!(format_media_type("bad type", &BTreeMap::new()), None);
}

#[test]
fn extensions_round_trip_through_the_registry() {
    add_extension_type(".zz-mime-test", "text/X-Zz").unwrap();
    assert_eq!(
        type_by_extension(".ZZ-MIME-TEST").as_deref(),
        Some("text/x-zz; charset=utf-8")
    );
    assert_eq!(
        extensions_by_type("text/x-zz").unwrap(),
        [".zz-mime-test".to_owned()]
    );
    assert!(add_extension_type("zz-mime-test", "text/x-zz").is_err());
    assert!(add_extension_type(".zz-mime-bad", "bad type").is_err());
    assert!(extensions_by_type("bad type").is_err());
}

#[test]
fn word_encoder_constants_select_the_encodings() {
    assert_eq!(WordEncoder::B.encode("utf-8", "é"), "=?utf-8?b?w6k=?=");
    assert_eq!(WordEncoder::Q.encode("utf-8", "é"), "=?utf-8?q?=C3=A9?=");
}
