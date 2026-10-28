#![no_main]
#![forbid(unsafe_code)]
use libfuzzer_sys::fuzz_target;
use rust_stdlib::{
    encoding::{csv, json, xml},
    html, path, tabwriter, template,
};
use std::io::Write;
fuzz_target!(|data: &[u8]| {
    if data.len() > 8192 {
        return;
    }
    if let Ok(value) = json::Value::try_from(data) {
        let wire = json::marshal(&value).unwrap();
        assert_eq!(json::Value::try_from(&wire[..]).unwrap(), value);
    }
    let mut reader = csv::Reader::new(data);
    reader.limits = csv::Limits {
        max_bytes: 8192,
        max_record_bytes: 8192,
        max_field_bytes: 8192,
        max_records: 4096,
        ..Default::default()
    };
    while matches!(reader.read(), Ok(Some(_))) {}
    // Go-compatible tokenizer: any input terminates, with or without strictness.
    let mut decoder = xml::Decoder::new(data);
    decoder.strict = data.first().is_none_or(|b| b & 1 == 0);
    decoder.max_depth = 64;
    decoder.max_token_bytes = 8192;
    for _ in 0..4096 {
        if decoder.token().is_err() {
            break;
        }
    }
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(duration) = text.parse::<rust_stdlib::time::Duration>() {
            assert_eq!(
                duration
                    .to_string()
                    .parse::<rust_stdlib::time::Duration>()
                    .unwrap(),
                duration
            );
        }
        assert_eq!(html::unescape(&html::escape(text)), text);
        let _ = html::unescape(text);
        let cleaned = path::clean(text);
        assert_eq!(path::clean(&cleaned), cleaned);
        if text.len() <= 256 {
            let _ = path::matches(text, text);
        }
        let mut values = template::Values::new();
        values.insert("x".into(), text.to_owned());
        for t in [
            template::Template::html(text),
            template::Template::text(text),
        ]
        .into_iter()
        .flatten()
        {
            let _ = t.render(&values);
        }
        let model = json::Value::object([
            ("x", json::Value::String(text.to_owned())),
            (
                "items",
                json::Value::Array(vec![
                    json::Value::String(text.to_owned()),
                    json::Value::String("☃".into()),
                ]),
            ),
        ]);
        fn identity(args: &[&json::Value]) -> Result<json::Value, String> {
            args.first()
                .map(|value| (*value).clone())
                .ok_or_else(|| "argument required".to_owned())
        }
        let limits = template::Limits {
            source_bytes: 8192,
            fields: 4096,
            output_bytes: 65536,
        };
        if let Ok(mut t) = template::TextTemplate::parse_with_limits(text, limits) {
            t.functions_mut().register("identity", identity).unwrap();
            let _ = t.render(&model);
        }
        if let Ok(mut t) = template::HtmlTemplate::parse_with_limits(text, limits) {
            t.functions_mut().register("identity", identity).unwrap();
            let _ = t.render(&model);
        }
        // Go's regexp matches in linear time and enforces its own pattern limits.
        if let Ok(regex) = rust_stdlib::regexp::compile(text) {
            let _ = regex.find_string("☃ aa abc 123\n");
            let _ = regex.find_string(text);
        }
        let _ = template::javascript_string(text);
        let _ = template::css_string(text);
    }
    let mut aligned = tabwriter::TabWriter::new(Vec::new(), 0, 8, 1, b' ', 0).unwrap();
    let _ = aligned.write_all(data);
    let _ = aligned.into_inner();
});
