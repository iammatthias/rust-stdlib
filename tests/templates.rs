use rust_stdlib::encoding::json;
use rust_stdlib::template::HtmlTemplate;
use rust_stdlib::template::TextTemplate;
use rust_stdlib::template::{css_string, javascript_string, Error, Limits, Template, Values};

fn values(pairs: &[(&str, &str)]) -> Values {
    pairs
        .iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

#[test]
fn text_preserves_values_and_unicode() {
    let t = Template::text("Hello {{ user.name }}! {{payload}}").unwrap();
    assert_eq!(
        t.render(&values(&[
            ("user.name", "世界"),
            ("payload", "<>&{{literal}}")
        ]))
        .unwrap(),
        "Hello 世界! <>&{{literal}}"
    );
}

#[test]
fn missing_and_invalid_fields_fail() {
    assert!(matches!(
        Template::text("{{missing}}")
            .unwrap()
            .render(&Values::new()),
        Err(Error::Missing(_))
    ));
    for source in [
        "{{",
        "{{}}",
        "{{0name}}",
        "{{a b}}",
        "{{a|raw}}",
        "{{if a}}",
    ] {
        assert!(Template::text(source).is_err(), "{source}");
    }
}

#[test]
fn html_text_and_quoted_attributes_escape() {
    let t = Template::html("<!DOCTYPE html><p class='{{value}}'>{{value}}</p>").unwrap();
    assert_eq!(
        t.render(&values(&[("value", "\"'><&")])).unwrap(),
        "<!DOCTYPE html><p class='&#34;&#39;&gt;&lt;&amp;'>&#34;&#39;&gt;&lt;&amp;</p>"
    );
}

#[test]
fn urls_check_composed_value_and_preserve_queries() {
    let t = Template::html("<a href=\"{{url}}\">{{label}}</a>").unwrap();
    assert_eq!(
        t.render(&values(&[
            ("url", "https://example.test/?a=1&b=2"),
            ("label", "go")
        ]))
        .unwrap(),
        "<a href=\"https://example.test/?a=1&amp;b=2\">go</a>"
    );
    for url in [
        "javascript:alert(1)",
        "data:text/html,x",
        "java\nscript:x",
        "\\example.test/x",
        "javascript&colon;x",
    ] {
        assert!(
            matches!(
                t.render(&values(&[("url", url), ("label", "x")])),
                Err(Error::UnsafeUrl)
            ),
            "{url:?}"
        );
    }
    let t = Template::html("<a href='java{{middle}}:alert(1)'>x</a>").unwrap();
    assert!(matches!(
        t.render(&values(&[("middle", "script")])),
        Err(Error::UnsafeUrl)
    ));
    let t = Template::html("<a href='javascript&#58;{{value}}'>x</a>").unwrap();
    assert!(matches!(
        t.render(&values(&[("value", "alert(1)")])),
        Err(Error::UnsafeUrl)
    ));
}

#[test]
fn safe_url_schemes_and_relative_references() {
    let t = Template::html("<a href='{{url}}'>x</a>").unwrap();
    for url in [
        "/hello",
        "../hello",
        "?a=b&c=d",
        "#fragment",
        "//example.test/x",
        "HTTPS://example.test",
        "mailto:me@example.test",
        "tel:+1234",
    ] {
        assert!(t.render(&values(&[("url", url)])).is_ok(), "{url}");
    }
}

#[test]
fn active_and_ambiguous_contexts_are_explicit_errors() {
    for source in [
        "<script>const a = {{value}};</script>",
        "<style>p{color:{{value}}}</style>",
        "<p onclick='{{value}}'>x</p>",
        "<p style='{{value}}'>x</p>",
        "<img srcset='{{value}}'>",
        "<iframe srcdoc='{{value}}'></iframe>",
        "<p class={{value}}>x</p>",
        "<!-- {{value}} -->",
        "<{{value}}>x</x>",
        "<svg><text>{{value}}</text></svg>",
        "<meta content='{{value}}'>",
    ] {
        assert!(Template::html(source).is_err(), "{source}");
    }
}

#[test]
fn raw_text_and_rcdata_are_separate_contexts() {
    let t = Template::html(
        "<script>if (a < b) x();</script><textarea>{{value}}</textarea><title>{{value}}</title>",
    )
    .unwrap();
    let rendered = t
        .render(&values(&[(
            "value",
            "</textarea><script>alert(1)</script>",
        )]))
        .unwrap();
    assert!(rendered.contains("<textarea>&lt;/textarea&gt;&lt;script&gt;"));
    assert!(rendered.contains("<script>if (a < b) x();</script>"));
    assert!(Template::html("<script>{{value}}</scriptX></script>").is_err());
    assert!(Template::html("<script/>{{value}}</script>").is_err());
    // HTML's script double-escaped state can ignore an apparent end tag. A
    // template engine must not subsequently treat still-active script as text.
    assert!(Template::html("<script><!--<script></script>{{value}}</script>").is_err());
}

#[test]
fn html_boolean_attributes_and_multiple_fields() {
    let t = Template::html("<input disabled class='{{first}} {{second}}' value=\"{{first}}\">")
        .unwrap();
    assert_eq!(
        t.render(&values(&[("first", "a"), ("second", "b")]))
            .unwrap(),
        "<input disabled class='a b' value=\"a\">"
    );
}

#[test]
fn budgets_apply_to_expanded_escape_output() {
    let limits = Limits {
        source_bytes: 100,
        fields: 1,
        output_bytes: 4,
    };
    assert!(matches!(
        Template::text_with_limits("{{a}}{{b}}", limits),
        Err(Error::Limit("fields"))
    ));
    assert!(matches!(
        Template::html_with_limits("{{a}}", limits)
            .unwrap()
            .render(&values(&[("a", "&")])),
        Err(Error::Limit("output bytes"))
    ));
    assert!(matches!(
        Template::text_with_limits(
            "abc",
            Limits {
                source_bytes: 2,
                ..limits
            }
        ),
        Err(Error::Limit("source bytes"))
    ));
}

#[test]
fn validation_precedes_writer_output() {
    let t = Template::html("prefix<a href='{{url}}'>x</a>").unwrap();
    let mut out = Vec::new();
    assert!(t
        .render_to(&values(&[("url", "javascript:x")]), &mut out)
        .is_err());
    assert!(out.is_empty());
    Template::text("{{value}}")
        .unwrap()
        .render_to(&values(&[("value", "ok")]), &mut out)
        .unwrap();
    assert_eq!(out, b"ok");
}

#[test]
fn standalone_language_string_literals_neutralize_html_end_tags() {
    assert_eq!(
        javascript_string("</script>\n\"\\\u{2028}"),
        "\"\\u003c/script\\u003e\\n\\\"\\\\\\u2028\""
    );
    assert_eq!(
        css_string("</style>\"\\\n"),
        "\"\\3c /style\\3e \\22 \\5c \\a \""
    );
    assert!(!javascript_string("</script>").contains('<'));
    assert!(!css_string("</style>").contains('<'));
}

#[test]
fn malformed_html_source_fails_closed() {
    for source in [
        "<p class='{{x}}",
        "<p{{x}}>",
        "<p / x>",
        "<script>x",
        "<textarea>x",
        "<!--x",
        "<p class=x\"{{x}}>",
    ] {
        assert!(Template::html(source).is_err(), "{source}");
    }
}

#[test]
fn javascript_quoted_interpolation_is_safe_in_both_quote_styles() {
    let template = Template::html("<script>const a='{{x}}'; const b=\"{{x}}\";</script>").unwrap();
    let output = template
        .render(&values(&[("x", "'</script>\\\n\";alert(1)//")]))
        .unwrap();
    assert!(output.contains("\\u0027\\u003c/script\\u003e"));
    assert_eq!(output.matches("</script>").count(), 1);
    for source in [
        "<script>const a=`{{x}}`;</script>",
        "<script>let r=/\"{{x}}\"/;</script>",
        "<script>const a=\"\\{{x}}\";</script>",
        "<script>const a=\"\\u{{x}}\";</script>",
        "<script>const a=\"\\x{{x}}\";</script>",
        "<script type='{{x}}'>const a=\"{{x}}\";</script>",
        "<script>// {{x}}\nconst a=1;</script>",
    ] {
        assert!(Template::html(source).is_err(), "{source}");
    }
}

#[test]
fn css_content_string_interpolation_is_context_checked() {
    let template = Template::html("<style>p::after{content:'{{x}}';}</style>").unwrap();
    let output = template.render(&values(&[("x", "'</style>\\\n")])).unwrap();
    assert!(output.contains("\\27 \\3c /style\\3e "));
    assert_eq!(output.matches("</style>").count(), 1);
    for source in [
        "<style>p{background:url('{{x}}');}</style>",
        "<style>@import '{{x}}';</style>",
        "<style>p{color:{{x}};}</style>",
    ] {
        assert!(Template::html(source).is_err(), "{source}");
    }
}

#[test]
fn structured_text_has_nested_ranges_root_and_conditionals() {
    let template = TextTemplate::parse("{{if enabled}}{{range users}}{{name}}:{{with details}}{{city}}{{end}}:{{$.title}};{{else}}empty{{end}}{{else}}off{{end}}").unwrap();
    let data = (r#"{"enabled":true,"title":"T","users":[{"name":"A","details":{"city":"LA"}},{"name":"B","details":{"city":"NY"}}]}"#).parse::<json::Value>().unwrap();
    assert_eq!(template.render(&data).unwrap(), "A:LA:T;B:NY:T;");
    let data = (r#"{"enabled":true,"title":"T","users":[]}"#)
        .parse::<json::Value>()
        .unwrap();
    assert_eq!(template.render(&data).unwrap(), "empty");
    let data = (r#"{"enabled":false}"#).parse::<json::Value>().unwrap();
    assert_eq!(template.render(&data).unwrap(), "off");
}

#[test]
fn structured_text_iterates_objects_in_order_and_preserves_exact_numbers() {
    let template =
        TextTemplate::parse("{{range items}}{{.}};{{end}}{{if tiny}}yes{{else}}no{{end}}").unwrap();
    let data = (r#"{"items":{"z":9007199254740993,"a":"first"},"tiny":1e-9999}"#)
        .parse::<json::Value>()
        .unwrap();
    assert_eq!(
        template.render(&data).unwrap(),
        "first;9007199254740993;yes"
    );
}

#[test]
fn structured_text_validates_grammar_missing_data_and_budgets() {
    for source in [
        "{{end}}",
        "{{else}}",
        "{{if x}}x",
        "{{range x}}{{else}}{{else}}{{end}}",
        "{{a..b}}",
    ] {
        assert!(TextTemplate::parse(source).is_err(), "{source}");
    }
    let too_deep = format!("{}x{}", "{{if x}}".repeat(65), "{{end}}".repeat(65));
    assert!(matches!(
        TextTemplate::parse(&too_deep),
        Err(Error::Limit("template nesting"))
    ));
    let data = (r#"{"items":["ab","cd"]}"#).parse::<json::Value>().unwrap();
    let template = TextTemplate::parse_with_limits(
        "{{range items}}{{.}}{{end}}",
        Limits {
            output_bytes: 3,
            ..Limits::default()
        },
    )
    .unwrap();
    assert!(matches!(
        template.render(&data),
        Err(Error::Limit("output bytes"))
    ));
    assert!(TextTemplate::parse("{{missing}}")
        .unwrap()
        .render(&data)
        .is_err());
}

#[test]
fn structured_html_renders_nested_lists_with_contextual_escaping() {
    let template = HtmlTemplate::parse("<ul>{{range users}}<li><a href='{{url}}'>{{name}}</a>{{if active}}<b>{{$.label}}</b>{{end}}</li>{{else}}<li>empty</li>{{end}}</ul>").unwrap();
    let data = (r#"{"label":"<active>","users":[{"name":"<script>","url":"https://example.test/?a=1&b=2","active":true}]}"#).parse::<json::Value>().unwrap();
    assert_eq!(template.render(&data).unwrap(), "<ul><li><a href='https://example.test/?a=1&amp;b=2'>&lt;script&gt;</a><b>&lt;active&gt;</b></li></ul>");
    let data = (r#"{"users":[]}"#).parse::<json::Value>().unwrap();
    assert_eq!(template.render(&data).unwrap(), "<ul><li>empty</li></ul>");
}

#[test]
fn html_branches_cannot_change_lexical_context_or_bypass_url_policy() {
    for source in [
        "<a href='{{if x}}a{{else}}b{{end}}'>x</a>",
        "<script>{{if x}}'{{value}}'{{end}}</script>",
        "{{if x}}<script>{{else}}<p>{{end}}{{value}}",
    ] {
        assert!(HtmlTemplate::parse(source).is_err(), "{source}");
    }
    let template = HtmlTemplate::parse("{{if x}}<a href='{{url}}'>x</a>{{end}}").unwrap();
    let data = (r#"{"x":true,"url":"javascript:alert(1)"}"#)
        .parse::<json::Value>()
        .unwrap();
    assert!(matches!(template.render(&data), Err(Error::UnsafeUrl)));
}

#[test]
fn pipelines_and_typed_functions_execute_live_values() {
    let template = TextTemplate::parse("{{name | upper | lower}}:{{len items}}:{{items | join \",\"}}:{{index items 1}}:{{if eq name \"A\"}}equal{{end}}:{{\"}}|héllo\"}}").unwrap();
    let data = (r#"{"name":"A","items":["first","second"]}"#)
        .parse::<json::Value>()
        .unwrap();
    assert_eq!(
        template.render(&data).unwrap(),
        "a:2:first,second:second:equal:}}|héllo"
    );
    let template = TextTemplate::parse("{{and false missing}}/{{or \"ok\" missing}}").unwrap();
    assert_eq!(template.render(&data).unwrap(), "false/ok");
}

#[test]
fn trusted_registered_functions_remain_html_escaped_and_fail_cleanly() {
    fn markup(args: &[&json::Value]) -> Result<json::Value, String> {
        if args.len() != 1 {
            return Err("requires one argument".into());
        }
        Ok(json::Value::from("<script>alert(1)</script>"))
    }
    fn failure(_: &[&json::Value]) -> Result<json::Value, String> {
        Err("deliberate failure".into())
    }
    let mut template = HtmlTemplate::parse("<p>{{name | markup}}</p>").unwrap();
    template.functions_mut().register("markup", markup).unwrap();
    assert!(template
        .functions_mut()
        .register("markup", failure)
        .is_err());
    let data = (r#"{"name":"x"}"#).parse::<json::Value>().unwrap();
    assert_eq!(
        template.render(&data).unwrap(),
        "<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>"
    );
    let mut template = TextTemplate::parse("{{failure()}}").unwrap();
    template
        .functions_mut()
        .register("failure", failure)
        .unwrap();
    assert!(template
        .render(&data)
        .unwrap_err()
        .to_string()
        .contains("function failure: deliberate failure"));
    assert!(template.functions_mut().register("upper", failure).is_err());
}

#[test]
fn pipeline_diagnostics_and_function_result_limits() {
    let data = (r#"{"name":"abc","items":[]}"#)
        .parse::<json::Value>()
        .unwrap();
    for source in [
        "{{name |}}",
        "{{| upper}}",
        "{{eq name \"x}}",
        "{{name || upper}}",
        "{{upper name \"extra\"}}",
        "{{name | absent}}",
        "{{index items 0}}",
    ] {
        let result = TextTemplate::parse(source).and_then(|t| t.render(&data));
        assert!(result.is_err(), "{source}");
    }
    fn large(_: &[&json::Value]) -> Result<json::Value, String> {
        Ok(json::Value::from("12345"))
    }
    let mut template = TextTemplate::parse_with_limits(
        "{{large()}}",
        Limits {
            output_bytes: 4,
            ..Limits::default()
        },
    )
    .unwrap();
    template.functions_mut().register("large", large).unwrap();
    assert!(matches!(
        template.render(&data),
        Err(Error::Limit("function result bytes"))
    ));
}

#[test]
fn zero_byte_function_outputs_still_consume_work_budget() {
    let items = json::Value::Array(vec![json::Value::from(""); 1_000_001]);
    let data = json::Value::object([("items", items)]);
    let template = TextTemplate::parse("{{join items \"\"}}").unwrap();
    assert!(template
        .render(&data)
        .unwrap_err()
        .to_string()
        .contains("render operations"));
}

#[test]
fn html_branches_reject_comment_and_rcdata_context_changes() {
    for source in [
        "<!--{{if enabled}}x{{end}}-->",
        "<textarea>{{if enabled}}x{{end}}</textarea>",
        "<style>p{content:'{{if enabled}}x{{end}}';}</style>",
        "{{if enabled}}<!--{{else}}<p>{{end}}{{value}}",
    ] {
        assert!(HtmlTemplate::parse(source).is_err(), "{source}");
    }
    let template=HtmlTemplate::parse("{{if enabled}}<script>let value='{{value | upper}}';</script>{{else}}<p>{{value}}</p>{{end}}").unwrap();
    let data = (r#"{"enabled":true,"value":"</script>"}"#)
        .parse::<json::Value>()
        .unwrap();
    assert_eq!(
        template.render(&data).unwrap(),
        "<script>let value='\\u003c/SCRIPT\\u003e';</script>"
    );
}
