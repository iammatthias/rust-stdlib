//! Ports of Go's `expvar` tests (`expvar_test.go`). The registry is
//! process-wide and tests run in parallel, so every test publishes under
//! names of its own; Go's `RemoveAll` helper is internal and not used.
use rust_stdlib::encoding::json::{self, Value};
use rust_stdlib::expvar::{self, Float, Func, Int, Map, String as StringVar, Var};
use std::sync::{Arc, Mutex};

fn as_int(v: Option<Arc<dyn Var>>) -> Option<i64> {
    let v = v?;
    v.as_int().map(Int::value)
}

#[test]
fn nil() {
    assert!(expvar::get("expvar-test-missing").is_none());
}

#[test]
fn int() {
    let reqs = expvar::Int::published("expvar-test-requests");
    assert_eq!(reqs.value(), 0);
    assert_eq!(
        as_int(expvar::get("expvar-test-requests")),
        Some(0),
        "Get() failed"
    );

    reqs.add(1);
    reqs.add(3);
    assert_eq!(reqs.value(), 4);
    assert_eq!(reqs.to_string(), "4");

    reqs.set(-2);
    assert_eq!(reqs.value(), -2);
}

#[test]
fn int_wraps_on_overflow() {
    let v = Int::default();
    v.set(i64::MAX);
    v.add(1);
    assert_eq!(v.value(), i64::MIN);
}

#[test]
fn float() {
    let reqs = expvar::Float::published("expvar-test-requests-float");
    assert_eq!(reqs.value(), 0.0);
    reqs.add(1.5);
    reqs.add(1.25);
    assert_eq!(reqs.value(), 2.75);
    assert_eq!(reqs.to_string(), "2.75");
    reqs.add(-2.0);
    assert_eq!(reqs.value(), 0.75);
}

#[test]
fn float_string_follows_go_g_format() {
    let f = Float::default();
    for (value, want) in [
        (1e6, "1e+06"),
        (1e21, "1e+21"),
        (0.1 + 0.2, "0.30000000000000004"),
        (-0.0, "-0"),
        (f64::INFINITY, "+Inf"),
        (f64::NAN, "NaN"),
    ] {
        f.set(value);
        assert_eq!(f.to_string(), want, "String of {value}");
    }
}

#[test]
fn string() {
    let name = expvar::String::published("expvar-test-my-name");
    assert_eq!(name.value(), "");

    name.set("Mike");
    assert_eq!(name.to_string(), r#""Mike""#, "name.String()");
    assert_eq!(name.value(), "Mike", "name.Value()");

    // Make sure we produce safe JSON output.
    name.set("<");
    assert_eq!(name.to_string(), "\"\\u003c\"");
}

#[test]
fn map_init() {
    let colors = expvar::Map::published("expvar-test-init-colors");
    colors.add("red", 1);
    colors.add("blue", 1);
    colors.add("chartreuse", 1);

    let mut n = 0;
    for _ in colors.iter() {
        n += 1;
    }
    assert_eq!(n, 3);

    colors.init();

    let mut n = 0;
    for _ in colors.iter() {
        n += 1;
    }
    assert_eq!(n, 0);
}

#[test]
fn map_delete() {
    let colors = expvar::Map::published("expvar-test-delete-colors");

    colors.add("red", 1);
    colors.add("red", 2);
    colors.add("blue", 4);

    let count = |m: &Map| {
        let mut n = 0;
        for _ in m.iter() {
            n += 1;
        }
        n
    };
    assert_eq!(count(&colors), 2);

    colors.delete("red");
    assert!(colors.get("red").is_none());
    assert_eq!(count(&colors), 1);

    colors.delete("notfound");
    assert_eq!(count(&colors), 1);

    colors.delete("blue");
    colors.delete("blue");
    assert!(colors.get("blue").is_none());
    assert_eq!(count(&colors), 0);
}

#[test]
fn map_counter() {
    let colors = expvar::Map::published("expvar-test-counter-colors");

    colors.add("red", 1);
    colors.add("red", 2);
    colors.add("blue", 4);
    colors.add_float(r#"green "midori""#, 4.125);
    assert_eq!(as_int(colors.get("red")), Some(3));
    assert_eq!(as_int(colors.get("blue")), Some(4));
    let green = colors
        .get(r#"green "midori""#)
        .and_then(|v| v.as_float().map(Float::value));
    assert_eq!(green, Some(4.125));

    // colors.String() should be '{"red":3, "blue":4}', though the order of
    // red and blue could vary.
    let parsed = colors
        .to_string()
        .parse::<json::Value>()
        .expect("colors.String() is valid JSON");
    let red = parsed.get("red").and_then(|v| match v {
        Value::Number(n) => n.int64().ok(),
        _ => None,
    });
    assert_eq!(red, Some(3));
}

#[test]
fn map_add_ignores_other_types() {
    let m = Map::default();
    m.set("name", Arc::new(StringVar::default()));
    m.add("name", 5);
    m.add_float("name", 5.0);
    assert_eq!(
        m.get("name").map(|v| v.to_string()),
        Some("\"\"".to_string())
    );
}

#[test]
fn func() {
    let x = Arc::new(Mutex::new(Value::Array(vec![
        Value::from("a"),
        Value::from("b"),
    ])));
    let shared = Arc::clone(&x);
    let f = Func::new(move || shared.lock().unwrap().clone());
    assert_eq!(f.to_string(), r#"["a","b"]"#);
    assert_eq!(f.value(), *x.lock().unwrap());
    *x.lock().unwrap() = Value::Number(json::Number::new("17").unwrap());
    assert_eq!(f.to_string(), "17");
}

#[cfg(feature = "net")]
#[test]
fn handler() {
    use rust_stdlib::net::http::Handler;
    let m = expvar::Map::published("expvar-test-handler-map1");
    m.add("a", 1);
    m.add("z", 2);
    let m2 = expvar::Map::published("expvar-test-handler-map2");
    for i in 0..9 {
        m2.add(&i.to_string(), i);
    }

    let mut request = rust_stdlib::net::http::httptest::request("GET", "/debug/vars", None)
        .expect("valid request");
    let mut recorder = rust_stdlib::net::http::httptest::ResponseRecorder::new();
    expvar::handler().serve_http(&mut recorder, &mut request);
    let response = recorder.result();
    assert_eq!(response.status_code, 200);
    assert_eq!(
        response.header.get("Content-Type").unwrap_or(""),
        "application/json; charset=utf-8"
    );
    let body = String::from_utf8(response.body.unwrap().read_all().unwrap()).unwrap();
    // The registry also holds cmdline and other tests' variables; check the
    // lines this test owns, in Go's layout.
    assert!(body.starts_with("{\n"), "{body}");
    assert!(body.ends_with("\n}\n"), "{body}");
    assert!(
        body.contains("\n\"expvar-test-handler-map1\": {\"a\": 1, \"z\": 2},\n"),
        "{body}"
    );
    assert!(
        body.contains(
            "\n\"expvar-test-handler-map2\": {\"0\": 0, \"1\": 1, \"2\": 2, \"3\": 3, \"4\": 4, \"5\": 5, \"6\": 6, \"7\": 7, \"8\": 8}"
        ),
        "{body}"
    );
    assert!(body.contains("\"cmdline\": ["), "{body}");
}

#[test]
fn append_json_quote() {
    // Every byte below 128, then U+2028 and U+2029.
    let mut s: std::string::String = (0u8..128).map(char::from).collect();
    s.push_str("\u{2028}\u{2029}");
    let want = concat!(
        "\"",
        "\\u0000\\u0001\\u0002\\u0003\\u0004\\u0005\\u0006\\u0007\\u0008\\t\\n\\u000b\\u000c\\r\\u000e\\u000f",
        "\\u0010\\u0011\\u0012\\u0013\\u0014\\u0015\\u0016\\u0017\\u0018\\u0019\\u001a\\u001b\\u001c\\u001d\\u001e\\u001f",
        " !\\\"#$%\\u0026'()*+,-./0123456789:;\\u003c=\\u003e?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\\\]^_",
        "`abcdefghijklmnopqrstuvwxyz{|}~\x7f\\u2028\\u2029\""
    );
    let quoted = StringVar::default();
    quoted.set(&s);
    assert_eq!(quoted.to_string(), want);
}
