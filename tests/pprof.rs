#![cfg(feature = "net")]
//! `net/http/pprof`: the endpoints that exist without a Go runtime, and the
//! documented answers for those that need one.
use rust_stdlib::net::http::pprof;
use rust_stdlib::net::http::Request;
use rust_stdlib::net::http::{Header, ResponseWriter};
use std::io::{self, Write};

#[derive(Default)]
struct Recorder {
    code: u16,
    header: Header,
    body: Vec<u8>,
}

impl std::io::Write for Recorder {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.code == 0 {
            self.code = 200;
        }
        self.body.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl ResponseWriter for Recorder {
    fn header(&mut self) -> &mut Header {
        &mut self.header
    }
    fn write_header(&mut self, code: u16) {
        if self.code == 0 {
            self.code = code;
        }
    }
}

fn get(
    url: &str,
    f: impl Fn(&mut Recorder, &mut rust_stdlib::net::http::request::Request),
) -> Recorder {
    let mut req = Request::new("GET", url).unwrap();
    let mut rec = Recorder::default();
    f(&mut rec, &mut req);
    rec
}

#[test]
fn cmdline_joins_arguments_with_nul() {
    let rec = get("http://x/debug/pprof/cmdline", |w, r| pprof::cmdline(w, r));
    assert_eq!(
        rec.header.get("X-Content-Type-Options").unwrap_or(""),
        "nosniff"
    );
    assert_eq!(
        rec.header.get("Content-Type").unwrap_or(""),
        "text/plain; charset=utf-8"
    );
    let want: Vec<String> = std::env::args().collect();
    assert_eq!(String::from_utf8_lossy(&rec.body), want.join("\0"));
}

#[test]
fn index_lists_fixed_and_registered_profiles() {
    pprof::register_profile(
        "widgets",
        "Live <widgets> & friends",
        || 3,
        |w: &mut dyn Write, debug| write!(w, "widgets debug={debug}"),
    );
    let rec = get("http://x/debug/pprof/", |w, r| pprof::index(w, r));
    assert_eq!(
        rec.header.get("Content-Type").unwrap_or(""),
        "text/html; charset=utf-8"
    );
    let page = String::from_utf8(rec.body).unwrap();
    assert!(page.starts_with("<html>\n<head>\n<title>/debug/pprof/</title>"));
    assert!(page.contains("<tr><td>3</td><td><a href='widgets?debug=1'>widgets</a></td></tr>\n"));
    assert!(page.contains("<tr><td>0</td><td><a href='cmdline?debug=1'>cmdline</a></td></tr>\n"));
    assert!(page.contains(
        "<li><div class=profile-name>widgets: </div> Live &lt;widgets&gt; &amp; friends</li>\n"
    ));
    assert!(page.ends_with("</ul>\n</p>\n</body>\n</html>"));
    // Rows are sorted by name.
    let at = |n: &str| page.find(&format!("href='{n}?debug=1'")).unwrap();
    assert!(
        at("cmdline") < at("profile") && at("profile") < at("symbol") && at("symbol") < at("trace")
    );

    // The index also routes a profile name below the prefix to its handler.
    let rec = get("http://x/debug/pprof/widgets?debug=1", |w, r| {
        pprof::index(w, r)
    });
    assert_eq!(
        rec.header.get("Content-Type").unwrap_or(""),
        "text/plain; charset=utf-8"
    );
    assert_eq!(rec.body, b"widgets debug=1");
    let rec = get("http://x/debug/pprof/widgets", |w, r| pprof::index(w, r));
    assert_eq!(
        rec.header.get("Content-Type").unwrap_or(""),
        "application/octet-stream"
    );
    assert_eq!(
        rec.header.get("Content-Disposition").unwrap_or(""),
        "attachment; filename=\"widgets\""
    );
}

#[test]
fn unknown_profiles_and_delta_errors() {
    let rec = get("http://x/debug/pprof/nope", |w, r| {
        pprof::handler("nope").serve_http(w, r)
    });
    assert_eq!(rec.code, 404);
    assert_eq!(rec.header.get("X-Go-Pprof").unwrap_or(""), "1");
    assert_eq!(rec.body, b"Unknown profile\n");
    // Go's runtime profiles do not exist here.
    let rec = get("http://x/debug/pprof/heap", |w, r| {
        pprof::handler("heap").serve_http(w, r)
    });
    assert_eq!(rec.code, 404);

    pprof::register_profile("things", "", || 0, |_: &mut dyn Write, _| Ok(()));
    let h = |q: &str| {
        get(&format!("http://x/debug/pprof/things{q}"), |w, r| {
            pprof::handler("things").serve_http(w, r)
        })
    };
    assert_eq!(h("?seconds=x").code, 400);
    assert_eq!(
        h("?seconds=x").body,
        b"invalid value for \"seconds\" - must be a positive integer\n"
    );
    assert_eq!(
        h("?seconds=2&debug=1").body,
        b"seconds and debug params are incompatible\n"
    );
    assert_eq!(
        h("?seconds=2").body,
        b"\"seconds\" parameter is not supported for this profile type\n"
    );
}

#[test]
fn symbol_reads_counters_and_reports_unreadable_input() {
    let rec = get("http://x/debug/pprof/symbol?0x1234+99", |w, r| {
        pprof::symbol(w, r)
    });
    assert_eq!(rec.body, b"num_symbols: 1\n");
    let rec = get(
        &format!("http://x/debug/pprof/symbol?{}", "a".repeat(5000)),
        |w, r| pprof::symbol(w, r),
    );
    assert_eq!(
        rec.body,
        b"num_symbols: 1\nreading request: bufio: buffer full\n"
    );
}

#[test]
fn profile_and_trace_report_unavailable_profilers() {
    let rec = get("http://x/debug/pprof/profile?seconds=1", |w, r| {
        pprof::profile(w, r)
    });
    assert_eq!(rec.code, 500);
    assert!(String::from_utf8_lossy(&rec.body).starts_with("Could not enable CPU profiling: "));
    assert_eq!(rec.header.get("Content-Disposition").unwrap_or(""), "");
    let rec = get("http://x/debug/pprof/trace", |w, r| pprof::trace(w, r));
    assert_eq!(rec.code, 500);
    assert!(String::from_utf8_lossy(&rec.body).starts_with("Could not enable tracing: "));
}
