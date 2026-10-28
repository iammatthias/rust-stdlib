//! Go's `net/http/pprof`: HTTP handlers that serve profiling data.
//!
//! Go's profiles are views of its runtime (goroutines, heap, mutexes, CPU,
//! execution traces, symbol tables). A Rust program has no such runtime, so
//! [`profile`], [`trace`] and the runtime-profile names served by [`handler`]
//! report "not available" the way Go reports a profiler it cannot start or a
//! profile it does not know, and [`symbol`] resolves no addresses (Go's
//! `runtime.FuncForPC` returns nil for an address it does not know).
//! [`cmdline`] and [`index`] are complete: the index lists the four fixed
//! endpoints plus every profile added with [`register_profile`] (the
//! counterpart of `runtime/pprof.NewProfile`), in Go's HTML layout.
//!
//! ```
//! use rust_stdlib::net::http::pprof;
//! let h = pprof::handler("heap");
//! # let _ = h;
//! ```
use std::io::{self, Cursor, Read, Write};
use std::sync::{Arc, LazyLock, Mutex};

use super::handler::{Handler, ResponseWriter};
use super::request::Request;
use super::servemux::DEFAULT_SERVE_MUX;
use crate::bufio;
use crate::net::url::Url;

type CountFn = Arc<dyn Fn() -> usize + Send + Sync>;
type WriteFn = Arc<dyn Fn(&mut dyn Write, i32) -> io::Result<()> + Send + Sync>;

/// A named profile served by [`handler`] and listed by [`index`], the
/// counterpart of a `runtime/pprof.Profile` made with `NewProfile`.
#[derive(Clone)]
struct Registered {
    name: String,
    description: String,
    count: CountFn,
    write_to: WriteFn,
}

static PROFILES: LazyLock<Mutex<Vec<Registered>>> = LazyLock::new(|| Mutex::new(Vec::new()));

/// Adds a custom profile (the counterpart of `pprof.NewProfile`). `count`
/// reports the number of entries shown in the index; `write_to` writes the
/// profile, with Go's `debug` argument (non-zero selects a text format).
/// A name already registered is replaced.
pub fn register_profile(
    name: &str,
    description: &str,
    count: impl Fn() -> usize + Send + Sync + 'static,
    write_to: impl Fn(&mut dyn Write, i32) -> io::Result<()> + Send + Sync + 'static,
) {
    let mut profiles = PROFILES.lock().unwrap_or_else(|e| e.into_inner());
    profiles.retain(|p| p.name != name);
    profiles.push(Registered {
        name: name.to_owned(),
        description: description.to_owned(),
        count: Arc::new(count),
        write_to: Arc::new(write_to),
    });
}

/// Registers the handlers on the default [`ServeMux`](super::ServeMux), as
/// importing Go's package does: `/debug/pprof/`, `cmdline`, `profile`,
/// `symbol` and `trace`, all for GET.
pub fn register_default_handlers() {
    let mux = &*DEFAULT_SERVE_MUX;
    let _ = mux.handle_func("GET /debug/pprof/", index);
    let _ = mux.handle_func("GET /debug/pprof/cmdline", cmdline);
    let _ = mux.handle_func("GET /debug/pprof/profile", profile);
    let _ = mux.handle_func("GET /debug/pprof/symbol", symbol);
    let _ = mux.handle_func("GET /debug/pprof/trace", trace);
}

fn description(name: &str) -> String {
    let fixed = match name {
        "cmdline" => "The command line invocation of the current program",
        "profile" => "CPU profile. You can specify the duration in the seconds GET parameter. After you get the profile file, use the go tool pprof command to investigate the profile.",
        "symbol" => "Maps given program counters to function names. Counters can be specified in a GET raw query or POST body, multiple counters are separated by '+'.",
        "trace" => "A trace of execution of the current program. You can specify the duration in the seconds GET parameter. After you get the trace file, use the go tool trace command to investigate the trace.",
        _ => "",
    };
    if !fixed.is_empty() {
        return fixed.to_owned();
    }
    PROFILES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .find(|p| p.name == name)
        .map(|p| p.description.clone())
        .unwrap_or_default()
}

/// Go's `pprof.Cmdline`: the running program's command line, arguments
/// separated by NUL bytes.
pub fn cmdline(w: &mut dyn ResponseWriter, _r: &mut Request) {
    w.header().set("X-Content-Type-Options", "nosniff");
    w.header().set("Content-Type", "text/plain; charset=utf-8");
    let args: Vec<String> = std::env::args_os()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let _ = w.write(args.join("\0").as_bytes());
}

fn serve_error(w: &mut dyn ResponseWriter, status: u16, txt: &str) {
    w.header().set("Content-Type", "text/plain; charset=utf-8");
    w.header().set("X-Go-Pprof", "1");
    w.header().del("Content-Disposition");
    w.write_header(status);
    let _ = w.write(format!("{txt}\n").as_bytes());
}

/// Go's `pprof.Profile`: responds with the pprof-formatted CPU profile. Rust
/// has no runtime CPU profiler, so this answers as Go does when profiling
/// cannot be enabled: status 500 and "Could not enable CPU profiling".
pub fn profile(w: &mut dyn ResponseWriter, r: &mut Request) {
    w.header().set("X-Content-Type-Options", "nosniff");
    // Go validates the duration first; it only matters to a profiler.
    let _ = r.form_value("seconds");
    w.header().set("Content-Type", "application/octet-stream");
    w.header()
        .set("Content-Disposition", "attachment; filename=\"profile\"");
    serve_error(
        w,
        500,
        "Could not enable CPU profiling: no CPU profiler is available in this runtime",
    );
}

/// Go's `pprof.Trace`: responds with the execution trace. Rust has no runtime
/// tracer, so this answers 500 "Could not enable tracing".
pub fn trace(w: &mut dyn ResponseWriter, r: &mut Request) {
    w.header().set("X-Content-Type-Options", "nosniff");
    let _ = r.form_value("seconds");
    w.header().set("Content-Type", "application/octet-stream");
    w.header()
        .set("Content-Disposition", "attachment; filename=\"trace\"");
    serve_error(
        w,
        500,
        "Could not enable tracing: no execution tracer is available in this runtime",
    );
}

/// Go's `pprof.Symbol`: looks up the program counters listed in the request
/// and responds with a table mapping program counters to function names. The
/// request is a GET with `+`-separated counters in the query or a POST with
/// them in the body. No counter names a function here, so only the header
/// line (and a "reading request" line for unreadable input) is written.
pub fn symbol(w: &mut dyn ResponseWriter, r: &mut Request) {
    w.header().set("X-Content-Type-Options", "nosniff");
    w.header().set("Content-Type", "text/plain; charset=utf-8");

    let mut buf = String::from("num_symbols: 1\n");

    let source: Box<dyn Read> = if r.method == "POST" {
        match r.body.clone() {
            Some(b) => Box::new(b),
            None => Box::new(io::empty()),
        }
    } else {
        Box::new(Cursor::new(r.url.raw_query.clone().into_bytes()))
    };
    let mut b = bufio::Reader::new(source);
    loop {
        let err = b.read_slice(b'+').err().map(bufio::SliceError::into_source);
        // Go parses the word and asks the runtime for the function at that
        // counter; with no function table the answer is always "none".
        if let Some(e) = err {
            if !crate::io::is_eof(&e) {
                buf.push_str(&format!("reading request: {e}\n"));
            }
            break;
        }
    }
    let _ = w.write(buf.as_bytes());
}

struct NamedHandler(String);

impl Handler for NamedHandler {
    fn serve_http(&self, w: &mut dyn ResponseWriter, r: &mut Request) {
        let name = &self.0;
        w.header().set("X-Content-Type-Options", "nosniff");
        let found = PROFILES
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|p| &p.name == name)
            .cloned();
        let Some(p) = found else {
            serve_error(w, 404, "Unknown profile");
            return;
        };
        let sec = r.form_value("seconds");
        if !sec.is_empty() {
            // Go's delta profiles are defined for its runtime profiles only.
            match crate::strconv::parse_int(&sec, 10, 64) {
                Ok(n) if n > 0 => {
                    let debug = atoi(&r.form_value("debug"));
                    if debug != 0 {
                        serve_error(w, 400, "seconds and debug params are incompatible");
                    } else {
                        serve_error(
                            w,
                            400,
                            "\"seconds\" parameter is not supported for this profile type",
                        );
                    }
                }
                _ => serve_error(
                    w,
                    400,
                    "invalid value for \"seconds\" - must be a positive integer",
                ),
            }
            return;
        }
        let debug = atoi(&r.form_value("debug"));
        if debug != 0 {
            w.header().set("Content-Type", "text/plain; charset=utf-8");
        } else {
            w.header().set("Content-Type", "application/octet-stream");
            w.header().set(
                "Content-Disposition",
                &format!("attachment; filename=\"{name}\""),
            );
        }
        let mut out = Vec::new();
        let _ = (p.write_to)(&mut out, debug as i32);
        let _ = w.write(&out);
    }
}

/// Go's `strconv.Atoi` with the error dropped: 0 when invalid.
fn atoi(s: &str) -> i64 {
    crate::strconv::atoi(s).unwrap_or_else(|e| e.int_value() as isize) as i64
}

/// Go's `pprof.Handler`: returns an HTTP handler that serves the named
/// profile. Go's runtime profiles (`goroutine`, `threadcreate`, `heap`,
/// `allocs`, `block`, `mutex`, `goroutineleak`) do not exist here and answer
/// 404 "Unknown profile"; profiles added with [`register_profile`] are served.
pub fn handler(name: &str) -> Arc<dyn Handler> {
    Arc::new(NamedHandler(name.to_owned()))
}

struct ProfileEntry {
    name: String,
    href: String,
    desc: String,
    count: usize,
}

/// Go's `pprof.Index`: responds with an HTML page listing the available
/// profiles; a path below `/debug/pprof/` names a profile to serve through
/// [`handler`].
pub fn index(w: &mut dyn ResponseWriter, r: &mut Request) {
    if let Some(name) = r.url.path.strip_prefix("/debug/pprof/") {
        if !name.is_empty() {
            handler(name).serve_http(w, r);
            return;
        }
    }

    w.header().set("X-Content-Type-Options", "nosniff");
    w.header().set("Content-Type", "text/html; charset=utf-8");

    let mut profiles: Vec<ProfileEntry> = PROFILES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .map(|p| ProfileEntry {
            name: p.name.clone(),
            href: p.name.clone(),
            desc: p.description.clone(),
            count: (p.count)(),
        })
        .collect();
    for p in ["cmdline", "profile", "symbol", "trace"] {
        profiles.push(ProfileEntry {
            name: p.to_owned(),
            href: p.to_owned(),
            desc: description(p),
            count: 0,
        });
    }
    profiles.sort_by(|a, b| a.name.cmp(&b.name));

    let _ = w.write(index_page(&profiles).as_bytes());
}

fn index_page(profiles: &[ProfileEntry]) -> String {
    let mut b = String::from(
        r#"<html>
<head>
<title>/debug/pprof/</title>
<style>
.profile-name{
	display:inline-block;
	width:6rem;
}
</style>
</head>
<body>
/debug/pprof/
<br>
<p>Set debug=1 as a query parameter to export in legacy text format</p>
<br>
Types of profiles available:
<table>
<thead><td>Count</td><td>Profile</td></thead>
"#,
    );
    for p in profiles {
        let link = Url {
            path: p.href.clone(),
            raw_query: "debug=1".to_owned(),
            ..Url::default()
        };
        b.push_str(&format!(
            "<tr><td>{}</td><td><a href='{}'>{}</a></td></tr>\n",
            p.count,
            link,
            crate::html::escape(&p.name)
        ));
    }
    b.push_str(
        r#"</table>
<a href="goroutine?debug=2">full goroutine stack dump</a>
<br>
<p>
Profile Descriptions:
<ul>
"#,
    );
    for p in profiles {
        b.push_str(&format!(
            "<li><div class=profile-name>{}: </div> {}</li>\n",
            crate::html::escape(&p.name),
            crate::html::escape(&p.desc)
        ));
    }
    b.push_str("</ul>\n</p>\n</body>\n</html>");
    b
}
