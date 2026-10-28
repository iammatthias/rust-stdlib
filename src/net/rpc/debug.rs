//! Go's `net/rpc/debug.go`: the HTML page at `/debug/rpc` that lists
//! services, their methods, and some statistics, still rudimentary.

#[cfg(feature = "net")]
use super::server::Server;

/// `html/template` text-context escaping (its `htmlReplacementTable`).
#[cfg(feature = "net")]
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\0' => out.push('\u{FFFD}'),
            '"' => out.push_str("&#34;"),
            '&' => out.push_str("&amp;"),
            '\'' => out.push_str("&#39;"),
            '+' => out.push_str("&#43;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            c => out.push(c),
        }
    }
    out
}

/// The debug page for the server's services, as Go's template renders it.
#[cfg(feature = "net")]
pub(crate) fn page(server: &Server) -> String {
    let mut out = String::from("<html>\n\t<body>\n\t<title>Services</title>\n\t");
    for (name, methods) in server.sorted_services() {
        out.push_str(&format!(
            "\n\t<hr>\n\tService {}\n\t<hr>\n\t\t<table>\n\t\t<th align=center>Method</th><th align=center>Calls</th>\n\t\t",
            escape(&name)
        ));
        for (mname, mtype) in methods {
            out.push_str(&format!(
                "\n\t\t\t<tr>\n\t\t\t<td align=left font=fixed>{}({}, {}) error</td>\n\t\t\t<td align=center>{}</td>\n\t\t\t</tr>\n\t\t",
                escape(&mname),
                escape(&mtype.arg_type.to_string()),
                escape(&mtype.reply_type.to_string()),
                mtype.num_calls()
            ));
        }
        out.push_str("\n\t\t</table>\n\t");
    }
    out.push_str("\n\t</body>\n\t</html>");
    out
}

/// The handler Go registers at the debug path (`debugHTTP`).
#[cfg(feature = "net")]
pub(crate) struct DebugHttp(pub(crate) Server);

#[cfg(feature = "net")]
impl crate::net::http::Handler for DebugHttp {
    fn serve_http(
        &self,
        w: &mut dyn crate::net::http::ResponseWriter,
        _r: &mut crate::net::http::request::Request,
    ) {
        let _ = w.write(page(&self.0).as_bytes());
    }
}
