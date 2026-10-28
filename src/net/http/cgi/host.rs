//! The host side of CGI: the web server running a CGI program (Go's
//! `net/http/cgi/host.go`).
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};

use crate::bufio;
use crate::log::{self, Logger};
use crate::net::http::header::{valid_header_field_name, Header};
use crate::net::http::request::Request;
use crate::net::http::{Handler as HttpHandler, ResponseWriter};
use crate::net::split_host_port;
use crate::net::textproto::trim_string;
use crate::os::exec::{self, Input, Output};

/// The environment variables inherited by default on this platform (Go's
/// `osDefaultInheritEnv`).
fn os_default_inherit_env() -> &'static [&'static str] {
    if cfg!(any(target_os = "macos", target_os = "ios")) {
        &["DYLD_LIBRARY_PATH"]
    } else if cfg!(any(
        target_os = "android",
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd"
    )) {
        &["LD_LIBRARY_PATH"]
    } else if cfg!(any(target_os = "illumos", target_os = "solaris")) {
        &[
            "LD_LIBRARY_PATH",
            "LD_LIBRARY_PATH_32",
            "LD_LIBRARY_PATH_64",
        ]
    } else if cfg!(windows) {
        &["SystemRoot", "COMSPEC", "PATHEXT", "WINDIR"]
    } else {
        &[]
    }
}

/// Go's `cgi.Handler`: runs an executable in a subprocess with a CGI
/// environment.
#[derive(Default)]
pub struct Handler {
    /// Path to the CGI executable (Go `Path`).
    pub path: String,
    /// Root URI prefix of the handler, or empty for "/" (Go `Root`).
    pub root: String,
    /// The CGI executable's working directory. If empty, the base directory of
    /// `path` is used; if `path` has no base directory, the current working
    /// directory (Go `Dir`).
    pub dir: String,
    /// Extra environment variables to set, as "key=value" (Go `Env`).
    pub env: Vec<String>,
    /// Environment variables to inherit from the host, as "key" (Go
    /// `InheritEnv`).
    pub inherit_env: Vec<String>,
    /// Optional log for errors; `None` uses [`log::printf`] (Go `Logger`).
    pub logger: Option<Arc<Logger>>,
    /// Optional arguments to pass to the child process (Go `Args`).
    pub args: Vec<String>,
    /// Optional standard error for the child process; `None` means the
    /// parent's standard error (Go `Stderr`).
    pub stderr: Option<Arc<Mutex<dyn Write + Send>>>,
    /// The root handler for internal redirects when the CGI process returns a
    /// `Location` header starting with "/" (RFC 3875 section 6.3.2). If
    /// `None`, such a response is sent back to the client (Go
    /// `PathLocationHandler`).
    pub path_location_handler: Option<Arc<dyn HttpHandler>>,
}

/// Removes leading duplicates in an environment, so a later entry overrides
/// an earlier one (Go's `removeLeadingDuplicates`).
fn remove_leading_duplicates(env: Vec<String>) -> Vec<String> {
    let mut ret = Vec::new();
    for (i, e) in env.iter().enumerate() {
        let mut found = false;
        if let Some(eq) = e.find('=') {
            let keq = &e[..=eq];
            found = env[i + 1..].iter().any(|e2| e2.starts_with(keq));
        }
        if !found {
            ret.push(e.clone());
        }
    }
    ret
}

fn upper_case_and_underscore(c: char) -> char {
    match c {
        'a'..='z' => c.to_ascii_uppercase(),
        '-' | '=' => '_',
        other => other,
    }
}

/// The port in `host`'s trailing ":digits", if any (Go's `trailingPort`).
fn trailing_port(host: &str) -> Option<&str> {
    let i = host.rfind(':')?;
    let digits = &host[i + 1..];
    (!digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())).then_some(digits)
}

impl Handler {
    fn printf(&self, args: std::fmt::Arguments<'_>) {
        match &self.logger {
            Some(l) => l.printf(args),
            None => log::printf(args),
        }
    }

    fn handle_internal_redirect(&self, rw: &mut dyn ResponseWriter, req: &Request, path: &str) {
        let url = match req.url.parse(path) {
            Ok(u) => u,
            Err(e) => {
                rw.write_header(500);
                self.printf(format_args!(
                    "cgi: error resolving local URI path {}: {e}",
                    crate::strconv::quote(path)
                ));
                return;
            }
        };
        // RFC 3875 isn't clear if only GET is supported for the redirected
        // request, so Go sends a fresh GET with no headers.
        let mut new_req = Request::default();
        new_req.method = "GET".into();
        new_req.host = url.host.clone();
        new_req.url = url;
        new_req.proto = "HTTP/1.1".into();
        new_req.proto_major = 1;
        new_req.proto_minor = 1;
        new_req.header = Header::new();
        new_req.remote_addr = req.remote_addr.clone();
        new_req.tls = req.tls.clone();
        if let Some(h) = &self.path_location_handler {
            h.serve_http(rw, &mut new_req);
        }
    }

    fn environment(&self, req: &Request) -> Vec<String> {
        let root = self.root.trim_end_matches('/');
        let path_info = req.url.path.strip_prefix(root).unwrap_or(&req.url.path);

        let mut port = if req.tls.is_some() { "443" } else { "80" }.to_owned();
        if let Some(p) = trailing_port(&req.host) {
            port = p.to_owned();
        }

        let mut env = vec![
            "SERVER_SOFTWARE=go".to_owned(),
            "SERVER_PROTOCOL=HTTP/1.1".to_owned(),
            format!("HTTP_HOST={}", req.host),
            "GATEWAY_INTERFACE=CGI/1.1".to_owned(),
            format!("REQUEST_METHOD={}", req.method),
            format!("QUERY_STRING={}", req.url.raw_query),
            format!("REQUEST_URI={}", req.url.request_uri()),
            format!("PATH_INFO={path_info}"),
            format!("SCRIPT_NAME={root}"),
            format!("SCRIPT_FILENAME={}", self.path),
            format!("SERVER_PORT={port}"),
        ];

        match split_host_port(&req.remote_addr) {
            Ok((ip, port)) => {
                env.push(format!("REMOTE_ADDR={ip}"));
                env.push(format!("REMOTE_HOST={ip}"));
                env.push(format!("REMOTE_PORT={port}"));
            }
            Err(_) => {
                // Could not parse ip:port: use the whole RemoteAddr and leave
                // REMOTE_PORT undefined.
                env.push(format!("REMOTE_ADDR={}", req.remote_addr));
                env.push(format!("REMOTE_HOST={}", req.remote_addr));
            }
        }

        match split_host_port(&req.host) {
            Ok((domain, _)) => env.push(format!("SERVER_NAME={domain}")),
            Err(_) => env.push(format!("SERVER_NAME={}", req.host)),
        }

        if req.tls.is_some() {
            env.push("HTTPS=on".to_owned());
        }

        for (k, v) in &req.header.0 {
            let k: String = k.chars().map(upper_case_and_underscore).collect();
            if k == "PROXY" {
                // See Go issue 16405.
                continue;
            }
            let join = if k == "COOKIE" { "; " } else { ", " };
            env.push(format!("HTTP_{k}={}", v.join(join)));
        }

        if req.content_length > 0 {
            env.push(format!("CONTENT_LENGTH={}", req.content_length));
        }
        let ctype = req.header.get_str("Content-Type");
        if !ctype.is_empty() {
            env.push(format!("CONTENT_TYPE={ctype}"));
        }

        let mut env_path = crate::os::getenv("PATH");
        if env_path.is_empty() {
            env_path = "/bin:/usr/bin:/usr/ucb:/usr/bsd:/usr/local/bin".to_owned();
        }
        env.push(format!("PATH={env_path}"));

        for e in &self.inherit_env {
            let v = crate::os::getenv(e);
            if !v.is_empty() {
                env.push(format!("{e}={v}"));
            }
        }
        for e in os_default_inherit_env() {
            let v = crate::os::getenv(e);
            if !v.is_empty() {
                env.push(format!("{e}={v}"));
            }
        }

        env.extend(self.env.iter().cloned());
        remove_leading_duplicates(env)
    }
}

impl HttpHandler for Handler {
    fn serve_http(&self, rw: &mut dyn ResponseWriter, req: &mut Request) {
        if req
            .transfer_encoding
            .first()
            .is_some_and(|t| t == "chunked")
        {
            rw.write_header(400);
            let _ = rw.write(b"Chunked request bodies are not supported by CGI.");
            return;
        }

        let env = self.environment(req);

        let (cwd, path) = if !self.dir.is_empty() {
            (self.dir.clone(), self.path.clone())
        } else {
            match self.path.rfind('/') {
                Some(i) => (self.path[..=i].to_owned(), self.path[i + 1..].to_owned()),
                None => (String::new(), self.path.clone()),
            }
        };
        let cwd = if cwd.is_empty() { ".".to_owned() } else { cwd };
        // Go executes `Path` relative to `Dir` without a PATH search.
        let path = if path.contains('/') {
            path
        } else {
            format!("./{path}")
        };

        let mut cmd = exec::command(&path, &[]);
        cmd.err = None;
        cmd.args = std::iter::once(self.path.clone())
            .chain(self.args.iter().cloned())
            .collect();
        cmd.dir = cwd;
        cmd.env = Some(env);
        cmd.stderr = Some(match &self.stderr {
            Some(w) => Output::Writer(w.clone()),
            None => Output::Writer(Arc::new(Mutex::new(io::stderr()))),
        });
        if req.content_length != 0 {
            if let Some(body) = req.body.clone() {
                cmd.stdin = Some(Input::reader(body));
            }
        }
        let internal_error = |rw: &mut dyn ResponseWriter, e: &dyn std::fmt::Display| {
            rw.write_header(500);
            self.printf(format_args!("CGI error: {e}"));
        };
        let stdout_read = match cmd.stdout_pipe() {
            Ok(f) => f,
            Err(e) => {
                internal_error(rw, &e);
                return;
            }
        };
        if let Err(e) = cmd.start() {
            internal_error(rw, &e);
            return;
        }
        // Close our end of the pipe before waiting, so a child still writing
        // sees the pipe go away (Go's deferred `stdoutRead.Close`).
        let reader = stdout_read.clone();
        self.serve_output(rw, req, &mut cmd, stdout_read);
        let _ = reader.close();
        let _ = cmd.wait();
    }
}

impl Handler {
    /// Reads the child's headers and body from its standard output.
    fn serve_output(
        &self,
        rw: &mut dyn ResponseWriter,
        req: &Request,
        cmd: &mut exec::Cmd,
        stdout_read: exec::PipeEnd,
    ) {
        let mut linebody = bufio::Reader::with_size(stdout_read, 1024);
        let mut headers = Header::new();
        let mut status_code = 0i64;
        let mut header_lines = 0;
        let mut saw_blank_line = false;
        loop {
            let (line, is_prefix) = match linebody.read_line_bytes() {
                Ok((line, is_prefix)) => (line.to_vec(), is_prefix),
                Err(e) if crate::io::is_eof(&e) => break,
                Err(e) => {
                    rw.write_header(500);
                    self.printf(format_args!("cgi: error reading headers: {e}"));
                    return;
                }
            };
            if is_prefix {
                rw.write_header(500);
                self.printf(format_args!("cgi: long header line from subprocess."));
                return;
            }
            if line.is_empty() {
                saw_blank_line = true;
                break;
            }
            header_lines += 1;
            let line = String::from_utf8_lossy(&line).into_owned();
            let Some((header, val)) = line.split_once(':') else {
                self.printf(format_args!("cgi: bogus header line: {line}"));
                continue;
            };
            if !valid_header_field_name(header) {
                self.printf(format_args!(
                    "cgi: invalid header name: {}",
                    crate::strconv::quote(header)
                ));
                continue;
            }
            let val = trim_string(val);
            if header == "Status" {
                if val.len() < 3 {
                    self.printf(format_args!(
                        "cgi: bogus status (short): {}",
                        crate::strconv::quote(val)
                    ));
                    return;
                }
                match val.get(0..3).map(crate::strconv::atoi) {
                    Some(Ok(code)) => status_code = code as i64,
                    _ => {
                        self.printf(format_args!(
                            "cgi: bogus status: {}",
                            crate::strconv::quote(val)
                        ));
                        self.printf(format_args!(
                            "cgi: line was {}",
                            crate::strconv::quote(&line)
                        ));
                        return;
                    }
                }
            } else {
                headers.add(header, val);
            }
        }
        if header_lines == 0 || !saw_blank_line {
            rw.write_header(500);
            self.printf(format_args!("cgi: no headers"));
            return;
        }

        let loc = headers.get_str("Location");
        if !loc.is_empty() {
            if loc.starts_with('/') && self.path_location_handler.is_some() {
                self.handle_internal_redirect(rw, req, loc);
                return;
            }
            if status_code == 0 {
                status_code = 302;
            }
        }

        if status_code == 0 && headers.get_str("Content-Type").is_empty() {
            rw.write_header(500);
            self.printf(format_args!(
                "cgi: missing required Content-Type in headers"
            ));
            return;
        }

        if status_code == 0 {
            status_code = 200;
        }

        // Copy headers to rw's headers, after we've decided not to go into
        // handle_internal_redirect, which won't want its headers touched.
        for (k, vv) in &headers.0 {
            for v in vv {
                rw.header().add(k, v);
            }
        }

        rw.write_header(status_code as u16);

        let mut buf = [0u8; 32 * 1024];
        loop {
            match linebody.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = rw.write(&buf[..n]) {
                        self.copy_failed(cmd, &e);
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    self.copy_failed(cmd, &e);
                    break;
                }
            }
        }
    }

    fn copy_failed(&self, cmd: &exec::Cmd, e: &io::Error) {
        self.printf(format_args!("cgi: copy error: {e}"));
        // Kill the child so we don't hang on the wait if the error was just
        // the client going away.
        if let Some(p) = &cmd.process {
            let _ = p.kill();
        }
    }
}
