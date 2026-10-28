//! Self-contained local demo: verified HTTPS bootstrap, templates, JSON, assets
//! and structured logs. Public test keys/CA are for loopback demonstrations only.
use rust_stdlib::{
    context::Context,
    encoding::{
        hex,
        json::{self, Deserialize, Serialize, Value},
    },
    log::json::{Level, Logger},
    net::{
        self,
        http::{self, handler_func, server::Server, Client, Handler, ServeMux, Transport},
    },
    template::Template,
};
use rust_stdlib_tls::tls::{x509, Certificate, Config, PrivateKey};
use std::{
    collections::BTreeMap,
    io::{self, BufRead, Read},
    sync::Arc,
    thread,
    time::Duration,
};
fn fixture(s: &str) -> Vec<u8> {
    hex::decode(s.trim()).expect("checked-in test hex")
}
struct Echo {
    message: String,
}
impl Deserialize for Echo {
    fn from_json(value: &Value) -> Result<Self, json::Error> {
        let Value::Object(fields) = value else {
            return Err(json::Error::Type("object required"));
        };
        if fields.len() != 1 {
            return Err(json::Error::Type("one message field required"));
        }
        let message = String::from_json(
            fields
                .get("message")
                .ok_or(json::Error::Type("message required"))?,
        )?;
        if message.len() > 4096 {
            return Err(json::Error::Limit("message bytes"));
        }
        Ok(Self { message })
    }
}
impl Serialize for Echo {
    fn to_json(&self) -> Result<Value, json::Error> {
        Ok(Value::object([(
            "message",
            Value::from(self.message.clone()),
        )]))
    }
}
fn main() -> Result<(), http::header::BoxError> {
    let logger = Arc::new(Logger::new(io::stderr(), Level::Info));
    let ca = fixture(include_str!("../tests/fixtures/ca.hex"));

    // Verified HTTPS: a TLS server answers one probe that trusts only our CA.
    let mut upstream = Server {
        handler: Some(handler_func(|w, r| {
            let verified = Value::object([("verified", Value::from(r.url.path == "/health"))]);
            w.header().set("Content-Type", "application/json");
            let _ = w.write(&json::marshal(&verified).unwrap_or_default());
        })),
        ..Server::default()
    };
    let mut server_tls = Config::new();
    server_tls.certificates = vec![Certificate {
        certificate: vec![fixture(include_str!("../tests/fixtures/server.hex"))],
        private_key: Some(PrivateKey::Pkcs8(fixture(include_str!(
            "../tests/fixtures/server-key.hex"
        )))),
        ..Certificate::default()
    }];
    upstream.tls_config = Some(Arc::new(server_tls));
    let listener = net::listen("tcp", "127.0.0.1:0")?;
    let port = listener.addr().expect("listener address").to_string();
    let port = port.rsplit(':').next().unwrap_or_default().to_owned();
    let serving = upstream.clone();
    let thread_handle = thread::spawn(move || {
        let _ = serving.serve_tls(listener, "", "");
    });
    let mut transport = Transport::default();
    let mut roots = x509::CertPool::new();
    roots.add_cert(x509::parse_certificate(&ca)?);
    let mut client_tls = Config::new();
    client_tls.root_cas = Some(roots);
    transport.tls_client_config = Some(Arc::new(client_tls));
    let client = Client {
        transport: Some(Arc::new(transport)),
        ..Client::default()
    };
    let reply = client.get(&format!("https://localhost:{port}/health"))?;
    let status = reply.status_code;
    let body = reply.body.ok_or("empty HTTPS reply")?.read_all()?;
    let verified = json::Value::try_from(&body[..])?;
    if status != 200 || verified.get("verified") != Some(&Value::Bool(true)) {
        return Err("HTTPS verification probe failed".into());
    }
    let _ = upstream.close();
    thread_handle
        .join()
        .map_err(|_| "upstream thread panicked")?;
    logger.write(
        Level::Info,
        "verified_https",
        BTreeMap::from([("status".to_owned(), Value::from(i64::from(status)))]),
    )?;

    // The application: an embedded template, a health check and typed JSON.
    let template = Template::html(include_str!("../../../examples/assets/index.html"))?;
    let mux = Arc::new(ServeMux::new());
    mux.handle_func("GET /{$}", move |w, r| {
        let query = r.url.query();
        let title = if query.has("title") {
            query.get("title").to_owned()
        } else {
            "Rust application library".to_owned()
        };
        match template.render(&BTreeMap::from([("title".to_owned(), title)])) {
            Ok(html) => {
                w.header().set("Content-Type", "text/html; charset=utf-8");
                let _ = w.write_string(&html);
            }
            Err(_) => {
                w.write_header(400);
                let _ = w.write_string("Template error\n");
            }
        }
    })?;
    mux.handle_func("GET /health", |w, _| {
        let _ = w.write_string("ok\n");
    })?;
    mux.handle_func("POST /echo", |w, r| {
        let content_type = r.header.get("Content-Type").unwrap_or("");
        if !content_type
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .eq_ignore_ascii_case("application/json")
        {
            w.write_header(415);
            let _ = w.write_string("JSON required\n");
            return;
        }
        let mut body = Vec::new();
        if let Some(b) = &r.body {
            let _ = b.clone().take(1 << 20).read_to_end(&mut body);
        }
        match json::Value::try_from(&body[..])
            .and_then(|v| Echo::from_json(&v))
            .and_then(|v| v.to_json())
            .and_then(|v| json::marshal(&v))
        {
            Ok(reply) => {
                w.header().set("Content-Type", "application/json");
                let _ = w.write(&reply);
            }
            Err(e) => {
                w.write_header(400);
                let _ = w.write_string(&e.to_string());
            }
        }
    })?;
    let log = logger.clone();
    let handler: Arc<dyn Handler> = handler_func(move |w, r| {
        let _ = log.write(
            Level::Info,
            "request",
            BTreeMap::from([("path".to_owned(), Value::from(r.url.path.clone()))]),
        );
        mux.serve_http(w, r);
    });
    let address = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8080".to_owned());
    let server = Server {
        handler: Some(handler),
        ..Server::default()
    };
    let listener = net::listen("tcp", &address)?;
    logger.write(
        Level::Info,
        "listening",
        BTreeMap::from([(
            "address".to_owned(),
            Value::from(listener.addr().expect("listener address").to_string()),
        )]),
    )?;
    let serving = server.clone();
    let serve_thread = thread::spawn(move || {
        let _ = serving.serve(listener);
    });
    let mut line = String::new();
    let _ = io::stdin().lock().read_line(&mut line);
    let (context, cancel) = Context::background().with_timeout(Duration::from_secs(5).into());
    let _ = server.shutdown(&context);
    cancel();
    let _ = serve_thread.join();
    Ok(())
}
