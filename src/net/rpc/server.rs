//! Go's `net/rpc/server.go`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, LazyLock, Mutex};

use crate::reflect::{self, Kind, Reflect, Type, Value};

use super::gobcodec::GobServerCodec;
use super::{Error, ReadWriteCloser, Request, Response, ServerCodec};

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Whether to log problems during method registration (Go's
/// `logRegisterError`).
const LOG_REGISTER_ERROR: bool = false;

pub(crate) struct MethodType {
    pub(crate) arg_type: Type,
    pub(crate) reply_type: Type,
    num_calls: AtomicU64,
    /// Whether the method has a pointer receiver; such calls read the
    /// receiver, change it and write it back, so they run one at a time.
    mutating: bool,
}

impl MethodType {
    #[cfg(feature = "net")]
    pub(crate) fn num_calls(&self) -> u64 {
        self.num_calls.load(Ordering::SeqCst)
    }
}

pub(crate) struct Service {
    rcvr: Value,
    typ: Type,
    pub(crate) method: HashMap<String, Arc<MethodType>>,
    serial: Mutex<()>,
}

pub(crate) struct ServerInner {
    pub(crate) service_map: Mutex<HashMap<String, Arc<Service>>>,
}

/// An RPC server (Go `rpc.Server`). It is a handle: cloning it shares the
/// registered services.
#[derive(Clone)]
pub struct Server {
    pub(crate) inner: Arc<ServerInner>,
}

/// Go `DefaultServer`: the default instance of [`Server`].
pub static DEFAULT_SERVER: LazyLock<Server> = LazyLock::new(Server::new);

/// Go `isExportedOrBuiltinType`: whether `t` is an exported or builtin type.
fn is_exported_or_builtin_type(t: &Type) -> bool {
    let mut t = t.clone();
    while t.kind() == Kind::Pointer {
        t = t.elem();
    }
    // PkgPath will be non-empty even for an exported type, so we need to
    // check the type name as well.
    crate::encoding::gob::is_exported_name(&t.name()) || t.pkg_path().is_empty()
}

/// Go `suitableMethods`: the suitable Rpc methods of `typ`. It logs errors if
/// `log_err` is true.
fn suitable_methods(typ: &Type, log_err: bool) -> HashMap<String, Arc<MethodType>> {
    let mut methods = HashMap::new();
    let value_type = if typ.kind() == Kind::Pointer {
        typ.elem()
    } else {
        typ.clone()
    };
    for m in 0..typ.num_method() {
        let method = typ.method(m);
        let mtype = &method.type_;
        let mname = &method.name;
        // Method must be exported.
        if !method.is_exported() {
            continue;
        }
        // Method needs three ins: receiver, *args, *reply.
        if mtype.num_in() != 3 {
            if log_err {
                crate::log::printf(format_args!(
                    "rpc.Register: method {} has {} input parameters; needs exactly three\n",
                    crate::strconv::quote(mname),
                    mtype.num_in()
                ));
            }
            continue;
        }
        // First arg need not be a pointer.
        let arg_type = mtype.in_(1);
        if !is_exported_or_builtin_type(&arg_type) {
            if log_err {
                crate::log::printf(format_args!(
                    "rpc.Register: argument type of method {} is not exported: {}\n",
                    crate::strconv::quote(mname),
                    crate::strconv::quote(arg_type.to_string())
                ));
            }
            continue;
        }
        // Second arg must be a pointer.
        let reply_type = mtype.in_(2);
        if reply_type.kind() != Kind::Pointer {
            if log_err {
                crate::log::printf(format_args!(
                    "rpc.Register: reply type of method {} is not a pointer: {}\n",
                    crate::strconv::quote(mname),
                    crate::strconv::quote(reply_type.to_string())
                ));
            }
            continue;
        }
        // Reply type must be exported.
        if !is_exported_or_builtin_type(&reply_type) {
            if log_err {
                crate::log::printf(format_args!(
                    "rpc.Register: reply type of method {} is not exported: {}\n",
                    crate::strconv::quote(mname),
                    crate::strconv::quote(reply_type.to_string())
                ));
            }
            continue;
        }
        // Method needs one out.
        if mtype.num_out() != 1 {
            if log_err {
                crate::log::printf(format_args!(
                    "rpc.Register: method {} has {} output parameters; needs exactly one\n",
                    crate::strconv::quote(mname),
                    mtype.num_out()
                ));
            }
            continue;
        }
        // The return type of the method must be error.
        let return_type = mtype.out(0);
        if return_type != Type::error_type() {
            if log_err {
                crate::log::printf(format_args!(
                    "rpc.Register: return type of method {} is {}, must be error\n",
                    crate::strconv::quote(mname),
                    crate::strconv::quote(return_type.to_string())
                ));
            }
            continue;
        }
        let mutating = typ.kind() == Kind::Pointer && value_type.method_by_name(mname).is_none();
        methods.insert(
            mname.clone(),
            Arc::new(MethodType {
                arg_type,
                reply_type,
                num_calls: AtomicU64::new(0),
                mutating,
            }),
        );
    }
    methods
}

/// A value sent as a placeholder for the server's response value when the
/// server receives an invalid request. It is never decoded by the client
/// since the Response contains an error when it is used.
fn invalid_request() -> Value {
    Value::from_parts(&reflect::struct_of(&[]), &[])
}

/// A wait group (Go `sync.WaitGroup`).
#[derive(Default)]
struct WaitGroup {
    count: Mutex<usize>,
    zero: Condvar,
}

impl WaitGroup {
    fn add(&self) {
        *lock(&self.count) += 1;
    }
    fn done(&self) {
        let mut c = lock(&self.count);
        *c -= 1;
        if *c == 0 {
            self.zero.notify_all();
        }
    }
    fn wait(&self) {
        let mut c = lock(&self.count);
        while *c > 0 {
            c = self.zero.wait(c).unwrap_or_else(|e| e.into_inner());
        }
    }
}

/// A service name with its methods, sorted.
#[cfg(feature = "net")]
pub(crate) type ServiceMethods = (String, Vec<(String, Arc<MethodType>)>);

/// What `readRequest` returns.
struct ReadRequest {
    service: Option<Arc<Service>>,
    mtype: Option<Arc<MethodType>>,
    method_name: String,
    req: Option<Request>,
    argv: Value,
    replyv: Value,
    keep_reading: bool,
    err: Option<Error>,
}

impl Default for Server {
    fn default() -> Server {
        Server::new()
    }
}

impl Server {
    /// Go `rpc.NewServer`: a new [`Server`].
    pub fn new() -> Server {
        Server {
            inner: Arc::new(ServerInner {
                service_map: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Go `Server.Register`: publishes in the server the set of methods of the
    /// receiver value that satisfy the following conditions:
    ///
    /// - exported method of exported type;
    /// - two arguments, both of exported type;
    /// - the second argument is a pointer;
    /// - one return value, of type error.
    ///
    /// It returns an error if the receiver is not an exported type or has no
    /// suitable methods. It also logs the error using package log. The client
    /// accesses each method using a string of the form `"Type.Method"`, where
    /// Type is the receiver's concrete type. Methods with a pointer receiver
    /// (`&mut self`) need a pointer: pass `&Some(value)` (an `Option` is
    /// Go's pointer) or use [`Server::register_value`].
    pub fn register<T: Reflect>(&self, rcvr: &T) -> Result<(), Error> {
        self.register_value(&rcvr.to_value())
    }

    /// [`Server::register`] for a [`reflect::Value`](crate::reflect::Value),
    /// which may be a pointer shared with the caller.
    pub fn register_value(&self, rcvr: &Value) -> Result<(), Error> {
        self.register_inner(rcvr, "", false)
    }

    /// Go `Server.RegisterName`: like [`Server::register`] but uses the
    /// provided name for the type instead of the receiver's concrete type.
    pub fn register_name<T: Reflect>(&self, name: &str, rcvr: &T) -> Result<(), Error> {
        self.register_name_value(name, &rcvr.to_value())
    }

    /// [`Server::register_name`] for a [`reflect::Value`](crate::reflect::Value).
    pub fn register_name_value(&self, name: &str, rcvr: &Value) -> Result<(), Error> {
        self.register_inner(rcvr, name, true)
    }

    fn register_inner(&self, rcvr: &Value, name: &str, use_name: bool) -> Result<(), Error> {
        let typ = rcvr.type_();
        let sname = if use_name {
            name.to_string()
        } else {
            reflect::indirect(rcvr).type_().name()
        };
        if sname.is_empty() {
            let s = format!("rpc.Register: no service name for type {typ}");
            crate::log::print(format_args!("{s}"));
            return Err(Error::new(s));
        }
        if !use_name && !crate::encoding::gob::is_exported_name(&sname) {
            let s = format!("rpc.Register: type {sname} is not exported");
            crate::log::print(format_args!("{s}"));
            return Err(Error::new(s));
        }
        // Install the methods.
        let method = suitable_methods(&typ, LOG_REGISTER_ERROR);
        if method.is_empty() {
            // To help the user, see if a pointer receiver would work.
            let ptr_methods = suitable_methods(&reflect::pointer_to(&typ), false);
            let s = if !ptr_methods.is_empty() {
                format!("rpc.Register: type {sname} has no exported methods of suitable type (hint: pass a pointer to value of that type)")
            } else {
                format!("rpc.Register: type {sname} has no exported methods of suitable type")
            };
            crate::log::print(format_args!("{s}"));
            return Err(Error::new(s));
        }
        let mut map = lock(&self.inner.service_map);
        if map.contains_key(&sname) {
            return Err(Error::new(format!("rpc: service already defined: {sname}")));
        }
        map.insert(
            sname.clone(),
            Arc::new(Service {
                rcvr: rcvr.clone(),
                typ,
                method,
                serial: Mutex::new(()),
            }),
        );
        Ok(())
    }

    fn send_response(
        &self,
        sending: &Mutex<()>,
        req: &Request,
        reply: &Value,
        codec: &dyn ServerCodec,
        errmsg: &str,
    ) {
        // Encode the response header.
        let mut resp = Response {
            service_method: req.service_method.clone(),
            seq: req.seq,
            error: String::new(),
        };
        let invalid;
        let mut reply = reply;
        if !errmsg.is_empty() {
            resp.error = errmsg.to_string();
            invalid = invalid_request();
            reply = &invalid;
        }
        let _g = lock(sending);
        let r = codec.write_response(&resp, reply);
        if super::DEBUG_LOG {
            if let Err(e) = r {
                crate::log::println(format_args!("rpc: writing response: {e}"));
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn call(
        &self,
        svc: &Service,
        sending: &Mutex<()>,
        wg: Option<&WaitGroup>,
        mtype: &MethodType,
        method_name: &str,
        req: &Request,
        argv: Value,
        replyv: Value,
        codec: &dyn ServerCodec,
    ) {
        mtype.num_calls.fetch_add(1, Ordering::SeqCst);
        // Invoke the method, providing a new value for the reply.
        let results = {
            let _g = mtype.mutating.then(|| lock(&svc.serial));
            svc.rcvr
                .method_by_name(method_name)
                .call(&[argv, replyv.clone()])
        };
        // The return value for the method is an error.
        let mut errmsg = String::new();
        if let Some(e) = results.first() {
            if e.is_valid() && !e.is_nil() {
                errmsg = crate::encoding::gob::error_text(e);
            }
        }
        self.send_response(sending, req, &replyv, codec, &errmsg);
        if let Some(wg) = wg {
            wg.done();
        }
    }

    /// Go `Server.ServeConn`: runs the server on a single connection. It
    /// blocks, serving the connection until the client hangs up. The caller
    /// typically invokes it on its own thread. It uses the gob wire format
    /// (see package gob) on the connection. To use an alternate codec, use
    /// [`Server::serve_codec`]. See [`Client::new`](super::Client::new) for
    /// information about concurrent access.
    pub fn serve_conn<C: ReadWriteCloser + 'static>(&self, conn: C) {
        self.serve_codec(GobServerCodec::new(Arc::new(conn)));
    }

    /// Go `Server.ServeCodec`: like [`Server::serve_conn`] but uses the
    /// specified codec to decode requests and encode responses.
    pub fn serve_codec<C: ServerCodec + 'static>(&self, codec: C) {
        let codec: Arc<dyn ServerCodec> = Arc::new(codec);
        let sending = Arc::new(Mutex::new(()));
        let wg = Arc::new(WaitGroup::default());
        loop {
            let rr = self.read_request(&*codec);
            if let Some(err) = rr.err {
                if super::DEBUG_LOG && !err.is_eof() {
                    crate::log::println(format_args!("rpc: {err}"));
                }
                if !rr.keep_reading {
                    break;
                }
                // Send a response if we actually managed to read a header.
                if let Some(req) = &rr.req {
                    self.send_response(
                        &sending,
                        req,
                        &invalid_request(),
                        &*codec,
                        &err.to_string(),
                    );
                }
                continue;
            }
            let (Some(svc), Some(mtype), Some(req)) = (rr.service, rr.mtype, rr.req) else {
                break;
            };
            wg.add();
            let server = self.clone();
            let (sending, wg, codec) = (sending.clone(), wg.clone(), codec.clone());
            let (argv, replyv, name) = (rr.argv, rr.replyv, rr.method_name);
            std::thread::spawn(move || {
                server.call(
                    &svc,
                    &sending,
                    Some(&wg),
                    &mtype,
                    &name,
                    &req,
                    argv,
                    replyv,
                    &*codec,
                );
            });
        }
        // We've seen that there are no more requests. Wait for responses to
        // be sent before closing codec.
        wg.wait();
        let _ = codec.close();
    }

    /// Go `Server.ServeRequest`: like [`Server::serve_codec`] but
    /// synchronously serves a single request. It does not close the codec
    /// upon completion.
    pub fn serve_request(&self, codec: &dyn ServerCodec) -> Result<(), Error> {
        let sending = Mutex::new(());
        let rr = self.read_request(codec);
        if let Some(err) = rr.err {
            if !rr.keep_reading {
                return Err(err);
            }
            // Send a response if we actually managed to read a header.
            if let Some(req) = &rr.req {
                self.send_response(&sending, req, &invalid_request(), codec, &err.to_string());
            }
            return Err(err);
        }
        if let (Some(svc), Some(mtype), Some(req)) = (rr.service, rr.mtype, rr.req) {
            self.call(
                &svc,
                &sending,
                None,
                &mtype,
                &rr.method_name,
                &req,
                rr.argv,
                rr.replyv,
                codec,
            );
        }
        Ok(())
    }

    fn read_request(&self, codec: &dyn ServerCodec) -> ReadRequest {
        let mut rr = self.read_request_header(codec);
        if rr.err.is_some() {
            if !rr.keep_reading {
                return rr;
            }
            // Discard body.
            let _ = codec.read_request_body(&Value::default());
            return rr;
        }
        let Some(mtype) = rr.mtype.clone() else {
            return rr;
        };
        // Decode the argument value.
        let mut arg_is_value = false; // if true, need to indirect before calling.
        let mut argv = if mtype.arg_type.kind() == Kind::Pointer {
            reflect::new(&mtype.arg_type.elem())
        } else {
            arg_is_value = true;
            reflect::new(&mtype.arg_type)
        };
        // argv guaranteed to be a pointer now.
        if let Err(e) = codec.read_request_body(&argv) {
            rr.err = Some(e);
            return rr;
        }
        if arg_is_value {
            argv = argv.elem();
        }
        let reply_elem = mtype.reply_type.elem();
        let replyv = reflect::new(&reply_elem);
        match reply_elem.kind() {
            Kind::Map => replyv.elem().set(&reflect::make_map(&reply_elem)),
            Kind::Slice => replyv.elem().set(&reflect::make_slice(&reply_elem, 0, 0)),
            _ => {}
        }
        rr.argv = argv;
        rr.replyv = replyv;
        rr
    }

    fn read_request_header(&self, codec: &dyn ServerCodec) -> ReadRequest {
        let mut rr = ReadRequest {
            service: None,
            mtype: None,
            method_name: String::new(),
            req: None,
            argv: Value::default(),
            replyv: Value::default(),
            keep_reading: false,
            err: None,
        };
        // Grab the request header.
        let mut req = Request::default();
        if let Err(e) = codec.read_request_header(&mut req) {
            if e.is_eof() || e.is_unexpected_eof() {
                rr.err = Some(e);
                return rr;
            }
            rr.err = Some(Error::new(format!(
                "rpc: server cannot decode request: {e}"
            )));
            return rr;
        }
        // We read the header successfully. If we see an error now, we can
        // still recover and move on to the next request.
        rr.keep_reading = true;
        let service_method = req.service_method.clone();
        rr.req = Some(req);
        let Some(dot) = service_method.rfind('.') else {
            rr.err = Some(Error::new(format!(
                "rpc: service/method request ill-formed: {service_method}"
            )));
            return rr;
        };
        let service_name = &service_method[..dot];
        let method_name = &service_method[dot + 1..];
        // Look up the request.
        let svc = lock(&self.inner.service_map).get(service_name).cloned();
        let Some(svc) = svc else {
            rr.err = Some(Error::new(format!(
                "rpc: can't find service {service_method}"
            )));
            return rr;
        };
        rr.mtype = svc.method.get(method_name).cloned();
        rr.method_name = method_name.to_string();
        if rr.mtype.is_none() {
            rr.err = Some(Error::new(format!(
                "rpc: can't find method {service_method}"
            )));
        }
        rr.service = Some(svc);
        rr
    }

    /// Go `Server.Accept`: accepts connections on the listener and serves
    /// requests for each incoming connection. It blocks until the listener
    /// returns an error. The caller typically invokes it on its own thread.
    pub fn accept(&self, lis: &dyn crate::net::Listener) {
        loop {
            let conn = match lis.accept() {
                Ok(c) => c,
                Err(e) => {
                    crate::log::print(format_args!("rpc.Serve: accept:{e}"));
                    return;
                }
            };
            let server = self.clone();
            std::thread::spawn(move || server.serve_conn(conn));
        }
    }

    /// The services as the debug page lists them: sorted by name, each with
    /// its methods sorted by name.
    #[cfg(feature = "net")]
    pub(crate) fn sorted_services(&self) -> Vec<ServiceMethods> {
        let map = lock(&self.inner.service_map);
        let mut services: Vec<_> = map
            .iter()
            .map(|(name, svc)| {
                let mut methods: Vec<(String, Arc<MethodType>)> = svc
                    .method
                    .iter()
                    .map(|(n, m)| (n.clone(), m.clone()))
                    .collect();
                methods.sort_by(|a, b| a.0.cmp(&b.0));
                (name.clone(), methods)
            })
            .collect();
        services.sort_by(|a, b| a.0.cmp(&b.0));
        services
    }
}

impl Service {
    #[allow(dead_code)]
    pub(crate) fn type_(&self) -> &Type {
        &self.typ
    }
}

/// Go `rpc.Register`: publishes the receiver's methods in the
/// [`DEFAULT_SERVER`].
pub fn register<T: Reflect>(rcvr: &T) -> Result<(), Error> {
    DEFAULT_SERVER.register(rcvr)
}

/// Go `rpc.RegisterName`: like [`register`] but uses the provided name for
/// the type instead of the receiver's concrete type.
pub fn register_name<T: Reflect>(name: &str, rcvr: &T) -> Result<(), Error> {
    DEFAULT_SERVER.register_name(name, rcvr)
}

/// Go `rpc.ServeConn`: runs the [`DEFAULT_SERVER`] on a single connection.
pub fn serve_conn<C: ReadWriteCloser + 'static>(conn: C) {
    DEFAULT_SERVER.serve_conn(conn);
}

/// Go `rpc.ServeCodec`: like [`serve_conn`] but uses the specified codec to
/// decode requests and encode responses.
pub fn serve_codec<C: ServerCodec + 'static>(codec: C) {
    DEFAULT_SERVER.serve_codec(codec);
}

/// Go `rpc.ServeRequest`: like [`serve_codec`] but synchronously serves a
/// single request. It does not close the codec upon completion.
pub fn serve_request(codec: &dyn ServerCodec) -> Result<(), Error> {
    DEFAULT_SERVER.serve_request(codec)
}

/// Go `rpc.Accept`: accepts connections on the listener and serves requests
/// to the [`DEFAULT_SERVER`] for each incoming connection.
pub fn accept(lis: &dyn crate::net::Listener) {
    DEFAULT_SERVER.accept(lis);
}

#[cfg(feature = "net")]
mod http_support {
    use super::*;
    use crate::net::http::request::Request as HttpRequest;
    use crate::net::http::{self, Handler, ResponseWriter};
    use crate::net::rpc::CONNECTED;

    impl Server {
        /// Go `Server.ServeHTTP`: implements an [`http::Handler`] that
        /// answers RPC requests.
        pub fn serve_http(&self, w: &mut dyn ResponseWriter, req: &mut HttpRequest) {
            if req.method != "CONNECT" {
                w.header().set("Content-Type", "text/plain; charset=utf-8");
                w.write_header(405);
                let _ = w.write_string("405 must CONNECT\n");
                return;
            }
            let hijacked = match w.hijacker() {
                Some(h) => h.hijack(),
                None => Err("http: ResponseWriter does not support Hijack".into()),
            };
            let hijacked = match hijacked {
                Ok(h) => h,
                Err(e) => {
                    crate::log::print(format_args!("rpc hijacking {}: {}", req.remote_addr, e));
                    return;
                }
            };
            let conn: Arc<dyn crate::net::Conn> = Arc::from(hijacked.conn);
            let _ = ReadWriteCloser::write(&conn, format!("HTTP/1.0 {CONNECTED}\n\n").as_bytes());
            self.serve_conn(conn);
        }

        /// Go `Server.HandleHTTP`: registers an HTTP handler for RPC messages
        /// on `rpc_path`, and a debugging handler on `debug_path`. It is still
        /// necessary to serve HTTP, typically on its own thread.
        pub fn handle_http(&self, rpc_path: &str, debug_path: &str) {
            let _ = http::handle(rpc_path, Arc::new(ServerHandler(self.clone())));
            let _ = http::handle(
                debug_path,
                Arc::new(super::super::debug::DebugHttp(self.clone())),
            );
        }
    }

    /// The server as an [`http::Handler`].
    pub struct ServerHandler(pub Server);

    impl Handler for ServerHandler {
        fn serve_http(&self, w: &mut dyn ResponseWriter, r: &mut HttpRequest) {
            self.0.serve_http(w, r);
        }
    }

    /// Go `rpc.HandleHTTP`: registers an HTTP handler for RPC messages to the
    /// [`DEFAULT_SERVER`] on [`DEFAULT_RPC_PATH`](super::super::DEFAULT_RPC_PATH)
    /// and a debugging handler on
    /// [`DEFAULT_DEBUG_PATH`](super::super::DEFAULT_DEBUG_PATH).
    pub fn handle_http() {
        DEFAULT_SERVER.handle_http(
            super::super::DEFAULT_RPC_PATH,
            super::super::DEFAULT_DEBUG_PATH,
        );
    }
}

#[cfg(feature = "net")]
pub use http_support::{handle_http, ServerHandler};
