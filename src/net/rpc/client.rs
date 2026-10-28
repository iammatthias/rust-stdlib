//! Go's `net/rpc/client.go`.

use std::collections::HashMap;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};

use crate::reflect::{self, Reflect, Value};

use super::gobcodec::GobClientCodec;
use super::{ClientCodec, Error, ReadWriteCloser, Request, Response, ServerError};

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// An active RPC (Go `rpc.Call`).
pub struct Call {
    /// The name of the service and method to call.
    pub service_method: String,
    /// The argument to the function.
    pub args: Value,
    /// The reply from the function: a pointer to receive it.
    pub reply: Value,
    /// Receives this call when [`Client::call_async`] is complete (Go `Call.Done`).
    pub done: SyncSender<Arc<Call>>,
    error: Mutex<Option<Error>>,
    receiver: Mutex<Option<Receiver<Arc<Call>>>>,
}

impl Call {
    /// Go `Call.Error`: after completion, the error status.
    pub fn error(&self) -> Option<Error> {
        lock(&self.error).clone()
    }

    /// The receiving end of the channel [`Client::call_async`] allocated when it was
    /// given none. It returns `None` if a channel was passed in, or if it was
    /// taken before.
    pub fn take_done(&self) -> Option<Receiver<Arc<Call>>> {
        lock(&self.receiver).take()
    }

    fn set_error(&self, e: Error) {
        *lock(&self.error) = Some(e);
    }

    /// Go `call.done`.
    fn finish(self: &Arc<Call>) {
        // We don't want to block here. It is the caller's responsibility to
        // make sure the channel has enough buffer space.
        if self.done.try_send(self.clone()).is_err() && super::DEBUG_LOG {
            crate::log::println(format_args!(
                "rpc: discarding Call reply due to insufficient Done chan capacity"
            ));
        }
    }
}

struct State {
    seq: u64,
    pending: HashMap<u64, Arc<Call>>,
    closing: bool,  // user has called Close
    shutdown: bool, // server has told us to stop
}

struct ClientInner {
    codec: Arc<dyn ClientCodec>,
    /// Protects the request being sent (Go `reqMutex`).
    req_mutex: Mutex<()>,
    mutex: Mutex<State>,
}

/// An RPC client (Go `rpc.Client`). There may be multiple outstanding calls
/// associated with a single client, and a client may be used by multiple
/// threads simultaneously.
pub struct Client {
    inner: Arc<ClientInner>,
}

impl Client {
    /// Go `NewClient`: a new client to handle requests to the set of services
    /// at the other end of the connection. It adds a buffer to the write side
    /// of the connection so the header and payload are sent as a unit.
    ///
    /// The read and write halves of the connection are serialized
    /// independently, so no interlocking is required. However each half may
    /// be accessed concurrently so the implementation of `conn` should protect
    /// against concurrent reads or concurrent writes.
    pub fn new<C: ReadWriteCloser + 'static>(conn: C) -> Client {
        Client::with_codec(GobClientCodec::new(Arc::new(conn)))
    }

    /// Go `NewClientWithCodec`: like [`Client::new`] but uses the specified
    /// codec to encode requests and decode responses.
    pub fn with_codec<C: ClientCodec + 'static>(codec: C) -> Client {
        let inner = Arc::new(ClientInner {
            codec: Arc::new(codec),
            req_mutex: Mutex::new(()),
            mutex: Mutex::new(State {
                seq: 0,
                pending: HashMap::new(),
                closing: false,
                shutdown: false,
            }),
        });
        let reader = inner.clone();
        std::thread::spawn(move || reader.input());
        Client { inner }
    }

    /// Go `Client.Close`: calls the underlying codec's close method. If the
    /// connection is already shutting down, [`ERR_SHUTDOWN`](super::ERR_SHUTDOWN)
    /// is returned.
    pub fn close(&self) -> Result<(), Error> {
        {
            let mut st = lock(&self.inner.mutex);
            if st.closing {
                return Err(Error::Shutdown);
            }
            st.closing = true;
        }
        self.inner.codec.close()
    }

    /// Go `Client.Go`: invokes the function asynchronously. It returns the
    /// [`Call`] structure representing the invocation. The `done` channel
    /// will signal when the call is complete by sending the same call. If
    /// `done` is `None`, a new channel is allocated with room for ten
    /// completions and its receiving end is available from
    /// [`Call::take_done`]. A given channel must be buffered
    /// (`sync_channel(n)` with `n > 0`): a completion that finds it full is
    /// dropped. `args` is the value to send and `reply` a pointer to receive
    /// the result.
    pub fn call_async(
        &self,
        service_method: &str,
        args: Value,
        reply: Value,
        done: Option<SyncSender<Arc<Call>>>,
    ) -> Arc<Call> {
        let (done, receiver) = match done {
            Some(d) => (d, None),
            None => {
                let (tx, rx) = mpsc::sync_channel(10);
                (tx, Some(rx))
            }
        };
        let call = Arc::new(Call {
            service_method: service_method.to_string(),
            args,
            reply,
            done,
            error: Mutex::new(None),
            receiver: Mutex::new(receiver),
        });
        self.inner.send(&call);
        call
    }

    /// Go `Client.Call` on values: invokes the named function, waits for it
    /// to complete, and returns its error status. `reply` is a pointer value
    /// that receives the result.
    pub fn call_value(
        &self,
        service_method: &str,
        args: &Value,
        reply: &Value,
    ) -> Result<(), Error> {
        let (tx, rx) = mpsc::sync_channel(1);
        let call = self.call_async(service_method, args.clone(), reply.clone(), Some(tx));
        let _ = rx.recv();
        match call.error() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Go `Client.Call`: invokes the named function, waits for it to
    /// complete, and returns its error status. `reply` is copied in, filled
    /// through a pointer and copied back when the call succeeds.
    pub fn call<A: Reflect, R: Reflect>(
        &self,
        service_method: &str,
        args: &A,
        reply: &mut R,
    ) -> Result<(), Error> {
        let a = args.to_value();
        let r = reflect::new(&R::reflect_type());
        r.elem().overwrite(&reply.to_value());
        self.call_value(service_method, &a, &r)?;
        *reply = R::from_value(&r.elem()).map_err(|e| Error::new(e.to_string()))?;
        Ok(())
    }
}

impl ClientInner {
    fn send(&self, call: &Arc<Call>) {
        let _req = lock(&self.req_mutex);
        // Register this call.
        let seq;
        {
            let mut st = lock(&self.mutex);
            if st.shutdown || st.closing {
                drop(st);
                call.set_error(Error::Shutdown);
                call.finish();
                return;
            }
            seq = st.seq;
            st.seq += 1;
            st.pending.insert(seq, call.clone());
        }
        // Encode and send the request.
        let request = Request {
            service_method: call.service_method.clone(),
            seq,
        };
        if let Err(err) = self.codec.write_request(&request, &call.args) {
            let c = lock(&self.mutex).pending.remove(&seq);
            if let Some(c) = c {
                c.set_error(err);
                c.finish();
            }
        }
    }

    fn input(&self) {
        let mut err: Option<Error> = None;
        while err.is_none() {
            let mut response = Response::default();
            if let Err(e) = self.codec.read_response_header(&mut response) {
                err = Some(e);
                break;
            }
            let seq = response.seq;
            let call = lock(&self.mutex).pending.remove(&seq);
            match call {
                None => {
                    // We've got no pending call. That usually means that
                    // WriteRequest partially failed, and call was already
                    // removed; response is a server telling us about an error
                    // reading request body. We should still attempt to read
                    // error body, but there's no one to give it to.
                    if let Err(e) = self.codec.read_response_body(&Value::default()) {
                        err = Some(Error::new(format!("reading error body: {e}")));
                    }
                }
                Some(call) if !response.error.is_empty() => {
                    // We've got an error response. Give this to the request;
                    // any subsequent requests will get the ReadResponseBody
                    // error if there is one.
                    call.set_error(Error::Server(ServerError(response.error)));
                    if let Err(e) = self.codec.read_response_body(&Value::default()) {
                        err = Some(Error::new(format!("reading error body: {e}")));
                    }
                    call.finish();
                }
                Some(call) => {
                    if let Err(e) = self.codec.read_response_body(&call.reply) {
                        call.set_error(Error::new(format!("reading body {e}")));
                    }
                    call.finish();
                }
            }
        }
        let err = err.unwrap_or_else(|| Error::new("unknown error"));
        // Terminate pending calls.
        let _req = lock(&self.req_mutex);
        let mut st = lock(&self.mutex);
        st.shutdown = true;
        let closing = st.closing;
        let err = if err.is_eof() {
            if closing {
                Error::Shutdown
            } else {
                Error::from(std::io::Error::from(crate::io::Error::UnexpectedEof))
            }
        } else {
            err
        };
        for (_, call) in st.pending.drain() {
            call.set_error(err.clone());
            call.finish();
        }
        if super::DEBUG_LOG && !err.is_eof() && !closing {
            crate::log::println(format_args!("rpc: client protocol error: {err}"));
        }
    }
}

/// Go `rpc.Dial`: connects to an RPC server at the specified network address.
pub fn dial(network: &str, address: &str) -> Result<Client, Error> {
    let conn: Box<dyn crate::net::Conn> = crate::net::dial(network, address)?;
    Ok(Client::new(conn))
}

#[cfg(feature = "net")]
mod http_support {
    use super::*;
    use crate::net::http::{self, BufioReader};

    /// Go `rpc.DialHTTP`: connects to an HTTP RPC server at the specified
    /// network address listening on the default HTTP RPC path.
    pub fn dial_http(network: &str, address: &str) -> Result<Client, Error> {
        dial_http_path(network, address, super::super::DEFAULT_RPC_PATH)
    }

    /// Go `rpc.DialHTTPPath`: connects to an HTTP RPC server at the specified
    /// network address and path.
    pub fn dial_http_path(network: &str, address: &str, path: &str) -> Result<Client, Error> {
        let conn: Arc<dyn crate::net::Conn> = Arc::from(crate::net::dial(network, address)?);
        let rwc: Arc<dyn ReadWriteCloser> = Arc::new(conn.clone());
        let _ = rwc.write(format!("CONNECT {path} HTTP/1.0\n\n").as_bytes());

        // Require successful HTTP response before switching to RPC protocol.
        let reader = BufioReader::new(super::super::ConnIo(rwc.clone()));
        let req = http::Request::new("CONNECT", "http://rpc.invalid/")
            .map_err(|e| Error::new(e.to_string()))?;
        let err = match http::response::read_response(&reader, Some(&req)) {
            Ok(resp) if resp.status == super::super::CONNECTED => {
                return Ok(Client::new(rwc));
            }
            Ok(resp) => format!("unexpected HTTP response: {}", resp.status),
            Err(e) => e.to_string(),
        };
        let _ = rwc.close();
        Err(Error::new(format!("dial-http {network} {address}: {err}")))
    }
}

#[cfg(feature = "net")]
pub use http_support::{dial_http, dial_http_path};
