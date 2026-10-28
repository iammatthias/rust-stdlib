#![cfg(feature = "net")]
//! Configuration structs are plain data: every field is public, so callers
//! outside the crate can use struct-update syntax with `..Default::default()`
//! as Go users set fields on a composite literal.
use rust_stdlib::net::{
    http::{client::Client, handler_func, httptest, server::Server, Transport},
    Dialer, ListenConfig, Resolver,
};
use rust_stdlib::time;
use std::sync::Arc;

#[test]
fn http_config_structs_support_struct_update() {
    let server = Server {
        addr: "127.0.0.1:0".into(),
        handler: Some(handler_func(|_, _| {})),
        read_timeout: time::SECOND,
        ..Server::default()
    };
    assert_eq!(server.addr, "127.0.0.1:0");

    let transport = Transport {
        disable_keep_alives: true,
        max_idle_conns: 7,
        ..Default::default()
    };
    let client = Client {
        transport: Some(Arc::new(transport)),
        timeout: time::SECOND * 2,
        ..Default::default()
    };
    assert_eq!(client.timeout, time::SECOND * 2);
}

#[test]
fn httptest_server_supports_struct_update() {
    let handler = handler_func(|w, _| w.write_header(204));
    let mut server = httptest::Server {
        enable_http2: true,
        config: Server {
            read_timeout: time::SECOND,
            handler: Some(handler.clone()),
            ..Server::default()
        },
        ..httptest::Server::unstarted(handler).unwrap()
    };
    assert!(server.enable_http2);
    assert_eq!(server.config.read_timeout, time::SECOND);
    server.start().unwrap();
    assert!(server.url.starts_with("http://"));
    server.close();

    let bare = httptest::Server {
        url: "http://example.test".into(),
        ..Default::default()
    };
    assert!(bare.listener.is_none());
}

#[test]
fn net_config_structs_support_struct_update() {
    let dialer = Dialer {
        timeout: time::SECOND * 5,
        multipath_tcp: true,
        ..Default::default()
    };
    assert!(dialer.multipath_tcp);
    let lc = ListenConfig {
        multipath_tcp: true,
        ..Default::default()
    };
    assert!(lc.multipath_tcp);
    let resolver = Resolver {
        prefer_builtin: true,
        ..Default::default()
    };
    assert!(resolver.prefer_builtin);
}
