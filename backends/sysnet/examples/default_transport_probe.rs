//! Prints the settings of `default_transport()` in the format of
//! `tools/sysnet_oracle.go`, for the differential `tools/sysnet_check.py`.
use rust_stdlib::net::http::transport::Transport;
use rust_stdlib_sys::net::{getsockopt_int, level, opt};
use std::net::TcpListener;

fn yes<T>(o: &Option<T>) -> bool {
    o.is_some()
}

fn main() {
    let t: Transport = (*rust_stdlib_sysnet::default_transport()).clone();
    println!("proxy {}", yes(&t.proxy));
    println!("dial_context {}", yes(&t.dial_context));
    println!("dial {}", yes(&t.dial));
    println!("dial_tls_context {}", yes(&t.dial_tls_context));
    println!("dial_tls {}", yes(&t.dial_tls));
    // Go prints `TLSClientConfig != nil`: whether a caller set its own TLS
    // config instead of the defaults.
    assert_eq!(yes(&t.tls_client_config), cfg!(feature = "tls"));
    println!(
        "tls_client_config {}",
        !rust_stdlib_sysnet::uses_default_tls(&t)
    );
    println!(
        "tls_handshake_timeout_ns {}",
        t.tls_handshake_timeout.nanoseconds()
    );
    println!("disable_keep_alives {}", t.disable_keep_alives);
    println!("disable_compression {}", t.disable_compression);
    println!("max_idle_conns {}", t.max_idle_conns);
    println!("max_idle_conns_per_host {}", t.max_idle_conns_per_host);
    println!("max_conns_per_host {}", t.max_conns_per_host);
    println!("idle_conn_timeout_ns {}", t.idle_conn_timeout.nanoseconds());
    println!(
        "response_header_timeout_ns {}",
        t.response_header_timeout.nanoseconds()
    );
    println!(
        "expect_continue_timeout_ns {}",
        t.expect_continue_timeout.nanoseconds()
    );
    println!("force_attempt_http2 {}", t.force_attempt_http2);

    let ln = TcpListener::bind("127.0.0.1:0").expect("listen");
    let c = t.dial_context.as_ref().expect("dial_context")(
        &rust_stdlib::context::Context::background(),
        "tcp",
        &ln.local_addr().unwrap().to_string(),
    )
    .expect("dial");
    let sys = c
        .as_any()
        .downcast_ref::<rust_stdlib_sysnet::Conn>()
        .expect("sysnet conn")
        .sys();
    let get = |l, o| getsockopt_int(sys, l, o).expect("getsockopt");
    println!(
        "so_keepalive {}",
        get(level::SOL_SOCKET, opt::SO_KEEPALIVE) != 0
    );
    println!("keepidle_s {}", get(level::IPPROTO_TCP, opt::TCP_KEEPIDLE));
    println!(
        "keepintvl_s {}",
        get(level::IPPROTO_TCP, opt::TCP_KEEPINTVL)
    );
}
