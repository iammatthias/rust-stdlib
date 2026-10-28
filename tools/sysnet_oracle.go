// Prints the observable settings of Go's http.DefaultTransport, one
// "key value" line each, for tools/sysnet_check.py. The dialer's keep-alive
// is read back from a socket dialed through DefaultTransport.DialContext.
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"syscall"
)

func sockopt(c net.Conn, level, name int) int {
	rc, err := c.(*net.TCPConn).SyscallConn()
	if err != nil {
		panic(err)
	}
	v := -1
	rc.Control(func(fd uintptr) {
		v, _ = syscall.GetsockoptInt(int(fd), level, name)
	})
	return v
}

func main() {
	t := http.DefaultTransport.(*http.Transport)
	fmt.Println("proxy", t.Proxy != nil)
	fmt.Println("dial_context", t.DialContext != nil)
	fmt.Println("dial", t.Dial != nil)
	fmt.Println("dial_tls_context", t.DialTLSContext != nil)
	fmt.Println("dial_tls", t.DialTLS != nil)
	fmt.Println("tls_client_config", t.TLSClientConfig != nil)
	fmt.Println("tls_handshake_timeout_ns", int64(t.TLSHandshakeTimeout))
	fmt.Println("disable_keep_alives", t.DisableKeepAlives)
	fmt.Println("disable_compression", t.DisableCompression)
	fmt.Println("max_idle_conns", t.MaxIdleConns)
	fmt.Println("max_idle_conns_per_host", t.MaxIdleConnsPerHost)
	fmt.Println("max_conns_per_host", t.MaxConnsPerHost)
	fmt.Println("idle_conn_timeout_ns", int64(t.IdleConnTimeout))
	fmt.Println("response_header_timeout_ns", int64(t.ResponseHeaderTimeout))
	fmt.Println("expect_continue_timeout_ns", int64(t.ExpectContinueTimeout))
	fmt.Println("force_attempt_http2", t.ForceAttemptHTTP2)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	c, err := t.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		panic(err)
	}
	defer c.Close()
	idle := 0x10 // TCP_KEEPALIVE on darwin
	intvl := 0x101
	if runtime.GOOS == "linux" {
		idle, intvl = 4, 5
	}
	fmt.Println("so_keepalive", sockopt(c, syscall.SOL_SOCKET, syscall.SO_KEEPALIVE) != 0)
	fmt.Println("keepidle_s", sockopt(c, syscall.IPPROTO_TCP, idle))
	fmt.Println("keepintvl_s", sockopt(c, syscall.IPPROTO_TCP, intvl))
}
