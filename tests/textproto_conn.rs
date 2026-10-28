//! `net/textproto` Pipeline, Conn, Dial and error values.
use rust_stdlib::net::textproto::{self, Conn, Error, Pipeline, ResponseError};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[test]
fn error_text_is_gos() {
    let e = ResponseError {
        code: 5,
        msg: "no \"way\"\n\u{1}é".to_owned(),
    };
    // Go: fmt.Sprintf("%03d %q", 5, "no \"way\"\n\x01é")
    let want = "005 \"no \\\"way\\\"\\n\\x01é\"";
    assert_eq!(e.to_string(), want);
    assert_eq!(Error::Response(e.clone()).to_string(), want);
    assert_eq!(
        textproto::ProtocolError("bad thing".into()).to_string(),
        "bad thing"
    );
    let mut r = textproto::Reader::new(&b"25\r\n"[..]);
    assert_eq!(
        r.read_code_line(0).unwrap_err().to_string(),
        "short response: \"25\""
    );
    let mut r = textproto::Reader::new(&b"550 \x01bad\r\n"[..]);
    assert_eq!(
        r.read_code_line(2).unwrap_err().to_string(),
        "550 \"\\x01bad\""
    );
}

#[test]
fn pipeline_orders_requests_and_responses() {
    let p = Arc::new(Pipeline::new());
    let log = Arc::new(Mutex::new(Vec::new()));
    let ids: Vec<u64> = (0..5).map(|_| p.next()).collect();
    assert_eq!(ids, [0, 1, 2, 3, 4]);
    // Start the later ids first so every thread has to wait for its turn.
    let handles: Vec<_> = ids
        .iter()
        .rev()
        .map(|&id| {
            let (p, log) = (p.clone(), log.clone());
            let handle = thread::spawn(move || {
                p.start_request(id);
                log.lock().unwrap().push(("req", id));
                p.end_request(id);
                p.start_response(id);
                log.lock().unwrap().push(("resp", id));
                p.end_response(id);
            });
            thread::sleep(Duration::from_millis(10));
            handle
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    let log = log.lock().unwrap();
    let reqs: Vec<u64> = log.iter().filter(|e| e.0 == "req").map(|e| e.1).collect();
    let resps: Vec<u64> = log.iter().filter(|e| e.0 == "resp").map(|e| e.1).collect();
    assert_eq!(reqs, [0, 1, 2, 3, 4]);
    assert_eq!(resps, [0, 1, 2, 3, 4]);
}

#[test]
#[should_panic(expected = "out of sync")]
fn pipeline_end_out_of_sync_panics() {
    let p = Pipeline::new();
    let id = p.next();
    p.end_request(id + 1);
}

fn pair() -> (Conn<TcpStream>, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    (Conn::new(client), server)
}

#[test]
fn cmd_and_responses_over_tcp() {
    let (mut conn, mut server) = pair();
    let id = conn.cmd(format_args!("HELP {}", "me")).unwrap();
    assert_eq!(id, 0);
    let mut line = [0; 9];
    server.read_exact(&mut line).unwrap();
    assert_eq!(&line, b"HELP me\r\n");
    server
        .write_all(b"110 help follows\r\nline one\r\n..dot\r\n.\r\n250 ok\r\n")
        .unwrap();
    conn.pipeline.start_response(id);
    assert_eq!(conn.reader.read_code_line(110).unwrap().0, 110);
    assert_eq!(conn.reader.read_dot_lines().unwrap(), ["line one", ".dot"]);
    assert_eq!(conn.reader.read_code_line(250).unwrap().1, "ok");
    conn.pipeline.end_response(id);
    assert_eq!(conn.cmd(format_args!("NOOP")).unwrap(), 1);

    // The stream is full duplex: a thread blocked in read does not stop writes.
    let mut parts = conn.into_parts();
    let reader = thread::spawn(move || {
        let line = parts.reader.read_line();
        (line, parts)
    });
    thread::sleep(Duration::from_millis(50));
    let mut buf = [0; 6];
    server.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"NOOP\r\n");
    server.write_all(b"pong\r\n").unwrap();
    let (line, mut parts) = reader.join().unwrap();
    assert_eq!(line.unwrap(), "pong");
    parts.writer.print_line("late").unwrap();
    parts.closer.close().unwrap();
    let mut rest = Vec::new();
    server.read_to_end(&mut rest).unwrap();
    assert_eq!(rest, b"late\r\n");
    assert!(matches!(parts.reader.read_line(), Err(Error::Eof)));
}

#[test]
fn writes_while_reading_do_not_deadlock() {
    let (conn, mut server) = pair();
    let parts = conn.into_parts();
    let (mut reader, mut writer) = (parts.reader, parts.writer);
    let blocked = thread::spawn(move || reader.read_line());
    thread::sleep(Duration::from_millis(50));
    // Nothing has arrived, so the reader thread is blocked in read; the write
    // must not wait for it.
    writer.print_line("ping").unwrap();
    let mut buf = [0; 6];
    server.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"ping\r\n");
    server.write_all(b"done\r\n").unwrap();
    assert_eq!(blocked.join().unwrap().unwrap(), "done");
}

#[test]
fn dial_connects_and_close_ends_reads() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.write_all(b"220 hi\r\n").unwrap();
        let mut rest = Vec::new();
        s.read_to_end(&mut rest).unwrap();
        rest
    });
    let mut conn = textproto::dial("tcp", &addr).unwrap();
    assert_eq!(conn.reader.read_response(2).unwrap(), (220, "hi".into()));
    conn.cmd(format_args!("QUIT")).unwrap();
    conn.close().unwrap();
    assert_eq!(server.join().unwrap(), b"QUIT\r\n");
    assert!(matches!(conn.reader.read_line(), Err(Error::Io(_))));
    let err = textproto::dial("tcp", "127.0.0.1:1")
        .map(|_| ())
        .unwrap_err();
    assert!(
        err.to_string()
            .starts_with("dial tcp 127.0.0.1:1: connect:"),
        "{err}"
    );
}

#[cfg(unix)]
#[test]
fn unix_streams_work() {
    use std::os::unix::net::UnixStream;
    let (a, b) = UnixStream::pair().unwrap();
    let mut left = Conn::new(a);
    let mut right = Conn::new(b);
    left.cmd(format_args!("PING")).unwrap();
    assert_eq!(right.reader.read_line().unwrap(), "PING");
    right.writer.print_line("250 PONG").unwrap();
    assert_eq!(left.reader.read_response(250).unwrap().1, "PONG");
    left.close().unwrap();
    assert!(matches!(right.reader.read_line(), Err(Error::Eof)));
}
