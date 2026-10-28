use rust_stdlib::{
    context::{Context, Error},
    encoding::json::{self, Value},
    html,
    log::json::{Level, Logger},
};
use std::{
    collections::BTreeMap,
    io::{self, Write},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};
#[test]
fn cancellation_wakes_waiter_and_is_idempotent() {
    let (ctx, cancel) = Context::background().with_cancel();
    let waiter = ctx.clone();
    let handle = thread::spawn(move || {
        waiter.done().wait();
        waiter.err()
    });
    cancel();
    cancel();
    assert_eq!(handle.join().unwrap(), Some(Error::Canceled));
    assert_eq!(ctx.err(), Some(Error::Canceled));
}
#[test]
fn deadline_is_monotonic() {
    let (ctx, _cancel) = Context::background().with_deadline(Instant::now());
    assert_eq!(ctx.err(), Some(Error::DeadlineExceeded));
    ctx.done().wait();
    let (ctx, _cancel) = Context::background().with_timeout(Duration::from_millis(5).into());
    ctx.done().wait();
    assert_eq!(ctx.err(), Some(Error::DeadlineExceeded));
}
#[test]
fn html_text_escaping() {
    assert_eq!(
        html::escape("<a x=\"&'\">é</a>"),
        "&lt;a x=&#34;&amp;&#39;&#34;&gt;é&lt;/a&gt;"
    );
    assert_eq!(html::escape("plain"), "plain");
}
#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);
impl Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn logger_keeps_records_intact_under_concurrency() {
    let sink = Sink::default();
    let logger = Logger::new(sink.clone(), Level::Info);
    logger
        .write(Level::Debug, "filtered", BTreeMap::new())
        .unwrap();
    let threads: Vec<_> = (0..8)
        .map(|i| {
            let logger = logger.clone();
            thread::spawn(move || {
                for j in 0..50 {
                    logger
                        .write(
                            Level::Info,
                            "line\nbreak",
                            BTreeMap::from([
                                ("worker".to_owned(), Value::from(i)),
                                ("record".to_owned(), Value::from(j)),
                                ("level".to_owned(), Value::from("nested")),
                            ]),
                        )
                        .unwrap();
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    let text = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
    assert_eq!(text.lines().count(), 400);
    for line in text.lines() {
        let v = line.parse::<json::Value>().unwrap();
        assert_eq!(v.get("level").and_then(Value::as_str), Some("INFO"));
        assert_eq!(
            v.get("message").and_then(Value::as_str),
            Some("line\nbreak")
        );
        assert_eq!(
            v.get("fields")
                .unwrap()
                .get("level")
                .and_then(Value::as_str),
            Some("nested")
        );
    }
}
struct Broken;
impl Write for Broken {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::BrokenPipe, "broken"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn logger_propagates_sink_failures() {
    assert!(Logger::new(Broken, Level::Debug)
        .write(Level::Error, "error", BTreeMap::new())
        .is_err());
}
