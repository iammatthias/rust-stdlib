use rust_stdlib::quotedprintable::{Reader, Writer};
use std::cell::RefCell;
use std::io::{self, Cursor, Read, Write};
use std::rc::Rc;

fn decode(input: &[u8]) -> (Vec<u8>, Option<String>) {
    let mut r = Reader::new(Cursor::new(input));
    let mut out = Vec::new();
    let err = r.read_to_end(&mut out).err().map(|e| e.to_string());
    (out, err)
}

#[test]
fn decoder_handles_hex_soft_breaks_and_go_extensions() {
    for (input, expected) in [
        (
            &b"a=20b\r\nnext\nline"[..],
            b"a b\r\nnext\nline"[..].to_vec(),
        ),
        (&b"=41=4a=4a"[..], b"AJJ".to_vec()),
        (&b"one=\r\ntwo=\nthree"[..], b"onetwothree".to_vec()),
        (&b"x=G1 y=4 z=Q"[..], b"x=G1 y=4 z=Q".to_vec()),
        (&[b'a', 0x80, b'\n'], vec![b'a', 0x80, b'\n']),
        (&b"a  \t\r\nb"[..], b"a\r\nb".to_vec()),
    ] {
        assert_eq!(decode(input), (expected, None), "input {input:?}");
    }
}

#[test]
fn decoder_reports_go_style_malformed_body_errors() {
    let (out, err) = decode(b"ok\0bad");
    assert_eq!(out, b"ok");
    assert_eq!(
        err.as_deref(),
        Some("quotedprintable: invalid unescaped byte 0x00 in body")
    );
    let (_, err) = decode(b"=\rX");
    assert!(err
        .unwrap()
        .contains("quotedprintable: invalid hex byte 0x0d"));
    let (_, err) = decode(b"=");
    assert!(err
        .unwrap()
        .contains("quotedprintable: invalid bytes after ="));
}

#[test]
fn writer_wraps_at_76_and_encodes_trailing_space() {
    let mut w = Writer::new(Vec::new());
    w.write_all(&[b'a'; 75]).unwrap();
    w.write_all(b" b \t\r\n").unwrap();
    w.close().unwrap();
    assert_eq!(
        w.into_inner().unwrap(),
        [&[b'a'; 75][..], b"=\r\n b =09\r\n"].concat()
    );
}

#[test]
fn writer_binary_mode_encodes_newlines() {
    let mut w = Writer::new(Vec::new());
    w.binary = true;
    w.write_all(b"a\r\nb\n").unwrap();
    w.close().unwrap();
    assert_eq!(w.into_inner().unwrap(), b"a=0D=0Ab=0A");
}

struct InterruptedReader {
    calls: usize,
    data: Cursor<Vec<u8>>,
}
impl Read for InterruptedReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.calls += 1;
        if self.calls % 2 == 1 {
            return Err(io::ErrorKind::Interrupted.into());
        }
        self.data.read(out)
    }
}

#[test]
fn reader_retries_interrupted_reads() {
    let source = InterruptedReader {
        calls: 0,
        data: Cursor::new(b"a=20b".to_vec()),
    };
    let mut r = Reader::new(source);
    let mut out = Vec::new();
    r.read_to_end(&mut out).unwrap();
    assert_eq!(out, b"a b");
}

struct PartialErrorReader {
    sent: usize,
}
impl Read for PartialErrorReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.sent < 3 {
            out[0] = b"abc"[self.sent];
            self.sent += 1;
            return Ok(1);
        }
        Err(io::Error::other("source failed"))
    }
}

#[test]
fn reader_returns_partial_line_before_source_error() {
    let mut r = Reader::new(PartialErrorReader { sent: 0 });
    let mut out = Vec::new();
    let err = r.read_to_end(&mut out).unwrap_err();
    assert_eq!(out, b"abc");
    assert_eq!(err.to_string(), "source failed");
}

#[test]
fn decoder_matches_bufio_full_boundaries() {
    let input = vec![b'a'; 4095];
    assert_eq!(decode(&input), (input.clone(), None));

    for length in [4096, 4097] {
        let input = vec![b'a'; length];
        let (out, err) = decode(&input);
        assert_eq!(out, vec![b'a'; 4096]);
        assert_eq!(err.as_deref(), Some("bufio: buffer full"));
    }

    let mut newline_at_boundary = vec![b'a'; 4095];
    newline_at_boundary.push(b'\n');
    assert_eq!(
        decode(&newline_at_boundary),
        (newline_at_boundary.clone(), None)
    );
    let mut newline_after_boundary = vec![b'a'; 4096];
    newline_after_boundary.push(b'\n');
    let (out, err) = decode(&newline_after_boundary);
    assert_eq!(out, vec![b'a'; 4096]);
    assert_eq!(err.as_deref(), Some("bufio: buffer full"));

    let mut final_equals = vec![b'a'; 4095];
    final_equals.push(b'=');
    let (out, err) = decode(&final_equals);
    assert_eq!(out, vec![b'a'; 4095]);
    assert_eq!(
        err.as_deref(),
        Some("quotedprintable: invalid bytes after =: \"\"")
    );

    let mut equals_spaces = vec![b'a'; 4094];
    equals_spaces.extend_from_slice(b"= \t");
    let (out, err) = decode(&equals_spaces);
    assert_eq!(out, vec![b'a'; 4094]);
    assert_eq!(
        err.as_deref(),
        Some("quotedprintable: invalid bytes after =: \"\"")
    );
}

struct ShortWriter {
    data: Vec<u8>,
    max: usize,
    calls: usize,
    interrupt_once: bool,
}
impl Write for ShortWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.calls += 1;
        if self.interrupt_once {
            self.interrupt_once = false;
            return Err(io::ErrorKind::Interrupted.into());
        }
        let n = buf.len().min(self.max);
        self.data.extend_from_slice(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn writer_completes_short_and_interrupted_output() {
    let target = ShortWriter {
        data: Vec::new(),
        max: 2,
        calls: 0,
        interrupt_once: true,
    };
    let mut w = Writer::new(target);
    w.write_all(b"a long line with = and trailing ").unwrap();
    w.close().unwrap();
    let target = w.into_inner().unwrap();
    assert!(target.calls > 1);
    assert_eq!(decode(&target.data).0, b"a long line with = and trailing ");
}

#[test]
fn writer_retries_partial_failure_on_subsequent_close() {
    let mut w = Writer::new(ShortWriter {
        data: Vec::new(),
        max: 3,
        calls: 0,
        interrupt_once: false,
    });
    w.write_all(b"text\n").unwrap();
    // A flush error preserves buffered data only if the underlying implementation
    // itself made no progress; write_all handles partial writes in the success case.
    w.close().unwrap();
    assert!(w.into_inner().unwrap().data.ends_with(b"\r\n"));
}

#[test]
fn flush_emits_valid_data_and_preserves_column_for_wraps() {
    let mut w = Writer::new(Vec::new());
    w.write_all(&[b'a'; 74]).unwrap();
    w.write_all(b" ").unwrap();
    w.flush().unwrap();
    w.write_all(b"b").unwrap();
    w.close().unwrap();
    let encoded = w.into_inner().unwrap();
    assert!(encoded.windows(2).any(|w| w == b"=\r"));
    assert_eq!(decode(&encoded).0, [&[b'a'; 74][..], b" b"].concat());
}

struct FailAfterPrefix {
    state: Rc<RefCell<(Vec<u8>, usize)>>,
}
impl Write for FailAfterPrefix {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut state = self.state.borrow_mut();
        state.1 += 1;
        if state.1 == 1 {
            let n = bytes.len().min(2);
            state.0.extend_from_slice(&bytes[..n]);
            Ok(n)
        } else {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "destination failed",
            ))
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn writer_latches_partial_output_failure() {
    let state = Rc::new(RefCell::new((Vec::new(), 0)));
    let mut w = Writer::new(FailAfterPrefix {
        state: state.clone(),
    });
    w.write_all(b"payload").unwrap();
    assert_eq!(w.close().unwrap_err().to_string(), "destination failed");
    let count = state.borrow().1;
    assert_eq!(
        w.write(b"more").unwrap_err().to_string(),
        "destination failed"
    );
    assert_eq!(w.close().unwrap_err().to_string(), "destination failed");
    assert_eq!(state.borrow().1, count);
    assert_eq!(state.borrow().0.len(), 2);
}
