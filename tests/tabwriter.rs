use rust_stdlib::tabwriter::{
    TabWriter, ALIGN_RIGHT, DEBUG, DISCARD_EMPTY_COLUMNS, FILTER_HTML, STRIP_ESCAPE, TAB_INDENT,
};
use std::io::{self, Write};

fn format(input: &[u8], flags: u32, min: usize, tab: usize, padding: usize, pad: u8) -> Vec<u8> {
    let mut w = TabWriter::new(Vec::new(), min, tab, padding, pad, flags).unwrap();
    w.write_all(input).unwrap();
    w.into_inner().unwrap()
}

#[test]
fn basic_columns_debug_and_right_alignment() {
    assert_eq!(
        format(b"name\tvalue\na\t17\n", 0, 1, 0, 1, b' '),
        b"name value\na    17\n"
    );
    assert_eq!(
        format(b"a\tb\nlong\tx\n", DEBUG, 1, 0, 1, b'.'),
        b"a....|b\nlong.|x\n"
    );
    assert_eq!(
        format(b"a\tb\nlong\tx\n", ALIGN_RIGHT, 1, 0, 1, b'.'),
        b"....ab\n.longx\n"
    );
}

#[test]
fn init_discards_unflushed_text_and_keeps_writer_on_limit_error() {
    let mut w = TabWriter::new(Vec::new(), 0, 8, 3, b'#', FILTER_HTML).unwrap();
    w.write_all(b"stale\tcell").unwrap();
    w.init(Vec::new(), 1, 0, 1, b'.', 0).unwrap();
    w.write_all(b"a\tb\nlong\tx\n").unwrap();
    assert_eq!(w.into_inner().unwrap(), b"a....b\nlong.x\n");

    let mut w = TabWriter::new(Vec::new(), 1, 0, 1, b'.', 0).unwrap();
    assert!(w
        .init(Vec::new(), 8 * 1024 * 1024 + 1, 0, 0, b' ', 0)
        .is_err());
    w.write_all(b"x\ty\n").unwrap();
    assert_eq!(w.into_inner().unwrap(), b"x.y\n");
}

#[test]
fn vertical_hard_tabs_formfeeds_and_tab_indent() {
    assert_eq!(
        format(b"a\x0bb\nlong\x0bc\x0cend", 0, 0, 0, 1, b'.'),
        b"a....b\nlong.c\nend"
    );
    assert_eq!(
        format(b"\tx\n\ty\n", TAB_INDENT, 8, 4, 0, b'.'),
        b"\t\tx\n\t\ty\n"
    );
    assert_eq!(format(b"a\t\n\n", DEBUG, 1, 0, 0, b'.'), b"a|\n\n");
    assert_eq!(
        format(b"a\x0b\x0bb", DISCARD_EMPTY_COLUMNS, 4, 0, 0, b'.'),
        b"a...b"
    );
    assert_eq!(
        format(
            b"a\x0b\x0bb",
            DISCARD_EMPTY_COLUMNS | ALIGN_RIGHT,
            4,
            0,
            0,
            b'.'
        ),
        b"...ab"
    );
}

#[test]
fn html_and_escape_filtering_preserve_source_bytes() {
    assert_eq!(
        format(b"<b>a</b>\t&amp;\nx\ty\n", FILTER_HTML, 1, 0, 1, b'.'),
        b"<b>a</b>.&amp;\nx.y\n"
    );
    let input = b"a\xffx\ty\xff\tz\n";
    assert_eq!(format(input, STRIP_ESCAPE, 1, 0, 1, b'.'), b"ax\ty.z\n");

    let input = b"<b>hello</b>\t&amp;\n\xffx\ty\xff\n";
    let mut chunked =
        TabWriter::new(Vec::new(), 1, 0, 1, b'.', FILTER_HTML | STRIP_ESCAPE).unwrap();
    for byte in input {
        chunked.write_all(std::slice::from_ref(byte)).unwrap();
    }
    assert_eq!(
        chunked.into_inner().unwrap(),
        format(input, FILTER_HTML | STRIP_ESCAPE, 1, 0, 1, b'.')
    );
}

#[test]
fn unicode_scalar_counts_not_grapheme_or_display_cells_and_writes_may_split_utf8() {
    let mut w = TabWriter::new(Vec::new(), 1, 0, 1, b'.', 0).unwrap();
    w.write_all("界".as_bytes().get(..1).unwrap()).unwrap();
    w.write_all(&"界".as_bytes()[1..]).unwrap();
    w.write_all(b"\tx\nxx\ty\n").unwrap();
    assert_eq!(w.into_inner().unwrap(), "界..x\nxx.y\n".as_bytes());
    assert_eq!(
        format("e\u{301}\tx\nxx\ty\n".as_bytes(), 0, 1, 0, 1, b'.'),
        "e\u{301}.x\nxx.y\n".as_bytes()
    );
}

struct FailAfterPrefix {
    state: std::rc::Rc<std::cell::RefCell<(Vec<u8>, usize)>>,
}
impl Write for FailAfterPrefix {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let mut s = self.state.borrow_mut();
        s.1 += 1;
        if s.1 == 1 {
            let n = b.len().min(2);
            s.0.extend_from_slice(&b[..n]);
            Ok(n)
        } else {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "sink failed"))
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn output_failure_is_latched_after_partial_sink_write() {
    let state = std::rc::Rc::new(std::cell::RefCell::new((Vec::new(), 0)));
    let mut w = TabWriter::new(
        FailAfterPrefix {
            state: state.clone(),
        },
        1,
        0,
        0,
        b' ',
        0,
    )
    .unwrap();
    w.write_all(b"a\tb\n").unwrap();
    assert_eq!(w.flush().unwrap_err().to_string(), "sink failed");
    let calls = state.borrow().1;
    assert_eq!(w.write(b"next").unwrap_err().to_string(), "sink failed");
    assert_eq!(w.flush().unwrap_err().to_string(), "sink failed");
    assert_eq!(state.borrow().1, calls);
    assert_eq!(state.borrow().0.len(), 2);
}

#[test]
fn resource_limits_reject_wide_tables_before_rendering() {
    let mut w = TabWriter::new(Vec::new(), 0, 0, 0, b' ', 0).unwrap();
    let input = vec![b'\t'; 258];
    assert!(w.write_all(&input).is_err());
}

#[test]
fn render_budget_fails_before_writing_any_output() {
    let sink = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    struct SharedSink(std::rc::Rc<std::cell::RefCell<Vec<u8>>>);
    impl Write for SharedSink {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut w = TabWriter::new(SharedSink(sink.clone()), 8 * 1024 * 1024, 0, 0, b'.', 0).unwrap();
    w.write_all(b"a\tb").unwrap();
    assert_eq!(
        w.flush().unwrap_err().to_string(),
        "tabwriter: output limit exceeded"
    );
    assert!(sink.borrow().is_empty());
}
