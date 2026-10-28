//! Cases ported from Go's `encoding/csv` reader_test.go and writer_test.go, for
//! the inputs that exercise distinct rules (quoting, CR handling, comments,
//! trimming, lazy quotes, field counts, error positions, non-ASCII delimiters).
//! Go's position markers are removed from the inputs; the expected positions
//! and errors are the values Go reports for those inputs.
use rust_stdlib::encoding::csv::{
    self, Reader, Writer, ERR_BARE_QUOTE, ERR_FIELD_COUNT, ERR_QUOTE,
};

#[derive(Debug, PartialEq)]
enum Event {
    Record {
        fields: Vec<String>,
        positions: Vec<(usize, usize)>,
    },
    Parse {
        start: usize,
        line: usize,
        column: usize,
        err: csv::SentinelError,
    },
    /// A non-parse error that ends the reader, such as an invalid delimiter.
    Other,
    Eof,
}

fn rec(fields: &[&str], positions: &[(usize, usize)]) -> Event {
    Event::Record {
        fields: fields.iter().map(|f| f.to_string()).collect(),
        positions: positions.to_vec(),
    }
}

fn parse(start: usize, line: usize, column: usize, err: csv::SentinelError) -> Event {
    Event::Parse {
        start,
        line,
        column,
        err,
    }
}

/// Reads every record, recording each field's position as Go's FieldPos does.
fn read(input: &str, configure: impl FnOnce(&mut Reader<&[u8]>)) -> Vec<Event> {
    let mut reader = Reader::new(input.as_bytes());
    configure(&mut reader);
    let mut events = Vec::new();
    loop {
        match reader.read() {
            Ok(None) => {
                events.push(Event::Eof);
                return events;
            }
            Ok(Some(fields)) => {
                let positions = (0..fields.len()).map(|j| reader.field_pos(j)).collect();
                events.push(Event::Record { fields, positions });
            }
            Err(csv::Error::Parse(e)) => events.push(Event::Parse {
                start: e.start_line,
                line: e.line,
                column: e.column,
                err: e.err,
            }),
            Err(_) => {
                events.push(Event::Other);
                return events;
            }
        }
    }
}

#[test]
fn reader_records_fields_and_line_endings() {
    assert_eq!(
        read("a,b,c\n", |_| {}),
        [rec(&["a", "b", "c"], &[(1, 1), (1, 3), (1, 5)]), Event::Eof]
    );
    assert_eq!(
        read("a,b\r\nc,d\r\n", |_| {}),
        [
            rec(&["a", "b"], &[(1, 1), (1, 3)]),
            rec(&["c", "d"], &[(2, 1), (2, 3)]),
            Event::Eof
        ]
    );
    // A bare CR inside an unquoted field is data.
    assert_eq!(
        read("a,b\rc,d\r\n", |_| {}),
        [
            rec(&["a", "b\rc", "d"], &[(1, 1), (1, 3), (1, 7)]),
            Event::Eof
        ]
    );
    assert_eq!(
        read("a,b,c", |_| {}),
        [rec(&["a", "b", "c"], &[(1, 1), (1, 3), (1, 5)]), Event::Eof]
    );
    assert_eq!(
        read("field1,field2\r", |_| {}),
        [rec(&["field1", "field2"], &[(1, 1), (1, 8)]), Event::Eof]
    );
    assert_eq!(
        read("\"field\"\r", |_| {}),
        [rec(&["field"], &[(1, 1)]), Event::Eof]
    );
    assert_eq!(
        read("\"field\"\r\r", |_| {}),
        [parse(1, 1, 7, ERR_QUOTE), Event::Eof]
    );
    assert_eq!(
        read("field\rfield\r", |_| {}),
        [rec(&["field\rfield"], &[(1, 1)]), Event::Eof]
    );
    assert_eq!(
        read("field\r\rfield\r\r", |_| {}),
        [rec(&["field\r\rfield\r"], &[(1, 1)]), Event::Eof]
    );
    assert_eq!(
        read("field\r\r\nfield\r\r\n", |_| {}),
        [
            rec(&["field\r"], &[(1, 1)]),
            rec(&["field\r"], &[(2, 1)]),
            Event::Eof
        ]
    );
    assert_eq!(
        read("field\r\r\n\rfield\r\r\n\r", |_| {}),
        [
            rec(&["field\r"], &[(1, 1)]),
            rec(&["\rfield\r"], &[(2, 1)]),
            Event::Eof
        ]
    );
    assert_eq!(
        read("field\r\r\n\r\rfield\r\r\n\r\r", |_| {}),
        [
            rec(&["field\r"], &[(1, 1)]),
            rec(&["\r\rfield\r"], &[(2, 1)]),
            rec(&["\r"], &[(3, 1)]),
            Event::Eof
        ]
    );
    assert_eq!(
        read("field1,field2\r\r\n\r\rfield1,field2\r\r\n\r\r,", |_| {}),
        [
            rec(&["field1", "field2\r"], &[(1, 1), (1, 8)]),
            rec(&["\r\rfield1", "field2\r"], &[(2, 1), (2, 10)]),
            rec(&["\r\r", ""], &[(3, 1), (3, 4)]),
            Event::Eof
        ]
    );
}

#[test]
fn reader_quoted_fields_and_blank_lines() {
    assert_eq!(
        read(
            "#field1,field2,field3\n\"aaa\",\"bb\nb\",ccc\n\"a,a\",\"b\"\"bb\",ccc\nzzz,yyy,xxx\n",
            |r| { r.fields_per_record = 0 }
        ),
        [
            rec(&["#field1", "field2", "field3"], &[(1, 1), (1, 9), (1, 16)]),
            rec(&["aaa", "bb\nb", "ccc"], &[(2, 1), (2, 7), (3, 4)]),
            rec(&["a,a", "b\"bb", "ccc"], &[(4, 1), (4, 7), (4, 15)]),
            rec(&["zzz", "yyy", "xxx"], &[(5, 1), (5, 5), (5, 9)]),
            Event::Eof
        ]
    );
    assert_eq!(
        read("\"two\nline\",\"one line\",\"three\nline\nfield\"", |_| {}),
        [
            rec(
                &["two\nline", "one line", "three\nline\nfield"],
                &[(1, 1), (2, 7), (2, 18)]
            ),
            Event::Eof
        ]
    );
    assert_eq!(
        read("a,b,c\n\nd,e,f\n\n", |_| {}),
        [
            rec(&["a", "b", "c"], &[(1, 1), (1, 3), (1, 5)]),
            rec(&["d", "e", "f"], &[(3, 1), (3, 3), (3, 5)]),
            Event::Eof
        ]
    );
    assert_eq!(
        read("\"field\"\"\n", |_| {}),
        [parse(1, 1, 10, ERR_QUOTE), Event::Eof]
    );
    assert_eq!(
        read("\"\"\"\"\"\"\n", |r| r.lazy_quotes = true),
        [rec(&["\"\""], &[(1, 1)]), Event::Eof]
    );
    assert_eq!(
        read("\"a\" ,b", |_| {}),
        [parse(1, 1, 3, ERR_QUOTE), Event::Eof]
    );
    assert_eq!(
        read("a,b\n\"d\n\n,e", |_| {}),
        [
            rec(&["a", "b"], &[(1, 1), (1, 3)]),
            parse(2, 4, 3, ERR_QUOTE),
            Event::Eof
        ]
    );
    assert_eq!(
        read("a,\"b\nc\"d,e", |_| {}),
        [parse(1, 2, 2, ERR_QUOTE), Event::Eof]
    );
    assert_eq!(
        read("A,\"Hello\r\nHi\",B\r\n", |_| {}),
        [
            rec(&["A", "Hello\nHi", "B"], &[(1, 1), (1, 3), (2, 5)]),
            Event::Eof
        ]
    );
}

#[test]
fn reader_quote_errors_and_lazy_quotes() {
    assert_eq!(
        read("a\"\"b,c", |_| {}),
        [parse(1, 1, 2, ERR_BARE_QUOTE), Event::Eof]
    );
    assert_eq!(
        read("a\"\"b,c", |r| r.lazy_quotes = true),
        [rec(&["a\"\"b", "c"], &[(1, 1), (1, 6)]), Event::Eof]
    );
    assert_eq!(
        read("a \"word\",\"b\"", |_| {}),
        [parse(1, 1, 3, ERR_BARE_QUOTE), Event::Eof]
    );
    assert_eq!(
        read("\"a word\",b\"", |_| {}),
        [parse(1, 1, 11, ERR_BARE_QUOTE), Event::Eof]
    );
    assert_eq!(
        read("\"a \"word\",\"b\"", |_| {}),
        [parse(1, 1, 4, ERR_QUOTE), Event::Eof]
    );
    assert_eq!(
        read("a \"word\",\"1\"2\",a\",\"b", |r| r.lazy_quotes = true),
        [
            rec(
                &["a \"word\"", "1\"2", "a\"", "b"],
                &[(1, 1), (1, 10), (1, 16), (1, 19)]
            ),
            Event::Eof
        ]
    );
    assert_eq!(
        read("a \"word\",\"1\"2\",a\"", |r| r.lazy_quotes = true),
        [
            rec(&["a \"word\"", "1\"2", "a\""], &[(1, 1), (1, 10), (1, 16)]),
            Event::Eof
        ]
    );
    assert_eq!(
        read(" \"a\", \" b\",c", |r| r.trim_leading_space = true),
        [
            rec(&["a", " b", "c"], &[(1, 2), (1, 7), (1, 12)]),
            Event::Eof
        ]
    );
}

#[test]
fn reader_field_counts_and_trailing_commas() {
    assert_eq!(
        read("a,b,c\nd,e", |r| r.fields_per_record = 0),
        [
            rec(&["a", "b", "c"], &[(1, 1), (1, 3), (1, 5)]),
            parse(2, 2, 1, ERR_FIELD_COUNT),
            Event::Eof
        ]
    );
    assert_eq!(
        read("a,b,c\nd,e\nf", |r| r.fields_per_record = 0),
        [
            rec(&["a", "b", "c"], &[(1, 1), (1, 3), (1, 5)]),
            parse(2, 2, 1, ERR_FIELD_COUNT),
            parse(3, 3, 1, ERR_FIELD_COUNT),
            Event::Eof
        ]
    );
    assert_eq!(
        read("a,b,c", |r| r.fields_per_record = 2),
        [parse(1, 1, 1, ERR_FIELD_COUNT), Event::Eof]
    );
    assert_eq!(
        read("a,b,c\nd,e", |_| {}),
        [
            rec(&["a", "b", "c"], &[(1, 1), (1, 3), (1, 5)]),
            parse(2, 2, 1, ERR_FIELD_COUNT),
            Event::Eof
        ]
    );
    // A negative count disables the check.
    assert_eq!(
        read("a,b,c\nd,e", |r| r.fields_per_record = -1),
        [
            rec(&["a", "b", "c"], &[(1, 1), (1, 3), (1, 5)]),
            rec(&["d", "e"], &[(2, 1), (2, 3)]),
            Event::Eof
        ]
    );
    assert_eq!(
        read("a,b,c,", |_| {}),
        [
            rec(&["a", "b", "c", ""], &[(1, 1), (1, 3), (1, 5), (1, 7)]),
            Event::Eof
        ]
    );
    assert_eq!(
        read("a,b,c, \n", |r| r.trim_leading_space = true),
        [
            rec(&["a", "b", "c", ""], &[(1, 1), (1, 3), (1, 5), (1, 8)]),
            Event::Eof
        ]
    );
    assert_eq!(
        read("a,b,c, \n", |_| {}),
        [
            rec(&["a", "b", "c", " "], &[(1, 1), (1, 3), (1, 5), (1, 7)]),
            Event::Eof
        ]
    );
    assert_eq!(
        read("a,b,c\nd,e,f\ng,hi,", |r| r.trim_leading_space = true),
        [
            rec(&["a", "b", "c"], &[(1, 1), (1, 3), (1, 5)]),
            rec(&["d", "e", "f"], &[(2, 1), (2, 3), (2, 5)]),
            rec(&["g", "hi", ""], &[(3, 1), (3, 3), (3, 6)]),
            Event::Eof
        ]
    );
    assert_eq!(
        read("a,b,\nc,d,e", |r| r.trim_leading_space = true),
        [
            rec(&["a", "b", ""], &[(1, 1), (1, 3), (1, 5)]),
            rec(&["c", "d", "e"], &[(2, 1), (2, 3), (2, 5)]),
            Event::Eof
        ]
    );
}

#[test]
fn reader_comments_and_non_ascii_delimiters() {
    assert_eq!(
        read("#1,2,3\na,b,c\n#comment", |r| r.comment = Some('#')),
        [rec(&["a", "b", "c"], &[(2, 1), (2, 3), (2, 5)]), Event::Eof]
    );
    assert_eq!(
        read("#1,2,3\na,b,c", |_| {}),
        [
            rec(&["#1", "2", "3"], &[(1, 1), (1, 4), (1, 6)]),
            rec(&["a", "b", "c"], &[(2, 1), (2, 3), (2, 5)]),
            Event::Eof
        ]
    );
    assert_eq!(
        read("a£b,c£ \td,e\n€ comment\n", |r| {
            r.comma = '£';
            r.comment = Some('€');
            r.trim_leading_space = true;
        }),
        [
            rec(&["a", "b,c", "d,e"], &[(1, 1), (1, 4), (1, 11)]),
            Event::Eof
        ]
    );
    assert_eq!(
        read("a€\"  b,\"€ c\nλ comment\n", |r| {
            r.comma = '€';
            r.comment = Some('λ');
        }),
        [
            rec(&["a", "  b,", " c"], &[(1, 1), (1, 5), (1, 14)]),
            Event::Eof
        ]
    );
    // λ and θ share a leading byte; the parser must not confuse them.
    assert_eq!(
        read("\"abθcd\"λefθgh", |r| {
            r.comma = 'λ';
            r.comment = Some('€');
        }),
        [rec(&["abθcd", "efθgh"], &[(1, 1), (1, 11)]), Event::Eof]
    );
}

#[test]
fn reader_rejects_invalid_delimiters() {
    for (comma, comment) in [
        ('"', None),
        ('\r', None),
        ('\n', None),
        ('\0', None),
        (',', Some(',')),
    ] {
        assert_eq!(
            read("a,b", |r| {
                r.comma = comma;
                r.comment = comment;
            }),
            [Event::Other],
            "{comma:?} {comment:?}"
        );
    }
}

#[test]
fn reader_read_all_and_error_text() {
    let mut reader = Reader::new(&b"a,b\nc\n"[..]);
    let err = reader.read_all().unwrap_err();
    assert_eq!(err.to_string(), "record on line 2: wrong number of fields");
    let mut reader = Reader::new(&b"a\n\"b\nc\"d,e\n"[..]);
    let err = reader.read_all().unwrap_err();
    assert_eq!(
        err.to_string(),
        "record on line 2; parse error on line 3, column 2: extraneous or missing \" in quoted-field"
    );
    let mut reader = Reader::new(&b"a,\"b\nc\"d,e"[..]);
    let err = reader.read_all().unwrap_err();
    assert_eq!(
        err.to_string(),
        "record on line 1; parse error on line 2, column 2: extraneous or missing \" in quoted-field"
    );
    let mut reader = Reader::new(&b"a,b,c\n"[..]);
    reader.read_all().unwrap();
    assert_eq!(reader.input_offset(), 6);
}

fn write(records: &[Vec<&str>], configure: impl FnOnce(&mut Writer<Vec<u8>>)) -> String {
    let mut writer = Writer::new(Vec::new());
    configure(&mut writer);
    for record in records {
        writer.write(record).unwrap();
    }
    writer.flush().unwrap();
    String::from_utf8(writer.into_inner().unwrap()).unwrap()
}

#[test]
fn writer_quoting_and_line_endings() {
    assert_eq!(write(&[vec!["abc"]], |_| {}), "abc\n");
    // Empty fields are not quoted; a leading space is.
    assert_eq!(write(&[vec!["", "x", ""]], |_| {}), ",x,\n");
    assert_eq!(
        write(&[vec![" lead", "trail "]], |_| {}),
        "\" lead\",trail \n"
    );
    assert_eq!(
        write(&[vec!["\\."], vec!["a\\."]], |_| {}),
        "\"\\.\"\na\\.\n"
    );
    assert_eq!(
        write(&[vec!["a\"b", "c,d", "e\nf"]], |_| {}),
        "\"a\"\"b\",\"c,d\",\"e\nf\"\n"
    );
    // With UseCRLF a bare CR inside quotes is dropped and LF becomes CRLF.
    assert_eq!(
        write(&[vec!["a\rb", "c"]], |w| w.use_crlf = true),
        "\"ab\",c\r\n"
    );
    assert_eq!(write(&[vec!["a\rb", "c"]], |_| {}), "\"a\rb\",c\n");
    assert_eq!(
        write(&[vec!["x"], vec!["y"]], |w| w.use_crlf = true),
        "x\r\ny\r\n"
    );
    assert_eq!(
        write(&[vec!["a", "b\nc"]], |w| w.use_crlf = true),
        "a,\"b\r\nc\"\r\n"
    );
    assert_eq!(write(&[Vec::new()], |_| {}), "\n");
}

#[test]
fn writer_custom_delimiters_and_errors() {
    assert_eq!(write(&[vec!["a", "b"]], |w| w.comma = ';'), "a;b\n");
    assert_eq!(write(&[vec!["a;b", "c"]], |w| w.comma = ';'), "\"a;b\";c\n");
    assert_eq!(write(&[vec!["é", "雪"]], |w| w.comma = 'é'), "\"é\"é雪\n");
    let mut writer = Writer::new(Vec::new());
    writer.comma = '"';
    assert!(writer.write(&["a"]).is_err());
    assert!(writer.error().is_none());
}

#[test]
fn read_raw_returns_the_record_with_the_error_like_go() {
    // A field-count error comes with its record.
    let mut r = Reader::new("a,b\nc\n".as_bytes());
    r.fields_per_record = 2;
    assert_eq!(r.read_raw().0, [b"a".to_vec(), b"b".to_vec()]);
    let (record, err) = r.read_raw();
    assert_eq!(record, [b"c".to_vec()]);
    assert!(matches!(err, Some(csv::Error::Parse(e)) if e.err == ERR_FIELD_COUNT));
    assert!(matches!(r.read_raw(), (_, Some(csv::Error::Eof))));

    // A bare quote returns the fields before it; invalid UTF-8 is kept as bytes.
    let mut r = Reader::new(&b"ok,\xff\xfe,a\"b\n"[..]);
    let (record, err) = r.read_raw();
    assert_eq!(record, [b"ok".to_vec(), b"\xff\xfe".to_vec()]);
    assert!(matches!(err, Some(csv::Error::Parse(e)) if e.err == ERR_BARE_QUOTE));
    assert!(Reader::new(&b"\xff\n"[..]).read().is_err());
}

#[test]
fn limits_are_opt_in() {
    let field = "x".repeat(2 << 20);
    let mut r = Reader::new(field.as_bytes());
    assert_eq!(r.read().unwrap().unwrap()[0].len(), field.len());
}
