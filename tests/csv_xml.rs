use rust_stdlib::encoding::{csv, xml};
use std::io::{self, Read, Write};
fn records(s: &str) -> io::Result<Vec<Vec<String>>> {
    csv::Reader::new(s.as_bytes())
        .read_all()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}
#[test]
fn csv_quoting_unicode_and_crlf() {
    assert_eq!(
        records("name,notes\r\nα,\"line1\r\nline2 \"\"quoted\"\"\"\r\n").unwrap(),
        vec![vec!["name", "notes"], vec!["α", "line1\nline2 \"quoted\""]]
    );
    assert_eq!(
        records("\n\r\na,b\n\n,\n").unwrap(),
        vec![vec!["a", "b"], vec!["", ""]]
    );
    assert_eq!(records("\"\"\n").unwrap(), vec![vec![""]]);
    assert_eq!(records("a,").unwrap(), vec![vec!["a", ""]]);
}
#[test]
fn csv_negative_corpus() {
    for s in ["a\"b", "\"a", "\"a\"z", "a,b\nc", "\"a\" ,b"] {
        assert!(records(s).is_err(), "{s:?}");
    }
    // Go keeps a bare CR inside an unquoted field.
    assert_eq!(records("a\rb").unwrap(), vec![vec!["a\rb"]]);
    assert!(csv::Reader::new(&b"\xff"[..]).next().unwrap().is_err());
    for delimiter in ['"', '\r', '\n', '\0', '\u{FFFD}'] {
        let mut reader = csv::Reader::new(&b"a"[..]);
        reader.comma = delimiter;
        assert!(reader.read().is_err(), "{delimiter:?}");
    }
    let mut reader = csv::Reader::new(&b"a"[..]);
    reader.comma = 'é';
    assert_eq!(reader.read_all().unwrap(), vec![vec!["a"]]);
}
#[test]
fn csv_writer_roundtrip_and_custom_delimiter() {
    let data = vec![
        vec!["", "雪", "a,b", "\"", "line\nbreak"],
        vec!["1", "2", "3", "4", "5"],
    ];
    let mut writer = csv::Writer::new(Vec::new());
    writer.write_all(&data).unwrap();
    assert_eq!(
        records(std::str::from_utf8(&writer.into_inner().unwrap()).unwrap()).unwrap(),
        data
    );
    let mut writer = csv::Writer::new(Vec::new());
    writer.comma = ';';
    writer.write(&["a;b", "c"]).unwrap();
    writer.flush().unwrap();
    assert_eq!(writer.into_inner().unwrap(), b"\"a;b\";c\n");
    let mut reader = csv::Reader::new(&b"\"a;b\";c\n"[..]);
    reader.comma = ';';
    assert_eq!(
        reader.read_all().unwrap(),
        vec![vec!["a;b".to_string(), "c".to_string()]]
    );
}
#[test]
fn csv_budgets_and_field_count_settings() {
    for limits in [
        csv::Limits {
            max_bytes: 2,
            ..Default::default()
        },
        csv::Limits {
            max_record_bytes: 2,
            ..Default::default()
        },
        csv::Limits {
            max_field_bytes: 1,
            ..Default::default()
        },
        csv::Limits {
            max_fields: 1,
            ..Default::default()
        },
        csv::Limits {
            max_records: 0,
            ..Default::default()
        },
    ] {
        let mut reader = csv::Reader::new(&b"ab,c\n"[..]);
        reader.limits = limits;
        assert!(reader.read().is_err());
    }
    let mut reader = csv::Reader::new(&b"a\nb,c"[..]);
    reader.fields_per_record = -1;
    assert_eq!(reader.read_all().unwrap().len(), 2);
    let mut reader = csv::Reader::new(&b"a"[..]);
    reader.limits = csv::Limits {
        max_bytes: 1,
        max_field_bytes: 1,
        max_record_bytes: 1,
        ..Default::default()
    };
    assert!(reader.read().unwrap().is_some());
}
struct Short<'a>(&'a [u8]);
impl Read for Short<'_> {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        if b.is_empty() || self.0.is_empty() {
            return Ok(0);
        }
        b[0] = self.0[0];
        self.0 = &self.0[1..];
        Ok(1)
    }
}
struct Broken;
impl Write for Broken {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::BrokenPipe, "fault"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn codecs_short_reads_and_failed_writes() {
    assert_eq!(
        csv::Reader::new(Short(b"a,b\n")).read_all().unwrap(),
        vec![vec!["a", "b"]]
    );
    let mut d = xml::Decoder::new(Short(b"<r>abc</r>"));
    let mut tokens = 0;
    while d.token().is_ok() {
        tokens += 1;
    }
    assert_eq!(tokens, 3);
    let mut c = csv::Writer::new(Broken);
    c.write(&["x"]).unwrap();
    assert!(c.flush().is_err());
    assert!(c.error().is_some());
    assert!(c.write(&["x"]).is_err());
}
#[test]
fn arbitrary_codec_bytes_never_panic() {
    let mut seed = 912u64;
    for len in 0..512 {
        let bytes: Vec<_> = (0..len)
            .map(|_| {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                (seed >> 32) as u8
            })
            .collect();
        let _ = csv::Reader::new(&bytes[..]).read_all();
        let mut d = xml::Decoder::new(&bytes[..]);
        while d.token().is_ok() {}
    }
}
