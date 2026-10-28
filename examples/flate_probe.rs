//! Line protocol used by `tools/flate_check.py`; the requests and replies are
//! documented in `tools/flate_oracle.go`.
use rust_stdlib::compress::{flate, gzip, zlib};
use rust_stdlib::time::DateTime;
use std::io::{self, BufRead, BufWriter, Read, Write};

type Res<T> = Result<T, Box<dyn std::error::Error>>;

fn from_hex(text: &str) -> Res<Vec<u8>> {
    if text == "-" {
        return Ok(Vec::new());
    }
    if !text.len().is_multiple_of(2) {
        return Err("odd-length hex input".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| Ok(u8::from_str_radix(&text[i..i + 2], 16)?))
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn clean(text: String) -> String {
    text.replace(['\t', '\n'], " ")
}

/// `None` for "-", `Some(empty)` for "+".
fn dict_arg(text: &str) -> Res<Option<Vec<u8>>> {
    Ok(match text {
        "-" => None,
        "+" => Some(Vec::new()),
        hex => Some(from_hex(hex)?),
    })
}

fn read_all(r: &mut impl Read) -> (Vec<u8>, Option<io::Error>) {
    let mut out = Vec::new();
    let mut buf = [0u8; 509];
    loop {
        match r.read(&mut buf) {
            Ok(0) => return (out, None),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) => return (out, Some(e)),
        }
    }
}

fn header_summary(h: &gzip::Header) -> String {
    let extra = match &h.extra {
        None => "-".to_string(),
        Some(e) => format!("+{}", to_hex(e)),
    };
    let mtime = h.mod_time.map_or(0, |t| t.unix_seconds());
    format!(
        "{}|{}|{}|{}|{}",
        to_hex(h.name.as_bytes()),
        to_hex(h.comment.as_bytes()),
        extra,
        h.os,
        mtime
    )
}

fn decode(format: &str, stream: &[u8], dict: &str, multistream: bool) -> Res<String> {
    let dict = dict_arg(dict)?.unwrap_or_default();
    let mut src = stream;
    let mut summary = "-".to_string();
    let (out, err) = match format {
        "flate" => {
            let mut r = flate::Decompressor::from_buf_read_with_dictionary(&mut src, &dict);
            read_all(&mut r)
        }
        "zlib" => match zlib::Reader::from_buf_read_with_dictionary(&mut src, &dict) {
            Ok(mut r) => read_all(&mut r),
            Err(e) => (Vec::new(), Some(e)),
        },
        "gzip" => match gzip::Reader::from_buf_read(&mut src) {
            Ok(mut r) => {
                summary = header_summary(&r.header);
                r.multistream(multistream);
                read_all(&mut r)
            }
            Err(e) => (Vec::new(), Some(e)),
        },
        _ => return Err("unknown format".into()),
    };
    let (status, text) = match err {
        None => ("ok", String::new()),
        Some(e) => ("err", clean(e.to_string())),
    };
    Ok(format!(
        "{status}\t{}\t{text}\t{}\t{summary}",
        to_hex(&out),
        src.len()
    ))
}

enum Enc {
    Flate(flate::Writer<Vec<u8>>),
    Zlib(zlib::Writer<Vec<u8>>),
    Gzip(Box<gzip::Writer<Vec<u8>>>),
}

impl Enc {
    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        match self {
            Enc::Flate(w) => w.write_all(data),
            Enc::Zlib(w) => w.write_all(data),
            Enc::Gzip(w) => w.write_all(data),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Enc::Flate(w) => w.flush(),
            Enc::Zlib(w) => w.flush(),
            Enc::Gzip(w) => w.flush(),
        }
    }
    fn close(&mut self) -> io::Result<()> {
        match self {
            Enc::Flate(w) => w.close(),
            Enc::Zlib(w) => w.close(),
            Enc::Gzip(w) => w.close(),
        }
    }
    fn out(&self) -> &[u8] {
        match self {
            Enc::Flate(w) => w.get_ref(),
            Enc::Zlib(w) => w.get_ref(),
            Enc::Gzip(w) => w.get_ref(),
        }
    }
}

fn encode(f: &str, level: i32, data: &[u8], dict: &str, plan: &str, hdr: &str) -> Res<String> {
    let dict = dict_arg(dict)?;
    let made: io::Result<Enc> = match f {
        "flate" => {
            flate::Writer::with_dictionary(Vec::new(), level, dict.as_deref().unwrap_or(&[]))
                .map(Enc::Flate)
        }
        "zlib" => zlib::Writer::with_level_and_dictionary(Vec::new(), level, dict.as_deref())
            .map(Enc::Zlib),
        "gzip" => gzip::Writer::with_level(Vec::new(), level).map(|mut w| {
            if hdr != "-" {
                let parts: Vec<&str> = hdr.split('|').collect();
                w.header.name = String::from_utf8_lossy(&from_hex(parts[0]).unwrap()).into_owned();
                w.header.comment =
                    String::from_utf8_lossy(&from_hex(parts[1]).unwrap()).into_owned();
                if parts[2] != "-" {
                    w.header.extra = Some(from_hex(&parts[2][1..]).unwrap());
                }
                w.header.os = parts[3].parse().unwrap();
                let mt: i64 = parts[4].parse().unwrap();
                if mt != 0 {
                    w.header.mod_time = Some(DateTime::from_unix(mt, 0, 0).unwrap());
                }
            }
            Enc::Gzip(Box::new(w))
        }),
        _ => return Err("unknown format".into()),
    };
    let mut w = match made {
        Ok(w) => w,
        Err(e) => return Ok(format!("err\t\t{}", clean(e.to_string()))),
    };
    let mut flushes: Vec<String> = Vec::new();
    let mut rest = data;
    macro_rules! step {
        ($e:expr) => {
            if let Err(e) = $e {
                return Ok(format!(
                    "err\t{}\t{}",
                    to_hex(w.out()),
                    clean(e.to_string())
                ));
            }
        };
    }
    if plan != "-" {
        for part in plan.split(';') {
            let flush = part.ends_with('f');
            let size: usize = part.trim_end_matches('f').parse()?;
            let n = size.min(rest.len());
            step!(w.write(&rest[..n]));
            rest = &rest[n..];
            if flush {
                step!(w.flush());
                flushes.push(w.out().len().to_string());
            }
        }
    }
    step!(w.write(rest));
    step!(w.close());
    Ok(format!("ok\t{}\t{}", to_hex(w.out()), flushes.join(",")))
}

fn handle(line: &str) -> Res<String> {
    let fields: Vec<&str> = line.split(' ').collect();
    match fields[0] {
        "dec" => decode(
            fields[1],
            &from_hex(fields[2])?,
            fields[3],
            fields[4] == "1",
        ),
        "enc" => encode(
            fields[1],
            fields[2].parse()?,
            &from_hex(fields[3])?,
            fields[4],
            fields[5],
            fields[6],
        ),
        _ => Ok("err\t\tunknown op".to_string()),
    }
}

fn main() -> Res<()> {
    let mut out = BufWriter::new(io::stdout().lock());
    for line in io::stdin().lock().lines() {
        let line = line?;
        let line = line.trim_end_matches(['\r', '\n']);
        if !line.is_empty() {
            writeln!(out, "{}", handle(line)?)?;
        }
    }
    out.flush()?;
    Ok(())
}
