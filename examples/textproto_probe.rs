//! Line protocol used by `tools/textproto_check.py` for Go differential checks.
//! Requests are `MODE:hex`; responses match `tools/textproto_oracle.go`.
use rust_stdlib::net::textproto::{self, Error, Limits, MIMEHeader, Reader, Writer};
use std::io::{self, BufRead, Read, Write};
use std::net::{Shutdown, TcpListener};

fn from_hex(text: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if !text.len().is_multiple_of(2) {
        return Err("odd-length hex input".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| Ok(u8::from_str_radix(&text[i..i + 2], 16)?))
        .collect()
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

fn reader(data: &[u8]) -> Reader<&[u8]> {
    // Go's ReadMIMEHeader and line methods are unbounded; the generated
    // inputs stay far below these budgets.
    Reader::with_limits(
        data,
        Limits {
            max_header_bytes: usize::MAX >> 1,
            ..Limits::default()
        },
    )
}

fn header_map(header: &MIMEHeader) -> String {
    header
        .iter()
        .map(|(key, values)| {
            let values: Vec<String> = values.iter().map(hex).collect();
            format!("{}={}", hex(key), values.join(","))
        })
        .collect::<Vec<_>>()
        .join(";")
}

fn header(result: Result<MIMEHeader, Error>) -> String {
    match result {
        Ok(header) => format!("ok\t{}", header_map(&header)),
        Err(Error::Eof) => "eof".into(),
        Err(_) => "err".into(),
    }
}

fn rest(r: &mut Reader<&[u8]>) -> String {
    let mut lines = Vec::new();
    while let Ok(line) = r.read_line_bytes() {
        lines.push(hex(line));
    }
    lines.join(",")
}

fn response(result: Result<(u16, String), Error>) -> String {
    match result {
        Ok((code, message)) => format!("ok\t{code}\t{}", hex(message)),
        Err(Error::Response(e)) => format!("code\t{}\t{}", e.code, hex(e.msg)),
        Err(_) => "err".into(),
    }
}

/// Classify an error the way `tools/textproto_oracle.go` does.
fn err_text(error: &Error) -> String {
    match error {
        Error::Eof => "EOF".into(),
        Error::UnexpectedEof => "UEOF".into(),
        Error::Response(e) => format!("E:{}", hex(e.to_string())),
        Error::Protocol(e) => format!("P:{}", hex(e.to_string())),
        Error::InvalidUtf8 => "utf8".into(),
        _ => "io".into(),
    }
}

/// Play the server half of a transcript: every `G`/`S` blob is written at
/// once and the write side is shut, so the client's reads see data and then
/// EOF and can never block; the server then collects whatever the client sent.
fn serve(listener: TcpListener, ops: Vec<Vec<u8>>) -> Vec<u8> {
    let Ok((mut stream, _)) = listener.accept() else {
        return Vec::new();
    };
    for op in &ops {
        if matches!(op[0], b'G' | b'S') {
            let _ = stream.write_all(&op[1..]);
        }
    }
    let _ = stream.shutdown(Shutdown::Write);
    let mut received = Vec::new();
    let _ = stream.read_to_end(&mut received);
    received
}

/// Dial a loopback server that replays `script` and run its client
/// operations with `textproto::Conn`.
fn transcript(script: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let ops: Vec<Vec<u8>> = script.split(|&b| b == 0x1e).map(<[u8]>::to_vec).collect();
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?.to_string();
    let server = std::thread::spawn({
        let ops = ops.clone();
        move || serve(listener, ops)
    });
    let mut conn = textproto::dial("tcp", &addr)?;
    let mut out = Vec::new();
    let mut id = 0;
    for op in &ops {
        let arg = &op[1..];
        let res = match op[0] {
            b'G' | b'S' => continue,
            b'C' => match conn.cmd(std::str::from_utf8(arg)?) {
                Ok(next) => {
                    id = next;
                    format!("C:ok:{id}")
                }
                Err(_) => "C:io".into(),
            },
            b'T' => {
                conn.pipeline.start_response(id);
                "T".into()
            }
            b'E' => {
                conn.pipeline.end_response(id);
                "E".into()
            }
            kind @ (b'R' | b'Q') => {
                let expect = std::str::from_utf8(arg)?.parse()?;
                let result = if kind == b'R' {
                    conn.reader.read_response(expect)
                } else {
                    conn.reader.read_code_line(expect)
                };
                match result {
                    Ok((code, msg)) => format!("{}:{code}:{}:", kind as char, hex(msg)),
                    Err(e) => format!("{}:0::{}", kind as char, err_text(&e)),
                }
            }
            b'l' => match conn.reader.read_line() {
                Ok(line) => format!("l:{}:", hex(line)),
                Err(e) => format!("l::{}", err_text(&e)),
            },
            b'D' => match conn.reader.read_dot_lines() {
                Ok(lines) => {
                    let lines: Vec<String> = lines.iter().map(hex).collect();
                    format!("D:{}:", lines.join(","))
                }
                Err(e) => format!("D::{}", err_text(&e)),
            },
            b'B' => match conn.reader.read_dot_bytes() {
                Ok(body) => format!("B:{}:", hex(body)),
                Err(e) => format!("B::{}", err_text(&e)),
            },
            b'H' => match conn.reader.read_mime_header() {
                Ok(h) => format!("H:{}:", header_map(&h)),
                Err(e) => format!("H::{}", err_text(&e)),
            },
            other => return Err(format!("unknown transcript op {other}").into()),
        };
        out.push(res);
    }
    if conn.close().is_err() {
        out.push("close:io".into());
    }
    let received = server.join().map_err(|_| "server thread panicked")?;
    out.push(format!("sent:{}", hex(received)));
    Ok(out.join("|"))
}

fn handle(mode: &str, data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    Ok(match mode {
        "X" => transcript(data)?,
        "K" => hex(textproto::canonical_mime_header_key(std::str::from_utf8(
            data,
        )?)),
        "T" => hex(textproto::trim_string(std::str::from_utf8(data)?)),
        "H" => header(reader(data).read_mime_header()),
        _ if mode.starts_with("HL") => {
            let (memory, count) = mode[2..].split_once(',').ok_or("bad HL request")?;
            let limits = Limits {
                max_header_bytes: memory.parse()?,
                max_headers: count.parse()?,
                ..Limits::default()
            };
            header(Reader::with_limits(data, limits).read_mime_header())
        }
        "C" => {
            let mut r = reader(data);
            let mut lines = Vec::new();
            loop {
                match r.read_continued_line() {
                    Ok(line) => lines.push(hex(line)),
                    Err(Error::Eof) => break format!("ok\t{}", lines.join(",")),
                    Err(_) => break "err".into(),
                }
            }
        }
        "D" => {
            let mut r = reader(data);
            match r.read_dot_bytes() {
                Ok(body) => format!("ok\t{}\t{}", hex(body), rest(&mut r)),
                Err(_) => "err".into(),
            }
        }
        "S" => {
            let mut r = reader(data);
            let mut one = [0; 1];
            match r.dot_reader().read(&mut one) {
                Ok(1) => {}
                _ => return Ok("err".into()),
            }
            match r.read_line_bytes() {
                Ok(line) => format!("ok\t{}\t{}", hex(one), hex(line)),
                Err(_) => "err".into(),
            }
        }
        "L" => {
            let mut r = reader(data);
            match r.read_dot_lines() {
                Ok(lines) => {
                    let lines: Vec<String> = lines.iter().map(hex).collect();
                    format!("ok\t{}\t{}", lines.join(","), rest(&mut r))
                }
                Err(_) => "err".into(),
            }
        }
        _ if mode.starts_with('R') => response(reader(data).read_response(mode[1..].parse()?)),
        _ if mode.starts_with('Q') => response(reader(data).read_code_line(mode[1..].parse()?)),
        "W" => {
            let mut out = Vec::new();
            let mut writer = Writer::new(&mut out);
            let mut dot = writer.dot_writer();
            dot.write_all(data)?;
            dot.close()?;
            hex(out)
        }
        _ => return Err(format!("unknown mode {mode}").into()),
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        let line = line?;
        let (mode, payload) = line.split_once(':').ok_or("bad request")?;
        writeln!(out, "{}", handle(mode, &from_hex(payload)?)?)?;
    }
    out.flush()?;
    Ok(())
}
