//! Line protocol used by `tools/bytes_check.py` for Go differential checks.
use rust_stdlib::text::{Buffer, BytesExt, Reader};
use rust_stdlib::unicode::TURKISH_CASE;
use std::io::{self, BufRead, Read, Seek, SeekFrom, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

fn fnv(b: &[u8]) -> u64 {
    b.iter().fold(14695981039346656037u64, |h, &c| {
        (h ^ u64::from(c)).wrapping_mul(1099511628211)
    })
}

fn fb(b: &[u8]) -> String {
    if b.len() > 64 {
        return format!("{}:{:016x}", b.len(), fnv(b));
    }
    b.iter().map(|c| format!("{c:02x}")).collect()
}

fn fl(parts: &[&[u8]]) -> String {
    let items: Vec<String> = parts.iter().map(|p| fb(p)).collect();
    format!("{}[{}]", parts.len(), items.join(","))
}

fn ix(i: Option<usize>) -> String {
    i.map_or(-1, |v| v as i64).to_string()
}

fn fe(err: &Option<io::Error>) -> String {
    err.as_ref().map_or("nil".into(), |e| e.to_string())
}

fn fr<T>(r: &io::Result<T>) -> String {
    match r {
        Ok(_) => "nil".into(),
        Err(e) => e.to_string(),
    }
}

fn pred(id: usize) -> fn(char) -> bool {
    match id {
        0 => |r| r as u32 >= 0x80,
        1 => |r| r == 'a' || r == '\u{FFFD}',
        2 => |r| r.is_ascii_digit(),
        _ => char::is_whitespace,
    }
}

fn mapping(id: usize) -> fn(char) -> Option<char> {
    match id {
        0 => |r| if r == 'a' { None } else { Some(r) },
        1 => |r| {
            Some(if r == 'x' {
                '\u{FFFD}'
            } else if r.is_ascii_lowercase() {
                r.to_ascii_uppercase()
            } else {
                r
            })
        },
        _ => |r| Some(if r as u32 >= 0x80 { '\u{FFFD}' } else { r }),
    }
}

struct ChunkReader {
    data: Vec<u8>,
    chunk: usize,
}

impl Read for ChunkReader {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        let n = self.chunk.min(p.len()).min(self.data.len());
        p[..n].copy_from_slice(&self.data[..n]);
        self.data.drain(..n);
        Ok(n)
    }
}

struct LimitWriter {
    limit: usize,
    got: Vec<u8>,
}

impl Write for LimitWriter {
    fn write(&mut self, p: &[u8]) -> io::Result<usize> {
        let n = p.len().min(self.limit);
        self.limit -= n;
        self.got.extend_from_slice(&p[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn num(s: &str) -> i64 {
    s.parse().expect("number")
}

fn rune_err(r: io::Result<(char, usize)>) -> String {
    match r {
        Ok((c, n)) => format!("{},{},nil", c as u32, n),
        Err(e) => format!("0,0,{e}"),
    }
}

fn buf_script(parts: &[&str]) -> String {
    let spec: Vec<&str> = parts[0].split(':').collect();
    let mut b = match spec[0] {
        "NEW" => Buffer::new(),
        "NB" => {
            let data = unhex(spec[1]);
            let mut v = Vec::with_capacity(num(spec[2]) as usize);
            v.extend_from_slice(&data);
            Buffer::from_vec(v)
        }
        _ => Buffer::from_str(std::str::from_utf8(&unhex(spec[1])).expect("utf8")),
    };
    let mut out = Vec::new();
    for op in &parts[1..] {
        let f: Vec<&str> = op.split(':').collect();
        let r = match f[0] {
            "W" => format!("{},nil", b.write(&unhex(f[1])).unwrap()),
            "WS" => format!(
                "{},nil",
                b.write_string(std::str::from_utf8(&unhex(f[1])).expect("utf8"))
            ),
            "WB" => {
                b.write_byte(unhex(f[1])[0]);
                "nil".into()
            }
            "WR" => format!(
                "{},nil",
                b.write_rune(char::from_u32(num(f[1]) as u32).expect("rune"))
            ),
            "R" => {
                let mut p = vec![0u8; num(f[1]) as usize];
                let was_empty = b.len() == 0;
                let n = b.read(&mut p).unwrap();
                let err = if was_empty && !p.is_empty() {
                    "EOF"
                } else {
                    "nil"
                };
                format!("{},{},{}", n, err, fb(&p[..n]))
            }
            "RB" => match b.read_byte() {
                Ok(c) => format!("{c},nil"),
                Err(e) => format!("0,{e}"),
            },
            "RR" => rune_err(b.read_rune()),
            "UB" => fr(&b.unread_byte()),
            "UR" => fr(&b.unread_rune()),
            "N" => fb(b.next(num(f[1]) as usize)),
            "T" => {
                let n = num(f[1]) as usize;
                match catch_unwind(AssertUnwindSafe(|| b.truncate(n))) {
                    Ok(()) => "ok".into(),
                    Err(_) => "panic".into(),
                }
            }
            "G" => {
                let n = num(f[1]) as usize;
                match catch_unwind(AssertUnwindSafe(|| b.grow(n))) {
                    Ok(()) => "ok".into(),
                    Err(_) => "panic".into(),
                }
            }
            "P" => {
                let (p, err) = b.peek(num(f[1]) as usize);
                format!("{},{}", fb(p), fe(&err))
            }
            "RBY" => {
                let (line, err) = b.read_bytes(unhex(f[1])[0]);
                format!("{},{}", fb(&line), fe(&err))
            }
            "RS" => {
                let (line, err) = b.read_string(unhex(f[1])[0]);
                format!("{},{}", fb(line.as_bytes()), fe(&err))
            }
            "RST" => {
                b.reset();
                "ok".into()
            }
            "STR" => fb(b.to_string().as_bytes()),
            "RF" => {
                let mut r = ChunkReader {
                    data: unhex(f[1]),
                    chunk: num(f[2]) as usize,
                };
                match b.read_from(&mut r) {
                    Ok(n) => format!("{n},nil"),
                    Err(e) => format!("0,{e}"),
                }
            }
            "WT" => {
                let mut w = LimitWriter {
                    limit: num(f[1]) as usize,
                    got: Vec::new(),
                };
                let res = b.write_to(&mut w);
                let (n, err) = match res {
                    Ok(n) => (n, "nil".to_string()),
                    Err(e) => (w.got.len() as u64, e.to_string()),
                };
                format!("{n},{err},{}", fb(&w.got))
            }
            other => panic!("unknown buffer op {other}"),
        };
        out.push(format!(
            "{r}/{},{},{},{}",
            b.len(),
            b.cap(),
            b.available(),
            fb(b.as_bytes())
        ));
    }
    out.join(";")
}

fn reader_script(parts: &[&str]) -> String {
    let data = unhex(parts[0]);
    let mut rd = Reader::new(&data);
    let mut out = Vec::new();
    for op in &parts[1..] {
        let f: Vec<&str> = op.split(':').collect();
        let r = match f[0] {
            "R" => {
                let mut p = vec![0u8; num(f[1]) as usize];
                let at_end = rd.len() == 0;
                let n = rd.read(&mut p).unwrap();
                format!(
                    "{},{},{}",
                    n,
                    if at_end { "EOF" } else { "nil" },
                    fb(&p[..n])
                )
            }
            "RB" => match rd.read_byte() {
                Ok(c) => format!("{c},nil"),
                Err(e) => format!("0,{e}"),
            },
            "RR" => rune_err(rd.read_rune()),
            "UB" => fr(&rd.unread_byte()),
            "UR" => fr(&rd.unread_rune()),
            "RA" => {
                let mut p = vec![0u8; num(f[1]) as usize];
                let (n, err) = rd.read_at(&mut p, num(f[2]));
                format!("{},{},{}", n, fe(&err), fb(&p[..n]))
            }
            "SK" => {
                let off = num(f[2]);
                let res = match f[1] {
                    "0" if off >= 0 => rd.seek(SeekFrom::Start(off as u64)),
                    // SeekFrom::Start cannot carry a negative offset.
                    "0" => rd.stream_position().and_then(|_| {
                        Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "bytes.Reader.Seek: negative position",
                        ))
                    }),
                    "1" => rd.seek(SeekFrom::Current(off)),
                    _ => rd.seek(SeekFrom::End(off)),
                };
                match res {
                    Ok(p) => format!("{p},nil"),
                    Err(e) => format!("0,{e}"),
                }
            }
            "WT" => {
                let mut w = LimitWriter {
                    limit: num(f[1]) as usize,
                    got: Vec::new(),
                };
                let res = rd.write_to(&mut w);
                let (n, err) = match res {
                    Ok(n) => (n, "nil".to_string()),
                    Err(e) => (w.got.len() as u64, e.to_string()),
                };
                format!("{n},{err},{}", fb(&w.got))
            }
            "RST" => {
                // Reset borrows its argument for the reader's lifetime.
                let leaked: &'static [u8] = Box::leak(unhex(f[1]).into_boxed_slice());
                rd.reset(leaked);
                "ok".into()
            }
            other => panic!("unknown reader op {other}"),
        };
        out.push(format!("{r}/{},{}", rd.len(), rd.size()));
    }
    out.join(";")
}

fn bool_s(b: bool) -> String {
    b.to_string()
}

fn request(line: &str) -> String {
    let f: Vec<&str> = line.split('\t').collect();
    let a = |i: usize| unhex(f[i]);
    let n = |i: usize| num(f[i]);
    match f[0] {
        "BUF" => buf_script(&f[1..]),
        "RDR" => reader_script(&f[1..]),
        "IDX" => ix(a(1).find_bytes(&a(2))),
        "LIDX" => ix(a(1).rfind_bytes(&a(2))),
        "IB" => ix(a(1).iter().position(|&b| b == a(2)[0])),
        "LIB" => ix(a(1).iter().rposition(|&b| b == a(2)[0])),
        "IR" => match char::from_u32(n(2) as u32) {
            Some(r) => ix(a(1).find_rune(r)),
            None => "-1".into(),
        },
        "CR" => match char::from_u32(n(2) as u32) {
            Some(r) => bool_s(a(1).contains_rune(r)),
            None => "false".into(),
        },
        "IA" => ix(a(1).find_any(&a(2))),
        "LIA" => ix(a(1).rfind_any(&a(2))),
        "CA" => bool_s(a(1).contains_any(&a(2))),
        "CNT" => a(1).count_bytes(&a(2)).to_string(),
        "CONT" => bool_s(a(1).contains_bytes(&a(2))),
        "SPL" => {
            let (s, sep) = (a(1), a(2));
            match n(4) {
                0 => fl(&s.split_bytes_n(&sep, n(3) as isize)),
                1 => fl(&s.split_bytes_after_n(&sep, n(3) as isize)),
                2 => fl(&s.split_bytes(&sep).collect::<Vec<_>>()),
                _ => fl(&s.split_bytes_after(&sep).collect::<Vec<_>>()),
            }
        }
        "FLD" => {
            let s = a(1);
            format!(
                "{} {}",
                fl(&s.fields().collect::<Vec<_>>()),
                fl(&s.fields().collect::<Vec<_>>())
            )
        }
        "LN" => fl(&a(1).split_lines().collect::<Vec<_>>()),
        "FF" => {
            let s = a(1);
            let p = pred(n(2) as usize);
            format!(
                "{} {}",
                fl(&s.fields_func(p).collect::<Vec<_>>()),
                fl(&s.fields_func(p).collect::<Vec<_>>())
            )
        }
        "IF" => {
            let s = a(1);
            let p = pred(n(2) as usize);
            format!(
                "{},{},{}",
                ix(s.find_func(p)),
                ix(s.rfind_func(p)),
                s.contains_func(p)
            )
        }
        "TF" => {
            let s = a(1);
            let p = pred(n(2) as usize);
            format!(
                "{},{},{}",
                fb(s.trim_func(p)),
                fb(s.trim_start_func(p)),
                fb(s.trim_end_func(p))
            )
        }
        "MAP" => fb(&a(1).map_runes(mapping(n(2) as usize))),
        "UP" => fb(&a(1).to_upper()),
        "LOW" => fb(&a(1).to_lower()),
        "TIT" => fb(&a(1).to_title()),
        "TITLE" => fb(&a(1).title()),
        "SPC" => {
            let s = a(1);
            format!(
                "{},{},{}",
                fb(&s.to_upper_special(TURKISH_CASE)),
                fb(&s.to_lower_special(TURKISH_CASE)),
                fb(&s.to_title_special(TURKISH_CASE))
            )
        }
        "TVU" => fb(&a(1).to_valid_utf8(&a(2))),
        "RUNES" => a(1)
            .runes()
            .iter()
            .map(|&r| (r as u32).to_string())
            .collect::<Vec<_>>()
            .join(","),
        "TRIM" => {
            let (s, c) = (a(1), a(2));
            format!(
                "{},{},{}",
                fb(s.trim_cutset(&c)),
                fb(s.trim_start_cutset(&c)),
                fb(s.trim_end_cutset(&c))
            )
        }
        "TSP" => fb(a(1).trim_space()),
        "TPS" => {
            let (s, p) = (a(1), a(2));
            format!(
                "{},{}",
                fb(s.strip_prefix(&p[..]).unwrap_or(&s)),
                fb(s.strip_suffix(&p[..]).unwrap_or(&s))
            )
        }
        "REP" => fb(&a(1).replace(&a(2), &a(3), n(4) as isize)),
        "EF" => bool_s(a(1).equal_fold(&a(2))),
        "CUT" => {
            let (s, sep) = (a(1), a(2));
            let show = |r: Option<(&[u8], &[u8])>| match r {
                Some((x, y)) => format!("true,{},{}", fb(x), fb(y)),
                None => format!("false,{},", fb(&s)),
            };
            format!("{} {}", show(s.cut(&sep)), show(s.cut_last(&sep)))
        }
        other => panic!("unknown op {other}"),
    }
}

fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    let stdin = io::stdin();
    let mut out = io::BufWriter::new(io::stdout().lock());
    let mut line = String::new();
    while stdin.lock().read_line(&mut line).unwrap() > 0 {
        let text = line.trim_end_matches('\n');
        if !text.is_empty() {
            writeln!(out, "{}", request(text)).unwrap();
        }
        line.clear();
    }
}
