//! Line protocol used by `tools/io_check.py`; mirrors `tools/io_oracle.go`.
use rust_stdlib::bufio::{self, Reader, Scanner, Split, SplitResult, Writer};
use rust_stdlib::io::fs::{self, DirEntry, FileInfo, FileMode, MapFS, MapFile, FS};
use rust_stdlib::io::{self as rio, ReadAt, WriteAt};
use rust_stdlib::time::{self, Time};
use std::cell::RefCell;
use std::io::{self, BufRead, Read, Seek, SeekFrom, Write};
use std::rc::Rc;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|c| format!("{c:02x}")).collect()
}

fn atoi(s: &str) -> i64 {
    s.parse().expect("integer")
}

fn ints(s: &str) -> Vec<usize> {
    s.split(',')
        .filter(|p| !p.is_empty())
        .map(|p| p.parse().expect("integer"))
        .collect()
}

fn es(err: Option<&io::Error>) -> String {
    err.map_or_else(|| "nil".to_string(), |e| e.to_string())
}

/// The `(n, err)` of a counted write result.
fn counted(res: Result<usize, rio::CopyError>) -> (usize, Option<io::Error>) {
    match res {
        Ok(n) => (n, None),
        Err(e) => (e.written() as usize, Some(e.into_source())),
    }
}

/// Go's `(offset, whence)` seek arguments as a `SeekFrom`, with Go's errors.
fn seek_from(offset: i64, whence: i32) -> io::Result<SeekFrom> {
    match whence {
        0 => u64::try_from(offset)
            .map(SeekFrom::Start)
            .map_err(|_| io::Error::other("Seek: invalid offset")),
        1 => Ok(SeekFrom::Current(offset)),
        2 => Ok(SeekFrom::End(offset)),
        _ => Err(io::Error::other("Seek: invalid whence")),
    }
}

/// The `(n, err)` of a counted copy result.
fn copied(res: Result<u64, rio::CopyError>) -> (u64, Option<io::Error>) {
    match res {
        Ok(n) => (n, None),
        Err(e) => (e.written(), Some(e.into_source())),
    }
}

fn cut<'a>(s: &'a str, sep: &str) -> (&'a str, &'a str) {
    s.split_once(sep).unwrap_or((s, ""))
}

/// Mirrors the Go chunkReader.
struct ChunkReader {
    data: Vec<u8>,
    pos: usize,
    chunks: Vec<usize>,
    ci: usize,
    err_at: i64,
}

impl Read for ChunkReader {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        if p.is_empty() {
            return Ok(0);
        }
        if self.err_at >= 0 && self.pos as i64 >= self.err_at {
            return Err(io::Error::other("boom"));
        }
        if self.pos >= self.data.len() {
            return Ok(0);
        }
        let mut n = self.chunks[self.ci % self.chunks.len()];
        self.ci += 1;
        let mut limit = self.data.len() - self.pos;
        if self.err_at >= 0 && (self.err_at as usize - self.pos) < limit {
            limit = self.err_at as usize - self.pos;
        }
        n = n.min(limit).min(p.len());
        p[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

fn new_chunk(data: &str, chunks: &str, err_at: &str) -> ChunkReader {
    ChunkReader {
        data: unhex(data),
        pos: 0,
        chunks: ints(chunks),
        ci: 0,
        err_at: atoi(err_at),
    }
}

/// Mirrors the Go limWriter; `buf` is shared so results can be read after
/// the writer has been moved into an adapter.
struct LimWriter {
    buf: Rc<RefCell<Vec<u8>>>,
    chunks: Vec<usize>,
    ci: usize,
    fail_after: i64,
}

impl Write for LimWriter {
    fn write(&mut self, p: &[u8]) -> io::Result<usize> {
        let len = self.buf.borrow().len();
        if self.fail_after >= 0 && len as i64 >= self.fail_after {
            return Err(io::Error::other("full"));
        }
        let mut n = self.chunks[self.ci % self.chunks.len()];
        self.ci += 1;
        n = n.min(p.len());
        if self.fail_after >= 0 && (len + n) as i64 > self.fail_after {
            n = (self.fail_after as usize) - len;
        }
        self.buf.borrow_mut().extend_from_slice(&p[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn new_lim(chunks: &str, fail_after: &str) -> (LimWriter, Rc<RefCell<Vec<u8>>>) {
    let buf = Rc::new(RefCell::new(Vec::new()));
    (
        LimWriter {
            buf: buf.clone(),
            chunks: ints(chunks),
            ci: 0,
            fail_after: atoi(fail_after),
        },
        buf,
    )
}

// ---------------------------------------------------------------- bufio

/// Go's `ReadBytes`: the data and `io.EOF` when `delim` was not found.
fn read_until<R: Read>(r: &mut Reader<R>, delim: u8) -> (Vec<u8>, Option<io::Error>) {
    let mut b = Vec::new();
    let err = match r.read_until(delim, &mut b) {
        Err(e) => Some(e),
        Ok(_) if b.last() != Some(&delim) => Some(rio::eof()),
        Ok(_) => None,
    };
    (b, err)
}

fn op_br(f: &[&str]) -> String {
    let mut r = Reader::with_size(new_chunk(f[1], f[2], f[3]), atoi(f[4]) as usize);
    let mut out: Vec<String> = Vec::new();
    for op in f[5].split(';') {
        let (name, arg) = cut(op, ":");
        match name {
            "peek" => {
                let n = atoi(arg) as usize;
                let err = r.peek(n).err();
                let b = r.buffer();
                out.push(format!(
                    "P:{}:{}",
                    hex(&b[..b.len().min(n)]),
                    es(err.as_ref())
                ));
            }
            "discard" => {
                let (n, err) = match r.discard(atoi(arg) as usize) {
                    Ok(n) => (n, None),
                    Err(e) => (e.read(), Some(e.into_source())),
                };
                out.push(format!("D:{n}:{}", es(err.as_ref())));
            }
            "rs" => {
                let (b, err) = match r.read_slice(unhex(arg)[0]) {
                    Ok(b) => (b, None),
                    Err(e) => (e.data(), Some(e.into_source())),
                };
                out.push(format!("RS:{}:{}", hex(b), es(err.as_ref())));
            }
            "rl" => {
                let (b, pre, err) = match r.read_line_bytes() {
                    Ok((b, pre)) => (b, pre, None),
                    Err(e) => (&[][..], false, Some(e)),
                };
                out.push(format!("RL:{}:{pre}:{}", hex(b), es(err.as_ref())));
            }
            "rb" => {
                let (b, err) = read_until(&mut r, unhex(arg)[0]);
                out.push(format!("RB:{}:{}", hex(&b), es(err.as_ref())));
            }
            "rstr" => {
                let (b, err) = read_until(&mut r, unhex(arg)[0]);
                out.push(format!("RT:{}:{}", hex(&b), es(err.as_ref())));
            }
            "rbyte" => match r.read_byte() {
                Ok(b) => out.push(format!("RY:{b}:nil")),
                Err(e) => out.push(format!("RY:0:{e}")),
            },
            "ubyte" => out.push(format!("UB:{}", es(r.unread_byte().err().as_ref()))),
            "rrune" => match r.read_rune() {
                Ok((c, n)) => out.push(format!("RR:{}:{n}:nil", c as u32)),
                Err(e) => out.push(format!("RR:0:0:{e}")),
            },
            "urune" => out.push(format!("UR:{}", es(r.unread_rune().err().as_ref()))),
            "buffered" => out.push(format!("BU:{}", r.buffered())),
            "size" => out.push(format!("SZ:{}", r.size())),
            "read" => {
                let n = atoi(arg) as usize;
                let mut p = vec![0; n];
                let res = r.read(&mut p);
                if n == 0 {
                    out.push(format!("R0:{}", res.unwrap_or(0)));
                } else {
                    out.push(match res {
                        Ok(0) => "R:0::EOF".to_string(),
                        Ok(k) => format!("R:{k}:{}:nil", hex(&p[..k])),
                        Err(e) => format!("R:0::{e}"),
                    });
                }
            }
            "wto" => {
                let (mut w, buf) = new_lim(&arg.replace('+', ","), f[6]);
                let res = r.write_to(&mut w);
                let (ns, err) = match &res {
                    Ok(n) => (n.to_string(), "nil".to_string()),
                    Err(e) => ("-".to_string(), e.to_string()),
                };
                out.push(format!("W:{}:{ns}:{err}", hex(&buf.borrow())));
            }
            _ => panic!("bad op {op}"),
        }
    }
    out.join("|")
}

fn op_bw(f: &[&str]) -> String {
    let (w, mut dst) = new_lim(f[2], f[3]);
    let mut b = Writer::with_size(w, atoi(f[1]) as usize);
    let mut out: Vec<String> = Vec::new();
    for op in f[4].split(';') {
        let (name, arg) = cut(op, ":");
        match name {
            "w" => {
                let (n, err) = counted(b.write_counted(&unhex(arg)));
                out.push(format!("W:{n}:{}", es(err.as_ref())));
            }
            "wb" => out.push(format!(
                "WB:{}",
                es(b.write_all(&[unhex(arg)[0]]).err().as_ref())
            )),
            "wr" => {
                let c = char::from_u32(atoi(arg) as u32).expect("scalar value");
                match b.write_char(c) {
                    Ok(n) => out.push(format!("WR:{n}:nil")),
                    Err(e) => out.push(format!("WR:-:{e}")),
                }
            }
            "ws" => {
                let s = String::from_utf8(unhex(arg)).expect("utf8");
                let (n, err) = counted(b.write_string(&s));
                out.push(format!("WS:{n}:{}", es(err.as_ref())));
            }
            "flush" => out.push(format!("F:{}", es(b.flush().err().as_ref()))),
            "avail" => out.push(format!("A:{}", b.available())),
            "buffered" => out.push(format!("BU:{}", b.buffered())),
            "size" => out.push(format!("SZ:{}", b.size())),
            "ab" => {
                let mut ab = b.available_buffer();
                let ok = ab.is_empty() && ab.capacity() == b.available();
                ab.extend_from_slice(&unhex(arg));
                let (n, err) = counted(b.write_counted(&ab));
                out.push(format!("AB:{ok}:{n}:{}", es(err.as_ref())));
            }
            "rf" => {
                let (d, c) = cut(arg, "+");
                let mut src = ChunkReader {
                    data: unhex(d),
                    pos: 0,
                    chunks: ints(&c.replace('+', ",")),
                    ci: 0,
                    err_at: -1,
                };
                let (ns, err) = match b.read_from(&mut src) {
                    Ok(n) => (n.to_string(), "nil".to_string()),
                    Err(e) => ("-".to_string(), e.to_string()),
                };
                out.push(format!("RF:{ns}:{err}"));
            }
            "reset" => {
                let (w, buf) = new_lim(f[2], f[3]);
                b.reset(w);
                dst = buf;
                out.push("RESET".to_string());
            }
            _ => panic!("bad op {op}"),
        }
    }
    out.push(format!("DST:{}", hex(&dst.borrow())));
    out.join("|")
}

fn lines_split(data: &[u8], at_eof: bool) -> SplitResult<'_> {
    bufio::scan_lines(data, at_eof)
}

fn comma(data: &[u8], at_eof: bool) -> SplitResult<'_> {
    if at_eof && data.is_empty() {
        return Ok(Split::Skip(0));
    }
    if let Some(i) = data.iter().position(|&c| c == b',') {
        return Ok(Split::Token(i + 1, &data[..i]));
    }
    if at_eof {
        return Ok(Split::Token(data.len(), data));
    }
    Ok(Split::Skip(0))
}

fn dollar_with(data: &[u8], at_eof: bool, nil_token: bool) -> SplitResult<'_> {
    if let Some(i) = data.iter().position(|&c| c == b'$') {
        let token = if nil_token { None } else { Some(&data[..i]) };
        return Ok(Split::Last(token));
    }
    if at_eof && data.is_empty() {
        return Ok(Split::Skip(0));
    }
    if at_eof {
        return Ok(Split::Token(data.len(), data));
    }
    Ok(Split::Skip(0))
}

fn dollar(data: &[u8], at_eof: bool) -> SplitResult<'_> {
    dollar_with(data, at_eof, false)
}

fn dollarnil(data: &[u8], at_eof: bool) -> SplitResult<'_> {
    dollar_with(data, at_eof, true)
}

/// Go's split function returning a negative advance; Rust has no such
/// value, so it reports the error Go's scanner would.
fn negadv(data: &[u8], _at_eof: bool) -> SplitResult<'_> {
    if !data.is_empty() {
        return Err(bufio::Error::NegativeAdvance.into());
    }
    Ok(Split::Skip(0))
}

fn toofar(data: &[u8], _at_eof: bool) -> SplitResult<'_> {
    if !data.is_empty() {
        return Ok(Split::Token(data.len() + 1, data));
    }
    Ok(Split::Skip(0))
}

fn emptytok(data: &[u8], at_eof: bool) -> SplitResult<'_> {
    if at_eof {
        return Ok(Split::Token(0, &data[..0]));
    }
    bufio::scan_bytes(data, at_eof)
}

fn errsplit(data: &[u8], at_eof: bool) -> SplitResult<'_> {
    if data.contains(&b'X') {
        return Err(io::Error::other("splitfail"));
    }
    bufio::scan_lines(data, at_eof)
}

fn needmore(data: &[u8], at_eof: bool) -> SplitResult<'_> {
    if at_eof {
        return Ok(Split::Token(data.len(), data));
    }
    Ok(Split::Skip(0))
}

fn op_sc(f: &[&str]) -> String {
    let s = Scanner::new(new_chunk(f[1], f[2], f[3]));
    let mut s = match f[4] {
        "lines" => s.split(lines_split),
        "words" => s.split(bufio::scan_words),
        "runes" => s.split(bufio::scan_runes),
        "bytes" => s.split(bufio::scan_bytes),
        "comma" => s.split(comma),
        "dollar" => s.split(dollar),
        "dollarnil" => s.split(dollarnil),
        "negadv" => s.split(negadv),
        "toofar" => s.split(toofar),
        "emptytok" => s.split(emptytok),
        "errsplit" => s.split(errsplit),
        "needmore" => s.split(needmore),
        other => panic!("bad split {other}"),
    };
    let init = atoi(f[5]);
    if init >= 0 {
        s = s.buffer(Vec::with_capacity(init as usize), atoi(f[6]) as usize);
    }
    let mut toks: Vec<String> = Vec::new();
    let mut err = None;
    while toks.len() < 3000 {
        match s.next() {
            Some(Ok(t)) => toks.push(hex(&t)),
            Some(Err(e)) => {
                err = Some(e);
                break;
            }
            None => break,
        }
    }
    match err {
        // Go's Scan panics here.
        Some(e) if bufio::Error::TooManyEmptyTokens.is(&e) => format!("{};panic", toks.join(",")),
        err => format!("{};{}", toks.join(","), es(err.as_ref())),
    }
}

// ---------------------------------------------------------------- io

fn op_ral(f: &[&str]) -> String {
    let mut r = new_chunk(f[1], f[2], f[3]);
    let mut p = vec![0; atoi(f[4]) as usize];
    let res = if f[5] == "full" {
        rio::read_full(&mut r, &mut p)
    } else {
        rio::read_at_least(&mut r, &mut p, atoi(f[5]) as usize)
    };
    let (n, err) = match res {
        Ok(n) => (n, None),
        Err(e) => (e.read(), Some(e.into_source())),
    };
    format!("{n}:{}:{}", hex(&p[..n]), es(err.as_ref()))
}

fn op_cp(f: &[&str]) -> String {
    let mut r = new_chunk(f[1], f[2], f[3]);
    let (mut w, buf) = new_lim(f[4], f[5]);
    let (mode, arg) = cut(f[6], ":");
    let (n, err) = copied(match mode {
        "copy" => rio::copy(&mut w, &mut r),
        // Go treats a negative count like zero.
        "copyn" => rio::copy_n(&mut w, &mut r, atoi(arg).max(0) as u64),
        "copybuf" => {
            let mut b = vec![0; atoi(arg) as usize];
            rio::copy_buffer(&mut w, &mut r, &mut b)
        }
        other => panic!("bad copy mode {other}"),
    });
    format!("{n}:{}:{}", es(err.as_ref()), hex(&buf.borrow()))
}

fn op_rall(f: &[&str]) -> String {
    let mut b = Vec::new();
    match new_chunk(f[1], f[2], f[3]).read_to_end(&mut b) {
        Ok(_) => format!("ok:{}", hex(&b)),
        Err(e) => format!("err:{e}"),
    }
}

/// Canonical rendering of a Read result; see fmtRead in the Go oracle.
fn fmt_read(res: io::Result<usize>, p: &[u8]) -> String {
    match res {
        Ok(0) => "0::EOF".to_string(),
        Ok(k) => format!("{k}:{}:nil", hex(&p[..k])),
        Err(e) => format!("-:-:{e}"),
    }
}

fn read_sizes<R: Read>(r: &mut R, sizes: &[usize]) -> Vec<String> {
    sizes
        .iter()
        .map(|&n| {
            let mut p = vec![0; n];
            let res = r.read(&mut p);
            fmt_read(res, &p)
        })
        .collect()
}

fn op_lr(f: &[&str]) -> String {
    // Go's LimitedReader leaves a non-positive N untouched.
    let n = atoi(f[3]);
    let mut lr = new_chunk(f[1], f[2], "-1").take(u64::try_from(n).unwrap_or(0));
    let out = read_sizes(&mut lr, &ints(f[4]));
    format!(
        "{}|N={}",
        out.join("|"),
        if n < 0 { n } else { lr.limit() as i64 }
    )
}

fn op_mr(f: &[&str]) -> String {
    let rs: Vec<Box<dyn Read>> = f[1]
        .split(',')
        .map(|d| Box::new(new_chunk(d, f[2], "-1")) as Box<dyn Read>)
        .collect();
    let mut all = rs
        .into_iter()
        .fold(Box::new(io::empty()) as Box<dyn Read>, |all, r| {
            Box::new(all.chain(r))
        });
    read_sizes(&mut all, &ints(f[3])).join("|")
}

fn op_mw(f: &[&str]) -> String {
    let mut bufs = Vec::new();
    let mut ws: Vec<Box<dyn Write>> = Vec::new();
    for spec in f[1].split(';') {
        let (c, fa) = cut(spec, "/");
        let (w, buf) = new_lim(&c.replace('+', ","), fa);
        bufs.push(buf);
        ws.push(Box::new(w));
    }
    let mut mw = rio::MultiWriter::new(ws);
    let mut out: Vec<String> = Vec::new();
    for d in f[2].split(',') {
        out.push(match mw.write(&unhex(d)) {
            Ok(n) => format!("{n}:nil"),
            Err(e) => format!("-:{e}"),
        });
    }
    for b in &bufs {
        out.push(hex(&b.borrow()));
    }
    out.join("|")
}

fn op_tr(f: &[&str]) -> String {
    let (w, buf) = new_lim(f[3], f[4]);
    let mut t = rio::TeeReader::new(new_chunk(f[1], f[2], "-1"), w);
    let out = read_sizes(&mut t, &ints(f[5]));
    format!("{}|DST:{}", out.join("|"), hex(&buf.borrow()))
}

fn op_sr(f: &[&str]) -> String {
    let data = unhex(f[1]);
    let br = rust_stdlib::text::Reader::new(&data);
    let mut s = rio::SectionReader::new(&br, atoi(f[2]), atoi(f[3]));
    let mut out: Vec<String> = Vec::new();
    for op in f[4].split(';') {
        let (name, arg) = cut(op, ":");
        match name {
            "read" => {
                let mut p = vec![0; atoi(arg) as usize];
                let res = s.read(&mut p);
                if p.is_empty() {
                    out.push(format!("R0:{}", res.unwrap_or(0)));
                } else {
                    out.push(format!("R:{}", fmt_read(res, &p)));
                }
            }
            "readat" => {
                let (a, b) = cut(arg, "@");
                let mut p = vec![0; atoi(a) as usize];
                let off = atoi(b);
                // Offsets above i64::MAX are Go's negative offsets.
                let (k, err) = match s.read_at(&mut p, off as u64) {
                    Ok(k) => (k, None),
                    Err(e) => (e.read(), Some(e.into_source())),
                };
                out.push(format!("RA:{k}:{}:{}", hex(&p[..k]), es(err.as_ref())));
            }
            "seek" => {
                let (a, b) = cut(arg, "@");
                let res = seek_from(atoi(b), atoi(a) as i32).and_then(|pos| s.seek(pos));
                out.push(match res {
                    Ok(n) => format!("S:{n}:nil"),
                    Err(e) => format!("S:0:{e}"),
                });
            }
            "size" => out.push(format!("SZ:{}", s.size())),
            "outer" => {
                let (r, off, n) = s.outer();
                out.push(format!("O:{}:{off}:{n}", std::ptr::eq(*r, &br)));
            }
            _ => panic!("bad op {op}"),
        }
    }
    out.join("|")
}

struct MemAt(Vec<u8>);

impl WriteAt for MemAt {
    fn write_at(&mut self, p: &[u8], off: u64) -> io::Result<()> {
        // Offsets above i64::MAX are Go's negative offsets.
        if off > i64::MAX as u64 {
            return Err(io::Error::other("neg"));
        }
        let end = off as usize + p.len();
        if self.0.len() < end {
            self.0.resize(end, 0);
        }
        self.0[off as usize..end].copy_from_slice(p);
        Ok(())
    }
}

fn op_ow(f: &[&str]) -> String {
    let mut o = rio::OffsetWriter::new(MemAt(Vec::new()), atoi(f[1]));
    let mut out: Vec<String> = Vec::new();
    for op in f[2].split(';') {
        let (name, arg) = cut(op, ":");
        match name {
            "write" => out.push(match o.write(&unhex(arg)) {
                Ok(n) => format!("W:{n}:nil"),
                Err(e) => format!("W:0:{e}"),
            }),
            "writeat" => {
                let (a, b) = cut(arg, "@");
                let data = unhex(a);
                let (n, err) = match o.write_at(&data, atoi(b) as u64) {
                    Ok(()) => (data.len(), None),
                    Err(e) => (0, Some(e)),
                };
                out.push(format!("WA:{n}:{}", es(err.as_ref())));
            }
            "seek" => {
                let (a, b) = cut(arg, "@");
                out.push(
                    match seek_from(atoi(b), atoi(a) as i32).and_then(|pos| o.seek(pos)) {
                        Ok(n) => format!("S:{n}:nil"),
                        Err(e) => format!("S:0:{e}"),
                    },
                );
            }
            _ => panic!("bad op {op}"),
        }
    }
    out.push(format!("MEM:{}", hex(&take_mem(o))));
    out.join("|")
}

fn take_mem(o: rio::OffsetWriter<MemAt>) -> Vec<u8> {
    o.into_inner().0
}

fn op_pipe(f: &[&str]) -> String {
    let chunks: Vec<Vec<u8>> = f[1].split(',').map(unhex).collect();
    let (mut pr, pw) = rio::pipe();
    let werr = f[3] == "err";
    let handle = std::thread::spawn(move || {
        let mut results = Vec::new();
        for c in &chunks {
            let (n, err) = counted(pw.write_shared(c));
            results.push(format!("W{n}:{}", es(err.as_ref())));
        }
        if werr {
            pw.close_with_error(Some(io::Error::other("custom")));
        } else {
            pw.close();
        }
        results
    });
    let close_after = atoi(f[4]);
    let sizes = ints(f[2]);
    let rclose = |pr: &rio::PipeReader| {
        if f[5] == "err" {
            pr.close_with_error(Some(io::Error::other("custom")));
        } else {
            pr.close();
        }
    };
    let mut out: Vec<String> = Vec::new();
    for (i, &n) in sizes.iter().enumerate() {
        if i as i64 == close_after {
            rclose(&pr);
        }
        let mut p = vec![0; n];
        let res = pr.read(&mut p);
        out.push(fmt_read(res, &p));
    }
    if close_after >= sizes.len() as i64 || close_after < 0 {
        pr.close();
    }
    out.extend(handle.join().expect("writer thread"));
    out.join("|")
}

// ---------------------------------------------------------------- io/fs

fn parse_tree(s: &str) -> MapFS {
    let mut m = MapFS::new();
    if s.is_empty() {
        return m;
    }
    for e in s.split(',') {
        if let Some(dir) = e.strip_suffix('/') {
            m.insert(
                dir,
                MapFile::new(Vec::new(), fs::MODE_DIR | FileMode(0o755)),
            );
            continue;
        }
        let (name, data) = cut(e, "=");
        m.insert(name, MapFile::new(unhex(data), FileMode(0o644)));
    }
    m
}

fn kind(d: Option<&dyn DirEntry>) -> &'static str {
    match d {
        None => "nil",
        Some(d) if d.is_dir() => "d",
        Some(_) => "f",
    }
}

fn op_walk(f: &[&str]) -> String {
    let fsys = parse_tree(f[1]);
    let mut rules = std::collections::HashMap::new();
    for r in f[3].split(';') {
        let (k, p) = cut(r, ":");
        if !k.is_empty() {
            rules.insert(p.to_string(), k.to_string());
        }
    }
    let mut out: Vec<String> = Vec::new();
    let res = fs::walk_dir(&fsys, f[2], |p, d, err| {
        let extra = match d {
            Some(d) => format!(":{}:{}", d.name(), d.file_type()),
            None => String::new(),
        };
        out.push(format!("{p}|{}{extra}|{}", kind(d), es(err.as_ref())));
        match rules.get(p).map(String::as_str) {
            Some("skipdir") => Err(fs::SKIP_DIR.into()),
            Some("skipall") => Err(fs::SKIP_ALL.into()),
            Some("err") => Err(io::Error::other("stop")),
            _ => Ok(()),
        }
    });
    format!("{}=>{}", out.join(";"), es(res.err().as_ref()))
}

fn glob_result(res: io::Result<Vec<String>>) -> String {
    match res {
        Ok(m) => format!("ok:{}", m.join(",")),
        Err(e) => format!("err:{e}"),
    }
}

fn op_glob(f: &[&str]) -> String {
    glob_result(fs::glob(&parse_tree(f[1]), f[2]))
}

fn op_valid(f: &[&str]) -> String {
    let name = String::from_utf8(unhex(f[1])).expect("utf8 name");
    fs::valid_path(&name).to_string()
}

fn list_dir(fsys: &dyn FS, name: &str) -> String {
    let list = match fs::read_dir(fsys, name) {
        Ok(l) => l,
        Err(e) => return format!("err:{e}"),
    };
    let out: Vec<String> = list
        .iter()
        .map(|e| {
            let mut s = format!(
                "{}:{}:{}:{}",
                e.name(),
                kind(Some(e.as_ref())),
                e.file_type(),
                fs::format_dir_entry(e.as_ref())
            );
            if let Ok(info) = e.info() {
                s.push(':');
                s.push_str(&fs::format_file_info(info.as_ref()));
            }
            s
        })
        .collect();
    format!("ok:{}", out.join(","))
}

fn stat_file(fsys: &dyn FS, name: &str) -> String {
    let s = match fs::stat(fsys, name) {
        Err(e) => format!("err:{e}"),
        Ok(info) => format!(
            "{}:{}:{}:{}:{}",
            info.name(),
            info.size(),
            info.mode(),
            info.is_dir(),
            info.mod_time() == Time::default()
        ),
    };
    match fs::read_file(fsys, name) {
        Ok(data) => format!("{s}|ok:{}", hex(&data)),
        Err(e) => format!("{s}|err:{e}"),
    }
}

fn op_subo(f: &[&str]) -> String {
    let m = parse_tree(f[1]);
    let sub = match fs::sub(&m, f[2]) {
        Ok(s) => s,
        Err(e) => return format!("err:{e}"),
    };
    let mut out: Vec<String> = Vec::new();
    for op in f[3].split(';') {
        let (name, arg) = cut(op, ":");
        out.push(match name {
            "readfile" => match fs::read_file(sub.as_ref(), arg) {
                Ok(b) => format!("ok:{}", hex(&b)),
                Err(e) => format!("err:{e}"),
            },
            "readdir" => list_dir(sub.as_ref(), arg),
            "stat" => stat_file(sub.as_ref(), arg),
            "glob" => glob_result(fs::glob(sub.as_ref(), arg)),
            "sub" => match fs::sub(sub.as_ref(), arg) {
                Ok(s2) => list_dir(s2.as_ref(), "."),
                Err(e) => format!("err:{e}"),
            },
            other => panic!("bad op {other}"),
        });
    }
    out.join("|")
}

#[derive(Debug)]
struct FakeInfo(FileMode);

impl FileInfo for FakeInfo {
    fn name(&self) -> &str {
        "n"
    }
    fn size(&self) -> i64 {
        1234
    }
    fn mode(&self) -> FileMode {
        self.0
    }
    fn mod_time(&self) -> Time {
        time::unix(86400 * 365, 5).utc()
    }
}

fn op_fmode(f: &[&str]) -> String {
    let m = FileMode(atoi(f[1]) as u32);
    let info = FakeInfo(m);
    let entry = fs::file_info_to_dir_entry(Some(Box::new(FakeInfo(m)))).expect("entry");
    format!(
        "{m}|{}|{}|{}|{}|{}|{}",
        m.is_dir(),
        m.is_regular(),
        m.perm(),
        m.file_type(),
        fs::format_file_info(&info),
        fs::format_dir_entry(entry.as_ref())
    )
}

fn main() {
    let stdin = io::stdin();
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line.expect("stdin");
        let f: Vec<&str> = line.split('\t').collect();
        let res = match f[0] {
            "BR" => op_br(&f),
            "BW" => op_bw(&f),
            "SC" => op_sc(&f),
            "RAL" => op_ral(&f),
            "CP" => op_cp(&f),
            "RALL" => op_rall(&f),
            "LR" => op_lr(&f),
            "MR" => op_mr(&f),
            "MW" => op_mw(&f),
            "TR" => op_tr(&f),
            "SR" => op_sr(&f),
            "OW" => op_ow(&f),
            "PIPE" => op_pipe(&f),
            "WALK" => op_walk(&f),
            "GLOB" => op_glob(&f),
            "VALID" => op_valid(&f),
            "RDIR" => list_dir(&parse_tree(f[1]), f[2]),
            "STAT" => stat_file(&parse_tree(f[1]), f[2]),
            "SUBO" => op_subo(&f),
            "FMODE" => op_fmode(&f),
            other => panic!("unknown request {other}"),
        };
        writeln!(out, "{res}").expect("stdout");
    }
}
