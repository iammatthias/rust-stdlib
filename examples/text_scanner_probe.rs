//! Line protocol used by `tools/text_scanner_check.py`; mirrors `tools/text_scanner_oracle.go`.
//! Each request is `<op>:<cfg>:<chunk>:<errAt>:<hex source>` and each answer is
//! one line with the same records as the Go oracle.
use rust_stdlib::text::scanner::{self, Position, Scanner};
use std::cell::{Cell, RefCell};
use std::io::{self, BufRead, Read, Write};
use std::rc::Rc;

/// Mode sets and white space shared with `configs()` in the Go oracle: each
/// mode set appears with and without a custom identifier predicate.
fn configs() -> Vec<(usize, u64, bool)> {
    let modes = [
        scanner::DEFAULT_TOKENS,
        0,
        scanner::SCAN_IDENTS,
        scanner::SCAN_INTS,
        scanner::SCAN_FLOATS,
        scanner::SCAN_CHARS | scanner::SCAN_STRINGS | scanner::SCAN_RAW_STRINGS,
        scanner::DEFAULT_TOKENS & !scanner::SKIP_COMMENTS,
        scanner::SCAN_IDENTS | scanner::SCAN_INTS | scanner::SCAN_COMMENTS | scanner::SKIP_COMMENTS,
        scanner::SCAN_FLOATS | scanner::SCAN_COMMENTS,
        scanner::SCAN_COMMENTS,
        scanner::SKIP_COMMENTS,
        scanner::SCAN_INTS | scanner::SCAN_IDENTS | scanner::SCAN_FLOATS | scanner::SCAN_STRINGS,
    ];
    let wss = [
        scanner::DEFAULT_WHITESPACE,
        0,
        (1 << 1) | (1 << b' ') | (1 << b'\t'),
    ];
    let mut out = Vec::new();
    for (i, mode) in modes.into_iter().enumerate() {
        for ident in [false, true] {
            out.push((mode, wss[i % wss.len()], ident));
        }
    }
    out
}

/// Delivers at most `chunk` bytes per call (0 means no limit) and fails with
/// "boom" once `err_at` bytes were delivered (`None` means never).
struct Reader<'a> {
    data: Vec<u8>,
    pos: usize,
    chunk: usize,
    err_at: Option<usize>,
    reads: &'a Cell<usize>,
}

impl Read for Reader<'_> {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        self.reads.set(self.reads.get() + 1);
        if let Some(at) = self.err_at {
            if self.pos >= at {
                return Err(io::Error::other("boom"));
            }
        }
        if self.pos >= self.data.len() {
            return Ok(0);
        }
        let mut n = p.len();
        if self.chunk > 0 && n > self.chunk {
            n = self.chunk;
        }
        n = n.min(self.data.len() - self.pos);
        if let Some(at) = self.err_at {
            if self.pos + n > at {
                n = at - self.pos;
            }
        }
        p[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(text: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if !text.len().is_multiple_of(2) {
        return Err("odd-length hex input".into());
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for i in (0..text.len()).step_by(2) {
        out.push(u8::from_str_radix(&text[i..i + 2], 16)?);
    }
    Ok(out)
}

fn position_record(p: &Position) -> String {
    format!("{},{},{}", p.offset, p.line, p.column)
}

fn process(line: &str, cfgs: &[(usize, u64, bool)]) -> Result<String, Box<dyn std::error::Error>> {
    let parts: Vec<&str> = line.split(':').collect();
    if parts.len() != 5 {
        return Err(format!("bad request {line}").into());
    }
    let (mode, ws, custom_ident) = cfgs[parts[1].parse::<usize>()?];
    let chunk: usize = parts[2].parse()?;
    let err_at: i64 = parts[3].parse()?;
    let data = from_hex(parts[4])?;

    let records: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let reads = Cell::new(0usize);
    let mut s = Scanner::default();
    s.init(Reader {
        data,
        pos: 0,
        chunk,
        err_at: usize::try_from(err_at).ok(),
        reads: &reads,
    });
    s.mode = mode;
    s.whitespace = ws;
    if custom_ident {
        s.is_ident_rune = Some(Box::new(|ch, i| {
            ch == '_' as i32
                || ('a' as i32..='z' as i32).contains(&ch)
                || (i > 0 && ('0' as i32..='9' as i32).contains(&ch))
        }));
    }
    let sink = Rc::clone(&records);
    s.error = Some(Rc::new(move |s: &mut Scanner<'_>, msg: &str| {
        let text = s.token_text();
        sink.borrow_mut().push(format!(
            "E{}@{}#{}",
            hex(msg.as_bytes()),
            hex(s.pos().to_string().as_bytes()),
            hex(&text)
        ));
    }));

    match parts[0] {
        "S" => {
            for _ in 0..100000 {
                let tok = s.scan();
                let (off, line, col) = (s.position.offset, s.position.line, s.position.column);
                let text = s.token_text();
                records
                    .borrow_mut()
                    .push(format!("T{tok}:{}@{off},{line},{col}", hex(&text)));
                records
                    .borrow_mut()
                    .push(format!("P{}", position_record(&s.pos())));
                if tok == scanner::EOF {
                    break;
                }
            }
        }
        "N" => {
            for _ in 0..100000 {
                let pk = s.peek();
                let ch = s.next();
                let p = s.pos();
                records.borrow_mut().push(format!(
                    "N{pk}/{ch}:{},{},{},{}",
                    p.offset, p.line, p.column, s.position.line
                ));
                if ch == scanner::EOF {
                    break;
                }
            }
        }
        op => return Err(format!("bad op {op}").into()),
    }
    let mut out = records.borrow().clone();
    out.push(format!("C{} R{}", s.error_count, reads.get()));
    Ok(out.join(" "))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfgs = configs();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        writeln!(out, "{}", process(&line?, &cfgs)?)?;
    }
    Ok(())
}
