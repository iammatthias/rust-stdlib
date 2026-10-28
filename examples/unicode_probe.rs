//! Line protocol used by `tools/unicode_check.py`; mirrors `tools/unicode_oracle.go`.
use rust_stdlib::unicode::{self as uni, rune as utf8, CaseRange, RangeTable};
use std::fmt::Write as _;
use std::io::{self, BufRead, Write};

struct Fnv(u64);

impl Fnv {
    fn new() -> Self {
        Fnv(14695981039346656037)
    }
    fn byte(&mut self, b: u8) {
        self.0 = (self.0 ^ b as u64).wrapping_mul(1099511628211);
    }
    fn u32(&mut self, v: u32) {
        for i in 0..4 {
            self.byte((v >> (8 * i)) as u8);
        }
    }
}

fn domain() -> Vec<i32> {
    let mut d = vec![
        i32::MIN,
        i32::MIN + 1,
        -0x7FFFFFFF,
        -0x110000,
        -0x10FFFF,
        -0xD800,
    ];
    d.extend(-300..0);
    d.extend(0..0x110020);
    d.extend([0x1FFFFF, 0x200000, 0xFFFFFFF, 0x7FFFFFFE, 0x7FFFFFFF]);
    d
}

fn sweep(out: &mut impl Write) -> io::Result<()> {
    let letter_digit: [&RangeTable; 2] = [uni::LETTER, uni::DIGIT];
    let mixed: [&RangeTable; 2] = [uni::LU, uni::ND];
    let (mut h_enc, mut h_p16, mut h_dec) = (Fnv::new(), Fnv::new(), Fnv::new());
    let mut prev = String::new();
    let mut prev_r = 0i32;
    let mut first = true;
    let dom = domain();
    for &r in &dom {
        let flags = [
            uni::is_upper(r),
            uni::is_lower(r),
            uni::is_title(r),
            uni::is_letter(r),
            uni::is_digit(r),
            uni::is_number(r),
            uni::is_mark(r),
            uni::is_punct(r),
            uni::is_symbol(r),
            char::from_u32(r as u32).is_some_and(char::is_whitespace),
            char::from_u32(r as u32).is_some_and(char::is_control),
            uni::is_graphic(r),
            uni::is_print(r),
            uni::in_(r, &letter_digit),
            uni::is_one_of(&mixed, r),
            uni::is(uni::HAN, r),
            uni::is(uni::LATIN, r),
            uni::is(uni::WHITE_SPACE, r),
            uni::is(uni::HEX_DIGIT, r),
            uni::in_(r, &letter_digit),
            utf8::valid_rune(r),
            utf8::is_surrogate(r),
        ];
        let mask = flags
            .iter()
            .enumerate()
            .fold(0u32, |m, (i, &v)| m | (v as u32) << i);
        let mut rec = format!("{mask:x}");
        fn d(rec: &mut String, v: i32, r: i32) {
            write!(rec, " {}", v.wrapping_sub(r)).unwrap();
        }
        d(&mut rec, uni::to_upper(r), r);
        d(&mut rec, uni::to_lower(r), r);
        d(&mut rec, uni::to_title(r), r);
        d(&mut rec, uni::simple_fold(r), r);
        for c in -1..=3 {
            if !(0..3).contains(&c) {
                write!(rec, " {}", uni::to(c, r)).unwrap(); // constant ReplacementChar
            } else {
                d(&mut rec, uni::to(c, r), r);
            }
        }
        for sc in [&uni::TURKISH_CASE, &uni::AZERI_CASE] {
            d(&mut rec, sc.to_upper(r), r);
            d(&mut rec, sc.to_lower(r), r);
            d(&mut rec, sc.to_title(r), r);
        }
        write!(rec, " {} {}", utf8::rune_len(r), utf16_rune_len(r)).unwrap();
        if first || rec != prev || r != prev_r.wrapping_add(1) {
            writeln!(out, "{r} {rec}")?;
        }
        first = false;
        prev_r = r;
        prev = rec;

        let mut buf = [0u8; 4];
        let n = utf8::encode_rune(&mut buf, r);
        h_enc.u32(n as u32);
        buf[..n].iter().for_each(|&b| h_enc.byte(b));
        let mut app = Vec::new();
        utf8::append_rune(&mut app, r);
        h_enc.u32(app.len() as u32);
        app.iter().for_each(|&b| h_enc.byte(b));
        let (r1, r2) = utf8::encode_surrogate_pair(r);
        h_p16.u32(r1 as u32);
        h_p16.u32(r2 as u32);
        let mut units = Vec::new();
        utf16_append(&mut units, r);
        units.iter().for_each(|&u| h_p16.u32(u as u32));
    }
    for r1 in 0xD7FE..0xE002 {
        for r2 in 0xDBFE..0xE002 {
            h_dec.u32(utf8::decode_surrogate_pair(r1, r2) as u32);
        }
    }
    for &r1 in &dom[..400] {
        for r2 in [r1, 0xDC00, 0xDFFF, -1, 0x10000] {
            h_dec.u32(utf8::decode_surrogate_pair(r1, r2) as u32);
            h_dec.u32(utf8::decode_surrogate_pair(r2, r1) as u32);
        }
    }
    writeln!(
        out,
        "H utf8-encode {:x}\nH utf16-encode {:x}\nH utf16-decode {:x}",
        h_enc.0, h_p16.0, h_dec.0
    )
}

fn table_hash(t: &RangeTable) -> String {
    let mut h = Fnv::new();
    h.u32(t.latin_offset as u32);
    for r in t.r16 {
        h.u32(r.lo as u32);
        h.u32(r.hi as u32);
        h.u32(r.stride as u32);
    }
    h.u32(0xFFFFFFFF);
    for r in t.r32 {
        h.u32(r.lo);
        h.u32(r.hi);
        h.u32(r.stride);
    }
    format!("{} {} {:x}", t.r16.len(), t.r32.len(), h.0)
}

fn sample(t: &RangeTable) -> String {
    let mut h = Fnv::new();
    let (mut n, mut ones) = (0, 0);
    let mut probe = |r: i32| {
        n += 1;
        let v = uni::is(t, r);
        ones += v as i32;
        h.byte(v as u8);
    };
    let spans = t
        .r16
        .iter()
        .map(|r| (r.lo as i32, r.hi as i32, r.stride as i32))
        .chain(
            t.r32
                .iter()
                .map(|r| (r.lo as i32, r.hi as i32, r.stride as i32)),
        );
    for (lo, hi, st) in spans {
        for p in [lo - 1, lo, lo + 1, lo + st, hi - 1, hi, hi + 1] {
            probe(p);
        }
    }
    format!("{n} {ones} {:x}", h.0)
}

fn case_hash(cs: &[CaseRange]) -> String {
    let mut h = Fnv::new();
    for c in cs {
        h.u32(c.lo);
        h.u32(c.hi);
        c.delta.iter().for_each(|&d| h.u32(d as u32));
    }
    format!("{} {:x}", cs.len(), h.0)
}

fn tables(out: &mut impl Write) -> io::Result<()> {
    writeln!(out, "version {}", uni::VERSION)?;
    let maps: [(&str, &[(&str, &RangeTable)]); 5] = [
        ("Categories", uni::CATEGORIES),
        ("Scripts", uni::SCRIPTS),
        ("Properties", uni::PROPERTIES),
        ("FoldCategory", uni::FOLD_CATEGORY),
        ("FoldScript", uni::FOLD_SCRIPT),
    ];
    for (name, m) in maps {
        for (k, t) in m {
            writeln!(out, "{name} {k} {} | {}", table_hash(t), sample(t))?;
        }
    }
    let aliases: [(&str, &RangeTable); 11] = [
        ("Digit", uni::DIGIT),
        ("Letter", uni::LETTER),
        ("Lower", uni::LOWER),
        ("Mark", uni::MARK),
        ("Number", uni::NUMBER),
        ("Other", uni::OTHER),
        ("Punct", uni::PUNCT),
        ("Space", uni::SPACE),
        ("Symbol", uni::SYMBOL),
        ("Title", uni::TITLE),
        ("Upper", uni::UPPER),
    ];
    for (k, t) in aliases {
        writeln!(out, "alias {k} {}", table_hash(t))?;
    }
    for (k, v) in uni::CATEGORY_ALIASES {
        writeln!(out, "CategoryAliases {k} {v}")?;
    }
    for (i, t) in uni::GRAPHIC_RANGES.iter().enumerate() {
        writeln!(out, "GraphicRanges {i} {}", table_hash(t))?;
    }
    for (i, t) in uni::PRINT_RANGES.iter().enumerate() {
        writeln!(out, "PrintRanges {i} {}", table_hash(t))?;
    }
    writeln!(
        out,
        "CaseRanges {}\nTurkishCase {}\nAzeriCase {}",
        case_hash(uni::CASE_RANGES),
        case_hash(uni::TURKISH_CASE.0),
        case_hash(uni::AZERI_CASE.0)
    )
}

fn from_hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

fn bits(n: usize, f: impl Fn(usize) -> bool) -> String {
    (0..n).map(|i| if f(i) { '1' } else { '0' }).collect()
}

fn r0((r, n): (i32, usize)) -> String {
    format!("{r:x}:{n}")
}

fn walk(p: &[u8], dec: fn(&[u8]) -> (i32, usize), fwd: bool) -> String {
    let mut parts = Vec::new();
    let mut rest = p;
    while !rest.is_empty() {
        let (r, n) = dec(rest);
        parts.push(r0((r, n)));
        rest = if fwd {
            &rest[n..]
        } else {
            &rest[..rest.len() - n]
        };
    }
    parts.join(",")
}

fn utf8_case(out: &mut impl Write, p: &[u8]) -> io::Result<()> {
    // Go's `*InString` forms are the same functions here (`&str` is `&[u8]`),
    // so each value is printed twice; `Valid` is `str::from_utf8`.
    let (f, l) = (
        walk(p, utf8::decode_rune, true),
        walk(p, utf8::decode_last_rune, false),
    );
    let c = utf8::rune_count(p);
    let v = std::str::from_utf8(p).is_ok() as u8;
    let fr = bits(p.len() + 1, |i| utf8::full_rune(&p[..i]));
    writeln!(
        out,
        "f={f} l={l} fs={f} ls={l} c={c} cs={c} v={v} vs={v} fr={fr} frs={fr} rs={} e={},{}",
        bits(p.len(), |i| utf8::rune_start(p[i])),
        r0(utf8::decode_rune(&[])),
        r0(utf8::decode_last_rune(&[])),
    )
}

/// Go's `utf16.Encode`: std's `char::encode_utf16`, invalid runes as U+FFFD.
fn utf16_append(units: &mut Vec<u16>, r: i32) {
    let c = u32::try_from(r)
        .ok()
        .and_then(char::from_u32)
        .unwrap_or(char::REPLACEMENT_CHARACTER);
    let mut buf = [0u16; 2];
    units.extend_from_slice(c.encode_utf16(&mut buf));
}

fn utf16_encode(runes: &[i32]) -> Vec<u16> {
    let mut units = Vec::new();
    runes.iter().for_each(|&r| utf16_append(&mut units, r));
    units
}

/// Go's `utf16.Decode`: std's `char::decode_utf16`, unpaired surrogates as U+FFFD.
fn utf16_decode(units: &[u16]) -> Vec<i32> {
    char::decode_utf16(units.iter().copied())
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER) as i32)
        .collect()
}

/// Go's `utf16.RuneLen`: `char::len_utf16`, -1 for invalid runes.
fn utf16_rune_len(r: i32) -> isize {
    u32::try_from(r)
        .ok()
        .and_then(char::from_u32)
        .map_or(-1, |c| c.len_utf16() as isize)
}

fn units(runes_or_units: Vec<String>) -> String {
    runes_or_units.join(",")
}

fn main() -> io::Result<()> {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        let line = line?;
        let (kind, arg) = line.split_once(' ').unwrap_or((line.as_str(), ""));
        match kind {
            "sweep" => sweep(&mut out)?,
            "tables" => tables(&mut out)?,
            "U8" => utf8_case(&mut out, &from_hex(arg))?,
            "U16" => {
                let us: Vec<u16> = (0..arg.len() / 4)
                    .map(|i| u16::from_str_radix(&arg[4 * i..4 * i + 4], 16).expect("hex"))
                    .collect();
                let runes = utf16_decode(&us);
                writeln!(
                    out,
                    "{} | {}",
                    units(runes.iter().map(|&r| format!("{:x}", r as u32)).collect()),
                    units(
                        utf16_encode(&runes)
                            .iter()
                            .map(|u| format!("{u:x}"))
                            .collect()
                    )
                )?;
            }
            "R32" => {
                let runes: Vec<i32> = (0..arg.len() / 8)
                    .map(|i| u32::from_str_radix(&arg[8 * i..8 * i + 8], 16).expect("hex") as i32)
                    .collect();
                writeln!(
                    out,
                    "{}",
                    units(
                        utf16_encode(&runes)
                            .iter()
                            .map(|u| format!("{u:x}"))
                            .collect()
                    )
                )?;
            }
            _ => panic!("unknown request {line}"),
        }
    }
    out.flush()
}
