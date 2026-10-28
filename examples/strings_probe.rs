//! Line protocol used by `tools/strings_check.py` for Go differential checks.
//!
//! Every request runs against `BytesExt` (Go's byte-string semantics); when
//! all arguments are valid UTF-8 and the Go symbol is mapped to a std `str`
//! method, the std result must agree with it.
use rust_stdlib::text::{BytesExt, Reader, Replacer};
use rust_stdlib::unicode::{SpecialCase, AZERI_CASE, TURKISH_CASE};
use std::io::{self, BufRead, Read, Seek, SeekFrom};

fn from_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

fn hx(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn b2s(b: bool) -> String {
    (b as u8).to_string()
}

fn opt(o: Option<usize>) -> String {
    o.map_or("-1".to_string(), |i| i.to_string())
}

fn list<'a>(items: impl IntoIterator<Item = &'a [u8]>) -> String {
    let parts: Vec<String> = items.into_iter().map(hx).collect();
    format!("[{}]", parts.join(","))
}

fn pred(r: char) -> bool {
    r == 'a' || r as u32 >= 0x80
}

fn mapping(r: char) -> Option<char> {
    match r {
        'a' => None,
        'b' => Some('\u{E9}'),
        '\u{394}' => Some('\u{FFFD}'),
        _ => Some(r),
    }
}

fn numeric(op: &str, i: usize) -> bool {
    match op {
        "IndexByte" | "LastIndexByte" | "IndexRune" | "ContainsRune" | "Repeat" => i == 1,
        "SplitN" | "SplitAfterN" => i == 2,
        "Replace" => i == 3,
        _ => false,
    }
}

fn special(arg: &[u8]) -> SpecialCase<'static> {
    if arg == b"T" {
        TURKISH_CASE
    } else {
        AZERI_CASE
    }
}

fn eof_kind(e: &io::Error) -> &'static str {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        "eof"
    } else {
        "err"
    }
}

fn errs<T>(r: &io::Result<T>) -> &'static str {
    match r {
        Ok(_) => "ok",
        Err(e) => eof_kind(e),
    }
}

fn errs_opt(r: &Option<io::Error>) -> &'static str {
    r.as_ref().map_or("ok", eof_kind)
}

fn reader(input: &[u8], script: &[u8]) -> String {
    let mut r = Reader::new(input);
    let mut out = Vec::new();
    for &c in script {
        out.push(match c {
            b'r' => {
                let mut buf = [0u8; 3];
                let n = r.read(&mut buf).unwrap();
                format!(
                    "r{n}:{}:{}",
                    hx(&buf[..n]),
                    if n == 0 { "eof" } else { "ok" }
                )
            }
            b'b' => {
                let v = r.read_byte();
                format!("b{}:{}", *v.as_ref().unwrap_or(&0), errs(&v))
            }
            b'B' => format!("B:{}", errs(&r.unread_byte())),
            b'c' => {
                let v = r.read_rune();
                let (ch, size) = v.as_ref().map_or((0, 0), |&(c, n)| (c as u32, n));
                format!("c{ch}:{size}:{}", errs(&v))
            }
            b'C' => format!("C:{}", errs(&r.unread_rune())),
            b'a' => {
                let mut buf = [0u8; 4];
                let (n, res) = r.read_at(&mut buf, 1);
                format!("a{n}:{}:{}", hx(&buf[..n]), errs_opt(&res))
            }
            b'n' => {
                let (_, res) = r.read_at(&mut [0u8; 1], -1);
                format!("n:{}", errs_opt(&res))
            }
            b's' | b'S' | b'e' | b'E' | b'z' => {
                let pos = match c {
                    b's' => SeekFrom::Start(2),
                    b'S' => SeekFrom::Current(-1),
                    b'e' => SeekFrom::End(-2),
                    b'E' => SeekFrom::End(5),
                    _ => SeekFrom::End(-1000),
                };
                let v = r.seek(pos);
                format!(
                    "{}{}:{}",
                    c as char,
                    v.as_ref().copied().unwrap_or(0),
                    errs(&v)
                )
            }
            b'w' => {
                let mut sink = Vec::new();
                let v = r.write_to(&mut sink);
                format!(
                    "w{}:{}:{}",
                    v.as_ref().copied().unwrap_or(0),
                    hx(&sink),
                    errs(&v)
                )
            }
            b'l' => format!("l{}/{}", r.len(), r.size()),
            b'f' => {
                // fill_buf + consume(2): exercised for prevRune clearing.
                let n = r.fill_buf().unwrap().len();
                r.consume(2);
                format!("f{n}")
            }
            _ => String::new(),
        });
    }
    out.join(" ")
}

/// Go's `Repeat` panics for a negative count, length overflow or an
/// allocation beyond the address space; `slice::repeat` is std's.
fn repeat(s: &[u8], count: isize) -> Option<Vec<u8>> {
    let n = usize::try_from(count).ok()?;
    let total = s
        .len()
        .checked_mul(n)
        .filter(|&t| t <= isize::MAX as usize)?;
    Vec::<u8>::new().try_reserve_exact(total).ok()?;
    Some(s.repeat(n))
}

fn run(op: &str, raw: &[Vec<u8>], nums: &[String]) -> String {
    let arg = |i: usize| -> &[u8] { &raw[i] };
    let num = |i: usize| -> isize { nums[i].parse().expect("number") };
    let rune = |i: usize| -> Option<char> { char::from_u32(num(i) as u32) };
    match op {
        "Index" => opt(arg(0).find_bytes(arg(1))),
        "LastIndex" => opt(arg(0).rfind_bytes(arg(1))),
        "IndexByte" => opt(arg(0).iter().position(|&b| b == num(1) as u8)),
        "LastIndexByte" => opt(arg(0).iter().rposition(|&b| b == num(1) as u8)),
        "IndexRune" => opt(rune(1).and_then(|r| arg(0).find_rune(r))),
        "IndexAny" => opt(arg(0).find_any(arg(1))),
        "LastIndexAny" => opt(arg(0).rfind_any(arg(1))),
        "IndexFunc" => opt(arg(0).find_func(pred)),
        "LastIndexFunc" => opt(arg(0).rfind_func(pred)),
        "Contains" => b2s(arg(0).contains_bytes(arg(1))),
        "ContainsAny" => b2s(arg(0).contains_any(arg(1))),
        "ContainsRune" => b2s(rune(1).is_some_and(|r| arg(0).contains_rune(r))),
        "ContainsFunc" => b2s(arg(0).contains_func(pred)),
        "Count" => arg(0).count_bytes(arg(1)).to_string(),
        "HasPrefix" => b2s(arg(0).starts_with(arg(1))),
        "HasSuffix" => b2s(arg(0).ends_with(arg(1))),
        "Compare" => (arg(0).cmp(arg(1)) as i32).to_string(),
        "Cut" | "CutLast" => {
            let r = if op == "Cut" {
                arg(0).cut(arg(1))
            } else {
                arg(0).cut_last(arg(1))
            };
            match r {
                Some((b, a)) => format!("1,{},{}", hx(b), hx(a)),
                None => format!("0,{},", hx(arg(0))),
            }
        }
        "CutPrefix" => match arg(0).strip_prefix(arg(1)) {
            Some(a) => format!("1,{}", hx(a)),
            None => format!("0,{}", hx(arg(0))),
        },
        "CutSuffix" => match arg(0).strip_suffix(arg(1)) {
            Some(a) => format!("1,{}", hx(a)),
            None => format!("0,{}", hx(arg(0))),
        },
        "TrimPrefix" => hx(arg(0).strip_prefix(arg(1)).unwrap_or(arg(0))),
        "TrimSuffix" => hx(arg(0).strip_suffix(arg(1)).unwrap_or(arg(0))),
        "EqualFold" => b2s(arg(0).equal_fold(arg(1))),
        "Fields" | "FieldsSeq" => list(arg(0).fields()),
        "FieldsFunc" | "FieldsFuncSeq" => list(arg(0).fields_func(pred)),
        "Lines" => list(arg(0).split_lines()),
        "Split" | "SplitSeq" => list(arg(0).split_bytes(arg(1))),
        "SplitAfter" | "SplitAfterSeq" => list(arg(0).split_bytes_after(arg(1))),
        "SplitN" => list(arg(0).split_bytes_n(arg(1), num(2))),
        "SplitAfterN" => list(arg(0).split_bytes_after_n(arg(1), num(2))),
        "Join" => {
            let elems: Vec<&[u8]> = arg(0).split_bytes(b",").collect();
            hx(&elems.join(arg(1)))
        }
        "Repeat" => repeat(arg(0), num(1)).map_or("panic".to_string(), |v| hx(&v)),
        "Replace" => hx(&arg(0).replace(arg(1), arg(2), num(3))),
        "ReplaceAll" => hx(&arg(0).replace_all(arg(1), arg(2))),
        "ToUpper" => hx(&arg(0).to_upper()),
        "ToLower" => hx(&arg(0).to_lower()),
        "ToTitle" => hx(&arg(0).to_title()),
        "Title" => hx(&arg(0).title()),
        "ToUpperSpecial" => hx(&arg(0).to_upper_special(special(&raw[1]))),
        "ToLowerSpecial" => hx(&arg(0).to_lower_special(special(&raw[1]))),
        "ToTitleSpecial" => hx(&arg(0).to_title_special(special(&raw[1]))),
        "ToValidUTF8" => hx(&arg(0).to_valid_utf8(arg(1))),
        "Map" => hx(&arg(0).map_runes(mapping)),
        "Trim" => hx(arg(0).trim_cutset(arg(1))),
        "TrimLeft" => hx(arg(0).trim_start_cutset(arg(1))),
        "TrimRight" => hx(arg(0).trim_end_cutset(arg(1))),
        "TrimSpace" => hx(arg(0).trim_space()),
        "TrimFunc" => hx(arg(0).trim_func(pred)),
        "TrimLeftFunc" => hx(arg(0).trim_start_func(pred)),
        "TrimRightFunc" => hx(arg(0).trim_end_func(pred)),
        "Reader" => reader(&raw[0], &raw[1]),
        "Replacer" => {
            let pairs: Vec<(&[u8], &[u8])> =
                raw[1..].chunks(2).map(|c| (&c[0][..], &c[1][..])).collect();
            let r = Replacer::new(&pairs);
            let mut sink = Vec::new();
            let (n, res) = r.write_to(&mut sink, arg(0));
            res.expect("vec write");
            format!("{},{},{}", hx(&r.replace(arg(0))), n, hx(&sink))
        }
        other => panic!("unknown op {other}"),
    }
}

/// Where a Go symbol is mapped to a std `str` item, the std result on valid
/// UTF-8 must equal ours (the `docs/api/strings.json` mapping claim).
fn check_std(op: &str, raw: &[Vec<u8>], nums: &[String], got: &str) {
    let strs: Vec<Option<&str>> = raw.iter().map(|b| std::str::from_utf8(b).ok()).collect();
    let s = |i: usize| strs.get(i).copied().flatten();
    let num = |i: usize| -> isize { nums[i].parse().expect("number") };
    let chars = |i: usize| -> Option<Vec<char>> { s(i).map(|t| t.chars().collect()) };
    let Some(text) = s(0) else { return };
    let want: Option<String> = match op {
        "Index" => s(1).map(|p| opt(text.find(p))),
        "LastIndex" => s(1).map(|p| opt(text.rfind(p))),
        "IndexRune" => char::from_u32(num(1) as u32).map(|r| opt(text.find(r))),
        "ContainsRune" => char::from_u32(num(1) as u32).map(|r| b2s(text.contains(r))),
        "IndexAny" => chars(1).map(|c| opt(text.find(&c[..]))),
        "LastIndexAny" => chars(1).map(|c| opt(text.rfind(&c[..]))),
        "ContainsAny" => chars(1).map(|c| b2s(text.contains(&c[..]))),
        "IndexFunc" => Some(opt(text.find(pred))),
        "LastIndexFunc" => Some(opt(text.rfind(pred))),
        "ContainsFunc" => Some(b2s(text.chars().any(pred))),
        "Contains" => s(1).map(|p| b2s(text.contains(p))),
        "Count" => s(1).map(|p| text.matches(p).count().to_string()),
        "HasPrefix" => s(1).map(|p| b2s(text.starts_with(p))),
        "HasSuffix" => s(1).map(|p| b2s(text.ends_with(p))),
        "Compare" => s(1).map(|p| (text.cmp(p) as i32).to_string()),
        "Cut" => s(1).map(|p| match text.split_once(p) {
            Some((b, a)) => format!("1,{},{}", hx(b.as_bytes()), hx(a.as_bytes())),
            None => format!("0,{},", hx(text.as_bytes())),
        }),
        "CutLast" => s(1).map(|p| match text.rsplit_once(p) {
            Some((b, a)) => format!("1,{},{}", hx(b.as_bytes()), hx(a.as_bytes())),
            None => format!("0,{},", hx(text.as_bytes())),
        }),
        "CutPrefix" => s(1).map(|p| match text.strip_prefix(p) {
            Some(a) => format!("1,{}", hx(a.as_bytes())),
            None => format!("0,{}", hx(text.as_bytes())),
        }),
        "CutSuffix" => s(1).map(|p| match text.strip_suffix(p) {
            Some(a) => format!("1,{}", hx(a.as_bytes())),
            None => format!("0,{}", hx(text.as_bytes())),
        }),
        "TrimPrefix" => s(1).map(|p| hx(text.strip_prefix(p).unwrap_or(text).as_bytes())),
        "TrimSuffix" => s(1).map(|p| hx(text.strip_suffix(p).unwrap_or(text).as_bytes())),
        "Fields" | "FieldsSeq" => Some(list(text.split_whitespace().map(str::as_bytes))),
        "Lines" => Some(list(text.split_inclusive('\n').map(str::as_bytes))),
        "TrimSpace" => Some(hx(text.trim().as_bytes())),
        "TrimFunc" => Some(hx(text.trim_matches(pred).as_bytes())),
        "TrimLeftFunc" => Some(hx(text.trim_start_matches(pred).as_bytes())),
        "TrimRightFunc" => Some(hx(text.trim_end_matches(pred).as_bytes())),
        "Trim" => chars(1).map(|c| hx(text.trim_matches(&c[..]).as_bytes())),
        "TrimLeft" => chars(1).map(|c| hx(text.trim_start_matches(&c[..]).as_bytes())),
        "TrimRight" => chars(1).map(|c| hx(text.trim_end_matches(&c[..]).as_bytes())),
        "Join" => s(1).map(|sep| {
            let elems: Vec<&str> = text.split(',').collect();
            hx(elems.join(sep).as_bytes())
        }),
        "ReplaceAll" => match (s(1), s(2)) {
            (Some(o), Some(n)) => Some(hx(text.replace(o, n).as_bytes())),
            _ => None,
        },
        "Replace" => match (s(1), s(2)) {
            (Some(o), Some(n)) => Some(hx(match usize::try_from(num(3)) {
                Ok(k) => text.replacen(o, n, k),
                Err(_) => text.replace(o, n),
            }
            .as_bytes())),
            _ => None,
        },
        "Repeat" => {
            repeat(text.as_bytes(), num(1)).map(|_| hx(text.repeat(num(1) as usize).as_bytes()))
        }
        _ => None,
    };
    if let Some(want) = want {
        assert_eq!(got, want, "std disagrees on {op} {raw:x?}");
    }
}

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.expect("stdin");
        let mut parts = line.split('\t');
        let op = parts.next().expect("op");
        let fields: Vec<&str> = parts.collect();
        let raw: Vec<Vec<u8>> = fields
            .iter()
            .enumerate()
            .map(|(i, f)| {
                if numeric(op, i) {
                    Vec::new()
                } else {
                    from_hex(f)
                }
            })
            .collect();
        let nums: Vec<String> = fields.iter().map(|f| f.to_string()).collect();
        let result = run(op, &raw, &nums);
        check_std(op, &raw, &nums, &result);
        println!("{result}");
    }
}
