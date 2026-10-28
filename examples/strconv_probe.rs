//! Line protocol used by `tools/strconv_check.py` for Go differential checks.
use rust_stdlib::strconv::{self, Complex, NumError};
use std::io::{self, BufRead, BufWriter, Write};

/// Go's `(value, error)` pair: the value that comes with an error.
fn pair<T>(r: Result<T, NumError>, partial: impl FnOnce(&NumError) -> T) -> (T, Option<NumError>) {
    match r {
        Ok(v) => (v, None),
        Err(e) => (partial(&e), Some(e)),
    }
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

fn enc(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn text(field: &str) -> String {
    String::from_utf8(unhex(field)).expect("request strings for parse modes are UTF-8")
}

fn err_str(err: &Option<NumError>) -> String {
    match err {
        None => "-".to_string(),
        Some(e) => enc(e.to_string().as_bytes()),
    }
}

fn fbits(f: f64) -> String {
    if f.is_nan() {
        "nan".to_string()
    } else {
        format!("{:016x}", f.to_bits())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut out = BufWriter::new(io::stdout().lock());
    for line in io::stdin().lock().lines() {
        let line = line?;
        let f: Vec<&str> = line.split('\t').collect();
        let num = |i: usize| -> i32 { f[i].parse().expect("int") };
        match f[0] {
            "F" => {
                let bits = u64::from_str_radix(f[1], 16)?;
                let bs = num(4);
                let v = if bs == 32 {
                    f32::from_bits(bits as u32) as f64
                } else {
                    f64::from_bits(bits)
                };
                writeln!(
                    out,
                    "{}",
                    strconv::format_float(v, f[2].as_bytes()[0], num(3), bs)
                )?;
            }
            "P" => {
                let (v, e) = pair(strconv::parse_float(&text(f[1]), num(2)), |e| {
                    e.float_value()
                });
                writeln!(out, "{} {}", fbits(v), err_str(&e))?;
            }
            "I" => {
                let (v, e) = pair(strconv::parse_int(&text(f[1]), num(2), num(3)), |e| {
                    e.int_value()
                });
                writeln!(out, "{} {}", v, err_str(&e))?;
            }
            "U" => {
                let (v, e) = pair(strconv::parse_uint(&text(f[1]), num(2), num(3)), |e| {
                    e.uint_value()
                });
                writeln!(out, "{} {}", v, err_str(&e))?;
            }
            "A" => {
                let (v, e) = pair(strconv::atoi(&text(f[1])), |e| e.int_value() as isize);
                writeln!(out, "{} {}", v, err_str(&e))?;
            }
            "B" => {
                let r = strconv::parse_bool(&text(f[1]));
                match r {
                    Ok(v) => writeln!(out, "{v} -")?,
                    Err(e) => writeln!(out, "false {}", enc(e.to_string().as_bytes()))?,
                }
            }
            "FI" => {
                let v: i64 = f[1].parse()?;
                let base = num(2);
                let mut app = b"x".to_vec();
                strconv::append_int(&mut app, v, base);
                writeln!(
                    out,
                    "{} {} {}",
                    strconv::format_int(v, base),
                    strconv::format_uint(v as u64, base),
                    String::from_utf8(app)?
                )?;
            }
            "C" => {
                let (c, e) = pair(strconv::parse_complex(&text(f[1]), num(2)), |e| {
                    e.complex_value()
                });
                writeln!(out, "{} {} {}", fbits(c.re), fbits(c.im), err_str(&e))?;
            }
            "FC" => {
                let mut re = f64::from_bits(u64::from_str_radix(f[1], 16)?);
                let mut im = f64::from_bits(u64::from_str_radix(f[2], 16)?);
                let bs = num(5);
                if bs == 64 {
                    re = re as f32 as f64;
                    im = im as f32 as f64;
                }
                writeln!(
                    out,
                    "{}",
                    strconv::format_complex(Complex { re, im }, f[3].as_bytes()[0], num(4), bs)
                )?;
            }
            "Q" => {
                let s = unhex(f[2]);
                let r = match f[1] {
                    "0" => strconv::quote(&s),
                    "1" => strconv::quote_to_ascii(&s),
                    _ => strconv::quote_to_graphic(&s),
                };
                let mut app = b"x".to_vec();
                strconv::append_quote(&mut app, &s);
                writeln!(out, "{} {}", enc(r.as_bytes()), enc(&app))?;
            }
            "R" => {
                let r: i32 = f[2].parse()?;
                let q = match f[1] {
                    "0" => strconv::quote_rune(r),
                    "1" => strconv::quote_rune_to_ascii(r),
                    _ => strconv::quote_rune_to_graphic(r),
                };
                writeln!(
                    out,
                    "{} {} {}",
                    enc(q.as_bytes()),
                    strconv::is_print(r),
                    strconv::is_graphic(r)
                )?;
            }
            "UQ" => match strconv::unquote(unhex(f[1])) {
                Ok(v) => writeln!(out, "{} -", enc(&v))?,
                Err(e) => writeln!(out, " {}", enc(e.to_string().as_bytes()))?,
            },
            "QP" => match strconv::quoted_prefix(&unhex(f[1])[..]) {
                Ok(v) => writeln!(out, "{} -", enc(v))?,
                Err(e) => writeln!(out, " {}", enc(e.to_string().as_bytes()))?,
            },
            "UC" => {
                let input = unhex(f[1]);
                match strconv::unquote_char(&input, num(2) as u8) {
                    Ok((v, mb, tail)) => writeln!(out, "{} {} {} -", v, mb, enc(tail))?,
                    Err(e) => writeln!(out, "0 false  {}", enc(e.to_string().as_bytes()))?,
                }
            }
            "CB" => writeln!(out, "{}", strconv::can_backquote(unhex(f[1])))?,
            other => return Err(format!("unknown request {other}").into()),
        }
    }
    Ok(())
}
