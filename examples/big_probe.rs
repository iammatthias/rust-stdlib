//! Line protocol used by `tools/big_check.py` for Go differential checks.
//! See `tools/big_oracle.go` for the request and reply format.
use rust_stdlib::math::big::{jacobi, Accuracy, ErrNaN, Float, FormatSpec, Int, Rat, RoundingMode};
use rust_stdlib::math::rand::v1;
use std::io::{self, BufRead, BufWriter, Write};
use std::panic::{self, AssertUnwindSafe};

type Res<T> = Result<T, Box<dyn std::error::Error>>;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Res<Vec<u8>> {
    let text = text.strip_prefix('h').unwrap_or(text);
    if !text.len().is_multiple_of(2) {
        return Err("odd-length hex input".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| Ok(u8::from_str_radix(&text[i..i + 2], 16)?))
        .collect()
}

fn unhex_str(text: &str) -> Res<String> {
    Ok(String::from_utf8(unhex(text)?)?)
}

fn pint(s: &str) -> Res<Int> {
    Int::from_str_radix(s, 0).ok_or_else(|| format!("bad int {s}").into())
}

fn prat(s: &str) -> Res<Rat> {
    Rat::from_string(s).ok_or_else(|| format!("bad rat {s}").into())
}

fn mode(s: &str) -> Res<RoundingMode> {
    let i: usize = s.parse()?;
    RoundingMode::ALL
        .get(i)
        .copied()
        .ok_or_else(|| "bad mode".into())
}

fn pfloat(s: &str) -> Res<Float> {
    let mut parts = s.splitn(3, ',');
    let prec: u32 = parts.next().ok_or("prec")?.parse()?;
    let m = mode(parts.next().ok_or("mode")?)?;
    let text = parts.next().ok_or("text")?;
    Ok(Float::parse_float(text, 0, prec, m)?.0)
}

fn new_z(prec: &str, m: &str) -> Res<Float> {
    let mut z = Float::with_prec(prec.parse()?);
    z.set_mode(mode(m)?);
    Ok(z)
}

fn ih(x: &Int) -> String {
    x.text(16)
}

fn oh(x: Option<Int>) -> String {
    x.as_ref().map_or_else(|| "nil".to_string(), ih)
}

fn fr(x: &Float) -> String {
    format!("{}/{}", x.text(b'p', 0), x.acc())
}

/// Runs `f`, reporting a panic as the token "panic" (Go's `try` in the oracle).
fn attempt(f: impl FnOnce() -> String) -> String {
    panic::catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_| "panic".to_string())
}

fn gob_hex<E>(r: Result<Vec<u8>, E>) -> String {
    r.map_or_else(|_| "err".to_string(), |b| hex(&b))
}

fn fmt_hex(x: &Int, verbs: &[&str]) -> Res<Vec<String>> {
    let mut out = Vec::new();
    for verb in verbs {
        let (sp, v) = spec(&format!("h{}", hex(verb.as_bytes())))?;
        out.push(hex(x.format(v, &sp).as_bytes()));
    }
    Ok(out)
}

fn f64b(x: f64) -> String {
    format!("{:016x}", x.to_bits())
}

fn f32b(x: f32) -> String {
    format!("{:08x}", x.to_bits())
}

fn acc(a: Accuracy) -> String {
    a.to_string()
}

fn spec(text: &str) -> Res<(FormatSpec, char)> {
    FormatSpec::parse(&unhex_str(text)?).ok_or_else(|| "bad format directive".into())
}

const TEXT_PRECS: [i64; 9] = [-1, 0, 1, 2, 5, 10, 17, 25, 50];

/// A NaN-producing operation, reported as Go's recovered ErrNaN.
fn nan<T>(r: Result<T, ErrNaN>) -> Option<T> {
    r.ok()
}

fn handle(f: &[&str]) -> Res<Vec<String>> {
    let s = |v: String| Ok(vec![v]);
    match f[0] {
        "i.add" => s(ih(&(pint(f[1])? + &pint(f[2])?))),
        "i.sub" => s(ih(&(pint(f[1])? - &pint(f[2])?))),
        "i.mul" => s(ih(&(&pint(f[1])? * &pint(f[2])?))),
        "i.quo" => s(ih(&(pint(f[1])? / &pint(f[2])?))),
        "i.rem" => s(ih(&(&pint(f[1])? % &pint(f[2])?))),
        "i.div" => s(ih(&pint(f[1])?.div_euclid(&pint(f[2])?))),
        "i.mod" => s(ih(&pint(f[1])?.rem_euclid(&pint(f[2])?))),
        "i.quorem" => {
            let (q, r) = pint(f[1])?.quo_rem(&pint(f[2])?);
            Ok(vec![ih(&q), ih(&r)])
        }
        "i.divmod" => {
            let (q, r) = pint(f[1])?.div_mod(&pint(f[2])?);
            Ok(vec![ih(&q), ih(&r)])
        }
        "i.divide" => {
            let (q, r) = pint(f[1])?.divide(&pint(f[2])?, mode(f[3])?);
            Ok(vec![ih(&q), ih(&r)])
        }
        "i.cmp" => {
            let (x, y) = (pint(f[1])?, pint(f[2])?);
            Ok(vec![
                (x.cmp(&y) as i32).to_string(),
                (x.cmp_abs(&y) as i32).to_string(),
            ])
        }
        "i.and" => s(ih(&(&pint(f[1])? & &pint(f[2])?))),
        "i.or" => s(ih(&(&pint(f[1])? | &pint(f[2])?))),
        "i.xor" => s(ih(&(&pint(f[1])? ^ &pint(f[2])?))),
        "i.andnot" => s(ih(&pint(f[1])?.and_not(&pint(f[2])?))),
        "i.lsh" => s(ih(&(&pint(f[1])? << f[2].parse::<usize>()?))),
        "i.rsh" => s(ih(&(&pint(f[1])? >> f[2].parse::<usize>()?))),
        "i.bit" => {
            let (x, i) = (pint(f[1])?, f[2].parse::<usize>()?);
            Ok(vec![
                x.bit(i).to_string(),
                ih(&x.set_bit(i, 0)),
                ih(&x.set_bit(i, 1)),
            ])
        }
        "i.misc" => {
            let x = pint(f[1])?;
            let (fv, a) = x.float64();
            let sq = if x.sign() >= 0 {
                ih(&x.sqrt())
            } else {
                "panic".to_string()
            };
            Ok(vec![
                x.sign().to_string(),
                x.bit_len().to_string(),
                x.trailing_zero_bits().to_string(),
                x.int64().to_string(),
                x.uint64().to_string(),
                x.is_int64().to_string(),
                x.is_uint64().to_string(),
                f64b(fv),
                acc(a),
                ih(&-&x),
                ih(&x.abs()),
                ih(&!&x),
                sq,
                format!("b{}", hex(&x.bytes())),
                x.to_string(),
                String::from_utf8(x.marshal_json())?,
                String::from_utf8(x.marshal_text())?,
            ])
        }
        "i.exp" => {
            let m = if f[3] == "nil" {
                None
            } else {
                Some(pint(f[3])?)
            };
            s(oh(pint(f[1])?.exp(&pint(f[2])?, m.as_ref())))
        }
        "i.gcd" => {
            let (a, b) = (pint(f[1])?, pint(f[2])?);
            let (d, x, y) = Int::gcd_ext(&a, &b);
            Ok(vec![ih(&d), ih(&x), ih(&y), ih(&Int::gcd(&a, &b))])
        }
        "i.modinv" => s(oh(pint(f[1])?.mod_inverse(&pint(f[2])?))),
        "i.modsqrt" => s(oh(pint(f[1])?.mod_sqrt(&pint(f[2])?))),
        "i.jacobi" => s(jacobi(&pint(f[1])?, &pint(f[2])?).to_string()),
        "i.prime" => s(pint(f[1])?.probably_prime(f[2].parse()?).to_string()),
        "i.text" => {
            let x = pint(f[1])?;
            Ok((2..=62).map(|base| x.text(base)).collect())
        }
        "i.parse" => {
            let text = unhex(f[1])?;
            s(Int::from_str_radix(&text, f[2].parse()?)
                .map_or_else(|| "fail".to_string(), |x| ih(&x)))
        }
        "i.unmarshal" => match Int::unmarshal_text(&unhex(f[1])?) {
            Ok(x) => s(ih(&x)),
            Err(e) => Ok(vec!["err".to_string(), hex(e.to_string().as_bytes())]),
        },
        "i.fmt" => {
            let (sp, verb) = spec(f[1])?;
            s(hex(pint(f[2])?.format(verb, &sp).as_bytes()))
        }
        "i.mulrange" => s(ih(&Int::mul_range(f[1].parse()?, f[2].parse()?))),
        "i.binomial" => s(ih(&Int::binomial(f[1].parse()?, f[2].parse()?))),
        "i.fill" => {
            let mut buf = vec![0u8; f[2].parse()?];
            s(hex(pint(f[1])?.fill_bytes(&mut buf)))
        }
        "i.setbytes" => s(ih(&Int::from_bytes(&unhex(f[1])?))),
        "i.rand" => {
            let mut r = v1::Rand::new(v1::RngSource::new(f[1].parse()?));
            let n = pint(f[2])?;
            let a = Int::random(&mut r, &n);
            let b = Int::random(&mut r, &n);
            Ok(vec![ih(&a), ih(&b)])
        }
        "i.scan" => {
            let verb = f[1].chars().next().ok_or("verb")?;
            let input = unhex(f[2])?;
            s(
                Int::scan(&mut input.as_slice(), verb)
                    .map_or_else(|_| "err".to_string(), |x| ih(&x)),
            )
        }
        "i.gobraw" => {
            let x = match Int::gob_decode(&unhex(f[1])?) {
                Ok(x) => x,
                Err(e) => return Ok(vec!["err".into(), hex(e.to_string().as_bytes())]),
            };
            let z = Int::zero();
            let ord = |o: std::cmp::Ordering| (o as i32).to_string();
            let mut out = vec![
                "ok".to_string(),
                hex(&x.gob_encode()),
                x.sign().to_string(),
                ord(x.cmp(&z)),
                ord(z.cmp(&x)),
                ord(x.cmp_abs(&z)),
                x.text(10),
                x.text(16),
                x.int64().to_string(),
                x.is_int64().to_string(),
                x.is_uint64().to_string(),
                x.bit_len().to_string(),
            ];
            let three = Int::new(3);
            let minus5 = Int::new(-5);
            let ops: Vec<Box<dyn Fn() -> Int + '_>> = vec![
                Box::new(|| x.neg()),
                Box::new(|| x.abs()),
                Box::new(|| x.clone()),
                Box::new(|| &x + &z),
                Box::new(|| &x - &z),
                Box::new(|| &z - &x),
                Box::new(|| &x * &three),
                Box::new(|| x.lsh(3)),
                Box::new(|| x.rsh(1)),
                Box::new(|| x.not()),
                Box::new(|| &x / &three),
                Box::new(|| &x + &minus5),
            ];
            for op in &ops {
                out.push(attempt(|| hex(&op().gob_encode())));
            }
            out.extend(fmt_hex(&x, &["%d", "%v", "%x", "%+d", "%s", "%10d"])?);
            Ok(out)
        }
        "q.gobraw" => {
            let x = match Rat::gob_decode(&unhex(f[1])?) {
                Ok(x) => x,
                Err(e) => return Ok(vec!["err".into(), hex(e.to_string().as_bytes())]),
            };
            let z = Rat::default();
            let ord = |o: std::cmp::Ordering| (o as i32).to_string();
            let (f6, e6) = x.float64();
            let (f3, e3) = x.float32();
            let mut out = vec![
                "ok".to_string(),
                gob_hex(x.gob_encode()),
                x.to_string(),
                x.rat_string(),
                x.float_string(3),
                x.is_int().to_string(),
                x.num().text(10),
                x.denom().text(10),
                x.sign().to_string(),
                ord(x.cmp(&z)),
                ord(z.cmp(&x)),
                ord(x.cmp(&Rat::new(1, 2))),
                f64b(f6),
                e6.to_string(),
                f32b(f3),
                e3.to_string(),
            ];
            let ops: Vec<Box<dyn Fn() -> Rat + '_>> = vec![
                Box::new(|| x.neg()),
                Box::new(|| x.abs()),
                Box::new(|| x.clone()),
                Box::new(|| &x + &z),
                Box::new(|| &x + &Rat::new(1, 3)),
                Box::new(|| &z - &x),
                Box::new(|| &x * &Rat::new(3, 2)),
                Box::new(|| &x / &Rat::new(3, 2)),
                Box::new(|| x.inv()),
            ];
            for op in &ops {
                out.push(attempt(|| {
                    let r = op();
                    format!("{}:{}", gob_hex(r.gob_encode()), r)
                }));
            }
            Ok(out)
        }
        "f.gobraw" => {
            let mut x = Float::new();
            if let Err(e) = x.gob_decode(&unhex(f[1])?) {
                return Ok(vec!["err".into(), hex(e.to_string().as_bytes())]);
            }
            let mut out = vec![
                "ok".to_string(),
                hex(&x.gob_encode()),
                x.mode().to_string(),
                x.acc().to_string(),
                x.prec().to_string(),
                x.min_prec().to_string(),
                x.sign().to_string(),
                x.is_inf().to_string(),
                x.is_int().to_string(),
                x.signbit().to_string(),
            ];
            let enc = |z: &Float| hex(&z.gob_encode());
            let ops: Vec<Box<dyn Fn() -> String + '_>> = vec![
                Box::new(|| x.text(b'p', 0)),
                Box::new(|| x.text(b'g', 10)),
                Box::new(|| x.to_string()),
                Box::new(|| {
                    let (v, a) = x.float64();
                    format!("{}/{}", f64b(v), a)
                }),
                Box::new(|| {
                    let (v, a) = x.float32();
                    format!("{}/{}", f32b(v), a)
                }),
                Box::new(|| {
                    let (v, a) = x.int64();
                    format!("{v}/{a}")
                }),
                Box::new(|| (x.partial_cmp(&Float::new()).map_or(0, |o| o as i32)).to_string()),
                Box::new(|| enc(Float::new().neg_into(&x))),
                Box::new(|| enc(Float::new().abs(&x))),
                Box::new(|| enc(Float::new().set(&x))),
                Box::new(|| {
                    let one = Float::from_f64(1.0).unwrap();
                    enc(Float::new().add_into(&x, &one).unwrap())
                }),
                Box::new(|| enc(Float::new().set_prec(10).set(&x))),
                Box::new(|| {
                    let three = Float::from_f64(3.0).unwrap();
                    enc(Float::new().mul_into(&x, &three).unwrap())
                }),
            ];
            for op in &ops {
                out.push(attempt(op));
            }
            Ok(out)
        }
        "i.gob" => {
            let b = pint(f[1])?.gob_encode();
            let x = Int::gob_decode(&b)?;
            Ok(vec![hex(&b), ih(&x)])
        }

        "q.add" => s((prat(f[1])? + &prat(f[2])?).to_string()),
        "q.sub" => s((prat(f[1])? - &prat(f[2])?).to_string()),
        "q.mul" => s((&prat(f[1])? * &prat(f[2])?).to_string()),
        "q.quo" => s((&prat(f[1])? / &prat(f[2])?).to_string()),
        "q.cmp" => s((prat(f[1])?.cmp(&prat(f[2])?) as i32).to_string()),
        "q.misc" => {
            let x = prat(f[1])?;
            let (f6, e6) = x.float64();
            let (f3, e3) = x.float32();
            let inv = if x.sign() != 0 {
                x.inv().to_string()
            } else {
                "panic".to_string()
            };
            let (n, exact) = x.float_prec();
            Ok(vec![
                f64b(f6),
                e6.to_string(),
                f32b(f3),
                e3.to_string(),
                x.rat_string(),
                x.float_string(0),
                x.float_string(1),
                x.float_string(3),
                x.float_string(20),
                (-&x).to_string(),
                x.abs().to_string(),
                inv,
                x.sign().to_string(),
                x.is_int().to_string(),
                x.num().to_string(),
                x.denom().to_string(),
                n.to_string(),
                exact.to_string(),
                String::from_utf8(x.marshal_text())?,
            ])
        }
        "q.parse" => s(
            Rat::from_string(&unhex(f[1])?).map_or_else(|| "fail".to_string(), |x| x.to_string())
        ),
        "q.scan" => {
            let verb = f[1].chars().next().ok_or("verb")?;
            let input = unhex(f[2])?;
            s(Rat::scan(&mut input.as_slice(), verb)
                .map_or_else(|_| "err".to_string(), |x| x.to_string()))
        }
        "q.setf64" => s(
            Rat::from_f64(f64::from_bits(u64::from_str_radix(f[1], 16)?))
                .map_or_else(|| "nil".to_string(), |x| x.to_string()),
        ),

        "f.add" | "f.sub" | "f.mul" | "f.quo" => {
            let mut z = new_z(f[1], f[2])?;
            let (x, y) = (pfloat(f[3])?, pfloat(f[4])?);
            let r = match f[0] {
                "f.add" => z.add_into(&x, &y).map(|_| ()),
                "f.sub" => z.sub_into(&x, &y).map(|_| ()),
                "f.mul" => z.mul_into(&x, &y).map(|_| ()),
                _ => z.quo_into(&x, &y).map(|_| ()),
            };
            if nan(r).is_none() {
                return s("nan".to_string());
            }
            Ok(vec![fr(&z), z.prec().to_string()])
        }
        "f.sqrt" => {
            let mut z = new_z(f[1], f[2])?;
            if nan(z.sqrt(&pfloat(f[3])?).map(|_| ())).is_none() {
                return s("nan".to_string());
            }
            Ok(vec![z.text(b'p', 0), z.prec().to_string()])
        }
        "f.cmp" => s((pfloat(f[1])?.cmp(&pfloat(f[2])?) as i32).to_string()),
        "f.parse" => {
            let mut z = new_z(f[1], f[2])?;
            match z.parse(&unhex(f[4])?, f[3].parse()?) {
                Ok(b) => Ok(vec![fr(&z), b.to_string(), z.prec().to_string()]),
                Err(e) => Ok(vec!["err".to_string(), hex(e.to_string().as_bytes())]),
            }
        }
        "f.conv" => {
            let x = pfloat(f[1])?;
            let (i64v, a1) = x.int64();
            let (u64v, a2) = x.uint64();
            let (fl64, a3) = x.float64();
            let (fl32, a4) = x.float32();
            let (zi, a5) = x.int();
            let (zr, a6) = x.rat();
            let mut mant = Float::new();
            let exp = x.mant_exp(Some(&mut mant));
            Ok(vec![
                i64v.to_string(),
                acc(a1),
                u64v.to_string(),
                acc(a2),
                f64b(fl64),
                acc(a3),
                f32b(fl32),
                acc(a4),
                oh(zi),
                acc(a5),
                zr.map_or_else(|| "nil".to_string(), |r| r.to_string()),
                acc(a6),
                x.is_int().to_string(),
                x.min_prec().to_string(),
                x.signbit().to_string(),
                x.sign().to_string(),
                exp.to_string(),
                mant.text(b'p', 0),
                x.is_inf().to_string(),
                x.to_string(),
                String::from_utf8(x.marshal_text())?,
            ])
        }
        "f.setprec" => {
            let mut x = pfloat(f[1])?;
            x.set_prec(f[2].parse()?);
            s(fr(&x))
        }
        "f.setmantexp" => {
            let mut z = new_z(f[1], f[2])?;
            z.set_mant_exp(&pfloat(f[3])?, f[4].parse()?);
            s(fr(&z))
        }
        "f.setint" => {
            let mut z = new_z(f[1], f[2])?;
            z.set_int(&pint(f[3])?);
            Ok(vec![fr(&z), z.prec().to_string()])
        }
        "f.setrat" => {
            let mut z = new_z(f[1], f[2])?;
            z.set_rat(&prat(f[3])?);
            Ok(vec![fr(&z), z.prec().to_string()])
        }
        "f.setf64" => {
            let mut z = new_z(f[1], f[2])?;
            if nan(z
                .set_float64(f64::from_bits(u64::from_str_radix(f[3], 16)?))
                .map(|_| ()))
            .is_none()
            {
                return s("nan".to_string());
            }
            Ok(vec![fr(&z), z.prec().to_string()])
        }
        "f.text" => {
            let x = pfloat(f[1])?;
            let mut out = Vec::new();
            for format in *b"eEfgGbpx" {
                for p in TEXT_PRECS {
                    out.push(x.text(format, p));
                }
            }
            Ok(out)
        }
        "f.fmt" => {
            let (sp, verb) = spec(f[1])?;
            s(hex(pfloat(f[2])?.format(verb, &sp).as_bytes()))
        }
        "f.scan" => {
            let mut z = new_z(f[1], f[2])?;
            let input = unhex(f[3])?;
            if z.scan(&mut input.as_slice()).is_err() {
                return s("err".to_string());
            }
            Ok(vec![fr(&z), z.prec().to_string()])
        }
        "f.gob" => {
            let x = pfloat(f[1])?;
            let b = x.gob_encode();
            let mut y = Float::new();
            y.gob_decode(&b)?;
            Ok(vec![hex(&b), fr(&y)])
        }
        op => Err(format!("unknown op {op}").into()),
    }
}

fn main() -> Res<()> {
    panic::set_hook(Box::new(|_| {}));
    let stdin = io::stdin();
    let mut out = BufWriter::with_capacity(1 << 20, io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line?;
        let fields: Vec<&str> = line.split_whitespace().collect();
        let reply = match panic::catch_unwind(AssertUnwindSafe(|| handle(&fields))) {
            Ok(result) => result?,
            Err(_) => vec!["panic".to_string()],
        };
        writeln!(out, "{}", reply.join(" "))?;
    }
    out.flush()?;
    Ok(())
}
