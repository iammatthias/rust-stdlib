//! Line protocol used by `tools/math_check.py`; mirrors `tools/math_oracle.go`.
//! It calls the Rust item each Go symbol is mapped to in `docs/api/math.json`
//! and `docs/api/math_bits.json`: std methods where std matches Go, the
//! `rust_stdlib::math` functions elsewhere.
use rust_stdlib::math;
use std::io::{self, BufRead, Write};
use std::panic;

fn f(s: &str) -> f64 {
    f64::from_bits(u64::from_str_radix(s, 16).expect("hex bits"))
}

fn i(s: &str) -> i64 {
    s.parse().expect("integer")
}

fn u(s: &str) -> u64 {
    s.parse().expect("unsigned integer")
}

fn o(x: f64) -> String {
    if x.is_nan() {
        "nan".to_string()
    } else {
        format!("{:016x}", x.to_bits())
    }
}

fn b(v: bool) -> String {
    if v { "1" } else { "0" }.to_string()
}

fn unary(op: &str) -> Option<fn(f64) -> f64> {
    Some(match op {
        "abs" => f64::abs,
        "acos" => math::acos,
        "acosh" => math::acosh,
        "asin" => math::asin,
        "asinh" => math::asinh,
        "atan" => math::atan,
        "atanh" => math::atanh,
        "cbrt" => math::cbrt,
        "ceil" => f64::ceil,
        "cos" => math::cos,
        "cosh" => math::cosh,
        "erf" => math::erf,
        "erfc" => math::erfc,
        "erfinv" => math::erfinv,
        "erfcinv" => math::erfcinv,
        "exp" => math::exp,
        "exp2" => math::exp2,
        "expm1" => math::expm1,
        "floor" => f64::floor,
        "gamma" => math::gamma,
        "j0" => math::j0,
        "j1" => math::j1,
        "log" => math::log,
        "log10" => math::log10,
        "log1p" => math::log1p,
        "log2" => math::log2,
        "logb" => math::logb,
        "round" => f64::round,
        "roundtoeven" => f64::round_ties_even,
        "sin" => math::sin,
        "sinh" => math::sinh,
        "sqrt" => f64::sqrt,
        "tan" => math::tan,
        "tanh" => math::tanh,
        "trunc" => f64::trunc,
        "y0" => math::y0,
        "y1" => math::y1,
        _ => return None,
    })
}

fn binary(op: &str) -> Option<fn(f64, f64) -> f64> {
    Some(match op {
        "atan2" => math::atan2,
        "copysign" => f64::copysign,
        "dim" => math::dim,
        "hypot" => math::hypot,
        "max" => math::max,
        "min" => math::min,
        "mod" => |x, y| x % y,
        "nextafter" => math::nextafter,
        "pow" => math::pow,
        "remainder" => math::remainder,
        _ => return None,
    })
}

fn answer(line: &str) -> String {
    let parts: Vec<&str> = line.split_whitespace().collect();
    let (op, a) = (parts[0], &parts[1..]);
    if let Some(func) = unary(op) {
        return o(func(f(a[0])));
    }
    if let Some(func) = binary(op) {
        return o(func(f(a[0]), f(a[1])));
    }
    match op {
        "fma" => o(f(a[0]).mul_add(f(a[1]), f(a[2]))),
        "frexp" => {
            let (fr, e) = math::frexp(f(a[0]));
            format!("{} {}", o(fr), e)
        }
        "ldexp" => o(math::ldexp(f(a[0]), i(a[1]))),
        "modf" => {
            let (ip, fp) = math::modf(f(a[0]));
            format!("{} {}", o(ip), o(fp))
        }
        "lgamma" => {
            let (l, s) = math::lgamma(f(a[0]));
            format!("{} {}", o(l), s)
        }
        "sincos" => {
            let (s, c) = math::sincos(f(a[0]));
            format!("{} {}", o(s), o(c))
        }
        "jn" => o(math::jn(i(a[0]), f(a[1]))),
        "yn" => o(math::yn(i(a[0]), f(a[1]))),
        "ilogb" => math::ilogb(f(a[0])).to_string(),
        "pow10" => o(math::pow10(i(a[0]))),
        "isinf" => b(math::is_inf(f(a[0]), i(a[1]) as i32)),
        "isnan" => b(f(a[0]).is_nan()),
        "signbit" => b(f(a[0]).is_sign_negative()),
        "inf" => o(math::inf(i(a[0]) as i32)),
        "nan" => format!("{:016x}", math::nan().to_bits()),
        "f64bits" => format!("{:016x}", f(a[0]).to_bits()),
        "f32bits" => format!("{:08x}", (f(a[0]) as f32).to_bits()),
        "f32from" => {
            let v = f32::from_bits(u(a[0]) as u32);
            if v.is_nan() {
                "nan".to_string()
            } else {
                format!("{:016x}", f64::from(v).to_bits())
            }
        }
        "nextafter32" => {
            let r = math::nextafter32(f(a[0]) as f32, f(a[1]) as f32);
            if r.is_nan() {
                "nan".to_string()
            } else {
                format!("{:08x}", r.to_bits())
            }
        }
        "const" => {
            use std::f64::consts as c;
            [
                c::E,
                c::PI,
                math::PHI,
                c::SQRT_2,
                math::SQRT_E,
                math::SQRT_PI,
                math::SQRT_PHI,
                c::LN_2,
                c::LOG2_E,
                c::LN_10,
                c::LOG10_E,
                math::MAX_FLOAT32,
                math::SMALLEST_NONZERO_FLOAT32,
                f64::MAX,
                math::SMALLEST_NONZERO_FLOAT64,
            ]
            .iter()
            .map(|v| o(*v))
            .collect::<Vec<_>>()
            .join(" ")
        }
        "intconst" => format!(
            "{} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {}",
            i8::MAX,
            i8::MIN,
            i16::MAX,
            i16::MIN,
            i32::MAX,
            i32::MIN,
            i64::MAX,
            i64::MIN,
            u8::MAX,
            u16::MAX,
            u32::MAX,
            u64::MAX,
            isize::MAX,
            isize::MIN,
            usize::MAX,
            usize::BITS
        ),
        _ => bits_answer(op, a),
    }
}

fn rot_k(s: &str) -> i32 {
    i(s) as i32
}

// math/bits through std: Len is `BITS - leading_zeros`, RotateLeft is
// `rotate_left` with a wrapped count, Add/Sub are two `overflowing_add`s
// or `overflowing_sub`s, and Mul/Div/Rem widen to `u128`.
fn len(x: u128) -> String {
    (u128::BITS - x.leading_zeros()).to_string()
}

macro_rules! rot_impl {
    ($($t:ty),*) => {$(impl Rot for $t {
        fn rot(self, k: i32) -> String {
            self.rotate_left((k as u32) & (<$t>::BITS - 1)).to_string()
        }
    })*};
}
trait Rot {
    fn rot(self, k: i32) -> String;
}
rot_impl!(u8, u16, u32, u64, usize);

fn rot<T: Rot>(x: T, k: i32) -> String {
    x.rot(k)
}

macro_rules! add {
    ($t:ty, $a:expr) => {{
        let (s, c1) = (u($a[0]) as $t).overflowing_add(u($a[1]) as $t);
        let (s, c2) = s.overflowing_add(u($a[2]) as $t);
        pair((s, (c1 | c2) as u8))
    }};
}
macro_rules! sub {
    ($t:ty, $a:expr) => {{
        let (d, b1) = (u($a[0]) as $t).overflowing_sub(u($a[1]) as $t);
        let (d, b2) = d.overflowing_sub(u($a[2]) as $t);
        pair((d, (b1 | b2) as u8))
    }};
}
macro_rules! mul {
    ($t:ty, $a:expr) => {{
        let p = (u($a[0]) as $t as u128) * (u($a[1]) as $t as u128);
        pair(((p >> <$t>::BITS) as $t, p as $t))
    }};
}
macro_rules! div {
    ($t:ty, $a:expr) => {{
        let (hi, lo, y) = (u($a[0]) as $t, u($a[1]) as $t, u($a[2]) as $t);
        assert!(y > hi, "division overflow or by zero");
        let n = (hi as u128) << <$t>::BITS | (lo as u128);
        pair(((n / (y as u128)) as $t, (n % (y as u128)) as $t))
    }};
}
macro_rules! rem {
    ($t:ty, $a:expr) => {{
        let (hi, lo, y) = (u($a[0]) as $t, u($a[1]) as $t, u($a[2]) as $t);
        let n = (hi as u128) << <$t>::BITS | (lo as u128);
        (n % (y as u128)).to_string()
    }};
}

fn bits_answer(op: &str, a: &[&str]) -> String {
    match op {
        "lz8" => u8::leading_zeros(u(a[0]) as u8).to_string(),
        "lz16" => u16::leading_zeros(u(a[0]) as u16).to_string(),
        "lz32" => u32::leading_zeros(u(a[0]) as u32).to_string(),
        "lz64" => u64::leading_zeros(u(a[0])).to_string(),
        "lz" => usize::leading_zeros(u(a[0]) as usize).to_string(),
        "tz8" => u8::trailing_zeros(u(a[0]) as u8).to_string(),
        "tz16" => u16::trailing_zeros(u(a[0]) as u16).to_string(),
        "tz32" => u32::trailing_zeros(u(a[0]) as u32).to_string(),
        "tz64" => u64::trailing_zeros(u(a[0])).to_string(),
        "tz" => usize::trailing_zeros(u(a[0]) as usize).to_string(),
        "oc8" => u8::count_ones(u(a[0]) as u8).to_string(),
        "oc16" => u16::count_ones(u(a[0]) as u16).to_string(),
        "oc32" => u32::count_ones(u(a[0]) as u32).to_string(),
        "oc64" => u64::count_ones(u(a[0])).to_string(),
        "oc" => usize::count_ones(u(a[0]) as usize).to_string(),
        "len8" => len(u(a[0]) as u8 as u128),
        "len16" => len(u(a[0]) as u16 as u128),
        "len32" => len(u(a[0]) as u32 as u128),
        "len64" => len(u(a[0]) as u128),
        "len" => len(u(a[0]) as usize as u128),
        "rev8" => u8::reverse_bits(u(a[0]) as u8).to_string(),
        "rev16" => u16::reverse_bits(u(a[0]) as u16).to_string(),
        "rev32" => u32::reverse_bits(u(a[0]) as u32).to_string(),
        "rev64" => u64::reverse_bits(u(a[0])).to_string(),
        "rev" => usize::reverse_bits(u(a[0]) as usize).to_string(),
        "revb16" => u16::swap_bytes(u(a[0]) as u16).to_string(),
        "revb32" => u32::swap_bytes(u(a[0]) as u32).to_string(),
        "revb64" => u64::swap_bytes(u(a[0])).to_string(),
        "revb" => usize::swap_bytes(u(a[0]) as usize).to_string(),
        "rot8" => rot(u(a[0]) as u8, rot_k(a[1])),
        "rot16" => rot(u(a[0]) as u16, rot_k(a[1])),
        "rot32" => rot(u(a[0]) as u32, rot_k(a[1])),
        "rot64" => rot(u(a[0]), rot_k(a[1])),
        "rot" => rot(u(a[0]) as usize, rot_k(a[1])),
        "add32" => add!(u32, a),
        "add64" => add!(u64, a),
        "add" => add!(usize, a),
        "sub32" => sub!(u32, a),
        "sub64" => sub!(u64, a),
        "sub" => sub!(usize, a),
        "mul32" => mul!(u32, a),
        "mul64" => mul!(u64, a),
        "mul" => mul!(usize, a),
        "div32" => div!(u32, a),
        "div64" => div!(u64, a),
        "div" => div!(usize, a),
        "rem32" => rem!(u32, a),
        "rem64" => rem!(u64, a),
        "rem" => rem!(usize, a),
        _ => format!("unknown op {op}"),
    }
}

fn pair<T: std::fmt::Display, U: std::fmt::Display>((x, y): (T, U)) -> String {
    format!("{x} {y}")
}

fn main() -> io::Result<()> {
    panic::set_hook(Box::new(|_| {}));
    let stdin = io::stdin();
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line?;
        let reply = panic::catch_unwind(|| answer(&line)).unwrap_or_else(|_| "panic".to_string());
        writeln!(out, "{reply}")?;
    }
    Ok(())
}
