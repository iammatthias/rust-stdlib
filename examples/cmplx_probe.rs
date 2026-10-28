//! Line protocol used by `tools/cmplx_check.py`; mirrors `tools/cmplx_oracle.go`.
use rust_stdlib::math::cmplx;
use rust_stdlib::strconv::Complex;
use std::io::{self, BufRead, Write};

fn f(s: &str) -> f64 {
    f64::from_bits(u64::from_str_radix(s, 16).expect("hex bits"))
}

fn o(x: f64) -> String {
    if x.is_nan() {
        "nan".to_string()
    } else {
        format!("{:016x}", x.to_bits())
    }
}

fn oc(z: Complex) -> String {
    format!("{} {}", o(z.re), o(z.im))
}

fn b(v: bool) -> String {
    if v { "1" } else { "0" }.to_string()
}

fn unary(op: &str) -> Option<fn(Complex) -> Complex> {
    Some(match op {
        "acos" => cmplx::acos,
        "acosh" => cmplx::acosh,
        "asin" => cmplx::asin,
        "asinh" => cmplx::asinh,
        "atan" => cmplx::atan,
        "atanh" => cmplx::atanh,
        "conj" => cmplx::conj,
        "cos" => cmplx::cos,
        "cosh" => cmplx::cosh,
        "cot" => cmplx::cot,
        "exp" => cmplx::exp,
        "log" => cmplx::log,
        "log10" => cmplx::log10,
        "sin" => cmplx::sin,
        "sinh" => cmplx::sinh,
        "sqrt" => cmplx::sqrt,
        "tan" => cmplx::tan,
        "tanh" => cmplx::tanh,
        "neg" => |z| -z,
        _ => return None,
    })
}

fn answer(line: &str) -> String {
    let parts: Vec<&str> = line.split_whitespace().collect();
    let (op, a) = (parts[0], &parts[1..]);
    match op {
        "inf" => return oc(cmplx::inf()),
        "nan" => return oc(cmplx::nan()),
        "rect" => return oc(cmplx::rect(f(a[0]), f(a[1]))),
        _ => {}
    }
    let z = Complex::new(f(a[0]), f(a[1]));
    if let Some(func) = unary(op) {
        return oc(func(z));
    }
    match op {
        "abs" => return o(cmplx::abs(z)),
        "phase" => return o(cmplx::phase(z)),
        "polar" => {
            let (r, t) = cmplx::polar(z);
            return format!("{} {}", o(r), o(t));
        }
        "isinf" => return b(cmplx::is_inf(z)),
        "isnan" => return b(cmplx::is_nan(z)),
        _ => {}
    }
    let w = Complex::new(f(a[2]), f(a[3]));
    match op {
        "pow" => oc(cmplx::pow(z, w)),
        "add" => oc(z + w),
        "sub" => oc(z - w),
        "mul" => oc(z * w),
        "div" => oc(z / w),
        _ => format!("unknown op {op}"),
    }
}

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        writeln!(out, "{}", answer(&line?))?;
    }
    Ok(())
}
