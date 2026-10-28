//! Go's `fmt` formatting (`Sprint`, `Sprintln`, `Sprintf`) over [`Value`]s,
//! as the template builtins `print`, `println` and `printf` and the output of
//! actions need it. The verbs, flags, width/precision, argument indexes and
//! the `%!verb(type=value)` error forms follow Go's `fmt`; `Formatter` and
//! `GoStringer` are not supported (a template value cannot implement them).

use super::value::{CallError, Kind, Repr, Type, Value};
use crate::strconv;
use std::cmp::Ordering;

const LDIGITS: &[u8; 17] = b"0123456789abcdefx";
const UDIGITS: &[u8; 17] = b"0123456789ABCDEFX";

/// `fmt.Sprint`.
pub fn sprint(args: &[Value]) -> String {
    let mut p = Printer::new();
    p.do_print(args);
    p.buf
}

/// `fmt.Sprintln`.
pub fn sprintln(args: &[Value]) -> String {
    let mut p = Printer::new();
    p.do_println(args);
    p.buf
}

/// `fmt.Sprintf`.
pub fn sprintf(format: &str, args: &[Value]) -> String {
    let mut p = Printer::new();
    p.do_printf(format, args);
    p.buf
}

fn cmp_f64(a: f64, b: f64) -> Ordering {
    // Go's cmp.Compare: NaN sorts before everything and equals itself.
    match (a.is_nan(), b.is_nan()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        _ => a.partial_cmp(&b).unwrap_or(Ordering::Equal),
    }
}

/// Orders map keys as Go's `internal/fmtsort` does.
pub(crate) fn compare_keys(a: &Value, b: &Value) -> Ordering {
    if a.ty != b.ty {
        return Ordering::Less;
    }
    match (&a.r, &b.r) {
        (Repr::Int(x), Repr::Int(y)) => x.cmp(y),
        (Repr::Uint(x), Repr::Uint(y)) => x.cmp(y),
        (Repr::Str(x), Repr::Str(y)) => x.as_bytes().cmp(y.as_bytes()),
        (Repr::Float(x), Repr::Float(y)) => cmp_f64(*x, *y),
        (Repr::Complex(x, i), Repr::Complex(y, j)) => cmp_f64(*x, *y).then(cmp_f64(*i, *j)),
        (Repr::Bool(x), Repr::Bool(y)) => x.cmp(y),
        (Repr::Struct(x), Repr::Struct(y)) => {
            for (p, q) in x.iter().zip(y.iter()) {
                let c = compare_keys(p, q);
                if c != Ordering::Equal {
                    return c;
                }
            }
            Ordering::Equal
        }
        (Repr::Array(x), Repr::Array(y)) => {
            for (p, q) in x.iter().zip(y.iter()) {
                let c = compare_keys(p, q);
                if c != Ordering::Equal {
                    return c;
                }
            }
            Ordering::Equal
        }
        (Repr::Iface(x), Repr::Iface(y)) => match (x, y) {
            (None, None) => Ordering::Equal,
            (None, _) => Ordering::Less,
            (_, None) => Ordering::Greater,
            (Some(x), Some(y)) => {
                let (tx, ty) = (
                    x.ty.as_ref().map(Type::type_string).unwrap_or_default(),
                    y.ty.as_ref().map(Type::type_string).unwrap_or_default(),
                );
                tx.cmp(&ty).then_with(|| compare_keys(x, y))
            }
        },
        (Repr::Ptr(x), Repr::Ptr(y)) => ptr_addr(x).cmp(&ptr_addr(y)),
        _ => Ordering::Equal,
    }
}

fn ptr_addr(p: &Option<std::sync::Arc<Value>>) -> usize {
    p.as_ref().map_or(0, |a| std::sync::Arc::as_ptr(a) as usize)
}

#[derive(Clone, Default)]
struct Flags {
    wid_present: bool,
    prec_present: bool,
    minus: bool,
    plus: bool,
    sharp: bool,
    space: bool,
    zero: bool,
    plus_v: bool,
    sharp_v: bool,
}

struct Printer {
    buf: String,
    f: Flags,
    wid: usize,
    prec: usize,
    reordered: bool,
    good_arg_num: bool,
    panicking: bool,
    erroring: bool,
}

fn parsenum(s: &[u8], start: usize, end: usize) -> (usize, bool, usize) {
    if start >= end {
        return (0, false, end);
    }
    let (mut num, mut isnum, mut i) = (0usize, false, start);
    while i < end && s[i].is_ascii_digit() {
        if num > 1_000_000 {
            return (0, false, end);
        }
        num = num * 10 + usize::from(s[i] - b'0');
        isnum = true;
        i += 1;
    }
    (num, isnum, i)
}

fn rune_count(s: &str) -> usize {
    s.chars().count()
}

impl Printer {
    fn new() -> Printer {
        Printer {
            buf: String::new(),
            f: Flags::default(),
            wid: 0,
            prec: 0,
            reordered: false,
            good_arg_num: true,
            panicking: false,
            erroring: false,
        }
    }

    fn clearflags(&mut self) {
        self.f = Flags::default();
        self.wid = 0;
        self.prec = 0;
    }

    // ---- fmt (format.go) ------------------------------------------------

    fn write_padding(&mut self, n: usize) {
        let pad = if self.f.zero && !self.f.minus {
            '0'
        } else {
            ' '
        };
        for _ in 0..n {
            self.buf.push(pad);
        }
    }

    fn pad(&mut self, s: &str) {
        if !self.f.wid_present || self.wid == 0 {
            self.buf.push_str(s);
            return;
        }
        let width = self.wid.saturating_sub(rune_count(s));
        if !self.f.minus {
            self.write_padding(width);
            self.buf.push_str(s);
        } else {
            self.buf.push_str(s);
            self.write_padding(width);
        }
    }

    fn fmt_boolean(&mut self, v: bool) {
        self.pad(if v { "true" } else { "false" });
    }

    fn fmt_unicode(&mut self, mut u: u64) {
        let orig = u;
        let mut prec = 4usize;
        if self.f.prec_present && self.prec > 4 {
            prec = self.prec;
        }
        let mut digits: Vec<u8> = Vec::new();
        while u >= 16 {
            digits.push(UDIGITS[(u & 0xF) as usize]);
            prec = prec.saturating_sub(1);
            u >>= 4;
        }
        digits.push(UDIGITS[u as usize]);
        prec = prec.saturating_sub(1);
        while prec > 0 {
            digits.push(b'0');
            prec -= 1;
        }
        digits.push(b'+');
        digits.push(b'U');
        digits.reverse();
        let mut s = String::from_utf8(digits).expect("ascii");
        if self.f.sharp {
            if let Some(c) = u32::try_from(orig).ok().and_then(char::from_u32) {
                if strconv::is_print(c as i32) {
                    s.push_str(&format!(" '{c}'"));
                }
            }
        }
        let old = self.f.zero;
        self.f.zero = false;
        self.pad(&s);
        self.f.zero = old;
    }

    fn fmt_integer(&mut self, u: u64, base: u32, is_signed: bool, verb: char, digits: &[u8; 17]) {
        let negative = is_signed && (u as i64) < 0;
        let mut u = u;
        if negative {
            u = u.wrapping_neg();
        }
        let mut prec = 0usize;
        if self.f.prec_present {
            prec = self.prec;
            if prec == 0 && u == 0 {
                let old = self.f.zero;
                self.f.zero = false;
                self.write_padding(self.wid);
                self.f.zero = old;
                return;
            }
        } else if self.f.zero && !self.f.minus && self.f.wid_present {
            prec = self.wid;
            if negative || self.f.plus || self.f.space {
                prec = prec.saturating_sub(1);
            }
        }
        let mut buf: Vec<u8> = Vec::new(); // built in reverse
        match base {
            10 => {
                while u >= 10 {
                    buf.push(b'0' + (u % 10) as u8);
                    u /= 10;
                }
            }
            16 => {
                while u >= 16 {
                    buf.push(digits[(u & 0xF) as usize]);
                    u >>= 4;
                }
            }
            8 => {
                while u >= 8 {
                    buf.push(b'0' + (u & 7) as u8);
                    u >>= 3;
                }
            }
            _ => {
                while u >= 2 {
                    buf.push(b'0' + (u & 1) as u8);
                    u >>= 1;
                }
            }
        }
        buf.push(digits[u as usize]);
        while prec > buf.len() {
            buf.push(b'0');
        }
        if self.f.sharp {
            match base {
                2 => {
                    buf.push(b'b');
                    buf.push(b'0');
                }
                8 => {
                    if *buf.last().expect("non-empty") != b'0' {
                        buf.push(b'0');
                    }
                }
                16 => {
                    buf.push(digits[16]);
                    buf.push(b'0');
                }
                _ => {}
            }
        }
        if verb == 'O' {
            buf.push(b'o');
            buf.push(b'0');
        }
        if negative {
            buf.push(b'-');
        } else if self.f.plus {
            buf.push(b'+');
        } else if self.f.space {
            buf.push(b' ');
        }
        buf.reverse();
        let s = String::from_utf8(buf).expect("ascii");
        let old = self.f.zero;
        self.f.zero = false;
        self.pad(&s);
        self.f.zero = old;
    }

    fn truncate_string<'a>(&self, s: &'a str) -> &'a str {
        if self.f.prec_present {
            let mut n = self.prec as isize;
            for (i, _) in s.char_indices() {
                n -= 1;
                if n < 0 {
                    return &s[..i];
                }
            }
        }
        s
    }

    fn fmt_s(&mut self, s: &str) {
        let s = self.truncate_string(s).to_owned();
        self.pad(&s);
    }

    fn fmt_sbx(&mut self, s: &[u8], digits: &[u8; 17]) {
        let mut length = s.len();
        if self.f.prec_present && self.prec < length {
            length = self.prec;
        }
        let mut width = 2 * length;
        if width > 0 {
            if self.f.space {
                if self.f.sharp {
                    width *= 2;
                }
                width += length - 1;
            } else if self.f.sharp {
                width += 2;
            }
        } else {
            if self.f.wid_present {
                self.write_padding(self.wid);
            }
            return;
        }
        if self.f.wid_present && self.wid > width && !self.f.minus {
            self.write_padding(self.wid - width);
        }
        if self.f.sharp {
            self.buf.push('0');
            self.buf.push(digits[16] as char);
        }
        for (i, &c) in s.iter().take(length).enumerate() {
            if self.f.space && i > 0 {
                self.buf.push(' ');
                if self.f.sharp {
                    self.buf.push('0');
                    self.buf.push(digits[16] as char);
                }
            }
            self.buf.push(digits[usize::from(c >> 4)] as char);
            self.buf.push(digits[usize::from(c & 0xF)] as char);
        }
        if self.f.wid_present && self.wid > width && self.f.minus {
            self.write_padding(self.wid - width);
        }
    }

    fn fmt_q(&mut self, s: &str) {
        let s = self.truncate_string(s).to_owned();
        if self.f.sharp && strconv::can_backquote(&s) {
            self.pad(&format!("`{s}`"));
            return;
        }
        let q = if self.f.plus {
            strconv::quote_to_ascii(&s)
        } else {
            strconv::quote(&s)
        };
        self.pad(&q);
    }

    fn fmt_c(&mut self, c: u64) {
        let r = if c > 0x10FFFF {
            '\u{FFFD}'
        } else {
            char::from_u32(c as u32).unwrap_or('\u{FFFD}')
        };
        self.pad(&r.to_string());
    }

    fn fmt_qc(&mut self, c: u64) {
        let r: i32 = if c > 0x10FFFF { 0xFFFD } else { c as i32 };
        let q = if self.f.plus {
            strconv::quote_rune_to_ascii(r)
        } else {
            strconv::quote_rune(r)
        };
        self.pad(&q);
    }

    fn fmt_float_raw(&mut self, v: f64, size: i32, verb: char, prec: i32) {
        let prec = if self.f.prec_present {
            self.prec as i32
        } else {
            prec
        };
        let s = strconv::format_float(v, verb as u8, prec, size);
        // num[0] holds the sign; make it explicit.
        let mut num: Vec<u8> = Vec::with_capacity(s.len() + 1);
        if s.starts_with('-') || s.starts_with('+') {
            num.extend_from_slice(s.as_bytes());
        } else {
            num.push(b'+');
            num.extend_from_slice(s.as_bytes());
        }
        if self.f.space && num[0] == b'+' && !self.f.plus {
            num[0] = b' ';
        }
        // Special handling for infinities and NaN, which don't look like a
        // number so shouldn't be padded with zeros.
        if num[1] == b'I' || num[1] == b'N' {
            let old = self.f.zero;
            self.f.zero = false;
            if num[1] == b'N' && !self.f.space && !self.f.plus {
                num.remove(0);
            }
            let s = String::from_utf8(num).expect("ascii");
            self.pad(&s);
            self.f.zero = old;
            return;
        }
        // The sharp flag forces printing a decimal point but removes trailing
        // zeros for %e, %f with the shortest flag.
        if self.f.sharp && verb != 'b' {
            let mut digits: i32 = 0;
            if matches!(verb, 'v' | 'g' | 'G' | 'x') {
                digits = prec;
                if digits == -1 {
                    digits = 6;
                }
            }
            let mut tail: Vec<u8> = Vec::new();
            let mut has_decimal_point = false;
            let mut saw_nonzero_digit = false;
            let mut i = 1;
            while i < num.len() {
                match num[i] {
                    b'.' => has_decimal_point = true,
                    b'p' | b'P' => {
                        tail.extend_from_slice(&num[i..]);
                        num.truncate(i);
                    }
                    b'e' | b'E' if verb != 'x' && verb != 'X' => {
                        tail.extend_from_slice(&num[i..]);
                        num.truncate(i);
                    }
                    c => {
                        if c != b'0' {
                            saw_nonzero_digit = true;
                        }
                        if saw_nonzero_digit {
                            digits -= 1;
                        }
                    }
                }
                i += 1;
            }
            if !has_decimal_point {
                // Leading digit 0 should contribute once to digits.
                if num.len() == 2 && num[1] == b'0' {
                    digits -= 1;
                }
                num.push(b'.');
            }
            while digits > 0 {
                num.push(b'0');
                digits -= 1;
            }
            num.extend_from_slice(&tail);
        }
        // We want a sign if asked for and if the sign is not positive.
        if self.f.plus || num[0] != b'+' {
            // If we're zero padding to the left we want the sign before the
            // leading zeros. Achieve this by writing the sign out and then
            // padding the unsigned number.
            if self.f.zero && !self.f.minus && self.f.wid_present && self.wid > num.len() {
                self.buf.push(num[0] as char);
                self.write_padding(self.wid - num.len());
                self.buf
                    .push_str(std::str::from_utf8(&num[1..]).expect("ascii"));
                return;
            }
            let s = String::from_utf8(num).expect("ascii");
            self.pad(&s);
            return;
        }
        // No sign to show and the number is positive; just print the unsigned
        // number.
        let s = String::from_utf8(num[1..].to_vec()).expect("ascii");
        self.pad(&s);
    }

    // ---- print.go ---------------------------------------------------------

    fn bad_verb(&mut self, arg: Option<&Value>, verb: char) {
        self.erroring = true;
        self.buf.push_str("%!");
        self.buf.push(verb);
        self.buf.push('(');
        match arg {
            Some(a) if a.is_valid() => {
                self.buf
                    .push_str(&a.ty.as_ref().expect("valid").type_string());
                self.buf.push('=');
                self.print_value(a, 'v', 0);
            }
            _ => self.buf.push_str("<nil>"),
        }
        self.buf.push(')');
        self.erroring = false;
    }

    fn fmt_bool(&mut self, arg: &Value, v: bool, verb: char) {
        match verb {
            't' | 'v' => self.fmt_boolean(v),
            _ => self.bad_verb(Some(arg), verb),
        }
    }

    fn fmt0x64(&mut self, v: u64, leading0x: bool) {
        let sharp = self.f.sharp;
        self.f.sharp = leading0x;
        self.fmt_integer(v, 16, false, 'v', LDIGITS);
        self.f.sharp = sharp;
    }

    fn fmt_int(&mut self, arg: &Value, v: u64, is_signed: bool, verb: char) {
        match verb {
            'v' => {
                if self.f.sharp_v && !is_signed {
                    self.fmt0x64(v, true);
                } else {
                    self.fmt_integer(v, 10, is_signed, verb, LDIGITS);
                }
            }
            'd' => self.fmt_integer(v, 10, is_signed, verb, LDIGITS),
            'b' => self.fmt_integer(v, 2, is_signed, verb, LDIGITS),
            'o' | 'O' => self.fmt_integer(v, 8, is_signed, verb, LDIGITS),
            'x' => self.fmt_integer(v, 16, is_signed, verb, LDIGITS),
            'X' => self.fmt_integer(v, 16, is_signed, verb, UDIGITS),
            'c' => self.fmt_c(v),
            'q' => self.fmt_qc(v),
            'U' => self.fmt_unicode(v),
            _ => self.bad_verb(Some(arg), verb),
        }
    }

    fn fmt_float(&mut self, arg: &Value, v: f64, size: i32, verb: char) {
        match verb {
            'v' => self.fmt_float_raw(v, size, 'g', -1),
            'b' | 'g' | 'G' | 'x' | 'X' => self.fmt_float_raw(v, size, verb, -1),
            'f' | 'e' | 'E' => self.fmt_float_raw(v, size, verb, 6),
            'F' => self.fmt_float_raw(v, size, 'f', 6),
            _ => self.bad_verb(Some(arg), verb),
        }
    }

    fn fmt_complex(&mut self, arg: &Value, re: f64, im: f64, size: i32, verb: char) {
        match verb {
            'v' | 'b' | 'g' | 'G' | 'x' | 'X' | 'f' | 'F' | 'e' | 'E' => {
                let old_plus = self.f.plus;
                self.buf.push('(');
                self.fmt_float(arg, re, size / 2, verb);
                // Imaginary part always has a sign.
                self.f.plus = true;
                self.fmt_float(arg, im, size / 2, verb);
                self.buf.push_str("i)");
                self.f.plus = old_plus;
            }
            _ => self.bad_verb(Some(arg), verb),
        }
    }

    fn fmt_string(&mut self, arg: &Value, v: &str, verb: char) {
        match verb {
            'v' => {
                if self.f.sharp_v {
                    self.fmt_q(v);
                } else {
                    self.fmt_s(v);
                }
            }
            's' => self.fmt_s(v),
            'x' => self.fmt_sbx(v.as_bytes(), LDIGITS),
            'X' => self.fmt_sbx(v.as_bytes(), UDIGITS),
            'q' => self.fmt_q(v),
            _ => self.bad_verb(Some(arg), verb),
        }
    }

    fn fmt_bytes(&mut self, arg: &Value, v: &[u8], verb: char, type_string: &str, is_nil: bool) {
        match verb {
            'v' | 'd' => {
                if self.f.sharp_v {
                    self.buf.push_str(type_string);
                    if is_nil {
                        self.buf.push_str("(nil)");
                        return;
                    }
                    self.buf.push('{');
                    for (i, &c) in v.iter().enumerate() {
                        if i > 0 {
                            self.buf.push_str(", ");
                        }
                        self.fmt0x64(u64::from(c), true);
                    }
                    self.buf.push('}');
                } else {
                    self.buf.push('[');
                    for (i, &c) in v.iter().enumerate() {
                        if i > 0 {
                            self.buf.push(' ');
                        }
                        self.fmt_integer(u64::from(c), 10, false, verb, LDIGITS);
                    }
                    self.buf.push(']');
                }
            }
            's' => {
                let s = String::from_utf8_lossy(v).into_owned();
                self.fmt_s(&s);
            }
            'x' => self.fmt_sbx(v, LDIGITS),
            'X' => self.fmt_sbx(v, UDIGITS),
            'q' => {
                let s = String::from_utf8_lossy(v).into_owned();
                self.fmt_q(&s);
            }
            _ => self.print_value_plain(arg, verb),
        }
    }

    fn pointer_value(v: &Value) -> Option<u64> {
        Some(match &v.r {
            Repr::Ptr(p) => ptr_addr(p) as u64,
            Repr::Map(Some(m)) => std::sync::Arc::as_ptr(m) as usize as u64,
            Repr::Slice {
                buf: Some(b), off, ..
            } => (std::sync::Arc::as_ptr(b) as usize + off * 8) as u64,
            Repr::Chan(Some(c)) => std::sync::Arc::as_ptr(c) as *const u8 as usize as u64,
            Repr::Func(Some(c)) => std::sync::Arc::as_ptr(c) as *const u8 as usize as u64,
            Repr::Seq(c) => std::sync::Arc::as_ptr(c) as *const u8 as usize as u64,
            Repr::Seq2(c) => std::sync::Arc::as_ptr(c) as *const u8 as usize as u64,
            Repr::UnsafePtr(Some(a)) => *a as u64,
            Repr::Map(None)
            | Repr::Slice { buf: None, .. }
            | Repr::Chan(None)
            | Repr::Func(None)
            | Repr::UnsafePtr(None) => 0,
            _ => return None,
        })
    }

    fn fmt_pointer(&mut self, value: &Value, verb: char) {
        let Some(u) = Self::pointer_value(value) else {
            self.bad_verb(Some(value), verb);
            return;
        };
        match verb {
            'v' => {
                if self.f.sharp_v {
                    self.buf.push('(');
                    self.buf
                        .push_str(&value.ty.as_ref().expect("valid").type_string());
                    self.buf.push_str(")(");
                    if u == 0 {
                        self.buf.push_str("nil");
                    } else {
                        self.fmt0x64(u, true);
                    }
                    self.buf.push(')');
                } else if u == 0 {
                    self.pad("<nil>");
                } else {
                    let sharp = self.f.sharp;
                    self.fmt0x64(u, !sharp);
                }
            }
            'p' => {
                let sharp = self.f.sharp;
                self.fmt0x64(u, !sharp);
            }
            'b' | 'o' | 'd' | 'x' | 'X' => self.fmt_int(value, u, false, verb),
            _ => self.bad_verb(Some(value), verb),
        }
    }

    /// Calls Error() or String() when the value's method set has one and the
    /// verb calls for it.
    fn handle_methods(&mut self, arg: &Value, verb: char) -> bool {
        if self.erroring {
            return false;
        }
        let verb = if verb == 'w' {
            self.bad_verb(Some(arg), verb);
            return true;
        } else {
            verb
        };
        if self.f.sharp_v {
            return false;
        }
        if !matches!(verb, 'v' | 's' | 'x' | 'X' | 'q') {
            return false;
        }
        let Some(ty) = &arg.ty else { return false };
        if arg.kind() == Kind::Interface {
            return false;
        }
        let ms = ty.method_set();
        let string_sig = super::value::FuncSig::new(vec![], vec![Type::string()], false);
        for name in ["Error", "String"] {
            if ms.iter().any(|(n, s)| n == name && *s == string_sig) {
                let m = arg.method_by_name(name);
                match m.call(&[]) {
                    Ok(v) => {
                        let s = v.as_string();
                        self.fmt_string(arg, &s, verb);
                    }
                    Err(e) => self.catch_panic(arg, verb, name, e),
                }
                return true;
            }
        }
        false
    }

    fn catch_panic(&mut self, arg: &Value, verb: char, method: &str, err: CallError) {
        if arg.kind() == Kind::Pointer && arg.is_nil() {
            self.buf.push_str("<nil>");
            return;
        }
        let msg = match err {
            CallError::Panic(m) => m,
            CallError::Error(e) => e.to_string(),
        };
        let old = self.f.clone();
        let (w, pr) = (self.wid, self.prec);
        self.clearflags();
        self.buf.push_str("%!");
        self.buf.push(verb);
        self.buf.push_str("(PANIC=");
        self.buf.push_str(method);
        self.buf.push_str(" method: ");
        self.panicking = true;
        self.buf.push_str(&msg);
        self.panicking = false;
        self.buf.push(')');
        self.f = old;
        self.wid = w;
        self.prec = pr;
    }

    fn print_arg(&mut self, arg: &Value, verb: char) {
        let arg = arg.interface();
        if !arg.is_valid() {
            match verb {
                'T' | 'v' => self.pad("<nil>"),
                _ => self.bad_verb(None, verb),
            }
            return;
        }
        match verb {
            'T' => {
                let s = arg.ty.as_ref().expect("valid").type_string();
                self.fmt_s(&s);
                return;
            }
            'p' => {
                self.fmt_pointer(&arg, 'p');
                return;
            }
            _ => {}
        }
        if !self.handle_methods(&arg, verb) {
            self.print_value(&arg, verb, 0);
        }
    }

    fn print_value_plain(&mut self, v: &Value, verb: char) {
        self.print_value(v, verb, 0);
    }

    fn print_value(&mut self, value: &Value, verb: char, depth: usize) {
        if depth > 0 && value.is_valid() && value.can_interface() {
            let arg = value.interface();
            if arg.is_valid() && self.handle_methods(&arg, verb) {
                return;
            }
        }
        let f = value;
        match f.kind() {
            Kind::Invalid => {
                if depth == 0 {
                    self.buf.push_str("<invalid reflect.Value>");
                } else if verb == 'v' {
                    self.buf.push_str("<nil>");
                } else {
                    self.bad_verb(None, verb);
                }
            }
            Kind::Bool => self.fmt_bool(f, f.as_bool(), verb),
            k if k.is_int() => self.fmt_int(f, f.as_int() as u64, true, verb),
            k if k.is_uint() => self.fmt_int(f, f.as_uint(), false, verb),
            Kind::Float32 => self.fmt_float(f, f.as_float(), 32, verb),
            Kind::Float64 => self.fmt_float(f, f.as_float(), 64, verb),
            Kind::Complex64 => {
                let (re, im) = f.as_complex();
                self.fmt_complex(f, re, im, 64, verb);
            }
            Kind::Complex128 => {
                let (re, im) = f.as_complex();
                self.fmt_complex(f, re, im, 128, verb);
            }
            Kind::String => {
                let s = f.as_string();
                self.fmt_string(f, &s, verb);
            }
            Kind::Map => {
                if self.f.sharp_v {
                    self.buf
                        .push_str(&f.ty.as_ref().expect("valid").type_string());
                    if f.is_nil() {
                        self.buf.push_str("(nil)");
                        return;
                    }
                    self.buf.push('{');
                } else {
                    self.buf.push_str("map[");
                }
                for (i, (k, v)) in f.map_entries().into_iter().enumerate() {
                    if i > 0 {
                        if self.f.sharp_v {
                            self.buf.push_str(", ");
                        } else {
                            self.buf.push(' ');
                        }
                    }
                    self.print_value(&k, verb, depth + 1);
                    self.buf.push(':');
                    self.print_value(&v, verb, depth + 1);
                }
                self.buf.push(if self.f.sharp_v { '}' } else { ']' });
            }
            Kind::Struct => {
                let ty = f.ty.clone().expect("valid");
                if self.f.sharp_v {
                    self.buf.push_str(&ty.type_string());
                }
                self.buf.push('{');
                let fields = ty.fields();
                for (i, fd) in fields.iter().enumerate() {
                    if i > 0 {
                        if self.f.sharp_v {
                            self.buf.push_str(", ");
                        } else {
                            self.buf.push(' ');
                        }
                    }
                    if (self.f.plus_v || self.f.sharp_v) && !fd.name.is_empty() {
                        self.buf.push_str(&fd.name);
                        self.buf.push(':');
                    }
                    let mut fv = f.field(i);
                    if fv.kind() == Kind::Interface && !fv.is_nil() {
                        fv = fv.elem();
                    }
                    self.print_value(&fv, verb, depth + 1);
                }
                self.buf.push('}');
            }
            Kind::Interface => {
                let inner = f.elem();
                if !inner.is_valid() {
                    if self.f.sharp_v {
                        self.buf
                            .push_str(&f.ty.as_ref().expect("valid").type_string());
                        self.buf.push_str("(nil)");
                    } else {
                        self.buf.push_str("<nil>");
                    }
                } else {
                    self.print_value(&inner, verb, depth + 1);
                }
            }
            Kind::Array | Kind::Slice => {
                let ty = f.ty.clone().expect("valid");
                if matches!(verb, 's' | 'q' | 'x' | 'X')
                    && ty.elem().map(|e| e.kind()) == Some(Kind::Uint8)
                {
                    let bytes: Vec<u8> = f.items().iter().map(|b| b.as_uint() as u8).collect();
                    let is_nil = f.kind() == Kind::Slice && f.is_nil();
                    self.fmt_bytes(f, &bytes, verb, &ty.type_string(), is_nil);
                    return;
                }
                if self.f.sharp_v {
                    self.buf.push_str(&ty.type_string());
                    if f.kind() == Kind::Slice && f.is_nil() {
                        self.buf.push_str("(nil)");
                        return;
                    }
                    self.buf.push('{');
                    for i in 0..f.len() {
                        if i > 0 {
                            self.buf.push_str(", ");
                        }
                        self.print_value(&f.index(i), verb, depth + 1);
                    }
                    self.buf.push('}');
                } else {
                    self.buf.push('[');
                    for i in 0..f.len() {
                        if i > 0 {
                            self.buf.push(' ');
                        }
                        self.print_value(&f.index(i), verb, depth + 1);
                    }
                    self.buf.push(']');
                }
            }
            Kind::Pointer => {
                if depth == 0 && !f.is_nil() {
                    let a = f.elem();
                    if matches!(
                        a.kind(),
                        Kind::Array | Kind::Slice | Kind::Struct | Kind::Map
                    ) {
                        self.buf.push('&');
                        self.print_value(&a, verb, depth + 1);
                        return;
                    }
                }
                self.fmt_pointer(f, verb);
            }
            Kind::Chan | Kind::Func | Kind::UnsafePointer => self.fmt_pointer(f, verb),
            _ => {
                self.buf.push('?');
                self.buf
                    .push_str(&f.ty.as_ref().map(Type::type_string).unwrap_or_default());
                self.buf.push('?');
            }
        }
    }

    fn arg_number(
        &mut self,
        arg_num: usize,
        format: &[u8],
        i: usize,
        num_args: usize,
    ) -> (usize, usize, bool) {
        if format.len() <= i || format[i] != b'[' {
            return (arg_num, i, false);
        }
        self.reordered = true;
        let (index, wid, ok) = parse_arg_number(&format[i..]);
        if ok && index < num_args {
            return (index, i + wid, true);
        }
        self.good_arg_num = false;
        (arg_num, i + wid, ok)
    }

    fn do_printf(&mut self, format_str: &str, a: &[Value]) {
        let format = format_str.as_bytes();
        let end = format.len();
        let mut arg_num = 0usize;
        let mut after_index;
        self.reordered = false;
        let mut i = 0;
        'format_loop: while i < end {
            self.good_arg_num = true;
            let lasti = i;
            while i < end && format[i] != b'%' {
                i += 1;
            }
            if i > lasti {
                self.buf.push_str(&format_str[lasti..i]);
            }
            if i >= end {
                break;
            }
            i += 1; // Process one verb

            self.clearflags();
            // Do we have flags?
            'simple: while i < end {
                let c = format[i];
                match c {
                    b'#' => self.f.sharp = true,
                    b'0' => self.f.zero = true,
                    b'+' => self.f.plus = true,
                    b'-' => self.f.minus = true,
                    b' ' => self.f.space = true,
                    _ => {
                        // Fast path for common case of ascii lower case simple verbs
                        // without precision or width or argument indices.
                        if c.is_ascii_lowercase() && arg_num < a.len() {
                            if c == b'v' || c == b'w' {
                                self.f.sharp_v = self.f.sharp;
                                self.f.sharp = false;
                                self.f.plus_v = self.f.plus;
                                self.f.plus = false;
                            }
                            self.print_arg(&a[arg_num], c as char);
                            arg_num += 1;
                            i += 1;
                            continue 'format_loop;
                        }
                        // Format is more complex than simple flags and a verb or is malformed.
                        break 'simple;
                    }
                }
                i += 1;
            }

            // Do we have an explicit argument index?
            let (an, ni, ai) = self.arg_number(arg_num, format, i, a.len());
            arg_num = an;
            i = ni;
            after_index = ai;

            // Do we have width?
            if i < end && format[i] == b'*' {
                i += 1;
                let (w, present, na) = Self::wid_from_arg(a, arg_num);
                arg_num = na;
                self.f.wid_present = present;
                self.wid = w.unsigned_abs() as usize;
                if !present {
                    self.buf.push_str("%!(BADWIDTH)");
                }
                if present && w < 0 {
                    self.f.minus = true;
                    self.f.zero = false; // Do not pad with zeros to the right.
                }
                after_index = false;
            } else {
                let (w, present, ni) = parsenum(format, i, end);
                self.wid = w;
                self.f.wid_present = present;
                i = ni;
                if after_index && self.f.wid_present {
                    // "%[3]2d"
                    self.good_arg_num = false;
                }
            }

            // Do we have precision?
            if i + 1 < end && format[i] == b'.' {
                i += 1;
                if after_index {
                    // "%[3].2d"
                    self.good_arg_num = false;
                }
                let (an, ni, ai) = self.arg_number(arg_num, format, i, a.len());
                arg_num = an;
                i = ni;
                after_index = ai;
                if i < end && format[i] == b'*' {
                    i += 1;
                    let (p, present, na) = Self::wid_from_arg(a, arg_num);
                    arg_num = na;
                    self.f.prec_present = present;
                    self.prec = if p < 0 { 0 } else { p as usize };
                    if p < 0 {
                        self.prec = 0;
                        self.f.prec_present = false;
                    }
                    if !self.f.prec_present {
                        self.buf.push_str("%!(BADPREC)");
                    }
                    after_index = false;
                } else {
                    let (p, present, ni) = parsenum(format, i, end);
                    self.prec = p;
                    self.f.prec_present = present;
                    i = ni;
                    if !self.f.prec_present {
                        self.prec = 0;
                        self.f.prec_present = true;
                    }
                }
            }

            if !after_index {
                let (an, ni, _) = self.arg_number(arg_num, format, i, a.len());
                arg_num = an;
                i = ni;
            }

            if i >= end {
                self.buf.push_str("%!(NOVERB)");
                break;
            }

            let verb = format_str[i..].chars().next().expect("in range");
            i += verb.len_utf8();

            if verb == '%' {
                // Percent does not absorb operands and ignores f.wid and f.prec.
                self.buf.push('%');
            } else if !self.good_arg_num {
                self.buf.push_str("%!");
                self.buf.push(verb);
                self.buf.push_str("(BADINDEX)");
            } else if arg_num >= a.len() {
                // No argument left over to print for the current verb.
                self.buf.push_str("%!");
                self.buf.push(verb);
                self.buf.push_str("(MISSING)");
            } else {
                if verb == 'v' || verb == 'w' {
                    // Go fmt: %w is only valid in Errorf; here it reports a bad verb.
                    self.f.sharp_v = self.f.sharp;
                    self.f.sharp = false;
                    self.f.plus_v = self.f.plus;
                    self.f.plus = false;
                }
                self.print_arg(&a[arg_num], verb);
                arg_num += 1;
            }
        }

        // Check for extra arguments unless the call accessed the arguments
        // out of order, in which case it's too expensive to detect if they've
        // all been used and arguably OK if they're not.
        if !self.reordered && arg_num < a.len() {
            self.clearflags();
            self.buf.push_str("%!(EXTRA ");
            for (i, arg) in a[arg_num..].iter().enumerate() {
                if i > 0 {
                    self.buf.push_str(", ");
                }
                let arg = arg.interface();
                if !arg.is_valid() {
                    self.buf.push_str("<nil>");
                } else {
                    self.buf
                        .push_str(&arg.ty.as_ref().expect("valid").type_string());
                    self.buf.push('=');
                    self.print_arg(&arg, 'v');
                }
            }
            self.buf.push(')');
        }
    }

    /// An `int` argument for `*` width or precision: (value, present, next).
    fn wid_from_arg(a: &[Value], arg_num: usize) -> (i64, bool, usize) {
        if arg_num >= a.len() {
            return (0, false, arg_num);
        }
        let v = a[arg_num].interface();
        let mut num: i64 = 0;
        let mut is_int = false;
        if v.kind().is_int() {
            num = v.as_int();
            is_int = true;
        } else if v.kind().is_uint() {
            let n = v.as_uint();
            if (n as i64) >= 0 {
                num = n as i64;
                is_int = true;
            }
        }
        if !(-1_000_000..=1_000_000).contains(&num) {
            num = 0;
            is_int = false;
        }
        (num, is_int, arg_num + 1)
    }

    fn do_print(&mut self, a: &[Value]) {
        let mut prev_string = false;
        for (arg_num, arg) in a.iter().enumerate() {
            let arg = arg.interface();
            let is_string = arg.is_valid() && arg.kind() == Kind::String;
            // Add a space between two non-string arguments.
            if arg_num > 0 && !is_string && !prev_string {
                self.buf.push(' ');
            }
            self.print_arg(&arg, 'v');
            prev_string = is_string;
        }
    }

    fn do_println(&mut self, a: &[Value]) {
        for (arg_num, arg) in a.iter().enumerate() {
            if arg_num > 0 {
                self.buf.push(' ');
            }
            self.print_arg(arg, 'v');
        }
        self.buf.push('\n');
    }
}

fn parse_arg_number(format: &[u8]) -> (usize, usize, bool) {
    // There must be at least 3 bytes: [n].
    if format.len() < 3 {
        return (0, 1, false);
    }
    // Find closing bracket.
    for i in 1..format.len() {
        if format[i] == b']' {
            let (width, ok, newi) = parsenum(format, 1, i);
            if !ok || newi != i {
                return (0, i + 1, false);
            }
            // arg numbers are one-indexed and skip paren.
            return (width.wrapping_sub(1), i + 1, true);
        }
    }
    (0, 1, false)
}
