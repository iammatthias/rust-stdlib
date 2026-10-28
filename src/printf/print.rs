//! The verb engine (Go `fmt/print.go`): `doPrintf`, `doPrint`, `printArg` and
//! `printValue` over [`Value`].

use std::cmp::Ordering;
use std::panic::{catch_unwind, AssertUnwindSafe};

use super::format::{Pp, LDIGITS, UDIGITS};
use super::value::{IntKind, Seq, UintKind, Value};
use super::State;
use crate::unicode;
use crate::unicode::rune::{append_rune, decode_rune};

const COMMA_SPACE: &[u8] = b", ";
const NIL_ANGLE: &[u8] = b"<nil>";
const NIL_PAREN: &[u8] = b"(nil)";
const PERCENT_BANG: &[u8] = b"%!";

/// The Go type string of an operand (`reflect.TypeOf(v).String()`).
pub(crate) fn type_string(v: &Value) -> String {
    match v {
        Value::Nil => "<nil>".into(),
        Value::NilIface(t) => t.clone(),
        Value::Bool(_) => "bool".into(),
        Value::Int(_, k) => match k {
            IntKind::Int => "int",
            IntKind::Int8 => "int8",
            IntKind::Int16 => "int16",
            IntKind::Int32 => "int32",
            IntKind::Int64 => "int64",
        }
        .into(),
        Value::Uint(_, k) => match k {
            UintKind::Uint => "uint",
            UintKind::Uint8 => "uint8",
            UintKind::Uint16 => "uint16",
            UintKind::Uint32 => "uint32",
            UintKind::Uint64 => "uint64",
            UintKind::Uintptr => "uintptr",
        }
        .into(),
        Value::Float32(_) => "float32".into(),
        Value::Float64(_) => "float64".into(),
        Value::Complex64(..) => "complex64".into(),
        Value::Complex128(..) => "complex128".into(),
        Value::String(_) => "string".into(),
        Value::Slice(s) => s.type_name.clone(),
        Value::Map(m) => m.type_name.clone(),
        Value::Struct(s) => s.type_name.clone(),
        Value::Pointer(p) => p.type_name.clone(),
        Value::Named(n) => n.type_name.clone(),
    }
}

/// Orders map keys as `internal/fmtsort` does.
fn compare(a: &Value, b: &Value) -> Ordering {
    let (a, b) = (a.underlying(), b.underlying());
    match (a, b) {
        (Value::Int(x, _), Value::Int(y, _)) => x.cmp(y),
        (Value::Uint(x, _), Value::Uint(y, _)) => x.cmp(y),
        (Value::String(x), Value::String(y)) => x.cmp(y),
        (Value::Bool(x), Value::Bool(y)) => x.cmp(y),
        (Value::Float32(x), Value::Float32(y)) => float_cmp(*x as f64, *y as f64),
        (Value::Float64(x), Value::Float64(y)) => float_cmp(*x, *y),
        (Value::Complex64(a1, b1), Value::Complex64(a2, b2)) => {
            float_cmp(*a1 as f64, *a2 as f64).then(float_cmp(*b1 as f64, *b2 as f64))
        }
        (Value::Complex128(a1, b1), Value::Complex128(a2, b2)) => {
            float_cmp(*a1, *a2).then(float_cmp(*b1, *b2))
        }
        (Value::Pointer(x), Value::Pointer(y)) => x.addr.cmp(&y.addr),
        (Value::Struct(x), Value::Struct(y)) => {
            for ((_, p), (_, q)) in x.fields.iter().zip(&y.fields) {
                let c = compare(p, q);
                if c != Ordering::Equal {
                    return c;
                }
            }
            Ordering::Equal
        }
        (Value::Slice(x), Value::Slice(y)) => {
            for (p, q) in x.items.iter().zip(&y.items) {
                let c = compare(p, q);
                if c != Ordering::Equal {
                    return c;
                }
            }
            x.items.len().cmp(&y.items.len())
        }
        (Value::Nil | Value::NilIface(_), Value::Nil | Value::NilIface(_)) => Ordering::Equal,
        (Value::Nil | Value::NilIface(_), _) => Ordering::Less,
        (_, Value::Nil | Value::NilIface(_)) => Ordering::Greater,
        _ => type_string(a).cmp(&type_string(b)),
    }
}

fn float_cmp(a: f64, b: f64) -> Ordering {
    match (a.is_nan(), b.is_nan()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        _ => a.partial_cmp(&b).unwrap_or(Ordering::Equal),
    }
}

fn is_exported(name: &str) -> bool {
    name.chars()
        .next()
        .is_some_and(|c| unicode::is_upper(c as i32))
}

fn too_large(x: i64) -> bool {
    !(-1_000_000..=1_000_000).contains(&x)
}

/// Converts ASCII to an integer; (0, false, end) when no number is present.
pub(crate) fn parsenum(s: &[u8], start: usize, end: usize) -> (i64, bool, usize) {
    if start >= end {
        return (0, false, end);
    }
    let mut num = 0i64;
    let mut isnum = false;
    let mut newi = start;
    while newi < end && s[newi].is_ascii_digit() {
        if too_large(num) {
            return (0, false, end); // Overflow; crazy long number most likely.
        }
        num = num * 10 + (s[newi] - b'0') as i64;
        isnum = true;
        newi += 1;
    }
    (num, isnum, newi)
}

fn panic_value(e: Box<dyn std::any::Any + Send>) -> Value {
    // `std::panic::panic_any(Value)` panics with any operand, as Go's panic(any).
    if let Some(v) = e.downcast_ref::<Value>() {
        v.clone()
    } else if let Some(s) = e.downcast_ref::<&str>() {
        Value::from(*s)
    } else if let Some(s) = e.downcast_ref::<String>() {
        Value::from(s.clone())
    } else {
        Value::from("panic")
    }
}

impl Pp {
    pub fn new() -> Pp {
        Pp::default()
    }

    fn write_rune(&mut self, r: char) {
        append_rune(&mut self.buf, r as i32);
    }

    fn unknown_type(&mut self, v: &Value) {
        self.buf.push(b'?');
        self.buf.extend_from_slice(type_string(v).as_bytes());
        self.buf.push(b'?');
    }

    fn bad_verb(&mut self, v: &Value, verb: char) {
        self.erroring = true;
        self.buf.extend_from_slice(PERCENT_BANG);
        self.write_rune(verb);
        self.buf.push(b'(');
        match v {
            Value::Nil => self.buf.extend_from_slice(NIL_ANGLE),
            _ => {
                self.buf.extend_from_slice(type_string(v).as_bytes());
                self.buf.push(b'=');
                self.print_value(v, 'v', 0, false);
            }
        }
        self.buf.push(b')');
        self.erroring = false;
    }

    fn fmt_bool(&mut self, v: &Value, b: bool, verb: char) {
        match verb {
            't' | 'v' => self.fmt_boolean(b),
            _ => self.bad_verb(v, verb),
        }
    }

    /// Formats a uint64 in hexadecimal and prefixes it with 0x or not, as
    /// requested, by temporarily setting the sharp flag.
    fn fmt_0x64(&mut self, v: u64, leading_0x: bool) {
        let sharp = self.sharp;
        self.sharp = leading_0x;
        self.fmt_integer(v, 16, false, 'v', LDIGITS);
        self.sharp = sharp;
    }

    fn fmt_int(&mut self, arg: &Value, v: u64, is_signed: bool, verb: char) {
        match verb {
            'v' => {
                if self.sharp_v && !is_signed {
                    self.fmt_0x64(v, true);
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
            _ => self.bad_verb(arg, verb),
        }
    }

    fn fmt_float(&mut self, arg: &Value, v: f64, size: i32, verb: char) {
        match verb {
            'v' => self.fmt_float_raw(v, size, 'g', -1),
            'b' | 'g' | 'G' | 'x' | 'X' => self.fmt_float_raw(v, size, verb, -1),
            'f' | 'e' | 'E' => self.fmt_float_raw(v, size, verb, 6),
            'F' => self.fmt_float_raw(v, size, 'f', 6),
            _ => self.bad_verb(arg, verb),
        }
    }

    fn fmt_complex(&mut self, arg: &Value, re: f64, im: f64, size: i32, verb: char) {
        match verb {
            'v' | 'b' | 'g' | 'G' | 'x' | 'X' | 'f' | 'F' | 'e' | 'E' => {
                let old_plus = self.plus;
                self.buf.push(b'(');
                self.fmt_float(arg, re, size / 2, verb);
                // Imaginary part always has a sign.
                self.plus = true;
                self.fmt_float(arg, im, size / 2, verb);
                self.buf.extend_from_slice(b"i)");
                self.plus = old_plus;
            }
            _ => self.bad_verb(arg, verb),
        }
    }

    fn fmt_string(&mut self, arg: &Value, v: &[u8], verb: char) {
        match verb {
            'v' => {
                if self.sharp_v {
                    self.fmt_q(v);
                } else {
                    self.fmt_s(v);
                }
            }
            's' => self.fmt_s(v),
            'x' => self.fmt_sbx(v, LDIGITS),
            'X' => self.fmt_sbx(v, UDIGITS),
            'q' => self.fmt_q(v),
            _ => self.bad_verb(arg, verb),
        }
    }

    fn fmt_bytes(&mut self, whole: &Value, seq: &Seq, verb: char, type_string: &str, ro: bool) {
        let bytes: Vec<u8> = seq
            .items
            .iter()
            .map(|v| match v.underlying() {
                Value::Uint(u, _) => *u as u8,
                _ => 0,
            })
            .collect();
        match verb {
            'v' | 'd' => {
                if self.sharp_v {
                    self.buf.extend_from_slice(type_string.as_bytes());
                    if seq.nil {
                        self.buf.extend_from_slice(NIL_PAREN);
                        return;
                    }
                    self.buf.push(b'{');
                    for (i, c) in bytes.iter().enumerate() {
                        if i > 0 {
                            self.buf.extend_from_slice(COMMA_SPACE);
                        }
                        self.fmt_0x64(*c as u64, true);
                    }
                    self.buf.push(b'}');
                } else {
                    self.buf.push(b'[');
                    for (i, c) in bytes.iter().enumerate() {
                        if i > 0 {
                            self.buf.push(b' ');
                        }
                        self.fmt_integer(*c as u64, 10, false, verb, LDIGITS);
                    }
                    self.buf.push(b']');
                }
            }
            's' => self.fmt_s(&bytes),
            'x' => self.fmt_sbx(&bytes, LDIGITS),
            'X' => self.fmt_sbx(&bytes, UDIGITS),
            'q' => self.fmt_q(&bytes),
            _ => self.print_value_generic(whole, verb, 0, ro),
        }
    }

    fn fmt_pointer(&mut self, whole: &Value, verb: char) {
        let u = match whole.underlying() {
            Value::Pointer(p) => p.addr,
            Value::Slice(s) if !s.array => s.addr,
            Value::Map(m) => m.addr,
            _ => {
                self.bad_verb(whole, verb);
                return;
            }
        };
        match verb {
            'v' => {
                if self.sharp_v {
                    self.buf.push(b'(');
                    self.buf.extend_from_slice(type_string(whole).as_bytes());
                    self.buf.extend_from_slice(b")(");
                    if u == 0 {
                        self.buf.extend_from_slice(b"nil");
                    } else {
                        self.fmt_0x64(u as u64, true);
                    }
                    self.buf.push(b')');
                } else if u == 0 {
                    self.pad(NIL_ANGLE);
                } else {
                    self.fmt_0x64(u as u64, !self.sharp);
                }
            }
            'p' => self.fmt_0x64(u as u64, !self.sharp),
            'b' | 'o' | 'd' | 'x' | 'X' => self.fmt_int(whole, u as u64, false, verb),
            _ => self.bad_verb(whole, verb),
        }
    }

    /// Runs a user method, turning a panic into Go's `%!v(PANIC=...)` text.
    fn catch<R>(
        &mut self,
        arg: &Value,
        verb: char,
        method: &str,
        f: impl FnOnce(&mut Pp) -> R,
    ) -> Option<R> {
        match catch_unwind(AssertUnwindSafe(|| f(&mut *self))) {
            Ok(r) => Some(r),
            Err(e) => {
                // A nil pointer receiver: just say "<nil>".
                if matches!(arg.underlying(), Value::Pointer(p) if p.addr == 0) {
                    self.buf.extend_from_slice(NIL_ANGLE);
                    return None;
                }
                if self.panicking {
                    // Nested panics; the recursion in printArg cannot succeed.
                    std::panic::resume_unwind(e);
                }
                let old = self.save_flags();
                self.clear_flags();
                self.buf.extend_from_slice(PERCENT_BANG);
                self.write_rune(verb);
                self.buf.extend_from_slice(b"(PANIC=");
                self.buf.extend_from_slice(method.as_bytes());
                self.buf.extend_from_slice(b" method: ");
                self.panicking = true;
                self.print_arg(&panic_value(e), 'v');
                self.panicking = false;
                self.buf.push(b')');
                self.restore_flags(old);
                None
            }
        }
    }

    fn handle_methods(&mut self, arg: &Value, mut verb: char) -> bool {
        if self.erroring {
            return false;
        }
        if verb == 'w' {
            // It is invalid to use %w other than with Errorf or with a non-error arg.
            if arg.as_error().is_none() || !self.wrap_errs {
                self.bad_verb(arg, verb);
                return true;
            }
            // If the arg is a Formatter, pass 'v' as the verb to it.
            verb = 'v';
        }
        let Some(m) = arg.methods() else {
            return false;
        };
        if let Some(fm) = m.formatter.clone() {
            self.catch(arg, verb, "Format", |p| {
                fm.format(p as &mut dyn State, verb)
            });
            return true;
        }
        // If we're doing Go syntax and the argument knows how to supply it, take care of it now.
        if self.sharp_v {
            if let Some(gs) = m.debug.clone() {
                if let Some(s) = self.catch(arg, verb, "GoString", |_| format!("{gs:?}")) {
                    self.fmt_s(s.as_bytes());
                }
                return true;
            }
        } else if matches!(verb, 'v' | 's' | 'x' | 'X' | 'q') {
            if let Some(e) = m.error.clone() {
                if let Some(s) = self.catch(arg, verb, "Error", |_| e.to_string()) {
                    self.fmt_string(arg, s.as_bytes(), verb);
                }
                return true;
            }
            if let Some(st) = m.display.clone() {
                if let Some(s) = self.catch(arg, verb, "String", |_| st.to_string()) {
                    self.fmt_string(arg, s.as_bytes(), verb);
                }
                return true;
            }
        }
        false
    }

    pub fn print_arg(&mut self, arg: &Value, verb: char) {
        if matches!(arg, Value::Nil) {
            match verb {
                'T' | 'v' => self.pad(NIL_ANGLE),
                _ => self.bad_verb(arg, verb),
            }
            return;
        }
        // %T (the value's type) and %p (its address) are special; we always do them first.
        match verb {
            'T' => {
                self.fmt_s(type_string(arg).as_bytes());
                return;
            }
            'p' => {
                self.fmt_pointer(arg, 'p');
                return;
            }
            _ => {}
        }
        if let Value::Slice(s) = arg {
            if s.type_name == "[]uint8" {
                self.fmt_bytes(arg, s, verb, "[]byte", false);
                return;
            }
        }
        // If the type is not simple, it might have methods.
        if !self.handle_methods(arg, verb) {
            self.print_value(arg, verb, 0, false);
        }
    }

    fn print_value(&mut self, value: &Value, verb: char, depth: usize, ro: bool) {
        // Handle values with special methods if not already handled by printArg (depth == 0).
        if depth > 0
            && !ro
            && (verb == 'w' || matches!(value, Value::Named(_)))
            && self.handle_methods(value, verb)
        {
            return;
        }
        self.print_value_generic(value, verb, depth, ro);
    }

    fn print_value_generic(&mut self, value: &Value, verb: char, depth: usize, ro: bool) {
        let f = value.underlying();
        match f {
            Value::Nil | Value::NilIface(_) => {
                if depth == 0 {
                    self.buf.extend_from_slice(b"<invalid reflect.Value>");
                } else if self.sharp_v {
                    let t = match f {
                        Value::NilIface(t) => t.as_str(),
                        _ => "interface {}",
                    };
                    self.buf.extend_from_slice(t.as_bytes());
                    self.buf.extend_from_slice(NIL_PAREN);
                } else {
                    self.buf.extend_from_slice(NIL_ANGLE);
                }
            }
            Value::Bool(b) => self.fmt_bool(value, *b, verb),
            Value::Int(i, _) => self.fmt_int(value, *i as u64, true, verb),
            Value::Uint(u, _) => self.fmt_int(value, *u, false, verb),
            Value::Float32(x) => self.fmt_float(value, *x as f64, 32, verb),
            Value::Float64(x) => self.fmt_float(value, *x, 64, verb),
            Value::Complex64(r, i) => self.fmt_complex(value, *r as f64, *i as f64, 64, verb),
            Value::Complex128(r, i) => self.fmt_complex(value, *r, *i, 128, verb),
            Value::String(s) => self.fmt_string(value, s, verb),
            Value::Map(m) => {
                if self.sharp_v {
                    self.buf.extend_from_slice(type_string(value).as_bytes());
                    if m.nil {
                        self.buf.extend_from_slice(NIL_PAREN);
                        return;
                    }
                    self.buf.push(b'{');
                } else {
                    self.buf.extend_from_slice(b"map[");
                }
                let mut sorted: Vec<&(Value, Value)> = m.entries.iter().collect();
                sorted.sort_by(|a, b| compare(&a.0, &b.0));
                for (i, (k, v)) in sorted.into_iter().enumerate() {
                    if i > 0 {
                        if self.sharp_v {
                            self.buf.extend_from_slice(COMMA_SPACE);
                        } else {
                            self.buf.push(b' ');
                        }
                    }
                    self.print_value(k, verb, depth + 1, ro);
                    self.buf.push(b':');
                    self.print_value(v, verb, depth + 1, ro);
                }
                self.buf.push(if self.sharp_v { b'}' } else { b']' });
            }
            Value::Struct(s) => {
                if self.sharp_v {
                    self.buf.extend_from_slice(type_string(value).as_bytes());
                }
                self.buf.push(b'{');
                for (i, (name, fv)) in s.fields.iter().enumerate() {
                    if i > 0 {
                        if self.sharp_v {
                            self.buf.extend_from_slice(COMMA_SPACE);
                        } else {
                            self.buf.push(b' ');
                        }
                    }
                    if (self.plus_v || self.sharp_v) && !name.is_empty() {
                        self.buf.extend_from_slice(name.as_bytes());
                        self.buf.push(b':');
                    }
                    let fro = ro || !is_exported(name);
                    self.print_value(fv, verb, depth + 1, fro);
                }
                self.buf.push(b'}');
            }
            Value::Slice(s) => {
                if matches!(verb, 's' | 'q' | 'x' | 'X') && s.bytes {
                    // Handle byte and uint8 slices and arrays special for the above verbs.
                    self.fmt_bytes(value, s, verb, &type_string(value), ro);
                    return;
                }
                if self.sharp_v {
                    self.buf.extend_from_slice(type_string(value).as_bytes());
                    if !s.array && s.nil {
                        self.buf.extend_from_slice(NIL_PAREN);
                        return;
                    }
                    self.buf.push(b'{');
                    for (i, v) in s.items.iter().enumerate() {
                        if i > 0 {
                            self.buf.extend_from_slice(COMMA_SPACE);
                        }
                        self.print_value(v, verb, depth + 1, ro);
                    }
                    self.buf.push(b'}');
                } else {
                    self.buf.push(b'[');
                    for (i, v) in s.items.iter().enumerate() {
                        if i > 0 {
                            self.buf.push(b' ');
                        }
                        self.print_value(v, verb, depth + 1, ro);
                    }
                    self.buf.push(b']');
                }
            }
            Value::Pointer(p) => {
                // pointer to array or slice or struct? ok at top level
                // but not embedded (avoid loops)
                if depth == 0 && p.addr != 0 {
                    if let Some(e) = &p.elem {
                        if matches!(
                            e.underlying(),
                            Value::Slice(_) | Value::Struct(_) | Value::Map(_)
                        ) {
                            self.buf.push(b'&');
                            self.print_value(e, verb, depth + 1, ro);
                            return;
                        }
                    }
                }
                self.fmt_pointer(value, verb);
            }
            Value::Named(_) => self.unknown_type(value),
        }
    }

    /// Gets the argNumth element of a as an int for `*` width or precision.
    fn int_from_arg(a: &[Value], arg_num: usize) -> (i64, bool, usize) {
        let mut new_arg_num = arg_num;
        let mut num = 0i64;
        let mut is_int = false;
        if arg_num < a.len() {
            match a[arg_num].underlying() {
                Value::Int(n, _) => {
                    num = *n;
                    is_int = true;
                }
                Value::Uint(n, _) if (*n as i64) >= 0 => {
                    num = *n as i64;
                    is_int = true;
                }
                _ => {}
            }
            new_arg_num = arg_num + 1;
            if too_large(num) {
                num = 0;
                is_int = false;
            }
        }
        (num, is_int, new_arg_num)
    }

    /// The value of the bracketed number, minus 1 (explicit argument numbers
    /// are one-indexed), the bytes to consume and whether it parsed.
    fn parse_arg_number(format: &[u8]) -> (i64, usize, bool) {
        // There must be at least 3 bytes: [n].
        if format.len() < 3 {
            return (0, 1, false);
        }
        for i in 1..format.len() {
            if format[i] == b']' {
                let (width, ok, newi) = parsenum(format, 1, i);
                if !ok || newi != i {
                    return (0, i + 1, false);
                }
                return (width - 1, i + 1, true);
            }
        }
        (0, 1, false)
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
        let (index, wid, ok) = Pp::parse_arg_number(&format[i..]);
        if ok && 0 <= index && (index as usize) < num_args {
            return (index as usize, i + wid, true);
        }
        self.good_arg_num = false;
        (arg_num, i + wid, ok)
    }

    fn bad_arg_num(&mut self, verb: char) {
        self.buf.extend_from_slice(PERCENT_BANG);
        self.write_rune(verb);
        self.buf.extend_from_slice(b"(BADINDEX)");
    }

    fn missing_arg(&mut self, verb: char) {
        self.buf.extend_from_slice(PERCENT_BANG);
        self.write_rune(verb);
        self.buf.extend_from_slice(b"(MISSING)");
    }

    pub fn do_printf(&mut self, format: &[u8], a: &[Value]) {
        let end = format.len();
        let mut arg_num = 0usize; // we process one argument per non-trivial format
        let mut after_index; // previous item in format was an index like [3].
        self.reordered = false;
        let mut i = 0usize;
        'format_loop: while i < end {
            self.good_arg_num = true;
            let lasti = i;
            while i < end && format[i] != b'%' {
                i += 1;
            }
            if i > lasti {
                self.buf.extend_from_slice(&format[lasti..i]);
            }
            if i >= end {
                break; // done processing format string
            }

            // Process one verb
            i += 1;

            // Do we have flags?
            self.clear_flags();
            while i < end {
                let c = format[i];
                match c {
                    b'#' => self.sharp = true,
                    b'0' => self.zero = true,
                    b'+' => self.plus = true,
                    b'-' => self.minus = true,
                    b' ' => self.space = true,
                    _ => {
                        // Fast path for common case of ascii lower case simple verbs
                        // without precision or width or argument indices.
                        if c.is_ascii_lowercase() && arg_num < a.len() {
                            match c {
                                b'w' | b'v' => {
                                    if c == b'w' {
                                        self.wrapped_errs.push(arg_num);
                                    }
                                    // Go syntax
                                    self.sharp_v = self.sharp;
                                    self.sharp = false;
                                    // Struct-field syntax
                                    self.plus_v = self.plus;
                                    self.plus = false;
                                }
                                _ => {}
                            }
                            self.print_arg(&a[arg_num], c as char);
                            arg_num += 1;
                            i += 1;
                            continue 'format_loop;
                        }
                        // Format is more complex than simple flags and a verb or is malformed.
                        break;
                    }
                }
                i += 1;
            }

            // Do we have an explicit argument index?
            (arg_num, i, after_index) = self.arg_number(arg_num, format, i, a.len());

            // Do we have width?
            if i < end && format[i] == b'*' {
                i += 1;
                (self.wid, self.wid_present, arg_num) = Pp::int_from_arg(a, arg_num);
                if !self.wid_present {
                    self.buf.extend_from_slice(b"%!(BADWIDTH)");
                }
                // We have a negative width, so take its value and ensure
                // that the minus flag is set
                if self.wid < 0 {
                    self.wid = -self.wid;
                    self.minus = true;
                    self.zero = false; // Do not pad with zeros to the right.
                }
                after_index = false;
            } else {
                (self.wid, self.wid_present, i) = parsenum(format, i, end);
                if after_index && self.wid_present {
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
                (arg_num, i, after_index) = self.arg_number(arg_num, format, i, a.len());
                if i < end && format[i] == b'*' {
                    i += 1;
                    (self.prec, self.prec_present, arg_num) = Pp::int_from_arg(a, arg_num);
                    // Negative precision arguments don't make sense
                    if self.prec < 0 {
                        self.prec = 0;
                        self.prec_present = false;
                    }
                    if !self.prec_present {
                        self.buf.extend_from_slice(b"%!(BADPREC)");
                    }
                    after_index = false;
                } else {
                    (self.prec, self.prec_present, i) = parsenum(format, i, end);
                    if !self.prec_present {
                        self.prec = 0;
                        self.prec_present = true;
                    }
                }
            }

            if !after_index {
                (arg_num, i, _) = self.arg_number(arg_num, format, i, a.len());
            }

            if i >= end {
                self.buf.extend_from_slice(b"%!(NOVERB)");
                break;
            }

            let (r, size) = decode_rune(&format[i..]);
            let verb = char::from_u32(r as u32).unwrap_or('\u{FFFD}');
            i += size;

            if verb == '%' {
                // Percent does not absorb operands and ignores wid and prec.
                self.buf.push(b'%');
            } else if !self.good_arg_num {
                self.bad_arg_num(verb);
            } else if arg_num >= a.len() {
                // No argument left over to print for the current verb.
                self.missing_arg(verb);
            } else {
                if verb == 'w' {
                    self.wrapped_errs.push(arg_num);
                }
                if verb == 'w' || verb == 'v' {
                    // Go syntax
                    self.sharp_v = self.sharp;
                    self.sharp = false;
                    // Struct-field syntax
                    self.plus_v = self.plus;
                    self.plus = false;
                }
                self.print_arg(&a[arg_num], verb);
                arg_num += 1;
            }
        }

        // Check for extra arguments unless the call accessed the arguments
        // out of order, in which case it's too expensive to detect if they've
        // all been used and arguably OK if they're not.
        if !self.reordered && arg_num < a.len() {
            self.clear_flags();
            self.buf.extend_from_slice(b"%!(EXTRA ");
            for (i, arg) in a[arg_num..].iter().enumerate() {
                if i > 0 {
                    self.buf.extend_from_slice(COMMA_SPACE);
                }
                if matches!(arg, Value::Nil) {
                    self.buf.extend_from_slice(NIL_ANGLE);
                } else {
                    self.buf.extend_from_slice(type_string(arg).as_bytes());
                    self.buf.push(b'=');
                    self.print_arg(arg, 'v');
                }
            }
            self.buf.push(b')');
        }
    }

    pub fn do_print(&mut self, a: &[Value]) {
        let mut prev_string = false;
        for (arg_num, arg) in a.iter().enumerate() {
            let is_string = matches!(arg.underlying(), Value::String(_));
            // Add a space between two non-string arguments.
            if arg_num > 0 && !is_string && !prev_string {
                self.buf.push(b' ');
            }
            self.print_arg(arg, 'v');
            prev_string = is_string;
        }
    }

    pub fn do_println(&mut self, a: &[Value]) {
        for (arg_num, arg) in a.iter().enumerate() {
            if arg_num > 0 {
                self.buf.push(b' ');
            }
            self.print_arg(arg, 'v');
        }
        self.buf.push(b'\n');
    }
}
