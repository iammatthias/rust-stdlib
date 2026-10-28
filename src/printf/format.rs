//! The raw formatter behind the verbs (Go `fmt/format.go`): padding,
//! integers, floats, strings and quoting.

use crate::strconv;
use crate::unicode::rune::{append_rune, decode_rune, rune_count, MAX_RUNE, RUNE_ERROR, UTF_MAX};

pub(crate) const LDIGITS: &[u8; 17] = b"0123456789abcdefx";
pub(crate) const UDIGITS: &[u8; 17] = b"0123456789ABCDEFX";

/// The printer: output buffer, flag state and verb bookkeeping (Go `pp`).
#[derive(Default)]
pub(crate) struct Pp {
    pub buf: Vec<u8>,
    pub wid_present: bool,
    pub prec_present: bool,
    pub minus: bool,
    pub plus: bool,
    pub sharp: bool,
    pub space: bool,
    pub zero: bool,
    pub plus_v: bool,
    pub sharp_v: bool,
    pub wid: i64,
    pub prec: i64,
    pub reordered: bool,
    pub good_arg_num: bool,
    pub panicking: bool,
    pub erroring: bool,
    pub wrap_errs: bool,
    pub wrapped_errs: Vec<usize>,
}

/// The saved flag state (Go `fmtFlags`).
#[derive(Clone, Copy)]
pub(crate) struct Flags {
    wid_present: bool,
    prec_present: bool,
    minus: bool,
    plus: bool,
    sharp: bool,
    space: bool,
    zero: bool,
    plus_v: bool,
    sharp_v: bool,
    wid: i64,
    prec: i64,
}

impl Pp {
    pub fn clear_flags(&mut self) {
        self.wid_present = false;
        self.prec_present = false;
        self.minus = false;
        self.plus = false;
        self.sharp = false;
        self.space = false;
        self.zero = false;
        self.plus_v = false;
        self.sharp_v = false;
        self.wid = 0;
        self.prec = 0;
    }

    pub fn save_flags(&self) -> Flags {
        Flags {
            wid_present: self.wid_present,
            prec_present: self.prec_present,
            minus: self.minus,
            plus: self.plus,
            sharp: self.sharp,
            space: self.space,
            zero: self.zero,
            plus_v: self.plus_v,
            sharp_v: self.sharp_v,
            wid: self.wid,
            prec: self.prec,
        }
    }

    pub fn restore_flags(&mut self, f: Flags) {
        self.wid_present = f.wid_present;
        self.prec_present = f.prec_present;
        self.minus = f.minus;
        self.plus = f.plus;
        self.sharp = f.sharp;
        self.space = f.space;
        self.zero = f.zero;
        self.plus_v = f.plus_v;
        self.sharp_v = f.sharp_v;
        self.wid = f.wid;
        self.prec = f.prec;
    }

    /// Generates n bytes of padding.
    pub fn write_padding(&mut self, n: i64) {
        if n <= 0 {
            return;
        }
        // Zero padding is allowed only to the left.
        let pad = if self.zero && !self.minus { b'0' } else { b' ' };
        let new_len = self.buf.len() + n as usize;
        self.buf.resize(new_len, pad);
    }

    /// Appends b, padded on the left (!minus) or right (minus).
    pub fn pad(&mut self, b: &[u8]) {
        if !self.wid_present || self.wid == 0 {
            self.buf.extend_from_slice(b);
            return;
        }
        let width = self.wid - rune_count(b) as i64;
        if !self.minus {
            self.write_padding(width);
            self.buf.extend_from_slice(b);
        } else {
            self.buf.extend_from_slice(b);
            self.write_padding(width);
        }
    }

    pub fn fmt_boolean(&mut self, v: bool) {
        self.pad(if v { b"true" } else { b"false" });
    }

    /// Formats a uint64 as "U+0078" or, with sharp set, "U+0078 'x'".
    pub fn fmt_unicode(&mut self, mut u: u64) {
        let mut prec: i64 = 4;
        if self.prec_present && self.prec > 4 {
            prec = self.prec;
        }
        let size = (2 + prec + 2 + UTF_MAX as i64 + 1).max(68) as usize;
        let mut buf = vec![0u8; size];
        let mut i = buf.len();
        if self.sharp && u <= MAX_RUNE as u64 && strconv::is_print(u as i32) {
            i -= 1;
            buf[i] = b'\'';
            let mut tmp = Vec::new();
            append_rune(&mut tmp, u as i32);
            i -= tmp.len();
            buf[i..i + tmp.len()].copy_from_slice(&tmp);
            i -= 1;
            buf[i] = b'\'';
            i -= 1;
            buf[i] = b' ';
        }
        while u >= 16 {
            i -= 1;
            buf[i] = UDIGITS[(u & 0xF) as usize];
            prec -= 1;
            u >>= 4;
        }
        i -= 1;
        buf[i] = UDIGITS[u as usize];
        prec -= 1;
        while prec > 0 {
            i -= 1;
            buf[i] = b'0';
            prec -= 1;
        }
        i -= 1;
        buf[i] = b'+';
        i -= 1;
        buf[i] = b'U';
        let old_zero = self.zero;
        self.zero = false;
        self.pad(&buf[i..]);
        self.zero = old_zero;
    }

    /// Formats signed and unsigned integers.
    pub fn fmt_integer(
        &mut self,
        mut u: u64,
        base: u32,
        is_signed: bool,
        verb: char,
        digits: &[u8; 17],
    ) {
        let negative = is_signed && (u as i64) < 0;
        if negative {
            u = u.wrapping_neg();
        }
        let mut size = 68usize;
        if self.wid_present || self.prec_present {
            size = size.max((3 + self.wid + self.prec) as usize);
        }
        let mut buf = vec![0u8; size];

        // Two ways to ask for extra leading zero digits: %.3d or %03d.
        // If both are specified the zero flag is ignored.
        let mut prec: i64 = 0;
        if self.prec_present {
            prec = self.prec;
            // Precision of 0 and value of 0 means "print nothing" but padding.
            if prec == 0 && u == 0 {
                let old_zero = self.zero;
                self.zero = false;
                self.write_padding(self.wid);
                self.zero = old_zero;
                return;
            }
        } else if self.zero && !self.minus && self.wid_present {
            prec = self.wid;
            if negative || self.plus || self.space {
                prec -= 1; // leave room for sign
            }
        }

        let mut i = buf.len();
        match base {
            10 => {
                while u >= 10 {
                    i -= 1;
                    let next = u / 10;
                    buf[i] = b'0' + (u - next * 10) as u8;
                    u = next;
                }
            }
            16 => {
                while u >= 16 {
                    i -= 1;
                    buf[i] = digits[(u & 0xF) as usize];
                    u >>= 4;
                }
            }
            8 => {
                while u >= 8 {
                    i -= 1;
                    buf[i] = b'0' + (u & 7) as u8;
                    u >>= 3;
                }
            }
            2 => {
                while u >= 2 {
                    i -= 1;
                    buf[i] = b'0' + (u & 1) as u8;
                    u >>= 1;
                }
            }
            _ => unreachable!("fmt: unknown base"),
        }
        i -= 1;
        buf[i] = digits[u as usize];
        while i > 0 && prec > (buf.len() - i) as i64 {
            i -= 1;
            buf[i] = b'0';
        }

        // Various prefixes: 0x, -, etc.
        if self.sharp {
            match base {
                2 => {
                    i -= 1;
                    buf[i] = b'b';
                    i -= 1;
                    buf[i] = b'0';
                }
                8 => {
                    if buf[i] != b'0' {
                        i -= 1;
                        buf[i] = b'0';
                    }
                }
                16 => {
                    i -= 1;
                    buf[i] = digits[16];
                    i -= 1;
                    buf[i] = b'0';
                }
                _ => {}
            }
        }
        if verb == 'O' {
            i -= 1;
            buf[i] = b'o';
            i -= 1;
            buf[i] = b'0';
        }
        if negative {
            i -= 1;
            buf[i] = b'-';
        } else if self.plus {
            i -= 1;
            buf[i] = b'+';
        } else if self.space {
            i -= 1;
            buf[i] = b' ';
        }

        // Left padding with zeros has already been handled like precision
        // or the zero flag is ignored due to an explicitly set precision.
        let old_zero = self.zero;
        self.zero = false;
        self.pad(&buf[i..]);
        self.zero = old_zero;
    }

    /// Truncates s to the specified precision (in runes), if present.
    pub fn truncate<'a>(&self, b: &'a [u8]) -> &'a [u8] {
        if self.prec_present {
            let mut n = self.prec;
            let mut i = 0;
            while i < b.len() {
                n -= 1;
                if n < 0 {
                    return &b[..i];
                }
                let (_, wid) = decode_rune(&b[i..]);
                i += wid;
            }
        }
        b
    }

    pub fn fmt_s(&mut self, s: &[u8]) {
        let s = self.truncate(s);
        self.pad(s);
    }

    /// Formats a string or byte slice as a hexadecimal encoding of its bytes.
    pub fn fmt_sbx(&mut self, s: &[u8], digits: &[u8; 17]) {
        let mut length = s.len() as i64;
        // Set length to not process more bytes than the precision demands.
        if self.prec_present && self.prec < length {
            length = self.prec;
        }
        let mut width = 2 * length;
        if width > 0 {
            if self.space {
                // Each element encoded by two hexadecimals gets a leading 0x or 0X.
                if self.sharp {
                    width *= 2;
                }
                // Elements are separated by a space.
                width += length - 1;
            } else if self.sharp {
                // Only a leading 0x or 0X for the whole string.
                width += 2;
            }
        } else {
            // The byte slice or string that should be encoded is empty.
            if self.wid_present {
                self.write_padding(self.wid);
            }
            return;
        }
        // Handle padding to the left.
        if self.wid_present && self.wid > width && !self.minus {
            self.write_padding(self.wid - width);
        }
        if self.sharp {
            self.buf.extend_from_slice(&[b'0', digits[16]]);
        }
        for (i, &c) in s.iter().enumerate().take(length as usize) {
            if self.space && i > 0 {
                self.buf.push(b' ');
                if self.sharp {
                    self.buf.extend_from_slice(&[b'0', digits[16]]);
                }
            }
            self.buf.push(digits[(c >> 4) as usize]);
            self.buf.push(digits[(c & 0xF) as usize]);
        }
        // Handle padding to the right.
        if self.wid_present && self.wid > width && self.minus {
            self.write_padding(self.wid - width);
        }
    }

    /// Formats a string as a double-quoted, escaped Go string constant. With
    /// sharp set a raw (backquoted) string may be returned instead.
    pub fn fmt_q(&mut self, s: &[u8]) {
        let s = self.truncate(s);
        if self.sharp && strconv::can_backquote(s) {
            let mut v = Vec::with_capacity(s.len() + 2);
            v.push(b'`');
            v.extend_from_slice(s);
            v.push(b'`');
            self.pad(&v);
            return;
        }
        let mut v = Vec::new();
        if self.plus {
            strconv::append_quote_to_ascii(&mut v, s);
        } else {
            strconv::append_quote(&mut v, s);
        }
        self.pad(&v);
    }

    /// Formats an integer as a Unicode character; invalid ones print U+FFFD.
    pub fn fmt_c(&mut self, c: u64) {
        let mut r = c as i32;
        if c > MAX_RUNE as u64 {
            r = RUNE_ERROR;
        }
        let mut v = Vec::new();
        append_rune(&mut v, r);
        self.pad(&v);
    }

    /// Formats an integer as a single-quoted, escaped Go character constant.
    pub fn fmt_qc(&mut self, c: u64) {
        let mut r = c as i32;
        if c > MAX_RUNE as u64 {
            r = RUNE_ERROR;
        }
        let mut v = Vec::new();
        if self.plus {
            strconv::append_quote_rune_to_ascii(&mut v, r);
        } else {
            strconv::append_quote_rune(&mut v, r);
        }
        self.pad(&v);
    }

    /// Formats a float64; verb is a valid strconv format byte.
    pub fn fmt_float_raw(&mut self, v: f64, size: i32, verb: char, mut prec: i32) {
        // Explicit precision in format specifier overrules default precision.
        if self.prec_present {
            prec = self.prec as i32;
        }
        // Format number, reserving space for leading + sign if needed.
        let mut num = vec![0u8];
        strconv::append_float(&mut num, v, verb as u8, prec, size);
        let mut start = 0usize; // num[start..] is the signed number
        if num[1] == b'-' || num[1] == b'+' {
            start = 1;
        } else {
            num[0] = b'+';
        }
        // space means to add a leading space instead of a "+" sign unless
        // the sign is explicitly asked for by plus.
        if self.space && num[start] == b'+' && !self.plus {
            num[start] = b' ';
        }
        // Infinities and NaN don't look like a number so are not zero padded.
        if num[start + 1] == b'I' || num[start + 1] == b'N' {
            let old_zero = self.zero;
            self.zero = false;
            // Remove sign before NaN if not asked for.
            if num[start + 1] == b'N' && !self.space && !self.plus {
                start += 1;
            }
            let n = num.split_off(start);
            self.pad(&n);
            self.zero = old_zero;
            return;
        }
        let mut num: Vec<u8> = num.split_off(start);
        // The sharp flag forces printing a decimal point for non-binary
        // formats and retains trailing zeros, which we may need to restore.
        if self.sharp && verb != 'b' {
            let mut digits: i32 = 0;
            if matches!(verb, 'v' | 'g' | 'G' | 'x') {
                digits = prec;
                // If no precision is set explicitly use a precision of 6.
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
                    c @ (b'e' | b'E') if verb != 'x' && verb != 'X' => {
                        let _ = c;
                        tail.extend_from_slice(&num[i..]);
                        num.truncate(i);
                    }
                    c => {
                        if c != b'0' {
                            saw_nonzero_digit = true;
                        }
                        // Count significant digits after the first non-zero digit.
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
        if self.plus || num[0] != b'+' {
            // If we're zero padding to the left we want the sign before the
            // leading zeros.
            if self.zero && !self.minus && self.wid_present && self.wid > num.len() as i64 {
                self.buf.push(num[0]);
                self.write_padding(self.wid - num.len() as i64);
                self.buf.extend_from_slice(&num[1..]);
                return;
            }
            self.pad(&num);
            return;
        }
        // No sign to show and the number is positive; just print it unsigned.
        self.pad(&num[1..]);
    }
}
