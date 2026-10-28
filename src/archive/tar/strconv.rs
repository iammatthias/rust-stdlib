//! Field encoding for tar header blocks: octal and base-256 numbers, NUL
//! padded strings and PAX records. Follows the rules of Go's
//! `archive/tar/strconv.go`.
use super::Error;
use crate::archive::iofs::{time_parts, time_representable, time_unix};
use std::time::SystemTime;

pub(super) fn has_nul(s: &str) -> bool {
    s.as_bytes().contains(&0)
}

pub(super) fn is_ascii(s: &str) -> bool {
    s.bytes().all(|c| c < 0x80 && c != 0)
}

pub(super) fn to_ascii(s: &str) -> String {
    if is_ascii(s) {
        return s.to_string();
    }
    s.chars()
        .filter(|&c| (c as u32) < 0x80 && c != '\0')
        .collect()
}

/// Records the last error seen while parsing header fields.
#[derive(Default)]
pub(super) struct Parser {
    pub(super) err: Option<Error>,
}

impl Parser {
    /// The bytes before the first NUL (Go's `parseString`): Go strings hold
    /// arbitrary bytes.
    pub(super) fn string(&mut self, b: &[u8]) -> Vec<u8> {
        let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
        b[..end].to_vec()
    }

    pub(super) fn numeric(&mut self, b: &[u8]) -> i64 {
        if !b.is_empty() && b[0] & 0x80 != 0 {
            let inv: u8 = if b[0] & 0x40 != 0 { 0xff } else { 0 };
            let mut x: u64 = 0;
            for (i, &c) in b.iter().enumerate() {
                let mut c = c ^ inv;
                if i == 0 {
                    c &= 0x7f;
                }
                if x >> 56 > 0 {
                    self.err = Some(Error::Header);
                    return 0;
                }
                x = x << 8 | u64::from(c);
            }
            if x >> 63 > 0 {
                self.err = Some(Error::Header);
                return 0;
            }
            return if inv == 0xff { !(x as i64) } else { x as i64 };
        }
        self.octal(b)
    }

    pub(super) fn octal(&mut self, b: &[u8]) -> i64 {
        let Some(start) = b.iter().position(|&c| c != b' ' && c != 0) else {
            return 0;
        };
        let end = b.iter().rposition(|&c| c != b' ' && c != 0).unwrap() + 1;
        let b = &b[start..end];
        let digits = &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())];
        let mut x: u64 = 0;
        let mut ok = !digits.is_empty();
        for &c in digits {
            if !(b'0'..=b'7').contains(&c) {
                ok = false;
                break;
            }
            match x
                .checked_mul(8)
                .and_then(|v| v.checked_add(u64::from(c - b'0')))
            {
                Some(v) => x = v,
                None => {
                    ok = false;
                    break;
                }
            }
        }
        if !ok {
            self.err = Some(Error::Header);
        }
        x as i64
    }
}

/// Records the last error seen while formatting header fields.
#[derive(Default)]
pub(super) struct Formatter {
    pub(super) err: Option<Error>,
}

impl Formatter {
    pub(super) fn string(&mut self, b: &mut [u8], s: &str) {
        let s = s.as_bytes();
        if s.len() > b.len() {
            self.err = Some(Error::FieldTooLong);
        }
        let n = s.len().min(b.len());
        b[..n].copy_from_slice(&s[..n]);
        if s.len() < b.len() {
            b[s.len()] = 0;
        }
        // Some readers treat regular files with a trailing slash in the V7
        // path field as a directory. If the field was truncated, make sure
        // it does not end in a slash.
        if s.len() > b.len() && b[b.len() - 1] == b'/' {
            let mut n = b.len() - 1;
            while n > 0 && s[n - 1] == b'/' {
                n -= 1;
            }
            b[n] = 0;
        }
    }

    pub(super) fn numeric(&mut self, b: &mut [u8], x: i64) {
        if fits_in_octal(b.len(), x) {
            self.octal(b, x);
            return;
        }
        if fits_in_base256(b.len(), x) {
            let mut x = x;
            for i in (0..b.len()).rev() {
                b[i] = x as u8;
                x >>= 8;
            }
            b[0] |= 0x80;
            return;
        }
        self.octal(b, 0);
        self.err = Some(Error::FieldTooLong);
    }

    pub(super) fn octal(&mut self, b: &mut [u8], x: i64) {
        let x = if fits_in_octal(b.len(), x) {
            x
        } else {
            self.err = Some(Error::FieldTooLong);
            0
        };
        let mut s = format!("{x:o}");
        if b.len() > s.len() + 1 {
            s = "0".repeat(b.len() - s.len() - 1) + &s;
        }
        self.string(b, &s);
    }
}

pub(super) fn fits_in_base256(n: usize, x: i64) -> bool {
    let bits = (n as u32 - 1) * 8;
    n >= 9 || (x >= -(1i64 << bits) && x < (1i64 << bits))
}

pub(super) fn fits_in_octal(n: usize, x: i64) -> bool {
    let bits = (n as u32 - 1) * 3;
    x >= 0 && (n >= 22 || x < (1i64 << bits))
}

pub(super) fn parse_pax_time(s: &str) -> Result<SystemTime, Error> {
    let (ss, sn) = s.split_once('.').unwrap_or((s, ""));
    let secs: i64 = ss.parse().map_err(|_| Error::Header)?;
    if sn.is_empty() {
        return pax_unix(secs, 0);
    }
    let mut digits = [b'0'; 9];
    for (i, c) in sn.bytes().enumerate() {
        match c {
            b'0'..=b'9' => {
                if i < digits.len() {
                    digits[i] = c;
                }
            }
            _ => return Err(Error::Header),
        }
    }
    let nsecs: i64 = std::str::from_utf8(&digits).unwrap().parse().unwrap();
    if ss.starts_with('-') {
        return pax_unix(secs, -nsecs);
    }
    pax_unix(secs, nsecs)
}

fn pax_unix(secs: i64, nanos: i64) -> Result<SystemTime, Error> {
    if !time_representable(secs) {
        return Err(Error::Header);
    }
    Ok(time_unix(secs, nanos))
}

pub(super) fn format_pax_time(ts: &SystemTime) -> String {
    let (mut secs, nanos) = time_parts(ts);
    if nanos == 0 {
        return secs.to_string();
    }
    let mut nsecs = i64::from(nanos);
    let mut sign = "";
    if secs < 0 {
        sign = "-";
        secs = -(secs + 1);
        nsecs = -(nsecs - 1_000_000_000);
    }
    let s = format!("{sign}{secs}.{nsecs:09}");
    s.trim_end_matches('0').to_string()
}

/// A parsed PAX record: key, value and the unparsed remainder.
pub(super) type PaxRecord<'a> = (&'a [u8], &'a [u8], &'a [u8]);

/// Parse one `"%d %s=%s\n"` record, returning key, value and the remainder.
/// Works on bytes: Go's PAX records may hold bytes that are not UTF-8.
pub(super) fn parse_pax_record(s: &[u8]) -> Result<PaxRecord<'_>, Error> {
    let space = s.iter().position(|&c| c == b' ').ok_or(Error::Header)?;
    let (n_str, rest) = (&s[..space], &s[space + 1..]);
    let n: i64 = std::str::from_utf8(n_str)
        .ok()
        .and_then(|t| t.parse().ok())
        .ok_or(Error::Header)?;
    if n < 5 || n > s.len() as i64 {
        return Err(Error::Header);
    }
    let n = n - (n_str.len() as i64 + 1);
    if n <= 0 {
        return Err(Error::Header);
    }
    let n = n as usize;
    if rest.len() < n {
        return Err(Error::Header);
    }
    let (rec, nl, rem) = (&rest[..n - 1], rest[n - 1], &rest[n..]);
    if nl != b'\n' {
        return Err(Error::Header);
    }
    let eq = rec.iter().position(|&c| c == b'=').ok_or(Error::Header)?;
    let (k, v) = (&rec[..eq], &rec[eq + 1..]);
    if !valid_pax_record_bytes(k, v) {
        return Err(Error::Header);
    }
    Ok((k, v, rem))
}

fn valid_pax_record_bytes(k: &[u8], v: &[u8]) -> bool {
    if k.is_empty() || k.contains(&b'=') {
        return false;
    }
    match k {
        b"path" | b"linkpath" | b"uname" | b"gname" => !v.contains(&0),
        _ => !k.contains(&0),
    }
}

pub(super) fn format_pax_record(k: &str, v: &str) -> Result<String, Error> {
    if !valid_pax_record(k, v) {
        return Err(Error::Header);
    }
    let padding = 3; // ' ', '=' and '\n'
    let mut size = k.len() + v.len() + padding;
    size += size.to_string().len();
    let mut record = format!("{size} {k}={v}\n");
    if record.len() != size {
        size = record.len();
        record = format!("{size} {k}={v}\n");
    }
    Ok(record)
}

pub(super) fn valid_pax_record(k: &str, v: &str) -> bool {
    if k.is_empty() || k.contains('=') {
        return false;
    }
    match k {
        "path" | "linkpath" | "uname" | "gname" => !has_nul(v),
        _ => !has_nul(k),
    }
}
