//! The arshalers of `time.Time` and `time.Duration`, ported from Go's
//! `arshal_time.go`.
//!
//! Go injects these into the arshaler of the two types rather than using
//! their methods, so `time.Time` is not written through `MarshalText` and
//! its errors carry no `Time.MarshalText:` prefix. A `Time` is an RFC 3339
//! string by default; a `Duration` has no default representation and needs
//! a `format` tag option (which needs [`experimental_support_format_tag`]).
//! The v1 compatibility flags `FormatDurationAsNano` and
//! `ParseTimeWithLooseRFC3339` have no option here.
//!
//! [`experimental_support_format_tag`]: super::experimental_support_format_tag
use super::arshal::{MarshalTo, UnmarshalFrom};
use super::errors::{
    err_invalid_string_tag, is_syntactic_error, marshal_error_before, unmarshal_error_after,
    unmarshal_error_before,
};
use super::scalars::{invalid_format_error_dec, invalid_format_error_enc};
use super::structs::is_letter_or_digit;
use super::typeinfo::{TypeInfo, TypeKind};
use crate::encoding::json::jsontext::flags;
use crate::encoding::json::jsontext::{
    wire, Decoder, Encoder, Error, Kind, Value, ValueFlags, KIND_NULL, KIND_NUMBER, KIND_STRING,
};
use crate::strconv;
use crate::time::{self, Duration, Time};

/// Go's `stringOrNumberKind`.
fn string_or_number_kind(stringify: bool) -> Kind {
    if stringify {
        KIND_STRING
    } else {
        KIND_NUMBER
    }
}

fn stringify_enc(enc: &Encoder<'_>, numeric: bool) -> bool {
    !numeric
        || enc.s.state.tokens.last.need_object_name()
        || enc
            .s
            .opts
            .flags
            .get(flags::STRINGIFY_NUMBERS | flags::STRING_TAG)
}

fn stringify_dec(dec: &Decoder<'_>, numeric: bool) -> bool {
    !numeric
        || dec.s.state.tokens.last.need_object_name()
        || dec
            .s
            .opts
            .flags
            .get(flags::STRINGIFY_NUMBERS | flags::STRING_TAG)
}

/// Reads one value for a time type and returns the text to parse: the
/// unquoted string when `stringify`, the number otherwise. `Ok(None)` is
/// JSON null.
fn read_time_value(
    dec: &mut Decoder<'_>,
    t: &TypeInfo,
    stringify: bool,
) -> Result<Option<Vec<u8>>, Error> {
    let mut vf = ValueFlags::default();
    let val = dec.s.read_value(&mut vf)?;
    match Value(val.clone()).kind() {
        KIND_NULL => Ok(None),
        KIND_STRING if stringify => Ok(Some(wire::unquote_may_copy(&val, vf.is_verbatim()))),
        KIND_NUMBER if !stringify => Ok(Some(val)),
        _ => Err(unmarshal_error_after(dec, Some(t.clone()), None)),
    }
}

/// Positions an error of writing a time value, unless it is a syntactic
/// or I/O error.
fn wrap_marshal_error(
    enc: &mut Encoder<'_>,
    t: TypeInfo,
    r: Result<(), Error>,
) -> Result<(), Error> {
    match r {
        Err(err) if !is_syntactic_error(&err) && !err.is_io_error() => {
            Err(marshal_error_before(enc, Some(t), Some(err)))
        }
        r => r,
    }
}

fn syntax_error(what: &str, b: &[u8]) -> Error {
    Error::msg(&format!(
        "{what} {}: {}",
        strconv::quote(b),
        strconv::ERR_SYNTAX
    ))
}

fn range_error(what: &str, b: &[u8]) -> Error {
    Error::msg(&format!(
        "{what} {}: {}",
        strconv::quote(b),
        strconv::ERR_RANGE
    ))
}

// --------------------------------------------------------------- Duration

/// How a `time.Duration` is written: the `format` tag option.
#[derive(Clone, Copy)]
enum DurationFormat {
    /// `units`: Go's `Duration.String`, such as `1h2m3s`.
    Units,
    /// `iso8601`: an ISO 8601 duration such as `PT1H2M3S`.
    Iso8601,
    /// `sec`, `milli`, `micro` or `nano`: a decimal number of the unit,
    /// which is this many nanoseconds.
    Base10(u64),
}

impl DurationFormat {
    fn parse(format: &str) -> Option<Self> {
        Some(match format {
            "units" => Self::Units,
            "sec" => Self::Base10(1_000_000_000),
            "milli" => Self::Base10(1_000_000),
            "micro" => Self::Base10(1_000),
            "nano" => Self::Base10(1),
            "iso8601" => Self::Iso8601,
            _ => return None,
        })
    }

    fn is_numeric(self) -> bool {
        matches!(self, Self::Base10(_))
    }

    fn append(self, b: &mut Vec<u8>, d: Duration) {
        match self {
            Self::Units => b.extend_from_slice(d.to_string().as_bytes()),
            Self::Iso8601 => append_duration_iso8601(b, d),
            Self::Base10(pow10) => append_duration_base10(b, d, pow10),
        }
    }

    fn parse_value(self, b: &[u8]) -> Result<Duration, Error> {
        match self {
            Self::Units => String::from_utf8_lossy(b)
                .parse::<Duration>()
                .map_err(Error::other),
            Self::Iso8601 => parse_duration_iso8601(b),
            Self::Base10(pow10) => parse_duration_base10(b, pow10),
        }
    }
}

/// The error of a `time.Duration` without a `format` tag option.
fn no_default_duration(format_tag_supported: bool) -> Error {
    let workaround = if format_tag_supported {
        "; specify an explicit format"
    } else {
        ""
    };
    Error::msg(&format!("no default representation{workaround}"))
}

fn duration_type() -> TypeInfo {
    TypeInfo::of::<Duration>("time.Duration", TypeKind::Int64)
}

impl MarshalTo for Duration {
    fn type_info() -> TypeInfo {
        duration_type()
    }

    fn marshal_default(&self, enc: &mut Encoder<'_>) -> Result<(), Error> {
        let t = duration_type();
        if !enc.s.opts.flags.has(flags::FORMAT_TAG) {
            let err = no_default_duration(enc.s.opts.flags.get(flags::FORMAT_TAG_SUPPORTED));
            return Err(marshal_error_before(enc, Some(t), Some(err)));
        }
        let Some(format) = DurationFormat::parse(&enc.s.opts.format) else {
            return Err(invalid_format_error_enc(enc, t));
        };
        if enc.s.opts.flags.get(flags::STRING_TAG) && !format.is_numeric() {
            return Err(marshal_error_before(
                enc,
                Some(t),
                Some(err_invalid_string_tag()),
            ));
        }
        let k = string_or_number_kind(stringify_enc(enc, format.is_numeric()));
        let d = *self;
        let r = enc.s.append_raw(k, true, |b| {
            format.append(b, d);
            Ok(())
        });
        wrap_marshal_error(enc, t, r)
    }

    fn is_zero_value(&self) -> bool {
        self.as_nanos() == 0
    }

    fn has_methods(&self) -> bool {
        true
    }
}

impl UnmarshalFrom for Duration {
    fn type_info() -> TypeInfo {
        duration_type()
    }

    fn zero() -> Self {
        Duration::default()
    }

    fn set_zero(&mut self) {
        *self = Duration::default();
    }

    fn unmarshal_default(&mut self, dec: &mut Decoder<'_>) -> Result<(), Error> {
        let t = duration_type();
        if !dec.s.opts.flags.has(flags::FORMAT_TAG) {
            let err = no_default_duration(dec.s.opts.flags.get(flags::FORMAT_TAG_SUPPORTED));
            return Err(unmarshal_error_before(dec, Some(t), Some(err)));
        }
        let Some(format) = DurationFormat::parse(&dec.s.opts.format) else {
            return Err(invalid_format_error_dec(dec, t));
        };
        if dec.s.opts.flags.get(flags::STRING_TAG) && !format.is_numeric() {
            return Err(unmarshal_error_before(
                dec,
                Some(t),
                Some(err_invalid_string_tag()),
            ));
        }
        let stringify = stringify_dec(dec, format.is_numeric());
        let Some(text) = read_time_value(dec, &t, stringify)? else {
            self.set_zero();
            return Ok(());
        };
        match format.parse_value(&text) {
            Ok(d) => {
                *self = d;
                Ok(())
            }
            Err(err) => Err(unmarshal_error_after(dec, Some(t), Some(err))),
        }
    }

    fn has_methods(&mut self) -> bool {
        true
    }
}

// ------------------------------------------------------------------- Time

/// How a `time.Time` is written: the `format` tag option.
#[derive(Clone)]
enum TimeFormat {
    /// `RFC3339` or `RFC3339Nano` (the default): checked RFC 3339.
    Rfc3339(&'static str),
    /// `unix`, `unixmilli`, `unixmicro` or `unixnano`: a decimal number of
    /// units since the Unix epoch, with this many units per second.
    Unix(u64),
    /// Any other layout, passed to `Time.Format` and `time.Parse`.
    Layout(String),
}

impl TimeFormat {
    fn parse(format: &str) -> Option<Self> {
        // An exported constant of package time starts with an ASCII letter.
        let c = *format.as_bytes().first()?;
        if !c.is_ascii_alphabetic() {
            return Some(Self::Layout(format.to_string()));
        }
        let layout = match format {
            "ANSIC" => time::ANSIC,
            "UnixDate" => time::UNIX_DATE,
            "RubyDate" => time::RUBY_DATE,
            "RFC822" => time::RFC822,
            "RFC822Z" => time::RFC822Z,
            "RFC850" => time::RFC850,
            "RFC1123" => time::RFC1123,
            "RFC1123Z" => time::RFC1123Z,
            "RFC3339" => return Some(Self::Rfc3339(time::RFC3339)),
            "RFC3339Nano" => return Some(Self::Rfc3339(time::RFC3339_NANO)),
            "Kitchen" => time::KITCHEN,
            "Stamp" => time::STAMP,
            "StampMilli" => time::STAMP_MILLI,
            "StampMicro" => time::STAMP_MICRO,
            "StampNano" => time::STAMP_NANO,
            "DateTime" => time::DATE_TIME,
            "DateOnly" => time::DATE_ONLY,
            "TimeOnly" => time::TIME_ONLY,
            "unix" => return Some(Self::Unix(1)),
            "unixmilli" => return Some(Self::Unix(1_000)),
            "unixmicro" => return Some(Self::Unix(1_000_000)),
            "unixnano" => return Some(Self::Unix(1_000_000_000)),
            // Reject any Go identifier in case new constants are supported.
            _ if format.chars().all(|r| is_letter_or_digit(r as i32)) => return None,
            _ => format,
        };
        Some(Self::Layout(layout.to_string()))
    }

    fn is_numeric(&self) -> bool {
        matches!(self, Self::Unix(_))
    }

    fn append(&self, b: &mut Vec<u8>, t: &Time) -> Result<(), Error> {
        match self {
            Self::Rfc3339(layout) => {
                let n0 = b.len();
                t.append_format(b, layout);
                // Not all Go timestamps can be represented as valid RFC 3339
                // (https://go.dev/issue/4556, https://go.dev/issue/54580).
                let s = &b[n0..];
                if s[4] != b'-' {
                    return Err(Error::msg("year outside of range [0,9999]"));
                }
                if s[s.len() - 1] != b'Z' {
                    let c = s[s.len() - 6];
                    if c.is_ascii_digit() || parse_dec2(&s[s.len() - 5..]) >= 24 {
                        return Err(Error::msg("timezone hour outside of range [0,23]"));
                    }
                }
                Ok(())
            }
            Self::Unix(pow10) => {
                append_time_unix(b, t, *pow10);
                Ok(())
            }
            Self::Layout(layout) => {
                t.append_format(b, layout);
                Ok(())
            }
        }
    }

    fn parse_value(&self, b: &[u8]) -> Result<Time, Error> {
        match self {
            Self::Rfc3339(_) => parse_rfc3339(b),
            Self::Unix(pow10) => parse_time_unix(b, *pow10),
            Self::Layout(layout) => {
                Time::parse(layout, &String::from_utf8_lossy(b)).map_err(Error::other)
            }
        }
    }
}

/// `time.Time.UnmarshalText` plus the checks Go's v2 adds because `time`
/// accepts some invalid RFC 3339 timestamps (https://go.dev/issue/57912).
fn parse_rfc3339(b: &[u8]) -> Result<Time, Error> {
    let mut t = Time::default();
    t.unmarshal_text(b).map_err(Error::other)?;
    let parse_error = |layout_elem: &[u8], value_elem: &[u8], message: &str| {
        let s = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        Error::other(time::ParseError {
            layout: time::RFC3339.to_string(),
            value: s(b),
            layout_elem: s(layout_elem),
            value_elem: s(value_elem),
            message: message.to_string(),
        })
    };
    const DATE_T: usize = "2006-01-02T".len();
    const DATE_TIME: usize = "2006-01-02T15:04:05".len();
    if b[DATE_T + 1] == b':' {
        return Err(parse_error(b"15", &b[DATE_T..DATE_T + 1], ""));
    }
    if b[DATE_TIME] == b',' {
        return Err(parse_error(b".", b",", ""));
    }
    if b[b.len() - 1] != b'Z' {
        let zone = &b[b.len() - 6..];
        if parse_dec2(&b[b.len() - 5..]) >= 24 {
            return Err(parse_error(b"Z07:00", zone, ": timezone hour out of range"));
        }
        if parse_dec2(&b[b.len() - 2..]) >= 60 {
            return Err(parse_error(
                b"Z07:00",
                zone,
                ": timezone minute out of range",
            ));
        }
    }
    Ok(t)
}

fn time_type() -> TypeInfo {
    TypeInfo::of::<Time>("time.Time", TypeKind::Struct)
}

impl MarshalTo for Time {
    fn type_info() -> TypeInfo {
        time_type()
    }

    fn marshal_default(&self, enc: &mut Encoder<'_>) -> Result<(), Error> {
        let t = time_type();
        let mut format = TimeFormat::Rfc3339(time::RFC3339_NANO);
        if enc.s.opts.flags.has(flags::FORMAT_TAG) {
            match TimeFormat::parse(&enc.s.opts.format) {
                Some(f) => format = f,
                None => return Err(invalid_format_error_enc(enc, t)),
            }
        }
        if enc.s.opts.flags.get(flags::STRING_TAG) && !format.is_numeric() {
            return Err(marshal_error_before(
                enc,
                Some(t),
                Some(err_invalid_string_tag()),
            ));
        }
        let k = string_or_number_kind(stringify_enc(enc, format.is_numeric()));
        let safe_ascii = !matches!(format, TimeFormat::Layout(_));
        let r = enc.s.append_raw(k, safe_ascii, |b| format.append(b, self));
        wrap_marshal_error(enc, t, r)
    }

    fn is_zero_value(&self) -> bool {
        self.is_zero_struct()
    }

    fn has_is_zero_method() -> bool {
        true
    }

    fn is_zero_field(&self) -> bool {
        self.is_zero()
    }

    fn has_methods(&self) -> bool {
        true
    }
}

impl UnmarshalFrom for Time {
    fn type_info() -> TypeInfo {
        time_type()
    }

    fn zero() -> Self {
        Time::default()
    }

    fn set_zero(&mut self) {
        *self = Time::default();
    }

    fn unmarshal_default(&mut self, dec: &mut Decoder<'_>) -> Result<(), Error> {
        let t = time_type();
        let mut format = TimeFormat::Rfc3339(time::RFC3339_NANO);
        if dec.s.opts.flags.has(flags::FORMAT_TAG) {
            match TimeFormat::parse(&dec.s.opts.format) {
                Some(f) => format = f,
                None => return Err(invalid_format_error_dec(dec, t)),
            }
        }
        if dec.s.opts.flags.get(flags::STRING_TAG) && !format.is_numeric() {
            return Err(unmarshal_error_before(
                dec,
                Some(t),
                Some(err_invalid_string_tag()),
            ));
        }
        let stringify = stringify_dec(dec, format.is_numeric());
        let Some(text) = read_time_value(dec, &t, stringify)? else {
            self.set_zero();
            return Ok(());
        };
        match format.parse_value(&text) {
            Ok(v) => {
                *self = v;
                Ok(())
            }
            Err(err) => Err(unmarshal_error_after(dec, Some(t), Some(err))),
        }
    }

    fn has_methods(&mut self) -> bool {
        true
    }
}

// ---------------------------------------------------------- number codecs

/// Appends `d` as a decimal number of units of `pow10` nanoseconds.
fn append_duration_base10(b: &mut Vec<u8>, d: Duration, pow10: u64) {
    let n = may_append_duration_sign(b, d);
    strconv::append_uint(b, n / pow10, 10);
    append_frac_base10(b, n % pow10, pow10);
}

/// Parses a decimal number of units of `pow10` nanoseconds.
fn parse_duration_base10(b: &[u8], pow10: u64) -> Result<Duration, Error> {
    let (suffix, neg) = consume_sign(b, false);
    let (whole_bytes, frac_bytes) = cut_byte_keep(suffix, b'.');
    let (whole, ok_whole) = wire::parse_uint(whole_bytes);
    let (frac, ok_frac) = parse_frac_base10(frac_bytes, pow10);
    let product = u128::from(whole) * u128::from(pow10);
    let (sum, carry) = (product as u64).overflowing_add(frac);
    let d = may_apply_duration_sign(sum, neg);
    if (!ok_whole && whole != u64::MAX) || !ok_frac {
        return Err(syntax_error("invalid duration", b));
    }
    if !ok_whole || product > u128::from(u64::MAX) || carry || neg != (d.as_nanos() < 0) {
        return Err(range_error("invalid duration", b));
    }
    Ok(d)
}

/// Appends an ISO 8601 duration that uses only the hour, minute and second
/// designators (the "accurate" ones) and omits zero components.
fn append_duration_iso8601(b: &mut Vec<u8>, d: Duration) {
    if d.as_nanos() == 0 {
        b.extend_from_slice(b"PT0S");
        return;
    }
    let n = may_append_duration_sign(b, d);
    b.extend_from_slice(b"PT");
    let (n, nsec) = (n / 1_000_000_000, n % 1_000_000_000);
    let (n, sec) = (n / 60, n % 60);
    let (hour, min) = (n / 60, n % 60);
    if hour > 0 {
        strconv::append_uint(b, hour, 10);
        b.push(b'H');
    }
    if min > 0 {
        strconv::append_uint(b, min, 10);
        b.push(b'M');
    }
    if sec > 0 || nsec > 0 {
        strconv::append_uint(b, sec, 10);
        append_frac_base10(b, nsec, 1_000_000_000);
        b.push(b'S');
    }
}

/// The exact average number of nanoseconds in a Gregorian year.
const NANOS_PER_YEAR: u64 = 31_556_952_000_000_000;
const NANOS_PER_HOUR: u64 = 3_600_000_000_000;
const NANOS_PER_SECOND: u64 = 1_000_000_000;

/// Go's `parseDurationISO8601` state: what the components seen so far add
/// up to and what went wrong.
#[derive(Default)]
struct Iso8601 {
    invalid: bool,
    overflow: bool,
    inaccurate: bool,
    saw_frac: bool,
    sum_nanos: u64,
}

impl Iso8601 {
    fn add(&mut self, n: u64) {
        let (sum, carry) = self.sum_nanos.overflowing_add(n);
        self.sum_nanos = sum;
        self.overflow |= carry;
    }

    /// Parses the component designated by `hi` or `lo` (a unit of `unit`
    /// nanoseconds) if `b` has one, and returns what follows it.
    fn unit<'a>(&mut self, b: &'a [u8], hi: u8, lo: u8, unit: u64) -> &'a [u8] {
        let Some((number, suffix)) = cut_either(b, hi, lo) else {
            return b;
        };
        if self.saw_frac {
            return b; // a fraction is only allowed in the last component
        }
        let mut whole = number;
        if let Some((w, frac)) = cut_either(number, b'.', b',') {
            whole = w;
            self.saw_frac = true;
            self.invalid = self.invalid || frac.is_empty() || unit > NANOS_PER_HOUR;
            let n = if unit == NANOS_PER_SECOND {
                let (n, ok) = parse_padded_base10(frac, NANOS_PER_SECOND);
                self.invalid = self.invalid || !ok;
                n
            } else {
                let text = format!("0.{}", String::from_utf8_lossy(frac));
                let f = strconv::parse_float(&text, 64);
                self.invalid =
                    self.invalid || f.is_err() || frac[1..].iter().any(|c| !c.is_ascii_digit());
                let f = f.unwrap_or_else(|e| e.float_value());
                (f * unit as f64).round() as u64
            };
            self.add(n);
        }
        while whole.len() > 1 && whole[0] == b'0' {
            whole = &whole[1..];
        }
        let (n, ok) = wire::parse_uint(whole);
        let product = u128::from(n) * u128::from(unit);
        self.add(product as u64);
        self.invalid = self.invalid || (!ok && n != u64::MAX);
        self.overflow = self.overflow || (!ok && n == u64::MAX) || product > u128::from(u64::MAX);
        self.inaccurate = self.inaccurate || unit > NANOS_PER_HOUR;
        suffix
    }
}

/// Go's `parseDurationISO8601`: ISO 8601-1:2019 durations with a leading
/// sign, a fraction only in the last accurate component, `.` or `,` as the
/// decimal separator, leading zeros and lowercase designators (JavaScript's
/// `Temporal.Duration` grammar). Year, month, week and day units give a
/// best-effort value and an error.
fn parse_duration_iso8601(b: &[u8]) -> Result<Duration, Error> {
    let mut p = Iso8601::default();
    let (rest, neg) = consume_sign(b, true);
    let (prefix, rest, ok_p) = match cut_either(rest, b'P', b'p') {
        Some((prefix, rest)) => (prefix, rest, true),
        None => (rest, &[][..], false),
    };
    let (mut dur_date, mut dur_time, ok_t) = match cut_either(rest, b'T', b't') {
        Some((date, time)) => (date, time, true),
        None => (rest, &[][..], false),
    };
    p.invalid = !prefix.is_empty()
        || !ok_p
        || (ok_t && dur_time.is_empty())
        || dur_date.len() + dur_time.len() == 0;
    if !dur_date.is_empty() {
        dur_date = p.unit(dur_date, b'Y', b'y', NANOS_PER_YEAR);
        dur_date = p.unit(dur_date, b'M', b'm', NANOS_PER_YEAR / 12);
        dur_date = p.unit(dur_date, b'W', b'w', 7 * 24 * NANOS_PER_HOUR);
        dur_date = p.unit(dur_date, b'D', b'd', 24 * NANOS_PER_HOUR);
        p.invalid = p.invalid || !dur_date.is_empty();
    }
    if !dur_time.is_empty() {
        dur_time = p.unit(dur_time, b'H', b'h', NANOS_PER_HOUR);
        dur_time = p.unit(dur_time, b'M', b'm', 60 * NANOS_PER_SECOND);
        dur_time = p.unit(dur_time, b'S', b's', NANOS_PER_SECOND);
        p.invalid = p.invalid || !dur_time.is_empty();
    }
    let d = may_apply_duration_sign(p.sum_nanos, neg);
    p.overflow = p.overflow || (neg != (d.as_nanos() < 0) && d.as_nanos() != 0);
    if p.invalid {
        Err(syntax_error("invalid ISO 8601 duration", b))
    } else if p.overflow {
        Err(range_error("invalid ISO 8601 duration", b))
    } else if p.inaccurate {
        Err(Error::msg(&format!(
            "invalid ISO 8601 duration {}: inaccurate year, month, week, or day units",
            strconv::quote(b)
        )))
    } else {
        Ok(d)
    }
}

/// Appends `-` if `d` is negative and returns its magnitude.
fn may_append_duration_sign(b: &mut Vec<u8>, d: Duration) -> u64 {
    let n = d.as_nanos();
    if n < 0 {
        b.push(b'-');
    }
    n.unsigned_abs()
}

/// The duration of `n` nanoseconds, negated if `neg` (wrapping like Go).
fn may_apply_duration_sign(n: u64, neg: bool) -> Duration {
    let d = n as i64;
    Duration::from_nanos(if neg { d.wrapping_neg() } else { d })
}

/// Appends `t` as a decimal number of units since the Unix epoch, with
/// `pow10` units per second.
fn append_time_unix(b: &mut Vec<u8>, t: &Time, pow10: u64) {
    let (mut sec, mut nsec) = (t.unix(), t.nanosecond());
    if sec < 0 {
        b.push(b'-');
        (sec, nsec) = negate_sec_nano(sec, nsec);
    }
    let (sec, nsec) = (sec as u64, nsec as u64);
    if pow10 == 1 {
        strconv::append_uint(b, sec, 10);
        append_frac_base10(b, nsec, NANOS_PER_SECOND);
    } else if sec < 1_000_000_000 {
        strconv::append_uint(b, sec * pow10 + nsec / (NANOS_PER_SECOND / pow10), 10);
        append_frac_base10(b, (nsec * pow10) % NANOS_PER_SECOND, NANOS_PER_SECOND);
    } else {
        strconv::append_uint(b, sec, 10);
        append_padded_base10(b, nsec / (NANOS_PER_SECOND / pow10), pow10);
        append_frac_base10(b, (nsec * pow10) % NANOS_PER_SECOND, NANOS_PER_SECOND);
    }
}

/// Parses a decimal number of units since the Unix epoch, with `pow10`
/// units per second, as a UTC time.
fn parse_time_unix(b: &[u8], pow10: u64) -> Result<Time, Error> {
    let (suffix, neg) = consume_sign(b, false);
    let (whole_bytes, frac_bytes) = cut_byte_keep(suffix, b'.');
    let (mut whole, mut ok_whole) = wire::parse_uint(whole_bytes);
    let (frac, ok_frac) = parse_frac_base10(frac_bytes, NANOS_PER_SECOND / pow10);
    let (mut sec, mut nsec) = (0i64, 0i64);
    if pow10 == 1 {
        sec = whole as i64;
        nsec = frac as i64;
    } else if ok_whole {
        sec = (whole / pow10) as i64;
        nsec = ((whole % pow10) * (NANOS_PER_SECOND / pow10) + frac) as i64;
    } else if whole == u64::MAX {
        // The units overflow a uint64: split off the sub-second digits.
        let width = pow10.ilog10() as usize;
        let split = whole_bytes.len() - width;
        (whole, ok_whole) = wire::parse_uint(&whole_bytes[..split]);
        let (mid, _) = parse_padded_base10(&whole_bytes[split..], pow10);
        sec = whole as i64;
        nsec = (mid * (NANOS_PER_SECOND / pow10) + frac) as i64;
    }
    if neg {
        (sec, nsec) = negate_sec_nano(sec, nsec);
    }
    let t = time::unix(sec, nsec).utc();
    if (!ok_whole && whole != u64::MAX) || !ok_frac {
        return Err(syntax_error("invalid time", b));
    }
    if !ok_whole || neg != (t.unix() < 0) {
        return Err(range_error("invalid time", b));
    }
    Ok(t)
}

/// Negates a Unix time whose `nsec` is in `0..1e9`.
fn negate_sec_nano(sec: i64, nsec: i64) -> (i64, i64) {
    let nsec = 1_000_000_000 - nsec;
    (
        (!sec).wrapping_add(nsec / 1_000_000_000),
        nsec % 1_000_000_000,
    )
}

/// Appends the fraction `n / max10` (`max10` a power of ten above `n`)
/// without trailing zeros, or nothing when it is zero.
fn append_frac_base10(b: &mut Vec<u8>, n: u64, max10: u64) {
    if n == 0 {
        return;
    }
    b.push(b'.');
    append_padded_base10(b, n, max10);
    while b.last() == Some(&b'0') {
        b.pop();
    }
}

/// Parses an optional `.` fraction of `max10`.
fn parse_frac_base10(b: &[u8], max10: u64) -> (u64, bool) {
    match b {
        [] => (0, true),
        [b'.', digits @ ..] if !digits.is_empty() => parse_padded_base10(digits, max10),
        _ => (0, false),
    }
}

/// Appends `n` zero-padded to the width of `max10 - 1`.
fn append_padded_base10(b: &mut Vec<u8>, n: u64, max10: u64) {
    if n < max10 / 10 {
        let i = b.len();
        strconv::append_uint(b, n + max10 / 10, 10);
        b[i] -= 1;
        return;
    }
    strconv::append_uint(b, n, 10);
}

/// Parses `b` as the zero-padded digits of `n / max10`: a short `b` has
/// implicit trailing zeros and the digits of a long one are ignored.
fn parse_padded_base10(mut b: &[u8], max10: u64) -> (u64, bool) {
    let mut n = 0u64;
    let mut pow10 = 1u64;
    while pow10 < max10 {
        n *= 10;
        if let [c, rest @ ..] = b {
            if !c.is_ascii_digit() {
                return (n, false);
            }
            n += u64::from(c - b'0');
            b = rest;
        }
        pow10 *= 10;
    }
    (n, b.iter().all(u8::is_ascii_digit))
}

/// Consumes an optional leading `-` (or `+` when `allow_plus`).
fn consume_sign(b: &[u8], allow_plus: bool) -> (&[u8], bool) {
    match b {
        [b'-', rest @ ..] => (rest, true),
        [b'+', rest @ ..] if allow_plus => (rest, false),
        _ => (b, false),
    }
}

/// Splits `b` before the first `c`, which stays in the suffix.
fn cut_byte_keep(b: &[u8], c: u8) -> (&[u8], &[u8]) {
    match b.iter().position(|&x| x == c) {
        Some(i) => b.split_at(i),
        None => (b, &[]),
    }
}

/// Splits `b` around the first `c0` or `c1`.
fn cut_either(b: &[u8], c0: u8, c1: u8) -> Option<(&[u8], &[u8])> {
    let i = b.iter().position(|&x| x == c0 || x == c1)?;
    Some((&b[..i], &b[i + 1..]))
}

/// Parses two decimal digits (undefined for non-digits, as in Go).
fn parse_dec2(b: &[u8]) -> u8 {
    if b.len() < 2 {
        return 0;
    }
    10u8.wrapping_mul(b[0].wrapping_sub(b'0'))
        .wrapping_add(b[1].wrapping_sub(b'0'))
}
