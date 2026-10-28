//! Line protocol used by `tools/tzif_check.py` for Go differential checks.
//! Requests are `MODE:hex(TZif):args`; responses match `tools/tzif_oracle.go`.
use rust_stdlib::time::{self as time, load_location, Location, LocationError, Month, Time};
use std::io::{self, BufRead, Write};

fn from_hex(text: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if !text.len().is_multiple_of(2) {
        return Err("odd-length hex input".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| Ok(u8::from_str_radix(&text[i..i + 2], 16)?))
        .collect()
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// Lossily decoded abbreviations contain U+FFFD; the oracle prints "?".
fn name(abbr: &str) -> String {
    if abbr.contains('\u{fffd}') {
        "?".into()
    } else {
        hex(abbr)
    }
}

fn ints(arg: &str) -> Result<Vec<i64>, Box<dyn std::error::Error>> {
    Ok(arg
        .split('.')
        .map(str::parse)
        .collect::<Result<Vec<i64>, _>>()?)
}

fn bound(value: &Time) -> String {
    if value.is_zero() {
        "-".into()
    } else {
        value.unix().to_string()
    }
}

fn handle(mode: &str, data: &[u8], args: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut prefix = String::from("ok\t");
    let (mode, loc) = if mode == "L" {
        match load_location(std::str::from_utf8(data)?) {
            Ok(loc) => {
                prefix += &format!("{}\t", hex(loc.name()));
                ("Z", loc)
            }
            Err(LocationError::InvalidName) => return Ok("invalid".into()),
            Err(LocationError::UnknownZone(_)) => return Ok("unknown".into()),
            Err(_) => return Ok("other".into()),
        }
    } else {
        match Location::from_tzdata("Zone", data) {
            Ok(loc) => (mode, loc),
            Err(_) => return Ok("err".into()),
        }
    };
    let mut out = Vec::new();
    for arg in args.split(',').filter(|a| !a.is_empty()) {
        let v = ints(arg)?;
        out.push(match mode {
            "Z" => {
                let t = time::unix(v[0], 0).in_location(&loc);
                let (abbr, offset) = t.zone();
                let (start, end) = t.zone_bounds();
                format!(
                    "{offset},{},{},{},{}",
                    name(abbr),
                    u8::from(t.is_dst()),
                    bound(&start),
                    bound(&end)
                )
            }
            "S" => {
                let t = time::unix(v[0], v[1]).in_location(&loc);
                if name(t.zone().0) == "?" {
                    "?".into()
                } else {
                    hex(t.to_string())
                }
            }
            "D" => time::date(v[0], Month(v[1]), v[2], v[3], v[4], v[5], 0, &loc)
                .unix()
                .to_string(),
            _ => return Err(format!("unknown mode {mode}").into()),
        });
    }
    Ok(format!("{prefix}{}", out.join(";")))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(3, ':');
        let mode = parts.next().unwrap_or_default();
        let data = from_hex(parts.next().ok_or("missing data")?)?;
        let args = parts.next().ok_or("missing arguments")?;
        writeln!(out, "{}", handle(mode, &data, args)?)?;
    }
    Ok(())
}
