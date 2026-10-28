//! Line protocol used by `tools/time_check.py` for Go differential checks of
//! formatting, parsing, durations and `Time` methods. Requests and responses
//! match `tools/time_oracle.go`.
use rust_stdlib::time::{
    self as time, load_location, local, Duration, Location, Month, Time, Weekday,
};
use std::collections::HashMap;
use std::io::{self, BufRead, Write};

type Res<T> = Result<T, Box<dyn std::error::Error>>;

fn unhex_bytes(text: &str) -> Res<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return Err("odd-length hex input".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| Ok(u8::from_str_radix(&text[i..i + 2], 16)?))
        .collect()
}

fn unhex(text: &str) -> Res<String> {
    Ok(String::from_utf8(unhex_bytes(text)?)?)
}

fn hx(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

fn num(s: &str) -> Res<i64> {
    Ok(s.parse()?)
}

struct Zones(HashMap<String, Location>);

impl Zones {
    fn get(&mut self, spec: &str) -> Res<Location> {
        Ok(match spec {
            "U" => Location::utc(),
            "L" => local(),
            _ if spec.starts_with('F') => {
                let (off, name) = spec[1..].split_once(',').ok_or("bad fixed zone")?;
                Location::fixed(&unhex(name)?, num(off)? as i32)
            }
            _ if spec.starts_with('Z') => {
                if let Some(l) = self.0.get(spec) {
                    return Ok(l.clone());
                }
                let l = load_location(&spec[1..])?;
                self.0.insert(spec.into(), l.clone());
                l
            }
            _ => return Err(format!("bad zone {spec}").into()),
        })
    }
}

fn err_text(r: &Result<Vec<u8>, time::Error>) -> (String, String) {
    match r {
        Ok(b) => (hx(b), "nil".into()),
        Err(e) => (String::new(), hx(e.to_string())),
    }
}

fn describe(t: &Time) -> String {
    let (name, off) = t.zone();
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}",
        t.unix(),
        t.nanosecond(),
        hx(name),
        off,
        hx(t.location().name()),
        hx(t.to_string())
    )
}

fn state(t: &Time) -> String {
    let (y, mo, d) = t.date();
    let (h, mi, s) = t.clock();
    let (iy, iw) = t.iso_week();
    let (name, off) = t.zone();
    let bin = err_text(&t.marshal_binary());
    let js = err_text(&t.marshal_json());
    let tx = err_text(&t.marshal_text());
    [
        hx(t.to_string()),
        hx(t.literal()),
        format!(
            "{y},{},{d},{h},{mi},{s},{},{iy},{iw},{}",
            mo.0,
            t.weekday().0,
            t.year_day()
        ),
        format!("{},{off},{},{}", hx(name), t.is_dst(), t.is_zero()),
        format!(
            "{},{},{},{}",
            t.unix(),
            t.unix_milli(),
            t.unix_micro(),
            t.unix_nano()
        ),
        format!("{},{}", bin.0, bin.1),
        format!("{},{}", js.0, js.1),
        format!("{},{}", tx.0, tx.1),
    ]
    .join("\t")
}

fn handle(f: &[&str], zones: &mut Zones) -> Res<String> {
    Ok(match f[0] {
        "F" => {
            let t = time::unix(num(f[1])?, num(f[2])?).in_location(&zones.get(f[3])?);
            hx(t.format(&unhex(f[4])?))
        }
        "S" => state(&time::unix(num(f[1])?, num(f[2])?).in_location(&zones.get(f[3])?)),
        "P" | "I" => {
            let layout = unhex(f[1])?;
            let value = unhex(f[2])?;
            let result = if f[0] == "P" {
                time::Time::parse(&layout, &value)
            } else {
                time::Time::parse_in_location(&layout, &value, &zones.get(f[3])?)
            };
            match result {
                Ok(t) => format!("ok\t{}", describe(&t)),
                Err(e) => {
                    if [&e.layout_elem, &e.value_elem]
                        .iter()
                        .any(|s| s.contains('\u{fffd}'))
                    {
                        "err\t?".into()
                    } else {
                        format!(
                            "err\t{}\t{}",
                            hx(e.to_string()),
                            [
                                &e.layout,
                                &e.value,
                                &e.layout_elem,
                                &e.value_elem,
                                &e.message
                            ]
                            .map(hx)
                            .join(",")
                        )
                    }
                }
            }
        }
        "D" => describe(&time::date(
            num(f[1])?,
            Month(num(f[2])?),
            num(f[3])?,
            num(f[4])?,
            num(f[5])?,
            num(f[6])?,
            num(f[7])?,
            &zones.get(f[8])?,
        )),
        "A" => {
            let t = time::unix(num(f[1])?, num(f[2])?).in_location(&zones.get(f[3])?);
            describe(&t.add_date(num(f[4])?, num(f[5])?, num(f[6])?))
        }
        "R" => {
            let t = time::unix(num(f[1])?, num(f[2])?).in_location(&zones.get(f[3])?);
            let d = Duration::from_nanos(num(f[4])?);
            let u = time::unix(num(f[5])?, num(f[6])?);
            [
                describe(&t.round(d)),
                describe(&t.truncate(d)),
                describe(&t.add(d)),
                t.sub(&u).as_nanos().to_string(),
                t.compare(&u).to_string(),
                t.before(&u).to_string(),
                t.after(&u).to_string(),
                t.equal(&u).to_string(),
            ]
            .join("\t")
        }
        "U" => {
            let data = unhex_bytes(f[2])?;
            let mut t = Time::default();
            let result = match f[1] {
                "json" => t.unmarshal_json(&data).map_err(|e| e.to_string()),
                "text" => t.unmarshal_text(&data).map_err(|e| e.to_string()),
                _ => t.unmarshal_binary(&data).map_err(|e| e.to_string()),
            };
            match result {
                Ok(()) => format!("ok\t{}", describe(&t)),
                Err(e) => format!("err\t{}", hx(e)),
            }
        }
        "N" => match unhex(f[1])?.parse::<time::Duration>() {
            Ok(d) => format!("ok\t{}\t{}", d.as_nanos(), hx(d.to_string())),
            Err(e) => format!("err\t{}", hx(e.to_string())),
        },
        "M" => {
            let d = Duration::from_nanos(num(f[1])?);
            let m = Duration::from_nanos(num(f[2])?);
            format!(
                "{}\t{}\t{}\t{:x}\t{:x}\t{:x}\t{}\t{}\t{}",
                d.round(m).as_nanos(),
                d.truncate(m).as_nanos(),
                d.abs().as_nanos(),
                d.seconds().to_bits(),
                d.minutes().to_bits(),
                d.hours().to_bits(),
                d.milliseconds(),
                d.microseconds(),
                hx(d.to_string())
            )
        }
        "T" => {
            let data = unhex_bytes(f[1])?;
            match Location::from_tzdata("x", &data) {
                Err(e) => format!("err\t{}", hx(e.to_string())),
                Ok(loc) => {
                    let mut out = vec!["ok".to_owned()];
                    for sec in f[2].split(',') {
                        let t = time::unix(num(sec)?, 0).in_location(&loc);
                        let (name, off) = t.zone();
                        out.push(format!("{},{}", hx(name), off));
                    }
                    out.join("\t")
                }
            }
        }
        "O" => format!(
            "{}\t{}",
            hx(Month(num(f[1])?).to_string()),
            hx(Weekday(num(f[2])?).to_string())
        ),
        mode => return Err(format!("bad mode {mode}").into()),
    })
}

fn main() -> Res<()> {
    let stdin = io::stdin();
    let mut out = io::BufWriter::new(io::stdout().lock());
    let mut zones = Zones(HashMap::new());
    for line in stdin.lock().lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        writeln!(out, "{}", handle(&fields, &mut zones)?)?;
    }
    Ok(())
}
