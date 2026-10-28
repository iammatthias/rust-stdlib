//! Line protocol used by `tools/rand_check.py` for Go differential checks.
//! See `tools/rand_oracle.go` for the request and reply format.
use rust_stdlib::math::rand::{v1, ChaCha8, Pcg, Rand, Zipf};
use rust_stdlib::time::Duration;
use std::io::{self, BufRead, Read, Write};

type Res<T> = Result<T, Box<dyn std::error::Error>>;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(text: &str) -> Res<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return Err("odd-length hex input".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| Ok(u8::from_str_radix(&text[i..i + 2], 16)?))
        .collect()
}

fn f64_bits(x: f64) -> String {
    format!("{:016x}", x.to_bits())
}

fn f32_bits(x: f32) -> String {
    format!("{:08x}", x.to_bits())
}

fn ints(values: &[usize]) -> String {
    let parts: Vec<String> = values.iter().map(usize::to_string).collect();
    format!("[{}]", parts.join(","))
}

/// The seeded v2 source under test, kept concrete for Marshal and Read.
trait Probe: rust_stdlib::math::rand::Source {
    fn marshal(&mut self) -> Res<String>;
    fn read_bytes(&mut self, _n: usize) -> Res<String> {
        Err("Read is ChaCha8-only".into())
    }
}

impl Probe for Pcg {
    fn marshal(&mut self) -> Res<String> {
        let data = self.marshal_binary();
        *self = Pcg::default();
        self.unmarshal_binary(&data)?;
        Ok(hex(&data))
    }
}

impl Probe for ChaCha8 {
    fn marshal(&mut self) -> Res<String> {
        let data = self.marshal_binary();
        *self = ChaCha8::new([0; 32]);
        self.unmarshal_binary(&data)?;
        Ok(hex(&data))
    }
    fn read_bytes(&mut self, n: usize) -> Res<String> {
        let mut buf = vec![0; n];
        if self.read(&mut buf)? != n {
            return Err("short read".into());
        }
        Ok(hex(&buf))
    }
}

/// Parses `s:v:imax:count` for the `Zipf` op.
fn zipf_args(arg: &str) -> Res<(f64, f64, u64, usize)> {
    let parts: Vec<&str> = arg.split(':').collect();
    let [s, v, imax, count] = parts[..] else {
        return Err(format!("bad Zipf arguments {arg}").into());
    };
    Ok((s.parse()?, v.parse()?, imax.parse()?, count.parse()?))
}

fn v2op<S: Probe>(r: &mut Rand<S>, name: &str, arg: &str) -> Res<String> {
    Ok(match name {
        "Int64" => r.int64().to_string(),
        "Uint32" => r.uint32().to_string(),
        "Uint64" => r.uint64().to_string(),
        "Int32" => r.int32().to_string(),
        "Int" => r.int().to_string(),
        "Uint" => r.uint().to_string(),
        "Int64N" => r.int64_n(arg.parse()?).to_string(),
        "Uint64N" => r.uint64_n(arg.parse()?).to_string(),
        "Int32N" => r.int32_n(arg.parse()?).to_string(),
        "Uint32N" => r.uint32_n(arg.parse()?).to_string(),
        "IntN" => r.int_n(arg.parse()?).to_string(),
        "UintN" => r.uint_n(arg.parse()?).to_string(),
        "NInt8" => r.n(arg.parse::<i8>()?).to_string(),
        "NUint16" => r.n(arg.parse::<u16>()?).to_string(),
        "NInt64" => r.n(arg.parse::<i64>()?).to_string(),
        "NDuration" => r
            .n(Duration::from_nanos(arg.parse()?))
            .as_nanos()
            .to_string(),
        "Float64" => f64_bits(r.float64()),
        "Float32" => f32_bits(r.float32()),
        "Perm" => ints(&r.perm(arg.parse()?)),
        "Shuffle" => {
            let mut p: Vec<usize> = (0..arg.parse()?).collect();
            r.shuffle(p.len(), |i, j| p.swap(i, j));
            ints(&p)
        }
        "NormFloat64" => f64_bits(r.norm_float64()),
        "ExpFloat64" => f64_bits(r.exp_float64()),
        "Zipf" => {
            let (s, v, imax, count) = zipf_args(arg)?;
            match Zipf::new(r, s, v, imax) {
                None => "nil".to_string(),
                Some(mut z) => (0..count)
                    .map(|_| z.uint64().to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            }
        }
        "Read" => r.source_mut().read_bytes(arg.parse()?)?,
        "Marshal" => r.source_mut().marshal()?,
        other => return Err(format!("unknown v2 op {other}").into()),
    })
}

fn v1op(r: &mut v1::Rand<v1::RngSource>, name: &str, arg: &str) -> Res<String> {
    Ok(match name {
        "Seed" => {
            r.seed(arg.parse()?);
            "-".to_string()
        }
        "Int63" => r.int63().to_string(),
        "Uint32" => r.uint32().to_string(),
        "Uint64" => r.uint64().to_string(),
        "Int31" => r.int31().to_string(),
        "Int" => r.int().to_string(),
        "Int63n" => r.int63n(arg.parse()?).to_string(),
        "Int31n" => r.int31n(arg.parse()?).to_string(),
        "Intn" => r.intn(arg.parse()?).to_string(),
        "Float64" => f64_bits(r.float64()),
        "Float32" => f32_bits(r.float32()),
        "Perm" => ints(&r.perm(arg.parse()?)),
        "Shuffle" => {
            let mut p: Vec<usize> = (0..arg.parse()?).collect();
            r.shuffle(p.len(), |i, j| p.swap(i, j));
            ints(&p)
        }
        "Read" => {
            let mut buf = vec![0; arg.parse()?];
            if r.read(&mut buf)? != buf.len() {
                return Err("short read".into());
            }
            hex(&buf)
        }
        "NormFloat64" => f64_bits(r.norm_float64()),
        "ExpFloat64" => f64_bits(r.exp_float64()),
        "Zipf" => {
            let (s, v, imax, count) = zipf_args(arg)?;
            match v1::Zipf::new(r, s, v, imax) {
                None => "nil".to_string(),
                Some(mut z) => (0..count)
                    .map(|_| z.uint64().to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            }
        }
        other => return Err(format!("unknown v1 op {other}").into()),
    })
}

fn run_v2<S: Probe>(mut r: Rand<S>, ops: &[(&str, &str)]) -> Res<Vec<String>> {
    ops.iter()
        .map(|(name, arg)| v2op(&mut r, name, arg))
        .collect()
}

fn main() -> Res<()> {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        let line = line?;
        let (head, body) = line.split_once(" | ").ok_or("bad request")?;
        let generator: Vec<&str> = head.split_whitespace().collect();
        let ops: Vec<(&str, &str)> = body
            .split_whitespace()
            .map(|op| op.split_once(':').unwrap_or((op, "")))
            .collect();
        let reply = match generator.as_slice() {
            ["pcg", a, b] => run_v2(Rand::new(Pcg::new(a.parse()?, b.parse()?)), &ops)?,
            ["chacha", seed] => {
                let seed: [u8; 32] = from_hex(seed)?
                    .try_into()
                    .map_err(|_| "seed must be 32 bytes")?;
                run_v2(Rand::new(ChaCha8::new(seed)), &ops)?
            }
            ["v1", seed] => {
                let mut r = v1::Rand::new(v1::RngSource::new(seed.parse()?));
                ops.iter()
                    .map(|(name, arg)| v1op(&mut r, name, arg))
                    .collect::<Res<Vec<_>>>()?
            }
            _ => return Err(format!("unknown generator {head}").into()),
        };
        writeln!(out, "{}", reply.join(" "))?;
    }
    out.flush()?;
    Ok(())
}
