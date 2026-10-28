//! Line protocol used by `tools/color_check.py` for Go differential checks.
//! Each request line is "<op> <model>" and each response is one FNV-1a hash
//! over the output words; see `tools/color_oracle.go`, which mirrors it.
use rust_stdlib::image::color::{
    self, Alpha, Alpha16, Cmyk, Color, Gray, Gray16, Model, Nrgba, Nrgba64, Nycbcra, Rgba, Rgba64,
    Ycbcr,
};
use std::io::{self, BufRead, BufWriter, Write};

struct Hash(u64);

impl Hash {
    fn add(&mut self, words: &[u32]) {
        for &word in words {
            self.0 ^= u64::from(word);
            self.0 = self.0.wrapping_mul(0x100000001b3);
        }
    }
}

/// The xorshift64 generator shared with `tools/color_oracle.go`.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut v = self.0;
        v ^= v << 13;
        v ^= v >> 7;
        v ^= v << 17;
        self.0 = v;
        v
    }
}

/// One color of kind `next % 11`, with fields drawn in Go's order.
fn random_color(rng: &mut Rng) -> (u32, Color) {
    macro_rules! u8v {
        () => {
            rng.next_u64() as u8
        };
    }
    macro_rules! u16v {
        () => {
            rng.next_u64() as u16
        };
    }
    let kind = (rng.next_u64() % 11) as u32;
    let color = match kind {
        0 => Rgba {
            r: u8v!(),
            g: u8v!(),
            b: u8v!(),
            a: u8v!(),
        }
        .into(),
        1 => Rgba64 {
            r: u16v!(),
            g: u16v!(),
            b: u16v!(),
            a: u16v!(),
        }
        .into(),
        2 => Nrgba {
            r: u8v!(),
            g: u8v!(),
            b: u8v!(),
            a: u8v!(),
        }
        .into(),
        3 => Nrgba64 {
            r: u16v!(),
            g: u16v!(),
            b: u16v!(),
            a: u16v!(),
        }
        .into(),
        4 => Gray { y: u8v!() }.into(),
        5 => Gray16 { y: u16v!() }.into(),
        6 => Alpha { a: u8v!() }.into(),
        7 => Alpha16 { a: u16v!() }.into(),
        8 => Ycbcr {
            y: u8v!(),
            cb: u8v!(),
            cr: u8v!(),
        }
        .into(),
        9 => Nycbcra {
            ycbcr: Ycbcr {
                y: u8v!(),
                cb: u8v!(),
                cr: u8v!(),
            },
            a: u8v!(),
        }
        .into(),
        _ => Cmyk {
            c: u8v!(),
            m: u8v!(),
            y: u8v!(),
            k: u8v!(),
        }
        .into(),
    };
    (kind, color)
}

/// Hashes the concrete type tag (the same numbering as the Go oracle) and fields.
fn add_color(h: &mut Hash, c: Color) {
    match c {
        Color::Rgba(c) => h.add(&[
            0,
            u32::from(c.r),
            u32::from(c.g),
            u32::from(c.b),
            u32::from(c.a),
        ]),
        Color::Rgba64(c) => h.add(&[
            1,
            u32::from(c.r),
            u32::from(c.g),
            u32::from(c.b),
            u32::from(c.a),
        ]),
        Color::Nrgba(c) => h.add(&[
            2,
            u32::from(c.r),
            u32::from(c.g),
            u32::from(c.b),
            u32::from(c.a),
        ]),
        Color::Nrgba64(c) => h.add(&[
            3,
            u32::from(c.r),
            u32::from(c.g),
            u32::from(c.b),
            u32::from(c.a),
        ]),
        Color::Gray(c) => h.add(&[4, u32::from(c.y)]),
        Color::Gray16(c) => h.add(&[5, u32::from(c.y)]),
        Color::Alpha(c) => h.add(&[6, u32::from(c.a)]),
        Color::Alpha16(c) => h.add(&[7, u32::from(c.a)]),
        Color::Ycbcr(c) => h.add(&[8, u32::from(c.y), u32::from(c.cb), u32::from(c.cr)]),
        Color::Nycbcra(c) => h.add(&[
            9,
            u32::from(c.ycbcr.y),
            u32::from(c.ycbcr.cb),
            u32::from(c.ycbcr.cr),
            u32::from(c.a),
        ]),
        Color::Cmyk(c) => h.add(&[
            10,
            u32::from(c.c),
            u32::from(c.m),
            u32::from(c.y),
            u32::from(c.k),
        ]),
    }
}

const SAMPLES: u32 = 1 << 22;

fn run(op: &str, model: &str) -> String {
    let mut h = Hash(0xcbf29ce484222325);
    let mut rng = Rng(0x9E3779B97F4A7C15);
    match op {
        "rgb_to_ycbcr" => {
            for v in 0..1u32 << 24 {
                let (y, cb, cr) = color::rgb_to_ycbcr((v >> 16) as u8, (v >> 8) as u8, v as u8);
                h.add(&[u32::from(y), u32::from(cb), u32::from(cr)]);
            }
        }
        "ycbcr_to_rgb" => {
            for v in 0..1u32 << 24 {
                let (r, g, b) = color::ycbcr_to_rgb((v >> 16) as u8, (v >> 8) as u8, v as u8);
                h.add(&[u32::from(r), u32::from(g), u32::from(b)]);
            }
        }
        "rgb_to_cmyk" => {
            for v in 0..1u32 << 24 {
                let (c, m, y, k) = color::rgb_to_cmyk((v >> 16) as u8, (v >> 8) as u8, v as u8);
                h.add(&[u32::from(c), u32::from(m), u32::from(y), u32::from(k)]);
            }
        }
        "cmyk_to_rgb" => {
            for _ in 0..SAMPLES {
                let v = rng.next_u64();
                let (r, g, b) =
                    color::cmyk_to_rgb(v as u8, (v >> 8) as u8, (v >> 16) as u8, (v >> 24) as u8);
                h.add(&[u32::from(r), u32::from(g), u32::from(b)]);
            }
        }
        "ycbcr_rgba" => {
            for v in 0..1u32 << 24 {
                let (r, g, b, a) = Ycbcr {
                    y: (v >> 16) as u8,
                    cb: (v >> 8) as u8,
                    cr: v as u8,
                }
                .rgba();
                h.add(&[r, g, b, a]);
            }
        }
        "nycbcra_rgba" => {
            for _ in 0..SAMPLES {
                let c = Nycbcra {
                    ycbcr: Ycbcr {
                        y: rng.next_u64() as u8,
                        cb: rng.next_u64() as u8,
                        cr: rng.next_u64() as u8,
                    },
                    a: rng.next_u64() as u8,
                };
                let (r, g, b, a) = c.rgba();
                h.add(&[r, g, b, a]);
            }
        }
        "cmyk_rgba" => {
            for _ in 0..SAMPLES {
                let c = Cmyk {
                    c: rng.next_u64() as u8,
                    m: rng.next_u64() as u8,
                    y: rng.next_u64() as u8,
                    k: rng.next_u64() as u8,
                };
                let (r, g, b, a) = c.rgba();
                h.add(&[r, g, b, a]);
            }
        }
        "color_rgba" => {
            for _ in 0..SAMPLES / 4 {
                let (_, c) = random_color(&mut rng);
                let (r, g, b, a) = c.rgba();
                h.add(&[r, g, b, a]);
            }
        }
        "model" => {
            let model = match model {
                "rgba" => Model::Rgba,
                "rgba64" => Model::Rgba64,
                "nrgba" => Model::Nrgba,
                "nrgba64" => Model::Nrgba64,
                "gray" => Model::Gray,
                "gray16" => Model::Gray16,
                "alpha" => Model::Alpha,
                "alpha16" => Model::Alpha16,
                "ycbcr" => Model::Ycbcr,
                "nycbcra" => Model::Nycbcra,
                "cmyk" => Model::Cmyk,
                _ => return "unknown model".into(),
            };
            for _ in 0..SAMPLES / 4 {
                let (_, c) = random_color(&mut rng);
                add_color(&mut h, model.convert(c));
            }
        }
        _ => return "unknown op".into(),
    }
    format!("{:016x}", h.0)
}

fn main() -> io::Result<()> {
    let mut out = BufWriter::new(io::stdout().lock());
    for line in io::stdin().lock().lines() {
        let line = line?;
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() != 2 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad request"));
        }
        writeln!(out, "{}", run(fields[0], fields[1]))?;
    }
    Ok(())
}
