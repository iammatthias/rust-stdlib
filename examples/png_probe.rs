//! Line protocol used by `tools/png_check.py` for Go differential checks.
//! See `tools/png_oracle.go` for the request and response formats.
use rust_stdlib::image::color::{self, Color, Model, Palette};
use rust_stdlib::image::{
    self, png, Alpha, Alpha16, AnyImage, Gray, Gray16, Image, Nrgba, Nrgba64, Paletted, Rectangle,
    Rgba, Rgba64,
};
use std::io::{self, BufRead, BufWriter, Write};

type Res<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Default)]
struct Pool(std::sync::Mutex<Vec<png::EncoderBuffer>>);

impl png::EncoderBufferPool for Pool {
    fn get(&self) -> Option<png::EncoderBuffer> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop()
    }
    fn put(&self, buffer: png::EncoderBuffer) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(buffer);
    }
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

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_rect(text: &str) -> Res<Rectangle> {
    let v: Vec<i32> = text.split(',').map(str::parse).collect::<Result<_, _>>()?;
    Ok(Rectangle {
        min: image::pt(v[0], v[1]),
        max: image::pt(v[2], v[3]),
    })
}

fn parse_color(text: &str) -> Res<Color> {
    let (tag, h) = text.split_once(':').ok_or("bad color")?;
    let b = from_hex(h)?;
    let u = |i: usize| u16::from_be_bytes([b[i], b[i + 1]]);
    Ok(match tag {
        "RGBA" => color::Rgba {
            r: b[0],
            g: b[1],
            b: b[2],
            a: b[3],
        }
        .into(),
        "NRGBA" => color::Nrgba {
            r: b[0],
            g: b[1],
            b: b[2],
            a: b[3],
        }
        .into(),
        "RGBA64" => color::Rgba64 {
            r: u(0),
            g: u(2),
            b: u(4),
            a: u(6),
        }
        .into(),
        "NRGBA64" => color::Nrgba64 {
            r: u(0),
            g: u(2),
            b: u(4),
            a: u(6),
        }
        .into(),
        "Gray" => color::Gray { y: b[0] }.into(),
        "Gray16" => color::Gray16 { y: u(0) }.into(),
        "Alpha" => color::Alpha { a: b[0] }.into(),
        "Alpha16" => color::Alpha16 { a: u(0) }.into(),
        _ => return Err(format!("unknown color {tag}").into()),
    })
}

fn encode(spec: &str) -> Res<Result<Vec<u8>, Vec<u8>>> {
    let f: Vec<&str> = spec.split(';').collect();
    let rect = parse_rect(f[1])?;
    let level = match f[2] {
        "0" => png::CompressionLevel::Default,
        "-1" => png::CompressionLevel::NoCompression,
        "-2" => png::CompressionLevel::BestSpeed,
        "-3" => png::CompressionLevel::BestCompression,
        other => return Err(format!("bad level {other}").into()),
    };
    let pix = from_hex(f[3])?;
    let palette = if f[4].is_empty() {
        Palette::default()
    } else {
        Palette(f[4].split(',').map(parse_color).collect::<Res<_>>()?)
    };
    let w = rect.dx() as usize;
    let sub = if f[5].is_empty() {
        None
    } else {
        Some(parse_rect(f[5])?)
    };
    macro_rules! direct {
        ($t:ident, $bpp:expr) => {{
            let mut img = $t {
                pix: pix.clone().into(),
                stride: $bpp * w,
                rect,
            };
            Box::new(match sub {
                Some(r) => img.sub_image(r),
                None => img,
            }) as Box<dyn Image>
        }};
    }
    let m: Box<dyn Image> = match f[0] {
        "RGBA" => direct!(Rgba, 4),
        "NRGBA" => direct!(Nrgba, 4),
        "RGBA64" => direct!(Rgba64, 8),
        "NRGBA64" => direct!(Nrgba64, 8),
        "Gray" => direct!(Gray, 1),
        "Gray16" => direct!(Gray16, 2),
        "Alpha" => direct!(Alpha, 1),
        "Alpha16" => direct!(Alpha16, 2),
        "Paletted" => {
            let mut img = Paletted {
                pix: pix.clone().into(),
                stride: w,
                rect,
                palette,
            };
            Box::new(match sub {
                Some(r) => img.sub_image(r),
                None => img,
            })
        }
        "Rect" => Box::new(rect),
        other => return Err(format!("unknown image {other}").into()),
    };
    let mut out = Vec::new();
    // Encoding through a shared pool checks that recycled buffers never leak
    // bytes from an earlier image into the next one.
    let pool: std::sync::Arc<dyn png::EncoderBufferPool> = std::sync::Arc::new(Pool::default());
    let encoder = png::Encoder {
        compression_level: level,
        buffer_pool: Some(pool),
    };
    Ok(match encoder.encode(&mut out, m.as_ref()) {
        Ok(()) => Ok(out),
        Err(_) => Err(out),
    })
}

fn palette_hex(p: &Palette) -> String {
    let mut b = Vec::new();
    for c in &p.0 {
        let (r, g, bl, a) = c.rgba();
        for v in [r, g, bl, a] {
            b.extend_from_slice(&(v as u16).to_be_bytes());
        }
    }
    format!("{}/{}", to_hex(&b), p.len())
}

fn describe(m: &AnyImage) -> String {
    let name = match m {
        AnyImage::Rgba(_) => "RGBA",
        AnyImage::Nrgba(_) => "NRGBA",
        AnyImage::Rgba64(_) => "RGBA64",
        AnyImage::Nrgba64(_) => "NRGBA64",
        AnyImage::Gray(_) => "Gray",
        AnyImage::Gray16(_) => "Gray16",
        AnyImage::Paletted(_) => "Paletted",
        AnyImage::Alpha(_) | AnyImage::Alpha16(_) => "other",
    };
    let b = m.bounds();
    let mut px = Vec::new();
    for y in b.min.y..b.max.y {
        for x in b.min.x..b.max.x {
            let c = m.rgba64_at(x, y);
            for v in [c.r, c.g, c.b, c.a] {
                px.extend_from_slice(&v.to_be_bytes());
            }
        }
    }
    let pal = match m {
        AnyImage::Paletted(p) => palette_hex(&p.palette),
        _ => "-".into(),
    };
    format!(
        "ok {name} {},{},{},{} {} {pal}",
        b.min.x,
        b.min.y,
        b.max.x,
        b.max.y,
        to_hex(&px)
    )
}

fn model_name(m: &Model) -> &'static str {
    match m {
        Model::Rgba => "RGBA",
        Model::Nrgba => "NRGBA",
        Model::Rgba64 => "RGBA64",
        Model::Nrgba64 => "NRGBA64",
        Model::Gray => "Gray",
        Model::Gray16 => "Gray16",
        Model::Palette(_) => "Palette",
        Model::Alpha
        | Model::Alpha16
        | Model::Ycbcr
        | Model::Nycbcra
        | Model::Cmyk
        | Model::Func(_)
        | Model::Uniform(_) => "other",
    }
}

fn main() -> Res<()> {
    let limits = png::Limits {
        max_width: 4096,
        max_height: 4096,
        max_pixels: 1 << 20,
        ..png::Limits::default()
    };
    let mut out = BufWriter::new(io::stdout().lock());
    for line in io::stdin().lock().lines() {
        let line = line?;
        let (kind, arg) = line.split_once(' ').unwrap_or((&line, ""));
        match kind {
            "E" => match encode(arg)? {
                Ok(bytes) => writeln!(out, "{}", to_hex(&bytes))?,
                Err(partial) => writeln!(out, "err {}", to_hex(&partial))?,
            },
            "I" if rust_stdlib::image::decode_config(&from_hex(arg)?[..]).is_ok_and(
                |(c, _)| c.width > 4096 || c.height > 4096 || c.width * c.height > 1 << 20,
            ) =>
            {
                writeln!(out, "skip")?
            }
            "I" => match rust_stdlib::image::decode(&from_hex(arg)?[..]) {
                Ok((_, name)) => writeln!(out, "ok {name:?}")?,
                Err(e) => writeln!(out, "err {:?}", e.format)?,
            },
            "D" => match png::decode_with_limits(&from_hex(arg)?[..], limits) {
                Ok(m) => writeln!(out, "{}", describe(&m))?,
                Err(_) => writeln!(out, "err")?,
            },
            "C" => match png::decode_config(&from_hex(arg)?[..]) {
                Ok(c) => {
                    let pal = match &c.color_model {
                        Model::Palette(p) => palette_hex(p),
                        _ => "-".into(),
                    };
                    writeln!(
                        out,
                        "ok {} {} {} {pal}",
                        c.width,
                        c.height,
                        model_name(&c.color_model)
                    )?;
                }
                Err(_) => writeln!(out, "err")?,
            },
            "TD" | "TC" | "TI" | "TJ" => {
                let data = from_hex(arg)?;
                let wide = |w: i32, h: i32| w > 4096 || h > 4096 || w * h > 1 << 20;
                let text = |r: Result<(), Box<dyn std::error::Error>>| match r {
                    Ok(()) => "ok".to_owned(),
                    Err(e) => format!("err {e}"),
                };
                let result = match kind {
                    "TD" => match png::decode_config(&data[..]) {
                        Ok(c) if wide(c.width, c.height) => "skip".to_owned(),
                        _ => text(
                            png::decode_with_limits(&data[..], limits)
                                .map(drop)
                                .map_err(Into::into),
                        ),
                    },
                    "TC" => text(png::decode_config(&data[..]).map(drop).map_err(Into::into)),
                    "TI" => match rust_stdlib::image::decode_config(&data[..]) {
                        Ok((c, _)) if wide(c.width, c.height) => "skip".to_owned(),
                        _ => text(
                            rust_stdlib::image::decode(&data[..])
                                .map(drop)
                                .map_err(Into::into),
                        ),
                    },
                    _ => text(
                        rust_stdlib::image::decode_config(&data[..])
                            .map(drop)
                            .map_err(Into::into),
                    ),
                };
                writeln!(out, "{result}")?;
            }
            other => return Err(format!("bad request {other}").into()),
        }
    }
    Ok(())
}
