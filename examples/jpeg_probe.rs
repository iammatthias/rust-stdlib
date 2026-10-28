//! Line protocol used by `tools/jpeg_check.py` for Go differential checks.
//! See `tools/jpeg_oracle.go` for the request and response formats.
use rust_stdlib::image::color::{self, Color, Model, Palette};
use rust_stdlib::image::{
    self, jpeg, Alpha, Cmyk, Gray, Gray16, Image, Nrgba, Nycbcra, Paletted, Rectangle, Rgba,
    Rgba64, Uniform, Ycbcr, YcbcrSubsampleRatio,
};
use std::io::{self, BufRead, BufWriter, Write};

type Res<T> = Result<T, Box<dyn std::error::Error>>;

/// Decode budget shared with tools/jpeg_oracle.go.
const MAX_PIXELS: i64 = 1 << 20;

fn from_hex(text: &str) -> Res<Vec<u8>> {
    if text == "-" {
        return Ok(Vec::new());
    }
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
    Ok(image::rect(v[0], v[1], v[2], v[3]))
}

/// A plane as its length and FNV-1a hash, or in full when `JPEG_FULL` is set.
fn plane(p: &[u8]) -> String {
    if std::env::var_os("JPEG_FULL").is_some() {
        return to_hex(p);
    }
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in p {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{}:{h:016x}", p.len())
}

fn rect_text(r: Rectangle) -> String {
    format!("{},{},{},{}", r.min.x, r.min.y, r.max.x, r.max.y)
}

fn class(error: &io::Error) -> &'static str {
    if let Some(inner) = error.get_ref() {
        if inner.is::<jpeg::FormatError>() {
            return "format";
        }
        if inner.is::<jpeg::UnsupportedError>() {
            return "unsupported";
        }
    }
    if error.kind() == io::ErrorKind::UnexpectedEof {
        return "eof";
    }
    "other"
}

fn fail(error: &io::Error) -> String {
    format!("err {} {}", class(error), error)
}

fn model_name(m: &Model) -> &'static str {
    match m {
        Model::Gray => "Gray",
        Model::Ycbcr => "YCbCr",
        Model::Rgba => "RGBA",
        Model::Cmyk => "CMYK",
        _ => "unknown",
    }
}

fn describe(m: &dyn Image) -> String {
    let any = m.as_any();
    if let Some(g) = any.and_then(|a| a.downcast_ref::<Gray>()) {
        return format!(
            "ok Gray {} {} {}",
            rect_text(g.rect),
            g.stride,
            plane(&g.pix.to_vec())
        );
    }
    if let Some(g) = any.and_then(|a| a.downcast_ref::<Rgba>()) {
        return format!(
            "ok RGBA {} {} {}",
            rect_text(g.rect),
            g.stride,
            plane(&g.pix.to_vec())
        );
    }
    if let Some(g) = any.and_then(|a| a.downcast_ref::<Cmyk>()) {
        return format!(
            "ok CMYK {} {} {}",
            rect_text(g.rect),
            g.stride,
            plane(&g.pix.to_vec())
        );
    }
    if let Some(g) = any.and_then(|a| a.downcast_ref::<Ycbcr>()) {
        return format!(
            "ok YCbCr {} {} {} {} {} {} {}",
            rect_text(g.rect),
            g.subsample_ratio as u8,
            g.y_stride,
            g.c_stride,
            plane(&g.y.to_vec()),
            plane(&g.cb.to_vec()),
            plane(&g.cr.to_vec())
        );
    }
    "ok other".to_owned()
}

fn decode_line(data: &[u8]) -> String {
    if let Ok(cfg) = jpeg::decode_config(data) {
        if i64::from(cfg.width) * i64::from(cfg.height) > MAX_PIXELS {
            return "skip".to_owned();
        }
    }
    match jpeg::decode(data) {
        Ok(m) => describe(m.as_ref()),
        Err(error) => fail(&error),
    }
}

/// Exposes only the `Image` methods of the wrapped image, which forces the
/// encoder's generic color path.
struct Hidden(Box<dyn Image>);

impl Image for Hidden {
    fn color_model(&self) -> Model {
        self.0.color_model()
    }
    fn bounds(&self) -> Rectangle {
        self.0.bounds()
    }
    fn at(&self, x: i32, y: i32) -> Color {
        self.0.at(x, y)
    }
}

fn ratio(n: usize) -> YcbcrSubsampleRatio {
    match n {
        0 => YcbcrSubsampleRatio::Ratio444,
        1 => YcbcrSubsampleRatio::Ratio422,
        2 => YcbcrSubsampleRatio::Ratio420,
        3 => YcbcrSubsampleRatio::Ratio440,
        4 => YcbcrSubsampleRatio::Ratio411,
        _ => YcbcrSubsampleRatio::Ratio410,
    }
}

fn encode_line(f: &[&str]) -> Res<String> {
    let kind = f[0];
    let r = parse_rect(f[1])?;
    let opts = if f[2] == "nil" {
        None
    } else {
        Some(jpeg::Options {
            quality: f[2].parse()?,
        })
    };
    let hide = f[3] == "1";
    let extra = f[4];
    let data = from_hex(f[5])?;
    let w = r.dx() as usize;
    macro_rules! direct {
        ($t:ident, $bpp:expr) => {
            Box::new($t {
                pix: data.into(),
                stride: $bpp * w,
                rect: r,
            }) as Box<dyn Image>
        };
    }
    let mut m: Box<dyn Image> = match kind {
        "Gray" => direct!(Gray, 1),
        "RGBA" => direct!(Rgba, 4),
        "NRGBA" => direct!(Nrgba, 4),
        "RGBA64" => direct!(Rgba64, 8),
        "Gray16" => direct!(Gray16, 2),
        "Alpha" => direct!(Alpha, 1),
        "CMYK" => direct!(Cmyk, 4),
        "YCbCr" | "NYCbCrA" => {
            let mut img = Ycbcr::new(r, ratio(extra.parse()?));
            let mut rest = &data[..];
            for plane in [&mut img.y, &mut img.cb, &mut img.cr] {
                let n = plane.len().min(rest.len());
                for (i, v) in rest[..n].iter().enumerate() {
                    plane.set(i, *v);
                }
                rest = &rest[n..];
            }
            if kind == "NYCbCrA" {
                let mut a = Nycbcra {
                    ycbcr: img,
                    a: vec![0; w * r.dy() as usize].into(),
                    a_stride: w,
                };
                let n = a.a.len().min(rest.len());
                for (i, v) in rest[..n].iter().enumerate() {
                    a.a.set(i, *v);
                }
                Box::new(a)
            } else {
                Box::new(img)
            }
        }
        "Paletted" => {
            let mut palette = Vec::new();
            for c in extra.split(',') {
                let b = from_hex(c)?;
                palette.push(Color::from(color::Rgba {
                    r: b[0],
                    g: b[1],
                    b: b[2],
                    a: b[3],
                }));
            }
            Box::new(Paletted {
                pix: data.into(),
                stride: w,
                rect: r,
                palette: Palette(palette),
            })
        }
        "Uniform" => Box::new(Uniform::new(
            color::Rgba {
                r: data[0],
                g: data[1],
                b: data[2],
                a: data[3],
            }
            .into(),
        )),
        other => return Err(format!("unknown kind {other}").into()),
    };
    if hide {
        m = Box::new(Hidden(m));
    }
    let mut out = Vec::new();
    Ok(match jpeg::encode(&mut out, m.as_ref(), opts.as_ref()) {
        Ok(()) => to_hex(&out),
        Err(error) => format!("err {error}"),
    })
}

fn handle(line: &str) -> Res<String> {
    let f: Vec<&str> = line.split_whitespace().collect();
    Ok(match f[0] {
        "D" => decode_line(&from_hex(f[1])?),
        "C" => match jpeg::decode_config(&from_hex(f[1])?[..]) {
            Ok(cfg) => format!(
                "ok {} {} {}",
                model_name(&cfg.color_model),
                cfg.width,
                cfg.height
            ),
            Err(error) => fail(&error),
        },
        "R" => {
            let data = from_hex(f[1])?;
            match jpeg::decode_config(&data[..]) {
                Err(error) => fail(&error),
                Ok(cfg) if i64::from(cfg.width) * i64::from(cfg.height) > MAX_PIXELS => {
                    "skip".to_owned()
                }
                Ok(_) => match image::decode(&data[..]) {
                    Ok((m, name)) => format!("ok {name} {}", rect_text(m.bounds())),
                    Err(error) => format!("err {error}"),
                },
            }
        }
        "E" => encode_line(&f[1..])?,
        other => return Err(format!("bad request {other}").into()),
    })
}

fn main() -> Res<()> {
    let stdin = io::stdin();
    let mut out = BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let result = std::panic::catch_unwind(|| handle(line.trim()));
        match result {
            Ok(Ok(text)) => writeln!(out, "{text}")?,
            Ok(Err(error)) => return Err(error),
            Err(_) => writeln!(out, "rust-panic")?,
        }
    }
    Ok(())
}
