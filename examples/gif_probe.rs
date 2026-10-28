//! Line protocol used by `tools/gif_check.py` for Go differential checks.
//! See `tools/gif_oracle.go` for the request and response formats.
use rust_stdlib::image::color::{self, Color, Model, Palette};
use rust_stdlib::image::draw::{self, Drawer, Quantizer};
use rust_stdlib::image::{
    self, gif, Alpha, Alpha16, Config, Gray, Gray16, Image, Nrgba, Nrgba64, Paletted, Rectangle,
    Rgba, Rgba64, Uniform,
};
use std::io::{self, BufRead, BufWriter, Write};

type Res<T> = Result<T, Box<dyn std::error::Error>>;

/// Decode budget shared with tools/gif_oracle.go.
const MAX_PIXELS: u64 = 1 << 20;

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

fn parse_palette(text: &str) -> Res<Palette> {
    if text == "-" {
        return Ok(Palette::default());
    }
    Ok(Palette(
        text.split(',').map(parse_color).collect::<Res<_>>()?,
    ))
}

fn build(spec: &str) -> Res<Box<dyn Image>> {
    let f: Vec<&str> = spec.split('/').collect();
    if f[0] == "Uniform" {
        return Ok(Box::new(Uniform::new(parse_color(f[3])?)));
    }
    let rect = parse_rect(f[1])?;
    if f[0] == "Rect" {
        return Ok(Box::new(rect));
    }
    let pix = from_hex(f[2])?;
    let w = rect.dx() as usize;
    macro_rules! direct {
        ($t:ident, $bpp:expr) => {
            Box::new($t {
                pix: pix.clone().into(),
                stride: $bpp * w,
                rect,
            })
        };
    }
    Ok(match f[0] {
        "RGBA" => direct!(Rgba, 4),
        "NRGBA" => direct!(Nrgba, 4),
        "RGBA64" => direct!(Rgba64, 8),
        "NRGBA64" => direct!(Nrgba64, 8),
        "Gray" => direct!(Gray, 1),
        "Gray16" => direct!(Gray16, 2),
        "Alpha" => direct!(Alpha, 1),
        "Alpha16" => direct!(Alpha16, 2),
        "Paletted" => Box::new(Paletted {
            pix: pix.clone().into(),
            stride: w,
            rect,
            palette: parse_palette(f[3])?,
        }),
        other => return Err(format!("unknown image {other}").into()),
    })
}

/// The first distinct colors in scan order, as `color::Rgba`.
struct FirstQuantizer;

impl Quantizer for FirstQuantizer {
    fn quantize(&self, mut p: Palette, capacity: usize, m: &dyn Image) -> Palette {
        let b = m.bounds();
        for y in b.min.y..b.max.y {
            for x in b.min.x..b.max.x {
                if p.len() == capacity {
                    return p;
                }
                let c = Color::Rgba(color::Rgba::from_color(m.at(x, y)));
                if !p.0.contains(&c) {
                    p.0.push(c);
                }
            }
        }
        p
    }
}

fn palette_hex(p: &Palette) -> String {
    if p.is_empty() {
        return "-".into();
    }
    let mut b = Vec::new();
    for c in &p.0 {
        let (r, g, bl, a) = c.rgba();
        b.extend_from_slice(&[
            (r >> 8) as u8,
            (g >> 8) as u8,
            (bl >> 8) as u8,
            (a >> 8) as u8,
        ]);
    }
    to_hex(&b)
}

fn frame_text(m: &Paletted, delay: i32, disposal: u8) -> String {
    let b = m.rect;
    format!(
        "{},{},{},{}/{delay}/{disposal}/{}/{}",
        b.min.x,
        b.min.y,
        b.max.x,
        b.max.y,
        palette_hex(&m.palette),
        to_hex(&m.pix.to_vec())
    )
}

fn config_palette(c: &Config) -> String {
    match &c.color_model {
        Model::Palette(p) => palette_hex(p),
        _ => "-".into(),
    }
}

fn decode(kind: &str, data: &[u8]) -> String {
    let limits = gif::Limits {
        max_frame_pixels: MAX_PIXELS,
        max_total_pixels: u64::MAX,
        max_frames: usize::MAX,
        ..gif::Limits::default()
    };
    let Ok(cfg) = gif::decode_config(data) else {
        return "err".into();
    };
    if kind == "C" {
        return format!("ok {} {} {}", cfg.width, cfg.height, config_palette(&cfg));
    }
    if cfg.width as u64 * cfg.height as u64 > MAX_PIXELS {
        return "err".into();
    }
    if kind == "D" {
        return match gif::decode_with_limits(data, limits) {
            Ok(m) => format!("ok {}", frame_text(&m, 0, 0)),
            Err(_) => "err".into(),
        };
    }
    let Ok(g) = gif::decode_all_with_limits(data, limits) else {
        return "err".into();
    };
    let cfg = g.config.as_ref().expect("decode_all sets the config");
    let mut out = format!(
        "ok {} {} {} {} {} {}",
        cfg.width,
        cfg.height,
        g.background_index,
        g.loop_count,
        config_palette(cfg),
        g.image.len()
    );
    let disposal = g.disposal.as_ref().expect("decode_all sets disposal");
    for (i, m) in g.image.iter().enumerate() {
        out.push(' ');
        out.push_str(&frame_text(m, g.delay[i], disposal[i]));
    }
    out
}

fn encode_all(f: &[&str]) -> Res<String> {
    let mut g = gif::Gif::default();
    let mut global = Palette::default();
    if f[0] != "zero" {
        let c: Vec<&str> = f[0].split(';').collect();
        let color_model = if c[2] == "model" {
            Model::Rgba
        } else {
            global = parse_palette(c[2])?;
            Model::Palette(global.clone())
        };
        g.config = Some(Config {
            color_model,
            width: c[0].parse()?,
            height: c[1].parse()?,
        });
    }
    g.background_index = f[1].parse()?;
    g.loop_count = f[2].parse()?;
    if f[3] != "nil" {
        g.disposal = Some(if f[3] == "-" {
            Vec::new()
        } else {
            f[3].split(',').map(str::parse).collect::<Result<_, _>>()?
        });
    }
    for frame in &f[4..] {
        let p: Vec<&str> = frame.split(';').collect();
        let palette = if p[3] == "G" {
            global.clone()
        } else if let Some(n) = p[3].strip_prefix("G:") {
            Palette(global.0[..n.parse::<usize>()?].to_vec())
        } else {
            parse_palette(p[3])?
        };
        g.image.push(Paletted {
            pix: from_hex(p[4])?.into(),
            stride: p[1].parse()?,
            rect: parse_rect(p[0])?,
            palette,
        });
        g.delay.push(p[2].parse()?);
    }
    let mut out = Vec::new();
    Ok(match gif::encode_all(&mut out, &g) {
        Ok(()) => to_hex(&out),
        Err(_) => "err".into(),
    })
}

fn encode(f: &[&str]) -> Res<String> {
    let m = build(f[0])?;
    let quantizer = FirstQuantizer;
    let drawer: Option<&dyn Drawer> = match f[3] {
        "Src" => Some(&draw::Op::Src),
        "Over" => Some(&draw::Op::Over),
        "FS" => Some(&draw::FloydSteinberg),
        _ => None,
    };
    let options = gif::Options {
        num_colors: f[1].parse()?,
        quantizer: (f[2] == "first").then_some(&quantizer as &dyn Quantizer),
        drawer,
    };
    let mut out = Vec::new();
    Ok(match gif::encode(&mut out, m.as_ref(), Some(&options)) {
        Ok(()) => to_hex(&out),
        Err(_) => "err".into(),
    })
}

fn main() -> Res<()> {
    let mut out = BufWriter::new(io::stdout().lock());
    for line in io::stdin().lock().lines() {
        let line = line?;
        let (kind, arg) = line.split_once(' ').unwrap_or((&line, ""));
        let fields: Vec<&str> = arg.split_whitespace().collect();
        let reply = match kind {
            "A" | "D" | "C" => decode(kind, &from_hex(arg)?),
            "E" => encode_all(&fields)?,
            "S" => encode(&fields)?,
            other => return Err(format!("bad request {other}").into()),
        };
        writeln!(out, "{reply}")?;
    }
    Ok(())
}
