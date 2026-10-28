//! Line protocol used by `tools/draw_check.py` for Go differential checks.
//! See `tools/draw_oracle.go` for the request and response formats.
use rust_stdlib::image::color::{self, Color, Palette};
use rust_stdlib::image::draw::{self, Drawer};
use rust_stdlib::image::{
    self, Alpha, Alpha16, AnyImage, Gray, Gray16, Image, Nrgba, Nrgba64, Paletted, Point,
    Rectangle, Rgba, Rgba64, Uniform,
};
use std::io::{self, BufRead, BufWriter, Write};

type Res<T> = Result<T, Box<dyn std::error::Error>>;

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

fn parse_point(text: &str) -> Res<Point> {
    let v: Vec<i32> = text.split(',').map(str::parse).collect::<Result<_, _>>()?;
    Ok(image::pt(v[0], v[1]))
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

fn build_dst(spec: &str) -> Res<AnyImage> {
    let f: Vec<&str> = spec.split('/').collect();
    let rect = parse_rect(f[1])?;
    let pix = from_hex(f[2])?;
    let w = rect.dx() as usize;
    macro_rules! direct {
        ($t:ident, $bpp:expr) => {
            AnyImage::$t($t {
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
        "Paletted" => AnyImage::Paletted(Paletted {
            pix: pix.clone().into(),
            stride: w,
            rect,
            palette: parse_palette(f[3])?,
        }),
        other => return Err(format!("unknown image {other}").into()),
    })
}

fn build(spec: &str) -> Res<Box<dyn Image>> {
    let f: Vec<&str> = spec.split('/').collect();
    Ok(match f[0] {
        "Uniform" => Box::new(Uniform::new(parse_color(f[3])?)),
        "Rect" => Box::new(parse_rect(f[1])?),
        _ => match build_dst(spec)? {
            // Unwrap so the draw fast paths see the same concrete types as
            // Go; AnyImage forwards to them as well.
            AnyImage::Rgba(i) => Box::new(i),
            AnyImage::Paletted(i) => Box::new(i),
            other => Box::new(other),
        },
    })
}

fn pix(m: &AnyImage) -> Vec<u8> {
    match m {
        AnyImage::Rgba(i) => i.pix.to_vec(),
        AnyImage::Rgba64(i) => i.pix.to_vec(),
        AnyImage::Nrgba(i) => i.pix.to_vec(),
        AnyImage::Nrgba64(i) => i.pix.to_vec(),
        AnyImage::Gray(i) => i.pix.to_vec(),
        AnyImage::Gray16(i) => i.pix.to_vec(),
        AnyImage::Alpha(i) => i.pix.to_vec(),
        AnyImage::Alpha16(i) => i.pix.to_vec(),
        AnyImage::Paletted(i) => i.pix.to_vec(),
    }
}

fn stride(m: &AnyImage) -> usize {
    match m {
        AnyImage::Rgba(i) => i.stride,
        AnyImage::Rgba64(i) => i.stride,
        AnyImage::Nrgba(i) => i.stride,
        AnyImage::Nrgba64(i) => i.stride,
        AnyImage::Gray(i) => i.stride,
        AnyImage::Gray16(i) => i.stride,
        AnyImage::Alpha(i) => i.stride,
        AnyImage::Alpha16(i) => i.stride,
        AnyImage::Paletted(i) => i.stride,
    }
}

/// `U`: SubImage, then a set through the parent and one through the child.
fn sub_image(f: &[&str]) -> Res<String> {
    let mut parent = build_dst(f[1])?;
    let r = parse_rect(f[2])?;
    let mut sub: AnyImage = match &mut parent {
        AnyImage::Rgba(i) => i.sub_image(r).into(),
        AnyImage::Rgba64(i) => i.sub_image(r).into(),
        AnyImage::Nrgba(i) => i.sub_image(r).into(),
        AnyImage::Nrgba64(i) => i.sub_image(r).into(),
        AnyImage::Gray(i) => i.sub_image(r).into(),
        AnyImage::Gray16(i) => i.sub_image(r).into(),
        AnyImage::Alpha(i) => i.sub_image(r).into(),
        AnyImage::Alpha16(i) => i.sub_image(r).into(),
        AnyImage::Paletted(i) => i.sub_image(r).into(),
    };
    let p = parse_point(f[3])?;
    draw::Image::set(&mut parent, p.x, p.y, parse_color(f[4])?);
    let c = parse_point(f[5])?;
    draw::Image::set(&mut sub, c.x, c.y, parse_color(f[6])?);
    let b = Image::bounds(&sub);
    Ok(format!(
        "{} {} {} {},{},{},{}",
        to_hex(&pix(&parent)),
        to_hex(&pix(&sub)),
        stride(&sub),
        b.min.x,
        b.min.y,
        b.max.x,
        b.max.y
    ))
}

fn run(f: &[&str]) -> Res<String> {
    if f[0] == "U" {
        return sub_image(f);
    }
    let mut dst = build_dst(f[1])?;
    match f[0] {
        "D" => {
            let mask = if f[3] == "nil" {
                None
            } else {
                Some(build(f[3])?)
            };
            let op = if f[7] == "Src" {
                draw::Op::Src
            } else {
                draw::Op::Over
            };
            let (r, sp, mp) = (parse_rect(f[4])?, parse_point(f[5])?, parse_point(f[6])?);
            if f[2] == "SELF" {
                draw::draw_mask_within(&mut dst, r, sp, mask.as_deref(), mp, op);
            } else {
                let src = build(f[2])?;
                draw::draw_mask(&mut dst, r, src.as_ref(), sp, mask.as_deref(), mp, op);
            }
        }
        "O" => {
            let src = build(f[2])?;
            let op = if f[5] == "Src" {
                draw::Op::Src
            } else {
                draw::Op::Over
            };
            op.draw(
                &mut dst,
                parse_rect(f[3])?,
                src.as_ref(),
                parse_point(f[4])?,
            );
        }
        "F" => {
            let src = build(f[2])?;
            draw::FloydSteinberg.draw(
                &mut dst,
                parse_rect(f[3])?,
                src.as_ref(),
                parse_point(f[4])?,
            );
        }
        other => return Err(format!("bad request {other}").into()),
    }
    Ok(to_hex(&pix(&dst)))
}

fn main() -> Res<()> {
    let mut out = BufWriter::new(io::stdout().lock());
    for line in io::stdin().lock().lines() {
        let line = line?;
        let fields: Vec<&str> = line.split_whitespace().collect();
        // Go panics where Rust panics (an index outside a palette, an empty
        // palette under dithering); both are reported as "panic".
        let reply = std::panic::catch_unwind(|| run(&fields).map_err(|e| e.to_string()));
        match reply {
            Ok(Ok(text)) => writeln!(out, "{text}")?,
            Ok(Err(message)) => return Err(message.into()),
            Err(_) => writeln!(out, "panic")?,
        }
    }
    Ok(())
}
