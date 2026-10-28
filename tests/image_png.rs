use rust_stdlib::compress;
use rust_stdlib::hash::crc32::checksum_ieee;
use rust_stdlib::image::color::{self, Color, Model, Palette};
use rust_stdlib::image::png::{self, CompressionLevel, Encoder, Limits};
use rust_stdlib::image::{
    pt, rect, Alpha, Alpha16, AnyImage, Gray, Gray16, Image, Nrgba, Nrgba64, Paletted, Pix,
    Rectangle, Rgba, Rgba64,
};
use std::io::{self, Read, Write};

fn chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut out = (data.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    let mut body = kind.to_vec();
    body.extend_from_slice(data);
    out.extend_from_slice(&checksum_ieee(&body).to_be_bytes());
    out
}

fn ihdr(w: u32, h: u32, depth: u8, color_type: u8, interlace: u8) -> Vec<u8> {
    let mut data = w.to_be_bytes().to_vec();
    data.extend_from_slice(&h.to_be_bytes());
    data.extend_from_slice(&[depth, color_type, 0, 0, interlace]);
    chunk(b"IHDR", &data)
}

fn zlib(raw: &[u8]) -> Vec<u8> {
    let mut z = compress::zlib::Writer::new(Vec::new());
    z.write_all(raw).unwrap();
    z.close().unwrap();
    z.into_inner()
}

fn png(chunks: &[Vec<u8>]) -> Vec<u8> {
    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    for c in chunks {
        out.extend_from_slice(c);
    }
    out
}

/// A 3x2 8-bit grayscale image with the given scanlines.
fn gray_png(raw: &[u8]) -> Vec<u8> {
    png(&[
        ihdr(3, 2, 8, 0, 0),
        chunk(b"IDAT", &zlib(raw)),
        chunk(b"IEND", &[]),
    ])
}

const GRAY_RAW: [u8; 8] = [0, 10, 20, 30, 0, 40, 50, 60];

fn pixels(m: &dyn Image) -> Vec<color::Rgba64> {
    let b = m.bounds();
    (b.min.y..b.max.y)
        .flat_map(|y| (b.min.x..b.max.x).map(move |x| (x, y)))
        .map(|(x, y)| m.rgba64_at(x, y))
        .collect()
}

#[test]
fn color_models_match_go_arithmetic() {
    let c: Color = color::Nrgba {
        r: 0xff,
        g: 0x80,
        b: 0,
        a: 0x80,
    }
    .into();
    assert_eq!(c.rgba(), (0x8080, 0x4080, 0, 0x8080));
    assert_eq!(
        color::Rgba::from_color(c),
        color::Rgba {
            r: 0x80,
            g: 0x40,
            b: 0,
            a: 0x80
        }
    );
    let premultiplied: Color = color::Rgba {
        r: 0x40,
        g: 0x20,
        b: 0x10,
        a: 0x80,
    }
    .into();
    assert_eq!(
        color::Nrgba::from_color(premultiplied),
        color::Nrgba {
            r: 0x7f,
            g: 0x3f,
            b: 0x1f,
            a: 0x80
        }
    );
    assert_eq!(
        color::Nrgba::from_color(color::TRANSPARENT.into()),
        color::Nrgba::default()
    );
    // Invalid premultiplied input (r > a) truncates exactly as Go's uint8 cast.
    let invalid: Color = color::Rgba {
        r: 0xff,
        g: 0,
        b: 0,
        a: 0x10,
    }
    .into();
    assert_eq!(color::Nrgba::from_color(invalid).r, 0xef);
    assert_eq!(
        color::Gray::from_color(
            color::Rgba {
                r: 0xff,
                g: 0,
                b: 0,
                a: 0xff
            }
            .into()
        )
        .y,
        0x4c
    );
    assert_eq!(color::Gray16::from_color(color::WHITE.into()).y, 0xffff);
    assert_eq!(color::Alpha::from_color(c).a, 0x80);
    assert_eq!(
        Model::Alpha16.convert(c),
        Color::Alpha16(color::Alpha16 { a: 0x8080 })
    );
    assert_eq!(
        Model::Nrgba64.convert(
            color::Rgba64 {
                r: 0x8000,
                g: 0,
                b: 0,
                a: 0x8000
            }
            .into()
        ),
        Color::Nrgba64(color::Nrgba64 {
            r: 0xffff,
            g: 0,
            b: 0,
            a: 0x8000
        })
    );
}

#[test]
fn palette_index_uses_first_nearest_entry() {
    let p = Palette(vec![
        color::Gray { y: 0 }.into(),
        color::Gray { y: 200 }.into(),
        color::Gray { y: 100 }.into(),
        color::Gray { y: 100 }.into(),
    ]);
    assert_eq!(p.index(color::Gray { y: 90 }.into()), 2);
    assert_eq!(p.index(color::Gray { y: 100 }.into()), 2);
    assert_eq!(p.index(color::WHITE.into()), 1);
    assert_eq!(
        p.convert(color::Gray { y: 10 }.into()),
        Some(color::Gray { y: 0 }.into())
    );
    assert_eq!(Palette::default().convert(color::BLACK.into()), None);
    assert_eq!(Palette::default().index(color::BLACK.into()), 0);
}

#[test]
fn rectangle_operations_follow_go() {
    let r = rect(10, 20, 0, 5);
    assert_eq!(
        r,
        Rectangle {
            min: pt(0, 5),
            max: pt(10, 20)
        }
    );
    assert_eq!((r.dx(), r.dy(), r.size()), (10, 15, pt(10, 15)));
    assert_eq!(r.intersect(rect(5, 0, 50, 10)), rect(5, 5, 10, 10));
    assert_eq!(r.intersect(rect(20, 20, 30, 30)), Rectangle::default());
    assert_eq!(r.union(rect(-1, 0, 2, 2)), rect(-1, 0, 10, 20));
    assert_eq!(r.union(Rectangle::default()), r);
    assert!(rect(1, 1, 1, 5).is_empty());
    assert!(rect(1, 1, 1, 5).equals(rect(3, 3, 3, 3)));
    assert!(rect(2, 6, 3, 7).is_in(r) && !rect(-1, 6, 3, 7).is_in(r));
    assert!(Rectangle::default().is_in(rect(5, 5, 6, 6)));
    assert!(r.overlaps(rect(9, 19, 11, 21)) && !r.overlaps(rect(10, 0, 11, 30)));
    assert_eq!(r.inset(2), rect(2, 7, 8, 18));
    assert_eq!(rect(0, 0, 3, 100).inset(2), rect(1, 2, 1, 98));
    assert_eq!(r + pt(1, 1), rect(1, 6, 11, 21));
    assert_eq!(r - pt(1, 1), rect(-1, 4, 9, 19));
    assert_eq!(pt(-1, 23).modulo(rect(0, 0, 10, 10)), pt(9, 3));
    assert_eq!(pt(7, -7) / 2, pt(3, -3));
    assert_eq!(pt(2, 3) * 4, pt(8, 12));
    assert!(pt(0, 5).is_in(r) && !pt(10, 5).is_in(r));
    assert_eq!(
        Rectangle {
            min: pt(4, 4),
            max: pt(1, 1)
        }
        .canon(),
        rect(1, 1, 4, 4)
    );
    assert_eq!(r.to_string(), "(0,5)-(10,20)");
    assert_eq!(r.at(0, 5), color::OPAQUE.into());
    assert_eq!(r.at(10, 5), color::TRANSPARENT.into());
}

#[test]
fn images_set_at_sub_image_and_opaque() {
    let mut m = Rgba::new(rect(-2, -2, 3, 1));
    assert_eq!(m.pix.len(), 5 * 3 * 4);
    m.set(
        -2,
        -2,
        color::Nrgba {
            r: 255,
            g: 0,
            b: 0,
            a: 128,
        }
        .into(),
    );
    assert_eq!(
        m.pixel_at(-2, -2),
        color::Rgba {
            r: 128,
            g: 0,
            b: 0,
            a: 128
        }
    );
    m.set(9, 9, color::WHITE.into());
    assert_eq!(m.at(9, 9), color::Rgba::default().into());
    assert!(!m.opaque());
    let sub = m.sub_image(rect(-3, -3, 0, -1));
    assert_eq!(sub.rect, rect(-2, -2, 0, -1));
    assert_eq!(
        sub.stride, 20,
        "SubImage keeps the parent's stride, as Go does"
    );
    assert_eq!(sub.pixel_at(-2, -2), m.pixel_at(-2, -2));
    assert_eq!(m.sub_image(rect(50, 50, 60, 60)).rect, Rectangle::default());
    let mut g = Gray16::new(rect(0, 0, 2, 2));
    g.set(
        1,
        1,
        color::Rgba64 {
            r: 0xffff,
            g: 0xffff,
            b: 0xffff,
            a: 0xffff,
        }
        .into(),
    );
    assert_eq!(g.pix.to_vec()[6..8], [0xff, 0xff]);
    assert!(g.opaque());
    assert!(Alpha::new(rect(0, 0, 1, 1))
        .sub_image(rect(5, 5, 6, 6))
        .opaque());
    assert!(Rgba::try_new(Rectangle {
        min: pt(5, 0),
        max: pt(0, 1)
    })
    .is_none());
    assert!(Nrgba64::try_new(rect(0, 0, i32::MAX, i32::MAX)).is_none());

    let mut p = Paletted::new(
        rect(0, 0, 2, 1),
        Palette(vec![color::BLACK.into(), color::TRANSPARENT.into()]),
    );
    p.set(1, 0, color::Alpha { a: 0 }.into());
    assert_eq!(p.color_index_at(1, 0), 1);
    assert!(!p.opaque());
    assert_eq!(p.at(100, 100), color::BLACK.into());
    p.set_color_index(0, 0, 9);
    // Go panics on an index outside the palette.
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| p.at(0, 0))).is_err());
    assert!(matches!(p.color_model(), Model::Palette(_)));
}

#[test]
fn every_image_type_round_trips_with_go_color_types() {
    let r = rect(3, -1, 8, 4);
    let mut seed = 7u32;
    let mut fill = |pix: &mut Pix| {
        pix.with_mut(|pix| {
            for b in pix.iter_mut() {
                seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
                *b = (seed >> 16) as u8;
            }
        });
    };
    let palette = Palette(vec![
        color::Rgba {
            r: 1,
            g: 2,
            b: 3,
            a: 255,
        }
        .into(),
        color::Nrgba {
            r: 9,
            g: 8,
            b: 7,
            a: 6,
        }
        .into(),
        color::Gray { y: 77 }.into(),
    ]);
    let mut images: Vec<(Box<dyn Image>, u8, u8, &str)> = Vec::new();
    macro_rules! add {
        ($t:ident, $depth:expr, $ct:expr, $decoded:expr) => {{
            let mut m = $t::new(r);
            fill(&mut m.pix);
            images.push((Box::new(m), $depth, $ct, $decoded));
        }};
    }
    add!(Rgba, 8, 6, "nrgba");
    add!(Nrgba, 8, 6, "nrgba");
    add!(Rgba64, 16, 6, "nrgba64");
    add!(Nrgba64, 16, 6, "nrgba64");
    add!(Gray, 8, 0, "gray");
    add!(Gray16, 16, 0, "gray16");
    add!(Alpha, 8, 6, "nrgba");
    add!(Alpha16, 16, 6, "nrgba64");
    let mut opaque = Nrgba::new(r);
    fill(&mut opaque.pix);
    opaque
        .pix
        .with_mut(|p| p.iter_mut().skip(3).step_by(4).for_each(|a| *a = 0xff));
    images.push((Box::new(opaque), 8, 2, "rgba"));
    let mut p = Paletted::new(r, palette);
    p.pix.with_mut(|p| {
        p.iter_mut()
            .enumerate()
            .for_each(|(i, v)| *v = (i % 3) as u8)
    });
    images.push((Box::new(p), 2, 3, "paletted"));
    images.push((Box::new(rect(0, 0, 3, 3)), 16, 2, "rgba64"));

    for (m, depth, color_type, decoded_type) in &images {
        for level in [
            CompressionLevel::Default,
            CompressionLevel::NoCompression,
            CompressionLevel::BestSpeed,
            CompressionLevel::BestCompression,
        ] {
            let mut bytes = Vec::new();
            Encoder {
                compression_level: level,
                ..Default::default()
            }
            .encode(&mut bytes, m.as_ref())
            .unwrap();
            assert_eq!(
                (bytes[24], bytes[25]),
                (*depth, *color_type),
                "{decoded_type}"
            );
            let decoded = png::decode(&bytes[..]).unwrap();
            let kind = match &decoded {
                AnyImage::Rgba(_) => "rgba",
                AnyImage::Nrgba(_) => "nrgba",
                AnyImage::Rgba64(_) => "rgba64",
                AnyImage::Nrgba64(_) => "nrgba64",
                AnyImage::Gray(_) => "gray",
                AnyImage::Gray16(_) => "gray16",
                AnyImage::Paletted(_) => "paletted",
                _ => "other",
            };
            assert_eq!(kind, *decoded_type);
            let b = m.bounds();
            assert_eq!(decoded.bounds(), rect(0, 0, b.dx(), b.dy()));
            let reencoded = {
                let mut out = Vec::new();
                png::encode(&mut out, &decoded).unwrap();
                png::decode(&out[..]).unwrap()
            };
            assert_eq!(pixels(&decoded), pixels(&reencoded));
            let config = png::decode_config(&bytes[..]).unwrap();
            assert_eq!((config.width, config.height), (b.dx(), b.dy()));
        }
    }
}

#[test]
fn opaque_and_lossless_types_preserve_pixels_exactly() {
    let mut g = Gray16::new(rect(0, 0, 7, 3));
    g.pix.with_mut(|p| {
        p.iter_mut()
            .enumerate()
            .for_each(|(i, v)| *v = (i * 37) as u8)
    });
    let mut out = Vec::new();
    png::encode(&mut out, &g).unwrap();
    assert_eq!(png::decode(&out[..]).unwrap(), AnyImage::Gray16(g));
    let mut n = Nrgba::new(rect(0, 0, 1, 1));
    n.pix.copy_from_slice(&[1, 2, 3, 4]);
    out.clear();
    png::encode(&mut out, &n).unwrap();
    assert_eq!(png::decode(&out[..]).unwrap(), AnyImage::Nrgba(n));
}

#[test]
fn decodes_low_bit_depths_interlacing_filters_and_transparency() {
    // 1-bit gray, 5x3, with tRNS selecting white; Adam7 interlaced.
    let (w, h) = (5usize, 3usize);
    let passes = [
        (8, 8, 0, 0),
        (8, 8, 4, 0),
        (4, 8, 0, 4),
        (4, 4, 2, 0),
        (2, 4, 0, 2),
        (2, 2, 1, 0),
        (1, 2, 0, 1),
    ];
    let value = |x: usize, y: usize| ((x + y) % 2) as u8;
    let mut raw = Vec::new();
    for (pass, &(xf, yf, xo, yo)) in passes.iter().enumerate() {
        let pw = (w + xf - 1 - xo) / xf;
        let ph = (h + yf - 1 - yo) / yf;
        if pw == 0 || ph == 0 {
            continue;
        }
        for py in 0..ph {
            let mut byte = 0u8;
            for px in 0..pw {
                byte |= value(px * xf + xo, py * yf + yo) << (7 - px);
            }
            // Every filter is the identity on a one-byte first row (the
            // previous row is zero); later rows alternate None and Sub.
            raw.push(if py == 0 {
                (pass % 5) as u8
            } else {
                (py % 2) as u8
            });
            raw.push(byte);
        }
    }
    let bytes = png(&[
        ihdr(w as u32, h as u32, 1, 0, 1),
        chunk(b"tRNS", &[0, 1]),
        chunk(b"IDAT", &zlib(&raw)),
        chunk(b"IEND", &[]),
    ]);
    let AnyImage::Nrgba(m) = png::decode(&bytes[..]).unwrap() else {
        panic!("1-bit gray with tRNS decodes as NRGBA");
    };
    for y in 0..h {
        for x in 0..w {
            let expected = if value(x, y) == 1 {
                color::Nrgba {
                    r: 255,
                    g: 255,
                    b: 255,
                    a: 0,
                }
            } else {
                color::Nrgba {
                    r: 0,
                    g: 0,
                    b: 0,
                    a: 255,
                }
            };
            assert_eq!(m.pixel_at(x as i32, y as i32), expected, "({x},{y})");
        }
    }
    assert_eq!(
        png::decode_config(&bytes[..]).unwrap().color_model,
        Model::Gray
    );

    // All five filters on 8-bit RGB: rows of constant deltas reconstruct.
    let row = |f: u8| -> Vec<u8> {
        let mut r = vec![f];
        r.extend((0..6).map(|i| i as u8 * 3));
        r
    };
    let raw: Vec<u8> = (0..5).flat_map(row).collect();
    let bytes = png(&[
        ihdr(2, 5, 8, 2, 0),
        chunk(b"IDAT", &zlib(&raw)),
        chunk(b"IEND", &[]),
    ]);
    let AnyImage::Rgba(m) = png::decode(&bytes[..]).unwrap() else {
        panic!("RGB decodes as RGBA");
    };
    assert_eq!(
        m.pixel_at(1, 0),
        color::Rgba {
            r: 9,
            g: 12,
            b: 15,
            a: 255
        }
    );
    assert_eq!(
        m.pixel_at(1, 1),
        color::Rgba {
            r: 9,
            g: 15,
            b: 21,
            a: 255
        }
    ); // Sub
    assert_eq!(
        m.pixel_at(0, 2),
        color::Rgba {
            r: 0,
            g: 6,
            b: 12,
            a: 255
        }
    ); // Up
    assert_eq!(
        m.pixel_at(0, 3),
        color::Rgba {
            r: 0,
            g: 6,
            b: 12,
            a: 255
        }
    ); // Average
    assert_eq!(
        m.pixel_at(1, 3),
        color::Rgba {
            r: 18,
            g: 28,
            b: 39,
            a: 255
        }
    );
    assert_eq!(
        m.pixel_at(0, 4),
        color::Rgba {
            r: 0,
            g: 9,
            b: 18,
            a: 255
        }
    ); // Paeth
    assert_eq!(
        m.pixel_at(1, 4),
        color::Rgba {
            r: 27,
            g: 40,
            b: 54,
            a: 255
        }
    );
}

#[test]
fn palette_is_extended_for_trns_and_out_of_range_indexes() {
    let bytes = png(&[
        ihdr(3, 1, 8, 3, 0),
        chunk(b"PLTE", &[10, 20, 30]),
        chunk(b"tRNS", &[0x40, 0x80]),
        chunk(b"IDAT", &zlib(&[0, 0, 1, 4])),
        chunk(b"IEND", &[]),
    ]);
    let AnyImage::Paletted(p) = png::decode(&bytes[..]).unwrap() else {
        panic!("paletted");
    };
    assert_eq!(p.palette.len(), 5);
    assert_eq!(
        p.palette.get(0),
        Some(
            color::Nrgba {
                r: 10,
                g: 20,
                b: 30,
                a: 0x40
            }
            .into()
        )
    );
    assert_eq!(
        p.palette.get(1),
        Some(
            color::Nrgba {
                r: 0,
                g: 0,
                b: 0,
                a: 0x80
            }
            .into()
        )
    );
    assert_eq!(
        p.palette.get(4),
        Some(
            color::Rgba {
                r: 0,
                g: 0,
                b: 0,
                a: 255
            }
            .into()
        )
    );
    let config = png::decode_config(&bytes[..]).unwrap();
    let Model::Palette(cp) = config.color_model else {
        panic!("palette model");
    };
    assert_eq!(cp.len(), 2);
}

fn assert_rejected(bytes: &[u8], what: &str) {
    assert!(png::decode(bytes).is_err(), "{what} accepted");
}

#[test]
fn malformed_input_is_rejected() {
    let good = gray_png(&GRAY_RAW);
    assert!(png::decode(&good[..]).is_ok());

    let mut bad_crc = good.clone();
    bad_crc[29] ^= 1; // IHDR CRC
    assert_rejected(&bad_crc, "bad IHDR CRC");
    let idat_crc = good.len() - 12 - 1;
    let mut bad_idat_crc = good.clone();
    bad_idat_crc[idat_crc] ^= 0x80;
    assert_rejected(&bad_idat_crc, "bad IDAT CRC");

    for n in 0..good.len() - 12 {
        assert_rejected(&good[..n], "truncated file");
    }
    let compressed = zlib(&GRAY_RAW);
    let truncated = png(&[
        ihdr(3, 2, 8, 0, 0),
        chunk(b"IDAT", &compressed[..compressed.len() - 5]),
        chunk(b"IEND", &[]),
    ]);
    assert_rejected(&truncated, "truncated IDAT stream");
    assert_rejected(&gray_png(&GRAY_RAW[..7]), "missing pixel data");
    assert_rejected(
        &gray_png(&[GRAY_RAW.as_slice(), &[0]].concat()),
        "extra pixel data",
    );

    let mut bad_filter = GRAY_RAW;
    bad_filter[4] = 5;
    assert_rejected(&gray_png(&bad_filter), "filter type 5");

    let iend = chunk(b"IEND", &[]);
    let idat = chunk(b"IDAT", &compressed);
    let order_cases = [
        (
            vec![idat.clone(), ihdr(3, 2, 8, 0, 0), iend.clone()],
            "IDAT before IHDR",
        ),
        (
            vec![
                ihdr(3, 2, 8, 0, 0),
                ihdr(3, 2, 8, 0, 0),
                idat.clone(),
                iend.clone(),
            ],
            "two IHDRs",
        ),
        (
            vec![ihdr(3, 2, 8, 0, 0), iend.clone(), idat.clone()],
            "IEND before IDAT",
        ),
        (vec![ihdr(3, 2, 8, 0, 0), idat.clone()], "missing IEND"),
        (
            vec![
                ihdr(3, 2, 8, 0, 0),
                idat.clone(),
                chunk(b"tRNS", &[0, 0]),
                iend.clone(),
            ],
            "tRNS after IDAT",
        ),
        (
            vec![
                ihdr(3, 2, 8, 0, 0),
                chunk(b"PLTE", &[0, 0, 0]),
                idat.clone(),
                iend.clone(),
            ],
            "PLTE on gray",
        ),
        (
            vec![ihdr(3, 2, 8, 3, 0), idat.clone(), iend.clone()],
            "paletted without PLTE",
        ),
        (
            vec![
                ihdr(3, 2, 8, 3, 0),
                chunk(b"tRNS", &[0]),
                chunk(b"PLTE", &[0, 0, 0]),
                idat.clone(),
                iend.clone(),
            ],
            "tRNS before PLTE",
        ),
        (
            vec![ihdr(3, 2, 8, 0, 0), idat.clone(), chunk(b"IEND", &[0])],
            "IEND with data",
        ),
        (
            vec![ihdr(3, 2, 8, 1, 0), idat.clone(), iend.clone()],
            "color type 1",
        ),
        (
            vec![ihdr(3, 2, 3, 0, 0), idat.clone(), iend.clone()],
            "bit depth 3",
        ),
        (
            vec![ihdr(3, 2, 8, 0, 2), idat.clone(), iend.clone()],
            "interlace 2",
        ),
        (
            vec![ihdr(0, 2, 8, 0, 0), idat.clone(), iend.clone()],
            "zero width",
        ),
        (
            vec![ihdr(0x8000_0000, 2, 8, 0, 0), idat.clone(), iend.clone()],
            "negative width",
        ),
    ];
    for (chunks, what) in order_cases {
        assert_rejected(&png(&chunks), what);
    }
    assert_rejected(b"\x89PNG\r\n\x1a\r", "bad signature");
}

#[test]
fn go_leniencies_are_preserved() {
    let compressed = zlib(&GRAY_RAW);
    let (a, b) = compressed.split_at(3);
    let mut trailing = png(&[
        ihdr(3, 2, 8, 0, 0),
        chunk(b"tIME", &[0; 7]),
        chunk(b"IDAT", &[]),
        chunk(b"IDAT", a),
        chunk(b"IDAT", &[]),
        chunk(b"IDAT", b),
        chunk(b"zzZZ", b"unknown critical chunks are skipped"),
        chunk(b"IDAT", b"a later IDAT run is ignored"),
        chunk(b"IEND", &[]),
    ]);
    trailing.extend_from_slice(b"bytes after IEND are ignored");
    let m = png::decode(&trailing[..]).unwrap();
    assert_eq!(m.at(2, 1), color::Gray { y: 60 }.into());
}

#[test]
fn junk_inside_the_stream_ending_idat_chunk_is_rejected() {
    // Deliberate difference: Go accepts this when the rest of the chunk fits
    // in its 4 KiB read-ahead (it does here), and rejects it otherwise.
    let compressed = zlib(&GRAY_RAW);
    let junk_inside = png(&[
        ihdr(3, 2, 8, 0, 0),
        chunk(b"IDAT", &[compressed.as_slice(), b"junk"].concat()),
        chunk(b"IEND", &[]),
    ]);
    assert_eq!(
        error_text(&junk_inside),
        "png: invalid format: too much pixel data"
    );
}

fn error_text(bytes: &[u8]) -> String {
    png::decode(bytes)
        .err()
        .map_or_else(|| "ok".to_string(), |e| e.to_string())
}

/// Chunk payloads whose CRC field is wrong by one bit.
fn bad_crc(mut c: Vec<u8>) -> Vec<u8> {
    let last = c.len() - 1;
    c[last] ^= 1;
    c
}

#[test]
fn idat_chunks_after_the_zlib_stream_are_ignored_like_go() {
    // farfield's repro: a 1x1 gray PNG whose only IDAT chunk appears twice.
    // Go 1.27 decodes it to (0,0)-(1,1).
    let dup = png(&[
        ihdr(1, 1, 8, 0, 0),
        chunk(b"IDAT", &hex("789c000200fdff0280030000860083")),
        chunk(b"IDAT", &hex("789c000200fdff0280030000860083")),
        chunk(b"IEND", &[]),
    ]);
    let m = png::decode(&dup[..]).unwrap();
    assert_eq!(m.bounds(), rect(0, 0, 1, 1));
    assert_eq!(m.at(0, 0), color::Gray { y: 0x80 }.into());

    // Go never reads an IDAT chunk after the one the zlib stream ended in,
    // whatever it holds, so the main chunk loop skips it.
    let compressed = zlib(&GRAY_RAW);
    let (a, b) = compressed.split_at(5);
    let trailing = png(&[
        ihdr(3, 2, 8, 0, 0),
        chunk(b"IDAT", a),
        chunk(b"IDAT", b),
        chunk(b"IDAT", &[]),
        chunk(b"IDAT", b"extra"),
        chunk(b"IEND", &[]),
    ]);
    let m = png::decode(&trailing[..]).unwrap();
    assert_eq!(m.at(2, 1), color::Gray { y: 60 }.into());

    // The skipped chunk is still read and checked, with Go's errors.
    let crc = png(&[
        ihdr(3, 2, 8, 0, 0),
        chunk(b"IDAT", &compressed),
        bad_crc(chunk(b"IDAT", b"extra")),
        chunk(b"IEND", &[]),
    ]);
    assert_eq!(error_text(&crc), "png: invalid format: invalid checksum");
    let cut = png(&[
        ihdr(3, 2, 8, 0, 0),
        chunk(b"IDAT", &compressed),
        chunk(b"IDAT", b"extra"),
    ]);
    let truncated = &cut[..cut.len() - 6];
    assert_eq!(error_text(truncated), "unexpected EOF");
    assert!(rust_stdlib::io::is_unexpected_eof(
        &png::decode(truncated).unwrap_err()
    ));

    // A pixel error comes first: Go decodes before it reaches the skipped chunk.
    let too_long = png(&[
        ihdr(3, 2, 8, 0, 0),
        chunk(
            b"IDAT",
            &zlib(&[GRAY_RAW.as_slice(), &[0, 1, 2, 3]].concat()),
        ),
        bad_crc(chunk(b"IDAT", b"extra")),
        chunk(b"IEND", &[]),
    ]);
    assert_eq!(
        error_text(&too_long),
        "png: invalid format: too much pixel data"
    );

    // A bad CRC on a chunk the stream still needs surfaces where Go's zlib
    // reader crosses it: in the rows, or wrapped once more at the end.
    let (deflate, adler) = compressed.split_at(compressed.len() - 4);
    let crossing = png(&[
        ihdr(3, 2, 8, 0, 0),
        bad_crc(chunk(b"IDAT", deflate)),
        chunk(b"IDAT", adler),
        chunk(b"IEND", &[]),
    ]);
    assert_eq!(
        error_text(&crossing),
        "png: invalid format: png: invalid format: invalid checksum"
    );
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn long_runs_of_tiny_idat_chunks_after_the_stream_decode() {
    // Skipped chunks still count toward the compressed budget: 50k one-byte
    // chunks fit a budget of the stream plus 50k, and one more does not.
    // Zero-length chunks cost input bytes only.
    let compressed = zlib(&GRAY_RAW);
    let mut chunks = vec![ihdr(3, 2, 8, 0, 0), chunk(b"IDAT", &compressed)];
    chunks.extend(std::iter::repeat_n(chunk(b"IDAT", &[]), 50_000));
    chunks.extend(std::iter::repeat_n(chunk(b"IDAT", b"x"), 50_000));
    chunks.extend(std::iter::repeat_n(chunk(b"IDAT", &[]), 50_000));
    chunks.push(chunk(b"IEND", &[]));
    let limits = Limits {
        max_compressed_bytes: compressed.len() + 50_000,
        ..Limits::default()
    };
    let m = png::decode_with_limits(&png(&chunks)[..], limits).unwrap();
    assert_eq!(m.bounds(), rect(0, 0, 3, 2));
    assert_eq!(m.at(2, 1), color::Gray { y: 60 }.into());

    let end = chunks.len() - 1;
    chunks.insert(end, chunk(b"IDAT", b"x"));
    assert_eq!(
        png::decode_with_limits(&png(&chunks)[..], limits)
            .unwrap_err()
            .to_string(),
        "png: compressed size exceeds decode limit"
    );
}

#[test]
fn limits_reject_before_allocating() {
    let huge = png(&[
        ihdr(0x7fff_ffff, 0x7fff_ffff, 16, 6, 0),
        chunk(b"IEND", &[]),
    ]);
    assert!(png::decode(&huge[..]).is_err());
    let config = png::decode_config(&huge[..]);
    assert!(
        config.is_err(),
        "Go reports dimension overflow for 2^62 pixels"
    );
    let wide = png(&[ihdr(1 << 24, 1, 8, 0, 0), chunk(b"IEND", &[])]);
    assert_eq!(png::decode_config(&wide[..]).unwrap().width, 1 << 24);
    assert!(png::decode(&wide[..]).is_err());

    let good = gray_png(&GRAY_RAW);
    let base = Limits::default();
    for limits in [
        Limits {
            max_width: 2,
            ..base
        },
        Limits {
            max_height: 1,
            ..base
        },
        Limits {
            max_pixels: 5,
            ..base
        },
        Limits {
            max_decompressed_bytes: 7,
            ..base
        },
        Limits {
            max_compressed_bytes: 4,
            ..base
        },
        Limits {
            max_input_bytes: good.len() as u64 - 1,
            ..base
        },
    ] {
        assert!(
            png::decode_with_limits(&good[..], limits).is_err(),
            "{limits:?}"
        );
    }
    let exact = Limits {
        max_width: 3,
        max_height: 2,
        max_pixels: 6,
        max_decompressed_bytes: 8,
        max_compressed_bytes: zlib(&GRAY_RAW).len(),
        max_input_bytes: good.len() as u64,
    };
    assert!(png::decode_with_limits(&good[..], exact).is_ok());

    // An endless stream of ancillary chunks stops at the input budget.
    struct Endless {
        data: Vec<u8>,
        pos: usize,
        repeat_from: usize,
    }
    impl Read for Endless {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = buf.len().min(self.data.len() - self.pos);
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            if self.pos == self.data.len() {
                self.pos = self.repeat_from;
            }
            Ok(n)
        }
    }
    let mut data = png(&[ihdr(1, 1, 8, 0, 0)]);
    let repeat_from = data.len();
    data.extend_from_slice(&chunk(b"tEXt", &[b'x'; 1000]));
    let endless = Endless {
        data,
        pos: 0,
        repeat_from,
    };
    let limits = Limits {
        max_input_bytes: 1 << 20,
        ..base
    };
    assert!(png::decode_with_limits(endless, limits).is_err());
}

#[test]
fn encoder_rejects_invalid_images_like_go() {
    let mut out = Vec::new();
    assert!(png::encode(&mut out, &Gray::new(rect(0, 0, 0, 5))).is_err());
    assert!(out.is_empty(), "an invalid size writes nothing");
    // A bad palette fails after Go has written the signature and IHDR.
    let empty = Paletted::new(rect(0, 0, 1, 1), Palette::default());
    assert!(png::encode(&mut out, &empty).is_err());
    assert_eq!(out.len(), 8 + 12 + 13);
    out.clear();
    let big = Paletted::new(rect(0, 0, 1, 1), Palette(vec![color::BLACK.into(); 257]));
    assert!(png::encode(&mut out, &big).is_err());
    assert_eq!(out.len(), 8 + 12 + 13);
}

#[derive(Default)]
struct RecyclingPool {
    buffers: std::sync::Mutex<Vec<png::EncoderBuffer>>,
    gets: std::sync::atomic::AtomicUsize,
    puts: std::sync::atomic::AtomicUsize,
}

impl png::EncoderBufferPool for RecyclingPool {
    fn get(&self) -> Option<png::EncoderBuffer> {
        self.gets.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.buffers.lock().unwrap().pop()
    }
    fn put(&self, buffer: png::EncoderBuffer) {
        self.puts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.buffers.lock().unwrap().push(buffer);
    }
}

#[test]
fn encoder_buffer_pool_is_used_and_output_is_unchanged() {
    let image = Gray::new(rect(0, 0, 3, 2));
    let mut plain = Vec::new();
    png::encode(&mut plain, &image).unwrap();
    let pool = std::sync::Arc::new(RecyclingPool::default());
    let encoder = Encoder {
        buffer_pool: Some(pool.clone()),
        ..Default::default()
    };
    for _ in 0..2 {
        let mut bytes = Vec::new();
        encoder.encode(&mut bytes, &image).unwrap();
        assert_eq!(bytes, plain);
    }
    assert_eq!(
        (
            pool.gets.load(std::sync::atomic::Ordering::SeqCst),
            pool.puts.load(std::sync::atomic::Ordering::SeqCst)
        ),
        (2, 2)
    );
    assert_eq!(pool.buffers.lock().unwrap().len(), 1);

    let mut out = Vec::new();
    let failing = Paletted::new(rect(0, 0, 1, 1), Palette::default());
    assert!(encoder.encode(&mut out, &failing).is_err());
    assert_eq!(
        pool.puts.load(std::sync::atomic::Ordering::SeqCst),
        3,
        "the buffer is returned after a failed encode"
    );
    assert_eq!(out.len(), 8 + 12 + 13, "signature and IHDR, as in Go");
}

#[test]
fn errors_carry_go_format_and_unsupported_payloads() {
    let error = png::decode(&b"not a png"[..]).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    let format = error
        .get_ref()
        .and_then(|e| e.downcast_ref::<png::FormatError>())
        .expect("FormatError payload");
    assert_eq!(
        format.to_string(),
        format!("png: invalid format: {}", format.0)
    );
    assert!(format.to_string().starts_with("png: invalid format: "));
    assert_eq!(error.to_string(), format.to_string());
    let unsupported = png::UnsupportedError("interlace".into());
    assert_eq!(
        unsupported.to_string(),
        "png: unsupported feature: interlace"
    );
}

/// A QR-like two-colour paletted image: 29x29 modules with finder squares,
/// scaled by 8 with a 2-module quiet zone. The expected sizes and CRC-32s of
/// the whole file come from Go's `png.Encode` on the same pixels.
fn qr_like() -> Paletted {
    const N: usize = 29;
    const SCALE: usize = 8;
    const QUIET: usize = 2;
    let mut mods = [[false; N]; N];
    let mut state = 12345u32;
    for row in mods.iter_mut() {
        for m in row.iter_mut() {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            *m = (state >> 16) & 1 == 1;
        }
    }
    for (ox, oy) in [(0, 0), (N - 7, 0), (0, N - 7)] {
        for y in 0..7 {
            for x in 0..7 {
                mods[oy + y][ox + x] = x == 0
                    || x == 6
                    || y == 0
                    || y == 6
                    || ((2..=4).contains(&x) && (2..=4).contains(&y));
            }
        }
    }
    let size = (N + 2 * QUIET) * SCALE;
    let mut img = Paletted::new(
        rect(0, 0, size as i32, size as i32),
        Palette(vec![
            color::Gray { y: 0xff }.into(),
            color::Gray { y: 0 }.into(),
        ]),
    );
    for y in 0..size {
        for x in 0..size {
            let (mx, my) = (
                (x / SCALE).wrapping_sub(QUIET),
                (y / SCALE).wrapping_sub(QUIET),
            );
            if mx < N && my < N && mods[my][mx] {
                img.set_color_index(x as i32, y as i32, 1);
            }
        }
    }
    img
}

#[test]
fn qr_like_paletted_encodes_byte_for_byte_like_go() {
    let img = qr_like();
    for (level, go_size, go_crc) in [
        (CompressionLevel::Default, 350usize, 1372601228u32),
        (CompressionLevel::NoCompression, 9064, 966509688),
        (CompressionLevel::BestSpeed, 558, 3412038312),
        (CompressionLevel::BestCompression, 304, 1686555383),
    ] {
        let mut bytes = Vec::new();
        Encoder {
            compression_level: level,
            ..Encoder::default()
        }
        .encode(&mut bytes, &img)
        .unwrap();
        assert_eq!(bytes.len(), go_size, "{level:?}");
        assert_eq!(checksum_ieee(&bytes), go_crc, "{level:?}");
        assert_eq!(png::decode(&bytes[..]).unwrap().bounds(), img.bounds());
    }
}

#[test]
fn truncated_input_reports_go_errors() {
    let signature = &b"\x89PNG\r\n\x1a\n"[..];
    let err = rust_stdlib::image::decode_config(signature).unwrap_err();
    assert_eq!(err.to_string(), "unexpected EOF");
    for cut in [0, 3, 8] {
        let err = png::decode_config(&signature[..cut.min(signature.len())]).unwrap_err();
        assert_eq!(err.to_string(), "unexpected EOF");
        let err = png::decode(&signature[..cut.min(signature.len())]).unwrap_err();
        assert_eq!(err.to_string(), "unexpected EOF");
        assert!(rust_stdlib::io::is_unexpected_eof(&err));
    }
}
