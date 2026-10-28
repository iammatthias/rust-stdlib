use rust_stdlib::compress::lzw;
use rust_stdlib::image::color::{self, palette, Color, Model, Palette};
use rust_stdlib::image::draw::{self, Quantizer};
use rust_stdlib::image::gif::{self, Gif, Limits, Options};
use rust_stdlib::image::{pt, rect, Config, Gray, Image, Paletted, Rgba};
use std::io;

// A valid 2x1 GIF header with a two-color global table, as in Go's tests.
const HEADER: &[u8] = b"GIF89a\x02\x00\x01\x00\x80\x00\x00";
const PALETTE: &[u8] = b"\x10\x20\x30\x40\x50\x60";
const TRAILER: &[u8] = b"\x3b";
// Image descriptor: (0,0)-(2,1), no local table, 2-bit LZW literals.
const DESCRIPTOR: &[u8] = b"\x2c\x00\x00\x00\x00\x02\x00\x01\x00\x00\x02";

fn lzw2(pixels: &[u8]) -> Vec<u8> {
    lzw::encode(pixels, lzw::Order::Lsb, 2).unwrap()
}

fn rgba(r: u8, g: u8, b: u8, a: u8) -> Color {
    color::Rgba { r, g, b, a }.into()
}

fn two_by_one(pixels: &[u8]) -> Vec<u8> {
    let enc = lzw2(pixels);
    let mut b = [HEADER, PALETTE, DESCRIPTOR].concat();
    b.push(enc.len() as u8);
    b.extend_from_slice(&enc);
    b.push(0);
    b.extend_from_slice(TRAILER);
    b
}

fn error_text(data: &[u8]) -> String {
    match gif::decode_all(data) {
        Ok(_) => String::new(),
        Err(e) => e.to_string(),
    }
}

// Go's testGIF: a 1x1 frame with a graphic control extension.
const TEST_GIF: &[u8] = &[
    b'G', b'I', b'F', b'8', b'9', b'a', 1, 0, 1, 0, 128, 0, 0, 0, 0, 0, 1, 1, 1, 0x21, 0xf9, 0x04,
    0x00, 0x00, 0x00, 0xff, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02,
    0x02, 0x4c, 0x01, 0x00, 0x3b,
];

#[test]
fn pixel_count_and_trailing_sub_blocks_follow_go() {
    // (pixels, extra bytes in the LZW sub-block, extra separate sub-block, error)
    let cases: [(usize, usize, usize, Option<&str>); 9] = [
        (0, 0, 0, Some("gif: not enough image data")),
        (1, 0, 0, Some("gif: not enough image data")),
        (2, 0, 0, None),
        (2, 0, 1, None),
        (2, 0, 2, Some("gif: too much image data")),
        (3, 0, 0, Some("gif: too much image data")),
        (2, 1, 0, None),
        (2, 2, 0, None),
        (2, 1, 1, Some("gif: too much image data")),
    ];
    for (n, existing, separate, want) in cases {
        let mut b = [HEADER, PALETTE, DESCRIPTOR].concat();
        if n > 0 {
            let enc = lzw2(&vec![0; n]);
            b.push((enc.len() + existing) as u8);
            b.extend_from_slice(&enc);
            b.extend(std::iter::repeat_n(2, existing));
        }
        if separate > 0 {
            b.push(separate as u8);
            b.extend(std::iter::repeat_n(2, separate));
        }
        b.push(0);
        b.extend_from_slice(TRAILER);
        match (gif::decode(&b[..]), want) {
            (Ok(m), None) => {
                assert_eq!(m.pix, [0, 0]);
                assert_eq!(m.rect, rect(0, 0, 2, 1));
                assert_eq!(
                    m.palette,
                    Palette(vec![
                        rgba(0x10, 0x20, 0x30, 0xff),
                        rgba(0x40, 0x50, 0x60, 0xff)
                    ])
                );
            }
            (Err(e), Some(text)) => {
                assert_eq!(e.to_string(), text, "case {n} {existing} {separate}")
            }
            (got, want) => panic!("case {n} {existing} {separate}: {got:?}, want {want:?}"),
        }
    }
}

#[test]
fn missing_end_code_is_accepted() {
    // 3-bit codes clear(4), 0, 0 and no end-of-information code (giflib
    // does not require one, golang.org/issue/9856).
    let mut b = [HEADER, PALETTE, DESCRIPTOR].concat();
    // Bits 0..9 hold clear, 0, 0; bits 9..15 two more clear codes; bit 15
    // starts a code the block terminator cuts short.
    let enc = [0x04, 0x48];
    b.push(enc.len() as u8);
    b.extend_from_slice(&enc);
    b.push(0);
    b.extend_from_slice(TRAILER);
    assert_eq!(gif::decode(&b[..]).unwrap().pix, [0, 0]);
}

#[test]
fn transparent_index_clears_one_entry_for_one_frame() {
    let mut b = [HEADER, PALETTE].concat();
    for ti in 0..3u8 {
        if ti < 2 {
            b.extend_from_slice(b"\x21\xf9\x04\x01\x00\x00");
            b.extend_from_slice(&[ti, 0]);
        }
        b.extend_from_slice(DESCRIPTOR);
        let enc = lzw2(&[0, 0]);
        b.push(enc.len() as u8);
        b.extend_from_slice(&enc);
        b.push(0);
    }
    b.extend_from_slice(TRAILER);
    let g = gif::decode_all(&b[..]).unwrap();
    let (c0, c1, cz) = (
        rgba(0x10, 0x20, 0x30, 0xff),
        rgba(0x40, 0x50, 0x60, 0xff),
        rgba(0, 0, 0, 0),
    );
    let wants = [vec![cz, c1], vec![c0, cz], vec![c0, c1]];
    assert_eq!(g.image.len(), 3);
    for (m, want) in g.image.iter().zip(wants) {
        assert_eq!(m.palette.0, want);
    }
    // The global palette is not modified.
    assert_eq!(
        g.config.unwrap().color_model,
        Model::Palette(Palette(vec![c0, c1]))
    );
}

#[test]
fn out_of_range_transparent_index_grows_the_palette() {
    let mut b = [HEADER, PALETTE].concat();
    b.extend_from_slice(b"\x21\xf9\x04\x01\x00\x00\x03\x00");
    b.extend_from_slice(DESCRIPTOR);
    let enc = lzw2(&[3, 3]);
    b.push(enc.len() as u8);
    b.extend_from_slice(&enc);
    b.push(0);
    b.extend_from_slice(TRAILER);
    let m = gif::decode(&b[..]).unwrap();
    assert_eq!(m.palette.len(), 4);
    assert_eq!(m.palette.0[2], rgba(0, 0, 0, 0));
    assert_eq!(m.at(0, 0), rgba(0, 0, 0, 0));
}

#[test]
fn frame_bounds_are_checked_against_the_screen() {
    let mut g = TEST_GIF.to_vec();
    g[32] = 2;
    assert_eq!(error_text(&g), "gif: frame bounds larger than image bounds");
    g[32] = 0;
    assert_eq!(error_text(&g), "gif: too much image data");
    g[32..36].copy_from_slice(&[0xff; 4]);
    assert_eq!(error_text(&g), "gif: frame bounds larger than image bounds");
}

#[test]
fn missing_color_table_and_bad_pixels_are_rejected() {
    let mut b = HEADER[..10].to_vec();
    b.extend_from_slice(b"\x00\x00\x00");
    b.extend_from_slice(DESCRIPTOR);
    let enc = lzw2(&[0, 3]);
    b.push(enc.len() as u8);
    b.extend_from_slice(&enc);
    b.push(0);
    b.extend_from_slice(TRAILER);
    assert_eq!(error_text(&b), "gif: no color table");

    for p in 0..4u8 {
        let want = if p >= 2 {
            "gif: invalid pixel value"
        } else {
            ""
        };
        assert_eq!(error_text(&two_by_one(&[p, p])), want);
    }
}

#[test]
fn block_and_header_errors_match_go() {
    let cases: [(&[u8], &str); 8] = [
        (b"GIF89", "gif: reading header: unexpected EOF"),
        (
            b"GIF90a\x01\x00\x01\x00\x00\x00\x00",
            "gif: can't recognize format \"GIF90a\"",
        ),
        (
            b"GIF89a\x01\x00\x01\x00\x00\x00\x00",
            "gif: reading frames: unexpected EOF",
        ),
        (
            b"GIF89a\x01\x00\x01\x00\x00\x00\x00\x3b",
            "gif: missing image data",
        ),
        (
            b"GIF89a\x01\x00\x01\x00\x00\x00\x00\x99",
            "gif: unknown block type: 0x99",
        ),
        (
            b"GIF89a\x01\x00\x01\x00\x00\x00\x00\x21\x42",
            "gif: unknown extension 0x42",
        ),
        (
            b"GIF89a\x01\x00\x01\x00\x00\x00\x00\x21\xf9\x05\x00\x00\x00\x00\x00",
            "gif: invalid graphic control extension block size: 5",
        ),
        (
            b"GIF89a\x01\x00\x01\x00\x00\x00\x00\x21\xf9\x04\x00\x00\x00\x00\x07",
            "gif: invalid graphic control extension block terminator: 7",
        ),
    ];
    for (data, want) in cases {
        assert_eq!(error_text(data), want);
    }
    for lit in [0u8, 1, 9] {
        let mut b = [HEADER, PALETTE, &DESCRIPTOR[..10]].concat();
        b.extend_from_slice(&[lit, 0, 0x3b]);
        assert_eq!(
            error_text(&b),
            format!("gif: pixel size in decode out of range: {lit}")
        );
    }
}

#[test]
fn every_truncation_is_an_unexpected_eof_or_not_enough_data() {
    for i in 0..TEST_GIF.len() {
        let text = error_text(&TEST_GIF[..i]);
        if text == "gif: not enough image data" {
            continue;
        }
        assert!(
            text.starts_with("gif:") && text.ends_with(": unexpected EOF"),
            "prefix {i}: {text}"
        );
    }
    assert!(gif::decode_all(TEST_GIF).is_ok());
}

#[test]
fn loop_counts_round_trip() {
    let body = |netscape: &[u8]| {
        let frame: &[u8] = b",0\x00\x00\x00\n\x00\n\x00\x80000000\x02\x08\xf01u\xb9\xfdal\x05\x00";
        let mut b = b"GIF89a000\x00000".to_vec();
        b.extend_from_slice(netscape);
        b.extend_from_slice(frame);
        if !netscape.is_empty() {
            b.extend_from_slice(frame);
        }
        b.push(b';');
        b
    };
    let cases: [(&[u8], i32); 3] = [
        (b"", -1),
        (b"!\xff\x0bNETSCAPE2.0\x03\x01\x00\x00\x00", 0),
        (b"!\xff\x0bNETSCAPE2.0\x03\x01\x01\x00\x00", 1),
    ];
    for (netscape, want) in cases {
        let g = gif::decode_all(&body(netscape)[..]).unwrap();
        assert_eq!(g.loop_count, want);
        let mut out = Vec::new();
        gif::encode_all(&mut out, &g).unwrap();
        let again = gif::decode_all(&out[..]).unwrap();
        assert_eq!(again.loop_count, want);
        assert_eq!(again.image, g.image);
    }
}

#[test]
fn decode_reads_only_the_first_frame() {
    let img = Paletted::new(rect(0, 0, 1, 1), palette::web_safe());
    let frames = 3000;
    let g = Gif {
        image: vec![img; frames],
        delay: vec![60; frames],
        disposal: Some(vec![0; frames]),
        ..Gif::default()
    };
    let mut buf = Vec::new();
    gif::encode_all(&mut buf, &g).unwrap();
    // A frame budget of one still decodes the first frame.
    let limits = Limits {
        max_frames: 1,
        ..Limits::default()
    };
    assert_eq!(
        gif::decode_with_limits(&buf[..], limits).unwrap().rect,
        rect(0, 0, 1, 1)
    );
    let err = gif::decode_all_with_limits(&buf[..], limits).unwrap_err();
    assert_eq!(err.to_string(), "gif: frame count exceeds decode limit");
    assert_eq!(gif::decode_all(&buf[..]).unwrap().image.len(), frames);
}

#[test]
fn limits_are_checked_before_allocation() {
    // A 65535x65535 screen and frame with almost no data.
    let mut b = b"GIF89a\xff\xff\xff\xff\x80\x00\x00\x00\x00\x00\xff\xff\xff".to_vec();
    b.extend_from_slice(b"\x2c\x00\x00\x00\x00\xff\xff\xff\xff\x00\x02\x02\x4c\x01\x00\x3b");
    let err = gif::decode(&b[..]).unwrap_err();
    assert_eq!(err.to_string(), "gif: frame size exceeds decode limit");
    let config = gif::decode_config(&b[..]).unwrap();
    assert_eq!((config.width, config.height), (65535, 65535));

    let small = Limits {
        max_input_bytes: 10,
        ..Limits::default()
    };
    let err = gif::decode_config_with_limits(TEST_GIF, small).unwrap_err();
    assert_eq!(err.to_string(), "gif: input size exceeds decode limit");

    let total = Limits {
        max_total_pixels: 3,
        ..Limits::default()
    };
    let mut two = [HEADER, PALETTE].concat();
    for _ in 0..2 {
        two.extend_from_slice(DESCRIPTOR);
        let enc = lzw2(&[0, 1]);
        two.push(enc.len() as u8);
        two.extend_from_slice(&enc);
        two.push(0);
    }
    two.push(0x3b);
    assert_eq!(gif::decode_all(&two[..]).unwrap().image.len(), 2);
    let err = gif::decode_all_with_limits(&two[..], total).unwrap_err();
    assert_eq!(
        err.to_string(),
        "gif: total frame size exceeds decode limit"
    );
}

#[test]
fn extensions_interlace_and_metadata_decode() {
    // 1x5 interlaced frame: rows arrive in the order 0, 4, 2, 1, 3.
    let mut b = b"GIF89a\x01\x00\x05\x00\x81\x07\x00".to_vec();
    b.extend_from_slice(&[0, 0, 0, 1, 1, 1, 2, 2, 2, 3, 3, 3]);
    b.extend_from_slice(b"\x21\xfe\x03abc\x00"); // comment
    b.extend_from_slice(b"\x21\x01"); // plain text
    b.extend_from_slice(&[0; 13]);
    b.extend_from_slice(b"\x02hi\x00");
    b.extend_from_slice(b"\x21\xff\x0aADOBE:XMP\x00\x01x\x00"); // 10-byte application
    b.extend_from_slice(b"\x21\xf9\x04\x0c\x2a\x00\x00\x00"); // disposal 3, delay 42
    b.extend_from_slice(b"\x2c\x00\x00\x00\x00\x01\x00\x05\x00\x40\x02");
    let enc = lzw2(&[0, 1, 2, 3, 0]);
    b.push(enc.len() as u8);
    b.extend_from_slice(&enc);
    b.extend_from_slice(b"\x00\x3b");
    let g = gif::decode_all(&b[..]).unwrap();
    assert_eq!(g.image[0].pix, [0, 3, 2, 0, 1]);
    assert_eq!(g.delay, [42]);
    assert_eq!(g.disposal, Some(vec![gif::DISPOSAL_PREVIOUS]));
    assert_eq!(g.background_index, 7);
    assert_eq!(g.loop_count, -1);
    let config = gif::decode_config(&b[..]).unwrap();
    assert_eq!((config.width, config.height), (1, 5));
    assert!(matches!(config.color_model, Model::Palette(p) if p.len() == 4));
}

fn frame(r: (i32, i32, i32, i32), pal: &Palette) -> Paletted {
    Paletted::new(rect(r.0, r.1, r.2, r.3), pal.clone())
}

#[test]
fn encode_all_validates_like_go() {
    let plan9 = palette::plan9();
    let two = vec![frame((0, 0, 5, 5), &plan9), frame((0, 0, 5, 5), &plan9)];
    let err = |g: &Gif| gif::encode_all(io::sink(), g).unwrap_err().to_string();
    assert_eq!(err(&Gif::default()), "gif: must provide at least one image");
    let g = Gif {
        image: two.clone(),
        delay: vec![0],
        ..Gif::default()
    };
    assert_eq!(err(&g), "gif: mismatched image and delay lengths");
    let g = Gif {
        image: two.clone(),
        delay: vec![0; 2],
        disposal: Some(vec![gif::DISPOSAL_NONE]),
        ..Gif::default()
    };
    assert_eq!(err(&g), "gif: mismatched image and disposal lengths");
    let g = Gif {
        image: vec![frame((0, 0, 1, 1), &plan9)],
        delay: vec![0],
        config: Some(Config {
            color_model: Model::Rgba,
            width: 1,
            height: 1,
        }),
        ..Gif::default()
    };
    assert_eq!(err(&g), "gif: GIF color model must be a color.Palette");

    let images = vec![
        frame((0, 0, 5, 5), &plan9),
        frame((2, 2, 8, 8), &plan9),
        frame((3, 3, 4, 4), &plan9),
    ];
    for bound in [6, 10] {
        let g = Gif {
            image: images.clone(),
            delay: vec![0; 3],
            disposal: Some(vec![0; 3]),
            config: Some(Config {
                color_model: Model::Palette(Palette::default()),
                width: bound,
                height: bound,
            }),
            ..Gif::default()
        };
        let result = gif::encode_all(io::sink(), &g);
        assert_eq!(result.is_ok(), bound >= 8, "bound {bound}");
    }

    for n in [256, 257] {
        let pal = Palette(vec![color::BLACK.into(); n]);
        let g = Gif {
            image: vec![frame((0, 0, 5, 5), &pal)],
            delay: vec![0],
            config: Some(Config {
                color_model: Model::Palette(pal.clone()),
                width: 5,
                height: 5,
            }),
            ..Gif::default()
        };
        assert_eq!(gif::encode_all(io::sink(), &g).is_err(), n > 256);
    }
    let g = Gif {
        image: vec![frame((0, 0, 1, 1), &Palette::default())],
        delay: vec![0],
        ..Gif::default()
    };
    assert_eq!(err(&g), "gif: cannot encode image block with empty palette");
    let g = Gif {
        image: vec![frame((-1, 0, 1, 1), &plan9)],
        delay: vec![0],
        config: Some(Config {
            color_model: Model::Palette(Palette::default()),
            width: 4,
            height: 4,
        }),
        ..Gif::default()
    };
    assert_eq!(err(&g), "gif: image block is too large to encode");
    // A frame whose pixel buffer is shorter than its bounds is an error (Go
    // panics).
    let mut short = frame((0, 0, 2, 2), &plan9);
    short.pix.truncate(3);
    let g = Gif {
        image: vec![short],
        delay: vec![0],
        ..Gif::default()
    };
    assert!(gif::encode_all(io::sink(), &g).is_err());
}

#[test]
fn encode_all_round_trips_animation_metadata() {
    let pal = Palette(vec![
        rgba(0, 0, 0, 0xff),
        rgba(0xff, 0, 0, 0xff),
        rgba(0, 0xff, 0, 0xff),
        rgba(0, 0, 0, 0),
    ]);
    let mut frames = Vec::new();
    for i in 0..3u8 {
        let mut f = frame((i32::from(i), 0, i32::from(i) + 3, 2), &pal);
        f.pix.with_mut(|pix| {
            pix.iter_mut()
                .enumerate()
                .for_each(|(j, p)| *p = (j as u8 + i) % 4)
        });
        frames.push(f);
    }
    let g = Gif {
        image: frames.clone(),
        delay: vec![10, 20, 0],
        loop_count: 3,
        disposal: Some(vec![
            gif::DISPOSAL_NONE,
            gif::DISPOSAL_BACKGROUND,
            gif::DISPOSAL_PREVIOUS,
        ]),
        config: Some(Config {
            color_model: Model::Palette(pal.clone()),
            width: 6,
            height: 2,
        }),
        background_index: 2,
    };
    let mut out = Vec::new();
    gif::encode_all(&mut out, &g).unwrap();
    let back = gif::decode_all(&out[..]).unwrap();
    assert_eq!(back.delay, g.delay);
    assert_eq!(back.loop_count, 3);
    assert_eq!(back.disposal, g.disposal);
    assert_eq!(back.background_index, 2);
    let config = back.config.unwrap();
    assert_eq!((config.width, config.height), (6, 2));
    for (a, b) in back.image.iter().zip(&frames) {
        assert_eq!(a.rect, b.rect);
        assert_eq!(a.pix, b.pix);
        // The transparent entry decodes as transparent black.
        assert_eq!(a.palette, pal);
    }
    // Frames sharing the global palette reference the global color table:
    // without one, each of the three frames carries its own 12-byte table.
    let mut local = Vec::new();
    let no_global = Config {
        color_model: Model::Palette(Palette::default()),
        width: 6,
        height: 2,
    };
    let g = Gif {
        config: Some(no_global),
        ..g
    };
    gif::encode_all(&mut local, &g).unwrap();
    assert_eq!(local.len(), out.len() + 3 * 12 - 12);
}

#[test]
fn encode_translates_and_quantizes() {
    for p in [pt(-8, -9), pt(-3, 3), pt(0, 0), pt(2, 2)] {
        let src = Paletted::new(rect(p.x, p.y, p.x + 6, p.y + 6), palette::plan9());
        let mut buf = Vec::new();
        gif::encode(&mut buf, &src, None).unwrap();
        assert_eq!(gif::decode(&buf[..]).unwrap().rect, rect(0, 0, 6, 6));
    }

    let mut src = Rgba::new(rect(2, 2, 8, 8));
    for (i, v) in [0x22u8, 0x33, 0x44, 0x55, 0x66, 0x77]
        .into_iter()
        .enumerate()
    {
        let k = 2 + i as i32;
        src.set_pixel(
            k,
            k,
            color::Rgba {
                r: v,
                g: v,
                b: v,
                a: 0xff,
            },
        );
    }
    let mut buf = Vec::new();
    gif::encode(&mut buf, &src, None).unwrap();
    let m = gif::decode(&buf[..]).unwrap();
    assert_eq!(m.rect, rect(0, 0, 6, 6));
    assert_eq!(m.at(0, 0).rgba().0 >> 8, 0x22);
    assert_eq!(m.at(5, 5).rgba().0 >> 8, 0x77);

    // A gray ramp quantized to the first 2 Plan 9 colors with plain Src.
    let mut gray = Gray::new(rect(0, 0, 4, 1));
    gray.pix.copy_from_slice(&[0, 0x40, 0xc0, 0xff]);
    let options = Options {
        num_colors: 2,
        drawer: Some(&draw::Op::Src),
        ..Options::default()
    };
    let mut buf = Vec::new();
    gif::encode(&mut buf, &gray, Some(&options)).unwrap();
    let m = gif::decode(&buf[..]).unwrap();
    // Plan 9 entry 1 is (0, 0, 0x44), nearer than black to 0x40 gray.
    assert_eq!(m.palette.len(), 2);
    assert_eq!(m.pix, [0, 1, 1, 1]);

    let too_large = Rgba::new(rect(0, 0, 1 << 16, 1));
    assert_eq!(
        gif::encode(io::sink(), &too_large, None)
            .unwrap_err()
            .to_string(),
        "gif: image is too large to encode"
    );
}

struct FirstColors;

impl Quantizer for FirstColors {
    fn quantize(&self, mut p: Palette, capacity: usize, m: &dyn Image) -> Palette {
        let b = m.bounds();
        for y in b.min.y..b.max.y {
            for x in b.min.x..b.max.x {
                let c = Color::Rgba(color::Rgba::from_color(m.at(x, y)));
                if p.len() < capacity && !p.0.contains(&c) {
                    p.0.push(c);
                }
            }
        }
        p
    }
}

#[test]
fn encode_uses_the_quantizer_palette() {
    let mut src = Rgba::new(rect(0, 0, 3, 1));
    src.set_pixel(
        0,
        0,
        color::Rgba {
            r: 9,
            g: 8,
            b: 7,
            a: 0xff,
        },
    );
    src.set_pixel(
        1,
        0,
        color::Rgba {
            r: 1,
            g: 2,
            b: 3,
            a: 0xff,
        },
    );
    src.set_pixel(
        2,
        0,
        color::Rgba {
            r: 9,
            g: 8,
            b: 7,
            a: 0xff,
        },
    );
    let options = Options {
        num_colors: 4,
        quantizer: Some(&FirstColors),
        ..Options::default()
    };
    let mut buf = Vec::new();
    gif::encode(&mut buf, &src, Some(&options)).unwrap();
    let m = gif::decode(&buf[..]).unwrap();
    assert_eq!(
        &m.palette.0[..2],
        &[rgba(9, 8, 7, 0xff), rgba(1, 2, 3, 0xff)]
    );
    assert_eq!(m.pix, [0, 1, 0]);
}

#[test]
fn reencode_with_one_color_succeeds() {
    // Go's TestReencodeExtendedPalette input.
    let hex = "4749463839616c02020157220221ff0b280154ffffffff00000021474946306127dc213000ff84ff840000000000800021ffffffff8f4e4554530041508f8f0202020000000000000000000000000202020202020207020202022f31050000000000000021f904ab2c3826002c00000000c00001009800462b07fc1f02061202020602020202220202930202020202020202020202020286090222202222222222222222222222222222222222222222222222222220222222222222222222222222222222222222222222222222221a22222222332223222222222222222222222222222222222222224b222222222222002200002b474946312829021f0000000000cbff002f0202073121f904ab2c2c000021f92c3803002c00e0c0000000f932";
    let data: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    let img = gif::decode(&data[..]).unwrap();
    let options = Options {
        num_colors: 1,
        ..Options::default()
    };
    gif::encode(io::sink(), &img, Some(&options)).unwrap();
}

#[test]
fn palettes_are_generated_from_go() {
    assert_eq!(palette::PLAN9.len(), 256);
    assert_eq!(palette::WEB_SAFE.len(), 216);
    assert_eq!(
        palette::PLAN9[0],
        color::Rgba {
            r: 0,
            g: 0,
            b: 0,
            a: 0xff
        }
    );
    assert_eq!(
        palette::PLAN9[255],
        color::Rgba {
            r: 0xff,
            g: 0xff,
            b: 0xff,
            a: 0xff
        }
    );
    assert_eq!(
        palette::WEB_SAFE[1],
        color::Rgba {
            r: 0,
            g: 0,
            b: 0x33,
            a: 0xff
        }
    );
    assert_eq!(palette::web_safe().0[215], rgba(0xff, 0xff, 0xff, 0xff));
}
