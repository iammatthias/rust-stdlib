//! Ports of the tables in Go's `image/jpeg` `reader_test.go` and
//! `writer_test.go`, over the JPEG fixtures copied from Go's `image/testdata`.
use rust_stdlib::image::color::{self, Model};
use rust_stdlib::image::jpeg::{self, FormatError, Options, UnsupportedError};
use rust_stdlib::image::png;
use rust_stdlib::image::{self, pt, rect, Cmyk, Gray, Image, Rgba, Ycbcr, YcbcrSubsampleRatio};
use std::io::{self, Read};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/jpeg/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn decode_file(name: &str) -> io::Result<Box<dyn Image>> {
    jpeg::decode(&fixture(name)[..])
}

fn downcast<T: 'static>(m: &dyn Image) -> &T {
    m.as_any()
        .and_then(|a| a.downcast_ref::<T>())
        .unwrap_or_else(|| panic!("unexpected image type"))
}

/// Compares two pix planes one 8x8 block at a time, ignoring blocks entirely
/// outside the bounds (Go's `check`).
fn check(max_x: i32, max_y: i32, pix0: &[u8], pix1: &[u8], stride0: usize, stride1: usize) {
    assert!(
        stride0 > 0 && stride0.is_multiple_of(8),
        "bad stride {stride0}"
    );
    assert!(
        stride1 > 0 && stride1.is_multiple_of(8),
        "bad stride {stride1}"
    );
    let mut y = 0;
    while y < pix0.len() / stride0 && y < pix1.len() / stride1 {
        let mut x = 0;
        while x < stride0 && x < stride1 {
            if x as i32 >= max_x || y as i32 >= max_y {
                x += 8;
                continue;
            }
            for j in 0..8 {
                for i in 0..8 {
                    assert_eq!(
                        pix0[(y + j) * stride0 + x + i],
                        pix1[(y + j) * stride1 + x + i],
                        "blocks at ({x}, {y}) differ"
                    );
                }
            }
            x += 8;
        }
        y += 8;
    }
}

#[test]
fn decode_progressive_matches_baseline() {
    for tc in [
        "video-001",
        "video-001.q50.410",
        "video-001.q50.411",
        "video-001.q50.420",
        "video-001.q50.422",
        "video-001.q50.440",
        "video-001.q50.444",
        "video-005.gray.q50",
        "video-005.gray.q50.2x2",
        "video-001.separate.dc.progression",
    ] {
        let m0 = decode_file(&format!("{tc}.jpeg")).unwrap();
        let m1 = decode_file(&format!("{tc}.progressive.jpeg")).unwrap();
        assert_eq!(m0.bounds(), m1.bounds(), "{tc}");
        // All of the video-*.jpeg files are 150x103.
        assert_eq!(m0.bounds(), rect(0, 0, 150, 103), "{tc}");
        if let Some(m0) = m0.as_any().and_then(|a| a.downcast_ref::<Ycbcr>()) {
            let m1 = downcast::<Ycbcr>(m1.as_ref());
            check(
                150,
                103,
                &m0.y.to_vec(),
                &m1.y.to_vec(),
                m0.y_stride,
                m1.y_stride,
            );
            check(
                150,
                103,
                &m0.cb.to_vec(),
                &m1.cb.to_vec(),
                m0.c_stride,
                m1.c_stride,
            );
            check(
                150,
                103,
                &m0.cr.to_vec(),
                &m1.cr.to_vec(),
                m0.c_stride,
                m1.c_stride,
            );
        } else {
            let m0 = downcast::<Gray>(m0.as_ref());
            let m1 = downcast::<Gray>(m1.as_ref());
            check(
                150,
                103,
                &m0.pix.to_vec(),
                &m1.pix.to_vec(),
                m0.stride,
                m1.stride,
            );
        }
    }
}

/// Delivers all but the last bytes, then the rest together with EOF
/// (Go's `eofReader`).
struct EofReader {
    data: Vec<u8>,
    data_eof: Vec<u8>,
}

impl Read for EofReader {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        if !self.data.is_empty() {
            let n = b.len().min(self.data.len());
            b[..n].copy_from_slice(&self.data[..n]);
            self.data.drain(..n);
            return Ok(n);
        }
        let n = b.len().min(self.data_eof.len());
        b[..n].copy_from_slice(&self.data_eof[..n]);
        self.data_eof.drain(..n);
        Ok(n)
    }
}

#[test]
fn decode_eof() {
    let data = fixture("video-001.jpeg");
    let n = data.len();
    let mut i = 0;
    while i < n {
        let r = EofReader {
            data: data[..n - i].to_vec(),
            data_eof: data[n - i..].to_vec(),
        };
        jpeg::decode(r).unwrap_or_else(|e| panic!("trailing {i} bytes with EOF: {e}"));
        i = if i == 0 { 1 } else { i * 2 };
    }
}

#[test]
fn truncated_sos_data_does_not_panic() {
    let b = fixture("video-005.gray.q50.jpeg");
    let at = b.windows(2).position(|w| w == [0xff, 0xda]).unwrap() + 2;
    for i in at..(at + 10).min(b.len()) {
        let _ = jpeg::decode(&b[..i]);
    }
}

#[test]
fn large_image_with_short_data() {
    // The fuzzer-generated input of golang.org/issue/10413.
    let input: &[u8] = b"\
\xff\xd8\xff\xe0\x00\x10\x4a\x46\x49\x46\x00\x01\x01\x00\x00\x01\
\x00\x01\x00\x00\xff\xdb\x00\x43\x00\x10\x0b\x0c\x0e\x0c\x0a\x10\
\x0e\x89\x0e\x12\x11\x10\x13\x18\xff\xd8\xff\xe0\x00\x10\x4a\x46\
\x49\x46\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xdb\x00\x43\
\x00\x10\x0b\x0c\x0e\x0c\x0a\x10\x0e\x0d\x0e\x12\x11\x10\x13\x18\
\x28\x1a\x18\x16\x16\x18\x31\x23\x25\x1d\x28\x3a\x33\x3d\x3c\x39\
\x33\x38\x37\x40\x48\x5c\x4e\x40\x44\x57\x45\x37\x38\x50\x6d\x51\
\x57\x5f\x62\x67\x68\x67\x3e\x4d\x71\x79\x70\x64\x78\x5c\x65\x67\
\x63\xff\xc0\x00\x0b\x08\x20\x00\x20\x00\x01\x01\x11\x00\xff\xc4\
\x00\x1f\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\
\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\xff\
\xc4\x00\xb5\x10\x00\x02\x01\x03\x03\x02\x04\x03\x05\x05\x04\x04\
\x00\x00\x01\x7d\x01\x02\x03\x00\x04\x11\x05\x12\x21\x31\x01\x06\
\x13\x51\x61\x07\x22\x71\x14\x32\x81\x91\xa1\x08\x23\xd8\xff\xdd\
\x42\xb1\xc1\x15\x52\xd1\xf0\x24\x33\x62\x72\x82\x09\x0a\x16\x17\
\x18\x19\x1a\x25\x26\x27\x28\x29\x2a\x34\x35\x36\x37\x38\x39\x3a\
\x43\x44\x45\x46\x47\x48\x49\x4a\x53\x54\x55\x56\x57\x58\x59\x5a\
\x00\x63\x64\x65\x66\x67\x68\x69\x6a\x73\x74\x75\x76\x77\x78\x79\
\x7a\x83\x84\x85\x86\x87\x88\x89\x8a\x92\x93\x94\x95\x96\x97\x98\
\x99\x9a\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xb2\xb3\xb4\xb5\xb6\
\xb7\xb8\xb9\xba\xc2\xc3\xc4\xc5\xc6\xc7\xff\xd8\xff\xe0\x00\x10\
\x4a\x46\x49\x46\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xdb\
\x00\x43\x00\x10\x0b\x0c\x0e\x0c\x0a\x10\x0e\x0d\x0e\x12\x11\x10\
\x13\x18\x28\x1a\x18\x16\x16\x18\x31\x23\x25\x1d\xc8\xc9\xca\xd2\
\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\
\xe9\xea\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xff\xda\x00\x08\
\x01\x01\x00\x00\x3f\x00\xb9\xeb\x50\xb0\xdb\xc8\xa8\xe4\x63\x80\
\xdd\x31\xd6\x9d\xbb\xf2\xc5\x42\x1f\x6c\x6f\xf4\x34\xdd\x3c\xfc\
\xac\xe7\x3d\x80\xa9\xcc\x87\x34\xb3\x37\xfa\x2b\x9f\x6a\xad\x63\
\x20\x36\x9f\x78\x64\x75\xe6\xab\x7d\xb2\xde\x29\x70\xd3\x20\x27\
\xde\xaf\xa4\xf0\xca\x9f\x24\xa8\xdf\x46\xa8\x24\x84\x96\xe3\x77\
\xf9\x2e\xe0\x0a\x62\x7f\xdf\xd9";
    assert!(jpeg::decode(input).is_err());
}

#[test]
fn padded_rst_marker() {
    // golang.org/issue/28717.
    decode_file("padded_rst.jpeg").unwrap();
}

fn average_delta(m0: &dyn Image, m1: &dyn Image) -> i64 {
    let b = m0.bounds();
    let (mut sum, mut n) = (0i64, 0i64);
    for y in b.min.y..b.max.y {
        for x in b.min.x..b.max.x {
            let (r0, g0, b0, _) = m0.at(x, y).rgba();
            let (r1, g1, b1, _) = m1.at(x, y).rgba();
            sum += (i64::from(r0) - i64::from(r1)).abs();
            sum += (i64::from(g0) - i64::from(g1)).abs();
            sum += (i64::from(b0) - i64::from(b1)).abs();
            n += 3;
        }
    }
    sum / n
}

#[test]
fn extraneous_data() {
    // Encode a 1x1 red image.
    let mut src = Rgba::new(rect(0, 0, 1, 1));
    src.pix.copy_from_slice(&[0xff, 0, 0, 0xff]);
    let mut enc = Vec::new();
    jpeg::encode(&mut enc, &src, None).unwrap();
    assert!(enc.len() >= 64);
    assert_eq!(&enc[enc.len() - 2..], b"\xff\xd9");
    assert!(enc[enc.len() - 64..].windows(2).any(|w| w == [0xff, 0xda]));
    // Random junk between the SOS data and the EOI marker is ignored. A fixed
    // linear congruential generator keeps the test deterministic.
    let mut state = 1u64;
    let mut next = move |n: u64| {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (state >> 33) % n
    };
    for i in 0..1000 {
        let mut data = enc[..enc.len() - 2].to_vec();
        for _ in 0..next(10) {
            let x = next(256) as u8;
            if x != 0xff {
                data.push(x);
            } else {
                data.extend_from_slice(b"\xff\x00");
            }
        }
        data.extend_from_slice(b"\xff\xd9");
        let got = jpeg::decode(&data[..]).unwrap_or_else(|e| panic!("image #{i}: {e}"));
        assert_eq!(got.bounds(), src.bounds());
        assert!(average_delta(got.as_ref(), &src) <= 2 << 8, "image #{i}");
    }
}

#[test]
fn issue_56724() {
    let b = fixture("video-001.jpeg");
    let err = jpeg::decode(&b[..24]).err().unwrap();
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(err.to_string(), "unexpected EOF");
}

#[test]
fn issue_78368() {
    // Must not panic.
    let _ = jpeg::decode(
        &[
            0xff, 0xd8, 0xff, 0xdb, 0x00, 0x84, 0x00, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0xff,
            0x20, 0x20, 0x20, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x20, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x20, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0x01, 0xff, 0xff, 0xff, 0x20, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0x20, 0xff, 0xff, 0x20, 0x20, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0x20, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xc2, 0x00, 0x11, 0x08, 0x00, 0x20, 0x00, 0x20, 0x03, 0x01, 0x11, 0x00,
            0x20, 0x21, 0x01, 0xff, 0x11, 0x01, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
            0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
            0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
            0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
            0xff, 0xc4, 0x00, 0x27, 0x10, 0x01, 0x00, 0x02, 0x01, 0x04, 0x01, 0x03, 0x04, 0x03,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
            0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0xff, 0xda,
            0x00, 0x08, 0x01, 0x20, 0x20, 0x20, 0x20, 0xed, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
            0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0xff, 0xee, 0x00,
            0x0e, 0x41, 0x64, 0x6f, 0x62, 0x65, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x00, 0xff,
            0xd9, 0x20, 0x20,
        ][..],
    );
}

#[test]
fn bad_restart_marker() {
    let b = fixture("video-001.restart2.jpeg");
    assert_eq!(b.len(), 4855);
    assert_eq!((b[2816], b[2817]), (0xff, 0xd1));
    let (prefix, suffix) = b.split_at(2816);
    let cases: &[(&[u8], bool)] = &[
        (b"", true),
        (b"\x00", true),
        (b"\x61", true),
        (b"\x61\x62\x63\xff\x00\x64", true),
        (b"\xff", true),
        (b"\xff\x00", true),
        (b"\xff\xff\xff\x00\xff\x00\x00\xff\xff\xff", true),
        (b"\xff\x03", false),
        (b"\xff\xd5", false),
        (b"\xff\xff\xd5", false),
    ];
    for (infix, want) in cases {
        let data = [prefix, infix, suffix].concat();
        assert_eq!(jpeg::decode(&data[..]).is_ok(), *want, "{infix:?}");
    }
}

#[test]
fn decode_flex_subsampling() {
    for (name, file) in [
        ("2x2,1x1,2x2", "video-001.q50.221122.jpeg"),
        ("2x1,1x2,1x1", "video-001.q50.211211.jpeg"),
        ("2x2,2x1,1x2", "video-001.q50.222112.jpeg"),
        ("1x2,1x1,2x1", "video-001.q50.121121.jpeg"),
    ] {
        let m = decode_file(file).unwrap();
        assert_eq!(m.bounds(), rect(0, 0, 150, 103), "{name}");
        let ycbcr = downcast::<Ycbcr>(m.as_ref());
        assert_eq!(
            ycbcr.subsample_ratio,
            YcbcrSubsampleRatio::Ratio444,
            "{name}"
        );
    }
}

#[test]
fn decode_types_and_config() {
    for (file, model, w, h) in [
        ("video-001.jpeg", Model::Ycbcr, 150, 103),
        ("video-001.rgb.jpeg", Model::Rgba, 150, 103),
        ("video-001.cmyk.jpeg", Model::Cmyk, 150, 103),
        ("video-005.gray.jpeg", Model::Gray, 150, 103),
    ] {
        let data = fixture(file);
        let cfg = jpeg::decode_config(&data[..]).unwrap();
        assert_eq!(
            (cfg.color_model, cfg.width, cfg.height),
            (model.clone(), w, h),
            "{file}"
        );
        let m = jpeg::decode(&data[..]).unwrap();
        assert_eq!(m.bounds(), rect(0, 0, w, h));
        let ok = match model {
            Model::Ycbcr => m.as_any().is_some_and(|a| a.is::<Ycbcr>()),
            Model::Rgba => m.as_any().is_some_and(|a| a.is::<Rgba>()),
            Model::Cmyk => m.as_any().is_some_and(|a| a.is::<Cmyk>()),
            _ => m.as_any().is_some_and(|a| a.is::<Gray>()),
        };
        assert!(ok, "{file}");
    }
}

#[test]
fn registered_with_image_decode() {
    let (m, name) = image::decode(&fixture("video-001.jpeg")[..]).unwrap();
    assert_eq!(name, "jpeg");
    assert_eq!(m.bounds(), rect(0, 0, 150, 103));
    let (cfg, name) = image::decode_config(&fixture("video-005.gray.jpeg")[..]).unwrap();
    assert_eq!((name.as_str(), cfg.width), ("jpeg", 150));
}

#[test]
fn error_texts_and_classes() {
    let err = jpeg::decode(&b"\xff\xd9"[..]).err().unwrap();
    assert_eq!(err.to_string(), "invalid JPEG format: missing SOI marker");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.get_ref().unwrap().is::<FormatError>());
    // A progressive scan with an unsupported precision.
    let err = jpeg::decode(&b"\xff\xd8\xff\xc0\x00\x0b\x0c\x00\x08\x00\x08\x01\x01\x11\x00"[..])
        .err()
        .unwrap();
    assert_eq!(err.to_string(), "unsupported JPEG feature: precision");
    assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    assert!(err.get_ref().unwrap().is::<UnsupportedError>());
    let err = jpeg::decode(&b"\xff\xd8\xff\xc3\x00\x02"[..])
        .err()
        .unwrap();
    assert_eq!(err.to_string(), "unsupported JPEG feature: unknown marker");
    let err = jpeg::decode(&b"\xff\xd8\xff\xd9"[..]).err().unwrap();
    assert_eq!(err.to_string(), "invalid JPEG format: missing SOS marker");
    assert_eq!(
        jpeg::decode_config(&b"\xff\xd8\xff\xd9"[..])
            .err()
            .unwrap()
            .to_string(),
        "invalid JPEG format: missing SOS marker"
    );
}

#[test]
fn write_grayscale() {
    let mut m0 = Gray::new(rect(0, 0, 32, 32));
    for i in 0..m0.pix.len() {
        m0.pix.set(i, i as u8);
    }
    let mut buf = Vec::new();
    jpeg::encode(&mut buf, &m0, None).unwrap();
    let m1 = jpeg::decode(&buf[..]).unwrap();
    assert_eq!(m0.bounds(), m1.bounds());
    assert!(m1.as_any().is_some_and(|a| a.is::<Gray>()));
    assert!(average_delta(&m0, m1.as_ref()) <= 2 << 8);
}

#[test]
fn writer_round_trips_png() {
    let png_bytes = fixture("video-001.png");
    let m0 = png::decode(&png_bytes[..]).unwrap();
    for (quality, tolerance) in [
        (1, 24 << 8),
        (20, 12 << 8),
        (60, 8 << 8),
        (80, 6 << 8),
        (90, 4 << 8),
        (100, 2 << 8),
    ] {
        let mut buf = Vec::new();
        jpeg::encode(&mut buf, &m0, Some(&Options { quality })).unwrap();
        let m1 = jpeg::decode(&buf[..]).unwrap();
        assert_eq!(m0.bounds(), m1.bounds());
        let d = average_delta(&m0, m1.as_ref());
        assert!(
            d <= tolerance,
            "quality={quality}: average delta is too high ({d} > {tolerance})"
        );
    }
}

/// An image that hides its concrete type, forcing the generic color path.
struct Hidden<'a>(&'a dyn Image);

impl Image for Hidden<'_> {
    fn color_model(&self) -> Model {
        self.0.color_model()
    }
    fn bounds(&self) -> image::Rectangle {
        self.0.bounds()
    }
    fn at(&self, x: i32, y: i32) -> color::Color {
        self.0.at(x, y)
    }
}

#[test]
fn encode_ycbcr_equals_rgba_and_generic_paths() {
    let bo = rect(0, 0, 160, 120);
    let mut rgba = Rgba::new(bo);
    // 4:4:4 avoids the lossy RGBA to YCbCr conversion.
    let mut ycbcr = Ycbcr::new(bo, YcbcrSubsampleRatio::Ratio444);
    let mut state = 123u64;
    for y in bo.min.y..bo.max.y {
        for x in bo.min.x..bo.max.x {
            let mut c = [0u8; 4];
            for v in &mut c[..3] {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *v = (state >> 56) as u8;
            }
            c[3] = 255;
            let o = rgba.pix_offset(x, y);
            for (k, v) in c.iter().enumerate() {
                rgba.pix.set(o + k, *v);
            }
            let (yo, co) = (ycbcr.y_offset(x, y), ycbcr.c_offset(x, y));
            let (cy, cb, cr) = color::rgb_to_ycbcr(c[0], c[1], c[2]);
            ycbcr.y.set(yo, cy);
            ycbcr.cb.set(co, cb);
            ycbcr.cr.set(co, cr);
        }
    }
    let encode = |m: &dyn Image| {
        let mut buf = Vec::new();
        jpeg::encode(&mut buf, m, None).unwrap();
        buf
    };
    let a = encode(&rgba);
    assert_eq!(a, encode(&ycbcr), "RGBA and YCbCr encoded bytes differ");
    assert_eq!(
        a,
        encode(&Hidden(&rgba)),
        "RGBA and generic encoded bytes differ"
    );
}

#[test]
fn encode_options_and_limits() {
    assert_eq!(jpeg::DEFAULT_QUALITY, 75);
    let mut m = Rgba::new(rect(0, 0, 9, 9));
    for i in 0..m.pix.len() {
        m.pix.set(i, (i * 7) as u8 | 0x80);
    }
    let enc = |o: Option<&Options>| {
        let mut buf = Vec::new();
        jpeg::encode(&mut buf, &m, o).unwrap();
        buf
    };
    // nil options mean quality 75; qualities clamp to [1, 100].
    assert_eq!(enc(None), enc(Some(&Options { quality: 75 })));
    assert_eq!(
        enc(Some(&Options { quality: -4 })),
        enc(Some(&Options { quality: 1 }))
    );
    assert_eq!(
        enc(Some(&Options { quality: 0 })),
        enc(Some(&Options::default()))
    );
    assert_eq!(
        enc(Some(&Options { quality: 1000 })),
        enc(Some(&Options { quality: 100 }))
    );
    assert_ne!(
        enc(Some(&Options { quality: 50 })),
        enc(Some(&Options { quality: 51 }))
    );

    let wide = Gray::new(rect(0, 0, 1 << 16, 1));
    let err = jpeg::encode(&mut Vec::new(), &wide, None).unwrap_err();
    assert_eq!(err.to_string(), "jpeg: image is too large to encode");
    let wide = Gray::new(rect(0, 0, (1 << 16) - 1, 1));
    jpeg::encode(&mut Vec::new(), &wide, None).unwrap();
    // A failing writer's first error is returned.
    struct Failing;
    impl io::Write for Failing {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("sink failed"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let err = jpeg::encode(Failing, &m, None).unwrap_err();
    assert_eq!(err.to_string(), "sink failed");
}

#[test]
fn encode_respects_non_zero_origin_and_edges() {
    let r = rect(-3, 5, 12, 22);
    let mut m = Gray::new(r);
    for i in 0..m.pix.len() {
        m.pix.set(i, (i * 13) as u8);
    }
    let mut buf = Vec::new();
    jpeg::encode(&mut buf, &m, Some(&Options { quality: 100 })).unwrap();
    let d = jpeg::decode(&buf[..]).unwrap();
    // The JPEG has no origin: bounds are the size at (0, 0).
    assert_eq!(d.bounds(), rect(0, 0, r.dx(), r.dy()));
    assert_eq!(d.bounds().max, pt(15, 17));
}

#[test]
fn huge_dimensions_are_limited_not_aborted() {
    // A 65535x65535 baseline frame header with no scan data: decoding fails
    // cleanly (the budget rejects it before any allocation).
    let mut data = vec![
        0xff, 0xd8, 0xff, 0xc0, 0x00, 0x0b, 0x08, 0xff, 0xff, 0xff, 0xff, 0x01, 0x01, 0x11, 0x00,
    ];
    data.extend_from_slice(&[0xff, 0xda, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3f, 0x00]);
    let err = jpeg::decode_with_limits(
        &data[..],
        jpeg::Limits {
            max_pixels: 1 << 20,
        },
    )
    .err()
    .unwrap();
    assert!(err.to_string().contains("over the limit"), "{err}");
}
