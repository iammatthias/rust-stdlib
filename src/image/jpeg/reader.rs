//! The JPEG decoder state and marker parsing (Go's `reader.go`).
use std::io::{self, Read};

use super::dct::{Block, BLOCK_SIZE};
use super::huffman::Huffman;
use super::{FormatError, Limits, UnsupportedError};
use crate::image::color;
use crate::image::ycbcr::{self, Ycbcr, YcbcrSubsampleRatio};
use crate::image::{rect, Cmyk, Config, Gray, Pix, Rgba};

/// The error type of the decoder internals; converted to an `io::Error` at
/// the public boundary.
#[derive(Debug)]
pub(super) enum Error {
    Format(&'static str),
    Unsupported(&'static str),
    /// Go's `io.ErrUnexpectedEOF`.
    UnexpectedEof,
    Io(io::Error),
    /// A [`Limits`] budget or an allocation failure.
    Limit(String),
}

pub(super) const ERR_MISSING_FF00: &str = "missing 0xff00 sequence";
pub(super) const ERR_SHORT_HUFFMAN_DATA: &str = "short Huffman data";
const ERR_UNSUPPORTED_SUBSAMPLING: Error = Error::Unsupported("luma/chroma subsampling ratio");

impl From<Error> for io::Error {
    fn from(error: Error) -> io::Error {
        match error {
            Error::Format(m) => {
                io::Error::new(io::ErrorKind::InvalidData, FormatError(m.to_owned()))
            }
            Error::Unsupported(m) => {
                io::Error::new(io::ErrorKind::Unsupported, UnsupportedError(m.to_owned()))
            }
            Error::UnexpectedEof => io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF"),
            Error::Io(error) => error,
            Error::Limit(m) => io::Error::new(io::ErrorKind::InvalidData, m),
        }
    }
}

pub(super) type Result<T> = std::result::Result<T, Error>;

/// Component specification, section B.2.2.
#[derive(Clone, Copy, Default)]
pub(super) struct Component {
    /// Horizontal sampling factor.
    pub h: i32,
    /// Vertical sampling factor.
    pub v: i32,
    /// Component identifier.
    pub c: u8,
    /// Quantization table destination selector.
    pub tq: u8,
    /// Horizontal expansion factor for non-standard subsampling.
    pub expand_h: i32,
    /// Vertical expansion factor for non-standard subsampling.
    pub expand_v: i32,
}

pub(super) const MAX_TC: u8 = 1;
pub(super) const MAX_TH: u8 = 3;
const MAX_TQ: u8 = 3;
pub(super) const MAX_COMPONENTS: usize = 4;

const SOF0_MARKER: u8 = 0xc0;
const SOF1_MARKER: u8 = 0xc1;
const SOF2_MARKER: u8 = 0xc2;
const DHT_MARKER: u8 = 0xc4;
pub(super) const RST0_MARKER: u8 = 0xd0;
pub(super) const RST7_MARKER: u8 = 0xd7;
const SOI_MARKER: u8 = 0xd8;
const EOI_MARKER: u8 = 0xd9;
const SOS_MARKER: u8 = 0xda;
const DQT_MARKER: u8 = 0xdb;
const DRI_MARKER: u8 = 0xdd;
const COM_MARKER: u8 = 0xfe;
const APP0_MARKER: u8 = 0xe0;
const APP14_MARKER: u8 = 0xee;
const APP15_MARKER: u8 = 0xef;

const ADOBE_TRANSFORM_UNKNOWN: u8 = 0;

/// Maps the zig-zag ordering to the natural ordering.
pub(super) const UNZIG: [usize; BLOCK_SIZE] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20,
    13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59,
    52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
];

/// Unprocessed bits taken from the byte stream: the `n` least significant bits
/// of `a` are unread, to be consumed from most to least significant.
#[derive(Clone, Copy, Default)]
pub(super) struct Bits {
    /// Accumulator.
    pub a: u32,
    /// Mask: `1 << (n-1)` when `n > 0`, else 0.
    pub m: u32,
    /// Number of unread bits in `a`.
    pub n: i32,
}

/// A decoded image of one of the four types Go's decoder returns.
pub(super) enum Decoded {
    Gray(Gray),
    Ycbcr(Ycbcr),
    Rgba(Rgba),
    Cmyk(Cmyk),
}

const BUF_SIZE: usize = 4096;

pub(super) struct Decoder<R: Read> {
    r: R,
    pub bits: Bits,
    /// A byte buffer like `bufio.Reader`'s, but able to unread more than one
    /// byte because of byte stuffing.
    buf: Box<[u8; BUF_SIZE]>,
    i: usize,
    j: usize,
    /// Bytes to back `i` up by after overshooting: 0, 1 or 2.
    pub n_unreadable: usize,
    pub width: i32,
    pub height: i32,

    pub img1: Option<Gray>,
    pub img3: Option<Ycbcr>,
    pub black_pix: Option<Pix>,
    pub black_stride: usize,

    /// Non-standard subsampling that needs manual pixel expansion.
    pub flex: bool,
    pub max_h: i32,
    pub max_v: i32,

    /// Restart interval.
    pub ri: i32,
    pub n_comp: usize,

    pub baseline: bool,
    pub progressive: bool,

    jfif: bool,
    adobe_transform_valid: bool,
    adobe_transform: u8,
    /// End-of-band run, section G.1.2.2.
    pub eob_run: u16,

    pub comp: [Component; MAX_COMPONENTS],
    pub prog_coeffs: [Option<Vec<Block>>; MAX_COMPONENTS],
    pub huff: Box<[[Huffman; (MAX_TH + 1) as usize]; (MAX_TC + 1) as usize]>,
    /// Quantization tables, in zig-zag order.
    pub quant: [Block; (MAX_TQ + 1) as usize],
    pub tmp: [u8; 2 * BLOCK_SIZE],
    pub limits: Limits,
}

/// Allocates `n` zero bytes, reporting failure instead of aborting.
pub(super) fn alloc_bytes(n: usize) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    v.try_reserve_exact(n)
        .map_err(|_| Error::Limit("jpeg: image too large to allocate".to_owned()))?;
    v.resize(n, 0);
    Ok(v)
}

/// Allocates `n` zeroed blocks, reporting failure instead of aborting.
pub(super) fn alloc_block_vec(n: usize) -> Result<Vec<Block>> {
    let mut v = Vec::new();
    v.try_reserve_exact(n)
        .map_err(|_| Error::Limit("jpeg: image too large to allocate".to_owned()))?;
    v.resize(n, [0; BLOCK_SIZE]);
    Ok(v)
}

impl<R: Read> Decoder<R> {
    pub fn new(r: R, limits: Limits) -> Self {
        Decoder {
            r,
            bits: Bits::default(),
            buf: Box::new([0; BUF_SIZE]),
            i: 0,
            j: 0,
            n_unreadable: 0,
            width: 0,
            height: 0,
            img1: None,
            img3: None,
            black_pix: None,
            black_stride: 0,
            flex: false,
            max_h: 0,
            max_v: 0,
            ri: 0,
            n_comp: 0,
            baseline: false,
            progressive: false,
            jfif: false,
            adobe_transform_valid: false,
            adobe_transform: 0,
            eob_run: 0,
            comp: [Component::default(); MAX_COMPONENTS],
            prog_coeffs: [None, None, None, None],
            huff: Box::new(std::array::from_fn(|_| {
                std::array::from_fn(|_| Huffman::default())
            })),
            quant: [[0; BLOCK_SIZE]; (MAX_TQ + 1) as usize],
            tmp: [0; 2 * BLOCK_SIZE],
            limits,
        }
    }

    /// Fills the buffer from the reader; only valid when there are no unread
    /// bytes.
    fn fill(&mut self) -> Result<()> {
        debug_assert_eq!(self.i, self.j);
        // Move the last 2 bytes to the start of the buffer, in case
        // unread_byte_stuffed_byte is called.
        if self.j > 2 {
            self.buf[0] = self.buf[self.j - 2];
            self.buf[1] = self.buf[self.j - 1];
            self.i = 2;
            self.j = 2;
        }
        loop {
            match self.r.read(&mut self.buf[self.j..]) {
                Ok(0) => return Err(Error::UnexpectedEof),
                Ok(n) => {
                    self.j += n;
                    return Ok(());
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(Error::Io(error)),
            }
        }
    }

    /// Undoes the most recent `read_byte_stuffed_byte`, giving a byte back
    /// from the bit accumulator to the buffer.
    pub fn unread_byte_stuffed_byte(&mut self) {
        self.i -= self.n_unreadable;
        self.n_unreadable = 0;
        if self.bits.n >= 8 {
            self.bits.a >>= 8;
            self.bits.n -= 8;
            self.bits.m >>= 8;
        }
    }

    /// The next byte, ignoring byte stuffing.
    pub fn read_byte(&mut self) -> Result<u8> {
        while self.i == self.j {
            self.fill()?;
        }
        let x = self.buf[self.i];
        self.i += 1;
        self.n_unreadable = 0;
        Ok(x)
    }

    /// Like [`read_byte`](Self::read_byte), for byte-stuffed Huffman data.
    pub fn read_byte_stuffed_byte(&mut self) -> Result<u8> {
        // Fast path when the buffer holds at least two bytes.
        if self.i + 2 <= self.j {
            let x = self.buf[self.i];
            self.i += 1;
            self.n_unreadable = 1;
            if x != 0xff {
                return Ok(x);
            }
            if self.buf[self.i] != 0x00 {
                return Err(Error::Format(ERR_MISSING_FF00));
            }
            self.i += 1;
            self.n_unreadable = 2;
            return Ok(0xff);
        }

        self.n_unreadable = 0;

        let x = self.read_byte()?;
        self.n_unreadable = 1;
        if x != 0xff {
            return Ok(x);
        }

        let x = self.read_byte()?;
        self.n_unreadable = 2;
        if x != 0x00 {
            return Err(Error::Format(ERR_MISSING_FF00));
        }
        Ok(0xff)
    }

    /// Unreads the overshot bytes, if any.
    fn unread_overshoot(&mut self) {
        if self.n_unreadable != 0 {
            if self.bits.n >= 8 {
                self.unread_byte_stuffed_byte();
            }
            self.n_unreadable = 0;
        }
    }

    /// Reads exactly `p.len()` bytes, ignoring byte stuffing.
    pub fn read_full(&mut self, p: &mut [u8]) -> Result<()> {
        self.unread_overshoot();
        let mut done = 0;
        loop {
            let n = (p.len() - done).min(self.j - self.i);
            p[done..done + n].copy_from_slice(&self.buf[self.i..self.i + n]);
            done += n;
            self.i += n;
            if done == p.len() {
                return Ok(());
            }
            self.fill()?;
        }
    }

    /// Reads `tmp[lo..hi]`.
    pub fn read_tmp(&mut self, lo: usize, hi: usize) -> Result<()> {
        let mut t = self.tmp;
        self.read_full(&mut t[lo..hi])?;
        self.tmp = t;
        Ok(())
    }

    /// Ignores the next `n` bytes.
    fn ignore(&mut self, mut n: usize) -> Result<()> {
        self.unread_overshoot();
        loop {
            let m = (self.j - self.i).min(n);
            self.i += m;
            n -= m;
            if n == 0 {
                return Ok(());
            }
            self.fill()?;
        }
    }

    /// Start of frame, section B.2.2.
    fn process_sof(&mut self, n: usize) -> Result<()> {
        if self.n_comp != 0 {
            return Err(Error::Format("multiple SOF markers"));
        }
        self.n_comp = match n {
            9 => 1,
            15 => 3,
            18 => 4,
            _ => return Err(Error::Unsupported("number of components")),
        };
        self.read_tmp(0, n)?;
        if self.tmp[0] != 8 {
            return Err(Error::Unsupported("precision"));
        }
        self.height = (i32::from(self.tmp[1]) << 8) + i32::from(self.tmp[2]);
        self.width = (i32::from(self.tmp[3]) << 8) + i32::from(self.tmp[4]);
        if usize::from(self.tmp[5]) != self.n_comp {
            return Err(Error::Format("SOF has wrong length"));
        }

        for i in 0..self.n_comp {
            self.comp[i].c = self.tmp[6 + 3 * i];
            for j in 0..i {
                if self.comp[i].c == self.comp[j].c {
                    return Err(Error::Format("repeated component identifier"));
                }
            }

            self.comp[i].tq = self.tmp[8 + 3 * i];
            if self.comp[i].tq > MAX_TQ {
                return Err(Error::Format("bad Tq value"));
            }

            let hv = self.tmp[7 + 3 * i];
            let (mut h, mut v) = (i32::from(hv >> 4), i32::from(hv & 0x0f));
            if !(1..=4).contains(&h) || !(1..=4).contains(&v) {
                return Err(Error::Format("luma/chroma subsampling ratio"));
            }
            if h == 3 || v == 3 {
                return Err(ERR_UNSUPPORTED_SUBSAMPLING);
            }
            match self.n_comp {
                // A single component is non-interleaved by definition, so its
                // effective sampling factors are always (1, 1).
                1 => {
                    h = 1;
                    v = 1;
                }
                // YCbCr or RGB: any factors that divide the maximum factors,
                // validated after the loop.
                3 => {}
                // CMYK or YCbCrK: only [0x11 0x11 0x11 0x11] and
                // [0x22 0x11 0x11 0x22] are supported.
                _ => match i {
                    0 => {
                        if hv != 0x11 && hv != 0x22 {
                            return Err(ERR_UNSUPPORTED_SUBSAMPLING);
                        }
                    }
                    1 | 2 => {
                        if hv != 0x11 {
                            return Err(ERR_UNSUPPORTED_SUBSAMPLING);
                        }
                    }
                    _ => {
                        if self.comp[0].h != h || self.comp[0].v != v {
                            return Err(ERR_UNSUPPORTED_SUBSAMPLING);
                        }
                    }
                },
            }

            self.max_h = self.max_h.max(h);
            self.max_v = self.max_v.max(v);
            self.comp[i].h = h;
            self.comp[i].v = v;
        }

        if self.n_comp == 3 {
            for i in 0..3 {
                if self.max_h % self.comp[i].h != 0 || self.max_v % self.comp[i].v != 0 {
                    return Err(ERR_UNSUPPORTED_SUBSAMPLING);
                }
            }
        }

        for i in 0..self.n_comp {
            self.comp[i].expand_h = self.max_h / self.comp[i].h;
            self.comp[i].expand_v = self.max_v / self.comp[i].v;
        }
        Ok(())
    }

    /// Define quantization table, section B.2.4.1.
    fn process_dqt(&mut self, mut n: usize) -> Result<()> {
        'segment: while n > 0 {
            n -= 1;
            let x = self.read_byte()?;
            let tq = usize::from(x & 0x0f);
            if tq > usize::from(MAX_TQ) {
                return Err(Error::Format("bad Tq value"));
            }
            match x >> 4 {
                0 => {
                    if n < BLOCK_SIZE {
                        break 'segment;
                    }
                    n -= BLOCK_SIZE;
                    self.read_tmp(0, BLOCK_SIZE)?;
                    for i in 0..BLOCK_SIZE {
                        self.quant[tq][i] = i32::from(self.tmp[i]);
                    }
                }
                1 => {
                    if n < 2 * BLOCK_SIZE {
                        break 'segment;
                    }
                    n -= 2 * BLOCK_SIZE;
                    self.read_tmp(0, 2 * BLOCK_SIZE)?;
                    for i in 0..BLOCK_SIZE {
                        self.quant[tq][i] =
                            (i32::from(self.tmp[2 * i]) << 8) | i32::from(self.tmp[2 * i + 1]);
                    }
                }
                _ => return Err(Error::Format("bad Pq value")),
            }
        }
        if n != 0 {
            return Err(Error::Format("DQT has wrong length"));
        }
        Ok(())
    }

    /// Define restart interval, section B.2.4.4.
    fn process_dri(&mut self, n: usize) -> Result<()> {
        if n != 2 {
            return Err(Error::Format("DRI has wrong length"));
        }
        self.read_tmp(0, 2)?;
        self.ri = (i32::from(self.tmp[0]) << 8) + i32::from(self.tmp[1]);
        Ok(())
    }

    fn process_app0_marker(&mut self, mut n: usize) -> Result<()> {
        if n < 5 {
            return self.ignore(n);
        }
        self.read_tmp(0, 5)?;
        n -= 5;
        self.jfif = &self.tmp[..5] == b"JFIF\0";
        if n > 0 {
            return self.ignore(n);
        }
        Ok(())
    }

    fn process_app14_marker(&mut self, mut n: usize) -> Result<()> {
        if n < 12 {
            return self.ignore(n);
        }
        self.read_tmp(0, 12)?;
        n -= 12;
        if &self.tmp[..5] == b"Adobe" {
            self.adobe_transform_valid = true;
            self.adobe_transform = self.tmp[11];
        }
        if n > 0 {
            return self.ignore(n);
        }
        Ok(())
    }

    /// Reads the image, or only up to its dimensions when `config_only`.
    pub fn decode(&mut self, config_only: bool) -> Result<Option<Decoded>> {
        // Check for the Start Of Image marker.
        self.read_tmp(0, 2)?;
        if self.tmp[0] != 0xff || self.tmp[1] != SOI_MARKER {
            return Err(Error::Format("missing SOI marker"));
        }

        // Process the remaining segments until the End Of Image marker.
        loop {
            self.read_tmp(0, 2)?;
            // Extraneous data between segments is silently ignored, as in
            // libjpeg.
            while self.tmp[0] != 0xff {
                self.tmp[0] = self.tmp[1];
                self.tmp[1] = self.read_byte()?;
            }
            let mut marker = self.tmp[1];
            if marker == 0 {
                // Treat "\xff\x00" as extraneous data.
                continue;
            }
            while marker == 0xff {
                // Any marker may be preceded by fill bytes (section B.1.1.2).
                marker = self.read_byte()?;
            }
            if marker == EOI_MARKER {
                break;
            }
            if (RST0_MARKER..=RST7_MARKER).contains(&marker) {
                // A restart marker after the final scan data: harmless.
                continue;
            }

            // The 16-bit length includes its own 2 bytes.
            self.read_tmp(0, 2)?;
            let n = (i32::from(self.tmp[0]) << 8) + i32::from(self.tmp[1]) - 2;
            if n < 0 {
                return Err(Error::Format("short segment length"));
            }
            let n = n as usize;

            match marker {
                SOF0_MARKER | SOF1_MARKER | SOF2_MARKER => {
                    self.baseline = marker == SOF0_MARKER;
                    self.progressive = marker == SOF2_MARKER;
                    let result = self.process_sof(n);
                    if config_only && self.jfif {
                        return result.map(|()| None);
                    }
                    result?;
                }
                DHT_MARKER => {
                    if config_only {
                        self.ignore(n)?;
                    } else {
                        self.process_dht(n)?;
                    }
                }
                DQT_MARKER => {
                    if config_only {
                        self.ignore(n)?;
                    } else {
                        self.process_dqt(n)?;
                    }
                }
                SOS_MARKER => {
                    if config_only {
                        return Ok(None);
                    }
                    self.process_sos(n)?;
                }
                DRI_MARKER => {
                    if config_only {
                        self.ignore(n)?;
                    } else {
                        self.process_dri(n)?;
                    }
                }
                APP0_MARKER => self.process_app0_marker(n)?,
                APP14_MARKER => self.process_app14_marker(n)?,
                _ => {
                    if (APP0_MARKER..=APP15_MARKER).contains(&marker) || marker == COM_MARKER {
                        self.ignore(n)?;
                    } else if marker < 0xc0 {
                        // Table B.1, "Marker code assignments".
                        return Err(Error::Format("unknown marker"));
                    } else {
                        return Err(Error::Unsupported("unknown marker"));
                    }
                }
            }
        }

        if self.progressive {
            self.reconstruct_progressive_image()?;
        }
        if let Some(img1) = self.img1.take() {
            return Ok(Some(Decoded::Gray(img1)));
        }
        if self.img3.is_some() {
            if self.black_pix.is_some() {
                return self.apply_black().map(Some);
            } else if self.is_rgb() {
                return self.convert_to_rgb().map(Some);
            }
            return Ok(self.img3.take().map(Decoded::Ycbcr));
        }
        Err(Error::Format("missing SOS marker"))
    }

    /// Combines `img3` and `black_pix` into a CMYK image. The formula depends
    /// on whether the Adobe APP14 metadata marks the data as CMYK or YCbCrK.
    fn apply_black(&mut self) -> Result<Decoded> {
        if !self.adobe_transform_valid {
            return Err(Error::Unsupported(
                "unknown color model: 4-component JPEG doesn't have Adobe APP14 metadata",
            ));
        }
        let (Some(img3), Some(black)) = (self.img3.as_ref(), self.black_pix.as_ref()) else {
            return Err(Error::Format("missing SOS marker"));
        };
        let bounds = img3.rect;
        let (w, h) = (bounds.dx() as usize, bounds.dy() as usize);
        let stride = w * 4;
        let mut pix = alloc_bytes(stride * h)?;
        let black = black.to_vec();

        // Anything but "Unknown (RGB or CMYK)" is assumed to be YCbCrK, as in
        // libjpeg's jdapimin.c.
        if self.adobe_transform != ADOBE_TRANSFORM_UNKNOWN {
            // Convert the YCbCr part to RGB; the RGB-to-CMY inversion cancels
            // Adobe's inversion, leaving only the black channel to invert.
            let (yp, cbp, crp) = (img3.y.to_vec(), img3.cb.to_vec(), img3.cr.to_vec());
            for y in 0..h {
                let yi = img3.y_offset(0, y as i32);
                for x in 0..w {
                    let c = img3.c_offset(x as i32, y as i32);
                    let (r, g, b) = color::ycbcr_to_rgb(yp[yi + x], cbp[c], crp[c]);
                    let o = y * stride + 4 * x;
                    pix[o] = r;
                    pix[o + 1] = g;
                    pix[o + 2] = b;
                    pix[o + 3] = 255 - black[y * self.black_stride + x];
                }
            }
            return Ok(Decoded::Cmyk(Cmyk {
                pix: pix.into(),
                stride,
                rect: bounds,
            }));
        }

        // The first three channels were decoded into img3's planes, some of
        // them subsampled; interleave them into one CMYK pixel array.
        let (yp, cbp, crp) = (img3.y.to_vec(), img3.cb.to_vec(), img3.cr.to_vec());
        let translations: [(&[u8], usize); 4] = [
            (&yp, img3.y_stride),
            (&cbp, img3.c_stride),
            (&crp, img3.c_stride),
            (&black, self.black_stride),
        ];
        for (t, (src, src_stride)) in translations.into_iter().enumerate() {
            let subsample = self.comp[t].h != self.comp[0].h || self.comp[t].v != self.comp[0].v;
            for y in 0..h {
                let sy = if subsample { y / 2 } else { y };
                for x in 0..w {
                    let sx = if subsample { x / 2 } else { x };
                    pix[y * stride + 4 * x + t] = 255 - src[sy * src_stride + sx];
                }
            }
        }
        Ok(Decoded::Cmyk(Cmyk {
            pix: pix.into(),
            stride,
            rect: bounds,
        }))
    }

    fn is_rgb(&self) -> bool {
        if self.jfif {
            return false;
        }
        if self.adobe_transform_valid && self.adobe_transform == ADOBE_TRANSFORM_UNKNOWN {
            // 0 means Unknown (in practice RGB) and 1 means YCbCr.
            return true;
        }
        self.comp[0].c == b'R' && self.comp[1].c == b'G' && self.comp[2].c == b'B'
    }

    fn convert_to_rgb(&mut self) -> Result<Decoded> {
        // Only the historical standard chroma ratios are supported here.
        let (h0, h1, h2) = (self.comp[0].h, self.comp[1].h, self.comp[2].h);
        let (v0, v1, v2) = (self.comp[0].v, self.comp[1].v, self.comp[2].v);
        if h1 != h2 || h0 % h1 != 0 || v1 != v2 || v0 % v1 != 0 {
            return Err(ERR_UNSUPPORTED_SUBSAMPLING);
        }
        let c_scale = (h0 / h1) as usize;
        let Some(img3) = self.img3.as_ref() else {
            return Err(Error::Format("missing SOS marker"));
        };
        let bounds = img3.rect;
        let (w, h) = (bounds.dx() as usize, bounds.dy() as usize);
        let stride = w * 4;
        let mut pix = alloc_bytes(stride * h)?;
        let (yp, cbp, crp) = (img3.y.to_vec(), img3.cb.to_vec(), img3.cr.to_vec());
        for y in 0..h {
            let yo = img3.y_offset(bounds.min.x, bounds.min.y + y as i32);
            let co = img3.c_offset(bounds.min.x, bounds.min.y + y as i32);
            for i in 0..w {
                let o = y * stride + 4 * i;
                pix[o] = yp[yo + i];
                pix[o + 1] = cbp[co + i / c_scale];
                pix[o + 2] = crp[co + i / c_scale];
                pix[o + 3] = 255;
            }
        }
        Ok(Decoded::Rgba(Rgba {
            pix: pix.into(),
            stride,
            rect: bounds,
        }))
    }

    /// The color model and size, valid after `decode(true)`.
    pub fn config(&self) -> std::result::Result<Config, Error> {
        let model = match self.n_comp {
            1 => color::Model::Gray,
            3 => {
                if self.is_rgb() {
                    color::Model::Rgba
                } else {
                    color::Model::Ycbcr
                }
            }
            4 => color::Model::Cmyk,
            _ => return Err(Error::Format("missing SOF marker")),
        };
        Ok(Config {
            color_model: model,
            width: self.width,
            height: self.height,
        })
    }

    /// Allocates the destination image for `mxx` by `myy` MCUs.
    pub fn make_img(&mut self, mxx: usize, myy: usize) -> Result<()> {
        let pixels = |w: usize, h: usize| -> Result<()> {
            let n = (w as u64) * (h as u64);
            if n > self.limits.max_pixels {
                return Err(Error::Limit(format!(
                    "jpeg: image has {n} pixels, over the limit of {}",
                    self.limits.max_pixels
                )));
            }
            Ok(())
        };
        let (width, height) = (self.width as usize, self.height as usize);
        if self.n_comp == 1 {
            let (w, h) = (8 * mxx, 8 * myy);
            pixels(w, h)?;
            // Go's SubImage of an empty rectangle is the zero image.
            self.img1 = Some(if width == 0 || height == 0 {
                Gray::default()
            } else {
                Gray {
                    pix: alloc_bytes(w * h)?.into(),
                    stride: w,
                    rect: rect(0, 0, width as i32, height as i32),
                }
            });
            return Ok(());
        }

        // Flex mode is needed when Cb and Cr differ in sampling, Y lacks the
        // maximum factors, or the ratio matches no standard ratio.
        let mut ratio = YcbcrSubsampleRatio::Ratio444;
        if self.comp[1].h != self.comp[2].h
            || self.comp[1].v != self.comp[2].v
            || self.max_h != self.comp[0].h
            || self.max_v != self.comp[0].v
        {
            self.flex = true;
        } else {
            let h_ratio = self.max_h / self.comp[1].h;
            let v_ratio = self.max_v / self.comp[1].v;
            match h_ratio << 4 | v_ratio {
                0x11 => ratio = YcbcrSubsampleRatio::Ratio444,
                0x12 => ratio = YcbcrSubsampleRatio::Ratio440,
                0x21 => ratio = YcbcrSubsampleRatio::Ratio422,
                0x22 => ratio = YcbcrSubsampleRatio::Ratio420,
                0x41 => ratio = YcbcrSubsampleRatio::Ratio411,
                0x42 => ratio = YcbcrSubsampleRatio::Ratio410,
                _ => self.flex = true,
            }
        }

        let (pw, ph) = (8 * self.max_h as usize * mxx, 8 * self.max_v as usize * myy);
        pixels(pw, ph)?;
        let full = rect(0, 0, pw as i32, ph as i32);
        let Some((_, _, cw, ch)) = ycbcr::plane_sizes(full, ratio) else {
            return Err(Error::Limit("jpeg: image too large to allocate".to_owned()));
        };
        self.img3 = Some(if width == 0 || height == 0 {
            Ycbcr {
                subsample_ratio: ratio,
                ..Ycbcr::default()
            }
        } else {
            Ycbcr {
                y: alloc_bytes(pw * ph)?.into(),
                cb: alloc_bytes(cw * ch)?.into(),
                cr: alloc_bytes(cw * ch)?.into(),
                y_stride: pw,
                c_stride: cw,
                subsample_ratio: ratio,
                rect: rect(0, 0, width as i32, height as i32),
            }
        });

        if self.n_comp == 4 {
            let (h3, v3) = (self.comp[3].h as usize, self.comp[3].v as usize);
            self.black_pix = Some(alloc_bytes(8 * h3 * mxx * 8 * v3 * myy)?.into());
            self.black_stride = 8 * h3 * mxx;
        }
        Ok(())
    }
}
