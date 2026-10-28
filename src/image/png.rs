//! PNG decoding and encoding compatible with Go's `image/png`.
//!
//! The decoder accepts every standard color type and bit depth, Adam7
//! interlacing, PLTE/tRNS and all five scanline filters, and verifies every
//! chunk CRC and the zlib checksum. It follows Go's chunk-ordering rules and
//! leniencies: unknown chunks (critical or not) are skipped after CRC
//! verification, bytes after IEND are ignored, palette indexes beyond the
//! palette decode as opaque black, and IDAT chunks after the one the zlib
//! stream ends in are skipped (read and CRC-checked, their contents ignored),
//! as are later IDAT runs. Decoded images have the same concrete type Go
//! returns. Every decode is bounded by [`Limits`], checked before pixel
//! buffers are allocated.
//!
//! Deliberate differences from Go: bytes after the end of the zlib stream
//! inside the IDAT chunk the stream ends in are always rejected, where Go
//! accepts them when the rest of that chunk fits in its 4 KiB read-ahead and
//! rejects them otherwise; and a zlib distance beyond the window advertised
//! in the zlib header is rejected. When the encoder fails on a palette it
//! has written the signature and IHDR first, as Go does.
//!
//! The encoder chooses the same PNG color type and bit depth as Go for each
//! image type and writes the same pixel values. It compresses with
//! [`crate::compress::zlib`] at the level Go maps [`CompressionLevel`] to, so
//! the IDAT payload is meant to match Go's byte for byte.
//!
//! ```
//! use rust_stdlib::image::{png, rect, Gray, Image};
//! let mut img = Gray::new(rect(0, 0, 3, 2));
//! img.pix.copy_from_slice(&[0, 64, 128, 192, 255, 7]);
//! let mut bytes = Vec::new();
//! png::encode(&mut bytes, &img)?;
//! let decoded = png::decode(&bytes[..])?;
//! assert_eq!(decoded.bounds(), rect(0, 0, 3, 2));
//! assert_eq!(decoded.at(1, 1), img.at(1, 1));
//! # Ok::<(), std::io::Error>(())
//! ```
use std::fmt;
use std::io::{self, Read, Write};
use std::sync::Arc;

use super::color::{self, Color, Model, Palette};
use super::{rect, AnyImage, Config, Gray, Gray16, Image, Nrgba, Nrgba64, Paletted, Rgba, Rgba64};
use crate::compress::zlib;
use crate::hash::crc32::Crc32;
use crate::io::is_unexpected_eof;

const SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";

/// Resource budgets for one decode. Dimension and pixel limits apply to
/// [`decode`]; [`decode_config`] reads only metadata and enforces the input
/// budget alone. The decoded image buffer is bounded by `max_pixels` times
/// its bytes per pixel (at most 8, for 16-bit RGBA), independently of
/// `max_decompressed_bytes`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Maximum image width in pixels.
    pub max_width: u32,
    /// Maximum image height in pixels.
    pub max_height: u32,
    /// Maximum `width * height`.
    pub max_pixels: u64,
    /// Maximum total IDAT payload bytes buffered for decompression. The
    /// payloads of IDAT chunks after the one the zlib stream ends in count
    /// too: the decoder reads and skips them as Go does, but buffers them
    /// first. Chunk boundaries add at most one bit per buffered byte, and
    /// both buffers carry the growth slack of a `Vec`.
    pub max_compressed_bytes: usize,
    /// Maximum decompressed scanline bytes (filter bytes included).
    pub max_decompressed_bytes: usize,
    /// Maximum bytes read from the source, including skipped chunks.
    pub max_input_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_width: 1 << 20,
            max_height: 1 << 20,
            max_pixels: 1 << 26,
            max_compressed_bytes: 1 << 28,
            max_decompressed_bytes: 1 << 28,
            max_input_bytes: 1 << 30,
        }
    }
}

/// Go's `png.FormatError`: the input is not a valid PNG. It is the payload of
/// the `io::Error` (kind `InvalidData`) that the decoder returns, so callers
/// can recover it with `get_ref().and_then(|e| e.downcast_ref())`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormatError(pub String);

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "png: invalid format: {}", self.0)
    }
}

impl std::error::Error for FormatError {}

/// Go's `png.UnsupportedError`: a valid PNG uses a feature this package does
/// not implement. Returned with kind `Unsupported`, like [`FormatError`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsupportedError(pub String);

impl fmt::Display for UnsupportedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "png: unsupported feature: {}", self.0)
    }
}

impl std::error::Error for UnsupportedError {}

fn format_error(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, FormatError(message.to_owned()))
}

fn unsupported(message: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        UnsupportedError(message.to_owned()),
    )
}

fn limit_error(message: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("png: {message} exceeds decode limit"),
    )
}

/// A combination of PNG color type and bit depth.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cb {
    G1,
    G2,
    G4,
    G8,
    Ga8,
    Tc8,
    P1,
    P2,
    P4,
    P8,
    Tca8,
    G16,
    Ga16,
    Tc16,
    Tca16,
}

impl Cb {
    fn new(depth: u8, color_type: u8) -> Option<Self> {
        Some(match (depth, color_type) {
            (1, 0) => Cb::G1,
            (2, 0) => Cb::G2,
            (4, 0) => Cb::G4,
            (8, 0) => Cb::G8,
            (16, 0) => Cb::G16,
            (8, 2) => Cb::Tc8,
            (16, 2) => Cb::Tc16,
            (1, 3) => Cb::P1,
            (2, 3) => Cb::P2,
            (4, 3) => Cb::P4,
            (8, 3) => Cb::P8,
            (8, 4) => Cb::Ga8,
            (16, 4) => Cb::Ga16,
            (8, 6) => Cb::Tca8,
            (16, 6) => Cb::Tca16,
            _ => return None,
        })
    }
    fn paletted(self) -> bool {
        matches!(self, Cb::P1 | Cb::P2 | Cb::P4 | Cb::P8)
    }
    fn true_color(self) -> bool {
        matches!(self, Cb::Tc8 | Cb::Tc16)
    }
    fn bits_per_pixel(self) -> usize {
        match self {
            Cb::G1 | Cb::P1 => 1,
            Cb::G2 | Cb::P2 => 2,
            Cb::G4 | Cb::P4 => 4,
            Cb::G8 | Cb::P8 => 8,
            Cb::Ga8 | Cb::G16 => 16,
            Cb::Tc8 => 24,
            Cb::Tca8 | Cb::Ga16 => 32,
            Cb::Tc16 => 48,
            Cb::Tca16 => 64,
        }
    }
}

/// Go's chunk-ordering stages; the integer order matters.
const STAGE_START: u8 = 0;
const STAGE_IHDR: u8 = 1;
const STAGE_PLTE: u8 = 2;
const STAGE_TRNS: u8 = 3;
const STAGE_IDAT: u8 = 4;
const STAGE_IEND: u8 = 5;

/// Adam7 passes as (x factor, y factor, x offset, y offset).
const ADAM7: [(usize, usize, usize, usize); 7] = [
    (8, 8, 0, 0),
    (8, 8, 4, 0),
    (4, 8, 0, 4),
    (4, 4, 2, 0),
    (2, 4, 0, 2),
    (2, 2, 1, 0),
    (1, 2, 0, 1),
];

/// Go's `io.ReadFull` on a short source: `io.EOF` or `io.ErrUnexpectedEOF`
/// both reach the caller of `Decode` as `io.ErrUnexpectedEOF`.
fn short_read(e: io::Error) -> io::Error {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        crate::io::Error::UnexpectedEof.into()
    } else {
        e
    }
}

/// Whether zlib reported a pixel stream that ends early (Go's
/// `io.ErrUnexpectedEOF` from `compress/zlib`).
fn zlib_truncated(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::UnexpectedEof
}

/// Where a run of IDAT chunks stopped short. Go streams the run into zlib,
/// so the cut only matters if the pixel stream needs bytes beyond it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Cut {
    /// The input ended inside a chunk's data, its checksum, or the next
    /// chunk header: Go's `io.ErrUnexpectedEOF`.
    Truncated,
    /// A chunk whose CRC did not match. Go reports it when the stream
    /// crosses the chunk's end, or after decoding when the chunk is skipped.
    Checksum,
}

/// Consecutive IDAT chunks, collected before decompression.
#[derive(Default)]
struct IdatRun {
    data: Vec<u8>,
    /// Bit `i` is set when a fully delivered chunk ends at offset `i` of
    /// `data`. Go's zlib reader never pulls from the chunk after the one the
    /// stream ends in, so a stream ending at a set bit leaves whole chunks Go
    /// skips. One bit per payload byte keeps the length within an eighth of
    /// `max_compressed_bytes` however many chunks the run holds; a
    /// zero-length chunk sets a bit that is already set.
    ends: Vec<u64>,
    cut: Option<Cut>,
}

impl IdatRun {
    /// Record that the chunk just delivered ends at the current end of `data`.
    fn end_chunk(&mut self) {
        let at = self.data.len();
        if self.ends.len() <= at / 64 {
            self.ends.resize(at / 64 + 1, 0);
        }
        self.ends[at / 64] |= 1 << (at % 64);
    }

    /// Whether a fully delivered chunk ends at `offset` in `data`.
    fn is_chunk_end(&self, offset: usize) -> bool {
        self.ends
            .get(offset / 64)
            .is_some_and(|word| (word >> (offset % 64)) & 1 == 1)
    }

    /// Go's error for what the run lacks, raised when the pixel stream needs
    /// bytes beyond it or when Go reads the chunks it skips after decoding.
    fn missing(&self) -> io::Error {
        match self.cut {
            Some(Cut::Checksum) => format_error("invalid checksum"),
            Some(Cut::Truncated) => crate::io::Error::UnexpectedEof.into(),
            None => format_error("not enough pixel data"),
        }
    }

    /// What a row read reports when the stream ends early. Go's row reader
    /// turns an early end into "not enough pixel data" and passes the chunk
    /// reader's own errors through.
    fn short_row(&self) -> io::Error {
        let e = self.missing();
        if is_unexpected_eof(&e) {
            format_error("not enough pixel data")
        } else {
            e
        }
    }
}

struct Source<R> {
    inner: R,
    read: u64,
    limit: u64,
}

impl<R: Read> Source<R> {
    fn charge(&mut self, n: u64) -> io::Result<()> {
        if n > self.limit - self.read {
            return Err(limit_error("input size"));
        }
        self.read += n;
        Ok(())
    }
    fn fill(&mut self, buf: &mut [u8]) -> io::Result<()> {
        self.charge(buf.len() as u64)?;
        self.inner.read_exact(buf).map_err(short_read)
    }
}

struct Decoder<R> {
    src: Source<R>,
    limits: Limits,
    crc: Crc32,
    stage: u8,
    width: usize,
    height: usize,
    depth: u8,
    cb: Option<Cb>,
    interlaced: bool,
    palette: Vec<Color>,
    transparent: Option<[u8; 6]>,
    pending: Option<[u8; 8]>,
    image: Option<AnyImage>,
}

impl<R: Read> Decoder<R> {
    fn new(reader: R, limits: Limits) -> Self {
        Self {
            src: Source {
                inner: reader,
                read: 0,
                limit: limits.max_input_bytes,
            },
            limits,
            crc: Crc32::ieee(),
            stage: STAGE_START,
            width: 0,
            height: 0,
            depth: 0,
            cb: None,
            interlaced: false,
            palette: Vec::new(),
            transparent: None,
            pending: None,
            image: None,
        }
    }

    fn check_signature(&mut self) -> io::Result<()> {
        let mut sig = [0; 8];
        self.src.fill(&mut sig)?;
        if &sig != SIGNATURE {
            return Err(format_error("not a PNG file"));
        }
        Ok(())
    }

    fn read_data(&mut self, buf: &mut [u8]) -> io::Result<()> {
        self.src.fill(buf)?;
        self.crc.update(buf);
        Ok(())
    }

    fn read_checksum(&mut self) -> io::Result<bool> {
        let mut sum = [0; 4];
        self.src.fill(&mut sum)?;
        Ok(u32::from_be_bytes(sum) == self.crc.sum32())
    }

    fn verify_checksum(&mut self) -> io::Result<()> {
        if self.read_checksum()? {
            Ok(())
        } else {
            Err(format_error("invalid checksum"))
        }
    }

    fn chunk_header(&mut self) -> io::Result<(u32, [u8; 4])> {
        let header = match self.pending.take() {
            Some(header) => header,
            None => {
                let mut header = [0; 8];
                self.src.fill(&mut header)?;
                header
            }
        };
        self.crc.reset();
        self.crc.update(&header[4..8]);
        let length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
        Ok((length, [header[4], header[5], header[6], header[7]]))
    }

    fn parse_chunk(&mut self, config_only: bool) -> io::Result<()> {
        let (length, kind) = self.chunk_header()?;
        let paletted = self.cb.is_some_and(Cb::paletted);
        match &kind {
            b"IHDR" => {
                if self.stage != STAGE_START {
                    return Err(format_error("chunk out of order"));
                }
                self.stage = STAGE_IHDR;
                return self.parse_ihdr(length, config_only);
            }
            b"PLTE" => {
                if self.stage != STAGE_IHDR {
                    return Err(format_error("chunk out of order"));
                }
                self.stage = STAGE_PLTE;
                return self.parse_plte(length);
            }
            b"tRNS" => {
                let allowed = if paletted {
                    self.stage == STAGE_PLTE
                } else if self.cb.is_some_and(Cb::true_color) {
                    self.stage == STAGE_IHDR || self.stage == STAGE_PLTE
                } else {
                    self.stage == STAGE_IHDR
                };
                if !allowed {
                    return Err(format_error("chunk out of order"));
                }
                self.stage = STAGE_TRNS;
                return self.parse_trns(length);
            }
            b"IDAT" => {
                if self.stage < STAGE_IHDR
                    || self.stage > STAGE_IDAT
                    || (self.stage == STAGE_IHDR && paletted)
                {
                    return Err(format_error("chunk out of order"));
                }
                // A second IDAT run after the image data is ignored, as in Go.
                if self.stage != STAGE_IDAT {
                    self.stage = STAGE_IDAT;
                    if config_only {
                        return Ok(());
                    }
                    return self.parse_idat(length);
                }
            }
            b"IEND" => {
                if self.stage != STAGE_IDAT {
                    return Err(format_error("chunk out of order"));
                }
                self.stage = STAGE_IEND;
                if length != 0 {
                    return Err(format_error("bad IEND length"));
                }
                return self.verify_checksum();
            }
            _ => {}
        }
        if length > 0x7fff_ffff {
            return Err(format_error(&format!("Bad chunk length: {length}")));
        }
        let mut remaining = length as usize;
        let mut ignored = [0; 4096];
        while remaining > 0 {
            let n = remaining.min(ignored.len());
            self.read_data(&mut ignored[..n])?;
            remaining -= n;
        }
        self.verify_checksum()
    }

    fn parse_ihdr(&mut self, length: u32, config_only: bool) -> io::Result<()> {
        if length != 13 {
            return Err(format_error("bad IHDR length"));
        }
        let mut h = [0; 13];
        self.read_data(&mut h)?;
        if h[10] != 0 {
            return Err(unsupported("compression method"));
        }
        if h[11] != 0 {
            return Err(unsupported("filter method"));
        }
        if h[12] > 1 {
            return Err(format_error("invalid interlace method"));
        }
        self.interlaced = h[12] == 1;
        let w = i32::from_be_bytes([h[0], h[1], h[2], h[3]]);
        let ht = i32::from_be_bytes([h[4], h[5], h[6], h[7]]);
        if w <= 0 || ht <= 0 {
            return Err(format_error("non-positive dimension"));
        }
        // Go rejects dimensions whose 8-byte-per-pixel size overflows i64.
        if (i64::from(w) * i64::from(ht)).checked_mul(8).is_none() {
            return Err(unsupported("dimension overflow"));
        }
        self.depth = h[8];
        self.cb = Some(
            Cb::new(h[8], h[9])
                .ok_or_else(|| unsupported(&format!("bit depth {}, color type {}", h[8], h[9])))?,
        );
        self.width = w as usize;
        self.height = ht as usize;
        if !config_only {
            self.check_limits()?;
        }
        self.verify_checksum()
    }

    fn check_limits(&self) -> io::Result<()> {
        let (w, h) = (self.width as u64, self.height as u64);
        if w > u64::from(self.limits.max_width) {
            return Err(limit_error("width"));
        }
        if h > u64::from(self.limits.max_height) {
            return Err(limit_error("height"));
        }
        if w * h > self.limits.max_pixels {
            return Err(limit_error("pixel count"));
        }
        match self.raw_size() {
            Some(n) if n <= self.limits.max_decompressed_bytes as u64 => Ok(()),
            _ => Err(limit_error("decompressed size")),
        }
    }

    /// Pass dimensions: one full pass, or the seven Adam7 reductions.
    fn passes(&self) -> Vec<(usize, usize, usize, usize, usize, usize)> {
        if !self.interlaced {
            return vec![(self.width, self.height, 1, 1, 0, 0)];
        }
        ADAM7
            .iter()
            .map(|&(xf, yf, xo, yo)| {
                let w = (self.width + xf - 1 - xo) / xf;
                let h = (self.height + yf - 1 - yo) / yf;
                (w, h, xf, yf, xo, yo)
            })
            .collect()
    }

    /// Total scanline bytes, including one filter byte per non-empty row.
    fn raw_size(&self) -> Option<u64> {
        let bits = self.cb?.bits_per_pixel() as u64;
        let mut total = 0u64;
        for (w, h, ..) in self.passes() {
            if w == 0 || h == 0 {
                continue;
            }
            let row = 1 + bits.checked_mul(w as u64)?.div_ceil(8);
            total = total.checked_add(row.checked_mul(h as u64)?)?;
        }
        Some(total)
    }

    fn parse_plte(&mut self, length: u32) -> io::Result<()> {
        let np = (length / 3) as usize;
        if !length.is_multiple_of(3) || np == 0 || np > 256 || np > 1usize << self.depth.min(16) {
            return Err(format_error("bad PLTE length"));
        }
        let mut entries = vec![0; 3 * np];
        self.read_data(&mut entries)?;
        match self.cb {
            Some(cb) if cb.paletted() => {
                self.palette = entries
                    .chunks(3)
                    .map(|c| {
                        color::Rgba {
                            r: c[0],
                            g: c[1],
                            b: c[2],
                            a: 0xff,
                        }
                        .into()
                    })
                    .collect();
            }
            Some(Cb::Tc8 | Cb::Tca8 | Cb::Tc16 | Cb::Tca16) => {}
            _ => return Err(format_error("PLTE, color type mismatch")),
        }
        self.verify_checksum()
    }

    fn parse_trns(&mut self, length: u32) -> io::Result<()> {
        let cb = self.cb;
        match cb {
            Some(Cb::G1 | Cb::G2 | Cb::G4 | Cb::G8 | Cb::G16) => {
                if length != 2 {
                    return Err(format_error("bad tRNS length"));
                }
                let mut t = [0; 6];
                self.read_data(&mut t[..2])?;
                // Go scales only the low byte, with wrapping 8-bit arithmetic.
                t[1] = t[1].wrapping_mul(match cb {
                    Some(Cb::G1) => 0xff,
                    Some(Cb::G2) => 0x55,
                    Some(Cb::G4) => 0x11,
                    _ => 1,
                });
                self.transparent = Some(t);
            }
            Some(Cb::Tc8 | Cb::Tc16) => {
                if length != 6 {
                    return Err(format_error("bad tRNS length"));
                }
                let mut t = [0; 6];
                self.read_data(&mut t)?;
                self.transparent = Some(t);
            }
            Some(Cb::P1 | Cb::P2 | Cb::P4 | Cb::P8) => {
                if length > 256 {
                    return Err(format_error("bad tRNS length"));
                }
                let mut alphas = vec![0; length as usize];
                self.read_data(&mut alphas)?;
                if self.palette.len() < alphas.len() {
                    self.palette.resize(alphas.len(), opaque_black());
                }
                for (entry, &a) in self.palette.iter_mut().zip(&alphas) {
                    let c = color::Rgba::from_color(*entry);
                    *entry = color::Nrgba {
                        r: c.r,
                        g: c.g,
                        b: c.b,
                        a,
                    }
                    .into();
                }
            }
            _ => return Err(format_error("tRNS, color type mismatch")),
        }
        self.verify_checksum()
    }

    /// Read one chunk payload into the run, enforcing the compressed budget.
    fn append_idat(&mut self, length: u32, run: &mut IdatRun) -> io::Result<()> {
        if length as usize > self.limits.max_compressed_bytes - run.data.len() {
            return Err(limit_error("compressed size"));
        }
        self.src.charge(u64::from(length))?;
        let start = run.data.len();
        let n = (&mut self.src.inner)
            .take(u64::from(length))
            .read_to_end(&mut run.data)?;
        if n != length as usize {
            run.cut = Some(Cut::Truncated);
            return Ok(());
        }
        run.end_chunk();
        self.crc.update(&run.data[start..]);
        run.cut = match self.read_checksum() {
            Err(e) if is_unexpected_eof(&e) => Some(Cut::Truncated),
            Err(e) => return Err(e),
            Ok(true) => None,
            Ok(false) => Some(Cut::Checksum),
        };
        Ok(())
    }

    /// Collect the consecutive IDAT run that starts with a chunk of `length`
    /// whose header is already read. The next non-IDAT chunk header is kept
    /// for the main loop.
    fn collect_idat(&mut self, length: u32) -> io::Result<IdatRun> {
        let mut run = IdatRun::default();
        self.append_idat(length, &mut run)?;
        while run.cut.is_none() {
            let mut header = [0; 8];
            match self.src.fill(&mut header) {
                Err(e) if is_unexpected_eof(&e) => {
                    run.cut = Some(Cut::Truncated);
                    break;
                }
                other => other?,
            }
            if &header[4..8] != b"IDAT" {
                self.pending = Some(header);
                break;
            }
            self.crc.reset();
            self.crc.update(b"IDAT");
            let length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
            self.append_idat(length, &mut run)?;
        }
        Ok(run)
    }

    fn parse_idat(&mut self, length: u32) -> io::Result<()> {
        let run = self.collect_idat(length)?;
        self.raw_size()
            .ok_or_else(|| limit_error("decompressed size"))?;
        // Go's zlib reader over the IDAT stream: its errors pass through
        // unchanged, except that a stream that ends early reports the cut.
        let mut z = zlib::Reader::from_buf_read(&run.data[..]).map_err(|e| {
            if zlib_truncated(&e) {
                run.missing()
            } else {
                e
            }
        })?;
        let mut image = self.allocate()?;
        let mut max_index = 0u8;
        for (w, h, xf, yf, xo, yo) in self.passes() {
            if w == 0 || h == 0 {
                continue;
            }
            let cb = self.cb.ok_or_else(|| format_error("missing IHDR"))?;
            let bits = cb.bits_per_pixel();
            let bpp = bits.div_ceil(8);
            let row = 1 + (bits * w).div_ceil(8);
            let mut cr = vec![0u8; row];
            let mut pr = vec![0u8; row];
            for y in 0..h {
                z.read_exact(&mut cr).map_err(|e| {
                    if zlib_truncated(&e) {
                        run.short_row()
                    } else {
                        e
                    }
                })?;
                unfilter(&mut cr, &pr, bpp)?;
                let dy = (y * yf + yo) as i32;
                let place = |x: usize| ((x * xf + xo) as i32, dy);
                self.store_row(&mut image, &cr[1..], w, place, &mut max_index);
                std::mem::swap(&mut cr, &mut pr);
            }
        }
        let mut probe = [0u8; 1];
        // Go's `Read` reports an error that arrives with the last byte, and
        // the error wins over "too much pixel data".
        let tail = match z.read(&mut probe) {
            Ok(n) if n > 0 => z.pending_error().map_or(Ok(n), Err),
            other => other,
        };
        match tail {
            Ok(0) => {
                // Bytes left in the chunk the stream ended in are rejected
                // (Go's read-ahead decides whether it sees them). Whole chunks
                // after it are ones Go skips after decoding, reporting only
                // what reading them turned up.
                let consumed = run.data.len() - z.get_ref().len();
                if !run.is_chunk_end(consumed) {
                    return Err(format_error("too much pixel data"));
                }
                if run.cut.is_some() {
                    return Err(run.missing());
                }
            }
            Ok(_) => return Err(format_error("too much pixel data")),
            // Go wraps whatever zlib reports once the rows are complete.
            Err(e) if zlib_truncated(&e) => return Err(format_error(&run.missing().to_string())),
            Err(e) => return Err(format_error(&e.to_string())),
        }
        if let AnyImage::Paletted(p) = &mut image {
            let used = usize::from(max_index) + 1;
            if p.palette.0.len() < used {
                p.palette.0.resize(used, opaque_black());
            }
        }
        self.image = Some(image);
        Ok(())
    }

    fn allocate(&self) -> io::Result<AnyImage> {
        let r = rect(0, 0, self.width as i32, self.height as i32);
        let oversize = || limit_error("image size");
        let transparent = self.transparent.is_some();
        Ok(match self.cb.ok_or_else(|| format_error("missing IHDR"))? {
            Cb::G1 | Cb::G2 | Cb::G4 | Cb::G8 if !transparent => {
                Gray::try_new(r).ok_or_else(oversize)?.into()
            }
            Cb::Tc8 if !transparent => Rgba::try_new(r).ok_or_else(oversize)?.into(),
            Cb::G1 | Cb::G2 | Cb::G4 | Cb::G8 | Cb::Ga8 | Cb::Tc8 | Cb::Tca8 => {
                Nrgba::try_new(r).ok_or_else(oversize)?.into()
            }
            Cb::P1 | Cb::P2 | Cb::P4 | Cb::P8 => {
                Paletted::try_new(r, Palette(self.palette.clone()))
                    .ok_or_else(oversize)?
                    .into()
            }
            Cb::G16 if !transparent => Gray16::try_new(r).ok_or_else(oversize)?.into(),
            Cb::Tc16 if !transparent => Rgba64::try_new(r).ok_or_else(oversize)?.into(),
            Cb::G16 | Cb::Ga16 | Cb::Tc16 | Cb::Tca16 => {
                Nrgba64::try_new(r).ok_or_else(oversize)?.into()
            }
        })
    }

    fn store_row(
        &self,
        image: &mut AnyImage,
        cdat: &[u8],
        width: usize,
        place: impl Fn(usize) -> (i32, i32),
        max_index: &mut u8,
    ) {
        let t = self.transparent.unwrap_or_default();
        let cb = self.cb.unwrap_or(Cb::G8);
        let be = |i: usize| u16::from_be_bytes([cdat[i], cdat[i + 1]]);
        match image {
            AnyImage::Gray(img) => {
                for x in 0..width {
                    let (px, py) = place(x);
                    img.set_pixel(
                        px,
                        py,
                        color::Gray {
                            y: gray_sample(cdat, cb, x),
                        },
                    );
                }
            }
            AnyImage::Gray16(img) => {
                for x in 0..width {
                    let (px, py) = place(x);
                    img.set_pixel(px, py, color::Gray16 { y: be(2 * x) });
                }
            }
            AnyImage::Rgba(img) => {
                for x in 0..width {
                    let (px, py) = place(x);
                    let s = &cdat[3 * x..3 * x + 3];
                    let c = color::Rgba {
                        r: s[0],
                        g: s[1],
                        b: s[2],
                        a: 0xff,
                    };
                    img.set_pixel(px, py, c);
                }
            }
            AnyImage::Rgba64(img) => {
                for x in 0..width {
                    let (px, py) = place(x);
                    let c = color::Rgba64 {
                        r: be(6 * x),
                        g: be(6 * x + 2),
                        b: be(6 * x + 4),
                        a: 0xffff,
                    };
                    img.set_pixel(px, py, c);
                }
            }
            AnyImage::Nrgba(img) => {
                for x in 0..width {
                    let (px, py) = place(x);
                    let c = match cb {
                        Cb::Ga8 => {
                            let y = cdat[2 * x];
                            color::Nrgba {
                                r: y,
                                g: y,
                                b: y,
                                a: cdat[2 * x + 1],
                            }
                        }
                        Cb::Tc8 => {
                            let s = &cdat[3 * x..3 * x + 3];
                            let clear = s[0] == t[1] && s[1] == t[3] && s[2] == t[5];
                            color::Nrgba {
                                r: s[0],
                                g: s[1],
                                b: s[2],
                                a: if clear { 0 } else { 0xff },
                            }
                        }
                        Cb::Tca8 => {
                            let s = &cdat[4 * x..4 * x + 4];
                            color::Nrgba {
                                r: s[0],
                                g: s[1],
                                b: s[2],
                                a: s[3],
                            }
                        }
                        _ => {
                            let y = gray_sample(cdat, cb, x);
                            color::Nrgba {
                                r: y,
                                g: y,
                                b: y,
                                a: if y == t[1] { 0 } else { 0xff },
                            }
                        }
                    };
                    img.set_pixel(px, py, c);
                }
            }
            AnyImage::Nrgba64(img) => {
                let ty = |i: usize| u16::from_be_bytes([t[i], t[i + 1]]);
                for x in 0..width {
                    let (px, py) = place(x);
                    let c = match cb {
                        Cb::G16 => {
                            let y = be(2 * x);
                            color::Nrgba64 {
                                r: y,
                                g: y,
                                b: y,
                                a: if y == ty(0) { 0 } else { 0xffff },
                            }
                        }
                        Cb::Ga16 => {
                            let y = be(4 * x);
                            color::Nrgba64 {
                                r: y,
                                g: y,
                                b: y,
                                a: be(4 * x + 2),
                            }
                        }
                        Cb::Tc16 => {
                            let (r, g, b) = (be(6 * x), be(6 * x + 2), be(6 * x + 4));
                            let clear = r == ty(0) && g == ty(2) && b == ty(4);
                            color::Nrgba64 {
                                r,
                                g,
                                b,
                                a: if clear { 0 } else { 0xffff },
                            }
                        }
                        _ => color::Nrgba64 {
                            r: be(8 * x),
                            g: be(8 * x + 2),
                            b: be(8 * x + 4),
                            a: be(8 * x + 6),
                        },
                    };
                    img.set_pixel(px, py, c);
                }
            }
            AnyImage::Paletted(img) => {
                let bits = cb.bits_per_pixel();
                for x in 0..width {
                    let (px, py) = place(x);
                    let index = packed_sample(cdat, bits, x);
                    *max_index = (*max_index).max(index);
                    img.set_color_index(px, py, index);
                }
            }
            AnyImage::Alpha(_) | AnyImage::Alpha16(_) => {}
        }
    }
}

fn opaque_black() -> Color {
    color::Rgba {
        r: 0,
        g: 0,
        b: 0,
        a: 0xff,
    }
    .into()
}

/// The `x`th `bits`-wide sample of a row, most significant bits first.
fn packed_sample(cdat: &[u8], bits: usize, x: usize) -> u8 {
    if bits == 8 {
        return cdat[x];
    }
    let bit = x * bits;
    let shift = 8 - bits - bit % 8;
    (cdat[bit / 8] >> shift) & ((1u8 << bits) - 1)
}

/// A grayscale sample of depth 1..8 scaled to 8 bits as Go does.
fn gray_sample(cdat: &[u8], cb: Cb, x: usize) -> u8 {
    let bits = cb.bits_per_pixel();
    let v = packed_sample(cdat, bits, x);
    match bits {
        1 => v * 0xff,
        2 => v * 0x55,
        4 => v * 0x11,
        _ => v,
    }
}

fn paeth(a: u8, b: u8, c: u8) -> u8 {
    let pc = i32::from(c);
    let pa = i32::from(b) - pc;
    let pb = i32::from(a) - pc;
    let pc = (pa + pb).abs();
    let (pa, pb) = (pa.abs(), pb.abs());
    if pa <= pb && pa <= pc {
        a
    } else if pb <= pc {
        b
    } else {
        c
    }
}

/// Reverse the scanline filter in `cr` (filter type at index 0) in place.
fn unfilter(cr: &mut [u8], pr: &[u8], bpp: usize) -> io::Result<()> {
    let (kind, cdat) = cr.split_at_mut(1);
    let pdat = &pr[1..];
    match kind[0] {
        0 => {}
        1 => {
            for i in bpp..cdat.len() {
                cdat[i] = cdat[i].wrapping_add(cdat[i - bpp]);
            }
        }
        2 => {
            for (c, &p) in cdat.iter_mut().zip(pdat) {
                *c = c.wrapping_add(p);
            }
        }
        3 => {
            for i in 0..cdat.len() {
                let left = if i >= bpp {
                    u16::from(cdat[i - bpp])
                } else {
                    0
                };
                cdat[i] = cdat[i].wrapping_add(((left + u16::from(pdat[i])) / 2) as u8);
            }
        }
        4 => {
            for i in 0..cdat.len() {
                let (a, c) = if i >= bpp {
                    (cdat[i - bpp], pdat[i - bpp])
                } else {
                    (0, 0)
                };
                cdat[i] = cdat[i].wrapping_add(paeth(a, pdat[i], c));
            }
        }
        _ => return Err(format_error("bad filter type")),
    }
    Ok(())
}

/// Decode a PNG image with default [`Limits`].
pub fn decode(reader: impl Read) -> io::Result<AnyImage> {
    decode_with_limits(reader, Limits::default())
}

/// Decode a PNG image, rejecting input that exceeds `limits` before
/// allocating pixel storage. Reading stops after the IEND chunk.
pub fn decode_with_limits(reader: impl Read, limits: Limits) -> io::Result<AnyImage> {
    let mut d = Decoder::new(reader, limits);
    d.check_signature()?;
    while d.stage != STAGE_IEND {
        d.parse_chunk(false)?;
    }
    d.image.ok_or_else(|| format_error("missing image data"))
}

/// Read the color model and dimensions without decoding pixel data, with
/// default [`Limits`].
pub fn decode_config(reader: impl Read) -> io::Result<Config> {
    decode_config_with_limits(reader, Limits::default())
}

/// Like [`decode_config`], bounded by `limits.max_input_bytes`. For paletted
/// images the returned palette includes tRNS alpha, as in Go.
pub fn decode_config_with_limits(reader: impl Read, limits: Limits) -> io::Result<Config> {
    let mut d = Decoder::new(reader, limits);
    d.check_signature()?;
    loop {
        d.parse_chunk(true)?;
        let paletted = d.cb.is_some_and(Cb::paletted);
        if (paletted && d.stage >= STAGE_TRNS) || (!paletted && d.stage >= STAGE_IHDR) {
            break;
        }
    }
    let color_model = match d.cb.ok_or_else(|| format_error("missing IHDR"))? {
        Cb::G1 | Cb::G2 | Cb::G4 | Cb::G8 => Model::Gray,
        Cb::Ga8 | Cb::Tca8 => Model::Nrgba,
        Cb::Tc8 => Model::Rgba,
        Cb::P1 | Cb::P2 | Cb::P4 | Cb::P8 => Model::Palette(Palette(d.palette.clone())),
        Cb::G16 => Model::Gray16,
        Cb::Ga16 | Cb::Tca16 => Model::Nrgba64,
        Cb::Tc16 => Model::Rgba64,
    };
    Ok(Config {
        color_model,
        width: d.width as i32,
        height: d.height as i32,
    })
}

/// Go's `png.CompressionLevel`; discriminants equal Go's constants.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum CompressionLevel {
    #[default]
    Default = 0,
    /// Stored DEFLATE blocks and unfiltered scanlines.
    NoCompression = -1,
    BestSpeed = -2,
    /// zlib level 9.
    BestCompression = -3,
}

/// Go's `png.EncoderBuffer`: scratch memory that an [`EncoderBufferPool`]
/// lends to encoders. Its contents are opaque, as in Go; an encoder keeps the
/// allocation of the output file in it, so pooled buffers are reused.
#[derive(Debug, Default)]
pub struct EncoderBuffer {
    out: Vec<u8>,
}

/// Go's `png.EncoderBufferPool`: source and sink of [`EncoderBuffer`]s. An
/// encoder calls `get` before encoding and `put` afterwards, even on failure.
pub trait EncoderBufferPool {
    /// A buffer to reuse, or `None` to let the encoder allocate one.
    fn get(&self) -> Option<EncoderBuffer>;
    /// Returns a buffer to the pool.
    fn put(&self, buffer: EncoderBuffer);
}

/// PNG encoder settings (Go's `png.Encoder`).
#[derive(Clone, Default)]
pub struct Encoder {
    pub compression_level: CompressionLevel,
    /// Optional pool of temporary [`EncoderBuffer`]s (Go's `BufferPool`).
    pub buffer_pool: Option<Arc<dyn EncoderBufferPool>>,
}

/// Encode `m` as PNG with default settings.
pub fn encode(writer: impl Write, m: &dyn Image) -> io::Result<()> {
    Encoder::default().encode(writer, m)
}

fn invalid_input(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn invalid_format_input(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, FormatError(message))
}

impl Encoder {
    /// Encode `m`. The file is built in memory and written at the end. Fails
    /// for empty bounds (nothing written) or palettes outside 1..=256 entries
    /// (signature and IHDR written, as Go does).
    pub fn encode(&self, mut writer: impl Write, m: &dyn Image) -> io::Result<()> {
        let mut buffer = self
            .buffer_pool
            .as_ref()
            .and_then(|pool| pool.get())
            .unwrap_or_default();
        let built = self.build(&mut buffer.out, m);
        // On failure the chunks built so far are still written (Go has
        // already written the signature and IHDR when it fails on a palette),
        // then the failure is returned.
        let written = match built {
            Ok(()) => writer.write_all(&buffer.out),
            Err(e) => writer.write_all(&buffer.out).and(Err(e)),
        };
        if let Some(pool) = &self.buffer_pool {
            pool.put(buffer);
        }
        written
    }

    /// Writes the complete PNG file for `m` into `out`, replacing its contents.
    fn build(&self, out: &mut Vec<u8>, m: &dyn Image) -> io::Result<()> {
        out.clear();
        let b = m.bounds();
        let (w, h) = (i64::from(b.dx()), i64::from(b.dy()));
        if w <= 0 || h <= 0 {
            return Err(invalid_format_input(format!("invalid image size: {w}x{h}")));
        }
        let palette = match (m.as_paletted(), m.color_model()) {
            (Some(_), Model::Palette(p)) => Some(p),
            _ => None,
        };
        let cb = match &palette {
            Some(p) if p.len() <= 2 => Cb::P1,
            Some(p) if p.len() <= 4 => Cb::P2,
            Some(p) if p.len() <= 16 => Cb::P4,
            Some(_) => Cb::P8,
            None => match m.color_model() {
                Model::Gray => Cb::G8,
                Model::Gray16 => Cb::G16,
                Model::Rgba | Model::Nrgba | Model::Alpha if m.opaque() => Cb::Tc8,
                Model::Rgba | Model::Nrgba | Model::Alpha => Cb::Tca8,
                _ if m.opaque() => Cb::Tc16,
                _ => Cb::Tca16,
            },
        };
        out.extend_from_slice(SIGNATURE);
        let (depth, color_type) = match cb {
            Cb::G8 => (8, 0),
            Cb::Tc8 => (8, 2),
            Cb::P8 => (8, 3),
            Cb::P4 => (4, 3),
            Cb::P2 => (2, 3),
            Cb::P1 => (1, 3),
            Cb::Tca8 => (8, 6),
            Cb::G16 => (16, 0),
            Cb::Tc16 => (16, 2),
            _ => (16, 6),
        };
        let mut ihdr = Vec::with_capacity(13);
        ihdr.extend_from_slice(&(w as u32).to_be_bytes());
        ihdr.extend_from_slice(&(h as u32).to_be_bytes());
        ihdr.extend_from_slice(&[depth, color_type, 0, 0, 0]);
        write_chunk(out, b"IHDR", &ihdr);
        if let Some(p) = &palette {
            // Like Go, the signature and IHDR are already written when this
            // fails; `encode` still writes them.
            if p.is_empty() || p.len() > 256 {
                return Err(invalid_format_input(format!(
                    "bad palette length: {}",
                    p.len()
                )));
            }
            let mut plte = Vec::with_capacity(3 * p.len());
            let mut alphas = Vec::with_capacity(p.len());
            for &c in &p.0 {
                let c = color::Nrgba::from_color(c);
                plte.extend_from_slice(&[c.r, c.g, c.b]);
                alphas.push(c.a);
            }
            write_chunk(out, b"PLTE", &plte);
            if let Some(last) = alphas.iter().rposition(|&a| a != 0xff) {
                write_chunk(out, b"tRNS", &alphas[..=last]);
            }
        }
        let raw = self.scanlines(m, cb)?;
        let level = match self.compression_level {
            CompressionLevel::Default => zlib::DEFAULT_COMPRESSION,
            CompressionLevel::NoCompression => zlib::NO_COMPRESSION,
            CompressionLevel::BestSpeed => zlib::BEST_SPEED,
            CompressionLevel::BestCompression => zlib::BEST_COMPRESSION,
        };
        let mut zw = zlib::Writer::with_level(IdatWriter::new(out), level)?;
        zw.write_all(&raw)?;
        zw.close()?;
        zw.into_inner().finish();
        write_chunk(out, b"IEND", &[]);
        Ok(())
    }

    /// Filtered scanlines for `m` in color type `cb`, using Go's per-row
    /// filter heuristic unless compression is disabled or the image is paletted.
    fn scanlines(&self, m: &dyn Image, cb: Cb) -> io::Result<Vec<u8>> {
        let b = m.bounds();
        let bits = cb.bits_per_pixel();
        let width = b.dx() as usize;
        let size = bits
            .checked_mul(width)
            .and_then(|n| n.checked_add(7))
            .map(|n| 1 + n / 8)
            .ok_or_else(|| invalid_input("png: image too large".into()))?;
        let total = size
            .checked_mul(b.dy() as usize)
            .ok_or_else(|| invalid_input("png: image too large".into()))?;
        let mut raw = Vec::with_capacity(total);
        let mut cr: [Vec<u8>; 5] = std::array::from_fn(|i| {
            let mut v = vec![0u8; size];
            v[0] = i as u8;
            v
        });
        let mut pr = vec![0u8; size];
        let paletted = m.as_paletted();
        let filtered = self.compression_level != CompressionLevel::NoCompression
            && !matches!(cb, Cb::P1 | Cb::P2 | Cb::P4 | Cb::P8);
        for y in b.min.y..b.max.y {
            let row = &mut cr[0][1..];
            let mut i = 0;
            match cb {
                Cb::G8 => {
                    for x in b.min.x..b.max.x {
                        row[i] = color::Gray::from_color(m.at(x, y)).y;
                        i += 1;
                    }
                }
                Cb::Tc8 => {
                    for x in b.min.x..b.max.x {
                        let (r, g, bl, _) = m.at(x, y).rgba();
                        row[i..i + 3].copy_from_slice(&[
                            (r >> 8) as u8,
                            (g >> 8) as u8,
                            (bl >> 8) as u8,
                        ]);
                        i += 3;
                    }
                }
                Cb::P1 | Cb::P2 | Cb::P4 | Cb::P8 => {
                    let p = paletted.ok_or_else(|| invalid_input("png: not paletted".into()))?;
                    let per_byte = 8 / bits;
                    let (mut a, mut c) = (0u8, 0);
                    for x in b.min.x..b.max.x {
                        a = if bits == 8 { 0 } else { a << bits } | p.color_index_at(x, y);
                        c += 1;
                        if c == per_byte {
                            row[i] = a;
                            i += 1;
                            a = 0;
                            c = 0;
                        }
                    }
                    if c != 0 {
                        while c != per_byte {
                            a <<= bits;
                            c += 1;
                        }
                        row[i] = a;
                    }
                }
                Cb::Tca8 => {
                    for x in b.min.x..b.max.x {
                        let c = color::Nrgba::from_color(m.at(x, y));
                        row[i..i + 4].copy_from_slice(&[c.r, c.g, c.b, c.a]);
                        i += 4;
                    }
                }
                Cb::G16 => {
                    for x in b.min.x..b.max.x {
                        let c = color::Gray16::from_color(m.at(x, y));
                        row[i..i + 2].copy_from_slice(&c.y.to_be_bytes());
                        i += 2;
                    }
                }
                Cb::Tc16 => {
                    for x in b.min.x..b.max.x {
                        let (r, g, bl, _) = m.at(x, y).rgba();
                        for v in [r, g, bl] {
                            row[i..i + 2].copy_from_slice(&(v as u16).to_be_bytes());
                            i += 2;
                        }
                    }
                }
                _ => {
                    for x in b.min.x..b.max.x {
                        let c = color::Nrgba64::from_color(m.at(x, y));
                        for v in [c.r, c.g, c.b, c.a] {
                            row[i..i + 2].copy_from_slice(&v.to_be_bytes());
                            i += 2;
                        }
                    }
                }
            }
            let f = if filtered {
                select_filter(&mut cr, &pr, bits / 8)
            } else {
                0
            };
            raw.extend_from_slice(&cr[f]);
            std::mem::swap(&mut pr, &mut cr[0]);
        }
        Ok(raw)
    }
}

/// Go's `bufio.NewWriterSize(encoder, 1<<15)` in front of the IDAT writer:
/// compressed bytes become IDAT chunks of exactly 32 KiB, except that a write
/// larger than the free space goes straight to a chunk when nothing is buffered.
struct IdatWriter<'a> {
    out: &'a mut Vec<u8>,
    buf: Vec<u8>,
}

impl<'a> IdatWriter<'a> {
    const SIZE: usize = 1 << 15;

    fn new(out: &'a mut Vec<u8>) -> Self {
        IdatWriter {
            out,
            buf: Vec::with_capacity(Self::SIZE),
        }
    }

    fn finish(self) {
        if !self.buf.is_empty() {
            write_chunk(self.out, b"IDAT", &self.buf);
        }
    }
}

impl Write for IdatWriter<'_> {
    fn write(&mut self, mut p: &[u8]) -> io::Result<usize> {
        let total = p.len();
        while p.len() > Self::SIZE - self.buf.len() {
            if self.buf.is_empty() {
                write_chunk(self.out, b"IDAT", p);
                return Ok(total);
            }
            let n = Self::SIZE - self.buf.len();
            self.buf.extend_from_slice(&p[..n]);
            p = &p[n..];
            write_chunk(self.out, b"IDAT", &self.buf);
            self.buf.clear();
        }
        self.buf.extend_from_slice(p);
        Ok(total)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn write_chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    let mut crc = Crc32::ieee();
    crc.update(kind);
    crc.update(data);
    out.extend_from_slice(&crc.sum32().to_be_bytes());
}

fn abs8(d: u8) -> usize {
    if d < 128 {
        usize::from(d)
    } else {
        256 - usize::from(d)
    }
}

/// Go's encoder heuristic: fill every filtered candidate row and pick the
/// one with the smallest sum of absolute differences, with Go's early exits.
fn select_filter(cr: &mut [Vec<u8>; 5], pr: &[u8], bpp: usize) -> usize {
    let (first, rest) = cr.split_at_mut(1);
    let cdat0 = &first[0][1..];
    let pdat = &pr[1..];
    let n = cdat0.len();
    let [c1, c2, c3, c4] = rest else {
        return 0;
    };
    let (cdat1, cdat2, cdat3, cdat4) = (&mut c1[1..], &mut c2[1..], &mut c3[1..], &mut c4[1..]);

    let mut sum = 0;
    for i in 0..n {
        cdat2[i] = cdat0[i].wrapping_sub(pdat[i]);
        sum += abs8(cdat2[i]);
    }
    let mut best = sum;
    let mut filter = 2;

    sum = 0;
    for i in 0..bpp.min(n) {
        cdat4[i] = cdat0[i].wrapping_sub(pdat[i]);
        sum += abs8(cdat4[i]);
    }
    for i in bpp..n {
        cdat4[i] = cdat0[i].wrapping_sub(paeth(cdat0[i - bpp], pdat[i], pdat[i - bpp]));
        sum += abs8(cdat4[i]);
        if sum >= best {
            break;
        }
    }
    if sum < best {
        best = sum;
        filter = 4;
    }

    sum = 0;
    for &v in cdat0 {
        sum += abs8(v);
        if sum >= best {
            break;
        }
    }
    if sum < best {
        best = sum;
        filter = 0;
    }

    sum = 0;
    for i in 0..bpp.min(n) {
        cdat1[i] = cdat0[i];
        sum += abs8(cdat1[i]);
    }
    for i in bpp..n {
        cdat1[i] = cdat0[i].wrapping_sub(cdat0[i - bpp]);
        sum += abs8(cdat1[i]);
        if sum >= best {
            break;
        }
    }
    if sum < best {
        best = sum;
        filter = 1;
    }

    sum = 0;
    for i in 0..bpp.min(n) {
        cdat3[i] = cdat0[i].wrapping_sub(pdat[i] / 2);
        sum += abs8(cdat3[i]);
    }
    for i in bpp..n {
        let avg = ((u16::from(cdat0[i - bpp]) + u16::from(pdat[i])) / 2) as u8;
        cdat3[i] = cdat0[i].wrapping_sub(avg);
        sum += abs8(cdat3[i]);
        if sum >= best {
            break;
        }
    }
    if sum < best {
        filter = 3;
    }
    filter
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Collect a run of IDAT chunks with these payloads, as `parse_idat` does
    /// once the main loop has read the first chunk's header.
    fn collect(payloads: &[&[u8]]) -> IdatRun {
        let mut bytes = Vec::new();
        for (i, payload) in payloads.iter().enumerate() {
            if i > 0 {
                bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
                bytes.extend_from_slice(b"IDAT");
            }
            bytes.extend_from_slice(payload);
            let mut crc = Crc32::ieee();
            crc.update(b"IDAT");
            crc.update(payload);
            bytes.extend_from_slice(&crc.sum32().to_be_bytes());
        }
        bytes.extend_from_slice(b"\0\0\0\0IEND");
        let mut d = Decoder::new(&bytes[..], Limits::default());
        d.crc.update(b"IDAT");
        let run = d.collect_idat(payloads[0].len() as u32).unwrap();
        assert!(run.cut.is_none());
        run
    }

    #[test]
    fn idat_run_boundaries_take_at_most_a_bit_per_payload_byte() {
        // Zero-length chunks cost input bytes but no payload, so a million of
        // them may not grow what the run stores.
        let run = collect(&vec![&[][..]; 1_000_000]);
        assert_eq!(run.data.len(), 0);
        assert!(run.is_chunk_end(0));
        assert!(!run.is_chunk_end(1));
        let stored = std::mem::size_of_val(run.ends.as_slice());
        assert!(stored <= 8, "{stored} bytes of boundaries for no payload");

        // Two-byte chunks end at every even offset; 100k of them hold 200 kB
        // of payload, and the boundaries stay within an eighth of that.
        let run = collect(&vec![&[7, 7][..]; 100_000]);
        assert_eq!(run.data.len(), 200_000);
        assert!(run.is_chunk_end(2));
        assert!(!run.is_chunk_end(3));
        assert!(run.is_chunk_end(200_000));
        assert!(!run.is_chunk_end(200_001));
        let stored = std::mem::size_of_val(run.ends.as_slice());
        assert!(
            stored <= run.data.len() / 8 + 8,
            "{stored} bytes of boundaries for {} payload bytes",
            run.data.len()
        );
    }
}
