//! GIF decoding and encoding compatible with Go's `image/gif`.
//!
//! The decoder follows Go's block grammar and leniencies: GIF87a and GIF89a
//! headers, global and local color tables, interlacing, graphic control
//! extensions (delay, disposal, transparency, including Go's enlargement of
//! the palette for an out-of-range transparent index), the NETSCAPE2.0 loop
//! count, skipped comment/plain-text/application extensions, LZW data
//! without an end code, and at most one stray trailing data sub-block. It
//! rejects exactly what Go rejects, with Go's messages: bad block and
//! extension types, frames outside the logical screen, missing color
//! tables, LZW code widths outside 2..=8, too little or too much image data
//! and pixel indexes outside a palette of fewer than 256 colors. Every
//! decode is bounded by [`Limits`], checked before frame buffers are
//! allocated.
//!
//! The encoder writes byte-for-byte what Go writes, including Go's choice
//! between local and global color tables, graphic control extensions,
//! NETSCAPE2.0 loop blocks and LZW sub-blocks. [`encode`] quantizes
//! non-paletted images with [`draw::FloydSteinberg`] and a prefix of the
//! Plan 9 palette unless [`Options`] say otherwise.
//!
//! Deliberate differences from Go: a [`Gif`]'s `config` is `None` where Go
//! uses a zero `image.Config`; Go reuses the global color table when a frame
//! shares the global palette's backing array, which Rust cannot observe, so
//! the encoder applies Go's byte-comparison test to every frame (this gives
//! the same output). The encoder writes nothing when it fails, where Go may
//! already have written a prefix, and it reports a frame whose `pix` is too
//! short for its bounds as an error where Go panics.
//!
//! ```
//! use rust_stdlib::image::{color, gif, rect, Image, Paletted};
//! let palette = color::Palette(vec![
//!     color::Rgba { r: 0, g: 0, b: 0, a: 0xff }.into(),
//!     color::Rgba { r: 0xff, g: 0xff, b: 0xff, a: 0xff }.into(),
//! ]);
//! let mut frame = Paletted::new(rect(0, 0, 2, 2), palette);
//! frame.set_color_index(1, 1, 1);
//! let mut bytes = Vec::new();
//! gif::encode(&mut bytes, &frame, None)?;
//! let decoded = gif::decode(&bytes[..])?;
//! assert_eq!(decoded.color_index_at(1, 1), 1);
//! assert_eq!(decoded.at(0, 0), frame.at(0, 0));
//! # Ok::<(), std::io::Error>(())
//! ```
use std::io::{self, BufReader, Read, Write};

use super::color::{self, palette, Color, Model, Palette};
use super::draw::{self, Drawer, Quantizer};
use super::{pt, Config, Image, Paletted, Point, Rectangle};
use crate::compress::lzw;

/// Go's `gif.DisposalNone`: leave the frame in place.
pub const DISPOSAL_NONE: u8 = 0x01;
/// Go's `gif.DisposalBackground`: restore the background color.
pub const DISPOSAL_BACKGROUND: u8 = 0x02;
/// Go's `gif.DisposalPrevious`: restore the previous frame.
pub const DISPOSAL_PREVIOUS: u8 = 0x03;

const F_COLOR_TABLE: u8 = 1 << 7;
const F_INTERLACE: u8 = 1 << 6;
const F_COLOR_TABLE_BITS_MASK: u8 = 7;
const GC_TRANSPARENT_COLOR_SET: u8 = 1;
const GC_DISPOSAL_METHOD_MASK: u8 = 7 << 2;

const S_EXTENSION: u8 = 0x21;
const S_IMAGE_DESCRIPTOR: u8 = 0x2c;
const S_TRAILER: u8 = 0x3b;

const E_TEXT: u8 = 0x01;
const E_GRAPHIC_CONTROL: u8 = 0xf9;
const E_COMMENT: u8 = 0xfe;
const E_APPLICATION: u8 = 0xff;

/// Resource budgets for one decode. [`decode_config`] reads only the header
/// and global color table and enforces the input budget alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Maximum `width * height` of one frame (one byte per pixel).
    pub max_frame_pixels: u64,
    /// Maximum total pixels across the frames a decode retains.
    pub max_total_pixels: u64,
    /// Maximum number of frames [`decode_all`] retains.
    pub max_frames: usize,
    /// Maximum bytes read from the source.
    pub max_input_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frame_pixels: 1 << 26,
            max_total_pixels: 1 << 28,
            max_frames: 1 << 16,
            max_input_bytes: 1 << 30,
        }
    }
}

/// The frames and metadata of a possibly animated GIF (Go's `gif.GIF`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Gif {
    /// The successive images.
    pub image: Vec<Paletted>,
    /// The delay before each frame, in hundredths of a second.
    pub delay: Vec<i32>,
    /// 0 loops forever, -1 shows each frame once, and n > 0 loops n + 1
    /// times. Only written for more than one frame.
    pub loop_count: i32,
    /// Disposal method per frame; `None` means 0 (unspecified) for all.
    pub disposal: Option<Vec<u8>>,
    /// Global palette (a [`Model::Palette`], empty for none) and logical
    /// screen size. `None` is Go's zero `Config`: the screen is
    /// `(0,0)-image[0].bounds().max` with no global color table.
    pub config: Option<Config>,
    /// Index of the background color in the global color table.
    pub background_index: u8,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// Go's `fmt.Errorf("gif: <prefix>: %v", err)`; this package's own errors
/// (decode limits) pass through unchanged.
fn wrap(prefix: &str, e: io::Error) -> io::Error {
    if e.to_string().starts_with("gif: ") {
        return e;
    }
    io::Error::new(e.kind(), format!("gif: {prefix}: {e}"))
}

/// An LZW error while reading pixels. The decoder's output budget is the
/// frame size, so exceeding it is Go's "too much image data".
fn lzw_error(e: io::Error) -> io::Error {
    if e.kind() == io::ErrorKind::InvalidData && e.to_string() == "lzw: output limit exceeded" {
        return invalid("gif: too much image data");
    }
    wrap("reading image data", e)
}

fn eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF")
}

fn limit_error(what: &str) -> io::Error {
    invalid(format!("gif: {what} exceeds decode limit"))
}

/// Buffered source charged against the input budget.
struct Input<R> {
    inner: BufReader<R>,
    read: u64,
    limit: u64,
}

impl<R: Read> Input<R> {
    fn charge(&mut self, n: usize) -> io::Result<()> {
        if n as u64 > self.limit - self.read {
            return Err(limit_error("input size"));
        }
        self.read += n as u64;
        Ok(())
    }
    /// Go's `readFull`: a short read is `io.ErrUnexpectedEOF`.
    fn full(&mut self, buf: &mut [u8]) -> io::Result<()> {
        self.charge(buf.len())?;
        self.inner.read_exact(buf).map_err(|e| match e.kind() {
            io::ErrorKind::UnexpectedEof => eof(),
            _ => e,
        })
    }
    fn byte(&mut self) -> io::Result<u8> {
        let mut b = [0u8];
        self.full(&mut b)?;
        Ok(b[0])
    }
}

/// Why a [`BlockReader`] stopped.
enum Stop {
    /// A clean block terminator (Go's `io.EOF`).
    Terminator,
    Failed(io::Error),
}

/// Go's `blockReader`: the data sub-blocks of one image, as a byte stream.
struct BlockReader<'a, R> {
    input: &'a mut Input<R>,
    buf: [u8; 255],
    i: usize,
    j: usize,
    stop: Option<Stop>,
}

impl<'a, R: Read> BlockReader<'a, R> {
    fn new(input: &'a mut Input<R>) -> Self {
        Self {
            input,
            buf: [0; 255],
            i: 0,
            j: 0,
            stop: None,
        }
    }
    fn fill(&mut self) {
        if self.stop.is_some() {
            return;
        }
        match self.input.byte() {
            Ok(0) => {
                self.j = 0;
                self.stop = Some(Stop::Terminator);
            }
            Ok(n) => {
                self.i = 0;
                self.j = usize::from(n);
                if let Err(e) = self.input.full(&mut self.buf[..self.j]) {
                    self.j = 0;
                    self.stop = Some(Stop::Failed(e));
                }
            }
            Err(e) => {
                self.j = 0;
                self.stop = Some(Stop::Failed(e));
            }
        }
    }
    fn stop_result(&self) -> io::Result<usize> {
        match &self.stop {
            Some(Stop::Failed(e)) => Err(io::Error::new(e.kind(), e.to_string())),
            _ => Ok(0),
        }
    }
    /// Go's `blockReader.close`: allow at most one trailing sub-block worth
    /// of data before the terminator. `Ok(false)` is Go's `errTooMuch`.
    fn close(&mut self) -> io::Result<bool> {
        match &self.stop {
            Some(Stop::Terminator) => return Ok(true),
            Some(Stop::Failed(_)) => return self.stop_result().map(|_| true),
            None => {}
        }
        if self.i == self.j {
            self.fill();
            match &self.stop {
                Some(Stop::Terminator) => return Ok(true),
                Some(Stop::Failed(_)) => return self.stop_result().map(|_| true),
                None if self.j > 1 => return Ok(false),
                None => {}
            }
        }
        self.fill();
        match &self.stop {
            Some(Stop::Terminator) => Ok(true),
            Some(Stop::Failed(_)) => self.stop_result().map(|_| true),
            None => Ok(false),
        }
    }
}

impl<R: Read> Read for BlockReader<'_, R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() || self.stop.is_some() {
            return self.stop_result();
        }
        if self.i == self.j {
            self.fill();
            if self.stop.is_some() {
                return self.stop_result();
            }
        }
        let n = out.len().min(self.j - self.i);
        out[..n].copy_from_slice(&self.buf[self.i..self.i + n]);
        self.i += n;
        Ok(n)
    }
}

struct Decoder<R> {
    r: Input<R>,
    limits: Limits,
    width: i32,
    height: i32,
    loop_count: i32,
    delay_time: i32,
    background_index: u8,
    disposal_method: u8,
    image_fields: u8,
    transparent_index: u8,
    has_transparent_index: bool,
    global_color_table: Option<Palette>,
    images: Vec<Paletted>,
    delay: Vec<i32>,
    disposal: Vec<u8>,
    total_pixels: u64,
}

impl<R: Read> Decoder<R> {
    fn new(reader: R, limits: Limits) -> Self {
        Self {
            r: Input {
                inner: BufReader::new(reader),
                read: 0,
                limit: limits.max_input_bytes,
            },
            limits,
            width: 0,
            height: 0,
            loop_count: -1,
            delay_time: 0,
            background_index: 0,
            disposal_method: 0,
            image_fields: 0,
            transparent_index: 0,
            has_transparent_index: false,
            global_color_table: None,
            images: Vec::new(),
            delay: Vec::new(),
            disposal: Vec::new(),
            total_pixels: 0,
        }
    }

    fn decode(&mut self, config_only: bool, keep_all_frames: bool) -> io::Result<()> {
        self.read_header_and_screen_descriptor()?;
        if config_only {
            return Ok(());
        }
        loop {
            let c = self.r.byte().map_err(|e| wrap("reading frames", e))?;
            match c {
                S_EXTENSION => self.read_extension()?,
                S_IMAGE_DESCRIPTOR => {
                    self.read_image_descriptor(keep_all_frames)?;
                    if !keep_all_frames && self.images.len() == 1 {
                        return Ok(());
                    }
                }
                S_TRAILER => {
                    if self.images.is_empty() {
                        return Err(invalid("gif: missing image data"));
                    }
                    return Ok(());
                }
                _ => return Err(invalid(format!("gif: unknown block type: 0x{c:02x}"))),
            }
        }
    }

    fn read_header_and_screen_descriptor(&mut self) -> io::Result<()> {
        let mut tmp = [0u8; 13];
        self.r
            .full(&mut tmp)
            .map_err(|e| wrap("reading header", e))?;
        let version = &tmp[..6];
        if version != b"GIF87a" && version != b"GIF89a" {
            return Err(invalid(format!(
                "gif: can't recognize format {:?}",
                String::from_utf8_lossy(version)
            )));
        }
        self.width = i32::from(u16::from_le_bytes([tmp[6], tmp[7]]));
        self.height = i32::from(u16::from_le_bytes([tmp[8], tmp[9]]));
        let fields = tmp[10];
        if fields & F_COLOR_TABLE != 0 {
            self.background_index = tmp[11];
            self.global_color_table = Some(self.read_color_table(fields)?);
        }
        // tmp[12] is the pixel aspect ratio, which is ignored.
        Ok(())
    }

    fn read_color_table(&mut self, fields: u8) -> io::Result<Palette> {
        let n = 1usize << (1 + (fields & F_COLOR_TABLE_BITS_MASK));
        let mut tmp = [0u8; 768];
        self.r
            .full(&mut tmp[..3 * n])
            .map_err(|e| wrap("reading color table", e))?;
        Ok(Palette(
            tmp[..3 * n]
                .chunks_exact(3)
                .map(|c| {
                    Color::Rgba(color::Rgba {
                        r: c[0],
                        g: c[1],
                        b: c[2],
                        a: 0xff,
                    })
                })
                .collect(),
        ))
    }

    fn read_extension(&mut self) -> io::Result<()> {
        let extension = self.r.byte().map_err(|e| wrap("reading extension", e))?;
        let size = match extension {
            E_TEXT => 13,
            E_GRAPHIC_CONTROL => return self.read_graphic_control(),
            E_COMMENT => 0,
            // The spec requires size 11, but Adobe sometimes uses 10.
            E_APPLICATION => usize::from(self.r.byte().map_err(|e| wrap("reading extension", e))?),
            _ => return Err(invalid(format!("gif: unknown extension 0x{extension:02x}"))),
        };
        let mut tmp = [0u8; 255];
        if size > 0 {
            self.r
                .full(&mut tmp[..size])
                .map_err(|e| wrap("reading extension", e))?;
        }
        if extension == E_APPLICATION && &tmp[..size] == b"NETSCAPE2.0" {
            let n = self
                .read_block(&mut tmp)
                .map_err(|e| wrap("reading extension", e))?;
            if n == 0 {
                return Ok(());
            }
            if n == 3 && tmp[0] == 1 {
                self.loop_count = i32::from(u16::from_le_bytes([tmp[1], tmp[2]]));
            }
        }
        loop {
            let n = self
                .read_block(&mut tmp)
                .map_err(|e| wrap("reading extension", e))?;
            if n == 0 {
                return Ok(());
            }
        }
    }

    fn read_graphic_control(&mut self) -> io::Result<()> {
        let mut tmp = [0u8; 6];
        self.r
            .full(&mut tmp)
            .map_err(|e| wrap("can't read graphic control", e))?;
        if tmp[0] != 4 {
            return Err(invalid(format!(
                "gif: invalid graphic control extension block size: {}",
                tmp[0]
            )));
        }
        let flags = tmp[1];
        self.disposal_method = (flags & GC_DISPOSAL_METHOD_MASK) >> 2;
        self.delay_time = i32::from(u16::from_le_bytes([tmp[2], tmp[3]]));
        if flags & GC_TRANSPARENT_COLOR_SET != 0 {
            self.transparent_index = tmp[4];
            self.has_transparent_index = true;
        }
        if tmp[5] != 0 {
            return Err(invalid(format!(
                "gif: invalid graphic control extension block terminator: {}",
                tmp[5]
            )));
        }
        Ok(())
    }

    fn read_block(&mut self, tmp: &mut [u8; 255]) -> io::Result<usize> {
        let n = usize::from(self.r.byte()?);
        if n == 0 {
            return Ok(0);
        }
        self.r.full(&mut tmp[..n])?;
        Ok(n)
    }

    fn new_image_from_descriptor(&mut self, keep: bool) -> io::Result<Paletted> {
        let mut tmp = [0u8; 9];
        self.r
            .full(&mut tmp)
            .map_err(|e| wrap("can't read image descriptor", e))?;
        let le = |i: usize| i32::from(u16::from_le_bytes([tmp[i], tmp[i + 1]]));
        let (left, top, width, height) = (le(0), le(2), le(4), le(6));
        self.image_fields = tmp[8];
        // Each image must fit within the logical screen (GIF89a section 20).
        if left + width > self.width || top + height > self.height {
            return Err(invalid("gif: frame bounds larger than image bounds"));
        }
        let pixels = width as u64 * height as u64;
        if pixels > self.limits.max_frame_pixels {
            return Err(limit_error("frame size"));
        }
        if keep {
            if self.images.len() >= self.limits.max_frames {
                return Err(limit_error("frame count"));
            }
            if pixels > self.limits.max_total_pixels - self.total_pixels {
                return Err(limit_error("total frame size"));
            }
        }
        let bounds = Rectangle {
            min: pt(left, top),
            max: pt(left + width, top + height),
        };
        Paletted::try_new(bounds, Palette::default()).ok_or_else(|| limit_error("frame size"))
    }

    fn read_image_descriptor(&mut self, keep_all_frames: bool) -> io::Result<()> {
        let keep = keep_all_frames || self.images.is_empty();
        let mut m = self.new_image_from_descriptor(keep)?;
        let use_local = self.image_fields & F_COLOR_TABLE != 0;
        m.palette = if use_local {
            self.read_color_table(self.image_fields)?
        } else {
            match &self.global_color_table {
                Some(p) => p.clone(),
                None => return Err(invalid("gif: no color table")),
            }
        };
        if self.has_transparent_index {
            let ti = usize::from(self.transparent_index);
            if ti < m.palette.len() {
                m.palette.0[ti] = color::Rgba::default().into();
            } else {
                // Out of range per the spec, but browsers accept it, so the
                // palette grows with transparent colors (golang.org/issue/15059).
                m.palette.0.resize(ti + 1, color::Rgba::default().into());
            }
        }
        let lit_width = self.r.byte().map_err(|e| wrap("reading image data", e))?;
        if !(2..=8).contains(&lit_width) {
            return Err(invalid(format!(
                "gif: pixel size in decode out of range: {lit_width}"
            )));
        }
        let too_much = || invalid("gif: too much image data");
        let mut pixels = vec![0u8; m.pix.len()];
        {
            let mut br = BlockReader::new(&mut self.r);
            let mut lzwr =
                lzw::Reader::new(&mut br, lzw::Order::Lsb, lit_width).with_max_output(pixels.len());
            let mut filled = 0;
            while filled < pixels.len() {
                match lzwr.read(&mut pixels[filled..]) {
                    Ok(0) => return Err(invalid("gif: not enough image data")),
                    Ok(n) => filled += n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                        return Err(invalid("gif: not enough image data"))
                    }
                    Err(e) => return Err(lzw_error(e)),
                }
            }
            // Both the LZW stream and the sub-blocks should now be exhausted.
            // A missing end code is accepted (giflib does not enforce it,
            // golang.org/issue/9856); trailing pixels are not.
            let mut extra = [0u8; 1];
            match lzwr.read(&mut extra) {
                Ok(0) => {}
                Ok(_) => return Err(too_much()),
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {}
                Err(e) => return Err(lzw_error(e)),
            }
            drop(lzwr);
            // Some GIFs carry an extra byte in the data sub-blocks
            // (golang.org/issue/16146).
            if !br.close().map_err(|e| wrap("reading image data", e))? {
                return Err(too_much());
            }
        }
        if m.palette.len() < 256 && pixels.iter().any(|&p| usize::from(p) >= m.palette.len()) {
            return Err(invalid("gif: invalid pixel value"));
        }
        m.pix = pixels.into();
        if self.image_fields & F_INTERLACE != 0 {
            uninterlace(&mut m);
        }
        if keep {
            self.total_pixels += m.pix.len() as u64;
            self.images.push(m);
            self.delay.push(self.delay_time);
            self.disposal.push(self.disposal_method);
        }
        // A graphic control extension applies to the next image only.
        self.delay_time = 0;
        self.has_transparent_index = false;
        Ok(())
    }
}

/// Undo GIF interlacing: rows arrive as every 8th from 0, every 8th from 4,
/// every 4th from 2 and every 2nd from 1.
fn uninterlace(m: &mut Paletted) {
    let dx = m.rect.dx() as usize;
    let dy = m.rect.dy() as usize;
    let mut out = vec![0u8; dx * dy];
    let src = m.pix.to_vec();
    let mut offset = 0;
    for (skip, start) in [(8, 0), (8, 4), (4, 2), (2, 1)] {
        for y in (start..dy).step_by(skip) {
            out[y * dx..(y + 1) * dx].copy_from_slice(&src[offset..offset + dx]);
            offset += dx;
        }
    }
    m.pix = out.into();
}

/// Decode the first frame of a GIF with default [`Limits`].
pub fn decode(reader: impl Read) -> io::Result<Paletted> {
    decode_with_limits(reader, Limits::default())
}

/// Decode the first frame of a GIF within `limits`.
pub fn decode_with_limits(reader: impl Read, limits: Limits) -> io::Result<Paletted> {
    let mut d = Decoder::new(reader, limits);
    d.decode(false, false)?;
    Ok(d.images.swap_remove(0))
}

/// Decode every frame and the animation metadata with default [`Limits`].
pub fn decode_all(reader: impl Read) -> io::Result<Gif> {
    decode_all_with_limits(reader, Limits::default())
}

/// Decode every frame and the animation metadata within `limits`.
pub fn decode_all_with_limits(reader: impl Read, limits: Limits) -> io::Result<Gif> {
    let mut d = Decoder::new(reader, limits);
    d.decode(false, true)?;
    Ok(Gif {
        image: d.images,
        delay: d.delay,
        loop_count: d.loop_count,
        disposal: Some(d.disposal),
        config: Some(Config {
            color_model: Model::Palette(d.global_color_table.unwrap_or_default()),
            width: d.width,
            height: d.height,
        }),
        background_index: d.background_index,
    })
}

/// The global palette (empty when absent) and logical screen size, with
/// default [`Limits`].
pub fn decode_config(reader: impl Read) -> io::Result<Config> {
    decode_config_with_limits(reader, Limits::default())
}

/// The global palette and logical screen size within `limits`.
pub fn decode_config_with_limits(reader: impl Read, limits: Limits) -> io::Result<Config> {
    let mut d = Decoder::new(reader, limits);
    d.decode(true, false)?;
    Ok(Config {
        color_model: Model::Palette(d.global_color_table.unwrap_or_default()),
        width: d.width,
        height: d.height,
    })
}

fn encode_error(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, format!("gif: {message}"))
}

/// Go's `log2`: the color table size field for `n` colors.
fn log2(n: usize) -> u32 {
    if n < 2 {
        return 0;
    }
    usize::BITS - (n - 1).leading_zeros() - 1
}

/// Go's `encodeColorTable`: RGB triples padded with black to `2^(size+1)`
/// entries. Returns the table length in bytes.
fn encode_color_table(dst: &mut [u8; 768], p: &Palette, size: u32) -> io::Result<usize> {
    if size >= 8 {
        return Err(encode_error(
            "cannot encode color table with more than 256 entries",
        ));
    }
    for (i, c) in p.0.iter().enumerate() {
        let (r, g, b) = match c {
            Color::Rgba(c) => (c.r, c.g, c.b),
            other => {
                let (r, g, b, _) = other.rgba();
                ((r >> 8) as u8, (g >> 8) as u8, (b >> 8) as u8)
            }
        };
        dst[3 * i..3 * i + 3].copy_from_slice(&[r, g, b]);
    }
    let n = 1usize << (size + 1);
    if n > p.len() {
        dst[3 * p.len()..3 * n].fill(0);
    }
    Ok(3 * n)
}

/// Go's `blockWriter`: splits a byte stream into data sub-blocks.
struct BlockWriter<'a> {
    out: &'a mut Vec<u8>,
    buf: [u8; 256],
}

impl Write for BlockWriter<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        for &c in data {
            self.buf[0] += 1;
            self.buf[usize::from(self.buf[0])] = c;
            if self.buf[0] == 255 {
                self.out.extend_from_slice(&self.buf);
                self.buf[0] = 0;
            }
        }
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl BlockWriter<'_> {
    /// Write any pending sub-block and the block terminator.
    fn close(self) {
        let n = usize::from(self.buf[0]);
        if n > 0 {
            self.out.extend_from_slice(&self.buf[..n + 1]);
        }
        self.out.push(0);
    }
}

struct Encoder<'a> {
    out: Vec<u8>,
    g: &'a Gif,
    width: i32,
    height: i32,
    global: Option<&'a Palette>,
    global_ct: usize,
    global_color_table: [u8; 768],
    local_color_table: [u8; 768],
}

impl Encoder<'_> {
    fn write_header(&mut self) -> io::Result<()> {
        self.out.extend_from_slice(b"GIF89a");
        self.out
            .extend_from_slice(&(self.width as u16).to_le_bytes());
        self.out
            .extend_from_slice(&(self.height as u16).to_le_bytes());
        match self.global {
            Some(p) if !p.is_empty() => {
                let padded = log2(p.len());
                self.out.extend_from_slice(&[
                    F_COLOR_TABLE | padded as u8,
                    self.g.background_index,
                    0,
                ]);
                self.global_ct = encode_color_table(&mut self.global_color_table, p, padded)?;
                self.out
                    .extend_from_slice(&self.global_color_table[..self.global_ct]);
            }
            // Every frame has a local color table.
            _ => self.out.extend_from_slice(&[0, 0, 0]),
        }
        if self.g.image.len() > 1 && self.g.loop_count >= 0 {
            self.out.extend_from_slice(&[0x21, 0xff, 0x0b]);
            self.out.extend_from_slice(b"NETSCAPE2.0");
            self.out.extend_from_slice(&[0x03, 0x01]);
            self.out
                .extend_from_slice(&(self.g.loop_count as u16).to_le_bytes());
            self.out.push(0);
        }
        Ok(())
    }

    fn color_tables_match(&self, local_len: usize, transparent_index: Option<usize>) -> bool {
        let local_size = 3 * local_len;
        let (g, l) = (&self.global_color_table, &self.local_color_table);
        match transparent_index {
            Some(ti) => {
                let off = 3 * ti;
                g[..off] == l[..off] && g[off + 3..local_size] == l[off + 3..local_size]
            }
            None => g[..local_size] == l[..local_size],
        }
    }

    fn write_image_block(&mut self, pm: &Paletted, delay: i32, disposal: u8) -> io::Result<()> {
        if pm.palette.is_empty() {
            return Err(encode_error("cannot encode image block with empty palette"));
        }
        let b = pm.rect;
        if b.min.x < 0 || b.max.x >= 1 << 16 || b.min.y < 0 || b.max.y >= 1 << 16 {
            return Err(encode_error("image block is too large to encode"));
        }
        let screen = Rectangle {
            min: Point::default(),
            max: pt(self.width, self.height),
        };
        if !b.is_in(screen) {
            return Err(encode_error("image block is out of bounds"));
        }
        let transparent_index = pm.palette.0.iter().position(|c| c.rgba().3 == 0);
        if delay > 0 || disposal != 0 || transparent_index.is_some() {
            let flags = u8::from(transparent_index.is_some()) | disposal.wrapping_shl(2);
            self.out
                .extend_from_slice(&[S_EXTENSION, 0xf9, 0x04, flags]);
            self.out.extend_from_slice(&(delay as u16).to_le_bytes());
            self.out
                .extend_from_slice(&[transparent_index.unwrap_or(0) as u8, 0]);
        }
        self.out.push(S_IMAGE_DESCRIPTOR);
        for v in [b.min.x, b.min.y, b.dx(), b.dy()] {
            self.out.extend_from_slice(&(v as u16).to_le_bytes());
        }
        let padded = log2(pm.palette.len());
        let ct = encode_color_table(&mut self.local_color_table, &pm.palette, padded)?;
        if ct <= self.global_ct && self.color_tables_match(pm.palette.len(), transparent_index) {
            // Use the global color table.
            self.out.push(0);
        } else {
            self.out.push(F_COLOR_TABLE | padded as u8);
            self.out.extend_from_slice(&self.local_color_table[..ct]);
        }
        let lit_width = (padded + 1).max(2) as u8;
        self.out.push(lit_width);

        let dx = b.dx() as usize;
        let dy = b.dy() as usize;
        let short = || encode_error("pixel buffer is too small for the image bounds");
        let mut bw = BlockWriter {
            out: &mut self.out,
            buf: [0; 256],
        };
        let mut lzww = lzw::Writer::new(&mut bw, lzw::Order::Lsb, lit_width);
        let pix = pm.pix.to_vec();
        if dx == pm.stride {
            lzww.write_all(pix.get(..dx * dy).ok_or_else(short)?)?;
        } else {
            for row in 0..dy {
                let i = row * pm.stride;
                lzww.write_all(pix.get(i..i + dx).ok_or_else(short)?)?;
            }
        }
        lzww.finish()?;
        bw.close();
        Ok(())
    }
}

/// Write every frame of `g` in GIF format (Go's `gif.EncodeAll`).
pub fn encode_all(mut writer: impl Write, g: &Gif) -> io::Result<()> {
    if g.image.is_empty() {
        return Err(encode_error("must provide at least one image"));
    }
    if g.image.len() != g.delay.len() {
        return Err(encode_error("mismatched image and delay lengths"));
    }
    if let Some(d) = &g.disposal {
        if d.len() != g.image.len() {
            return Err(encode_error("mismatched image and disposal lengths"));
        }
    }
    let (width, height, global) = match &g.config {
        None => {
            let p = g.image[0].bounds().max;
            (p.x, p.y, None)
        }
        Some(c) => match &c.color_model {
            Model::Palette(p) => (c.width, c.height, Some(p)),
            _ => return Err(encode_error("GIF color model must be a color.Palette")),
        },
    };
    let mut e = Encoder {
        out: Vec::new(),
        g,
        width,
        height,
        global,
        global_ct: 0,
        global_color_table: [0; 768],
        local_color_table: [0; 768],
    };
    e.write_header()?;
    for (i, pm) in g.image.iter().enumerate() {
        let disposal = g.disposal.as_ref().map_or(0, |d| d[i]);
        e.write_image_block(pm, g.delay[i], disposal)?;
    }
    e.out.push(S_TRAILER);
    writer.write_all(&e.out)?;
    writer.flush()
}

/// Encoding parameters for [`encode`] (Go's `gif.Options`).
#[derive(Clone, Copy, Default)]
pub struct Options<'a> {
    /// Maximum number of colors, 1 to 256; other values mean 256.
    pub num_colors: i32,
    /// Produces the palette; `None` uses a prefix of the Plan 9 palette.
    pub quantizer: Option<&'a dyn Quantizer>,
    /// Converts the image to the palette; `None` uses
    /// [`draw::FloydSteinberg`].
    pub drawer: Option<&'a dyn Drawer>,
}

/// Write `m` as a single-frame GIF (Go's `gif.Encode`). Paletted images with
/// at most `num_colors` colors are written as is; others are converted.
pub fn encode(writer: impl Write, m: &dyn Image, options: Option<&Options<'_>>) -> io::Result<()> {
    let b = m.bounds();
    let (wide_dx, wide_dy) = (
        i64::from(b.max.x) - i64::from(b.min.x),
        i64::from(b.max.y) - i64::from(b.min.y),
    );
    if wide_dx >= 1 << 16 || wide_dy >= 1 << 16 {
        return Err(encode_error("image is too large to encode"));
    }
    let options = options.copied().unwrap_or_default();
    let num_colors = if (1..=256).contains(&options.num_colors) {
        options.num_colors as usize
    } else {
        256
    };
    let drawer: &dyn Drawer = options.drawer.unwrap_or(&draw::FloydSteinberg);
    let too_large = || encode_error("image is too large to encode");

    let mut pm: Option<Paletted> = m
        .as_any()
        .and_then(|a| a.downcast_ref::<Paletted>())
        .cloned();
    if pm.is_none() {
        if let Model::Palette(cp) = m.color_model() {
            let mut p = Paletted::try_new(b, cp.clone()).ok_or_else(too_large)?;
            for y in b.min.y..b.max.y {
                for x in b.min.x..b.max.x {
                    p.set(
                        x,
                        y,
                        cp.convert(m.at(x, y)).unwrap_or(color::TRANSPARENT.into()),
                    );
                }
            }
            pm = Some(p);
        }
    }
    let mut pm = match pm {
        Some(p) if p.palette.len() <= num_colors => p,
        _ => {
            let plan9 = Palette(palette::plan9().0[..num_colors].to_vec());
            let mut p = Paletted::try_new(b, plan9).ok_or_else(too_large)?;
            if let Some(q) = options.quantizer {
                p.palette = q.quantize(Palette(Vec::with_capacity(num_colors)), num_colors, m);
            }
            drawer.draw(&mut p, b, m, b.min);
            p
        }
    };
    // The single frame is translated so that it fills the logical screen.
    pm.rect = pm.rect - pm.rect.min;
    let config = Config {
        color_model: Model::Palette(pm.palette.clone()),
        width: b.dx(),
        height: b.dy(),
    };
    encode_all(
        writer,
        &Gif {
            image: vec![pm],
            delay: vec![0],
            loop_count: 0,
            disposal: None,
            config: Some(config),
            background_index: 0,
        },
    )
}
