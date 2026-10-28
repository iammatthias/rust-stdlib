//! The baseline JPEG encoder (Go's `writer.go`).
use std::io::{self, Write};

use super::dct::{fdct, Block, BLOCK_SIZE};
use super::reader::UNZIG;
use crate::image::color;
use crate::image::ycbcr::Ycbcr;
use crate::image::{Gray, Image, Point, Rgba};

const SOF0_MARKER: u8 = 0xc0;
const DHT_MARKER: u8 = 0xc4;
const DQT_MARKER: u8 = 0xdb;

/// Returns `a/b` rounded to the nearest integer, instead of toward zero.
fn div(a: i32, b: i32) -> i32 {
    if a >= 0 {
        (a + (b >> 1)) / b
    } else {
        -((-a + (b >> 1)) / b)
    }
}

const N_QUANT_INDEX: usize = 2;

/// The unscaled quantization tables in zig-zag order (section K.1 of the
/// spec, after converting from natural order). Each encoder copies and scales
/// them according to its quality parameter.
const UNSCALED_QUANT: [[u8; BLOCK_SIZE]; N_QUANT_INDEX] = [
    // Luminance.
    [
        16, 11, 12, 14, 12, 10, 16, 14, 13, 14, 18, 17, 16, 19, 24, 40, 26, 24, 22, 22, 24, 49, 35,
        37, 29, 40, 58, 51, 61, 60, 57, 51, 56, 55, 64, 72, 92, 78, 64, 68, 87, 69, 55, 56, 80,
        109, 81, 87, 95, 98, 103, 104, 103, 62, 77, 113, 121, 112, 100, 120, 92, 101, 103, 99,
    ],
    // Chrominance.
    [
        17, 18, 18, 24, 21, 24, 47, 26, 26, 47, 99, 66, 56, 66, 99, 99, 99, 99, 99, 99, 99, 99, 99,
        99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
        99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
    ],
];

const N_HUFF_INDEX: usize = 4;

/// A Huffman encoding specification.
struct HuffmanSpec {
    /// `count[i]` is the number of codes of length `i+1` bits.
    count: [u8; 16],
    /// `value[i]` is the decoded value of the i'th codeword.
    value: &'static [u8],
}

/// The Huffman encodings used for every image: those of section K.3 of the
/// spec.
const THE_HUFFMAN_SPEC: [HuffmanSpec; N_HUFF_INDEX] = [
    // Luminance DC.
    HuffmanSpec {
        count: [0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0],
        value: &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
    },
    // Luminance AC.
    HuffmanSpec {
        count: [0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 125],
        value: &[
            0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06, 0x13, 0x51,
            0x61, 0x07, 0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xa1, 0x08, 0x23, 0x42, 0xb1, 0xc1,
            0x15, 0x52, 0xd1, 0xf0, 0x24, 0x33, 0x62, 0x72, 0x82, 0x09, 0x0a, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
            0x3a, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x53, 0x54, 0x55, 0x56, 0x57,
            0x58, 0x59, 0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x73, 0x74, 0x75,
            0x76, 0x77, 0x78, 0x79, 0x7a, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x92,
            0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
            0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xc2, 0xc3,
            0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8,
            0xd9, 0xda, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xf1, 0xf2,
            0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa,
        ],
    },
    // Chrominance DC.
    HuffmanSpec {
        count: [0, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0],
        value: &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
    },
    // Chrominance AC.
    HuffmanSpec {
        count: [0, 2, 1, 2, 4, 4, 3, 4, 7, 5, 4, 4, 0, 1, 2, 119],
        value: &[
            0x00, 0x01, 0x02, 0x03, 0x11, 0x04, 0x05, 0x21, 0x31, 0x06, 0x12, 0x41, 0x51, 0x07,
            0x61, 0x71, 0x13, 0x22, 0x32, 0x81, 0x08, 0x14, 0x42, 0x91, 0xa1, 0xb1, 0xc1, 0x09,
            0x23, 0x33, 0x52, 0xf0, 0x15, 0x62, 0x72, 0xd1, 0x0a, 0x16, 0x24, 0x34, 0xe1, 0x25,
            0xf1, 0x17, 0x18, 0x19, 0x1a, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x35, 0x36, 0x37, 0x38,
            0x39, 0x3a, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x53, 0x54, 0x55, 0x56,
            0x57, 0x58, 0x59, 0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x73, 0x74,
            0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
            0x8a, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0xa2, 0xa3, 0xa4, 0xa5,
            0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba,
            0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6,
            0xd7, 0xd8, 0xd9, 0xda, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xf2,
            0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa,
        ],
    },
];

/// Compiles a spec into a look-up table: the 8 most significant bits of each
/// entry hold the codeword size in bits and the 24 least significant bits
/// hold the codeword.
fn huffman_lut(s: &HuffmanSpec) -> Vec<u32> {
    let max_value = s.value.iter().copied().max().map_or(0, usize::from);
    let mut lut = vec![0u32; max_value + 1];
    let (mut code, mut k) = (0u32, 0usize);
    for (i, &count) in s.count.iter().enumerate() {
        let n_bits = (i as u32 + 1) << 24;
        for _ in 0..count {
            lut[usize::from(s.value[k])] = n_bits | code;
            code += 1;
            k += 1;
        }
        code <<= 1;
    }
    lut
}

/// Go's `bufio.Writer` with its default 4096-byte buffer, so a failing
/// writer sees the same sequence of writes.
struct BufWriter<W: Write> {
    w: W,
    buf: Vec<u8>,
    err: Option<io::Error>,
}

const BUF_SIZE: usize = 4096;

impl<W: Write> BufWriter<W> {
    fn flush(&mut self) {
        if self.err.is_some() {
            return;
        }
        if let Err(error) = self.w.write_all(&self.buf) {
            self.err = Some(error);
        }
        self.buf.clear();
    }

    fn write(&mut self, mut p: &[u8]) {
        while self.err.is_none() && p.len() > BUF_SIZE - self.buf.len() {
            if self.buf.is_empty() {
                // Large write, empty buffer: write directly.
                if let Err(error) = self.w.write_all(p) {
                    self.err = Some(error);
                }
                return;
            }
            let n = BUF_SIZE - self.buf.len();
            self.buf.extend_from_slice(&p[..n]);
            p = &p[n..];
            self.flush();
        }
        if self.err.is_none() {
            self.buf.extend_from_slice(p);
        }
    }

    fn write_byte(&mut self, b: u8) {
        if self.err.is_some() {
            return;
        }
        if self.buf.len() >= BUF_SIZE {
            self.flush();
            if self.err.is_some() {
                return;
            }
        }
        self.buf.push(b);
    }
}

/// Encodes an image to the JPEG format.
struct Encoder<W: Write> {
    /// The writer; after the first error all writes are no-ops.
    w: BufWriter<W>,
    /// Accumulated bits to write.
    bits: u32,
    n_bits: u32,
    /// The scaled quantization tables, in zig-zag order.
    quant: [[u8; BLOCK_SIZE]; N_QUANT_INDEX],
    huffman_lut: [Vec<u32>; N_HUFF_INDEX],
}

impl<W: Write> Encoder<W> {
    /// Emits the least significant `n_bits` bits of `bits`.
    /// Precondition: `bits < 1 << n_bits && n_bits <= 16`.
    fn emit(&mut self, mut bits: u32, n_bits: u32) {
        let mut n_bits = n_bits + self.n_bits;
        bits <<= 32 - n_bits;
        bits |= self.bits;
        while n_bits >= 8 {
            let b = (bits >> 24) as u8;
            self.w.write_byte(b);
            if b == 0xff {
                self.w.write_byte(0x00);
            }
            bits <<= 8;
            n_bits -= 8;
        }
        self.bits = bits;
        self.n_bits = n_bits;
    }

    /// Emits the given value with the given Huffman encoder.
    fn emit_huff(&mut self, h: usize, value: i32) {
        let x = self.huffman_lut[h][value as usize];
        self.emit(x & ((1 << 24) - 1), x >> 24);
    }

    /// Emits a run of `run_length` zeros followed by `value`, Huffman coded.
    fn emit_huff_rle(&mut self, h: usize, run_length: i32, value: i32) {
        let (a, b) = if value < 0 {
            (-value, value - 1)
        } else {
            (value, value)
        };
        // The number of bits needed to hold a.
        let n_bits = 32 - (a as u32).leading_zeros();
        self.emit_huff(h, run_length << 4 | n_bits as i32);
        if n_bits > 0 {
            self.emit(b as u32 & ((1 << n_bits) - 1), n_bits);
        }
    }

    fn write_marker_header(&mut self, marker: u8, marker_len: usize) {
        self.w.write(&[
            0xff,
            marker,
            (marker_len >> 8) as u8,
            (marker_len & 0xff) as u8,
        ]);
    }

    /// Writes the Define Quantization Table marker.
    fn write_dqt(&mut self) {
        let marker_len = 2 + N_QUANT_INDEX * (1 + BLOCK_SIZE);
        self.write_marker_header(DQT_MARKER, marker_len);
        for i in 0..N_QUANT_INDEX {
            self.w.write_byte(i as u8);
            let table = self.quant[i];
            self.w.write(&table);
        }
    }

    /// Writes the Start Of Frame (Baseline Sequential) marker.
    fn write_sof0(&mut self, size: Point, n_component: usize) {
        let marker_len = 8 + 3 * n_component;
        self.write_marker_header(SOF0_MARKER, marker_len);
        let mut buf = [0u8; 16];
        buf[0] = 8; // 8-bit color.
        buf[1] = (size.y >> 8) as u8;
        buf[2] = (size.y & 0xff) as u8;
        buf[3] = (size.x >> 8) as u8;
        buf[4] = (size.x & 0xff) as u8;
        buf[5] = n_component as u8;
        if n_component == 1 {
            buf[6] = 1;
            // No subsampling for grayscale image.
            buf[7] = 0x11;
            buf[8] = 0x00;
        } else {
            for i in 0..n_component {
                buf[3 * i + 6] = (i + 1) as u8;
                // 4:2:0 chroma subsampling.
                buf[3 * i + 7] = b"\x22\x11\x11"[i];
                buf[3 * i + 8] = b"\x00\x01\x01"[i];
            }
        }
        self.w.write(&buf[..3 * (n_component - 1) + 9]);
    }

    /// Writes the Define Huffman Table marker.
    fn write_dht(&mut self, n_component: usize) {
        let mut marker_len = 2;
        let specs = if n_component == 1 {
            // Drop the chrominance tables.
            &THE_HUFFMAN_SPEC[..2]
        } else {
            &THE_HUFFMAN_SPEC[..]
        };
        for s in specs {
            marker_len += 1 + 16 + s.value.len();
        }
        self.write_marker_header(DHT_MARKER, marker_len);
        for (i, s) in specs.iter().enumerate() {
            self.w.write_byte(b"\x00\x10\x01\x11"[i]);
            self.w.write(&s.count);
            self.w.write(s.value);
        }
    }

    /// Writes a block of pixel data using quantization table `q`, returning
    /// the post-quantized DC value of the transformed block. `b` is in natural
    /// order.
    fn write_block(&mut self, b: &mut Block, q: usize, prev_dc: i32) -> i32 {
        fdct(b);
        // Emit the DC delta.
        let dc = div(b[0], 8 * i32::from(self.quant[q][0]));
        self.emit_huff_rle(2 * q, 0, dc - prev_dc);
        // Emit the AC components.
        let (h, mut run_length) = (2 * q + 1, 0i32);
        for zig in 1..BLOCK_SIZE {
            let ac = div(b[UNZIG[zig]], 8 * i32::from(self.quant[q][zig]));
            if ac == 0 {
                run_length += 1;
            } else {
                while run_length > 15 {
                    self.emit_huff(h, 0xf0);
                    run_length -= 16;
                }
                self.emit_huff_rle(h, run_length, ac);
                run_length = 0;
            }
        }
        if run_length > 0 {
            self.emit_huff(h, 0x00);
        }
        dc
    }

    /// Writes the Start Of Scan marker and the entropy-coded data.
    fn write_sos(&mut self, m: &dyn Image) {
        let any = m.as_any();
        let gray = any.and_then(|a| a.downcast_ref::<Gray>());
        let rgba = any.and_then(|a| a.downcast_ref::<Rgba>());
        let ycbcr = any.and_then(|a| a.downcast_ref::<Ycbcr>());
        if gray.is_some() {
            // The SOS marker, length 8, 1 component using DC and AC table 0,
            // then Ss, Se and Ah/Al for a sequential DCT (0x00, 0x3f, 0x00).
            self.w
                .write(&[0xff, 0xda, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3f, 0x00]);
        } else {
            // Length 12, 3 components: Y uses tables 0, Cb and Cr tables 1.
            self.w.write(&[
                0xff, 0xda, 0x00, 0x0c, 0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3f, 0x00,
            ]);
        }
        // Scratch buffers for the YCbCr values, in natural order.
        let mut b: Block = [0; BLOCK_SIZE];
        let mut cb: [Block; 4] = [[0; BLOCK_SIZE]; 4];
        let mut cr: [Block; 4] = [[0; BLOCK_SIZE]; 4];
        // DC components are delta-encoded.
        let (mut prev_dc_y, mut prev_dc_cb, mut prev_dc_cr) = (0, 0, 0);
        let bounds = m.bounds();
        if let Some(gray) = gray {
            let mut y = bounds.min.y;
            while y < bounds.max.y {
                let mut x = bounds.min.x;
                while x < bounds.max.x {
                    gray_to_y(gray, Point { x, y }, &mut b);
                    prev_dc_y = self.write_block(&mut b, 0, prev_dc_y);
                    x += 8;
                }
                y += 8;
            }
        } else {
            let mut y = bounds.min.y;
            while y < bounds.max.y {
                let mut x = bounds.min.x;
                while x < bounds.max.x {
                    for i in 0..4 {
                        let x_off = (i & 1) * 8;
                        let y_off = (i & 2) * 4;
                        let p = Point {
                            x: x + x_off,
                            y: y + y_off,
                        };
                        if let Some(rgba) = rgba {
                            rgba_to_ycbcr(
                                rgba,
                                p,
                                &mut b,
                                &mut cb[i as usize],
                                &mut cr[i as usize],
                            );
                        } else if let Some(ycbcr) = ycbcr {
                            ycbcr_to_ycbcr(
                                ycbcr,
                                p,
                                &mut b,
                                &mut cb[i as usize],
                                &mut cr[i as usize],
                            );
                        } else {
                            to_ycbcr(m, p, &mut b, &mut cb[i as usize], &mut cr[i as usize]);
                        }
                        prev_dc_y = self.write_block(&mut b, 0, prev_dc_y);
                    }
                    scale(&mut b, &cb);
                    prev_dc_cb = self.write_block(&mut b, 1, prev_dc_cb);
                    scale(&mut b, &cr);
                    prev_dc_cr = self.write_block(&mut b, 1, prev_dc_cr);
                    x += 16;
                }
                y += 16;
            }
        }
        // Pad the last byte with 1's.
        self.emit(0x7f, 7);
    }
}

/// Converts the 8x8 region of `m` whose top-left corner is `p` to YCbCr.
fn to_ycbcr(
    m: &dyn Image,
    p: Point,
    y_block: &mut Block,
    cb_block: &mut Block,
    cr_block: &mut Block,
) {
    let b = m.bounds();
    let (xmax, ymax) = (b.max.x - 1, b.max.y - 1);
    for j in 0..8 {
        for i in 0..8 {
            let (r, g, b, _) = m.at((p.x + i).min(xmax), (p.y + j).min(ymax)).rgba();
            let (yy, cb, cr) = color::rgb_to_ycbcr((r >> 8) as u8, (g >> 8) as u8, (b >> 8) as u8);
            let k = (8 * j + i) as usize;
            y_block[k] = i32::from(yy);
            cb_block[k] = i32::from(cb);
            cr_block[k] = i32::from(cr);
        }
    }
}

/// Stores the 8x8 region of `m` whose top-left corner is `p` in `y_block`.
fn gray_to_y(m: &Gray, p: Point, y_block: &mut Block) {
    let b = m.rect;
    let (xmax, ymax) = (b.max.x - 1, b.max.y - 1);
    for j in 0..8 {
        for i in 0..8 {
            let idx = m.pix_offset((p.x + i).min(xmax), (p.y + j).min(ymax));
            y_block[(8 * j + i) as usize] = i32::from(m.pix.get(idx));
        }
    }
}

/// A specialized [`to_ycbcr`] for [`Rgba`] images.
fn rgba_to_ycbcr(
    m: &Rgba,
    p: Point,
    y_block: &mut Block,
    cb_block: &mut Block,
    cr_block: &mut Block,
) {
    let b = m.rect;
    let (xmax, ymax) = (b.max.x - 1, b.max.y - 1);
    for j in 0..8 {
        let sj = (p.y + j).min(ymax);
        for i in 0..8 {
            let sx = (p.x + i).min(xmax);
            let o = m.pix_offset(sx, sj);
            let (yy, cb, cr) =
                color::rgb_to_ycbcr(m.pix.get(o), m.pix.get(o + 1), m.pix.get(o + 2));
            let k = (8 * j + i) as usize;
            y_block[k] = i32::from(yy);
            cb_block[k] = i32::from(cb);
            cr_block[k] = i32::from(cr);
        }
    }
}

/// A specialized [`to_ycbcr`] for [`Ycbcr`] images.
fn ycbcr_to_ycbcr(
    m: &Ycbcr,
    p: Point,
    y_block: &mut Block,
    cb_block: &mut Block,
    cr_block: &mut Block,
) {
    let b = m.rect;
    let (xmax, ymax) = (b.max.x - 1, b.max.y - 1);
    for j in 0..8 {
        let sy = (p.y + j).min(ymax);
        for i in 0..8 {
            let sx = (p.x + i).min(xmax);
            let yi = m.y_offset(sx, sy);
            let ci = m.c_offset(sx, sy);
            let k = (8 * j + i) as usize;
            y_block[k] = i32::from(m.y.get(yi));
            cb_block[k] = i32::from(m.cb.get(ci));
            cr_block[k] = i32::from(m.cr.get(ci));
        }
    }
}

/// Scales the 16x16 region represented by the 4 `src` blocks to the 8x8
/// `dst` block.
fn scale(dst: &mut Block, src: &[Block; 4]) {
    for (i, s) in src.iter().enumerate() {
        let dst_off = (i & 2) << 4 | (i & 1) << 2;
        for y in 0..4 {
            for x in 0..4 {
                let j = 16 * y + 2 * x;
                let sum = s[j] + s[j + 1] + s[j + 8] + s[j + 9];
                dst[8 * y + x + dst_off] = (sum + 2) >> 2;
            }
        }
    }
}

/// Go's `jpeg.DefaultQuality`.
pub const DEFAULT_QUALITY: i32 = 75;

/// Go's `jpeg.Options`: the encoding parameters. Quality ranges from 1 to 100
/// inclusive, higher is better; values outside are clamped.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Options {
    pub quality: i32,
}

/// Go's `jpeg.Encode`: writes `m` to `w` in JPEG 4:2:0 baseline format with
/// the given options; `None` (Go's nil `*Options`) uses [`DEFAULT_QUALITY`].
///
/// Like Go, the output goes through a 4096-byte buffer and the first write
/// error is returned.
pub fn encode(w: impl Write, m: &dyn Image, o: Option<&Options>) -> io::Result<()> {
    let b = m.bounds();
    if b.dx() >= 1 << 16 || b.dy() >= 1 << 16 {
        return Err(io::Error::other("jpeg: image is too large to encode"));
    }
    // Clip quality to [1, 100].
    let mut quality = DEFAULT_QUALITY;
    if let Some(o) = o {
        quality = o.quality.clamp(1, 100);
    }
    // Convert from a quality rating to a scaling factor.
    let scale = if quality < 50 {
        5000 / quality
    } else {
        200 - quality * 2
    };
    // Initialize the quantization tables.
    let mut quant = [[0u8; BLOCK_SIZE]; N_QUANT_INDEX];
    for i in 0..N_QUANT_INDEX {
        for j in 0..BLOCK_SIZE {
            let x = (i32::from(UNSCALED_QUANT[i][j]) * scale + 50) / 100;
            quant[i][j] = x.clamp(1, 255) as u8;
        }
    }
    // The number of components depends on the input image type.
    let n_component = if m.as_any().is_some_and(|a| a.is::<Gray>()) {
        1
    } else {
        3
    };
    let mut e = Encoder {
        w: BufWriter {
            w,
            buf: Vec::with_capacity(BUF_SIZE),
            err: None,
        },
        bits: 0,
        n_bits: 0,
        quant,
        huffman_lut: std::array::from_fn(|i| huffman_lut(&THE_HUFFMAN_SPEC[i])),
    };
    // Start Of Image, quantization tables, image dimensions, Huffman tables,
    // image data and End Of Image.
    e.w.write(&[0xff, 0xd8]);
    e.write_dqt();
    e.write_sof0(b.size(), n_component);
    e.write_dht(n_component);
    e.write_sos(m);
    e.w.write(&[0xff, 0xd9]);
    e.w.flush();
    match e.w.err.take() {
        Some(error) => Err(error),
        None => Ok(()),
    }
}
