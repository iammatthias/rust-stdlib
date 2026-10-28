//! Scan decoding and image reconstruction (Go's `scan.go`).
use std::io::Read;

use super::dct::{idct, Block, BLOCK_SIZE};
use super::reader::{
    alloc_block_vec, Bits, Decoder, Error, Result, MAX_COMPONENTS, RST0_MARKER, RST7_MARKER, UNZIG,
};
use crate::image::Pix;

#[derive(Clone, Copy, Default)]
struct ScanComponent {
    comp_index: usize,
    /// DC table selector.
    td: usize,
    /// AC table selector.
    ta: usize,
}

const DC_TABLE: usize = 0;
const AC_TABLE: usize = 1;

impl<R: Read> Decoder<R> {
    /// Start of scan, section B.2.3.
    pub fn process_sos(&mut self, n: usize) -> Result<()> {
        if self.n_comp == 0 {
            return Err(Error::Format("missing SOF marker"));
        }
        if n < 6 || 4 + 2 * self.n_comp < n || !n.is_multiple_of(2) {
            return Err(Error::Format("SOS has wrong length"));
        }
        self.read_tmp(0, n)?;
        let n_comp = usize::from(self.tmp[0]);
        if n != 4 + 2 * n_comp {
            return Err(Error::Format(
                "SOS length inconsistent with number of components",
            ));
        }
        let mut scan = [ScanComponent::default(); MAX_COMPONENTS];
        let mut total_hv = 0;
        for i in 0..n_comp {
            let cs = self.tmp[1 + 2 * i]; // Component selector.
            let mut comp_index = None;
            for (j, comp) in self.comp[..self.n_comp].iter().enumerate() {
                if cs == comp.c {
                    comp_index = Some(j);
                }
            }
            let Some(comp_index) = comp_index else {
                return Err(Error::Format("unknown component selector"));
            };
            scan[i].comp_index = comp_index;
            // Frame component identifiers are unique, so unique indexes are
            // enough to check the scan's selectors are.
            for j in 0..i {
                if scan[i].comp_index == scan[j].comp_index {
                    return Err(Error::Format("repeated component selector"));
                }
            }
            total_hv += self.comp[comp_index].h * self.comp[comp_index].v;

            // The baseline t <= 1 restriction is in table B.3.
            scan[i].td = usize::from(self.tmp[2 + 2 * i] >> 4);
            if scan[i].td > 3 || (self.baseline && scan[i].td > 1) {
                return Err(Error::Format("bad Td value"));
            }
            scan[i].ta = usize::from(self.tmp[2 + 2 * i] & 0x0f);
            if scan[i].ta > 3 || (self.baseline && scan[i].ta > 1) {
                return Err(Error::Format("bad Ta value"));
            }
        }
        // With more than one component, the scan's total H*V must be <= 10.
        if self.n_comp > 1 && total_hv > 10 {
            return Err(Error::Format("total sampling factors too large"));
        }

        // The spectral selection bounds (Ss, Se) and the successive
        // approximation values (Ah, Al); fixed for sequential JPEGs.
        let (mut zig_start, mut zig_end, mut ah, mut al) =
            (0i32, BLOCK_SIZE as i32 - 1, 0u32, 0u32);
        if self.progressive {
            zig_start = i32::from(self.tmp[1 + 2 * n_comp]);
            zig_end = i32::from(self.tmp[2 + 2 * n_comp]);
            ah = u32::from(self.tmp[3 + 2 * n_comp] >> 4);
            al = u32::from(self.tmp[3 + 2 * n_comp] & 0x0f);
            if (zig_start == 0 && zig_end != 0)
                || zig_start > zig_end
                || BLOCK_SIZE as i32 <= zig_end
            {
                return Err(Error::Format("bad spectral selection bounds"));
            }
            if zig_start != 0 && n_comp != 1 {
                return Err(Error::Format(
                    "progressive AC coefficients for more than one component",
                ));
            }
            if ah != 0 && ah != al + 1 {
                return Err(Error::Format("bad successive approximation values"));
            }
        }

        // The number of MCUs, based on the maximum sampling factors.
        let (max_h, max_v) = (self.max_h as usize, self.max_v as usize);
        let mxx = (self.width as usize).div_ceil(8 * max_h);
        let myy = (self.height as usize).div_ceil(8 * max_v);
        if self.img1.is_none() && self.img3.is_none() {
            self.make_img(mxx, myy)?;
        }
        if self.progressive {
            for item in scan.iter().take(n_comp) {
                let ci = item.comp_index;
                if self.prog_coeffs[ci].is_none() {
                    let blocks = mxx * myy * self.comp[ci].h as usize * self.comp[ci].v as usize;
                    self.prog_coeffs[ci] = Some(alloc_block_vec(blocks)?);
                }
            }
        }

        self.bits = Bits::default();
        let (mut mcu, mut expected_rst) = (0usize, RST0_MARKER);
        // b holds the decoded coefficients, in natural order.
        let mut b: Block;
        let mut dc = [0i32; MAX_COMPONENTS];
        let mut block_count = 0usize;
        for my in 0..myy {
            for mx in 0..mxx {
                for item in scan.iter().take(n_comp) {
                    let comp_index = item.comp_index;
                    let hi = self.comp[comp_index].h as usize;
                    let vi = self.comp[comp_index].v as usize;
                    for j in 0..hi * vi {
                        // Blocks are visited one MCU at a time. Interleaved
                        // scans follow the MCU layout; non-interleaved scans
                        // go left to right, top to bottom, with no data for
                        // blocks inside the MCU grid but outside the image.
                        let (bx, by);
                        if n_comp != 1 {
                            bx = hi * mx + j % hi;
                            by = vi * my + j / hi;
                        } else {
                            let q = mxx * hi;
                            bx = block_count % q;
                            by = block_count / q;
                            block_count += 1;
                            if bx * 8 >= self.width as usize || by * 8 >= self.height as usize {
                                continue;
                            }
                        }

                        // Load the previous partially decoded coefficients.
                        if self.progressive {
                            b = match self.prog_coeffs[comp_index].as_ref() {
                                Some(blocks) => blocks[by * mxx * hi + bx],
                                None => [0; BLOCK_SIZE],
                            };
                        } else {
                            b = [0; BLOCK_SIZE];
                        }

                        if ah != 0 {
                            self.refine(&mut b, (AC_TABLE, item.ta), zig_start, zig_end, 1 << al)?;
                        } else {
                            let mut zig = zig_start;
                            if zig == 0 {
                                zig += 1;
                                // The DC coefficient, section F.2.2.1.
                                let value = self.decode_huffman((DC_TABLE, item.td))?;
                                if value > 16 {
                                    return Err(Error::Unsupported("excessive DC component"));
                                }
                                let dc_delta = self.receive_extend(value)?;
                                dc[comp_index] = dc[comp_index].wrapping_add(dc_delta);
                                b[0] = dc[comp_index].wrapping_shl(al);
                            }

                            if zig <= zig_end && self.eob_run > 0 {
                                self.eob_run -= 1;
                            } else {
                                // The AC coefficients, section F.2.2.2.
                                while zig <= zig_end {
                                    let value = self.decode_huffman((AC_TABLE, item.ta))?;
                                    let val0 = value >> 4;
                                    let val1 = value & 0x0f;
                                    if val1 != 0 {
                                        zig += i32::from(val0);
                                        if zig > zig_end {
                                            break;
                                        }
                                        let ac = self.receive_extend(val1)?;
                                        b[UNZIG[zig as usize]] = ac.wrapping_shl(al);
                                    } else {
                                        if val0 != 0x0f {
                                            self.eob_run = 1u16 << val0;
                                            if val0 != 0 {
                                                let bits = self.decode_bits(i32::from(val0))?;
                                                self.eob_run |= bits as u16;
                                            }
                                            self.eob_run -= 1;
                                            break;
                                        }
                                        zig += 0x0f;
                                    }
                                    zig += 1;
                                }
                            }
                        }

                        if self.progressive {
                            // Save the coefficients; the image is
                            // reconstructed after all scans are processed.
                            if let Some(blocks) = self.prog_coeffs[comp_index].as_mut() {
                                blocks[by * mxx * hi + bx] = b;
                            }
                            continue;
                        }
                        self.reconstruct_block(&mut b, bx, by, comp_index)?;
                    }
                }
                mcu += 1;
                if self.ri > 0 && mcu % self.ri as usize == 0 && mcu < mxx * myy {
                    // For well-formed input the RST marker follows
                    // immediately; for corrupt input try to resynchronize.
                    self.read_tmp(0, 2)?;
                    if self.tmp[0] != 0xff || self.tmp[1] != expected_rst {
                        self.find_rst(expected_rst)?;
                    }
                    expected_rst += 1;
                    if expected_rst == RST7_MARKER + 1 {
                        expected_rst = RST0_MARKER;
                    }
                    // Reset the Huffman decoder, the DC predictors (section
                    // F.2.1.3.1) and the progressive state (section G.1.2.2).
                    self.bits = Bits::default();
                    dc = [0; MAX_COMPONENTS];
                    self.eob_run = 0;
                }
            }
        }
        Ok(())
    }

    /// A successive approximation refinement block, section G.1.2.
    fn refine(
        &mut self,
        b: &mut Block,
        table: (usize, usize),
        zig_start: i32,
        zig_end: i32,
        delta: i32,
    ) -> Result<()> {
        // Refining a DC component is trivial.
        if zig_start == 0 {
            let bit = self.decode_bit()?;
            if bit {
                b[0] |= delta;
            }
            return Ok(());
        }

        // Refining AC components, sections G.1.2.2 and G.1.2.3.
        let mut zig = zig_start;
        if self.eob_run == 0 {
            while zig <= zig_end {
                let mut z = 0i32;
                let value = self.decode_huffman(table)?;
                let val0 = value >> 4;
                let val1 = value & 0x0f;

                match val1 {
                    0 => {
                        if val0 != 0x0f {
                            self.eob_run = 1u16 << val0;
                            if val0 != 0 {
                                let bits = self.decode_bits(i32::from(val0))?;
                                self.eob_run |= bits as u16;
                            }
                            break;
                        }
                    }
                    1 => {
                        z = delta;
                        let bit = self.decode_bit()?;
                        if !bit {
                            z = -z;
                        }
                    }
                    _ => return Err(Error::Format("unexpected Huffman code")),
                }

                zig = self.refine_non_zeroes(b, zig, zig_end, i32::from(val0), delta)?;
                if zig > zig_end {
                    return Err(Error::Format("too many coefficients"));
                }
                if z != 0 {
                    b[UNZIG[zig as usize]] = z;
                }
                zig += 1;
            }
        }
        if self.eob_run > 0 {
            self.eob_run -= 1;
            self.refine_non_zeroes(b, zig, zig_end, -1, delta)?;
        }
        Ok(())
    }

    /// Refines the non-zero entries of `b` in zig-zag order. If `nz >= 0`, the
    /// first `nz` zero entries are skipped over.
    fn refine_non_zeroes(
        &mut self,
        b: &mut Block,
        mut zig: i32,
        zig_end: i32,
        mut nz: i32,
        delta: i32,
    ) -> Result<i32> {
        while zig <= zig_end {
            let u = UNZIG[zig as usize];
            if b[u] == 0 {
                if nz == 0 {
                    break;
                }
                nz -= 1;
                zig += 1;
                continue;
            }
            let bit = self.decode_bit()?;
            if bit {
                if b[u] >= 0 {
                    b[u] = b[u].wrapping_add(delta);
                } else {
                    b[u] = b[u].wrapping_sub(delta);
                }
            }
            zig += 1;
        }
        Ok(zig)
    }

    pub fn reconstruct_progressive_image(&mut self) -> Result<()> {
        let (max_h, max_v) = (self.max_h as usize, self.max_v as usize);
        let mxx = (self.width as usize).div_ceil(8 * max_h);
        for i in 0..self.n_comp {
            let Some(mut blocks) = self.prog_coeffs[i].take() else {
                continue;
            };
            let v = 8 * max_v / self.comp[i].v as usize;
            let h = 8 * max_h / self.comp[i].h as usize;
            let stride = mxx * self.comp[i].h as usize;
            let mut by = 0;
            while by * v < self.height as usize {
                let mut bx = 0;
                while bx * h < self.width as usize {
                    self.reconstruct_block(&mut blocks[by * stride + bx], bx, by, i)?;
                    bx += 1;
                }
                by += 1;
            }
            self.prog_coeffs[i] = Some(blocks);
        }
        Ok(())
    }

    /// Dequantizes, performs the inverse DCT and stores the block in the image.
    fn reconstruct_block(
        &mut self,
        b: &mut Block,
        bx: usize,
        by: usize,
        comp_index: usize,
    ) -> Result<()> {
        let qt = &self.quant[usize::from(self.comp[comp_index].tq)];
        for zig in 0..BLOCK_SIZE {
            b[UNZIG[zig]] = b[UNZIG[zig]].wrapping_mul(qt[zig]);
        }
        idct(b);

        let (mut bx, mut by) = (bx, by);
        let (mut h, mut v) = (1usize, 1usize);
        if self.flex {
            // Scale bx and by by the component's sampling factors.
            h = self.comp[comp_index].expand_h as usize;
            v = self.comp[comp_index].expand_v as usize;
            bx *= h;
            by *= v;
        }

        let (pix, stride): (&mut Pix, usize) = if self.n_comp == 1 {
            match self.img1.as_mut() {
                Some(img) => (&mut img.pix, img.stride),
                None => return Err(Error::Format("missing SOS marker")),
            }
        } else {
            match (comp_index, self.img3.as_mut()) {
                (0, Some(img)) => (&mut img.y, img.y_stride),
                (1, Some(img)) => (&mut img.cb, img.c_stride),
                (2, Some(img)) => (&mut img.cr, img.c_stride),
                (3, _) => match self.black_pix.as_mut() {
                    Some(pix) => (pix, self.black_stride),
                    None => return Err(Error::Format("missing SOS marker")),
                },
                (_, Some(_)) => return Err(Error::Unsupported("too many components")),
                (_, None) => return Err(Error::Format("missing SOS marker")),
            }
        };
        let offset = 8 * (by * stride + bx);
        let flex = self.flex;
        let level = |v: i32| v.wrapping_add(128).clamp(0, 255) as u8;
        pix.with_mut(|dst| {
            // Go panics when a block falls outside the plane; reject instead.
            if offset > dst.len() {
                return Err(Error::Format("bad block position"));
            }
            let dst = &mut dst[offset..];
            if flex {
                // Expand each source pixel to h by v destination pixels.
                if dst.len() < (8 * v - 1) * stride + 8 * h {
                    return Err(Error::Format("bad block position"));
                }
                for y in 0..8 {
                    for x in 0..8 {
                        let val = level(b[y * 8 + x]);
                        for yy in 0..v {
                            for xx in 0..h {
                                dst[(y * v + yy) * stride + x * h + xx] = val;
                            }
                        }
                    }
                }
                return Ok(());
            }

            if dst.len() < 7 * stride + 8 {
                return Err(Error::Format("bad block position"));
            }
            for y in 0..8 {
                for x in 0..8 {
                    dst[y * stride + x] = level(b[y * 8 + x]);
                }
            }
            Ok(())
        })
    }

    /// Advances past the next RST marker that matches `expected_rst`. Other
    /// than I/O errors, it is an error to meet `{0xFF, M}` where M is not
    /// 0x00, 0xFF or the expected marker.
    ///
    /// Precondition: `tmp[..2]` holds the next two input bytes.
    fn find_rst(&mut self, expected_rst: u8) -> Result<()> {
        loop {
            // After this iteration `tmp[..2]` again holds the next two bytes:
            // i is 0 or 1, so each iteration advances by 2 or 1 bytes.
            let mut i = 0;

            if self.tmp[0] == 0xff {
                if self.tmp[1] == expected_rst {
                    return Ok(());
                } else if self.tmp[1] == 0xff {
                    i = 1;
                } else if self.tmp[1] != 0x00 {
                    // libjpeg treats nearby RST markers specially; any other
                    // marker is simply fatal here.
                    return Err(Error::Format("bad RST marker"));
                }
            } else if self.tmp[1] == 0xff {
                self.tmp[0] = 0xff;
                i = 1;
            }

            self.read_tmp(i, 2)?;
        }
    }
}
