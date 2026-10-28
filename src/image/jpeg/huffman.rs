//! Huffman decoding (Go's `huffman.go`).
use std::io::Read;

use super::reader::{
    Decoder, Error, Result, ERR_MISSING_FF00, ERR_SHORT_HUFFMAN_DATA, MAX_TC, MAX_TH,
};

/// Maximum (inclusive) number of bits in a Huffman code.
const MAX_CODE_LENGTH: usize = 16;
/// Maximum (inclusive) number of codes in a Huffman tree.
const MAX_N_CODES: usize = 256;
/// Log-2 size of the look-up table.
const LUT_SIZE: u32 = 8;

/// A Huffman decoder, section C.
#[derive(Clone)]
pub(super) struct Huffman {
    /// Number of codes in the tree.
    pub n_codes: i32,
    /// Look-up table for the next `LUT_SIZE` bits: the high 8 bits are the
    /// decoded value, the low 8 bits are 1 plus the code length, or 0 if the
    /// code is too long for the table.
    lut: [u16; 1 << LUT_SIZE],
    /// Decoded values, sorted by their encoding.
    vals: [u8; MAX_N_CODES],
    /// Minimum code of each length, or -1 if there is none.
    min_codes: [i32; MAX_CODE_LENGTH],
    /// Maximum code of each length, or -1 if there is none.
    max_codes: [i32; MAX_CODE_LENGTH],
    /// Index into `vals` of `min_codes[i]`.
    vals_indices: [i32; MAX_CODE_LENGTH],
}

impl Default for Huffman {
    fn default() -> Self {
        Huffman {
            n_codes: 0,
            lut: [0; 1 << LUT_SIZE],
            vals: [0; MAX_N_CODES],
            min_codes: [0; MAX_CODE_LENGTH],
            max_codes: [0; MAX_CODE_LENGTH],
            vals_indices: [0; MAX_CODE_LENGTH],
        }
    }
}

impl<R: Read> Decoder<R> {
    /// Reads bytes until `bits.n` is at least `n`. Callers check `bits.n < n`
    /// first.
    pub fn ensure_n_bits(&mut self, n: i32) -> Result<()> {
        loop {
            let c = match self.read_byte_stuffed_byte() {
                Ok(c) => c,
                Err(Error::UnexpectedEof) => return Err(Error::Format(ERR_SHORT_HUFFMAN_DATA)),
                Err(error) => return Err(error),
            };
            self.bits.a = (self.bits.a << 8) | u32::from(c);
            self.bits.n += 8;
            if self.bits.m == 0 {
                self.bits.m = 1 << 7;
            } else {
                self.bits.m <<= 8;
            }
            if self.bits.n >= n {
                return Ok(());
            }
        }
    }

    /// RECEIVE and EXTEND, section F.2.2.1: the signed integer encoded in `t`
    /// bits, where `t <= 16`.
    pub fn receive_extend(&mut self, t: u8) -> Result<i32> {
        if self.bits.n < i32::from(t) {
            self.ensure_n_bits(i32::from(t))?;
        }
        self.bits.n -= i32::from(t);
        self.bits.m >>= t;
        if t == 0 {
            return Ok(0);
        }
        let s = 1i32 << t;
        let mut x = ((self.bits.a >> self.bits.n as u32) as i32) & (s - 1);
        // Branchless equivalent of: if x < s>>1 { x += ((-1) << t) + 1 }.
        let sign = (x >> (t - 1)) - 1;
        x += sign & ((-1i32 << t) + 1);
        Ok(x)
    }

    /// Define Huffman table, section B.2.4.2.
    pub fn process_dht(&mut self, mut n: usize) -> Result<()> {
        while n > 0 {
            if n < 17 {
                return Err(Error::Format("DHT has wrong length"));
            }
            self.read_tmp(0, 17)?;
            let tc = self.tmp[0] >> 4;
            if tc > MAX_TC {
                return Err(Error::Format("bad Tc value"));
            }
            let th = self.tmp[0] & 0x0f;
            // The baseline th <= 1 restriction is in table B.5.
            if th > MAX_TH || (self.baseline && th > 1) {
                return Err(Error::Format("bad Th value"));
            }

            // n_codes[i] is the number of codes with code length i+1.
            let mut counts = [0i32; MAX_CODE_LENGTH];
            let mut total = 0i32;
            for (count, &byte) in counts.iter_mut().zip(&self.tmp[1..]) {
                *count = i32::from(byte);
                total += *count;
            }
            self.huff[usize::from(tc)][usize::from(th)].n_codes = total;
            if total == 0 {
                return Err(Error::Format("Huffman table has zero length"));
            }
            if total > MAX_N_CODES as i32 {
                return Err(Error::Format("Huffman table has excessive length"));
            }
            let remaining = n as i64 - i64::from(total) - 17;
            if remaining < 0 {
                return Err(Error::Format("DHT has wrong length"));
            }
            n = remaining as usize;
            let mut vals = [0u8; MAX_N_CODES];
            self.read_full(&mut vals[..total as usize])?;

            let h = &mut self.huff[usize::from(tc)][usize::from(th)];
            h.vals = vals;

            // Derive the look-up table.
            h.lut = [0; 1 << LUT_SIZE];
            let (mut x, mut code) = (0usize, 0u32);
            for i in 0..LUT_SIZE {
                code <<= 1;
                for _ in 0..counts[i as usize] {
                    // The code length is 1+i, so shift by 8-(1+i) to get the
                    // high bits of every 8-bit sequence that starts with it.
                    let base = (code << (7 - i)) as u8;
                    let lut_value = (u16::from(h.vals[x]) << 8) | (2 + i) as u16;
                    for k in 0..(1u32 << (7 - i)) {
                        h.lut[usize::from(base | k as u8)] = lut_value;
                    }
                    code += 1;
                    x += 1;
                }
            }

            // Derive min_codes, max_codes and vals_indices.
            let (mut c, mut index) = (0i32, 0i32);
            for (i, &count) in counts.iter().enumerate() {
                if count == 0 {
                    h.min_codes[i] = -1;
                    h.max_codes[i] = -1;
                    h.vals_indices[i] = -1;
                } else {
                    h.min_codes[i] = c;
                    h.max_codes[i] = c + count - 1;
                    h.vals_indices[i] = index;
                    c += count;
                    index += count;
                }
                c <<= 1;
            }
        }
        Ok(())
    }

    /// The next Huffman-coded value from the bit stream. `table` is the
    /// `(tc, th)` index of the table in `huff`.
    pub fn decode_huffman(&mut self, table: (usize, usize)) -> Result<u8> {
        if self.huff[table.0][table.1].n_codes == 0 {
            return Err(Error::Format("uninitialized Huffman table"));
        }

        let mut slow = false;
        if self.bits.n < 8 {
            if let Err(error) = self.ensure_n_bits(8) {
                match error {
                    Error::Format(m) if m == ERR_MISSING_FF00 || m == ERR_SHORT_HUFFMAN_DATA => {}
                    other => return Err(other),
                }
                // No more bytes in this segment, but the next symbol may still
                // be in the bits already read. Undo the read_byte first.
                if self.n_unreadable != 0 {
                    self.unread_byte_stuffed_byte();
                }
                slow = true;
            }
        }
        if !slow {
            let h = &self.huff[table.0][table.1];
            let v = h.lut[((self.bits.a >> (self.bits.n as u32 - LUT_SIZE)) & 0xff) as usize];
            if v != 0 {
                let n = i32::from(v & 0xff) - 1;
                self.bits.n -= n;
                self.bits.m >>= n as u32;
                return Ok((v >> 8) as u8);
            }
        }

        let mut code = 0i32;
        for i in 0..MAX_CODE_LENGTH {
            if self.bits.n == 0 {
                self.ensure_n_bits(1)?;
            }
            if self.bits.a & self.bits.m != 0 {
                code |= 1;
            }
            self.bits.n -= 1;
            self.bits.m >>= 1;
            let h = &self.huff[table.0][table.1];
            if code <= h.max_codes[i] {
                // Go indexes out of range (and panics) on some malformed
                // tables; report them as a bad code instead.
                let index = h.vals_indices[i] + code - h.min_codes[i];
                return usize::try_from(index)
                    .ok()
                    .and_then(|index| h.vals.get(index))
                    .copied()
                    .ok_or(Error::Format("bad Huffman code"));
            }
            code <<= 1;
        }
        Err(Error::Format("bad Huffman code"))
    }

    pub fn decode_bit(&mut self) -> Result<bool> {
        if self.bits.n == 0 {
            self.ensure_n_bits(1)?;
        }
        let ret = self.bits.a & self.bits.m != 0;
        self.bits.n -= 1;
        self.bits.m >>= 1;
        Ok(ret)
    }

    pub fn decode_bits(&mut self, n: i32) -> Result<u32> {
        if self.bits.n < n {
            self.ensure_n_bits(n)?;
        }
        let mut ret = self.bits.a >> (self.bits.n - n) as u32;
        ret &= (1 << n as u32) - 1;
        self.bits.n -= n;
        self.bits.m >>= n as u32;
        Ok(ret)
    }
}
