// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the NOTICE file.
//
// Ported from $GOROOT/src/internal/chacha8rand/{chacha8,chacha8_generic}.go
// and $GOROOT/src/math/rand/v2/chacha8.go. See Go's C2SP specification
// https://c2sp.org/chacha8rand for the construction.

use super::{Source, UnmarshalError};
use std::io;

const CTR_INC: u32 = 4; // counter increment between block calls
const CTR_MAX: u32 = 16; // reseed when the counter reaches 16
const CHUNK: u32 = 32; // each block call produces 32 u64 values
const RESEED: usize = 4; // reseed with the last 4 words

/// Go's `internal/chacha8rand.State`.
#[derive(Clone, PartialEq, Eq)]
struct State {
    buf: [u64; 32],
    seed: [u64; 4],
    i: u32,
    n: u32,
    c: u32,
}

/// One ChaCha8 quarter round.
fn qr(mut a: u32, mut b: u32, mut c: u32, mut d: u32) -> (u32, u32, u32, u32) {
    a = a.wrapping_add(b);
    d ^= a;
    d = d.rotate_left(16);
    c = c.wrapping_add(d);
    b ^= c;
    b = b.rotate_left(12);
    a = a.wrapping_add(b);
    d ^= a;
    d = d.rotate_left(8);
    c = c.wrapping_add(d);
    b ^= c;
    b = b.rotate_left(7);
    (a, b, c, d)
}

/// Go's `block_generic`: four interleaved ChaCha8 blocks with counters
/// `counter..counter+4`. Only the key rows receive the feed-forward addition;
/// Go's layout stores word `k` of block `i` at u32 index `4k+i`, and the
/// output u64s are the little-endian pairs of that u32 array.
// Lane-indexed loops keep the `b[word][lane]` layout identical to Go's.
#[allow(clippy::needless_range_loop)]
fn block(seed: &[u64; 4], counter: u32) -> [u64; 32] {
    let mut b = [[0u32; 4]; 16];
    for i in 0..4 {
        b[0][i] = 0x61707865;
        b[1][i] = 0x3320646e;
        b[2][i] = 0x79622d32;
        b[3][i] = 0x6b206574;
        for (k, word) in seed.iter().enumerate() {
            b[4 + 2 * k][i] = *word as u32;
            b[5 + 2 * k][i] = (*word >> 32) as u32;
        }
        b[12][i] = counter.wrapping_add(i as u32);
    }
    for i in 0..4 {
        let mut x = [0u32; 16];
        for (k, word) in x.iter_mut().enumerate() {
            *word = b[k][i];
        }
        for _ in 0..4 {
            (x[0], x[4], x[8], x[12]) = qr(x[0], x[4], x[8], x[12]);
            (x[1], x[5], x[9], x[13]) = qr(x[1], x[5], x[9], x[13]);
            (x[2], x[6], x[10], x[14]) = qr(x[2], x[6], x[10], x[14]);
            (x[3], x[7], x[11], x[15]) = qr(x[3], x[7], x[11], x[15]);

            (x[0], x[5], x[10], x[15]) = qr(x[0], x[5], x[10], x[15]);
            (x[1], x[6], x[11], x[12]) = qr(x[1], x[6], x[11], x[12]);
            (x[2], x[7], x[8], x[13]) = qr(x[2], x[7], x[8], x[13]);
            (x[3], x[4], x[9], x[14]) = qr(x[3], x[4], x[9], x[14]);
        }
        for (k, word) in x.iter().enumerate() {
            if (4..12).contains(&k) {
                b[k][i] = b[k][i].wrapping_add(*word);
            } else {
                b[k][i] = *word;
            }
        }
    }
    let mut buf = [0u64; 32];
    for (k, row) in b.iter().enumerate() {
        buf[2 * k] = u64::from(row[0]) | (u64::from(row[1]) << 32);
        buf[2 * k + 1] = u64::from(row[2]) | (u64::from(row[3]) << 32);
    }
    buf
}

impl State {
    fn new(seed: [u64; 4]) -> Self {
        Self {
            buf: block(&seed, 0),
            seed,
            i: 0,
            n: CHUNK,
            c: 0,
        }
    }

    fn next(&mut self) -> Option<u64> {
        if self.i >= self.n {
            return None;
        }
        let value = self.buf[(self.i & 31) as usize];
        self.i += 1;
        Some(value)
    }

    fn refill(&mut self) {
        self.c += CTR_INC;
        if self.c == CTR_MAX {
            self.seed.copy_from_slice(&self.buf[32 - RESEED..]);
            self.c = 0;
        }
        self.buf = block(&self.seed, self.c);
        self.i = 0;
        self.n = CHUNK;
        if self.c == CTR_MAX - CTR_INC {
            self.n = CHUNK - RESEED as u32;
        }
    }

    fn marshal(&self) -> [u8; 48] {
        let mut data = [0u8; 48];
        data[..8].copy_from_slice(b"chacha8:");
        let used = (self.c / CTR_INC) * CHUNK + self.i;
        data[8..16].copy_from_slice(&u64::from(used).to_be_bytes());
        for (i, seed) in self.seed.iter().enumerate() {
            data[16 + 8 * i..24 + 8 * i].copy_from_slice(&seed.to_le_bytes());
        }
        data
    }

    fn unmarshal(data: &[u8]) -> Result<Self, UnmarshalError> {
        const INVALID: UnmarshalError = UnmarshalError("invalid ChaCha8 encoding");
        if data.len() != 48 || &data[..8] != b"chacha8:" {
            return Err(INVALID);
        }
        let used = u64::from_be_bytes(data[8..16].try_into().expect("8-byte slice"));
        if used > u64::from((CTR_MAX / CTR_INC) * CHUNK) - RESEED as u64 {
            return Err(INVALID);
        }
        let used = used as u32;
        let mut seed = [0u64; 4];
        for (i, word) in seed.iter_mut().enumerate() {
            *word = u64::from_le_bytes(
                data[16 + 8 * i..24 + 8 * i]
                    .try_into()
                    .expect("8-byte slice"),
            );
        }
        let c = CTR_INC * (used / CHUNK);
        Ok(Self {
            buf: block(&seed, c),
            seed,
            i: used % CHUNK,
            n: if c == CTR_MAX - CTR_INC {
                CHUNK - RESEED as u32
            } else {
                CHUNK
            },
            c,
        })
    }
}

/// Go's `rand.ChaCha8`: the ChaCha8-based generator that also backs Go's
/// runtime randomness, with reseeding every 16 blocks for forward secrecy.
///
/// The same seed produces the same `uint64` and [`io::Read`] streams as Go's
/// `rand.NewChaCha8`. Go describes ChaCha8 as cryptographically strong, but
/// this crate makes no security claim for it; use a reviewed crypto/rand
/// backend for keys and tokens.
#[derive(Clone, PartialEq, Eq)]
pub struct ChaCha8 {
    state: State,
    read_buf: [u8; 8],
    read_len: usize,
}

impl std::fmt::Debug for ChaCha8 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print generator state; it predicts all future output.
        f.debug_struct("ChaCha8").finish_non_exhaustive()
    }
}

impl ChaCha8 {
    /// Equivalent to Go's `rand.NewChaCha8(seed)`.
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            state: State::new(seed_words(&seed)),
            read_buf: [0; 8],
            read_len: 0,
        }
    }

    /// Reset the generator as if freshly created by `ChaCha8::new(seed)`.
    pub fn seed(&mut self, seed: [u8; 32]) {
        *self = Self::new(seed);
    }

    /// Append Go's binary encoding: an optional `"readbuf:"` record holding
    /// unread [`io::Read`] bytes, then `"chacha8:"`, the big-endian count of
    /// values used in the current 16-block cycle, and the little-endian seed.
    pub fn append_binary(&self, mut out: Vec<u8>) -> Vec<u8> {
        if self.read_len > 0 {
            out.extend_from_slice(b"readbuf:");
            out.push(self.read_len as u8);
            out.extend_from_slice(&self.read_buf[8 - self.read_len..]);
        }
        out.extend_from_slice(&self.state.marshal());
        out
    }

    /// Go's `MarshalBinary`.
    pub fn marshal_binary(&self) -> Vec<u8> {
        self.append_binary(Vec::with_capacity(64))
    }

    /// Go's `UnmarshalBinary`.
    ///
    /// As in Go, an encoding without a `"readbuf:"` record leaves any pending
    /// read bytes in place. Go panics on a read buffer longer than 8 bytes;
    /// this returns an error instead. On any error the generator is unchanged.
    pub fn unmarshal_binary(&mut self, data: &[u8]) -> Result<(), UnmarshalError> {
        let mut read = None;
        let mut data = data;
        if let Some(rest) = data.strip_prefix(b"readbuf:".as_slice()) {
            const INVALID: UnmarshalError = UnmarshalError("invalid ChaCha8 Read buffer encoding");
            let (&len, rest) = rest.split_first().ok_or(INVALID)?;
            let len = usize::from(len);
            if rest.len() < len || len > 8 {
                return Err(INVALID);
            }
            read = Some(&rest[..len]);
            data = &rest[len..];
        }
        let state = State::unmarshal(data)?;
        if let Some(pending) = read {
            self.read_buf[8 - pending.len()..].copy_from_slice(pending);
            self.read_len = pending.len();
        }
        self.state = state;
        Ok(())
    }
}

fn seed_words(seed: &[u8; 32]) -> [u64; 4] {
    let mut words = [0u64; 4];
    for (i, word) in words.iter_mut().enumerate() {
        *word = u64::from_le_bytes(seed[8 * i..8 * i + 8].try_into().expect("8-byte slice"));
    }
    words
}

impl Source for ChaCha8 {
    fn uint64(&mut self) -> u64 {
        loop {
            if let Some(value) = self.state.next() {
                return value;
            }
            self.state.refill();
        }
    }
}

/// Go's `ChaCha8.Read`: fills the buffer with little-endian `uint64` output,
/// keeping unread bytes of a partial word for the next call. Never fails.
impl io::Read for ChaCha8 {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut n = 0;
        let mut p = out;
        if self.read_len > 0 {
            let start = 8 - self.read_len;
            let take = self.read_len.min(p.len());
            p[..take].copy_from_slice(&self.read_buf[start..start + take]);
            self.read_len -= take;
            n = take;
            p = &mut p[take..];
        }
        while p.len() >= 8 {
            let value = self.uint64();
            p[..8].copy_from_slice(&value.to_le_bytes());
            p = &mut p[8..];
            n += 8;
        }
        if !p.is_empty() {
            self.read_buf = self.uint64().to_le_bytes();
            let len = p.len();
            p.copy_from_slice(&self.read_buf[..len]);
            n += len;
            self.read_len = 8 - len;
        }
        Ok(n)
    }
}
