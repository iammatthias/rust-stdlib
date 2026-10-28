//! Go's `index/suffixarray`: substring search in logarithmic time using an
//! in-memory suffix array.
//!
//! ```
//! use rust_stdlib::index::suffixarray::Index;
//!
//! let index = Index::new(b"banana");
//! let mut offsets = index.lookup(b"an", -1);
//! offsets.sort_unstable();
//! assert_eq!(offsets, [1, 3]);
//!
//! let mut serialized = Vec::new();
//! index.write(&mut serialized)?;
//! let mut restored = Index::default();
//! restored.read(&mut serialized.as_slice())?;
//! assert_eq!(restored.bytes(), b"banana");
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! The suffix array of a text is unique, so any correct construction gives
//! Go's array; this module builds it by prefix doubling rather than porting
//! Go's SA-IS. The serialized form follows Go's byte layout, including the
//! 10-byte size slots whose unused bytes keep earlier contents, as Go's
//! writer does.

use crate::encoding::binary;
use crate::io::Error as IoError;
use crate::regexp::Regexp;
use std::io::{self, ErrorKind, Read, Write};

const MAX_VARINT_LEN64: usize = 10;
/// Go's bufSize: the buffer for all reads and writes of the serialized form.
const BUF_SIZE: usize = 16 << 10;
/// Upper bound of one allocation while reading the data, so a corrupt length
/// cannot allocate more than the input provides.
const READ_CHUNK: usize = 64 << 10;

/// An index for fast substring search over a byte string.
///
/// Go's `New` keeps the caller's slice; this index owns a copy of the data.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Index {
    data: Vec<u8>,
    // Suffix array for data; sa.len() == data.len().
    sa: Vec<usize>,
}

/// Builds the suffix array of `data` by prefix doubling.
fn suffix_array(data: &[u8]) -> Vec<usize> {
    let n = data.len();
    if n == 0 {
        return Vec::new();
    }
    let mut sa: Vec<usize> = (0..n).collect();
    let mut rank: Vec<usize> = data.iter().map(|&b| usize::from(b)).collect();
    let mut next = vec![0; n];
    sa.sort_by_key(|&i| rank[i]);
    let mut k = 1;
    loop {
        // Suffixes are ordered by their first 2k bytes: the rank of the first
        // k bytes, then the rank of the next k (0 past the end).
        let key = |i: usize| (rank[i], rank.get(i + k).map_or(0, |&r| r + 1));
        sa.sort_unstable_by_key(|&i| key(i));
        next[sa[0]] = 0;
        for w in 1..n {
            next[sa[w]] = next[sa[w - 1]] + usize::from(key(sa[w - 1]) != key(sa[w]));
        }
        std::mem::swap(&mut rank, &mut next);
        if rank[sa[n - 1]] == n - 1 {
            return sa;
        }
        k <<= 1;
    }
}

/// Go's `Uvarint`, including the (value, length) pair for truncated input
/// (0, 0) and overflow (0, -(i+1)); `read_slice` advances by that length.
fn go_uvarint(buf: &[u8]) -> (u64, isize) {
    let mut x = 0u64;
    let mut s = 0;
    for (i, &b) in buf.iter().enumerate() {
        if i == MAX_VARINT_LEN64 {
            return (0, -(i as isize + 1)); // overflow
        }
        if b < 0x80 {
            if i == MAX_VARINT_LEN64 - 1 && b > 1 {
                return (0, -(i as isize + 1)); // overflow
            }
            return (x | u64::from(b) << s, i as isize + 1);
        }
        x |= u64::from(b & 0x7f) << s;
        s += 7;
    }
    (0, 0)
}

/// Go's `Varint`.
fn go_varint(buf: &[u8]) -> (i64, isize) {
    let (ux, n) = go_uvarint(buf);
    let mut x = (ux >> 1) as i64;
    if ux & 1 != 0 {
        x = !x;
    }
    (x, n)
}

/// Go's `sort.Search`: the smallest `i` in `0..n` for which `pred(i)` holds,
/// or `n` if there is none. `pred` must be false before that point and true after.
fn search(n: usize, mut pred: impl FnMut(usize) -> bool) -> usize {
    let (mut lo, mut hi) = (0, n);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if pred(mid) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    lo
}

fn corrupted() -> io::Error {
    io::Error::new(ErrorKind::InvalidData, "suffixarray: data corrupted")
}

/// Go's `io.ReadFull`: fills `buf`, or fails with `io.EOF` when nothing was
/// read and `io.ErrUnexpectedEOF` when the input ends part way.
fn read_full<R: Read + ?Sized>(r: &mut R, buf: &mut [u8]) -> io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    if filled == buf.len() {
        return Ok(());
    }
    Err(if filled == 0 {
        IoError::Eof.into()
    } else {
        IoError::UnexpectedEof.into()
    })
}

/// Reads `n` bytes of index data without trusting `n` for the allocation.
fn read_data<R: Read + ?Sized>(r: &mut R, n: usize) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    while data.len() < n {
        let start = data.len();
        data.resize(n.min(start + READ_CHUNK), 0);
        if let Err(e) = read_full(r, &mut data[start..]) {
            // One io.ReadFull over all n bytes: running out after some bytes is unexpected.
            return Err(if start > 0 && IoError::Eof.is(&e) {
                IoError::UnexpectedEof.into()
            } else {
                e
            });
        }
    }
    Ok(data)
}

/// Go's `writeInt`: a varint in a 10-byte slot of `buf`. The bytes after the
/// varint keep whatever `buf` held before, as in Go.
fn write_int<W: Write + ?Sized>(w: &mut W, buf: &mut [u8], x: i64) -> io::Result<()> {
    binary::put_varint(buf, x)?;
    w.write_all(&buf[..MAX_VARINT_LEN64])
}

/// Go's `readInt`: reads a 10-byte varint slot. The value is decoded even
/// when the read fails, as Go does.
fn read_int<R: Read + ?Sized>(r: &mut R, buf: &mut [u8]) -> (i64, io::Result<()>) {
    let err = read_full(r, &mut buf[..MAX_VARINT_LEN64]);
    let (x, _) = go_varint(buf);
    (x, err)
}

/// Go's `writeSlice`: writes as many elements of `data` as fit in `buf` and
/// returns how many were written.
fn write_slice<W: Write + ?Sized>(w: &mut W, buf: &mut [u8], data: &[usize]) -> io::Result<usize> {
    // encode as many elements as fit into buf
    let mut p = MAX_VARINT_LEN64;
    let mut n = 0;
    while n < data.len() && p + MAX_VARINT_LEN64 <= buf.len() {
        p += binary::put_uvarint(&mut buf[p..], data[n] as u64)?;
        n += 1;
    }
    // update buffer size
    binary::put_varint(buf, p as i64)?;
    // write buffer
    w.write_all(&buf[..p])?;
    Ok(n)
}

/// Go's `readSlice`: reads one chunk of suffix array elements and appends
/// them to `sa`, where `total` is the final length of the suffix array.
/// Returns how many elements the chunk held.
fn read_slice<R: Read + ?Sized>(
    r: &mut R,
    buf: &mut [u8],
    sa: &mut Vec<usize>,
    total: usize,
) -> io::Result<usize> {
    // read buffer size
    let (size64, err) = read_int(r, buf);
    err?;
    if size64 < 0 {
        return Err(corrupted());
    }
    let size = size64 as usize;
    // Go slices buf[10:size] here and panics for a size outside the buffer; the
    // port reports corrupt data instead.
    if size < MAX_VARINT_LEN64 || size > buf.len() {
        return Err(corrupted());
    }

    // read buffer w/o the size
    read_full(r, &mut buf[MAX_VARINT_LEN64..size])?;

    // decode as many elements as present in buf
    let remaining = total - sa.len();
    let mut n = 0;
    let mut p = MAX_VARINT_LEN64 as isize;
    while p < size as isize {
        if p < 0 {
            return Err(corrupted());
        }
        let (x, w) = go_uvarint(&buf[p as usize..]);
        // - prevent index-out-of-bounds panic if there are more indices than expected
        // - prevent index-out-of-bounds panic in a future lookup by ensuring all
        //   indices x satisfy x < total
        if n >= remaining || x >= total as u64 {
            return Err(corrupted());
        }
        sa.push(x as usize);
        p += w;
        n += 1;
    }
    Ok(n)
}

impl Index {
    /// Creates a new index for `data`. Creation time is O(N log N) for N = data.len().
    pub fn new(data: impl Into<Vec<u8>>) -> Index {
        let data = data.into();
        let sa = suffix_array(&data);
        Index { data, sa }
    }

    /// Writes the index to `w` in Go's serialized format.
    pub fn write<W: Write + ?Sized>(&self, w: &mut W) -> io::Result<()> {
        // buffer for all writes
        let mut buf = vec![0; BUF_SIZE];

        // write length
        write_int(w, &mut buf, self.data.len() as i64)?;

        // write data
        w.write_all(&self.data)?;

        // write index
        let mut sa = &self.sa[..];
        while !sa.is_empty() {
            let n = write_slice(w, &mut buf, sa)?;
            sa = &sa[n..];
        }
        Ok(())
    }

    /// Replaces the index with one read from `r`, in the format written by
    /// [`Index::write`].
    ///
    /// On error the index is left unchanged. Go instead keeps the buffers it
    /// had already filled, so Go's index can hold partial data after an error.
    pub fn read<R: Read + ?Sized>(&mut self, r: &mut R) -> io::Result<()> {
        // buffer for all reads
        let mut buf = vec![0; BUF_SIZE];

        // read length
        let (n64, err) = read_int(r, &mut buf);
        err?;
        if n64 < 0 {
            return Err(corrupted());
        }
        let n = n64 as usize;

        // read data
        let data = read_data(r, n)?;

        // read index
        let mut sa = Vec::new();
        while sa.len() < n {
            read_slice(r, &mut buf, &mut sa, n)?;
        }
        self.data = data;
        self.sa = sa;
        Ok(())
    }

    /// Returns the data over which the index was created. It must not be modified.
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }

    fn at(&self, i: usize) -> &[u8] {
        &self.data[self.sa[i]..]
    }

    /// Returns the range of suffix array positions whose suffixes start with `s`.
    fn lookup_all(&self, s: &[u8]) -> std::ops::Range<usize> {
        let len = self.sa.len();
        // find the first index where s would be the prefix
        let i = search(len, |i| self.at(i) >= s);
        // starting at i, find the first index at which s is not a prefix
        let j = i + search(len - i, |j| !self.at(j + i).starts_with(s));
        i..j
    }

    /// Returns the offsets where `s` occurs in the indexed data, at most `n` of
    /// them if `n >= 0`, and all of them if `n < 0`. The order is the suffix
    /// array order, which is unspecified for callers. The result is empty if
    /// `s` is empty, `s` is not found, or `n == 0`.
    pub fn lookup(&self, s: &[u8], n: isize) -> Vec<usize> {
        if s.is_empty() || n == 0 {
            return Vec::new();
        }
        let matches = self.lookup_all(s);
        let count = matches.len();
        let n = if n < 0 { count } else { count.min(n as usize) };
        self.sa[matches.start..matches.start + n].to_vec()
    }

    /// Returns a sorted list of non-overlapping matches of the regular
    /// expression `re` in the indexed data, as `(start, end)` byte offsets.
    /// If `n < 0`, all matches are returned. Otherwise at most `n` matches are
    /// returned, and they may not be successive. The result is empty if there
    /// are no matches or if `n == 0`.
    pub fn find_all_index(&self, re: &Regexp, n: isize) -> Vec<(usize, usize)> {
        // a non-empty literal prefix is used to determine possible
        // match start indices with lookup
        let (prefix, complete) = re.literal_prefix();
        let lit = prefix.as_bytes();

        // worst-case scenario: no literal prefix
        if prefix.is_empty() {
            return re.find_all_index(&self.data, n);
        }

        // if regexp is a literal just use lookup and convert its
        // result into match pairs
        if complete {
            // lookup returns indices that may belong to overlapping matches.
            // After eliminating them, we may end up with fewer than n matches.
            // If we don't have enough at the end, redo the search with an
            // increased value n1, but only if lookup returned all the requested
            // indices in the first place (if it returned fewer than that then
            // there cannot be more).
            let mut n1 = n;
            let mut result = Vec::new();
            loop {
                let mut indices = self.lookup(lit, n1);
                if indices.is_empty() {
                    return result;
                }
                indices.sort_unstable();
                result.clear();
                let mut prev = 0;
                for &i in &indices {
                    if result.len() as isize == n {
                        break;
                    }
                    // ignore indices leading to overlapping matches
                    if prev <= i {
                        result.push((i, i + lit.len()));
                        prev = i + lit.len();
                    }
                }
                // found all matches or there's no chance to find more
                // (n and n1 can be negative)
                if result.len() as isize >= n || indices.len() as isize != n1 {
                    break;
                }
                n1 = n1.wrapping_add(2 * (n - result.len() as isize));
            }
            return result;
        }

        // regexp has a non-empty literal prefix; lookup(lit) computes
        // the indices of possible complete matches; use these as starting
        // points for anchored searches
        // (regexp "^" matches beginning of input, not beginning of line)
        let anchored = Regexp::new(&format!("^{}", re.as_str()))
            .expect("the expression compiled, so its anchored form compiles");

        // same comment about lookup applies here as in the loop above
        let mut n1 = n;
        let mut result = Vec::new();
        loop {
            let mut indices = self.lookup(lit, n1);
            if indices.is_empty() {
                return result;
            }
            indices.sort_unstable();
            result.clear();
            let mut prev = 0;
            for &i in &indices {
                if result.len() as isize == n {
                    break;
                }
                // anchored search - will not run off
                let m = anchored.find_index(&self.data[i..]);
                // ignore indices leading to overlapping matches
                if let Some((_, end)) = m {
                    if prev <= i {
                        result.push((i, i + end));
                        prev = i + end;
                    }
                }
            }
            if result.len() as isize >= n || indices.len() as isize != n1 {
                break;
            }
            n1 = n1.wrapping_add(2 * (n - result.len() as isize));
        }
        result
    }
}
