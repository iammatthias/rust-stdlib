//! Sparse-file map helpers shared by the tar reader and writer.

/// A region of a sparse file (`offset` and `length` in bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SparseEntry {
    pub offset: i64,
    pub length: i64,
}

impl SparseEntry {
    pub fn end_offset(&self) -> i64 {
        self.offset.wrapping_add(self.length)
    }
}

pub(super) fn block_padding(offset: i64) -> i64 {
    offset.wrapping_neg() & 511
}

/// Report whether entries are sorted, non-overlapping and inside `size`.
pub(super) fn validate_sparse_entries(sp: &[SparseEntry], size: i64) -> bool {
    if size < 0 {
        return false;
    }
    let mut pre = SparseEntry {
        offset: 0,
        length: 0,
    };
    for cur in sp {
        if cur.offset < 0 || cur.length < 0 {
            return false;
        }
        if cur.offset > i64::MAX - cur.length {
            return false;
        }
        if cur.end_offset() > size {
            return false;
        }
        if pre.end_offset() > cur.offset {
            return false;
        }
        pre = *cur;
    }
    true
}

/// Shrink entries to whole 512-byte blocks, dropping those that vanish.
pub(super) fn align_sparse_entries(src: &[SparseEntry], size: i64) -> Vec<SparseEntry> {
    let mut dst = Vec::new();
    for s in src {
        let mut pos = s.offset;
        let mut end = s.end_offset();
        pos += block_padding(pos);
        if end != size {
            end -= block_padding(-end);
        }
        if pos < end {
            dst.push(SparseEntry {
                offset: pos,
                length: end - pos,
            });
        }
    }
    dst
}

/// Convert data fragments to holes or the reverse; the last element covers
/// the tail up to `size` and may be empty.
pub(super) fn invert_sparse_entries(src: &[SparseEntry], size: i64) -> Vec<SparseEntry> {
    let mut dst = Vec::new();
    let mut pre = SparseEntry {
        offset: 0,
        length: 0,
    };
    for cur in src {
        if cur.length == 0 {
            continue;
        }
        pre.length = cur.offset - pre.offset;
        if pre.length > 0 {
            dst.push(pre);
        }
        pre.offset = cur.end_offset();
    }
    pre.length = size - pre.offset;
    dst.push(pre);
    dst
}
