//! Collections std lacks: Go's `container/heap`, `container/list` and
//! `container/ring`, `slices.CompactFunc` and Go's unstable sort
//! ([`sort_unstable_by`]).
//!
//! Everything else in Go's `sort`, `slices`, `maps`, `cmp` and `iter` is
//! a std method; `docs/api/*.json` maps each symbol to it.
pub mod heap;
pub mod list;
pub mod ring;
mod sort;

pub use sort::{sort_unstable_by, sort_unstable_by_less};

/// Go's `slices.CompactFunc`: removes each element for which `same` reports
/// that it equals its original predecessor.
///
/// `Vec::dedup_by` differs when `same` is not transitive: it compares each
/// element with the last element it kept, not with the one before it.
pub fn compact_by<T>(v: &mut Vec<T>, mut same: impl FnMut(&T, &T) -> bool) {
    if v.len() < 2 {
        return;
    }
    let mut keep = vec![true; v.len()];
    for k in 1..v.len() {
        keep[k] = !same(&v[k], &v[k - 1]);
    }
    let mut flags = keep.into_iter();
    v.retain(|_| flags.next().unwrap_or(true));
}
