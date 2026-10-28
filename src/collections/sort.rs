//! Go's unstable sort, `slices.SortFunc` and `sort.Sort`, as Go orders it.
//!
//! The standard library's `sort_unstable_by` is a different algorithm, so
//! elements that compare equal come out in a different order than from Go.
//! This is a port of Go's pattern-defeating quicksort (`zsortanyfunc.go`),
//! deterministic like Go's, so programs that print the result of sorting
//! records with equal keys get Go's output. The stable sorts are exact in
//! std (`sort_by`), as the stable order is unique.
use std::cmp::Ordering;

/// Go's `slices.SortFunc`: sorts `data` in ascending order as determined by
/// `cmp`. The order of equal elements is Go's, not specified by Go.
pub fn sort_unstable_by<T>(data: &mut [T], mut cmp: impl FnMut(&T, &T) -> Ordering) {
    sort_unstable_by_less(data, |a, b| cmp(a, b) == Ordering::Less);
}

/// Go's `sort.Sort` and `sort.Slice` over a slice: sorts `data` with a
/// `less` that reports whether the first element must come before the second.
pub fn sort_unstable_by_less<T>(data: &mut [T], mut less: impl FnMut(&T, &T) -> bool) {
    let n = data.len();
    let limit = (usize::BITS - n.leading_zeros()) as usize;
    pdqsort(data, 0, n, limit, &mut less);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Hint {
    Unknown,
    Increasing,
    Decreasing,
}

fn insertion_sort<T, F: FnMut(&T, &T) -> bool>(data: &mut [T], a: usize, b: usize, less: &mut F) {
    for i in a + 1..b {
        let mut j = i;
        while j > a && less(&data[j], &data[j - 1]) {
            data.swap(j, j - 1);
            j -= 1;
        }
    }
}

fn sift_down<T, F: FnMut(&T, &T) -> bool>(
    data: &mut [T],
    lo: usize,
    hi: usize,
    first: usize,
    less: &mut F,
) {
    let mut root = lo;
    loop {
        let mut child = 2 * root + 1;
        if child >= hi {
            break;
        }
        if child + 1 < hi && less(&data[first + child], &data[first + child + 1]) {
            child += 1;
        }
        if !less(&data[first + root], &data[first + child]) {
            return;
        }
        data.swap(first + root, first + child);
        root = child;
    }
}

fn heap_sort<T, F: FnMut(&T, &T) -> bool>(data: &mut [T], a: usize, b: usize, less: &mut F) {
    let first = a;
    let hi = b - a;
    // Build heap with greatest element at top.
    for i in (0..hi.div_ceil(2)).rev() {
        sift_down(data, i, hi, first, less);
    }
    // Pop elements, largest first, into end of data.
    for i in (0..hi).rev() {
        data.swap(first, first + i);
        sift_down(data, 0, i, first, less);
    }
}

/// Go's `pdqsortCmpFunc`: sorts `data[a..b]`. `limit` is the number of
/// allowed bad (very unbalanced) pivots before falling back to heapsort.
fn pdqsort<T, F: FnMut(&T, &T) -> bool>(
    data: &mut [T],
    mut a: usize,
    mut b: usize,
    mut limit: usize,
    less: &mut F,
) {
    const MAX_INSERTION: usize = 12;
    let mut was_balanced = true;
    let mut was_partitioned = true;
    loop {
        let length = b - a;
        if length <= MAX_INSERTION {
            insertion_sort(data, a, b, less);
            return;
        }
        // Fall back to heapsort if too many bad choices were made.
        if limit == 0 {
            heap_sort(data, a, b, less);
            return;
        }
        // If the last partitioning was imbalanced, break patterns.
        if !was_balanced {
            break_patterns(data, a, b);
            limit -= 1;
        }
        let (mut pivot, mut hint) = choose_pivot(data, a, b, less);
        if hint == Hint::Decreasing {
            data[a..b].reverse();
            // The pivot was pivot-a elements after the start; after reversing
            // it is that many elements before the end.
            pivot = (b - 1) - (pivot - a);
            hint = Hint::Increasing;
        }
        // The slice is likely already sorted.
        if was_balanced
            && was_partitioned
            && hint == Hint::Increasing
            && partial_insertion_sort(data, a, b, less)
        {
            return;
        }
        // Probably many duplicates: partition into elements equal to and
        // elements greater than the pivot.
        if a > 0 && !less(&data[a - 1], &data[pivot]) {
            a = partition_equal(data, a, b, pivot, less);
            continue;
        }
        let (mid, already_partitioned) = partition(data, a, b, pivot, less);
        was_partitioned = already_partitioned;
        let (left_len, right_len) = (mid - a, b - mid);
        let balance_threshold = length / 8;
        if left_len < right_len {
            was_balanced = left_len >= balance_threshold;
            pdqsort(data, a, mid, limit, less);
            a = mid + 1;
        } else {
            was_balanced = right_len >= balance_threshold;
            pdqsort(data, mid + 1, b, limit, less);
            b = mid;
        }
    }
}

/// One quicksort partition around `data[pivot]`; returns the new pivot index
/// and whether the slice was already partitioned.
fn partition<T, F: FnMut(&T, &T) -> bool>(
    data: &mut [T],
    a: usize,
    b: usize,
    pivot: usize,
    less: &mut F,
) -> (usize, bool) {
    data.swap(a, pivot);
    // i and j are inclusive of the elements remaining to be partitioned;
    // they are signed because j can step below zero.
    let (mut i, mut j) = (a as isize + 1, b as isize - 1);
    while i <= j && less(&data[i as usize], &data[a]) {
        i += 1;
    }
    while i <= j && !less(&data[j as usize], &data[a]) {
        j -= 1;
    }
    if i > j {
        data.swap(j as usize, a);
        return (j as usize, true);
    }
    data.swap(i as usize, j as usize);
    i += 1;
    j -= 1;
    loop {
        while i <= j && less(&data[i as usize], &data[a]) {
            i += 1;
        }
        while i <= j && !less(&data[j as usize], &data[a]) {
            j -= 1;
        }
        if i > j {
            break;
        }
        data.swap(i as usize, j as usize);
        i += 1;
        j -= 1;
    }
    data.swap(j as usize, a);
    (j as usize, false)
}

/// Partitions `data[a..b]` into elements equal to `data[pivot]` followed by
/// elements greater than it; nothing in the range is smaller than the pivot.
fn partition_equal<T, F: FnMut(&T, &T) -> bool>(
    data: &mut [T],
    a: usize,
    b: usize,
    pivot: usize,
    less: &mut F,
) -> usize {
    data.swap(a, pivot);
    let (mut i, mut j) = (a as isize + 1, b as isize - 1);
    loop {
        while i <= j && !less(&data[a], &data[i as usize]) {
            i += 1;
        }
        while i <= j && less(&data[a], &data[j as usize]) {
            j -= 1;
        }
        if i > j {
            break;
        }
        data.swap(i as usize, j as usize);
        i += 1;
        j -= 1;
    }
    i as usize
}

/// Partially sorts the slice; reports whether it is sorted at the end.
fn partial_insertion_sort<T, F: FnMut(&T, &T) -> bool>(
    data: &mut [T],
    a: usize,
    b: usize,
    less: &mut F,
) -> bool {
    const MAX_STEPS: usize = 5; // adjacent out-of-order pairs that will get shifted
    const SHORTEST_SHIFTING: usize = 50; // don't shift any elements on short arrays
    let mut i = a + 1;
    for _ in 0..MAX_STEPS {
        while i < b && !less(&data[i], &data[i - 1]) {
            i += 1;
        }
        if i == b {
            return true;
        }
        if b - a < SHORTEST_SHIFTING {
            return false;
        }
        data.swap(i, i - 1);
        // Shift the smaller one to the left. (Go's loop stops at index 1,
        // not at `a + 1`; kept as is.)
        if i - a >= 2 {
            let mut j = i - 1;
            while j >= 1 {
                if !less(&data[j], &data[j - 1]) {
                    break;
                }
                data.swap(j, j - 1);
                j -= 1;
            }
        }
        // Shift the greater one to the right.
        if b - i >= 2 {
            for j in i + 1..b {
                if !less(&data[j], &data[j - 1]) {
                    break;
                }
                data.swap(j, j - 1);
            }
        }
    }
    false
}

/// Scatters some elements around to break patterns that might cause
/// imbalanced partitions.
fn break_patterns<T>(data: &mut [T], a: usize, b: usize) {
    let length = b - a;
    if length >= 8 {
        let mut random = length as u64;
        let modulus = 1usize << (usize::BITS - length.leading_zeros());
        let mut idx = a + (length / 4) * 2 - 1;
        while idx <= a + (length / 4) * 2 + 1 {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            let mut other = (random as usize) & (modulus - 1);
            if other >= length {
                other -= length;
            }
            data.swap(idx, a + other);
            idx += 1;
        }
    }
}

/// Chooses a pivot in `data[a..b]`: a static one below 8 elements, the median
/// of three below 50, Tukey's ninther from there on.
fn choose_pivot<T, F: FnMut(&T, &T) -> bool>(
    data: &[T],
    a: usize,
    b: usize,
    less: &mut F,
) -> (usize, Hint) {
    const SHORTEST_NINTHER: usize = 50;
    const MAX_SWAPS: usize = 4 * 3;
    let l = b - a;
    let mut swaps = 0;
    let mut i = a + l / 4;
    let mut j = a + l / 4 * 2;
    let mut k = a + l / 4 * 3;
    if l >= 8 {
        if l >= SHORTEST_NINTHER {
            i = median(data, i - 1, i, i + 1, &mut swaps, less);
            j = median(data, j - 1, j, j + 1, &mut swaps, less);
            k = median(data, k - 1, k, k + 1, &mut swaps, less);
        }
        // Find the median among i, j, k and store it into j.
        j = median(data, i, j, k, &mut swaps, less);
    }
    match swaps {
        0 => (j, Hint::Increasing),
        MAX_SWAPS => (j, Hint::Decreasing),
        _ => (j, Hint::Unknown),
    }
}

/// Returns `(x, y)` with `data[x] <= data[y]`, being `(a, b)` or `(b, a)`.
fn order2<T, F: FnMut(&T, &T) -> bool>(
    data: &[T],
    a: usize,
    b: usize,
    swaps: &mut usize,
    less: &mut F,
) -> (usize, usize) {
    if less(&data[b], &data[a]) {
        *swaps += 1;
        return (b, a);
    }
    (a, b)
}

/// Returns the index among `a`, `b`, `c` of the median element.
fn median<T, F: FnMut(&T, &T) -> bool>(
    data: &[T],
    a: usize,
    b: usize,
    c: usize,
    swaps: &mut usize,
    less: &mut F,
) -> usize {
    let (a, b) = order2(data, a, b, swaps, less);
    let (b, _) = order2(data, b, c, swaps, less);
    let (_, b) = order2(data, a, b, swaps, less);
    b
}
