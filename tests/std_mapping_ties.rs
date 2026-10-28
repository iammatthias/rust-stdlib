//! The exact std expressions that docs/api/slices.json gives for Go's
//! tie-breaking and comparison-function symbols, checked against values
//! printed by Go 1.27 (`slices.MaxFunc`, `MinFunc`, `BinarySearch*`,
//! `EqualFunc`, `CompareFunc`, `IsSorted`, `Compact`).
use rust_stdlib::math;
use std::cmp::Ordering;

#[derive(Clone, Copy, Debug)]
struct R {
    k: i32,
    id: char,
}

fn recs() -> Vec<R> {
    [(1, 'a'), (3, 'b'), (3, 'c'), (1, 'd'), (1, 'e')]
        .into_iter()
        .map(|(k, id)| R { k, id })
        .collect()
}

#[test]
fn max_func_and_min_func_return_the_first_tie() {
    let a = recs();
    let cmp = |x: &R, y: &R| x.k.cmp(&y.k);
    // Go: MaxFunc b, MinFunc a. Iterator::max_by returns the last maximum
    // (here 'c'), so the documented expression iterates in reverse.
    assert_eq!(a.iter().max_by(|x, y| cmp(x, y)).unwrap().id, 'c');
    assert_eq!(a.iter().rev().max_by(|x, y| cmp(x, y)).unwrap().id, 'b');
    assert_eq!(a.iter().min_by(|x, y| cmp(x, y)).unwrap().id, 'a');
}

#[test]
fn binary_search_is_the_leftmost_position() {
    let s = [1, 2, 2, 2, 3];
    let i = s.partition_point(|e| *e < 2);
    assert_eq!((i, s.get(i) == Some(&2)), (1, true));
    let s = [1, 2, 2, 2, 4];
    let i = s.partition_point(|e| *e < 3);
    assert_eq!((i, s.get(i) == Some(&3)), (4, false));
    // BinarySearchFunc on the records sorted by key, target key 3: the first
    // of the two equal keys.
    let mut a = recs();
    a.sort_by_key(|r| r.k);
    let i = a.partition_point(|e| e.k.cmp(&3) == Ordering::Less);
    assert_eq!((i, a[i].id), (3, 'b'));
}

#[test]
fn equal_func_and_compare_func_expressions() {
    let eq_func = |a: &[i32], b: &[i32], eq: &dyn Fn(i32, i32) -> bool| {
        a.len() == b.len() && a.iter().zip(b).all(|(x, y)| eq(*x, *y))
    };
    assert!(eq_func(&[1, 2], &[2, 4], &|x, y| x * 2 == y));
    assert!(!eq_func(&[1], &[2, 4], &|_, _| true));

    let cmp_func = |a: &[i32], b: &[i32]| {
        a.iter()
            .zip(b)
            .map(|(x, y)| (x - y).cmp(&0))
            .find(|o| o.is_ne())
            .unwrap_or_else(|| a.len().cmp(&b.len()))
    };
    // Go (sign of 30, -1, 1, 0, -30).
    assert_eq!(cmp_func(&[1, 5], &[1, 2]), Ordering::Greater);
    assert_eq!(cmp_func(&[1], &[1, 2]), Ordering::Less);
    assert_eq!(cmp_func(&[1, 2], &[1]), Ordering::Greater);
    assert_eq!(cmp_func(&[1, 2], &[1, 2]), Ordering::Equal);
    assert_eq!(cmp_func(&[0, 9], &[3]), Ordering::Less);
}

#[test]
fn is_sorted_of_floats_puts_nan_first() {
    let nan = f64::NAN;
    let sorted = |v: &[f64]| v.is_sorted_by(|a, b| math::compare(a, b).is_le());
    // Go: IsSorted([NaN 1 2]) = true, IsSorted([1 NaN 2]) = false.
    assert!(sorted(&[nan, 1.0, 2.0]));
    assert!(!sorted(&[1.0, nan, 2.0]));
    // slice::is_sorted uses PartialOrd and rejects any NaN.
    assert!(![nan, 1.0, 2.0].is_sorted());
}

#[test]
fn compact_keeps_nan_runs() {
    let nan = f64::NAN;
    let mut v = vec![1.0, 1.0, nan, nan, 2.0, 2.0];
    v.dedup();
    // Go: [1 NaN NaN 2]
    assert_eq!(v.len(), 4);
    assert!(v[1].is_nan() && v[2].is_nan());
}
