//! Tables ported from Go's container/{heap,list,ring} tests.
use rust_stdlib::collections::{compact_by, heap::Heap, list, ring};

fn verify(h: &Heap<i32, fn(&i32, &i32) -> bool>, i: usize) {
    let items = h.as_slice();
    let n = items.len();
    for c in [2 * i + 1, 2 * i + 2] {
        if c < n {
            assert!(items[i] <= items[c], "heap invariant at {i}/{c}");
            verify(h, c);
        }
    }
}

fn less(a: &i32, b: &i32) -> bool {
    a < b
}

fn int_heap(items: Vec<i32>) -> Heap<i32, fn(&i32, &i32) -> bool> {
    Heap::from_vec(items, less as fn(&i32, &i32) -> bool)
}

#[test]
fn heap_go_tests() {
    let h = int_heap(Vec::new());
    verify(&h, 0);
    let h20 = int_heap((1..=20).rev().collect());
    verify(&h20, 0);
    let mut h = h20;
    for i in 1..=10 {
        h.push(i);
        verify(&h, 0);
    }
    let mut prev = i32::MIN;
    while !h.is_empty() {
        let x = h.pop().unwrap();
        verify(&h, 0);
        assert!(x >= prev);
        prev = x;
    }
    assert_eq!(h.pop(), None);
    // TestRemove / TestFix
    let mut h = int_heap((0..10).collect());
    assert_eq!(h.remove(5), Some(5));
    assert_eq!(h.remove(100), None);
    verify(&h, 0);
    h.update(3, |x| *x = 100).unwrap();
    verify(&h, 0);
    // Exact layout from Go: Init on 3,1,2 gives 1,3,2; pop yields 1 then [2,3].
    let mut h = int_heap(vec![3, 1, 2]);
    assert_eq!(h.as_slice(), [1, 3, 2]);
    assert_eq!(h.pop(), Some(1));
    assert_eq!(h.as_slice(), [2, 3]);
}

#[test]
fn compact_by_compares_with_the_original_predecessor() {
    // Vec::dedup_by would compare with the last kept element and keep [1, 3, 5].
    let mut t: Vec<i32> = vec![1, 2, 3, 5];
    compact_by(&mut t, |a, b| (a - b).abs() <= 1);
    assert_eq!(t, [1, 5]);
    let mut e: Vec<i32> = Vec::new();
    compact_by(&mut e, |a, b| a == b);
    assert!(e.is_empty());
}

fn values(l: &list::List<i32>) -> Vec<i32> {
    l.iter().copied().collect()
}

#[test]
fn list_go_tests() {
    let mut l = list::List::new();
    let e4 = l.push_back(4);
    let e1 = l.push_front(1);
    let e3 = l.insert_before(3, e4).unwrap();
    let e2 = l.insert_after(2, e1).unwrap();
    assert_eq!(values(&l), [1, 2, 3, 4]);
    assert_eq!(l.len(), 4);
    assert_eq!(l.remove(e2), Some(2));
    assert_eq!(l.remove(e2), None); // already removed: no-op
    l.move_to_front(e3);
    l.move_to_back(e1);
    assert_eq!(values(&l), [3, 4, 1]);
    l.move_before(e1, e3);
    assert_eq!(values(&l), [1, 3, 4]);
    l.move_after(e1, e4);
    assert_eq!(values(&l), [3, 4, 1]);
    assert_eq!(e3.next(&l), Some(e4));
    assert_eq!(e3.prev(&l), None);
    assert_eq!(l.front().unwrap().value(&l), Some(&3));
    *e4.value_mut(&mut l).unwrap() = 40;
    assert_eq!(
        l.back().and_then(|e| e.prev(&l)).and_then(|e| e.value(&l)),
        Some(&40)
    );

    // Elements of another list are ignored.
    let mut other: list::List<i32> = list::List::new();
    let x = other.push_back(9);
    assert!(l.insert_after(0, x).is_none());
    l.move_to_front(x);
    assert_eq!(l.remove(x), None);
    assert_eq!(values(&other), [9]);

    let mut dst = list::List::new();
    dst.push_back_list(&l);
    dst.push_front_list(&l);
    assert_eq!(values(&dst), [3, 40, 1, 3, 40, 1]);
    dst.init();
    assert_eq!(dst.len(), 0);
    assert!(dst.front().is_none());
    assert!(e1.next(&dst).is_none());
}

#[test]
fn ring_go_tests() {
    let r: ring::Ring<i32> = ring::Ring::new(10).unwrap();
    assert_eq!(r.len(), 10);
    assert!(ring::Ring::<i32>::new(0).is_none());
    let mut p = r.clone();
    for i in 0..10 {
        p.set_value(i);
        p = p.next();
    }
    let mut seen = Vec::new();
    r.for_each(|v| seen.push(*v));
    assert_eq!(seen, (0..10).collect::<Vec<_>>());
    assert_eq!(r.move_by(3).value(), 3);
    assert_eq!(r.move_by(-1).value(), 9);
    assert_eq!(r.move_by(13).value(), 3);

    // Unlink 3 elements after r: they form their own ring.
    let removed = r.unlink(3).unwrap();
    assert_eq!(r.len(), 7);
    assert_eq!(removed.len(), 3);
    assert_eq!(removed.value(), 1);
    // Link them back.
    r.link(Some(&removed));
    assert_eq!(r.len(), 10);
    assert!(r.unlink(0).is_none());

    let s = ring::Ring::singleton(100);
    assert_eq!(s.len(), 1);
    assert!(s.next() == s);
    r.link(Some(&s));
    assert_eq!(r.len(), 11);
    assert_eq!(r.next().value(), 100);
    // Link(None) just returns next().
    assert_eq!(r.link(None).value(), 100);
}

#[derive(Default)]
struct Probe(Option<std::rc::Rc<std::cell::Cell<usize>>>);

impl Drop for Probe {
    fn drop(&mut self) {
        if let Some(c) = &self.0 {
            c.set(c.get() + 1);
        }
    }
}

#[test]
fn ring_drop_frees_cycle() {
    let drops = std::rc::Rc::new(std::cell::Cell::new(0));
    let r: ring::Ring<Probe> = ring::Ring::new(100).unwrap();
    let mut p = r.clone();
    for _ in 0..100 {
        p.set_value(Probe(Some(drops.clone())));
        p = p.next();
    }
    // Splitting keeps both halves alive until the last handle to each drops.
    let tail = r.unlink(40).unwrap();
    drop(p);
    drop(r);
    assert_eq!(drops.get(), 60); // only the 60-element ring is freed
    drop(tail);
    assert_eq!(drops.get(), 100);
}
