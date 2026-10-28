//! Ported from Go's unique and weak tests.
use rust_stdlib::unique::Handle;
use std::sync::{Arc, Weak};

#[test]
fn unique_handles_compare_by_value() {
    let a = Handle::new("hello".to_string());
    let b = Handle::new(String::from("hel") + "lo");
    let c = Handle::new("world".to_string());
    assert_eq!(a, b);
    assert_ne!(a, c);
    assert_eq!(a.value(), "hello");
    assert_eq!(c.clone().value(), "world");
    let i = Handle::new(7u32);
    assert_eq!(i, Handle::new(7u32));
    assert_ne!(i, Handle::new(8u32));
    // The same bit pattern in another type is another table.
    let k = Handle::new(7u64);
    assert_eq!(*k.value(), 7);
}

#[test]
fn unique_survives_drop_and_remake() {
    let h = Handle::new(vec![1u8, 2, 3]);
    drop(h);
    let again = Handle::new(vec![1u8, 2, 3]);
    assert_eq!(again.value(), &vec![1u8, 2, 3]);
    for n in 0..1000u32 {
        // Enough distinct values to trigger sweeps of dead entries.
        let _ = Handle::new(n);
    }
    assert_eq!(Handle::new(vec![1u8, 2, 3]), again);
}

#[test]
fn unique_handles_hash_and_work_across_threads() {
    use std::collections::HashSet;
    let handles: Vec<_> = (0..8)
        .map(|_| std::thread::spawn(|| Handle::new("shared".to_string())))
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let set: HashSet<_> = results.iter().cloned().collect();
    assert_eq!(set.len(), 1);
}

#[test]
fn weak_pointers() {
    let x = Arc::new(41);
    let y = Arc::new(42);
    let (w1, w2, w3) = (Arc::downgrade(&x), Arc::downgrade(&x), Arc::downgrade(&y));
    assert!(w1.ptr_eq(&w2));
    assert!(!w1.ptr_eq(&w3));
    assert!(Arc::ptr_eq(&w1.upgrade().unwrap(), &x));
    assert_eq!(*w3.upgrade().unwrap(), 42);
    let nil: Weak<i32> = Weak::new();
    assert!(nil.upgrade().is_none());
    assert!(nil.ptr_eq(&Weak::new()));
    let w1c = w1.clone();
    drop(x);
    assert!(w1.upgrade().is_none(), "no strong references remain");
    assert!(w1c.upgrade().is_none());
    assert!(w1.ptr_eq(&w2), "equality survives the value");
    drop(y);
    assert!(w3.upgrade().is_none());
}
