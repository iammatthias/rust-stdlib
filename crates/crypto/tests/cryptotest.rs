//! Go's `testing/cryptotest.SetGlobalRandom` (`rand::set_global_random`).
//!
//! Go's own test checks that a seeded stream repeats, differs per seed and is
//! restored after the test; the bytes differ from Go's ChaCha8 stream by design.
use rust_stdlib_crypto::rand;
use std::io::Read;
use std::sync::Mutex;

/// The random source is process-wide.
static SERIAL: Mutex<()> = Mutex::new(());

fn bytes() -> [u8; 32] {
    let mut b = [0u8; 32];
    assert_eq!(rand::read(&mut b), 32);
    b
}

#[test]
fn seeded_stream_repeats_and_differs_per_seed() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let first = {
        let _guard = rand::set_global_random(1);
        let a = bytes();
        let b = bytes();
        assert_ne!(a, b, "the stream advances");
        (a, b)
    };
    let again = {
        let _guard = rand::set_global_random(1);
        (bytes(), bytes())
    };
    assert_eq!(first, again);
    let other = {
        let _guard = rand::set_global_random(2);
        bytes()
    };
    assert_ne!(first.0, other);
}

#[test]
fn calling_again_resets_the_stream_and_the_guard_restores_the_system_source() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let outer = rand::set_global_random(7);
    let a = bytes();
    // Called a second time in the same "test": resets the stream.
    let inner = rand::set_global_random(7);
    assert_eq!(bytes(), a);
    drop(inner);
    // Back to the first source: it continues where it was.
    assert_ne!(bytes(), a);
    drop(outer);
    // The system source is not deterministic.
    assert_ne!(bytes(), bytes());
}

#[test]
fn all_entry_points_use_the_seeded_stream() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let text = |seed| {
        let _guard = rand::set_global_random(seed);
        rand::text()
    };
    assert_eq!(text(3), text(3));
    assert_ne!(text(3), text(4));
    let reader = |seed| {
        let _guard = rand::set_global_random(seed);
        let mut b = [0u8; 40];
        rand::Reader.read_exact(&mut b).unwrap();
        b
    };
    assert_eq!(reader(5), reader(5));
}
