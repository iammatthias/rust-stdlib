//! Go's `closingMutex` (closemu.go): a reader-preferring lock whose read side
//! is acquired and released explicitly, because Go holds it across calls.
use std::sync::{Condvar, Mutex};

pub(crate) struct ClosingMutex {
    state: Mutex<State>,
    changed: Condvar,
}

#[derive(Default)]
struct State {
    readers: usize,
    writer: bool,
}

impl ClosingMutex {
    pub(crate) fn new() -> Self {
        ClosingMutex {
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
        }
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn rlock(&self) {
        let mut s = self.lock_state();
        while s.writer {
            s = self.changed.wait(s).unwrap_or_else(|e| e.into_inner());
        }
        s.readers += 1;
    }

    pub(crate) fn runlock(&self) {
        let mut s = self.lock_state();
        assert!(s.readers > 0, "runlock of un-rlocked mutex");
        s.readers -= 1;
        if s.readers == 0 {
            self.changed.notify_all();
        }
    }

    pub(crate) fn lock(&self) {
        let mut s = self.lock_state();
        while s.writer || s.readers > 0 {
            s = self.changed.wait(s).unwrap_or_else(|e| e.into_inner());
        }
        s.writer = true;
    }

    pub(crate) fn unlock(&self) {
        let mut s = self.lock_state();
        assert!(s.writer, "unlock of unlocked mutex");
        s.writer = false;
        self.changed.notify_all();
    }

    /// Whether `lock` would block right now.
    pub(crate) fn is_busy(&self) -> bool {
        let s = self.lock_state();
        s.writer || s.readers > 0
    }
}

/// Releases a read lock taken with `rlock` when dropped.
pub(crate) struct ReadGuard<'a>(pub(crate) &'a ClosingMutex);

impl Drop for ReadGuard<'_> {
    fn drop(&mut self) {
        self.0.runlock();
    }
}
