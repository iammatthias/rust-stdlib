//! Concurrency primitives std lacks.
//!
//! Go's `sync` and `sync/atomic` are std: `Mutex`, `RwLock`, `Condvar`, `Once`,
//! `OnceLock` and the `std::sync::atomic` types (`docs/api/sync.json` maps each
//! symbol). Only `sync.WaitGroup` has no std counterpart that tracks a counter
//! across detached threads; `std::thread::scope` covers the scoped case.

use std::sync::{Arc, Condvar, Mutex};

#[derive(Debug, Default)]
struct Inner {
    count: Mutex<i64>,
    cv: Condvar,
}

/// Waits for a collection of threads to finish (Go's `sync.WaitGroup`).
/// Clones share one counter, which is how [`WaitGroup::spawn`] hands the group
/// to the thread it starts.
#[derive(Clone, Debug, Default)]
pub struct WaitGroup(Arc<Inner>);

impl WaitGroup {
    /// Creates a wait group with a zero counter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `delta`, which may be negative, to the counter. It panics if the
    /// counter would become negative; when it reaches zero all `wait`ers
    /// are released.
    pub fn add(&self, delta: i64) {
        let mut g = self.0.count.lock().unwrap_or_else(|e| e.into_inner());
        match g.checked_add(delta).filter(|n| *n >= 0) {
            Some(n) => {
                *g = n;
                drop(g);
                if n == 0 {
                    self.0.cv.notify_all();
                }
            }
            None => {
                drop(g);
                panic!("sync: negative WaitGroup counter");
            }
        }
    }

    /// Decrements the counter by one.
    pub fn done(&self) {
        self.add(-1);
    }

    /// Blocks until the counter is zero.
    pub fn wait(&self) {
        let mut g = self.0.count.lock().unwrap_or_else(|e| e.into_inner());
        while *g > 0 {
            g = self.0.cv.wait(g).unwrap_or_else(|e| e.into_inner());
        }
    }

    /// Calls `f` in a new thread and adds that task to the group. The counter
    /// is decremented when `f` returns, or panics.
    pub fn spawn<F: FnOnce() + Send + 'static>(&self, f: F) {
        self.add(1);
        let group = self.clone();
        std::thread::spawn(move || {
            struct Done(WaitGroup);
            impl Drop for Done {
                fn drop(&mut self) {
                    self.0.done();
                }
            }
            let _done = Done(group);
            f();
        });
    }
}
