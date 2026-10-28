//! A binary min-heap with Go's `container/heap` sift algorithms.
//!
//! `std::collections::BinaryHeap` is a max-heap over `Ord` with its own sift
//! order and no `remove` or `fix`. [`Heap`] keeps Go's algorithms, so the
//! element order of the backing array after any sequence of operations is
//! identical to Go's, and it orders by a `less` function instead of `Ord`.

/// A binary heap ordered by `less`; the smallest element is at index 0.
pub struct Heap<T, F> {
    items: Vec<T>,
    less: F,
}

impl<T, F: Fn(&T, &T) -> bool> Heap<T, F> {
    /// Returns an empty heap ordered by `less`.
    pub fn new(less: F) -> Self {
        Heap {
            items: Vec::new(),
            less,
        }
    }

    /// Establishes the heap invariant over `items` in O(n).
    pub fn from_vec(items: Vec<T>, less: F) -> Self {
        let mut h = Heap { items, less };
        let n = h.items.len();
        for i in (0..n / 2).rev() {
            h.down(i, n);
        }
        h
    }

    /// Number of elements.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Reports whether the heap holds no elements.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// The smallest element.
    pub fn peek(&self) -> Option<&T> {
        self.items.first()
    }

    /// The backing array in heap order.
    pub fn as_slice(&self) -> &[T] {
        &self.items
    }

    /// Consumes the heap, returning the backing array in heap order.
    pub fn into_vec(self) -> Vec<T> {
        self.items
    }

    /// Adds `x`.
    pub fn push(&mut self, x: T) {
        self.items.push(x);
        let j = self.items.len() - 1;
        self.up(j);
    }

    /// Removes and returns the smallest element.
    pub fn pop(&mut self) -> Option<T> {
        let n = self.items.len().checked_sub(1)?;
        self.items.swap(0, n);
        self.down(0, n);
        self.items.pop()
    }

    /// Removes and returns the element at index `i`, or `None` if out of range.
    pub fn remove(&mut self, i: usize) -> Option<T> {
        let n = self.items.len().checked_sub(1)?;
        if i > n {
            return None;
        }
        if n != i {
            self.items.swap(i, n);
            if !self.down(i, n) {
                self.up(i);
            }
        }
        self.items.pop()
    }

    /// Changes the element at index `i` with `f` and restores the order, or
    /// returns `None` if `i` is out of range.
    pub fn update<R>(&mut self, i: usize, f: impl FnOnce(&mut T) -> R) -> Option<R> {
        let r = f(self.items.get_mut(i)?);
        let n = self.items.len();
        if !self.down(i, n) {
            self.up(i);
        }
        Some(r)
    }

    fn up(&mut self, mut j: usize) {
        while j > 0 {
            let i = (j - 1) / 2;
            if !(self.less)(&self.items[j], &self.items[i]) {
                break;
            }
            self.items.swap(i, j);
            j = i;
        }
    }

    fn down(&mut self, i0: usize, n: usize) -> bool {
        let mut i = i0;
        loop {
            let j1 = 2 * i + 1;
            if j1 >= n {
                break;
            }
            let mut j = j1;
            let j2 = j1 + 1;
            if j2 < n && (self.less)(&self.items[j2], &self.items[j1]) {
                j = j2;
            }
            if !(self.less)(&self.items[j], &self.items[i]) {
                break;
            }
            self.items.swap(i, j);
            i = j;
        }
        i > i0
    }
}
