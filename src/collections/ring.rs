//! A circular list (Go's `container/ring`); std has no equivalent.
//!
//! A [`Ring`] is a handle to one element of a ring, like Go's `*Ring`; cloning
//! the handle does not copy the ring. Elements are `Rc<RefCell<..>>` nodes
//! (`next` strong, `prev` weak, no `unsafe`), so [`Ring::link`] and
//! [`Ring::unlink`] splice rings exactly like Go's pointer surgery. Dropping
//! the last handle to a ring frees it (see the `Drop` impl).
//!
//! Go's exported `Value` field is [`Ring::value`] / [`Ring::set_value`] /
//! [`Ring::with_value`]. `Move` is `move_by` because `move` is a Rust keyword; `Do` is
//! `for_each`. Go's nil ring is `Option::None`;
//! `New(n)` with `n <= 0` returns `None`. Go values start as `nil`; here they
//! start as `T::default()`. Mutating the ring from inside `for_each` is
//! undefined in Go and panics here if it touches the element being visited.
use std::cell::RefCell;
use std::rc::{Rc, Weak};

type Link<T> = Rc<RefCell<Node<T>>>;

struct Node<T> {
    next: Option<Link<T>>,
    prev: Weak<RefCell<Node<T>>>,
    value: T,
}

/// Go `ring.Ring`: a handle to an element of a circular list.
pub struct Ring<T>(Link<T>);

impl<T> Clone for Ring<T> {
    fn clone(&self) -> Self {
        Ring(Rc::clone(&self.0))
    }
}

impl<T> PartialEq for Ring<T> {
    /// Pointer identity, like comparing Go `*Ring` values.
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}

impl<T> Drop for Ring<T> {
    fn drop(&mut self) {
        // The ring is a strong cycle. If this handle is the only outside
        // reference to every node (each node has just its predecessor's
        // `next` link), break the cycle so the nodes are freed.
        if Rc::strong_count(&self.0) != 2 {
            return;
        }
        let mut nodes = vec![Rc::clone(&self.0)];
        let mut cur = self.0.borrow().next.clone();
        while let Some(c) = cur {
            if Rc::ptr_eq(&c, &self.0) {
                break;
            }
            if Rc::strong_count(&c) != 2 {
                return;
            }
            let next = c.borrow().next.clone();
            nodes.push(c);
            cur = next;
        }
        for n in nodes {
            n.borrow_mut().next = None;
        }
    }
}

impl<T: Default> Ring<T> {
    /// Go `ring.New`: a ring of `n` elements holding default values; `None` if `n == 0`.
    pub fn new(n: usize) -> Option<Ring<T>> {
        if n == 0 {
            return None;
        }
        let mk = |prev: Weak<RefCell<Node<T>>>| {
            Rc::new(RefCell::new(Node {
                next: None,
                prev,
                value: T::default(),
            }))
        };
        let first = mk(Weak::new());
        let mut p = Rc::clone(&first);
        for _ in 1..n {
            let r = mk(Rc::downgrade(&p));
            p.borrow_mut().next = Some(Rc::clone(&r));
            p = r;
        }
        p.borrow_mut().next = Some(Rc::clone(&first));
        first.borrow_mut().prev = Rc::downgrade(&p);
        Some(Ring(first))
    }
}

impl<T> Ring<T> {
    /// A one-element ring holding `value` (Go's zero `Ring` with `Value` set).
    pub fn singleton(value: T) -> Ring<T> {
        let node = Rc::new(RefCell::new(Node {
            next: None,
            prev: Weak::new(),
            value,
        }));
        node.borrow_mut().next = Some(Rc::clone(&node));
        node.borrow_mut().prev = Rc::downgrade(&node);
        Ring(node)
    }

    /// Go `Ring.Next`.
    pub fn next(&self) -> Ring<T> {
        Ring(self.0.borrow().next.clone().expect("ring is linked"))
    }

    /// Go `Ring.Prev`.
    pub fn prev(&self) -> Ring<T> {
        Ring(self.0.borrow().prev.upgrade().expect("ring is linked"))
    }

    /// Go `Ring.Move`: moves `n % r.Len()` elements backward (`n < 0`) or forward.
    pub fn move_by(&self, n: isize) -> Ring<T> {
        let mut r = self.clone();
        if n < 0 {
            for _ in 0..n.unsigned_abs() {
                r = r.prev();
            }
        } else {
            for _ in 0..n {
                r = r.next();
            }
        }
        r
    }

    /// Go `Ring.Link`: connects `self` with `s` so that `self.next()` becomes
    /// `s`, and returns the original `self.next()`. If `s` is in the same ring
    /// the elements between them are removed into their own ring.
    pub fn link(&self, s: Option<&Ring<T>>) -> Ring<T> {
        let n = self.next();
        if let Some(s) = s {
            let p = s.prev();
            self.0.borrow_mut().next = Some(Rc::clone(&s.0));
            s.0.borrow_mut().prev = Rc::downgrade(&self.0);
            n.0.borrow_mut().prev = Rc::downgrade(&p.0);
            p.0.borrow_mut().next = Some(Rc::clone(&n.0));
        }
        n
    }

    /// Go `Ring.Unlink`: removes `n % r.Len()` elements after `self`; `None` if `n <= 0`.
    pub fn unlink(&self, n: isize) -> Option<Ring<T>> {
        if n <= 0 {
            return None;
        }
        let target = self.move_by(n + 1);
        Some(self.link(Some(&target)))
    }

    /// Go `Ring.Len`: the number of elements, O(n).
    pub fn len(&self) -> usize {
        let mut n = 1;
        let mut p = self.next();
        while p != *self {
            n += 1;
            p = p.next();
        }
        n
    }

    /// Always false: a ring has at least one element.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Go `Ring.Do`: calls `f` on each element's value in forward order.
    pub fn for_each(&self, mut f: impl FnMut(&T)) {
        f(&self.0.borrow().value);
        let mut p = self.next();
        while p != *self {
            f(&p.0.borrow().value);
            p = p.next();
        }
    }

    /// Go `Ring.Value` (read, cloned).
    pub fn value(&self) -> T
    where
        T: Clone,
    {
        self.0.borrow().value.clone()
    }

    /// Go `Ring.Value` (write).
    pub fn set_value(&self, v: T) {
        self.0.borrow_mut().value = v;
    }

    /// Go `Ring.Value` (borrowed access).
    pub fn with_value<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        f(&mut self.0.borrow_mut().value)
    }
}
