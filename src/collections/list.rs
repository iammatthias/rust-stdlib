//! A doubly linked list with element handles (Go's `container/list`).
//!
//! `std::collections::LinkedList` has no stable cursors, so there is no way to
//! insert or move relative to an element in the middle.
//!
//! Elements live in an index arena owned by the [`List`] (no `unsafe`, no
//! `Rc`). An [`Element`] is a small `Copy` handle carrying the list identity
//! and a slot generation, which reproduces Go's rule that operations given an
//! element that does not belong to the list (including one already removed)
//! are no-ops. Because the list owns the values, Go's `e.Value` field is read
//! with [`Element::value`] / [`Element::value_mut`], `e.Next()` / `e.Prev()`
//! take the list, and [`List::remove`] returns `None` for a foreign element
//! where Go would return that element's value. `PushBackList(l)` onto itself
//! cannot be expressed under the borrow rules; clone the values first.
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_LIST_ID: AtomicU64 = AtomicU64::new(1);

const ROOT: usize = 0;

struct Node<T> {
    value: Option<T>,
    prev: usize,
    next: usize,
    gen: u32,
    live: bool,
}

/// Go `list.Element`: a handle to an element of a [`List`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Element {
    list: u64,
    idx: usize,
    gen: u32,
}

/// Go `list.List`.
pub struct List<T> {
    id: u64,
    nodes: Vec<Node<T>>,
    free: Vec<usize>,
    len: usize,
}

impl<T> Default for List<T> {
    fn default() -> Self {
        List::new()
    }
}

impl<T> List<T> {
    /// Returns an empty list.
    pub fn new() -> Self {
        List {
            id: NEXT_LIST_ID.fetch_add(1, Ordering::Relaxed),
            nodes: vec![Node {
                value: None,
                prev: ROOT,
                next: ROOT,
                gen: 0,
                live: true,
            }],
            free: Vec::new(),
            len: 0,
        }
    }

    /// Go `List.Init`: clears the list. Outstanding elements become invalid.
    pub fn init(&mut self) {
        *self = List::new();
    }

    /// Go `List.Len`.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Reports whether the list has no elements.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Go `List.Front`.
    pub fn front(&self) -> Option<Element> {
        self.handle(self.nodes[ROOT].next)
    }

    /// Go `List.Back`.
    pub fn back(&self) -> Option<Element> {
        self.handle(self.nodes[ROOT].prev)
    }

    /// Go `List.PushFront`.
    pub fn push_front(&mut self, v: T) -> Element {
        let e = self.insert_value(v, ROOT);
        self.make(e)
    }

    /// Go `List.PushBack`.
    pub fn push_back(&mut self, v: T) -> Element {
        let at = self.nodes[ROOT].prev;
        let e = self.insert_value(v, at);
        self.make(e)
    }

    /// Go `List.InsertBefore`: `None` if `mark` is not an element of this list.
    pub fn insert_before(&mut self, v: T, mark: Element) -> Option<Element> {
        let m = self.index_of(mark)?;
        let at = self.nodes[m].prev;
        let e = self.insert_value(v, at);
        Some(self.make(e))
    }

    /// Go `List.InsertAfter`: `None` if `mark` is not an element of this list.
    pub fn insert_after(&mut self, v: T, mark: Element) -> Option<Element> {
        let m = self.index_of(mark)?;
        let e = self.insert_value(v, m);
        Some(self.make(e))
    }

    /// Go `List.Remove`: removes `e` and returns its value, or `None` if `e`
    /// is not an element of this list (Go returns the element's own value).
    pub fn remove(&mut self, e: Element) -> Option<T> {
        let i = self.index_of(e)?;
        let (p, n) = (self.nodes[i].prev, self.nodes[i].next);
        self.nodes[p].next = n;
        self.nodes[n].prev = p;
        let node = &mut self.nodes[i];
        node.live = false;
        node.gen = node.gen.wrapping_add(1);
        let v = node.value.take();
        self.free.push(i);
        self.len -= 1;
        v
    }

    /// Go `List.MoveToFront`.
    pub fn move_to_front(&mut self, e: Element) {
        if let Some(i) = self.index_of(e) {
            if self.nodes[ROOT].next != i {
                self.relink(i, ROOT);
            }
        }
    }

    /// Go `List.MoveToBack`.
    pub fn move_to_back(&mut self, e: Element) {
        if let Some(i) = self.index_of(e) {
            if self.nodes[ROOT].prev != i {
                let at = self.nodes[ROOT].prev;
                self.relink(i, at);
            }
        }
    }

    /// Go `List.MoveBefore`: no-op unless both belong to this list and differ.
    pub fn move_before(&mut self, e: Element, mark: Element) {
        if let (Some(i), Some(m)) = (self.index_of(e), self.index_of(mark)) {
            if i != m {
                let at = self.nodes[m].prev;
                self.relink(i, at);
            }
        }
    }

    /// Go `List.MoveAfter`: no-op unless both belong to this list and differ.
    pub fn move_after(&mut self, e: Element, mark: Element) {
        if let (Some(i), Some(m)) = (self.index_of(e), self.index_of(mark)) {
            if i != m {
                self.relink(i, m);
            }
        }
    }

    /// Go `List.PushBackList`: appends a copy of `other`'s values.
    pub fn push_back_list(&mut self, other: &List<T>)
    where
        T: Clone,
    {
        let mut e = other.front();
        while let Some(h) = e {
            let at = self.nodes[ROOT].prev;
            self.insert_value(other.value_of(h).clone(), at);
            e = h.next(other);
        }
    }

    /// Go `List.PushFrontList`: prepends a copy of `other`'s values.
    pub fn push_front_list(&mut self, other: &List<T>)
    where
        T: Clone,
    {
        let mut e = other.back();
        while let Some(h) = e {
            self.insert_value(other.value_of(h).clone(), ROOT);
            e = h.prev(other);
        }
    }

    /// Iterates values front to back.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        let mut i = self.nodes[ROOT].next;
        std::iter::from_fn(move || {
            if i == ROOT {
                return None;
            }
            let n = &self.nodes[i];
            i = n.next;
            n.value.as_ref()
        })
    }

    fn value_of(&self, e: Element) -> &T {
        self.nodes[e.idx].value.as_ref().expect("live element")
    }

    fn make(&self, idx: usize) -> Element {
        Element {
            list: self.id,
            idx,
            gen: self.nodes[idx].gen,
        }
    }

    fn handle(&self, idx: usize) -> Option<Element> {
        (idx != ROOT).then(|| self.make(idx))
    }

    fn index_of(&self, e: Element) -> Option<usize> {
        let n = self.nodes.get(e.idx)?;
        (e.list == self.id && e.idx != ROOT && n.live && n.gen == e.gen).then_some(e.idx)
    }

    fn insert_value(&mut self, v: T, at: usize) -> usize {
        let next = self.nodes[at].next;
        let node = Node {
            value: Some(v),
            prev: at,
            next,
            gen: 0,
            live: true,
        };
        let i = match self.free.pop() {
            Some(i) => {
                let gen = self.nodes[i].gen;
                self.nodes[i] = Node { gen, ..node };
                i
            }
            None => {
                self.nodes.push(node);
                self.nodes.len() - 1
            }
        };
        self.nodes[at].next = i;
        self.nodes[next].prev = i;
        self.len += 1;
        i
    }

    fn relink(&mut self, e: usize, at: usize) {
        if e == at {
            return;
        }
        let (p, n) = (self.nodes[e].prev, self.nodes[e].next);
        self.nodes[p].next = n;
        self.nodes[n].prev = p;
        let after = self.nodes[at].next;
        self.nodes[e].prev = at;
        self.nodes[e].next = after;
        self.nodes[at].next = e;
        self.nodes[after].prev = e;
    }
}

impl Element {
    /// Go `Element.Next`: the next element of `l`, or `None`.
    pub fn next<T>(self, l: &List<T>) -> Option<Element> {
        let i = l.index_of(self)?;
        l.handle(l.nodes[i].next)
    }

    /// Go `Element.Prev`.
    pub fn prev<T>(self, l: &List<T>) -> Option<Element> {
        let i = l.index_of(self)?;
        l.handle(l.nodes[i].prev)
    }

    /// Go `Element.Value` (read).
    pub fn value<T>(self, l: &List<T>) -> Option<&T> {
        let i = l.index_of(self)?;
        l.nodes[i].value.as_ref()
    }

    /// Go `Element.Value` (write).
    pub fn value_mut<T>(self, l: &mut List<T>) -> Option<&mut T> {
        let i = l.index_of(self)?;
        l.nodes[i].value.as_mut()
    }
}
