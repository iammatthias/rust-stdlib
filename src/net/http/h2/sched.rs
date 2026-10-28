//! The server's frame write schedulers: round robin across streams, and
//! RFC 9218 urgency/incremental priorities (Go's `writesched_roundrobin.go`
//! and `writesched_priority_rfc9218.go`). Control frames always go first.
use std::collections::{HashMap, VecDeque};

/// What a queued write request must tell the scheduler.
pub(crate) trait SchedItem {
    /// True for requests not bound to an open stream (SETTINGS, PING, ...).
    fn is_control(&self) -> bool;
    /// The stream a request belongs to (0 for connection-level frames).
    fn stream_id(&self) -> u32;
}

/// The outcome of offering the front of a stream queue to the writer.
pub(crate) enum Take<T> {
    /// Flow control allows nothing now.
    Blocked,
    /// The whole front request may be written; it is removed from the queue.
    Whole,
    /// The caller split the request: this piece goes out and the rest stays
    /// at the front of the queue.
    Piece(T),
}

struct StreamQueue<T> {
    q: VecDeque<T>,
    urgency: u8,
    incremental: u8,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    RoundRobin,
    Rfc9218,
}

/// A write scheduler.
pub(crate) struct Sched<T> {
    kind: Kind,
    control: VecDeque<T>,
    streams: HashMap<u32, StreamQueue<T>>,
    /// Round robin: one ring. RFC 9218: `rings[urgency][incremental]`.
    rings: Vec<Vec<u32>>,
    heads: Vec<usize>,
    prioritize_incremental: bool,
    priority_update_buf: Option<(u32, u8, u8)>,
}

fn ring_index(kind: Kind, urgency: u8, incremental: u8) -> usize {
    match kind {
        Kind::RoundRobin => 0,
        Kind::Rfc9218 => usize::from(urgency) * 2 + usize::from(incremental),
    }
}

impl<T: SchedItem> Sched<T> {
    pub(crate) fn new(kind: Kind) -> Self {
        let n = match kind {
            Kind::RoundRobin => 1,
            Kind::Rfc9218 => 16,
        };
        Self {
            kind,
            control: VecDeque::new(),
            streams: HashMap::new(),
            rings: vec![Vec::new(); n],
            heads: vec![0; n],
            prioritize_incremental: false,
            priority_update_buf: None,
        }
    }

    pub(crate) fn kind(&self) -> Kind {
        self.kind
    }

    /// Go's `OpenStream`.
    pub(crate) fn open_stream(&mut self, id: u32, mut urgency: u8, mut incremental: u8) {
        if let Some((sid, u, i)) = self.priority_update_buf {
            if sid == id {
                self.priority_update_buf = None;
                urgency = u;
                incremental = i;
            }
        }
        if self.streams.contains_key(&id) {
            return;
        }
        let r = ring_index(self.kind, urgency, incremental);
        self.rings[r].push(id);
        self.streams.insert(
            id,
            StreamQueue {
                q: VecDeque::new(),
                urgency,
                incremental,
            },
        );
    }

    fn remove_from_ring(&mut self, r: usize, id: u32) {
        let ring = &mut self.rings[r];
        let Some(idx) = ring.iter().position(|&s| s == id) else {
            return;
        };
        ring.remove(idx);
        let head = &mut self.heads[r];
        if idx < *head {
            *head -= 1;
        }
        if *head >= ring.len() {
            *head = 0;
        }
    }

    /// Go's `CloseStream`: drops the stream and every request still queued
    /// for it (dropping their completion channels wakes the waiters).
    pub(crate) fn close_stream(&mut self, id: u32) {
        let Some(sq) = self.streams.remove(&id) else {
            return;
        };
        let r = ring_index(self.kind, sq.urgency, sq.incremental);
        self.remove_from_ring(r, id);
    }

    /// Go's `AdjustStream` for RFC 9218 priorities.
    pub(crate) fn adjust_stream(&mut self, id: u32, urgency: u8, incremental: u8) {
        if self.kind != Kind::Rfc9218 {
            return;
        }
        let Some(sq) = self.streams.get(&id) else {
            self.priority_update_buf = Some((id, urgency, incremental));
            return;
        };
        let old = ring_index(self.kind, sq.urgency, sq.incremental);
        self.remove_from_ring(old, id);
        let new = ring_index(self.kind, urgency, incremental);
        self.rings[new].push(id);
        if let Some(sq) = self.streams.get_mut(&id) {
            sq.urgency = urgency;
            sq.incremental = incremental;
        }
    }

    /// Go's `Push`.
    pub(crate) fn push(&mut self, wr: T) {
        if wr.is_control() {
            self.control.push_back(wr);
            return;
        }
        match self.streams.get_mut(&wr.stream_id()) {
            Some(sq) => sq.q.push_back(wr),
            None => self.control.push_back(wr),
        }
    }

    fn consume(&mut self, id: u32, f: &mut dyn FnMut(&mut T) -> Take<T>) -> Option<T> {
        let sq = self.streams.get_mut(&id)?;
        let front = sq.q.front_mut()?;
        match f(front) {
            Take::Blocked => None,
            Take::Whole => sq.q.pop_front(),
            Take::Piece(p) => Some(p),
        }
    }

    /// Go's `Pop`: the next request to write. `f` decides how much of a
    /// stream's front request flow control lets through.
    pub(crate) fn pop(&mut self, f: &mut dyn FnMut(&mut T) -> Take<T>) -> Option<T> {
        if let Some(wr) = self.control.pop_front() {
            return Some(wr);
        }
        match self.kind {
            Kind::RoundRobin => self.pop_ring(0, true, f),
            Kind::Rfc9218 => {
                self.prioritize_incremental = !self.prioritize_incremental;
                for u in 0..8 {
                    for i in 0..2 {
                        let i = if self.prioritize_incremental {
                            (i + 1) % 2
                        } else {
                            i
                        };
                        let r = u * 2 + i;
                        if self.rings[r].is_empty() {
                            continue;
                        }
                        if let Some(wr) = self.pop_ring(r, i == 1, f) {
                            return Some(wr);
                        }
                    }
                }
                None
            }
        }
    }

    /// Walks ring `r` from its head; `advance` moves the head past the
    /// stream served (round robin) instead of staying on it.
    fn pop_ring(
        &mut self,
        r: usize,
        advance: bool,
        f: &mut dyn FnMut(&mut T) -> Take<T>,
    ) -> Option<T> {
        let n = self.rings[r].len();
        let head = self.heads[r];
        for k in 0..n {
            let idx = (head + k) % n;
            let id = self.rings[r][idx];
            if let Some(wr) = self.consume(id, f) {
                self.heads[r] = if advance { (idx + 1) % n } else { idx };
                return Some(wr);
            }
        }
        None
    }

    /// True when nothing is queued anywhere.
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.control.is_empty() && self.streams.values().all(|s| s.q.is_empty())
    }
}
