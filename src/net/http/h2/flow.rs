//! HTTP/2 flow control windows (Go's `flow.go`): `Inflow` tracks the window
//! we have granted the peer, `Outflow` the window the peer has granted us.

/// Window updates smaller than this are held back until they accumulate
/// (Go's `inflowMinRefresh`).
const INFLOW_MIN_REFRESH: i32 = 4 << 10;

/// The receive window: how much more the peer may send us.
#[derive(Clone, Copy, Debug, Default)]
pub struct Inflow {
    avail: i32,
    unsent: i32,
}

impl Inflow {
    pub fn init(&mut self, n: i32) {
        self.avail = n;
    }
    pub fn avail(&self) -> i32 {
        self.avail
    }

    /// Go's `add`: returns the WINDOW_UPDATE increment to send now (0 for none).
    pub fn add(&mut self, n: usize) -> i32 {
        let unsent = i64::from(self.unsent) + n as i64;
        const MAX_WINDOW: i64 = (1 << 31) - 1;
        if unsent + i64::from(self.avail) > MAX_WINDOW {
            // Go panics ("flow control update exceeds maximum window size");
            // clamp so a bookkeeping slip cannot take the process down.
            let room = (MAX_WINDOW - i64::from(self.avail)).max(0);
            self.unsent = room as i32;
        } else {
            self.unsent = unsent as i32;
        }
        if self.unsent < INFLOW_MIN_REFRESH && self.unsent < self.avail {
            return 0;
        }
        self.avail += self.unsent;
        let sent = self.unsent;
        self.unsent = 0;
        sent
    }

    /// Go's `take`: consumes `n` of the window; false when it would overdraw.
    pub fn take(&mut self, n: u32) -> bool {
        if i64::from(n) > i64::from(self.avail) {
            return false;
        }
        self.avail -= n as i32;
        true
    }
}

/// Go's `takeInflows`: takes `n` from both windows or neither.
pub fn take_inflows(f1: &mut Inflow, f2: &mut Inflow, n: u32) -> bool {
    if i64::from(n) > i64::from(f1.avail) || i64::from(n) > i64::from(f2.avail) {
        return false;
    }
    f1.avail -= n as i32;
    f2.avail -= n as i32;
    true
}

/// The send window: how much more we may send the peer.
#[derive(Clone, Copy, Debug, Default)]
pub struct Outflow {
    pub n: i32,
}

impl Outflow {
    /// Go's `add`: false when the window would overflow 2^31-1.
    pub fn add(&mut self, n: i32) -> bool {
        match self.n.checked_add(n) {
            Some(sum) => {
                self.n = sum;
                true
            }
            None => false,
        }
    }
}

/// Go's `outflow.available`: the smaller of the stream and connection windows.
pub fn available(stream: &Outflow, conn: &Outflow) -> i32 {
    stream.n.min(conn.n)
}

/// Go's `outflow.take`: takes `n` from the stream and connection windows.
pub fn take(stream: &mut Outflow, conn: &mut Outflow, n: i32) {
    debug_assert!(n <= available(stream, conn), "took too much");
    stream.n -= n;
    conn.n -= n;
}
