//! Signal dispositions and the handler behind `os/signal`: `sigaction`, the
//! self-pipe a handler writes to, and the reads that drain it.
use crate::errno::Errno;
use std::os::fd::RawFd;
use std::os::raw::c_int;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

mod c {
    use std::os::raw::c_int;

    /// The C library's `struct sigaction`.
    #[repr(C)]
    pub struct Sigaction {
        pub handler: usize,
        #[cfg(target_os = "linux")]
        pub mask: [u64; 16],
        #[cfg(target_os = "macos")]
        pub mask: u32,
        pub flags: c_int,
        #[cfg(target_os = "linux")]
        pub restorer: usize,
    }

    extern "C" {
        pub fn sigaction(sig: c_int, act: *const Sigaction, old: *mut Sigaction) -> c_int;
        #[cfg(target_os = "linux")]
        pub fn __errno_location() -> *mut c_int;
        #[cfg(target_os = "macos")]
        pub fn __error() -> *mut c_int;
    }
}

#[cfg(target_os = "linux")]
const SA_RESTART: c_int = 0x1000_0000;
#[cfg(target_os = "macos")]
const SA_RESTART: c_int = 0x0002;

const SIG_DFL: usize = 0;
const SIG_IGN: usize = 1;

/// What a signal does when it arrives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// `SIG_DFL`.
    Default,
    /// `SIG_IGN`.
    Ignore,
    /// A handler function, by address.
    Handler(usize),
}

impl Disposition {
    fn raw(self) -> usize {
        match self {
            Disposition::Default => SIG_DFL,
            Disposition::Ignore => SIG_IGN,
            Disposition::Handler(h) => h,
        }
    }

    fn from_raw(h: usize) -> Disposition {
        match h {
            SIG_DFL => Disposition::Default,
            SIG_IGN => Disposition::Ignore,
            other => Disposition::Handler(other),
        }
    }
}

fn empty_action(handler: usize) -> c::Sigaction {
    c::Sigaction {
        handler,
        #[cfg(target_os = "linux")]
        mask: [0; 16],
        #[cfg(target_os = "macos")]
        mask: 0,
        flags: SA_RESTART,
        #[cfg(target_os = "linux")]
        restorer: 0,
    }
}

/// The current disposition of `sig`.
pub fn disposition(sig: i32) -> Result<Disposition, Errno> {
    let mut old = empty_action(0);
    // SAFETY: a null `act` only queries; `old` is a valid, writable sigaction.
    let r = unsafe { c::sigaction(sig, std::ptr::null(), &mut old) };
    if r < 0 {
        return Err(Errno::last());
    }
    Ok(Disposition::from_raw(old.handler))
}

/// Sets the disposition of `sig`, returning the previous one.
pub fn set_disposition(sig: i32, d: Disposition) -> Result<Disposition, Errno> {
    let act = empty_action(d.raw());
    let mut old = empty_action(0);
    // SAFETY: `act` and `old` are valid sigaction structures; the handler
    // address is either SIG_DFL, SIG_IGN or `on_signal`.
    let r = unsafe { c::sigaction(sig, &act, &mut old) };
    if r < 0 {
        return Err(Errno::last());
    }
    Ok(Disposition::from_raw(old.handler))
}

/// Routes `sig` to the self-pipe handler, returning the previous disposition.
pub fn install_handler(sig: i32) -> Result<Disposition, Errno> {
    set_disposition(sig, Disposition::Handler(on_signal as extern "C" fn(c_int) as usize))
}

static WRITE_FD: AtomicI32 = AtomicI32::new(-1);
static READ_FD: AtomicI32 = AtomicI32::new(-1);
static RECEIVED: AtomicU64 = AtomicU64::new(0);

/// How many signals the handler has queued so far.
pub fn received() -> u64 {
    RECEIVED.load(Ordering::SeqCst)
}

/// Creates the self-pipe the handler writes to. The write end is
/// non-blocking, so a full pipe drops signals as Go's queue coalesces them.
pub fn init_pipe() -> Result<(), Errno> {
    let (r, w) = super::sock::pipe()?;
    super::sock::set_nonblocking(w.raw(), true)?;
    READ_FD.store(r.raw(), Ordering::SeqCst);
    WRITE_FD.store(w.raw(), Ordering::SeqCst);
    // Both ends stay open for the life of the process.
    std::mem::forget(r);
    std::mem::forget(w);
    Ok(())
}

fn errno_ptr() -> *mut c_int {
    // SAFETY: both functions return the address of the calling thread's errno.
    #[cfg(target_os = "linux")]
    unsafe {
        c::__errno_location()
    }
    #[cfg(target_os = "macos")]
    unsafe {
        c::__error()
    }
}

/// The signal handler: queues the signal number on the self-pipe. It only
/// stores to atomics and calls `write`, which are async-signal-safe, and it
/// preserves `errno` for the interrupted code.
extern "C" fn on_signal(sig: c_int) {
    let fd: RawFd = WRITE_FD.load(Ordering::Relaxed);
    if fd < 0 {
        return;
    }
    let p = errno_ptr();
    // SAFETY: `p` points at this thread's errno, which is always valid.
    let saved = unsafe { *p };
    if let Ok(1) = super::sock::write(fd, &[sig as u8]) {
        RECEIVED.fetch_add(1, Ordering::SeqCst);
    }
    // SAFETY: as above; restores what the interrupted code saw.
    unsafe { *p = saved };
}

/// Blocks until a signal number arrives on the self-pipe.
pub fn read_signal() -> Result<u8, Errno> {
    let fd = READ_FD.load(Ordering::SeqCst);
    let mut buf = [0u8; 1];
    loop {
        match super::sock::read(fd, &mut buf) {
            Ok(1) => return Ok(buf[0]),
            Ok(_) => return Err(crate::errno::EIO),
            Err(e) if e == crate::errno::EINTR => {}
            Err(e) => return Err(e),
        }
    }
}
