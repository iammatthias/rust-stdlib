//! Go's `log/syslog` package: a client for the system syslog daemon or a remote one.
//!
//! [`Dial`](dial) connects over UDP, TCP or a Unix socket; [`new`] finds the
//! local daemon at `/dev/log`, `/var/run/syslog` or `/var/run/log`. The wire
//! format is Go's: `<PRI>TIMESTAMP [HOSTNAME ]TAG[PID]: MSG\n`, with an
//! RFC 3339 timestamp and hostname for network connections and the BSD
//! `Stamp` timestamp without hostname for Unix sockets.
//!
//! Deviations from Go, forced by Rust std: the host name comes from
//! `/proc/sys/kernel/hostname`, `/etc/hostname`, the `hostname` command or the
//! `HOSTNAME` variable, and timestamps are UTC because there is no local zone
//! database.
//!
//! ```no_run
//! use rust_stdlib::log::syslog::{self, LOG_INFO, LOG_USER};
//! let w = syslog::new(LOG_USER | LOG_INFO, "demo")?;
//! w.info("hello")?;
//! # Ok::<(), std::io::Error>(())
//! ```
use crate::log::{self as stdlog, now};
use std::{
    io::{self, Write},
    net::{TcpStream, ToSocketAddrs, UdpSocket},
    sync::{Mutex, MutexGuard},
};

#[cfg(unix)]
use std::os::unix::net::{UnixDatagram, UnixStream};

/// A combination of a syslog facility and severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Priority(pub i32);

const SEVERITY_MASK: i32 = 0x07;
const FACILITY_MASK: i32 = 0xf8;

impl std::ops::BitOr for Priority {
    type Output = Priority;
    fn bitor(self, rhs: Priority) -> Priority {
        Priority(self.0 | rhs.0)
    }
}

// Severity.

/// System is unusable.
pub const LOG_EMERG: Priority = Priority(0);
/// Action must be taken immediately.
pub const LOG_ALERT: Priority = Priority(1);
/// Critical conditions.
pub const LOG_CRIT: Priority = Priority(2);
/// Error conditions.
pub const LOG_ERR: Priority = Priority(3);
/// Warning conditions.
pub const LOG_WARNING: Priority = Priority(4);
/// Normal but significant conditions.
pub const LOG_NOTICE: Priority = Priority(5);
/// Informational messages.
pub const LOG_INFO: Priority = Priority(6);
/// Debug-level messages.
pub const LOG_DEBUG: Priority = Priority(7);

// Facility.

/// Kernel messages.
pub const LOG_KERN: Priority = Priority(0 << 3);
/// User-level messages.
pub const LOG_USER: Priority = Priority(1 << 3);
/// Mail system.
pub const LOG_MAIL: Priority = Priority(2 << 3);
/// System daemons.
pub const LOG_DAEMON: Priority = Priority(3 << 3);
/// Security/authorization messages.
pub const LOG_AUTH: Priority = Priority(4 << 3);
/// Messages generated internally by syslogd.
pub const LOG_SYSLOG: Priority = Priority(5 << 3);
/// Line printer subsystem.
pub const LOG_LPR: Priority = Priority(6 << 3);
/// Network news subsystem.
pub const LOG_NEWS: Priority = Priority(7 << 3);
/// UUCP subsystem.
pub const LOG_UUCP: Priority = Priority(8 << 3);
/// Clock daemon.
pub const LOG_CRON: Priority = Priority(9 << 3);
/// Security/authorization messages (private).
pub const LOG_AUTHPRIV: Priority = Priority(10 << 3);
/// FTP daemon.
pub const LOG_FTP: Priority = Priority(11 << 3);
/// Local use 0.
pub const LOG_LOCAL0: Priority = Priority(16 << 3);
/// Local use 1.
pub const LOG_LOCAL1: Priority = Priority(17 << 3);
/// Local use 2.
pub const LOG_LOCAL2: Priority = Priority(18 << 3);
/// Local use 3.
pub const LOG_LOCAL3: Priority = Priority(19 << 3);
/// Local use 4.
pub const LOG_LOCAL4: Priority = Priority(20 << 3);
/// Local use 5.
pub const LOG_LOCAL5: Priority = Priority(21 << 3);
/// Local use 6.
pub const LOG_LOCAL6: Priority = Priority(22 << 3);
/// Local use 7.
pub const LOG_LOCAL7: Priority = Priority(23 << 3);

enum Stream {
    Udp(UdpSocket),
    Tcp(TcpStream),
    #[cfg(unix)]
    UnixDgram(UnixDatagram),
    #[cfg(unix)]
    Unix(UnixStream),
}

impl Stream {
    /// One write per message, as datagram transports require.
    fn send(&mut self, msg: &[u8]) -> io::Result<()> {
        match self {
            Stream::Udp(s) => s.send(msg).map(|_| ()),
            Stream::Tcp(s) => s.write_all(msg),
            #[cfg(unix)]
            Stream::UnixDgram(s) => s.send(msg).map(|_| ()),
            #[cfg(unix)]
            Stream::Unix(s) => s.write_all(msg),
        }
    }
}

struct Conn {
    /// Local delivery: no hostname in the message, BSD timestamp.
    local: bool,
    stream: Stream,
    /// The local address, used as hostname when none is known.
    local_addr: String,
}

struct Inner {
    hostname: String,
    conn: Option<Conn>,
}

/// A connection to a syslog server. It is safe for concurrent use.
pub struct Writer {
    priority: Priority,
    tag: String,
    network: String,
    raddr: String,
    inner: Mutex<Inner>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn hostname() -> String {
    for path in ["/proc/sys/kernel/hostname", "/etc/hostname"] {
        if let Ok(s) = std::fs::read_to_string(path) {
            let s = s.trim();
            if !s.is_empty() {
                return s.to_owned();
            }
        }
    }
    if let Ok(out) = std::process::Command::new("hostname").output() {
        let s = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        if out.status.success() && !s.is_empty() {
            return s;
        }
    }
    std::env::var("HOSTNAME").unwrap_or_default()
}

/// Creates a connection to the local syslog daemon (Go `New`).
pub fn new(priority: Priority, tag: &str) -> io::Result<Writer> {
    dial("", "", priority, tag)
}

/// Establishes a connection to a log daemon by connecting to address `raddr`
/// on the specified network (`udp`, `tcp`, `unixgram`, `unix`, ...). If
/// `network` is empty, the local daemon's socket is used. The `tag` is the
/// program name; an empty tag uses `argv[0]`.
pub fn dial(network: &str, raddr: &str, priority: Priority, tag: &str) -> io::Result<Writer> {
    if priority.0 < 0 || priority.0 > (LOG_LOCAL7 | LOG_DEBUG).0 {
        return Err(io::Error::other("log/syslog: invalid priority"));
    }
    let tag = if tag.is_empty() {
        std::env::args().next().unwrap_or_default()
    } else {
        tag.to_owned()
    };
    let w = Writer {
        priority,
        tag,
        network: network.to_owned(),
        raddr: raddr.to_owned(),
        inner: Mutex::new(Inner {
            hostname: hostname(),
            conn: None,
        }),
    };
    {
        let mut inner = lock(&w.inner);
        w.connect(&mut inner)?;
    }
    Ok(w)
}

/// Returns a `log::Logger` that writes to the local syslog daemon with the
/// given priority and log flags (Go `NewLogger`).
pub fn logger(p: Priority, log_flag: i32) -> io::Result<stdlog::Logger> {
    let s = new(p, "")?;
    Ok(stdlog::Logger::new(s, "", log_flag))
}

#[cfg(unix)]
fn unix_syslog() -> io::Result<Conn> {
    for network in ["unixgram", "unix"] {
        for path in ["/dev/log", "/var/run/syslog", "/var/run/log"] {
            let stream = match network {
                "unixgram" => UnixDatagram::unbound().and_then(|s| {
                    s.connect(path)?;
                    Ok(Stream::UnixDgram(s))
                }),
                _ => UnixStream::connect(path).map(Stream::Unix),
            };
            if let Ok(stream) = stream {
                return Ok(Conn {
                    local: true,
                    stream,
                    local_addr: String::new(),
                });
            }
        }
    }
    Err(io::Error::other("Unix syslog delivery error"))
}

#[cfg(not(unix))]
fn unix_syslog() -> io::Result<Conn> {
    Err(io::Error::other("Unix syslog delivery error"))
}

fn dial_network(network: &str, raddr: &str) -> io::Result<Conn> {
    let local_stream = matches!(network, "unixgram" | "unix");
    let stream = match network {
        "udp" | "udp4" | "udp6" => {
            let addrs: Vec<_> = raddr.to_socket_addrs()?.collect();
            let addr = addrs
                .into_iter()
                .find(|a| match network {
                    "udp4" => a.is_ipv4(),
                    "udp6" => a.is_ipv6(),
                    _ => true,
                })
                .ok_or_else(|| io::Error::other(format!("no suitable address for {raddr}")))?;
            let bind = if addr.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let s = UdpSocket::bind(bind)?;
            s.connect(addr)?;
            Stream::Udp(s)
        }
        "tcp" | "tcp4" | "tcp6" => Stream::Tcp(TcpStream::connect(raddr)?),
        #[cfg(unix)]
        "unixgram" => {
            let s = UnixDatagram::unbound()?;
            s.connect(raddr)?;
            Stream::UnixDgram(s)
        }
        #[cfg(unix)]
        "unix" => Stream::Unix(UnixStream::connect(raddr)?),
        other => {
            return Err(io::Error::other(format!("unknown network {other}")));
        }
    };
    let local_addr = match &stream {
        Stream::Udp(s) => s.local_addr().map(|a| a.to_string()).unwrap_or_default(),
        Stream::Tcp(s) => s.local_addr().map(|a| a.to_string()).unwrap_or_default(),
        #[cfg(unix)]
        _ => String::new(),
    };
    Ok(Conn {
        local: local_stream,
        stream,
        local_addr,
    })
}

/// Go's `time.Stamp` layout, `Jan _2 15:04:05`.
fn stamp(t: &crate::time::DateTime) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{} {:2} {:02}:{:02}:{:02}",
        MONTHS[usize::from(t.month()) - 1],
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

/// Go's `time.RFC3339` layout, without a fractional second: `Z` for a zero
/// offset, otherwise `±hh:mm`.
fn rfc3339(t: &crate::time::DateTime) -> String {
    let offset = t.offset();
    let zone = if offset == 0 {
        "Z".to_owned()
    } else {
        let o = offset.abs();
        format!(
            "{}{:02}:{:02}",
            if offset < 0 { '-' } else { '+' },
            o / 3600,
            (o % 3600) / 60
        )
    };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{zone}",
        t.year(),
        t.month(),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

impl Writer {
    fn connect(&self, inner: &mut Inner) -> io::Result<()> {
        inner.conn = None;
        if self.network.is_empty() {
            let conn = unix_syslog()?;
            if inner.hostname.is_empty() {
                inner.hostname = "localhost".to_owned();
            }
            inner.conn = Some(conn);
        } else {
            let conn = dial_network(&self.network, &self.raddr)?;
            if inner.hostname.is_empty() {
                inner.hostname.clone_from(&conn.local_addr);
            }
            inner.conn = Some(conn);
        }
        Ok(())
    }

    /// Writes `b` at the priority the writer was opened with.
    pub fn write(&self, b: &[u8]) -> io::Result<usize> {
        self.write_and_retry(self.priority, &String::from_utf8_lossy(b))
    }

    /// Closes the connection to the syslog daemon.
    pub fn close(&self) -> io::Result<()> {
        lock(&self.inner).conn = None;
        Ok(())
    }

    /// Logs a message with severity `LOG_EMERG`, ignoring the severity passed to [`dial`].
    pub fn emerg(&self, m: &str) -> io::Result<()> {
        self.write_and_retry(LOG_EMERG, m).map(|_| ())
    }

    /// Logs a message with severity `LOG_ALERT`.
    pub fn alert(&self, m: &str) -> io::Result<()> {
        self.write_and_retry(LOG_ALERT, m).map(|_| ())
    }

    /// Logs a message with severity `LOG_CRIT`.
    pub fn crit(&self, m: &str) -> io::Result<()> {
        self.write_and_retry(LOG_CRIT, m).map(|_| ())
    }

    /// Logs a message with severity `LOG_ERR`.
    pub fn err(&self, m: &str) -> io::Result<()> {
        self.write_and_retry(LOG_ERR, m).map(|_| ())
    }

    /// Logs a message with severity `LOG_WARNING`.
    pub fn warning(&self, m: &str) -> io::Result<()> {
        self.write_and_retry(LOG_WARNING, m).map(|_| ())
    }

    /// Logs a message with severity `LOG_NOTICE`.
    pub fn notice(&self, m: &str) -> io::Result<()> {
        self.write_and_retry(LOG_NOTICE, m).map(|_| ())
    }

    /// Logs a message with severity `LOG_INFO`.
    pub fn info(&self, m: &str) -> io::Result<()> {
        self.write_and_retry(LOG_INFO, m).map(|_| ())
    }

    /// Logs a message with severity `LOG_DEBUG`.
    pub fn debug(&self, m: &str) -> io::Result<()> {
        self.write_and_retry(LOG_DEBUG, m).map(|_| ())
    }

    fn write_and_retry(&self, p: Priority, s: &str) -> io::Result<usize> {
        let pr = Priority((self.priority.0 & FACILITY_MASK) | (p.0 & SEVERITY_MASK));
        let mut inner = lock(&self.inner);
        if inner.conn.is_some() {
            if let Ok(n) = self.write_msg(&mut inner, pr, s) {
                return Ok(n);
            }
        }
        self.connect(&mut inner)?;
        self.write_msg(&mut inner, pr, s)
    }

    fn write_msg(&self, inner: &mut Inner, p: Priority, msg: &str) -> io::Result<usize> {
        let nl = if msg.ends_with('\n') { "" } else { "\n" };
        let now = now();
        let pid = std::process::id();
        let hostname = inner.hostname.clone();
        let conn = inner
            .conn
            .as_mut()
            .ok_or_else(|| io::Error::other("no connection"))?;
        let line = if conn.local {
            format!(
                "<{}>{} {}[{}]: {}{}",
                p.0,
                stamp(&now),
                self.tag,
                pid,
                msg,
                nl
            )
        } else {
            format!(
                "<{}>{} {} {}[{}]: {}{}",
                p.0,
                rfc3339(&now),
                hostname,
                self.tag,
                pid,
                msg,
                nl
            )
        };
        conn.stream.send(line.as_bytes())?;
        Ok(msg.len())
    }
}

impl Write for Writer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Writer::write(self, buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl std::fmt::Debug for Writer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Writer")
            .field("priority", &self.priority)
            .field("tag", &self.tag)
            .field("network", &self.network)
            .field("raddr", &self.raddr)
            .finish_non_exhaustive()
    }
}
