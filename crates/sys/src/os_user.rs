//! Go's `os/user`: user account lookups by name or id.
//!
//! This is Go's cgo build (the default on Linux and macOS): lookups go
//! through the C library (`getpwuid_r`, `getpwnam_r`, `getgrgid_r`,
//! `getgrnam_r`, `getgrouplist`), so accounts known only to the system's name
//! service (NSS, LDAP, Open Directory) resolve, with Go's buffer-growth loop
//! and error texts. Go's pure `osusergo` build, which parses `/etc/passwd`
//! and `/etc/group` itself, is not provided.
use crate::errno::{Errno, ENOENT, ERANGE};
use crate::ffi::user as ffi;
use std::fmt;
use std::io;
use std::sync::OnceLock;

/// A user account (`user.User`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct User {
    /// The user's id, a decimal number (`User.Uid`).
    pub uid: String,
    /// The primary group id (`User.Gid`).
    pub gid: String,
    /// The login name (`User.Username`).
    pub username: String,
    /// The real or display name, possibly empty (`User.Name`).
    pub name: String,
    /// The home directory (`User.HomeDir`).
    pub home_dir: String,
}

/// A group of users (`user.Group`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Group {
    /// The group id, a decimal number (`Group.Gid`).
    pub gid: String,
    /// The group name (`Group.Name`).
    pub name: String,
}

macro_rules! unknown_error {
    ($(#[$m:meta])* $name:ident($ty:ty), $fmt:expr) => {
        $(#[$m])*
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct $name(pub $ty);

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, $fmt, self.0)
            }
        }

        impl std::error::Error for $name {}

        impl From<$name> for io::Error {
            fn from(e: $name) -> io::Error {
                io::Error::other(e)
            }
        }
    };
}

unknown_error!(
    /// No user has this numeric id (`user.UnknownUserIdError`).
    UnknownUserIdError(i64),
    "user: unknown userid {}"
);
unknown_error!(
    /// No user has this name (`user.UnknownUserError`).
    UnknownUserError(String),
    "user: unknown user {}"
);
unknown_error!(
    /// No group has this id (`user.UnknownGroupIdError`).
    UnknownGroupIdError(String),
    "group: unknown groupid {}"
);
unknown_error!(
    /// No group has this name (`user.UnknownGroupError`).
    UnknownGroupError(String),
    "group: unknown group {}"
);

/// A failure that can be cached and handed out again.
#[derive(Clone)]
enum Failure {
    UnknownUserId(i64),
    UnknownUser(String),
    UnknownGroupId(String),
    UnknownGroup(String),
    Other(String),
}

impl From<Failure> for io::Error {
    fn from(f: Failure) -> io::Error {
        match f {
            Failure::UnknownUserId(i) => UnknownUserIdError(i).into(),
            Failure::UnknownUser(s) => UnknownUserError(s).into(),
            Failure::UnknownGroupId(s) => UnknownGroupIdError(s).into(),
            Failure::UnknownGroup(s) => UnknownGroupError(s).into(),
            Failure::Other(s) => io::Error::other(s),
        }
    }
}

type Res<T> = Result<T, Failure>;

fn other<T>(msg: String) -> Res<T> {
    Err(Failure::Other(msg))
}

/// Go's `strconv.Quote` for the text this package quotes.
fn quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\x07' => out.push_str("\\a"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x0b' => out.push_str("\\v"),
            c if c.is_control() && (c as u32) < 0x80 => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c if c.is_control() => {
                if (c as u32) <= 0xffff {
                    out.push_str(&format!("\\u{:04x}", c as u32))
                } else {
                    out.push_str(&format!("\\U{:08x}", c as u32))
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Go's `strconv.Atoi` on a 64-bit system, with its error text.
fn atoi(s: &str) -> Res<i64> {
    let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
    let fail = |why: &str| {
        other(format!(
            "strconv.Atoi: parsing {}: {why}",
            quote(s)
        ))
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return fail("invalid syntax");
    }
    let mut n: i64 = 0;
    for b in digits.bytes() {
        let d = i64::from(b - b'0');
        let next = if s.starts_with('-') {
            n.checked_mul(10).and_then(|n| n.checked_sub(d))
        } else {
            n.checked_mul(10).and_then(|n| n.checked_add(d))
        };
        match next {
            Some(v) => n = v,
            None => return fail("value out of range"),
        }
    }
    Ok(n)
}

const MAX_BUFFER_SIZE: usize = 1 << 20;

fn is_size_reasonable(sz: i64) -> bool {
    sz > 0 && sz <= MAX_BUFFER_SIZE as i64
}

/// The size of the first lookup buffer (`bufferKind.initialSize`).
fn initial_size(key: i32) -> usize {
    let sz = ffi::sysconf(key);
    if sz == -1 {
        return 1024;
    }
    if !is_size_reasonable(sz) {
        return MAX_BUFFER_SIZE;
    }
    sz as usize
}

/// Why a buffered lookup failed.
enum Retry {
    Errno(Errno),
    TooBig,
}

impl fmt::Display for Retry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Retry::Errno(e) => e.fmt(f),
            Retry::TooBig => write!(f, "internal buffer exceeds {MAX_BUFFER_SIZE} bytes"),
        }
    }
}

/// Go's `retryWithBuffer`: calls `f` with a buffer that doubles on `ERANGE`
/// until it succeeds, fails otherwise, or the buffer is too big.
fn retry_with_buffer<T>(
    key: i32,
    f: impl Fn(&mut [u8]) -> Result<Option<T>, Errno>,
) -> Result<Option<T>, Retry> {
    let mut buf = vec![0u8; initial_size(key)];
    loop {
        match f(&mut buf) {
            Ok(found) => return Ok(found),
            Err(e) if e == ERANGE => {}
            Err(e) => return Err(Retry::Errno(e)),
        }
        let new_size = buf.len() * 2;
        if !is_size_reasonable(new_size as i64) {
            return Err(Retry::TooBig);
        }
        buf = vec![0u8; new_size];
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn build_user(p: ffi::Passwd) -> User {
    let gecos = text(&p.gecos);
    // The pw_gecos field is a comma-separated list; the name is its first item.
    let name = gecos.split(',').next().unwrap_or("").to_string();
    User {
        uid: p.uid.to_string(),
        gid: p.gid.to_string(),
        username: text(&p.name),
        name,
        home_dir: text(&p.dir),
    }
}

fn build_group(g: ffi::Group) -> Group {
    Group {
        gid: i64::from(g.gid).to_string(),
        name: text(&g.name),
    }
}

fn lookup_unix_uid(uid: i64) -> Res<User> {
    let r = retry_with_buffer(ffi::SC_GETPW_R_SIZE_MAX, |buf| {
        ffi::getpwuid_r(uid as u32, buf)
    });
    match r {
        Ok(Some(p)) => Ok(build_user(p)),
        Ok(None) | Err(Retry::Errno(ENOENT)) => Err(Failure::UnknownUserId(uid)),
        Err(e) => other(format!("user: lookup userid {uid}: {e}")),
    }
}

fn lookup_user(username: &str) -> Res<User> {
    let r = retry_with_buffer(ffi::SC_GETPW_R_SIZE_MAX, |buf| {
        ffi::getpwnam_r(username.as_bytes(), buf)
    });
    match r {
        Ok(Some(p)) => Ok(build_user(p)),
        Ok(None) | Err(Retry::Errno(ENOENT)) => Err(Failure::UnknownUser(username.to_string())),
        Err(e) => other(format!("user: lookup username {username}: {e}")),
    }
}

fn lookup_unix_gid(gid: i64) -> Res<Group> {
    let r = retry_with_buffer(ffi::SC_GETGR_R_SIZE_MAX, |buf| {
        ffi::getgrgid_r(gid as u32, buf)
    });
    match r {
        Ok(Some(g)) => Ok(build_group(g)),
        Ok(None) | Err(Retry::Errno(ENOENT)) => Err(Failure::UnknownGroupId(gid.to_string())),
        Err(e) => other(format!("user: lookup groupid {gid}: {e}")),
    }
}

fn lookup_group_name(name: &str) -> Res<Group> {
    let r = retry_with_buffer(ffi::SC_GETGR_R_SIZE_MAX, |buf| {
        ffi::getgrnam_r(name.as_bytes(), buf)
    });
    match r {
        Ok(Some(g)) => Ok(build_group(g)),
        Ok(None) | Err(Retry::Errno(ENOENT)) => Err(Failure::UnknownGroup(name.to_string())),
        Err(e) => other(format!("user: lookup groupname {name}: {e}")),
    }
}

impl PartialEq<Errno> for Retry {
    fn eq(&self, other: &Errno) -> bool {
        matches!(self, Retry::Errno(e) if e == other)
    }
}

fn current_user() -> Res<User> {
    lookup_unix_uid(crate::os::getuid())
}

/// Returns the current user (`user.Current`). The result is cached.
pub fn current() -> io::Result<User> {
    static CACHE: OnceLock<Res<User>> = OnceLock::new();
    CACHE.get_or_init(current_user).clone().map_err(Into::into)
}

/// Looks up a user by username (`user.Lookup`).
pub fn lookup(username: &str) -> io::Result<User> {
    if let Ok(u) = current() {
        if u.username == username {
            return Ok(u);
        }
    }
    lookup_user(username).map_err(Into::into)
}

/// Looks up a user by user id (`user.LookupId`).
pub fn lookup_id(uid: &str) -> io::Result<User> {
    if let Ok(u) = current() {
        if u.uid == uid {
            return Ok(u);
        }
    }
    atoi(uid)
        .and_then(lookup_unix_uid)
        .map_err(Into::into)
}

/// Looks up a group by name (`user.LookupGroup`).
pub fn lookup_group(name: &str) -> io::Result<Group> {
    lookup_group_name(name).map_err(Into::into)
}

/// Looks up a group by group id (`user.LookupGroupId`).
pub fn lookup_group_id(gid: &str) -> io::Result<Group> {
    atoi(gid).and_then(lookup_unix_gid).map_err(Into::into)
}

const MAX_GROUPS: i32 = 2048;

impl User {
    /// The ids of the groups the user is a member of, as `getgrouplist`
    /// reports them (`User.GroupIds`).
    pub fn group_ids(&self) -> io::Result<Vec<String>> {
        list_groups(self).map_err(Into::into)
    }
}

fn list_groups(u: &User) -> Res<Vec<String>> {
    let ug = match atoi(&u.gid) {
        Ok(v) => v,
        Err(_) => {
            return other(format!(
                "user: list groups for {}: invalid gid {}",
                u.username,
                quote(&u.gid)
            ))
        }
    };
    let user_gid = ug as u32;
    let mut n: i32 = 256;
    let mut gids = vec![0u32; n as usize];
    let rv = ffi::getgrouplist(u.username.as_bytes(), user_gid, &mut gids, &mut n);
    if rv == -1 {
        // macOS does not set n properly here, so Go retries with whatever n
        // holds, bounded by MAX_GROUPS.
        if n > MAX_GROUPS {
            return other(format!(
                "user: {} is a member of more than {MAX_GROUPS} groups",
                quote(&u.username)
            ));
        }
        gids = vec![0u32; n.max(0) as usize];
        let rv = ffi::getgrouplist(u.username.as_bytes(), user_gid, &mut gids, &mut n);
        if rv == -1 {
            return other(format!("user: list groups for {} failed", u.username));
        }
    }
    gids.truncate(n.max(0) as usize);
    Ok(gids.iter().map(|g| g.to_string()).collect())
}
