//! Name lookups for `archive/tar` headers: Go's pure-Go `os/user` parser
//! (the `osusergo` build, which `tools/check_archive_api.py` compares with via
//! `CGO_ENABLED=0`) over `/etc/passwd` and `/etc/group`.
//!
//! The public `os/user` is `rust_stdlib_sys::os::user`, which goes through the
//! C library; the root crate has no FFI, so `tar` keeps this parser as the
//! default for its best-effort Uname and Gname. An id /etc/passwd does not
//! list resolves only for the current user (via `$USER`), where Go asks the C
//! library (NSS, macOS Open Directory) for any id;
//! `archive::tar::set_name_lookup` installs the sys crate's lookups instead.

use std::io::Read;

fn read_file(path: &str) -> Option<String> {
    let f = super::open(path).ok()?;
    let mut data = Vec::new();
    (&f).read_to_end(&mut data).ok()?;
    Some(String::from_utf8_lossy(&data).into_owned())
}

fn is_int(s: &str) -> bool {
    let t = s.strip_prefix(['+', '-']).unwrap_or(s);
    !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()) && s.parse::<i64>().is_ok()
}

/// Lines worth parsing: trimmed, non-empty, not comments.
fn lines(data: &str) -> impl Iterator<Item = &str> {
    data.split('\n')
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
}

/// The name of the group line with this id (Go's `matchGroupIndexValue`).
fn match_group_id(line: &str, id: &str) -> Option<String> {
    if line.matches(':').count() < 3 {
        return None;
    }
    let parts: Vec<&str> = line.splitn(4, ':').collect();
    if parts.len() < 4
        || parts[0].is_empty()
        || parts[2] != id
        || parts[0].starts_with(['+', '-'])
        || !is_int(parts[2])
    {
        return None;
    }
    Some(parts[0].to_string())
}

/// The login name of the passwd line with this id (Go's `matchUserIndexValue`).
fn match_user_id(line: &str, id: &str) -> Option<String> {
    if line.matches(':').count() < 6 {
        return None;
    }
    let parts: Vec<&str> = line.splitn(7, ':').collect();
    if parts.len() < 6
        || parts[2] != id
        || parts[0].is_empty()
        || parts[0].starts_with(['+', '-'])
        || !is_int(parts[2])
        || !is_int(parts[3])
    {
        return None;
    }
    Some(parts[0].to_string())
}

/// The name of the group with this decimal id, if `/etc/group` lists it.
pub(crate) fn group_name(gid: &str) -> Option<String> {
    let data = read_file("/etc/group")?;
    let name = lines(&data).find_map(|l| match_group_id(l, gid));
    name
}

/// The login name of the user with this decimal id, if `/etc/passwd` lists it.
pub(crate) fn user_name(uid: &str) -> Option<String> {
    uid.parse::<i32>().ok()?;
    let listed =
        read_file("/etc/passwd").and_then(|data| lines(&data).find_map(|l| match_user_id(l, uid)));
    if listed.is_some() {
        return listed;
    }
    // Go's pure `Current` falls back to $USER and $HOME for an id that
    // /etc/passwd does not list (accounts kept by Open Directory, LDAP, ...).
    let me = super::getuid();
    let user = super::getenv("USER");
    let home = super::user_home_dir().unwrap_or_default();
    (me >= 0 && me.to_string() == uid && !user.is_empty() && !home.is_empty()).then_some(user)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_like_go() {
        assert_eq!(
            match_user_id("root:x:0:0:r:/root:/bin/sh", "0").as_deref(),
            Some("root")
        );
        assert_eq!(match_user_id("root:x:0:0:r:/root", "1"), None);
        assert_eq!(
            match_user_id("+x:x:5:5:::", "5"),
            None,
            "NIS entries are skipped"
        );
        assert_eq!(
            match_user_id("a:x:5:y:::", "5"),
            None,
            "gid must be a number"
        );
        assert_eq!(
            match_group_id("wheel:x:10:a,b", "10").as_deref(),
            Some("wheel")
        );
        assert_eq!(match_group_id("wheel:x:q:a", "q"), None);
        assert_eq!(match_group_id("-wheel:x:10:", "10"), None);
    }
}
