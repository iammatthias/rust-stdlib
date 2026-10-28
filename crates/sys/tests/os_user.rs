//! Tests for `rust_stdlib_sys::os::user`, after Go's `user_test.go` and
//! `cgo_lookup_unix_test.go` (the libc-backed lookups). The Go differential in
//! `tools/os_user_check.py` compares them with Go's cgo build.
#![cfg(all(
    any(target_os = "linux", target_os = "macos"),
    target_pointer_width = "64"
))]

use rust_stdlib_sys::os::user::{self, Group, User};

#[test]
fn error_messages() {
    assert_eq!(
        user::UnknownUserIdError(42).to_string(),
        "user: unknown userid 42"
    );
    assert_eq!(
        user::UnknownUserError("bob".into()).to_string(),
        "user: unknown user bob"
    );
    assert_eq!(
        user::UnknownGroupIdError("7".into()).to_string(),
        "group: unknown groupid 7"
    );
    assert_eq!(
        user::UnknownGroupError("g".into()).to_string(),
        "group: unknown group g"
    );
}

#[test]
fn current_user() {
    let u = user::current().expect("the current uid resolves through libc");
    assert!(!u.uid.is_empty() && !u.gid.is_empty() && !u.username.is_empty());
    assert_eq!(u.uid.parse::<i64>().unwrap(), rust_stdlib_sys::os::getuid());
    assert_eq!(user::current().unwrap(), u, "Current is cached");
    // Lookup by the current name and id shortcut to the same user.
    assert_eq!(user::lookup(&u.username).unwrap(), u);
    assert_eq!(user::lookup_id(&u.uid).unwrap(), u);
}

#[test]
fn lookups_through_libc() {
    let u = user::lookup("root").unwrap();
    assert_eq!((u.username.as_str(), u.uid.as_str()), ("root", "0"));
    assert_eq!(user::lookup_id("0").unwrap().username, "root");
    // Go's Atoi accepts a sign and leading zeros.
    assert_eq!(user::lookup_id("+0").unwrap().username, "root");
    assert_eq!(user::lookup_id("00").unwrap().username, "root");
    assert_eq!(
        user::lookup("no-such-user-xyz").unwrap_err().to_string(),
        "user: unknown user no-such-user-xyz"
    );
    assert_eq!(
        user::lookup_id("99999").unwrap_err().to_string(),
        "user: unknown userid 99999"
    );
    assert_eq!(
        user::lookup_id("abc").unwrap_err().to_string(),
        "strconv.Atoi: parsing \"abc\": invalid syntax"
    );
    assert_eq!(
        user::lookup_id("99999999999999999999")
            .unwrap_err()
            .to_string(),
        "strconv.Atoi: parsing \"99999999999999999999\": value out of range"
    );
    let g = user::lookup_group_id(&u.gid);
    if let Ok(g) = g {
        assert_eq!(
            user::lookup_group(&g.name).unwrap(),
            Group {
                gid: g.gid.clone(),
                name: g.name.clone()
            }
        );
    }
    assert_eq!(
        user::lookup_group("no-such-group-xyz")
            .unwrap_err()
            .to_string(),
        "group: unknown group no-such-group-xyz"
    );
    assert_eq!(
        user::lookup_group_id("99999").unwrap_err().to_string(),
        "group: unknown groupid 99999"
    );
}

#[test]
fn unknown_errors_are_typed() {
    let e = user::lookup("no-such-user-xyz").unwrap_err();
    assert_eq!(
        e.get_ref()
            .and_then(|e| e.downcast_ref::<user::UnknownUserError>()),
        Some(&user::UnknownUserError("no-such-user-xyz".into()))
    );
}

#[test]
fn group_ids_lists_primary_first() {
    let u = user::current().unwrap();
    let ids = u.group_ids().unwrap();
    assert_eq!(ids[0], u.gid, "{ids:?}");
    let mut seen = ids.clone();
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len(), ids.len(), "no duplicates: {ids:?}");
    let bad = User {
        username: "x".into(),
        gid: "notanumber".into(),
        ..Default::default()
    };
    assert_eq!(
        bad.group_ids().unwrap_err().to_string(),
        "user: list groups for x: invalid gid \"notanumber\""
    );
}
