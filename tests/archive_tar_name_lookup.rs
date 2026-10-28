//! `tar::set_name_lookup` is process-wide, so it gets its own test binary.
#![cfg(unix)]

use rust_stdlib::archive::iofs::FsInfo;
use rust_stdlib::archive::tar::{file_info_header, set_name_lookup};
use rust_stdlib::io::fs::{DirFS, ReadLinkFS};
use std::os::unix::fs::MetadataExt;

fn names(path: &str) -> (String, String) {
    let fi = DirFS::new("/").lstat(path.trim_start_matches('/')).unwrap();
    let h = file_info_header(&FsInfo(fi), "").unwrap();
    (h.uname, h.gname)
}

#[test]
fn hook_replaces_the_etc_lookup() {
    let dir = std::env::temp_dir().join(format!("tar-name-lookup-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let owned = dir.join("owned");
    std::fs::write(&owned, b"x").unwrap();
    let owned = owned.to_str().unwrap().to_string();
    let meta = std::fs::metadata(&owned).unwrap();

    let passwd_uid = std::fs::metadata("/etc/passwd").unwrap().uid();
    if passwd_uid == 0 {
        assert_eq!(
            names("/etc/passwd").0,
            "root",
            "without a hook, /etc/passwd resolves uid 0"
        );
    }

    set_name_lookup(
        |uid| Some(format!("hook-u{uid}")),
        |gid| Some(format!("hook-g{gid}")),
    );
    assert_eq!(
        names(&owned),
        (
            format!("hook-u{}", meta.uid()),
            format!("hook-g{}", meta.gid())
        )
    );
    assert_eq!(names("/etc/passwd").0, format!("hook-u{passwd_uid}"));

    set_name_lookup(|_| None, |_| None);
    assert_eq!(
        names("/etc/passwd"),
        (String::new(), String::new()),
        "an installed hook replaces the /etc lookup rather than falling back to it"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
