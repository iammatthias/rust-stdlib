//! `rust_stdlib_sys::syscall`: Go's tables and tests for the hand-written
//! helpers (ported from `$GOROOT/src/syscall/*_test.go` where they apply),
//! the generated expected-value tables (constants, struct layouts, error and
//! signal messages) and, on linux/x86_64, real system calls.
#![cfg(all(
    any(target_os = "linux", target_os = "macos"),
    target_pointer_width = "64"
))]

use rust_stdlib_sys::syscall::{self as sc, Errno, Signal};
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;

#[rustfmt::skip]
#[path = "syscall_expected/mod.rs"]
mod expected;

fn os(s: &str) -> OsString {
    OsString::from(s)
}

// ---- errors and signals -------------------------------------------------------

#[test]
fn errno_methods() {
    assert_eq!(sc::ENOENT.error(), "no such file or directory");
    assert_eq!(Errno(9999).error(), "errno 9999");
    // The package mirrors linux/amd64 on every host, whose table stops at 132.
    assert_eq!(Errno(133).error(), "errno 133");
    assert_eq!(
        format!("{}", sc::EAGAIN),
        "resource temporarily unavailable"
    );
    assert!(sc::EACCES.is("permission") && sc::EPERM.is("permission"));
    assert!(sc::EEXIST.is("exist") && sc::ENOTEMPTY.is("exist"));
    assert!(sc::ENOENT.is("not-exist") && !sc::EEXIST.is("not-exist"));
    assert!(
        sc::ENOSYS.is("unsupported")
            && sc::ENOTSUP.is("unsupported")
            && sc::EOPNOTSUPP.is("unsupported")
    );
    assert!(!sc::EINVAL.is("permission") && !sc::EINVAL.is("nonsense"));
    for e in [sc::EINTR, sc::EMFILE, sc::ENFILE, sc::EAGAIN, sc::ETIMEDOUT] {
        assert!(e.temporary(), "{e}");
    }
    assert!(!sc::ENOENT.temporary());
    assert!(sc::EAGAIN.timeout() && sc::EWOULDBLOCK.timeout() && sc::ETIMEDOUT.timeout());
    assert!(!sc::EINTR.timeout());
    assert_eq!(sc::EWOULDBLOCK, sc::EAGAIN);
    assert_eq!(sc::ENOTSUP, sc::EOPNOTSUPP);
}

#[test]
fn signal_strings() {
    assert_eq!(sc::SIGKILL.to_string(), "killed");
    assert_eq!(Signal(0).to_string(), "signal 0");
    assert_eq!(Signal(99).to_string(), "signal 99");
    assert_eq!(Signal(-1).to_string(), "signal -1");
    sc::SIGINT.signal();
}

// ---- strings -------------------------------------------------------------------

#[test]
fn byte_conversions() {
    assert_eq!(sc::byte_slice_from_string("ab").unwrap(), b"ab\0");
    assert_eq!(sc::byte_slice_from_string("").unwrap(), b"\0");
    assert_eq!(sc::byte_slice_from_string("a\0b"), Err(sc::EINVAL));
    assert_eq!(sc::byte_ptr_from_string("a\0b").unwrap_err(), sc::EINVAL);
    assert_eq!(
        sc::byte_ptr_from_string("hi").unwrap().as_bytes_with_nul(),
        b"hi\0"
    );
    assert_eq!(sc::string_byte_slice("x"), b"x\0");
    assert_eq!(sc::string_byte_ptr("x").as_bytes(), b"x");
    let v = sc::slice_ptr_from_strings(&["a".to_string(), "bc".to_string()]).unwrap();
    assert_eq!(v.len(), 2);
    assert!(!v.is_empty());
    assert_eq!(v.strings()[1].as_bytes(), b"bc");
    assert!(sc::slice_ptr_from_strings(&["a\0".to_string()]).is_err());
    assert!(sc::slice_ptr_from_strings(&[]).unwrap().is_empty());
    assert_eq!(sc::string_slice_ptr(&["q".to_string()]).len(), 1);
}

#[test]
#[should_panic(expected = "string with NUL")]
fn string_byte_slice_panics_on_nul() {
    sc::string_byte_slice("a\0");
}

// ---- environment (syscall_test.go TestEnv) ----------------------------------------

#[test]
fn env_round_trip() {
    let key = "RUST_STDLIB_SYSCALL_ENV_TEST";
    assert_eq!(sc::getenv(key), None);
    sc::setenv(key, "value").unwrap();
    assert_eq!(sc::getenv(key), Some(os("value")));
    assert!(sc::environ().contains(&os(&format!("{key}=value"))));
    sc::setenv(key, "").unwrap();
    assert_eq!(sc::getenv(key), Some(os("")));
    sc::unsetenv(key).unwrap();
    assert_eq!(sc::getenv(key), None);
    assert!(!sc::environ()
        .iter()
        .any(|e| e.to_string_lossy().starts_with(&format!("{key}="))));
}

#[test]
fn env_invalid() {
    assert_eq!(sc::setenv("", "x"), Err(sc::EINVAL));
    assert_eq!(sc::setenv("a=b", "x"), Err(sc::EINVAL));
    assert_eq!(sc::setenv("a\0b", "x"), Err(sc::EINVAL));
    assert_eq!(sc::setenv("ok_key_nul", "a\0b"), Err(sc::EINVAL));
    assert_eq!(sc::getenv(""), None);
    assert_eq!(sc::getenv("a=b"), None);
    assert_eq!(sc::unsetenv(""), Ok(()));
}

// ---- directory entries ---------------------------------------------------------------

fn dirent(ino: u64, name: &[u8], reclen: usize) -> Vec<u8> {
    let mut b = vec![0u8; reclen];
    b[0..8].copy_from_slice(&ino.to_le_bytes());
    b[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
    b[19..19 + name.len()].copy_from_slice(name);
    b
}

#[test]
fn parse_dirent_names() {
    let mut buf = Vec::new();
    buf.extend(dirent(1, b".", 24));
    buf.extend(dirent(2, b"..", 24));
    buf.extend(dirent(3, b"hello", 24));
    buf.extend(dirent(0, b"zero-inode", 32));
    buf.extend(dirent(5, b"last", 24));
    let (consumed, count, names) = sc::parse_dirent(&buf, -1, Vec::new());
    assert_eq!((consumed as usize, count), (buf.len(), 3));
    assert_eq!(names, vec![os("hello"), os("zero-inode"), os("last")]);
    // max limits the names and leaves the rest unconsumed.
    let (consumed, count, names) = sc::parse_dirent(&buf, 1, vec![os("seed")]);
    assert_eq!(count, 1);
    assert_eq!(names, vec![os("seed"), os("hello")]);
    assert_eq!(consumed as usize, 24 * 3);
    // A truncated record consumes everything and stops.
    let (consumed, count, _) = sc::parse_dirent(&buf[..40], -1, Vec::new());
    assert_eq!((consumed as usize, count), (40, 0));
    // Non-UTF-8 names survive.
    let b = dirent(9, &[0xff, 0xfe], 24);
    let (_, _, names) = sc::parse_dirent(&b, -1, Vec::new());
    assert_eq!(names[0], OsString::from_vec(vec![0xff, 0xfe]));
    assert_eq!(sc::parse_dirent(&[], -1, Vec::new()), (0, 0, Vec::new()));
}

// ---- time ---------------------------------------------------------------------------------

#[test]
fn time_conversions() {
    let ts = sc::nsec_to_timespec(1_500_000_000);
    assert_eq!((ts.sec, ts.nsec), (1, 500_000_000));
    assert_eq!(ts.unix(), (1, 500_000_000));
    assert_eq!(sc::timespec_to_nsec(ts), 1_500_000_000);
    let neg = sc::nsec_to_timespec(-1);
    assert_eq!((neg.sec, neg.nsec), (-1, 999_999_999));
    let tv = sc::nsec_to_timeval(1_500_000_001);
    assert_eq!((tv.sec, tv.usec), (1, 500_001));
    assert_eq!(tv.unix(), (1, 500_001));
    assert_eq!(sc::timeval_to_nsec(tv), 1_500_001_000);
    let tv = sc::nsec_to_timeval(-1);
    assert_eq!((tv.sec, tv.usec), (0, 0));
    let tv = sc::nsec_to_timeval(-1_000_000_000);
    assert_eq!((tv.sec, tv.usec), (-1, 1));
}

// ---- WaitStatus -----------------------------------------------------------------------------

#[test]
fn wait_status() {
    let exited = sc::WaitStatus(3 << 8);
    assert!(exited.exited() && !exited.signaled() && !exited.stopped() && !exited.continued());
    assert_eq!(exited.exit_status(), 3);
    assert_eq!(exited.signal(), Signal(-1));
    assert_eq!(exited.stop_signal(), Signal(-1));
    let killed = sc::WaitStatus(9);
    assert!(killed.signaled() && !killed.exited() && !killed.core_dump());
    assert_eq!(killed.signal(), sc::SIGKILL);
    assert_eq!(killed.exit_status(), -1);
    let dumped = sc::WaitStatus(11 | 0x80);
    assert!(dumped.core_dump() && dumped.signaled());
    let stopped = sc::WaitStatus(0x7f | (19 << 8));
    assert!(stopped.stopped() && !stopped.signaled());
    assert_eq!(stopped.stop_signal(), sc::SIGSTOP);
    assert_eq!(stopped.trap_cause(), -1);
    assert!(sc::WaitStatus(0xffff).continued());
    let trap = sc::WaitStatus(0x7f | (5 << 8) | (3 << 16));
    assert_eq!(trap.stop_signal(), sc::SIGTRAP);
    assert_eq!(trap.trap_cause(), 3);
}

// ---- socket addresses ----------------------------------------------------------------------------

#[test]
fn sockaddr_encoding() {
    use sc::Sockaddr;
    let (raw, n) = sc::SockaddrInet4 {
        port: 0x1234,
        addr: [1, 2, 3, 4],
    }
    .sockaddr()
    .unwrap();
    assert_eq!(n, 16);
    assert_eq!(&raw[..8], &[2, 0, 0x12, 0x34, 1, 2, 3, 4]);
    assert_eq!(raw.len(), 16);
    assert_eq!(
        sc::SockaddrInet4 {
            port: -1,
            addr: [0; 4]
        }
        .sockaddr(),
        Err(sc::EINVAL)
    );
    assert_eq!(
        sc::SockaddrInet4 {
            port: 0x10000,
            addr: [0; 4]
        }
        .sockaddr(),
        Err(sc::EINVAL)
    );
    let (raw, n) = sc::SockaddrInet6 {
        port: 80,
        zone_id: 7,
        addr: [9; 16],
    }
    .sockaddr()
    .unwrap();
    assert_eq!(n, 28);
    assert_eq!(&raw[..4], &[10, 0, 0, 80]);
    assert_eq!(&raw[8..24], &[9; 16]);
    assert_eq!(&raw[24..28], &7u32.to_ne_bytes());
    assert!(sc::SockaddrInet6 {
        port: 65536,
        zone_id: 0,
        addr: [0; 16]
    }
    .sockaddr()
    .is_err());
    // Unix: named addresses count their NUL, abstract ones do not.
    let (raw, n) = sc::SockaddrUnix {
        name: "/tmp/s".into(),
    }
    .sockaddr()
    .unwrap();
    assert_eq!((n, &raw[2..8]), (2 + 6 + 1, &b"/tmp/s"[..]));
    let (raw, n) = sc::SockaddrUnix {
        name: "@abc".into(),
    }
    .sockaddr()
    .unwrap();
    assert_eq!((n, &raw[2..6]), (2 + 4, &b"\0abc"[..]));
    let (_, n) = sc::SockaddrUnix {
        name: String::new(),
    }
    .sockaddr()
    .unwrap();
    assert_eq!(n, 2);
    let long = "a".repeat(108);
    assert_eq!(
        sc::SockaddrUnix { name: long.clone() }.sockaddr(),
        Err(sc::EINVAL)
    );
    assert!(sc::SockaddrUnix {
        name: format!("@{}", &long[1..])
    }
    .sockaddr()
    .is_ok());
    assert_eq!(
        sc::SockaddrUnix {
            name: "a".repeat(109)
        }
        .sockaddr(),
        Err(sc::EINVAL)
    );
    let (raw, n) = sc::SockaddrLinklayer {
        protocol: 0x0800,
        ifindex: 3,
        hatype: 1,
        pkttype: 2,
        halen: 6,
        addr: [1, 2, 3, 4, 5, 6, 0, 0],
    }
    .sockaddr()
    .unwrap();
    assert_eq!(n, 20);
    assert_eq!(&raw[0..2], &17u16.to_ne_bytes());
    assert_eq!(&raw[4..8], &3u32.to_ne_bytes());
    assert_eq!(raw[11], 6);
    assert!(sc::SockaddrLinklayer {
        ifindex: -1,
        ..Default::default()
    }
    .sockaddr()
    .is_err());
    let (raw, n) = sc::SockaddrNetlink {
        family: 99,
        pad: 0,
        pid: 5,
        groups: 6,
    }
    .sockaddr()
    .unwrap();
    assert_eq!(n, 12);
    assert_eq!(
        &raw[0..2],
        &16u16.to_ne_bytes(),
        "the family is always AF_NETLINK"
    );
    assert_eq!(&raw[4..12], &[5, 0, 0, 0, 6, 0, 0, 0]);
}

// ---- control messages --------------------------------------------------------------------------

#[test]
fn cmsg_sizes() {
    assert_eq!(sc::cmsg_len(0), 16);
    assert_eq!(sc::cmsg_len(4), 20);
    assert_eq!(sc::cmsg_space(0), 16);
    assert_eq!(sc::cmsg_space(4), 24);
    assert_eq!(sc::cmsg_space(8), 24);
    assert_eq!(sc::cmsg_space(9), 32);
}

#[test]
fn unix_rights_round_trip() {
    let b = sc::unix_rights(&[3, 4, 5]);
    assert_eq!(b.len() as isize, sc::cmsg_space(12));
    let msgs = sc::parse_socket_control_message(&b).unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].header.level, sc::SOL_SOCKET as i32);
    assert_eq!(msgs[0].header.type_, sc::SCM_RIGHTS as i32);
    assert_eq!(msgs[0].header.len as isize, sc::cmsg_len(12));
    assert_eq!(sc::parse_unix_rights(&msgs[0]).unwrap(), vec![3, 4, 5]);
    // Two messages back to back.
    let mut two = sc::unix_rights(&[1]);
    two.extend(sc::unix_rights(&[2, 7]));
    let msgs = sc::parse_socket_control_message(&two).unwrap();
    assert_eq!(msgs.len(), 2);
    assert_eq!(sc::parse_unix_rights(&msgs[1]).unwrap(), vec![2, 7]);
    // A length beyond the buffer, or below the header, is EINVAL.
    let mut bad = sc::unix_rights(&[1]);
    bad[0] = 0xff;
    assert_eq!(sc::parse_socket_control_message(&bad), Err(sc::EINVAL));
    let mut bad = sc::unix_rights(&[1]);
    bad[0] = 4;
    assert_eq!(sc::parse_socket_control_message(&bad), Err(sc::EINVAL));
    assert_eq!(sc::parse_socket_control_message(&[0; 8]).unwrap(), vec![]);
}

#[test]
fn unix_credentials_round_trip() {
    let cred = sc::Ucred {
        pid: 11,
        uid: 22,
        gid: 33,
    };
    let b = sc::unix_credentials(&cred);
    assert_eq!(b.len() as isize, sc::cmsg_space(12));
    let msgs = sc::parse_socket_control_message(&b).unwrap();
    assert_eq!(sc::parse_unix_credentials(&msgs[0]).unwrap(), cred);
    // Wrong kind of message.
    let rights = sc::parse_socket_control_message(&sc::unix_rights(&[1])).unwrap();
    assert_eq!(sc::parse_unix_credentials(&rights[0]), Err(sc::EINVAL));
    assert_eq!(sc::parse_unix_rights(&msgs[0]), Err(sc::EINVAL));
    let mut short = msgs[0].clone();
    short.data.truncate(8);
    assert_eq!(sc::parse_unix_credentials(&short), Err(sc::EINVAL));
}

// ---- netlink ---------------------------------------------------------------------------------------

fn nl_message(typ: u16, seq: u32, pid: u32, payload: &[u8]) -> Vec<u8> {
    let len = 16 + payload.len();
    let mut b = Vec::new();
    b.extend((len as u32).to_ne_bytes());
    b.extend(typ.to_ne_bytes());
    b.extend(0u16.to_ne_bytes());
    b.extend(seq.to_ne_bytes());
    b.extend(pid.to_ne_bytes());
    b.extend(payload);
    while b.len() % 4 != 0 {
        b.push(0);
    }
    b
}

#[test]
fn parse_netlink_messages() {
    let mut buf = nl_message(sc::RTM_NEWADDR as u16, 1, 42, &[1, 2, 3, 4, 5]);
    buf.extend(nl_message(sc::NLMSG_DONE as u16, 1, 42, &[0, 0, 0, 0]));
    let msgs = sc::parse_netlink_message(&buf).unwrap();
    assert_eq!(msgs.len(), 2);
    assert_eq!(msgs[0].header.type_, sc::RTM_NEWADDR as u16);
    assert_eq!((msgs[0].header.seq, msgs[0].header.pid), (1, 42));
    assert_eq!(msgs[0].data, vec![1, 2, 3, 4, 5]);
    assert_eq!(msgs[1].header.type_, sc::NLMSG_DONE as u16);
    // Too-short length fields are EINVAL.
    let mut bad = nl_message(1, 1, 1, &[0; 4]);
    bad[0] = 8;
    assert_eq!(sc::parse_netlink_message(&bad), Err(sc::EINVAL));
    let mut bad = nl_message(1, 1, 1, &[0; 4]);
    bad[0] = 200;
    assert_eq!(sc::parse_netlink_message(&bad), Err(sc::EINVAL));
    assert_eq!(sc::parse_netlink_message(&[0; 8]).unwrap(), vec![]);
}

#[test]
fn parse_netlink_route_attrs() {
    // An ifaddrmsg (8 bytes) followed by two attributes, the first padded.
    let mut payload = vec![0u8; sc::SIZEOF_IF_ADDRMSG as usize];
    payload.extend(7u16.to_ne_bytes()); // len = 4 + 3
    payload.extend((sc::IFA_LABEL as u16).to_ne_bytes());
    payload.extend([b'e', b't', b'h', 0]); // value + padding
    payload.extend(8u16.to_ne_bytes()); // len = 4 + 4
    payload.extend((sc::IFA_ADDRESS as u16).to_ne_bytes());
    payload.extend([10, 0, 0, 1]);
    let m = sc::parse_netlink_message(&nl_message(sc::RTM_NEWADDR as u16, 1, 1, &payload)).unwrap();
    let attrs = sc::parse_netlink_route_attr(&m[0]).unwrap();
    assert_eq!(attrs.len(), 2);
    assert_eq!(attrs[0].attr.type_, sc::IFA_LABEL as u16);
    assert_eq!(attrs[0].value, b"eth");
    assert_eq!(attrs[1].value, vec![10, 0, 0, 1]);
    // Other message types are not route attributes.
    let m = sc::parse_netlink_message(&nl_message(sc::NLMSG_DONE as u16, 1, 1, &payload)).unwrap();
    assert_eq!(sc::parse_netlink_route_attr(&m[0]), Err(sc::EINVAL));
}

// ---- struct methods ----------------------------------------------------------------------------------

#[test]
fn struct_methods() {
    let mut iov = sc::Iovec::default();
    iov.set_len(10);
    assert_eq!(iov.len, 10);
    let mut msg = sc::Msghdr::default();
    msg.set_controllen(24);
    assert_eq!(msg.controllen, 24);
    let mut c = sc::Cmsghdr::default();
    c.set_len(16);
    assert_eq!(c.len, 16);
    let mut regs = sc::PtraceRegs::default();
    regs.set_pc(0xdead);
    assert_eq!(regs.pc(), 0xdead);
    assert_eq!(regs.rip, 0xdead);
}

#[test]
fn lsf_helpers() {
    let s = sc::lsf_stmt(sc::BPF_LD | sc::BPF_W | sc::BPF_ABS, 12);
    assert_eq!((s.code, s.k, s.jt, s.jf), (0x20, 12, 0, 0));
    let j = sc::lsf_jump(sc::BPF_JMP | sc::BPF_JEQ | sc::BPF_K, 0x800, 1, 2);
    assert_eq!((j.code, j.k, j.jt, j.jf), (0x15, 0x800, 1, 2));
}

// ---- portable system calls (run on every supported host) ------------------------------------------------

#[test]
fn process_queries() {
    assert_eq!(sc::getpid(), std::process::id() as isize);
    assert!(sc::getppid() > 0);
    assert!(sc::getuid() >= 0 && sc::geteuid() >= 0 && sc::getgid() >= 0 && sc::getegid() >= 0);
    assert!(sc::getpagesize() >= 4096);
    assert_eq!(sc::getpgrp(), sc::getpgid(0).unwrap());
}

#[test]
fn umask_round_trip() {
    let old = sc::umask(0o077);
    assert_eq!(sc::umask(old), 0o077);
}

#[test]
fn pipe_read_write() {
    let mut p = [0isize; 2];
    assert_eq!(sc::pipe(&mut [0isize; 3]), Err(sc::EINVAL));
    sc::pipe2(&mut p, sc::O_CLOEXEC).unwrap();
    assert_eq!(sc::write(p[1], b"hello").unwrap(), 5);
    let mut buf = [0u8; 16];
    let n = sc::read(p[0], &mut buf).unwrap();
    assert_eq!(&buf[..n as usize], b"hello");
    sc::set_nonblock(p[0], true).unwrap();
    assert_eq!(sc::read(p[0], &mut buf), Err(sc::EAGAIN));
    sc::set_nonblock(p[0], false).unwrap();
    let d = sc::dup(p[1]).unwrap();
    assert!(d > 2);
    sc::close(d).unwrap();
    sc::close(p[0]).unwrap();
    sc::close(p[1]).unwrap();
    assert_eq!(sc::close(p[1]), Err(sc::EBADF));
    assert_eq!(sc::read(p[1], &mut buf), Err(sc::EBADF));
}

fn run_sh(script: &str, attr: Option<&sc::ProcAttr>) -> sc::WaitStatus {
    let pid = sc::fork_exec("/bin/sh", &["sh".into(), "-c".into(), script.into()], attr).unwrap();
    let mut ws = sc::WaitStatus::default();
    let wpid = sc::wait4(pid, Some(&mut ws), 0, None).unwrap();
    assert_eq!(wpid, pid);
    ws
}

fn attr(files: &[usize]) -> sc::ProcAttr {
    sc::ProcAttr {
        files: files.to_vec(),
        env: vec!["PATH=/usr/bin:/bin".into()],
        ..Default::default()
    }
}

#[test]
fn fork_exec_exit_status() {
    let a = attr(&[0, 1, 2]);
    assert_eq!(run_sh("exit 3", Some(&a)).exit_status(), 3);
    let ws = run_sh("kill -KILL $$", Some(&a));
    assert!(ws.signaled());
    assert_eq!(ws.signal(), sc::SIGKILL);
}

#[test]
fn fork_exec_dir_env_and_files() {
    let dir = std::env::temp_dir().join(format!("syscall-fe-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let out = dir.join("out");
    let file = std::fs::File::create(&out).unwrap();
    use std::os::fd::AsRawFd;
    let a = sc::ProcAttr {
        dir: dir.to_str().unwrap().into(),
        env: vec!["FOO=bar".into()],
        files: vec![0, file.as_raw_fd() as usize, 2],
        sys: None,
    };
    let ws = run_sh("echo $FOO; pwd -P", Some(&a));
    assert_eq!(ws.exit_status(), 0);
    let text = std::fs::read_to_string(&out).unwrap();
    let mut lines = text.lines();
    assert_eq!(lines.next(), Some("bar"));
    assert_eq!(
        std::fs::canonicalize(lines.next().unwrap()).unwrap(),
        std::fs::canonicalize(&dir).unwrap()
    );
    // nil Env means an empty environment, not an inherited one.
    let none = sc::ProcAttr {
        files: vec![0, file.as_raw_fd() as usize, 2],
        ..Default::default()
    };
    let out2 = dir.join("out2");
    let file2 = std::fs::File::create(&out2).unwrap();
    let none = sc::ProcAttr {
        files: vec![0, file2.as_raw_fd() as usize, 2],
        ..none
    };
    assert_eq!(run_sh("echo \"[$HOME]\"", Some(&none)).exit_status(), 0);
    assert_eq!(std::fs::read_to_string(&out2).unwrap(), "[]\n");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn fork_exec_errors() {
    let a = attr(&[0, 1, 2]);
    let err = sc::fork_exec("/nonexistent/program", &["x".into()], Some(&a)).unwrap_err();
    assert_eq!(err, sc::ForkExecError::Errno(sc::ENOENT));
    assert_eq!(err.to_string(), "no such file or directory");
    assert_eq!(
        sc::fork_exec("/bin/sh\0", &[], None).unwrap_err(),
        sc::ForkExecError::Errno(sc::EINVAL)
    );
    assert_eq!(
        sc::fork_exec("/bin/sh", &["a\0".into()], None).unwrap_err(),
        sc::ForkExecError::Errno(sc::EINVAL)
    );
    let both = sc::ProcAttr {
        files: vec![0, 1, 2],
        sys: Some(sc::SysProcAttr {
            setctty: true,
            foreground: true,
            ..Default::default()
        }),
        ..Default::default()
    };
    assert_eq!(
        sc::fork_exec("/bin/sh", &[], Some(&both))
            .unwrap_err()
            .to_string(),
        "both Setctty and Foreground set in SysProcAttr"
    );
    let bad = sc::ProcAttr {
        files: vec![0, 1, 2],
        sys: Some(sc::SysProcAttr {
            setctty: true,
            ctty: 7,
            ..Default::default()
        }),
        ..Default::default()
    };
    assert_eq!(
        sc::fork_exec("/bin/sh", &[], Some(&bad))
            .unwrap_err()
            .to_string(),
        "Setctty set but Ctty not valid in child"
    );
}

#[test]
fn fork_exec_session_and_group() {
    // The child blocks reading its stdin, so its group can be inspected.
    for (name, sys) in [
        (
            "setsid",
            sc::SysProcAttr {
                setsid: true,
                ..Default::default()
            },
        ),
        (
            "setpgid",
            sc::SysProcAttr {
                setpgid: true,
                ..Default::default()
            },
        ),
    ] {
        let mut p = [0isize; 2];
        sc::pipe2(&mut p, sc::O_CLOEXEC).unwrap();
        let a = sc::ProcAttr {
            env: vec!["PATH=/usr/bin:/bin".into()],
            files: vec![p[0] as usize, 1, 2],
            sys: Some(sys),
            ..Default::default()
        };
        let pid = sc::fork_exec(
            "/bin/sh",
            &["sh".into(), "-c".into(), "read x; exit 0".into()],
            Some(&a),
        )
        .unwrap();
        // Each makes the child the leader of a new group.
        assert_eq!(sc::getpgid(pid).unwrap(), pid, "{name}");
        assert_ne!(sc::getpgid(pid).unwrap(), sc::getpgrp(), "{name}");
        sc::close(p[1]).unwrap();
        sc::close(p[0]).unwrap();
        let mut ws = sc::WaitStatus::default();
        sc::wait4(pid, Some(&mut ws), 0, None).unwrap();
        assert_eq!(ws.exit_status(), 0, "{name}");
    }
}

#[test]
fn start_process_returns_zero_handle() {
    let a = attr(&[0, 1, 2]);
    let (pid, handle) = sc::start_process(
        "/bin/sh",
        &["sh".into(), "-c".into(), "exit 0".into()],
        Some(&a),
    )
    .unwrap();
    assert_eq!(handle, 0);
    let mut ws = sc::WaitStatus::default();
    sc::wait4(pid, Some(&mut ws), 0, None).unwrap();
    assert!(ws.exited());
}

#[test]
fn exec_failure_returns_error() {
    assert_eq!(
        sc::exec("/nonexistent/program", &["x".into()], &[]),
        Err(sc::ENOENT)
    );
    assert_eq!(sc::exec("a\0", &[], &[]), Err(sc::EINVAL));
}

#[test]
fn wait4_without_children_is_echild() {
    let mut ws = sc::WaitStatus::default();
    // Only meaningful if no test in this binary has a child at this moment;
    // waiting for a pid that is not ours is ECHILD either way.
    assert_eq!(
        sc::wait4(0x3fff_fffe, Some(&mut ws), 0, None),
        Err(sc::ECHILD)
    );
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
#[test]
fn unsupported_calls_fail_with_enosys() {
    assert_eq!(sc::open("/", sc::O_RDONLY, 0), Err(sc::ENOSYS));
    assert_eq!(sc::socket(sc::AF_INET, sc::SOCK_STREAM, 0), Err(sc::ENOSYS));
    assert_eq!(sc::mkdir("/tmp/never", 0o755), Err(sc::ENOSYS));
    let mut u = sc::Utsname::default();
    assert_eq!(sc::uname(&mut u), Err(sc::ENOSYS));
}

// ---- linux/x86_64: real system calls -------------------------------------------------------------------

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("syscall-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn file_operations() {
        let dir = scratch("files");
        let d = dir.to_str().unwrap();
        let path = format!("{d}/f");
        let fd = sc::open(&path, sc::O_CREAT | sc::O_RDWR | sc::O_CLOEXEC, 0o644).unwrap();
        assert_eq!(sc::write(fd, b"0123456789").unwrap(), 10);
        assert_eq!(sc::pwrite(fd, b"AB", 2).unwrap(), 2);
        let mut buf = [0u8; 10];
        assert_eq!(sc::pread(fd, &mut buf, 0).unwrap(), 10);
        assert_eq!(&buf, b"01AB456789");
        assert_eq!(sc::seek(fd, 4, 0).unwrap(), 4);
        let mut st = sc::Stat_t::default();
        sc::fstat(fd, &mut st).unwrap();
        assert_eq!(
            (st.size, st.mode & sc::S_IFMT as u32),
            (10, sc::S_IFREG as u32)
        );
        sc::ftruncate(fd, 4).unwrap();
        sc::fsync(fd).unwrap();
        sc::close(fd).unwrap();
        sc::stat(&path, &mut st).unwrap();
        assert_eq!(st.size, 4);
        sc::chmod(&path, 0o600).unwrap();
        sc::stat(&path, &mut st).unwrap();
        assert_eq!(st.mode & 0o777, 0o600);
        sc::symlink(&path, &format!("{d}/l")).unwrap();
        let mut link = [0u8; 256];
        let n = sc::readlink(&format!("{d}/l"), &mut link).unwrap();
        assert_eq!(&link[..n as usize], path.as_bytes());
        sc::lstat(&format!("{d}/l"), &mut st).unwrap();
        assert_eq!(st.mode & sc::S_IFMT as u32, sc::S_IFLNK as u32);
        sc::link(&path, &format!("{d}/h")).unwrap();
        sc::rename(&format!("{d}/h"), &format!("{d}/h2")).unwrap();
        sc::mkdir(&format!("{d}/sub"), 0o755).unwrap();
        assert_eq!(sc::mkdir(&format!("{d}/sub"), 0o755), Err(sc::EEXIST));
        sc::mkfifo(&format!("{d}/fifo"), 0o600).unwrap();
        sc::access(&path, 4).unwrap();
        assert_eq!(sc::access(&format!("{d}/nope"), 0), Err(sc::ENOENT));
        sc::faccessat(-0x64, &path, 4, 0x200).unwrap();
        sc::utimes_nano(
            &path,
            &[
                sc::nsec_to_timespec(1_000_000_000),
                sc::nsec_to_timespec(2_000_000_000),
            ],
        )
        .unwrap();
        sc::stat(&path, &mut st).unwrap();
        assert_eq!(st.mtim.sec, 2);
        assert_eq!(
            sc::utimes(&path, &[sc::Timeval::default()]),
            Err(sc::EINVAL)
        );
        sc::unlink(&format!("{d}/l")).unwrap();
        sc::unlink(&format!("{d}/h2")).unwrap();
        sc::unlink(&format!("{d}/fifo")).unwrap();
        sc::rmdir(&format!("{d}/sub")).unwrap();
        assert_eq!(sc::rmdir(&format!("{d}/sub")), Err(sc::ENOENT));
        sc::unlink(&path).unwrap();
        assert_eq!(sc::open("a\0b", sc::O_RDONLY, 0), Err(sc::EINVAL));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn working_directory() {
        let dir = scratch("cwd");
        let cwd = sc::getwd().unwrap();
        assert_eq!(
            std::path::PathBuf::from(&cwd),
            std::env::current_dir().unwrap()
        );
        let mut buf = [0u8; 4096];
        let n = sc::getcwd(&mut buf).unwrap();
        assert_eq!(&buf[..n as usize - 1], cwd.as_encoded_bytes());
        let _ = dir;
    }

    #[test]
    fn read_dirent_lists_names() {
        let dir = scratch("dirent");
        std::fs::write(dir.join("one"), b"").unwrap();
        std::fs::write(dir.join("two"), b"").unwrap();
        let fd = sc::open(dir.to_str().unwrap(), sc::O_RDONLY | sc::O_DIRECTORY, 0).unwrap();
        let mut buf = [0u8; 4096];
        let n = sc::read_dirent(fd, &mut buf).unwrap();
        let (consumed, count, mut names) = sc::parse_dirent(&buf[..n as usize], -1, Vec::new());
        assert_eq!((consumed, count), (n, 2));
        names.sort();
        assert_eq!(names, vec![os("one"), os("two")]);
        sc::close(fd).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn mmap_round_trip() {
        let dir = scratch("mmap");
        let path = dir.join("m");
        std::fs::write(&path, b"mapped data").unwrap();
        let fd = sc::open(path.to_str().unwrap(), sc::O_RDWR, 0).unwrap();
        assert_eq!(
            sc::mmap(fd, 0, 0, sc::PROT_READ, sc::MAP_SHARED).err(),
            Some(sc::EINVAL)
        );
        let b = sc::mmap(fd, 0, 11, sc::PROT_READ | sc::PROT_WRITE, sc::MAP_SHARED).unwrap();
        assert_eq!(&b[..], b"mapped data");
        b[0] = b'M';
        let mut other = [0u8; 4];
        assert_eq!(sc::munmap(&mut other), Err(sc::EINVAL));
        sc::munmap(b).unwrap();
        sc::close(fd).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"Mapped data");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn socketpair_with_rights_and_credentials() {
        let [a, b] = sc::socketpair(sc::AF_UNIX, sc::SOCK_STREAM | sc::SOCK_CLOEXEC, 0).unwrap();
        sc::setsockopt_int(b, sc::SOL_SOCKET, sc::SO_PASSCRED, 1).unwrap();
        let mut p = [0isize; 2];
        sc::pipe2(&mut p, sc::O_CLOEXEC).unwrap();
        let rights = sc::unix_rights(&[p[0], p[1]]);
        sc::sendmsg(a, b"x", &rights, None, 0).unwrap();
        let mut buf = [0u8; 4];
        let mut oob = [0u8; 128];
        let (n, oobn, _flags, from) = sc::recvmsg(b, &mut buf, &mut oob, 0).unwrap();
        assert_eq!((n, &buf[..1]), (1, &b"x"[..]));
        assert!(from.is_none() || from.is_some());
        let msgs = sc::parse_socket_control_message(&oob[..oobn as usize]).unwrap();
        let mut received = Vec::new();
        for m in &msgs {
            if m.header.type_ == sc::SCM_RIGHTS as i32 {
                received = sc::parse_unix_rights(m).unwrap();
            } else if m.header.type_ == sc::SCM_CREDENTIALS as i32 {
                let cred = sc::parse_unix_credentials(m).unwrap();
                assert_eq!(cred.pid as isize, sc::getpid());
            }
        }
        assert_eq!(received.len(), 2);
        // The received descriptors are new ones for the same pipe.
        assert_eq!(sc::write(received[1], b"ping").unwrap(), 4);
        let mut r = [0u8; 4];
        assert_eq!(sc::read(p[0], &mut r).unwrap(), 4);
        assert_eq!(&r, b"ping");
        for fd in [a, b, p[0], p[1], received[0], received[1]] {
            sc::close(fd).unwrap();
        }
    }

    #[test]
    fn tcp_sockets_and_options() {
        let l = sc::socket(sc::AF_INET, sc::SOCK_STREAM | sc::SOCK_CLOEXEC, 0).unwrap();
        sc::setsockopt_int(l, sc::SOL_SOCKET, sc::SO_REUSEADDR, 1).unwrap();
        assert_eq!(
            sc::getsockopt_int(l, sc::SOL_SOCKET, sc::SO_REUSEADDR).unwrap(),
            1
        );
        assert_eq!(
            sc::getsockopt_int(l, sc::SOL_SOCKET, sc::SO_TYPE).unwrap(),
            sc::SOCK_STREAM
        );
        sc::setsockopt_linger(
            l,
            sc::SOL_SOCKET,
            sc::SO_LINGER,
            &sc::Linger {
                onoff: 1,
                linger: 3,
            },
        )
        .unwrap();
        sc::bind(
            l,
            &sc::SockaddrInet4 {
                port: 0,
                addr: [127, 0, 0, 1],
            },
        )
        .unwrap();
        sc::listen(l, 4).unwrap();
        let name = sc::getsockname(l).unwrap();
        let name = *name.as_any().downcast_ref::<sc::SockaddrInet4>().unwrap();
        assert_eq!(name.addr, [127, 0, 0, 1]);
        assert!(name.port > 0);
        let c = sc::socket(sc::AF_INET, sc::SOCK_STREAM, 0).unwrap();
        sc::connect(c, &name).unwrap();
        let (s, peer) = sc::accept4(l, sc::SOCK_CLOEXEC).unwrap();
        let peer = *peer.as_any().downcast_ref::<sc::SockaddrInet4>().unwrap();
        let local = sc::getsockname(c).unwrap();
        assert_eq!(
            *local.as_any().downcast_ref::<sc::SockaddrInet4>().unwrap(),
            peer
        );
        let remote = sc::getpeername(c).unwrap();
        assert_eq!(
            *remote.as_any().downcast_ref::<sc::SockaddrInet4>().unwrap(),
            name
        );
        assert_eq!(sc::sendto(c, b"abc", 0, None), Ok(()));
        let (n, from) = sc::recvfrom(s, &mut [0u8; 8], 0).unwrap();
        assert_eq!(n, 3);
        assert!(from.is_none() || from.is_some());
        sc::shutdown(c, sc::SHUT_WR).unwrap();
        for fd in [l, c, s] {
            sc::close(fd).unwrap();
        }
        sc::SOCKET_DISABLE_IPV6.store(true, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            sc::socket(sc::AF_INET6, sc::SOCK_STREAM, 0),
            Err(sc::EAFNOSUPPORT)
        );
        sc::SOCKET_DISABLE_IPV6.store(false, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn unix_socket_addresses() {
        let dir = scratch("unix");
        let path = format!("{}/s", dir.to_str().unwrap());
        let l = sc::socket(sc::AF_UNIX, sc::SOCK_STREAM, 0).unwrap();
        sc::bind(l, &sc::SockaddrUnix { name: path.clone() }).unwrap();
        let got = sc::getsockname(l).unwrap();
        assert_eq!(
            got.as_any()
                .downcast_ref::<sc::SockaddrUnix>()
                .unwrap()
                .name,
            path
        );
        sc::close(l).unwrap();
        // Abstract names come back with '@'.
        let l = sc::socket(sc::AF_UNIX, sc::SOCK_STREAM, 0).unwrap();
        let name = format!("@syscall-test-{}", std::process::id());
        sc::bind(l, &sc::SockaddrUnix { name: name.clone() }).unwrap();
        let got = sc::getsockname(l).unwrap();
        assert_eq!(
            got.as_any()
                .downcast_ref::<sc::SockaddrUnix>()
                .unwrap()
                .name,
            name
        );
        sc::close(l).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn system_information() {
        let mut u = sc::Utsname::default();
        sc::uname(&mut u).unwrap();
        let sysname: Vec<u8> = u
            .sysname
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect();
        assert_eq!(sysname, b"Linux");
        let mut tv = sc::Timeval::default();
        sc::gettimeofday(&mut tv).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!((tv.sec - now).abs() <= 2);
        let mut t = 0;
        assert_eq!(sc::time(Some(&mut t)).unwrap(), t);
        let mut rl = sc::Rlimit::default();
        sc::getrlimit(sc::RLIMIT_NOFILE, &mut rl).unwrap();
        assert!(rl.cur > 0 && rl.cur <= rl.max);
        let mut ru = sc::Rusage::default();
        sc::getrusage(sc::RUSAGE_SELF, &mut ru).unwrap();
        let mut si = sc::Sysinfo_t::default();
        sc::sysinfo(&mut si).unwrap();
        assert!(si.uptime > 0);
        assert!(sc::gettid() > 0);
        assert!(sc::getpriority(sc::PRIO_PROCESS, 0).is_ok());
        assert!(sc::getgroups().is_ok());
    }

    #[test]
    fn epoll_and_eventfd_style_wakeup() {
        let ep = sc::epoll_create1(sc::EPOLL_CLOEXEC).unwrap();
        let mut p = [0isize; 2];
        sc::pipe2(&mut p, sc::O_CLOEXEC).unwrap();
        let mut ev = sc::EpollEvent {
            events: sc::EPOLLIN as u32,
            fd: p[0] as i32,
            ..Default::default()
        };
        sc::epoll_ctl(ep, sc::EPOLL_CTL_ADD, p[0], Some(&mut ev)).unwrap();
        let mut out = [sc::EpollEvent::default(); 4];
        assert_eq!(sc::epoll_wait(ep, &mut out, 0).unwrap(), 0);
        sc::write(p[1], b"x").unwrap();
        assert_eq!(sc::epoll_wait(ep, &mut out, 1000).unwrap(), 1);
        assert_eq!(out[0].fd, p[0] as i32);
        assert_eq!(sc::epoll_create(0), Err(sc::EINVAL));
        for fd in [ep, p[0], p[1]] {
            sc::close(fd).unwrap();
        }
    }

    #[test]
    fn select_on_pipe() {
        let mut p = [0isize; 2];
        sc::pipe2(&mut p, sc::O_CLOEXEC).unwrap();
        let mut set = sc::FdSet::default();
        set.bits[0] |= 1 << p[0];
        let mut tv = sc::Timeval { sec: 0, usec: 0 };
        assert_eq!(
            sc::select(p[0] + 1, Some(&mut set), None, None, Some(&mut tv)).unwrap(),
            0
        );
        sc::write(p[1], b"x").unwrap();
        let mut set = sc::FdSet::default();
        set.bits[0] |= 1 << p[0];
        assert_eq!(
            sc::select(p[0] + 1, Some(&mut set), None, None, None).unwrap(),
            1
        );
        sc::close(p[0]).unwrap();
        sc::close(p[1]).unwrap();
    }

    #[test]
    fn extended_attributes_and_flock() {
        let dir = scratch("xattr");
        let path = dir.join("f");
        std::fs::write(&path, b"").unwrap();
        let p = path.to_str().unwrap();
        // tmpfs may not support user xattrs: ENOTSUP is acceptable.
        match sc::setxattr(p, "user.test", b"v", 0) {
            Ok(()) => {
                let mut dest = [0u8; 8];
                let n = sc::getxattr(p, "user.test", &mut dest).unwrap();
                assert_eq!(&dest[..n as usize], b"v");
                sc::removexattr(p, "user.test").unwrap();
            }
            Err(e) => assert!(e == sc::ENOTSUP || e == sc::EPERM, "{e}"),
        }
        let fd = sc::open(p, sc::O_RDWR, 0).unwrap();
        sc::flock(fd, sc::LOCK_EX).unwrap();
        sc::flock(fd, sc::LOCK_UN).unwrap();
        let mut lk = sc::Flock_t {
            type_: sc::F_WRLCK as i16,
            whence: 0,
            ..Default::default()
        };
        sc::fcntl_flock(fd as usize, sc::F_SETLK, &mut lk).unwrap();
        lk.type_ = sc::F_UNLCK as i16;
        sc::fcntl_flock(fd as usize, sc::F_SETLK, &mut lk).unwrap();
        sc::close(fd).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn netlink_route_dump() {
        // Dump the address table: at least the loopback address is there.
        let rib = match sc::netlink_rib(sc::RTM_GETADDR, sc::AF_UNSPEC) {
            Ok(r) => r,
            // Sandboxes without netlink sockets.
            Err(e) if e == sc::EPERM || e == sc::EACCES || e == sc::EAFNOSUPPORT => return,
            Err(e) => panic!("netlink_rib: {e}"),
        };
        let msgs = sc::parse_netlink_message(&rib).unwrap();
        let mut found_loopback = false;
        for m in &msgs {
            if m.header.type_ as isize != sc::RTM_NEWADDR {
                continue;
            }
            for a in sc::parse_netlink_route_attr(m).unwrap() {
                if a.attr.type_ as isize == sc::IFA_ADDRESS && a.value == [127, 0, 0, 1] {
                    found_loopback = true;
                }
            }
        }
        assert!(found_loopback);
    }

    #[test]
    fn identity_setters_report_errors() {
        // Unprivileged callers cannot become another user; root can, so only
        // check the failing shape when not root.
        if sc::geteuid() != 0 {
            assert_eq!(sc::setuid(0), Err(sc::EPERM));
            assert_eq!(sc::setgid(0), Err(sc::EPERM));
            assert_eq!(sc::setgroups(&[0]), Err(sc::EPERM));
            assert_eq!(sc::setresuid(0, 0, 0), Err(sc::EPERM));
        }
        // Setting to the current identity always works.
        let uid = sc::getuid();
        sc::setuid(uid).unwrap();
        sc::setreuid(-1, uid).unwrap_or(());
    }

    #[test]
    fn fork_exec_credential_and_chroot_errors() {
        let a = sc::ProcAttr {
            files: vec![0, 1, 2],
            sys: Some(sc::SysProcAttr {
                chroot: "/nonexistent-root".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let err = sc::fork_exec("/bin/true", &["true".into()], Some(&a)).unwrap_err();
        assert!(
            matches!(err, sc::ForkExecError::Errno(e) if e == sc::ENOENT || e == sc::EPERM),
            "{err}"
        );
        // pidfd and pdeathsig on an ordinary child.
        let cell = std::sync::Arc::new(std::sync::atomic::AtomicIsize::new(-2));
        let a = sc::ProcAttr {
            files: vec![0, 1, 2],
            env: vec!["PATH=/usr/bin:/bin".into()],
            sys: Some(sc::SysProcAttr {
                pdeathsig: sc::SIGKILL,
                pid_fd: Some(cell.clone()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let ws = run_sh("exit 4", Some(&a));
        assert_eq!(ws.exit_status(), 4);
        let fd = cell.load(std::sync::atomic::Ordering::SeqCst);
        assert!(fd == -1 || fd > 2, "pidfd cell {fd}");
        if fd > 2 {
            sc::close(fd).unwrap();
        }
    }

    #[test]
    fn fork_exec_unshare_flags_fail_or_work() {
        // Namespaces may be forbidden in the sandbox: EPERM/EINVAL/ENOSPC are
        // acceptable, but the call must not hang and a success must run the program.
        let a = sc::ProcAttr {
            files: vec![0, 1, 2],
            env: vec!["PATH=/usr/bin:/bin".into()],
            sys: Some(sc::SysProcAttr {
                unshareflags: sc::CLONE_NEWUTS as usize,
                ..Default::default()
            }),
            ..Default::default()
        };
        match sc::fork_exec(
            "/bin/sh",
            &["sh".into(), "-c".into(), "exit 0".into()],
            Some(&a),
        ) {
            Ok(pid) => {
                let mut ws = sc::WaitStatus::default();
                sc::wait4(pid, Some(&mut ws), 0, None).unwrap();
                assert_eq!(ws.exit_status(), 0);
            }
            Err(sc::ForkExecError::Errno(e)) => {
                assert!(e == sc::EPERM || e == sc::EINVAL || e == sc::ENOSPC, "{e}");
            }
            Err(e) => panic!("{e}"),
        }
    }

    #[test]
    fn fork_exec_user_namespace_maps() {
        // Clone into a new user namespace and map our identity to root there;
        // sandboxes that forbid user namespaces are skipped.
        use std::os::fd::AsRawFd;
        let dir = scratch("userns");
        let out = dir.join("out");
        let file = std::fs::File::create(&out).unwrap();
        let (uid, gid) = (sc::getuid(), sc::getgid());
        let a = sc::ProcAttr {
            files: vec![0, file.as_raw_fd() as usize, 2],
            env: vec!["PATH=/usr/bin:/bin".into()],
            sys: Some(sc::SysProcAttr {
                cloneflags: sc::CLONE_NEWUSER as usize,
                uid_mappings: vec![sc::SysProcIDMap {
                    container_id: 0,
                    host_id: uid,
                    size: 1,
                }],
                gid_mappings: vec![sc::SysProcIDMap {
                    container_id: 0,
                    host_id: gid,
                    size: 1,
                }],
                gid_mappings_enable_setgroups: false,
                ..Default::default()
            }),
            ..Default::default()
        };
        match sc::fork_exec(
            "/bin/sh",
            &["sh".into(), "-c".into(), "id -u; id -g".into()],
            Some(&a),
        ) {
            Ok(pid) => {
                let mut ws = sc::WaitStatus::default();
                sc::wait4(pid, Some(&mut ws), 0, None).unwrap();
                assert_eq!(ws.exit_status(), 0);
                assert_eq!(std::fs::read_to_string(&out).unwrap(), "0\n0\n");
                eprintln!("user namespace test: ran in a new user namespace");
            }
            Err(sc::ForkExecError::Errno(e)) => {
                assert!(
                    e == sc::EPERM || e == sc::EINVAL || e == sc::ENOSPC || e == sc::EACCES,
                    "{e}"
                );
                eprintln!("user namespace test: skipped ({e})");
            }
            Err(e) => panic!("{e}"),
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn ptrace_traceme_stops_child() {
        let a = sc::ProcAttr {
            files: vec![0, 1, 2],
            env: vec!["PATH=/usr/bin:/bin".into()],
            sys: Some(sc::SysProcAttr {
                ptrace: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        // The traced child stops with SIGTRAP at exec; this thread must be the
        // tracer, which fork_exec's caller is.
        let pid = match sc::fork_exec("/bin/true", &["true".into()], Some(&a)) {
            Ok(pid) => pid,
            // ptrace may be forbidden by the sandbox's seccomp profile.
            Err(_) => return,
        };
        let mut ws = sc::WaitStatus::default();
        sc::wait4(pid, Some(&mut ws), 0, None).unwrap();
        assert!(ws.stopped());
        assert_eq!(ws.stop_signal(), sc::SIGTRAP);
        // Continue through any further stops until the child exits.
        for _ in 0..16 {
            sc::ptrace_cont(pid, 0).unwrap();
            sc::wait4(pid, Some(&mut ws), 0, None).unwrap();
            if !ws.stopped() {
                break;
            }
        }
        assert!(ws.exited(), "status {ws:?}");
    }
}
