//! Probe for the `os` differential (`tools/os_check.py`): the counterpart of
//! `tools/os_oracle.go`.
use rust_stdlib::io::fs::{self, DirEntry, FileInfo};
use rust_stdlib::io::{ReadAt, WriteAt};
use rust_stdlib::os::{self, File, Root};
use rust_stdlib::path::filepath;
use std::io::{self, BufRead, Read, Seek, SeekFrom, Write};

fn enc(s: &str) -> String {
    s.bytes().map(|b| format!("{b:02x}")).collect()
}

fn hexb(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

fn dec(s: &str) -> String {
    let bytes: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect();
    String::from_utf8(bytes).expect("UTF-8 input")
}

/// Replaces runs of three or more digits by `#`.
fn norm(s: &str) -> String {
    let mut out = String::new();
    let b: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit() {
            let mut j = i;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            if j - i >= 3 {
                out.push('#');
            } else {
                out.extend(&b[i..j]);
            }
            i = j;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    out
}

fn flags(err: &io::Error) -> String {
    let mut s = String::new();
    let mut pred = |c: char, v: bool| {
        if v {
            s.push(c);
        }
    };
    pred('e', os::is_exist(err));
    pred('n', os::is_not_exist(err));
    pred('p', os::is_permission(err));
    pred('t', os::is_timeout(err));
    pred('E', fs::ERR_EXIST.is(err));
    pred('N', fs::ERR_NOT_EXIST.is(err));
    pred('P', fs::ERR_PERMISSION.is(err));
    pred('C', fs::ERR_CLOSED.is(err));
    pred('I', fs::ERR_INVALID.is(err));
    pred('F', rust_stdlib::io::is_eof(err));
    s
}

fn err_str(err: &io::Error) -> String {
    format!("err:{}:{}", flags(err), enc(&norm(&err.to_string())))
}

fn parse_mode(s: &str) -> fs::FileMode {
    fs::FileMode(u32::from_str_radix(s, 8).expect("octal"))
}

fn parse_flags(s: &str) -> i32 {
    let mut f = 0;
    if s.contains("RW") {
        f |= os::O_RDWR;
    } else if s.contains('W') {
        f |= os::O_WRONLY;
    }
    if s.contains('A') {
        f |= os::O_APPEND;
    }
    if s.contains('C') {
        f |= os::O_CREATE;
    }
    if s.contains('X') {
        f |= os::O_EXCL;
    }
    if s.contains('T') {
        f |= os::O_TRUNC;
    }
    f
}

fn describe(fi: &dyn FileInfo) -> String {
    let size = if fi.mode().is_regular() {
        fi.size()
    } else {
        -1
    };
    format!("{}|{}|{}|{}", enc(fi.name()), fi.mode(), size, fi.is_dir())
}

fn type_str(m: fs::FileMode) -> String {
    m.file_type().to_string()
}

fn res(r: io::Result<()>) -> String {
    match r {
        Ok(()) => "ok".into(),
        Err(e) => err_str(&e),
    }
}

fn entries(es: &[Box<dyn DirEntry>]) -> Vec<String> {
    es.iter()
        .map(|e| format!("{}/{}", e.name(), type_str(e.file_type())))
        .collect()
}

fn rel_wd(base: &str) -> String {
    match os::getwd() {
        Err(e) => err_str(&e),
        Ok(wd) => {
            let real = filepath::eval_symlinks(&wd).unwrap_or(wd);
            match filepath::rel(base, &real) {
                Ok(r) => format!("ok:{}", enc(&r)),
                Err(_) => "outside".into(),
            }
        }
    }
}

fn dump() -> String {
    let mut recs: Vec<String> = Vec::new();
    for item in filepath::WalkDir::new(".") {
        let p = match item {
            Ok(entry) => entry.path().to_string(),
            Err(e) => {
                recs.push(format!("E {}", norm(e.path())));
                continue;
            }
        };
        let p = p.as_str();
        let fi = match os::lstat(p) {
            Ok(fi) => fi,
            Err(_) => {
                recs.push(format!("E {}", norm(p)));
                continue;
            }
        };
        let mut rec = format!("{} {}", norm(p), fi.mode());
        if fi.mode().is_regular() {
            match os::read_file(p) {
                Ok(data) => rec.push_str(&format!(" {} {}", fi.size(), hexb(&data))),
                Err(_) => rec.push_str(" unreadable"),
            }
        } else if fi.mode().0 & fs::MODE_SYMLINK.0 != 0 {
            let t = os::readlink(p).unwrap_or_default();
            rec.push_str(&format!(" -> {t}"));
        }
        recs.push(rec);
    }
    recs.sort();
    enc(&recs.join("\n"))
}

fn file_ops(f: &mut File, script: &str) -> String {
    let mut out = Vec::new();
    for a in script.split(';') {
        if a.is_empty() {
            continue;
        }
        let p: Vec<&str> = a.split(':').collect();
        let r = match p[0] {
            "w" => {
                let data = dec(p[1]);
                match f.write(data.as_bytes()) {
                    Ok(n) => format!("w{n}"),
                    Err(e) => format!("w0{}", err_str(&e)),
                }
            }
            "ws" => {
                let data = dec(p[1]);
                match f.write(data.as_bytes()) {
                    Ok(n) => format!("ws{n}"),
                    Err(e) => format!("ws0{}", err_str(&e)),
                }
            }
            "r" => {
                let n: usize = p[1].parse().unwrap();
                let mut buf = vec![0u8; n];
                match f.read(&mut buf) {
                    // Go: a zero-length read at EOF is io.EOF for non-empty buffers.
                    Ok(0) if n > 0 => format!("r0:{}", err_str(&rust_stdlib::io::eof())),
                    Ok(k) => format!("r{k}:{}", hexb(&buf[..k])),
                    Err(e) => format!("r0:{}", err_str(&e)),
                }
            }
            "s" => {
                let off: i64 = p[1].parse().unwrap();
                let wh: i32 = p[2].parse().unwrap();
                let pos = match wh {
                    0 => SeekFrom::Start(off as u64),
                    1 => SeekFrom::Current(off),
                    _ => SeekFrom::End(off),
                };
                match f.seek(pos) {
                    Ok(n) => format!("s{n}"),
                    Err(e) => format!("s0{}", err_str(&e)),
                }
            }
            "ra" => {
                let off: i64 = p[1].parse().unwrap();
                let n: usize = p[2].parse().unwrap();
                let mut buf = vec![0u8; n];
                // Offsets above i64::MAX are Go's negative ones.
                let (k, e) = match f.read_at(&mut buf, off as u64) {
                    Ok(k) => (k, None),
                    Err(e) => (e.read(), Some(e.into_source())),
                };
                let mut r = format!("ra{k}:{}", hexb(&buf[..k]));
                if let Some(e) = e {
                    r.push_str(&err_str(&e));
                }
                r
            }
            "wa" => {
                let off: i64 = p[1].parse().unwrap();
                let data = dec(p[2]);
                let (k, e) = match f.write_at(data.as_bytes(), off as u64) {
                    Ok(()) => (data.len(), None),
                    Err(e) => (0, Some(e)),
                };
                let mut r = format!("wa{k}");
                if let Some(e) = e {
                    r.push_str(&err_str(&e));
                }
                r
            }
            "tr" => match f.truncate(p[1].parse().unwrap()) {
                Ok(()) => "tr-ok".into(),
                Err(e) => format!("tr{}", err_str(&e)),
            },
            "st" => match f.stat() {
                Ok(fi) => format!("st:{}", describe(fi.as_ref())),
                Err(e) => format!("st{}", err_str(&e)),
            },
            "sync" => match f.sync() {
                Ok(()) => "sync-ok".into(),
                Err(e) => format!("sync{}", err_str(&e)),
            },
            "chmod" => match f.chmod(parse_mode(p[1])) {
                Ok(()) => "chmod-ok".into(),
                Err(e) => format!("chmod{}", err_str(&e)),
            },
            "rd" | "rdn" | "rdi" => {
                let n: i32 = p[1].parse().unwrap();
                let (mut names, err) = match p[0] {
                    "rd" => match f.read_dir(n) {
                        Ok(es) => (entries(&es), None),
                        Err(e) => (Vec::new(), Some(e)),
                    },
                    "rdn" => match f.readdirnames(n) {
                        Ok(v) => (v, None),
                        Err(e) => (Vec::new(), Some(e)),
                    },
                    _ => match f.readdir(n) {
                        Ok(is) => (
                            is.iter()
                                .map(|i| format!("{}/{}", i.name(), i.mode()))
                                .collect(),
                            None,
                        ),
                        Err(e) => (Vec::new(), Some(e)),
                    },
                };
                names.sort();
                let mut r = format!("{}{}:{}", p[0], names.len(), enc(&names.join(",")));
                if let Some(e) = err {
                    r.push_str(&err_str(&e));
                }
                r
            }
            "c" => match f.close() {
                Ok(()) => "c-ok".into(),
                Err(e) => format!("c{}", err_str(&e)),
            },
            "name" => format!("name:{}", enc(f.name())),
            "dl" => match f.set_deadline(rust_stdlib::time::now()) {
                Ok(()) => "dl-ok".into(),
                Err(e) => format!("dl{}", err_str(&e)),
            },
            "rdl" => match f.set_read_deadline(Default::default()) {
                Ok(()) => "rdl-ok".into(),
                Err(e) => format!("rdl{}", err_str(&e)),
            },
            "all" => {
                let mut data = Vec::new();
                match f.read_to_end(&mut data) {
                    Ok(_) => format!("all{}:{}", data.len(), hexb(&data)),
                    Err(e) => format!("all{}:{}{}", data.len(), hexb(&data), err_str(&e)),
                }
            }
            "wt" => {
                let mut b = Vec::new();
                match f.write_to(&mut b) {
                    Ok(n) => format!("wt{n}:{}", hexb(&b)),
                    Err(e) => format!("wt{}:{}{}", b.len(), hexb(&b), err_str(&e)),
                }
            }
            "rf" => {
                let data = dec(p[1]);
                match f.read_from(&mut data.as_bytes()) {
                    Ok(n) => format!("rf{n}"),
                    Err(e) => format!("rf0{}", err_str(&e)),
                }
            }
            other => panic!("unknown file op {other}"),
        };
        out.push(r);
    }
    out.join(",")
}

struct State {
    base: String,
    root: Option<Root>,
}

fn run(st: &mut State, f: &[&str]) -> String {
    let get = |i: usize| f.get(i).map(|v| dec(v)).unwrap_or_default();
    match f[0] {
        "mkdir" => res(os::mkdir(&get(1), parse_mode(&get(2)))),
        "mkdirall" => res(os::mkdir_all(&get(1), parse_mode(&get(2)))),
        "writefile" => res(os::write_file(
            &get(1),
            get(2).as_bytes(),
            parse_mode(&get(3)),
        )),
        "readfile" => match os::read_file(&get(1)) {
            Ok(d) => format!("ok:{}", hexb(&d)),
            Err(e) => err_str(&e),
        },
        "remove" => res(os::remove(&get(1))),
        "removeall" => res(os::remove_all(&get(1))),
        "rename" => res(os::rename(&get(1), &get(2))),
        "link" => res(os::link(&get(1), &get(2))),
        "symlink" => res(os::symlink(&get(1), &get(2))),
        "readlink" => match os::readlink(&get(1)) {
            Ok(d) => format!("ok:{}", enc(&d)),
            Err(e) => err_str(&e),
        },
        "stat" | "lstat" => {
            let r = if f[0] == "stat" {
                os::stat(&get(1))
            } else {
                os::lstat(&get(1))
            };
            match r {
                Ok(fi) => format!("ok:{}", describe(fi.as_ref())),
                Err(e) => err_str(&e),
            }
        }
        "stattime" => match os::stat(&get(1)) {
            Ok(fi) => format!("ok:{}", fi.mod_time().unix()),
            Err(e) => err_str(&e),
        },
        "chmod" => res(os::chmod(&get(1), parse_mode(&get(2)))),
        "truncate" => res(os::truncate(&get(1), get(2).parse().unwrap())),
        "chtimes" => {
            let a: i64 = get(2).parse().unwrap();
            let m: i64 = get(3).parse().unwrap();
            let t = |v: i64| {
                if v == 0 {
                    rust_stdlib::time::Time::default()
                } else {
                    rust_stdlib::time::unix(v, 0)
                }
            };
            res(os::chtimes(&get(1), t(a), t(m)))
        }
        "readdir" => match os::read_dir(&get(1)) {
            Ok(es) => format!("ok:{}", enc(&entries(&es).join(","))),
            Err(e) => err_str(&e),
        },
        "samefile" => {
            let a = match os::stat(&get(1)) {
                Ok(a) => a,
                Err(e) => return err_str(&e),
            };
            match os::stat(&get(2)) {
                Ok(b) => format!("ok:{}", os::same_file(a.as_ref(), b.as_ref())),
                Err(e) => err_str(&e),
            }
        }
        "openw" => {
            let f = match os::open_file(&get(1), parse_flags(&get(2)), parse_mode(&get(3))) {
                Ok(f) => f,
                Err(e) => return err_str(&e),
            };
            let w = (&f).write(get(4).as_bytes());
            let c = f.close();
            let mut r = match &w {
                Ok(n) => format!("ok:{n}"),
                Err(_) => "ok:0".into(),
            };
            if let Err(e) = w {
                r.push_str(&format!(":w{}", err_str(&e)));
            }
            if let Err(e) = c {
                r.push_str(&format!(":c{}", err_str(&e)));
            }
            r
        }
        "file" => {
            let mut file = match os::open_file(&get(1), parse_flags(&get(2)), parse_mode(&get(3))) {
                Ok(f) => f,
                Err(e) => return err_str(&e),
            };
            let r = file_ops(&mut file, &get(4));
            format!("ok:{r}")
        }
        "createtemp" => match os::create_temp(&get(1), &get(2)) {
            Ok(f) => format!("ok:{}", enc(&norm(f.name()))),
            Err(e) => err_str(&e),
        },
        "mkdirtemp" => match os::mkdir_temp(&get(1), &get(2)) {
            Ok(n) => format!("ok:{}", enc(&norm(&n))),
            Err(e) => err_str(&e),
        },
        "chdir" => res(os::chdir(&get(1))),
        "getwd" => rel_wd(&st.base),
        "copyfs" => res(os::copy_fs(&get(2), &os::dir_fs(&get(1)))),
        "dirfsread" => match fs::read_file(&os::dir_fs(&get(1)), &get(2)) {
            Ok(d) => format!("ok:{}", hexb(&d)),
            Err(e) => err_str(&e),
        },
        "dirfsstat" => match fs::stat(&os::dir_fs(&get(1)), &get(2)) {
            Ok(fi) => format!("ok:{}", describe(fi.as_ref())),
            Err(e) => err_str(&e),
        },
        "dirfsreaddir" => match fs::read_dir(&os::dir_fs(&get(1)), &get(2)) {
            Ok(es) => format!("ok:{}", enc(&entries(&es).join(","))),
            Err(e) => err_str(e.source()),
        },
        "pipe" => match os::pipe() {
            Ok((r, w)) => {
                let _ = (&w).write(get(1).as_bytes());
                let _ = w.close();
                let mut d = Vec::new();
                let _ = (&r).read_to_end(&mut d);
                let _ = r.close();
                format!("ok:{}", hexb(&d))
            }
            Err(e) => err_str(&e),
        },
        "setenv" => res(os::setenv(&get(1), &get(2))),
        "unsetenv" => res(os::unsetenv(&get(1))),
        "getenv" => format!(
            "ok:{}",
            enc(&std::env::var_os(get(1))
                .map_or_else(String::new, |v| v.to_string_lossy().into_owned()))
        ),
        "lookupenv" => match std::env::var_os(get(1)).map(|v| v.to_string_lossy().into_owned()) {
            Some(v) => format!("ok:true:{}", enc(&v)),
            None => "ok:false:".into(),
        },
        "expand" => format!("ok:{}", enc(&os::expand(&get(1), |k| format!("<{k}>")))),
        "expandenv" => format!("ok:{}", enc(&os::expand_env(&get(1)))),
        "userdirs" => {
            let part = |r: io::Result<String>| match r {
                Ok(s) => enc(&s),
                Err(e) => format!("E{}", enc(&e.to_string())),
            };
            format!(
                "ok:{},{},{},{}",
                part(os::user_home_dir()),
                part(os::user_cache_dir()),
                part(os::user_config_dir()),
                enc(&os::temp_dir())
            )
        }
        "info" => {
            let mut g = os::getgroups().unwrap_or_default();
            g.sort();
            let g: Vec<String> = g.iter().map(|x| x.to_string()).collect();
            format!(
                "ok:{},{},{},{},{},[{}]",
                os::getuid(),
                os::geteuid(),
                os::getgid(),
                os::getegid(),
                os::getpagesize(),
                g.join(" ")
            )
        }
        "consts" => format!(
            "ok:{},{},{},{},{}",
            std::path::MAIN_SEPARATOR,
            ':',
            os::DEV_NULL,
            std::path::is_separator('/'),
            std::path::is_separator('a')
        ),
        "modes" => {
            let m = u32::from_str_radix(&get(1), 8).unwrap();
            let bits = [
                0,
                fs::MODE_DIR.0,
                fs::MODE_SYMLINK.0,
                fs::MODE_SETUID.0,
                fs::MODE_STICKY.0,
                fs::MODE_NAMED_PIPE.0,
                fs::MODE_SOCKET.0,
                fs::MODE_DEVICE.0 | fs::MODE_CHAR_DEVICE.0,
                fs::MODE_APPEND.0 | fs::MODE_EXCLUSIVE.0 | fs::MODE_TEMPORARY.0,
                fs::MODE_IRREGULAR.0,
                fs::MODE_SETGID.0,
            ];
            let out: Vec<String> = bits
                .iter()
                .map(|b| fs::FileMode(b | m).to_string())
                .collect();
            format!("ok:{}", enc(&out.join(",")))
        }
        // ---- Root ----
        "rootopen" => match os::open_root(&get(1)) {
            Ok(r) => {
                let name = r.name().to_string();
                st.root = Some(r);
                format!("ok:{}", enc(&name))
            }
            Err(e) => err_str(&e),
        },
        "rootclose" => res(st.root.as_ref().unwrap().close()),
        "rsub" => match st.root.as_ref().unwrap().open_root(&get(1)) {
            Ok(r) => format!("ok:{}", enc(r.name())),
            Err(e) => err_str(&e),
        },
        "rread" => match st.root.as_ref().unwrap().read_file(&get(1)) {
            Ok(d) => format!("ok:{}", hexb(&d)),
            Err(e) => err_str(&e),
        },
        "rwrite" => res(st.root.as_ref().unwrap().write_file(
            &get(1),
            get(2).as_bytes(),
            parse_mode(&get(3)),
        )),
        "rfile" => {
            match st.root.as_ref().unwrap().open_file(
                &get(1),
                parse_flags(&get(2)),
                parse_mode(&get(3)),
            ) {
                Ok(mut file) => {
                    let name = file.name().to_string();
                    let r = file_ops(&mut file, &get(4));
                    format!("ok:{}:{r}", enc(&name))
                }
                Err(e) => err_str(&e),
            }
        }
        "rcreate" => match st.root.as_ref().unwrap().create(&get(1)) {
            Ok(_) => "ok".into(),
            Err(e) => err_str(&e),
        },
        "rmkdir" => res(st
            .root
            .as_ref()
            .unwrap()
            .mkdir(&get(1), parse_mode(&get(2)))),
        "rmkdirall" => res(st
            .root
            .as_ref()
            .unwrap()
            .mkdir_all(&get(1), parse_mode(&get(2)))),
        "rstat" | "rlstat" => {
            let root = st.root.as_ref().unwrap();
            let r = if f[0] == "rstat" {
                root.stat(&get(1))
            } else {
                root.lstat(&get(1))
            };
            match r {
                Ok(fi) => format!("ok:{}", describe(fi.as_ref())),
                Err(e) => err_str(&e),
            }
        }
        "rreadlink" => match st.root.as_ref().unwrap().readlink(&get(1)) {
            Ok(d) => format!("ok:{}", enc(&d)),
            Err(e) => err_str(&e),
        },
        "rsymlink" => res(st.root.as_ref().unwrap().symlink(&get(1), &get(2))),
        "rlink" => res(st.root.as_ref().unwrap().link(&get(1), &get(2))),
        "rrename" => res(st.root.as_ref().unwrap().rename(&get(1), &get(2))),
        "rremove" => res(st.root.as_ref().unwrap().remove(&get(1))),
        "rremoveall" => res(st.root.as_ref().unwrap().remove_all(&get(1))),
        "rchmod" => res(st
            .root
            .as_ref()
            .unwrap()
            .chmod(&get(1), parse_mode(&get(2)))),
        "rfsread" => {
            let root = st.root.as_ref().unwrap();
            match fs::read_file(&root.fs(), &get(1)) {
                Ok(d) => format!("ok:{}", hexb(&d)),
                Err(e) => err_str(&e),
            }
        }
        "rfsreaddir" => {
            let root = st.root.as_ref().unwrap();
            match fs::read_dir(&root.fs(), &get(1)) {
                Ok(es) => format!("ok:{}", enc(&entries(&es).join(","))),
                Err(e) => err_str(e.source()),
            }
        }
        "inroot" => match os::open_in_root(&get(1), &get(2)) {
            Ok(file) => {
                let mut d = Vec::new();
                let _ = (&file).read_to_end(&mut d);
                format!("ok:{}", hexb(&d))
            }
            Err(e) => err_str(&e),
        },
        other => panic!("unknown op {other}"),
    }
}

fn main() {
    let base = os::getwd().expect("getwd");
    let base = filepath::eval_symlinks(&base).unwrap_or(base);
    let mut st = State {
        base: base.clone(),
        root: None,
    };
    let mut n = 0;
    let mut cur_dir = String::new();
    let out = io::stdout();
    let mut w = io::BufWriter::new(out.lock());
    for line in io::stdin().lock().lines() {
        let line = line.expect("stdin");
        let f: Vec<&str> = line.split('\t').collect();
        if f[0] == "NEW" {
            if n > 0 {
                let _ = os::chdir(&cur_dir);
                writeln!(w, "TREE|{}", dump()).unwrap();
            }
            let _ = os::chdir(&base);
            st.root = None;
            let dir = format!("s{n}");
            n += 1;
            os::mkdir(&dir, fs::FileMode(0o755)).expect("mkdir");
            os::chdir(&dir).expect("chdir");
            cur_dir = filepath::join(&[base.as_str(), dir.as_str()]);
            continue;
        }
        let r = run(&mut st, &f);
        writeln!(w, "{}|{}", f[0], r).unwrap();
    }
    if n > 0 {
        let _ = os::chdir(&cur_dir);
        writeln!(w, "TREE|{}", dump()).unwrap();
    }
}
