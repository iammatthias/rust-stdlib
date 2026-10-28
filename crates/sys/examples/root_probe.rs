//! Rust side of the os.Root differential (tools/os_check.py): reads the root
//! scripts, one tab separated hex-encoded operation per line, and prints one
//! result line per operation plus a TREE line per script, matching
//! tools/os_oracle.go.

#[cfg(not(all(
    any(target_os = "linux", target_os = "macos"),
    target_pointer_width = "64"
)))]
fn main() {}

#[cfg(all(
    any(target_os = "linux", target_os = "macos"),
    target_pointer_width = "64"
))]
mod probe {
    use rust_stdlib_sys::os::{self, FileMode, Root, RootError};
    use std::io::{BufRead, Write};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
    use std::path::{Path, PathBuf};

    fn enc(s: &[u8]) -> String {
        s.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn dec(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    /// Replaces every run of three or more digits with '#'.
    fn norm(s: &str) -> String {
        let mut out = String::new();
        let chars: Vec<char> = s.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            if chars[i].is_ascii_digit() {
                let mut j = i;
                while j < chars.len() && chars[j].is_ascii_digit() {
                    j += 1;
                }
                if j - i >= 3 {
                    out.push('#');
                } else {
                    out.extend(&chars[i..j]);
                }
                i = j;
            } else {
                out.push(chars[i]);
                i += 1;
            }
        }
        out
    }

    fn err_str(e: &RootError) -> String {
        let mut flags = String::new();
        let mut pred = |c: char, v: bool| {
            if v {
                flags.push(c)
            }
        };
        pred('e', e.is_exist());
        pred('n', e.is_not_exist());
        pred('p', e.is_permission());
        pred('t', e.is_timeout());
        pred('E', e.err_is_exist());
        pred('N', e.err_is_not_exist());
        pred('P', e.err_is_permission());
        pred('C', e.is_closed());
        pred('I', e.is_invalid());
        format!("err:{flags}:{}", enc(norm(&e.to_string()).as_bytes()))
    }

    fn res(r: Result<(), RootError>) -> String {
        match r {
            Ok(()) => "ok".into(),
            Err(e) => err_str(&e),
        }
    }

    fn parse_mode(s: &str) -> u32 {
        u32::from_str_radix(s, 8).unwrap()
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

    fn describe(fi: &os::FileInfo) -> String {
        let size = if fi.mode().is_regular() {
            fi.size()
        } else {
            -1
        };
        format!(
            "{}|{}|{}|{}",
            enc(fi.name().as_bytes()),
            fi.mode(),
            size,
            fi.is_dir()
        )
    }

    fn file_ops(f: &os::File, script: &str) -> String {
        let mut out = Vec::new();
        for a in script.split(';') {
            if a.is_empty() {
                continue;
            }
            let p: Vec<&str> = a.split(':').collect();
            let r = match p[0] {
                "w" => match f.write(&dec(p[1])) {
                    Ok(n) => format!("w{n}"),
                    Err(e) => format!("w0{}", err_str(&RootError::File(e))),
                },
                "st" => match f.stat() {
                    Ok(fi) => format!("st:{}", describe(&fi)),
                    Err(e) => format!("st{}", err_str(&RootError::File(e))),
                },
                "name" => format!("name:{}", enc(f.name().as_bytes())),
                other => panic!("unknown file op {other}"),
            };
            out.push(r);
        }
        out.join(",")
    }

    fn dump(dir: &Path) -> String {
        let mut recs = Vec::new();
        fn walk(base: &Path, rel: &str, hint_dir: bool, recs: &mut Vec<String>) {
            let full = if rel == "." {
                base.to_path_buf()
            } else {
                base.join(rel)
            };
            let md = std::fs::symlink_metadata(&full).ok();
            let is_dir = match &md {
                Some(md) => {
                    let mode = FileMode::from_unix_mode(md.mode());
                    let mut rec = format!("{} {}", norm(rel), mode);
                    if md.file_type().is_symlink() {
                        let t = std::fs::read_link(&full).unwrap_or_default();
                        rec.push_str(&format!(" -> {}", t.to_string_lossy()));
                    } else if md.is_file() {
                        match std::fs::read(&full) {
                            Ok(data) => rec.push_str(&format!(" {} {}", md.len(), enc(&data))),
                            Err(_) => rec.push_str(" unreadable"),
                        }
                    }
                    recs.push(rec);
                    md.is_dir()
                }
                None => {
                    recs.push(format!("E {}", norm(rel)));
                    hint_dir
                }
            };
            if is_dir {
                // Go's WalkDir reports a directory it cannot read once more.
                match std::fs::read_dir(&full) {
                    Err(_) => recs.push(format!("E {}", norm(rel))),
                    Ok(rd) => {
                        for e in rd.flatten() {
                            let n = e.file_name().to_string_lossy().into_owned();
                            let child = if rel == "." { n } else { format!("{rel}/{n}") };
                            let dir_hint = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
                            walk(base, &child, dir_hint, recs);
                        }
                    }
                }
            }
        }
        walk(dir, ".", true, &mut recs);
        recs.sort();
        enc(recs.join("\n").as_bytes())
    }

    fn run(f: &[&str], root: &mut Option<Root>) -> String {
        let get = |i: usize| -> String {
            f.get(i)
                .map(|s| String::from_utf8_lossy(&dec(s)).into_owned())
                .unwrap_or_default()
        };
        let io_res = |r: std::io::Result<()>| match r {
            Ok(()) => "ok".to_string(),
            Err(e) => format!("err::{}", enc(e.to_string().as_bytes())),
        };
        match f[0] {
            "mkdir" => io_res(
                std::fs::DirBuilder::new()
                    .mode(parse_mode(&get(2)))
                    .create(get(1)),
            ),
            "writefile" => io_res(
                std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(parse_mode(&get(3)))
                    .open(get(1))
                    .and_then(|mut fl| fl.write_all(get(2).as_bytes())),
            ),
            "symlink" => io_res(std::os::unix::fs::symlink(get(1), get(2))),
            "rootopen" => match os::open_root(&get(1)) {
                Ok(r) => {
                    let name = enc(r.name().as_bytes());
                    *root = Some(r);
                    format!("ok:{name}")
                }
                Err(e) => err_str(&e),
            },
            "rootclose" => res(root.as_ref().unwrap().close()),
            "inroot" => match os::open_in_root(&get(1), &get(2)) {
                Ok(fl) => {
                    let mut data = Vec::new();
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = fl.read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                        data.extend_from_slice(&buf[..n]);
                    }
                    let _ = fl.close();
                    format!("ok:{}", enc(&data))
                }
                Err(e) => err_str(&e),
            },
            op => {
                let r = root.as_ref().unwrap();
                run_root(op, f, r, &get, &res)
            }
        }
    }

    fn run_root(
        op: &str,
        f: &[&str],
        r: &Root,
        get: &dyn Fn(usize) -> String,
        res: &dyn Fn(Result<(), RootError>) -> String,
    ) -> String {
        match op {
            "rsub" => match r.open_root(&get(1)) {
                Ok(s) => {
                    let n = enc(s.name().as_bytes());
                    let _ = s.close();
                    format!("ok:{n}")
                }
                Err(e) => err_str(&e),
            },
            "rread" => match r.read_file(&get(1)) {
                Ok(d) => format!("ok:{}", enc(&d)),
                Err(e) => err_str(&e),
            },
            "rwrite" => res(r.write_file(&get(1), get(2).as_bytes(), parse_mode(&get(3)))),
            "rfile" => match r.open_file(&get(1), parse_flags(&get(2)), parse_mode(&get(3))) {
                Ok(fl) => {
                    let out = format!(
                        "ok:{}:{}",
                        enc(fl.name().as_bytes()),
                        file_ops(&fl, &get(4))
                    );
                    let _ = fl.close();
                    out
                }
                Err(e) => err_str(&e),
            },
            "rcreate" => match r.create(&get(1)) {
                Ok(fl) => {
                    let _ = fl.close();
                    "ok".into()
                }
                Err(e) => err_str(&e),
            },
            "rmkdir" => res(r.mkdir(&get(1), parse_mode(&get(2)))),
            "rmkdirall" => res(r.mkdir_all(&get(1), parse_mode(&get(2)))),
            "rstat" | "rlstat" => {
                let fi = if op == "rstat" {
                    r.stat(&get(1))
                } else {
                    r.lstat(&get(1))
                };
                match fi {
                    Ok(fi) => format!("ok:{}", describe(&fi)),
                    Err(e) => err_str(&e),
                }
            }
            "rreadlink" => match r.readlink(&get(1)) {
                Ok(d) => format!("ok:{}", enc(d.as_bytes())),
                Err(e) => err_str(&e),
            },
            "rsymlink" => res(r.symlink(&get(1), &get(2))),
            "rlink" => res(r.link(&get(1), &get(2))),
            "rrename" => res(r.rename(&get(1), &get(2))),
            "rremove" => res(r.remove(&get(1))),
            "rremoveall" => res(r.remove_all(&get(1))),
            "rchmod" => res(r.chmod(&get(1), FileMode(parse_mode(&get(2))))),
            "rfsread" => match r.fs().read_file(&get(1)) {
                Ok(d) => format!("ok:{}", enc(&d)),
                Err(e) => err_str(&e),
            },
            "rfsreaddir" => match r.fs().read_dir(&get(1)) {
                Ok(es) => {
                    let names: Vec<String> = es
                        .iter()
                        .map(|e| format!("{}/{}", e.name(), e.file_type()))
                        .collect();
                    format!("ok:{}", enc(names.join(",").as_bytes()))
                }
                Err(e) => err_str(&e),
            },
            other => panic!("unknown op {other} {f:?}"),
        }
    }

    pub fn main() {
        let base: PathBuf = std::fs::canonicalize(std::env::current_dir().unwrap()).unwrap();
        let stdin = std::io::stdin();
        let mut out = std::io::BufWriter::new(std::io::stdout());
        let mut root: Option<Root> = None;
        let mut n = 0;
        let mut cur = base.clone();
        for line in stdin.lock().lines() {
            let line = line.unwrap();
            let f: Vec<&str> = line.split('\t').collect();
            if f[0] == "NEW" {
                if n > 0 {
                    writeln!(out, "TREE|{}", dump(&cur)).unwrap();
                }
                std::env::set_current_dir(&base).unwrap();
                if let Some(r) = root.take() {
                    let _ = r.close();
                }
                let dir = format!("s{n}");
                n += 1;
                std::fs::DirBuilder::new().mode(0o755).create(&dir).unwrap();
                std::env::set_current_dir(&dir).unwrap();
                cur = base.join(&dir);
                continue;
            }
            writeln!(out, "{}|{}", f[0], run(&f, &mut root)).unwrap();
        }
        if n > 0 {
            writeln!(out, "TREE|{}", dump(&cur)).unwrap();
        }
    }
}

#[cfg(all(
    any(target_os = "linux", target_os = "macos"),
    target_pointer_width = "64"
))]
fn main() {
    probe::main();
}
