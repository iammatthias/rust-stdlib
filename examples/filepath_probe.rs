//! Probe for the `path/filepath` Go differential (`tools/filepath_check.py`).
use rust_stdlib::io::fs;
use rust_stdlib::path::filepath;
use std::io::{self, BufRead};

fn dec(value: &str) -> String {
    let bytes: Vec<u8> = (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).expect("hex"))
        .collect();
    String::from_utf8(bytes).expect("UTF-8 input")
}

fn enc(value: &str) -> String {
    value
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn enc_list(l: &[String]) -> String {
    l.iter().map(|s| enc(s)).collect::<Vec<_>>().join(",")
}

fn text<T>(r: &io::Result<T>) -> String {
    match r {
        Ok(_) => "ok".into(),
        Err(e) => format!("err:{}", enc(&e.to_string())),
    }
}

fn kind(mode: fs::FileMode) -> &'static str {
    if mode.0 & fs::MODE_SYMLINK.0 != 0 {
        "L"
    } else if mode.is_dir() {
        "D"
    } else {
        "F"
    }
}

fn policy(path: &str, is_dir: bool) -> io::Result<()> {
    let base = filepath::base(path);
    if (base.starts_with("skip") && is_dir) || base == "skipfile" {
        Err(fs::SKIP_DIR.into())
    } else if base == "stop" {
        Err(fs::SKIP_ALL.into())
    } else if base == "boom" {
        Err(io::Error::other("boom"))
    } else {
        Ok(())
    }
}

/// Go's callback-style walk over the iterator: `f(path, entry, err)` returns
/// `SkipDir`, `SkipAll` or an error as in Go.
fn go_walk<F>(root: &str, list_first: bool, mut f: F) -> io::Result<()>
where
    F: FnMut(&str, Option<&filepath::WalkEntry>, Option<io::Error>) -> io::Result<()>,
{
    let mut it = filepath::WalkDir::new(root);
    if list_first {
        it = it.list_first();
    }
    while let Some(item) = it.next() {
        let res = match item {
            Ok(entry) => f(entry.path(), Some(&entry), None),
            Err(e) => {
                let path = e.path().to_string();
                f(&path, None, Some(e.into_source()))
            }
        };
        match res {
            Ok(()) => {}
            Err(e) if fs::Error::SkipDir.is(&e) => it.skip_current_dir(),
            Err(e) if fs::Error::SkipAll.is(&e) => return Ok(()),
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn res(r: io::Result<String>) -> String {
    match r {
        Ok(s) => enc(&s),
        Err(e) => format!("error:{}", enc(&e.to_string())),
    }
}

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.expect("stdin");
        let f: Vec<&str> = line.split('\t').collect();
        let op = f[0];
        let get = |i: usize| f.get(i).map(|v| dec(v)).unwrap_or_default();
        let a = get(1);
        let result = match op {
            "C" => enc(&filepath::clean(&a)),
            "S" => {
                let (d, file) = filepath::split(&a);
                format!("{}|{}", enc(d), enc(file))
            }
            "B" => enc(filepath::base(&a)),
            "D" => enc(&filepath::dir(&a)),
            "E" => enc(filepath::ext(&a)),
            "A" => filepath::is_abs(&a).to_string(),
            "J" => {
                let parts: Vec<String> = f[1..].iter().map(|v| dec(v)).collect();
                enc(&filepath::join(&parts))
            }
            "M" => match filepath::matches(&a, &get(2)) {
                Ok(m) => m.to_string(),
                Err(e) => format!("error:{}", enc(&e.to_string())),
            },
            "R" => res(filepath::rel(&a, &get(2))),
            "L" => filepath::is_local(&a).to_string(),
            "Z" => res(filepath::localize(&a)),
            "P" => enc_list(&filepath::split_list(&a)),
            "V" => enc(filepath::volume_name(&a)),
            "T" => enc(&filepath::to_slash(&a)),
            "F" => enc(&filepath::from_slash(&a)),
            "H" => filepath::has_prefix(&a, &get(2)).to_string(),
            "X" => res(filepath::eval_symlinks(&a)),
            "Y" => res(filepath::abs(&a)),
            "G" => match filepath::glob(&a) {
                Ok(m) => enc_list(&m),
                Err(e) => format!("error:{}", enc(&e.to_string())),
            },
            "W" => {
                let mut recs: Vec<String> = Vec::new();
                let r = go_walk(&a, true, |path, entry, err| {
                    if let Some(err) = err {
                        recs.push(format!("E {path} {err}"));
                        return Ok(());
                    }
                    let entry = entry.expect("entry without error");
                    recs.push(format!("{} {path}", kind(entry.file_type())));
                    policy(path, entry.is_dir())
                });
                format!("{}|{}", enc_list(&recs), text(&r))
            }
            "K" => {
                let mut recs: Vec<String> = Vec::new();
                let r = go_walk(&a, false, |path, entry, err| {
                    if let Some(err) = err {
                        recs.push(format!("E {path} {err}"));
                        return Ok(());
                    }
                    let entry = entry.expect("entry without error");
                    recs.push(format!("{} {path}", kind(entry.file_type())));
                    policy(path, entry.is_dir())
                });
                format!("{}|{}", enc_list(&recs), text(&r))
            }
            _ => panic!("unknown operation {op}"),
        };
        println!("{op}|{result}");
    }
}
