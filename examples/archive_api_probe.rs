//! Rust side of the archive/tar and archive/zip API differential. Mirrors
//! tools/archive_api_oracle.go line for line; see tools/check_archive_api.py.
//!
//!   archive_api_probe tar-read FILE
//!   archive_api_probe tar-write MANIFEST OUT
#[path = "common/archive_transcript.rs"]
mod transcript;

use rust_stdlib::archive::iofs::{self, time_unix, time_zero};
use rust_stdlib::archive::tar;
use rust_stdlib::archive::zip;
use std::collections::BTreeMap;
use std::io::Write;
use std::{fs, time::SystemTime};
use transcript::{tar_transcript, zip_transcript};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

type Fields = BTreeMap<String, String>;

fn manifest(path: &str) -> Vec<Fields> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            l.split_whitespace()
                .map(|kv| {
                    let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                    (k.to_string(), v.to_string())
                })
                .collect()
        })
        .collect()
}

fn fstr(f: &Fields, k: &str) -> String {
    String::from_utf8(unhex(f.get(k).map_or("", String::as_str))).unwrap()
}

fn fnum(f: &Fields, k: &str) -> i64 {
    f.get(k).and_then(|v| v.parse().ok()).unwrap_or(0)
}

fn ftime(f: &Fields, k: &str) -> SystemTime {
    match f.get(k) {
        None => time_zero(),
        Some(v) if v == "zero" => time_zero(),
        Some(v) => {
            let (s, n) = v.split_once('.').unwrap_or((v, "0"));
            time_unix(s.parse().unwrap(), n.parse().unwrap())
        }
    }
}

fn fkv(f: &Fields, k: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    if let Some(v) = f.get(k) {
        if v != "-" {
            for p in v.split(',') {
                let (a, b) = p.split_once(':').unwrap();
                m.insert(
                    String::from_utf8(unhex(a)).unwrap(),
                    String::from_utf8(unhex(b)).unwrap(),
                );
            }
        }
    }
    m
}

fn status<T>(r: &std::io::Result<T>) -> &'static str {
    if r.is_ok() {
        "ok"
    } else {
        "err"
    }
}

fn tar_read(path: &str) {
    println!("@@ {path}");
    print!("{}", tar_transcript(&fs::read(path).unwrap()));
}

fn tar_write(manifest_path: &str, out_path: &str) {
    let lines = manifest(manifest_path);
    let mut buf: Vec<u8> = Vec::new();
    let mut report = String::new();
    {
        let mut tw = tar::Writer::new(&mut buf);
        for f in &lines {
            let h = tar::Header {
                typeflag: fnum(f, "type") as u8,
                name: fstr(f, "name"),
                linkname: fstr(f, "link"),
                size: fnum(f, "size"),
                mode: fnum(f, "mode"),
                uid: fnum(f, "uid"),
                gid: fnum(f, "gid"),
                uname: fstr(f, "uname"),
                gname: fstr(f, "gname"),
                mod_time: ftime(f, "mtime"),
                access_time: ftime(f, "atime"),
                change_time: ftime(f, "ctime"),
                devmajor: fnum(f, "dmaj"),
                devminor: fnum(f, "dmin"),
                xattrs: fkv(f, "xattr"),
                pax_records: fkv(f, "pax"),
                format: tar::Format(fnum(f, "fmt") as i32),
            };
            // `sparse=OFFSET:LENGTH,...` lists holes (Rust extension; Go's writer
            // cannot write sparse files).
            let r = match f.get("sparse") {
                None => tw.write_header(&h),
                Some(list) => {
                    let holes: Vec<tar::SparseEntry> = list
                        .split(',')
                        .filter(|p| *p != "-")
                        .map(|p| {
                            let (o, l) = p.split_once(':').unwrap();
                            tar::SparseEntry {
                                offset: o.parse().unwrap(),
                                length: l.parse().unwrap(),
                            }
                        })
                        .collect();
                    tw.write_sparse_header(&h, &holes)
                }
            };
            report.push_str(&format!("W {}\n", status(&r)));
            if r.is_err() {
                continue;
            }
            let d = unhex(f.get("data").map_or("", String::as_str));
            if !d.is_empty() {
                let r = tw.write_all(&d);
                report.push_str(&format!("D {}\n", status(&r)));
            }
        }
        let r = tw.close();
        report.push_str(&format!("CLOSE {}\n", status(&r)));
    }
    fs::write(out_path, buf).unwrap();
    print!("{report}");
}

/// A `.zsparse` golden (gzip of u64 size, u32 spans, then u64 offset, u32 length and
/// bytes per span) served as a large, mostly zero archive.
struct SparseAt {
    size: i64,
    spans: Vec<(i64, Vec<u8>)>,
}

impl rust_stdlib::io::ReadAt for SparseAt {
    fn read_at(&self, p: &mut [u8], off: u64) -> Result<usize, rust_stdlib::io::ReadError> {
        let off = off as i64;
        if off >= self.size {
            return Err(rust_stdlib::io::ReadError::new(0, rust_stdlib::io::eof()));
        }
        let end = (off + p.len() as i64).min(self.size);
        let n = (end - off) as usize;
        p[..n].fill(0);
        for (s_off, data) in &self.spans {
            let s_end = s_off + data.len() as i64;
            if s_end <= off || *s_off >= end {
                continue;
            }
            let (from, to) = ((*s_off).max(off), s_end.min(end));
            p[(from - off) as usize..(to - off) as usize]
                .copy_from_slice(&data[(from - s_off) as usize..(to - s_off) as usize]);
        }
        if n < p.len() {
            return Err(rust_stdlib::io::ReadError::new(n, rust_stdlib::io::eof()));
        }
        Ok(n)
    }
}

fn open_sparse(data: &[u8]) -> SparseAt {
    let mut raw = Vec::new();
    rust_stdlib::compress::decode_gzip(data, &mut raw, rust_stdlib::compress::Limits::default())
        .unwrap();
    let size = i64::from_le_bytes(raw[..8].try_into().unwrap());
    let n = u32::from_le_bytes(raw[8..12].try_into().unwrap());
    let mut rest = &raw[12..];
    let mut spans = Vec::new();
    for _ in 0..n {
        let off = i64::from_le_bytes(rest[..8].try_into().unwrap());
        let l = u32::from_le_bytes(rest[8..12].try_into().unwrap()) as usize;
        spans.push((off, rest[12..12 + l].to_vec()));
        rest = &rest[12 + l..];
    }
    SparseAt { size, spans }
}

fn zip_read(path: &str) {
    println!("@@ {path}");
    let data = fs::read(path).unwrap();
    if path.ends_with(".zsparse") {
        let sparse = open_sparse(&data);
        let size = sparse.size;
        print!(
            "{}",
            zip_transcript(zip::Reader::new(sparse, size).map_err(std::io::Error::from))
        );
    } else {
        let size = data.len() as i64;
        print!(
            "{}",
            zip_transcript(zip::Reader::new(data, size).map_err(std::io::Error::from))
        );
    }
}

fn zip_write(manifest_path: &str, out_path: &str) {
    let lines = manifest(manifest_path);
    let mut buf: Vec<u8> = Vec::new();
    let mut report = String::new();
    {
        let mut zw = zip::Writer::new(&mut buf);
        for f in &lines {
            match f.get("op").map(String::as_str) {
                Some("comment") => {
                    let r = zw.set_comment(&fstr(f, "comment"));
                    report.push_str(&format!("C {}\n", status(&r)));
                    continue;
                }
                Some("offset") => {
                    zw.set_offset(fnum(f, "offset"));
                    continue;
                }
                _ => {}
            }
            let mut h = zip::FileHeader {
                name: fstr(f, "name"),
                comment: fstr(f, "comment"),
                raw_name: f.get("rawname").map(|v| unhex(v)),
                raw_comment: f.get("rawcomment").map(|v| unhex(v)),
                method: fnum(f, "method") as u16,
                non_utf8: f.get("nonutf8").map(String::as_str) == Some("1"),
                extra: unhex(f.get("extra").map_or("", String::as_str)),
                flags: fnum(f, "flags") as u16,
                ..zip::FileHeader::default()
            };
            if let Some(v) = f.get("modified") {
                if v != "zero" {
                    h.modified = ftime(f, "modified");
                }
            }
            if let Some(v) = f.get("mode") {
                h.set_mode(iofs::FileMode(v.parse().unwrap()));
            }
            let raw = f.get("op").map(String::as_str) == Some("raw");
            if raw {
                h.crc32 = fnum(f, "crc") as u32;
                h.compressed_size64 = fnum(f, "csize64") as u64;
                h.uncompressed_size64 = fnum(f, "usize64") as u64;
            }
            let created = if raw {
                zw.create_raw(&h)
            } else {
                zw.create_header(&h)
            };
            let mut w = match created {
                Ok(w) => w,
                Err(e) => {
                    let _ = e;
                    report.push_str("W err\n");
                    continue;
                }
            };
            report.push_str("W ok\n");
            let d = unhex(f.get("data").map_or("", String::as_str));
            if !d.is_empty() {
                let r = w.write_all(&d);
                report.push_str(&format!("D {}\n", status(&r)));
            }
        }
        let r = zw.close();
        report.push_str(&format!("CLOSE {}\n", status(&r)));
        // Go updates the headers it is given; the Rust writer exposes its copies.
        for h in zw.headers() {
            let sizes = if h.method == zip::STORE {
                format!(
                    "{},{},{},{}",
                    h.compressed_size,
                    h.uncompressed_size,
                    h.compressed_size64,
                    h.uncompressed_size64
                )
            } else {
                "-".to_string()
            };
            report.push_str(&format!(
                "HD name={} creator={} reader={} flags={} method={} mtime={} mdate={} crc={} sizes={} usize64={} extra={}\n",
                transcript::hx(h.name_bytes()),
                h.creator_version,
                h.reader_version,
                h.flags,
                h.method,
                h.modified_time,
                h.modified_date,
                h.crc32,
                sizes,
                h.uncompressed_size64,
                h.extra.iter().map(|b| format!("{b:02x}")).collect::<String>()
            ));
        }
    }
    fs::write(out_path, buf).unwrap();
    print!("{report}");
}

/// FileInfoHeader of `os::lstat(path)`, mirroring tarFileInfo in the Go oracle.
fn tar_fileinfo(paths: &[String]) {
    use rust_stdlib::io::fs::{DirFS, ReadLinkFS};
    use transcript::{hx, tm};
    // Absolute paths, resolved from the root; DirFS::lstat does not follow symlinks (lstat).
    let root = DirFS::new("/");
    for path in paths {
        let Ok(fi) = root.lstat(path.trim_start_matches('/')) else {
            println!("FI {} lstat-err", hx(path));
            continue;
        };
        let link = if fi.mode().file_type() == rust_stdlib::io::fs::MODE_SYMLINK {
            fs::read_link(path)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default()
        } else {
            String::new()
        };
        let Ok(h) = tar::file_info_header(&iofs::FsInfo(fi), &link) else {
            println!("FI {} err", hx(path));
            continue;
        };
        println!(
            "FI {} type={} name={} link={} size={} mode={} uid={} gid={} uname={} gname={} mtime={} atime={} ctime={} dmaj={} dmin={}",
            hx(path),
            h.typeflag,
            hx(&h.name),
            hx(&h.linkname),
            h.size,
            h.mode,
            h.uid,
            h.gid,
            hx(&h.uname),
            hx(&h.gname),
            tm(&h.mod_time),
            tm(&h.access_time),
            tm(&h.change_time),
            h.devmajor,
            h.devminor
        );
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("tar-fileinfo") => tar_fileinfo(&args[2..]),
        Some("tar-read") => {
            for path in &args[2..] {
                let p = path.clone();
                if std::panic::catch_unwind(move || tar_read(&p)).is_err() {
                    println!("PANIC");
                }
            }
        }
        Some("tar-write") => tar_write(&args[2], &args[3]),
        Some("zip-read") => {
            for path in &args[2..] {
                let p = path.clone();
                if std::panic::catch_unwind(move || zip_read(&p)).is_err() {
                    println!("PANIC");
                }
            }
        }
        Some("zip-write") => zip_write(&args[2], &args[3]),
        _ => {
            eprintln!("usage: archive_api_probe tar-read|tar-write ...");
            std::process::exit(2);
        }
    }
    std::io::stdout().flush().unwrap();
}
