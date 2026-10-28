//! Canonical, line-oriented descriptions of tar and zip archives. The same
//! format is produced by tools/archive_api_oracle.go for Go's `archive/tar`
//! and `archive/zip`, so Rust output can be diffed against Go (differential
//! harness) or against checked-in Go transcripts (tests/archive_*.rs).
#![allow(dead_code)]
use rust_stdlib::archive::iofs::{self, time_is_zero, time_parts};
use rust_stdlib::archive::{tar, zip};
use rust_stdlib::io::fs::{self, DirEntry};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Read;
use std::time::SystemTime;

pub const CONTENT_CAP: usize = 8 << 20;

pub fn hx<T: AsRef<[u8]> + ?Sized>(s: &T) -> String {
    s.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

pub fn tm(t: &SystemTime) -> String {
    if time_is_zero(t) {
        return "zero".into();
    }
    let (s, n) = time_parts(t);
    format!("{s}.{n}")
}

pub fn kvs<K: AsRef<[u8]>, V: AsRef<[u8]>>(m: &BTreeMap<K, V>) -> String {
    if m.is_empty() {
        return "-".into();
    }
    m.iter()
        .map(|(k, v)| format!("{}:{}", hx(k), hx(v)))
        .collect::<Vec<_>>()
        .join(",")
}

/// FNV-1a (64-bit) of everything readable from `r`, capped at [`CONTENT_CAP`].
pub fn digest(r: &mut dyn Read) -> String {
    let mut h: u64 = 14695981039346656037;
    let mut total = 0usize;
    let (mut trunc, mut failed) = (0, 0);
    let mut buf = vec![0u8; 32 << 10];
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(mut n) => {
                if total + n > CONTENT_CAP {
                    n = CONTENT_CAP - total;
                    trunc = 1;
                }
                for &c in &buf[..n] {
                    h ^= u64::from(c);
                    h = h.wrapping_mul(1099511628211);
                }
                total += n;
                if trunc == 1 {
                    break;
                }
            }
            Err(_) => {
                failed = 1;
                break;
            }
        }
    }
    format!("D len={total} fnv={h:016x} trunc={trunc} err={failed}")
}

pub fn tar_transcript(data: &[u8]) -> String {
    let mut out = String::new();
    let mut tr = tar::Reader::new(data);
    loop {
        match tr.next_raw() {
            Ok(None) => {
                out.push_str("END ok\n");
                break;
            }
            Err(_) => {
                out.push_str("END err\n");
                break;
            }
            Ok(Some(h)) => {
                let utf8 = |s: &[u8]| std::str::from_utf8(s).is_ok();
                let bad = !(utf8(&h.name) && utf8(&h.linkname) && utf8(&h.uname) && utf8(&h.gname))
                    || h.pax_records
                        .iter()
                        .chain(&h.xattrs)
                        .any(|(k, v)| !utf8(k) || !utf8(v));
                let _ = writeln!(
                    out,
                    "H type={} name={} link={} size={} mode={} uid={} gid={} uname={} gname={} mtime={} atime={} ctime={} dmaj={} dmin={} fmt={} xattr={} pax={} local={} nonutf8={}",
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
                    h.devminor,
                    h.format.0,
                    kvs(&h.xattrs),
                    kvs(&h.pax_records),
                    i32::from(iofs::is_local(&String::from_utf8_lossy(&h.name))),
                    i32::from(bad)
                );
                out.push_str(&digest(&mut tr));
                out.push('\n');
            }
        }
    }
    out
}

/// Transcript of an opened zip archive: headers, member and raw digests and
/// the `fs.FS` walk.
pub fn zip_transcript<R: rust_stdlib::io::ReadAt + 'static>(
    created: std::io::Result<zip::Reader<R>>,
) -> String {
    let mut out = String::new();
    let zr = match created {
        Ok(z) => z,
        Err(_) => return "END err\n".into(),
    };
    let _ = writeln!(out, "Z comment={} count={}", hx(&zr.comment), zr.file.len());
    for f in &zr.file {
        let fh = &f.file_header;
        let (off, off_err) = match f.data_offset() {
            Ok(o) => (o, 0),
            Err(_) => (0, 1),
        };
        let _ = writeln!(
            out,
            "F name={} comment={} nonutf8={} creator={} reader={} flags={} method={} mtime={} mdate={} modified={} crc={} csize={} usize={} csize64={} usize64={} extra={} attrs={} mode={} offset={} offerr={}",
            hx(fh.name_bytes()),
            hx(fh.comment_bytes()),
            i32::from(fh.non_utf8),
            fh.creator_version,
            fh.reader_version,
            fh.flags,
            fh.method,
            fh.modified_time,
            fh.modified_date,
            tm(&fh.modified),
            fh.crc32,
            fh.compressed_size,
            fh.uncompressed_size,
            fh.compressed_size64,
            fh.uncompressed_size64,
            fh.extra.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            fh.external_attrs,
            fh.mode().0,
            off,
            off_err
        );
        match f.open() {
            Err(_) => {
                out.push_str("D open=err\n");
                continue;
            }
            Ok(mut rc) => {
                out.push_str(&digest(&mut rc));
                out.push('\n');
            }
        }
        match f.open_raw() {
            Err(_) => out.push_str("R err\n"),
            Ok(mut r) => {
                out.push_str(&digest(&mut r).replacen("D ", "R ", 1));
                out.push('\n');
            }
        }
    }
    let mut names: Vec<String> = Vec::new();
    let _ = fs::walk_dir(&zr, ".", |name: &str, d: Option<&dyn DirEntry>, err| {
        if err.is_some() {
            names.push(format!("walkerr:{}", hx(name)));
            return Ok(());
        }
        let Some(d) = d else {
            return Ok(());
        };
        let info = match d.info() {
            Ok(i) => i,
            Err(_) => {
                names.push(format!("infoerr:{}", hx(name)));
                return Ok(());
            }
        };
        let mut line = format!(
            "{}:dir={}:size={}:mode={}",
            hx(name),
            i32::from(d.is_dir()),
            info.size(),
            info.mode().0
        );
        if !d.is_dir() {
            match fs::FS::open(&zr, name) {
                Ok(mut f) => {
                    line.push(':');
                    line.push_str(&digest(&mut f).replace(' ', ","));
                }
                Err(_) => line.push_str(":openerr"),
            }
        }
        names.push(line);
        Ok(())
    });
    let _ = writeln!(out, "FS {}", names.join(" "));
    out.push_str("END ok\n");
    out
}
