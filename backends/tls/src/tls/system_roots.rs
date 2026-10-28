//! The system root certificates, used when `Config.RootCAs` or `ClientCAs` is
//! nil, as Go's `systemRootsPool` does.
//!
//! This is a copy of the loader in `crates/crypto/src/x509/pool.rs` (Go's
//! `root.go`, `root_unix.go`, `root_linux.go` and `root_darwin.go`) retargeted
//! to [`x509::CertPool`]. backends/tls cannot depend on crates/crypto because
//! the two lock files resolve shared crates at different versions, so keep the
//! two copies in step. On macOS, as in crypto, the keychain is exported with
//! `security` when neither `SSL_CERT_FILE` nor `SSL_CERT_DIR` is set; when one
//! is set the files are read as on other Unix systems, which is what Go's
//! darwin `loadSystemRoots` does.

use super::x509::CertPool;
use std::io;
use std::path::Path;
use std::sync::{Arc, OnceLock};

const CERT_FILE_ENV: &str = "SSL_CERT_FILE";
const CERT_DIR_ENV: &str = "SSL_CERT_DIR";

#[cfg(target_os = "linux")]
const CERT_FILES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu/Gentoo etc.
    "/etc/pki/tls/certs/ca-bundle.crt",   // Fedora/RHEL 6
    "/etc/ssl/ca-bundle.pem",             // OpenSUSE
    "/etc/pki/tls/cacert.pem",            // OpenELEC
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7
    "/etc/ssl/cert.pem",                  // Alpine Linux
];
#[cfg(target_os = "linux")]
const CERT_DIRECTORIES: &[&str] = &[
    "/etc/ssl/certs",     // SLES10/SLES11
    "/etc/pki/tls/certs", // Fedora/RHEL
];

#[cfg(any(
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "openbsd"
))]
const CERT_FILES: &[&str] = &[
    "/usr/local/etc/ssl/cert.pem",
    "/etc/ssl/cert.pem",
    "/usr/local/share/certs/ca-root-nss.crt",
    "/etc/openssl/certs/ca-certificates.crt",
];
#[cfg(any(
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "openbsd"
))]
const CERT_DIRECTORIES: &[&str] = &[
    "/etc/ssl/certs",
    "/usr/local/share/certs",
    "/etc/openssl/certs",
];

// macOS has no default SSL_CERT_{FILE,DIR} paths (Go's root_darwin.go).
#[cfg(target_os = "macos")]
const CERT_FILES: &[&str] = &[];
#[cfg(target_os = "macos")]
const CERT_DIRECTORIES: &[&str] = &[];

#[cfg(not(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "macos"
)))]
const CERT_FILES: &[&str] = &[];
#[cfg(not(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "macos"
)))]
const CERT_DIRECTORIES: &[&str] = &[];

/// Go's `systemRootsPool`: the system roots, loaded once per process. `Err` is
/// the text of Go's `SystemRootsError`, returned when the roots cannot be
/// loaded. An empty pool is a successful load.
pub(crate) fn system_roots() -> Result<Arc<CertPool>, String> {
    static ROOTS: OnceLock<Result<Arc<CertPool>, String>> = OnceLock::new();
    ROOTS
        .get_or_init(|| {
            load_system_roots().map(Arc::new).map_err(|e| {
                format!("x509: failed to load system roots and no roots provided; {e}")
            })
        })
        .clone()
}

/// Go's `loadSystemRoots`.
fn load_system_roots() -> Result<CertPool, io::Error> {
    let cert_file_path = std::env::var(CERT_FILE_ENV).unwrap_or_default();
    let cert_dir_path = std::env::var(CERT_DIR_ENV).unwrap_or_default();

    #[cfg(target_os = "macos")]
    if cert_file_path.is_empty() && cert_dir_path.is_empty() {
        if let Some(pool) = load_keychain_roots() {
            return Ok(pool);
        }
    }

    load_on_disk_roots(
        CERT_FILES,
        CERT_DIRECTORIES,
        &cert_file_path,
        &cert_dir_path,
    )
}

/// Exports the system root certificates with the `security` tool, the way Go
/// did before it used the Security framework.
#[cfg(target_os = "macos")]
fn load_keychain_roots() -> Option<CertPool> {
    let output = std::process::Command::new("/usr/bin/security")
        .args([
            "find-certificate",
            "-a",
            "-p",
            "/System/Library/Keychains/SystemRootCertificates.keychain",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let mut roots = CertPool::new();
    roots.append_certs_from_pem(&output.stdout);
    if roots.is_empty() {
        return None;
    }
    Some(roots)
}

/// Go's `loadOnDiskRoots`, with the default locations as parameters (Go's
/// `certFiles` and `certDirectories` variables).
fn load_on_disk_roots(
    default_files: &[&str],
    default_dirs: &[&str],
    cert_file_path: &str,
    cert_dir_path: &str,
) -> Result<CertPool, io::Error> {
    let mut roots = CertPool::new();

    let files: Vec<String> = if cert_file_path.is_empty() {
        default_files.iter().map(|s| s.to_string()).collect()
    } else {
        vec![cert_file_path.to_string()]
    };

    let mut first_err: Option<io::Error> = None;
    for file in &files {
        match std::fs::read(file) {
            Ok(data) => {
                roots.append_certs_from_pem(&data);
                break;
            }
            Err(e) => {
                if first_err.is_none() && e.kind() != io::ErrorKind::NotFound {
                    first_err = Some(e);
                }
            }
        }
    }

    let dirs: Vec<String> = if cert_dir_path.is_empty() {
        default_dirs.iter().map(|s| s.to_string()).collect()
    } else {
        // filepath.SplitList
        std::env::split_paths(cert_dir_path)
            .map(|p| p.to_string_lossy().into_owned())
            .collect()
    };

    for directory in &dirs {
        let entries = match read_unique_directory_entries(directory) {
            Ok(e) => e,
            Err(e) => {
                if first_err.is_none() && e.kind() != io::ErrorKind::NotFound {
                    first_err = Some(e);
                }
                continue;
            }
        };
        for path in entries {
            if let Ok(data) = std::fs::read(&path) {
                roots.append_certs_from_pem(&data);
            }
        }
    }

    if !roots.is_empty() || first_err.is_none() {
        return Ok(roots);
    }

    Err(first_err.expect("checked"))
}

/// Go's `readUniqueDirectoryEntries`: the files of a directory, omitting
/// symlinks that point within the same directory.
fn read_unique_directory_entries(dir: &str) -> Result<Vec<std::path::PathBuf>, io::Error> {
    let mut names: Vec<std::ffi::OsString> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name())
        .collect();
    names.sort();
    let mut out = Vec::new();
    for name in names {
        let path = Path::new(dir).join(&name);
        if is_same_dir_symlink(&path) {
            continue;
        }
        out.push(path);
    }
    Ok(out)
}

fn is_same_dir_symlink(path: &Path) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if !meta.file_type().is_symlink() {
        return false;
    }
    match std::fs::read_link(path) {
        Ok(target) => !target.to_string_lossy().contains(std::path::MAIN_SEPARATOR),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rust-stdlib-tls-roots-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn missing_locations_are_an_empty_load_not_an_error() {
        let dir = temp_dir("missing");
        let missing_file = dir.join("no-such.pem");
        let missing_dir = dir.join("no-such-dir");
        let pool = load_on_disk_roots(
            &[],
            &[],
            missing_file.to_str().unwrap(),
            missing_dir.to_str().unwrap(),
        )
        .expect("NotFound is not an error");
        assert!(pool.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn garbage_files_add_no_roots() {
        let dir = temp_dir("garbage");
        std::fs::write(dir.join("junk.pem"), b"not a certificate\n").unwrap();
        let pool = load_on_disk_roots(&[], &[], "", dir.to_str().unwrap()).unwrap();
        assert!(pool.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
