//! Certificate pools and the system roots, a port of Go's `cert_pool.go`,
//! `root.go` and the pure-Go root loaders.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use super::pem;
use super::{parse_certificate, Certificate, Error};
use crate::Hash;

/// The constraint function of [`CertPool::add_cert_with_constraint`]: it is
/// called with the chain so far and may reject it.
pub type Constraint = Arc<dyn Fn(&[Arc<Certificate>]) -> Result<(), Error> + Send + Sync>;

#[derive(Clone)]
struct LazyCert {
    raw_subject: Vec<u8>,
    constraint: Option<Constraint>,
    cert: Arc<Certificate>,
}

/// Go's `x509.CertPool`: a set of certificates.
#[derive(Clone, Default)]
pub struct CertPool {
    /// `cert.RawSubject` => indexes into `lazy_certs`.
    by_name: HashMap<Vec<u8>, Vec<usize>>,
    lazy_certs: Vec<LazyCert>,
    /// SHA-224 sums of the raw certificates, to deduplicate.
    have_sum: HashSet<Vec<u8>>,
    /// Whether the pool stands for the platform's trust store. The pure
    /// loaders here never create such a pool.
    system_pool: bool,
}

impl std::fmt::Debug for CertPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertPool")
            .field("len", &self.lazy_certs.len())
            .finish()
    }
}

/// A certificate that might be the parent of another, with the constraint of
/// the pool it came from.
pub(crate) struct PotentialParent {
    pub cert: Arc<Certificate>,
    pub constraint: Option<Constraint>,
}

fn sum224(raw: &[u8]) -> Vec<u8> {
    let mut h = Hash::Sha224.new().expect("SHA-224 is implemented");
    std::io::Write::write_all(&mut h, raw).expect("hash writes do not fail");
    let mut out = Vec::new();
    h.sum(&mut out);
    out
}

impl CertPool {
    /// Go's `NewCertPool`: returns a new, empty pool.
    pub fn new() -> CertPool {
        CertPool::default()
    }

    /// The number of certificates, Go's unexported `len` (zero for nil).
    pub(crate) fn len(&self) -> usize {
        self.lazy_certs.len()
    }

    pub(crate) fn cert(&self, n: usize) -> (&Arc<Certificate>, Option<&Constraint>) {
        let lc = &self.lazy_certs[n];
        (&lc.cert, lc.constraint.as_ref())
    }

    /// Go's `CertPool.Clone`: returns a copy of the pool.
    pub fn clone_pool(&self) -> CertPool {
        self.clone()
    }

    /// Go's `findPotentialParents`: certificates in the pool that might have
    /// signed `cert`, ordered by how well their key identifiers match.
    pub(crate) fn find_potential_parents(&self, cert: &Certificate) -> Vec<PotentialParent> {
        let mut matching_key_id = Vec::new();
        let mut one_key_id = Vec::new();
        let mut mismatch_key_id = Vec::new();
        if let Some(indexes) = self.by_name.get(&cert.raw_issuer) {
            for &c in indexes {
                let (candidate, constraint) = self.cert(c);
                let parent = PotentialParent {
                    cert: candidate.clone(),
                    constraint: constraint.cloned(),
                };
                let kid_match = candidate.subject_key_id == cert.authority_key_id;
                if kid_match {
                    matching_key_id.push(parent);
                } else if (candidate.subject_key_id.is_empty() && !cert.authority_key_id.is_empty())
                    || (!candidate.subject_key_id.is_empty() && cert.authority_key_id.is_empty())
                {
                    one_key_id.push(parent);
                } else {
                    mismatch_key_id.push(parent);
                }
            }
        }
        let mut candidates = matching_key_id;
        candidates.extend(one_key_id);
        candidates.extend(mismatch_key_id);
        candidates
    }

    /// Whether the pool contains `cert`, compared by SHA-224 of the raw bytes.
    pub(crate) fn contains(&self, cert: &Certificate) -> bool {
        self.have_sum.contains(&sum224(&cert.raw))
    }

    /// Go's `CertPool.AddCert`: adds a certificate to the pool.
    pub fn add_cert(&mut self, cert: &Certificate) {
        self.add_cert_arc(Arc::new(cert.clone()));
    }

    /// [`CertPool::add_cert`] for a certificate that is already shared.
    pub fn add_cert_arc(&mut self, cert: Arc<Certificate>) {
        self.add_cert_func(cert, None);
    }

    fn add_cert_func(&mut self, cert: Arc<Certificate>, constraint: Option<Constraint>) {
        let sum = sum224(&cert.raw);
        if self.have_sum.contains(&sum) {
            return;
        }
        self.have_sum.insert(sum);
        let raw_subject = cert.raw_subject.clone();
        self.lazy_certs.push(LazyCert {
            raw_subject: raw_subject.clone(),
            constraint,
            cert,
        });
        self.by_name
            .entry(raw_subject)
            .or_default()
            .push(self.lazy_certs.len() - 1);
    }

    /// Go's `CertPool.AddCertWithConstraint`: adds a certificate to the pool
    /// with a constraint function, which will be called when the certificate
    /// is considered as a parent during chain building. The function receives
    /// the chain so far and returns an error if the chain must not be
    /// extended with this certificate.
    pub fn add_cert_with_constraint(&mut self, cert: &Certificate, constraint: Constraint) {
        self.add_cert_func(Arc::new(cert.clone()), Some(constraint));
    }

    /// Go's `CertPool.AppendCertsFromPEM`: attempts to parse a series of PEM
    /// encoded certificates, adds them to the pool and reports whether any
    /// were successfully parsed. Blocks that are not certificates, or that
    /// have headers, are skipped.
    pub fn append_certs_from_pem(&mut self, pem_certs: &[u8]) -> bool {
        let mut ok = false;
        let mut rest = pem_certs;
        while !rest.is_empty() {
            let (block, tail) = pem::decode(rest);
            rest = tail;
            let Some(block) = block else {
                break;
            };
            if block.type_ != "CERTIFICATE" || !block.headers.is_empty() {
                continue;
            }
            let Ok(cert) = parse_certificate(&block.bytes) else {
                continue;
            };
            self.add_cert_func(Arc::new(cert), None);
            ok = true;
        }
        ok
    }

    /// Go's `CertPool.Subjects`: the DER encoded subjects of all the
    /// certificates in the pool.
    ///
    /// Deprecated in Go: not correct for system roots.
    pub fn subjects(&self) -> Vec<Vec<u8>> {
        self.lazy_certs
            .iter()
            .map(|lc| lc.raw_subject.clone())
            .collect()
    }

    /// Go's `CertPool.Equal`: reports whether the two pools are equal.
    pub fn equal(&self, other: &CertPool) -> bool {
        self.system_pool == other.system_pool && self.have_sum == other.have_sum
    }
}

// ---- System roots -----------------------------------------------------

struct SystemRoots {
    loaded: bool,
    pool: Option<Arc<CertPool>>,
    err: Option<Arc<dyn std::error::Error + Send + Sync>>,
    fallbacks_set: bool,
    use_fallback_roots: bool,
}

static SYSTEM_ROOTS: Mutex<SystemRoots> = Mutex::new(SystemRoots {
    loaded: false,
    pool: None,
    err: None,
    fallbacks_set: false,
    use_fallback_roots: false,
});

fn lock() -> std::sync::MutexGuard<'static, SystemRoots> {
    SYSTEM_ROOTS.lock().unwrap_or_else(|e| e.into_inner())
}

fn init_system_roots(state: &mut SystemRoots) {
    if state.loaded {
        return;
    }
    state.loaded = true;
    let fallback_roots = state.pool.take();
    match load_system_roots() {
        Ok(pool) => {
            state.pool = Some(Arc::new(pool));
            state.err = None;
        }
        Err(e) => {
            state.pool = None;
            state.err = Some(Arc::new(e));
        }
    }

    let Some(fallback_roots) = fallback_roots else {
        return; // No fallbacks to try.
    };

    let system_certs_avail = state
        .pool
        .as_ref()
        .is_some_and(|p| p.len() > 0 || p.system_pool);

    if !state.use_fallback_roots && system_certs_avail {
        return;
    }

    state.pool = Some(fallback_roots);
    state.err = None;
}

/// The system roots, loaded on first use. `None` if they could not be loaded
/// (see [`system_roots_error`]).
pub(crate) fn system_roots_pool() -> Option<Arc<CertPool>> {
    let mut state = lock();
    init_system_roots(&mut state);
    state.pool.clone()
}

/// The error from loading the system roots, if any.
pub(crate) fn system_roots_error() -> Option<Arc<dyn std::error::Error + Send + Sync>> {
    let state = lock();
    state.err.clone()
}

/// Go's `SetFallbackRoots`: sets the roots to use during certificate
/// verification if the system roots are not available or empty. Panics (like
/// Go) if called more than once.
///
/// Setting `x509usefallbackroots=1` in `GODEBUG` makes the fallback roots
/// override the system roots.
pub fn set_fallback_roots(roots: CertPool) {
    let mut state = lock();
    if state.fallbacks_set {
        panic!("SetFallbackRoots has already been called");
    }
    state.fallbacks_set = true;

    let force = crate::sysrng::godebug("x509usefallbackroots").as_deref() == Some("1");
    if !state.loaded {
        state.pool = Some(Arc::new(roots));
        state.use_fallback_roots = force;
        return;
    }

    let system_certs_avail = state
        .pool
        .as_ref()
        .is_some_and(|p| p.len() > 0 || p.system_pool);

    if !force && system_certs_avail {
        return;
    }

    state.pool = Some(Arc::new(roots));
    state.err = None;
}

/// Go's `SystemCertPool`: returns a copy of the system cert pool.
///
/// On Unix systems other than macOS the environment variables `SSL_CERT_FILE`
/// and `SSL_CERT_DIR` can be used to override the system default locations for
/// the SSL certificate file and SSL certificate files directory. On macOS the
/// trust store is exported with the `security` tool; the platform verifier Go
/// uses there (and its trust settings) is not available, so the exported
/// certificates are used by the portable verifier.
///
/// Any mutations to the returned pool are not written to disk and do not
/// affect any other pool returned by `system_cert_pool`. New changes in the
/// system cert pool might not be reflected in subsequent calls.
pub fn system_cert_pool() -> Result<CertPool, Error> {
    if let Some(sys_roots) = system_roots_pool() {
        return Ok((*sys_roots).clone());
    }
    load_system_roots().map_err(|e| Error::new(e.to_string()))
}

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

/// Go's `loadSystemRoots`.
fn load_system_roots() -> Result<CertPool, std::io::Error> {
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
    if roots.len() == 0 {
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
) -> Result<CertPool, std::io::Error> {
    let mut roots = CertPool::new();

    let files: Vec<String> = if cert_file_path.is_empty() {
        default_files.iter().map(|s| s.to_string()).collect()
    } else {
        vec![cert_file_path.to_string()]
    };

    let mut first_err: Option<std::io::Error> = None;
    for file in &files {
        match std::fs::read(file) {
            Ok(data) => {
                roots.append_certs_from_pem(&data);
                break;
            }
            Err(e) => {
                if first_err.is_none() && e.kind() != std::io::ErrorKind::NotFound {
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
                if first_err.is_none() && e.kind() != std::io::ErrorKind::NotFound {
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

    if roots.len() > 0 || first_err.is_none() {
        return Ok(roots);
    }

    Err(first_err.expect("checked"))
}

/// Go's `readUniqueDirectoryEntries`: the files of a directory, omitting
/// symlinks that point within the same directory.
fn read_unique_directory_entries(dir: &str) -> Result<Vec<std::path::PathBuf>, std::io::Error> {
    let mut names: Vec<std::ffi::OsString> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name())
        .collect();
    names.sort();
    let mut out = Vec::new();
    for name in names {
        let path = std::path::Path::new(dir).join(&name);
        if is_same_dir_symlink(&path) {
            continue;
        }
        out.push(path);
    }
    Ok(out)
}

fn is_same_dir_symlink(path: &std::path::Path) -> bool {
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
    //! Ported from Go's cert_pool_test.go and root_test.go.
    use super::*;
    use std::path::{Path, PathBuf};

    fn fixture(path: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/x509")
            .join(path)
    }

    fn const_pem(name: &str) -> Vec<u8> {
        let text = std::fs::read_to_string(fixture("certs.tsv")).unwrap();
        for line in text.lines() {
            let mut parts = line.split('\t');
            if parts.next() == Some(name) {
                let label = parts.next().unwrap();
                let body = parts.next().unwrap();
                let mut out = format!("-----BEGIN {label}-----\n");
                for chunk in body.as_bytes().chunks(64) {
                    out.push_str(std::str::from_utf8(chunk).unwrap());
                    out.push('\n');
                }
                out.push_str(&format!("-----END {label}-----\n"));
                return out.into_bytes();
            }
        }
        panic!("no PEM constant {name}");
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("x509-pool-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn cert(raw: &[u8], subject: &[u8]) -> Certificate {
        Certificate {
            raw: raw.to_vec(),
            raw_subject: subject.to_vec(),
            ..Certificate::default()
        }
    }

    #[test]
    fn cert_pool_equal() {
        let tc = cert(&[1, 2, 3], &[2]);
        let other = cert(&[9, 8, 7], &[8]);
        let empty = CertPool::new();
        let mut populated = CertPool::new();
        populated.add_cert(&tc);
        let mut populated_alt = CertPool::new();
        populated_alt.add_cert(&other);
        let system_empty = CertPool {
            system_pool: true,
            ..CertPool::default()
        };
        let mut system_populated = system_empty.clone();
        system_populated.add_cert(&tc);
        let mut system_populated_alt = system_empty.clone();
        system_populated_alt.add_cert(&other);

        assert!(empty.equal(&empty));
        assert!(!empty.equal(&populated));
        assert!(populated.equal(&populated));
        assert!(!populated.equal(&populated_alt));
        assert!(system_empty.equal(&system_empty));
        assert!(!system_empty.equal(&system_populated));
        assert!(system_populated.equal(&system_populated));
        assert!(!system_populated.equal(&system_populated_alt));
        // A system pool never equals a pool of the same certificates.
        assert!(!populated.equal(&system_populated));
    }

    #[test]
    fn append_certs_from_pem_skips_other_blocks() {
        let mut pool = CertPool::new();
        let mut pem = const_pem("gtsRoot");
        pem.extend(b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n");
        pem.extend(b"-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\n\nAAAA\n-----END CERTIFICATE-----\n");
        pem.extend(b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n");
        pem.extend(const_pem("googleLeaf"));
        pem.extend(const_pem("gtsRoot")); // a duplicate
        assert!(pool.append_certs_from_pem(&pem));
        assert_eq!(pool.len(), 2);
        assert_eq!(pool.subjects().len(), 2);
        assert!(!CertPool::new().append_certs_from_pem(b"not a certificate"));
    }

    const TEST_DIR_CN: &str = "test-dir";
    const TEST_FILE: &str = "test-file.crt";
    const TEST_FILE_CN: &str = "test-file";
    const TEST_MISSING: &str = "missing";

    fn common_names(pool: &CertPool) -> Vec<String> {
        (0..pool.len())
            .map(|i| pool.cert(i).0.subject.common_name.clone())
            .collect()
    }

    #[test]
    fn env_vars() {
        // The directory holds test-dir.crt (common name "test-dir"); the file
        // test-file.crt has the common name "test-file".
        let tmp = temp_dir("env-vars");
        let test_cert = std::fs::read(fixture("test-dir.crt")).unwrap();
        std::fs::write(tmp.join(TEST_FILE), &test_cert).unwrap();
        let tmp_str = tmp.to_string_lossy().into_owned();
        let test_file = fixture("test-file.crt").to_string_lossy().into_owned();

        struct Case<'a> {
            name: &'a str,
            file_env: &'a str,
            dir_env: &'a str,
            files: Vec<&'a str>,
            dirs: Vec<&'a str>,
            cns: Vec<&'a str>,
        }
        let cases = vec![
            // Environment variables override the default locations,
            // preventing fall through.
            Case {
                name: "override-defaults",
                file_env: TEST_MISSING,
                dir_env: TEST_MISSING,
                files: vec![&test_file],
                dirs: vec![&tmp_str],
                cns: vec![],
            },
            // File environment overrides default file locations.
            Case {
                name: "file",
                file_env: &test_file,
                dir_env: "",
                files: vec![],
                dirs: vec![],
                cns: vec![TEST_FILE_CN],
            },
            // Directory environment overrides default directory locations.
            Case {
                name: "dir",
                file_env: "",
                dir_env: &tmp_str,
                files: vec![],
                dirs: vec![],
                cns: vec![TEST_DIR_CN],
            },
            // File and directory environment override both default locations.
            Case {
                name: "file+dir",
                file_env: &test_file,
                dir_env: &tmp_str,
                files: vec![],
                dirs: vec![],
                cns: vec![TEST_FILE_CN, TEST_DIR_CN],
            },
            // An empty environment variable uses the default locations.
            Case {
                name: "empty-fall-through",
                file_env: "",
                dir_env: "",
                files: vec![&test_file],
                dirs: vec![&tmp_str],
                cns: vec![TEST_FILE_CN, TEST_DIR_CN],
            },
        ];
        for case in cases {
            let pool = load_on_disk_roots(&case.files, &case.dirs, case.file_env, case.dir_env)
                .unwrap_or_else(|e| panic!("{}: unexpected failure: {e}", case.name));
            assert_eq!(common_names(&pool), case.cns, "{}", case.name);
        }
    }

    #[test]
    fn load_colon_separated_dirs() {
        let tmp = temp_dir("colon-dirs");
        let mut dirs = Vec::new();
        for (i, name) in ["gtsRoot", "googleLeaf"].iter().enumerate() {
            let dir = tmp.join(format!("cert-{i}"));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("cert.crt"), const_pem(name)).unwrap();
            dirs.push(dir.to_string_lossy().into_owned());
        }
        let joined = dirs.join(if cfg!(windows) { ";" } else { ":" });
        let got = load_on_disk_roots(&[], &[], "", &joined).unwrap();
        assert_eq!(got.subjects().len(), 2);

        let mut want = CertPool::new();
        want.append_certs_from_pem(&const_pem("gtsRoot"));
        want.append_certs_from_pem(&const_pem("googleLeaf"));
        assert!(got.equal(&want));
    }

    #[cfg(unix)]
    #[test]
    fn read_unique_directory_entries_skips_same_dir_symlinks() {
        let base = temp_dir("unique-entries");
        std::fs::File::create(base.join("file")).unwrap();
        std::os::unix::fs::symlink("target-in", base.join("link-in")).unwrap();
        std::os::unix::fs::symlink("../target-out", base.join("link-out")).unwrap();
        let got: Vec<String> = read_unique_directory_entries(base.to_str().unwrap())
            .unwrap()
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(got, vec!["file".to_string(), "link-out".to_string()]);
    }

    #[test]
    fn missing_everything_is_an_empty_pool() {
        let pool =
            load_on_disk_roots(&["/nonexistent/file"], &["/nonexistent/dir"], "", "").unwrap();
        assert_eq!(pool.len(), 0);
        let _ = Path::new("/");
    }
}
