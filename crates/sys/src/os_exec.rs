//! Go's `os/exec` over `fork`/`execve`: [`Cmd`] with `ExtraFiles`, Go's
//! "exec format error" for an executable without a shebang, and `WaitDelay`
//! that interrupts copying threads by closing the parent's pipe ends (the
//! pipes are [`File`]s, whose `close` wakes a blocked read or write).
//!
//! Not covered here: `CommandContext`, `Cancel` and `SysProcAttr`.
use crate::errno::{Errno, EACCES, EISDIR, EPERM};
use crate::ffi::at;
use crate::os::{pipe, start_process, File, FileError, ProcAttr, Process, ProcessError, ProcessState};
use std::fmt;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Why `LookPath` failed.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum LookupCause {
    /// `exec.ErrNotFound`: "executable file not found in $PATH".
    NotFound,
    /// `exec.ErrDot`: "cannot run executable found relative to current directory".
    Dot,
    /// `*PathError{Op: "stat"}` from `os.Stat`.
    Stat { path: String, err: Errno },
    /// A bare system error from the access check.
    Errno(Errno),
}

impl fmt::Display for LookupCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LookupCause::NotFound => f.write_str("executable file not found in $PATH"),
            LookupCause::Dot => {
                f.write_str("cannot run executable found relative to current directory")
            }
            LookupCause::Stat { path, err } => write!(f, "stat {path}: {err}"),
            LookupCause::Errno(e) => e.fmt(f),
        }
    }
}

/// `*exec.ExitError`: the command ran and exited unsuccessfully.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExitError {
    /// What `Wait` reported.
    pub process_state: ProcessState,
    /// The start and end of the standard error, when captured by `output`.
    pub stderr: Vec<u8>,
}

/// An error from [`Cmd`] and [`look_path`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CmdError {
    /// `*exec.Error`: `exec: "name": cause`.
    Lookup { name: String, err: LookupCause },
    /// An error from starting or waiting for the process.
    Process(ProcessError),
    /// `*exec.ExitError`.
    Exit(ExitError),
    /// `exec.ErrWaitDelay`: "exec: WaitDelay expired before I/O complete".
    WaitDelay,
    /// A message such as "exec: already started".
    Msg(String),
    /// An error from copying the standard streams.
    Io(String, Option<Errno>),
}

impl fmt::Display for CmdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CmdError::Lookup { name, err } => write!(f, "exec: \"{name}\": {err}"),
            CmdError::Process(e) => e.fmt(f),
            CmdError::Exit(e) => f.write_str(&e.process_state.to_string()),
            CmdError::WaitDelay => f.write_str("exec: WaitDelay expired before I/O complete"),
            CmdError::Msg(m) | CmdError::Io(m, _) => f.write_str(m),
        }
    }
}

impl std::error::Error for CmdError {}

impl CmdError {
    fn msg(m: &str) -> CmdError {
        CmdError::Msg(m.to_string())
    }

    fn errno(&self) -> Option<Errno> {
        match self {
            CmdError::Lookup {
                err: LookupCause::Stat { err, .. } | LookupCause::Errno(err),
                ..
            } => Some(*err),
            CmdError::Process(p) => p.errno(),
            CmdError::Io(_, e) => *e,
            _ => None,
        }
    }

    /// `errors.As(err, &*ExitError)`.
    pub fn exit_error(&self) -> Option<&ExitError> {
        match self {
            CmdError::Exit(e) => Some(e),
            _ => None,
        }
    }
    /// `errors.As(err, &*exec.Error)`.
    pub fn is_lookup_error(&self) -> bool {
        matches!(self, CmdError::Lookup { .. })
    }
    /// `errors.Is(err, exec.ErrNotFound)`.
    pub fn is_not_found(&self) -> bool {
        matches!(self, CmdError::Lookup { err: LookupCause::NotFound, .. })
    }
    /// `errors.Is(err, exec.ErrDot)`.
    pub fn is_dot(&self) -> bool {
        matches!(self, CmdError::Lookup { err: LookupCause::Dot, .. })
    }
    /// `errors.Is(err, exec.ErrWaitDelay)`.
    pub fn is_wait_delay(&self) -> bool {
        matches!(self, CmdError::WaitDelay)
    }
    /// `errors.Is(err, fs.ErrNotExist)`.
    pub fn is_not_exist(&self) -> bool {
        self.errno().is_some_and(|e| e.is("not-exist"))
    }
    /// `errors.Is(err, fs.ErrPermission)`.
    pub fn is_permission(&self) -> bool {
        self.errno().is_some_and(|e| e.is("permission"))
    }
}

impl From<ProcessError> for CmdError {
    fn from(e: ProcessError) -> CmdError {
        CmdError::Process(e)
    }
}

impl From<CmdError> for io::Error {
    fn from(e: CmdError) -> io::Error {
        io::Error::other(e)
    }
}

// ---- LookPath ---------------------------------------------------------------

/// Go's `findExecutable`.
fn find_executable(file: &str) -> Result<(), LookupCause> {
    let md = std::fs::metadata(file).map_err(|e| LookupCause::Stat {
        path: file.to_string(),
        err: Errno::from(e),
    })?;
    if md.is_dir() {
        return Err(LookupCause::Errno(EISDIR));
    }
    at::eaccess_exec(file.as_bytes()).map_err(|e| {
        if e == EPERM {
            LookupCause::Errno(EACCES)
        } else {
            LookupCause::Errno(e)
        }
    })
}

fn lookup(name: &str, err: LookupCause) -> CmdError {
    CmdError::Lookup {
        name: name.to_string(),
        err,
    }
}

/// Go's two-value `LookPath`: the path found (possibly with `ErrDot`) and
/// the error.
pub fn look_path_dot(file: &str) -> (String, Option<CmdError>) {
    if matches!(file, "" | "." | "..") {
        return (String::new(), Some(lookup(file, LookupCause::NotFound)));
    }
    if file.contains('/') {
        return match find_executable(file) {
            Ok(()) => (file.to_string(), None),
            Err(e) => (String::new(), Some(lookup(file, e))),
        };
    }
    let path = std::env::var("PATH").unwrap_or_default();
    // filepath.SplitList: an empty PATH has no elements.
    for dir in path.split(':').filter(|_| !path.is_empty()) {
        let dir = if dir.is_empty() { "." } else { dir };
        let p = clean(&format!("{dir}/{file}"));
        if find_executable(&p).is_ok() {
            if !p.starts_with('/') {
                return (p, Some(lookup(file, LookupCause::Dot)));
            }
            return (p, None);
        }
    }
    (String::new(), Some(lookup(file, LookupCause::NotFound)))
}

/// `exec.LookPath`.
pub fn look_path(file: &str) -> Result<String, CmdError> {
    match look_path_dot(file) {
        (p, None) => Ok(p),
        (_, Some(e)) => Err(e),
    }
}

/// `filepath.Clean` for Unix paths.
fn clean(path: &str) -> String {
    if path.is_empty() {
        return ".".into();
    }
    let rooted = path.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if out.last().is_some_and(|l| *l != "..") {
                    out.pop();
                } else if !rooted {
                    out.push("..");
                }
            }
            p => out.push(p),
        }
    }
    let joined = out.join("/");
    match (rooted, joined.is_empty()) {
        (true, _) => format!("/{joined}"),
        (false, true) => ".".into(),
        (false, false) => joined,
    }
}

/// `filepath.Base` for Unix paths.
fn base(path: &str) -> String {
    if path.is_empty() {
        return ".".into();
    }
    let t = path.trim_end_matches('/');
    if t.is_empty() {
        return "/".into();
    }
    t.rsplit('/').next().unwrap_or(t).to_string()
}

/// `filepath.Abs`.
fn abs(path: &str) -> io::Result<String> {
    if path.starts_with('/') {
        return Ok(clean(path));
    }
    let wd = std::env::current_dir()?;
    Ok(clean(&format!("{}/{path}", wd.to_string_lossy())))
}

// ---- standard streams ---------------------------------------------------------

/// The source of a command's standard input (`Cmd.Stdin`); `None` in
/// [`Cmd::stdin`] means the null device.
pub enum Input {
    /// A file passed to the child directly.
    File(std::fs::File),
    /// The child's end of a pipe from [`Cmd::stdin_pipe`]; closed in this
    /// process after the child has started.
    Pipe(File),
    /// Any reader, copied into a pipe by a thread.
    Reader(Box<dyn Read + Send>),
}

/// The destination of a command's standard output or error.
#[derive(Clone)]
pub enum Output {
    /// A file passed to the child directly.
    File(Arc<std::fs::File>),
    /// The child's end of a pipe from [`Cmd::stdout_pipe`] or
    /// [`Cmd::stderr_pipe`]; closed in this process after the child started.
    Pipe(Arc<File>),
    /// Any writer, fed from a pipe by a thread.
    Writer(Arc<Mutex<dyn Write + Send>>),
}

impl Output {
    /// An output writing to `w`; keep a clone of the `Arc` to read results.
    pub fn writer<W: Write + Send + 'static>(w: Arc<Mutex<W>>) -> Output {
        Output::Writer(w)
    }

    fn same(&self, other: &Output) -> bool {
        match (self, other) {
            (Output::Writer(a), Output::Writer(b)) => {
                std::ptr::eq(Arc::as_ptr(a) as *const (), Arc::as_ptr(b) as *const ())
            }
            (Output::File(a), Output::File(b)) => a.as_raw_fd() == b.as_raw_fd(),
            _ => false,
        }
    }
}

/// Keeps the first and last `n` bytes written, as `exec`'s stderr capture does.
struct PrefixSuffixSaver {
    n: usize,
    prefix: Vec<u8>,
    suffix: Vec<u8>,
    suffix_off: usize,
    skipped: i64,
}

impl PrefixSuffixSaver {
    fn new(n: usize) -> Self {
        PrefixSuffixSaver {
            n,
            prefix: Vec::new(),
            suffix: Vec::new(),
            suffix_off: 0,
            skipped: 0,
        }
    }

    fn fill<'a>(dst: &mut Vec<u8>, n: usize, p: &'a [u8]) -> &'a [u8] {
        let remain = n.saturating_sub(dst.len());
        let add = p.len().min(remain);
        dst.extend_from_slice(&p[..add]);
        &p[add..]
    }

    fn bytes(&self) -> Vec<u8> {
        if self.suffix.is_empty() {
            return self.prefix.clone();
        }
        let mut v = self.prefix.clone();
        if self.skipped == 0 {
            v.extend_from_slice(&self.suffix);
            return v;
        }
        v.extend_from_slice(format!("\n... omitting {} bytes ...\n", self.skipped).as_bytes());
        v.extend_from_slice(&self.suffix[self.suffix_off..]);
        v.extend_from_slice(&self.suffix[..self.suffix_off]);
        v
    }
}

impl Write for PrefixSuffixSaver {
    fn write(&mut self, p: &[u8]) -> io::Result<usize> {
        let lenp = p.len();
        let mut p = Self::fill(&mut self.prefix, self.n, p);
        if p.len() > self.n {
            let overage = p.len() - self.n;
            p = &p[overage..];
            self.skipped += overage as i64;
        }
        p = Self::fill(&mut self.suffix, self.n, p);
        while !p.is_empty() {
            let room = self.n - self.suffix_off;
            let k = p.len().min(room);
            self.suffix[self.suffix_off..self.suffix_off + k].copy_from_slice(&p[..k]);
            p = &p[k..];
            self.skipped += k as i64;
            self.suffix_off += k;
            if self.suffix_off == self.n {
                self.suffix_off = 0;
            }
        }
        Ok(lenp)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ---- Cmd ------------------------------------------------------------------------

type Copier = JoinHandle<Result<(), CmdError>>;

/// An external command (`exec.Cmd`). It can be started once.
pub struct Cmd {
    /// The path of the command to run (`Cmd.Path`).
    pub path: String,
    /// Command line arguments including the command as `args[0]` (`Cmd.Args`).
    pub args: Vec<String>,
    /// The environment as `key=value` strings; `None` uses the current
    /// process's environment (`Cmd.Env`). Later duplicates win.
    pub env: Option<Vec<String>>,
    /// The working directory; empty runs in the caller's (`Cmd.Dir`).
    pub dir: String,
    /// The standard input (`Cmd.Stdin`); `None` is the null device.
    pub stdin: Option<Input>,
    /// The standard output (`Cmd.Stdout`); `None` discards it.
    pub stdout: Option<Output>,
    /// The standard error (`Cmd.Stderr`); `None` discards it.
    pub stderr: Option<Output>,
    /// `Cmd.ExtraFiles`: files for the child's descriptors 3, 4, ... in
    /// order. They are duplicated into the child at exactly those numbers.
    pub extra_files: Vec<std::fs::File>,
    /// The underlying process, once started (`Cmd.Process`).
    pub process: Option<Process>,
    /// Information about the exited process, available after `wait`
    /// (`Cmd.ProcessState`).
    pub process_state: Option<ProcessState>,
    /// The error from resolving `path`, reported by `start` (`Cmd.Err`).
    pub err: Option<CmdError>,
    /// `Cmd.WaitDelay`: how long `wait` lets copying continue after the
    /// process exits before closing the pipes and failing with
    /// `ErrWaitDelay`; zero waits forever.
    pub wait_delay: Duration,
    started: bool,
    parent_io: Vec<Arc<File>>,
    copiers: Vec<Copier>,
    done_rx: Option<mpsc::Receiver<()>>,
}

impl fmt::Debug for Cmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cmd")
            .field("path", &self.path)
            .field("args", &self.args)
            .field("dir", &self.dir)
            .finish_non_exhaustive()
    }
}

/// `exec.Command`: a bare name is resolved with [`look_path`]; a failure is
/// kept in `err` and reported by `start`.
pub fn command(name: &str, args: &[&str]) -> Cmd {
    let mut cmd = Cmd {
        path: name.to_string(),
        args: std::iter::once(name)
            .chain(args.iter().copied())
            .map(str::to_string)
            .collect(),
        env: None,
        dir: String::new(),
        stdin: None,
        stdout: None,
        stderr: None,
        extra_files: Vec::new(),
        process: None,
        process_state: None,
        err: None,
        wait_delay: Duration::ZERO,
        started: false,
        parent_io: Vec::new(),
        copiers: Vec::new(),
        done_rx: None,
    };
    if base(name) == name {
        let (lp, err) = look_path_dot(name);
        if !lp.is_empty() {
            cmd.path = lp;
        }
        cmd.err = err;
    }
    cmd
}

/// What a copying thread reports.
fn io_err(e: FileError) -> CmdError {
    let errno = match &e.err {
        crate::net::Cause::Errno(n) => Some(*n),
        _ => None,
    };
    CmdError::Io(e.to_string(), errno)
}

impl fmt::Display for Cmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.string())
    }
}

impl Cmd {
    /// The command line as a string (`Cmd.String`), for display only.
    fn string(&self) -> String {
        if self.err.is_some() {
            return self.args.join(" ");
        }
        let mut b = self.path.clone();
        for a in self.argv().iter().skip(1) {
            b.push(' ');
            b.push_str(a);
        }
        b
    }

    fn argv(&self) -> Vec<String> {
        if self.args.is_empty() {
            vec![self.path.clone()]
        } else {
            self.args.clone()
        }
    }

    fn environ_checked(&self) -> (Vec<String>, Option<CmdError>) {
        let mut err = None;
        let mut env = match &self.env {
            Some(e) => e.clone(),
            None => {
                let mut env: Vec<String> = std::env::vars_os()
                    .map(|(k, v)| format!("{}={}", k.to_string_lossy(), v.to_string_lossy()))
                    .collect();
                if !self.dir.is_empty() {
                    match abs(&self.dir) {
                        Ok(pwd) => env.push(format!("PWD={pwd}")),
                        Err(e) => err = Some(CmdError::Io(e.to_string(), None)),
                    }
                }
                env
            }
        };
        // dedupEnv: the last value of a key wins; order of first survivors is
        // preserved.
        let mut out: Vec<String> = Vec::with_capacity(env.len());
        let mut saw = std::collections::HashSet::new();
        for kv in env.drain(..).rev() {
            if kv.contains('\0') {
                err = Some(CmdError::msg("exec: environment variable contains NUL"));
                continue;
            }
            let mut i = kv.find('=');
            if i == Some(0) {
                i = kv[1..].find('=').map(|j| j + 1);
            }
            match i {
                None => {
                    if !kv.is_empty() {
                        out.push(kv);
                    }
                }
                Some(i) => {
                    if saw.insert(kv[..i].to_string()) {
                        out.push(kv);
                    }
                }
            }
        }
        out.reverse();
        (out, err)
    }

    /// The environment the command will run with (`Cmd.Environ`).
    pub fn environ(&self) -> Vec<String> {
        self.environ_checked().0
    }

    /// Starts the command but does not wait for it (`Cmd.Start`). The
    /// program is started with `execve`, so a file that is not a valid
    /// executable image fails with "exec format error".
    pub fn start(&mut self) -> Result<(), CmdError> {
        if self.started {
            return Err(CmdError::msg("exec: already started"));
        }
        self.started = true;
        self.start_inner()
    }

    fn start_inner(&mut self) -> Result<(), CmdError> {
        if self.path.is_empty() && self.err.is_none() {
            self.err = Some(CmdError::msg("exec: no command"));
        }
        if let Some(e) = &self.err {
            return Err(e.clone());
        }
        // Files kept open until the child has started.
        let mut keep_files: Vec<std::fs::File> = Vec::new();
        let mut child_ends: Vec<File> = Vec::new();
        let mut fds: Vec<Option<RawFd>> = Vec::new();
        let mut tasks: Vec<Box<dyn FnOnce() -> Result<(), CmdError> + Send>> = Vec::new();

        // Standard input.
        match self.stdin.take() {
            None => {
                let f = std::fs::File::open("/dev/null").map_err(|e| io_msg(&e))?;
                fds.push(Some(f.as_raw_fd()));
                keep_files.push(f);
            }
            Some(Input::File(f)) => {
                fds.push(Some(f.as_raw_fd()));
                keep_files.push(f);
            }
            Some(Input::Pipe(p)) => {
                fds.push(Some(p.as_raw_fd()));
                child_ends.push(p);
            }
            Some(Input::Reader(mut r)) => {
                let (pr, pw) = pipe().map_err(|e| CmdError::Io(e.to_string(), Some(e)))?;
                fds.push(Some(pr.as_raw_fd()));
                child_ends.push(pr);
                let pw = Arc::new(pw);
                self.parent_io.push(pw.clone());
                tasks.push(Box::new(move || {
                    let mut buf = vec![0u8; 32 * 1024];
                    let mut res = Ok(());
                    loop {
                        match r.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                if let Err(e) = pw.write(&buf[..n]) {
                                    // A child that stops reading is not an error.
                                    let broken = matches!(&e.err,
                                        crate::net::Cause::Errno(n) if *n == crate::errno::EPIPE);
                                    if !broken {
                                        res = Err(io_err(e));
                                    }
                                    break;
                                }
                            }
                            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                            Err(e) => {
                                res = Err(io_msg(&e));
                                break;
                            }
                        }
                    }
                    let _ = pw.close();
                    res
                }));
            }
        }

        // Standard output and error.
        // A pipe's child end is handed over and closed after the start; the
        // other kinds stay set.
        let out = match &self.stdout {
            Some(Output::Pipe(_)) => self.stdout.take(),
            o => o.clone(),
        };
        let err_out = match &self.stderr {
            Some(Output::Pipe(_)) => self.stderr.take(),
            o => o.clone(),
        };
        let same = matches!((&out, &err_out), (Some(o), Some(e)) if e.same(o));
        let mut out_fd = self.output_fd(out, &mut keep_files, &mut child_ends, &mut tasks)?;
        fds.push(Some(out_fd));
        if same {
            // Output::Pipe shares the one child end.
            out_fd = fds[1].unwrap_or(out_fd);
            fds.push(Some(out_fd));
        } else {
            let fd = self.output_fd(err_out, &mut keep_files, &mut child_ends, &mut tasks)?;
            fds.push(Some(fd));
        }

        // ExtraFiles: descriptors 3, 4, ...
        for f in &self.extra_files {
            fds.push(Some(f.as_raw_fd()));
        }

        let (env, env_err) = self.environ_checked();
        if let Some(e) = env_err {
            return Err(e);
        }
        let attr = ProcAttr {
            dir: self.dir.clone(),
            env: Some(env),
            files: fds,
        };
        let started = start_process(&self.path, &self.argv(), &attr);
        // The child's ends of the pipes must not stay open here, or the
        // reader would never see end of file.
        for p in child_ends {
            let _ = p.close();
        }
        drop(keep_files);
        let process = started.inspect_err(|_| {
            for p in self.parent_io.drain(..) {
                let _ = p.close();
            }
        })?;
        self.process = Some(process);

        if !tasks.is_empty() {
            let (tx, rx) = mpsc::channel();
            for t in tasks {
                let tx = tx.clone();
                self.copiers.push(thread::spawn(move || {
                    let r = t();
                    let _ = tx.send(());
                    r
                }));
            }
            self.done_rx = Some(rx);
        }
        Ok(())
    }

    /// The child's descriptor for an output stream, creating the pipe and
    /// copying thread for a writer.
    fn output_fd(
        &mut self,
        o: Option<Output>,
        keep_files: &mut Vec<std::fs::File>,
        child_ends: &mut Vec<File>,
        tasks: &mut Vec<Box<dyn FnOnce() -> Result<(), CmdError> + Send>>,
    ) -> Result<RawFd, CmdError> {
        match o {
            None => {
                let f = std::fs::OpenOptions::new()
                    .write(true)
                    .open("/dev/null")
                    .map_err(|e| io_msg(&e))?;
                let fd = f.as_raw_fd();
                keep_files.push(f);
                Ok(fd)
            }
            Some(Output::File(f)) => {
                let fd = f.as_raw_fd();
                keep_files.push(f.try_clone().map_err(|e| io_msg(&e))?);
                Ok(fd)
            }
            Some(Output::Pipe(p)) => {
                let fd = p.as_raw_fd();
                if let Ok(file) = Arc::try_unwrap(p) {
                    child_ends.push(file);
                }
                Ok(fd)
            }
            Some(Output::Writer(w)) => {
                let (pr, pw) = pipe().map_err(|e| CmdError::Io(e.to_string(), Some(e)))?;
                let fd = pw.as_raw_fd();
                child_ends.push(pw);
                let pr = Arc::new(pr);
                self.parent_io.push(pr.clone());
                tasks.push(Box::new(move || {
                    let mut buf = vec![0u8; 32 * 1024];
                    let mut res = Ok(());
                    loop {
                        match pr.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                let mut g = w.lock().unwrap_or_else(|e| e.into_inner());
                                if let Err(e) = g.write_all(&buf[..n]) {
                                    res = Err(io_msg(&e));
                                    break;
                                }
                            }
                            Err(e) => {
                                res = Err(io_err(e));
                                break;
                            }
                        }
                    }
                    let _ = pr.close();
                    res
                }));
                Ok(fd)
            }
        }
    }

    /// Waits for the command to exit and for copying to finish (`Cmd.Wait`).
    /// A non-zero exit status is an [`ExitError`]. If `wait_delay` is set and
    /// copying is still going on that long after the process exited, the
    /// parent's pipe ends are closed, which interrupts the copying threads,
    /// and the result is `ErrWaitDelay`.
    pub fn wait(&mut self) -> Result<(), CmdError> {
        let Some(process) = self.process.clone() else {
            return Err(CmdError::msg("exec: not started"));
        };
        if self.process_state.is_some() {
            return Err(CmdError::msg("exec: Wait was already called"));
        }
        let state = process.wait();
        let mut err = match &state {
            Ok(st) if !st.success() => Some(CmdError::Exit(ExitError {
                process_state: *st,
                stderr: Vec::new(),
            })),
            Ok(_) => None,
            Err(e) => Some(CmdError::Process(e.clone())),
        };
        self.process_state = state.ok();
        let copy_err = self.await_copiers();
        if err.is_none() {
            err = copy_err;
        }
        match err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn await_copiers(&mut self) -> Option<CmdError> {
        let rx = self.done_rx.take()?;
        let mut remaining = self.copiers.len();
        let deadline = (!self.wait_delay.is_zero()).then(|| Instant::now() + self.wait_delay);
        let mut expired = false;
        while remaining > 0 {
            let got = match deadline {
                None => rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
                Some(d) => rx.recv_timeout(d.saturating_duration_since(Instant::now())),
            };
            match got {
                Ok(()) => remaining -= 1,
                Err(RecvTimeoutError::Timeout) => {
                    expired = true;
                    // Closing the parent's ends wakes the blocked threads.
                    for p in &self.parent_io {
                        let _ = p.close();
                    }
                    break;
                }
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        let mut first = None;
        for h in self.copiers.drain(..) {
            if let Ok(Err(e)) = h.join() {
                first.get_or_insert(e);
            }
        }
        self.parent_io.clear();
        if expired {
            return Some(CmdError::WaitDelay);
        }
        first
    }

    /// Starts the command and waits for it to complete (`Cmd.Run`).
    pub fn run(&mut self) -> Result<(), CmdError> {
        self.start()?;
        self.wait()
    }

    /// Runs the command and returns its standard output together with the
    /// error (`Cmd.Output`). If `stderr` was not set, the start and end of
    /// its output is captured in the [`ExitError`] on failure.
    pub fn output(&mut self) -> (Vec<u8>, Result<(), CmdError>) {
        if self.stdout.is_some() {
            return (Vec::new(), Err(CmdError::msg("exec: Stdout already set")));
        }
        let out = Arc::new(Mutex::new(Vec::<u8>::new()));
        self.stdout = Some(Output::writer(out.clone()));
        let capture = self.stderr.is_none();
        let saver = Arc::new(Mutex::new(PrefixSuffixSaver::new(32 << 10)));
        if capture {
            self.stderr = Some(Output::writer(saver.clone()));
        }
        let result = self.run();
        let data = std::mem::take(&mut *out.lock().unwrap_or_else(|e| e.into_inner()));
        if let (Err(CmdError::Exit(ee)), true) = (&result, capture) {
            let mut ee = ee.clone();
            ee.stderr = saver.lock().unwrap_or_else(|e| e.into_inner()).bytes();
            return (data, Err(CmdError::Exit(ee)));
        }
        (data, result)
    }

    /// Runs the command and returns its combined standard output and
    /// standard error (`Cmd.CombinedOutput`).
    pub fn combined_output(&mut self) -> (Vec<u8>, Result<(), CmdError>) {
        if self.stdout.is_some() {
            return (Vec::new(), Err(CmdError::msg("exec: Stdout already set")));
        }
        if self.stderr.is_some() {
            return (Vec::new(), Err(CmdError::msg("exec: Stderr already set")));
        }
        let b = Arc::new(Mutex::new(Vec::<u8>::new()));
        self.stdout = Some(Output::writer(b.clone()));
        self.stderr = Some(Output::writer(b.clone()));
        let r = self.run();
        let data = std::mem::take(&mut *b.lock().unwrap_or_else(|e| e.into_inner()));
        (data, r)
    }

    /// A pipe connected to the command's standard input (`Cmd.StdinPipe`);
    /// the caller closes it.
    pub fn stdin_pipe(&mut self) -> Result<File, CmdError> {
        if self.stdin.is_some() {
            return Err(CmdError::msg("exec: Stdin already set"));
        }
        if self.process.is_some() {
            return Err(CmdError::msg("exec: StdinPipe after process started"));
        }
        let (pr, pw) = pipe().map_err(|e| CmdError::Io(e.to_string(), Some(e)))?;
        self.stdin = Some(Input::Pipe(pr));
        Ok(pw)
    }

    /// A pipe connected to the command's standard output (`Cmd.StdoutPipe`).
    pub fn stdout_pipe(&mut self) -> Result<File, CmdError> {
        if self.stdout.is_some() {
            return Err(CmdError::msg("exec: Stdout already set"));
        }
        if self.process.is_some() {
            return Err(CmdError::msg("exec: StdoutPipe after process started"));
        }
        let (pr, pw) = pipe().map_err(|e| CmdError::Io(e.to_string(), Some(e)))?;
        self.stdout = Some(Output::Pipe(Arc::new(pw)));
        Ok(pr)
    }

    /// A pipe connected to the command's standard error (`Cmd.StderrPipe`).
    pub fn stderr_pipe(&mut self) -> Result<File, CmdError> {
        if self.stderr.is_some() {
            return Err(CmdError::msg("exec: Stderr already set"));
        }
        if self.process.is_some() {
            return Err(CmdError::msg("exec: StderrPipe after process started"));
        }
        let (pr, pw) = pipe().map_err(|e| CmdError::Io(e.to_string(), Some(e)))?;
        self.stderr = Some(Output::Pipe(Arc::new(pw)));
        Ok(pr)
    }
}

fn io_msg(e: &io::Error) -> CmdError {
    CmdError::Io(e.to_string(), e.raw_os_error().map(Errno))
}
