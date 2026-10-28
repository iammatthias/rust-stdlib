//! Go's `os/exec`: running external commands, over `std::process`.
//!
//! [`Cmd`] mirrors `exec.Cmd`: set the public fields, then [`Cmd::run`],
//! [`Cmd::output`] or [`Cmd::start`] and [`Cmd::wait`]. Standard streams are
//! [`Input`] and [`Output`] values: a [`File`] is passed to the child
//! directly, any other reader or writer is connected through a pipe and a
//! copying thread, exactly as Go does with goroutines.
//!
//! Differences from Go, all forced by safe `std`:
//!
//! * `ExtraFiles` and `SysProcAttr` cannot be honored (`std` cannot place a
//!   descriptor at an arbitrary number without `unsafe`); `start` fails when
//!   `extra_files` is not empty and there is no `SysProcAttr` field.
//! * The pipes returned by [`Cmd::stdout_pipe`] and friends are [`PipeEnd`]s, a
//!   shared handle on a [`File`]: as in Go, [`Cmd::wait`] closes the parent's
//!   end after the process exits, and later reads or writes fail with "file
//!   already closed".
//! * With `wait_delay`, a copying thread blocked on a pipe that a grandchild
//!   still holds open is abandoned rather than interrupted.

use super::error::{errno, from_errno, Errno};
use super::file::{pipe, File};
use super::proc::{spawn_process, Process, ProcessState};
use super::{environ, getenv};
use crate::context::Context;
use crate::io::fs;
use crate::time::Duration;
use std::fmt;
use std::io::{self, Read, Write};
use std::process::Stdio;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Instant;

/// The error of `LookPath` and `Command` (`exec.Error`): `exec: "name": err`.
#[derive(Debug)]
pub struct Error {
    /// The file name that failed to resolve (`Error.Name`).
    pub name: String,
    /// The underlying error (`Error.Err`).
    pub err: io::Error,
}

impl Error {
    /// The underlying error (`Error.Unwrap`).
    pub fn unwrap(&self) -> &io::Error {
        &self.err
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "exec: {}: {}",
            crate::strconv::quote(&self.name),
            self.err
        )
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.err)
    }
}

impl From<Error> for io::Error {
    fn from(e: Error) -> io::Error {
        io::Error::new(e.err.kind(), e)
    }
}

/// Returns the [`Error`] inside `err`, if any.
pub fn error_of(err: &io::Error) -> Option<&Error> {
    err.get_ref().and_then(|e| e.downcast_ref::<Error>())
}

/// The sentinels of `os/exec` (`ErrNotFound`, `ErrDot`, `ErrWaitDelay`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Sentinel {
    /// `exec.ErrNotFound`
    NotFound,
    /// `exec.ErrDot`
    Dot,
    /// `exec.ErrWaitDelay`
    WaitDelay,
}

/// `exec.ErrNotFound`: the executable was not found in `$PATH`.
pub const ERR_NOT_FOUND: Sentinel = Sentinel::NotFound;
/// `exec.ErrDot`: the executable was found relative to the current directory.
pub const ERR_DOT: Sentinel = Sentinel::Dot;
/// `exec.ErrWaitDelay`: `WaitDelay` expired before I/O completed.
pub const ERR_WAIT_DELAY: Sentinel = Sentinel::WaitDelay;

impl Sentinel {
    /// Reports whether `err` is or wraps this sentinel (`errors.Is`).
    pub fn is(self, err: &io::Error) -> bool {
        crate::io::chain_has(err, &self)
    }
}

impl fmt::Display for Sentinel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Sentinel::NotFound => "executable file not found in $PATH",
            Sentinel::Dot => "cannot run executable found relative to current directory",
            Sentinel::WaitDelay => "exec: WaitDelay expired before I/O complete",
        })
    }
}

impl std::error::Error for Sentinel {}

impl From<Sentinel> for io::Error {
    fn from(s: Sentinel) -> io::Error {
        // Go's `ErrNotFound` is not `ErrNotExist`: the kind is `Other`.
        io::Error::other(s)
    }
}

/// A command that exited with a non-zero status (`exec.ExitError`).
#[derive(Clone, Debug)]
pub struct ExitError {
    /// The exit information (`ExitError.ProcessState`).
    pub process_state: ProcessState,
    /// The start and end of the standard error output, captured by
    /// [`Cmd::output`] when `stderr` was not set (`ExitError.Stderr`).
    pub stderr: Vec<u8>,
}

impl fmt::Display for ExitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.process_state)
    }
}

impl std::error::Error for ExitError {}

impl From<ExitError> for io::Error {
    fn from(e: ExitError) -> io::Error {
        io::Error::other(e)
    }
}

/// Returns the [`ExitError`] inside `err`, if any.
pub fn exit_error(err: &io::Error) -> Option<&ExitError> {
    err.get_ref().and_then(|e| e.downcast_ref::<ExitError>())
}

#[derive(Debug)]
struct WrappedError {
    prefix: &'static str,
    err: io::Error,
}

impl fmt::Display for WrappedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.prefix, self.err)
    }
}

impl std::error::Error for WrappedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.err)
    }
}

/// A copy of `err`: payloads of this crate's error types are rebuilt, any
/// other error keeps its kind and message.
fn clone_error(err: &io::Error) -> io::Error {
    if let Some(e) = error_of(err) {
        return Error {
            name: e.name.clone(),
            err: clone_error(&e.err),
        }
        .into();
    }
    if let Some(s) = err.get_ref().and_then(|e| e.downcast_ref::<Sentinel>()) {
        return (*s).into();
    }
    if let Some(n) = super::errno_of(err) {
        if err.raw_os_error().is_some() || err.get_ref().is_some_and(|e| e.is::<Errno>()) {
            return n.into();
        }
    }
    if let Some(p) = fs::path_error(err) {
        return fs::PathError::new(&p.op, &p.path, clone_error(&p.err)).into();
    }
    if let Some(e) = err.get_ref().and_then(|e| e.downcast_ref::<fs::Error>()) {
        return (*e).into();
    }
    if let Some(e) = err.get_ref().and_then(|e| e.downcast_ref::<super::Error>()) {
        return (*e).into();
    }
    io::Error::new(err.kind(), err.to_string())
}

// ---- LookPath ---------------------------------------------------------------

/// `findExecutable`: `file` must be a regular, executable (for the effective
/// user) file.
fn find_executable(file: &str) -> io::Result<()> {
    let d = super::stat(file)?;
    if d.is_dir() {
        return Err(from_errno(errno::EISDIR));
    }
    let mode = d.mode().0;
    let (euid, egid, groups) = super::creds();
    let meta = d
        .sys()
        .and_then(|s| s.downcast_ref::<std::fs::Metadata>())
        .cloned();
    let ok = match meta {
        Some(meta) => {
            use std::os::unix::fs::MetadataExt;
            if euid == 0 {
                mode & 0o111 != 0
            } else if euid >= 0 && meta.uid() == euid as u32 {
                mode & 0o100 != 0
            } else if egid >= 0
                && (meta.gid() == egid as u32 || groups.contains(&(meta.gid() as i32)))
            {
                mode & 0o010 != 0
            } else {
                mode & 0o001 != 0
            }
        }
        None => mode & 0o111 != 0,
    };
    if ok {
        Ok(())
    } else {
        Err(from_errno(errno::EACCES))
    }
}

/// Go's two-value `LookPath`: the path found (possibly with [`ERR_DOT`]) and
/// the error. `LookPath` returns the path together with `ErrDot`; the
/// path is empty on other errors.
pub fn look_path_dot(file: &str) -> (String, Option<io::Error>) {
    if matches!(file, "" | "." | "..") {
        return (
            String::new(),
            Some(
                Error {
                    name: file.to_string(),
                    err: Sentinel::NotFound.into(),
                }
                .into(),
            ),
        );
    }
    if file.contains('/') {
        return match find_executable(file) {
            Ok(()) => (file.to_string(), None),
            Err(err) => (
                String::new(),
                Some(
                    Error {
                        name: file.to_string(),
                        err,
                    }
                    .into(),
                ),
            ),
        };
    }
    let path = getenv("PATH");
    for dir in crate::path::filepath::split_list(&path) {
        let dir = if dir.is_empty() { ".".to_string() } else { dir };
        let p = crate::path::filepath::join(&[dir.as_str(), file]);
        if find_executable(&p).is_ok() {
            if !p.starts_with('/') {
                return (
                    p,
                    Some(
                        Error {
                            name: file.to_string(),
                            err: Sentinel::Dot.into(),
                        }
                        .into(),
                    ),
                );
            }
            return (p, None);
        }
    }
    (
        String::new(),
        Some(
            Error {
                name: file.to_string(),
                err: Sentinel::NotFound.into(),
            }
            .into(),
        ),
    )
}

/// Searches for an executable named `file` in the directories of `$PATH`
/// (`exec.LookPath`). A `file` with a slash is tried as is. A result found
/// relative to the current directory fails with [`ERR_DOT`]; use
/// [`look_path_dot`] to also get the path.
pub fn look_path(file: &str) -> io::Result<String> {
    match look_path_dot(file) {
        (p, None) => Ok(p),
        (_, Some(e)) => Err(e),
    }
}

// ---- standard streams ---------------------------------------------------------

/// The source of a command's standard input (`Cmd.Stdin`). `None` in
/// [`Cmd::stdin`] means the null device.
pub enum Input {
    /// A file passed to the child directly.
    File(File),
    /// Any reader, copied into a pipe by a thread.
    Reader(Box<dyn Read + Send>),
}

impl Input {
    /// An input reading from `r`.
    pub fn reader(r: impl Read + Send + 'static) -> Input {
        Input::Reader(Box::new(r))
    }
}

impl fmt::Debug for Input {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Input::File(file) => f.debug_tuple("File").field(file).finish(),
            Input::Reader(_) => f.write_str("Reader(..)"),
        }
    }
}

/// The destination of a command's standard output or error (`Cmd.Stdout`,
/// `Cmd.Stderr`). `None` means the null device. Two `Writer`s that are the
/// same `Arc` (or two `File`s with the same descriptor) share one pipe and
/// are written one at a time.
#[derive(Clone)]
pub enum Output {
    /// A file passed to the child directly.
    File(Arc<File>),
    /// Any writer, fed from a pipe by a thread.
    Writer(Arc<Mutex<dyn Write + Send>>),
}

impl Output {
    /// An output writing to `w`; keep a clone of the `Arc` to read results.
    pub fn writer<W: Write + Send + 'static>(w: Arc<Mutex<W>>) -> Output {
        Output::Writer(w)
    }

    /// An output writing to `f`.
    pub fn file(f: File) -> Output {
        Output::File(Arc::new(f))
    }

    fn same(&self, other: &Output) -> bool {
        match (self, other) {
            (Output::File(a), Output::File(b)) => Arc::ptr_eq(a, b) || a.fd() == b.fd(),
            (Output::Writer(a), Output::Writer(b)) => {
                std::ptr::eq(Arc::as_ptr(a) as *const (), Arc::as_ptr(b) as *const ())
            }
            _ => false,
        }
    }
}

impl fmt::Debug for Output {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Output::File(file) => f.debug_tuple("File").field(file).finish(),
            Output::Writer(_) => f.write_str("Writer(..)"),
        }
    }
}

/// Keeps the first and last `n` bytes written, as `exec`'s stderr capture
/// does.
#[derive(Debug)]
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
        if self.skipped == 0 {
            let mut v = self.prefix.clone();
            v.extend_from_slice(&self.suffix);
            return v;
        }
        let mut v = self.prefix.clone();
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

type CancelFn = Box<dyn Fn(&Process) -> io::Result<()> + Send + Sync>;

struct Watch {
    shared: Arc<(Mutex<bool>, Condvar)>,
    stop: crate::context::CancelFunc,
    result: Receiver<WatchResult>,
}

struct WatchResult {
    err: Option<io::Error>,
    deadline: Option<Instant>,
    expired: bool,
}

/// The parent's end of a pipe from [`Cmd::stdin_pipe`], [`Cmd::stdout_pipe`] or
/// [`Cmd::stderr_pipe`]. It is a shared handle on the pipe's [`File`] (and
/// dereferences to it): [`Cmd::wait`] closes it once the process has exited, so
/// the caller need not, and later I/O or a second close fail with "file
/// already closed", as with Go's `*os.File`.
#[derive(Clone)]
pub struct PipeEnd {
    file: Arc<File>,
}

impl PipeEnd {
    fn new(file: File) -> PipeEnd {
        PipeEnd {
            file: Arc::new(file),
        }
    }

    /// Closes the pipe (`Close`).
    pub fn close(&self) -> io::Result<()> {
        self.file.close()
    }
}

impl std::ops::Deref for PipeEnd {
    type Target = File;
    fn deref(&self) -> &File {
        &self.file
    }
}

impl fmt::Debug for PipeEnd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PipeEnd").field(&self.file).finish()
    }
}

impl Read for PipeEnd {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&*self.file).read(buf)
    }
}

impl Read for &PipeEnd {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&*self.file).read(buf)
    }
}

impl Write for PipeEnd {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&*self.file).write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        (&*self.file).flush()
    }
}

impl Write for &PipeEnd {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&*self.file).write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        (&*self.file).flush()
    }
}

/// An external command (`exec.Cmd`).
///
/// A `Cmd` can be started once. Fields are set before [`Cmd::start`].
pub struct Cmd {
    /// The path of the command to run (`Cmd.Path`).
    pub path: String,
    /// Command line arguments including the command as `args[0]`
    /// (`Cmd.Args`).
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
    /// Extra files for the child (`Cmd.ExtraFiles`). Not supported: `start`
    /// fails if this is not empty.
    pub extra_files: Vec<File>,
    /// The underlying process, once started (`Cmd.Process`).
    pub process: Option<Process>,
    /// Information about the exited process, available after `wait`
    /// (`Cmd.ProcessState`).
    pub process_state: Option<ProcessState>,
    /// The error from resolving `path`, reported by `start` (`Cmd.Err`).
    pub err: Option<io::Error>,
    /// Called when the context is done (`Cmd.Cancel`); only valid for
    /// commands made by [`command_context`]. The default kills the process.
    pub cancel: Option<CancelFn>,
    /// How long to wait for I/O after the context is done or the process
    /// exits before giving up (`Cmd.WaitDelay`); zero waits forever.
    pub wait_delay: Duration,
    ctx: Option<Context>,
    started: bool,
    /// Which standard streams were set by the pipe helpers; the parent's
    /// copy of the child's end is dropped once the process has started.
    pipe_ends: [bool; 3],
    child_io: Vec<File>,
    /// The parent's ends of the pipe helpers, closed by `wait`.
    parent_io: Vec<PipeEnd>,
    goroutines: Vec<JoinHandle<io::Result<()>>>,
    goroutine_rx: Option<Receiver<io::Result<()>>>,
    goroutine_count: usize,
    watch: Option<Watch>,
}

impl fmt::Debug for Cmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cmd")
            .field("path", &self.path)
            .field("args", &self.args)
            .field("dir", &self.dir)
            .field("process", &self.process)
            .finish_non_exhaustive()
    }
}

/// Returns a [`Cmd`] to run the named program with the arguments
/// (`exec.Command`). A bare name is resolved with [`look_path`]; a failure
/// is stored in `err` and reported by `start`.
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
        cancel: None,
        wait_delay: Duration::ZERO,
        ctx: None,
        started: false,
        pipe_ends: [false; 3],
        child_io: Vec::new(),
        parent_io: Vec::new(),
        goroutines: Vec::new(),
        goroutine_rx: None,
        goroutine_count: 0,
        watch: None,
    };
    if crate::path::filepath::base(name) == name {
        let (lp, err) = look_path_dot(name);
        if !lp.is_empty() {
            cmd.path = lp;
        }
        cmd.err = err;
    }
    cmd
}

/// Like [`command`] but the command is killed when `ctx` is done
/// (`exec.CommandContext`). Cancel through `cancel` and the grace period
/// `wait_delay` to change that.
pub fn command_context(ctx: &Context, name: &str, args: &[&str]) -> Cmd {
    let mut cmd = command(name, args);
    cmd.ctx = Some(ctx.clone());
    cmd.cancel = Some(Box::new(|p: &Process| p.kill()));
    cmd
}

fn ctx_error(e: crate::context::Error) -> io::Error {
    io::Error::new(
        match e {
            crate::context::Error::DeadlineExceeded => io::ErrorKind::TimedOut,
            crate::context::Error::Canceled => io::ErrorKind::Other,
        },
        e,
    )
}

type CopyTask = Box<dyn FnOnce() -> io::Result<()> + Send>;

/// The command line (`Cmd.String`), for display only.
impl fmt::Display for Cmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.err.is_some() {
            return f.write_str(&self.args.join(" "));
        }
        f.write_str(&self.path)?;
        for a in self.argv().iter().skip(1) {
            write!(f, " {a}")?;
        }
        Ok(())
    }
}

impl Cmd {
    fn argv(&self) -> Vec<String> {
        if self.args.is_empty() {
            vec![self.path.clone()]
        } else {
            self.args.clone()
        }
    }

    fn environ_checked(&self) -> (Vec<String>, Option<io::Error>) {
        let mut err = None;
        let mut env = match &self.env {
            Some(e) => e.clone(),
            None => {
                let mut env = environ();
                if !self.dir.is_empty() {
                    match crate::path::filepath::abs(&self.dir) {
                        Ok(pwd) => env.push(format!("PWD={pwd}")),
                        Err(e) => err = Some(e),
                    }
                }
                env
            }
        };
        // dedupEnv: the last value of a key wins; order of first survivors
        // is preserved.
        let mut out: Vec<String> = Vec::with_capacity(env.len());
        let mut saw = std::collections::HashSet::new();
        for kv in env.drain(..).rev() {
            if kv.contains('\0') {
                err = Some(io::Error::other("exec: environment variable contains NUL"));
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

    fn child_stdin(&mut self, tasks: &mut Vec<CopyTask>) -> io::Result<Stdio> {
        match self.stdin.take() {
            None => Ok(Stdio::null()),
            Some(Input::File(f)) => {
                let s = Stdio::from(f.try_clone_std()?);
                self.stdin = Some(Input::File(f));
                Ok(s)
            }
            Some(Input::Reader(mut r)) => {
                let (pr, pw) = pipe()?;
                let child = Stdio::from(pr.try_clone_std()?);
                self.child_io.push(pr);
                tasks.push(Box::new(move || {
                    let res = io::copy(&mut r, &mut &pw);
                    let res = match res {
                        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(0),
                        r => r,
                    };
                    let closed = pw.close();
                    res.map(|_| ()).and(closed)
                }));
                Ok(child)
            }
        }
    }

    fn writer_stdio(
        &mut self,
        w: Option<Output>,
        tasks: &mut Vec<CopyTask>,
    ) -> io::Result<(Stdio, Option<File>)> {
        match w {
            None => Ok((Stdio::null(), None)),
            Some(Output::File(f)) => Ok((Stdio::from(f.try_clone_std()?), None)),
            Some(Output::Writer(w)) => {
                let (pr, pw) = pipe()?;
                let child = pw.try_clone_std()?;
                self.child_io.push(pw);
                tasks.push(Box::new(move || {
                    let mut buf = vec![0u8; 32 * 1024];
                    let mut res = Ok(());
                    loop {
                        match (&pr).read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                let mut g = w.lock().unwrap_or_else(|e| e.into_inner());
                                if let Err(e) = g.write_all(&buf[..n]) {
                                    res = Err(e);
                                    break;
                                }
                            }
                            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                            Err(e) => {
                                res = Err(e);
                                break;
                            }
                        }
                    }
                    let _ = pr.close();
                    res
                }));
                Ok((Stdio::from(child), None))
            }
        }
    }

    /// Starts the command but does not wait for it (`Cmd.Start`).
    pub fn start(&mut self) -> io::Result<()> {
        if self.started {
            return Err(io::Error::other("exec: already started"));
        }
        self.started = true;
        let r = self.start_inner();
        // Close the child's ends of the pipes whether or not it started.
        self.child_io.clear();
        if r.is_err() {
            self.close_parent_io();
            self.goroutines.clear();
        }
        r
    }

    fn start_inner(&mut self) -> io::Result<()> {
        if self.path.is_empty() && self.err.is_none() {
            self.err = Some(io::Error::other("exec: no command"));
        }
        if let Some(e) = &self.err {
            return Err(clone_error(e));
        }
        if self.cancel.is_some() && self.ctx.is_none() {
            return Err(io::Error::other(
                "exec: command with a non-nil Cancel was not created with CommandContext",
            ));
        }
        if let Some(ctx) = &self.ctx {
            ctx.check().map_err(ctx_error)?;
        }
        if !self.extra_files.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "exec: ExtraFiles is not supported",
            ));
        }
        let mut tasks: Vec<CopyTask> = Vec::new();
        let stdin = self.child_stdin(&mut tasks)?;
        let out = self.stdout.clone();
        let (stdout, _) = self.writer_stdio(out.clone(), &mut tasks)?;
        // Stderr shares the stdout pipe when both are the same writer.
        let same = matches!((&self.stderr, &out), (Some(e), Some(o)) if e.same(o));
        let stderr = if same {
            // The stdout child end was the last file pushed (or a File).
            match &out {
                Some(Output::File(f)) => Stdio::from(f.try_clone_std()?),
                Some(Output::Writer(_)) => {
                    let last = self
                        .child_io
                        .last()
                        .ok_or_else(|| io::Error::other("exec: missing pipe"))?;
                    Stdio::from(last.try_clone_std()?)
                }
                None => Stdio::null(),
            }
        } else {
            let e = self.stderr.clone();
            self.writer_stdio(e, &mut tasks)?.0
        };
        let (env, env_err) = self.environ_checked();
        if let Some(e) = env_err {
            return Err(e);
        }
        let argv = self.argv();
        let process = spawn_process(
            &self.path,
            &argv,
            &self.dir,
            Some(&env),
            [stdin, stdout, stderr],
        )?;
        self.process = Some(process);
        self.child_io.clear();
        // The pipes' child ends must not stay open in this process, or the
        // reader would never see end of file.
        if self.pipe_ends[0] {
            self.stdin = None;
        }
        if self.pipe_ends[1] {
            self.stdout = None;
        }
        if self.pipe_ends[2] {
            self.stderr = None;
        }

        if !tasks.is_empty() {
            let (tx, rx) = mpsc::channel();
            self.goroutine_count = tasks.len();
            for t in tasks {
                let tx = tx.clone();
                thread::spawn(move || {
                    let _ = tx.send(t());
                });
            }
            self.goroutine_rx = Some(rx);
        }

        if (self.cancel.is_some() || !self.wait_delay.is_zero()) && self.ctx.is_some() {
            self.start_watch();
        }
        Ok(())
    }

    fn start_watch(&mut self) {
        let Some(ctx) = &self.ctx else { return };
        let (stop, stop_cancel) = ctx.with_cancel();
        let shared = Arc::new((Mutex::new(false), Condvar::new()));
        let (tx, rx) = mpsc::channel();
        let wctx = stop.clone();
        let wshared = shared.clone();
        let process = self.process.clone().expect("process started");
        let cancel = self.cancel.take();
        let delay = self.wait_delay;
        thread::spawn(move || {
            wctx.done().wait();
            let is_done = || *wshared.0.lock().unwrap_or_else(|e| e.into_inner());
            if is_done() {
                let _ = tx.send(WatchResult {
                    err: None,
                    deadline: None,
                    expired: false,
                });
                return;
            }
            let mut err = None;
            if let Some(cancel) = &cancel {
                match cancel(&process) {
                    Ok(()) => {
                        err = Some(ctx_error(
                            wctx.check()
                                .err()
                                .unwrap_or(crate::context::Error::Canceled),
                        ))
                    }
                    Err(e) if super::Error::ProcessDone.is(&e) => {}
                    Err(e) => {
                        err = Some(
                            WrappedError {
                                prefix: "exec: canceling Cmd",
                                err: e,
                            }
                            .into_io(),
                        )
                    }
                }
            }
            if delay.is_zero() {
                let _ = tx.send(WatchResult {
                    err,
                    deadline: None,
                    expired: false,
                });
                return;
            }
            let deadline = Instant::now() + delay.to_std();
            let (lock, cv) = &*wshared;
            let mut done = lock.lock().unwrap_or_else(|e| e.into_inner());
            while !*done {
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                done = cv
                    .wait_timeout(done, deadline - now)
                    .unwrap_or_else(|e| e.into_inner())
                    .0;
            }
            if *done {
                let _ = tx.send(WatchResult {
                    err,
                    deadline: Some(deadline),
                    expired: false,
                });
                return;
            }
            drop(done);
            match process.kill() {
                Ok(()) => {}
                Err(e) if super::Error::ProcessDone.is(&e) => {}
                Err(e) => {
                    err = Some(
                        WrappedError {
                            prefix: "exec: killing Cmd",
                            err: e,
                        }
                        .into_io(),
                    )
                }
            }
            let _ = tx.send(WatchResult {
                err,
                deadline: None,
                expired: true,
            });
        });
        self.watch = Some(Watch {
            shared,
            stop: stop_cancel,
            result: rx,
        });
    }

    /// Waits for the command to exit and for copying to finish
    /// (`Cmd.Wait`). A non-zero exit status is an [`ExitError`].
    pub fn wait(&mut self) -> io::Result<()> {
        let Some(process) = self.process.clone() else {
            return Err(io::Error::other("exec: not started"));
        };
        if self.process_state.is_some() {
            return Err(io::Error::other("exec: Wait was already called"));
        }
        let state = process.wait();
        let mut err = match &state {
            Ok(st) if !st.success() => Some(
                ExitError {
                    process_state: *st,
                    stderr: Vec::new(),
                }
                .into(),
            ),
            Ok(_) => None,
            Err(e) => Some(clone_error(e)),
        };
        self.process_state = state.ok();

        let mut deadline = None;
        let mut expired = false;
        if let Some(w) = self.watch.take() {
            {
                let (lock, cv) = &*w.shared;
                *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
                cv.notify_all();
            }
            (w.stop)();
            if let Ok(r) = w.result.recv() {
                deadline = r.deadline;
                expired = r.expired;
                if err.is_none() {
                    err = r.err;
                }
            }
        }
        let gerr = self.await_goroutines(deadline, expired);
        if err.is_none() {
            err = gerr;
        }
        self.close_parent_io();
        match err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Go's `closeDescriptors(c.parentIOPipes)`.
    fn close_parent_io(&mut self) {
        for end in self.parent_io.drain(..) {
            let _ = end.close();
        }
    }

    fn await_goroutines(&mut self, deadline: Option<Instant>, expired: bool) -> Option<io::Error> {
        let rx = self.goroutine_rx.take()?;
        let mut remaining = self.goroutine_count;
        let mut first: Option<io::Error> = None;
        self.goroutine_count = 0;
        let limit = if expired {
            Some(Instant::now())
        } else if let Some(d) = deadline {
            Some(d)
        } else if !self.wait_delay.is_zero() {
            Some(Instant::now() + self.wait_delay.to_std())
        } else {
            None
        };
        while remaining > 0 {
            let got = match limit {
                None => rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
                Some(l) => rx.recv_timeout(l.saturating_duration_since(Instant::now())),
            };
            match got {
                Ok(r) => {
                    remaining -= 1;
                    if let Err(e) = r {
                        first.get_or_insert(e);
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    // Abandon the copiers; they end when the pipes close.
                    return Some(Sentinel::WaitDelay.into());
                }
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        first
    }

    /// Starts the command and waits for it to complete (`Cmd.Run`).
    pub fn run(&mut self) -> io::Result<()> {
        self.start()?;
        self.wait()
    }

    /// Runs the command and returns its standard output (`Cmd.Output`). If
    /// `stderr` was not set, the start and end of its output is captured in
    /// the [`ExitError`] on failure. Like Go, the output is returned together
    /// with the error.
    pub fn output(&mut self) -> (Vec<u8>, io::Result<()>) {
        if self.stdout.is_some() {
            return (
                Vec::new(),
                Err(io::Error::other("exec: Stdout already set")),
            );
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
        if let Err(err) = &result {
            if capture {
                if let Some(ee) = exit_error(err) {
                    let mut ee = ee.clone();
                    ee.stderr = saver.lock().unwrap_or_else(|e| e.into_inner()).bytes();
                    return (data, Err(ee.into()));
                }
            }
        }
        (data, result)
    }

    /// Runs the command and returns its combined standard output and
    /// standard error (`Cmd.CombinedOutput`), together with the error.
    pub fn combined_output(&mut self) -> (Vec<u8>, io::Result<()>) {
        if self.stdout.is_some() {
            return (
                Vec::new(),
                Err(io::Error::other("exec: Stdout already set")),
            );
        }
        if self.stderr.is_some() {
            return (
                Vec::new(),
                Err(io::Error::other("exec: Stderr already set")),
            );
        }
        let b = Arc::new(Mutex::new(Vec::<u8>::new()));
        self.stdout = Some(Output::writer(b.clone()));
        self.stderr = Some(Output::writer(b.clone()));
        let r = self.run();
        let data = std::mem::take(&mut *b.lock().unwrap_or_else(|e| e.into_inner()));
        (data, r)
    }

    /// A pipe connected to the command's standard input (`Cmd.StdinPipe`).
    /// `wait` closes it after the process exits; the caller must still close
    /// it for the process to see end of input.
    pub fn stdin_pipe(&mut self) -> io::Result<PipeEnd> {
        if self.stdin.is_some() {
            return Err(io::Error::other("exec: Stdin already set"));
        }
        if self.process.is_some() {
            return Err(io::Error::other("exec: StdinPipe after process started"));
        }
        let (pr, pw) = pipe()?;
        self.stdin = Some(Input::File(File::from_std(
            pr.try_clone_std()?,
            pr.name().to_string(),
            false,
        )));
        self.child_io.push(pr);
        self.pipe_ends[0] = true;
        let end = PipeEnd::new(pw);
        self.parent_io.push(end.clone());
        Ok(end)
    }

    /// A pipe connected to the command's standard output
    /// (`Cmd.StdoutPipe`). Finish reading before calling `wait`, which closes
    /// the pipe once the process has exited.
    pub fn stdout_pipe(&mut self) -> io::Result<PipeEnd> {
        if self.stdout.is_some() {
            return Err(io::Error::other("exec: Stdout already set"));
        }
        if self.process.is_some() {
            return Err(io::Error::other("exec: StdoutPipe after process started"));
        }
        let (pr, pw) = pipe()?;
        self.stdout = Some(Output::File(Arc::new(File::from_std(
            pw.try_clone_std()?,
            pw.name().to_string(),
            false,
        ))));
        self.child_io.push(pw);
        self.pipe_ends[1] = true;
        let end = PipeEnd::new(pr);
        self.parent_io.push(end.clone());
        Ok(end)
    }

    /// A pipe connected to the command's standard error (`Cmd.StderrPipe`);
    /// `wait` closes it like the standard-output pipe.
    pub fn stderr_pipe(&mut self) -> io::Result<PipeEnd> {
        if self.stderr.is_some() {
            return Err(io::Error::other("exec: Stderr already set"));
        }
        if self.process.is_some() {
            return Err(io::Error::other("exec: StderrPipe after process started"));
        }
        let (pr, pw) = pipe()?;
        self.stderr = Some(Output::File(Arc::new(File::from_std(
            pw.try_clone_std()?,
            pw.name().to_string(),
            false,
        ))));
        self.child_io.push(pw);
        self.pipe_ends[2] = true;
        let end = PipeEnd::new(pr);
        self.parent_io.push(end.clone());
        Ok(end)
    }
}

impl WrappedError {
    fn into_io(self) -> io::Error {
        io::Error::other(self)
    }
}
