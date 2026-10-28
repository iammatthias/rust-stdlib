//! Rust side of the exec differential for rust_stdlib_sys::os::exec
//! (tools/exec_check.py): the counterpart of tools/exec_oracle.go, plus the
//! modes that need the system layer: ExtraFiles, StartProcess with arbitrary
//! descriptors, process handles and WaitDelay.

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
    use rust_stdlib_sys::errno::{self, Errno};
    use rust_stdlib_sys::os::exec::{self, CmdError};
    use rust_stdlib_sys::os::{self, ProcAttr, ProcessError, SignalError};
    use std::io::{self, BufRead, Write};
    use std::os::fd::AsRawFd;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

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

    fn err_text(err: &Option<CmdError>) -> String {
        match err {
            None => "-".into(),
            Some(e) => enc(&e.to_string()),
        }
    }

    fn classes(err: &Option<CmdError>) -> String {
        let Some(e) = err else { return String::new() };
        let mut s = String::new();
        if e.exit_error().is_some() {
            s.push('X');
        }
        if e.is_lookup_error() {
            s.push('E');
        }
        if e.is_not_found() {
            s.push('N');
        }
        if e.is_dot() {
            s.push('D');
        }
        if e.is_wait_delay() {
            s.push('W');
        }
        if e.is_not_exist() {
            s.push('n');
        }
        if e.is_permission() {
            s.push('p');
        }
        s
    }

    /// A Process error with how Go's errors.Is classifies it: D for
    /// os.ErrProcessDone, I for syscall.EINVAL, C for syscall.ECHILD.
    fn perr(text: String, done: bool, errno: Option<Errno>) -> String {
        let mut flags = String::new();
        if done {
            flags.push('D');
        }
        if errno == Some(errno::EINVAL) {
            flags.push('I');
        }
        if errno == Some(errno::ECHILD) {
            flags.push('C');
        }
        enc(&format!("{text}/{flags}"))
    }

    fn wait_err(r: Result<os::ProcessState, ProcessError>) -> String {
        match r {
            Ok(_) => "-".into(),
            Err(e) => perr(e.to_string(), e == ProcessError::ProcessDone, e.errno()),
        }
    }

    fn signal_err(r: Result<(), SignalError>) -> String {
        match r {
            Ok(()) => "-".into(),
            Err(e) => {
                let errno = match e {
                    SignalError::Errno(n) => Some(n),
                    _ => None,
                };
                perr(e.to_string(), e == SignalError::ProcessDone, errno)
            }
        }
    }

    fn with_handle(p: &os::Process) -> String {
        match p.with_handle(|_| {}) {
            Ok(()) => "ok".to_string(),
            Err(e) => e.to_string(),
        }
    }

    fn start_quiet(name: &str, args: &[&str]) -> os::Process {
        let argv: Vec<String> = std::iter::once(name)
            .chain(args.iter().copied())
            .map(str::to_string)
            .collect();
        let attr = ProcAttr {
            dir: String::new(),
            env: Some(vec!["PATH=/usr/bin:/bin".into()]),
            files: vec![None, None, None],
        };
        os::start_process(name, &argv, &attr).unwrap()
    }

    fn state(c: &exec::Cmd) -> String {
        match &c.process_state {
            None => "-".into(),
            Some(s) => format!(
                "{};{};{};{}",
                enc(&s.to_string()),
                s.exit_code(),
                s.success(),
                s.exited()
            ),
        }
    }

    fn buffer() -> Arc<Mutex<Vec<u8>>> {
        Arc::new(Mutex::new(Vec::new()))
    }

    fn take(b: &Arc<Mutex<Vec<u8>>>) -> String {
        hexb(&b.lock().unwrap())
    }

    fn read_all(f: &os::File) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        while let Ok(n) = f.read(&mut buf) {
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        out
    }

    /// Opens the comma separated names read-only.
    fn open_all(list: &str) -> Vec<std::fs::File> {
        list.split(',')
            .filter(|n| !n.is_empty())
            .map(|n| std::fs::File::open(n).expect("open extra file"))
            .collect()
    }

    /// `os.StartProcess` with stdin from /dev/null, stdout and stderr into one
    /// pipe, `files` (a name, or "-" for nil) at descriptors 3, 4, ...
    fn procattr(name: &str, args: &[&str], dir: &str, files: &str) -> (String, String) {
        let null = std::fs::File::open("/dev/null").unwrap();
        let (pr, pw) = os::pipe().unwrap();
        let opened: Vec<Option<std::fs::File>> = files
            .split(',')
            .filter(|n| !n.is_empty())
            .map(|n| (n != "-").then(|| std::fs::File::open(n).unwrap()))
            .collect();
        let mut fds = vec![
            Some(null.as_raw_fd()),
            Some(pw.as_raw_fd()),
            Some(pw.as_raw_fd()),
        ];
        fds.extend(opened.iter().map(|f| f.as_ref().map(|f| f.as_raw_fd())));
        let attr = ProcAttr {
            dir: dir.to_string(),
            env: Some(vec!["PATH=/usr/bin:/bin".into()]),
            files: fds,
        };
        let argv: Vec<String> = std::iter::once(name)
            .chain(args.iter().copied())
            .map(str::to_string)
            .collect();
        match os::start_process(name, &argv, &attr) {
            Err(e) => {
                let _ = pw.close();
                (String::new(), enc(&e.to_string()))
            }
            Ok(p) => {
                let _ = pw.close();
                let data = read_all(&pr);
                let st = p.wait();
                let text = match st {
                    Ok(s) => s.to_string(),
                    Err(e) => e.to_string(),
                };
                (hexb(&data), enc(&text))
            }
        }
    }

    pub fn main() {
        let out = io::stdout();
        let mut w = io::BufWriter::new(out.lock());
        for line in io::stdin().lock().lines() {
            let line = line.expect("stdin");
            let f: Vec<&str> = line.split('\t').collect();
            let mode = f[0];
            let get = |i: usize| f.get(i).map(|v| dec(v)).unwrap_or_default();
            match mode {
                "setenv" => {
                    std::env::set_var(get(1), get(2));
                    writeln!(w, "setenv|ok").unwrap();
                    continue;
                }
                "chdir" => {
                    let d = get(1);
                    let err = std::env::set_current_dir(&d).err().map(|e| {
                        CmdError::Io(
                            format!("chdir {d}: {}", Errno(e.raw_os_error().unwrap_or(0))),
                            None,
                        )
                    });
                    writeln!(w, "chdir|{}", err_text(&err)).unwrap();
                    continue;
                }
                "lookpath" => {
                    let (p, err) = exec::look_path_dot(&get(1));
                    writeln!(
                        w,
                        "lookpath|{}|{}|{}",
                        enc(&p),
                        err_text(&err),
                        classes(&err)
                    )
                    .unwrap();
                    continue;
                }
                _ => {}
            }
            let name = get(1);
            let args_s = get(2);
            let args: Vec<&str> = if args_s.is_empty() {
                Vec::new()
            } else {
                args_s.split('\x1f').collect()
            };
            let env_set = f[3] != "NIL";
            let env: Option<Vec<String>> = if env_set {
                let e = get(3);
                Some(if e.is_empty() {
                    Vec::new()
                } else {
                    e.split('\x1f').map(str::to_string).collect()
                })
            } else {
                None
            };
            let dir = get(4);
            let stdin = get(5);
            let wait_delay_ms: u64 = get(7).parse().unwrap_or(0);

            if mode == "procattr" {
                let (data, status) = procattr(&name, &args, &dir, &stdin);
                writeln!(w, "procattr|{data}|{status}").unwrap();
                continue;
            }
            if mode == "handle" {
                let mut p = start_quiet(&name, &args);
                let mut seen = false;
                let before = match p.with_handle(|h| seen = h >= 0) {
                    Ok(()) => format!("ok:{seen}"),
                    Err(e) => e.to_string(),
                };
                let _ = p.wait();
                let after = with_handle(&p);
                let werr = wait_err(p.wait());
                let sig = signal_err(p.signal(errno::SIGKILL));
                p.release();
                let sig2 = signal_err(p.signal(errno::SIGKILL));
                writeln!(
                    w,
                    "handle|{}|{}|{werr}|{sig}|{sig2}|{}",
                    enc(&before),
                    enc(&after),
                    enc(&with_handle(&p))
                )
                .unwrap();
                continue;
            }
            if mode == "released" {
                let mut p = start_quiet(&name, &args);
                p.release();
                writeln!(
                    w,
                    "released|{}|{}|{}|{}",
                    enc(&with_handle(&p)),
                    wait_err(p.wait()),
                    signal_err(p.signal(errno::SIGKILL)),
                    signal_err(p.kill())
                )
                .unwrap();
                continue;
            }

            let mut cmd = exec::command(&name, &args);
            if let Some(e) = env {
                cmd.env = Some(e);
            }
            cmd.dir = dir;
            cmd.wait_delay = Duration::from_millis(wait_delay_ms);
            let out_b = buffer();
            let err_b = buffer();
            let mut stdout = String::new();
            let mut stderr = String::new();
            let mut err: Option<CmdError> = None;
            let mut extra = "-".to_string();
            let set_stdin = |cmd: &mut exec::Cmd| {
                if !stdin.is_empty() {
                    cmd.stdin = Some(exec::Input::Reader(Box::new(io::Cursor::new(
                        stdin.clone().into_bytes(),
                    ))));
                }
            };
            match mode {
                "run" => {
                    set_stdin(&mut cmd);
                    cmd.stdout = Some(exec::Output::writer(out_b.clone()));
                    cmd.stderr = Some(exec::Output::writer(err_b.clone()));
                    err = cmd.run().err();
                    stdout = take(&out_b);
                    stderr = take(&err_b);
                }
                "extra" => {
                    cmd.extra_files = open_all(&stdin);
                    cmd.stdout = Some(exec::Output::writer(out_b.clone()));
                    cmd.stderr = Some(exec::Output::writer(err_b.clone()));
                    err = cmd.run().err();
                    stdout = take(&out_b);
                    stderr = take(&err_b);
                }
                "output" => {
                    set_stdin(&mut cmd);
                    let (o, r) = cmd.output();
                    stdout = hexb(&o);
                    if let Err(e) = r {
                        if let Some(ee) = e.exit_error() {
                            extra = hexb(&ee.stderr);
                        }
                        err = Some(e);
                    }
                }
                "combined" => {
                    set_stdin(&mut cmd);
                    let (o, r) = cmd.combined_output();
                    stdout = hexb(&o);
                    err = r.err();
                }
                "same" => {
                    cmd.stdout = Some(exec::Output::writer(out_b.clone()));
                    cmd.stderr = Some(exec::Output::writer(out_b.clone()));
                    err = cmd.run().err();
                    stdout = take(&out_b);
                }
                "pipes" => {
                    let so = cmd.stdout_pipe();
                    let se = match &so {
                        Ok(_) => cmd.stderr_pipe(),
                        Err(_) => Err(CmdError::Msg("skipped".into())),
                    };
                    match (so, se) {
                        (Ok(so), Ok(se)) => match cmd.start() {
                            Ok(()) => {
                                stdout = hexb(&read_all(&so));
                                stderr = hexb(&read_all(&se));
                                err = cmd.wait().err();
                            }
                            Err(e) => err = Some(e),
                        },
                        (Err(e), _) | (_, Err(e)) => err = Some(e),
                    }
                }
                "stdinpipe" => match cmd.stdin_pipe() {
                    Ok(wc) => {
                        cmd.stdout = Some(exec::Output::writer(out_b.clone()));
                        match cmd.start() {
                            Ok(()) => {
                                let _ = wc.write(stdin.as_bytes());
                                let _ = wc.close();
                                err = cmd.wait().err();
                            }
                            Err(e) => err = Some(e),
                        }
                        stdout = take(&out_b);
                    }
                    Err(e) => err = Some(e),
                },
                "environ" => {
                    let mut keep: Vec<String> = cmd
                        .environ()
                        .into_iter()
                        .filter(|kv| kv.starts_with("RS_") || kv.starts_with("PWD="))
                        .collect();
                    keep.sort();
                    stdout = enc(&keep.join("\n"));
                }
                "twice" => {
                    cmd.stdout = Some(exec::Output::writer(out_b.clone()));
                    let e1 = cmd.start().err();
                    let e2 = cmd.start().err();
                    let e3 = cmd.wait().err();
                    let e4 = cmd.wait().err();
                    err = Some(CmdError::Msg(format!(
                        "{}|{}|{}|{}",
                        err_text(&e1),
                        err_text(&e2),
                        err_text(&e3),
                        err_text(&e4)
                    )));
                    stdout = take(&out_b);
                }
                "waitfirst" => err = cmd.wait().err(),
                "string" => stdout = enc(&cmd.to_string()),
                "pathargs" => {
                    stdout = enc(&format!(
                        "{}|{}|{}",
                        cmd.path,
                        cmd.args.join(" "),
                        err_text(&cmd.err)
                    ))
                }
                other => panic!("unknown mode {other}"),
            }
            writeln!(
                w,
                "{mode}|{stdout}|{stderr}|{}|{}|{}|{}|{extra}|",
                err_text(&err),
                classes(&err),
                state(&cmd),
                enc(&cmd.to_string())
            )
            .unwrap();
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
