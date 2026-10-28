//! Probe for the `os/exec` differential (`tools/exec_check.py`): the
//! counterpart of `tools/exec_oracle.go`.
use rust_stdlib::context::Context;
use rust_stdlib::os::{self, exec};
use std::io::{self, BufRead, Read, Write};
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

fn err_text(err: &Option<io::Error>) -> String {
    match err {
        None => "-".into(),
        Some(e) => enc(&e.to_string()),
    }
}

fn classes(err: &Option<io::Error>) -> String {
    let Some(e) = err else { return String::new() };
    let mut s = String::new();
    if exec::exit_error(e).is_some() {
        s.push('X');
    }
    if exec::error_of(e).is_some() {
        s.push('E');
    }
    if exec::ERR_NOT_FOUND.is(e) {
        s.push('N');
    }
    if exec::ERR_DOT.is(e) {
        s.push('D');
    }
    if exec::ERR_WAIT_DELAY.is(e) {
        s.push('W');
    }
    if rust_stdlib::io::fs::ERR_NOT_EXIST.is(e) {
        s.push('n');
    }
    if rust_stdlib::io::fs::ERR_PERMISSION.is(e) {
        s.push('p');
    }
    if e.kind() == io::ErrorKind::TimedOut {
        s.push('T');
    }
    s
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

fn main() {
    let out = io::stdout();
    let mut w = io::BufWriter::new(out.lock());
    for line in io::stdin().lock().lines() {
        let line = line.expect("stdin");
        let f: Vec<&str> = line.split('\t').collect();
        let mode = f[0];
        let get = |i: usize| f.get(i).map(|v| dec(v)).unwrap_or_default();
        match mode {
            "setenv" => {
                let _ = os::setenv(&get(1), &get(2));
                writeln!(w, "setenv|ok").unwrap();
                continue;
            }
            "chdir" => {
                let err = os::chdir(&get(1)).err();
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
        let timeout_ms: u64 = get(6).parse().unwrap_or(0);
        let wait_delay_ms: u64 = get(7).parse().unwrap_or(0);

        let mut cmd = if timeout_ms > 0 {
            let (c, cancel) =
                Context::background().with_timeout(Duration::from_millis(timeout_ms).into());
            std::mem::forget(cancel);
            exec::command_context(&c, &name, &args)
        } else {
            exec::command(&name, &args)
        };
        if let Some(e) = env {
            cmd.env = Some(e);
        }
        cmd.dir = dir;
        cmd.wait_delay = Duration::from_millis(wait_delay_ms).into();
        let out_b = buffer();
        let err_b = buffer();
        let mut stdout = String::new();
        let mut stderr = String::new();
        let mut err: Option<io::Error> = None;
        let mut extra = "-".to_string();
        let set_stdin = |cmd: &mut exec::Cmd| {
            if !stdin.is_empty() {
                cmd.stdin = Some(exec::Input::reader(io::Cursor::new(
                    stdin.clone().into_bytes(),
                )));
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
            "output" => {
                set_stdin(&mut cmd);
                let (o, r) = cmd.output();
                stdout = hexb(&o);
                if let Err(e) = r {
                    if let Some(ee) = exec::exit_error(&e) {
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
                    Err(_) => Err(io::Error::other("skipped")),
                };
                match (so, se) {
                    (Ok(so), Ok(se)) => match cmd.start() {
                        Ok(()) => {
                            let mut ob = Vec::new();
                            let mut eb = Vec::new();
                            let _ = (&so).read_to_end(&mut ob);
                            let _ = (&se).read_to_end(&mut eb);
                            stdout = hexb(&ob);
                            stderr = hexb(&eb);
                            err = cmd.wait().err();
                        }
                        Err(e) => err = Some(e),
                    },
                    (Err(e), _) | (_, Err(e)) => err = Some(e),
                }
            }
            "pipesafter" => {
                // Wait closes the parent's pipe ends: later I/O reports a closed file.
                let ends = cmd.stdin_pipe().and_then(|wc| {
                    let so = cmd.stdout_pipe()?;
                    let se = cmd.stderr_pipe()?;
                    Ok((wc, so, se))
                });
                match ends {
                    Ok((wc, so, se)) => match cmd.start() {
                        Ok(()) => {
                            let _ = (&wc).write_all(stdin.as_bytes());
                            let _ = wc.close();
                            let mut ob = Vec::new();
                            let mut eb = Vec::new();
                            let _ = (&so).read_to_end(&mut ob);
                            let _ = (&se).read_to_end(&mut eb);
                            stdout = hexb(&ob);
                            stderr = hexb(&eb);
                            err = cmd.wait().err();
                            let text = |r: io::Result<()>| err_text(&r.err());
                            let parts = [
                                text((&so).read(&mut [0u8; 1]).map(|_| ())),
                                text((&se).read(&mut [0u8; 1]).map(|_| ())),
                                text((&wc).write(b"x").map(|_| ())),
                                text(wc.close()),
                                text(so.close()),
                                text(se.close()),
                            ];
                            extra = enc(&parts.join(";"));
                        }
                        Err(e) => err = Some(e),
                    },
                    Err(e) => err = Some(e),
                }
            }
            "stdinpipe" => match cmd.stdin_pipe() {
                Ok(wc) => {
                    cmd.stdout = Some(exec::Output::writer(out_b.clone()));
                    match cmd.start() {
                        Ok(()) => {
                            let _ = (&wc).write_all(stdin.as_bytes());
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
                err = Some(io::Error::other(format!(
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
                    err_text(
                        &cmd.err
                            .as_ref()
                            .map(|e| io::Error::new(e.kind(), e.to_string()))
                    )
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
