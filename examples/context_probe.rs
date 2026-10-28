//! Script interpreter used by `tools/context_check.py` for Go differential
//! checks. Mirrors `tools/context_oracle.go`: one script per input line, one
//! trace per output line.
use rust_stdlib::context::{CancelCauseFunc, CancelFunc, Context, Error, Key, StopFunc};
use std::{
    io::{self, BufRead, Write},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

struct Node {
    ctx: Context,
    cancel: Option<CancelFunc>,
    cause: Option<CancelCauseFunc>,
}

#[derive(Debug)]
struct Named(String);
impl std::fmt::Display for Named {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Named {}

/// Strip `.WithDeadline(<time> [<duration>])` payloads, which are wall-clock
/// dependent.
fn normalize(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find(".WithDeadline(") {
        out.push_str(&rest[..at]);
        out.push_str(".WithDeadline(*)");
        let tail = &rest[at..];
        match tail.find("])") {
            Some(end) => rest = &tail[end + 2..],
            None => return out,
        }
    }
    out.push_str(rest);
    out
}

fn err_name(err: Option<Error>) -> &'static str {
    match err {
        None => "nil",
        Some(Error::Canceled) => "canceled",
        Some(Error::DeadlineExceeded) => "deadline",
    }
}

fn deadline_at(ms: i64) -> Instant {
    let now = Instant::now();
    if ms >= 0 {
        now + Duration::from_millis(ms as u64)
    } else {
        now - Duration::from_millis(ms.unsigned_abs())
    }
}

fn run(script: &str) -> String {
    let toks: Vec<&str> = script.split_whitespace().collect();
    let keys = [
        Key::<String>::named("k0"),
        Key::<String>::named("k1"),
        Key::<String>::named("k2"),
    ];
    let mut nodes = vec![Node {
        ctx: Context::background(),
        cancel: None,
        cause: None,
    }];
    let mut stops: Vec<StopFunc> = Vec::new();
    let fired = Arc::new(Mutex::new(Vec::<usize>::new()));
    let mut log: Vec<String> = Vec::new();
    let num = |i: usize| -> i64 { toks[i].parse().expect("number") };
    let snap = |nodes: &[Node], log: &mut Vec<String>, final_snap: bool| {
        let mut parts = Vec::new();
        for (i, n) in nodes.iter().enumerate() {
            let values: Vec<String> = keys
                .iter()
                .map(|k| n.ctx.value(k).map_or("-".to_string(), |v| (*v).clone()))
                .collect();
            parts.push(format!(
                "{i}:E{}/C{}/D{}/N{}/V{}/S{}",
                err_name(n.ctx.err()),
                n.ctx.cause().map_or("nil".to_string(), |c| c.to_string()),
                u8::from(n.ctx.deadline().is_some()),
                u8::from(n.ctx.done().is_never()),
                values.join(","),
                normalize(&n.ctx.to_string()),
            ));
        }
        if final_snap {
            let mut ids = fired.lock().unwrap().clone();
            ids.sort_unstable();
            let ids: Vec<String> = ids.iter().map(usize::to_string).collect();
            parts.push(format!("fired[{}]", ids.join(" ")));
        }
        log.push(parts.join(" "));
    };
    let mut i = 0;
    while i < toks.len() {
        match toks[i] {
            "cancel" => {
                let (ctx, cancel) = (nodes[num(i + 1) as usize].ctx).with_cancel();
                nodes.push(Node {
                    ctx,
                    cancel: Some(cancel),
                    cause: None,
                });
                i += 2;
            }
            "cause" => {
                let (ctx, f) = (nodes[num(i + 1) as usize].ctx).with_cancel_cause();
                nodes.push(Node {
                    ctx,
                    cancel: None,
                    cause: Some(f),
                });
                i += 2;
            }
            "dl" | "dlc" | "dd" | "ddc" => {
                let parent = nodes[num(i + 1) as usize].ctx.clone();
                let ms = num(i + 2);
                let why: Arc<dyn std::error::Error + Send + Sync> =
                    Arc::new(Named(format!("dlcause{}", nodes.len())));
                let (ctx, cancel) = match toks[i] {
                    "dl" => parent.with_timeout((Duration::from_millis(ms as u64)).into()),
                    "dlc" => parent
                        .with_timeout_cause((Duration::from_millis(ms as u64)).into(), Some(why)),
                    "dd" => parent.with_deadline(deadline_at(ms)),
                    _ => parent.with_deadline_cause(deadline_at(ms), Some(why)),
                };
                if let Some(pd) = parent.deadline() {
                    log.push(format!(
                        "inherit{}={}",
                        nodes.len(),
                        ctx.deadline() == Some(pd)
                    ));
                }
                nodes.push(Node {
                    ctx,
                    cancel: Some(cancel),
                    cause: None,
                });
                i += 3;
            }
            "val" => {
                let key = &keys[num(i + 2) as usize];
                let ctx = (nodes[num(i + 1) as usize].ctx).with_value(key, toks[i + 3].to_string());
                nodes.push(Node {
                    ctx,
                    cancel: None,
                    cause: None,
                });
                i += 4;
            }
            "woc" => {
                let ctx = (nodes[num(i + 1) as usize].ctx).without_cancel();
                nodes.push(Node {
                    ctx,
                    cancel: None,
                    cause: None,
                });
                i += 2;
            }
            "af" => {
                let id = stops.len();
                let fired = fired.clone();
                stops.push(
                    (nodes[num(i + 1) as usize].ctx)
                        .after_func(move || fired.lock().unwrap().push(id)),
                );
                i += 2;
            }
            "x" => {
                let n = &nodes[num(i + 1) as usize];
                if let Some(cancel) = &n.cancel {
                    cancel();
                } else if let Some(f) = &n.cause {
                    f(None);
                }
                i += 2;
            }
            "xc" => {
                let n = &nodes[num(i + 1) as usize];
                if let Some(f) = &n.cause {
                    f(Some(Arc::new(Named(toks[i + 2].to_string()))));
                } else if let Some(cancel) = &n.cancel {
                    cancel();
                }
                i += 3;
            }
            "stop" => {
                let id = num(i + 1) as usize;
                log.push(format!("stop{id}={}", stops[id]()));
                i += 2;
            }
            "sleep" => {
                thread::sleep(Duration::from_millis(num(i + 1) as u64));
                i += 2;
            }
            "snap" => {
                snap(&nodes, &mut log, false);
                i += 1;
            }
            other => panic!("bad op {other}"),
        }
    }
    thread::sleep(Duration::from_millis(60));
    snap(&nodes, &mut log, true);
    log.join(" | ")
}

fn main() {
    let scripts: Vec<String> = io::stdin().lock().lines().map(|l| l.unwrap()).collect();
    let scripts = Arc::new(scripts);
    let results = Arc::new(Mutex::new(vec![String::new(); scripts.len()]));
    let next = Arc::new(Mutex::new(0usize));
    let workers: Vec<_> = (0..256)
        .map(|_| {
            let (scripts, results, next) = (scripts.clone(), results.clone(), next.clone());
            thread::spawn(move || loop {
                let i = {
                    let mut n = next.lock().unwrap();
                    let i = *n;
                    *n += 1;
                    i
                };
                if i >= scripts.len() {
                    return;
                }
                let line = run(&scripts[i]);
                results.lock().unwrap()[i] = line;
            })
        })
        .collect();
    for w in workers {
        w.join().unwrap();
    }
    let mut out = io::stdout().lock();
    for r in results.lock().unwrap().iter() {
        writeln!(out, "{r}").unwrap();
    }
}
