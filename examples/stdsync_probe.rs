//! Line protocol used by `tools/stdsync_check.py`; mirrors
//! `tools/stdsync_oracle.go` for errors, sync, sync/atomic, hash/maphash,
//! unique and weak.
use rust_stdlib::concurrent::WaitGroup;
use rust_stdlib::error::{self, Joined, Message};
use rust_stdlib::hash::maphash;
use rust_stdlib::unique::Handle;
use std::any::{Any, TypeId};
use std::collections::{BTreeMap, HashMap};
use std::io::{self, BufRead, Write};
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{
    AtomicBool, AtomicI32, AtomicI64, AtomicPtr, AtomicU32, AtomicU64, AtomicUsize,
};
use std::sync::{Arc, Condvar, Mutex, Once, OnceLock, RwLock, Weak};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

fn b(v: bool) -> String {
    if v { "1" } else { "0" }.to_string()
}

type Cmds = Vec<Vec<String>>;

fn cmds_of(script: &str) -> Cmds {
    script
        .split(';')
        .map(|c| c.split_whitespace().map(str::to_string).collect::<Vec<_>>())
        .filter(|c| !c.is_empty())
        .collect()
}

fn message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "?".to_string()
    }
}

fn catch(f: impl FnOnce() -> String) -> String {
    match panic::catch_unwind(AssertUnwindSafe(f)) {
        Ok(s) => s,
        Err(p) => format!("panic:{}", message(p.as_ref())),
    }
}

// sync/atomic through std: Go's Add returns the new value (`fetch_add` returns
// the old one), And/Or return the old value, CompareAndSwap reports success.
macro_rules! run_atom {
    ($name:ident, $ty:ident, $int:ty) => {
        fn $name(cmds: &Cmds) -> Vec<String> {
            let a = $ty::new(0);
            let mut out = Vec::new();
            for c in cmds {
                let n = |i: usize| {
                    c[i].parse::<$int>()
                        .unwrap_or_else(|_| c[i].parse::<i128>().unwrap() as $int)
                };
                out.push(match c[0].as_str() {
                    "load" => a.load(SC).to_string(),
                    "store" => {
                        a.store(n(1), SC);
                        "-".into()
                    }
                    "swap" => a.swap(n(1), SC).to_string(),
                    "cas" => b(a.compare_exchange(n(1), n(2), SC, SC).is_ok()),
                    "add" => a.fetch_add(n(1), SC).wrapping_add(n(1)).to_string(),
                    "and" => a.fetch_and(n(1), SC).to_string(),
                    "or" => a.fetch_or(n(1), SC).to_string(),
                    _ => unreachable!(),
                });
            }
            out
        }
    };
}

const SC: std::sync::atomic::Ordering = std::sync::atomic::Ordering::SeqCst;

run_atom!(run_i32, AtomicI32, i32);
run_atom!(run_i64, AtomicI64, i64);
run_atom!(run_u32, AtomicU32, u32);
run_atom!(run_u64, AtomicU64, u64);
run_atom!(run_up, AtomicUsize, usize);

fn run_bool(cmds: &Cmds) -> Vec<String> {
    let a = AtomicBool::new(false);
    let mut out = Vec::new();
    for c in cmds {
        out.push(match c[0].as_str() {
            "load" => b(a.load(SC)),
            "store" => {
                a.store(c[1] == "1", SC);
                "-".into()
            }
            "swap" => b(a.swap(c[1] == "1", SC)),
            "cas" => b(a.compare_exchange(c[1] == "1", c[2] == "1", SC, SC).is_ok()),
            _ => unreachable!(),
        });
    }
    out
}

type Stored = Arc<dyn Any + Send + Sync>;

/// sync/atomic.Value: holds any value, but every store must have the same
/// type (Go panics otherwise). Rust types are static, so this check only
/// exists to reproduce Go's script behaviour.
#[derive(Default)]
struct AnyValue(Mutex<Option<Stored>>);

impl AnyValue {
    fn slot(&self) -> std::sync::MutexGuard<'_, Option<Stored>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn load(&self) -> Option<Stored> {
        self.slot().clone()
    }
    fn store<T: Any + Send + Sync>(&self, v: T) {
        let mut slot = self.slot();
        if slot
            .as_ref()
            .is_some_and(|c| (**c).type_id() != TypeId::of::<T>())
        {
            panic!("sync/atomic: store of inconsistently typed value into Value");
        }
        *slot = Some(Arc::new(v));
    }
    fn swap<T: Any + Send + Sync>(&self, new: T) -> Option<Stored> {
        let mut slot = self.slot();
        if slot
            .as_ref()
            .is_some_and(|c| (**c).type_id() != TypeId::of::<T>())
        {
            panic!("sync/atomic: swap of inconsistently typed value into Value");
        }
        slot.replace(Arc::new(new))
    }
    fn compare_and_swap<T: Any + Send + Sync + PartialEq>(&self, old: Option<&T>, new: T) -> bool {
        let mut slot = self.slot();
        let matches = match (slot.as_ref(), old) {
            (None, None) => true,
            (None, Some(_)) => false,
            (Some(cur), old) => match cur.downcast_ref::<T>() {
                Some(cur) => old.is_some_and(|old| cur == old),
                None => {
                    panic!("sync/atomic: compare and swap of inconsistently typed value into Value")
                }
            },
        };
        if matches {
            *slot = Some(Arc::new(new));
        }
        matches
    }
}

fn show_any(x: Option<Arc<dyn Any + Send + Sync>>) -> String {
    match x {
        None => "nil".into(),
        Some(a) => {
            if let Some(i) = a.downcast_ref::<i64>() {
                i.to_string()
            } else {
                a.downcast_ref::<String>().cloned().unwrap_or_default()
            }
        }
    }
}

fn run_value(cmds: &Cmds) -> Vec<String> {
    let v = AnyValue::default();
    let mut out = Vec::new();
    for c in cmds {
        out.push(catch(|| match c[0].as_str() {
            "load" => show_any(v.load()),
            "store" => {
                if c[1] == "i" {
                    v.store(c[2].parse::<i64>().unwrap());
                } else {
                    v.store(c[2].clone());
                }
                "-".into()
            }
            "swap" => {
                if c[1] == "i" {
                    show_any(v.swap(c[2].parse::<i64>().unwrap()))
                } else {
                    show_any(v.swap(c[2].clone()))
                }
            }
            "cas" => {
                if c[3] == "i" {
                    let old = (c[1] != "n").then(|| c[2].parse::<i64>().unwrap());
                    b(v.compare_and_swap(old.as_ref(), c[4].parse::<i64>().unwrap()))
                } else {
                    let old = (c[1] != "n").then(|| c[2].clone());
                    b(v.compare_and_swap(old.as_ref(), c[4].clone()))
                }
            }
            _ => unreachable!(),
        }));
    }
    out.into_iter()
        .map(|s| {
            s.strip_prefix("panic:")
                .map_or(s.clone(), |_| "panic".into())
        })
        .collect()
}

// atomic.Pointer[T] is `AtomicPtr<T>`; the probe compares addresses only, so the
// named targets just need to stay alive.
fn run_pointer(cmds: &Cmds) -> Vec<String> {
    let p: AtomicPtr<i32> = AtomicPtr::new(std::ptr::null_mut());
    let mut objs: Vec<(String, Arc<i32>)> = Vec::new();
    let addr = |objs: &mut Vec<(String, Arc<i32>)>, name: &str| -> *mut i32 {
        if name == "nil" {
            return std::ptr::null_mut();
        }
        if let Some((_, a)) = objs.iter().find(|(k, _)| k == name) {
            return Arc::as_ptr(a) as *mut i32;
        }
        let a = Arc::new(objs.len() as i32);
        let ptr = Arc::as_ptr(&a) as *mut i32;
        objs.push((name.to_string(), a));
        ptr
    };
    let show = |objs: &Vec<(String, Arc<i32>)>, q: *mut i32| {
        if q.is_null() {
            return "nil".to_string();
        }
        objs.iter()
            .find(|(_, a)| std::ptr::eq(Arc::as_ptr(a), q))
            .map_or("?".into(), |(k, _)| k.clone())
    };
    let mut out = Vec::new();
    for c in cmds {
        for name in &c[1..] {
            addr(&mut objs, name);
        }
        out.push(match c[0].as_str() {
            "load" => show(&objs, p.load(SC)),
            "store" => {
                p.store(addr(&mut objs, &c[1]), SC);
                "-".into()
            }
            "swap" => {
                let new = addr(&mut objs, &c[1]);
                show(&objs, p.swap(new, SC))
            }
            "cas" => {
                let (old, new) = (addr(&mut objs, &c[1]), addr(&mut objs, &c[2]));
                b(p.compare_exchange(old, new, SC, SC).is_ok())
            }
            _ => unreachable!(),
        });
    }
    out
}

// sync.Mutex/RWMutex through std: Go's Lock/Unlock become holding and dropping
// a guard.
fn run_mutex(cmds: &Cmds) -> Vec<String> {
    let m = Mutex::new(());
    let rw = RwLock::new(());
    let mut mg = None;
    let mut wg = None;
    let mut rgs = Vec::new();
    let mut out = Vec::new();
    for c in cmds {
        match c[0].as_str() {
            "lock" => {
                mg = Some(m.lock().unwrap());
                out.push("-".to_string());
            }
            "trylock" => {
                let g = m.try_lock().ok();
                out.push(b(g.is_some()));
                mg = mg.or(g);
            }
            "unlock" => {
                mg = None;
                out.push("-".into());
            }
            "rwlock" => {
                wg = Some(rw.write().unwrap());
                out.push("-".into());
            }
            "rwtrylock" => {
                let g = rw.try_write().ok();
                out.push(b(g.is_some()));
                wg = wg.or(g);
            }
            "rwunlock" => {
                wg = None;
                out.push("-".into());
            }
            "rlock" => {
                rgs.push(rw.read().unwrap());
                out.push("-".into());
            }
            "tryrlock" => {
                let g = rw.try_read().ok();
                out.push(b(g.is_some()));
                rgs.extend(g);
            }
            "runlock" => {
                rgs.pop();
                out.push("-".into());
            }
            "rlocker" => {
                // RWMutex.RLocker().Lock() is `RwLock::read`.
                let g = rw.read().unwrap();
                out.push(b(rw.try_write().is_err()));
                drop(g);
                out.push(b(rw.try_write().is_ok()));
            }
            _ => unreachable!(),
        }
    }
    out
}

fn run_wg(cmds: &Cmds) -> Vec<String> {
    let wg = WaitGroup::new();
    let mut n = 0i64;
    let mut out = Vec::new();
    for c in cmds {
        out.push(catch(|| {
            match c[0].as_str() {
                "add" => {
                    let d: i64 = c[1].parse().unwrap();
                    wg.add(d);
                    n += d;
                }
                "done" => {
                    wg.done();
                    n -= 1;
                }
                "wait" => {
                    if n == 0 {
                        wg.wait();
                    }
                }
                "go" => {
                    let (tx, rx) = std::sync::mpsc::channel::<()>();
                    wg.spawn(move || {
                        let _ = rx.recv();
                    });
                    drop(tx);
                    wg.wait();
                }
                _ => unreachable!(),
            }
            "-".to_string()
        }));
    }
    out
}

// sync.Once.Do: a panicking f still counts as done (std's `Once` would poison),
// and the panic propagates to the caller.
fn go_do(once: &Once, f: impl FnOnce()) {
    let mut panicked = None;
    once.call_once(|| panicked = panic::catch_unwind(AssertUnwindSafe(f)).err());
    if let Some(p) = panicked {
        panic::resume_unwind(p);
    }
}

fn run_once(cmds: &Cmds) -> Vec<String> {
    let once = Once::new();
    let mut count = 0;
    let mut out = Vec::new();
    for c in cmds {
        out.push(catch(|| {
            match c[0].as_str() {
                "do" => go_do(&once, || count += 1),
                "dopanic" => go_do(&once, || {
                    count += 1;
                    panic!("boom")
                }),
                "count" => return count.to_string(),
                _ => unreachable!(),
            }
            "-".to_string()
        }));
    }
    out
}

// sync.OnceValue: `OnceLock::get_or_init`, plus Go's rule that a panic is
// remembered and raised again by every later call.
fn once_value<T: Clone>(f: impl FnOnce() -> T) -> impl Fn() -> T {
    let f = std::cell::Cell::new(Some(f));
    let cell: OnceLock<Result<T, String>> = OnceLock::new();
    move || {
        let r = cell.get_or_init(|| {
            let f = f.take().unwrap();
            panic::catch_unwind(AssertUnwindSafe(f)).map_err(|p| message(p.as_ref()))
        });
        match r {
            Ok(v) => v.clone(),
            Err(m) => panic!("{m}"),
        }
    }
}

fn run_oncefuncs(cmds: &Cmds) -> Vec<String> {
    use std::sync::atomic::Ordering;
    let calls = Arc::new(AtomicUsize::new(0));
    let k = calls.clone();
    let f = once_value(move || {
        k.fetch_add(1, Ordering::SeqCst);
    });
    let k = calls.clone();
    let v = once_value(move || (k.fetch_add(1, Ordering::SeqCst) + 1) * 10);
    let k = calls.clone();
    let vs = once_value(move || (k.fetch_add(1, Ordering::SeqCst) + 1, "x".to_string()));
    let k = calls.clone();
    let pf = once_value(move || {
        k.fetch_add(1, Ordering::SeqCst);
        panic!("pf")
    });
    let k = calls.clone();
    let pv = once_value(move || -> i32 {
        k.fetch_add(1, Ordering::SeqCst);
        panic!("pv")
    });
    let mut out = Vec::new();
    for c in cmds {
        out.push(catch(|| match c[0].as_str() {
            "f" => {
                f();
                "-".into()
            }
            "v" => v().to_string(),
            "vs" => {
                let (a, s) = vs();
                format!("{a} {s}")
            }
            "pf" => {
                pf();
                "-".into()
            }
            "pv" => pv().to_string(),
            "calls" => calls.load(Ordering::SeqCst).to_string(),
            _ => unreachable!(),
        }));
    }
    out
}

// sync.Map is a `Mutex<HashMap>`; sync.Pool is a `Mutex<Vec>` plus a constructor.
fn run_map(cmds: &Cmds) -> Vec<String> {
    let m: Mutex<HashMap<String, String>> = Mutex::new(HashMap::new());
    let show = |v: Option<String>| v.unwrap_or_else(|| "none".into());
    let mut out = Vec::new();
    for c in cmds {
        let mut g = m.lock().unwrap();
        out.push(match c[0].as_str() {
            "store" => {
                g.insert(c[1].clone(), c[2].clone());
                "-".into()
            }
            "load" => show(g.get(&c[1]).cloned()),
            "loadorstore" => match g.get(&c[1]) {
                Some(v) => format!("{v} {}", b(true)),
                None => {
                    g.insert(c[1].clone(), c[2].clone());
                    format!("{} {}", c[2], b(false))
                }
            },
            "loadanddelete" => show(g.remove(&c[1])),
            "delete" => {
                g.remove(&c[1]);
                "-".into()
            }
            "swap" => show(g.insert(c[1].clone(), c[2].clone())),
            "cas" => {
                let hit = g.get(&c[1]) == Some(&c[2]);
                if hit {
                    g.insert(c[1].clone(), c[3].clone());
                }
                b(hit)
            }
            "cad" => {
                let hit = g.get(&c[1]) == Some(&c[2]);
                if hit {
                    g.remove(&c[1]);
                }
                b(hit)
            }
            "clear" => {
                g.clear();
                "-".into()
            }
            "range" => {
                let mut items: Vec<String> = g.iter().map(|(k, v)| format!("{k}={v}")).collect();
                items.sort();
                format!("[{}]", items.join(","))
            }
            // Range whose callback stops after the first entry.
            "rangestop" => g.iter().take(1).count().to_string(),
            _ => unreachable!(),
        });
    }
    out
}

fn run_pool(cmds: &Cmds) -> Vec<String> {
    let n = AtomicUsize::new(0);
    let with_new: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let plain: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let mut out = Vec::new();
    for c in cmds {
        out.push(match c[0].as_str() {
            "put" => {
                with_new.lock().unwrap().push(c[1].clone());
                plain.lock().unwrap().push(c[1].clone());
                "-".into()
            }
            "get" => {
                let item = with_new.lock().unwrap().pop();
                item.unwrap_or_else(|| format!("new{}", n.fetch_add(1, SC) + 1))
            }
            "getplain" => plain.lock().unwrap().pop().unwrap_or_else(|| "nil".into()),
            _ => unreachable!(),
        });
    }
    out
}

// sync.Cond is `Condvar` paired with a `Mutex`; Signal and Broadcast are
// `notify_one` and `notify_all`.
fn run_cond() -> Vec<String> {
    let c = Condvar::new();
    c.notify_one();
    c.notify_all();
    vec![b(true)]
}

#[derive(Debug)]
struct W {
    msg: String,
    err: Option<BoxError>,
}

impl std::fmt::Display for W {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "w({})", self.msg)
    }
}

impl std::error::Error for W {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.err
            .as_deref()
            .map(|e| e as &(dyn std::error::Error + 'static))
    }
}

struct Parser {
    s: Vec<u8>,
    i: usize,
    leaves: BTreeMap<usize, Message>,
}

impl Parser {
    fn expr(&mut self) -> Option<BoxError> {
        match self.s[self.i] {
            b'N' => {
                self.i += 1;
                None
            }
            b'L' => {
                self.i += 1;
                let j = self.i;
                while self.i < self.s.len() && self.s[self.i].is_ascii_digit() {
                    self.i += 1;
                }
                let k: usize = std::str::from_utf8(&self.s[j..self.i])
                    .unwrap()
                    .parse()
                    .unwrap();
                let e = self
                    .leaves
                    .entry(k)
                    .or_insert_with(|| Message::new(&format!("e{k}")))
                    .clone();
                Some(Box::new(e))
            }
            b'W' => {
                self.i += 2;
                let e = self.expr();
                self.i += 1;
                let msg = e.as_ref().map_or("<nil>".to_string(), |e| e.to_string());
                Some(Box::new(W { msg, err: e }))
            }
            _ => {
                self.i += 2;
                let mut errs = Vec::new();
                loop {
                    errs.extend(self.expr());
                    if self.s[self.i] == b',' {
                        self.i += 1;
                        continue;
                    }
                    self.i += 1;
                    return Joined::new(errs).map(|j| Box::new(j) as BoxError);
                }
            }
        }
    }
}

fn run_errors(script: &str) -> Vec<String> {
    let mut p = Parser {
        s: script.as_bytes().to_vec(),
        i: 0,
        leaves: BTreeMap::new(),
    };
    let root = p.expr();
    let r: Option<&(dyn std::error::Error + 'static)> = root.as_deref().map(|e| e as _);
    // Go's `errors.Is` also accepts nil on either side.
    let is = |err: Option<&(dyn std::error::Error + 'static)>,
              target: Option<&(dyn std::error::Error + 'static)>| match (err, target) {
        (None, None) => true,
        (Some(e), Some(t)) => error::is(e, t),
        _ => false,
    };
    let pipe = |s: String| s.replace('\n', "|");
    let mut out = vec![root.as_ref().map_or("nil".into(), |e| pipe(e.to_string()))];
    for leaf in p.leaves.values() {
        out.push(b(is(r, Some(leaf))));
    }
    let other = Message::new("other");
    out.push(b(is(r, Some(&other))));
    out.push(b(is(r, None)));
    out.push(b(is(None, None)));
    // errors.As and errors.AsType are the same search over the tree.
    let found = r.and_then(error::find::<W>);
    out.push(match found {
        Some(w) => pipe(w.to_string()),
        None => "noas".into(),
    });
    out.push(match found {
        Some(w) => pipe(w.to_string()),
        None => "noastype".into(),
    });
    // errors.Unwrap is `Error::source`.
    out.push(match r.and_then(|e| e.source()) {
        Some(u) => pipe(u.to_string()),
        None => "nounwrap".into(),
    });
    let unsupported = Message::unsupported();
    out.push(b(error::is(&unsupported, &Message::unsupported())));
    out.push(unsupported.to_string());
    out
}

fn run_maphash(script: &str) -> Vec<String> {
    let (hex, chunks) = script.split_once(':').unwrap();
    let data: Vec<u8> = (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
        .collect();
    let chunks: Vec<usize> = chunks
        .split_whitespace()
        .map(|c| c.parse().unwrap())
        .collect();
    let seed = maphash::make_seed();
    let seed2 = maphash::make_seed();
    let mut out = Vec::new();
    let mut h = maphash::Hash::new();
    h.set_seed(seed);
    h.write_all(&data).unwrap();
    let one_shot = h.sum64();
    out.push(b(one_shot == maphash::bytes(seed, &data)));
    out.push(b(maphash::string(seed, &String::from_utf8_lossy(&data))
        == maphash::bytes(seed, &data)
        || std::str::from_utf8(&data).is_err()));
    let mut h2 = maphash::Hash::new();
    h2.set_seed(seed);
    let mut rest: &[u8] = &data;
    for (i, &n) in chunks.iter().enumerate() {
        let n = n.min(rest.len());
        let (piece, tail) = rest.split_at(n);
        rest = tail;
        match i % 3 {
            0 => h2.write_all(piece).unwrap(),
            1 => {
                h2.write_all(piece).unwrap();
            }
            _ => {
                for &c in piece {
                    h2.write_byte(c).unwrap();
                }
            }
        }
    }
    h2.write_all(rest).unwrap();
    out.push(b(h2.sum64() == one_shot));
    h2.reset();
    h2.write_all(&data).unwrap();
    out.push(b(h2.sum64() == one_shot));
    out.push(b(h.seed() == seed));
    let sum = h.sum(b"pre".to_vec());
    let le = u64::from_le_bytes(sum[3..].try_into().unwrap());
    out.push(b(sum.len() == 11 && &sum[..3] == b"pre" && le == one_shot));
    out.push(b(h.size() == 8 && h.block_size() == 128));
    out.push(b(
        maphash::bytes(seed2, &data) != maphash::bytes(seed, &data)
    ));
    let mut longer = data.clone();
    longer.push(0);
    out.push(b(maphash::bytes(seed, &longer) != one_shot));
    let mut c = h.clone();
    out.push(b(c.sum64() == one_shot));
    c.write_string("more");
    out.push(b(c.sum64() != one_shot && h.sum64() == one_shot));
    let n = data.len();
    let mut h3 = maphash::Hash::new();
    h3.set_seed(seed);
    maphash::write_comparable(&mut h3, &n);
    out.push(b(maphash::comparable(seed, &n) == h3.sum64()
        && maphash::comparable(seed, &n)
            == maphash::comparable(seed, &data.len())));
    let s = String::from_utf8_lossy(&data).into_owned();
    out.push(b(
        maphash::comparable(seed, &s) == maphash::comparable(seed, &s.clone())
    ));
    out.push(catch(|| {
        let mut z = maphash::Hash::new();
        z.set_seed(maphash::Seed::default());
        "no".into()
    }));
    use maphash::Hasher as _;
    let hasher = maphash::ComparableHasher::<String>::new();
    let mut h4 = maphash::Hash::new();
    h4.set_seed(seed);
    hasher.hash(&mut h4, &s);
    let mut h5 = maphash::Hash::new();
    h5.set_seed(seed);
    hasher.hash(&mut h5, &s.clone());
    out.push(b(h4.sum64() == h5.sum64()
        && hasher.equal(&s, &s.clone())
        && !hasher.equal(&s, &format!("{s}x"))));
    out
}

fn run_unique(cmds: &Cmds) -> Vec<String> {
    let mut hs = Vec::new();
    let mut is = Vec::new();
    for c in cmds {
        match c[0].as_str() {
            "s" => hs.push(Handle::new(c[1].clone())),
            "i" => is.push(Handle::new(c[1].parse::<i64>().unwrap())),
            _ => unreachable!(),
        }
    }
    let mut out = Vec::new();
    for a in &hs {
        out.push(a.value().clone());
        for c in &hs {
            out.push(b(a == c));
        }
    }
    for a in &is {
        out.push(a.value().to_string());
        for c in &is {
            out.push(b(a == c));
        }
    }
    out
}

// weak.Pointer is `std::sync::Weak`: `Arc::downgrade` makes one, `upgrade`
// reads it, and `ptr_eq` compares them (even once the value is gone).
fn run_weak() -> Vec<String> {
    let x = Arc::new(1);
    let y = Arc::new(2);
    let (w1, w2, w3) = (Arc::downgrade(&x), Arc::downgrade(&x), Arc::downgrade(&y));
    let nilw: Weak<i32> = Weak::new();
    vec![
        b(w1.ptr_eq(&w2)),
        b(w1.ptr_eq(&w3)),
        b(Arc::ptr_eq(&w1.upgrade().unwrap(), &x)),
        b(Arc::ptr_eq(&w3.upgrade().unwrap(), &y)),
        b(nilw.upgrade().is_none()),
        b(Weak::<i32>::new().ptr_eq(&nilw)),
    ]
}

fn answer(line: &str) -> String {
    let (domain, script) = line.split_once(' ').unwrap_or((line, ""));
    let cmds = cmds_of(script);
    let out = match domain {
        "i32" => run_i32(&cmds),
        "i64" => run_i64(&cmds),
        "u32" => run_u32(&cmds),
        "u64" => run_u64(&cmds),
        "up" => run_up(&cmds),
        "bool" => run_bool(&cmds),
        // The AddInt32-style functions are the same std atomics.
        "f32" => run_i32(&cmds),
        "f64" => run_u64(&cmds),
        "value" => run_value(&cmds),
        "pointer" => run_pointer(&cmds),
        "mutex" => run_mutex(&cmds),
        "wg" => run_wg(&cmds),
        "once" => run_once(&cmds),
        "oncefunc" => run_oncefuncs(&cmds),
        "map" => run_map(&cmds),
        "pool" => run_pool(&cmds),
        "cond" => run_cond(),
        "errors" => run_errors(script),
        "maphash" => run_maphash(script),
        "unique" => run_unique(&cmds),
        "weak" => run_weak(),
        _ => return format!("unknown domain {domain}"),
    };
    out.join(" ")
}

fn main() -> io::Result<()> {
    panic::set_hook(Box::new(|_| {}));
    let stdin = io::stdin();
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line?;
        let reply = panic::catch_unwind(|| answer(&line))
            .unwrap_or_else(|p| format!("probe-panic:{} in {line}", message(p.as_ref())));
        writeln!(out, "{reply}")?;
    }
    Ok(())
}
