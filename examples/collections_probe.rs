//! Line protocol used by `tools/collections_check.py` for Go differential checks.
use rust_stdlib::collections::{compact_by, heap::Heap, list, ring};
use rust_stdlib::math;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::io::{self, BufRead};

type Rec = (isize, usize);

fn ints(f: &[&str]) -> Vec<isize> {
    f.iter().map(|s| s.parse().expect("int")).collect()
}

fn floats(f: &[&str]) -> Vec<f64> {
    f.iter()
        .map(|s| f64::from_bits(u64::from_str_radix(s, 16).expect("hex")))
        .collect()
}

fn join<T: ToString>(v: &[T]) -> String {
    v.iter()
        .map(|x| x.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn b2s(b: bool) -> &'static str {
    if b {
        "1"
    } else {
        "0"
    }
}

/// Go's `cmp.Compare` as an `i32`.
fn sign(o: Ordering) -> i32 {
    o as i32
}

fn do_sort(f: &[&str]) -> String {
    let algo = f[0];
    let mut keys = ints(&f[1..]);
    let mut rs: Vec<Rec> = keys.iter().enumerate().map(|(i, &k)| (k, i)).collect();
    let pre = format!(
        "{}{}{}{}{}",
        b2s(rs.is_sorted_by(|a, b| a.0 <= b.0)),
        b2s(rs.is_sorted_by_key(|r| r.0)),
        b2s(rs.is_sorted_by(|a, b| a.0.cmp(&b.0).is_le())),
        b2s(keys.is_sorted()),
        b2s(keys.is_sorted())
    );
    let mut stable = false;
    match algo {
        "sort" | "slice" | "sortfunc" => rs.sort_unstable_by_key(|r| r.0),
        "rsort" => rs.sort_unstable_by_key(|a| std::cmp::Reverse(a.0)),
        "stable" | "slicestable" | "sortstablefunc" => {
            rs.sort_by_key(|r| r.0);
            stable = true
        }
        "rstable" => {
            rs.sort_by_key(|a| std::cmp::Reverse(a.0));
            stable = true
        }
        "sorted" => {
            let mut v: Vec<isize> = keys.to_vec();
            v.sort_unstable();
            return format!("{} {}", pre, join(&v));
        }
        "ints" | "intslice" => {
            keys.sort_unstable();
            return format!("{} {}", pre, join(&keys));
        }
        "strings" => {
            let mut ss: Vec<String> = keys.iter().map(|k| k.to_string()).collect();
            ss.sort_unstable();
            let mut a = ss.to_vec();
            a.sort();
            return format!(
                "{} {} {}{}",
                pre,
                join(&ss),
                b2s(ss.is_sorted()),
                b2s(a == ss)
            );
        }
        _ => panic!("bad sort algo"),
    }
    if stable {
        let ids: Vec<usize> = rs.iter().map(|r| r.1).collect();
        return format!("{} {}", pre, join(&ids));
    }
    let ks: Vec<isize> = rs.iter().map(|r| r.0).collect();
    let mut by_id = vec![0; rs.len()];
    for r in &rs {
        by_id[r.1] = r.0;
    }
    format!("{} {} {}", pre, join(&ks), join(&by_id))
}

fn fnorm(f: f64) -> String {
    if f.is_nan() {
        "n".into()
    } else if f == 0.0 {
        "0".into()
    } else {
        format!("{:x}", f.to_bits())
    }
}

fn do_fsort(f: &[&str]) -> String {
    let fs = floats(f);
    let sorted = |v: &[f64]| v.is_sorted_by(|a, b| math::compare(a, b).is_le());
    let pre = format!("{}{}", b2s(sorted(&fs)), b2s(sorted(&fs)));
    let mut a = fs.clone();
    a.sort_unstable_by(math::compare);
    let mut b = fs.clone();
    b.sort_unstable_by(math::compare);
    let mut c = fs.clone();
    c.sort_by(math::compare);
    let mut d = fs.clone();
    d.sort_by(math::compare);
    let norm = |v: &[f64]| v.iter().map(|x| fnorm(*x)).collect::<Vec<_>>().join(",");
    let mut raw: Vec<u64> = a.iter().map(|x| x.to_bits()).collect();
    raw.sort_unstable();
    let rp: Vec<String> = raw.iter().map(|x| format!("{x:x}")).collect();
    format!(
        "{} {} {} {} {} {}",
        pre,
        norm(&a),
        norm(&b),
        norm(&c),
        norm(&d),
        rp.join(",")
    )
}

/// Go's `slices.BinarySearch` for floats: leftmost position and whether found.
fn bsearch(a: &[f64], t: f64) -> (usize, bool) {
    let i = a.partition_point(|e| math::compare(e, &t).is_lt());
    (i, i < a.len() && math::compare(&a[i], &t).is_eq())
}

/// sort.SearchFloat64s: plain `>=`, so NaN never matches.
fn search_float64s(a: &[f64], t: f64) -> usize {
    a.partition_point(|e| !matches!(e.partial_cmp(&t), Some(Ordering::Greater | Ordering::Equal)))
}

fn do_fsearch(f: &[&str]) -> String {
    let fs = floats(f);
    let (t, a) = (fs[0], &fs[1..]);
    let (i, found) = bsearch(a, t);
    let (j, found2) = bsearch(a, t);
    format!(
        "{},{} {} {},{} {}",
        i,
        b2s(found),
        search_float64s(a, t),
        j,
        b2s(found2),
        search_float64s(a, t)
    )
}

fn do_isearch(f: &[&str]) -> String {
    let v = ints(f);
    let (t, a) = (v[0], &v[1..]);
    let i = a.partition_point(|e| *e < t);
    let found = i < a.len() && a[i] == t;
    // sort.Find: smallest index where cmp(t, a[i]) <= 0.
    let k = a.partition_point(|e| t.cmp(e).is_gt());
    let kf = k < a.len() && t.cmp(&a[k]).is_eq();
    let s: Vec<String> = a.iter().map(|x| x.to_string()).collect();
    let ts = t.to_string();
    let ss = s.partition_point(|e| *e < ts);
    format!(
        "{},{} {} {},{} {},{} {} {} {}",
        i,
        b2s(found),
        i,
        k,
        b2s(kf),
        i,
        b2s(found),
        i,
        ss,
        i
    )
}

fn opt(i: Option<usize>) -> i64 {
    i.map_or(-1, |i| i as i64)
}

fn do_sl(line: &str) -> String {
    let parts: Vec<&str> = line.split(';').collect();
    let head: Vec<&str> = parts[0].split_whitespace().collect();
    let op = head[0];
    let p = ints(&head[1..]);
    let ufn = |i: usize| p[i] as usize;
    let mut a = ints(&parts[1].split_whitespace().collect::<Vec<_>>());
    let b = parts
        .get(2)
        .map(|s| ints(&s.split_whitespace().collect::<Vec<_>>()))
        .unwrap_or_default();
    let eq = |x: &isize, y: &isize| (x - y).abs() <= 1;
    match op {
        "compact" => {
            a.dedup();
            join(&a)
        }
        "compactfunc" => {
            compact_by(&mut a, |x, y| eq(x, y));
            join(&a)
        }
        "delete" => {
            a.drain(ufn(0)..ufn(1));
            join(&a)
        }
        "deletefunc" => {
            let mut n = 0;
            a.retain(|x| {
                n += 1;
                x % 3 != 0
            });
            format!("{} {}", join(&a), n)
        }
        "insert" => {
            a.splice(ufn(0)..ufn(0), b.iter().copied());
            join(&a)
        }
        "replace" => {
            a.splice(ufn(0)..ufn(1), b.iter().copied());
            join(&a)
        }
        "reverse" => {
            a.reverse();
            join(&a)
        }
        "index" => format!(
            "{} {} {} {}",
            opt(a.iter().position(|x| *x == p[0])),
            opt(a.iter().position(|x| *x > p[0])),
            a.contains(&p[0]),
            a.iter().any(|x| *x > p[0])
        ),
        "repeat" => join(&a.repeat(ufn(0))),
        "chunk" => a.chunks(ufn(0)).map(join).collect::<Vec<_>>().join("|"),
        "compare" => {
            // slices.CompareFunc with a reversed comparison.
            let rev = a
                .iter()
                .zip(&b)
                .map(|(x, y)| y.cmp(x))
                .find(|o| o.is_ne())
                .unwrap_or_else(|| a.len().cmp(&b.len()));
            format!(
                "{} {} {} {}",
                sign(a.cmp(&b)),
                sign(rev),
                a == b,
                a.len() == b.len() && a.iter().zip(&b).all(|(x, y)| eq(x, y))
            )
        }
        "concat" => join(&[&a[..], &b[..], &a[..]].concat()),
        "minmax" => {
            let c = |x: &&isize, y: &&isize| (*x % 5).cmp(&(*y % 5));
            format!(
                "{} {} {} {}",
                a.iter().min().unwrap(),
                a.iter().max().unwrap(),
                a.iter().min_by(c).unwrap(),
                // Go returns the first maximal element; Iterator::max_by the last.
                a.iter().rev().max_by(c).unwrap()
            )
        }
        "backward" => {
            let s = a
                .iter()
                .enumerate()
                .rev()
                .map(|(i, v)| format!("{i}:{v}"))
                .collect::<Vec<_>>()
                .join(",");
            let mut b2 = b.clone();
            b2.extend(a.iter().copied());
            format!("{} {}", s, join(&b2))
        }
        _ => panic!("bad SL op"),
    }
}

fn do_fmm(f: &[&str]) -> String {
    let fs = floats(f);
    let bits = |f: f64| {
        if f.is_nan() {
            "n".to_string() // NaN payloads are not preserved by min/max
        } else {
            format!("{:x}", f.to_bits())
        }
    };
    let min = fs.iter().copied().reduce(math::minimum).unwrap();
    let max = fs.iter().copied().reduce(math::maximum).unwrap();
    format!("{} {}", bits(min), bits(max))
}

fn do_cmp(f: &[&str]) -> String {
    let v = floats(f);
    let (x, y) = (v[0], v[1]);
    let xi = (x.to_bits() as u8 as i8) as isize;
    let yi = (y.to_bits() as u8 as i8) as isize;
    format!(
        "{} {} {} {}",
        sign(math::compare(&x, &y)),
        math::compare(&x, &y).is_lt(),
        sign(xi.cmp(&yi)),
        [xi, yi, 7].iter().find(|v| **v != 0).copied().unwrap_or(0)
    )
}

fn parse_map(s: &str) -> BTreeMap<isize, isize> {
    s.split_whitespace()
        .map(|kv| {
            let (k, v) = kv.split_once(':').expect("k:v");
            (k.parse().expect("int"), v.parse().expect("int"))
        })
        .collect()
}

fn map_str(m: &BTreeMap<isize, isize>) -> String {
    m.iter()
        .map(|(k, v)| format!("{k}:{v}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn do_map(line: &str) -> String {
    let parts: Vec<&str> = line.split(';').collect();
    let (m1, m2) = (parse_map(parts[0]), parse_map(parts[1]));
    // Exercise both map kinds: m1 is also checked through a HashMap.
    let h1: HashMap<isize, isize> = m1.iter().map(|(k, v)| (*k, *v)).collect();
    let mut vs: Vec<isize> = h1.values().copied().collect();
    vs.sort_unstable();
    let mut c = m1.clone();
    c.extend(m2.iter().map(|(k, v)| (*k, *v)));
    let mut d = m1.clone();
    d.retain(|k, v| (k + *v).rem_euclid(2) != 1);
    let mut e: BTreeMap<isize, isize> = m1.iter().map(|(k, v)| (*k, *v)).collect();
    e.extend(m2.iter().map(|(k, v)| (*k, *v)));
    assert!(h1.len() == m1.len() && m1.iter().all(|(k, v)| h1.get(k) == Some(v)));
    // maps.EqualFunc: same length and every key present with equal values.
    let equal_func = m1.len() == m2.len()
        && m1.iter().all(|(k, v)| {
            m2.get(k)
                .is_some_and(|w| v.rem_euclid(3) == w.rem_euclid(3))
        });
    format!(
        "{} {} {} {} {} {} {}",
        m1 == m2,
        equal_func,
        join(&vs),
        map_str(&c),
        map_str(&d),
        map_str(&e),
        map_str(&m1)
    )
}

/// iter.Pull: `fuse` ends the sequence for good, dropping the iterator is `stop`.
fn do_pull(f: &[&str]) -> String {
    let v = ints(f);
    let stop_at = v[0] as usize;
    let mut p = Some(v[1..].iter().fuse());
    let mut out = Vec::new();
    for i in 0..v.len() + 1 {
        if i == stop_at {
            p = None;
        }
        let r = p.as_mut().and_then(Iterator::next);
        out.push(format!("{}{}", r.map_or(0, |x| *x), b2s(r.is_some())));
    }
    let r = v[1..].iter().enumerate().next();
    let (i, x, ok) = r.map_or((0, 0, false), |(i, x)| (i as isize, *x, true));
    format!("{} {},{},{}", out.join(","), i, x, b2s(ok))
}

fn rec_less(a: &Rec, b: &Rec) -> bool {
    a.0 < b.0
}

fn do_heap(line: &str) -> String {
    let mut h = Heap::new(rec_less);
    let mut next = 0;
    let mut out = Vec::new();
    for op in line.split(';') {
        let f: Vec<&str> = op.split_whitespace().collect();
        if f.is_empty() {
            continue;
        }
        let v = ints(&f[1..]);
        let mut res = String::new();
        match f[0] {
            "init" => {
                let items = v
                    .iter()
                    .map(|&k| {
                        next += 1;
                        (k, next - 1)
                    })
                    .collect();
                h = Heap::from_vec(items, rec_less);
            }
            "push" => {
                h.push((v[0], next));
                next += 1;
            }
            "pop" => {
                let r = h.pop().expect("non-empty");
                res = format!("={}.{}", r.0, r.1);
            }
            "remove" => {
                let r = h.remove(v[0] as usize).expect("in range");
                res = format!("={}.{}", r.0, r.1);
            }
            "fix" => {
                h.update(v[0] as usize, |r| r.0 = v[1]).expect("in range");
            }
            _ => panic!("bad heap op"),
        }
        let dump: Vec<String> = h
            .as_slice()
            .iter()
            .map(|r| format!("{}.{}", r.0, r.1))
            .collect();
        out.push(format!("{}{}[{}]", f[0], res, dump.join(",")));
    }
    out.join(" ")
}

fn list_str(l: &list::List<isize>) -> String {
    let mut f = Vec::new();
    let mut e = l.front();
    while let Some(h) = e {
        f.push(h.value(l).expect("live").to_string());
        e = h.next(l);
    }
    let mut b = Vec::new();
    let mut e = l.back();
    while let Some(h) = e {
        b.push(h.value(l).expect("live").to_string());
        e = h.prev(l);
    }
    format!("{}/{}#{}", f.join(","), b.join(","), l.len())
}

fn add(hs: &mut Vec<(bool, list::Element)>, in_a: bool, e: Option<list::Element>) -> String {
    match e {
        None => "=nil".into(),
        Some(e) => {
            hs.push((in_a, e));
            "=h".into()
        }
    }
}

fn do_list(line: &str) -> String {
    let mut a: list::List<isize> = list::List::new();
    let mut b: list::List<isize> = list::List::new();
    // Element handles with the list that created them (for Next/Prev/Value).
    let mut hs: Vec<(bool, list::Element)> = Vec::new();
    let mut out = Vec::new();
    for op in line.split(';') {
        let f: Vec<&str> = op.split_whitespace().collect();
        if f.is_empty() {
            continue;
        }
        let in_a = f[0] == "A";
        let v = ints(&f[2..]);
        let mut res = String::new();
        let (l, other) = if in_a {
            (&mut a, &mut b)
        } else {
            (&mut b, &mut a)
        };
        let h = |i: isize| hs[i as usize].1;
        match f[1] {
            "pb" => res = add(&mut hs, in_a, Some(l.push_back(v[0]))),
            "pf" => res = add(&mut hs, in_a, Some(l.push_front(v[0]))),
            "ib" => {
                let e = l.insert_before(v[0], h(v[1]));
                res = add(&mut hs, in_a, e)
            }
            "ia" => {
                let e = l.insert_after(v[0], h(v[1]));
                res = add(&mut hs, in_a, e)
            }
            "rm" => {
                res = match l.remove(h(v[0])) {
                    Some(x) => format!("={x}"),
                    None => "=-".into(),
                }
            }
            "mf" => l.move_to_front(h(v[0])),
            "mb" => l.move_to_back(h(v[0])),
            "mbf" => l.move_before(h(v[0]), h(v[1])),
            "maf" => l.move_after(h(v[0]), h(v[1])),
            "pbl" => l.push_back_list(other),
            "pfl" => l.push_front_list(other),
            "sv" => {
                let (owner_a, e) = hs[v[0] as usize];
                let target = if owner_a == in_a { l } else { other };
                if let Some(x) = e.value_mut(target) {
                    *x = v[1];
                }
            }
            "nx" | "pv" => {
                let (owner_a, e) = hs[v[0] as usize];
                let target: &list::List<isize> = if owner_a == in_a { l } else { other };
                let r = if f[1] == "nx" {
                    e.next(target)
                } else {
                    e.prev(target)
                };
                res = match r {
                    None => "=nil".into(),
                    Some(n) => format!("={}", n.value(target).expect("live")),
                };
            }
            "init" => l.init(),
            _ => panic!("bad list op"),
        }
        out.push(format!(
            "{}{} A:{} B:{}",
            f[1],
            res,
            list_str(&a),
            list_str(&b)
        ));
    }
    out.join(" ")
}

type R = ring::Ring<isize>;

fn ring_str(r: &Option<R>) -> String {
    match r {
        None => "nil".into(),
        Some(r) => {
            let mut p = Vec::new();
            r.for_each(|x| p.push(x.to_string()));
            format!("{}:{}", r.len(), p.join(","))
        }
    }
}

fn do_ring(line: &str) -> String {
    let mut rs: [Option<R>; 4] = [None, None, None, None];
    let mut ctr = 0;
    let mut out = Vec::new();
    for op in line.split(';') {
        let f: Vec<&str> = op.split_whitespace().collect();
        if f.is_empty() {
            continue;
        }
        let v = ints(&f[1..]);
        let u = |i: usize| v[i] as usize;
        match f[0] {
            "new" => {
                let r = R::new(u(1));
                if let Some(r) = &r {
                    let mut p = r.clone();
                    loop {
                        p.set_value(ctr);
                        ctr += 1;
                        p = p.next();
                        if p == *r {
                            break;
                        }
                    }
                }
                rs[u(0)] = r;
            }
            "mv" => {
                if let Some(r) = rs[u(1)].clone() {
                    rs[u(0)] = Some(r.move_by(v[2]));
                }
            }
            "link" => {
                if let Some(r) = rs[u(0)].clone() {
                    let s = rs[u(1)].clone();
                    rs[u(2)] = Some(r.link(s.as_ref()));
                }
            }
            "unlink" => {
                if let Some(r) = rs[u(0)].clone() {
                    rs[u(2)] = r.unlink(v[1]);
                }
            }
            "nx" => {
                if let Some(r) = rs[u(1)].clone() {
                    rs[u(0)] = Some(r.next());
                }
            }
            "pv" => {
                if let Some(r) = rs[u(1)].clone() {
                    rs[u(0)] = Some(r.prev());
                }
            }
            "sv" => {
                if let Some(r) = &rs[u(0)] {
                    r.set_value(v[1]);
                }
            }
            _ => panic!("bad ring op"),
        }
        out.push(format!(
            "{} {} {} {} {}",
            f[0],
            ring_str(&rs[0]),
            ring_str(&rs[1]),
            ring_str(&rs[2]),
            ring_str(&rs[3])
        ));
    }
    out.join(" | ")
}

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.expect("stdin");
        let (cmd, rest) = line.split_once(' ').unwrap_or((&line, ""));
        let f: Vec<&str> = rest.split_whitespace().collect();
        let r = match cmd {
            "SORT" => do_sort(&f),
            "FSORT" => do_fsort(&f),
            "FSEARCH" => do_fsearch(&f),
            "ISEARCH" => do_isearch(&f),
            "SL" => do_sl(rest),
            "FMM" => do_fmm(&f),
            "CMP" => do_cmp(&f),
            "MAP" => do_map(rest),
            "PULL" => do_pull(&f),
            "HEAP" => do_heap(rest),
            "LIST" => do_list(rest),
            "RING" => do_ring(rest),
            _ => panic!("bad command {cmd}"),
        };
        println!("{r}");
    }
}
