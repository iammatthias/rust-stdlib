//! `collections::sort_unstable_by` against Go 1.27's pdqsort: the order of
//! records with equal keys must be Go's (`slices.SortFunc`, `sort.Sort` and
//! `sort.Slice` agree with each other and with this port). The fixture holds
//! an FNV-1a hash of the sorted id sequence for each generated input; the
//! inputs are generated identically by the Go program that wrote it.
use rust_stdlib::collections::{sort_unstable_by, sort_unstable_by_less};

#[derive(Clone, Copy)]
struct Rec {
    key: i64,
    id: u64,
}

fn gen(pattern: &str, n: usize, k: i64) -> Vec<Rec> {
    let mut s = (n as u64)
        .wrapping_mul(2654435761)
        .wrapping_add((k as u64).wrapping_mul(40503))
        .wrapping_add(12345);
    let mut next = || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s >> 33
    };
    let ni = n as i64;
    (0..n)
        .map(|i| {
            let ii = i as i64;
            let key = match pattern {
                "random" => (next() % k as u64) as i64,
                "asc" => ii * k / ni.max(1),
                "desc" => (ni - ii) * k / ni.max(1),
                "saw" => ii % k,
                "equal" => 0,
                "organ" => {
                    if i < n / 2 {
                        ii % (k + 1)
                    } else {
                        (ni - ii) % (k + 1)
                    }
                }
                other => panic!("unknown pattern {other}"),
            };
            Rec { key, id: i as u64 }
        })
        .collect()
}

fn hash(rs: &[Rec]) -> u64 {
    let mut h: u64 = 14695981039346656037;
    for r in rs {
        h ^= r.id;
        h = h.wrapping_mul(1099511628211);
    }
    h
}

#[test]
fn unstable_sort_orders_equal_elements_as_go() {
    let mut checked = 0;
    for line in include_str!("fixtures/go_unstable_sort.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        let (n, k): (usize, i64) = (f[1].parse().unwrap(), f[2].parse().unwrap());
        let want = u64::from_str_radix(f[3], 16).unwrap();
        let mut a = gen(f[0], n, k);
        sort_unstable_by(&mut a, |x, y| x.key.cmp(&y.key));
        assert_eq!(hash(&a), want, "cmp {line}");
        let mut b = gen(f[0], n, k);
        sort_unstable_by_less(&mut b, |x, y| x.key < y.key);
        assert_eq!(hash(&b), want, "less {line}");
        assert!(a.windows(2).all(|w| w[0].key <= w[1].key), "{line}");
        checked += 1;
    }
    assert_eq!(checked, 540);
}
