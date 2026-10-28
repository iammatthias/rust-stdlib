//! Port of Go's `testing/match.go`: sanitises, uniquifies and filters the
//! names of subtests and sub-benchmarks.

use std::{collections::HashMap, sync::Mutex};

use crate::strconv;

/// A boxed matching function with the shape of Go's `matchString`
/// (`func(pat, str string) (bool, error)`).
pub type MatchFn =
    std::sync::Arc<dyn Fn(&str, &str) -> Result<bool, String> + Send + Sync + 'static>;

/// The default matcher: [`crate::regexp::match_string`].
pub fn regexp_match() -> MatchFn {
    std::sync::Arc::new(|pat, s| crate::regexp::match_string(pat, s).map_err(|e| e.to_string()))
}

#[derive(Clone, Debug)]
enum Filter {
    Simple(Vec<String>),
    Alternation(Vec<Filter>),
}

impl Filter {
    fn matches(&self, name: &[&str], m: &MatchFn) -> (bool, bool) {
        match self {
            Filter::Simple(pats) => {
                for (i, s) in name.iter().enumerate() {
                    if i >= pats.len() {
                        break;
                    }
                    if !m(&pats[i], s).unwrap_or(false) {
                        return (false, false);
                    }
                }
                (true, name.len() < pats.len())
            }
            Filter::Alternation(alts) => {
                for a in alts {
                    let (ok, partial) = a.matches(name, m);
                    if ok {
                        return (ok, partial);
                    }
                }
                (false, false)
            }
        }
    }

    fn verify(&mut self, name: &str, m: &MatchFn) -> Result<(), String> {
        match self {
            Filter::Simple(pats) => {
                for s in pats.iter_mut() {
                    *s = rewrite(s);
                }
                for (i, s) in pats.iter().enumerate() {
                    if let Err(e) = m(s, "non-empty") {
                        return Err(format!(
                            "element {i} of {name} ({}): {e}",
                            strconv::quote(s)
                        ));
                    }
                }
                Ok(())
            }
            Filter::Alternation(alts) => {
                for (i, a) in alts.iter_mut().enumerate() {
                    if let Err(e) = a.verify(name, m) {
                        return Err(format!("alternation {i} of {e}"));
                    }
                }
                Ok(())
            }
        }
    }
}

/// Splits a `-run` style pattern on top-level `/` and `|`.
fn split_regexp(s: &str) -> Filter {
    let bytes = s.as_bytes();
    let mut a: Vec<String> = Vec::new();
    let mut b: Vec<Filter> = Vec::new();
    let (mut cs, mut cp) = (0i32, 0i32);
    let mut start = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'[' => cs += 1,
            b']' => {
                cs -= 1;
                if cs < 0 {
                    cs = 0;
                }
            }
            b'(' if cs == 0 => cp += 1,
            b')' if cs == 0 => cp -= 1,
            b'\\' => i += 1,
            b'/' if cs == 0 && cp == 0 => {
                a.push(s[start..i].to_string());
                start = i + 1;
                i = start;
                continue;
            }
            b'|' if cs == 0 && cp == 0 => {
                a.push(s[start..i].to_string());
                start = i + 1;
                i = start;
                b.push(Filter::Simple(std::mem::take(&mut a)));
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    a.push(s[start.min(s.len())..].to_string());
    if b.is_empty() {
        Filter::Simple(a)
    } else {
        b.push(Filter::Simple(a));
        Filter::Alternation(b)
    }
}

/// Filters and uniquifies test names (Go's `matcher`).
pub(crate) struct Matcher {
    filter: Filter,
    skip: Filter,
    match_fn: MatchFn,
    sub_names: Mutex<HashMap<String, i32>>,
}

impl Matcher {
    pub(crate) fn all() -> Matcher {
        Matcher::new(regexp_match(), "", "-test.run", "").expect("empty filters are valid")
    }

    pub(crate) fn new(
        match_fn: MatchFn,
        patterns: &str,
        name: &str,
        skips: &str,
    ) -> Result<Matcher, String> {
        let filter = if patterns.is_empty() {
            Filter::Simple(Vec::new())
        } else {
            let mut f = split_regexp(patterns);
            f.verify(name, &match_fn)
                .map_err(|e| format!("testing: invalid regexp for {e}"))?;
            f
        };
        let skip = if skips.is_empty() {
            Filter::Alternation(Vec::new())
        } else {
            let mut f = split_regexp(skips);
            f.verify("-test.skip", &match_fn)
                .map_err(|e| format!("testing: invalid regexp for {e}"))?;
            f
        };
        Ok(Matcher {
            filter,
            skip,
            match_fn,
            sub_names: Mutex::new(HashMap::new()),
        })
    }

    /// Reports the (possibly uniquified) full name and whether it passes the
    /// filters. `parent` is the name and level of the enclosing test.
    pub(crate) fn full_name(
        &self,
        parent: Option<(&str, usize)>,
        subname: &str,
    ) -> (String, bool, bool) {
        let mut name = subname.to_string();
        if let Some((pname, level)) = parent {
            if level > 0 {
                name = self.unique(pname, &rewrite(subname));
            }
        }
        let elem: Vec<&str> = name.split('/').collect();
        let (ok, partial) = self.filter.matches(&elem, &self.match_fn);
        if !ok {
            return (name, false, false);
        }
        let (skip, partial_skip) = self.skip.matches(&elem, &self.match_fn);
        if skip && !partial_skip {
            return (name, false, false);
        }
        (name, ok, partial)
    }

    fn unique(&self, parent: &str, subname: &str) -> String {
        let mut names = self.sub_names.lock().unwrap();
        let base = format!("{parent}/{subname}");
        loop {
            let n = *names.get(&base).unwrap_or(&0);
            names.insert(base.clone(), n + 1);
            if n == 0 && !subname.is_empty() {
                let (prefix, nn) = parse_subtest_number(&base);
                if prefix.len() < base.len() && nn < *names.get(prefix).unwrap_or(&0) {
                    continue;
                }
                return base;
            }
            let name = format!("{base}#{n:02}");
            if names.get(&name).copied().unwrap_or(0) != 0 {
                continue;
            }
            return name;
        }
    }
}

fn parse_subtest_number(s: &str) -> (&str, i32) {
    let Some(i) = s.rfind('#') else {
        return (s, 0);
    };
    let (prefix, suffix) = (&s[..i], &s[i + 1..]);
    if suffix.len() < 2 || (suffix.len() > 2 && suffix.starts_with('0')) {
        return (s, 0);
    }
    if suffix == "00" && !prefix.ends_with('/') {
        return (s, 0);
    }
    match suffix.parse::<i32>() {
        Ok(n) if n >= 0 && suffix.bytes().all(|b| b.is_ascii_digit()) => (prefix, n),
        _ => (s, 0),
    }
}

/// Rewrites a subtest name to printable characters without white space.
pub(crate) fn rewrite(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for r in s.chars() {
        if is_space(r) {
            out.push('_');
        } else if !strconv::is_print(r) {
            let q = strconv::quote_rune(r);
            out.push_str(&q[1..q.len() - 1]);
        } else {
            out.push(r);
        }
    }
    out
}

fn is_space(r: char) -> bool {
    let r = r as u32;
    if r < 0x2000 {
        matches!(r, 0x09..=0x0d | 0x20 | 0x85 | 0xa0 | 0x1680)
    } else if r <= 0x200a {
        true
    } else {
        matches!(r, 0x2028 | 0x2029 | 0x202f | 0x205f | 0x3000)
    }
}

#[cfg(test)]
#[path = "matcher_tests.rs"]
mod tests;
