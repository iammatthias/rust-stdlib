//! `embed!`: Go's `//go:embed` for `rust_stdlib::embed::FS`.
//!
//! `embed!("static", "docs/*.md", "all:assets")` walks the named files,
//! directories and wildcard patterns (relative to the invoking crate's
//! `CARGO_MANIFEST_DIR`) at compile time and expands to an
//! `rust_stdlib::embed::FS` whose files are `include_bytes!` of their absolute
//! paths, so Cargo rebuilds when an embedded file changes. Go's rules apply:
//! a directory is embedded recursively but names starting with `.` or `_` are
//! skipped unless the pattern starts with `all:`; a file named explicitly or
//! matched by a wildcard is always embedded; a pattern that matches nothing,
//! or a directory with no embeddable files, is a compile error.

use proc_macro::{TokenStream, TokenTree};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

fn fail(message: &str) -> TokenStream {
    format!("compile_error!({message:?});")
        .parse()
        .expect("static diagnostic tokens")
}

/// Decodes a plain (non-raw) string literal with `\\`, `\"`, `\n`, `\t`.
fn string_literal(text: &str) -> Result<String, String> {
    let body = text
        .strip_prefix('"')
        .and_then(|t| t.strip_suffix('"'))
        .ok_or_else(|| format!("embed! expects string literals, found {text}"))?;
    let mut out = String::new();
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('\\') => out.push('\\'),
            Some('"') => out.push('"'),
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            _ => return Err(format!("unsupported escape in embed! pattern {text}")),
        }
    }
    Ok(out)
}

/// `path.Match` for one path element: `*`, `?`, `[...]` classes and `\`.
fn match_element(pattern: &[char], name: &[char]) -> bool {
    match pattern.split_first() {
        None => name.is_empty(),
        Some((&'*', rest)) => (0..=name.len()).any(|i| match_element(rest, &name[i..])),
        Some((&'?', rest)) => !name.is_empty() && match_element(rest, &name[1..]),
        Some((&'[', rest)) => {
            let Some((&c, tail)) = name.split_first() else {
                return false;
            };
            let (negate, mut rest) = match rest.split_first() {
                Some((&'^' | &'!', r)) => (true, r),
                _ => (false, rest),
            };
            let mut matched = false;
            let mut first = true;
            loop {
                match rest.split_first() {
                    None => return false,
                    Some((&']', r)) if !first => {
                        rest = r;
                        break;
                    }
                    Some((&lo, r)) => {
                        let (lo, r) = if lo == '\\' {
                            match r.split_first() {
                                Some((&l, r2)) => (l, r2),
                                None => return false,
                            }
                        } else {
                            (lo, r)
                        };
                        let (hi, r) = match r.split_first() {
                            Some((&'-', r2)) if !matches!(r2.first(), Some(&']') | None) => {
                                match r2.split_first() {
                                    Some((&'\\', r3)) => match r3.split_first() {
                                        Some((&h, r4)) => (h, r4),
                                        None => return false,
                                    },
                                    Some((&h, r3)) => (h, r3),
                                    None => return false,
                                }
                            }
                            _ => (lo, r),
                        };
                        if lo <= c && c <= hi {
                            matched = true;
                        }
                        rest = r;
                    }
                }
                first = false;
            }
            matched != negate && match_element(rest, tail)
        }
        Some((&'\\', rest)) => match rest.split_first() {
            Some((&c, r)) => name.first() == Some(&c) && match_element(r, &name[1..]),
            None => false,
        },
        Some((&c, rest)) => name.first() == Some(&c) && match_element(rest, &name[1..]),
    }
}

fn has_meta(s: &str) -> bool {
    s.contains(['*', '?', '[', '\\'])
}

/// Expands `pattern` (slash separated, relative to `base`) to existing paths.
fn expand(base: &Path, pattern: &str) -> Result<Vec<PathBuf>, String> {
    let mut current = vec![PathBuf::new()];
    for element in pattern.split('/') {
        let mut next = Vec::new();
        for dir in &current {
            if !has_meta(element) {
                let candidate = dir.join(element);
                if base.join(&candidate).exists() {
                    next.push(candidate);
                }
                continue;
            }
            let Ok(read) = fs::read_dir(base.join(dir)) else {
                continue;
            };
            let pat: Vec<char> = element.chars().collect();
            let mut names: Vec<String> = read
                .filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().into_string().ok())
                .collect();
            names.sort();
            for name in names {
                let chars: Vec<char> = name.chars().collect();
                if match_element(&pat, &chars) {
                    next.push(dir.join(name));
                }
            }
        }
        current = next;
    }
    Ok(current)
}

fn walk(
    base: &Path,
    rel: &Path,
    all: bool,
    out: &mut BTreeMap<String, PathBuf>,
) -> Result<(), String> {
    let mut entries: Vec<_> = fs::read_dir(base.join(rel))
        .map_err(|e| format!("cannot read {}: {e}", rel.display()))?
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !all && (name.starts_with('.') || name.starts_with('_')) {
            continue;
        }
        let rel_child = rel.join(&name);
        let meta = fs::metadata(base.join(&rel_child))
            .map_err(|e| format!("cannot stat {}: {e}", rel_child.display()))?;
        if meta.is_dir() {
            walk(base, &rel_child, all, out)?;
        } else if meta.is_file() {
            add(base, &rel_child, out);
        } else {
            return Err(format!(
                "cannot embed irregular file {}",
                rel_child.display()
            ));
        }
    }
    Ok(())
}

fn add(base: &Path, rel: &Path, out: &mut BTreeMap<String, PathBuf>) {
    let name: Vec<String> = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    out.insert(name.join("/"), base.join(rel));
}

fn valid_pattern(pattern: &str) -> bool {
    !pattern.is_empty()
        && pattern
            .split('/')
            .all(|e| !(e.is_empty() || e == "." || e == ".."))
}

pub(crate) fn embed(input: TokenStream) -> TokenStream {
    match build(input) {
        Ok(source) => source
            .parse()
            .unwrap_or_else(|_| fail("embed! could not generate Rust syntax")),
        Err(e) => fail(&e),
    }
}

fn build(input: TokenStream) -> Result<String, String> {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .map_err(|_| "embed! needs CARGO_MANIFEST_DIR (build with Cargo)".to_string())?;
    let base = PathBuf::from(manifest);
    let mut patterns = Vec::new();
    let mut expect_literal = true;
    for tree in input {
        match tree {
            TokenTree::Literal(l) if expect_literal => {
                patterns.push(string_literal(&l.to_string())?);
                expect_literal = false;
            }
            TokenTree::Punct(p) if p.as_char() == ',' && !expect_literal => expect_literal = true,
            other => {
                return Err(format!(
                    "embed! expects comma separated string literals, found {other}"
                ))
            }
        }
    }
    let mut files = BTreeMap::new();
    for pattern in &patterns {
        let (all, pat) = match pattern.strip_prefix("all:") {
            Some(rest) => (true, rest),
            None => (false, pattern.as_str()),
        };
        if !valid_pattern(pat) {
            return Err(format!("invalid embed pattern {pattern:?}"));
        }
        let matched = expand(&base, pat)?;
        if matched.is_empty() {
            return Err(format!("embed pattern {pattern}: no matching files found"));
        }
        for rel in matched {
            let meta = fs::metadata(base.join(&rel))
                .map_err(|e| format!("embed pattern {pattern}: {e}"))?;
            if meta.is_dir() {
                let mut found = BTreeMap::new();
                walk(&base, &rel, all, &mut found)?;
                if found.is_empty() {
                    return Err(format!(
                        "embed pattern {pattern}: cannot embed directory {}: contains no embeddable files",
                        rel.display()
                    ));
                }
                files.extend(found);
            } else if meta.is_file() {
                add(&base, &rel, &mut files);
            } else {
                return Err(format!(
                    "embed pattern {pattern}: cannot embed irregular file {}",
                    rel.display()
                ));
            }
        }
    }
    let entries: Vec<String> = files
        .iter()
        .map(|(name, path)| {
            format!(
                "({name:?}, include_bytes!({:?}) as &'static [u8])",
                path.to_string_lossy()
            )
        })
        .collect();
    Ok(format!(
        "::rust_stdlib::embed::FS::new(&[{}])",
        entries.join(",")
    ))
}
